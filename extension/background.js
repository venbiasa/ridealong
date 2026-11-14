// ridealong — service worker.
//
// Long-polls the local ridealong bridge, runs each request inside the user's signed-in session, and
// posts the response back. Security model:
//  - The bridge token lives in chrome.storage.local so pairing survives a browser restart. It is
//    never put in window.localStorage or web-page-reachable storage, and Unpair deletes it.
//  - The token is never sent anywhere: bridge calls are HMAC-signed, and work is only accepted from
//    a bridge that proves it holds the same token (see auth.js). It arrives by click-to-pair.
//  - Requests only ever go to https origins the user granted, one origin at a time, by clicking
//    Allow on the grant page and approving Chrome's own permission prompt.

import { BridgeVerificationError, DEFAULT_PORT, bridgeCall, bridgeOrigin } from "./auth.js";
import { accessPattern } from "./config.js";

const POLL_TIMEOUT_GUARD_MS = 35_000; // a little above the server's long-poll window
/** After asking a bridge to open a pairing page, wait this long before asking again. */
const PAIR_REQUEST_BACKOFF_MS = 10 * 60_000;
/** Don't reopen a sign-in tab for the same origin more often than this while the user signs in. */
const SIGN_IN_BACKOFF_MS = 2 * 60_000;
const VISIT_TIMEOUT_MS = 20_000;
const VISIT_SETTLE_MS = 1500;
/** How long a request waits for the user to answer the grant page. */
const GRANT_TIMEOUT_MS = 2 * 60_000;
/** After a Deny, requests to that origin are refused without reopening the page for this long. */
const GRANT_DENY_BACKOFF_MS = 2 * 60_000;
const DROP_HEADERS = new Set([
  "content-encoding", // body is already decoded by fetch(); keeping this would double-decode
  "content-length",
  "transfer-encoding",
  "connection",
  "set-cookie",
]);

async function bridgePort() {
  const { port } = await chrome.storage.local.get(["port"]);
  return Number.isInteger(port) ? port : DEFAULT_PORT;
}

async function sessionToken() {
  const { token } = await chrome.storage.local.get(["token"]);
  return token;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function utf8ToB64(s) {
  return btoa(unescape(encodeURIComponent(s)));
}

function bytesToB64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

async function redirectsAway(work, headers) {
  try {
    const probe = await fetch(work.url, {
      method: work.method === "GET" || work.method === "HEAD" ? work.method : "GET",
      headers,
      credentials: "include",
      redirect: "manual",
    });
    return probe.type === "opaqueredirect";
  } catch {
    return false;
  }
}

/** Opens the target in a tab so the gateway can sign the user back in, at most once per backoff per origin. */
async function openSignIn(target, work) {
  const { signInOpenedAt = {} } = await chrome.storage.session.get(["signInOpenedAt"]);
  const last = signInOpenedAt[target.origin];
  if (last && Date.now() - last < SIGN_IN_BACKOFF_MS) return false;
  await chrome.storage.session.set({ signInOpenedAt: { ...signInOpenedAt, [target.origin]: Date.now() } });
  // A GET lands back on the requested page after sign-in; anything else just needs the origin.
  const url = (work.method || "GET") === "GET" ? target.href : `${target.origin}/`;
  try {
    await chrome.tabs.create({ url, active: true });
    return true;
  } catch {
    return false;
  }
}

async function sessionExpired(target, work) {
  const opened = await openSignIn(target, work);
  const hint = opened
    ? "A tab is open in your browser: sign in there, then retry."
    : "Open it in this browser, sign in, then retry.";
  return { status: 401, bodyB64: utf8ToB64(`ridealong: your session for ${target.origin} has expired. ${hint}`) };
}

const grantWaits = new Map();

/** Opens the grant page for `origin` and waits for Allow (true), or Deny, a closed tab or a timeout (false). */
async function askForAccess(origin, pattern) {
  const { grantDenied = {} } = await chrome.storage.session.get(["grantDenied"]);
  if (grantDenied[origin] && Date.now() - grantDenied[origin] < GRANT_DENY_BACKOFF_MS) return false;
  const started = Date.now();
  let tab;
  try {
    tab = await chrome.tabs.create({
      url: chrome.runtime.getURL(`grant.html?origin=${encodeURIComponent(origin)}`),
      active: true,
    });
    await chrome.windows.update(tab.windowId, { focused: true }).catch(() => {});
  } catch {
    return false;
  }
  // Polling (rather than waiting on an event) also keeps the service worker alive meanwhile.
  while (Date.now() - started < GRANT_TIMEOUT_MS) {
    await sleep(1000);
    if (await chrome.permissions.contains({ origins: [pattern] })) return true;
    const { grantDenied: denied = {} } = await chrome.storage.session.get(["grantDenied"]);
    if ((denied[origin] ?? 0) >= started) return false;
    const open = await chrome.tabs.get(tab.id).then(
      () => true,
      () => false,
    );
    if (!open) return chrome.permissions.contains({ origins: [pattern] });
  }
  return false;
}

/** Whether requests to this URL may run, asking the user once per origin when not yet granted. */
async function ensureAccess(target) {
  const pattern = accessPattern(target);
  if (!pattern) return false;
  if (await chrome.permissions.contains({ origins: [pattern] })) return true;
  let wait = grantWaits.get(target.origin);
  if (!wait) {
    wait = askForAccess(target.origin, pattern).finally(() => grantWaits.delete(target.origin));
    grantWaits.set(target.origin, wait);
  }
  return wait;
}

function refused(target) {
  return {
    status: 403,
    bodyB64: utf8ToB64(
      target.protocol === "https:"
        ? `ridealong: access to ${target.origin} was not allowed. Click Allow on the page the extension opens, then retry.`
        : `ridealong: refusing ${target.origin}; only https is supported.`,
    ),
  };
}

/** Resolves once the tab finishes loading a page on `origin`, or false after `ms`. */
function settledOn(tabId, origin, ms) {
  return new Promise((resolve) => {
    // tab.url is only visible for origins we hold a permission for, so a sign-in host reads as "".
    const onTarget = (tab) => tab.status === "complete" && (tab.url ?? "").startsWith(`${origin}/`);
    const done = (value) => {
      clearTimeout(timer);
      chrome.tabs.onUpdated.removeListener(listener);
      resolve(value);
    };
    const listener = (id, _change, tab) => {
      if (id === tabId && onTarget(tab)) done(tab.url);
    };
    const timer = setTimeout(() => done(false), ms);
    chrome.tabs.onUpdated.addListener(listener);
    chrome.tabs.get(tabId).then(
      (tab) => onTarget(tab) && done(tab.url),
      () => done(false),
    );
  });
}

/** Opens the target as a page so the app can renew its own login, then closes the tab. */
async function visit(work) {
  let target;
  try {
    target = new URL(work.url);
  } catch {
    return { status: 400, bodyB64: utf8ToB64("ridealong: invalid URL") };
  }
  if (!(await ensureAccess(target))) return refused(target);
  let tab;
  try {
    tab = await chrome.tabs.create({ url: target.href, active: false });
  } catch (e) {
    return { status: 502, bodyB64: utf8ToB64(`ridealong: could not open a tab: ${e?.message ?? e}`) };
  }
  const finalUrl = await settledOn(tab.id, target.origin, VISIT_TIMEOUT_MS);
  if (!finalUrl) {
    await chrome.tabs.update(tab.id, { active: true }).catch(() => {});
    return {
      status: 401,
      bodyB64: utf8ToB64(`ridealong: ${target.origin} needs you to sign in. A tab is open: sign in there, then retry.`),
    };
  }
  // Let the app's post-login redirects and cookie writes finish before the tab goes away.
  await sleep(VISIT_SETTLE_MS);
  await chrome.tabs.remove(tab.id).catch(() => {});
  return {
    status: 200,
    headers: { "content-type": "application/json" },
    bodyB64: utf8ToB64(JSON.stringify({ url: finalUrl })),
  };
}

/** Run one request in-session and shape the reply for the bridge. */
async function execute(work) {
  let target;
  try {
    target = new URL(work.url);
  } catch {
    return { status: 400, bodyB64: utf8ToB64("ridealong: invalid URL") };
  }
  if (!(await ensureAccess(target))) return refused(target);
  // The browser attaches the session cookies; a caller-supplied Authorization is never forwarded.
  const headers = {};
  for (const [k, v] of Object.entries(work.headers || {})) {
    if (k.toLowerCase() !== "authorization") headers[k] = v;
  }
  let resp;
  try {
    resp = await fetch(work.url, {
      method: work.method || "GET",
      headers,
      body: work.body ?? undefined,
      credentials: "include",
      redirect: "follow",
    });
  } catch (e) {
    // A gateway bounce to a sign-in host we have no permission for fails as a CORS error, not a
    // redirect, so check whether the target itself answers with a redirect.
    if (await redirectsAway(work, headers)) return sessionExpired(target, work);
    return { status: 502, bodyB64: utf8ToB64(`ridealong: fetch failed: ${e?.message ?? e}`) };
  }
  let finalOrigin;
  try {
    finalOrigin = new URL(resp.url).origin;
  } catch {
    finalOrigin = target.origin;
  }
  if (resp.redirected && finalOrigin !== target.origin) return sessionExpired(target, work);
  const buf = new Uint8Array(await resp.arrayBuffer());
  const outHeaders = {};
  for (const [k, v] of resp.headers) {
    if (!DROP_HEADERS.has(k.toLowerCase())) outHeaders[k] = v;
  }
  if (resp.redirected) outHeaders["x-ridealong-final-url"] = resp.url;
  return { status: resp.status, statusText: resp.statusText, headers: outHeaders, bodyB64: bytesToB64(buf) };
}

/** Asks a running bridge to open its pairing page, at most once per backoff window. */
async function requestPairing(port) {
  const { pairRequestedAt } = await chrome.storage.session.get(["pairRequestedAt"]);
  if (pairRequestedAt && Date.now() - pairRequestedAt < PAIR_REQUEST_BACKOFF_MS) return;
  try {
    const res = await fetch(`${bridgeOrigin(port)}/pair/request`, { method: "POST" });
    if (res.status === 202) await chrome.storage.session.set({ pairRequestedAt: Date.now() });
  } catch {
    // No bridge running; the keepalive alarm tries again.
  }
}

let running = false;

async function loop() {
  if (running) return;
  running = true;
  try {
    for (;;) {
      const port = await bridgePort();
      const token = await sessionToken();
      if (!token) {
        await requestPairing(port);
        return;
      }

      let work;
      try {
        const res = await bridgeCall(port, token, "GET", "/poll", null, AbortSignal.timeout(POLL_TIMEOUT_GUARD_MS));
        if (res.status === 204) continue;
        if (res.status === 401) {
          // This bridge doesn't know our token (it restarted): forget it and ask to pair again.
          await chrome.storage.local.remove(["token"]);
          continue;
        }
        if (res.status !== 200) {
          await sleep(2000);
          continue;
        }
        work = JSON.parse(res.text);
      } catch (e) {
        // Unreachable bridge, or something on the port that failed verification: never trust it.
        await sleep(e instanceof BridgeVerificationError ? 5000 : 2000);
        continue;
      }

      const reply = work.kind === "visit" ? await visit(work) : await execute(work);
      try {
        await bridgeCall(port, token, "POST", "/result", JSON.stringify({ id: work.id, ...reply }));
      } catch {
        // The caller times the request out; nothing to do here.
      }
    }
  } finally {
    running = false;
  }
}

// The bridge's /pair page (via pair-content.js) hands over its one-time secret. The port comes from
// the sender's URL, which Chrome supplies, never from the message.
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg?.type !== "ridealong-pair" || sender.tab?.id == null || !sender.url) return;
  let page;
  try {
    page = new URL(sender.url);
  } catch {
    return;
  }
  const port = Number(page.port);
  if (page.protocol !== "http:" || page.hostname !== "127.0.0.1" || page.pathname !== "/pair") return;
  if (!Number.isInteger(port) || port <= 0) return;
  if (typeof msg.secret !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(msg.secret)) return;
  void chrome.storage.session
    .set({ pairing: { port, secret: msg.secret } })
    .then(() => chrome.tabs.update(sender.tab.id, { url: chrome.runtime.getURL("pair.html") }));
});

chrome.runtime.onStartup.addListener(() => void loop());
chrome.runtime.onInstalled.addListener(() => {
  // Development builds stored a typed allowlist under this key; host access is a Chrome permission.
  void chrome.storage.local.remove(["targetOrigins"]);
  void loop();
});
chrome.storage.session.onChanged.addListener(() => void loop());
chrome.storage.local.onChanged.addListener(() => void loop());
chrome.alarms.create("ridealong-keepalive", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(() => void loop());
void loop();
