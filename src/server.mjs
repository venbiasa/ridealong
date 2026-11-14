import { createCipheriv, createECDH, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";

export const DEFAULT_PORT = 8731;
export const PROTOCOL_VERSION = "ridealong-v1";
/** A reply body larger than this is refused; browser-gated API responses are far smaller. */
const MAX_BODY_BYTES = 64 * 1024 * 1024;
const DEFAULT_POLL_TIMEOUT_MS = 25_000;
/** Signed requests older or newer than this are refused (replay window). */
export const MAX_CLOCK_SKEW_MS = 120_000;
/** How long a pairing link stays usable. */
const PAIRING_TTL_MS = 10 * 60_000;
/** An extension asking to pair again within this window doesn't open another browser tab. */
const PAIR_REOPEN_MS = 60_000;

const PAIR_PAGE = `<!doctype html>
<meta charset="utf-8">
<title>ridealong pairing</title>
<body style="font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.5">
<h1>ridealong</h1>
<p>Handing this pairing request to the ridealong extension&hellip;</p>
<p>If nothing happens, this browser doesn't have the extension. Copy this page's full address,
including everything after <code>#</code>, into the browser where ridealong is installed.</p>
</body>`;

const sha256Hex = (buf) => createHash("sha256").update(buf).digest("hex");
const hmacHex = (key, msg) => createHmac("sha256", key).update(msg).digest("hex");

function equalHex(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/** What the extension signs for each request. */
export function clientMessage(method, path, ts, nonce, bodyHash) {
  return `${PROTOCOL_VERSION}|client|${method}|${path}|${ts}|${nonce}|${bodyHash}`;
}

/** What the bridge signs for each response. */
export function serverMessage(nonce, status, bodyHash) {
  return `${PROTOCOL_VERSION}|server|${nonce}|${status}|${bodyHash}`;
}

/**
 * Signs a request the way the extension does. For other clients of the protocol and for tests.
 * @returns {{ headers: Record<string,string>, nonce: string }}
 */
export function signRequest(token, method, path, body = "") {
  const ts = Date.now();
  const nonce = randomBytes(16).toString("hex");
  const auth = hmacHex(token, clientMessage(method, path, ts, nonce, sha256Hex(Buffer.from(body))));
  return {
    nonce,
    headers: { "x-ridealong-ts": String(ts), "x-ridealong-nonce": nonce, "x-ridealong-auth": auth },
  };
}

/** Checks a response's proof the way the extension does. */
export function verifyResponse(token, nonce, status, body, proof) {
  const expected = hmacHex(token, serverMessage(nonce, status, sha256Hex(Buffer.from(body))));
  return typeof proof === "string" && equalHex(proof, expected);
}

/**
 * The key both sides derive while pairing. Keyed by the one-time pairing secret from the link, over
 * the ECDH shared secret and both public keys, so neither someone who only saw the link nor someone
 * who only watched the exchange can derive it.
 */
export function pairingKey(secret, sharedSecret, bridgePub, extensionPub) {
  return createHmac("sha256", secret)
    .update(`${PROTOCOL_VERSION}|pair|${Buffer.from(sharedSecret).toString("hex")}|${bridgePub}|${extensionPub}`)
    .digest();
}

function abortError() {
  return Object.assign(new Error("The operation was aborted"), { name: "AbortError" });
}

/**
 * A local control channel for the ridealong browser extension. A caller enqueues a request with
 * `request()`; the extension long-polls `/poll`, runs it inside the user's signed-in tab, and posts
 * the response to `/result`.
 *
 * Both directions are authenticated without ever sending the token: the extension signs each
 * request with an HMAC keyed by the token, and the bridge signs each response the same way. So a
 * program that grabs the port first learns nothing it can replay and cannot hand the extension
 * work. Bound to 127.0.0.1; the Host and Origin headers are checked too.
 *
 * Pairing hands the token to the extension with one click instead of a paste: `pair()` (also
 * triggered by an unpaired extension via `/pair/request`) calls `onPairingUrl` with a link carrying a
 * one-time secret; the caller opens it in the browser, the extension picks it up, and once the user
 * clicks Pair the two run an ECDH exchange keyed by that secret. `onPaired` fires on success.
 *
 * @param {{ port?: number, token?: string, pollTimeoutMs?: number,
 *   onPairingUrl?: (url: string) => void, onPaired?: () => void }} [opts]
 * @returns {Promise<{ request: Function, visit: Function, port: number, token: string, close: Function, pair: Function }>}
 */
export async function startBridge(opts = {}) {
  const token = opts.token ?? randomBytes(32).toString("base64url");
  const pollTimeoutMs = opts.pollTimeoutMs ?? DEFAULT_POLL_TIMEOUT_MS;
  const queue = [];
  const waiters = [];
  const pending = new Map();
  const seenNonces = new Map();
  let port = 0;
  let pairing = null;

  const activePairing = () => (pairing && pairing.expires > Date.now() ? pairing : null);

  /** Opens (or re-opens) the pairing page through `onPairingUrl`. */
  const pair = () => {
    let p = activePairing();
    if (!p) {
      const ecdh = createECDH("prime256v1");
      ecdh.generateKeys();
      p = pairing = {
        secret: randomBytes(32).toString("base64url"),
        ecdh,
        pub: ecdh.getPublicKey().toString("base64url"),
        expires: Date.now() + PAIRING_TTL_MS,
        openedAt: 0,
      };
    }
    p.openedAt = Date.now();
    opts.onPairingUrl?.(`http://127.0.0.1:${port}/pair#${p.secret}`);
  };

  /** Completes a pairing claim: returns the encrypted token, or null if the claim is not valid. */
  const claim = (body) => {
    const p = activePairing();
    if (!p) return null;
    let extensionPub;
    let confirm;
    let shared;
    try {
      ({ pub: extensionPub, confirm } = JSON.parse(body.toString("utf8")));
      if (typeof extensionPub !== "string" || typeof confirm !== "string") return null;
      shared = p.ecdh.computeSecret(Buffer.from(extensionPub, "base64url"));
    } catch {
      return null;
    }
    const key = pairingKey(p.secret, shared, p.pub, extensionPub);
    if (!equalHex(confirm, hmacHex(key, `${PROTOCOL_VERSION}|pair-client`))) return null;
    pairing = null;
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(Buffer.from(`${PROTOCOL_VERSION}|pair-token`));
    const ct = Buffer.concat([cipher.update(token, "utf8"), cipher.final(), cipher.getAuthTag()]);
    return { iv: iv.toString("base64url"), ct: ct.toString("base64url") };
  };

  const dispatch = (work) => {
    const waiter = waiters.shift();
    if (waiter) waiter(work);
    else queue.push(work);
  };

  /** Returns the request's nonce when its signature is valid and fresh, else null. */
  const verifyClient = (req, path, body) => {
    const ts = Number(req.headers["x-ridealong-ts"]);
    const nonce = req.headers["x-ridealong-nonce"];
    const auth = req.headers["x-ridealong-auth"];
    if (!Number.isFinite(ts) || typeof auth !== "string") return null;
    if (typeof nonce !== "string" || !/^[0-9a-f]{32}$/.test(nonce)) return null;
    const now = Date.now();
    if (Math.abs(now - ts) > MAX_CLOCK_SKEW_MS) return null;
    for (const [n, expires] of seenNonces) if (expires < now) seenNonces.delete(n);
    if (seenNonces.has(nonce)) return null;
    const expected = hmacHex(token, clientMessage(req.method, path, ts, nonce, sha256Hex(body)));
    if (!equalHex(auth, expected)) return null;
    seenNonces.set(nonce, now + 2 * MAX_CLOCK_SKEW_MS);
    return nonce;
  };

  /** Writes a response with its proof. */
  const send = (res, nonce, status, body, contentType) => {
    const buf = body == null ? Buffer.alloc(0) : Buffer.from(body);
    res.setHeader("x-ridealong-proof", hmacHex(token, serverMessage(nonce, status, sha256Hex(buf))));
    if (contentType) res.setHeader("content-type", contentType);
    res.writeHead(status).end(buf.length ? buf : undefined);
  };

  const cors = (req, res) => {
    const origin = req.headers.origin;
    if (typeof origin === "string" && origin.startsWith("chrome-extension://")) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader(
        "Access-Control-Allow-Headers",
        "content-type, x-ridealong-ts, x-ridealong-nonce, x-ridealong-auth",
      );
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Expose-Headers", "x-ridealong-proof");
    }
  };

  const readBody = (req) =>
    new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      req.on("data", (c) => {
        size += c.length;
        if (size > MAX_BODY_BYTES) {
          reject(new Error("ridealong body too large"));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on("end", () => resolve(Buffer.concat(chunks)));
      req.on("error", reject);
    });

  const handle = async (req, res) => {
    cors(req, res);
    const host = (req.headers.host ?? "").split(":")[0];
    if (host && host !== "127.0.0.1" && host !== "localhost") {
      res.writeHead(403).end();
      return;
    }
    if (req.method === "OPTIONS") {
      res.writeHead(204).end();
      return;
    }
    const origin = req.headers.origin;
    if (typeof origin === "string" && !origin.startsWith("chrome-extension://")) {
      res.writeHead(401).end();
      return;
    }
    let body;
    try {
      body = await readBody(req);
    } catch {
      res.writeHead(413).end();
      return;
    }
    const path = (req.url ?? "").split("?")[0];

    // Pairing is unauthenticated by nature; the one-time secret in the link carries the trust.
    if (req.method === "GET" && path === "/pair") {
      res.setHeader("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'");
      res.setHeader("cache-control", "no-store");
      res.setHeader("referrer-policy", "no-referrer");
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(PAIR_PAGE);
      return;
    }
    if (req.method === "GET" && path === "/pair/key") {
      const p = activePairing();
      if (!p) res.writeHead(404).end();
      else res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ pub: p.pub }));
      return;
    }
    if (req.method === "POST" && path === "/pair/claim") {
      const sealed = claim(body);
      if (!sealed) {
        res.writeHead(401).end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(sealed));
      opts.onPaired?.();
      return;
    }
    if (req.method === "POST" && path === "/pair/request") {
      const p = activePairing();
      if (!p || Date.now() - p.openedAt > PAIR_REOPEN_MS) pair();
      res.writeHead(202).end();
      return;
    }

    const nonce = verifyClient(req, path, body);
    if (!nonce) {
      res.writeHead(401).end();
      return;
    }

    if (req.method === "GET" && path === "/health") {
      send(res, nonce, 200, JSON.stringify({ ok: true }), "application/json");
      return;
    }
    if (req.method === "GET" && path === "/poll") {
      const next = queue.shift();
      if (next) {
        send(res, nonce, 200, JSON.stringify(next), "application/json");
        return;
      }
      let settled = false;
      const finish = (work) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (work) send(res, nonce, 200, JSON.stringify(work), "application/json");
        else send(res, nonce, 204, null);
      };
      const timer = setTimeout(() => finish(null), pollTimeoutMs);
      waiters.push(finish);
      res.on("close", () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        const i = waiters.indexOf(finish);
        if (i >= 0) waiters.splice(i, 1);
      });
      return;
    }
    if (req.method === "POST" && path === "/result") {
      send(res, nonce, 204, null);
      let reply;
      try {
        reply = JSON.parse(body.toString("utf8"));
      } catch {
        return;
      }
      const entry = pending.get(reply.id);
      if (!entry) return;
      pending.delete(reply.id);
      entry.resolve({
        status: reply.status,
        statusText: reply.statusText ?? "",
        headers: reply.headers ?? {},
        body: reply.bodyB64 ? Buffer.from(reply.bodyB64, "base64") : Buffer.alloc(0),
      });
      return;
    }
    send(res, nonce, 404, null);
  };

  const server = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? DEFAULT_PORT, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });

  /**
   * Enqueue one request for the extension to run in-session.
   * @returns {Promise<{status:number, statusText:string, headers:object, body:Buffer}>}
   */
  const request = ({ method = "GET", url, headers = {}, body = null, signal, kind } = {}) => {
    const id = randomBytes(12).toString("hex");
    return new Promise((resolve, reject) => {
      if (signal?.aborted) {
        reject(abortError());
        return;
      }
      const onAbort = () => {
        pending.delete(id);
        reject(abortError());
      };
      pending.set(id, {
        resolve: (r) => {
          signal?.removeEventListener("abort", onAbort);
          resolve(r);
        },
        reject: (e) => {
          signal?.removeEventListener("abort", onAbort);
          reject(e);
        },
      });
      signal?.addEventListener("abort", onAbort, { once: true });
      dispatch(
        kind === "visit" ? { id, kind, url } : { id, method: method.toUpperCase(), url, headers, body },
      );
    });
  };

  /**
   * Ask the extension to open `url` as a page in a background tab, for apps whose own login a page
   * load renews but an API call doesn't. Resolves 200 once the page settles on the target origin,
   * or 401 when it is left open on a sign-in page for the user.
   */
  const visit = ({ url, signal } = {}) => request({ kind: "visit", url, signal });

  const close = () =>
    new Promise((resolve) => {
      for (const w of waiters.splice(0)) w(null);
      for (const { reject } of pending.values()) reject(new Error("bridge closed"));
      pending.clear();
      server.close(() => resolve());
      server.closeAllConnections?.();
    });

  const address = server.address();
  port = typeof address === "object" && address ? address.port : (opts.port ?? DEFAULT_PORT);
  return { request, visit, port, token, close, pair };
}
