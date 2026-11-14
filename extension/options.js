// Settings page. Config and the pairing token live in chrome.storage.local (extension-only);
// nothing goes to window.localStorage.

import { BridgeVerificationError, DEFAULT_PORT, bridgeCall } from "./auth.js";
import { grantedHosts, parsePort } from "./config.js";

const $ = (id) => document.getElementById(id);

function show(message, ok) {
  $("status").textContent = message;
  $("status").className = ok ? "ok" : "err";
}

async function renderPairState() {
  const { token, port } = await chrome.storage.local.get(["token", "port"]);
  $("pairState").textContent = token
    ? `Paired with the bridge on port ${port ?? DEFAULT_PORT}.`
    : "Not paired. Start the bridge; it opens a pairing page in this browser.";
  $("unpair").disabled = !token;
}

async function renderHosts() {
  const { origins = [] } = await chrome.permissions.getAll();
  const hosts = grantedHosts(origins);
  const list = $("hosts");
  list.replaceChildren();
  if (hosts.length === 0) {
    const empty = document.createElement("li");
    empty.className = "hint";
    empty.textContent = "None yet.";
    list.append(empty);
    return;
  }
  for (const host of hosts) {
    const item = document.createElement("li");
    const name = document.createElement("code");
    name.textContent = host;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "Remove";
    remove.addEventListener("click", async () => {
      await chrome.permissions.remove({ origins: [`https://${host}/*`] });
      show(`Removed ${host}. The next request to it asks again.`, true);
    });
    item.append(name, remove);
    list.append(item);
  }
}

async function load() {
  const { port } = await chrome.storage.local.get(["port"]);
  if (Number.isInteger(port) && port !== DEFAULT_PORT) $("port").value = String(port);
  await Promise.all([renderPairState(), renderHosts()]);
}

async function save() {
  let port;
  try {
    port = parsePort($("port").value);
  } catch (e) {
    return show(e.message, false);
  }
  await chrome.storage.local.set({ port });
  show(`Saved port ${port}.`, true);
}

async function test() {
  let port;
  try {
    port = parsePort($("port").value);
  } catch (e) {
    return show(e.message, false);
  }
  const { token } = await chrome.storage.local.get(["token"]);
  if (!token) return show("Not paired yet. Start the bridge and click Pair on the page it opens.", false);
  try {
    const res = await bridgeCall(port, token, "GET", "/health");
    if (res.status === 200) show("Connected. The bridge proved it holds the pairing token.", true);
    else if (res.status === 401) show("This bridge doesn't know the pairing. Restart it to pair again.", false);
    else show(`The bridge answered ${res.status}.`, false);
  } catch (e) {
    if (e instanceof BridgeVerificationError) {
      show(`Something else is listening on port ${port} and failed verification. Not using it.`, false);
    } else {
      show(`Could not reach a bridge on port ${port}. Is \`ridealong serve\` running?`, false);
    }
  }
}

async function unpair() {
  await chrome.storage.local.remove(["token"]);
  // Leave the pairing-request backoff in place so unpairing doesn't immediately pop a new tab.
  await chrome.storage.session.set({ pairRequestedAt: Date.now() });
  await renderPairState();
  show("Unpaired.", true);
}

$("save").addEventListener("click", save);
$("test").addEventListener("click", test);
$("unpair").addEventListener("click", unpair);
chrome.storage.local.onChanged.addListener(() => void renderPairState());
chrome.permissions.onAdded.addListener(() => void renderHosts());
chrome.permissions.onRemoved.addListener(() => void renderHosts());
load();
