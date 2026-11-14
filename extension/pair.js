import { BridgeVerificationError, pairWithBridge } from "./auth.js";

const $ = (id) => document.getElementById(id);

function show(message, ok) {
  $("status").textContent = message;
  $("status").className = ok ? "ok" : "err";
}

const { pairing } = await chrome.storage.session.get(["pairing"]);

if (!pairing) {
  $("pair").disabled = true;
  show("No pairing request is waiting. Start the bridge (`ridealong serve`); it opens this page.", false);
} else {
  $("port").textContent = String(pairing.port);
}

$("pair").addEventListener("click", async () => {
  $("pair").disabled = true;
  show("Pairing…", true);
  try {
    const token = await pairWithBridge(pairing.port, pairing.secret);
    await chrome.storage.session.remove(["pairing", "pairRequestedAt"]);
    await chrome.storage.local.set({ port: pairing.port, token });
    show("Paired. The first request to each host asks you to allow it. You can close this tab.", true);
  } catch (e) {
    $("pair").disabled = false;
    show(
      e instanceof BridgeVerificationError ? `${e.message} Not pairing with it.` : (e?.message ?? String(e)),
      false,
    );
  }
});
