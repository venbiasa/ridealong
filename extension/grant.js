import { grantOrigin } from "./config.js";

const $ = (id) => document.getElementById(id);

function show(message, ok) {
  $("status").textContent = message;
  $("status").className = ok ? "ok" : "err";
}

const origin = grantOrigin(location.search);

if (!origin) {
  $("allow").disabled = true;
  $("deny").disabled = true;
  show("This page was opened without a valid https host.", false);
} else {
  $("host").textContent = new URL(origin).host;
  $("origin").textContent = origin;
}

// permissions.request must run straight from the click, before any await.
$("allow").addEventListener("click", () => {
  chrome.permissions.request({ origins: [`${origin}/*`] }).then((granted) => {
    if (!granted) return show("Chrome's permission prompt was declined. Run the command again to retry.", false);
    show("Allowed. The request continues; this tab closes itself.", true);
    setTimeout(() => window.close(), 1200);
  });
});

$("deny").addEventListener("click", async () => {
  const { grantDenied = {} } = await chrome.storage.session.get(["grantDenied"]);
  await chrome.storage.session.set({ grantDenied: { ...grantDenied, [origin]: Date.now() } });
  window.close();
});
