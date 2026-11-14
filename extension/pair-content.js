// Runs on the bridge's http://127.0.0.1:<port>/pair page. Hands the one-time secret in the link's
// fragment to the service worker, and strips it from the address bar first.
(() => {
  const secret = location.hash.slice(1);
  if (!/^[A-Za-z0-9_-]{43}$/.test(secret)) return;
  history.replaceState(null, "", location.pathname);
  chrome.runtime.sendMessage({ type: "ridealong-pair", secret });
})();
