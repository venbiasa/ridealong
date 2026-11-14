# ridealong

Read a **browser-gated service** — one behind Google IAP, Cloudflare Access, an SSO proxy or other
zero-trust gateway — from a local tool, by **riding your own signed-in browser session**. You
authenticate exactly the way you already do, in the browser; ridealong never copies a credential out
of it.

It's for the case where a gateway allows only two things: a human in a browser, or a client an admin
has allowlisted — and you can't get the second. ridealong is the first, automated.

```
your tool ──HTTP──▶ ridealong bridge (127.0.0.1)
                          │  long-poll, signed both ways
                          ▼
                 ridealong extension (your signed-in Chrome)
                          │  fetch(service, { credentials: "include" })   ← browser attaches the cookies
                          ▼
                 the gated service
```

The bridge never sees the service's cookies or credentials — only the response bytes come back.

## What's in the box

- **A Chrome extension** (`extension/`) — generic: you allow each host the first time it's used; it has no
  knowledge of any particular service.
- **A bridge server + CLI** (`src/`, command `ridealong`) — dependency-free Node, so any tool can
  drive it, and you can use it on its own.
- **[`PROTOCOL.md`](PROTOCOL.md)** — the tiny local protocol, so other tools can implement the server
  side (butlerbridge, for example, speaks it to read IAP-gated Jenkins).

## Setup

1. **Run the bridge:**
   ```bash
   npx ridealong serve
   ```
   It listens on `127.0.0.1` port `8731` and opens a pairing page in your default browser (the link is
   also printed; `--no-open` skips opening it).
2. **Load the extension:** `chrome://extensions` → **Developer mode** → **Load unpacked** → pick
   `extension/`. (If your organization blocks unpacked extensions by policy — `chrome://policy` — this
   route is closed.)
3. **Pair:** on the page the bridge opened, click **Pair**. Nothing to type, copy or paste. If the page opened in a browser without the extension, copy its full link into
   the one that has it. The pairing survives browser restarts; when the bridge restarts with a new
   token, the extension asks it to reopen the page and you click **Pair** again.
4. **Allow each host once:** the first request to a host opens an **Allow access** page in that
   browser. Click **Allow**, then approve Chrome's own permission prompt, and the request carries on.
   Allowed hosts are listed in the extension's options, where **Remove** takes one back.
5. **Sign in:** open each target service in the same browser and sign in through its gateway as usual.

## Use it

One-shot fetch from the shell:

```bash
ridealong get https://service.example.com/api/thing
```

If the service has its own login that a page load renews but an API call doesn't (Jenkins behind
IAP, for example), add `--visit <url>`: the extension first opens that URL in a background tab, waits
for it to settle, and closes it. `--include` prints the status and headers to stderr.

Each run starts its own bridge, so it asks you to pair. To skip that on repeated runs, pin a token
(`export RIDEALONG_TOKEN=$(ridealong token)`) and pair once; the extension then stays paired across
bridge runs.

Or let another tool drive the bridge over [the protocol](PROTOCOL.md).

## Security properties

- **The token is stored in the extension's own storage** (`chrome.storage.local`), so pairing
  survives a browser restart. No web page can read it, and it is never in `window.localStorage`.
  It does sit unencrypted in your Chrome profile on disk, so a program running as you could read it
  and pose as your bridge; **Unpair** in the extension's options deletes it. The one-time pairing
  secret stays in memory only (`chrome.storage.session`).
- **Access is granted per host, by you, on first use.** A request to a host the extension can't yet
  reach opens an **Allow access** page naming it. Nothing runs until you click Allow and approve
  Chrome's permission prompt (the click is required: Chrome lets an extension ask only from a user
  gesture). A Deny, a closed tab or two minutes of silence refuses the request, and after a Deny the
  page doesn't reopen for that host for two minutes. Only https is ever allowed, one exact origin at
  a time.
- **Click-to-pair hands the token over without exposing it.** The pairing link carries a one-time,
  10-minute secret in its `#fragment` (never sent to any server). The extension and the bridge run
  an ECDH exchange keyed by that secret, and the token travels encrypted under the result, so
  neither the link (which lands in browser history) nor the exchange alone reveals it. A web page
  can't trigger pairing, and the Pair page tells you to pair only if you just started a bridge.
- **The token is never sent after that.** The extension HMAC-signs every call to the bridge, and the
  bridge must sign every answer. A program that grabs the port first can't learn the token, and the
  extension refuses work from anything that can't prove it holds it. Replays are refused (nonce plus
  a 120 s clock window). Details in [`PROTOCOL.md`](PROTOCOL.md).
- **Requests go only to https origins you allowed.** Anything else is refused.
- **The bridge binds to `127.0.0.1`** and rejects a bad `Origin` (must be `chrome-extension://…`) or
  `Host` (loopback only, against DNS rebinding).
- **An expired session is detected** (the gateway redirects off the target origin) and the extension
  opens the target in a new tab so you can sign in again, at most once every 2 minutes per origin. The
  request fails with "sign in, then retry" rather than a broken response.
- **It respects the gateway.** ridealong does not extract cookies, bypass the gateway, or weaken it —
  it rides the session the gateway already granted you. It changes nothing on the gateway and needs no
  administrator action. It cannot grant access you don't already have in the browser.

## Develop

```bash
node --test        # no dependencies to install
```
