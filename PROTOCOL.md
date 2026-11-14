# The ridealong bridge protocol (`ridealong-v1`)

ridealong is two halves that talk over a tiny local HTTP protocol:

- a **bridge server** on `127.0.0.1` (the reference one is `src/server.mjs`; any tool can implement it);
- a **browser extension** that long-polls the server, runs each request inside the user's signed-in
  session, and posts the response back.

The server never sees the gated service's credentials — the browser attaches them. Only response
bytes cross the bridge. Any tool that implements the server side can read a browser-gated service.

## Pairing: getting the token to the extension with one click

The server mints a pairing session — a one-time **secret** (32 random bytes, base64url, valid 10
minutes) and an ephemeral ECDH P-256 key pair — and opens `http://127.0.0.1:<port>/pair#<secret>`
in the user's browser. The secret sits in the fragment, so it never reaches any server.

1. `GET /pair` serves a static page with no secret in it. The extension's content script on that
   page reads the fragment, strips it from the address bar, and hands it to the service worker,
   which takes the port from the page URL Chrome reports and opens the extension's own Pair page.
2. When the user clicks **Pair**, the extension calls `GET /pair/key` → `{"pub": "<base64url
   uncompressed point>"}` (`404` when no pairing is active), generates its own P-256 key pair, and
   derives
   `Z = ECDH(own private, bridge pub)` (32-byte x-coordinate) and
   `K = HMAC-SHA256(key=utf8(secret), "ridealong-v1|pair|<hex Z>|<bridge pub>|<extension pub>")`.
3. It posts `POST /pair/claim` `{"pub": "<extension pub>", "confirm": hex(HMAC(K, "ridealong-v1|pair-client"))}`.
   The server derives the same `K`, checks `confirm` in constant time (`401` if wrong), ends the
   pairing session (the link is single-use), and answers
   `{"iv": "<12 bytes>", "ct": "<AES-256-GCM(K, token) || 16-byte tag>"}` with additional data
   `ridealong-v1|pair-token`, all base64url.
4. The extension decrypts. A failed decryption means whatever answered did not mint the link; the
   extension refuses it.

`POST /pair/request` (no body) asks a running server to open its pairing page — an unpaired
extension sends it after a browser restart, or when the server answers `401` (it restarted). The
server reopens at most once a minute and answers `202`; the extension asks at most once every 10
minutes.

Pairing endpoints are unauthenticated by design, but the `Host` and `Origin` checks below still
apply, so a web page can neither trigger nor complete a pairing.

## Authentication: both directions, token never sent

After pairing, both halves share a high-entropy **token**. It is never put on the wire again. Instead each request and each response carries an HMAC keyed by it, so
neither side trusts the other until it has proved it holds the token. A program that grabs the port
first can't learn the token and can't hand the extension work.

Notation: `HMAC(m)` is HMAC-SHA256 keyed by the UTF-8 bytes of the token, hex-encoded (lowercase).
`H(b)` is the lowercase hex SHA-256 of the raw body bytes (the empty body included).

### Request (extension → server)

Every request carries three headers:

| Header | Value |
| --- | --- |
| `x-ridealong-ts` | sender's clock, milliseconds since the epoch |
| `x-ridealong-nonce` | 16 random bytes, 32 lowercase hex characters, never reused |
| `x-ridealong-auth` | `HMAC("ridealong-v1\|client\|<METHOD>\|<path>\|<ts>\|<nonce>\|<H(body)>")` |

`<path>` is the request path without the query string (`/poll`). The server **rejects with `401`**
(no proof) when:

- any header is missing or malformed;
- `ts` is more than **120 s** away from its own clock;
- it has already seen the nonce (it remembers nonces for 240 s, which covers the whole window);
- the signature does not match (compared in constant time).

### Response (server → extension)

Every non-`401` response carries:

```
x-ridealong-proof: HMAC("ridealong-v1|server|<nonce>|<status>|<H(response body)>")
```

where `<nonce>` is the request's nonce. The extension **rejects any response whose proof doesn't
verify** — it never acts on its body — and backs off before retrying. A `401` without a proof means
"wrong token": the extension forgets its token and asks the server to pair again.

## Endpoints

The server also requires the `Host` header to be loopback (`127.0.0.1`/`localhost`, else `403`) and
rejects any `Origin` that is not `chrome-extension://…`. The default port is `8731`.

### `GET /health`

Returns `200 {"ok":true}`. Used by the extension's "Test connection".

### `GET /poll` (long-poll)

The extension calls this in a loop. The server answers with the next queued request as JSON:

```json
{ "id": "…", "method": "GET", "url": "https://service.example.com/api", "headers": {}, "body": null }
```

If no request is queued within the server's window (~25 s), it answers `204`; the extension polls
again.

A work item with `"kind": "visit"` asks the extension to **open the URL as a page** instead of
fetching it, for apps whose own login is renewed by a page load but not by an API call:

```json
{ "id": "…", "kind": "visit", "url": "https://service.example.com/" }
```

The extension opens it in a background tab, waits for the page to settle back on the target origin,
closes the tab, and posts `200` with `{"url": "<final URL>"}`. If the page is still elsewhere (a
sign-in page waiting for the user) after ~20 s, it leaves the tab open, brings it to the front, and
posts `401`. The same per-origin access rule applies.

### `POST /result`

The extension posts the outcome of one request:

```json
{ "id": "…", "status": 200, "statusText": "OK", "headers": { "content-type": "application/json" }, "bodyB64": "…" }
```

`bodyB64` is the response body, base64-encoded. The server matches `id` to the pending request and
resolves it. The server replies `204`.

## Extension responsibilities

- Fetch the target with `credentials: "include"` so the browser attaches the session cookies.
- Only ever reach **https** origins the **user granted**. The reference extension asks on first use:
  it opens a page naming the origin, and the user's click there triggers Chrome's own permission
  prompt. A request waits for that answer (up to two minutes) and gets `403` if it is refused.
- Never forward any `Authorization` header to the target.
- Strip `content-encoding`, `content-length`, `transfer-encoding` from the returned headers (the body
  is already decoded), and never return `set-cookie`.
- If the response was redirected off the target origin, the gateway bounced it to a sign-in page:
  return `401` with a short "session expired, sign in again" message instead of the sign-in HTML.

## Security requirements (both halves)

- Keep the token in extension-private storage (the reference extension uses `chrome.storage.local`
  so pairing survives a browser restart); never in web-page-reachable storage such as
  `window.localStorage`. Keep the one-time pairing secret in memory only.
- The server binds to `127.0.0.1`, never `0.0.0.0`.
- The loopback `Host` check defends against DNS rebinding; the `Origin` check and the request
  signature defend against a malicious local web page; the response proof defends against a program
  squatting on the port.
