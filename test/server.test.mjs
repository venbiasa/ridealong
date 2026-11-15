import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import { after, describe, test } from "node:test";
import { signRequest, startBridge, verifyResponse } from "../src/server.mjs";

const TOKEN = "test-ridealong-token-0123456789";
const URL_A = "https://service.example.test/api/thing";

const open = [];
after(async () => {
  await Promise.all(open.map((b) => b.close()));
});

async function make(pollTimeoutMs = 50) {
  const b = await startBridge({ port: 0, token: TOKEN, pollTimeoutMs });
  open.push(b);
  return b;
}

/** Calls the bridge as the extension would: signed request, verified response. */
async function call(b, method, path, body, token = TOKEN) {
  const { headers, nonce } = signRequest(token, method, path, body ?? "");
  const res = await fetch(`http://127.0.0.1:${b.port}${path}`, {
    method,
    headers: { ...headers, ...(body != null ? { "content-type": "application/json" } : {}) },
    body: body ?? undefined,
  });
  const text = await res.text();
  const proof = res.headers.get("x-ridealong-proof");
  return { status: res.status, text, verified: verifyResponse(token, nonce, res.status, text, proof) };
}

const getWork = async (b) => JSON.parse((await call(b, "GET", "/poll")).text);
const postResult = (b, reply) => call(b, "POST", "/result", JSON.stringify(reply));

/** A raw request so we can set headers fetch() forbids (Host) or replay exact bytes. */
function raw(b, path, headers) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port: b.port, path, method: "GET", headers }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on("error", reject);
    req.end();
  });
}

test("forwards a request and returns the extension's response", async () => {
  const b = await make();
  const p = b.request({ url: URL_A });
  const work = await getWork(b);
  assert.equal(work.method, "GET");
  assert.equal(work.url, URL_A);
  await postResult(b, {
    id: work.id,
    status: 200,
    headers: { "content-type": "application/json", "x-more-data": "false" },
    bodyB64: Buffer.from('{"ok":1}').toString("base64"),
  });
  const res = await p;
  assert.equal(res.status, 200);
  assert.equal(res.headers["x-more-data"], "false");
  assert.deepEqual(JSON.parse(res.body.toString()), { ok: 1 });
});

test("carries the method and body of a POST", async () => {
  const b = await make();
  const p = b.request({ method: "POST", url: URL_A, body: "a=1" });
  const work = await getWork(b);
  assert.equal(work.method, "POST");
  assert.equal(work.body, "a=1");
  await postResult(b, { id: work.id, status: 201 });
  assert.equal((await p).status, 201);
});

test("visit queues a page-open work item and returns the extension's outcome", async () => {
  const b = await make();
  const p = b.visit({ url: URL_A });
  const work = await getWork(b);
  assert.deepEqual(Object.keys(work).sort(), ["id", "kind", "url"]);
  assert.equal(work.kind, "visit");
  assert.equal(work.url, URL_A);
  await postResult(b, { id: work.id, status: 401, bodyB64: Buffer.from("sign in").toString("base64") });
  const res = await p;
  assert.equal(res.status, 401);
  assert.equal(res.body.toString(), "sign in");
});

test("every response carries a proof the extension can verify", async () => {
  const b = await make(30);
  const health = await call(b, "GET", "/health");
  assert.equal(health.status, 200);
  assert.equal(health.verified, true);
  const idle = await call(b, "GET", "/poll");
  assert.equal(idle.status, 204);
  assert.equal(idle.verified, true);
});

test("a bridge with a different token cannot produce a valid proof", async () => {
  const rogue = await startBridge({ port: 0, token: "some-other-token", pollTimeoutMs: 30 });
  open.push(rogue);
  // The extension signs with its token; the rogue bridge rejects it and offers no proof.
  const res = await call(rogue, "GET", "/health");
  assert.equal(res.status, 401);
  assert.equal(res.verified, false);
});

test("a squatter that answers with fake work fails verification and learns no token", async () => {
  const seen = [];
  const squatter = createServer((req, res) => {
    seen.push(JSON.stringify(req.headers));
    res.setHeader("x-ridealong-proof", "0".repeat(64));
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ id: "x", method: "GET", url: "https://mail.example.com/inbox" }));
  });
  await new Promise((r) => squatter.listen(0, "127.0.0.1", r));
  const port = squatter.address().port;
  const res = await call({ port }, "GET", "/poll");
  await new Promise((r) => squatter.close(r));
  assert.equal(res.verified, false);
  assert.equal(seen.join("").includes(TOKEN), false);
});

test("the token itself never appears on the wire", async () => {
  const { headers } = signRequest(TOKEN, "GET", "/poll");
  assert.equal(JSON.stringify(headers).includes(TOKEN), false);
});

test("rejects unsigned, wrongly signed and tampered requests", async () => {
  const b = await make();
  assert.equal((await fetch(`http://127.0.0.1:${b.port}/health`)).status, 401);
  assert.equal((await call(b, "GET", "/health", undefined, "wrong-token")).status, 401);
  // Signed for /health but sent to /poll: the path is part of the signature.
  const { headers } = signRequest(TOKEN, "GET", "/health");
  assert.equal((await fetch(`http://127.0.0.1:${b.port}/poll`, { headers })).status, 401);
});

test("refuses a replayed request", async () => {
  const b = await make();
  const { headers } = signRequest(TOKEN, "GET", "/health");
  assert.equal(await raw(b, "/health", headers), 200);
  assert.equal(await raw(b, "/health", headers), 401);
});

test("refuses a request outside the clock window", async () => {
  const b = await make();
  const { headers } = signRequest(TOKEN, "GET", "/health");
  assert.equal(await raw(b, "/health", { ...headers, "x-ridealong-ts": String(Date.now() - 10 * 60_000) }), 401);
});

test("rejects a non-extension Origin even when signed", async () => {
  const b = await make();
  const { headers } = signRequest(TOKEN, "GET", "/health");
  const res = await fetch(`http://127.0.0.1:${b.port}/health`, { headers: { ...headers, origin: "https://evil.example" } });
  assert.equal(res.status, 401);
});

test("rejects a mismatched Host header (DNS rebinding)", async () => {
  const b = await make();
  assert.equal(await raw(b, "/health", { ...signRequest(TOKEN, "GET", "/health").headers, host: "evil.example" }), 403);
  assert.equal(await raw(b, "/health", { ...signRequest(TOKEN, "GET", "/health").headers, host: `127.0.0.1:${b.port}` }), 200);
});

test("a forged result without a valid signature is ignored", async () => {
  const b = await make();
  const p = b.request({ url: URL_A });
  const work = await getWork(b);
  const forged = await fetch(`http://127.0.0.1:${b.port}/result`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ id: work.id, status: 200, bodyB64: Buffer.from("forged").toString("base64") }),
  });
  assert.equal(forged.status, 401);
  await postResult(b, { id: work.id, status: 200, bodyB64: Buffer.from("real").toString("base64") });
  assert.equal((await p).body.toString(), "real");
});

test("the extension's own client interoperates with the bridge", async () => {
  const { bridgeCall, BridgeVerificationError } = await import("../extension/auth.js");
  const b = await make();
  const health = await bridgeCall(b.port, TOKEN, "GET", "/health");
  assert.equal(health.status, 200);
  assert.equal((await bridgeCall(b.port, "wrong-token", "GET", "/health")).status, 401);

  const p = b.request({ url: URL_A });
  const work = JSON.parse((await bridgeCall(b.port, TOKEN, "GET", "/poll")).text);
  const reply = JSON.stringify({ id: work.id, status: 200, bodyB64: Buffer.from("héllo").toString("base64") });
  assert.equal((await bridgeCall(b.port, TOKEN, "POST", "/result", reply)).status, 204);
  assert.equal((await p).body.toString(), "héllo");

  const squatter = createServer((_req, res) => res.writeHead(200).end("{}"));
  await new Promise((r) => squatter.listen(0, "127.0.0.1", r));
  await assert.rejects(bridgeCall(squatter.address().port, TOKEN, "GET", "/poll"), BridgeVerificationError);
  await new Promise((r) => squatter.close(r));
});

test("rejects the request when its signal aborts", async () => {
  const b = await make();
  const controller = new AbortController();
  const p = b.request({ url: URL_A, signal: controller.signal });
  controller.abort();
  await assert.rejects(p, /abort/i);
});

describe("click-to-pair", () => {
  const secretOf = (url) => new URL(url).hash.slice(1);

  async function pairable(opts = {}) {
    const urls = [];
    let paired = 0;
    const b = await startBridge({
      port: 0,
      pollTimeoutMs: 30,
      onPairingUrl: (u) => urls.push(u),
      onPaired: () => paired++,
      ...opts,
    });
    open.push(b);
    return { b, urls, paired: () => paired };
  }

  test("the extension pairs with one click and receives the bridge token", async () => {
    const { pairWithBridge, bridgeCall } = await import("../extension/auth.js");
    const { b, urls, paired } = await pairable();
    b.pair();
    assert.equal(urls.length, 1);
    assert.match(urls[0], new RegExp(`^http://127\\.0\\.0\\.1:${b.port}/pair#[A-Za-z0-9_-]{43}$`));
    const token = await pairWithBridge(b.port, secretOf(urls[0]));
    assert.equal(token, b.token);
    assert.equal(paired(), 1);
    assert.equal((await bridgeCall(b.port, token, "GET", "/health")).status, 200);
  });

  test("a pairing link works once", async () => {
    const { pairWithBridge, PairingError } = await import("../extension/auth.js");
    const { b, urls } = await pairable();
    b.pair();
    await pairWithBridge(b.port, secretOf(urls[0]));
    await assert.rejects(pairWithBridge(b.port, secretOf(urls[0])), PairingError);
  });

  test("a wrong secret is refused and does not burn the real one", async () => {
    const { pairWithBridge, PairingError } = await import("../extension/auth.js");
    const { b, urls } = await pairable();
    b.pair();
    await assert.rejects(pairWithBridge(b.port, "x".repeat(43)), PairingError);
    assert.equal(await pairWithBridge(b.port, secretOf(urls[0])), b.token);
  });

  test("the token never crosses the wire in the clear while pairing", async () => {
    const { pairWithBridge } = await import("../extension/auth.js");
    const { b, urls } = await pairable();
    b.pair();
    const secret = secretOf(urls[0]);
    const seen = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (...args) => {
      const res = await realFetch(...args);
      seen.push(await res.clone().text());
      return res;
    };
    try {
      await pairWithBridge(b.port, secret);
    } finally {
      globalThis.fetch = realFetch;
    }
    assert.equal(seen.join("").includes(b.token), false);
    const page = await (await fetch(`http://127.0.0.1:${b.port}/pair`)).text();
    assert.equal(page.includes(b.token) || page.includes(secret), false);
  });

  test("a squatter that did not mint the link cannot complete pairing", async () => {
    const { pairWithBridge, BridgeVerificationError } = await import("../extension/auth.js");
    const { createECDH } = await import("node:crypto");
    const fake = createECDH("prime256v1");
    fake.generateKeys();
    const squatter = createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url === "/pair/key") res.end(JSON.stringify({ pub: fake.getPublicKey().toString("base64url") }));
      else res.end(JSON.stringify({ iv: "AAAAAAAAAAAAAAAA", ct: "A".repeat(43) }));
    });
    await new Promise((r) => squatter.listen(0, "127.0.0.1", r));
    try {
      await assert.rejects(pairWithBridge(squatter.address().port, "y".repeat(43)), BridgeVerificationError);
    } finally {
      await new Promise((r) => squatter.close(r));
    }
  });

  test("an unpaired extension can ask the bridge to reopen the page, rate-limited", async () => {
    const { b, urls } = await pairable();
    const ask = () => fetch(`http://127.0.0.1:${b.port}/pair/request`, { method: "POST" });
    assert.equal((await ask()).status, 202);
    assert.equal((await ask()).status, 202);
    assert.equal(urls.length, 1);
  });

  test("a web page cannot trigger or complete pairing", async () => {
    const { b, urls } = await pairable();
    const res = await fetch(`http://127.0.0.1:${b.port}/pair/request`, {
      method: "POST",
      headers: { origin: "https://evil.example" },
    });
    assert.equal(res.status, 401);
    assert.equal(urls.length, 0);
  });

  test("the pairing page itself carries neither the secret nor the token", async () => {
    const { b, urls } = await pairable();
    b.pair();
    const page = await (await fetch(`http://127.0.0.1:${b.port}/pair`)).text();
    assert.ok(!page.includes(secretOf(urls[0])));
    assert.ok(!page.includes(b.token));
  });

  test("no pairing key is offered until pairing starts", async () => {
    const { b } = await pairable();
    assert.equal((await fetch(`http://127.0.0.1:${b.port}/pair/key`)).status, 404);
  });
});

test("connected() turns true once an extension holding the token polls", async () => {
  const b = await make(20);
  assert.equal(b.connected(), false);
  await call(b, "GET", "/health");
  assert.equal(b.connected(), false);
  await call(b, "GET", "/poll", null, "wrong-token");
  assert.equal(b.connected(), false);
  await call(b, "GET", "/poll");
  assert.equal(b.connected(), true);
});

test("the package entry point is the bridge library", async () => {
  const lib = await import("ridealong");
  for (const name of ["startBridge", "signRequest", "verifyResponse", "pairingKey", "openInBrowser"]) {
    assert.equal(typeof lib[name], "function", name);
  }
  assert.equal(lib.DEFAULT_PORT, 8731);
});
