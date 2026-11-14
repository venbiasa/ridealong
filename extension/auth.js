// Signed calls to the local ridealong bridge. The token never leaves the extension: each request
// carries an HMAC of (method, path, time, nonce, body hash) keyed by the token, and each response
// must carry the bridge's HMAC over (nonce, status, body hash). A program squatting on the port can
// neither learn the token nor hand the extension work.

export const DEFAULT_PORT = 8731;
const PROTOCOL_VERSION = "ridealong-v1";
const enc = new TextEncoder();

export class BridgeVerificationError extends Error {}
export class PairingError extends Error {}

let cachedKey = { token: null, key: null };

async function hmacKey(token) {
  if (cachedKey.token !== token) {
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(token),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    cachedKey = { token, key };
  }
  return cachedKey.key;
}

const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function sha256Hex(bytes) {
  return toHex(await crypto.subtle.digest("SHA-256", bytes));
}

async function hmacHex(token, message) {
  return toHex(await crypto.subtle.sign("HMAC", await hmacKey(token), enc.encode(message)));
}

async function hmacBytes(keyBytes, message) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(message)));
}

const toB64url = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function fromB64url(s) {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function randomNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

/** Constant-time string compare. */
function equal(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function bridgeOrigin(port) {
  return `http://127.0.0.1:${port}`;
}

/**
 * Calls the bridge with a signed request and verifies its signed response.
 * Returns { status, text } for a verified response, or { status: 401 } when the bridge rejected
 * our signature (wrong token). Throws BridgeVerificationError when whatever answered could not
 * prove it holds the token.
 */
export async function bridgeCall(port, token, method, path, bodyText = null, signal = undefined) {
  const bodyBytes = enc.encode(bodyText ?? "");
  const ts = Date.now();
  const nonce = randomNonce();
  const auth = await hmacHex(
    token,
    `${PROTOCOL_VERSION}|client|${method}|${path}|${ts}|${nonce}|${await sha256Hex(bodyBytes)}`,
  );
  const headers = { "x-ridealong-ts": String(ts), "x-ridealong-nonce": nonce, "x-ridealong-auth": auth };
  if (bodyText != null) headers["content-type"] = "application/json";
  const res = await fetch(`${bridgeOrigin(port)}${path}`, {
    method,
    headers,
    body: bodyText ?? undefined,
    signal,
  });
  const buf = new Uint8Array(await res.arrayBuffer());
  if (res.status === 401) return { status: 401, text: "" };
  const proof = res.headers.get("x-ridealong-proof") ?? "";
  const expected = await hmacHex(
    token,
    `${PROTOCOL_VERSION}|server|${nonce}|${res.status}|${await sha256Hex(buf)}`,
  );
  if (!equal(proof, expected)) {
    throw new BridgeVerificationError(
      `Something on port ${port} answered but could not prove it is your bridge.`,
    );
  }
  return { status: res.status, text: new TextDecoder().decode(buf) };
}

/**
 * Pairs with the bridge using the one-time secret from its pairing link, and returns the bridge
 * token. An ECDH exchange keyed by the secret means the token never crosses the wire in the clear,
 * and only the bridge that minted the secret can produce a token this decrypts.
 * Throws PairingError when the link is stale or refused, BridgeVerificationError when whatever
 * answered could not prove it minted the link.
 */
export async function pairWithBridge(port, secret) {
  const base = bridgeOrigin(port);
  const keyRes = await fetch(`${base}/pair/key`);
  if (keyRes.status === 404) {
    throw new PairingError("This pairing link expired or was already used. Restart the bridge to get a new one.");
  }
  if (!keyRes.ok) throw new PairingError(`The bridge answered ${keyRes.status}.`);
  const { pub: bridgePub } = await keyRes.json();

  const curve = { name: "ECDH", namedCurve: "P-256" };
  const mine = await crypto.subtle.generateKey(curve, false, ["deriveBits"]);
  const extensionPub = toB64url(new Uint8Array(await crypto.subtle.exportKey("raw", mine.publicKey)));
  let theirs;
  try {
    theirs = await crypto.subtle.importKey("raw", fromB64url(String(bridgePub)), curve, false, []);
  } catch {
    throw new BridgeVerificationError(`Something on port ${port} sent an invalid pairing key.`);
  }
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: theirs }, mine.privateKey, 256));
  const key = await hmacBytes(
    enc.encode(secret),
    `${PROTOCOL_VERSION}|pair|${toHex(shared)}|${bridgePub}|${extensionPub}`,
  );
  const confirm = toHex(await hmacBytes(key, `${PROTOCOL_VERSION}|pair-client`));

  const res = await fetch(`${base}/pair/claim`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ pub: extensionPub, confirm }),
  });
  if (res.status === 401) throw new PairingError("The bridge did not accept this pairing link.");
  if (!res.ok) throw new PairingError(`The bridge answered ${res.status}.`);
  try {
    const { iv, ct } = await res.json();
    const aes = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromB64url(iv), additionalData: enc.encode(`${PROTOCOL_VERSION}|pair-token`) },
      aes,
      fromB64url(ct),
    );
    return new TextDecoder().decode(plain);
  } catch {
    throw new BridgeVerificationError(`Something on port ${port} could not prove it opened this pairing link.`);
  }
}
