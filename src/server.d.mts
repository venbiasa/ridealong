/** Default 127.0.0.1 port of the bridge; the extension assumes it unless told otherwise. */
export const DEFAULT_PORT: number;
/** The protocol tag every signature covers. */
export const PROTOCOL_VERSION: string;
/** Signed requests older or newer than this are refused (replay window). */
export const MAX_CLOCK_SKEW_MS: number;

/** What the extension signs for each request. */
export function clientMessage(
  method: string,
  path: string,
  ts: number,
  nonce: string,
  bodyHash: string,
): string;
/** What the bridge signs for each response. */
export function serverMessage(nonce: string, status: number, bodyHash: string): string;
/** Signs a request the way the extension does. For other clients of the protocol and for tests. */
export function signRequest(
  token: string,
  method: string,
  path: string,
  body?: string,
): { headers: Record<string, string>; nonce: string };
/** Checks a response's proof the way the extension does. */
export function verifyResponse(
  token: string,
  nonce: string,
  status: number,
  body: string | Uint8Array,
  proof: string | null,
): boolean;
/** The key both sides derive while pairing (see PROTOCOL.md). */
export function pairingKey(
  secret: string,
  sharedSecret: Uint8Array,
  bridgePub: string,
  extensionPub: string,
): Buffer;
/** Opens a URL in the default browser; failures are silent, so callers should also print it. */
export function openInBrowser(url: string): void;

/** One request for the extension to run inside the user's signed-in session. */
export interface BridgeRequest {
  method?: string;
  url: string;
  headers?: Record<string, string>;
  body?: string | null;
  signal?: AbortSignal;
}

/** The extension's answer. A body of a redirect off the target origin is replaced by a 401 note. */
export interface BridgeResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: Buffer;
}

export interface BridgeOptions {
  /** 0 picks a free port (tests); default {@link DEFAULT_PORT}. */
  port?: number;
  /** Fixed token so a paired extension stays paired across runs; default a fresh 256-bit one. */
  token?: string;
  pollTimeoutMs?: number;
  /** Receives each pairing link; the caller opens it in the browser that has the extension. */
  onPairingUrl?: (url: string) => void;
  onPaired?: () => void;
}

export interface Bridge {
  /**
   * Enqueues a request for the extension. Rejects with an `AbortError` when `signal` aborts, and
   * with "bridge closed" when the bridge closes first.
   */
  request(req: BridgeRequest): Promise<BridgeResponse>;
  /**
   * Has the extension open `url` as a page in a background tab, which renews an app's own login
   * that an API call doesn't. 200 once it settles on the target origin; 401 when it is left open on
   * a sign-in page for the user.
   */
  visit(req: { url: string; signal?: AbortSignal }): Promise<BridgeResponse>;
  /** Starts (or re-opens) click-to-pair through `onPairingUrl`. */
  pair(): void;
  /** Whether an extension holding the token has polled since the bridge started. */
  connected(): boolean;
  readonly port: number;
  readonly token: string;
  close(): Promise<void>;
}

/** Starts the bridge on 127.0.0.1. Rejects with the listen error (`EADDRINUSE`) if the port is taken. */
export function startBridge(opts?: BridgeOptions): Promise<Bridge>;
