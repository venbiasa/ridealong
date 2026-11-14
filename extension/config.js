import { DEFAULT_PORT } from "./auth.js";

/** Parses the optional port field; empty means the default. */
export function parsePort(text) {
  const trimmed = text.trim();
  if (trimmed === "") return DEFAULT_PORT;
  const port = Number(trimmed);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error("Port must be a whole number between 1024 and 65535");
  }
  return port;
}

/** The Chrome permission pattern covering a target URL's origin, or null when it isn't https. */
export function accessPattern(url) {
  return url.protocol === "https:" ? `${url.origin}/*` : null;
}

/**
 * The https origin a grant page was opened for, from its `?origin=` parameter, or null when the
 * parameter is anything but a bare https origin.
 */
export function grantOrigin(search) {
  const raw = new URLSearchParams(search).get("origin");
  if (!raw) return null;
  try {
    const u = new URL(raw);
    return u.protocol === "https:" && u.origin === raw ? u.origin : null;
  } catch {
    return null;
  }
}

/** Granted https host patterns (`https://host/*`) shown without the scheme and path, sorted. */
export function grantedHosts(origins) {
  return origins
    .filter((o) => o.startsWith("https://") && o.endsWith("/*"))
    .map((o) => o.slice("https://".length, -"/*".length))
    .sort();
}
