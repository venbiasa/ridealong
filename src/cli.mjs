#!/usr/bin/env node
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { startBridge, DEFAULT_PORT } from "./server.mjs";

const HELP = `ridealong — read browser-gated services (IAP, SSO, ZTNA) through your signed-in browser

Usage:
  ridealong serve [--port <n>] [--no-open]
                                          run the bridge; opens a pairing page in your browser
  ridealong get <url> [--method <m>] [--body <s>] [--port <n>] [--timeout <ms>] [--no-open]
                [--include] [--visit <url>]
                                          fetch one URL through the extension, print the body
                                          (--include: status and headers to stderr;
                                           --visit: first open <url> as a page in a background tab,
                                           for apps whose own login a page load renews)
  ridealong token                         print a fresh token for RIDEALONG_TOKEN

Pairing: the bridge opens a page in your default browser; the ridealong extension picks it up and
you click Pair. If that isn't the browser with the extension, copy the printed link into it.

Set RIDEALONG_TOKEN to keep the same token across runs, so a paired extension stays paired when the
bridge restarts (handy for repeated 'get' calls).`;

function flag(argv, name, fallback) {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : fallback;
}

function openInBrowser(url) {
  const [cmd, args] =
    process.platform === "darwin"
      ? ["open", [url]]
      : process.platform === "win32"
        ? ["cmd", ["/c", "start", "", url]]
        : ["xdg-open", [url]];
  try {
    const child = spawn(cmd, args, { stdio: "ignore", detached: true });
    child.on("error", () => {});
    child.unref();
  } catch {
    // The printed link is the fallback.
  }
}

function pairingHooks(rest) {
  const noOpen = rest.includes("--no-open");
  return {
    onPairingUrl: (url) => {
      process.stderr.write(`ridealong: pair the extension by opening ${url}\n`);
      if (!noOpen) openInBrowser(url);
    },
    onPaired: () => process.stderr.write("ridealong: paired with the extension.\n"),
  };
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const port = Number(flag(rest, "port", process.env.RIDEALONG_PORT ?? DEFAULT_PORT));
  const pinnedToken = process.env.RIDEALONG_TOKEN || undefined;

  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    process.stdout.write(`${HELP}\n`);
    return cmd ? 0 : 1;
  }

  if (cmd === "token") {
    process.stdout.write(`${randomBytes(32).toString("base64url")}\n`);
    return 0;
  }

  if (cmd === "serve") {
    const bridge = await startBridge({ port, token: pinnedToken, ...pairingHooks(rest) });
    process.stderr.write(`ridealong: listening on 127.0.0.1 port ${bridge.port}\n`);
    // A pinned token may already be in the extension; an unpaired extension asks for pairing itself.
    if (!pinnedToken) bridge.pair();
    await new Promise(() => {}); // run until killed
    return 0;
  }

  if (cmd === "get") {
    const valueFlags = new Set(["--method", "--body", "--port", "--timeout", "--visit"]);
    const url = rest.find((a, i) => !a.startsWith("--") && !valueFlags.has(rest[i - 1]));
    if (!url) {
      process.stderr.write("ridealong: usage: ridealong get <url>\n");
      return 2;
    }
    // Long enough for a first-time pairing or a click on the extension's Allow page.
    const timeoutMs = Number(flag(rest, "timeout", 120_000));
    const bridge = await startBridge({ port, token: pinnedToken, ...pairingHooks(rest) });
    if (!pinnedToken) bridge.pair();
    try {
      const visitUrl = flag(rest, "visit", null);
      if (visitUrl) {
        const opened = await bridge.visit({ url: visitUrl, signal: AbortSignal.timeout(timeoutMs) });
        if (opened.status !== 200) {
          process.stderr.write(`${opened.body.toString("utf8")}\n`);
          return 1;
        }
      }
      const res = await bridge.request({
        method: flag(rest, "method", "GET"),
        url,
        body: flag(rest, "body", null),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (rest.includes("--include")) {
        const lines = [`${res.status} ${res.statusText}`.trim()];
        for (const [k, v] of Object.entries(res.headers)) lines.push(`${k}: ${v}`);
        process.stderr.write(`${lines.join("\n")}\n\n`);
      }
      process.stdout.write(res.body);
      if (!process.stdout.write("")) await new Promise((r) => process.stdout.once("drain", r));
      return res.status >= 400 ? 1 : 0;
    } catch (err) {
      if (err?.name === "AbortError") {
        const hint = pinnedToken
          ? "Check that Chrome is open and the extension is paired with this RIDEALONG_TOKEN."
          : "Without RIDEALONG_TOKEN every run needs a new pairing: click Pair on the page it opened, " +
            "or set RIDEALONG_TOKEN once (see `ridealong help`).";
        process.stderr.write(`ridealong: no answer from the extension within ${timeoutMs / 1000}s. ${hint}\n`);
        return 1;
      }
      process.stderr.write(`ridealong: ${err?.message ?? err}\n`);
      return 1;
    } finally {
      await bridge.close();
    }
  }

  process.stderr.write(`ridealong: unknown command '${cmd}'. Run \`ridealong help\`.\n`);
  return 2;
}

main().then(
  (code) => {
    if (typeof code === "number" && code > 0) process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`ridealong: ${err?.message ?? err}\n`);
    process.exitCode = 1;
  },
);
