/**
 * Content script — isolated-world bridge.
 *
 * Runs in the extension's isolated world on every dApp page (matches
 * `<all_urls>` in the manifest). Two responsibilities:
 *
 *   1. Inject the in-page provider script into the page's main world,
 *      so `window.tenzro` and the EIP-6963 / Wallet-Standard announcers
 *      run with the page's own JS realm (and thus appear as "trusted"
 *      to dApp code that introspects the provider).
 *
 *   2. Bridge `window.postMessage` (page world ↔ content script) to the
 *      service worker via `chrome.runtime.connect()`. The page never
 *      talks to the service worker directly — this script is the only
 *      crossing point.
 *
 * Wire format is defined in `./types.ts`. We trust nothing about the
 * page's message shape: every inbound message is type-narrowed before
 * being forwarded, and every outbound message carries the fixed
 * `BRIDGE_TARGET_INPAGE` discriminator so other listeners on the page
 * can ignore it cheaply.
 */

import {
  BRIDGE_TARGET_CONTENT,
  BRIDGE_TARGET_INPAGE,
  BridgeRequest,
  BridgeResponse,
  RPC_ERROR_CODES,
} from "./types";

// ─── chrome.runtime narrow surface ───────────────────────────────────────
// We only use a tiny slice of the WebExtension API and don't want to pull
// `@types/chrome` (or `webextension-polyfill`) into the bundle. Declare
// just what we touch here.

interface RuntimePort {
  readonly name: string;
  postMessage(message: unknown): void;
  onMessage: { addListener(cb: (message: unknown) => void): void };
  onDisconnect: { addListener(cb: () => void): void };
  disconnect(): void;
}

interface RuntimeApi {
  connect(connectInfo?: { name?: string }): RuntimePort;
  getURL(path: string): string;
  readonly id?: string;
}

interface BrowserGlobal {
  runtime?: RuntimeApi;
}

declare const chrome: BrowserGlobal | undefined;
declare const browser: BrowserGlobal | undefined;

function getRuntime(): RuntimeApi {
  const runtime =
    (typeof chrome !== "undefined" && chrome?.runtime) ||
    (typeof browser !== "undefined" && browser?.runtime);
  if (!runtime) {
    throw new Error(
      "tenzro-inject content script: no chrome.runtime / browser.runtime — " +
        "this script must run in an extension content-script context",
    );
  }
  return runtime;
}

// ─── In-page provider injection ──────────────────────────────────────────

/**
 * Inject `inpage.js` into the page's main world.
 *
 * MV3 prefers `chrome.scripting.executeScript({ world: "MAIN" })` for
 * privileged scripts, but content scripts can't call `chrome.scripting`
 * directly. The manifest's `content_scripts[].world: "MAIN"` is one path,
 * but it changes the script's privilege model — we'd lose access to
 * `chrome.runtime` here. So we take the classic route: append a
 * `<script src=...>` tag whose URL is `chrome-extension://<id>/inpage.js`
 * (resolved via `chrome.runtime.getURL`). The browser fetches it from
 * the extension package and runs it in the page's main world.
 *
 * Inserted at `document_start` (per the manifest's `run_at`) so it
 * executes before any dApp code.
 */
export function injectInPageScript(): void {
  const runtime = getRuntime();
  const scriptUrl = runtime.getURL("inpage.js");

  const script = document.createElement("script");
  script.src = scriptUrl;
  script.type = "text/javascript";
  script.async = false; // preserve document-start ordering

  // Remove the tag from the DOM after load so it doesn't pollute
  // dApp introspection of `<head>` / `<html>` children.
  script.onload = () => {
    script.remove();
  };

  // Append to <html> (not <head>/<body>) — at document_start the
  // <head> may not exist yet on some browsers.
  const root = document.documentElement;
  root.insertBefore(script, root.firstChild);
}

// ─── Page ↔ service-worker bridge ────────────────────────────────────────

interface BridgeContext {
  port: RuntimePort;
  /**
   * Page-side requests waiting on a service-worker response.
   * Keyed by request id; value is the page's window for postMessage echo.
   */
  pending: Set<string>;
}

function isBridgeRequest(value: unknown): value is BridgeRequest {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    v.target === BRIDGE_TARGET_CONTENT &&
    typeof v.id === "string" &&
    (v.kind === "rpc" || v.kind === "session")
  );
}

function isBridgeResponse(value: unknown): value is BridgeResponse {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    v.target === BRIDGE_TARGET_INPAGE &&
    (v.kind === "rpc-response" || v.kind === "event")
  );
}

/**
 * Establish the long-lived port to the service worker and wire the
 * bidirectional bridge. Idempotent: subsequent calls are no-ops.
 */
export function startBridge(): BridgeContext {
  const runtime = getRuntime();
  const port = runtime.connect({ name: "tenzro-inject" });
  const ctx: BridgeContext = {
    port,
    pending: new Set(),
  };

  // ── Page → service worker ──
  // Listen for postMessage envelopes from the in-page provider and
  // forward request kinds to the service worker. We ignore everything
  // that isn't tagged for us — the page is full of foreign messages.
  window.addEventListener("message", (event: MessageEvent) => {
    // postMessage spec: the source is the window that sent it. Reject
    // anything not from this top-level frame to avoid relaying messages
    // that originated in untrusted iframes (the dApp's main JS context
    // is always `window`, which equals `event.source` for same-frame
    // messages).
    if (event.source !== window) return;

    if (!isBridgeRequest(event.data)) return;

    const message = event.data;

    // Origin is asserted by the in-page provider, but we re-stamp it
    // from the trusted DOM-level location so the service worker has a
    // ground-truth value. The page can't forge `window.location.origin`
    // from a same-origin script.
    const trustedOrigin = window.location.origin;
    const stamped: BridgeRequest = { ...message, origin: trustedOrigin };

    ctx.pending.add(message.id);
    try {
      ctx.port.postMessage(stamped);
    } catch (err) {
      // Service worker may have been torn down between requests — surface
      // a synthetic disconnect error to the page so it can retry.
      ctx.pending.delete(message.id);
      window.postMessage(
        {
          target: BRIDGE_TARGET_INPAGE,
          id: message.id,
          kind: "rpc-response",
          error: {
            code: RPC_ERROR_CODES.DISCONNECTED,
            message:
              err instanceof Error
                ? `service worker unreachable: ${err.message}`
                : "service worker unreachable",
          },
        },
        trustedOrigin,
      );
    }
  });

  // ── Service worker → page ──
  // Forward responses and events back to the page world. Same trust
  // discipline: type-narrow before forwarding, and target `*` for
  // postMessage because the page world's listener filters by the
  // `target` field anyway.
  ctx.port.onMessage.addListener((message: unknown) => {
    if (!isBridgeResponse(message)) return;

    if (message.kind === "rpc-response") {
      ctx.pending.delete(message.id);
    }

    // postMessage's targetOrigin is the page's *own* origin, which is
    // already known to the page. Use it explicitly rather than `*` so
    // a transient origin change (e.g., document.domain shenanigans)
    // doesn't accidentally leak the response.
    window.postMessage(message, window.location.origin);
  });

  // ── Service worker disconnect ──
  // The MV3 service worker can be killed at any time. When it dies, all
  // pending requests need synthetic disconnect errors so callers don't
  // hang forever. The next outbound message from the page will trigger
  // the runtime to wake the worker back up.
  ctx.port.onDisconnect.addListener(() => {
    for (const id of ctx.pending) {
      window.postMessage(
        {
          target: BRIDGE_TARGET_INPAGE,
          id,
          kind: "rpc-response",
          error: {
            code: RPC_ERROR_CODES.DISCONNECTED,
            message: "service worker disconnected mid-request",
          },
        },
        window.location.origin,
      );
    }
    ctx.pending.clear();
  });

  return ctx;
}

// ─── Auto-start ──────────────────────────────────────────────────────────
// The content script is loaded at `document_start`. Inject and bridge
// immediately — there's no dApp code yet to race with.

injectInPageScript();
startBridge();
