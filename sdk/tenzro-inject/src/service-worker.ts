/**
 * Service worker — extension background.
 *
 * Owns:
 *   - Reaching the network: the RPC operators staked on chain, discovered
 *     from seed URLs (the SDK's default network unless the extension names
 *     another) and checked to agree on the chain's history (the SDK's
 *     `discoverEndpoints`, as `connectToNetwork` uses it), with failover.
 *   - Origin → session bookkeeping (CAIP-25 sessions), each confirmed by
 *     the user.
 *   - Method routing across CAIP scopes (`routing.ts`).
 *
 * It holds no key, no token and no credential of any kind. Requests carry
 * none: reads are open, and a transaction is already signed by the user's
 * passkey in the open wallet when it arrives here. Methods that would need a
 * key are refused; the page signs them in the wallet window instead.
 */

import {
  BRIDGE_TARGET_CONTENT,
  BRIDGE_TARGET_INPAGE,
  BridgeRequest,
  BridgeResponse,
  CAIP25Scopes,
  RPC_ERROR_CODES,
} from "./types";
import { ScopeConfirmer, SessionStore } from "./session-store";
import { NetworkSettings, parseNetworkSettings, resolveMethodName } from "./routing";
import { DEFAULT_NETWORK, FailoverTransport, discoverEndpoints } from "tenzro-sdk";

// ─── Browser API surface ─────────────────────────────────────────────────

interface RuntimePort {
  readonly name: string;
  readonly sender?: { url?: string; origin?: string };
  postMessage(message: unknown): void;
  onMessage: { addListener(cb: (message: unknown) => void): void };
  onDisconnect: { addListener(cb: () => void): void };
  disconnect(): void;
}

interface MessageSender {
  readonly id?: string;
  readonly url?: string;
  /** Set only for messages from a content script running in a tab. */
  readonly tab?: unknown;
}

interface RuntimeApi {
  readonly id: string;
  onConnect: { addListener(cb: (port: RuntimePort) => void): void };
  onMessage: {
    addListener(
      cb: (
        message: unknown,
        sender: MessageSender,
        sendResponse: (response: unknown) => void,
      ) => boolean | void,
    ): void;
  };
  getURL(path: string): string;
}

interface WindowsApi {
  create(options: { url: string; type: "popup"; width: number; height: number }): Promise<{ id?: number }>;
  onRemoved: { addListener(cb: (windowId: number) => void): void };
}

interface StorageArea {
  get(keys: string | string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

interface StorageApi {
  local: StorageArea;
  onChanged?: {
    addListener(
      cb: (
        changes: Record<string, { oldValue?: unknown; newValue?: unknown }>,
        areaName: string,
      ) => void,
    ): void;
  };
}

interface BrowserGlobal {
  runtime?: RuntimeApi;
  storage?: StorageApi;
  windows?: WindowsApi;
}

declare const chrome: BrowserGlobal | undefined;
declare const browser: BrowserGlobal | undefined;

function getBrowser(): BrowserGlobal {
  if (typeof chrome !== "undefined" && chrome) return chrome;
  if (typeof browser !== "undefined" && browser) return browser;
  throw new Error("tenzro-inject service worker: no chrome / browser global");
}

function getRuntime(): RuntimeApi {
  const runtime = getBrowser().runtime;
  if (!runtime) {
    throw new Error(
      "tenzro-inject service worker: no chrome.runtime / browser.runtime",
    );
  }
  return runtime;
}

function getStorage(): StorageApi | undefined {
  return getBrowser().storage;
}

// ─── The network ─────────────────────────────────────────────────────────

/** Where the network settings are kept (written by the extension's settings page). */
const STORAGE_KEY_NETWORK = "tenzro:network";

/** Until the extension names another, the SDK's default network (its seeds and chain id). */
let settings: NetworkSettings = { seeds: [...DEFAULT_NETWORK.seeds], chainId: DEFAULT_NETWORK.chainId };
let configured = false;
let transport: Promise<FailoverTransport> | undefined;

/**
 * The network to reach: seed URLs to discover the RPC operators from and
 * the chain id they must report. A seed is only a way in: the operators
 * come from consensus state, and only those agreeing on the chain's history
 * are used.
 */
export function configureNetwork(next: NetworkSettings): void {
  const parsed = parseNetworkSettings(next);
  if (!parsed) throw new Error("network settings need https seed URLs and a chain id");
  settings = parsed;
  configured = true;
  transport = undefined;
}

// Read the settings from storage on start, and follow changes to them.
(async () => {
  const storage = getStorage();
  if (!storage) return;
  try {
    const stored = parseNetworkSettings((await storage.local.get(STORAGE_KEY_NETWORK))[STORAGE_KEY_NETWORK]);
    if (stored && !configured) {
      settings = stored;
      transport = undefined;
    }
  } catch {
    // Unreadable storage keeps the default network.
  }
  storage.onChanged?.addListener((changes, areaName) => {
    if (areaName !== "local" || !changes[STORAGE_KEY_NETWORK]) return;
    settings = parseNetworkSettings(changes[STORAGE_KEY_NETWORK].newValue) ?? {
      seeds: [...DEFAULT_NETWORK.seeds],
      chainId: DEFAULT_NETWORK.chainId,
    };
    transport = undefined;
  });
})();

/** The checked operators, discovered once and again after every failure. */
function network(): Promise<FailoverTransport> {
  const s = settings;
  transport ??= discoverEndpoints({ seeds: [...s.seeds], chainId: s.chainId }).then(
    (endpoints) => new FailoverTransport(endpoints.map((e) => e.url)),
  );
  const current = transport;
  current.catch(() => {
    if (transport === current) transport = undefined;
  });
  return current;
}

async function callTenzroRpc(method: string, params: unknown): Promise<unknown> {
  const t = await network();
  const args = Array.isArray(params) || (params && typeof params === "object") ? (params as unknown[] | Record<string, unknown>) : [];
  try {
    return await t.call(method, args);
  } catch (err) {
    // An unreachable operator set is rediscovered on the next call.
    if (!(err && typeof err === "object" && "code" in err)) transport = undefined;
    throw err;
  }
}

// ─── CAIP-25 sessions, confirmed by the user ─────────────────────────────

/** Extension page that renders a pending session request for the user. */
const CONFIRM_PAGE = "confirm.html";

interface PendingConfirmation {
  readonly origin: string;
  readonly requested: CAIP25Scopes;
  readonly resolve: (approved: CAIP25Scopes | null) => void;
}

const pendingConfirmations = new Map<string, PendingConfirmation>();

/**
 * Opens the confirmation window and waits for the user's decision. Closing
 * the window without deciding declines the request.
 */
const confirmInWindow: ScopeConfirmer = async (origin, requested) => {
  const windows = getBrowser().windows;
  if (!windows) return null;
  const requestId = crypto.randomUUID();
  const decision = new Promise<CAIP25Scopes | null>((resolve) => {
    pendingConfirmations.set(requestId, { origin, requested, resolve });
  });
  const win = await windows.create({
    url: getRuntime().getURL(`${CONFIRM_PAGE}?request=${encodeURIComponent(requestId)}`),
    type: "popup",
    width: 380,
    height: 560,
  });
  if (win.id !== undefined) {
    const windowId = win.id;
    windows.onRemoved.addListener((closed) => {
      if (closed === windowId) settleConfirmation(requestId, null);
    });
  }
  return decision;
};

function settleConfirmation(requestId: string, approved: CAIP25Scopes | null): void {
  const pending = pendingConfirmations.get(requestId);
  if (!pending) return;
  pendingConfirmations.delete(requestId);
  pending.resolve(approved);
}

/**
 * Only the extension's own pages may read or answer a pending request. A
 * content script shares the extension id but always carries `sender.tab`,
 * so a page cannot approve its own request through one.
 */
function isExtensionPage(sender: MessageSender): boolean {
  const runtime = getRuntime();
  return (
    sender.id === runtime.id &&
    sender.tab === undefined &&
    typeof sender.url === "string" &&
    sender.url.startsWith(runtime.getURL(CONFIRM_PAGE))
  );
}

const sessionStore = new SessionStore(confirmInWindow);

// ─── Bridge dispatcher ───────────────────────────────────────────────────

async function handleRequest(request: BridgeRequest): Promise<BridgeResponse> {
  if (request.kind === "session") {
    try {
      switch (request.action) {
        case "create": {
          if (!request.params) {
            return {
              target: BRIDGE_TARGET_INPAGE,
              id: request.id,
              kind: "rpc-response",
              error: {
                code: RPC_ERROR_CODES.INVALID_PARAMS,
                message: "session.create requires params",
              },
            };
          }
          const result = await sessionStore.create(request.origin, request.params);
          return {
            target: BRIDGE_TARGET_INPAGE,
            id: request.id,
            kind: "rpc-response",
            result,
          };
        }
        case "revoke":
          sessionStore.revoke(request.origin);
          return {
            target: BRIDGE_TARGET_INPAGE,
            id: request.id,
            kind: "rpc-response",
            result: null,
          };
        case "describe":
          return {
            target: BRIDGE_TARGET_INPAGE,
            id: request.id,
            kind: "rpc-response",
            result: sessionStore.describe(request.origin) ?? null,
          };
      }
    } catch (err) {
      if (err && typeof err === "object" && "code" in err && "message" in err) {
        const e = err as { code: number; message: string };
        return {
          target: BRIDGE_TARGET_INPAGE,
          id: request.id,
          kind: "rpc-response",
          error: { code: e.code, message: e.message },
        };
      }
      return {
        target: BRIDGE_TARGET_INPAGE,
        id: request.id,
        kind: "rpc-response",
        error: {
          code: RPC_ERROR_CODES.INTERNAL_ERROR,
          message: err instanceof Error ? err.message : String(err),
        },
      };
    }
  }

  // RPC kind. The origin must hold a user-approved session that grants
  // this scope and method before anything is sent to the node.
  const denied = sessionStore.authorize(request.origin, request.scope, request.method);
  if (denied) {
    return {
      target: BRIDGE_TARGET_INPAGE,
      id: request.id,
      kind: "rpc-response",
      error: denied,
    };
  }
  const resolved = resolveMethodName(request.scope, request.method);
  if ("error" in resolved) {
    return {
      target: BRIDGE_TARGET_INPAGE,
      id: request.id,
      kind: "rpc-response",
      error: resolved.error,
    };
  }

  try {
    const result = await callTenzroRpc(resolved.rpcMethod, request.params);
    return {
      target: BRIDGE_TARGET_INPAGE,
      id: request.id,
      kind: "rpc-response",
      result,
    };
  } catch (err) {
    // `callTenzroRpc` throws either a JSON-RPC error object or a thrown
    // Error from the fetch layer. Normalise both.
    if (err && typeof err === "object" && "code" in err && "message" in err) {
      const e = err as { code: number; message: string; data?: unknown };
      return {
        target: BRIDGE_TARGET_INPAGE,
        id: request.id,
        kind: "rpc-response",
        error: { code: e.code, message: e.message, data: e.data },
      };
    }
    return {
      target: BRIDGE_TARGET_INPAGE,
      id: request.id,
      kind: "rpc-response",
      error: {
        code: RPC_ERROR_CODES.INTERNAL_ERROR,
        message: err instanceof Error ? err.message : String(err),
      },
    };
  }
}

// ─── Wire-up ─────────────────────────────────────────────────────────────

function isBridgeRequest(value: unknown): value is BridgeRequest {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    v.target === BRIDGE_TARGET_CONTENT &&
    typeof v.id === "string" &&
    (v.kind === "rpc" || v.kind === "session")
  );
}

// The confirmation page reads the pending request it was opened for and
// answers it. Messages from anything but that page are ignored.
getRuntime().onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== "object" || !isExtensionPage(sender)) return;
  const m = message as { kind?: string; requestId?: string; approved?: CAIP25Scopes | null };
  if (typeof m.requestId !== "string") return;
  if (m.kind === "session-confirm:get") {
    const pending = pendingConfirmations.get(m.requestId);
    sendResponse(pending ? { origin: pending.origin, requested: pending.requested } : null);
    return;
  }
  if (m.kind === "session-confirm:decide") {
    settleConfirmation(m.requestId, m.approved ?? null);
    sendResponse(true);
  }
});

getRuntime().onConnect.addListener((port: RuntimePort) => {
  if (port.name !== "tenzro-inject") return;

  port.onMessage.addListener(async (message: unknown) => {
    if (!isBridgeRequest(message)) return;
    const response = await handleRequest(message);
    try {
      port.postMessage(response);
    } catch {
      // Port may have closed between request and response. Drop the
      // response — the content script will surface a synthetic
      // disconnect error to the page world.
    }
  });
});
