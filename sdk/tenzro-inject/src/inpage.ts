/**
 * In-page provider — runs in the **page (main) world** of the host dApp.
 *
 * The provider object exposed at `window.tenzro` has four facets:
 *
 *   tenzro.request         — flat scoped to `tenzro:mainnet` (CAIP-27 wrapper)
 *   tenzro.evm             — full EIP-1193 surface for the EVM-on-Tenzro view
 *   tenzro.svm             — Solana-shaped methods routing through tenzro_*
 *   tenzro.native          — TDIP / ERC-8004 / ZK / VRF native verbs
 *   tenzro.multichain      — CAIP-25 createSession + CAIP-27 invokeMethod
 *
 * The provider and the extension behind it hold **no key and no
 * credential**. Methods that need the user's authority open the open
 * wallet's window from this page, where the user's passkey signs them
 * (`wallet-window.ts`). Everything else is forwarded through
 * `window.postMessage` to the content script and from there to the
 * extension's MV3 service worker, which sends it to the network unsigned.
 *
 * dApp authors typically don't import this file directly — they consume
 * the provider via `@tenzro/inject/detect`. Extension authors do import
 * this file and call `installTenzroProvider()` from their content script's
 * injected `<script>` tag.
 */

import {
  EIP1193Provider,
  EIP1193RequestArguments,
  EIP1193ProviderRpcError,
  EIP1193EventName,
  EIP6963ProviderInfo,
  EIP6963ProviderDetail,
  CAIP25CreateSessionParams,
  CAIP25CreateSessionResult,
  CAIP27InvokeParams,
  WalletStandardWallet,
  RPC_ERROR_CODES,
  BRIDGE_TARGET_INPAGE,
  BRIDGE_TARGET_CONTENT,
  BridgeRpcRequestMessage,
  BridgeRpcResponseMessage,
  BridgeEventMessage,
  BridgeSessionRequestMessage,
  TENZRO_SCOPES,
  TENZRO_PROVIDER_RDNS,
  TENZRO_PROVIDER_NAME,
  DEFAULT_PLACEHOLDER_ICON,
} from "./types";
import {
  KEY_METHODS,
  PROVIDER_METHODS,
  STANDARD_WALLET_METHODS,
  WALLET_CAPABILITIES,
  WALLET_METHODS,
  CALLS_VERSION,
  supportedExecutionPermissions,
} from "./routing";
import { DEFAULT_WALLET_URL, requestInWallet } from "./wallet-window";

// ─── The open wallet, for everything the user's passkey signs ───────────

/** Sends wallet methods to the open wallet's window and remembers the account it connected. */
class WalletRoute {
  account: string | undefined;

  constructor(readonly url: string) {}

  async request(method: string, params: unknown): Promise<unknown> {
    // Standard wallet methods keep their positional params; Tenzro wallet
    // methods take one params object.
    const one = STANDARD_WALLET_METHODS.has(method)
      ? (params ?? [])
      : Array.isArray(params)
        ? params.length
          ? params[0]
          : undefined
        : params;
    try {
      const result = await requestInWallet<unknown>(this.url, method, one ?? {});
      if (method === "tenzro_connect") {
        const account = (result as { account?: unknown } | null)?.account;
        if (typeof account === "string") this.account = account;
      }
      return result;
    } catch (err) {
      const e = err as { code?: number; message?: string };
      throw new ProviderRpcError(typeof e.code === "number" ? e.code : RPC_ERROR_CODES.INTERNAL_ERROR, e.message ?? String(err));
    }
  }
}

function keyMethodError(method: string): ProviderRpcError {
  return new ProviderRpcError(
    RPC_ERROR_CODES.UNSUPPORTED_METHOD,
    `${method} needs a key this provider does not hold; sign in the open wallet (tenzro_sendTransaction and the other wallet methods)`,
  );
}

// ─── ProviderRpcError implementation ─────────────────────────────────────

class ProviderRpcError extends Error implements EIP1193ProviderRpcError {
  readonly code: number;
  readonly data?: unknown;

  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = "ProviderRpcError";
    this.code = code;
    if (data !== undefined) this.data = data;
  }
}

// ─── Per-request id generation ───────────────────────────────────────────

function newRequestId(): string {
  // crypto.randomUUID is available in all modern browsers and in MV3
  // service workers. Falls back to time + random for very old envs.
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (c && typeof c.randomUUID === "function") return c.randomUUID();
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

// ─── Bridge — page world side ────────────────────────────────────────────

interface PendingRpc {
  readonly resolve: (value: unknown) => void;
  readonly reject: (reason: ProviderRpcError) => void;
}

class InpageBridge {
  private readonly pending = new Map<string, PendingRpc>();
  private readonly eventListeners = new Map<
    string,
    Set<(...args: unknown[]) => void>
  >();
  private readonly origin: string;

  constructor() {
    this.origin = window.location.origin;
    window.addEventListener("message", this.onMessage);
  }

  private readonly onMessage = (event: MessageEvent): void => {
    // Only accept messages from this same window — the content script
    // bridges over `window.postMessage(_, window.location.origin)`.
    if (event.source !== window) return;
    const data = event.data as
      | BridgeRpcResponseMessage
      | BridgeEventMessage
      | { target?: unknown };
    if (!data || data.target !== BRIDGE_TARGET_INPAGE) return;

    if ("kind" in data && data.kind === "rpc-response") {
      const pending = this.pending.get(data.id);
      if (!pending) return;
      this.pending.delete(data.id);
      if (data.error) {
        pending.reject(
          new ProviderRpcError(
            data.error.code,
            data.error.message,
            data.error.data,
          ),
        );
      } else {
        pending.resolve(data.result);
      }
      return;
    }

    if ("kind" in data && data.kind === "event") {
      const listeners = this.eventListeners.get(data.event);
      if (!listeners) return;
      for (const listener of listeners) {
        try {
          listener(...data.args);
        } catch {
          // Swallow listener errors per EIP-1193 §Events — emitter
          // must not be derailed by misbehaving consumers.
        }
      }
      return;
    }
  };

  /** Send a JSON-RPC call scoped to a specific CAIP-2 chain. */
  sendRpc(scope: string | null, method: string, params: unknown): Promise<unknown> {
    const id = newRequestId();
    const message: BridgeRpcRequestMessage = {
      target: BRIDGE_TARGET_CONTENT,
      id,
      kind: "rpc",
      scope,
      method,
      params,
      origin: this.origin,
    };
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      window.postMessage(message, this.origin);
    });
  }

  /** Send a CAIP-25 session control message. */
  sendSession(
    action: "create" | "revoke" | "describe",
    params?: CAIP25CreateSessionParams,
  ): Promise<unknown> {
    const id = newRequestId();
    const message: BridgeSessionRequestMessage = {
      target: BRIDGE_TARGET_CONTENT,
      id,
      kind: "session",
      action,
      origin: this.origin,
      ...(params !== undefined ? { params } : {}),
    };
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      window.postMessage(message, this.origin);
    });
  }

  on(event: string, listener: (...args: unknown[]) => void): void {
    let set = this.eventListeners.get(event);
    if (!set) {
      set = new Set();
      this.eventListeners.set(event, set);
    }
    set.add(listener);
  }

  removeListener(event: string, listener: (...args: unknown[]) => void): void {
    const set = this.eventListeners.get(event);
    if (set) set.delete(listener);
  }
}

// ─── EIP-1193 provider — used by tenzro.evm and the EIP-6963 announcement ─

export class TenzroEvmProvider implements EIP1193Provider {
  /** EIP-1193 §isMetaMask compat field. False — we are not MetaMask. */
  readonly isMetaMask = false;
  /** Discriminator dApps can branch on. */
  readonly isTenzro = true;

  constructor(
    private readonly bridge: InpageBridge,
    private readonly wallet: WalletRoute,
  ) {}

  async request<T = unknown>(args: EIP1193RequestArguments): Promise<T> {
    if (args?.method === "eth_requestAccounts") {
      const connected = (await this.wallet.request("tenzro_connect", {})) as { account?: string };
      return (connected?.account ? [connected.account] : []) as T;
    }
    if (args?.method === "eth_accounts") return (this.wallet.account ? [this.wallet.account] : []) as T;
    if (args && KEY_METHODS.has(args.method)) throw keyMethodError(args.method);
    if (args && STANDARD_WALLET_METHODS.has(args.method)) {
      return (await this.wallet.request(args.method, args.params ?? [])) as T;
    }
    if (args && PROVIDER_METHODS.has(args.method)) return (await this.answer(args.method, args.params)) as T;
    if (
      !args ||
      typeof args.method !== "string" ||
      args.method.length === 0
    ) {
      throw new ProviderRpcError(
        RPC_ERROR_CODES.INVALID_REQUEST,
        "Invalid request: method must be a non-empty string",
      );
    }
    return (await this.bridge.sendRpc(
      TENZRO_SCOPES.EVM,
      args.method,
      args.params ?? [],
    )) as T;
  }

  private async chainIdHex(): Promise<string> {
    const id = await this.bridge.sendRpc(TENZRO_SCOPES.EVM, "eth_chainId", []);
    if (typeof id !== "string") throw new ProviderRpcError(RPC_ERROR_CODES.INTERNAL_ERROR, "eth_chainId answered no chain id");
    return `0x${BigInt(id).toString(16)}`;
  }

  /** The ERC-5792 and ERC-7715 reads answered here, from what the open wallet supports and from the network. */
  private async answer(method: string, params: unknown): Promise<unknown> {
    const list = Array.isArray(params) ? params : [];
    const chainId = await this.chainIdHex();
    if (method === "wallet_getCapabilities") {
      const address = typeof list[0] === "string" ? list[0].toLowerCase() : undefined;
      if (address && address !== this.wallet.account?.toLowerCase()) {
        throw new ProviderRpcError(RPC_ERROR_CODES.UNAUTHORIZED, "that address is not connected");
      }
      const wanted = Array.isArray(list[1]) ? (list[1] as unknown[]).map((c) => `0x${BigInt(String(c)).toString(16)}`) : [chainId];
      return Object.fromEntries(wanted.filter((c) => c === chainId).map((c) => [c, WALLET_CAPABILITIES]));
    }
    if (method === "wallet_getSupportedExecutionPermissions") return supportedExecutionPermissions(chainId);
    // wallet_getCallsStatus: a batch id is the hash of its one transaction.
    const id = typeof list[0] === "string" ? list[0] : "";
    if (!/^0x[0-9a-fA-F]{64}$/.test(id)) {
      throw new ProviderRpcError(RPC_ERROR_CODES.UNKNOWN_BUNDLE, "unknown call batch id");
    }
    const receipt = (await this.bridge.sendRpc(TENZRO_SCOPES.EVM, "eth_getTransactionReceipt", [id])) as {
      status?: string;
      logs?: { address: string; data: string; topics: string[] }[];
      blockHash?: string;
      blockNumber?: string;
      gasUsed?: string;
      transactionHash?: string;
    } | null;
    if (!receipt) {
      const tx = await this.bridge.sendRpc(TENZRO_SCOPES.EVM, "eth_getTransactionByHash", [id]);
      if (!tx) throw new ProviderRpcError(RPC_ERROR_CODES.UNKNOWN_BUNDLE, "unknown call batch id");
      return { version: CALLS_VERSION, id, chainId, status: 100, atomic: true };
    }
    const ok = receipt.status === "0x1";
    return {
      version: CALLS_VERSION,
      id,
      chainId,
      status: ok ? 200 : 500,
      atomic: true,
      receipts: [
        {
          logs: (receipt.logs ?? []).map((l) => ({ address: l.address, data: l.data, topics: l.topics })),
          status: ok ? "0x1" : "0x0",
          blockHash: receipt.blockHash,
          blockNumber: receipt.blockNumber,
          gasUsed: receipt.gasUsed,
          transactionHash: receipt.transactionHash ?? id,
        },
      ],
    };
  }

  on(event: EIP1193EventName, listener: (...args: unknown[]) => void): void {
    // EIP-1193 events are scoped to the EVM view here. Multi-VM events
    // (cross-VM transfer, identity revocation cascade) are surfaced via
    // tenzro.native event listeners.
    this.bridge.on(`evm:${event}`, listener);
  }

  removeListener(
    event: EIP1193EventName,
    listener: (...args: unknown[]) => void,
  ): void {
    this.bridge.removeListener(`evm:${event}`, listener);
  }
}

// ─── SVM provider — Solana-shaped surface ────────────────────────────────

export interface TenzroSvmProvider {
  /**
   * Connect — returns the SVM-side public key (32 bytes, base58).
   * Routes through `solana_connect`; under the pointer model the EVM
   * and SVM views read against the same native account.
   */
  connect(): Promise<{ publicKey: string }>;
  /** Sign a Solana-format VersionedTransaction or Transaction. */
  signTransaction(serializedTx: Uint8Array): Promise<Uint8Array>;
  /** Sign + send. Returns the Tenzro tx hash (which is also visible from EVM). */
  signAndSendTransaction(serializedTx: Uint8Array): Promise<string>;
  /** Sign an arbitrary message. */
  signMessage(message: Uint8Array): Promise<Uint8Array>;
  on(event: string, listener: (...args: unknown[]) => void): void;
  removeListener(event: string, listener: (...args: unknown[]) => void): void;
}

class TenzroSvmProviderImpl implements TenzroSvmProvider {
  constructor(private readonly bridge: InpageBridge) {}

  async connect(): Promise<{ publicKey: string }> {
    return (await this.bridge.sendRpc(
      TENZRO_SCOPES.SVM,
      "solana_connect",
      {},
    )) as { publicKey: string };
  }

  async signTransaction(serializedTx: Uint8Array): Promise<Uint8Array> {
    const result = (await this.bridge.sendRpc(
      TENZRO_SCOPES.SVM,
      "solana_signTransaction",
      { transaction: bytesToBase64(serializedTx) },
    )) as { signedTransaction: string };
    return base64ToBytes(result.signedTransaction);
  }

  async signAndSendTransaction(serializedTx: Uint8Array): Promise<string> {
    const result = (await this.bridge.sendRpc(
      TENZRO_SCOPES.SVM,
      "solana_signAndSendTransaction",
      { transaction: bytesToBase64(serializedTx) },
    )) as { signature: string };
    return result.signature;
  }

  async signMessage(message: Uint8Array): Promise<Uint8Array> {
    const result = (await this.bridge.sendRpc(
      TENZRO_SCOPES.SVM,
      "solana_signMessage",
      { message: bytesToBase64(message) },
    )) as { signature: string };
    return base64ToBytes(result.signature);
  }

  on(event: string, listener: (...args: unknown[]) => void): void {
    this.bridge.on(`svm:${event}`, listener);
  }

  removeListener(event: string, listener: (...args: unknown[]) => void): void {
    this.bridge.removeListener(`svm:${event}`, listener);
  }
}

// ─── Native provider — TDIP / ERC-8004 / ZK / VRF ────────────────────────

export interface TenzroNativeProvider {
  /**
   * Generic JSON-RPC entry to any `tenzro_*` method. Dispatched against
   * the native scope (`tenzro:mainnet`).
   */
  request<T = unknown>(method: string, params?: unknown): Promise<T>;
  /** EIP-1193-shaped flavour for symmetry with `tenzro.evm.request`. */
  invoke<T = unknown>(args: EIP1193RequestArguments): Promise<T>;
  on(event: string, listener: (...args: unknown[]) => void): void;
  removeListener(event: string, listener: (...args: unknown[]) => void): void;
}

class TenzroNativeProviderImpl implements TenzroNativeProvider {
  constructor(
    private readonly bridge: InpageBridge,
    private readonly scope: string,
    private readonly wallet: WalletRoute,
  ) {}

  async request<T = unknown>(method: string, params?: unknown): Promise<T> {
    if (WALLET_METHODS.has(method)) return (await this.wallet.request(method, params)) as T;
    return (await this.bridge.sendRpc(
      this.scope,
      method,
      params ?? [],
    )) as T;
  }

  async invoke<T = unknown>(args: EIP1193RequestArguments): Promise<T> {
    return this.request<T>(args.method, args.params ?? []);
  }

  on(event: string, listener: (...args: unknown[]) => void): void {
    this.bridge.on(`native:${event}`, listener);
  }

  removeListener(event: string, listener: (...args: unknown[]) => void): void {
    this.bridge.removeListener(`native:${event}`, listener);
  }
}

// ─── Multichain provider — CAIP-25 / CAIP-27 ─────────────────────────────

export interface TenzroMultichainProvider {
  /**
   * CAIP-25 `wallet_createSession`. The wallet may narrow `scopes` —
   * always honor the scopes returned in the result, not the ones
   * requested.
   */
  createSession(
    params: CAIP25CreateSessionParams,
  ): Promise<CAIP25CreateSessionResult>;
  /** Describe the current session for the calling origin (no-op if none). */
  describeSession(): Promise<CAIP25CreateSessionResult | null>;
  /** Revoke the current session. Subsequent `invokeMethod` calls fail with 4100. */
  revokeSession(): Promise<{ revoked: boolean }>;
  /** CAIP-27 `wallet_invokeMethod` — route a per-chain RPC through the session. */
  invokeMethod<T = unknown>(args: CAIP27InvokeParams): Promise<T>;
}

class TenzroMultichainProviderImpl implements TenzroMultichainProvider {
  constructor(private readonly bridge: InpageBridge) {}

  async createSession(
    params: CAIP25CreateSessionParams,
  ): Promise<CAIP25CreateSessionResult> {
    return (await this.bridge.sendSession(
      "create",
      params,
    )) as CAIP25CreateSessionResult;
  }

  async describeSession(): Promise<CAIP25CreateSessionResult | null> {
    return (await this.bridge.sendSession(
      "describe",
    )) as CAIP25CreateSessionResult | null;
  }

  async revokeSession(): Promise<{ revoked: boolean }> {
    return (await this.bridge.sendSession("revoke")) as { revoked: boolean };
  }

  async invokeMethod<T = unknown>(args: CAIP27InvokeParams): Promise<T> {
    return (await this.bridge.sendRpc(
      args.scope,
      args.request.method,
      args.request.params ?? [],
    )) as T;
  }
}

// ─── Top-level Tenzro provider ───────────────────────────────────────────

export interface TenzroProvider extends EIP1193Provider {
  readonly isTenzro: true;
  readonly version: string;
  readonly evm: TenzroEvmProvider;
  readonly svm: TenzroSvmProvider;
  readonly native: TenzroNativeProvider;
  readonly multichain: TenzroMultichainProvider;
  /** CAIP-2 chain id, e.g. `tenzro:testnet`. Set when the wallet advertises one. */
  readonly chain: string;
}

export interface InstallProviderOptions {
  /**
   * data: URI for the wallet icon (≥96px square, per EIP-6963). If
   * omitted, a transparent 1×1 placeholder is used.
   */
  readonly icon?: string;
  /** Override the displayed wallet name. Default `"Tenzro"`. */
  readonly name?: string;
  /** Override the rdns. Default `"com.tenzro.wallet"`. */
  readonly rdns?: string;
  /** CAIP-2 chain id this provider is currently connected to. */
  readonly chain?: string;
  /** Provider version string surfaced to dApps. */
  readonly version?: string;
  /** The open wallet that signs for the user. Default `https://wallet.tenzro.com`. */
  readonly walletUrl?: string;
}

class TenzroProviderImpl implements TenzroProvider {
  readonly isTenzro = true as const;
  readonly version: string;
  readonly evm: TenzroEvmProvider;
  readonly svm: TenzroSvmProvider;
  readonly native: TenzroNativeProvider;
  readonly multichain: TenzroMultichainProvider;
  readonly chain: string;

  private readonly bridge: InpageBridge;

  constructor(bridge: InpageBridge, options: InstallProviderOptions) {
    this.bridge = bridge;
    this.version = options.version ?? "0.1.0";
    this.chain = options.chain ?? TENZRO_SCOPES.NATIVE_TESTNET;
    const wallet = new WalletRoute(options.walletUrl ?? DEFAULT_WALLET_URL);
    this.evm = new TenzroEvmProvider(bridge, wallet);
    this.svm = new TenzroSvmProviderImpl(bridge);
    this.native = new TenzroNativeProviderImpl(bridge, this.chain, wallet);
    this.multichain = new TenzroMultichainProviderImpl(bridge);
  }

  /**
   * Top-level EIP-1193-shaped request. Routes to `tenzro.native` (the
   * native scope). Pure-Tenzro dApps that want any of the 264+
   * `tenzro_*` methods without explicitly reaching for `.native`
   * call `tenzro.request({ method, params })` here.
   */
  async request<T = unknown>(args: EIP1193RequestArguments): Promise<T> {
    return this.native.invoke<T>(args);
  }

  on(event: EIP1193EventName, listener: (...args: unknown[]) => void): void {
    this.bridge.on(`native:${event}`, listener);
  }

  removeListener(
    event: EIP1193EventName,
    listener: (...args: unknown[]) => void,
  ): void {
    this.bridge.removeListener(`native:${event}`, listener);
  }
}

// ─── EIP-6963 announcement helpers ───────────────────────────────────────

export function announceEip6963(
  provider: EIP1193Provider,
  info: EIP6963ProviderInfo,
): void {
  const detail: EIP6963ProviderDetail = Object.freeze({ info, provider });
  const event = new CustomEvent("eip6963:announceProvider", { detail });
  window.dispatchEvent(event);
}

/**
 * Listen for `eip6963:requestProvider` and re-announce. Per EIP-6963
 * §Specification, both wallet and dApp re-announce on receipt to handle
 * load-order races (wallet may load before dApp installs its listener).
 */
export function listenForEip6963Requests(
  provider: EIP1193Provider,
  info: EIP6963ProviderInfo,
): () => void {
  const handler = (): void => announceEip6963(provider, info);
  window.addEventListener("eip6963:requestProvider", handler);
  return () => window.removeEventListener("eip6963:requestProvider", handler);
}

// ─── Wallet Standard registration helper ─────────────────────────────────

export function announceWalletStandard(wallet: WalletStandardWallet): void {
  // Per @wallet-standard/wallet — the wallet dispatches
  // `wallet-standard:register-wallet` carrying a callback. The app side
  // calls the callback's register() with the wallet object.
  const event = new CustomEvent("wallet-standard:register-wallet", {
    detail: ({ register }: { register: (w: WalletStandardWallet) => void }) =>
      register(wallet),
  });
  window.dispatchEvent(event);
}

export function listenForWalletStandardAppReady(
  wallet: WalletStandardWallet,
): () => void {
  const handler = (): void => announceWalletStandard(wallet);
  window.addEventListener("wallet-standard:app-ready", handler);
  return () => window.removeEventListener("wallet-standard:app-ready", handler);
}

// ─── Public install entrypoint ───────────────────────────────────────────

export interface InstallResult {
  readonly provider: TenzroProvider;
  /** Call to remove all event listeners and stop announcing. */
  readonly uninstall: () => void;
}

/**
 * Install the Tenzro provider into the page world.
 *
 * Idempotent: if a provider with the same `rdns` is already installed
 * (e.g. another Tenzro-compatible wallet beat us to it) we still wire up
 * our own provider behind a per-instance UUID — both providers coexist
 * via EIP-6963's multi-announcement model. We do **not** clobber
 * `window.ethereum`; that namespace stays whoever-got-there-first to
 * preserve compatibility with other EVM wallets.
 *
 * The returned `provider` is also stamped onto `window.tenzro`, where
 * dApps that look for it directly find it.
 */
export function installTenzroProvider(
  options: InstallProviderOptions = {},
): InstallResult {
  if (typeof window === "undefined") {
    throw new Error(
      "installTenzroProvider must be called in a browser environment",
    );
  }

  const bridge = new InpageBridge();
  const provider = new TenzroProviderImpl(bridge, options);

  // Stamp onto window.tenzro for direct discovery.
  Object.defineProperty(window, "tenzro", {
    value: provider,
    configurable: false,
    enumerable: true,
    writable: false,
  });

  // EIP-6963 — announce the EVM facet.
  const info: EIP6963ProviderInfo = {
    uuid: newRequestId(),
    name: options.name ?? TENZRO_PROVIDER_NAME,
    icon: options.icon ?? DEFAULT_PLACEHOLDER_ICON,
    rdns: options.rdns ?? TENZRO_PROVIDER_RDNS,
  };
  announceEip6963(provider.evm, info);
  const stopEip6963 = listenForEip6963Requests(provider.evm, info);

  // Wallet Standard — announce the SVM facet as a Solana wallet.
  const svmWallet: WalletStandardWallet = {
    version: "1.0.0",
    name: info.name,
    icon: info.icon,
    chains: [TENZRO_SCOPES.SVM, TENZRO_SCOPES.SVM_TESTNET],
    features: {
      "standard:connect": {
        version: "1.0.0",
        connect: () => provider.svm.connect(),
      },
      "standard:events": {
        version: "1.0.0",
        on: (event: string, listener: (...args: unknown[]) => void) =>
          provider.svm.on(event, listener),
      },
      "solana:signTransaction": {
        version: "1.0.0",
        signTransaction: (tx: Uint8Array) => provider.svm.signTransaction(tx),
      },
      "solana:signAndSendTransaction": {
        version: "1.0.0",
        signAndSendTransaction: (tx: Uint8Array) =>
          provider.svm.signAndSendTransaction(tx),
      },
      "solana:signMessage": {
        version: "1.0.0",
        signMessage: (msg: Uint8Array) => provider.svm.signMessage(msg),
      },
    },
    accounts: [],
  };
  announceWalletStandard(svmWallet);
  const stopWalletStandard = listenForWalletStandardAppReady(svmWallet);

  return {
    provider,
    uninstall: (): void => {
      stopEip6963();
      stopWalletStandard();
    },
  };
}

// ─── Tiny base64 helpers (Uint8Array <-> string) ─────────────────────────
// Page-world code can't depend on Buffer; stick to btoa/atoa.

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
