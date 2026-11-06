/**
 * Type definitions for the Tenzro injected provider.
 *
 * The on-the-wire protocol between the in-page provider, the content
 * script, and the extension's service worker is defined here in one
 * place so all three sides (page world, isolated world, background)
 * agree on the message shape.
 */

// ─── EIP-1193: Ethereum Provider JavaScript API ──────────────────────────
// https://eips.ethereum.org/EIPS/eip-1193

export interface EIP1193RequestArguments {
  readonly method: string;
  readonly params?: readonly unknown[] | Record<string, unknown>;
}

export interface EIP1193ProviderRpcError extends Error {
  readonly code: number;
  readonly data?: unknown;
}

export type EIP1193EventName =
  | "connect"
  | "disconnect"
  | "chainChanged"
  | "accountsChanged"
  | "message";

export interface EIP1193Provider {
  request<T = unknown>(args: EIP1193RequestArguments): Promise<T>;
  on(event: EIP1193EventName, listener: (...args: unknown[]) => void): void;
  removeListener(
    event: EIP1193EventName,
    listener: (...args: unknown[]) => void,
  ): void;
}

/** EIP-1193 standardised error codes. */
export const RPC_ERROR_CODES = {
  /** User rejected the request. */
  USER_REJECTED: 4001,
  /** Method/account not authorized for this origin. */
  UNAUTHORIZED: 4100,
  /** Provider does not implement this method. */
  UNSUPPORTED_METHOD: 4200,
  /** Provider is disconnected from all chains. */
  DISCONNECTED: 4900,
  /** Provider is disconnected from the requested chain. */
  CHAIN_DISCONNECTED: 4901,
  /** JSON-RPC parse error. */
  PARSE_ERROR: -32700,
  /** Invalid JSON-RPC request. */
  INVALID_REQUEST: -32600,
  /** Method does not exist on the server side. */
  METHOD_NOT_FOUND: -32601,
  /** Invalid method parameters. */
  INVALID_PARAMS: -32602,
  /** Internal JSON-RPC error. */
  INTERNAL_ERROR: -32603,
  /** ERC-5792: unknown call batch id. */
  UNKNOWN_BUNDLE: 5730,
} as const;

// ─── EIP-6963: Multi-Injected Provider Discovery ─────────────────────────
// https://eips.ethereum.org/EIPS/eip-6963

export interface EIP6963ProviderInfo {
  /** UUIDv4 unique to this provider instance (regenerate per page load). */
  readonly uuid: string;
  /** Human-readable wallet name. */
  readonly name: string;
  /** data: URI for the wallet icon, ≥96×96 px. */
  readonly icon: string;
  /** Reverse-DNS identifier — `com.tenzro.wallet` for Tenzro. */
  readonly rdns: string;
}

export interface EIP6963ProviderDetail {
  readonly info: EIP6963ProviderInfo;
  readonly provider: EIP1193Provider;
}

export interface EIP6963AnnounceProviderEvent extends CustomEvent {
  readonly type: "eip6963:announceProvider";
  readonly detail: EIP6963ProviderDetail;
}

// ─── Wallet Standard (Solana / chain-agnostic) ───────────────────────────
// https://github.com/wallet-standard/wallet-standard

/** A reduced surface — we only implement the slice needed for SVM-on-Tenzro. */
export interface WalletStandardAccount {
  readonly address: string;
  readonly publicKey: Uint8Array;
  /** CAIP-2 chains this account is reachable on. */
  readonly chains: readonly string[];
  readonly features: readonly string[];
  readonly label?: string;
  readonly icon?: string;
}

export interface WalletStandardWallet {
  readonly version: "1.0.0";
  readonly name: string;
  readonly icon: string;
  /** CAIP-2 chains the wallet supports — e.g. `["solana:tenzro-mainnet"]`. */
  readonly chains: readonly string[];
  readonly features: Record<string, unknown>;
  readonly accounts: readonly WalletStandardAccount[];
}

// ─── CAIP-25 / CAIP-27 — multi-chain session and invocation ──────────────
// https://chainagnostic.org/CAIPs/caip-25
// https://chainagnostic.org/CAIPs/caip-27

export interface CAIP25Scope {
  readonly methods: readonly string[];
  readonly notifications: readonly string[];
  readonly accounts?: readonly string[];
  /** CAIP-2 chains nested inside this scope (e.g. `eip155:13380`). */
  readonly chains?: readonly string[];
}

export interface CAIP25Scopes {
  readonly [scopeKey: string]: CAIP25Scope;
}

export interface CAIP25CreateSessionParams {
  readonly scopes: CAIP25Scopes;
  readonly sessionProperties?: Record<string, unknown>;
}

export interface CAIP25CreateSessionResult {
  /** Server-issued session id. */
  readonly sessionId: string;
  /** Echo of the agreed-upon scopes — the wallet may have narrowed them. */
  readonly scopes: CAIP25Scopes;
  readonly sessionProperties?: Record<string, unknown>;
  readonly expiry?: number;
}

export interface CAIP27InvokeParams {
  readonly sessionId?: string;
  /** CAIP-2 scope key — e.g. `eip155:13380`, `solana:tenzro-mainnet`, `tenzro:mainnet`. */
  readonly scope: string;
  readonly request: {
    readonly method: string;
    readonly params?: readonly unknown[] | Record<string, unknown>;
  };
}

// ─── Tenzro-specific scopes and methods ──────────────────────────────────

/** CAIP-2 scope identifiers for Tenzro's three VMs. */
export const TENZRO_SCOPES = {
  /** Native TnzoToken layer — `tenzro_*` namespace methods. */
  NATIVE: "tenzro:mainnet",
  NATIVE_TESTNET: "tenzro:testnet",
  /** EVM-on-Tenzro view — full eth_* surface. */
  EVM: "eip155:1337",
  /** SVM-on-Tenzro view — accessed through `tenzro_*` namespace, not Solana JSON-RPC. */
  SVM: "solana:tenzro-mainnet",
  SVM_TESTNET: "solana:tenzro-testnet",
} as const;

/** Methods exposed on each scope. */
export const SCOPE_METHODS = {
  [TENZRO_SCOPES.NATIVE]: [
    "tenzro_blockNumber",
    "tenzro_getBlock",
    "tenzro_getBlockRange",
    "tenzro_getTransaction",
    "tenzro_getBalance",
    "tenzro_getNonce",
    "tenzro_listTokens",
    "tenzro_getTokenBalance",
    "tenzro_registerIdentity",
    "tenzro_resolveIdentity",
    "tenzro_settle",
    "tenzro_createPaymentChallenge",
    "tenzro_createZkProof",
    "tenzro_verifyZkProof",
    "tenzro_verifyVrfProof",
    "tenzro_sendRawTransaction",
    // Signed in the open wallet's window with the user's passkey.
    "tenzro_connect",
    "tenzro_sendTransaction",
    "tenzro_signSettlementPlan",
    "tenzro_approveAgentTerms",
    "tenzro_approveAgentAction",
  ],
  [TENZRO_SCOPES.EVM]: [
    "eth_chainId",
    "eth_blockNumber",
    "eth_getBalance",
    "eth_getTransactionCount",
    "eth_gasPrice",
    "eth_maxPriorityFeePerGas",
    "eth_feeHistory",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getTransactionReceipt",
    "eth_getBlockReceipts",
    "eth_call",
    "eth_estimateGas",
    "eth_sendRawTransaction",
    // The account the open wallet connected.
    "eth_accounts",
    "eth_requestAccounts",
    // ERC-5792 call batches and ERC-7715 permissions, through the open wallet.
    "wallet_getCapabilities",
    "wallet_sendCalls",
    "wallet_getCallsStatus",
    "wallet_showCallsStatus",
    "wallet_getSupportedExecutionPermissions",
    "wallet_requestExecutionPermissions",
    "wallet_revokeExecutionPermission",
    "wallet_getGrantedExecutionPermissions",
  ],
  [TENZRO_SCOPES.SVM]: [
    // SVM-on-Tenzro is reached through the tenzro_* namespace; the node
    // does not speak Solana JSON-RPC.
    "tenzro_listTokens",
    "tenzro_getTokenBalance",
  ],
} as const;

// ─── Bridge protocol — page world ↔ content script ───────────────────────

/**
 * All bridge messages share this discriminator so window.postMessage
 * can be filtered cheaply. The page world only sees its own messages.
 */
export const BRIDGE_TARGET_INPAGE = "tenzro-inpage";
export const BRIDGE_TARGET_CONTENT = "tenzro-content";

export interface BridgeRpcRequestMessage {
  readonly target: typeof BRIDGE_TARGET_CONTENT;
  readonly id: string;
  readonly kind: "rpc";
  /** CAIP-2 scope, or `null` for unscoped/legacy EIP-1193 calls. */
  readonly scope: string | null;
  readonly method: string;
  readonly params: unknown;
  readonly origin: string;
}

export interface BridgeRpcResponseMessage {
  readonly target: typeof BRIDGE_TARGET_INPAGE;
  readonly id: string;
  readonly kind: "rpc-response";
  readonly result?: unknown;
  readonly error?: { code: number; message: string; data?: unknown };
}

export interface BridgeEventMessage {
  readonly target: typeof BRIDGE_TARGET_INPAGE;
  readonly kind: "event";
  /** EIP-1193 event name (`accountsChanged`, `chainChanged`, …) or a Tenzro-specific event. */
  readonly event: string;
  readonly scope: string | null;
  readonly args: readonly unknown[];
}

export interface BridgeSessionRequestMessage {
  readonly target: typeof BRIDGE_TARGET_CONTENT;
  readonly id: string;
  readonly kind: "session";
  readonly action: "create" | "revoke" | "describe";
  readonly origin: string;
  readonly params?: CAIP25CreateSessionParams;
}

export type BridgeRequest =
  | BridgeRpcRequestMessage
  | BridgeSessionRequestMessage;

export type BridgeResponse =
  | BridgeRpcResponseMessage
  | BridgeEventMessage;

// ─── Tenzro-specific provider info — single source of truth ──────────────

export const TENZRO_PROVIDER_RDNS = "com.tenzro.wallet" as const;
export const TENZRO_PROVIDER_NAME = "Tenzro" as const;

/**
 * 1×1 transparent placeholder. Real extensions ship a 96×96 SVG and pass it
 * via `installTenzroProvider({ icon: ... })`. Per EIP-6963 §Specification,
 * `icon` SHOULD be ≥96px square; this default is the "no icon" sentinel.
 */
export const DEFAULT_PLACEHOLDER_ICON =
  "data:image/svg+xml;utf8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2096%2096%22%2F%3E" as const;
