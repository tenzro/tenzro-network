/**
 * Which methods the extension serves, and where each goes.
 *
 * The extension holds no key and no credential. Reads and transactions that
 * are already signed go to the network's RPC operators, which accept them on
 * their own merits. Anything that needs the user's authority is signed in the
 * open wallet (wallet.tenzro.com), on its own origin, with the user's passkey:
 * the page opens the wallet window for those methods (see `wallet-window.ts`),
 * and the service worker refuses them.
 */

import { RPC_ERROR_CODES, TENZRO_SCOPES } from "./types";

/** Methods the open wallet serves through its window; the user's passkey approves each. */
export const WALLET_METHODS: ReadonlySet<string> = new Set([
  "tenzro_connect",
  "tenzro_sendTransaction",
  "tenzro_addWallet",
  "tenzro_linkDevice",
  "tenzro_linkCredential",
  "tenzro_signSettlementPlan",
  "tenzro_approveAgentTerms",
  "tenzro_approveAgentAction",
]);

/**
 * Methods that would need a key the extension does not hold. They are never
 * sent to a node; the page signs in the open wallet instead.
 */
export const KEY_METHODS: ReadonlySet<string> = new Set([
  "eth_sendTransaction",
  "eth_signTransaction",
  "eth_sign",
  "personal_sign",
  "eth_signTypedData",
  "eth_signTypedData_v3",
  "eth_signTypedData_v4",
  "solana_signTransaction",
  "solana_signAndSendTransaction",
  "solana_signMessage",
  "solana_signIn",
]);

/**
 * ERC-5792 and ERC-7715 methods the open wallet serves through its window.
 * Their params are the standard positional ones and reach the wallet as sent.
 * A call batch is one native contract-call transaction (every call applies
 * or none does), approved once by the user's passkey; a permission is the
 * Terms of one of the user's agents, recorded in consensus and checked by
 * every validator on each of the agent's actions.
 */
export const STANDARD_WALLET_METHODS: ReadonlySet<string> = new Set([
  "wallet_sendCalls",
  "wallet_showCallsStatus",
  "wallet_requestExecutionPermissions",
  "wallet_revokeExecutionPermission",
  "wallet_getGrantedExecutionPermissions",
]);

/** ERC-5792 and ERC-7715 reads the page's provider answers itself, with no window. */
export const PROVIDER_METHODS: ReadonlySet<string> = new Set([
  "wallet_getCapabilities",
  "wallet_getCallsStatus",
  "wallet_getSupportedExecutionPermissions",
]);

/** ERC-5792 version of the call batches the open wallet sends. */
export const CALLS_VERSION = "2.0.0";

/**
 * What the open wallet supports for call batches, on the network's chain
 * (ERC-5792 `wallet_getCapabilities`). A batch always executes atomically.
 * A sponsor cannot pay for a call batch: the network takes a transaction's
 * fee from its sender.
 */
export const WALLET_CAPABILITIES = {
  atomic: { status: "supported" },
  paymasterService: { supported: false },
} as const;

/**
 * ERC-7715 permission types the open wallet grants, as an agent's spend limit
 * per clock hour (`periodDuration` 3600) or per day (86400), with an optional
 * `expiry` rule as the Terms' expiry.
 */
export function supportedExecutionPermissions(chainIdHex: string): Record<string, { chainIds: string[]; ruleTypes: string[] }> {
  return { "native-token-periodic": { chainIds: [chainIdHex], ruleTypes: ["expiry"] } };
}

export interface RouteError {
  readonly code: number;
  readonly message: string;
}

const SIGN_IN_WALLET =
  "this extension holds no key; the user signs in the open wallet (tenzro_sendTransaction, tenzro_signSettlementPlan and the other wallet methods), and a signed transaction is sent with tenzro_sendRawTransaction or eth_sendRawTransaction";

/**
 * The node method a (scope, method) pair is sent as, or why it is not sent.
 * Native scopes take `tenzro_*`, the EVM scope `eth_*`, the SVM view the
 * token reads of the `tenzro_*` namespace (the node does not speak Solana
 * JSON-RPC).
 */
export function resolveMethodName(scope: string | null, method: string): { rpcMethod: string } | { error: RouteError } {
  if (KEY_METHODS.has(method) || WALLET_METHODS.has(method) || STANDARD_WALLET_METHODS.has(method) || PROVIDER_METHODS.has(method)) {
    return { error: { code: RPC_ERROR_CODES.UNSUPPORTED_METHOD, message: `${method}: ${SIGN_IN_WALLET}` } };
  }
  if (scope === TENZRO_SCOPES.NATIVE || scope === TENZRO_SCOPES.NATIVE_TESTNET) {
    if (!method.startsWith("tenzro_")) {
      return {
        error: { code: RPC_ERROR_CODES.UNSUPPORTED_METHOD, message: `native scope only supports tenzro_* methods, got "${method}"` },
      };
    }
    return { rpcMethod: method };
  }
  if (scope === TENZRO_SCOPES.EVM) {
    if (!method.startsWith("eth_")) {
      return {
        error: { code: RPC_ERROR_CODES.UNSUPPORTED_METHOD, message: `EVM scope only supports eth_* methods, got "${method}"` },
      };
    }
    return { rpcMethod: method };
  }
  if (scope === TENZRO_SCOPES.SVM || scope === TENZRO_SCOPES.SVM_TESTNET) {
    if (method === "tenzro_listTokens" || method === "tenzro_getTokenBalance") return { rpcMethod: method };
    return {
      error: {
        code: RPC_ERROR_CODES.UNSUPPORTED_METHOD,
        message: `SVM scope: "${method}" is not served; Tenzro does not implement Solana JSON-RPC. Use tenzro_listTokens or tenzro_getTokenBalance.`,
      },
    };
  }
  return { error: { code: RPC_ERROR_CODES.UNSUPPORTED_METHOD, message: `unknown CAIP scope "${scope}"` } };
}

/** The network the extension reaches: seed URLs to discover RPC operators from, and the chain id they must report. */
export interface NetworkSettings {
  readonly seeds: readonly string[];
  readonly chainId: number;
}

/** `value` as network settings, or `null` when it is not a usable one. */
export function parseNetworkSettings(value: unknown): NetworkSettings | null {
  if (!value || typeof value !== "object") return null;
  const v = value as { seeds?: unknown; chainId?: unknown };
  if (!Array.isArray(v.seeds) || v.seeds.length === 0) return null;
  const seeds: string[] = [];
  for (const s of v.seeds) {
    if (typeof s !== "string") return null;
    let url: URL;
    try {
      url = new URL(s);
    } catch {
      return null;
    }
    if (url.protocol !== "https:" && !(url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1"))) {
      return null;
    }
    seeds.push(url.toString());
  }
  if (typeof v.chainId !== "number" || !Number.isSafeInteger(v.chainId) || v.chainId <= 0) return null;
  return { seeds, chainId: v.chainId };
}
