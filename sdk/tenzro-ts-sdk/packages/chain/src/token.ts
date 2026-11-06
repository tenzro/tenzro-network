import type { RpcClient } from "@tenzro/core";

/**
 * The deterministic CREATE2 address of the wTNZO ERC-20 pointer contract on EVM.
 * All VMs (EVM, SVM) share the same underlying native TNZO balance via
 * the Sei V2 pointer model -- this address is the EVM representation.
 */
export const WTNZO_EVM_ADDRESS = '0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93';

// ── Parameter types ──

/** Parameters for creating a new token via the factory. */
/** Parameters for creating a token issued by the signing wallet. */
export interface CreateTokenParams {
  /** Token name (e.g. "Tenzro Rewards") */
  name: string;
  /** Token ticker symbol (e.g. "TRW") */
  symbol: string;
  /** Number of decimals */
  decimals: number;
  /** Initial supply credited to the issuer, smallest unit (decimal string) */
  initial_supply: string;
  /** Ceiling on the supply, smallest unit (decimal string), if any */
  max_supply: string | null;
  /**
   * Who holds each issuer power (mint, freeze, halt, force, policy_change),
   * each "disabled" | "issuer" or {issuer_council: {k}}. Only| "issuer"} or {kind: "issuer_council", k}. Only
   * narrows after creation.
   */
  powers: Record<string, unknown>;
  /** Eligibility policy: {eligibility: Rule[], policy_timelock_ms} */
  policy: Record<string, unknown>;
  /** Issuer council {k, members}, when a power names one */
  council: { k: number; members: string[] } | null;
  /** For a reserve-backed token: the bonded attestor stake, whole TNZO, each mint's reserve attestations must hold between them. Any bonded attestor may attest. */
  reserve_backing: { min_attestor_stake_tnzo: number } | null;
}

/** Verdict of the token rule engine. */
export interface CanTransferResult {
  allowed: boolean;
  code?: number;
  reason?: string;
}

/** One `Token` operation, externally tagged by its snake_case name. */
export type TokenOp = Record<string, unknown>;

/** Parameters for looking up a token. */
export interface GetTokenInfoParams {
  /** Token symbol (e.g. "TNZO") */
  symbol?: string;
  /** EVM contract address */
  address?: string;
  /** Unified token ID */
  token_id?: string;
}

/** Parameters for listing tokens. */
export interface ListTokensParams {
  /** Filter by VM type: "evm", "svm" */
  vm_type?: string;
}

// ── Return types ──

/** Information about a registered token. */
export interface TokenInfo {
  /** Unique token identifier */
  token_id: string;
  /** Token name */
  name: string;
  /** Token symbol */
  symbol: string;
  /** Number of decimals */
  decimals: number;
  /** Total supply as a decimal string */
  total_supply: string;
  /** Creator address */
  creator: string;
  /** VM type the token was deployed on */
  vm_type: string;
  /** EVM contract address (if applicable) */
  evm_address?: string;
  /** The token's ERC-20 / ERC-7943 facade address on the EVM */
  erc20_facade?: string;
  /** SVM SPL mint address (if applicable) */
  svm_mint?: string;
  /** Tempo L1 TIP-20 contract address (if applicable) */
  tempo_address?: string;
  /** Transaction hash of the creation */
  tx_hash?: string;
}

/** Result of listing tokens. */
export interface TokenListResult {
  /** Array of registered tokens */
  tokens: TokenInfo[];
  /** Total number of tokens matching the filter */
  total: number;
}

/** Native TNZO view (18 decimals). */
export interface NativeBalance {
  /** Balance in wei (decimal string) */
  balance_wei: string;
  /** Number of decimals (always 18) */
  decimals: number;
}

/** EVM wTNZO ERC-20 view — same wei as native, 18 decimals. */
export interface EvmBalance {
  /** Balance in wei (decimal string) */
  balance_wei: string;
  /** Number of decimals (always 18) */
  decimals: number;
}

/** SVM wTNZO SPL view — 9-decimal truncation of native balance. */
export interface SvmBalance {
  /** Balance in SPL base units (decimal string, 9 decimals) */
  balance_base_units: string;
  /** Number of decimals (always 9) */
  decimals: number;
}

/** Token balance across all three VM views (pointer model). */
export interface TokenBalance {
  /** Address queried */
  address: string;
  /** Native TNZO balance (18-decimal wei) */
  native: NativeBalance;
  /** EVM wTNZO ERC-20 view — tracks native 1:1 */
  evm_wtnzo: EvmBalance;
  /** SVM wTNZO SPL view — 9-decimal truncation */
  svm_wtnzo: SvmBalance;
}

// ── Client ──

/**
 * Client for token registry and cross-VM token operations.
 * Supports creating ERC-20 tokens, querying the unified registry,
 * wrapping native TNZO, and atomic cross-VM transfers.
 */
export class TokenClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * Look up a token by symbol, EVM address, or token ID.
   * @param params - At least one of symbol, address, or token_id
   * @returns Token information
   */
  async getTokenInfo(params: GetTokenInfoParams): Promise<TokenInfo> {
    return this.rpc.call<TokenInfo>('tenzro_getToken', [params]);
  }

  /**
   * List registered tokens with an optional VM type filter.
   * @param params - Optional filter parameters
   * @returns List of tokens
   */
  async listTokens(params?: ListTokensParams): Promise<TokenListResult> {
    return this.rpc.call<TokenListResult>('tenzro_listTokens', [params ?? {}]);
  }

  /**
   * Get TNZO balance across all VMs with decimal conversion.
   * @param address - Address to query
   * @param token - Token symbol (default: "TNZO")
   * @returns Token balance with optional per-VM breakdown
   */
  /**
   * Whether the token's rules allow `from` to send `amount` to `to` now:
   * `{allowed}` or `{allowed: false, code, reason}`.
   */
  async canTransfer(tokenId: string, from: string, to: string, amount: bigint): Promise<CanTransferResult> {
    return this.rpc.call<CanTransferResult>('tenzro_canTransfer', [
      { token_id: tokenId, from, to, amount: amount.toString() },
    ]);
  }

  /**
   * An address's TNZO balance in every VM form: native and EVM wrapped TNZO
   * in wei (18 decimals), SVM wrapped TNZO in base units (9 decimals).
   */
  async getTokenBalance(address: string): Promise<TokenBalance> {
    return this.rpc.call<TokenBalance>('tenzro_getTokenBalance', { address });
  }
}
