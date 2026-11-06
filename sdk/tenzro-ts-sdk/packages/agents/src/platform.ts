import type { RpcClient } from "@tenzro/core";

/** The chain's randomness beacon. */
export class BeaconClient {
  constructor(private readonly rpc: RpcClient) {}

  /** The head (next round, current mix), the value at `round`, or the first at or after `atMs`. */
  get(at?: { round?: number; atMs?: number }): Promise<unknown> {
    return this.rpc.call('tenzro_getBeacon', {
      ...(at?.round !== undefined ? { round: at.round } : {}),
      ...(at?.atMs !== undefined ? { at_ms: at.atMs } : {}),
    });
  }
}

/** Data-availability objects and their governed retention. */
export class DaRetentionClient {
  constructor(private readonly rpc: RpcClient) {}

  /** An object as chain state records it, with its expiry. */
  object(commitment: string): Promise<unknown> {
    return this.rpc.call('tenzro_getDaObject', { commitment });
  }

  /** Retention per class, live and expired totals, and where expiry stands. */
  retention(): Promise<unknown> {
    return this.rpc.call('tenzro_getDaRetention', {});
  }
}

/** The base fee of every resource market: compute, state growth, bandwidth, proof. */
export function getFeeMarket(rpc: RpcClient): Promise<Record<string, { base_fee_usd: string; base_fee: string; target_per_block: number }>> {
  return rpc.call('tenzro_getFeeMarket', {});
}
