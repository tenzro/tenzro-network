import type { RpcClient } from "@tenzro/core";
import { TypedTxClient } from "@tenzro/core";
import type { HybridSigner } from "@tenzro/core";
import type {
  BridgeRouteInfo,
} from "@tenzro/core";

/** An IBC message a relayer brings to Tenzro. */
export type IbcMessage =
  | 'connection_open_try'
  | 'connection_open_confirm'
  | 'channel_open_try'
  | 'channel_open_confirm'
  | 'acknowledge'
  | 'timeout';

/**
 * TNZO moves between Tenzro and external chains only over governed routes:
 * a CCIP-compatible envelope for Ethereum, Base, Arbitrum and Solana, IBC,
 * Bitcoin deposits and contract routes. Every route enforces committee attestations
 * bound to the chain, the route, a nonce and an expiry; a circuit breaker;
 * per-transfer and per-epoch caps; and the supply invariant.
 */

/**
 * The `Bridge` transaction fields that send `amount` base units to
 * `recipient` (hex, the account on `targetChain`). `asset` names a carried
 * asset (`USDC`), whose representation is burned here and released from the
 * route's vault there; omit it to move TNZO, or the deposit asset over a
 * deposit route.
 */
export function outboundFields(targetChain: string, recipient: string, amount: bigint, asset?: string) {
  const to = recipient.replace(/^0x/, '').toLowerCase();
  if (to.length === 0 || to.length % 2 !== 0 || !/^[0-9a-f]+$/.test(to)) {
    throw new Error('recipient must be non-empty hex');
  }
  if (amount <= 0n) throw new Error('amount must be positive');
  return {
    op: {
      outbound: {
        target_chain: targetChain.toLowerCase(),
        recipient: to,
        amount: amount.toString(),
        asset: asset ? asset.toUpperCase() : null,
      },
    },
  };
}

/** Client for the governed bridge routes. */
export class BridgeClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * Send `amount` base units out over the route to `targetChain`, to
   * `recipient` (hex), as a `Bridge` transaction `signer` signs locally.
   * `asset` names a carried asset (`USDC`); omit it to move TNZO.
   */
  async send(signer: HybridSigner, targetChain: string, recipient: string, amount: bigint, asset?: string): Promise<unknown> {
    return new TypedTxClient(this.rpc).send(signer, {
      kind: 'Bridge',
      fields: outboundFields(targetChain, recipient, amount, asset),
    });
  }

  /** Every governed route with its caps, epoch usage and supply. */
  async listRoutes(): Promise<BridgeRouteInfo[]> {
    const r = await this.rpc.call<{ routes: BridgeRouteInfo[] }>('tenzro_listBridgeRoutes', {});
    return r.routes ?? [];
  }

  /** The route for `adapter` (`ccip`, `ibc`, `deposit` or `contract`) and `chain`. */
  async getRoute(adapter: string, chain: string): Promise<BridgeRouteInfo> {
    return this.rpc.call<BridgeRouteInfo>('tenzro_getBridgeRoute', {
      adapter,
      source_chain: chain,
    });
  }

  /**
   * Outbound record `sequence` of the route `(adapter, chain)`, as relayers
   * and signers take it; for a Bitcoin deposit route, the withdrawal and the
   * digest each input is signed over.
   */
  async getOutbound(adapter: string, chain: string, sequence: number): Promise<Record<string, unknown>> {
    return this.rpc.call<Record<string, unknown>>('tenzro_getBridgeOutbound', {
      adapter,
      source_chain: chain,
      sequence,
    });
  }

  /**
   * The network-wide exit limits: for each unit, the cap in force per epoch
   * (the lower of its governed cap and the stake-backed cap), the governed
   * cap, how much has left over every route together this epoch and how much
   * waits in the exit queue; the security ratio and its inputs (`security`);
   * the exit delay rule; the most one proposal may raise a cap; and the last
   * exit id queued.
   */
  async getOutflow(): Promise<Record<string, unknown>> {
    return this.rpc.call<Record<string, unknown>>('tenzro_getBridgeOutflow', {});
  }

  /** The queued exit `id`: its sender, destination, amount and release time. */
  async getExit(id: number): Promise<Record<string, unknown>> {
    return this.rpc.call<Record<string, unknown>>('tenzro_getBridgeExit', { id });
  }

}
