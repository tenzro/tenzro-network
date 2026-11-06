import type { RpcClient } from "@tenzro/core";

export interface QuoteBridgeFeeRequest {
  adapter: string;
  /** Destination chain, CAIP-2. */
  dest_chain: string;
  native_fee_smallest_unit: string;
}

/** A destination-native fee and the TNZO that pays it at committed rates. */
export interface QuoteBridgeFeeResponse {
  quote_id_hex: string;
  adapter: string;
  dest_chain: string;
  native_symbol: string;
  native_fee_smallest_unit: string;
  tnzo_amount_wei: string;
  native_rate_nano_usd: string;
  tnzo_rate_nano_usd: string;
  rate_epoch: number | null;
  issued_at_ms: number;
  valid_until_ms: number;
}

/**
 * Bridge fee in TNZO: converts a destination-native fee at the USD rates
 * validators commit on chain. Refused while the destination's native asset
 * is unpriced.
 */
export class BridgeFeeClient {
  constructor(private readonly rpc: RpcClient) {}

  async quote(req: QuoteBridgeFeeRequest): Promise<QuoteBridgeFeeResponse> {
    return this.rpc.call<QuoteBridgeFeeResponse>('tenzro_quoteBridgeFeeInTnzo', [req]);
  }
}
