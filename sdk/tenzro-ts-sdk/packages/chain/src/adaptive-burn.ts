import { RpcClient } from "@tenzro/core";

/**
 * Client for the adaptive-burn governance dial (TNZO supply control).
 *
 * Surfaces the current `BurnRateConfig`, rolling `SupplyMetricsSnapshot`,
 * the recommended action computed from the targets and metrics, and the
 * list of in-flight adaptive-burn governance proposals.
 *
 * All endpoints are read-only. The auto-proposal generator and the
 * EIP-1559 fee-market consumer run inside the node alongside the
 * governance executor; this client only reads their output.
 */
export class AdaptiveBurnClient {
  constructor(private rpc: RpcClient) {}

  /**
   * Returns the current `BurnRateConfig` (base and local fee burn bps).
   * @returns Active burn-rate configuration
   */
  async getBurnRateConfig(): Promise<any> {
    return this.rpc.call("tenzro_getBurnRateConfig", [{}]);
  }

  /**
   * Returns the economic policy this node applies to every settlement — how a
   * payment divides, the network's default settlement asset, and the
   * micro-settlement floor.
   *
   * Read this before paying rather than inferring the split from a receipt
   * afterwards. The response also reports, per capability, which economic mode
   * the node is in: a **private** capability keeps the whole payment, a
   * **public validating** one shares with the treasury, and a **public
   * delegated** one also pays the RPC provider validating on its behalf.
   *
   * Every rate is governance-set; see `docs/ECONOMICS.md`.
   */
  async getEconomicPolicy(): Promise<any> {
    return this.rpc.call("tenzro_getEconomicPolicy", [{}]);
  }

  /**
   * Returns the latest rolling supply metrics snapshot — circulating
   * supply, epoch delta, burn breakdown, and supply added (always 0: TNZO
   * supply is fixed at genesis; reported as `emission_breakdown`).
   * @returns Latest `SupplyMetricsSnapshot`
   */
  async getSupplyMetrics(): Promise<any> {
    return this.rpc.call("tenzro_getSupplyMetrics", [{}]);
  }

  /**
   * Computes the recommended adaptive-burn action from the current
   * metrics and configured supply targets. May return `NoChange`,
   * `IncreaseBurnPct`, `DecreaseBurnPct`, or alarm variants.
   * @returns `BurnRateRecommendation`
   */
  async getBurnRateRecommendation(): Promise<any> {
    return this.rpc.call("tenzro_getBurnRateRecommendation", [{}]);
  }

  /**
   * Returns the TNZO/USD rate fees are priced at (nano-USD per TNZO), its
   * mode (`governance` or `validators`), its hourly rise and fall caps
   * (`max_change_bps`, `max_fall_bps`), the safety rate safety checks value
   * TNZO at (`safety_rate_nano_usd`), the next block's base fee in USD and
   * in TNZO, and the settlement fee in basis points. With `symbol` (`ETH`,
   * `SOL`, ...) it returns that asset's committed USD rate instead.
   */
  async getFeeRate(symbol?: string): Promise<any> {
    return this.rpc.call("tenzro_getFeeRate", [symbol ? { symbol } : {}]);
  }

  /**
   * Returns growth and concentration metrics for a reward epoch (the current
   * one when `epoch` is omitted): settled value, payments per settlement,
   * unique paying root identities, organic against unattributed volume, burn
   * against rewards released from the pool, and the holder count, top-10 and top-100 share and Gini
   * coefficient.
   */
  async getEconomyMetrics(epoch?: number): Promise<any> {
    return this.rpc.call("tenzro_getEconomyMetrics", [epoch === undefined ? {} : { epoch }]);
  }

  /**
   * Burn-dial governance proposals, newest first: the policy updates that set
   * the burn shares or the supply targets the dial steers by.
   */
  async listAdaptiveBurnProposals(limit = 100): Promise<any[]> {
    const page = await this.rpc.call<any>("tenzro_listProposals", [{ kind: "policy_update", limit }]);
    return (page?.proposals ?? []).filter((p: any) => {
      const update = p?.proposal?.action?.update ?? {};
      return "AdaptiveBurnConfigUpdate" in update || "SupplyTargetsUpdate" in update;
    });
  }
}
