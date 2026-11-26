//! Adaptive-burn governance dial SDK for Tenzro Network.
//!
//! Surfaces the current `BurnRateConfig`, rolling `SupplyMetricsSnapshot`,
//! the recommended action computed from the targets and metrics, and the
//! list of in-flight adaptive-burn governance proposals.
//!
//! All endpoints are read-only. The auto-proposal generator and the
//! EIP-1559 fee-market consumer run inside the node alongside the
//! governance executor; this client only reads their output.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde_json::Value;
use std::sync::Arc;

/// Adaptive-burn governance dial client.
#[derive(Clone)]
pub struct AdaptiveBurnClient {
    rpc: Arc<RpcClient>,
}

impl AdaptiveBurnClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Returns the current `BurnRateConfig` (base and local fee burn bps).
    pub async fn get_burn_rate_config(&self) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getBurnRateConfig", serde_json::json!({}))
            .await
    }

    /// Returns the economic policy governance last set: the network's default
    /// settlement asset and the micro-settlement floor.
    ///
    /// What a settlement pays (the governed fee, the class treasury leg, the
    /// HTTP-402 share and the RPC-provider leg) is in the governed network
    /// parameters; see `docs/ECONOMICS.md`.
    pub async fn get_economic_policy(&self) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getEconomicPolicy", serde_json::json!({}))
            .await
    }

    /// Returns the validator an address names as its RPC provider, the
    /// governed leg paid to it, whether the leg is in force, and what the leg
    /// has paid the address as a validator (`tenzro_getRpcProviderLeg`).
    pub async fn get_rpc_provider_leg(&self, address: &str) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_getRpcProviderLeg",
                serde_json::json!({ "address": address }),
            )
            .await
    }

    /// Returns the latest rolling supply metrics snapshot — circulating
    /// supply, epoch delta, burn breakdown, and supply added (always 0: TNZO
    /// supply is fixed at genesis; reported as `emission_breakdown`).
    pub async fn get_supply_metrics(&self) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getSupplyMetrics", serde_json::json!({}))
            .await
    }

    /// Returns the TNZO/USD rate fees are priced at (nano-USD per TNZO), its
    /// mode (`governance` or `validators`), its hourly rise and fall caps,
    /// the safety rate safety checks value TNZO at, the next block's base fee
    /// in USD and in TNZO, and the settlement fee in basis points.
    pub async fn get_fee_rate(&self) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getFeeRate", serde_json::json!({}))
            .await
    }

    /// Returns the committed USD rate of `symbol` (`ETH`, `SOL`, ...):
    /// nano-USD per whole unit, the epoch it was committed for and the last
    /// report, from the validators' per-symbol median.
    pub async fn get_symbol_rate(&self, symbol: &str) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getFeeRate", serde_json::json!({ "symbol": symbol }))
            .await
    }

    /// Returns growth and concentration metrics for a reward epoch (the
    /// current one when `epoch` is `None`): settled value, payments per
    /// settlement, unique paying root identities, organic against
    /// unattributed volume, burn against rewards released from the pool, and the
    /// holder count, top-10 and
    /// top-100 share and Gini coefficient.
    pub async fn get_economy_metrics(&self, epoch: Option<u64>) -> SdkResult<Value> {
        let params = match epoch {
            Some(epoch) => serde_json::json!({ "epoch": epoch }),
            None => serde_json::json!({}),
        };
        self.rpc.call("tenzro_getEconomyMetrics", params).await
    }
}
