//! Adaptive-burn governance dial commands for the Tenzro CLI.
//!
//! Wraps the read-only `tenzro_get*` JSON-RPC namespace for the adaptive
//! burn-rate dial (tenzro-token). Exposes:
//!
//! - `tenzro adaptive-burn config`           — current `BurnRateConfig`
//! - `tenzro adaptive-burn metrics`          — latest `SupplyMetricsSnapshot`
//! - `tenzro adaptive-burn recommendation`   — recommended action vs targets
//! - `tenzro adaptive-burn proposals`        — burn-dial governance proposals
//! - `tenzro adaptive-burn fee-rate`         — TNZO/USD fee rate and base fee
//! - `tenzro adaptive-burn economy`          — growth and concentration metrics
//!
//! Changes to the dial are `policy_update` proposals decided on-chain
//! (`tenzro governance`); every node applies the enacted change.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;

/// Adaptive-burn governance dial commands
#[derive(Debug, Subcommand)]
pub enum AdaptiveBurnCommand {
    /// Show the active BurnRateConfig (base and local fee burn bps)
    Config(AdaptiveBurnConfigCmd),
    /// Show the latest SupplyMetricsSnapshot (circulating supply, burns, supply added: always 0, TNZO supply is fixed)
    Metrics(AdaptiveBurnMetricsCmd),
    /// Compute the recommended BurnRateRecommendation from current metrics
    Recommendation(AdaptiveBurnRecommendationCmd),
    /// List burn-dial governance proposals, newest first
    Proposals(AdaptiveBurnProposalsCmd),
    /// Show the TNZO/USD rate fees are priced at, its mode, and the base fee
    FeeRate(AdaptiveBurnFeeRateCmd),
    /// Show an epoch's settled value, payers, seed vs organic volume, burn vs
    /// rewards released from the pool and holder concentration
    Economy(AdaptiveBurnEconomyCmd),
}

impl AdaptiveBurnCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Config(cmd) => cmd.execute().await,
            Self::Metrics(cmd) => cmd.execute().await,
            Self::Recommendation(cmd) => cmd.execute().await,
            Self::Proposals(cmd) => cmd.execute().await,
            Self::FeeRate(cmd) => cmd.execute().await,
            Self::Economy(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct AdaptiveBurnConfigCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AdaptiveBurnConfigCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Adaptive Burn — BurnRateConfig");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_getBurnRateConfig", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AdaptiveBurnMetricsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AdaptiveBurnMetricsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Adaptive Burn — SupplyMetricsSnapshot");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_getSupplyMetrics", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AdaptiveBurnRecommendationCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AdaptiveBurnRecommendationCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Adaptive Burn — Recommendation");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_getBurnRateRecommendation", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AdaptiveBurnProposalsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AdaptiveBurnProposalsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Adaptive Burn — Proposals");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_listProposals",
                serde_json::json!({ "kind": "policy_update", "limit": 100 }),
            )
            .await?;
        // Burn-dial changes are the policy updates that set the burn shares or
        // the supply targets the dial steers by.
        let burn: Vec<&serde_json::Value> = v["proposals"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|p| {
                        let update = &p["proposal"]["action"]["update"];
                        update.get("AdaptiveBurnConfigUpdate").is_some()
                            || update.get("SupplyTargetsUpdate").is_some()
                    })
                    .collect()
            })
            .unwrap_or_default();
        println!("{}", serde_json::to_string_pretty(&burn)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AdaptiveBurnFeeRateCmd {
    /// Another asset's committed USD rate instead (`ETH`, `SOL`, ...)
    #[arg(long)]
    symbol: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AdaptiveBurnFeeRateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Fee Rate");
        let rpc = RpcClient::new(&self.rpc);
        let params = match &self.symbol {
            Some(s) => serde_json::json!({ "symbol": s }),
            None => serde_json::json!({}),
        };
        let v: serde_json::Value = rpc.call("tenzro_getFeeRate", params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AdaptiveBurnEconomyCmd {
    /// Reward epoch; the current one when omitted
    #[arg(long)]
    epoch: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AdaptiveBurnEconomyCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Economy Metrics");
        let rpc = RpcClient::new(&self.rpc);
        let params = match self.epoch {
            Some(epoch) => serde_json::json!({ "epoch": epoch }),
            None => serde_json::json!({}),
        };
        let v: serde_json::Value = rpc.call("tenzro_getEconomyMetrics", params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
