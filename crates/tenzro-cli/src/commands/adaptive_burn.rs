//! Adaptive-burn governance dial commands for the Tenzro CLI.
//!
//! Wraps the read-only `tenzro_get*` JSON-RPC namespace for the adaptive
//! burn-rate dial (Spec 7 / tenzro-token). Exposes:
//!
//! - `tenzro adaptive-burn config`           — current `BurnRateConfig`
//! - `tenzro adaptive-burn metrics`          — latest `SupplyMetricsSnapshot`
//! - `tenzro adaptive-burn recommendation`   — recommended action vs targets
//! - `tenzro adaptive-burn proposals`        — in-flight governance proposals
//!
//! Write-side (auto-proposal generator + EIP-1559 fee-market consumer) lands
//! with the governance executor wiring.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;

/// Adaptive-burn governance dial commands
#[derive(Debug, Subcommand)]
pub enum AdaptiveBurnCommand {
    /// Show the active BurnRateConfig (base/local/paymaster bps)
    Config(AdaptiveBurnConfigCmd),
    /// Show the latest SupplyMetricsSnapshot (circulating supply, burn/emission)
    Metrics(AdaptiveBurnMetricsCmd),
    /// Compute the recommended BurnRateRecommendation from current metrics
    Recommendation(AdaptiveBurnRecommendationCmd),
    /// List in-flight adaptive-burn governance proposals
    Proposals(AdaptiveBurnProposalsCmd),
}

impl AdaptiveBurnCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Config(cmd) => cmd.execute().await,
            Self::Metrics(cmd) => cmd.execute().await,
            Self::Recommendation(cmd) => cmd.execute().await,
            Self::Proposals(cmd) => cmd.execute().await,
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
        output::print_header("Adaptive Burn — In-flight Proposals");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_listAdaptiveBurnProposals", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
