//! Decentralized MoE serving commands.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum MoeCommand {
    /// Show the live expert-shard map for a model (holders, replication,
    /// hot experts, under-replicated experts).
    ShardMap(ShardMapCmd),
    /// Build a dispatch plan from a JSON file of top-k routing decisions.
    /// Useful for inspecting how a request would fan out across holders
    /// before submitting it.
    PlanDispatch(PlanDispatchCmd),
    /// Show the current governance-tuned replication policy.
    ReplicationPolicy(RpcOnly),
    /// Show the catalog-side MoE topology for a model.
    CatalogShape(CatalogShapeCmd),
}

impl MoeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::ShardMap(c) => c.execute().await,
            Self::PlanDispatch(c) => c.execute().await,
            Self::ReplicationPolicy(c) => c.execute().await,
            Self::CatalogShape(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct RpcOnly {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl RpcOnly {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("MoE Replication Policy");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_moeReplicationPolicy", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ShardMapCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    /// Tenzro model id (e.g. `qwen3.5-397b-a17b`).
    #[arg(long)]
    model_id: String,
}

impl ShardMapCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!("MoE Shard Map — {}", self.model_id));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_moeShardMap",
                serde_json::json!({ "model_id": self.model_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct PlanDispatchCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    /// Tenzro model id.
    #[arg(long)]
    model_id: String,
    /// Path to a JSON file containing an array of routing decisions —
    /// `[{token_index: u32, experts: [{layer: u32, expert: u32}, ...]}]`.
    #[arg(long)]
    routings_json: String,
    /// Allow cold-residency holders when no warm holder is available.
    #[arg(long, default_value_t = false)]
    allow_cold: bool,
}

impl PlanDispatchCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!("MoE Dispatch Plan — {}", self.model_id));
        let raw = std::fs::read_to_string(&self.routings_json)?;
        let routings: serde_json::Value = serde_json::from_str(&raw)?;
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_moePlanDispatch",
                serde_json::json!({
                    "model_id": self.model_id,
                    "allow_cold": self.allow_cold,
                    "routings": routings,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CatalogShapeCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    #[arg(long)]
    model_id: String,
}

impl CatalogShapeCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!("MoE Catalog Shape — {}", self.model_id));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_moeCatalogShape",
                serde_json::json!({ "model_id": self.model_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
