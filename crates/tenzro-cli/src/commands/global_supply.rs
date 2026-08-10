//! Tenzro global supply accounting helpers.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum GlobalSupplyCommand {
    /// Read the per-asset policy.
    Policy(PolicyCmd),
    /// Read the per-asset circulating supply.
    Circulating(CirculatingCmd),
}

impl GlobalSupplyCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Policy(c) => c.execute().await,
            Self::Circulating(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct PolicyCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    #[arg(long)]
    asset_id: String,
}

impl PolicyCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Global Supply — Policy");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_globalSupplyPolicy",
                serde_json::json!({ "asset_id": self.asset_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CirculatingCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    #[arg(long)]
    asset_id: String,
}

impl CirculatingCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Global Supply — Circulating");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_globalSupplyCirculating",
                serde_json::json!({ "asset_id": self.asset_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
