//! Tenzro DKLS23 pre-signing pool + PKR scheduler observability.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum PresignCommand {
    /// Snapshot of all per-group pre-sign pools.
    Stats(RpcOnly),
    /// PKR scheduler snapshots.
    PkrStatus(RpcOnly),
}

impl PresignCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Stats(c) => c.execute_stats().await,
            Self::PkrStatus(c) => c.execute_pkr().await,
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
    async fn execute_stats(&self) -> Result<()> {
        output::print_header("MPC — Pre-sign Pool Stats");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_mpcPresignStats", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }

    async fn execute_pkr(&self) -> Result<()> {
        output::print_header("MPC — PKR Status");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_mpcPkrStatus", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
