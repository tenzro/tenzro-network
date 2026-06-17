//! Tenzro IBC-Eureka light-client surface (read-only discovery for now).

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum IbcEurekaCommand {
    /// Commitment domain tag the on-EVM IBC_VERIFY precompile (0x1020) uses.
    CommitmentTag(RpcOnly),
}

impl IbcEurekaCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::CommitmentTag(c) => c.execute().await,
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
        output::print_header("IBC-Eureka Commitment Tag");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_ibcEurekaCommitmentTag", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
