//! Tenzro Stargate V2 Hydra surface.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum StargateV2Command {
    /// List verified Stargate V2 Hydra pools.
    KnownPools(RpcOnly),
}

impl StargateV2Command {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::KnownPools(c) => c.execute().await,
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
        output::print_header("Stargate V2 Hydra — Known Pools");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_stargateV2KnownPools", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
