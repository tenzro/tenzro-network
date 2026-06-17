//! Tenzro Hyperbridge ISMP surface.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum HyperbridgeCommand {
    /// Default mint-control policy (post-2026-04-13 hardening).
    MintControlsDefault(RpcOnly),
}

impl HyperbridgeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::MintControlsDefault(c) => c.execute().await,
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
        output::print_header("Hyperbridge Mint Controls (default)");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_hyperbridgeMintControlsDefault", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
