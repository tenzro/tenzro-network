//! Wormhole NTT (Native Token Transfers) commands.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum WormholeNttCommand {
    /// Enumerate the registered Wormhole NTT chain catalog
    ListChains(ListChainsCmd),
}

impl WormholeNttCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::ListChains(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct ListChainsCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl ListChainsCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Wormhole NTT — Chain Catalog");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_wormholeNttListChains", serde_json::Value::Null)
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
