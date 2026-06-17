//! Tenzro NEAR Chain Signatures helpers.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum NearChainSigCommand {
    /// Compute the NEAR MPC `epsilon` derivation for `(predecessor, path)`.
    Epsilon(EpsilonCmd),
}

impl NearChainSigCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Epsilon(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct EpsilonCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    /// NEAR predecessor account id (the caller).
    #[arg(long)]
    predecessor: String,
    /// Derivation path (e.g. `bitcoin-1`, `ethereum-mainnet-tnzo`).
    #[arg(long)]
    path: String,
}

impl EpsilonCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("NEAR Chain Signatures Epsilon");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_nearChainSigEpsilon",
                serde_json::json!({
                    "predecessor": self.predecessor,
                    "path": self.path,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
