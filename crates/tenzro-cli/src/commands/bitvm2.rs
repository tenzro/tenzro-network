//! Tenzro BitVM2 / Clementine v2 peg surface.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum BitVm2Command {
    /// List supported BitVM2 / Clementine verifier kinds.
    VerifierKinds(RpcOnly),
}

impl BitVm2Command {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::VerifierKinds(c) => c.execute().await,
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
        output::print_header("BitVM2 Verifier Kinds");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_bitvm2VerifierKinds", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
