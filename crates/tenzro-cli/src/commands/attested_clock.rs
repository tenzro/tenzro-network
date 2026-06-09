//! TEE-attested clock commands.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum AttestedClockCommand {
    /// Return the current node wall-clock as an AttestedTimestamp
    Now(NowCmd),
}

impl AttestedClockCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Now(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct NowCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl NowCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Attested Clock — Now");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_attestedClockNow", serde_json::Value::Null)
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
