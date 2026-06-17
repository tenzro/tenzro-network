//! Tenzro institution identity helpers.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum InstitutionCommand {
    /// Validate a 20-character ISO 17442 LEI via Mod 97-10.
    ValidateLei(ValidateLeiCmd),
}

impl InstitutionCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::ValidateLei(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct ValidateLeiCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    /// 20-character LEI to validate.
    #[arg(long)]
    lei: String,
}

impl ValidateLeiCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("LEI Mod 97-10 Validation");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_validateLei", serde_json::json!({ "lei": self.lei }))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
