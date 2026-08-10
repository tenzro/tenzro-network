//! Tenzro Sign-In With Tenzro (SIWT) helpers.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum SiwtCommand {
    /// Build a SIWT canonical-form message from JSON fields.
    Build(BuildCmd),
    /// Parse a SIWT canonical-form message.
    Parse(ParseCmd),
}

impl SiwtCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Build(c) => c.execute().await,
            Self::Parse(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct BuildCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    /// SIWT JSON payload (object) — fields: domain, address, statement,
    /// uri, version, chain_id, nonce, issued_at, expiration_time,
    /// not_before, request_id, resources.
    #[arg(long)]
    json: String,
}

impl BuildCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("SIWT Build");
        let v: serde_json::Value = serde_json::from_str(&self.json)?;
        let rpc = RpcClient::new(&self.rpc);
        let out: serde_json::Value = rpc.call("tenzro_siwtBuildMessage", v).await?;
        println!("{}", serde_json::to_string_pretty(&out)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ParseCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    /// Raw SIWT message (multi-line; pass via $(cat file) in shell).
    #[arg(long)]
    message: String,
}

impl ParseCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("SIWT Parse");
        let rpc = RpcClient::new(&self.rpc);
        let out: serde_json::Value = rpc
            .call(
                "tenzro_siwtParseMessage",
                serde_json::json!({ "message": self.message }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&out)?);
        Ok(())
    }
}
