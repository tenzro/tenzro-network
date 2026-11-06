//! ERC-7943 (uRWA) reads. The issuer's controls (freezing, halting, forced
//! transfers) are signed `Token` transactions: `tenzro token freeze|halt|force-transfer`.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum UrwaCommand {
    /// Check whether the kill-switch is active for a token
    IsKillSwitched(IsKillSwitchedCmd),
    /// Read the frozen-token amount for a (token, account) pair
    GetFrozenTokens(GetFrozenCmd),
}

impl UrwaCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::IsKillSwitched(c) => c.execute().await,
            Self::GetFrozenTokens(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct IsKillSwitchedCmd {
    /// 32-byte hex-encoded token id (with or without 0x)
    #[arg(long)]
    token_id: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl IsKillSwitchedCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("uRWA — Kill-Switch State");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_urwaIsKillSwitched",
                serde_json::json!({ "token_id_hex": self.token_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct GetFrozenCmd {
    #[arg(long)]
    token_id: String,
    /// 20-byte hex-encoded account address
    #[arg(long)]
    account: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl GetFrozenCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("uRWA — Frozen Tokens");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_urwaGetFrozenTokens",
                serde_json::json!({ "token_id_hex": self.token_id, "account_hex": self.account }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
