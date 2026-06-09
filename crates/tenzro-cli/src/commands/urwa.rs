//! ERC-7943 (uRWA) commands.

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
    /// (Admin) Freeze a specific amount on an account
    SetFrozenTokens(SetFrozenCmd),
    /// (Admin) Activate the kill-switch for a token
    TriggerKillSwitch(TriggerKillSwitchCmd),
    /// (Admin) Clear the kill-switch for a token
    ClearKillSwitch(ClearKillSwitchCmd),
}

impl UrwaCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::IsKillSwitched(c) => c.execute().await,
            Self::GetFrozenTokens(c) => c.execute().await,
            Self::SetFrozenTokens(c) => c.execute().await,
            Self::TriggerKillSwitch(c) => c.execute().await,
            Self::ClearKillSwitch(c) => c.execute().await,
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

#[derive(Debug, Parser)]
pub struct SetFrozenCmd {
    #[arg(long)]
    token_id: String,
    #[arg(long)]
    account: String,
    /// Amount in token smallest unit (u128 decimal)
    #[arg(long)]
    amount: String,
    #[arg(long)]
    reason: Option<String>,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    /// Operator admin token (required — sent as X-Tenzro-Admin-Token)
    #[arg(long, env = "TENZRO_ADMIN_TOKEN")]
    admin_token: String,
}

impl SetFrozenCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("uRWA — Set Frozen Tokens");
        let rpc = RpcClient::new(&self.rpc).with_admin_token(&self.admin_token);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_urwaSetFrozenTokens",
                serde_json::json!({
                    "token_id_hex": self.token_id,
                    "account_hex": self.account,
                    "amount": self.amount,
                    "reason": self.reason,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TriggerKillSwitchCmd {
    #[arg(long)]
    token_id: String,
    #[arg(long)]
    triggered_by_did: Option<String>,
    #[arg(long)]
    reason: Option<String>,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    #[arg(long, env = "TENZRO_ADMIN_TOKEN")]
    admin_token: String,
}

impl TriggerKillSwitchCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("uRWA — Trigger Kill-Switch");
        let rpc = RpcClient::new(&self.rpc).with_admin_token(&self.admin_token);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_urwaTriggerKillSwitch",
                serde_json::json!({
                    "token_id_hex": self.token_id,
                    "triggered_by_did": self.triggered_by_did,
                    "reason": self.reason,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ClearKillSwitchCmd {
    #[arg(long)]
    token_id: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    #[arg(long, env = "TENZRO_ADMIN_TOKEN")]
    admin_token: String,
}

impl ClearKillSwitchCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("uRWA — Clear Kill-Switch");
        let rpc = RpcClient::new(&self.rpc).with_admin_token(&self.admin_token);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_urwaClearKillSwitch",
                serde_json::json!({ "token_id_hex": self.token_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
