//! Secure-Mint registry commands — per-token 1:1 reserve-attestation
//! invariant for tokenized RWAs.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum SecureMintCommand {
    /// Set or update a Secure-Mint policy for a token
    SetPolicy(SetPolicyCmd),
    /// Read the policy for a token
    GetPolicy(TokenCmd),
    /// Clear the policy for a token
    ClearPolicy(TokenCmd),
    /// Read-only invariant check for a proposed mint
    Check(TokenAmountCmd),
    /// Atomic check + circulating increment
    Apply(TokenAmountCmd),
    /// Decrement circulating on redemption
    RecordBurn(TokenAmountCmd),
    /// Trip or clear the per-token issuance circuit breaker
    SetPaused(SetPausedCmd),
    /// Trip or clear the global issuance circuit breaker
    SetGlobalPause(SetGlobalPauseCmd),
}

impl SecureMintCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::SetPolicy(c) => c.execute().await,
            Self::GetPolicy(c) => c.execute("tenzro_getSecureMintPolicy").await,
            Self::ClearPolicy(c) => c.execute("tenzro_clearSecureMintPolicy").await,
            Self::Check(c) => c.execute("tenzro_secureMintCheck").await,
            Self::Apply(c) => c.execute("tenzro_secureMintApply").await,
            Self::RecordBurn(c) => c.execute("tenzro_secureMintRecordBurn").await,
            Self::SetPaused(c) => c.execute().await,
            Self::SetGlobalPause(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct SetPolicyCmd {
    /// 20-byte token address (0x-hex)
    #[arg(long)]
    token: String,
    /// CAIP-19 reserve asset id (e.g. iso4217:USD)
    #[arg(long)]
    asset_id: String,
    #[arg(long)]
    reserve: String,
    #[arg(long)]
    circulating: Option<String>,
    #[arg(long)]
    por_feed_id: String,
    #[arg(long)]
    attester_did: String,
    #[arg(long)]
    attestation_hash: String,
    #[arg(long)]
    attested_at: u64,
    #[arg(long)]
    ttl_secs: u64,
    /// PoR feed-liveness window in seconds (0 = disabled). Distinct from
    /// ttl_secs: gates mint on a *live* attestation heartbeat.
    #[arg(long)]
    heartbeat_secs: Option<u64>,
    /// Max amount mintable per rolling window (0 = uncapped).
    #[arg(long)]
    mint_window_cap: Option<String>,
    /// Length of the velocity window in seconds (0 = disabled).
    #[arg(long)]
    mint_window_secs: Option<u64>,
    /// Install the policy already tripped (mint blocked until cleared).
    #[arg(long)]
    paused: bool,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl SetPolicyCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Secure-Mint — Set Policy");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({
            "token": self.token,
            "asset_id": self.asset_id,
            "reserve": self.reserve,
            "por_feed_id": self.por_feed_id,
            "attester_did": self.attester_did,
            "attestation_hash": self.attestation_hash,
            "attested_at": self.attested_at,
            "ttl_secs": self.ttl_secs,
            "paused": self.paused,
        });
        if let Some(c) = &self.circulating {
            params["circulating"] = serde_json::Value::String(c.clone());
        }
        if let Some(h) = self.heartbeat_secs {
            params["heartbeat_secs"] = serde_json::Value::from(h);
        }
        if let Some(c) = &self.mint_window_cap {
            params["mint_window_cap"] = serde_json::Value::String(c.clone());
        }
        if let Some(s) = self.mint_window_secs {
            params["mint_window_secs"] = serde_json::Value::from(s);
        }
        let v: serde_json::Value = rpc.call("tenzro_setSecureMintPolicy", params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TokenCmd {
    /// 20-byte token address (0x-hex)
    #[arg(long)]
    token: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl TokenCmd {
    pub async fn execute(&self, method: &str) -> Result<()> {
        output::print_header(&format!("Secure-Mint — {}", method));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(method, serde_json::json!({ "token": self.token }))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TokenAmountCmd {
    /// 20-byte token address (0x-hex)
    #[arg(long)]
    token: String,
    #[arg(long)]
    amount: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl TokenAmountCmd {
    pub async fn execute(&self, method: &str) -> Result<()> {
        output::print_header(&format!("Secure-Mint — {}", method));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                method,
                serde_json::json!({ "token": self.token, "amount": self.amount }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SetPausedCmd {
    /// 20-byte token address (0x-hex)
    #[arg(long)]
    token: String,
    /// true to trip the per-token breaker, false to clear it
    #[arg(long, action = clap::ArgAction::Set)]
    paused: bool,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl SetPausedCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Secure-Mint — Set Paused");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_setSecureMintPaused",
                serde_json::json!({ "token": self.token, "paused": self.paused }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SetGlobalPauseCmd {
    /// true to halt mint across every token, false to resume
    #[arg(long, action = clap::ArgAction::Set)]
    paused: bool,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl SetGlobalPauseCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Secure-Mint — Set Global Pause");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_setGlobalIssuancePause",
                serde_json::json!({ "paused": self.paused }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
