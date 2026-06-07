//! Secure-Mint registry commands — per-token 1:1 reserve-attestation
//! invariant for tokenized RWAs.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum SecureMintCommand {
    /// Set or update a Secure-Mint policy for an asset
    SetPolicy(SetPolicyCmd),
    /// Read the policy for an asset
    GetPolicy(AssetIdCmd),
    /// Clear the policy for an asset
    ClearPolicy(AssetIdCmd),
    /// Read-only invariant check for a proposed mint
    Check(AssetAmountCmd),
    /// Atomic check + circulating increment
    Apply(AssetAmountCmd),
    /// Decrement circulating on redemption
    RecordBurn(AssetAmountCmd),
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
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct SetPolicyCmd {
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
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl SetPolicyCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Secure-Mint — Set Policy");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({
            "asset_id": self.asset_id,
            "reserve": self.reserve,
            "por_feed_id": self.por_feed_id,
            "attester_did": self.attester_did,
            "attestation_hash": self.attestation_hash,
            "attested_at": self.attested_at,
            "ttl_secs": self.ttl_secs,
        });
        if let Some(c) = &self.circulating {
            params["circulating"] = serde_json::Value::String(c.clone());
        }
        let v: serde_json::Value = rpc.call("tenzro_setSecureMintPolicy", params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AssetIdCmd {
    #[arg(long)]
    asset_id: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl AssetIdCmd {
    pub async fn execute(&self, method: &str) -> Result<()> {
        output::print_header(&format!("Secure-Mint — {}", method));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(method, serde_json::json!({ "asset_id": self.asset_id }))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AssetAmountCmd {
    #[arg(long)]
    asset_id: String,
    #[arg(long)]
    amount: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl AssetAmountCmd {
    pub async fn execute(&self, method: &str) -> Result<()> {
        output::print_header(&format!("Secure-Mint — {}", method));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                method,
                serde_json::json!({ "asset_id": self.asset_id, "amount": self.amount }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
