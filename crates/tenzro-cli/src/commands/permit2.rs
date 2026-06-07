//! Permit2 SignatureTransfer commands.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum Permit2Command {
    /// Read the EIP-712 domain separator for a chain id
    DomainSeparator(DomainSepCmd),
    /// Compute the EIP-712 digest a user signs
    Digest(DigestCmd),
    /// Atomically verify a signed Permit2 message and consume the nonce
    VerifyAndConsume(VerifyConsumeCmd),
    /// Check whether a (owner, nonce) slot has been consumed
    NonceUsed(NonceUsedCmd),
}

impl Permit2Command {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::DomainSeparator(c) => c.execute().await,
            Self::Digest(c) => c.execute().await,
            Self::VerifyAndConsume(c) => c.execute().await,
            Self::NonceUsed(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct DomainSepCmd {
    #[arg(long)]
    chain_id: u64,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl DomainSepCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Permit2 — Domain Separator");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_permit2DomainSeparator",
                serde_json::json!({ "chain_id": self.chain_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct DigestCmd {
    #[arg(long)]
    chain_id: u64,
    #[arg(long)]
    owner: String,
    #[arg(long)]
    token: String,
    #[arg(long)]
    amount: String,
    #[arg(long)]
    spender: String,
    #[arg(long)]
    nonce: String,
    #[arg(long)]
    deadline: u64,
    #[arg(long)]
    witness: Option<String>,
    #[arg(long)]
    witness_type_string: Option<String>,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl DigestCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Permit2 — Digest");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({
            "chain_id": self.chain_id,
            "owner": self.owner,
            "token": self.token,
            "amount": self.amount,
            "spender": self.spender,
            "nonce": self.nonce,
            "deadline": self.deadline,
        });
        if let Some(w) = &self.witness {
            params["witness"] = serde_json::Value::String(w.clone());
        }
        if let Some(t) = &self.witness_type_string {
            params["witness_type_string"] = serde_json::Value::String(t.clone());
        }
        let v: serde_json::Value = rpc.call("tenzro_permit2Digest", params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct VerifyConsumeCmd {
    #[arg(long)]
    chain_id: u64,
    #[arg(long)]
    owner: String,
    #[arg(long)]
    token: String,
    #[arg(long)]
    amount: String,
    #[arg(long)]
    spender: String,
    #[arg(long)]
    nonce: String,
    #[arg(long)]
    deadline: u64,
    #[arg(long)]
    signature: String,
    #[arg(long)]
    witness: Option<String>,
    #[arg(long)]
    witness_type_string: Option<String>,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl VerifyConsumeCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Permit2 — Verify & Consume");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({
            "chain_id": self.chain_id,
            "owner": self.owner,
            "token": self.token,
            "amount": self.amount,
            "spender": self.spender,
            "nonce": self.nonce,
            "deadline": self.deadline,
            "signature": self.signature,
        });
        if let Some(w) = &self.witness {
            params["witness"] = serde_json::Value::String(w.clone());
        }
        if let Some(t) = &self.witness_type_string {
            params["witness_type_string"] = serde_json::Value::String(t.clone());
        }
        let v: serde_json::Value = rpc
            .call("tenzro_permit2VerifyAndConsume", params)
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct NonceUsedCmd {
    #[arg(long)]
    owner: String,
    #[arg(long)]
    nonce: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl NonceUsedCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Permit2 — Nonce Used");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_permit2NonceUsed",
                serde_json::json!({ "owner": self.owner, "nonce": self.nonce }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
