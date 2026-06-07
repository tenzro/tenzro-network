//! EIP-7702 (Set EOA Account Code) helper commands.
//!
//! Wraps the stateless helper RPCs (`tenzro_eip7702SigningHash`,
//! `tenzro_eip7702BuildDesignator`, `tenzro_eip7702ParseDesignator`,
//! `tenzro_eip7702ProtocolInfo`). Sign the resulting hash with the
//! EOA's secp256k1 key out of band.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum Eip7702Command {
    /// Compute the secp256k1 signing hash for an authorization
    SigningHash(SigningHashCmd),
    /// Build the 23-byte EIP-7702 designator
    BuildDesignator(BuildDesignatorCmd),
    /// Decode an account's code; report the delegate if 7702
    ParseDesignator(ParseDesignatorCmd),
    /// Static protocol metadata
    ProtocolInfo(ProtocolInfoCmd),
}

impl Eip7702Command {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::SigningHash(c) => c.execute().await,
            Self::BuildDesignator(c) => c.execute().await,
            Self::ParseDesignator(c) => c.execute().await,
            Self::ProtocolInfo(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct SigningHashCmd {
    #[arg(long)]
    chain_id: u64,
    #[arg(long)]
    delegate_address: String,
    #[arg(long)]
    nonce: u64,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl SigningHashCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("EIP-7702 — Signing Hash");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_eip7702SigningHash",
                serde_json::json!({
                    "chain_id": self.chain_id,
                    "delegate_address": self.delegate_address,
                    "nonce": self.nonce,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct BuildDesignatorCmd {
    #[arg(long)]
    delegate_address: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl BuildDesignatorCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("EIP-7702 — Build Designator");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_eip7702BuildDesignator",
                serde_json::json!({ "delegate_address": self.delegate_address }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ParseDesignatorCmd {
    /// Account code (hex, with or without 0x prefix)
    #[arg(long)]
    code: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl ParseDesignatorCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("EIP-7702 — Parse Designator");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_eip7702ParseDesignator",
                serde_json::json!({ "code": self.code }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ProtocolInfoCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl ProtocolInfoCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("EIP-7702 — Protocol Info");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_eip7702ProtocolInfo", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
