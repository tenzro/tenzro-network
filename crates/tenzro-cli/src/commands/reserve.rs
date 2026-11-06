//! Proof-of-Reserve commands: submit and read the reserve attestation
//! backing a tokenized asset (`tenzro_submitReserveAttestation`,
//! `tenzro_getReserve`).

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

const DEFAULT_RPC: &str = "http://127.0.0.1:8545";

/// Proof-of-Reserve operations.
#[derive(Debug, Subcommand)]
pub enum ReserveCommand {
    /// Submit a Proof-of-Reserve attestation backing a tokenized asset.
    Submit(ReserveSubmitCmd),
    /// Read the current reserve attestation.
    Get(ReserveGetCmd),
}

impl ReserveCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Submit(c) => c.execute().await,
            Self::Get(c) => c.execute().await,
        }
    }
}

fn read_json_arg(arg: &str) -> Result<serde_json::Value> {
    let text = if let Some(path) = arg.strip_prefix('@') {
        std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?
    } else {
        arg.to_string()
    };
    serde_json::from_str(&text).context("parsing JSON argument")
}

#[derive(Debug, Parser)]
pub struct ReserveSubmitCmd {
    /// ReserveAttestation JSON (inline or `@file.json`).
    attestation: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl ReserveSubmitCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Reserve: Submit Attestation");
        let att = read_json_arg(&self.attestation)?;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_submitReserveAttestation",
                serde_json::json!({ "attestation": att }),
            )
            .await
            .context("calling tenzro_submitReserveAttestation")?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ReserveGetCmd {
    /// Tokenized-asset id.
    asset_id: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl ReserveGetCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Reserve: Get");
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_getReserve",
                serde_json::json!({ "asset_id": self.asset_id }),
            )
            .await
            .context("calling tenzro_getReserve")?;
        output::print_json(&result)?;
        Ok(())
    }
}
