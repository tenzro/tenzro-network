//! Post-quantum hybrid signing helpers for the Tenzro CLI.
//!
//! Lets operators check which legs of the composite signature a transaction
//! carried: the hardware P-256 leg (raw or passkey assertion) and, when the
//! account enrolled an ML-DSA-65 key, the ML-DSA-65 leg.
//!
//! - `tenzro pq-hybrid inspect <tx_hash>`: show the signature legs of a transaction
//! - `tenzro pq-hybrid enroll`: enroll the hardware's ML-DSA-65 key as the
//!   client account's post-quantum key. An account signs nothing until it has
//!   enrolled one; any command that sends a transaction from a new account
//!   enrolls it first.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;

/// PQ-hybrid signing helper commands
#[derive(Debug, Subcommand)]
pub enum PqHybridCommand {
    /// Inspect a finalized transaction's signature legs
    Inspect(PqHybridInspectCmd),
    /// Enroll the hardware ML-DSA-65 key as the client account's post-quantum key
    Enroll(PqHybridEnrollCmd),
}

impl PqHybridCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Inspect(cmd) => cmd.execute().await,
            Self::Enroll(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct PqHybridEnrollCmd {
    /// The client account's hardware key namespace
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PqHybridEnrollCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("PQ Hybrid - Enroll");
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let answer = crate::keystore::enroll_client_pq_key(&rpc, &self.key_namespace).await?;
        output::print_success("ML-DSA-65 key enrolled for the client account");
        output::print_field(
            "Tx Hash",
            &answer
                .as_str()
                .map_or_else(|| answer.to_string(), str::to_string),
        );
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct PqHybridInspectCmd {
    /// Transaction hash
    #[arg(long)]
    tx_hash: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PqHybridInspectCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("PQ Hybrid — Inspect");
        let rpc = RpcClient::new(&self.rpc);
        let tx: serde_json::Value = rpc
            .call("tenzro_getTransaction", serde_json::json!([self.tx_hash]))
            .await?;

        let signature = &tx["signature"];
        let form = signature["classical"]["form"].as_str().unwrap_or("absent");
        let has_pq = signature.get("pq").is_some_and(|v| !v.is_null());
        output::print_field(
            "p256_public_key",
            tx["public_key"].as_str().unwrap_or("absent"),
        );
        output::print_field("p256_signature_form", form);
        output::print_field("ml_dsa_65_signature_present", &has_pq.to_string());
        println!("{}", serde_json::to_string_pretty(&tx)?);
        Ok(())
    }
}
