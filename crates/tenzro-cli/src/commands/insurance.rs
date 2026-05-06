//! Insurance claim commands for the Tenzro CLI (Agent-Swarm Spec 9).
//!
//! When a bonded agent causes harm, anyone holding receipts can file
//! an insurance claim. Claims enter the `Open` state awaiting
//! governance adjudication; if approved, payout is triggered by a
//! `PayInsuranceClaim` typed transaction (governance-only — not
//! exposed as a direct CLI write).
//!
//! - `tenzro insurance claim` — file a new claim (`tenzro_fileInsuranceClaim`)
//! - `tenzro insurance list` — list all claims (`tenzro_listInsuranceClaims`)
//! - `tenzro insurance get` — fetch a single claim (`tenzro_getInsuranceClaim`)
//! - `tenzro insurance pool` — show insurance-pool balance and counters
//!   (`tenzro_getInsurancePoolBalance`)

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Insurance claim commands (Spec 9)
#[derive(Debug, Subcommand)]
pub enum InsuranceCommand {
    /// File a new insurance claim against a bonded agent
    Claim(InsuranceClaimCmd),
    /// List all insurance claims (read-only)
    List(InsuranceListCmd),
    /// Inspect a single claim by id (read-only)
    Get(InsuranceGetCmd),
    /// Show insurance-pool balance and aggregate counters (read-only)
    Pool(InsurancePoolCmd),
}

impl InsuranceCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Claim(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::Pool(cmd) => cmd.execute().await,
        }
    }
}

/// File a new insurance claim against a bonded agent.
#[derive(Debug, Parser)]
pub struct InsuranceClaimCmd {
    /// Claimant DID (the harmed party)
    #[arg(long)]
    claimant_did: String,

    /// Claimant wallet address (hex; payout destination if claim is approved)
    #[arg(long)]
    claimant_address: String,

    /// Agent DID the claim is filed against (must have an Active or recently-Slashed bond)
    #[arg(long)]
    against_agent_did: String,

    /// Requested payout amount in wei
    #[arg(long)]
    amount_requested: u128,

    /// Receipt references (repeatable; e.g. tx hashes, settlement ids, log refs)
    #[arg(long, value_name = "REF")]
    receipt: Vec<String>,

    /// Free-form narrative describing the harm (capped to 1024 bytes server-side)
    #[arg(long)]
    narrative: Option<String>,

    /// Nonce for deterministic claim_id derivation
    #[arg(long)]
    nonce: u64,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InsuranceClaimCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("File Insurance Claim");

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Filing claim...");

        let mut params = serde_json::json!({
            "claimant_did": self.claimant_did,
            "claimant_address": self.claimant_address,
            "against_agent_did": self.against_agent_did,
            "amount_requested": self.amount_requested.to_string(),
            "receipt_refs": self.receipt,
            "nonce": self.nonce,
        });
        if let Some(n) = &self.narrative {
            params["narrative"] = serde_json::Value::String(n.clone());
        }

        let result: serde_json::Value = rpc.call("tenzro_fileInsuranceClaim", params).await?;

        spinner.finish_and_clear();

        output::print_success("Insurance claim filed (status: Open)");
        println!();
        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }
        println!();
        output::print_warning(
            "Payout is governance-adjudicated. If approved, a PayInsuranceClaim \
             transaction will settle the claim against the deterministic vault."
        );
        Ok(())
    }
}

/// List all insurance claims.
#[derive(Debug, Parser)]
pub struct InsuranceListCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InsuranceListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Insurance Claims");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_listInsuranceClaims", serde_json::Value::Null)
            .await?;

        let claims = result
            .get("claims")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);

        println!();
        output::print_field("Total Claims", &count.to_string());
        println!();

        if claims.is_empty() {
            output::print_warning("No claims filed.");
            return Ok(());
        }

        for (i, claim) in claims.iter().enumerate() {
            println!("Claim #{}", i + 1);
            for (key, val) in claim.as_object().unwrap_or(&serde_json::Map::new()) {
                output::print_field(key, val.to_string().trim_matches('"'));
            }
            println!();
        }

        Ok(())
    }
}

/// Inspect a single insurance claim by id.
#[derive(Debug, Parser)]
pub struct InsuranceGetCmd {
    /// Claim ID (hex)
    claim_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InsuranceGetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Insurance Claim Details");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getInsuranceClaim",
                serde_json::json!({ "claim_id": self.claim_id }),
            )
            .await?;

        if result.is_null() {
            output::print_warning(&format!("No claim found with id {}", self.claim_id));
            return Ok(());
        }

        println!();
        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }

        Ok(())
    }
}

/// Show insurance pool aggregate state.
#[derive(Debug, Parser)]
pub struct InsurancePoolCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InsurancePoolCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Insurance Pool");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getInsurancePoolBalance", serde_json::Value::Null)
            .await?;

        println!();
        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }

        Ok(())
    }
}
