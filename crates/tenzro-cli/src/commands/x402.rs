//! x402 (Coinbase HTTP-402 micropayment protocol) commands.
//!
//! Tenzro is an x402 facilitator: clients send a one-shot payment header
//! against an `HTTP 402 Payment Required` challenge, and the node verifies
//! and (optionally) settles on-chain via the configured scheme.
//!
//! These commands are thin wrappers around the existing x402 RPCs:
//!
//! - `tenzro_listX402Schemes` — enumerate scheme adapters (e.g. `exact`,
//!   `permit2`) registered with the facilitator.
//! - `tenzro_payX402` — submit a payment payload against a challenge.
//!
//! For the higher-level `tenzro payment pay --protocol x402` flow, see
//! `tenzro payment`. This module exists so users who think in protocol
//! terms ("I want to pay an x402 challenge") can drive the CLI by name.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// x402 (Coinbase HTTP-402) operations.
#[derive(Debug, Subcommand)]
pub enum X402Command {
    /// List the x402 scheme adapters this facilitator can verify.
    ListSchemes(X402ListSchemesCmd),
    /// Submit an x402 payment payload against a challenge.
    Pay(X402PayCmd),
}

impl X402Command {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::ListSchemes(cmd) => cmd.execute().await,
            Self::Pay(cmd) => cmd.execute().await,
        }
    }
}

/// `tenzro x402 list-schemes` — enumerate registered scheme verifiers.
#[derive(Debug, Parser)]
pub struct X402ListSchemesCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl X402ListSchemesCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("x402 Schemes");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_listX402Schemes", serde_json::json!({}))
            .await
            .context("calling tenzro_listX402Schemes")?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// `tenzro x402 pay` — submit a payment payload.
///
/// The payload is the `X-PAYMENT` header value the client built locally
/// (signed authorization for `exact` scheme, signed Permit2 for `permit2`,
/// etc.). The CLI does not construct or sign payloads — that is the
/// principal's job per the AP2 separation-of-duties rule.
#[derive(Debug, Parser)]
pub struct X402PayCmd {
    /// Path to a JSON file containing the x402 PaymentRequired challenge
    /// (the body of the `402` response).
    #[arg(long)]
    challenge_file: String,

    /// Path to a JSON file containing the X-PAYMENT payload (already
    /// signed by the principal's wallet).
    #[arg(long)]
    payload_file: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl X402PayCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("x402 Pay");
        let challenge: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&self.challenge_file)
                .with_context(|| format!("reading {}", self.challenge_file))?,
        )
        .context("parsing challenge JSON")?;
        let payload: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&self.payload_file)
                .with_context(|| format!("reading {}", self.payload_file))?,
        )
        .context("parsing payload JSON")?;

        let spinner = output::create_spinner("Submitting payment to facilitator...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_payX402",
                serde_json::json!({
                    "challenge": challenge,
                    "payload": payload,
                }),
            )
            .await
            .context("calling tenzro_payX402")?;
        spinner.finish_and_clear();

        output::print_json(&result)?;
        Ok(())
    }
}
