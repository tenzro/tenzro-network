//! AP2 (Agent Payments Protocol) commands for the Tenzro CLI.
//!
//! Verifies Vdc-wrapped intent/cart mandates and validates mandate
//! pairs. The node never signs — principals sign locally, Tenzro
//! settles.

use clap::{Parser, Subcommand};
use anyhow::{Context, Result};
use crate::output;

/// AP2 (Agent Payments Protocol) operations
#[derive(Debug, Subcommand)]
pub enum Ap2Command {
    /// Verify the Ed25519 signature on a Vdc-wrapped AP2 mandate
    VerifyMandate(Ap2VerifyMandateCmd),
    /// Cross-validate a cart mandate against its parent intent mandate
    ValidatePair(Ap2ValidatePairCmd),
    /// Print AP2 protocol metadata (version, signing alg, kinds)
    Info(Ap2InfoCmd),
}

impl Ap2Command {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::VerifyMandate(cmd) => cmd.execute().await,
            Self::ValidatePair(cmd) => cmd.execute().await,
            Self::Info(cmd) => cmd.execute().await,
        }
    }
}

/// Verify a single Vdc-wrapped mandate
#[derive(Debug, Parser)]
pub struct Ap2VerifyMandateCmd {
    /// Path to a JSON file containing the Vdc object
    #[arg(long)]
    vdc_file: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Ap2VerifyMandateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Verify AP2 Mandate");
        let vdc_str = std::fs::read_to_string(&self.vdc_file)
            .with_context(|| format!("reading {}", self.vdc_file))?;
        let vdc: serde_json::Value = serde_json::from_str(&vdc_str)
            .context("parsing Vdc JSON")?;

        let spinner = output::create_spinner("Verifying signature...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_ap2VerifyMandate", serde_json::json!({ "vdc": vdc }))
            .await?;
        spinner.finish_and_clear();

        let valid = result.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
        if valid {
            output::print_success("Mandate signature is valid");
            output::print_field(
                "Mandate ID",
                result.get("mandate_id").and_then(|v| v.as_str()).unwrap_or(""),
            );
            output::print_field(
                "Kind",
                result.get("kind").and_then(|v| v.as_str()).unwrap_or(""),
            );
            output::print_field(
                "Signer DID",
                result.get("signer_did").and_then(|v| v.as_str()).unwrap_or(""),
            );
            output::print_field(
                "Algorithm",
                result.get("alg").and_then(|v| v.as_str()).unwrap_or(""),
            );
        } else {
            output::print_error(&format!(
                "Mandate INVALID: {}",
                result.get("error").and_then(|v| v.as_str()).unwrap_or("unknown")
            ));
        }
        Ok(())
    }
}

/// Cross-validate an intent+cart mandate pair
#[derive(Debug, Parser)]
pub struct Ap2ValidatePairCmd {
    /// Path to JSON file with the parent intent Vdc
    #[arg(long)]
    intent_file: String,
    /// Path to JSON file with the child cart Vdc
    #[arg(long)]
    cart_file: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Ap2ValidatePairCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Validate AP2 Mandate Pair");
        let intent: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&self.intent_file)
                .with_context(|| format!("reading {}", self.intent_file))?,
        )?;
        let cart: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&self.cart_file)
                .with_context(|| format!("reading {}", self.cart_file))?,
        )?;

        let spinner = output::create_spinner("Cross-validating...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_ap2ValidateMandatePair",
                serde_json::json!({ "intent_vdc": intent, "cart_vdc": cart }),
            )
            .await?;
        spinner.finish_and_clear();

        let valid = result.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
        if valid {
            output::print_success("Mandate pair is valid");
            output::print_field(
                "Intent ID",
                result.get("intent_mandate_id").and_then(|v| v.as_str()).unwrap_or(""),
            );
            output::print_field(
                "Cart ID",
                result.get("cart_mandate_id").and_then(|v| v.as_str()).unwrap_or(""),
            );
            output::print_field(
                "Principal DID",
                result.get("principal_did").and_then(|v| v.as_str()).unwrap_or(""),
            );
            output::print_field(
                "Agent DID",
                result.get("agent_did").and_then(|v| v.as_str()).unwrap_or(""),
            );
        } else {
            output::print_error(&format!(
                "Mandate pair INVALID: {}",
                result.get("error").and_then(|v| v.as_str()).unwrap_or("unknown")
            ));
        }
        Ok(())
    }
}

/// Print AP2 protocol metadata
#[derive(Debug, Parser)]
pub struct Ap2InfoCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Ap2InfoCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("AP2 Protocol Info");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_ap2ProtocolInfo", serde_json::json!({}))
            .await?;

        output::print_field(
            "Version",
            result.get("version").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Signing Algorithm",
            result.get("signing_alg").and_then(|v| v.as_str()).unwrap_or(""),
        );
        if let Some(kinds) = result.get("mandate_kinds").and_then(|v| v.as_array()) {
            let joined: Vec<&str> = kinds.iter().filter_map(|v| v.as_str()).collect();
            output::print_field("Mandate Kinds", &joined.join(", "));
        }
        if let Some(modes) = result.get("presence_modes").and_then(|v| v.as_array()) {
            let joined: Vec<&str> = modes.iter().filter_map(|v| v.as_str()).collect();
            output::print_field("Presence Modes", &joined.join(", "));
        }
        output::print_field(
            "Position",
            result.get("position").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}
