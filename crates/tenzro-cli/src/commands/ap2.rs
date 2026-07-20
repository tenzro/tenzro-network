//! AP2 (Agent Payments Protocol) v0.2 commands for the Tenzro CLI.
//!
//! Signs and verifies Vdc-wrapped Checkout/Payment mandates and validates
//! mandate pairs. The `sign-mandate` subcommand uses the auth-bound
//! wallet's Ed25519 key on the node — no raw private keys leave the
//! caller's environment beyond the DPoP+JWT bearer.

use clap::{Parser, Subcommand};
use anyhow::{Context, Result};
use crate::output;

/// AP2 (Agent Payments Protocol) v0.2 operations
#[derive(Debug, Subcommand)]
pub enum Ap2Command {
    /// Sign an AP2 v0.2 Checkout or Payment mandate via the auth-bound wallet
    SignMandate(Ap2SignMandateCmd),
    /// Verify the Ed25519 signature on a Vdc-wrapped AP2 mandate
    VerifyMandate(Ap2VerifyMandateCmd),
    /// Cross-validate a PaymentMandate against its parent CheckoutMandate
    ValidatePair(Ap2ValidatePairCmd),
    /// List persisted intent/cart mandate pairs for a controller DID
    ListMandates(Ap2ListMandatesCmd),
    /// Print AP2 protocol metadata (version, signing alg, kinds)
    Info(Ap2InfoCmd),
}

impl Ap2Command {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::SignMandate(cmd) => cmd.execute().await,
            Self::VerifyMandate(cmd) => cmd.execute().await,
            Self::ValidatePair(cmd) => cmd.execute().await,
            Self::ListMandates(cmd) => cmd.execute().await,
            Self::Info(cmd) => cmd.execute().await,
        }
    }
}

/// Sign an AP2 v0.2 Checkout or Payment mandate via the auth-bound wallet.
///
/// Auth: requires `TENZRO_BEARER_JWT` (and `TENZRO_DPOP_PROOF`) to be set
/// — the RpcClient forwards them to the node, which signs the canonical
/// AP2 v0.2 preimage with the wallet's Ed25519 key. The returned VDC
/// self-verifies before being printed.
#[derive(Debug, Parser)]
pub struct Ap2SignMandateCmd {
    /// Mandate kind: `checkout` (principal-signed pre-authorization) or
    /// `payment` (agent-signed final-offer commit) per AP2 v0.2.
    #[arg(long, value_parser = ["checkout", "payment"])]
    kind: String,
    /// Path to a JSON file containing the CheckoutMandate or PaymentMandate
    #[arg(long)]
    mandate_file: String,
    /// Signer DID — must match the controller of the auth-bound wallet
    /// (principal for checkout, agent for payment)
    #[arg(long)]
    signer_did: String,
    /// Optional path to write the signed VDC; if omitted, prints to stdout
    #[arg(long)]
    out: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Ap2SignMandateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Sign AP2 Mandate");
        let mandate_str = std::fs::read_to_string(&self.mandate_file)
            .with_context(|| format!("reading {}", self.mandate_file))?;
        let mandate: serde_json::Value = serde_json::from_str(&mandate_str)
            .context("parsing mandate JSON")?;

        let spinner = output::create_spinner("Signing via auth-bound wallet...");
        let rpc = RpcClient::new(&self.rpc);
        let vdc: serde_json::Value = rpc
            .call(
                "tenzro_ap2SignMandate",
                serde_json::json!({
                    "mandate_kind": self.kind,
                    "mandate": mandate,
                    "signer_did": self.signer_did,
                }),
            )
            .await?;
        spinner.finish_and_clear();

        let pretty = serde_json::to_string_pretty(&vdc)?;
        if let Some(path) = &self.out {
            std::fs::write(path, &pretty)
                .with_context(|| format!("writing {}", path))?;
            output::print_success(&format!("VDC written to {}", path));
            output::print_field(
                "Mandate ID",
                vdc.get("payload")
                    .and_then(|p| p.get("mandate_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            );
            output::print_field(
                "Signer DID",
                vdc.get("signer_did").and_then(|v| v.as_str()).unwrap_or(""),
            );
        } else {
            output::print_success("Signed VDC:");
            println!("{pretty}");
        }
        Ok(())
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

/// Cross-validate a CheckoutMandate + PaymentMandate pair (AP2 v0.2)
#[derive(Debug, Parser)]
pub struct Ap2ValidatePairCmd {
    /// Path to JSON file with the parent CheckoutMandate Vdc (AP2 v0.2)
    #[arg(long)]
    checkout_file: String,
    /// Path to JSON file with the child PaymentMandate Vdc (AP2 v0.2)
    #[arg(long)]
    payment_file: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Ap2ValidatePairCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Validate AP2 Mandate Pair");
        let checkout: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&self.checkout_file)
                .with_context(|| format!("reading {}", self.checkout_file))?,
        )?;
        let payment: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&self.payment_file)
                .with_context(|| format!("reading {}", self.payment_file))?,
        )?;

        let spinner = output::create_spinner("Cross-validating...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_ap2ValidateMandatePair",
                serde_json::json!({ "checkout_vdc": checkout, "payment_vdc": payment }),
            )
            .await?;
        spinner.finish_and_clear();

        let valid = result.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
        if valid {
            output::print_success("Mandate pair is valid");
            output::print_field(
                "Checkout ID",
                result.get("checkout_mandate_id").and_then(|v| v.as_str()).unwrap_or(""),
            );
            output::print_field(
                "Payment ID",
                result.get("payment_mandate_id").and_then(|v| v.as_str()).unwrap_or(""),
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
/// List persisted intent/cart mandate pairs authorized by a controller DID.
///
/// Calls `tenzro_listMandates` and prints the stored records — each carrying
/// the mandate id, payment-mandate id, the controller/agent/merchant DIDs,
/// `max_amount` + `total_amount` (decimal strings), asset, chain, expiry, the
/// `delegation_enforced` flag, and the stored checkout/payment VDCs.
#[derive(Debug, Parser)]
pub struct Ap2ListMandatesCmd {
    /// Controller DID whose persisted mandates to list
    #[arg(long)]
    controller_did: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Ap2ListMandatesCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("AP2 Persisted Mandates");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listMandates",
                serde_json::json!({ "controller_did": self.controller_did }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

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
