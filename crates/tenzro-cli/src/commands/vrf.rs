//! VRF (Verifiable Random Function) commands for the Tenzro CLI.
//!
//! Verifies RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI proofs, as used for
//! provably-fair NFT reveals, lotteries, and randomized trait assignment.
//! Proving needs the VRF secret key, which stays with the hardware signer
//! that holds it; the node offers no RPC that takes one.

use crate::output;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// VRF (Verifiable Random Function) operations
#[derive(Debug, Subcommand)]
pub enum VrfCommand {
    /// Verify a VRF proof against a public key and input message
    Verify(VrfVerifyCmd),
}

impl VrfCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Verify(cmd) => cmd.execute().await,
        }
    }
}

/// Verify a VRF proof
#[derive(Debug, Parser)]
pub struct VrfVerifyCmd {
    /// Hex-encoded 32-byte VRF public key
    #[arg(long)]
    pubkey: String,
    /// Hex-encoded 80-byte VRF proof (Gamma(32) || c(16) || s(32))
    #[arg(long)]
    proof: String,
    /// Hex-encoded input message (alpha)
    #[arg(long)]
    alpha: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl VrfVerifyCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Verify VRF Proof");
        let spinner = output::create_spinner("Verifying...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyVrfProof",
                serde_json::json!({
                    "pubkey": self.pubkey,
                    "proof": self.proof,
                    "alpha": self.alpha,
                }),
            )
            .await?;

        spinner.finish_and_clear();

        let valid = result
            .get("valid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if valid {
            output::print_success("VRF proof is valid!");
            if let Some(output_hex) = result.get("output").and_then(|v| v.as_str()) {
                output::print_field("Output (64B)", output_hex);
            }
        } else {
            let err = result
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            output::print_error(&format!("VRF verification failed: {}", err));
        }

        Ok(())
    }
}
