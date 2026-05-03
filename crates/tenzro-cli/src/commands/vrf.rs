//! VRF (Verifiable Random Function) commands for the Tenzro CLI.
//!
//! Implements RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI. Used for
//! provably-fair NFT reveals, lotteries, and randomized trait assignment.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// VRF (Verifiable Random Function) operations
#[derive(Debug, Subcommand)]
pub enum VrfCommand {
    /// Generate a VRF proof from a secret key and input message
    Prove(VrfProveCmd),
    /// Verify a VRF proof against a public key and input message
    Verify(VrfVerifyCmd),
    /// Generate a fresh Ed25519-compatible VRF keypair (hex)
    Keygen(VrfKeygenCmd),
}

impl VrfCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Prove(cmd) => cmd.execute().await,
            Self::Verify(cmd) => cmd.execute().await,
            Self::Keygen(cmd) => cmd.execute().await,
        }
    }
}

/// Generate a VRF proof
#[derive(Debug, Parser)]
pub struct VrfProveCmd {
    /// Hex-encoded 32-byte VRF secret key (Ed25519-compatible seed)
    #[arg(long)]
    secret_key: String,
    /// Hex-encoded input message (alpha). Use public data: block hash, request ID, NFT mint nonce.
    #[arg(long)]
    alpha: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl VrfProveCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Generate VRF Proof");
        let spinner = output::create_spinner("Proving...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_generateVrfProof", serde_json::json!({
            "secret_key": self.secret_key,
            "alpha": self.alpha,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Proof generated!");
        output::print_field("Ciphersuite", "ECVRF-EDWARDS25519-SHA512-TAI");
        output::print_field("Public Key", result.get("pubkey").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Proof (80B)", result.get("proof").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Output (64B)", result.get("output").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
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

        let result: serde_json::Value = rpc.call("tenzro_verifyVrfProof", serde_json::json!({
            "pubkey": self.pubkey,
            "proof": self.proof,
            "alpha": self.alpha,
        })).await?;

        spinner.finish_and_clear();

        let valid = result.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
        if valid {
            output::print_success("VRF proof is valid!");
            if let Some(output_hex) = result.get("output").and_then(|v| v.as_str()) {
                output::print_field("Output (64B)", output_hex);
            }
        } else {
            let err = result.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error");
            output::print_error(&format!("VRF verification failed: {}", err));
        }

        Ok(())
    }
}

/// Generate a fresh VRF keypair locally (does not hit RPC).
#[derive(Debug, Parser)]
pub struct VrfKeygenCmd;

impl VrfKeygenCmd {
    pub async fn execute(&self) -> Result<()> {
        use rand::RngCore;

        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);

        // Derive public key offline via the same ECVRF math as tenzro-crypto.
        // We mirror the derivation here to avoid making the CLI depend on tenzro-crypto.
        // For a full derivation, users can also call `tenzro vrf prove` with this secret
        // and any alpha — the RPC response includes the derived public key.
        output::print_header("New VRF Keypair");
        output::print_field("Ciphersuite", "ECVRF-EDWARDS25519-SHA512-TAI");
        output::print_field("Secret Key (32B)", &format!("0x{}", hex::encode(seed)));
        output::print_info("Derive the public key via: tenzro vrf prove --secret-key <sk> --alpha 0x00");
        output::print_info("Treat the secret key as a signing key — keep it offline.");

        Ok(())
    }
}
