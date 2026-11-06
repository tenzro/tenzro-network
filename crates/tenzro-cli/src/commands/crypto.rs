//! Cryptographic operations for the Tenzro CLI
//!
//! Verify signatures and compute hashes. Signing, encryption and key
//! generation happen where the key is held, never through the node.

use crate::output;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Cryptographic operations
#[derive(Debug, Subcommand)]
pub enum CryptoCommand {
    /// Verify a message signature
    Verify(CryptoVerifyCmd),
}

impl CryptoCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Verify(cmd) => cmd.execute().await,
        }
    }
}

/// Verify a signature
#[derive(Debug, Parser)]
pub struct CryptoVerifyCmd {
    /// Public key (hex)
    #[arg(long)]
    key: String,
    /// Message (hex)
    #[arg(long)]
    message: String,
    /// Signature (hex)
    #[arg(long)]
    signature: String,
    /// Key type: ed25519 or secp256k1
    #[arg(long, default_value = "ed25519")]
    key_type: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CryptoVerifyCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Verify Signature");
        let spinner = output::create_spinner("Verifying...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifySignature",
                serde_json::json!({
                    "public_key": self.key,
                    "message_hex": self.message,
                    "signature_hex": self.signature,
                    "key_type": self.key_type,
                }),
            )
            .await?;

        spinner.finish_and_clear();

        let valid = result
            .get("valid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if valid {
            output::print_success("Signature is valid!");
        } else {
            output::print_error("Signature is invalid.");
        }

        Ok(())
    }
}
