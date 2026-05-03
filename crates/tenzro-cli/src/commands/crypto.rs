//! Cryptographic operations for the Tenzro CLI
//!
//! Sign, verify, encrypt, decrypt, hash, and generate keypairs.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Cryptographic operations
#[derive(Debug, Subcommand)]
pub enum CryptoCommand {
    /// Sign a message with a private key
    Sign(CryptoSignCmd),
    /// Verify a message signature
    Verify(CryptoVerifyCmd),
    /// Encrypt data with AES-256-GCM
    Encrypt(CryptoEncryptCmd),
    /// Decrypt AES-256-GCM encrypted data
    Decrypt(CryptoDecryptCmd),
    /// Compute a SHA-256 or Keccak-256 hash
    Hash(CryptoHashCmd),
    /// Generate a new keypair
    Keygen(CryptoKeygenCmd),
    /// Derive a shared key via X25519 key exchange
    DeriveKey(CryptoDeriveKeyCmd),
}

impl CryptoCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Sign(cmd) => cmd.execute().await,
            Self::Verify(cmd) => cmd.execute().await,
            Self::Encrypt(cmd) => cmd.execute().await,
            Self::Decrypt(cmd) => cmd.execute().await,
            Self::Hash(cmd) => cmd.execute().await,
            Self::Keygen(cmd) => cmd.execute().await,
            Self::DeriveKey(cmd) => cmd.execute().await,
        }
    }
}

/// Sign a message
#[derive(Debug, Parser)]
pub struct CryptoSignCmd {
    /// Private key (hex)
    #[arg(long)]
    key: String,
    /// Message to sign (hex)
    #[arg(long)]
    message: String,
    /// Key type: ed25519 or secp256k1
    #[arg(long, default_value = "ed25519")]
    key_type: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CryptoSignCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Sign Message");
        let spinner = output::create_spinner("Signing...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_signMessage", serde_json::json!({
            "private_key": self.key,
            "message_hex": self.message,
            "key_type": self.key_type,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Message signed!");
        output::print_field("Signature", result.get("signature").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Public Key", result.get("public_key").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
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

        let result: serde_json::Value = rpc.call("tenzro_verifySignature", serde_json::json!({
            "public_key": self.key,
            "message_hex": self.message,
            "signature_hex": self.signature,
            "key_type": self.key_type,
        })).await?;

        spinner.finish_and_clear();

        let valid = result.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
        if valid {
            output::print_success("Signature is valid!");
        } else {
            output::print_error("Signature is invalid.");
        }

        Ok(())
    }
}

/// Encrypt data
#[derive(Debug, Parser)]
pub struct CryptoEncryptCmd {
    /// Plaintext data (hex)
    #[arg(long)]
    data: String,
    /// Encryption key (hex, 32 bytes)
    #[arg(long)]
    key: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CryptoEncryptCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Encrypt Data");
        let spinner = output::create_spinner("Encrypting...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_encryptData", serde_json::json!({
            "plaintext_hex": self.data,
            "key_hex": self.key,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Data encrypted (AES-256-GCM)!");
        output::print_field("Ciphertext", result.get("ciphertext_hex").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Decrypt data
#[derive(Debug, Parser)]
pub struct CryptoDecryptCmd {
    /// Ciphertext (hex, includes nonce + tag)
    #[arg(long)]
    data: String,
    /// Decryption key (hex, 32 bytes)
    #[arg(long)]
    key: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CryptoDecryptCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Decrypt Data");
        let spinner = output::create_spinner("Decrypting...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_decryptData", serde_json::json!({
            "ciphertext_hex": self.data,
            "key_hex": self.key,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Data decrypted!");
        output::print_field("Plaintext", result.get("plaintext_hex").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Hash data
#[derive(Debug, Parser)]
pub struct CryptoHashCmd {
    /// Data to hash (hex)
    #[arg(long)]
    data: String,
    /// Hash algorithm: sha256 or keccak256
    #[arg(long, default_value = "sha256")]
    algorithm: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CryptoHashCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Hash Data");
        let rpc = RpcClient::new(&self.rpc);

        let method = if self.algorithm == "keccak256" {
            "tenzro_hashKeccak256"
        } else {
            "tenzro_hashSha256"
        };

        let result: serde_json::Value = rpc.call(method, serde_json::json!({
            "data_hex": self.data,
        })).await?;

        output::print_field("Algorithm", &self.algorithm);
        output::print_field("Hash", result.get("hash").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Generate a keypair
#[derive(Debug, Parser)]
pub struct CryptoKeygenCmd {
    /// Key type: ed25519 or secp256k1
    #[arg(long, default_value = "ed25519")]
    key_type: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CryptoKeygenCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Generate Keypair");
        let spinner = output::create_spinner("Generating...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_generateKeypair", serde_json::json!({
            "key_type": self.key_type,
        })).await?;

        spinner.finish_and_clear();

        output::print_success(&format!("{} keypair generated!", self.key_type));
        output::print_field("Public Key", result.get("public_key").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Private Key", result.get("private_key").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Address", result.get("address").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Derive a shared key via X25519 key exchange
#[derive(Debug, Parser)]
pub struct CryptoDeriveKeyCmd {
    /// Your private key (hex)
    #[arg(long)]
    private_key: String,
    /// Peer's public key (hex)
    #[arg(long)]
    peer_public_key: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CryptoDeriveKeyCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Derive Shared Key");
        let spinner = output::create_spinner("Deriving key...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_deriveKey", serde_json::json!({
            "private_key": self.private_key,
            "peer_public_key": self.peer_public_key,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Shared key derived!");
        output::print_field("Shared Key", result.get("shared_key").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}
