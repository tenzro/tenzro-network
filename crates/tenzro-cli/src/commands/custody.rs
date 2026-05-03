//! Custody and MPC wallet management commands for the Tenzro CLI
//!
//! Create MPC wallets, export/import keystores, rotate keys, manage spending
//! limits, and create/revoke session keys.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Custody & MPC wallet operations
#[derive(Debug, Subcommand)]
pub enum CustodyCommand {
    /// Create a new MPC threshold wallet
    CreateWallet(CustodyCreateWalletCmd),
    /// Export an encrypted keystore file
    Export(CustodyExportCmd),
    /// Import a wallet from an encrypted keystore
    Import(CustodyImportCmd),
    /// Rotate MPC key shares without changing the address
    Rotate(CustodyRotateCmd),
    /// Set spending limits for a wallet
    SetLimits(CustodySetLimitsCmd),
    /// Get current spending limits and usage
    GetLimits(CustodyGetLimitsCmd),
    /// Create a time-limited session key
    Session(CustodySessionCmd),
    /// Revoke an active session key
    RevokeSession(CustodyRevokeSessionCmd),
    /// Get key share information for a wallet
    KeyShares(CustodyKeySharesCmd),
}

impl CustodyCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::CreateWallet(cmd) => cmd.execute().await,
            Self::Export(cmd) => cmd.execute().await,
            Self::Import(cmd) => cmd.execute().await,
            Self::Rotate(cmd) => cmd.execute().await,
            Self::SetLimits(cmd) => cmd.execute().await,
            Self::GetLimits(cmd) => cmd.execute().await,
            Self::Session(cmd) => cmd.execute().await,
            Self::RevokeSession(cmd) => cmd.execute().await,
            Self::KeyShares(cmd) => cmd.execute().await,
        }
    }
}

/// Create MPC wallet
#[derive(Debug, Parser)]
pub struct CustodyCreateWalletCmd {
    /// Threshold (minimum shares to sign)
    #[arg(long, default_value = "2")]
    threshold: u32,
    /// Total number of key shares
    #[arg(long, default_value = "3")]
    shares: u32,
    /// Key type: ed25519 or secp256k1
    #[arg(long, default_value = "ed25519")]
    key_type: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CustodyCreateWalletCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Create MPC Wallet");
        let spinner = output::create_spinner("Creating wallet...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_createMpcWallet", serde_json::json!({
            "threshold": self.threshold,
            "total_shares": self.shares,
            "key_type": self.key_type,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("MPC wallet created!");
        output::print_field("Address", result.get("address").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Threshold", &format!("{}-of-{}", self.threshold, self.shares));
        output::print_field("Key Type", &self.key_type);

        Ok(())
    }
}

/// Export keystore
#[derive(Debug, Parser)]
pub struct CustodyExportCmd {
    /// Wallet address (hex)
    #[arg(long)]
    address: String,
    /// Password to encrypt the keystore
    #[arg(long)]
    password: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CustodyExportCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Export Keystore");
        let spinner = output::create_spinner("Encrypting keystore...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_exportKeystore", serde_json::json!({
            "address": self.address,
            "password": self.password,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Keystore exported!");
        output::print_field("Address", &self.address);
        if let Some(keystore) = result.get("keystore_json").and_then(|v| v.as_str()) {
            println!("{}", keystore);
        } else {
            output::print_json(&result)?;
        }

        Ok(())
    }
}

/// Import keystore
#[derive(Debug, Parser)]
pub struct CustodyImportCmd {
    /// Path to keystore JSON file
    #[arg(long)]
    file: String,
    /// Password to decrypt the keystore
    #[arg(long)]
    password: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CustodyImportCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Import Keystore");
        let keystore_json = std::fs::read_to_string(&self.file)?;
        let spinner = output::create_spinner("Decrypting keystore...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_importKeystore", serde_json::json!({
            "keystore_json": keystore_json,
            "password": self.password,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Keystore imported!");
        output::print_field("Address", result.get("address").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Rotate keys
#[derive(Debug, Parser)]
pub struct CustodyRotateCmd {
    /// Wallet address (hex)
    #[arg(long)]
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CustodyRotateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Rotate Key Shares");
        let spinner = output::create_spinner("Rotating...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_rotateKeys", serde_json::json!({
            "address": self.address,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Key shares rotated! Address unchanged.");
        output::print_field("Address", &self.address);
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or("ok"));

        Ok(())
    }
}

/// Set spending limits
#[derive(Debug, Parser)]
pub struct CustodySetLimitsCmd {
    /// Wallet address (hex)
    #[arg(long)]
    address: String,
    /// Daily spending limit (TNZO)
    #[arg(long)]
    daily: String,
    /// Per-transaction limit (TNZO)
    #[arg(long)]
    per_tx: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CustodySetLimitsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Set Spending Limits");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_setSpendingLimits", serde_json::json!({
            "address": self.address,
            "daily_limit": self.daily,
            "per_tx_limit": self.per_tx,
        })).await?;

        output::print_success("Spending limits updated!");
        output::print_field("Address", &self.address);
        output::print_field("Daily Limit", &format!("{} TNZO", self.daily));
        output::print_field("Per-Tx Limit", &format!("{} TNZO", self.per_tx));
        let _ = result;

        Ok(())
    }
}

/// Get spending limits
#[derive(Debug, Parser)]
pub struct CustodyGetLimitsCmd {
    /// Wallet address (hex)
    #[arg(long)]
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CustodyGetLimitsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Spending Limits");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_getSpendingLimits", serde_json::json!({
            "address": self.address,
        })).await?;

        output::print_field("Address", &self.address);
        output::print_field("Daily Limit", result.get("daily_limit").and_then(|v| v.as_str()).unwrap_or("unlimited"));
        output::print_field("Per-Tx Limit", result.get("per_tx_limit").and_then(|v| v.as_str()).unwrap_or("unlimited"));
        output::print_field("Daily Used", result.get("daily_used").and_then(|v| v.as_str()).unwrap_or("0"));

        Ok(())
    }
}

/// Create session key
#[derive(Debug, Parser)]
pub struct CustodySessionCmd {
    /// Wallet address (hex)
    #[arg(long)]
    address: String,
    /// Session duration in seconds
    #[arg(long)]
    duration: u64,
    /// Maximum spend amount (TNZO)
    #[arg(long)]
    max_amount: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CustodySessionCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Create Session Key");
        let spinner = output::create_spinner("Creating session...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_authorizeSession", serde_json::json!({
            "address": self.address,
            "duration_secs": self.duration,
            "max_amount": self.max_amount,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Session key created!");
        output::print_field("Session ID", result.get("session_id").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Duration", &format!("{}s", self.duration));
        output::print_field("Max Amount", &format!("{} TNZO", self.max_amount));

        Ok(())
    }
}

/// Revoke session key
#[derive(Debug, Parser)]
pub struct CustodyRevokeSessionCmd {
    /// Wallet address (hex)
    #[arg(long)]
    address: String,
    /// Session ID to revoke
    #[arg(long)]
    session_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CustodyRevokeSessionCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Revoke Session Key");
        let rpc = RpcClient::new(&self.rpc);

        let _result: serde_json::Value = rpc.call("tenzro_revokeSession", serde_json::json!({
            "address": self.address,
            "session_id": self.session_id,
        })).await?;

        output::print_success("Session revoked!");
        output::print_field("Session ID", &self.session_id);

        Ok(())
    }
}

/// Get key share information for a wallet
#[derive(Debug, Parser)]
pub struct CustodyKeySharesCmd {
    /// Wallet address (hex)
    #[arg(long)]
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CustodyKeySharesCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Key Shares");
        let spinner = output::create_spinner("Fetching key shares...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_getKeyShares", serde_json::json!({
            "address": self.address,
        })).await?;

        spinner.finish_and_clear();

        output::print_field("Address", &self.address);
        output::print_field("Threshold", result.get("threshold").and_then(|v| v.as_u64()).map(|v| v.to_string()).unwrap_or_else(|| "?".to_string()).as_str());
        output::print_field("Total Shares", result.get("total_shares").and_then(|v| v.as_u64()).map(|v| v.to_string()).unwrap_or_else(|| "?".to_string()).as_str());
        output::print_field("Key Type", result.get("key_type").and_then(|v| v.as_str()).unwrap_or("unknown"));

        if let Some(shares) = result.get("shares").and_then(|v| v.as_array()) {
            println!();
            for (i, share) in shares.iter().enumerate() {
                let status = share.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
                let location = share.get("location").and_then(|v| v.as_str()).unwrap_or("unknown");
                output::print_field(&format!("Share {}", i + 1), &format!("{} ({})", location, status));
            }
        }

        Ok(())
    }
}
