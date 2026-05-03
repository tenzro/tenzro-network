//! ERC-7802 cross-chain token operations for the Tenzro CLI
//!
//! Manage cross-chain mint/burn operations and bridge authorizations.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Cross-chain token commands (ERC-7802)
#[derive(Debug, Subcommand)]
pub enum CrosschainCommand {
    /// Mint tokens on this chain from a cross-chain transfer
    Mint(CrosschainMintCmd),
    /// Burn tokens on this chain for a cross-chain transfer
    Burn(CrosschainBurnCmd),
    /// Authorize a bridge for cross-chain mint/burn
    Authorize(AuthorizeBridgeCmd),
    /// Revoke a bridge's cross-chain mint/burn authorization
    Revoke(RevokeBridgeCmd),
    /// List authorized bridges
    Bridges(ListBridgesCmd),
    /// Update bridge limits (per-tx, daily)
    UpdateLimits(UpdateLimitsCmd),
}

impl CrosschainCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Mint(cmd) => cmd.execute().await,
            Self::Burn(cmd) => cmd.execute().await,
            Self::Authorize(cmd) => cmd.execute().await,
            Self::Revoke(cmd) => cmd.execute().await,
            Self::Bridges(cmd) => cmd.execute().await,
            Self::UpdateLimits(cmd) => cmd.execute().await,
        }
    }
}

/// Mint tokens via cross-chain bridge (ERC-7802 crosschainMint)
#[derive(Debug, Parser)]
pub struct CrosschainMintCmd {
    /// Bridge address (hex) performing the mint
    #[arg(long)]
    bridge: String,
    /// Recipient address (hex)
    #[arg(long)]
    to: String,
    /// Amount to mint (in smallest units)
    #[arg(long)]
    amount: String,
    /// Sender identifier on the source chain (hex or string)
    #[arg(long)]
    sender: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CrosschainMintCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Cross-Chain Mint (ERC-7802)");
        let spinner = output::create_spinner("Minting tokens...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_crosschainMint", serde_json::json!({
            "bridge": self.bridge,
            "to": self.to,
            "amount": self.amount,
            "sender": self.sender,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Cross-chain mint successful!");
        output::print_field("Nonce", &result.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("To", result.get("to").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Amount", result.get("amount").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Bridge", result.get("bridge").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Burn tokens for cross-chain transfer (ERC-7802 crosschainBurn)
#[derive(Debug, Parser)]
pub struct CrosschainBurnCmd {
    /// Bridge address (hex) performing the burn
    #[arg(long)]
    bridge: String,
    /// Address to burn from (hex)
    #[arg(long)]
    from: String,
    /// Amount to burn (in smallest units)
    #[arg(long)]
    amount: String,
    /// Destination identifier on the target chain (hex or string)
    #[arg(long)]
    destination: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CrosschainBurnCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Cross-Chain Burn (ERC-7802)");
        let spinner = output::create_spinner("Burning tokens...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_crosschainBurn", serde_json::json!({
            "bridge": self.bridge,
            "from": self.from,
            "amount": self.amount,
            "destination": self.destination,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Cross-chain burn successful!");
        output::print_field("Nonce", &result.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("From", result.get("from").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Amount", result.get("amount").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Bridge", result.get("bridge").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Authorize a bridge for cross-chain mint/burn operations
#[derive(Debug, Parser)]
pub struct AuthorizeBridgeCmd {
    /// Bridge address (hex, 20 bytes)
    #[arg(long)]
    bridge: String,
    /// Human-readable bridge name
    #[arg(long)]
    name: String,
    /// Maximum mint per transaction (optional, in smallest units)
    #[arg(long)]
    max_mint_per_tx: Option<String>,
    /// Maximum burn per transaction (optional)
    #[arg(long)]
    max_burn_per_tx: Option<String>,
    /// Daily mint limit (optional)
    #[arg(long)]
    daily_mint_limit: Option<String>,
    /// Daily burn limit (optional)
    #[arg(long)]
    daily_burn_limit: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AuthorizeBridgeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Authorize Bridge (ERC-7802)");
        let spinner = output::create_spinner("Authorizing bridge...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_authorizeBridge", serde_json::json!({
            "bridge": self.bridge,
            "name": self.name,
            "max_mint_per_tx": self.max_mint_per_tx,
            "max_burn_per_tx": self.max_burn_per_tx,
            "daily_mint_limit": self.daily_mint_limit,
            "daily_burn_limit": self.daily_burn_limit,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Bridge authorized!");
        output::print_field("Bridge", result.get("bridge").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Name", result.get("name").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or("authorized"));

        Ok(())
    }
}

/// Revoke a bridge's cross-chain authorization
#[derive(Debug, Parser)]
pub struct RevokeBridgeCmd {
    /// Bridge address (hex)
    #[arg(long)]
    bridge: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RevokeBridgeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Revoke Bridge Authorization");
        let spinner = output::create_spinner("Revoking...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_revokeBridge", serde_json::json!({
            "bridge": self.bridge,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Bridge authorization revoked!");
        output::print_field("Bridge", result.get("bridge").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Status", "revoked");

        Ok(())
    }
}

/// List authorized bridges
#[derive(Debug, Parser)]
pub struct ListBridgesCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ListBridgesCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Authorized Bridges (ERC-7802)");
        let spinner = output::create_spinner("Loading bridges...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_listAuthorizedBridges", serde_json::json!({})).await?;

        spinner.finish_and_clear();

        if let Some(bridges) = result.get("bridges").and_then(|v| v.as_array()) {
            if bridges.is_empty() {
                output::print_info("No bridges authorized.");
            } else {
                let headers = vec!["Address", "Name", "Enabled", "Daily Mint Limit", "Daily Burn Limit"];
                let mut rows = Vec::new();
                for b in bridges {
                    rows.push(vec![
                        b.get("address").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        b.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        b.get("enabled").and_then(|v| v.as_bool()).map(|v| if v { "yes" } else { "no" }).unwrap_or("?").to_string(),
                        b.get("daily_mint_limit").and_then(|v| v.as_str()).unwrap_or("unlimited").to_string(),
                        b.get("daily_burn_limit").and_then(|v| v.as_str()).unwrap_or("unlimited").to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        }

        Ok(())
    }
}

/// Update bridge rate limits
#[derive(Debug, Parser)]
pub struct UpdateLimitsCmd {
    /// Bridge address (hex)
    #[arg(long)]
    bridge: String,
    /// New max mint per transaction (optional)
    #[arg(long)]
    max_mint_per_tx: Option<String>,
    /// New max burn per transaction (optional)
    #[arg(long)]
    max_burn_per_tx: Option<String>,
    /// New daily mint limit (optional)
    #[arg(long)]
    daily_mint_limit: Option<String>,
    /// New daily burn limit (optional)
    #[arg(long)]
    daily_burn_limit: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl UpdateLimitsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Update Bridge Limits");
        let spinner = output::create_spinner("Updating limits...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_updateBridgeLimits", serde_json::json!({
            "bridge": self.bridge,
            "max_mint_per_tx": self.max_mint_per_tx,
            "max_burn_per_tx": self.max_burn_per_tx,
            "daily_mint_limit": self.daily_mint_limit,
            "daily_burn_limit": self.daily_burn_limit,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Bridge limits updated!");
        output::print_field("Bridge", result.get("bridge").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or("updated"));

        Ok(())
    }
}
