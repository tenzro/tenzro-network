//! Application management commands for the Tenzro CLI
//!
//! Register applications, create and manage user wallets, sponsor
//! transactions, and view usage statistics.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Application management operations
#[derive(Debug, Subcommand)]
pub enum AppCommand {
    /// Register an application
    Register(AppRegisterCmd),
    /// Create a custodial wallet for an app user
    CreateUser(AppCreateUserCmd),
    /// Fund a user wallet from the app treasury
    FundUser(AppFundUserCmd),
    /// List all user wallets for an app
    ListUsers(AppListUsersCmd),
    /// Sponsor a transaction for a user (app pays gas)
    Sponsor(AppSponsorCmd),
    /// Get usage statistics for an app
    Stats(AppStatsCmd),
}

impl AppCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Register(cmd) => cmd.execute().await,
            Self::CreateUser(cmd) => cmd.execute().await,
            Self::FundUser(cmd) => cmd.execute().await,
            Self::ListUsers(cmd) => cmd.execute().await,
            Self::Sponsor(cmd) => cmd.execute().await,
            Self::Stats(cmd) => cmd.execute().await,
        }
    }
}

/// Register an application
#[derive(Debug, Parser)]
pub struct AppRegisterCmd {
    /// Application name
    #[arg(long)]
    name: String,
    /// Description
    #[arg(long)]
    description: String,
    /// Callback URL (optional)
    #[arg(long)]
    callback_url: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AppRegisterCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Register Application");
        let spinner = output::create_spinner("Registering...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "name": self.name,
            "description": self.description,
        });
        if let Some(ref url) = self.callback_url {
            params["callback_url"] = serde_json::json!(url);
        }

        let result: serde_json::Value = rpc.call("tenzro_registerApp", params).await?;

        spinner.finish_and_clear();

        output::print_success("Application registered!");
        output::print_field("App ID", result.get("app_id").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Name", &self.name);

        Ok(())
    }
}

/// Create user wallet
#[derive(Debug, Parser)]
pub struct AppCreateUserCmd {
    /// Application ID
    #[arg(long)]
    app_id: String,
    /// User ID (application-defined)
    #[arg(long)]
    user_id: String,
    /// Key type: ed25519 or secp256k1
    #[arg(long, default_value = "ed25519")]
    key_type: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AppCreateUserCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Create User Wallet");
        let spinner = output::create_spinner("Creating wallet...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_createUserWallet", serde_json::json!({
            "app_id": self.app_id,
            "user_id": self.user_id,
            "key_type": self.key_type,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("User wallet created!");
        output::print_field("Address", result.get("address").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("User ID", &self.user_id);

        Ok(())
    }
}

/// Fund user wallet
#[derive(Debug, Parser)]
pub struct AppFundUserCmd {
    /// Application ID
    #[arg(long)]
    app_id: String,
    /// User ID
    #[arg(long)]
    user_id: String,
    /// Amount (TNZO)
    #[arg(long)]
    amount: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AppFundUserCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Fund User Wallet");
        let spinner = output::create_spinner("Funding...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_fundUserWallet", serde_json::json!({
            "app_id": self.app_id,
            "user_id": self.user_id,
            "amount": self.amount,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("User wallet funded!");
        output::print_field("User ID", &self.user_id);
        output::print_field("Amount", &format!("{} TNZO", self.amount));
        output::print_field("Tx Hash", result.get("tx_hash").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// List user wallets
#[derive(Debug, Parser)]
pub struct AppListUsersCmd {
    /// Application ID
    #[arg(long)]
    app_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AppListUsersCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("User Wallets");
        let spinner = output::create_spinner("Fetching wallets...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_listUserWallets", serde_json::json!({
            "app_id": self.app_id,
        })).await?;

        spinner.finish_and_clear();

        if let Some(wallets) = result.as_array() {
            if wallets.is_empty() {
                output::print_info("No user wallets found for this app.");
            } else {
                for w in wallets {
                    let uid = w.get("user_id").and_then(|v| v.as_str()).unwrap_or("?");
                    let addr = w.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                    output::print_field(uid, addr);
                }
            }
        } else {
            output::print_json(&result)?;
        }

        Ok(())
    }
}

/// Sponsor a transaction
#[derive(Debug, Parser)]
pub struct AppSponsorCmd {
    /// Application ID
    #[arg(long)]
    app_id: String,
    /// User wallet address (hex)
    #[arg(long)]
    user_address: String,
    /// Transaction data (hex-encoded calldata)
    #[arg(long)]
    tx_data: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AppSponsorCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Sponsor Transaction");
        let spinner = output::create_spinner("Sponsoring...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_sponsorTransaction", serde_json::json!({
            "app_id": self.app_id,
            "user_address": self.user_address,
            "tx_data": self.tx_data,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Transaction sponsored!");
        output::print_field("Tx Hash", result.get("tx_hash").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Gas Paid By", "app (paymaster)");

        Ok(())
    }
}

/// Get usage stats
#[derive(Debug, Parser)]
pub struct AppStatsCmd {
    /// Application ID
    #[arg(long)]
    app_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AppStatsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Application Usage Stats");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_getUsageStats", serde_json::json!({
            "app_id": self.app_id,
        })).await?;

        output::print_field("App ID", &self.app_id);
        output::print_field("Total Wallets", &result.get("total_wallets").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("Total Transactions", &result.get("total_transactions").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("Gas Spent", result.get("gas_spent").and_then(|v| v.as_str()).unwrap_or("0"));

        Ok(())
    }
}
