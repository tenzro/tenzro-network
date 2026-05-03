//! Staking commands for the Tenzro CLI

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output::{self};

/// Staking commands
#[derive(Debug, Subcommand)]
pub enum StakeCommand {
    /// Stake TNZO tokens
    Deposit(StakeDepositCmd),
    /// Withdraw staked tokens
    Withdraw(StakeWithdrawCmd),
    /// Show staking information
    Info(StakeInfoCmd),
}

impl StakeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Deposit(cmd) => cmd.execute().await,
            Self::Withdraw(cmd) => cmd.execute().await,
            Self::Info(cmd) => cmd.execute().await,
        }
    }
}

/// Stake TNZO tokens
#[derive(Debug, Parser)]
pub struct StakeDepositCmd {
    /// Amount to stake
    amount: String,

    /// Provider type (validator, inference, tee)
    #[arg(long)]
    provider_type: Option<String>,

    /// Lock period in days (optional, for higher rewards)
    #[arg(long)]
    lock_days: Option<u32>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl StakeDepositCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Stake TNZO Tokens");

        // Parse amount
        let amount_float: f64 = self.amount.parse()?;
        let decimals = 18;
        let _amount_raw = (amount_float * 10f64.powi(decimals)) as u64;

        // Check minimum
        let minimum = 1000.0;
        if amount_float < minimum {
            return Err(anyhow::anyhow!("Minimum stake amount is {} TNZO", minimum));
        }

        // Calculate APY based on lock period
        let apy = if let Some(days) = self.lock_days {
            match days {
                0..=30 => 5.0,
                31..=90 => 7.5,
                91..=180 => 10.0,
                181..=365 => 12.5,
                _ => 15.0,
            }
        } else {
            5.0 // No lock period
        };

        // Show staking details
        println!();
        output::print_field("Amount", &format!("{} TNZO", self.amount));

        if let Some(provider_type) = &self.provider_type {
            output::print_field("Provider Type", provider_type);
        }

        if let Some(days) = self.lock_days {
            output::print_field("Lock Period", &format!("{} days", days));
        } else {
            output::print_field("Lock Period", "None (flexible)");
        }

        output::print_field("APY", &format!("{}%", apy));

        let estimated_yearly = amount_float * (apy / 100.0);
        output::print_field("Est. Yearly Rewards", &format!("{:.2} TNZO", estimated_yearly));
        println!();

        // Confirm with user
        use dialoguer::Confirm;
        let confirmed = Confirm::new()
            .with_prompt("Confirm staking transaction?")
            .default(false)
            .interact()?;

        if !confirmed {
            output::print_warning("Staking cancelled");
            return Ok(());
        }

        let spinner = output::create_spinner("Creating staking transaction...");

        let rpc = crate::rpc::RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_stake", serde_json::json!([{
            "amount": self.amount,
            "provider_type": self.provider_type.as_deref().unwrap_or("validator"),
            "lock_days": self.lock_days,
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Tokens staked successfully!");
        println!();
        if let Some(v) = result.get("stake_id").and_then(|v| v.as_str()) {
            output::print_field("Stake ID", v);
        }
        if let Some(v) = result.get("transaction_hash").and_then(|v| v.as_str()) {
            output::print_field("Transaction Hash", v);
        }
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", v);
        }

        Ok(())
    }
}

/// Withdraw staked tokens
#[derive(Debug, Parser)]
pub struct StakeWithdrawCmd {
    /// Amount to withdraw (or "all")
    amount: String,

    /// Force withdrawal even if in lock period (may incur penalty)
    #[arg(long)]
    force: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl StakeWithdrawCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Withdraw Staked Tokens");

        let is_all = self.amount.to_lowercase() == "all";

        println!();
        if is_all {
            output::print_field("Withdrawing", "All staked tokens");
        } else {
            output::print_field("Amount", &format!("{} TNZO", self.amount));
        }

        // Query actual lock status from the node
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let cfg = crate::config::load_config();
        let from_address = cfg.wallet_address
            .ok_or_else(|| anyhow::anyhow!(
                "No wallet address found. Run `tenzro-cli wallet create` or `tenzro-cli wallet import` first."
            ))?;
        let stake_info_result = rpc.call::<serde_json::Value>("tenzro_getVotingPower", serde_json::json!([from_address])).await;

        let (is_locked, lock_remaining_days) = match stake_info_result {
            Ok(info) => {
                let locked = info.get("is_locked").and_then(|v| v.as_bool()).unwrap_or(false);
                let days = info.get("lock_remaining_days").and_then(|v| v.as_u64()).unwrap_or(0);
                (locked, days)
            }
            Err(_) => (false, 0),  // Default to unlocked if RPC fails
        };

        if is_locked && !self.force {
            output::print_warning(&format!(
                "Your stake is locked for {} more days",
                lock_remaining_days
            ));
            output::print_info("Use --force to withdraw early (25% penalty applies)");
            return Ok(());
        }

        if self.force && is_locked {
            output::print_warning("Early withdrawal will incur a 25% penalty");
            println!();

            use dialoguer::Confirm;
            let confirmed = Confirm::new()
                .with_prompt("Do you want to proceed with early withdrawal?")
                .default(false)
                .interact()?;

            if !confirmed {
                output::print_warning("Withdrawal cancelled");
                return Ok(());
            }
        }

        let spinner = output::create_spinner("Creating withdrawal transaction...");

        let rpc = crate::rpc::RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_unstake", serde_json::json!([{
            "amount": self.amount,
            "force": self.force,
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Withdrawal initiated successfully!");
        println!();
        output::print_field("Amount", if is_all { "All" } else { &self.amount });

        if let Some(v) = result.get("unbonding_period").and_then(|v| v.as_str()) {
            output::print_field("Unbonding Period", v);
        }
        if let Some(v) = result.get("available_after").and_then(|v| v.as_str()) {
            output::print_field("Available After", v);
        }
        if let Some(v) = result.get("transaction_hash").and_then(|v| v.as_str()) {
            output::print_field("Transaction Hash", v);
        }

        if self.force {
            if let Some(v) = result.get("penalty").and_then(|v| v.as_str()) {
                output::print_field("Penalty Applied", v);
            }
        }

        println!();
        output::print_info("Tokens will be available after the unbonding period.");

        Ok(())
    }
}

/// Show staking information
#[derive(Debug, Parser)]
pub struct StakeInfoCmd {
    /// Address to query (optional, uses default wallet if not specified)
    #[arg(long)]
    address: Option<String>,

    /// Show detailed breakdown
    #[arg(long)]
    detailed: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl StakeInfoCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Staking Information");

        let spinner = output::create_spinner("Fetching staking data...");

        let rpc = RpcClient::new(&self.rpc);

        // Get voting power as a proxy for staking info
        let address = self.address.as_deref().unwrap_or("default");
        let staking_info: serde_json::Value = rpc.call("tenzro_getVotingPower", serde_json::json!([address])).await
            .unwrap_or(serde_json::json!({"total_staked": "0", "rewards": "0", "apy": "7.5"}));

        spinner.finish_and_clear();

        if let Some(addr) = &self.address {
            output::print_field("Address", &output::format_address(addr));
        }

        println!();

        if let Some(total_staked) = staking_info.get("total_staked").and_then(|v| v.as_str()) {
            output::print_field("Total Staked", &format!("{} TNZO", total_staked));
        }
        if let Some(rewards) = staking_info.get("rewards").and_then(|v| v.as_str()) {
            output::print_field("Total Rewards", &format!("{} TNZO", rewards));
        }
        if let Some(apy) = staking_info.get("apy").and_then(|v| v.as_str()) {
            output::print_field("Current APY", &format!("{}%", apy));
        }
        if let Some(unbonding) = staking_info.get("unbonding").and_then(|v| v.as_str()) {
            output::print_field("Unbonding", &format!("{} TNZO", unbonding));
        }

        if self.detailed {
            // Fetch detailed stake breakdown
            if let Some(stakes) = staking_info.get("active_stakes").and_then(|v| v.as_array()) {
                println!();
                output::print_header("Active Stakes");

                let headers = vec!["Stake ID", "Amount", "Type", "APY", "Lock", "Rewards"];
                let mut rows = Vec::new();
                for stake in stakes {
                    rows.push(vec![
                        stake.get("stake_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        stake.get("amount").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                        stake.get("provider_type").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        stake.get("apy").and_then(|v| v.as_str()).unwrap_or("N/A").to_string(),
                        stake.get("lock_remaining").and_then(|v| v.as_str()).unwrap_or("None").to_string(),
                        stake.get("rewards").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                    ]);
                }
                if rows.is_empty() {
                    output::print_info("No active stakes");
                } else {
                    output::print_table(&headers, &rows);
                }
            }

            if let Some(unbonding) = staking_info.get("unbonding_stakes").and_then(|v| v.as_array()) {
                if !unbonding.is_empty() {
                    println!();
                    output::print_header("Unbonding Stakes");

                    let headers = vec!["Amount", "Available After"];
                    let mut rows = Vec::new();
                    for u in unbonding {
                        rows.push(vec![
                            u.get("amount").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                            u.get("available_after").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        ]);
                    }
                    output::print_table(&headers, &rows);
                }
            }
        }

        Ok(())
    }
}
