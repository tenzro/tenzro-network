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
    /// Liquid staking (stTNZO) — deposit TNZO, receive a rebasing derivative
    /// usable in DeFi while the underlying earns staking rewards.
    Liquid(LiquidStakingCmd),
}

impl StakeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Deposit(cmd) => cmd.execute().await,
            Self::Withdraw(cmd) => cmd.execute().await,
            Self::Info(cmd) => cmd.execute().await,
            Self::Liquid(cmd) => cmd.execute().await,
        }
    }
}

/// Liquid staking subcommands — surface the on-chain `LiquidStakingPool`
/// (stTNZO derivative) over the JSON-RPC `tenzro_liquidStaking*` namespace.
#[derive(Debug, Parser)]
pub struct LiquidStakingCmd {
    #[command(subcommand)]
    pub action: LiquidStakingAction,
}

#[derive(Debug, Subcommand)]
pub enum LiquidStakingAction {
    /// Deposit TNZO into the liquid staking pool, receive stTNZO at the
    /// current exchange rate. The underlying TNZO is debited from the
    /// caller's wallet.
    Deposit {
        /// TNZO amount to deposit (whole tokens, e.g. "100" or "100.5")
        amount: String,
        /// RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Request a withdrawal: burn stTNZO and start the unbonding period.
    /// Returns a request_id used by `claim` after unbonding completes.
    RequestWithdrawal {
        /// stTNZO amount to burn (whole tokens)
        amount: String,
        /// RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Claim a pending withdrawal once unbonding completes — credits TNZO
    /// back to the original requester's wallet.
    Claim {
        /// Request ID returned by `request-withdrawal`
        request_id: String,
        /// RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Show pool stats: total supply, exchange rate, fees collected.
    Stats {
        /// RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Show stTNZO balance for an address (defaults to caller).
    BalanceOf {
        /// Optional address (hex). Defaults to the node's primary identity.
        #[arg(long)]
        address: Option<String>,
        /// RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// List pending withdrawal requests for a holder.
    PendingWithdrawals {
        /// Optional holder address (hex). Defaults to the node's primary identity.
        #[arg(long)]
        holder: Option<String>,
        /// RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Distribute rewards into the pool (operator path — typically called
    /// by the rewards distributor at epoch boundaries).
    DistributeRewards {
        /// TNZO reward amount to distribute (whole tokens)
        amount: String,
        /// RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Transfer stTNZO between addresses.
    Transfer {
        /// Recipient address (hex)
        to: String,
        /// stTNZO amount (whole tokens)
        amount: String,
        /// Optional sender address (hex). Defaults to the node's primary identity.
        #[arg(long)]
        from: Option<String>,
        /// RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
}

impl LiquidStakingCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        match &self.action {
            LiquidStakingAction::Deposit { amount, rpc } => {
                output::print_header("Liquid Staking — Deposit");
                let amount_wei = crate::units::tnzo_to_wei_string(amount)?;
                let client = RpcClient::new(rpc);
                let result: serde_json::Value = client
                    .call(
                        "tenzro_liquidStakingDeposit",
                        serde_json::json!([{ "amount": amount_wei }]),
                    )
                    .await?;
                println!();
                if let Some(v) = result.get("sttnzo_minted").and_then(|v| v.as_str()) {
                    output::print_field("stTNZO Minted (units)", v);
                }
                if let Some(v) = result.get("exchange_rate").and_then(|v| v.as_str()) {
                    output::print_field("Exchange Rate", v);
                }
                Ok(())
            }
            LiquidStakingAction::RequestWithdrawal { amount, rpc } => {
                output::print_header("Liquid Staking — Request Withdrawal");
                // stTNZO uses the same 18-decimal scale as TNZO.
                let amount_base = crate::units::tnzo_to_wei_string(amount)?;
                let client = RpcClient::new(rpc);
                let result: serde_json::Value = client
                    .call(
                        "tenzro_liquidStakingRequestWithdrawal",
                        serde_json::json!([{ "sttnzo_amount": amount_base }]),
                    )
                    .await?;
                println!();
                if let Some(v) = result.get("request_id").and_then(|v| v.as_str()) {
                    output::print_field("Request ID", v);
                }
                if let Some(v) = result.get("tnzo_amount").and_then(|v| v.as_str()) {
                    output::print_field("TNZO Owed (units)", v);
                }
                if let Some(v) = result.get("unbonding_complete_at").and_then(|v| v.as_i64()) {
                    output::print_field("Unbonding Complete At", &v.to_string());
                }
                Ok(())
            }
            LiquidStakingAction::Claim { request_id, rpc } => {
                output::print_header("Liquid Staking — Claim Withdrawal");
                let client = RpcClient::new(rpc);
                let result: serde_json::Value = client
                    .call(
                        "tenzro_liquidStakingClaimWithdrawal",
                        serde_json::json!([{ "request_id": request_id }]),
                    )
                    .await?;
                println!();
                if let Some(v) = result.get("tnzo_amount").and_then(|v| v.as_str()) {
                    output::print_field("TNZO Returned (units)", v);
                }
                if let Some(v) = result.get("recipient").and_then(|v| v.as_str()) {
                    output::print_field("Recipient", v);
                }
                Ok(())
            }
            LiquidStakingAction::Stats { rpc } => {
                output::print_header("Liquid Staking — Pool Stats");
                let client = RpcClient::new(rpc);
                let result: serde_json::Value = client
                    .call("tenzro_liquidStakingStats", serde_json::json!([]))
                    .await?;
                println!();
                for (label, key) in &[
                    ("Total stTNZO Supply", "total_sttnzo_supply"),
                    ("Total Underlying (wei)", "total_underlying_wei"),
                    ("Pending Withdrawal (wei)", "pending_withdrawal_wei"),
                    ("Exchange Rate", "exchange_rate"),
                    ("Total Protocol Fees", "total_protocol_fees"),
                    ("Total Rewards Distributed", "total_rewards_distributed"),
                ] {
                    if let Some(v) = result.get(*key).and_then(|v| v.as_str()) {
                        output::print_field(label, v);
                    }
                }
                if let Some(v) = result.get("holder_count").and_then(|v| v.as_u64()) {
                    output::print_field("Holders", &v.to_string());
                }
                if let Some(v) = result.get("pending_withdrawals").and_then(|v| v.as_u64()) {
                    output::print_field("Pending Withdrawals", &v.to_string());
                }
                Ok(())
            }
            LiquidStakingAction::BalanceOf { address, rpc } => {
                output::print_header("Liquid Staking — Balance");
                let client = RpcClient::new(rpc);
                let mut params = serde_json::json!({});
                if let Some(a) = address {
                    params["address"] = serde_json::Value::String(a.clone());
                }
                let result: serde_json::Value = client
                    .call("tenzro_liquidStakingBalanceOf", serde_json::json!([params]))
                    .await?;
                println!();
                if let Some(v) = result.get("address").and_then(|v| v.as_str()) {
                    output::print_field("Address", v);
                }
                if let Some(v) = result.get("sttnzo_balance").and_then(|v| v.as_str()) {
                    output::print_field("stTNZO Balance (units)", v);
                }
                Ok(())
            }
            LiquidStakingAction::PendingWithdrawals { holder, rpc } => {
                output::print_header("Liquid Staking — Pending Withdrawals");
                let client = RpcClient::new(rpc);
                let mut params = serde_json::json!({});
                if let Some(h) = holder {
                    params["holder"] = serde_json::Value::String(h.clone());
                }
                let result: serde_json::Value = client
                    .call(
                        "tenzro_liquidStakingPendingWithdrawals",
                        serde_json::json!([params]),
                    )
                    .await?;
                let arr = result.as_array().cloned().unwrap_or_default();
                if arr.is_empty() {
                    output::print_info("No pending withdrawals");
                    return Ok(());
                }
                let headers = vec!["Request ID", "stTNZO", "TNZO", "Unbonding At", "Claimed"];
                let mut rows = Vec::new();
                for r in &arr {
                    rows.push(vec![
                        r.get("request_id").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
                        r.get("sttnzo_amount").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                        r.get("tnzo_amount").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                        r.get("unbonding_complete_at")
                            .and_then(|v| v.as_i64())
                            .map(|t| t.to_string())
                            .unwrap_or_else(|| "?".to_string()),
                        r.get("claimed").and_then(|v| v.as_bool()).unwrap_or(false).to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
                Ok(())
            }
            LiquidStakingAction::DistributeRewards { amount, rpc } => {
                output::print_header("Liquid Staking — Distribute Rewards");
                let amount_wei = crate::units::tnzo_to_wei_string(amount)?;
                let client = RpcClient::new(rpc);
                let result: serde_json::Value = client
                    .call(
                        "tenzro_liquidStakingDistributeRewards",
                        serde_json::json!([{ "reward_amount": amount_wei }]),
                    )
                    .await?;
                println!();
                for (label, key) in &[
                    ("Total Reward (units)", "total_reward"),
                    ("Staker Share (units)", "staker_share"),
                    ("Protocol Fee (units)", "protocol_fee"),
                    ("New Exchange Rate", "new_exchange_rate"),
                ] {
                    if let Some(v) = result.get(*key).and_then(|v| v.as_str()) {
                        output::print_field(label, v);
                    }
                }
                Ok(())
            }
            LiquidStakingAction::Transfer {
                to,
                amount,
                from,
                rpc,
            } => {
                output::print_header("Liquid Staking — Transfer stTNZO");
                // stTNZO uses the same 18-decimal scale as TNZO.
                let amount_base = crate::units::tnzo_to_wei_string(amount)?;
                let client = RpcClient::new(rpc);
                let mut params = serde_json::json!({ "to": to, "amount": amount_base });
                if let Some(f) = from {
                    params["from"] = serde_json::Value::String(f.clone());
                }
                let result: serde_json::Value = client
                    .call("tenzro_liquidStakingTransfer", serde_json::json!([params]))
                    .await?;
                println!();
                output::print_success("Transfer submitted");
                if let Some(v) = result.get("from").and_then(|v| v.as_str()) {
                    output::print_field("From", v);
                }
                if let Some(v) = result.get("to").and_then(|v| v.as_str()) {
                    output::print_field("To", v);
                }
                if let Some(v) = result.get("amount").and_then(|v| v.as_str()) {
                    output::print_field("Amount (units)", v);
                }
                Ok(())
            }
        }
    }
}

/// Stake TNZO tokens
#[derive(Debug, Parser)]
pub struct StakeDepositCmd {
    /// Amount to stake (whole TNZO; CLI converts to wei)
    amount: String,

    /// Provider type: validator | model_provider | tee_provider | storage_provider
    #[arg(long, default_value = "validator")]
    provider_type: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl StakeDepositCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Stake TNZO Tokens");

        println!();
        output::print_field("Amount", &format!("{} TNZO", self.amount));
        output::print_field("Provider Type", &self.provider_type);
        println!();

        use dialoguer::Confirm;
        let confirmed = Confirm::new()
            .with_prompt("Confirm staking transaction?")
            .default(false)
            .interact()?;

        if !confirmed {
            output::print_warning("Staking cancelled");
            return Ok(());
        }

        let spinner = output::create_spinner("Submitting stake...");

        let rpc = crate::rpc::RpcClient::new(&self.rpc);

        // The RPC takes amounts in **wei** (10^-18 TNZO). The CLI accepts
        // human-friendly TNZO input and converts here.
        let amount_wei = crate::units::tnzo_to_wei_string(&self.amount)?;
        let result: serde_json::Value = rpc.call("tenzro_stake", serde_json::json!([{
            "amount": amount_wei,
            "provider_type": self.provider_type,
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Stake submitted");
        println!();
        if let Some(v) = result.get("address").and_then(|v| v.as_str()) {
            output::print_field("Address", v);
        }
        if let Some(v) = result.get("amount").and_then(|v| v.as_str()) {
            output::print_field("Amount (wei)", v);
        }
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", v);
        }

        Ok(())
    }
}

/// Withdraw staked tokens (initiates 7-day unbonding)
#[derive(Debug, Parser)]
pub struct StakeWithdrawCmd {
    /// Amount to withdraw in whole TNZO (CLI converts to wei)
    amount: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl StakeWithdrawCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Withdraw Staked Tokens");

        println!();
        output::print_field("Amount", &format!("{} TNZO", self.amount));
        println!();

        let spinner = output::create_spinner("Submitting unstake...");

        let rpc = crate::rpc::RpcClient::new(&self.rpc);

        let amount_wei = crate::units::tnzo_to_wei_string(&self.amount)?;
        let result: serde_json::Value = rpc.call("tenzro_unstake", serde_json::json!([{
            "amount": amount_wei,
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Unstake submitted");
        println!();
        if let Some(v) = result.get("address").and_then(|v| v.as_str()) {
            output::print_field("Address", v);
        }
        if let Some(v) = result.get("amount").and_then(|v| v.as_str()) {
            output::print_field("Amount (wei)", v);
        }
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", v);
        }

        println!();
        output::print_info("Tokens unbond after the 7-day cooldown.");

        Ok(())
    }
}

/// Show staking information
#[derive(Debug, Parser)]
pub struct StakeInfoCmd {
    /// Address to query (defaults to current wallet)
    #[arg(long)]
    address: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl StakeInfoCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Staking Information");

        let address = match &self.address {
            Some(a) => a.clone(),
            None => crate::config::load_config()
                .wallet_address
                .ok_or_else(|| anyhow::anyhow!(
                    "No wallet address found. Run `tenzro wallet create` first or pass --address."
                ))?,
        };

        let spinner = output::create_spinner("Fetching voting power...");

        let rpc = RpcClient::new(&self.rpc);
        let info: serde_json::Value = rpc
            .call("tenzro_getVotingPower", serde_json::json!({"address": address}))
            .await?;

        spinner.finish_and_clear();

        if let Some(addr) = info.get("address").and_then(|v| v.as_str()) {
            output::print_field("Address", &output::format_address(addr));
        }
        if let Some(vp) = info.get("voting_power").and_then(|v| v.as_str()) {
            output::print_field("Voting Power (wei)", vp);
        }

        Ok(())
    }
}
