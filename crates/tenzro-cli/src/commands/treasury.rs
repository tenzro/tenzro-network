//! Treasury multisig withdrawal commands.
//!
//! Config mutations (`add-withdrawer`, `remove-withdrawer`,
//! `set-threshold`) are operator-only and require the
//! `X-Tenzro-Admin-Token` header. Approval and execution are not
//! admin-gated: the approver's Ed25519/Secp256k1 signature over the
//! domain-separated preimage
//! `"tenzro/treasury/withdrawal-approval" || withdrawal_id || asset_id || amount_le`
//! plus the configured threshold is the authorization.

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::json;

use crate::output;
use crate::rpc::RpcClient;

/// Treasury multisig withdrawals (add/remove withdrawers, threshold,
/// approve, execute, inspect pending).
#[derive(Debug, Subcommand)]
pub enum TreasuryCommand {
    /// Authorize a withdrawer address (admin token required).
    AddWithdrawer(AddWithdrawerCmd),
    /// Remove an authorized withdrawer address (admin token required).
    RemoveWithdrawer(RemoveWithdrawerCmd),
    /// Set the approval threshold (admin token required).
    SetThreshold(SetThresholdCmd),
    /// Approve a withdrawal with a signed approval.
    Approve(ApproveCmd),
    /// Execute a withdrawal once the threshold is reached.
    Execute(ExecuteCmd),
    /// Show a pending withdrawal's approval state.
    Pending(PendingCmd),
}

impl TreasuryCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::AddWithdrawer(cmd) => cmd.execute().await,
            Self::RemoveWithdrawer(cmd) => cmd.execute().await,
            Self::SetThreshold(cmd) => cmd.execute().await,
            Self::Approve(cmd) => cmd.execute().await,
            Self::Execute(cmd) => cmd.execute().await,
            Self::Pending(cmd) => cmd.execute().await,
        }
    }
}

fn client(rpc: &str, admin_token: &Option<String>) -> RpcClient {
    let mut c = RpcClient::new(rpc);
    if let Some(token) = admin_token {
        c = c.with_admin_token(token);
    }
    c
}

fn print_withdrawers(result: &serde_json::Value) {
    if let Some(list) = result.get("withdrawers").and_then(|v| v.as_array()) {
        output::print_field("Withdrawers", &list.len().to_string());
        for w in list {
            if let Some(s) = w.as_str() {
                output::print_info(&format!("  {}", s));
            }
        }
    }
    if let Some(t) = result.get("threshold").and_then(|v| v.as_u64()) {
        output::print_field("Threshold", &t.to_string());
    }
}

/// Authorize a withdrawer address.
#[derive(Debug, Parser)]
pub struct AddWithdrawerCmd {
    /// Withdrawer address (0x-prefixed hex).
    #[arg(long)]
    address: String,

    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator admin token (`X-Tenzro-Admin-Token`).
    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

impl AddWithdrawerCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Treasury: Add Withdrawer");
        let rpc = client(&self.rpc, &self.admin_token);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_treasuryAddWithdrawer",
                json!({ "address": self.address }),
            )
            .await?;
        output::print_field("Added", &self.address);
        print_withdrawers(&result);
        Ok(())
    }
}

/// Remove an authorized withdrawer address.
#[derive(Debug, Parser)]
pub struct RemoveWithdrawerCmd {
    /// Withdrawer address (0x-prefixed hex).
    #[arg(long)]
    address: String,

    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator admin token (`X-Tenzro-Admin-Token`).
    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

impl RemoveWithdrawerCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Treasury: Remove Withdrawer");
        let rpc = client(&self.rpc, &self.admin_token);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_treasuryRemoveWithdrawer",
                json!({ "address": self.address }),
            )
            .await?;
        output::print_field("Removed", &self.address);
        print_withdrawers(&result);
        Ok(())
    }
}

/// Set the withdrawal approval threshold.
#[derive(Debug, Parser)]
pub struct SetThresholdCmd {
    /// Number of distinct approvals required per withdrawal.
    #[arg(long)]
    threshold: u64,

    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator admin token (`X-Tenzro-Admin-Token`).
    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

impl SetThresholdCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Treasury: Set Withdrawal Threshold");
        let rpc = client(&self.rpc, &self.admin_token);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_treasurySetWithdrawalThreshold",
                json!({ "threshold": self.threshold }),
            )
            .await?;
        print_withdrawers(&result);
        Ok(())
    }
}

/// Approve a withdrawal with a signed approval.
#[derive(Debug, Parser)]
pub struct ApproveCmd {
    /// Withdrawal identifier (shared by all approvers).
    #[arg(long)]
    withdrawal_id: String,

    /// Asset identifier (e.g. `TNZO`).
    #[arg(long)]
    asset_id: String,

    /// Amount in base units (decimal string).
    #[arg(long)]
    amount: String,

    /// Approver address (0x-prefixed hex) — must be an authorized withdrawer.
    #[arg(long)]
    approver: String,

    /// Signature key type: `ed25519` (default) or `secp256k1`.
    #[arg(long, default_value = "ed25519")]
    key_type: String,

    /// Approver public key (hex).
    #[arg(long)]
    public_key: String,

    /// Signature (hex) over the withdrawal-approval preimage.
    #[arg(long)]
    signature: String,

    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ApproveCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Treasury: Approve Withdrawal");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_treasuryApproveWithdrawal",
                json!({
                    "withdrawal_id": self.withdrawal_id,
                    "asset_id": self.asset_id,
                    "amount": self.amount,
                    "approver": self.approver,
                    "key_type": self.key_type,
                    "public_key": self.public_key,
                    "signature": self.signature,
                }),
            )
            .await?;
        output::print_field("Withdrawal", &self.withdrawal_id);
        output::print_field("Asset", &self.asset_id);
        output::print_field("Amount", &self.amount);
        if let Some(n) = result.get("approvals").and_then(|v| v.as_u64()) {
            output::print_field("Approvals", &n.to_string());
        }
        if let Some(t) = result.get("threshold").and_then(|v| v.as_u64()) {
            output::print_field("Threshold", &t.to_string());
        }
        if let Some(reached) = result.get("threshold_reached").and_then(|v| v.as_bool()) {
            output::print_field("Threshold Reached", if reached { "yes" } else { "no" });
        }
        Ok(())
    }
}

/// Execute a withdrawal once the threshold is reached.
#[derive(Debug, Parser)]
pub struct ExecuteCmd {
    /// Withdrawal identifier.
    #[arg(long)]
    withdrawal_id: String,

    /// Asset identifier (e.g. `TNZO`).
    #[arg(long)]
    asset_id: String,

    /// Amount in base units (decimal string) — must match the approved amount.
    #[arg(long)]
    amount: String,

    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ExecuteCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Treasury: Execute Withdrawal");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_treasuryExecuteWithdrawal",
                json!({
                    "withdrawal_id": self.withdrawal_id,
                    "asset_id": self.asset_id,
                    "amount": self.amount,
                }),
            )
            .await?;
        output::print_field("Withdrawal", &self.withdrawal_id);
        output::print_field("Executed", "yes");
        if let Some(balance) = result.get("remaining_balance").and_then(|v| v.as_str()) {
            output::print_field("Remaining Balance", balance);
        }
        Ok(())
    }
}

/// Show a pending withdrawal's approval state.
#[derive(Debug, Parser)]
pub struct PendingCmd {
    /// Withdrawal identifier.
    #[arg(long)]
    withdrawal_id: String,

    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PendingCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Treasury: Pending Withdrawal");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_treasuryGetPendingWithdrawal",
                json!({ "withdrawal_id": self.withdrawal_id }),
            )
            .await?;
        if result.is_null() {
            output::print_info("No pending withdrawal with that id.");
            return Ok(());
        }
        output::print_field("Withdrawal", &self.withdrawal_id);
        if let Some(asset) = result.get("asset_id").and_then(|v| v.as_str()) {
            output::print_field("Asset", asset);
        }
        if let Some(amount) = result.get("amount").and_then(|v| v.as_str()) {
            output::print_field("Amount", amount);
        }
        if let Some(n) = result.get("approvals").and_then(|v| v.as_u64()) {
            output::print_field("Approvals", &n.to_string());
        }
        if let Some(t) = result.get("threshold").and_then(|v| v.as_u64()) {
            output::print_field("Threshold", &t.to_string());
        }
        if let Some(list) = result.get("approvers").and_then(|v| v.as_array()) {
            output::print_info("Approvers:");
            for a in list {
                if let Some(s) = a.as_str() {
                    output::print_info(&format!("  {}", s));
                }
            }
        }
        Ok(())
    }
}
