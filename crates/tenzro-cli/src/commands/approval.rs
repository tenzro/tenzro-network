//! Approval-flow commands.
//!
//! When a delegated agent attempts an operation that exceeds its
//! `DelegationScope` (transaction value, daily-spend cap, restricted
//! contract, etc.), the auth engine parks the request as a pending
//! approval keyed to the controller's DID. The controller's UI (or this
//! CLI) lists, inspects, and decides those approvals.
//!
//! Each subcommand maps 1:1 to an existing RPC: `tenzro_listPendingApprovals`,
//! `tenzro_getApproval`, `tenzro_decideApproval`. The CLI does no policy
//! interpretation — it is a thin transport for human review.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Approval-flow operations.
#[derive(Debug, Subcommand)]
pub enum ApprovalCommand {
    /// List approvals waiting on this controller DID.
    List(ApprovalListCmd),
    /// Inspect a single approval by id.
    Get(ApprovalGetCmd),
    /// Approve or deny a pending request.
    Decide(ApprovalDecideCmd),
}

impl ApprovalCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::List(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::Decide(cmd) => cmd.execute().await,
        }
    }
}

/// `tenzro approval list --approver-did <did>` — pending approvals for
/// the given controller. The node lazily expires stale entries on read,
/// so anything returned here is still actionable.
#[derive(Debug, Parser)]
pub struct ApprovalListCmd {
    /// Controller DID whose pending approvals to list.
    #[arg(long)]
    approver_did: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ApprovalListCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Pending Approvals");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listPendingApprovals",
                serde_json::json!({ "approver_did": self.approver_did }),
            )
            .await
            .context("calling tenzro_listPendingApprovals")?;
        output::print_field(
            "Approver",
            result.get("approver_did").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Count",
            &result
                .get("count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        if let Some(items) = result.get("pending").and_then(|v| v.as_array()) {
            for item in items {
                output::print_json(item)?;
            }
        }
        Ok(())
    }
}

/// `tenzro approval get <approval_id>` — inspect a single record.
#[derive(Debug, Parser)]
pub struct ApprovalGetCmd {
    /// Approval id (returned by `list` or by the original out-of-scope
    /// operation that parked the request).
    approval_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ApprovalGetCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Approval");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getApproval",
                serde_json::json!({ "approval_id": self.approval_id }),
            )
            .await
            .context("calling tenzro_getApproval")?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// `tenzro approval decide --approval-id <id> --decision <approved|denied>`
/// — apply a decision. `approver_did` is optional but recommended:
/// supplying it makes the node verify the caller matches the record's
/// approver, preventing accidental cross-approver tampering.
#[derive(Debug, Parser)]
pub struct ApprovalDecideCmd {
    /// Approval id.
    #[arg(long)]
    approval_id: String,

    /// `approved` or `denied`.
    #[arg(long)]
    decision: String,

    /// Optional: the approver DID to check against the record. The node
    /// returns RPC error `-32001` (Forbidden) if the value does not match.
    #[arg(long)]
    approver_did: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ApprovalDecideCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Approval Decision");
        let mut params = serde_json::Map::new();
        params.insert(
            "approval_id".to_string(),
            serde_json::Value::String(self.approval_id.clone()),
        );
        params.insert(
            "decision".to_string(),
            serde_json::Value::String(self.decision.clone()),
        );
        if let Some(did) = &self.approver_did {
            params.insert(
                "approver_did".to_string(),
                serde_json::Value::String(did.clone()),
            );
        }

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_decideApproval", serde_json::Value::Object(params))
            .await
            .context("calling tenzro_decideApproval")?;
        output::print_json(&result)?;
        Ok(())
    }
}
