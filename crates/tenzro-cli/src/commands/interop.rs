//! Agent-interop commands: saga workflow coordination + DID envelope verification.
//!
//! Thin JSON-RPC clients over the node surface — `tenzro_workflow*`
//! (`multi-agent-workflow-coordination.md`) and `tenzro_verifyDidEnvelope`
//! (`agent-interop-protocol-bridge.md`). Mirrors the same methods exposed by
//! the Rust/Python MCP servers and the agent SDK.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Agent-interop operations: saga workflows + DID envelope verification.
#[derive(Debug, Subcommand)]
pub enum InteropCommand {
    /// Open a saga workflow from a JSON array of steps.
    WorkflowOpen(WorkflowOpenCmd),
    /// Execute a saga step (optionally locking per-step escrow).
    WorkflowExecute(WorkflowExecuteCmd),
    /// Verify a saga step (releases escrow + writes ERC-8004 reputation).
    WorkflowVerify(WorkflowVerifyCmd),
    /// Compensate a saga step (optionally cascading rollback in reverse).
    WorkflowCompensate(WorkflowCompensateCmd),
    /// Finalize a saga once all steps are verified.
    WorkflowFinalize(WorkflowFinalizeCmd),
    /// Read a saga workflow's current state.
    WorkflowGet(WorkflowGetCmd),
    /// Verify a Tenzro DID envelope (hex header value): did:tenzro/key/ethr/web.
    VerifyEnvelope(VerifyEnvelopeCmd),
}

impl InteropCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::WorkflowOpen(c) => c.execute().await,
            Self::WorkflowExecute(c) => c.execute().await,
            Self::WorkflowVerify(c) => c.execute().await,
            Self::WorkflowCompensate(c) => c.execute().await,
            Self::WorkflowFinalize(c) => c.execute().await,
            Self::WorkflowGet(c) => c.execute().await,
            Self::VerifyEnvelope(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct WorkflowOpenCmd {
    /// Caller-chosen unique workflow id.
    workflow_id: String,
    /// Orchestrator DID.
    orchestrator_did: String,
    /// JSON array of steps: [{"id":..,"executor_did":..,"compensation":..}, ...]
    steps_json: String,
    /// Comma-separated participant DIDs.
    #[arg(long)]
    participants: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WorkflowOpenCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Saga: Open Workflow");
        let steps: serde_json::Value =
            serde_json::from_str(&self.steps_json).context("parsing steps_json")?;
        let participants: Vec<String> = self
            .participants
            .as_deref()
            .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
            .unwrap_or_default();
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_workflowOpen",
                serde_json::json!({
                    "workflow_id": self.workflow_id,
                    "orchestrator_did": self.orchestrator_did,
                    "saga_steps": steps,
                    "participants": participants,
                }),
            )
            .await
            .context("calling tenzro_workflowOpen")?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct WorkflowExecuteCmd {
    workflow_id: String,
    step_idx: u64,
    /// Opaque execution-proof reference.
    #[arg(long)]
    proof: Option<String>,
    /// Per-step escrow amount to lock (smallest unit); requires --payer/--payee.
    #[arg(long)]
    escrow_amount: Option<String>,
    #[arg(long)]
    payer: Option<String>,
    #[arg(long)]
    payee: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WorkflowExecuteCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Saga: Execute Step");
        let mut params = serde_json::json!({
            "workflow_id": self.workflow_id, "step_idx": self.step_idx,
        });
        let obj = params.as_object_mut().unwrap();
        if let Some(p) = &self.proof {
            obj.insert("proof".into(), serde_json::json!(p));
        }
        if let Some(a) = &self.escrow_amount {
            obj.insert("escrow_amount".into(), serde_json::json!(a));
        }
        if let Some(p) = &self.payer {
            obj.insert("payer".into(), serde_json::json!(p));
        }
        if let Some(p) = &self.payee {
            obj.insert("payee".into(), serde_json::json!(p));
        }
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_workflowStepExecute", params)
            .await
            .context("calling tenzro_workflowStepExecute")?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct WorkflowVerifyCmd {
    workflow_id: String,
    step_idx: u64,
    /// Outcome score 0..=100 fed to ERC-8004 reputation (default 100).
    #[arg(long)]
    outcome_score: Option<u64>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WorkflowVerifyCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Saga: Verify Step");
        let mut params = serde_json::json!({
            "workflow_id": self.workflow_id, "step_idx": self.step_idx,
        });
        if let Some(s) = self.outcome_score {
            params.as_object_mut().unwrap().insert("outcome_score".into(), serde_json::json!(s));
        }
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_workflowStepVerify", params)
            .await
            .context("calling tenzro_workflowStepVerify")?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct WorkflowCompensateCmd {
    workflow_id: String,
    step_idx: u64,
    /// Also compensate every lower-index executed/verified step in reverse order.
    #[arg(long)]
    cascade: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WorkflowCompensateCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Saga: Compensate Step");
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_workflowStepCompensate",
                serde_json::json!({
                    "workflow_id": self.workflow_id,
                    "step_idx": self.step_idx,
                    "cascade": self.cascade,
                }),
            )
            .await
            .context("calling tenzro_workflowStepCompensate")?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct WorkflowFinalizeCmd {
    workflow_id: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WorkflowFinalizeCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Saga: Finalize Workflow");
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_workflowFinalize",
                serde_json::json!({ "workflow_id": self.workflow_id }),
            )
            .await
            .context("calling tenzro_workflowFinalize")?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct WorkflowGetCmd {
    workflow_id: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WorkflowGetCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Saga: Workflow State");
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_getWorkflowSaga",
                serde_json::json!({ "workflow_id": self.workflow_id }),
            )
            .await
            .context("calling tenzro_getWorkflowSaga")?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct VerifyEnvelopeCmd {
    /// Hex header value of the envelope (TenzroDidEnvelope::to_header_value).
    envelope: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl VerifyEnvelopeCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Verify DID Envelope");
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_verifyDidEnvelope",
                serde_json::json!({ "envelope": self.envelope }),
            )
            .await
            .context("calling tenzro_verifyDidEnvelope")?;
        output::print_json(&result)?;
        Ok(())
    }
}
