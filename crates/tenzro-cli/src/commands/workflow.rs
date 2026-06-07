//! Multi-party saga workflow commands (`tenzro workflow ...`).
//!
//! Wraps the `tenzro_workflow*` RPC namespace: declare a workflow,
//! execute / verify / compensate steps, finalize on-chain receipts,
//! mirror to Canton, and verify DID-signed step envelopes. Each
//! transition produces a `WorkflowReceipt` linked into a per-workflow
//! hash chain; optional `MandateRef` ties the workflow back to an
//! AP2 / x402 / MPP / Stripe SPT / Visa TAP / Mastercard Agent Pay
//! mandate.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum WorkflowCommand {
    /// Open a multi-party saga workflow with an ordered step list
    Open(WorkflowOpenCmd),
    /// Transition a step Pending → Executing
    StepExecute(WorkflowStepCmd),
    /// Mark a step Verified (or Failed if the verifier rejects it)
    StepVerify(WorkflowStepCmd),
    /// Compensate a previously-executed step
    StepCompensate(WorkflowStepCmd),
    /// Finalize the workflow and emit the on-chain WorkflowReceipt
    Finalize(WorkflowIdCmd),
    /// Mirror the workflow to a Canton synchronizer
    MirrorToCanton(WorkflowMirrorCmd),
    /// Verify a DID-signed step payload envelope
    VerifyDidEnvelope(WorkflowVerifyEnvelopeCmd),
    /// Read the workflow record
    Get(WorkflowIdCmd),
    /// Read the workflow saga (steps + per-step status)
    GetSaga(WorkflowIdCmd),
    /// Read workflow lifecycle (state transitions)
    GetLifecycle(WorkflowIdCmd),
    /// Read the on-chain WorkflowReceipt for a workflow
    GetReceipt(WorkflowIdCmd),
    /// Read operational metrics for a workflow
    GetOperationalMetrics(WorkflowIdCmd),
    /// List workflows by creator DID
    ListByCreator(WorkflowByDidCmd),
    /// List workflows where the given DID is a participant
    ListByParticipant(WorkflowByDidCmd),
    /// List workflows in a given status
    ListByStatus(WorkflowByStatusCmd),
    /// List on-chain WorkflowReceipts
    ListReceipts(WorkflowListCmd),
}

impl WorkflowCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Open(c) => c.execute().await,
            Self::StepExecute(c) => c.execute("tenzro_workflowStepExecute").await,
            Self::StepVerify(c) => c.execute("tenzro_workflowStepVerify").await,
            Self::StepCompensate(c) => c.execute("tenzro_workflowStepCompensate").await,
            Self::Finalize(c) => c.execute("tenzro_workflowFinalize").await,
            Self::MirrorToCanton(c) => c.execute().await,
            Self::VerifyDidEnvelope(c) => c.execute().await,
            Self::Get(c) => c.execute("tenzro_getWorkflow").await,
            Self::GetSaga(c) => c.execute("tenzro_getWorkflowSaga").await,
            Self::GetLifecycle(c) => c.execute("tenzro_getWorkflowLifecycle").await,
            Self::GetReceipt(c) => c.execute("tenzro_getWorkflowReceipt").await,
            Self::GetOperationalMetrics(c) => {
                c.execute("tenzro_getWorkflowOperationalMetrics").await
            }
            Self::ListByCreator(c) => c.execute("tenzro_listWorkflowsByCreator").await,
            Self::ListByParticipant(c) => c.execute("tenzro_listWorkflowsByParticipant").await,
            Self::ListByStatus(c) => c.execute().await,
            Self::ListReceipts(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct WorkflowOpenCmd {
    /// Raw workflow body (JSON) — pass the spec the node accepts
    #[arg(long)]
    body: String,

    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl WorkflowOpenCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Workflow — Open");
        let rpc = RpcClient::new(&self.rpc);
        let body: serde_json::Value = serde_json::from_str(&self.body)?;
        let v: serde_json::Value = rpc.call("tenzro_workflowOpen", body).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct WorkflowStepCmd {
    #[arg(long)]
    workflow_id: String,

    #[arg(long)]
    step_index: u32,

    /// Optional JSON payload (step outcome, witness, etc.)
    #[arg(long)]
    payload: Option<String>,

    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl WorkflowStepCmd {
    pub async fn execute(&self, method: &str) -> Result<()> {
        output::print_header(&format!("Workflow — {}", method));
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({
            "workflow_id": self.workflow_id,
            "step_index": self.step_index,
        });
        if let Some(p) = &self.payload {
            params["payload"] = serde_json::from_str(p)?;
        }
        let v: serde_json::Value = rpc.call(method, params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct WorkflowIdCmd {
    #[arg(long)]
    workflow_id: String,

    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl WorkflowIdCmd {
    pub async fn execute(&self, method: &str) -> Result<()> {
        output::print_header(&format!("Workflow — {}", method));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(method, serde_json::json!({ "workflow_id": self.workflow_id }))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct WorkflowMirrorCmd {
    #[arg(long)]
    workflow_id: String,

    #[arg(long)]
    synchronizer: String,

    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl WorkflowMirrorCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Workflow — Mirror to Canton");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_mirrorWorkflowToCanton",
                serde_json::json!({
                    "workflow_id": self.workflow_id,
                    "synchronizer": self.synchronizer,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct WorkflowVerifyEnvelopeCmd {
    /// Raw DID envelope JSON
    #[arg(long)]
    envelope: String,

    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl WorkflowVerifyEnvelopeCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Workflow — Verify DID Envelope");
        let rpc = RpcClient::new(&self.rpc);
        let env: serde_json::Value = serde_json::from_str(&self.envelope)?;
        let v: serde_json::Value = rpc.call("tenzro_verifyDidEnvelope", env).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct WorkflowByDidCmd {
    #[arg(long)]
    did: String,

    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl WorkflowByDidCmd {
    pub async fn execute(&self, method: &str) -> Result<()> {
        output::print_header(&format!("Workflow — {}", method));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(method, serde_json::json!({ "did": self.did }))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct WorkflowByStatusCmd {
    #[arg(long)]
    status: String,

    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl WorkflowByStatusCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Workflow — List by Status");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_listWorkflowsByStatus",
                serde_json::json!({ "status": self.status }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct WorkflowListCmd {
    #[arg(long, default_value_t = 50)]
    limit: u32,

    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl WorkflowListCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Workflow — List Receipts");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_listWorkflowReceipts",
                serde_json::json!({ "limit": self.limit }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
