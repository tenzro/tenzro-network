//! Agent SDK for Tenzro Network
//!
//! This module provides AI agent registration and interaction functionality.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Agent client for AI agent operations
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let agent_client = client.agent();
///
/// // Read the node's agent card
/// let card = agent_client.get_agent_card().await?;
/// println!("Agent card: {card}");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AgentClient {
    rpc: Arc<RpcClient>,
}

impl AgentClient {
    /// Creates a new agent client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Delegates a task to the node's A2A agent with an A2A v1.0
    /// `SendMessage` call.
    ///
    /// The response carries exactly one of `task` (the task the message
    /// created or updated) or `message` (a direct reply).
    pub async fn delegate_task(&self, task_description: &str) -> SdkResult<A2aSendMessageResponse> {
        self.rpc
            .a2a_call("SendMessage", a2a_text_message(task_description))
            .await
    }

    /// Fetches the current state of an A2A task (`GetTask`).
    pub async fn get_a2a_task(&self, task_id: &str) -> SdkResult<A2aTask> {
        self.rpc
            .a2a_call("GetTask", serde_json::json!({ "id": task_id }))
            .await
    }

    /// Cancels an A2A task (`CancelTask`).
    pub async fn cancel_a2a_task(&self, task_id: &str) -> SdkResult<A2aTask> {
        self.rpc
            .a2a_call("CancelTask", serde_json::json!({ "id": task_id }))
            .await
    }

    /// Fetches the node's public A2A agent card from
    /// `/.well-known/agent-card.json`.
    pub async fn get_agent_card(&self) -> SdkResult<serde_json::Value> {
        self.rpc.get(crate::rpc::A2A_AGENT_CARD_PATH).await
    }

    /// Discovers available models with optional filters
    pub async fn discover_models(
        &self,
        modality: Option<&str>,
        serving_only: Option<bool>,
        query: Option<&str>,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_discoverModels",
                serde_json::json!([{"modality": modality, "serving_only": serving_only, "query": query}]),
            )
            .await
    }
}

/// Build A2A v1.0 `SendMessage` params carrying one user text part.
pub fn a2a_text_message(text: &str) -> serde_json::Value {
    serde_json::json!({
        "message": {
            "messageId": uuid::Uuid::new_v4().to_string(),
            "role": "ROLE_USER",
            "parts": [{ "text": text }],
        },
    })
}

/// A2A v1.0 `SendMessage` result: exactly one of `task` or `message`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aSendMessageResponse {
    /// The task the message created or updated
    pub task: Option<A2aTask>,
    /// A direct reply message from the agent
    pub message: Option<serde_json::Value>,
}

/// A2A v1.0 task as returned by `SendMessage`, `GetTask` and `CancelTask`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aTask {
    /// Task id
    pub id: String,
    /// Conversation context the task belongs to
    pub context_id: Option<String>,
    /// Current status
    pub status: A2aTaskStatus,
    /// Artifacts produced so far
    #[serde(default)]
    pub artifacts: Vec<serde_json::Value>,
}

/// A2A v1.0 task status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aTaskStatus {
    /// Task state, e.g. `TASK_STATE_COMPLETED`
    pub state: String,
    /// Optional status message from the agent
    pub message: Option<serde_json::Value>,
    /// ISO 8601 timestamp of the status
    pub timestamp: Option<String>,
}

impl AgentClient {
    /// Exports an evidence pack for one agent or for every agent of a root.
    pub async fn export_evidence_pack(
        &self,
        request: &EvidencePackRequest,
    ) -> crate::error::SdkResult<serde_json::Value> {
        let params = serde_json::to_value(request)?;
        self.rpc.call("tenzro_exportEvidencePack", params).await
    }

    /// Calls `tenzro_getAgentAuditCommit`: get agent audit commit.
    pub async fn get_audit_commit(
        &self,
        committer: &str,
        epoch: Option<u64>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getAgentAuditCommit",
                serde_json::json!({ "committer": committer, "epoch": epoch }),
            )
            .await
    }

    /// Calls `tenzro_getAgentQuarantine`: get agent quarantine.
    pub async fn get_quarantine(
        &self,
        agent_did: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getAgentQuarantine",
                serde_json::json!({ "agent_did": agent_did }),
            )
            .await
    }

    /// Calls `tenzro_verifyAgentAuditAttestation`: verify agent audit attestation.
    pub async fn verify_audit_attestation(
        &self,
        committer: &str,
        epoch: u64,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_verifyAgentAuditAttestation",
                serde_json::json!({ "committer": committer, "epoch": epoch }),
            )
            .await
    }
}

/// Whose actions an evidence pack covers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceSubject {
    /// One agent.
    #[serde(rename = "agent_did")]
    Agent(String),
    /// A root and the agents it names in `agents`.
    #[serde(rename = "root_did")]
    Root(String),
}

/// Parameters of `tenzro_exportEvidencePack`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackRequest {
    /// The pack's subject.
    #[serde(flatten)]
    pub subject: EvidenceSubject,
    /// Audit entry proofs from the agents' recorder.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit: Vec<serde_json::Value>,
    /// The agents' signed session receipts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<serde_json::Value>,
    /// The root's agents to cover.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
    /// Payment references of the covered agents' payments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub payments: Vec<String>,
    /// Governance proposal ids (32 bytes hex) touching the subject.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proposals: Vec<String>,
    /// Token ids (32 bytes hex) whose issuer actions to prove.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tokens: Vec<String>,
    /// Contract addresses (20 bytes hex) whose cards to prove.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contracts: Vec<String>,
}

impl AgentClient {
    /// Calls `tenzro_flagAgentAudit`: flag agent audit.
    pub async fn flag_agent_audit(
        &self,
        epoch: u64,
        findings: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_flagAgentAudit",
                serde_json::json!({ "epoch": epoch, "findings": findings }),
            )
            .await
    }

    /// Calls `tenzro_recordAgentAuditSession` (operator only): report an
    /// audit session's latest line (its MMR root over `count` entries, hex
    /// digests) to the serving node, which commits each ended epoch's lines
    /// on chain. Returns the epoch the line will be committed in.
    pub async fn record_agent_audit_session(
        &self,
        session_id: &str,
        mmr_root: &str,
        count: u64,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_recordAgentAuditSession", serde_json::json!({ "session_id": session_id, "mmr_root": mmr_root, "count": count }))
            .await
    }

    /// Calls `tenzro_getBridgeCircuit`: get bridge circuit.
    pub async fn get_bridge_circuit(
        &self,
        source_chain: &str,
        adapter: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getBridgeCircuit",
                serde_json::json!({ "source_chain": source_chain, "adapter": adapter }),
            )
            .await
    }

    /// Calls `tenzro_resolveAgentKey`: resolve agent key.
    pub async fn resolve_agent_key(
        &self,
        agent_did: &str,
        keyid: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_resolveAgentKey",
                serde_json::json!({ "agent_did": agent_did, "keyid": keyid }),
            )
            .await
    }

    /// A kill-switch receipt by its id (hex), from consensus state, or
    /// `None` when there is none.
    pub async fn get_kill_switch_receipt(
        &self,
        receipt_id: &str,
    ) -> crate::error::SdkResult<Option<KillSwitchReceipt>> {
        self.rpc
            .call(
                "tenzro_getKillSwitchReceipt",
                serde_json::json!({ "receipt_id": receipt_id }),
            )
            .await
    }

    /// Kill-switch receipts naming `agent_did`, in chain order from their
    /// logs, each with its event cursor.
    pub async fn list_kill_switch_by_agent(
        &self,
        agent_did: &str,
        page: crate::types::PageRequest,
    ) -> crate::error::SdkResult<KillSwitchPage> {
        let mut params = page.to_params();
        params["agent_did"] = agent_did.into();
        self.rpc.call("tenzro_listKillSwitchByAgent", params).await
    }

    /// Kill-switch receipts `controller_did` issued, in chain order from
    /// their logs, each with its event cursor.
    pub async fn list_kill_switch_by_controller(
        &self,
        controller_did: &str,
        page: crate::types::PageRequest,
    ) -> crate::error::SdkResult<KillSwitchPage> {
        let mut params = page.to_params();
        params["controller_did"] = controller_did.into();
        self.rpc
            .call("tenzro_listKillSwitchByController", params)
            .await
    }
}

/// A kill-switch receipt from consensus state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KillSwitchReceipt {
    /// The receipt id, hex.
    pub receipt_id: String,
    /// `pause`, `quarantine` or `terminate`.
    pub action: String,
    /// The agent acted on.
    pub agent_did: String,
    /// The controller who issued it.
    pub controller_did: String,
    /// The reason code.
    pub reason_code: u16,
    /// The reason, in words.
    pub reason_text: Option<String>,
    /// The hash of the evidence, hex.
    pub evidence_hash: Option<String>,
    /// The share of the agent's bond slashed, basis points.
    pub slash_bps: Option<u16>,
    /// Whether the action cascades to the agent's sub-agents.
    pub cascade: Option<bool>,
    /// When a pause ends of itself, Unix seconds; `None` for a pause that
    /// lasts until resumed, and for every other action.
    #[serde(default)]
    pub pause_until: Option<u64>,
    /// The block the agent was frozen at.
    pub frozen_at_block: u64,
    /// When, Unix milliseconds.
    pub timestamp: u64,
    /// The receipt's event cursor, on a listed receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// A page of kill-switch receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KillSwitchPage {
    /// The receipts.
    pub receipts: Vec<KillSwitchReceipt>,
    /// Pass back as [`crate::types::PageRequest::from_cursor`] to continue; `None` at the end.
    pub cursor: Option<String>,
}
