//! Agent SDK for Tenzro Network
//!
//! This module provides AI agent registration and interaction functionality.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use crate::wallet::HybridSigner;
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
/// // Read the agent card of the node whose machine DID is this one
/// let card = agent_client
///     .get_agent_card("did:tenzro:machine:0a1b")
///     .await?;
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

    /// One A2A task call as `sender_did` to the node whose machine DID is
    /// `agent_did`, carrying the DID envelope `signer` signs for it
    /// ([`crate::a2a_envelope`]). The node answers no task call without one,
    /// and none addressed to another node.
    async fn signed_a2a_call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        mut params: serde_json::Value,
        sender_did: &str,
        signer: &dyn HybridSigner,
        agent_did: &str,
    ) -> SdkResult<T> {
        crate::a2a_envelope::sign(agent_did, method, &mut params, sender_did, signer).await?;
        self.rpc.a2a_call(method, params).await
    }

    /// Delegates a task to the A2A agent of the node whose machine identity
    /// is `agent_did`, with an A2A v1.0 `SendMessage` call signed by `signer`
    /// as `sender_did`. The task belongs to `sender_did`: only it can read,
    /// continue or cancel it.
    ///
    /// The node's card is fetched and checked first
    /// ([`AgentClient::get_agent_card`]); when it does not prove the
    /// endpoint is `agent_did`'s, nothing is sent.
    ///
    /// The response carries exactly one of `task` (the task the message
    /// created or updated) or `message` (a direct reply).
    pub async fn delegate_task(
        &self,
        sender_did: &str,
        signer: &dyn HybridSigner,
        agent_did: &str,
        task_description: &str,
    ) -> SdkResult<A2aSendMessageResponse> {
        self.get_agent_card(agent_did).await?;
        self.signed_a2a_call(
            "SendMessage",
            a2a_text_message(task_description),
            sender_did,
            signer,
            agent_did,
        )
        .await
    }

    /// Fetches the current state of one of `sender_did`'s own A2A tasks
    /// (`GetTask`) on the node whose machine DID is `agent_did`. A task another DID opened is reported as not found.
    pub async fn get_a2a_task(
        &self,
        sender_did: &str,
        signer: &dyn HybridSigner,
        agent_did: &str,
        task_id: &str,
    ) -> SdkResult<A2aTask> {
        self.signed_a2a_call(
            "GetTask",
            serde_json::json!({ "id": task_id }),
            sender_did,
            signer,
            agent_did,
        )
        .await
    }

    /// Lists the A2A tasks `sender_did` opened (`ListTasks`) on the node whose
    /// machine DID is `agent_did`, and no others.
    pub async fn list_a2a_tasks(
        &self,
        sender_did: &str,
        signer: &dyn HybridSigner,
        agent_did: &str,
        filter: &A2aTaskFilter,
    ) -> SdkResult<A2aTaskList> {
        let params =
            serde_json::to_value(filter).map_err(|_| crate::error::SdkError::SerializationError)?;
        self.signed_a2a_call("ListTasks", params, sender_did, signer, agent_did)
            .await
    }

    /// Cancels one of `sender_did`'s own A2A tasks (`CancelTask`) on the node
    /// whose machine DID is `agent_did`.
    pub async fn cancel_a2a_task(
        &self,
        sender_did: &str,
        signer: &dyn HybridSigner,
        agent_did: &str,
        task_id: &str,
    ) -> SdkResult<A2aTask> {
        self.signed_a2a_call(
            "CancelTask",
            serde_json::json!({ "id": task_id }),
            sender_did,
            signer,
            agent_did,
        )
        .await
    }

    /// Fetches the node's A2A agent card from `/.well-known/agent-card.json`
    /// and checks it was signed by the hardware key `agent_did` derives from
    /// ([`crate::agent_card`]). A card that is unsigned, altered, or signed
    /// by another machine is an error; no card is returned unchecked.
    pub async fn get_agent_card(&self, agent_did: &str) -> SdkResult<serde_json::Value> {
        let card = self.rpc.get(crate::rpc::A2A_AGENT_CARD_PATH).await?;
        crate::agent_card::verify_agent_card(&card, agent_did)?;
        Ok(card)
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

/// Which of the sender's tasks `ListTasks` returns, and how much of each.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aTaskFilter {
    /// Only tasks of this context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Only tasks in this state, e.g. `TASK_STATE_COMPLETED`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Tasks per page (the node returns at most 100)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    /// The `next_page_token` of the page before
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
    /// Most recent messages to return with each task
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_length: Option<u32>,
    /// Whether each task carries its artifacts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_artifacts: Option<bool>,
}

/// One page of `ListTasks`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aTaskList {
    /// The tasks on this page, ordered by id
    pub tasks: Vec<A2aTask>,
    /// Token of the next page; empty on the last one
    pub next_page_token: String,
    /// Tasks per page the node used
    pub page_size: u32,
    /// How many of the sender's tasks match the filter
    pub total_size: u32,
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
    /// Calls `tenzro_getAgentTermsCredential`: a delegated agent's Terms as an
    /// unsigned W3C VC 2.0 credential its controller signs; null when the
    /// agent has no Terms.
    pub async fn get_agent_terms_credential(
        &self,
        agent_did: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getAgentTermsCredential",
                serde_json::json!({ "agent_did": agent_did }),
            )
            .await
    }

    /// Calls `tenzro_recordExecutionReceipt` (owner proof): record, once, a
    /// receipt an outside platform gave an agent for work it ran there; the
    /// receipt's SHA-256 enters the agent's signed audit log. `did_envelope`
    /// is the agent's DID envelope over the request.
    pub async fn record_execution_receipt(
        &self,
        agent_did: &str,
        platform: &str,
        receipt: &str,
        units: Option<u64>,
        did_envelope: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_recordExecutionReceipt",
                serde_json::json!({
                    "agent_did": agent_did,
                    "platform": platform,
                    "receipt": receipt,
                    "units": units,
                    "did_envelope": did_envelope,
                }),
            )
            .await
    }

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
    /// The cascade flag the action was sent with. The chain records it and
    /// acts on nothing: an agent has no sub-agents.
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

#[cfg(test)]
mod a2a_tests {
    use super::*;
    use crate::a2a_envelope::tests::{AUDIENCE, SoftSigner, verified_sender};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// One HTTP exchange: answers with `result` and returns the JSON-RPC
    /// request the client sent.
    async fn exchange(
        listener: tokio::net::TcpListener,
        result: serde_json::Value,
    ) -> serde_json::Value {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let body_start = loop {
            let n = sock.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..body_start]).to_lowercase();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        while buf.len() < body_start + len {
            let n = sock.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
        }
        let request: serde_json::Value = serde_json::from_slice(&buf[body_start..]).unwrap();
        let body = serde_json::json!({ "jsonrpc": "2.0", "id": request["id"], "result": result })
            .to_string();
        let reply = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(reply.as_bytes()).await.unwrap();
        request
    }

    async fn client() -> (AgentClient, tokio::net::TcpListener) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let rpc = RpcClient::new(&url, std::time::Duration::from_secs(10), None).unwrap();
        (AgentClient::new(Arc::new(rpc)), listener)
    }

    const DID: &str = "did:tenzro:machine:reader";

    fn task(id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "status": { "state": "TASK_STATE_COMPLETED", "timestamp": "2027-01-15T08:00:00.000Z" },
        })
    }

    /// Each task call goes out with an envelope the node's
    /// rules accept: signed by the caller's key over that method, that task
    /// and that body.
    #[tokio::test]
    async fn every_task_call_carries_the_senders_signed_envelope() {
        let signer = SoftSigner::new(21);

        let (agent, listener) = client().await;
        let server = tokio::spawn(exchange(listener, task("t-1")));
        let got = agent
            .get_a2a_task(DID, &signer, AUDIENCE, "t-1")
            .await
            .unwrap();
        assert_eq!(got.id, "t-1");
        let request = server.await.unwrap();
        assert_eq!(request["method"], "GetTask");
        assert_eq!(request["params"]["id"], "t-1");
        assert_eq!(
            verified_sender(AUDIENCE, "GetTask", &request["params"]).as_deref(),
            Some(DID)
        );

        let (agent, listener) = client().await;
        let server = tokio::spawn(exchange(
            listener,
            serde_json::json!({
                "tasks": [task("t-1"), task("t-2")],
                "nextPageToken": "",
                "pageSize": 50,
                "totalSize": 2,
            }),
        ));
        let filter = A2aTaskFilter {
            context_id: Some("ctx".to_string()),
            include_artifacts: Some(true),
            ..Default::default()
        };
        let page = agent
            .list_a2a_tasks(DID, &signer, AUDIENCE, &filter)
            .await
            .unwrap();
        assert_eq!(page.total_size, 2);
        assert_eq!(page.tasks[1].id, "t-2");
        assert!(page.next_page_token.is_empty());
        let request = server.await.unwrap();
        assert_eq!(request["method"], "ListTasks");
        assert_eq!(request["params"]["contextId"], "ctx");
        assert_eq!(request["params"]["includeArtifacts"], true);
        assert!(
            request["params"].get("pageSize").is_none(),
            "unset filters are not sent"
        );
        assert_eq!(
            verified_sender(AUDIENCE, "ListTasks", &request["params"]).as_deref(),
            Some(DID)
        );

        let (agent, listener) = client().await;
        let server = tokio::spawn(exchange(listener, task("t-1")));
        agent
            .cancel_a2a_task(DID, &signer, AUDIENCE, "t-1")
            .await
            .unwrap();
        let request = server.await.unwrap();
        assert_eq!(request["method"], "CancelTask");
        assert_eq!(
            verified_sender(AUDIENCE, "CancelTask", &request["params"]).as_deref(),
            Some(DID)
        );
    }

    /// Serves `replies` to as many connections, in order, and returns each
    /// request's first line with its JSON body (null for a GET).
    async fn serve(
        listener: tokio::net::TcpListener,
        replies: Vec<serde_json::Value>,
    ) -> Vec<(String, serde_json::Value)> {
        let mut seen = Vec::new();
        for reply in replies {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let body_start = loop {
                let n = sock.read(&mut chunk).await.unwrap();
                buf.extend_from_slice(&chunk[..n]);
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let head = String::from_utf8_lossy(&buf[..body_start]).to_string();
            let len: usize = head
                .to_lowercase()
                .lines()
                .find_map(|l| {
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().to_string())
                })
                .map_or(0, |v| v.parse().unwrap());
            while buf.len() < body_start + len {
                let n = sock.read(&mut chunk).await.unwrap();
                buf.extend_from_slice(&chunk[..n]);
            }
            let body =
                serde_json::from_slice(&buf[body_start..]).unwrap_or(serde_json::Value::Null);
            seen.push((head.lines().next().unwrap_or_default().to_string(), body));
            let text = reply.to_string();
            let answer = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
                text.len()
            );
            sock.write_all(answer.as_bytes()).await.unwrap();
        }
        seen
    }

    /// A delegation goes out only after the node's card proved the endpoint
    /// is the machine the caller named.
    #[tokio::test]
    async fn a_task_is_delegated_only_to_a_node_whose_card_proves_its_identity() {
        use crate::agent_card::tests::{card, did_of, key, sign, sign_as};
        let signer = SoftSigner::new(21);
        let node_key = key(40);
        let node_did = did_of(&node_key);

        // A good card: the card is fetched, then the signed message is sent.
        let (agent, listener) = client().await;
        let sent =
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": { "task": task("t-9") } });
        let server = tokio::spawn(serve(listener, vec![sign(card(), &node_key), sent]));
        let out = agent
            .delegate_task(DID, &signer, &node_did, "summarise the report")
            .await
            .unwrap();
        assert_eq!(out.task.unwrap().id, "t-9");
        let seen = server.await.unwrap();
        assert!(
            seen[0].0.starts_with("GET /.well-known/agent-card.json"),
            "{}",
            seen[0].0
        );
        assert!(seen[1].0.starts_with("POST /a2a"), "{}", seen[1].0);
        let params = &seen[1].1["params"];
        assert_eq!(seen[1].1["method"], "SendMessage");
        assert_eq!(
            params["message"]["parts"][0]["text"],
            "summarise the report"
        );
        assert_eq!(
            verified_sender(&node_did, "SendMessage", params).as_deref(),
            Some(DID)
        );
        assert!(
            params.get("metadata").is_none(),
            "a message carries it inside"
        );

        // A card signed by another key, a card that claims the named machine
        // under another key, an unsigned card, and a good card of another
        // machine: each is refused and nothing is sent after the card.
        let other = key(41);
        for bad in [
            sign(card(), &other),
            sign_as(card(), &other, &node_did),
            card(),
        ] {
            let (agent, listener) = client().await;
            let server = tokio::spawn(serve(listener, vec![bad]));
            let err = agent
                .delegate_task(DID, &signer, &node_did, "summarise the report")
                .await
                .unwrap_err();
            assert!(
                matches!(err, crate::error::SdkError::AuthenticationError(_)),
                "{err}"
            );
            let seen = server.await.unwrap();
            assert_eq!(seen.len(), 1, "only the card was asked for");
            assert!(seen[0].0.starts_with("GET "));
        }
        let (agent, listener) = client().await;
        let server = tokio::spawn(serve(listener, vec![sign(card(), &node_key)]));
        let named_other = did_of(&other);
        assert!(
            agent
                .delegate_task(DID, &signer, &named_other, "summarise the report")
                .await
                .is_err(),
            "the card is this machine's, not the one the caller named"
        );
        assert_eq!(server.await.unwrap().len(), 1);
    }
}
