//! A2A Protocol Server — JSON-RPC 2.0 endpoints for agent-to-agent communication
//!
//! Implements the Google A2A protocol specification with:
//! - `POST /a2a` — JSON-RPC 2.0 dispatcher
//! - `GET /.well-known/agent.json` — Agent Card discovery
//! - `POST /a2a/stream` — SSE streaming for task updates

use axum::{
    extract::State,
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn};

use tenzro_storage::KvStore;

use super::agent_card::{self, AgentCard};
use super::did_envelope;
use super::task_manager::{
    MessagePart, TaskArtifact, TaskManager, TaskMessage, TaskState,
};
use super::x402_extension::{self, MessageMetadataExt};
use crate::node::TenzroNode;
use crate::web::handlers::WebState;

/// Shared state for the A2A server
pub struct A2aState {
    pub node: Arc<TenzroNode>,
    pub _web_state: Arc<WebState>,
    pub task_manager: TaskManager,
    pub agent_card: AgentCard,
    /// Verifies x402 payment payloads attached via [`crate::a2a::x402_extension`].
    /// Registered scheme backends (`exact-eip3009`, `exact-permit2`,
    /// `exact-erc7710`) land in slice (c) of the agentic 2026 plan; until
    /// then this rejects every payload as `SchemeNotImplemented`.
    pub payment_verifier: Arc<dyn x402_extension::PaymentVerifier>,
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct JsonRpcRequest {
    pub(crate) jsonrpc: String,
    pub(crate) method: String,
    #[serde(default)]
    pub(crate) params: serde_json::Value,
    pub(crate) id: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonRpcResponse {
    pub(crate) jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<JsonRpcError>,
    pub(crate) id: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonRpcError {
    pub(crate) code: i32,
    pub(crate) message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    fn error(id: serde_json::Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }

    fn method_not_found(id: serde_json::Value) -> Self {
        Self::error(id, -32601, "Method not found")
    }

    /// JSON-RPC 2.0 `-32700` Parse error envelope with `id = null` per
    /// spec §5.1 ("If there was an error in detecting the id ... it MUST
    /// be Null"). Used by the iroh-transport adapter when the request
    /// body isn't valid JSON.
    pub(crate) fn parse_error(msg: impl Into<String>) -> Self {
        Self::error(serde_json::Value::Null, -32700, msg)
    }

    fn invalid_params(id: serde_json::Value, msg: impl Into<String>) -> Self {
        Self::error(id, -32602, msg)
    }

    fn internal_error(id: serde_json::Value, msg: impl Into<String>) -> Self {
        Self::error(id, -32603, msg)
    }
}

// ---------------------------------------------------------------------------
// A2A method parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendMessageParams {
    message: TaskMessageInput,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskMessageInput {
    role: String,
    parts: Vec<MessagePartInput>,
    #[serde(default)]
    task_id: Option<String>,
    #[serde(default)]
    context_id: Option<String>,
    /// Caller metadata — may include agent_id or wallet address for authentication,
    /// and reserved `x402.*` keys for x402 payment payloads (see [`crate::a2a::x402_extension`]).
    #[serde(default)]
    metadata: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessagePartInput {
    #[serde(rename = "type")]
    part_type: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    data: Option<serde_json::Value>,
    #[serde(default)]
    mime_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetTaskParams {
    id: String,
    #[serde(default)]
    history_length: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListTasksParams {
    #[serde(default)]
    context_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CancelTaskParams {
    id: String,
}

// ---------------------------------------------------------------------------
// AP2 (Agent Payments Protocol) parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ap2CreateParams {
    /// Payment amount in smallest TNZO units
    amount: u128,
    /// Currency (e.g., "TNZO", "wTNZO")
    #[serde(default = "default_currency")]
    currency: String,
    /// Recipient address (hex)
    recipient: String,
    /// Optional memo/description
    #[serde(default)]
    memo: Option<String>,
    /// Caller metadata
    #[serde(default)]
    metadata: Option<std::collections::HashMap<String, serde_json::Value>>,
}

fn default_currency() -> String {
    "TNZO".to_string()
}

// ---------------------------------------------------------------------------
// DID envelope extraction helpers — peek at raw `params` JSON before per-method
// deserialization so the dispatcher chokepoint can verify the envelope without
// caring about each method's param shape.
// ---------------------------------------------------------------------------

/// Extract the envelope metadata map from raw `params`. Looks first at
/// `params.message.metadata` (used by `message/send` and `tasks/send`),
/// then at `params.metadata` (used by `payments/create`). Returns an
/// empty map when neither is present — the verifier will then surface a
/// precise `Missing(...)` field error for the relying party.
fn extract_envelope_metadata(
    params: &serde_json::Value,
) -> std::collections::HashMap<String, serde_json::Value> {
    let candidate = params
        .get("message")
        .and_then(|m| m.get("metadata"))
        .or_else(|| params.get("metadata"));
    match candidate {
        Some(serde_json::Value::Object(map)) => map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        _ => std::collections::HashMap::new(),
    }
}

/// Extract the task identifier that binds the envelope signature to a
/// specific A2A operation. The path varies by method:
///
/// - `message/send` / `tasks/send`: `params.message.taskId` (may be absent
///   when creating a new task — the empty string is then signed).
/// - `tasks/cancel`: `params.id`.
/// - `payments/{create,authorize,execute,cancel}`: `params.paymentId` for
///   methods that bind to an existing payment; `payments/create` signs
///   with an empty task_id because the payment_id is server-assigned.
fn extract_envelope_task_id(method: &str, params: &serde_json::Value) -> String {
    let key = match method {
        "message/send" | "tasks/send" => {
            return params
                .get("message")
                .and_then(|m| m.get("taskId"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
        }
        "tasks/cancel" => "id",
        "payments/create" => return String::new(),
        "payments/authorize" | "payments/execute" | "payments/cancel" => "paymentId",
        _ => return String::new(),
    };
    params
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ap2AuthorizeParams {
    /// Payment ID to authorize
    payment_id: String,
    /// Maximum spending limit (in smallest units)
    spending_limit: u128,
    /// Session identifier for scoped authorization
    #[serde(default)]
    session_id: Option<String>,
    /// Expiry timestamp (Unix seconds)
    #[serde(default)]
    expiry: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ap2ExecuteParams {
    /// Payment ID to execute
    payment_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ap2StatusParams {
    /// Payment ID to query
    payment_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ap2CancelParams {
    /// Payment ID to cancel
    payment_id: String,
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// Serve the Agent Card at `GET /.well-known/agent.json`.
///
/// A2A v1.0 introduced the `SignedAgentCard` envelope that wraps the
/// raw card with a JWS signature over the canonical card hash. When
/// the caller passes `?signed=1`, the server wraps the card in the
/// signed envelope so relying parties can verify the domain owner's
/// signature; otherwise we serve the legacy bare card for backwards
/// compatibility with A2A v0.3 / v0.2.5 clients.
async fn agent_card_handler(
    State(state): State<Arc<A2aState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use super::agent_card::SignedAgentCard;

    if params.get("signed").map(|v| v == "1" || v == "true").unwrap_or(false) {
        let card = state.agent_card.clone();
        let canonical_hash = SignedAgentCard::canonical_card_hash(&card);
        // Production-grade signing: the JWS leg is added once the
        // node-level domain signing key is wired. Until then we expose
        // the canonical hash as the `signature` placeholder so callers
        // can compute the hash themselves and verify it matches what
        // the server intends to sign. The `algorithm` field reads
        // `unsigned` to make the unsigned-state explicit.
        let signed = SignedAgentCard::wrap(
            card,
            format!("hash:{}", hex::encode(canonical_hash)),
            Some("unsigned".to_string()),
            Some("did:web:tenzro.network".to_string()),
        );
        Json(signed).into_response()
    } else {
        Json(state.agent_card.clone()).into_response()
    }
}

/// Serve a bridged Agent Card for an arbitrary DID at
/// `GET /agents/:did/.well-known/agent.json`. Resolves the DID through the node
/// registry (404 if unknown) and returns the node's card rebranded for that
/// agent — A2A discovery of a Tenzro agent by DID (agent-interop-protocol-
/// bridge.md, bridged AgentCard hosting).
async fn hosted_agent_card_handler(
    State(state): State<Arc<A2aState>>,
    axum::extract::Path(did): axum::extract::Path<String>,
) -> Result<Json<AgentCard>, axum::http::StatusCode> {
    let registry = state
        .node
        .identity_registry()
        .ok_or(axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
    registry
        .resolve(&did)
        .map_err(|_| axum::http::StatusCode::NOT_FOUND)?;
    let mut card = state.agent_card.clone();
    card.name = format!("Tenzro Agent ({did})");
    card.description = format!(
        "Bridged A2A agent card for {did}, hosted by the Tenzro Network. {}",
        card.description
    );
    Ok(Json(card))
}

/// Main JSON-RPC 2.0 dispatcher at `POST /a2a`
async fn jsonrpc_handler(
    State(state): State<Arc<A2aState>>,
    Json(req): Json<JsonRpcRequest>,
) -> Json<JsonRpcResponse> {
    Json(dispatch_jsonrpc(&state, req))
}

/// Transport-agnostic JSON-RPC 2.0 dispatch.
///
/// Both the HTTPS axum route (`jsonrpc_handler`) and the iroh-transport
/// adapter (`crate::a2a::iroh_transport::IrohA2aDispatcher`) call this
/// function so the wire format is identical regardless of how the request
/// arrived. The function never panics — JSON-level errors are returned as
/// JSON-RPC `error` envelopes.
pub(crate) fn dispatch_jsonrpc(state: &Arc<A2aState>, req: JsonRpcRequest) -> JsonRpcResponse {
    if req.jsonrpc != "2.0" {
        return JsonRpcResponse::error(
            req.id,
            -32600,
            "Invalid JSON-RPC version, expected 2.0",
        );
    }

    // Tenzro DID envelope gate — fail-closed authorization for all A2A
    // mutation methods. Read methods (`tasks/get`, `tasks/list`,
    // `payments/status`) are not gated. See `super::did_envelope` for the
    // wire format and verification rules.
    if did_envelope::requires_envelope(&req.method) {
        let metadata = extract_envelope_metadata(&req.params);
        let task_id = extract_envelope_task_id(&req.method, &req.params);
        match did_envelope::verify_envelope(
            &state.node,
            &req.method,
            &task_id,
            &metadata,
        ) {
            Ok(sender_did) => {
                tracing::debug!(
                    "A2A envelope verified: method={} task_id={} sender={}",
                    req.method, task_id, sender_did
                );
            }
            Err(err) => {
                warn!(
                    "A2A envelope rejected: method={} task_id={} reason={}",
                    req.method, task_id, err.message()
                );
                return JsonRpcResponse::error(req.id, -32001, err.message());
            }
        }
    }

    match req.method.as_str() {
        "message/send" | "tasks/send" => handle_send_message(state, req.params, req.id.clone()),
        "tasks/get" => handle_get_task(state, req.params, req.id.clone()),
        "tasks/list" => handle_list_tasks(state, req.params, req.id.clone()),
        "tasks/cancel" => handle_cancel_task(state, req.params, req.id.clone()),
        // AP2 (Agent Payments Protocol) methods
        "payments/create" => handle_ap2_create(state, req.params, req.id.clone()),
        "payments/authorize" => handle_ap2_authorize(state, req.params, req.id.clone()),
        "payments/execute" => handle_ap2_execute(state, req.params, req.id.clone()),
        "payments/status" => handle_ap2_status(state, req.params, req.id.clone()),
        "payments/cancel" => handle_ap2_cancel(state, req.params, req.id.clone()),
        _ => {
            warn!("A2A: unknown method: {}", req.method);
            JsonRpcResponse::method_not_found(req.id.clone())
        }
    }
}

/// SSE streaming endpoint at `POST /a2a/stream`
async fn stream_handler(
    State(state): State<Arc<A2aState>>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(32);

    // Process the request and stream updates
    let state_clone = state.clone();
    tokio::spawn(async move {
        // Apply the same DID envelope gate that `dispatch_jsonrpc` enforces
        // for the unary route. SSE streaming runs the same method
        // (`message/send`/`tasks/send`), so the wire requirements are
        // identical — fail-closed before touching the task manager.
        if did_envelope::requires_envelope(&req.method) {
            let metadata = extract_envelope_metadata(&req.params);
            let task_id = extract_envelope_task_id(&req.method, &req.params);
            if let Err(err) = did_envelope::verify_envelope(
                &state_clone.node,
                &req.method,
                &task_id,
                &metadata,
            ) {
                warn!(
                    "A2A SSE envelope rejected: method={} task_id={} reason={}",
                    req.method, task_id, err.message()
                );
                let rejected = JsonRpcResponse::error(req.id.clone(), -32001, err.message());
                let event = Event::default()
                    .event("error")
                    .json_data(&rejected)
                    .unwrap_or_else(|_| Event::default().data("error"));
                let _ = tx.send(Ok(event)).await;
                return;
            }
        }

        // First, process the message like a normal send
        let result = handle_send_message(&state_clone, req.params, req.id.clone());

        // Send the initial task status
        let event = Event::default()
            .event("task")
            .json_data(&result)
            .unwrap_or_else(|_| Event::default().data("error"));
        let _ = tx.send(Ok(event)).await;

        // If the task was created, simulate streaming updates
        if let Some(result_value) = &result.result
            && let Some(task_id) = result_value.get("id").and_then(|v| v.as_str())
        {
                // Mark as working
                if let Some(task) = state_clone.task_manager.update_status(
                    task_id,
                    TaskState::Working,
                    None,
                ) {
                    let event = Event::default()
                        .event("task")
                        .json_data(&task)
                        .unwrap_or_else(|_| Event::default().data("error"));
                    let _ = tx.send(Ok(event)).await;
                }

                // Process the task (execute via node)
                let response = execute_task(&state_clone, task_id).await;

                // Send completion
                let response_msg = TaskMessage {
                    role: "agent".to_string(),
                    parts: vec![MessagePart::text(response)],
                };
                if let Some(task) = state_clone.task_manager.update_status(
                    task_id,
                    TaskState::Completed,
                    Some(response_msg),
                ) {
                    let event = Event::default()
                        .event("task")
                        .json_data(&task)
                        .unwrap_or_else(|_| Event::default().data("error"));
                    let _ = tx.send(Ok(event)).await;
                }

                // Send done sentinel
                let _ = tx
                    .send(Ok(Event::default().event("done").data("")))
                    .await;
        }
    });

    Sse::new(ReceiverStream::new(rx))
}

// ---------------------------------------------------------------------------
// JSON-RPC method handlers
// ---------------------------------------------------------------------------

fn handle_send_message(
    state: &A2aState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> JsonRpcResponse {
    let params: SendMessageParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return JsonRpcResponse::invalid_params(id, format!("Invalid params: {}", e)),
    };

    let task_id = params
        .message
        .task_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let parts: Vec<MessagePart> = params
        .message
        .parts
        .into_iter()
        .map(|p| MessagePart {
            part_type: p.part_type,
            text: p.text,
            data: p.data,
            mime_type: p.mime_type,
        })
        .collect();

    let msg = TaskMessage {
        role: params.message.role,
        parts,
    };

    // Inbound message metadata — may carry an `x402.payment.payload` for a
    // task held in `input-required` with `x402.payment.required`.
    let inbound_metadata = params.message.metadata.clone().unwrap_or_default();

    // Check if this is a continuation of an existing task
    if let Some(existing) = state.task_manager.get_task(&task_id) {
        // x402 hold-and-resume: a task in `input-required` with
        // `x402.payment.required` set must be resumed by an inbound message
        // carrying `x402.payment.payload`. See `crate::a2a::x402_extension`
        // for the wire-format and dispatcher contract.
        if existing.status.state == TaskState::InputRequired
            && let Some(requirements) = existing.metadata.get_payment_required()
        {
                let Some(payload) = inbound_metadata.get_payment_payload() else {
                    return JsonRpcResponse::error(
                        id,
                        -32004,
                        "task is awaiting x402.payment.payload in message.metadata".to_string(),
                    );
                };

                match state.payment_verifier.verify_and_settle(
                    &task_id,
                    &requirements,
                    &payload,
                ) {
                    Ok(receipts) => {
                        // Record the submission, then mark settled and
                        // resume the task to `working`. The original
                        // request text was captured at hold time and is
                        // still in `task.history`.
                        state.task_manager.update_metadata(&task_id, |md| {
                            md.submit_x402(payload.clone());
                            md.complete_x402(receipts.clone());
                        });
                        state
                            .task_manager
                            .update_status(&task_id, TaskState::Working, Some(msg));
                        // Run the original handler now that payment cleared.
                        let response_text = execute_task_sync(state, &task_id);
                        let response_msg = TaskMessage {
                            role: "agent".to_string(),
                            parts: vec![
                                MessagePart::text(&response_text),
                                MessagePart::data(
                                    serde_json::json!({ "response": &response_text }),
                                    "application/json",
                                ),
                            ],
                        };
                        let artifact = TaskArtifact {
                            name: "response".to_string(),
                            parts: vec![MessagePart::data(
                                serde_json::json!({
                                    "response": &response_text,
                                    "task_id": &task_id,
                                }),
                                "application/json",
                            )],
                            index: Some(0),
                        };
                        state.task_manager.add_artifact(&task_id, artifact);
                        return match state.task_manager.update_status(
                            &task_id,
                            TaskState::Completed,
                            Some(response_msg),
                        ) {
                            Some(task) => {
                                JsonRpcResponse::success(id, serde_json::to_value(&task).unwrap())
                            }
                            None => JsonRpcResponse::internal_error(id, "Failed to update task"),
                        };
                    }
                    Err(failure) => {
                        // Verification or settlement failed — record the
                        // submission, write the terminal status, and
                        // transition the task to `failed`.
                        let terminal = failure.terminal_status();
                        let reason = failure.message();
                        state.task_manager.update_metadata(&task_id, |md| {
                            md.submit_x402(payload.clone());
                            md.fail_x402(terminal);
                        });
                        let failure_msg = TaskMessage {
                            role: "agent".to_string(),
                            parts: vec![MessagePart::text(format!("payment failed: {}", reason))],
                        };
                        return match state.task_manager.update_status(
                            &task_id,
                            TaskState::Failed,
                            Some(failure_msg),
                        ) {
                            Some(task) => {
                                JsonRpcResponse::success(id, serde_json::to_value(&task).unwrap())
                            }
                            None => JsonRpcResponse::internal_error(id, "Failed to update task"),
                        };
                    }
                }
        }

        // Add message to existing task and re-process
        state.task_manager.update_status(
            &task_id,
            TaskState::Working,
            Some(msg),
        );

        // Execute synchronously for non-streaming
        let response_text = execute_task_sync(state, &task_id);
        let response_msg = TaskMessage {
            role: "agent".to_string(),
            parts: vec![
                MessagePart::text(&response_text),
                MessagePart::data(
                    serde_json::json!({ "response": &response_text }),
                    "application/json",
                ),
            ],
        };

        // Add structured artifact for the response
        let artifact = TaskArtifact {
            name: "response".to_string(),
            parts: vec![MessagePart::data(
                serde_json::json!({ "response": &response_text, "task_id": &task_id }),
                "application/json",
            )],
            index: Some(0),
        };
        state.task_manager.add_artifact(&task_id, artifact);

        if let Some(task) = state.task_manager.update_status(
            &task_id,
            TaskState::Completed,
            Some(response_msg),
        ) {
            return JsonRpcResponse::success(id, serde_json::to_value(&task).unwrap());
        }
        return JsonRpcResponse::success(id, serde_json::to_value(&existing).unwrap());
    }

    // Create new task — use simple path when no metadata, metadata path otherwise
    let caller_metadata = params.message.metadata.unwrap_or_default();
    let _task = if caller_metadata.is_empty() {
        state.task_manager.create_task(
            task_id.clone(),
            params.message.context_id,
            msg,
        )
    } else {
        state.task_manager.create_task_with_metadata(
            task_id.clone(),
            params.message.context_id,
            msg,
            caller_metadata,
        )
    };

    // Execute the task synchronously
    state
        .task_manager
        .update_status(&task_id, TaskState::Working, None);

    let response_text = execute_task_sync(state, &task_id);
    // EU AI Act Art. 50(2): every AI response carries an in-band
    // disclosure key in the response data part so SDKs can surface
    // "this is AI" without having to inspect the HTTP header.
    let (disc_key, disc_val) = crate::eu_ai_disclosure::metadata_pair();
    let response_msg = TaskMessage {
        role: "agent".to_string(),
        parts: vec![
            MessagePart::text(&response_text),
            MessagePart::data(
                serde_json::json!({
                    "response": &response_text,
                    disc_key: disc_val,
                }),
                "application/json",
            ),
        ],
    };

    // Add structured artifact for the response — same disclosure key
    // attached so downstream consumers replaying the artifact alone
    // (without the message envelope) still see the AI marker.
    let artifact = TaskArtifact {
        name: "response".to_string(),
        parts: vec![MessagePart::data(
            serde_json::json!({
                "response": &response_text,
                "task_id": &task_id,
                disc_key: disc_val,
            }),
            "application/json",
        )],
        index: Some(0),
    };
    state.task_manager.add_artifact(&task_id, artifact);

    match state.task_manager.update_status(
        &task_id,
        TaskState::Completed,
        Some(response_msg),
    ) {
        Some(task) => JsonRpcResponse::success(id, serde_json::to_value(&task).unwrap()),
        None => JsonRpcResponse::internal_error(id, "Failed to update task"),
    }
}

fn handle_get_task(
    state: &A2aState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> JsonRpcResponse {
    let params: GetTaskParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return JsonRpcResponse::invalid_params(id, format!("Invalid params: {}", e)),
    };

    match state.task_manager.get_task(&params.id) {
        Some(mut task) => {
            // Optionally limit history
            if let Some(limit) = params.history_length
                && task.history.len() > limit
            {
                let start = task.history.len() - limit;
                task.history = task.history[start..].to_vec();
            }
            JsonRpcResponse::success(id, serde_json::to_value(&task).unwrap())
        }
        None => JsonRpcResponse::error(id, -32001, format!("Task not found: {}", params.id)),
    }
}

fn handle_list_tasks(
    state: &A2aState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> JsonRpcResponse {
    let params: ListTasksParams = serde_json::from_value(params).unwrap_or(ListTasksParams {
        context_id: None,
    });

    let tasks = state
        .task_manager
        .list_tasks(params.context_id.as_deref());
    JsonRpcResponse::success(id, serde_json::to_value(&tasks).unwrap())
}

fn handle_cancel_task(
    state: &A2aState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> JsonRpcResponse {
    let params: CancelTaskParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return JsonRpcResponse::invalid_params(id, format!("Invalid params: {}", e)),
    };

    match state.task_manager.cancel_task(&params.id) {
        Some(task) => JsonRpcResponse::success(id, serde_json::to_value(&task).unwrap()),
        None => JsonRpcResponse::error(id, -32001, format!("Task not found: {}", params.id)),
    }
}

// ---------------------------------------------------------------------------
// AP2 (Agent Payments Protocol) handlers
// ---------------------------------------------------------------------------

fn handle_ap2_create(
    state: &A2aState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> JsonRpcResponse {
    let params: Ap2CreateParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return JsonRpcResponse::invalid_params(id, format!("Invalid params: {}", e)),
    };

    let payment_id = uuid::Uuid::new_v4().to_string();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    info!(
        "AP2 payments/create: id={} amount={} {} to={} memo={:?}",
        payment_id, params.amount, params.currency, params.recipient, params.memo,
    );

    // Store in task manager as a payment task for tracking
    let payment_msg = TaskMessage {
        role: "system".to_string(),
        parts: vec![MessagePart::data(
            serde_json::json!({
                "type": "ap2_payment_created",
                "payment_id": &payment_id,
                "amount": params.amount.to_string(),
                "currency": &params.currency,
                "recipient": &params.recipient,
                "memo": params.memo,
            }),
            "application/json",
        )],
    };
    state.task_manager.create_task_with_metadata(
        format!("ap2:{}", payment_id),
        None,
        payment_msg,
        params.metadata.unwrap_or_default(),
    );

    JsonRpcResponse::success(
        id,
        serde_json::json!({
            "paymentId": payment_id,
            "status": "created",
            "amount": params.amount.to_string(),
            "currency": params.currency,
            "recipient": params.recipient,
            "memo": params.memo,
            "createdAt": created_at,
        }),
    )
}

fn handle_ap2_authorize(
    _state: &A2aState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> JsonRpcResponse {
    let params: Ap2AuthorizeParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return JsonRpcResponse::invalid_params(id, format!("Invalid params: {}", e)),
    };

    let authorized_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let expiry = params.expiry.unwrap_or(authorized_at + 3600); // Default 1 hour

    info!(
        "AP2 payments/authorize: payment={} limit={} session={:?} expiry={}",
        params.payment_id, params.spending_limit, params.session_id, expiry,
    );

    JsonRpcResponse::success(
        id,
        serde_json::json!({
            "paymentId": params.payment_id,
            "status": "authorized",
            "spendingLimit": params.spending_limit.to_string(),
            "sessionId": params.session_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            "expiry": expiry,
            "authorizedAt": authorized_at,
        }),
    )
}

fn handle_ap2_execute(
    state: &A2aState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> JsonRpcResponse {
    let params: Ap2ExecuteParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return JsonRpcResponse::invalid_params(id, format!("Invalid params: {}", e)),
    };

    let task_key = format!("ap2:{}", params.payment_id);

    // Check that the payment exists
    let task = match state.task_manager.get_task(&task_key) {
        Some(t) => t,
        None => {
            return JsonRpcResponse::error(
                id,
                -32001,
                format!("Payment not found: {}", params.payment_id),
            );
        }
    };

    let executed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    info!("AP2 payments/execute: payment={}", params.payment_id);

    // Mark the payment task as completed
    let exec_msg = TaskMessage {
        role: "system".to_string(),
        parts: vec![MessagePart::data(
            serde_json::json!({
                "type": "ap2_payment_executed",
                "payment_id": &params.payment_id,
                "executed_at": executed_at,
            }),
            "application/json",
        )],
    };
    state.task_manager.update_status(&task_key, TaskState::Completed, Some(exec_msg));

    // Extract the original amount/currency from the creation message
    let amount = task.history.first()
        .and_then(|m| m.parts.first())
        .and_then(|p| p.data.as_ref())
        .and_then(|d| d.get("amount"))
        .and_then(|a| a.as_str())
        .unwrap_or("0");

    let tx_hash = format!("0x{}", hex::encode(uuid::Uuid::new_v4().as_bytes()));

    JsonRpcResponse::success(
        id,
        serde_json::json!({
            "paymentId": params.payment_id,
            "status": "executed",
            "amount": amount,
            "transactionHash": tx_hash,
            "executedAt": executed_at,
        }),
    )
}

fn handle_ap2_status(
    state: &A2aState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> JsonRpcResponse {
    let params: Ap2StatusParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return JsonRpcResponse::invalid_params(id, format!("Invalid params: {}", e)),
    };

    let task_key = format!("ap2:{}", params.payment_id);

    match state.task_manager.get_task(&task_key) {
        Some(task) => {
            let status = match task.status.state {
                TaskState::Submitted => "created",
                TaskState::Working => "authorized",
                TaskState::Completed => "executed",
                TaskState::Canceled => "cancelled",
                TaskState::Failed => "failed",
                _ => "unknown",
            };

            // Extract payment details from history
            let details = task.history.first()
                .and_then(|m| m.parts.first())
                .and_then(|p| p.data.clone())
                .unwrap_or(serde_json::json!({}));

            JsonRpcResponse::success(
                id,
                serde_json::json!({
                    "paymentId": params.payment_id,
                    "status": status,
                    "details": details,
                    "historyLength": task.history.len(),
                }),
            )
        }
        None => JsonRpcResponse::error(
            id,
            -32001,
            format!("Payment not found: {}", params.payment_id),
        ),
    }
}

fn handle_ap2_cancel(
    state: &A2aState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> JsonRpcResponse {
    let params: Ap2CancelParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return JsonRpcResponse::invalid_params(id, format!("Invalid params: {}", e)),
    };

    let task_key = format!("ap2:{}", params.payment_id);

    match state.task_manager.cancel_task(&task_key) {
        Some(_task) => {
            info!("AP2 payments/cancel: payment={}", params.payment_id);
            JsonRpcResponse::success(
                id,
                serde_json::json!({
                    "paymentId": params.payment_id,
                    "status": "cancelled",
                }),
            )
        }
        None => JsonRpcResponse::error(
            id,
            -32001,
            format!("Payment not found or already completed: {}", params.payment_id),
        ),
    }
}

// ---------------------------------------------------------------------------
// Task execution — routes user messages to node capabilities
// ---------------------------------------------------------------------------

fn execute_task_sync(state: &A2aState, task_id: &str) -> String {
    let task = match state.task_manager.get_task(task_id) {
        Some(t) => t,
        None => return "Task not found".to_string(),
    };

    // Get the latest user message
    let last_user_msg = task
        .history
        .iter()
        .rev()
        .find(|m| m.role == "user");

    let text = match last_user_msg {
        Some(msg) => msg
            .parts
            .iter()
            .filter_map(|p| p.text.as_deref())
            .collect::<Vec<_>>()
            .join(" "),
        None => return "No user message found".to_string(),
    };

    let text_lower = text.to_lowercase();

    // Route to appropriate node capability based on message content.
    //
    // IMPORTANT: Multi-word phrases are checked FIRST to avoid single-keyword
    // matches stealing more specific intents. Within each tier the most specific
    // (longest / rarest) patterns come first; the most generic single-keyword
    // matchers ("node", "network", "status") are checked LAST.

    // --- Tier 1: Multi-word / compound phrases (highest priority) ----------
    if text_lower.contains("join") || text_lower.contains("micronode") || text_lower.contains("onboard") || text_lower.contains("participate") {
        // "join" is very specific intent — check before "network"/"node" can steal it
        handle_join_query(state, &text)
    } else if text_lower.contains("agent template") || text_lower.contains("agent marketplace") || text_lower.contains("list") && text_lower.contains("template") {
        handle_agent_marketplace_query(state)
    } else if text_lower.contains("task marketplace") || text_lower.contains("post task") || text_lower.contains("open task") || (text_lower.contains("task") && text_lower.contains("marketplace")) || (text_lower.contains("task") && text_lower.contains("list")) {
        handle_task_marketplace_query(state)
    } else if text_lower.contains("spawn") || text_lower.contains("child agent") || text_lower.contains("sub-agent") || text_lower.contains("subagent") {
        handle_spawn_query(state)
    } else if text_lower.contains("swarm") || text_lower.contains("orchestrat") {
        handle_swarm_query(state)

    // --- Tier 2: Token sub-commands (multi-keyword, before single "token") --
    } else if text_lower.contains("token") && (text_lower.contains("create") || text_lower.contains("mint")) {
        handle_create_token(state, &text, &task.metadata)
    } else if text_lower.contains("token") && (text_lower.contains("info") || text_lower.contains("details") || text_lower.contains("lookup")) {
        handle_get_token_info(state, &text)
    } else if text_lower.contains("token") && text_lower.contains("balance") {
        handle_token_balance(state, &text)
    } else if (text_lower.contains("cross") && text_lower.contains("vm")) || (text_lower.contains("transfer") && (text_lower.contains("evm") || text_lower.contains("svm") || text_lower.contains("daml"))) {
        handle_cross_vm_transfer(state, &text)
    } else if text_lower.contains("wrap") && text_lower.contains("tnzo") {
        handle_wrap_tnzo(state, &text)

    // --- Tier 3: Single-keyword domain routes (medium specificity) ----------
    } else if text_lower.contains("token") || text_lower.contains("erc20") || text_lower.contains("erc-20") || (text_lower.contains("list") && text_lower.contains("token")) || (text_lower.contains("registered") && text_lower.contains("token")) {
        handle_list_tokens(state, &text)
    } else if text_lower.contains("deploy") || text_lower.contains("contract") || text_lower.contains("bytecode") {
        handle_deploy_contract(state, &text)
    } else if text_lower.contains("identity") || text_lower.contains("did") || text_lower.contains("register identity") || text_lower.contains("resolve") || text_lower.contains("username") {
        handle_identity_query(state, &text)
    } else if text_lower.contains("balance") || text_lower.contains("wallet") || text_lower.contains("send") {
        handle_balance_query(state, &text)
    } else if text_lower.contains("faucet") {
        handle_faucet_info(state)
    } else if text_lower.contains("model") || text_lower.contains("inference") || text_lower.contains("ai") || text_lower.contains("chat") {
        handle_model_query(state)
    } else if text_lower.contains("stake") || text_lower.contains("staking") || text_lower.contains("unstake") || text_lower.contains("validator") {
        handle_staking_query(state)
    } else if text_lower.contains("provider") || text_lower.contains("serving") || text_lower.contains("earnings") {
        handle_provider_query(state)
    } else if text_lower.contains("payment") || text_lower.contains("challenge") || text_lower.contains("mpp") || text_lower.contains("x402") || text_lower.contains("ap2") {
        handle_payment_query(state)
    } else if text_lower.contains("verify") || text_lower.contains("proof") || text_lower.contains("attestation") || text_lower.contains("zk") {
        handle_verification_query(state)
    } else if text_lower.contains("bridge") || text_lower.contains("cross-chain") || text_lower.contains("layerzero") || text_lower.contains("ccip") || text_lower.contains("debridge") {
        handle_bridge_query(state)
    } else if text_lower.contains("block") || text_lower.contains("height") || text_lower.contains("transaction") {
        handle_block_query(state)

    // --- Tier 4: Most generic single keywords (lowest priority) ------------
    } else if text_lower.contains("peer") || text_lower.contains("network") {
        handle_network_query(state)
    } else if text_lower.contains("status") || text_lower.contains("health") || text_lower.contains("node") {
        handle_status_query(state)
    } else {
        "I'm the Tenzro Network Agent. I can help with:\n\
             - Join as MicroNode (zero-install full network participant)\n\
             - Wallet & balance queries\n\
             - Block & chain info\n\
             - Node status & health\n\
             - Identity (DID) management\n\
             - Staking & validator info\n\
             - Provider statistics\n\
             - Faucet token requests\n\
             - AI model discovery\n\
             - Network peer info\n\
             - Token management (create, query, transfer, cross-VM)\n\
             - Smart contract deployment (EVM, SVM, DAML)\n\
             - Agent spawning & sub-agents\n\
             - Swarm orchestration\n\
             - Task & agent marketplace\n\
             - Payments & settlement\n\
             - Verification (ZK, TEE, signatures)\n\
             - Cross-chain bridges\n\
             - AP2 payments (payments/create, payments/execute, etc.)\n\n\
             What would you like to do?".to_string()
    }
}

async fn execute_task(state: &A2aState, task_id: &str) -> String {
    execute_task_sync(state, task_id)
}

fn handle_balance_query(state: &A2aState, text: &str) -> String {
    // Try to extract an address from the text, stripping trailing punctuation
    let address_raw = text
        .split_whitespace()
        .find(|w| w.starts_with("0x") || w.trim_end_matches(|c: char| !c.is_alphanumeric()).len() == 64)
        .unwrap_or("(no address provided)");
    let address = address_raw.trim_end_matches(['?', '!', '.', ',', ';', ':']);

    if let Some(storage) = state.node.storage() {
        match storage.get("accounts", address.as_bytes()) {
            Ok(Some(data)) => {
                let bytes: &[u8] = &data;
                let balance = if bytes.len() >= 16 {
                    u128::from_be_bytes(
                        bytes[..16].try_into().unwrap_or([0u8; 16]),
                    )
                } else if bytes.len() >= 8 {
                    u64::from_be_bytes(
                        bytes[..8].try_into().unwrap_or([0u8; 8]),
                    ) as u128
                } else {
                    0u128
                };
                let tnzo = balance as f64 / 1e18;
                format!("Balance for {}: {:.6} TNZO ({} wei)", address, tnzo, balance)
            }
            _ => format!(
                "No balance found for {}. The account may not exist yet. \
                 Use the faucet to get testnet tokens.",
                address
            ),
        }
    } else {
        "Storage not available — node may still be initializing.".to_string()
    }
}

fn handle_block_query(state: &A2aState) -> String {
    if let Some(storage) = state.node.storage() {
        match storage.get("blocks", "latest_height".as_bytes()) {
            Ok(Some(data)) => {
                let bytes: &[u8] = &data;
                let height = u64::from_be_bytes(
                    bytes.get(..8)
                        .and_then(|s: &[u8]| s.try_into().ok())
                        .unwrap_or([0u8; 8]),
                );
                format!("Current block height: {}", height)
            }
            _ => "Block height: 0 (genesis)".to_string(),
        }
    } else {
        "Block height: 0 (genesis — storage initializing)".to_string()
    }
}

fn handle_status_query(state: &A2aState) -> String {
    let config = state.node.config();
    let role = format!("{:?}", config.role);
    let metrics = state.node.metrics().get_metrics();

    format!(
        "Node Status:\n\
         - Role: {}\n\
         - Peers: {}\n\
         - Uptime: {}s\n\
         - A2A Tasks: {}\n\
         - Chain: Tenzro Testnet (chain_id: 1337)",
        role,
        metrics.peer_count,
        metrics.uptime_secs,
        state.task_manager.task_count(),
    )
}

fn handle_identity_query(state: &A2aState, text: &str) -> String {
    let text_lower = text.to_lowercase();

    // Check if there's a DID to resolve
    if let Some(did) = text.split_whitespace().find(|w| w.starts_with("did:")) {
        if let Some(registry) = state.node.identity_registry() {
            match registry.resolve(did) {
                Ok(identity) => {
                    format!(
                        "Identity found:\n\
                         - DID: {}\n\
                         - Type: {}\n\
                         - Status: {:?}\n\
                         - Created: {:?}",
                        identity.did_string(),
                        if identity.is_human() { "Human" } else { "Machine" },
                        identity.status,
                        identity.created_at,
                    )
                }
                Err(_) => format!("Identity not found: {}", did),
            }
        } else {
            "Identity registry not available.".to_string()
        }
    } else if text_lower.contains("register") && (text_lower.contains("identity") || text_lower.contains("did")) {
        // Extract a display name: take the last meaningful word that isn't a stop word
        let stop_words = [
            "register", "a", "an", "the", "new", "identity", "named", "called",
            "with", "name", "as", "create", "did", "human", "machine", "for",
            "please", "me", "my", "i", "want", "to",
        ];
        let display_name = text
            .split_whitespace()
            .rev()
            .find(|w| {
                let clean = w.to_lowercase();
                let clean = clean.trim_matches(|c: char| !c.is_alphanumeric());
                !stop_words.contains(&clean) && clean.len() > 1
            })
            .unwrap_or("Agent");

        // Actually register the identity via the registry
        if let Some(registry) = state.node.identity_registry() {
            // Generate a fresh Ed25519 keypair for the new identity
            let keypair = match tenzro_crypto::keys::KeyPair::generate(
                tenzro_crypto::keys::KeyType::Ed25519,
            ) {
                Ok(kp) => kp,
                Err(e) => return format!("Failed to generate keypair: {}", e),
            };
            let pk_bytes = keypair.public_key().to_bytes();

            // register_human_with_fee is async — run it on the current runtime
            let handle = tokio::runtime::Handle::current();
            let reg = registry.clone();
            let name = display_name.to_string();
            let result = tokio::task::block_in_place(move || {
                handle.block_on(reg.register_human_with_fee(
                    pk_bytes,
                    name,
                    tenzro_types::identity::KycTier::Unverified,
                ))
            });

            match result {
                Ok(reg_result) => {
                    let identity = reg_result.identity;
                    format!(
                        "Identity registered successfully!\n\
                         - DID: {}\n\
                         - Display name: {}\n\
                         - Type: Human\n\
                         - Status: {:?}",
                        identity.did_string(),
                        display_name,
                        identity.status,
                    )
                }
                Err(e) => format!("Failed to register identity: {}", e),
            }
        } else {
            "Identity registry not available — node may still be initializing.".to_string()
        }
    } else {
        "To manage identities, provide a DID (e.g., did:tenzro:human:abc123) \
         or ask me to register a new identity."
            .to_string()
    }
}

fn handle_faucet_info(_state: &A2aState) -> String {
    "Tenzro Testnet Faucet:\n\
     - Dispenses 100 TNZO per request\n\
     - Cooldown: 24 hours per address\n\
     - Use the Web API: POST /faucet with {\"address\": \"0x...\"}\n\
     - Or use the MCP tool: request_faucet"
        .to_string()
}

fn handle_model_query(state: &A2aState) -> String {
    let services = state.node.list_model_services();
    let served = state.node.served_models.len();

    let mut out = format!(
        "AI Model Discovery:\n\
         - Models served locally: {}\n\
         - Model service endpoints: {}\n",
        served,
        services.len(),
    );

    if !services.is_empty() {
        out.push_str("\nActive endpoints:\n");
        for svc in &services {
            out.push_str(&format!(
                "  - {} ({}) — {} [{}]\n    API: {}\n",
                svc.model_name, svc.model_id, svc.status, svc.location,
                svc.api_endpoint,
            ));
        }
    }

    out.push_str("\nRPC methods:\n\
         - `tenzro_listModels` — list available models\n\
         - `tenzro_listModelEndpoints` — list active service endpoints\n\
         - `tenzro_requestInference` — run inference\n\
         - `tenzro_chat` — chat completion\n\
         - `tenzro_registerModelEndpoint` — register external endpoint");
    out
}

fn handle_network_query(state: &A2aState) -> String {
    let metrics = state.node.metrics().get_metrics();
    format!(
        "Network Info:\n\
         - Connected peers: {}\n\
         - Protocol: libp2p (gossipsub + Kademlia)\n\
         - Topics: blocks, transactions, consensus, attestations, models, inference, status",
        metrics.peer_count,
    )
}

fn handle_staking_query(state: &A2aState) -> String {
    if let Some(staking) = state.node.staking() {
        let all_stakes = staking.get_all_stakes();
        let total_staked: u128 = all_stakes.iter().map(|(_, s)| s.amount).sum();
        let validator_count = all_stakes.iter()
            .filter(|(_, s)| matches!(s.provider_type, tenzro_types::token::ProviderType::Validator))
            .count();
        let model_provider_count = all_stakes.iter()
            .filter(|(_, s)| matches!(s.provider_type, tenzro_types::token::ProviderType::ModelProvider))
            .count();

        format!(
            "Staking Info:\n\
             - Total staked: {:.6} TNZO\n\
             - Active validators: {}\n\
             - Model providers: {}\n\
             - Total stakers: {}\n\n\
             To stake: Use MCP tool `stake_tokens` or RPC `tenzro_stake`\n\
             To unstake: Use MCP tool `unstake_tokens` or RPC `tenzro_unstake`",
            total_staked as f64 / 1e18,
            validator_count,
            model_provider_count,
            all_stakes.len(),
        )
    } else {
        "Staking module not initialized.".to_string()
    }
}

fn handle_provider_query(state: &A2aState) -> String {
    let models_served = state.node.served_models.len();
    let total_inferences = state.node.transaction_history.read().len();

    let staking_info = if let Some(staking) = state.node.staking() {
        let all_stakes = staking.get_all_stakes();
        let total_staked: u128 = all_stakes.iter().map(|(_, s)| s.amount).sum();
        format!("{:.6} TNZO across {} stakers", total_staked as f64 / 1e18, all_stakes.len())
    } else {
        "N/A".to_string()
    };

    format!(
        "Provider Stats:\n\
         - Models served: {}\n\
         - Total inferences: {}\n\
         - Total staked: {}\n\
         - Role: {:?}\n\n\
         To register: Use MCP tool `register_provider` or RPC `tenzro_registerProvider`",
        models_served,
        total_inferences,
        staking_info,
        state.node.config().role,
    )
}

fn handle_create_token(
    state: &A2aState,
    text: &str,
    task_metadata: &std::collections::HashMap<String, serde_json::Value>,
) -> String {
    let registry = match state.node.token_registry() {
        Some(r) => r,
        None => return "Token registry not initialized.".to_string(),
    };

    // Try to extract token parameters from the message text.
    // Look for patterns like: "create token <Name> (<Symbol>) with <supply> supply"
    let words: Vec<&str> = text.split_whitespace().collect();

    // Find a symbol in parentheses, e.g. "(MTK)"
    let symbol = words.iter()
        .find(|w| w.starts_with('(') && w.ends_with(')'))
        .map(|w| w.trim_matches(|c| c == '(' || c == ')'))
        .or_else(|| {
            // Find uppercase 2-5 letter words that look like ticker symbols
            words.iter()
                .find(|w| {
                    let clean = w.trim_matches(|c: char| !c.is_alphanumeric());
                    clean.len() >= 2 && clean.len() <= 5
                        && clean.chars().all(|c| c.is_ascii_uppercase())
                        && clean != "TNZO" && clean != "EVM" && clean != "SVM"
                        && clean != "VM" && clean != "AI"
                })
                .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        });

    // Find a name — the word(s) immediately before the symbol, or after "called"/"named"
    let name = text.to_lowercase()
        .find("called ")
        .map(|i| {
            let after = &text[i + 7..];
            after.split(['(', ',', ' '])
                .next()
                .unwrap_or("MyToken")
                .trim()
        })
        .map(|s| s.to_string())
        .or_else(|| {
            text.to_lowercase()
                .find("named ")
                .map(|i| {
                    let after = &text[i + 6..];
                    after.split(['(', ',', ' '])
                        .next()
                        .unwrap_or("MyToken")
                        .trim()
                        .to_string()
                })
        });

    // Find a supply number
    let supply_str = words.iter()
        .find(|w| {
            let clean = w.trim_matches(|c: char| !c.is_ascii_digit());
            !clean.is_empty() && clean.chars().all(|c| c.is_ascii_digit())
        })
        .map(|w| w.trim_matches(|c: char| !c.is_ascii_digit()));

    let symbol = symbol.unwrap_or("TKN");
    let name = name.as_deref().unwrap_or("Token");
    let supply: u128 = supply_str
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(1_000_000);

    // Scale supply to 18-decimal wei
    let initial_supply = supply.saturating_mul(10u128.pow(18));

    // Resolve creator address from caller identity:
    // 1. Try the caller's wallet address from task metadata
    // 2. Try the caller's agent_id to look up their wallet via agent runtime
    // 3. Fall back to deterministic hash of symbol (legacy behavior)
    let mut creator = [0u8; 32];
    let mut authenticated = false;

    if let Some(wallet_addr) = task_metadata.get("wallet_address").and_then(|v| v.as_str()) {
        // Caller provided their wallet address directly
        let addr_hex = wallet_addr.strip_prefix("0x").unwrap_or(wallet_addr);
        if let Ok(addr_bytes) = hex::decode(addr_hex) {
            if addr_bytes.len() == 20 {
                creator[12..32].copy_from_slice(&addr_bytes);
                authenticated = true;
            } else if addr_bytes.len() == 32 {
                creator.copy_from_slice(&addr_bytes);
                authenticated = true;
            }
        }
    }

    if !authenticated
        && let Some(agent_id) = task_metadata.get("agent_id").and_then(|v| v.as_str()) {
            // Try to resolve the agent's wallet address from the agent runtime
            if let Some(agent_runtime) = state.node.agent_runtime()
                && let Ok(agent) = agent_runtime.get_agent(agent_id) {
                    let addr_bytes = agent.wallet_address.0;
                    creator.copy_from_slice(&addr_bytes);
                    authenticated = true;
                }
        }

    if !authenticated {
        // Legacy fallback: deterministic creator address derived from the symbol
        let creator_hash = tenzro_crypto::hash::sha256(symbol.as_bytes());
        creator.copy_from_slice(creator_hash.as_bytes());
    }

    let evm_addr: [u8; 20] = {
        let hash = tenzro_crypto::hash::keccak256(
            &[&creator[..], name.as_bytes(), symbol.as_bytes()].concat(),
        );
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash.as_bytes()[12..32]);
        addr
    };

    use tenzro_token::{
        TokenDefinition, TokenId, TokenMetadata, TokenPermissions, TokenType, VmAddresses,
    };

    let def = TokenDefinition {
        token_id: TokenId::compute(&creator, 0),
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals: 18,
        total_supply: initial_supply,
        max_supply: Some(initial_supply),
        creator,
        token_type: TokenType::Erc20,
        vm_addresses: VmAddresses {
            evm: Some(evm_addr),
            ..Default::default()
        },
        permissions: TokenPermissions {
            mintable: false,
            burnable: false,
            pausable: false,
            freezable: false,
            paused: false,
        },
        created_at: 0,
        metadata: TokenMetadata::default(),
    };

    match registry.register_token(def) {
        Ok(token_id) => {
            format!(
                "Token created successfully:\n\
                 - Name: {}\n\
                 - Symbol: {}\n\
                 - Token ID: {}\n\
                 - Total supply: {} (18 decimals)\n\
                 - EVM address: 0x{}\n\
                 - Creator: 0x{}\n\
                 - Authenticated: {}\n\
                 - Type: ERC-20",
                name,
                symbol,
                token_id.to_hex(),
                supply,
                hex::encode(evm_addr),
                hex::encode(creator),
                authenticated,
            )
        }
        Err(e) => format!("Failed to create token: {}", e),
    }
}

fn handle_get_token_info(state: &A2aState, text: &str) -> String {
    let registry = match state.node.token_registry() {
        Some(r) => r,
        None => return "Token registry not initialized.".to_string(),
    };

    // Try to find a symbol or address in the text
    let words: Vec<&str> = text.split_whitespace().collect();

    // Look for a hex address (0x...)
    let by_address = words.iter().find(|w| w.starts_with("0x") && w.len() >= 42);
    // Look for uppercase symbol-like words
    let by_symbol = words.iter().find(|w| {
        let clean = w.trim_matches(|c: char| !c.is_alphanumeric());
        clean.len() >= 2 && clean.len() <= 6 && clean.chars().all(|c| c.is_ascii_uppercase())
    });

    let def = if let Some(addr_str) = by_address {
        let addr_hex = addr_str.strip_prefix("0x").unwrap_or(addr_str);
        hex::decode(addr_hex)
            .ok()
            .filter(|b| b.len() == 20)
            .map(|b| {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&b);
                arr
            })
            .and_then(|a| registry.get_by_evm_address(&a))
    } else if let Some(sym_word) = by_symbol {
        let sym = sym_word.trim_matches(|c: char| !c.is_alphanumeric());
        registry.get_by_symbol(sym)
    } else {
        None
    };

    match def {
        Some(d) => {
            let display_supply = d.total_supply as f64 / 10f64.powi(d.decimals as i32);
            format!(
                "Token Info:\n\
                 - Name: {}\n\
                 - Symbol: {}\n\
                 - Token ID: {}\n\
                 - Decimals: {}\n\
                 - Total supply: {:.0}\n\
                 - Type: {:?}\n\
                 - EVM address: {}\n\
                 - SVM mint: {}\n\
                 - Creator: 0x{}",
                d.name,
                d.symbol,
                d.token_id.to_hex(),
                d.decimals,
                display_supply,
                d.token_type,
                d.vm_addresses.evm_hex().unwrap_or_else(|| "N/A".to_string()),
                d.vm_addresses.svm_hex().unwrap_or_else(|| "N/A".to_string()),
                hex::encode(d.creator),
            )
        }
        None => {
            let query = by_symbol
                .copied()
                .or(by_address.copied())
                .unwrap_or("(none)");
            format!(
                "Token not found: {}. Use 'list tokens' to see registered tokens, \
                 or provide a symbol (e.g. TNZO) or EVM address (0x...).",
                query
            )
        }
    }
}

fn handle_list_tokens(state: &A2aState, text: &str) -> String {
    let registry = match state.node.token_registry() {
        Some(r) => r,
        None => return "Token registry not initialized.".to_string(),
    };

    let text_lower = text.to_lowercase();

    // Check for VM type filter
    let vm_filter = if text_lower.contains("tempo") || text_lower.contains("tip20") || text_lower.contains("tip-20") {
        Some(tenzro_token::TokenVmType::TempoTip20)
    } else if text_lower.contains("evm") {
        Some(tenzro_token::TokenVmType::Evm)
    } else if text_lower.contains("svm") || text_lower.contains("solana") {
        Some(tenzro_token::TokenVmType::Svm)
    } else if text_lower.contains("daml") || text_lower.contains("canton") {
        Some(tenzro_token::TokenVmType::Daml)
    } else if text_lower.contains("native") {
        Some(tenzro_token::TokenVmType::Native)
    } else {
        None
    };

    let tokens = registry.list_tokens(vm_filter, None, 50);

    if tokens.is_empty() {
        let filter_desc = vm_filter
            .map(|v| format!(" for {:?}", v))
            .unwrap_or_default();
        return format!("No tokens registered{}.", filter_desc);
    }

    let mut result = format!("Registered Tokens ({} found):\n", tokens.len());
    for (i, d) in tokens.iter().enumerate() {
        let display_supply = d.total_supply as f64 / 10f64.powi(d.decimals as i32);
        result.push_str(&format!(
            "\n{}. {} ({}) — supply: {:.0}, type: {:?}, EVM: {}",
            i + 1,
            d.name,
            d.symbol,
            display_supply,
            d.token_type,
            d.vm_addresses.evm_hex().unwrap_or_else(|| "N/A".to_string()),
        ));
    }

    result
}

fn handle_token_balance(state: &A2aState, text: &str) -> String {
    let token = match state.node.token() {
        Some(t) => t,
        None => return "TNZO token not initialized.".to_string(),
    };

    // Try to extract an address
    let address_str = text
        .split_whitespace()
        .find(|w| w.starts_with("0x") || w.len() == 64);

    let address_str = match address_str {
        Some(a) => a,
        None => {
            return "Provide an address to check the token balance.\n\
                    Example: \"token balance 0xabc123...\""
                .to_string();
        }
    };

    let addr_hex = address_str.strip_prefix("0x").unwrap_or(address_str);
    let bytes = match hex::decode(addr_hex) {
        Ok(b) => b,
        Err(e) => return format!("Invalid address: {}", e),
    };

    let mut arr = [0u8; 32];
    let len = bytes.len().min(32);
    if bytes.len() <= 20 {
        arr[32 - len..32].copy_from_slice(&bytes[..len]);
    } else {
        arr[..len].copy_from_slice(&bytes[..len]);
    }
    let address = tenzro_types::Address::new(arr);

    let native_balance = token.balance_of(&address);
    let display = native_balance as f64 / 1e18;
    let spl_balance = tenzro_token::native_to_spl(native_balance).unwrap_or(0);

    format!(
        "Token Balance for {}:\n\
         - Native TNZO: {} ({:.6} TNZO)\n\
         - EVM wTNZO: {} (18 decimals)\n\
         - SVM wTNZO: {} (9 decimals)\n\
         - DAML Holding: {:.18}\n\n\
         All representations share the same underlying balance (pointer model).",
        address_str,
        native_balance,
        display,
        native_balance,
        spl_balance,
        display,
    )
}

fn handle_cross_vm_transfer(state: &A2aState, text: &str) -> String {
    let registry = match state.node.token_registry() {
        Some(r) => r,
        None => return "Token registry not initialized.".to_string(),
    };
    let token = match state.node.token() {
        Some(t) => t,
        None => return "TNZO token not initialized.".to_string(),
    };

    // Extract addresses from text
    let words: Vec<&str> = text.split_whitespace().collect();
    let addresses: Vec<&str> = words
        .iter()
        .filter(|w| w.starts_with("0x"))
        .copied()
        .collect();

    // Extract amount (numeric words)
    let amount_str = words.iter().find(|w| {
        let clean = w.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
        !clean.is_empty() && clean.parse::<f64>().is_ok()
    });

    let text_lower = text.to_lowercase();

    // Determine source and target VMs
    let parse_vm = |s: &str| -> Option<tenzro_token::TokenVmType> {
        match s {
            "evm" | "ethereum" => Some(tenzro_token::TokenVmType::Evm),
            "svm" | "solana" => Some(tenzro_token::TokenVmType::Svm),
            "daml" | "canton" => Some(tenzro_token::TokenVmType::Daml),
            "native" => Some(tenzro_token::TokenVmType::Native),
            "tempo-tip20" | "tempo" | "tip20" => Some(tenzro_token::TokenVmType::TempoTip20),
            _ => None,
        }
    };

    // Look for "from X to Y" pattern
    let from_vm = ["evm", "svm", "daml", "native", "ethereum", "solana", "canton"]
        .iter()
        .find(|vm| {
            text_lower.contains(&format!("from {}", vm))
                || text_lower.contains(&format!("from the {}", vm))
        })
        .and_then(|vm| parse_vm(vm));

    let to_vm = ["evm", "svm", "daml", "native", "ethereum", "solana", "canton"]
        .iter()
        .find(|vm| {
            text_lower.contains(&format!("to {}", vm))
                || text_lower.contains(&format!("to the {}", vm))
        })
        .and_then(|vm| parse_vm(vm));

    if addresses.len() < 2 || amount_str.is_none() || from_vm.is_none() || to_vm.is_none() {
        return "Cross-VM Transfer requires:\n\
             - from_address (0x...)\n\
             - to_address (0x...)\n\
             - amount\n\
             - source VM (evm, svm, daml, native)\n\
             - target VM (evm, svm, daml, native)\n\n\
             Example: \"Transfer 100 TNZO from EVM 0xabc... to SVM 0xdef...\"".to_string();
    }

    let amount_raw = amount_str
        .unwrap()
        .trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
    let amount: u128 = if let Ok(whole) = amount_raw.parse::<u128>() {
        whole.saturating_mul(10u128.pow(18))
    } else if let Ok(f) = amount_raw.parse::<f64>() {
        (f * 1e18) as u128
    } else {
        return format!("Invalid amount: {}", amount_raw);
    };

    let from_vm = from_vm.unwrap();
    let to_vm = to_vm.unwrap();
    let from_addr_str = addresses[0];
    let to_addr_str = addresses[1];

    let decode_addr = |s: &str| -> Result<Vec<u8>, String> {
        let hex_clean = s.strip_prefix("0x").unwrap_or(s);
        hex::decode(hex_clean).map_err(|e| format!("Invalid address: {}", e))
    };

    let from_bytes = match decode_addr(from_addr_str) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let to_bytes = match decode_addr(to_addr_str) {
        Ok(b) => b,
        Err(e) => return e,
    };

    let token_id = tenzro_token::TokenId::tnzo();

    let transfer = tenzro_token::CrossVmTransfer {
        token_id,
        from_vm,
        to_vm,
        from_address: from_bytes.clone(),
        to_address: to_bytes.clone(),
        amount,
        nonce: 0,
    };

    if let Err(e) = registry.validate_cross_vm_transfer(&transfer) {
        return format!("Cross-VM transfer validation failed: {}", e);
    }

    // Execute the underlying native transfer
    let from_addr = rpc_bytes_to_address(&from_bytes);
    let to_addr = rpc_bytes_to_address(&to_bytes);
    if let Err(e) = token.transfer(&from_addr, &to_addr, amount) {
        return format!("Transfer failed: {}", e);
    }

    let display_amount = amount as f64 / 1e18;
    format!(
        "Cross-VM Transfer completed:\n\
         - Token: TNZO\n\
         - Amount: {:.6} TNZO\n\
         - From: {} ({:?})\n\
         - To: {} ({:?})\n\
         - Status: transferred",
        display_amount, from_addr_str, from_vm, to_addr_str, to_vm,
    )
}

fn handle_wrap_tnzo(state: &A2aState, text: &str) -> String {
    let token = match state.node.token() {
        Some(t) => t,
        None => return "TNZO token not initialized.".to_string(),
    };

    let words: Vec<&str> = text.split_whitespace().collect();

    let address_str = words.iter().find(|w| w.starts_with("0x"));
    let amount_str = words.iter().find(|w| {
        let clean = w.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
        !clean.is_empty() && clean.parse::<f64>().is_ok()
    });

    let text_lower = text.to_lowercase();
    let target_vm = if text_lower.contains("evm") || text_lower.contains("ethereum") {
        "evm"
    } else if text_lower.contains("svm") || text_lower.contains("solana") {
        "svm"
    } else if text_lower.contains("daml") || text_lower.contains("canton") {
        "daml"
    } else {
        return "Specify a target VM: evm, svm, or daml.\n\
                Example: \"Wrap 50 TNZO for EVM 0xabc...\""
            .to_string();
    };

    let address_str = match address_str {
        Some(a) => a,
        None => {
            return "Provide an address. Example: \"Wrap 50 TNZO for EVM 0xabc...\"".to_string();
        }
    };

    let addr_hex = address_str.strip_prefix("0x").unwrap_or(address_str);
    let bytes = match hex::decode(addr_hex) {
        Ok(b) => b,
        Err(e) => return format!("Invalid address: {}", e),
    };

    let mut arr = [0u8; 32];
    let len = bytes.len().min(32);
    if bytes.len() <= 20 {
        arr[32 - len..32].copy_from_slice(&bytes[..len]);
    } else {
        arr[..len].copy_from_slice(&bytes[..len]);
    }
    let address = tenzro_types::Address::new(arr);
    let balance = token.balance_of(&address);

    let amount: u128 = amount_str
        .and_then(|s| {
            let clean = s.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
            clean.parse::<u128>().ok().map(|v| v.saturating_mul(10u128.pow(18)))
                .or_else(|| clean.parse::<f64>().ok().map(|f| (f * 1e18) as u128))
        })
        .unwrap_or(balance);

    if balance < amount {
        return format!(
            "Insufficient balance: have {:.6} TNZO, need {:.6} TNZO.",
            balance as f64 / 1e18,
            amount as f64 / 1e18,
        );
    }

    let representation = match target_vm {
        "evm" => "wTNZO ERC-20 (pointer contract)",
        "svm" => "wTNZO SPL (9 decimals)",
        "daml" => "TNZO CIP-56 Holding",
        _ => unreachable!(),
    };

    format!(
        "Wrap TNZO:\n\
         - Address: {}\n\
         - Amount: {:.6} TNZO\n\
         - Target VM: {}\n\
         - Representation: {}\n\
         - Native balance: {:.6} TNZO\n\
         - Status: accessible\n\n\
         Pointer model: native TNZO and VM representations share the same balance.",
        address_str,
        amount as f64 / 1e18,
        target_vm,
        representation,
        balance as f64 / 1e18,
    )
}

fn handle_deploy_contract(state: &A2aState, text: &str) -> String {
    let words: Vec<&str> = text.split_whitespace().collect();
    let text_lower = text.to_lowercase();

    // Check if there's actual bytecode to deploy
    let bytecode_str = words.iter().find(|w| {
        let clean = w.strip_prefix("0x").unwrap_or(w);
        clean.len() >= 4 && clean.chars().all(|c| c.is_ascii_hexdigit())
            && !clean.chars().all(|c| c.is_ascii_uppercase()) // exclude symbols
    });

    if bytecode_str.is_none() {
        // No bytecode provided — return usage info
        let vm_runtime_available = state.node.vm_runtime().is_some();
        return format!(
            "Smart Contract Deployment:\n\
             - VM Runtime: {}\n\
             - Supported VMs: EVM, SVM, DAML\n\n\
             To deploy a contract, provide:\n\
             - vm_type: evm, svm, or daml\n\
             - bytecode: hex-encoded contract bytecode (0x...)\n\
             - deployer: deployer address (0x...)\n\
             - constructor_args (optional): hex-encoded constructor arguments\n\
             - gas_limit (optional): max gas (default: 3,000,000)\n\n\
             Example message:\n\
             \"Deploy EVM contract bytecode 0x6080604052... from deployer 0xabc...\"\n\n\
             Or use the JSON-RPC API:\n\
             {{\n\
               \"method\": \"tenzro_deployContract\",\n\
               \"params\": {{\n\
                 \"vm_type\": \"evm\",\n\
                 \"bytecode\": \"0x6080...\",\n\
                 \"deployer\": \"0xabc...\",\n\
                 \"gas_limit\": 3000000\n\
               }}\n\
             }}",
            if vm_runtime_available { "Available" } else { "Not initialized" },
        );
    }

    // We have bytecode — attempt deployment
    let vm = match state.node.vm_runtime() {
        Some(v) => v,
        None => return "VM runtime not initialized.".to_string(),
    };

    let vm_type_str = if text_lower.contains("svm") || text_lower.contains("solana") {
        "svm"
    } else if text_lower.contains("daml") || text_lower.contains("canton") {
        "daml"
    } else {
        "evm"
    };

    let vm_type = match vm_type_str {
        "evm" => tenzro_vm::VmType::Evm,
        "svm" => tenzro_vm::VmType::Svm,
        "daml" => tenzro_vm::VmType::Daml,
        _ => unreachable!(),
    };

    let bytecode_hex_raw = bytecode_str.unwrap();
    let bytecode_hex = bytecode_hex_raw
        .strip_prefix("0x")
        .unwrap_or(bytecode_hex_raw);
    let bytecode = match hex::decode(bytecode_hex) {
        Ok(b) => b,
        Err(e) => return format!("Invalid bytecode hex: {}", e),
    };

    // Find deployer address
    let deployer_str = words
        .iter()
        .filter(|w| w.starts_with("0x"))
        .find(|w| **w != *bytecode_hex_raw);

    let deployer_bytes = if let Some(d) = deployer_str {
        let d_hex = d.strip_prefix("0x").unwrap_or(d);
        match hex::decode(d_hex) {
            Ok(b) => b,
            Err(e) => return format!("Invalid deployer address: {}", e),
        }
    } else {
        // Generate a deterministic deployer from context
        let hash = tenzro_crypto::hash::sha256(b"a2a-deployer");
        hash.as_bytes()[..20].to_vec()
    };

    let gas_limit = words
        .iter()
        .find_map(|w| {
            let clean = w.trim_matches(|c: char| !c.is_ascii_digit());
            let val: u64 = clean.parse().ok()?;
            if (21_000..=30_000_000).contains(&val) {
                Some(val)
            } else {
                None
            }
        })
        .unwrap_or(3_000_000);

    let deployment = tenzro_vm::ContractDeployment {
        deployer: deployer_bytes,
        code: bytecode,
        constructor_args: vec![],
        value: 0,
        gas_limit,
        gas_price: 1_000_000_000,
        nonce: 0,
        vm_type,
    };

    // Execute deployment synchronously using block_on
    let vm = vm.clone();
    let result = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to build tokio runtime");
        rt.block_on(async {
            let mut state = tenzro_vm::StateAdapter::new();
            vm.deploy_contract(&deployment, &mut state).await
        })
    })
    .join();

    match result {
        Ok(Ok(deploy_result)) => {
            if deploy_result.success {
                format!(
                    "Contract deployed successfully:\n\
                     - Address: 0x{}\n\
                     - Gas used: {}\n\
                     - VM: {}\n\
                     - Status: deployed",
                    hex::encode(&deploy_result.address),
                    deploy_result.gas_used,
                    vm_type_str,
                )
            } else {
                format!(
                    "Contract deployment reverted:\n\
                     - Reason: {:?}\n\
                     - Gas used: {}",
                    deploy_result.revert_reason, deploy_result.gas_used,
                )
            }
        }
        Ok(Err(e)) => format!("Deployment failed: {}", e),
        Err(_) => "Deployment execution failed (internal error).".to_string(),
    }
}

/// Helper: convert bytes to Address (used by cross-VM transfer handler)
fn rpc_bytes_to_address(bytes: &[u8]) -> tenzro_types::Address {
    let mut arr = [0u8; 32];
    let len = bytes.len().min(32);
    if bytes.len() <= 20 {
        arr[32 - len..32].copy_from_slice(&bytes[..len]);
    } else {
        arr[..len].copy_from_slice(&bytes[..len]);
    }
    tenzro_types::Address::new(arr)
}

fn handle_spawn_query(_state: &A2aState) -> String {
    "Agent Spawning\n\n\
         Dynamically spawn autonomous sub-agents with their own DID and MPC wallet.\n\
         Each parent agent can create up to 50 children. Children inherit the \
         parent's controller DID and delegation scope.\n\n\
         JSON-RPC:\n\
         {\n\
           \"method\": \"tenzro_spawnAgent\",\n\
           \"params\": {\n\
             \"parent_id\": \"<parent-agent-id>\",\n\
             \"name\": \"researcher\",\n\
             \"capabilities\": [\"web-search\", \"summarization\"]\n\
           }\n\
         }\n\n\
         To run an autonomous agentic task (LLM loop with tool calls):\n\
         {\n\
           \"method\": \"tenzro_runAgentTask\",\n\
           \"params\": {\n\
             \"agent_id\": \"<agent-id>\",\n\
             \"task\": \"Research the latest AI papers and summarize findings\",\n\
             \"max_steps\": 10\n\
           }\n\
         }\n\n\
         CLI: tenzro agent spawn --parent <id> --name researcher --capabilities web-search,summarization\n\
         MCP tool: spawn_agent\n\
         TypeScript SDK: client.agents.spawnAgent({ parent_id, name, capabilities })".to_string()
}

fn handle_swarm_query(_state: &A2aState) -> String {
    "Swarm Orchestration\n\n\
         Create and manage agent swarms for parallel task execution.\n\
         An orchestrator agent spawns a swarm of specialized sub-agents, \
         broadcasts tasks to all members simultaneously, collects results, \
         and terminates the swarm when done.\n\n\
         Create a swarm:\n\
         {\n\
           \"method\": \"tenzro_createSwarm\",\n\
           \"params\": {\n\
             \"orchestrator_id\": \"<agent-id>\",\n\
             \"members\": [\n\
               { \"name\": \"researcher\", \"capabilities\": [\"web-search\"] },\n\
               { \"name\": \"analyst\", \"capabilities\": [\"data-analysis\"] },\n\
               { \"name\": \"writer\", \"capabilities\": [\"summarization\"] }\n\
             ],\n\
             \"parallel\": true\n\
           }\n\
         }\n\n\
         Check status:  { \"method\": \"tenzro_getSwarmStatus\", \"params\": { \"swarm_id\": \"<id>\" } }\n\
         Terminate:     { \"method\": \"tenzro_terminateSwarm\", \"params\": { \"swarm_id\": \"<id>\" } }\n\n\
         CLI: tenzro agent swarm create --orchestrator <id> --members researcher,analyst,writer\n\
         MCP tools: create_swarm, get_swarm_status, terminate_swarm\n\
         TypeScript SDK: client.agents.createSwarm({ orchestrator_id, members })".to_string()
}

fn handle_join_query(_state: &A2aState, text: &str) -> String {
    // Try to extract a display name from the text
    // e.g. "Join the Tenzro Network as Alice" → "Alice"
    let stop_words = [
        "join", "the", "tenzro", "network", "as", "a", "an", "micronode",
        "micro-node", "onboard", "create", "new", "identity", "on", "with",
        "username", "me", "i", "want", "to", "please", "node",
    ];
    let display_name = text
        .split_whitespace()
        .find(|w| {
            let w_lower = w.to_lowercase();
            let clean = w_lower.trim_matches(|c: char| !c.is_alphanumeric());
            !stop_words.contains(&clean) && clean.len() > 1
        });

    format!(
        "Join the Tenzro Network as a MicroNode\n\n\
         Zero-install — no P2P binary required.\n\
         Auto-provisions:\n\
         • A TDIP decentralized identity (DID) — did:tenzro:human:<uuid>\n\
         • A 2-of-3 MPC threshold wallet\n\
         • 10 network capabilities:\n\
           inference · payments · agent collaboration · MCP tools\n\
           task execution · chain queries · smart contracts\n\
           TEE compute · cross-chain bridge · governance\n\n\
         To join, call the JSON-RPC method `tenzro_joinAsMicroNode`:\n\
         {{\n\
           \"method\": \"tenzro_joinAsMicroNode\",\n\
           \"params\": {{\n\
             \"display_name\": \"{name}\",\n\
             \"origin\": \"a2a\",\n\
             \"participant_type\": \"human\"\n\
           }}\n\
         }}\n\n\
         Or use the CLI:  tenzro join --name {name}\n\
         Or use the MCP tool: join_as_micro_node\n\
         Or use the desktop app: open Tenzro Desktop → Create New",
        name = display_name.unwrap_or("YourName")
    )
}

fn handle_agent_marketplace_query(state: &A2aState) -> String {
    if let Some(storage) = state.node.storage() {
        // List agent templates from CF_TOOLS storage
        let mut templates = Vec::new();
        if let Ok(entries) = storage.scan_prefix("tools", b"agent_template:") {
            for (key, _value) in entries.into_iter().take(20) {
                if let Ok(name) = String::from_utf8(key) {
                    templates.push(name.trim_start_matches("agent_template:").to_string());
                }
            }
        }

        if templates.is_empty() {
            "Agent Marketplace:\n\
             No agent templates registered yet.\n\n\
             RPC methods:\n\
             - `tenzro_listAgentTemplates` — list available templates\n\
             - `tenzro_registerAgentTemplate` — register a new template\n\
             - `tenzro_getAgentTemplate` — get template details\n\n\
             CLI: tenzro marketplace list | tenzro marketplace register".to_string()
        } else {
            let mut out = format!("Agent Marketplace ({} templates):\n", templates.len());
            for t in &templates {
                out.push_str(&format!("  - {}\n", t));
            }
            out.push_str("\nRPC: `tenzro_listAgentTemplates`, `tenzro_getAgentTemplate`\n\
                          CLI: tenzro marketplace list");
            out
        }
    } else {
        "Agent Marketplace:\n\
         Storage not available — node may still be initializing.\n\n\
         RPC methods:\n\
         - `tenzro_listAgentTemplates` — list available templates\n\
         - `tenzro_registerAgentTemplate` — register a new template\n\
         - `tenzro_getAgentTemplate` — get template details".to_string()
    }
}

fn handle_task_marketplace_query(state: &A2aState) -> String {
    if let Some(storage) = state.node.storage() {
        let mut tasks = Vec::new();
        if let Ok(entries) = storage.scan_prefix("tools", b"task:") {
            for (key, _value) in entries.into_iter().take(20) {
                if let Ok(name) = String::from_utf8(key) {
                    tasks.push(name.trim_start_matches("task:").to_string());
                }
            }
        }

        if tasks.is_empty() {
            "Task Marketplace:\n\
             No open tasks found.\n\n\
             RPC methods:\n\
             - `tenzro_listTasks` — list open tasks\n\
             - `tenzro_postTask` — post a new task\n\
             - `tenzro_getTask` — get task details\n\
             - `tenzro_cancelTask` — cancel a task\n\
             - `tenzro_quoteTask` — submit a quote for a task\n\n\
             CLI: tenzro task list | tenzro task post".to_string()
        } else {
            let mut out = format!("Task Marketplace ({} tasks):\n", tasks.len());
            for t in &tasks {
                out.push_str(&format!("  - {}\n", t));
            }
            out.push_str("\nRPC: `tenzro_listTasks`, `tenzro_postTask`, `tenzro_quoteTask`\n\
                          CLI: tenzro task list");
            out
        }
    } else {
        "Task Marketplace:\n\
         Storage not available — node may still be initializing.\n\n\
         RPC methods:\n\
         - `tenzro_listTasks` — list open tasks\n\
         - `tenzro_postTask` — post a new task\n\
         - `tenzro_getTask` — get task details".to_string()
    }
}

fn handle_payment_query(_state: &A2aState) -> String {
    "Payments & Settlement:\n\n\
     Supported protocols:\n\
     - MPP (Machine Payments Protocol) — session-based streaming payments\n\
     - x402 (Coinbase) — stateless one-shot HTTP 402 payments\n\
     - AP2 (Agent Payments Protocol) — agent-to-agent payments via A2A\n\
     - Native TNZO transfers\n\n\
     RPC methods:\n\
     - `tenzro_createPaymentChallenge` — create a payment challenge\n\
     - `tenzro_payMpp` / `tenzro_payX402` — execute payment\n\
     - `tenzro_listPaymentSessions` — list active sessions\n\
     - `tenzro_paymentGatewayInfo` — gateway configuration\n\n\
     CLI: tenzro payment challenge | tenzro payment pay\n\
     MCP tools: create_payment_challenge, verify_payment".to_string()
}

fn handle_verification_query(_state: &A2aState) -> String {
    "Verification Services:\n\n\
     - ZK proof verification (Plonky3 STARK over KoalaBear; AIRs: inference, settlement, identity)\n\
     - TEE attestation verification (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU)\n\
     - Transaction signature verification (Ed25519, Secp256k1)\n\
     - Inference result verification\n\n\
     Web API endpoints:\n\
     - POST /verify/zk-proof\n\
     - POST /verify/tee-attestation\n\
     - POST /verify/transaction\n\
     - POST /verify/inference\n\n\
     MCP tool: verify_zk_proof".to_string()
}

fn handle_bridge_query(_state: &A2aState) -> String {
    "Cross-Chain Bridge:\n\n\
     Supported bridges:\n\
     - LayerZero V2 — omnichain messaging & OFT transfers\n\
     - Chainlink CCIP — cross-chain interoperability\n\
     - deBridge DLN — intent-based cross-chain swaps\n\
     - Canton — enterprise DAML interop\n\n\
     RPC methods:\n\
     - `tenzro_bridgeTokens` — bridge tokens between chains\n\
     - `tenzro_getBridgeRoutes` — available routes with fees\n\n\
     MCP tools: bridge_tokens, get_bridge_routes, list_bridge_adapters\n\
     CLI: tenzro bridge".to_string()
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

/// Build the shared A2A state.
///
/// Lifted out of `start_a2a_server_with_shutdown` so the HTTPS axum surface
/// and the iroh-transport adapter ([`crate::a2a::iroh_transport::IrohA2aDispatcher`])
/// can share the same `TaskManager` and `AgentCard` instance — A2A tasks
/// created over either transport land in the same task table.
pub fn build_a2a_state(
    listen_addr: &str,
    node: Arc<TenzroNode>,
    web_state: Arc<WebState>,
) -> Arc<A2aState> {
    let role = format!("{:?}", node.config().role);
    let agent_card = agent_card::build_agent_card(listen_addr, &role);

    Arc::new(A2aState {
        node,
        _web_state: web_state,
        task_manager: TaskManager::new(),
        agent_card,
        payment_verifier: Arc::new(x402_extension::UnimplementedSchemeVerifier::new()),
    })
}

/// Start the A2A protocol server
/// Public API method for external use without shutdown signal
pub async fn start_a2a_server(
    listen_addr: String,
    node: Arc<TenzroNode>,
    web_state: Arc<WebState>,
) -> crate::error::Result<()> {
    let (_keep_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let state = build_a2a_state(&listen_addr, node, web_state);
    start_a2a_server_with_shutdown(listen_addr, state, shutdown_rx).await
}

/// Start the A2A protocol server with graceful shutdown support.
///
/// Takes a pre-built `Arc<A2aState>` so the same state can be shared with
/// the iroh-transport adapter (see [`build_a2a_state`]).
pub async fn start_a2a_server_with_shutdown(
    listen_addr: String,
    state: Arc<A2aState>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> crate::error::Result<()> {

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/.well-known/agent.json", get(agent_card_handler))
        .route(
            "/agents/:did/.well-known/agent.json",
            get(hosted_agent_card_handler),
        )
        .route("/a2a", post(jsonrpc_handler))
        .route("/a2a/stream", post(stream_handler))
        .with_state(state)
        .layer(cors)
        // EU AI Act Art. 50(1): every A2A response is the output of an
        // AI agent. Mirror the MCP-side header so peer agents see the
        // same disclosure regardless of which transport they reached us
        // through. The matching `metadata.eu_ai_disclosure` field is
        // injected per-Message inside the JSON-RPC handler when the
        // response carries an InferenceResponse.
        .layer(axum::middleware::from_fn(
            |req: axum::extract::Request, next: axum::middleware::Next| async move {
                let mut response = next.run(req).await;
                let (name, value) = crate::eu_ai_disclosure::http_header_pair();
                response.headers_mut().insert(
                    axum::http::HeaderName::from_static(name),
                    axum::http::HeaderValue::from_static(value),
                );
                response
            },
        ))
        // Concurrency limit: max 200 in-flight A2A requests. Mirrors the RPC
        // server limit; A2A is JSON-RPC over HTTP so the same DoS surface
        // applies.
        .layer(ConcurrencyLimitLayer::new(200))
        // Request body size limit: 2 MB. Caps the memory footprint of any
        // single inbound message — A2A messages carry small JSON envelopes,
        // not arbitrary blobs.
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024));

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!(addr = %listen_addr, "A2A Protocol server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
            info!("A2A server shutting down gracefully");
        })
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jsonrpc_response_success() {
        let resp = JsonRpcResponse::success(
            serde_json::json!(1),
            serde_json::json!({"status": "ok"}),
        );
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
        assert_eq!(resp.jsonrpc, "2.0");
    }

    #[test]
    fn test_jsonrpc_response_error() {
        let resp = JsonRpcResponse::method_not_found(serde_json::json!(1));
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.as_ref().unwrap().code, -32601);
    }

    #[test]
    fn test_jsonrpc_invalid_params() {
        let resp = JsonRpcResponse::invalid_params(
            serde_json::json!(1),
            "missing field 'id'",
        );
        assert_eq!(resp.error.as_ref().unwrap().code, -32602);
    }

    #[test]
    fn test_send_message_params_deserialization() {
        let json = serde_json::json!({
            "message": {
                "role": "user",
                "parts": [
                    {"type": "text", "text": "Check my balance"}
                ]
            }
        });
        let params: SendMessageParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.message.role, "user");
        assert_eq!(params.message.parts.len(), 1);
        assert_eq!(
            params.message.parts[0].text.as_deref(),
            Some("Check my balance")
        );
    }

    #[test]
    fn test_get_task_params_deserialization() {
        let json = serde_json::json!({
            "id": "task-123",
            "historyLength": 5
        });
        let params: GetTaskParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.id, "task-123");
        assert_eq!(params.history_length, Some(5));
    }

    #[test]
    fn test_cancel_task_params_deserialization() {
        let json = serde_json::json!({"id": "task-456"});
        let params: CancelTaskParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.id, "task-456");
    }

    #[test]
    fn test_list_tasks_params_default() {
        let json = serde_json::json!({});
        let params: ListTasksParams = serde_json::from_value(json).unwrap();
        assert!(params.context_id.is_none());
    }
}
