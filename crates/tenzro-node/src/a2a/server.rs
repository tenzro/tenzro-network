//! A2A 1.0 server — JSON-RPC 2.0 binding.
//!
//! - `POST /a2a` — JSON-RPC dispatcher. `SendStreamingMessage` is answered
//!   with a server-sent-event stream on the same route.
//! - `GET /.well-known/agent-card.json` — the agent card, carrying a detached
//!   JWS by the operator's wallet key. A node that cannot sign serves no card.
//!
//! Every JSON-RPC request declares the protocol version in the `A2A-Version`
//! header. An absent header means 0.3, which this server does not speak, so
//! it is refused with `VersionNotSupportedError` like any other unsupported
//! version.
//!
//! State changes (`SendMessage`, `SendStreamingMessage`, `CancelTask`) require
//! the Tenzro DID envelope (see [`super::did_envelope`]). The DID it verifies
//! is the request's principal: it owns the tasks it opens, and it is the only
//! party whose funds a typed operation can move. Free text is routed only to
//! read-only answers; nothing in a text part changes state.
//!
//! This is the node's front door and audit surface for agents, not a task
//! marketplace: a task is answered by this node itself (a read-only answer
//! or a `readEvents` read), never handed to another worker or provider, and
//! tasks are held in memory only.

use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    response::{
        IntoResponse, Response,
        sse::{Event, Sse},
    },
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn};

use tenzro_storage::KvStore;

use super::agent_card::{self, AgentCard};
use super::did_envelope::{self, VerifiedSender};
use super::task_manager::{
    A2aTask, CancelError, MessagePart, Role, TaskArtifact, TaskManager, TaskMessage, TaskState,
};
use super::x402_extension::{self, MessageMetadataExt};
use crate::node::TenzroNode;
use crate::web::handlers::WebState;

/// Shared state for the A2A server
pub struct A2aState {
    pub node: Arc<TenzroNode>,
    pub web_state: Arc<WebState>,
    pub task_manager: TaskManager,
    /// The card as built from configuration, without signatures.
    pub agent_card: AgentCard,
    /// The card once the operator's wallet has signed it. Filled on the first
    /// successful signing; until then every card request retries.
    signed_card: tokio::sync::Mutex<Option<AgentCard>>,
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

/// A2A error codes of the JSON-RPC binding.
const TASK_NOT_FOUND: i32 = -32001;
const TASK_NOT_CANCELABLE: i32 = -32002;
const PUSH_NOTIFICATION_NOT_SUPPORTED: i32 = -32003;
const UNSUPPORTED_OPERATION: i32 = -32004;
const EXTENDED_AGENT_CARD_NOT_CONFIGURED: i32 = -32007;
const VERSION_NOT_SUPPORTED: i32 = -32009;
/// The DID envelope on a mutation was missing or did not verify. Chosen
/// outside the block the A2A binding assigns.
const ENVELOPE_REJECTED: i32 = -32050;

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
        Self::error_with_data(id, code, message, None)
    }

    fn error_with_data(
        id: serde_json::Value,
        code: i32,
        message: impl Into<String>,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data,
            }),
            id,
        }
    }

    fn method_not_found(id: serde_json::Value) -> Self {
        Self::error(id, -32601, "Method not found")
    }

    /// JSON-RPC 2.0 `-32700` Parse error envelope with `id = null`. Used by
    /// the iroh-transport adapter when the request body isn't valid JSON.
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
// Methods and version negotiation
// ---------------------------------------------------------------------------

/// The A2A 1.0 JSON-RPC methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    SendMessage,
    SendStreamingMessage,
    GetTask,
    ListTasks,
    CancelTask,
    SubscribeToTask,
    CreateTaskPushNotificationConfig,
    GetTaskPushNotificationConfig,
    ListTaskPushNotificationConfigs,
    DeleteTaskPushNotificationConfig,
    GetExtendedAgentCard,
}

impl Method {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "SendMessage" => Self::SendMessage,
            "SendStreamingMessage" => Self::SendStreamingMessage,
            "GetTask" => Self::GetTask,
            "ListTasks" => Self::ListTasks,
            "CancelTask" => Self::CancelTask,
            "SubscribeToTask" => Self::SubscribeToTask,
            "CreateTaskPushNotificationConfig" => Self::CreateTaskPushNotificationConfig,
            "GetTaskPushNotificationConfig" => Self::GetTaskPushNotificationConfig,
            "ListTaskPushNotificationConfigs" => Self::ListTaskPushNotificationConfigs,
            "DeleteTaskPushNotificationConfig" => Self::DeleteTaskPushNotificationConfig,
            "GetExtendedAgentCard" => Self::GetExtendedAgentCard,
            _ => return None,
        })
    }
}

/// Header carrying the protocol version the client speaks.
pub const A2A_VERSION_HEADER: &str = "A2A-Version";

/// Whether a declared `A2A-Version` is one this server speaks. An absent or
/// empty declaration means 0.3.
fn version_supported(declared: Option<&str>) -> bool {
    let declared = declared
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("0.3");
    declared == agent_card::A2A_PROTOCOL_VERSION
}

fn version_not_supported(id: serde_json::Value, declared: Option<&str>) -> JsonRpcResponse {
    JsonRpcResponse::error_with_data(
        id,
        VERSION_NOT_SUPPORTED,
        format!(
            "A2A version {} is not supported; send {}: {}",
            declared
                .filter(|v| !v.trim().is_empty())
                .unwrap_or("0.3 (no A2A-Version header)"),
            A2A_VERSION_HEADER,
            agent_card::A2A_PROTOCOL_VERSION
        ),
        Some(serde_json::json!({
            "supportedVersions": [agent_card::A2A_PROTOCOL_VERSION],
        })),
    )
}

/// Verify the DID envelope on a mutation and return its sender.
fn verify_sender(
    state: &A2aState,
    method: &str,
    params: &serde_json::Value,
    id: &serde_json::Value,
) -> Result<VerifiedSender, JsonRpcResponse> {
    did_envelope::verify_envelope(&state.node, method, params).map_err(|err| {
        warn!(
            "A2A envelope rejected: method={} reason={}",
            method,
            err.message()
        );
        JsonRpcResponse::error(id.clone(), ENVELOPE_REJECTED, err.message())
    })
}

// ---------------------------------------------------------------------------
// A2A method parameter types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendMessageParams {
    message: InboundMessage,
    #[serde(default)]
    configuration: Option<SendMessageConfiguration>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendMessageConfiguration {
    #[serde(default)]
    history_length: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InboundMessage {
    message_id: String,
    role: Role,
    parts: Vec<MessagePart>,
    #[serde(default)]
    task_id: Option<String>,
    #[serde(default)]
    context_id: Option<String>,
    /// Carries the DID envelope and reserved `x402.*` keys.
    #[serde(default)]
    metadata: Option<std::collections::HashMap<String, serde_json::Value>>,
}

impl InboundMessage {
    /// A client message is authored by the user and every part carries
    /// exactly one kind of content.
    fn validate(&self) -> Result<(), String> {
        if self.role != Role::User {
            return Err("message.role must be ROLE_USER".to_string());
        }
        if self.message_id.trim().is_empty() {
            return Err("message.messageId is required".to_string());
        }
        if self.parts.is_empty() {
            return Err("message.parts must not be empty".to_string());
        }
        if let Some(i) = self.parts.iter().position(|p| p.content_count() != 1) {
            return Err(format!(
                "message.parts[{i}] must carry exactly one of text, raw, url or data"
            ));
        }
        Ok(())
    }

    /// Caller metadata without the envelope keys, which authenticate the
    /// request and are not task state.
    fn task_metadata(&self) -> std::collections::HashMap<String, serde_json::Value> {
        let mut md = self.metadata.clone().unwrap_or_default();
        md.retain(|k, _| !k.starts_with("tenzro.a2a.envelope."));
        md
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetTaskParams {
    id: String,
    #[serde(default)]
    history_length: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListTasksParams {
    #[serde(default)]
    context_id: Option<String>,
    #[serde(default)]
    status: Option<TaskState>,
    #[serde(default)]
    page_size: Option<usize>,
    #[serde(default)]
    page_token: Option<String>,
    #[serde(default)]
    history_length: Option<usize>,
    #[serde(default)]
    include_artifacts: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CancelTaskParams {
    id: String,
}

/// Largest page `ListTasks` returns.
const LIST_TASKS_MAX_PAGE: usize = 100;

fn trim_history(task: &mut A2aTask, history_length: Option<usize>) {
    if let Some(limit) = history_length
        && task.history.len() > limit
    {
        let start = task.history.len() - limit;
        task.history = task.history[start..].to_vec();
    }
}

fn task_value(task: &A2aTask) -> serde_json::Value {
    serde_json::to_value(task).unwrap_or(serde_json::Value::Null)
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// Serve the agent card signed by the operator's wallet key. A node that
/// cannot sign answers 503: a card without a signature is not served.
async fn agent_card_handler(State(state): State<Arc<A2aState>>) -> Response {
    let mut cached = state.signed_card.lock().await;
    if let Some(card) = cached.as_ref() {
        return Json(card.clone()).into_response();
    }
    match agent_card::sign_with_operator_wallet(&state.node, &state.agent_card).await {
        Ok(signed) => {
            *cached = Some(signed.clone());
            Json(signed).into_response()
        }
        Err(e) => {
            warn!("A2A agent card not served: it cannot be signed: {e}");
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "agent card unavailable: this node cannot sign it",
                    "reason": e.to_string(),
                })),
            )
                .into_response()
        }
    }
}

/// Main JSON-RPC 2.0 dispatcher at `POST /a2a`.
async fn jsonrpc_handler(
    State(state): State<Arc<A2aState>>,
    headers: HeaderMap,
    Json(req): Json<JsonRpcRequest>,
) -> Response {
    let version = headers
        .get(A2A_VERSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    if req.jsonrpc == "2.0"
        && Method::parse(&req.method) == Some(Method::SendStreamingMessage)
        && version_supported(version.as_deref())
    {
        return stream_send_message(state, req).await;
    }
    Json(dispatch_jsonrpc(&state, req, version.as_deref()).await).into_response()
}

/// Transport-agnostic JSON-RPC 2.0 dispatch of unary methods.
///
/// The HTTPS route passes the `A2A-Version` header; the iroh adapter passes
/// the version its ALPN is pinned to. `SendStreamingMessage` is only
/// answerable where a stream can be returned, so over a unary transport it
/// is refused as unsupported.
pub(crate) async fn dispatch_jsonrpc(
    state: &Arc<A2aState>,
    req: JsonRpcRequest,
    a2a_version: Option<&str>,
) -> JsonRpcResponse {
    if req.jsonrpc != "2.0" {
        return JsonRpcResponse::error(req.id, -32600, "Invalid JSON-RPC version, expected 2.0");
    }
    if !version_supported(a2a_version) {
        return version_not_supported(req.id, a2a_version);
    }
    let Some(method) = Method::parse(&req.method) else {
        warn!("A2A: unknown method: {}", req.method);
        return JsonRpcResponse::method_not_found(req.id);
    };

    match method {
        Method::SendMessage => {
            let sender = match verify_sender(state, &req.method, &req.params, &req.id) {
                Ok(s) => s,
                Err(resp) => return resp,
            };
            handle_send_message(state, req.params, req.id, &sender).await
        }
        Method::CancelTask => {
            let sender = match verify_sender(state, &req.method, &req.params, &req.id) {
                Ok(s) => s,
                Err(resp) => return resp,
            };
            handle_cancel_task(state, req.params, req.id, &sender)
        }
        Method::GetTask => handle_get_task(state, req.params, req.id),
        Method::ListTasks => handle_list_tasks(state, req.params, req.id),
        Method::SendStreamingMessage => JsonRpcResponse::error(
            req.id,
            UNSUPPORTED_OPERATION,
            "SendStreamingMessage returns an event stream; send it over HTTPS to /a2a",
        ),
        Method::SubscribeToTask => JsonRpcResponse::error(
            req.id,
            UNSUPPORTED_OPERATION,
            "SubscribeToTask is not served: tasks run to completion within SendMessage",
        ),
        Method::CreateTaskPushNotificationConfig
        | Method::GetTaskPushNotificationConfig
        | Method::ListTaskPushNotificationConfigs
        | Method::DeleteTaskPushNotificationConfig => JsonRpcResponse::error(
            req.id,
            PUSH_NOTIFICATION_NOT_SUPPORTED,
            "Push notifications are not supported by this agent",
        ),
        Method::GetExtendedAgentCard => JsonRpcResponse::error(
            req.id,
            EXTENDED_AGENT_CARD_NOT_CONFIGURED,
            "This agent publishes no extended agent card",
        ),
    }
}

/// `SendStreamingMessage`: the envelope and the message are checked before
/// the stream opens, so a refusal is an ordinary JSON-RPC error. Once
/// accepted the stream carries the task as it enters `WORKING` and as it
/// ends, each as a JSON-RPC response whose result is `{"task": ...}`.
async fn stream_send_message(state: Arc<A2aState>, req: JsonRpcRequest) -> Response {
    let sender = match verify_sender(&state, &req.method, &req.params, &req.id) {
        Ok(s) => s,
        Err(resp) => return Json(resp).into_response(),
    };
    if let Err(why) = crate::tool_call_record::admit(&state.node) {
        return Json(JsonRpcResponse::error(
            req.id,
            crate::tool_call_record::UNRECORDABLE,
            why,
        ))
        .into_response();
    }
    let (task_id, history_length) = match accept_message(&state, req.params, &req.id, &sender).await
    {
        Ok(Accepted::Run {
            task_id,
            history_length,
        }) => (task_id, history_length),
        Ok(Accepted::Done(task)) => {
            return Json(JsonRpcResponse::success(
                req.id,
                serde_json::json!({ "task": task_value(&task) }),
            ))
            .into_response();
        }
        Err(resp) => return Json(resp).into_response(),
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(8);
    let id = req.id;
    tokio::spawn(async move {
        let emit = |task: &A2aTask| {
            let mut task = task.clone();
            trim_history(&mut task, history_length);
            let resp = JsonRpcResponse::success(
                id.clone(),
                serde_json::json!({ "task": task_value(&task) }),
            );
            Event::default()
                .json_data(&resp)
                .unwrap_or_else(|_| Event::default().data("error"))
        };
        if let Some(task) = state.task_manager.get_task(&task_id) {
            let _ = tx.send(Ok(emit(&task))).await;
        }
        let finished = run_task(&state, &task_id, &sender).await;
        if let Some(task) = finished {
            let _ = tx.send(Ok(emit(&task))).await;
        }
    });
    Sse::new(ReceiverStream::new(rx)).into_response()
}

// ---------------------------------------------------------------------------
// JSON-RPC method handlers
// ---------------------------------------------------------------------------

/// Outcome of accepting an inbound message.
enum Accepted {
    /// The task is `WORKING` and must now be run.
    Run {
        task_id: String,
        history_length: Option<usize>,
    },
    /// The task reached a terminal state while the message was accepted
    /// (an x402 payment that did not verify).
    Done(A2aTask),
}

/// Validate a `SendMessage` request and move its task to `WORKING`.
///
/// A message naming an existing task continues it only when the envelope's
/// DID opened that task and the task is not terminal. Another DID's task is
/// reported as not found, so task ids cannot be probed.
async fn accept_message(
    state: &A2aState,
    params: serde_json::Value,
    id: &serde_json::Value,
    sender: &VerifiedSender,
) -> Result<Accepted, JsonRpcResponse> {
    let params: SendMessageParams = serde_json::from_value(params)
        .map_err(|e| JsonRpcResponse::invalid_params(id.clone(), format!("Invalid params: {e}")))?;
    params
        .message
        .validate()
        .map_err(|e| JsonRpcResponse::invalid_params(id.clone(), e))?;
    let history_length = params.configuration.and_then(|c| c.history_length);
    let inbound_metadata = params.message.task_metadata();
    let msg = TaskMessage {
        message_id: params.message.message_id.clone(),
        role: Role::User,
        parts: params.message.parts.clone(),
    };

    let Some(task_id) = params.message.task_id.clone() else {
        let task_id = uuid::Uuid::new_v4().to_string();
        state.task_manager.create_task(
            task_id.clone(),
            params.message.context_id.clone(),
            msg,
            inbound_metadata,
            &sender.did,
        );
        state
            .task_manager
            .update_status(&task_id, TaskState::Working, None);
        return Ok(Accepted::Run {
            task_id,
            history_length,
        });
    };

    let existing = state
        .task_manager
        .get_task(&task_id)
        .filter(|t| t.principal == sender.did)
        .ok_or_else(|| {
            JsonRpcResponse::error(
                id.clone(),
                TASK_NOT_FOUND,
                format!("Task not found: {task_id}"),
            )
        })?;
    if existing.status.state.is_terminal() {
        return Err(JsonRpcResponse::error(
            id.clone(),
            UNSUPPORTED_OPERATION,
            format!("Task {task_id} is in a terminal state and accepts no further messages"),
        ));
    }

    // x402 hold-and-resume: a task in `INPUT_REQUIRED` with
    // `x402.payment.required` resumes only on a message carrying
    // `x402.payment.payload` that verifies and settles.
    if existing.status.state == TaskState::InputRequired
        && let Some(requirements) = existing.metadata.get_payment_required()
    {
        let Some(payload) = inbound_metadata.get_payment_payload() else {
            return Err(JsonRpcResponse::error(
                id.clone(),
                UNSUPPORTED_OPERATION,
                "task is awaiting x402.payment.payload in message.metadata",
            ));
        };
        match x402_extension::verify_and_settle(
            // The facilitator the operator names, else this node's own.
            state
                .node
                .x402_facilitator()
                .map(|f| f.as_ref() as &dyn x402_extension::X402Settler)
                .or_else(|| {
                    state
                        .node
                        .x402_facilitator_service()
                        .map(|f| f.as_ref() as &dyn x402_extension::X402Settler)
                }),
            &task_id,
            &requirements,
            &payload,
        )
        .await
        {
            Ok(receipts) => {
                state.task_manager.update_metadata(&task_id, |md| {
                    md.submit_x402(payload.clone());
                    md.complete_x402(receipts.clone());
                });
            }
            Err(failure) => {
                let terminal = failure.terminal_status();
                let reason = failure.message();
                state.task_manager.update_metadata(&task_id, |md| {
                    md.submit_x402(payload.clone());
                    md.fail_x402(terminal);
                });
                let failure_msg = TaskMessage::agent(vec![MessagePart::text(format!(
                    "payment failed: {reason}"
                ))]);
                let task = state
                    .task_manager
                    .update_status(&task_id, TaskState::Failed, Some(failure_msg))
                    .ok_or_else(|| {
                        JsonRpcResponse::internal_error(id.clone(), "Failed to update task")
                    })?;
                return Ok(Accepted::Done(task));
            }
        }
    }

    state
        .task_manager
        .update_status(&task_id, TaskState::Working, Some(msg));
    Ok(Accepted::Run {
        task_id,
        history_length,
    })
}

/// Execute a `WORKING` task and record the terminal state.
async fn run_task(state: &A2aState, task_id: &str, sender: &VerifiedSender) -> Option<A2aTask> {
    let request = state.task_manager.get_task(task_id).and_then(|t| {
        t.history
            .iter()
            .rev()
            .find(|m| m.role == Role::User)
            .map(|m| m.parts.clone())
    });
    let mut outcome = execute_task(state, task_id, sender).await;
    let recorded = match request {
        Some(parts) => record_task(state, sender, &parts, &outcome),
        None => Err("the task has no message to record".to_string()),
    };
    if let Err(why) = recorded {
        outcome = Err(why);
    }
    let (state_after, text) = match outcome {
        Ok(text) => (TaskState::Completed, text),
        Err(text) => (TaskState::Failed, text),
    };
    // EU AI Act Art. 50(2): every AI response carries an in-band
    // disclosure key in the response data part so SDKs can surface
    // "this is AI" without having to inspect the HTTP header.
    let (disc_key, disc_val) = crate::eu_ai_disclosure::metadata_pair();
    let data = serde_json::json!({
        "response": &text,
        "task_id": task_id,
        disc_key: disc_val,
    });
    state.task_manager.add_artifact(
        task_id,
        TaskArtifact {
            artifact_id: uuid::Uuid::new_v4().to_string(),
            name: "response".to_string(),
            parts: vec![MessagePart::data(data.clone())],
        },
    );
    let response_msg = TaskMessage::agent(vec![MessagePart::text(&text), MessagePart::data(data)]);
    state
        .task_manager
        .update_status(task_id, state_after, Some(response_msg))
}

/// The signed record of a task the sender ran: the operation it named (or
/// `message` for a plain message), the digest of its parts and of the answer,
/// and whether it ran.
fn record_task(
    state: &A2aState,
    sender: &VerifiedSender,
    parts: &[MessagePart],
    outcome: &Result<String, String>,
) -> Result<(), String> {
    let signer = crate::tool_call_record::admit(&state.node)?;
    let tool = parts
        .iter()
        .filter_map(|p| p.data.as_ref())
        .find_map(|d| d.get("operation").and_then(|v| v.as_str()))
        .unwrap_or("message")
        .to_string();
    let approval = parts
        .iter()
        .filter_map(|p| p.data.as_ref())
        .find_map(|d| {
            d.get(crate::tool_call_record::APPROVAL_META)
                .and_then(|v| v.as_str())
        })
        .map(str::to_string);
    let args = serde_json::to_vec(parts).unwrap_or_default();
    let result = serde_json::to_vec(outcome).unwrap_or_default();
    let ran = match outcome {
        Ok(_) => tenzro_types::agent_audit::ActionOutcome::Allowed,
        Err(e) if e.starts_with("Unknown operation") => {
            tenzro_types::agent_audit::ActionOutcome::Refused(e.clone())
        }
        Err(_) => tenzro_types::agent_audit::ActionOutcome::Allowed,
    };
    let refused = matches!(ran, tenzro_types::agent_audit::ActionOutcome::Refused(_));
    crate::tool_call_record::record(
        &state.node,
        &signer,
        crate::tool_call_record::Call {
            surface: crate::tool_call_record::Surface::A2a,
            agent: &sender.did,
            tool: &tool,
            args: &args,
            outcome: ran,
            result: (!refused).then_some(result.as_slice()),
            approval,
            principal: crate::tool_call_record::principal_of(&state.node, &sender.did),
        },
    )
    .map(|_| ())
}

async fn handle_send_message(
    state: &A2aState,
    params: serde_json::Value,
    id: serde_json::Value,
    sender: &VerifiedSender,
) -> JsonRpcResponse {
    // No message from an authenticated sender is taken without its signed
    // record: a node that cannot sign refuses it before it is accepted.
    if let Err(why) = crate::tool_call_record::admit(&state.node) {
        return JsonRpcResponse::error(id, crate::tool_call_record::UNRECORDABLE, why);
    }
    let (task, history_length) = match accept_message(state, params, &id, sender).await {
        Ok(Accepted::Run {
            task_id,
            history_length,
        }) => match run_task(state, &task_id, sender).await {
            Some(task) => (task, history_length),
            None => return JsonRpcResponse::internal_error(id, "Failed to update task"),
        },
        Ok(Accepted::Done(task)) => (task, None),
        Err(resp) => return resp,
    };
    let mut task = task;
    trim_history(&mut task, history_length);
    JsonRpcResponse::success(id, serde_json::json!({ "task": task_value(&task) }))
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
            trim_history(&mut task, params.history_length);
            JsonRpcResponse::success(id, task_value(&task))
        }
        None => {
            JsonRpcResponse::error(id, TASK_NOT_FOUND, format!("Task not found: {}", params.id))
        }
    }
}

fn handle_list_tasks(
    state: &A2aState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> JsonRpcResponse {
    let params: ListTasksParams = if params.is_null() {
        ListTasksParams::default()
    } else {
        match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => return JsonRpcResponse::invalid_params(id, format!("Invalid params: {}", e)),
        }
    };
    let offset = match params.page_token.as_deref().filter(|t| !t.is_empty()) {
        None => 0,
        Some(token) => match token.parse::<usize>() {
            Ok(n) => n,
            Err(_) => return JsonRpcResponse::invalid_params(id, "pageToken is not valid"),
        },
    };
    let page_size = params.page_size.unwrap_or(50).clamp(1, LIST_TASKS_MAX_PAGE);

    let all = state
        .task_manager
        .list_tasks(params.context_id.as_deref(), params.status);
    let total = all.len();
    let include_artifacts = params.include_artifacts.unwrap_or(false);
    let page: Vec<serde_json::Value> = all
        .into_iter()
        .skip(offset)
        .take(page_size)
        .map(|mut t| {
            trim_history(&mut t, params.history_length);
            if !include_artifacts {
                t.artifacts.clear();
            }
            task_value(&t)
        })
        .collect();
    let next = offset + page.len();
    JsonRpcResponse::success(
        id,
        serde_json::json!({
            "tasks": page,
            "nextPageToken": if next < total { next.to_string() } else { String::new() },
            "pageSize": page_size,
            "totalSize": total,
        }),
    )
}

fn handle_cancel_task(
    state: &A2aState,
    params: serde_json::Value,
    id: serde_json::Value,
    sender: &VerifiedSender,
) -> JsonRpcResponse {
    let params: CancelTaskParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => return JsonRpcResponse::invalid_params(id, format!("Invalid params: {}", e)),
    };
    match state.task_manager.cancel_task(&params.id, &sender.did) {
        Ok(task) => JsonRpcResponse::success(id, task_value(&task)),
        Err(CancelError::NotFound) | Err(CancelError::NotOwner) => {
            JsonRpcResponse::error(id, TASK_NOT_FOUND, format!("Task not found: {}", params.id))
        }
        Err(CancelError::NotCancelable) => JsonRpcResponse::error(
            id,
            TASK_NOT_CANCELABLE,
            format!("Task {} is already in a terminal state", params.id),
        ),
    }
}

// ---------------------------------------------------------------------------
// Task execution
// ---------------------------------------------------------------------------

/// Answer the latest user message of a task on this node, with no hand-off to
/// any other worker: a data part naming the
/// `readEvents` operation reads the chain's events, and text parts are
/// routed to read-only answers. `Err` marks the task `FAILED`. Value moves on
/// chain only through signed transactions, never through a message.
async fn execute_task(
    state: &A2aState,
    task_id: &str,
    sender: &VerifiedSender,
) -> Result<String, String> {
    let task = state
        .task_manager
        .get_task(task_id)
        .ok_or_else(|| "Task not found".to_string())?;
    let msg = task
        .history
        .iter()
        .rev()
        .find(|m| m.role == Role::User)
        .ok_or_else(|| "No user message found".to_string())?;

    if let Some(op) = msg
        .parts
        .iter()
        .filter_map(|p| p.data.as_ref())
        .find(|d| d.get("operation").is_some())
    {
        return match op.get("operation").and_then(|v| v.as_str()) {
            Some("readEvents") => execute_read_events(state, sender, op).await,
            Some(other) => Err(format!("Unknown operation '{other}'")),
            None => Err("`operation` must be a string".to_string()),
        };
    }

    let text = msg
        .parts
        .iter()
        .filter_map(|p| p.text.as_deref())
        .collect::<Vec<_>>()
        .join(" ");
    Ok(answer_text(state, &text))
}

/// The chain's next events after a cursor, requested through a data part
/// `{operation: "readEvents", filter?, from_cursor?, from_height?, limit?,
/// anchor_index?}`. The answer carries the cursor to pass back next, so an
/// agent that restarts resumes with no gap, and its proofs inline: each
/// event's proof and the completeness proof of the range, anchored at one
/// certified checkpoint, so the agent trusts nothing this node says. Only
/// certified heights are read. A delegated agent reads only within its terms.
async fn execute_read_events(
    state: &A2aState,
    sender: &VerifiedSender,
    op: &serde_json::Value,
) -> Result<String, String> {
    crate::agent_delegation::check_agent_event_read(&state.node, &sender.did, op)?;
    let log = state.node.event_log().ok_or("the event log is not open")?;
    let certified = state
        .node
        .consensus()
        .and_then(|c| c.latest_certificate())
        .map(|c| c.checkpoint.last_height)
        .ok_or("no certified checkpoint yet")?;
    let mut params = op.clone();
    params["completeness"] = serde_json::json!(true);
    let mut req = crate::event_index::ReadRequest::parse(
        &params,
        log.tip().map(tenzro_events::log::end_of_height),
    )
    .map_err(|e| e.message)?;
    let through = tenzro_events::log::end_of_height(certified);
    req.to = Some(req.to.map_or(through, |t| t.min(through)));
    let anchor = op.get("anchor_index").and_then(serde_json::Value::as_u64);
    let page = crate::event_index::read(&state.node, &req)
        .await
        .map_err(|e| e.message)?;
    let (proofs, completeness) =
        crate::event_index::prove_complete(&state.node, &req, &page, anchor)
            .await
            .map_err(|e| e.message)?;
    Ok(serde_json::json!({
        "events": proofs.into_iter().map(|p| serde_json::json!({ "event": p.event, "proof": p })).collect::<Vec<_>>(),
        "completeness": completeness,
        "cursor": page.cursor.map(|c| c.to_string()),
        "tip": log.tip(),
    })
    .to_string())
}

/// Read-only answers a text message can be routed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Join,
    Moe,
    Discovery,
    Storage,
    Compute,
    TokenOperations,
    TokenInfo,
    TokenBalance,
    TokenList,
    Contract,
    Identity,
    Balance,
    Model,
    Staking,
    Provider,
    Payment,
    Verification,
    Bridge,
    Block,
    Network,
    Status,
    Help,
}

/// Classify free text. Multi-word phrases are checked before the single
/// keywords they contain, and the most generic keywords last.
fn classify(text: &str) -> Route {
    let t = text.to_lowercase();
    let has = |s: &str| t.contains(s);
    if has("join") || has("micronode") || has("onboard") || has("participate") {
        Route::Join
    } else if has("shard map") || has("expert") || has("moe") {
        Route::Moe
    } else if has("lan cluster")
        || has("cluster plan")
        || has("pipeline")
        || (has("local") && has("peer"))
        || has("reachability")
        || has("hardware profile")
    {
        Route::Discovery
    } else if has("storage deal")
        || has("byte-epoch")
        || has("retrievability")
        || (has("store") && has("object"))
    {
        Route::Storage
    } else if has("compute rental") || has("rent compute") || has("rental task") {
        Route::Compute
    } else if (has("token") && (has("create") || has("mint")))
        || (has("cross") && has("vm"))
        || (has("transfer") && (has("evm") || has("svm")))
    {
        Route::TokenOperations
    } else if has("token") && (has("info") || has("details") || has("lookup")) {
        Route::TokenInfo
    } else if has("token") && has("balance") {
        Route::TokenBalance
    } else if has("token") || has("erc20") || has("erc-20") {
        Route::TokenList
    } else if has("deploy") || has("contract") || has("bytecode") {
        Route::Contract
    } else if has("identity") || has("did") || has("resolve") {
        Route::Identity
    } else if has("balance") || has("wallet") || has("send") {
        Route::Balance
    } else if has("model") || has("inference") || has("ai") || has("chat") {
        Route::Model
    } else if has("stake") || has("staking") || has("validator") {
        Route::Staking
    } else if has("provider") || has("serving") || has("earnings") {
        Route::Provider
    } else if has("payment") || has("challenge") || has("mpp") || has("x402") {
        Route::Payment
    } else if has("verify") || has("proof") || has("attestation") || has("zk") {
        Route::Verification
    } else if has("bridge") || has("cross-chain") || has("ccip") {
        Route::Bridge
    } else if has("block") || has("height") || has("transaction") {
        Route::Block
    } else if has("peer") || has("network") {
        Route::Network
    } else if has("status") || has("health") || has("node") {
        Route::Status
    } else {
        Route::Help
    }
}

fn answer_text(state: &A2aState, text: &str) -> String {
    match classify(text) {
        Route::Join => handle_join_query(state, text),
        Route::Moe => handle_moe_query(state),
        Route::Discovery => handle_discovery_query(state),
        Route::Storage => handle_storage_query(state),
        Route::Compute => handle_compute_query(state),
        Route::TokenOperations => handle_token_operations_query(),
        Route::TokenInfo => handle_get_token_info(state, text),
        Route::TokenBalance => handle_token_balance(state, text),
        Route::TokenList => handle_list_tokens(state, text),
        Route::Contract => handle_contract_query(state),
        Route::Identity => handle_identity_query(state, text),
        Route::Balance => handle_balance_query(state, text),
        Route::Model => handle_model_query(state),
        Route::Staking => handle_staking_query(state),
        Route::Provider => handle_provider_query(state),
        Route::Payment => handle_payment_query(state),
        Route::Verification => handle_verification_query(state),
        Route::Bridge => handle_bridge_query(state),
        Route::Block => handle_block_query(state),
        Route::Network => handle_network_query(state),
        Route::Status => handle_status_query(state),
        Route::Help => "I'm the Tenzro Network Agent. I can help with:\n\
             - Join as MicroNode (zero-install full network participant)\n\
             - Wallet & balance queries\n\
             - Block & chain info\n\
             - Node status & health\n\
             - Identity (DID) lookup\n\
             - Staking & validator info\n\
             - Provider statistics\n\
             - AI model discovery\n\
             - Network peer info\n\
             - Token queries\n\
             - Smart contract deployment guidance\n\
             - Payments & settlement\n\
             - Verification (ZK, TEE, signatures)\n\
             - Cross-chain bridges\n\n\
             What would you like to do?"
            .to_string(),
    }
}

fn handle_token_operations_query() -> String {
    "Token operations are not taken from free text.\n\
     - Transfers, in any VM or across VMs: a signed contract-call transaction, whose calls \
     move the token through each VM's own view of the one ledger.\n\
     - Token creation, minting and the issuer's compliance controls: a signed \
     `Token` transaction."
        .to_string()
}

fn handle_contract_query(state: &A2aState) -> String {
    format!(
        "Smart Contract Deployment:\n\
         - VM Runtime: {}\n\
         - Deployable code: EVM creation code\n\n\
         Deployment is a signed transaction, not a chat message: sign a \
         `ContractDeploy` transaction carrying the EVM creation code and submit it \
         with the JSON-RPC method `tenzro_deployContract` (the same fields as \
         `tenzro_sendRawTransaction`). The contract is created when a block \
         executes it, at the address its receipt reports.",
        if state.node.vm_runtime().is_some() {
            "Available"
        } else {
            "Not initialized"
        },
    )
}

fn handle_balance_query(state: &A2aState, text: &str) -> String {
    // Try to extract an address from the text, stripping trailing punctuation
    let address_raw = text
        .split_whitespace()
        .find(|w| {
            w.starts_with("0x") || w.trim_end_matches(|c: char| !c.is_alphanumeric()).len() == 64
        })
        .unwrap_or("(no address provided)");
    let address = address_raw.trim_end_matches(['?', '!', '.', ',', ';', ':']);

    if let Some(storage) = state.node.storage() {
        match storage.get("accounts", address.as_bytes()) {
            Ok(Some(data)) => {
                let bytes: &[u8] = &data;
                let balance = if bytes.len() >= 16 {
                    u128::from_be_bytes(bytes[..16].try_into().unwrap_or([0u8; 16]))
                } else if bytes.len() >= 8 {
                    u64::from_be_bytes(bytes[..8].try_into().unwrap_or([0u8; 8])) as u128
                } else {
                    0u128
                };
                let tnzo = balance as f64 / 1e18;
                format!(
                    "Balance for {}: {:.6} TNZO ({} wei)",
                    address, tnzo, balance
                )
            }
            _ => format!(
                "No balance found for {}. The account may not exist yet.",
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
                    bytes
                        .get(..8)
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
    let role = config.roles.to_string();
    let metrics = state.node.metrics().get_metrics();

    format!(
        "Node Status:\n\
         - Roles: {}\n\
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
                        if identity.is_human() {
                            "Human"
                        } else {
                            "Machine"
                        },
                        identity.status,
                        identity.created_at,
                    )
                }
                Err(_) => format!("Identity not found: {}", did),
            }
        } else {
            "Identity registry not available.".to_string()
        }
    } else if text_lower.contains("register")
        && (text_lower.contains("identity") || text_lower.contains("did"))
    {
        // Registering an identity needs key material and proof of consent, and a
        // chat message carries neither.
        "Identity registration is not available over A2A chat.\n\
         An identity is bound to a key you hold — a passkey for a person, a TPM \
         or Secure Enclave key for a machine — and this node never generates one \
         on your behalf.\n\
         Use the `tenzro_registerIdentity` RPC, passing `public_key` and \
         `credential_id` from your authenticator."
            .to_string()
    } else {
        "To look up an identity, provide a DID (e.g., did:tenzro:human:abc123). \
         Registration happens over the `tenzro_registerIdentity` RPC, which \
         takes the public half of a key you hold."
            .to_string()
    }
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
                "  - {} ({}) — {} [{}]\n    Endpoint: {}\n",
                svc.model_name, svc.model_id, svc.status, svc.location, svc.iroh_endpoint_id,
            ));
        }
    }

    out.push_str(
        "\nRPC methods:\n\
         - `tenzro_listModels` — list available models\n\
         - `tenzro_listModelEndpoints` — list active service endpoints\n\
         - `tenzro_requestInference` — run inference\n\
         - `tenzro_chat` — chat completion\n\
         - `tenzro_registerModelEndpoint` — register external endpoint",
    );
    out
}

fn handle_network_query(state: &A2aState) -> String {
    let metrics = state.node.metrics().get_metrics();
    format!(
        "Network Info:\n\
         - Connected peers: {}\n\
         - Protocol: iroh gossip (tenzro/gossip), identity endpoint records + relays\n\
         - Topics: blocks, transactions, certificates, validators, models, status",
        metrics.peer_count,
    )
}

fn handle_discovery_query(_state: &A2aState) -> String {
    "Local Discovery:\n\
     - Cluster members find each other on the local network by multicast DNS\n\
     - Every node is reachable by its iroh endpoint, directly or through a relay\n\n\
     RPC: tenzro_nodeProfile\n\
     CLI: `tenzro discover profile`"
        .to_string()
}

fn handle_storage_query(_state: &A2aState) -> String {
    "Decentralized Storage (content-addressed, billed per byte-epoch, held to a proof of \
     retrievability):\n\
     - Store an object, then pay for keeping it with a storage compute claim that\n\
       commits its descriptor digest; the claim settles hourly on SLA verdicts\n\
       that require a possession proof of the object.\n\n\
     RPC: tenzro_storageStatus, tenzro_storageStoreObject, tenzro_storageSetPricing, \
     tenzro_computeGetClaim\n\
     CLI: `tenzro node storage status`"
        .to_string()
}

fn handle_compute_query(_state: &A2aState) -> String {
    "Compute rental is a stream escrow to the provider's bonded address:\n\
     - CreateEscrow with release `Stream` pays the provider by the epoch until the expiry \
     (ClaimEscrowStream), and the renter stops it with RefundEscrow. Finding a provider and \
     agreeing a price happens in a harness task market, not on chain.\n\
     - An epoch the validators judged the provider unavailable is never paid out of the stream: \
     it stays with the renter, returned when the stream is stopped.\n\
     - Capacity bought ahead from a bonded provider is a compute claim (ComputeClaim), settled hour by hour on SLA verdicts.\n\n\
     RPC: tenzro_getEscrow, tenzro_slaVerdict, tenzro_computeGetClaim, tenzro_computeListClaims"
        .to_string()
}

fn handle_moe_query(_state: &A2aState) -> String {
    "Distributed MoE Serving (decentralized expert-shard serving):\n\
     - Read the shard map for a model, plan dispatch from per-token top-k routings, read the \
     replication policy and catalog topology.\n\n\
     RPC: tenzro_moeShardMap, tenzro_moePlanDispatch, tenzro_moeReplicationPolicy, \
     tenzro_moeCatalogShape"
        .to_string()
}

fn handle_staking_query(state: &A2aState) -> String {
    let Some(chain) = crate::rpc::chain_state_of(&state.node) else {
        return "Chain state is not available on this node.".to_string();
    };
    let totals = tenzro_vm::native::role_stake_totals(&chain);
    let total_staked: u128 = totals.iter().map(|(_, t)| t.bonded).sum();
    let roles = totals
        .iter()
        .map(|(role, t)| {
            format!(
                "             - {role}: {} stakers, {:.6} TNZO",
                t.stakers.len(),
                t.bonded as f64 / 1e18
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Role stakes:\n\
         - Total bonded: {:.6} TNZO\n\
         Per role:\n{}\n\n\
         To bond, unbond or withdraw: sign a `Stake` transaction (MCP tool `stake`, \
         CLI `tenzro stake`)",
        total_staked as f64 / 1e18,
        roles,
    )
}

fn handle_provider_query(state: &A2aState) -> String {
    let models_served = state.node.served_models.len();
    let total_inferences = state.node.transaction_history.read().len();

    let staking_info = match crate::rpc::chain_state_of(&state.node) {
        Some(chain) => {
            let totals = tenzro_vm::native::role_stake_totals(&chain);
            let bonded: u128 = totals.iter().map(|(_, t)| t.bonded).sum();
            let stakers: usize = totals.iter().map(|(_, t)| t.stakers.len()).sum();
            format!(
                "{:.6} TNZO across {} role bonds",
                bonded as f64 / 1e18,
                stakers
            )
        }
        None => "N/A".to_string(),
    };

    let bond_info = if let Some(chain) = state.node.chain_state() {
        let bonds = tenzro_vm::native::compute_bonds(&chain);
        let active = bonds.iter().filter(|b| b.is_eligible()).count();
        format!(
            "- Compute bond minimum: {:.6} TNZO\n\
             - Withdrawal cooldown: {} ms\n\
             - Compute bonds on chain: {} ({} eligible)\n",
            tenzro_vm::native::compute_bond_min(&chain) as f64 / 1e18,
            tenzro_vm::native::network_param(
                &chain,
                tenzro_vm::native::COMPUTE_BOND_COOLDOWN_PARAM
            ),
            bonds.len(),
            active,
        )
    } else {
        String::new()
    };

    format!(
        "Provider Stats:\n\
         - Models served: {}\n\
         - Total inferences: {}\n\
         - Total staked: {}\n\
         - Roles: {}\n\
         {}\n\
         A node serves a bonded role only while its operator holds that role's stake: bond \
         it with a signed `Stake` transaction (MCP tool `stake`, CLI `tenzro stake bond`) and \
         read it with `tenzro_getRoleStakes`. Compute bonds back served inference: read them \
         with MCP tool `get_compute_bond` or RPC `tenzro_getComputeBond` / \
         `tenzro_computeBondParams`.",
        models_served,
        total_inferences,
        staking_info,
        state.node.config().roles,
        bond_info,
    )
}

fn handle_get_token_info(state: &A2aState, text: &str) -> String {
    let registry = match state.node.token_registry() {
        Some(r) => r,
        None => return "Token registry not initialized.".to_string(),
    };

    let words: Vec<&str> = text.split_whitespace().collect();
    let by_address = words.iter().find(|w| w.starts_with("0x") && w.len() >= 42);
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
                d.vm_addresses
                    .evm_hex()
                    .unwrap_or_else(|| "N/A".to_string()),
                d.vm_addresses
                    .svm_hex()
                    .unwrap_or_else(|| "N/A".to_string()),
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
    let vm_filter = if text_lower.contains("tempo")
        || text_lower.contains("tip20")
        || text_lower.contains("tip-20")
    {
        Some(tenzro_token::TokenVmType::TempoTip20)
    } else if text_lower.contains("evm") {
        Some(tenzro_token::TokenVmType::Evm)
    } else if text_lower.contains("svm") || text_lower.contains("solana") {
        Some(tenzro_token::TokenVmType::Svm)
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
            d.vm_addresses
                .evm_hex()
                .unwrap_or_else(|| "N/A".to_string()),
        ));
    }

    result
}

fn handle_token_balance(state: &A2aState, text: &str) -> String {
    let token = match state.node.token() {
        Some(t) => t,
        None => return "TNZO token not initialized.".to_string(),
    };

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

    let bytes = match decode_hex_address(address_str) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let address = rpc_bytes_to_address(&bytes);

    let native_balance = token.balance_of(&address);
    let display = native_balance as f64 / 1e18;
    let spl_balance = tenzro_token::native_to_spl(native_balance).unwrap_or(0);

    format!(
        "Token Balance for {}:\n\
         - Native TNZO: {} ({:.6} TNZO)\n\
         - EVM wTNZO: {} (18 decimals)\n\
         - SVM wTNZO: {} (9 decimals)\n\n\
         All representations share the same underlying balance (pointer model).",
        address_str, native_balance, display, native_balance, spl_balance,
    )
}

fn decode_hex_address(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| format!("Invalid address: {e}"))
}

/// Convert address bytes to a 32-byte `Address`. A 20-byte EVM address
/// occupies the leading bytes with zeros after it, the one ledger account
/// every VM names it by.
fn rpc_bytes_to_address(bytes: &[u8]) -> tenzro_types::Address {
    let mut arr = [0u8; 32];
    let len = bytes.len().min(32);
    arr[..len].copy_from_slice(&bytes[..len]);
    tenzro_types::Address::new(arr)
}

fn handle_join_query(_state: &A2aState, text: &str) -> String {
    let stop_words = [
        "join",
        "the",
        "tenzro",
        "network",
        "as",
        "a",
        "an",
        "micronode",
        "micro-node",
        "onboard",
        "create",
        "new",
        "identity",
        "on",
        "with",
        "username",
        "me",
        "i",
        "want",
        "to",
        "please",
        "node",
    ];
    let display_name = text.split_whitespace().find(|w| {
        let w_lower = w.to_lowercase();
        let clean = w_lower.trim_matches(|c: char| !c.is_alphanumeric());
        !stop_words.contains(&clean) && clean.len() > 1
    });

    format!(
        "Join the Tenzro Network as a MicroNode\n\n\
         Zero-install — no P2P binary required.\n\
         Auto-provisions:\n\
         • A TDIP decentralized identity (DID) — did:tenzro:human:<uuid>\n\
         • A permissionless wallet (hardware-held key; no custody held)\n\
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

fn handle_payment_query(_state: &A2aState) -> String {
    "Payments & Settlement:\n\n\
     Supported protocols:\n\
     - MPP (Machine Payments Protocol) — session-based streaming payments\n\
     - x402 — stateless one-shot HTTP 402 payments\n\
     - Native TNZO transfers\n\n\
     RPC methods:\n\
     - `tenzro_createPaymentChallenge` — create a payment challenge\n\
     - `tenzro_verifyPayment` — check a credential against its challenge\n\n\
     CLI: tenzro payment challenge\n\
     MCP tools: create_payment_challenge, verify_payment"
        .to_string()
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
     TNZO moves only over governed routes, under one set of rules:\n\
     - CCIP-compatible envelope — Ethereum, Base, Arbitrum, Solana\n\
     - IBC — Cosmos chains\n\
     - Bitcoin deposits\n\
     - Contract routes — Stellar, Sui, Aptos, TON\n\n\
     RPC methods:\n\
     - `tenzro_listBridgeRoutes` / `tenzro_getBridgeRoute` — routes, caps, supply\n\
     - a signed `Bridge` outbound transaction — send TNZO out (the holder signs)\n\
     - a signed `Bridge` inbound transaction — relay a committee-attested transfer (the relayer signs and pays)\n\n\
     MCP tools: list_bridge_routes, get_bridge_route, bridge_outbound, bridge_inbound\n\
     CLI: tenzro bridge"
        .to_string()
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

/// Build the shared A2A state.
///
/// Shared by the HTTPS axum surface and the iroh-transport adapter
/// ([`crate::a2a::iroh_transport::IrohA2aDispatcher`]) so tasks created over
/// either transport land in the same task table.
pub fn build_a2a_state(node: Arc<TenzroNode>, web_state: Arc<WebState>) -> Arc<A2aState> {
    let role = node.config().roles.to_string();
    let agent_card = agent_card::build_agent_card(agent_card::card_url(node.config()), &role);

    Arc::new(A2aState {
        node,
        web_state,
        task_manager: TaskManager::new(),
        agent_card,
        signed_card: tokio::sync::Mutex::new(None),
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
    let state = build_a2a_state(node, web_state);
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
    let cors = crate::http_surface::cors_layer(&state.node.config().cors_allowed_origins);

    // Operator admission gate for the A2A surface. Captured before the state
    // is moved into the router.
    let node = state.node.clone();

    let app = Router::new()
        .route(
            agent_card::WELL_KNOWN_AGENT_CARD_PATH,
            get(agent_card_handler),
        )
        .route("/a2a", post(jsonrpc_handler))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            (node.clone(), tenzro_types::node_access::Surface::A2a),
            crate::access::http_gate,
        ))
        .layer(axum::middleware::from_fn_with_state(
            node.clone(),
            crate::inference_admission::identify_caller,
        ))
        .layer(cors)
        // EU AI Act Art. 50(1): every A2A response is the output of an
        // AI agent. Mirror the MCP-side header so peer agents see the
        // same disclosure regardless of which transport they reached us
        // through.
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
        // Concurrency limit: max 200 in-flight A2A requests.
        .layer(ConcurrencyLimitLayer::new(200))
        // Request body size limit: 2 MB.
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
    use crate::a2a::did_envelope::tests::TestSender;

    #[test]
    fn a2a_1_0_method_names_parse_and_0_x_names_do_not() {
        for name in [
            "SendMessage",
            "SendStreamingMessage",
            "GetTask",
            "ListTasks",
            "CancelTask",
            "SubscribeToTask",
            "CreateTaskPushNotificationConfig",
            "GetTaskPushNotificationConfig",
            "ListTaskPushNotificationConfigs",
            "DeleteTaskPushNotificationConfig",
            "GetExtendedAgentCard",
        ] {
            assert!(Method::parse(name).is_some(), "{name}");
        }
        for name in [
            "message/send",
            "message/stream",
            "tasks/send",
            "tasks/get",
            "tasks/cancel",
            "payments/create",
            "payments/authorize",
            "payments/execute",
            "payments/cancel",
        ] {
            assert!(Method::parse(name).is_none(), "{name}");
        }
    }

    #[test]
    fn only_version_1_0_is_spoken() {
        assert!(version_supported(Some("1.0")));
        assert!(version_supported(Some(" 1.0 ")));
        assert!(!version_supported(None));
        assert!(!version_supported(Some("")));
        assert!(!version_supported(Some("0.3")));
        assert!(!version_supported(Some("1.1")));
        assert!(!version_supported(Some("2.0")));
    }

    #[test]
    fn free_text_never_routes_to_a_mutation() {
        assert_eq!(
            classify("Transfer 100 TNZO from EVM 0xaaaa to SVM 0xbbbb"),
            Route::TokenOperations
        );
        assert_eq!(
            classify("create token called Evil (EVL) with 1000000 supply"),
            Route::TokenOperations
        );
        assert_eq!(
            classify("Deploy EVM contract bytecode 0x6080604052"),
            Route::Contract
        );
        assert_eq!(classify("check balance of 0xabc"), Route::Balance);
    }

    #[test]
    fn inbound_message_validation() {
        let parse = |v: serde_json::Value| serde_json::from_value::<InboundMessage>(v).unwrap();
        let ok = parse(serde_json::json!({
            "messageId": "m", "role": "ROLE_USER", "parts": [{"text": "hi"}]
        }));
        assert!(ok.validate().is_ok());
        let agent = parse(serde_json::json!({
            "messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "hi"}]
        }));
        assert!(agent.validate().is_err());
        let two = parse(serde_json::json!({
            "messageId": "m", "role": "ROLE_USER",
            "parts": [{"text": "hi", "url": "https://example.com"}]
        }));
        assert!(two.validate().is_err());
        let none = parse(serde_json::json!({
            "messageId": "m", "role": "ROLE_USER", "parts": [{}]
        }));
        assert!(none.validate().is_err());
        assert!(
            serde_json::from_value::<InboundMessage>(serde_json::json!({
                "messageId": "m", "role": "user", "parts": [{"text": "hi"}]
            }))
            .is_err(),
            "0.x lowercase roles are not accepted"
        );
    }

    async fn test_state() -> (Arc<A2aState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("temp dir");
        let config = crate::config::NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..crate::config::NodeConfig::default()
        };
        let node = TenzroNode::new(config).await.expect("node");
        let state = build_a2a_state(Arc::new(node), Arc::new(WebState::new()));
        (state, tmp)
    }

    fn request(method: &str, params: serde_json::Value) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: serde_json::json!(1),
        }
    }

    fn error_code(resp: &JsonRpcResponse) -> i32 {
        resp.error.as_ref().expect("an error response").code
    }

    fn send_params(parts: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "message": {"messageId": "m-1", "role": "ROLE_USER", "parts": parts}
        })
    }

    #[tokio::test]
    async fn dispatch_refuses_requests_without_a_supported_version() {
        let (state, _tmp) = test_state().await;
        let resp =
            dispatch_jsonrpc(&state, request("ListTasks", serde_json::json!({})), None).await;
        assert_eq!(error_code(&resp), VERSION_NOT_SUPPORTED);
        let resp = dispatch_jsonrpc(
            &state,
            request("ListTasks", serde_json::json!({})),
            Some("0.3"),
        )
        .await;
        assert_eq!(error_code(&resp), VERSION_NOT_SUPPORTED);
        let resp = dispatch_jsonrpc(
            &state,
            request("ListTasks", serde_json::json!({})),
            Some("1.0"),
        )
        .await;
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap()["totalSize"], 0);
    }

    /// The HTTPS route answers the unary methods with the `A2A-Version`
    /// header, refuses a message without the DID envelope, and refuses a
    /// client that sends no version.
    #[tokio::test]
    async fn the_https_route_serves_tasks_and_refuses_unsigned_messages() {
        let (state, _tmp) = test_state().await;
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let (_keep, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
        let addr = format!("127.0.0.1:{port}");
        tokio::spawn(start_a2a_server_with_shutdown(
            addr,
            state.clone(),
            shutdown_rx,
        ));
        let base = format!("http://127.0.0.1:{port}");
        let client = reqwest::Client::new();
        let mut up = false;
        for _ in 0..50 {
            if client.get(format!("{base}/a2a")).send().await.is_ok() {
                up = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(up, "the A2A server listens");

        let post = |version: Option<&'static str>, body: serde_json::Value| {
            let client = client.clone();
            let url = format!("{base}/a2a");
            async move {
                let mut r = client.post(url).json(&body);
                if let Some(v) = version {
                    r = r.header(A2A_VERSION_HEADER, v);
                }
                r.send()
                    .await
                    .unwrap()
                    .json::<serde_json::Value>()
                    .await
                    .unwrap()
            }
        };
        let list = post(
            Some("1.0"),
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"ListTasks","params":{}}),
        )
        .await;
        assert_eq!(list["result"]["totalSize"], 0, "{list}");
        let missing = post(
            Some("1.0"),
            serde_json::json!({"jsonrpc":"2.0","id":2,"method":"GetTask","params":{"id":"nope"}}),
        )
        .await;
        assert!(missing["error"].is_object(), "{missing}");
        let unsigned = post(
            Some("1.0"),
            serde_json::json!({"jsonrpc":"2.0","id":3,"method":"SendMessage","params":
                {"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"hi"}]}}}),
        )
        .await;
        assert_eq!(unsigned["error"]["code"], ENVELOPE_REJECTED, "{unsigned}");
        let unversioned = post(
            None,
            serde_json::json!({"jsonrpc":"2.0","id":4,"method":"ListTasks","params":{}}),
        )
        .await;
        assert_eq!(
            unversioned["error"]["code"], VERSION_NOT_SUPPORTED,
            "{unversioned}"
        );
        assert_eq!(state.task_manager.task_count(), 0);
    }

    #[tokio::test]
    async fn dispatch_has_no_ap2_or_0_x_methods() {
        let (state, _tmp) = test_state().await;
        for method in ["payments/execute", "payments/create", "message/send"] {
            let resp = dispatch_jsonrpc(
                &state,
                request(method, serde_json::json!({"paymentId": "p-1"})),
                Some("1.0"),
            )
            .await;
            assert_eq!(error_code(&resp), -32601, "{method}");
            assert!(resp.result.is_none());
        }
    }

    #[tokio::test]
    async fn send_message_without_an_envelope_is_refused() {
        let (state, _tmp) = test_state().await;
        let resp = dispatch_jsonrpc(
            &state,
            request(
                "SendMessage",
                send_params(serde_json::json!([{"text": "hi"}])),
            ),
            Some("1.0"),
        )
        .await;
        assert_eq!(error_code(&resp), ENVELOPE_REJECTED);
        assert_eq!(state.task_manager.task_count(), 0);
    }

    #[tokio::test]
    async fn a_message_from_an_unregistered_sender_is_refused_before_execution() {
        let (state, _tmp) = test_state().await;
        let attacker = TestSender::new("did:tenzro:human:not-registered");
        let mut params = send_params(serde_json::json!([{"text": "token balance 0x1111"}]));
        attacker.sign(
            "SendMessage",
            &mut params,
            chrono::Utc::now().timestamp_millis(),
        );
        let resp = dispatch_jsonrpc(&state, request("SendMessage", params), Some("1.0")).await;
        assert_eq!(error_code(&resp), ENVELOPE_REJECTED);
        assert_eq!(state.task_manager.task_count(), 0);
    }

    #[tokio::test]
    async fn task_cannot_be_continued_or_canceled_by_another_did() {
        let (state, _tmp) = test_state().await;
        let owner = VerifiedSender {
            did: "did:tenzro:human:owner".to_string(),
            wallet_address: tenzro_types::Address::new([1u8; 32]),
        };
        let other = VerifiedSender {
            did: "did:tenzro:human:other".to_string(),
            wallet_address: tenzro_types::Address::new([2u8; 32]),
        };
        state.task_manager.create_task(
            "t-own".to_string(),
            None,
            TaskMessage {
                message_id: "m-0".to_string(),
                role: Role::User,
                parts: vec![MessagePart::text("hello")],
            },
            Default::default(),
            &owner.did,
        );
        state
            .task_manager
            .update_status("t-own", TaskState::InputRequired, None);

        let mut params = send_params(serde_json::json!([{"text": "status"}]));
        params["message"]["taskId"] = serde_json::json!("t-own");
        match accept_message(&state, params, &serde_json::json!(1), &other).await {
            Err(resp) => assert_eq!(error_code(&resp), TASK_NOT_FOUND),
            Ok(_) => panic!("another DID continued the task"),
        }

        let resp = handle_cancel_task(
            &state,
            serde_json::json!({"id": "t-own"}),
            serde_json::json!(1),
            &other,
        );
        assert_eq!(error_code(&resp), TASK_NOT_FOUND);
        let resp = handle_cancel_task(
            &state,
            serde_json::json!({"id": "t-own"}),
            serde_json::json!(1),
            &owner,
        );
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn read_only_send_message_completes_with_a_v1_task() {
        let sender = VerifiedSender {
            did: "did:tenzro:human:reader".to_string(),
            wallet_address: tenzro_types::Address::new([3u8; 32]),
        };
        let params = || send_params(serde_json::json!([{"text": "what is the node status?"}]));

        // A node that cannot sign its records refuses the message outright.
        let (state, _tmp) = test_state().await;
        let resp = handle_send_message(&state, params(), serde_json::json!(7), &sender).await;
        assert_eq!(error_code(&resp), crate::tool_call_record::UNRECORDABLE);
        assert_eq!(state.task_manager.task_count(), 0);

        // One that can answers, and the answer leaves a signed record.
        let tmp = tempfile::tempdir().expect("temp dir");
        let mut node = TenzroNode::new(crate::config::NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..crate::config::NodeConfig::default()
        })
        .await
        .expect("node");
        let id: Arc<dyn tenzro_crypto::composite::HybridSigner> =
            Arc::new(tenzro_crypto::testing::TestHybridSigner::p256_only(40));
        node.set_record_signer(tenzro_crypto::batch::ImmediateRecordSigner::new(id));
        let state = build_a2a_state(Arc::new(node), Arc::new(WebState::new()));
        let resp = handle_send_message(&state, params(), serde_json::json!(7), &sender).await;
        let task = &resp.result.expect("result")["task"];
        assert_eq!(task["status"]["state"], "TASK_STATE_COMPLETED");
        assert_eq!(task["status"]["message"]["role"], "ROLE_AGENT");
        let log = state.node.tool_calls();
        let sessions = log.sessions_of(&sender.did).unwrap();
        let entries = log.entries(&sessions[0]).unwrap();
        let entry = entries[0].entry().unwrap();
        assert_eq!(entry.action, "message");
        assert_eq!(entry.call.unwrap().surface, "a2a");
    }
}
