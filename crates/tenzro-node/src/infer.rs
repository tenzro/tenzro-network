//! Inference-over-iroh — the `tenzro/infer` ALPN server half.
//!
//! A node that serves an AI model over the network advertises its iroh
//! `EndpointId` in its `tenzro/models` announcement. A consumer that wants
//! to run inference against that model dials the provider's `EndpointId`
//! on the `tenzro/infer` ALPN and sends either a `tenzro_chat` JSON-RPC
//! frame or an OpenAI-shaped chat completion. This is the only way one
//! node forwards inference to another.
//!
//! [`IrohInferDispatcher`] is the server half. It forwards the inbound
//! JSON-RPC frame straight into [`crate::rpc::dispatch_embedded`], so the
//! iroh path runs the exact same handler pipeline (`tenzro_chat`, gating,
//! provenance signing) as the HTTP path, and answers an OpenAI body with the
//! status and (streamed) body of the node's own `/v1/chat/completions`
//! handler. The dispatcher needs the full `Arc<TenzroNode>` to reach that
//! pipeline, so it is installed via a [`tenzro_iroh::DeferredRequestHandler`]
//! trampoline from `main.rs` after the node `Arc` exists.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use serde_json::{Value, json};

use tenzro_iroh::{EndpointId, Reply, RequestHandler};
use tenzro_payments::middleware::InferenceAccess;
use tenzro_payments::middleware::PAYMENT_REQUIRED_OFF_HTTP as PAY_REQUIRED;

use crate::node::TenzroNode;
use crate::rpc::{EmbeddedAuth, dispatch_embedded};

/// `RequestHandler` for the `tenzro/infer` iroh ALPN.
///
/// Forwards inbound frames into the node's embedded JSON-RPC dispatcher so
/// peer inference calls run the same `tenzro_chat` handler as local HTTP
/// callers. Only inference-namespace methods are meaningful over this ALPN;
/// unknown methods fall through to the embedded dispatcher's own
/// method-not-found handling.
pub struct IrohInferDispatcher {
    node: Arc<TenzroNode>,
}

impl std::fmt::Debug for IrohInferDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohInferDispatcher")
            .finish_non_exhaustive()
    }
}

impl IrohInferDispatcher {
    /// Wrap the node for iroh-side inference dispatch.
    pub fn new(node: Arc<TenzroNode>) -> Self {
        Self { node }
    }

    /// Serve an OpenAI-shape chat completion carried on this ALPN.
    ///
    /// The request goes to [`crate::rpc::openai_chat_completions_inner`] — the
    /// same function the HTTP `/v1/chat/completions` route calls — and its
    /// status and body are returned verbatim, the body streamed as the handler
    /// produces it so a `stream: true` request is answered with its SSE.
    /// Down-converting into a `tenzro_chat` frame and re-synthesizing a
    /// completion on the way back would be a second implementation of the
    /// OpenAI shape, and would drop everything the frame shape has no slot
    /// for: tool calls, the usage block the broker meters against, and the
    /// provider's own commitment.
    async fn serve_openai(&self, payload: Value) -> Reply {
        // The access token rides at the frame's top level, the same place the
        // JSON-RPC half carries it, and the same policy the HTTP route applies
        // decides — so one gate covers both transports.
        let model = payload.get("model").and_then(|v| v.as_str());
        let did = match crate::access::iroh_caller(&self.node, &payload, INFER_ALPN).await {
            Ok(c) => c.did,
            Err(e) => {
                return openai_error(
                    401,
                    e.message,
                    tenzro_payments::middleware::refusal_code(401),
                );
            }
        };

        let admission = crate::inference_admission::NodeInferenceAdmission::for_node(&self.node);
        match admission.decide_as(
            tenzro_types::node_access::Surface::Iroh,
            did.as_deref(),
            model,
        ) {
            InferenceAccess::Allow => {}
            // This transport carries one frame each way and cannot present a
            // payment challenge. Serving the call free instead would price the
            // same model at zero here and at the operator's rate over HTTP.
            InferenceAccess::NeedPayment => {
                return openai_error(
                    402,
                    PAY_REQUIRED.to_string(),
                    tenzro_payments::middleware::refusal_code(402),
                );
            }
            InferenceAccess::Refuse(status, msg) => {
                return openai_error(
                    status,
                    msg,
                    tenzro_payments::middleware::refusal_code(status),
                );
            }
        }

        let headers = axum::http::HeaderMap::new();
        let caller = tenzro_model::access::Caller::Remote { did };

        let request: crate::rpc::OpenAIChatRequest = match serde_json::from_value(payload) {
            Ok(r) => r,
            Err(e) => {
                return openai_error(400, format!("invalid request: {e}"), "invalid_request");
            }
        };

        let response = tenzro_model::access::as_caller(
            caller,
            crate::rpc::openai_chat_completions_inner(self.node.clone(), headers, request),
        )
        .await;
        let status = response.status().as_u16();
        let mut body = response.into_body().into_data_stream();
        let (tx, rx) = tokio::sync::mpsc::channel(REPLY_CHUNKS_IN_FLIGHT);
        tokio::spawn(async move {
            while let Some(chunk) = body.next().await {
                let item = chunk.map_err(|e| e.to_string());
                let failed = item.is_err();
                if tx.send(item).await.is_err() || failed {
                    return;
                }
            }
        });
        Reply::streamed(status, rx)
    }
}

/// Body chunks buffered between the completion handler and the stream.
const REPLY_CHUNKS_IN_FLIGHT: usize = 16;

/// Longest a forwarded request read whole waits for the provider's answer.
const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Open an inference request to the provider at `endpoint_id` and return once
/// its status arrives; the body is read from the returned response.
///
/// The credential the caller addressed to this provider rides at the top of
/// the request, where both halves of this ALPN read it. A provider serving
/// `Gated` models refuses a request that carries none. The credential that
/// reaches it is one that provider issued; the caller's own token for this
/// node never leaves it.
pub(crate) async fn open_provider(
    node: &TenzroNode,
    endpoint_id: &str,
    body: &Value,
    credential: &crate::forward_billing::ProviderCredential,
) -> Result<tenzro_iroh::Response, String> {
    let resolver = node
        .iroh_resolver
        .as_ref()
        .ok_or_else(|| "this node has no network endpoint".to_string())?;
    let endpoint_id = endpoint_id
        .parse::<EndpointId>()
        .map_err(|e| format!("provider announced no usable endpoint id ({endpoint_id:?}): {e}"))?;
    let mut body = body.clone();
    if let Some(obj) = body.as_object_mut() {
        for (field, value) in [
            ("access_token", credential.access_token.as_deref()),
            ("dpop", credential.dpop.as_deref()),
        ] {
            if let Some(v) = value {
                obj.insert(field.to_string(), Value::String(v.to_string()));
            }
        }
    }
    let frame = serde_json::to_vec(&body).map_err(|e| format!("encode request: {e}"))?;
    tenzro_iroh::request(
        resolver.endpoint(),
        endpoint_id,
        tenzro_iroh::ALPN_INFER,
        &frame,
    )
    .await
    .map_err(|e| e.to_string())
}

/// The inference router's transport: carries each forwarded request over
/// `tenzro/infer` to the endpoint id its provider announced. Bound to the
/// node's endpoint once that endpoint exists; until then every forward fails
/// over.
#[derive(Debug, Default)]
pub struct RouterTransport {
    endpoint: std::sync::OnceLock<tenzro_iroh::Endpoint>,
}

impl RouterTransport {
    /// Carry requests on `endpoint` from now on.
    pub fn bind(&self, endpoint: tenzro_iroh::Endpoint) {
        let _ = self.endpoint.set(endpoint);
    }
}

#[async_trait]
impl tenzro_model::ProviderTransport for RouterTransport {
    async fn send(
        &self,
        provider: &tenzro_types::model::InferenceProvider,
        request: Vec<u8>,
    ) -> Result<(u16, Vec<u8>), String> {
        let endpoint = self
            .endpoint
            .get()
            .ok_or_else(|| "this node has no network endpoint".to_string())?;
        let id = provider
            .capacity
            .iroh_endpoint_id
            .as_deref()
            .ok_or_else(|| format!("provider {} announced no endpoint id", provider.address))?
            .parse::<EndpointId>()
            .map_err(|e| format!("provider {} endpoint id: {e}", provider.address))?;
        let response = tenzro_iroh::request(endpoint, id, tenzro_iroh::ALPN_INFER, &request)
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status;
        let body = response
            .bytes(tenzro_iroh::MAX_INFER_BYTES)
            .await
            .map_err(|e| e.to_string())?;
        Ok((status, body.to_vec()))
    }
}

/// A provider's reply body as a stream of chunks, for relaying a streamed
/// completion as it arrives.
pub(crate) fn body_stream(
    response: tenzro_iroh::Response,
) -> std::pin::Pin<Box<dyn futures::Stream<Item = Result<Bytes, String>> + Send>> {
    Box::pin(futures::stream::unfold(
        Some(response),
        |state| async move {
            let mut response = state?;
            match response.chunk().await {
                Ok(Some(bytes)) => Some((Ok(bytes), Some(response))),
                Ok(None) => None,
                Err(e) => Some((Err(e.to_string()), None)),
            }
        },
    ))
}

/// Send an inference request to the provider at `endpoint_id` and read its
/// whole answer, whatever its status: refusals arrive as encoded error bodies.
pub(crate) async fn call_provider(
    node: &TenzroNode,
    endpoint_id: &str,
    body: &Value,
    credential: &crate::forward_billing::ProviderCredential,
) -> Result<Bytes, String> {
    let exchange = async {
        let response = open_provider(node, endpoint_id, body, credential).await?;
        response
            .bytes(tenzro_iroh::MAX_INFER_BYTES)
            .await
            .map_err(|e| e.to_string())
    };
    tokio::time::timeout(CALL_TIMEOUT, exchange)
        .await
        .map_err(|_| format!("no answer within {}s", CALL_TIMEOUT.as_secs()))?
}

fn parse_error(id: Value, message: String) -> Bytes {
    let body = json!({
        "jsonrpc": "2.0",
        "error": { "code": -32700, "message": message },
        "id": id,
    });
    // Encoding a fixed-shape JSON object cannot fail; fall back to an empty
    // object rather than propagating an error that would close the stream.
    Bytes::from(serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()))
}

/// An OpenAI-shape error body, for refusals on the OpenAI half of this ALPN.
///
/// The consuming broker returns whatever the provider sent straight to its own
/// client, so a refusal has to arrive in the shape that surface speaks rather
/// than as a JSON-RPC envelope the client has no parser for.
fn openai_error(status: u16, message: String, code: &str) -> Reply {
    let body = json!({
        "error": { "message": message, "type": "invalid_request_error", "code": code },
    });
    Reply::full(
        status,
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
    )
}

/// A JSON-RPC answer. Like the HTTP JSON-RPC listener, errors travel inside
/// the envelope under a success status.
fn jsonrpc_reply(body: Bytes) -> Reply {
    Reply::full(200, body)
}

#[async_trait]
impl RequestHandler for IrohInferDispatcher {
    async fn handle(&self, remote: EndpointId, request: Bytes) -> Reply {
        // Everything on this ALPN comes from a peer, never from this machine.
        crate::admin_audit::with_origin(
            crate::admin_audit::Origin::overlay(remote.to_string()),
            crate::inference_admission::from_overlay(self.dispatch_frame(request)),
        )
        .await
    }
}

/// The ALPN this dispatcher serves, which an iroh caller's DPoP proof names.
const INFER_ALPN: &str = "tenzro/infer";

impl IrohInferDispatcher {
    async fn dispatch_frame(&self, request: Bytes) -> Reply {
        // Parse the JSON-RPC frame. A parse failure returns a -32700 error
        // envelope (per spec) rather than a transport error, so the client
        // gets a defined response instead of a closed stream.
        let payload: Value = match serde_json::from_slice(&request) {
            Ok(v) => v,
            Err(e) => {
                return jsonrpc_reply(parse_error(Value::Null, format!("{e}")));
            }
        };

        // Two request shapes travel this ALPN, told apart by whether the frame
        // names a `method`. A broker forwards whichever shape its own caller
        // sent — the Tenzro JSON-RPC frame for `tenzro_chat`, the OpenAI body
        // for `/v1/chat/completions` — and each is dispatched here through the
        // handler that already owns it. Sending only frames would mean the
        // OpenAI surface could not reach a NATed provider at all, since HTTP is
        // exactly what such a provider has no reachable address for.
        if payload.get("method").is_none() && payload.get("messages").is_some() {
            return self.serve_openai(payload).await;
        }

        // Every method meets the same access policy the JSON-RPC listener
        // applies, with the frame's access token as the caller, and an
        // inference method the same model admission as
        // `/v1/chat/completions`.
        let field = |k: &str| payload.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let did = match crate::access::iroh_caller(&self.node, &payload, INFER_ALPN).await {
            Ok(c) => c.did,
            Err(e) => {
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": payload.get("id").cloned().unwrap_or(Value::Null),
                    "error": { "code": e.code, "message": e.message },
                });
                return jsonrpc_reply(Bytes::from(
                    serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
                ));
            }
        };
        // Named for every method: the runtimes check any model a method runs.
        let caller = tenzro_model::access::Caller::Remote { did };
        let auth = EmbeddedAuth {
            authorization: field("access_token").map(|t| format!("DPoP {t}")),
            dpop: field("dpop"),
            surface: Some(tenzro_types::node_access::Surface::Iroh),
            http_method: Some("POST".to_string()),
            http_uri: Some(crate::access::iroh_htu(INFER_ALPN)),
        };

        let response =
            tenzro_model::access::as_caller(caller, dispatch_embedded(&self.node, payload, auth))
                .await;

        match serde_json::to_vec(&response) {
            Ok(body) => jsonrpc_reply(Bytes::from(body)),
            Err(e) => Reply::full(500, format!("encode infer response: {e}")),
        }
    }
}
