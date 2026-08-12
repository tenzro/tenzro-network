//! Inference-over-iroh — the `tenzro/infer` ALPN server half.
//!
//! A node that serves an AI model over the network advertises its iroh
//! `EndpointId` in its `tenzro/models` announcement. A consumer that wants
//! to run inference against that model dials the provider's `EndpointId`
//! on the `tenzro/infer` ALPN and sends a `tenzro_chat` JSON-RPC frame,
//! rather than HTTP-POSTing to the provider's `rpc_endpoint` — which is a
//! loopback address on every NATed or non-RPC-public node and is therefore
//! never peer-reachable.
//!
//! [`IrohInferDispatcher`] is the server half. It forwards the inbound
//! JSON-RPC frame straight into [`crate::rpc::dispatch_embedded`], so the
//! iroh path runs the exact same handler pipeline (`tenzro_chat`, gating,
//! provenance signing) as the HTTP path. The dispatcher needs the full
//! `Arc<TenzroNode>` to reach that pipeline, so — like the A2A/MCP
//! dispatchers — it is installed via a [`tenzro_iroh::DeferredJsonRpcDispatcher`]
//! trampoline from `main.rs` after the node `Arc` exists.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::{Value, json};

use tenzro_iroh::{IrohError, IrohResult, JsonRpcDispatcher};
use tenzro_payments::middleware::InferenceAccess;

use crate::node::TenzroNode;
use crate::rpc::{EmbeddedAuth, dispatch_embedded};

/// `JsonRpcDispatcher` for the `tenzro/infer` iroh ALPN.
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

#[async_trait]
impl JsonRpcDispatcher for IrohInferDispatcher {
    async fn dispatch(&self, request: Bytes) -> IrohResult<Bytes> {
        // Parse the JSON-RPC frame. A parse failure returns a -32700 error
        // envelope (per spec) rather than a transport error, so the client
        // gets a defined response instead of a closed stream.
        let payload: Value = match serde_json::from_slice(&request) {
            Ok(v) => v,
            Err(e) => {
                return Ok(parse_error(Value::Null, format!("{e}")));
            }
        };

        // The inference methods (`tenzro_chat` / `tenzro_chatCompletion`) are
        // credential-gated exactly like the HTTP `/chat` path: a peer dialing
        // this ALPN must present the same subscription api-key / rental
        // service-key to reach a `Gated` model. Other methods pass through
        // unchanged as an unauthenticated read surface.
        let method = payload.get("method").and_then(|m| m.as_str());
        let is_inference =
            matches!(method, Some("tenzro_chat") | Some("tenzro_chatCompletion"));

        let mut auth = EmbeddedAuth::default();

        if is_inference {
            // Credentials + model id ride in the JSON-RPC frame (fixed client
            // contract): top-level `api_key` / `service_key`, model at
            // `params.model` (or `params.model_id`).
            let api_key = payload.get("api_key").and_then(|v| v.as_str());
            let service_key = payload.get("service_key").and_then(|v| v.as_str());
            let model = payload
                .get("params")
                .and_then(|p| p.get("model").or_else(|| p.get("model_id")))
                .and_then(|v| v.as_str());

            // Run the SAME admission policy as the HTTP gate
            // (`NodeInferenceAdmission`), reading the credential from the frame.
            let admission = crate::inference_admission::NodeInferenceAdmission {
                node: self.node.clone(),
                gated_on_demand_fallback: self.node.config().payments.gated_on_demand_fallback,
            };
            match admission.decide_creds(api_key, service_key, model) {
                // Allow: pre-paid/pre-authorized credential. NeedPayment: open
                // `Network` model. x402-over-overlay is not implemented yet, so
                // open models are served without payment over the overlay for
                // now; only the gated-credential gate is enforced here.
                InferenceAccess::Allow | InferenceAccess::NeedPayment => {}
                // Refuse: gated model without a valid credential, or
                // private/unknown model. Return a JSON-RPC error frame.
                InferenceAccess::Refuse(_status, msg) => {
                    let id = payload.get("id").cloned().unwrap_or(Value::Null);
                    let body = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32001, "message": msg },
                    });
                    return Ok(Bytes::from(
                        serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
                    ));
                }
            }

            // Thread the api-key into EmbeddedAuth so downstream scope gates in
            // the embedded pipeline also see the credential.
            auth = EmbeddedAuth {
                api_key: api_key.map(|s| s.to_string()),
                ..EmbeddedAuth::default()
            };
        }

        let response = dispatch_embedded(&self.node, payload, auth).await;

        serde_json::to_vec(&response)
            .map(Bytes::from)
            .map_err(|e| IrohError::Backend(format!("encode infer response: {e}")))
    }
}
