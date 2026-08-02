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

        // Peer calls carry no operator/tenant credentials — inference is an
        // unauthenticated read surface. The embedded dispatcher applies its
        // own gates; `tenzro_chat` needs none.
        let response = dispatch_embedded(&self.node, payload, EmbeddedAuth::default()).await;

        serde_json::to_vec(&response)
            .map(Bytes::from)
            .map_err(|e| IrohError::Backend(format!("encode infer response: {e}")))
    }
}
