//! A2A JSON-RPC dispatcher adapter for the iroh transport — Phase D2 (#223).
//!
//! Glue between [`tenzro_iroh::JsonRpcDispatcher`] (raw opaque request/response
//! bytes on a QUIC bistream) and [`super::server::dispatch_jsonrpc`] (the
//! transport-agnostic A2A method router).
//!
//! The HTTPS axum surface and this iroh-transport surface share the **same**
//! `Arc<A2aState>` — A2A tasks created over either transport land in the
//! same `TaskManager`. See [`super::server::build_a2a_state`].
//!
//! # Wire format
//!
//! Identical to the HTTPS surface: UTF-8 JSON-RPC 2.0 request/response
//! envelopes (`{"jsonrpc":"2.0","method":..,"params":..,"id":..}`). The
//! iroh transport layer adds only a `u32_LE` length prefix per frame (see
//! `tenzro_iroh::jsonrpc` for the framing).

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tenzro_iroh::{IrohError, IrohResult, JsonRpcDispatcher};

use super::server::{A2aState, JsonRpcRequest, JsonRpcResponse, dispatch_jsonrpc};

/// `JsonRpcDispatcher` impl that decodes the request body as A2A
/// JSON-RPC 2.0 and delegates to the shared `dispatch_jsonrpc` router.
pub struct IrohA2aDispatcher {
    state: Arc<A2aState>,
}

impl std::fmt::Debug for IrohA2aDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohA2aDispatcher").finish_non_exhaustive()
    }
}

impl IrohA2aDispatcher {
    /// Wrap the shared A2A state for iroh-side dispatch.
    pub fn new(state: Arc<A2aState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl JsonRpcDispatcher for IrohA2aDispatcher {
    async fn dispatch(&self, request: Bytes) -> IrohResult<Bytes> {
        // JSON parse error → JSON-RPC `-32700` envelope (per spec). Don't
        // surface this as a transport error — that would close the stream.
        let req: JsonRpcRequest = match serde_json::from_slice(&request) {
            Ok(r) => r,
            Err(e) => {
                let body =
                    serde_json::to_vec(&JsonRpcResponse::parse_error(format!("Parse error: {e}")))
                        .map_err(|e| IrohError::Backend(format!("encode parse-error: {e}")))?;
                return Ok(Bytes::from(body));
            }
        };

        let resp = dispatch_jsonrpc(&self.state, req);
        let body = serde_json::to_vec(&resp)
            .map_err(|e| IrohError::Backend(format!("encode response: {e}")))?;
        Ok(Bytes::from(body))
    }
}
