//! MCP-over-iroh stream handler — Phase D2 follow-up to #223.
//!
//! Bridges [`tenzro_iroh::McpStreamHandler`] (per-bistream session
//! contract) into rmcp 1.7's `ServiceExt::serve(transport)` API. Each
//! inbound iroh bi-stream becomes a full MCP session: Initialize
//! handshake → `tools/list` → `tools/call` → server notifications →
//! Shutdown, run against a freshly-constructed [`TenzroMcpServer`].
//!
//! # Why not the request/response trampoline?
//!
//! MCP is not request/response — it is a session-bound bidirectional
//! JSON-RPC channel with a mandatory `initialize` handshake and
//! server-initiated notifications. The
//! [`JsonRpcDispatcher`](tenzro_iroh::JsonRpcDispatcher) trampoline used
//! by A2A reads one frame and writes one frame per stream, which would
//! force the client to renegotiate the Initialize handshake for every
//! tool call. Instead we treat each iroh bi-stream as a full session and
//! feed it to rmcp via the `AsyncRwTransport` adapter (line-delimited
//! JSON, the same wire format rmcp uses for stdio MCP servers).
//!
//! # Wire format
//!
//! Newline-delimited JSON-RPC 2.0 messages per rmcp's `AsyncRwTransport`
//! contract: `<json-rpc-message>\n<json-rpc-message>\n...`. This is the
//! stdio/socket MCP wire format spec'd by MCP itself — clients
//! connecting over iroh can reuse the same parser as their stdio MCP
//! clients, only swapping the transport.

use std::sync::Arc;

use async_trait::async_trait;
use rmcp::ServiceExt;
use tenzro_iroh::{IrohError, IrohResult, McpStreamHandler, RecvStream, SendStream};
use tracing::{debug, warn};

use super::server::TenzroMcpServer;
use crate::node::TenzroNode;
use crate::web::handlers::WebState;

/// Per-session MCP handler that constructs a fresh [`TenzroMcpServer`]
/// per inbound bi-stream and runs the full rmcp session loop over the
/// iroh QUIC transport.
pub struct IrohMcpHandler {
    node: Arc<TenzroNode>,
    web_state: Arc<WebState>,
}

impl std::fmt::Debug for IrohMcpHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohMcpHandler").finish_non_exhaustive()
    }
}

impl IrohMcpHandler {
    /// Construct a handler bound to the shared node + web state.
    pub fn new(node: Arc<TenzroNode>, web_state: Arc<WebState>) -> Self {
        Self { node, web_state }
    }
}

#[async_trait]
impl McpStreamHandler for IrohMcpHandler {
    async fn serve_stream(self: Arc<Self>, send: SendStream, recv: RecvStream) -> IrohResult<()> {
        debug!(
            target: "tenzro_node::mcp::iroh_transport",
            "starting MCP session over iroh bi-stream",
        );

        // rmcp's `AsyncRwTransport` consumes a `(R: AsyncRead, W: AsyncWrite)`
        // pair and produces a `Transport<RoleServer>` that line-delimits
        // JSON-RPC messages. iroh's `RecvStream` / `SendStream` already
        // implement `tokio::io::AsyncRead` / `AsyncWrite` (via noq, iroh's
        // quinn fork) — no adapter shim needed.
        let server = TenzroMcpServer::new(self.node.clone(), self.web_state.clone());

        // `ServiceExt::serve(transport)` runs the rmcp Initialize handshake,
        // then awaits inbound `tools/call` etc. concurrently with whatever
        // notifications the server emits. Returns a `RunningService` once
        // initialize succeeds.
        let running = server
            .serve((recv, send))
            .await
            .map_err(|e| IrohError::Backend(format!("rmcp serve init: {e}")))?;

        // Block until the peer closes the session or the transport errors.
        // `RunningService::waiting()` returns the QuitReason; we don't care
        // about the discriminator on this path — the stream is already
        // closed by the time we get here.
        match running.waiting().await {
            Ok(reason) => {
                debug!(
                    target: "tenzro_node::mcp::iroh_transport",
                    ?reason,
                    "MCP session over iroh closed cleanly",
                );
                Ok(())
            }
            Err(e) => {
                warn!(
                    target: "tenzro_node::mcp::iroh_transport",
                    error = %e,
                    "MCP session over iroh terminated with error",
                );
                Err(IrohError::Backend(format!("rmcp serve: {e}")))
            }
        }
    }
}
