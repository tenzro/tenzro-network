//! JSON-RPC 2.0 transport over an iroh QUIC endpoint — Phase D2 (#223).
//!
//! Adds two new ALPNs to the shared iroh endpoint already owned by
//! [`IrohBackedResolver`](crate::IrohBackedResolver) so A2A and MCP traffic
//! can ride the same NAT-traversing QUIC + Pkarr-discovery substrate as
//! iroh-blobs, in addition to the existing HTTPS surfaces:
//!
//! - `tenzro/a2a` — A2A protocol JSON-RPC 2.0 (peer-to-peer agent
//!   messaging — mirrors `POST /a2a` on `a2a.tenzro.network`)
//! - `tenzro/mcp`  — MCP Streamable HTTP JSON-RPC 2.0 (tool invocation —
//!   mirrors `POST /mcp` on `mcp.tenzro.network`)
//!
//! # Why not `irpc`?
//!
//! `irpc` (0.15) is the n0 framework for rust-to-rust message-typed RPC
//! over iroh streams, with postcard serialization and per-request enum
//! dispatch. It's a great fit when the wire shape is your own typed
//! Rust enum, but for A2A and MCP we already have a settled JSON-RPC 2.0
//! contract (`{jsonrpc, method, params, id}`) and a working axum dispatcher
//! that handles serialization end-to-end. Wrapping that in irpc would
//! re-serialize the same payload twice (JSON → typed enum → postcard →
//! wire) and tie the wire format to a Rust-specific framework, which
//! breaks the cross-language interop story that JSON-RPC 2.0 gives us
//! for free (Python A2A clients, browser MCP clients, etc.).
//!
//! Instead, we use the same length-prefixed-frame-on-an-iroh-bistream
//! pattern that `irpc` uses internally, but we carry the JSON-RPC bytes
//! opaquely. This keeps the wire format identical to what HTTPS clients
//! already speak — only the transport changes.
//!
//! # Wire format
//!
//! Each bidirectional QUIC stream carries exactly one JSON-RPC
//! request/response round-trip:
//!
//! ```text
//!   client → server:  u32_LE(req_len) || req_bytes
//!   server → client:  u32_LE(resp_len) || resp_bytes
//! ```
//!
//! `req_bytes` is the UTF-8 JSON-RPC 2.0 request envelope; `resp_bytes`
//! is the JSON-RPC 2.0 response envelope. Both sides finish their write
//! after the body and close their respective stream half. Per-stream
//! frame size is capped at [`MAX_FRAME_BYTES`] to avoid resource
//! exhaustion from a hostile peer.
//!
//! Streaming RPCs (A2A `tasks/stream`, MCP server-sent notifications)
//! are not yet carried over this transport — they remain on the HTTPS
//! SSE surface until follow-up work shapes them around iroh's native
//! bidirectional streams.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use iroh::{
    endpoint::{Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
    Endpoint, EndpointId,
};
use parking_lot::RwLock;
use tracing::{debug, trace, warn};

use crate::error::{IrohError, IrohResult};

/// ALPN for A2A JSON-RPC 2.0 over iroh.
///
/// Per `feedback_no_version_prefix_in_identifiers`, no version segment is
/// embedded in this string — the namespace owns the wire-format contract.
pub const ALPN_A2A: &[u8] = b"tenzro/a2a";

/// ALPN for MCP JSON-RPC 2.0 over iroh.
pub const ALPN_MCP: &[u8] = b"tenzro/mcp";

/// Hard cap on a single JSON-RPC frame (request or response).
///
/// 4 MiB matches the per-message ceiling used by the libp2p gossipsub
/// transport (`crate::network::*`) — large enough to fit a fat MCP tool
/// response with embedded base64 payloads, small enough that a single
/// hostile peer cannot allocate gigabytes from one accept.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Opaque JSON-RPC 2.0 dispatcher.
///
/// Implementations receive the raw JSON-RPC request bytes (no decoding
/// applied at the transport layer) and return the raw response bytes.
/// The transport never inspects the envelope — that's the dispatcher's
/// job. This keeps `tenzro-iroh` free of any A2A or MCP method
/// definitions; the wire stays decoupled from the methods.
#[async_trait]
pub trait JsonRpcDispatcher: Send + Sync + std::fmt::Debug + 'static {
    /// Dispatch a single JSON-RPC request and return the response bytes.
    ///
    /// Implementations should never panic — JSON parse errors and unknown
    /// methods must be encoded as JSON-RPC error responses per the spec
    /// (`{"jsonrpc":"2.0","error":{"code":-32600,...},"id":...}`).
    /// Returning `Err` here closes the QUIC stream with a transport-level
    /// error code; do that only for unrecoverable transport-layer faults.
    async fn dispatch(&self, request: Bytes) -> IrohResult<Bytes>;
}

/// Trampoline dispatcher whose backing implementation can be swapped in
/// after the iroh router has already been spawned.
///
/// `iroh::protocol::Router` sets all ALPNs at `spawn()` time and a second
/// `Router` on the same endpoint would overwrite the first router's ALPNs.
/// That forces us to register every ALPN at bind time. But the node-side
/// A2A / MCP state (`Arc<A2aState>`, `Arc<TenzroNode>`) is only available
/// *after* the iroh resolver has been bound — chicken-and-egg.
///
/// `DeferredJsonRpcDispatcher` resolves the cycle: it can be constructed
/// empty, registered with `JsonRpcProtocol::a2a` / `::mcp` at bind time,
/// then have its real backing dispatcher installed via [`Self::set`]
/// later. Until that happens, calls return a JSON-RPC `-32603` (server
/// not ready) error so peers see a defined response rather than a hung
/// stream.
#[derive(Debug, Clone)]
pub struct DeferredJsonRpcDispatcher {
    inner: Arc<RwLock<Option<Arc<dyn JsonRpcDispatcher>>>>,
    /// Surfaces in log lines + the JSON-RPC error envelope so operators
    /// can tell A2A-not-yet-ready from MCP-not-yet-ready.
    label: &'static str,
}

impl DeferredJsonRpcDispatcher {
    /// Create an unbound dispatcher. `label` is purely a log/error tag
    /// (e.g. `"a2a"` / `"mcp"`).
    pub fn new(label: &'static str) -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
            label,
        }
    }

    /// Install the real backing dispatcher. Idempotent — subsequent calls
    /// overwrite the previous binding (useful for tests and live
    /// reconfiguration).
    pub fn set(&self, dispatcher: Arc<dyn JsonRpcDispatcher>) {
        *self.inner.write() = Some(dispatcher);
    }

    /// Has a real dispatcher been installed?
    pub fn is_ready(&self) -> bool {
        self.inner.read().is_some()
    }
}

#[async_trait]
impl JsonRpcDispatcher for DeferredJsonRpcDispatcher {
    async fn dispatch(&self, request: Bytes) -> IrohResult<Bytes> {
        let backing = self.inner.read().clone();
        match backing {
            Some(d) => d.dispatch(request).await,
            None => {
                // Server-not-ready: encode as a JSON-RPC `-32603` envelope
                // so peers see a real response. The request `id` is
                // unparseable here without round-tripping the body; use
                // `null` per JSON-RPC 2.0 §5.1 ("If there was an error
                // in detecting the id ... it MUST be Null").
                let body = format!(
                    "{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":-32603,\"message\":\"{label} dispatcher not yet bound\"}},\"id\":null}}",
                    label = self.label,
                );
                Ok(Bytes::from(body))
            }
        }
    }
}

/// `iroh::ProtocolHandler` adapter that turns an inbound QUIC connection
/// into a stream of JSON-RPC 2.0 request/response pairs.
///
/// One `JsonRpcProtocol` is registered per ALPN
/// ([`ALPN_A2A`] / [`ALPN_MCP`]) on the shared
/// [`IrohBackedResolver`](crate::IrohBackedResolver) endpoint. Multiple
/// concurrent peers may open bidirectional streams against the same ALPN
/// — each stream is dispatched on its own tokio task.
#[derive(Debug, Clone)]
pub struct JsonRpcProtocol {
    dispatcher: Arc<dyn JsonRpcDispatcher>,
    alpn_label: &'static str,
}

impl JsonRpcProtocol {
    /// Wrap a dispatcher for the A2A ALPN.
    pub fn a2a(dispatcher: Arc<dyn JsonRpcDispatcher>) -> Self {
        Self {
            dispatcher,
            alpn_label: "a2a",
        }
    }

    /// Wrap a dispatcher for the MCP ALPN.
    pub fn mcp(dispatcher: Arc<dyn JsonRpcDispatcher>) -> Self {
        Self {
            dispatcher,
            alpn_label: "mcp",
        }
    }
}

impl ProtocolHandler for JsonRpcProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        debug!(
            target: "tenzro_iroh::jsonrpc",
            alpn = self.alpn_label,
            remote = %remote,
            "accepted iroh JSON-RPC connection",
        );

        loop {
            let (send, recv) = match conn.accept_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    trace!(
                        target: "tenzro_iroh::jsonrpc",
                        alpn = self.alpn_label,
                        error = %e,
                        "remote closed connection",
                    );
                    return Ok(());
                }
            };

            let dispatcher = self.dispatcher.clone();
            let alpn = self.alpn_label;
            tokio::spawn(async move {
                if let Err(e) = handle_stream(send, recv, dispatcher).await {
                    warn!(
                        target: "tenzro_iroh::jsonrpc",
                        alpn,
                        error = %e,
                        "iroh JSON-RPC stream dispatch failed",
                    );
                }
            });
        }
    }
}

/// Server-side per-stream handler: read one length-prefixed request,
/// dispatch, write one length-prefixed response.
async fn handle_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    dispatcher: Arc<dyn JsonRpcDispatcher>,
) -> IrohResult<()> {
    let req = read_frame(&mut recv).await?;
    let resp = dispatcher.dispatch(req).await?;
    write_frame(&mut send, &resp).await?;
    send.finish()
        .map_err(|e| IrohError::Backend(format!("send.finish: {e}")))?;
    Ok(())
}

/// Read a single `u32_LE(len) || body` frame from a QUIC RecvStream.
async fn read_frame(recv: &mut RecvStream) -> IrohResult<Bytes> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| IrohError::Backend(format!("read len: {e}")))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(IrohError::Backend(format!(
            "frame too large: {len} > {MAX_FRAME_BYTES}"
        )));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(|e| IrohError::Backend(format!("read body: {e}")))?;
    Ok(Bytes::from(body))
}

/// Write a single `u32_LE(len) || body` frame to a QUIC SendStream.
async fn write_frame(send: &mut SendStream, body: &[u8]) -> IrohResult<()> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(IrohError::Backend(format!(
            "frame too large: {} > {MAX_FRAME_BYTES}",
            body.len()
        )));
    }
    let len = (body.len() as u32).to_le_bytes();
    send.write_all(&len)
        .await
        .map_err(|e| IrohError::Backend(format!("write len: {e}")))?;
    send.write_all(body)
        .await
        .map_err(|e| IrohError::Backend(format!("write body: {e}")))?;
    Ok(())
}

/// MCP-over-iroh per-stream handler trait.
///
/// MCP (Model Context Protocol) is *not* a request/response protocol — it is
/// a session-bound bidirectional JSON-RPC channel (Initialize handshake,
/// `tools/list`, `tools/call`, server-initiated notifications, etc.). The
/// [`JsonRpcDispatcher`] one-shot trampoline above is sufficient for A2A's
/// `message/send` / `tasks/send` request/response shape but throws away
/// MCP's session state after a single round-trip.
///
/// `McpStreamHandler` is the alternative: instead of reading a single
/// length-prefixed request and writing a single response, the handler is
/// handed the *raw bidirectional QUIC stream pair* and runs the full
/// rmcp `ServerHandler::serve(transport)` loop over it for the lifetime
/// of the stream.
///
/// Implemented in `tenzro-node::mcp::iroh_transport::IrohMcpHandler`,
/// which adapts iroh `(SendStream, RecvStream)` into rmcp's
/// `AsyncRwTransport` (line-delimited JSON-RPC) and feeds it into
/// `TenzroMcpServer::serve(...)`. Keeping the trait here keeps
/// `tenzro-iroh` rmcp-free.
#[async_trait]
pub trait McpStreamHandler: Send + Sync + std::fmt::Debug + 'static {
    /// Run a full MCP session over one iroh bi-stream.
    ///
    /// The handler owns the stream for its full lifetime — it runs the
    /// rmcp Initialize handshake, dispatches inbound tool calls, emits
    /// notifications, and finally closes both stream halves when the
    /// session terminates. Returning `Err` aborts the session with a
    /// QUIC-level reset; clean session termination should return `Ok(())`.
    async fn serve_stream(
        self: Arc<Self>,
        send: SendStream,
        recv: RecvStream,
    ) -> IrohResult<()>;
}

/// `iroh::ProtocolHandler` adapter for MCP-over-iroh.
///
/// Unlike [`JsonRpcProtocol`] (which runs the one-shot
/// [`JsonRpcDispatcher`] per stream), `McpProtocol` accepts inbound
/// bi-streams and hands each to an [`McpStreamHandler`] for the full
/// rmcp session lifecycle (Initialize → tools/list → tools/call →
/// notifications → Shutdown).
///
/// Each stream is a fresh MCP session, served on its own tokio task so
/// concurrent peers / concurrent sessions from the same peer never block
/// each other.
#[derive(Debug, Clone)]
pub struct McpProtocol {
    handler: Arc<dyn McpStreamHandler>,
}

impl McpProtocol {
    /// Wrap an [`McpStreamHandler`] for registration under [`ALPN_MCP`].
    pub fn new(handler: Arc<dyn McpStreamHandler>) -> Self {
        Self { handler }
    }
}

impl ProtocolHandler for McpProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        debug!(
            target: "tenzro_iroh::jsonrpc",
            alpn = "mcp",
            remote = %remote,
            "accepted iroh MCP connection",
        );

        loop {
            let (send, recv) = match conn.accept_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    trace!(
                        target: "tenzro_iroh::jsonrpc",
                        alpn = "mcp",
                        error = %e,
                        "remote closed MCP connection",
                    );
                    return Ok(());
                }
            };

            let handler = self.handler.clone();
            tokio::spawn(async move {
                if let Err(e) = handler.serve_stream(send, recv).await {
                    warn!(
                        target: "tenzro_iroh::jsonrpc",
                        alpn = "mcp",
                        error = %e,
                        "iroh MCP session terminated with error",
                    );
                }
            });
        }
    }
}

/// Deferred [`McpStreamHandler`] trampoline — same chicken-and-egg
/// resolution as [`DeferredJsonRpcDispatcher`].
///
/// Allows `IrohBackedResolver::bind_with_jsonrpc` to register the
/// `tenzro/mcp` ALPN at bind time before `TenzroMcpServer` (which needs
/// `Arc<TenzroNode>`) is constructible. Calls before [`Self::set`] is
/// invoked close the stream cleanly without serving an MCP session.
#[derive(Debug, Clone)]
pub struct DeferredMcpHandler {
    inner: Arc<RwLock<Option<Arc<dyn McpStreamHandler>>>>,
}

impl DeferredMcpHandler {
    /// Create an unbound handler.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
        }
    }

    /// Install the real backing handler. Idempotent.
    pub fn set(&self, handler: Arc<dyn McpStreamHandler>) {
        *self.inner.write() = Some(handler);
    }

    /// Has a real handler been installed?
    pub fn is_ready(&self) -> bool {
        self.inner.read().is_some()
    }
}

impl Default for DeferredMcpHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl McpStreamHandler for DeferredMcpHandler {
    async fn serve_stream(
        self: Arc<Self>,
        mut send: SendStream,
        _recv: RecvStream,
    ) -> IrohResult<()> {
        let backing = self.inner.read().clone();
        match backing {
            Some(h) => h.serve_stream(send, _recv).await,
            None => {
                // Server-not-ready: emit a single JSON-RPC error line in
                // rmcp's `AsyncRwTransport` wire format (newline-delimited
                // JSON) and close the stream so the client gets a defined
                // failure rather than a hung session.
                let body = b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"mcp handler not yet bound\"},\"id\":null}\n";
                let _ = send.write_all(body).await;
                let _ = send.finish();
                Ok(())
            }
        }
    }
}

/// Client-side JSON-RPC-over-iroh caller.
///
/// Opens a bidirectional stream against `remote` on the given ALPN,
/// writes the request, reads the response, closes the stream. One stream
/// per call — concurrent calls open independent streams over the same
/// QUIC connection (iroh multiplexes them).
pub async fn call(
    endpoint: &Endpoint,
    remote: EndpointId,
    alpn: &[u8],
    request: Bytes,
) -> IrohResult<Bytes> {
    let conn = endpoint
        .connect(remote, alpn)
        .await
        .map_err(|e| IrohError::Backend(format!("connect: {e}")))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| IrohError::Backend(format!("open_bi: {e}")))?;
    write_frame(&mut send, &request).await?;
    send.finish()
        .map_err(|e| IrohError::Backend(format!("send.finish: {e}")))?;
    let resp = read_frame(&mut recv).await?;
    conn.close(0u32.into(), b"done");
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{endpoint::presets, Endpoint};
    use iroh::protocol::Router;

    #[derive(Debug)]
    struct EchoDispatcher;

    #[async_trait]
    impl JsonRpcDispatcher for EchoDispatcher {
        async fn dispatch(&self, request: Bytes) -> IrohResult<Bytes> {
            // Pretend to be a JSON-RPC server that echoes the params back
            // in `result`. Real dispatchers (A2A / MCP) plug their full
            // method-match table in here.
            let body = format!(
                "{{\"jsonrpc\":\"2.0\",\"result\":{},\"id\":1}}",
                std::str::from_utf8(&request).unwrap_or("null")
            );
            Ok(Bytes::from(body))
        }
    }

    #[tokio::test]
    async fn roundtrip_jsonrpc_over_iroh() {
        // Server side: bind endpoint, accept A2A ALPN.
        let server_ep = Endpoint::bind(presets::N0).await.unwrap();
        let server_id = server_ep.id();
        let proto = JsonRpcProtocol::a2a(Arc::new(EchoDispatcher));
        let _router = Router::builder(server_ep.clone())
            .accept(ALPN_A2A, proto)
            .spawn();

        // Client side: separate endpoint, call() against the server.
        let client_ep = Endpoint::bind(presets::N0).await.unwrap();
        let req = Bytes::from_static(b"null");
        let resp = call(&client_ep, server_id, ALPN_A2A, req).await.unwrap();
        let resp_str = std::str::from_utf8(&resp).unwrap();
        assert!(resp_str.contains("\"jsonrpc\":\"2.0\""));
        assert!(resp_str.contains("\"id\":1"));
    }
}
