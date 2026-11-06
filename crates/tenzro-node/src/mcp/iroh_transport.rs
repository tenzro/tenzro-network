//! MCP-over-iroh stream handler.
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

/// Per-session MCP handler that constructs a fresh [`TenzroMcpServer`]
/// per inbound bi-stream and runs the full rmcp session loop over the
/// iroh QUIC transport.
pub struct IrohMcpHandler {
    node: Arc<TenzroNode>,
}

impl std::fmt::Debug for IrohMcpHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohMcpHandler").finish_non_exhaustive()
    }
}

impl IrohMcpHandler {
    /// Construct a handler bound to the shared node.
    pub fn new(node: Arc<TenzroNode>) -> Self {
        Self { node }
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
        // Read-only mode: this bi-stream has no credential and no verified
        // peer identity (the axum `bearer_auth_check` / `ServiceSurface::Mcp`
        // gate is HTTP-only and cannot apply here). `new_iroh` locks the
        // session to the read-only tool allowlist — every state-changing /
        // admin / operator / compute / key-management tool, and
        // `chat_completion`, is refused over iroh. Gated inference remains
        // available via the credential-gated `tenzro/infer` ALPN.
        let server = TenzroMcpServer::new_iroh(self.node.clone());

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tenzro_iroh::identity_transport::base_builder;
    use tenzro_iroh::limits::AdmissionLimits;
    use tenzro_iroh::{ALPN_MCP, McpProtocol};
    use tokio::io::{AsyncBufReadExt, BufReader};

    struct Served {
        server: tenzro_iroh::Endpoint,
        client: tenzro_iroh::Endpoint,
        router: iroh::protocol::Router,
        _tmp: tempfile::TempDir,
    }

    async fn serve(limits: AdmissionLimits) -> Served {
        let (node, tmp) = crate::bare_node().await;
        let server = base_builder().bind().await.unwrap();
        let router = iroh::protocol::Router::builder(server.clone())
            .accept(ALPN_MCP, McpProtocol::new(Arc::new(IrohMcpHandler::new(node)), limits))
            .spawn();
        let client = base_builder().bind().await.unwrap();
        Served { server, client, router, _tmp: tmp }
    }

    async fn open(s: &Served) -> (tenzro_iroh::Connection, SendStream, RecvStream) {
        let conn = s.client.connect(s.server.addr(), ALPN_MCP).await.unwrap();
        let (send, recv) = conn.open_bi().await.unwrap();
        (conn, send, recv)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_that_never_speaks_json_rpc_ends_without_an_answer() {
        let s = serve(AdmissionLimits::default()).await;
        let (_conn, mut send, mut recv) = open(&s).await;
        send.write_all(b"this is not json-rpc\n").await.unwrap();
        send.finish().unwrap();
        let rest = tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(1 << 16))
            .await
            .expect("the session ends")
            .unwrap_or_default();
        assert!(
            !String::from_utf8_lossy(&rest).contains("\"result\""),
            "no initialize result for a peer that did not initialize"
        );
        s.router.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_over_its_session_limit_has_the_extra_stream_refused() {
        let limits = AdmissionLimits {
            max_in_flight_per_peer: 1,
            ..AdmissionLimits::default()
        };
        let s = serve(limits).await;
        let conn = s.client.connect(s.server.addr(), ALPN_MCP).await.unwrap();
        // The first session is held open by a request that is never finished.
        let (mut first, _first_recv) = conn.open_bi().await.unwrap();
        first.write_all(b"{\"jsonrpc\":").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let (mut second, mut second_recv) = conn.open_bi().await.unwrap();
        second.write_all(b"{\"jsonrpc\":").await.unwrap();
        let refused = tokio::time::timeout(Duration::from_secs(10), second_recv.read_to_end(1024))
            .await
            .expect("the refusal arrives");
        assert!(refused.is_err(), "the second stream is reset, not served");
        s.router.shutdown().await.unwrap();
    }

    type Lines = tokio::io::Lines<BufReader<RecvStream>>;

    /// One open MCP session on its own bi-stream.
    struct Session {
        _conn: tenzro_iroh::Connection,
        send: SendStream,
        lines: Lines,
        next_id: u64,
    }

    async fn session(s: &Served) -> Session {
        let (conn, send, recv) = open(s).await;
        Session {
            _conn: conn,
            send,
            lines: BufReader::new(recv).lines(),
            next_id: 1,
        }
    }

    /// The per-request `_meta` of the revision `version`.
    fn meta(version: &str) -> serde_json::Value {
        serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientInfo": { "name": "test", "version": "0" },
            "io.modelcontextprotocol/clientCapabilities": {},
        })
    }

    impl Session {
        /// Send `method` with the revision's `_meta` merged into `params`
        /// and return the reply that answers it.
        async fn request(
            &mut self,
            version: &str,
            method: &str,
            mut params: serde_json::Value,
        ) -> serde_json::Value {
            params["_meta"] = meta(version);
            self.raw(method, params).await
        }

        /// Send `method` with `params` exactly as given.
        async fn raw(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
            let id = self.next_id;
            self.next_id += 1;
            let mut line = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0", "id": id, "method": method, "params": params,
            }))
            .unwrap();
            line.push(b'\n');
            self.send.write_all(&line).await.unwrap();
            loop {
                let next = tokio::time::timeout(Duration::from_secs(30), self.lines.next_line())
                    .await
                    .expect("the node answers")
                    .expect("the stream is readable")
                    .expect("the stream stays open until the answer");
                let reply: serde_json::Value = serde_json::from_str(&next).unwrap();
                if reply["id"] == id {
                    return reply;
                }
            }
        }
    }

    fn listed_versions() -> Vec<String> {
        crate::mcp::served_protocol_versions()
            .iter()
            .map(|v| v.as_str().to_string())
            .collect()
    }

    /// Every revision the node lists opens a session over iroh with
    /// `server/discover`, and the same stream then serves `tools/list`.
    #[tokio::test(flavor = "multi_thread")]
    async fn each_listed_version_opens_a_session_over_iroh() {
        let s = serve(AdmissionLimits::default()).await;
        let versions = listed_versions();
        assert!(!versions.is_empty());
        for version in &versions {
            let mut session = session(&s).await;
            let discover = session
                .request(version, "server/discover", serde_json::json!({}))
                .await;
            assert!(discover["error"].is_null(), "{version}: {discover}");
            assert_eq!(discover["result"]["resultType"], "complete", "{discover}");
            let advertised: Vec<String> = discover["result"]["supportedVersions"]
                .as_array()
                .expect("supportedVersions")
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            assert_eq!(&advertised, &versions);
            assert!(discover["result"]["capabilities"]["tools"].is_object());

            let list = session
                .request(version, "tools/list", serde_json::json!({}))
                .await;
            assert_eq!(list["result"]["resultType"], "complete", "{list}");
            let names: Vec<&str> = list["result"]["tools"]
                .as_array()
                .expect("tools")
                .iter()
                .filter_map(|t| t["name"].as_str())
                .collect();
            assert!(names.contains(&"get_node_status"), "{names:?}");
            assert!(
                !names.contains(&"register_identity"),
                "a state-changing tool is not listed over iroh"
            );
        }
        s.router.shutdown().await.unwrap();
    }

    /// The first request on a stream may be any request that carries the
    /// revision's `_meta`; no `server/discover` is needed before it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_may_open_with_tools_list() {
        let s = serve(AdmissionLimits::default()).await;
        let mut session = session(&s).await;
        let list = session
            .request(&listed_versions()[0], "tools/list", serde_json::json!({}))
            .await;
        assert!(list["result"]["tools"].as_array().is_some_and(|t| !t.is_empty()), "{list}");
        s.router.shutdown().await.unwrap();
    }

    /// `initialize` belongs to revisions the node does not speak. It is
    /// refused with -32022 naming the supported revisions and the request
    /// that opens a session, whichever version the client asks for.
    #[tokio::test(flavor = "multi_thread")]
    async fn initialize_is_refused_naming_the_supported_versions_and_the_opener() {
        let s = serve(AdmissionLimits::default()).await;
        let mut asked = listed_versions();
        asked.push("2025-11-25".to_string());
        for version in asked {
            let mut session = session(&s).await;
            let reply = session
                .raw(
                    "initialize",
                    serde_json::json!({
                        "protocolVersion": version,
                        "capabilities": {},
                        "clientInfo": { "name": "t", "version": "1" },
                    }),
                )
                .await;
            assert!(reply["result"].is_null(), "{version}: {reply}");
            assert_eq!(reply["error"]["code"], -32022, "{reply}");
            let supported: Vec<String> = reply["error"]["data"]["supported"]
                .as_array()
                .expect("the supported versions are named")
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            assert_eq!(supported, listed_versions(), "{reply}");
            assert_eq!(reply["error"]["data"]["requested"], version);
            assert_eq!(reply["error"]["data"]["opener"], "server/discover");
            assert!(
                reply["error"]["message"].as_str().unwrap().contains("server/discover"),
                "{reply}"
            );
        }
        s.router.shutdown().await.unwrap();
    }

    /// A request that names a revision the node does not speak is refused
    /// with -32022 and the list it does speak.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_for_an_unsupported_version_is_refused_naming_the_supported_ones() {
        let s = serve(AdmissionLimits::default()).await;
        let mut session = session(&s).await;
        let reply = session
            .request("2024-11-05", "tools/list", serde_json::json!({}))
            .await;
        assert_eq!(reply["error"]["code"], -32022, "{reply}");
        assert_eq!(reply["error"]["data"]["requested"], "2024-11-05");
        let supported: Vec<String> = reply["error"]["data"]["supported"]
            .as_array()
            .expect("supported")
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        assert_eq!(supported, listed_versions());
        s.router.shutdown().await.unwrap();
    }

    /// A request without the revision's `_meta` is refused as invalid
    /// params and names the missing keys.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_without_the_meta_fields_is_refused() {
        let s = serve(AdmissionLimits::default()).await;
        let mut session = session(&s).await;
        let reply = session.raw("tools/list", serde_json::json!({})).await;
        assert_eq!(reply["error"]["code"], -32602, "{reply}");
        assert!(
            reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains("io.modelcontextprotocol/protocolVersion"),
            "{reply}"
        );
        s.router.shutdown().await.unwrap();
    }

    /// A tool outside the read-only allowlist is refused over iroh before it
    /// runs: the stream carries no credential and no verified peer identity.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_state_changing_tool_call_over_iroh_is_refused() {
        let s = serve(AdmissionLimits::default()).await;
        let version = listed_versions()[0].clone();
        let mut session = session(&s).await;
        for tool in ["register_identity", "chat_completion", "not_a_tool_at_all"] {
            let reply = session
                .request(
                    &version,
                    "tools/call",
                    serde_json::json!({ "name": tool, "arguments": {} }),
                )
                .await;
            assert!(reply["result"].is_null(), "{tool}: {reply}");
            let message = reply["error"]["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("not authorized over the iroh MCP transport"),
                "{tool}: {reply}"
            );
        }
        s.router.shutdown().await.unwrap();
    }

    /// A read-only tool runs to completion over iroh.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_read_only_tool_call_over_iroh_returns_a_result() {
        let s = serve(AdmissionLimits::default()).await;
        let mut session = session(&s).await;
        let reply = session
            .request(
                &listed_versions()[0],
                "tools/call",
                serde_json::json!({ "name": "get_node_status", "arguments": {} }),
            )
            .await;
        assert!(reply["error"].is_null(), "{reply}");
        assert_eq!(reply["result"]["resultType"], "complete", "{reply}");
        assert_ne!(reply["result"]["isError"], true, "{reply}");
        s.router.shutdown().await.unwrap();
    }

    /// Resources: the event template is listed, `resources/list` answers,
    /// and a read of a URI that is not an event resource is refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn resources_are_reachable_over_iroh() {
        let s = serve(AdmissionLimits::default()).await;
        let version = listed_versions()[0].clone();
        let mut session = session(&s).await;
        let templates = session
            .request(&version, "resources/templates/list", serde_json::json!({}))
            .await;
        let found = templates["result"]["resourceTemplates"]
            .as_array()
            .is_some_and(|t| t.iter().any(|t| t["name"] == "chain-events"));
        assert!(found, "{templates}");
        let list = session
            .request(&version, "resources/list", serde_json::json!({}))
            .await;
        assert!(list["result"]["resources"].is_array(), "{list}");
        let read = session
            .request(
                &version,
                "resources/read",
                serde_json::json!({ "uri": "file:///etc/passwd" }),
            )
            .await;
        assert!(read["result"].is_null(), "{read}");
        assert!(read["error"]["code"].is_i64(), "{read}");
        s.router.shutdown().await.unwrap();
    }
}
