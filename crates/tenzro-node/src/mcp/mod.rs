pub mod auth_page;
pub mod client_metadata;
mod compact;
pub(crate) mod event_resources;
pub mod iroh_transport;
pub mod oauth;
mod rpc_tools;
pub mod server;
mod tool_types_access;
mod tool_types_catalog;
mod tool_types_chain;
mod tool_types_models;
mod tool_types_payments;

use rmcp::model::ProtocolVersion;
use rmcp::transport::streamable_http_server::StreamableHttpServerConfig;

/// The one MCP revision every server on this node speaks.
pub(crate) fn served_protocol_versions() -> std::borrow::Cow<'static, [ProtocolVersion]> {
    std::borrow::Cow::Borrowed(&[ProtocolVersion::V_2026_07_28])
}

/// The refusal an `initialize` request receives. Revision 2026-07-28 has no
/// `initialize` handshake: a session opens with `server/discover`, or with any
/// request carrying the revision's `_meta` (`io.modelcontextprotocol/protocolVersion`
/// and `io.modelcontextprotocol/clientCapabilities`). Every revision this node
/// serves is one of those, so no `initialize` can be answered; the error names
/// the supported revisions and the request that opens a session.
pub(crate) fn initialize_refused(requested: &ProtocolVersion) -> rmcp::ErrorData {
    rmcp::ErrorData::new(
        rmcp::model::ErrorCode::UNSUPPORTED_PROTOCOL_VERSION,
        "Unsupported protocol version: initialize is not part of the revisions this \
         server speaks; open the session with server/discover or any request that \
         carries the io.modelcontextprotocol/protocolVersion and \
         io.modelcontextprotocol/clientCapabilities _meta",
        Some(serde_json::json!({
            "requested": requested,
            "supported": served_protocol_versions(),
            "opener": "server/discover",
        })),
    )
}

/// Streamable HTTP settings shared by every MCP server on this node:
/// stateless (no session endpoints), JSON replies, and the revision's
/// per-request `_meta` required on every request.
pub(crate) fn http_config(allowed_hosts: Vec<String>) -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_stateless_protocol_metadata_required(true)
        .with_json_response(true)
        .with_allowed_hosts(allowed_hosts)
}
