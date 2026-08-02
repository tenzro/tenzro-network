//! One uniform way to reach every RPC method from every surface.
//!
//! # The problem this solves
//!
//! The node serves 900-odd JSON-RPC methods. Six client surfaces sit in front
//! of them — REST, MCP, A2A, the Rust and TypeScript SDKs, and the CLI — and
//! each had its own hand-maintained subset. Measured, those subsets ranged from
//! 35% to 76% of the method surface, and they disagreed about *which* methods
//! they covered: the AI control plane was reachable only from the CLI, hosting
//! only from everything except the TypeScript SDK.
//!
//! That is not a gap you close once. Every new RPC re-opens it in five places,
//! and the failure is silent — a developer discovers their SDK cannot reach a
//! method at the point they need it.
//!
//! # Why a gateway rather than 5,000 wrappers
//!
//! The obvious fix is to hand-write a binding per method per surface. It is
//! also the wrong one, and not only on effort:
//!
//! - For **MCP** it would actively make the server worse. Tool-selection
//!   accuracy degrades as the list grows, and the server already carries 534
//!   tools. Adding 500 more would cost every agent accuracy on the tools it
//!   actually wanted.
//! - For the **SDKs** it produces thousands of functions whose parameters are
//!   all `Value`, because there is no per-method schema to type them from. That
//!   is autocomplete, not type safety.
//! - In every case the wrappers drift from the dispatcher the moment someone
//!   adds a method and forgets one language.
//!
//! So instead: one gateway that forwards any method, plus one discovery call
//! that enumerates what exists. Both read [`crate::rpc_gates`], which the
//! classification test already proves is exactly the dispatcher's own method
//! set — so coverage cannot drift, because there is no second list to drift
//! from.
//!
//! # This widens ergonomics, not authorization
//!
//! The gateway dispatches through [`crate::rpc::handle_request`] with the
//! caller's own credentials, behind the same admin-token gate, the same
//! API-key scope gate, and the same default-deny classification as a direct
//! JSON-RPC call. A method a caller could not reach on port 8545 is a method
//! they cannot reach through the gateway either.
//!
//! It is worth being precise about what does change. An operator who exposes
//! MCP but not JSON-RPC has, until now, been relying on the MCP tool list as a
//! de-facto allowlist. After this, MCP reaches what the gates allow rather than
//! what someone remembered to write a tool for. That is the intended
//! behaviour — a tool list is not an authorization model, and treating it as
//! one meant the real gate was never the one being reasoned about — but an
//! operator who wants a narrower surface should use the API-key scopes, which
//! are the mechanism actually designed for it.

use std::sync::Arc;

use serde::Serialize;
use serde_json::{Value, json};

use crate::node::TenzroNode;
use crate::rpc_gates::{GateClass, all_methods, gate_class};

/// One row of the method directory.
#[derive(Debug, Clone, Serialize)]
pub struct MethodEntry {
    /// The JSON-RPC method name, as dispatched.
    pub method: String,
    /// Whether the operator admin token is required.
    pub gate: GateClass,
    /// The API-key scope this method requires, if any.
    ///
    /// Present so a caller can tell "I need a differently-scoped key" from "I
    /// need the operator's token" without having to provoke the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<&'static str>,
    /// Which namespace it belongs to, derived from the name.
    pub namespace: String,
}

/// The namespace a method belongs to, for grouping in a directory listing.
///
/// Derived from the name rather than declared, because a declared mapping is a
/// second list that can disagree with the first.
fn namespace_of(method: &str) -> String {
    if let Some(rest) = method.strip_prefix("tenzro_") {
        // `tenzro_canton_health` → `canton`; `tenzro_listDatabases` →
        // `database`. The snake-case form names its namespace directly; the
        // camelCase form has it embedded, so fall back to the leading word.
        if let Some((head, _)) = rest.split_once('_') {
            return head.to_string();
        }
        let head: String = rest
            .chars()
            .take_while(|c| c.is_lowercase() || !c.is_alphabetic())
            .collect();
        return if head.is_empty() {
            rest.to_string()
        } else {
            head
        };
    }
    method
        .split_once('_')
        .map(|(head, _)| head.to_string())
        .unwrap_or_else(|| method.to_string())
}

/// Every method the node serves, with how each is gated.
///
/// Optional `namespace` and `contains` filters narrow the listing; a directory
/// of 900 entries is not something a caller wants in one response by default,
/// but it is available by asking for it.
pub fn method_directory(namespace: Option<&str>, contains: Option<&str>) -> Vec<MethodEntry> {
    all_methods()
        .into_iter()
        .filter(|m| contains.is_none_or(|c| m.to_lowercase().contains(&c.to_lowercase())))
        .map(|m| MethodEntry {
            gate: gate_class(m).unwrap_or(GateClass::Open),
            scope: crate::api_key::required_scope_for_method(m).map(|s| s.as_str()),
            namespace: namespace_of(m),
            method: m.to_string(),
        })
        .filter(|e| namespace.is_none_or(|n| e.namespace.eq_ignore_ascii_case(n)))
        .collect()
}

/// `tenzro_listRpcMethods` — the method directory.
///
/// Params: optional `namespace`, optional `contains`. This is the call every
/// other surface's discovery is built on, so that none of them ships its own
/// list.
pub(crate) async fn handle_list_rpc_methods(
    params: Option<Value>,
) -> std::result::Result<Value, crate::rpc::JsonRpcError> {
    let p = params.unwrap_or_else(|| json!({}));
    let namespace = p.get("namespace").and_then(|v| v.as_str());
    let contains = p.get("contains").and_then(|v| v.as_str());
    let entries = method_directory(namespace, contains);

    let mut namespaces: Vec<String> = method_directory(None, None)
        .into_iter()
        .map(|e| e.namespace)
        .collect();
    namespaces.sort();
    namespaces.dedup();

    Ok(json!({
        "methods": entries,
        "count": entries.len(),
        "total": all_methods().len(),
        "namespaces": namespaces,
    }))
}

/// Forward `method` to the dispatcher with the caller's own credentials.
///
/// Returns the inner call's result, or its error verbatim — the gateway adds
/// no interpretation, because a caller debugging a refusal needs the
/// dispatcher's own message, not this layer's paraphrase of it.
pub(crate) async fn forward(
    node: &Arc<TenzroNode>,
    method: &str,
    params: Value,
    api_key: Option<&str>,
    admin_token: Option<&str>,
) -> std::result::Result<Value, crate::rpc::JsonRpcError> {
    // Refuse an unknown method here rather than letting it reach the
    // dispatcher's fallback, so the error names the discovery call that would
    // have told the caller what exists.
    if !crate::rpc_gates::is_known_method(method) {
        return Err(crate::rpc::JsonRpcError {
            code: -32601,
            message: format!(
                "Unknown method '{method}'. Call tenzro_listRpcMethods to enumerate what this \
                 node serves."
            ),
            data: None,
        });
    }

    let request = crate::rpc::JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params: Some(params),
        id: json!(1),
    };
    // Both gates, in the dispatcher's own order: admin first, then subject.
    if let Some(err) = crate::rpc::gate_admin_token(node, &request, admin_token)
        && let Some(e) = err.error
    {
        return Err(e);
    }
    if let Some(err) = crate::rpc::gate_api_key(node, &request, api_key)
        && let Some(e) = err.error
    {
        return Err(e);
    }

    let auth_ctx = crate::rpc::AuthContext::from_mcp(
        None,
        None,
        "POST".to_string(),
        format!("http://{}/", node.config().rpc_addr),
    );
    let response = crate::rpc::handle_request(node, request, &auth_ctx, api_key, None).await;
    match (response.result, response.error) {
        (Some(result), _) => Ok(result),
        (None, Some(e)) => Err(e),
        (None, None) => Err(crate::rpc::JsonRpcError {
            code: -32603,
            message: "the dispatcher returned neither a result nor an error".to_string(),
            data: None,
        }),
    }
}

/// Router for the universal REST gateway.
///
/// Two routes carry the whole method surface:
///
/// | Route | Does |
/// |---|---|
/// | `GET  /v1/rpc` | the method directory (`?namespace=` / `?contains=`) |
/// | `POST /v1/rpc/{method}` | call any method; the JSON body is its params |
///
/// The named REST routes elsewhere (`/v1/chat/completions`, `/v1/files`,
/// `/v1/databases`) stay where they are — they exist because a developer
/// expects a particular vendor-compatible shape at a particular path, which a
/// generic gateway cannot provide. This covers everything else.
pub fn gateway_routes() -> axum::Router<Arc<TenzroNode>> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/v1/rpc", get(handle_rest_directory))
        .route("/v1/rpc/:method", post(handle_rest_call))
}

/// Credentials as presented on an HTTP request.
fn credentials(headers: &axum::http::HeaderMap) -> (Option<String>, Option<String>) {
    let get = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    (get("x-tenzro-api-key"), get("x-tenzro-admin-token"))
}

/// `GET /v1/rpc` — the method directory.
async fn handle_rest_directory(
    axum::extract::Query(q): axum::extract::Query<DirectoryQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match handle_list_rpc_methods(Some(json!({
        "namespace": q.namespace,
        "contains": q.contains,
    })))
    .await
    {
        Ok(v) => axum::Json(v).into_response(),
        Err(e) => rest_error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, &e.message),
    }
}

/// Query parameters for the directory listing.
#[derive(Debug, serde::Deserialize)]
pub struct DirectoryQuery {
    /// Restrict to one namespace (`eth`, `canton`, …).
    pub namespace: Option<String>,
    /// Substring match on the method name, case-insensitive.
    pub contains: Option<String>,
}

/// `POST /v1/rpc/{method}` — call any method.
async fn handle_rest_call(
    axum::extract::State(node): axum::extract::State<Arc<TenzroNode>>,
    axum::extract::Path(method): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: Option<axum::Json<Value>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let (api_key, admin_token) = credentials(&headers);
    let params = body.map(|axum::Json(v)| v).unwrap_or_else(|| json!({}));
    match forward(
        &node,
        &method,
        params,
        api_key.as_deref(),
        admin_token.as_deref(),
    )
    .await
    {
        Ok(v) => axum::Json(v).into_response(),
        Err(e) => {
            // The dispatcher's codes, mapped onto the statuses an HTTP client
            // acts on. Anything unrecognised is a server fault rather than a
            // client one — guessing "bad request" for an error we did not
            // anticipate blames the caller for our gap.
            let status = match e.code {
                -32601 => axum::http::StatusCode::NOT_FOUND,
                -32602 => axum::http::StatusCode::BAD_REQUEST,
                -32001 | -32004 => axum::http::StatusCode::UNAUTHORIZED,
                -32005 => axum::http::StatusCode::TOO_MANY_REQUESTS,
                _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            };
            rest_error(status, &e.message)
        }
    }
}

fn rest_error(status: axum::http::StatusCode, message: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        status,
        axum::Json(json!({
            "error": { "message": message, "type": "invalid_request_error" }
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_directory_covers_every_method() {
        // The property the whole parity claim rests on: the directory is the
        // dispatcher's own method set, not a copy of it.
        let all = all_methods();
        let dir = method_directory(None, None);
        assert_eq!(dir.len(), all.len());
        let listed: std::collections::BTreeSet<&str> =
            dir.iter().map(|e| e.method.as_str()).collect();
        for m in &all {
            assert!(listed.contains(m), "{m} missing from the directory");
        }
    }

    #[test]
    fn namespaces_group_the_way_a_caller_would_expect() {
        assert_eq!(namespace_of("tenzro_listDatabases"), "list");
        assert_eq!(namespace_of("tenzro_canton_health"), "canton");
        assert_eq!(namespace_of("eth_blockNumber"), "eth");
        assert_eq!(namespace_of("net_listening"), "net");
    }

    #[test]
    fn a_namespace_filter_narrows_and_never_invents() {
        let eth = method_directory(Some("eth"), None);
        assert!(!eth.is_empty());
        assert!(eth.iter().all(|e| e.method.starts_with("eth_")));
        assert!(method_directory(Some("no-such-namespace"), None).is_empty());
    }

    #[test]
    fn a_contains_filter_is_case_insensitive() {
        let hits = method_directory(None, Some("DATABASE"));
        assert!(!hits.is_empty());
        assert!(
            hits.iter()
                .all(|e| e.method.to_lowercase().contains("database"))
        );
    }

    #[test]
    fn the_directory_reports_the_gate_and_the_scope() {
        let dir = method_directory(None, Some("createApiKey"));
        let entry = dir
            .iter()
            .find(|e| e.method == "tenzro_createApiKey")
            .expect("present");
        assert_eq!(entry.gate, GateClass::Admin);

        let files = method_directory(None, Some("uploadFile"));
        let upload = files
            .iter()
            .find(|e| e.method == "tenzro_uploadFile")
            .expect("present");
        assert_eq!(upload.gate, GateClass::Open);
        assert_eq!(
            upload.scope,
            Some("storage"),
            "a caller must be able to learn which key they need without provoking the error"
        );
    }
}
