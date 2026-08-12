//! `/v1/databases` — the REST surface over the managed-database service.
//!
//! # What this adds over the RPCs
//!
//! Not new capability. Every route here dispatches into the same JSON-RPC
//! handler an SDK would call, through the same
//! [`crate::rpc::handle_request`] entry point, so the access-policy gate, the
//! capability adjudication, and the engine routing are all the ones already
//! under test. Duplicating that logic here would mean two gates that can
//! disagree, and the one an attacker finds is whichever is weaker.
//!
//! What it adds is *shape*. A developer provisioning a database for their
//! application reaches for `POST /v1/databases`, not for a JSON-RPC envelope
//! naming `tenzro_createDatabase`, and having to construct the latter is the
//! kind of friction that decides whether a managed service gets used.
//!
//! # The caller is the key's subject, always
//!
//! The RPC surface takes `caller_did` as a parameter because a node-to-node
//! call legitimately speaks for someone else, having proved it with a signed
//! envelope. The REST surface does not: `caller_did` is *derived* from the
//! presented API key's subject and any value in the body is overwritten. A
//! REST endpoint that let a caller name whoever they liked as `caller_did`
//! would hand every tenant every other tenant's databases, since the policy
//! check downstream trusts that field to have been authenticated.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::api_key::ApiKeyScope;
use crate::node::TenzroNode;
use crate::resource_authz::{Authorized, authorize_resource};

/// Router for the whole `/v1/databases` surface.
pub fn database_routes() -> axum::Router<Arc<TenzroNode>> {
    use axum::routing::{delete, get, post};
    axum::Router::new()
        // Node capability advertisement — what engines this operator wired up.
        // Ungated for the same reason `/v1/models` is: a caller cannot decide
        // whether to ask for a database here without first knowing what this
        // node can serve.
        .route("/v1/databases/engines", get(handle_list_engines))
        .route(
            "/v1/databases",
            post(handle_create).get(handle_list_databases),
        )
        .route("/v1/databases/:id", get(handle_get))
        .route("/v1/databases/:id", delete(handle_drop))
        .route("/v1/databases/:id/partitions", get(handle_partitions))
        .route("/v1/databases/:id/query", post(handle_query))
        .route("/v1/databases/:id/rescale", post(handle_rescale))
        .route("/v1/databases/:id/connections", post(handle_connection))
        .route("/v1/databases/:id/usage", get(handle_usage))
}

/// An error body in the shape the rest of the `/v1` surface uses.
fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "error": { "message": message, "type": "invalid_request_error", "code": code }
        })),
    )
        .into_response()
}

/// The raw API key as presented, if any.
fn presented_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-tenzro-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Resolve the calling tenant's DID, or the refusal to return.
fn tenant_or_refusal(
    node: &Arc<TenzroNode>,
    headers: &HeaderMap,
) -> Result<(String, String), Response> {
    let key = presented_key(headers).ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "missing_api_key",
            "Missing X-Tenzro-Api-Key. A managed database is adjudicated against a caller DID, \
             and the key's subject is what supplies it.",
        )
    })?;
    let manager = node.api_key_manager().ok_or_else(|| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_api_keys",
            "This node has no API-key manager, so it cannot resolve a caller DID.",
        )
    })?;
    let record = manager.lookup(&key).ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_api_key",
            "The presented API key is unknown or revoked.",
        )
    })?;
    if !record.scopes.contains(&ApiKeyScope::Database) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "This API key does not carry the 'database' scope.",
        ));
    }
    let subject = record
        .subject
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            error_response(
                StatusCode::FORBIDDEN,
                "no_subject",
                "This API key names no subject, so there is no caller DID to adjudicate against. \
                 Reissue the key with a subject DID.",
            )
        })?;
    Ok((subject, key))
}

/// Dispatch into the JSON-RPC layer and project the result onto HTTP.
///
/// Going through [`crate::rpc::handle_request`] rather than calling the
/// handlers directly is the point: the admin gate, the scope gate, and the
/// default-deny classification all run, so a REST route cannot become a way
/// around a check that the RPC path enforces.
async fn dispatch(node: &Arc<TenzroNode>, method: &str, params: Value, api_key: &str) -> Response {
    let request = crate::rpc::JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params: Some(params),
        id: json!(1),
    };
    let auth_ctx = crate::rpc::AuthContext::from_mcp(
        None,
        None,
        "POST".to_string(),
        format!("http://{}/", node.config().rpc_addr),
    );
    // No admin token: this REST surface is the *tenant* one. Every route here
    // has already resolved a subject DID from the presented key in order to
    // adjudicate access, so there is no operator identity to offer and nothing
    // to gain by accepting one — the operator reaches the same handlers over
    // JSON-RPC, where their token is honoured.
    if let Some(err) = crate::rpc::gate_api_key(node, &request, Some(api_key), None)
        && let Some(e) = err.error
    {
        return error_response(StatusCode::FORBIDDEN, "refused", &e.message);
    }
    let response = crate::rpc::handle_request(node, request, &auth_ctx, Some(api_key), None).await;
    // The JSON-RPC codes the database handlers use are mapped onto the statuses
    // an HTTP client acts on (retry, fix the request, or stop) in
    // `project_rpc_response`; anything unrecognised is a server fault rather
    // than a client one, because guessing "bad request" for an error we did not
    // anticipate blames the caller for our gap.
    project_rpc_response(response)
}

/// Dispatch into the JSON-RPC layer *without* the tenant API-key gate.
///
/// The twin of [`dispatch`] for requests that cleared the resource's serving
/// mode by payment (`Open`) or by being on-node (`Private`/loopback) rather than
/// by a key. [`dispatch`] runs [`crate::rpc::gate_api_key`], which refuses a
/// keyless database method — correct for the Gated path, wrong once the operator
/// has declared the resource Open or a loopback caller reached a Private one.
/// The gate is therefore skipped here and the request runs keyless: the
/// downstream handlers still enforce the database's own `access_policy` (the
/// *who* layer) against the `caller_did` this layer set, and `enforce_database_scope`
/// with no key is a no-op, so nothing else is loosened.
async fn dispatch_open(node: &Arc<TenzroNode>, method: &str, params: Value) -> Response {
    let request = crate::rpc::JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params: Some(params),
        id: json!(1),
    };
    let auth_ctx = crate::rpc::AuthContext::from_mcp(
        None,
        None,
        "POST".to_string(),
        format!("http://{}/", node.config().rpc_addr),
    );
    let response = crate::rpc::handle_request(node, request, &auth_ctx, None, None).await;
    project_rpc_response(response)
}

/// Project a JSON-RPC response onto HTTP, shared by [`dispatch`] and
/// [`dispatch_open`].
fn project_rpc_response(response: crate::rpc::JsonRpcResponse) -> Response {
    match (response.result, response.error) {
        (Some(result), _) => (StatusCode::OK, Json(result)).into_response(),
        (None, Some(e)) => {
            let status = match e.code {
                -32001 => StatusCode::FORBIDDEN,
                -32004 => StatusCode::UNAUTHORIZED,
                -32005 => StatusCode::TOO_MANY_REQUESTS,
                -32601 => StatusCode::NOT_FOUND,
                -32602 => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            error_response(status, "rpc_error", &e.message)
        }
        (None, None) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "empty_response",
            "The node returned neither a result nor an error.",
        ),
    }
}

/// How a request to an existing database cleared its serving mode, plus the
/// caller DID the request is attributed to. Produced by [`authorize_db`].
enum DbAuth {
    /// A valid `database`-scoped API key. Continues through [`dispatch`] so the
    /// existing key gate + scope + access-policy path runs unchanged.
    Keyed {
        /// The key's subject DID, adjudicated as the caller.
        caller_did: String,
        /// The raw API key.
        key: String,
    },
    /// Cleared by x402 payment (`Open`) or by being on-node (`Private`/loopback).
    /// Dispatched keyless via [`dispatch_open`].
    Keyless {
        /// The caller DID: the payer for `Open`, the database owner for loopback.
        caller_did: String,
    },
}

impl DbAuth {
    fn caller_did(&self) -> &str {
        match self {
            DbAuth::Keyed { caller_did, .. } | DbAuth::Keyless { caller_did } => caller_did,
        }
    }
}

/// Authorize a request against an existing database's operator-set serving mode.
///
/// Looks the database up to read its per-record
/// [`tenzro_database::DatabaseDescriptor::access`], then runs the shared
/// [`authorize_resource`] precedence (valid key → x402 for `Open` → refuse for
/// `Gated`/no-key → loopback for `Private`). The returned [`DbAuth`] carries the
/// caller DID and how to dispatch.
async fn authorize_db(
    node: &Arc<TenzroNode>,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    database_id: &str,
) -> Result<DbAuth, Response> {
    let registry = node.database_registry().ok_or_else(|| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_database_registry",
            "This node has no database registry, so it serves no managed databases.",
        )
    })?;
    let desc = registry.get_database(database_id).map_err(|_| {
        error_response(
            StatusCode::NOT_FOUND,
            "no_such_database",
            &format!("No database '{database_id}'."),
        )
    })?;

    match authorize_resource(node, headers, peer, desc.access, ApiKeyScope::Database).await? {
        Authorized::Key { key, subject } => {
            let caller_did = subject.ok_or_else(|| {
                error_response(
                    StatusCode::FORBIDDEN,
                    "no_subject",
                    "This API key names no subject, so there is no caller DID to adjudicate \
                     against. Reissue the key with a subject DID.",
                )
            })?;
            Ok(DbAuth::Keyed { caller_did, key })
        }
        // The payer owns the request under the operator's Open policy.
        Authorized::Payment { payer_did } => Ok(DbAuth::Keyless {
            caller_did: payer_did,
        }),
        // An on-node caller of a Private database acts as its owner.
        Authorized::Loopback => Ok(DbAuth::Keyless {
            caller_did: desc.access_policy.owner_did().to_string(),
        }),
    }
}

/// Run an existing-database method with the identity and dispatch path chosen by
/// [`authorize_db`]. `body` is the caller's request body (if any); `id` is
/// injected as `database_id`; `caller_did` is set from the authorization.
async fn dispatch_db(
    node: &Arc<TenzroNode>,
    auth: DbAuth,
    method: &str,
    body: Option<Value>,
    id: &str,
) -> Response {
    let mut params = with_caller(body, auth.caller_did(), false);
    params["database_id"] = json!(id);
    match auth {
        DbAuth::Keyed { key, .. } => dispatch(node, method, params, &key).await,
        DbAuth::Keyless { .. } => dispatch_open(node, method, params).await,
    }
}

/// Merge caller-supplied fields with the ones this layer owns.
///
/// `caller_did` and `owner_did` are overwritten rather than defaulted: a body
/// that names someone else is not a caller expressing a preference, it is a
/// caller trying to act as another tenant.
fn with_caller(body: Option<Value>, caller_did: &str, set_owner: bool) -> Value {
    let mut map = match body {
        Some(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    map.insert("caller_did".into(), json!(caller_did));
    if set_owner {
        map.insert("owner_did".into(), json!(caller_did));
    }
    Value::Object(map)
}

/// Why a create body was refused before it reached the handler.
#[derive(Debug, PartialEq, Eq)]
enum PolicyRejection {
    /// The `access_policy` did not parse as one.
    Malformed(String),
    /// It parsed, and named someone else as owner.
    ForeignOwner {
        /// Who the body tried to make the owner.
        named: String,
    },
}

/// Check that a create body's `access_policy`, if it has one, is owned by the
/// caller.
///
/// Overwriting `owner_did` is not enough on its own. `tenzro_createDatabase`
/// takes `owner_did` only as a *fallback* — when the body carries a full
/// `access_policy`, that policy's own `owner_did` wins and the top-level field
/// is never read. So a body carrying
/// `{"access_policy": {"owner_only": {"owner_did": "<someone else>"}}}` would
/// sail past an `owner_did` overwrite and create a database inside another
/// tenant's boundary.
///
/// Refusing rather than rewriting: a tenant may legitimately want a `public` or
/// `did_allowlist` policy, so the shape has to stay expressive, but a body that
/// names a foreign owner is not a shape question — it is an attempt, and
/// silently correcting it would hide that from whoever reads the logs.
fn check_policy_owner(body: &Value, caller_did: &str) -> Result<(), PolicyRejection> {
    let Some(ap) = body.get("access_policy").filter(|v| !v.is_null()) else {
        return Ok(());
    };
    let parsed = serde_json::from_value::<tenzro_types::access_policy::AccessPolicy>(ap.clone())
        .map_err(|e| PolicyRejection::Malformed(e.to_string()))?;
    if parsed.owner_did() != caller_did {
        return Err(PolicyRejection::ForeignOwner {
            named: parsed.owner_did().to_string(),
        });
    }
    Ok(())
}

/// `GET /v1/databases/engines`
async fn handle_list_engines(State(node): State<Arc<TenzroNode>>, headers: HeaderMap) -> Response {
    // Ungated, so it dispatches with whatever key was presented — which may be
    // none. `tenzro_listDatabaseEngines` is excluded from the database scope
    // for exactly this reason.
    let key = presented_key(&headers).unwrap_or_default();
    dispatch(&node, "tenzro_listDatabaseEngines", json!({}), &key).await
}

/// `POST /v1/databases`
async fn handle_create(
    State(node): State<Arc<TenzroNode>>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Response {
    let (did, key) = match tenant_or_refusal(&node, &headers) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let params = with_caller(body.map(|Json(v)| v), &did, true);
    if let Err(e) = check_policy_owner(&params, &did) {
        return match e {
            PolicyRejection::Malformed(why) => error_response(
                StatusCode::BAD_REQUEST,
                "invalid_access_policy",
                &format!("'access_policy' is not a valid policy: {why}"),
            ),
            PolicyRejection::ForeignOwner { named } => error_response(
                StatusCode::FORBIDDEN,
                "foreign_policy_owner",
                &format!(
                    "'access_policy' names {named} as owner, but this API key's subject is \
                     {did}. A database can only be created inside your own boundary."
                ),
            ),
        };
    }
    dispatch(&node, "tenzro_createDatabase", params, &key).await
}

/// `GET /v1/databases`
async fn handle_list_databases(
    State(node): State<Arc<TenzroNode>>,
    headers: HeaderMap,
) -> Response {
    let (did, key) = match tenant_or_refusal(&node, &headers) {
        Ok(t) => t,
        Err(r) => return r,
    };
    dispatch(
        &node,
        "tenzro_listDatabases",
        with_caller(None, &did, false),
        &key,
    )
    .await
}

/// `GET /v1/databases/{id}`
async fn handle_get(
    State(node): State<Arc<TenzroNode>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authorize_db(&node, &headers, Some(peer), &id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    dispatch_db(&node, auth, "tenzro_getDatabase", None, &id).await
}

/// `DELETE /v1/databases/{id}`
async fn handle_drop(
    State(node): State<Arc<TenzroNode>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authorize_db(&node, &headers, Some(peer), &id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    dispatch_db(&node, auth, "tenzro_dropDatabase", None, &id).await
}

/// `GET /v1/databases/{id}/partitions`
async fn handle_partitions(
    State(node): State<Arc<TenzroNode>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authorize_db(&node, &headers, Some(peer), &id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    dispatch_db(&node, auth, "tenzro_listDatabasePartitions", None, &id).await
}

/// `POST /v1/databases/{id}/query`
async fn handle_query(
    State(node): State<Arc<TenzroNode>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> Response {
    let auth = match authorize_db(&node, &headers, Some(peer), &id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    dispatch_db(
        &node,
        auth,
        "tenzro_databaseQuery",
        body.map(|Json(v)| v),
        &id,
    )
    .await
}

/// `POST /v1/databases/{id}/rescale`
async fn handle_rescale(
    State(node): State<Arc<TenzroNode>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> Response {
    let auth = match authorize_db(&node, &headers, Some(peer), &id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    dispatch_db(
        &node,
        auth,
        "tenzro_rescaleDatabase",
        body.map(|Json(v)| v),
        &id,
    )
    .await
}

/// `POST /v1/databases/{id}/connections`
async fn handle_connection(
    State(node): State<Arc<TenzroNode>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> Response {
    let auth = match authorize_db(&node, &headers, Some(peer), &id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    dispatch_db(
        &node,
        auth,
        "tenzro_issueDatabaseConnection",
        body.map(|Json(v)| v),
        &id,
    )
    .await
}

/// `GET /v1/databases/{id}/usage`
async fn handle_usage(
    State(node): State<Arc<TenzroNode>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authorize_db(&node, &headers, Some(peer), &id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    dispatch_db(&node, auth, "tenzro_databaseUsage", None, &id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "did:tenzro:human:alice";
    const BOB: &str = "did:tenzro:human:bob";

    #[test]
    fn a_body_naming_another_caller_is_overwritten_not_merged() {
        // The whole isolation property of this layer. If a body could set
        // `caller_did`, the policy check downstream — which trusts that field
        // to have been authenticated — would hand Alice Bob's databases.
        let hostile = json!({ "caller_did": BOB, "database_id": "db-1" });
        let out = with_caller(Some(hostile), ALICE, false);
        assert_eq!(out["caller_did"], ALICE);
        assert_eq!(out["database_id"], "db-1", "other fields survive");
    }

    #[test]
    fn a_create_body_cannot_name_another_owner() {
        // Same attack one step earlier: creating a database owned by someone
        // else would let a tenant plant rows inside another's boundary.
        let hostile = json!({ "owner_did": BOB, "engine": "postgres" });
        let out = with_caller(Some(hostile), ALICE, true);
        assert_eq!(out["owner_did"], ALICE);
        assert_eq!(out["caller_did"], ALICE);
        assert_eq!(out["engine"], "postgres");
    }

    #[test]
    fn only_create_sets_an_owner() {
        // Every other route addresses an existing database; writing an owner
        // there would be either a no-op or, worse, a takeover attempt the
        // handler might honour.
        let out = with_caller(None, ALICE, false);
        assert!(out.get("owner_did").is_none());
        assert_eq!(out["caller_did"], ALICE);
    }

    #[test]
    fn a_policy_naming_a_foreign_owner_is_refused() {
        // The hole an `owner_did` overwrite alone leaves open: the handler
        // reads the policy's own owner and ignores the top-level field, so a
        // body carrying a full policy sails straight past the overwrite.
        let hostile = with_caller(
            Some(json!({ "access_policy": { "kind": "owner_only", "owner_did": BOB } })),
            ALICE,
            true,
        );
        assert_eq!(
            check_policy_owner(&hostile, ALICE),
            Err(PolicyRejection::ForeignOwner {
                named: BOB.to_string()
            })
        );
    }

    #[test]
    fn a_policy_owned_by_the_caller_passes_in_every_shape() {
        // The refusal must not cost a tenant the expressiveness of the policy
        // model — public, allowlist and capability policies are all legitimate
        // things to ask for, as long as you own them.
        for policy in [
            json!({ "kind": "owner_only", "owner_did": ALICE }),
            json!({ "kind": "public", "owner_did": ALICE }),
            json!({ "kind": "did_allowlist", "owner_did": ALICE, "readers": [BOB] }),
            json!({
                "kind": "capability_required",
                "owner_did": ALICE,
                "read_action": "db.read",
                "write_action": "db.write"
            }),
        ] {
            let body = json!({ "access_policy": policy });
            assert_eq!(check_policy_owner(&body, ALICE), Ok(()), "{body}");
        }
    }

    #[test]
    fn a_body_with_no_policy_is_left_alone() {
        // The common case: no policy means the handler derives an owner-only
        // one from the `owner_did` this layer already overwrote.
        assert_eq!(check_policy_owner(&json!({}), ALICE), Ok(()));
        assert_eq!(
            check_policy_owner(&json!({"access_policy": null}), ALICE),
            Ok(())
        );
    }

    #[test]
    fn a_malformed_policy_is_refused_rather_than_ignored() {
        // Passing it through would let the handler reject it later with an
        // owner already assigned — or, worse, accept some shape this check
        // could not read and therefore could not vet.
        let body = json!({ "access_policy": "not-a-policy" });
        assert!(matches!(
            check_policy_owner(&body, ALICE),
            Err(PolicyRejection::Malformed(_))
        ));
    }

    #[test]
    fn a_non_object_body_does_not_lose_the_caller() {
        // A client that sends `null`, a bare string, or an array must still
        // end up with an authenticated caller rather than an empty one.
        for body in [
            Some(json!(null)),
            Some(json!("nonsense")),
            Some(json!([1, 2, 3])),
            None,
        ] {
            let out = with_caller(body, ALICE, false);
            assert_eq!(out["caller_did"], ALICE);
        }
    }
}
