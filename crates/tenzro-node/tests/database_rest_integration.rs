//! End-to-end tests for `/v1/databases`.
//!
//! The unit tests in `database_routes` prove `with_caller` overwrites a hostile
//! body. What they cannot prove is that the overwrite is on the live path —
//! that the route is mounted, that the scope gate is consulted, and that a
//! caller who names another tenant in the body genuinely does not reach that
//! tenant's databases. Each test here boots a real node and speaks HTTP to it.

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::api_key::{ApiKeyScope, KeyClass};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

const ALICE: &str = "did:tenzro:human:alice";
const BOB: &str = "did:tenzro:human:bob";

struct TestNode {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    node: Arc<TenzroNode>,
    client: reqwest::Client,
}

impl TestNode {
    async fn boot() -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let mut node = TenzroNode::new(config).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);

        let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
        let handle =
            tokio::spawn(
                async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await },
            );
        let addr = addr_rx.await.expect("bound address");

        Self {
            base_url: format!("http://{addr}"),
            shutdown,
            handle,
            _tmp: tmp,
            node,
            client: reqwest::Client::new(),
        }
    }

    fn key(&self, subject: &str, scopes: Vec<ApiKeyScope>) -> String {
        self.node
            .api_key_manager()
            .expect("the node has an API-key manager")
            .issue(
                Some(subject.to_string()),
                format!("test-{subject}"),
                scopes,
                KeyClass::Subject,
                None,
                None,
                None,
                None,
            )
            .expect("issue")
            .key
    }

    async fn get(&self, path: &str, key: Option<&str>) -> reqwest::Response {
        let mut req = self.client.get(format!("{}{path}", self.base_url));
        if let Some(k) = key {
            req = req.header("x-tenzro-api-key", k);
        }
        req.send().await.expect("HTTP request")
    }

    async fn post(&self, path: &str, body: Value, key: Option<&str>) -> reqwest::Response {
        let mut req = self.client.post(format!("{}{path}", self.base_url));
        if let Some(k) = key {
            req = req.header("x-tenzro-api-key", k);
        }
        req.json(&body).send().await.expect("HTTP request")
    }

    async fn rpc(&self, method: &str, params: Value, key: Option<&str>) -> Value {
        let mut req = self.client.post(&self.base_url);
        if let Some(k) = key {
            req = req.header("x-tenzro-api-key", k);
        }
        req.json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .expect("HTTP request")
            .json::<Value>()
            .await
            .expect("JSON parse")
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

// ---------------------------------------------------------------------------
// Mounted, and gated
// ---------------------------------------------------------------------------

/// The engine catalog is node capability advertisement, like `/v1/models`.
/// Gating it would mean a caller cannot discover what a node offers without
/// first being issued a key by its operator.
#[tokio::test]
async fn the_engine_catalog_is_reachable_without_a_key() {
    let n = TestNode::boot().await;
    let resp = n.get("/v1/databases/engines", None).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("JSON");
    let engines = body["engines"].as_array().expect("engine list");
    assert!(!engines.is_empty(), "the catalog must list something");
    n.shutdown().await;
}

/// Everything that names or touches an actual database needs a key.
#[tokio::test]
async fn every_database_route_refuses_an_unauthenticated_caller() {
    let n = TestNode::boot().await;
    for path in [
        "/v1/databases",
        "/v1/databases/db-1",
        "/v1/databases/db-1/partitions",
        "/v1/databases/db-1/usage",
    ] {
        let resp = n.get(path, None).await;
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{path} served an unauthenticated caller"
        );
    }
    for path in [
        "/v1/databases",
        "/v1/databases/db-1/query",
        "/v1/databases/db-1/rescale",
        "/v1/databases/db-1/connections",
    ] {
        let resp = n.post(path, json!({}), None).await;
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{path} served an unauthenticated caller"
        );
    }
    n.shutdown().await;
}

#[tokio::test]
async fn a_key_without_the_database_scope_is_refused() {
    let n = TestNode::boot().await;
    let key = n.key(ALICE, vec![ApiKeyScope::Inference]);
    let resp = n.get("/v1/databases", Some(&key)).await;
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.expect("JSON");
    assert_eq!(body["error"]["code"], "insufficient_scope", "{body}");
    n.shutdown().await;
}

/// The scope gate must bite on the RPC path too, not only the REST one — the
/// REST routes dispatch through it, so a gap there is a gap everywhere.
#[tokio::test]
async fn the_rpc_database_namespace_is_scope_gated() {
    let n = TestNode::boot().await;
    let unauthenticated = n.rpc("tenzro_listDatabases", json!({}), None).await;
    assert_eq!(
        unauthenticated["error"]["code"], -32004,
        "expected a scope refusal: {unauthenticated}"
    );

    // And the engine catalog is deliberately exempt.
    let engines = n.rpc("tenzro_listDatabaseEngines", json!({}), None).await;
    assert!(
        engines.get("result").is_some(),
        "the catalog must stay reachable: {engines}"
    );
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// The caller cannot name themselves
// ---------------------------------------------------------------------------

/// The isolation property of this layer, on the live path. A body naming
/// another tenant as `caller_did` must not reach that tenant's databases: the
/// policy check downstream trusts that field to have been authenticated.
#[tokio::test]
async fn a_body_cannot_name_another_caller() {
    let n = TestNode::boot().await;
    let alice = n.key(ALICE, vec![ApiKeyScope::Database]);

    // Bob owns a database. Created through the RPC path with Bob's own key, so
    // the fixture itself does not depend on what is under test.
    let bob = n.key(BOB, vec![ApiKeyScope::Database]);
    let created = n
        .rpc(
            "tenzro_createDatabase",
            json!({
                "database_id": "bobs-db",
                "engine_id": "tantivy",
                "owner_did": BOB,
                "caller_did": BOB,
            }),
            Some(&bob),
        )
        .await;
    assert!(
        created.get("result").is_some(),
        "fixture setup failed: {created}"
    );

    // Alice asks for it while claiming to be Bob.
    let resp = n
        .post(
            "/v1/databases/bobs-db/query",
            json!({ "caller_did": BOB, "body": { "op": "search", "query": "*" } }),
            Some(&alice),
        )
        .await;
    assert!(
        !resp.status().is_success(),
        "Alice queried Bob's database by claiming to be Bob (status {})",
        resp.status()
    );
    n.shutdown().await;
}

/// The other half: a tenant reaching their *own* database over REST must
/// actually work. A layer that refused everything would pass the test above
/// and be useless.
#[tokio::test]
async fn a_tenant_reaches_their_own_database_over_rest() {
    let n = TestNode::boot().await;
    let alice = n.key(ALICE, vec![ApiKeyScope::Database]);

    let created = n
        .post(
            "/v1/databases",
            json!({ "database_id": "alices-db", "engine_id": "tantivy" }),
            Some(&alice),
        )
        .await;
    assert_eq!(
        created.status(),
        reqwest::StatusCode::OK,
        "create failed: {}",
        created.text().await.unwrap_or_default()
    );

    let fetched = n.get("/v1/databases/alices-db", Some(&alice)).await;
    assert_eq!(fetched.status(), reqwest::StatusCode::OK);
    let body: Value = fetched.json().await.expect("JSON");
    assert_eq!(body["database_id"], "alices-db", "{body}");
    assert_eq!(
        body["access_policy"]["owner_did"], ALICE,
        "the key's subject must be recorded as the owner: {body}"
    );

    let parts = n
        .get("/v1/databases/alices-db/partitions", Some(&alice))
        .await;
    assert_eq!(parts.status(), reqwest::StatusCode::OK);
    n.shutdown().await;
}

/// A create body naming someone else as owner must not plant a database inside
/// their boundary.
#[tokio::test]
async fn a_create_body_cannot_name_another_owner() {
    let n = TestNode::boot().await;
    let alice = n.key(ALICE, vec![ApiKeyScope::Database]);

    let created = n
        .post(
            "/v1/databases",
            json!({ "database_id": "planted", "engine_id": "tantivy", "owner_did": BOB }),
            Some(&alice),
        )
        .await;
    assert_eq!(created.status(), reqwest::StatusCode::OK);
    let body: Value = created.json().await.expect("JSON");
    let owner = &body["database"]["access_policy"]["owner_did"];
    assert_eq!(
        owner, ALICE,
        "the request body set the owner to another tenant: {body}"
    );
    n.shutdown().await;
}

/// A tenant who has created nothing sees an empty list rather than the node's
/// other tenants.
#[tokio::test]
async fn a_database_belonging_to_another_tenant_is_not_readable() {
    let n = TestNode::boot().await;
    let bob = n.key(BOB, vec![ApiKeyScope::Database]);
    let alice = n.key(ALICE, vec![ApiKeyScope::Database]);

    let created = n
        .post(
            "/v1/databases",
            json!({ "database_id": "bobs-private", "engine_id": "tantivy" }),
            Some(&bob),
        )
        .await;
    assert_eq!(created.status(), reqwest::StatusCode::OK);

    let queried = n
        .post(
            "/v1/databases/bobs-private/query",
            json!({ "body": { "op": "search", "query": "*" } }),
            Some(&alice),
        )
        .await;
    assert!(
        !queried.status().is_success(),
        "Alice queried Bob's database (status {})",
        queried.status()
    );
    n.shutdown().await;
}

/// The hole an `owner_did` overwrite alone leaves: `tenzro_createDatabase`
/// reads a supplied `access_policy`'s own owner and never looks at the
/// top-level field, so a body carrying a full policy would sail past the
/// overwrite and land inside another tenant's boundary.
#[tokio::test]
async fn a_create_body_cannot_smuggle_a_foreign_owner_through_the_access_policy() {
    let n = TestNode::boot().await;
    let alice = n.key(ALICE, vec![ApiKeyScope::Database]);

    let resp = n
        .post(
            "/v1/databases",
            json!({
                "database_id": "smuggled",
                "engine_id": "tantivy",
                "access_policy": { "kind": "owner_only", "owner_did": BOB },
            }),
            Some(&alice),
        )
        .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a policy naming another owner must be refused"
    );
    let body: Value = resp.json().await.expect("JSON");
    assert_eq!(body["error"]["code"], "foreign_policy_owner", "{body}");

    // And nothing was created under either name.
    let fetched = n.get("/v1/databases/smuggled", Some(&alice)).await;
    assert!(!fetched.status().is_success());
    n.shutdown().await;
}

/// A policy the caller *does* own is accepted, so the refusal above has not
/// cost tenants the expressiveness of the policy model.
#[tokio::test]
async fn a_create_body_may_set_a_policy_it_owns() {
    let n = TestNode::boot().await;
    let alice = n.key(ALICE, vec![ApiKeyScope::Database]);

    let resp = n
        .post(
            "/v1/databases",
            json!({
                "database_id": "alices-public",
                "engine_id": "tantivy",
                "access_policy": { "kind": "public", "owner_did": ALICE },
            }),
            Some(&alice),
        )
        .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "own-policy create failed: {}",
        resp.text().await.unwrap_or_default()
    );
    n.shutdown().await;
}
