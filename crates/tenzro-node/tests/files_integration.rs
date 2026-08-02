//! End-to-end tests for the `/v1/files` surface and its JSON-RPC twin.
//!
//! The unit tests in `files_store` and `files_api` prove the index and the
//! validation behave. What they cannot prove is that any of it is *reachable*:
//! a router that was never merged, an RPC missing from the classification
//! table, or a scope gate that maps the wrong methods all pass every unit test
//! in the workspace and fail the first real request.
//!
//! So each test here boots a real node, stands up a real RPC server, and
//! speaks HTTP to it — including the case that matters most, which is one
//! tenant trying to read another's file.

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::api_key::{ApiKeyScope, KeyClass};
use tenzro_node::files_api::{FileObject, FilePurpose};
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

    /// Issue a storage-scoped key for `subject`, straight through the manager.
    ///
    /// Not via `tenzro_createApiKey`, deliberately: that path is admin-gated
    /// and what is under test here is the *storage* surface, not key issuance.
    fn storage_key(&self, subject: &str) -> String {
        self.node
            .api_key_manager()
            .expect("the node has an API-key manager")
            .issue(
                Some(subject.to_string()),
                format!("test-{subject}"),
                vec![ApiKeyScope::Storage],
                KeyClass::Subject,
                None,
                None,
                None,
                None,
            )
            .expect("issue")
            .key
    }

    /// A key with every scope except storage — for proving the gate bites.
    fn unscoped_key(&self, subject: &str) -> String {
        self.node
            .api_key_manager()
            .expect("the node has an API-key manager")
            .issue(
                Some(subject.to_string()),
                format!("test-unscoped-{subject}"),
                vec![ApiKeyScope::Inference],
                KeyClass::Subject,
                None,
                None,
                None,
                None,
            )
            .expect("issue")
            .key
    }

    /// Put a record straight into the index.
    ///
    /// A default-config node does not run the StorageProvider role, so an
    /// upload has nowhere to put bytes. Seeding the index directly separates
    /// the two questions: whether the ownership boundary holds (this file) and
    /// whether erasure coding works (the storage-provider tests).
    fn seed(&self, id: &str, owner: &str) -> FileObject {
        let f = FileObject {
            id: id.to_string(),
            object: "file",
            bytes: 42,
            created_at: 1,
            filename: format!("{id}.txt"),
            purpose: FilePurpose::UserData,
            owner: owner.to_string(),
            deal_id: None,
        };
        self.node.file_index().insert(f.clone());
        f
    }

    async fn get(&self, path: &str, key: Option<&str>) -> reqwest::Response {
        let mut req = self.client.get(format!("{}{path}", self.base_url));
        if let Some(k) = key {
            req = req.header("x-tenzro-api-key", k);
        }
        req.send().await.expect("HTTP request")
    }

    async fn delete(&self, path: &str, key: Option<&str>) -> reqwest::Response {
        let mut req = self.client.delete(format!("{}{path}", self.base_url));
        if let Some(k) = key {
            req = req.header("x-tenzro-api-key", k);
        }
        req.send().await.expect("HTTP request")
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
// The routes exist at all
// ---------------------------------------------------------------------------

/// A router that was never merged answers 404 for everything, which would look
/// exactly like an empty file list to a client that ignores status codes.
#[tokio::test]
async fn the_files_routes_are_actually_mounted() {
    let n = TestNode::boot().await;
    let resp = n.get("/v1/files", None).await;
    assert_ne!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "/v1/files is not mounted"
    );
    // Unauthenticated, so it must refuse rather than serve.
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// No unauthenticated path, including for reads
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_read_route_refuses_an_unauthenticated_caller() {
    let n = TestNode::boot().await;
    n.seed("file-a1", ALICE);
    for path in [
        "/v1/files",
        "/v1/files/file-a1",
        "/v1/files/file-a1/content",
    ] {
        let resp = n.get(path, None).await;
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{path} served an unauthenticated caller"
        );
    }
    assert_eq!(
        n.delete("/v1/files/file-a1", None).await.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    // And the record is still there — a refused delete must not have deleted.
    assert!(n.node.file_index().get("file-a1").is_some());
    n.shutdown().await;
}

#[tokio::test]
async fn a_key_without_the_storage_scope_is_refused() {
    let n = TestNode::boot().await;
    let key = n.unscoped_key(ALICE);
    let resp = n.get("/v1/files", Some(&key)).await;
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.expect("JSON body");
    assert_eq!(body["error"]["code"], "insufficient_scope", "{body}");
    n.shutdown().await;
}

#[tokio::test]
async fn an_unknown_key_is_refused() {
    let n = TestNode::boot().await;
    let resp = n.get("/v1/files", Some("tnz_not_a_real_key")).await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// The isolation boundary, over real HTTP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_tenant_lists_only_their_own_files() {
    let n = TestNode::boot().await;
    n.seed("file-a1", ALICE);
    n.seed("file-a2", ALICE);
    n.seed("file-b1", BOB);

    let alice = n.storage_key(ALICE);
    let body: Value = n
        .get("/v1/files", Some(&alice))
        .await
        .json()
        .await
        .expect("JSON body");
    let ids: Vec<&str> = body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .map(|f| f["id"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(ids.len(), 2, "{body}");
    assert!(
        !ids.contains(&"file-b1"),
        "Bob's file leaked into Alice's list"
    );
    assert_eq!(body["object"], "list");
    assert_eq!(body["total_bytes"], 84, "two 42-byte files");
    n.shutdown().await;
}

/// The response for another tenant's file must be identical to the response
/// for a file that does not exist. A distinct 403 confirms the id is real and
/// turns the id space into an oracle.
#[tokio::test]
async fn another_tenants_file_is_indistinguishable_from_a_missing_one() {
    let n = TestNode::boot().await;
    n.seed("file-b1", BOB);
    let alice = n.storage_key(ALICE);

    let theirs = n.get("/v1/files/file-b1", Some(&alice)).await;
    let nothing = n.get("/v1/files/file-does-not-exist", Some(&alice)).await;
    assert_eq!(theirs.status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(nothing.status(), reqwest::StatusCode::NOT_FOUND);

    let a: Value = theirs.json().await.expect("JSON");
    let b: Value = nothing.json().await.expect("JSON");
    assert_eq!(a["error"]["code"], b["error"]["code"]);
    n.shutdown().await;
}

#[tokio::test]
async fn a_tenant_cannot_delete_another_tenants_file() {
    let n = TestNode::boot().await;
    n.seed("file-b1", BOB);
    let alice = n.storage_key(ALICE);

    let resp = n.delete("/v1/files/file-b1", Some(&alice)).await;
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(
        n.node.file_index().get("file-b1").is_some(),
        "Alice deleted Bob's file"
    );
    n.shutdown().await;
}

#[tokio::test]
async fn a_tenant_can_read_and_delete_their_own_file() {
    let n = TestNode::boot().await;
    n.seed("file-a1", ALICE);
    let alice = n.storage_key(ALICE);

    let resp = n.get("/v1/files/file-a1", Some(&alice)).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("JSON");
    assert_eq!(body["id"], "file-a1");
    assert_eq!(body["object"], "file");
    assert_eq!(body["purpose"], "user_data");

    let del = n.delete("/v1/files/file-a1", Some(&alice)).await;
    assert_eq!(del.status(), reqwest::StatusCode::OK);
    let del_body: Value = del.json().await.expect("JSON");
    assert_eq!(del_body["deleted"], true);
    assert!(
        del_body["note"]
            .as_str()
            .unwrap_or_default()
            .contains("not erased on request"),
        "deletion must say what it is not: {del_body}"
    );
    assert!(n.node.file_index().get("file-a1").is_none());
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// The JSON-RPC twin agrees with the REST surface
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_rpc_surface_is_dispatched_and_scope_gated() {
    let n = TestNode::boot().await;
    n.seed("file-a1", ALICE);

    // Reachable at all: an unclassified method would come back -32601.
    let unauthenticated = n.rpc("tenzro_listFiles", json!({}), None).await;
    assert_eq!(
        unauthenticated["error"]["code"], -32004,
        "expected a scope refusal, not a dispatch failure: {unauthenticated}"
    );

    let alice = n.storage_key(ALICE);
    let listed = n.rpc("tenzro_listFiles", json!({}), Some(&alice)).await;
    let data = listed["result"]["data"]
        .as_array()
        .unwrap_or_else(|| panic!("expected a list, got {listed}"));
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["id"], "file-a1");
    n.shutdown().await;
}

#[tokio::test]
async fn the_rpc_surface_enforces_the_same_ownership_boundary() {
    let n = TestNode::boot().await;
    n.seed("file-b1", BOB);
    let alice = n.storage_key(ALICE);

    let resp = n
        .rpc(
            "tenzro_getFile",
            json!({"file_id": "file-b1"}),
            Some(&alice),
        )
        .await;
    assert!(
        resp.get("result").is_none(),
        "Alice read Bob's record over RPC: {resp}"
    );

    let deleted = n
        .rpc(
            "tenzro_deleteFile",
            json!({"file_id": "file-b1"}),
            Some(&alice),
        )
        .await;
    assert!(deleted.get("result").is_none(), "{deleted}");
    assert!(n.node.file_index().get("file-b1").is_some());
    n.shutdown().await;
}

#[tokio::test]
async fn usage_is_reported_per_tenant() {
    let n = TestNode::boot().await;
    n.seed("file-a1", ALICE);
    n.seed("file-a2", ALICE);
    n.seed("file-b1", BOB);

    let alice = n.storage_key(ALICE);
    let usage = n
        .rpc("tenzro_fileStorageUsage", json!({}), Some(&alice))
        .await;
    let r = &usage["result"];
    assert_eq!(r["owner"], ALICE, "{usage}");
    assert_eq!(r["file_count"], 2);
    assert_eq!(r["total_bytes"], 84);
    // Seeded records carry no deal, and the surface must say so rather than
    // let a tenant assume unbilled storage is durable.
    assert_eq!(r["files_without_open_deal"], 2);
    assert!(r["renter_address"].as_str().is_some_and(|s| !s.is_empty()));
    n.shutdown().await;
}

/// An upload on a node with no StorageProvider role must refuse cleanly rather
/// than record a file whose bytes were never stored.
#[tokio::test]
async fn an_upload_without_a_storage_role_is_refused_and_indexes_nothing() {
    let n = TestNode::boot().await;
    let alice = n.storage_key(ALICE);
    let before = n.node.file_index().len();

    let resp = n
        .rpc(
            "tenzro_uploadFile",
            json!({"filename": "notes.txt", "data": "aGVsbG8="}),
            Some(&alice),
        )
        .await;
    assert!(resp.get("result").is_none(), "{resp}");
    assert_eq!(
        n.node.file_index().len(),
        before,
        "a refused upload must not leave an index entry"
    );
    n.shutdown().await;
}
