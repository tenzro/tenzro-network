//! A private node is fully capable — just not discoverable.
//!
//! The whole claim of node privacy mode is that these two things are separable:
//! what a node *can do* and what it *tells peers it can do*. These tests hold
//! both halves at once, because either alone is a different (and useless)
//! feature — a node that hides by refusing work is just a broken node, and a
//! node that "hides" while still announcing has not hidden.
//!
//! The distinction that matters most is stated on every response and asserted
//! here: **privacy is not access control**. Suppressing an advertisement stops
//! a stranger *finding* a node; it does not stop them *using* it if they learn
//! the address. Anyone who reads "private" as "protected" has misread it.

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_types::node_visibility::Capability;
use tokio::sync::broadcast;

struct TestNode {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    node: Arc<TenzroNode>,
    client: reqwest::Client,
}

/// The operator token these tests present. Set into the environment before the
/// first node boots, because that is where the node reads it from.
const TEST_ADMIN_TOKEN: &str = "visibility-test-admin-token";

fn ensure_admin_token() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: single-threaded init before any node reads the variable.
        unsafe { std::env::set_var("TENZRO_ADMIN_TOKEN", TEST_ADMIN_TOKEN) };
    });
}

impl TestNode {
    async fn boot() -> Self {
        ensure_admin_token();
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

    async fn rpc(&self, method: &str, params: Value) -> Value {
        self.client
            .post(&self.base_url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .expect("HTTP request")
            .json::<Value>()
            .await
            .expect("JSON parse")
    }

    /// Set visibility as the operator.
    ///
    /// Changing what a machine advertises is the operator's own decision, so
    /// the write is admin-gated while the read is open — a caller may
    /// reasonably ask what a node offers.
    async fn set_visibility(&self, params: Value) -> Value {
        self.client
            .post(&self.base_url)
            .header("x-tenzro-admin-token", TEST_ADMIN_TOKEN)
            .json(&json!({
                "jsonrpc": "2.0", "id": 1,
                "method": "tenzro_setNodeVisibility", "params": params,
            }))
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

fn capability(v: &Value, name: &str) -> Value {
    v["capabilities"]
        .as_array()
        .expect("capability list")
        .iter()
        .find(|c| c["capability"] == name)
        .unwrap_or_else(|| panic!("{name} not reported"))
        .clone()
}

// ---------------------------------------------------------------------------
// Default and reporting
// ---------------------------------------------------------------------------

/// A node whose operator expressed no preference is an ordinary participant.
/// Defaulting to private would mean joining the network and never being found —
/// a confusing silence, not a safe default, because privacy here protects
/// discoverability rather than secrets.
#[tokio::test]
async fn a_node_advertises_everything_by_default() {
    let n = TestNode::boot().await;
    let v = n.rpc("tenzro_nodeVisibility", json!({})).await;
    let result = &v["result"];
    let caps = result["capabilities"].as_array().expect("list");
    assert_eq!(caps.len(), Capability::ALL.len());
    assert!(
        caps.iter().all(|c| c["advertised"] == true),
        "something defaulted to private: {result}"
    );
    assert_eq!(result["has_private_capabilities"], false);
    n.shutdown().await;
}

/// Every response says what privacy does and does not do. The failure mode
/// being guarded against is an operator marking something private and believing
/// it is therefore protected.
#[tokio::test]
async fn the_response_says_privacy_is_not_access_control() {
    let n = TestNode::boot().await;
    let v = n.rpc("tenzro_nodeVisibility", json!({})).await;
    let note = v["result"]["note"].as_str().unwrap_or_default();
    assert!(note.contains("discovery, not access"), "{note}");
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Per-capability, not all-or-nothing
// ---------------------------------------------------------------------------

/// The configurations that matter are mixed: a public web app on a machine
/// whose GPUs are reserved for the operator's own team. A node-wide switch
/// would force running two nodes to express one intent.
#[tokio::test]
async fn capabilities_hide_independently() {
    let n = TestNode::boot().await;
    let v = n
        .set_visibility(json!({ "capability": "ai", "visibility": "private" }))
        .await;
    let result = &v["result"];
    assert_eq!(capability(result, "ai")["advertised"], false, "{result}");
    assert_eq!(capability(result, "hosting")["advertised"], true);
    assert_eq!(capability(result, "storage")["advertised"], true);
    assert_eq!(result["has_private_capabilities"], true);

    // And the node agrees internally — the policy is what the announcement
    // path will actually read.
    assert!(!n.node.advertises(Capability::Ai));
    assert!(n.node.advertises(Capability::Hosting));
    n.shutdown().await;
}

/// The one-flag answer for an operator who wants a node nobody finds.
#[tokio::test]
async fn the_private_preset_hides_everything_it_can() {
    let n = TestNode::boot().await;
    let v = n.set_visibility(json!({ "preset": "private" })).await;
    let result = &v["result"];
    for cap in [
        "ai", "storage", "database", "hosting", "rpc", "tee", "compute",
    ] {
        assert_eq!(
            capability(result, cap)["advertised"],
            false,
            "{cap} was still advertised: {result}"
        );
    }
    n.shutdown().await;
}

/// Consensus is the exception, and it is refused rather than silently ignored.
/// An operator who set it and got silence would believe their validator was
/// hidden and still earning.
#[tokio::test]
async fn a_validator_cannot_be_hidden() {
    let n = TestNode::boot().await;
    let v = n
        .set_visibility(json!({ "capability": "validator", "visibility": "private" }))
        .await;
    assert!(
        v.get("result").is_none(),
        "hiding a validator was accepted: {v}"
    );
    let msg = v["error"]["message"].as_str().unwrap_or_default();
    assert!(msg.contains("cannot vote"), "{msg}");

    // The refusal left the policy untouched.
    let after = n.rpc("tenzro_nodeVisibility", json!({})).await;
    assert_eq!(
        capability(&after["result"], "validator")["advertised"],
        true
    );

    // And the `private` preset does not sneak it in.
    let preset = n.set_visibility(json!({ "preset": "private" })).await;
    assert_eq!(
        capability(&preset["result"], "validator")["advertised"],
        true,
        "the private preset hid consensus"
    );
    n.shutdown().await;
}

#[tokio::test]
async fn a_capability_can_be_published_again() {
    let n = TestNode::boot().await;
    n.set_visibility(json!({ "preset": "private" })).await;
    assert!(!n.node.advertises(Capability::Storage));

    let v = n
        .set_visibility(json!({ "capability": "storage", "visibility": "network" }))
        .await;
    assert_eq!(capability(&v["result"], "storage")["advertised"], true);
    assert!(n.node.advertises(Capability::Storage));
    n.shutdown().await;
}

#[tokio::test]
async fn an_unknown_capability_or_visibility_is_refused() {
    let n = TestNode::boot().await;
    // Refused rather than defaulted: a typo that silently became "advertise
    // everything" is the wrong way to be wrong.
    let bad_cap = n
        .set_visibility(json!({ "capability": "gpu", "visibility": "private" }))
        .await;
    assert!(bad_cap.get("result").is_none(), "{bad_cap}");

    let bad_vis = n
        .set_visibility(json!({ "capability": "ai", "visibility": "hidden" }))
        .await;
    assert!(bad_vis.get("result").is_none(), "{bad_vis}");

    let bad_preset = n.set_visibility(json!({ "preset": "stealth" })).await;
    assert!(bad_preset.get("result").is_none(), "{bad_preset}");
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Private does not mean crippled
// ---------------------------------------------------------------------------

/// The half that makes this a feature rather than a fault: a fully private node
/// still answers everything it did before. Hiding is a discovery property.
#[tokio::test]
async fn a_fully_private_node_still_serves_every_surface() {
    let n = TestNode::boot().await;
    n.set_visibility(json!({ "preset": "private" })).await;

    // Core RPC.
    let block = n.rpc("eth_blockNumber", json!([])).await;
    assert!(block.get("result").is_some(), "{block}");

    // Discovery of its own method surface — all 900-odd, unchanged.
    let methods = n.rpc("tenzro_listRpcMethods", json!({})).await;
    assert_eq!(
        methods["result"]["total"].as_u64().unwrap_or(0) as usize,
        tenzro_node::rpc_gates::all_methods().len(),
        "a private node served a smaller method surface"
    );

    // The REST gateway.
    let rest = n
        .client
        .get(format!("{}/v1/rpc", n.base_url))
        .send()
        .await
        .expect("HTTP");
    assert_eq!(rest.status(), reqwest::StatusCode::OK);

    // An AI control-plane read, with AI marked private.
    let budget = n.rpc("tenzro_memoryBudget", json!({})).await;
    assert!(
        budget.get("result").is_some(),
        "a private AI capability stopped answering: {budget}"
    );
    n.shutdown().await;
}

/// Privacy must not have quietly become an authorization mechanism. A gated
/// method is gated on a private node exactly as on a public one — no more, no
/// less — because the gates are the API-key scopes, not the visibility policy.
#[tokio::test]
async fn privacy_does_not_change_who_is_authorized() {
    let n = TestNode::boot().await;

    let before = n.rpc("tenzro_listFiles", json!({})).await;
    let before_code = before["error"]["code"].as_i64();
    assert_eq!(
        before_code,
        Some(-32004),
        "expected a scope refusal: {before}"
    );

    n.set_visibility(json!({ "preset": "private" })).await;

    let after = n.rpc("tenzro_listFiles", json!({})).await;
    assert_eq!(
        after["error"]["code"].as_i64(),
        before_code,
        "going private changed an authorization outcome: {after}"
    );

    // And an admin method is still admin-gated, not newly open.
    let admin = n.rpc("tenzro_listApiKeys", json!({})).await;
    assert!(admin.get("result").is_none(), "{admin}");
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// The choice survives a restart
// ---------------------------------------------------------------------------

/// A node that came back advertising capabilities its operator had hidden would
/// be worse than never offering the switch.
///
/// Tested through the persistence layer rather than by restarting in-process: a
/// started node's background tasks hold the RocksDB handle for the life of the
/// process, so a second node on the same directory cannot open it. What is
/// asserted instead is the exact pair that a restart consists of — the policy
/// was written durably, and the loader boot calls returns it.
#[tokio::test]
async fn the_policy_is_persisted_and_reloaded() {
    let n = TestNode::boot().await;

    // Nothing written yet: a fresh node loads the public default.
    let store = n.node.storage().cloned().expect("the node has storage")
        as Arc<dyn tenzro_storage::KvStore>;
    assert!(
        !tenzro_node::visibility_rpc::load(&store).has_private_capabilities(),
        "a node with no stored policy should load as public"
    );

    let set = n
        .set_visibility(json!({ "capability": "ai", "visibility": "private" }))
        .await;
    assert!(set.get("result").is_some(), "{set}");

    // The loader boot uses now returns the operator's choice.
    let reloaded = tenzro_node::visibility_rpc::load(&store);
    assert!(
        !reloaded.is_advertised(Capability::Ai),
        "the policy was not persisted, so a restart would re-advertise it"
    );
    assert!(
        reloaded.is_advertised(Capability::Hosting),
        "persistence over-applied the change"
    );

    // And it round-trips as a whole, not just the one field.
    assert_eq!(reloaded, n.node.visibility());
    n.shutdown().await;
}
