//! The identity edge, asked through real requests.
//!
//! The unit tests prove the decision. These prove it is reached: each boots a
//! real node in an `[onboarding]` mode and makes a write the identity rule
//! gives to the caller's registered identity, over HTTP JSON-RPC and through
//! the embedded dispatch the MCP server calls for a tool
//! (`tenzro_node::dispatch_embedded`), on the MCP and the A2A surface.

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::{EmbeddedAuth, NodeConfig, RpcServer, TenzroNode, dispatch_embedded};
use tenzro_onboarding_types::onboarding::GateMode;
use tenzro_types::node_access::Surface;
use tokio::sync::broadcast;

/// A write the edge covers by the caller its token names.
const COVERED: &str = "tenzro_fileInferenceChallenge";

struct TestNode {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    node: Arc<TenzroNode>,
    client: reqwest::Client,
}

impl TestNode {
    async fn boot(mode: GateMode) -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let mut config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
            ..Default::default()
        };
        config.onboarding.policy.mode = mode;
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

    /// One JSON-RPC request over HTTP, with no access token.
    async fn rpc(&self, method: &str, params: Value) -> Value {
        self.client
            .post(&self.base_url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .expect("HTTP request")
            .json()
            .await
            .expect("a JSON answer")
    }

    /// One call the way the MCP server makes it for a tool, on `surface`,
    /// with no access token.
    async fn embedded(&self, surface: Surface, method: &str, params: Value) -> Value {
        let auth = EmbeddedAuth {
            surface: Some(surface),
            ..Default::default()
        };
        let payload = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        dispatch_embedded(&self.node, payload, auth).await
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

fn error_message(resp: &Value) -> String {
    resp.get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string()
}

/// The three ways a call arrives, each with no token: an unregistered caller.
async fn each_surface(n: &TestNode, method: &str) -> Vec<(&'static str, String)> {
    vec![
        ("rpc", error_message(&n.rpc(method, json!({})).await)),
        (
            "mcp",
            error_message(&n.embedded(Surface::Mcp, method, json!({})).await),
        ),
        (
            "a2a",
            error_message(&n.embedded(Surface::A2a, method, json!({})).await),
        ),
    ]
}

#[tokio::test]
async fn enforce_refuses_an_unregistered_caller_on_every_surface_before_the_handler() {
    let n = TestNode::boot(GateMode::Enforce).await;
    for (surface, message) in each_surface(&n, COVERED).await {
        assert!(
            message.contains(COVERED) && message.contains("no registered identity"),
            "{surface}: {message}"
        );
        assert!(
            message.contains("register an identity first"),
            "{surface}: {message}"
        );
    }
    n.shutdown().await;
}

#[tokio::test]
async fn audit_admits_the_same_call_and_the_handler_answers() {
    let n = TestNode::boot(GateMode::Audit).await;
    for (surface, message) in each_surface(&n, COVERED).await {
        // The handler's own complaint about the empty params, not the edge's.
        assert!(!message.is_empty(), "{surface}: the handler did not answer");
        assert!(
            !message.contains("no registered identity"),
            "{surface}: {message}"
        );
    }
    n.shutdown().await;
}

#[tokio::test]
async fn enforce_leaves_the_registration_paths_reachable_without_an_identity() {
    let n = TestNode::boot(GateMode::Enforce).await;
    for method in [
        "tenzro_accessChallenge",
        "tenzro_createCustodyChallenge",
        "tenzro_createPasskeySession",
        "tenzro_joinAsMicroNode",
        "tenzro_onboardAutonomousAgent",
    ] {
        for (surface, message) in each_surface(&n, method).await {
            assert!(
                !message.contains("no registered identity"),
                "{method} on {surface}: {message}"
            );
        }
    }
    n.shutdown().await;
}

#[tokio::test]
async fn enforce_admits_the_nodes_own_administrators_before_they_are_on_chain() {
    let n = TestNode::boot(GateMode::Enforce).await;
    let edge = |did: &str| {
        tenzro_node::identity_gate::edge_admits(
            &n.node,
            "tenzro_issueAccessToken",
            Some(did),
            false,
        )
    };
    // Nobody is registered on this fresh chain. A stranger gets no token.
    let stranger = "did:tenzro:human:00000000-0000-4000-8000-000000000001";
    assert!(
        edge(stranger)
            .unwrap_err()
            .contains("no registered identity")
    );
    // An admin the access policy names signs in to set the node up.
    let admin = "did:tenzro:human:00000000-0000-4000-8000-000000000002";
    let mut policy = (*n.node.access().policy()).clone();
    policy.admins.push(admin.to_string());
    n.node
        .access()
        .store()
        .set(policy, "test")
        .expect("policy set");
    assert_eq!(edge(admin), Ok(()));
    assert!(edge(stranger).is_err());
    // So does the operator, where this node knows one.
    if let Some(operator) = n.node.administrator_did() {
        assert_eq!(edge(&operator), Ok(()));
    }
    // A caller the call has proven to be a delegated agent's serving key.
    assert_eq!(
        tenzro_node::identity_gate::edge_admits(
            &n.node,
            "tenzro_issueAccessToken",
            Some(stranger),
            true
        ),
        Ok(())
    );
    n.shutdown().await;
}
