//! Every method the node serves is reachable from every client surface.
//!
//! # Why this is a test and not a spreadsheet
//!
//! Coverage was measured by hand once and came back between 35% and 76%
//! depending on the surface, with the surfaces disagreeing about *which*
//! methods they covered. A number in a document does not stop that recurring:
//! the next RPC re-opens the gap in five places, silently, and the developer
//! who needs it finds out at the point of use.
//!
//! So the claim is pinned here instead. The node's own method registry is the
//! source — the classification test in `rpc_gates` already refuses to pass
//! while any dispatch arm is unclassified, so the registry *is* the dispatcher's
//! method set rather than a copy of it. This file then asserts that each
//! surface can reach all of it.
//!
//! # What "reachable" means
//!
//! Two ways, and both count:
//!
//! 1. A **named binding** — a dedicated MCP tool, SDK method, or CLI command.
//!    Better ergonomics, and what the common paths have.
//! 2. The **universal gateway** — discovery plus a by-name call, present on
//!    every surface.
//!
//! A surface with the gateway covers 100% by construction. That is the point:
//! it makes coverage a property of the architecture rather than of anyone's
//! diligence. These tests verify the gateway is actually wired on each surface
//! and actually works, because a gateway that exists in a source file and is
//! not mounted covers nothing.

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::api_key::{ApiKeyScope, KeyClass};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

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

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

// ---------------------------------------------------------------------------
// The registry is the whole method surface
// ---------------------------------------------------------------------------

/// Everything downstream rests on this: the registry the surfaces enumerate is
/// the dispatcher's own method set.
#[tokio::test]
async fn the_directory_reports_every_method_the_node_serves() {
    let n = TestNode::boot().await;
    let resp = n.rpc("tenzro_listRpcMethods", json!({})).await;
    let result = &resp["result"];
    let listed = result["methods"].as_array().expect("a method list");
    let total = result["total"].as_u64().expect("a total");

    let expected = tenzro_node::rpc_gates::all_methods();
    assert_eq!(listed.len(), expected.len());
    assert_eq!(total as usize, expected.len());
    assert!(
        expected.len() > 900,
        "the registry looks truncated: {} methods",
        expected.len()
    );

    let got: std::collections::BTreeSet<&str> =
        listed.iter().filter_map(|m| m["method"].as_str()).collect();
    for m in &expected {
        assert!(
            got.contains(m),
            "{m} is served but absent from the directory"
        );
    }
    n.shutdown().await;
}

/// The directory has to be usable, not just complete — 900 rows in one response
/// is not something a caller wants by default.
#[tokio::test]
async fn the_directory_can_be_narrowed() {
    let n = TestNode::boot().await;

    let eth = n
        .rpc("tenzro_listRpcMethods", json!({"namespace": "eth"}))
        .await;
    let rows = eth["result"]["methods"].as_array().expect("list");
    assert!(!rows.is_empty());
    assert!(
        rows.iter()
            .all(|m| m["method"].as_str().unwrap_or_default().starts_with("eth_"))
    );

    let hits = n
        .rpc("tenzro_listRpcMethods", json!({"contains": "database"}))
        .await;
    let rows = hits["result"]["methods"].as_array().expect("list");
    assert!(rows.len() >= 12, "expected the database namespace");

    // And it reports what a caller needs in order to act: the gate, and the
    // scope of key to go and get.
    let files = n
        .rpc("tenzro_listRpcMethods", json!({"contains": "uploadFile"}))
        .await;
    let upload = files["result"]["methods"]
        .as_array()
        .and_then(|a| a.first())
        .expect("uploadFile");
    assert_eq!(upload["gate"], "open");
    assert_eq!(upload["scope"], "storage");
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// REST reaches everything
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rest_can_discover_and_call_any_method() {
    let n = TestNode::boot().await;

    let dir: Value = n
        .client
        .get(format!("{}/v1/rpc", n.base_url))
        .send()
        .await
        .expect("HTTP")
        .json()
        .await
        .expect("JSON");
    assert_eq!(
        dir["total"].as_u64().unwrap_or(0) as usize,
        tenzro_node::rpc_gates::all_methods().len()
    );

    // A method with no dedicated REST route of its own, reached by name.
    let resp = n
        .client
        .post(format!("{}/v1/rpc/eth_blockNumber", n.base_url))
        .json(&json!({}))
        .send()
        .await
        .expect("HTTP");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("JSON");
    assert!(body.is_string() || body.is_number(), "{body}");
    n.shutdown().await;
}

/// An unknown method is a 404 that names the discovery call, rather than a
/// generic failure the caller has to guess at.
#[tokio::test]
async fn the_rest_gateway_refuses_an_unknown_method_helpfully() {
    let n = TestNode::boot().await;
    let resp = n
        .client
        .post(format!("{}/v1/rpc/tenzro_notAMethod", n.base_url))
        .json(&json!({}))
        .send()
        .await
        .expect("HTTP");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    let body: Value = resp.json().await.expect("JSON");
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(msg.contains("tenzro_listRpcMethods"), "{msg}");
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// The gateway widens ergonomics, not authorization
// ---------------------------------------------------------------------------

/// The property that makes the gateway safe to ship. If it bypassed a gate, it
/// would be a privilege-escalation path wearing a convenience label.
#[tokio::test]
async fn the_gateway_does_not_bypass_the_admin_gate() {
    let n = TestNode::boot().await;

    // Admin-gated, called without the operator token.
    let resp = n
        .client
        .post(format!("{}/v1/rpc/tenzro_listApiKeys", n.base_url))
        .json(&json!({}))
        .send()
        .await
        .expect("HTTP");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the gateway reached an admin method without the admin token"
    );
    n.shutdown().await;
}

#[tokio::test]
async fn the_gateway_does_not_bypass_the_api_key_scope_gate() {
    let n = TestNode::boot().await;

    // Storage-scoped, called with no key at all.
    let unkeyed = n
        .client
        .post(format!("{}/v1/rpc/tenzro_listFiles", n.base_url))
        .json(&json!({}))
        .send()
        .await
        .expect("HTTP");
    assert_eq!(unkeyed.status(), reqwest::StatusCode::UNAUTHORIZED);

    // And with a key carrying the wrong scope.
    let wrong = n
        .node
        .api_key_manager()
        .expect("manager")
        .issue(
            Some("did:tenzro:human:alice".to_string()),
            "wrong-scope",
            vec![ApiKeyScope::Inference],
            KeyClass::Subject,
            None,
            None,
            None,
            None,
        )
        .expect("issue")
        .key;
    let mis_scoped = n
        .client
        .post(format!("{}/v1/rpc/tenzro_listFiles", n.base_url))
        .header("x-tenzro-api-key", &wrong)
        .json(&json!({}))
        .send()
        .await
        .expect("HTTP");
    assert_eq!(
        mis_scoped.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the gateway ignored the API-key scope gate"
    );

    // The correctly-scoped key gets through, so the gate is a gate and not a
    // wall.
    let right = n
        .node
        .api_key_manager()
        .expect("manager")
        .issue(
            Some("did:tenzro:human:alice".to_string()),
            "right-scope",
            vec![ApiKeyScope::Storage],
            KeyClass::Subject,
            None,
            None,
            None,
            None,
        )
        .expect("issue")
        .key;
    let ok = n
        .client
        .post(format!("{}/v1/rpc/tenzro_listFiles", n.base_url))
        .header("x-tenzro-api-key", &right)
        .json(&json!({}))
        .send()
        .await
        .expect("HTTP");
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    n.shutdown().await;
}

/// A method nobody classified stays unreachable through the gateway too — the
/// default-deny classification is not something the gateway routes around.
#[tokio::test]
async fn the_gateway_respects_default_deny_classification() {
    let n = TestNode::boot().await;
    let resp = n
        .client
        .post(format!(
            "{}/v1/rpc/tenzro_methodNobodyClassified",
            n.base_url
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("HTTP");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Every surface carries the gateway
// ---------------------------------------------------------------------------

/// The parity claim, as a test over the surfaces' own sources.
///
/// Each client surface must ship both halves — discovery *and* a by-name
/// call. Discovery alone tells a caller about a method they cannot invoke;
/// invocation alone leaves them guessing at names. Checking the source rather
/// than the behaviour is deliberate here: these are four different languages,
/// and the alternative is four language-specific harnesses to prove a fact
/// about wiring.
#[test]
fn every_client_surface_ships_discovery_and_a_by_name_call() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");

    // (surface, files, discovery marker, call marker)
    let surfaces: &[(&str, &[&str], &str, &str)] = &[
        (
            "MCP",
            &["crates/tenzro-node/src/mcp/server.rs"],
            "list_rpc_methods",
            "call_rpc",
        ),
        (
            "Rust SDK",
            &[
                "sdk/tenzro-sdk/src/gateway.rs",
                "sdk/tenzro-sdk/src/client.rs",
            ],
            "tenzro_listRpcMethods",
            "fn gateway",
        ),
        (
            "TypeScript SDK",
            &[
                "sdk/tenzro-ts-sdk/src/gateway.ts",
                "sdk/tenzro-ts-sdk/src/client.ts",
            ],
            "tenzro_listRpcMethods",
            "GatewayClient",
        ),
        (
            "CLI",
            &["crates/tenzro-cli/src/commands/rpc_cmd.rs"],
            "tenzro_listRpcMethods",
            "RpcCallCmd",
        ),
        (
            "A2A",
            &["integrations/a2a/tenzro_a2a_server/agent_card.py"],
            "rpc-gateway",
            "rpc.call",
        ),
        (
            "OpenClaw",
            &["skills/openclaw-tenzro/tools/tenzro_rpc.py"],
            "def list_rpc_methods",
            "def call_rpc",
        ),
        (
            "REST",
            &["crates/tenzro-node/src/rpc_gateway.rs"],
            "/v1/rpc",
            "/v1/rpc/:method",
        ),
    ];

    for (name, files, discovery, call) in surfaces {
        let src: String = files
            .iter()
            .map(|f| {
                std::fs::read_to_string(root.join(f))
                    .unwrap_or_else(|e| panic!("{name}: cannot read {f}: {e}"))
            })
            .collect();
        assert!(
            src.contains(discovery),
            "{name} has no method discovery (looked for {discovery:?}) — a caller cannot find \
             out what the node serves"
        );
        assert!(
            src.contains(call),
            "{name} has no by-name call (looked for {call:?}) — a caller can discover methods \
             it cannot invoke"
        );
    }
}

/// The gateway must be mounted, not merely written. A router that was never
/// merged answers 404 for everything, which no source-level check would catch.
#[tokio::test]
async fn the_rest_gateway_is_actually_mounted() {
    let n = TestNode::boot().await;
    let resp = n
        .client
        .get(format!("{}/v1/rpc", n.base_url))
        .send()
        .await
        .expect("HTTP");
    assert_ne!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "/v1/rpc is not mounted"
    );
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    n.shutdown().await;
}
