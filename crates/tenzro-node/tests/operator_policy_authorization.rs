//! Machine policy belongs to whoever runs the machine.
//!
//! RPCs that change how a node earns were reachable with no credential at all.
//! Each was confirmed against a running node before being closed:
//!
//! - `tenzro_setProviderPricing` — set their prices to 1 wei, or high enough
//!   that nobody buys.
//!
//! They were open because the gate used to be an allowlist of methods that
//! needed *closing*, so anything new was open until someone remembered. That
//! default is inverted now, but methods predating the inversion still had to be
//! audited one at a time — which is what these tests pin.

mod dpop_bearer;
mod passkey_holder;

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

/// The operator every test node admits.
fn operator() -> &'static dpop_bearer::OperatorKey {
    static KEY: std::sync::OnceLock<dpop_bearer::OperatorKey> = std::sync::OnceLock::new();
    KEY.get_or_init(dpop_bearer::OperatorKey::new)
}

struct TestNode {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    client: reqwest::Client,
    node: Arc<TenzroNode>,
}

impl TestNode {
    async fn boot() -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        dpop_bearer::admit_operator(tmp.path(), &operator().did());
        let config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
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
            client: reqwest::Client::new(),
            node,
        }
    }

    async fn call(&self, method: &str, params: Value, admin: bool) -> Value {
        if admin {
            let op = operator().sign_in(&self.client, &self.base_url).await;
            return op.call(&self.client, &self.base_url, method, params).await;
        }
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

fn pricing() -> Value {
    json!({
        "default": {
            "denom": "wei",
            "lines": {
                "input_tokens": { "price": "1" },
                "output_tokens": { "price": "1" },
            },
        },
    })
}

/// The exact probes that succeeded before the fix, now asserting refusal.
#[tokio::test]
async fn operator_policy_cannot_be_changed_without_the_operators_token() {
    let n = TestNode::boot().await;

    for (method, params, what) in [(
        "tenzro_setProviderPricing",
        pricing(),
        "a stranger set the operator's prices",
    )] {
        let resp = n.call(method, params, false).await;
        assert!(
            resp.get("result").is_none(),
            "{what} ({method} accepted an unauthenticated caller): {resp}"
        );
        assert_eq!(
            resp["error"]["code"].as_i64(),
            Some(-32004),
            "{method} was refused for the wrong reason: {resp}"
        );
    }
    n.shutdown().await;
}

/// The other half: the operator can still administer their own machine. A gate
/// that refused everyone would pass the test above and break the node.
#[tokio::test]
async fn the_operator_can_still_set_their_own_policy() {
    let n = TestNode::boot().await;

    let priced = n.call("tenzro_setProviderPricing", pricing(), true).await;
    assert!(
        priced.get("result").is_some(),
        "the operator could not set their own pricing: {priced}"
    );
    n.shutdown().await;
}

/// The price the operator sets is the one in force after a restart, not the
/// configured one. Tested through the persistence layer: a started node's
/// background tasks hold the RocksDB handle for the life of the process, so
/// the pair a restart consists of is asserted instead, the write and the
/// loader startup applies.
#[tokio::test]
async fn the_operators_pricing_is_persisted_and_reloaded() {
    let n = TestNode::boot().await;
    let store = n.node.storage().cloned().expect("the node has storage");
    assert!(TenzroNode::saved_provider_pricing(store.as_ref()).is_none());

    let priced = n
        .call(
            "tenzro_setProviderPricing",
            json!({
                "default": {
                    "denom": "wei",
                    "lines": {
                        "input_tokens": { "price": "123000000000" },
                        "output_tokens": { "price": "456000000000" },
                    },
                },
                "models": {
                    "qwen3-0.6b": {
                        "denom": "nano_usd",
                        "lines": { "output_tokens": { "price": "1000000000", "per_exp": 6 } },
                    },
                },
            }),
            true,
        )
        .await;
    assert!(priced.get("result").is_some(), "{priced}");
    let saved = TenzroNode::saved_provider_pricing(store.as_ref()).expect("the pricing was saved");
    assert_eq!(saved.default.lines["input_tokens"].price, 123_000_000_000);
    assert_eq!(saved.default.lines["output_tokens"].price, 456_000_000_000);
    assert_eq!(
        saved.card_for("qwen3-0.6b").denom,
        tenzro_types::price_card::Denom::NanoUsd
    );

    // A card naming a unit nobody registered is refused, and nothing changes.
    let bad = n
        .call(
            "tenzro_setProviderPricing",
            json!({ "default": { "lines": { "warp_drive": { "price": "1" } } } }),
            true,
        )
        .await;
    assert!(bad.get("error").is_some(), "{bad}");
    let still = TenzroNode::saved_provider_pricing(store.as_ref()).expect("saved");
    assert_eq!(still, saved);
    n.shutdown().await;
}

/// Reading policy stays open. A prospective customer has to be able to see what
/// a provider charges before buying, and a price is not a secret.
#[tokio::test]
async fn reading_provider_policy_needs_no_credential() {
    let n = TestNode::boot().await;
    for method in ["tenzro_getProviderPricing"] {
        let resp = n.call(method, json!({}), false).await;
        assert!(
            resp.get("result").is_some(),
            "{method} should stay readable: {resp}"
        );
    }
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Registry entries belong to their creators
// ---------------------------------------------------------------------------

/// A tool with no recorded creator is one of the node's own built-ins. Letting
/// an unowned row through unchecked would make "register a tool with no
/// creator_did" the way to opt out of the gate.
#[tokio::test]
async fn a_tool_with_no_creator_cannot_be_updated_by_anyone() {
    let n = TestNode::boot().await;
    let listed = n.call("tenzro_listTools", json!({}), false).await;
    let tools = listed["result"].as_array().cloned().unwrap_or_default();
    let Some(builtin) = tools
        .iter()
        .find(|t| t.get("creator_did").map(|c| c.is_null()).unwrap_or(true))
    else {
        // No unowned tool on this node; nothing to assert.
        n.shutdown().await;
        return;
    };
    let id = builtin["tool_id"].as_str().unwrap_or_default().to_string();

    let attempt = n
        .call(
            "tenzro_updateTool",
            json!({ "tool_id": id, "endpoint": "https://attacker.example/pwn" }),
            false,
        )
        .await;
    assert!(attempt.get("result").is_none(), "{attempt}");
    assert!(
        attempt["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("records no creator"),
        "{attempt}"
    );
    n.shutdown().await;
}
