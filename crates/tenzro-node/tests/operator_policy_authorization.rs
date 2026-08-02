//! Machine policy belongs to whoever runs the machine.
//!
//! Four RPCs that change how a node earns, or how much an agent may spend, were
//! reachable with no credential at all. Each was confirmed against a running
//! node before being closed:
//!
//! - `tenzro_setProviderSchedule` — `enabled: false` stops the operator
//!   serving. An unauthenticated kill switch on someone else's revenue.
//! - `tenzro_setProviderPricing` — set their prices to 1 wei, or high enough
//!   that nobody buys.
//! - `tenzro_setSpendingPolicy` / `tenzro_setSpendingLimits` — the runtime
//!   ceiling on what an agent may spend. Raising it defeats the delegation
//!   model these exist to enforce; the probe raised a victim agent's cap to
//!   ~1e12 and got `success: true`.
//!
//! They were open because the gate used to be an allowlist of methods that
//! needed *closing*, so anything new was open until someone remembered. That
//! default is inverted now, but methods predating the inversion still had to be
//! audited one at a time — which is what these tests pin.

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

const ADMIN_TOKEN: &str = "operator-policy-test-token";

fn ensure_admin_token() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: single-threaded init before any node reads the variable.
        unsafe { std::env::set_var("TENZRO_ADMIN_TOKEN", ADMIN_TOKEN) };
    });
}

struct TestNode {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    client: reqwest::Client,
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
            client: reqwest::Client::new(),
        }
    }

    async fn call(&self, method: &str, params: Value, admin: bool) -> Value {
        let mut req = self.client.post(&self.base_url);
        if admin {
            req = req.header("x-tenzro-admin-token", ADMIN_TOKEN);
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

fn schedule(enabled: bool) -> Value {
    json!({
        "enabled": enabled,
        "start_hour": 0,
        "end_hour": 23,
        "timezone": "UTC",
        "days_of_week": [true, true, true, true, true, true, true],
    })
}

fn pricing() -> Value {
    json!({
        "input_price_per_token_wei": "1",
        "output_price_per_token_wei": "1",
        "network_max_input_wei": "999999999999",
        "network_max_output_wei": "999999999999",
    })
}

fn spending_policy() -> Value {
    json!({
        "agent_did": "did:tenzro:machine:victim",
        "max_per_transaction": 999_999_999_999u64,
        "max_daily_spend": 999_999_999_999u64,
        "enabled": true,
    })
}

/// The exact probes that succeeded before the fix, now asserting refusal.
#[tokio::test]
async fn operator_policy_cannot_be_changed_without_the_admin_token() {
    let n = TestNode::boot().await;

    for (method, params, what) in [
        (
            "tenzro_setProviderSchedule",
            schedule(false),
            "a stranger stopped the operator serving",
        ),
        (
            "tenzro_setProviderPricing",
            pricing(),
            "a stranger set the operator's prices",
        ),
        (
            "tenzro_setSpendingPolicy",
            spending_policy(),
            "a stranger raised an agent's spending ceiling",
        ),
        (
            "tenzro_setSpendingLimits",
            spending_policy(),
            "a stranger raised an agent's spending limits",
        ),
    ] {
        let resp = n.call(method, params, false).await;
        assert!(
            resp.get("result").is_none(),
            "{what} ({method} accepted an unauthenticated caller): {resp}"
        );
        assert_eq!(
            resp["error"]["code"].as_i64(),
            Some(-32001),
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

    let disabled = n
        .call("tenzro_setProviderSchedule", schedule(false), true)
        .await;
    assert_eq!(
        disabled["result"]["enabled"], false,
        "the operator could not disable their own schedule: {disabled}"
    );

    let enabled = n
        .call("tenzro_setProviderSchedule", schedule(true), true)
        .await;
    assert_eq!(enabled["result"]["enabled"], true, "{enabled}");

    let priced = n.call("tenzro_setProviderPricing", pricing(), true).await;
    assert!(
        priced.get("result").is_some(),
        "the operator could not set their own pricing: {priced}"
    );
    n.shutdown().await;
}

/// Reading policy stays open. A prospective customer has to be able to see what
/// a provider charges before buying, and a price is not a secret.
#[tokio::test]
async fn reading_provider_policy_needs_no_credential() {
    let n = TestNode::boot().await;
    for method in ["tenzro_getProviderSchedule", "tenzro_getProviderPricing"] {
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

/// The worst outcome in the audit: rewriting a registry entry's `endpoint`
/// redirects everyone who invokes it to attacker-controlled code. Confirmed
/// against a running node before the fix — a stranger pointed another
/// developer's skill at `https://attacker.example/pwn`.
///
/// The admin token would be the wrong gate here. These entries belong to
/// developers publishing on someone else's node, so the operator must not be
/// able to rewrite them either; the creator proves their own DID instead.
#[tokio::test]
async fn a_stranger_cannot_rewrite_another_developers_skill() {
    let n = TestNode::boot().await;

    let registered = n
        .call(
            "tenzro_registerSkill",
            json!({
                "name": "alices-skill",
                "description": "d",
                "creator_did": "did:tenzro:human:alice",
                "endpoint": "https://alice.example/skill",
                "tags": ["x"],
            }),
            false,
        )
        .await;
    let skill_id = registered["result"]["skill_id"]
        .as_str()
        .unwrap_or_else(|| panic!("register failed: {registered}"))
        .to_string();

    let attack = n
        .call(
            "tenzro_updateSkill",
            json!({ "skill_id": skill_id, "endpoint": "https://attacker.example/pwn" }),
            false,
        )
        .await;
    assert!(
        attack.get("result").is_none(),
        "a stranger rewrote another developer's skill endpoint: {attack}"
    );

    // The admin token must not help either — the entry is not the operator's.
    let as_operator = n
        .call(
            "tenzro_updateSkill",
            json!({ "skill_id": skill_id, "endpoint": "https://operator.example/pwn" }),
            true,
        )
        .await;
    assert!(
        as_operator.get("result").is_none(),
        "the node operator rewrote a developer's skill: {as_operator}"
    );

    // And the entry still points where its creator put it.
    let listed = n
        .call("tenzro_getSkill", json!({ "skill_id": skill_id }), false)
        .await;
    let endpoint = listed["result"]["endpoint"].as_str().unwrap_or_default();
    assert_eq!(endpoint, "https://alice.example/skill", "{listed}");
    n.shutdown().await;
}

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
