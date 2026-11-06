//! One node visibility, applied to every resource the node offers.
//!
//! The operator sets `public`, `gated` or `private` once. Every model (of every
//! type) follows it unless the model carries its own override. These tests hold the rule end to end: what is announced, what is
//! payable, what needs a key, and what only the node's own callers reach, on
//! every inference route.

mod dpop_bearer;
mod passkey_holder;

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::inference_admission::{NodeInferenceAdmission, from_overlay};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_payments::middleware::InferenceAccess;
use tenzro_types::Visibility;
use tenzro_types::node_access::Surface;
use tokio::sync::broadcast;

struct TestNode {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    node: Arc<TenzroNode>,
    client: reqwest::Client,
}

/// The operator every test node admits.
fn operator() -> &'static dpop_bearer::OperatorKey {
    static KEY: std::sync::OnceLock<dpop_bearer::OperatorKey> = std::sync::OnceLock::new();
    KEY.get_or_init(dpop_bearer::OperatorKey::new)
}

/// A caller the access policy admits to inference by name, the way an
/// operator grants a customer a gated model.
fn member() -> &'static dpop_bearer::OperatorKey {
    static KEY: std::sync::OnceLock<dpop_bearer::OperatorKey> = std::sync::OnceLock::new();
    KEY.get_or_init(dpop_bearer::OperatorKey::new)
}

/// The test nodes' policy: open, with the operator as admin and `member()`
/// admitted to inference by name.
fn policy() -> tenzro_types::node_access::NodeAccessPolicy {
    use tenzro_types::node_access::{MethodClass, NodeAccessPolicy, Rule, SurfaceRule};
    let mut p = NodeAccessPolicy::default();
    p.admins.push(operator().did());
    p.rules.push(SurfaceRule {
        surface: None,
        class: MethodClass::Inference,
        rule: Rule::Any {
            rules: vec![
                Rule::Allow {
                    dids: vec![member().did()],
                    orgs: vec![],
                },
                Rule::Open,
            ],
        },
    });
    p
}

impl TestNode {
    async fn boot() -> Self {
        Self::boot_with(|_| {}).await
    }

    async fn boot_with(configure: impl FnOnce(&mut NodeConfig)) -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        dpop_bearer::write_policy(tmp.path(), &policy());
        let mut config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
            ..Default::default()
        };
        configure(&mut config);
        let mut node = TenzroNode::new(config).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);

        let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string())
            .with_inference_admission(Arc::new(NodeInferenceAdmission::for_node(&node)));
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

    /// Set the node's visibility as the operator (the write is admin-class).
    async fn set_visibility(&self, params: Value) -> Value {
        let op = operator().sign_in(&self.client, &self.base_url).await;
        op.call(
            &self.client,
            &self.base_url,
            "tenzro_setNodeVisibility",
            params,
        )
        .await
    }

    /// The models this node lists itself as serving to the network, and the
    /// key-required subset.
    async fn announced(&self) -> (Vec<String>, Vec<String>) {
        let providers = self.rpc("tenzro_listProviders", json!({})).await;
        let local = providers["result"]["providers"]
            .as_array()
            .and_then(|a| a.iter().find(|p| p["source"] == "local").cloned());
        let list = |field: &str| -> Vec<String> {
            local
                .as_ref()
                .and_then(|p| p[field].as_array().cloned())
                .unwrap_or_default()
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        };
        (list("served_models"), list("key_required_models"))
    }

    /// The admission decision for a keyless caller arriving from off this
    /// machine (over the overlay), so the loopback exemption does not apply.
    async fn keyless_off_node(&self, model: &str) -> InferenceAccess {
        let admission = NodeInferenceAdmission::for_node(&self.node);
        from_overlay(async move { admission.decide_as(Surface::Iroh, None, Some(model)) }).await
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

// ---------------------------------------------------------------------------
// The setting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_node_is_public_by_default_and_says_so() {
    let n = TestNode::boot().await;
    let v = n.rpc("tenzro_nodeVisibility", json!({})).await;
    assert_eq!(v["result"]["visibility"], "public", "{v}");
    assert_eq!(v["result"]["announced"], true, "{v}");
    assert_eq!(n.node.visibility(), Visibility::Public);
    n.shutdown().await;
}

#[tokio::test]
async fn the_configured_visibility_applies_at_start() {
    let n = TestNode::boot_with(|c| c.visibility = Visibility::Gated).await;
    assert_eq!(n.node.visibility(), Visibility::Gated);
    n.shutdown().await;
}

#[tokio::test]
async fn setting_the_visibility_takes_the_three_values_only() {
    let n = TestNode::boot().await;
    for v in ["gated", "private", "public"] {
        let set = n.set_visibility(json!({ "visibility": v })).await;
        assert_eq!(set["result"]["visibility"], v, "{set}");
    }
    for bad in [json!({ "visibility": "network" }), json!({})] {
        let set = n.set_visibility(bad).await;
        assert!(set.get("result").is_none(), "{set}");
        let msg = set["error"]["message"].as_str().unwrap_or_default();
        assert!(msg.contains("'public', 'gated' or 'private'"), "{msg}");
    }
    // The write is the operator's: without the admin token it is refused.
    let anon = n
        .rpc(
            "tenzro_setNodeVisibility",
            json!({ "visibility": "private" }),
        )
        .await;
    assert!(anon.get("result").is_none(), "{anon}");
    assert_eq!(n.node.visibility(), Visibility::Public);
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Models follow the node unless they override it
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_public_node_announces_a_model_without_an_override_and_serves_it_at_its_price() {
    let n = TestNode::boot().await;
    n.node.served_models.insert("m".to_string(), None);

    let (served, key_required) = n.announced().await;
    assert_eq!(served, vec!["m".to_string()], "announced");
    assert!(key_required.is_empty());
    // Price 0: free to anyone.
    assert!(matches!(
        n.keyless_off_node("m").await,
        InferenceAccess::Allow
    ));
    n.shutdown().await;
}

#[tokio::test]
async fn a_public_model_is_paid_for_at_the_operator_price() {
    let n = TestNode::boot_with(|c| c.payments.default_amount = 5).await;
    n.node.served_models.insert("m".to_string(), None);
    assert!(matches!(
        n.keyless_off_node("m").await,
        InferenceAccess::NeedPayment
    ));
    n.shutdown().await;
}

#[tokio::test]
async fn a_private_node_announces_nothing_without_an_override() {
    let n = TestNode::boot().await;
    n.node.served_models.insert("m".to_string(), None);
    let set = n.set_visibility(json!({ "visibility": "private" })).await;
    assert_eq!(set["result"]["visibility"], "private", "{set}");

    let (served, _) = n.announced().await;
    assert!(served.is_empty(), "a private node announced {served:?}");
    assert!(matches!(
        n.keyless_off_node("m").await,
        InferenceAccess::Refuse(403, _)
    ));
    // Its own callers still reach it.
    let local = NodeInferenceAdmission::for_node(&n.node).decide_as(Surface::Rpc, None, Some("m"));
    assert!(matches!(local, InferenceAccess::Allow));
    n.shutdown().await;
}

#[tokio::test]
async fn an_explicit_override_wins_in_both_directions() {
    let n = TestNode::boot().await;
    n.node
        .served_models
        .insert("hidden".to_string(), Some(Visibility::Private));
    n.node
        .served_models
        .insert("shown".to_string(), Some(Visibility::Public));

    // Public node, private override: not announced, not served off-node.
    let (served, _) = n.announced().await;
    assert_eq!(served, vec!["shown".to_string()]);
    assert!(matches!(
        n.keyless_off_node("hidden").await,
        InferenceAccess::Refuse(403, _)
    ));

    // Private node, public override: still announced and served.
    n.set_visibility(json!({ "visibility": "private" })).await;
    let (served, _) = n.announced().await;
    assert_eq!(served, vec!["shown".to_string()]);
    assert!(matches!(
        n.keyless_off_node("shown").await,
        InferenceAccess::Allow
    ));
    n.shutdown().await;
}

#[tokio::test]
async fn a_gated_model_is_announced_as_key_required_and_refused_without_a_key() {
    // A price is set so a pay-per-use fallback, if one existed, would show up
    // as NeedPayment rather than as a refusal.
    let n = TestNode::boot_with(|c| c.payments.default_amount = 5).await;
    n.node
        .served_models
        .insert("by-override".to_string(), Some(Visibility::Gated));
    n.node.served_models.insert("by-node".to_string(), None);
    n.set_visibility(json!({ "visibility": "gated" })).await;

    let (served, key_required) = n.announced().await;
    assert_eq!(
        served,
        vec!["by-node".to_string(), "by-override".to_string()]
    );
    assert_eq!(key_required, served, "both are flagged key-required");

    for model in ["by-override", "by-node"] {
        match n.keyless_off_node(model).await {
            InferenceAccess::Refuse(402, msg) => assert!(msg.contains("gated"), "{msg}"),
            other => panic!("{model}: a keyless call to a gated model got {other:?}"),
        }
        let did = member().did();
        let admission = NodeInferenceAdmission::for_node(&n.node);
        let keyed =
            from_overlay(
                async move { admission.decide_as(Surface::Iroh, Some(&did), Some(model)) },
            )
            .await;
        assert!(
            matches!(keyed, InferenceAccess::Allow),
            "{model}: {keyed:?}"
        );
    }
    n.shutdown().await;
}

/// Every inference route runs the one admission check: a caller the policy
/// admits by name gets through, an anonymous call to a gated model is refused
/// before any payment challenge.
#[tokio::test]
async fn every_inference_route_admits_a_key_and_refuses_a_keyless_gated_call() {
    let n = TestNode::boot().await;
    n.node
        .served_models
        .insert("g".to_string(), Some(Visibility::Gated));
    let named = member().sign_in(&n.client, &n.base_url).await;

    for route in tenzro_payments::middleware::INFERENCE_ROUTES.iter() {
        let url = format!("{}{route}", n.base_url);
        let body = json!({ "model": "g", "history": [1.0, 2.0], "horizon": 1 });

        let keyless = n.client.post(&url).json(&body).send().await.expect("HTTP");
        assert_eq!(keyless.status().as_u16(), 402, "{route} keyless");
        let refusal: Value = keyless.json().await.expect("JSON");
        assert_eq!(
            refusal["error"]["code"], "credential_required",
            "{route}: {refusal}"
        );

        let keyed = named
            .authorize_route(n.client.post(&url), &url)
            .json(&body)
            .send()
            .await
            .expect("HTTP");
        let status = keyed.status().as_u16();
        let text = keyed.text().await.unwrap_or_default();
        assert!(
            status != 402 && !text.contains("credential_required"),
            "{route} refused the admitted caller: {status} {text}"
        );
    }

    // A multipart upload names its model in a form field; the same check reads it.
    let form = "--B\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ng\r\n--B--\r\n";
    let resp = n
        .client
        .post(format!("{}/v1/audio/transcriptions", n.base_url))
        .header("content-type", "multipart/form-data; boundary=B")
        .body(form)
        .send()
        .await
        .expect("HTTP");
    assert_eq!(resp.status().as_u16(), 402, "multipart keyless gated call");

    // And the JSON-RPC inference methods.
    let rpc_keyless = n
        .rpc(
            "tenzro_forecast",
            json!({ "model_id": "g", "history": [1.0], "horizon": 1 }),
        )
        .await;
    let msg = rpc_keyless["error"]["message"].as_str().unwrap_or_default();
    assert!(msg.contains("gated"), "{rpc_keyless}");
    let rpc_keyed = named
        .call(
            &n.client,
            &n.base_url,
            "tenzro_forecast",
            json!({ "model_id": "g", "history": [1.0], "horizon": 1 }),
        )
        .await;
    let msg = rpc_keyed["error"]["message"].as_str().unwrap_or_default();
    assert!(
        !msg.contains("gated"),
        "the admitted caller was refused: {rpc_keyed}"
    );
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Private is not non-participation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_private_node_still_validates() {
    // A validating chain needs a genesis whose validators hold hardware keys,
    // which a test host does not have, so the role is set on the running node.
    let n = TestNode::boot_with(|c| c.visibility = Visibility::Private).await;
    *n.node.runtime_roles.write() = tenzro_types::RoleSet::validator_only();
    assert_eq!(n.node.visibility(), Visibility::Private);
    assert!(n.node.runtime_roles.read().is_validator());
    let set = n.set_visibility(json!({ "visibility": "private" })).await;
    assert_eq!(set["result"]["visibility"], "private", "{set}");
    assert!(n.node.runtime_roles.read().is_validator());
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// The choice survives a restart
// ---------------------------------------------------------------------------

/// Tested through the persistence layer rather than by restarting in-process: a
/// started node's background tasks hold the RocksDB handle for the life of the
/// process, so a second node on the same directory cannot open it. What is
/// asserted instead is the pair a restart consists of: the choice was written
/// durably, and the loader boot calls returns it.
#[tokio::test]
async fn the_choice_is_persisted_and_reloaded() {
    let n = TestNode::boot().await;
    let store = n.node.storage().cloned().expect("the node has storage")
        as Arc<dyn tenzro_storage::KvStore>;
    assert_eq!(tenzro_node::visibility_rpc::load(&store), None);

    let set = n.set_visibility(json!({ "visibility": "gated" })).await;
    assert!(set.get("result").is_some(), "{set}");
    assert_eq!(
        tenzro_node::visibility_rpc::load(&store),
        Some(Visibility::Gated)
    );
    n.shutdown().await;
}
