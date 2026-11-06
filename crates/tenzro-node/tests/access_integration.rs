//! Operator access gating end to end: sign-in, the policy over a live RPC
//! server, and token withdrawal.

mod dpop_bearer;
mod passkey_holder;

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::sync::broadcast;

use tenzro_node::{NodeConfig, RpcServer, TenzroNode};

use dpop_bearer::{Bearer, OperatorKey};

struct TestNode {
    url: String,
    tx: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    tmp: tempfile::TempDir,
    client: reqwest::Client,
}

impl TestNode {
    async fn start(operator: &OperatorKey) -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
            operator_did: Some(operator.did()),
            ..Default::default()
        };
        let mut node = TenzroNode::new(cfg).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);
        node.bind_self();
        let (tx, rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node, "127.0.0.1:0".to_string());
        let handle =
            tokio::spawn(async move { rpc.start_with_shutdown_and_addr(rx, addr_tx).await });
        let addr = addr_rx.await.expect("bound address");
        Self {
            url: format!("http://{addr}"),
            tx,
            handle,
            tmp,
            client: reqwest::Client::new(),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Value {
        self.client
            .post(&self.url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .expect("HTTP")
            .json()
            .await
            .expect("JSON")
    }

    async fn call_as(&self, who: &Bearer, method: &str, params: Value) -> Value {
        who.call(&self.client, &self.url, method, params).await
    }

    async fn stop(self) {
        let _ = self.tx.send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), self.handle).await;
    }
}

#[tokio::test]
async fn only_the_operator_administers_access() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let op = operator.sign_in(&n.client, &n.url).await;
    let stranger = OperatorKey::new().sign_in(&n.client, &n.url).await;

    let resp = n.call_as(&op, "tenzro_getAccessPolicy", json!({})).await;
    assert_eq!(resp["result"]["policy"]["version"], 0, "{resp}");
    for who in [None, Some(&stranger)] {
        let resp = match who {
            Some(b) => n.call_as(b, "tenzro_getAccessPolicy", json!({})).await,
            None => n.call("tenzro_getAccessPolicy", json!({})).await,
        };
        assert_eq!(resp["error"]["code"], -32004, "{resp}");
    }
    n.stop().await;
}

#[tokio::test]
async fn a_closed_surface_refuses_and_an_allow_list_names_who_gets_through() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let op = operator.sign_in(&n.client, &n.url).await;
    let member = OperatorKey::new();
    let member_bearer = member.sign_in(&n.client, &n.url).await;

    let policy = json!({
        "default_rule": { "rule": "open" },
        "rules": [{
            "surface": "rpc",
            "class": "read",
            "rule": { "rule": "allow", "dids": [member.did()] },
        }],
        "tiers": [{ "name": "standard", "rate_per_minute": 600, "burst": 100 }],
    });
    let set = n
        .call_as(&op, "tenzro_setAccessPolicy", json!({ "policy": policy }))
        .await;
    assert_eq!(set["result"]["version"], 1, "{set}");

    let anon = n.call("tenzro_getNodeStatus", json!({})).await;
    assert_eq!(
        anon["error"]["code"], -32004,
        "an anonymous caller is refused: {anon}"
    );
    let named = n
        .call_as(&member_bearer, "tenzro_getNodeStatus", json!({}))
        .await;
    assert!(
        named.get("result").is_some(),
        "the allow-listed caller is served: {named}"
    );

    // The file the store wrote is the policy a restarted node would load.
    let text = std::fs::read_to_string(n.tmp.path().join("access.toml")).expect("access.toml");
    assert!(text.contains(&member.did()));
    n.stop().await;
}

#[tokio::test]
async fn a_withdrawn_token_stops_working_and_the_holder_can_sign_in_again() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let op = operator.sign_in(&n.client, &n.url).await;
    let user = OperatorKey::new();
    let first = user.sign_in(&n.client, &n.url).await;

    let listed = n.call_as(&op, "tenzro_listAccessTokens", json!({})).await;
    let jti = listed["result"]["tokens"]
        .as_array()
        .expect("tokens")
        .iter()
        .find(|t| t["bearer_did"] == user.did())
        .map(|t| t["jti"].clone())
        .expect("the user's token is listed");
    let revoked = n
        .call_as(&op, "tenzro_revokeAccessToken", json!({ "jti": jti }))
        .await;
    assert!(revoked.get("result").is_some(), "{revoked}");

    let refused = n.call_as(&first, "tenzro_getNodeStatus", json!({})).await;
    assert!(
        refused.get("error").is_some(),
        "a withdrawn token is refused: {refused}"
    );
    let again = user.sign_in(&n.client, &n.url).await;
    let served = n.call_as(&again, "tenzro_getNodeStatus", json!({})).await;
    assert!(
        served.get("result").is_some(),
        "a fresh sign-in works: {served}"
    );
    n.stop().await;
}

#[tokio::test]
async fn a_sign_in_answered_with_another_key_is_refused() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let holder = dpop_bearer::DpopHolder::new();
    let issued = n
        .call(
            "tenzro_accessChallenge",
            json!({ "did": operator.did(), "dpop_jkt": holder.jkt }),
        )
        .await;
    let impostor = OperatorKey::new();
    let resp = n
        .call(
            "tenzro_issueAccessToken",
            json!({
                "challenge_id": issued["result"]["challenge_id"],
                "proof": {
                    "kind": "device",
                    "public_key": hex::encode(impostor.public_key()),
                    "signature": "00".repeat(64),
                },
            }),
        )
        .await;
    assert_eq!(resp["error"]["code"], -32004, "{resp}");
    n.stop().await;
}
