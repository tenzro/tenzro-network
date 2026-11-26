//! The `/mcp` edge end to end: a DPoP-bound access token reaches an
//! owner-class tool, and a token the node withdrew, a Bearer-only token and a
//! request whose DPoP proof covers another URL are each refused with 401.

mod dpop_bearer;
mod passkey_holder;

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::sync::broadcast;

use dpop_bearer::{Bearer, OperatorKey};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};

struct TestNode {
    rpc_url: String,
    mcp_url: String,
    tx: broadcast::Sender<()>,
    _tmp: tempfile::TempDir,
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
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
        tokio::spawn(async move { rpc.start_with_shutdown_and_addr(rx, addr_tx).await });
        let rpc_url = format!("http://{}", addr_rx.await.expect("bound address"));

        let web = Arc::new(tenzro_node::web::handlers::WebState::new().with_node(node.clone()));
        let rx = tx.subscribe();
        let (mcp_tx, mcp_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tenzro_node::mcp::server::start_mcp_server_with_shutdown(
                "127.0.0.1:0".to_string(),
                node,
                web,
                rx,
                Some(mcp_tx),
            )
            .await
        });
        let mcp_addr = mcp_rx.await.expect("bound address");
        Self {
            rpc_url,
            mcp_url: format!("http://{mcp_addr}"),
            tx,
            _tmp: tmp,
            client: reqwest::Client::new(),
        }
    }

    /// `stake` is an owner-class tool: no unauthenticated caller reaches it.
    async fn stake(&self, authorization: Option<String>, dpop: Option<String>) -> (u16, String) {
        let name = "stake";
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": { "name": "test", "version": "0" },
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        });
        let mut req = self
            .client
            .post(format!("{}/mcp", self.mcp_url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", name)
            .json(&body);
        if let Some(a) = authorization {
            req = req.header("Authorization", a);
        }
        if let Some(d) = dpop {
            req = req.header("DPoP", d);
        }
        let resp = req.send().await.expect("mcp post");
        (resp.status().as_u16(), resp.text().await.expect("body"))
    }

    /// The tool call carrying `who`'s token and a DPoP proof for `url`.
    async fn stake_as(&self, who: &Bearer, proof_url: &str) -> (u16, String) {
        self.stake(
            Some(format!("DPoP {}", who.token)),
            Some(who.holder.sign_proof("POST", proof_url, Some(&who.token))),
        )
        .await
    }

    fn mcp_route(&self) -> String {
        format!("{}/mcp", self.mcp_url)
    }

    async fn rpc_as(&self, who: &Bearer, method: &str, params: Value) -> Value {
        who.call(&self.client, &self.rpc_url, method, params).await
    }
}

#[tokio::test]
async fn a_valid_dpop_token_reaches_an_owner_class_tool_on_mcp() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let user = OperatorKey::new().sign_in(&n.client, &n.rpc_url).await;
    let (status, body) = n.stake_as(&user, &n.mcp_route()).await;
    assert_ne!(
        status, 401,
        "a proved token passes the bearer layer: {body}"
    );
    assert!(
        !body.contains("requires authentication"),
        "the bearer layer did not ask for a token: {body}"
    );
    let _ = n.tx.send(());
}

#[tokio::test]
async fn a_withdrawn_dpop_token_is_refused_on_mcp() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let op = operator.sign_in(&n.client, &n.rpc_url).await;
    let holder = OperatorKey::new();
    let user = holder.sign_in(&n.client, &n.rpc_url).await;
    let (status, body) = n.stake_as(&user, &n.mcp_route()).await;
    assert_ne!(
        status, 401,
        "the token is good before it is withdrawn: {body}"
    );

    // Revoking an identity withdraws every token its DID holds.
    let withdrawn = n
        .rpc_as(
            &op,
            "tenzro_revokeAccessToken",
            json!({ "did": holder.did() }),
        )
        .await;
    assert!(withdrawn.get("result").is_some(), "{withdrawn}");

    let (status, body) = n.stake_as(&user, &n.mcp_route()).await;
    assert_eq!(status, 401, "a withdrawn token is refused on /mcp: {body}");
    let _ = n.tx.send(());
}

#[tokio::test]
async fn a_bearer_only_token_is_refused_on_an_owner_class_tool() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let user = OperatorKey::new().sign_in(&n.client, &n.rpc_url).await;
    let (status, body) = n.stake(Some(format!("Bearer {}", user.token)), None).await;
    assert_eq!(status, 401, "a Bearer scheme is not a proof: {body}");
    let (status, body) = n.stake(None, None).await;
    assert_eq!(status, 401, "no token is not a proof either: {body}");
    let _ = n.tx.send(());
}

#[tokio::test]
async fn a_dpop_proof_for_another_url_is_refused_on_mcp() {
    let operator = OperatorKey::new();
    let n = TestNode::start(&operator).await;
    let user = OperatorKey::new().sign_in(&n.client, &n.rpc_url).await;
    let (status, body) = n.stake_as(&user, &format!("{}/elsewhere", n.mcp_url)).await;
    assert_eq!(status, 401, "a proof covers one URL: {body}");
    let (status, body) = n
        .stake(
            Some(format!("DPoP {}", user.token)),
            Some("not-a-proof".into()),
        )
        .await;
    assert_eq!(status, 401, "a malformed proof is refused: {body}");
    let _ = n.tx.send(());
}
