//! The operator's admin token satisfies the tenant scope gate on their own
//! node — and nothing weaker does.
//!
//! API-key scopes separate *network tenants* from each other: a key names the
//! databases, files and sites its holder may reach, and the gate is what stops
//! one tenant enumerating another's. The node's operator is not one of those
//! tenants, so without this a `tenzro_listDatabases` against your own node is
//! refused for want of a tenant key you would have to issue yourself — while
//! holding the credential that can revoke every key on the node.
//!
//! Both directions matter and both are asserted here. Widening a gate is
//! exactly the kind of change that is easy to widen too far, so the negative
//! case — a wrong token is still refused — is the more important of the two.

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

const ADMIN_TOKEN: &str = "operator-token-for-the-scope-gate-test";

/// A method that carries a tenant scope (`database`) and is not itself
/// admin-gated, so it exercises the scope gate rather than the admin gate.
const SCOPED_METHOD: &str = "tenzro_listDatabases";

/// The refusal code the scope gate returns.
const UNAUTHORIZED: i64 = -32004;

async fn setup() -> (
    String,
    broadcast::Sender<()>,
    tokio::task::JoinHandle<tenzro_node::Result<()>>,
    tempfile::TempDir,
    Arc<TenzroNode>,
) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };

    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");
    let node = Arc::new(node);

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
    let handle =
        tokio::spawn(async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await });
    let addr = addr_rx.await.expect("bound address");

    (format!("http://{addr}"), shutdown_tx, handle, tmp, node)
}

/// `None` when the response carries no error, else the JSON-RPC error code.
fn error_code(body: &Value) -> Option<i64> {
    body.get("error")?.get("code")?.as_i64()
}

#[tokio::test]
async fn operator_admin_token_satisfies_the_tenant_scope_gate() {
    // Read at node startup. nextest gives every test its own process, so this
    // cannot leak into another test.
    unsafe { std::env::set_var("TENZRO_ADMIN_TOKEN", ADMIN_TOKEN) };

    let (base_url, shutdown_tx, handle, _tmp, node) = setup().await;
    assert_eq!(
        node.admin_token(),
        Some(ADMIN_TOKEN),
        "node did not pick the admin token up from the environment"
    );

    let client = reqwest::Client::new();
    let body = json!({"jsonrpc":"2.0","id":1,"method":SCOPED_METHOD,"params":{}});

    // 1. No credential at all — refused, as a passer-by should be.
    let anonymous: Value = client
        .post(&base_url)
        .json(&body)
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(
        error_code(&anonymous),
        Some(UNAUTHORIZED),
        "a request with no credential must be refused: {anonymous}"
    );

    // 2. A token that is not this node's — still refused. This is the
    //    assertion that keeps the operator path from becoming a bypass: the
    //    gate must verify the token, not merely notice that a header exists.
    let forged: Value = client
        .post(&base_url)
        .header("X-Tenzro-Admin-Token", "not-the-operators-token")
        .json(&body)
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(
        error_code(&forged),
        Some(UNAUTHORIZED),
        "a wrong admin token must not open the scope gate: {forged}"
    );

    // 3. The operator's own token — allowed through to the handler. The
    //    handler's own outcome is not the subject here; what matters is that
    //    the request is no longer refused for want of a tenant key.
    let operator: Value = client
        .post(&base_url)
        .header("X-Tenzro-Admin-Token", ADMIN_TOKEN)
        .json(&body)
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_ne!(
        error_code(&operator),
        Some(UNAUTHORIZED),
        "the operator's own admin token must satisfy the tenant scope gate on \
         their own node: {operator}"
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}
