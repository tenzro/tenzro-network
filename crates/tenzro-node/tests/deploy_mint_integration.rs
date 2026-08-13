//! Integration tests for `tenzro_deployMintKey` — the opt-in, delegated,
//! non-admin deploy-mint path that closes Phase D "gap 1".
//!
//! Each test spins up a full `TenzroNode` (no live network) and exercises one
//! fail-closed guardrail end-to-end through the JSON-RPC server:
//!
//!   1. Disabled by default: refused unless the operator opted in.
//!   2. Unauthenticated: refused without a presented API key.
//!   3. Subject-pinned: cannot mint for a different subject.
//!   4. Scope-bounded: privileged scopes are refused; a database-scoped key
//!      must name the databases it may reach.
//!   5. Rate-limited: per-caller-DID mints/hour ceiling trips.
//!   6. Happy path: a subject-pinned, scope-bounded, expiring key is minted
//!      by reusing the same primitive `tenzro_createApiKey` uses.
//!
//! The caller's own API key (the credential a deploy presents) is minted via
//! the admin-gated `tenzro_createApiKey`, standing in for the real network
//! identity a deploy would already hold.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tokio::sync::broadcast;

use tenzro_node::config::DeployConfig;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};

const TEST_ADMIN_TOKEN: &str = "test-admin-token";

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn config_with_deploy(deploy: DeployConfig) -> (NodeConfig, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        deploy,
        ..Default::default()
    };
    (cfg, tmp)
}

async fn setup(
    deploy: DeployConfig,
) -> (
    String,
    broadcast::Sender<()>,
    tokio::task::JoinHandle<tenzro_node::Result<()>>,
    tempfile::TempDir,
) {
    let (cfg, tmp) = config_with_deploy(deploy);
    // The node captures TENZRO_ADMIN_TOKEN at startup; nextest isolates each
    // test in its own process, so this cannot race.
    // SAFETY: single-threaded until the node is constructed on the next line.
    unsafe { std::env::set_var("TENZRO_ADMIN_TOKEN", TEST_ADMIN_TOKEN) };
    let mut node = TenzroNode::new(cfg).await.expect("node creation");
    node.start().await.expect("node start");
    let node = Arc::new(node);

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
    let handle =
        tokio::spawn(async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await });
    let addr = addr_rx.await.expect("bound address");
    (format!("http://{}", addr), shutdown_tx, handle, tmp)
}

fn rpc_request(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
}

async fn rpc_call(client: &reqwest::Client, url: &str, body: Value) -> Value {
    client
        .post(url)
        .json(&body)
        .send()
        .await
        .expect("HTTP")
        .json::<Value>()
        .await
        .expect("JSON")
}

async fn rpc_call_admin(client: &reqwest::Client, url: &str, body: Value) -> Value {
    client
        .post(url)
        .header("X-Tenzro-Admin-Token", TEST_ADMIN_TOKEN)
        .json(&body)
        .send()
        .await
        .expect("HTTP")
        .json::<Value>()
        .await
        .expect("JSON")
}

async fn rpc_call_key(client: &reqwest::Client, url: &str, api_key: &str, body: Value) -> Value {
    client
        .post(url)
        .header("X-Tenzro-Api-Key", api_key)
        .json(&body)
        .send()
        .await
        .expect("HTTP")
        .json::<Value>()
        .await
        .expect("JSON")
}

async fn shutdown(
    tx: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
) {
    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// Mint a caller API key (the credential a deploy presents) via the
/// admin-gated path, bound to `subject`. Returns the plaintext `tnz_...`.
async fn mint_caller_key(client: &reqwest::Client, url: &str, subject: &str) -> String {
    let resp = rpc_call_admin(
        client,
        url,
        rpc_request(
            "tenzro_createApiKey",
            json!({
                "label": "deployer",
                "subject": subject,
                "scopes": ["database"],
                "class": "subject",
            }),
        ),
    )
    .await;
    resp["result"]["key"]
        .as_str()
        .unwrap_or_else(|| panic!("createApiKey returned no key: {resp}"))
        .to_string()
}

fn enabled_deploy() -> DeployConfig {
    DeployConfig {
        allow_self_service_mint: true,
        ..DeployConfig::default()
    }
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn disabled_by_default_refuses() {
    // Default config: allow_self_service_mint is false.
    let (url, tx, handle, _tmp) = setup(DeployConfig::default()).await;
    let client = reqwest::Client::new();
    let subject = "did:tenzro:machine:deployer";
    let caller = mint_caller_key(&client, &url, subject).await;

    let resp = rpc_call_key(
        &client,
        &url,
        &caller,
        rpc_request(
            "tenzro_deployMintKey",
            json!({ "scopes": ["database"], "allowed_databases": ["mydb"] }),
        ),
    )
    .await;
    assert!(
        resp["error"].is_object(),
        "disabled node must refuse deploy-mint: {resp}"
    );
    assert_eq!(resp["error"]["code"], -32004);

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn unauthenticated_refuses() {
    let (url, tx, handle, _tmp) = setup(enabled_deploy()).await;
    let client = reqwest::Client::new();

    // No X-Tenzro-Api-Key header.
    let resp = rpc_call(
        &client,
        &url,
        rpc_request(
            "tenzro_deployMintKey",
            json!({ "scopes": ["database"], "allowed_databases": ["mydb"] }),
        ),
    )
    .await;
    assert!(
        resp["error"].is_object(),
        "unauthenticated deploy-mint must refuse: {resp}"
    );
    assert_eq!(resp["error"]["code"], -32004);

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn subject_pin_blocks_minting_for_another_did() {
    let (url, tx, handle, _tmp) = setup(enabled_deploy()).await;
    let client = reqwest::Client::new();
    let subject = "did:tenzro:machine:deployer";
    let caller = mint_caller_key(&client, &url, subject).await;

    // Ask to mint a key whose subject is a DIFFERENT tenant.
    let resp = rpc_call_key(
        &client,
        &url,
        &caller,
        rpc_request(
            "tenzro_deployMintKey",
            json!({
                "subject": "did:tenzro:machine:victim",
                "scopes": ["database"],
                "allowed_databases": ["mydb"],
            }),
        ),
    )
    .await;
    assert!(
        resp["error"].is_object(),
        "subject-pin must block cross-subject mint: {resp}"
    );
    assert_eq!(resp["error"]["code"], -32004);

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn privileged_scope_is_refused() {
    let (url, tx, handle, _tmp) = setup(enabled_deploy()).await;
    let client = reqwest::Client::new();
    let subject = "did:tenzro:machine:deployer";
    let caller = mint_caller_key(&client, &url, subject).await;

    for bad in ["canton", "evm", "issuer", "tee", "bridge"] {
        let resp = rpc_call_key(
            &client,
            &url,
            &caller,
            rpc_request(
                "tenzro_deployMintKey",
                json!({ "scopes": [bad] }),
            ),
        )
        .await;
        assert!(
            resp["error"].is_object(),
            "scope '{bad}' must be refused: {resp}"
        );
        assert_eq!(resp["error"]["code"], -32602, "scope '{bad}'");
    }

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn database_scope_requires_allowed_databases() {
    let (url, tx, handle, _tmp) = setup(enabled_deploy()).await;
    let client = reqwest::Client::new();
    let subject = "did:tenzro:machine:deployer";
    let caller = mint_caller_key(&client, &url, subject).await;

    // database scope but no allowed_databases → refused (would be unrestricted).
    let resp = rpc_call_key(
        &client,
        &url,
        &caller,
        rpc_request("tenzro_deployMintKey", json!({ "scopes": ["database"] })),
    )
    .await;
    assert!(
        resp["error"].is_object(),
        "unrestricted database key must be refused: {resp}"
    );
    assert_eq!(resp["error"]["code"], -32602);

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn happy_path_mints_subject_pinned_bounded_expiring_key() {
    let (url, tx, handle, _tmp) = setup(enabled_deploy()).await;
    let client = reqwest::Client::new();
    let subject = "did:tenzro:machine:deployer";
    let caller = mint_caller_key(&client, &url, subject).await;

    let resp = rpc_call_key(
        &client,
        &url,
        &caller,
        rpc_request(
            "tenzro_deployMintKey",
            json!({
                "label": "myapp",
                "scopes": ["database", "storage", "inference"],
                "allowed_databases": ["myapp-db"],
                "allowed_models": ["gpt-oss"],
                "ttl_secs": 600,
            }),
        ),
    )
    .await;
    assert!(resp.get("error").is_none(), "mint error: {resp}");
    let r = &resp["result"];
    // Subject is pinned to the caller, not caller-controlled.
    assert_eq!(r["subject"], subject);
    assert!(r["key"].as_str().unwrap().starts_with("tnz_"));
    // Class is Subject (never operator_*), and it carries the deploy marker.
    assert_eq!(r["class"], "subject");
    assert!(r["label"].as_str().unwrap().starts_with("deploy-mint:"));
    // Scope-bounded.
    assert_eq!(r["allowed_databases"], json!(["myapp-db"]));
    assert_eq!(r["allowed_models"], json!(["gpt-oss"]));
    // Expiring: valid_until is in the future and within the requested TTL.
    let valid_until = r["valid_until"].as_i64().expect("valid_until");
    let now = now_unix_secs();
    assert!(valid_until > now && valid_until <= now + 600 + 5, "ttl bounds");

    // The minted key must show up under the caller's own subject listing.
    let mine = rpc_call_key(
        &client,
        &url,
        &caller,
        rpc_request("tenzro_listMyApiKeys", json!({})),
    )
    .await;
    let keys = mine["result"]["keys"].as_array().expect("keys");
    assert!(
        keys.iter()
            .any(|k| k["label"].as_str() == Some("deploy-mint:myapp")),
        "minted key must be listed under caller subject: {mine}"
    );

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn ttl_is_clamped_to_config_ceiling() {
    let (url, tx, handle, _tmp) = setup(DeployConfig {
        allow_self_service_mint: true,
        max_key_ttl_secs: 300,
        ..DeployConfig::default()
    })
    .await;
    let client = reqwest::Client::new();
    let subject = "did:tenzro:machine:deployer";
    let caller = mint_caller_key(&client, &url, subject).await;

    // Request a year; must be clamped down to the 300s ceiling.
    let resp = rpc_call_key(
        &client,
        &url,
        &caller,
        rpc_request(
            "tenzro_deployMintKey",
            json!({
                "scopes": ["database"],
                "allowed_databases": ["mydb"],
                "ttl_secs": 31_536_000,
            }),
        ),
    )
    .await;
    assert!(resp.get("error").is_none(), "mint error: {resp}");
    let valid_until = resp["result"]["valid_until"].as_i64().expect("valid_until");
    let now = now_unix_secs();
    assert!(
        valid_until <= now + 300 + 5,
        "TTL must be clamped to config ceiling, got {}s",
        valid_until - now
    );

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn rate_limit_trips_per_caller() {
    let (url, tx, handle, _tmp) = setup(DeployConfig {
        allow_self_service_mint: true,
        max_mints_per_hour: 2,
        ..DeployConfig::default()
    })
    .await;
    let client = reqwest::Client::new();
    let subject = "did:tenzro:machine:deployer";
    let caller = mint_caller_key(&client, &url, subject).await;

    let mint = |i: usize| {
        rpc_request(
            "tenzro_deployMintKey",
            json!({
                "label": format!("app{i}"),
                "scopes": ["database"],
                "allowed_databases": [format!("db{i}")],
            }),
        )
    };

    // First two succeed.
    for i in 0..2 {
        let resp = rpc_call_key(&client, &url, &caller, mint(i)).await;
        assert!(resp.get("error").is_none(), "mint {i} should succeed: {resp}");
    }
    // Third trips the hourly ceiling.
    let resp = rpc_call_key(&client, &url, &caller, mint(2)).await;
    assert!(
        resp["error"].is_object(),
        "third mint must be rate-limited: {resp}"
    );
    assert_eq!(resp["error"]["code"], -32005);

    shutdown(tx, handle).await;
}
