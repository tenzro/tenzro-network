//! HTTP-level integration tests for the Tenzro Node RPC server.
//!
//! Each test spins up a fresh TenzroNode + RPC server on an OS-assigned port,
//! issues real HTTP requests via reqwest, and asserts on the JSON-RPC responses.
//! Every test gets its own temp directory so RocksDB instances never contend.

mod dpop_bearer;
mod passkey_holder;

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a NodeConfig backed by a unique temp directory.
fn test_config() -> (NodeConfig, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
        // This node advertises but does not validate, so an RPC provider
        // validates on its behalf and is owed a leg of every split. Settlement
        // refuses when that payee is unnamed — deliberately, because quietly
        // redirecting their share to the treasury pays the wrong party and
        // reports nothing wrong. Naming one here exercises the three-way
        // delegated split rather than routing around it.
        economics: tenzro_node::EconomicsConfig {
            // All-numeric so EIP-55 mixed-case checksum validation is moot:
            // `Address::from_hex` checksums the letters in a 20-byte address,
            // so a mis-cased one is rejected. That rejection is now logged
            // rather than swallowed, but an address with no letters cannot
            // trip it at all.
            rpc_provider_payee: Some("0x0000000000000000000000000000000000000011".to_string()),
        },
        ..Default::default()
    };
    (config, tmp)
}

/// Boot a TenzroNode and its RPC server.  Returns the base URL
/// (e.g. "http://127.0.0.1:54321"), a shutdown sender, and a join handle.
/// The operator every test node admits.
fn operator() -> &'static dpop_bearer::OperatorKey {
    static KEY: std::sync::OnceLock<dpop_bearer::OperatorKey> = std::sync::OnceLock::new();
    KEY.get_or_init(dpop_bearer::OperatorKey::new)
}

async fn setup_test_server() -> (
    String,
    broadcast::Sender<()>,
    tokio::task::JoinHandle<tenzro_node::Result<()>>,
    tempfile::TempDir,
    Arc<TenzroNode>,
) {
    let (config, tmp) = test_config();
    dpop_bearer::admit_operator(tmp.path(), &operator().did());
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");
    let node = Arc::new(node);

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();

    let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
    let handle =
        tokio::spawn(async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await });

    let addr = addr_rx.await.expect("receive bound address");
    let base_url = format!("http://{}", addr);

    (base_url, shutdown_tx, handle, tmp, node)
}

/// Build a standard JSON-RPC 2.0 request body.
fn rpc_request(method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
}

/// Build a JSON-RPC 2.0 request without params.
/// The public half of a caller-held wallet key and the passkey credential
/// that holds it. The node never mints a wallet key.
fn wallet_key_params(seed: u8) -> Value {
    let key = tenzro_crypto::p256::P256KeyPair::from_secret_bytes(&[seed; 32]).unwrap();
    json!({
        "public_key": hex::encode(key.public_key_bytes()),
        "credential_id": hex::encode([seed; 16]),
    })
}

fn rpc_request_no_params(method: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
    })
}

/// Send a JSON-RPC POST request and return the parsed response.
async fn rpc_call(client: &reqwest::Client, url: &str, body: Value) -> Value {
    client
        .post(url)
        .json(&body)
        .send()
        .await
        .expect("HTTP request")
        .json::<Value>()
        .await
        .expect("JSON parse")
}

// ---------------------------------------------------------------------------
// Core RPC Tests
// ---------------------------------------------------------------------------

/// GET /health returns 200 with node status information.
#[tokio::test]
async fn test_rpc_health_endpoint() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .expect("GET /health");

    assert_eq!(resp.status(), 200);

    let body: Value = resp.json().await.expect("parse JSON");
    assert_eq!(body["jsonrpc"], "2.0");
    assert!(body["result"]["version"].is_string());
    assert!(body["result"]["status"].is_string());

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// POST eth_blockNumber returns a hex-encoded block height.
#[tokio::test]
async fn test_rpc_block_number() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request_no_params("eth_blockNumber");
    let resp = rpc_call(&client, &base_url, body).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);
    // Result should be a hex string like "0x0" or "0x1"
    let result = resp["result"].as_str().expect("result is string");
    assert!(
        result.starts_with("0x"),
        "block number should be hex: {}",
        result
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// POST eth_getBalance for the zero address returns a hex balance.
#[tokio::test]
async fn test_rpc_get_balance() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let zero_addr = format!("0x{}", "00".repeat(20));
    let body = rpc_request("eth_getBalance", json!([zero_addr, "latest"]));
    let resp = rpc_call(&client, &base_url, body).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    // Should return a hex balance (possibly "0x0")
    let result = resp["result"].as_str().expect("result is string");
    assert!(
        result.starts_with("0x"),
        "balance should be hex: {}",
        result
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// Calling an unknown method returns JSON-RPC MethodNotFound error (-32601).
#[tokio::test]
async fn test_rpc_invalid_method() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request_no_params("nonexistent_method_xyz");
    let resp = rpc_call(&client, &base_url, body).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    assert!(resp["error"].is_object(), "should have error");
    assert_eq!(resp["error"]["code"], -32601);
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Method not found"),
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// Posting malformed JSON returns ParseError (-32700).
#[tokio::test]
async fn test_rpc_malformed_json() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(&base_url)
        .header("content-type", "application/json")
        .body("{not valid json!!!")
        .send()
        .await
        .expect("HTTP request");

    // The server might return 400 (axum JSON rejection) or 200 with a parse error.
    // Either is acceptable. Check the body if we get 200.
    let status = resp.status().as_u16();
    if status == 200 {
        let body: Value = resp.json().await.expect("parse JSON");
        assert_eq!(body["error"]["code"], -32700);
    } else {
        // axum rejects malformed JSON with 400/422 before it reaches the handler
        assert!(
            status == 400 || status == 422,
            "unexpected status: {}",
            status
        );
    }

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// Batch request: send an array of JSON-RPC calls, receive an array of responses.
#[tokio::test]
async fn test_rpc_batch_request() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let batch = json!([
        { "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber" },
        { "jsonrpc": "2.0", "id": 2, "method": "eth_chainId" },
        { "jsonrpc": "2.0", "id": 3, "method": "nonexistent_method" },
    ]);

    let resp = rpc_call(&client, &base_url, batch).await;
    let arr = resp.as_array().expect("response should be an array");
    assert_eq!(arr.len(), 3);

    // First two should succeed
    assert!(arr[0]["result"].is_string());
    assert!(arr[1]["result"].is_string());
    // Third should be an error
    assert_eq!(arr[2]["error"]["code"], -32601);

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// Calling a method that requires params without providing them returns InvalidParams.
#[tokio::test]
async fn test_rpc_missing_params() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    // tenzro_settle requires params (payee, amount, payment)
    let body = rpc_request_no_params("tenzro_settle");
    let resp = rpc_call(&client, &base_url, body).await;

    assert!(
        resp["error"].is_object(),
        "should have error for missing params"
    );
    let code = resp["error"]["code"].as_i64().unwrap();
    // -32602 (InvalidParams) or -32000 (server error)
    assert!(
        code == -32602 || code == -32000,
        "unexpected error code: {}",
        code
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

// ---------------------------------------------------------------------------
// Settlement RPC Tests
// ---------------------------------------------------------------------------

/// POST tenzro_settle without the payer's signed authorization is refused.
#[tokio::test]
async fn test_rpc_settle_without_payer_authorization_is_refused() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request(
        "tenzro_settle",
        json!({
            "payee": format!("0x{}", "aa".repeat(20)),
            "amount": "5000",
        }),
    );
    let resp = rpc_call(&client, &base_url, body).await;

    // Settlement debits the payer, so it moves nothing without the payer's
    // signed authorization of it.
    assert_eq!(resp["error"]["code"], -32602, "{resp}");
    let msg = resp["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("Missing payment"),
        "unexpected settlement error: {msg}"
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// Settlement with a missing required field (no payee) returns an error.
#[tokio::test]
async fn test_rpc_settle_missing_payee() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request(
        "tenzro_settle",
        json!({
            "amount": "999999999999",
        }),
    );
    let resp = rpc_call(&client, &base_url, body).await;

    assert!(resp["error"].is_object(), "should return error");
    let code = resp["error"]["code"].as_i64().unwrap();
    assert!(code == -32602 || code == -32000, "error code: {}", code);

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// The convenience write RPCs `tenzro_createEscrow` and `tenzro_releaseEscrow`
/// have been removed in favor of consensus-mediated typed transactions
/// (`CreateEscrow` / `ReleaseEscrow` / `RefundEscrow`). Calling them must
/// return a `Method not found` error so old clients fail loudly instead of
/// silently no-op'ing.
#[tokio::test]
async fn test_rpc_create_escrow_removed() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let payer = format!("0x{}", "11".repeat(20));
    let payee = format!("0x{}", "22".repeat(20));

    let body = rpc_request(
        "tenzro_createEscrow",
        json!({
            "payer": payer,
            "payee": payee,
            "amount": 10000,
        }),
    );
    let resp = rpc_call(&client, &base_url, body).await;

    assert!(
        resp["error"].is_object(),
        "removed RPC must return an error"
    );
    let code = resp["error"]["code"].as_i64().unwrap_or(0);
    assert_eq!(code, -32601, "expected Method not found, got {}", code);

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

#[tokio::test]
async fn test_rpc_release_escrow_removed() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request(
        "tenzro_releaseEscrow",
        json!({
            "escrow_id": "nonexistent-escrow-id",
            "proof": "deadbeef"
        }),
    );
    let resp = rpc_call(&client, &base_url, body).await;

    assert!(
        resp["error"].is_object(),
        "removed RPC must return an error"
    );
    let code = resp["error"]["code"].as_i64().unwrap_or(0);
    assert_eq!(code, -32601, "expected Method not found, got {}", code);

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// `tenzro_getEscrow` with a non-existent id must return an error.
#[tokio::test]
async fn test_rpc_get_escrow_not_found() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request(
        "tenzro_getEscrow",
        json!({
            "escrow_id": format!("0x{}", "ab".repeat(32)),
        }),
    );
    let resp = rpc_call(&client, &base_url, body).await;

    assert!(
        resp["error"].is_object(),
        "missing escrow must return error"
    );
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// `tenzro_listEscrowsByPayer` returns an empty list for a fresh address.
#[tokio::test]
async fn test_rpc_list_escrows_by_payer_empty() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let payer = format!("0x{}", "33".repeat(20));
    let body = rpc_request("tenzro_listEscrowsByPayer", json!({ "payer": payer }));
    let resp = rpc_call(&client, &base_url, body).await;

    assert!(
        resp["result"].is_object(),
        "expected result object: {}",
        resp
    );
    assert_eq!(
        resp["result"]["escrows"].as_array().map(|a| a.len()),
        Some(0)
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// `tenzro_listEscrowsByPayee` returns an empty list for a fresh address.
#[tokio::test]
async fn test_rpc_list_escrows_by_payee_empty() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let payee = format!("0x{}", "44".repeat(20));
    let body = rpc_request("tenzro_listEscrowsByPayee", json!({ "payee": payee }));
    let resp = rpc_call(&client, &base_url, body).await;

    assert!(
        resp["result"].is_object(),
        "expected result object: {}",
        resp
    );
    assert_eq!(
        resp["result"]["escrows"].as_array().map(|a| a.len()),
        Some(0)
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// Open a micropayment channel via tenzro_openPaymentChannel.
#[tokio::test]
async fn test_rpc_open_payment_channel() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let sender = format!("0x{}", "aa".repeat(20));
    let counterparty = format!("0x{}", "bb".repeat(20));

    let body = rpc_request(
        "tenzro_openPaymentChannel",
        json!({
            "sender": sender,
            "counterparty": counterparty,
            "deposit": 50000
        }),
    );
    let resp = rpc_call(&client, &base_url, body).await;

    if resp["error"].is_object() {
        let msg = resp["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("Channel manager not initialized") || msg.contains("channel"),
            "unexpected error: {}",
            msg
        );
    } else {
        let result = &resp["result"];
        assert!(result["channel_id"].is_string(), "channel_id missing");
        assert!(result["deposit"].is_string(), "deposit missing");
        assert!(result["status"].is_string(), "status missing");
    }

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// Close a payment channel — closing a non-existent channel returns an error.
#[tokio::test]
async fn test_rpc_close_payment_channel() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request(
        "tenzro_closePaymentChannel",
        json!({
            "channel_id": "nonexistent-channel-id"
        }),
    );
    let resp = rpc_call(&client, &base_url, body).await;

    // Should error because the channel doesn't exist
    assert!(
        resp["error"].is_object(),
        "should error for non-existent channel"
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

// ---------------------------------------------------------------------------
// Identity & Wallet RPC Tests
// ---------------------------------------------------------------------------

/// `tenzro_registerIdentity` records an identity only together with its
/// replication transaction. A node that cannot submit that transaction (this
/// one runs no hardware node key or holds no gas for it) returns the error
/// and records nothing, rather than an identity only it knows.
#[tokio::test]
async fn test_rpc_register_identity_records_nothing_without_its_replication_tx() {
    let (base_url, shutdown_tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();

    use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
    let signer = tenzro_crypto::composite::testing::TestHybridSigner::p256_only(0x32);
    let mut params = wallet_key_params(0x32);
    params["identity_type"] = json!("human");
    params["display_name"] = json!("Test User");
    let proof = signer
        .sign(
            SignatureContext::IdentityRegistration,
            b"tenzro/identity/registration",
        )
        .unwrap();
    params["proof"] = serde_json::to_value(&proof).unwrap();
    let public_key = hex::decode(params["public_key"].as_str().unwrap()).unwrap();
    let did = tenzro_identity::TenzroDid::from_passkey(&public_key).to_string();
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request("tenzro_registerIdentity", params),
    )
    .await;
    let registry = node.identity_registry().expect("identity registry");
    if resp["error"].is_object() {
        assert!(
            registry.resolve(&did).is_err(),
            "a registration whose transaction failed was recorded: {resp}"
        );
    } else {
        let result = &resp["result"];
        assert_eq!(result["did"], json!(did), "{resp}");
        assert!(
            result["tx_hash"].is_string(),
            "a registration was recorded without its transaction: {resp}"
        );
        assert!(registry.resolve(&did).is_ok());
    }

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// A machine registered through `tenzro_registerIdentity` under someone
/// else's DID needs that controller's signed envelope, as it does through
/// `tenzro_registerMachineIdentity`. Naming a controller is not the
/// controller agreeing.
#[tokio::test]
async fn test_rpc_register_machine_under_a_controller_needs_its_envelope() {
    let (base_url, shutdown_tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();

    use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
    let proof_of = |seed: u8| {
        let signer = tenzro_crypto::composite::testing::TestHybridSigner::p256_only(seed);
        let proof = signer
            .sign(
                SignatureContext::IdentityRegistration,
                b"tenzro/identity/registration",
            )
            .unwrap();
        serde_json::to_value(&proof).unwrap()
    };

    let human = wallet_key_params(0x41);
    let controller = node
        .identity_registry()
        .expect("identity registry")
        .register_human_via_binder(
            vec![0x41; 16],
            hex::decode(human["public_key"].as_str().unwrap()).unwrap(),
            "Controller".to_string(),
        )
        .await
        .expect("controller registered")
        .identity
        .did_string();

    let mut machine = wallet_key_params(0x42);
    machine["identity_type"] = json!("machine");
    machine["controller_did"] = json!(controller);
    machine["capabilities"] = json!(["transfer"]);
    machine["proof"] = proof_of(0x42);
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request("tenzro_registerIdentity", machine),
    )
    .await;
    assert!(
        resp["result"].is_null(),
        "a machine was registered under {controller} without its consent: {resp}"
    );
    let message = resp["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("did_envelope"),
        "unexpected refusal: {resp}"
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// A registration proof by the test key from `seed`.
fn registration_proof(seed: u8) -> Value {
    use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
    let signer = tenzro_crypto::composite::testing::TestHybridSigner::p256_only(seed);
    let proof = signer
        .sign(
            SignatureContext::IdentityRegistration,
            b"tenzro/identity/registration",
        )
        .unwrap();
    serde_json::to_value(&proof).unwrap()
}

/// A human whose key is the test signer from `seed`, already registered on
/// `node` as if its registration had replicated; returns its DID.
async fn register_signing_human(node: &TenzroNode, seed: u8) -> String {
    use tenzro_crypto::composite::HybridSigner as _;
    let signer = tenzro_crypto::composite::testing::TestHybridSigner::p256_only(seed);
    node.identity_registry()
        .expect("identity registry")
        .register_human_via_binder(
            vec![seed; 16],
            signer.public_key().p256.clone(),
            format!("Controller {seed}"),
        )
        .await
        .expect("controller registered")
        .identity
        .did_string()
}

/// `params` with `did`'s envelope for `method`, signed by the test key from
/// `seed`, over every field.
fn with_envelope(mut params: Value, did: &str, method: &str, seed: u8) -> Value {
    use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
    use tenzro_identity::envelope::{
        TenzroDidEnvelope, canonical_preimage, params_hash, request_binding,
    };
    let signer = tenzro_crypto::composite::testing::TestHybridSigner::p256_only(seed);
    let mut env = TenzroDidEnvelope {
        did: did.to_string(),
        method: method.to_string(),
        params_hash: params_hash(&request_binding(&params)),
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
        nonce: rand::random(),
        signature: Vec::new(),
    };
    let sig = signer
        .sign(SignatureContext::DidEnvelope, &canonical_preimage(&env))
        .unwrap();
    env.signature = serde_json::to_vec(&sig).unwrap();
    params["did_envelope"] = json!(env.to_header_value());
    params
}

/// A machine registration its controller signed is accepted through both
/// methods; one signed by another identity, or by another key under the
/// controller's name, or not signed at all, is refused.
#[tokio::test]
async fn test_rpc_machine_registration_signed_by_its_controller() {
    let (base_url, shutdown_tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let controller = register_signing_human(&node, 0x51).await;
    let stranger = register_signing_human(&node, 0x53).await;
    let machine_key = |seed: u8| wallet_key_params(seed)["public_key"].clone();
    let dedicated = |seed: u8| {
        json!({
            "controller_did": controller,
            "public_key": machine_key(seed),
            "capabilities": ["inference"],
        })
    };
    let call = |method: &'static str, params: Value| {
        let client = client.clone();
        let base_url = base_url.clone();
        async move { rpc_call(&client, &base_url, rpc_request(method, params)).await }
    };
    const DEDICATED: &str = "tenzro_registerMachineIdentity";
    const GENERIC: &str = "tenzro_registerIdentity";

    // Signed by the controller: accepted through the dedicated method.
    let resp = call(
        DEDICATED,
        with_envelope(dedicated(0x61), &controller, DEDICATED, 0x51),
    )
    .await;
    let did = resp["result"]["did"]
        .as_str()
        .unwrap_or_else(|| panic!("signed registration refused: {resp}"));
    assert!(did.starts_with("did:tenzro:machine:"), "{resp}");
    assert_eq!(resp["result"]["controller_did"], json!(controller));

    // And through tenzro_registerIdentity, which records the identity only
    // with its replication transaction. This node runs no consensus, so the
    // signed request passes the envelope check and then records nothing.
    let mut generic = dedicated(0x62);
    generic["identity_type"] = json!("machine");
    generic["proof"] = registration_proof(0x62);
    let resp = call(
        GENERIC,
        with_envelope(generic.clone(), &controller, GENERIC, 0x51),
    )
    .await;
    match resp["result"]["did"].as_str() {
        Some(did) => {
            assert!(did.starts_with("did:tenzro:machine:"), "{resp}");
            assert!(resp["result"]["tx_hash"].is_string(), "{resp}");
        }
        None => {
            let message = resp["error"]["message"].as_str().unwrap_or_default();
            assert!(
                !message.contains("did_envelope") && message.contains("nothing was recorded"),
                "signed registration refused: {resp}"
            );
        }
    }

    let refused = |resp: &Value, why: &str| {
        assert!(resp["result"].is_null(), "{why}: accepted: {resp}");
        let message = resp["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains("did_envelope"), "{why}: {resp}");
    };
    // Unsigned.
    refused(&call(DEDICATED, dedicated(0x63)).await, "unsigned");
    let mut unsigned = generic.clone();
    unsigned["public_key"] = machine_key(0x64);
    refused(&call(GENERIC, unsigned).await, "unsigned");
    // Signed by another identity, naming the controller.
    refused(
        &call(
            DEDICATED,
            with_envelope(dedicated(0x65), &stranger, DEDICATED, 0x53),
        )
        .await,
        "signed by another identity",
    );
    // Signed with another key under the controller's DID.
    refused(
        &call(
            DEDICATED,
            with_envelope(dedicated(0x66), &controller, DEDICATED, 0x53),
        )
        .await,
        "signed by another key",
    );
    // The controller's envelope for the other method.
    refused(
        &call(
            DEDICATED,
            with_envelope(dedicated(0x67), &controller, GENERIC, 0x51),
        )
        .await,
        "envelope for another method",
    );
    // The controller's envelope, with the machine key swapped afterwards.
    let mut swapped = with_envelope(dedicated(0x68), &controller, DEDICATED, 0x51);
    swapped["public_key"] = machine_key(0x69);
    refused(
        &call(DEDICATED, swapped).await,
        "fields changed after signing",
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

// ---------------------------------------------------------------------------
// Error Handling Tests
// ---------------------------------------------------------------------------

/// The JSON-RPC root is bounded at the ordinary ceiling for every caller and
/// at the media ceiling for the operator.
///
/// Media bytes travel base64 inside a JSON-RPC envelope: a media-sized body
/// from the operator gets through. Anyone else is held to the ordinary
/// ceiling, and nobody gets past the media one.
///
/// The two constants are private to `rpc.rs`; the figures are repeated here
/// deliberately, so that moving either ceiling trips this test rather than
/// silently changing what the endpoint accepts.
#[tokio::test]
async fn test_rpc_body_size_limit() {
    const MEDIA_BODY_LIMIT: usize = 64 * 1024 * 1024;
    const RPC_BODY_LIMIT: usize = 8 * 1024 * 1024;

    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let body_of = |len: usize| {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_blockNumber",
            "params": ["x".repeat(len)],
        })
    };

    // Over the ordinary ceiling, under the media one, from an ordinary caller.
    // Windows resets a connection that the server closes while the client is
    // still sending, before the client can read the 413 the server wrote; the
    // oversize body is refused all the same.
    let refused = |sent: Result<reqwest::Response, reqwest::Error>, why: &str| match sent {
        Ok(resp) => assert_eq!(resp.status().as_u16(), 413, "{why}"),
        Err(e) if cfg!(windows) && e.is_request() => {}
        Err(e) => panic!("HTTP request: {e:?}"),
    };
    refused(
        client
            .post(&base_url)
            .json(&body_of(RPC_BODY_LIMIT + 1024))
            .send()
            .await,
        "an ordinary caller is held to the ordinary ceiling",
    );

    // The same body from the operator: the media-gen publish path.
    let op = operator().sign_in(&client, &base_url).await;
    let resp = op
        .authorize(client.post(&base_url), &base_url)
        .json(&body_of(RPC_BODY_LIMIT + 1024))
        .send()
        .await
        .expect("HTTP request");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "the operator's render-sized body must be accepted on the JSON-RPC root"
    );

    // Past the media ceiling the request is refused, operator or not.
    refused(
        op.authorize(client.post(&base_url), &base_url)
            .json(&body_of(MEDIA_BODY_LIMIT + 1024))
            .send()
            .await,
        "a body past the media ceiling is refused",
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// 50 concurrent requests should all complete without server errors.
#[tokio::test]
async fn test_rpc_concurrent_requests() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let mut handles = Vec::new();
    for i in 0..50u64 {
        let client = client.clone();
        let url = base_url.clone();
        handles.push(tokio::spawn(async move {
            let body = json!({
                "jsonrpc": "2.0",
                "id": i,
                "method": "eth_blockNumber",
            });
            let resp = client
                .post(&url)
                .json(&body)
                .send()
                .await
                .expect("HTTP request");
            let status = resp.status();
            let body: Value = resp.json().await.expect("parse JSON");
            (status, body)
        }));
    }

    let mut success_count = 0;
    for h in handles {
        let (status, body) = h.await.expect("join");
        // All should succeed or at least return valid JSON-RPC
        assert_eq!(status.as_u16(), 200, "concurrent request returned non-200");
        assert_eq!(body["jsonrpc"], "2.0");
        if body["result"].is_string() {
            success_count += 1;
        }
    }

    // At least most should succeed (some might hit concurrency limit)
    assert!(
        success_count >= 40,
        "expected at least 40 successes, got {}",
        success_count
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

// ---------------------------------------------------------------------------
// Additional JSON-RPC protocol tests
// ---------------------------------------------------------------------------

/// eth_chainId returns the correct chain ID for the test network.
#[tokio::test]
async fn test_rpc_chain_id() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request_no_params("eth_chainId");
    let resp = rpc_call(&client, &base_url, body).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    let result = resp["result"].as_str().expect("result is string");
    assert!(
        result.starts_with("0x"),
        "chain ID should be hex: {}",
        result
    );
    // Default chain ID is 1337 = 0x539
    assert_eq!(result, "0x539", "default chain ID should be 1337");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// tenzro_blockNumber and eth_blockNumber should return the same value.
#[tokio::test]
async fn test_rpc_tenzro_and_eth_block_number_agree() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let tenzro_body = rpc_request_no_params("tenzro_blockNumber");
    let eth_body = rpc_request_no_params("eth_blockNumber");

    let tenzro_resp = rpc_call(&client, &base_url, tenzro_body).await;
    let eth_resp = rpc_call(&client, &base_url, eth_body).await;

    assert_eq!(
        tenzro_resp["result"], eth_resp["result"],
        "tenzro_blockNumber and eth_blockNumber should agree"
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// tenzro_getNodeStatus returns node metadata.
#[tokio::test]
async fn test_rpc_node_info() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request_no_params("tenzro_getNodeStatus");
    let resp = rpc_call(&client, &base_url, body).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    // nodeInfo should return some data about the node
    assert!(
        resp["result"].is_object() || resp["result"].is_string(),
        "nodeInfo result should have content"
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// Positional-array-of-scalars must still work: `eth_getBalance` reads
/// `params.as_array()[0].as_str()` for the address — that path is preserved
/// by normalize_params() because the inner element is not an object.
#[tokio::test]
async fn test_rpc_positional_scalar_array_preserved() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let zero_addr = format!("0x{}", "00".repeat(20));
    // Single-element scalar array — must NOT be unwrapped.
    let body = rpc_request("eth_getBalance", json!([zero_addr]));
    let resp = rpc_call(&client, &base_url, body).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    let result = resp["result"].as_str().expect("result is string");
    assert!(
        result.starts_with("0x"),
        "balance should be hex: {}",
        result
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// Multi-element positional arrays must also be preserved: `eth_getBalance`
/// with `[address, "latest"]` is a standard EVM-compat pattern.
#[tokio::test]
async fn test_rpc_multi_element_positional_array_preserved() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let zero_addr = format!("0x{}", "00".repeat(20));
    let body = rpc_request("eth_getBalance", json!([zero_addr, "latest"]));
    let resp = rpc_call(&client, &base_url, body).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    let result = resp["result"].as_str().expect("result is string");
    assert!(
        result.starts_with("0x"),
        "balance should be hex: {}",
        result
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}
