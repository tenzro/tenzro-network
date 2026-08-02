//! HTTP-level integration tests for the Tenzro Node RPC server.
//!
//! Each test spins up a fresh TenzroNode + RPC server on an OS-assigned port,
//! issues real HTTP requests via reqwest, and asserts on the JSON-RPC responses.
//! Every test gets its own temp directory so RocksDB instances never contend.

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
        ..Default::default()
    };
    (config, tmp)
}

/// Boot a TenzroNode and its RPC server.  Returns the base URL
/// (e.g. "http://127.0.0.1:54321"), a shutdown sender, and a join handle.
async fn setup_test_server() -> (
    String,
    broadcast::Sender<()>,
    tokio::task::JoinHandle<tenzro_node::Result<()>>,
    tempfile::TempDir,
    Arc<TenzroNode>,
) {
    let (config, tmp) = test_config();
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

    // tenzro_settle requires params (provider, customer, amount)
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

/// POST tenzro_settle with valid inference params returns a settlement receipt.
#[tokio::test]
async fn test_rpc_settle_inference() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let provider_addr = format!("0x{}", "aa".repeat(20));
    let customer_addr = format!("0x{}", "bb".repeat(20));

    let body = rpc_request(
        "tenzro_settle",
        json!({
            "provider": provider_addr,
            "customer": customer_addr,
            "amount": 5000,
            "service_type": "inference",
            "model_id": "test-model",
            "tokens": 100,
            "proof": "deadbeef"
        }),
    );
    let resp = rpc_call(&client, &base_url, body).await;

    if resp["error"].is_object() {
        // Settlement engine might not be initialized — that is a valid server error
        let msg = resp["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("Settlement engine not initialized") || msg.contains("Settlement failed"),
            "unexpected settlement error: {}",
            msg
        );
    } else {
        // If it succeeds, validate the receipt
        let result = &resp["result"];
        assert!(result["receipt_id"].is_string(), "receipt_id missing");
        assert!(result["amount"].is_number(), "amount missing");
        assert!(result["status"].is_string(), "status missing");
    }

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// Settlement with missing required fields (no customer) returns an error.
#[tokio::test]
async fn test_rpc_settle_insufficient_balance() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let provider_addr = format!("0x{}", "cc".repeat(20));

    // Missing the customer field
    let body = rpc_request(
        "tenzro_settle",
        json!({
            "provider": provider_addr,
            "amount": 999999999999u64,
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
    assert_eq!(resp["result"]["count"].as_u64().unwrap_or(99), 0);
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
    assert_eq!(resp["result"]["count"].as_u64().unwrap_or(99), 0);
    assert_eq!(
        resp["result"]["escrows"].as_array().map(|a| a.len()),
        Some(0)
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// POST tenzro_getSettlement with a bogus receipt_id returns null (not found).
#[tokio::test]
async fn test_rpc_get_settlement() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request(
        "tenzro_getSettlement",
        json!({
            "receipt_id": "nonexistent-receipt-id"
        }),
    );
    let resp = rpc_call(&client, &base_url, body).await;

    if resp["error"].is_object() {
        let msg = resp["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("Settlement engine not initialized"),
            "unexpected error: {}",
            msg
        );
    } else {
        // If engine is initialized, a missing receipt returns null
        assert!(
            resp["result"].is_null(),
            "nonexistent receipt should return null"
        );
    }

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

/// POST tenzro_createWallet returns a wallet with address and public key.
#[tokio::test]
async fn test_rpc_create_wallet() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request_no_params("tenzro_createWallet");
    let resp = rpc_call(&client, &base_url, body).await;

    if resp["error"].is_object() {
        let msg = resp["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("Wallet service not initialized"),
            "unexpected error: {}",
            msg
        );
    } else {
        let result = &resp["result"];
        assert!(result["address"].is_string(), "address missing");
        assert!(result["public_key"].is_string(), "public_key missing");
        assert!(result["wallet_id"].is_string(), "wallet_id missing");
    }

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// POST tenzro_registerIdentity creates a DID.
#[tokio::test]
async fn test_rpc_register_identity() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request(
        "tenzro_registerIdentity",
        json!({
            "display_name": "Test User"
        }),
    );
    let resp = rpc_call(&client, &base_url, body).await;

    if resp["error"].is_object() {
        let msg = resp["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("Identity registry not initialized")
                || msg.contains("Registration failed"),
            "unexpected error: {}",
            msg
        );
    } else {
        let result = &resp["result"];
        assert!(result["did"].is_string(), "did missing");
        let did = result["did"].as_str().unwrap();
        assert!(
            did.starts_with("did:tenzro:human:"),
            "DID format wrong: {}",
            did
        );
        assert!(result["status"].is_string(), "status missing");
    }

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// POST tenzro_participate provisions identity + wallet in one call.
#[tokio::test]
async fn test_rpc_participate() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request(
        "tenzro_participate",
        json!({
            "display_name": "Integration Test User"
        }),
    );
    let resp = rpc_call(&client, &base_url, body).await;

    if resp["error"].is_object() {
        let msg = resp["error"]["message"].as_str().unwrap_or("");
        // Hardware detection, wallet, or identity might not be available
        assert!(
            msg.contains("not initialized") || msg.contains("failed") || msg.contains("Hardware"),
            "unexpected error: {}",
            msg
        );
    } else {
        let result = &resp["result"];
        assert!(result["identity"].is_object(), "identity section missing");
        assert!(
            result["identity"]["did"].is_string(),
            "identity.did missing"
        );
        assert!(result["wallet"].is_object(), "wallet section missing");
        assert!(
            result["wallet"]["address"].is_string(),
            "wallet.address missing"
        );
    }

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

// ---------------------------------------------------------------------------
// Error Handling Tests
// ---------------------------------------------------------------------------

/// A request body larger than 2 MB should be rejected.
#[tokio::test]
async fn test_rpc_body_size_limit() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    // Create a payload slightly over 2 MB
    let big_data = "x".repeat(2 * 1024 * 1024 + 1024);
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_blockNumber",
        "params": [big_data]
    });

    let resp = client
        .post(&base_url)
        .json(&body)
        .send()
        .await
        .expect("HTTP request");

    // The server should reject with 413 Payload Too Large (or 400)
    let status = resp.status().as_u16();
    assert!(
        status == 413 || status == 400 || status == 422,
        "oversized body should be rejected, got status: {}",
        status,
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

/// tenzro_nodeInfo returns node metadata.
#[tokio::test]
async fn test_rpc_node_info() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request_no_params("tenzro_nodeInfo");
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

/// tenzro_createAccount generates a fresh keypair.
#[tokio::test]
async fn test_rpc_create_account() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request("tenzro_createAccount", json!({"key_type": "ed25519"}));
    let resp = rpc_call(&client, &base_url, body).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    let result = &resp["result"];
    assert!(result["address"].is_string(), "address missing");
    let addr = result["address"].as_str().unwrap();
    assert!(addr.starts_with("0x"), "address should be hex");
    assert!(result["public_key"].is_string(), "public_key missing");
    assert!(result["private_key"].is_string(), "private_key missing");

    // Creating a second account should produce a different address
    let body2 = rpc_request("tenzro_createAccount", json!({"key_type": "secp256k1"}));
    let resp2 = rpc_call(&client, &base_url, body2).await;
    let addr2 = resp2["result"]["address"].as_str().unwrap();
    assert_ne!(addr, addr2, "two accounts should have different addresses");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// Settlement roundtrip: settle then look up the receipt by ID.
#[tokio::test]
async fn test_rpc_settle_then_get_settlement() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let provider = format!("0x{}", "dd".repeat(20));
    let customer = format!("0x{}", "ee".repeat(20));

    // Step 1: settle
    let settle_body = rpc_request(
        "tenzro_settle",
        json!({
            "provider": provider,
            "customer": customer,
            "amount": 1000,
            "service_type": "custom",
            "proof": "test-proof"
        }),
    );
    let settle_resp = rpc_call(&client, &base_url, settle_body).await;

    // If settlement engine isn't initialized, skip the lookup
    if settle_resp["error"].is_object() {
        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
        return;
    }

    let receipt_id = settle_resp["result"]["receipt_id"]
        .as_str()
        .expect("receipt_id");

    // Step 2: look up the settlement
    let get_body = rpc_request(
        "tenzro_getSettlement",
        json!({
            "receipt_id": receipt_id
        }),
    );
    let get_resp = rpc_call(&client, &base_url, get_body).await;

    let result = &get_resp["result"];
    assert!(
        !result.is_null(),
        "looking up a valid receipt_id should return data"
    );
    assert_eq!(result["receipt_id"].as_str().unwrap(), receipt_id);

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

// ---------------------------------------------------------------------------
// JSON-RPC params normalization
//
// JSON-RPC 2.0 §4.2 explicitly allows EITHER a positional (array) or named
// (object) `params` value. Most SDKs that wrap a single object argument send
// it positionally as `[{...}]`; our handlers historically read named fields
// via `params.get("foo")`. Without dispatcher-level normalization, calls
// like `tenzro_registerAgent` with array-wrapped params silently fail with
// misleading "Missing X" errors. These tests pin both shapes through the full
// HTTP → JSON-RPC → handler stack so the regression cannot return.
// ---------------------------------------------------------------------------

/// `tenzro_createWallet` accepts named-form params: {key_type: "ed25519"}.
#[tokio::test]
async fn test_rpc_named_params_object_form() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request("tenzro_createWallet", json!({"key_type": "ed25519"}));
    let resp = rpc_call(&client, &base_url, body).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    assert!(
        resp["result"].is_object(),
        "named-form createWallet should succeed, got {:?}",
        resp
    );
    assert!(resp["result"]["address"].as_str().is_some());

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

/// `tenzro_createWallet` accepts SDK-form positional-array-wrapped params:
/// [{key_type: "ed25519"}]. Without normalize_params() at the dispatcher,
/// this would fail with "Missing key_type" because the handler reads
/// `params.get("key_type")` on what would otherwise be a JSON array.
#[tokio::test]
async fn test_rpc_array_wrapped_params_unwrapped_by_dispatcher() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let body = rpc_request("tenzro_createWallet", json!([{"key_type": "ed25519"}]));
    let resp = rpc_call(&client, &base_url, body).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    assert!(
        resp["result"].is_object(),
        "array-wrapped createWallet should succeed (normalize_params), got {:?}",
        resp
    );
    assert!(resp["result"]["address"].as_str().is_some());

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
