//! On-chain AgentBond wire-format integration tests (Spec 9).
//!
//! AgentBond mutating operations (`PostAgentBond`, `IncreaseAgentBond`,
//! `WithdrawAgentBond`, `PayInsuranceClaim`) flow through consensus-mediated
//! typed transactions submitted via `eth_sendRawTransaction`. The unit tests in
//! `tenzro-vm` exercise the VM dispatch arms directly and the unit tests in
//! `tenzro-token` cover the off-chain `BondManager` state machine. The
//! in-module tests in `tenzro_node::event_loop` cover the post-block scan that
//! reflects VM-emitted bond logs back into the manager.
//!
//! What none of those layers catch is the *wire-format* contract:
//!
//! - Does `eth_sendRawTransaction` accept a JSON `tx_type` that decodes into
//!   each of the four bond `TransactionType` variants?
//! - Does the hybrid (Ed25519 + ML-DSA-65) signature pipeline accept a
//!   transaction whose hash preimage commits to the bond payload?
//! - Does post-signing tampering with the on-chain payload (e.g. inflating the
//!   `amount` on a `PostAgentBond`) get rejected at the synchronous signature
//!   gate (-32003)?
//!
//! These tests bring up a real `TenzroNode` + `RpcServer`, build genuine
//! hybrid-signed payloads, and submit via HTTP. Tx admission is the success
//! criterion — full block production through to `BondManager` reflection is
//! asynchronous and is exercised by the in-module event-loop tests.

use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::broadcast;

use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
use tenzro_crypto::{KeyPair, KeyType};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_types::primitives::{Address, ChainId, Nonce};
use tenzro_types::transaction::{Transaction, TransactionType};

// ---------------------------------------------------------------------------
// Boilerplate
// ---------------------------------------------------------------------------

fn test_config() -> (NodeConfig, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    (config, tmp)
}

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
    let handle = tokio::spawn(async move {
        rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await
    });

    let addr = addr_rx.await.expect("receive bound address");
    let base_url = format!("http://{}", addr);

    (base_url, shutdown_tx, handle, tmp, node)
}

fn rpc_request(method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
}

async fn rpc_call(client: &reqwest::Client, url: &str, body: Value) -> Value {
    client
        .post(url)
        .json(&body)
        .send()
        .await
        .expect("HTTP request")
        .json::<Value>()
        .await
        .expect("parse JSON")
}

/// Build a hybrid-signed JSON payload for `eth_sendRawTransaction`.
///
/// `from` is derived from the generated Ed25519 keypair (20-byte derived
/// address left-aligned in the canonical 32-byte slot) — the admission-time
/// sender-impersonation guard requires the signing pubkey to derive `from`.
fn build_signed_eth_send_params(
    to: Address,
    nonce: u64,
    tx_type: TransactionType,
    gas_limit: u64,
    gas_price: u64,
) -> Value {
    let kp = KeyPair::generate(KeyType::Ed25519).expect("ed25519 keypair");
    let classical_pk = kp.public_key().clone();
    let classical = Ed25519SignerImpl::new(kp).expect("ed25519 signer");
    let pq_key = MlDsaSigningKey::generate();
    let pq_vk = pq_key.verifying_key_bytes().to_vec();
    assert_eq!(pq_vk.len(), 1952);

    let derived = classical_pk.to_address();
    let mut from_bytes = [0u8; 32];
    from_bytes[..20].copy_from_slice(derived.as_bytes());
    let from = Address::new(from_bytes);

    let tx = Transaction::new(
        ChainId::from(1337),
        from,
        to,
        Nonce::from(nonce),
        tx_type,
        gas_limit,
        gas_price,
        pq_vk.clone(),
    );
    let hash = tx.hash();
    let timestamp = tx.timestamp.0;

    let classical_sig = classical.sign(hash.as_bytes()).expect("classical sign");
    let pq_sig = pq_key.sign(hash.as_bytes()).to_vec();
    assert_eq!(pq_sig.len(), 3309);

    let tx_type_json = serde_json::to_value(&tx.tx_type).expect("serialize tx_type");

    json!({
        "from": format!("0x{}", hex::encode(tx.from.as_bytes())),
        "to": format!("0x{}", hex::encode(tx.to.as_bytes())),
        "nonce": nonce,
        "gas_limit": gas_limit,
        "gas_price": gas_price,
        "chain_id": 1337u64,
        "timestamp": timestamp,
        "tx_type": tx_type_json,
        "signature": hex::encode(classical_sig.to_bytes()),
        "public_key": hex::encode(classical_pk.as_bytes()),
        "pq_public_key": hex::encode(&pq_vk),
        "pq_signature": hex::encode(&pq_sig),
    })
}

/// Assert the JSON-RPC response carries a `result` (admission succeeded).
fn assert_admission_succeeded(resp: &Value, label: &str) {
    if let Some(err) = resp.get("error")
        && !err.is_null() {
            panic!("{label}: eth_sendRawTransaction returned error: {err}");
        }
    let result = resp.get("result").expect("missing `result` field");
    let s = result
        .as_str()
        .unwrap_or_else(|| panic!("{label}: result is not a string: {result}"));
    let hex_part = s.strip_prefix("0x").unwrap_or(s);
    assert_eq!(
        hex_part.len(),
        64,
        "{label}: result must be a 32-byte hex tx_hash (64 chars), got {s:?}"
    );
    assert!(
        hex_part.chars().all(|c| c.is_ascii_hexdigit()),
        "{label}: result must be hex-encoded, got {s:?}"
    );
}

// ---------------------------------------------------------------------------
// 1. PostAgentBond typed-tx admission
// ---------------------------------------------------------------------------

/// `eth_sendRawTransaction` with `tx_type = PostAgentBond` must (a) decode the
/// JSON into `TransactionType::PostAgentBond`, (b) accept the hybrid signature
/// over the resulting `Transaction::hash()`, and (c) enqueue without error.
/// VM-layer authorization (controller authority, prior-bond-state check) runs
/// inside block production, not at admission.
#[tokio::test]
async fn eth_send_raw_admits_post_agent_bond_typed_tx() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let tx_type = TransactionType::PostAgentBond {
        agent_did: "did:tenzro:machine:0xabc:1".to_string(),
        controller_did: "did:tenzro:human:0x111".to_string(),
        amount: 100_000u128,
    };

    let params = build_signed_eth_send_params(
        Address::zero(),
        0,
        tx_type,
        90_000,
        1_000_000_000,
    );
    let body = rpc_request("eth_sendRawTransaction", params);
    let resp = rpc_call(&client, &base_url, body).await;
    assert_admission_succeeded(&resp, "PostAgentBond");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

// ---------------------------------------------------------------------------
// 2. IncreaseAgentBond typed-tx admission
// ---------------------------------------------------------------------------

#[tokio::test]
async fn eth_send_raw_admits_increase_agent_bond_typed_tx() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let tx_type = TransactionType::IncreaseAgentBond {
        agent_did: "did:tenzro:machine:0xabc:1".to_string(),
        amount: 50_000u128,
    };

    let params = build_signed_eth_send_params(
        Address::zero(),
        1,
        tx_type,
        70_000,
        1_000_000_000,
    );
    let body = rpc_request("eth_sendRawTransaction", params);
    let resp = rpc_call(&client, &base_url, body).await;
    assert_admission_succeeded(&resp, "IncreaseAgentBond");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

// ---------------------------------------------------------------------------
// 3. WithdrawAgentBond typed-tx admission
// ---------------------------------------------------------------------------

#[tokio::test]
async fn eth_send_raw_admits_withdraw_agent_bond_typed_tx() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let tx_type = TransactionType::WithdrawAgentBond {
        agent_did: "did:tenzro:machine:0xabc:1".to_string(),
    };

    let params = build_signed_eth_send_params(
        Address::zero(),
        2,
        tx_type,
        50_000,
        1_000_000_000,
    );
    let body = rpc_request("eth_sendRawTransaction", params);
    let resp = rpc_call(&client, &base_url, body).await;
    assert_admission_succeeded(&resp, "WithdrawAgentBond");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

// ---------------------------------------------------------------------------
// 4. PayInsuranceClaim typed-tx admission
// ---------------------------------------------------------------------------

#[tokio::test]
async fn eth_send_raw_admits_pay_insurance_claim_typed_tx() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    // 32-byte deterministic claim id, lowercase hex.
    let claim_id_hex = hex::encode([0x5C; 32]);
    let tx_type = TransactionType::PayInsuranceClaim {
        claim_id_hex,
        claimant: Address::new([0x33; 32]),
        amount: 25_000u128,
    };

    let params = build_signed_eth_send_params(
        Address::zero(),
        3,
        tx_type,
        90_000,
        1_000_000_000,
    );
    let body = rpc_request("eth_sendRawTransaction", params);
    let resp = rpc_call(&client, &base_url, body).await;
    assert_admission_succeeded(&resp, "PayInsuranceClaim");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

// ---------------------------------------------------------------------------
// 5. Tampered PostAgentBond fails hybrid-signature verification
// ---------------------------------------------------------------------------

/// Mutating the `tx_type` payload after signing must invalidate the hybrid
/// signature: `Transaction::hash()` includes the JSON-serialized tx_type, so a
/// `PostAgentBond` payload signed for `amount: 100_000` cannot be re-submitted
/// with `amount: 999_999_999`. The RPC must reject at the synchronous
/// signature-verification gate (-32003), not silently enqueue. This is the
/// guard that prevents an attacker who observes a small bond posting from
/// re-broadcasting an inflated version.
#[tokio::test]
async fn eth_send_raw_rejects_post_agent_bond_with_tampered_amount() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let original_tx_type = TransactionType::PostAgentBond {
        agent_did: "did:tenzro:machine:0xabc:1".to_string(),
        controller_did: "did:tenzro:human:0x111".to_string(),
        amount: 100_000u128,
    };

    let mut params = build_signed_eth_send_params(
        Address::zero(),
        0,
        original_tx_type,
        90_000,
        1_000_000_000,
    );

    // Swap in a different amount post-signing. The signatures bind to the
    // original hash, so the server must reject.
    let forged_tx_type = TransactionType::PostAgentBond {
        agent_did: "did:tenzro:machine:0xabc:1".to_string(),
        controller_did: "did:tenzro:human:0x111".to_string(),
        amount: 999_999_999u128,
    };
    params["tx_type"] = serde_json::to_value(&forged_tx_type).expect("serialize forged");

    let body = rpc_request("eth_sendRawTransaction", params);
    let resp = rpc_call(&client, &base_url, body).await;

    let err = resp
        .get("error")
        .and_then(|v| v.as_object())
        .expect("tampered tx must return error, got success");
    let code = err
        .get("code")
        .and_then(|v| v.as_i64())
        .expect("error code missing");
    assert_eq!(
        code, -32003,
        "tampered tx must be rejected by signature gate, got code {code}: {resp}"
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

// ---------------------------------------------------------------------------
// 6. Tampered PayInsuranceClaim claimant fails hybrid-signature verification
// ---------------------------------------------------------------------------

/// The most security-sensitive bond tx is `PayInsuranceClaim` — it transfers
/// pool funds to a claimant address. An attacker who observes a legitimate
/// payout must not be able to redirect it by swapping the `claimant` after
/// signing. Same hash-preimage guarantee as the amount case, but separately
/// asserted because this is the dollar-denominated attack surface.
#[tokio::test]
async fn eth_send_raw_rejects_pay_insurance_claim_with_tampered_claimant() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let claim_id_hex = hex::encode([0x5C; 32]);
    let original_tx_type = TransactionType::PayInsuranceClaim {
        claim_id_hex: claim_id_hex.clone(),
        claimant: Address::new([0x33; 32]),
        amount: 25_000u128,
    };

    let mut params = build_signed_eth_send_params(
        Address::zero(),
        0,
        original_tx_type,
        90_000,
        1_000_000_000,
    );

    let forged_tx_type = TransactionType::PayInsuranceClaim {
        claim_id_hex,
        claimant: Address::new([0xAA; 32]), // attacker's address
        amount: 25_000u128,
    };
    params["tx_type"] = serde_json::to_value(&forged_tx_type).expect("serialize forged");

    let body = rpc_request("eth_sendRawTransaction", params);
    let resp = rpc_call(&client, &base_url, body).await;

    let err = resp
        .get("error")
        .and_then(|v| v.as_object())
        .expect("tampered tx must return error, got success");
    let code = err
        .get("code")
        .and_then(|v| v.as_i64())
        .expect("error code missing");
    assert_eq!(
        code, -32003,
        "tampered claimant must be rejected by signature gate, got code {code}: {resp}"
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}
