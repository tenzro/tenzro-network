//! On-chain AgentBond wire-format integration tests.
//!
//! AgentBond mutating operations (`PostAgentBond`, `IncreaseAgentBond`,
//! `WithdrawAgentBond`, `PayInsuranceClaim`) flow through consensus-mediated
//! typed transactions submitted via `tenzro_sendRawTransaction`. The unit tests in
//! `tenzro-vm` exercise the VM dispatch arms directly, including the bond
//! records `tenzro_getAgentBond` reads.
//!
//! What none of those layers catch is the *wire-format* contract:
//!
//! - Does `tenzro_sendRawTransaction` accept a JSON `tx_type` that decodes into
//!   each of the four bond `TransactionType` variants?
//! - Does the composite (P-256, optional ML-DSA-65) signature pipeline accept a
//!   transaction whose hash preimage commits to the bond payload?
//! - Does post-signing tampering with the on-chain payload (e.g. inflating the
//!   `amount` on a `PostAgentBond`) get rejected at the synchronous signature
//!   gate (-32003)?
//!
//! These tests bring up a real `TenzroNode` + `RpcServer`, build genuine
//! hybrid-signed payloads, and submit via HTTP. Tx admission is the success
//! criterion.

mod hybrid_account;

use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::broadcast;

use tenzro_crypto::composite::{HybridSigner, SignatureContext};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_types::insurance::InsuranceEvidence;
use tenzro_types::primitives::{Address, ChainId, Nonce};
use tenzro_types::transaction::{Transaction, TransactionType};

// ---------------------------------------------------------------------------
// Boilerplate
// ---------------------------------------------------------------------------

fn test_config() -> (NodeConfig, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
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
    let handle =
        tokio::spawn(async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await });

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

/// Gas price the fixtures sign at.
///
/// These transactions are sent by freshly-generated, unverified keypairs, so
/// admission places them in the **Open** lane, whose fee floor is `4×` the
/// 1 Gwei base (`Lane::Open` in `tenzro-consensus::admission`). Signing at the
/// bare base rate is rejected before the handler runs, with
/// `-32012 Fee floor not met for open lane`.
const OPEN_LANE_GAS_PRICE: u64 = 4_000_000_000;

/// Credit `address` so admission's balance check passes.
///
/// Mempool admission requires `gas_limit × gas_price + value` to be covered by
/// the sender's balance, and these fixtures sign with a freshly-generated
/// keypair that starts at zero. The economic gates are covered on their own in
/// `tenzro-consensus::mempool`; what these suites assert is the *wire-format*
/// contract, so the sender is funded up front to let the transaction reach it.
///
/// Writes through the same `StateAdapter` that
/// `NodeAccountStateReader::account_balance` reads, then commits so the value
/// is visible to the admission path.
fn fund_account(node: &TenzroNode, address: &Address, amount: u128) {
    use tenzro_vm::traits::VmState as _;
    let storage = node.storage().expect("node storage").clone();
    let mut state = tenzro_vm::StateAdapter::with_storage(storage);
    state.set_balance(address.as_bytes(), amount);
    state.commit().expect("commit funded balance");
}

/// Comfortably above `gas_limit × OPEN_LANE_GAS_PRICE + value` for every
/// fixture in this file.
const FIXTURE_BALANCE: u128 = 1_000_000_000_000_000_000;

/// Build a signed JSON payload for `tenzro_sendRawTransaction`.
///
/// `from` is the account the generated P-256 key controls; admission requires
/// the signing key to name `from`.
fn build_signed_eth_send_params(
    to: Address,
    nonce: u64,
    tx_type: TransactionType,
    gas_limit: u64,
    gas_price: u64,
) -> (Value, Address) {
    let signer = hybrid_account::fresh_signer();
    let from = signer.address();

    let tx = Transaction::new(
        ChainId::from(1337),
        from,
        to,
        Nonce::from(nonce),
        tx_type,
        gas_limit,
        gas_price,
    );
    let signature = signer
        .sign(SignatureContext::Transaction, tx.hash().as_bytes())
        .expect("sign");

    // Re-emit `tx_type` as JSON so the handler's `serde_json::from_value::<
    // TransactionType>` path is exercised.
    let tx_type_json = serde_json::to_value(&tx.tx_type).expect("serialize tx_type");

    let params = json!({
        "from": format!("0x{}", hex::encode(tx.from.as_bytes())),
        "to": format!("0x{}", hex::encode(tx.to.as_bytes())),
        "nonce": nonce,
        "gas_limit": gas_limit,
        "gas_price": gas_price,
        "chain_id": 1337u64,
        "timestamp": tx.timestamp.0,
        "valid_until": tx.valid_until.0,
        "tx_type": tx_type_json,
        "public_key": hex::encode(&signer.public_key().p256),
        "signature": signature,
    });
    (params, from)
}

/// Assert the JSON-RPC response carries a `result` (admission succeeded).
fn assert_admission_succeeded(resp: &Value, label: &str) {
    if let Some(err) = resp.get("error")
        && !err.is_null()
    {
        panic!("{label}: tenzro_sendRawTransaction returned error: {err}");
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

/// `tenzro_sendRawTransaction` with `tx_type = PostAgentBond` must (a) decode the
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

    let (params, sender) =
        build_signed_eth_send_params(Address::zero(), 0, tx_type, 90_000, OPEN_LANE_GAS_PRICE);
    fund_account(&_node, &sender, FIXTURE_BALANCE);
    hybrid_account::enroll_sender(&_node, &params);
    let body = rpc_request("tenzro_sendRawTransaction", params);
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

    let (params, sender) =
        build_signed_eth_send_params(Address::zero(), 1, tx_type, 70_000, OPEN_LANE_GAS_PRICE);
    fund_account(&_node, &sender, FIXTURE_BALANCE);
    hybrid_account::enroll_sender(&_node, &params);
    let body = rpc_request("tenzro_sendRawTransaction", params);
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

    let (params, sender) =
        build_signed_eth_send_params(Address::zero(), 2, tx_type, 50_000, OPEN_LANE_GAS_PRICE);
    fund_account(&_node, &sender, FIXTURE_BALANCE);
    hybrid_account::enroll_sender(&_node, &params);
    let body = rpc_request("tenzro_sendRawTransaction", params);
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

    let tx_type = TransactionType::PayInsuranceClaim {
        evidence: InsuranceEvidence::ReconMismatch {
            adapter: tenzro_types::bridge_route::BridgeRouteAdapter::Ibc,
            chain: "cosmoshub-4".into(),
            position: 1,
        },
    };

    let (params, sender) =
        build_signed_eth_send_params(Address::zero(), 3, tx_type, 90_000, OPEN_LANE_GAS_PRICE);
    fund_account(&_node, &sender, FIXTURE_BALANCE);
    hybrid_account::enroll_sender(&_node, &params);
    let body = rpc_request("tenzro_sendRawTransaction", params);
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

    let (mut params, sender) = build_signed_eth_send_params(
        Address::zero(),
        0,
        original_tx_type,
        90_000,
        OPEN_LANE_GAS_PRICE,
    );

    // Swap in a different amount post-signing. The signatures bind to the
    // original hash, so the server must reject.
    let forged_tx_type = TransactionType::PostAgentBond {
        agent_did: "did:tenzro:machine:0xabc:1".to_string(),
        controller_did: "did:tenzro:human:0x111".to_string(),
        amount: 999_999_999u128,
    };
    params["tx_type"] = serde_json::to_value(&forged_tx_type).expect("serialize forged");

    fund_account(&_node, &sender, FIXTURE_BALANCE);
    hybrid_account::enroll_sender(&_node, &params);
    let body = rpc_request("tenzro_sendRawTransaction", params);
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
// 6. Tampered PayInsuranceClaim evidence fails hybrid-signature verification
// ---------------------------------------------------------------------------

/// The most security-sensitive bond tx is `PayInsuranceClaim` — it transfers
/// pool funds to the party its evidence names. An attacker who observes a
/// legitimate claim must not be able to swap the evidence after signing.
/// Same hash-preimage guarantee as the amount case, but separately asserted
/// because this is the dollar-denominated attack surface.
#[tokio::test]
async fn eth_send_raw_rejects_pay_insurance_claim_with_tampered_evidence() {
    let (base_url, shutdown_tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let original_tx_type = TransactionType::PayInsuranceClaim {
        evidence: InsuranceEvidence::ReconMismatch {
            adapter: tenzro_types::bridge_route::BridgeRouteAdapter::Ibc,
            chain: "cosmoshub-4".into(),
            position: 1,
        },
    };

    let (mut params, sender) = build_signed_eth_send_params(
        Address::zero(),
        0,
        original_tx_type,
        90_000,
        OPEN_LANE_GAS_PRICE,
    );

    let forged_tx_type = TransactionType::PayInsuranceClaim {
        evidence: InsuranceEvidence::ReconMismatch {
            adapter: tenzro_types::bridge_route::BridgeRouteAdapter::Ibc,
            chain: "cosmoshub-4".into(),
            position: 2,
        },
    };
    params["tx_type"] = serde_json::to_value(&forged_tx_type).expect("serialize forged");

    fund_account(&_node, &sender, FIXTURE_BALANCE);
    hybrid_account::enroll_sender(&_node, &params);
    let body = rpc_request("tenzro_sendRawTransaction", params);
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
        "tampered evidence must be rejected by signature gate, got code {code}: {resp}"
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}
