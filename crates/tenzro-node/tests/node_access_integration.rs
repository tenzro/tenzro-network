//! End-to-end tests for method classification, node addressing, and
//! settlement routing.
//!
//! These exist because the unit tests for those features prove the *policy*
//! objects behave, and prove nothing about whether they are reachable. A gate
//! that is never mounted, an RPC that is dispatched to the wrong handler, or a
//! method missing from the classification table all pass every unit test in the
//! workspace and fail the first real request. Each test here boots a real node,
//! stands up a real RPC server, and speaks HTTP to it.

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct TestNode {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    node: Arc<TenzroNode>,
    client: reqwest::Client,
    /// The node's web surface, where the well-known paths are served; the
    /// JSON-RPC server at `base_url` does not serve them.
    web_url: String,
    web_handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
}

impl TestNode {
    async fn boot() -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
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

        let web_port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("a free port")
            .port();
        let web_state =
            Arc::new(tenzro_node::web::handlers::WebState::new().with_node(node.clone()));
        let web_rx = shutdown.subscribe();
        let web_handle = tokio::spawn(
            tenzro_node::web::WebServer::new(format!("127.0.0.1:{web_port}"))
                .with_state_arc(web_state)
                .start_with_shutdown(web_rx),
        );
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", web_port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        Self {
            web_url: format!("http://127.0.0.1:{web_port}"),
            web_handle,
            base_url: format!("http://{addr}"),
            shutdown,
            handle,
            _tmp: tmp,
            node,
            client: reqwest::Client::new(),
        }
    }

    async fn rpc(&self, method: &str, params: Value) -> Value {
        let resp = self
            .client
            .post(&self.base_url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .expect("HTTP request");
        let status = resp.status();
        let body = resp.text().await.expect("HTTP body");
        serde_json::from_str(&body).unwrap_or_else(|e| {
            let head: String = body.chars().take(200).collect();
            panic!("{method} answered {status} with a body that is not JSON ({e}): {head}")
        })
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
        let _ = self.web_handle.await;
    }
}

fn error_message(resp: &Value) -> String {
    resp.get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string()
}

// ---------------------------------------------------------------------------
// Default-deny method classification
// ---------------------------------------------------------------------------

/// The asset an unconfigured payee settles in, derived from the economic
/// policy rather than hardcoded.
///
/// The default is governance-settable (`EconomicPolicy::default_conversion`),
/// so asserting a literal here would bake in whatever it happened to be the
/// day the test was written — which is exactly how these three tests came to
/// assert `keep_inbound` long after the network default became TNZO.
fn policy_default_asset() -> &'static str {
    tenzro_payments::settlement_asset::SettlementAsset::from_policy(
        tenzro_types::economics::ConversionPolicy::default(),
    )
    .as_str()
}

/// A method nobody classified must not reach its handler. The unit test proves
/// the table is complete; this proves the check is actually consulted on the
/// live dispatch path.
#[tokio::test]
async fn an_unclassified_method_is_refused_before_dispatch() {
    let n = TestNode::boot().await;
    let resp = n
        .rpc("tenzro_methodThatWasNeverClassified", json!({}))
        .await;
    assert_eq!(
        resp["error"]["code"], -32601,
        "an unclassified method must be unreachable, got: {resp}"
    );
    n.shutdown().await;
}

/// The other side of it: a classified open method still works. A default-deny
/// gate that also denied everything would pass the test above and be useless.
#[tokio::test]
async fn a_classified_open_method_still_reaches_its_handler() {
    let n = TestNode::boot().await;
    let resp = n.rpc("eth_blockNumber", json!({})).await;
    assert!(
        resp.get("result").is_some(),
        "eth_blockNumber should answer, got: {resp}"
    );
    n.shutdown().await;
}

/// Admin-class methods are refused to a caller who has not signed in as the
/// operator, and the refusal is about access rather than the method not
/// existing.
#[tokio::test]
async fn an_admin_method_is_refused_to_an_anonymous_caller() {
    let n = TestNode::boot().await;
    let resp = n.rpc("tenzro_listAccessTokens", json!({})).await;
    assert_eq!(resp["error"]["code"], -32004, "got: {resp}");
    assert!(error_message(&resp).contains("operator"), "got: {resp}");
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Node DID Document
// ---------------------------------------------------------------------------

/// The well-known path answers, and answers the same thing the RPC does. Two
/// surfaces over one document is exactly where they drift apart.
#[tokio::test]
async fn the_did_document_is_consistent_across_both_surfaces() {
    let n = TestNode::boot().await;

    let over_rpc = n.rpc("tenzro_nodeDidDocument", json!({})).await;
    let over_http = n
        .client
        .get(format!("{}/.well-known/did.json", n.web_url))
        .send()
        .await;

    // A freshly-booted node has no provisioned identity, so both surfaces
    // should agree that there is nothing to publish — rather than one
    // inventing a document the other does not have.
    match over_rpc.get("result") {
        Some(doc) => {
            let http = over_http.expect("GET well-known");
            assert_eq!(http.status(), 200);
            let body: Value = http.json().await.expect("JSON");
            assert_eq!(body["id"], doc["id"], "the two surfaces must agree");
        }
        None => {
            assert_eq!(over_rpc["error"]["code"], -32404, "got: {over_rpc}");
            assert!(
                error_message(&over_rpc).contains("provisioned identity"),
                "the refusal should say why: {over_rpc}"
            );
            assert_eq!(
                over_http.expect("GET well-known").status(),
                404,
                "a node with no identity must 404 rather than serve an empty document"
            );
        }
    }
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Remote access leases
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Settlement preferences
// ---------------------------------------------------------------------------

/// Reading a preference is open, and an unconfigured payee reads back as the
/// default rather than as an error.
#[tokio::test]
async fn an_unconfigured_payee_reads_back_the_policy_default() {
    let n = TestNode::boot().await;
    let resp = n
        .rpc(
            "tenzro_getSettlementPreference",
            json!({"payee_did": "did:tenzro:machine:never-configured"}),
        )
        .await;
    assert_eq!(
        resp["result"]["asset"],
        policy_default_asset(),
        "an unconfigured payee must read back the policy default, got: {resp}"
    );
    n.shutdown().await;
}

/// Setting a preference is open — it belongs to the payee, not the node
/// operator — but it requires a signature. An unsigned attempt must fail on
/// the missing proof, not sail through.
#[tokio::test]
async fn setting_a_preference_requires_the_payees_signature() {
    let n = TestNode::boot().await;
    let resp = n
        .rpc(
            "tenzro_setSettlementPreference",
            json!({"payee_did": "did:tenzro:machine:someone-else", "asset": "tnzo"}),
        )
        .await;

    assert_ne!(
        resp["error"]["code"], -32601,
        "the method must be dispatched, got: {resp}"
    );
    let msg = error_message(&resp);
    assert!(
        msg.contains("public_key") || msg.contains("signature") || msg.contains("timestamp_ms"),
        "an unsigned change must be refused for want of proof, got: {resp}"
    );

    // And it must not have taken effect.
    let read_back = n
        .rpc(
            "tenzro_getSettlementPreference",
            json!({"payee_did": "did:tenzro:machine:someone-else"}),
        )
        .await;
    assert_eq!(
        read_back["result"]["asset"],
        policy_default_asset(),
        "a refused change must not have been applied"
    );
    n.shutdown().await;
}

/// An unrecognised asset is refused rather than silently coerced to a default.
/// Coercion here would pay someone in an asset nobody chose.
#[tokio::test]
async fn an_unknown_settlement_asset_is_refused() {
    let n = TestNode::boot().await;
    let resp = n
        .rpc(
            "tenzro_setSettlementPreference",
            json!({"payee_did": "did:tenzro:machine:x", "asset": "dogecoin"}),
        )
        .await;
    assert_eq!(resp["error"]["code"], -32602, "got: {resp}");
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Settlement preferences
// ---------------------------------------------------------------------------

/// The end-to-end case the unit tests could not reach: a real registered
/// payee, signing with the identity key their DID actually declares, changes
/// their own settlement asset.
///
/// This test is why the handler checks `public_keys` rather than
/// `wallet_address`. The wallet address is the payee's permissionless wallet, derived
/// from threshold key material unrelated to the identity key — comparing
/// against it refused every legitimate payee, and every unit test still passed.
#[tokio::test]
async fn a_real_payee_can_set_their_own_settlement_asset() {
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};

    let n = TestNode::boot().await;
    let registry = n
        .node
        .identity_registry()
        .expect("identity registry")
        .clone();

    // A payee with a real P-256 identity key, registered the ordinary way.
    let keypair = TestHybridSigner::random();
    let public_key = keypair.public_key().p256.clone();
    let registered = registry
        .register_human_via_binder(
            b"test-credential".to_vec(),
            public_key.clone(),
            "integration payee".to_string(),
        )
        .await
        .expect("register identity");
    let payee_did = registered.identity.did.to_string();

    // Sign the change with that key, over the exact preimage the node builds:
    // domain tag, then length-prefixed did / asset / timestamp.
    let timestamp_ms = chrono::Utc::now().timestamp_millis();
    let mut preimage = b"tenzro/settlement-preference/v1".to_vec();
    for field in [
        payee_did.as_bytes(),
        b"tnzo".as_slice(),
        &timestamp_ms.to_le_bytes()[..],
    ] {
        preimage.extend_from_slice(&(field.len() as u64).to_le_bytes());
        preimage.extend_from_slice(field);
    }
    let signature = keypair
        .sign(SignatureContext::AccountOwner, &preimage)
        .expect("sign");

    let resp = n
        .rpc(
            "tenzro_setSettlementPreference",
            json!({
                "payee_did": payee_did,
                "asset": "tnzo",
                "public_key": hex::encode(&public_key),
                "signature": signature,
                "timestamp_ms": timestamp_ms,
            }),
        )
        .await;

    assert!(
        resp.get("result").is_some(),
        "a payee signing with their own declared identity key must be able to \
         set their preference, got: {resp}"
    );
    assert_eq!(resp["result"]["asset"], "tnzo");

    // And it must actually have been applied, not merely accepted.
    let read_back = n
        .rpc(
            "tenzro_getSettlementPreference",
            json!({"payee_did": payee_did}),
        )
        .await;
    assert_eq!(read_back["result"]["asset"], "tnzo");

    n.shutdown().await;
}

/// The other half: someone else's key does not work, even with a
/// well-formed signature over a correct preimage. Otherwise anyone could
/// redirect any payee's earnings.
#[tokio::test]
async fn another_partys_key_cannot_change_a_payees_settlement_asset() {
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};

    let n = TestNode::boot().await;
    let registry = n
        .node
        .identity_registry()
        .expect("identity registry")
        .clone();

    let victim = TestHybridSigner::random();
    let registered = registry
        .register_human_via_binder(
            b"test-credential".to_vec(),
            victim.public_key().p256.clone(),
            "victim".to_string(),
        )
        .await
        .expect("register identity");
    let payee_did = registered.identity.did.to_string();

    // An attacker signs a perfectly valid signature — with their own key.
    let attacker = TestHybridSigner::random();
    let attacker_public_key = attacker.public_key().p256.clone();
    let timestamp_ms = chrono::Utc::now().timestamp_millis();
    let mut preimage = b"tenzro/settlement-preference/v1".to_vec();
    for field in [
        payee_did.as_bytes(),
        b"tnzo".as_slice(),
        &timestamp_ms.to_le_bytes()[..],
    ] {
        preimage.extend_from_slice(&(field.len() as u64).to_le_bytes());
        preimage.extend_from_slice(field);
    }
    let signature = attacker
        .sign(SignatureContext::AccountOwner, &preimage)
        .expect("sign");

    let resp = n
        .rpc(
            "tenzro_setSettlementPreference",
            json!({
                "payee_did": payee_did,
                "asset": "tnzo",
                "public_key": hex::encode(&attacker_public_key),
                "signature": signature,
                "timestamp_ms": timestamp_ms,
            }),
        )
        .await;

    assert_eq!(resp["error"]["code"], -32001, "got: {resp}");
    assert!(
        error_message(&resp).contains("authentication keys"),
        "the refusal should name why: {resp}"
    );

    let read_back = n
        .rpc(
            "tenzro_getSettlementPreference",
            json!({"payee_did": payee_did}),
        )
        .await;
    assert_eq!(
        read_back["result"]["asset"],
        policy_default_asset(),
        "the victim's preference must be untouched"
    );
    n.shutdown().await;
}

/// A signature that verifies but is stale must be refused, or a captured
/// change could be replayed to undo a later one.
#[tokio::test]
async fn a_stale_signed_preference_change_is_refused() {
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};

    let n = TestNode::boot().await;
    let registry = n
        .node
        .identity_registry()
        .expect("identity registry")
        .clone();

    let keypair = TestHybridSigner::random();
    let public_key = keypair.public_key().p256.clone();
    let registered = registry
        .register_human_via_binder(
            b"test-credential".to_vec(),
            public_key.clone(),
            "payee".to_string(),
        )
        .await
        .expect("register identity");
    let payee_did = registered.identity.did.to_string();

    // An hour old — well outside the ±5 minute window.
    let timestamp_ms = chrono::Utc::now().timestamp_millis() - 3_600_000;
    let mut preimage = b"tenzro/settlement-preference/v1".to_vec();
    for field in [
        payee_did.as_bytes(),
        b"tnzo".as_slice(),
        &timestamp_ms.to_le_bytes()[..],
    ] {
        preimage.extend_from_slice(&(field.len() as u64).to_le_bytes());
        preimage.extend_from_slice(field);
    }
    let signature = keypair
        .sign(SignatureContext::AccountOwner, &preimage)
        .expect("sign");

    let resp = n
        .rpc(
            "tenzro_setSettlementPreference",
            json!({
                "payee_did": payee_did,
                "asset": "tnzo",
                "public_key": hex::encode(&public_key),
                "signature": signature,
                "timestamp_ms": timestamp_ms,
            }),
        )
        .await;
    assert_eq!(resp["error"]["code"], -32602, "got: {resp}");
    assert!(error_message(&resp).contains("clock"), "got: {resp}");
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// TEE fail-closed
// ---------------------------------------------------------------------------

/// A TEE-bound ZK proof must be unobtainable on hardware with no TEE.
///
/// This is a regression test for a real defect found by running the RPC
/// against this machine: `generate_tee_zk_proof` fabricated the attestation
/// itself — empty quote, measurement derived from
/// `sha256("CODE_MEASUREMENT_<circuit>_<vendor>")`, a constant rather than a
/// hardware measurement — and the handler never checked whether a TEE existed.
/// Any anonymous caller could obtain a "TEE ZK proof" whose attestation
/// attested to nothing but was shaped like a real one.
///
/// A fresh test node has no TEE provider, so every vendor must be refused.
#[tokio::test]
async fn a_tee_bound_proof_is_refused_on_hardware_with_no_tee() {
    let n = TestNode::boot().await;
    assert!(
        n.node.tee_provider().is_none(),
        "this test is meaningless if the test node somehow has a TEE"
    );

    for vendor in ["intel-tdx", "intel-sgx", "amd-sev-snp", "aws-nitro"] {
        let resp = n
            .rpc(
                "tenzro_createTeeZkProof",
                json!({
                    "vendor": vendor,
                    "circuit_id": "settlement",
                    "witness": format!("0x{}", "11".repeat(32)),
                    "binding": format!("0x{}", "22".repeat(32)),
                }),
            )
            .await;

        assert!(
            resp.get("result").is_none(),
            "{vendor}: a proof must not be produced without an enclave, got: {resp}"
        );
        assert_eq!(resp["error"]["code"], -32001, "{vendor}: got {resp}");
        assert!(
            error_message(&resp).contains("no TEE hardware"),
            "{vendor}: the refusal should say why, got: {resp}"
        );
    }
    n.shutdown().await;
}

/// The ZK surface end to end through the JSON-RPC dispatcher: prove a
/// settlement statement in every system, verify it, and refuse the same proofs
/// against a digest whose preimage the prover does not know.
#[tokio::test]
async fn zk_proofs_verify_through_rpc_and_forgeries_do_not() {
    let n = TestNode::boot().await;

    let created = n
        .rpc(
            "tenzro_createZkProof",
            json!({
                "circuit_id": "settlement",
                "witness": format!("0x{}", "5a".repeat(32)),
                "binding": format!("0x{}", "a5".repeat(32)),
            }),
        )
        .await;
    let created = &created["result"];
    assert_eq!(
        created["proofs"].as_array().map(|a| a.len()),
        Some(3),
        "{created}"
    );

    let bundle = json!({
        "circuit_id": "settlement",
        "public_inputs": created["public_inputs"],
        "proofs": created["proofs"],
    });
    // Anyone may verify, so a bundle must fit the ordinary JSON-RPC ceiling.
    let size = serde_json::to_vec(&bundle).expect("bundle").len();
    assert!(
        size < 8 * 1024 * 1024,
        "a proof bundle of {size} bytes exceeds the RPC ceiling"
    );
    let verified = n.rpc("tenzro_verifyZkProof", bundle.clone()).await;
    assert_eq!(verified["result"]["valid"], true, "{verified}");
    assert_eq!(
        verified["result"]["meets_diverse_threshold"], true,
        "{verified}"
    );

    let mut forged = bundle.clone();
    forged["public_inputs"][0] = json!(format!("0x{}", "00".repeat(32)));
    let rejected = n.rpc("tenzro_verifyZkProof", forged).await;
    assert_eq!(rejected["result"]["valid"], false, "{rejected}");

    // The two Plonky3 legs alone share one implementation: valid, but not
    // accepted as diverse.
    let mut plonky3_only = bundle;
    let legs: Vec<Value> = plonky3_only["proofs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["system"] != "halo2-ipa-pasta")
        .cloned()
        .collect();
    assert_eq!(legs.len(), 2);
    plonky3_only["proofs"] = json!(legs);
    let partial = n.rpc("tenzro_verifyZkProof", plonky3_only).await;
    assert_eq!(partial["result"]["valid"], true, "{partial}");
    assert_eq!(
        partial["result"]["meets_diverse_threshold"], false,
        "{partial}"
    );

    let circuits = n.rpc("tenzro_listCircuits", json!({})).await;
    for c in circuits["result"]["circuits"].as_array().unwrap() {
        for s in c["proof_systems"].as_array().unwrap() {
            if s["implementation"] == "plonky3" {
                assert!(s["proven_security_bits"].as_f64().unwrap() >= 128.0, "{s}");
            } else {
                assert!(
                    s["computational_security_bits"].as_u64().unwrap() >= 126,
                    "{s}"
                );
            }
        }
    }
    n.shutdown().await;
}

/// Malformed proof requests are refused with an error and the node keeps
/// serving: an unknown circuit, a missing witness, and an identity proof
/// (whose witness is a secret a node must never receive).
#[tokio::test]
async fn a_malformed_proof_request_does_not_take_the_node_down() {
    let n = TestNode::boot().await;

    for params in [
        json!({ "vendor": "intel-tdx", "circuit_id": "inference" }),
        json!({ "vendor": "intel-tdx", "circuit_id": "settlement" }),
        json!({
            "vendor": "intel-tdx",
            "circuit_id": "identity",
            "witness": format!("0x{}", "11".repeat(32)),
            "binding": format!("0x{}", "22".repeat(32)),
        }),
    ] {
        let resp = n.rpc("tenzro_createTeeZkProof", params.clone()).await;
        assert_eq!(resp["error"]["code"], -32602, "{params}: got {resp}");
    }
    let resp = n
        .rpc(
            "tenzro_createZkProof",
            json!({
                "circuit_id": "identity",
                "witness": format!("0x{}", "11".repeat(32)),
                "binding": format!("0x{}", "22".repeat(32)),
            }),
        )
        .await;
    assert_eq!(resp["error"]["code"], -32602, "got: {resp}");

    // Still serving.
    let alive = n.rpc("eth_blockNumber", json!({})).await;
    assert!(
        alive.get("result").is_some(),
        "the node must survive a malformed proof request, got: {alive}"
    );
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Model visibility vs. the node's service-key gate
// ---------------------------------------------------------------------------
//
// A service key rents raw machine resources. It says nothing about what the
// operator is willing to serve. These tests pin the separation: a gated node
// still serves a model it published to the network, and gates everything else.
//
// Each asserts on the gate's answer (401 vs. not-401), not on the inference
// result — the models are not loaded, so a call that gets past the gate fails
// in the handler. That is the correct assertion: it isolates admission from
// serving.

// ---------------------------------------------------------------------------
// Operator lockout — both directions
// ---------------------------------------------------------------------------
//
// Found by running the real flow against a live node rather than by reading
// the code: the invariant "an operator who gates their node is not locked out
// of it by their own setting" held only for a gate enabled by config, and only
// on surfaces still behind the blanket middleware.

// ---------------------------------------------------------------------------
// Client-side signing
// ---------------------------------------------------------------------------

/// The signing payload is `Transaction::hash` of the unsigned transaction the
/// request describes, with the canonical `tx_type` encoding the digest covers,
/// so a wallet can check both before it signs.
#[tokio::test]
async fn the_signing_payload_is_the_transactions_own_digest() {
    use tenzro_types::primitives::{Address, ChainId, Nonce, Timestamp};
    let n = TestNode::boot().await;
    let resp = n
        .rpc(
            "tenzro_getSigningPayload",
            json!({
                "from": format!("0x{}", hex::encode([1u8; 32])),
                "to": format!("0x{}", hex::encode([2u8; 32])),
                "nonce": 3,
                "chain_id": 1337,
                "gas_limit": 21000,
                "gas_price": 1,
                "timestamp": 1_000,
                "valid_until": 2_000,
                "tx_type": { "Transfer": { "amount": 5 } },
            }),
        )
        .await;
    let payload = &resp["result"];
    assert_eq!(payload["kind"], "plain", "got: {resp}");
    assert_eq!(payload["tx_type_json"], r#"{"Transfer":{"amount":5}}"#);
    let tx = tenzro_types::Transaction {
        chain_id: ChainId(1337),
        from: Address::new([1u8; 32]),
        to: Address::new([2u8; 32]),
        nonce: Nonce::from(3),
        tx_type: tenzro_types::TransactionType::Transfer { amount: 5 },
        gas_limit: 21000,
        gas_price: 1,
        timestamp: Timestamp::new(1_000),
        valid_until: Timestamp::new(2_000),
        memo: None,
    };
    assert_eq!(payload["digest"], hex::encode(tx.hash().as_bytes()));
    n.shutdown().await;
}
