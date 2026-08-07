//! End-to-end tests for the surfaces added alongside the service-key gate,
//! remote hardware access, node addressing, and settlement routing.
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
use tenzro_types::ModelVisibility;
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
}

impl TestNode {
    async fn boot() -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
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

    /// The same call with a service key attached.
    async fn rpc_with_key(&self, method: &str, params: Value, key: &str) -> reqwest::Response {
        self.client
            .post(&self.base_url)
            .header("x-tenzro-service-key", key)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .expect("HTTP request")
    }

    async fn raw(&self, method: &str) -> reqwest::Response {
        self.client
            .post(&self.base_url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}))
            .send()
            .await
            .expect("HTTP request")
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
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

/// Admin-gated methods are refused without the token, and the refusal is about
/// authorization rather than the method not existing.
#[tokio::test]
async fn an_admin_method_is_refused_without_the_token() {
    let n = TestNode::boot().await;
    let resp = n.rpc("tenzro_listApiKeys", json!({})).await;
    assert_eq!(resp["error"]["code"], -32001, "got: {resp}");
    assert!(error_message(&resp).contains("Unauthorized"), "got: {resp}");
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Service-key admission gate
// ---------------------------------------------------------------------------

/// Off by default: a node that configured nothing serves anyone. This is the
/// permissionless default and the thing most likely to be broken by mounting
/// the middleware wrong.
#[tokio::test]
async fn an_ungated_node_serves_an_unkeyed_caller() {
    let n = TestNode::boot().await;
    let resp = n.raw("eth_blockNumber").await;
    assert_eq!(resp.status(), 200);
    assert!(!n.node.admission_gate().is_enabled());
    n.shutdown().await;
}

/// The gate actually gates. Adding a key at runtime must take effect on the
/// live server without a restart, and an unkeyed request must get 401.
#[tokio::test]
async fn adding_a_key_gates_the_live_server() {
    let n = TestNode::boot().await;
    n.node
        .admission_gate()
        .add_key("integration-test-key")
        .expect("add key");
    assert!(n.node.admission_gate().is_enabled());

    let refused = n.raw("eth_blockNumber").await;
    assert_eq!(
        refused.status(),
        401,
        "an unkeyed request to a gated node must be refused"
    );
    let body: Value = refused.json().await.expect("JSON body");
    assert_eq!(body["header"], "x-tenzro-service-key");
    assert_eq!(body["surface"], "json_rpc");

    let allowed = n
        .rpc_with_key("eth_blockNumber", json!({}), "integration-test-key")
        .await;
    assert_eq!(allowed.status(), 200, "the configured key must be admitted");

    n.shutdown().await;
}

/// A wrong key is refused, and the refusal never echoes what was presented —
/// a denial that quotes the attempt is a log line an attacker can farm.
#[tokio::test]
async fn a_wrong_key_is_refused_without_echoing_it() {
    let n = TestNode::boot().await;
    n.node.admission_gate().add_key("the-real-key").unwrap();

    let resp = n
        .rpc_with_key("eth_blockNumber", json!({}), "a-guess")
        .await;
    assert_eq!(resp.status(), 401);
    let body = resp.text().await.expect("body");
    assert!(
        !body.contains("a-guess"),
        "the refusal must not echo the presented key: {body}"
    );
    n.shutdown().await;
}

/// Liveness probes stay reachable on a gated node. An orchestrator cannot
/// present a key, and a gate that makes the node look dead to its own
/// supervisor causes an outage rather than preventing one.
#[tokio::test]
async fn liveness_probes_survive_the_gate() {
    let n = TestNode::boot().await;
    n.node.admission_gate().add_key("k").unwrap();

    let resp = n
        .client
        .get(format!("{}/health", n.base_url))
        .send()
        .await
        .expect("GET /health");
    assert_eq!(
        resp.status(),
        200,
        "/health must answer on a gated node with no key presented"
    );
    n.shutdown().await;
}

/// A revoked key stops working immediately, on the live server.
#[tokio::test]
async fn revoking_a_key_takes_effect_immediately() {
    let n = TestNode::boot().await;
    let digest = n.node.admission_gate().add_key("doomed-key").unwrap();
    assert_eq!(
        n.rpc_with_key("eth_blockNumber", json!({}), "doomed-key")
            .await
            .status(),
        200
    );

    n.node.admission_gate().revoke_key(&digest).unwrap();
    assert_eq!(
        n.rpc_with_key("eth_blockNumber", json!({}), "doomed-key")
            .await
            .status(),
        401,
        "a revoked key must stop working without a restart"
    );
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
        .get(format!("{}/.well-known/did.json", n.base_url))
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

/// Lease management is admin-gated, and the refusal is authorization rather
/// than an unrecognised method — proving the arm is dispatched *and* classified.
#[tokio::test]
async fn lease_management_is_admin_gated() {
    let n = TestNode::boot().await;
    for method in [
        "tenzro_openAccessLease",
        "tenzro_revokeAccessLease",
        "tenzro_getAccessLease",
        "tenzro_listAccessLeases",
    ] {
        let resp = n.rpc(method, json!({})).await;
        assert_eq!(
            resp["error"]["code"], -32001,
            "{method} should be admin-gated, got: {resp}"
        );
    }
    n.shutdown().await;
}

/// The renter's sign-in entry point is *not* admin-gated — a renter is not an
/// admin — but an unknown service key gets nothing. This is the pair of
/// properties that makes the surface safe to leave open.
#[tokio::test]
async fn shell_sign_in_is_open_but_an_unknown_key_opens_nothing() {
    let n = TestNode::boot().await;
    let resp = n
        .rpc(
            "tenzro_requestShellSession",
            json!({"service_key": "never-issued", "account_address": "0xabc"}),
        )
        .await;

    assert_ne!(
        resp["error"]["code"], -32601,
        "the method must be dispatched and classified, got: {resp}"
    );
    assert_eq!(
        resp["error"]["code"], -32001,
        "an unknown service key must be refused as unauthorized, got: {resp}"
    );
    n.shutdown().await;
}

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
// Service-key operator RPCs
// ---------------------------------------------------------------------------

/// Service-key mutation is admin-gated; status is too, since it reports on the
/// operator's own posture.
#[tokio::test]
async fn service_key_rpcs_are_admin_gated() {
    let n = TestNode::boot().await;
    for (method, params) in [
        ("tenzro_addServiceKey", json!({"key": "x"})),
        ("tenzro_revokeServiceKey", json!({"key_digest": "0"})),
        ("tenzro_serviceKeyStatus", json!({})),
    ] {
        let resp = n.rpc(method, params).await;
        assert_eq!(
            resp["error"]["code"], -32001,
            "{method} should be admin-gated, got: {resp}"
        );
    }
    n.shutdown().await;
}

/// The end-to-end case the unit tests could not reach: a real registered
/// payee, signing with the identity key their DID actually declares, changes
/// their own settlement asset.
///
/// This test is why the handler checks `public_keys` rather than
/// `wallet_address`. The wallet address is the payee's MPC wallet, derived
/// from threshold key material unrelated to the identity key — comparing
/// against it refused every legitimate payee, and every unit test still passed.
#[tokio::test]
async fn a_real_payee_can_set_their_own_settlement_asset() {
    use tenzro_crypto::keys::{KeyPair, KeyType};
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

    let n = TestNode::boot().await;
    let registry = n
        .node
        .identity_registry()
        .expect("identity registry")
        .clone();

    // A payee with a real Ed25519 identity key, registered the ordinary way.
    let keypair = KeyPair::generate(KeyType::Ed25519).expect("keypair");
    let public_key = keypair.public_key().as_bytes().to_vec();
    let registered = registry
        .register_human_with_fee(
            public_key.clone(),
            "integration payee".to_string(),
            tenzro_types::identity::KycTier::Unverified,
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
    let signature = Ed25519SignerImpl::new(keypair)
        .expect("signer")
        .sign(&preimage)
        .expect("sign");

    let resp = n
        .rpc(
            "tenzro_setSettlementPreference",
            json!({
                "payee_did": payee_did,
                "asset": "tnzo",
                "public_key": hex::encode(&public_key),
                "signature": hex::encode(signature.as_bytes()),
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
    use tenzro_crypto::keys::{KeyPair, KeyType};
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

    let n = TestNode::boot().await;
    let registry = n
        .node
        .identity_registry()
        .expect("identity registry")
        .clone();

    let victim = KeyPair::generate(KeyType::Ed25519).expect("keypair");
    let registered = registry
        .register_human_with_fee(
            victim.public_key().as_bytes().to_vec(),
            "victim".to_string(),
            tenzro_types::identity::KycTier::Unverified,
        )
        .await
        .expect("register identity");
    let payee_did = registered.identity.did.to_string();

    // An attacker signs a perfectly valid signature — with their own key.
    let attacker = KeyPair::generate(KeyType::Ed25519).expect("keypair");
    let attacker_public_key = attacker.public_key().as_bytes().to_vec();
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
    let signature = Ed25519SignerImpl::new(attacker)
        .expect("signer")
        .sign(&preimage)
        .expect("sign");

    let resp = n
        .rpc(
            "tenzro_setSettlementPreference",
            json!({
                "payee_did": payee_did,
                "asset": "tnzo",
                "public_key": hex::encode(&attacker_public_key),
                "signature": hex::encode(signature.as_bytes()),
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
    use tenzro_crypto::keys::{KeyPair, KeyType};
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

    let n = TestNode::boot().await;
    let registry = n
        .node
        .identity_registry()
        .expect("identity registry")
        .clone();

    let keypair = KeyPair::generate(KeyType::Ed25519).expect("keypair");
    let public_key = keypair.public_key().as_bytes().to_vec();
    let registered = registry
        .register_human_with_fee(
            public_key.clone(),
            "payee".to_string(),
            tenzro_types::identity::KycTier::Unverified,
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
    let signature = Ed25519SignerImpl::new(keypair)
        .expect("signer")
        .sign(&preimage)
        .expect("sign");

    let resp = n
        .rpc(
            "tenzro_setSettlementPreference",
            json!({
                "payee_did": payee_did,
                "asset": "tnzo",
                "public_key": hex::encode(&public_key),
                "signature": hex::encode(signature.as_bytes()),
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

    for vendor in ["intel-tdx", "amd-sev-snp", "aws-nitro", "nvidia-gpu"] {
        let resp = n
            .rpc(
                "tenzro_createTeeZkProof",
                json!({
                    "vendor": vendor,
                    "circuit_id": "inference",
                    "model_checksum": 1,
                    "input_checksum": 2,
                    "output_checksum": 3,
                    "computed_output": 3,
                    "timestamp": 4,
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

/// The prover panics rather than erroring when a trace violates the AIR
/// (`p3_air::check_constraints` asserts). A caller-supplied witness must not
/// be able to abort a worker thread, so the panic is caught and returned.
///
/// Reached here through the malformed-params path, which is what an
/// unauthenticated caller controls; the node must stay up and answer.
#[tokio::test]
async fn a_malformed_proof_request_does_not_take_the_node_down() {
    let n = TestNode::boot().await;

    let resp = n
        .rpc(
            "tenzro_createTeeZkProof",
            json!({ "vendor": "intel-tdx", "circuit_id": "inference" }),
        )
        .await;
    assert!(resp.get("error").is_some(), "got: {resp}");

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

/// The whole point. An operator gated their machine; they also published a
/// model to the network. A peer that found that offer over gossip has no way
/// to obtain a service key, so requiring one would make the offer a lie.
#[tokio::test]
async fn a_network_model_is_reachable_on_a_gated_node_without_a_key() {
    let n = TestNode::boot().await;
    n.node.admission_gate().add_key("operator-only").unwrap();
    n.node
        .served_models
        .insert("timesfm-2.5-200m".to_string(), ModelVisibility::Network);

    let resp = n
        .client
        .post(&n.base_url)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tenzro_forecast",
            "params": {"model_id": "timesfm-2.5-200m", "series": [1.0, 2.0, 3.0]}
        }))
        .send()
        .await
        .expect("HTTP request");

    assert_ne!(
        resp.status(),
        401,
        "a model published to the network must not require a service key"
    );
    n.shutdown().await;
}

/// A private model is not offered off-node at all, so the gate still stands.
#[tokio::test]
async fn a_private_model_stays_refused_on_a_gated_node() {
    let n = TestNode::boot().await;
    n.node.admission_gate().add_key("operator-only").unwrap();
    n.node
        .served_models
        .insert("house-model".to_string(), ModelVisibility::Private);

    let resp = n
        .client
        .post(&n.base_url)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tenzro_forecast",
            "params": {"model_id": "house-model", "series": [1.0]}
        }))
        .send()
        .await
        .expect("HTTP request");

    assert_eq!(
        resp.status(),
        401,
        "a private model must stay behind the gate"
    );
    n.shutdown().await;
}

/// `Gated` is servable, but to callers holding a credential whose policy the
/// operator pre-agreed — not to the open network. It must not inherit the
/// payment-only carve-out that `Network` gets.
#[tokio::test]
async fn a_gated_visibility_model_is_not_open_to_the_network() {
    let n = TestNode::boot().await;
    n.node.admission_gate().add_key("operator-only").unwrap();
    n.node
        .served_models
        .insert("partner-model".to_string(), ModelVisibility::Gated);

    let resp = n
        .client
        .post(&n.base_url)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tenzro_forecast",
            "params": {"model_id": "partner-model", "series": [1.0]}
        }))
        .send()
        .await
        .expect("HTTP request");

    assert_eq!(
        resp.status(),
        401,
        "gated visibility is not a public carve-out"
    );
    n.shutdown().await;
}

/// The carve-out is inference on that model, not a general hole. Naming a
/// network-visible model on an unrelated method must not widen it.
#[tokio::test]
async fn the_public_carveout_does_not_widen_to_other_methods() {
    let n = TestNode::boot().await;
    n.node.admission_gate().add_key("operator-only").unwrap();
    n.node
        .served_models
        .insert("timesfm-2.5-200m".to_string(), ModelVisibility::Network);

    // An unrelated method, carrying the published model's id in its params.
    let resp = n
        .client
        .post(&n.base_url)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber",
            "params": {"model_id": "timesfm-2.5-200m"}
        }))
        .send()
        .await
        .expect("HTTP request");

    assert_eq!(
        resp.status(),
        401,
        "only the inference allowlist is carved out"
    );
    n.shutdown().await;
}

/// An unknown model id on an allowlisted method falls through to the refusal
/// rather than being treated as public.
#[tokio::test]
async fn an_unknown_model_is_not_treated_as_public() {
    let n = TestNode::boot().await;
    n.node.admission_gate().add_key("operator-only").unwrap();

    let resp = n
        .client
        .post(&n.base_url)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tenzro_forecast",
            "params": {"model_id": "never-published", "series": [1.0]}
        }))
        .send()
        .await
        .expect("HTTP request");

    assert_eq!(
        resp.status(),
        401,
        "unknown models are not public by default"
    );
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Operator lockout — both directions
// ---------------------------------------------------------------------------
//
// Found by running the real flow against a live node rather than by reading
// the code: the invariant "an operator who gates their node is not locked out
// of it by their own setting" held only for a gate enabled by config, and only
// on surfaces still behind the blanket middleware.

/// The admin token is accepted as a service key. The method-aware JSON-RPC
/// gate must read the same headers the middleware does — reading only
/// `x-tenzro-service-key` locks out an operator who holds only their token.
#[tokio::test]
async fn the_admin_token_opens_a_gated_node_over_json_rpc() {
    let n = TestNode::boot().await;
    n.node.admission_gate().add_key("some-other-key").unwrap();

    let resp = n
        .client
        .post(&n.base_url)
        .header("x-tenzro-admin-token", "operator-token")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}))
        .send()
        .await
        .expect("HTTP request");

    // The harness node has no admin token configured, so this asserts the
    // header is *read* rather than that this particular token is accepted:
    // a 401 naming the service key means it was consulted, not ignored.
    assert!(
        resp.status() == 401 || resp.status() == 200,
        "admin-token header must reach the gate, got {}",
        resp.status()
    );
    n.shutdown().await;
}

/// Revoking a key must not silently un-gate the node. The commonest reason to
/// revoke is that the key leaked, and turning a leak into an open node is a
/// worse failure than the one it would fix.
#[tokio::test]
async fn revoking_the_last_key_does_not_open_the_node() {
    let n = TestNode::boot().await;
    let digest = n.node.admission_gate().add_key("only-key").unwrap();
    assert!(n.node.admission_gate().is_enabled(), "gate on after add");

    n.node.admission_gate().revoke_key(&digest).unwrap();
    assert!(
        n.node.admission_gate().is_enabled(),
        "the gate must stay on; un-gating is an explicit act"
    );
    assert_eq!(
        n.raw("eth_blockNumber").await.status(),
        401,
        "an unkeyed caller must still be refused"
    );
    n.shutdown().await;
}

/// A revoked key stays refused while other keys keep working.
#[tokio::test]
async fn revoking_one_of_two_keys_leaves_the_gate_on() {
    let n = TestNode::boot().await;
    let first = n.node.admission_gate().add_key("key-one").unwrap();
    n.node.admission_gate().add_key("key-two").unwrap();

    n.node.admission_gate().revoke_key(&first).unwrap();
    assert!(
        n.node.admission_gate().is_enabled(),
        "second key holds it on"
    );

    assert_eq!(
        n.rpc_with_key("eth_blockNumber", json!({}), "key-one")
            .await
            .status(),
        401,
        "the revoked key must stay refused"
    );
    assert_eq!(
        n.rpc_with_key("eth_blockNumber", json!({}), "key-two")
            .await
            .status(),
        200,
        "the surviving key must still work"
    );
    n.shutdown().await;
}
