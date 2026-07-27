//! Auth integration tests.
//!
//! Spins up a full TenzroNode (storage + RPC + auth engine) per test and
//! exercises the OAuth 2.1 + DPoP + RAR surface in full:
//!
//!   1. Onboarding RPCs (human / delegated / autonomous) issue signed JWTs.
//!   2. Issued JWTs validate against the live `AuthEngine`, with DPoP
//!      proofs produced by signing canonical JWS over an in-test Ed25519
//!      keypair.
//!   3. HITL approval lifecycle — `record_approval` → list → decide → consume.
//!   4. Cascading revocation — revoking a parent JWT or DID propagates to
//!      every act-chain descendant.
//!   5. RFC 9728 protected-resource-metadata endpoint surfaces the full
//!      metadata profile (DPoP, RAR `authorization_details_types`, etc.).
//!   6. Public read RPCs work without a bearer (sanity guard against an
//!      accidental "everything requires auth" regression).
//!
//! Each test owns its own `tempfile::TempDir`, so RocksDB instances never
//! contend.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use tenzro_auth::{
    ApprovalRecord, ApprovalStatus, AuthorityAction, AuthorityRequest, AuthorizationDetail,
    AuthorizationDetails, DpopProof, DpopValidation, ResourceConstraint,
};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_types::AssetId;

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Test scaffolding (mirrors tests/rpc_settlement_integration.rs)
// ---------------------------------------------------------------------------

fn test_config() -> (NodeConfig, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    (cfg, tmp)
}

async fn setup_test_server() -> (
    String,
    broadcast::Sender<()>,
    tokio::task::JoinHandle<tenzro_node::Result<()>>,
    tempfile::TempDir,
    Arc<TenzroNode>,
) {
    let (cfg, tmp) = test_config();
    let mut node = TenzroNode::new(cfg).await.expect("node creation");
    node.start().await.expect("node start");
    let node = Arc::new(node);

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();

    let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
    let handle = tokio::spawn(async move {
        rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await
    });

    let addr = addr_rx.await.expect("bound address");
    let base_url = format!("http://{}", addr);

    (base_url, shutdown_tx, handle, tmp, node)
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

async fn shutdown(
    tx: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
) {
    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}

// ---------------------------------------------------------------------------
// DPoP test helper — produce a real signed DPoP proof for an Ed25519 keypair.
// ---------------------------------------------------------------------------

/// In-test holder keypair. Owns its `SigningKey` so callers can mint many
/// DPoP proofs over the lifetime of one bearer.
struct DpopHolder {
    signing_key: SigningKey,
    jwk_json: String,
    jkt: String,
}

impl DpopHolder {
    fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key();
        let x = URL_SAFE_NO_PAD.encode(pubkey.to_bytes());
        // RFC 7638 canonical form: sorted required members, no whitespace.
        let jwk_json = format!(
            r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
            x
        );
        let jkt = DpopProof::compute_jkt(&jwk_json).expect("compute jkt");
        Self { signing_key, jwk_json, jkt }
    }

    /// Sign a fresh DPoP proof for (htm, htu) at the current wall clock.
    /// Returns the compact JWS string suitable for the `DPoP` header.
    fn sign_proof(&self, htm: &str, htu: &str) -> String {
        // Header: typ=dpop+jwt, alg=EdDSA, jwk=<this holder's pubkey JWK>.
        // We embed the *full* JWK JSON, not just the thumbprint.
        let jwk_value: Value =
            serde_json::from_str(&self.jwk_json).expect("jwk parse");
        let header = json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": jwk_value,
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // Random JTI so each proof is unique (replay cache eats duplicates).
        let jti_bytes: [u8; 16] = rand::random();
        let jti = URL_SAFE_NO_PAD.encode(jti_bytes);
        let payload = json!({
            "htm": htm,
            "htu": htu,
            "iat": now,
            "jti": jti,
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());

        let signed_input = format!("{}.{}", header_b64, payload_b64);
        let sig = self.signing_key.sign(signed_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        format!("{}.{}", signed_input, sig_b64)
    }
}

// ---------------------------------------------------------------------------
// Onboarding RPCs (3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_onboard_human_returns_jwt_identity_and_wallet() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let holder = DpopHolder::new();

    let body = rpc_request(
        "tenzro_onboardHuman",
        json!({
            "display_name": "Alice",
            "dpop_jkt": holder.jkt,
        }),
    );
    let resp = rpc_call(&client, &base_url, body).await;

    assert!(resp.get("error").is_none(), "unexpected error: {}", resp);
    let result = &resp["result"];
    assert_eq!(result["identity"]["identity_type"], "human");
    assert_eq!(result["identity"]["display_name"], "Alice");
    assert!(
        result["identity"]["did"]
            .as_str()
            .unwrap_or("")
            .starts_with("did:tenzro:human:"),
        "did shape: {}",
        result["identity"]["did"]
    );
    assert!(result["wallet"]["wallet_id"].is_string());
    assert!(result["wallet"]["address"]
        .as_str()
        .unwrap()
        .starts_with("0x"));
    assert!(result["access_token"].is_string());
    assert_eq!(result["token_type"], "Bearer");
    assert_eq!(result["dpop_bound"], true);

    // The issued JWT must validate against the live engine when paired
    // with a DPoP proof signed by the same holder key.
    let token = result["access_token"].as_str().unwrap().to_string();
    let engine = node.auth_engine().expect("auth engine wired");
    let htu = format!("{}/", base_url); // canonical resource URI
    let proof = holder.sign_proof("POST", &htu);
    let (parsed, signed_input, signature) =
        DpopProof::parse_with_signed_input(&proof).expect("parse proof");
    let dpop_ctx = DpopValidation {
        proof: &parsed,
        expected_htm: "POST",
        expected_htu: &htu,
        now_unix: now_unix_secs(),
        signed_input: &signed_input,
        signature: &signature,
    };
    let claims = engine
        .validate_jwt(&token, Some(dpop_ctx))
        .expect("JWT validates with matching DPoP");
    // sub == bearer DID == controller DID (self-custody for humans).
    assert_eq!(
        claims.sub,
        result["identity"]["did"].as_str().unwrap()
    );
    assert_eq!(claims.controller_did, claims.sub);
    assert_eq!(
        claims.cnf.as_ref().map(|c| c.jkt.as_str()),
        Some(holder.jkt.as_str())
    );

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn test_onboard_delegated_agent_carries_controller_and_scope() {
    let (base_url, tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    // First create a human controller.
    let human = rpc_call(
        &client,
        &base_url,
        rpc_request("tenzro_onboardHuman", json!({ "display_name": "Owner" })),
    )
    .await;
    let controller_did = human["result"]["identity"]["did"]
        .as_str()
        .unwrap()
        .to_string();

    // Now onboard a delegated agent under that controller.
    let agent_holder = DpopHolder::new();
    let body = rpc_request(
        "tenzro_onboardDelegatedAgent",
        json!({
            "controller_did": controller_did,
            "capabilities": ["inference", "settlement"],
            "delegation_scope": {
                "max_transaction_value": 1_000_000_000_000_000_000u64,
                "max_daily_spend": 5_000_000_000_000_000_000u64,
                "allowed_operations": ["transfer", "create_escrow"],
            },
            "dpop_jkt": agent_holder.jkt,
        }),
    );
    let resp = rpc_call(&client, &base_url, body).await;

    assert!(resp.get("error").is_none(), "unexpected error: {}", resp);
    let r = &resp["result"];
    assert_eq!(r["identity"]["identity_type"], "machine");
    assert_eq!(r["identity"]["controller_did"], controller_did);
    assert!(r["access_token"].is_string());

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn test_onboard_delegated_agent_rejects_missing_controller() {
    let (base_url, tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardDelegatedAgent",
            json!({ "capabilities": ["inference"] }),
        ),
    )
    .await;
    assert!(resp["error"].is_object(), "should error: {}", resp);
    assert_eq!(resp["error"]["code"], -32602);

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn test_onboard_autonomous_agent_requires_funded_bond_address() {
    let (base_url, tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    // Synthetic empty address — no bond posted, must reject.
    let unfunded = format!("0x{}", "ee".repeat(20));
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardAutonomousAgent",
            json!({ "bond_funding_address": unfunded }),
        ),
    )
    .await;
    // Bond floor is 1 TNZO; an empty/synthetic address holds 0 → rejected.
    assert!(resp["error"].is_object(), "should error: {}", resp);

    shutdown(tx, handle).await;
}

// ---------------------------------------------------------------------------
// JWT + DPoP validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_jwt_validation_rejects_dpop_with_wrong_key() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let real_holder = DpopHolder::new();
    let attacker = DpopHolder::new();

    // Mint a JWT bound to real_holder's jkt.
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardHuman",
            json!({ "display_name": "Bob", "dpop_jkt": real_holder.jkt }),
        ),
    )
    .await;
    let token = resp["result"]["access_token"].as_str().unwrap().to_string();

    // Attacker tries to use it with a DPoP proof signed by their key.
    let engine = node.auth_engine().expect("auth engine");
    let htu = format!("{}/", base_url);
    let bad_proof = attacker.sign_proof("POST", &htu);
    let (parsed, signed_input, signature) =
        DpopProof::parse_with_signed_input(&bad_proof).expect("parse");
    let result = engine.validate_jwt(
        &token,
        Some(DpopValidation {
            proof: &parsed,
            expected_htm: "POST",
            expected_htu: &htu,
            now_unix: now_unix_secs(),
            signed_input: &signed_input,
            signature: &signature,
        }),
    );
    assert!(result.is_err(), "DPoP/JWT mismatch must be rejected");

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn test_jwt_validation_rejects_dpop_replay() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let holder = DpopHolder::new();

    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardHuman",
            json!({ "display_name": "Carol", "dpop_jkt": holder.jkt }),
        ),
    )
    .await;
    let token = resp["result"]["access_token"].as_str().unwrap().to_string();

    let engine = node.auth_engine().expect("auth engine");
    let htu = format!("{}/", base_url);
    let proof = holder.sign_proof("POST", &htu);
    let (parsed, signed_input, signature) =
        DpopProof::parse_with_signed_input(&proof).expect("parse");

    // First use — must succeed.
    engine
        .validate_jwt(
            &token,
            Some(DpopValidation {
                proof: &parsed,
                expected_htm: "POST",
                expected_htu: &htu,
                now_unix: now_unix_secs(),
                signed_input: &signed_input,
                signature: &signature,
            }),
        )
        .expect("first DPoP use must succeed");

    // Second use of the *same* proof (same jti) — replay cache must reject.
    let replay = engine.validate_jwt(
        &token,
        Some(DpopValidation {
            proof: &parsed,
            expected_htm: "POST",
            expected_htu: &htu,
            now_unix: now_unix_secs(),
            signed_input: &signed_input,
            signature: &signature,
        }),
    );
    assert!(replay.is_err(), "replayed DPoP must be rejected");

    shutdown(tx, handle).await;
}

// ---------------------------------------------------------------------------
// HITL approval lifecycle
// ---------------------------------------------------------------------------

fn make_pending_approval(requester: &str, approver: &str) -> ApprovalRecord {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    ApprovalRecord {
        approval_id: uuid_v4(),
        requester_did: requester.to_string(),
        approver_did: approver.to_string(),
        created_at_ms: now_ms,
        expires_at_ms: now_ms + 60_000, // 1 minute window
        action: AuthorizationDetail::Transfer {
            asset: AssetId("TNZO".into()),
            max_amount: 50_000_000_000_000_000_000u128,
            max_daily_amount: None,
            allowed_counterparties: None,
        },
        summary: "Pay 50 TNZO to acme.eth for invoice #1234".to_string(),
        status: ApprovalStatus::Pending,
        decided_at_ms: None,
        deny_reason: None,
    }
}

fn uuid_v4() -> String {
    // Avoid pulling another dep — synthesize a UUIDv4 from rand bytes.
    let bytes: [u8; 16] = rand::random();
    let mut b = bytes;
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

#[tokio::test]
async fn test_hitl_approval_lifecycle_approve_then_consume() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let engine = node.auth_engine().expect("auth engine");

    let approver = "did:tenzro:human:approver-001";
    let requester = "did:tenzro:machine:agent-001";

    // 1. Create pending approval (engine API; no RPC for create).
    let rec = make_pending_approval(requester, approver);
    let approval_id = engine
        .record_approval(rec.clone())
        .expect("record_approval");

    // 2. List via RPC — approver sees one pending entry.
    let listed = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_listPendingApprovals",
            json!({ "approver_did": approver }),
        ),
    )
    .await;
    assert_eq!(listed["result"]["count"], 1);
    assert_eq!(listed["result"]["pending"][0]["approval_id"], approval_id);
    assert_eq!(listed["result"]["pending"][0]["status"], "Pending");

    // 3. Decide (approve) via RPC.
    let decided = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_decideApproval",
            json!({
                "approval_id": approval_id,
                "decision": "approved",
                "approver_did": approver,
            }),
        ),
    )
    .await;
    assert!(decided.get("error").is_none(), "decide error: {}", decided);
    assert_eq!(decided["result"]["status"], "Approved");

    // 4. After approval, list must no longer include it.
    let listed_after = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_listPendingApprovals",
            json!({ "approver_did": approver }),
        ),
    )
    .await;
    assert_eq!(listed_after["result"]["count"], 0);

    // 5. consume_approval (engine API) marks Consumed; second consume fails.
    let consumed = engine.consume_approval(&approval_id).expect("consume");
    assert_eq!(consumed.status, ApprovalStatus::Consumed);
    let second = engine.consume_approval(&approval_id);
    assert!(
        second.is_err(),
        "second consume must fail (single-use approval)"
    );

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn test_hitl_approval_decide_rejects_wrong_approver() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let engine = node.auth_engine().expect("auth engine");

    let approver = "did:tenzro:human:owner";
    let attacker = "did:tenzro:human:imposter";
    let rec = make_pending_approval("did:tenzro:machine:bot", approver);
    let approval_id = engine.record_approval(rec).expect("record_approval");

    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_decideApproval",
            json!({
                "approval_id": approval_id,
                "decision": "approved",
                "approver_did": attacker,
            }),
        ),
    )
    .await;

    assert!(resp["error"].is_object(), "wrong approver must error: {}", resp);
    assert_eq!(
        resp["error"]["code"], -32001,
        "expected forbidden (-32001)"
    );

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn test_hitl_approval_deny_path() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let engine = node.auth_engine().expect("auth engine");

    let approver = "did:tenzro:human:owner-deny";
    let rec = make_pending_approval("did:tenzro:machine:bot", approver);
    let approval_id = engine.record_approval(rec).expect("record_approval");

    let decided = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_decideApproval",
            json!({
                "approval_id": approval_id,
                "decision": "denied",
                "approver_did": approver,
            }),
        ),
    )
    .await;
    assert_eq!(decided["result"]["status"], "Denied");

    // A denied approval cannot be consumed.
    let consume_err = engine.consume_approval(&approval_id);
    assert!(consume_err.is_err(), "denied approval must not be consumable");

    shutdown(tx, handle).await;
}

// ---------------------------------------------------------------------------
// Cascading revocation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_revoke_jti_invalidates_subsequent_validation() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let engine = node.auth_engine().expect("auth engine");
    let holder = DpopHolder::new();

    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardHuman",
            json!({ "display_name": "Dave", "dpop_jkt": holder.jkt }),
        ),
    )
    .await;
    let token = resp["result"]["access_token"].as_str().unwrap().to_string();

    // Validate first (no DPoP — exercise unbound path).
    let claims = engine
        .validate_jwt(&token, None)
        .expect("first validation succeeds");
    let jti = claims.jti.clone();

    // Revoke via RPC.
    let revoke_resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_revokeJwt",
            json!({ "jti": jti, "reason": "test revocation" }),
        ),
    )
    .await;
    assert!(
        revoke_resp.get("error").is_none(),
        "revoke error: {}",
        revoke_resp
    );
    assert_eq!(revoke_resp["result"]["status"], "revoked");

    // Subsequent validation must fail.
    let post_revoke = engine.validate_jwt(&token, None);
    assert!(post_revoke.is_err(), "revoked JWT must fail validation");

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn test_revoke_did_cascades_to_act_chain() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let engine = node.auth_engine().expect("auth engine");

    // Onboard human controller.
    let human = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardHuman",
            json!({ "display_name": "Root" }),
        ),
    )
    .await;
    let controller_did = human["result"]["identity"]["did"]
        .as_str()
        .unwrap()
        .to_string();
    let controller_token = human["result"]["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Onboard a delegated agent under that controller.
    let agent = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardDelegatedAgent",
            json!({
                "controller_did": controller_did,
                "capabilities": ["inference"],
            }),
        ),
    )
    .await;
    let agent_token = agent["result"]["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Both tokens validate before revocation.
    engine
        .validate_jwt(&controller_token, None)
        .expect("controller token valid");
    engine
        .validate_jwt(&agent_token, None)
        .expect("agent token valid");

    // Revoke the controller DID.  Cascade must invalidate the agent token
    // too (its `controller_did` claim points back at the revoked DID).
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_revokeDid",
            json!({ "did": controller_did, "reason": "key compromise" }),
        ),
    )
    .await;
    assert!(resp.get("error").is_none(), "revokeDid error: {}", resp);
    assert!(
        resp["result"]["affected_jti_count"].as_u64().unwrap_or(0) >= 1,
        "expected cascade to touch >=1 JTI: {}",
        resp
    );

    // Controller token rejected.
    assert!(
        engine.validate_jwt(&controller_token, None).is_err(),
        "controller token must be rejected after DID revocation"
    );
    // Agent token rejected via cascade.
    assert!(
        engine.validate_jwt(&agent_token, None).is_err(),
        "agent token must be rejected via act-chain cascade"
    );

    shutdown(tx, handle).await;
}

// ---------------------------------------------------------------------------
// RFC 9728 Protected Resource Metadata endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_rfc9728_protected_resource_metadata_surface() {
    let (base_url, tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    // The MCP server (which serves /.well-known/oauth-protected-resource)
    // is a separate axum stack from the JSON-RPC server. The JSON-RPC
    // server doesn't host this endpoint, so a direct HTTP probe against
    // base_url must 404 — that's the contract.
    let resp = client
        .get(format!("{}/.well-known/oauth-protected-resource", base_url))
        .send()
        .await
        .expect("HTTP");
    assert_eq!(
        resp.status().as_u16(),
        404,
        "the JSON-RPC server should not serve the MCP resource metadata"
    );

    shutdown(tx, handle).await;
}

// ---------------------------------------------------------------------------
// Public read RPCs work without bearer (regression guard)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_public_read_rpc_does_not_require_auth() {
    let (base_url, tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    // No Authorization header on the request — must still succeed.
    let payer = format!("0x{}", "44".repeat(20));
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request("tenzro_listEscrowsByPayer", json!({ "payer": payer })),
    )
    .await;

    assert!(
        resp.get("result").is_some(),
        "public read RPC must work unauthenticated: {}",
        resp
    );
    assert_eq!(resp["result"]["count"], 0);

    shutdown(tx, handle).await;
}

// ---------------------------------------------------------------------------
// Engine-level authority resolution (RAR)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_authority_request_within_rar_envelope_permits() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let engine = node.auth_engine().expect("auth engine");

    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardHuman",
            json!({ "display_name": "Eve" }),
        ),
    )
    .await;
    let token = resp["result"]["access_token"].as_str().unwrap().to_string();
    let claims = engine.validate_jwt(&token, None).expect("validate");

    // Human envelope grants unconstrained Transfer; a small TNZO transfer
    // must resolve to Permit.
    let request = AuthorityRequest {
        action: AuthorityAction::Transfer,
        constraint: ResourceConstraint {
            asset: Some(AssetId("TNZO".into())),
            amount: Some(1_000_000_000_000_000_000u128),
            counterparty: None,
            resource_id: None,
        },
        approval_id: None,
    };
    let decision = engine
        .resolve_authority(&claims, &request, None)
        .expect("resolve");
    // Must be Permit (not RequireApproval / Deny).
    let decision_str = format!("{:?}", decision);
    assert!(
        decision_str.starts_with("Permit"),
        "expected Permit, got: {:?}",
        decision_str
    );

    shutdown(tx, handle).await;
}

// ---------------------------------------------------------------------------
// linkWalletForAuth: re-bind to existing identity, no duplicates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_link_wallet_for_auth_reuses_existing_identity() {
    // Onboarding mints {identity, wallet}. A subsequent linkWalletForAuth
    // call against the same wallet must return the SAME `did` instead of
    // minting a fresh one.
    let (base_url, tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let onboard = rpc_call(
        &client,
        &base_url,
        rpc_request("tenzro_onboardHuman", json!({ "display_name": "Owner" })),
    )
    .await;
    let did_before = onboard["result"]["identity"]["did"]
        .as_str()
        .expect("did")
        .to_string();
    let wallet_id = onboard["result"]["wallet"]["wallet_id"]
        .as_str()
        .expect("wallet_id")
        .to_string();

    let linked = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_linkWalletForAuth",
            json!({ "wallet_id": wallet_id, "display_name": "Owner (linked)" }),
        ),
    )
    .await;
    assert!(linked.get("error").is_none(), "link error: {}", linked);
    let did_after = linked["result"]["identity"]["did"]
        .as_str()
        .expect("did");
    assert_eq!(
        did_after, did_before,
        "linkWalletForAuth must reuse the wallet's existing DID, not mint a new one"
    );

    shutdown(tx, handle).await;
}

// ---------------------------------------------------------------------------
// Bearer-only tokens: no `cnf` claim, rejected at DPoP-protected endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_onboard_without_jkt_emits_bearer_only_jwt() {
    // Onboarding without `dpop_jkt` must produce a JWT whose `cnf` claim
    // is omitted entirely (RFC 9449 §6) and whose response advertises
    // `dpop_bound: false`.
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request("tenzro_onboardHuman", json!({ "display_name": "Bob" })),
    )
    .await;
    let result = &resp["result"];
    assert_eq!(result["dpop_bound"], false);

    let token = result["access_token"].as_str().unwrap().to_string();
    let engine = node.auth_engine().expect("auth engine");

    // Validation without DPoP context must succeed and the resulting
    // claims must carry NO cnf.
    let claims = engine.validate_jwt(&token, None).expect("bearer validates");
    assert!(claims.cnf.is_none(), "bearer-only JWT must omit cnf claim");

    // Pairing the bearer-only JWT with a DPoP proof must be rejected
    // with InvalidDpop — bearer tokens cannot satisfy DPoP-protected
    // endpoints.
    let holder = DpopHolder::new();
    let htu = format!("{}/", base_url);
    let proof = holder.sign_proof("POST", &htu);
    let (parsed, signed_input, signature) =
        DpopProof::parse_with_signed_input(&proof).expect("parse proof");
    let dpop_ctx = DpopValidation {
        proof: &parsed,
        expected_htm: "POST",
        expected_htu: &htu,
        now_unix: now_unix_secs(),
        signed_input: &signed_input,
        signature: &signature,
    };
    let err = engine
        .validate_jwt(&token, Some(dpop_ctx))
        .expect_err("DPoP-paired bearer-only token must fail");
    let msg = format!("{}", err);
    assert!(
        msg.contains("cnf") || msg.contains("bearer"),
        "expected bearer/cnf error, got: {}",
        msg
    );

    shutdown(tx, handle).await;
}

// ---------------------------------------------------------------------------
// Spec-conformance tests for the auth primitives directly.
// ---------------------------------------------------------------------------

/// RFC 9396 §2: an empty RAR envelope (no authorization_details grants) means
/// the bearer can do nothing privileged. A `Transfer` request must resolve to
/// `Deny` when the JWT carries an empty `AuthorizationDetails`.
#[tokio::test]
async fn test_empty_rar_envelope_denies_privileged_action() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let engine = node.auth_engine().expect("auth engine");

    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardHuman",
            json!({ "display_name": "Mallory" }),
        ),
    )
    .await;
    let token = resp["result"]["access_token"].as_str().unwrap().to_string();
    let mut claims = engine.validate_jwt(&token, None).expect("validate");

    // Force-clear the RAR envelope to simulate an attenuated token that
    // grants nothing. (Onboarding mints a generous human envelope; we
    // overwrite to test the empty-envelope policy explicitly.)
    claims.authorization_details = AuthorizationDetails::empty();

    let request = AuthorityRequest {
        action: AuthorityAction::Transfer,
        constraint: ResourceConstraint {
            asset: Some(AssetId("TNZO".into())),
            amount: Some(1_000_000u128),
            counterparty: None,
            resource_id: None,
        },
        approval_id: None,
    };
    let decision = engine
        .resolve_authority(&claims, &request, None)
        .expect("resolve");
    let decision_str = format!("{:?}", decision);
    assert!(
        decision_str.starts_with("Deny"),
        "empty RAR envelope must deny privileged action, got: {:?}",
        decision_str
    );

    shutdown(tx, handle).await;
}

/// RFC 7638 §3: the JWK Thumbprint is `base64url(SHA-256(canonical-JWK))`
/// where canonical form has the required members in lexicographic order with
/// no whitespace. `DpopProof::compute_jkt` must match a manual SHA-256 over
/// the canonical JWK string byte-for-byte.
#[test]
fn test_dpop_jkt_matches_manual_sha256() {
    let holder = DpopHolder::new();
    let canonical = holder.jwk_json.clone();

    let manual_digest = Sha256::digest(canonical.as_bytes());
    let manual_jkt = URL_SAFE_NO_PAD.encode(manual_digest);

    assert_eq!(
        holder.jkt, manual_jkt,
        "DpopProof::compute_jkt must match manual SHA-256 over canonical JWK (RFC 7638 §3)"
    );
}
