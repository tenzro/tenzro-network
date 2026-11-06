//! Run with a raised descriptor limit: `ulimit -n 65536`.
//!
//! Every test here boots a full node with RocksDB and they run in parallel, so
//! the suite's fd usage grows with the test count. At the common 1024 soft
//! limit the run fails partway through with `Too many open files` while
//! opening the db directory or reading a sealed key — which reads like storage
//! corruption and is not. The same run passes once the limit is raised.

//! Auth integration tests.
//!
//! Spins up a full TenzroNode (storage + RPC + auth engine) per test and
//! exercises the OAuth 2.1 + DPoP + RAR surface in full:
//!
//!   1. Onboarding RPCs (human / delegated / autonomous) issue signed JWTs.
//!   2. Issued JWTs validate against the live `AuthEngine`, with DPoP
//!      proofs produced by signing canonical JWS over an in-test Ed25519
//!      keypair.
//!   3. Cascading revocation — revoking a parent JWT or DID propagates to
//!      every act-chain descendant.
//!   4. RFC 9728 protected-resource-metadata endpoint surfaces the full
//!      metadata profile (DPoP, RAR `authorization_details_types`, etc.).
//!   6. Public read RPCs work without a bearer (sanity guard against an
//!      accidental "everything requires auth" regression).
//!
//! Each test owns its own `tempfile::TempDir`, so RocksDB instances never
//! contend.

mod dpop_bearer;
mod passkey_holder;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use tenzro_auth::{
    AuthorityAction, AuthorityRequest, AuthorizationDetails, DpopProof, DpopValidation,
    ResourceConstraint,
};
use tenzro_identity::envelope::{TenzroDidEnvelope, canonical_preimage, params_hash};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_types::AssetId;

use passkey_holder::PasskeyHolder;

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
    dpop_bearer::admit_operator(tmp.path(), &operator().did());
    let cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        // A loopback endpoint on a port of its own, so the test does not
        // contend with a node already running on the host.
        iroh: tenzro_iroh::TenzroIrohConfig {
            bind_addr: free_udp_port(),
            ..Default::default()
        },
        ..Default::default()
    };
    (cfg, tmp)
}

/// A UDP port on loopback that was free a moment ago.
fn free_udp_port() -> std::net::SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free loopback port")
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
    let handle =
        tokio::spawn(async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await });

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

/// The operator every test node admits: its key derives the DID the node's
/// access policy names an administrator.
fn operator() -> &'static dpop_bearer::OperatorKey {
    static KEY: std::sync::OnceLock<dpop_bearer::OperatorKey> = std::sync::OnceLock::new();
    KEY.get_or_init(dpop_bearer::OperatorKey::new)
}

/// `rpc_call` as the node's operator, signed in with the operator's key.
///
/// Operator-only RPCs sit behind the access policy's admin class: without
/// the operator's access token they are refused before the handler runs.
async fn rpc_call_admin(client: &reqwest::Client, url: &str, body: Value) -> Value {
    let bearer = operator().sign_in(client, url).await;
    bearer
        .call(
            client,
            url,
            body["method"].as_str().expect("method"),
            body["params"].clone(),
        )
        .await
}

/// Onboarding params for a human: the display fields in `fields` plus a
/// fresh passkey and ML-DSA-65 key, signed over an `enroll_passkey` custody
/// challenge from the node, as a passkey-holding client would supply them.
async fn human(client: &reqwest::Client, url: &str, fields: Value) -> Value {
    let holder = PasskeyHolder::generate();
    let authorization = holder.authorize(&challenge(client, url, holder.challenge_params()).await);
    holder.onboard_params(fields, authorization)
}

/// The `result` of a `tenzro_createCustodyChallenge` call.
async fn challenge(client: &reqwest::Client, url: &str, params: Value) -> Value {
    let issued = rpc_call(
        client,
        url,
        rpc_request("tenzro_createCustodyChallenge", params),
    )
    .await;
    assert!(issued.get("error").is_none(), "challenge refused: {issued}");
    issued["result"].clone()
}

/// Onboarding params for a machine: `fields` plus the public half of a
/// fresh device key and a machine id, as a TPM or Secure Enclave host
/// would supply them.
fn machine(fields: Value) -> Value {
    machine_with_key(fields).0
}

/// [`machine`], keeping the device key so the test can sign as the machine.
fn machine_with_key(fields: Value) -> (Value, tenzro_crypto::testing::TestHybridSigner) {
    use tenzro_crypto::composite::HybridSigner as _;
    let mut params = fields;
    let key = tenzro_crypto::testing::TestHybridSigner::random();
    let public = key.public_key().p256.clone();
    params["device_public_key"] = json!(hex::encode(&public));
    params["machine_id"] = json!(format!("device-{}", hex::encode(&public[..8])));
    (params, key)
}

/// A human controller with a passkey-bound smart account: its passkey,
/// DID and account address.
/// Its keystore is not on chain until its first change, so approvals carry
/// the anchor the account derives from.
async fn passkey_controller(
    client: &reqwest::Client,
    url: &str,
) -> (PasskeyHolder, String, String, Value) {
    let holder = PasskeyHolder::generate();
    let authorization = holder.authorize(&challenge(client, url, holder.challenge_params()).await);
    let enrolled = rpc_call(
        client,
        url,
        rpc_request("tenzro_enrollPasskey", holder.enroll_params(authorization)),
    )
    .await;
    let r = &enrolled["result"];
    let did = r["did"]
        .as_str()
        .unwrap_or_else(|| panic!("enroll failed: {enrolled}"))
        .to_string();
    let account = r["smart_account_address"]
        .as_str()
        .expect("account")
        .to_string();
    let anchor = r["anchor"].clone();
    (holder, did, account, anchor)
}

/// Machine onboarding params approved by a passkey controller: the
/// controller's passkey signs a `delegate_agent` challenge over the
/// machine's terms, with the machine as its single serving node.
async fn approved_machine(
    client: &reqwest::Client,
    url: &str,
    holder: &PasskeyHolder,
    account: &str,
    anchor: &Value,
    fields: Value,
) -> Value {
    approve_machine(client, url, holder, account, anchor, machine(fields)).await
}

/// Attach the passkey controller's `delegate_agent` approval to machine
/// onboarding params built by [`machine`] or [`machine_with_key`].
async fn approve_machine(
    client: &reqwest::Client,
    url: &str,
    holder: &PasskeyHolder,
    account: &str,
    anchor: &Value,
    mut params: Value,
) -> Value {
    let machine_id = params["machine_id"]
        .as_str()
        .expect("machine id")
        .to_string();
    let issued = challenge(
        client,
        url,
        json!({
            "account_address": account,
            "operation": "delegate_agent",
            "device_public_key": params["device_public_key"],
            "machine_id": machine_id,
            "delegation": {
                "controller_did": params["controller_did"],
                "agent_name": machine_id,
                "delegation_scope": params.get("delegation_scope").cloned().unwrap_or(json!({})),
                "capabilities": params.get("capabilities").cloned().unwrap_or(json!([])),
            },
        }),
    )
    .await;
    params["authorization"] = with_anchor(holder.authorize(&issued), anchor);
    params
}

/// `authorization` naming the account's anchor, while its keystore is not on chain.
/// A signed `RevokeIdentity` transaction carrying `op`, from a fresh funded
/// account unrelated to the identity, as `tenzro_revokeIdentity` takes it.
fn signed_revocation(
    node: &TenzroNode,
    op: &tenzro_types::identity::IdentityRevocationOp,
) -> Value {
    use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
    use tenzro_types::primitives::{ChainId, Nonce};
    use tenzro_types::transaction::{Transaction, TransactionType};
    use tenzro_vm::traits::VmState as _;
    let signer = tenzro_crypto::composite::testing::TestHybridSigner::random();
    let from = signer.address();
    let gas_limit = 200_000u64;
    let gas_price = 4_000_000_000u64;
    {
        let storage = node.storage().expect("node storage").clone();
        let mut state = tenzro_vm::StateAdapter::with_storage(storage);
        state.set_balance(from.as_bytes(), 1_000_000_000_000_000_000);
        state.commit().expect("commit funded balance");
    }
    let tx = Transaction::new(
        ChainId::from(1337),
        from,
        from,
        Nonce::from(0),
        TransactionType::RevokeIdentity { op: op.clone() },
        gas_limit,
        gas_price,
    );
    let signature = signer
        .sign(SignatureContext::Transaction, tx.hash().as_bytes())
        .expect("sign");
    json!({
        "from": format!("0x{}", hex::encode(tx.from.as_bytes())),
        "to": format!("0x{}", hex::encode(tx.to.as_bytes())),
        "nonce": 0,
        "gas_limit": gas_limit,
        "gas_price": gas_price,
        "chain_id": 1337u64,
        "timestamp": tx.timestamp.0,
        "valid_until": tx.valid_until.0,
        "tx_type": serde_json::to_value(&tx.tx_type).expect("tx_type"),
        "public_key": hex::encode(&signer.public_key().p256),
        "signature": signature,
    })
}

fn with_anchor(mut authorization: Value, anchor: &Value) -> Value {
    if !anchor.is_null() {
        authorization["anchor"] = anchor.clone();
    }
    authorization
}

/// An identity whose signing key the test holds.
///
/// The onboarding RPCs auto-provision a permissionless wallet and keep the key inside
/// the node, which is right for production and useless for a test that has to
/// *prove* ownership. The identity is written to the node's registry with a
/// caller-held key, as its replicated registration leaves it, so the private
/// half stays here.
struct SigningIdentity {
    did: String,
    key: tenzro_crypto::testing::TestHybridSigner,
}

impl SigningIdentity {
    /// Registered on `node` as if its registration had replicated.
    async fn register(node: &TenzroNode, seed: u8) -> Self {
        use tenzro_crypto::composite::HybridSigner as _;
        let key = tenzro_crypto::testing::TestHybridSigner::p256_only(seed);
        let did = node
            .identity_registry()
            .expect("identity registry")
            .register_human_via_binder(
                vec![seed; 16],
                key.public_key().p256.clone(),
                "Envelope Signer".to_string(),
            )
            .await
            .expect("identity registered")
            .identity
            .did_string();
        Self { did, key }
    }

    /// A valid envelope over `(method, canonical)` — the same binding
    /// `require_did_owner` recomputes on the node side.
    fn envelope(&self, method: &str, canonical: &[u8]) -> String {
        let mut env = TenzroDidEnvelope {
            did: self.did.clone(),
            method: method.to_string(),
            params_hash: params_hash(canonical),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_millis() as u64,
            // Nonces only need to differ within a run, and are burned on
            // acceptance; deriving one from the clock keeps this free of an
            // RNG dependency. An all-zero nonce is rejected outright.
            nonce: {
                let mut n = [0u8; 16];
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
                    .to_le_bytes();
                n.copy_from_slice(&now[..16]);
                n[15] |= 1;
                n
            },
            signature: vec![],
        };
        use tenzro_crypto::composite::HybridSigner as _;
        let sig = self
            .key
            .sign(
                tenzro_crypto::composite::SignatureContext::DidEnvelope,
                &canonical_preimage(&env),
            )
            .expect("sign");
        env.signature = serde_json::to_vec(&sig).expect("encode");
        env.to_header_value()
    }
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
        let jwk_json = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, x);
        let jkt = DpopProof::compute_jkt(&jwk_json).expect("compute jkt");
        Self {
            signing_key,
            jwk_json,
            jkt,
        }
    }

    /// Sign a fresh DPoP proof for (htm, htu) at the current wall clock.
    /// Returns the compact JWS string suitable for the `DPoP` header.
    fn sign_proof(&self, htm: &str, htu: &str, access_token: Option<&str>) -> String {
        // Header: typ=dpop+jwt, alg=EdDSA, jwk=<this holder's pubkey JWK>.
        // We embed the *full* JWK JSON, not just the thumbprint.
        let jwk_value: Value = serde_json::from_str(&self.jwk_json).expect("jwk parse");
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
        let mut payload = json!({
            "htm": htm,
            "htu": htu,
            "iat": now,
            "jti": jti,
        });
        if let Some(token) = access_token {
            payload["ath"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())));
        }
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

    let passkey = PasskeyHolder::generate();
    let authorization =
        passkey.authorize(&challenge(&client, &base_url, passkey.challenge_params()).await);
    let body = rpc_request(
        "tenzro_onboardHuman",
        passkey.onboard_params(
            json!({
                "display_name": "Alice",
                "dpop_jkt": holder.jkt,
            }),
            authorization,
        ),
    );
    let resp = rpc_call(&client, &base_url, body.clone()).await;

    assert!(resp.get("error").is_none(), "unexpected error: {}", resp);

    // The challenge is single-use: the same proof cannot onboard twice.
    let replay = rpc_call(&client, &base_url, body).await;
    assert_eq!(
        replay["error"]["code"], -32001,
        "replayed proof accepted: {replay}"
    );
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
    assert!(
        result["wallet"]["address"]
            .as_str()
            .unwrap()
            .starts_with("0x")
    );
    assert!(result["access_token"].is_string());
    assert_eq!(result["token_type"], "Bearer");
    assert_eq!(result["dpop_bound"], true);

    // The issued JWT must validate against the live engine when paired
    // with a DPoP proof signed by the same holder key.
    let token = result["access_token"].as_str().unwrap().to_string();
    let engine = node.auth_engine().expect("auth engine wired");
    let htu = format!("{}/", base_url); // canonical resource URI
    let proof = holder.sign_proof("POST", &htu, Some(&token));
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
    assert_eq!(claims.sub, result["identity"]["did"].as_str().unwrap());
    assert_eq!(claims.controller_did, claims.sub);
    assert_eq!(
        claims.cnf.as_ref().map(|c| c.jkt.as_str()),
        Some(holder.jkt.as_str())
    );

    shutdown(tx, handle).await;
}

/// A passkey is enrolled only together with the ML-DSA-65 key of the
/// hardware that holds it, proved by its leg over the same challenge.
#[tokio::test]
async fn test_passkey_enrolment_without_its_ml_dsa_key_is_refused() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let holder = PasskeyHolder::generate();
    let enrol = |params: Value| {
        let client = client.clone();
        let base_url = base_url.clone();
        async move {
            rpc_call(
                &client,
                &base_url,
                rpc_request("tenzro_enrollPasskey", params),
            )
            .await
        }
    };

    // No ML-DSA-65 key at all.
    let authorization =
        holder.authorize(&challenge(&client, &base_url, holder.challenge_params()).await);
    let mut params = holder.enroll_params(authorization);
    params
        .as_object_mut()
        .expect("params object")
        .remove("ml_dsa_public_key_hex");
    let resp = enrol(params).await;
    assert_eq!(
        resp["error"]["code"], -32602,
        "enrolled without ML-DSA-65: {resp}"
    );
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("ml_dsa_public_key_hex is required"),
        "{resp}"
    );

    // The key, but no ML-DSA-65 leg over the challenge.
    let mut authorization =
        holder.authorize(&challenge(&client, &base_url, holder.challenge_params()).await);
    authorization
        .as_object_mut()
        .expect("authorization object")
        .remove("ml_dsa_signature_hex");
    let resp = enrol(holder.enroll_params(authorization)).await;
    assert_eq!(
        resp["error"]["code"], -32001,
        "enrolled without the leg: {resp}"
    );
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("ML-DSA-65"),
        "{resp}"
    );

    // Someone else's ML-DSA-65 key: the leg does not verify against it.
    let other = PasskeyHolder::generate();
    let authorization =
        holder.authorize(&challenge(&client, &base_url, holder.challenge_params()).await);
    let mut params = holder.enroll_params(authorization);
    params["ml_dsa_public_key_hex"] = json!(other.ml_dsa_public_key_hex());
    let resp = enrol(params).await;
    assert_eq!(
        resp["error"]["code"], -32001,
        "enrolled a key it does not hold: {resp}"
    );

    // Both legs enrol, and the identity records the ML-DSA-65 key that
    // passkey sign-in checks.
    let authorization =
        holder.authorize(&challenge(&client, &base_url, holder.challenge_params()).await);
    let resp = enrol(holder.enroll_params(authorization)).await;
    let did = resp["result"]["did"]
        .as_str()
        .unwrap_or_else(|| panic!("enrol failed: {resp}"));
    let identity = node
        .identity_registry()
        .expect("identity registry")
        .resolve(did)
        .expect("identity");
    assert_eq!(
        hex::encode(&identity.pq_verifying_key),
        holder.ml_dsa_public_key_hex()
    );
    shutdown(tx, handle).await;
}

/// A passkey public key alone does not onboard: the caller must prove it
/// holds the key.
#[tokio::test]
async fn test_onboard_human_without_proof_is_refused() {
    let (base_url, tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let passkey = PasskeyHolder::generate();

    let mut params = passkey.onboard_params(json!({ "display_name": "Mallory" }), Value::Null);
    params
        .as_object_mut()
        .expect("params object")
        .remove("authorization");
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request("tenzro_onboardHuman", params),
    )
    .await;
    assert_eq!(
        resp["error"]["code"], -32001,
        "onboarded without proof: {resp}"
    );
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("requires proof you hold it"),
        "{resp}"
    );

    shutdown(tx, handle).await;
}

/// A proof over a challenge bound to a different credential and ML-DSA-65
/// key does not onboard this pairing.
#[tokio::test]
async fn test_onboard_human_proof_over_another_challenge_is_refused() {
    let (base_url, tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let alice = PasskeyHolder::generate();
    let other = PasskeyHolder::generate();

    let mut params = alice.challenge_params();
    params["target_hex"] = other.challenge_params()["target_hex"].clone();
    let authorization = alice.authorize(&challenge(&client, &base_url, params).await);
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardHuman",
            alice.onboard_params(json!({ "display_name": "Alice" }), authorization),
        ),
    )
    .await;
    assert_eq!(
        resp["error"]["code"], -32001,
        "onboarded over another challenge: {resp}"
    );

    shutdown(tx, handle).await;
}

/// Someone who knows a passkey's public key and credential id cannot onboard
/// it by signing its challenge with keys of their own.
#[tokio::test]
async fn test_onboard_human_proof_by_a_different_key_is_refused() {
    let (base_url, tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let alice = PasskeyHolder::generate();
    let mallory = PasskeyHolder::generate();

    let mut params = alice.onboard_params(json!({ "display_name": "Alice" }), Value::Null);
    let mut forged =
        mallory.authorize(&challenge(&client, &base_url, alice.challenge_params()).await);
    forged["credential_id_hex"] = params["credential_id"].clone();
    params["authorization"] = forged;
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request("tenzro_onboardHuman", params),
    )
    .await;
    assert_eq!(
        resp["error"]["code"], -32001,
        "onboarded with a forged proof: {resp}"
    );
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("did not verify against the passkey being enrolled"),
        "{resp}"
    );

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn test_onboard_delegated_agent_carries_controller_and_scope() {
    let (base_url, tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();

    // A human controller with a passkey-bound account.
    let (holder, controller_did, account, anchor) = passkey_controller(&client, &base_url).await;

    // Now onboard a delegated agent under that controller.
    let agent_holder = DpopHolder::new();
    let body = rpc_request(
        "tenzro_onboardDelegatedAgent",
        approved_machine(
            &client,
            &base_url,
            &holder,
            &account,
            &anchor,
            json!({
                "controller_did": controller_did,
                "capabilities": ["inference", "settlement"],
                "delegation_scope": {
                    "max_transaction_value": "1000000000000000000",
                    "max_daily_spend": "5000000000000000000",
                    "allowed_operations": ["transfer", "create_escrow"],
                },
                "dpop_jkt": agent_holder.jkt,
            }),
        )
        .await,
    );
    let resp = rpc_call_admin(&client, &base_url, body).await;

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

    let resp = rpc_call_admin(
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
            human(
                &client,
                &base_url,
                json!({ "display_name": "Bob", "dpop_jkt": real_holder.jkt }),
            )
            .await,
        ),
    )
    .await;
    let token = resp["result"]["access_token"].as_str().unwrap().to_string();

    // Attacker tries to use it with a DPoP proof signed by their key.
    let engine = node.auth_engine().expect("auth engine");
    let htu = format!("{}/", base_url);
    let bad_proof = attacker.sign_proof("POST", &htu, Some(&token));
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
            human(
                &client,
                &base_url,
                json!({ "display_name": "Carol", "dpop_jkt": holder.jkt }),
            )
            .await,
        ),
    )
    .await;
    let token = resp["result"]["access_token"].as_str().unwrap().to_string();

    let engine = node.auth_engine().expect("auth engine");
    let htu = format!("{}/", base_url);
    let proof = holder.sign_proof("POST", &htu, Some(&token));
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
// Cascading revocation
// ---------------------------------------------------------------------------

/// A `jti` identifies a token; it does not authorize destroying one.
///
/// Every audit row carries the jti, and so does the token itself, so treating
/// knowledge of one as authority would mean anyone who ever saw a token — or
/// read the audit log — could revoke it, and the act-chain cascade would take
/// every token minted under it along too.
///
/// The bearer's own envelope is the owner proof exercised here. A controller
/// pulls a compromised agent with its passkey through `tenzro_revokeIdentity`
/// (see [`test_revoke_did_cascades_to_act_chain`]).
#[tokio::test]
async fn test_revoke_jti_invalidates_subsequent_validation() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let engine = node.auth_engine().expect("auth engine");

    // A machine delegated by a passkey controller. The controller's passkey
    // cannot sign a DID envelope, so the token's owner proof here is the
    // bearer's: the machine signs with its hardware key.
    let (holder, controller_did, account, anchor) = passkey_controller(&client, &base_url).await;
    let (params, device_key) = machine_with_key(json!({
        "controller_did": controller_did,
        "capabilities": ["inference"],
    }));
    let resp = rpc_call_admin(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardDelegatedAgent",
            approve_machine(&client, &base_url, &holder, &account, &anchor, params).await,
        ),
    )
    .await;
    let token = resp["result"]["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("onboardDelegatedAgent returned no token: {resp}"))
        .to_string();
    let bearer = SigningIdentity {
        did: resp["result"]["identity"]["did"]
            .as_str()
            .expect("agent did")
            .to_string(),
        key: device_key,
    };

    // Validate first (no DPoP — exercise unbound path).
    let claims = engine
        .validate_jwt(&token, None)
        .expect("first validation succeeds");
    let jti = claims.jti.clone();

    // Knowing the jti is not enough.
    let bare = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_revokeJwt",
            json!({ "jti": jti, "reason": "test revocation" }),
        ),
    )
    .await;
    assert!(
        bare.get("error").is_some(),
        "revokeJwt accepted a bare jti with no owner proof: {bare}"
    );
    assert!(
        engine.validate_jwt(&token, None).is_ok(),
        "an unauthorized revoke must leave the token usable"
    );

    // An envelope from a DID that is neither the bearer nor the controller is
    // a valid signature by the wrong party, which is still not authorization.
    let stranger = SigningIdentity::register(&node, 12).await;
    let wrong = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_revokeJwt",
            json!({
                "jti": jti,
                "did_envelope": stranger.envelope("tenzro_revokeJwt", jti.as_bytes()),
            }),
        ),
    )
    .await;
    assert!(
        wrong.get("error").is_some(),
        "revokeJwt accepted an envelope from an unrelated DID: {wrong}"
    );

    // The bearer can.
    let revoke_resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_revokeJwt",
            json!({
                "jti": jti,
                "reason": "test revocation",
                "did_envelope": bearer.envelope("tenzro_revokeJwt", jti.as_bytes()),
            }),
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

/// A `jti` with no issuance record is refused rather than revoked.
///
/// Otherwise "a jti this node has never seen" is the way past the ownership
/// gate: there is no bearer and no controller to check against, so a permissive
/// reading would treat the token as unowned and revoke it — and the cascade
/// would run.
#[tokio::test]
async fn test_revoke_unknown_jti_is_refused() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();

    let signer = SigningIdentity::register(&node, 13).await;
    let jti = "01JZZZZZZZZZZZZZZZZZZZZZZZ";
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_revokeJwt",
            json!({
                "jti": jti,
                "did_envelope": signer.envelope("tenzro_revokeJwt", jti.as_bytes()),
            }),
        ),
    )
    .await;
    assert!(
        resp.get("error").is_some(),
        "an unattributable jti was accepted for revocation: {resp}"
    );

    shutdown(tx, handle).await;
}

/// Revoking a delegated agent's DID cascades to every token in its act-chain,
/// and requires proof from an owner: the operator admin token alone is
/// refused, because destroying a tenant's identity network-wide is not the
/// operator's call to make. The controller proves it with its passkey.
#[tokio::test]
async fn test_revoke_did_cascades_to_act_chain() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let engine = node.auth_engine().expect("auth engine");

    // Onboard a delegated agent under a passkey controller.
    let (holder, controller_did, account, anchor) = passkey_controller(&client, &base_url).await;
    let agent = rpc_call_admin(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardDelegatedAgent",
            approved_machine(
                &client,
                &base_url,
                &holder,
                &account,
                &anchor,
                json!({
                    "controller_did": controller_did,
                    "capabilities": ["inference"],
                }),
            )
            .await,
        ),
    )
    .await;
    let agent_token = agent["result"]["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("onboardDelegatedAgent returned no token: {agent}"))
        .to_string();
    let agent_did = agent["result"]["identity"]["did"]
        .as_str()
        .expect("agent did")
        .to_string();

    // Token validates before revocation.
    engine
        .validate_jwt(&agent_token, None)
        .expect("agent token valid");

    // The admin token alone is not enough: a shared node's host does not get
    // to revoke a tenant's identity network-wide on their own say-so.
    let admin_only = rpc_call_admin(
        &client,
        &base_url,
        rpc_request(
            "tenzro_revokeIdentity",
            json!({ "did": agent_did, "reason": "key compromise" }),
        ),
    )
    .await;
    assert!(
        admin_only.get("error").is_some(),
        "revokeDid accepted the operator admin token with no owner proof: {admin_only}"
    );
    assert!(
        engine.validate_jwt(&agent_token, None).is_ok(),
        "an unauthorized revoke must leave the act-chain intact"
    );

    // The controller's passkey approves revoking the machine: a
    // revoke_identity challenge over the DID and the reason. The machine's
    // DID is derived under its controller, the root every validator accepts
    // as its approver. The approval rides in a RevokeIdentity transaction
    // that any account may sign; here an unrelated account sends it.
    let reason = "key compromise";
    let target = tenzro_types::identity::revocation_target(&agent_did, reason);
    let issued = challenge(
        &client,
        &base_url,
        json!({
            "account_address": account,
            "operation": "revoke_identity",
            "target_hex": hex::encode(target),
        }),
    )
    .await;
    let op = tenzro_types::identity::IdentityRevocationOp {
        did: agent_did.clone(),
        reason: reason.to_string(),
        approver_did: controller_did.clone(),
        approval: holder.approval(&issued),
    };

    // A stranger's approval in the same transaction is refused before
    // admission: the sender does not authorise a revocation.
    let stranger = PasskeyHolder::generate();
    let forged = tenzro_types::identity::IdentityRevocationOp {
        approval: stranger.approval(&issued),
        ..op.clone()
    };
    let refused = rpc_call_admin(
        &client,
        &base_url,
        rpc_request("tenzro_revokeIdentity", signed_revocation(&node, &forged)),
    )
    .await;
    assert!(
        refused.get("error").is_some(),
        "a revocation the controller did not approve was admitted: {refused}"
    );

    let resp = rpc_call_admin(
        &client,
        &base_url,
        rpc_request("tenzro_revokeIdentity", signed_revocation(&node, &op)),
    )
    .await;
    assert!(resp.get("error").is_none(), "revokeDid error: {}", resp);
    assert!(
        resp["result"]["tx_hash"].is_string(),
        "the revocation goes to consensus as a transaction: {resp}"
    );
    assert_eq!(
        resp["result"]["approver_did"].as_str(),
        Some(controller_did.as_str()),
        "the machine is revoked on its controller's authority: {resp}"
    );

    // This harness runs no consensus, so apply the admitted transaction as
    // every validator does and hand its logs to the node's read-model hook,
    // as the event loop does for each block.
    let logs = {
        let storage = node.storage().expect("node storage").clone();
        let mut chain = tenzro_vm::StateAdapter::with_storage(storage);
        let (_, logs) = tenzro_vm::native::identity_revocation::apply(
            &mut chain,
            &op,
            chrono::Utc::now().timestamp_millis(),
        )
        .expect("every validator applies the approved revocation");
        logs
    };
    let outcome = tenzro_node::identity_mirror::mirror_identity_logs(
        node.identity_registry().expect("identity registry"),
        Some(engine.as_ref()),
        &logs,
    );
    assert_eq!(outcome.revoked, vec![agent_did.clone()]);
    assert!(
        outcome.tokens_revoked >= 1,
        "expected cascade to touch >=1 JTI: {outcome:?}"
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
    assert_eq!(resp["result"]["escrows"].as_array().map(Vec::len), Some(0));

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
            human(&client, &base_url, json!({ "display_name": "Eve" })).await,
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
    };
    let decision = engine
        .resolve_authority(&claims, &request)
        .expect("resolve");
    // Must be Permit (not Deny).
    let decision_str = format!("{:?}", decision);
    assert!(
        decision_str.starts_with("Permit"),
        "expected Permit, got: {:?}",
        decision_str
    );

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn a_second_identity_for_the_same_passkey_is_refused() {
    let (base_url, tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();
    // One passkey, onboarded twice, each time over its own fresh challenge,
    // so the second refusal is about the passkey and not a spent challenge.
    let holder = PasskeyHolder::generate();
    let first_auth =
        holder.authorize(&challenge(&client, &base_url, holder.challenge_params()).await);
    let params = holder.onboard_params(json!({ "display_name": "Owner" }), first_auth);

    let first = rpc_call(
        &client,
        &base_url,
        rpc_request("tenzro_onboardHuman", params),
    )
    .await;
    let did = first["result"]["identity"]["did"]
        .as_str()
        .unwrap_or_else(|| panic!("first onboarding: {first}"))
        .to_string();

    let again_auth =
        holder.authorize(&challenge(&client, &base_url, holder.challenge_params()).await);
    let again_params = holder.onboard_params(json!({ "display_name": "Owner" }), again_auth);
    let again = rpc_call(
        &client,
        &base_url,
        rpc_request("tenzro_onboardHuman", again_params),
    )
    .await;
    assert!(
        again["result"].is_null(),
        "second identity created: {again}"
    );
    let message = again["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&did),
        "refusal names the existing identity: {message}"
    );

    shutdown(tx, handle).await;
}

// ---------------------------------------------------------------------------
// linkWalletForAuth: re-bind to existing identity, no duplicates
// ---------------------------------------------------------------------------

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
        rpc_request(
            "tenzro_onboardHuman",
            human(&client, &base_url, json!({ "display_name": "Bob" })).await,
        ),
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
    let proof = holder.sign_proof("POST", &htu, Some(&token));
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
            human(&client, &base_url, json!({ "display_name": "Mallory" })).await,
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
    };
    let decision = engine
        .resolve_authority(&claims, &request)
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

/// Call `method` with a `DPoP` proof header and no access token.
async fn rpc_call_with_proof(
    client: &reqwest::Client,
    url: &str,
    proof: &str,
    body: Value,
) -> Value {
    client
        .post(url)
        .header("DPoP", proof)
        .json(&body)
        .send()
        .await
        .expect("HTTP")
        .json::<Value>()
        .await
        .expect("JSON")
}

/// A refresh token mints access only for the key it is bound to, proven by
/// a DPoP proof from that key, and is spent by the exchange.
#[tokio::test]
async fn a_refresh_token_cannot_be_rebound_and_is_spent_once() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let holder = DpopHolder::new();
    let attacker = DpopHolder::new();
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardHuman",
            human(
                &client,
                &base_url,
                json!({ "display_name": "Rae", "dpop_jkt": holder.jkt }),
            )
            .await,
        ),
    )
    .await;
    let refresh = resp["result"]["refresh_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no refresh token: {resp}"))
        .to_string();
    let htu = format!("{base_url}/");

    let stolen = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_refreshToken",
            json!({ "refresh_token": refresh, "dpop_jkt": attacker.jkt }),
        ),
    )
    .await;
    assert_eq!(
        stolen["error"]["code"], -32001,
        "refresh rebound to another key without a proof: {stolen}"
    );

    let wrong = rpc_call_with_proof(
        &client,
        &base_url,
        &attacker.sign_proof("POST", &htu, None),
        rpc_request("tenzro_refreshToken", json!({ "refresh_token": refresh })),
    )
    .await;
    assert_eq!(wrong["error"]["code"], -32001, "{wrong}");

    let ok = rpc_call_with_proof(
        &client,
        &base_url,
        &holder.sign_proof("POST", &htu, None),
        rpc_request("tenzro_refreshToken", json!({ "refresh_token": refresh })),
    )
    .await;
    assert!(ok.get("error").is_none(), "{ok}");
    let rotated = ok["result"]["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(rotated, refresh);
    let claims = node
        .auth_engine()
        .unwrap()
        .validate_jwt(ok["result"]["access_token"].as_str().unwrap(), None)
        .unwrap();
    assert_eq!(claims.cnf.unwrap().jkt, holder.jkt);

    let again = rpc_call_with_proof(
        &client,
        &base_url,
        &holder.sign_proof("POST", &htu, None),
        rpc_request("tenzro_refreshToken", json!({ "refresh_token": refresh })),
    )
    .await;
    assert_eq!(
        again["error"]["code"], -32001,
        "spent token reused: {again}"
    );

    shutdown(tx, handle).await;
}

/// Token exchange proves possession of the parent token's key before
/// anything else is looked at.
#[tokio::test]
async fn token_exchange_needs_a_proof_from_the_parent_key() {
    let (base_url, tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let holder = DpopHolder::new();
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardHuman",
            human(
                &client,
                &base_url,
                json!({ "display_name": "Sol", "dpop_jkt": holder.jkt }),
            )
            .await,
        ),
    )
    .await;
    let token = resp["result"]["access_token"].as_str().unwrap().to_string();
    let child = DpopHolder::new();
    let out = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_exchangeToken",
            json!({
                "subject_token": token,
                "child_bearer_did": "did:tenzro:machine:child",
                "child_dpop_jkt": child.jkt,
            }),
        ),
    )
    .await;
    assert_eq!(
        out["error"]["code"], -32001,
        "exchange without a proof: {out}"
    );
    assert!(
        out["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("DPoP"),
        "{out}"
    );
    shutdown(tx, handle).await;
}

/// A signed ContractDeploy transaction for a funded account.
fn signed_deploy(
    node: &TenzroNode,
    signer: &tenzro_crypto::composite::testing::TestHybridSigner,
    code: Vec<u8>,
) -> Value {
    use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
    use tenzro_types::primitives::{Address, ChainId, Nonce};
    use tenzro_types::transaction::{Transaction, TransactionType};
    use tenzro_vm::traits::VmState as _;
    let from = signer.address();
    {
        let storage = node.storage().expect("node storage").clone();
        let mut state = tenzro_vm::StateAdapter::with_storage(storage);
        state.set_balance(from.as_bytes(), 1_000_000_000_000_000_000);
        state.commit().expect("commit funded balance");
    }
    let (gas_limit, gas_price) = (500_000u64, 4_000_000_000u64);
    let tx = Transaction::new(
        ChainId::from(1337),
        from,
        Address::zero(),
        Nonce::from(0),
        TransactionType::ContractDeploy { code, args: vec![] },
        gas_limit,
        gas_price,
    );
    let signature = signer
        .sign(SignatureContext::Transaction, tx.hash().as_bytes())
        .expect("sign");
    json!({
        "from": format!("0x{}", hex::encode(tx.from.as_bytes())),
        "to": format!("0x{}", hex::encode(tx.to.as_bytes())),
        "nonce": 0,
        "gas_limit": gas_limit,
        "gas_price": gas_price,
        "chain_id": 1337u64,
        "timestamp": tx.timestamp.0,
        "valid_until": tx.valid_until.0,
        "tx_type": serde_json::to_value(&tx.tx_type).expect("tx_type"),
        "public_key": hex::encode(&signer.public_key().p256),
        "signature": signature,
    })
}

/// Deploying a contract is a transaction like any other: the RPC admits a
/// signed ContractDeploy, which binds the code, nonce, chain and sender, and
/// nothing executes outside a block. A signature over anything less deploys
/// nothing.
#[tokio::test]
async fn deploy_contract_admits_a_signed_transaction_and_executes_nothing() {
    use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
    use tenzro_vm::traits::VmState as _;
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let signer = tenzro_crypto::composite::testing::TestHybridSigner::random();
    let params = signed_deploy(&node, &signer, vec![0x60, 0x00]);
    let from = signer.address();
    let balance_before = {
        let state = tenzro_vm::StateAdapter::with_storage(node.storage().unwrap().clone());
        state.get_balance(from.as_bytes())
    };

    let deployer = format!("0x{}", hex::encode(from.as_bytes()));
    let message = format!("tenzro:deploy_contract:evm:{deployer}");
    let loose = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_deployContract",
            json!({
                "vm_type": "evm",
                "bytecode": "0x6000",
                "deployer": deployer,
                "public_key": hex::encode(&signer.public_key().p256),
                "signature": signer
                    .sign(SignatureContext::AccountOwner, message.as_bytes())
                    .expect("sign"),
            }),
        ),
    )
    .await;
    assert!(
        loose.get("error").is_some(),
        "a deploy signed over no code was executed: {loose}"
    );
    {
        let state = tenzro_vm::StateAdapter::with_storage(node.storage().unwrap().clone());
        assert_eq!(
            state.get_nonce(from.as_bytes()),
            0,
            "nonce moved outside consensus"
        );
        assert_eq!(state.get_balance(from.as_bytes()), balance_before);
    }

    let admitted = rpc_call(
        &client,
        &base_url,
        rpc_request("tenzro_deployContract", params.clone()),
    )
    .await;
    assert_eq!(admitted["result"]["status"], "admitted", "{admitted}");
    assert!(admitted["result"]["tx_hash"].is_string(), "{admitted}");

    let replay = rpc_call(
        &client,
        &base_url,
        rpc_request("tenzro_deployContract", params),
    )
    .await;
    assert!(
        replay.get("error").is_some()
            || replay["result"]["tx_hash"] == admitted["result"]["tx_hash"],
        "the same signed deploy became a second transaction: {replay}"
    );
    shutdown(tx, handle).await;
}

/// A funded address that the caller does not even claim to hold is not a
/// bond: onboarding an autonomous agent needs a bond locked on chain for the
/// DID its device key derives.
#[tokio::test]
async fn an_autonomous_agent_is_not_bonded_by_someone_elses_balance() {
    use tenzro_crypto::composite::HybridSigner as _;
    use tenzro_vm::traits::VmState as _;
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let rich = [0xeeu8; 32];
    {
        let storage = node.storage().expect("node storage").clone();
        let mut state = tenzro_vm::StateAdapter::with_storage(storage);
        state.set_balance(&rich, 5_000_000_000_000_000_000);
        state.commit().expect("commit funded balance");
    }
    let device = tenzro_crypto::testing::TestHybridSigner::p256_only(0x71);
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardAutonomousAgent",
            json!({
                "device_public_key": hex::encode(&device.public_key().p256),
                "machine_id": "autonomous-test-machine",
                "bond_funding_address": format!("0x{}", hex::encode(rich)),
            }),
        ),
    )
    .await;
    assert!(
        resp["error"].is_object(),
        "onboarded against another account's balance: {resp}"
    );
    shutdown(tx, handle).await;
}

/// A partner running the onboarding node never holds the person's keys or
/// funds: the onboarded identity's DID and wallet are the passkey's own, the
/// answer carries no key material, and a transfer out of that wallet signed
/// by any key but the passkey (a key the partner holds) is refused.
#[tokio::test]
async fn a_partner_run_onboarding_cannot_sign_for_or_move_the_users_funds() {
    use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
    use tenzro_types::primitives::{Address, ChainId, Nonce};
    use tenzro_types::transaction::{Transaction, TransactionType};
    let (base_url, tx, handle, _tmp, _node) = setup_test_server().await;
    let client = reqwest::Client::new();
    let person = PasskeyHolder::generate();
    let authorization =
        person.authorize(&challenge(&client, &base_url, person.challenge_params()).await);
    let resp = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_onboardHuman",
            person.onboard_params(json!({ "display_name": "Ana" }), authorization),
        ),
    )
    .await;
    assert!(resp["error"].is_null(), "{resp}");
    let result = &resp["result"];

    // The wallet is the account the person's passkey names, so only the
    // passkey signs for it.
    let own = tenzro_crypto::composite::account_address(&person.public_xy());
    let wallet = result["wallet"]["address"]
        .as_str()
        .expect("a wallet address");
    let wallet_bytes = hex::decode(wallet.trim_start_matches("0x")).expect("hex");
    assert!(
        tenzro_crypto::controls_account(&person.public_xy(), &wallet_bytes),
        "the wallet {wallet} is not the passkey's own account {own:?}"
    );

    // Nothing in the answer is key material the partner could keep.
    let text = resp.to_string().to_ascii_lowercase();
    for secret in [
        "private",
        "secret",
        "mnemonic",
        "seed",
        "share",
        "keystore_blob",
    ] {
        assert!(
            !text.contains(secret),
            "the answer carries {secret}: {resp}"
        );
    }

    // A key the partner holds cannot move the person's funds.
    let partner = tenzro_crypto::testing::TestHybridSigner::random();
    let from = Address::from_bytes(&wallet_bytes).expect("an account address");
    let to = Address::new([0x5a; 32]);
    let transfer = Transaction::new(
        ChainId::from(1337),
        from,
        to,
        Nonce::from(0),
        TransactionType::Transfer { amount: 1 },
        21_000,
        1_000_000_000,
    );
    let signature = partner
        .sign(SignatureContext::Transaction, transfer.hash().as_bytes())
        .expect("sign");
    let sent = rpc_call(
        &client,
        &base_url,
        rpc_request(
            "tenzro_sendRawTransaction",
            json!({
                "from": format!("0x{}", hex::encode(from.as_bytes())),
                "to": format!("0x{}", hex::encode(to.as_bytes())),
                "nonce": 0,
                "gas_limit": 21_000,
                "gas_price": 1_000_000_000u64,
                "chain_id": 1337u64,
                "timestamp": transfer.timestamp.0,
                "valid_until": transfer.valid_until.0,
                "tx_type": serde_json::to_value(&transfer.tx_type).expect("tx_type"),
                "public_key": hex::encode(&partner.public_key().p256),
                "signature": signature,
            }),
        ),
    )
    .await;
    assert!(
        sent["error"].is_object(),
        "a partner key moved the funds: {sent}"
    );

    shutdown(tx, handle).await;
}
