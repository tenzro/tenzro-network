//! Certifications, revocation, trust lists, operator policies and violations,
//! and model provenance, driven through the node's JSON-RPC surface.
//!
//! Every document is signed by a P-256 key the test holds, standing in for
//! the issuer's, operator's or observer's own hardware key.

mod dpop_bearer;
mod passkey_holder;

use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::broadcast;

use tenzro_crypto::composite::HybridSigner;
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::p256::{P256KeyPair, P256Signer};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_trust::credential::{Claim, ClaimKind, Subject, unsigned as unsigned_credential};
use tenzro_trust::origin::{ObservedFile, OriginAttestation, OriginKind};
use tenzro_trust::policy::{
    Clause, OperatorPolicy, PolicyTerms, ReceiptKey, Serves, violation_evidence,
};
use tenzro_trust::proof::{ProofRequest, attach_hardware, machine_did, options, signing_digest};
use tenzro_trust::status_list::{IssuerRevocation, Revocation};
use tenzro_types::model::{JurisdictionClaim, JurisdictionReceipt};
use tenzro_types::primitives::{Address, Hash, Timestamp};

/// The operator every test node admits.
fn operator() -> &'static dpop_bearer::OperatorKey {
    static KEY: std::sync::OnceLock<dpop_bearer::OperatorKey> = std::sync::OnceLock::new();
    KEY.get_or_init(dpop_bearer::OperatorKey::new)
}

struct Key(P256Signer);

impl Key {
    fn new(seed: u8) -> Self {
        Key(P256Signer::from_keypair(
            &P256KeyPair::from_secret_bytes(&[seed; 32]).unwrap(),
        ))
    }
    fn sec1(&self) -> [u8; 65] {
        self.0.public_key_sec1()
    }
    fn did(&self) -> String {
        machine_did(&self.sec1())
    }
    fn sign(&self, doc: Value) -> Value {
        let created = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let opts = options(&ProofRequest {
            signer_did: self.did(),
            public_key_sec1: self.sec1(),
            purpose: "assertionMethod".into(),
            created,
            rp_id: None,
        });
        let digest = signing_digest(&doc, &opts);
        let sig: [u8; 64] = self.0.sign_prehash(&digest).as_bytes().try_into().unwrap();
        attach_hardware(doc, opts, &sig)
    }
}

/// The model catalog is process-wide and every node installs its own, so the
/// tests in this binary run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn setup() -> (
    String,
    broadcast::Sender<()>,
    tempfile::TempDir,
    Arc<TenzroNode>,
) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let genesis = tenzro_node::config::GenesisConfig::default_testnet();
    let config = NodeConfig {
        genesis: Some(genesis),
        data_dir: tmp.path().to_path_buf(),
        iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
        models_dir: Some(tmp.path().join("models")),
        ..Default::default()
    };
    dpop_bearer::admit_operator(tmp.path(), &operator().did());
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");
    let node = Arc::new(node);
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
    tokio::spawn(async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await });
    let addr = addr_rx.await.expect("bound address");
    (format!("http://{addr}"), shutdown_tx, tmp, node)
}

async fn call(url: &str, method: &str, params: Value) -> Value {
    call_as(url, method, params, false).await
}

async fn call_as(url: &str, method: &str, params: Value, admin: bool) -> Value {
    let client = reqwest::Client::new();
    if admin {
        let op = operator().sign_in(&client, url).await;
        return op.call(&client, url, method, params).await;
    }
    client
        .post(url)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .send()
        .await
        .expect("HTTP")
        .json::<Value>()
        .await
        .expect("JSON")
}

fn ok(v: &Value) -> &Value {
    assert!(v.get("error").is_none(), "unexpected error: {v}");
    &v["result"]
}

fn err(v: &Value) -> String {
    v.get("error")
        .unwrap_or_else(|| panic!("expected an error, got {v}"))["message"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

fn credential(issuer: &Key, subject: &Subject, kind: ClaimKind, scheme: &str, index: u32) -> Value {
    let claim = Claim {
        kind,
        scheme: scheme.into(),
        grade: None,
        score: Some(9000),
        scope: None,
        evidence: vec![],
    };
    issuer.sign(unsigned_credential(
        &issuer.did(),
        subject,
        &claim,
        now() - chrono::Duration::days(1),
        now() + chrono::Duration::days(365),
        index,
    ))
}

fn model_subject(n: u8) -> Subject {
    Subject::Model(hex::encode([n; 32]))
}

#[tokio::test]
async fn a_forged_credential_is_refused_and_a_genuine_one_verifies() {
    let _serial = SERIAL.lock().await;
    let (url, _shutdown, _tmp, _node) = setup().await;
    let issuer = Key::new(1);
    let doc = credential(
        &issuer,
        &model_subject(1),
        ClaimKind::Certification,
        "iso-iec-42001",
        1,
    );

    let mut forged = doc.clone();
    forged["credentialSubject"]["claim"]["scheme"] = "ailuminate".into();
    let r = call(&url, "tenzro_submitTrustRecord", json!({"record": forged})).await;
    assert!(err(&r).contains("signature"), "{r}");

    let r = call(&url, "tenzro_submitTrustRecord", json!({"record": doc})).await;
    assert_eq!(ok(&r)["kind"], "credential");
    let v = call(
        &url,
        "tenzro_verifyTrustCredential",
        json!({"credential": doc}),
    )
    .await;
    assert_eq!(ok(&v)["valid"], true);
    assert_eq!(ok(&v)["anchored"], true);
    let v = call(
        &url,
        "tenzro_verifyTrustCredential",
        json!({"credential": forged}),
    )
    .await;
    assert_eq!(ok(&v)["valid"], false);
}

#[tokio::test]
async fn revocation_by_the_issuer_and_a_revoked_issuer_invalidate_credentials() {
    let _serial = SERIAL.lock().await;
    let (url, _shutdown, _tmp, _node) = setup().await;
    let issuer = Key::new(1);
    let a = credential(&issuer, &model_subject(1), ClaimKind::Certification, "x", 5);
    let b = credential(&issuer, &model_subject(2), ClaimKind::Certification, "x", 6);
    for d in [&a, &b] {
        ok(&call(&url, "tenzro_submitTrustRecord", json!({"record": d})).await);
    }

    // Someone else cannot revoke the issuer's entry.
    let attacker = Key::new(9);
    let fake = attacker.sign(Revocation::unsigned(&issuer.did(), &[5], now()));
    err(&call(&url, "tenzro_submitTrustRecord", json!({"record": fake})).await);
    let v = call(
        &url,
        "tenzro_verifyTrustCredential",
        json!({"credential": a}),
    )
    .await;
    assert_eq!(ok(&v)["state"], "valid");

    let rev = issuer.sign(Revocation::unsigned(&issuer.did(), &[5], now()));
    ok(&call(&url, "tenzro_submitTrustRecord", json!({"record": rev})).await);
    let v = call(
        &url,
        "tenzro_verifyTrustCredential",
        json!({"credential": a}),
    )
    .await;
    assert_eq!(ok(&v)["state"], "revoked");
    let v = call(
        &url,
        "tenzro_verifyTrustCredential",
        json!({"credential": b}),
    )
    .await;
    assert_eq!(ok(&v)["state"], "valid");

    let list = call(
        &url,
        "tenzro_getStatusList",
        json!({"issuer": issuer.did()}),
    )
    .await;
    assert!(
        ok(&list)["credentialSubject"]["encodedList"]
            .as_str()
            .unwrap()
            .starts_with('u')
    );

    let key_gone = issuer.sign(IssuerRevocation::unsigned(
        &issuer.did(),
        now(),
        "key compromised",
    ));
    ok(&call(
        &url,
        "tenzro_submitTrustRecord",
        json!({"record": key_gone}),
    )
    .await);
    let v = call(
        &url,
        "tenzro_verifyTrustCredential",
        json!({"credential": b}),
    )
    .await;
    assert_eq!(ok(&v)["state"], "issuer-revoked");
}

/// A receipt stamped the way a serving node stamps one: `signer`, the node's
/// hardware identity stand-in, signs a batch holding the receipt.
fn receipt(signer: &Arc<TestHybridSigner>, model_id: &str, country: &str) -> JurisdictionReceipt {
    let mut r = JurisdictionReceipt {
        request_hash: Hash([1u8; 32]),
        response_hash: Hash([2u8; 32]),
        model_id: model_id.into(),
        provider: Address([3u8; 32]),
        jurisdiction: JurisdictionClaim {
            country: country.into(),
            blocs: vec![],
            attestation_hash: None,
            declared_at: Timestamp::new(0),
        },
        signed_at: Timestamp::new((now() + chrono::Duration::seconds(5)).timestamp_millis()),
        signer_public_key: signer.public_key().p256.clone(),
        signer_pq_key: signer.public_key().pq.clone(),
        batched: None,
    };
    let session = tenzro_crypto::batch::ImmediateRecordSigner::new(signer.clone());
    let signed =
        tenzro_crypto::batch::RecordSigner::sign_record(&session, &r.canonical_preimage()).unwrap();
    r.batched = Some(serde_json::to_vec(&signed.batched).unwrap());
    r
}

#[tokio::test]
async fn an_operator_serving_outside_its_own_policy_is_recorded_once_and_the_node_slashes_nothing()
{
    let _serial = SERIAL.lock().await;
    let (url, _shutdown, _tmp, _node) = setup().await;
    let op = Key::new(4);
    let rs = Arc::new(TestHybridSigner::random());
    let terms = PolicyTerms {
        receipt_keys: vec![ReceiptKey::bind(rs.as_ref(), &op.did()).unwrap()],
        serves: Serves {
            models: Some(["qwen3.5-0.8b".to_string()].into_iter().collect()),
            ..Serves::default()
        },
        ..PolicyTerms::default()
    };
    let start = now() + chrono::Duration::seconds(2);
    let policy = op.sign(OperatorPolicy::unsigned(
        &op.did(),
        1,
        start,
        start + chrono::Duration::days(30),
        &terms,
    ));
    ok(&call(&url, "tenzro_submitTrustRecord", json!({"record": policy})).await);

    let bond = |url: String, did: String| async move {
        ok(&call(&url, "tenzro_getComputeBond", json!({"provider_did": did})).await).clone()
    };
    let before = bond(url.clone(), op.did()).await;

    // A receipt for a model the policy serves proves nothing.
    let fine = violation_evidence(
        &policy,
        &receipt(&rs, "qwen3.5-0.8b", "DE"),
        Clause::ServesModels,
    );
    err(&call(&url, "tenzro_submitTrustRecord", json!({"record": fine})).await);
    // A receipt signed by a key the operator never bound proves nothing.
    let framer = Arc::new(TestHybridSigner::random());
    let framed = violation_evidence(
        &policy,
        &receipt(&framer, "other-model", "DE"),
        Clause::ServesModels,
    );
    err(&call(&url, "tenzro_submitTrustRecord", json!({"record": framed})).await);
    assert_eq!(bond(url.clone(), op.did()).await, before);

    let bad = violation_evidence(
        &policy,
        &receipt(&rs, "other-model", "DE"),
        Clause::ServesModels,
    );
    let r = call(&url, "tenzro_submitTrustRecord", json!({"record": bad})).await;
    let res = ok(&r);
    assert_eq!(res["violation"]["operator"], op.did());
    // Bonds move only by consensus transactions: a node's reading of a
    // trust record never slashes.
    assert!(res.get("slash").is_none());
    assert_eq!(bond(url.clone(), op.did()).await, before);

    // The same evidence again is not new.
    let again = call(&url, "tenzro_submitTrustRecord", json!({"record": bad})).await;
    assert_eq!(ok(&again)["new"], false);

    let p = call(
        &url,
        "tenzro_getOperatorPolicy",
        json!({"operator": op.did(), "at": (start + chrono::Duration::seconds(10)).to_rfc3339()}),
    )
    .await;
    assert_eq!(ok(&p)["violations"].as_array().unwrap().len(), 1);
    assert_eq!(ok(&p)["in_force"]["sequence"], 1);
}

#[tokio::test]
async fn a_back_dated_policy_is_refused() {
    let _serial = SERIAL.lock().await;
    let (url, _shutdown, _tmp, _node) = setup().await;
    let op = Key::new(4);
    // Signed now but with the proof dated a day ago: the node refuses it.
    let created =
        (now() - chrono::Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let doc = OperatorPolicy::unsigned(
        &op.did(),
        1,
        now(),
        now() + chrono::Duration::days(1),
        &PolicyTerms::default(),
    );
    let opts = options(&ProofRequest {
        signer_did: op.did(),
        public_key_sec1: op.sec1(),
        purpose: "assertionMethod".into(),
        created,
        rp_id: None,
    });
    let digest = signing_digest(&doc, &opts);
    let sig: [u8; 64] = op.0.sign_prehash(&digest).as_bytes().try_into().unwrap();
    let signed = attach_hardware(doc, opts, &sig);
    assert!(
        err(&call(&url, "tenzro_submitTrustRecord", json!({"record": signed})).await)
            .contains("clock")
    );
}

fn write_model(dir: &std::path::Path) {
    let header = br#"{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#;
    let mut st = (header.len() as u64).to_le_bytes().to_vec();
    st.extend_from_slice(header);
    st.extend_from_slice(&[0u8; 8]);
    std::fs::write(dir.join("model.safetensors"), st).unwrap();
    std::fs::write(dir.join("config.json"), br#"{"arch":"test"}"#).unwrap();
}

#[tokio::test]
async fn model_provenance_verifies_across_origins_and_catches_a_tampered_shard_and_a_lying_mirror()
{
    let _serial = SERIAL.lock().await;
    let (url, _shutdown, tmp, _node) = setup().await;
    let dir = tmp.path().join("models/org-model");
    std::fs::create_dir_all(&dir).unwrap();
    write_model(&dir);

    // Manifest building reads this node's disk: admin only.
    let denied = call(
        &url,
        "tenzro_buildModelManifest",
        json!({"name": "org/model", "path": dir}),
    )
    .await;
    assert!(denied.get("error").is_some(), "{denied}");
    let built = call_as(
        &url,
        "tenzro_buildModelManifest",
        json!({"name": "org/model", "path": dir}),
        true,
    )
    .await;
    let manifest = ok(&built)["manifest"].clone();
    let root = manifest["root"].as_str().unwrap().to_string();

    let files: Vec<ObservedFile> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| ObservedFile {
            path: f["path"].as_str().unwrap().into(),
            size: f["size"].as_u64().unwrap(),
            sha256: f["sha256"].as_str().unwrap().into(),
            blake3: Some(f["blake3"].as_str().unwrap().into()),
        })
        .collect();
    let hub = Key::new(11);
    let hub_obs = hub.sign(OriginAttestation::unsigned(
        &hub.did(),
        OriginKind::Huggingface,
        "hf:org/model@0123456789abcdef0123456789abcdef01234567",
        "org/model",
        &files,
        now(),
    ));
    ok(&call(&url, "tenzro_submitTrustRecord", json!({"record": hub_obs})).await);
    let p = call(&url, "tenzro_getModelProvenance", json!({"root": root})).await;
    assert_eq!(
        ok(&p)["manifests"][0]["verified"],
        false,
        "one origin is not enough"
    );

    let mirror = Key::new(12);
    let mirror_obs = mirror.sign(OriginAttestation::unsigned(
        &mirror.did(),
        OriginKind::Mirror,
        "https://mirror.example/org/model",
        "org/model",
        &files,
        now(),
    ));
    ok(&call(
        &url,
        "tenzro_submitTrustRecord",
        json!({"record": mirror_obs}),
    )
    .await);
    let p = call(
        &url,
        "tenzro_getModelProvenance",
        json!({"name": "org/model"}),
    )
    .await;
    assert_eq!(ok(&p)["manifests"][0]["verified"], true);

    let v = call_as(
        &url,
        "tenzro_verifyModelFiles",
        json!({"name": "org/model", "path": dir}),
        true,
    )
    .await;
    assert_eq!(ok(&v)["verified"], true);
    let scan = call_as(
        &url,
        "tenzro_scanModelFiles",
        json!({"name": "org/model", "path": dir}),
        true,
    )
    .await;
    assert_eq!(ok(&scan)["accepted"], true);

    // A lying mirror serves different bytes for the weights: a signed conflict.
    let liar = Key::new(13);
    let mut lied = files.clone();
    let w = lied
        .iter_mut()
        .find(|f| f.path == "model.safetensors")
        .unwrap();
    w.sha256 = "ee".repeat(32);
    w.blake3 = None;
    let liar_obs = liar.sign(OriginAttestation::unsigned(
        &liar.did(),
        OriginKind::Mirror,
        "https://evil.example/org/model",
        "org/model",
        &lied,
        now(),
    ));
    ok(&call(
        &url,
        "tenzro_submitTrustRecord",
        json!({"record": liar_obs}),
    )
    .await);
    let p = call(&url, "tenzro_getModelProvenance", json!({"root": root})).await;
    let m = &ok(&p)["manifests"][0];
    assert_eq!(m["verified"], false);
    assert_eq!(m["status"]["conflicts"][0]["observer"], liar.did());

    // A tampered shard on disk is named.
    let mut bytes = std::fs::read(dir.join("model.safetensors")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(dir.join("model.safetensors"), bytes).unwrap();
    let v = call_as(
        &url,
        "tenzro_verifyModelFiles",
        json!({"root": root, "path": dir}),
        true,
    )
    .await;
    assert_eq!(ok(&v)["verified"], false);
    assert_eq!(ok(&v)["file"], "model.safetensors");
}

#[tokio::test]
async fn a_pickle_in_a_model_directory_is_refused_by_the_scan() {
    let _serial = SERIAL.lock().await;
    let (url, _shutdown, tmp, _node) = setup().await;
    let dir = tmp.path().join("models/pickled");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("pytorch_model.safetensors"),
        b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x94.",
    )
    .unwrap();
    let built = call_as(
        &url,
        "tenzro_buildModelManifest",
        json!({"name": "org/pickled", "path": dir}),
        true,
    )
    .await;
    let root = ok(&built)["manifest"]["root"].as_str().unwrap().to_string();
    let scan = call_as(
        &url,
        "tenzro_scanModelFiles",
        json!({"root": root, "path": dir}),
        true,
    )
    .await;
    assert_eq!(ok(&scan)["accepted"], false);
    assert_eq!(ok(&scan)["report"]["files"][0]["format"], "pickle");
}

#[tokio::test]
async fn the_replaced_credential_claim_and_model_hash_methods_are_gone() {
    let _serial = SERIAL.lock().await;
    let (url, _shutdown, _tmp, _node) = setup().await;
    for method in [
        "tenzro_addCredential",
        "tenzro_issueCredential",
        "tenzro_addIdentityClaim",
        "tenzro_addTrustedIssuer",
        "tenzro_listTrustedIssuers",
        "tenzro_recordModelHash",
        "tenzro_overrideModelHash",
        "tenzro_getModelHash",
        "tenzro_listModelHashes",
        "tenzro_checkCompliance",
        "tenzro_registerCompliance",
        "tenzro_freezeAddress",
        "tenzro_unfreezeAddress",
        "tenzro_whitelistAddress",
        "tenzro_setCountryRestriction",
        "tenzro_recoverTokens",
        "tenzro_evaluateTrust",
        "tenzro_getTrustList",
        "tenzro_getKyaRecord",
    ] {
        let r = call_as(&url, method, json!({}), true).await;
        assert_eq!(r["error"]["code"], -32601, "{method}: {r}");
    }
}
