//! The model catalog as published data, driven through the node's JSON-RPC
//! surface: entries signed by a publisher whose key's account holds a
//! catalog publisher bond, narrowed to the publishers the operator names when it names
//! any, picked up without a restart, and enforced on the load, download and
//! pricing paths.
//!
//! Every document is signed by a P-256 key the test holds, standing in for
//! the publisher's or operator's own hardware key.
//!
//! The catalog a node installs is process-wide, so these tests run one at a
//! time.

mod dpop_bearer;
mod passkey_holder;

use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::broadcast;

use tenzro_catalog::{
    CatalogEntry, Component, HfModelEntry, Licence, LicenseTier, ModelSpec, Source,
};
use tenzro_crypto::p256::{P256KeyPair, P256Signer};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_trust::catalog::CatalogRecord;
use tenzro_trust::proof::{ProofRequest, attach_hardware, machine_did, options, signing_digest};

/// The operator every test node admits.
fn operator() -> &'static dpop_bearer::OperatorKey {
    static KEY: std::sync::OnceLock<dpop_bearer::OperatorKey> = std::sync::OnceLock::new();
    KEY.get_or_init(dpop_bearer::OperatorKey::new)
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Key(P256Signer);

impl Key {
    fn new(seed: u8) -> Self {
        Key(P256Signer::from_keypair(
            &P256KeyPair::from_secret_bytes(&[seed; 32]).unwrap(),
        ))
    }
    fn did(&self) -> String {
        machine_did(&self.0.public_key_sec1())
    }
    /// The ledger account of this key, where its role stakes are held.
    fn account(&self) -> [u8; 32] {
        tenzro_crypto::composite::account_slot(&self.0.public_key_sec1()[1..])
    }
    fn sign(&self, doc: Value) -> Value {
        let created = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let opts = options(&ProofRequest {
            signer_did: self.did(),
            public_key_sec1: self.0.public_key_sec1(),
            purpose: "assertionMethod".into(),
            created,
            rp_id: None,
        });
        let digest = signing_digest(&doc, &opts);
        let sig: [u8; 64] = self.0.sign_prehash(&digest).as_bytes().try_into().unwrap();
        attach_hardware(doc, opts, &sig)
    }
}

const OPERATOR: u8 = 41;
const PUBLISHER: u8 = 42;
const OTHER_PUBLISHER: u8 = 43;

/// No token and no Hugging Face login reachable from these tests, so nothing
/// here can fetch from the Hub.
fn hermetic_env() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let home = tempfile::tempdir().expect("temp home").keep();
        // SAFETY: set once, before any node is constructed, while the tests
        // hold the serial lock.
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("TENZRO_HOME", home.join(".tenzro"));
        }
    });
}

async fn setup() -> (
    String,
    broadcast::Sender<()>,
    tempfile::TempDir,
    Arc<TenzroNode>,
) {
    start(NodeConfig {
        catalog_publishers: vec![Key::new(PUBLISHER).did()],
        release_publishers: vec![Key::new(PUBLISHER).did()],
        ..Default::default()
    })
    .await
}

async fn start(
    config: NodeConfig,
) -> (
    String,
    broadcast::Sender<()>,
    tempfile::TempDir,
    Arc<TenzroNode>,
) {
    hermetic_env();
    let tmp = tempfile::tempdir().expect("temp dir");
    // Both test publishers bond the catalog publisher role at genesis from
    // their signing keys' accounts; a publisher without a bond is never
    // served.
    let mut genesis = config
        .genesis
        .clone()
        .unwrap_or_else(tenzro_node::config::GenesisConfig::default_testnet);
    for seed in [PUBLISHER, OTHER_PUBLISHER] {
        genesis
            .role_stakes
            .push(tenzro_node::config::GenesisRoleStake {
                address: hex::encode(Key::new(seed).account()),
                role: "catalog".into(),
                stake: None,
                capacity: Default::default(),
                endpoint: None,
            });
    }
    let config = NodeConfig {
        genesis: Some(genesis),
        data_dir: tmp.path().to_path_buf(),
        iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
        models_dir: Some(tmp.path().join("models")),
        ..config
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

async fn call(url: &str, method: &str, params: Value) -> Value {
    call_as(url, method, params, false).await
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

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// A single-file GGUF entry whose weights are `weights`.
fn gguf(id: &str, weights: &[u8], tier: LicenseTier, gated: bool) -> CatalogEntry {
    let repo = format!("publisher/{id}");
    let file = format!("{id}.Q4_K_M.gguf");
    CatalogEntry {
        model: ModelSpec::Gguf(HfModelEntry {
            id: id.into(),
            name: id.into(),
            family: "test".into(),
            hf_repo: repo.clone(),
            hf_filename: file.clone(),
            parameters: "1B".into(),
            context_length: 4096,
            quantization: "Q4_K_M".into(),
            size_bytes: weights.len() as u64,
            min_ram_gb: 1,
            promotable: true,
            ..Default::default()
        }),
        licence: Licence {
            name: match tier {
                LicenseTier::NonCommercial => "CC-BY-NC-4.0".into(),
                _ => "Apache-2.0".into(),
            },
            id: (tier == LicenseTier::CommercialCustom).then(|| "test-custom".to_string()),
            tier,
            conditions: None,
            components: Vec::new(),
        },
        gated,
        components: vec![Component {
            repo,
            path: file,
            source: Source::Hub {
                revision: "0123456789abcdef0123456789abcdef01234567".into(),
            },
            size: weights.len() as u64,
            sha256: sha256_hex(weights),
            at: None,
        }],
        capabilities: vec![],
        capability_priors: Default::default(),
        moe_source: None,
        requires: Vec::new(),
    }
}

fn publish(publisher: &Key, sequence: u64, entry: &CatalogEntry) -> Value {
    let body = serde_json::to_value(entry).unwrap();
    publisher.sign(CatalogRecord::unsigned(
        &publisher.did(),
        entry.id(),
        sequence,
        Some(&body),
    ))
}

fn withdraw(publisher: &Key, sequence: u64, model: &str) -> Value {
    publisher.sign(CatalogRecord::unsigned(
        &publisher.did(),
        model,
        sequence,
        None,
    ))
}

async fn submit(url: &str, record: Value) -> Value {
    call(url, "tenzro_submitTrustRecord", json!({ "record": record })).await
}

async fn served(url: &str, model: &str) -> Value {
    call(url, "tenzro_getCatalogEntry", json!({ "model": model })).await
}

#[tokio::test]
async fn a_published_entry_is_served_at_once_and_only_from_a_named_publisher() {
    let _serial = SERIAL.lock().await;
    let (url, _shutdown, _tmp, _node) = setup().await;
    let publisher = Key::new(PUBLISHER);
    let stranger = Key::new(OTHER_PUBLISHER);

    ok(&submit(
        &url,
        publish(
            &publisher,
            1,
            &gguf("m-early", b"early", LicenseTier::Permissive, false),
        ),
    )
    .await);
    let got = ok(&served(&url, "m-early").await).clone();
    assert_eq!(got["served"], true);
    assert_eq!(got["publishers"], json!([publisher.did()]));

    // A publisher the operator does not recognise is ignored.
    ok(&submit(
        &url,
        publish(
            &stranger,
            1,
            &gguf("m-stranger", b"s", LicenseTier::Permissive, false),
        ),
    )
    .await);
    let e = err(&served(&url, "m-stranger").await);
    assert!(e.contains("not in this node's catalog"), "{e}");
    assert!(tenzro_model::catalog::get_model_by_id("m-stranger").is_none());

    // A newly published model is served without a restart, through every
    // reader of the catalog.
    ok(&submit(
        &url,
        publish(
            &publisher,
            1,
            &gguf("m-new", b"new", LicenseTier::Permissive, false),
        ),
    )
    .await);
    assert_eq!(ok(&served(&url, "m-new").await)["served"], true);
    let ids: Vec<String> =
        ok(&call(&url, "tenzro_listCatalog", json!({"engine": "gguf"})).await)["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["model"]["spec"]["id"].as_str().unwrap().to_string())
            .collect();
    assert_eq!(ids, ["m-early", "m-new"]);
    assert!(tenzro_model::catalog::get_model_by_id("m-new").is_some());

    // An older sequence cannot replace an entry; a withdrawal removes it.
    assert!(
        err(&submit(
            &url,
            publish(
                &publisher,
                0,
                &gguf("m-new", b"x", LicenseTier::Permissive, false)
            )
        )
        .await)
        .contains("sequence")
    );
    ok(&submit(&url, withdraw(&publisher, 2, "m-new")).await);
    assert!(err(&served(&url, "m-new").await).contains("not in this node's catalog"));
}

#[tokio::test]
async fn two_named_publishers_that_disagree_serve_neither_version() {
    let _serial = SERIAL.lock().await;
    let (a, b) = (Key::new(PUBLISHER), Key::new(OTHER_PUBLISHER));
    let (url, _shutdown, _tmp, _node) = start(NodeConfig {
        catalog_publishers: vec![a.did(), b.did()],
        ..Default::default()
    })
    .await;
    ok(&submit(
        &url,
        publish(
            &a,
            1,
            &gguf("m-shared", b"one", LicenseTier::Permissive, false),
        ),
    )
    .await);
    ok(&submit(
        &url,
        publish(
            &b,
            1,
            &gguf("m-shared", b"one", LicenseTier::Permissive, false),
        ),
    )
    .await);
    // Agreement: both publish the same entry.
    assert_eq!(
        ok(&served(&url, "m-shared").await)["publishers"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    ok(&submit(
        &url,
        publish(
            &b,
            2,
            &gguf("m-shared", b"two", LicenseTier::Permissive, false),
        ),
    )
    .await);
    let e = err(&served(&url, "m-shared").await);
    assert!(e.contains("describe this model differently"), "{e}");
}

#[tokio::test]
async fn weights_that_differ_from_the_published_hash_refuse_the_load() {
    let _serial = SERIAL.lock().await;
    let (url, _shutdown, tmp, _node) = setup().await;
    let publisher = Key::new(PUBLISHER);
    let entry = gguf(
        "m-pinned",
        b"the published weights",
        LicenseTier::Permissive,
        false,
    );
    ok(&submit(&url, publish(&publisher, 1, &entry)).await);

    let models = tmp.path().join("models");
    std::fs::create_dir_all(&models).unwrap();
    std::fs::write(models.join("m-pinned.gguf"), b"not the published weights").unwrap();
    let r = call_as(
        &url,
        "tenzro_serveModel",
        json!({"model_id": "m-pinned"}),
        true,
    )
    .await;
    assert_eq!(r["error"]["code"], -32006, "{r}");
    assert!(
        err(&r).contains("catalog pins") && err(&r).contains("m-pinned.Q4_K_M.gguf"),
        "{r}"
    );

    // A manifest that contradicts the published hash is refused too.
    let c = &entry.components[0];
    let file = |sha256: String| tenzro_trust::FileEntry {
        path: c.path.clone(),
        size: c.size,
        sha256,
        blake3: "cd".repeat(32),
    };
    let forged = tenzro_trust::ModelManifest::new(&c.repo, vec![file("ab".repeat(32))]).unwrap();
    assert!(err(&submit(&url, forged.to_json()).await).contains("catalog pins"));
    let genuine = tenzro_trust::ModelManifest::new(&c.repo, vec![file(c.sha256.clone())]).unwrap();
    ok(&submit(&url, genuine.to_json()).await);
}

#[tokio::test]
async fn a_gated_model_is_refused_before_any_download() {
    let _serial = SERIAL.lock().await;
    let (url, _shutdown, tmp, _node) = setup().await;
    let publisher = Key::new(PUBLISHER);
    ok(&submit(
        &url,
        publish(
            &publisher,
            1,
            &gguf("m-gated", b"licensed", LicenseTier::CommercialCustom, true),
        ),
    )
    .await);

    let shown = ok(&served(&url, "m-gated").await).clone();
    assert_eq!(shown["entry"]["gated"], true);
    let r = call_as(
        &url,
        "tenzro_serveModel",
        json!({"model_id": "m-gated"}),
        true,
    )
    .await;
    let e = err(&r);
    assert!(e.contains("gated"), "{e}");
    assert!(!tmp.path().join("models").join("m-gated.gguf").exists());

    // Gated weights are offered only by a node whose operator accepted their
    // licence; this node's operator has not, so it refuses to host them.
    let c = gguf("m-gated", b"licensed", LicenseTier::CommercialCustom, true)
        .components
        .remove(0);
    let dir = tmp.path().join("held");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(&c.path), b"licensed").unwrap();
    let (size, sha256, blake3) = tenzro_trust::manifest::hash_file(&dir.join(&c.path)).unwrap();
    let held = tenzro_trust::ModelManifest::new(
        &c.repo,
        vec![tenzro_trust::FileEntry {
            path: c.path.clone(),
            size,
            sha256,
            blake3,
        }],
    )
    .unwrap();
    ok(&submit(&url, held.to_json()).await);
    let r = call_as(
        &url,
        "tenzro_hostModel",
        json!({"root": held.root_hex(), "path": dir}),
        true,
    )
    .await;
    let e = err(&r);
    assert!(
        e.contains("gated behind the licence") && e.contains("has not accepted"),
        "{e}"
    );
}

#[tokio::test]
async fn a_non_commercial_model_is_never_charged() {
    let _serial = SERIAL.lock().await;
    let (url, _shutdown, _tmp, node) = setup().await;
    let publisher = Key::new(PUBLISHER);
    ok(&submit(
        &url,
        publish(
            &publisher,
            1,
            &gguf("m-nc", b"nc", LicenseTier::NonCommercial, false),
        ),
    )
    .await);
    ok(&submit(
        &url,
        publish(
            &publisher,
            1,
            &gguf("m-open", b"open", LicenseTier::Permissive, false),
        ),
    )
    .await);

    assert!(tenzro_node::catalog_sync::non_commercial(&node, "m-nc"));
    assert!(!tenzro_node::catalog_sync::non_commercial(&node, "m-open"));
    for id in ["m-nc", "m-open"] {
        node.register_model_service(
            id,
            id,
            "Local Node",
            tenzro_types::model::ModelLocation::Local,
            "",
            "1B",
        );
    }
    let offers = node.list_model_services();
    let offer = |id: &str| {
        offers
            .iter()
            .find(|s| s.model_id == id)
            .unwrap()
            .pricing
            .clone()
    };
    let nc = offer("m-nc");
    assert_eq!(nc.min_charge, 0);
    assert!(nc.lines.values().all(|r| r.price == 0));
    assert!(nc.lines.contains_key("output_tokens"));
    assert!(offer("m-open").lines["input_tokens"].price > 0);
}

fn release(publisher: &Key, version: &str, sha: char) -> Value {
    let artifact = tenzro_trust::release::Artifact {
        platform: "x86_64-linux".into(),
        size: 1024,
        sha256: sha.to_string().repeat(64),
        blake3: "b".repeat(64),
    };
    publisher.sign(tenzro_trust::release::EngineRelease::unsigned(
        &publisher.did(),
        version,
        &[artifact],
    ))
}

#[tokio::test]
async fn an_engine_release_is_reported_only_from_a_named_publisher_and_never_installed() {
    let _serial = SERIAL.lock().await;
    let (url, _shutdown, _tmp, _node) = setup().await;
    let publisher = Key::new(PUBLISHER);
    let stranger = Key::new(OTHER_PUBLISHER);

    let r = ok(&call(&url, "tenzro_getEngineReleases", json!({})).await).clone();
    assert_eq!(r["releases"], json!([]));
    ok(&submit(&url, release(&publisher, "999.0.0", 'a')).await);
    ok(&submit(&url, release(&publisher, "0.0.1", 'c')).await);
    ok(&submit(&url, release(&stranger, "999.1.0", 'd')).await);
    // A version is published once: a different binary under it is refused.
    assert!(
        err(&submit(&url, release(&publisher, "999.0.0", 'e')).await).contains("already published")
    );
    // A release signed by someone other than its named publisher is refused.
    let forged = stranger.sign(tenzro_trust::release::EngineRelease::unsigned(
        &publisher.did(),
        "999.2.0",
        &[tenzro_trust::release::Artifact {
            platform: "x86_64-linux".into(),
            size: 1,
            sha256: "f".repeat(64),
            blake3: "f".repeat(64),
        }],
    ));
    assert!(submit(&url, forged).await.get("error").is_some());

    let r = ok(&call(&url, "tenzro_getEngineReleases", json!({})).await).clone();
    assert_eq!(r["available"], "999.0.0", "{r}");
    let versions: Vec<(&str, bool)> = r["releases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["version"].as_str().unwrap(),
                x["newer"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(versions, [("999.0.0", true), ("0.0.1", false)]);
    assert_eq!(r["running"], env!("CARGO_PKG_VERSION"));
}

/// Any publisher whose signing key's account holds a catalog publisher bond is
/// served with no publishers named, including an autonomous machine
/// whose DID is derived from a key its own TPM holds; a publisher without a
/// bond never is. An operator that names publishers narrows the bonded
/// publishers to those.
#[tokio::test]
async fn a_bonded_publisher_is_served_and_named_publishers_only_narrow() {
    let _serial = SERIAL.lock().await;
    let machine = Key::new(PUBLISHER);
    let did = tenzro_identity::TenzroDid::parse(&machine.did()).expect("a DID");
    assert!(!did.has_controller(), "the publisher is its own controller");

    let (url, _shutdown, _tmp, _node) = start(NodeConfig::default()).await;
    ok(&submit(
        &url,
        publish(
            &machine,
            1,
            &gguf("m-seed", b"seed", LicenseTier::Permissive, false),
        ),
    )
    .await);
    let got = ok(&served(&url, "m-seed").await).clone();
    assert_eq!(got["publishers"], json!([machine.did()]));
    assert_eq!(
        ok(&call(&url, "tenzro_listCatalog", json!({})).await)["status"]["named_publishers"],
        json!([])
    );

    // A publisher with no bond publishes into the ledger, and is not served.
    let unbonded = Key::new(OPERATOR);
    ok(&submit(
        &url,
        publish(
            &unbonded,
            1,
            &gguf("m-unbonded", b"unbonded", LicenseTier::Permissive, false),
        ),
    )
    .await);
    assert!(err(&served(&url, "m-unbonded").await).contains("not in this node's catalog"));
    drop(_shutdown);

    // An operator that names its own publishers serves only those of them
    // that are bonded.
    let other = Key::new(OTHER_PUBLISHER);
    let (url, _shutdown, _tmp, _node) = start(NodeConfig {
        catalog_publishers: vec![other.did()],
        ..Default::default()
    })
    .await;
    ok(&submit(
        &url,
        publish(
            &machine,
            1,
            &gguf("m-seed", b"seed", LicenseTier::Permissive, false),
        ),
    )
    .await);
    assert!(err(&served(&url, "m-seed").await).contains("not in this node's catalog"));
    ok(&submit(
        &url,
        publish(
            &other,
            1,
            &gguf("m-own", b"own", LicenseTier::Permissive, false),
        ),
    )
    .await);
    assert_eq!(ok(&served(&url, "m-own").await)["served"], true);
}
