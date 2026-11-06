//! `tenzro_receipt` on the local `/v1/chat/completions` path, streamed and
//! non-streamed, against a real served model — not a mock.
//!
//! Ignored by default: it downloads a few hundred megabytes and runs a model
//! on CPU, the same live-model contract as `live_tool_calls.rs`. Run with
//! `--ignored`; `TENZRO_LIVE_MODEL` picks the catalog id (default
//! `qwen3-0.6b`) and `TENZRO_MODELS_DIR` where it is stored.
#![cfg(feature = "inference")]

// The model parser runs as this binary started again.
tenzro_node::enter_parse_jail_child_before_tests!();

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_model::hf_download::{DownloadProgress, DownloadState, HfDownloader, SourcePolicy};
use tenzro_node::inference_admission::NodeInferenceAdmission;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

mod common;
mod dpop_bearer;
mod passkey_holder;

/// The catalog publisher this test bonds at genesis and publishes the model
/// through, the way a node learns every model.
struct Publisher(tenzro_crypto::p256::P256Signer);

impl Publisher {
    fn new(seed: u8) -> Self {
        Publisher(tenzro_crypto::p256::P256Signer::from_keypair(
            &tenzro_crypto::p256::P256KeyPair::from_secret_bytes(&[seed; 32]).unwrap(),
        ))
    }
    fn did(&self) -> String {
        tenzro_trust::proof::machine_did(&self.0.public_key_sec1())
    }
    /// The ledger account of this key, where its catalog role stake is held.
    fn account(&self) -> [u8; 32] {
        tenzro_crypto::composite::account_slot(&self.0.public_key_sec1()[1..])
    }
    /// A signed catalog record publishing `entry`.
    fn publish(&self, entry: &tenzro_catalog::CatalogEntry) -> Value {
        use tenzro_trust::proof::{ProofRequest, attach_hardware, options, signing_digest};
        let body = serde_json::to_value(entry).unwrap();
        let doc =
            tenzro_trust::catalog::CatalogRecord::unsigned(&self.did(), entry.id(), 1, Some(&body));
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

/// The catalog entry for `model_id` as the project ships it, read from the
/// catalog crate's source data. It reaches the node only as a record the
/// bonded publisher signs.
fn shipped_entry(model_id: &str) -> tenzro_catalog::CatalogEntry {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tenzro-catalog/seed");
    tenzro_catalog::read_entries(&dir)
        .expect("the shipped entries parse")
        .into_iter()
        .find(|e| e.id() == model_id)
        .unwrap_or_else(|| panic!("no shipped entry for {model_id}"))
}

fn models_dir() -> PathBuf {
    std::env::var("TENZRO_MODELS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("tenzro-live-models"))
}

fn free_udp_port() -> std::net::SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free loopback port")
}

struct Gateway {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
}

impl Gateway {
    /// Boots a node that serves `model_id` from a pre-downloaded checkpoint
    /// at `dir`, open to any caller — this test is about the receipt a
    /// served response carries, not about access control.
    async fn boot_serving(
        model_id: &str,
        dir: &std::path::Path,
        publisher: &Publisher,
        entry: &tenzro_catalog::CatalogEntry,
    ) -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        {
            use tenzro_types::node_access::{MethodClass, NodeAccessPolicy, Rule, SurfaceRule};
            let mut policy = NodeAccessPolicy::default();
            policy.rules.push(SurfaceRule {
                surface: None,
                class: MethodClass::Inference,
                rule: Rule::Open,
            });
            dpop_bearer::write_policy(tmp.path(), &policy);
        }
        let iroh = tenzro_iroh::TenzroIrohConfig {
            bind_addr: free_udp_port(),
            ..Default::default()
        };
        // A machine identity, registered on chain: `tenzro_receipt` is a
        // signature, and `sign_local` has no key to sign with — so no
        // receipt rides the response at all — until this node has one.
        let mut owner = common::MachineOwner::generate(0x62);
        let mut genesis = tenzro_node::config::GenesisConfig::default_testnet();
        genesis
            .role_stakes
            .push(tenzro_node::config::GenesisRoleStake {
                address: hex::encode(publisher.account()),
                role: "catalog".into(),
                stake: None,
                capacity: Default::default(),
                endpoint: None,
            });
        let config = NodeConfig {
            genesis: Some(genesis),
            catalog_publishers: vec![publisher.did()],
            data_dir: tmp.path().to_path_buf(),
            models_dir: Some(dir.to_path_buf()),
            operator_did: Some(owner.machine_did()),
            iroh,
            ..Default::default()
        };
        let mut node = TenzroNode::new(config).await.expect("node creation");
        node.start().await.expect("node start");
        node.served_models
            .insert(model_id.to_string(), Some(tenzro_types::Visibility::Public));
        // The concurrency cap a `tenzro serveModel` command (or the boot-time
        // reconciler) would otherwise size from a hardware probe: this test
        // inserts into `served_models` directly rather than through that
        // path, so nothing has registered a cap yet, and the host this runs
        // on may have too little memory free at probe time for even one real
        // slot of this model's KV cache — a true "no capacity on this box
        // right now" that a fixed test cap sidesteps on purpose, since this
        // test is about the receipt in the response, not about capacity
        // sizing (that has its own coverage).
        node.load_tracker.register_model(model_id, 1);
        let node = Arc::new(node);
        let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string())
            .with_inference_admission(Arc::new(NodeInferenceAdmission::for_node(&node)));
        let handle =
            tokio::spawn(
                async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await },
            );
        let addr = addr_rx.await.expect("bound address");
        let base_url = format!("http://{addr}");
        // The owner's human identity must exist on chain before a machine
        // can be registered under it — `enroll` is the HTTP call that
        // records it, so it needs the server already listening.
        let client = reqwest::Client::new();
        owner.enroll(&client, &base_url).await;
        owner.register_machine(&node).await;
        // The model reaches the catalog the way every model does: a record
        // signed by a bonded catalog publisher.
        let submitted: Value = client
            .post(&base_url)
            .json(
                &json!({"jsonrpc": "2.0", "id": 1, "method": "tenzro_submitTrustRecord",
                          "params": {"record": publisher.publish(entry)}}),
            )
            .send()
            .await
            .expect("submit the catalog record")
            .json()
            .await
            .expect("submit reply");
        assert!(
            submitted.get("error").is_none(),
            "the bonded publisher's record was refused: {submitted}"
        );
        Self {
            base_url,
            shutdown,
            handle,
            _tmp: tmp,
        }
    }

    async fn chat(&self, body: Value) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/v1/chat/completions", self.base_url))
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

#[tokio::test]
#[ignore = "downloads a model, runs inference on CPU, and signs the receipt with this machine hardware identity key (a TPM)"]
async fn a_local_chat_completion_carries_a_tenzro_receipt_streamed_and_not() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let model_id = std::env::var("TENZRO_LIVE_MODEL").unwrap_or_else(|_| "qwen3-0.6b".into());
    let dir = models_dir();
    std::fs::create_dir_all(&dir).unwrap();

    // The node learns the model from a bonded publisher before anything is
    // downloaded or served.
    let publisher = Publisher::new(0x42);
    let gw = Gateway::boot_serving(&model_id, &dir, &publisher, &shipped_entry(&model_id)).await;
    let entry = tenzro_model::catalog::get_model_by_id(&model_id)
        .expect("the node serves the entry its bonded publisher published");

    let (tx, _rx) = tokio::sync::watch::channel(DownloadProgress {
        model_id: model_id.clone(),
        status: DownloadState::Pending,
        progress_percent: 0.0,
        downloaded_bytes: 0,
        total_bytes: 0,
    });
    let downloader = HfDownloader::new(dir.clone());
    if !downloader.is_downloaded(&model_id) {
        downloader
            .download_model(&entry, None, SourcePolicy::HuggingFace, tx)
            .await
            .expect("pinned download");
    }

    // Non-streamed: the completion body carries `tenzro_receipt` directly.
    let resp = gw
        .chat(json!({"model": model_id, "max_tokens": 16,
                      "messages": [{"role": "user", "content": "Say hello in one word."}]}))
        .await;
    assert!(resp.status().is_success(), "{:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.get("tenzro_receipt").is_some_and(|r| !r.is_null()),
        "non-streamed completion carries no tenzro_receipt: {body}"
    );

    // Streamed: no chunk before the last carries a receipt, and the last
    // chunk does — the final-chunk contract this item is proving.
    let resp = gw
        .chat(json!({"model": model_id, "max_tokens": 16, "stream": true,
                      "messages": [{"role": "user", "content": "Say hello in one word."}]}))
        .await;
    assert!(resp.status().is_success(), "{:?}", resp.text().await);
    let text = resp.text().await.unwrap();
    let chunks: Vec<Value> = text
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter(|d| *d != "[DONE]")
        .map(|d| serde_json::from_str(d).unwrap_or_else(|e| panic!("bad SSE chunk json: {e}: {d}")))
        .collect();
    assert!(!chunks.is_empty(), "no SSE data lines in: {text}");
    let (last, earlier) = chunks.split_last().unwrap();
    for chunk in earlier {
        assert!(
            chunk.get("tenzro_receipt").is_none(),
            "a non-final chunk already carries tenzro_receipt: {chunk}"
        );
    }
    assert!(
        last.get("tenzro_receipt").is_some_and(|r| !r.is_null()),
        "the final streamed chunk carries no tenzro_receipt: {last}"
    );

    gw.shutdown().await;
}
