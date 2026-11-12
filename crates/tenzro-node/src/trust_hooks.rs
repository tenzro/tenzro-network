//! Where the node applies trust records: its own serving admission, model
//! provenance and gossip.
//!
//! Everything here reads the [`tenzro_trust::TrustLedger`]. The operator
//! policy is this node's own; the network adds nothing of its own to it.

use std::sync::Arc;

use serde_json::Value;
use tenzro_trust::credential::Subject;
use tenzro_trust::{Applied, TrustLedger};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Gossip topic carrying trust records. Every receiver re-verifies.
pub const TRUST_TOPIC: &str = "tenzro/trust";

pub(crate) fn invalid(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: msg.into(),
        data: None,
    }
}

pub(crate) fn refused(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32003,
        message: msg.into(),
        data: None,
    }
}

pub(crate) fn ledger(node: &TenzroNode) -> Result<&Arc<TrustLedger>, JsonRpcError> {
    node.trust_ledger().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "trust ledger not initialized".into(),
        data: None,
    })
}

/// Whether the identity registry has revoked `did`.
pub(crate) fn did_revoked(node: &TenzroNode) -> impl Fn(&str) -> bool + '_ {
    move |did: &str| node.identity_registry().is_some_and(|r| r.is_revoked(did))
}

/// The subject a model id or name resolves to: its verified manifest.
pub(crate) fn model_subject(ledger: &TrustLedger, model_id: &str) -> Option<Subject> {
    ledger
        .verified_manifest_named(model_id)
        .map(|m| Subject::Model(m.root_hex()))
}

/// The trust credentials stated about `did`, each with its current state.
pub(crate) fn identity_credentials(node: &TenzroNode, did: &str) -> Vec<Value> {
    let Some(ledger) = node.trust_ledger() else {
        return Vec::new();
    };
    let now = chrono::Utc::now();
    let revoked = did_revoked(node);
    ledger
        .credentials_for(&Subject::Operator(did.to_string()))
        .iter()
        .map(|c| {
            serde_json::json!({
                "digest": c.digest,
                "issuer": c.issuer,
                "claim": c.claim,
                "validUntil": c.valid_until,
                "state": ledger.state(c, now, &revoked),
            })
        })
        .collect()
}

/// This node's own admission: refuse a model its published policy does not
/// serve, or one lacking the credentials the policy promises. A node without
/// a published policy has promised nothing and admits as before.
pub(crate) fn admit_own_model(node: &TenzroNode, model_id: &str) -> Result<(), JsonRpcError> {
    let (Some(ledger), Some(operator)) = (node.trust_ledger(), node.operator_did()) else {
        return Ok(());
    };
    let now = chrono::Utc::now();
    let Some(policy) = ledger.policy_in_force(&operator, now) else {
        return Ok(());
    };
    let subject = model_subject(ledger, model_id);
    let valid = subject
        .as_ref()
        .map(|s| ledger.valid_credentials_for(s, now, &did_revoked(node)))
        .unwrap_or_default();
    policy
        .admit_model(model_id, subject.as_ref(), &valid)
        .map_err(|e| refused(e.to_string()))
}

/// Apply a record received from anywhere, and re-assemble the model catalog
/// when the record can change it. Gossip receipt and RPC submission share
/// this path. A proven violation counts against the operator in every trust
/// verdict, and a validator flags it to consensus as a `PolicyViolation`
/// finding: the operator's compute bond is slashed once validators holding two
/// thirds of bonded stake have proved the same violation.
pub(crate) fn apply(
    ledger: &TrustLedger,
    catalog: Option<&crate::catalog_sync::CatalogSync>,
    findings: Option<&crate::agent_audit::FindingSink>,
    record: &Value,
) -> Result<Applied, tenzro_trust::TrustError> {
    if matches!(
        tenzro_trust::ledger::RecordKind::of(record),
        Ok(tenzro_trust::ledger::RecordKind::Manifest)
    ) {
        check_catalog_pins(&tenzro_trust::ModelManifest::from_json(record)?)?;
    }
    let applied = ledger.apply(record)?;
    if let (Some(v), Some(sink)) = (&applied.violation, findings) {
        let sink = sink.clone();
        let finding = tenzro_types::agent_audit::AuditFinding::PolicyViolation {
            violation_id: v.id.clone(),
            operator_did: v.operator.clone(),
        };
        tokio::spawn(async move { sink.flag(finding).await });
    }
    if applied.new
        && crate::catalog_sync::CatalogSync::affected_by(applied.kind)
        && let Some(catalog) = catalog
    {
        catalog.request_refresh();
    }
    Ok(applied)
}

/// [`apply`] against this node's ledger.
pub(crate) fn apply_record(
    node: &TenzroNode,
    record: &Value,
) -> Result<Applied, tenzro_trust::TrustError> {
    let ledger = node
        .trust_ledger()
        .ok_or_else(|| tenzro_trust::TrustError::Storage("trust ledger not initialized".into()))?;
    apply(
        ledger,
        node.catalog_sync().map(|c| c.as_ref()),
        node.finding_sink().as_ref(),
        record,
    )
}

/// Publish a record to peers.
pub(crate) fn broadcast(node: &TenzroNode, record: &Value) {
    use tenzro_network::{MessagePayload, NetworkMessage, NetworkService};
    let Some(network) = node.network().cloned() else {
        return;
    };
    let Ok(data) = serde_json::to_vec(record) else {
        return;
    };
    tokio::spawn(async move {
        let msg = NetworkMessage::new(MessagePayload::Custom {
            topic: TRUST_TOPIC.to_string(),
            data,
        });
        if let Err(e) = network.broadcast(TRUST_TOPIC, msg).await {
            tracing::warn!(error = %e, "trust record broadcast failed");
        }
    });
}

/// Subscribe to trust records from peers and apply each one.
pub(crate) fn spawn_subscriber(
    ledger: Arc<TrustLedger>,
    catalog: Option<Arc<crate::catalog_sync::CatalogSync>>,
    findings: Option<crate::agent_audit::FindingSink>,
    network: Arc<tenzro_network::TenzroNetworkService>,
) {
    use tenzro_network::{MessagePayload, NetworkService};
    tokio::spawn(async move {
        let mut rx = match network.subscribe(TRUST_TOPIC).await {
            Ok(rx) => rx,
            Err(e) => {
                tracing::warn!(error = %e, "could not subscribe to {TRUST_TOPIC}");
                return;
            }
        };
        while let Some(msg) = rx.recv().await {
            let MessagePayload::Custom { topic, data } = msg.payload else {
                continue;
            };
            if topic != TRUST_TOPIC || data.len() > 1024 * 1024 {
                continue;
            }
            let Ok(record) = serde_json::from_slice::<Value>(&data) else {
                continue;
            };
            if let Err(e) = apply(&ledger, catalog.as_deref(), findings.as_ref(), &record) {
                tracing::debug!(error = %e, "trust record from a peer refused");
            }
        }
    });
}

/// The licence the file `name`/`path` is gated behind, when the catalog
/// entry pinning it says its origin gates it. Such a file passes only between
/// nodes whose operators accepted the licence.
pub(crate) fn gating_licence(name: &str, path: &str) -> Option<String> {
    tenzro_model::catalog::file(name, path)
        .and_then(|(entry, _)| entry.gating_licence().map(str::to_string))
}

/// Binds the blob `blake3` of the file `name`/`path` to the licence it is
/// gated behind, before its bytes are published, so `resolver` serves it only
/// to nodes whose operator accepted that licence. Refuses when this node's
/// operator has not accepted it. A file no licence gates needs nothing.
pub(crate) async fn bind_gated(
    node: &TenzroNode,
    resolver: &tenzro_iroh::IrohBackedResolver,
    name: &str,
    path: &str,
    blake3: &str,
) -> Result<(), String> {
    let Some(licence) = gating_licence(name, path) else {
        return Ok(());
    };
    if !node
        .config()
        .model_licensing
        .accepted_license_ids
        .contains(&licence)
    {
        return Err(format!(
            "{name}/{path} is gated behind the licence {licence}, which this node's operator has not accepted \
             (--accept-license {licence})"
        ));
    }
    resolver
        .bind_licence(blake3, &licence)
        .await
        .map_err(|e| e.to_string())
}

/// Label of the hardware key a node signs its own origin attestations with.
pub const OBSERVER_KEY_LABEL: &str = "tenzro/node/trust-observer";

/// Refuse a manifest named after a Hub repository whose files contradict the
/// catalog's pinned hashes for that repository.
pub(crate) fn check_catalog_pins(
    m: &tenzro_trust::ModelManifest,
) -> Result<(), tenzro_trust::TrustError> {
    for f in &m.files {
        if let Some((_, pin)) = tenzro_model::catalog::file(&m.name, &f.path)
            && (pin.sha256 != f.sha256 || pin.size != f.size)
        {
            return Err(tenzro_trust::TrustError::FileMismatch {
                path: format!("{}/{}", m.name, f.path),
                reason: format!(
                    "the catalog pins SHA-256 {} ({} bytes)",
                    pin.sha256, pin.size
                ),
            });
        }
    }
    Ok(())
}

/// The provenance name of a GGUF model and the files it occupies on this
/// node, as `(path in the model, local path)`. A catalogued model is named by
/// its Hub repository and its files by their paths there, the names Hub
/// origin attestations use; any other model by its id and its file name.
/// `local` is the weight file the node resolves for the model (the first
/// shard of a split model).
pub(crate) fn gguf_files(
    model_id: &str,
    local: &std::path::Path,
) -> (String, Vec<(String, std::path::PathBuf)>) {
    let file_name = |p: &std::path::Path| {
        p.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string()
    };
    let Some(entry) = tenzro_model::catalog::get_model_by_id(model_id) else {
        return (
            model_id.to_string(),
            vec![(file_name(local), local.to_path_buf())],
        );
    };
    let Some((prefix, _)) = entry.hf_filename.split_once("-00001-of-") else {
        return (
            entry.hf_repo,
            vec![(entry.hf_filename, local.to_path_buf())],
        );
    };
    let repo_dir = entry
        .hf_filename
        .rsplit_once('/')
        .map(|(d, _)| format!("{d}/"))
        .unwrap_or_default();
    let shard_prefix = prefix.rsplit('/').next().unwrap_or(prefix).to_string();
    let mut files: Vec<(String, std::path::PathBuf)> = local
        .parent()
        .and_then(|dir| std::fs::read_dir(dir).ok())
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .filter(|p| {
            let n = file_name(p);
            n.starts_with(&shard_prefix) && n.contains("-of-")
        })
        .map(|p| (format!("{repo_dir}{}", file_name(&p)), p))
        .collect();
    files.sort();
    (entry.hf_repo, files)
}

/// Hash files off the async executor into manifest entries.
pub(crate) async fn hash_files(
    files: Vec<(String, std::path::PathBuf)>,
) -> Result<Vec<tenzro_trust::FileEntry>, JsonRpcError> {
    tokio::task::spawn_blocking(move || {
        files
            .into_iter()
            .map(|(path, local)| {
                let (size, sha256, blake3) = tenzro_trust::manifest::hash_file(&local)?;
                Ok(tenzro_trust::FileEntry {
                    path,
                    size,
                    sha256,
                    blake3,
                })
            })
            .collect::<Result<Vec<_>, tenzro_trust::TrustError>>()
    })
    .await
    .map_err(|e| refused(e.to_string()))?
    .map_err(|e| refused(e.to_string()))
}

/// Record a manifest of files this node holds and, when the node has a
/// hardware key, sign a `storage` origin attestation for them. Without a
/// hardware key the manifest is recorded and nothing is signed. Returns the
/// manifest root.
pub(crate) fn record_local_manifest(
    node: &TenzroNode,
    name: &str,
    files: Vec<tenzro_trust::FileEntry>,
) -> Result<String, JsonRpcError> {
    let m = tenzro_trust::ModelManifest::new(name, files).map_err(|e| invalid(e.to_string()))?;
    let doc = m.to_json();
    let applied = apply_record(node, &doc).map_err(|e| refused(e.to_string()))?;
    if applied.new {
        broadcast(node, &doc);
    }
    if let Some(signed) = sign_storage_observation(&m) {
        match apply_record(node, &signed) {
            Ok(applied) if applied.new => broadcast(node, &signed),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "own storage observation refused"),
        }
    }
    Ok(m.root_hex())
}

/// A `storage` origin attestation for `m`, signed by this machine's hardware
/// observer key. `None` on a machine without one.
fn sign_storage_observation(m: &tenzro_trust::ModelManifest) -> Option<Value> {
    let signer = tenzro_device_key::signer::open_or_create(OBSERVER_KEY_LABEL).ok()?;
    let pk = signer.public_key_sec1().ok()?;
    let did = tenzro_trust::proof::machine_did(&pk);
    let files: Vec<tenzro_trust::origin::ObservedFile> = m
        .files
        .iter()
        .map(|f| tenzro_trust::origin::ObservedFile {
            path: f.path.clone(),
            size: f.size,
            sha256: f.sha256.clone(),
            blake3: Some(f.blake3.clone()),
        })
        .collect();
    let now = chrono::Utc::now();
    let unsigned = tenzro_trust::OriginAttestation::unsigned(
        &did,
        tenzro_trust::OriginKind::Storage,
        &format!("tenzro:{did}"),
        &m.name,
        &files,
        now,
    );
    let opts = tenzro_trust::proof::options(&tenzro_trust::proof::ProofRequest {
        signer_did: did,
        public_key_sec1: pk,
        purpose: "assertionMethod".into(),
        created: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        rp_id: None,
    });
    let digest = tenzro_trust::proof::signing_digest(&unsigned, &opts);
    let sig = signer.sign_prehash(&digest).ok()?;
    Some(tenzro_trust::proof::attach_hardware(unsigned, opts, &sig))
}

/// What a load learned about the provenance of the files it loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoadProvenance {
    /// Every file matches a verified manifest; the roots of those manifests.
    Verified(Vec<String>),
    /// At least one file is listed by no verified manifest.
    Unverified,
}

impl LoadProvenance {
    pub(crate) fn to_json(&self) -> Value {
        match self {
            LoadProvenance::Verified(roots) => serde_json::json!({
                "status": "verified",
                "manifests": roots.iter().map(|r| format!("tenzro:model:{r}")).collect::<Vec<_>>(),
            }),
            LoadProvenance::Unverified => serde_json::json!({"status": "unverified"}),
        }
    }
}

/// Check files about to be loaded against the catalog's pins and the
/// verified manifests of the model named `name`, hashing each file once. A
/// file that differs from either refuses the load (-32006, naming the file);
/// a file no verified manifest lists loads, and the load is reported
/// unverified.
pub(crate) async fn verify_before_load(
    node: &TenzroNode,
    name: &str,
    files: Vec<(String, std::path::PathBuf)>,
) -> Result<LoadProvenance, JsonRpcError> {
    let ledger = node.trust_ledger().cloned();
    let model = name.to_string();
    let outcome = tokio::task::spawn_blocking(move || -> Result<LoadProvenance, String> {
        let total = files.len();
        let mut roots: Vec<String> = Vec::new();
        let mut verified = 0;
        for (path, local) in &files {
            let pin = tenzro_model::catalog::file(&model, path).map(|(_, c)| c);
            let listed = ledger.as_ref().and_then(|l| l.verified_entry(&model, path));
            if pin.is_none() && listed.is_none() {
                continue;
            }
            let (size, sha256, blake3) = tenzro_trust::manifest::hash_file(local).map_err(|e| format!("{path}: {e}"))?;
            if let Some(pin) = pin
                && (pin.sha256 != sha256 || pin.size != size) {
                    return Err(format!(
                        "{path} hashes to SHA-256 {sha256} ({size} bytes) but the catalog pins {} ({} bytes)",
                        pin.sha256, pin.size
                    ));
                }
            if let Some((root, entry)) = listed {
                if entry.size != size || entry.sha256 != sha256 || entry.blake3 != blake3 {
                    return Err(format!("{path} differs from the verified manifest tenzro:model:{root}"));
                }
                if !roots.contains(&root) {
                    roots.push(root);
                }
                verified += 1;
            }
        }
        Ok(if total > 0 && verified == total {
            LoadProvenance::Verified(roots)
        } else {
            LoadProvenance::Unverified
        })
    })
    .await
    .map_err(|e| refused(e.to_string()))?;
    outcome.map_err(|m| JsonRpcError {
        code: -32006,
        message: format!("{name}: {m}; refusing to load it"),
        data: None,
    })
}

/// Download hints for `files` of the model named `name`: each file a
/// verified manifest lists can be fetched from peers by its BLAKE3 content
/// address and checked against its SHA-256. `hints[i]` belongs to `files[i]`.
pub(crate) fn peer_hints(
    node: &TenzroNode,
    name: &str,
    files: &[String],
) -> Vec<Option<tenzro_model::PeerHint>> {
    let Some(ledger) = node.trust_ledger() else {
        return vec![None; files.len()];
    };
    files
        .iter()
        .map(|f| {
            ledger
                .verified_entry(name, f)
                .map(|(_, entry)| tenzro_model::PeerHint {
                    tenzro_uri: tenzro_types::tenzro_uri::TenzroUri::Blob {
                        hash: entry.blake3,
                        provider_hint: None,
                    },
                    sha256_hex: Some(entry.sha256),
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::p256::{P256KeyPair, P256Signer};
    use tenzro_trust::origin::{ObservedFile, OriginAttestation, OriginKind};

    /// An origin observer holding a P-256 key.
    fn observe(seed: u8, locator: &str, name: &str, files: &[ObservedFile]) -> Value {
        let key = P256Signer::from_keypair(&P256KeyPair::from_secret_bytes(&[seed; 32]).unwrap());
        let pk = key.public_key_sec1();
        let did = tenzro_trust::proof::machine_did(&pk);
        let now = chrono::Utc::now();
        let doc = OriginAttestation::unsigned(&did, OriginKind::Mirror, locator, name, files, now);
        let opts = tenzro_trust::proof::options(&tenzro_trust::proof::ProofRequest {
            signer_did: did,
            public_key_sec1: pk,
            purpose: "assertionMethod".into(),
            created: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            rp_id: None,
        });
        let digest = tenzro_trust::proof::signing_digest(&doc, &opts);
        let sig: [u8; 64] = key.sign_prehash(&digest).as_bytes().try_into().unwrap();
        tenzro_trust::proof::attach_hardware(doc, opts, &sig)
    }

    #[tokio::test]
    async fn a_load_is_checked_against_the_verified_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let config = crate::NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            models_dir: Some(tmp.path().join("models")),
            iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
            ..Default::default()
        };
        let mut node = TenzroNode::new(config).await.unwrap();
        node.start().await.unwrap();
        let name = "org/unpinned-model";
        let weights = tmp.path().join("weights.gguf");
        std::fs::write(&weights, b"weights the origins agree on".repeat(32)).unwrap();
        let files = vec![("model.gguf".to_string(), weights.clone())];

        // Nothing verified lists the file yet: it loads, unverified.
        let p = verify_before_load(&node, name, files.clone())
            .await
            .unwrap();
        assert_eq!(p, LoadProvenance::Unverified);

        let entries = hash_files(files.clone()).await.unwrap();
        // Applied directly: record_local_manifest would also reach for this
        // machine's hardware key.
        let manifest = tenzro_trust::ModelManifest::new(name, entries.clone()).unwrap();
        let root = manifest.root_hex();
        apply_record(&node, &manifest.to_json()).unwrap();
        let observed: Vec<ObservedFile> = entries
            .iter()
            .map(|f| ObservedFile {
                path: f.path.clone(),
                size: f.size,
                sha256: f.sha256.clone(),
                blake3: Some(f.blake3.clone()),
            })
            .collect();
        apply_record(&node, &observe(31, "https://a.example/m", name, &observed)).unwrap();
        let p = verify_before_load(&node, name, files.clone())
            .await
            .unwrap();
        assert_eq!(
            p,
            LoadProvenance::Unverified,
            "one origin does not verify a manifest"
        );
        apply_record(&node, &observe(32, "https://b.example/m", name, &observed)).unwrap();
        let p = verify_before_load(&node, name, files.clone())
            .await
            .unwrap();
        assert_eq!(p, LoadProvenance::Verified(vec![root]));

        // Bytes that differ from the verified manifest are refused, naming the file.
        let mut bytes = std::fs::read(&weights).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&weights, bytes).unwrap();
        let e = verify_before_load(&node, name, files).await.unwrap_err();
        assert_eq!(e.code, -32006);
        assert!(e.message.contains("model.gguf"), "{}", e.message);
        node.stop().await.ok();
    }
}
