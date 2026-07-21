//! Governance-anchored model-hash transparency log.
//!
//! A node that fetches model weights over the peer network (iroh/BLAKE3) needs
//! a trust root to decide whether the bytes it received are the *canonical*
//! weights for a given `model_id`, rather than a tampered substitute. This
//! module holds that trust root: a per-model canonical hash the validator
//! committee has witnessed and HotStuff-2 has finalized.
//!
//! ## Recording model
//!
//! Recording a canonical hash is **permissionless with first-recorder-wins
//! semantics**: the first recorder to assert a hash for a `model_id` binds it.
//! A second, differing assertion for the same `model_id` is rejected — unless
//! it carries a governance override (produced by the on-chain
//! `GovernanceEngine` via precompile `0x1005`), which is the only way to
//! correct or revoke a previously-recorded hash. Serving and fetching stay
//! fully permissionless; only the canonical-hash assertion is anchored.
//!
//! ## Two hashes per artifact
//!
//! Every weight file contributes both a BLAKE3 content address (the hash iroh
//! indexes and verifies streaming) and a SHA-256 digest (the canonical Tenzro
//! integrity hash). The [`ModelManifest`] binds the whole file set, and
//! [`compute_model_manifest_hash`] reduces it to a single SHA-256 the
//! transparency log records.

use crate::error::{ModelError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_storage::kv::{KvStore, CF_MODEL_HASHES};
use tenzro_types::primitives::Hash;
use tracing::{debug, info, warn};

/// Domain tag for the canonical per-model manifest hash. Distinct from the
/// sealed-model and training sealed-manifest tags so the three hash spaces
/// never collide.
pub const MODEL_MANIFEST_DOMAIN: &[u8] = b"tenzro/model/manifest";

/// BLAKE3 content address of a byte slice — the same hash iroh indexes and
/// verifies streaming. Kept here so every BLAKE3 measurement in the workspace
/// (registration, verify-before-load, transparency log) resolves to one
/// definition and one crate dependency.
pub fn blake3_of_bytes(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// One weight file inside a model's canonical manifest. Both hashes are
/// derived from the same bytes: `blake3` is the peer content address (what
/// iroh indexes and verifies during transfer), `sha256` is the Tenzro
/// integrity digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelFileRecord {
    /// File name as it appears in the model repository (e.g. `model.gguf` or
    /// `onnx/model.onnx`).
    pub filename: String,
    /// SHA-256 of the file bytes.
    pub sha256: [u8; 32],
    /// BLAKE3 of the file bytes — the iroh content address.
    pub blake3: [u8; 32],
    /// File size in bytes.
    pub size: u64,
}

impl ModelFileRecord {
    /// Computes both hashes over a byte slice. `blake3` is the iroh content
    /// address; `sha256` is the Tenzro integrity digest — both over the same
    /// bytes.
    pub fn from_bytes(filename: impl Into<String>, bytes: &[u8]) -> Self {
        let sha256 = {
            let mut h = Sha256::new();
            h.update(bytes);
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.finalize());
            out
        };
        let blake3 = blake3_of_bytes(bytes);
        Self {
            filename: filename.into(),
            sha256,
            blake3,
            size: bytes.len() as u64,
        }
    }

    /// Computes both hashes for a file on disk. The record's `filename` is the
    /// provided logical name, not the on-disk path, so a peer can request the
    /// file by its repository-relative name.
    pub fn from_path(
        filename: impl Into<String>,
        path: &std::path::Path,
    ) -> Result<Self> {
        let bytes = std::fs::read(path)
            .map_err(|e| ModelError::StorageError(format!("read {}: {e}", path.display())))?;
        Ok(Self::from_bytes(filename, &bytes))
    }
}

/// The full canonical file set for a model. Reduced to a single manifest hash
/// by [`compute_model_manifest_hash`], which is what the transparency log
/// binds to a `model_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelManifest {
    /// The model this manifest describes.
    pub model_id: String,
    /// The weight files, in any order — the manifest hash sorts them.
    pub files: Vec<ModelFileRecord>,
}

impl ModelManifest {
    /// A single-file manifest (the common GGUF / single-file-ONNX case).
    pub fn single_file(
        model_id: impl Into<String>,
        filename: impl Into<String>,
        sha256: [u8; 32],
        blake3: [u8; 32],
        size: u64,
    ) -> Self {
        Self {
            model_id: model_id.into(),
            files: vec![ModelFileRecord {
                filename: filename.into(),
                sha256,
                blake3,
                size,
            }],
        }
    }
}

/// Canonical SHA-256 over a model's file set. Files contribute in
/// filename-ascending order so the hash is independent of the order they were
/// discovered in. Each file binds its name, SHA-256, BLAKE3, and size.
pub fn compute_model_manifest_hash(m: &ModelManifest) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(MODEL_MANIFEST_DOMAIN);
    hasher.update((m.model_id.len() as u32).to_le_bytes());
    hasher.update(m.model_id.as_bytes());
    let mut files: Vec<&ModelFileRecord> = m.files.iter().collect();
    files.sort_by(|a, b| a.filename.cmp(&b.filename));
    hasher.update((files.len() as u32).to_le_bytes());
    for f in files {
        hasher.update((f.filename.len() as u32).to_le_bytes());
        hasher.update(f.filename.as_bytes());
        hasher.update(f.sha256);
        hasher.update(f.blake3);
        hasher.update(f.size.to_le_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Hash::new(out)
}

/// The canonical hash record for a model, as anchored in the transparency log.
///
/// The primary weight file's BLAKE3 is surfaced directly so a fetcher can
/// build a peer request without decoding the full manifest; the manifest hash
/// binds the whole file set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalModelHash {
    /// The model this record binds.
    pub model_id: String,
    /// BLAKE3 content address of the primary weight file — the value a peer
    /// fetch is verified against. For single-file models this is the file's
    /// BLAKE3; for bundles it is the BLAKE3 of the first file in
    /// filename-ascending order.
    pub blake3: [u8; 32],
    /// SHA-256 integrity digest of the primary weight file.
    pub sha256: [u8; 32],
    /// SHA-256 over the whole file set — see [`compute_model_manifest_hash`].
    pub manifest_hash: [u8; 32],
    /// DID of the first recorder that asserted this hash. First recorder wins.
    pub recorder_did: String,
    /// Consensus epoch in which the hash was recorded.
    pub recorded_at_epoch: u64,
    /// Set when a governance override replaced a previously-recorded hash.
    pub governance_overridden: bool,
}

/// Governance-anchored transparency log binding `model_id → CanonicalModelHash`.
///
/// In-memory index over a `CF_MODEL_HASHES` RocksDB column family. First
/// recorder wins; a differing later assertion is rejected unless it carries a
/// governance override. Write-through on every mutation, hydrate on
/// construction.
pub struct ModelHashRegistry {
    records: DashMap<String, CanonicalModelHash>,
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for ModelHashRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelHashRegistry")
            .field("records", &self.records.len())
            .field("storage", &self.storage.is_some())
            .finish()
    }
}

impl ModelHashRegistry {
    /// Creates an in-memory-only registry (tests / ephemeral nodes).
    pub fn new() -> Self {
        Self {
            records: DashMap::new(),
            storage: None,
        }
    }

    /// Creates a registry backed by RocksDB, hydrating the in-memory index
    /// from `CF_MODEL_HASHES` on construction.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let records = DashMap::new();
        match storage.get_keys_with_prefix(CF_MODEL_HASHES, b"") {
            Ok(keys) => {
                let mut hydrated = 0usize;
                for key_bytes in keys {
                    match storage.get(CF_MODEL_HASHES, &key_bytes) {
                        Ok(Some(data)) => match serde_json::from_slice::<CanonicalModelHash>(&data) {
                            Ok(rec) => {
                                records.insert(rec.model_id.clone(), rec);
                                hydrated += 1;
                            }
                            Err(e) => warn!(
                                "Failed to decode CanonicalModelHash during hydration: {}",
                                e
                            ),
                        },
                        Ok(None) => {}
                        Err(e) => warn!("Failed to read CF_MODEL_HASHES key during hydration: {}", e),
                    }
                }
                if hydrated > 0 {
                    info!("Hydrated {} model-hash record(s) from CF_MODEL_HASHES", hydrated);
                }
            }
            Err(e) => warn!("Failed to scan CF_MODEL_HASHES during hydration: {}", e),
        }
        Self {
            records,
            storage: Some(storage),
        }
    }

    fn persist(&self, rec: &CanonicalModelHash) {
        if let Some(ref storage) = self.storage {
            match serde_json::to_vec(rec) {
                Ok(data) => {
                    if let Err(e) = storage.put(CF_MODEL_HASHES, rec.model_id.as_bytes(), &data) {
                        warn!(
                            "Failed to persist canonical hash for {} to CF_MODEL_HASHES: {}",
                            rec.model_id, e
                        );
                    }
                }
                Err(e) => warn!(
                    "Failed to serialize canonical hash for {}: {}",
                    rec.model_id, e
                ),
            }
        }
    }

    /// Records the canonical hash for a model. First recorder wins: if a
    /// record already exists for `model_id` and the asserted `manifest_hash`
    /// differs, this is rejected with [`ModelError::HashAlreadyRecorded`].
    /// Re-asserting an identical hash is idempotent (the recorder is not
    /// overwritten). Use [`ModelHashRegistry::override_hash`] with a
    /// governance proof to correct or revoke.
    pub fn record(
        &self,
        manifest: &ModelManifest,
        recorder_did: impl Into<String>,
        epoch: u64,
    ) -> Result<CanonicalModelHash> {
        let model_id = manifest.model_id.clone();
        let manifest_hash = compute_model_manifest_hash(manifest);
        let (blake3, sha256) = primary_file_hashes(manifest)?;

        if let Some(existing) = self.records.get(&model_id) {
            if existing.manifest_hash == manifest_hash.0 {
                debug!("Canonical hash for {} re-asserted identically; no-op", model_id);
                return Ok(existing.clone());
            }
            return Err(ModelError::HashAlreadyRecorded(model_id));
        }

        let rec = CanonicalModelHash {
            model_id: model_id.clone(),
            blake3,
            sha256,
            manifest_hash: manifest_hash.0,
            recorder_did: recorder_did.into(),
            recorded_at_epoch: epoch,
            governance_overridden: false,
        };
        self.persist(&rec);
        self.records.insert(model_id.clone(), rec.clone());
        info!("Recorded canonical hash for {} at epoch {}", model_id, epoch);
        Ok(rec)
    }

    /// Replaces the canonical hash for a model under a governance decision.
    /// The caller (the node RPC layer) is responsible for having verified the
    /// governance override before calling this — the registry only marks the
    /// resulting record as `governance_overridden`.
    pub fn override_hash(
        &self,
        manifest: &ModelManifest,
        recorder_did: impl Into<String>,
        epoch: u64,
    ) -> Result<CanonicalModelHash> {
        let model_id = manifest.model_id.clone();
        let manifest_hash = compute_model_manifest_hash(manifest);
        let (blake3, sha256) = primary_file_hashes(manifest)?;
        let rec = CanonicalModelHash {
            model_id: model_id.clone(),
            blake3,
            sha256,
            manifest_hash: manifest_hash.0,
            recorder_did: recorder_did.into(),
            recorded_at_epoch: epoch,
            governance_overridden: true,
        };
        self.persist(&rec);
        self.records.insert(model_id.clone(), rec.clone());
        info!("Governance override of canonical hash for {} at epoch {}", model_id, epoch);
        Ok(rec)
    }

    /// Looks up the canonical hash record for a model.
    pub fn get(&self, model_id: &str) -> Option<CanonicalModelHash> {
        self.records.get(model_id).map(|r| r.clone())
    }

    /// Lists every recorded canonical hash.
    pub fn list(&self) -> Vec<CanonicalModelHash> {
        self.records.iter().map(|e| e.value().clone()).collect()
    }

    /// Verifies that a fetched artifact's manifest matches the recorded
    /// canonical hash for its model. Returns `Ok(())` when they match,
    /// [`ModelError::HashMismatch`] when a record exists but differs, and
    /// [`ModelError::HashNotRecorded`] when no canonical hash is on record.
    pub fn verify(&self, manifest: &ModelManifest) -> Result<()> {
        let model_id = &manifest.model_id;
        let recorded = self
            .records
            .get(model_id)
            .ok_or_else(|| ModelError::HashNotRecorded(model_id.clone()))?;
        let computed = compute_model_manifest_hash(manifest);
        if recorded.manifest_hash == computed.0 {
            Ok(())
        } else {
            Err(ModelError::HashMismatch(model_id.clone()))
        }
    }
}

impl Default for ModelHashRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `(blake3, sha256)` of the primary file — the first file in
/// filename-ascending order. Errors if the manifest has no files.
fn primary_file_hashes(m: &ModelManifest) -> Result<([u8; 32], [u8; 32])> {
    let primary = m
        .files
        .iter()
        .min_by(|a, b| a.filename.cmp(&b.filename))
        .ok_or_else(|| ModelError::EmptyManifest(m.model_id.clone()))?;
    Ok((primary.blake3, primary.sha256))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::kv::MemoryStore;

    fn file(name: &str, seed: u8) -> ModelFileRecord {
        ModelFileRecord {
            filename: name.to_string(),
            sha256: [seed; 32],
            blake3: [seed.wrapping_add(1); 32],
            size: 1024,
        }
    }

    #[test]
    fn manifest_hash_order_independent() {
        let m1 = ModelManifest {
            model_id: "qwen3-0.6b".to_string(),
            files: vec![file("a.gguf", 1), file("b.gguf", 2)],
        };
        let m2 = ModelManifest {
            model_id: "qwen3-0.6b".to_string(),
            files: vec![file("b.gguf", 2), file("a.gguf", 1)],
        };
        assert_eq!(compute_model_manifest_hash(&m1), compute_model_manifest_hash(&m2));
    }

    #[test]
    fn first_recorder_wins() {
        let reg = ModelHashRegistry::new();
        let m = ModelManifest::single_file("m", "m.gguf", [1; 32], [2; 32], 10);
        reg.record(&m, "did:tenzro:machine:alice", 1).unwrap();

        // identical re-assert is idempotent
        reg.record(&m, "did:tenzro:machine:bob", 2).unwrap();

        // differing assertion is rejected
        let m2 = ModelManifest::single_file("m", "m.gguf", [9; 32], [8; 32], 10);
        assert!(matches!(
            reg.record(&m2, "did:tenzro:machine:bob", 3),
            Err(ModelError::HashAlreadyRecorded(_))
        ));

        // recorder is still the first one
        assert_eq!(reg.get("m").unwrap().recorder_did, "did:tenzro:machine:alice");
    }

    #[test]
    fn governance_override_replaces() {
        let reg = ModelHashRegistry::new();
        let m = ModelManifest::single_file("m", "m.gguf", [1; 32], [2; 32], 10);
        reg.record(&m, "did:tenzro:machine:alice", 1).unwrap();

        let m2 = ModelManifest::single_file("m", "m.gguf", [9; 32], [8; 32], 10);
        let rec = reg.override_hash(&m2, "did:tenzro:governance", 5).unwrap();
        assert!(rec.governance_overridden);
        assert_eq!(reg.get("m").unwrap().blake3, [8; 32]);
    }

    #[test]
    fn verify_matches_and_mismatches() {
        let reg = ModelHashRegistry::new();
        let m = ModelManifest::single_file("m", "m.gguf", [1; 32], [2; 32], 10);
        assert!(matches!(reg.verify(&m), Err(ModelError::HashNotRecorded(_))));

        reg.record(&m, "did:tenzro:machine:alice", 1).unwrap();
        assert!(reg.verify(&m).is_ok());

        let tampered = ModelManifest::single_file("m", "m.gguf", [9; 32], [8; 32], 10);
        assert!(matches!(reg.verify(&tampered), Err(ModelError::HashMismatch(_))));
    }

    #[test]
    fn hydrate_from_storage() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        {
            let reg = ModelHashRegistry::with_storage(storage.clone());
            let m = ModelManifest::single_file("m", "m.gguf", [1; 32], [2; 32], 10);
            reg.record(&m, "did:tenzro:machine:alice", 1).unwrap();
        }
        let reg2 = ModelHashRegistry::with_storage(storage.clone());
        assert_eq!(reg2.get("m").unwrap().recorder_did, "did:tenzro:machine:alice");
        assert_eq!(reg2.list().len(), 1);
    }
}
