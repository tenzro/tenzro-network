//! Confidential-tier sealed-shard manifest handling.
//!
//! The Confidential tier protects sponsor data from ingestion through
//! training: the dataset is sharded and encrypted under per-shard
//! AES-256-GCM keys, those data keys are wrapped one-per-trainer to the
//! trainer's attested enclave public key,
//! and the wrapped envelopes are gathered into a [`SealedDatasetManifest`]
//! that the sponsor publishes alongside the task spec.
//!
//! This module owns the *protocol-side* pieces:
//!
//! - [`compute_manifest_hash`] — canonical SHA-256 over the envelope set,
//!   used to bind a manifest to a `tee://...` `dataset_ref`.
//! - [`validate_confidential_enrollment`] — gate run at trainer enroll time
//!   that checks (a) tier requires a sealed manifest, (b) the trainer has an
//!   envelope in it, (c) the trainer's TEE attestation matches the enclave
//!   identity the sponsor sealed to.
//! - [`SealedManifestStore`] — write-through cache for manifests, keyed by
//!   `task_id` under the `manifest:` prefix in `CF_TRAINING_RUNS`.
//!
//! Key wrapping itself (HPKE encrypt / decrypt) is **deliberately not here**.
//! The sponsor wraps in their offline data-preparation tool; the trainer
//! unwraps inside the TEE enclave (Python reference trainer, helper at
//! `integrations/trainer/tenzro_trainer/confidential.py`). The Rust protocol
//! layer never sees a cleartext data key.

use crate::error::{Result, TrainingError};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_storage::{KvStore, CF_TRAINING_RUNS};
use tenzro_types::primitives::Hash;
use tenzro_types::training::{
    SealedDatasetManifest, SealedShardEnvelope, TrainingAttestation, TrainingTier,
};

/// Canonical SHA-256 over the envelope set of a manifest.
///
/// Order is normalized by `(shard_index, trainer_did)` ascending before
/// hashing. The hash is independent of the sponsor signature and timestamp
/// so two sponsors signing the same envelope set produce the same hash.
pub fn compute_manifest_hash(envelopes: &[SealedShardEnvelope]) -> Hash {
    let mut sorted: Vec<&SealedShardEnvelope> = envelopes.iter().collect();
    sorted.sort_by(|a, b| {
        a.shard_index
            .cmp(&b.shard_index)
            .then_with(|| a.trainer_did.cmp(&b.trainer_did))
    });
    let mut hasher = Sha256::new();
    hasher.update(b"tenzro/training/sealed-manifest");
    for e in sorted {
        hasher.update((e.trainer_did.len() as u32).to_le_bytes());
        hasher.update(e.trainer_did.as_bytes());
        hasher.update(e.shard_index.to_le_bytes());
        hasher.update(e.shard_ciphertext_hash.as_bytes());
        hasher.update(e.shard_ciphertext_bytes.to_le_bytes());
        hasher.update((e.wrapped_data_key.len() as u32).to_le_bytes());
        hasher.update(&e.wrapped_data_key);
        hasher.update((e.wrap_alg.len() as u32).to_le_bytes());
        hasher.update(e.wrap_alg.as_bytes());
        hasher.update((e.enclave_pubkey.len() as u32).to_le_bytes());
        hasher.update(&e.enclave_pubkey);
        hasher.update((e.enclave_measurements_hex.len() as u32).to_le_bytes());
        hasher.update(e.enclave_measurements_hex.as_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Hash::new(out)
}

/// Parse the `tee://<hex>` form into the bound manifest hash. Returns
/// `None` for any other scheme — the caller turns that into a missing-manifest
/// error.
pub fn parse_tee_dataset_ref(dataset_ref: &str) -> Option<Hash> {
    let suffix = dataset_ref.strip_prefix("tee://")?;
    let bytes = hex::decode(suffix).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(Hash::new(out))
}

/// Verify a sealed manifest matches the `tee://...` reference in the task
/// spec — i.e. that the envelope set the trainer fetched is the one the
/// sponsor committed to at posting time.
pub fn verify_manifest_binding(
    task_id: &str,
    dataset_ref: &str,
    manifest: &SealedDatasetManifest,
) -> Result<()> {
    let expected = parse_tee_dataset_ref(dataset_ref).ok_or_else(|| {
        TrainingError::InvalidTaskSpec(format!(
            "Confidential-tier task {} has non-tee:// dataset_ref '{}'",
            task_id, dataset_ref
        ))
    })?;
    let actual = compute_manifest_hash(&manifest.envelopes);
    if actual != expected {
        return Err(TrainingError::SealedManifestHashMismatch {
            task_id: task_id.to_string(),
            expected: hex::encode(expected.as_bytes()),
            actual: hex::encode(actual.as_bytes()),
        });
    }
    Ok(())
}

/// Validate that a Confidential-tier trainer is authorized by the sealed
/// manifest before letting them enroll.
///
/// The trainer's per-round [`TrainingAttestation`] carries the enclave
/// program/firmware measurements and the enclave pubkey (encoded inside
/// `report_hex` — vendor-specific layout). The sponsor's envelope binds the
/// same fields. We require:
///
/// 1. The manifest has an envelope addressed to this trainer DID.
/// 2. The envelope's `enclave_pubkey` is byte-equal to what the trainer is
///    presenting via a side-channel (the caller passes
///    `trainer_enclave_pubkey` — typically extracted from the attestation
///    report by the syncer's TEE verifier).
/// 3. The envelope's `enclave_measurements_hex` is byte-equal to the
///    measurements the trainer's attestation report carries
///    (`trainer_measurements_hex`).
///
/// All three are exact-match checks: a mismatch means the trainer is not
/// running the enclave the sponsor sealed to, and admission is rejected.
pub fn validate_confidential_enrollment(
    task_id: &str,
    tier: TrainingTier,
    manifest: Option<&SealedDatasetManifest>,
    trainer_did: &str,
    trainer_attestation: Option<&TrainingAttestation>,
    trainer_enclave_pubkey: &[u8],
    trainer_measurements_hex: &str,
) -> Result<()> {
    // Only enforce at Confidential tier. Open + Verified tiers don't need
    // a manifest.
    if tier != TrainingTier::Confidential {
        return Ok(());
    }
    if trainer_attestation.is_none() {
        return Err(TrainingError::AttestationRequired(tier));
    }
    let manifest = manifest.ok_or_else(|| TrainingError::SealedManifestMissing {
        task_id: task_id.to_string(),
    })?;
    let envelope = manifest
        .envelope_for(trainer_did)
        .ok_or_else(|| TrainingError::SealedEnvelopeMissing {
            task_id: task_id.to_string(),
            trainer_did: trainer_did.to_string(),
        })?;
    if envelope.enclave_pubkey != trainer_enclave_pubkey {
        return Err(TrainingError::EnclaveBindingMismatch {
            trainer_did: trainer_did.to_string(),
            field: "enclave_pubkey",
        });
    }
    if envelope.enclave_measurements_hex != trainer_measurements_hex {
        return Err(TrainingError::EnclaveBindingMismatch {
            trainer_did: trainer_did.to_string(),
            field: "enclave_measurements_hex",
        });
    }
    Ok(())
}

/// Write-through cache for [`SealedDatasetManifest`]s. Keyed by `task_id`
/// under the `manifest:` prefix in `CF_TRAINING_RUNS`. Manifests are loaded
/// on first access and rehydrated on node startup via [`Self::hydrate`].
pub struct SealedManifestStore {
    cache: DashMap<String, Arc<SealedDatasetManifest>>,
    storage: Option<Arc<dyn KvStore>>,
}

impl Default for SealedManifestStore {
    fn default() -> Self {
        Self {
            cache: DashMap::new(),
            storage: None,
        }
    }
}

impl SealedManifestStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        Self {
            cache: DashMap::new(),
            storage: Some(storage),
        }
    }

    /// Restore all persisted manifests at node startup. Returns the count
    /// loaded.
    pub fn hydrate(&self) -> Result<usize> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(0),
        };
        let pairs = storage
            .scan_prefix(CF_TRAINING_RUNS, b"manifest:")
            .map_err(|e| TrainingError::Storage(format!("hydrate sealed manifests: {}", e)))?;
        let mut count = 0;
        for (_key, value) in pairs {
            let manifest: SealedDatasetManifest = serde_json::from_slice(&value)
                .map_err(|e| TrainingError::Serialization(format!("decode manifest: {}", e)))?;
            let task_id = manifest.task_id.clone();
            self.cache.insert(task_id, Arc::new(manifest));
            count += 1;
        }
        Ok(count)
    }

    /// Install a manifest (write-through). Recomputes the manifest hash and
    /// stamps it into the in-memory copy so callers reading from the cache
    /// see the canonical hash even if the sponsor sent zeros in that field.
    pub fn put(&self, mut manifest: SealedDatasetManifest) -> Result<Arc<SealedDatasetManifest>> {
        manifest.manifest_hash = compute_manifest_hash(&manifest.envelopes);
        let task_id = manifest.task_id.clone();
        if let Some(storage) = &self.storage {
            let key = format!("manifest:{}", task_id);
            let value = serde_json::to_vec(&manifest)
                .map_err(|e| TrainingError::Serialization(e.to_string()))?;
            storage
                .put(CF_TRAINING_RUNS, key.as_bytes(), &value)
                .map_err(|e| TrainingError::Storage(e.to_string()))?;
        }
        let arc = Arc::new(manifest);
        self.cache.insert(task_id, arc.clone());
        Ok(arc)
    }

    pub fn get(&self, task_id: &str) -> Option<Arc<SealedDatasetManifest>> {
        self.cache.get(task_id).map(|v| v.clone())
    }
}

// ---------------------------------------------------------------------------
// Sealed shard ciphertext distribution (Phase B2, #217)
// ---------------------------------------------------------------------------

/// Compute the canonical SHA-256 over a sealed shard ciphertext. This is the
/// hash a sponsor writes into
/// [`SealedShardEnvelope::shard_ciphertext_hash`] when building a manifest,
/// and the hash a trainer recomputes after fetching the ciphertext bytes.
///
/// Domain-separated with `"tenzro/training/sealed-shard"` so the same byte
/// string can never collide with a payload hash from
/// [`crate::compute_payload_hash`] (`"tenzro/training/payload"`).
pub fn compute_shard_ciphertext_hash(bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(b"tenzro/training/sealed-shard");
    hasher.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Hash::new(out)
}

/// Verify a fetched shard ciphertext against the [`SealedShardEnvelope`]
/// declarations. Mirrors [`crate::verify_payload`]: a fast size check first
/// (cheap, catches truncation early), then the SHA-256 compare.
///
/// Belt-and-braces on top of the transport's own integrity check (iroh-blobs
/// verifies BLAKE3 over every transferred chunk; this catches a wiring bug
/// between the transport-layer hash and the protocol-layer hash).
pub fn verify_shard_ciphertext(envelope: &SealedShardEnvelope, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 != envelope.shard_ciphertext_bytes {
        return Err(TrainingError::SealedShardSizeMismatch {
            shard_index: envelope.shard_index,
            declared: envelope.shard_ciphertext_bytes,
            actual: bytes.len() as u64,
        });
    }
    let actual = compute_shard_ciphertext_hash(bytes);
    if actual != envelope.shard_ciphertext_hash {
        return Err(TrainingError::SealedShardHashMismatch {
            shard_index: envelope.shard_index,
            declared: envelope.shard_ciphertext_hash.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

/// Content-addressed publish/fetch surface for sealed shard ciphertexts.
///
/// Mirrors [`crate::GradientPayloadStore`] but for the Confidential-tier
/// per-shard encrypted bytes:
///
/// - **Sponsor side** (offline data-prep tool, or sponsor's node):
///   `publish(ciphertext) -> Hash` returns the protocol-side SHA-256 (the
///   value written into [`SealedShardEnvelope::shard_ciphertext_hash`]). The
///   adapter records whatever transport-layer locator it needs (e.g. iroh
///   BLAKE3 hex) keyed by the SHA-256, exactly as
///   [`crate::IrohGradientStore`] does for gradients.
///
/// - **Trainer side** (Python reference trainer enclave, via JSON-RPC):
///   `fetch(envelope) -> Bytes` looks up the ciphertext by
///   `envelope.shard_ciphertext_hash`. The implementation MUST call
///   [`verify_shard_ciphertext`] before returning — a wiring bug between
///   transport-layer and protocol-layer hashes is detected at the contract
///   boundary, not silently inside the enclave.
///
/// Phase B2 (#217) lands [`crate::confidential::SealedShardStore`] alongside
/// the [`InstallSealedManifest`](crate::TrainingGossipMessage) gossip event:
/// sponsor publishes shards locally, announces the manifest on
/// `tenzro/training` so remote trainers and witnesses can install it, and
/// trainers fetch shard ciphertexts via this trait when their inner training
/// loop needs them.
#[async_trait]
pub trait SealedShardStore: Send + Sync {
    /// Adapter identifier for status / logs (e.g. `"iroh_blobs"`,
    /// `"in_memory"`).
    fn id(&self) -> &'static str;

    /// Publish a sealed shard ciphertext. Returns the canonical
    /// `shard_ciphertext_hash` (SHA-256, domain-separated). The adapter is
    /// responsible for any transport-layer indexing (BLAKE3 mapping, etc.).
    async fn publish(&self, ciphertext: Bytes) -> Result<Hash>;

    /// Fetch a sealed shard ciphertext referenced by an envelope. The
    /// implementation MUST verify `shard_ciphertext_bytes` and
    /// `shard_ciphertext_hash` before returning.
    async fn fetch(&self, envelope: &SealedShardEnvelope) -> Result<Bytes>;
}

/// In-memory [`SealedShardStore`] for tests and single-node runs. Keys
/// ciphertexts by the protocol-side SHA-256 hash.
pub struct InMemorySealedShardStore {
    store: DashMap<Hash, Bytes>,
}

impl Default for InMemorySealedShardStore {
    fn default() -> Self {
        Self {
            store: DashMap::new(),
        }
    }
}

impl InMemorySealedShardStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn arc() -> Arc<dyn SealedShardStore> {
        Arc::new(Self::new())
    }
}

#[async_trait]
impl SealedShardStore for InMemorySealedShardStore {
    fn id(&self) -> &'static str {
        "in_memory"
    }

    async fn publish(&self, ciphertext: Bytes) -> Result<Hash> {
        let hash = compute_shard_ciphertext_hash(&ciphertext);
        self.store.insert(hash, ciphertext);
        Ok(hash)
    }

    async fn fetch(&self, envelope: &SealedShardEnvelope) -> Result<Bytes> {
        let bytes = self
            .store
            .get(&envelope.shard_ciphertext_hash)
            .map(|r| r.value().clone())
            .ok_or_else(|| {
                TrainingError::Internal(format!(
                    "sealed shard ciphertext not found: {} (shard_index={})",
                    envelope.shard_ciphertext_hash, envelope.shard_index,
                ))
            })?;
        verify_shard_ciphertext(envelope, &bytes)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::primitives::{Signature, Timestamp};

    fn sample_envelope(trainer_did: &str, shard_index: u32) -> SealedShardEnvelope {
        SealedShardEnvelope {
            trainer_did: trainer_did.to_string(),
            shard_index,
            shard_ciphertext_hash: Hash::new([0xaa; 32]),
            shard_ciphertext_bytes: 1_048_576,
            wrapped_data_key: vec![0xbb; 96],
            wrap_alg: "hpke-x25519-hkdf-sha256-aes-256-gcm".to_string(),
            enclave_pubkey: vec![0xcc; 32],
            enclave_measurements_hex: "deadbeef".to_string(),
            created_at: Timestamp::now(),
        }
    }

    fn sample_manifest(task_id: &str) -> SealedDatasetManifest {
        let envelopes = vec![
            sample_envelope("did:tenzro:machine:alice", 0),
            sample_envelope("did:tenzro:machine:bob", 1),
        ];
        let manifest_hash = compute_manifest_hash(&envelopes);
        SealedDatasetManifest {
            task_id: task_id.to_string(),
            sponsor_did: "did:tenzro:human:sponsor".to_string(),
            manifest_hash,
            envelopes,
            sponsor_signature: Signature::default(),
            created_at: Timestamp::now(),
        }
    }

    fn sample_attestation() -> TrainingAttestation {
        TrainingAttestation {
            vendor: "intel-tdx".to_string(),
            report_hex: "00".to_string(),
            program_hash: Hash::new([0xee; 32]),
            shard_hash: Hash::new([0xaa; 32]),
        }
    }

    #[test]
    fn manifest_hash_is_order_independent() {
        let env_a = sample_envelope("did:tenzro:machine:alice", 0);
        let env_b = sample_envelope("did:tenzro:machine:bob", 1);
        let h1 = compute_manifest_hash(&[env_a.clone(), env_b.clone()]);
        let h2 = compute_manifest_hash(&[env_b, env_a]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn parse_tee_ref_roundtrip() {
        let h = Hash::new([0x42; 32]);
        let s = format!("tee://{}", hex::encode(h.as_bytes()));
        assert_eq!(parse_tee_dataset_ref(&s), Some(h));
        assert_eq!(parse_tee_dataset_ref("ipfs://abc"), None);
        assert_eq!(parse_tee_dataset_ref("tee://short"), None);
    }

    #[test]
    fn verify_manifest_binding_accepts_matching_ref() {
        let m = sample_manifest("task-c1");
        let dataset_ref = format!("tee://{}", hex::encode(m.manifest_hash.as_bytes()));
        verify_manifest_binding("task-c1", &dataset_ref, &m).unwrap();
    }

    #[test]
    fn verify_manifest_binding_rejects_wrong_hash() {
        let m = sample_manifest("task-c1");
        let dataset_ref = format!("tee://{}", hex::encode([0x55; 32]));
        let err = verify_manifest_binding("task-c1", &dataset_ref, &m).unwrap_err();
        match err {
            TrainingError::SealedManifestHashMismatch { task_id, .. } => {
                assert_eq!(task_id, "task-c1");
            }
            _ => panic!("expected SealedManifestHashMismatch, got {:?}", err),
        }
    }

    #[test]
    fn confidential_enrollment_open_tier_skips_check() {
        validate_confidential_enrollment(
            "task-o1",
            TrainingTier::Open,
            None,
            "did:tenzro:machine:any",
            None,
            &[],
            "",
        )
        .unwrap();
    }

    #[test]
    fn confidential_enrollment_requires_attestation() {
        let m = sample_manifest("task-c1");
        let err = validate_confidential_enrollment(
            "task-c1",
            TrainingTier::Confidential,
            Some(&m),
            "did:tenzro:machine:alice",
            None,
            &[0xcc; 32],
            "deadbeef",
        )
        .unwrap_err();
        match err {
            TrainingError::AttestationRequired(TrainingTier::Confidential) => {}
            _ => panic!("expected AttestationRequired, got {:?}", err),
        }
    }

    #[test]
    fn confidential_enrollment_requires_manifest() {
        let att = sample_attestation();
        let err = validate_confidential_enrollment(
            "task-c1",
            TrainingTier::Confidential,
            None,
            "did:tenzro:machine:alice",
            Some(&att),
            &[0xcc; 32],
            "deadbeef",
        )
        .unwrap_err();
        match err {
            TrainingError::SealedManifestMissing { task_id } => assert_eq!(task_id, "task-c1"),
            _ => panic!("expected SealedManifestMissing, got {:?}", err),
        }
    }

    #[test]
    fn confidential_enrollment_rejects_unknown_trainer() {
        let m = sample_manifest("task-c1");
        let att = sample_attestation();
        let err = validate_confidential_enrollment(
            "task-c1",
            TrainingTier::Confidential,
            Some(&m),
            "did:tenzro:machine:carol",
            Some(&att),
            &[0xcc; 32],
            "deadbeef",
        )
        .unwrap_err();
        match err {
            TrainingError::SealedEnvelopeMissing { trainer_did, .. } => {
                assert_eq!(trainer_did, "did:tenzro:machine:carol");
            }
            _ => panic!("expected SealedEnvelopeMissing, got {:?}", err),
        }
    }

    #[test]
    fn confidential_enrollment_rejects_pubkey_mismatch() {
        let m = sample_manifest("task-c1");
        let att = sample_attestation();
        let err = validate_confidential_enrollment(
            "task-c1",
            TrainingTier::Confidential,
            Some(&m),
            "did:tenzro:machine:alice",
            Some(&att),
            &[0xdd; 32],
            "deadbeef",
        )
        .unwrap_err();
        match err {
            TrainingError::EnclaveBindingMismatch { trainer_did, field } => {
                assert_eq!(trainer_did, "did:tenzro:machine:alice");
                assert_eq!(field, "enclave_pubkey");
            }
            _ => panic!("expected EnclaveBindingMismatch(enclave_pubkey), got {:?}", err),
        }
    }

    #[test]
    fn confidential_enrollment_rejects_measurement_mismatch() {
        let m = sample_manifest("task-c1");
        let att = sample_attestation();
        let err = validate_confidential_enrollment(
            "task-c1",
            TrainingTier::Confidential,
            Some(&m),
            "did:tenzro:machine:alice",
            Some(&att),
            &[0xcc; 32],
            "facade",
        )
        .unwrap_err();
        match err {
            TrainingError::EnclaveBindingMismatch { field, .. } => {
                assert_eq!(field, "enclave_measurements_hex");
            }
            _ => panic!("expected EnclaveBindingMismatch(measurements), got {:?}", err),
        }
    }

    #[test]
    fn confidential_enrollment_accepts_matching_envelope() {
        let m = sample_manifest("task-c1");
        let att = sample_attestation();
        validate_confidential_enrollment(
            "task-c1",
            TrainingTier::Confidential,
            Some(&m),
            "did:tenzro:machine:alice",
            Some(&att),
            &[0xcc; 32],
            "deadbeef",
        )
        .unwrap();
    }

    fn make_envelope(shard_index: u32, bytes: &[u8]) -> SealedShardEnvelope {
        SealedShardEnvelope {
            trainer_did: "did:tenzro:machine:t".to_string(),
            shard_index,
            shard_ciphertext_hash: compute_shard_ciphertext_hash(bytes),
            shard_ciphertext_bytes: bytes.len() as u64,
            wrapped_data_key: vec![0xbb; 96],
            wrap_alg: "hpke-x25519-hkdf-sha256-aes-256-gcm".to_string(),
            enclave_pubkey: vec![0xcc; 32],
            enclave_measurements_hex: "deadbeef".to_string(),
            created_at: Timestamp::now(),
        }
    }

    #[test]
    fn shard_hash_is_domain_separated_from_payload_hash() {
        // Same bytes hashed under shard vs. payload tags must produce
        // distinct hashes — protects against a wiring bug confusing
        // gradients with sealed ciphertexts.
        let bytes = b"some bytes that could be either";
        let h_shard = compute_shard_ciphertext_hash(bytes);
        let h_payload = crate::compute_payload_hash(bytes);
        assert_ne!(h_shard, h_payload);
    }

    #[test]
    fn verify_shard_ciphertext_accepts_matching_bytes() {
        let bytes = b"sealed shard ciphertext bytes";
        let env = make_envelope(0, bytes);
        verify_shard_ciphertext(&env, bytes).unwrap();
    }

    #[test]
    fn verify_shard_ciphertext_rejects_size_mismatch() {
        let bytes = b"sealed shard ciphertext bytes";
        let mut env = make_envelope(7, bytes);
        env.shard_ciphertext_bytes += 1;
        let err = verify_shard_ciphertext(&env, bytes).unwrap_err();
        match err {
            TrainingError::SealedShardSizeMismatch { shard_index, .. } => {
                assert_eq!(shard_index, 7)
            }
            _ => panic!("expected SealedShardSizeMismatch, got {:?}", err),
        }
    }

    #[test]
    fn verify_shard_ciphertext_rejects_hash_mismatch() {
        let bytes = b"sealed shard ciphertext bytes";
        let mut env = make_envelope(3, bytes);
        env.shard_ciphertext_hash = Hash::new([0xff; 32]);
        let err = verify_shard_ciphertext(&env, bytes).unwrap_err();
        match err {
            TrainingError::SealedShardHashMismatch { shard_index, .. } => {
                assert_eq!(shard_index, 3)
            }
            _ => panic!("expected SealedShardHashMismatch, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn in_memory_sealed_shard_store_round_trips() {
        let store = InMemorySealedShardStore::new();
        let bytes = Bytes::from_static(b"sealed-shard-ciphertext-blob");
        let hash = store.publish(bytes.clone()).await.unwrap();
        assert_eq!(hash, compute_shard_ciphertext_hash(&bytes));

        let env = SealedShardEnvelope {
            trainer_did: "did:tenzro:machine:t".to_string(),
            shard_index: 0,
            shard_ciphertext_hash: hash,
            shard_ciphertext_bytes: bytes.len() as u64,
            wrapped_data_key: vec![0xbb; 96],
            wrap_alg: "hpke-x25519-hkdf-sha256-aes-256-gcm".to_string(),
            enclave_pubkey: vec![0xcc; 32],
            enclave_measurements_hex: "deadbeef".to_string(),
            created_at: Timestamp::now(),
        };
        let fetched = store.fetch(&env).await.unwrap();
        assert_eq!(fetched, bytes);
    }

    #[tokio::test]
    async fn in_memory_sealed_shard_store_missing_is_internal_err() {
        let store = InMemorySealedShardStore::new();
        let env = SealedShardEnvelope {
            trainer_did: "did:tenzro:machine:t".to_string(),
            shard_index: 0,
            shard_ciphertext_hash: Hash::new([0; 32]),
            shard_ciphertext_bytes: 0,
            wrapped_data_key: vec![],
            wrap_alg: "hpke-x25519-hkdf-sha256-aes-256-gcm".to_string(),
            enclave_pubkey: vec![],
            enclave_measurements_hex: String::new(),
            created_at: Timestamp::now(),
        };
        let err = store.fetch(&env).await.unwrap_err();
        assert!(matches!(err, TrainingError::Internal(_)));
    }
}
