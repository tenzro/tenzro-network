//! Sealed-model distribution: encrypted shard serving for private models.
//!
//! A private model's weights never travel in cleartext. The owner seals the
//! artifact into fixed-size shards, each encrypted under a single content key
//! (AES-256-GCM), publishes the ciphertext shards to the content-addressed
//! blob store, and wraps the content key once per named recipient using
//! X25519 envelope encryption (`x25519-envelope-aes-256-gcm`). The signed
//! [`SealedModelManifest`] binds the shard set, the recipient set, and the
//! plaintext artifact hash together — a recipient fetches the ciphertext
//! shards by `tenzro://` URI, unwraps the content key with their X25519
//! secret, decrypts, reassembles, and verifies the plaintext hash.
//!
//! Recipients are identified by DID + X25519 public key. A recipient entry
//! may additionally carry an attestation report hash, pinning the key to a
//! specific TEE identity the owner verified out-of-band (same binding model
//! as Confidential-tier training enrollment).
//!
//! This module owns the seal/unseal pipeline and the write-through
//! [`SealedModelStore`]. Manifest signing is Ed25519 over
//! [`SealedModelManifest::manifest_hash`] — the node signs with its announce
//! key via [`SealedModelManifest::attach_signature`] and any peer verifies
//! with [`SealedModelManifest::verify_signature`].

use crate::error::{ModelError, Result};
use crate::hf_download::BlobFetcher;
use bytes::Bytes;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use tenzro_crypto::encryption::{
    envelope_decrypt, envelope_encrypt, EncryptedEnvelope, SymmetricKey, X25519KeyPair,
    X25519PublicKey,
};
use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_crypto::signatures::{verify as verify_ed25519, Signature};
use tenzro_storage::kv::{KvStore, CF_MODELS};
use tenzro_types::primitives::Hash;
use tenzro_types::tenzro_uri::TenzroUri;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

/// Domain tag for per-shard ciphertext hashes.
pub const SEALED_SHARD_DOMAIN: &[u8] = b"tenzro/model/sealed-shard";

/// Domain tag for the manifest hash.
pub const SEALED_MANIFEST_DOMAIN: &[u8] = b"tenzro/model/sealed-manifest";

/// The only key-wrap scheme this module produces or accepts: X25519
/// ephemeral-static envelope encryption carrying an AES-256-GCM content key
/// (`tenzro_crypto::encryption::envelope_encrypt`).
pub const SEALED_WRAP_ALG: &str = "x25519-envelope-aes-256-gcm";

/// Default plaintext shard size: 256 MiB.
pub const DEFAULT_SHARD_BYTES: u64 = 256 * 1024 * 1024;

/// Storage key prefix for sealed-model manifests in `CF_MODELS`.
const SEALED_KEY_PREFIX: &[u8] = b"sealed:";

/// One encrypted shard of a sealed model artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedModelShard {
    /// Zero-based shard index; shards reassemble in index order.
    pub index: u32,
    /// Plaintext byte length of this shard (last shard may be short).
    pub plaintext_bytes: u64,
    /// Ciphertext byte length as published (nonce-prefixed AES-256-GCM).
    pub ciphertext_bytes: u64,
    /// Domain-separated SHA-256 of the ciphertext
    /// (`SEALED_SHARD_DOMAIN || model_id || index_le || ciphertext`).
    pub ciphertext_hash: Hash,
    /// `tenzro://blob/<blake3-hex>` URI of the published ciphertext.
    pub blob_uri: String,
}

/// A named recipient authorized to unwrap the content key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedRecipient {
    /// Recipient DID (`did:tenzro:...`).
    pub did: String,
    /// Recipient X25519 public key the content key is wrapped to.
    pub x25519_pubkey: [u8; 32],
    /// Content key wrapped for this recipient (`SEALED_WRAP_ALG`).
    pub wrapped_key: EncryptedEnvelope,
    /// Optional TEE attestation report hash the owner verified before
    /// sealing to this key — pins the recipient key to an enclave identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_hash: Option<Hash>,
}

/// Recipient specification supplied to [`seal_model_file`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientSpec {
    /// Recipient DID.
    pub did: String,
    /// Recipient X25519 public key (32 bytes).
    pub x25519_pubkey: [u8; 32],
    /// Optional attestation report hash to record on the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_hash: Option<Hash>,
}

/// Signed manifest binding a sealed model's shard set and recipient set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedModelManifest {
    /// Model registry identifier the sealed artifact belongs to.
    pub model_id: String,
    /// Artifact filename (e.g. `qwen3-0.6b-q4_k_m.gguf`).
    pub artifact_name: String,
    /// SHA-256 of the plaintext artifact — verified after reassembly.
    pub model_hash: Hash,
    /// Total plaintext byte length.
    pub total_bytes: u64,
    /// Plaintext shard size used when sealing (last shard may be short).
    pub shard_bytes: u64,
    /// Encrypted shards in index order.
    pub shards: Vec<SealedModelShard>,
    /// Recipients authorized to unwrap the content key.
    pub recipients: Vec<SealedRecipient>,
    /// Key-wrap scheme identifier; always [`SEALED_WRAP_ALG`].
    pub wrap_alg: String,
    /// DID of the sealing owner.
    pub owner_did: String,
    /// Unix milliseconds at seal time.
    pub created_at: u64,
    /// Canonical hash of the fields above (see [`compute_manifest_hash`]).
    pub manifest_hash: Hash,
    /// Ed25519 signature over `manifest_hash` bytes by the owner node's
    /// announce key. Empty until [`SealedModelManifest::attach_signature`].
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Ed25519 public key that produced `signature`.
    #[serde(default)]
    pub signer_pubkey: Vec<u8>,
}

impl SealedModelManifest {
    /// Attaches the owner's Ed25519 signature over `manifest_hash`.
    pub fn attach_signature(&mut self, signature: Vec<u8>, signer_pubkey: Vec<u8>) {
        self.signature = signature;
        self.signer_pubkey = signer_pubkey;
    }

    /// Verifies the attached Ed25519 signature over `manifest_hash` and that
    /// the recorded `manifest_hash` matches a recomputation over the fields.
    pub fn verify_signature(&self) -> Result<()> {
        let recomputed = compute_manifest_hash(self);
        if recomputed != self.manifest_hash {
            return Err(ModelError::SealedModel(format!(
                "manifest hash mismatch for '{}': recorded {} recomputed {}",
                self.model_id, self.manifest_hash, recomputed
            )));
        }
        if self.signature.is_empty() || self.signer_pubkey.is_empty() {
            return Err(ModelError::SealedModel(format!(
                "manifest for '{}' is unsigned",
                self.model_id
            )));
        }
        let pk = PublicKey::new(KeyType::Ed25519, self.signer_pubkey.clone());
        let sig = Signature::new(KeyType::Ed25519, self.signature.clone());
        verify_ed25519(&pk, self.manifest_hash.as_bytes(), &sig).map_err(|e| {
            ModelError::SealedModel(format!(
                "manifest signature invalid for '{}': {}",
                self.model_id, e
            ))
        })
    }

    /// Finds the recipient entry for `did`, if present.
    pub fn recipient(&self, did: &str) -> Option<&SealedRecipient> {
        self.recipients.iter().find(|r| r.did == did)
    }
}

/// Canonical SHA-256 over a manifest's binding fields. Excludes
/// `manifest_hash` itself and the signature pair. Shards contribute in index
/// order; recipients are normalized by DID ascending.
pub fn compute_manifest_hash(m: &SealedModelManifest) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(SEALED_MANIFEST_DOMAIN);
    hasher.update((m.model_id.len() as u32).to_le_bytes());
    hasher.update(m.model_id.as_bytes());
    hasher.update((m.artifact_name.len() as u32).to_le_bytes());
    hasher.update(m.artifact_name.as_bytes());
    hasher.update(m.model_hash.as_bytes());
    hasher.update(m.total_bytes.to_le_bytes());
    hasher.update(m.shard_bytes.to_le_bytes());
    hasher.update((m.wrap_alg.len() as u32).to_le_bytes());
    hasher.update(m.wrap_alg.as_bytes());
    hasher.update((m.owner_did.len() as u32).to_le_bytes());
    hasher.update(m.owner_did.as_bytes());
    hasher.update(m.created_at.to_le_bytes());
    let mut shards: Vec<&SealedModelShard> = m.shards.iter().collect();
    shards.sort_by_key(|s| s.index);
    for s in shards {
        hasher.update(s.index.to_le_bytes());
        hasher.update(s.plaintext_bytes.to_le_bytes());
        hasher.update(s.ciphertext_bytes.to_le_bytes());
        hasher.update(s.ciphertext_hash.as_bytes());
        hasher.update((s.blob_uri.len() as u32).to_le_bytes());
        hasher.update(s.blob_uri.as_bytes());
    }
    let mut recipients: Vec<&SealedRecipient> = m.recipients.iter().collect();
    recipients.sort_by(|a, b| a.did.cmp(&b.did));
    for r in recipients {
        hasher.update((r.did.len() as u32).to_le_bytes());
        hasher.update(r.did.as_bytes());
        hasher.update(r.x25519_pubkey);
        hasher.update((r.wrapped_key.encrypted_key.len() as u32).to_le_bytes());
        hasher.update(&r.wrapped_key.encrypted_key);
        hasher.update((r.wrapped_key.encrypted_data.len() as u32).to_le_bytes());
        hasher.update(&r.wrapped_key.encrypted_data);
        hasher.update(r.wrapped_key.sender_public_key);
        match &r.attestation_hash {
            Some(h) => {
                hasher.update([1u8]);
                hasher.update(h.as_bytes());
            }
            None => hasher.update([0u8]),
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Hash::new(out)
}

/// Domain-separated ciphertext hash for one shard.
pub fn compute_shard_ciphertext_hash(model_id: &str, index: u32, ciphertext: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(SEALED_SHARD_DOMAIN);
    hasher.update((model_id.len() as u32).to_le_bytes());
    hasher.update(model_id.as_bytes());
    hasher.update(index.to_le_bytes());
    hasher.update(ciphertext);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Hash::new(out)
}

/// Seals a model artifact on disk into encrypted shards, publishes each
/// ciphertext shard via the blob fetcher, and returns the unsigned manifest.
///
/// The artifact is streamed in `shard_bytes` chunks — memory use is bounded
/// by one shard, not the artifact size. A single random AES-256-GCM content
/// key encrypts every shard (fresh nonce per shard, prepended by
/// `SymmetricKey::encrypt`); the key is then wrapped once per recipient.
/// The caller signs the returned manifest with the node's announce key via
/// [`SealedModelManifest::attach_signature`].
pub async fn seal_model_file(
    path: &Path,
    model_id: &str,
    artifact_name: &str,
    owner_did: &str,
    recipients: &[RecipientSpec],
    shard_bytes: u64,
    fetcher: &dyn BlobFetcher,
) -> Result<SealedModelManifest> {
    if recipients.is_empty() {
        return Err(ModelError::SealedModel(
            "sealing requires at least one recipient".to_string(),
        ));
    }
    if shard_bytes == 0 {
        return Err(ModelError::SealedModel("shard_bytes must be non-zero".to_string()));
    }

    let content_key = SymmetricKey::generate();
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| ModelError::SealedModel(format!("open {}: {}", path.display(), e)))?;

    let mut plaintext_hasher = Sha256::new();
    let mut shards: Vec<SealedModelShard> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut index: u32 = 0;
    let mut buf = vec![0u8; shard_bytes as usize];

    loop {
        // Fill the shard buffer (read() may return short counts mid-file).
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = file
                .read(&mut buf[filled..])
                .await
                .map_err(|e| ModelError::SealedModel(format!("read {}: {}", path.display(), e)))?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        let chunk = &buf[..filled];
        plaintext_hasher.update(chunk);
        total_bytes += filled as u64;

        let ciphertext = content_key
            .encrypt(chunk)
            .map_err(|e| ModelError::SealedModel(format!("shard {} encrypt: {}", index, e)))?;
        let ciphertext_hash = compute_shard_ciphertext_hash(model_id, index, &ciphertext);
        let ciphertext_len = ciphertext.len() as u64;
        let uri = fetcher
            .publish(Bytes::from(ciphertext))
            .await
            .map_err(|e| ModelError::SealedModel(format!("shard {} publish: {}", index, e)))?;

        shards.push(SealedModelShard {
            index,
            plaintext_bytes: filled as u64,
            ciphertext_bytes: ciphertext_len,
            ciphertext_hash,
            blob_uri: uri.to_string(),
        });
        index += 1;
        if filled < buf.len() {
            break;
        }
    }

    if total_bytes == 0 {
        return Err(ModelError::SealedModel(format!(
            "artifact {} is empty",
            path.display()
        )));
    }

    let mut model_hash_bytes = [0u8; 32];
    model_hash_bytes.copy_from_slice(&plaintext_hasher.finalize());
    let model_hash = Hash::new(model_hash_bytes);

    let key_bytes = content_key.to_bytes();
    let mut sealed_recipients = Vec::with_capacity(recipients.len());
    for spec in recipients {
        let pk = X25519PublicKey::from(spec.x25519_pubkey);
        let wrapped_key = envelope_encrypt(&pk, &key_bytes).map_err(|e| {
            ModelError::SealedModel(format!("wrap content key for {}: {}", spec.did, e))
        })?;
        sealed_recipients.push(SealedRecipient {
            did: spec.did.clone(),
            x25519_pubkey: spec.x25519_pubkey,
            wrapped_key,
            attestation_hash: spec.attestation_hash,
        });
    }

    let mut manifest = SealedModelManifest {
        model_id: model_id.to_string(),
        artifact_name: artifact_name.to_string(),
        model_hash,
        total_bytes,
        shard_bytes,
        shards,
        recipients: sealed_recipients,
        wrap_alg: SEALED_WRAP_ALG.to_string(),
        owner_did: owner_did.to_string(),
        created_at: chrono::Utc::now().timestamp_millis() as u64,
        manifest_hash: Hash::zero(),
        signature: Vec::new(),
        signer_pubkey: Vec::new(),
    };
    manifest.manifest_hash = compute_manifest_hash(&manifest);
    info!(
        "Sealed model '{}': {} shard(s), {} bytes, {} recipient(s)",
        model_id,
        manifest.shards.len(),
        total_bytes,
        manifest.recipients.len()
    );
    Ok(manifest)
}

/// Unseals a sealed model to `dest`: unwraps the content key for
/// `recipient_did`, fetches each ciphertext shard by URI, verifies its
/// declared hash and length, decrypts, reassembles in index order, and
/// verifies the final plaintext hash against `manifest.model_hash`.
///
/// The manifest signature is verified first — an unsigned or tampered
/// manifest never reaches the fetch path. Writes to `<dest>.partial` and
/// renames on success.
pub async fn unseal_model_to_file(
    manifest: &SealedModelManifest,
    recipient_did: &str,
    keypair: &X25519KeyPair,
    dest: &Path,
    fetcher: &dyn BlobFetcher,
) -> Result<()> {
    manifest.verify_signature()?;
    if manifest.wrap_alg != SEALED_WRAP_ALG {
        return Err(ModelError::SealedModel(format!(
            "unsupported wrap_alg '{}' (expected '{}')",
            manifest.wrap_alg, SEALED_WRAP_ALG
        )));
    }
    let recipient = manifest.recipient(recipient_did).ok_or_else(|| {
        ModelError::SealedModel(format!(
            "'{}' is not a recipient of sealed model '{}'",
            recipient_did, manifest.model_id
        ))
    })?;
    if recipient.x25519_pubkey != keypair.public_key_bytes() {
        return Err(ModelError::SealedModel(format!(
            "local X25519 key does not match the recipient entry for '{}'",
            recipient_did
        )));
    }
    let key_bytes = envelope_decrypt(keypair, &recipient.wrapped_key).map_err(|e| {
        ModelError::SealedModel(format!("unwrap content key for '{}': {}", recipient_did, e))
    })?;
    let content_key = SymmetricKey::from_bytes(&key_bytes)
        .map_err(|e| ModelError::SealedModel(format!("content key invalid: {}", e)))?;

    let mut shards: Vec<&SealedModelShard> = manifest.shards.iter().collect();
    shards.sort_by_key(|s| s.index);
    for (expect, s) in shards.iter().enumerate() {
        if s.index as usize != expect {
            return Err(ModelError::SealedModel(format!(
                "shard index gap in manifest for '{}': expected {}, found {}",
                manifest.model_id, expect, s.index
            )));
        }
    }

    let partial = dest.with_extension("partial");
    let mut out = tokio::fs::File::create(&partial)
        .await
        .map_err(|e| ModelError::SealedModel(format!("create {}: {}", partial.display(), e)))?;
    let mut plaintext_hasher = Sha256::new();
    let mut total: u64 = 0;

    for s in shards {
        let uri = TenzroUri::parse(&s.blob_uri).map_err(|e| {
            ModelError::SealedModel(format!("shard {} bad uri '{}': {}", s.index, s.blob_uri, e))
        })?;
        let ciphertext = fetcher
            .fetch(&uri)
            .await
            .map_err(|e| ModelError::SealedModel(format!("shard {} fetch: {}", s.index, e)))?;
        if ciphertext.len() as u64 != s.ciphertext_bytes {
            return Err(ModelError::SealedModel(format!(
                "shard {} length mismatch: manifest {} fetched {}",
                s.index,
                s.ciphertext_bytes,
                ciphertext.len()
            )));
        }
        let actual = compute_shard_ciphertext_hash(&manifest.model_id, s.index, &ciphertext);
        if actual != s.ciphertext_hash {
            return Err(ModelError::SealedModel(format!(
                "shard {} ciphertext hash mismatch",
                s.index
            )));
        }
        let plaintext = content_key
            .decrypt(&ciphertext)
            .map_err(|e| ModelError::SealedModel(format!("shard {} decrypt: {}", s.index, e)))?;
        if plaintext.len() as u64 != s.plaintext_bytes {
            return Err(ModelError::SealedModel(format!(
                "shard {} plaintext length mismatch: manifest {} decrypted {}",
                s.index,
                s.plaintext_bytes,
                plaintext.len()
            )));
        }
        plaintext_hasher.update(&plaintext);
        total += plaintext.len() as u64;
        out.write_all(&plaintext)
            .await
            .map_err(|e| ModelError::SealedModel(format!("write {}: {}", partial.display(), e)))?;
    }
    out.flush()
        .await
        .map_err(|e| ModelError::SealedModel(format!("flush {}: {}", partial.display(), e)))?;
    drop(out);

    if total != manifest.total_bytes {
        let _ = tokio::fs::remove_file(&partial).await;
        return Err(ModelError::SealedModel(format!(
            "total length mismatch: manifest {} reassembled {}",
            manifest.total_bytes, total
        )));
    }
    let mut actual_bytes = [0u8; 32];
    actual_bytes.copy_from_slice(&plaintext_hasher.finalize());
    if Hash::new(actual_bytes) != manifest.model_hash {
        let _ = tokio::fs::remove_file(&partial).await;
        return Err(ModelError::SealedModel(format!(
            "plaintext hash mismatch for '{}' after reassembly",
            manifest.model_id
        )));
    }
    tokio::fs::rename(&partial, dest)
        .await
        .map_err(|e| ModelError::SealedModel(format!("rename to {}: {}", dest.display(), e)))?;
    info!(
        "Unsealed model '{}' to {} ({} bytes)",
        manifest.model_id,
        dest.display(),
        total
    );
    Ok(())
}

/// Write-through cache for sealed-model manifests, keyed by `model_id`
/// under the `sealed:` prefix in `CF_MODELS`.
pub struct SealedModelStore {
    manifests: DashMap<String, SealedModelManifest>,
    storage: Option<Arc<dyn KvStore>>,
}

impl SealedModelStore {
    /// Creates an in-memory store (tests / storage-less nodes).
    pub fn new() -> Self {
        Self {
            manifests: DashMap::new(),
            storage: None,
        }
    }

    /// Creates a store backed by RocksDB, hydrating existing manifests.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let manifests = DashMap::new();
        match storage.get_keys_with_prefix(CF_MODELS, SEALED_KEY_PREFIX) {
            Ok(keys) => {
                let mut hydrated = 0usize;
                for key in &keys {
                    match storage.get(CF_MODELS, key) {
                        Ok(Some(data)) => {
                            match serde_json::from_slice::<SealedModelManifest>(&data) {
                                Ok(m) => {
                                    manifests.insert(m.model_id.clone(), m);
                                    hydrated += 1;
                                }
                                Err(e) => warn!("Bad sealed-model manifest record: {}", e),
                            }
                        }
                        Ok(None) => {}
                        Err(e) => warn!("Sealed-model hydration read failure: {}", e),
                    }
                }
                if hydrated > 0 {
                    info!("Hydrated {} sealed-model manifest(s) from CF_MODELS", hydrated);
                }
            }
            Err(e) => warn!("Sealed-model hydration scan failure: {}", e),
        }
        Self {
            manifests,
            storage: Some(storage),
        }
    }

    fn storage_key(model_id: &str) -> Vec<u8> {
        [SEALED_KEY_PREFIX, model_id.as_bytes()].concat()
    }

    /// Inserts or replaces a manifest, writing through to storage.
    pub fn put(&self, manifest: SealedModelManifest) -> Result<()> {
        if let Some(ref storage) = self.storage {
            let data = serde_json::to_vec(&manifest)
                .map_err(|e| ModelError::SealedModel(format!("serialize manifest: {}", e)))?;
            storage
                .put(CF_MODELS, &Self::storage_key(&manifest.model_id), &data)
                .map_err(|e| ModelError::SealedModel(format!("persist manifest: {}", e)))?;
        }
        self.manifests.insert(manifest.model_id.clone(), manifest);
        Ok(())
    }

    /// Looks up the manifest for a model.
    pub fn get(&self, model_id: &str) -> Option<SealedModelManifest> {
        self.manifests.get(model_id).map(|m| m.clone())
    }

    /// Lists all stored manifests.
    pub fn list(&self) -> Vec<SealedModelManifest> {
        self.manifests.iter().map(|e| e.value().clone()).collect()
    }

    /// Removes a manifest, deleting the persisted record.
    pub fn remove(&self, model_id: &str) -> Option<SealedModelManifest> {
        if let Some(ref storage) = self.storage
            && let Err(e) = storage.delete(CF_MODELS, &Self::storage_key(model_id))
        {
            warn!("Failed to delete sealed-model record '{}': {}", model_id, e);
        }
        self.manifests.remove(model_id).map(|(_, m)| m)
    }
}

impl Default for SealedModelStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use tenzro_crypto::keys::KeyPair;
    use tenzro_crypto::signatures::Signer as _;

    /// In-memory BlobFetcher: BLAKE3-free — keys by SHA-256 hex for tests.
    struct MemFetcher {
        blobs: parking_lot::Mutex<HashMap<String, Bytes>>,
    }

    impl MemFetcher {
        fn new() -> Self {
            Self {
                blobs: parking_lot::Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl BlobFetcher for MemFetcher {
        async fn fetch(&self, uri: &TenzroUri) -> std::result::Result<Bytes, String> {
            let hash = match uri {
                TenzroUri::Blob { hash, .. } => hash.clone(),
                other => return Err(format!("unexpected uri {:?}", other)),
            };
            self.blobs
                .lock()
                .get(&hash)
                .cloned()
                .ok_or_else(|| "not found".to_string())
        }

        async fn publish(&self, bytes: Bytes) -> std::result::Result<TenzroUri, String> {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let hash = hex::encode(hasher.finalize());
            self.blobs.lock().insert(hash.clone(), bytes);
            Ok(TenzroUri::Blob {
                hash,
                provider_hint: None,
            })
        }
    }

    fn signed_manifest_roundtrip_input() -> (tempfile::TempDir, std::path::PathBuf, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("model.gguf");
        // Non-uniform content larger than one test shard.
        let data: Vec<u8> = (0..300_000u32).flat_map(|i| i.to_le_bytes()).collect();
        std::fs::write(&path, &data).unwrap();
        (dir, path, data)
    }

    #[tokio::test]
    async fn seal_unseal_roundtrip() {
        let (_dir, path, data) = signed_manifest_roundtrip_input();
        let fetcher = MemFetcher::new();
        let recipient_kp = X25519KeyPair::generate();
        let specs = vec![RecipientSpec {
            did: "did:tenzro:machine:abc".to_string(),
            x25519_pubkey: recipient_kp.public_key_bytes(),
            attestation_hash: None,
        }];
        // 512 KiB shards → 3 shards for ~1.2 MB input.
        let mut manifest = seal_model_file(
            &path,
            "test-model",
            "model.gguf",
            "did:tenzro:human:owner",
            &specs,
            512 * 1024,
            &fetcher,
        )
        .await
        .unwrap();
        assert_eq!(manifest.shards.len(), 3);
        assert_eq!(manifest.total_bytes, data.len() as u64);
        assert_eq!(manifest.wrap_alg, SEALED_WRAP_ALG);

        // Sign with an Ed25519 announce-style key.
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer_pubkey = kp.public_key().as_bytes().to_vec();
        let signer = tenzro_crypto::signatures::Ed25519SignerImpl::new(kp).unwrap();
        let sig = signer.sign(manifest.manifest_hash.as_bytes()).unwrap();
        manifest.attach_signature(sig.to_bytes(), signer_pubkey);
        manifest.verify_signature().unwrap();

        let dest = path.parent().unwrap().join("restored.gguf");
        unseal_model_to_file(
            &manifest,
            "did:tenzro:machine:abc",
            &recipient_kp,
            &dest,
            &fetcher,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), data);
    }

    #[tokio::test]
    async fn unseal_refuses_wrong_recipient_and_tamper() {
        let (_dir, path, _data) = signed_manifest_roundtrip_input();
        let fetcher = MemFetcher::new();
        let recipient_kp = X25519KeyPair::generate();
        let specs = vec![RecipientSpec {
            did: "did:tenzro:machine:abc".to_string(),
            x25519_pubkey: recipient_kp.public_key_bytes(),
            attestation_hash: None,
        }];
        let mut manifest = seal_model_file(
            &path,
            "test-model",
            "model.gguf",
            "did:tenzro:human:owner",
            &specs,
            512 * 1024,
            &fetcher,
        )
        .await
        .unwrap();
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer_pubkey = kp.public_key().as_bytes().to_vec();
        let signer = tenzro_crypto::signatures::Ed25519SignerImpl::new(kp).unwrap();
        let sig = signer.sign(manifest.manifest_hash.as_bytes()).unwrap();
        manifest.attach_signature(sig.to_bytes(), signer_pubkey);

        let dest = path.parent().unwrap().join("restored.gguf");
        // Non-recipient DID refused.
        let other_kp = X25519KeyPair::generate();
        let err = unseal_model_to_file(
            &manifest,
            "did:tenzro:machine:other",
            &other_kp,
            &dest,
            &fetcher,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("not a recipient"));

        // Tampered manifest (recipient swap) fails hash/signature check.
        let mut tampered = manifest.clone();
        tampered.recipients[0].did = "did:tenzro:machine:mallory".to_string();
        let err = unseal_model_to_file(
            &tampered,
            "did:tenzro:machine:mallory",
            &recipient_kp,
            &dest,
            &fetcher,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("manifest hash mismatch"));
    }

    #[test]
    fn store_put_get_list_remove() {
        let store = SealedModelStore::new();
        let manifest = SealedModelManifest {
            model_id: "m1".to_string(),
            artifact_name: "m1.gguf".to_string(),
            model_hash: Hash::zero(),
            total_bytes: 1,
            shard_bytes: 1,
            shards: vec![],
            recipients: vec![],
            wrap_alg: SEALED_WRAP_ALG.to_string(),
            owner_did: "did:tenzro:human:o".to_string(),
            created_at: 0,
            manifest_hash: Hash::zero(),
            signature: vec![],
            signer_pubkey: vec![],
        };
        store.put(manifest.clone()).unwrap();
        assert!(store.get("m1").is_some());
        assert_eq!(store.list().len(), 1);
        assert!(store.remove("m1").is_some());
        assert!(store.get("m1").is_none());
    }
}
