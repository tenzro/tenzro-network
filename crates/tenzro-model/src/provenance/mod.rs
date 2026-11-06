//! Content provenance for AI inference outputs.
//!
//! EU AI Act Article 50(2) (effective 2026-08-02) requires generative-AI
//! systems to mark outputs with a verifiable provenance trail so downstream
//! consumers can establish *what model* produced *what content* on *what
//! provider*. This module implements that mark.
//!
//! ## Architecture
//!
//! - [`ProvenanceSigner`] is the pluggable interface used by
//!   `tenzro-model::routing` to stamp every [`InferenceResponse`] before it
//!   leaves the inference router.
//! - [`HardwareProvenanceSigner`] signs the canonical preimage of
//!   [`ContentProvenanceManifest`] with ECDSA-P256 by a key held in the
//!   provider's TPM or Secure Enclave.
//! - [`ProvenanceStore`] is a small SHA-256-keyed in-memory cache so
//!   `tenzro_getContentProvenance(content_hash)` can resolve a manifest after the
//!   fact (e.g. when an agent quotes an output and the consumer wants to
//!   verify the original source).
//!
//! When the C2PA Content Credentials final spec under the EU AI Office Code
//! of Practice (June 2026) is finalized, the wire encoding swap point is the
//! [`ProvenanceSigner::sign`] return value — the
//! [`tenzro_types::ContentProvenanceManifest`] in-memory shape is stable.
//!
//! [`InferenceResponse`]: tenzro_types::InferenceResponse

pub mod c2pa;

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_types::ContentProvenanceManifest;
use tenzro_types::primitives::{Address, Hash};

/// Standard EU AI Act Art. 50(2) assertion tag for ordinary AI outputs.
///
/// Use [`ASSERTION_DEEPFAKE`] instead when the output imitates a real person,
/// place, or event — Article 50(4) requires explicit deepfake labeling.
pub const ASSERTION_AI_GENERATED: &str = "ai-generated";

/// EU AI Act Art. 50(4) assertion tag for outputs imitating real people,
/// places, or events. Producers must surface this so downstream UIs can
/// render an "this content imitates a real subject" disclaimer.
pub const ASSERTION_DEEPFAKE: &str = "deepfake";

/// SHA-256 hash of the inference output bytes — the content fingerprint that
/// keys [`ProvenanceStore`].
pub fn hash_content(output: &[u8]) -> Hash {
    let digest = Sha256::digest(output);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Hash::new(bytes)
}

/// Pluggable provenance signer. The router calls
/// [`sign`](ProvenanceSigner::sign) before returning each
/// [`InferenceResponse`]; implementations are responsible for producing a
/// fully-populated [`ContentProvenanceManifest`] (including `signature`,
/// `signer_public_key`, and `algorithm`) over the canonical preimage.
///
/// [`InferenceResponse`]: tenzro_types::InferenceResponse
pub trait ProvenanceSigner: Send + Sync {
    /// Produce a signed provenance manifest for `(model_id, provider,
    /// output)`. `assertion` is one of [`ASSERTION_AI_GENERATED`] or
    /// [`ASSERTION_DEEPFAKE`] (or a custom string for future Art. 50(3)/(5)
    /// categories).
    fn sign(
        &self,
        model_id: &str,
        provider: Address,
        output: &[u8],
        assertion: &str,
    ) -> Result<ContentProvenanceManifest, ProvenanceError>;
}

/// In-memory store keyed by `content_hash`. Wired into `tenzro-node` as a
/// shared `Arc<ProvenanceStore>` consumed by both the router (writer) and
/// the `tenzro_getContentProvenance` RPC handler (reader).
///
/// The store is intentionally bounded by a hard cap so a node serving a
/// chatty model cannot OOM. When the cap is hit, the oldest entry by
/// `signed_at` is evicted.
#[derive(Debug)]
pub struct ProvenanceStore {
    inner: DashMap<Hash, ContentProvenanceManifest>,
    capacity: usize,
}

impl ProvenanceStore {
    /// Create a store with the given hard cap on number of cached manifests.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: DashMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// Insert a manifest, evicting the oldest entry by `signed_at` when full.
    pub fn put(&self, manifest: ContentProvenanceManifest) {
        if self.inner.len() >= self.capacity {
            // Evict oldest. DashMap's iteration is not ordered, so we scan —
            // acceptable at this small capacity (a few thousand entries).
            let oldest = self
                .inner
                .iter()
                .min_by_key(|e| e.value().signed_at.as_millis())
                .map(|e| *e.key());
            if let Some(k) = oldest {
                self.inner.remove(&k);
            }
        }
        self.inner.insert(manifest.content_hash, manifest);
    }

    /// Lookup by SHA-256 content hash.
    pub fn get(&self, content_hash: &Hash) -> Option<ContentProvenanceManifest> {
        self.inner.get(content_hash).map(|v| v.value().clone())
    }

    /// Number of cached manifests.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for ProvenanceStore {
    fn default() -> Self {
        // 10k manifests ≈ a few MB at typical inference output sizes; safe
        // default for a single node serving one model.
        Self::new(10_000)
    }
}

/// Convenience type alias for trait objects.
pub type SharedProvenanceSigner = Arc<dyn ProvenanceSigner>;

/// Errors raised while signing or verifying a provenance manifest. Kept
/// transport-agnostic so RPC/MCP/A2A handlers can map to their own error
/// types.
#[derive(Debug, thiserror::Error)]
pub enum ProvenanceError {
    /// The signer's underlying crypto primitive (e.g. Ed25519) failed.
    #[error("Provenance signature error: {0}")]
    SignatureFailure(String),
    /// The provenance manifest's signature did not verify against the
    /// embedded public key + canonical preimage.
    #[error("Provenance signature verification failed")]
    VerificationFailed,
    /// The signer key type is not the supported algorithm (`ecdsa-p256`).
    #[error("Unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The manifest's `content_hash` does not match the SHA-256 of the
    /// actual response output bytes.
    #[error("Provenance content hash does not match response output")]
    ContentHashMismatch,
    /// The manifest's `model_id` does not match the model the request
    /// was routed for.
    #[error("Provenance model mismatch: manifest says {manifest}, request was {requested}")]
    ModelMismatch {
        /// Model id embedded in the manifest.
        manifest: String,
        /// Model id the request was routed for.
        requested: String,
    },
    /// The manifest's embedded `signer_public_key` does not match the
    /// provider's registered signing key.
    #[error("Provenance signer key does not match the provider's registered signing key")]
    KeyMismatch,
}

/// Verify a provenance manifest's signature against its embedded public key
/// and canonical preimage. Returns `Ok(())` if the signature is valid.
pub fn verify_manifest(manifest: &ContentProvenanceManifest) -> Result<(), ProvenanceError> {
    if manifest.algorithm != c2pa::PROVENANCE_ALGORITHM {
        return Err(ProvenanceError::UnsupportedAlgorithm(
            manifest.algorithm.clone(),
        ));
    }
    let preimage = manifest.canonical_preimage();
    if tenzro_device_key::signer::verify_p256(
        &manifest.signer_public_key,
        &preimage,
        &manifest.signature,
    ) {
        Ok(())
    } else {
        Err(ProvenanceError::VerificationFailed)
    }
}

/// Verify every field of a provider-attached response manifest: the content
/// hash must match the actual output bytes, the model id must match the
/// routed request, the manifest must be signed by the P-256 leg of
/// `registered` (the hardware identity key registered for the provider's
/// machine DID), and the signature must verify. A provider with no
/// registered key cannot attach a verifiable manifest: `None` is refused.
pub fn verify_response_manifest(
    manifest: &ContentProvenanceManifest,
    output: &[u8],
    model_id: &str,
    registered: Option<&tenzro_crypto::composite::CompositePublicKey>,
) -> Result<(), ProvenanceError> {
    if manifest.content_hash != hash_content(output) {
        return Err(ProvenanceError::ContentHashMismatch);
    }
    if manifest.model_id != model_id {
        return Err(ProvenanceError::ModelMismatch {
            manifest: manifest.model_id.clone(),
            requested: model_id.to_string(),
        });
    }
    let registered = registered.ok_or(ProvenanceError::KeyMismatch)?;
    if manifest.signer_public_key.strip_prefix(&[0x04]) != Some(registered.p256.as_slice()) {
        return Err(ProvenanceError::KeyMismatch);
    }
    verify_manifest(manifest)
}

/// Re-export the hardware-key signer.
pub use c2pa::HardwareProvenanceSigner;
