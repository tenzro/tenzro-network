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
//! - [`Ed25519ProvenanceSigner`] is the in-process implementation used on
//!   testnet: it signs the canonical preimage of [`ProvenanceManifest`] with
//!   an Ed25519 key, identical to the validator block-signing scheme.
//! - [`ProvenanceStore`] is a small SHA-256-keyed in-memory cache so
//!   `tenzro_getProvenance(content_hash)` can resolve a manifest after the
//!   fact (e.g. when an agent quotes an output and the consumer wants to
//!   verify the original source).
//!
//! When the C2PA Content Credentials final spec under the EU AI Office Code
//! of Practice (June 2026) is finalized, the wire encoding swap point is the
//! [`ProvenanceSigner::sign`] return value — the
//! [`tenzro_types::ProvenanceManifest`] in-memory shape is stable.
//!
//! [`InferenceResponse`]: tenzro_types::InferenceResponse

pub mod c2pa;

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_types::primitives::{Address, Hash};
use tenzro_types::ProvenanceManifest;

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
/// fully-populated [`ProvenanceManifest`] (including `signature`,
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
    ) -> Result<ProvenanceManifest, ProvenanceError>;
}

/// In-memory store keyed by `content_hash`. Wired into `tenzro-node` as a
/// shared `Arc<ProvenanceStore>` consumed by both the router (writer) and
/// the `tenzro_getProvenance` RPC handler (reader).
///
/// The store is intentionally bounded by a hard cap so a node serving a
/// chatty model cannot OOM. When the cap is hit, the oldest entry by
/// `signed_at` is evicted.
#[derive(Debug)]
pub struct ProvenanceStore {
    inner: DashMap<Hash, ProvenanceManifest>,
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
    pub fn put(&self, manifest: ProvenanceManifest) {
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
    pub fn get(&self, content_hash: &Hash) -> Option<ProvenanceManifest> {
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
    /// The signer key type is not one of the supported algorithms
    /// (`ed25519`, `secp256k1`).
    #[error("Unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Verify a provenance manifest's signature against its embedded public key
/// and canonical preimage. Returns `Ok(())` if the signature is valid.
pub fn verify_manifest(manifest: &ProvenanceManifest) -> Result<(), ProvenanceError> {
    use tenzro_crypto::keys::{KeyType, PublicKey};
    use tenzro_crypto::signatures::{verify, Signature};

    let key_type = match manifest.algorithm.as_str() {
        "ed25519" => KeyType::Ed25519,
        "secp256k1" => KeyType::Secp256k1,
        other => return Err(ProvenanceError::UnsupportedAlgorithm(other.to_string())),
    };

    let public_key = PublicKey::new(key_type, manifest.signer_public_key.clone());
    let signature = Signature::new(key_type, manifest.signature.clone());

    let preimage = manifest.canonical_preimage();
    verify(&public_key, &preimage, &signature)
        .map_err(|_| ProvenanceError::VerificationFailed)
}

/// Re-export the in-process Ed25519 signer.
pub use c2pa::Ed25519ProvenanceSigner;
