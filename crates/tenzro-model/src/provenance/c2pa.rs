//! In-process Ed25519 [`ProvenanceSigner`] implementation.
//!
//! This is the testnet signer: it produces a Tenzro-native, C2PA-style
//! manifest signed with the provider's Ed25519 key. The encoding is
//! intentionally not the on-the-wire C2PA Content Credentials format yet —
//! that swap will happen once the EU AI Office Code of Practice's June 2026
//! final spec is published and a stable `c2pa-rs` release is available under
//! a permissive license.
//!
//! Until then, this signer + the `verify_manifest` helper in the parent
//! module are byte-stable: a manifest signed today will verify against the
//! same canonical preimage encoding tomorrow.
//!
//! [`ProvenanceSigner`]: super::ProvenanceSigner

use super::{ProvenanceError, ProvenanceSigner, hash_content};
use std::sync::Arc;
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
use tenzro_types::ContentProvenanceManifest;
use tenzro_types::primitives::{Address, Timestamp};

/// Provenance signer that stamps manifests with an Ed25519 signature.
///
/// In production each provider node owns its signer and signs every
/// inference response it returns. The signer's public key lands inside the
/// manifest itself (`signer_public_key`) so any third party can verify
/// `signature` against `canonical_preimage()` without consulting the node.
pub struct Ed25519ProvenanceSigner {
    inner: Ed25519SignerImpl,
}

impl Ed25519ProvenanceSigner {
    /// Wrap an existing Ed25519 signer.
    pub fn new(signer: Ed25519SignerImpl) -> Self {
        Self { inner: signer }
    }

    /// Generate a fresh Ed25519 signer. Useful for tests and for nodes that
    /// lack a long-term provenance key on first boot.
    pub fn generate() -> Result<Self, ProvenanceError> {
        let signer = Ed25519SignerImpl::generate()
            .map_err(|e| ProvenanceError::SignatureFailure(e.to_string()))?;
        Ok(Self { inner: signer })
    }

    /// Convenience: wrap into a shared `Arc<dyn ProvenanceSigner>` for the
    /// router's `with_provenance_signer()` builder.
    pub fn into_shared(self) -> Arc<dyn ProvenanceSigner> {
        Arc::new(self)
    }
}

impl ProvenanceSigner for Ed25519ProvenanceSigner {
    fn sign(
        &self,
        model_id: &str,
        provider: Address,
        output: &[u8],
        assertion: &str,
    ) -> Result<ContentProvenanceManifest, ProvenanceError> {
        // Build the manifest *first* with empty signature, then compute the
        // canonical preimage from the populated fields and sign that. This
        // avoids the bug where the signed bytes drift from what verifiers
        // re-compute (e.g. timestamp skew between sign and serialize).
        let mut manifest = ContentProvenanceManifest {
            content_hash: hash_content(output),
            model_id: model_id.to_string(),
            provider,
            signed_at: Timestamp::now(),
            assertion: assertion.to_string(),
            signer_public_key: self.inner.public_key().as_bytes().to_vec(),
            signature: Vec::new(),
            algorithm: "ed25519".to_string(),
        };

        let preimage = manifest.canonical_preimage();
        let signature = self
            .inner
            .sign(&preimage)
            .map_err(|e| ProvenanceError::SignatureFailure(e.to_string()))?;
        manifest.signature = signature.as_bytes().to_vec();

        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ASSERTION_AI_GENERATED, ASSERTION_DEEPFAKE, verify_manifest};
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let signer = Ed25519ProvenanceSigner::generate().unwrap();
        let provider = Address::new([0x42; 32]);
        let output = b"the quick brown fox jumps over the lazy dog";

        let manifest = signer
            .sign("gpt-4-test", provider, output, ASSERTION_AI_GENERATED)
            .unwrap();

        assert_eq!(manifest.algorithm, "ed25519");
        assert_eq!(manifest.assertion, ASSERTION_AI_GENERATED);
        assert_eq!(manifest.provider, provider);
        assert!(!manifest.signature.is_empty());
        assert_eq!(manifest.content_hash, hash_content(output));

        verify_manifest(&manifest).expect("freshly signed manifest must verify");
    }

    #[test]
    fn deepfake_assertion_supported() {
        let signer = Ed25519ProvenanceSigner::generate().unwrap();
        let manifest = signer
            .sign(
                "stable-diffusion",
                Address::default(),
                b"<deepfake image bytes>",
                ASSERTION_DEEPFAKE,
            )
            .unwrap();

        assert_eq!(manifest.assertion, ASSERTION_DEEPFAKE);
        verify_manifest(&manifest).unwrap();
    }

    #[test]
    fn tampered_output_fails_verify() {
        let signer = Ed25519ProvenanceSigner::generate().unwrap();
        let mut manifest = signer
            .sign(
                "gpt-4",
                Address::default(),
                b"original",
                ASSERTION_AI_GENERATED,
            )
            .unwrap();

        // Forge a different content hash — signature now points at the
        // wrong preimage and must fail.
        manifest.content_hash = hash_content(b"tampered");
        let err = verify_manifest(&manifest).unwrap_err();
        assert!(matches!(err, ProvenanceError::VerificationFailed));
    }

    #[test]
    fn unknown_algorithm_rejected() {
        let signer = Ed25519ProvenanceSigner::generate().unwrap();
        let mut manifest = signer
            .sign("m", Address::default(), b"x", ASSERTION_AI_GENERATED)
            .unwrap();
        manifest.algorithm = "ml-dsa-65".to_string();
        let err = verify_manifest(&manifest).unwrap_err();
        assert!(matches!(err, ProvenanceError::UnsupportedAlgorithm(_)));
    }
}
