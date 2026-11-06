//! Hardware-key [`ProvenanceSigner`] implementation.
//!
//! Produces a Tenzro-native, C2PA-style manifest signed with ECDSA-P256 by the
//! provider machine's hardware identity key (TPM or Secure Enclave), the key
//! registered for its machine DID. The encoding is not the
//! on-the-wire C2PA Content Credentials format; the swap point is the
//! [`ProvenanceSigner::sign`] return value.
//!
//! This signer and the `verify_manifest` helper in the parent module are
//! byte-stable: a manifest signed today verifies against the same canonical
//! preimage encoding tomorrow.
//!
//! [`ProvenanceSigner`]: super::ProvenanceSigner
//! [`ProvenanceSigner::sign`]: super::ProvenanceSigner::sign

use super::{ProvenanceError, ProvenanceSigner, hash_content};
use std::sync::Arc;
use tenzro_crypto::composite::HybridSigner;
use tenzro_types::ContentProvenanceManifest;
use tenzro_types::primitives::{Address, Timestamp};

/// The `algorithm` a hardware-signed manifest carries.
pub const PROVENANCE_ALGORITHM: &str = "ecdsa-p256";

/// Provenance signer that stamps manifests with an ECDSA-P256 signature made
/// by the P-256 leg of the machine's hardware identity key.
///
/// Each provider node owns its signer and signs every inference response it
/// returns. The signer's SEC1 public key lands inside the manifest itself
/// (`signer_public_key`) so any third party can verify `signature` against
/// `canonical_preimage()` without consulting the node.
pub struct HardwareProvenanceSigner {
    inner: Arc<dyn HybridSigner>,
}

impl HardwareProvenanceSigner {
    /// Wrap the machine's hardware identity signer.
    pub fn new(signer: Arc<dyn HybridSigner>) -> Self {
        Self { inner: signer }
    }

    /// Convenience: wrap into a shared `Arc<dyn ProvenanceSigner>` for the
    /// router's `with_provenance_signer()` builder.
    pub fn into_shared(self) -> Arc<dyn ProvenanceSigner> {
        Arc::new(self)
    }
}

impl ProvenanceSigner for HardwareProvenanceSigner {
    fn sign(
        &self,
        model_id: &str,
        provider: Address,
        output: &[u8],
        assertion: &str,
    ) -> Result<ContentProvenanceManifest, ProvenanceError> {
        // Uncompressed SEC1: the identity's `x || y` behind the 0x04 tag.
        let mut public_key = vec![0x04];
        public_key.extend_from_slice(&self.inner.public_key().p256);
        // Build the manifest first with an empty signature, then compute the
        // canonical preimage from the populated fields and sign that, so the
        // signed bytes can never drift from what verifiers re-compute.
        let mut manifest = ContentProvenanceManifest {
            content_hash: hash_content(output),
            model_id: model_id.to_string(),
            provider,
            signed_at: Timestamp::now(),
            assertion: assertion.to_string(),
            signer_public_key: public_key,
            signature: Vec::new(),
            algorithm: PROVENANCE_ALGORITHM.to_string(),
        };

        let preimage = manifest.canonical_preimage();
        manifest.signature = self
            .inner
            .sign_external(&preimage)
            .map_err(|e| ProvenanceError::SignatureFailure(e.to_string()))?;

        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ASSERTION_AI_GENERATED, ASSERTION_DEEPFAKE, verify_manifest};
    use super::*;

    fn signer() -> HardwareProvenanceSigner {
        HardwareProvenanceSigner::new(Arc::new(
            tenzro_crypto::testing::TestHybridSigner::p256_only(5),
        ))
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let signer = signer();
        let provider = Address::new([0x42; 32]);
        let output = b"the quick brown fox jumps over the lazy dog";

        let manifest = signer
            .sign("gpt-4-test", provider, output, ASSERTION_AI_GENERATED)
            .unwrap();

        assert_eq!(manifest.algorithm, PROVENANCE_ALGORITHM);
        assert_eq!(manifest.assertion, ASSERTION_AI_GENERATED);
        assert_eq!(manifest.provider, provider);
        assert!(!manifest.signature.is_empty());
        assert_eq!(manifest.content_hash, hash_content(output));

        verify_manifest(&manifest).expect("freshly signed manifest must verify");
        let identity = tenzro_crypto::testing::TestHybridSigner::p256_only(5);
        super::super::verify_response_manifest(
            &manifest,
            output,
            "gpt-4-test",
            Some(HybridSigner::public_key(&identity)),
        )
        .expect("the manifest names the registered identity key");
        let other = tenzro_crypto::testing::TestHybridSigner::p256_only(6);
        for registered in [Some(HybridSigner::public_key(&other)), None] {
            assert!(matches!(
                super::super::verify_response_manifest(&manifest, output, "gpt-4-test", registered),
                Err(ProvenanceError::KeyMismatch)
            ));
        }
    }

    #[test]
    fn deepfake_assertion_supported() {
        let manifest = signer()
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
        let mut manifest = signer()
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
        let mut manifest = signer()
            .sign("m", Address::default(), b"x", ASSERTION_AI_GENERATED)
            .unwrap();
        manifest.algorithm = "ml-dsa-65".to_string();
        let err = verify_manifest(&manifest).unwrap_err();
        assert!(matches!(err, ProvenanceError::UnsupportedAlgorithm(_)));
    }
}
