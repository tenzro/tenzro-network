//! Jurisdiction receipts for AI inference — signed, attestation-bound
//! statements of *where* a specific request was served.
//!
//! Data-sovereignty deployments pin requests to a legal jurisdiction
//! (`parameters.custom["jurisdiction"]`, comma-separated ISO 3166-1 alpha-2
//! country codes and/or bloc tokens like `EU`). The router hard-filters to
//! providers whose declared [`JurisdictionClaim`] satisfies the pin, and the
//! serving node returns a signed [`JurisdictionReceipt`] binding the claim
//! to the exact request/response byte hashes.
//!
//! A receipt is a *locality claim*, not a geolocation proof: the signature
//! proves which key (and, via `attestation_hash`, which TEE enclave) made
//! the claim, and slashing/reputation punishes false declarations. Framing
//! matters — docs and UIs must present receipts as attestation-bound claims.
//!
//! Mirrors the [`provenance`](crate::provenance) module: pluggable signer
//! trait, in-process Ed25519 implementation, offline verification helpers.

use std::sync::Arc;
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_types::{JurisdictionClaim, JurisdictionReceipt};

use crate::provenance::hash_content;

/// Errors raised while signing or verifying a jurisdiction receipt. Kept
/// transport-agnostic so RPC/MCP/A2A handlers can map to their own error
/// types.
#[derive(Debug, thiserror::Error)]
pub enum JurisdictionError {
    /// The signer's underlying crypto primitive (e.g. Ed25519) failed.
    #[error("Jurisdiction receipt signature error: {0}")]
    SignatureFailure(String),
    /// The receipt's signature did not verify against the embedded public
    /// key + canonical preimage.
    #[error("Jurisdiction receipt signature verification failed")]
    VerificationFailed,
    /// The signer key type is not one of the supported algorithms
    /// (`ed25519`, `secp256k1`).
    #[error("Unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The receipt's `request_hash` does not match the SHA-256 of the
    /// actual request input bytes.
    #[error("Jurisdiction receipt request hash does not match request input")]
    RequestHashMismatch,
    /// The receipt's `response_hash` does not match the SHA-256 of the
    /// actual response output bytes.
    #[error("Jurisdiction receipt response hash does not match response output")]
    ResponseHashMismatch,
    /// The receipt's `model_id` does not match the model the request was
    /// routed for.
    #[error("Jurisdiction receipt model mismatch: receipt says {receipt}, request was {requested}")]
    ModelMismatch {
        /// Model id embedded in the receipt.
        receipt: String,
        /// Model id the request was routed for.
        requested: String,
    },
    /// The receipt's embedded `signer_public_key` does not match the
    /// provider's registered signing key.
    #[error("Jurisdiction receipt signer key does not match the provider's registered signing key")]
    KeyMismatch,
    /// The receipt's claim does not satisfy the jurisdictions the request
    /// pinned.
    #[error("Jurisdiction receipt claim {claimed} does not satisfy the requested pin {pinned}")]
    ClaimMismatch {
        /// Country code the receipt claims.
        claimed: String,
        /// The pin string the request carried.
        pinned: String,
    },
}

/// Pluggable jurisdiction-receipt signer. The serving node calls
/// [`sign`](JurisdictionSigner::sign) with its declared claim before the
/// response leaves the node; implementations produce a fully-populated
/// [`JurisdictionReceipt`] (including `signature`, `signer_public_key`, and
/// `algorithm`) over the canonical preimage.
pub trait JurisdictionSigner: Send + Sync {
    /// Produce a signed jurisdiction receipt binding `claim` to the
    /// SHA-256 hashes of `request_input` and `output` for
    /// `(model_id, provider)`.
    fn sign(
        &self,
        request_input: &[u8],
        output: &[u8],
        model_id: &str,
        provider: Address,
        claim: &JurisdictionClaim,
    ) -> Result<JurisdictionReceipt, JurisdictionError>;
}

/// Convenience type alias for trait objects.
pub type SharedJurisdictionSigner = Arc<dyn JurisdictionSigner>;

/// Jurisdiction signer that stamps receipts with an Ed25519 signature.
///
/// Each serving node owns its signer; the public key lands inside the
/// receipt itself (`signer_public_key`) so any third party can verify
/// `signature` against `canonical_preimage()` without consulting the node.
pub struct Ed25519JurisdictionSigner {
    inner: Ed25519SignerImpl,
}

impl Ed25519JurisdictionSigner {
    /// Wrap an existing Ed25519 signer.
    pub fn new(signer: Ed25519SignerImpl) -> Self {
        Self { inner: signer }
    }

    /// Generate a fresh Ed25519 signer. Useful for tests and for nodes that
    /// lack a long-term receipt key on first boot.
    pub fn generate() -> Result<Self, JurisdictionError> {
        let signer = Ed25519SignerImpl::generate()
            .map_err(|e| JurisdictionError::SignatureFailure(e.to_string()))?;
        Ok(Self { inner: signer })
    }

    /// Convenience: wrap into a shared `Arc<dyn JurisdictionSigner>`.
    pub fn into_shared(self) -> SharedJurisdictionSigner {
        Arc::new(self)
    }
}

impl JurisdictionSigner for Ed25519JurisdictionSigner {
    fn sign(
        &self,
        request_input: &[u8],
        output: &[u8],
        model_id: &str,
        provider: Address,
        claim: &JurisdictionClaim,
    ) -> Result<JurisdictionReceipt, JurisdictionError> {
        // Build the receipt first with an empty signature, then compute the
        // canonical preimage from the populated fields and sign that, so the
        // signed bytes can never drift from what verifiers re-compute.
        let mut receipt = JurisdictionReceipt {
            request_hash: hash_content(request_input),
            response_hash: hash_content(output),
            model_id: model_id.to_string(),
            provider,
            jurisdiction: claim.clone(),
            signed_at: Timestamp::now(),
            signer_public_key: self.inner.public_key().as_bytes().to_vec(),
            signature: Vec::new(),
            algorithm: "ed25519".to_string(),
        };

        let preimage = receipt.canonical_preimage();
        let signature = self
            .inner
            .sign(&preimage)
            .map_err(|e| JurisdictionError::SignatureFailure(e.to_string()))?;
        receipt.signature = signature.as_bytes().to_vec();

        Ok(receipt)
    }
}

/// Verify a jurisdiction receipt's signature against its embedded public
/// key and canonical preimage. Returns `Ok(())` if the signature is valid.
pub fn verify_receipt(receipt: &JurisdictionReceipt) -> Result<(), JurisdictionError> {
    use tenzro_crypto::keys::{KeyType, PublicKey};
    use tenzro_crypto::signatures::{Signature, verify};

    let key_type = match receipt.algorithm.as_str() {
        "ed25519" => KeyType::Ed25519,
        "secp256k1" => KeyType::Secp256k1,
        other => return Err(JurisdictionError::UnsupportedAlgorithm(other.to_string())),
    };

    let public_key = PublicKey::new(key_type, receipt.signer_public_key.clone());
    let signature = Signature::new(key_type, receipt.signature.clone());

    let preimage = receipt.canonical_preimage();
    verify(&public_key, &preimage, &signature).map_err(|_| JurisdictionError::VerificationFailed)
}

/// Verify every field of a provider-attached response receipt: the request and
/// response hashes must match the actual bytes, the model id must match the
/// routed request, the signature must verify against the embedded public
/// key, and — when the provider has a registered signing key — the embedded
/// key must equal the registered one. Providers without a registered key
/// pass the key check trivially (self-attested receipt, verified
/// best-effort only).
pub fn verify_response_receipt(
    receipt: &JurisdictionReceipt,
    request_input: &[u8],
    output: &[u8],
    model_id: &str,
    registered_pubkey: Option<&[u8]>,
) -> Result<(), JurisdictionError> {
    if receipt.request_hash != hash_content(request_input) {
        return Err(JurisdictionError::RequestHashMismatch);
    }
    if receipt.response_hash != hash_content(output) {
        return Err(JurisdictionError::ResponseHashMismatch);
    }
    if receipt.model_id != model_id {
        return Err(JurisdictionError::ModelMismatch {
            receipt: receipt.model_id.clone(),
            requested: model_id.to_string(),
        });
    }
    if let Some(registered) = registered_pubkey
        && receipt.signer_public_key != registered
    {
        return Err(JurisdictionError::KeyMismatch);
    }
    verify_receipt(receipt)
}

/// Check that a verified receipt's claim satisfies the request's pin
/// string (comma-separated tokens, case-insensitive).
pub fn check_receipt_satisfies_pin(
    receipt: &JurisdictionReceipt,
    pin: &str,
) -> Result<(), JurisdictionError> {
    let tokens = pin.split(',').map(str::trim).filter(|t| !t.is_empty());
    if receipt.jurisdiction.matches_any(tokens) {
        Ok(())
    } else {
        Err(JurisdictionError::ClaimMismatch {
            claimed: receipt.jurisdiction.country.clone(),
            pinned: pin.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim() -> JurisdictionClaim {
        JurisdictionClaim {
            country: "DE".to_string(),
            blocs: vec!["EU".to_string(), "EEA".to_string()],
            attestation_hash: None,
            declared_at: Timestamp::now(),
        }
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let signer = Ed25519JurisdictionSigner::generate().unwrap();
        let provider = Address::new([0x42; 32]);
        let receipt = signer
            .sign(
                b"prompt bytes",
                b"output bytes",
                "qwen3-8b",
                provider,
                &claim(),
            )
            .unwrap();

        assert_eq!(receipt.algorithm, "ed25519");
        assert_eq!(receipt.provider, provider);
        assert_eq!(receipt.jurisdiction.country, "DE");
        assert!(!receipt.signature.is_empty());

        verify_receipt(&receipt).expect("freshly signed receipt must verify");
        verify_response_receipt(&receipt, b"prompt bytes", b"output bytes", "qwen3-8b", None)
            .expect("full response check must pass");
    }

    #[test]
    fn tampered_claim_fails_verify() {
        let signer = Ed25519JurisdictionSigner::generate().unwrap();
        let mut receipt = signer
            .sign(b"in", b"out", "m", Address::default(), &claim())
            .unwrap();
        receipt.jurisdiction.country = "US".to_string();
        assert!(matches!(
            verify_receipt(&receipt).unwrap_err(),
            JurisdictionError::VerificationFailed
        ));
    }

    #[test]
    fn wrong_output_fails_response_check() {
        let signer = Ed25519JurisdictionSigner::generate().unwrap();
        let receipt = signer
            .sign(b"in", b"out", "m", Address::default(), &claim())
            .unwrap();
        assert!(matches!(
            verify_response_receipt(&receipt, b"in", b"different", "m", None).unwrap_err(),
            JurisdictionError::ResponseHashMismatch
        ));
    }

    #[test]
    fn wrong_model_fails_response_check() {
        let signer = Ed25519JurisdictionSigner::generate().unwrap();
        let receipt = signer
            .sign(b"in", b"out", "m", Address::default(), &claim())
            .unwrap();
        assert!(matches!(
            verify_response_receipt(&receipt, b"in", b"out", "other", None).unwrap_err(),
            JurisdictionError::ModelMismatch { .. }
        ));
    }

    #[test]
    fn registered_key_mismatch_rejected() {
        let signer = Ed25519JurisdictionSigner::generate().unwrap();
        let receipt = signer
            .sign(b"in", b"out", "m", Address::default(), &claim())
            .unwrap();
        let other_key = [0u8; 32];
        assert!(matches!(
            verify_response_receipt(&receipt, b"in", b"out", "m", Some(&other_key)).unwrap_err(),
            JurisdictionError::KeyMismatch
        ));
    }

    #[test]
    fn pin_matching_is_case_insensitive_over_country_and_blocs() {
        let signer = Ed25519JurisdictionSigner::generate().unwrap();
        let receipt = signer
            .sign(b"in", b"out", "m", Address::default(), &claim())
            .unwrap();
        check_receipt_satisfies_pin(&receipt, "de").unwrap();
        check_receipt_satisfies_pin(&receipt, "eu, ch").unwrap();
        check_receipt_satisfies_pin(&receipt, " eea ").unwrap();
        assert!(matches!(
            check_receipt_satisfies_pin(&receipt, "US,SG").unwrap_err(),
            JurisdictionError::ClaimMismatch { .. }
        ));
    }

    #[test]
    fn unknown_algorithm_rejected() {
        let signer = Ed25519JurisdictionSigner::generate().unwrap();
        let mut receipt = signer
            .sign(b"in", b"out", "m", Address::default(), &claim())
            .unwrap();
        receipt.algorithm = "ml-dsa-65".to_string();
        assert!(matches!(
            verify_receipt(&receipt).unwrap_err(),
            JurisdictionError::UnsupportedAlgorithm(_)
        ));
    }
}
