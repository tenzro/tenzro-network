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
use tenzro_crypto::batch::{RecordSignature, RecordSigner};
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
/// [`JurisdictionReceipt`] (including `batched` and `signer_public_key`) over the canonical preimage.
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

/// Jurisdiction signer that stamps receipts with an Ed25519 session key.
///
/// Each serving node owns its signer. The node's hardware identity key lands
/// inside the receipt (`signer_public_key`, `signer_pq_key`) together with
/// its certificate of the session key, so any third party can verify `signature` against
/// `canonical_preimage()` without consulting the node.
pub struct Ed25519JurisdictionSigner {
    inner: Arc<dyn RecordSigner>,
}

impl Ed25519JurisdictionSigner {
    /// Wrap the node's session signer.
    pub fn new(signer: Arc<dyn RecordSigner>) -> Self {
        Self { inner: signer }
    }

    /// A signer certified by a fresh in-memory identity, for tests.
    #[cfg(test)]
    pub fn generate() -> Result<Self, JurisdictionError> {
        let identity = tenzro_crypto::testing::TestHybridSigner::random();
        let signer = tenzro_crypto::batch::ImmediateRecordSigner::new(Arc::new(identity));
        Ok(Self::new(Arc::new(signer)))
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
            signer_public_key: self.inner.identity().p256.clone(),
            signer_pq_key: self.inner.identity().pq.clone(),
            batched: None,
        };

        let preimage = receipt.canonical_preimage();
        let signed = self
            .inner
            .sign_record(&preimage)
            .map_err(|e| JurisdictionError::SignatureFailure(e.to_string()))?;
        receipt.batched = Some(
            serde_json::to_vec(&signed.batched)
                .map_err(|e| JurisdictionError::SignatureFailure(e.to_string()))?,
        );

        Ok(receipt)
    }
}

/// Verify a jurisdiction receipt's signature against its embedded public
/// key and canonical preimage: the embedded key signed the batch holding it.
pub fn verify_receipt(receipt: &JurisdictionReceipt) -> Result<(), JurisdictionError> {
    use tenzro_crypto::composite::CompositePublicKey;

    let identity = CompositePublicKey::new(
        receipt.signer_public_key.clone(),
        receipt.signer_pq_key.clone(),
    )
    .map_err(|_| JurisdictionError::VerificationFailed)?;
    let signed_at_ms = u64::try_from(receipt.signed_at.as_millis())
        .map_err(|_| JurisdictionError::VerificationFailed)?;
    let sig: tenzro_crypto::batch::BatchedSignature = receipt
        .batched
        .as_deref()
        .and_then(|raw| serde_json::from_slice(raw).ok())
        .ok_or(JurisdictionError::VerificationFailed)?;
    RecordSignature::batched(sig)
        .verify_record_at(&identity, &receipt.canonical_preimage(), signed_at_ms)
        .map_err(|_| JurisdictionError::VerificationFailed)
}

/// Verify every field of a provider-attached response receipt: the request and
/// response hashes must match the actual bytes, the model id must match the
/// routed request, the receipt must name `registered` (the hardware identity
/// key registered for the provider's machine DID, both legs) as its signer,
/// and the signature must verify against it. A provider with no registered
/// key cannot attach a verifiable receipt: `None` is refused.
pub fn verify_response_receipt(
    receipt: &JurisdictionReceipt,
    request_input: &[u8],
    output: &[u8],
    model_id: &str,
    registered: Option<&tenzro_crypto::composite::CompositePublicKey>,
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
    let registered = registered.ok_or(JurisdictionError::KeyMismatch)?;
    if receipt.signer_public_key != registered.p256 || receipt.signer_pq_key != registered.pq {
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

    /// The identity key the receipt names: what the registry holds for an
    /// honest provider.
    fn own_key(receipt: &JurisdictionReceipt) -> tenzro_crypto::composite::CompositePublicKey {
        tenzro_crypto::composite::CompositePublicKey::new(
            receipt.signer_public_key.clone(),
            receipt.signer_pq_key.clone(),
        )
        .unwrap()
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

        assert_eq!(receipt.provider, provider);
        assert_eq!(receipt.jurisdiction.country, "DE");
        assert!(receipt.batched.is_some());

        verify_receipt(&receipt).expect("freshly signed receipt must verify");
        verify_response_receipt(
            &receipt,
            b"prompt bytes",
            b"output bytes",
            "qwen3-8b",
            Some(&own_key(&receipt)),
        )
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
            verify_response_receipt(&receipt, b"in", b"different", "m", Some(&own_key(&receipt)))
                .unwrap_err(),
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
            verify_response_receipt(&receipt, b"in", b"out", "other", Some(&own_key(&receipt)))
                .unwrap_err(),
            JurisdictionError::ModelMismatch { .. }
        ));
    }

    #[test]
    fn registered_key_mismatch_rejected() {
        let signer = Ed25519JurisdictionSigner::generate().unwrap();
        let receipt = signer
            .sign(b"in", b"out", "m", Address::default(), &claim())
            .unwrap();
        // Another identity, no identity, and the registered key with a leg
        // that differs are all refused.
        let other = tenzro_crypto::testing::TestHybridSigner::random();
        let other_key = tenzro_crypto::composite::HybridSigner::public_key(&other).clone();
        let mut with_pq = own_key(&receipt);
        with_pq.pq = Some(vec![7u8; 1952]);
        for registered in [Some(&other_key), None, Some(&with_pq)] {
            assert!(matches!(
                verify_response_receipt(&receipt, b"in", b"out", "m", registered).unwrap_err(),
                JurisdictionError::KeyMismatch
            ));
        }
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
    fn a_receipt_signed_in_a_hardware_batch_verifies() {
        use tenzro_crypto::batch::{BatchParams, BatchRecordSigner, BatchService};
        let id: Arc<dyn tenzro_crypto::composite::HybridSigner> = Arc::new(
            tenzro_crypto::composite::testing::TestHybridSigner::hybrid(31),
        );
        let service = Arc::new(
            BatchService::new(
                id,
                BatchParams {
                    max_batch: 1,
                    flush_interval_ms: 1_000,
                },
                0,
            )
            .unwrap(),
        );
        let signer = Ed25519JurisdictionSigner::new(Arc::new(BatchRecordSigner::new(
            service,
            std::time::Duration::from_millis(200),
        )));
        let claim = JurisdictionClaim {
            country: "DE".into(),
            blocs: vec![],
            attestation_hash: None,
            declared_at: Timestamp::new(0),
        };
        let r = signer
            .sign(b"in", b"out", "m", Address([3u8; 32]), &claim)
            .unwrap();
        assert!(r.batched.is_some());
        verify_receipt(&r).unwrap();
        let mut tampered = r.clone();
        tampered.jurisdiction.country = "US".into();
        assert!(verify_receipt(&tampered).is_err());
        // A receipt without its batch signature is refused.
        let mut unsigned = r.clone();
        unsigned.batched = None;
        assert!(verify_receipt(&unsigned).is_err());
        let again: JurisdictionReceipt =
            serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        assert_eq!(again, r);
    }
}
