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
//!
//! A receipt is signed in one of two forms, both held in `batched`. The
//! record form is a batch signature by a session key the node's hardware
//! identity key certified, checked against the key the receipt names. The
//! identity key form ([`IdentityKeyJurisdictionSigner`]) is one member of a
//! batch whose root the node's identity key signed, at the version the chain
//! records for the machine the hardware key names; it is checked against
//! that machine's key history on chain ([`IdentityKeyCheck`]), so a key the
//! machine rotated away or declared compromised stops vouching for it.

use std::sync::Arc;
use tenzro_crypto::batch::{RecordSignature, RecordSigner};
use tenzro_crypto::composite::CompositePublicKey;
use tenzro_device_key::batch_signer::{Member, RootSigner};
use tenzro_device_key::delegation::{IssuerResolver, VerifyParams};
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
    /// The receipt is signed with an identity key and the verifier has no
    /// view of the chain's identity key histories to check it against.
    #[error("Jurisdiction receipt is signed with an identity key and no chain view is available")]
    NoChainView,
    /// The identity key signature does not stand against the chain's record
    /// of the machine's keys.
    #[error("Jurisdiction receipt identity key signature: {0}")]
    IdentityKey(String),
}

/// What a verifier checks an identity-key-signed receipt against: the
/// chain's record of identity keys, the verifier's clock, and how far a
/// signing time may run ahead of it.
#[derive(Clone, Copy)]
pub struct IdentityKeyCheck<'a> {
    pub resolver: &'a dyn IssuerResolver,
    pub now_ms: u64,
    pub params: VerifyParams,
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

/// The receipt for `(request_input, output, model_id, provider, claim)`
/// naming `hardware` as its signer, with no signature yet. Signers compute
/// the canonical preimage from it and sign that, so the signed bytes can
/// never drift from what verifiers re-compute.
fn unsigned(
    hardware: &CompositePublicKey,
    request_input: &[u8],
    output: &[u8],
    model_id: &str,
    provider: Address,
    claim: &JurisdictionClaim,
) -> JurisdictionReceipt {
    JurisdictionReceipt {
        request_hash: hash_content(request_input),
        response_hash: hash_content(output),
        model_id: model_id.to_string(),
        provider,
        jurisdiction: claim.clone(),
        signed_at: Timestamp::now(),
        signer_public_key: hardware.p256.clone(),
        signer_pq_key: hardware.pq.clone(),
        batched: None,
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
        let mut receipt = unsigned(
            self.inner.identity(),
            request_input,
            output,
            model_id,
            provider,
            claim,
        );
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

/// Jurisdiction signer that signs each receipt with the node's identity key
/// at the version the chain records for the machine. The receipt alone is
/// the batch, signed at once, since it is answered in the same response. The
/// receipt still names the node's hardware identity key, whose machine DID
/// is the identity the root signature is made for.
pub struct IdentityKeyJurisdictionSigner {
    root: Arc<dyn RootSigner>,
    hardware: CompositePublicKey,
}

impl IdentityKeyJurisdictionSigner {
    /// `root` signs as the machine whose hardware identity key is `hardware`.
    pub fn new(root: Arc<dyn RootSigner>, hardware: CompositePublicKey) -> Self {
        Self { root, hardware }
    }
}

impl JurisdictionSigner for IdentityKeyJurisdictionSigner {
    fn sign(
        &self,
        request_input: &[u8],
        output: &[u8],
        model_id: &str,
        provider: Address,
        claim: &JurisdictionClaim,
    ) -> Result<JurisdictionReceipt, JurisdictionError> {
        let mut receipt = unsigned(
            &self.hardware,
            request_input,
            output,
            model_id,
            provider,
            claim,
        );
        let signed_at_ms = u64::try_from(receipt.signed_at.as_millis())
            .map_err(|_| JurisdictionError::SignatureFailure("time before 1970".into()))?;
        let member = Member::sign_alone(
            self.root.as_ref(),
            &receipt.canonical_preimage(),
            signed_at_ms,
        )
        .map_err(|e| JurisdictionError::SignatureFailure(e.to_string()))?;
        if member.signature.signed_at_ms != signed_at_ms
            || member.signature.identity
                != tenzro_types::did_derivation::machine_did(&self.hardware.p256)
        {
            return Err(JurisdictionError::SignatureFailure(
                "the identity key signed for another machine or time".into(),
            ));
        }
        receipt.batched = Some(member.to_json());
        Ok(receipt)
    }
}

/// Verify a jurisdiction receipt's signature over its canonical preimage.
/// The record form verifies against the key the receipt names. The identity
/// key form verifies against `chain`: the root signature is made for the
/// machine the named hardware key derives, at the receipt's own time, by the
/// key the chain recorded for that machine at the version it names, that key
/// was not declared compromised, and the signature was not revoked.
pub fn verify_receipt(
    receipt: &JurisdictionReceipt,
    chain: Option<IdentityKeyCheck<'_>>,
) -> Result<(), JurisdictionError> {
    let signed_at_ms = u64::try_from(receipt.signed_at.as_millis())
        .map_err(|_| JurisdictionError::VerificationFailed)?;
    let raw = receipt
        .batched
        .as_deref()
        .ok_or(JurisdictionError::VerificationFailed)?;
    if let Some(member) = Member::from_json(raw) {
        let member = member.map_err(|e| JurisdictionError::IdentityKey(e.to_string()))?;
        let chain = chain.ok_or(JurisdictionError::NoChainView)?;
        if member.signature.identity
            != tenzro_types::did_derivation::machine_did(&receipt.signer_public_key)
        {
            return Err(JurisdictionError::KeyMismatch);
        }
        if member.signature.signed_at_ms != signed_at_ms {
            return Err(JurisdictionError::VerificationFailed);
        }
        return member
            .verify(
                &receipt.canonical_preimage(),
                chain.resolver,
                chain.now_ms,
                chain.params,
            )
            .map_err(|e| JurisdictionError::IdentityKey(e.to_string()));
    }
    let identity = CompositePublicKey::new(
        receipt.signer_public_key.clone(),
        receipt.signer_pq_key.clone(),
    )
    .map_err(|_| JurisdictionError::VerificationFailed)?;
    let sig: tenzro_crypto::batch::BatchedSignature =
        serde_json::from_slice(raw).map_err(|_| JurisdictionError::VerificationFailed)?;
    RecordSignature::batched(sig)
        .verify_record_at(&identity, &receipt.canonical_preimage(), signed_at_ms)
        .map_err(|_| JurisdictionError::VerificationFailed)
}

/// Verify every field of a provider-attached response receipt: the request and
/// response hashes must match the actual bytes, the model id must match the
/// routed request, the receipt must name `registered` (the hardware identity
/// key registered for the provider's machine DID, both legs) as its signer,
/// and the signature must verify against it. A provider with no registered
/// key cannot attach a verifiable receipt: `None` is refused. `chain` checks
/// a receipt in the identity key form ([`verify_receipt`]).
pub fn verify_response_receipt(
    receipt: &JurisdictionReceipt,
    request_input: &[u8],
    output: &[u8],
    model_id: &str,
    registered: Option<&CompositePublicKey>,
    chain: Option<IdentityKeyCheck<'_>>,
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
    verify_receipt(receipt, chain)
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

        verify_receipt(&receipt, None).expect("freshly signed receipt must verify");
        verify_response_receipt(
            &receipt,
            b"prompt bytes",
            b"output bytes",
            "qwen3-8b",
            Some(&own_key(&receipt)),
            None,
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
            verify_receipt(&receipt, None).unwrap_err(),
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
            verify_response_receipt(
                &receipt,
                b"in",
                b"different",
                "m",
                Some(&own_key(&receipt)),
                None
            )
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
            verify_response_receipt(
                &receipt,
                b"in",
                b"out",
                "other",
                Some(&own_key(&receipt)),
                None
            )
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
                verify_response_receipt(&receipt, b"in", b"out", "m", registered, None)
                    .unwrap_err(),
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

    mod identity_key {
        use super::*;
        use ed25519_dalek::Signer as _;
        use tenzro_crypto::composite::HybridSigner as _;
        use tenzro_crypto::pq::{MlDsaSigningKey, context};
        use tenzro_device_key::batch_signer::RootSignature;
        use tenzro_device_key::delegation::{DelegationResult, IssuerRecord};

        /// The machine's identity key at version 1, standing in for its TPM.
        pub(super) struct Key {
            pub(super) identity: String,
            ed: ed25519_dalek::SigningKey,
            ml: MlDsaSigningKey,
        }

        impl Key {
            pub(super) fn of(hardware: &CompositePublicKey, seed: u8) -> Self {
                Self {
                    identity: tenzro_types::did_derivation::machine_did(&hardware.p256),
                    ed: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
                    ml: MlDsaSigningKey::generate(),
                }
            }
            /// What the chain records for the key.
            pub(super) fn record(&self) -> IssuerRecord {
                IssuerRecord {
                    version: 1,
                    ed25519: self.ed.verifying_key().to_bytes(),
                    ml_dsa: self.ml.verifying_key_bytes().to_vec(),
                }
            }
        }

        impl RootSigner for Key {
            fn sign_root(
                &self,
                root: &[u8; 32],
                count: u32,
                now_ms: u64,
            ) -> DelegationResult<RootSignature> {
                let rec = self.record();
                let mut sig = RootSignature {
                    identity: self.identity.clone(),
                    issuer_version: rec.version,
                    issuer_ed25519: rec.ed25519,
                    issuer_ml_dsa: rec.ml_dsa,
                    signed_at_ms: now_ms,
                    count,
                    root: *root,
                    ed_signature: [0; 64],
                    ml_dsa_signature: Vec::new(),
                };
                let statement = sig.statement();
                sig.ed_signature = self.ed.sign(&statement).to_bytes();
                sig.ml_dsa_signature = self.ml.sign(context::BATCH_ROOT, &statement);
                Ok(sig)
            }
        }

        /// The chain's record of one identity's key, and one revocation.
        pub(super) struct Recorded {
            pub(super) rec: IssuerRecord,
            pub(super) revoked: Option<[u8; 32]>,
        }

        impl IssuerResolver for Recorded {
            fn resolve(&self, _identity: &str) -> DelegationResult<IssuerRecord> {
                Ok(self.rec.clone())
            }
            fn is_revoked(&self, _identity: &str, id: &[u8; 32]) -> bool {
                self.revoked == Some(*id)
            }
        }

        pub(super) fn hardware() -> CompositePublicKey {
            tenzro_crypto::composite::testing::TestHybridSigner::hybrid(41)
                .public_key()
                .clone()
        }
    }

    /// A receipt signed with the machine's identity key verifies against the
    /// key the chain records for that machine, and against nothing else: not
    /// without a chain view, not under another key, not once revoked, not
    /// tampered, and not for a machine the named hardware key does not derive.
    #[test]
    fn an_identity_key_receipt_verifies_against_the_chains_record_only() {
        use identity_key::{Key, Recorded, hardware};
        use tenzro_crypto::composite::HybridSigner as _;
        let hw = hardware();
        let key = Arc::new(Key::of(&hw, 7));
        let signer = IdentityKeyJurisdictionSigner::new(key.clone(), hw.clone());
        let r = signer
            .sign(b"in", b"out", "m", Address::default(), &claim())
            .unwrap();
        assert!(Member::from_json(r.batched.as_deref().unwrap()).is_some());
        let at = u64::try_from(r.signed_at.as_millis()).unwrap();
        let chain = Recorded {
            rec: key.record(),
            revoked: None,
        };
        let now_ms = at + 1_000;
        fn check(resolver: &dyn IssuerResolver, now_ms: u64) -> IdentityKeyCheck<'_> {
            IdentityKeyCheck {
                resolver,
                now_ms,
                params: VerifyParams { skew_ms: 60_000 },
            }
        }

        verify_receipt(&r, Some(check(&chain, now_ms))).unwrap();
        verify_response_receipt(
            &r,
            b"in",
            b"out",
            "m",
            Some(&hw),
            Some(check(&chain, now_ms)),
        )
        .unwrap();
        assert!(matches!(
            verify_receipt(&r, None).unwrap_err(),
            JurisdictionError::NoChainView
        ));

        let other = Recorded {
            rec: Key::of(&hw, 8).record(),
            revoked: None,
        };
        assert!(matches!(
            verify_receipt(&r, Some(check(&other, now_ms))).unwrap_err(),
            JurisdictionError::IdentityKey(_)
        ));

        let member = Member::from_json(r.batched.as_deref().unwrap())
            .unwrap()
            .unwrap();
        let revoked = Recorded {
            rec: key.record(),
            revoked: Some(member.signature.id()),
        };
        assert!(verify_receipt(&r, Some(check(&revoked, now_ms))).is_err());

        let mut tampered = r.clone();
        tampered.jurisdiction.country = "US".into();
        assert!(verify_receipt(&tampered, Some(check(&chain, now_ms))).is_err());

        // Naming another hardware key points the signature at a machine it
        // was not made for.
        let mut renamed = r.clone();
        renamed.signer_public_key = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(42)
            .public_key()
            .p256
            .clone();
        assert!(matches!(
            verify_receipt(&renamed, Some(check(&chain, now_ms))).unwrap_err(),
            JurisdictionError::KeyMismatch
        ));
    }

    /// A receipt in the record form still verifies when a chain view is
    /// given: the view is read only for the identity key form.
    #[test]
    fn a_record_form_receipt_verifies_with_or_without_a_chain_view() {
        use identity_key::{Recorded, hardware};
        let r = Ed25519JurisdictionSigner::generate()
            .unwrap()
            .sign(b"in", b"out", "m", Address::default(), &claim())
            .unwrap();
        let chain = Recorded {
            rec: identity_key::Key::of(&hardware(), 7).record(),
            revoked: None,
        };
        let check = IdentityKeyCheck {
            resolver: &chain,
            now_ms: 0,
            params: VerifyParams { skew_ms: 0 },
        };
        verify_receipt(&r, None).unwrap();
        verify_receipt(&r, Some(check)).unwrap();
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
        verify_receipt(&r, None).unwrap();
        let mut tampered = r.clone();
        tampered.jurisdiction.country = "US".into();
        assert!(verify_receipt(&tampered, None).is_err());
        // A receipt without its batch signature is refused.
        let mut unsigned = r.clone();
        unsigned.batched = None;
        assert!(verify_receipt(&unsigned, None).is_err());
        let again: JurisdictionReceipt =
            serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        assert_eq!(again, r);
    }
}
