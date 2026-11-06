//! x402 signed offers.
//!
//! An unsigned 402 body gives a buyer no way to prove which offer it paid
//! against if the seller later disputes the price. The server binds a
//! 32-byte domain-separated SHA-256 commitment over the canonical
//! [`X402PaymentRequirement`] and P-256-signs it. The signature travels in
//! `requirement.extra["offerSig"]` (+ `offerCommitment` + `offerSigner`) so a
//! client that does not know the extension ignores it and one that does
//! verifies the offer before paying.
//!
//! # Domain separation
//!
//! Per the project rule against version segments in Tenzro-owned strings, the
//! SHA-256 domain tag is the literal `"tenzro/x402/offer"` — no `/v1`, no
//! `1.0.0`. Schema revisions are flag-day cutovers under the same tag.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{PaymentError, Result};
use crate::x402::payment_required::X402PaymentRequirement;
use crate::x402::wire::CHALLENGE_ID_KEY;

/// Domain-separation tag for the offer commitment.
pub const X402_OFFER_DOMAIN: &str = "tenzro/x402/offer";

/// `extra` key carrying the hex-encoded offer commitment.
pub const OFFER_COMMITMENT_KEY: &str = "offerCommitment";
/// `extra` key carrying the hex-encoded P-256 offer signature (`r || s`).
pub const OFFER_SIG_KEY: &str = "offerSig";
/// `extra` key carrying the hex-encoded P-256 signer public key (`x || y`).
pub const OFFER_SIGNER_KEY: &str = "offerSigner";

/// Length of the offer commitment (SHA-256).
pub const X402_OFFER_COMMITMENT_LEN: usize = 32;

/// Compute the 32-byte offer commitment for a payment option on `resource`.
///
/// The commitment binds what a buyer relies on: the resource, scheme,
/// network, amount, asset, pay-to address and the challenge the option
/// answers. The challenge id carries the expiry, so a lapsed offer cannot be
/// paid against. Other `extra` entries are advisory and not bound.
///
/// Every field is length-prefixed with a 4-byte little-endian length so a
/// `/` in the resource path can never be confused with a field boundary.
pub fn compute_offer_commitment(
    resource: &str,
    requirement: &X402PaymentRequirement,
) -> [u8; X402_OFFER_COMMITMENT_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(X402_OFFER_DOMAIN.as_bytes());
    for field in [
        resource,
        requirement.scheme.as_str(),
        requirement.network.as_str(),
        requirement.amount.as_str(),
        requirement.asset.as_str(),
        requirement.pay_to.as_str(),
        requirement.extra_str(CHALLENGE_ID_KEY).unwrap_or_default(),
    ] {
        let bytes = field.as_bytes();
        hasher.update((bytes.len() as u32).to_le_bytes());
        hasher.update(bytes);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; X402_OFFER_COMMITMENT_LEN];
    out.copy_from_slice(&digest);
    out
}

/// A server-signed offer: the offer commitment, the P-256 signature over
/// it, and the signer's public key. All hex-encoded (no `0x` prefix).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedOffer {
    /// Hex-encoded 32-byte offer commitment.
    pub offer_commitment: String,
    /// Hex-encoded P-256 signature (`r || s`) over the commitment bytes.
    pub offer_sig: String,
    /// Hex-encoded P-256 public key (`x || y`) of the seller/facilitator.
    pub offer_signer: String,
}

impl SignedOffer {
    /// Sign the option `requirement` on `resource` with the server's hardware P-256 signer, returning the
    /// signed-offer triple. The signature is over the raw 32-byte commitment.
    pub fn sign(
        resource: &str,
        requirement: &X402PaymentRequirement,
        signer: &dyn tenzro_crypto::composite::HybridSigner,
    ) -> Result<Self> {
        let key = &signer.public_key().p256;
        let commitment = compute_offer_commitment(resource, requirement);
        let sig = signer
            .sign(
                tenzro_crypto::composite::SignatureContext::X402Offer,
                &commitment,
            )
            .map_err(|e| PaymentError::CryptoError(format!("offer sign failed: {e}")))?;
        let tenzro_crypto::composite::ClassicalProof::Raw { signature } = sig.classical else {
            return Err(PaymentError::CryptoError(
                "offers are signed with a device P-256 key, not a passkey".to_string(),
            ));
        };
        Ok(Self {
            offer_commitment: hex::encode(commitment),
            offer_sig: hex::encode(&signature),
            offer_signer: hex::encode(key),
        })
    }

    /// Verify the offer signature against the option `requirement` on `resource`.
    ///
    /// Recomputes the commitment from the requirement (so a tampered price or
    /// pay-to address invalidates the signature), checks it matches the
    /// carried commitment, then verifies the P-256 signature under the
    /// carried signer key.
    pub fn verify(&self, resource: &str, requirement: &X402PaymentRequirement) -> Result<()> {
        let expected = compute_offer_commitment(resource, requirement);
        let carried = hex::decode(&self.offer_commitment).map_err(|e| {
            PaymentError::VerificationFailed(format!("bad offer commitment hex: {e}"))
        })?;
        if carried != expected {
            return Err(PaymentError::VerificationFailed(
                "offer commitment does not match requirement".to_string(),
            ));
        }
        let sig_bytes = hex::decode(&self.offer_sig)
            .map_err(|e| PaymentError::VerificationFailed(format!("bad offer sig hex: {e}")))?;
        let key_bytes = hex::decode(&self.offer_signer)
            .map_err(|e| PaymentError::VerificationFailed(format!("bad offer signer hex: {e}")))?;
        // Any error (bad key, bad signature, mismatch) becomes a
        // VerificationFailed.
        tenzro_crypto::composite::verify_classical_component(
            &key_bytes,
            tenzro_crypto::composite::SignatureContext::X402Offer,
            &expected,
            &tenzro_crypto::composite::ClassicalProof::Raw {
                signature: sig_bytes,
            },
        )
        .map_err(|e| PaymentError::VerificationFailed(format!("offer signature invalid: {e}")))?;
        Ok(())
    }

    /// Attach this signed offer to a requirement's `extra` object under the
    /// `offerCommitment` / `offerSig` / `offerSigner` keys, preserving any
    /// existing scheme-specific `extra`.
    pub fn attach_to(&self, requirement: &mut X402PaymentRequirement) {
        let obj = match &mut requirement.extra {
            serde_json::Value::Object(m) => m,
            other => {
                *other = serde_json::Value::Object(serde_json::Map::new());
                other.as_object_mut().expect("just set object")
            }
        };
        obj.insert(
            OFFER_COMMITMENT_KEY.to_string(),
            serde_json::Value::String(self.offer_commitment.clone()),
        );
        obj.insert(
            OFFER_SIG_KEY.to_string(),
            serde_json::Value::String(self.offer_sig.clone()),
        );
        obj.insert(
            OFFER_SIGNER_KEY.to_string(),
            serde_json::Value::String(self.offer_signer.clone()),
        );
    }

    /// Extract a signed offer from a requirement's `extra`, if all three keys
    /// are present and string-typed.
    pub fn extract_from(requirement: &X402PaymentRequirement) -> Option<Self> {
        let obj = requirement.extra.as_object()?;
        let s = |k: &str| obj.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
        Some(Self {
            offer_commitment: s(OFFER_COMMITMENT_KEY)?,
            offer_sig: s(OFFER_SIG_KEY)?,
            offer_signer: s(OFFER_SIGNER_KEY)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESOURCE: &str = "https://api.tenzro.com/paid/resource";

    fn requirement() -> X402PaymentRequirement {
        X402PaymentRequirement::new(
            "tenzro-hybrid",
            "tenzro:1337",
            "1000",
            "0xrecipient",
            "TNZO",
            300,
        )
        .with_extra(serde_json::json!({ "challengeId": "ch-1" }))
    }

    fn signer() -> tenzro_crypto::composite::testing::TestHybridSigner {
        static SEED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
        tenzro_crypto::composite::testing::TestHybridSigner::hybrid(
            SEED.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )
    }

    #[test]
    fn the_commitment_binds_price_payee_resource_and_challenge() {
        let base = compute_offer_commitment(RESOURCE, &requirement());
        assert_eq!(base, compute_offer_commitment(RESOURCE, &requirement()));

        let mut r = requirement();
        r.amount = "1001".to_string();
        assert_ne!(compute_offer_commitment(RESOURCE, &r), base);

        let mut r = requirement();
        r.pay_to = "0xother".to_string();
        assert_ne!(compute_offer_commitment(RESOURCE, &r), base);

        let mut r = requirement();
        r.set_extra(CHALLENGE_ID_KEY, serde_json::json!("ch-2"));
        assert_ne!(compute_offer_commitment(RESOURCE, &r), base);

        assert_ne!(compute_offer_commitment("/other", &requirement()), base);

        // Advisory extra does not move it.
        let mut r = requirement();
        r.set_extra("eip712Name", serde_json::json!("USD Coin"));
        assert_eq!(compute_offer_commitment(RESOURCE, &r), base);
    }

    #[test]
    fn a_signed_offer_verifies_and_a_tampered_price_does_not() {
        let r = requirement();
        let signed = SignedOffer::sign(RESOURCE, &r, &signer()).unwrap();
        assert!(signed.verify(RESOURCE, &r).is_ok());

        let mut tampered = r.clone();
        tampered.amount = "1".to_string();
        assert!(matches!(
            signed.verify(RESOURCE, &tampered).unwrap_err(),
            PaymentError::VerificationFailed(_)
        ));
    }

    #[test]
    fn attach_and_extract_round_trips_and_preserves_scheme_extra() {
        let mut r = requirement();
        r.set_extra("permit2Nonce", serde_json::json!("0x7"));
        let signed = SignedOffer::sign(RESOURCE, &r, &signer()).unwrap();
        signed.attach_to(&mut r);
        assert_eq!(r.extra["permit2Nonce"], serde_json::json!("0x7"));
        let extracted = SignedOffer::extract_from(&r).unwrap();
        assert_eq!(extracted, signed);
        assert!(extracted.verify(RESOURCE, &r).is_ok());
    }
}
