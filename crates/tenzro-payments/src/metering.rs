//! Signed usage records for metered (`upto`) payments.
//!
//! Under `upto` the buyer signs a ceiling and the seller chooses the charge
//! after serving. When the challenge names a meter key (`meter_key` in its
//! `extra`, set by the seller at mint time), the charge must come with a
//! usage record that key signed: the units served, their prices, and the
//! resulting charge, bound to the challenge, the payer and the ceiling. The
//! charge is then exactly what the seller's meter claims, and the buyer holds
//! the seller's signed statement of it.

use tenzro_crypto::composite::HybridSigner;

use crate::error::{PaymentError, Result};
use crate::types::{PaymentChallenge, PaymentCredential};

pub use tenzro_types::metering::{USAGE_RECORD_DOMAIN, UsageLine, UsageRecord};

/// Challenge `extra` key naming the meter's P-256 key (hex `x || y`) that signs usage.
pub const METER_KEY: &str = "meter_key";

/// Credential `extra` key carrying the usage record.
pub const USAGE_RECORD_KEY: &str = "usage_record";

fn refuse(why: impl Into<String>) -> PaymentError {
    PaymentError::VerificationFailed(format!("usage record: {}", why.into()))
}

/// Signing and checking a [`UsageRecord`] against the challenge it meters.
pub trait MeterRecord: Sized {
    /// The charge the lines add up to.
    fn checked_charge(&self) -> Result<u128>;

    /// Sign a record for `lines` served against `challenge` to `payer`
    /// under `ceiling`, with the meter's signer.
    fn sign(
        challenge: &PaymentChallenge,
        payer: &str,
        ceiling: u128,
        lines: Vec<UsageLine>,
        signer: &dyn HybridSigner,
    ) -> Result<Self> {
        Self::sign_committed(challenge, payer, ceiling, lines, Default::default(), signer)
    }

    /// [`MeterRecord::sign`] binding `commitments` (32-byte hex each): what
    /// the charge was priced on, the receipts it covers, provenance.
    fn sign_committed(
        challenge: &PaymentChallenge,
        payer: &str,
        ceiling: u128,
        lines: Vec<UsageLine>,
        commitments: std::collections::BTreeMap<String, String>,
        signer: &dyn HybridSigner,
    ) -> Result<Self>;

    /// Check the record backs `charge` for `payer` against `challenge`,
    /// signed by the meter's P-256 key and, when the meter's account enrolled
    /// one, its ML-DSA-65 key.
    fn verify(
        &self,
        keys: &dyn crate::payer_auth::EnrolledKeys,
        challenge: &PaymentChallenge,
        payer: &str,
        ceiling: u128,
        charge: u128,
    ) -> Result<()>;
}

impl MeterRecord for UsageRecord {
    fn checked_charge(&self) -> Result<u128> {
        self.charge().ok_or_else(|| refuse("the charge overflows"))
    }

    fn sign_committed(
        challenge: &PaymentChallenge,
        payer: &str,
        ceiling: u128,
        lines: Vec<UsageLine>,
        commitments: std::collections::BTreeMap<String, String>,
        signer: &dyn HybridSigner,
    ) -> Result<Self> {
        if !tenzro_types::metering::commitments_well_formed(&commitments) {
            return Err(refuse(
                "commitments must be at most 8 labelled 32-byte hex values",
            ));
        }
        let mut record = Self {
            challenge_id: challenge.challenge_id.clone(),
            payer: payer.to_string(),
            ceiling,
            lines,
            measured_at_ms: chrono::Utc::now().timestamp_millis(),
            commitments,
            meter_key: hex::encode(&signer.public_key().p256),
            signature: tenzro_crypto::composite::CompositeSignature::classical(
                tenzro_crypto::composite::ClassicalProof::Raw {
                    signature: Vec::new(),
                },
            ),
        };
        if record.checked_charge()? > ceiling {
            return Err(refuse("the metered charge exceeds the signed ceiling"));
        }
        let sig = signer
            .sign(
                tenzro_crypto::composite::SignatureContext::UsageRecord,
                &record.preimage(),
            )
            .map_err(|e| PaymentError::CryptoError(format!("meter signing: {e}")))?;
        record.signature = sig;
        Ok(record)
    }

    fn verify(
        &self,
        keys: &dyn crate::payer_auth::EnrolledKeys,
        challenge: &PaymentChallenge,
        payer: &str,
        ceiling: u128,
        charge: u128,
    ) -> Result<()> {
        let expected_key = challenge
            .extra
            .get(METER_KEY)
            .and_then(|v| v.as_str())
            .ok_or_else(|| refuse("the challenge names no meter key"))?;
        if !self.meter_key.eq_ignore_ascii_case(expected_key) {
            return Err(refuse("signed by another meter"));
        }
        if self.challenge_id != challenge.challenge_id {
            return Err(refuse("for another challenge"));
        }
        if !self.payer.eq_ignore_ascii_case(payer) {
            return Err(refuse("for another payer"));
        }
        if self.ceiling != ceiling {
            return Err(refuse("under another ceiling"));
        }
        if self.checked_charge()? != charge {
            return Err(refuse(format!(
                "its lines add to {} but the charge is {}",
                self.checked_charge()?,
                charge
            )));
        }
        let key = self
            .meter_public_key()
            .ok_or_else(|| refuse("meter key is not a P-256 key"))?;
        crate::payer_auth::verify_payer_signature(
            keys,
            &key,
            tenzro_crypto::composite::SignatureContext::UsageRecord,
            &self.preimage(),
            &self.signature,
        )
        .map_err(|e| refuse(format!("signature does not verify: {e}")))
    }
}

/// The usage record a credential carries.
pub fn usage_record(credential: &PaymentCredential) -> Result<Option<UsageRecord>> {
    credential
        .extra
        .get(USAGE_RECORD_KEY)
        .map(|v| serde_json::from_value(v.clone()).map_err(|e| refuse(format!("unreadable: {e}"))))
        .transpose()
}

/// Attach `record` to `credential` and set the charge it backs. The ceiling
/// the payer signed stays recorded under `upto_max`.
pub fn attach(credential: &mut PaymentCredential, record: &UsageRecord) -> Result<()> {
    credential
        .extra
        .entry(crate::payer_auth::UPTO_MAX_KEY.to_string())
        .or_insert_with(|| serde_json::json!(record.ceiling.to_string()));
    credential.amount = record.checked_charge()?;
    credential.extra.insert(
        USAGE_RECORD_KEY.to_string(),
        serde_json::to_value(record)
            .map_err(|e| PaymentError::SerializationError(e.to_string()))?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::signer;

    fn challenge(meter: &dyn HybridSigner) -> PaymentChallenge {
        let mut extra = std::collections::HashMap::new();
        extra.insert(
            METER_KEY.to_string(),
            serde_json::json!(hex::encode(&meter.public_key().p256)),
        );
        PaymentChallenge {
            challenge_id: "ch-1".into(),
            protocol: "x402".into(),
            resource: "/v1/chat".into(),
            amount: 10_000,
            asset: "TNZO".into(),
            recipient: "09".repeat(20),
            chain: "tenzro".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(1),
            extra,
        }
    }

    fn lines() -> Vec<UsageLine> {
        vec![
            UsageLine {
                unit: "input_tokens".into(),
                quantity: 120,
                unit_price: 10,
            },
            UsageLine {
                unit: "output_tokens".into(),
                quantity: 40,
                unit_price: 30,
            },
        ]
    }

    #[test]
    fn a_signed_record_backs_exactly_its_charge() {
        let meter = signer();
        let ch = challenge(&meter);
        let r = UsageRecord::sign(&ch, "ab", 10_000, lines(), &meter).unwrap();
        assert_eq!(r.checked_charge().unwrap(), 2_400);
        r.verify(&crate::test_support::SeedKeys, &ch, "ab", 10_000, 2_400)
            .unwrap();
        assert!(
            r.verify(&crate::test_support::SeedKeys, &ch, "ab", 10_000, 2_401)
                .is_err()
        );
        assert!(
            r.verify(&crate::test_support::SeedKeys, &ch, "cd", 10_000, 2_400)
                .is_err()
        );
        assert!(
            r.verify(&crate::test_support::SeedKeys, &ch, "ab", 9_999, 2_400)
                .is_err()
        );
    }

    #[test]
    fn a_forged_or_inflated_record_is_refused() {
        let meter = signer();
        let ch = challenge(&meter);
        let mut r = UsageRecord::sign(&ch, "ab", 10_000, lines(), &meter).unwrap();
        r.lines[1].quantity = 400;
        assert!(
            r.verify(&crate::test_support::SeedKeys, &ch, "ab", 10_000, 12_120)
                .is_err()
        );

        let other = signer();
        let forged = UsageRecord::sign(&ch, "ab", 10_000, lines(), &other).unwrap();
        assert!(
            forged
                .verify(&crate::test_support::SeedKeys, &ch, "ab", 10_000, 2_400)
                .is_err()
        );

        let over = vec![UsageLine {
            unit: "seconds".into(),
            quantity: 1,
            unit_price: 10_001,
        }];
        assert!(UsageRecord::sign(&ch, "ab", 10_000, over, &meter).is_err());
    }
}
