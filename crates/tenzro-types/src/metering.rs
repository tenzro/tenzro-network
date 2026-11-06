//! Signed usage records and the bond that backs them.
//!
//! Under an `upto` HTTP-402 payment the buyer signs a ceiling and the seller
//! settles what it served beneath it. A seller that meters signs a
//! [`UsageRecord`] with its meter key: the units served, their prices, and the
//! charge they add up to, bound to the challenge, the payer and the ceiling.
//!
//! The record is a claim the seller can be held to. A meter key is backed by a
//! [`MeterBond`] posted on chain, and for the governed dispute window after a
//! record is measured its payer may prove on chain that the meter lied:
//!
//! - [`MeterDispute::Equivocation`]: two different records signed by one meter
//!   key for one challenge.
//! - [`MeterDispute::OverCeiling`]: a signed record whose lines add up to more
//!   than the ceiling the payer signed.
//! - [`MeterDispute::OverSettled`]: the chain settled more for the challenge
//!   than the record the meter signed for it.
//!
//! Each is decided from signed data and chain state alone. A proven dispute
//! pays the payer out of the bond; a bond can be withdrawn only after the
//! window has passed since its owner asked to withdraw it.

use serde::{Deserialize, Serialize};

/// Domain tag of a usage record's signing preimage.
pub const USAGE_RECORD_DOMAIN: &str = "tenzro/metering/usage-record";

/// Most commitments one usage record carries.
pub const MAX_COMMITMENTS: usize = 8;

/// Whether `commitments` is well formed: at most [`MAX_COMMITMENTS`], each
/// label 1..=24 of `[a-z0-9_]`, each value 64 lower-case hex characters.
pub fn commitments_well_formed(commitments: &std::collections::BTreeMap<String, String>) -> bool {
    commitments.len() <= MAX_COMMITMENTS
        && commitments.iter().all(|(l, v)| {
            !l.is_empty()
                && l.len() <= 24
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                && v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// Domain tag of the meter key's consent to a bond owner.
pub const METER_BOND_DOMAIN: &str = "tenzro/metering/bond";

/// One metered line: `quantity` units of `unit` at `unit_price` each.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageLine {
    /// What was metered: `requests`, `input_tokens`, `seconds`, ...
    pub unit: String,
    /// How many.
    #[serde(with = "crate::primitives::u128_serde")]
    pub quantity: u128,
    /// Price per unit, in the payment asset's smallest unit.
    #[serde(with = "crate::primitives::u128_serde")]
    pub unit_price: u128,
}

/// A seller's signed statement of what it served against one challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageRecord {
    /// The challenge the usage was served against; the settlement's payment id.
    pub challenge_id: String,
    /// The paying account (hex of its first 20 bytes).
    pub payer: String,
    /// The ceiling the payer signed.
    #[serde(with = "crate::primitives::u128_serde")]
    pub ceiling: u128,
    /// The metered lines.
    pub lines: Vec<UsageLine>,
    /// Unix milliseconds the metering closed.
    pub measured_at_ms: i64,
    /// 32-byte commitments the record binds, hex, each under a label: what
    /// the charge was priced on (`card`, a registry entry's digest), the
    /// receipts it covers (`receipts`), provenance (`provenance`), and what a
    /// unit's verification class needs, such as an inference's `model`,
    /// `decode` (precision, engine version, hardware class and seed) and
    /// `activations`. A unit that needs none carries none. The chain does
    /// not interpret them; a dispute or an audit shows what they open to.
    /// At most [`MAX_COMMITMENTS`], labels 1..=24 of `[a-z0-9_]`.
    #[serde(default)]
    pub commitments: std::collections::BTreeMap<String, String>,
    /// The meter's hardware P-256 public key (`x || y`, hex). The meter id
    /// is its account slot (`tenzro_crypto::account_slot`).
    pub meter_key: String,
    /// The meter's signature over [`UsageRecord::preimage`] under the
    /// usage-record context; an ML-DSA-65 leg is checked against the key
    /// enrolled in state for the meter id.
    pub signature: crate::account_signature::CompositeSignature,
}

impl UsageRecord {
    /// The charge the lines add up to, or `None` if it overflows.
    pub fn charge(&self) -> Option<u128> {
        self.lines.iter().try_fold(0u128, |acc, l| {
            l.quantity
                .checked_mul(l.unit_price)
                .and_then(|v| acc.checked_add(v))
        })
    }

    /// The bytes the meter key signs.
    pub fn preimage(&self) -> Vec<u8> {
        let mut m = USAGE_RECORD_DOMAIN.as_bytes().to_vec();
        let mut field = |b: &[u8]| {
            m.extend_from_slice(&(b.len() as u32).to_le_bytes());
            m.extend_from_slice(b);
        };
        field(self.challenge_id.as_bytes());
        field(self.payer.as_bytes());
        field(&self.ceiling.to_le_bytes());
        field(&(self.lines.len() as u32).to_le_bytes());
        for l in &self.lines {
            field(l.unit.as_bytes());
            field(&l.quantity.to_le_bytes());
            field(&l.unit_price.to_le_bytes());
        }
        field(&self.measured_at_ms.to_le_bytes());
        field(self.meter_key.as_bytes());
        field(&(self.commitments.len() as u32).to_le_bytes());
        for (label, c) in &self.commitments {
            field(label.as_bytes());
            field(c.as_bytes());
        }
        m
    }

    /// The meter's P-256 key as raw bytes, if it is 64 bytes of hex.
    pub fn meter_public_key(&self) -> Option<Vec<u8>> {
        hex::decode(self.meter_key.trim_start_matches("0x"))
            .ok()
            .filter(|k| k.len() == crate::payment_authorization::P256_PUBLIC_KEY_LEN)
    }
}

/// The bytes a meter signs to let `owner` post its bond on `chain_id`.
pub fn meter_bond_consent(chain_id: u64, meter_id: &[u8; 32], owner: &[u8; 32]) -> Vec<u8> {
    let mut m = METER_BOND_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(&chain_id.to_le_bytes());
    m.extend_from_slice(meter_id);
    m.extend_from_slice(owner);
    m
}

/// A bond backing a meter, held by the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeterBond {
    /// The meter it backs: the account slot of the meter's P-256 key.
    pub meter_id: [u8; 32],
    /// The account that posted it and receives it back.
    pub owner: [u8; 32],
    /// What the bond holds.
    #[serde(with = "crate::primitives::u128_serde")]
    pub amount: u128,
    /// When its owner asked to withdraw it; it pays out a full dispute window
    /// later.
    pub withdrawal_requested_at_ms: Option<i64>,
}

/// What a dispute claims a meter did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeterDispute {
    /// Two different records for one challenge, signed by one meter key.
    Equivocation {
        /// One record.
        first: UsageRecord,
        /// The other.
        second: UsageRecord,
    },
    /// A signed record whose lines exceed its ceiling.
    OverCeiling {
        /// The record.
        record: UsageRecord,
    },
    /// The chain settled more for the record's challenge than it charges.
    OverSettled {
        /// The record.
        record: UsageRecord,
    },
}

impl MeterDispute {
    /// The record the dispute is about (the first, for an equivocation).
    pub fn record(&self) -> &UsageRecord {
        match self {
            MeterDispute::Equivocation { first, .. } => first,
            MeterDispute::OverCeiling { record } | MeterDispute::OverSettled { record } => record,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> UsageRecord {
        UsageRecord {
            challenge_id: "ch".into(),
            payer: "ab".into(),
            ceiling: 100,
            lines: vec![UsageLine {
                unit: "requests".into(),
                quantity: 2,
                unit_price: 30,
            }],
            measured_at_ms: 1,
            commitments: Default::default(),
            meter_key: "00".repeat(64),
            signature: crate::account_signature::CompositeSignature::classical(
                crate::account_signature::ClassicalProof::Raw {
                    signature: Vec::new(),
                },
            ),
        }
    }

    #[test]
    fn the_preimage_covers_every_signed_field() {
        let base = record();
        let mut changed = vec![];
        let mut r = base.clone();
        r.challenge_id = "other".into();
        changed.push(r);
        let mut r = base.clone();
        r.payer = "cd".into();
        changed.push(r);
        let mut r = base.clone();
        r.ceiling = 101;
        changed.push(r);
        let mut r = base.clone();
        r.lines[0].quantity = 3;
        changed.push(r);
        let mut r = base.clone();
        r.lines[0].unit_price = 31;
        changed.push(r);
        let mut r = base.clone();
        r.commitments.insert("card".into(), "ab".repeat(32));
        changed.push(r);
        let mut r = base.clone();
        r.commitments.insert("decode".into(), "ab".repeat(32));
        changed.push(r);
        let mut r = base.clone();
        r.lines[0].unit = "seconds".into();
        changed.push(r);
        let mut r = base.clone();
        r.measured_at_ms = 2;
        changed.push(r);
        let mut r = base.clone();
        r.meter_key = "11".repeat(64);
        changed.push(r);
        for r in changed {
            assert_ne!(r.preimage(), base.preimage());
        }
        assert_eq!(base.charge(), Some(60));
    }

    #[test]
    fn an_overflowing_charge_is_none() {
        let mut r = record();
        r.lines[0].quantity = u128::MAX;
        assert_eq!(r.charge(), None);
    }
}
