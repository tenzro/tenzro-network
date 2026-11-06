//! The network insurance pool and the claims it pays.
//!
//! The pool is funded by a governed share of the fee revenue that would
//! otherwise go to the treasury (`fees.insurance_pool_bps`) and by every
//! slashed agent bond. It pays a claim only on evidence chain state already
//! holds of a loss a bonded party caused:
//!
//! - a frozen SLA verdict that judged a provider unavailable in an epoch its
//!   renter's stream paid it for, or
//! - a reconciliation mismatch on an attested route's settlement lock.
//!
//! A metered-charge dispute is repaid from the meter's bond alone: a meter
//! and its payer can be one party, so the pool never covers it.
//!
//! Each piece of evidence pays once, to the party the evidence names, capped
//! by `insurance.max_claim_bps` of the pool and `insurance.max_claim_tnzo`.

use serde::{Deserialize, Serialize};

/// Evidence of a loss caused by a bonded party's fault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsuranceEvidence {
    /// A reconciliation mismatch stored for an attested route's settlement
    /// lock that cost the claimant a leg's value.
    ReconMismatch {
        /// The route's bridge protocol.
        adapter: crate::bridge_route::BridgeRouteAdapter,
        /// The route's external chain.
        chain: String,
        /// The mismatched entry's position in the lock's record.
        position: u64,
    },
}

/// A claim the pool paid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsuranceClaim {
    /// Claim id: SHA-256 over the evidence, hex. One claim per evidence.
    pub claim_id: String,
    /// Account paid, hex.
    pub claimant: String,
    /// The evidence.
    pub evidence: InsuranceEvidence,
    /// The loss the evidence proves, wei.
    #[serde(with = "crate::primitives::u128_serde")]
    pub loss: u128,
    /// What the pool paid, wei: the loss, capped.
    #[serde(with = "crate::primitives::u128_serde")]
    pub paid: u128,
    /// Block time it was paid at, ms.
    pub paid_at_ms: i64,
}

/// Totals of the pool's history.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsurancePoolTotals {
    /// Claims paid.
    pub claims_paid: u64,
    /// Value paid out, wei.
    #[serde(with = "crate::primitives::u128_serde")]
    pub total_paid: u128,
    /// Value credited from fees, wei.
    #[serde(with = "crate::primitives::u128_serde")]
    pub from_fees: u128,
    /// Value credited from slashed bonds, wei.
    #[serde(with = "crate::primitives::u128_serde")]
    pub from_slashes: u128,
}

/// The id of the claim `evidence` pays.
pub fn claim_id(evidence: &InsuranceEvidence) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update(b"tenzro/insurance-claim")
        .chain_update(serde_json::to_vec(evidence).unwrap_or_default())
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_evidence_has_its_own_claim_id() {
        let a = InsuranceEvidence::ReconMismatch {
            adapter: crate::bridge_route::BridgeRouteAdapter::Ibc,
            chain: "cosmoshub-4".into(),
            position: 3,
        };
        let b = InsuranceEvidence::ReconMismatch {
            adapter: crate::bridge_route::BridgeRouteAdapter::Ibc,
            chain: "cosmoshub-4".into(),
            position: 4,
        };
        assert_ne!(claim_id(&a), claim_id(&b));
        assert_eq!(claim_id(&a), claim_id(&a.clone()));
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<InsuranceEvidence>(&json).unwrap(), a);
    }
}
