//! The network's economic policy: what is done with an inbound asset and where
//! the meter stops settling charges one by one.
//!
//! A settled payment is not divided by node mode: the payee gets the payment.
//! [`EconomicPolicy`] is the single governance-settable block for the two
//! values that are applied at settlement, and neither is a constant.

use std::fmt;

use serde::{Deserialize, Serialize};

/// What the network does with an inbound asset that is not TNZO.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionPolicy {
    /// Convert to TNZO at settlement. The network's default: TNZO is the unit
    /// the ledger accounts in, and a treasury holding forty stablecoins is a
    /// treasury nobody can value.
    #[default]
    ConvertToTnzo,
    /// Settle in whatever asset arrived. Selected per payee, for operators who
    /// would rather hold the stablecoin they were paid in than take conversion
    /// risk on every microtransaction.
    KeepInbound,
}

impl ConversionPolicy {
    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            ConversionPolicy::ConvertToTnzo => "convert_to_tnzo",
            ConversionPolicy::KeepInbound => "keep_inbound",
        }
    }

    /// Parse the wire form; unknown values are refused.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "convert_to_tnzo" => Some(ConversionPolicy::ConvertToTnzo),
            "keep_inbound" => Some(ConversionPolicy::KeepInbound),
            _ => None,
        }
    }
}

impl fmt::Display for ConversionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Every economic value governance sets, in one block.
///
/// Persisted and hydrated by the node; mutated only through a governance
/// proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicPolicy {
    /// The network's default disposition of a non-TNZO inbound asset. A payee
    /// may override it for their own receipts; this is what applies when they
    /// have expressed no preference.
    pub default_conversion: ConversionPolicy,
    /// Smallest charge the meter will settle on its own rather than accumulate.
    ///
    /// A per-token charge can be worth less than the gas to move it. Below this
    /// floor the meter accrues into a channel and settles the aggregate — the
    /// charge is still metered exactly, it is just not moved on its own.
    #[serde(with = "crate::primitives::u128_serde")]
    pub micro_settlement_floor: u128,
}

impl Default for EconomicPolicy {
    fn default() -> Self {
        Self {
            default_conversion: ConversionPolicy::ConvertToTnzo,
            // 10^13 of 10^18 — one ten-thousandth of a TNZO. Chosen so a single
            // token of a cheap model accrues rather than settling alone, while a
            // media-generation call settles immediately.
            micro_settlement_floor: 10_000_000_000_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_policy_round_trips_its_wire_form() {
        for policy in [
            ConversionPolicy::ConvertToTnzo,
            ConversionPolicy::KeepInbound,
        ] {
            assert_eq!(ConversionPolicy::parse(policy.as_str()), Some(policy));
        }
        assert_eq!(ConversionPolicy::parse("keep"), None);
    }

    #[test]
    fn the_default_policy_converts_to_tnzo_and_has_a_floor() {
        let policy = EconomicPolicy::default();
        assert_eq!(policy.default_conversion, ConversionPolicy::ConvertToTnzo);
        assert!(policy.micro_settlement_floor > 0);
    }
}
