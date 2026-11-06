//! Provider resource pricing.
//!
//! A provider prices each resource (compute/GPU per epoch, storage per
//! byte-epoch) at a fixed rate it publishes. The rate never follows demand:
//! a deal opened now pays what a deal opened at any other time would, so a
//! buyer cannot be priced by how busy the network is and a provider cannot
//! raise its rate by filling its own capacity.

use serde::{Deserialize, Serialize};

/// How a provider sets the rate for one resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PricingPolicy {
    /// Flat operator-set rate.
    Fixed {
        #[serde(with = "tenzro_types::primitives::u128_serde")]
        rate: u128,
    },
}

impl PricingPolicy {
    /// The rate a deal opened now pays.
    pub fn effective_rate(&self) -> u128 {
        match self {
            PricingPolicy::Fixed { rate } => *rate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_rate_is_flat() {
        let p = PricingPolicy::Fixed { rate: 42 };
        assert_eq!(p.effective_rate(), 42);
    }

    /// A configuration asking for a demand-driven rate is refused when it is
    /// read, so no node runs one.
    #[test]
    fn a_demand_driven_policy_is_refused() {
        let fixed: PricingPolicy =
            serde_json::from_value(serde_json::json!({ "kind": "fixed", "rate": "7" })).unwrap();
        assert_eq!(fixed.effective_rate(), 7);
        let dynamic = serde_json::json!({
            "kind": "dynamic",
            "capacity": "1000",
            "denominator": "16",
            "ema_window": "4",
            "min_rate": "1",
            "max_rate": "10",
            "current_rate": "5",
            "ema_utilization": "500",
        });
        assert!(serde_json::from_value::<PricingPolicy>(dynamic).is_err());
    }
}
