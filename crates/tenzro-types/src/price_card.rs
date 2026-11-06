//! What an operator charges for a model, and the one function that turns a
//! meter into a charge.
//!
//! A [`RateCard`] is the price list: a price per meter key (unit, or unit at
//! a tier), each quoted per a power of ten of the unit so a fraction of the
//! smallest denomination per token can still be stated exactly, plus a
//! per-call minimum. It is denominated in USD (billionths of a dollar,
//! converted to TNZO at the rate chain state holds when the charge is
//! computed) or directly in TNZO base units.
//!
//! A [`PriceCard`] is a rate card a provider publishes for one model as a
//! generic registry entry; receipts and usage records commit to that entry's
//! digest. The chain stores the card and never prices with it: pricing,
//! quoting and comparing cards are the business of the node that serves and
//! of the harness modules that route and pay.
//!
//! [`RateCard::charge_in_denom`] is the only pricing rule. Each billable key
//! the card prices costs its line; a billable key the card does not price
//! costs nothing, since what a card leaves out is its operator's choice, but
//! a call none of whose billable work the card prices is refused rather than
//! served free. A key for a unit that is recorded but not billable (time to
//! first token) is ignored, a key for an unregistered unit refuses the
//! charge, and arithmetic is checked.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::meter::{MeterError, parse_key};
use crate::model::BillableUnits;

/// Largest [`Rate::per_exp`]: a price may be quoted per up to 10^24 units.
pub const MAX_PER_EXP: u8 = 24;

/// Billionths of a US dollar in one dollar.
pub const NANO_USD_PER_USD: u128 = 1_000_000_000;

/// TNZO base units in one TNZO.
pub const WEI_PER_TNZO: u128 = 1_000_000_000_000_000_000;

/// What a card's prices are denominated in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Denom {
    /// Billionths of a US dollar, settled in TNZO at the rate in force.
    #[default]
    NanoUsd,
    /// TNZO base units.
    Wei,
}

/// The price of one meter key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rate {
    /// Price of `10^per_exp` units, in the card's denomination.
    #[serde(with = "crate::primitives::u128_serde")]
    pub price: u128,
    /// The power of ten of units `price` is quoted for: 6 quotes per million
    /// tokens, 3 per second of a millisecond unit, 0 per unit.
    #[serde(default)]
    pub per_exp: u8,
}

impl Rate {
    /// `price` per `10^per_exp` units.
    pub fn per(price: u128, per_exp: u8) -> Self {
        Self { price, per_exp }
    }

    /// What `quantity` units cost at this rate, rounded up so a non-zero
    /// quantity at a non-zero price never costs nothing.
    pub fn cost(&self, quantity: u128) -> Option<u128> {
        let num = quantity.checked_mul(self.price)?;
        let den = 10u128.checked_pow(self.per_exp as u32)?;
        Some(num.div_ceil(den))
    }
}

/// A price list for one model.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RateCard {
    #[serde(default)]
    pub denom: Denom,
    /// Price per meter key.
    #[serde(default)]
    pub lines: BTreeMap<String, Rate>,
    /// Least one call is charged, in the card's denomination.
    #[serde(default, with = "crate::primitives::u128_serde")]
    pub min_charge: u128,
}

/// Why a charge or a card was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PricingError {
    #[error(transparent)]
    Meter(#[from] MeterError),
    #[error("unit '{0}' is not registered")]
    UnknownUnit(String),
    #[error("unit '{0}' is recorded but not billable, so a card cannot price it")]
    NotBillable(String),
    #[error("the card prices none of the billable work metered ({0})")]
    Unpriced(String),
    #[error("per_exp of '{0}' is above {MAX_PER_EXP}")]
    PerExp(String),
    #[error("the card has {0} lines, more than the {1} allowed")]
    TooManyLines(usize, usize),
    #[error("the charge overflows")]
    Overflow,
    #[error("no TNZO/USD rate to convert a USD card at")]
    NoRate,
}

impl RateCard {
    /// Check the card against the unit registry, read through `billable`:
    /// `Some(true)` for a billable unit, `Some(false)` for a recorded-only
    /// one, `None` for an unregistered id.
    pub fn validate(
        &self,
        max_lines: usize,
        billable: impl Fn(&str) -> Option<bool>,
    ) -> Result<(), PricingError> {
        if self.lines.len() > max_lines {
            return Err(PricingError::TooManyLines(self.lines.len(), max_lines));
        }
        for (k, rate) in &self.lines {
            let (unit, _) = parse_key(k)?;
            match billable(unit) {
                None => return Err(PricingError::UnknownUnit(unit.to_string())),
                Some(false) => return Err(PricingError::NotBillable(unit.to_string())),
                Some(true) => {}
            }
            if rate.per_exp > MAX_PER_EXP {
                return Err(PricingError::PerExp(k.clone()));
            }
        }
        Ok(())
    }

    /// The charge for `units`, in the card's denomination: the sum of each
    /// priced key's cost, at least `min_charge`. A key for a recorded-only
    /// unit is skipped and a billable key the card does not price costs
    /// nothing; a key the registry does not know refuses the charge, and so
    /// does billable work none of which the card prices.
    pub fn charge_in_denom(
        &self,
        units: &BillableUnits,
        billable: impl Fn(&str) -> Option<bool>,
    ) -> Result<u128, PricingError> {
        let mut total = 0u128;
        let mut unpriced = Vec::new();
        let mut priced_any = false;
        for (k, q) in units.iter() {
            let (unit, _) = parse_key(k)?;
            match billable(unit) {
                None => return Err(PricingError::UnknownUnit(unit.to_string())),
                Some(false) => continue,
                Some(true) => {}
            }
            let Some(rate) = self.lines.get(k) else {
                unpriced.push(k.to_string());
                continue;
            };
            priced_any = true;
            let cost = rate.cost(q).ok_or(PricingError::Overflow)?;
            total = total.checked_add(cost).ok_or(PricingError::Overflow)?;
        }
        if !priced_any && !unpriced.is_empty() {
            return Err(PricingError::Unpriced(unpriced.join(", ")));
        }
        Ok(total.max(self.min_charge))
    }

    /// The charge for `units` in TNZO base units. A USD card converts at
    /// `tnzo_usd_nano`, billionths of a dollar per TNZO, rounding up.
    pub fn charge_wei(
        &self,
        units: &BillableUnits,
        billable: impl Fn(&str) -> Option<bool>,
        tnzo_usd_nano: u128,
    ) -> Result<u128, PricingError> {
        let amount = self.charge_in_denom(units, billable)?;
        self.to_wei(amount, tnzo_usd_nano)
    }

    /// Convert an amount in this card's denomination to TNZO base units.
    pub fn to_wei(&self, amount: u128, tnzo_usd_nano: u128) -> Result<u128, PricingError> {
        match self.denom {
            _ if amount == 0 => Ok(0),
            Denom::Wei => Ok(amount),
            Denom::NanoUsd => {
                if tnzo_usd_nano == 0 {
                    return Err(PricingError::NoRate);
                }
                amount
                    .checked_mul(WEI_PER_TNZO)
                    .map(|v| v.div_ceil(tnzo_usd_nano))
                    .ok_or(PricingError::Overflow)
            }
        }
    }
}

/// A rate card a provider publishes for one model, as the data of its
/// registry entry `<provider>/card/<model_id>` (kind `card`). The provider is
/// the entry's owner; the registry versions it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceCard {
    /// Catalog id of the model.
    pub model_id: String,
    /// Hash of the catalog entry's weights the card prices, so a card cannot
    /// be carried over to other weights under the same id.
    pub model_hash: String,
    pub rates: RateCard,
}

/// Registry kind of a price card entry.
pub const CARD_KIND: &str = "card";

/// The name, under its provider, of the registry entry carrying the card for
/// `model_id`.
pub fn card_entry_name(model_id: &str) -> String {
    format!("card/{model_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meter::unit;

    fn registry(unit: &str) -> Option<bool> {
        crate::meter::genesis_units()
            .into_iter()
            .find(|u| u.id == unit)
            .map(|u| u.billable)
    }

    fn llm_card() -> RateCard {
        let mut lines = BTreeMap::new();
        // $0.20 per million input tokens, $1.00 per million output tokens.
        lines.insert(unit::INPUT_TOKENS.into(), Rate::per(200_000_000, 6));
        lines.insert(unit::OUTPUT_TOKENS.into(), Rate::per(1_000_000_000, 6));
        // Long context costs double on input.
        lines.insert("input_tokens@ctx_gt_200k".into(), Rate::per(400_000_000, 6));
        RateCard {
            denom: Denom::NanoUsd,
            lines,
            min_charge: 0,
        }
    }

    #[test]
    fn a_meter_is_charged_line_by_line() {
        let card = llm_card();
        let u = BillableUnits::tokens(1_000, 500);
        // 1000 * 0.2e9 / 1e6 = 200_000 nano; 500 * 1e9 / 1e6 = 500_000 nano.
        assert_eq!(card.charge_in_denom(&u, registry).unwrap(), 700_000);
        let mut long = BillableUnits::new();
        long.set("input_tokens@ctx_gt_200k", 1_000).unwrap();
        assert_eq!(card.charge_in_denom(&long, registry).unwrap(), 400_000);
    }

    #[test]
    fn a_spot_tier_line_prices_tokens_tokens_cannot_alone() {
        let mut card = llm_card();
        // $0.10 per million output tokens at the spot tier -- a discount off
        // the plain $1.00/M line `llm_card()` already carries.
        card.lines
            .insert("output_tokens@spot".into(), Rate::per(100_000_000, 6));
        let plain = BillableUnits::tokens(0, 1_000);
        let spot = BillableUnits::tokens_in_tier(0, 1_000, Some("spot"));
        let plain_cost = card.charge_in_denom(&plain, registry).unwrap();
        let spot_cost = card.charge_in_denom(&spot, registry).unwrap();
        assert_eq!(plain_cost, 1_000_000); // 1000 * 1.0e9 / 1e6
        assert_eq!(spot_cost, 100_000); // 1000 * 0.1e9 / 1e6
        assert!(spot_cost < plain_cost);
        // unit_total sums across tiers, so metering still sees one call's
        // worth of output tokens however it was priced.
        assert_eq!(spot.unit_total(unit::OUTPUT_TOKENS), 1_000);
    }

    #[test]
    fn work_the_card_leaves_out_costs_nothing_but_nothing_priced_is_refused() {
        let card = llm_card();
        // Reasoning tokens are not on this card: the call costs its tokens.
        let u = BillableUnits::tokens(1_000, 0).with_reasoning_tokens(5);
        assert_eq!(card.charge_in_denom(&u, registry).unwrap(), 200_000);
        // A meter with only unpriced billable work is never served free.
        let mut tier = BillableUnits::new();
        tier.set("output_tokens@priority", 1).unwrap();
        assert_eq!(
            card.charge_in_denom(&tier, registry),
            Err(PricingError::Unpriced("output_tokens@priority".into()))
        );
        // Unless the card's minimum charge applies to every call.
        let floor = RateCard {
            min_charge: 7,
            ..card.clone()
        };
        assert!(floor.charge_in_denom(&tier, registry).is_err());
    }

    #[test]
    fn a_recorded_only_unit_is_never_charged_and_an_unknown_one_refuses() {
        let card = llm_card();
        let mut u = BillableUnits::tokens(1_000, 0);
        u.set(unit::TTFT_MS, 250).unwrap();
        assert_eq!(card.charge_in_denom(&u, registry).unwrap(), 200_000);
        let mut x = BillableUnits::new();
        x.set("teleport_ms", 1).unwrap();
        assert_eq!(
            card.charge_in_denom(&x, registry),
            Err(PricingError::UnknownUnit("teleport_ms".into()))
        );
    }

    #[test]
    fn costs_round_up_and_the_minimum_holds() {
        let mut card = llm_card();
        let u = BillableUnits::tokens(1, 0);
        // 1 * 0.2e9 / 1e6 = 200 exactly.
        assert_eq!(card.charge_in_denom(&u, registry).unwrap(), 200);
        card.lines
            .insert(unit::INPUT_TOKENS.into(), Rate::per(1, 6));
        assert_eq!(card.charge_in_denom(&u, registry).unwrap(), 1);
        card.min_charge = 50;
        assert_eq!(card.charge_in_denom(&u, registry).unwrap(), 50);
        assert_eq!(
            card.charge_in_denom(&BillableUnits::new(), registry)
                .unwrap(),
            50
        );
    }

    #[test]
    fn usd_converts_to_wei_at_the_rate_rounding_up() {
        let card = llm_card();
        let u = BillableUnits::tokens(1_000_000, 0); // $0.20
        // At $0.50 per TNZO, $0.20 is 0.4 TNZO.
        let wei = card.charge_wei(&u, registry, 500_000_000).unwrap();
        assert_eq!(wei, 400_000_000_000_000_000);
        assert_eq!(card.charge_wei(&u, registry, 0), Err(PricingError::NoRate));
        let wei_card = RateCard {
            denom: Denom::Wei,
            ..card
        };
        assert_eq!(wei_card.charge_wei(&u, registry, 0).unwrap(), 200_000_000);
    }

    #[test]
    fn overflow_is_an_error() {
        let mut card = llm_card();
        card.lines
            .insert(unit::PIXEL_STEPS.into(), Rate::per(u128::MAX, 0));
        let u = BillableUnits::new().with_pixel_steps(2);
        assert_eq!(
            card.charge_in_denom(&u, registry),
            Err(PricingError::Overflow)
        );
    }

    #[test]
    fn validation_follows_the_registry() {
        let mut card = llm_card();
        assert!(card.validate(16, registry).is_ok());
        assert_eq!(
            card.validate(2, registry),
            Err(PricingError::TooManyLines(3, 2))
        );
        card.lines.insert(unit::TTFT_MS.into(), Rate::per(1, 0));
        assert_eq!(
            card.validate(16, registry),
            Err(PricingError::NotBillable(unit::TTFT_MS.into()))
        );
        card.lines.remove(unit::TTFT_MS);
        card.lines.insert("warp_drive".into(), Rate::per(1, 0));
        assert!(matches!(
            card.validate(16, registry),
            Err(PricingError::UnknownUnit(_))
        ));
        card.lines.remove("warp_drive");
        card.lines
            .insert(unit::IMAGES.into(), Rate::per(1, MAX_PER_EXP + 1));
        assert!(matches!(
            card.validate(16, registry),
            Err(PricingError::PerExp(_))
        ));
    }

    #[test]
    fn a_meter_round_trips_through_json_and_bincode() {
        let mut u = BillableUnits::tokens(3, 4).with_pixel_steps(u128::MAX - 1);
        u.set("control_steps@hz50", 9).unwrap();
        let j = serde_json::to_string(&u).unwrap();
        assert!(j.contains("\"control_steps@hz50\":9"));
        assert_eq!(serde_json::from_str::<BillableUnits>(&j).unwrap(), u);
        let b = bincode::serialize(&u).unwrap();
        assert_eq!(bincode::deserialize::<BillableUnits>(&b).unwrap(), u);
        assert!(serde_json::from_str::<BillableUnits>(r#"{"output_tokens":0}"#).is_err());
        assert!(serde_json::from_str::<BillableUnits>(r#"{"Output":1}"#).is_err());
        assert_eq!(
            serde_json::from_str::<BillableUnits>(r#"{"output_tokens":"7"}"#)
                .unwrap()
                .output_tokens(),
            7
        );
    }

    #[test]
    fn meter_bytes_are_canonical() {
        let mut a = BillableUnits::new();
        a.set("b", 2).unwrap();
        a.set("a", 1).unwrap();
        let mut b = BillableUnits::new();
        b.set("a", 1).unwrap();
        b.set("b", 2).unwrap();
        b.set("c", 5).unwrap();
        b.set("c", 0).unwrap();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(a, b);
        let mut c = a.clone();
        assert!(c.add("a", u128::MAX).is_err());
        assert!(c.set("Bad", 1).is_err());
    }
}
