//! Pricing a call against the rate card its provider posted.
//!
//! The pricing rule itself is [`RateCard::charge_wei`] in `tenzro-types`, so
//! the router here, the node that settles, the chain that decides a dispute
//! and every SDK agree on what a meter costs. What this module adds is what
//! the rule needs from outside the card: which units are registered and
//! billable, and the TNZO/USD rate a USD card converts at. A
//! [`PriceContext`] holds both; the node keeps it current from chain state.

use std::collections::BTreeMap;

use tenzro_types::meter::{UnitDef, genesis_units};
use tenzro_types::model::BillableUnits;
use tenzro_types::price_card::{PricingError, RateCard};

/// What a charge needs beyond the card: the unit registry and the rate.
#[derive(Debug, Clone)]
pub struct PriceContext {
    /// Registered units by id, billable or not.
    units: BTreeMap<String, bool>,
    /// Billionths of a dollar per TNZO; 0 while unknown, which refuses a
    /// USD card rather than pricing it at a guess.
    tnzo_usd_nano: u128,
}

impl Default for PriceContext {
    fn default() -> Self {
        Self::genesis(0)
    }
}

impl PriceContext {
    /// The units the network starts with, at `tnzo_usd_nano`.
    pub fn genesis(tnzo_usd_nano: u128) -> Self {
        Self {
            units: genesis_units()
                .into_iter()
                .map(|u| (u.id, u.billable))
                .collect(),
            tnzo_usd_nano,
        }
    }

    /// Add units registered after genesis.
    pub fn with_units(mut self, defs: impl IntoIterator<Item = UnitDef>) -> Self {
        for d in defs {
            self.units.insert(d.id, d.billable);
        }
        self
    }

    /// Set the TNZO/USD rate.
    pub fn set_rate(&mut self, tnzo_usd_nano: u128) {
        self.tnzo_usd_nano = tnzo_usd_nano;
    }

    /// The TNZO/USD rate in use.
    pub fn rate(&self) -> u128 {
        self.tnzo_usd_nano
    }

    /// Whether `unit` is billable; `None` when it is not registered.
    pub fn billable(&self, unit: &str) -> Option<bool> {
        self.units.get(unit).copied()
    }

    /// What `units` cost on `card`, in TNZO base units.
    pub fn charge_wei(&self, card: &RateCard, units: &BillableUnits) -> Result<u128, PricingError> {
        card.charge_wei(units, |u| self.billable(u), self.tnzo_usd_nano)
    }

    /// The least a call costs on `card`, in TNZO base units: its minimum
    /// charge. Saturates at `u128::MAX` when it cannot be converted, so an
    /// unconvertible card sorts last and passes no budget.
    pub fn floor_wei(&self, card: &RateCard) -> u128 {
        card.to_wei(card.min_charge, self.tnzo_usd_nano)
            .unwrap_or(u128::MAX)
    }

    /// What a call of `input_tokens` in and `output_tokens` out would cost on
    /// `card`, for ranking and budgets before a call runs. A card that prices
    /// no tokens yields `u128::MAX`, so it never wins a token budget.
    pub fn estimate_tokens_wei(
        &self,
        card: &RateCard,
        input_tokens: u32,
        output_tokens: u32,
    ) -> u128 {
        self.charge_wei(card, &BillableUnits::tokens(input_tokens, output_tokens))
            .unwrap_or(u128::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::meter::{Witness, unit};
    use tenzro_types::price_card::{Denom, Rate};

    fn wei_card(lines: &[(&str, u128, u8)], min: u128) -> RateCard {
        RateCard {
            denom: Denom::Wei,
            lines: lines
                .iter()
                .map(|(k, p, e)| (k.to_string(), Rate::per(*p, *e)))
                .collect(),
            min_charge: min,
        }
    }

    #[test]
    fn each_model_type_bills_on_its_own_units() {
        let ctx = PriceContext::genesis(0);
        let card = wei_card(
            &[
                (unit::INPUT_TOKENS, 10, 0),
                (unit::OUTPUT_TOKENS, 20, 0),
                (unit::RERANK_PAIRS, 7, 0),
                (unit::DECISION_QUESTIONS, 11, 0),
                (unit::FORECAST_POINTS, 3, 0),
                (unit::PIXEL_STEPS, 7, 0),
                (unit::CHARACTERS, 2, 0),
                (unit::AUDIO_OUT_MS, 400, 3),
                (unit::FRAMES, 50, 0),
            ],
            0,
        );
        let cost = |u: BillableUnits| ctx.charge_wei(&card, &u).unwrap();
        // A language model: tokens in and out.
        assert_eq!(cost(BillableUnits::tokens(100, 50)), 100 * 10 + 50 * 20);
        // An embedding: input tokens only.
        assert_eq!(cost(BillableUnits::tokens(120, 0)), 120 * 10);
        // A reranker per pair, a forecaster per point.
        assert_eq!(cost(BillableUnits::new().with_rerank_pairs(5)), 35);
        // A decision model per question answered.
        assert_eq!(cost(BillableUnits::new().with_decision_questions(4)), 44);
        assert_eq!(cost(BillableUnits::new().with_forecast_points(48)), 144);
        // An image: denoising work only; frames are a factor of it.
        assert_eq!(cost(BillableUnits::new().with_pixel_steps(1_000)), 7_000);
        // Speech: characters plus audio produced, 400 per second, partial
        // seconds rounded up on the cost.
        assert_eq!(
            cost(
                BillableUnits::new()
                    .with_characters(11)
                    .with_audio_out_ms(2_400)
            ),
            22 + 960
        );
        // A video encoder reads frames.
        assert_eq!(cost(BillableUnits::new().with_frames(8)), 400);
    }

    #[test]
    fn a_registered_unit_prices_without_code_changes() {
        let mut card = wei_card(&[("action_chunks@h16", 1_000, 0)], 0);
        card.lines.insert("energy_mwh".into(), Rate::per(5, 0));
        let mut chunks = BillableUnits::new();
        chunks.set("action_chunks@h16", 30).unwrap();
        let genesis = PriceContext::genesis(0);
        assert_eq!(genesis.charge_wei(&card, &chunks).unwrap(), 30_000);
        let mut energy = BillableUnits::new();
        energy.set("energy_mwh", 4).unwrap();
        assert!(
            genesis.charge_wei(&card, &energy).is_err(),
            "not registered yet"
        );
        let registered = genesis.with_units([UnitDef {
            id: "energy_mwh".into(),
            scale: "mwh".into(),
            witness: Witness::Device,
            billable: true,
            max_per_call: 0,
            doc_hash: "11".repeat(32),
        }]);
        assert_eq!(registered.charge_wei(&card, &energy).unwrap(), 20);
    }

    #[test]
    fn a_usd_card_needs_a_rate_and_estimates_rank_unpriced_cards_last() {
        let card = RateCard {
            denom: Denom::NanoUsd,
            lines: [(unit::OUTPUT_TOKENS.to_string(), Rate::per(1_000_000_000, 6))]
                .into_iter()
                .collect(),
            min_charge: 1_000,
        };
        let unknown = PriceContext::genesis(0);
        assert_eq!(unknown.floor_wei(&card), u128::MAX);
        let ctx = PriceContext::genesis(1_000_000_000); // $1 per TNZO
        assert_eq!(ctx.floor_wei(&card), 1_000 * 1_000_000_000);
        // 1M output tokens at $1 per million is one TNZO.
        assert_eq!(
            ctx.estimate_tokens_wei(&card, 0, 1_000_000),
            1_000_000_000_000_000_000
        );
        // Input tokens are not on this card, so only the output counts.
        assert_eq!(ctx.estimate_tokens_wei(&card, 10, 10), 10_000_000_000_000);
        // A card that prices no tokens at all never wins a token budget.
        let images_only = RateCard {
            lines: [(unit::IMAGES.to_string(), Rate::per(1, 0))]
                .into_iter()
                .collect(),
            ..card
        };
        assert_eq!(ctx.estimate_tokens_wei(&images_only, 10, 10), u128::MAX);
    }
}
