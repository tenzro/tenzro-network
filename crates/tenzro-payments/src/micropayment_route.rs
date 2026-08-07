//! Where a metered charge should go: accumulate, settle here, or settle there.
//!
//! The token meter ([`tenzro_types::meter_units_wei`]) answers *how much* a
//! call cost across any modality. This module answers the question immediately
//! after it, which nothing previously owned: **what should happen to that
//! amount now.**
//!
//! There are only three honest answers, and picking between them is the whole
//! job:
//!
//! - **Accumulate.** The charge is worth less than moving it. It belongs in a
//!   micropayment channel until it is worth settling. Settling anyway would
//!   spend more on the transfer than the transfer moves — the network would be
//!   paying to be paid.
//! - **Settle on the Tenzro Ledger.** The home chain, and the default. Tenzro
//!   is its own settlement layer.
//! - **Settle on a secondary rail.** Only when the payee wants an asset the
//!   home chain does not carry, and only on a rail whose fee the payment can
//!   absorb.
//!
//! # Why this is a routing problem and not a preference
//!
//! An agentic economy metered per token generates charges spanning six orders
//! of magnitude: a tenth of a cent for one token, tens of dollars for a video
//! render, thousands for a month's rental. No single rail is correct across
//! that range. Ethereum L1 cannot carry the small end — the fee exceeds the
//! payment by orders of magnitude — and a channel is pointless at the large
//! end. Choosing per payment is the only thing that works, and choosing wrong
//! is silent: the payment still succeeds, it just destroys more value than it
//! moves.
//!
//! Supporting x402 on a rail is *not* the same as that rail being able to
//! carry a micropayment, which is the trap this module exists to avoid. Base
//! speaks x402 and still cannot carry a one-cent charge without ~10% overhead.

use tenzro_types::settlement_network::{
    DEFAULT_FEE_RATIO, SettlementNetwork, cheapest_rail_for, network_by_caip2,
};

/// What to do with a metered charge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MicropaymentRoute {
    /// Hold it in a micropayment channel: it is below the network's
    /// micro-settlement floor. Carries the running total so a caller can see
    /// how close the channel is to being worth settling.
    Accumulate {
        /// The charge that triggered this decision, in TNZO wei.
        amount_wei: u128,
        /// The floor it fell under, in TNZO wei.
        floor_wei: u128,
    },
    /// Settle on the Tenzro Ledger.
    Primary {
        /// Amount to settle, in TNZO wei.
        amount_wei: u128,
    },
    /// Settle on a secondary rail because the payee wants an asset the home
    /// chain does not carry.
    Secondary {
        /// Amount to settle, in TNZO wei.
        amount_wei: u128,
        /// CAIP-2 identifier of the chosen rail.
        caip2: &'static str,
        /// Asset the payee asked for.
        asset: String,
    },
    /// The payee wants an asset no rail can carry at this size. The caller
    /// must accumulate and retry later, or the payee must accept another
    /// asset.
    ///
    /// This is a distinct outcome from `Accumulate`: the charge clears the
    /// floor, so it *would* settle on the home chain — it is the payee's asset
    /// preference that cannot be honoured here. Collapsing the two would hide
    /// which constraint actually bound.
    NoViableRail {
        /// Amount that could not be routed, in TNZO wei.
        amount_wei: u128,
        /// Asset the payee asked for.
        asset: String,
    },
}

impl MicropaymentRoute {
    /// Whether this route moves money now.
    pub fn settles_now(&self) -> bool {
        matches!(self, Self::Primary { .. } | Self::Secondary { .. })
    }

    /// Stable identifier for logs, receipts and RPC output.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Accumulate { .. } => "accumulate",
            Self::Primary { .. } => "primary",
            Self::Secondary { .. } => "secondary",
            Self::NoViableRail { .. } => "no_viable_rail",
        }
    }
}

/// Decide what happens to a metered charge.
///
/// `amount_wei` is the meter's output in TNZO wei. `floor_wei` is the
/// governance-set `EconomicPolicy::micro_settlement_floor`. `payee_asset` is
/// what the payee has declared they want to hold — `None` or `"TNZO"` means
/// the home chain.
///
/// `tnzo_micro_usd` is the TNZO price in micro-USD used to compare a TNZO
/// amount against a rail's fee floor. It is supplied by the caller rather than
/// read from an oracle here so this function stays pure and testable; a caller
/// with no price feed should pass `None` and get home-chain settlement, which
/// is the safe answer rather than a guess.
pub fn route(
    amount_wei: u128,
    floor_wei: u128,
    payee_asset: Option<&str>,
    tnzo_micro_usd: Option<u64>,
) -> MicropaymentRoute {
    // The floor binds first. A charge too small to move is too small to move
    // regardless of what the payee would like to hold.
    if amount_wei > 0 && amount_wei < floor_wei {
        return MicropaymentRoute::Accumulate {
            amount_wei,
            floor_wei,
        };
    }

    let asset = match payee_asset {
        None => return MicropaymentRoute::Primary { amount_wei },
        Some(a) if a.eq_ignore_ascii_case("TNZO") => {
            return MicropaymentRoute::Primary { amount_wei };
        }
        Some(a) => a,
    };

    // Without a price we cannot compare a TNZO amount to a rail's fee, and
    // guessing would route real money on an invented number. The home chain is
    // always able to settle, so it is the correct fallback.
    let Some(price) = tnzo_micro_usd else {
        return MicropaymentRoute::Primary { amount_wei };
    };

    let amount_micro_usd = tnzo_wei_to_micro_usd(amount_wei, price);
    match cheapest_rail_for(asset, amount_micro_usd, DEFAULT_FEE_RATIO) {
        Some(rail) => MicropaymentRoute::Secondary {
            amount_wei,
            caip2: rail.caip2,
            asset: asset.to_string(),
        },
        None => MicropaymentRoute::NoViableRail {
            amount_wei,
            asset: asset.to_string(),
        },
    }
}

/// Convert TNZO wei to micro-USD at `tnzo_micro_usd` per whole TNZO.
///
/// Uses quotient/remainder decomposition so a large balance cannot overflow
/// the intermediate multiply — the same discipline the revenue split uses.
pub fn tnzo_wei_to_micro_usd(amount_wei: u128, tnzo_micro_usd: u64) -> u64 {
    const WEI_PER_TNZO: u128 = 1_000_000_000_000_000_000;
    let price = tnzo_micro_usd as u128;
    let whole = (amount_wei / WEI_PER_TNZO).saturating_mul(price);
    let frac = (amount_wei % WEI_PER_TNZO).saturating_mul(price) / WEI_PER_TNZO;
    whole.saturating_add(frac).min(u64::MAX as u128) as u64
}

/// The rail a given CAIP-2 identifier names, if Tenzro settles there.
pub fn rail(caip2: &str) -> Option<&'static SettlementNetwork> {
    network_by_caip2(caip2)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One TNZO at $1.00.
    const ONE_TNZO: u128 = 1_000_000_000_000_000_000;
    const PRICE_ONE_DOLLAR: u64 = 1_000_000;
    /// The shipped `EconomicPolicy` default: one ten-thousandth of a TNZO.
    const FLOOR: u128 = 10_000_000_000_000;

    #[test]
    fn a_charge_under_the_floor_accumulates() {
        let r = route(FLOOR - 1, FLOOR, None, Some(PRICE_ONE_DOLLAR));
        assert_eq!(r.kind(), "accumulate");
        assert!(!r.settles_now());
    }

    #[test]
    fn the_floor_binds_before_the_payee_preference() {
        // A dust charge does not become movable because the payee would like
        // it in USDC. Ordering matters: checking the asset first would route a
        // sub-floor charge onto a rail and pay a fee to move nothing.
        let r = route(FLOOR - 1, FLOOR, Some("USDC"), Some(PRICE_ONE_DOLLAR));
        assert_eq!(r.kind(), "accumulate");
    }

    #[test]
    fn a_zero_charge_is_not_an_accumulation() {
        // Free calls are metered too. Zero is settled-and-done, not held open
        // in a channel forever.
        let r = route(0, FLOOR, None, None);
        assert_eq!(r.kind(), "primary");
    }

    #[test]
    fn no_declared_asset_settles_on_the_home_chain() {
        let r = route(ONE_TNZO, FLOOR, None, Some(PRICE_ONE_DOLLAR));
        assert_eq!(
            r,
            MicropaymentRoute::Primary {
                amount_wei: ONE_TNZO
            }
        );
    }

    #[test]
    fn tnzo_is_the_home_chain_however_it_is_spelled() {
        for spelling in ["TNZO", "tnzo", "Tnzo"] {
            assert_eq!(
                route(ONE_TNZO, FLOOR, Some(spelling), Some(PRICE_ONE_DOLLAR)).kind(),
                "primary"
            );
        }
    }

    #[test]
    fn a_stablecoin_payee_routes_to_the_cheapest_rail_carrying_it() {
        // $1.00 of USDC: Stellar is cheapest among the rails carrying USDC.
        let r = route(ONE_TNZO, FLOOR, Some("USDC"), Some(PRICE_ONE_DOLLAR));
        match r {
            MicropaymentRoute::Secondary {
                caip2, ref asset, ..
            } => {
                assert_eq!(caip2, "stellar:pubnet");
                assert_eq!(asset, "USDC");
            }
            other => panic!("expected secondary, got {other:?}"),
        }
    }

    #[test]
    fn an_rlusd_payee_routes_to_xrpl() {
        let r = route(ONE_TNZO, FLOOR, Some("RLUSD"), Some(PRICE_ONE_DOLLAR));
        match r {
            MicropaymentRoute::Secondary { caip2, .. } => assert_eq!(caip2, "xrpl:0"),
            other => panic!("expected xrpl, got {other:?}"),
        }
    }

    #[test]
    fn an_unroutable_asset_is_reported_distinctly_from_accumulation() {
        // Clears the floor, so it is not an accumulation — the payee's asset
        // is simply not carried anywhere. Reporting these as the same outcome
        // would tell an operator to open a channel when the real fix is to
        // change the declared asset.
        let r = route(ONE_TNZO, FLOOR, Some("DOGE"), Some(PRICE_ONE_DOLLAR));
        assert_eq!(r.kind(), "no_viable_rail");
        assert!(!r.settles_now());
    }

    #[test]
    fn a_missing_price_falls_back_to_the_home_chain_rather_than_guessing() {
        // Routing real money on an invented exchange rate is worse than not
        // routing at all. The home chain can always settle.
        let r = route(ONE_TNZO, FLOOR, Some("USDC"), None);
        assert_eq!(r.kind(), "primary");
    }

    #[test]
    fn a_tiny_stablecoin_charge_that_clears_the_floor_may_still_have_no_rail() {
        // The floor is a TNZO-denominated policy dial; rail fees are USD.
        // A charge can clear the floor and still be too small for any rail
        // carrying the payee's asset — the two limits are independent, which
        // is exactly why both are checked.
        let just_over = FLOOR + 1; // ~0.00001 TNZO ≈ 10 micro-USD at $1
        let r = route(just_over, FLOOR, Some("USDC"), Some(PRICE_ONE_DOLLAR));
        assert_eq!(r.kind(), "no_viable_rail");
    }

    #[test]
    fn wei_to_micro_usd_is_exact_on_whole_tokens() {
        assert_eq!(tnzo_wei_to_micro_usd(ONE_TNZO, PRICE_ONE_DOLLAR), 1_000_000);
        assert_eq!(
            tnzo_wei_to_micro_usd(ONE_TNZO * 5, PRICE_ONE_DOLLAR),
            5_000_000
        );
    }

    #[test]
    fn wei_to_micro_usd_keeps_fractional_precision() {
        // Half a TNZO at $1 is 500_000 micro-USD. Truncating the fraction
        // would under-price every sub-token charge, which is most of them.
        assert_eq!(
            tnzo_wei_to_micro_usd(ONE_TNZO / 2, PRICE_ONE_DOLLAR),
            500_000
        );
    }

    #[test]
    fn wei_to_micro_usd_survives_an_absurd_balance() {
        // Must not overflow the intermediate multiply.
        let huge = u128::MAX / 2;
        let _ = tnzo_wei_to_micro_usd(huge, PRICE_ONE_DOLLAR);
    }

    #[test]
    fn rail_lookup_resolves_known_networks_and_rejects_unknown() {
        assert!(rail("stellar:pubnet").is_some());
        assert!(rail("eip155:8453").is_some());
        assert!(rail("bitcoin:mainnet").is_none());
    }
}
