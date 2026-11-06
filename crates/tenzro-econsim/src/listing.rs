//! The listing gate of a closed-phase run: the first day each item is met,
//! and the day all of them have held together for [`HOLD_DAYS`] days.
//!
//! The items, each read from a day's record:
//! - unrelated demand: payments settled to providers, less the related-party
//!   anchor share, at least [`UNRELATED_USD_DAY`] a day;
//! - fee revenue covers the running costs at the running-cost revenue share
//!   ([`GATE_SHARE_BPS`]): annualised fee revenue at least `10_000 /
//!   GATE_SHARE_BPS` times the annual running costs; the same test at
//!   [`GENESIS_SHARE_BPS`] is reported beside it and is not part of the gate;
//! - a majority of providers profitable;
//! - validators' fee income, their share of the burn without issuance,
//!   covers their running costs over the trailing 30 days.

use serde::Serialize;

use crate::economy::{Day, YEAR_DAYS};

/// Unrelated demand the gate asks for, USD a day.
pub const UNRELATED_USD_DAY: f64 = 60_000.0;
/// Running-cost revenue share the gate tests revenue at, bps: revenue at
/// least about 1.5 times the running costs.
pub const GATE_SHARE_BPS: u64 = 6_500;
/// The genesis running-cost revenue share, bps: revenue at least about 3.3
/// times the running costs. Reported, not gated.
pub const GENESIS_SHARE_BPS: u64 = 3_000;
/// Consecutive days every item must hold.
pub const HOLD_DAYS: usize = 90;

/// When each item of the listing gate was first met, as calendar days of
/// the run; `None`: never within the run.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ListingGate {
    /// Unrelated demand at least [`UNRELATED_USD_DAY`].
    pub unrelated_demand_day: Option<f64>,
    /// Revenue covers the running costs at [`GATE_SHARE_BPS`].
    pub revenue_cover_day: Option<f64>,
    /// Revenue covers the running costs at [`GENESIS_SHARE_BPS`].
    pub revenue_cover_genesis_share_day: Option<f64>,
    /// More than half the active providers profitable.
    pub providers_majority_day: Option<f64>,
    /// Validators' fee income covers their running costs.
    pub validators_cover_day: Option<f64>,
    /// Day all four items had held for [`HOLD_DAYS`] consecutive days.
    pub gate_held_day: Option<f64>,
    /// Day the first such run of days began.
    pub gate_streak_start_day: Option<f64>,
}

/// Whether annualised revenue covers the day's running costs at `share_bps`.
fn revenue_covers(d: &Day, trail_days: usize, share_bps: u64) -> bool {
    let costs_year = d.running_costs_asked_usd_30d / trail_days.clamp(1, 30) as f64 * YEAR_DAYS;
    d.revenue_usd_year * share_bps as f64 / 10_000.0 >= costs_year
}

/// The items met on day `i` of `days`: (unrelated demand, revenue at the
/// gate share, revenue at the genesis share, providers, validators).
pub fn items(days: &[Day], i: usize) -> [bool; 5] {
    let d = &days[i];
    [
        d.unrelated_demand_usd_day >= UNRELATED_USD_DAY,
        revenue_covers(d, i + 1, GATE_SHARE_BPS),
        revenue_covers(d, i + 1, GENESIS_SHARE_BPS),
        d.providers > 0 && d.providers_profitable > 0.5,
        d.validator_cost_usd_30d > 0.0
            && d.validator_fee_income_usd_30d >= d.validator_cost_usd_30d,
    ]
}

impl ListingGate {
    /// The gate over a run's daily records.
    pub fn of(days: &[Day]) -> Self {
        let mut g = ListingGate::default();
        let mut streak = 0usize;
        for (i, d) in days.iter().enumerate() {
            let day = d.snap.day;
            let met = items(days, i);
            let firsts = [
                &mut g.unrelated_demand_day,
                &mut g.revenue_cover_day,
                &mut g.revenue_cover_genesis_share_day,
                &mut g.providers_majority_day,
                &mut g.validators_cover_day,
            ];
            for (first, ok) in firsts.into_iter().zip(met) {
                if ok && first.is_none() {
                    *first = Some(day);
                }
            }
            let all = met[0] && met[1] && met[3] && met[4];
            streak = if all { streak + 1 } else { 0 };
            if streak == HOLD_DAYS && g.gate_held_day.is_none() {
                g.gate_held_day = Some(day);
                g.gate_streak_start_day = Some(days[i + 1 - HOLD_DAYS].snap.day);
            }
        }
        g
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(n: usize, demand: f64, revenue_x: f64, providers: f64, validators_x: f64) -> Day {
        let mut d = Day::default();
        d.snap.day = n as f64 + 1.0;
        d.unrelated_demand_usd_day = demand;
        d.running_costs_asked_usd_30d = (n + 1).min(30) as f64 * 1_000.0;
        d.revenue_usd_year = revenue_x * 1_000.0 * YEAR_DAYS;
        d.providers = 10;
        d.providers_profitable = providers;
        d.validator_cost_usd_30d = 100.0;
        d.validator_fee_income_usd_30d = 100.0 * validators_x;
        d
    }

    #[test]
    fn each_item_is_dated_by_its_own_first_day() {
        let mut days: Vec<Day> = (0..40).map(|n| day(n, 0.0, 0.0, 0.0, 0.0)).collect();
        days[5].unrelated_demand_usd_day = 60_000.0;
        days[10].revenue_usd_year = 1.6 * 1_000.0 * YEAR_DAYS;
        days[20].revenue_usd_year = 3.4 * 1_000.0 * YEAR_DAYS;
        days[30].providers_profitable = 0.6;
        days[35].validator_fee_income_usd_30d = 100.0;
        let g = ListingGate::of(&days);
        assert_eq!(g.unrelated_demand_day, Some(6.0));
        assert_eq!(g.revenue_cover_day, Some(11.0));
        assert_eq!(g.revenue_cover_genesis_share_day, Some(21.0));
        assert_eq!(g.providers_majority_day, Some(31.0));
        assert_eq!(g.validators_cover_day, Some(36.0));
        assert_eq!(g.gate_held_day, None);
    }

    #[test]
    fn the_revenue_item_needs_about_one_and_a_half_times_the_costs() {
        let below: Vec<Day> = (0..30).map(|n| day(n, 0.0, 1.5, 0.0, 0.0)).collect();
        let above: Vec<Day> = (0..30).map(|n| day(n, 0.0, 1.54, 0.0, 0.0)).collect();
        assert!(!items(&below, 29)[1]);
        assert!(items(&above, 29)[1]);
        assert!(!items(&above, 29)[2]);
        let genesis: Vec<Day> = (0..30).map(|n| day(n, 0.0, 3.34, 0.0, 0.0)).collect();
        assert!(items(&genesis, 29)[2]);
    }

    #[test]
    fn the_gate_holds_only_after_ninety_unbroken_days() {
        let mut days: Vec<Day> = (0..300).map(|n| day(n, 70_000.0, 1.6, 0.6, 1.1)).collect();
        // A break on day 50 restarts the count.
        days[49].providers_profitable = 0.4;
        let g = ListingGate::of(&days);
        assert_eq!(g.providers_majority_day, Some(1.0));
        assert_eq!(g.gate_streak_start_day, Some(51.0));
        assert_eq!(g.gate_held_day, Some(140.0));
        // The genesis-share item is not part of the gate.
        assert_eq!(g.revenue_cover_genesis_share_day, None);
    }
}
