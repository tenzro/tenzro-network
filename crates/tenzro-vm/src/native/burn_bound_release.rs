//! Pool release bound to the burn.
//!
//! A gated rule ([`crate::feature_gate`]): from the epoch
//! `feature.burn_bound_release.activation_epoch` names, what a closed epoch
//! releases from the rewards pool is at most a governed ratio of the TNZO the
//! epoch burned (its burn and the burn-equivalent of fees collected in other
//! assets, [`super::economy::EpochActivity`]). Burn and release are both
//! counted in TNZO at the epoch's own rate, so the bound holds in USD at any
//! price. The ratio is at most one: a payer buying its own service burns more
//! than the pool gives back.
//!
//! The ceiling of an epoch is built in this order:
//!
//! 1. the budget: the epoch's burn, or with `smoothing_keep_bps` above zero
//!    that share of the prior budget and the rest of the epoch's burn;
//! 2. the ratio in force for the share of the pool left: `ratio_bps`, the
//!    lower `step_ratio_bps` under `step_pool_bps` of the pool, nothing under
//!    `floor_pool_bps` (validators' running cost is still paid from fees
//!    kept, [`super::validator_cover`]);
//! 3. a matched start on top, for the first `boot_epochs` after the rule goes
//!    live: `boot_ratio_bps` falling in a straight line to the ratio, counted
//!    on the epoch's own burn and spending at most `boot_budget_bps` of the
//!    pool in all;
//! 4. the yearly room: releases of one schedule year stay within
//!    `yearly_pool_limit_bps` of the pool left when the year began.
//!
//! The pool left is the genesis pool less what earlier closes took and did
//! not give back: rights withheld, and coupons claimed or still claimable.
//! What lapsed (unmatched, cut by this rule, or expired unclaimed) is still
//! in it.
//!
//! Each address is then held to `operator_share_cap_bps` of the bounded
//! release. The cap is per address, so an earner who splits its work across
//! addresses is not held by it as one. What the bounds cut lapses and stays in the pool. A reward is
//! still earned only by verified paid work; the rule adds a ceiling, never a
//! payment.
//!
//! Record under `SYSTEM_ADDRESS`: `burn_bound_release` ([`ReleaseBook`]),
//! written from the first live epoch close.

use serde::{Deserialize, Serialize};
use tenzro_token::rewards::{EpochRewardSummary, MintingSchedule, RewardCoupon, pro_rata};

use super::funding::{read_json, write_json};
use super::*;

/// Gate: first epoch whose closes bind pool release to the burn.
pub const KEY: &str = "feature.burn_bound_release.activation_epoch";
/// Governed key: most an epoch releases, bps of its burn budget.
pub const RATIO_PARAM: &str = "feature.burn_bound_release.ratio_bps";
/// Governed key: share of the prior budget kept each epoch, bps; zero makes
/// the budget each epoch's own burn.
pub const SMOOTHING_KEEP_PARAM: &str = "feature.burn_bound_release.smoothing_keep_bps";
/// Governed key: most one schedule year releases, bps of the pool left at
/// its start.
pub const YEARLY_LIMIT_PARAM: &str = "feature.burn_bound_release.yearly_pool_limit_bps";
/// Governed key: share of the genesis pool, bps, under which the step ratio
/// applies.
pub const STEP_POOL_PARAM: &str = "feature.burn_bound_release.step_pool_bps";
/// Governed key: the ratio under the step, bps; never above the ratio.
pub const STEP_RATIO_PARAM: &str = "feature.burn_bound_release.step_ratio_bps";
/// Governed key: share of the genesis pool, bps, under which the pool
/// releases nothing.
pub const FLOOR_POOL_PARAM: &str = "feature.burn_bound_release.floor_pool_bps";
/// Governed key: the matched ratio at the rule's first epoch, bps; at or
/// under the ratio there is no matched start.
pub const BOOT_RATIO_PARAM: &str = "feature.burn_bound_release.boot_ratio_bps";
/// Governed key: epochs over which the matched ratio falls to the ratio.
pub const BOOT_EPOCHS_PARAM: &str = "feature.burn_bound_release.boot_epochs";
/// Governed key: most the matched start releases in all, bps of the genesis
/// pool.
pub const BOOT_BUDGET_PARAM: &str = "feature.burn_bound_release.boot_budget_bps";
/// Governed key: most one address takes of an epoch's bounded release, bps.
pub const SHARE_CAP_PARAM: &str = "feature.burn_bound_release.operator_share_cap_bps";

const BOOK_KEY: &str = "burn_bound_release";

/// What the rule carries from one epoch close to the next.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseBook {
    /// The first epoch closed under the rule.
    pub first_epoch: u64,
    /// The burn budget after the last close, TNZO base units.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub budget: u128,
    /// Released by the matched start so far.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub boot_spent: u128,
    /// The schedule year the yearly room is counted in.
    pub year: u64,
    /// The pool left when that year's first epoch closed.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub year_start_pool: u128,
    /// Released in that year so far.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub year_released: u128,
}

/// The governed values of the rule in force.
#[derive(Debug, Clone, Copy)]
struct Terms {
    ratio_bps: u64,
    keep_bps: u64,
    yearly_bps: u64,
    step_pool_bps: u64,
    step_ratio_bps: u64,
    floor_pool_bps: u64,
    boot_ratio_bps: u64,
    boot_epochs: u64,
    boot_budget_bps: u64,
}

impl Terms {
    fn read(state: &dyn VmState) -> Terms {
        Terms {
            ratio_bps: network_param(state, RATIO_PARAM).min(10_000),
            keep_bps: network_param(state, SMOOTHING_KEEP_PARAM).min(10_000),
            yearly_bps: network_param(state, YEARLY_LIMIT_PARAM).min(10_000),
            step_pool_bps: network_param(state, STEP_POOL_PARAM),
            step_ratio_bps: network_param(state, STEP_RATIO_PARAM),
            floor_pool_bps: network_param(state, FLOOR_POOL_PARAM),
            boot_ratio_bps: network_param(state, BOOT_RATIO_PARAM),
            boot_epochs: network_param(state, BOOT_EPOCHS_PARAM),
            boot_budget_bps: network_param(state, BOOT_BUDGET_PARAM).min(10_000),
        }
    }

    /// The ratio in force with `left` of a pool of `pool`.
    fn ratio_at(&self, left: u128, pool: u128) -> u64 {
        if left < bps_of(pool, self.floor_pool_bps) {
            0
        } else if left < bps_of(pool, self.step_pool_bps) {
            self.step_ratio_bps.min(self.ratio_bps)
        } else {
            self.ratio_bps
        }
    }
}

fn bps_of(amount: u128, bps: u64) -> u128 {
    let b = u128::from(bps);
    amount / 10_000 * b + amount % 10_000 * b / 10_000
}

/// An epoch's ceiling and the two parts it was built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ceiling {
    /// Most the epoch releases.
    total: u128,
    /// The ratio's part, before the yearly room.
    ratio_part: u128,
    /// The matched start's part, before the yearly room.
    boot_part: u128,
}

impl ReleaseBook {
    /// Advances the book to `epoch`, which burned `burn` with `left` of a
    /// pool of `pool` still in it, and returns the epoch's ceiling.
    fn open(
        &mut self,
        terms: &Terms,
        epoch: u64,
        epochs_per_year: u64,
        pool: u128,
        left: u128,
        burn: u128,
    ) -> Ceiling {
        self.budget = bps_of(self.budget, terms.keep_bps)
            .saturating_add(bps_of(burn, 10_000 - terms.keep_bps));
        let year = epoch / epochs_per_year.max(1);
        if year != self.year {
            self.year = year;
            self.year_start_pool = left;
            self.year_released = 0;
        }
        let ratio_bps = terms.ratio_at(left, pool);
        let ratio_part = bps_of(self.budget, ratio_bps);
        let age = epoch.saturating_sub(self.first_epoch);
        let boot_part =
            if ratio_bps > 0 && terms.boot_ratio_bps > ratio_bps && age < terms.boot_epochs {
                let over = u128::from(terms.boot_ratio_bps - ratio_bps);
                let matched = burn / 10_000 * over + burn % 10_000 * over / 10_000;
                let falling =
                    matched / u128::from(terms.boot_epochs) * u128::from(terms.boot_epochs - age);
                falling.min(bps_of(pool, terms.boot_budget_bps).saturating_sub(self.boot_spent))
            } else {
                0
            };
        let room =
            bps_of(self.year_start_pool, terms.yearly_bps).saturating_sub(self.year_released);
        Ceiling {
            total: ratio_part.saturating_add(boot_part).min(room),
            ratio_part,
            boot_part,
        }
    }

    /// Books an epoch that released `released` under `ceiling`. The boot
    /// budget is charged the boot share of the ceiling, scaled by how much of
    /// the ceiling was released, so a cut of the release (the per-address
    /// share) charges the matched part pro rata rather than not at all.
    fn close(&mut self, ceiling: &Ceiling, released: u128) {
        self.year_released = self.year_released.saturating_add(released);
        let boot = ceiling
            .total
            .saturating_sub(ceiling.ratio_part)
            .min(ceiling.boot_part);
        self.boot_spent = self.boot_spent.saturating_add(pro_rata(
            released.min(ceiling.total),
            boot,
            ceiling.total,
        ));
    }
}

/// The book as the last live epoch close left it; `None` before the first.
pub fn read_book(state: &dyn VmState) -> Option<ReleaseBook> {
    read_json(state, BOOK_KEY)
}

/// Holds the coupons of `epoch` to the epoch's ceiling and each address to
/// its share. `spoken_for` is what earlier closes took from the pool and did
/// not give back: rights withheld, and coupons claimed or still claimable.
/// Rights that lapsed (unmatched, cut by this rule, or expired unclaimed)
/// stayed in the pool and do not count.
pub(super) fn bound_epoch(
    state: &mut dyn VmState,
    epoch: u64,
    schedule: &MintingSchedule,
    spoken_for: u128,
    summary: &mut EpochRewardSummary,
    coupons: &mut Vec<RewardCoupon>,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let terms = Terms::read(state);
    let left = schedule.pool.saturating_sub(spoken_for);
    let mut book = read_book(state).unwrap_or(ReleaseBook {
        first_epoch: epoch,
        year: epoch / schedule.epochs_per_year.max(1),
        year_start_pool: left,
        ..ReleaseBook::default()
    });
    let activity = super::economy::read_epoch_activity(state, epoch);
    let burn = activity.burned.saturating_add(activity.burn_eq);
    let ceiling = book.open(
        &terms,
        epoch,
        schedule.epochs_per_year,
        schedule.pool,
        left,
        burn,
    );
    tenzro_token::rewards::bound_release(
        summary,
        coupons,
        ceiling.total,
        network_param(state, SHARE_CAP_PARAM),
    );
    book.close(&ceiling, summary.matched);
    write_json(state, BOOK_KEY, &book, changes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_cut_release_charges_the_boot_budget_pro_rata() {
        let ceiling = Ceiling {
            total: 100,
            ratio_part: 60,
            boot_part: 40,
        };
        let mut book = ReleaseBook::default();
        book.close(&ceiling, 100);
        assert_eq!(book.boot_spent, 40);
        let mut book = ReleaseBook::default();
        book.close(&ceiling, 50);
        assert_eq!(
            book.boot_spent, 20,
            "half the ceiling released, half the boot part spent"
        );
        let mut book = ReleaseBook::default();
        book.close(&ceiling, 0);
        assert_eq!(book.boot_spent, 0);
    }

    use super::*;

    const POOL: u128 = 1_000_000;

    fn terms() -> Terms {
        Terms {
            ratio_bps: 10_000,
            keep_bps: 0,
            yearly_bps: 10_000,
            step_pool_bps: 0,
            step_ratio_bps: 0,
            floor_pool_bps: 0,
            boot_ratio_bps: 10_000,
            boot_epochs: 0,
            boot_budget_bps: 0,
        }
    }

    fn book() -> ReleaseBook {
        ReleaseBook {
            year_start_pool: POOL,
            ..ReleaseBook::default()
        }
    }

    #[test]
    fn the_ceiling_is_the_ratio_of_the_epochs_own_burn() {
        for (ratio_bps, want) in [(10_000, 800), (5_000, 400), (0, 0)] {
            let t = Terms {
                ratio_bps,
                ..terms()
            };
            let c = book().open(&t, 0, 365, POOL, POOL, 800);
            assert_eq!((c.total, c.boot_part), (want, 0));
        }
        assert_eq!(book().open(&terms(), 0, 365, POOL, POOL, 0).total, 0);
    }

    #[test]
    fn smoothing_keeps_a_share_of_the_prior_budget_and_never_adds_to_the_burn() {
        let t = Terms {
            keep_bps: 5_000,
            ..terms()
        };
        let mut b = book();
        let burns = [1_000u128, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut ceilings = Vec::new();
        for (epoch, burn) in burns.iter().enumerate() {
            ceilings.push(b.open(&t, epoch as u64, 365, POOL, POOL, *burn).total);
        }
        assert_eq!(&ceilings[..4], &[500, 250, 125, 262]);
        assert!(ceilings.iter().sum::<u128>() <= burns.iter().sum::<u128>());
    }

    #[test]
    fn the_ratio_steps_down_and_then_stops_as_the_pool_falls() {
        let t = Terms {
            step_pool_bps: 1_000,
            step_ratio_bps: 2_500,
            floor_pool_bps: 200,
            ..terms()
        };
        let at = |left: u128| book().open(&t, 0, 365, POOL, left, 1_000).total;
        assert_eq!(at(POOL), 1_000);
        assert_eq!(at(100_000), 1_000);
        assert_eq!(at(99_999), 250);
        assert_eq!(at(20_000), 250);
        assert_eq!(at(19_999), 0);
        // A step ratio set over the ratio does not raise it.
        let over = Terms {
            ratio_bps: 1_000,
            ..t
        };
        assert_eq!(book().open(&over, 0, 365, POOL, 50_000, 1_000).total, 100);
    }

    #[test]
    fn the_matched_start_falls_to_nothing_and_stays_within_its_budget() {
        let t = Terms {
            ratio_bps: 5_000,
            boot_ratio_bps: 20_000,
            boot_epochs: 10,
            boot_budget_bps: 10,
            ..terms()
        };
        let mut b = book();
        // Epoch 0: 0.5 x burn from the ratio, 1.5 x burn matched.
        let c = b.open(&t, 0, 365, POOL, POOL, 400);
        assert_eq!((c.ratio_part, c.boot_part, c.total), (200, 600, 800));
        b.close(&c, 800);
        assert_eq!(b.boot_spent, 600);
        // Halfway: half of the matched part, and no more than the budget of 1000 leaves.
        let c = b.open(&t, 5, 365, POOL, POOL, 4_000);
        assert_eq!((c.ratio_part, c.boot_part), (2_000, 400));
        // A release cut below the ceiling (the per-address share) spends the
        // matched budget in proportion: 1500 of 2400 charges 250 of the 400.
        b.close(&c, 1_500);
        assert_eq!(b.boot_spent, 850);
        assert_eq!(b.open(&t, 10, 365, POOL, POOL, 400).boot_part, 0);
        // No burn, no matched release.
        assert_eq!(book().open(&t, 0, 365, POOL, POOL, 0).total, 0);
    }

    #[test]
    fn a_years_releases_stay_within_the_limit_of_the_pool_it_began_with() {
        let t = Terms {
            yearly_bps: 100,
            ..terms()
        };
        let mut b = book();
        let mut released = 0;
        for epoch in 0..4 {
            let c = b.open(&t, epoch, 4, POOL, POOL - released, 6_000);
            b.close(&c, c.total);
            released += c.total;
        }
        assert_eq!(released, 10_000);
        // The next year begins with the pool that is left.
        let c = b.open(&t, 4, 4, POOL, POOL - released, 20_000);
        assert_eq!(c.total, 9_900);
    }
}
