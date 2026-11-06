//! Hardware-level bonus against network growth.
//!
//! A population of providers on a hardware mix skewed to older devices joins
//! and leaves on its own profit, epoch by epoch, twice from the same arrivals:
//! once with the hardware-level bonus at its governed band and once with it
//! off. Rewards are the reward engine's own settlement
//! ([`tenzro_token::rewards::settle_epoch_with_levels`]) at the genesis mint
//! policy; levels come from each provider's hardware class.
//!
//! Checks:
//! - H1, growth: the final and the mean participant count with the bonus on
//!   are at least those with it off. Epochs with fewer, the largest dip and
//!   the level-0 count are reported beside it: extra attested entrants
//!   compete for the same demand.
//! - H2, base untouched: in every epoch of the bonus-on run, every level-0
//!   provider earns exactly what the same network pays it with the bonus off.
//! - H3, no rank beyond the cap: no provider's reward exceeds its base share
//!   by more than the cap, and the share of rewards held by levels above 0
//!   is at most its share of base rewards times (1 + cap).

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tenzro_token::rewards::{
    LevelBonus, MINT_MULT_ONE_PPM, MintPolicy, MintingSchedule, ONE_TNZO, WorkClass, WorkRecord,
    settle_epoch_with_levels,
};
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_vm::governance::genesis_param;
use tenzro_vm::native::hardware_level as hl;

use crate::bme::TestResult;

/// One run's settings.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HwConfig {
    /// Seed of the arrivals.
    pub seed: u64,
    /// Daily epochs simulated.
    pub epochs: u64,
    /// Hardware mix of arrivals, percent at levels 0 to 3.
    pub mix: [u32; 4],
    /// Bonus per level, bps (index 0 unused).
    pub level_bps: [u64; 4],
    /// Bonus cap, bps.
    pub cap_bps: u64,
    /// Candidate providers arriving each epoch.
    pub arrivals: u32,
    /// Paid demand in the first epoch, whole TNZO of provider reward weight.
    pub demand0_tnzo: u64,
    /// Demand growth per epoch, ppm.
    pub demand_growth_ppm: u64,
}

impl Default for HwConfig {
    fn default() -> Self {
        Self {
            seed: 1,
            epochs: 365,
            mix: [70, 25, 4, 1],
            level_bps: [
                0,
                hl::DEFAULT_LEVEL1_BONUS_BPS,
                hl::DEFAULT_LEVEL2_BONUS_BPS,
                hl::DEFAULT_LEVEL3_BONUS_BPS,
            ],
            cap_bps: hl::DEFAULT_LEVEL_BONUS_CAP_BPS,
            arrivals: 20,
            demand0_tnzo: 20_000,
            demand_growth_ppm: 5_000,
        }
    }
}

/// A candidate provider: hardware level, serving capacity and running cost
/// per epoch (whole TNZO), drawn before either run so both see the same.
#[derive(Debug, Clone, Copy)]
struct Candidate {
    level: u8,
    capacity: u64,
    cost: u64,
}

#[derive(Debug, Clone)]
struct Provider {
    id: u32,
    c: Candidate,
    /// Profit of the last epochs, whole TNZO.
    recent: Vec<i128>,
}

/// One epoch of a run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HwPoint {
    pub epoch: u64,
    pub participants: u64,
    pub participants_l0: u64,
    pub participants_above_l0: u64,
    /// Rewards paid, whole TNZO.
    pub rewards_tnzo: f64,
    /// Bonus paid, whole TNZO.
    pub bonus_tnzo: f64,
    /// Share of rewards held by levels above 0, bps.
    pub above_l0_reward_bps: u64,
    /// Share of base rewards held by levels above 0, bps.
    pub above_l0_base_bps: u64,
    /// Largest reward over base share of any provider, ppm of base.
    pub max_reward_over_base_ppm: u64,
    /// Level-0 providers whose reward differed from the bonus-off settlement
    /// of the same network.
    pub l0_mismatches: u64,
}

fn policy() -> MintPolicy {
    MintPolicy {
        base_tnzo_per_year: genesis_param("mint.base_tnzo_per_year"),
        decay_bps_per_year: genesis_param("mint.decay_bps_per_year"),
        floor_tnzo_per_year: genesis_param("mint.floor_tnzo_per_year"),
        mult_ppm: MINT_MULT_ONE_PPM,
        validator_bps: genesis_param("mint.validator_share_bps"),
        provider_bps: genesis_param("mint.provider_share_bps"),
        ecosystem_bps: genesis_param("mint.ecosystem_share_bps"),
        revenue_peg_bps: genesis_param("mint.revenue_peg_bps"),
        validator_base_rights: 0,
        withheld_rights: 0,
    }
}

fn arrivals(cfg: &HwConfig) -> Vec<Vec<Candidate>> {
    let mut rng = StdRng::seed_from_u64(cfg.seed);
    let total: u32 = cfg.mix.iter().sum::<u32>().max(1);
    (0..cfg.epochs)
        .map(|_| {
            (0..cfg.arrivals)
                .map(|_| {
                    let mut roll = rng.gen_range(0..total);
                    let mut level = 0u8;
                    for (l, share) in cfg.mix.iter().enumerate() {
                        if roll < *share {
                            level = l as u8;
                            break;
                        }
                        roll -= share;
                    }
                    // Newer hardware serves more and costs more to run.
                    let capacity = rng.gen_range(50..150) * (10 + u64::from(level) * 3) / 10;
                    let cost = rng.gen_range(20..120) * (10 + u64::from(level) * 4) / 10;
                    Candidate {
                        level,
                        capacity,
                        cost,
                    }
                })
                .collect()
        })
        .collect()
}

fn addr(id: u32) -> Address {
    let mut a = [0u8; 32];
    a[..4].copy_from_slice(&id.to_be_bytes());
    Address::new(a)
}

/// One run: `bonus_on` pays the configured band, otherwise cap 0.
pub fn run(cfg: &HwConfig, bonus_on: bool) -> Vec<HwPoint> {
    let schedule = MintingSchedule::for_epoch_ms(86_400_000).expect("schedule");
    let policy = policy();
    let arriving = arrivals(cfg);
    let mut live: Vec<Provider> = Vec::new();
    let mut next_id = 0u32;
    let mut cumulative: u128 = 0;
    // Income per unit of capacity by level last epoch, whole TNZO.
    let mut per_capacity = [1.0f64; 4];
    let mut points = Vec::new();
    for epoch in 0..cfg.epochs {
        // Arrivals join when last epoch's income for their level covers cost.
        for c in &arriving[epoch as usize] {
            if per_capacity[usize::from(c.level)] * c.capacity as f64 >= c.cost as f64 {
                live.push(Provider {
                    id: next_id,
                    c: *c,
                    recent: Vec::new(),
                });
                next_id += 1;
            }
        }
        let demand =
            cfg.demand0_tnzo as f64 * (1.0 + cfg.demand_growth_ppm as f64 / 1e6).powf(epoch as f64);
        let total_capacity: u64 = live.iter().map(|p| p.c.capacity).sum::<u64>().max(1);
        let work: Vec<WorkRecord> = live
            .iter()
            .map(|p| WorkRecord {
                address: addr(p.id),
                class: WorkClass::InferenceServed,
                weight: (demand * p.c.capacity as f64 / total_capacity as f64 * ONE_TNZO as f64)
                    as u128,
            })
            .collect();
        let band = LevelBonus {
            levels: live
                .iter()
                .filter(|p| p.c.level > 0)
                .map(|p| (addr(p.id).0, p.c.level))
                .collect(),
            level_bps: cfg.level_bps,
            cap_bps: if bonus_on { cfg.cap_bps } else { 0 },
        };
        let at = Timestamp::new(epoch as i64 * 86_400_000);
        let (summary, coupons) =
            settle_epoch_with_levels(&schedule, &policy, cumulative, epoch, &work, &band, at);
        let (_, base) = settle_epoch_with_levels(
            &schedule,
            &policy,
            cumulative,
            epoch,
            &work,
            &LevelBonus::default(),
            at,
        );
        cumulative = cumulative.saturating_add(summary.rights_issued);

        let mut l0_mismatches = 0;
        let mut max_over = 0u64;
        let (mut above, mut above_base, mut all, mut all_base) = (0u128, 0u128, 0u128, 0u128);
        let mut income_by_level = [0.0f64; 4];
        let mut capacity_by_level = [0u64; 4];
        for p in live.iter_mut() {
            let a = addr(p.id);
            let got = coupons
                .iter()
                .find(|c| c.address == a)
                .map_or(0, |c| c.amount);
            let b = base.iter().find(|c| c.address == a).map_or(0, |c| c.amount);
            if p.c.level == 0 && got != b {
                l0_mismatches += 1;
            }
            if let Some(over) = ((got - b) * 1_000_000).checked_div(b) {
                max_over = max_over.max(over as u64);
            }
            all += got;
            all_base += b;
            if p.c.level > 0 {
                above += got;
                above_base += b;
            }
            let weight = work.iter().find(|w| w.address == a).map_or(0, |w| w.weight);
            // Service income beside the reward: what buyers paid, at the
            // provider reward ceiling's inverse.
            let fees = weight as f64 / ONE_TNZO as f64 * 2.5;
            let income = got as f64 / ONE_TNZO as f64 + fees;
            income_by_level[usize::from(p.c.level)] += income;
            capacity_by_level[usize::from(p.c.level)] += p.c.capacity;
            p.recent.push(income as i128 - p.c.cost as i128);
            if p.recent.len() > 7 {
                p.recent.remove(0);
            }
        }
        for l in 0..4 {
            if capacity_by_level[l] > 0 {
                per_capacity[l] = income_by_level[l] / capacity_by_level[l] as f64;
            }
        }
        let bps = |x: u128, of: u128| (x * 10_000).checked_div(of).unwrap_or(0) as u64;
        points.push(HwPoint {
            epoch,
            participants: live.len() as u64,
            participants_l0: live.iter().filter(|p| p.c.level == 0).count() as u64,
            participants_above_l0: live.iter().filter(|p| p.c.level > 0).count() as u64,
            rewards_tnzo: all as f64 / ONE_TNZO as f64,
            bonus_tnzo: summary.level_bonus as f64 / ONE_TNZO as f64,
            above_l0_reward_bps: bps(above, all),
            above_l0_base_bps: bps(above_base, all_base),
            max_reward_over_base_ppm: max_over,
            l0_mismatches,
        });
        // Providers whose last week lost money leave.
        live.retain(|p| p.recent.len() < 7 || p.recent.iter().sum::<i128>() >= 0);
    }
    points
}

/// Both runs and the three checks.
pub fn tests(cfg: &HwConfig) -> (Vec<TestResult>, Vec<HwPoint>, Vec<HwPoint>) {
    let on = run(cfg, true);
    let off = run(cfg, false);
    // Growth is judged over the run: the final count and the mean count
    // with the bonus on are at least those with it off. Single epochs can
    // dip by a few participants where extra attested entrants take demand
    // a marginal older device needed; the largest such dip is reported.
    let fewer = on
        .iter()
        .zip(&off)
        .filter(|(a, b)| a.participants < b.participants)
        .count();
    let worst_dip = on
        .iter()
        .zip(&off)
        .map(|(a, b)| b.participants.saturating_sub(a.participants))
        .max()
        .unwrap_or(0);
    let mean = |v: &[HwPoint]| {
        v.iter().map(|p| p.participants as f64).sum::<f64>() / v.len().max(1) as f64
    };
    let (mean_on, mean_off) = (mean(&on), mean(&off));
    let (last_on, last_off) = (on.last().cloned(), off.last().cloned());
    let final_ok = match (&last_on, &last_off) {
        (Some(a), Some(b)) => a.participants >= b.participants,
        _ => true,
    };
    let h1 = TestResult {
        number: 1,
        name: "participant growth with the bonus on is not lower than with it off".into(),
        pass: final_ok && mean_on >= mean_off,
        detail: format!(
            "final participants on {} (L0 {}) off {} (L0 {}); mean on {mean_on:.1} off {mean_off:.1}; epochs with fewer {fewer} of {}, largest dip {worst_dip}",
            last_on.as_ref().map_or(0, |p| p.participants),
            last_on.as_ref().map_or(0, |p| p.participants_l0),
            last_off.as_ref().map_or(0, |p| p.participants),
            last_off.as_ref().map_or(0, |p| p.participants_l0),
            on.len(),
        ),
    };
    let mismatches: u64 = on.iter().map(|p| p.l0_mismatches).sum();
    let h2 = TestResult {
        number: 2,
        name: "every level-0 provider earns its bonus-off reward exactly".into(),
        pass: mismatches == 0,
        detail: format!("level-0 rewards that differed: {mismatches}"),
    };
    let cap_ppm = cfg.cap_bps * 100;
    let worst_over = on
        .iter()
        .map(|p| p.max_reward_over_base_ppm)
        .max()
        .unwrap_or(0);
    let share_breach = on
        .iter()
        .filter(|p| {
            u128::from(p.above_l0_reward_bps) * 10_000
                > u128::from(p.above_l0_base_bps) * u128::from(10_000 + cfg.cap_bps) + 10_000
        })
        .count();
    let h3 = TestResult {
        number: 3,
        name: "no provider or level class gains beyond the cap".into(),
        pass: worst_over <= cap_ppm && share_breach == 0,
        detail: format!(
            "largest reward over base {worst_over} ppm (cap {cap_ppm}); epochs where levels above 0 out-earned their base share by more than the cap: {share_breach}"
        ),
    };
    (vec![h1, h2, h3], on, off)
}
