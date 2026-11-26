//! Operator-earnings beyond per-call settlement: the spot tier, the standby
//! fee and the availability (readiness) reward.
//!
//! The demand, price, treasury-runway and listing-gate trajectory comes from
//! one real [`crate::economy::Economy`] run per market mode. The availability
//! reward is the ledger's own rule: each day's per-unit-hour reward is
//! `tenzro_vm::native::availability_reward::unit_hour_reward` on a state
//! holding the sweep point's governed cap and half-life, at that day's TNZO
//! price, once with the absolute cap and once with the indexed cap live (the
//! datacenter-GPU index held at the list rate, the simulated unit a proven
//! GPU). The demand offset runs on the whole-USD target with its gate live,
//! at the listing gate's 60,000 USD/day, each day's unrelated demand settled
//! in the hour the reward is read at. Spot and
//! standby are operator-set rate-card lines with no network rule to replay,
//! so their income stays rate-card arithmetic, as do vesting, Sybil and
//! challenge-energy figures.

use serde::Serialize;

use crate::economy::{Day, Economy, Market, RunConfig, RunOutcome};
use crate::listing::{ListingGate, UNRELATED_USD_DAY};
use tenzro_vm::native::{self as n, availability_reward as ar};
use tenzro_vm::traits::VmState;

/// Reference GPU-hour list rate the three legs price against (H100-class
/// spot, VERIFY doc section 6: raw spot USD 1-2/GPU-hour; mid of range).
pub const LIST_RATE_USD_GPU_HOUR: f64 = 1.5;

/// Per-tier reward multiplier and challenge energy, VERIFY doc sections 2.3
/// and 4 (H100 idle-with-context power, challenge energy per tier).
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Warm,
    Cool,
    Cold,
}

impl Tier {
    pub const ALL: [Tier; 3] = [Tier::Warm, Tier::Cool, Tier::Cold];

    /// Reward multiplier (section 9: warm 1.0 / cool 0.6 / cold 0.2).
    pub fn reward_mult(self) -> f64 {
        match self {
            Tier::Warm => 1.0,
            Tier::Cool => 0.6,
            Tier::Cold => 0.2,
        }
    }

    /// Default challenge rate, per unit-day (section 9 defaults).
    pub fn default_challenge_rate_per_day(self) -> f64 {
        match self {
            Tier::Warm => 4.0,
            Tier::Cool => 1.0,
            Tier::Cold => 1.0 / 7.0,
        }
    }

    /// Energy per challenge, kJ (section 4: ~1 kJ warm/cool small-model
    /// challenge; cold adds an unconfirmed host boot cost, taken here at the
    /// documented midpoint of the 50-150 kJ range, flagged UNCONFIRMED).
    pub fn challenge_energy_kj(self) -> f64 {
        match self {
            Tier::Warm => 1.0,
            Tier::Cool => 4.0,
            Tier::Cold => 100.0, // [UNCONFIRMED], section 4 table
        }
    }

    /// Idle energy denominator per unit-day, MJ (section 4 table: warm-idle
    /// 10.5 MJ/day at 122 W; cool 6.2 MJ/day at 72 W; cold ~0, not
    /// meaningful per-node, so reported separately as fleet host-standby
    /// share, not folded into this ratio).
    pub fn idle_energy_mj_day(self) -> f64 {
        match self {
            Tier::Warm => 10.5,
            Tier::Cool => 6.2,
            Tier::Cold => 0.5, // host standby only, [UNCONFIRMED]
        }
    }
}

/// One sweep point's governed parameters: the knobs the three legs expose
/// to governance, per section 9's recommended-parameters table. Not
/// emergent from the ledger sim (the sim has no leg code yet); the macro
/// context (demand, price, runway, listing gate) is emergent, from the one
/// real [`Economy`] run per market this point is paired with.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct LegParams {
    pub market: &'static str,
    /// Spot discount off the list rate (section 9 sweep 30-70%, anchor 50%).
    pub spot_discount: f64,
    /// Share of idle GPU-hours sold at spot instead of standing fully idle.
    pub spot_share: f64,
    /// Standby fee, share of the list rate, paid whether called or not
    /// (section 9 sweep 10-100%, recommended 20-40%).
    pub standby_fee_share: f64,
    /// Share of the fleet opted into a standby reservation.
    pub standby_uptake: f64,
    /// Per-unit reward cap, share of the list rate per idle unit-hour
    /// (section 9: at most 7.5%, sweep 5-10%).
    pub reward_cap_share: f64,
    /// Decay half-life, months (section 9 sweep 6-24, default 12).
    pub decay_half_life_months: f64,
    /// Vested share, forfeited on slash or early exit (section 9 sweep
    /// 0/50/100%, recommended 50%).
    pub vested_share: f64,
    /// Vesting window, days (section 9 sweep 30-180, recommended 90).
    pub vest_days: f64,
    /// Bond per unit, days of expected reward (section 9: 3-14, recommended
    /// 7).
    pub bond_days: f64,
    /// Share of the idle fleet declaring cool or cold (vs warm): drives the
    /// energy-saved and challenge-energy-ratio figures.
    pub low_power_share: f64,
}

/// One sweep point's measures.
#[derive(Debug, Clone, Serialize)]
pub struct LegResult {
    pub params: LegParams,

    // -- macro context, read from the one real Economy run for this market --
    /// Year the listing gate held (`gate_held_day` / 365.25), if within the
    /// run.
    pub listing_gate_year: Option<f64>,
    /// Treasury runway at the end of the run, months.
    pub treasury_runway_months_end: f64,
    /// TNZO price at the end of the run, USD (the "buyer price" of the
    /// chain's own unit of account; the three legs' own buyer price is
    /// reported in USD/GPU-hour below, which does not depend on this).
    pub chain_price_usd_end: f64,
    /// Day the chain's unrelated demand first reached the listing gate's
    /// USD/day threshold (`UNRELATED_USD_DAY`), the demand offset's target
    /// in the design: the day the offset would have phased the reward out,
    /// and the reference point for "when does usage income dominate".
    pub target_demand_reached_day: Option<f64>,

    // -- treasury concentration: structural, not re-simulated here --
    /// Whether this leg design worsens the existing treasury-concentration
    /// warning (dex.rs's stake-share/handover sweep over the *bonded
    /// validator stake* pool). False here because the availability reward
    /// is paid from a separate rewards-treasury pool, and validators are
    /// explicitly excluded from it (VERIFY doc section 8); spot and standby
    /// are per-call/per-reservation settlement, not stake. See dex.rs
    /// (`stake_share`, `handover`) for the pool this warning is actually
    /// about.
    pub worsens_concentration_warning: bool,

    // -- leg economics, rate-card arithmetic on the macro trajectory --
    /// Operator income per GPU-hour on the spot leg, USD.
    pub operator_income_spot_usd_gpu_hour: f64,
    /// Buyer price per GPU-hour on the spot leg, USD (what the buyer pays;
    /// equals the operator's income less the network's take is not
    /// modelled here -- the rate card is quoted net of take already, as in
    /// `ClassSpec::take` elsewhere in this crate).
    pub buyer_price_spot_usd_gpu_hour: f64,
    /// Operator income per GPU-hour on the standby leg, USD (paid whether
    /// or not the standby unit is called).
    pub operator_income_standby_usd_gpu_hour: f64,
    /// Operator income per idle GPU-hour from the availability reward alone
    /// (no spot, no standby), at the run's start (full budget, no decay, no
    /// demand offset yet) and at its end (decayed, demand-offset applied).
    pub operator_income_reward_usd_gpu_hour_start: f64,
    pub operator_income_reward_usd_gpu_hour_end: f64,
    /// The same with the indexed cap live, at the run's start and end.
    pub operator_income_reward_indexed_usd_gpu_hour_start: f64,
    pub operator_income_reward_indexed_usd_gpu_hour_end: f64,
    /// Day usage income (spot + standby, constant rate-card income) first
    /// exceeds the reward income for an all-cold-declared idle unit: the
    /// crossover the design is meant to produce. `None` if it never does
    /// within the run (e.g. reward cap already below usage income at day
    /// 0: reported as crossover at day 0).
    pub crossover_day: Option<f64>,

    // -- Sybil deterrence, section 3.1/8's (1-v)R/r vs B+U condition --
    /// A fake unit's expected liquid net before being caught, USD
    /// (`(1 - vested_share) * reward_per_unit_day / challenge_rate_per_day`).
    pub sybil_attacker_net_usd: f64,
    /// The bond plus the steady-state forfeitable unvested balance the
    /// attacker risks, USD (`(bond_days + vest_days) * reward_per_unit_day`).
    pub sybil_at_risk_usd: f64,
    /// Whether cheating is profitable under these parameters
    /// (`attacker_net > at_risk`): should be false everywhere the sweep
    /// recommends.
    pub sybil_profitable: bool,

    // -- energy, section 4 --
    /// Challenge energy as a share of the idle fleet's own energy, warm
    /// tier, at the warm default challenge rate (the tightest case: cool
    /// breaks budget above ~1/day per section 4).
    pub challenge_energy_share_warm_pct: f64,
    pub challenge_energy_share_cool_pct: f64,
    /// Fleet-wide challenge energy share, blended by `low_power_share`
    /// across warm and cool (cold excluded from the ratio: its idle
    /// denominator is not meaningful per-node, per section 4).
    pub challenge_energy_share_fleet_pct: f64,
    /// Energy saved by moving `low_power_share` of the idle fleet from warm
    /// to cool, as a share of always-warm idle energy (section 2.3: ~40-50%
    /// per GPU moved).
    pub idle_energy_saved_pct: f64,
}

/// A run's listing-gate year and the day unrelated demand first reached
/// the gate's threshold -- both read once per market, shared by every
/// sweep point paired with that market.
struct MacroContext {
    outcome: RunOutcome,
    listing_gate: ListingGate,
}

fn macro_context(market: Market, seed: u64, days: u32) -> MacroContext {
    let outcome = Economy::new(RunConfig::scenario(market, seed, days)).run();
    let listing_gate = ListingGate::of(&outcome.days);
    MacroContext {
        outcome,
        listing_gate,
    }
}

fn target_demand_reached_day(days: &[Day]) -> Option<f64> {
    days.iter()
        .find(|d| d.unrelated_demand_usd_day >= UNRELATED_USD_DAY)
        .map(|d| d.snap.day)
}

/// The availability reward one unit earns per hour on each of `days`, USD,
/// by the ledger's rule: the governed cap is `reward_cap_share` of the list
/// rate in TNZO at the first day's price, decaying from the first epoch on
/// the sweep point's half-life; with `indexed`, the indexed cap is live
/// against a datacenter-GPU index at the list rate and the unit is a proven
/// GPU. The demand offset targets [`UNRELATED_USD_DAY`] and each day's
/// unrelated demand is settled in the hour that day's reward is read at.
fn ledger_reward_usd_gpu_hour(p: &LegParams, days: &[Day], indexed: bool) -> Vec<f64> {
    let Some(first) = days.first() else {
        return Vec::new();
    };
    let mut st = tenzro_vm::StateAdapter::new();
    let cap_wei = p.reward_cap_share * LIST_RATE_USD_GPU_HOUR / first.price_usd.max(1e-9) * 1e18;
    let cap_wei = cap_wei.min(ar::MAX_AVAILABILITY_REWARD_PER_UNIT_HOUR as f64) as u64;
    n::set_genesis_param(
        &mut st,
        ar::AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM,
        cap_wei,
    );
    n::set_genesis_param(
        &mut st,
        ar::AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS_PARAM,
        (p.decay_half_life_months * 30.4375).round() as u64,
    );
    n::set_genesis_param(&mut st, ar::AVAILABILITY_REWARD_DECAY_START_EPOCH_PARAM, 1);
    n::set_genesis_param(&mut st, ar::AVAILABILITY_DEMAND_TARGET_USD_KEY, 0);
    n::set_genesis_param(
        &mut st,
        ar::AVAILABILITY_REWARD_DEMAND_TARGET_USD_PER_DAY_PARAM,
        UNRELATED_USD_DAY as u64,
    );
    if indexed {
        n::set_genesis_param(&mut st, ar::AVAILABILITY_INDEX_CAP_KEY, 0);
        let index = serde_json::json!({
            "rate_nano_usd": ((LIST_RATE_USD_GPU_HOUR * 1e9).round() as u128).to_string(),
            "epoch": 0,
        });
        let symbol =
            n::economy::compute_index_symbol(tenzro_types::hardware::HardwareClass::DatacenterGpu)
                .expect("the datacenter-GPU class has an index");
        st.set_storage(
            &n::SYSTEM_ADDRESS,
            n::economy::live_key(symbol).as_bytes(),
            serde_json::to_vec(&index).expect("an index record encodes"),
        );
    }
    days.iter()
        .map(|d| {
            let rate = (d.price_usd * 1e9).round().max(1.0) as u64;
            n::set_genesis_param(&mut st, n::economy::GOVERNANCE_RATE_PARAM, rate);
            let epoch = 1 + (d.snap.day.max(0.0) * 24.0) as u64;
            let settled = d.unrelated_demand_usd_day / d.price_usd.max(1e-9) * 1e18;
            let activity = n::economy::EpochActivity {
                settled_value: settled.max(0.0) as u128,
                ..Default::default()
            };
            st.set_storage(
                &n::SYSTEM_ADDRESS,
                n::economy::activity_key(epoch).as_bytes(),
                serde_json::to_vec(&activity).expect("an activity record encodes"),
            );
            ar::unit_hour_reward(&st, epoch, indexed) as f64 / 1e18 * d.price_usd
        })
        .collect()
}

fn leg_result(p: LegParams, mc: &MacroContext) -> LegResult {
    let days = &mc.outcome.days;
    let last = days.last();

    let spot_rate = LIST_RATE_USD_GPU_HOUR * (1.0 - p.spot_discount);
    let standby_rate = LIST_RATE_USD_GPU_HOUR * p.standby_fee_share;

    let ledger = ledger_reward_usd_gpu_hour(&p, days, false);
    let indexed = ledger_reward_usd_gpu_hour(&p, days, true);
    let reward_start = ledger.first().copied().unwrap_or(0.0) * Tier::Warm.reward_mult();
    let reward_end = ledger.last().copied().unwrap_or(0.0) * Tier::Warm.reward_mult();

    let usage_income_usd_gpu_hour = p.spot_share * spot_rate + p.standby_uptake * standby_rate;
    let crossover_day = days
        .iter()
        .zip(&ledger)
        .find(|(_, r)| usage_income_usd_gpu_hour >= *r * Tier::Cold.reward_mult())
        .map(|(d, _)| d.snap.day)
        .or((usage_income_usd_gpu_hour >= reward_start).then_some(0.0));

    // Sybil deterrence at the warm tier, the easiest tier to fake (highest
    // reward, and the tier a rented cloud GPU can satisfy): R is the warm
    // reward at the run's start (the attacker's best-case window, before
    // decay/offset erode it).
    let r_warm_usd_day = reward_start * 24.0 / Tier::Warm.reward_mult().max(1e-9);
    let attacker_net = (1.0 - p.vested_share) * r_warm_usd_day / p.challenge_rate_per_day_warm();
    let at_risk = (p.bond_days + p.vest_days) * r_warm_usd_day;

    let challenge_warm_pct =
        100.0 * Tier::Warm.default_challenge_rate_per_day() * Tier::Warm.challenge_energy_kj()
            / (Tier::Warm.idle_energy_mj_day() * 1_000.0);
    let challenge_cool_pct =
        100.0 * Tier::Cool.default_challenge_rate_per_day() * Tier::Cool.challenge_energy_kj()
            / (Tier::Cool.idle_energy_mj_day() * 1_000.0);
    let fleet_pct =
        (1.0 - p.low_power_share) * challenge_warm_pct + p.low_power_share * challenge_cool_pct;
    let idle_saved_pct = p.low_power_share
        * 100.0
        * (Tier::Warm.idle_energy_mj_day() - Tier::Cool.idle_energy_mj_day())
        / Tier::Warm.idle_energy_mj_day();

    LegResult {
        params: p,
        listing_gate_year: mc.listing_gate.gate_held_day.map(|d| d / 365.25),
        treasury_runway_months_end: last.map(|d| d.treasury_runway_months).unwrap_or(0.0),
        chain_price_usd_end: last.map(|d| d.price_usd).unwrap_or(0.0),
        target_demand_reached_day: target_demand_reached_day(days),
        worsens_concentration_warning: false,
        operator_income_spot_usd_gpu_hour: spot_rate,
        buyer_price_spot_usd_gpu_hour: spot_rate,
        operator_income_standby_usd_gpu_hour: standby_rate,
        operator_income_reward_usd_gpu_hour_start: reward_start,
        operator_income_reward_usd_gpu_hour_end: reward_end,
        operator_income_reward_indexed_usd_gpu_hour_start: indexed.first().copied().unwrap_or(0.0),
        operator_income_reward_indexed_usd_gpu_hour_end: indexed.last().copied().unwrap_or(0.0),
        crossover_day,
        sybil_attacker_net_usd: attacker_net,
        sybil_at_risk_usd: at_risk,
        sybil_profitable: attacker_net > at_risk,
        challenge_energy_share_warm_pct: challenge_warm_pct,
        challenge_energy_share_cool_pct: challenge_cool_pct,
        challenge_energy_share_fleet_pct: fleet_pct,
        idle_energy_saved_pct: idle_saved_pct,
    }
}

impl LegParams {
    fn challenge_rate_per_day_warm(&self) -> f64 {
        Tier::Warm.default_challenge_rate_per_day()
    }
}

/// Every sweep point, one [`Economy`] run per market (3 total; every other
/// parameter is swept analytically on top of it, so the grid below is cheap
/// however large it grows).
pub fn sweep_grid() -> Vec<LegParams> {
    let mut out = Vec::new();
    for &(name, market) in &[
        ("growth", Market::Growth),
        ("flat", Market::Flat),
        ("downturn", Market::Downturn),
    ] {
        let _ = market;
        for &decay_half_life_months in &[6.0, 12.0, 24.0] {
            for &spot_discount in &[0.3, 0.5, 0.7] {
                for &standby_uptake in &[0.0, 0.25, 0.5] {
                    // spot_share fixed at 0.5 made usage income dominate
                    // the reward from day 0 everywhere, so crossover_day
                    // was uniformly day 1 and uninformative; swept here so
                    // low-spot-share points can show the reward's decay
                    // actually mattering.
                    for &spot_share in &[0.0, 0.1, 0.5] {
                        out.push(LegParams {
                            market: name,
                            spot_discount,
                            spot_share,
                            standby_fee_share: 0.3,
                            standby_uptake,
                            reward_cap_share: 0.075,
                            decay_half_life_months,
                            vested_share: 0.5,
                            vest_days: 90.0,
                            bond_days: 7.0,
                            low_power_share: 0.5,
                        });
                    }
                }
            }
        }
    }
    out
}

/// Runs the grid, one real [`Economy`] run per market, `days` long, cached
/// and reused across every sweep point sharing that market.
pub fn sweep(days: u32, seed: u64) -> Vec<LegResult> {
    let growth = macro_context(Market::Growth, seed, days);
    let flat = macro_context(Market::Flat, seed, days);
    let downturn = macro_context(Market::Downturn, seed, days);
    sweep_grid()
        .into_iter()
        .map(|p| {
            let mc = match p.market {
                "growth" => &growth,
                "flat" => &flat,
                _ => &downturn,
            };
            leg_result(p, mc)
        })
        .collect()
}

/// The results as a Markdown table.
pub fn table(results: &[LegResult]) -> String {
    let mut s = String::from(
        "| market | decay half-life mo | spot discount | standby uptake | listing-gate yr | runway end mo | spot $/GPU-h | standby $/GPU-h | reward $/GPU-h start | reward $/GPU-h end | indexed reward $/GPU-h start | indexed reward $/GPU-h end | crossover day | Sybil net $ | Sybil at-risk $ | Sybil profitable | challenge E warm % | challenge E cool % | fleet challenge E % | idle E saved % |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    for r in results {
        let p = &r.params;
        s.push_str(&format!(
            "| {} | {:.0} | {:.0}% | {:.0}% | {} | {:.1} | {:.3} | {:.3} | {:.4} | {:.4} | {:.4} | {:.4} | {} | {:.2} | {:.2} | {} | {:.3} | {:.3} | {:.3} | {:.1} |\n",
            p.market,
            p.decay_half_life_months,
            100.0 * p.spot_discount,
            100.0 * p.standby_uptake,
            r.listing_gate_year
                .map(|y| format!("{y:.1}"))
                .unwrap_or_else(|| "not within run".into()),
            r.treasury_runway_months_end,
            r.operator_income_spot_usd_gpu_hour,
            r.operator_income_standby_usd_gpu_hour,
            r.operator_income_reward_usd_gpu_hour_start,
            r.operator_income_reward_usd_gpu_hour_end,
            r.operator_income_reward_indexed_usd_gpu_hour_start,
            r.operator_income_reward_indexed_usd_gpu_hour_end,
            r.crossover_day
                .map(|d| format!("{d:.0}"))
                .unwrap_or_else(|| "not within run".into()),
            r.sybil_attacker_net_usd,
            r.sybil_at_risk_usd,
            if r.sybil_profitable { "YES (bad)" } else { "no" },
            r.challenge_energy_share_warm_pct,
            r.challenge_energy_share_cool_pct,
            r.challenge_energy_share_fleet_pct,
            r.idle_energy_saved_pct,
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Days every test's economy runs over. The tests check the legs'
    /// arithmetic and the ledger rule, not long-horizon outcomes; the full
    /// sweep over two years is `tenzro-econsim earnings --days 730`.
    const TEST_DAYS: u32 = 400;

    /// One economy run per market for the whole test binary: each run is
    /// the expensive part, and every test reads it without changing it.
    fn ctx(market: Market) -> &'static MacroContext {
        static CTX: std::sync::OnceLock<[MacroContext; 3]> = std::sync::OnceLock::new();
        let all = CTX.get_or_init(|| {
            [Market::Growth, Market::Flat, Market::Downturn].map(|m| macro_context(m, 1, TEST_DAYS))
        });
        match market {
            Market::Growth => &all[0],
            Market::Flat => &all[1],
            Market::Downturn => &all[2],
        }
    }

    #[test]
    fn sybil_deterrence_holds_at_section_9_defaults() {
        let mc = ctx(Market::Flat);
        let p = sweep_grid()
            .into_iter()
            .find(|p| {
                p.market == "flat" && p.decay_half_life_months == 12.0 && p.spot_discount == 0.5
            })
            .expect("a default-ish point exists in the grid");
        let r = leg_result(p, mc);
        assert!(
            !r.sybil_profitable,
            "attacker net {} should not exceed at-risk {} at the section 9 defaults",
            r.sybil_attacker_net_usd, r.sybil_at_risk_usd
        );
    }

    #[test]
    fn challenge_energy_budget_holds_for_warm_and_breaks_as_documented_for_cool_above_one_per_day()
    {
        // Section 4: warm stays well under 0.1%; cool at the default 1/day
        // rate (not 2/day) also holds, matching the research doc's table.
        let warm =
            100.0 * Tier::Warm.default_challenge_rate_per_day() * Tier::Warm.challenge_energy_kj()
                / (Tier::Warm.idle_energy_mj_day() * 1_000.0);
        let cool =
            100.0 * Tier::Cool.default_challenge_rate_per_day() * Tier::Cool.challenge_energy_kj()
                / (Tier::Cool.idle_energy_mj_day() * 1_000.0);
        assert!(
            warm < 0.1,
            "warm {warm}% should be well under the 0.1% budget"
        );
        assert!(
            cool < 0.1,
            "cool at 1/day {cool}% should hold the 0.1% budget"
        );
        let cool_2x = 100.0 * 2.0 * Tier::Cool.challenge_energy_kj()
            / (Tier::Cool.idle_energy_mj_day() * 1_000.0);
        assert!(
            cool_2x > 0.1,
            "cool at 2/day {cool_2x}% should break the 0.1% budget, per section 4"
        );
    }

    #[test]
    fn crossover_day_is_found_when_usage_income_eventually_exceeds_reward() {
        let mc = ctx(Market::Growth);
        let mut p = sweep_grid()
            .into_iter()
            .find(|p| p.market == "growth" && p.decay_half_life_months == 6.0)
            .expect("a fast-decay growth point exists");
        p.spot_share = 1.0;
        p.standby_uptake = 1.0;
        let r = leg_result(p, mc);
        assert!(
            r.crossover_day.is_some(),
            "a fast-decaying reward against full spot+standby uptake should cross over within 1000 days"
        );
    }

    #[test]
    fn sweep_grid_is_nonempty_and_every_point_runs() {
        // Every grid point over a 30-day horizon: what this checks is that
        // each point evaluates, not what a long run concludes.
        let results = sweep(30, 1);
        assert_eq!(results.len(), sweep_grid().len());
        assert!(results.iter().all(|r| r.chain_price_usd_end > 0.0));
    }

    #[test]
    fn sweep_grid_varies_spot_share_instead_of_fixing_it_at_one_half() {
        // The grid used to hardcode spot_share: 0.5 at every point, so
        // usage income dominated the cold-tier reward from day 0
        // everywhere and crossover_day was uniformly day 1 -- the econsim
        // results doc flagged this as uninformative. The grid must now
        // actually sweep spot_share.
        let shares: std::collections::BTreeSet<_> = sweep_grid()
            .into_iter()
            .map(|p| (p.spot_share * 1000.0).round() as i64)
            .collect();
        assert!(
            shares.len() > 1,
            "sweep_grid should vary spot_share across more than one value, got {shares:?}"
        );
    }

    #[test]
    fn crossover_day_varies_with_spot_share_instead_of_always_landing_on_day_one() {
        // With spot_share swept down toward 0, usage income shrinks and the
        // reward's own decay should start to matter, so crossover_day must
        // differ across spot_share values for otherwise-identical points.
        let mc = ctx(Market::Growth);
        let base = sweep_grid()
            .into_iter()
            .find(|p| {
                p.market == "growth" && p.decay_half_life_months == 6.0 && p.spot_discount == 0.3
            })
            .expect("a matching growth point exists");

        let mut low = base;
        low.spot_share = 0.0;
        let mut high = base;
        high.spot_share = 0.5;

        let r_low = leg_result(low, mc);
        let r_high = leg_result(high, mc);
        assert_ne!(
            r_low.crossover_day, r_high.crossover_day,
            "sweeping spot_share should change crossover_day, not leave it fixed at day 1 everywhere"
        );
    }

    /// The ledger's indexed cap never pays more than its absolute cap, both
    /// start equal (the absolute cap is set at the first day's price to the
    /// index share), and they part as the TNZO price moves: in a market whose
    /// price rises the absolute cap, fixed in TNZO, is worth more than the
    /// index share, which is fixed in USD.
    #[test]
    fn the_indexed_cap_holds_the_reward_to_its_share_of_the_index() {
        let mc = ctx(Market::Growth);
        let p = sweep_grid()
            .into_iter()
            .find(|p| p.market == "growth" && p.decay_half_life_months == 24.0)
            .expect("a slow-decay growth point exists");
        // No paid demand, so the offset does not mask either cap.
        let mut days: Vec<Day> = mc.outcome.days.clone();
        for d in &mut days {
            d.unrelated_demand_usd_day = 0.0;
        }
        let absolute = ledger_reward_usd_gpu_hour(&p, &days, false);
        let indexed = ledger_reward_usd_gpu_hour(&p, &days, true);
        assert!(absolute[0] > 0.0);
        assert!((absolute[0] - indexed[0]).abs() < 1e-6 * absolute[0]);
        assert!(
            absolute
                .iter()
                .zip(&indexed)
                .all(|(a, i)| *i <= *a * (1.0 + 1e-9))
        );
        let rose = days.last().unwrap().price_usd > days[0].price_usd;
        let last = absolute.len() - 1;
        assert_eq!(rose, indexed[last] < absolute[last] * (1.0 - 1e-6));
    }

    /// The reward follows the ledger's half-life: after one half-life at a
    /// steady price it is half the starting reward.
    #[test]
    fn the_ledger_reward_halves_over_one_half_life() {
        let mc = ctx(Market::Flat);
        let mut p = sweep_grid()
            .into_iter()
            .find(|p| p.market == "flat" && p.decay_half_life_months == 12.0)
            .expect("a 12-month flat point exists");
        p.decay_half_life_months = 365.0 / 30.4375;
        let mut days: Vec<Day> = mc.outcome.days.clone();
        let price = days[0].price_usd;
        for d in &mut days {
            d.price_usd = price;
            d.unrelated_demand_usd_day = 0.0;
        }
        let r = ledger_reward_usd_gpu_hour(&p, &days, false);
        let at_365 = days.iter().position(|d| d.snap.day >= 365.0).unwrap();
        let ratio = r[at_365] / r[0];
        assert!((ratio - 0.5).abs() < 0.01, "ratio {ratio}");
    }

    /// Paid demand at the 60,000 USD/day target phases the ledger's reward
    /// to zero; half of it halves the reward.
    #[test]
    fn the_demand_offset_phases_the_reward_out_at_the_target() {
        let mc = ctx(Market::Flat);
        let p = sweep_grid()
            .into_iter()
            .find(|p| p.market == "flat" && p.decay_half_life_months == 24.0)
            .expect("a slow-decay flat point exists");
        let mut days: Vec<Day> = mc.outcome.days.clone();
        let price = days[0].price_usd;
        for (i, d) in days.iter_mut().enumerate() {
            d.price_usd = price;
            d.unrelated_demand_usd_day = [0.0, UNRELATED_USD_DAY / 2.0, UNRELATED_USD_DAY][i % 3];
        }
        let r = ledger_reward_usd_gpu_hour(&p, &days, false);
        assert!(r[0] > 0.0);
        assert!(
            (r[1] / r[0] - 0.5).abs() < 0.01,
            "half the target: {}",
            r[1] / r[0]
        );
        assert_eq!(r[2], 0.0);
    }
}
