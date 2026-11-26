//! On-chain cap: the SLA probe cadence may not spend more than a governed
//! share of the bonded compute fleet's own energy on challenges.
//!
//! # Scope, named precisely
//!
//! The operator-earnings design
//! recommends per-tier Poisson challenge rates (warm 1-8/day, cool 0.5-2/day)
//! per readiness tier. A readiness tier exists on chain as a subject's own
//! declaration ([`super::availability_reward::ReadinessTier`]) that scales
//! its availability reward; the probe cadence does not read it. A single
//! governed cadence, [`super::SLA_PROBE_INTERVAL_PARAM`], probes every
//! eligible compute bond at the same rate. This module enforces the energy
//! budget against *that* mechanism, untiered, and [`energy_report`] counts
//! the fleet by declared tier under the same tier-blind figures.
//!
//! # What is governed, what is a physical constant, and what is real chain state
//!
//! - **Governed (a policy decision)**: [`SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM`],
//!   the only lever this module adds. Genesis is disabled (0), matching this
//!   track's convention for a brand-new economic/enforcement lever
//!   (`AVAILABILITY_REWARD_REQUIRE_HARDWARE_PARAM` is the precedent) -- and for
//!   a second, load-bearing reason: at the *current* genesis
//!   `SLA_PROBE_INTERVAL_PARAM` (ten minutes, i.e. 144 probes/unit/day), this
//!   module's own math puts the challenge-energy share at roughly 9.3% of the
//!   fleet's idle energy, nowhere near the research doc's validated 0.1%
//!   figure. That figure was computed for the much sparser tiered rates
//!   section 9 recommends (1-8/day), not for this untiered liveness-style
//!   cadence. Shipping a genesis value that the network already violates
//!   would not be enforcement, it would be a lie the chain starts in. Once
//!   the probe cadence follows the declared tier and can drop to the
//!   recommended rates, governance can turn this on at whatever figure the
//!   then-current cadence actually supports.
//! - **Physical constants, not governed**: [`SLA_CHALLENGE_JOULES_PER_PROBE`]
//!   and [`SLA_FLEET_JOULES_PER_UNIT_PER_DAY`]. These are hardware facts from
//!   the research doc's section 4 table, not policy choices -- exactly the
//!   kind of value `crate::governance`'s own module doc says belongs outside
//!   [`crate::governance::GOVERNED_PARAMS`]: "a constant not in that table
//!   still needs a rebuild to change, which is the honest signal that nobody
//!   decided it should be adjustable at runtime." Both are deliberately the
//!   *worst-case* GPU figures in that table (the cool-tier reload cost and
//!   the cool-tier idle baseline, the smallest denominator and largest
//!   numerator among the GPU rows) because a bond's tier is its owner's
//!   own unverified declaration and every bond is probed at one cadence, so
//!   a single untiered estimate must not understate the energy a probe
//!   actually costs.
//! - **Real on-chain state, not a static number**: the fleet size this module
//!   multiplies both the budget and the challenge cost by is
//!   [`super::economy::compute_bonds`] filtered to
//!   [`super::economy::ComputeBond::is_eligible`] -- the same real bonded-
//!   capacity register [`super::sla_attest`-style probing][super::role_stake]
//!   already probes every round, not a parallel estimate invented here.
//!
//! # What this does not cover, named precisely
//!
//! - RPC, edge and wallet-provider role-stake SLA subjects are excluded from
//!   the fleet this module sums over. The research doc's own table puts their
//!   challenge energy at "negligible" / "under 0.001%" (CPU-millisecond
//!   checks, not a GPU wake), so folding them into a GPU-tuned joule estimate
//!   would distort the ratio in both directions without representing
//!   anything real.
//! - This is re-checked at a `ParameterChange`'s submission and again at its
//!   enactment (mirroring exactly how `security::param_change_allowed`
//!   already straddles both sites), but not a third time when the change
//!   finally activates after the tightening-grace delay
//!   (`begin_block_params`). A fleet that shrank drastically during that
//!   window could in theory let an over-budget interval activate
//!   unchecked. This is an existing shape in this codebase's parameter
//!   pipeline -- `security::param_change_allowed` has the identical gap --
//!   not a new one introduced here.
//! - The per-probe and per-unit-day joule figures stay governance-fixed
//!   constants rather than a measured quantity, because no on-chain telemetry
//!   of actual GPU power draw exists. A fuller version needs that
//!   measurement (or a verified hardware-class declaration per bond) before
//!   the energy side of the ratio can be anything but an estimate.

use super::availability_reward::{ReadinessTier, declared_readiness_tier};
use super::*;

/// Governed key: most of a basis point (1/10,000) of the bonded compute
/// fleet's own daily energy that the SLA probe cadence may spend on
/// challenges, aggregated across the whole fleet. Zero disables the check
/// entirely -- the probe cadence is unconstrained by energy, exactly as it
/// is today.
pub const SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM: &str = "reward.sla_challenge_energy_budget_bps";
/// Genesis: disabled. See the module doc for why 0 and not the research
/// doc's validated 0.1% (10 bps): at the current genesis probe interval the
/// real ratio is already roughly 9.3%, far past that figure, because that
/// figure was computed for the sparser tiered rates this chain does not
/// implement yet.
pub const DEFAULT_SLA_CHALLENGE_ENERGY_BUDGET_BPS: u64 = 0;
/// Highest share governance may set: 10% of fleet energy. Generous on
/// purpose -- this is a ceiling on a policy choice, not a claim that 10% is
/// a good operating point.
pub const MAX_SLA_CHALLENGE_ENERGY_BUDGET_BPS: u64 = 1_000;

/// Energy one SLA probe costs, joules: the cool-tier reload estimate
/// (~4 kJ), the larger of the two GPU-tier per-probe figures in that table.
/// Not governed -- see the module doc.
pub const SLA_CHALLENGE_JOULES_PER_PROBE: u128 = 4_000;

/// One bonded unit's own energy over a day, joules: the cool-tier idle
/// baseline from the same table (6.2 MJ/day), the smaller of the two GPU-tier
/// denominators. Not governed -- see the module doc.
pub const SLA_FLEET_JOULES_PER_UNIT_PER_DAY: u128 = 6_200_000;

/// Probe rounds between burst challenges of a unit declared warm. A burst
/// asks every unit of a multi-unit operator for a matrix proof, which wakes
/// the model; the hourly probe between bursts is a liveness check.
pub const WARM_BURST_ROUNDS_BETWEEN: u64 = 36;
/// Probe rounds between burst challenges of a unit declared cool, which pays
/// a model reload to answer one: a quarter as often as warm.
pub const COOL_BURST_ROUNDS_BETWEEN: u64 = WARM_BURST_ROUNDS_BETWEEN * 4;
/// Probe rounds between burst challenges of a unit declared cold, whose host
/// wakes from standby to answer one: once a week at the ten-minute interval.
pub const COLD_BURST_ROUNDS_BETWEEN: u64 = COOL_BURST_ROUNDS_BETWEEN * 7;

/// Rounds between burst challenges of a unit declared `tier`. Each is a
/// multiple of the warmer ones, so a round that bursts a colder unit bursts
/// its operator's warmer units with it.
pub fn burst_rounds_between(tier: ReadinessTier) -> u64 {
    match tier {
        ReadinessTier::Warm => WARM_BURST_ROUNDS_BETWEEN,
        ReadinessTier::Cool => COOL_BURST_ROUNDS_BETWEEN,
        ReadinessTier::Cold => COLD_BURST_ROUNDS_BETWEEN,
    }
}

/// Milliseconds in a day, the basis this module compares against (the
/// research doc's own table is per-day; [`super::MARKET_EPOCH_MS`] is one
/// hour and divides it exactly, but every figure here is computed directly
/// per day to avoid compounding rounding error across 24 epochs).
const MS_PER_DAY: u64 = 86_400_000;

/// The real, on-chain bonded compute fleet this budget is measured against:
/// every compute bond backing its provider right now. Role-stake SLA
/// subjects (RPC, edge, wallet-provider) are excluded -- see the module doc.
pub fn fleet_unit_count(state: &dyn VmState) -> u64 {
    economy::compute_bonds(state)
        .iter()
        .filter(|bond| bond.is_eligible())
        .count() as u64
}

/// Probes one unit answers per day at `probe_interval_ms`, rounded up: a
/// partial period at the end of a day still costs a full probe, so rounding
/// up never understates the energy actually spent.
fn probes_per_unit_per_day(probe_interval_ms: u64) -> u64 {
    let interval = probe_interval_ms.max(1);
    MS_PER_DAY.div_ceil(interval)
}

/// Gate of the wake-cost rule: from its epoch a scheduled probe is charged
/// [`SLA_LIVENESS_JOULES_PER_PROBE`] (it wakes no model) and a burst
/// challenge the wake cost of the unit's declared tier at that tier's burst
/// cadence, against the tier's own idle energy. Before it every scheduled
/// probe is charged the cool-tier wake figure against the cool-tier idle
/// baseline. Never at genesis.
pub const SLA_WAKE_ENERGY_KEY: &str = "feature.sla_wake_energy.activation_epoch";

/// Energy one scheduled liveness probe costs the answering unit, joules: a
/// signed reply over the network with no model work, an upper estimate.
pub const SLA_LIVENESS_JOULES_PER_PROBE: u128 = 50;

/// Energy one burst challenge costs a unit of `tier`, joules (the research
/// doc's section 4 table): a warm model computes in place (about 1 kJ), a
/// cool one reloads (4 kJ), a cold host boots (taken at 100 kJ, the middle of
/// the table's unconfirmed 50-150 kJ).
pub fn burst_joules(tier: ReadinessTier) -> u128 {
    match tier {
        ReadinessTier::Warm => 1_000,
        ReadinessTier::Cool => 4_000,
        ReadinessTier::Cold => 100_000,
    }
}

/// One unit's own energy over a day when it holds `tier`, joules (the same
/// table): warm idle with its model loaded 10.5 MJ, cool 6.2 MJ, cold host
/// standby 0.5 MJ.
pub fn idle_joules_per_day(tier: ReadinessTier) -> u128 {
    match tier {
        ReadinessTier::Warm => 10_500_000,
        ReadinessTier::Cool => SLA_FLEET_JOULES_PER_UNIT_PER_DAY,
        ReadinessTier::Cold => 500_000,
    }
}

/// Wake energy one unit of `tier` spends on burst challenges per day at
/// `probe_interval_ms`, joules, prorated over the days between bursts and
/// rounded up.
fn burst_joules_per_day(tier: ReadinessTier, probe_interval_ms: u64) -> u128 {
    let between_ms = u128::from(
        probe_interval_ms
            .max(1)
            .saturating_mul(burst_rounds_between(tier)),
    );
    (u128::from(MS_PER_DAY) * burst_joules(tier)).div_ceil(between_ms)
}

/// One unit of `tier`'s challenge energy over a day at `probe_interval_ms`,
/// joules, under the rule in force.
fn unit_challenge_joules_per_day(
    state: &dyn VmState,
    tier: ReadinessTier,
    probe_interval_ms: u64,
) -> u128 {
    let probes = u128::from(probes_per_unit_per_day(probe_interval_ms));
    if !crate::feature_gate::is_live_now(state, SLA_WAKE_ENERGY_KEY) {
        return probes * SLA_CHALLENGE_JOULES_PER_PROBE;
    }
    probes * SLA_LIVENESS_JOULES_PER_PROBE + burst_joules_per_day(tier, probe_interval_ms)
}

/// One unit of `tier`'s own energy over a day, joules, under the rule in
/// force.
fn unit_idle_joules_per_day(state: &dyn VmState, tier: ReadinessTier) -> u128 {
    if !crate::feature_gate::is_live_now(state, SLA_WAKE_ENERGY_KEY) {
        return SLA_FLEET_JOULES_PER_UNIT_PER_DAY;
    }
    idle_joules_per_day(tier)
}

/// Eligible compute bonds by the readiness tier their provider declared,
/// indexed by the tier's value (an undeclared provider counts as warm).
fn units_by_tier(state: &dyn VmState) -> [u64; 3] {
    let mut counts = [0u64; 3];
    for bond in economy::compute_bonds(state) {
        if bond.is_eligible() {
            counts[declared_readiness_tier(state, &bond.provider_did) as usize] += 1;
        }
    }
    counts
}

const TIERS: [ReadinessTier; 3] = [
    ReadinessTier::Cold,
    ReadinessTier::Cool,
    ReadinessTier::Warm,
];

/// The fleet's challenge energy and own energy over a day, joules, for the
/// tier counts `counts` at `probe_interval_ms` under the rule in force.
fn fleet_totals(state: &dyn VmState, counts: &[u64; 3], probe_interval_ms: u64) -> (u128, u128) {
    TIERS.iter().fold((0, 0), |(c, f), t| {
        let n = u128::from(counts[*t as usize]);
        (
            c + n * unit_challenge_joules_per_day(state, *t, probe_interval_ms),
            f + n * unit_idle_joules_per_day(state, *t),
        )
    })
}

/// The whole fleet's own energy over a day, joules: each declared tier's
/// eligible units times that tier's per-unit figure under the rule in force.
pub fn total_fleet_energy_joules_per_day(state: &dyn VmState) -> u128 {
    let interval = network_param(state, super::SLA_PROBE_INTERVAL_PARAM);
    fleet_totals(state, &units_by_tier(state), interval).1
}

/// The whole fleet's SLA challenge energy over a day at `probe_interval_ms`,
/// joules: each declared tier's eligible units times that tier's per-unit
/// challenge energy under the rule in force.
pub fn total_challenge_energy_joules_per_day(state: &dyn VmState, probe_interval_ms: u64) -> u128 {
    fleet_totals(state, &units_by_tier(state), probe_interval_ms).0
}

/// Whether probing the fleet at `probe_interval_ms` stays within
/// `budget_bps` of the fleet's own daily energy. `budget_bps` of zero always
/// holds -- the check is disabled. An empty fleet always holds: there is
/// nothing to probe and nothing is spent.
pub fn challenge_energy_within_budget(
    state: &dyn VmState,
    probe_interval_ms: u64,
    budget_bps: u64,
) -> bool {
    if budget_bps == 0 {
        return true;
    }
    let (challenge, fleet) = fleet_totals(state, &units_by_tier(state), probe_interval_ms);
    within_budget(challenge, fleet, budget_bps)
}

/// Whether `challenge` joules stay within `budget_bps` of `fleet` joules.
/// Zero budget is disabled; an empty fleet spends nothing.
fn within_budget(challenge: u128, fleet: u128, budget_bps: u64) -> bool {
    budget_bps == 0
        || fleet == 0
        || challenge.saturating_mul(10_000) <= fleet.saturating_mul(u128::from(budget_bps))
}

/// Refuse a `ParameterChange` of `key` to `value` that, together with
/// whatever `scheduled_of` returns for the other parameter this one is
/// bound to (its pending value if one is queued, else the value in force),
/// would spend more than the governed energy budget on SLA challenges
/// against the real bonded fleet right now. A no-op for every key but
/// [`super::SLA_PROBE_INTERVAL_PARAM`] and
/// [`SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM`].
pub fn param_change_allowed(
    state: &dyn VmState,
    key: &str,
    value: u64,
    scheduled_of: &dyn Fn(&str) -> u64,
) -> Result<()> {
    if key != super::SLA_PROBE_INTERVAL_PARAM && key != SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM {
        return Ok(());
    }
    let interval_ms = if key == super::SLA_PROBE_INTERVAL_PARAM {
        value
    } else {
        scheduled_of(super::SLA_PROBE_INTERVAL_PARAM)
    };
    let budget_bps = if key == SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM {
        value
    } else {
        scheduled_of(SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM)
    };
    if challenge_energy_within_budget(state, interval_ms, budget_bps) {
        return Ok(());
    }
    let fleet = fleet_unit_count(state);
    Err(VmError::InvalidTransaction(format!(
        "probing {fleet} bonded units every {interval_ms} ms would spend more than \
         {budget_bps} bps of the fleet's own daily energy on SLA challenges \
         ({} J/day against a {} J/day budget share)",
        total_challenge_energy_joules_per_day(state, interval_ms),
        fleet_energy_budget_joules_per_day(state, budget_bps),
    )))
}

/// `budget_bps` of the fleet's own daily energy, joules.
fn fleet_energy_budget_joules_per_day(state: &dyn VmState, budget_bps: u64) -> u128 {
    total_fleet_energy_joules_per_day(state) * u128::from(budget_bps) / 10_000
}

/// The eligible bonds that declared one readiness tier, and the energy this
/// module's figures put on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierEnergy {
    pub tier: ReadinessTier,
    /// Eligible compute bonds whose provider declared this tier (an
    /// undeclared provider counts as warm).
    pub units: u64,
    /// Probe rounds between this tier's burst challenges.
    pub burst_rounds_between: u64,
    /// Challenge energy one unit of this tier spends per day, joules.
    pub challenge_joules_per_unit_per_day: u128,
    /// One unit of this tier's own energy per day, joules.
    pub idle_joules_per_unit_per_day: u128,
    /// These units' own energy over a day, joules.
    pub fleet_joules_per_day: u128,
    /// SLA challenge energy these units spend over a day, joules.
    pub challenge_joules_per_day: u128,
}

/// What SLA challenges cost the bonded compute fleet in energy at the probe
/// cadence in force, under the figures the budget check uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnergyReport {
    /// [`super::SLA_PROBE_INTERVAL_PARAM`] in force, ms.
    pub probe_interval_ms: u64,
    /// Probes one unit answers per day at that interval.
    pub probes_per_unit_per_day: u64,
    /// Whether the wake-cost rule ([`SLA_WAKE_ENERGY_KEY`]) prices these
    /// figures; before it every probe is charged a cool-tier wake.
    pub wake_rule_live: bool,
    /// Challenge energy as a share of the fleet's own energy, basis points,
    /// rounded up; for an empty fleet, that of one warm unit.
    pub challenge_share_bps: u64,
    /// [`SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM`] in force; zero is disabled.
    pub budget_bps: u64,
    /// Whether the cadence in force holds within that budget.
    pub within_budget: bool,
    /// Eligible compute bonds.
    pub units: u64,
    /// The whole fleet's own energy over a day, joules.
    pub fleet_joules_per_day: u128,
    /// The whole fleet's challenge energy over a day, joules.
    pub challenge_joules_per_day: u128,
    /// The fleet by declared tier, cold first. The rows sum to the totals.
    pub tiers: [TierEnergy; 3],
}

/// The energy report for the fleet and parameters in `state`. Reads the
/// compute-bond register once: every count, total and the budget check come
/// from that one pass, since anyone may ask for it.
pub fn energy_report(state: &dyn VmState) -> EnergyReport {
    let probe_interval_ms = network_param(state, super::SLA_PROBE_INTERVAL_PARAM);
    let budget_bps = network_param(state, SLA_CHALLENGE_ENERGY_BUDGET_BPS_PARAM);
    let counts = units_by_tier(state);
    let tiers = TIERS.map(|tier| {
        let units = counts[tier as usize];
        let challenge = unit_challenge_joules_per_day(state, tier, probe_interval_ms);
        let idle = unit_idle_joules_per_day(state, tier);
        TierEnergy {
            tier,
            units,
            burst_rounds_between: burst_rounds_between(tier),
            challenge_joules_per_unit_per_day: challenge,
            idle_joules_per_unit_per_day: idle,
            fleet_joules_per_day: u128::from(units) * idle,
            challenge_joules_per_day: u128::from(units) * challenge,
        }
    });
    let units: u64 = counts.iter().sum();
    let fleet: u128 = tiers.iter().map(|t| t.fleet_joules_per_day).sum();
    let challenge: u128 = tiers.iter().map(|t| t.challenge_joules_per_day).sum();
    let (num, den) = if fleet == 0 {
        let warm = &tiers[ReadinessTier::Warm as usize];
        (
            warm.challenge_joules_per_unit_per_day,
            warm.idle_joules_per_unit_per_day,
        )
    } else {
        (challenge, fleet)
    };
    let share = num.saturating_mul(10_000).div_ceil(den.max(1));
    EnergyReport {
        probe_interval_ms,
        probes_per_unit_per_day: probes_per_unit_per_day(probe_interval_ms),
        wake_rule_live: crate::feature_gate::is_live_now(state, SLA_WAKE_ENERGY_KEY),
        challenge_share_bps: u64::try_from(share).unwrap_or(u64::MAX),
        budget_bps,
        within_budget: within_budget(challenge, fleet, budget_bps),
        units,
        fleet_joules_per_day: fleet,
        challenge_joules_per_day: challenge,
        tiers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    /// A cheap test fixture: `n` eligible compute bonds, written directly
    /// (bypassing the posting transaction, which this test has no interest
    /// in) and indexed in one write so `compute_bonds` finds all of them --
    /// the whole point of a fleet-scale test is posting thousands of bonds
    /// without thousands of individual transactions.
    fn fleet_of(state: &mut StateAdapter, n: u64) {
        let min = compute_bond_min(&*state);
        let amount = (min + 1).to_string();
        let mut index = Vec::with_capacity(n as usize);
        for i in 0..n {
            let did = format!("did:tenzro:machine:fleet-{i}");
            let marker = serde_json::json!({
                "provider_did": did,
                "provider_address": hex::encode([0u8; 20]),
                "amount": amount,
                "op": "Posted",
            });
            state.set_storage(
                &SYSTEM_ADDRESS,
                compute_bond_storage_key(&did).as_bytes(),
                serde_json::to_vec(&marker).unwrap(),
            );
            index.push(did);
        }
        state.set_storage(
            &SYSTEM_ADDRESS,
            b"compute_bond_index",
            serde_json::to_vec(&index).unwrap(),
        );
    }

    /// The report's tier rows sum to the totals the budget check uses, and
    /// its share is the ratio that check compares against the budget.
    #[test]
    fn the_energy_report_sums_to_the_budget_formula() {
        let mut state = StateAdapter::new();
        fleet_of(&mut state, 10);
        for (i, tier) in [
            (0, ReadinessTier::Cold),
            (1, ReadinessTier::Cool),
            (2, ReadinessTier::Cool),
        ] {
            state.set_storage(
                &SYSTEM_ADDRESS,
                format!("readiness_tier:did:tenzro:machine:fleet-{i}").as_bytes(),
                vec![tier as u8],
            );
        }
        let report = energy_report(&state);
        let interval = crate::governance::genesis_param(SLA_PROBE_INTERVAL_PARAM);
        assert_eq!(report.probe_interval_ms, interval);
        assert_eq!(report.units, fleet_unit_count(&state));
        assert_eq!(
            report.tiers.iter().map(|t| t.units).collect::<Vec<_>>(),
            vec![1, 2, 7]
        );
        assert_eq!(
            report
                .tiers
                .iter()
                .map(|t| t.fleet_joules_per_day)
                .sum::<u128>(),
            total_fleet_energy_joules_per_day(&state)
        );
        assert_eq!(
            report
                .tiers
                .iter()
                .map(|t| t.challenge_joules_per_day)
                .sum::<u128>(),
            total_challenge_energy_joules_per_day(&state, interval)
        );
        assert_eq!(
            report.fleet_joules_per_day,
            total_fleet_energy_joules_per_day(&state)
        );
        assert_eq!(
            report.challenge_joules_per_day,
            report
                .tiers
                .iter()
                .map(|t| u128::from(t.units) * t.challenge_joules_per_unit_per_day)
                .sum::<u128>()
        );
        assert!(!report.wake_rule_live);
        // 144 probes a day at 4 kJ against 6.2 MJ: 9.29%, rounded up.
        assert_eq!(report.challenge_share_bps, 930);
        assert_eq!(report.budget_bps, 0);
        assert!(report.within_budget);
        // The share is the smallest budget the cadence holds within.
        assert!(challenge_energy_within_budget(
            &state,
            interval,
            report.challenge_share_bps
        ));
        assert!(!challenge_energy_within_budget(
            &state,
            interval,
            report.challenge_share_bps - 1
        ));
    }

    /// A state that counts reads of the compute-bond register's index.
    struct CountingState {
        inner: StateAdapter,
        index_reads: std::sync::atomic::AtomicUsize,
    }

    impl VmState for CountingState {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }
        fn get_code(&self, a: &[u8]) -> Option<Vec<u8>> {
            self.inner.get_code(a)
        }
        fn set_code(&mut self, a: &[u8], c: Vec<u8>) {
            self.inner.set_code(a, c)
        }
        fn get_storage(&self, a: &[u8], k: &[u8]) -> Option<Vec<u8>> {
            if k == b"compute_bond_index" {
                self.index_reads
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            self.inner.get_storage(a, k)
        }
        fn set_storage(&mut self, a: &[u8], k: &[u8], v: Vec<u8>) {
            self.inner.set_storage(a, k, v)
        }
        fn get_balance(&self, a: &[u8]) -> u128 {
            self.inner.get_balance(a)
        }
        fn set_balance(&mut self, a: &[u8], b: u128) {
            self.inner.set_balance(a, b)
        }
        fn get_nonce(&self, a: &[u8]) -> u64 {
            self.inner.get_nonce(a)
        }
        fn set_nonce(&mut self, a: &[u8], n: u64) {
            self.inner.set_nonce(a, n)
        }
        fn exists(&self, a: &[u8]) -> bool {
            self.inner.exists(a)
        }
        fn native_total_supply(&self) -> u128 {
            self.inner.native_total_supply()
        }
        fn record_native_burn(&mut self, amount: u128) {
            self.inner.record_native_burn(amount)
        }
    }

    /// One report call walks the compute-bond register once, however many
    /// bonds it holds: the method is open to anyone.
    #[test]
    fn one_energy_report_reads_the_bond_register_once() {
        let mut inner = StateAdapter::new();
        fleet_of(&mut inner, 25);
        let state = CountingState {
            inner,
            index_reads: std::sync::atomic::AtomicUsize::new(0),
        };
        let report = energy_report(&state);
        assert_eq!(report.units, 25);
        assert_eq!(
            state.index_reads.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// From the wake-cost gate a scheduled probe costs a liveness reply and
    /// a burst the tier's wake at the tier's cadence, against the tier's own
    /// energy: at the ten-minute interval a warm unit spends 144 x 50 J plus
    /// 4 x 1 kJ a day against 10.5 MJ, a cold one 144 x 50 J plus one
    /// 100 kJ boot a week (14,286 J a day, rounded up) against 0.5 MJ.
    #[test]
    fn from_the_wake_gate_challenges_are_priced_per_tier() {
        let mut state = StateAdapter::new();
        fleet_of(&mut state, 3);
        state.set_storage(
            &SYSTEM_ADDRESS,
            b"readiness_tier:did:tenzro:machine:fleet-0",
            vec![ReadinessTier::Cold as u8],
        );
        set_genesis_param(&mut state, SLA_WAKE_ENERGY_KEY, 0);
        let r = energy_report(&state);
        assert!(r.wake_rule_live);
        let warm = &r.tiers[ReadinessTier::Warm as usize];
        let cold = &r.tiers[ReadinessTier::Cold as usize];
        assert_eq!((warm.units, cold.units), (2, 1));
        assert_eq!(warm.burst_rounds_between, 36);
        assert_eq!(warm.challenge_joules_per_unit_per_day, 144 * 50 + 4 * 1_000);
        assert_eq!(warm.idle_joules_per_unit_per_day, 10_500_000);
        assert_eq!(cold.burst_rounds_between, 1_008);
        assert_eq!(cold.challenge_joules_per_unit_per_day, 144 * 50 + 14_286);
        assert_eq!(cold.idle_joules_per_unit_per_day, 500_000);
        let challenge = 2 * (144 * 50 + 4_000) + (144 * 50 + 14_286);
        let fleet = 2 * 10_500_000 + 500_000;
        assert_eq!(r.challenge_joules_per_day, challenge);
        assert_eq!(r.fleet_joules_per_day, fleet);
        assert_eq!(
            r.challenge_share_bps,
            (challenge * 10_000).div_ceil(fleet) as u64
        );
        // About 0.2%: the 9.3% came from charging every probe a wake. A cold
        // unit's own share stays high (its idle energy is tiny), which is
        // what the per-tier rows show.
        assert!(r.challenge_share_bps < 200);
        let interval = crate::governance::genesis_param(SLA_PROBE_INTERVAL_PARAM);
        assert!(challenge_energy_within_budget(
            &state,
            interval,
            r.challenge_share_bps
        ));
        assert!(!challenge_energy_within_budget(
            &state,
            interval,
            r.challenge_share_bps - 1
        ));
    }

    #[test]
    fn the_wake_gate_is_dormant_at_genesis() {
        let gate = crate::governance::governed_param(SLA_WAKE_ENERGY_KEY).unwrap();
        assert!(crate::feature_gate::follows_convention(gate));
        assert_eq!(gate.genesis, crate::feature_gate::NEVER);
    }

    /// An empty fleet reports the per-unit figures and no energy.
    #[test]
    fn the_energy_report_of_an_empty_fleet_is_per_unit_only() {
        let report = energy_report(&StateAdapter::new());
        assert_eq!(report.units, 0);
        assert_eq!(report.fleet_joules_per_day, 0);
        assert_eq!(report.challenge_joules_per_day, 0);
        assert_eq!(report.challenge_share_bps, 930);
    }

    #[test]
    fn disabled_budget_always_holds() {
        let mut state = StateAdapter::new();
        fleet_of(&mut state, 50);
        assert!(challenge_energy_within_budget(&state, 1, 0));
    }

    #[test]
    fn empty_fleet_always_holds() {
        let state = StateAdapter::new();
        assert!(challenge_energy_within_budget(&state, 60_000, 10));
    }

    /// At the current genesis probe interval (ten minutes), the untiered
    /// challenge rate is far past the research doc's validated 0.1% figure
    /// -- the real finding behind this module's genesis-disabled default,
    /// reproduced here as a regression check so it cannot silently drift.
    #[test]
    fn the_genesis_probe_interval_fails_the_research_docs_01_percent_figure() {
        let mut state = StateAdapter::new();
        fleet_of(&mut state, 200);
        let genesis_interval = crate::governance::genesis_param(SLA_PROBE_INTERVAL_PARAM);
        assert!(!challenge_energy_within_budget(
            &state,
            genesis_interval,
            10
        ));
    }

    /// The same genesis interval holds comfortably within the generous 10%
    /// ceiling this module's own `MAX_SLA_CHALLENGE_ENERGY_BUDGET_BPS` allows.
    #[test]
    fn the_genesis_probe_interval_holds_within_the_max_allowed_budget() {
        let mut state = StateAdapter::new();
        fleet_of(&mut state, 200);
        let genesis_interval = crate::governance::genesis_param(SLA_PROBE_INTERVAL_PARAM);
        assert!(challenge_energy_within_budget(
            &state,
            genesis_interval,
            MAX_SLA_CHALLENGE_ENERGY_BUDGET_BPS
        ));
    }

    /// The ratio this module enforces is per-unit by construction: whether a
    /// given interval and budget hold does not depend on how large the real
    /// bonded fleet is. Proven here rather than assumed -- a careless
    /// implementation that multiplied one side by the fleet count and not
    /// the other would fail this test the moment the fleet size changed.
    #[test]
    fn the_cap_holds_identically_as_the_bonded_fleet_scales() {
        let interval_ms = 10 * 60 * 1000; // the genesis interval
        let tight_budget = 10; // 0.1%, fails at this interval (see above)
        let loose_budget = 1_000; // 10%, holds at this interval (see above)
        for n in [1u64, 50, 500, 5_000, 50_000] {
            let mut state = StateAdapter::new();
            fleet_of(&mut state, n);
            assert!(
                !challenge_energy_within_budget(&state, interval_ms, tight_budget),
                "fleet of {n}: a 0.1% budget should still be exceeded"
            );
            assert!(
                challenge_energy_within_budget(&state, interval_ms, loose_budget),
                "fleet of {n}: a 10% budget should still hold"
            );
        }
    }

    /// At fleet scale (tens of thousands of bonded units), the u128
    /// arithmetic does not overflow or silently wrap even at the shortest
    /// interval governance may set.
    #[test]
    fn large_fleets_do_not_overflow_the_u128_math() {
        let mut state = StateAdapter::new();
        fleet_of(&mut state, 100_000);
        let shortest_interval = crate::governance::governed_param(SLA_PROBE_INTERVAL_PARAM)
            .unwrap()
            .min;
        let challenge = total_challenge_energy_joules_per_day(&state, shortest_interval);
        let fleet = total_fleet_energy_joules_per_day(&state);
        assert!(challenge > 0);
        assert!(fleet > 0);
        assert!(!challenge_energy_within_budget(
            &state,
            shortest_interval,
            1
        ));
    }

    /// A tier-blind per-probe figure is exactly the module's intended
    /// scope: with one probe cadence for every tier, one figure applies to every
    /// bonded unit, and it is the worst-case GPU figure from the research
    /// doc's table, not the cheaper warm-tier one.
    #[test]
    fn the_per_probe_and_per_unit_figures_match_the_research_docs_worst_case_gpu_row() {
        assert_eq!(SLA_CHALLENGE_JOULES_PER_PROBE, 4_000);
        assert_eq!(SLA_FLEET_JOULES_PER_UNIT_PER_DAY, 6_200_000);
    }
}
