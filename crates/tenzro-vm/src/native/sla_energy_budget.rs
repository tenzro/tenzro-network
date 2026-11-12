//! On-chain cap: the SLA probe cadence may not spend more than a governed
//! share of the bonded compute fleet's own energy on challenges.
//!
//! # Scope, named precisely
//!
//! The operator-earnings design
//! recommends per-tier Poisson challenge rates (warm 1-8/day, cool 0.5-2/day)
//! against readiness tiers that are not built on chain yet (no `warm`/`cool`/
//! `cold` concept exists anywhere in consensus state today -- that is a
//! separate build item, not invented here). What exists on chain today is a
//! single governed cadence, [`super::SLA_PROBE_INTERVAL_PARAM`], that
//! probes every eligible compute bond at the same rate. This module
//! enforces the energy budget against *that* real mechanism, untiered,
//! rather than against a tier concept that does not exist yet.
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
//!   readiness tiers exist and the probe cadence can drop to their
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
//!   numerator among the GPU rows) because nothing on chain today
//!   distinguishes which tier a given compute bond is in, and a single
//!   untiered estimate must not understate the energy a probe actually
//!   costs.
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

/// The whole fleet's own energy over a day, joules: real on-chain fleet size
/// times the governance-fixed per-unit baseline.
pub fn total_fleet_energy_joules_per_day(state: &dyn VmState) -> u128 {
    u128::from(fleet_unit_count(state)) * SLA_FLEET_JOULES_PER_UNIT_PER_DAY
}

/// The whole fleet's SLA challenge energy over a day at `probe_interval_ms`,
/// joules: real on-chain fleet size times probes/unit/day times the
/// governance-fixed per-probe cost.
pub fn total_challenge_energy_joules_per_day(state: &dyn VmState, probe_interval_ms: u64) -> u128 {
    u128::from(fleet_unit_count(state))
        * u128::from(probes_per_unit_per_day(probe_interval_ms))
        * SLA_CHALLENGE_JOULES_PER_PROBE
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
    let fleet = total_fleet_energy_joules_per_day(state);
    if fleet == 0 {
        return true;
    }
    let challenge = total_challenge_energy_joules_per_day(state, probe_interval_ms);
    challenge.saturating_mul(10_000) <= fleet.saturating_mul(u128::from(budget_bps))
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
    /// scope: without a tier concept on chain, one figure applies to every
    /// bonded unit, and it is the worst-case GPU figure from the research
    /// doc's table, not the cheaper warm-tier one.
    #[test]
    fn the_per_probe_and_per_unit_figures_match_the_research_docs_worst_case_gpu_row() {
        assert_eq!(SLA_CHALLENGE_JOULES_PER_PROBE, 4_000);
        assert_eq!(SLA_FLEET_JOULES_PER_UNIT_PER_DAY, 6_200_000);
    }
}
