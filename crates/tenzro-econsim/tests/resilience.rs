//! S2 "source-venue manipulation" (TENZRO-ECONOMY-RESILIENCE-2026-10-25.md,
//! proves B2, T2): the real TNZO/USD fee-rate oracle
//! (`tenzro_vm::native::economy`) under a single manipulated venue, across
//! the scenario's four named arms. See `tenzro_econsim::resilience` for the
//! harness and why each arm is configured as it is.

use tenzro_econsim::resilience::{Arm, Scenario, VenueEvent, run, run_rearm};
use tenzro_vm::native::economy::DEFAULT_RATE_BREAKER_EPOCHS;

const VALIDATORS: u32 = 5;
const EVENT_START: u64 = 4;
const EVENT_EPOCHS: u64 = 48; // two days, inside the spec's 1 hour to 7 day window
const TAIL_EPOCHS: u64 = 10;
const TOTAL_EPOCHS: u64 = EVENT_START + EVENT_EPOCHS + TAIL_EPOCHS;

/// A clear crash: comfortably past the default dispersion-breaker gap
/// bound (see `dispersion_breaker_sits_exactly_on_its_gap_bound_at_the
/// _spec_s_own_x0_5_floor` for what happens at the spec's literal x0.5
/// floor instead).
const CRASH_FACTOR: f64 = 0.3;
/// The spec's own stated pump ceiling.
const PUMP_FACTOR: f64 = 3.0;

fn crash_scenario() -> Scenario {
    Scenario::new(
        VALIDATORS,
        TOTAL_EPOCHS,
        VenueEvent {
            start_epoch: EVENT_START,
            duration_epochs: EVENT_EPOCHS,
            factor: CRASH_FACTOR,
        },
    )
}

fn pump_scenario() -> Scenario {
    Scenario::new(
        VALIDATORS,
        TOTAL_EPOCHS,
        VenueEvent {
            start_epoch: EVENT_START,
            duration_epochs: EVENT_EPOCHS,
            factor: PUMP_FACTOR,
        },
    )
}

/// Today's mode 1, at the bare 2-source floor with the breaker parked
/// loose: a sustained single-venue crash walks the committed rate down
/// past any single epoch's step cap. `report_rate`'s median of exactly two
/// sources always resolves to the lower of the two, so a crashed venue's
/// quote is never outvoted by the honest one.
#[test]
fn today_mode1_lets_a_sustained_crash_walk_past_one_step_cap() {
    let scenario = crash_scenario();
    let r = run(Arm::TodayMode1, &scenario);
    let window = (
        scenario.event.start_epoch,
        scenario.event.start_epoch + scenario.event.duration_epochs,
    );
    let deviation = r.max_deviation_bps(window.0, window.1);
    assert!(
        deviation > r.step_cap_bps,
        "today's mode 1 held the crash within one step cap ({deviation} <= {}): {r:?}",
        r.step_cap_bps
    );
    let burn_error = r.burn_equivalent_error_ratio(window.0, window.1);
    assert!(
        burn_error > 0.01,
        "today's mode 1 kept the burn-equivalent error under 1% ({burn_error}): the baseline no \
         longer reproduces the known vulnerability"
    );
}

/// The complement of the finding above: the same median-of-two arithmetic
/// that lets a crash through always resolves a pump to the lower (honest)
/// quote, so a sustained pump never reaches the chain under today's mode
/// 1 -- not because anything guards against it, but as a side effect of
/// the same asymmetry that lets a crash through.
#[test]
fn today_mode1_never_lets_a_sustained_pump_reach_the_chain() {
    let scenario = pump_scenario();
    let r = run(Arm::TodayMode1, &scenario);
    let window = (
        scenario.event.start_epoch,
        scenario.event.start_epoch + scenario.event.duration_epochs,
    );
    assert_eq!(
        r.max_deviation_bps(window.0, window.1),
        0,
        "a sustained pump moved the chain rate under today's mode 1: {r:?}"
    );
}

/// `fees.usd_rate_min_sources` raised to 3, with reporters actually reading
/// a third, honest venue: a single manipulated venue is now one of three
/// quotes a report takes its own median over, so it is outvoted by the two
/// honest ones in either direction -- a crash this time, within the step
/// cap and the burn-equivalent error bound with no help from the breaker
/// (which is parked exactly as loose as in `TodayMode1` here).
#[test]
fn min_sources_alone_keeps_a_crashed_venue_within_the_step_cap() {
    let scenario = crash_scenario();
    let r = run(Arm::MinSources, &scenario);
    let window = (
        scenario.event.start_epoch,
        scenario.event.start_epoch + scenario.event.duration_epochs,
    );
    assert!(
        r.max_deviation_bps(window.0, window.1) <= r.step_cap_bps,
        "min-sources alone did not hold the crash within one step cap: {r:?}"
    );
    assert!(
        r.burn_equivalent_error_ratio(window.0, window.1) < 0.01,
        "min-sources alone did not hold the burn-equivalent error under 1%: {r:?}"
    );
}

/// The same guard against a pump: proves the fix is not merely "crashes
/// now behave like pumps did before" but genuinely outvotes one bad venue
/// in either direction.
#[test]
fn min_sources_alone_keeps_a_pumped_venue_within_the_step_cap() {
    let scenario = pump_scenario();
    let r = run(Arm::MinSources, &scenario);
    let window = (
        scenario.event.start_epoch,
        scenario.event.start_epoch + scenario.event.duration_epochs,
    );
    assert!(
        r.max_deviation_bps(window.0, window.1) <= r.step_cap_bps,
        "min-sources alone did not hold the pump within one step cap: {r:?}"
    );
    assert!(
        r.burn_equivalent_error_ratio(window.0, window.1) < 0.01,
        "min-sources alone did not hold the burn-equivalent error under 1%: {r:?}"
    );
}

/// Mode 1 at the governed defaults: the dispersion breaker's gap bound
/// (half the governance rate) is breached from the event's first epoch, so
/// every epoch of the crash is held rather than moved -- the chain rate
/// never leaves the honest rate at all, let alone by more than one step
/// cap -- and after `fees.usd_rate_breaker_epochs` consecutive breaches
/// the breaker trips and the read path falls back to the governance rate,
/// which already is where the rate sat.
#[test]
fn dispersion_breaker_keeps_a_sustained_crash_within_the_step_cap() {
    let scenario = crash_scenario();
    let r = run(Arm::DispersionBreaker, &scenario);
    let window = (
        scenario.event.start_epoch,
        scenario.event.start_epoch + scenario.event.duration_epochs,
    );
    assert!(
        r.max_deviation_bps(window.0, window.1) <= r.step_cap_bps,
        "the dispersion breaker did not hold the crash within one step cap: {r:?}"
    );
    assert!(
        r.burn_equivalent_error_ratio(window.0, window.1) < 0.01,
        "the dispersion breaker did not hold the burn-equivalent error under 1%: {r:?}"
    );
}

/// The fallback triggers within `fees.usd_rate_breaker_epochs` (the
/// governed `N` the spec's "fallback triggers within N epochs" names,
/// read here from its own genesis default rather than invented): the
/// breach starts the event's first epoch, so the trip lands before the
/// event's `N`th epoch ends.
#[test]
fn dispersion_breaker_fallback_triggers_within_the_governed_epoch_count() {
    let scenario = crash_scenario();
    let r = run(Arm::DispersionBreaker, &scenario);
    let tripped = r
        .tripped_epoch
        .expect("a sustained crash this far past the gap bound trips the breaker");
    assert!(
        tripped < scenario.event.start_epoch + DEFAULT_RATE_BREAKER_EPOCHS,
        "the breaker tripped at epoch {tripped}, more than {DEFAULT_RATE_BREAKER_EPOCHS} epochs \
         into the event that started at {}",
        scenario.event.start_epoch
    );
}

/// A real edge case the governed defaults leave open, found by running the
/// mechanism rather than by inspection: `fees.usd_rate_breaker_gap_bps`'s
/// genesis value (5,000 bps, half the governance rate) is a bound compared
/// with strict inequality (`far_from_governed` in
/// `tenzro-vm/src/native/economy.rs`), so a venue crashed to exactly the
/// spec's own x0.5 floor sits precisely on the bound rather than past it
/// and never breaches -- the breaker does not engage, and the chain rate
/// walks down exactly as it does under `TodayMode1`. A crash past x0.5
/// (this module's `CRASH_FACTOR`, and anything else strictly below half)
/// breaches as expected. Recorded here rather than worked around: closing
/// it would mean tightening a governed default, which is governance's
/// call, not a step cap this scenario invents on its own.
#[test]
fn dispersion_breaker_sits_exactly_on_its_gap_bound_at_the_spec_s_own_x0_5_floor() {
    let scenario = Scenario::new(
        VALIDATORS,
        TOTAL_EPOCHS,
        VenueEvent {
            start_epoch: EVENT_START,
            duration_epochs: EVENT_EPOCHS,
            factor: 0.5,
        },
    );
    let r = run(Arm::DispersionBreaker, &scenario);
    assert_eq!(
        r.tripped_epoch, None,
        "a crash to exactly x0.5 tripped the breaker after all: {r:?}"
    );
    let window = (
        scenario.event.start_epoch,
        scenario.event.start_epoch + scenario.event.duration_epochs,
    );
    assert!(
        r.max_deviation_bps(window.0, window.1) > r.step_cap_bps,
        "a crash to exactly x0.5 stayed within one step cap without the breaker tripping: {r:?}"
    );
}

/// Mode 0: the governance rate is not a report away from anything a venue
/// says, so neither a crash nor a pump moves it at all. Reports are still
/// tallied and the dispersion breaker still keeps its own count in the
/// background regardless of `fees.usd_rate_mode` (`tally_rates` does not
/// branch on it), so it can still trip here -- that bookkeeping only
/// matters once `validator_rate_in_force` reads it, which it never does
/// at mode 0, so a trip (or none) changes nothing this arm reads.
#[test]
fn governance_only_mode0_ignores_the_manipulated_venue_in_either_direction() {
    for scenario in [crash_scenario(), pump_scenario()] {
        let r = run(Arm::GovernanceOnly, &scenario);
        let window = (
            scenario.event.start_epoch,
            scenario.event.start_epoch + scenario.event.duration_epochs,
        );
        assert_eq!(
            r.max_deviation_bps(window.0, window.1),
            0,
            "mode 0 moved away from the governance rate: {r:?}"
        );
    }
}

/// The breaker re-arms only by governance: it does not clear itself after
/// any number of clean epochs, and clears only once a real
/// `fees.usd_rate_mode = 1` proposal is filed, voted, past its timelock
/// and enacted -- not merely filed or merely passed. `rearm_rate_breaker`
/// (`tenzro-vm/src/native/mod.rs`) runs nowhere outside that enactment.
#[test]
fn the_breaker_re_arms_only_once_governance_enacts_mode_one_again() {
    let scenario = Scenario::new(
        VALIDATORS,
        EVENT_START + EVENT_EPOCHS,
        VenueEvent {
            start_epoch: EVENT_START,
            duration_epochs: EVENT_EPOCHS,
            factor: CRASH_FACTOR,
        },
    );
    // Long enough that every reporter's genesis bond clears
    // `governance.min_bond_age_ms` (7 days of hourly epochs = 168) well
    // before it votes.
    let quiet_epochs = 160;
    let r = run_rearm(&scenario, quiet_epochs);
    assert!(
        r.tripped_after_event,
        "the crash never tripped the breaker: {r:?}"
    );
    assert!(
        r.still_tripped_after_quiet_epochs,
        "the breaker cleared itself after clean epochs with no governance action: {r:?}"
    );
    assert!(
        r.cleared_after_governance,
        "the breaker did not clear once fees.usd_rate_mode = 1 was enacted: {r:?}"
    );
}
