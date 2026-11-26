//! Adversarial scenarios cut from recent exploits, run against the chain's
//! own rules. Each test names the attack shape and the incident class it
//! comes from, and asserts the invariant that must hold under it. No
//! threshold is set here: caps, delays and limits are the governed
//! parameters the simulated chain carries, read back where an assertion
//! needs them.
//!
//! Scenarios that live in the crate that owns the rule, and are listed in
//! the threat model beside these:
//! - a run of pre-signed EIP-7702 authorizations over consecutive nonces
//!   (tenzro-vm tests/eip7702_sweep_guard.rs);
//! - the standing-permission thief (a script or a steered agent holding a
//!   delegation) is covered below by the agent-terms scenarios.
//!
//! The validator-floor schedule is the economy lane's work; assertions here
//! name the invariants the attack bears on and never read the floor.

use std::sync::Arc;

use tenzro_econsim::attack::Adversary;
use tenzro_econsim::chaos::{self, Event, Kind, Plan, Settings};
use tenzro_econsim::economy::{Economy, MAX_SUPPLY_TNZO, Market, RunConfig};
use tenzro_types::agent_terms::{
    ActionHistory, AgentAction, AgentTerms, HOUR_MS, ServingNode, TermsScope, check_action,
};

const YEARS: f64 = 0.25;
const DAY_MS: u64 = 24 * HOUR_MS;

/// Invariants an attack on value, supply or the rate must never break,
/// whatever the economy's other state.
const ATTACK_INVARIANTS: [&str; 4] = [
    "value_conservation",
    "supply_bounds",
    "treasury_insurance_solvency",
    "fee_rate_stability",
];

fn chaos_run(seed: u64, events: Vec<Event>) -> chaos::SeedResult {
    let s = Settings::new(YEARS);
    let mut c = s.base.clone();
    c.seed = seed;
    c.days = s.days;
    c.chaos = Some(Arc::new(Plan {
        days: s.days,
        events,
    }));
    chaos::run_config(c, &s.limits)
}

fn event(kind: Kind, day: u32, days: u32, size: f64, factor: f64) -> Event {
    Event {
        kind,
        day,
        days,
        size,
        factor,
        tail_days: 0,
        amount: 0.0,
        joint: false,
    }
}

/// The attack must not break any invariant the same seed keeps without it.
/// An invariant the seed already breaks with no event is the economy's own
/// state (reported to the economy lane), not something the attack did.
fn assert_attack_invariants(seed: u64, events: Vec<Event>) -> chaos::SeedResult {
    let base = chaos_run(seed, Vec::new());
    let r = chaos_run(seed, events);
    for name in ATTACK_INVARIANTS {
        let n = name.to_string();
        assert!(
            !r.broken.contains(&n) || base.broken.contains(&n),
            "{name} broken by the attack (baseline {:?}): {r:?}",
            base.broken
        );
    }
    assert_eq!(r.conservation_breaks, 0, "{r:?}");
    // Fixed supply: nothing minted past the cap, ever.
    assert!(
        r.supply_max_tnzo <= MAX_SUPPLY_TNZO,
        "supply reached {} past the cap",
        r.supply_max_tnzo
    );
    r
}

fn run_with(
    adv: Adversary,
    days: u32,
    rate_reports: bool,
) -> tenzro_econsim::attack::AttackOutcome {
    let mut c = RunConfig::scenario(Market::Flat, 11, days);
    c.rate_reports = rate_reports;
    c.assumptions.buyer_price_elasticity = 4.0;
    c.adversary = Some(adv);
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    out.adversary.expect("adversary outcome")
}

// (3) and (5): a compromised signing path or a forged bridge message across
// several assets at once. The loss is whatever the bridge's per-epoch
// outflow and mint caps admit, nothing is minted past the fixed supply and
// the ledger stays conserved.
#[test]
fn a_bridge_drain_up_to_the_whole_attack_window_keeps_supply_and_value() {
    let r = assert_attack_invariants(21, vec![event(Kind::BridgeLoss, 5, 1, 1.0, 1.0)]);
    assert!(
        r.shocks.get("bridge_loss").copied().unwrap_or(0) >= 1,
        "{r:?}"
    );
}

// (4) governance takeover: an accumulating holder pushes a treasury grant to
// itself while the rest turn out thinly.
#[test]
fn an_accumulating_holder_cannot_move_the_treasury_to_itself() {
    assert_attack_invariants(22, vec![event(Kind::GovernanceCapture, 3, 20, 0.34, 0.4)]);
}

#[test]
fn a_capture_by_a_stake_share_does_not_profit() {
    let o = run_with(
        Adversary::GovernanceCapture {
            start_day: 2,
            attackers: 0,
            honest_turnout: 0.5,
            grant_tnzo: 1_000_000.0,
            stake_share: 0.34,
        },
        8,
        false,
    );
    assert!(
        !o.succeeded && o.profit_tnzo <= 0.0,
        "capture paid {} TNZO: {:?}",
        o.profit_tnzo,
        o.detail
    );
}

// (S9) patient capture of a safety bound: an accumulator reaches 20-45% of
// stake over the first year (set here at the band's midpoint, 30%) at low
// honest turnout, then proposes loosening a single governed safety bound
// by one salami-thin step (fees.usd_rate_max_change_bps, genesis 100 bps,
// raised by 1 bps) rather than a grant. B8 blocks it regardless of how
// small the step is or how quiet the opposition: a loosening proposal
// needs yes votes of governance.large_spend_approval_bps (genesis 7,500,
// 75%) of ALL eligible stake, not of whoever turns out. 30% comfortably
// clears the ordinary quorum (33.34% is met by the attacker's own stake
// alone being just under it -- see the 40%-stake companion test below for
// a share that clears quorum on its own) and threshold on size alone, so
// the only thing that can still block it is B8's own guard.
const SAFETY_BOUND_KEY: &str = "fees.usd_rate_max_change_bps";
const SAFETY_BOUND_GENESIS: u64 = 100;

#[test]
fn patient_capture_below_three_quarters_of_stake_cannot_loosen_a_safety_bound() {
    // 40% of stake clears the ordinary 33.34% quorum and 66.67% threshold
    // on its own (honest turnout is low and votes no, so participation is
    // effectively just the attacker's own stake, all of it yes) -- so
    // without B8 this proposal would pass by the chain's ordinary rules.
    // With B8 it must still be rejected, because 40% is well under the
    // 75% of all eligible stake a loosening change needs.
    let o = run_with(
        Adversary::SafetyBoundCapture {
            start_day: 365,
            honest_turnout: 0.05,
            stake_share: 0.40,
            key: SAFETY_BOUND_KEY.into(),
            value: SAFETY_BOUND_GENESIS + 1,
        },
        400,
        false,
    );
    // By day 365 of this default scenario, the validator population has
    // already consolidated to two equally-bonded survivors (this scenario's
    // own validator-floor dynamic, documented separately and not examined
    // here -- see the stake_share=0.40 input above): the lowest-id bonded
    // validator alone already holds about half of what remains bonded, so
    // the actual attacker share this run achieves is near 50%, reported in
    // o.detail["attacker_stake_share"]. That is still well under 75%, so
    // the assertion below holds regardless of the exact figure.
    assert!(
        !o.succeeded,
        "a loosening proposal under 75% of eligible stake must not succeed under B8: {:?}",
        o.detail
    );
    assert_eq!(
        o.detail.get("final_param").copied(),
        Some(SAFETY_BOUND_GENESIS as f64),
        "the bound must stay at genesis, not move to the proposed value: {:?}",
        o.detail
    );
}

#[test]
fn patient_capture_tightening_the_same_bound_passes_at_the_standard_threshold() {
    // Identical attacker and identical low honest turnout, but TIGHTENING
    // the same bound (lowering it by 1 bps) instead of loosening it. B8
    // only guards loosening; tightening needs just the track's ordinary
    // quorum and threshold, which the attacker's own stake share (near 50%
    // in this scenario by day 365 -- see the companion test above) already
    // clears on its own, so this passes with no extra bar.
    let o = run_with(
        Adversary::SafetyBoundCapture {
            start_day: 365,
            honest_turnout: 0.05,
            stake_share: 0.40,
            key: SAFETY_BOUND_KEY.into(),
            value: SAFETY_BOUND_GENESIS - 1,
        },
        400,
        false,
    );
    assert!(
        o.succeeded,
        "a tightening change at the standard threshold should pass: {:?}",
        o.detail
    );
    assert_eq!(
        o.detail.get("final_param").copied(),
        Some((SAFETY_BOUND_GENESIS - 1) as f64),
        "the bound must move to the tightened value: {:?}",
        o.detail
    );
}

#[test]
fn patient_capture_at_three_quarters_of_stake_can_loosen_a_safety_bound() {
    // The control for B8's own bar: a loosening backed by at least 75% of
    // eligible stake does pass -- B8 is a real bar at 75%, not an absolute
    // veto on ever loosening a guard. Asking for 0.75 of eligible stake in
    // this scenario (only two validators remain bonded by day 365, as
    // above) pulls in both of them, i.e. all remaining stake (100%); the
    // point stands at well above 75%, not exactly at the boundary.
    // Loosening a capture guard also carries its own advance-notice delay
    // once it passes a vote (governance.guard_loosening_grace_epochs,
    // genesis 2,160 epochs -- this scenario's epochs run about one per
    // simulated day, so roughly six years): real, intentional notice,
    // separate from the vote-threshold question this test is about. A
    // 400-day run cannot observe it land at the real default, so the
    // notice period is fast-forwarded to exercise the propose -> vote ->
    // schedule -> grace -> activate pipeline deterministically; the real
    // governed default is untouched.
    let mut c = RunConfig::scenario(Market::Flat, 11, 400);
    c.assumptions.buyer_price_elasticity = 4.0;
    c.network_params
        .insert("governance.guard_loosening_grace_epochs".into(), 1);
    c.adversary = Some(Adversary::SafetyBoundCapture {
        start_day: 365,
        honest_turnout: 0.0,
        stake_share: 0.75,
        key: SAFETY_BOUND_KEY.into(),
        value: SAFETY_BOUND_GENESIS + 1,
    });
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    let o = out.adversary.expect("adversary outcome");
    assert!(
        o.succeeded,
        "a loosening proposal backed by 75% of eligible stake should pass \
         once its own notice period elapses: {:?}",
        o.detail
    );
    assert_eq!(
        o.detail.get("final_param").copied(),
        Some((SAFETY_BOUND_GENESIS + 1) as f64),
        "the bound must move to the loosened value once 75% backs it: {:?}",
        o.detail
    );
}

// (4) treasury drain by a flood of proposals timed across the outflow
// period boundary: what is paid in any period never passes the governed
// period cap (3 percent unless governance set another).
#[test]
fn a_proposal_flood_across_the_period_boundary_never_passes_the_period_cap() {
    let o = run_with(
        Adversary::SalamiGrants {
            open_day: 1,
            attackers: 10,
            grants: 40,
            grant_tnzo: 1_000_000.0,
            enact_day: 5.0,
            second_enact_day: 5.5,
        },
        10,
        false,
    );
    let worst = o
        .detail
        .get("worst_period_paid_over_cap")
        .copied()
        .unwrap_or(0.0);
    assert!(
        worst <= 1.0 + 1e-9,
        "a period paid {worst} times its cap: {o:?}"
    );
}

// (6) price manipulation of fee pricing: a venue quote pushed off for every
// reporter, and a validator cartel skewing the rate inside the band.
#[test]
fn a_manipulated_venue_quote_and_a_rate_cartel_do_not_break_fee_stability() {
    assert_attack_invariants(
        23,
        vec![
            event(Kind::VenueManipulation, 4, 10, 0.5, 2.0),
            event(Kind::RateCartel, 20, 20, 0.34, 1.5),
        ],
    );
}

#[test]
fn a_rate_skew_inside_the_band_is_measured_against_the_honest_run() {
    let spec = Adversary::OracleSkew {
        start_day: 1,
        run_days: 4,
        cartel: 10,
        skew_bps: -900,
    };
    let base = run_with(spec.baseline().expect("paired"), 6, true);
    let mut o = run_with(spec, 6, true);
    tenzro_econsim::attack::pair(&mut o, &base);
    assert!(o.profit_tnzo.is_finite());
    let dev = o.detail.get("rate_max_deviation").copied().unwrap_or(0.0);
    assert!(dev <= 0.5, "the chain rate left the market by {dev}");
}

// (6) commit-reveal manipulation of the rate oracle: a cartel seals a rate
// walked below the rate in force every epoch but opens it only when doing so
// still serves the walk, withholding (and forfeiting) the rest.
#[test]
fn reveal_withholding_moves_the_rate_no_further_and_costs_more_than_reporting_honestly() {
    let spec = Adversary::RevealWithhold {
        start_day: 1,
        run_days: 5,
        cartel: 5,
        step_bps: 300,
    };
    let base = run_with(spec.baseline().expect("paired"), 8, true);
    let mut o = run_with(spec, 8, true);
    tenzro_econsim::attack::pair(&mut o, &base);

    // The scenario's own range: 5-33% of stake.
    let share = o.detail.get("cartel_stake_share").copied().unwrap_or(0.0);
    assert!(
        (0.05..=0.33).contains(&share),
        "the coalition held {share} of stake, outside the scenario's 5-33% range"
    );

    // Pass (a): the rate moves no further than the same run with nobody
    // withholding.
    let dev = o.detail.get("rate_max_deviation").copied().unwrap_or(0.0);
    let base_dev = base
        .detail
        .get("rate_max_deviation")
        .copied()
        .unwrap_or(0.0);
    assert!(
        dev <= base_dev + 1e-9,
        "withholding moved the rate further ({dev}) than the no-withholder baseline ({base_dev})"
    );

    // Pass (b): the withholders' outcome (their bond, net of the
    // unopened-report forfeit) is worse than the honest reporters'.
    let cartel_avg = o.detail.get("cartel_avg_gain_tnzo").copied().unwrap_or(0.0);
    let honest_avg = o.detail.get("honest_avg_gain_tnzo").copied().unwrap_or(0.0);
    assert!(
        cartel_avg < honest_avg,
        "withholders ({cartel_avg} TNZO) did not end up worse off than honest reporters ({honest_avg} TNZO): {o:?}"
    );
}

// (7) validator collusion: a cartel declares an honest provider down to
// collect insurance; a wave of validators leaves at once.
#[test]
fn a_false_down_cartel_does_not_collect() {
    let o = run_with(
        Adversary::CartelFalseDown {
            start_day: 1,
            run_days: 4,
            cartel: 6,
            honest_attest: 0.9,
            streams_per_hour: 2,
            rate_tnzo: 5.0,
        },
        6,
        false,
    );
    assert!(!o.succeeded, "the cartel gained {}: {o:?}", o.profit_tnzo);
}

#[test]
fn a_validator_exit_wave_keeps_value_and_supply() {
    assert_attack_invariants(24, vec![event(Kind::ValidatorExit, 5, 3, 0.6, 1.0)]);
}

// (8) front-running of paid work and fee-payer abuse: a party that is both
// renter and provider, and a ring of roots paying one another for the
// rewards, earn nothing from the loop.
#[test]
fn self_dealing_and_wash_rings_earn_nothing() {
    let o = run_with(
        Adversary::SelfDealingSla {
            start_day: 1,
            run_days: 4,
            streams_per_hour: 2,
            rate_tnzo: 5.0,
            stream_hours: 4,
            bond_tnzo: 100.0,
        },
        6,
        false,
    );
    assert!(!o.succeeded, "self-dealing paid {}: {o:?}", o.profit_tnzo);
    let o = run_with(
        Adversary::WashRing {
            start_day: 1,
            run_days: 3,
            ring: 3,
            plans_per_hour: 2,
            value_tnzo: 2_000.0,
            report_work: true,
        },
        6,
        false,
    );
    assert!(
        o.profit_tnzo <= 0.0 && !o.succeeded,
        "wash ring gained {}: {o:?}",
        o.profit_tnzo
    );
}

// (1), (10), and the steered agent: a standing permission held by a script
// or an agent that hidden instructions steer. Every action the agent sends
// goes through the delegation's own caps; the sum of what passes never
// exceeds the governed day and hour caps, a first-time recipient and a large
// transfer need the controller's step-up, and a tainted action needs one for
// any value to a new counterparty.
mod standing_permission {
    use super::*;

    const MACHINE: &str = "did:tenzro:machine:m";
    const PER_TX: u128 = 1_000;
    const HOURLY: u128 = 2_500;
    const DAILY: u128 = 9_000;
    const STEP_UP: u128 = 400;

    fn terms() -> AgentTerms {
        AgentTerms {
            controller_did: "did:tenzro:human:abc".into(),
            agent_name: "buyer".into(),
            delegation_scope: TermsScope {
                allowed_operations: vec!["transfer".into()],
                max_transaction_value: Some(PER_TX.to_string()),
                max_hourly_spend: Some(HOURLY.to_string()),
                max_daily_spend: Some(DAILY.to_string()),
                step_up_above: Some(STEP_UP.to_string()),
                step_up_new_counterparty: true,
                tainted_value_limit: Some("0".into()),
                ..Default::default()
            },
            capabilities: vec![],
            serving_nodes: vec![ServingNode {
                machine_did: MACHINE.into(),
                operator_did: "did:tenzro:human:op".into(),
                ..Default::default()
            }],
            min_distinct_operators: 1,
            expires_at_ms: None,
            trifecta_exception: false,
            auto_approve: None,
            credentials: Vec::new(),
        }
    }

    fn action(amount: u128, counterparty: &str, tainted: bool) -> AgentAction {
        AgentAction {
            asset: None,
            usd_e6: 0,
            payment: None,
            agent_did: "a".into(),
            machine_did: MACHINE.into(),
            operation: "transfer".into(),
            counterparty: counterparty.into(),
            amount,
            chain: "tenzro".into(),
            payment_protocol: None,
            model: None,
            calls: Vec::new(),
            escrow: None,
            remote_grant: None,
            ballot: None,
            veto_signal: None,
            nonce: 0,
            tainted,
            step_up: None,
        }
    }

    #[test]
    fn a_steered_agent_sweeping_to_fresh_recipients_passes_nothing_without_the_controller() {
        let t = terms();
        let mut passed = 0u128;
        for i in 0..2_000u64 {
            // Every recipient is new, every action is small and tainted by
            // the hidden instruction that produced it.
            let cp = format!("{:064x}", i + 1);
            let a = action(1 + (i as u128 % 50), &cp, true);
            let h = ActionHistory {
                known_counterparty: false,
                ..Default::default()
            };
            if check_action(&t, &a, &h, false, 19_000 * DAY_MS + i * 1_000).is_ok() {
                passed += a.amount;
            }
        }
        assert_eq!(passed, 0, "{passed} left without a controller step-up");
    }

    #[test]
    fn what_passes_in_a_day_never_exceeds_the_day_cap_even_with_every_step_up() {
        let t = terms();
        let cp = "00".repeat(32);
        let mut h = ActionHistory {
            known_counterparty: true,
            ..Default::default()
        };
        let mut passed = 0u128;
        for i in 0..5_000u64 {
            // The controller approves everything: the caps still bind.
            let a = action(1_000, &cp, false);
            let now = 19_000 * DAY_MS + (i % 20) * 60_000;
            if check_action(&t, &a, &h, true, now).is_ok() {
                passed += a.amount;
                h.spent_today += a.amount;
                h.spent_this_hour += a.amount;
                h.actions_today += 1;
                h.actions_this_hour += 1;
            }
        }
        assert!(
            passed <= DAILY,
            "{passed} passed against a day cap of {DAILY}"
        );
        assert!(passed > 0);
    }

    #[test]
    fn one_large_transfer_to_a_known_recipient_needs_a_step_up() {
        let t = terms();
        let cp = "00".repeat(32);
        let h = ActionHistory {
            known_counterparty: true,
            ..Default::default()
        };
        let a = action(STEP_UP + 1, &cp, false);
        assert!(check_action(&t, &a, &h, false, 0).is_err());
        assert!(check_action(&t, &a, &h, true, 0).is_ok());
        // Past the per-transaction cap, even the controller's approval of
        // this one action does not lift it.
        let a = action(PER_TX + 1, &cp, false);
        assert!(check_action(&t, &a, &h, true, 0).is_err());
    }
}

// S6 (TENZRO-ECONOMY-RESILIENCE-2026-10-25.md, proves B5; T14, T15):
// treasury, reserve and insurance under crash. Three stresses, each a
// separate scenario per the spec's own wording ("TNZO -90% in 3 days with
// claims tripled for 60 days; zero fee revenue for 2 years (design 10.4);
// single-issuer permanent failure at its maximum exposure"), each driven
// through the real `Economy`/`chaos` machinery, nothing invented: the grant
// floor is `treasury_reserve::check_grant_floor` (already gates `Grant` and
// tranche-release enactment); the safety rate is `economy::safety_rate`
// (already what `insurance::claim_cap` values the pool at); coverage
// publication is `insurance::publish_coverage`, called from the chain's own
// reward epoch close; the single issuer is the one settlement asset this
// simulation registers, and its permanent failure is the existing
// `chaos::Kind::StableFailure` shock at `size: 0.0` with no recovery.
mod s6_treasury_reserve_and_insurance_under_crash {
    use super::*;

    // (B5c/T15) A claim's evidence (a bridge reconciliation mismatch) is not
    // modelled in tenzro-econsim at all -- confirmed by reading
    // tenzro-vm/src/native/insurance.rs and payment_settlement/recon.rs:
    // `InsuranceEvidence` has exactly one variant, `ReconMismatch`, provable
    // only from a reconciled bridge settlement lock, and no bridge route
    // exists anywhere in this crate. So no `PayInsuranceClaim` transaction
    // can be submitted here; this is a real, confirmed gap (T18 territory),
    // not something this item invents a shortcut around. What is tested
    // instead is the exact governed valuation the chain would apply to a
    // real claim -- `insurance::claim_cap`, `insurance::payable`,
    // `insurance::coverage` -- read against the live, crashing chain state.
    #[test]
    fn claims_through_a_ninety_percent_crash_stay_capped_at_the_safety_rate_and_within_the_pool() {
        let baseline_days = 20u32;
        let crash_day = 30u32;
        let claim_window_days = 60u32;
        let total_days = crash_day + claim_window_days + 10;
        let mut c = RunConfig::scenario(Market::Flat, 31, total_days);
        c.rate_reports = true;
        c.assumptions.insurance_genesis_tnzo = 20_000.0;
        c.chaos = Some(Arc::new(Plan {
            days: total_days,
            events: vec![event(Kind::PriceCrash, crash_day, 3, 0.9, 0.0)],
        }));
        c.adversary = Some(Adversary::InsuranceUnderCrash {
            baseline_days,
            crash_day,
            claim_window_days,
            // Well past the pool and its cap, so every sample exercises the
            // ceiling for real.
            loss_tnzo: 50_000.0,
        });
        let out = Economy::new(c).run();
        assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
        let a = out.adversary.expect("adversary outcome");

        // The scenario actually ran long enough to sample the whole window.
        assert!(
            a.detail.get("window_evals").copied().unwrap_or(0.0)
                >= (claim_window_days * 3 - 3) as f64,
            "{:?}",
            a.detail
        );

        let baseline_sr = a
            .detail
            .get("baseline_safety_rate_nano_usd")
            .copied()
            .expect("baseline sampled before the crash");
        let baseline_ratio_bps = a
            .detail
            .get("baseline_ratio_bps")
            .copied()
            .expect("baseline sampled before the crash");
        let window_sr_min = a
            .detail
            .get("window_safety_rate_min_nano_usd")
            .copied()
            .expect("window sampled after the crash");
        let window_ratio_bps_min = a
            .detail
            .get("window_ratio_bps_min")
            .copied()
            .expect("window sampled after the crash");
        let window_safety_over_force_min = a
            .detail
            .get("window_safety_over_force_min")
            .copied()
            .expect("window sampled after the crash");

        // The safety rate itself reflects the crash: it is the lowest
        // frozen median over its window, so it drops at once rather than
        // following the chain's own rate (which only moves at most
        // `fees.usd_rate_max_fall_bps` an epoch).
        assert!(
            window_sr_min < baseline_sr * 0.5,
            "the safety rate did not reflect the crash: baseline {baseline_sr}, window min {window_sr_min}"
        );

        // Claims capped at the safety rate, not at the chain's own rate in
        // force: real finding from running this, not assumed -- a claim cap
        // read back in whole TNZO does not fall with the crash on its own,
        // because `claim_cap` first values the pool at the safety rate (a
        // USD figure) and then converts that same figure back into TNZO
        // through the rate in force; once the rate in force has stepped
        // down to meet it, the two cancel and the TNZO-denominated cap
        // returns to roughly its pre-crash level. What the safety rate
        // actually protects is the pool's own published USD valuation,
        // which only ever reads the safety rate and has no such
        // cancellation.
        assert!(
            window_ratio_bps_min < baseline_ratio_bps * 0.5,
            "the pool's published USD coverage did not collapse with the crash: baseline {baseline_ratio_bps} bps, window min {window_ratio_bps_min} bps"
        );
        // A second real finding, also from running this rather than
        // assuming it: `safety_rate` is the *minimum* of the rate in force
        // and the window's recent medians, so during a sustained,
        // one-directional fall the two never actually diverge -- the rate
        // in force's own latest accepted value is already the window's
        // lowest point, by construction of the fold. The "lowest frozen
        // median" window instead guards a *recovering* price (a rate in
        // force rising back up faster than the market's low point should
        // be trusted), not an ongoing crash; this scenario only exercises
        // the crash leg, so no divergence is expected here. What the
        // formula does guarantee unconditionally -- and what is asserted --
        // is that the safety rate is never a more generous valuation than
        // the rate in force.
        assert!(
            window_safety_over_force_min <= 1.0 + 1e-9,
            "safety_rate exceeded the rate in force, which the formula (a min over it) forbids: {window_safety_over_force_min}"
        );

        // No insurance payment exceeds the pool, at any sampled point,
        // including every one of the tripled claims that demanded far more
        // than the pool holds.
        assert_eq!(
            a.detail.get("pool_exceeded_count").copied().unwrap_or(0.0),
            0.0,
            "payable() exceeded the pool's balance at least once: {:?}",
            a.detail
        );

        // Coverage ratio published each epoch: the live-read epoch never
        // went backwards and advanced through the whole sampled span (one
        // epoch a simulated day).
        assert_eq!(
            a.detail.get("coverage_epoch_regressed").copied(),
            None,
            "{:?}",
            a.detail
        );
        let epoch_first = a
            .detail
            .get("coverage_epoch_first")
            .copied()
            .expect("sampled");
        let epoch_last = a
            .detail
            .get("coverage_epoch_last")
            .copied()
            .expect("sampled");
        assert!(
            epoch_last - epoch_first >= (baseline_days + claim_window_days) as f64 - 2.0,
            "coverage epoch did not advance through the run: first {epoch_first}, last {epoch_last}"
        );
    }

    // (B5a/T14, design 10.4) Zero TNZO fee revenue for two years: every
    // payment settles in the stable token with the treasury leg also taken
    // in it (`stable_leg`), so no TNZO changes hands at payment time
    // (tenzro-vm's `record_fee` `Collect::InKind` path; confirmed by direct
    // read). `RESERVE_SEED_TNZO` in chaos.rs documents, in its own words,
    // that with fees settled in a stable asset "the reserve is not filled
    // from fee revenue, and the chain holds every discretionary treasury
    // payment ... while the reserve is under half its target" -- this test
    // removes that seed on purpose, to exercise exactly the floor it
    // otherwise keeps clear of.
    #[test]
    fn two_years_of_zero_tnzo_fee_revenue_refuses_a_grant_under_the_floor_while_running_costs_keep_paying_from_the_stable_leg()
     {
        let mut s = Settings::new(2.2).without_sponsorship();
        s.shocks = chaos::Shocks::calm();
        s.base.assumptions.stable_leg = true;
        s.base.assumptions.reserve_seed_tnzo = 0.0;
        let mut cfg = s.config(1);
        // A plain, fully supported grant: every bonded validator's stake
        // votes for it, nobody against, well under the large-spend
        // threshold -- so the only thing that can block it is the reserve
        // floor, not quorum or the 75%-of-eligible large-spend rule.
        cfg.adversary = Some(Adversary::GovernanceCapture {
            start_day: 400,
            attackers: 0,
            honest_turnout: 0.0,
            grant_tnzo: 5_000.0,
            stake_share: 1.0,
        });
        let out = Economy::new(cfg).run();
        assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);

        // Grants refused while the reserve is under the floor.
        assert!(
            out.refusals
                .keys()
                .any(|k| k.contains("running-cost reserve") && k.contains("floor")),
            "no grant-floor refusal recorded in two years of drought: {:?}",
            out.refusals
        );

        // Running costs continue from the stable leg: validator cover keeps
        // paying out through the drought, though the TNZO-denominated
        // running-cost reserve never fills from fee revenue.
        let mid = out
            .days
            .iter()
            .find(|d| d.snap.day >= 450.0)
            .expect("the run reached day 450");
        let late = out.days.last().expect("a day ran");
        assert!(
            late.cover_paid_usd_total > mid.cover_paid_usd_total,
            "validator cover stopped paying during the drought: day {} total {}, day {} total {}",
            mid.snap.day,
            mid.cover_paid_usd_total,
            late.snap.day,
            late.cover_paid_usd_total
        );
        assert!(late.cover_paid_usd_total > 0.0, "{late:?}");
    }

    // (B5b/T5) A single issuer -- the one settlement asset this simulation
    // registers -- fails for good while the treasury holds it. The peg
    // breaker (settlement_asset.rs) suspends a sustained off-peg asset and
    // only re-enables it after a run of on-peg epochs; a failure that never
    // recovers (`Kind::StableFailure` at `size: 0.0`, forever) therefore
    // suspends it for good. The module's own rule: a suspended asset "settles
    // nothing and pays out nothing; what the treasury holds of it is kept,
    // never sold" -- so the loss shows up in published value, not in a
    // forced liquidation.
    #[test]
    fn a_single_issuers_permanent_failure_at_its_exposure_is_absorbed_without_a_forced_sale() {
        let failure_day = 540u32;
        let total_days = failure_day + 200;
        let mut c = RunConfig::scenario(Market::Flat, 41, total_days);
        c.assumptions.stable_settlement = true;
        c.assumptions.stable_asset = true;
        c.assumptions.stable_leg = true;
        c.rate_reports = true;
        c.network_params.insert(
            "fees.treasury_leg_inference_bps".into(),
            chaos::TREASURY_LEG_BPS,
        );
        c.network_params.insert(
            "fees.treasury_leg_compute_bps".into(),
            chaos::TREASURY_LEG_BPS,
        );
        c.chaos = Some(Arc::new(Plan {
            days: total_days,
            events: vec![Event {
                kind: Kind::StableFailure,
                day: failure_day,
                days: u32::MAX - failure_day,
                size: 0.0,
                factor: 1.0,
                tail_days: 0,
                amount: 0.0,
                joint: false,
            }],
        }));
        let out = Economy::new(c).run();
        assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);

        let before = out
            .days
            .iter()
            .rev()
            .find(|d| d.snap.day < failure_day as f64)
            .expect("the run reached the day before the failure");
        let after = out.days.last().expect("a day ran");

        // At its maximum exposure: real, material exposure built up before
        // the failure -- otherwise this is not the scenario the spec asks
        // for.
        let exposure_before = before.treasury_stable_usd
            / (before.treasury_stable_usd + before.snap.treasury * before.chain_rate_usd).max(1e-9);
        assert!(
            exposure_before > 0.05,
            "exposure to the issuer never became material: {exposure_before} ({before:?})"
        );

        // Permanent failure: the published value of the failed leg collapses
        // and, being permanent, never recovers.
        assert!(
            after.treasury_stable_usd < before.treasury_stable_usd * 0.1,
            "the failed asset's published value did not collapse: before {}, after {}",
            before.treasury_stable_usd,
            after.treasury_stable_usd
        );
        let recovered = out
            .days
            .iter()
            .filter(|d| d.snap.day >= (failure_day + 20) as f64)
            .any(|d| d.treasury_stable_usd > before.treasury_stable_usd * 0.5);
        assert!(
            !recovered,
            "a permanently failed issuer should never recover"
        );

        // The run (and with it the chain's own per-epoch coverage
        // publication, read in the first scenario above) kept advancing
        // through the failure, not halted by it.
        assert!(after.snap.day > before.snap.day);
    }
}

// S3 (TENZRO-ECONOMY-RESILIENCE-2026-10-25, B3; T4, T5): stablecoin depeg
// paths against the chain's own peg breaker (tenzro-vm native/
// settlement_asset.rs). Every threshold below is read from the code's
// governed values, never restated: the suspend run K
// (`settlement_asset.breaker_suspend_epochs`), the resume run, the resume
// band, the entry's par band and its exposure ceiling. One rate epoch is an
// hour (`MARKET_EPOCH_MS`) and a simulated block is an hour, so the breaker
// steps once per block and the quotes below are laid at hour resolution
// (`RunConfig::stable_quotes`); the run's samples (`RunOutcome::stable_hours`) are
// read from chain state after every block, not modelled.
mod s3_stablecoin_depeg_paths {
    use super::*;
    use tenzro_econsim::economy::{RunOutcome as Out, StableHour, StableQuote};
    use tenzro_types::settlement_asset as sa;
    use tenzro_vm::native::settlement_asset as breaker;

    const START_DAY: u32 = 30;
    const H0: f64 = (START_DAY * 24) as f64;

    fn k() -> usize {
        breaker::DEFAULT_BREAKER_SUSPEND_EPOCHS as usize
    }
    fn resume_epochs() -> usize {
        breaker::DEFAULT_BREAKER_RESUME_EPOCHS as usize
    }

    fn q(from: f64, to: f64, a: (f64, f64), b: (f64, f64)) -> StableQuote {
        StableQuote {
            from_hour: from,
            to_hour: to,
            venue_a: a,
            venue_b: b,
        }
    }
    /// Both venues at `v` from `from` to `to`.
    fn both(from: f64, to: f64, v: f64) -> StableQuote {
        q(from, to, (v, v), (v, v))
    }

    fn run_path(quotes: Vec<StableQuote>, days: u32) -> Out {
        let mut c = RunConfig::scenario(Market::Flat, 41, days);
        c.assumptions.stable_settlement = true;
        c.assumptions.stable_asset = true;
        c.assumptions.stable_leg = true;
        c.rate_reports = true;
        c.network_params.insert(
            "fees.treasury_leg_inference_bps".into(),
            chaos::TREASURY_LEG_BPS,
        );
        c.network_params.insert(
            "fees.treasury_leg_compute_bps".into(),
            chaos::TREASURY_LEG_BPS,
        );
        c.stable_quotes = quotes;
        let out = Economy::new(c).run();
        assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
        assert!(!out.stable_hours.is_empty());
        out
    }

    fn suspend_hours(h: &[StableHour]) -> Vec<f64> {
        h.windows(2)
            .filter(|w| !w[0].suspended && w[1].suspended)
            .map(|w| w[1].hour)
            .collect()
    }
    fn resume_hours(h: &[StableHour]) -> Vec<f64> {
        h.windows(2)
            .filter(|w| w[0].suspended && !w[1].suspended)
            .map(|w| w[1].hour)
            .collect()
    }
    /// First hour at or after `from` the rate in force sat outside the par
    /// band (what the breaker counts from).
    fn first_off_peg(h: &[StableHour], from: f64) -> Option<f64> {
        let band = sa::DEFAULT_PAR_BAND_BPS;
        h.iter()
            .find(|s| {
                s.hour >= from
                    && s.rate_nano_usd > 0
                    && !breaker::on_peg(s.rate_nano_usd as u128, 1_000_000_000, band)
            })
            .map(|s| s.hour)
    }

    /// The invariants every path owes, whatever it does to the peg.
    fn common(out: &Out, label: &str) {
        let h = &out.stable_hours;
        // At most one suspend/re-enable cycle per event.
        assert!(
            suspend_hours(h).len() <= 1,
            "{label}: more than one suspension: {:?}",
            suspend_hours(h)
        );
        // Zero swaps or payouts out of a suspended leg: while suspended the
        // treasury's holding never falls and no settlement leg arrives.
        for w in h.windows(2) {
            if w[0].suspended && w[1].suspended {
                assert!(
                    w[1].treasury_units >= w[0].treasury_units,
                    "{label}: the treasury's holding of a suspended asset fell at hour {}: {} -> {}",
                    w[1].hour,
                    w[0].treasury_units,
                    w[1].treasury_units
                );
            }
        }
        // Settlements in a suspended asset are refused by the chain
        // (`permitted` -> `check_breaker`), not executed.
        if !suspend_hours(h).is_empty() {
            assert!(
                out.refusals
                    .iter()
                    .any(|(k, v)| k.contains("suspended by its peg breaker") && *v > 0),
                "{label}: nothing was refused while suspended: {:?}",
                out.refusals
            );
            // The only leg that still reaches the treasury is the daily
            // transfer of legs owed on payments made BEFORE the suspension
            // (economy.rs, the provider close: a plain token transfer, which
            // the breaker does not gate and which only adds to the treasury).
            // It arrives at most once a day, never per settlement.
            let mut days = std::collections::BTreeSet::new();
            for w in h.windows(2) {
                if w[0].suspended && w[1].suspended && w[1].legs_sent > w[0].legs_sent {
                    days.insert((w[1].hour / 24.0).round() as i64);
                }
            }
            let suspended_hours = h.iter().filter(|s| s.suspended).count() as f64;
            assert!(
                days.len() as f64 <= suspended_hours / 24.0 + 2.0,
                "{label}: legs arrived on {} distinct days in {suspended_hours} suspended hours",
                days.len()
            );
        }
        // Treasury exposure to the issuer under the entry's ceiling. NOTE:
        // this holds here by scale, not by mechanism: `check_exposure`
        // (settlement_asset.rs) is called only from payout_swap.rs:236, so
        // the routine leg that credits the treasury is not capped by it.
        let cap = sa::DEFAULT_EXPOSURE_BPS as f64;
        let max = h.iter().map(|s| s.exposure_bps).fold(0.0, f64::max);
        assert!(
            max <= cap,
            "{label}: exposure reached {max} bps, over the {cap} bps ceiling"
        );
    }

    fn dump(label: &str, out: &Out) {
        let h = &out.stable_hours;
        eprintln!(
            "S3 {label}: suspends {:?} resumes {:?} first_off {:?} max_exposure_bps {:.0} refusals_susp {:?}",
            suspend_hours(h),
            resume_hours(h),
            first_off_peg(h, H0),
            h.iter().map(|s| s.exposure_bps).fold(0.0, f64::max),
            out.refusals
                .iter()
                .filter(|(k, _)| k.contains("suspended"))
                .map(|(k, v)| (k.chars().take(60).collect::<String>(), *v))
                .collect::<Vec<_>>()
        );
    }

    /// Suspended once, no later than `K` epochs after the rate in force
    /// first left the band (the breaker counts from that epoch).
    fn suspended_within_k(out: &Out, label: &str) -> f64 {
        let h = &out.stable_hours;
        let off =
            first_off_peg(h, H0).unwrap_or_else(|| panic!("{label}: the rate never left the band"));
        let s = suspend_hours(h);
        assert_eq!(s.len(), 1, "{label}: expected one suspension, got {s:?}");
        assert!(
            s[0] <= off + k() as f64,
            "{label}: suspended at hour {} but the rate left the band at hour {off}, more than K={} epochs earlier",
            s[0],
            k()
        );
        s[0]
    }

    #[test]
    fn usdc_2023_two_days_at_087_suspends_within_k_and_resumes_once_after_the_resume_run() {
        let out = run_path(vec![both(H0, H0 + 48.0, 0.87)], 40);
        dump("usdc", &out);
        common(&out, "usdc");
        suspended_within_k(&out, "usdc");
        let r = resume_hours(&out.stable_hours);
        assert_eq!(r.len(), 1, "usdc: expected one re-enable, got {r:?}");
        assert!(
            r[0] >= H0 + 48.0 + resume_epochs() as f64,
            "usdc: re-enabled at hour {} before {} epochs on peg could have passed",
            r[0],
            resume_epochs()
        );
    }

    // SPEC PASS CONDITION NOT MET, kept truthful (as S8 did for the FCFS
    // caps): the spec wants no suspension for a venue-only flash. Measured:
    // a 40-minute quote of 0.65 on ONE venue (the other at par) touches one
    // epoch, yet the validators' median for that epoch is far off par, the
    // rate IN FORCE moves toward it only by its bounded step
    // (economy.rs `next_rate`: the rate in force falls at most
    // `fees.usd_rate_max_fall_bps` an epoch and is walked back the same way),
    // and the breaker steps on that applied rate
    // (economy.rs:1225 `observe_rate(.., applied, ..)`), so the applied rate
    // stays outside the 100 bps band for K or more epochs after a single
    // epoch's dip. Result: one suspension, one re-enable. What does hold:
    // once, within K epochs of leaving the band, re-enabled only after the
    // resume run, no flapping. Fixing it is a consensus change (the breaker
    // would have to step on the epoch median, or the venue quote be
    // discarded as an outlier) and is not made here.
    #[test]
    fn a_forty_minute_flash_on_one_venue_still_suspends_once_because_the_breaker_reads_the_bounded_rate()
     {
        let end = H0 + 0.5 + 40.0 / 60.0;
        let out = run_path(vec![q(H0 + 0.5, end, (0.65, 0.65), (1.0, 1.0))], 40);
        dump("venue-only", &out);
        common(&out, "venue-only");
        suspended_within_k(&out, "venue-only");
        let r = resume_hours(&out.stable_hours);
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(
            r[0] >= end + resume_epochs() as f64 - 1.0,
            "re-enabled at {} before the resume run",
            r[0]
        );
    }

    // Same finding for a 40-minute flash across every venue at 0.92.
    #[test]
    fn a_forty_minute_flash_across_every_venue_also_suspends_once_for_the_same_reason() {
        let end = H0 + 0.5 + 40.0 / 60.0;
        let out = run_path(vec![both(H0 + 0.5, end, 0.92)], 40);
        dump("multi-venue-40min", &out);
        common(&out, "multi-venue-40min");
        // The window covers a block, so the flash reached the chain's rate
        // (otherwise this would pass vacuously).
        let min_rate = out
            .stable_hours
            .iter()
            .filter(|s| s.rate_nano_usd > 0)
            .map(|s| s.rate_nano_usd)
            .min()
            .unwrap();
        assert!(
            min_rate < 990_000_000,
            "the flash never reached the rate: {min_rate}"
        );
        suspended_within_k(&out, "multi-venue-40min");
        assert_eq!(resume_hours(&out.stable_hours).len(), 1);
    }

    // Not in the spec's pass list; measured so the behaviour is on record: a
    // single venue held down past K epochs.
    #[test]
    fn a_single_venue_held_down_for_six_hours_is_recorded() {
        let out = run_path(vec![q(H0, H0 + 6.0, (0.65, 0.65), (1.0, 1.0))], 40);
        dump("venue-only-6h", &out);
        common(&out, "venue-only-6h");
        // Finding: one venue held down for K or more epochs does move the
        // validators' median enough to suspend (the chain cannot tell it
        // from a real depeg), once, and the asset resumes after the resume
        // run.
        suspended_within_k(&out, "venue-only-6h");
        assert_eq!(resume_hours(&out.stable_hours).len(), 1);
    }

    #[test]
    fn xusd_falling_to_026_over_two_days_suspends_within_k_and_never_resumes() {
        let out = run_path(
            vec![
                q(H0, H0 + 48.0, (1.0, 0.26), (1.0, 0.26)),
                both(H0 + 48.0, 1e9, 0.26),
            ],
            60,
        );
        dump("xusd", &out);
        common(&out, "xusd");
        suspended_within_k(&out, "xusd");
        assert!(resume_hours(&out.stable_hours).is_empty());
        assert!(out.stable_hours.last().unwrap().suspended);
    }

    #[test]
    fn a_slow_bleed_from_0995_to_095_over_thirty_days_suspends_within_k_of_leaving_the_band() {
        let out = run_path(
            vec![
                q(H0, H0 + 720.0, (0.995, 0.95), (0.995, 0.95)),
                both(H0 + 720.0, 1e9, 0.95),
            ],
            70,
        );
        dump("bleed", &out);
        common(&out, "bleed");
        let at = suspended_within_k(&out, "bleed");
        // Not before the market itself left the 100 bps band (0.99).
        let crossed = H0 + 720.0 * (0.005 / 0.045);
        assert!(
            at >= crossed,
            "suspended at hour {at}, before the market crossed the band at {crossed}"
        );
        assert!(resume_hours(&out.stable_hours).is_empty());
    }

    #[test]
    fn oscillation_at_the_suspend_edge_never_runs_k_epochs_off_peg_and_never_suspends() {
        // 0.9895 is 105 bps off par (out of the band), 0.9905 is 95 bps (in).
        let mut qs = Vec::new();
        for i in 0..72 {
            let v = if i % 2 == 0 { 0.9895 } else { 0.9905 };
            qs.push(both(H0 + i as f64, H0 + i as f64 + 1.0, v));
        }
        let out = run_path(qs, 40);
        dump("osc-suspend-edge", &out);
        common(&out, "osc-suspend-edge");
        assert!(
            suspend_hours(&out.stable_hours).is_empty(),
            "{:?}",
            suspend_hours(&out.stable_hours)
        );
    }

    #[test]
    fn oscillation_at_the_resume_edge_does_not_flap_the_asset_back_on() {
        // A real depeg suspends it; then the quote oscillates around the
        // resume band's edge (50 bps) for 72 hours.
        let mut qs = vec![both(H0, H0 + 6.0, 0.90)];
        for i in 0..72 {
            let v = if i % 2 == 0 { 0.9948 } else { 0.9952 };
            qs.push(both(H0 + 6.0 + i as f64, H0 + 7.0 + i as f64, v));
        }
        let out = run_path(qs, 40);
        dump("osc-resume-edge", &out);
        common(&out, "osc-resume-edge");
        suspended_within_k(&out, "osc-resume-edge");
        let end = H0 + 78.0;
        for r in resume_hours(&out.stable_hours) {
            assert!(
                r >= end,
                "re-enabled at hour {r} while still oscillating at the resume edge"
            );
        }
        assert!(resume_hours(&out.stable_hours).len() <= 1);
    }

    #[test]
    fn treasury_exposure_to_the_issuer_against_its_ceiling_is_recorded() {
        let out = run_path(vec![], 120);
        dump("exposure", &out);
        let cap = sa::DEFAULT_EXPOSURE_BPS as f64;
        let max = out
            .stable_hours
            .iter()
            .map(|s| s.exposure_bps)
            .fold(0.0, f64::max);
        eprintln!("S3 exposure: max {max:.0} bps against ceiling {cap}");
    }
}
