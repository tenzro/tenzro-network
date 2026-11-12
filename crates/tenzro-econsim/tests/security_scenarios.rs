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
        r.supply_max_tnzo <= MAX_SUPPLY_TNZO as f64,
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
