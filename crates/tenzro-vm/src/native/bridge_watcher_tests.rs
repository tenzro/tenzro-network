//! The bonded watcher's pause of a bridge route: it works when validators
//! holding more than a third of stake withhold their flags, it lifts by
//! itself, and spam, a thin or freshly posted bond, a replayed signal and a
//! false signal cost the watcher.

use super::bridge_circuit::{
    BridgeCircuitAuthority, BridgeCircuitTrip, bridge_route_stop_at, trip,
};
use super::bridge_watcher::{self, Op, read_signal};
use super::staking;
use super::*;
use crate::state_adapter::StateAdapter;
use tenzro_types::bridge_route::{BridgeRouteAdapter, BridgeRouteMode};

const TNZO: u128 = tenzro_types::constants::ONE_TNZO;
const GAS_BALANCE: u128 = 10_000_000_000_000_000_000;
const T0: i64 = 1_800_000_000_000;
const HOUR: i64 = 3_600_000;
const DAY: i64 = 24 * HOUR;
const CHAIN_NAME: &str = "ethereum";
const A: BridgeRouteAdapter = BridgeRouteAdapter::Ccip;

/// Validators bonded since two days before `T0`, with `stakes` whole TNZO.
fn chain(stakes: &[u128]) -> (StateAdapter, Vec<[u8; 32]>) {
    let mut state = StateAdapter::new();
    let mut who = Vec::new();
    let mut vault = 0u128;
    for (i, s) in stakes.iter().enumerate() {
        let a = [0xd0 + i as u8; 32];
        staking::add_bond(&mut state, &a, s * TNZO, T0 - 2 * DAY).unwrap();
        vault += s * TNZO;
        state.set_balance(&a, GAS_BALANCE);
        who.push(a);
    }
    state.set_balance(&STAKING_VAULT_ADDRESS, vault);
    (state, who)
}

fn tx(from: &[u8], op: &Op, at: i64) -> VmTransaction {
    let mut data = SELECTOR_BRIDGE_WATCHER.to_vec();
    data.extend_from_slice(&serde_json::to_vec(op).unwrap());
    let mut tx = VmTransaction::new(
        from.to_vec(),
        None,
        0,
        data,
        500_000,
        1_000_000_000,
        0,
        VmType::Evm,
        1337,
    );
    tx.block_timestamp_ms = Some(at);
    tx
}

fn signal(evidence: u8) -> Op {
    Op::Signal {
        adapter: A,
        source_chain: CHAIN_NAME.to_string(),
        evidence_hash: format!("{evidence:02x}").repeat(32),
        reason: "mint exceeds what the source chain locked".to_string(),
    }
}

fn settle() -> Op {
    Op::Settle {
        adapter: A,
        source_chain: CHAIN_NAME.to_string(),
    }
}

async fn run(state: &mut StateAdapter, from: &[u8], op: &Op, at: i64) -> bool {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    match executor.execute_transaction(&tx(from, op, at), state).await {
        Ok(r) => r.success,
        Err(_) => false,
    }
}

fn stopped(state: &StateAdapter, at: i64) -> Option<BridgeRouteMode> {
    bridge_route_stop_at(state, A, CHAIN_NAME, at).map(|s| s.0)
}

fn pause_ms(state: &StateAdapter) -> i64 {
    network_param(state, bridge_watcher::PAUSE_MS_PARAM) as i64
}

fn governance_stops(state: &mut StateAdapter, at: i64) {
    let gov = BridgeCircuitTrip {
        adapter: A,
        source_chain: CHAIN_NAME.to_string(),
        mode: BridgeRouteMode::Paused,
        by: BridgeCircuitAuthority::Governance,
        reason: "confirmed".to_string(),
        evidence_hash: None,
        epoch: 0,
        at_ms: at,
    };
    trip(state, &gov, &mut Vec::new(), &mut Vec::new()).unwrap();
}

#[tokio::test]
async fn a_watcher_pauses_the_route_when_over_a_third_of_stake_withholds_its_flags() {
    // Seven equal validators; three withhold (3/7 of stake), the other four
    // cannot reach two thirds, so the validator path never pauses the route.
    let (mut state, v) = chain(&[10_000; 7]);
    assert_eq!(stopped(&state, T0), None);
    assert!(run(&mut state, &v[3], &signal(1), T0).await);
    let pause = pause_ms(&state);
    assert_eq!(stopped(&state, T0 + 1), Some(BridgeRouteMode::Paused));
    assert_eq!(
        stopped(&state, T0 + pause - 1),
        Some(BridgeRouteMode::Paused)
    );
    assert_eq!(
        stopped(&state, T0 + pause),
        None,
        "the pause is bounded: it lifts by itself"
    );
}

#[tokio::test]
async fn a_signal_governance_confirms_costs_the_watcher_nothing_and_a_false_one_is_slashed() {
    let (mut state, v) = chain(&[10_000; 4]);
    let w = v[0];
    let before = staking::bonded_stake_of(&state, &w);
    assert!(run(&mut state, &w, &signal(1), T0).await);
    let s = read_signal(&state, A, CHAIN_NAME).unwrap();

    // Judging before the review time is refused.
    assert!(!run(&mut state, &v[1], &settle(), s.expires_ms).await);

    // Governance confirms inside the review time: no slash.
    governance_stops(&mut state, T0 + 2 * HOUR);
    assert!(run(&mut state, &v[1], &settle(), s.review_until_ms).await);
    assert_eq!(staking::bonded_stake_of(&state, &w), before);
    // Judged once.
    assert!(!run(&mut state, &v[1], &settle(), s.review_until_ms + 1).await);

    // A second chain: nothing confirms it, the watcher loses the governed share.
    let (mut state, v) = chain(&[10_000; 4]);
    let w = v[0];
    let before = staking::bonded_stake_of(&state, &w);
    assert!(run(&mut state, &w, &signal(2), T0).await);
    let s = read_signal(&state, A, CHAIN_NAME).unwrap();
    assert!(run(&mut state, &v[1], &settle(), s.review_until_ms).await);
    let slash = network_param(&state, bridge_watcher::SLASH_BPS_PARAM) as u128;
    assert_eq!(
        staking::bonded_stake_of(&state, &w),
        before - before * slash / 10_000
    );
}

#[tokio::test]
async fn a_watcher_cannot_dodge_the_slash_by_unbonding() {
    let (mut state, v) = chain(&[10_000; 4]);
    let w = v[0];
    assert!(run(&mut state, &w, &signal(1), T0).await);
    staking::begin_unbonding(&mut state, &w, T0 + 1).unwrap();
    assert_eq!(staking::bonded_stake_of(&state, &w), 0);
    let s = read_signal(&state, A, CHAIN_NAME).unwrap();
    // The unbonding period is longer than the pause plus the review time (a
    // governed relation the parameter checks enforce), so the stake is
    // still there to take.
    let unbonding = network_param(&state, staking::UNBONDING_PARAM) as i64;
    assert!(s.review_until_ms - T0 < unbonding);
    let pool = super::insurance::pool_address();
    let before = state.get_balance(pool.as_bytes());
    assert!(run(&mut state, &v[1], &settle(), s.review_until_ms).await);
    assert!(
        state.get_balance(pool.as_bytes()) > before,
        "the unbonding stake was slashed into the insurance pool"
    );
}

#[tokio::test]
async fn spam_is_bounded_by_one_open_signal_the_route_state_and_the_cooloff() {
    let (mut state, v) = chain(&[10_000; 5]);
    assert!(run(&mut state, &v[0], &signal(1), T0).await);
    // The same watcher cannot open another signal, whatever the evidence.
    for e in 2..10u8 {
        assert!(!run(&mut state, &v[0], &signal(e), T0 + e as i64).await);
    }
    // Another watcher cannot pause a route that is already stopped.
    assert!(!run(&mut state, &v[1], &signal(20), T0 + 10).await);
    // Past the pause but inside the cooloff the route cannot be paused again.
    let s = read_signal(&state, A, CHAIN_NAME).unwrap();
    assert!(!run(&mut state, &v[1], &signal(21), s.expires_ms + 1).await);
    // After the cooloff another watcher may.
    assert!(run(&mut state, &v[1], &signal(22), s.cooloff_until_ms).await);
}

#[tokio::test]
async fn a_replayed_signal_is_refused() {
    let (mut state, v) = chain(&[10_000; 5]);
    assert!(run(&mut state, &v[0], &signal(1), T0).await);
    let s = read_signal(&state, A, CHAIN_NAME).unwrap();
    assert!(run(&mut state, &v[2], &settle(), s.review_until_ms).await);
    // The same evidence hash again, by anyone, after the cooloff.
    assert!(!run(&mut state, &v[1], &signal(1), s.cooloff_until_ms + 1).await);
    assert!(run(&mut state, &v[1], &signal(2), s.cooloff_until_ms + 1).await);
}

#[tokio::test]
async fn a_thin_or_freshly_posted_bond_is_not_a_watcher() {
    let (mut state, _) = chain(&[10_000; 4]);
    // Posted for the occasion: bonded an hour before the signal.
    let fresh = [0xee; 32];
    staking::add_bond(&mut state, &fresh, 10_000 * TNZO, T0 - HOUR).unwrap();
    state.set_balance(&fresh, GAS_BALANCE);
    assert!(!run(&mut state, &fresh, &signal(1), T0).await, "too young");
    assert!(
        run(&mut state, &fresh, &signal(1), T0 + 2 * DAY).await,
        "aged"
    );

    // Under the governed minimum.
    let (mut state, _) = chain(&[10_000; 4]);
    let thin = [0xef; 32];
    let min = network_param(&state, bridge_watcher::MIN_STAKE_PARAM) as u128;
    staking::add_bond(&mut state, &thin, (min - 1) * TNZO, T0 - 2 * DAY).unwrap();
    state.set_balance(&thin, GAS_BALANCE);
    assert!(!run(&mut state, &thin, &signal(1), T0).await);
    // An unbonded account.
    let nobody = [0xf0; 32];
    state.set_balance(&nobody, GAS_BALANCE);
    assert!(!run(&mut state, &nobody, &signal(1), T0).await);
}

#[test]
fn the_unbonding_period_must_outlast_the_watcher_pause_and_review() {
    use crate::governance::joint_change_allowed;
    use crate::native::bridge_watcher::{PAUSE_MS_PARAM, REVIEW_MS_PARAM};
    let unbonding = 7 * DAY as u64;
    let now = move |k: &str| match k {
        k if k == staking::UNBONDING_PARAM => unbonding,
        k if k == PAUSE_MS_PARAM => 6 * HOUR as u64,
        k if k == REVIEW_MS_PARAM => 3 * DAY as u64,
        k if k == crate::governance::VOTING_PERIOD_PARAM => 3 * DAY as u64,
        k if k == crate::governance::TIMELOCK_PARAM => 2 * DAY as u64,
        k if k == crate::governance::EXPEDITED_VOTING_PERIOD_PARAM => 6 * HOUR as u64,
        k if k == crate::governance::EXPEDITED_TIMELOCK_PARAM => 12 * HOUR as u64,
        _ => 0,
    };
    // Pause plus review past the unbonding period: a watcher's stake could
    // leave before it is judged.
    assert!(joint_change_allowed(REVIEW_MS_PARAM, 7 * DAY as u64, &now).is_err());
    assert!(joint_change_allowed(PAUSE_MS_PARAM, 5 * DAY as u64, &now).is_err());
    assert!(joint_change_allowed(REVIEW_MS_PARAM, 3 * DAY as u64, &now).is_ok());
    // Lowering the unbonding period under the watcher window, the standard
    // vote plus timelock, or the expedited vote plus timelock.
    assert!(joint_change_allowed(staking::UNBONDING_PARAM, 3 * DAY as u64, &now).is_err());
    assert!(joint_change_allowed(staking::UNBONDING_PARAM, 5 * DAY as u64 - 1, &now).is_err());
    assert!(joint_change_allowed(staking::UNBONDING_PARAM, 6 * DAY as u64, &now).is_ok());
    // A longer voting period or timelock that stake could outrun.
    assert!(
        joint_change_allowed(crate::governance::VOTING_PERIOD_PARAM, 6 * DAY as u64, &now).is_err()
    );
    assert!(joint_change_allowed(crate::governance::TIMELOCK_PARAM, 5 * DAY as u64, &now).is_err());
    assert!(
        joint_change_allowed(
            crate::governance::EXPEDITED_TIMELOCK_PARAM,
            8 * DAY as u64,
            &now
        )
        .is_err()
    );
}

/// Flash stake: stake that votes cannot be withdrawn before the decision it
/// voted on has taken effect, because the unbonding period is at least the
/// voting period plus the timelock; and it stays slashable meanwhile.
#[test]
fn stake_that_votes_is_still_bonded_when_the_decision_takes_effect() {
    let (mut state, v) = chain(&[1_000; 3]);
    let voted_at = T0;
    staking::begin_unbonding(&mut state, &v[0], voted_at).unwrap();
    let decided = voted_at
        + network_param(&state, crate::governance::VOTING_PERIOD_PARAM) as i64
        + network_param(&state, crate::governance::TIMELOCK_PARAM) as i64;
    let out = staking::withdraw_unbonded(&mut state, &v[0], decided).unwrap_or(0);
    assert_eq!(
        out, 0,
        "nothing can be withdrawn before the decision takes effect"
    );
}
