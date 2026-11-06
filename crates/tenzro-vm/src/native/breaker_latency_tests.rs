//! How long a breaker takes from the anomaly to the stop, with the governed
//! values the chain carries: the value monitor freezes a leaking module in
//! the block of the leak, and a guardian pause carries once the governed
//! threshold of independent guardians has signalled inside the signal
//! window, holds for at most the governed maximum and lifts by itself.

use super::guardian::{
    PauseScope, apply_pause, is_paused, seats, signal_pause, threshold, write_seat,
};
use super::*;
use crate::governance::{
    DEFAULT_GUARDIAN_SIGNAL_WINDOW_MS, GuardianRole, GuardianSeat, MAX_PAUSE_PARAM, SeatKeyRoot,
};
use crate::invariant_monitor::{GuardedModule, check_block, require_unfrozen};
use crate::state_adapter::StateAdapter;

const STAKE: u128 = 1_000_000;
const T0: i64 = 1_700_000_000_000;
const HOUR: i64 = 3_600_000;

#[test]
fn a_value_leak_stops_its_module_in_the_block_that_leaked() {
    let mut state = StateAdapter::new();
    let alice = [0xa1u8; 20];
    staking::add_bond(&mut state, &alice, STAKE, 0).unwrap();
    let vault = staking_vault_address();
    state.set_balance(&vault, STAKE);
    assert!(check_block(&mut state).is_empty(), "nothing leaked yet");
    require_unfrozen(&state, GuardedModule::Staking).unwrap();

    // A bug pays 250k out of the vault in one block.
    state.set_balance(&vault, STAKE - 250_000);
    let frozen = check_block(&mut state);
    assert_eq!(
        frozen.len(),
        1,
        "frozen by the check that ends the same block"
    );
    assert!(require_unfrozen(&state, GuardedModule::Staking).is_err());
    // The loss is bounded by what one block moved: the next block pays nothing.
    assert_eq!(state.get_balance(&vault), STAKE - 250_000);
}

fn seat_guardians(state: &mut StateAdapter, n: usize) -> Vec<[u8; 20]> {
    let mut out = Vec::new();
    for i in 0..n {
        let who = [0xc0 + i as u8; 20];
        let seat = GuardianSeat {
            did: format!("did:tenzro:human:g{i}"),
            role: GuardianRole::Protocol,
            term_ends_ms: T0 + 1000 * HOUR,
            key_root: SeatKeyRoot::Device {
                credential_id: format!("{i:02x}"),
            },
        };
        write_seat(state, &who, Some(&seat), &mut Vec::new());
        out.push(who);
    }
    assert!(seats(state).len() >= n);
    out
}

#[test]
fn a_guardian_pause_carries_within_the_signal_window_and_lifts_by_itself() {
    let mut state = StateAdapter::new();
    let t = threshold(&state);
    let guardians = seat_guardians(&mut state, t + 1);
    let mut changes = Vec::new();

    // The anomaly is seen at T0. Each guardian signals ten minutes after the
    // one before; the pause carries on the threshold-th signal.
    let mut carried_at = None;
    for (i, g) in guardians.iter().take(t).enumerate() {
        let at = T0 + i as i64 * 600_000;
        let tally = signal_pause(&mut state, PauseScope::Enactment, true, g, at, &mut changes)
            .expect("a seated guardian may signal");
        if tally.carried() {
            carried_at = Some(at);
        }
    }
    let at = carried_at.expect("the threshold of guardians carried the pause");
    assert!(
        at - T0 <= DEFAULT_GUARDIAN_SIGNAL_WINDOW_MS as i64,
        "time from anomaly to pause stays inside the signal window"
    );
    let record = apply_pause(&mut state, PauseScope::Enactment, true, at, &mut changes);
    let max_pause = network_param(&state, MAX_PAUSE_PARAM) as i64;
    assert!(is_paused(&state, PauseScope::Enactment, at + 1));
    assert_eq!(record.paused_until_ms, at + max_pause);
    assert!(
        !is_paused(&state, PauseScope::Enactment, at + max_pause + 1),
        "a pause cannot be held open: it lifts by itself"
    );
}

#[test]
fn signals_that_trickle_in_past_the_window_do_not_carry() {
    let mut state = StateAdapter::new();
    let t = threshold(&state);
    let guardians = seat_guardians(&mut state, t);
    if t < 2 {
        return;
    }
    let mut changes = Vec::new();
    let window = DEFAULT_GUARDIAN_SIGNAL_WINDOW_MS as i64;
    // The first signal goes stale before the rest arrive.
    signal_pause(
        &mut state,
        PauseScope::Enactment,
        true,
        &guardians[0],
        T0,
        &mut changes,
    )
    .unwrap();
    let mut last = None;
    for (i, g) in guardians.iter().enumerate().skip(1) {
        let at = T0 + window + 1 + i as i64;
        last = Some(
            signal_pause(&mut state, PauseScope::Enactment, true, g, at, &mut changes).unwrap(),
        );
    }
    assert!(
        !last.unwrap().carried(),
        "a stale signal no longer counts toward the threshold"
    );
}

// ---- bridge route breaker: validators holding two thirds of stake ----------

use super::bridge_circuit::{BridgeCircuitAuthority, BridgeCircuitTrip, read_bridge_circuit, trip};
use tenzro_types::agent_audit::AuditFinding;
use tenzro_types::bridge_route::{BridgeRouteAdapter, BridgeRouteMode};
use tenzro_types::primitives::Address;

const CHAIN_NAME: &str = "ethereum";

fn audited_chain(stakes: &[u128]) -> (StateAdapter, Vec<[u8; 32]>) {
    let mut state = StateAdapter::new();
    state.set_storage(
        &SYSTEM_ADDRESS,
        rewards::REWARD_SCHEDULE_KEY.as_bytes(),
        rewards::genesis_reward_schedule(86_400_000).unwrap(),
    );
    rewards::begin_block(&mut state, 0, &Address::new([5; 32]), 1).unwrap();
    let mut who = Vec::new();
    for (i, stake) in stakes.iter().enumerate() {
        let a = [0xd0 + i as u8; 32];
        staking::add_bond(&mut state, &a, *stake, -crate::governance::MIN_BOND_AGE_MS).unwrap();
        who.push(a);
    }
    (state, who)
}

fn flag_trip(state: &mut StateAdapter, from: &[u8], at: i64) {
    let finding = AuditFinding::TripBridge {
        adapter: BridgeRouteAdapter::Ccip,
        source_chain: CHAIN_NAME.to_string(),
        evidence_hash: "ab".repeat(32),
        reason: "mint exceeds what the source chain locked".to_string(),
    };
    let payload =
        serde_json::to_vec(&serde_json::json!({"epoch": 0, "findings": [finding]})).unwrap();
    super::agent_audit::flag(state, from, at, &payload).expect("a bonded validator may flag");
}

fn route_mode(state: &StateAdapter) -> Option<BridgeRouteMode> {
    read_bridge_circuit(state, BridgeRouteAdapter::Ccip, CHAIN_NAME).map(|t| t.mode)
}

#[test]
fn the_route_pauses_when_validators_holding_two_thirds_of_stake_have_flagged() {
    let (mut state, v) = audited_chain(&[100; 6]);
    // The anomaly is first flagged at T0; one more validator flags each hour.
    for (i, a) in v.iter().enumerate() {
        flag_trip(&mut state, a, T0 + i as i64 * HOUR);
        let flagged = i + 1;
        if flagged < 4 {
            assert_eq!(
                route_mode(&state),
                None,
                "{flagged} of 6 is under two thirds"
            );
        } else {
            assert_eq!(route_mode(&state), Some(BridgeRouteMode::Paused));
            // Anomaly to pause: three hours here, however long the fourth
            // validator takes to see it. The bound is the validators'
            // reaction time, not a parameter.
            assert_eq!(flagged, 4);
            return;
        }
    }
}

#[test]
fn a_cartel_over_a_third_of_stake_that_withholds_flags_keeps_validators_from_pausing_it() {
    // Seven validators; the three that hold 3/7 of stake collude with the
    // exploit and never flag. The honest four hold 4/7, under two thirds.
    let (mut state, v) = audited_chain(&[100; 7]);
    for (i, a) in v.iter().take(4).enumerate() {
        flag_trip(&mut state, a, T0 + i as i64 * HOUR);
    }
    assert_eq!(
        route_mode(&state),
        None,
        "validators cannot pause a route against a cartel of over a third of stake"
    );
    // The remaining defences do not depend on the cartel: governance sets the
    // mode on its expedited track and replaces whatever record is there.
    let gov = BridgeCircuitTrip {
        adapter: BridgeRouteAdapter::Ccip,
        source_chain: CHAIN_NAME.to_string(),
        mode: BridgeRouteMode::Paused,
        by: BridgeCircuitAuthority::Governance,
        reason: "mint exceeds what the source chain locked".to_string(),
        evidence_hash: None,
        epoch: 0,
        at_ms: T0 + 6 * HOUR,
    };
    trip(&mut state, &gov, &mut Vec::new(), &mut Vec::new()).unwrap();
    assert_eq!(route_mode(&state), Some(BridgeRouteMode::Paused));
}

#[test]
fn flags_from_stake_that_has_left_do_not_count_toward_the_pause() {
    let (mut state, v) = audited_chain(&[100; 6]);
    for a in v.iter().take(3) {
        flag_trip(&mut state, a, T0);
    }
    // Two flaggers unbond before the fourth flags: their stake no longer counts.
    staking::begin_unbonding(&mut state, &v[0], T0 + 1).unwrap();
    staking::begin_unbonding(&mut state, &v[1], T0 + 1).unwrap();
    flag_trip(&mut state, &v[3], T0 + HOUR);
    assert_eq!(route_mode(&state), None);
}
