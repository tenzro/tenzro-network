//! Guardian pause of one feature: who may call it, how it carries, what it
//! holds and how it lifts.

use super::feature_pause::{FeaturePause, active, pause_of};
use super::guardian::write_seat;
use super::*;
use crate::governance::{
    FEATURE_PAUSE_COOLOFF_PARAM, FEATURE_PAUSE_MAX_PARAM, GuardianRole, GuardianSeat, SeatKeyRoot,
};
use crate::state_adapter::StateAdapter;

const KEY: &str = "bridge.ccip.status";
const T0: i64 = 1_700_000_000_000;
const HOUR: i64 = 3_600_000;
const BALANCE: u128 = 10_000_000_000_000_000_000;

fn seat(state: &mut StateAdapter, who: [u8; 20], role: GuardianRole, tag: usize) {
    let seat = GuardianSeat {
        did: format!("did:tenzro:human:g{tag}"),
        role,
        term_ends_ms: T0 + 1000 * HOUR,
        key_root: SeatKeyRoot::Device {
            credential_id: format!("{tag:02x}"),
        },
    };
    write_seat(state, &who, Some(&seat), &mut Vec::new());
    state.set_balance(&who, BALANCE);
}

/// `n` protocol guardians.
fn guardians(state: &mut StateAdapter, n: usize) -> Vec<[u8; 20]> {
    (0..n)
        .map(|i| {
            let who = [0xc0 + i as u8; 20];
            seat(state, who, GuardianRole::Protocol, i);
            who
        })
        .collect()
}

fn call(
    state: &mut StateAdapter,
    who: &[u8],
    epochs: u32,
    key: &str,
    at: i64,
) -> Result<ExecutionResult> {
    let mut data = SELECTOR_GOVERNANCE_FEATURE_PAUSE.to_vec();
    data.extend_from_slice(&epochs.to_be_bytes());
    data.extend_from_slice(key.as_bytes());
    let mut tx = VmTransaction::new(
        who.to_vec(),
        None,
        0,
        data,
        200_000,
        1_000_000_000,
        0,
        VmType::Tenzro,
        1337,
    );
    tx.block_timestamp_ms = Some(at);
    let mut meter = GasMeter::new(200_000);
    feature_pause::execute_feature_pause(&tx, state, &mut meter)
}

/// Every guardian signals the same pause; the last one carries it.
fn carry(state: &mut StateAdapter, gs: &[[u8; 20]], epochs: u32, key: &str) {
    let t = guardian::threshold(state);
    for (i, g) in gs.iter().take(t).enumerate() {
        let r = call(state, g, epochs, key, T0 + i as i64).unwrap();
        assert!(r.success);
    }
}

#[test]
fn guardians_pause_one_feature_for_a_bounded_time_and_it_lifts_by_itself() {
    let mut state = StateAdapter::new();
    let gs = guardians(&mut state, guardian::threshold(&StateAdapter::new()) + 1);
    begin_block_params(&mut state, 10).unwrap();
    let cooloff = network_param(&state, FEATURE_PAUSE_COOLOFF_PARAM);

    assert_eq!(
        lever_status(&state, KEY),
        crate::governance::LeverStatus::Enabled
    );
    carry(&mut state, &gs, 5, KEY);
    assert!(active(&state, KEY));
    assert_eq!(
        pause_of(&state, KEY),
        FeaturePause {
            until_epoch: 15,
            cooloff_until_epoch: 15 + cooloff
        }
    );
    // The lever reads paused, the governed value does not move, and a
    // feature that asks for an enabled lever is refused.
    assert_eq!(
        lever_status(&state, KEY),
        crate::governance::LeverStatus::Paused
    );
    assert_eq!(network_param(&state, KEY), 0);
    assert!(require_lever_enabled(&state, KEY, "the route").is_err());

    // Other levers are untouched.
    assert!(require_lever_enabled(&state, "bridge.ibc.status", "the route").is_ok());

    begin_block_params(&mut state, 14).unwrap();
    assert!(active(&state, KEY));
    begin_block_params(&mut state, 15).unwrap();
    assert!(!active(&state, KEY));
    assert!(require_lever_enabled(&state, KEY, "the route").is_ok());

    // Guardians cannot pause it again until the cool-off has passed.
    for g in gs.iter().take(guardian::threshold(&state)) {
        assert!(call(&mut state, g, 5, KEY, T0 + 9 * HOUR).is_err());
    }
    begin_block_params(&mut state, 15 + cooloff).unwrap();
    carry_later(&mut state, &gs, 5, KEY);
    assert!(active(&state, KEY));
}

/// [`carry`] at a later block time, so the signals sit in a new window.
fn carry_later(state: &mut StateAdapter, gs: &[[u8; 20]], epochs: u32, key: &str) {
    let t = guardian::threshold(state);
    for (i, g) in gs.iter().take(t).enumerate() {
        call(state, g, epochs, key, T0 + 500 * HOUR + i as i64).unwrap();
    }
}

#[test]
fn one_guardian_alone_does_not_pause_and_the_signals_must_agree() {
    let mut state = StateAdapter::new();
    let t = guardian::threshold(&state);
    let gs = guardians(&mut state, t + 1);
    begin_block_params(&mut state, 10).unwrap();
    if t < 2 {
        return;
    }
    // Different lengths do not add up to the threshold.
    for (i, g) in gs.iter().take(t).enumerate() {
        call(&mut state, g, 3 + i as u32, KEY, T0).unwrap();
    }
    assert!(!active(&state, KEY));
}

#[test]
fn only_a_seated_protocol_guardian_pauses_and_only_a_running_status_lever() {
    let mut state = StateAdapter::new();
    let gs = guardians(&mut state, guardian::threshold(&StateAdapter::new()));
    let outsider = [0x77u8; 20];
    state.set_balance(&outsider, BALANCE);
    let veto_only = [0x78u8; 20];
    seat(&mut state, veto_only, GuardianRole::Governance, 90);
    let steward = [0x79u8; 20];
    seat(&mut state, steward, GuardianRole::Steward, 91);
    begin_block_params(&mut state, 10).unwrap();

    for who in [&outsider, &veto_only, &steward] {
        assert!(call(&mut state, who, 3, KEY, T0).is_err());
    }
    let g = &gs[0];
    // Not a status lever: a value cannot be changed or switched.
    assert!(call(&mut state, g, 3, "fees.settlement_fee_bps", T0).is_err());
    assert!(call(&mut state, g, 3, "no.such.key", T0).is_err());
    // Length bounds.
    let longest = network_param(&state, FEATURE_PAUSE_MAX_PARAM) as u32;
    assert!(call(&mut state, g, 0, KEY, T0).is_err());
    assert!(call(&mut state, g, longest + 1, KEY, T0).is_err());
    // A feature a vote paused or retired is not enabled: guardians cannot
    // resume or retire it, and have nothing to stop.
    for status in [1u64, 2] {
        set_governed_param_for_test(&mut state, KEY, status);
        assert!(call(&mut state, g, 3, KEY, T0).is_err(), "status {status}");
    }
}
