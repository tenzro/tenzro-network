//! The testnet genesis shortens three governance-process values: a 24 hour
//! voting period, a 4 hour timelock and a 24 epoch loosening grace. A node
//! refuses a genesis whose parameters fall outside the registry bounds, so
//! these values must sit inside them and satisfy the rules that bind
//! parameters together.

use tenzro_vm::governance::{
    GUARD_LOOSENING_GRACE_PARAM, TIMELOCK_PARAM, VOTING_PERIOD_PARAM, governed_param,
    joint_change_allowed,
};

const HOUR_MS: u64 = 60 * 60 * 1000;

fn start(key: &str) -> u64 {
    tenzro_vm::governance::genesis_param(key)
}

#[test]
fn the_testnet_process_timings_are_inside_the_registry_bounds() {
    for (key, value) in [
        (VOTING_PERIOD_PARAM, 24 * HOUR_MS),
        (TIMELOCK_PARAM, 4 * HOUR_MS),
        (GUARD_LOOSENING_GRACE_PARAM, 24),
    ] {
        let p = governed_param(key).expect("a governed parameter");
        assert!(
            value >= p.min && value <= p.max,
            "{key} = {value} is outside {}..={}",
            p.min,
            p.max
        );
        joint_change_allowed(key, value, &start)
            .unwrap_or_else(|e| panic!("{key} = {value} breaks a joint rule: {e}"));
    }
}

#[test]
fn a_timelock_shorter_than_the_expedited_floor_is_still_refused() {
    let p = governed_param(TIMELOCK_PARAM).expect("a governed parameter");
    assert_eq!(p.min, 4 * HOUR_MS);
    assert!(3 * HOUR_MS < p.min);
}
