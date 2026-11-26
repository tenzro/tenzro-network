//! A parameter change enacted while the release floor allowed its key is
//! dropped at the epoch it would apply if the floor was lowered meanwhile.

use super::payout_gates_tests::{STEP_MS, chain, enact_ok};
use super::*;
use crate::governance::{
    ProposalAction, RELEASE_0_2_1, RELEASE_FLOOR_PARAM, TIMELOCK_PARAM, governed_param,
};

const NEW_TIMELOCK_MS: u64 = 3 * 24 * 60 * 60 * 1000;

/// Enacts a change of the timelock, a key that came with 0.2.2, and returns
/// the value in force after the epoch it was due, with the floor left alone
/// or lowered to 0.2.1 first.
async fn timelock_after_due_epoch(floor_lowered: bool) -> u64 {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    let change = ProposalAction::ParameterChange {
        key: TIMELOCK_PARAM.into(),
        value: NEW_TIMELOCK_MS,
        memo: "three days".into(),
    };
    enact_ok(&executor, &mut state, &change, STEP_MS).await;
    let pending = pending_param(&state, TIMELOCK_PARAM).expect("scheduled");
    assert_eq!(pending.value, NEW_TIMELOCK_MS);
    if floor_lowered {
        set_governed_param_for_test(&mut state, RELEASE_FLOOR_PARAM, RELEASE_0_2_1);
    }
    begin_block_params(&mut state, pending.activates_epoch).unwrap();
    network_param(&state, TIMELOCK_PARAM)
}

#[tokio::test]
async fn a_change_applies_while_the_floor_allows_its_key() {
    assert_eq!(timelock_after_due_epoch(false).await, NEW_TIMELOCK_MS);
}

#[tokio::test]
async fn a_change_is_dropped_when_the_floor_was_lowered_before_it_applied() {
    let genesis = governed_param(TIMELOCK_PARAM).unwrap().genesis;
    assert_eq!(timelock_after_due_epoch(true).await, genesis);
}
