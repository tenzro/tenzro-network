//! The identity rule's mode moves by an ordinary `parameter_change`: a vote
//! relaxes a live rule to audit with no new genesis and no release, and the
//! relaxation applies at the next epoch.

use super::payout_gates_tests::{STEP_MS, chain, enact_ok};
use super::*;
use crate::governance::ProposalAction;
use crate::identity_required::{KEY, MODE_KEY, Mode, check, mode};

fn plain(from: u8) -> VmTransaction {
    let mut tx = VmTransaction::new(
        vec![from; 32],
        Some(vec![9; 32]),
        1,
        Vec::new(),
        100_000,
        1,
        0,
        VmType::Tenzro,
        1337,
    );
    tx.signing_digest = Some(vec![1; 32]);
    tx
}

#[tokio::test]
async fn a_vote_relaxes_the_live_identity_rule_to_audit_from_the_next_epoch() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    set_governed_param_for_test(&mut state, KEY, 0);
    let stranger = 0x55;
    assert_eq!(mode(&state), Mode::Enforce);
    assert!(
        check(&plain(stranger), &state).is_err(),
        "enforced from genesis"
    );

    let relax = ProposalAction::ParameterChange {
        key: MODE_KEY.into(),
        value: Mode::Audit as u64,
        memo: "audit the identity rule".into(),
    };
    assert_eq!(relax.track(), crate::governance::ProposalTrack::Expedited);
    enact_ok(&executor, &mut state, &relax, STEP_MS).await;
    let pending = pending_param(&state, MODE_KEY).expect("scheduled");
    assert_eq!(pending.value, Mode::Audit as u64);
    assert_eq!(
        pending.activates_epoch,
        params_epoch(&state) + 1,
        "no grace"
    );
    assert!(check(&plain(stranger), &state).is_err(), "not mid-epoch");

    begin_block_params(&mut state, pending.activates_epoch).unwrap();
    assert_eq!(mode(&state), Mode::Audit);
    assert!(check(&plain(stranger), &state).is_ok(), "admitted, logged");

    // Back to enforce asks more of everyone, so it waits the grace window.
    let restore = ProposalAction::ParameterChange {
        key: MODE_KEY.into(),
        value: Mode::Enforce as u64,
        memo: "enforce again".into(),
    };
    assert_eq!(restore.track(), crate::governance::ProposalTrack::Standard);
    enact_ok(&executor, &mut state, &restore, 2 * STEP_MS).await;
    let pending = pending_param(&state, MODE_KEY).expect("scheduled");
    assert!(pending.activates_epoch > params_epoch(&state) + 1);
    begin_block_params(&mut state, pending.activates_epoch).unwrap();
    assert!(check(&plain(stranger), &state).is_err());
}
