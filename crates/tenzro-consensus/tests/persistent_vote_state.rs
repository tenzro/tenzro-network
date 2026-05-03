//! Regression tests for the persistent vote-state safety invariant.
//!
//! These exercise the exact failure mode that produced the testnet
//! equivocation cascade at view=62 on 2026-04-27: a validator votes,
//! crashes (or freezes mid-broadcast), restarts, and on recovery casts a
//! vote for a *different* block in the *same* view. With persistent
//! vote-state in place this can no longer happen — the second sign attempt
//! is refused, and the engine surfaces a self-detected `Equivocation`
//! error instead of producing a slashable signature.

use std::sync::Arc;

use tenzro_consensus::{
    FileVoteStateStore, LastSignState, MemoryVoteStateStore, VoteStateStore, VoteStep,
    VrsDecision,
};
use tenzro_types::primitives::Hash;

fn h(b: u8) -> Hash {
    Hash::new([b; 32])
}

/// Scenario: validator signs Prepare for block A in view 62, then tries to
/// sign Prepare for block B in the same view (the literal cascade
/// signature). The store must refuse.
#[test]
fn refuses_same_view_different_block() {
    let store = MemoryVoteStateStore::new();

    // Pretend we already signed block A.
    store
        .record(&LastSignState {
            version: 1,
            view: 62,
            height: 1,
            step: VoteStep::Prepare,
            block_hash: Some(h(0xAA)),
            signature: Some(b"signature_for_A".to_vec()),
        })
        .unwrap();

    // Now try to sign block B in the same view — must refuse.
    let decision = store
        .check_vrs(62, 1, VoteStep::Prepare, &h(0xBB))
        .unwrap();

    match decision {
        VrsDecision::Reject { reason } => {
            assert!(reason.contains("double-sign refused"));
        }
        other => panic!("expected Reject, got {:?}", other),
    }
}

/// Scenario: validator restarts from a freshly-opened file store. The
/// pre-restart sign state must survive and continue to refuse the
/// equivocating second sign.
#[test]
fn file_store_survives_restart_and_refuses_equivocation() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("last_sign.json");

    // First instance: record a vote.
    {
        let store = FileVoteStateStore::open(&path).unwrap();
        store
            .record(&LastSignState {
                version: 1,
                view: 62,
                height: 1,
                step: VoteStep::Prepare,
                block_hash: Some(h(0xAA)),
                signature: Some(b"sig_for_A".to_vec()),
            })
            .unwrap();
    }

    // Simulated crash + restart.
    let store2 = FileVoteStateStore::open(&path).unwrap();

    // Equivocation attempt.
    let decision = store2
        .check_vrs(62, 1, VoteStep::Prepare, &h(0xBB))
        .unwrap();
    match decision {
        VrsDecision::Reject { .. } => {}
        other => panic!("post-restart equivocation must be rejected, got {:?}", other),
    }

    // Idempotent retry of the same block — must Reuse.
    let decision = store2
        .check_vrs(62, 1, VoteStep::Prepare, &h(0xAA))
        .unwrap();
    match decision {
        VrsDecision::Reuse { signature } => assert_eq!(signature, b"sig_for_A"),
        other => panic!("expected Reuse for identical retry, got {:?}", other),
    }
}

/// Scenario: progress is monotonic — Prepare -> Commit -> next height all
/// allowed; each step write-backed.
#[test]
fn allows_normal_progression() {
    let store: Arc<dyn VoteStateStore> = Arc::new(MemoryVoteStateStore::new());

    // Prepare at (view=10, h=5).
    assert!(matches!(
        store.check_vrs(10, 5, VoteStep::Prepare, &h(1)).unwrap(),
        VrsDecision::Sign
    ));
    store
        .record(&LastSignState {
            version: 1,
            view: 10,
            height: 5,
            step: VoteStep::Prepare,
            block_hash: Some(h(1)),
            signature: Some(vec![1]),
        })
        .unwrap();

    // Commit at same (view=10, h=5) — same block.
    assert!(matches!(
        store.check_vrs(10, 5, VoteStep::Commit, &h(1)).unwrap(),
        VrsDecision::Sign
    ));
    store
        .record(&LastSignState {
            version: 1,
            view: 10,
            height: 5,
            step: VoteStep::Commit,
            block_hash: Some(h(1)),
            signature: Some(vec![2]),
        })
        .unwrap();

    // Next height — Prepare allowed.
    assert!(matches!(
        store.check_vrs(11, 6, VoteStep::Prepare, &h(2)).unwrap(),
        VrsDecision::Sign
    ));
}

/// Scenario: explicit regression to a strictly earlier (view, height,
/// step) — must refuse. Catches replay/rewind attacks.
#[test]
fn refuses_regression_to_earlier_tuple() {
    let store = MemoryVoteStateStore::new();
    store
        .record(&LastSignState {
            version: 1,
            view: 100,
            height: 50,
            step: VoteStep::Commit,
            block_hash: Some(h(7)),
            signature: Some(vec![0xCC]),
        })
        .unwrap();

    // Earlier view — refuse.
    match store.check_vrs(99, 999, VoteStep::Decide, &h(7)).unwrap() {
        VrsDecision::Reject { .. } => {}
        other => panic!("expected Reject, got {:?}", other),
    }
    // Same view, earlier height — refuse.
    match store.check_vrs(100, 49, VoteStep::Decide, &h(7)).unwrap() {
        VrsDecision::Reject { .. } => {}
        other => panic!("expected Reject, got {:?}", other),
    }
    // Same (view, height), earlier step — refuse.
    match store.check_vrs(100, 50, VoteStep::Prepare, &h(7)).unwrap() {
        VrsDecision::Reject { .. } => {}
        other => panic!("expected Reject, got {:?}", other),
    }
}
