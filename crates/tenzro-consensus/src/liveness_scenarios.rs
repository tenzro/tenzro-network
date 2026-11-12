//! Liveness scenarios from the 2026-10 chain halt: the quorum arithmetic of
//! a validator set that was launched with a member that never signed. Block
//! 7341 was the last one certified; with the one remaining spare gone the
//! other three could not reach the three votes four equal validators need.
//!
//! These tests state the arithmetic the committee computes, so a change to
//! the thresholds, or a genesis set with no spare, shows up here.

use crate::committee::Committee;
use crate::committee::test_support::committee;

/// A block is certified when at least a quorum of seats vote for it.
fn advances(c: &Committee, live: u64) -> bool {
    live >= c.quorum()
}

/// Seats that can still be lost before the chain stops.
fn headroom(c: &Committee, live: u64) -> i64 {
    live as i64 - c.quorum() as i64
}

/// A dead validator is removed at an epoch boundary, and an epoch boundary
/// is a certified block: a halted chain cannot eject anyone.
fn can_eject(c: &Committee, live: u64) -> bool {
    advances(c, live)
}

#[test]
fn four_equal_validators_with_one_dead_since_genesis_have_no_headroom() {
    let (c, _) = committee(4);
    assert_eq!((c.total_seats(), c.max_faulty(), c.quorum()), (4, 1, 3));
    // The founding set: one member never came up. Three live seats still
    // certify, with nothing to spare.
    assert!(advances(&c, 3));
    assert_eq!(headroom(&c, 3), 0);
    // The loss of any one of the three halts the chain.
    assert!(!advances(&c, 2));
    assert_eq!(headroom(&c, 2), -1);
}

#[test]
fn a_halted_set_cannot_eject_its_dead_members() {
    let (c, _) = committee(4);
    // Two live of four: no certified block, so no epoch boundary, so the
    // ejection of the dead members never happens by itself.
    assert!(!can_eject(&c, 2));
    // With one dead and three live the boundary comes and the dead member
    // can be removed.
    assert!(can_eject(&c, 3));
}

#[test]
fn ejecting_the_dead_from_a_live_set_leaves_a_three_of_three_set_with_no_tolerance() {
    // Four seats, one dead, three live: the chain advances, the dead member
    // is ejected, the set is now the three live validators.
    let (c3, _) = committee(3);
    assert_eq!((c3.total_seats(), c3.max_faulty(), c3.quorum()), (3, 0, 3));
    // It certifies while all three are up...
    assert!(advances(&c3, 3));
    // ...and halts on the first loss: ejection restored liveness, not fault
    // tolerance. Tolerance needs a replacement to join (permissionless), so
    // the set is four or more again.
    assert!(!advances(&c3, 2));
    let (c4, _) = committee(4);
    assert!(
        advances(&c4, 3),
        "a replacement restores one failure of tolerance"
    );
}

#[test]
fn fault_tolerance_needs_four_validators_and_grows_with_the_set() {
    for n in 1..=30usize {
        let (c, _) = committee(n);
        let f = (n as u64 - 1) / 3;
        assert_eq!(c.max_faulty(), f, "n = {n}");
        assert_eq!(c.quorum(), n as u64 - f, "n = {n}");
        if n < 4 {
            assert_eq!(c.max_faulty(), 0, "a set under four tolerates nothing");
        }
    }
}

#[test]
fn a_set_launched_at_three_f_plus_one_with_f_dead_has_no_spare_for_any_f() {
    for f in 1..=10usize {
        let n = 3 * f + 1;
        let (c, _) = committee(n);
        let live = (n - f) as u64;
        assert!(advances(&c, live), "n = {n}: f dead still certifies");
        assert_eq!(headroom(&c, live), 0, "n = {n}: and nothing is spare");
        assert!(!advances(&c, live - 1), "n = {n}: one more loss halts");
        assert!(
            !can_eject(&c, live - 1),
            "n = {n}: a halted set ejects nobody"
        );
    }
}

/// What a launch gate must check: a genesis set is acceptable only if every
/// founding validator has signed, that is, the live count equals the set,
/// so the headroom at launch is the full f.
#[test]
fn a_genesis_set_is_sound_only_when_every_founding_member_is_live() {
    for n in 4..=13usize {
        let (c, _) = committee(n);
        assert_eq!(headroom(&c, n as u64), c.max_faulty() as i64);
        assert!(
            headroom(&c, n as u64 - 1) < headroom(&c, n as u64),
            "a dead founder spends the headroom"
        );
    }
}
