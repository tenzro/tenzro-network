//! Training challenges: a challenge bond is paid out in full, to the
//! challenger, the trainer and the insurance pool, and no more than it holds.

use super::slashing::bps_share_by_lemma;
use crate::native::staking::bps_share;
use crate::native::training_proof::{ChallengeOutcome, split_challenge_bond};

#[kani::proof]
#[kani::stub(bps_share, bps_share_by_lemma)]
fn a_challenge_bond_is_split_without_creating_or_losing_value() {
    let (bond, bps, pick): (u128, u64, u8) = kani::any();
    let outcome = match pick % 3 {
        0 => ChallengeOutcome::Upheld,
        1 => ChallengeOutcome::Dismissed,
        _ => ChallengeOutcome::Expired,
    };
    let s = split_challenge_bond(bond, bps, outcome);
    assert!(s.to_pool <= bond);
    assert!(s.to_challenger.checked_add(s.to_trainer) == Some(bond - s.to_pool));
    match outcome {
        ChallengeOutcome::Dismissed => assert!(s.to_challenger == 0),
        _ => assert!(s.to_trainer == 0),
    }
}
