//! The consensus committee of one epoch and its quorum thresholds.
//!
//! Stake enters every quorum as an integer number of seats. Each validator
//! holds seats in proportion to its normalized stake (largest-remainder
//! apportionment of a fixed seat budget, with no one-seat floor; a
//! validator whose stake earns no seat is not a member), and every
//! message a validator sends counts once per seat it holds. A validator with
//! `k` seats is then exactly `k` parties that always act together, so the
//! protocol's count-based thresholds, and the arguments that make them safe,
//! apply unchanged with `n` = total seats and `f` = `(n - 1) / 3`: an
//! adversary is tolerated while the validators it controls hold at most `f`
//! seats.

use crate::error::Result;
use crate::validator::ValidatorSet;

pub use tenzro_finality::committee::{
    Committee, DEFAULT_SEAT_BUDGET, Member, SeatSet, ValidatorIndex,
};

/// Builds the committee of `set`, apportioning `seat_budget` seats. A
/// validator whose stake earns no seat is not a member: it has no vote to
/// count.
pub fn from_validator_set(set: &ValidatorSet, seat_budget: u64) -> Result<Committee> {
    let weights = set.normalized_weights();
    let seats = apportion(&weights, seat_budget.max(set.len() as u64));
    let members = set
        .iter()
        .zip(seats)
        .filter(|(_, seats)| *seats > 0)
        .map(|(v, seats)| Member {
            address: v.address,
            public_key: v.public_key.clone(),
            stake: v.voting_power(),
            seats,
        })
        .collect();
    Ok(Committee::from_members(set.epoch, members)?)
}

/// Largest-remainder apportionment of `budget` seats by `weights`. Ties break
/// by index, so the result is deterministic. There is no floor of one seat:
/// a floor would let a stake split across many small validators outweigh the
/// same stake held by one.
fn apportion(weights: &[u128], budget: u64) -> Vec<u64> {
    let n = weights.len();
    let total: u128 = weights.iter().sum();
    if total == 0 {
        return vec![1; n];
    }
    let budget_u = budget as u128;
    let mut seats: Vec<u64> = Vec::with_capacity(n);
    let mut remainders: Vec<(u128, usize)> = Vec::with_capacity(n);
    for (i, w) in weights.iter().enumerate() {
        let exact = w.saturating_mul(budget_u);
        seats.push((exact / total) as u64);
        remainders.push((exact % total, i));
    }
    let assigned: u64 = seats.iter().sum();
    let mut left = budget.saturating_sub(assigned);
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for (_, i) in remainders {
        if left == 0 {
            break;
        }
        seats[i] += 1;
        left -= 1;
    }
    seats
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::validator::test_support::validators;
    use crate::validator_key::test_signer::SoftwareTestSigner;

    /// A committee of `n` equal-stake members holding one seat each.
    pub(crate) fn committee(n: usize) -> (Committee, Vec<SoftwareTestSigner>) {
        let (infos, signers) = validators(n, 100);
        let set = ValidatorSet::new(0, infos).unwrap();
        (
            crate::committee::from_validator_set(&set, n as u64).unwrap(),
            signers,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::committee;
    use super::*;

    #[test]
    fn thresholds_match_the_counting_formulas_at_n_3f_plus_1() {
        let (c, _) = committee(4);
        assert_eq!((c.total_seats(), c.max_faulty(), c.quorum()), (4, 1, 3));
        assert_eq!(c.rbc_vote_threshold(), 2);
        assert_eq!(c.rbc_ack_threshold(), 2);
        assert_eq!(c.rbc_fast_threshold(), 2);
        let (c, _) = committee(100);
        assert_eq!((c.max_faulty(), c.quorum()), (33, 67));
        assert_eq!(c.rbc_vote_threshold(), 50);
        assert_eq!(c.rbc_ack_threshold(), 66);
        assert_eq!(c.rbc_fast_threshold(), 82);
    }

    #[test]
    fn any_two_quorums_share_an_honest_seat() {
        for n in 1..400u64 {
            let f = (n - 1) / 3;
            let q = n - f;
            assert!(2 * q > n + f, "n={n}");
        }
    }

    #[test]
    fn apportionment_spends_the_budget_in_proportion() {
        let s = apportion(&[1, 1, 1, 1_000_000], 10);
        assert_eq!(s, vec![0, 0, 0, 10]);
        let s = apportion(&[3, 3, 3], 10);
        assert_eq!(s.iter().sum::<u64>(), 10);
        assert_eq!(s, vec![4, 3, 3]);
    }

    /// Stake split across many small validators earns no more seats than
    /// the same stake held by one.
    #[test]
    fn splitting_stake_does_not_buy_seats() {
        let mut split = vec![1_000u128; 300];
        split.push(9_700_000);
        let s = apportion(&split, 1_000);
        let small: u64 = s[..300].iter().sum();
        let whole = apportion(&[300_000, 9_700_000], 1_000);
        assert!(small <= whole[0] + 1, "{small} vs {}", whole[0]);
    }

    #[test]
    fn a_seat_set_counts_each_member_once() {
        let mut s = SeatSet::new();
        assert!(s.insert(3, 5));
        assert!(!s.insert(3, 5));
        assert!(s.insert(70, 2));
        assert_eq!(s.weight(), 7);
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![3, 70]);
    }
}
