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
use crate::validator::{ValidatorInfo, ValidatorSet};

pub use tenzro_finality::committee::{
    Committee, DEFAULT_SEAT_BUDGET, Member, SeatSet, ValidatorIndex,
};

/// Largest `f` the exact fault bound is computed for; a committee that
/// tolerates more seats than this uses `f` itself.
const EXACT_FAULT_BOUND_LIMIT: u64 = 1 << 16;

/// The most seats faulty validators can hold. A validator is faulty with all
/// its seats or none, so the adversary holds the seats of some set of whole
/// members, and that set holds at most `f = (n - 1) / 3` seats. This is the
/// heaviest such set: at most `f`, and less whenever no set of members adds
/// up to `f` exactly. It is `0` when no single member fits within `f` (two
/// members of 400 seats each, `f = 266`): the committee then tolerates no
/// faulty member at all, under either bound, and one READY delivers.
pub fn largest_faulty_weight(committee: &Committee) -> u64 {
    let f = committee.max_faulty();
    if f > EXACT_FAULT_BOUND_LIMIT {
        return f;
    }
    // reachable[w]: some set of members holds exactly w seats.
    let mut reachable = vec![false; f as usize + 1];
    reachable[0] = true;
    for seats in committee
        .members()
        .iter()
        .map(|m| m.seats)
        .filter(|s| (1..=f).contains(s))
    {
        for w in (seats..=f).rev() {
            if reachable[(w - seats) as usize] {
                reachable[w as usize] = true;
            }
        }
    }
    (0..=f).rev().find(|w| reachable[*w as usize]).unwrap_or(0)
}

/// Which bound on the faulty seats the reliable-broadcast thresholds of an
/// epoch are computed from. Every validator of the epoch must use the same
/// one: a party that sends or delivers on lower thresholds than its peers
/// breaks the counting the others rely on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultBound {
    /// `f = (n - 1) / 3` seats, whoever holds them.
    Seats,
    /// [`largest_faulty_weight`]: the most seats whole members within `f`
    /// can hold.
    WholeMembers,
}

impl FaultBound {
    /// The bound of `epoch` on a chain whose whole-member bound starts at
    /// epoch `whole_members_from`.
    pub fn of_epoch(epoch: u64, whole_members_from: u64) -> Self {
        if epoch >= whole_members_from {
            Self::WholeMembers
        } else {
            Self::Seats
        }
    }
}

/// The reliable-broadcast thresholds of one committee, in seats, for a
/// fault bound `t`: `f` under [`FaultBound::Seats`], and
/// [`largest_faulty_weight`] under [`FaultBound::WholeMembers`]. The
/// protocol's arguments hold for any `t` with `n >= 3t + 1` that the faulty
/// seats cannot exceed, and the second is such a bound: it is at most `f`,
/// and no set of whole members within `f` holds more. Where it is below `f`
/// the thresholds are lower, so a committee of a few equal validators still
/// delivers in two steps when one is silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BroadcastThresholds {
    /// Non-author ECHO weight at which a party sends VOTE, `ceil(n / 2)`.
    pub vote: u64,
    /// Non-author weight of VOTE or ECHO (for ACK) and of ACK (for READY),
    /// `ceil((n + t - 1) / 2)`.
    pub ack: u64,
    /// READY weight that holds an honest seat, `t + 1`.
    pub ready: u64,
    /// READY weight at which the broadcast delivers, `2t + 1`.
    pub deliver: u64,
    /// Non-author ECHO weight at which it delivers in two steps,
    /// `ceil((n + 2t - 2) / 2)`.
    pub fast: u64,
}

impl BroadcastThresholds {
    pub fn of(committee: &Committee, bound: FaultBound) -> Self {
        let n = committee.total_seats();
        let t = match bound {
            FaultBound::Seats => {
                return Self {
                    vote: committee.rbc_vote_threshold(),
                    ack: committee.rbc_ack_threshold(),
                    ready: committee.validity(),
                    deliver: committee.ready_delivery(),
                    fast: committee.rbc_fast_threshold(),
                };
            }
            FaultBound::WholeMembers => largest_faulty_weight(committee),
        };
        Self {
            vote: n.div_ceil(2),
            ack: (n + t).saturating_sub(1).div_ceil(2),
            ready: t + 1,
            deliver: 2 * t + 1,
            fast: (n + 2 * t).saturating_sub(2).div_ceil(2),
        }
    }
}

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

/// The committee of epoch 0: the validators a genesis names, under its seat
/// budget. Its root is what a light client that trusts only the genesis
/// starts from.
pub fn genesis_committee(validators: Vec<ValidatorInfo>, seat_budget: u64) -> Result<Committee> {
    from_validator_set(&ValidatorSet::new(0, validators)?, seat_budget)
}

/// Most rounds [`cap_group_stakes`] takes to bring every group under its
/// cap.
const GROUP_CAP_ROUNDS: usize = 64;

/// Stakes for `validators` under which no group of any grouping holds more
/// than its cap of the committee's seats. Each grouping is `(groups,
/// cap_bps)`: `groups[i]` is the group of `validators[i]`, numbered from
/// zero (an operator's root identity, or a declared region). The bound is
/// checked on the seats themselves, after the per-validator cap of
/// [`ValidatorSet::normalized_weights`] and with every member of a group
/// counted as winning its largest-remainder seat, so it holds whatever
/// order the set is built in. A group over its cap has its members' stakes
/// scaled down until it is not; others keep theirs.
///
/// A grouping whose cap cannot hold for every group that holds stake (too
/// few groups for the cap) is skipped. The caps bind groups as the chain
/// knows them: an operator who spreads validators over separate identities,
/// or declares a region it is not in, is counted as it declared.
pub fn cap_group_stakes(
    validators: &[ValidatorInfo],
    groupings: &[(&[usize], u32)],
    seat_budget: u64,
) -> Result<Vec<u128>> {
    let raw: Vec<u128> = validators.iter().map(|v| v.voting_power()).collect();
    let live: Vec<(&[usize], u128, usize)> = groupings
        .iter()
        .filter_map(|(groups, cap_bps)| {
            let cap = u128::from((*cap_bps).min(10_000));
            let count = groups.iter().max().map_or(0, |m| m + 1);
            let mut held = vec![false; count];
            for (w, g) in raw.iter().zip(groups.iter()) {
                held[*g] |= *w > 0;
            }
            let groups_held = held.iter().filter(|h| **h).count() as u128;
            (cap > 0 && groups.len() == raw.len() && groups_held * cap > 10_000)
                .then_some((*groups, cap, count))
        })
        .collect();
    if live.is_empty() {
        return Ok(raw);
    }
    let budget = u128::from(seat_budget.max(raw.len() as u64));
    let mut stakes = raw.clone();
    for (groups, cap, _) in &live {
        stakes = crate::validator::cap_group_weights(&stakes, groups, *cap as u32);
    }
    for _ in 0..GROUP_CAP_ROUNDS {
        let set = ValidatorSet::new(
            0,
            validators
                .iter()
                .zip(&stakes)
                .map(|(v, s)| ValidatorInfo {
                    stake: *s,
                    ..v.clone()
                })
                .collect(),
        )?;
        let weights = set.normalized_weights();
        let total: u128 = weights.iter().sum();
        if total == 0 {
            break;
        }
        let mut over = false;
        let mut scale: Vec<(u128, u128)> = vec![(1, 1); stakes.len()];
        for (groups, cap, count) in &live {
            let room = cap * budget / 10_000;
            let mut bound = vec![0u128; *count];
            for (w, g) in weights.iter().zip(groups.iter()) {
                if *w > 0 {
                    bound[*g] += crate::validator::mul_div(*w, budget, total) + 1;
                }
            }
            for (i, g) in groups.iter().enumerate() {
                if bound[*g] > room {
                    over = true;
                    // Keep the tightest scale any grouping asks of this
                    // validator.
                    let (n, d) = scale[i];
                    if room * d < n * bound[*g] {
                        scale[i] = (room, bound[*g]);
                    }
                }
            }
        }
        if !over {
            break;
        }
        for (s, (n, d)) in stakes.iter_mut().zip(&scale) {
            if n < d {
                *s = crate::validator::mul_div(*s, *n, *d).min(s.saturating_sub(1));
            }
        }
    }
    Ok(stakes)
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

    /// A committee whose members hold `seats`, in order.
    pub(crate) fn seated(seats: &[u64]) -> Committee {
        let (equal, _) = committee(seats.len());
        let members = equal
            .members()
            .iter()
            .zip(seats)
            .map(|(m, seats)| Member {
                seats: *seats,
                ..m.clone()
            })
            .collect();
        Committee::from_members(0, members).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{committee, seated};
    use super::*;

    #[test]
    fn thresholds_match_the_counting_formulas_at_n_3f_plus_1() {
        let (c, _) = committee(4);
        assert_eq!((c.total_seats(), c.max_faulty(), c.quorum()), (4, 1, 3));
        for bound in [FaultBound::Seats, FaultBound::WholeMembers] {
            let t = BroadcastThresholds::of(&c, bound);
            assert_eq!((t.vote, t.ack, t.ready, t.deliver, t.fast), (2, 2, 2, 3, 2));
        }
        let (c, _) = committee(100);
        assert_eq!((c.max_faulty(), c.quorum()), (33, 67));
        for bound in [FaultBound::Seats, FaultBound::WholeMembers] {
            let t = BroadcastThresholds::of(&c, bound);
            assert_eq!(
                (t.vote, t.ack, t.ready, t.deliver, t.fast),
                (50, 66, 34, 67, 82)
            );
        }
    }

    #[test]
    fn an_epoch_counts_whole_members_from_the_activation_epoch_on() {
        assert_eq!(FaultBound::of_epoch(0, u64::MAX), FaultBound::Seats);
        assert_eq!(FaultBound::of_epoch(6, 7), FaultBound::Seats);
        assert_eq!(FaultBound::of_epoch(7, 7), FaultBound::WholeMembers);
        assert_eq!(FaultBound::of_epoch(8, 7), FaultBound::WholeMembers);
        assert_eq!(FaultBound::of_epoch(0, 0), FaultBound::WholeMembers);
    }

    #[test]
    fn the_fault_bound_is_the_heaviest_set_of_whole_members_within_f() {
        // One seat each: every count up to f is some set of members.
        for n in [1usize, 3, 4, 7, 10, 100] {
            let (c, _) = committee(n);
            assert_eq!(largest_faulty_weight(&c), c.max_faulty(), "n = {n}");
        }
        // Four validators of 200 seats: f is 266, but faulty validators hold 0 or 200.
        let c = seated(&[200, 200, 200, 200]);
        assert_eq!((c.max_faulty(), largest_faulty_weight(&c)), (266, 200));
        // Uneven: 100 + 100 and 200 both fit, 300 does not.
        assert_eq!(largest_faulty_weight(&seated(&[400, 200, 100, 100])), 200);
        assert_eq!(largest_faulty_weight(&seated(&[300, 250, 150, 100])), 250);
        // No single member fits within f: nothing can be faulty.
        assert_eq!(largest_faulty_weight(&seated(&[400, 400])), 0);
        // Above the limit the arithmetic bound stands.
        let big = seated(&[100_000, 100_000, 100_000, 100_000]);
        assert_eq!(largest_faulty_weight(&big), big.max_faulty());
    }

    #[test]
    fn the_bound_never_exceeds_f_and_keeps_n_at_least_3t_plus_1() {
        for seats in [
            vec![200u64; 4],
            vec![1; 7],
            vec![5, 4, 3, 2, 1],
            vec![400, 200, 100, 100],
            vec![9, 1, 1, 1],
        ] {
            let c = seated(&seats);
            let t = largest_faulty_weight(&c);
            assert!(t <= c.max_faulty());
            assert!(c.total_seats() > 3 * t);
        }
    }

    #[test]
    fn four_equal_validators_reach_the_two_step_threshold_with_one_silent() {
        let c = seated(&[200, 200, 200, 200]);
        let t = BroadcastThresholds::of(&c, FaultBound::WholeMembers);
        assert_eq!(
            (t.vote, t.ack, t.ready, t.deliver, t.fast),
            (400, 500, 201, 401, 599)
        );
        // Under the seat bound the thresholds are the ones f gives.
        let by_seats = BroadcastThresholds::of(&c, FaultBound::Seats);
        assert_eq!(
            (
                by_seats.vote,
                by_seats.ack,
                by_seats.ready,
                by_seats.deliver,
                by_seats.fast
            ),
            (400, 533, 267, 533, 665)
        );
        // The author's own ECHO and two others, the fourth silent.
        let echo = c.non_broadcaster_weight(0, 0)
            + c.non_broadcaster_weight(1, 0)
            + c.non_broadcaster_weight(2, 0);
        assert_eq!(echo, 599);
        assert!(echo >= t.fast);
        // With f in place of the bound the same three ECHOs fall short.
        assert!(echo < (c.total_seats() + 2 * c.max_faulty() - 2).div_ceil(2));
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

    /// Seats each group holds in the committee `stakes` give `infos`, built
    /// in the order given.
    fn group_seats(
        infos: &[ValidatorInfo],
        stakes: &[u128],
        groups: &[usize],
        order: &[usize],
        budget: u64,
    ) -> (Vec<u64>, u64) {
        let set = ValidatorSet::new(
            1,
            order
                .iter()
                .map(|i| ValidatorInfo {
                    stake: stakes[*i],
                    ..infos[*i].clone()
                })
                .collect(),
        )
        .unwrap();
        let c = from_validator_set(&set, budget).unwrap();
        let mut per = vec![0u64; groups.iter().max().unwrap() + 1];
        for m in c.members() {
            let i = infos.iter().position(|v| v.address == m.address).unwrap();
            per[groups[i]] += m.seats;
        }
        (per, c.total_seats())
    }

    /// Four of nine validators under one operator, holding most of the
    /// stake, end with at most the cap of the committee's seats, whatever
    /// order the set is built in and whatever the seat budget.
    #[test]
    fn one_operator_ends_at_or_below_its_cap_of_the_seats() {
        let (mut infos, _) = crate::validator::test_support::validators(9, 1_000);
        for v in infos.iter_mut().take(4) {
            v.stake = 5_000;
        }
        let groups = [0, 0, 0, 0, 1, 2, 3, 4, 5];
        for budget in [9u64, 100, 1_000, 64_000] {
            let raw: Vec<u128> = infos.iter().map(|v| v.stake).collect();
            let (before, total) =
                group_seats(&infos, &raw, &groups, &(0..9).collect::<Vec<_>>(), budget);
            assert!(before[0] * 10_000 > 3_300 * total, "{before:?}");
            let stakes = cap_group_stakes(&infos, &[(&groups[..], 3_300)], budget).unwrap();
            for order in [
                (0..9).collect::<Vec<_>>(),
                (0..9).rev().collect(),
                vec![4, 0, 5, 1, 6, 2, 7, 3, 8],
            ] {
                let (per, total) = group_seats(&infos, &stakes, &groups, &order, budget);
                assert!(
                    per[0] * 10_000 <= 3_300 * total,
                    "budget {budget}: {per:?} of {total}"
                );
            }
        }
    }

    /// An operator under the cap, and every operator when too few hold
    /// stake for the cap to hold for each, keep their stakes.
    #[test]
    fn stakes_change_only_for_an_operator_over_the_cap() {
        let (infos, _) = crate::validator::test_support::validators(9, 1_000);
        let groups = [0, 0, 1, 2, 3, 4, 5, 6, 7];
        let raw: Vec<u128> = infos.iter().map(|v| v.stake).collect();
        assert_eq!(
            cap_group_stakes(&infos, &[(&groups[..], 3_300)], 64_000).unwrap(),
            raw
        );
        let three = [0, 0, 0, 1, 1, 1, 2, 2, 2];
        assert_eq!(
            cap_group_stakes(&infos, &[(&three[..], 3_300)], 64_000).unwrap(),
            raw
        );
    }

    /// The group cap holds a group to the cap of the total it leaves, keeps
    /// each member's share of its group, and leaves the others as they were.
    #[test]
    fn the_group_cap_scales_a_group_down_to_the_cap_of_what_is_left() {
        let w = [600u128, 300, 100, 100, 100, 100];
        let g = [0, 0, 1, 2, 3, 4];
        let out = crate::validator::cap_group_weights(&w, &g, 3_000);
        let total: u128 = out.iter().sum();
        assert!((out[0] + out[1]) * 10_000 <= 3_000 * total);
        assert_eq!(out[2..], w[2..]);
        assert_eq!(out[0], 2 * out[1]);
    }

    /// An operator cap and a region cap together: no operator and no
    /// region ends above its cap of the seats, whatever the set's order.
    #[test]
    fn operator_and_region_caps_hold_together_on_the_seats() {
        let (mut infos, _) = crate::validator::test_support::validators(12, 1_000);
        for v in infos.iter_mut().take(3) {
            v.stake = 6_000;
        }
        let operators = [0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let regions = [0, 1, 2, 0, 0, 0, 1, 2, 3, 3, 4, 4];
        let stakes = cap_group_stakes(
            &infos,
            &[(&operators[..], 3_300), (&regions[..], 3_300)],
            64_000,
        )
        .unwrap();
        for order in [(0..12).collect::<Vec<_>>(), (0..12).rev().collect()] {
            for groups in [&operators[..], &regions[..]] {
                let (per, total) = group_seats(&infos, &stakes, groups, &order, 64_000);
                for g in per {
                    assert!(g * 10_000 <= 3_300 * total, "{g} of {total}");
                }
            }
        }
    }
}
