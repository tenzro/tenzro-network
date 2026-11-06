//! The arithmetic of a validator set that survives a failure.
//!
//! One definition, used by every place that decides whether a set of
//! validators may exist or lose a member: the genesis launch check, the
//! pre-stop guard, and the epoch planner's ejection of inactive validators.
//! A set is *accepted* when it has at least [`MIN_LAUNCH_VALIDATORS`]
//! members, its live stake is above two thirds of its stake, and it is still
//! above two thirds after its largest live member is lost (a live spare).
//! These are consequences of `n >= 3f + 1` with `f = 1`, not tunable values.

/// Fewest validators that tolerate one failure: `3f + 1` with `f = 1`.
pub const MIN_LAUNCH_VALIDATORS: usize = 4;

/// Wei in one TNZO.
pub const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

/// A validator's consensus voting power for a self-stake in wei: whole TNZO
/// rounded down, never below 1 for a non-zero stake (a validator that holds
/// stake always holds a vote), 0 for no stake. The one definition: the node's
/// committee, the ejection guard, the stop guard and the launch check all
/// weigh validators with it, so none can accept a set consensus would not.
pub fn voting_power(self_stake_wei: u128) -> u128 {
    match self_stake_wei {
        0 => 0,
        wei => (wei / ONE_TNZO).max(1),
    }
}

/// Whether `part` is strictly more than two thirds of `total`, without
/// overflow for any real stake.
pub fn above_two_thirds(part: u128, total: u128) -> bool {
    part.checked_mul(3)
        .zip(total.checked_mul(2))
        .map(|(p, t)| p > t)
        .unwrap_or_else(|| part / 2 > total / 3)
}

/// Whether a set whose members all answer holds the launch arithmetic:
/// enough members, and the stake left after the largest one is lost is still
/// above two thirds. `stakes` are the members' voting powers
/// ([`voting_power`]); a set whose powers are all zero holds no vote and is
/// refused, the same as the launch check refuses it.
pub fn all_live_set_accepted(stakes: &[u128]) -> bool {
    if stakes.len() < MIN_LAUNCH_VALIDATORS {
        return false;
    }
    let total: u128 = stakes.iter().sum();
    if total == 0 {
        return false;
    }
    let largest = stakes.iter().copied().max().unwrap_or(0);
    above_two_thirds(total, total) && above_two_thirds(total - largest, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_equal_members_are_accepted_and_three_are_not() {
        // Lose one of four: 3 of 4 is above two thirds.
        assert!(all_live_set_accepted(&[1, 1, 1, 1]));
        assert!(!all_live_set_accepted(&[1, 1, 1]));
    }

    #[test]
    fn a_heavy_member_is_weighed_by_stake() {
        // [2,1,1,1,1,1,1]: lose the 2, 6 of 8 = 0.75 > 2/3: accepted.
        assert!(all_live_set_accepted(&[2, 1, 1, 1, 1, 1, 1]));
        // [2,1,1,1]: lose the 2, 3 of 5 = 0.6: refused although it has 4 members.
        assert!(!all_live_set_accepted(&[2, 1, 1, 1]));
    }

    #[test]
    fn a_set_with_no_voting_power_is_refused() {
        assert!(!all_live_set_accepted(&[0; 7]));
    }

    /// The rounding boundaries of the shared voting power.
    #[test]
    fn voting_power_rounds_down_with_a_floor_of_one() {
        assert_eq!(voting_power(0), 0);
        assert_eq!(voting_power(1), 1);
        assert_eq!(voting_power(ONE_TNZO - 1), 1);
        assert_eq!(voting_power(ONE_TNZO), 1);
        assert_eq!(voting_power(2 * ONE_TNZO - 1), 1);
        assert_eq!(voting_power(2 * ONE_TNZO), 2);
        assert_eq!(voting_power(10_000 * ONE_TNZO + ONE_TNZO / 2), 10_000);
    }

    /// Review case D1: stakes [2.0, 1.99, 1.99, 1.99] TNZO look like a set
    /// with a spare in raw wei (5.97 of 7.97 after the loss) but carry the
    /// powers [2, 1, 1, 1], where 3 of 5 is not above two thirds.
    #[test]
    fn the_guard_weighs_in_consensus_units_not_raw_wei() {
        let wei = [
            2 * ONE_TNZO,
            199 * ONE_TNZO / 100,
            199 * ONE_TNZO / 100,
            199 * ONE_TNZO / 100,
        ];
        assert!(all_live_set_accepted(&wei), "raw wei accepts it");
        let powers: Vec<u128> = wei.iter().map(|w| voting_power(*w)).collect();
        assert_eq!(powers, [2, 1, 1, 1]);
        assert!(!all_live_set_accepted(&powers));
    }
}
