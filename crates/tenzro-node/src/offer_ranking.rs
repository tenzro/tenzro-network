//! The order in which a network offer for a named model is chosen.
//!
//! An unpinned call names a model and no provider, so every live
//! announcement for it that passed the verification, payee and self-dial
//! checks is a candidate. The candidates are ranked on facts this node already
//! holds: whether the provider has room to take the call (its announced
//! capacity), its standing read from consensus state, the price its signed
//! card quotes for a reference call, the median latency it reports to its
//! peers, and its announced load. Equal candidates are ordered by payee
//! address and then endpoint id, so every node facing the same data makes the
//! same choice whatever order the announcement map yields them in.

use std::cmp::Reverse;

/// The reference call every card is priced at when offers are compared.
pub const REFERENCE_INPUT_TOKENS: u32 = 1_000;
/// The reference call every card is priced at when offers are compared.
pub const REFERENCE_OUTPUT_TOKENS: u32 = 1_000;

/// What one candidate announcement is ranked on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferRank {
    /// The provider announced room for at least one more request. A provider
    /// that announces no capacity record counts as having room.
    pub has_room: bool,
    /// The provider's standing from consensus state, 0 without a live bond.
    pub standing: u64,
    /// The card's charge for the reference call, `u128::MAX` when the card
    /// does not price it.
    pub price: u128,
    /// Median latency to peers the provider reports, `u32::MAX` when it
    /// reports none.
    pub latency_ms: u32,
    /// Announced load in basis points of its concurrent-request limit.
    pub load_bps: u32,
    /// The payee the call settles to.
    pub payee: [u8; 32],
    /// The iroh endpoint the call is dialled on.
    pub endpoint_id: String,
}

impl OfferRank {
    /// Announced load from the provider's capacity record.
    pub fn load_bps(active: u32, max: u32) -> u32 {
        if max == 0 {
            return 0;
        }
        ((u64::from(active) * 10_000) / u64::from(max)).min(10_000) as u32
    }

    /// Whether the capacity record leaves room for another request.
    pub fn room(active: u32, max: u32) -> bool {
        max == 0 || active < max
    }

    /// The sort key: smaller ranks first.
    fn key(&self) -> (Reverse<bool>, Reverse<u64>, u128, u32, u32, [u8; 32], &str) {
        (
            Reverse(self.has_room),
            Reverse(self.standing),
            self.price,
            self.latency_ms,
            self.load_bps,
            self.payee,
            self.endpoint_id.as_str(),
        )
    }
}

/// The index of the best candidate, `None` for an empty list.
pub fn best(candidates: &[OfferRank]) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| a.key().cmp(&b.key()))
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rank(payee: u8) -> OfferRank {
        OfferRank {
            has_room: true,
            standing: 0,
            price: 100,
            latency_ms: 50,
            load_bps: 0,
            payee: [payee; 32],
            endpoint_id: format!("ep{payee}"),
        }
    }

    #[test]
    fn a_bonded_provider_beats_a_cheaper_unbonded_one() {
        let mut cheap = rank(1);
        cheap.price = 10;
        let mut bonded = rank(2);
        bonded.standing = 6_000;
        bonded.price = 90;
        assert_eq!(best(&[cheap, bonded]), Some(1));
    }

    #[test]
    fn at_equal_standing_the_cheaper_price_wins() {
        let mut dear = rank(1);
        dear.standing = 5_000;
        dear.price = 200;
        let mut cheap = rank(2);
        cheap.standing = 5_000;
        cheap.price = 150;
        assert_eq!(best(&[dear, cheap]), Some(1));
    }

    #[test]
    fn a_card_that_does_not_price_the_call_ranks_last_on_price() {
        let mut unpriced = rank(1);
        unpriced.price = u128::MAX;
        let priced = rank(2);
        assert_eq!(best(&[unpriced, priced]), Some(1));
    }

    #[test]
    fn a_provider_with_no_room_loses_to_one_with_room_whatever_its_standing() {
        let mut full = rank(1);
        full.has_room = false;
        full.standing = 9_000;
        let open = rank(2);
        assert_eq!(best(&[full, open]), Some(1));
    }

    #[test]
    fn latency_then_load_break_a_tie_on_standing_and_price() {
        let mut slow = rank(1);
        slow.latency_ms = 200;
        let fast = rank(2);
        assert_eq!(best(&[slow, fast.clone()]), Some(1));
        let mut busy = rank(3);
        busy.load_bps = 9_000;
        assert_eq!(best(&[busy, fast]), Some(1));
    }

    #[test]
    fn the_choice_does_not_depend_on_the_order_candidates_arrive_in() {
        let all = [rank(5), rank(3), rank(9), rank(4)];
        let expected = all.iter().map(|r| r.payee).min().unwrap();
        for rotation in 0..all.len() {
            let mut rotated = all.to_vec();
            rotated.rotate_left(rotation);
            let pick = best(&rotated).unwrap();
            assert_eq!(rotated[pick].payee, expected);
        }
    }

    #[test]
    fn one_payee_on_two_endpoints_is_ordered_by_endpoint_id() {
        let mut a = rank(7);
        a.endpoint_id = "zz".into();
        let mut b = rank(7);
        b.endpoint_id = "aa".into();
        assert_eq!(best(&[a, b]), Some(1));
    }

    #[test]
    fn nothing_to_choose_from_is_none() {
        assert_eq!(best(&[]), None);
    }

    #[test]
    fn load_and_room_read_the_capacity_record() {
        assert_eq!(OfferRank::load_bps(5, 10), 5_000);
        assert_eq!(OfferRank::load_bps(50, 10), 10_000);
        assert_eq!(OfferRank::load_bps(3, 0), 0);
        assert!(OfferRank::room(9, 10));
        assert!(!OfferRank::room(10, 10));
        assert!(OfferRank::room(100, 0));
    }
}
