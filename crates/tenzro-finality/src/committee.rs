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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tenzro_types::primitives::Address;

use crate::error::{FinalityError, Result};
use crate::key::ValidatorPublicKey;

/// Index of a validator within its epoch's committee.
pub type ValidatorIndex = u16;

/// Default seat budget apportioned across a committee.
pub const DEFAULT_SEAT_BUDGET: u64 = 1_000;

/// One committee member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Account address.
    pub address: Address,
    /// Composite public key.
    pub public_key: ValidatorPublicKey,
    /// Bonded stake.
    pub stake: u128,
    /// Seats this member holds.
    pub seats: u64,
}

/// Most seats one committee may hold in all.
pub const MAX_TOTAL_SEATS: u64 = u32::MAX as u64;

/// The committee of one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Committee {
    /// Epoch number.
    pub epoch: u64,
    members: Vec<Member>,
    total_seats: u64,
    #[serde(skip)]
    by_address: HashMap<Address, ValidatorIndex>,
}

impl Committee {
    /// A committee from explicit members.
    pub fn from_members(epoch: u64, members: Vec<Member>) -> Result<Self> {
        if members.is_empty() || members.len() > ValidatorIndex::MAX as usize {
            return Err(FinalityError::InvalidValidatorSet(format!(
                "a committee holds 1 to {} members, got {}",
                ValidatorIndex::MAX,
                members.len()
            )));
        }
        let mut keys = std::collections::HashSet::new();
        let mut addresses = std::collections::HashSet::new();
        if !members
            .iter()
            .all(|m| keys.insert(m.public_key.fingerprint()) && addresses.insert(m.address))
        {
            return Err(FinalityError::InvalidValidatorSet(
                "two members share a key or an address".into(),
            ));
        }
        if members.iter().any(|m| m.seats == 0) {
            return Err(FinalityError::InvalidValidatorSet(
                "every member holds at least one seat".into(),
            ));
        }
        let total_seats = members
            .iter()
            .try_fold(0u64, |t, m| t.checked_add(m.seats))
            .filter(|t| *t <= MAX_TOTAL_SEATS)
            .ok_or_else(|| {
                FinalityError::InvalidValidatorSet(format!(
                    "a committee holds at most {MAX_TOTAL_SEATS} seats in all"
                ))
            })?;
        let mut c = Self {
            epoch,
            members,
            total_seats,
            by_address: HashMap::new(),
        };
        c.rebuild_index();
        Ok(c)
    }

    /// Restores the address index after deserialisation.
    pub fn rebuild_index(&mut self) {
        self.by_address = self
            .members
            .iter()
            .enumerate()
            .map(|(i, m)| (m.address, i as ValidatorIndex))
            .collect();
    }

    /// Number of members.
    pub fn size(&self) -> usize {
        self.members.len()
    }

    /// The members in index order.
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// Member `index`.
    pub fn member(&self, index: ValidatorIndex) -> Option<&Member> {
        self.members.get(index as usize)
    }

    /// Index of `address`.
    pub fn index_of(&self, address: &Address) -> Option<ValidatorIndex> {
        self.by_address.get(address).copied()
    }

    /// Seats held by member `index` (zero for an unknown index).
    pub fn seats(&self, index: ValidatorIndex) -> u64 {
        self.member(index).map_or(0, |m| m.seats)
    }

    /// Total seats, `n`.
    pub fn total_seats(&self) -> u64 {
        self.total_seats
    }

    /// Largest tolerated Byzantine seat count, `f = (n - 1) / 3`.
    pub fn max_faulty(&self) -> u64 {
        (self.total_seats - 1) / 3
    }

    /// Quorum, `n - f` (`2f + 1` when `n = 3f + 1`). Any two quorums share at
    /// least `f + 1` seats, so at least one honest seat.
    pub fn quorum(&self) -> u64 {
        self.total_seats - self.max_faulty()
    }

    /// `f + 1`: weight that contains at least one honest seat.
    pub fn validity(&self) -> u64 {
        self.max_faulty() + 1
    }

    /// `2f + 1`: READY weight at which reliable broadcast delivers.
    pub fn ready_delivery(&self) -> u64 {
        2 * self.max_faulty() + 1
    }

    /// Non-broadcaster ECHO weight at which a party sends VOTE, `ceil(n / 2)`.
    pub fn rbc_vote_threshold(&self) -> u64 {
        self.total_seats.div_ceil(2)
    }

    /// Non-broadcaster weight of VOTE or ECHO (for ACK) and of ACK (for
    /// READY), `ceil((n + f - 1) / 2)`.
    pub fn rbc_ack_threshold(&self) -> u64 {
        (self.total_seats + self.max_faulty() - 1).div_ceil(2)
    }

    /// Non-broadcaster ECHO weight at which reliable broadcast delivers in
    /// two steps, `ceil((n + 2f - 2) / 2)`.
    pub fn rbc_fast_threshold(&self) -> u64 {
        (self.total_seats + 2 * self.max_faulty())
            .saturating_sub(2)
            .div_ceil(2)
    }

    /// Weight a message from `sender` carries in a broadcast by
    /// `broadcaster`: every seat of the sender except the broadcaster's own
    /// seat, which is not a non-broadcaster party.
    pub fn non_broadcaster_weight(
        &self,
        sender: ValidatorIndex,
        broadcaster: ValidatorIndex,
    ) -> u64 {
        let s = self.seats(sender);
        if sender == broadcaster {
            s.saturating_sub(1)
        } else {
            s
        }
    }

    /// Root committing the ordered member list: address, key and stake.
    pub fn root(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"tenzro/consensus/committee");
        h.update(&self.epoch.to_be_bytes());
        h.update(&(self.members.len() as u64).to_be_bytes());
        for m in &self.members {
            h.update(m.address.as_bytes());
            h.update(&m.public_key.fingerprint());
            h.update(&m.stake.to_be_bytes());
            h.update(&m.seats.to_be_bytes());
        }
        h.finalize().into()
    }
}

/// A set of validators counted by seats.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeatSet {
    bits: Vec<u64>,
    weight: u64,
}

impl SeatSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `index` with `seats`; returns whether it was new.
    pub fn insert(&mut self, index: ValidatorIndex, seats: u64) -> bool {
        let (word, bit) = (index as usize / 64, index as usize % 64);
        if self.bits.len() <= word {
            self.bits.resize(word + 1, 0);
        }
        if self.bits[word] & (1 << bit) != 0 {
            return false;
        }
        self.bits[word] |= 1 << bit;
        self.weight += seats;
        true
    }

    /// Whether `index` is present.
    pub fn contains(&self, index: ValidatorIndex) -> bool {
        let (word, bit) = (index as usize / 64, index as usize % 64);
        self.bits.get(word).is_some_and(|w| w & (1 << bit) != 0)
    }

    /// Total seats of the members.
    pub fn weight(&self) -> u64 {
        self.weight
    }

    /// The members in ascending index order.
    pub fn iter(&self) -> impl Iterator<Item = ValidatorIndex> + '_ {
        self.bits.iter().enumerate().flat_map(|(w, bits)| {
            (0..64)
                .filter(move |b| bits & (1u64 << b) != 0)
                .map(move |b| (w * 64 + b) as ValidatorIndex)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(byte: u8, seats: u64) -> Member {
        Member {
            address: Address::new([byte; 32]),
            public_key: ValidatorPublicKey {
                ml_dsa: vec![byte; 4],
                p256: vec![byte; 4],
            },
            stake: 1,
            seats,
        }
    }

    /// Two members on one key or one address are refused: session
    /// certificates are filed by key, so the second could never count.
    #[test]
    fn a_committee_with_a_repeated_key_or_address_is_refused() {
        let mut same_key = m(2, 1);
        same_key.public_key = m(1, 1).public_key;
        assert!(Committee::from_members(0, vec![m(1, 1), same_key]).is_err());
        let mut same_address = m(2, 1);
        same_address.address = m(1, 1).address;
        assert!(Committee::from_members(0, vec![m(1, 1), same_address]).is_err());
        assert!(Committee::from_members(0, vec![m(1, 1), m(2, 1)]).is_ok());
    }

    /// Seats that overflow when summed, or exceed the most a committee may
    /// hold, are refused rather than wrapped.
    #[test]
    fn seats_past_the_committee_limit_are_refused_without_overflow() {
        assert!(Committee::from_members(0, vec![m(1, u64::MAX), m(2, 1)]).is_err());
        assert!(Committee::from_members(0, vec![m(1, MAX_TOTAL_SEATS), m(2, 1)]).is_err());
        let c = Committee::from_members(0, vec![m(1, MAX_TOTAL_SEATS - 1), m(2, 1)]).unwrap();
        assert_eq!(c.total_seats(), MAX_TOTAL_SEATS);
        let _ = c.quorum();
    }
}
