//! DAG vertices.
//!
//! A vertex is one validator's contribution to one round. It carries no
//! signature: it reaches other validators only through reliable broadcast
//! over authenticated channels, which fixes its author, and it is named by
//! the BLAKE3 digest of its canonical encoding, which fixes its content.

use serde::{Deserialize, Serialize};

use crate::committee::{Committee, SeatSet, ValidatorIndex};
use crate::error::{ConsensusError, Result};

pub use tenzro_finality::{Digest, Round};

/// A reference to another vertex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VertexRef {
    /// Round of the referenced vertex.
    pub round: Round,
    /// Its author.
    pub source: ValidatorIndex,
    /// Its digest.
    pub digest: Digest,
}

/// A transaction batch this vertex's author disseminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BatchRef {
    /// The author's sequence number of the batch.
    pub sequence: u64,
    /// Digest of the batch payload (see [`crate::batch::BatchPayload::digest`]).
    pub digest: Digest,
    /// Payload size in bytes.
    pub bytes: u32,
    /// Number of transactions.
    pub transactions: u32,
}

/// Another author's batch a leader vertex carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CarriedBatch {
    /// The batch's author.
    pub author: ValidatorIndex,
    /// The batch.
    pub batch: BatchRef,
}

/// One round's vertex from one author.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vertex {
    /// Epoch.
    pub epoch: u64,
    /// Round.
    pub round: Round,
    /// Author.
    pub source: ValidatorIndex,
    /// References to round `round - 1` vertices, carrying at least a quorum
    /// of seats. Empty only in round 0.
    pub strong: Vec<VertexRef>,
    /// References to older vertices not otherwise reachable, so every
    /// delivered vertex is eventually ordered.
    pub weak: Vec<VertexRef>,
    /// Batches this author introduces, in sequence order, continuing from
    /// the last batch its earlier vertices introduced. A validator echoes
    /// the vertex only once it holds all of them.
    pub batches: Vec<BatchRef>,
    /// Set by a leader of the round: other authors' batches it holds that no
    /// vertex it references introduced yet, sorted by author then
    /// sequence. They are ordered with the leader vertex when its slot is
    /// committed, a round before their authors' own vertices would be; any
    /// other vertex's carried batches are never ordered. A
    /// validator echoes the vertex only once it holds all of them, each
    /// under the author and sequence named here.
    pub carried: Vec<CarriedBatch>,
    /// Author's clock when the vertex was built, milliseconds.
    pub timestamp_ms: u64,
}

const VERTEX_DOMAIN: &[u8] = b"tenzro/consensus/vertex";

/// Largest number of references of each kind a vertex may carry.
pub const MAX_REFS: usize = 4_096;
/// Largest number of batches a vertex may introduce.
pub const MAX_BATCH_REFS: usize = 4_096;
/// Largest number of other authors' batches a vertex may carry.
pub const MAX_CARRIED: usize = 4_096;

impl Vertex {
    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("vertex encodes")
    }

    /// Digest naming this vertex.
    pub fn digest(&self) -> Digest {
        let mut h = blake3::Hasher::new();
        h.update(VERTEX_DOMAIN);
        h.update(&self.encode());
        h.finalize().into()
    }

    /// A reference to this vertex.
    pub fn reference(&self) -> VertexRef {
        VertexRef {
            round: self.round,
            source: self.source,
            digest: self.digest(),
        }
    }

    /// Whether this vertex strongly references `r`.
    pub fn references(&self, r: &VertexRef) -> bool {
        self.strong.iter().any(|s| s == r)
    }

    /// Whether this vertex strongly references any vertex of `source` in the
    /// previous round.
    pub fn references_author(&self, source: ValidatorIndex) -> bool {
        self.strong.iter().any(|s| s.source == source)
    }

    /// Checks everything about the vertex that needs no other vertex: the
    /// epoch, the author, the reference rounds, distinct strong authors
    /// carrying a quorum, and bounded list sizes.
    pub fn check_structure(&self, committee: &Committee) -> Result<()> {
        let bad = |why: &str| Err(ConsensusError::InvalidVertex(why.to_string()));
        if self.epoch != committee.epoch {
            return bad("vertex is for another epoch");
        }
        if committee.member(self.source).is_none() {
            return bad("vertex author is not a committee member");
        }
        if self.strong.len() > MAX_REFS
            || self.weak.len() > MAX_REFS
            || self.batches.len() > MAX_BATCH_REFS
            || self.carried.len() > MAX_CARRIED
        {
            return bad("vertex carries too many references");
        }
        if self
            .batches
            .windows(2)
            .any(|w| w[0].sequence.checked_add(1) != Some(w[1].sequence))
        {
            return bad("introduced batches are not consecutive");
        }
        if self
            .carried
            .iter()
            .any(|c| c.author == self.source || committee.member(c.author).is_none())
        {
            return bad("a carried batch must be another member's");
        }
        if self
            .carried
            .windows(2)
            .any(|w| (w[0].author, w[0].batch.sequence) >= (w[1].author, w[1].batch.sequence))
        {
            return bad("carried batches are not sorted by author and sequence");
        }
        if self.round == 0 {
            if !self.strong.is_empty() || !self.weak.is_empty() {
                return bad("a round-0 vertex has no parents");
            }
            return Ok(());
        }
        // Reference rounds are chosen by the author: compare them with the
        // previous round instead of adding to them.
        let previous = self.round - 1;
        let mut seats = SeatSet::new();
        for s in &self.strong {
            if s.round != previous {
                return bad("strong reference to a round other than the previous one");
            }
            if committee.member(s.source).is_none() {
                return bad("strong reference to a non-member");
            }
            if !seats.insert(s.source, committee.seats(s.source)) {
                return bad("two strong references to one author");
            }
        }
        if seats.weight() < committee.quorum() {
            return bad("strong references carry less than a quorum");
        }
        for w in &self.weak {
            if w.round >= previous || committee.member(w.source).is_none() {
                return bad("weak reference must name an older vertex of a member");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::test_support::committee;

    fn vertex(round: Round, source: ValidatorIndex, parents: &[ValidatorIndex]) -> Vertex {
        Vertex {
            epoch: 0,
            round,
            source,
            strong: parents
                .iter()
                .map(|p| VertexRef {
                    round: round - 1,
                    source: *p,
                    digest: [*p as u8; 32],
                })
                .collect(),
            weak: vec![],
            batches: vec![],
            carried: vec![],
            timestamp_ms: 7,
        }
    }

    #[test]
    fn a_vertex_needs_a_quorum_of_distinct_parents() {
        let (c, _) = committee(4);
        assert!(vertex(1, 0, &[0, 1, 2]).check_structure(&c).is_ok());
        assert!(vertex(1, 0, &[0, 1]).check_structure(&c).is_err());
        assert!(vertex(1, 0, &[0, 1, 1]).check_structure(&c).is_err());
        assert!(vertex(1, 9, &[0, 1, 2]).check_structure(&c).is_err());
    }

    #[test]
    fn references_and_batches_at_the_end_of_the_range_are_refused_without_panicking() {
        let (c, _) = committee(4);
        let mut strong = vertex(2, 0, &[0, 1, 2]);
        strong.strong[0].round = Round::MAX;
        assert!(strong.check_structure(&c).is_err());

        let mut weak = vertex(2, 0, &[0, 1, 2]);
        weak.weak.push(VertexRef {
            round: Round::MAX,
            source: 3,
            digest: [3; 32],
        });
        assert!(weak.check_structure(&c).is_err());

        let mut batches = vertex(1, 0, &[0, 1, 2]);
        batches.batches = [u64::MAX, 0]
            .into_iter()
            .map(|sequence| BatchRef {
                sequence,
                digest: [sequence as u8; 32],
                bytes: 1,
                transactions: 1,
            })
            .collect();
        assert!(batches.check_structure(&c).is_err());
    }

    #[test]
    fn the_digest_changes_with_any_field() {
        let a = vertex(1, 0, &[0, 1, 2]);
        let mut b = a.clone();
        b.timestamp_ms += 1;
        assert_ne!(a.digest(), b.digest());
        let mut c = a.clone();
        c.batches.push(BatchRef {
            sequence: 0,
            digest: [1; 32],
            bytes: 1,
            transactions: 1,
        });
        assert_ne!(a.digest(), c.digest());
    }

    #[test]
    fn introductions_are_consecutive() {
        let (c, _) = committee(4);
        let batch = |sequence| BatchRef {
            sequence,
            digest: [sequence as u8; 32],
            bytes: 1,
            transactions: 1,
        };
        let mut v = vertex(1, 0, &[0, 1, 2]);
        v.batches = vec![batch(4), batch(5)];
        assert!(v.check_structure(&c).is_ok());
        let mut x = v.clone();
        x.batches = vec![batch(4), batch(6)];
        assert!(x.check_structure(&c).is_err(), "a gap in the introductions");
    }

    #[test]
    fn carried_batches_are_other_members_sorted_and_distinct() {
        let (c, _) = committee(4);
        let carry = |author, sequence| CarriedBatch {
            author,
            batch: BatchRef {
                sequence,
                digest: [sequence as u8; 32],
                bytes: 1,
                transactions: 1,
            },
        };
        let mut v = vertex(1, 0, &[0, 1, 2]);
        v.carried = vec![carry(1, 3), carry(1, 4), carry(2, 0)];
        assert!(v.check_structure(&c).is_ok());
        let mut own = v.clone();
        own.carried = vec![carry(0, 3)];
        assert!(own.check_structure(&c).is_err(), "its own batch");
        let mut stranger = v.clone();
        stranger.carried = vec![carry(9, 0)];
        assert!(
            stranger.check_structure(&c).is_err(),
            "a non-member's batch"
        );
        let mut twice = v.clone();
        twice.carried = vec![carry(1, 3), carry(1, 3)];
        assert!(twice.check_structure(&c).is_err(), "one batch twice");
        let mut unsorted = v.clone();
        unsorted.carried = vec![carry(2, 0), carry(1, 3)];
        assert!(unsorted.check_structure(&c).is_err(), "out of order");
        let mut d = v.clone();
        d.carried.pop();
        assert_ne!(v.digest(), d.digest());
    }
}
