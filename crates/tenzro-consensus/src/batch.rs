//! Transaction batches and their availability.
//!
//! Every validator cuts its mempool into [`BatchPart`]s as transactions
//! arrive and pushes each as a batch at once, numbered by a per-author
//! sequence; its next vertex introduces the batches pushed since the last.
//! A validator echoes a vertex in reliable broadcast only once it holds
//! every batch the vertex introduces (see [`crate::core`]), so a delivered
//! vertex's batches are held by the honest validators among its echoers, at
//! least one of them whichever path delivered it, and every validator can
//! fetch them. Availability therefore costs no round of its own: a batch is
//! ordered with the vertex that introduced it.
//!
//! The round's leader also carries the batches it holds that no vertex it
//! references introduced yet (see [`crate::vertex::Vertex::carried`]). When
//! the leader vertex is the committed anchor they are ordered with it, a
//! round earlier than their authors' own vertices would order them; the
//! later introduction of the same sequence is then ignored. A validator
//! echoes a leader vertex only once it holds every carried batch under the
//! author and sequence it is carried as, and fetches a missing one from the
//! leader, so an author that sends different batches to different
//! validators delays the leader's vertex by one fetch at most, and otherwise
//! only keeps its own vertex from being delivered.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::committee::ValidatorIndex;
use crate::vertex::{BatchRef, Digest, MAX_BATCH_REFS, Round, Vertex};

/// The validator of a committee of `n` that batches `sender`'s transactions
/// first. All of one sender's transactions go to one validator, which
/// batches them in nonce order: spread by transaction, a sender's next
/// nonce often reached a block ahead of the one before it and failed, and
/// every later one of that sender with it. The node and the simulator route
/// through this one function.
pub fn assigned_validator(sender: &tenzro_types::primitives::Address, n: u64) -> u64 {
    let d = blake3::hash(sender.as_bytes());
    u64::from_be_bytes(d.as_bytes()[..8].try_into().expect("8 bytes")) % n.max(1)
}

/// Largest batch payload.
pub const MAX_BATCH_BYTES: usize = 1 << 20;

/// Bytes each part costs in a sealed body beyond its own: its length.
const PART_HEADER_BYTES: usize = 4;

/// Largest part a batch can hold.
pub const MAX_PART_BYTES: usize = MAX_BATCH_BYTES - PART_HEADER_BYTES;

/// A slice of one validator's mempool, cut by the caller: an opaque encoding
/// of `transactions` transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchPart {
    /// Transactions it encodes.
    pub transactions: u32,
    /// Their encoding.
    pub bytes: Vec<u8>,
}

/// A batch as disseminated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchPayload {
    /// Epoch.
    pub epoch: u64,
    /// Author.
    pub author: ValidatorIndex,
    /// The author's batch sequence number within the epoch.
    pub sequence: u64,
    /// Number of transactions in `body`.
    pub transactions: u32,
    /// The sealed parts: each a 4-byte big-endian length, then that many
    /// bytes.
    #[serde(with = "whole_bytes")]
    pub body: Vec<u8>,
}

/// A byte vector encoded as one block: the same bytes bincode writes for a
/// `Vec<u8>` (its length, then each byte), written and read in one copy
/// rather than one element at a time, which made encoding and decoding
/// megabytes of batches the larger part of a validator's work.
mod whole_bytes {
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct Bytes;
        impl<'de> Visitor<'de> for Bytes {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(1 << 20));
                while let Some(b) = seq.next_element()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(Bytes)
    }
}

impl BatchPayload {
    /// Seals `parts`, in order, into one batch.
    pub fn seal(epoch: u64, author: ValidatorIndex, sequence: u64, parts: &[BatchPart]) -> Self {
        let mut body = Vec::with_capacity(
            parts
                .iter()
                .map(|p| PART_HEADER_BYTES + p.bytes.len())
                .sum(),
        );
        let mut transactions = 0u32;
        for p in parts {
            body.extend_from_slice(&(p.bytes.len() as u32).to_be_bytes());
            body.extend_from_slice(&p.bytes);
            transactions = transactions.saturating_add(p.transactions);
        }
        Self {
            epoch,
            author,
            sequence,
            transactions,
            body,
        }
    }

    /// The parts sealed into this batch, in order. None if the body is not a
    /// well-formed sequence of parts.
    pub fn parts(&self) -> Option<Vec<&[u8]>> {
        let mut out = Vec::new();
        let mut rest = self.body.as_slice();
        while !rest.is_empty() {
            let (len, tail) = rest.split_first_chunk::<PART_HEADER_BYTES>()?;
            let len = u32::from_be_bytes(*len) as usize;
            if tail.len() < len {
                return None;
            }
            let (part, tail) = tail.split_at(len);
            out.push(part);
            rest = tail;
        }
        Some(out)
    }

    /// Digest naming this batch.
    pub fn digest(&self) -> Digest {
        let mut h = blake3::Hasher::new();
        h.update(b"tenzro/consensus/batch");
        h.update(&self.epoch.to_be_bytes());
        h.update(&self.author.to_be_bytes());
        h.update(&self.sequence.to_be_bytes());
        h.update(&self.transactions.to_be_bytes());
        h.update(&self.body);
        h.finalize().into()
    }

    /// The reference a vertex carries.
    pub fn reference(&self) -> BatchRef {
        BatchRef {
            sequence: self.sequence,
            digest: self.digest(),
            bytes: self.body.len() as u32,
            transactions: self.transactions,
        }
    }
}

/// A batch the availability filter released, in segment order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderedBatch {
    /// The batch.
    pub batch: BatchRef,
    /// The batch's author.
    pub author: ValidatorIndex,
    /// Round of the vertex that introduced or carried it.
    pub round: Round,
}

/// Most introductions of one author that may wait ordered ahead of an
/// earlier sequence of the same author; further ones are ignored.
pub const MAX_UNRELEASED_PER_AUTHOR: usize = 4_096;

/// Batches released as the ordered history introduces them.
///
/// An author's batches are released in sequence order: an introduction
/// ordered ahead of an earlier sequence of its author (an author's vertex
/// need not be an ancestor of its next one) waits for the gap to fill. The
/// first introduction ordered for a sequence is the one released.
#[derive(Default)]
pub struct Availability {
    /// Per author, the sequence of its first unreleased batch.
    next: HashMap<ValidatorIndex, u64>,
    /// Per author, introductions ordered ahead of `next`, by sequence.
    early: HashMap<ValidatorIndex, BTreeMap<u64, (Round, usize, BatchRef)>>,
    /// Released since the last [`Availability::release`], in order.
    ready: Vec<(Round, ValidatorIndex, usize, BatchRef)>,
}

impl Availability {
    /// Empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accounts for one newly ordered vertex.
    pub fn on_ordered(&mut self, v: &Vertex) {
        for (position, b) in v.batches.iter().enumerate() {
            self.introduce(v.source, v.round, position, b);
        }
        self.advance(v.source);
    }

    /// Accounts for the batches the committed anchor `v` carries. They
    /// follow the anchor's own introductions in the release order.
    pub fn on_carried(&mut self, v: &Vertex) {
        for (i, c) in v.carried.iter().enumerate() {
            self.introduce(c.author, v.round, MAX_BATCH_REFS + i, &c.batch);
        }
        let mut authors: Vec<ValidatorIndex> = v.carried.iter().map(|c| c.author).collect();
        authors.dedup();
        for a in authors {
            self.advance(a);
        }
    }

    fn introduce(&mut self, author: ValidatorIndex, round: Round, position: usize, b: &BatchRef) {
        let next = self.next.get(&author).copied().unwrap_or(0);
        // The last sequence has no successor for the frontier to move to,
        // so no author may use it: every released sequence then leaves the
        // frontier one past it.
        if b.sequence < next || b.sequence == u64::MAX {
            return;
        }
        let early = self.early.entry(author).or_default();
        if early.len() < MAX_UNRELEASED_PER_AUTHOR || early.contains_key(&b.sequence) {
            early.entry(b.sequence).or_insert((round, position, *b));
        }
    }

    fn advance(&mut self, author: ValidatorIndex) {
        let next = self.next.entry(author).or_insert(0);
        if let Some(early) = self.early.get_mut(&author) {
            while let Some((round, position, b)) = early.remove(next) {
                self.ready.push((round, author, position, b));
                *next += 1;
            }
        }
    }

    /// Gives up on gaps no vertex can fill any more. An author introduces
    /// its batches in sequence order, so the vertex that would fill a gap
    /// before an introduction made in round `r` is of a round below `r`;
    /// once `r` is at or below `floor`, the lowest round the DAG still holds,
    /// that vertex can never be ordered. The waiting introductions are then
    /// released and the gap skipped. `floor` must be a function of the
    /// ordered history (the DAG floor after the previous commit), so every
    /// validator skips the same gaps.
    pub fn expire_gaps(&mut self, floor: Round) {
        for (author, early) in &mut self.early {
            let Some((&first, &(round, _, _))) = early.iter().next() else {
                continue;
            };
            let next = self.next.entry(*author).or_insert(0);
            if round > floor || first <= *next {
                continue;
            }
            *next = first;
            while let Some((round, position, b)) = early.remove(next) {
                self.ready.push((round, *author, position, b));
                *next += 1;
            }
        }
    }

    /// Batches released since the last call, in deterministic order: by the
    /// round, author and position of the introducing vertex.
    pub fn release(&mut self) -> Vec<OrderedBatch> {
        let mut ready = std::mem::take(&mut self.ready);
        ready.sort_by_key(|a| (a.0, a.1, a.2));
        ready
            .into_iter()
            .map(|(round, author, _, batch)| OrderedBatch {
                batch,
                author,
                round,
            })
            .collect()
    }

    /// The sequence of `author`'s first unreleased batch. A validator need
    /// not keep what is already ordered.
    pub fn released_through(&self, author: ValidatorIndex) -> u64 {
        self.next.get(&author).copied().unwrap_or(0)
    }

    /// The release frontier, in a canonical order.
    pub fn export(&self) -> crate::ordering::AvailabilityState {
        let mut next: Vec<(ValidatorIndex, u64)> = self
            .next
            .iter()
            .filter(|(_, s)| **s > 0)
            .map(|(a, s)| (*a, *s))
            .collect();
        next.sort_unstable();
        let mut early: Vec<(ValidatorIndex, Vec<(u64, Round, u64, BatchRef)>)> = self
            .early
            .iter()
            .filter(|(_, m)| !m.is_empty())
            .map(|(a, m)| {
                (
                    *a,
                    m.iter()
                        .map(|(s, (r, p, b))| (*s, *r, *p as u64, *b))
                        .collect(),
                )
            })
            .collect();
        early.sort_unstable_by_key(|(a, _)| *a);
        crate::ordering::AvailabilityState { next, early }
    }

    /// The frontier `state` was exported from, with nothing released yet.
    pub fn import(state: &crate::ordering::AvailabilityState) -> Self {
        Self {
            next: state.next.iter().copied().collect(),
            early: state
                .early
                .iter()
                .map(|(a, v)| {
                    (
                        *a,
                        v.iter()
                            .map(|(s, r, p, b)| (*s, (*r, *p as usize, *b)))
                            .collect(),
                    )
                })
                .collect(),
            ready: Vec::new(),
        }
    }

    /// Introductions ordered but waiting for an earlier sequence.
    pub fn pending_len(&self) -> usize {
        self.early.values().map(BTreeMap::len).sum()
    }
}

#[cfg(test)]
mod tests {
    /// A batch encodes to exactly the bytes it did as a plain `Vec<u8>`, so
    /// journals and frames written before decode the same, and back.
    #[test]
    fn a_batch_encodes_as_it_did_with_a_plain_byte_vector() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Plain {
            epoch: u64,
            author: super::ValidatorIndex,
            sequence: u64,
            transactions: u32,
            body: Vec<u8>,
        }
        let p = super::BatchPayload {
            epoch: 3,
            author: 2,
            sequence: 7,
            transactions: 2,
            body: (0..=255u8).cycle().take(5_000).collect(),
        };
        let plain = Plain {
            epoch: p.epoch,
            author: p.author,
            sequence: p.sequence,
            transactions: p.transactions,
            body: p.body.clone(),
        };
        let ours = bincode::serialize(&p).unwrap();
        assert_eq!(ours, bincode::serialize(&plain).unwrap());
        assert_eq!(
            bincode::deserialize::<super::BatchPayload>(&ours).unwrap(),
            p
        );
        use bincode::Options;
        let opts = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(1 << 20);
        let framed = opts.serialize(&p).unwrap();
        assert_eq!(framed, opts.serialize(&plain).unwrap());
        assert_eq!(opts.deserialize::<super::BatchPayload>(&framed).unwrap(), p);
    }

    use super::*;

    /// Every transaction of one sender goes to one validator, and senders
    /// spread across the committee.
    #[test]
    fn a_sender_is_assigned_to_one_validator() {
        use tenzro_types::primitives::Address;
        let n = 7;
        let sender = |b: u8| Address::new([b; 32]);
        let mut seen = std::collections::HashSet::new();
        for b in 0..=255u8 {
            let v = assigned_validator(&sender(b), n);
            assert!(v < n);
            assert_eq!(v, assigned_validator(&sender(b), n));
            seen.insert(v);
        }
        assert_eq!(seen.len() as u64, n, "senders spread over every validator");
    }

    fn vertex(round: Round, source: ValidatorIndex, batches: Vec<BatchRef>) -> Vertex {
        Vertex {
            epoch: 0,
            round,
            source,
            strong: vec![],
            weak: vec![],
            batches,
            carried: vec![],
            timestamp_ms: 0,
        }
    }

    fn batch(author: ValidatorIndex, seq: u64) -> BatchPayload {
        BatchPayload {
            epoch: 0,
            author,
            sequence: seq,
            transactions: 1,
            body: vec![seq as u8, author as u8, 1, 2],
        }
    }

    /// A Byzantine author's batch at the last sequence neither overflows the
    /// release frontier nor rewinds it to release the author's batches again.
    #[test]
    fn a_batch_at_the_last_sequence_does_not_wrap_the_frontier() {
        let mut a = Availability::new();
        a.on_ordered(&vertex(1, 0, vec![batch(0, 0).reference()]));
        assert_eq!(a.released_through(0), 1);
        assert_eq!(a.release().len(), 1);
        a.on_ordered(&vertex(2, 0, vec![batch(0, u64::MAX).reference()]));
        a.expire_gaps(2);
        a.expire_gaps(3);
        assert!(a.released_through(0) >= 1);
        a.on_ordered(&vertex(3, 0, vec![batch(0, 0).reference()]));
        assert!(
            a.release().iter().all(|b| b.batch.sequence != 0),
            "sequence 0 was released twice"
        );
    }

    #[test]
    fn sealed_parts_come_back_in_order_and_malformed_bodies_are_refused() {
        let parts = vec![
            BatchPart {
                transactions: 2,
                bytes: vec![1, 2, 3],
            },
            BatchPart {
                transactions: 0,
                bytes: vec![],
            },
            BatchPart {
                transactions: 5,
                bytes: vec![9; 70],
            },
        ];
        let p = BatchPayload::seal(3, 1, 7, &parts);
        assert_eq!(p.transactions, 7);
        let back: Vec<Vec<u8>> = p.parts().unwrap().into_iter().map(<[u8]>::to_vec).collect();
        assert_eq!(
            back,
            parts.iter().map(|x| x.bytes.clone()).collect::<Vec<_>>()
        );
        assert_eq!(BatchPayload::seal(3, 1, 7, &[]).parts().unwrap().len(), 0);
        let mut truncated = p.clone();
        truncated.body.pop();
        assert!(
            truncated.parts().is_none(),
            "a part shorter than its length"
        );
        let mut header_only = p.clone();
        header_only.body = vec![0, 0];
        assert!(header_only.parts().is_none(), "a partial length");
    }

    #[test]
    fn a_batch_is_released_with_the_vertex_that_introduces_it_once() {
        let mut a = Availability::new();
        let b = [batch(0, 0).reference()];
        a.on_ordered(&vertex(1, 0, b.to_vec()));
        let out = a.release();
        assert_eq!(out.len(), 1);
        assert_eq!(
            (out[0].author, out[0].round, out[0].batch.digest),
            (0, 1, b[0].digest)
        );
        // Introduced again (a faulty author) or a different batch claimed
        // for the same sequence: already released, ignored.
        let mut other = batch(0, 0);
        other.body.push(9);
        a.on_ordered(&vertex(2, 0, vec![b[0], other.reference()]));
        assert!(a.release().is_empty());
        assert_eq!(a.released_through(0), 1);
    }

    #[test]
    fn introductions_ordered_out_of_sequence_wait_for_the_gap() {
        let mut a = Availability::new();
        let bs: Vec<BatchRef> = (0..3).map(|s| batch(0, s).reference()).collect();
        // The author's later vertex is ordered before its earlier one.
        a.on_ordered(&vertex(2, 0, bs[1..].to_vec()));
        assert!(a.release().is_empty(), "sequence 0 is not introduced yet");
        assert_eq!(a.pending_len(), 2);
        a.on_ordered(&vertex(1, 0, bs[..1].to_vec()));
        let got: Vec<u64> = a.release().iter().map(|o| o.batch.sequence).collect();
        assert_eq!(got, vec![0, 1, 2]);
        assert_eq!(a.pending_len(), 0);
    }

    #[test]
    fn a_gap_no_vertex_can_fill_any_more_is_skipped() {
        let mut a = Availability::new();
        let bs: Vec<BatchRef> = (0..4).map(|s| batch(0, s).reference()).collect();
        // Sequence 0 and 1 were introduced by a vertex that was never
        // ordered; 2 and 3 by the author's vertex of round 5.
        a.on_ordered(&vertex(5, 0, bs[2..].to_vec()));
        a.expire_gaps(4);
        assert!(
            a.release().is_empty(),
            "round 5 is above the floor: the gap may still fill"
        );
        a.expire_gaps(5);
        let got: Vec<u64> = a.release().iter().map(|o| o.batch.sequence).collect();
        assert_eq!(got, vec![2, 3]);
        assert_eq!(a.released_through(0), 4);
        a.on_ordered(&vertex(4, 0, bs[..2].to_vec()));
        assert!(
            a.release().is_empty(),
            "the skipped sequences are never released afterwards"
        );
    }

    #[test]
    fn release_order_is_by_introducing_round_author_and_position() {
        let mut a = Availability::new();
        let x = [batch(2, 0).reference()];
        let yz = [batch(1, 0).reference(), batch(1, 1).reference()];
        a.on_ordered(&vertex(1, 2, x.to_vec()));
        a.on_ordered(&vertex(1, 1, yz.to_vec()));
        let order: Vec<Digest> = a.release().iter().map(|o| o.batch.digest).collect();
        assert_eq!(order, vec![yz[0].digest, yz[1].digest, x[0].digest]);
    }

    #[test]
    fn a_carried_batch_is_released_with_the_anchor_and_its_later_introduction_ignored() {
        use crate::vertex::CarriedBatch;
        let mut a = Availability::new();
        let own = batch(0, 0).reference();
        let others: Vec<BatchRef> = (0..2).map(|s| batch(1, s).reference()).collect();
        let mut anchor = vertex(3, 0, vec![own]);
        anchor.carried = others
            .iter()
            .map(|b| CarriedBatch {
                author: 1,
                batch: *b,
            })
            .collect();
        a.on_ordered(&anchor);
        a.on_carried(&anchor);
        let out = a.release();
        let got: Vec<(ValidatorIndex, u64, Round)> = out
            .iter()
            .map(|o| (o.author, o.batch.sequence, o.round))
            .collect();
        assert_eq!(
            got,
            vec![(0, 0, 3), (1, 0, 3), (1, 1, 3)],
            "released under the batch author, at the anchor's round"
        );
        assert_eq!(a.released_through(1), 2);
        // The author's own vertex introducing the same batches is ordered
        // later: nothing is released twice.
        a.on_ordered(&vertex(4, 1, others.clone()));
        assert!(a.release().is_empty());
    }
}
