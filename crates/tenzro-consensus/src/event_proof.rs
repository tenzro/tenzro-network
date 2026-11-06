//! Proof that an event was emitted by the chain, checked against a
//! certified checkpoint.
//!
//! The chain of commitments runs: the event's leaf into its block header's
//! event root; the header's hash into the blocks root of the checkpoint
//! covering the block; that checkpoint's digest forward through the `prev`
//! links of each later checkpoint body to a certified one. Nothing in a proof
//! is trusted: [`EventProof::verify`] needs only the certified checkpoint,
//! which a [`LightClient`] accepted or a [`Certification`] establishes from
//! genesis.

use serde::{Deserialize, Serialize};
use tenzro_types::block::BlockHeader;
use tenzro_types::chain_event::{ChainEvent, EventCursor, IndexEntry, Projection};
use tenzro_types::merkle::{PathStep, root_from_path};

use crate::checkpoint::Checkpoint;
use crate::error::{ConsensusError, Result};
use crate::light_client::{Certification, GenesisAnchor, LightClient};
use crate::vertex::Digest;

/// An event, the header that commits it, and the checkpoints that carry the
/// header to a certified one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventProof {
    /// The event.
    pub event: ChainEvent,
    /// Path from the event's leaf to the header's event root.
    pub event_path: Vec<PathStep>,
    /// Header of the block that emitted the event.
    pub header: BlockHeader,
    /// Path from the header hash to the covering checkpoint's blocks root.
    pub block_path: Vec<PathStep>,
    /// Checkpoint bodies from the one covering the block up to the certified
    /// anchor, in index order, each the `prev` of the next.
    pub checkpoints: Vec<Checkpoint>,
}

fn invalid(msg: impl Into<String>) -> ConsensusError {
    ConsensusError::Malformed(format!("event proof: {}", msg.into()))
}

impl EventProof {
    /// The checkpoint the proof ends at, whose certification it relies on.
    pub fn anchor(&self) -> Option<&Checkpoint> {
        self.checkpoints.last()
    }

    /// Checks every link from the event to `certified`, a checkpoint the
    /// caller already knows is certified.
    pub fn verify(&self, certified: &Checkpoint) -> Result<()> {
        let height = self.header.height.0;
        if self.event.cursor.height != height {
            return Err(invalid(format!(
                "the event is at height {}, the header at {height}",
                self.event.cursor.height
            )));
        }
        if root_from_path(&self.event.leaf(), &self.event_path) != self.header.event_root.0 {
            return Err(invalid("the event is not under the header's event root"));
        }
        check_chain(&self.checkpoints, certified)?;
        check_header(&self.header, &self.block_path, &self.checkpoints)
    }
}

/// Checks that `checkpoints` is a run of consecutive checkpoint bodies, each
/// the `prev` of the next, ending at `certified`.
fn check_chain(checkpoints: &[Checkpoint], certified: &Checkpoint) -> Result<()> {
    let Some(anchor) = checkpoints.last() else {
        return Err(invalid("no checkpoint"));
    };
    for pair in checkpoints.windows(2) {
        if pair[1].prev != pair[0].digest() || Some(pair[1].index) != pair[0].index.checked_add(1) {
            return Err(invalid(format!(
                "checkpoint {} does not follow {}",
                pair[1].index, pair[0].index
            )));
        }
    }
    if anchor.digest() != certified.digest() {
        return Err(invalid(format!(
            "the proof ends at checkpoint {}, not at the certified checkpoint {}",
            anchor.index, certified.index
        )));
    }
    Ok(())
}

/// Checks that `header` is under the blocks root of the checkpoint in the
/// (already linked) `checkpoints` that covers its height.
fn check_header(
    header: &BlockHeader,
    block_path: &[tenzro_types::merkle::PathStep],
    checkpoints: &[Checkpoint],
) -> Result<()> {
    let height = header.height.0;
    let covering = checkpoints
        .iter()
        .find(|c| (c.first_height..=c.last_height).contains(&height))
        .ok_or_else(|| invalid(format!("no checkpoint of the proof covers height {height}")))?;
    if root_from_path(&header.hash().0, block_path) != covering.blocks_root {
        return Err(invalid(format!(
            "the header of block {height} is not under its checkpoint's blocks root"
        )));
    }
    Ok(())
}

/// An index entry of a block and its path to the block's event root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntryProof {
    /// The entry.
    pub entry: IndexEntry,
    /// Path from the entry's leaf to the header's event root.
    pub path: Vec<PathStep>,
}

/// One block's index entries for the keys a read asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockIndexProof {
    /// The block's header.
    pub header: BlockHeader,
    /// Path from the header hash to its checkpoint's blocks root.
    pub block_path: Vec<PathStep>,
    /// For each key, in the order of [`CompletenessProof::keys`], the entry
    /// that speaks for it.
    pub entries: Vec<IndexEntryProof>,
}

/// Proof that a read left nothing out: for every block from `first_height`
/// to the height of `through`, the index entries covering each of `keys`,
/// so a verifier knows every event the read could have selected after
/// `after` and through `through`. Candidates the answer leaves out because
/// the filter rejects them are proven in `excluded`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletenessProof {
    /// The index keys covered, hex.
    pub keys: Vec<String>,
    /// The first block covered.
    pub first_height: u64,
    /// Events at or before this cursor are not part of the read.
    pub after: Option<EventCursor>,
    /// The last cursor the read covers.
    pub through: EventCursor,
    /// One proof per block, in height order.
    pub blocks: Vec<BlockIndexProof>,
    /// Checkpoint bodies from the one covering `first_height` to the
    /// certified anchor.
    pub checkpoints: Vec<Checkpoint>,
    /// Proofs of the candidate events the filter rejects.
    pub excluded: Vec<EventProof>,
}

impl CompletenessProof {
    /// Checks the proof against `certified` for a read whose filter maps to
    /// `keys` and selects an event when `selects` says so: `answer` must be
    /// exactly the selected events among every event the covered entries
    /// list in the range. The answer's own inclusion proofs are checked by
    /// the caller.
    pub fn verify(
        &self,
        certified: &Checkpoint,
        keys: &[Vec<u8>],
        answer: &[ChainEvent],
        selects: &dyn Fn(&ChainEvent) -> bool,
    ) -> Result<()> {
        let wanted: Vec<String> = keys.iter().map(hex::encode).collect();
        if self.keys != wanted {
            return Err(invalid(
                "the proof covers other index keys than the filter needs",
            ));
        }
        if self.after.is_some_and(|a| a > self.through) {
            return Err(invalid("the range ends before it starts"));
        }
        // A read past `after` through `through` holds nothing only when the
        // two meet; any other read is covered block by block from where it
        // starts: the block of `after`, or the chain's first block.
        if self.after == Some(self.through) {
            if !self.blocks.is_empty() {
                return Err(invalid("an empty range carries no block proofs"));
            }
        } else {
            if self.blocks.is_empty() {
                return Err(invalid(
                    "a read that covers events proves at least one block",
                ));
            }
            check_chain(&self.checkpoints, certified)?;
            let start = match self.after {
                Some(a) => a.height,
                None => {
                    let first = &self.checkpoints[0];
                    if first.index != 0 {
                        return Err(invalid(
                            "a read from the start proves the chain from its first checkpoint",
                        ));
                    }
                    first.first_height
                }
            };
            if self.first_height != start {
                return Err(invalid(format!(
                    "the proof starts at height {}, the read at {start}",
                    self.first_height
                )));
            }
        }
        let span = self
            .through
            .height
            .checked_sub(self.first_height)
            .and_then(|d| d.checked_add(1))
            .unwrap_or(0);
        if self.blocks.len() as u64 != span {
            return Err(invalid(format!(
                "{} block proofs for {span} heights",
                self.blocks.len()
            )));
        }
        let in_range = |c: &EventCursor| self.after.is_none_or(|a| *c > a) && *c <= self.through;
        let mut candidates = std::collections::BTreeSet::new();
        for (i, block) in self.blocks.iter().enumerate() {
            let height = self.first_height + i as u64;
            if block.header.height.0 != height {
                return Err(invalid(format!(
                    "block proof {i} is for height {}, not {height}",
                    block.header.height.0
                )));
            }
            check_header(&block.header, &block.block_path, &self.checkpoints)?;
            if block.entries.len() != keys.len() {
                return Err(invalid(format!(
                    "block {height} proves {} entries for {} keys",
                    block.entries.len(),
                    keys.len()
                )));
            }
            for (key, proof) in keys.iter().zip(&block.entries) {
                if root_from_path(&proof.entry.leaf(), &proof.path) != block.header.event_root.0 {
                    return Err(invalid(format!(
                        "an index entry is not under block {height}'s event root"
                    )));
                }
                let listed = proof.entry.covers(key).ok_or_else(|| {
                    invalid(format!(
                        "block {height}'s entry does not speak for key {}",
                        hex::encode(key)
                    ))
                })?;
                for c in listed {
                    if c.height != height {
                        return Err(invalid(format!(
                            "block {height}'s index lists an event at height {}",
                            c.height
                        )));
                    }
                    if in_range(c) {
                        candidates.insert(*c);
                    }
                }
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for e in answer {
            if !candidates.contains(&e.cursor) {
                return Err(invalid(format!(
                    "event {} is outside the range or under no covered key",
                    e.cursor
                )));
            }
            if !selects(e) {
                return Err(invalid(format!(
                    "event {} does not match the filter",
                    e.cursor
                )));
            }
            seen.insert(e.cursor);
        }
        for proof in &self.excluded {
            proof.verify(certified)?;
            if !candidates.contains(&proof.event.cursor) || selects(&proof.event) {
                return Err(invalid(format!(
                    "event {} is not a candidate the filter rejects",
                    proof.event.cursor
                )));
            }
            seen.insert(proof.event.cursor);
        }
        if let Some(missing) = candidates.difference(&seen).next() {
            return Err(invalid(format!(
                "event {missing} is under a covered key but neither answered nor excluded"
            )));
        }
        Ok(())
    }
}

/// An [`EventProof`] with the proof from genesis that its anchor is
/// certified: everything a client holding only the genesis anchor needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertifiedEventProof {
    /// The inclusion proof.
    pub proof: EventProof,
    /// Certification of the proof's anchor checkpoint.
    pub certification: Certification,
}

impl CertifiedEventProof {
    /// The event, once the anchor's certification verifies from `genesis`
    /// (a chained one against `handover_program`, its receipt checked by
    /// `verify_receipt`) and the inclusion proof verifies against it.
    pub fn verify<F>(
        &self,
        genesis: &GenesisAnchor,
        handover_program: Option<Digest>,
        verify_receipt: F,
    ) -> Result<&ChainEvent>
    where
        F: FnOnce(&Digest, &[u8]) -> std::result::Result<Vec<u8>, String>,
    {
        let certified = self
            .certification
            .verify(genesis, handover_program, verify_receipt)?;
        self.proof.verify(certified)?;
        Ok(&self.proof.event)
    }
}

/// An index's answer: a projection of events, with the proof of every event
/// it was computed from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenAnswer {
    /// What was computed.
    pub projection: Projection,
    /// The answer.
    pub result: serde_json::Value,
    /// The events the answer was computed from, in cursor order, each with
    /// its proof.
    pub proofs: Vec<EventProof>,
}

impl ProvenAnswer {
    /// Checks every proof against `certified`, the checkpoint the caller
    /// knows is certified, and that the answer is the projection of exactly
    /// the proven events.
    pub fn verify(&self, certified: &Checkpoint) -> Result<()> {
        for proof in &self.proofs {
            proof.verify(certified)?;
        }
        let events: Vec<ChainEvent> = self.proofs.iter().map(|p| p.event.clone()).collect();
        if events.windows(2).any(|w| w[0].cursor >= w[1].cursor) {
            return Err(invalid("the answer's events are not in cursor order"));
        }
        if self.projection.apply(&events) != self.result {
            return Err(invalid(
                "the answer is not the projection of its proven events",
            ));
        }
        Ok(())
    }
}

impl LightClient {
    /// Checks `proof` against the latest checkpoint this client accepted.
    pub fn verify_event(&self, proof: &EventProof) -> Result<()> {
        let latest = self
            .latest()
            .ok_or_else(|| invalid("the light client has accepted no checkpoint"))?;
        proof.verify(latest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{checkpoint_state_height, merkle_root};
    use tenzro_types::block::BlockMetadata;
    use tenzro_types::chain_event::{
        ChainEventKind, block_index, event_root, event_tree_leaves, index_key, transaction_events,
    };
    use tenzro_types::merkle::merkle_path;
    use tenzro_types::primitives::{Address, BlockHeight, Hash, Timestamp};

    fn header(height: u64, events: &[ChainEvent]) -> BlockHeader {
        BlockHeader {
            height: BlockHeight(height),
            epoch: 0,
            round: height,
            anchor: Hash::new([height as u8; 32]),
            prev_hash: Hash::zero(),
            tx_root: Hash::zero(),
            state_root: Hash::zero(),
            event_root: event_root(events),
            receipts_root: Hash::zero(),
            logs_bloom: tenzro_types::LogsBloom::default(),
            timestamp: Timestamp::new(height as i64),
            proposer: Address::zero(),
            metadata: BlockMetadata::default(),
        }
    }

    fn checkpoint(
        index: u64,
        prev: [u8; 32],
        first: u64,
        last: u64,
        blocks_root: [u8; 32],
    ) -> Checkpoint {
        Checkpoint {
            chain_id: 1,
            genesis_hash: [0; 32],
            epoch: 0,
            index,
            prev,
            first_height: first,
            last_height: last,
            blocks_root,
            state_height: checkpoint_state_height(first, last),
            state_root: [0; 32],
            statement_root: [0; 32],
            next_committee_root: None,
            anchor_round: last,
            timestamp_ms: last,
            ordering_root: [0; 32],
        }
    }

    /// Blocks 1..=3 under checkpoint 0, block 4 under checkpoint 1; the
    /// proof is for the second event of block 2, anchored at checkpoint 1.
    fn fixture() -> EventProof {
        let topics = [vec![3u8; 32]];
        let mut per_block = Vec::new();
        for h in 1..=4u64 {
            let logs = [(&[h as u8; 20][..], &topics[..], &b"payload"[..])];
            per_block.push(transaction_events(
                h,
                0,
                Hash::new([h as u8; 32]),
                true,
                21_000,
                None,
                logs,
            ));
        }
        let headers: Vec<BlockHeader> = (0..4)
            .map(|i| header(i as u64 + 1, &per_block[i]))
            .collect();
        let hashes: Vec<[u8; 32]> = headers[..3].iter().map(|h| h.hash().0).collect();
        let cp0 = checkpoint(0, [0; 32], 1, 3, merkle_root(&hashes));
        let cp1 = checkpoint(1, cp0.digest(), 4, 4, merkle_root(&[headers[3].hash().0]));
        let events = &per_block[1];
        let leaves = event_tree_leaves(events);
        EventProof {
            event: events[1].clone(),
            event_path: merkle_path(&leaves, 1).unwrap(),
            header: headers[1].clone(),
            block_path: merkle_path(&hashes, 1).unwrap(),
            checkpoints: vec![cp0, cp1],
        }
    }

    #[test]
    fn an_emitted_event_verifies_against_the_certified_checkpoint() {
        let proof = fixture();
        let certified = proof.anchor().unwrap().clone();
        proof.verify(&certified).unwrap();
    }

    #[test]
    fn a_tampered_event_fails() {
        let proof = fixture();
        let certified = proof.anchor().unwrap().clone();

        let mut p = proof.clone();
        if let ChainEventKind::Log { data, .. } = &mut p.event.kind {
            data[0] ^= 1;
        }
        assert!(p.verify(&certified).is_err(), "changed log data");

        let mut p = proof.clone();
        p.event.cursor.event_index = 0;
        assert!(p.verify(&certified).is_err(), "moved cursor");

        let mut p = proof.clone();
        p.header.event_root = Hash::new([1; 32]);
        assert!(
            p.verify(&certified).is_err(),
            "header rewritten to match nothing"
        );

        let mut p = proof.clone();
        p.checkpoints[0].blocks_root[0] ^= 1;
        assert!(
            p.verify(&certified).is_err(),
            "covering checkpoint body altered"
        );

        let mut other = certified.clone();
        other.state_root[0] ^= 1;
        assert!(
            proof.verify(&other).is_err(),
            "a checkpoint that is not the certified one"
        );
    }

    #[test]
    fn an_index_answer_verifies_only_as_the_projection_of_its_proofs() {
        let proof = fixture();
        let certified = proof.anchor().unwrap().clone();
        let answer = ProvenAnswer {
            projection: Projection::Count,
            result: serde_json::json!(1),
            proofs: vec![proof.clone()],
        };
        answer.verify(&certified).unwrap();

        let mut inflated = answer.clone();
        inflated.result = serde_json::json!(2);
        assert!(
            inflated.verify(&certified).is_err(),
            "a count its proofs do not support"
        );

        let mut forged = answer.clone();
        if let ChainEventKind::Log { data, .. } = &mut forged.proofs[0].event.kind {
            data[0] ^= 1;
        }
        assert!(
            forged.verify(&certified).is_err(),
            "an event the chain did not emit"
        );

        let doubled = ProvenAnswer {
            result: serde_json::json!(2),
            proofs: vec![proof.clone(), proof],
            ..answer
        };
        assert!(
            doubled.verify(&certified).is_err(),
            "one event counted twice"
        );
    }

    /// Blocks 1..=3 under one checkpoint: block 1 has a log of contract A,
    /// block 2 none, block 3 two logs of A and one of B.
    fn completeness_fixture() -> (CompletenessProof, Vec<ChainEvent>, Checkpoint, Vec<u8>) {
        let a = [0xAAu8; 20];
        let b = [0xBBu8; 20];
        let none: Vec<Vec<u8>> = Vec::new();
        let blocks: Vec<Vec<ChainEvent>> = vec![
            transaction_events(
                1,
                0,
                Hash::new([1; 32]),
                true,
                1,
                None,
                [(&a[..], &none[..], &b"1"[..])],
            ),
            transaction_events(2, 0, Hash::new([2; 32]), true, 1, None, std::iter::empty()),
            transaction_events(
                3,
                0,
                Hash::new([3; 32]),
                true,
                1,
                None,
                [
                    (&a[..], &none[..], &b"2"[..]),
                    (&b[..], &none[..], &b"3"[..]),
                    (&a[..], &none[..], &b"4"[..]),
                ],
            ),
        ];
        let headers: Vec<BlockHeader> = blocks
            .iter()
            .enumerate()
            .map(|(i, e)| header(i as u64 + 1, e))
            .collect();
        let hashes: Vec<[u8; 32]> = headers.iter().map(|h| h.hash().0).collect();
        let cp = checkpoint(0, [0; 32], 1, 3, merkle_root(&hashes));
        let key = index_key::address(&a);
        let mut proofs = Vec::new();
        let mut answer = Vec::new();
        for (i, events) in blocks.iter().enumerate() {
            let index = block_index(events);
            let at = index.iter().position(|e| e.covers(&key).is_some()).unwrap();
            let leaves = event_tree_leaves(events);
            proofs.push(BlockIndexProof {
                header: headers[i].clone(),
                block_path: merkle_path(&hashes, i).unwrap(),
                entries: vec![IndexEntryProof {
                    entry: index[at].clone(),
                    path: merkle_path(&leaves, events.len() + at).unwrap(),
                }],
            });
            answer.extend(
                events
                    .iter()
                    .filter(|e| e.log_address() == Some(&a[..]))
                    .cloned(),
            );
        }
        let proof = CompletenessProof {
            keys: vec![hex::encode(&key)],
            first_height: 1,
            after: None,
            through: EventCursor::new(3, u32::MAX, u32::MAX),
            blocks: proofs,
            checkpoints: vec![cp.clone()],
            excluded: Vec::new(),
        };
        (proof, answer, cp, key)
    }

    #[test]
    fn a_filtered_read_proves_it_left_nothing_out() {
        let (proof, answer, cp, key) = completeness_fixture();
        assert_eq!(answer.len(), 3);
        let selects = |e: &ChainEvent| e.log_address() == Some(&[0xAAu8; 20][..]);
        proof
            .verify(&cp, std::slice::from_ref(&key), &answer, &selects)
            .unwrap();

        // Omitting any one event is caught.
        for skip in 0..answer.len() {
            let mut short = answer.clone();
            short.remove(skip);
            assert!(
                proof
                    .verify(&cp, std::slice::from_ref(&key), &short, &selects)
                    .is_err(),
                "omitted {skip}"
            );
        }
        // An entry with a cursor dropped no longer proves under the root.
        let mut p = proof.clone();
        p.blocks[2].entries[0].entry.cursors.pop();
        assert!(
            p.verify(&cp, std::slice::from_ref(&key), &answer[..2], &selects)
                .is_err()
        );
        // Skipping a block is caught.
        let mut p = proof.clone();
        p.blocks.remove(1);
        assert!(
            p.verify(&cp, std::slice::from_ref(&key), &answer, &selects)
                .is_err()
        );
        // Claiming the empty block holds nothing under another entry is caught.
        let mut p = proof.clone();
        p.blocks[1].entries[0] = p.blocks[0].entries[0].clone();
        assert!(
            p.verify(&cp, std::slice::from_ref(&key), &answer, &selects)
                .is_err()
        );
        // A proof for other keys is refused.
        let other = index_key::address(&[0xBBu8; 20]);
        assert!(proof.verify(&cp, &[other], &answer, &selects).is_err());
    }

    /// The covered range starts where the read does: a proof that starts
    /// later, covers no block at all, or names heights at the end of the
    /// range is refused, and none of them panics.
    #[test]
    fn a_proof_must_cover_the_read_from_its_start() {
        let (proof, answer, cp, key) = completeness_fixture();
        let selects = |e: &ChainEvent| e.log_address() == Some(&[0xAAu8; 20][..]);
        let keys = std::slice::from_ref(&key);

        // Starting at the last block drops the first block's event.
        let mut late = proof.clone();
        late.first_height = 3;
        late.blocks = vec![proof.blocks[2].clone()];
        assert!(late.verify(&cp, keys, &answer[1..], &selects).is_err());

        // No block at all.
        let mut empty = proof.clone();
        empty.first_height = 4;
        empty.blocks.clear();
        assert!(empty.verify(&cp, keys, &[], &selects).is_err());

        // A range to the last height.
        let mut huge = proof.clone();
        huge.first_height = 0;
        huge.through = EventCursor::new(u64::MAX, u32::MAX, u32::MAX);
        assert!(huge.verify(&cp, keys, &answer, &selects).is_err());

        // A read after a cursor starts at the cursor's block.
        let mut after = proof.clone();
        after.after = Some(EventCursor::new(1, u32::MAX, u32::MAX));
        after.verify(&cp, keys, &answer[1..], &selects).unwrap();
        let mut skipped = after.clone();
        skipped.first_height = 3;
        skipped.blocks = vec![proof.blocks[2].clone()];
        assert!(skipped.verify(&cp, keys, &answer[1..], &selects).is_err());
        // Nothing past the cursor: an empty proof says so.
        let mut nothing = proof.clone();
        nothing.after = Some(nothing.through);
        nothing.first_height = 4;
        nothing.blocks.clear();
        nothing.verify(&cp, keys, &[], &selects).unwrap();
    }

    #[test]
    fn a_candidate_the_filter_rejects_must_be_proven() {
        let (proof, answer, cp, key) = completeness_fixture();
        // A narrower filter: only contract A's logs with data "4".
        let selects =
            |e: &ChainEvent| matches!(&e.kind, ChainEventKind::Log { data, .. } if data == b"4");
        let narrow: Vec<ChainEvent> = answer.iter().filter(|e| selects(e)).cloned().collect();
        assert!(
            proof
                .verify(&cp, std::slice::from_ref(&key), &narrow, &selects)
                .is_err(),
            "rejected candidates unproven"
        );
    }
}
