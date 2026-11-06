//! Checks blocks must pass before a node executes them when they did not
//! come out of this node's own consensus.
//!
//! Blocks arrive from peers over gossip (`tenzro/blocks`) and block-sync.
//! No block carries a signature of its own: validators certify blocks in
//! ranges, one checkpoint certificate per range, and the checkpoint's blocks
//! root commits the hash of every header in it. A follower therefore holds
//! received blocks until a certificate covering them arrives, and then:
//!
//! 1. verifies the certificate against the committee of its epoch
//!    ([`crate::consensus_driver::ConsensusHandle::accept_certificate`]);
//! 2. checks the range: exactly the certificate's heights, whose header
//!    hashes rebuild its blocks root ([`check_range`]);
//! 3. executes the blocks in order, each the successor of the local tip
//!    with the body its header commits to ([`check_successor`]), and each
//!    claiming the state root this node computed for its lagged height
//!    ([`check_state_root`]);
//! 4. checks its own post-state root at the certificate's state height
//!    against the one the certificate commits.

use tenzro_consensus::checkpoint::{Checkpoint, merkle_root, state_root_height};
use tenzro_types::block::Block;
use tenzro_types::primitives::Hash;

/// The local chain tip a candidate block must extend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    /// Height of the last executed block.
    pub height: u64,
    /// Hash of the last executed block.
    pub hash: Hash,
    /// Timestamp of the last executed block, in milliseconds.
    pub timestamp_ms: i64,
}

/// Checks that `block` extends `tip` and carries the body its header commits
/// to. Block timestamps never go backwards; consecutive blocks may share one.
pub fn check_successor(block: &Block, tip: &ChainTip) -> Result<(), String> {
    let height = block.height().0;
    if height != tip.height + 1 {
        return Err(format!(
            "block at height {height} does not extend the local tip at height {}",
            tip.height
        ));
    }
    if block.header.prev_hash != tip.hash {
        return Err(format!(
            "block at height {height} links to {} but the local tip is {}",
            block.header.prev_hash, tip.hash
        ));
    }
    let ts = block.header.timestamp.as_millis();
    if ts < tip.timestamp_ms {
        return Err(format!(
            "block at height {height} has timestamp {ts} ms, before its parent's {} ms",
            tip.timestamp_ms
        ));
    }
    block.verify_body()
}

/// Checks that `blocks` are exactly the range checkpoint `cp` covers, in
/// height order, and that their header hashes rebuild its blocks root. The
/// checkpoint itself is authenticated by the caller: by a certificate, or by
/// the digest a later authenticated checkpoint names as its predecessor.
pub fn check_range(cp: &Checkpoint, blocks: &[Block]) -> Result<(), String> {
    // A checkpoint decided while no block was ordered covers none
    // (`first_height` one past `last_height`).
    let expected = (cp.last_height + 1).saturating_sub(cp.first_height);
    if blocks.len() as u64 != expected {
        return Err(format!(
            "checkpoint {} covers heights {}..={} but {} blocks were supplied",
            cp.index,
            cp.first_height,
            cp.last_height,
            blocks.len()
        ));
    }
    for (i, b) in blocks.iter().enumerate() {
        if b.height().0 != cp.first_height + i as u64 {
            return Err(format!(
                "block {i} of checkpoint {} is at height {}",
                cp.index,
                b.height()
            ));
        }
    }
    let hashes: Vec<[u8; 32]> = blocks.iter().map(|b| b.hash().0).collect();
    if merkle_root(&hashes) != cp.blocks_root {
        return Err(format!(
            "the blocks do not rebuild checkpoint {}'s blocks root",
            cp.index
        ));
    }
    Ok(())
}

/// Checks the header's state root against the root this node computed for
/// the lagged height. `local` is `None` when this node has no root for that
/// height, which is itself a refusal: a block whose state claim cannot be
/// checked is not executed.
pub fn check_state_root(block: &Block, local: Option<Hash>) -> Result<(), String> {
    let claimed = block.header.state_root;
    let at = state_root_height(block.height().0);
    match local {
        Some(root) if root == claimed => Ok(()),
        Some(root) => Err(format!(
            "block at height {} claims state root {claimed} for height {at}, this node computed {root}",
            block.height()
        )),
        None => Err(format!(
            "block at height {} claims state root {claimed} for height {at}, which this node has not computed",
            block.height()
        )),
    }
}

/// Checks this node's post-state root at the checkpoint's state height
/// against the root the checkpoint commits.
pub fn check_certified_state(cp: &Checkpoint, local: Option<Hash>) -> Result<(), String> {
    let at = cp.state_height;
    match local {
        Some(root) if root.0 == cp.state_root => Ok(()),
        Some(root) => Err(format!(
            "checkpoint {} commits state root {} at height {at}, this node computed {root}",
            cp.index,
            hex::encode(cp.state_root)
        )),
        None => Err(format!(
            "checkpoint {} commits a state root at height {at}, which this node has not computed",
            cp.index
        )),
    }
}

/// Authenticates checkpoint bodies against one verified checkpoint by the
/// chain of predecessor digests: each body counts only if its digest is the
/// `prev` of an already authenticated one. Returns the authenticated bodies
/// in ascending index order, `verified` included.
pub fn authenticate_chain(verified: &Checkpoint, bodies: &[Checkpoint]) -> Vec<Checkpoint> {
    authenticate_chain_to(verified, bodies, u64::MAX, |_| None)
}

/// As [`authenticate_chain`], with `local` (the bodies this node recorded
/// itself) standing in where the served `bodies` lack one or hold another,
/// for as long as the chain has not reached back to the block after `tip`.
/// A peer may hold a certificate without every body below it; the
/// predecessor digests authenticate a body wherever it came from.
pub fn authenticate_chain_to(
    verified: &Checkpoint,
    bodies: &[Checkpoint],
    tip: u64,
    local: impl Fn(u64) -> Option<Checkpoint>,
) -> Vec<Checkpoint> {
    let by_index: std::collections::HashMap<u64, &Checkpoint> =
        bodies.iter().map(|b| (b.index, b)).collect();
    let links = |prev: &Checkpoint, cur: &Checkpoint| {
        prev.digest() == cur.prev
            && prev.chain_id == cur.chain_id
            && prev.genesis_hash == cur.genesis_hash
    };
    let mut out = vec![verified.clone()];
    let mut cur = verified.clone();
    while cur.index > 0 {
        let served = by_index
            .get(&(cur.index - 1))
            .map(|b| (*b).clone())
            .filter(|b| links(b, &cur));
        let prev = match served {
            Some(b) => b,
            None if cur.first_height > tip.saturating_add(1) => {
                match local(cur.index - 1).filter(|b| links(b, &cur)) {
                    Some(b) => b,
                    None => break,
                }
            }
            None => break,
        };
        out.push(prev.clone());
        cur = prev;
    }
    out.reverse();
    out
}

/// Checks a weak-subjectivity checkpoint: at the checkpoint height the block
/// must be the trusted block, by hash. Blocks at other heights pass.
pub fn check_checkpoint(block: &Block, checkpoint: Option<(u64, Hash)>) -> Result<(), String> {
    let Some((height, hash)) = checkpoint else {
        return Ok(());
    };
    if block.height().0 != height {
        return Ok(());
    }
    let actual = block.hash();
    if actual != hash {
        return Err(format!(
            "block at checkpoint height {height} is {actual}, the trusted checkpoint is {hash}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::block::{BlockHeader, BlockMetadata};
    use tenzro_types::primitives::{Address, BlockHeight, Timestamp};

    fn block_on(tip: &ChainTip, ts_ms: i64) -> Block {
        let header = BlockHeader {
            height: BlockHeight(tip.height + 1),
            epoch: 0,
            round: tip.height + 1,
            anchor: Hash::new([9; 32]),
            prev_hash: tip.hash,
            tx_root: Hash::zero(),
            state_root: Hash::zero(),
            event_root: Hash::zero(),
            receipts_root: Hash::zero(),
            logs_bloom: tenzro_types::LogsBloom::default(),
            timestamp: Timestamp::new(ts_ms),
            proposer: Address::zero(),
            metadata: BlockMetadata::default(),
        };
        Block::new(header, Vec::new())
    }

    fn tip() -> ChainTip {
        ChainTip {
            height: 5,
            hash: Hash::new([7; 32]),
            timestamp_ms: 1_000,
        }
    }

    fn chain(n: usize) -> Vec<Block> {
        let mut t = tip();
        let mut out = Vec::new();
        for _ in 0..n {
            let b = block_on(&t, t.timestamp_ms + 10);
            t = ChainTip {
                height: b.height().0,
                hash: b.hash(),
                timestamp_ms: b.header.timestamp.as_millis(),
            };
            out.push(b);
        }
        out
    }

    fn checkpoint_over(blocks: &[Block]) -> Checkpoint {
        let hashes: Vec<[u8; 32]> = blocks.iter().map(|b| b.hash().0).collect();
        Checkpoint {
            chain_id: 1,
            genesis_hash: [0; 32],
            epoch: 0,
            index: 3,
            prev: [0; 32],
            first_height: blocks[0].height().0,
            last_height: blocks.last().unwrap().height().0,
            blocks_root: merkle_root(&hashes),
            state_height: state_root_height(blocks.last().unwrap().height().0),
            state_root: [5; 32],
            statement_root: [0; 32],
            next_committee_root: None,
            anchor_round: 1,
            timestamp_ms: 0,
            ordering_root: [0; 32],
        }
    }

    #[test]
    fn bodies_are_authenticated_only_through_the_predecessor_chain() {
        let blocks = chain(6);
        let mut a = checkpoint_over(&blocks[..2]);
        a.index = 1;
        let mut b = checkpoint_over(&blocks[2..4]);
        b.index = 2;
        b.prev = a.digest();
        let mut c = checkpoint_over(&blocks[4..]);
        c.index = 3;
        c.prev = b.digest();
        let got = authenticate_chain(&c, &[a.clone(), b.clone()]);
        assert_eq!(
            got.iter().map(|x| x.index).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        let mut forged = b.clone();
        forged.state_root = [9; 32];
        let got = authenticate_chain(&c, &[a, forged]);
        assert_eq!(
            got.iter().map(|x| x.index).collect::<Vec<_>>(),
            vec![3],
            "a forged body breaks the chain"
        );
    }

    /// A peer serving a certificate without a body below it: the node's own
    /// body for that index fills the chain while it has not reached the
    /// node's tip, and a forged one does not.
    #[test]
    fn a_body_the_peer_lacks_is_taken_from_the_node_down_to_its_tip() {
        let blocks = chain(6);
        let mut a = checkpoint_over(&blocks[..2]);
        a.index = 1;
        let mut b = checkpoint_over(&blocks[2..4]);
        b.index = 2;
        b.prev = a.digest();
        let mut c = checkpoint_over(&blocks[4..]);
        c.index = 3;
        c.prev = b.digest();
        let indices = |got: Vec<Checkpoint>| got.iter().map(|x| x.index).collect::<Vec<_>>();
        let tip = blocks[1].height().0;
        let local = |i: u64| [a.clone(), b.clone()].into_iter().find(|x| x.index == i);
        assert_eq!(indices(authenticate_chain(&c, &[])), vec![3]);
        assert_eq!(
            indices(authenticate_chain_to(&c, &[], tip, local)),
            vec![2, 3],
            "down to the block after the tip, not further"
        );
        assert_eq!(
            indices(authenticate_chain_to(
                &c,
                &[],
                blocks[0].height().0 - 1,
                local
            )),
            vec![1, 2, 3]
        );
        let mut forged = b.clone();
        forged.state_root = [9; 32];
        assert_eq!(
            indices(authenticate_chain_to(&c, &[forged], tip, local)),
            vec![2, 3],
            "the node's body where the served one does not link"
        );
        assert_eq!(
            indices(authenticate_chain_to(&c, &[], tip, |_| None)),
            vec![3]
        );
    }

    #[test]
    fn the_successor_of_the_tip_passes_even_with_an_equal_timestamp() {
        assert!(check_successor(&block_on(&tip(), 1_000), &tip()).is_ok());
        assert!(check_successor(&block_on(&tip(), 1_001), &tip()).is_ok());
    }

    #[test]
    fn a_block_past_a_gap_on_another_history_or_earlier_is_refused() {
        let mut t = tip();
        t.height = 4;
        assert!(check_successor(&block_on(&tip(), 1_001), &t).is_err());
        let mut t = tip();
        t.hash = Hash::new([8; 32]);
        assert!(check_successor(&block_on(&tip(), 1_001), &t).is_err());
        assert!(check_successor(&block_on(&tip(), 999), &tip()).is_err());
    }

    #[test]
    fn a_range_must_rebuild_the_blocks_root_exactly() {
        let blocks = chain(4);
        let cp = checkpoint_over(&blocks);
        assert!(check_range(&cp, &blocks).is_ok());
        assert!(check_range(&cp, &blocks[..3]).is_err(), "short range");
        let mut swapped = blocks.clone();
        swapped.swap(1, 2);
        assert!(check_range(&cp, &swapped).is_err(), "reordered");
        let mut forged = blocks.clone();
        forged[2].header.timestamp = Timestamp::new(55);
        assert!(
            check_range(&cp, &forged).is_err(),
            "a header the checkpoint does not commit"
        );
    }

    #[test]
    fn the_certified_state_root_must_match_local_execution() {
        let blocks = chain(2);
        let cp = checkpoint_over(&blocks);
        assert!(check_certified_state(&cp, Some(Hash::new([5; 32]))).is_ok());
        assert!(check_certified_state(&cp, Some(Hash::new([6; 32]))).is_err());
        assert!(check_certified_state(&cp, None).is_err());
    }

    #[test]
    fn a_wrong_or_unknown_state_root_is_refused() {
        let b = block_on(&tip(), 1_001);
        assert!(check_state_root(&b, Some(Hash::zero())).is_ok());
        assert!(check_state_root(&b, Some(Hash::new([1; 32]))).is_err());
        assert!(check_state_root(&b, None).is_err());
    }

    #[test]
    fn the_checkpoint_pins_the_block_by_hash() {
        let b = block_on(&tip(), 1_001);
        assert!(check_checkpoint(&b, Some((6, b.hash()))).is_ok());
        assert!(check_checkpoint(&b, Some((6, Hash::new([3; 32])))).is_err());
        assert!(check_checkpoint(&b, Some((7, Hash::new([3; 32])))).is_ok());
    }
}
