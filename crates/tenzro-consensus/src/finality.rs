//! Finality tracking for consensus

use crate::error::{ConsensusError, Result};
use crate::voter::QuorumCertificate;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::sync::broadcast;
use tenzro_types::block::Block;
use tenzro_types::primitives::{BlockHeight, Hash};

/// Notification about a finalized block
#[derive(Debug, Clone)]
pub struct FinalityNotification {
    /// The finalized block
    pub block: Block,

    /// Height of the finalized block
    pub height: BlockHeight,

    /// Hash of the finalized block
    pub hash: Hash,

    /// Quorum certificate that finalized this block
    pub qc: QuorumCertificate,
}

/// Tracks finalized blocks and provides finality notifications
pub struct FinalityTracker {
    /// Highest finalized block height
    finalized_height: Arc<RwLock<BlockHeight>>,

    /// Finalized blocks by height
    finalized_blocks: Arc<DashMap<BlockHeight, Block>>,

    /// Finalized block hashes by height
    finalized_hashes: Arc<DashMap<BlockHeight, Hash>>,

    /// Broadcast channel for finality notifications
    finality_tx: broadcast::Sender<FinalityNotification>,

    /// Wall-clock instant of the most recent `finalize_block` call.
    /// `None` until the first finalization after process start. Read by
    /// the `/metrics` exporter as `tenzro_consensus_last_finalized_age_seconds`
    /// — the primary stall-detection signal for on-call alerting.
    last_finalized_at: Arc<RwLock<Option<std::time::Instant>>>,
}

impl FinalityTracker {
    /// Creates a new finality tracker
    pub fn new() -> Self {
        let (finality_tx, _) = broadcast::channel(1000);

        Self {
            finalized_height: Arc::new(RwLock::new(BlockHeight::from(0))),
            finalized_blocks: Arc::new(DashMap::new()),
            finalized_hashes: Arc::new(DashMap::new()),
            finality_tx,
            last_finalized_at: Arc::new(RwLock::new(None)),
        }
    }

    /// Marks a block as finalized
    pub fn finalize_block(&self, block: Block, qc: QuorumCertificate) -> Result<()> {
        let height = block.height();
        let hash = block.hash();

        let current_finalized = *self.finalized_height.read();

        // Ensure we're finalizing blocks in order
        if height <= current_finalized {
            return Err(ConsensusError::InvalidHeight {
                expected: current_finalized + 1u64,
                actual: height,
            });
        }

        // Check for gaps in finalization
        if height > current_finalized + 1u64 {
            tracing::warn!(
                expected = %current_finalized + 1u64,
                actual = %height,
                "Gap in finalized blocks detected"
            );
        }

        // Store the finalized block
        self.finalized_blocks.insert(height, block.clone());
        self.finalized_hashes.insert(height, hash);

        // Update finalized height
        *self.finalized_height.write() = height;
        *self.last_finalized_at.write() = Some(std::time::Instant::now());

        tracing::info!(
            height = %height,
            hash = %hash,
            tx_count = block.tx_count(),
            "Block finalized"
        );

        // Send finality notification
        let notification = FinalityNotification {
            block,
            height,
            hash,
            qc,
        };

        // Ignore error if no receivers
        let _ = self.finality_tx.send(notification);

        Ok(())
    }

    /// Returns the highest finalized block height
    pub fn finalized_height(&self) -> BlockHeight {
        *self.finalized_height.read()
    }

    /// Seconds elapsed since the most recent finalization on this
    /// process, or `None` if nothing has finalized since start. Alerting
    /// rule of thumb: sustained values well above the block cadence mean
    /// the chain has stalled from this replica's perspective.
    pub fn seconds_since_last_finalized(&self) -> Option<u64> {
        self.last_finalized_at.read().map(|t| t.elapsed().as_secs())
    }

    /// Sets the initial finalized height from persistent storage.
    ///
    /// Called during node startup to resume consensus from the last persisted
    /// block height. Without this, the FinalityTracker starts at height 0
    /// on every restart, causing consensus to propose blocks at heights
    /// below the already-persisted chain tip.
    pub fn set_initial_height(&self, height: BlockHeight) {
        let current = *self.finalized_height.read();
        if height > current {
            *self.finalized_height.write() = height;
            tracing::info!(
                height = %height,
                "FinalityTracker initialized from storage"
            );
        }
    }

    /// Returns a finalized block by height
    pub fn get_finalized_block(&self, height: BlockHeight) -> Option<Block> {
        self.finalized_blocks.get(&height).map(|b| b.clone())
    }

    /// Returns the hash of a finalized block
    pub fn get_finalized_hash(&self, height: BlockHeight) -> Option<Hash> {
        self.finalized_hashes.get(&height).map(|h| *h)
    }

    /// Checks if a block at the given height is finalized
    pub fn is_finalized(&self, height: BlockHeight) -> bool {
        height <= self.finalized_height()
    }

    /// Subscribe to finality notifications
    pub fn subscribe(&self) -> broadcast::Receiver<FinalityNotification> {
        self.finality_tx.subscribe()
    }

    /// Returns the number of finalized blocks stored
    pub fn finalized_block_count(&self) -> usize {
        self.finalized_blocks.len()
    }

    /// Cleans up finalized blocks below the given height
    ///
    /// This is useful for pruning old blocks to save memory
    pub fn prune_blocks_below(&self, height: BlockHeight) {
        self.finalized_blocks.retain(|h, _| *h >= height);
        self.finalized_hashes.retain(|h, _| *h >= height);

        tracing::debug!(
            threshold = %height,
            remaining = self.finalized_blocks.len(),
            "Pruned old finalized blocks"
        );
    }
}

impl Default for FinalityTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Fork choice rule for selecting the canonical chain
pub struct ForkChoice {
    /// Blocks by hash
    blocks: Arc<DashMap<Hash, Block>>,

    /// Quorum certificates by block hash
    qcs: Arc<DashMap<Hash, QuorumCertificate>>,

    /// Finality tracker
    finality_tracker: Arc<FinalityTracker>,
}

impl ForkChoice {
    /// Hard ceiling on the number of indexed blocks. Matches the consensus
    /// engine's `BLOCK_CACHE_MAX_ENTRIES`: the height window alone cannot bound
    /// growth under single-height view churn, so this count cap is the
    /// backstop against OOM. Comfortably above any legitimate working set.
    const MAX_ENTRIES: usize = 4096;

    /// Creates a new fork choice instance
    pub fn new(finality_tracker: Arc<FinalityTracker>) -> Self {
        Self {
            blocks: Arc::new(DashMap::new()),
            qcs: Arc::new(DashMap::new()),
            finality_tracker,
        }
    }

    /// Adds a block to the fork choice
    pub fn add_block(&self, block: Block, qc: Option<QuorumCertificate>) {
        let hash = block.hash();
        self.blocks.insert(hash, block);

        if let Some(qc) = qc {
            self.qcs.insert(hash, qc);
        }
    }

    /// Records a QC for an already-known block. Idempotent: if the incoming
    /// QC has a strictly higher view than what we already have, replace;
    /// otherwise no-op. Returns true if the index was updated.
    ///
    /// HotStuff-2 observes blocks (via `on_proposal`) before the votes
    /// they collect aggregate into a QC. Fork choice needs to learn the
    /// QC at QC-formation time, separate from the block insertion path.
    pub fn record_qc(&self, qc: QuorumCertificate) -> bool {
        if !self.blocks.contains_key(&qc.block_hash) {
            return false;
        }
        let incoming_view = qc.view;
        // Read the existing QC's view in a tight scope so the DashMap
        // read guard is dropped before we re-acquire as a writer below.
        // Holding a `Ref` across `insert()` on the same map deadlocks.
        let existing_view = self.qcs.get(&qc.block_hash).map(|r| r.view);
        match existing_view {
            Some(v) if v >= incoming_view => false,
            _ => {
                self.qcs.insert(qc.block_hash, qc);
                true
            }
        }
    }

    /// Returns the number of blocks tracked by fork choice. Test-only
    /// observability hook.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the number of QCs tracked by fork choice. Test-only
    /// observability hook.
    #[cfg(test)]
    pub fn qc_count(&self) -> usize {
        self.qcs.len()
    }

    /// Selects the best block at the given height
    ///
    /// Uses the "follow highest QC" rule - select the block with the
    /// highest view number in its QC
    pub fn select_best_block(&self, height: BlockHeight) -> Option<Block> {
        let candidates: Vec<_> = self
            .blocks
            .iter()
            .filter(|entry| entry.value().height() == height)
            .collect();

        if candidates.is_empty() {
            return None;
        }

        // Find the block with the highest QC view
        let best = candidates.iter().max_by_key(|entry| {
            let hash = *entry.key();
            self.qcs.get(&hash).map(|qc| qc.view).unwrap_or(0)
        })?;

        Some(best.value().clone())
    }

    /// Gets a block by hash
    pub fn get_block(&self, hash: &Hash) -> Option<Block> {
        self.blocks.get(hash).map(|b| b.clone())
    }

    /// Gets the QC for a block
    pub fn get_qc(&self, hash: &Hash) -> Option<QuorumCertificate> {
        self.qcs.get(hash).map(|qc| qc.clone())
    }

    /// Checks if we have the block
    pub fn has_block(&self, hash: &Hash) -> bool {
        self.blocks.contains_key(hash)
    }

    /// Prunes blocks below the finalized height
    pub fn prune_below_finalized(&self) {
        let finalized_height = self.finality_tracker.finalized_height();

        self.blocks.retain(|_, block| block.height() >= finalized_height);

        // Count-bounded backstop. The height retain above cannot bound growth
        // when consensus is wedged at a single height: every failed view there
        // proposes a *distinct* block hash, all `>= finalized_height`, so the
        // retain reclaims none of them and the index grows one full `Block` per
        // view until the process OOMs. Cap by count and evict the lowest-`view`
        // entries (stalest competing proposals) first — a future winning
        // proposal extends the QC'd chain, never a stale same-height sibling,
        // so the evicted blocks can never be a future proposal's parent.
        if self.blocks.len() > Self::MAX_ENTRIES {
            let mut by_view: Vec<(Hash, u64)> = self
                .blocks
                .iter()
                .map(|e| (*e.key(), e.value().header.view))
                .collect();
            by_view.sort_unstable_by_key(|(_, view)| *view);
            let excess = self.blocks.len().saturating_sub(Self::MAX_ENTRIES);
            for (hash, _) in by_view.into_iter().take(excess) {
                self.blocks.remove(&hash);
            }
        }

        self.qcs.retain(|hash, _| self.blocks.contains_key(hash));

        tracing::debug!(
            finalized_height = %finalized_height,
            remaining_blocks = self.blocks.len(),
            "Pruned blocks below finalized height"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::voter::VoteType;
    use tenzro_types::block::{BlockHeader, ConsensusAlgorithm, ConsensusProof};
    use tenzro_types::primitives::Address;

    fn create_test_block(height: u64) -> Block {
        Block::new(
            BlockHeader::new(
                BlockHeight::from(height),
                Hash::default(),
                Hash::default(),
                Hash::default(),
                Address::default(),
                ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
            ),
            vec![],
        )
    }

    fn create_test_qc(view: u64, height: u64) -> QuorumCertificate {
        // Fork-choice tests don't verify the BLS aggregate; placeholder bytes
        // are fine because none of these QCs flow through `verify_bls_aggregate`.
        QuorumCertificate::new(
            view,
            BlockHeight::from(height),
            Hash::default(),
            VoteType::Commit,
            0,
            [0u8; 96],
            Vec::new(),
        )
    }

    fn create_test_block_at_view(height: u64, view: u64) -> Block {
        Block::new(
            BlockHeader::new_at_view(
                BlockHeight::from(height),
                view,
                Hash::default(),
                Hash::default(),
                Hash::default(),
                Address::default(),
                ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
            ),
            vec![],
        )
    }

    #[test]
    fn prune_count_caps_single_height_view_churn() {
        // Simulate consensus wedged at one height: many competing proposals,
        // all at the same height, distinct views/hashes. finalized_height
        // stays 0, so the height retain reclaims none — the count cap must.
        let tracker = Arc::new(FinalityTracker::new());
        let fork_choice = ForkChoice::new(tracker);

        let total = ForkChoice::MAX_ENTRIES + 500;
        for view in 0..total as u64 {
            let block = create_test_block_at_view(192_745, view);
            let qc = create_test_qc(view, 192_745);
            let qc = QuorumCertificate {
                block_hash: block.hash(),
                ..qc
            };
            fork_choice.add_block(block, Some(qc));
        }
        assert_eq!(fork_choice.block_count(), total);

        fork_choice.prune_below_finalized();
        assert_eq!(fork_choice.block_count(), ForkChoice::MAX_ENTRIES);

        // QCs for evicted blocks are dropped alongside them.
        assert!(fork_choice.qc_count() <= ForkChoice::MAX_ENTRIES);
    }

    #[test]
    fn test_finality_tracker() {
        let tracker = FinalityTracker::new();

        assert_eq!(tracker.finalized_height(), BlockHeight::from(0));

        let block = create_test_block(1);
        let qc = create_test_qc(1, 1);

        tracker.finalize_block(block.clone(), qc).unwrap();

        assert_eq!(tracker.finalized_height(), BlockHeight::from(1));
        assert!(tracker.is_finalized(BlockHeight::from(1)));
        assert!(!tracker.is_finalized(BlockHeight::from(2)));
    }

    #[test]
    fn test_finality_ordering() {
        let tracker = FinalityTracker::new();

        let block1 = create_test_block(1);
        let block2 = create_test_block(2);
        let qc1 = create_test_qc(1, 1);
        let qc2 = create_test_qc(2, 2);

        tracker.finalize_block(block1, qc1).unwrap();

        // Must finalize in order - can't skip heights
        tracker.finalize_block(block2, qc2).unwrap();

        // Verify both blocks are finalized
        assert_eq!(tracker.finalized_height(), BlockHeight::from(2));
        assert!(tracker.is_finalized(BlockHeight::from(1)));
        assert!(tracker.is_finalized(BlockHeight::from(2)));
    }

    #[test]
    fn test_fork_choice() {
        let finality_tracker = Arc::new(FinalityTracker::new());
        let fork_choice = ForkChoice::new(finality_tracker);

        let block = create_test_block(1);
        let qc = create_test_qc(1, 1);

        fork_choice.add_block(block.clone(), Some(qc));

        let retrieved = fork_choice.select_best_block(BlockHeight::from(1));
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().height(), block.height());
    }

    /// Distinct blocks at the same height — exercises the highest-QC-view
    /// selection rule. Use different proposer addresses to force distinct
    /// content hashes (BlockHeader::hash includes the proposer field).
    fn create_test_block_with_proposer(height: u64, proposer_seed: u8) -> Block {
        let mut proposer_bytes = [0u8; 32];
        proposer_bytes[0] = proposer_seed;
        Block::new(
            BlockHeader::new(
                BlockHeight::from(height),
                Hash::default(),
                Hash::default(),
                Hash::default(),
                Address::new(proposer_bytes),
                ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
            ),
            vec![],
        )
    }

    #[test]
    fn test_fork_choice_picks_highest_qc_view() {
        // Two distinct blocks at height 5; the one with the higher QC
        // view must win.
        let fork_choice = ForkChoice::new(Arc::new(FinalityTracker::new()));

        let block_a = create_test_block_with_proposer(5, 0xAA);
        let block_b = create_test_block_with_proposer(5, 0xBB);
        assert_ne!(
            block_a.hash(),
            block_b.hash(),
            "test setup: distinct proposers must yield distinct block hashes"
        );

        // block_a has a QC at view 7, block_b at view 12 → block_b wins
        fork_choice.add_block(block_a.clone(), Some(create_test_qc(7, 5)));
        fork_choice.add_block(block_b.clone(), Some(create_test_qc(12, 5)));

        let best = fork_choice.select_best_block(BlockHeight::from(5)).unwrap();
        assert_eq!(best.hash(), block_b.hash());
    }

    #[test]
    fn test_fork_choice_record_qc_monotonic() {
        // record_qc is monotonic by view — a higher-view QC supersedes a
        // lower-view QC for the same block; a lower-view QC is a no-op.
        let fork_choice = ForkChoice::new(Arc::new(FinalityTracker::new()));

        let block = create_test_block(3);
        fork_choice.add_block(block.clone(), None);

        // First QC at view 5
        let qc_v5 = QuorumCertificate::new(
            5,
            BlockHeight::from(3),
            block.hash(),
            VoteType::Prepare,
            0,
            [0u8; 96],
            Vec::new(),
        );
        assert!(fork_choice.record_qc(qc_v5));

        // Higher-view QC for the same block — supersedes
        let qc_v9 = QuorumCertificate::new(
            9,
            BlockHeight::from(3),
            block.hash(),
            VoteType::Commit,
            0,
            [0u8; 96],
            Vec::new(),
        );
        assert!(fork_choice.record_qc(qc_v9));
        assert_eq!(fork_choice.get_qc(&block.hash()).unwrap().view, 9);

        // Re-recording the lower view is a no-op
        let qc_v5_again = QuorumCertificate::new(
            5,
            BlockHeight::from(3),
            block.hash(),
            VoteType::Prepare,
            0,
            [0u8; 96],
            Vec::new(),
        );
        assert!(!fork_choice.record_qc(qc_v5_again));
        assert_eq!(fork_choice.get_qc(&block.hash()).unwrap().view, 9);
    }

    #[test]
    fn test_fork_choice_record_qc_requires_known_block() {
        // record_qc must refuse to index a QC for a block we haven't
        // observed locally — otherwise we'd accumulate dangling QCs.
        let fork_choice = ForkChoice::new(Arc::new(FinalityTracker::new()));

        let block = create_test_block(1);
        let qc = QuorumCertificate::new(
            1,
            BlockHeight::from(1),
            block.hash(),
            VoteType::Prepare,
            0,
            [0u8; 96],
            Vec::new(),
        );

        // Block is not added — record_qc must return false
        assert!(!fork_choice.record_qc(qc));
        assert_eq!(fork_choice.block_count(), 0);
    }

    #[test]
    fn test_finality_notifications() {
        let tracker = FinalityTracker::new();
        let mut receiver = tracker.subscribe();

        let block = create_test_block(1);
        let qc = create_test_qc(1, 1);

        tracker.finalize_block(block.clone(), qc.clone()).unwrap();

        // Should receive notification
        let notification = receiver.try_recv().unwrap();
        assert_eq!(notification.height, BlockHeight::from(1));
    }
}
