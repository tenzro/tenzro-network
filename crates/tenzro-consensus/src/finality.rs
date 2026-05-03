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
        self.qcs.retain(|hash, _| {
            self.blocks
                .get(hash)
                .map(|b| b.height() >= finalized_height)
                .unwrap_or(false)
        });

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
        QuorumCertificate::new(
            view,
            BlockHeight::from(height),
            Hash::default(),
            VoteType::Commit,
            vec![],
            0,
        )
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
