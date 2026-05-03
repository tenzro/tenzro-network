//! Block proposal logic

use crate::config::ConsensusConfig;
use crate::error::{ConsensusError, Result};
use crate::mempool::Mempool;
use std::sync::Arc;
use tenzro_types::block::{
    calculate_next_base_fee, Block, BlockHeader, BlockMetadata, ConsensusAlgorithm,
    ConsensusProof, FeeMarketParams,
};
use tenzro_types::primitives::{Address, BlockHeight, Hash};
use tenzro_types::transaction::SignedTransaction;

/// Block proposer responsible for creating new blocks
pub struct BlockProposer {
    /// Mempool for transaction selection
    mempool: Arc<Mempool>,

    /// Consensus configuration
    config: Arc<ConsensusConfig>,
}

impl BlockProposer {
    /// Creates a new block proposer
    pub fn new(mempool: Arc<Mempool>, config: Arc<ConsensusConfig>) -> Self {
        Self { mempool, config }
    }

    /// Proposes a new block at the given HotStuff view.
    ///
    /// The view is stamped into `BlockHeader::view` so peers receiving the
    /// proposal can advance their local view to match before voting (see
    /// `HotStuff2Engine::on_proposal`). Without this, votes from peers at
    /// drifted views never coalesce into a quorum.
    ///
    /// `parent_base_fee`, `parent_gas_used`, and `parent_gas_limit` come
    /// from the parent block's `BlockMetadata` and feed the EIP-1559
    /// base-fee derivation. The proposer stamps the resulting base fee
    /// into the new block's metadata; validators independently re-derive
    /// from the same parent and reject the proposal on mismatch (see
    /// [`Self::validate_base_fee`]). For the genesis child (height=1),
    /// pass the genesis metadata fields — `calculate_next_base_fee`
    /// detects the gas-limit-zero edge and returns the initial base fee.
    pub fn propose_block(
        &self,
        height: BlockHeight,
        view: u64,
        prev_hash: Hash,
        proposer: Address,
        state_root: Hash,
        parent_base_fee: Option<u128>,
        parent_gas_used: u64,
        parent_gas_limit: u64,
    ) -> Result<Block> {
        // Select transactions from mempool
        let transactions = self.select_transactions()?;

        if transactions.is_empty() {
            tracing::debug!("No transactions available for block proposal");
        }

        // Calculate transaction root (Merkle root)
        let tx_root = self.calculate_tx_root(&transactions);

        // Derive EIP-1559 base fee for this block from the parent. Same
        // pure formula validators will run during `validate_base_fee`.
        let base_fee = calculate_next_base_fee(
            parent_base_fee,
            parent_gas_used,
            parent_gas_limit,
            &FeeMarketParams::default(),
        );

        // Create block metadata (carries the stamped base fee)
        let metadata = self.create_metadata(&transactions, base_fee);
        let gas_used = metadata.gas_used;

        // Create consensus proof (will be filled with votes later)
        let consensus_proof = ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new());

        // Create block header stamped with the proposer's current view
        let header = BlockHeader::new_at_view(
            height,
            view,
            prev_hash,
            tx_root,
            state_root,
            proposer,
            consensus_proof,
        )
        .with_metadata(metadata);

        // Create the block
        let block = Block::new(header, transactions);

        tracing::info!(
            height = %height,
            view = view,
            tx_count = block.tx_count(),
            gas_used = gas_used,
            base_fee_per_gas = base_fee,
            proposer = %proposer,
            "Block proposed"
        );

        Ok(block)
    }

    /// Selects transactions from the mempool for inclusion in a block
    fn select_transactions(&self) -> Result<Vec<SignedTransaction>> {
        // Clean up expired transactions first
        self.mempool.cleanup_expired();

        // Select transactions based on priority and limits
        let transactions = self.mempool.select_transactions(
            self.config.max_transactions_per_block,
            self.config.max_gas_per_block,
        );

        Ok(transactions)
    }

    /// Calculates the Merkle root of transactions
    fn calculate_tx_root(&self, transactions: &[SignedTransaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::default();
        }

        // Simple hash-based approach (in production, use proper Merkle tree)
        let mut combined = Vec::new();
        for tx in transactions {
            combined.extend_from_slice(tx.transaction.hash().as_bytes());
        }

        // Hash the combined data
        let hash_bytes = tenzro_crypto::hash::sha256(&combined);
        Hash::new(hash_bytes.as_bytes().try_into().unwrap_or([0u8; 32]))
    }

    /// Creates block metadata, stamping the EIP-1559 base fee derived
    /// from the parent block.
    fn create_metadata(&self, transactions: &[SignedTransaction], base_fee: u128) -> BlockMetadata {
        let tx_count = transactions.len() as u64;

        // Calculate total gas used
        let gas_used: u64 = transactions
            .iter()
            .map(|tx| tx.transaction.gas_limit)
            .sum();

        BlockMetadata {
            gas_used,
            gas_limit: self.config.max_gas_per_block,
            tx_count,
            protocol_version: 1,
            base_fee_per_gas: Some(base_fee),
        }
    }

    /// Validates a proposed block before voting
    pub fn validate_proposal(&self, block: &Block, expected_height: BlockHeight) -> Result<()> {
        // Check block height
        if block.height() != expected_height {
            return Err(ConsensusError::InvalidHeight {
                expected: expected_height,
                actual: block.height(),
            });
        }

        // Validate block structure
        if !block.validate_structure() {
            return Err(ConsensusError::InvalidProposal(
                "Invalid block structure".to_string(),
            ));
        }

        // Check transaction count limit
        if block.tx_count() > self.config.max_transactions_per_block {
            return Err(ConsensusError::InvalidProposal(format!(
                "Too many transactions: {} > {}",
                block.tx_count(),
                self.config.max_transactions_per_block
            )));
        }

        // Check gas limit
        if block.header.metadata.gas_used > self.config.max_gas_per_block {
            return Err(ConsensusError::InvalidProposal(format!(
                "Gas limit exceeded: {} > {}",
                block.header.metadata.gas_used,
                self.config.max_gas_per_block
            )));
        }

        // Check block size limit
        self.validate_block_size(block)?;

        // Validate transaction ordering (gas price descending)
        if !self.validate_transaction_ordering(&block.transactions) {
            return Err(ConsensusError::InvalidProposal(
                "Invalid transaction ordering".to_string(),
            ));
        }

        tracing::debug!(
            height = %block.height(),
            tx_count = block.tx_count(),
            "Block proposal validated"
        );

        Ok(())
    }

    /// Re-derives the EIP-1559 base fee from the parent block and rejects
    /// the proposal if the proposer's stamped value diverges.
    ///
    /// This is the consensus rule that prevents a malicious proposer
    /// from setting an arbitrary base fee. Every honest validator runs
    /// the same pure function over the same parent and must agree.
    /// Mirrors go-ethereum `consensus/misc/eip1559.VerifyEIP1559Header`.
    pub fn validate_base_fee(&self, block: &Block, parent: &Block) -> Result<()> {
        let expected = calculate_next_base_fee(
            parent.header.metadata.base_fee_per_gas,
            parent.header.metadata.gas_used,
            parent.header.metadata.gas_limit,
            &FeeMarketParams::default(),
        );

        match block.header.metadata.base_fee_per_gas {
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(ConsensusError::InvalidProposal(format!(
                "EIP-1559 base fee mismatch: expected {}, got {} (parent height {}, gas_used {}, gas_limit {})",
                expected,
                actual,
                parent.height(),
                parent.header.metadata.gas_used,
                parent.header.metadata.gas_limit,
            ))),
            None => Err(ConsensusError::InvalidProposal(
                "EIP-1559 base fee missing from block metadata".to_string(),
            )),
        }
    }

    /// Validates that transactions are properly ordered by gas price
    fn validate_transaction_ordering(&self, transactions: &[SignedTransaction]) -> bool {
        if transactions.len() <= 1 {
            return true;
        }

        for i in 0..transactions.len() - 1 {
            let current_gas_price = transactions[i].transaction.gas_price;
            let next_gas_price = transactions[i + 1].transaction.gas_price;

            // Transactions should be ordered by descending gas price
            if current_gas_price < next_gas_price {
                return false;
            }
        }

        true
    }

    /// Estimates the size of a block in bytes
    pub fn estimate_block_size(&self, block: &Block) -> usize {
        serde_json::to_string(block)
            .map(|s| s.len())
            .unwrap_or(0)
    }

    /// Checks if a block exceeds the maximum size
    pub fn validate_block_size(&self, block: &Block) -> Result<()> {
        let size = self.estimate_block_size(block);
        if size > self.config.max_block_size {
            return Err(ConsensusError::InvalidProposal(format!(
                "Block size {} exceeds maximum {}",
                size, self.config.max_block_size
            )));
        }
        Ok(())
    }
}

// Extension trait for BlockHeader
trait BlockHeaderExt {
    fn with_metadata(self, metadata: BlockMetadata) -> Self;
}

impl BlockHeaderExt for BlockHeader {
    fn with_metadata(mut self, metadata: BlockMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::Mempool;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_types::primitives::{ChainId, Nonce};
    use tenzro_types::transaction::{Transaction, TransactionType};
    use tenzro_types::Signature;

    fn create_test_transaction(gas_price: u64, nonce: u64) -> SignedTransaction {
        let pq_key = MlDsaSigningKey::generate();
        let tx = Transaction::new(
            ChainId::from(1),
            Address::default(),
            Address::default(),
            Nonce::from(nonce),
            TransactionType::Transfer { amount: 1000 },
            21000,
            gas_price,
            pq_key.verifying_key_bytes().to_vec(),
        );
        let pq_sig = pq_key.sign(tx.hash().as_bytes()).to_vec();
        SignedTransaction::new(tx, Signature::default(), pq_sig)
    }

    #[test]
    fn test_propose_block() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Arc::new(Mempool::new(config.clone()));
        let proposer = BlockProposer::new(mempool.clone(), config);

        // Add transactions to mempool
        mempool.add_transaction(create_test_transaction(100, 1)).unwrap();
        mempool.add_transaction(create_test_transaction(200, 2)).unwrap();

        // Propose a block. Genesis-edge case: parent_gas_limit=0 → child
        // uses initial_base_fee.
        let block = proposer
            .propose_block(
                BlockHeight::from(1),
                0,
                Hash::default(),
                Address::default(),
                Hash::default(),
                None, // parent_base_fee
                0,    // parent_gas_used
                0,    // parent_gas_limit (genesis)
            )
            .unwrap();

        assert_eq!(block.height(), BlockHeight::from(1));
        assert_eq!(block.tx_count(), 2);
        // Genesis child must stamp the initial base fee.
        assert_eq!(
            block.header.metadata.base_fee_per_gas,
            Some(FeeMarketParams::default().initial_base_fee)
        );
    }

    #[test]
    fn test_validate_proposal() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Arc::new(Mempool::new(config.clone()));
        let proposer = BlockProposer::new(mempool, config);

        // Create a valid block
        let block = Block::new(
            BlockHeader::new(
                BlockHeight::from(1),
                Hash::default(),
                Hash::default(),
                Hash::default(),
                Address::default(),
                ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
            ),
            vec![],
        );

        // Should validate successfully
        assert!(proposer.validate_proposal(&block, BlockHeight::from(1)).is_ok());
    }

    #[test]
    fn test_validate_wrong_height() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Arc::new(Mempool::new(config.clone()));
        let proposer = BlockProposer::new(mempool, config);

        let block = Block::new(
            BlockHeader::new(
                BlockHeight::from(1),
                Hash::default(),
                Hash::default(),
                Hash::default(),
                Address::default(),
                ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
            ),
            vec![],
        );

        // Should fail with wrong height
        let result = proposer.validate_proposal(&block, BlockHeight::from(2));
        assert!(result.is_err());
    }
}
