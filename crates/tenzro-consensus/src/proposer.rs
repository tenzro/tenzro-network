//! Block proposal logic

use crate::config::ConsensusConfig;
use crate::error::{ConsensusError, Result};
use crate::mempool::Mempool;
use std::sync::Arc;
use tenzro_types::block::{
    Block, BlockHeader, BlockMetadata, ConsensusAlgorithm, ConsensusProof, FeeMarketParams,
    calculate_next_base_fee,
};
use tenzro_types::primitives::{Address, BlockHeight, Hash};
use tenzro_types::transaction::SignedTransaction;

/// Block proposer responsible for creating new blocks
pub struct BlockProposer {
    /// Transaction hashes already present in unfinalized ancestor blocks.
    ///
    /// Set by the engine immediately before each proposal. Mempool eviction
    /// happens on finalization, and HotStuff-2 proposes block N+1 before block
    /// N commits, so in that window an already-included transaction is neither
    /// a duplicate within the new body nor gone from the mempool. Without this
    /// it is selected again, executes twice, and the failing second execution
    /// overwrites the receipt of the first.
    uncommitted: parking_lot::RwLock<std::collections::HashSet<Hash>>,
    /// Mempool for transaction selection
    mempool: Arc<Mempool>,

    /// Consensus configuration
    config: Arc<ConsensusConfig>,
}

impl BlockProposer {
    /// Creates a new block proposer
    /// Records the transaction hashes carried by the uncommitted prefix, so
    /// the next proposal does not re-propose any of them. Called by the engine
    /// with the walk from the parent back to the finalized tip.
    pub fn set_uncommitted_tx_hashes(&self, hashes: std::collections::HashSet<Hash>) {
        *self.uncommitted.write() = hashes;
    }

    pub fn new(mempool: Arc<Mempool>, config: Arc<ConsensusConfig>) -> Self {
        Self {
            mempool,
            config,
            uncommitted: parking_lot::RwLock::new(std::collections::HashSet::new()),
        }
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

        self.assemble_block(
            height,
            view,
            prev_hash,
            proposer,
            state_root,
            parent_base_fee,
            parent_gas_used,
            parent_gas_limit,
            transactions,
        )
    }

    /// Assemble a block from a pre-selected, already-ordered transaction set.
    ///
    /// This is the block-body-independent assembly core shared by the mempool
    /// path ([`Self::propose_block`]) and the batch-certificate path
    /// ([`Self::propose_block_from_transactions`]). The transactions are taken
    /// verbatim in the order supplied — the caller owns ordering. Header,
    /// tx-root, EIP-1559 base fee, and metadata are derived identically
    /// regardless of where the transactions came from, so a block built from a
    /// certified batch prefix is byte-compatible with one built from the
    /// mempool and validates through the same path.
    pub fn propose_block_from_transactions(
        &self,
        height: BlockHeight,
        view: u64,
        prev_hash: Hash,
        proposer: Address,
        state_root: Hash,
        parent_base_fee: Option<u128>,
        parent_gas_used: u64,
        parent_gas_limit: u64,
        transactions: Vec<SignedTransaction>,
    ) -> Result<Block> {
        self.assemble_block(
            height,
            view,
            prev_hash,
            proposer,
            state_root,
            parent_base_fee,
            parent_gas_used,
            parent_gas_limit,
            transactions,
        )
    }

    /// Fee-order a block body and truncate it to the configured limits.
    ///
    /// Deterministic: every validator handed the same transactions produces the
    /// same body. Ties break on `(from, nonce)` rather than sort stability —
    /// equal-fee transactions are the common case here because the faucet
    /// issues every grant at the same gas price, and two proposers must not
    /// emit different blocks from the same inputs. `(from, nonce)` is unique
    /// among valid transactions and, unlike the transaction hash, readable
    /// without a mutable borrow.
    fn shape_block_body(&self, mut transactions: Vec<SignedTransaction>) -> Vec<SignedTransaction> {
        // Drop duplicates first.
        //
        // The certified prefix is a concatenation of batch bodies, and the same
        // transaction can sit in more than one batch — a client resubmits, or a
        // batch is re-produced after a restart before the first certified. The
        // body was assembled without checking, so a block executed the same
        // transaction repeatedly:
        //
        //   00:27:40.188299 Executing transaction tx_hash=4b305909…
        //   00:27:40.188441 Executing transaction tx_hash=4b305909…
        //
        // Two executions of the same hash a fraction of a millisecond apart, in
        // one block. Every copy after the first fails — the nonce is spent by
        // then — which is what kept producing `Invalid nonce` in a loop no
        // amount of *store* eviction could stop, because the duplication was
        // downstream of every store.
        //
        // Aptos hit the same thing and fixed it the same way, in AIP-37,
        // "Filter duplicate transactions within a block": duplicates are
        // possible whenever proposals are assembled from batches, and they
        // cannot affect correctness — the first copy wins and the rest are
        // discarded — but they waste a block.
        let mut seen = std::collections::HashSet::with_capacity(transactions.len());
        transactions.retain(|tx| seen.insert(tx.transaction.hash()));

        // And drop anything already sitting in an unfinalized ancestor.
        //
        // The dedupe above only sees this body. Mempool eviction only happens
        // at finalization. Between proposing block N and committing it, an
        // included transaction is in neither — so it gets proposed again,
        // executes a second time against a spent nonce, fails, and its receipt
        // replaces the successful one. The sender is left short the funds the
        // first execution moved, with a receipt saying nothing happened.
        {
            let uncommitted = self.uncommitted.read();
            if !uncommitted.is_empty() {
                transactions.retain(|tx| !uncommitted.contains(&tx.transaction.hash()));
            }
        }

        transactions.sort_by_cached_key(|t| {
            (
                std::cmp::Reverse(t.transaction.gas_price),
                t.transaction.from.as_bytes().to_vec(),
                t.transaction.nonce,
            )
        });

        // Reserve for the header and the non-transaction body fields, so the
        // estimate here stays under what `estimate_block_size` measures.
        let mut used_size = 4096usize;
        let mut used_gas = 0u64;
        let mut fitted = Vec::with_capacity(transactions.len());
        for tx in transactions {
            if fitted.len() >= self.config.max_transactions_per_block {
                break;
            }
            // The same serialisation `estimate_block_size` measures with, so
            // the two cannot disagree about what a transaction costs.
            let tx_size = serde_json::to_string(&tx).map(|s| s.len()).unwrap_or(0);
            let next_size = used_size.saturating_add(tx_size);
            let next_gas = used_gas.saturating_add(tx.transaction.gas_limit);
            if next_size > self.config.max_block_size || next_gas > self.config.max_gas_per_block {
                // Keep scanning rather than stopping: a later, smaller
                // transaction may still fit, and stopping would strand it
                // behind one oversized neighbour indefinitely.
                continue;
            }
            used_size = next_size;
            used_gas = next_gas;
            fitted.push(tx);
        }
        fitted
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble_block(
        &self,
        height: BlockHeight,
        view: u64,
        prev_hash: Hash,
        proposer: Address,
        state_root: Hash,
        parent_base_fee: Option<u128>,
        parent_gas_used: u64,
        parent_gas_limit: u64,
        transactions: Vec<SignedTransaction>,
    ) -> Result<Block> {
        // Every block is fee-ordered and fitted here, in the one place both
        // proposal paths pass through.
        //
        // The chain halted at 1497 because a proposer built blocks its own
        // validator rejected, and it happened twice for two different limits:
        //
        //   Invalid block proposal: Invalid transaction ordering
        //   Invalid block proposal: Block size 3614410 exceeds maximum 2097152
        //
        // Both paths had a gap. The batch path concatenates certified batch
        // bodies — availability order, unbounded length. The mempool path calls
        // `select_transactions(max_count, max_gas)`, which caps count and gas
        // but not *size*, so a backlog of large transactions selected fine and
        // then blew the size limit. Shaping in each path separately is how the
        // second bug survived the first fix; doing it here means
        // `validate_proposal` cannot disagree with what was just built,
        // whichever path built it.
        let transactions = self.shape_block_body(transactions);

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
        let gas_used: u64 = transactions.iter().map(|tx| tx.transaction.gas_limit).sum();

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
                block.header.metadata.gas_used, self.config.max_gas_per_block
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
        serde_json::to_string(block).map(|s| s.len()).unwrap_or(0)
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
mod uncommitted_prefix_tests {
    use super::*;
    use std::collections::HashSet;

    use crate::mempool::Mempool;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_types::Signature;
    use tenzro_types::primitives::{ChainId, Nonce};
    use tenzro_types::transaction::{Transaction, TransactionType};

    fn proposer() -> BlockProposer {
        BlockProposer::new(
            Arc::new(Mempool::new(Default::default())),
            Arc::new(ConsensusConfig::default()),
        )
    }

    fn tx(nonce: u64) -> SignedTransaction {
        let pq_key = MlDsaSigningKey::generate();
        let t = Transaction::new(
            ChainId::from(1),
            Address::default(),
            Address::default(),
            Nonce::from(nonce),
            TransactionType::Transfer { amount: 1000 },
            21000,
            1_000_000_000,
            pq_key.verifying_key_bytes().to_vec(),
        );
        let pq_sig = pq_key.sign(t.hash().as_bytes()).to_vec();
        SignedTransaction::new(t, Signature::default(), pq_sig)
    }

    /// A transaction already in an unfinalized ancestor must not be proposed
    /// again.
    ///
    /// This is what put the same hash in three consecutive blocks on the live
    /// chain. The first inclusion executed and moved 10,000,000 TNZO; the
    /// second re-executed against a spent nonce, failed, and wrote its own
    /// receipt under the same hash — leaving an account short the funds with a
    /// receipt saying nothing had happened.
    #[test]
    fn a_transaction_in_the_uncommitted_prefix_is_not_reproposed() {
        let p = proposer();
        let txs: Vec<_> = (0..3).map(tx).collect();
        let already_included = txs[1].transaction.hash();

        // Nothing excluded: all three are shaped into the body.
        assert_eq!(p.shape_block_body(txs.clone()).len(), 3);

        // With one carried by an unfinalized ancestor, it is dropped and the
        // others are untouched.
        p.set_uncommitted_tx_hashes(HashSet::from([already_included]));
        let shaped = p.shape_block_body(txs.clone());
        assert_eq!(shaped.len(), 2, "the already-included transaction survived");
        assert!(
            !shaped
                .iter()
                .any(|t| t.transaction.hash() == already_included),
            "the proposer re-proposed a transaction from the uncommitted prefix"
        );
    }

    /// Clearing the set restores normal selection — the filter must not latch.
    #[test]
    fn the_filter_does_not_latch_once_the_prefix_commits() {
        let p = proposer();
        let txs: Vec<_> = (0..2).map(tx).collect();
        p.set_uncommitted_tx_hashes(HashSet::from([txs[0].transaction.hash()]));
        assert_eq!(p.shape_block_body(txs.clone()).len(), 1);

        // Once those blocks finalize the prefix is empty again.
        p.set_uncommitted_tx_hashes(HashSet::new());
        assert_eq!(p.shape_block_body(txs).len(), 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::Mempool;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_types::Signature;
    use tenzro_types::primitives::{ChainId, Nonce};
    use tenzro_types::transaction::{Transaction, TransactionType};

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

    /// A batch-sourced proposal must satisfy the proposer's own ordering rule.
    ///
    /// This halted the chain. Transactions concatenated from a certified batch
    /// prefix arrive in DAG (availability) order, but `validate_proposal` —
    /// which every validator runs against every proposal, including one it
    /// just built itself — requires descending gas price. So the proposer
    /// rejected its own block and the view retried forever:
    ///
    ///   Block proposed height=1498 view=3049 tx_count=69
    ///   ERROR Consensus step failed: Invalid block proposal: Invalid
    ///         transaction ordering
    ///
    /// It stayed hidden while traffic was low, because the mempool path
    /// already sorts and only heavy blocks take the batch path at all.
    #[test]
    fn a_batch_sourced_proposal_satisfies_the_ordering_rule() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Arc::new(Mempool::new(config.clone()));
        let proposer = BlockProposer::new(mempool, config);

        // Deliberately not fee-ordered, as a certified prefix would be.
        let unordered = vec![
            create_test_transaction(100, 1),
            create_test_transaction(900, 2),
            create_test_transaction(500, 3),
        ];

        let block = proposer
            .propose_block_from_transactions(
                BlockHeight::new(1),
                1,
                Hash::default(),
                Address::default(),
                Hash::default(),
                None,
                0,
                0,
                unordered,
            )
            .expect("proposing from a certified prefix must succeed");

        assert!(
            proposer.validate_transaction_ordering(&block.transactions),
            "the proposer must accept a block it just built"
        );
        let prices: Vec<u64> = block
            .transactions
            .iter()
            .map(|t| t.transaction.gas_price)
            .collect();
        assert_eq!(prices, vec![900, 500, 100]);
    }

    /// A certified prefix larger than a block must be truncated, not proposed.
    ///
    /// The prefix grows with every certified batch while the chain is not
    /// finalising, so it is routinely larger than `max_block_size`. Proposing
    /// it whole reproduced the self-rejection loop one limit further along:
    ///
    ///   Block proposed height=1498 tx_count=156
    ///   ERROR Invalid block proposal: Block size 3614462 exceeds maximum 2097152
    #[test]
    fn an_oversized_certified_prefix_is_truncated_to_fit() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Arc::new(Mempool::new(config.clone()));
        let proposer = BlockProposer::new(mempool, config.clone());

        // Each transaction carries an ML-DSA-65 verifying key and signature, so
        // a few hundred comfortably clear 2 MiB.
        let many: Vec<_> = (1..=400).map(|n| create_test_transaction(100, n)).collect();
        let offered = many.len();

        let block = proposer
            .propose_block_from_transactions(
                BlockHeight::new(1),
                1,
                Hash::default(),
                Address::default(),
                Hash::default(),
                None,
                0,
                0,
                many,
            )
            .expect("an oversized prefix must still yield a proposable block");

        assert!(
            block.transactions.len() < offered,
            "the prefix should have been truncated ({offered} offered)"
        );
        proposer
            .validate_block_size(&block)
            .expect("the proposer must accept the size of a block it just built");
        assert!(
            proposer.validate_transaction_ordering(&block.transactions),
            "truncation must not disturb fee ordering"
        );
    }

    /// The mempool path must fit the block too, not just the batch path.
    ///
    /// `select_transactions(max_count, max_gas)` caps count and gas but not
    /// size, so a backlog of large transactions selected cleanly and then blew
    /// the size limit. Fixing only the batch path left this one live — which is
    /// how the second halt survived the first fix.
    #[tokio::test]
    async fn the_mempool_path_also_fits_the_block() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Arc::new(Mempool::new(config.clone()));
        let proposer = BlockProposer::new(mempool.clone(), config);

        for n in 1..=400 {
            let _ = mempool.add_transaction(create_test_transaction(100, n));
        }

        let block = proposer
            .propose_block(
                BlockHeight::new(1),
                1,
                Hash::default(),
                Address::default(),
                Hash::default(),
                None,
                0,
                0,
            )
            .expect("the mempool path must yield a proposable block");

        proposer
            .validate_block_size(&block)
            .expect("the proposer must accept the size of a block it just built");
        assert!(proposer.validate_transaction_ordering(&block.transactions));
    }

    /// A block must never contain the same transaction twice.
    ///
    /// The certified prefix concatenates batch bodies, and one transaction can
    /// sit in more than one batch — a client resubmits, or a batch is
    /// re-produced after a restart before the first certified. Assembling
    /// without checking put both copies in the block:
    ///
    ///   00:27:40.188299 Executing transaction tx_hash=4b305909…
    ///   00:27:40.188441 Executing transaction tx_hash=4b305909…
    ///
    /// Every copy after the first fails with `Invalid nonce` — the nonce is
    /// spent by then — which produced a retry loop no store-level eviction
    /// could stop, because the duplication happened downstream of every store.
    #[test]
    fn a_block_never_contains_the_same_transaction_twice() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Arc::new(Mempool::new(config.clone()));
        let proposer = BlockProposer::new(mempool, config);

        let tx = create_test_transaction(100, 1);
        let other = create_test_transaction(100, 2);
        // The same transaction offered three times, as a concatenated prefix
        // spanning overlapping batches would.
        let offered = vec![tx.clone(), other.clone(), tx.clone(), tx.clone()];

        let block = proposer
            .propose_block_from_transactions(
                BlockHeight::new(1),
                1,
                Hash::default(),
                Address::default(),
                Hash::default(),
                None,
                0,
                0,
                offered,
            )
            .expect("proposing must succeed");

        let mut hashes: Vec<_> = block
            .transactions
            .iter()
            .map(|t| t.transaction.hash())
            .collect();
        let before = hashes.len();
        hashes.sort_unstable_by_key(|h| h.as_bytes().to_vec());
        hashes.dedup();
        assert_eq!(before, hashes.len(), "the block contains a duplicate");
        assert_eq!(block.transactions.len(), 2, "both distinct transactions kept");
    }

    /// Equal-fee transactions must order identically on every validator.
    ///
    /// The faucet issues every grant at the same gas price, so ties are the
    /// common case rather than a corner. If the tiebreak were left to sort
    /// stability, two validators concatenating the same batches in the same
    /// order could still emit different blocks and fail to agree.
    #[test]
    fn equal_fee_transactions_order_deterministically() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Arc::new(Mempool::new(config.clone()));
        let proposer = BlockProposer::new(mempool, config);

        let build = |order: [u64; 3]| {
            let txs = order
                .iter()
                .map(|n| create_test_transaction(500, *n))
                .collect();
            proposer
                .propose_block_from_transactions(
                    BlockHeight::new(1),
                    1,
                    Hash::default(),
                    Address::default(),
                    Hash::default(),
                    None,
                    0,
                    0,
                    txs,
                )
                .expect("proposal must succeed")
                .transactions
                .iter()
                .map(|t| t.transaction.nonce.0)
                .collect::<Vec<_>>()
        };

        assert_eq!(
            build([1, 2, 3]),
            build([3, 1, 2]),
            "the same transactions must order the same way regardless of arrival order"
        );
    }

    #[test]
    fn test_propose_block() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Arc::new(Mempool::new(config.clone()));
        let proposer = BlockProposer::new(mempool.clone(), config);

        // Add transactions to mempool
        mempool
            .add_transaction(create_test_transaction(100, 1))
            .unwrap();
        mempool
            .add_transaction(create_test_transaction(200, 2))
            .unwrap();

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
        assert!(
            proposer
                .validate_proposal(&block, BlockHeight::from(1))
                .is_ok()
        );
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
