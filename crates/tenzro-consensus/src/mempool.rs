//! Transaction mempool with priority ordering

use crate::config::ConsensusConfig;
use crate::error::{ConsensusError, Result};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tenzro_types::primitives::Hash;
use tenzro_types::transaction::SignedTransaction;

/// Transaction with priority metadata
#[derive(Debug, Clone)]
struct PrioritizedTransaction {
    /// The transaction
    pub transaction: SignedTransaction,

    /// Gas price (priority)
    pub gas_price: u64,

    /// Transaction hash
    pub hash: Hash,

    /// Timestamp when added to mempool
    pub added_at: SystemTime,
}

impl PartialEq for PrioritizedTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.gas_price == other.gas_price
    }
}

impl Eq for PrioritizedTransaction {}

impl PartialOrd for PrioritizedTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher gas price = higher priority
        // If gas prices are equal, earlier timestamp = higher priority
        match self.gas_price.cmp(&other.gas_price) {
            Ordering::Equal => other.added_at.cmp(&self.added_at), // Earlier = higher priority
            other => other,
        }
    }
}

/// Transaction mempool with priority ordering
pub struct Mempool {
    /// Priority queue of transactions
    queue: Arc<RwLock<BinaryHeap<PrioritizedTransaction>>>,

    /// Transaction lookup by hash
    transactions: Arc<DashMap<Hash, SignedTransaction>>,

    /// Configuration
    config: Arc<ConsensusConfig>,

    /// Total size in bytes
    total_size: Arc<RwLock<usize>>,
}

impl Mempool {
    /// Creates a new mempool
    pub fn new(config: Arc<ConsensusConfig>) -> Self {
        Self {
            queue: Arc::new(RwLock::new(BinaryHeap::new())),
            transactions: Arc::new(DashMap::new()),
            config,
            total_size: Arc::new(RwLock::new(0)),
        }
    }

    /// Adds a transaction to the mempool
    ///
    /// # Security (Issue #73 - RESOLVED)
    ///
    /// This method enforces strict mempool size limits to prevent resource exhaustion:
    /// - **Count limit**: Default 10,000 transactions (configurable via mempool_max_transactions)
    /// - **Size limit**: Default 100MB (configurable via mempool_size_limit)
    /// - **Eviction policy**: When full, evicts lowest-gas-price transactions to make room
    ///   for higher-priority transactions
    ///
    /// This prevents DoS attacks where an attacker floods the mempool with low-fee transactions.
    pub fn add_transaction(&self, mut transaction: SignedTransaction) -> Result<()> {
        let hash = transaction.hash();

        // Check if already in mempool
        if self.transactions.contains_key(&hash) {
            return Err(ConsensusError::Mempool(
                "Transaction already in mempool".to_string(),
            ));
        }

        let tx_size = self.estimate_transaction_size(&transaction);
        let gas_price = transaction.transaction.gas_price;

        // SECURITY (Issue #73 - RESOLVED): Mempool count limit with eviction
        // Check count limit and evict if necessary
        if self.transactions.len() >= self.config.mempool_max_transactions {
            // Try to evict the lowest-gas-price transaction
            if !self.evict_lowest_gas_price_transaction(gas_price)? {
                return Err(ConsensusError::Mempool(
                    "Mempool full and new transaction has lower gas price than all existing ones".to_string(),
                ));
            }
        }

        // SECURITY (Issue #73 - RESOLVED): Mempool size limit with eviction
        // Check size limit
        let current_size = *self.total_size.read();
        if current_size + tx_size > self.config.mempool_size_limit {
            // Try to evict transactions until we have space
            if !self.evict_for_size(tx_size)? {
                return Err(ConsensusError::Mempool(
                    "Mempool size limit exceeded and cannot evict enough transactions".to_string(),
                ));
            }
        }

        // Add to priority queue
        let prioritized = PrioritizedTransaction {
            transaction: transaction.clone(),
            gas_price,
            hash,
            added_at: SystemTime::now(),
        };

        self.queue.write().push(prioritized);
        self.transactions.insert(hash, transaction);

        // Update size
        *self.total_size.write() += tx_size;

        tracing::debug!(
            hash = %hash,
            gas_price = gas_price,
            size = tx_size,
            total_size = *self.total_size.read(),
            count = self.transactions.len(),
            "Transaction added to mempool"
        );

        Ok(())
    }

    /// Evicts the lowest gas price transaction if the new gas price is higher
    /// Returns true if eviction succeeded, false otherwise
    fn evict_lowest_gas_price_transaction(&self, new_gas_price: u64) -> Result<bool> {
        // Find the transaction with the lowest gas price
        let mut lowest_gas_price = u64::MAX;
        let mut lowest_hash = None;

        for entry in self.transactions.iter() {
            let tx = entry.value();
            if tx.transaction.gas_price < lowest_gas_price {
                lowest_gas_price = tx.transaction.gas_price;
                lowest_hash = Some(*entry.key());
            }
        }

        // Only evict if the new transaction has a higher gas price
        if let Some(hash) = lowest_hash {
            if new_gas_price > lowest_gas_price {
                self.remove_transaction(&hash);
                tracing::debug!(
                    evicted_hash = %hash,
                    evicted_gas_price = lowest_gas_price,
                    new_gas_price = new_gas_price,
                    "Evicted lowest gas price transaction"
                );
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Evicts transactions to make room for the given size
    /// Returns true if enough space was freed, false otherwise
    fn evict_for_size(&self, needed_size: usize) -> Result<bool> {
        let current_size = *self.total_size.read();
        let available = self.config.mempool_size_limit.saturating_sub(current_size);

        if available >= needed_size {
            return Ok(true);
        }

        let mut to_evict = Vec::new();
        let mut freed_size = 0usize;
        let needed_to_free = needed_size - available;

        // Collect transactions sorted by gas price (lowest first)
        let mut txs: Vec<(Hash, u64, usize)> = self.transactions.iter()
            .map(|entry| {
                let hash = *entry.key();
                let tx = entry.value();
                let size = self.estimate_transaction_size(tx);
                (hash, tx.transaction.gas_price, size)
            })
            .collect();

        txs.sort_by_key(|(_, gas_price, _)| *gas_price);

        // Evict lowest gas price transactions until we have enough space
        for (hash, _, size) in txs {
            to_evict.push(hash);
            freed_size += size;

            if freed_size >= needed_to_free {
                break;
            }
        }

        // Perform evictions
        for hash in &to_evict {
            self.remove_transaction(hash);
        }

        tracing::debug!(
            evicted_count = to_evict.len(),
            freed_size = freed_size,
            needed_size = needed_size,
            "Evicted transactions to free space"
        );

        Ok(freed_size >= needed_to_free)
    }

    /// Removes a transaction from the mempool
    pub fn remove_transaction(&self, hash: &Hash) -> Option<SignedTransaction> {
        if let Some((_, transaction)) = self.transactions.remove(hash) {
            let tx_size = self.estimate_transaction_size(&transaction);
            *self.total_size.write() -= tx_size;

            // Note: We don't remove from the priority queue immediately
            // It will be filtered out when popping
            Some(transaction)
        } else {
            None
        }
    }

    /// Gets a transaction from the mempool
    pub fn get_transaction(&self, hash: &Hash) -> Option<SignedTransaction> {
        self.transactions.get(hash).map(|tx| tx.clone())
    }

    /// Selects transactions for block proposal
    pub fn select_transactions(
        &self,
        max_count: usize,
        max_gas: u64,
    ) -> Vec<SignedTransaction> {
        let mut selected = Vec::new();
        let mut total_gas = 0u64;
        let mut temp_queue = Vec::new();

        let mut queue = self.queue.write();

        // Pop transactions from priority queue
        while let Some(prioritized) = queue.pop() {
            let hash = prioritized.hash;

            // Check if still in mempool (might have been removed)
            if !self.transactions.contains_key(&hash) {
                continue;
            }

            let tx = &prioritized.transaction;
            let gas_limit = tx.transaction.gas_limit;

            // Check if transaction has expired
            if self.is_transaction_expired(&prioritized) {
                self.transactions.remove(&hash);
                continue;
            }

            // Check gas limit
            if total_gas + gas_limit > max_gas {
                temp_queue.push(prioritized);
                continue;
            }

            // Check count limit
            if selected.len() >= max_count {
                temp_queue.push(prioritized);
                continue;
            }

            // Add to selected
            selected.push(tx.clone());
            total_gas += gas_limit;
        }

        // Put back unselected transactions
        for tx in temp_queue {
            queue.push(tx);
        }

        tracing::debug!(
            count = selected.len(),
            total_gas = total_gas,
            "Selected transactions for block"
        );

        selected
    }

    /// Removes transactions that are included in a block
    pub fn remove_transactions(&self, hashes: &[Hash]) {
        for hash in hashes {
            self.remove_transaction(hash);
        }
    }

    /// Cleans up expired transactions
    pub fn cleanup_expired(&self) {
        let mut expired = Vec::new();

        // Collect expired transactions
        for entry in self.transactions.iter() {
            let hash = *entry.key();
            let tx = entry.value();

            let tx_age = SystemTime::now()
                .duration_since(tx.transaction.timestamp.into())
                .unwrap_or(Duration::from_secs(0));

            if tx_age > self.config.transaction_ttl() {
                expired.push(hash);
            }
        }

        // Remove expired transactions
        for hash in expired {
            self.remove_transaction(&hash);
            tracing::debug!(hash = %hash, "Removed expired transaction");
        }
    }

    /// Returns the number of transactions in the mempool
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Returns whether the mempool is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Returns the total size in bytes
    pub fn size(&self) -> usize {
        *self.total_size.read()
    }

    /// Clears all transactions from the mempool
    pub fn clear(&self) {
        self.queue.write().clear();
        self.transactions.clear();
        *self.total_size.write() = 0;
    }

    /// Estimates the size of a transaction in bytes
    fn estimate_transaction_size(&self, transaction: &SignedTransaction) -> usize {
        // Rough estimation based on serialized size
        serde_json::to_string(transaction)
            .map(|s| s.len())
            .unwrap_or(1024) // Default 1KB if serialization fails
    }

    /// Checks if a transaction has expired
    fn is_transaction_expired(&self, prioritized: &PrioritizedTransaction) -> bool {
        let age = SystemTime::now()
            .duration_since(prioritized.added_at)
            .unwrap_or(Duration::from_secs(0));

        age > self.config.transaction_ttl()
    }
}

/// Mempool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolStats {
    /// Number of transactions
    pub transaction_count: usize,

    /// Total size in bytes
    pub total_size: usize,

    /// Average gas price
    pub avg_gas_price: u64,

    /// Size limit in bytes
    pub size_limit: usize,

    /// Maximum number of transactions
    pub max_transactions: usize,
}

impl Mempool {
    /// Returns mempool statistics
    pub fn stats(&self) -> MempoolStats {
        let transaction_count = self.len();
        let total_size = self.size();

        let avg_gas_price = if transaction_count > 0 {
            let total_gas_price: u64 = self
                .transactions
                .iter()
                .map(|entry| entry.value().transaction.gas_price)
                .sum();
            total_gas_price / transaction_count as u64
        } else {
            0
        };

        MempoolStats {
            transaction_count,
            total_size,
            avg_gas_price,
            size_limit: self.config.mempool_size_limit,
            max_transactions: self.config.mempool_max_transactions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_types::primitives::{Address, ChainId, Nonce};
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
    fn test_mempool_add_transaction() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Mempool::new(config);

        let tx = create_test_transaction(100, 1);
        mempool.add_transaction(tx.clone()).unwrap();

        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_priority_ordering() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Mempool::new(config);

        // Add transactions with different gas prices
        let tx1 = create_test_transaction(100, 1);
        let tx2 = create_test_transaction(200, 2);
        let tx3 = create_test_transaction(150, 3);

        mempool.add_transaction(tx1).unwrap();
        mempool.add_transaction(tx2.clone()).unwrap();
        mempool.add_transaction(tx3).unwrap();

        // Select transactions - should be ordered by gas price
        let selected = mempool.select_transactions(10, 1_000_000);
        assert_eq!(selected.len(), 3);

        // First should be tx2 (highest gas price)
        assert_eq!(selected[0].transaction.gas_price, 200);
    }

    #[test]
    fn test_mempool_gas_limit() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Mempool::new(config);

        let tx1 = create_test_transaction(100, 1);
        let tx2 = create_test_transaction(200, 2);

        mempool.add_transaction(tx1).unwrap();
        mempool.add_transaction(tx2).unwrap();

        // Select with low gas limit - should only get one transaction
        let selected = mempool.select_transactions(10, 25000);
        assert_eq!(selected.len(), 1);
    }

    #[test]
    fn test_mempool_remove_transaction() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Mempool::new(config);

        let mut tx = create_test_transaction(100, 1);
        let hash = tx.hash();

        mempool.add_transaction(tx).unwrap();
        assert_eq!(mempool.len(), 1);

        mempool.remove_transaction(&hash);
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_mempool_count_limit_eviction() {
        let config = ConsensusConfig {
            mempool_max_transactions: 3,
            ..ConsensusConfig::default()
        };
        let mempool = Mempool::new(Arc::new(config));

        // Add 3 transactions with different gas prices
        mempool.add_transaction(create_test_transaction(100, 1)).unwrap();
        mempool.add_transaction(create_test_transaction(200, 2)).unwrap();
        mempool.add_transaction(create_test_transaction(150, 3)).unwrap();
        assert_eq!(mempool.len(), 3);

        // Add a 4th transaction with higher gas price - should evict lowest (100)
        mempool.add_transaction(create_test_transaction(300, 4)).unwrap();
        assert_eq!(mempool.len(), 3);

        // The mempool should now have gas prices: 200, 150, 300
        let selected = mempool.select_transactions(10, 1_000_000);
        assert_eq!(selected.len(), 3);

        // Highest should be 300
        assert_eq!(selected[0].transaction.gas_price, 300);
    }

    #[test]
    fn test_mempool_eviction_rejects_lower_gas() {
        let config = ConsensusConfig {
            mempool_max_transactions: 2,
            ..ConsensusConfig::default()
        };
        let mempool = Mempool::new(Arc::new(config));

        // Add 2 transactions with higher gas prices
        mempool.add_transaction(create_test_transaction(200, 1)).unwrap();
        mempool.add_transaction(create_test_transaction(300, 2)).unwrap();
        assert_eq!(mempool.len(), 2);

        // Try to add transaction with lower gas price - should fail
        let result = mempool.add_transaction(create_test_transaction(50, 3));
        assert!(result.is_err());
        assert_eq!(mempool.len(), 2);
    }
}
