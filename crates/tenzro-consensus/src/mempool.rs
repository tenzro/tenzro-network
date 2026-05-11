//! Transaction mempool with priority ordering.
//!
//! ## Mempool ↔ proposer coupling
//!
//! `select_transactions` is **non-destructive**: it reads the priority queue
//! without removing anything. Removal happens only via [`Mempool::remove_transactions`],
//! which the consensus engine invokes on **finalization** of a block.
//!
//! This is the canonical production pattern — same shape as CometBFT's
//! `ReapMaxBytesMaxGas` + `Update` split, the original Diem/Libra mempool, and
//! pre-Quorum-Store Aptos. It guarantees liveness across view changes:
//! transactions in an abandoned proposal stay selectable, so the next leader
//! picks them up. Across concurrent in-flight proposals the same tx may appear
//! in more than one — at most one block finalizes, the other proposal is
//! dropped wholesale, and the `contains_key` check on subsequent selections
//! filters out anything already finalized.
//!
//! The destructive-pop-with-explicit-reinjection pattern (the obvious
//! alternative) is **not** used by any major project in 2026: it requires
//! plumbing proposal lifecycle (timeout, abandon, commit) back into the
//! mempool, and any desync between the in-flight set and the abandonment
//! notification reproduces exactly the stranding bug this design avoids.
//!
//! Future direction: abandon priority-pull entirely in favor of Quorum Store
//! (Aptos) or DAG-mempool (Sui Mysticeti), where data availability is
//! certified before consensus orders it. Until then, non-destructive read is
//! the right interim design.

use crate::admission::{AdmissionController, AdmissionDecision, Lane};
use crate::config::ConsensusConfig;
use crate::error::{ConsensusError, Result};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::{Arc, OnceLock};
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

    /// Per-DID admission controller (Spec 2). When set, every
    /// `add_transaction` call first runs lane assignment + token-bucket
    /// rate limiting. When unset, the mempool falls back to the legacy
    /// path (size/count limits only) — used by tests and very early
    /// bootstrap before identity is wired.
    ///
    /// Stored in a `OnceLock` so it can be wired in *after* `Mempool::new`
    /// (which happens inside `HotStuff2Engine::new` before the node has
    /// `IdentityRegistry` and `StakingManager` handles), without forcing
    /// any `&mut self` on the hot path. Read on every `add_transaction`,
    /// written exactly once at node startup.
    admission: OnceLock<Arc<AdmissionController>>,
}

impl Mempool {
    /// Creates a new mempool
    pub fn new(config: Arc<ConsensusConfig>) -> Self {
        Self {
            queue: Arc::new(RwLock::new(BinaryHeap::new())),
            transactions: Arc::new(DashMap::new()),
            config,
            total_size: Arc::new(RwLock::new(0)),
            admission: OnceLock::new(),
        }
    }

    /// Wire a Spec-2 admission controller into a live `Mempool`. The
    /// controller is shared (via `Arc`) so RPC handlers and the node tick
    /// loop can also read its bucket snapshots and stats. May be called
    /// at most once per `Mempool` instance — subsequent calls return
    /// `Err(ConsensusError::AlreadyStarted)` so a buggy second wiring
    /// can't silently desync the resolver from the engine.
    pub fn set_admission(&self, admission: Arc<AdmissionController>) -> Result<()> {
        self.admission
            .set(admission)
            .map_err(|_| ConsensusError::AlreadyStarted)
    }

    /// Read access to the admission controller, if any. Used by RPC
    /// handlers (`tenzro_getMempoolLane`, `tenzro_getMempoolStats`) and
    /// metrics collection.
    pub fn admission(&self) -> Option<&Arc<AdmissionController>> {
        self.admission.get()
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

        // Spec 2 (#312): per-DID admission lane + token bucket + fee floor.
        // Runs before any size/count work so rate-limited / under-priced
        // senders can't push out expensive eviction passes. Skipped when
        // the controller is unwired (early bootstrap, test harness).
        //
        // Order matters:
        //   1. assign_lane (cheap, no side effect)
        //   2. fee-floor check — reject without consuming a bucket token
        //   3. try_admit (consumes token; rejects if bucket empty)
        //
        // Doing fee-floor *before* try_admit ensures spam at zero gas
        // doesn't drain a controller's bucket — only well-formed
        // transactions burn admission rate.
        let admitted_lane = if let Some(ctrl) = self.admission.get() {
            let lane = ctrl.assign_lane(&transaction);

            // (2) Fee-floor check.
            let base_floor = self.config.mempool_min_gas_price;
            if base_floor > 0 {
                let multiplier = ctrl.fee_floor_mult(lane);
                let required = (base_floor as f64 * multiplier).ceil() as u64;
                if transaction.transaction.gas_price < required {
                    ctrl.record_rejected_fee_floor(lane);
                    tracing::debug!(
                        target: "mempool::admission",
                        hash = %hash,
                        lane = %lane.as_str(),
                        gas_price = transaction.transaction.gas_price,
                        required,
                        base = base_floor,
                        multiplier,
                        "Rejected at fee-floor"
                    );
                    return Err(ConsensusError::FeeFloorTooLow {
                        lane: lane.as_str(),
                        gas_price: transaction.transaction.gas_price,
                        required,
                        base: base_floor,
                        multiplier,
                    });
                }
            }

            // (3) Token bucket — actually consume.
            match ctrl.try_admit(&transaction) {
                AdmissionDecision::Admit { lane } => Some(lane),
                AdmissionDecision::RateLimited {
                    lane,
                    retry_after_ms,
                    burst_remaining,
                    current_rate,
                } => {
                    tracing::debug!(
                        target: "mempool::admission",
                        hash = %hash,
                        lane = %lane.as_str(),
                        retry_after_ms,
                        burst_remaining,
                        current_rate,
                        "Rate-limited at admission"
                    );
                    return Err(ConsensusError::RateLimited {
                        lane: lane.as_str(),
                        retry_after_ms,
                        burst_remaining,
                        current_rate,
                    });
                }
            }
        } else {
            None
        };

        let tx_size = self.estimate_transaction_size(&transaction);
        let gas_price = transaction.transaction.gas_price;

        // SECURITY (Issue #73 - RESOLVED): Mempool count limit with eviction
        // Check count limit and evict if necessary
        if self.transactions.len() >= self.config.mempool_max_transactions {
            // Try to evict the lowest-gas-price transaction
            if !self.evict_lowest_gas_price_transaction(gas_price)? {
                if let (Some(ctrl), Some(lane)) = (self.admission.get(), admitted_lane) {
                    ctrl.record_rejected_mempool_full(lane);
                }
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
                if let (Some(ctrl), Some(lane)) = (self.admission.get(), admitted_lane) {
                    ctrl.record_rejected_mempool_full(lane);
                }
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
            lane = ?admitted_lane.map(|l| l.as_str()),
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
        if let Some(hash) = lowest_hash
            && new_gas_price > lowest_gas_price
        {
            self.remove_transaction(&hash);
            tracing::debug!(
                evicted_hash = %hash,
                evicted_gas_price = lowest_gas_price,
                new_gas_price = new_gas_price,
                "Evicted lowest gas price transaction"
            );
            return Ok(true);
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

    /// Selects transactions for block proposal.
    ///
    /// Selected transactions are put **back** into the priority queue so they
    /// remain selectable on a subsequent call. They are only removed from the
    /// `transactions` map by [`Self::remove_transactions`] on finalization.
    /// This is what guarantees liveness across view changes: if a proposal is
    /// abandoned (timeout, leader change), the txs it carried are still in
    /// the mempool and will be re-selected by the next leader's
    /// `select_transactions` call.
    ///
    /// Within a single call, a tx is popped at most once (BinaryHeap pop is
    /// destructive); duplicates within the returned `Vec` are therefore
    /// impossible. Across calls, the same tx may be selected for two
    /// concurrent in-flight proposals — that's fine: at most one of those
    /// blocks finalizes, the other proposal is dropped wholesale, and the
    /// `contains_key` check on subsequent selections filters out anything
    /// already finalized.
    pub fn select_transactions(
        &self,
        max_count: usize,
        max_gas: u64,
    ) -> Vec<SignedTransaction> {
        let mut selected = Vec::new();
        let mut total_gas = 0u64;
        let mut reinsert = Vec::new();

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
                reinsert.push(prioritized);
                continue;
            }

            // Check count limit
            if selected.len() >= max_count {
                reinsert.push(prioritized);
                continue;
            }

            // Add to selected, and queue it for reinsertion so it's
            // available again if this proposal doesn't finalize.
            selected.push(tx.clone());
            total_gas += gas_limit;
            reinsert.push(prioritized);
        }

        // Put back every transaction we popped — selected txs included.
        // `remove_transactions` (called on finalization) is what actually
        // takes them out of the mempool. Until then, they must remain
        // selectable so a view-change can't strand them.
        for tx in reinsert {
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

    /// Returns current queue depth bucketed by admission lane.
    ///
    /// Returns `[verified_count, delegated_count, open_count]`; if no
    /// admission controller is wired (early bootstrap) all transactions
    /// are reported as Open. Walks the transaction map and re-resolves
    /// each tx's lane — O(n) in the mempool size. Suitable for periodic
    /// metrics scrapes (every 10–60s); not for the admission hot path.
    pub fn lane_depths(&self) -> [u64; 3] {
        let mut depths = [0u64; 3];
        match self.admission.get() {
            Some(ctrl) => {
                for entry in self.transactions.iter() {
                    let lane = ctrl.assign_lane(entry.value());
                    depths[lane as usize] = depths[lane as usize].saturating_add(1);
                }
            }
            None => {
                // No admission wired — everything is Open lane.
                depths[Lane::Open as usize] = self.transactions.len() as u64;
            }
        }
        depths
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

    /// Regression: `select_transactions` must NOT remove selected txs from
    /// the mempool. They are only removed by `remove_transactions` on
    /// finalization. This is what guarantees liveness when a proposal is
    /// abandoned by a view change — the next leader's selection must still
    /// see them.
    #[test]
    fn test_select_is_non_destructive_across_view_changes() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Mempool::new(config);

        let tx1 = create_test_transaction(100, 1);
        let tx2 = create_test_transaction(200, 2);
        let tx3 = create_test_transaction(150, 3);

        mempool.add_transaction(tx1).unwrap();
        mempool.add_transaction(tx2).unwrap();
        mempool.add_transaction(tx3).unwrap();
        assert_eq!(mempool.len(), 3);

        // Leader 1 selects — proposal is built but never finalizes (e.g. view
        // change before commit QC). `remove_transactions` is NOT called.
        let leader1 = mempool.select_transactions(10, 1_000_000);
        assert_eq!(leader1.len(), 3);
        assert_eq!(mempool.len(), 3, "select must not shrink mempool");

        // Leader 2 selects on the next view. With the buggy
        // destructive-pop-no-reinsert design, this returned 0 — the selected
        // txs were stranded. With the fix, the same 3 txs are re-selected.
        let leader2 = mempool.select_transactions(10, 1_000_000);
        assert_eq!(
            leader2.len(),
            3,
            "after a view change, abandoned txs must be re-selectable"
        );

        // Order is preserved across selections (still gas-priority sorted).
        assert_eq!(leader2[0].transaction.gas_price, 200);

        // Only finalization removes them.
        let hashes: Vec<_> = leader2.iter().cloned().map(|mut t| t.hash()).collect();
        mempool.remove_transactions(&hashes);
        assert_eq!(mempool.len(), 0);

        let leader3 = mempool.select_transactions(10, 1_000_000);
        assert_eq!(leader3.len(), 0);
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

    #[test]
    fn test_fee_floor_rejects_below_open_lane_multiplier() {
        // With admission wired and Open-lane multiplier 4.0× × base 1 Gwei = 4 Gwei,
        // a 100-wei tx must be rejected with FeeFloorTooLow.
        use crate::admission::{AdmissionConfig, AdmissionController, DefaultLaneResolver, Lane};

        let config = ConsensusConfig::default(); // 1 Gwei base floor
        let mempool = Mempool::new(Arc::new(config));

        let admission = Arc::new(AdmissionController::new(
            AdmissionConfig::default(),
            Arc::new(DefaultLaneResolver),
        ));
        mempool.set_admission(admission.clone()).unwrap();

        let tx = create_test_transaction(100, 1); // way below 1 Gwei
        let result = mempool.add_transaction(tx);

        match result {
            Err(ConsensusError::FeeFloorTooLow {
                lane,
                gas_price,
                required,
                base,
                multiplier,
            }) => {
                assert_eq!(lane, Lane::Open.as_str());
                assert_eq!(gas_price, 100);
                assert_eq!(base, 1_000_000_000);
                assert!((multiplier - 4.0).abs() < 1e-9);
                assert_eq!(required, 4_000_000_000);
            }
            other => panic!("expected FeeFloorTooLow, got {:?}", other),
        }

        assert_eq!(mempool.len(), 0, "rejected tx must not enter mempool");
    }

    #[test]
    fn test_fee_floor_admits_at_or_above_open_lane_multiplier() {
        use crate::admission::{AdmissionConfig, AdmissionController, DefaultLaneResolver};

        let config = ConsensusConfig::default(); // 1 Gwei base floor
        let mempool = Mempool::new(Arc::new(config));

        let admission = Arc::new(AdmissionController::new(
            AdmissionConfig::default(),
            Arc::new(DefaultLaneResolver),
        ));
        mempool.set_admission(admission).unwrap();

        // 4 Gwei = exactly the Open-lane floor — must be admitted.
        let tx = create_test_transaction(4_000_000_000, 1);
        mempool.add_transaction(tx).unwrap();
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_fee_floor_disabled_when_base_is_zero() {
        use crate::admission::{AdmissionConfig, AdmissionController, DefaultLaneResolver};

        let config = ConsensusConfig {
            mempool_min_gas_price: 0, // explicitly disable static floor
            ..ConsensusConfig::default()
        };
        let mempool = Mempool::new(Arc::new(config));

        let admission = Arc::new(AdmissionController::new(
            AdmissionConfig::default(),
            Arc::new(DefaultLaneResolver),
        ));
        mempool.set_admission(admission).unwrap();

        // Even gas_price=0 should pass the floor check (then admission token bucket).
        let tx = create_test_transaction(0, 1);
        mempool.add_transaction(tx).unwrap();
        assert_eq!(mempool.len(), 1);
    }

    /// Spec 2 metrics path: the per-lane queue-depth accessor reports
    /// the number of pending transactions in each admission lane.
    /// `DefaultLaneResolver` puts everything in Open, so all admitted
    /// txs land there.
    #[test]
    fn test_lane_depths_with_default_resolver() {
        use crate::admission::{AdmissionConfig, AdmissionController, DefaultLaneResolver, Lane};

        let config = ConsensusConfig {
            mempool_min_gas_price: 0, // skip fee-floor for simpler test
            ..ConsensusConfig::default()
        };
        let mempool = Mempool::new(Arc::new(config));

        let admission = Arc::new(AdmissionController::new(
            AdmissionConfig::default(),
            Arc::new(DefaultLaneResolver),
        ));
        mempool.set_admission(admission).unwrap();

        // Empty mempool: all lanes are zero.
        let depths = mempool.lane_depths();
        assert_eq!(depths, [0, 0, 0]);

        // Admit two transactions — both land in Open via the default resolver.
        mempool.add_transaction(create_test_transaction(1_000_000_000, 1)).unwrap();
        mempool.add_transaction(create_test_transaction(1_000_000_000, 2)).unwrap();

        let depths = mempool.lane_depths();
        assert_eq!(depths[Lane::Verified as usize], 0);
        assert_eq!(depths[Lane::Delegated as usize], 0);
        assert_eq!(depths[Lane::Open as usize], 2);
    }

    /// Without an admission controller wired, `lane_depths` falls back
    /// to attributing every tx to Open. This is the bootstrap path
    /// before identity/staking come online.
    #[test]
    fn test_lane_depths_without_admission_attributes_to_open() {
        use crate::admission::Lane;

        let config = ConsensusConfig {
            mempool_min_gas_price: 0,
            ..ConsensusConfig::default()
        };
        let mempool = Mempool::new(Arc::new(config));

        // No `set_admission` call. Insert 3 txs.
        mempool.add_transaction(create_test_transaction(1_000_000_000, 1)).unwrap();
        mempool.add_transaction(create_test_transaction(1_000_000_000, 2)).unwrap();
        mempool.add_transaction(create_test_transaction(1_000_000_000, 3)).unwrap();

        let depths = mempool.lane_depths();
        assert_eq!(depths[Lane::Verified as usize], 0);
        assert_eq!(depths[Lane::Delegated as usize], 0);
        assert_eq!(depths[Lane::Open as usize], 3);
    }

    /// A fee-floor rejection bumps `rejected_fee_floor` (not the
    /// rate-limited or mempool-full counters) so /metrics can attribute
    /// the cause cleanly.
    #[test]
    fn test_fee_floor_rejection_bumps_correct_counter() {
        use crate::admission::{AdmissionConfig, AdmissionController, DefaultLaneResolver, Lane};

        let config = ConsensusConfig::default();
        let mempool = Mempool::new(Arc::new(config));

        let admission = Arc::new(AdmissionController::new(
            AdmissionConfig::default(),
            Arc::new(DefaultLaneResolver),
        ));
        mempool.set_admission(admission.clone()).unwrap();

        // Below 4× × 1 Gwei Open-lane floor — rejected at fee-floor.
        let tx = create_test_transaction(100, 1);
        let _ = mempool.add_transaction(tx);

        let stats = admission.stats();
        assert_eq!(stats.rejected_fee_floor(Lane::Open), 1);
        assert_eq!(stats.rejected_rate_limited(Lane::Open), 0);
        assert_eq!(stats.rejected_mempool_full(Lane::Open), 0);
        // And the bucket token was *not* consumed — fee-floor runs
        // before try_admit. Subsequent admission attempts must succeed.
        let tx2 = create_test_transaction(4_000_000_000, 2);
        mempool.add_transaction(tx2).unwrap();
        let stats = admission.stats();
        assert_eq!(stats.admitted(Lane::Open), 1);
    }
}
