//! Transaction mempool with priority ordering.
//!
//! ## Mempool ↔ proposer coupling
//!
//! `select_transactions` is **non-destructive**: it reads the priority queue
//! without removing anything. Removal happens only via [`Mempool::remove_transactions`],
//! which the consensus engine invokes on **finalization** of a block.
//!
//! This is the canonical production pattern — the same
//! reap-then-update split used by production BFT mempools, including the
//! pre-quorum-store design. It guarantees liveness across view changes:
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
//! Future direction: abandon priority-pull entirely in favor of a quorum store
//! or DAG-based mempool design, where data availability is
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
use tenzro_types::primitives::{Address, Hash};
use tenzro_types::transaction::{SignedTransaction, TransactionType};

/// Read access to live account execution state for stateful admission.
///
/// Implemented by the node layer over the VM execution state (CF_STATE
/// `nonce:` / balance keys) and wired post-construction via
/// [`Mempool::set_state_reader`] — same lifecycle as the Spec 2 admission
/// controller. When unwired (tests, early bootstrap before storage is up),
/// the mempool skips nonce/balance validation and relies on execution-time
/// rejection alone.
pub trait AccountStateReader: Send + Sync {
    /// Current execution-state nonce for `address` (0 for unknown accounts).
    fn account_nonce(&self, address: &Address) -> u64;

    /// Current spendable balance for `address` (0 for unknown accounts).
    fn account_balance(&self, address: &Address) -> u128;
}

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

    /// Live account state reader for stateful admission (nonce ordering +
    /// balance coverage). Same wire-once lifecycle as `admission`; when
    /// unset, nonce/balance checks are skipped and only execution rejects
    /// invalid transactions.
    state_reader: OnceLock<Arc<dyn AccountStateReader>>,

    /// Pending-transaction count per sender address. Enforces
    /// `ConsensusConfig::mempool_max_per_sender` so a single account cannot
    /// monopolize shared mempool capacity. Incremented on insert,
    /// decremented in `remove_transaction`, cleared in `clear`.
    sender_counts: Arc<DashMap<Address, usize>>,
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
            state_reader: OnceLock::new(),
            sender_counts: Arc::new(DashMap::new()),
        }
    }

    /// Wire an account state reader into a live `Mempool` for stateful
    /// admission (nonce ordering + balance coverage). Same at-most-once
    /// contract as [`Self::set_admission`].
    pub fn set_state_reader(&self, reader: Arc<dyn AccountStateReader>) -> Result<()> {
        self.state_reader
            .set(reader)
            .map_err(|_| ConsensusError::AlreadyStarted)
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

        // Per-sender pending cap. Runs regardless of whether a state reader
        // is wired — it is a pure mempool-shape invariant, not a state check.
        let sender = transaction.transaction.from;
        let per_sender_cap = self.config.mempool_max_per_sender;
        if per_sender_cap > 0 {
            let pending = self
                .sender_counts
                .get(&sender)
                .map(|c| *c.value())
                .unwrap_or(0);
            if pending >= per_sender_cap {
                return Err(ConsensusError::SenderCapExceeded {
                    sender: sender.to_string(),
                    pending,
                    cap: per_sender_cap,
                });
            }
        }

        // Stateful admission: nonce ordering + balance coverage against live
        // execution state. Skipped when no reader is wired (tests, early
        // bootstrap) — execution-time rejection is the backstop.
        if let Some(reader) = self.state_reader.get() {
            let account_nonce = reader.account_nonce(&sender);
            let tx_nonce = transaction.transaction.nonce.0;

            if tx_nonce < account_nonce {
                return Err(ConsensusError::NonceTooLow {
                    sender: sender.to_string(),
                    tx_nonce,
                    account_nonce,
                });
            }

            // Bound the future-nonce gap so unexecutable transactions can't
            // park in the mempool indefinitely. The per-sender cap doubles as
            // the look-ahead window.
            if per_sender_cap > 0 && tx_nonce > account_nonce.saturating_add(per_sender_cap as u64)
            {
                return Err(ConsensusError::NonceGapTooLarge {
                    sender: sender.to_string(),
                    tx_nonce,
                    account_nonce,
                    max_gap: per_sender_cap as u64,
                });
            }

            // Worst-case cost: gas_limit × gas_price + transferred value.
            let value: u128 = match &transaction.transaction.tx_type {
                TransactionType::Transfer { amount } => *amount,
                TransactionType::ProviderStake { amount, .. } => *amount,
                TransactionType::BridgeTransfer { amount, .. } => *amount,
                TransactionType::CreateEscrow { amount, .. } => *amount,
                _ => 0,
            };
            let required = (transaction.transaction.gas_limit as u128)
                .saturating_mul(transaction.transaction.gas_price as u128)
                .saturating_add(value);
            let balance = reader.account_balance(&sender);
            if balance < required {
                return Err(ConsensusError::InsufficientBalance {
                    sender: sender.to_string(),
                    balance,
                    required,
                });
            }
        }

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
        *self.sender_counts.entry(sender).or_insert(0) += 1;

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

            let sender = transaction.transaction.from;
            if let Some(mut count) = self.sender_counts.get_mut(&sender) {
                if *count.value() <= 1 {
                    drop(count);
                    self.sender_counts.remove(&sender);
                } else {
                    *count.value_mut() -= 1;
                }
            }

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
        self.sender_counts.clear();
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

    /// Mock state reader with fixed nonce/balance for every address.
    struct FixedStateReader {
        nonce: u64,
        balance: u128,
    }

    impl AccountStateReader for FixedStateReader {
        fn account_nonce(&self, _address: &Address) -> u64 {
            self.nonce
        }
        fn account_balance(&self, _address: &Address) -> u128 {
            self.balance
        }
    }

    #[test]
    fn test_stateful_admission_rejects_stale_nonce() {
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        mempool
            .set_state_reader(Arc::new(FixedStateReader {
                nonce: 5,
                balance: u128::MAX,
            }))
            .unwrap();

        // tx nonce 1 < account nonce 5 — can never execute.
        let result = mempool.add_transaction(create_test_transaction(1_000_000_000, 1));
        match result {
            Err(ConsensusError::NonceTooLow {
                tx_nonce,
                account_nonce,
                ..
            }) => {
                assert_eq!(tx_nonce, 1);
                assert_eq!(account_nonce, 5);
            }
            other => panic!("expected NonceTooLow, got {:?}", other),
        }
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_stateful_admission_rejects_excessive_nonce_gap() {
        let config = ConsensusConfig {
            mempool_max_per_sender: 8,
            ..ConsensusConfig::default()
        };
        let mempool = Mempool::new(Arc::new(config));
        mempool
            .set_state_reader(Arc::new(FixedStateReader {
                nonce: 0,
                balance: u128::MAX,
            }))
            .unwrap();

        // nonce 9 > account nonce 0 + gap 8 — parked-forever spam.
        let result = mempool.add_transaction(create_test_transaction(1_000_000_000, 9));
        match result {
            Err(ConsensusError::NonceGapTooLarge {
                tx_nonce, max_gap, ..
            }) => {
                assert_eq!(tx_nonce, 9);
                assert_eq!(max_gap, 8);
            }
            other => panic!("expected NonceGapTooLarge, got {:?}", other),
        }

        // nonce 8 == account nonce 0 + gap 8 — at the boundary, admitted.
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 8))
            .unwrap();
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_stateful_admission_rejects_insufficient_balance() {
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        // Balance covers neither gas nor the 1000-unit transfer value.
        mempool
            .set_state_reader(Arc::new(FixedStateReader {
                nonce: 0,
                balance: 10,
            }))
            .unwrap();

        let result = mempool.add_transaction(create_test_transaction(1_000_000_000, 0));
        match result {
            Err(ConsensusError::InsufficientBalance {
                balance, required, ..
            }) => {
                assert_eq!(balance, 10);
                // 21000 gas × 1 Gwei + 1000 transfer value
                assert_eq!(required, 21_000u128 * 1_000_000_000 + 1000);
            }
            other => panic!("expected InsufficientBalance, got {:?}", other),
        }
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_stateful_admission_admits_when_balance_covers_cost() {
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        mempool
            .set_state_reader(Arc::new(FixedStateReader {
                nonce: 0,
                balance: 21_000u128 * 1_000_000_000 + 1000,
            }))
            .unwrap();

        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 0))
            .unwrap();
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_per_sender_cap_enforced_and_released() {
        let config = ConsensusConfig {
            mempool_max_per_sender: 2,
            ..ConsensusConfig::default()
        };
        let mempool = Mempool::new(Arc::new(config));

        // All test txs share Address::default() as sender.
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 0))
            .unwrap();
        let mut second = create_test_transaction(1_000_000_001, 1);
        let second_hash = second.hash();
        mempool.add_transaction(second).unwrap();

        // Third pending tx from the same sender exceeds the cap.
        let result = mempool.add_transaction(create_test_transaction(1_000_000_002, 2));
        match result {
            Err(ConsensusError::SenderCapExceeded { pending, cap, .. }) => {
                assert_eq!(pending, 2);
                assert_eq!(cap, 2);
            }
            other => panic!("expected SenderCapExceeded, got {:?}", other),
        }

        // Removing one pending tx frees a slot.
        mempool.remove_transaction(&second_hash);
        mempool
            .add_transaction(create_test_transaction(1_000_000_002, 2))
            .unwrap();
        assert_eq!(mempool.len(), 2);
    }

    #[test]
    fn test_unwired_state_reader_skips_stateful_checks() {
        // No set_state_reader call: a stale-nonce, zero-balance-account tx
        // still enters the mempool (execution is the backstop).
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 999))
            .unwrap();
        assert_eq!(mempool.len(), 1);
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
