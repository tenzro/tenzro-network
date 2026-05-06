//! Transaction history tracking for Tenzro Network wallets.
//!
//! Tracks all transactions sent and received by wallet addresses,
//! their confirmation status, and provides query/filter capabilities.

use crate::error::{Result, WalletError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use tenzro_types::primitives::{Address, Hash, Nonce, Timestamp};
use tenzro_types::transaction::TransactionType;

/// Transaction status in the lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxStatus {
    /// Transaction created but not yet submitted
    Created,
    /// Transaction submitted to mempool
    Pending,
    /// Transaction included in a block
    Confirmed,
    /// Transaction reached finality
    Finalized,
    /// Transaction failed during execution
    Failed,
    /// Transaction was replaced (by higher gas price)
    Replaced,
    /// Transaction was dropped from mempool
    Dropped,
}

impl std::fmt::Display for TxStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxStatus::Created => write!(f, "created"),
            TxStatus::Pending => write!(f, "pending"),
            TxStatus::Confirmed => write!(f, "confirmed"),
            TxStatus::Finalized => write!(f, "finalized"),
            TxStatus::Failed => write!(f, "failed"),
            TxStatus::Replaced => write!(f, "replaced"),
            TxStatus::Dropped => write!(f, "dropped"),
        }
    }
}

/// Direction of a transaction relative to a wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxDirection {
    /// Transaction sent from this wallet
    Outgoing,
    /// Transaction received by this wallet
    Incoming,
    /// Self-transaction (e.g., contract interaction from own wallet)
    Internal,
}

/// A recorded transaction in the history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Sender address
    pub from: Address,
    /// Recipient address
    pub to: Address,
    /// Transaction nonce
    pub nonce: Nonce,
    /// Transaction type
    pub tx_type: TransactionType,
    /// Gas limit set
    pub gas_limit: u64,
    /// Gas price set
    pub gas_price: u64,
    /// Gas actually used (set after confirmation)
    pub gas_used: Option<u64>,
    /// Current status
    pub status: TxStatus,
    /// Direction relative to the tracking wallet
    pub direction: TxDirection,
    /// Block height where included (set after confirmation)
    pub block_height: Option<u64>,
    /// Timestamp when the transaction was created
    pub created_at: Timestamp,
    /// Timestamp when confirmed (set after confirmation)
    pub confirmed_at: Option<Timestamp>,
    /// Optional error message (set on failure)
    pub error: Option<String>,
    /// Optional memo from the transaction
    pub memo: Option<String>,
}

impl TxRecord {
    /// Create a new outgoing transaction record.
    pub fn new_outgoing(
        tx_hash: Hash,
        from: Address,
        to: Address,
        nonce: Nonce,
        tx_type: TransactionType,
        gas_limit: u64,
        gas_price: u64,
        memo: Option<String>,
    ) -> Self {
        Self {
            tx_hash,
            from,
            to,
            nonce,
            tx_type,
            gas_limit,
            gas_price,
            gas_used: None,
            status: TxStatus::Created,
            direction: TxDirection::Outgoing,
            block_height: None,
            created_at: Timestamp::now(),
            confirmed_at: None,
            error: None,
            memo,
        }
    }

    /// Create a new incoming transaction record.
    pub fn new_incoming(
        tx_hash: Hash,
        from: Address,
        to: Address,
        nonce: Nonce,
        tx_type: TransactionType,
        gas_limit: u64,
        gas_price: u64,
        block_height: u64,
    ) -> Self {
        Self {
            tx_hash,
            from,
            to,
            nonce,
            tx_type,
            gas_limit,
            gas_price,
            gas_used: None,
            status: TxStatus::Confirmed,
            direction: TxDirection::Incoming,
            block_height: Some(block_height),
            created_at: Timestamp::now(),
            confirmed_at: Some(Timestamp::now()),
            error: None,
            memo: None,
        }
    }

    /// Mark the transaction as submitted to mempool.
    pub fn mark_pending(&mut self) {
        self.status = TxStatus::Pending;
    }

    /// Mark the transaction as confirmed in a block.
    pub fn mark_confirmed(&mut self, block_height: u64, gas_used: u64) {
        self.status = TxStatus::Confirmed;
        self.block_height = Some(block_height);
        self.gas_used = Some(gas_used);
        self.confirmed_at = Some(Timestamp::now());
    }

    /// Mark the transaction as finalized.
    pub fn mark_finalized(&mut self) {
        self.status = TxStatus::Finalized;
    }

    /// Mark the transaction as failed.
    pub fn mark_failed(&mut self, error: String) {
        self.status = TxStatus::Failed;
        self.error = Some(error);
    }

    /// Mark the transaction as dropped from mempool.
    pub fn mark_dropped(&mut self) {
        self.status = TxStatus::Dropped;
    }

    /// Check if the transaction is still pending.
    pub fn is_pending(&self) -> bool {
        matches!(self.status, TxStatus::Created | TxStatus::Pending)
    }

    /// Check if the transaction is confirmed or finalized.
    pub fn is_confirmed(&self) -> bool {
        matches!(self.status, TxStatus::Confirmed | TxStatus::Finalized)
    }

    /// Get the effective gas cost (gas_used * gas_price).
    pub fn gas_cost(&self) -> Option<u128> {
        self.gas_used
            .map(|used| (used as u128) * (self.gas_price as u128))
    }

    /// Get the transfer value if this is a transfer-type transaction.
    pub fn value(&self) -> u128 {
        match &self.tx_type {
            TransactionType::Transfer { amount } => *amount,
            TransactionType::ProviderStake { amount, .. } => *amount,
            TransactionType::ProviderUnstake { amount } => *amount,
            TransactionType::BridgeTransfer { amount, .. } => *amount,
            _ => 0,
        }
    }
}

/// Query filter for transaction history.
#[derive(Debug, Clone, Default)]
pub struct HistoryFilter {
    /// Filter by status
    pub status: Option<TxStatus>,
    /// Filter by direction
    pub direction: Option<TxDirection>,
    /// Filter by minimum timestamp
    pub after: Option<Timestamp>,
    /// Filter by maximum timestamp
    pub before: Option<Timestamp>,
    /// Maximum number of results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: usize,
}

impl HistoryFilter {
    /// Create a new filter for pending transactions.
    pub fn pending() -> Self {
        Self {
            status: Some(TxStatus::Pending),
            ..Default::default()
        }
    }

    /// Create a new filter for confirmed transactions.
    pub fn confirmed() -> Self {
        Self {
            status: Some(TxStatus::Confirmed),
            ..Default::default()
        }
    }

    /// Create a new filter for outgoing transactions.
    pub fn outgoing() -> Self {
        Self {
            direction: Some(TxDirection::Outgoing),
            ..Default::default()
        }
    }

    /// Create a new filter for incoming transactions.
    pub fn incoming() -> Self {
        Self {
            direction: Some(TxDirection::Incoming),
            ..Default::default()
        }
    }

    /// Set the result limit.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set the offset for pagination.
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }
}

/// Transaction history tracker for wallet addresses.
///
/// Stores transaction records indexed by address and provides
/// query/filter capabilities for retrieving history.
pub struct TransactionHistory {
    /// Records indexed by address → list of records
    records: DashMap<Address, Vec<TxRecord>>,
    /// Index by transaction hash for quick lookups
    hash_index: DashMap<Hash, (Address, usize)>,
    /// Total record count
    total_count: AtomicU64,
}

impl TransactionHistory {
    /// Create a new transaction history tracker.
    pub fn new() -> Self {
        Self {
            records: DashMap::new(),
            hash_index: DashMap::new(),
            total_count: AtomicU64::new(0),
        }
    }

    /// Record a new transaction.
    pub fn record(&self, address: &Address, record: TxRecord) {
        let tx_hash = record.tx_hash;
        let mut entries = self.records.entry(*address).or_default();
        let idx = entries.len();
        entries.push(record);
        self.hash_index.insert(tx_hash, (*address, idx));
        self.total_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a transaction record by hash.
    pub fn get_by_hash(&self, tx_hash: &Hash) -> Option<TxRecord> {
        if let Some(entry) = self.hash_index.get(tx_hash) {
            let (address, idx) = entry.value();
            if let Some(records) = self.records.get(address) {
                return records.get(*idx).cloned();
            }
        }
        None
    }

    /// Update the status of a transaction by hash.
    pub fn update_status(&self, tx_hash: &Hash, status: TxStatus) -> Result<()> {
        if let Some(entry) = self.hash_index.get(tx_hash) {
            let (address, idx) = entry.value();
            if let Some(mut records) = self.records.get_mut(address)
                && let Some(record) = records.get_mut(*idx)
            {
                record.status = status;
                return Ok(());
            }
        }
        Err(WalletError::Other(format!(
            "Transaction {} not found in history",
            tx_hash
        )))
    }

    /// Mark a transaction as confirmed.
    pub fn confirm(&self, tx_hash: &Hash, block_height: u64, gas_used: u64) -> Result<()> {
        if let Some(entry) = self.hash_index.get(tx_hash) {
            let (address, idx) = entry.value();
            if let Some(mut records) = self.records.get_mut(address)
                && let Some(record) = records.get_mut(*idx)
            {
                record.mark_confirmed(block_height, gas_used);
                return Ok(());
            }
        }
        Err(WalletError::Other(format!(
            "Transaction {} not found in history",
            tx_hash
        )))
    }

    /// Get all records for an address.
    pub fn get_history(&self, address: &Address) -> Vec<TxRecord> {
        self.records
            .get(address)
            .map(|records| records.clone())
            .unwrap_or_default()
    }

    /// Get filtered records for an address.
    pub fn get_filtered(&self, address: &Address, filter: &HistoryFilter) -> Vec<TxRecord> {
        let records = self
            .records
            .get(address)
            .map(|r| r.clone())
            .unwrap_or_default();

        let filtered: Vec<TxRecord> = records
            .into_iter()
            .filter(|r| {
                if let Some(status) = &filter.status
                    && r.status != *status
                {
                    return false;
                }
                if let Some(direction) = &filter.direction
                    && r.direction != *direction
                {
                    return false;
                }
                if let Some(after) = &filter.after
                    && r.created_at.0 < after.0
                {
                    return false;
                }
                if let Some(before) = &filter.before
                    && r.created_at.0 > before.0
                {
                    return false;
                }
                true
            })
            .skip(filter.offset)
            .take(filter.limit.unwrap_or(usize::MAX))
            .collect();

        filtered
    }

    /// Get the number of pending transactions for an address.
    pub fn pending_count(&self, address: &Address) -> usize {
        self.records
            .get(address)
            .map(|records| records.iter().filter(|r| r.is_pending()).count())
            .unwrap_or(0)
    }

    /// Get total record count across all addresses.
    pub fn total_count(&self) -> u64 {
        self.total_count.load(Ordering::Relaxed)
    }

    /// Clear all history for an address.
    pub fn clear(&self, address: &Address) {
        if let Some((_, records)) = self.records.remove(address) {
            for record in &records {
                self.hash_index.remove(&record.tx_hash);
            }
            self.total_count
                .fetch_sub(records.len() as u64, Ordering::Relaxed);
        }
    }

    /// Clear all history.
    pub fn clear_all(&self) {
        self.records.clear();
        self.hash_index.clear();
        self.total_count.store(0, Ordering::Relaxed);
    }
}

impl Default for TransactionHistory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_types::primitives::ChainId;
    use tenzro_types::transaction::Transaction;

    fn test_tx_record(from: Address, to: Address) -> TxRecord {
        let pq_pk = MlDsaSigningKey::generate().verifying_key_bytes().to_vec();
        let tx = Transaction::new(
            ChainId(1337),
            from,
            to,
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            21_000,
            1_000_000_000,
            pq_pk,
        );
        TxRecord::new_outgoing(
            tx.hash(),
            from,
            to,
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            21_000,
            1_000_000_000,
            None,
        )
    }

    #[test]
    fn test_record_and_retrieve() {
        let history = TransactionHistory::new();
        let addr = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);

        let record = test_tx_record(addr, to);
        let tx_hash = record.tx_hash;

        history.record(&addr, record);

        let retrieved = history.get_by_hash(&tx_hash).unwrap();
        assert_eq!(retrieved.tx_hash, tx_hash);
        assert_eq!(retrieved.from, addr);
        assert_eq!(retrieved.status, TxStatus::Created);
    }

    #[test]
    fn test_confirm_transaction() {
        let history = TransactionHistory::new();
        let addr = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);

        let record = test_tx_record(addr, to);
        let tx_hash = record.tx_hash;

        history.record(&addr, record);
        history.confirm(&tx_hash, 100, 21_000).unwrap();

        let retrieved = history.get_by_hash(&tx_hash).unwrap();
        assert_eq!(retrieved.status, TxStatus::Confirmed);
        assert_eq!(retrieved.block_height, Some(100));
        assert_eq!(retrieved.gas_used, Some(21_000));
    }

    #[test]
    fn test_filter_by_status() {
        let history = TransactionHistory::new();
        let addr = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);

        // Add 3 records
        let r1 = test_tx_record(addr, to);
        let hash1 = r1.tx_hash;
        history.record(&addr, r1);

        let r2 = test_tx_record(addr, to);
        history.record(&addr, r2);

        let r3 = test_tx_record(addr, to);
        history.record(&addr, r3);

        // Confirm first one
        history.confirm(&hash1, 100, 21_000).unwrap();

        let confirmed = history.get_filtered(&addr, &HistoryFilter::confirmed());
        assert_eq!(confirmed.len(), 1);

        // Created records still show as "Created" not "Pending"
        let all = history.get_history(&addr);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_pagination() {
        let history = TransactionHistory::new();
        let addr = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);

        for _ in 0..10 {
            history.record(&addr, test_tx_record(addr, to));
        }

        let filter = HistoryFilter::default()
            .with_limit(3)
            .with_offset(2);

        let page = history.get_filtered(&addr, &filter);
        assert_eq!(page.len(), 3);
    }

    #[test]
    fn test_pending_count() {
        let history = TransactionHistory::new();
        let addr = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);

        let r1 = test_tx_record(addr, to);
        let hash1 = r1.tx_hash;
        history.record(&addr, r1);
        history.record(&addr, test_tx_record(addr, to));

        assert_eq!(history.pending_count(&addr), 2);

        history.confirm(&hash1, 100, 21_000).unwrap();
        assert_eq!(history.pending_count(&addr), 1);
    }

    #[test]
    fn test_gas_cost() {
        let mut record = test_tx_record(Address::new([1u8; 32]), Address::new([2u8; 32]));
        assert!(record.gas_cost().is_none());

        record.mark_confirmed(100, 21_000);
        // gas_cost = 21_000 * 1_000_000_000 = 21_000_000_000_000
        assert_eq!(record.gas_cost(), Some(21_000_000_000_000u128));
    }

    #[test]
    fn test_clear_history() {
        let history = TransactionHistory::new();
        let addr = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);

        history.record(&addr, test_tx_record(addr, to));
        history.record(&addr, test_tx_record(addr, to));
        assert_eq!(history.total_count(), 2);

        history.clear(&addr);
        assert_eq!(history.get_history(&addr).len(), 0);
        assert_eq!(history.total_count(), 0);
    }
}
