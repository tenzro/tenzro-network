//! Batch settlement processing for atomic multi-settlement operations
//!
//! When a [`KvStore`] is wired via [`BatchProcessor::with_storage`], batch results
//! are persisted atomically using [`KvStore::write_batch_sync`].  All settlement
//! receipts and the batch metadata are collected in memory first and flushed in a
//! single atomic write — if any settlement in the batch fails, nothing is written
//! (atomic rollback).  Without storage the processor falls back to in-memory
//! DashMap-only bookkeeping (the original behaviour).

use crate::error::{Result, SettlementError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_storage::{
    CF_SETTLEMENTS, KvStore, ReceiptEnvelope, ReceiptKind, ReceiptStorageMode, ReceiptSummary,
    WriteOp, compute_commitment,
};
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_types::settlement::{SettlementReceipt, SettlementRequest};
use tracing::{debug, info, warn};

/// Status of a settlement batch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchStatus {
    /// Batch created but not yet processing
    Created,
    /// Batch is currently being processed
    Processing,
    /// All settlements in batch completed successfully
    Completed,
    /// One or more settlements failed
    Failed,
    /// Batch was rolled back
    RolledBack,
}

/// A batch of settlement requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementBatch {
    /// Unique batch identifier
    pub batch_id: String,
    /// Settlement requests in this batch
    pub settlements: Vec<SettlementRequest>,
    /// Current status
    pub status: BatchStatus,
    /// Timestamp when batch was created
    pub created_at: Timestamp,
    /// Timestamp when processing started
    pub started_at: Option<Timestamp>,
    /// Timestamp when batch completed
    pub completed_at: Option<Timestamp>,
    /// Error message if failed
    pub error: Option<String>,
}

impl SettlementBatch {
    /// Creates a new settlement batch
    pub fn new(settlements: Vec<SettlementRequest>) -> Self {
        Self {
            batch_id: uuid::Uuid::new_v4().to_string(),
            settlements,
            status: BatchStatus::Created,
            created_at: Timestamp::now(),
            started_at: None,
            completed_at: None,
            error: None,
        }
    }

    /// Returns the number of settlements in the batch
    pub fn size(&self) -> usize {
        self.settlements.len()
    }

    /// Checks if batch is empty
    pub fn is_empty(&self) -> bool {
        self.settlements.is_empty()
    }
}

/// Result of a batch settlement operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSettlementResult {
    /// Batch ID
    pub batch_id: String,
    /// Final status
    pub status: BatchStatus,
    /// Receipts for successful settlements
    pub receipts: Vec<SettlementReceipt>,
    /// Number of successful settlements
    pub successful: usize,
    /// Number of failed settlements
    pub failed: usize,
    /// Processing duration in milliseconds
    pub duration_ms: i64,
}

/// Batch processor for atomic multi-settlement operations
///
/// When constructed with [`Self::with_storage`], completed batch results are
/// persisted atomically via [`KvStore::write_batch_sync`].  All receipts and
/// batch metadata are collected in memory during processing; on success they
/// are flushed as a single atomic write batch.  On failure nothing is written
/// (true atomic rollback).
pub struct BatchProcessor {
    /// Active and completed batches
    batches: DashMap<String, SettlementBatch>,
    /// Batch results
    results: DashMap<String, BatchSettlementResult>,
    /// Maximum batch size
    max_batch_size: usize,
    /// Optional reference to account balances for snapshot/rollback atomicity
    balances: Option<Arc<DashMap<(Address, AssetId), u128>>>,
    /// Optional durable storage backend for atomic persistence
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for BatchProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchProcessor")
            .field("max_batch_size", &self.max_batch_size)
            .field("batches", &self.batches.len())
            .field("results", &self.results.len())
            .field("has_storage", &self.storage.is_some())
            .finish()
    }
}

impl BatchProcessor {
    /// Creates a new batch processor
    pub fn new(max_batch_size: usize) -> Self {
        Self {
            batches: DashMap::new(),
            results: DashMap::new(),
            max_batch_size,
            balances: None,
            storage: None,
        }
    }

    /// Creates a new batch processor with balance reference for atomic rollback
    pub fn with_balances(
        max_batch_size: usize,
        balances: Arc<DashMap<(Address, AssetId), u128>>,
    ) -> Self {
        Self {
            batches: DashMap::new(),
            results: DashMap::new(),
            max_batch_size,
            balances: Some(balances),
            storage: None,
        }
    }

    /// Attaches a durable storage backend for atomic batch persistence.
    ///
    /// When storage is attached, successful batch results (batch metadata and
    /// every settlement receipt) are written in a single atomic
    /// [`KvStore::write_batch_sync`] call.  Failed batches are never persisted.
    pub fn with_storage(mut self, storage: Arc<dyn KvStore>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Takes a snapshot of all current balances for rollback
    fn snapshot_balances(&self) -> HashMap<(Address, AssetId), u128> {
        let mut snapshot = HashMap::new();
        if let Some(ref balances) = self.balances {
            for entry in balances.iter() {
                snapshot.insert(entry.key().clone(), *entry.value());
            }
        }
        snapshot
    }

    /// Restores balances from a snapshot (rollback)
    fn restore_balances(&self, snapshot: &HashMap<(Address, AssetId), u128>) {
        if let Some(ref balances) = self.balances {
            // Remove any keys that weren't in the snapshot (new entries)
            let current_keys: Vec<_> = balances.iter().map(|e| e.key().clone()).collect();
            for key in &current_keys {
                if !snapshot.contains_key(key) {
                    balances.remove(key);
                }
            }
            // Restore original values
            for (key, value) in snapshot {
                balances.insert(key.clone(), *value);
            }
        }
    }

    /// Creates a new batch from settlement requests
    pub fn create_batch(&self, settlements: Vec<SettlementRequest>) -> Result<SettlementBatch> {
        if settlements.is_empty() {
            return Err(SettlementError::BatchError(
                "Cannot create empty batch".to_string(),
            ));
        }

        if settlements.len() > self.max_batch_size {
            return Err(SettlementError::BatchError(format!(
                "Batch size {} exceeds maximum {}",
                settlements.len(),
                self.max_batch_size
            )));
        }

        let batch = SettlementBatch::new(settlements);
        let batch_id = batch.batch_id.clone();

        self.batches.insert(batch_id.clone(), batch.clone());

        info!(
            "Created settlement batch {} with {} settlements",
            batch_id,
            batch.size()
        );

        Ok(batch)
    }

    /// Persists batch metadata and all receipts atomically via `write_batch_sync`.
    ///
    /// Storage key layout inside `CF_SETTLEMENTS`:
    /// - `batch:{batch_id}` — serialised [`SettlementBatch`]
    /// - `batch_result:{batch_id}` — serialised [`BatchSettlementResult`]
    /// - `receipt:{batch_id}:{index}` — serialised [`SettlementReceipt`]
    fn persist_batch_result(
        &self,
        batch: &SettlementBatch,
        result: &BatchSettlementResult,
    ) -> Result<()> {
        let storage = match self.storage.as_ref() {
            Some(s) => s,
            None => return Ok(()), // No storage attached — skip persistence
        };

        let mut ops = Vec::with_capacity(2 + result.receipts.len());

        // 1. Batch metadata
        let batch_key = format!("batch:{}", batch.batch_id);
        let batch_value = serde_json::to_vec(batch).map_err(|e| {
            SettlementError::BatchError(format!("Failed to serialize batch metadata: {}", e))
        })?;
        ops.push(WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: batch_key.into_bytes(),
            value: batch_value,
        });

        // 2. Batch result
        let result_key = format!("batch_result:{}", result.batch_id);
        let result_value = serde_json::to_vec(result).map_err(|e| {
            SettlementError::BatchError(format!("Failed to serialize batch result: {}", e))
        })?;
        ops.push(WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: result_key.into_bytes(),
            value: result_value,
        });

        // 3. Individual receipts (indexed for efficient lookup) wrapped in
        //    `ReceiptEnvelope` per Spec 7 / Tasks #147 + #150. Same
        //    `ReceiptKind::SettlementEscrow` + Inline mode as the single-
        //    settlement engine path; same canonical payload encoding
        //    (`serde_json::to_vec(&SettlementReceipt)`).
        for (i, receipt) in result.receipts.iter().enumerate() {
            let receipt_key = format!("receipt:{}:{}", result.batch_id, i);
            let payload = serde_json::to_vec(receipt).map_err(|e| {
                SettlementError::BatchError(format!("Failed to serialize receipt: {}", e))
            })?;
            let summary = ReceiptSummary {
                receipt_id: compute_commitment(receipt.receipt_id.as_bytes()),
                payer: Some(format!("{}", receipt.customer)),
                payee: Some(format!("{}", receipt.provider)),
                amount_wei: Some(receipt.amount as u128),
                timestamp: receipt.settled_at,
                principal_chain_summary: Some(receipt.principal_chain.summary()),
            };
            let kind = ReceiptKind::SettlementEscrow;
            debug_assert_eq!(kind.default_mode(), ReceiptStorageMode::Inline);
            let envelope = ReceiptEnvelope::inline(kind, summary, payload);
            envelope
                .validate()
                .map_err(|e| SettlementError::BatchError(format!("envelope validate: {}", e)))?;
            let receipt_value = serde_json::to_vec(&envelope).map_err(|e| {
                SettlementError::BatchError(format!("Failed to serialize receipt envelope: {}", e))
            })?;
            ops.push(WriteOp::Put {
                cf: CF_SETTLEMENTS.to_string(),
                key: receipt_key.into_bytes(),
                value: receipt_value,
            });
        }

        // Atomic, durable write — either all keys land or none do.
        storage.write_batch_sync(ops).map_err(|e| {
            SettlementError::BatchError(format!(
                "Atomic storage write failed for batch {}: {}",
                batch.batch_id, e
            ))
        })?;

        debug!(
            "Persisted batch {} with {} receipts to storage",
            batch.batch_id,
            result.receipts.len()
        );

        Ok(())
    }

    /// Processes a batch atomically.
    ///
    /// 1. Snapshots in-memory balances.
    /// 2. Executes every settlement via `settle_fn`.
    /// 3. On first failure: restores the balance snapshot, clears receipts,
    ///    marks the batch as `Failed`, and returns **without** writing anything
    ///    to durable storage (atomic rollback).
    /// 4. On success: atomically flushes batch metadata + all receipts to
    ///    storage via [`KvStore::write_batch_sync`] (when storage is attached),
    ///    then updates the in-memory DashMaps.
    pub async fn process_batch<F, Fut>(
        &self,
        batch_id: &str,
        settle_fn: F,
    ) -> Result<BatchSettlementResult>
    where
        F: Fn(SettlementRequest) -> Fut,
        Fut: std::future::Future<Output = Result<SettlementReceipt>>,
    {
        // Get and update batch
        let mut batch_entry = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| SettlementError::BatchError(format!("Batch {} not found", batch_id)))?;

        let batch = batch_entry.value_mut();

        if batch.status != BatchStatus::Created {
            return Err(SettlementError::BatchError(format!(
                "Batch {} is not in Created state",
                batch_id
            )));
        }

        // Update status to processing
        batch.status = BatchStatus::Processing;
        batch.started_at = Some(Timestamp::now());
        let start_time = batch.started_at.unwrap();

        let settlements = batch.settlements.clone();
        drop(batch_entry);

        info!(
            "Processing batch {} with {} settlements",
            batch_id,
            settlements.len()
        );

        // Snapshot balances before processing for atomic rollback
        let balance_snapshot = self.snapshot_balances();

        // Process all settlements — collect results in memory first
        let mut receipts = Vec::new();
        let mut failed = 0;
        let mut last_error: Option<String> = None;

        for settlement in settlements {
            match settle_fn(settlement).await {
                Ok(receipt) => {
                    receipts.push(receipt);
                }
                Err(e) => {
                    failed += 1;
                    last_error = Some(e.to_string());
                    warn!("Settlement failed in batch {}: {}", batch_id, e);
                    break; // Stop on first failure for atomicity
                }
            }
        }

        let end_time = Timestamp::now();
        let duration_ms = end_time.as_millis() - start_time.as_millis();

        // If any settlement failed, rollback all balance changes and do NOT
        // persist anything — this is the atomic rollback guarantee.
        if failed > 0 {
            self.restore_balances(&balance_snapshot);
            info!(
                "Rolled back {} successful settlements in batch {} due to failure",
                receipts.len(),
                batch_id
            );
            receipts.clear(); // Clear receipts since we rolled back
        }

        // Update batch status in memory, then drop the DashMap ref before
        // calling persist_batch_result (which acquires storage locks).
        // Holding a DashMap Ref across another lock risks deadlocks.
        let (batch_snapshot, result) = {
            let mut batch_entry = self.batches.get_mut(batch_id).unwrap();
            let batch = batch_entry.value_mut();

            if failed > 0 {
                batch.status = BatchStatus::Failed;
                batch.error = last_error.clone();
                warn!(
                    "Batch {} failed with {} errors, all changes rolled back",
                    batch_id, failed
                );
            } else {
                batch.status = BatchStatus::Completed;
                info!("Batch {} completed successfully", batch_id);
            }

            batch.completed_at = Some(end_time);

            let result = BatchSettlementResult {
                batch_id: batch_id.to_string(),
                status: batch.status,
                receipts: receipts.clone(),
                successful: receipts.len(),
                failed,
                duration_ms,
            };

            (batch.clone(), result)
            // batch_entry dropped here — DashMap ref released
        };

        // Persist atomically to durable storage ONLY on success.
        // On failure we intentionally skip this so no partial state leaks.
        if failed == 0
            && let Err(e) = self.persist_batch_result(&batch_snapshot, &result)
        {
            // Storage write failed — rollback in-memory state too so the
            // caller sees a consistent failure rather than an in-memory
            // success that never hit disk.
            self.restore_balances(&balance_snapshot);
            {
                let mut batch_entry = self.batches.get_mut(batch_id).unwrap();
                let batch = batch_entry.value_mut();
                batch.status = BatchStatus::Failed;
                batch.error = Some(format!("Storage persistence failed: {}", e));
                batch.completed_at = Some(Timestamp::now());
            }

            let failed_result = BatchSettlementResult {
                batch_id: batch_id.to_string(),
                status: BatchStatus::Failed,
                receipts: Vec::new(),
                successful: 0,
                failed: 1,
                duration_ms,
            };
            self.results
                .insert(batch_id.to_string(), failed_result.clone());
            return Err(e);
        }

        // Store result in the in-memory index
        self.results.insert(batch_id.to_string(), result.clone());

        Ok(result)
    }

    /// Loads a batch result from durable storage.
    ///
    /// Returns `None` when no storage is attached or the batch is not found.
    pub fn load_batch_result(&self, batch_id: &str) -> Result<Option<BatchSettlementResult>> {
        let storage = match self.storage.as_ref() {
            Some(s) => s,
            None => return Ok(None),
        };

        let result_key = format!("batch_result:{}", batch_id);
        match storage
            .get(CF_SETTLEMENTS, result_key.as_bytes())
            .map_err(|e| SettlementError::BatchError(format!("Storage read failed: {}", e)))?
        {
            Some(bytes) => {
                let result: BatchSettlementResult =
                    serde_json::from_slice(&bytes).map_err(|e| {
                        SettlementError::BatchError(format!(
                            "Failed to deserialize batch result: {}",
                            e
                        ))
                    })?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Gets the status of a batch
    pub fn get_batch_status(&self, batch_id: &str) -> Result<BatchStatus> {
        self.batches
            .get(batch_id)
            .map(|entry| entry.value().status)
            .ok_or_else(|| SettlementError::BatchError(format!("Batch {} not found", batch_id)))
    }

    /// Gets a batch by ID
    pub fn get_batch(&self, batch_id: &str) -> Result<SettlementBatch> {
        self.batches
            .get(batch_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| SettlementError::BatchError(format!("Batch {} not found", batch_id)))
    }

    /// Gets batch result by ID
    pub fn get_result(&self, batch_id: &str) -> Result<BatchSettlementResult> {
        self.results
            .get(batch_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| {
                SettlementError::BatchError(format!("Result for batch {} not found", batch_id))
            })
    }

    /// Rolls back a batch (marks it as rolled back)
    pub fn rollback_batch(&self, batch_id: &str) -> Result<()> {
        let mut batch_entry = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| SettlementError::BatchError(format!("Batch {} not found", batch_id)))?;

        let batch = batch_entry.value_mut();

        if batch.status == BatchStatus::Completed {
            return Err(SettlementError::BatchError(
                "Cannot rollback completed batch".to_string(),
            ));
        }

        if batch.status == BatchStatus::RolledBack {
            return Err(SettlementError::BatchError(
                "Batch already rolled back".to_string(),
            ));
        }

        batch.status = BatchStatus::RolledBack;
        batch.completed_at = Some(Timestamp::now());

        info!("Rolled back batch {}", batch_id);

        Ok(())
    }

    /// Returns batch processing statistics
    pub fn stats(&self) -> BatchStats {
        let total_batches = self.batches.len();
        let mut created = 0;
        let mut processing = 0;
        let mut completed = 0;
        let mut failed = 0;
        let mut rolled_back = 0;

        for entry in self.batches.iter() {
            match entry.value().status {
                BatchStatus::Created => created += 1,
                BatchStatus::Processing => processing += 1,
                BatchStatus::Completed => completed += 1,
                BatchStatus::Failed => failed += 1,
                BatchStatus::RolledBack => rolled_back += 1,
            }
        }

        BatchStats {
            total_batches,
            created,
            processing,
            completed,
            failed,
            rolled_back,
        }
    }

    /// Cleans up old batch records
    pub fn cleanup_old_batches(&self, older_than: Timestamp) {
        let to_remove: Vec<String> = self
            .batches
            .iter()
            .filter(|entry| {
                let batch = entry.value();
                batch.status == BatchStatus::Completed || batch.status == BatchStatus::Failed
            })
            .filter(|entry| entry.value().created_at < older_than)
            .map(|entry| entry.key().clone())
            .collect();

        for batch_id in &to_remove {
            self.batches.remove(batch_id);
            self.results.remove(batch_id);
        }

        if !to_remove.is_empty() {
            debug!("Cleaned up {} old batches", to_remove.len());
        }
    }
}

/// Batch processing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchStats {
    /// Total number of batches
    pub total_batches: usize,
    /// Number of created batches
    pub created: usize,
    /// Number of processing batches
    pub processing: usize,
    /// Number of completed batches
    pub completed: usize,
    /// Number of failed batches
    pub failed: usize,
    /// Number of rolled back batches
    pub rolled_back: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;
    use tenzro_types::principal_chain::anonymous_chain_for_address;
    use tenzro_types::settlement::{ProofType, ServiceProof, ServiceType};

    /// Test helper: synthesize an anonymous principal chain for a payer
    /// address. Used to satisfy the `SettlementReceipt::new` signature
    /// (Agent-Swarm Spec 5) in batch tests where identity wiring is not
    /// the unit under test.
    fn test_chain(payer: &Address) -> tenzro_types::principal_chain::PrincipalChain {
        anonymous_chain_for_address(payer, 0)
    }

    #[tokio::test]
    async fn test_batch_creation() {
        let processor = BatchProcessor::new(100);

        let settlements = vec![
            SettlementRequest::new(
                Address::new([1u8; 32]),
                Address::new([2u8; 32]),
                ServiceType::ModelInference {
                    model_id: "gpt-4".to_string(),
                    tokens: 1000,
                },
                1000,
                ServiceProof::new(ProofType::Cryptographic, vec![1, 2, 3]),
            ),
            SettlementRequest::new(
                Address::new([1u8; 32]),
                Address::new([3u8; 32]),
                ServiceType::ModelInference {
                    model_id: "gpt-4".to_string(),
                    tokens: 2000,
                },
                2000,
                ServiceProof::new(ProofType::Cryptographic, vec![4, 5, 6]),
            ),
        ];

        let batch = processor.create_batch(settlements).unwrap();
        assert_eq!(batch.size(), 2);
        assert_eq!(batch.status, BatchStatus::Created);
    }

    #[tokio::test]
    async fn test_empty_batch() {
        let processor = BatchProcessor::new(100);
        let result = processor.create_batch(vec![]);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_batch_size_limit() {
        let processor = BatchProcessor::new(2);

        let settlements = vec![
            SettlementRequest::new(
                Address::new([1u8; 32]),
                Address::new([2u8; 32]),
                ServiceType::ModelInference {
                    model_id: "gpt-4".to_string(),
                    tokens: 1000,
                },
                1000,
                ServiceProof::new(ProofType::Cryptographic, vec![1]),
            ),
            SettlementRequest::new(
                Address::new([1u8; 32]),
                Address::new([3u8; 32]),
                ServiceType::ModelInference {
                    model_id: "gpt-4".to_string(),
                    tokens: 2000,
                },
                2000,
                ServiceProof::new(ProofType::Cryptographic, vec![2]),
            ),
            SettlementRequest::new(
                Address::new([1u8; 32]),
                Address::new([4u8; 32]),
                ServiceType::ModelInference {
                    model_id: "gpt-4".to_string(),
                    tokens: 3000,
                },
                3000,
                ServiceProof::new(ProofType::Cryptographic, vec![3]),
            ),
        ];

        let result = processor.create_batch(settlements);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_batch_atomicity_rollback() {
        use tenzro_types::primitives::Hash;
        use tenzro_types::settlement::SettlementStatus;

        // Create shared balances
        let balances = Arc::new(DashMap::new());
        let provider = Address::new([1u8; 32]);
        let customer1 = Address::new([2u8; 32]);
        let customer2 = Address::new([3u8; 32]);
        let asset = AssetId::tnzo();

        // Set initial balance
        balances.insert((customer1, asset.clone()), 10000u128);

        let processor = BatchProcessor::with_balances(100, balances.clone());

        let settlements = vec![
            SettlementRequest::new(
                provider,
                customer1,
                ServiceType::ModelInference {
                    model_id: "gpt-4".to_string(),
                    tokens: 1000,
                },
                1000,
                ServiceProof::new(ProofType::Cryptographic, vec![1, 2, 3]),
            ),
            SettlementRequest::new(
                provider,
                customer2,
                ServiceType::ModelInference {
                    model_id: "gpt-4".to_string(),
                    tokens: 2000,
                },
                2000,
                ServiceProof::new(ProofType::Cryptographic, vec![4, 5, 6]),
            ),
        ];

        let batch = processor.create_batch(settlements).unwrap();

        // Process with a settle_fn where the second settlement fails
        let call_count = std::sync::atomic::AtomicU32::new(0);
        let result = processor
            .process_batch(&batch.batch_id, |req| {
                let current_call = call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                async move {
                    if current_call == 2 {
                        Err(SettlementError::InsufficientFunds {
                            required: 99999,
                            available: 0,
                        })
                    } else {
                        // First settlement succeeds
                        Ok(SettlementReceipt::new(
                            req.request_id.clone(),
                            Hash::new([0u8; 32]),
                            req.provider,
                            req.customer,
                            req.service_type.clone(),
                            req.amount,
                            SettlementStatus::Completed,
                            test_chain(&req.customer),
                        ))
                    }
                }
            })
            .await
            .unwrap();

        // Batch should have failed status
        assert_eq!(result.status, BatchStatus::Failed);
        assert_eq!(result.successful, 0); // All cleared on rollback
        assert_eq!(result.failed, 1);

        // Verify balances were rolled back to original state
        let customer_balance = balances
            .get(&(customer1, asset.clone()))
            .map(|e| *e.value())
            .unwrap_or(0);
        assert_eq!(
            customer_balance, 10000,
            "Customer balance should be restored to original 10000"
        );
    }

    #[tokio::test]
    async fn test_successful_batch_persists_to_storage() {
        use tenzro_types::primitives::Hash;
        use tenzro_types::settlement::SettlementStatus;

        let storage = Arc::new(MemoryStore::new());
        let processor = BatchProcessor::new(100).with_storage(storage.clone());

        let settlements = vec![
            SettlementRequest::new(
                Address::new([1u8; 32]),
                Address::new([2u8; 32]),
                ServiceType::ModelInference {
                    model_id: "gpt-4".to_string(),
                    tokens: 1000,
                },
                1000,
                ServiceProof::new(ProofType::Cryptographic, vec![1, 2, 3]),
            ),
            SettlementRequest::new(
                Address::new([1u8; 32]),
                Address::new([3u8; 32]),
                ServiceType::ModelInference {
                    model_id: "gpt-4".to_string(),
                    tokens: 2000,
                },
                2000,
                ServiceProof::new(ProofType::Cryptographic, vec![4, 5, 6]),
            ),
        ];

        let batch = processor.create_batch(settlements).unwrap();
        let batch_id = batch.batch_id.clone();

        // Process — all succeed
        let result = processor
            .process_batch(&batch_id, |req| async move {
                Ok(SettlementReceipt::new(
                    req.request_id.clone(),
                    Hash::new([0u8; 32]),
                    req.provider,
                    req.customer,
                    req.service_type.clone(),
                    req.amount,
                    SettlementStatus::Completed,
                    test_chain(&req.customer),
                ))
            })
            .await
            .unwrap();

        assert_eq!(result.status, BatchStatus::Completed);
        assert_eq!(result.successful, 2);

        // Verify batch metadata was written to storage
        let batch_key = format!("batch:{}", batch_id);
        let stored_batch_bytes = storage
            .get(CF_SETTLEMENTS, batch_key.as_bytes())
            .unwrap()
            .expect("batch metadata should be persisted");
        let stored_batch: SettlementBatch = serde_json::from_slice(&stored_batch_bytes).unwrap();
        assert_eq!(stored_batch.batch_id, batch_id);
        assert_eq!(stored_batch.status, BatchStatus::Completed);

        // Verify batch result was written to storage
        let loaded = processor.load_batch_result(&batch_id).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.successful, 2);
        assert_eq!(loaded.receipts.len(), 2);

        // Verify individual receipts
        let receipt_key_0 = format!("receipt:{}:0", batch_id);
        assert!(
            storage
                .get(CF_SETTLEMENTS, receipt_key_0.as_bytes())
                .unwrap()
                .is_some(),
            "receipt 0 should be persisted"
        );
        let receipt_key_1 = format!("receipt:{}:1", batch_id);
        assert!(
            storage
                .get(CF_SETTLEMENTS, receipt_key_1.as_bytes())
                .unwrap()
                .is_some(),
            "receipt 1 should be persisted"
        );
    }

    #[tokio::test]
    async fn test_failed_batch_does_not_persist_to_storage() {
        use tenzro_types::primitives::Hash;
        use tenzro_types::settlement::SettlementStatus;

        let storage = Arc::new(MemoryStore::new());
        let processor = BatchProcessor::new(100).with_storage(storage.clone());

        let settlements = vec![
            SettlementRequest::new(
                Address::new([1u8; 32]),
                Address::new([2u8; 32]),
                ServiceType::ModelInference {
                    model_id: "gpt-4".to_string(),
                    tokens: 1000,
                },
                1000,
                ServiceProof::new(ProofType::Cryptographic, vec![1, 2, 3]),
            ),
            SettlementRequest::new(
                Address::new([1u8; 32]),
                Address::new([3u8; 32]),
                ServiceType::ModelInference {
                    model_id: "gpt-4".to_string(),
                    tokens: 2000,
                },
                2000,
                ServiceProof::new(ProofType::Cryptographic, vec![4, 5, 6]),
            ),
        ];

        let batch = processor.create_batch(settlements).unwrap();
        let batch_id = batch.batch_id.clone();

        // Process — second settlement fails
        let call_count = std::sync::atomic::AtomicU32::new(0);
        let result = processor
            .process_batch(&batch_id, |req| {
                let current = call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                async move {
                    if current == 2 {
                        Err(SettlementError::InsufficientFunds {
                            required: 99999,
                            available: 0,
                        })
                    } else {
                        Ok(SettlementReceipt::new(
                            req.request_id.clone(),
                            Hash::new([0u8; 32]),
                            req.provider,
                            req.customer,
                            req.service_type.clone(),
                            req.amount,
                            SettlementStatus::Completed,
                            test_chain(&req.customer),
                        ))
                    }
                }
            })
            .await
            .unwrap();

        assert_eq!(result.status, BatchStatus::Failed);

        // Nothing should have been written to storage
        let batch_key = format!("batch:{}", batch_id);
        assert!(
            storage
                .get(CF_SETTLEMENTS, batch_key.as_bytes())
                .unwrap()
                .is_none(),
            "failed batch metadata must NOT be persisted"
        );

        let result_key = format!("batch_result:{}", batch_id);
        assert!(
            storage
                .get(CF_SETTLEMENTS, result_key.as_bytes())
                .unwrap()
                .is_none(),
            "failed batch result must NOT be persisted"
        );

        let receipt_key = format!("receipt:{}:0", batch_id);
        assert!(
            storage
                .get(CF_SETTLEMENTS, receipt_key.as_bytes())
                .unwrap()
                .is_none(),
            "failed batch receipts must NOT be persisted"
        );
    }

    #[tokio::test]
    async fn test_no_storage_still_works() {
        use tenzro_types::primitives::Hash;
        use tenzro_types::settlement::SettlementStatus;

        // No storage attached — should work exactly like before
        let processor = BatchProcessor::new(100);

        let settlements = vec![SettlementRequest::new(
            Address::new([1u8; 32]),
            Address::new([2u8; 32]),
            ServiceType::ModelInference {
                model_id: "gpt-4".to_string(),
                tokens: 500,
            },
            500,
            ServiceProof::new(ProofType::Cryptographic, vec![7, 8, 9]),
        )];

        let batch = processor.create_batch(settlements).unwrap();
        let batch_id = batch.batch_id.clone();

        let result = processor
            .process_batch(&batch_id, |req| async move {
                Ok(SettlementReceipt::new(
                    req.request_id.clone(),
                    Hash::new([0u8; 32]),
                    req.provider,
                    req.customer,
                    req.service_type.clone(),
                    req.amount,
                    SettlementStatus::Completed,
                    test_chain(&req.customer),
                ))
            })
            .await
            .unwrap();

        assert_eq!(result.status, BatchStatus::Completed);
        assert_eq!(result.successful, 1);

        // load_batch_result returns None when no storage
        let loaded = processor.load_batch_result(&batch_id).unwrap();
        assert!(loaded.is_none());

        // In-memory result still available
        let in_mem = processor.get_result(&batch_id).unwrap();
        assert_eq!(in_mem.successful, 1);
    }
}
