//! Model usage tracking module
//!
//! This module provides comprehensive tracking and statistics for model inference usage,
//! persisting data to RocksDB for durability across node restarts.

use crate::error::{ModelError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::kv::{KvStore, WriteOp, CF_MODELS};
use tenzro_storage::{
    compute_commitment, InlineFallbackBackend, ReceiptEnvelope, ReceiptKind, ReceiptStorageMode,
    ReceiptSummary,
};
use tenzro_types::primitives::{Address, Timestamp};
use tracing::{debug, info, warn};

/// DA namespace used when offloading inference receipts via the inline-fallback
/// backend. Stable string; if the operator wires in a real DA backend later the
/// namespace stays the same so receipts indexed by namespace remain comparable.
const INFERENCE_DA_NAMESPACE: &[u8] = b"tenzro/inference";

/// Prefix for usage records in storage
const USAGE_RECORD_PREFIX: &[u8] = b"model_usage:";

/// Prefix for aggregated stats in storage
const STATS_PREFIX: &[u8] = b"model_stats:";

/// Prefix for provider stats in storage
const PROVIDER_STATS_PREFIX: &[u8] = b"provider_stats:";

/// Global stats key in storage
const GLOBAL_STATS_KEY: &[u8] = b"global_stats";

/// Individual usage record for a single inference request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    /// Unique record ID (timestamp + counter for uniqueness)
    pub record_id: String,
    /// Model identifier
    pub model_id: String,
    /// Provider that served the inference
    pub provider_id: Address,
    /// Number of input tokens
    pub input_tokens: u32,
    /// Number of output tokens
    pub output_tokens: u32,
    /// Bytes received from the consumer (request body size at the HTTP boundary).
    /// Used for marketplace bandwidth accounting alongside token counts.
    pub bytes_in: u64,
    /// Bytes sent back to the consumer (response body size at the HTTP boundary).
    /// Used for marketplace bandwidth accounting alongside token counts.
    pub bytes_out: u64,
    /// Cost in smallest TNZO unit
    pub cost: u64,
    /// Latency in milliseconds
    pub latency_ms: u64,
    /// Timestamp of the inference
    pub timestamp: Timestamp,
}

impl UsageRecord {
    /// Creates a new usage record
    pub fn new(
        model_id: String,
        provider_id: Address,
        input_tokens: u32,
        output_tokens: u32,
        bytes_in: u64,
        bytes_out: u64,
        cost: u64,
        latency_ms: u64,
    ) -> Self {
        let timestamp = Timestamp::now();
        let record_id = format!("{}-{}", timestamp.as_millis(), uuid::Uuid::new_v4());

        Self {
            record_id,
            model_id,
            provider_id,
            input_tokens,
            output_tokens,
            bytes_in,
            bytes_out,
            cost,
            latency_ms,
            timestamp,
        }
    }

    /// Total tokens (input + output)
    pub fn total_tokens(&self) -> u32 {
        self.input_tokens.saturating_add(self.output_tokens)
    }

    /// Total bytes (in + out) at the HTTP boundary
    pub fn total_bytes(&self) -> u64 {
        self.bytes_in.saturating_add(self.bytes_out)
    }
}

/// Aggregated statistics for a specific model
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelUsageStats {
    /// Model identifier
    pub model_id: String,
    /// Total number of inference requests
    pub inference_count: u64,
    /// Total input tokens
    pub total_input_tokens: u64,
    /// Total output tokens
    pub total_output_tokens: u64,
    /// Total cost in smallest TNZO unit
    pub total_cost: u64,
    /// Sum of all latencies for calculating average
    pub total_latency_ms: u64,
    /// Total bytes received from consumers across all inferences
    pub total_bytes_in: u64,
    /// Total bytes sent back to consumers across all inferences
    pub total_bytes_out: u64,
    /// Timestamp of first inference
    pub first_inference: Option<Timestamp>,
    /// Timestamp of last inference
    pub last_inference: Option<Timestamp>,
}

impl ModelUsageStats {
    /// Creates a new model stats tracker
    pub fn new(model_id: String) -> Self {
        Self {
            model_id,
            ..Default::default()
        }
    }

    /// Total tokens (input + output)
    pub fn total_tokens(&self) -> u64 {
        self.total_input_tokens.saturating_add(self.total_output_tokens)
    }

    /// Average latency in milliseconds
    pub fn avg_latency_ms(&self) -> u64 {
        if self.inference_count == 0 {
            0
        } else {
            self.total_latency_ms / self.inference_count
        }
    }

    /// Average cost per inference
    pub fn avg_cost(&self) -> u64 {
        if self.inference_count == 0 {
            0
        } else {
            self.total_cost / self.inference_count
        }
    }

    /// Total bytes (in + out) at the HTTP boundary across all inferences
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes_in.saturating_add(self.total_bytes_out)
    }

    /// Updates stats with a new usage record
    fn update(&mut self, record: &UsageRecord) {
        self.inference_count = self.inference_count.saturating_add(1);
        self.total_input_tokens = self
            .total_input_tokens
            .saturating_add(record.input_tokens as u64);
        self.total_output_tokens = self
            .total_output_tokens
            .saturating_add(record.output_tokens as u64);
        self.total_cost = self.total_cost.saturating_add(record.cost);
        self.total_latency_ms = self.total_latency_ms.saturating_add(record.latency_ms);
        self.total_bytes_in = self.total_bytes_in.saturating_add(record.bytes_in);
        self.total_bytes_out = self.total_bytes_out.saturating_add(record.bytes_out);

        if self.first_inference.is_none() {
            self.first_inference = Some(record.timestamp);
        }
        self.last_inference = Some(record.timestamp);
    }
}

/// Aggregated statistics for a specific provider
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderUsageStats {
    /// Provider address
    pub provider_id: Address,
    /// Total number of inference requests served
    pub inference_count: u64,
    /// Total input tokens processed
    pub total_input_tokens: u64,
    /// Total output tokens generated
    pub total_output_tokens: u64,
    /// Total revenue earned in smallest TNZO unit
    pub total_revenue: u64,
    /// Sum of all latencies
    pub total_latency_ms: u64,
    /// Total bytes received from consumers across all inferences served
    pub total_bytes_in: u64,
    /// Total bytes sent back to consumers across all inferences served
    pub total_bytes_out: u64,
    /// Timestamp of first inference served
    pub first_inference: Option<Timestamp>,
    /// Timestamp of last inference served
    pub last_inference: Option<Timestamp>,
}

impl ProviderUsageStats {
    /// Creates a new provider stats tracker
    pub fn new(provider_id: Address) -> Self {
        Self {
            provider_id,
            ..Default::default()
        }
    }

    /// Total tokens (input + output)
    pub fn total_tokens(&self) -> u64 {
        self.total_input_tokens.saturating_add(self.total_output_tokens)
    }

    /// Average latency in milliseconds
    pub fn avg_latency_ms(&self) -> u64 {
        if self.inference_count == 0 {
            0
        } else {
            self.total_latency_ms / self.inference_count
        }
    }

    /// Average revenue per inference
    pub fn avg_revenue(&self) -> u64 {
        if self.inference_count == 0 {
            0
        } else {
            self.total_revenue / self.inference_count
        }
    }

    /// Total bytes (in + out) at the HTTP boundary across all inferences served
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes_in.saturating_add(self.total_bytes_out)
    }

    /// Updates stats with a new usage record
    fn update(&mut self, record: &UsageRecord) {
        self.inference_count = self.inference_count.saturating_add(1);
        self.total_input_tokens = self
            .total_input_tokens
            .saturating_add(record.input_tokens as u64);
        self.total_output_tokens = self
            .total_output_tokens
            .saturating_add(record.output_tokens as u64);
        self.total_revenue = self.total_revenue.saturating_add(record.cost);
        self.total_latency_ms = self.total_latency_ms.saturating_add(record.latency_ms);
        self.total_bytes_in = self.total_bytes_in.saturating_add(record.bytes_in);
        self.total_bytes_out = self.total_bytes_out.saturating_add(record.bytes_out);

        if self.first_inference.is_none() {
            self.first_inference = Some(record.timestamp);
        }
        self.last_inference = Some(record.timestamp);
    }
}

/// Global network-wide usage statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalUsageStats {
    /// Total number of inference requests across all models
    pub total_inference_count: u64,
    /// Total input tokens across all models
    pub total_input_tokens: u64,
    /// Total output tokens across all models
    pub total_output_tokens: u64,
    /// Total cost/revenue across all models
    pub total_cost: u64,
    /// Sum of all latencies across all requests
    pub total_latency_ms: u64,
    /// Total bytes received from consumers across the entire network
    pub total_bytes_in: u64,
    /// Total bytes sent back to consumers across the entire network
    pub total_bytes_out: u64,
    /// Number of unique models that have been used
    pub unique_models: u64,
    /// Number of unique providers that have served requests
    pub unique_providers: u64,
    /// Timestamp of first inference on the network
    pub first_inference: Option<Timestamp>,
    /// Timestamp of last inference on the network
    pub last_inference: Option<Timestamp>,
}

impl GlobalUsageStats {
    /// Total tokens (input + output)
    pub fn total_tokens(&self) -> u64 {
        self.total_input_tokens.saturating_add(self.total_output_tokens)
    }

    /// Average latency in milliseconds
    pub fn avg_latency_ms(&self) -> u64 {
        if self.total_inference_count == 0 {
            0
        } else {
            self.total_latency_ms / self.total_inference_count
        }
    }

    /// Average cost per inference
    pub fn avg_cost(&self) -> u64 {
        if self.total_inference_count == 0 {
            0
        } else {
            self.total_cost / self.total_inference_count
        }
    }

    /// Total bytes (in + out) at the HTTP boundary network-wide
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes_in.saturating_add(self.total_bytes_out)
    }

    /// Updates global stats with a new usage record
    fn update(&mut self, record: &UsageRecord) {
        self.total_inference_count = self.total_inference_count.saturating_add(1);
        self.total_input_tokens = self
            .total_input_tokens
            .saturating_add(record.input_tokens as u64);
        self.total_output_tokens = self
            .total_output_tokens
            .saturating_add(record.output_tokens as u64);
        self.total_cost = self.total_cost.saturating_add(record.cost);
        self.total_latency_ms = self.total_latency_ms.saturating_add(record.latency_ms);
        self.total_bytes_in = self.total_bytes_in.saturating_add(record.bytes_in);
        self.total_bytes_out = self.total_bytes_out.saturating_add(record.bytes_out);

        if self.first_inference.is_none() {
            self.first_inference = Some(record.timestamp);
        }
        self.last_inference = Some(record.timestamp);
    }
}

/// Usage tracker for model inference statistics
///
/// Tracks per-model, per-provider, and global usage statistics with RocksDB persistence.
/// All statistics are kept in-memory for fast access and periodically synced to disk.
///
/// Per-record persistence wraps each `UsageRecord` in a [`ReceiptEnvelope`]
/// with `kind = Inference` and `storage_mode = OffloadedDA`. The bincode
/// payload is submitted to the configured DA backend (currently always
/// [`InlineFallbackBackend`] until external DA layers land); only the envelope
/// (commitment + summary + DA pointer) is persisted under
/// `model_usage:<record_id>` in `CF_MODELS`. Aggregated stats remain plain
/// bincode — they are not receipts.
#[derive(Clone)]
pub struct UsageTracker {
    /// Per-model statistics cache
    model_stats: Arc<DashMap<String, ModelUsageStats>>,
    /// Per-provider statistics cache
    provider_stats: Arc<DashMap<Address, ProviderUsageStats>>,
    /// Global statistics
    global_stats: Arc<parking_lot::RwLock<GlobalUsageStats>>,
    /// Recent usage records (limited ring buffer)
    recent_records: Arc<parking_lot::RwLock<Vec<UsageRecord>>>,
    /// Maximum number of recent records to keep in memory
    max_recent_records: usize,
    /// Optional persistent storage backend
    storage: Option<Arc<dyn KvStore>>,
    /// DA backend used to offload inference-receipt payloads. Always present;
    /// defaults to a fresh in-process [`InlineFallbackBackend`] when no
    /// explicit backend is wired. When `with_storage()` is used, the backend
    /// shares that `KvStore` so offloaded payloads survive restarts.
    da_backend: Arc<InlineFallbackBackend>,
}

impl UsageTracker {
    /// Creates a new usage tracker without persistent storage
    pub fn new() -> Self {
        Self {
            model_stats: Arc::new(DashMap::new()),
            provider_stats: Arc::new(DashMap::new()),
            global_stats: Arc::new(parking_lot::RwLock::new(GlobalUsageStats::default())),
            recent_records: Arc::new(parking_lot::RwLock::new(Vec::new())),
            max_recent_records: 1000,
            storage: None,
            da_backend: Arc::new(InlineFallbackBackend::new()),
        }
    }

    /// Creates a new usage tracker with RocksDB persistence
    ///
    /// Loads existing stats from storage on initialization. The DA backend
    /// shares the same `KvStore` so offloaded inference payloads survive
    /// restarts via `CF_METADATA / da_fallback:<locator>`.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let da_backend = Arc::new(InlineFallbackBackend::new().with_storage(storage.clone()));
        let tracker = Self {
            model_stats: Arc::new(DashMap::new()),
            provider_stats: Arc::new(DashMap::new()),
            global_stats: Arc::new(parking_lot::RwLock::new(GlobalUsageStats::default())),
            recent_records: Arc::new(parking_lot::RwLock::new(Vec::new())),
            max_recent_records: 1000,
            storage: Some(storage.clone()),
            da_backend,
        };

        // Load existing stats from storage
        tracker.load_from_storage()?;

        Ok(tracker)
    }

    /// Access the DA backend used for inference-receipt offload. Exposed so
    /// hydration / fetch RPCs that need to dereference offloaded payloads can
    /// use the same in-process backend instance.
    pub fn da_backend(&self) -> Arc<InlineFallbackBackend> {
        self.da_backend.clone()
    }

    /// Sets the maximum number of recent records to keep in memory
    pub fn with_max_recent_records(mut self, max: usize) -> Self {
        self.max_recent_records = max;
        self
    }

    /// Records a new usage event
    ///
    /// Updates all relevant statistics (per-model, per-provider, global) and persists
    /// to storage if configured.
    pub fn record_usage(&self, record: UsageRecord) -> Result<()> {
        debug!(
            "Recording usage: model={}, provider={}, tokens={}/{}, bytes={}/{}, cost={}, latency={}ms",
            record.model_id,
            record.provider_id,
            record.input_tokens,
            record.output_tokens,
            record.bytes_in,
            record.bytes_out,
            record.cost,
            record.latency_ms
        );

        // Update per-model stats
        self.model_stats
            .entry(record.model_id.clone())
            .or_insert_with(|| ModelUsageStats::new(record.model_id.clone()))
            .update(&record);

        // Update per-provider stats
        self.provider_stats
            .entry(record.provider_id)
            .or_insert_with(|| ProviderUsageStats::new(record.provider_id))
            .update(&record);

        // Update global stats
        {
            let mut global = self.global_stats.write();
            global.update(&record);
            // Update unique counts
            global.unique_models = self.model_stats.len() as u64;
            global.unique_providers = self.provider_stats.len() as u64;
        }

        // Add to recent records
        {
            let mut recent = self.recent_records.write();
            recent.push(record.clone());
            // Trim if exceeds max
            if recent.len() > self.max_recent_records {
                let excess = recent.len() - self.max_recent_records;
                recent.drain(0..excess);
            }
        }

        // Persist to storage if available
        if let Some(ref storage) = self.storage {
            self.persist_record(&record, storage)?;
            self.persist_stats(storage)?;
        }

        info!(
            "Usage recorded: {} total inferences across {} models",
            self.global_stats.read().total_inference_count,
            self.model_stats.len()
        );

        Ok(())
    }

    /// Gets statistics for a specific model
    ///
    /// Returns None if the model has no usage history.
    pub fn get_model_stats(&self, model_id: &str) -> Option<ModelUsageStats> {
        self.model_stats.get(model_id).map(|entry| entry.clone())
    }

    /// Gets statistics for a specific provider
    ///
    /// Returns None if the provider has no usage history.
    pub fn get_provider_stats(&self, provider_id: &Address) -> Option<ProviderUsageStats> {
        self.provider_stats
            .get(provider_id)
            .map(|entry| entry.clone())
    }

    /// Gets global network-wide usage statistics
    pub fn get_global_stats(&self) -> GlobalUsageStats {
        self.global_stats.read().clone()
    }

    /// Gets the N most recent usage records
    ///
    /// Returns up to `limit` records, sorted by timestamp (newest first).
    pub fn get_recent_usage(&self, limit: usize) -> Vec<UsageRecord> {
        let recent = self.recent_records.read();
        let start = if recent.len() > limit {
            recent.len() - limit
        } else {
            0
        };
        recent[start..].iter().rev().cloned().collect()
    }

    /// Lists all models with usage statistics
    pub fn list_model_stats(&self) -> Vec<ModelUsageStats> {
        self.model_stats
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Lists all providers with usage statistics
    pub fn list_provider_stats(&self) -> Vec<ProviderUsageStats> {
        self.provider_stats
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Persists a usage record to storage as an offloaded inference receipt.
    ///
    /// The bincode-serialized `UsageRecord` is the canonical payload. It is
    /// submitted to the inference DA backend (currently always
    /// [`InlineFallbackBackend`]) which returns a [`tenzro_storage::DaPointer`].
    /// Only the [`ReceiptEnvelope`] (commitment + summary + pointer) is
    /// serialized to RocksDB under `model_usage:<record_id>` — the bulk
    /// payload lives in the DA backend (and, when the backend is wired with a
    /// `KvStore`, mirrored to `CF_METADATA / da_fallback:<locator>` for
    /// cross-restart durability).
    fn persist_record(&self, record: &UsageRecord, storage: &Arc<dyn KvStore>) -> Result<()> {
        let key = [USAGE_RECORD_PREFIX, record.record_id.as_bytes()].concat();

        let payload = bincode::serialize(record).map_err(|e| {
            ModelError::SerializationError(format!("Failed to serialize usage record: {}", e))
        })?;

        let summary = ReceiptSummary {
            // Hash the record_id string so the on-chain summary carries a
            // 32-byte digest (the rest of the protocol indexes receipts by
            // Hash, not by free-form string).
            receipt_id: compute_commitment(record.record_id.as_bytes()),
            payer: None,
            payee: Some(format!("{}", record.provider_id)),
            amount_wei: Some(record.cost as u128),
            timestamp: record.timestamp,
            principal_chain_summary: None,
        };

        let kind = ReceiptKind::Inference;
        debug_assert_eq!(kind.default_mode(), ReceiptStorageMode::OffloadedDA);

        let commitment = compute_commitment(&payload);
        let pointer = self.da_backend.submit_sync(INFERENCE_DA_NAMESPACE, &payload);
        let envelope = ReceiptEnvelope::offloaded(kind, summary, pointer, commitment);

        // Belt-and-suspenders: refuse to persist a malformed envelope.
        envelope.validate().map_err(|e| {
            ModelError::SerializationError(format!("Inference receipt envelope invalid: {}", e))
        })?;

        let value = bincode::serialize(&envelope).map_err(|e| {
            ModelError::SerializationError(format!(
                "Failed to serialize inference receipt envelope: {}",
                e
            ))
        })?;

        storage
            .put(CF_MODELS, &key, &value)
            .map_err(|e| ModelError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Persists all statistics to storage
    fn persist_stats(&self, storage: &Arc<dyn KvStore>) -> Result<()> {
        let mut ops = Vec::new();

        // Persist per-model stats
        for entry in self.model_stats.iter() {
            let key = [STATS_PREFIX, entry.key().as_bytes()].concat();
            let value = bincode::serialize(entry.value()).map_err(|e| {
                ModelError::SerializationError(format!("Failed to serialize model stats: {}", e))
            })?;
            ops.push(WriteOp::Put {
                cf: CF_MODELS.to_string(),
                key,
                value,
            });
        }

        // Persist per-provider stats
        for entry in self.provider_stats.iter() {
            let key = [PROVIDER_STATS_PREFIX, entry.key().as_bytes()].concat();
            let value = bincode::serialize(entry.value()).map_err(|e| {
                ModelError::SerializationError(format!("Failed to serialize provider stats: {}", e))
            })?;
            ops.push(WriteOp::Put {
                cf: CF_MODELS.to_string(),
                key,
                value,
            });
        }

        // Persist global stats
        {
            let global = self.global_stats.read();
            let value = bincode::serialize(&*global).map_err(|e| {
                ModelError::SerializationError(format!("Failed to serialize global stats: {}", e))
            })?;
            ops.push(WriteOp::Put {
                cf: CF_MODELS.to_string(),
                key: GLOBAL_STATS_KEY.to_vec(),
                value,
            });
        }

        // Write all stats in a single batch
        storage
            .write_batch(ops)
            .map_err(|e| ModelError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Loads statistics from storage
    fn load_from_storage(&self) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };

        // Load global stats
        if let Some(value) = storage
            .get(CF_MODELS, GLOBAL_STATS_KEY)
            .map_err(|e| ModelError::StorageError(e.to_string()))?
        {
            match bincode::deserialize::<GlobalUsageStats>(&value) {
                Ok(stats) => {
                    *self.global_stats.write() = stats;
                    info!("Loaded global usage stats from storage");
                }
                Err(e) => {
                    warn!("Failed to deserialize global stats: {}", e);
                }
            }
        }

        // Load per-model stats
        let model_keys = storage
            .get_keys_with_prefix(CF_MODELS, STATS_PREFIX)
            .map_err(|e| ModelError::StorageError(e.to_string()))?;

        for key in model_keys {
            if let Some(value) = storage
                .get(CF_MODELS, &key)
                .map_err(|e| ModelError::StorageError(e.to_string()))?
            {
                match bincode::deserialize::<ModelUsageStats>(&value) {
                    Ok(stats) => {
                        self.model_stats.insert(stats.model_id.clone(), stats);
                    }
                    Err(e) => {
                        warn!("Failed to deserialize model stats: {}", e);
                    }
                }
            }
        }

        info!("Loaded {} model stats from storage", self.model_stats.len());

        // Load per-provider stats
        let provider_keys = storage
            .get_keys_with_prefix(CF_MODELS, PROVIDER_STATS_PREFIX)
            .map_err(|e| ModelError::StorageError(e.to_string()))?;

        for key in provider_keys {
            if let Some(value) = storage
                .get(CF_MODELS, &key)
                .map_err(|e| ModelError::StorageError(e.to_string()))?
            {
                match bincode::deserialize::<ProviderUsageStats>(&value) {
                    Ok(stats) => {
                        self.provider_stats.insert(stats.provider_id, stats);
                    }
                    Err(e) => {
                        warn!("Failed to deserialize provider stats: {}", e);
                    }
                }
            }
        }

        info!(
            "Loaded {} provider stats from storage",
            self.provider_stats.len()
        );

        Ok(())
    }

    /// Clears all statistics (in-memory and storage)
    ///
    /// This is a destructive operation that removes all usage history.
    pub fn clear_all(&self) -> Result<()> {
        self.model_stats.clear();
        self.provider_stats.clear();
        *self.global_stats.write() = GlobalUsageStats::default();
        self.recent_records.write().clear();

        if let Some(ref storage) = self.storage {
            // Delete all records from storage
            let mut ops = Vec::new();

            // Delete usage records
            let record_keys = storage
                .get_keys_with_prefix(CF_MODELS, USAGE_RECORD_PREFIX)
                .map_err(|e| ModelError::StorageError(e.to_string()))?;
            for key in record_keys {
                ops.push(WriteOp::Delete {
                    cf: CF_MODELS.to_string(),
                    key,
                });
            }

            // Delete model stats
            let model_keys = storage
                .get_keys_with_prefix(CF_MODELS, STATS_PREFIX)
                .map_err(|e| ModelError::StorageError(e.to_string()))?;
            for key in model_keys {
                ops.push(WriteOp::Delete {
                    cf: CF_MODELS.to_string(),
                    key,
                });
            }

            // Delete provider stats
            let provider_keys = storage
                .get_keys_with_prefix(CF_MODELS, PROVIDER_STATS_PREFIX)
                .map_err(|e| ModelError::StorageError(e.to_string()))?;
            for key in provider_keys {
                ops.push(WriteOp::Delete {
                    cf: CF_MODELS.to_string(),
                    key,
                });
            }

            // Delete global stats
            ops.push(WriteOp::Delete {
                cf: CF_MODELS.to_string(),
                key: GLOBAL_STATS_KEY.to_vec(),
            });

            storage
                .write_batch(ops)
                .map_err(|e| ModelError::StorageError(e.to_string()))?;

            info!("Cleared all usage statistics from storage");
        }

        Ok(())
    }
}

impl Default for UsageTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::kv::MemoryStore;

    #[test]
    fn test_usage_record_creation() {
        let record = UsageRecord::new(
            "gemma4-9b".to_string(),
            Address::zero(),
            100,
            50,
            512,
            2048,
            1000,
            250,
        );

        assert_eq!(record.model_id, "gemma4-9b");
        assert_eq!(record.input_tokens, 100);
        assert_eq!(record.output_tokens, 50);
        assert_eq!(record.total_tokens(), 150);
        assert_eq!(record.bytes_in, 512);
        assert_eq!(record.bytes_out, 2048);
        assert_eq!(record.total_bytes(), 2560);
        assert_eq!(record.cost, 1000);
        assert_eq!(record.latency_ms, 250);
    }

    #[test]
    fn test_model_stats_update() {
        let mut stats = ModelUsageStats::new("test-model".to_string());

        let record1 = UsageRecord::new(
            "test-model".to_string(),
            Address::zero(),
            100,
            50,
            500,
            1500,
            1000,
            200,
        );
        stats.update(&record1);

        assert_eq!(stats.inference_count, 1);
        assert_eq!(stats.total_input_tokens, 100);
        assert_eq!(stats.total_output_tokens, 50);
        assert_eq!(stats.total_cost, 1000);
        assert_eq!(stats.total_bytes_in, 500);
        assert_eq!(stats.total_bytes_out, 1500);
        assert_eq!(stats.avg_latency_ms(), 200);

        let record2 = UsageRecord::new(
            "test-model".to_string(),
            Address::zero(),
            200,
            100,
            1000,
            3000,
            2000,
            300,
        );
        stats.update(&record2);

        assert_eq!(stats.inference_count, 2);
        assert_eq!(stats.total_input_tokens, 300);
        assert_eq!(stats.total_output_tokens, 150);
        assert_eq!(stats.total_cost, 3000);
        assert_eq!(stats.total_bytes_in, 1500);
        assert_eq!(stats.total_bytes_out, 4500);
        assert_eq!(stats.total_bytes(), 6000);
        assert_eq!(stats.avg_latency_ms(), 250);
        assert_eq!(stats.avg_cost(), 1500);
    }

    #[test]
    fn test_provider_stats_update() {
        let provider = Address::zero();
        let mut stats = ProviderUsageStats::new(provider);

        let record = UsageRecord::new(
            "test-model".to_string(),
            provider,
            100,
            50,
            512,
            2048,
            1000,
            200,
        );
        stats.update(&record);

        assert_eq!(stats.inference_count, 1);
        assert_eq!(stats.total_revenue, 1000);
        assert_eq!(stats.total_bytes_in, 512);
        assert_eq!(stats.total_bytes_out, 2048);
        assert_eq!(stats.total_bytes(), 2560);
        assert_eq!(stats.avg_revenue(), 1000);
    }

    #[test]
    fn test_usage_tracker_basic() {
        let tracker = UsageTracker::new();

        let record1 = UsageRecord::new(
            "model-a".to_string(),
            Address::zero(),
            100,
            50,
            512,
            2048,
            1000,
            200,
        );
        tracker.record_usage(record1).unwrap();

        let record2 = UsageRecord::new(
            "model-b".to_string(),
            Address::zero(),
            200,
            100,
            1024,
            4096,
            2000,
            300,
        );
        tracker.record_usage(record2).unwrap();

        // Check global stats
        let global = tracker.get_global_stats();
        assert_eq!(global.total_inference_count, 2);
        assert_eq!(global.unique_models, 2);
        assert_eq!(global.total_tokens(), 450);
        assert_eq!(global.total_bytes_in, 1536);
        assert_eq!(global.total_bytes_out, 6144);
        assert_eq!(global.total_bytes(), 7680);

        // Check model stats
        let model_a_stats = tracker.get_model_stats("model-a").unwrap();
        assert_eq!(model_a_stats.inference_count, 1);
        assert_eq!(model_a_stats.total_tokens(), 150);
        assert_eq!(model_a_stats.total_bytes(), 2560);

        // Check recent records
        let recent = tracker.get_recent_usage(10);
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn test_usage_tracker_with_storage() {
        let storage = Arc::new(MemoryStore::new());
        let tracker = UsageTracker::with_storage(storage.clone()).unwrap();

        let record = UsageRecord::new(
            "model-a".to_string(),
            Address::zero(),
            100,
            50,
            512,
            2048,
            1000,
            200,
        );
        tracker.record_usage(record).unwrap();

        // Create a new tracker with the same storage
        let tracker2 = UsageTracker::with_storage(storage).unwrap();

        // Should load stats from storage
        let global = tracker2.get_global_stats();
        assert_eq!(global.total_inference_count, 1);
        assert_eq!(global.total_bytes_in, 512);
        assert_eq!(global.total_bytes_out, 2048);

        let model_stats = tracker2.get_model_stats("model-a").unwrap();
        assert_eq!(model_stats.inference_count, 1);
        assert_eq!(model_stats.total_bytes_in, 512);
        assert_eq!(model_stats.total_bytes_out, 2048);
    }

    #[test]
    fn test_recent_records_limit() {
        let tracker = UsageTracker::new().with_max_recent_records(3);

        for i in 0..5 {
            let record = UsageRecord::new(
                format!("model-{}", i),
                Address::zero(),
                100,
                50,
                512,
                2048,
                1000,
                200,
            );
            tracker.record_usage(record).unwrap();
        }

        let recent = tracker.get_recent_usage(10);
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn test_clear_all() {
        let storage = Arc::new(MemoryStore::new());
        let tracker = UsageTracker::with_storage(storage).unwrap();

        let record = UsageRecord::new(
            "model-a".to_string(),
            Address::zero(),
            100,
            50,
            512,
            2048,
            1000,
            200,
        );
        tracker.record_usage(record).unwrap();

        assert_eq!(tracker.get_global_stats().total_inference_count, 1);

        tracker.clear_all().unwrap();

        assert_eq!(tracker.get_global_stats().total_inference_count, 0);
        assert!(tracker.get_model_stats("model-a").is_none());
    }

    #[test]
    fn test_list_model_stats() {
        let tracker = UsageTracker::new();

        let record1 = UsageRecord::new(
            "model-a".to_string(),
            Address::zero(),
            100,
            50,
            512,
            2048,
            1000,
            200,
        );
        tracker.record_usage(record1).unwrap();

        let record2 = UsageRecord::new(
            "model-b".to_string(),
            Address::zero(),
            200,
            100,
            1024,
            4096,
            2000,
            300,
        );
        tracker.record_usage(record2).unwrap();

        let all_stats = tracker.list_model_stats();
        assert_eq!(all_stats.len(), 2);
    }

    #[test]
    fn test_saturating_arithmetic() {
        let mut stats = ModelUsageStats::new("test".to_string());

        // Set to max values
        stats.inference_count = u64::MAX - 1;
        stats.total_input_tokens = u64::MAX - 100;
        stats.total_output_tokens = u64::MAX - 50;
        stats.total_cost = u64::MAX - 1000;
        stats.total_latency_ms = u64::MAX - 200;
        stats.total_bytes_in = u64::MAX - 512;
        stats.total_bytes_out = u64::MAX - 2048;

        let record = UsageRecord::new(
            "test".to_string(),
            Address::zero(),
            100,
            50,
            1024,
            4096,
            1000,
            200,
        );

        // Should saturate at u64::MAX, not panic
        stats.update(&record);

        assert_eq!(stats.inference_count, u64::MAX);
        assert_eq!(stats.total_input_tokens, u64::MAX);
        assert_eq!(stats.total_output_tokens, u64::MAX);
        assert_eq!(stats.total_cost, u64::MAX);
        assert_eq!(stats.total_latency_ms, u64::MAX);
        assert_eq!(stats.total_bytes_in, u64::MAX);
        assert_eq!(stats.total_bytes_out, u64::MAX);
    }
}
