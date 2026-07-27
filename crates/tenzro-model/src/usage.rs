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
use tenzro_types::model::BillableUnits;
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

/// Lifetime totals of every billable dimension.
///
/// The per-call counters on [`BillableUnits`] are sized for one request; summed
/// over a provider's lifetime they would wrap. This is the widened mirror used
/// by the three aggregate tiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BillableTotals {
    /// Prompt tokens read
    pub input_tokens: u64,
    /// Completion tokens generated
    pub output_tokens: u64,
    /// Prompt tokens served from a warm prefix cache
    pub cached_read_tokens: u64,
    /// Prompt tokens written into a prefix cache
    pub cached_write_tokens: u64,
    /// Reasoning loops executed
    pub reasoning_loops: u64,
    /// Tokens derived from image geometry
    pub image_tokens: u64,
    /// Audio duration processed, in milliseconds
    pub audio_ms: u64,
    /// Video duration processed, in milliseconds
    pub video_ms: u64,
    /// Denoising work: width × height × steps × frames
    pub pixel_steps: u128,
    /// Frames produced or consumed
    pub frames: u64,
}

impl BillableTotals {
    /// Folds one call's units into the running totals.
    pub fn add(&mut self, units: &BillableUnits) {
        self.input_tokens = self.input_tokens.saturating_add(units.input_tokens as u64);
        self.output_tokens = self.output_tokens.saturating_add(units.output_tokens as u64);
        self.cached_read_tokens = self
            .cached_read_tokens
            .saturating_add(units.cached_read_tokens as u64);
        self.cached_write_tokens = self
            .cached_write_tokens
            .saturating_add(units.cached_write_tokens as u64);
        self.reasoning_loops = self
            .reasoning_loops
            .saturating_add(units.reasoning_loops as u64);
        self.image_tokens = self.image_tokens.saturating_add(units.image_tokens as u64);
        self.audio_ms = self.audio_ms.saturating_add(units.audio_ms);
        self.video_ms = self.video_ms.saturating_add(units.video_ms);
        self.pixel_steps = self.pixel_steps.saturating_add(units.pixel_steps);
        self.frames = self.frames.saturating_add(units.frames as u64);
    }

    /// Every token-denominated dimension summed: prompt, completion, both cache
    /// legs, and image tokens.
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens
            .saturating_add(self.output_tokens)
            .saturating_add(self.cached_read_tokens)
            .saturating_add(self.cached_write_tokens)
            .saturating_add(self.image_tokens)
    }
}

/// Individual usage record for a single inference request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    /// Lookup key for the record. Defaults to a timestamp-plus-UUID string;
    /// producers that mint a client-visible id for the generation pass it
    /// through [`UsageRecord::with_record_id`] instead, so a consumer holding
    /// only that id can read the record back.
    pub record_id: String,
    /// Model identifier
    pub model_id: String,
    /// Provider that served the inference
    pub provider_id: Address,
    /// Billable work the call consumed, across every modality. A chat call
    /// fills the token legs; a transcription fills `audio_ms`; an image
    /// generation fills `pixel_steps` and `frames`.
    pub units: BillableUnits,
    /// Bytes received from the consumer, for marketplace bandwidth accounting
    /// alongside token counts. Measured at whichever boundary the generation
    /// crossed: the HTTP request body for a routed inference, the prompt text
    /// for one served from local weights.
    pub bytes_in: u64,
    /// Bytes sent back to the consumer, measured at the same boundary as
    /// [`UsageRecord::bytes_in`].
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
        units: BillableUnits,
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
            units,
            bytes_in,
            bytes_out,
            cost,
            latency_ms,
            timestamp,
        }
    }

    /// Replaces the generated record id with a caller-supplied one.
    ///
    /// Callers that already mint a client-visible id for the generation — the
    /// `chatcmpl-…` completion id on the chat routes, the `request_id` on a
    /// routed inference — pass it here so a consumer holding only that id can
    /// read the recorded token counts and cost back through
    /// [`UsageTracker::get_record`]. Without it the record is keyed on a
    /// timestamp-plus-UUID string the consumer never sees.
    pub fn with_record_id(mut self, record_id: String) -> Self {
        self.record_id = record_id;
        self
    }

    /// Every token-denominated dimension summed
    pub fn total_tokens(&self) -> u32 {
        self.units.total_tokens()
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
    /// Lifetime totals of every billable dimension
    pub total_units: BillableTotals,
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

    /// Every token-denominated dimension summed
    pub fn total_tokens(&self) -> u64 {
        self.total_units.total_tokens()
    }

    /// Average latency in milliseconds
    pub fn avg_latency_ms(&self) -> u64 {
        self.total_latency_ms
            .checked_div(self.inference_count)
            .unwrap_or(0)
    }

    /// Average cost per inference
    pub fn avg_cost(&self) -> u64 {
        self.total_cost.checked_div(self.inference_count).unwrap_or(0)
    }

    /// Total bytes (in + out) at the HTTP boundary across all inferences
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes_in.saturating_add(self.total_bytes_out)
    }

    /// Updates stats with a new usage record
    fn update(&mut self, record: &UsageRecord) {
        self.inference_count = self.inference_count.saturating_add(1);
        self.total_units.add(&record.units);
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
    /// Lifetime totals of every billable dimension served
    pub total_units: BillableTotals,
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

    /// Every token-denominated dimension summed
    pub fn total_tokens(&self) -> u64 {
        self.total_units.total_tokens()
    }

    /// Average latency in milliseconds
    pub fn avg_latency_ms(&self) -> u64 {
        self.total_latency_ms
            .checked_div(self.inference_count)
            .unwrap_or(0)
    }

    /// Average revenue per inference
    pub fn avg_revenue(&self) -> u64 {
        self.total_revenue
            .checked_div(self.inference_count)
            .unwrap_or(0)
    }

    /// Total bytes (in + out) at the HTTP boundary across all inferences served
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes_in.saturating_add(self.total_bytes_out)
    }

    /// Realized output-token throughput in tokens/sec, measured over the
    /// wall-clock window between the first and last inference this provider
    /// served. This is the *measured* counterpart to the provider's
    /// self-declared `ProviderCapacity.requests_per_second`: consumers compare
    /// the two to judge whether a provider delivers what it advertises.
    ///
    /// Returns `None` when there is not yet enough history to measure — fewer
    /// than two inferences, or a zero-length window (all inferences in the same
    /// millisecond). A brand-new provider therefore reports "no measurement"
    /// rather than a misleading zero or infinity.
    pub fn measured_tokens_per_sec(&self) -> Option<f64> {
        let (first, last) = (self.first_inference?, self.last_inference?);
        if self.inference_count < 2 {
            return None;
        }
        let window_ms = last.as_millis().saturating_sub(first.as_millis());
        if window_ms <= 0 {
            return None;
        }
        Some(self.total_units.output_tokens as f64 * 1000.0 / window_ms as f64)
    }

    /// Updates stats with a new usage record
    fn update(&mut self, record: &UsageRecord) {
        self.inference_count = self.inference_count.saturating_add(1);
        self.total_units.add(&record.units);
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
    /// Lifetime totals of every billable dimension network-wide
    pub total_units: BillableTotals,
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
    /// Every token-denominated dimension summed
    pub fn total_tokens(&self) -> u64 {
        self.total_units.total_tokens()
    }

    /// Average latency in milliseconds
    pub fn avg_latency_ms(&self) -> u64 {
        self.total_latency_ms
            .checked_div(self.total_inference_count)
            .unwrap_or(0)
    }

    /// Average cost per inference
    pub fn avg_cost(&self) -> u64 {
        self.total_cost
            .checked_div(self.total_inference_count)
            .unwrap_or(0)
    }

    /// Total bytes (in + out) at the HTTP boundary network-wide
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes_in.saturating_add(self.total_bytes_out)
    }

    /// Updates global stats with a new usage record
    fn update(&mut self, record: &UsageRecord) {
        self.total_inference_count = self.total_inference_count.saturating_add(1);
        self.total_units.add(&record.units);
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
        // Shrinking below what the ring already holds (after hydration, or after
        // an earlier larger bound) drops the oldest records immediately rather
        // than waiting for enough new calls to evict them.
        let mut recent = self.recent_records.write();
        if recent.len() > max {
            let excess = recent.len() - max;
            recent.drain(0..excess);
        }
        drop(recent);
        self
    }

    /// Records a new usage event
    ///
    /// Updates all relevant statistics (per-model, per-provider, global) and persists
    /// to storage if configured.
    pub fn record_usage(&self, record: UsageRecord) -> Result<()> {
        debug!(
            "Recording usage: model={}, provider={}, units={:?}, bytes={}/{}, cost={}, latency={}ms",
            record.model_id,
            record.provider_id,
            record.units,
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

    /// Looks up a single usage record by its id.
    ///
    /// Consumers reconcile a generation after the response is already consumed
    /// — the streamed case, where token counts arrive in the terminal chunk and
    /// are easy to miss. The id is whatever the producer keyed the record on
    /// via [`UsageRecord::with_record_id`].
    ///
    /// Reads the in-memory ring first, then falls back to storage. The ring is
    /// bounded by `max_recent_records` and is refilled from storage on boot with
    /// the newest records, so the storage path is what serves a lookup for a
    /// record older than the ring holds.
    ///
    /// Returns `None` when no record exists for the id rather than a zeroed
    /// record, so a caller can distinguish "not measured" from "measured zero".
    pub fn get_record(&self, record_id: &str) -> Option<UsageRecord> {
        {
            let recent = self.recent_records.read();
            if let Some(found) = recent.iter().rev().find(|r| r.record_id == record_id) {
                return Some(found.clone());
            }
        }
        self.load_record(record_id)
    }

    /// Reads a usage record out of storage, inverting [`Self::persist_record`]:
    /// envelope at `model_usage:<record_id>` → DA pointer → payload → record.
    /// The recomputed SHA-256 is checked against the envelope commitment so a
    /// payload swapped underneath the pointer is refused rather than reported.
    fn load_record(&self, record_id: &str) -> Option<UsageRecord> {
        let storage = self.storage.as_ref()?;
        let key = [USAGE_RECORD_PREFIX, record_id.as_bytes()].concat();

        let value = match storage.get(CF_MODELS, &key) {
            Ok(Some(value)) => value,
            Ok(None) => return None,
            Err(e) => {
                warn!("Failed to read usage record {}: {}", record_id, e);
                return None;
            }
        };

        self.decode_record(record_id, &value)
    }

    /// Resolves one persisted receipt envelope back to its record: envelope →
    /// DA pointer → payload → commitment check → record.
    fn decode_record(&self, record_id: &str, value: &[u8]) -> Option<UsageRecord> {
        let envelope = match bincode::deserialize::<ReceiptEnvelope>(value) {
            Ok(envelope) => envelope,
            Err(e) => {
                warn!(
                    "Failed to deserialize inference receipt envelope for {}: {}",
                    record_id, e
                );
                return None;
            }
        };

        let pointer = match envelope.da_pointer.as_ref() {
            Some(pointer) => pointer,
            None => {
                warn!(
                    "Inference receipt {} carries no DA pointer; cannot resolve payload",
                    record_id
                );
                return None;
            }
        };

        let payload = match self.da_backend.fetch_sync(pointer) {
            Ok(payload) => payload,
            Err(e) => {
                warn!(
                    "Failed to fetch offloaded inference payload for {}: {}",
                    record_id, e
                );
                return None;
            }
        };

        if compute_commitment(&payload) != envelope.commitment {
            warn!(
                "Inference payload for {} does not match its receipt commitment",
                record_id
            );
            return None;
        }

        match bincode::deserialize::<UsageRecord>(&payload) {
            Ok(record) => Some(record),
            Err(e) => {
                warn!("Failed to deserialize usage record {}: {}", record_id, e);
                None
            }
        }
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

        self.load_recent_records(storage)?;

        Ok(())
    }

    /// Refills the recent-records ring from storage with the newest
    /// `max_recent_records` records.
    ///
    /// Record ids are not ordered — a caller-supplied `chatcmpl-…` id sorts
    /// nowhere near the timestamp-prefixed default — so ordering comes from the
    /// record's own timestamp. The working set is pruned once it reaches twice
    /// the ring size so a node with a long history does not hold every record in
    /// memory to fill a bounded ring.
    fn load_recent_records(&self, storage: &Arc<dyn KvStore>) -> Result<()> {
        if self.max_recent_records == 0 {
            return Ok(());
        }

        let keys = storage
            .get_keys_with_prefix(CF_MODELS, USAGE_RECORD_PREFIX)
            .map_err(|e| ModelError::StorageError(e.to_string()))?;

        let prune_at = self.max_recent_records.saturating_mul(2);
        let mut newest: Vec<UsageRecord> = Vec::new();

        for key in keys {
            let record_id = match std::str::from_utf8(&key[USAGE_RECORD_PREFIX.len()..]) {
                Ok(id) => id,
                Err(_) => continue,
            };
            let value = match storage.get(CF_MODELS, &key) {
                Ok(Some(value)) => value,
                Ok(None) => continue,
                Err(e) => {
                    warn!("Failed to read usage record {}: {}", record_id, e);
                    continue;
                }
            };
            if let Some(record) = self.decode_record(record_id, &value) {
                newest.push(record);
            }
            if newest.len() >= prune_at {
                newest.sort_by_key(|r| std::cmp::Reverse(r.timestamp.as_millis()));
                newest.truncate(self.max_recent_records);
            }
        }

        newest.sort_by_key(|r| std::cmp::Reverse(r.timestamp.as_millis()));
        newest.truncate(self.max_recent_records);
        // The ring is oldest-first; `get_recent_usage` reads the tail and reverses.
        newest.reverse();

        let loaded = newest.len();
        *self.recent_records.write() = newest;
        info!("Loaded {} recent usage records from storage", loaded);

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
            BillableUnits::tokens(100, 50),
            512,
            2048,
            1000,
            250,
        );

        assert_eq!(record.model_id, "gemma4-9b");
        assert_eq!(record.units.input_tokens, 100);
        assert_eq!(record.units.output_tokens, 50);
        assert_eq!(record.total_tokens(), 150);
        assert_eq!(record.bytes_in, 512);
        assert_eq!(record.bytes_out, 2048);
        assert_eq!(record.total_bytes(), 2560);
        assert_eq!(record.cost, 1000);
        assert_eq!(record.latency_ms, 250);
    }

    #[test]
    fn test_non_token_units_survive_the_receipt_round_trip() {
        let storage = Arc::new(MemoryStore::new());
        let tracker = UsageTracker::with_storage(storage.clone())
            .unwrap()
            .with_max_recent_records(0);

        let units = BillableUnits::default()
            .with_audio_ms(4_500)
            .with_video_ms(12_000)
            .with_pixel_steps(1_048_576, 24)
            .with_image_tokens(729)
            .with_reasoning_loops(3)
            .with_cache(2_000, 500);

        let record = UsageRecord::new(
            "sam3".to_string(),
            Address::zero(),
            units.clone(),
            0,
            0,
            9_000,
            600,
        )
        .with_record_id("media-1".to_string());
        tracker.record_usage(record).unwrap();

        let found = tracker.get_record("media-1").unwrap();
        assert_eq!(found.units, units);
        // Partial seconds round up: a 4.5s clip bills as 5s.
        assert_eq!(found.units.audio_seconds(), 5);
        assert_eq!(found.units.video_seconds(), 12);

        let stats = tracker.get_model_stats("sam3").unwrap();
        assert_eq!(stats.total_units.audio_ms, 4_500);
        assert_eq!(stats.total_units.video_ms, 12_000);
        assert_eq!(stats.total_units.pixel_steps, 1_048_576);
        assert_eq!(stats.total_units.frames, 24);
        assert_eq!(stats.total_units.reasoning_loops, 3);
        // Image tokens and both cache legs are token-denominated.
        assert_eq!(stats.total_tokens(), 729 + 2_000 + 500);
    }

    #[test]
    fn test_model_stats_update() {
        let mut stats = ModelUsageStats::new("test-model".to_string());

        let record1 = UsageRecord::new(
            "test-model".to_string(),
            Address::zero(),
            BillableUnits::tokens(100, 50),
            500,
            1500,
            1000,
            200,
        );
        stats.update(&record1);

        assert_eq!(stats.inference_count, 1);
        assert_eq!(stats.total_units.input_tokens, 100);
        assert_eq!(stats.total_units.output_tokens, 50);
        assert_eq!(stats.total_cost, 1000);
        assert_eq!(stats.total_bytes_in, 500);
        assert_eq!(stats.total_bytes_out, 1500);
        assert_eq!(stats.avg_latency_ms(), 200);

        let record2 = UsageRecord::new(
            "test-model".to_string(),
            Address::zero(),
            BillableUnits::tokens(200, 100),
            1000,
            3000,
            2000,
            300,
        );
        stats.update(&record2);

        assert_eq!(stats.inference_count, 2);
        assert_eq!(stats.total_units.input_tokens, 300);
        assert_eq!(stats.total_units.output_tokens, 150);
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
            BillableUnits::tokens(100, 50),
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
            BillableUnits::tokens(100, 50),
            512,
            2048,
            1000,
            200,
        );
        tracker.record_usage(record1).unwrap();

        let record2 = UsageRecord::new(
            "model-b".to_string(),
            Address::zero(),
            BillableUnits::tokens(200, 100),
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
            BillableUnits::tokens(100, 50),
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

        // The ring is refilled too, so the record is servable without a
        // storage read.
        let recent = tracker2.get_recent_usage(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].model_id, "model-a");
        assert_eq!(recent[0].units.input_tokens, 100);
    }

    #[test]
    fn test_recent_records_hydrate_newest_first() {
        let storage = Arc::new(MemoryStore::new());
        let tracker = UsageTracker::with_storage(storage.clone()).unwrap();

        // Timestamps are explicit so ordering is not at the mercy of clock
        // resolution — record ids sort nowhere near their timestamps.
        for i in 0..6u64 {
            let mut record = UsageRecord::new(
                format!("model-{}", i),
                Address::zero(),
                BillableUnits::tokens(100, 50),
                512,
                2048,
                1000,
                200,
            )
            .with_record_id(format!("call-{}", i));
            record.timestamp = Timestamp::new(1_000 + (i as i64) * 1_000);
            tracker.record_usage(record).unwrap();
        }

        let rehydrated = UsageTracker::with_storage(storage)
            .unwrap()
            .with_max_recent_records(3);

        // Newest first, and only the newest three of six.
        let recent = rehydrated.get_recent_usage(10);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].record_id, "call-5");
        assert_eq!(recent[1].record_id, "call-4");
        assert_eq!(recent[2].record_id, "call-3");
    }

    #[test]
    fn test_recent_records_limit() {
        let tracker = UsageTracker::new().with_max_recent_records(3);

        for i in 0..5 {
            let record = UsageRecord::new(
                format!("model-{}", i),
                Address::zero(),
                BillableUnits::tokens(100, 50),
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
            BillableUnits::tokens(100, 50),
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
            BillableUnits::tokens(100, 50),
            512,
            2048,
            1000,
            200,
        );
        tracker.record_usage(record1).unwrap();

        let record2 = UsageRecord::new(
            "model-b".to_string(),
            Address::zero(),
            BillableUnits::tokens(200, 100),
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
    fn test_get_record_by_caller_supplied_id() {
        let tracker = UsageTracker::new();

        let record = UsageRecord::new(
            "model-a".to_string(),
            Address::zero(),
            BillableUnits::tokens(100, 50),
            512,
            2048,
            1000,
            250,
        )
        .with_record_id("chatcmpl-abc".to_string());
        tracker.record_usage(record).unwrap();

        let found = tracker.get_record("chatcmpl-abc").unwrap();
        assert_eq!(found.model_id, "model-a");
        assert_eq!(found.units.input_tokens, 100);
        assert_eq!(found.units.output_tokens, 50);
        assert_eq!(found.cost, 1000);
        assert_eq!(found.latency_ms, 250);

        assert!(tracker.get_record("chatcmpl-missing").is_none());
    }

    #[test]
    fn test_get_record_falls_back_to_storage() {
        let storage = Arc::new(MemoryStore::new());
        // A zero-length ring forces every lookup down the storage path:
        // envelope → DA pointer → payload → record.
        let tracker = UsageTracker::with_storage(storage)
            .unwrap()
            .with_max_recent_records(0);

        let record = UsageRecord::new(
            "model-a".to_string(),
            Address::zero(),
            BillableUnits::tokens(200, 100),
            1024,
            4096,
            2000,
            300,
        )
        .with_record_id("chatcmpl-def".to_string());
        tracker.record_usage(record).unwrap();

        assert!(tracker.get_recent_usage(10).is_empty());

        let found = tracker.get_record("chatcmpl-def").unwrap();
        assert_eq!(found.record_id, "chatcmpl-def");
        assert_eq!(found.units.input_tokens, 200);
        assert_eq!(found.units.output_tokens, 100);
        assert_eq!(found.bytes_in, 1024);
        assert_eq!(found.bytes_out, 4096);
        assert_eq!(found.cost, 2000);
        assert_eq!(found.latency_ms, 300);
    }

    #[test]
    fn test_saturating_arithmetic() {
        let mut stats = ModelUsageStats::new("test".to_string());

        // Set to max values
        stats.inference_count = u64::MAX - 1;
        stats.total_units.input_tokens = u64::MAX - 100;
        stats.total_units.output_tokens = u64::MAX - 50;
        stats.total_units.pixel_steps = u128::MAX - 4;
        stats.total_cost = u64::MAX - 1000;
        stats.total_latency_ms = u64::MAX - 200;
        stats.total_bytes_in = u64::MAX - 512;
        stats.total_bytes_out = u64::MAX - 2048;

        let record = UsageRecord::new(
            "test".to_string(),
            Address::zero(),
            BillableUnits::tokens(100, 50).with_pixel_steps(64, 1),
            1024,
            4096,
            1000,
            200,
        );

        // Should saturate at the type maximum, not panic
        stats.update(&record);

        assert_eq!(stats.inference_count, u64::MAX);
        assert_eq!(stats.total_units.input_tokens, u64::MAX);
        assert_eq!(stats.total_units.output_tokens, u64::MAX);
        assert_eq!(stats.total_units.pixel_steps, u128::MAX);
        assert_eq!(stats.total_cost, u64::MAX);
        assert_eq!(stats.total_latency_ms, u64::MAX);
        assert_eq!(stats.total_bytes_in, u64::MAX);
        assert_eq!(stats.total_bytes_out, u64::MAX);
    }
}
