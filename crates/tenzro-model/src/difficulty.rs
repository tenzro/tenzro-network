//! Per-query difficulty estimation for model routing.
//!
//! [`MetaRouter`](crate::meta_router::MetaRouter) selects a model from declared
//! metadata alone: parameter count, context window, capability tags. That says
//! nothing about whether a *specific* prompt needs the expensive model. This
//! module supplies the missing signal.
//!
//! Prompts are embedded (via [`PromptEmbedder`], backed in production by
//! [`TextEmbeddingRuntime`](crate::text_embedding_runtime::TextEmbeddingRuntime))
//! and grouped into clusters by an online sequential k-means map that grows on
//! demand — there is no training corpus and no offline fit step. Each model
//! accrues per-cluster outcome counters from real serving results, so a model's
//! strength becomes a measured property per prompt neighbourhood rather than a
//! declared property of the model.
//!
//! Because clusters are discovered rather than fixed, a newly registered model
//! needs no retraining to become routable: it starts at the neutral prior and
//! earns its per-cluster error rates from observations. Cold models keep an
//! optimism bonus so they stay explorable.
//!
//! Both the cluster map and the per-model counters write through to
//! `CF_MODELS` and hydrate on startup.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tenzro_storage::kv::{CF_MODELS, KvStore};
use tracing::{debug, info, warn};

use crate::error::{ModelError, Result};

/// Storage key holding the serialized cluster map.
const CLUSTER_MAP_KEY: &[u8] = b"difficulty:map";

/// Storage key prefix for per-model cluster counters.
const MODEL_STATS_PREFIX: &[u8] = b"difficulty:model:";

/// Default upper bound on the number of prompt clusters.
///
/// The map grows lazily up to this bound and then only updates existing
/// centroids, so the memory cost is `capacity * embedding_dim` floats.
pub const DEFAULT_CLUSTER_CAPACITY: usize = 32;

/// Cosine similarity below which an incoming prompt opens a new cluster
/// instead of joining the nearest existing one.
pub const DEFAULT_SPLIT_THRESHOLD: f32 = 0.80;

/// Weight on the uncertainty bonus subtracted from a model's expected error.
///
/// Higher values route more traffic to under-observed models.
const EXPLORATION_WEIGHT: f32 = 0.35;

/// Ceiling on the uncertainty bonus so an unobserved model can never look
/// better than a model with a measured zero error rate by more than this.
const MAX_EXPLORATION_BONUS: f32 = 0.40;

/// Embeds a routing prompt into a fixed-dimension vector.
///
/// Kept as a trait so `tenzro-model`'s routing path does not depend on which
/// encoder is loaded, and so tests can supply deterministic vectors.
#[async_trait]
pub trait PromptEmbedder: Send + Sync {
    /// Embeds a single prompt. The dimension must be stable across calls.
    async fn embed_prompt(&self, prompt: &str) -> Result<Vec<f32>>;
}

/// Result of serving a routed request, fed back into the difficulty index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteOutcome {
    /// The model answered and the caller accepted the answer.
    Resolved,
    /// The caller re-asked a stronger model — the routed model was too weak.
    Escalated,
    /// The request errored, timed out, or was rejected by the provider.
    Failed,
}

impl RouteOutcome {
    /// Parses a wire representation.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "resolved" | "ok" | "accepted" => Some(Self::Resolved),
            "escalated" | "retried" => Some(Self::Escalated),
            "failed" | "error" => Some(Self::Failed),
            _ => None,
        }
    }

    /// Canonical wire representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Escalated => "escalated",
            Self::Failed => "failed",
        }
    }

    /// Every variant, for error messages listing accepted values.
    pub const ALL: [&'static str; 3] = ["resolved", "escalated", "failed"];
}

/// Cosine similarity between two equal-length vectors. Returns `0.0` when
/// either vector has zero magnitude.
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na <= 0.0 || nb <= 0.0 {
        return 0.0;
    }
    dot / (na.sqrt() * nb.sqrt())
}

/// Self-organizing map of prompt clusters.
///
/// Assignment is nearest-centroid by cosine similarity. A prompt that matches
/// nothing closely enough opens a new cluster while capacity remains; once the
/// map is full every prompt joins its nearest cluster and nudges that centroid
/// toward itself by a running mean.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterMapState {
    /// Embedding dimension, locked in by the first observed prompt.
    pub dim: usize,
    /// Maximum number of clusters.
    pub capacity: usize,
    /// Similarity floor for joining an existing cluster.
    pub split_threshold: f32,
    /// Cluster centroids, indexed by cluster id.
    pub centroids: Vec<Vec<f32>>,
    /// Number of prompts assigned to each centroid.
    pub counts: Vec<u64>,
}

impl ClusterMapState {
    /// Creates an empty map with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            dim: 0,
            capacity: capacity.max(1),
            split_threshold: DEFAULT_SPLIT_THRESHOLD,
            centroids: Vec::new(),
            counts: Vec::new(),
        }
    }

    /// Number of clusters discovered so far.
    pub fn len(&self) -> usize {
        self.centroids.len()
    }

    /// Whether no cluster has been created yet.
    pub fn is_empty(&self) -> bool {
        self.centroids.is_empty()
    }

    /// Nearest cluster and its cosine similarity, without mutating the map.
    ///
    /// Returns `None` when the map is empty or the embedding dimension does
    /// not match the map.
    pub fn assign(&self, embedding: &[f32]) -> Option<(u32, f32)> {
        if self.centroids.is_empty() || embedding.len() != self.dim {
            return None;
        }
        let mut best = 0usize;
        let mut best_sim = f32::MIN;
        for (idx, centroid) in self.centroids.iter().enumerate() {
            let sim = cosine(embedding, centroid);
            if sim > best_sim {
                best_sim = sim;
                best = idx;
            }
        }
        Some((best as u32, best_sim))
    }

    /// Assigns an embedding, growing or updating the map.
    ///
    /// Returns the cluster id, or `None` when the embedding is empty or its
    /// dimension conflicts with the map's.
    pub fn observe(&mut self, embedding: &[f32]) -> Option<u32> {
        if embedding.is_empty() {
            return None;
        }
        if self.dim == 0 {
            self.dim = embedding.len();
        } else if embedding.len() != self.dim {
            return None;
        }

        match self.assign(embedding) {
            Some((idx, sim))
                if sim >= self.split_threshold || self.centroids.len() >= self.capacity =>
            {
                let i = idx as usize;
                let n = self.counts[i];
                let centroid = &mut self.centroids[i];
                let denom = (n + 1) as f32;
                for (c, x) in centroid.iter_mut().zip(embedding.iter()) {
                    *c += (x - *c) / denom;
                }
                self.counts[i] = n.saturating_add(1);
                Some(idx)
            }
            _ => {
                self.centroids.push(embedding.to_vec());
                self.counts.push(1);
                Some((self.centroids.len() - 1) as u32)
            }
        }
    }
}

/// Outcome counters for one model in one cluster.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ClusterOutcomeCounts {
    /// Requests the model answered acceptably.
    pub resolved: u64,
    /// Requests the caller escalated to a stronger model.
    pub escalated: u64,
    /// Requests that errored out.
    pub failed: u64,
}

impl ClusterOutcomeCounts {
    /// Total observations.
    pub fn total(&self) -> u64 {
        self.resolved
            .saturating_add(self.escalated)
            .saturating_add(self.failed)
    }

    /// Observations counted against the model.
    pub fn adverse(&self) -> u64 {
        self.escalated.saturating_add(self.failed)
    }

    /// Laplace-smoothed error rate — neutral `0.5` with no observations, so a
    /// model is neither punished nor favoured before it has served anything.
    pub fn error_rate(&self) -> f32 {
        (self.adverse() as f32 + 1.0) / (self.total() as f32 + 2.0)
    }

    fn record(&mut self, outcome: RouteOutcome) {
        match outcome {
            RouteOutcome::Resolved => self.resolved = self.resolved.saturating_add(1),
            RouteOutcome::Escalated => self.escalated = self.escalated.saturating_add(1),
            RouteOutcome::Failed => self.failed = self.failed.saturating_add(1),
        }
    }
}

/// Per-cluster outcome counters for a single model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelClusterStats {
    /// Catalog id of the model these counters describe.
    pub model_id: String,
    /// Counters keyed by cluster id.
    pub clusters: BTreeMap<u32, ClusterOutcomeCounts>,
}

impl ModelClusterStats {
    /// Creates empty stats for a model.
    pub fn new(model_id: impl Into<String>) -> Self {
        Self {
            model_id: model_id.into(),
            clusters: BTreeMap::new(),
        }
    }

    /// Counters for a cluster, if the model has served it.
    pub fn cluster(&self, cluster: u32) -> Option<&ClusterOutcomeCounts> {
        self.clusters.get(&cluster)
    }
}

/// Measured per-prompt difficulty signal consumed by the meta router.
pub struct DifficultyIndex {
    map: Arc<RwLock<ClusterMapState>>,
    models: Arc<DashMap<String, ModelClusterStats>>,
    storage: Option<Arc<dyn KvStore>>,
}

impl DifficultyIndex {
    /// Creates an in-memory index.
    pub fn new(capacity: usize) -> Self {
        Self {
            map: Arc::new(RwLock::new(ClusterMapState::new(capacity))),
            models: Arc::new(DashMap::new()),
            storage: None,
        }
    }

    /// Creates an index backed by `CF_MODELS`, hydrating any persisted state.
    pub fn with_storage(capacity: usize, storage: Arc<dyn KvStore>) -> Result<Self> {
        let index = Self {
            map: Arc::new(RwLock::new(ClusterMapState::new(capacity))),
            models: Arc::new(DashMap::new()),
            storage: Some(storage),
        };
        index.hydrate()?;
        Ok(index)
    }

    fn hydrate(&self) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };

        if let Some(bytes) = storage
            .get(CF_MODELS, CLUSTER_MAP_KEY)
            .map_err(|e| ModelError::StorageError(e.to_string()))?
        {
            match bincode::deserialize::<ClusterMapState>(&bytes) {
                Ok(state) => {
                    let clusters = state.len();
                    *self.map.write() = state;
                    info!("Hydrated prompt cluster map with {} clusters", clusters);
                }
                Err(e) => warn!("Failed to deserialize prompt cluster map: {}", e),
            }
        }

        let keys = storage
            .get_keys_with_prefix(CF_MODELS, MODEL_STATS_PREFIX)
            .map_err(|e| ModelError::StorageError(e.to_string()))?;
        for key in keys {
            if let Some(bytes) = storage
                .get(CF_MODELS, &key)
                .map_err(|e| ModelError::StorageError(e.to_string()))?
            {
                match bincode::deserialize::<ModelClusterStats>(&bytes) {
                    Ok(stats) => {
                        self.models.insert(stats.model_id.clone(), stats);
                    }
                    Err(e) => warn!("Failed to deserialize model cluster stats: {}", e),
                }
            }
        }
        info!(
            "Hydrated difficulty counters for {} models",
            self.models.len()
        );
        Ok(())
    }

    fn model_key(model_id: &str) -> Vec<u8> {
        let mut key = MODEL_STATS_PREFIX.to_vec();
        key.extend_from_slice(model_id.as_bytes());
        key
    }

    fn persist_map(&self, state: &ClusterMapState) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let bytes = bincode::serialize(state)
            .map_err(|e| ModelError::StorageError(format!("serialize cluster map: {}", e)))?;
        storage
            .put(CF_MODELS, CLUSTER_MAP_KEY, &bytes)
            .map_err(|e| ModelError::StorageError(e.to_string()))
    }

    fn persist_model(&self, stats: &ModelClusterStats) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let bytes = bincode::serialize(stats)
            .map_err(|e| ModelError::StorageError(format!("serialize model stats: {}", e)))?;
        storage
            .put(CF_MODELS, &Self::model_key(&stats.model_id), &bytes)
            .map_err(|e| ModelError::StorageError(e.to_string()))
    }

    /// Number of clusters discovered so far.
    pub fn cluster_count(&self) -> usize {
        self.map.read().len()
    }

    /// Snapshot of the cluster map, for diagnostics.
    pub fn map_snapshot(&self) -> ClusterMapState {
        self.map.read().clone()
    }

    /// Counters for a model, if it has served anything.
    pub fn model_stats(&self, model_id: &str) -> Option<ModelClusterStats> {
        self.models.get(model_id).map(|kv| kv.value().clone())
    }

    /// Nearest cluster for an embedding without mutating the map.
    pub fn assign(&self, embedding: &[f32]) -> Option<u32> {
        self.map.read().assign(embedding).map(|(idx, _)| idx)
    }

    /// Assigns an embedding, growing or updating the map, and persists it.
    ///
    /// Called on the routing path: every routed prompt refines the map.
    pub fn observe_prompt(&self, embedding: &[f32]) -> Option<u32> {
        let (cluster, snapshot) = {
            let mut map = self.map.write();
            let cluster = map.observe(embedding)?;
            (cluster, map.clone())
        };
        if let Err(e) = self.persist_map(&snapshot) {
            warn!("Failed to persist prompt cluster map: {}", e);
        }
        Some(cluster)
    }

    /// Total observations recorded across every model for one cluster.
    fn cluster_observations(&self, cluster: u32) -> u64 {
        self.models
            .iter()
            .filter_map(|kv| kv.value().cluster(cluster).map(|c| c.total()))
            .fold(0u64, |acc, n| acc.saturating_add(n))
    }

    /// Expected error rate for a model on a cluster, in `0.0..=1.0`.
    ///
    /// The Laplace-smoothed rate is reduced by an uncertainty bonus that
    /// shrinks as observations accumulate, so an untried model stays
    /// competitive against a well-measured one until it has evidence against
    /// it. With no observations anywhere the value is the neutral prior, which
    /// leaves the router's cost ordering in control.
    pub fn expected_error(&self, model_id: &str, cluster: u32) -> f32 {
        let counts = self
            .models
            .get(model_id)
            .and_then(|kv| kv.value().cluster(cluster).copied())
            .unwrap_or_default();
        let mean = counts.error_rate();
        let cluster_total = self.cluster_observations(cluster);
        if cluster_total == 0 {
            return mean;
        }
        let bonus = (EXPLORATION_WEIGHT
            * ((1.0 + cluster_total as f32).ln() / (1.0 + counts.total() as f32)).sqrt())
        .min(MAX_EXPLORATION_BONUS);
        (mean - bonus).clamp(0.0, 1.0)
    }

    /// Whether any model has recorded an outcome for a cluster.
    ///
    /// The router uses this to decide between measured scoring and the
    /// declared-metadata tier heuristic.
    pub fn has_observations(&self, cluster: u32) -> bool {
        self.cluster_observations(cluster) > 0
    }

    /// Records a serving outcome and persists the model's counters.
    pub fn record_outcome(
        &self,
        model_id: &str,
        cluster: u32,
        outcome: RouteOutcome,
    ) -> Result<()> {
        let stats = {
            let mut entry = self
                .models
                .entry(model_id.to_string())
                .or_insert_with(|| ModelClusterStats::new(model_id));
            entry.clusters.entry(cluster).or_default().record(outcome);
            entry.value().clone()
        };
        debug!(
            "Recorded {} for model={} cluster={}",
            outcome.as_str(),
            model_id,
            cluster
        );
        self.persist_model(&stats)
    }
}

impl std::fmt::Debug for DifficultyIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DifficultyIndex")
            .field("clusters", &self.cluster_count())
            .field("models", &self.models.len())
            .field("persistent", &self.storage.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::kv::MemoryStore;

    fn vec3(a: f32, b: f32, c: f32) -> Vec<f32> {
        vec![a, b, c]
    }

    #[test]
    fn first_prompt_opens_cluster_zero() {
        let index = DifficultyIndex::new(4);
        assert_eq!(index.cluster_count(), 0);
        assert_eq!(index.observe_prompt(&vec3(1.0, 0.0, 0.0)), Some(0));
        assert_eq!(index.cluster_count(), 1);
    }

    #[test]
    fn similar_prompts_share_a_cluster() {
        let index = DifficultyIndex::new(4);
        let a = index.observe_prompt(&vec3(1.0, 0.0, 0.0)).unwrap();
        let b = index.observe_prompt(&vec3(0.98, 0.05, 0.0)).unwrap();
        assert_eq!(a, b);
        assert_eq!(index.cluster_count(), 1);
    }

    #[test]
    fn dissimilar_prompt_opens_new_cluster() {
        let index = DifficultyIndex::new(4);
        let a = index.observe_prompt(&vec3(1.0, 0.0, 0.0)).unwrap();
        let b = index.observe_prompt(&vec3(0.0, 1.0, 0.0)).unwrap();
        assert_ne!(a, b);
        assert_eq!(index.cluster_count(), 2);
    }

    #[test]
    fn capacity_caps_cluster_growth() {
        let index = DifficultyIndex::new(2);
        index.observe_prompt(&vec3(1.0, 0.0, 0.0)).unwrap();
        index.observe_prompt(&vec3(0.0, 1.0, 0.0)).unwrap();
        // Third orthogonal prompt has nowhere to go, so it joins its nearest.
        index.observe_prompt(&vec3(0.0, 0.0, 1.0)).unwrap();
        assert_eq!(index.cluster_count(), 2);
    }

    #[test]
    fn dimension_mismatch_is_rejected() {
        let index = DifficultyIndex::new(4);
        index.observe_prompt(&vec3(1.0, 0.0, 0.0)).unwrap();
        assert_eq!(index.observe_prompt(&[1.0, 0.0]), None);
    }

    #[test]
    fn read_only_assign_does_not_grow_map() {
        let index = DifficultyIndex::new(4);
        index.observe_prompt(&vec3(1.0, 0.0, 0.0)).unwrap();
        assert_eq!(index.assign(&vec3(0.0, 1.0, 0.0)), Some(0));
        assert_eq!(index.cluster_count(), 1);
    }

    #[test]
    fn neutral_prior_without_observations() {
        let index = DifficultyIndex::new(4);
        assert!((index.expected_error("unknown", 0) - 0.5).abs() < 1e-6);
        assert!(!index.has_observations(0));
    }

    #[test]
    fn escalations_raise_expected_error_above_resolutions() {
        let index = DifficultyIndex::new(4);
        for _ in 0..20 {
            index
                .record_outcome("weak", 0, RouteOutcome::Escalated)
                .unwrap();
            index
                .record_outcome("strong", 0, RouteOutcome::Resolved)
                .unwrap();
        }
        assert!(index.has_observations(0));
        assert!(index.expected_error("weak", 0) > index.expected_error("strong", 0));
    }

    #[test]
    fn cold_model_keeps_optimism_bonus() {
        let index = DifficultyIndex::new(4);
        for _ in 0..50 {
            index
                .record_outcome("known", 0, RouteOutcome::Resolved)
                .unwrap();
        }
        // A model with no data on this cluster sits at the prior minus the
        // uncertainty bonus, so it stays reachable rather than being frozen out.
        let cold = index.expected_error("cold", 0);
        assert!(cold < 0.5, "cold model should get optimism, got {}", cold);
        assert!(cold >= 0.0);
    }

    #[test]
    fn outcomes_are_scoped_per_cluster() {
        let index = DifficultyIndex::new(4);
        for _ in 0..10 {
            index.record_outcome("m", 0, RouteOutcome::Failed).unwrap();
        }
        assert!(index.expected_error("m", 0) > index.expected_error("m", 1));
    }

    #[test]
    fn state_survives_rehydration() {
        let store: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        {
            let index = DifficultyIndex::with_storage(4, store.clone()).unwrap();
            index.observe_prompt(&vec3(1.0, 0.0, 0.0)).unwrap();
            index.observe_prompt(&vec3(0.0, 1.0, 0.0)).unwrap();
            for _ in 0..5 {
                index
                    .record_outcome("m", 1, RouteOutcome::Escalated)
                    .unwrap();
            }
        }
        let reloaded = DifficultyIndex::with_storage(4, store).unwrap();
        assert_eq!(reloaded.cluster_count(), 2);
        let stats = reloaded.model_stats("m").expect("stats hydrated");
        assert_eq!(stats.cluster(1).unwrap().escalated, 5);
        // Cluster assignment must be stable across the restart.
        assert_eq!(reloaded.assign(&vec3(0.0, 1.0, 0.0)), Some(1));
    }

    #[test]
    fn outcome_parses_aliases() {
        assert_eq!(RouteOutcome::parse("OK"), Some(RouteOutcome::Resolved));
        assert_eq!(
            RouteOutcome::parse("retried"),
            Some(RouteOutcome::Escalated)
        );
        assert_eq!(RouteOutcome::parse("error"), Some(RouteOutcome::Failed));
        assert_eq!(RouteOutcome::parse("maybe"), None);
        assert_eq!(RouteOutcome::Escalated.as_str(), "escalated");
    }
}
