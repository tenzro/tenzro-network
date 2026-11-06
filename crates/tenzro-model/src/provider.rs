//! Inference provider management module
//!
//! This module handles registration, tracking, and health monitoring of
//! inference providers on Tenzro Network.

use crate::error::{ModelError, Result};
use crate::latency::LatencyTail;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::kv::{CF_PROVIDERS, KvStore};
use tenzro_types::{
    model::{InferenceProvider, ProviderStatus},
    primitives::{Address, Timestamp},
};
use tracing::{debug, info, warn};

/// Storage key prefix for provider data
const PROVIDER_KEY_PREFIX: &[u8] = b"provider:";

/// Health status of a provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHealth {
    /// Whether the provider is healthy
    pub healthy: bool,
    /// Last health check timestamp
    pub last_check: Timestamp,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Number of consecutive failed health checks
    pub consecutive_failures: u32,
}

impl Default for ProviderHealth {
    fn default() -> Self {
        Self {
            healthy: true,
            last_check: Timestamp::now(),
            response_time_ms: 0,
            consecutive_failures: 0,
        }
    }
}

/// Metrics for tracking provider performance.
///
/// Call failures and stream failures are tracked together in
/// `failed_requests` for the success-rate calculation, but stream drops
/// are also counted separately in `consecutive_stream_failures` because
/// they are a much sharper trust signal than a single call rejection — a
/// dropped stream means the client lost in-flight tokens it already paid
/// for, while a failed call before any tokens left the wire is usually
/// recoverable by retrying a sibling provider. After
/// `STREAM_FAILURE_QUARANTINE_THRESHOLD` consecutive stream drops the
/// provider is auto-quarantined for `STREAM_FAILURE_QUARANTINE_MS` ms.
/// Any subsequent success resets the consecutive counter to zero.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderMetrics {
    /// Total number of inference requests received
    pub total_requests: u64,
    /// Number of successful requests
    pub successful_requests: u64,
    /// Number of failed requests (call + stream)
    pub failed_requests: u64,
    /// Number of failures that happened mid-stream (after first token)
    pub stream_failures: u64,
    /// Consecutive stream failures without an intervening success.
    /// Reset by `record_success`. Used to drive auto-quarantine.
    pub consecutive_stream_failures: u32,
    /// If `Some(t)` and `t > now`, the provider is auto-quarantined and
    /// will not be returned by `get_active_providers_for_model` until the
    /// timestamp passes. Cleared on `record_success`.
    pub quarantined_until: Option<Timestamp>,
    /// Average latency in milliseconds
    pub avg_latency_ms: u64,
    /// Running p95 latency estimate (P² streaming quantile). Hedging keys
    /// off this tail rather than the mean, so a backup request fires only
    /// when the primary has landed in its own slow tail — not on every
    /// request slower than average.
    #[serde(default)]
    pub latency_p95: LatencyTail,
    /// Uptime percentage (0-100)
    pub uptime_percentage: f64,
    /// Last heartbeat timestamp
    pub last_heartbeat: Option<Timestamp>,
    /// Total inference time in milliseconds
    pub total_latency_ms: u64,
    /// When the last decay pass was applied by
    /// `ProviderManager::decay_metrics`. Anchors decay to the time elapsed
    /// since the previous pass, so repeated routing calls decay
    /// proportionally instead of compounding.
    pub last_decay: Option<Timestamp>,
    /// Health status
    pub health: ProviderHealth,
}

/// Consecutive stream drops that trigger an auto-quarantine.
pub const STREAM_FAILURE_QUARANTINE_THRESHOLD: u32 = 3;
/// Duration of an auto-quarantine, in milliseconds (5 minutes).
pub const STREAM_FAILURE_QUARANTINE_MS: i64 = 5 * 60 * 1000;

impl ProviderMetrics {
    /// Creates new provider metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a successful inference request.
    ///
    /// Also resets the consecutive-stream-failure counter and clears any
    /// active quarantine — a single success means the provider is
    /// reachable and producing tokens again.
    pub fn record_success(&mut self, latency_ms: u64) {
        self.total_requests += 1;
        self.successful_requests += 1;
        self.total_latency_ms += latency_ms;
        self.consecutive_stream_failures = 0;
        self.quarantined_until = None;
        self.latency_p95.observe(latency_ms);
        self.update_avg_latency();
    }

    /// Records a failed inference request (call-time, before any tokens
    /// were emitted). Bumps the failed-requests counter only — does not
    /// touch the consecutive-stream-failure counter, since a pre-stream
    /// failure is a softer signal than a mid-stream drop.
    pub fn record_call_failure(&mut self) {
        self.total_requests += 1;
        self.failed_requests += 1;
    }

    /// Records a mid-stream failure (transport drop after at least one
    /// token was emitted, or upstream stream error). Bumps the
    /// consecutive-stream-failure counter; if it reaches
    /// `STREAM_FAILURE_QUARANTINE_THRESHOLD`, sets `quarantined_until`
    /// to `now + STREAM_FAILURE_QUARANTINE_MS`.
    pub fn record_stream_failure(&mut self) {
        self.total_requests += 1;
        self.failed_requests += 1;
        self.stream_failures += 1;
        self.consecutive_stream_failures = self.consecutive_stream_failures.saturating_add(1);
        if self.consecutive_stream_failures >= STREAM_FAILURE_QUARANTINE_THRESHOLD {
            let now = Timestamp::now();
            self.quarantined_until = Some(Timestamp::new(
                now.as_millis() + STREAM_FAILURE_QUARANTINE_MS,
            ));
        }
    }

    /// Returns true if the provider is currently auto-quarantined.
    pub fn is_quarantined(&self) -> bool {
        match self.quarantined_until {
            Some(until) => Timestamp::now().as_millis() < until.as_millis(),
            None => false,
        }
    }

    /// Updates average latency
    fn update_avg_latency(&mut self) {
        self.avg_latency_ms = self
            .total_latency_ms
            .checked_div(self.successful_requests)
            .unwrap_or(self.avg_latency_ms);
    }

    /// Current p95 latency estimate in milliseconds, or `None` before the
    /// estimator has warmed up (fewer than five successful requests).
    pub fn latency_p95_ms(&self) -> Option<u64> {
        self.latency_p95.estimate_ms()
    }

    /// Calculates success rate (0.0 - 1.0)
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.successful_requests as f64 / self.total_requests as f64
        }
    }

    /// Updates heartbeat timestamp
    pub fn heartbeat(&mut self) {
        self.last_heartbeat = Some(Timestamp::now());
    }

    /// Checks if provider is healthy (recent heartbeat)
    pub fn is_healthy(&self, max_heartbeat_age_ms: i64) -> bool {
        if let Some(last_heartbeat) = self.last_heartbeat {
            let now = Timestamp::now();
            let age_ms = now.as_millis() - last_heartbeat.as_millis();
            age_ms < max_heartbeat_age_ms
        } else {
            false
        }
    }
}

/// Provider with associated metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderWithMetrics {
    /// The provider information
    pub provider: InferenceProvider,
    /// Performance metrics
    pub metrics: ProviderMetrics,
    /// Whether provider has TEE capabilities
    pub has_tee: bool,
}

impl ProviderWithMetrics {
    /// Creates a new provider with metrics
    pub fn new(provider: InferenceProvider, has_tee: bool) -> Self {
        Self {
            provider,
            metrics: ProviderMetrics::new(),
            has_tee,
        }
    }

    /// Normalized observed-performance factor in `[0.0, 1.0]` combining
    /// success rate and measured latency. This is the gate applied to any
    /// advertised capability: a provider that claims high-tier hardware
    /// but returns errors or serves slowly has this factor drop, which
    /// discounts its advertised bias back toward zero. A provider with no
    /// history yet (no completed requests) returns `0.5` — neutral, so it
    /// is neither trusted nor distrusted until it has served traffic.
    ///
    /// This is the "gate on observed" half of the trust-advertised /
    /// gate-on-observed model: advertised class biases initial routing,
    /// observed behavior corrects it. The correction mirrors the resource-
    /// matching-then-measured-throughput loop used by volunteer-compute
    /// schedulers (BOINC) and decentralized-inference dispatchers (Petals
    /// per-device block assignment),
    /// where a device's declared capacity seeds assignment and its
    /// realized service rate continuously reweights it.
    pub fn observed_factor(&self) -> f64 {
        if self.metrics.total_requests == 0 {
            return 0.5;
        }
        let success = self.metrics.success_rate();
        let latency = if self.metrics.avg_latency_ms == 0 {
            0.5
        } else {
            (1000.0 / self.metrics.avg_latency_ms as f64).min(1.0)
        };
        // Weight success more heavily than latency: a provider that fails
        // is useless regardless of how fast it fails.
        (success * 0.7) + (latency * 0.3)
    }

    /// Calculates a score for provider ranking (0.0 - 100.0)
    pub fn calculate_score(&self) -> f64 {
        let success_weight = 35.0;
        let latency_weight = 25.0;
        let uptime_weight = 20.0;
        let reputation_weight = 10.0;
        let hardware_weight = 10.0;

        // Success rate component
        let success_score = self.metrics.success_rate() * success_weight;

        // Latency component - lower is better.
        // Assume 1000ms is baseline, 100ms is excellent
        let latency_score = if self.metrics.avg_latency_ms == 0 {
            0.0
        } else {
            let normalized = 1000.0 / self.metrics.avg_latency_ms as f64;
            normalized.min(1.0) * latency_weight
        };

        // Uptime component
        let uptime_score = (self.metrics.uptime_percentage / 100.0) * uptime_weight;

        // Reputation component: the consensus score, `0..=10_000`.
        let reputation_score =
            (self.provider.reputation as f64 / 10_000.0).min(1.0) * reputation_weight;

        // Advertised-hardware component, gated on observed performance. The
        // provider's declared hardware class sets the ceiling; the observed
        // factor scales it down toward zero when realized behavior diverges
        // from what the class implies. An overclaiming provider cannot hold
        // hardware points it hasn't earned in measured service.
        let hardware_score = self.provider.capacity.hardware.class().advertised_weight()
            * self.observed_factor()
            * hardware_weight;

        success_score + latency_score + uptime_score + reputation_score + hardware_score
    }
}

/// Copy the advertised fields from a gossip announcement onto a provider's
/// full capacity: the numeric throughput envelope plus the MoE expert-shard
/// declarations ([`MoeShardView`](crate::moe_shard::MoeShardView) is built
/// from these). Heavier locally-derived fields (LAN cluster, drafter
/// footprint, hardware) stay untouched.
fn apply_advertised_capacity(
    capacity: &mut tenzro_types::ProviderCapacity,
    advertised: &tenzro_types::AdvertisedCapacity,
) {
    capacity.max_concurrent_requests = advertised.max_concurrent_requests;
    capacity.active_requests = advertised.active_requests;
    capacity.requests_per_second = advertised.requests_per_second;
    capacity.max_batch_size = advertised.max_batch_size;
    capacity.mtp_enabled = advertised.mtp_enabled;
    capacity.verifiable_inference = advertised.verifiable_inference;
    capacity.moe_holdings = advertised.moe_holdings.clone();
    capacity.moe_roles = advertised.moe_roles.clone();
    capacity.moe_gpu = advertised.moe_gpu;
    capacity.prefix_cache = advertised.prefix_cache.clone();
    capacity.jurisdiction = advertised.jurisdiction.clone();
    capacity.verification = advertised.verification.clone();
}

/// Manager for inference providers
#[derive(Clone)]
pub struct ProviderManager {
    /// Map of provider address to provider with metrics
    providers: Arc<DashMap<Address, ProviderWithMetrics>>,
    /// Maximum heartbeat age in milliseconds before provider is considered unhealthy
    max_heartbeat_age_ms: i64,
    /// Optional persistent storage backend
    storage: Option<Arc<dyn KvStore>>,
    /// Heartbeat and anomaly liveness of the providers, shared with the
    /// gossip handler that feeds it and the router that consults it.
    liveness: Arc<crate::provider_liveness::ProviderLiveness>,
}

impl std::fmt::Debug for ProviderManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderManager")
            .field("providers", &self.providers.len())
            .field("max_heartbeat_age_ms", &self.max_heartbeat_age_ms)
            .field("storage", &self.storage.is_some())
            .finish()
    }
}

impl ProviderManager {
    /// Creates a new provider manager
    pub fn new() -> Self {
        Self {
            providers: Arc::new(DashMap::new()),
            max_heartbeat_age_ms: 300_000, // 5 minutes default
            storage: None,
            liveness: Arc::default(),
        }
    }

    /// Heartbeat and anomaly liveness of the providers.
    pub fn liveness(&self) -> &Arc<crate::provider_liveness::ProviderLiveness> {
        &self.liveness
    }

    /// Creates a new provider manager with persistent storage.
    ///
    /// Hydrates provider data from the storage backend on construction.
    /// Subsequent registrations and metric updates are written through to storage.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let providers = Arc::new(DashMap::new());

        // Hydrate from storage: scan CF_PROVIDERS for all provider entries
        if let Ok(Some(index_data)) = storage.get(CF_PROVIDERS, b"__index__")
            && let Ok(keys) = serde_json::from_slice::<Vec<String>>(&index_data)
        {
            for key_hex in &keys {
                let storage_key = [PROVIDER_KEY_PREFIX, key_hex.as_bytes()].concat();
                if let Ok(Some(data)) = storage.get(CF_PROVIDERS, &storage_key) {
                    match serde_json::from_slice::<ProviderWithMetrics>(&data) {
                        Ok(pwm) => {
                            info!("Hydrated provider {} from storage", pwm.provider.address);
                            providers.insert(pwm.provider.address, pwm);
                        }
                        Err(e) => {
                            warn!("Failed to deserialize provider {}: {}", key_hex, e);
                        }
                    }
                }
            }
            info!("Hydrated {} providers from storage", providers.len());
        }

        Self {
            providers,
            max_heartbeat_age_ms: 300_000,
            storage: Some(storage),
            liveness: Arc::default(),
        }
    }

    /// Creates a new provider manager with custom heartbeat timeout
    pub fn with_heartbeat_timeout(max_heartbeat_age_ms: i64) -> Self {
        Self {
            providers: Arc::new(DashMap::new()),
            max_heartbeat_age_ms,
            storage: None,
            liveness: Arc::default(),
        }
    }

    /// Persists a single provider to storage (if configured).
    fn persist_provider(&self, address: &Address, pwm: &ProviderWithMetrics) {
        if let Some(ref storage) = self.storage {
            let key_hex = format!("{}", address);
            let storage_key = [PROVIDER_KEY_PREFIX, key_hex.as_bytes()].concat();
            match serde_json::to_vec(pwm) {
                Ok(data) => {
                    if let Err(e) = storage.put(CF_PROVIDERS, &storage_key, &data) {
                        warn!("Failed to persist provider {}: {}", address, e);
                    }
                }
                Err(e) => {
                    warn!("Failed to serialize provider {}: {}", address, e);
                }
            }
        }
    }

    /// Deletes a single provider's persisted record (if storage configured).
    fn delete_persisted_provider(&self, address: &Address) {
        if let Some(ref storage) = self.storage {
            let key_hex = format!("{}", address);
            let storage_key = [PROVIDER_KEY_PREFIX, key_hex.as_bytes()].concat();
            if let Err(e) = storage.delete(CF_PROVIDERS, &storage_key) {
                warn!("Failed to delete persisted provider {}: {}", address, e);
            }
        }
    }

    /// Updates the provider index in storage (list of all provider key hexes).
    fn persist_index(&self) {
        if let Some(ref storage) = self.storage {
            let keys: Vec<String> = self
                .providers
                .iter()
                .map(|e| format!("{}", e.key()))
                .collect();
            match serde_json::to_vec(&keys) {
                Ok(data) => {
                    if let Err(e) = storage.put(CF_PROVIDERS, b"__index__", &data) {
                        warn!("Failed to persist provider index: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Failed to serialize provider index: {}", e);
                }
            }
        }
    }

    /// Registers a new inference provider with access control.
    ///
    /// Requires a registration signature proving the registrant controls the
    /// provider address. The `registration_sig` must be a valid Ed25519 or
    /// Secp256k1 signature over the provider address bytes.
    ///
    /// # Arguments
    ///
    /// * `provider` - The provider to register
    /// * `has_tee` - Whether the provider has TEE hardware
    /// * `registration_sig` - Signature over provider address bytes, proving ownership
    /// * `public_key` - Public key corresponding to the provider address
    ///
    /// # Errors
    ///
    /// Returns error if provider already exists or signature is invalid.
    pub fn register_provider(&self, provider: InferenceProvider, has_tee: bool) -> Result<()> {
        self.register_provider_authenticated(provider, has_tee, None, None)
    }

    /// Registers a provider with signature-based access control.
    ///
    /// If `registration_sig` and `public_key` are provided, verifies that the
    /// registrant controls the provider address before allowing registration.
    pub fn register_provider_authenticated(
        &self,
        provider: InferenceProvider,
        has_tee: bool,
        registration_sig: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<()> {
        let address = provider.address;

        // Verify registration signature if provided
        if let (Some(sig), Some(pk)) = (registration_sig, public_key) {
            let message = address.as_bytes();
            let public_key = tenzro_crypto::keys::PublicKey::new(
                tenzro_crypto::keys::KeyType::Ed25519,
                pk.to_vec(),
            );
            let signature = tenzro_crypto::signatures::Signature::new(
                tenzro_crypto::keys::KeyType::Ed25519,
                sig.to_vec(),
            );
            if tenzro_crypto::signatures::verify(&public_key, message, &signature).is_err() {
                return Err(ModelError::InvalidModel(format!(
                    "Invalid registration signature for provider {}",
                    address
                )));
            }
            debug!("Provider {} registration signature verified", address);
        }

        if self.providers.contains_key(&address) {
            return Err(ModelError::ModelAlreadyExists(format!(
                "Provider {} already registered",
                address
            )));
        }

        let provider_with_metrics = ProviderWithMetrics::new(provider, has_tee);
        self.persist_provider(&address, &provider_with_metrics);
        self.providers.insert(address, provider_with_metrics);
        self.persist_index();

        info!("Registered new provider: {}", address);
        Ok(())
    }

    /// Retrieves a provider by address
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ProviderNotFound` if provider doesn't exist.
    pub fn get_provider(&self, address: &Address) -> Result<InferenceProvider> {
        self.providers
            .get(address)
            .map(|entry| entry.value().provider.clone())
            .ok_or_else(|| ModelError::ProviderNotFound(address.to_string()))
    }

    /// Updates an existing provider
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ProviderNotFound` if provider doesn't exist.
    pub fn update_provider(&self, provider: InferenceProvider) -> Result<()> {
        let address = provider.address;

        if let Some(mut entry) = self.providers.get_mut(&address) {
            entry.provider = provider;
            let pwm = entry.clone();
            drop(entry); // Release DashMap guard before persistence
            self.persist_provider(&address, &pwm);
            debug!("Updated provider: {}", address);
            Ok(())
        } else {
            Err(ModelError::ProviderNotFound(address.to_string()))
        }
    }

    /// Idempotently installs or refreshes a provider discovered off the
    /// `tenzro/providers` gossip topic.
    ///
    /// Gossip announcements are the real membership signal on the network —
    /// every serving node broadcasts its `served_models`, iroh endpoint id, and
    /// detected `HardwareCapabilities` on a TTL. This is the bridge that lets
    /// those announcements reach the [`crate::InferenceRouter`] scoring path:
    /// the router scores over `ProviderManager` entries, so a provider that
    /// only lives in the node's gossip cache is invisible to routing until it
    /// is upserted here.
    ///
    /// The `capacity.hardware` field is set from the announcement so the
    /// advertised [`tenzro_types::HardwareClass`] biases assignment and the
    /// `min_hardware` routing floor can admit or reject the provider.
    ///
    /// Unlike [`Self::register_provider`], this never errors on a re-announce:
    /// an existing entry keeps its accumulated [`ProviderMetrics`] (the whole
    /// "gate on observed" signal — success rate, latency, quarantine state)
    /// and only its advertised fields (endpoint id, served models, hardware,
    /// status, TEE bit) are refreshed. A provider that re-announces every TTL
    /// therefore does not reset its own observed history.
    pub fn upsert_from_announcement(
        &self,
        address: Address,
        name: String,
        models: Vec<String>,
        hardware: tenzro_types::HardwareCapabilities,
        advertised: tenzro_types::AdvertisedCapacity,
        status: ProviderStatus,
        has_tee: bool,
        machine_did: Option<String>,
        iroh_endpoint_id: Option<String>,
    ) {
        if let Some(mut entry) = self.providers.get_mut(&address) {
            // Refresh advertised fields; preserve observed metrics.
            entry.provider.name = name;
            entry.provider.models = models;
            entry.provider.capacity.hardware = hardware;
            apply_advertised_capacity(&mut entry.provider.capacity, &advertised);
            entry.provider.capacity.iroh_endpoint_id = iroh_endpoint_id;
            entry.provider.status = status;
            entry.provider.machine_did = machine_did;
            entry.has_tee = has_tee;
            let pwm = entry.clone();
            drop(entry);
            self.persist_provider(&address, &pwm);
            debug!("Refreshed gossip-discovered provider: {}", address);
            return;
        }

        let mut provider = InferenceProvider::new(address, name);
        provider.models = models;
        provider.capacity.hardware = hardware;
        apply_advertised_capacity(&mut provider.capacity, &advertised);
        provider.capacity.iroh_endpoint_id = iroh_endpoint_id;
        provider.status = status;
        provider.machine_did = machine_did;

        let pwm = ProviderWithMetrics::new(provider, has_tee);
        self.persist_provider(&address, &pwm);
        self.providers.insert(address, pwm);
        self.persist_index();
        info!("Installed gossip-discovered provider: {}", address);
    }

    /// Install this node's own MoE expert-shard declaration.
    ///
    /// Called by the MoE load/unload handlers after every mutation of the
    /// local [`MoeExpertRuntime`](crate::moe_exec::MoeExpertRuntime): the
    /// runtime status is the source of truth, so `holdings` replaces the
    /// stored set wholesale (idempotent under replay). The heartbeat reads
    /// the self entry back each tick, so the declaration rides the next
    /// `tenzro/providers` announcement and remote routers admit this node
    /// into their [`MoeShardView`](crate::moe_shard::MoeShardView).
    pub fn set_moe_declaration(
        &self,
        address: Address,
        endpoint_url: Option<String>,
        holdings: Vec<tenzro_types::MoeExpertHolding>,
        is_router: bool,
        iroh_endpoint_id: Option<String>,
        moe_gpu: bool,
    ) {
        use tenzro_types::MoeProviderRole;

        let apply = |capacity: &mut tenzro_types::ProviderCapacity| {
            capacity.moe_holdings = holdings.clone();
            capacity.moe_gpu = moe_gpu;
            capacity
                .moe_roles
                .retain(|r| !matches!(r, MoeProviderRole::Router | MoeProviderRole::ExpertHolder));
            if is_router {
                capacity.moe_roles.push(MoeProviderRole::Router);
            }
            if !holdings.is_empty() {
                capacity.moe_roles.push(MoeProviderRole::ExpertHolder);
            }
            if iroh_endpoint_id.is_some() {
                capacity.iroh_endpoint_id = iroh_endpoint_id.clone();
            }
        };

        if let Some(mut entry) = self.providers.get_mut(&address) {
            if endpoint_url.is_some() {
                entry.provider.endpoint_url = endpoint_url;
            }
            apply(&mut entry.provider.capacity);
            let pwm = entry.clone();
            drop(entry);
            self.persist_provider(&address, &pwm);
            debug!("Refreshed self MoE declaration for provider {}", address);
            return;
        }

        let mut provider = InferenceProvider::new(address, address.to_string());
        provider.endpoint_url = endpoint_url;
        provider.status = ProviderStatus::Active;
        apply(&mut provider.capacity);

        let pwm = ProviderWithMetrics::new(provider, false);
        self.persist_provider(&address, &pwm);
        self.providers.insert(address, pwm);
        self.persist_index();
        info!("Installed self MoE declaration for provider {}", address);
    }

    /// Removes a provider from the routing set.
    ///
    /// Used by the provider-heartbeat sweep when a gossip-discovered provider
    /// exceeds its announcement TTL without a refresh — an expired provider
    /// must not remain routable. Returns `true` if an entry was removed.
    pub fn remove_provider(&self, address: &Address) -> bool {
        self.liveness.forget(address);
        if self.providers.remove(address).is_some() {
            self.delete_persisted_provider(address);
            self.persist_index();
            debug!("Removed provider from routing set: {}", address);
            true
        } else {
            false
        }
    }

    /// Lists all providers
    pub fn list_providers(&self) -> Vec<InferenceProvider> {
        self.providers
            .iter()
            .map(|entry| entry.value().provider.clone())
            .collect()
    }

    /// Gets all providers that serve a specific model
    pub fn get_providers_for_model(&self, model_id: &str) -> Vec<InferenceProvider> {
        self.providers
            .iter()
            .filter(|entry| entry.value().provider.serves_model(model_id))
            .map(|entry| entry.value().provider.clone())
            .collect()
    }

    /// Gets active providers for a specific model.
    ///
    /// Excludes providers that are auto-quarantined due to consecutive
    /// mid-stream drops — see [`Self::record_stream_failure`].
    pub fn get_active_providers_for_model(&self, model_id: &str) -> Vec<ProviderWithMetrics> {
        self.providers
            .iter()
            .filter(|entry| {
                let pwm = entry.value();
                pwm.provider.serves_model(model_id)
                    && pwm.provider.status == ProviderStatus::Active
                    && pwm.metrics.is_healthy(self.max_heartbeat_age_ms)
                    && !pwm.metrics.is_quarantined()
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Gets providers with TEE capability
    pub fn get_tee_providers(&self) -> Vec<InferenceProvider> {
        self.providers
            .iter()
            .filter(|entry| entry.value().has_tee)
            .map(|entry| entry.value().provider.clone())
            .collect()
    }

    /// Records a successful inference for a provider: latency metrics only.
    /// Reputation is the provider's consensus standing ([`Self::refresh_reputation`]).
    pub fn record_success(&self, provider_address: &Address, latency_ms: u64) {
        if let Some(mut entry) = self.providers.get_mut(provider_address) {
            entry.metrics.record_success(latency_ms);
            let pwm = entry.clone();
            drop(entry);
            self.persist_provider(provider_address, &pwm);
        }
    }

    /// Records a call-time failure (pre-stream) for a provider. A pre-stream
    /// failure is recoverable by retrying a sibling provider; see
    /// [`Self::record_stream_failure`] for the mid-stream signal.
    pub fn record_call_failure(&self, provider_address: &Address) {
        if let Some(mut entry) = self.providers.get_mut(provider_address) {
            entry.metrics.record_call_failure();
            let pwm = entry.clone();
            drop(entry);
            self.persist_provider(provider_address, &pwm);
        }
    }

    /// Records a mid-stream failure for a provider (transport drop after
    /// at least one token was emitted, or upstream stream error).
    ///
    /// Bumps the consecutive-stream-failure counter on [`ProviderMetrics`]; after
    /// [`STREAM_FAILURE_QUARANTINE_THRESHOLD`] consecutive drops the
    /// provider is auto-quarantined for [`STREAM_FAILURE_QUARANTINE_MS`]
    /// and removed from the routable pool until the window passes.
    pub fn record_stream_failure(&self, provider_address: &Address) {
        if let Some(mut entry) = self.providers.get_mut(provider_address) {
            entry.metrics.record_stream_failure();
            let pwm = entry.clone();
            drop(entry);
            self.persist_provider(provider_address, &pwm);
        }
    }

    /// Returns true if the provider is currently auto-quarantined due to
    /// consecutive stream failures.
    pub fn is_quarantined(&self, provider_address: &Address) -> bool {
        self.providers
            .get(provider_address)
            .map(|entry| entry.value().metrics.is_quarantined())
            .unwrap_or(false)
    }

    /// Set every provider's reputation from `score`: the provider's standing
    /// in consensus state (`0..=10_000`), read from its serving bond and the
    /// SLA verdicts recorded for it. Nothing is computed from local
    /// observations; this keeps the routing view in step with chain state.
    pub fn refresh_reputation(&self, score: &dyn Fn(&Address) -> u64) {
        for mut entry in self.providers.iter_mut() {
            let addr = entry.provider.address;
            entry.provider.reputation = score(&addr);
        }
    }

    /// Returns the current reputation score for a provider, or `None` if
    /// unknown: the consensus standing set by [`Self::refresh_reputation`].
    pub fn get_reputation(&self, provider_address: &Address) -> Option<u64> {
        self.providers
            .get(provider_address)
            .map(|entry| entry.value().provider.reputation)
    }

    /// Updates provider heartbeat
    pub fn heartbeat(&self, provider_address: &Address) -> Result<()> {
        if let Some(mut entry) = self.providers.get_mut(provider_address) {
            entry.metrics.heartbeat();
            let pwm = entry.clone();
            drop(entry);
            self.persist_provider(provider_address, &pwm);
            Ok(())
        } else {
            Err(ModelError::ProviderNotFound(provider_address.to_string()))
        }
    }

    /// Gets metrics for a provider
    pub fn get_metrics(&self, provider_address: &Address) -> Result<ProviderMetrics> {
        self.providers
            .get(provider_address)
            .map(|entry| entry.value().metrics.clone())
            .ok_or_else(|| ModelError::ProviderNotFound(provider_address.to_string()))
    }

    /// Gets ranked providers for a model (sorted by score)
    pub fn get_ranked_providers(&self, model_id: &str) -> Vec<ProviderWithMetrics> {
        let mut providers = self.get_active_providers_for_model(model_id);
        providers.sort_by(|a, b| {
            b.calculate_score()
                .partial_cmp(&a.calculate_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        providers
    }

    /// Gets the count of registered providers
    pub fn count(&self) -> usize {
        self.providers.len()
    }

    /// The reputation and service record of the cluster `cluster_did`,
    /// aggregated from the records of its member providers at `members`.
    /// Nothing is stored under the cluster: each member keeps its own record,
    /// and every call stays attributed to the member that served it.
    pub fn cluster_record(&self, cluster_did: &str, members: &[Address]) -> ClusterRecord {
        let mut record = ClusterRecord {
            cluster_did: cluster_did.to_string(),
            ..ClusterRecord::default()
        };
        let mut reputation_sum = 0u64;
        for address in members {
            let Some(entry) = self.providers.get(address) else {
                continue;
            };
            let (provider, metrics) = (&entry.value().provider, &entry.value().metrics);
            record.members_with_records += 1;
            reputation_sum += provider.reputation;
            record.min_reputation = Some(
                record
                    .min_reputation
                    .map_or(provider.reputation, |m| m.min(provider.reputation)),
            );
            record.total_requests += metrics.total_requests;
            record.successful_requests += metrics.successful_requests;
            record.failed_requests += metrics.failed_requests;
            if metrics.is_quarantined() {
                record.quarantined_members += 1;
            }
        }
        if record.members_with_records > 0 {
            record.mean_reputation = Some(reputation_sum / record.members_with_records as u64);
        }
        record
    }
}

/// A cluster's reputation and service record, aggregated from its members'
/// provider records (see [`ProviderManager::cluster_record`]).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterRecord {
    /// The cluster DID the record is keyed by.
    pub cluster_did: String,
    /// Members this node holds a provider record for.
    pub members_with_records: usize,
    /// Mean member reputation, `None` when no member has a record.
    pub mean_reputation: Option<u64>,
    /// Lowest member reputation, `None` when no member has a record.
    pub min_reputation: Option<u64>,
    /// Requests served across members.
    pub total_requests: u64,
    /// Successful requests across members.
    pub successful_requests: u64,
    /// Failed requests across members.
    pub failed_requests: u64,
    /// Members currently quarantined.
    pub quarantined_members: usize,
}

impl ProviderManager {
    /// Gets the health status of a provider
    pub fn get_health(&self, provider_address: &Address) -> Result<ProviderHealth> {
        self.providers
            .get(provider_address)
            .map(|entry| entry.value().metrics.health.clone())
            .ok_or_else(|| ModelError::ProviderNotFound(provider_address.to_string()))
    }

    /// Lists all healthy providers
    pub fn list_healthy_providers(&self) -> Vec<InferenceProvider> {
        self.providers
            .iter()
            .filter(|entry| entry.value().metrics.health.healthy)
            .map(|entry| entry.value().provider.clone())
            .collect()
    }

    /// Applies exponential decay to provider metrics to reduce the impact of old data.
    ///
    /// Half-life is 1 hour of *elapsed time since the previous decay pass*
    /// (`ProviderMetrics::last_decay`), so calling this before every routing
    /// decision applies decay proportionally rather than compounding a full
    /// factor per call. Elapsed intervals shorter than one minute leave
    /// `last_decay` untouched, letting time accumulate instead of being
    /// rounded away pass after pass.
    ///
    /// `total_latency_ms` decays by the same factor as the counts so
    /// `avg_latency_ms` stays a truthful per-request average.
    pub fn decay_metrics(&self) {
        const HALF_LIFE_SECS: f64 = 3600.0; // 1 hour
        const MIN_DECAY_INTERVAL_SECS: f64 = 60.0;

        let now = Timestamp::now();
        let now_secs = now.as_millis() as f64 / 1000.0;

        for mut entry in self.providers.iter_mut() {
            let metrics = &mut entry.metrics;

            let Some(last_decay) = metrics.last_decay else {
                // First pass for this provider: anchor the decay clock.
                metrics.last_decay = Some(now);
                continue;
            };
            let elapsed_secs = (now_secs - last_decay.as_millis() as f64 / 1000.0).max(0.0);
            if elapsed_secs < MIN_DECAY_INTERVAL_SECS {
                continue;
            }

            let decay_factor = 0.5_f64.powf(elapsed_secs / HALF_LIFE_SECS);

            metrics.successful_requests =
                (metrics.successful_requests as f64 * decay_factor).round() as u64;
            metrics.failed_requests =
                (metrics.failed_requests as f64 * decay_factor).round() as u64;
            metrics.total_requests = metrics.successful_requests + metrics.failed_requests;
            metrics.total_latency_ms =
                (metrics.total_latency_ms as f64 * decay_factor).round() as u64;
            metrics.avg_latency_ms = metrics
                .total_latency_ms
                .checked_div(metrics.successful_requests)
                .unwrap_or(0);
            metrics.last_decay = Some(now);
        }
    }
}

impl Default for ProviderManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_get_provider() {
        let manager = ProviderManager::new();
        let provider = create_test_provider();

        manager.register_provider(provider.clone(), false).unwrap();
        let retrieved = manager.get_provider(&provider.address).unwrap();

        assert_eq!(retrieved.address, provider.address);
    }

    #[test]
    fn test_provider_metrics() {
        let mut metrics = ProviderMetrics::new();

        metrics.record_success(100);
        metrics.record_success(200);
        metrics.record_call_failure();

        assert_eq!(metrics.total_requests, 3);
        assert_eq!(metrics.successful_requests, 2);
        assert_eq!(metrics.failed_requests, 1);
        assert_eq!(metrics.avg_latency_ms, 150);
        assert_eq!(metrics.success_rate(), 2.0 / 3.0);
    }

    #[test]
    fn stream_failure_quarantines_after_threshold() {
        let mut metrics = ProviderMetrics::new();
        // Heartbeat so the provider is otherwise "healthy" — quarantine
        // must be the discriminator here.
        metrics.heartbeat();

        for _ in 0..(STREAM_FAILURE_QUARANTINE_THRESHOLD - 1) {
            metrics.record_stream_failure();
            assert!(!metrics.is_quarantined());
        }
        metrics.record_stream_failure();
        assert!(metrics.is_quarantined());
        assert_eq!(
            metrics.consecutive_stream_failures,
            STREAM_FAILURE_QUARANTINE_THRESHOLD
        );
        assert_eq!(
            metrics.stream_failures,
            STREAM_FAILURE_QUARANTINE_THRESHOLD as u64
        );
    }

    #[test]
    fn success_clears_quarantine_and_resets_counter() {
        let mut metrics = ProviderMetrics::new();
        for _ in 0..STREAM_FAILURE_QUARANTINE_THRESHOLD {
            metrics.record_stream_failure();
        }
        assert!(metrics.is_quarantined());

        metrics.record_success(50);
        assert!(!metrics.is_quarantined());
        assert_eq!(metrics.consecutive_stream_failures, 0);
        assert!(metrics.quarantined_until.is_none());
    }

    #[test]
    fn call_failure_does_not_advance_stream_counter() {
        let mut metrics = ProviderMetrics::new();
        for _ in 0..10 {
            metrics.record_call_failure();
        }
        assert_eq!(metrics.consecutive_stream_failures, 0);
        assert!(!metrics.is_quarantined());
        assert_eq!(metrics.failed_requests, 10);
        assert_eq!(metrics.stream_failures, 0);
    }

    #[test]
    fn test_get_providers_for_model() {
        let manager = ProviderManager::new();
        let mut provider = create_test_provider();
        provider.models.push("model-1".to_string());

        manager.register_provider(provider, false).unwrap();

        let providers = manager.get_providers_for_model("model-1");
        assert_eq!(providers.len(), 1);

        let empty = manager.get_providers_for_model("model-2");
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn test_provider_persistence_roundtrip() {
        use tenzro_storage::kv::MemoryStore;

        let store = Arc::new(MemoryStore::new());

        // Register a provider with storage
        let manager = ProviderManager::with_storage(store.clone());
        let provider = create_test_provider();
        manager.register_provider(provider.clone(), false).unwrap();

        // Record some metrics
        manager.record_success(&provider.address, 150);
        manager.record_success(&provider.address, 250);

        // Create a new manager from the same storage — it should hydrate
        let manager2 = ProviderManager::with_storage(store);
        let retrieved = manager2.get_provider(&provider.address).unwrap();
        assert_eq!(retrieved.address, provider.address);

        let metrics = manager2.get_metrics(&provider.address).unwrap();
        assert_eq!(metrics.successful_requests, 2);
        assert_eq!(metrics.avg_latency_ms, 200);
    }

    fn create_test_provider() -> InferenceProvider {
        InferenceProvider::new(Address::zero(), "Test Provider".to_string())
    }

    #[test]
    fn a_cluster_record_aggregates_only_its_members() {
        let manager = ProviderManager::new();
        let addr = |b: u8| Address::new([b; 32]);
        for (b, reputation) in [(1u8, 800u64), (2, 400), (3, 1000)] {
            let mut p = InferenceProvider::new(addr(b), format!("p{b}"));
            p.reputation = reputation;
            manager.register_provider(p, false).unwrap();
        }
        manager.record_success(&addr(1), 10);
        manager.record_call_failure(&addr(2));
        manager.record_success(&addr(3), 10);

        let record = manager.cluster_record("did:tenzro:cluster:c", &[addr(1), addr(2), addr(9)]);
        assert_eq!(record.cluster_did, "did:tenzro:cluster:c");
        assert_eq!(record.members_with_records, 2);
        let (r1, r2) = (
            manager.get_reputation(&addr(1)).unwrap(),
            manager.get_reputation(&addr(2)).unwrap(),
        );
        assert_eq!(record.mean_reputation, Some((r1 + r2) / 2));
        assert_eq!(record.min_reputation, Some(r1.min(r2)));
        assert_eq!(record.total_requests, 2);
        assert_eq!(record.successful_requests, 1);
        assert_eq!(record.failed_requests, 1);
    }
}
