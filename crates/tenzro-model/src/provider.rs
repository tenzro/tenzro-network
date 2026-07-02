//! Inference provider management module
//!
//! This module handles registration, tracking, and health monitoring of
//! inference providers on Tenzro Network.

use crate::error::{ModelError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::kv::{KvStore, CF_PROVIDERS};
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
        self.consecutive_stream_failures =
            self.consecutive_stream_failures.saturating_add(1);
        if self.consecutive_stream_failures >= STREAM_FAILURE_QUARANTINE_THRESHOLD {
            let now = Timestamp::now();
            self.quarantined_until =
                Some(Timestamp::new(now.as_millis() + STREAM_FAILURE_QUARANTINE_MS));
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
        if self.successful_requests > 0 {
            self.avg_latency_ms = self.total_latency_ms / self.successful_requests;
        }
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

    /// Calculates a score for provider ranking (0.0 - 100.0)
    pub fn calculate_score(&self) -> f64 {
        let success_weight = 40.0;
        let latency_weight = 30.0;
        let uptime_weight = 20.0;
        let reputation_weight = 10.0;

        // Success rate component (0-40 points)
        let success_score = self.metrics.success_rate() * success_weight;

        // Latency component (0-30 points) - lower is better
        // Assume 1000ms is baseline, 100ms is excellent
        let latency_score = if self.metrics.avg_latency_ms == 0 {
            0.0
        } else {
            let normalized = 1000.0 / self.metrics.avg_latency_ms as f64;
            normalized.min(1.0) * latency_weight
        };

        // Uptime component (0-20 points)
        let uptime_score = (self.metrics.uptime_percentage / 100.0) * uptime_weight;

        // Reputation component (0-10 points)
        // Normalize reputation to 0-1 range (assuming max 1000)
        let reputation_score = (self.provider.reputation as f64 / 1000.0).min(1.0) * reputation_weight;

        success_score + latency_score + uptime_score + reputation_score
    }
}

/// Manager for inference providers
#[derive(Clone)]
pub struct ProviderManager {
    /// Map of provider address to provider with metrics
    providers: Arc<DashMap<Address, ProviderWithMetrics>>,
    /// Maximum heartbeat age in milliseconds before provider is considered unhealthy
    max_heartbeat_age_ms: i64,
    /// Health check interval in milliseconds
    health_check_interval_ms: u64,
    /// Maximum consecutive failures before marking unhealthy
    max_consecutive_failures: u32,
    /// Optional persistent storage backend
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for ProviderManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderManager")
            .field("providers", &self.providers.len())
            .field("max_heartbeat_age_ms", &self.max_heartbeat_age_ms)
            .field("health_check_interval_ms", &self.health_check_interval_ms)
            .field("max_consecutive_failures", &self.max_consecutive_failures)
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
            health_check_interval_ms: 60_000, // 1 minute default
            max_consecutive_failures: 3, // 3 failures before marking unhealthy
            storage: None,
        }
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
            health_check_interval_ms: 60_000,
            max_consecutive_failures: 3,
            storage: Some(storage),
        }
    }

    /// Creates a new provider manager with custom heartbeat timeout
    pub fn with_heartbeat_timeout(max_heartbeat_age_ms: i64) -> Self {
        Self {
            providers: Arc::new(DashMap::new()),
            max_heartbeat_age_ms,
            health_check_interval_ms: 60_000,
            max_consecutive_failures: 3,
            storage: None,
        }
    }

    /// Creates a new provider manager with custom health check configuration
    pub fn with_health_config(
        health_check_interval_ms: u64,
        max_consecutive_failures: u32,
    ) -> Self {
        Self {
            providers: Arc::new(DashMap::new()),
            max_heartbeat_age_ms: 300_000,
            health_check_interval_ms,
            max_consecutive_failures,
            storage: None,
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

    /// Updates the provider index in storage (list of all provider key hexes).
    fn persist_index(&self) {
        if let Some(ref storage) = self.storage {
            let keys: Vec<String> = self.providers.iter().map(|e| format!("{}", e.key())).collect();
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
    pub fn register_provider(
        &self,
        provider: InferenceProvider,
        has_tee: bool,
    ) -> Result<()> {
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

    /// Deactivates a provider
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ProviderNotFound` if provider doesn't exist.
    pub fn deactivate_provider(&self, address: &Address) -> Result<()> {
        if let Some(mut entry) = self.providers.get_mut(address) {
            entry.provider.status = ProviderStatus::Inactive;
            let pwm = entry.clone();
            drop(entry);
            self.persist_provider(address, &pwm);
            warn!("Deactivated provider: {}", address);
            Ok(())
        } else {
            Err(ModelError::ProviderNotFound(address.to_string()))
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

    /// Records a successful inference for a provider.
    ///
    /// Bumps reputation by `+1` (saturating at 1000, the same ceiling
    /// `ProviderWithMetrics::calculate_score` normalizes against). Reputation
    /// flows back into routing decisions via `RoutingStrategy::Reputation`,
    /// `RoutingStrategy::Cortex`, and the weighted-score path in
    /// `ProviderWithMetrics::calculate_score`, so this is the only producer
    /// for the score axis.
    ///
    /// Updates LATENCY metrics only, NOT reputation.
    /// HTTP-200 is a circuit-breaker signal (the provider answered) and
    /// is not a settled-payment signal (the consumer actually got value).
    /// A provider could otherwise self-deal by hitting its own endpoint to
    /// manufacture HTTP-200 responses, so the reputation axis is reserved
    /// for [`Self::record_settled_success`] — that fires only when the
    /// inference→settlement loop confirms a real payment from the
    /// consumer to the provider.
    pub fn record_success(&self, provider_address: &Address, latency_ms: u64) {
        if let Some(mut entry) = self.providers.get_mut(provider_address) {
            entry.metrics.record_success(latency_ms);
            let pwm = entry.clone();
            drop(entry);
            self.persist_provider(provider_address, &pwm);
        }
    }

    /// Records a payment-bound success: the consumer received the
    /// inference AND a real settlement to the provider has cleared. This
    /// is the ONLY path that moves the reputation axis upward, closing
    /// the self-deal attack where a provider could earn reputation by
    /// hitting its own endpoint.
    ///
    /// Caller invariant: only call this after the settlement engine
    /// confirms a non-zero TNZO transfer from the consumer to the
    /// provider. The `settled_amount` parameter is passed through for
    /// metrics correlation but does not gate the reputation bump — the
    /// caller is responsible for verifying it is non-zero before
    /// invoking this method.
    pub fn record_settled_success(&self, provider_address: &Address, settled_amount: u128) {
        if settled_amount == 0 {
            return;
        }
        if let Some(mut entry) = self.providers.get_mut(provider_address) {
            entry.provider.reputation = entry.provider.reputation.saturating_add(1).min(1000);
            let pwm = entry.clone();
            drop(entry);
            self.persist_provider(provider_address, &pwm);
        }
    }

    /// Records a call-time failure (pre-stream) for a provider.
    ///
    /// Penalizes reputation by `-5` (saturating at 0). The asymmetry against
    /// `record_success`'s `+1` is intentional: a single failure should cost
    /// roughly as much trust as five successes earn, so a flaky provider
    /// drifts down the ranking quickly. A pre-stream failure is recoverable
    /// by retrying a sibling provider — see [`Self::record_stream_failure`]
    /// for the sharper mid-stream signal.
    pub fn record_call_failure(&self, provider_address: &Address) {
        if let Some(mut entry) = self.providers.get_mut(provider_address) {
            entry.metrics.record_call_failure();
            entry.provider.reputation = entry.provider.reputation.saturating_sub(5);
            let pwm = entry.clone();
            drop(entry);
            self.persist_provider(provider_address, &pwm);
        }
    }

    /// Records a mid-stream failure for a provider (transport drop after
    /// at least one token was emitted, or upstream stream error).
    ///
    /// Penalizes reputation by `-15` — three times the call-failure
    /// penalty — because a dropped stream means the client lost in-flight
    /// tokens it already paid for, while a failed call before any tokens
    /// left the wire is usually recoverable. Also bumps the
    /// consecutive-stream-failure counter on [`ProviderMetrics`]; after
    /// [`STREAM_FAILURE_QUARANTINE_THRESHOLD`] consecutive drops the
    /// provider is auto-quarantined for [`STREAM_FAILURE_QUARANTINE_MS`]
    /// and removed from the routable pool until the window passes.
    pub fn record_stream_failure(&self, provider_address: &Address) {
        if let Some(mut entry) = self.providers.get_mut(provider_address) {
            entry.metrics.record_stream_failure();
            entry.provider.reputation = entry.provider.reputation.saturating_sub(15);
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

    /// Returns the current reputation score for a provider, or `None` if
    /// unknown. Reputation is a u64 in `[0, 1000]` — see [`Self::record_success`]
    /// and [`Self::record_failure`] for how it evolves.
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

    /// Performs a health check on a provider
    ///
    /// Sends an HTTP GET request to the provider's health endpoint
    /// and updates health metrics based on the response.
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ProviderNotFound` if provider doesn't exist.
    pub async fn check_provider_health(&self, provider_address: &Address) -> Result<bool> {
        let provider = self.get_provider(provider_address)?;

        // Construct health endpoint URL from the provider's configured endpoint
        let health_url = match provider.endpoint_url {
            Some(ref endpoint) => {
                let base = endpoint.trim_end_matches('/');
                format!("{}/health", base)
            }
            None => {
                return Err(ModelError::ProviderNotAvailable(
                    format!("Provider {} has no endpoint_url configured", provider_address),
                ));
            }
        };

        info!("Checking health for provider {} at {}", provider_address, health_url);

        let start = std::time::Instant::now();

        // Perform HTTP GET request with timeout
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| ModelError::ProviderNotAvailable(format!("Failed to create HTTP client: {}", e)))?;

        let response_result = client.get(&health_url).send().await;

        let elapsed = start.elapsed().as_millis() as u64;

        // Update health metrics
        if let Some(mut entry) = self.providers.get_mut(provider_address) {
            let is_healthy = if let Ok(response) = response_result {
                if response.status().is_success() {
                    // Reset consecutive failures on success
                    entry.metrics.health.consecutive_failures = 0;
                    entry.metrics.health.healthy = true;
                    entry.metrics.health.response_time_ms = elapsed;
                    entry.metrics.health.last_check = Timestamp::now();

                    // Update uptime percentage
                    let total_checks = entry.metrics.total_requests + 1;
                    let successful_checks = entry.metrics.successful_requests + 1;
                    entry.metrics.uptime_percentage = (successful_checks as f64 / total_checks as f64) * 100.0;

                    debug!(
                        "Provider {} health check passed in {}ms",
                        provider_address, elapsed
                    );
                    true
                } else {
                    // Increment failures
                    entry.metrics.health.consecutive_failures += 1;
                    entry.metrics.health.response_time_ms = elapsed;
                    entry.metrics.health.last_check = Timestamp::now();

                    // Mark unhealthy if threshold exceeded
                    if entry.metrics.health.consecutive_failures >= self.max_consecutive_failures {
                        entry.metrics.health.healthy = false;
                        warn!(
                            "Provider {} marked unhealthy after {} consecutive failures",
                            provider_address, entry.metrics.health.consecutive_failures
                        );
                    }

                    false
                }
            } else {
                // Network error or timeout
                entry.metrics.health.consecutive_failures += 1;
                entry.metrics.health.last_check = Timestamp::now();

                if entry.metrics.health.consecutive_failures >= self.max_consecutive_failures {
                    entry.metrics.health.healthy = false;
                    warn!(
                        "Provider {} marked unhealthy after {} consecutive failures (network error)",
                        provider_address, entry.metrics.health.consecutive_failures
                    );
                }

                false
            };

            Ok(is_healthy)
        } else {
            Err(ModelError::ProviderNotFound(provider_address.to_string()))
        }
    }

    /// Performs health checks on all registered providers
    ///
    /// Returns a map of provider addresses to their health status.
    pub async fn check_all_providers(&self) -> Vec<(Address, bool)> {
        let mut results = Vec::new();

        for entry in self.providers.iter() {
            let address = *entry.key();
            match self.check_provider_health(&address).await {
                Ok(is_healthy) => {
                    results.push((address, is_healthy));
                }
                Err(e) => {
                    warn!("Failed to check health for provider {}: {}", address, e);
                    results.push((address, false));
                }
            }
        }

        results
    }

    /// Starts periodic health checks for all providers
    ///
    /// Spawns a background task that periodically checks the health of all providers.
    /// Health check results are applied directly to provider state in the DashMap
    /// by `check_provider_health()`, and summary statistics are logged.
    pub fn start_health_checks(&self) -> tokio::task::JoinHandle<()> {
        let manager = self.clone();
        let interval_ms = self.health_check_interval_ms;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(interval_ms));

            loop {
                interval.tick().await;
                debug!("Running periodic health checks");
                let results = manager.check_all_providers().await;

                // Log health check summary and apply deactivation for unhealthy providers
                let total = results.len();
                let healthy = results.iter().filter(|(_, h)| *h).count();
                let unhealthy = total - healthy;

                if unhealthy > 0 {
                    warn!(
                        "Health check: {}/{} providers healthy, {} unhealthy",
                        healthy, total, unhealthy
                    );

                    // Deactivate providers that have exceeded max consecutive failures
                    for (address, is_healthy) in &results {
                        if !is_healthy
                            && let Some(entry) = manager.providers.get(address)
                            && entry.metrics.health.consecutive_failures
                                >= manager.max_consecutive_failures
                        {
                            info!(
                                "Deactivating unhealthy provider {} ({} consecutive failures)",
                                address, entry.metrics.health.consecutive_failures
                            );
                            drop(entry); // Release read guard before write
                            let _ = manager.deactivate_provider(address);
                        }
                    }
                } else if total > 0 {
                    debug!("Health check: all {}/{} providers healthy", healthy, total);
                }
            }
        })
    }

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
            metrics.avg_latency_ms = if metrics.successful_requests > 0 {
                metrics.total_latency_ms / metrics.successful_requests
            } else {
                0
            };
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
    fn stream_failure_penalty_is_three_times_call_failure() {
        // -15 vs -5 — verify via the ProviderManager surface.
        let manager_call = ProviderManager::new();
        let mut p_call = create_test_provider();
        p_call.reputation = 100;
        let addr_call = p_call.address.clone();
        manager_call.register_provider(p_call, false).unwrap();
        manager_call.record_call_failure(&addr_call);
        let rep_after_call = manager_call.get_reputation(&addr_call).unwrap();

        let manager_stream = ProviderManager::new();
        let mut p_stream = create_test_provider();
        p_stream.reputation = 100;
        let addr_stream = p_stream.address.clone();
        manager_stream.register_provider(p_stream, false).unwrap();
        manager_stream.record_stream_failure(&addr_stream);
        let rep_after_stream = manager_stream.get_reputation(&addr_stream).unwrap();

        assert_eq!(100 - rep_after_call, 5);
        assert_eq!(100 - rep_after_stream, 15);
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
}
