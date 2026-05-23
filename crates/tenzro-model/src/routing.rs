//! Inference request routing module
//!
//! This module handles intelligent routing of inference requests to the best
//! available provider based on various strategies and requirements.

use crate::{
    error::{ModelError, Result},
    provider::{ProviderManager, ProviderWithMetrics},
    registry::ModelRegistry,
    usage::{UsageRecord, UsageTracker},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tenzro_types::{
    model::{InferenceRequest, InferenceResponse, InferenceMetadata, ModelModality},
    primitives::{Address, Timestamp},
};
use tracing::{debug, info, warn};

/// Strategy for routing inference requests
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum RoutingStrategy {
    /// Route to provider with lowest price
    LowestPrice,
    /// Route to provider with lowest latency
    LowestLatency,
    /// Route to provider with highest reputation
    HighestReputation,
    /// Route to a random provider
    Random,
    /// Route based on weighted score combining all factors
    #[default]
    WeightedScore,
    /// Tenzro Cortex: prefer providers whose advertised max loop count
    /// meets or exceeds the caller's target reasoning depth, breaking
    /// ties by reputation. Intended for recurrent-depth reasoning models.
    ReasoningDepth,
}


/// Typed inference payload — discriminated by modality so the router
/// can dispatch to the correct backend runtime without re-parsing the
/// raw `InferenceRequest::input` byte buffer.
///
/// LLMs keep their existing OpenAI-compatible chat shape (`Chat`); every
/// other modality wraps a typed sidecar request that the per-runtime
/// handler decodes directly. This enum exists so RPC handlers, the MCP
/// bridge, and the agent kit can all hand the router a typed payload
/// instead of stringly-typed bytes.
///
/// The variant names map 1:1 to `ModelModality` via `payload_modality()`,
/// which the router uses to validate that the caller's payload matches
/// the registered model — sending a `Forecast` payload to a `Text` model
/// returns `ModelError::ModalityMismatch` synchronously rather than
/// failing at runtime decode time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InferencePayload {
    /// LLM chat completion (Text modality). Carries the legacy
    /// `InferenceRequest` for source-compatibility with existing routes.
    Chat(InferenceRequest),
    /// Timeseries forecast: univariate context plus optional covariates.
    Forecast {
        model_id: String,
        context: Vec<f32>,
        horizon: u32,
    },
    /// Image embedding: returns `[1, D]`.
    VisionEmbed {
        model_id: String,
        image_bytes: Vec<u8>,
        normalize: bool,
    },
    /// Image-text similarity (CLIP/SigLIP-style zero-shot).
    VisionSimilarity {
        model_id: String,
        image_bytes: Vec<u8>,
        labels: Vec<String>,
    },
    /// Text embedding: returns `[B, D]` per input string.
    TextEmbed {
        model_id: String,
        texts: Vec<String>,
        requested_dim: Option<u32>,
    },
    /// SAM-family segmentation: image + prompts → masks.
    Segment {
        model_id: String,
        image_bytes: Vec<u8>,
        /// Opaque prompt blob — decoded by the segmentation runtime.
        prompts_json: String,
    },
    /// DETR-family detection: image + threshold → boxes.
    Detect {
        model_id: String,
        image_bytes: Vec<u8>,
        score_threshold: f32,
    },
    /// ASR transcription.
    Transcribe {
        model_id: String,
        audio_bytes: Vec<u8>,
        language: Option<String>,
    },
    /// Video embedding (encoder-only, returns `[1, D]`).
    VideoEmbed {
        model_id: String,
        video_bytes: Vec<u8>,
        normalize: bool,
    },
}

impl InferencePayload {
    /// Returns the model_id this payload addresses.
    pub fn model_id(&self) -> &str {
        match self {
            Self::Chat(req) => &req.model_id,
            Self::Forecast { model_id, .. }
            | Self::VisionEmbed { model_id, .. }
            | Self::VisionSimilarity { model_id, .. }
            | Self::TextEmbed { model_id, .. }
            | Self::Segment { model_id, .. }
            | Self::Detect { model_id, .. }
            | Self::Transcribe { model_id, .. }
            | Self::VideoEmbed { model_id, .. } => model_id,
        }
    }

    /// Returns the `ModelModality` this payload requires the target
    /// model to support. Used by `InferenceRouter::check_modality` to
    /// reject mismatches before dispatch.
    ///
    /// Note: text embedding models (`TextEmbed`) take text input and so
    /// share the `Text` modality with chat LLMs — the payload variant
    /// itself disambiguates which runtime handles the request. The
    /// router's modality check is about *input modality*, not output
    /// shape.
    pub fn payload_modality(&self) -> ModelModality {
        match self {
            Self::Chat(_) | Self::TextEmbed { .. } => ModelModality::Text,
            Self::Forecast { .. } => ModelModality::Timeseries,
            Self::VisionEmbed { .. }
            | Self::VisionSimilarity { .. }
            | Self::Segment { .. }
            | Self::Detect { .. } => ModelModality::Image,
            Self::Transcribe { .. } => ModelModality::Audio,
            Self::VideoEmbed { .. } => ModelModality::Video,
        }
    }
}

/// Configuration for inference routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Routing strategy to use
    pub strategy: RoutingStrategy,
    /// Maximum number of retries on failure
    pub max_retries: u32,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
    /// Require TEE provider
    pub require_tee: bool,
    /// Preferred providers (will be tried first if available)
    pub preferred_providers: Vec<Address>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            strategy: RoutingStrategy::WeightedScore,
            max_retries: 3,
            timeout_ms: 120_000,
            require_tee: false,
            preferred_providers: Vec::new(),
        }
    }
}

impl RoutingConfig {
    /// Creates a new routing configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the routing strategy
    pub fn with_strategy(mut self, strategy: RoutingStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Sets TEE requirement
    pub fn with_tee_required(mut self, required: bool) -> Self {
        self.require_tee = required;
        self
    }

    /// Sets the request timeout in milliseconds
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Adds a preferred provider
    pub fn add_preferred_provider(mut self, provider: Address) -> Self {
        self.preferred_providers.push(provider);
        self
    }
}

/// Circuit breaker state for a provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitBreakerState {
    /// Circuit is closed, requests can flow
    Closed,
    /// Circuit is open, provider is temporarily blacklisted
    Open,
    /// Circuit is half-open, testing if provider has recovered
    HalfOpen,
}

/// Circuit breaker for provider failure handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreaker {
    /// Number of consecutive failures
    pub failure_count: u32,
    /// Timestamp of last failure
    pub last_failure: Option<Timestamp>,
    /// Current state of the circuit breaker
    pub state: CircuitBreakerState,
    /// Failure threshold before opening circuit
    pub failure_threshold: u32,
    /// Time to wait before attempting half-open (milliseconds)
    pub reset_timeout_ms: i64,
}

impl CircuitBreaker {
    /// Creates a new circuit breaker
    pub fn new(failure_threshold: u32, reset_timeout_ms: i64) -> Self {
        Self {
            failure_count: 0,
            last_failure: None,
            state: CircuitBreakerState::Closed,
            failure_threshold,
            reset_timeout_ms,
        }
    }

    /// Records a failure
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure = Some(Timestamp::now());

        if self.failure_count >= self.failure_threshold {
            self.state = CircuitBreakerState::Open;
        }
    }

    /// Records a success
    pub fn record_success(&mut self) {
        self.failure_count = 0;
        self.state = CircuitBreakerState::Closed;
    }

    /// Checks if requests are allowed
    pub fn is_request_allowed(&mut self) -> bool {
        match self.state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                // Check if we should try half-open
                if let Some(last_failure) = self.last_failure {
                    let elapsed = Timestamp::now().as_millis() - last_failure.as_millis();
                    if elapsed >= self.reset_timeout_ms {
                        self.state = CircuitBreakerState::HalfOpen;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitBreakerState::HalfOpen => true,
        }
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(5, 60_000) // 5 failures, 60 second timeout
    }
}

/// Router for inference requests
pub struct InferenceRouter {
    /// Provider manager
    provider_manager: Arc<ProviderManager>,
    /// Optional registry handle. When set, the router can check the
    /// caller's `InferencePayload` modality against the registered
    /// model's modality and reject mismatches synchronously
    /// (`ModelError::ModalityMismatch`).
    registry: Option<Arc<ModelRegistry>>,
    /// Circuit breakers for each provider
    circuit_breakers: Arc<dashmap::DashMap<Address, CircuitBreaker>>,
    /// Default routing configuration
    default_config: RoutingConfig,
    /// HTTP client for forwarding requests to providers
    http_client: reqwest::Client,
    /// Optional usage tracker. When set, every successful inference is
    /// recorded as a `UsageRecord` (model/provider/tokens/cost/latency)
    /// and aggregated into per-model + per-provider + global stats. This
    /// is the producer side of the marketplace observability data —
    /// without a tracker attached, `UsageTracker` exists but stays empty.
    usage_tracker: Option<Arc<UsageTracker>>,
    /// Optional EU AI Act Art. 50(2) provenance signer. When set, every
    /// successful inference response is stamped with a signed
    /// `ProvenanceManifest` before it is returned. When unset (e.g. unit
    /// tests, dev-mode nodes that haven't generated a key yet), responses
    /// still carry `synthetic_content = true` but no manifest — downstream
    /// consumers can still tell the content is AI-generated, just not who
    /// signed for it.
    provenance_signer: Option<crate::provenance::SharedProvenanceSigner>,
    /// Optional provenance store. When both `provenance_signer` and
    /// `provenance_store` are set, freshly signed manifests are written
    /// into the store under their `content_hash` so the
    /// `tenzro_getProvenance(content_hash)` RPC can resolve them later.
    provenance_store: Option<Arc<crate::provenance::ProvenanceStore>>,
}

impl InferenceRouter {
    /// Creates a new inference router
    pub fn new(provider_manager: Arc<ProviderManager>) -> Self {
        let config = RoutingConfig::default();
        let timeout = Duration::from_millis(config.timeout_ms);
        Self {
            provider_manager,
            registry: None,
            circuit_breakers: Arc::new(dashmap::DashMap::new()),
            http_client: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .unwrap_or_default(),
            default_config: config,
            usage_tracker: None,
            provenance_signer: None,
            provenance_store: None,
        }
    }

    /// Creates a new router with custom default configuration
    pub fn with_config(provider_manager: Arc<ProviderManager>, config: RoutingConfig) -> Self {
        let timeout = Duration::from_millis(config.timeout_ms);
        Self {
            provider_manager,
            registry: None,
            circuit_breakers: Arc::new(dashmap::DashMap::new()),
            http_client: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .unwrap_or_default(),
            default_config: config,
            usage_tracker: None,
            provenance_signer: None,
            provenance_store: None,
        }
    }

    /// Attaches a `ModelRegistry` so the router can perform modality
    /// validation on typed `InferencePayload` requests. Returns `self`
    /// to support builder-style chaining at construction sites.
    #[must_use]
    pub fn with_registry(mut self, registry: Arc<ModelRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Attaches a `UsageTracker` so successful inferences are recorded
    /// as durable `UsageRecord`s. The tracker is the producer side of
    /// the per-model / per-provider / global usage stats consumed by
    /// `tenzro_listInferenceUsage` and the marketplace settlement
    /// reconciler.
    #[must_use]
    pub fn with_usage_tracker(mut self, tracker: Arc<UsageTracker>) -> Self {
        self.usage_tracker = Some(tracker);
        self
    }

    /// Attaches a [`ProvenanceSigner`] (typically [`Ed25519ProvenanceSigner`])
    /// so every successful inference response is stamped with a signed
    /// EU AI Act Art. 50(2) provenance manifest. Pair with
    /// [`with_provenance_store`] to make those manifests retrievable via
    /// `tenzro_getProvenance(content_hash)`.
    ///
    /// [`ProvenanceSigner`]: crate::provenance::ProvenanceSigner
    /// [`Ed25519ProvenanceSigner`]: crate::provenance::Ed25519ProvenanceSigner
    /// [`with_provenance_store`]: Self::with_provenance_store
    #[must_use]
    pub fn with_provenance_signer(
        mut self,
        signer: crate::provenance::SharedProvenanceSigner,
    ) -> Self {
        self.provenance_signer = Some(signer);
        self
    }

    /// Attaches a shared [`ProvenanceStore`] that the router writes every
    /// freshly signed manifest into. The same `Arc` should be handed to the
    /// `tenzro_getProvenance` RPC handler so the read and write paths share
    /// state.
    ///
    /// [`ProvenanceStore`]: crate::provenance::ProvenanceStore
    #[must_use]
    pub fn with_provenance_store(
        mut self,
        store: Arc<crate::provenance::ProvenanceStore>,
    ) -> Self {
        self.provenance_store = Some(store);
        self
    }

    /// Validates that `payload` targets a model whose registered
    /// modality supports the payload's modality. Returns
    /// `ModelError::ModalityMismatch` on mismatch.
    ///
    /// If no registry is attached, returns `Ok(())` (the router falls
    /// back to behavior identical to pre-Layer-7 nodes — payload is
    /// trusted to match the model). When a registry IS attached, an
    /// unknown model_id surfaces as `ModelError::ModelNotFound`.
    pub fn check_modality(&self, payload: &InferencePayload) -> Result<()> {
        let Some(registry) = &self.registry else {
            return Ok(());
        };
        let model = registry.get_model(payload.model_id())?;
        let want = payload.payload_modality();
        if !model.modality.supports(want) {
            return Err(ModelError::ModalityMismatch {
                model_id: payload.model_id().to_string(),
                model_modality: model.modality,
                payload_modality: want,
            });
        }
        Ok(())
    }

    /// Routes an inference request to the best available provider
    ///
    /// # Errors
    ///
    /// Returns `ModelError::NoProvidersAvailable` if no suitable providers are available.
    /// Returns `ModelError::RoutingError` if routing fails.
    pub fn route_request(&self, request: &InferenceRequest) -> Result<Address> {
        self.route_request_with_config(request, &self.default_config)
    }

    /// Routes an inference request with custom configuration
    ///
    /// # Errors
    ///
    /// Returns `ModelError::NoProvidersAvailable` if no suitable providers are available.
    pub fn route_request_with_config(
        &self,
        request: &InferenceRequest,
        config: &RoutingConfig,
    ) -> Result<Address> {
        // Apply time-based decay to provider metrics before routing decision
        // This ensures recent performance is weighted more heavily than historical data
        self.provider_manager.decay_metrics();

        // Get active providers for the model
        let mut providers = self
            .provider_manager
            .get_active_providers_for_model(&request.model_id);

        if providers.is_empty() {
            return Err(ModelError::NoProvidersAvailable(request.model_id.clone()));
        }

        // Filter by TEE requirement
        if config.require_tee {
            providers.retain(|p| p.has_tee);
            if providers.is_empty() {
                return Err(ModelError::NoProvidersAvailable(format!(
                    "{} (TEE required)",
                    request.model_id
                )));
            }
        }

        // Filter by price
        providers.retain(|p| {
            let provider_price = p.provider.pricing.minimum_price;
            provider_price <= request.max_price
        });

        if providers.is_empty() {
            return Err(ModelError::NoProvidersAvailable(format!(
                "{} (price constraint)",
                request.model_id
            )));
        }

        // Filter by capacity
        providers.retain(|p| p.provider.capacity.has_capacity());

        if providers.is_empty() {
            return Err(ModelError::NoProvidersAvailable(format!(
                "{} (no capacity)",
                request.model_id
            )));
        }

        // Filter by circuit breaker state
        providers.retain(|p| {
            self.circuit_breakers
                .entry(p.provider.address)
                .or_default()
                .is_request_allowed()
        });

        if providers.is_empty() {
            return Err(ModelError::NoProvidersAvailable(format!(
                "{} (circuit breakers open)",
                request.model_id
            )));
        }

        // Select provider based on strategy
        let selected = self.select_provider(providers, config)?;

        debug!(
            "Routed request {} to provider {}",
            request.request_id, selected
        );

        Ok(selected)
    }

    /// Selects the best provider based on the routing strategy
    fn select_provider(
        &self,
        mut providers: Vec<ProviderWithMetrics>,
        config: &RoutingConfig,
    ) -> Result<Address> {
        // Check preferred providers first
        if !config.preferred_providers.is_empty() {
            for preferred in &config.preferred_providers {
                if let Some(provider) = providers.iter().find(|p| &p.provider.address == preferred)
                {
                    return Ok(provider.provider.address);
                }
            }
        }

        // Select based on strategy
        match config.strategy {
            RoutingStrategy::LowestPrice => {
                providers.sort_by_key(|p| p.provider.pricing.minimum_price);
            }
            RoutingStrategy::LowestLatency => {
                providers.sort_by_key(|p| p.metrics.avg_latency_ms);
            }
            RoutingStrategy::HighestReputation => {
                providers.sort_by_key(|p| std::cmp::Reverse(p.provider.reputation));
            }
            RoutingStrategy::Random => {
                // Use OsRng (CSPRNG) for inference routing — prevents an attacker
                // from predicting which provider serves their request, which would
                // otherwise enable targeted side-channel and timing attacks.
                use rand::rngs::OsRng;
                use rand::seq::SliceRandom;
                providers.shuffle(&mut OsRng);
            }
            RoutingStrategy::WeightedScore => {
                providers.sort_by(|a, b| {
                    b.calculate_score()
                        .partial_cmp(&a.calculate_score())
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
            RoutingStrategy::ReasoningDepth => {
                // Cortex-style routing: provider ranking by reputation is a
                // reasonable proxy here because the provider-level routing
                // layer does not yet carry per-model Cortex metadata.
                // The Cortex worker crate performs a secondary filter on
                // `CortexModelFamily::max_loops` before accepting the
                // request.
                providers.sort_by_key(|p| std::cmp::Reverse(p.provider.reputation));
            }
        }

        providers
            .first()
            .map(|p| p.provider.address)
            .ok_or_else(|| ModelError::RoutingError("No provider selected".to_string()))
    }

    /// Forwards an inference request to the best available provider via HTTP.
    ///
    /// This method:
    /// 1. Selects the best provider using the configured routing strategy
    /// 2. POSTs the request to the provider's OpenAI-compatible `/chat/completions` endpoint
    /// 3. Records success/failure in the circuit breaker and provider metrics
    /// 4. On failure, retries with failover to alternative providers (up to `max_retries`)
    ///
    /// # Errors
    ///
    /// Returns `ModelError::NoProvidersAvailable` if no provider can be reached.
    /// Returns `ModelError::InferenceError` if the request fails after retries.
    pub async fn forward_request(&self, request: &InferenceRequest) -> Result<InferenceResponse> {
        self.forward_request_with_config(request, &self.default_config)
            .await
    }

    /// Forwards an inference request with custom routing configuration
    pub async fn forward_request_with_config(
        &self,
        request: &InferenceRequest,
        config: &RoutingConfig,
    ) -> Result<InferenceResponse> {
        let mut last_error = None;
        let mut excluded_providers: Vec<Address> = Vec::new();

        for attempt in 0..=config.max_retries {
            // Select provider (excluding previously failed ones)
            let provider_address = if attempt == 0 {
                self.route_request_with_config(request, config)?
            } else {
                // Get providers excluding failed ones
                let mut providers = self
                    .provider_manager
                    .get_active_providers_for_model(&request.model_id);
                providers.retain(|p| !excluded_providers.contains(&p.provider.address));

                if providers.is_empty() {
                    break;
                }

                self.select_provider(providers, config)?
            };

            // Get the provider's endpoint URL
            let provider = match self.provider_manager.get_provider(&provider_address) {
                Ok(p) => p,
                Err(_) => {
                    excluded_providers.push(provider_address);
                    continue;
                }
            };

            let endpoint_url = match &provider.endpoint_url {
                Some(url) => url.clone(),
                None => {
                    warn!(
                        "Provider {} has no endpoint URL, skipping",
                        provider_address
                    );
                    excluded_providers.push(provider_address);
                    continue;
                }
            };

            let chat_url = format!("{}/chat/completions", endpoint_url.trim_end_matches('/'));

            info!(
                "Forwarding inference request {} to provider {} at {} (attempt {})",
                request.request_id, provider_address, chat_url, attempt + 1
            );

            // Build OpenAI-compatible request body
            let input_text = String::from_utf8_lossy(&request.input);
            let temperature = request
                .parameters
                .temperature
                .map(|t| t as f64 / 100.0)
                .unwrap_or(0.7);
            let top_p = request
                .parameters
                .top_p
                .map(|t| t as f64 / 100.0);
            let max_tokens = request.parameters.max_tokens;

            let mut body = serde_json::json!({
                "model": request.model_id,
                "messages": [
                    { "role": "user", "content": input_text }
                ],
                "temperature": temperature,
                "stream": false,
            });

            if let Some(tp) = top_p {
                body["top_p"] = serde_json::json!(tp);
            }
            if let Some(mt) = max_tokens {
                body["max_tokens"] = serde_json::json!(mt);
            }

            // Pre-serialize the request body so we can record the exact
            // wire-level byte count consumed at the provider's HTTP boundary.
            // This is the `bytes_in` side of UsageRecord (from the provider's
            // perspective — bytes received from the consumer).
            let body_bytes = match serde_json::to_vec(&body) {
                Ok(b) => b,
                Err(e) => {
                    warn!(
                        "Failed to serialize inference request body: {}",
                        e
                    );
                    excluded_providers.push(provider_address);
                    continue;
                }
            };
            let bytes_in = body_bytes.len() as u64;

            // Send HTTP request
            let start = std::time::Instant::now();
            let result = self
                .http_client
                .post(&chat_url)
                .header("content-type", "application/json")
                .body(body_bytes)
                .send()
                .await;

            let elapsed_ms = start.elapsed().as_millis() as u64;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    // Record success in circuit breaker and provider metrics
                    self.record_provider_success(&provider_address);
                    self.provider_manager
                        .record_success(&provider_address, elapsed_ms);

                    // Read the raw response bytes first so we can record the
                    // wire-level `bytes_out` count, then parse the JSON.
                    let resp_bytes = resp.bytes().await.map_err(|e| {
                        ModelError::InferenceError(format!("Failed to read response body: {}", e))
                    })?;
                    let bytes_out = resp_bytes.len() as u64;

                    let resp_body: serde_json::Value =
                        serde_json::from_slice(&resp_bytes).map_err(|e| {
                            ModelError::InferenceError(format!("Failed to parse response: {}", e))
                        })?;

                    let output_text = resp_body["choices"]
                        .get(0)
                        .and_then(|c| c["message"]["content"].as_str())
                        .unwrap_or("")
                        .to_string();

                    let input_tokens = resp_body["usage"]["prompt_tokens"]
                        .as_u64()
                        .unwrap_or(0) as u32;
                    let output_tokens = resp_body["usage"]["completion_tokens"]
                        .as_u64()
                        .unwrap_or(0) as u32;
                    let finish_reason = resp_body["choices"]
                        .get(0)
                        .and_then(|c| c["finish_reason"].as_str())
                        .map(String::from);

                    // Calculate price
                    let price = (input_tokens as u64 * provider.pricing.price_per_input_token)
                        + (output_tokens as u64 * provider.pricing.price_per_output_token);
                    let price = price.max(provider.pricing.minimum_price);

                    let mut response = InferenceResponse::new(
                        request.request_id.clone(),
                        request.model_id.clone(),
                        provider_address,
                        output_text.into_bytes(),
                        price,
                    );
                    response.metadata = InferenceMetadata {
                        input_tokens,
                        output_tokens,
                        latency_ms: elapsed_ms,
                        model_version: resp_body["model"].as_str().map(String::from),
                        finish_reason,
                    };

                    info!(
                        "Inference request {} completed in {}ms ({} input, {} output tokens)",
                        request.request_id, elapsed_ms, input_tokens, output_tokens
                    );

                    // Record durable usage iff a tracker is attached. The
                    // tracker aggregates per-model / per-provider / global
                    // stats and persists them to RocksDB CF_MODELS, so this
                    // is the only producer call site for marketplace
                    // observability data.
                    if let Some(tracker) = &self.usage_tracker {
                        let record = UsageRecord::new(
                            request.model_id.clone(),
                            provider_address,
                            input_tokens,
                            output_tokens,
                            bytes_in,
                            bytes_out,
                            price,
                            elapsed_ms,
                        );
                        if let Err(e) = tracker.record_usage(record) {
                            warn!(
                                "Failed to record usage for request {}: {}",
                                request.request_id, e
                            );
                        }
                    }

                    // EU AI Act Art. 50(2): stamp the response with a signed
                    // provenance manifest before returning. Failure to sign
                    // is logged but non-fatal — the consumer still gets the
                    // `synthetic_content = true` disclosure flag, just no
                    // verifiable signature. This matches the behavior on
                    // dev-mode nodes that don't yet have a provenance key.
                    if let Some(signer) = &self.provenance_signer {
                        match signer.sign(
                            &response.model_id,
                            response.provider,
                            &response.output,
                            crate::provenance::ASSERTION_AI_GENERATED,
                        ) {
                            Ok(manifest) => {
                                if let Some(store) = &self.provenance_store {
                                    store.put(manifest.clone());
                                }
                                response.provenance = Some(manifest);
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to sign provenance manifest for request {}: {}",
                                    request.request_id, e
                                );
                            }
                        }
                    }

                    return Ok(response);
                }
                Ok(resp) => {
                    let status = resp.status();
                    let error_body = resp.text().await.unwrap_or_default();
                    warn!(
                        "Provider {} returned HTTP {}: {}",
                        provider_address, status, error_body
                    );
                    self.record_provider_failure(&provider_address);
                    self.provider_manager.record_call_failure(&provider_address);
                    excluded_providers.push(provider_address);
                    last_error = Some(ModelError::InferenceError(format!(
                        "Provider {} returned HTTP {}: {}",
                        provider_address, status, error_body
                    )));
                }
                Err(e) => {
                    warn!(
                        "Provider {} request failed: {}",
                        provider_address, e
                    );
                    self.record_provider_failure(&provider_address);
                    self.provider_manager.record_call_failure(&provider_address);
                    excluded_providers.push(provider_address);
                    last_error = Some(ModelError::InferenceError(format!(
                        "Provider {} unreachable: {}",
                        provider_address, e
                    )));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            ModelError::NoProvidersAvailable(format!(
                "{} (all providers failed after {} retries)",
                request.model_id, self.default_config.max_retries
            ))
        }))
    }

    /// Attempts to find an alternative provider for failover
    ///
    /// # Errors
    ///
    /// Returns `ModelError::NoProvidersAvailable` if no alternative is found.
    pub fn failover_to_next(
        &self,
        request: &InferenceRequest,
        failed_provider: &Address,
    ) -> Result<Address> {
        // Record failure in circuit breaker
        self.record_provider_failure(failed_provider);

        // Get providers excluding the failed one
        let mut providers = self
            .provider_manager
            .get_active_providers_for_model(&request.model_id);

        providers.retain(|p| &p.provider.address != failed_provider);

        if providers.is_empty() {
            return Err(ModelError::NoProvidersAvailable(format!(
                "{} (failover)",
                request.model_id
            )));
        }

        let selected = self.select_provider(providers, &self.default_config)?;

        warn!(
            "Failed over from {} to {} for request {}",
            failed_provider, selected, request.request_id
        );

        Ok(selected)
    }

    /// Records a provider failure in the circuit breaker
    pub fn record_provider_failure(&self, provider: &Address) {
        self.circuit_breakers
            .entry(*provider)
            .or_default()
            .record_failure();
    }

    /// Records a provider success in the circuit breaker
    pub fn record_provider_success(&self, provider: &Address) {
        self.circuit_breakers
            .entry(*provider)
            .or_default()
            .record_success();
    }

    /// Gets the circuit breaker state for a provider
    pub fn get_circuit_state(&self, provider: &Address) -> CircuitBreakerState {
        self.circuit_breakers
            .get(provider)
            .map(|entry| entry.state)
            .unwrap_or(CircuitBreakerState::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::model::ModelInfo;

    #[test]
    fn test_circuit_breaker() {
        let mut breaker = CircuitBreaker::new(3, 60_000);

        assert_eq!(breaker.state, CircuitBreakerState::Closed);
        assert!(breaker.is_request_allowed());

        // Record failures
        breaker.record_failure();
        breaker.record_failure();
        assert_eq!(breaker.state, CircuitBreakerState::Closed);

        breaker.record_failure();
        assert_eq!(breaker.state, CircuitBreakerState::Open);
        assert!(!breaker.is_request_allowed());

        // Record success should reset
        breaker.record_success();
        assert_eq!(breaker.state, CircuitBreakerState::Closed);
        assert!(breaker.is_request_allowed());
    }

    #[test]
    fn test_routing_config() {
        let config = RoutingConfig::new()
            .with_strategy(RoutingStrategy::LowestLatency)
            .with_tee_required(true);

        assert_eq!(config.strategy, RoutingStrategy::LowestLatency);
        assert!(config.require_tee);
    }

    #[test]
    fn payload_modality_maps_correctly() {
        let chat = InferencePayload::Chat(InferenceRequest::new(
            "model-text".to_string(),
            Address::zero(),
            vec![],
            0,
        ));
        assert_eq!(chat.payload_modality(), ModelModality::Text);
        assert_eq!(chat.model_id(), "model-text");

        let fc = InferencePayload::Forecast {
            model_id: "timesfm-2.5-200m".into(),
            context: vec![1.0, 2.0, 3.0],
            horizon: 12,
        };
        assert_eq!(fc.payload_modality(), ModelModality::Timeseries);
        assert_eq!(fc.model_id(), "timesfm-2.5-200m");

        let det = InferencePayload::Detect {
            model_id: "rf-detr-nano".into(),
            image_bytes: vec![],
            score_threshold: 0.5,
        };
        assert_eq!(det.payload_modality(), ModelModality::Image);

        let txt = InferencePayload::TextEmbed {
            model_id: "qwen3-embedding-0.6b".into(),
            texts: vec!["hello".into()],
            requested_dim: None,
        };
        // Text embeddings take text input → share the Text input modality
        // with chat. The variant disambiguates which runtime handles it.
        assert_eq!(txt.payload_modality(), ModelModality::Text);

        let vid = InferencePayload::VideoEmbed {
            model_id: "videomae-base".into(),
            video_bytes: vec![],
            normalize: true,
        };
        assert_eq!(vid.payload_modality(), ModelModality::Video);
    }

    #[test]
    fn check_modality_no_registry_passes() {
        let pm = Arc::new(ProviderManager::new());
        let router = InferenceRouter::new(pm);
        // No registry attached → check is a no-op (backward compat).
        let p = InferencePayload::Forecast {
            model_id: "anything".into(),
            context: vec![],
            horizon: 1,
        };
        assert!(router.check_modality(&p).is_ok());
    }

    #[test]
    fn check_modality_rejects_mismatch() {
        let pm = Arc::new(ProviderManager::new());
        let registry = Arc::new(ModelRegistry::new());

        // Register a Text model. `register_model` rejects a zero hash as
        // an integrity check, so seed a deterministic non-zero hash.
        let mut text_model = ModelInfo::new(
            "llm-1".into(),
            "Llama".into(),
            "1.0".into(),
            ModelModality::Text,
            Address::zero(),
        );
        text_model.parameters.context_window = 2048;
        text_model.model_hash = tenzro_types::primitives::Hash::from_bytes(&[1u8; 32]).unwrap();
        registry.register_model(text_model).unwrap();

        let router = InferenceRouter::new(pm).with_registry(registry);

        // Forecast payload sent to a Text model → ModalityMismatch.
        let bad = InferencePayload::Forecast {
            model_id: "llm-1".into(),
            context: vec![1.0; 32],
            horizon: 8,
        };
        let err = router.check_modality(&bad).unwrap_err();
        assert!(matches!(err, ModelError::ModalityMismatch { .. }), "got {err:?}");

        // Chat payload to the same model → OK.
        let good = InferencePayload::Chat(InferenceRequest::new(
            "llm-1".into(),
            Address::zero(),
            vec![],
            0,
        ));
        assert!(router.check_modality(&good).is_ok());
    }

    #[test]
    fn check_modality_unknown_model_returns_not_found() {
        let pm = Arc::new(ProviderManager::new());
        let registry = Arc::new(ModelRegistry::new());
        let router = InferenceRouter::new(pm).with_registry(registry);

        let p = InferencePayload::Chat(InferenceRequest::new(
            "missing".into(),
            Address::zero(),
            vec![],
            0,
        ));
        let err = router.check_modality(&p).unwrap_err();
        assert!(matches!(err, ModelError::ModelNotFound(_)), "got {err:?}");
    }

    #[test]
    fn payload_serializes_round_trip() {
        let p = InferencePayload::Forecast {
            model_id: "timesfm-2.5-200m".into(),
            context: vec![1.0, 2.0],
            horizon: 4,
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains("\"kind\":\"forecast\""));
        let _: InferencePayload = serde_json::from_str(&s).unwrap();
    }
}
