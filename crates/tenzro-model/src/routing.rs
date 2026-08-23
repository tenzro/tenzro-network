//! Inference request routing module
//!
//! This module handles intelligent routing of inference requests to the best
//! available provider based on various strategies and requirements.

use crate::{
    error::{ModelError, Result},
    pricing::PricingEngine,
    provider::{ProviderManager, ProviderWithMetrics},
    registry::ModelRegistry,
    usage::{UsageRecord, UsageTracker},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tenzro_types::{
    hardware::HardwareClass,
    model::{BillableUnits, InferenceMetadata, InferenceRequest, InferenceResponse, ModelModality},
    primitives::{Address, Timestamp},
};
use tracing::{debug, info, warn};

/// Strategy for routing inference requests
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
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
    /// SAM 3 text-promptable segmentation: image + text label (+ optional
    /// box) → detection-shaped (bbox, score, mask) triples.
    TextSegment {
        model_id: String,
        image_bytes: Vec<u8>,
        /// Serialized `TextSegmentConfig` — decoded by the
        /// text-segmentation runtime.
        config_json: String,
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
            | Self::TextSegment { model_id, .. }
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
            | Self::TextSegment { .. }
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
    /// Per-HTTP-call timeout in milliseconds. Bounds a single dispatch to
    /// one provider; it does NOT bound the whole request, which may retry
    /// across several providers — see `request_deadline_ms`.
    pub timeout_ms: u64,
    /// Wall-clock deadline for the entire request, in milliseconds,
    /// spanning provider selection plus every retry. Without it a request
    /// that keeps hitting slow-but-not-dead providers can silently consume
    /// `(max_retries + 1) × timeout_ms` of wall time (e.g. 4 × 120 s = 8
    /// min) before surfacing a failure — unacceptable for interactive
    /// inference. The router checks the elapsed budget before each attempt
    /// and stops retrying once it is exhausted ("The Tail at Scale", Dean &
    /// Barroso 2013: bound the tail explicitly rather than let retries
    /// compound it). `0` disables the deadline (retry budget governed only
    /// by `max_retries` × `timeout_ms`).
    pub request_deadline_ms: u64,
    /// Require TEE provider
    pub require_tee: bool,
    /// Require a provider-signed inference response. When true, routing
    /// is restricted to providers with a registered signing key and the
    /// response manifest is verified against that key — a missing or
    /// invalid manifest counts as a provider failure. When false
    /// (default), unsigned providers are fully routable and any attached
    /// manifest is verified best-effort only.
    pub require_signed_response: bool,
    /// Preferred providers (will be tried first if available)
    pub preferred_providers: Vec<Address>,
    /// Enable hedged request dispatch ("The Tail at Scale", Dean & Barroso
    /// 2013). When true, the router races a second identical request to
    /// the next-best provider once `hedge_delay` elapses without a reply
    /// from the primary, returns whichever finishes first, and drops the
    /// loser. Only the winner is billed and reputation-credited. Capped at
    /// one hedge per request. Inference is stateless (no side effects), so
    /// the only cost of a duplicate is the loser's wasted compute, which
    /// the abort bounds.
    pub enable_hedging: bool,
    /// Lower bound on the hedge delay in milliseconds. The delay is
    /// derived from the primary provider's tracked average latency; this
    /// floor keeps a fast provider from being hedged so aggressively that
    /// every request doubles.
    pub hedge_delay_floor_ms: u64,
    /// Upper bound on the hedge delay in milliseconds. Caps how long the
    /// router waits on a slow-but-not-dead primary before racing a hedge.
    pub hedge_delay_ceiling_ms: u64,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            strategy: RoutingStrategy::WeightedScore,
            max_retries: 3,
            timeout_ms: 120_000,
            request_deadline_ms: 180_000,
            require_tee: false,
            require_signed_response: false,
            preferred_providers: Vec::new(),
            enable_hedging: true,
            hedge_delay_floor_ms: 40,
            hedge_delay_ceiling_ms: 500,
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

    /// Sets the signed-response requirement
    pub fn with_signed_response_required(mut self, required: bool) -> Self {
        self.require_signed_response = required;
        self
    }

    /// Sets the per-HTTP-call timeout in milliseconds
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Sets the whole-request wall-clock deadline in milliseconds spanning
    /// every retry. `0` disables it.
    pub fn with_request_deadline_ms(mut self, deadline_ms: u64) -> Self {
        self.request_deadline_ms = deadline_ms;
        self
    }

    /// Adds a preferred provider
    pub fn add_preferred_provider(mut self, provider: Address) -> Self {
        self.preferred_providers.push(provider);
        self
    }

    /// Enables or disables hedged request dispatch.
    pub fn with_hedging(mut self, enabled: bool) -> Self {
        self.enable_hedging = enabled;
        self
    }

    /// Sets the hedge-delay floor and ceiling in milliseconds.
    pub fn with_hedge_delay_bounds(mut self, floor_ms: u64, ceiling_ms: u64) -> Self {
        self.hedge_delay_floor_ms = floor_ms;
        self.hedge_delay_ceiling_ms = ceiling_ms.max(floor_ms);
        self
    }

    /// Computes the hedge delay for a primary provider whose observed
    /// tail latency is `tail_latency_ms` (the P² p95 estimate, or the mean
    /// during warm-up). A cold provider (no latency history, `0`) hedges at
    /// the midpoint of the configured bounds; a warm provider hedges at its
    /// own tail, clamped to `[floor, ceiling]`. Racing at the p95 fires a
    /// backup only when the primary has genuinely landed in its slow tail,
    /// which keeps hedge volume proportional to real stragglers instead of
    /// firing on every request slower than average.
    fn hedge_delay_ms(&self, tail_latency_ms: u64) -> u64 {
        let floor = self.hedge_delay_floor_ms;
        let ceiling = self.hedge_delay_ceiling_ms.max(floor);
        if tail_latency_ms == 0 {
            return floor + (ceiling - floor) / 2;
        }
        tail_latency_ms.clamp(floor, ceiling)
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

/// Counters for hedged-dispatch observability. Exposed as a snapshot via
/// [`InferenceRouter::metrics`] and surfaced through the node's inference
/// metrics RPC.
#[derive(Debug, Default)]
pub struct RouterMetrics {
    /// Total inference requests routed through the hedge-aware dispatch path.
    requests: AtomicU64,
    /// Number of requests for which a hedge was actually dispatched (the
    /// primary did not reply before the hedge delay elapsed).
    hedges_dispatched: AtomicU64,
    /// Number of requests where the hedge finished first and its result
    /// was returned. `hedges_won <= hedges_dispatched`.
    hedges_won: AtomicU64,
    /// Number of requests abandoned because the whole-request wall-clock
    /// deadline was exhausted before a provider succeeded.
    deadline_exceeded: AtomicU64,
}

/// Point-in-time copy of [`RouterMetrics`] counters.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RouterMetricsSnapshot {
    /// Total requests routed.
    pub requests: u64,
    /// Requests where a hedge was dispatched.
    pub hedges_dispatched: u64,
    /// Requests where the hedge won the race.
    pub hedges_won: u64,
    /// Requests abandoned on the whole-request wall-clock deadline.
    pub deadline_exceeded: u64,
}

/// Outcome of a single-provider dispatch that did not succeed.
enum DispatchFailure {
    /// The provider failed in a way that warrants excluding it and trying
    /// another (unreachable, non-2xx, missing signed manifest). Carries the
    /// provider address so the caller can add it to the exclusion set.
    Retryable {
        provider: Address,
        error: ModelError,
    },
    /// Both legs of a hedged race failed. Carries each leg's underlying
    /// error (if any) for diagnostics.
    Both {
        primary: Option<ModelError>,
        hedge: Option<ModelError>,
    },
    /// An unrecoverable error (e.g. the response body could not be read or
    /// parsed). Propagated straight to the caller — retrying won't help.
    Fatal(ModelError),
}

impl DispatchFailure {
    /// Projects the failure to its representative error, discarding the
    /// provider address. Used when folding a hedge race down to a single
    /// `last_error`.
    fn into_error(self) -> Option<ModelError> {
        match self {
            DispatchFailure::Retryable { error, .. } => Some(error),
            DispatchFailure::Both { primary, hedge } => hedge.or(primary),
            DispatchFailure::Fatal(e) => Some(e),
        }
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
    /// `ContentProvenanceManifest` before it is returned. When unset (e.g. unit
    /// tests, dev-mode nodes that haven't generated a key yet), responses
    /// still carry `synthetic_content = true` but no manifest — downstream
    /// consumers can still tell the content is AI-generated, just not who
    /// signed for it.
    provenance_signer: Option<crate::provenance::SharedProvenanceSigner>,
    /// Optional provenance store. When both `provenance_signer` and
    /// `provenance_store` are set, freshly signed manifests are written
    /// into the store under their `content_hash` so the
    /// `tenzro_getContentProvenance(content_hash)` RPC can resolve them later.
    provenance_store: Option<Arc<crate::provenance::ProvenanceStore>>,
    /// Prices every routed call under the model its provider declared, and
    /// accumulates the resulting prices as the market history that
    /// [`PricingModel::Dynamic`] scales against. The router is the only
    /// component that observes every settled price for every model, so it is
    /// where that history can be built.
    pricing: Arc<PricingEngine>,
    /// Hedged-dispatch counters.
    metrics: RouterMetrics,
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
            pricing: Arc::new(PricingEngine::new()),
            metrics: RouterMetrics::default(),
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
            pricing: Arc::new(PricingEngine::new()),
            metrics: RouterMetrics::default(),
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
    /// `tenzro_getContentProvenance(content_hash)`.
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
    /// `tenzro_getContentProvenance` RPC handler so the read and write paths share
    /// state.
    ///
    /// [`ProvenanceStore`]: crate::provenance::ProvenanceStore
    #[must_use]
    pub fn with_provenance_store(mut self, store: Arc<crate::provenance::ProvenanceStore>) -> Self {
        self.provenance_store = Some(store);
        self
    }

    /// Returns a point-in-time snapshot of the router's hedged-dispatch
    /// counters.
    pub fn metrics(&self) -> RouterMetricsSnapshot {
        RouterMetricsSnapshot {
            requests: self.metrics.requests.load(Ordering::Relaxed),
            hedges_dispatched: self.metrics.hedges_dispatched.load(Ordering::Relaxed),
            hedges_won: self.metrics.hedges_won.load(Ordering::Relaxed),
            deadline_exceeded: self.metrics.deadline_exceeded.load(Ordering::Relaxed),
        }
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

        // Filter by signed-response requirement — only providers with a
        // registered signing key can satisfy a verified response.
        if config.require_signed_response {
            providers.retain(|p| p.provider.signing_pubkey.is_some());
            if providers.is_empty() {
                return Err(ModelError::NoProvidersAvailable(format!(
                    "{} (signed response required)",
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

        // Hardware floor — when the caller pins a minimum hardware class
        // (via `parameters.custom["min_hardware"]`, same non-churning
        // mechanism as `draft_n`), drop providers whose advertised class
        // does not meet it. Undeclared (`Unknown`) providers never satisfy
        // an explicit floor: a request that sets one is deliberately
        // opting out of providers that haven't declared their hardware.
        // Absent the hint, no filter is applied and every class competes
        // on score — advertised hardware only biases ranking, it does not
        // exclude, unless the caller explicitly asks it to.
        if let Some(required) = request
            .parameters
            .custom
            .get("min_hardware")
            .and_then(|v| HardwareClass::parse_hint(v))
        {
            providers.retain(|p| p.provider.capacity.hardware.class().satisfies(required));
            if providers.is_empty() {
                return Err(ModelError::NoProvidersAvailable(format!(
                    "{} (hardware floor {:?})",
                    request.model_id, required
                )));
            }
        }

        // Jurisdiction pin — when the caller pins serving jurisdictions
        // (via `parameters.custom["jurisdiction"]`, a comma-separated list
        // of ISO 3166-1 alpha-2 country codes and/or bloc tokens like
        // `EU`, matched case-insensitively), keep only providers whose
        // declared `JurisdictionClaim` satisfies at least one token.
        // Fail-closed, like the hardware floor and unlike the MTP filter:
        // data sovereignty is a hard constraint, so a pin that no declared
        // provider satisfies fails the request rather than silently
        // routing outside the requested jurisdiction. Providers with no
        // declared claim never satisfy a pin.
        if let Some(pin) = request.parameters.custom.get("jurisdiction") {
            let tokens: Vec<&str> = pin
                .split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .collect();
            if !tokens.is_empty() {
                providers.retain(|p| {
                    p.provider
                        .capacity
                        .jurisdiction
                        .as_ref()
                        .is_some_and(|claim| claim.matches_any(tokens.iter().copied()))
                });
                if providers.is_empty() {
                    return Err(ModelError::NoProvidersAvailable(format!(
                        "{} (jurisdiction pin {})",
                        request.model_id,
                        tokens.join(",")
                    )));
                }
            }
        }

        // Memory-fit admission — when the registry knows the model's
        // resident artifact size, drop providers whose *detected* memory
        // envelope (RAM + VRAM, or the unified pool on Apple Silicon)
        // cannot hold the weights at all. `can_hold_model` returns `None`
        // for providers that never ran hardware detection and for models
        // with no declared size, so absent claims are never filtered on —
        // undeclared providers keep competing per the trust-advertised
        // model, and the serving runtime's local free-memory admission
        // remains the final gate at load time.
        if let Some(registry) = &self.registry
            && let Ok(model) = registry.get_model(&request.model_id)
            && model.size_bytes > 0
        {
            let model_gb = model.size_bytes as f32 / 1_073_741_824.0;
            providers
                .retain(|p| p.provider.capacity.hardware.can_hold_model(model_gb) != Some(false));
            if providers.is_empty() {
                return Err(ModelError::NoProvidersAvailable(format!(
                    "{} (memory fit: {:.1} GiB model exceeds every detected provider envelope)",
                    request.model_id, model_gb
                )));
            }
        }

        // MTP filter — when the caller asked for speculative decoding
        // (Multi-Token Prediction), prefer providers that advertise an
        // MTP-capable runtime (`ProviderCapacity.mtp_enabled = true`).
        //
        // The `draft_n` hint rides on `InferenceParameters.custom` so
        // we don't churn the serialized request shape. Tenzro chat
        // RPC + SDKs already mirror their own `draft_n` field into
        // this slot.
        //
        // Strategy: hard-filter when at least one MTP-capable provider
        // exists; if none do, fall back to the existing pool rather
        // than failing the request — the runtime will return a clean
        // MtpUnavailable error so the caller can degrade.
        let wants_mtp = request
            .parameters
            .custom
            .get("draft_n")
            .and_then(|v| v.parse::<u8>().ok())
            .filter(|n| (1..=6).contains(n))
            .is_some();
        if wants_mtp {
            let mtp_providers: Vec<_> = providers
                .iter()
                .filter(|p| p.provider.capacity.mtp_enabled)
                .cloned()
                .collect();
            if !mtp_providers.is_empty() {
                providers = mtp_providers;
            }
        }

        // Verifiable-inference filter — when the caller asked for a TOPLOC
        // commitment (`verifiable: true` on `InferenceParameters.custom`),
        // prefer providers whose advertised capacity carries
        // `verifiable_inference = true` (the flag is set automatically for
        // AI-serving nodes at announcement time). Same semantics as the MTP
        // filter above: hard-filter when at least one capable provider
        // exists, otherwise keep the full pool — a non-capable provider
        // returns `commitment: None` and the caller can degrade.
        let wants_verifiable = request
            .parameters
            .custom
            .get("verifiable")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        if wants_verifiable {
            let verifiable_providers: Vec<_> = providers
                .iter()
                .filter(|p| p.provider.capacity.verifiable_inference)
                .cloned()
                .collect();
            if !verifiable_providers.is_empty() {
                providers = verifiable_providers;
            }
        }

        // Prefix-affinity ordering — bias selection toward the provider whose
        // advertised warm KV-cache prefix best matches this prompt. A warm
        // prefix lets the provider skip re-prefilling those bytes, so the
        // request's time-to-first-token drops. The incoming prompt is hashed
        // under the shared rolling scheme (`prefix_run_hashes`) and each
        // provider is scored by its longest warm-prefix match against it
        // (`PrefixCacheSummary::longest_match_len`). This is a soft bias, not
        // a filter: a provider with no advertised prefix (or no match) still
        // competes on the strategy score below — the prefix term only breaks
        // ties in favor of a warm provider and floats a strongly-matching
        // provider up the WeightedScore ranking.
        let prompt_run_hashes = tenzro_types::prefix_run_hashes(&request.input);

        // Select provider based on strategy
        let selected = self.select_provider(providers, config, &prompt_run_hashes)?;

        debug!(
            "Routed request {} to provider {}",
            request.request_id, selected
        );

        Ok(selected)
    }

    /// Selects the best provider based on the routing strategy.
    ///
    /// `prompt_run_hashes` is the incoming prompt hashed under the shared
    /// rolling scheme; it drives the prefix-affinity bias applied on top of
    /// the `WeightedScore` strategy (and as the final tie-break on every
    /// strategy). Pass an empty slice when the prompt is unavailable — the
    /// bias then contributes nothing.
    fn select_provider(
        &self,
        mut providers: Vec<ProviderWithMetrics>,
        config: &RoutingConfig,
        prompt_run_hashes: &[u64],
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
                // Steer on the observed p95 tail, falling back to the mean
                // until the estimator warms up. A provider with a low mean
                // but a heavy tail delivers worse user-perceived latency
                // than one whose tail is tight, so the tail is the right
                // sort key for "lowest latency".
                providers.sort_by_key(|p| {
                    p.metrics
                        .latency_p95_ms()
                        .unwrap_or(p.metrics.avg_latency_ms)
                });
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
                // Fold the prefix-affinity bias into the composite score: a
                // provider whose warm prefix matches more of this prompt gets
                // a bounded bonus on top of its observed-quality score, so a
                // strong warm-prefix match can float a provider up the ranking
                // without ever overriding a provider that is materially better
                // on success rate / latency / reputation. `prefix_bias` is 0
                // when the prompt or the provider's advertised prefix is
                // empty, so this reduces to the plain score in that case.
                providers.sort_by(|a, b| {
                    let sa = a.calculate_score()
                        + Self::prefix_bias(a, prompt_run_hashes)
                        + Self::speculation_bias(a);
                    let sb = b.calculate_score()
                        + Self::prefix_bias(b, prompt_run_hashes)
                        + Self::speculation_bias(b);
                    sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
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

        // Capability tie-break: among the providers the strategy ranks
        // effectively equal at the top, prefer the one holding the longest
        // warm prefix for this prompt and, failing that, the one that can
        // decode speculatively. This applies to every strategy (not just
        // WeightedScore) but only ever reorders providers the strategy
        // already considers interchangeable, so it never overrides a
        // strategy's primary ordering (e.g. LowestPrice still wins on price).
        //
        // Both preferences are automatic — no caller flag, no operator
        // config. A warm prefix saves a whole prefill and a co-located
        // drafter is worth roughly 1.7-2x on decode at the low concurrency a
        // provider network actually runs at, so a caller who did not ask for
        // it still gets it when it is free.
        //
        // Only the warm prefix is decided here. Speculation is applied as
        // `speculation_bias` inside the `WeightedScore` sort instead, because
        // `leading_tie_group_len` returns 1 for that strategy and
        // `InferenceRouter::new` builds it unconditionally — a speculation
        // preference expressed in this block would be unreachable in the
        // shipping binary while looking entirely live.
        if providers.len() > 1 {
            let tie_len = Self::leading_tie_group_len(&providers, config);
            if tie_len > 1
                && let Some(pos) = (0..tie_len).max_by_key(|&i| {
                    let cap = &providers[i].provider.capacity;
                    let warm = if prompt_run_hashes.is_empty() {
                        0
                    } else {
                        cap.prefix_cache.longest_match_len(prompt_run_hashes)
                    };
                    // `Reverse(i)` keeps the first best on equal keys, so a
                    // group with nothing to distinguish it stays exactly as
                    // the strategy scored it.
                    (warm, std::cmp::Reverse(i))
                })
                && pos != 0
            {
                providers.swap(0, pos);
            }
        }

        providers
            .first()
            .map(|p| p.provider.address)
            .ok_or_else(|| ModelError::RoutingError("No provider selected".to_string()))
    }

    /// Bounded prefix-affinity bonus (in the same 0-100 scale as
    /// [`ProviderWithMetrics::calculate_score`]) for `provider` given the
    /// incoming prompt's rolling run hashes. Scales the fraction of the prompt
    /// covered by the provider's longest advertised warm prefix by a fixed
    /// ceiling, so a full warm-prefix hit adds at most that ceiling and a
    /// partial hit adds proportionally less. Returns 0 when the prompt or the
    /// advertised prefix is empty.
    fn prefix_bias(provider: &ProviderWithMetrics, prompt_run_hashes: &[u64]) -> f64 {
        // Ceiling kept below the hardware component (10.0) so prefix affinity
        // biases ranking without dominating observed quality.
        const PREFIX_BIAS_CEILING: f64 = 8.0;
        if prompt_run_hashes.is_empty() {
            return 0.0;
        }
        let matched = provider
            .provider
            .capacity
            .prefix_cache
            .longest_match_len(prompt_run_hashes) as f64;
        if matched <= 0.0 {
            return 0.0;
        }
        let prompt_bytes = (prompt_run_hashes.len() * tenzro_types::PREFIX_RUN_BYTES) as f64;
        let fraction = (matched / prompt_bytes).min(1.0);
        fraction * PREFIX_BIAS_CEILING
    }

    /// Bounded bonus for a provider that can decode speculatively *and* is
    /// idle enough for it to pay, on the same 0-100 scale as
    /// [`ProviderWithMetrics::calculate_score`].
    ///
    /// This lives in the score rather than in a tie-break because
    /// `leading_tie_group_len` returns 1 for `WeightedScore`, and
    /// `InferenceRouter::new` builds `WeightedScore` unconditionally — a
    /// tie-break here would be unreachable in the shipping binary. Folding it
    /// into the sort is what makes the preference actually run, and mirrors
    /// how `prefix_bias` is applied.
    ///
    /// The ceiling sits below `PREFIX_BIAS_CEILING` because a warm prefix
    /// saves a whole prefill while speculation only accelerates decode, and
    /// the decode win is the less certain of the two: measured acceptance
    /// varies by prompt, and a config accepting 4.64 tokens per step has been
    /// measured running at 0.67x of plain decoding once the provider is
    /// batching. `idle_enough` is what keeps this on the winning side of that
    /// inversion, so the bonus is zero for a busy provider rather than merely
    /// smaller.
    fn speculation_bias(provider: &ProviderWithMetrics) -> f64 {
        const SPECULATION_BIAS_CEILING: f64 = 4.0;
        let cap = &provider.provider.capacity;
        if cap.mtp_enabled && crate::meta_router::idle_enough(
            cap.active_requests,
            cap.max_concurrent_requests,
        ) {
            SPECULATION_BIAS_CEILING
        } else {
            0.0
        }
    }

    /// Number of leading providers the active strategy ranks equal to the
    /// first, i.e. the tie-group the prefix tie-break may reorder within.
    /// Conservative: for score/latency/price/reputation strategies it counts
    /// exact key equality with the head; for `Random` the whole list is a tie
    /// group (the shuffle already made order arbitrary).
    fn leading_tie_group_len(providers: &[ProviderWithMetrics], config: &RoutingConfig) -> usize {
        if providers.is_empty() {
            return 0;
        }
        match config.strategy {
            RoutingStrategy::Random => providers.len(),
            RoutingStrategy::LowestPrice => {
                let head = providers[0].provider.pricing.minimum_price;
                providers
                    .iter()
                    .take_while(|p| p.provider.pricing.minimum_price == head)
                    .count()
            }
            RoutingStrategy::LowestLatency => {
                let head = providers[0]
                    .metrics
                    .latency_p95_ms()
                    .unwrap_or(providers[0].metrics.avg_latency_ms);
                providers
                    .iter()
                    .take_while(|p| {
                        p.metrics
                            .latency_p95_ms()
                            .unwrap_or(p.metrics.avg_latency_ms)
                            == head
                    })
                    .count()
            }
            RoutingStrategy::HighestReputation | RoutingStrategy::ReasoningDepth => {
                let head = providers[0].provider.reputation;
                providers
                    .iter()
                    .take_while(|p| p.provider.reputation == head)
                    .count()
            }
            RoutingStrategy::WeightedScore => {
                // WeightedScore already folded the prefix bias into its sort,
                // so no separate tie-break group is needed here.
                1
            }
        }
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

    /// Returns the router's default routing configuration. Callers that
    /// need per-request overrides (e.g. `require_signed_response`) clone
    /// this and pass the result to `forward_request_with_config`.
    pub fn default_config(&self) -> &RoutingConfig {
        &self.default_config
    }

    /// Forwards an inference request with custom routing configuration.
    ///
    /// On the first attempt the router optionally hedges: it dispatches
    /// the request to the primary provider and, if the primary has not
    /// replied within a latency-derived hedge delay, races an identical
    /// request to the next-best provider. The first success wins and the
    /// loser is dropped (its future is cancelled). Only the winner runs
    /// its billing / reputation / usage side-effects. Inference is
    /// stateless, so a hedge never mutates shared state — the cost of a
    /// duplicate is bounded by the cancelled loser's wasted compute.
    ///
    /// Subsequent attempts (after a provider failure) fall back to plain
    /// sequential failover with no hedging, since the whole point of a
    /// retry is that the previous provider is already known-bad.
    pub async fn forward_request_with_config(
        &self,
        request: &InferenceRequest,
        config: &RoutingConfig,
    ) -> Result<InferenceResponse> {
        self.metrics.requests.fetch_add(1, Ordering::Relaxed);

        let mut last_error = None;
        let mut excluded_providers: Vec<Address> = Vec::new();

        let request_start = std::time::Instant::now();
        let deadline = (config.request_deadline_ms > 0)
            .then(|| Duration::from_millis(config.request_deadline_ms));

        for attempt in 0..=config.max_retries {
            // Whole-request wall-clock budget: stop retrying once the
            // deadline is exhausted so a request never silently consumes
            // (max_retries + 1) × timeout_ms. The first attempt (attempt 0)
            // always runs — a deadline shorter than a single dispatch is a
            // misconfiguration, not a reason to reject before trying.
            if attempt > 0
                && let Some(deadline) = deadline
                && request_start.elapsed() >= deadline
            {
                self.metrics
                    .deadline_exceeded
                    .fetch_add(1, Ordering::Relaxed);
                last_error = Some(last_error.take().unwrap_or_else(|| {
                    ModelError::InferenceError(format!(
                        "request deadline of {}ms exceeded after {} attempt(s)",
                        config.request_deadline_ms, attempt
                    ))
                }));
                break;
            }

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

                // On failover the replacement provider still benefits from a
                // warm prefix — it may already hold the shared prompt prefix,
                // cutting the re-prefill cost of resuming the request.
                let prompt_run_hashes = tenzro_types::prefix_run_hashes(&request.input);
                self.select_provider(providers, config, &prompt_run_hashes)?
            };

            // First attempt only: try to line up a hedge target. The hedge
            // is the next-best provider that (a) isn't the primary,
            // (b) isn't already excluded, (c) passes its circuit breaker,
            // and (d) has a usable endpoint. `hedge_eligible` also gates on
            // the request being hedgeable (idempotent) — see
            // `is_request_hedgeable`.
            let hedge_address =
                if attempt == 0 && config.enable_hedging && self.is_request_hedgeable(request) {
                    self.pick_hedge_target(request, config, provider_address)
                } else {
                    None
                };

            match hedge_address {
                Some(hedge_address) => {
                    // Hedge at the primary's observed p95 tail, not its
                    // mean: a still-pending request past the p95 is a
                    // genuine tail case worth racing. Before the estimator
                    // warms up, fall back to the mean.
                    let primary_tail_ms = self
                        .provider_manager
                        .get_metrics(&provider_address)
                        .ok()
                        .and_then(|m| {
                            m.latency_p95_ms()
                                .or_else(|| (m.avg_latency_ms > 0).then_some(m.avg_latency_ms))
                        })
                        .unwrap_or(0);
                    let delay = Duration::from_millis(config.hedge_delay_ms(primary_tail_ms));

                    match self
                        .dispatch_hedged(request, config, provider_address, hedge_address, delay)
                        .await
                    {
                        Ok(response) => return Ok(response),
                        Err(DispatchFailure::Retryable { provider, error }) => {
                            excluded_providers.push(provider);
                            last_error = Some(error);
                        }
                        Err(DispatchFailure::Both { primary, hedge }) => {
                            excluded_providers.push(provider_address);
                            excluded_providers.push(hedge_address);
                            last_error = Some(hedge.or(primary).unwrap_or_else(|| {
                                ModelError::InferenceError(
                                    "hedged dispatch failed with no error".to_string(),
                                )
                            }));
                        }
                        Err(DispatchFailure::Fatal(e)) => return Err(e),
                    }
                    continue;
                }
                None => {
                    match self
                        .dispatch_to_provider(request, config, provider_address)
                        .await
                    {
                        Ok(response) => return Ok(response),
                        Err(DispatchFailure::Retryable { provider, error }) => {
                            excluded_providers.push(provider);
                            last_error = Some(error);
                        }
                        Err(DispatchFailure::Both { primary, hedge }) => {
                            excluded_providers.push(provider_address);
                            last_error = hedge.or(primary);
                        }
                        Err(DispatchFailure::Fatal(e)) => return Err(e),
                    }
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

    /// True when a request may be safely hedged. Inference through this
    /// router is stateless (no side effects at the provider), so the only
    /// reason to suppress a hedge is an explicit caller opt-out via the
    /// `no_hedge` custom hint — used when the caller has some external,
    /// non-idempotent binding (e.g. a metered upstream that charges on
    /// receipt regardless of whether the router keeps the result).
    fn is_request_hedgeable(&self, request: &InferenceRequest) -> bool {
        !request
            .parameters
            .custom
            .get("no_hedge")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    /// Picks a hedge target: the best provider for the model, excluding the
    /// primary, that passes its circuit breaker and price/capacity filters.
    /// Returns `None` when no distinct healthy alternative exists.
    fn pick_hedge_target(
        &self,
        request: &InferenceRequest,
        config: &RoutingConfig,
        primary: Address,
    ) -> Option<Address> {
        let mut providers = self
            .provider_manager
            .get_active_providers_for_model(&request.model_id);
        providers.retain(|p| p.provider.address != primary);
        if config.require_tee {
            providers.retain(|p| p.has_tee);
        }
        if config.require_signed_response {
            providers.retain(|p| p.provider.signing_pubkey.is_some());
        }
        providers.retain(|p| p.provider.pricing.minimum_price <= request.max_price);
        providers.retain(|p| p.provider.capacity.has_capacity());
        // A hedge is a duplicate request, so it is only free when the fleet
        // has headroom to absorb it. `has_capacity()` only means "not
        // completely full", which is far too late: measured replica-selection
        // work finds duplication *inverts* well before saturation — C3 saw
        // speculative retries 5x worse at p99 under load, Rein 2x worse tail
        // above 55% utilisation, and Vulimiri et al. put the safe ceiling
        // nearer 30%. Past that point the extra load is itself what lengthens
        // the tail the hedge was meant to shorten.
        //
        // Requiring the *target* to be below half its declared ceiling keeps
        // hedging in the regime where Dean & Barroso measured it winning
        // (24x at p99.9 for ~2% extra requests) and switches it off exactly
        // when it would start costing. Providers that declare no ceiling are
        // excluded rather than assumed idle, for the same reason
        // `speculation_pays` excludes them: an absent value is unknown, and
        // unknown must not be the most attractive state to advertise.
        providers.retain(|p| {
            crate::meta_router::idle_enough(
                p.provider.capacity.active_requests,
                p.provider.capacity.max_concurrent_requests,
            )
        });
        // Respect circuit breakers: a quarantined (Open) provider must never
        // be a hedge target.
        providers.retain(|p| {
            self.circuit_breakers
                .entry(p.provider.address)
                .or_default()
                .is_request_allowed()
        });
        if providers.is_empty() {
            return None;
        }
        let prompt_run_hashes = tenzro_types::prefix_run_hashes(&request.input);
        self.select_provider(providers, config, &prompt_run_hashes)
            .ok()
    }

    /// Races a primary dispatch against a hedge dispatch. The primary
    /// starts immediately; the hedge starts only after `delay` elapses
    /// without the primary finishing. Returns the first success and drops
    /// the loser. A hedge counts in metrics only when it is actually
    /// dispatched (the primary was still pending at `delay`).
    async fn dispatch_hedged(
        &self,
        request: &InferenceRequest,
        config: &RoutingConfig,
        primary: Address,
        hedge: Address,
        delay: Duration,
    ) -> std::result::Result<InferenceResponse, DispatchFailure> {
        let primary_fut = self.dispatch_to_provider(request, config, primary);
        tokio::pin!(primary_fut);

        // Phase 1: wait for the primary, but no longer than `delay`. If it
        // finishes first (success or Retryable failure), we may skip the
        // hedge entirely.
        let primary_early = tokio::select! {
            biased;
            result = &mut primary_fut => Some(result),
            _ = tokio::time::sleep(delay) => None,
        };

        match primary_early {
            // Primary succeeded before the hedge delay — no hedge dispatched.
            Some(Ok(response)) => return Ok(response),
            // Primary failed before the hedge delay. Fall straight through
            // to the hedge without waiting the rest of `delay` — the tail we
            // were protecting against already materialised as an outright
            // failure.
            Some(Err(DispatchFailure::Fatal(e))) => return Err(DispatchFailure::Fatal(e)),
            Some(Err(primary_err)) => {
                let primary_error = primary_err.into_error();
                return match self.dispatch_to_provider(request, config, hedge).await {
                    Ok(response) => Ok(response),
                    Err(DispatchFailure::Fatal(e)) => Err(DispatchFailure::Fatal(e)),
                    Err(hedge_err) => Err(DispatchFailure::Both {
                        primary: primary_error,
                        hedge: hedge_err.into_error(),
                    }),
                };
            }
            // Primary still pending at `delay` — dispatch the hedge and race.
            None => {}
        }

        self.metrics
            .hedges_dispatched
            .fetch_add(1, Ordering::Relaxed);
        info!(
            "Hedging request {} to {} after {}ms (primary {} still pending)",
            request.request_id,
            hedge,
            delay.as_millis(),
            primary
        );

        let hedge_fut = self.dispatch_to_provider(request, config, hedge);
        tokio::pin!(hedge_fut);

        // Race the still-pending primary against the freshly-dispatched hedge.
        // Both arms resolve the request outright (the loser is awaited only if
        // the winner failed), so this select fires exactly once.
        tokio::select! {
            biased;
            primary_result = &mut primary_fut => match primary_result {
                Ok(response) => Ok(response),
                Err(DispatchFailure::Fatal(e)) => Err(DispatchFailure::Fatal(e)),
                Err(primary_err) => {
                    // Primary lost the race by failing. Await the hedge.
                    let primary_error = primary_err.into_error();
                    match (&mut hedge_fut).await {
                        Ok(response) => {
                            self.metrics.hedges_won.fetch_add(1, Ordering::Relaxed);
                            Ok(response)
                        }
                        Err(DispatchFailure::Fatal(e)) => Err(DispatchFailure::Fatal(e)),
                        Err(hedge_err) => Err(DispatchFailure::Both {
                            primary: primary_error,
                            hedge: hedge_err.into_error(),
                        }),
                    }
                }
            },
            hedge_result = &mut hedge_fut => match hedge_result {
                Ok(response) => {
                    self.metrics.hedges_won.fetch_add(1, Ordering::Relaxed);
                    Ok(response)
                }
                Err(DispatchFailure::Fatal(e)) => Err(DispatchFailure::Fatal(e)),
                Err(hedge_err) => {
                    // Hedge failed. Await the primary, which is still in flight.
                    let hedge_error = hedge_err.into_error();
                    match (&mut primary_fut).await {
                        Ok(response) => Ok(response),
                        Err(DispatchFailure::Fatal(e)) => Err(DispatchFailure::Fatal(e)),
                        Err(primary_err) => Err(DispatchFailure::Both {
                            primary: primary_err.into_error(),
                            hedge: hedge_error,
                        }),
                    }
                }
            },
        }
    }

    /// Dispatches a single inference request to one resolved provider over
    /// HTTP, applying all success side-effects (circuit-breaker + provider
    /// metrics, token-count capping, pricing, usage recording, reputation,
    /// provenance) and returning the built [`InferenceResponse`]. Provider
    /// failures (unreachable, non-2xx, missing signed manifest) return
    /// [`DispatchFailure::Retryable`] so the caller can exclude the provider
    /// and try another; unrecoverable response-parse errors return
    /// [`DispatchFailure::Fatal`].
    async fn dispatch_to_provider(
        &self,
        request: &InferenceRequest,
        config: &RoutingConfig,
        provider_address: Address,
    ) -> std::result::Result<InferenceResponse, DispatchFailure> {
        // Get the provider's endpoint URL
        let provider = match self.provider_manager.get_provider(&provider_address) {
            Ok(p) => p,
            Err(e) => {
                return Err(DispatchFailure::Retryable {
                    provider: provider_address,
                    error: ModelError::InferenceError(format!(
                        "Provider {} not found: {}",
                        provider_address, e
                    )),
                });
            }
        };

        let endpoint_url = match &provider.endpoint_url {
            Some(url) => url.clone(),
            None => {
                warn!(
                    "Provider {} has no endpoint URL, skipping",
                    provider_address
                );
                return Err(DispatchFailure::Retryable {
                    provider: provider_address,
                    error: ModelError::InferenceError(format!(
                        "Provider {} has no endpoint URL",
                        provider_address
                    )),
                });
            }
        };

        let chat_url = format!("{}/chat/completions", endpoint_url.trim_end_matches('/'));

        info!(
            "Forwarding inference request {} to provider {} at {}",
            request.request_id, provider_address, chat_url
        );

        {
            // Build OpenAI-compatible request body
            let input_text = String::from_utf8_lossy(&request.input);
            let temperature = request
                .parameters
                .temperature
                .map(|t| t as f64 / 100.0)
                .unwrap_or(0.7);
            let top_p = request.parameters.top_p.map(|t| t as f64 / 100.0);
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
                    warn!("Failed to serialize inference request body: {}", e);
                    return Err(DispatchFailure::Retryable {
                        provider: provider_address,
                        error: ModelError::InferenceError(format!(
                            "Failed to serialize inference request body: {}",
                            e
                        )),
                    });
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
                    let resp_bytes = match resp.bytes().await {
                        Ok(b) => b,
                        Err(e) => {
                            return Err(DispatchFailure::Fatal(ModelError::InferenceError(
                                format!("Failed to read response body: {}", e),
                            )));
                        }
                    };
                    let bytes_out = resp_bytes.len() as u64;

                    let resp_body: serde_json::Value = match serde_json::from_slice(&resp_bytes) {
                        Ok(v) => v,
                        Err(e) => {
                            return Err(DispatchFailure::Fatal(ModelError::InferenceError(
                                format!("Failed to parse response: {}", e),
                            )));
                        }
                    };

                    let output_text = resp_body["choices"]
                        .get(0)
                        .and_then(|c| c["message"]["content"].as_str())
                        .unwrap_or("")
                        .to_string();

                    // Provider-attached provenance manifest (optional
                    // `tenzro_contentProvenance` extension on the OpenAI-compatible
                    // response). Verified against the output bytes, the
                    // routed model id, and — when the provider registered a
                    // signing key — that key. When the caller demanded a
                    // signed response, a missing or invalid manifest is a
                    // provider failure and the retry loop moves on; when
                    // verification is optional, a bad manifest is dropped
                    // with a warning and routing proceeds unsigned.
                    let provider_manifest = match resp_body.get("tenzro_contentProvenance") {
                        Some(v) if !v.is_null() => {
                            match serde_json::from_value::<tenzro_types::ContentProvenanceManifest>(
                                v.clone(),
                            ) {
                                Ok(manifest) => {
                                    match crate::provenance::verify_response_manifest(
                                        &manifest,
                                        output_text.as_bytes(),
                                        &request.model_id,
                                        provider.signing_pubkey.as_deref(),
                                    ) {
                                        Ok(()) => Some(manifest),
                                        Err(e) => {
                                            warn!(
                                                "Provider {} attached an invalid provenance \
                                                 manifest for request {}: {}",
                                                provider_address, request.request_id, e
                                            );
                                            None
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "Provider {} attached a malformed provenance \
                                         manifest for request {}: {}",
                                        provider_address, request.request_id, e
                                    );
                                    None
                                }
                            }
                        }
                        _ => None,
                    };

                    // Provider-attached jurisdiction receipt (optional
                    // `tenzro_jurisdiction` extension on the OpenAI-compatible
                    // response). The receipt is an attestation-bound locality
                    // claim signed by the serving node — verified against the
                    // exact prompt/output bytes, the routed model id, the
                    // provider identity, and — when the provider registered a
                    // signing key — that key. When the request pins a
                    // jurisdiction, the receipt's claim must also satisfy the
                    // pin. The router never countersigns: asserting another
                    // node's locality would be dishonest.
                    let jurisdiction_pin = request.parameters.custom.get("jurisdiction");
                    let provider_jurisdiction_receipt = match resp_body.get("tenzro_jurisdiction") {
                        Some(v) if !v.is_null() => {
                            match serde_json::from_value::<tenzro_types::JurisdictionReceipt>(
                                v.clone(),
                            ) {
                                Ok(receipt) => {
                                    let verdict = if receipt.provider != provider_address {
                                        Err(crate::jurisdiction::JurisdictionError::VerificationFailed)
                                    } else {
                                        crate::jurisdiction::verify_response_receipt(
                                            &receipt,
                                            input_text.as_bytes(),
                                            output_text.as_bytes(),
                                            &request.model_id,
                                            provider.signing_pubkey.as_deref(),
                                        )
                                        .and_then(|()| match jurisdiction_pin {
                                            Some(pin) => {
                                                crate::jurisdiction::check_receipt_satisfies_pin(
                                                    &receipt, pin,
                                                )
                                            }
                                            None => Ok(()),
                                        })
                                    };
                                    match verdict {
                                        Ok(()) => Some(receipt),
                                        Err(e) => {
                                            warn!(
                                                "Provider {} attached an invalid jurisdiction \
                                                 receipt for request {}: {}",
                                                provider_address, request.request_id, e
                                            );
                                            None
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "Provider {} attached a malformed jurisdiction \
                                         receipt for request {}: {}",
                                        provider_address, request.request_id, e
                                    );
                                    None
                                }
                            }
                        }
                        _ => None,
                    };

                    // Opt-in strictness: `jurisdiction_receipt=required` turns
                    // a missing or invalid receipt into a provider failure so
                    // the retry loop moves on to the next candidate instead of
                    // returning an unverifiable locality claim.
                    let jurisdiction_receipt_required = request
                        .parameters
                        .custom
                        .get("jurisdiction_receipt")
                        .is_some_and(|v| v.eq_ignore_ascii_case("required"));
                    if jurisdiction_receipt_required && provider_jurisdiction_receipt.is_none() {
                        warn!(
                            "Provider {} did not return a verifiable jurisdiction receipt \
                             for request {} (jurisdiction receipt required)",
                            provider_address, request.request_id
                        );
                        self.record_provider_failure(&provider_address);
                        self.provider_manager.record_call_failure(&provider_address);
                        return Err(DispatchFailure::Retryable {
                            provider: provider_address,
                            error: ModelError::InferenceError(format!(
                                "Provider {} did not return a verifiable jurisdiction receipt",
                                provider_address
                            )),
                        });
                    }

                    if config.require_signed_response && provider_manifest.is_none() {
                        warn!(
                            "Provider {} did not return a verifiable signed response \
                             for request {} (signed response required)",
                            provider_address, request.request_id
                        );
                        self.record_provider_failure(&provider_address);
                        self.provider_manager.record_call_failure(&provider_address);
                        return Err(DispatchFailure::Retryable {
                            provider: provider_address,
                            error: ModelError::InferenceError(format!(
                                "Provider {} did not return a verifiable signed response",
                                provider_address
                            )),
                        });
                    }

                    // Provider self-reports token counts in the OpenAI-compatible
                    // `usage` field. A dishonest provider can inflate either
                    // count to overbill the consumer, since the router has
                    // no second-source token oracle today. As a structural
                    // sanity bound we cap each count at the corresponding
                    // HTTP body byte count: well-formed UTF-8 tokens can't
                    // be shorter than 1 byte each, so a count > bytes can
                    // only come from a lying provider. The cap silently
                    // floors the bill at a defensible upper bound rather
                    // than rejecting the request, so consumers still get
                    // the inference result.
                    //
                    // Real fix (future): deterministic client-side
                    // tokenization for `input_tokens` (using the model's
                    // pinned tokenizer) and a TEE-attested or redundant-
                    // execution oracle for `output_tokens`. Tracked
                    // separately from this audit.
                    let raw_input = resp_body["usage"]["prompt_tokens"].as_u64().unwrap_or(0);
                    let raw_output = resp_body["usage"]["completion_tokens"]
                        .as_u64()
                        .unwrap_or(0);
                    let input_cap = bytes_in.min(u32::MAX as u64);
                    let output_cap = bytes_out.min(u32::MAX as u64);
                    if raw_input > input_cap {
                        warn!(
                            "Provider over-reported input_tokens: {} > bytes_in {} \
                             (capping to bytes_in)",
                            raw_input, input_cap
                        );
                    }
                    if raw_output > output_cap {
                        warn!(
                            "Provider over-reported output_tokens: {} > bytes_out {} \
                             (capping to bytes_out)",
                            raw_output, output_cap
                        );
                    }
                    let prompt_tokens = raw_input.min(input_cap) as u32;
                    let output_tokens = raw_output.min(output_cap) as u32;

                    // A prefix-cache hit is reported inside `prompt_tokens`, so
                    // the cached share is split out and the remainder billed at
                    // the fresh-input rate — otherwise a cached token would be
                    // charged twice, once at each rate.
                    let cached_read_tokens =
                        resp_body["usage"]["prompt_tokens_details"]["cached_tokens"]
                            .as_u64()
                            .unwrap_or(0)
                            .min(prompt_tokens as u64) as u32;
                    let cached_write_tokens =
                        resp_body["usage"]["prompt_tokens_details"]["cache_write_tokens"]
                            .as_u64()
                            .unwrap_or(0)
                            .min(prompt_tokens as u64) as u32;
                    let input_tokens = prompt_tokens.saturating_sub(cached_read_tokens);

                    let finish_reason = resp_body["choices"]
                        .get(0)
                        .and_then(|c| c["finish_reason"].as_str())
                        .map(String::from);

                    let units = BillableUnits::tokens(input_tokens, output_tokens)
                        .with_cache(cached_read_tokens, cached_write_tokens);
                    let metadata = InferenceMetadata {
                        units: units.clone(),
                        latency_ms: elapsed_ms,
                        model_version: resp_body["model"].as_str().map(String::from),
                        finish_reason,
                    };

                    // Price under whichever model the provider's announcement
                    // declared, so a per-request or per-compute-time offer bills
                    // the way it was advertised rather than being silently
                    // re-metered per token.
                    let price = PricingEngine::price_units(
                        &provider.pricing,
                        &units,
                        elapsed_ms,
                        self.pricing.get_market_average(&request.model_id),
                    );

                    // Feed the price back as market history, which is what makes
                    // a dynamic offer track the going rate for the model rather
                    // than standing at its metered cost forever.
                    self.pricing
                        .update_market_price(request.model_id.clone(), price);

                    let mut response = InferenceResponse::new(
                        request.request_id.clone(),
                        request.model_id.clone(),
                        provider_address,
                        output_text.into_bytes(),
                        price,
                    );
                    response.metadata = metadata;

                    info!(
                        "Inference request {} completed in {}ms ({} input, {} output tokens)",
                        request.request_id, elapsed_ms, input_tokens, output_tokens
                    );

                    // Record durable usage iff a tracker is attached. The
                    // tracker aggregates per-model / per-provider / global
                    // stats and persists them to RocksDB CF_MODELS, so this
                    // is the producer call site for marketplace observability
                    // data on routed inference. The record is keyed on
                    // `request_id` — the same id the caller holds — so the
                    // generation can be read back per-request afterwards.
                    if let Some(tracker) = &self.usage_tracker {
                        let record = UsageRecord::new(
                            request.model_id.clone(),
                            provider_address,
                            units,
                            bytes_in,
                            bytes_out,
                            price,
                            elapsed_ms,
                        )
                        .with_record_id(request.request_id.clone());
                        if let Err(e) = tracker.record_usage(record) {
                            warn!(
                                "Failed to record usage for request {}: {}",
                                request.request_id, e
                            );
                        }
                    }

                    // Reputation bump: the inference was served AND the
                    // billable price was computed. In the HTTP-402 paid
                    // flow the payment is verified before this code runs
                    // (middleware-gated), so a non-zero price here means
                    // a real consumer→provider payment settled. The
                    // free-tier path (price == 0) is correctly skipped
                    // because there is no settlement to anchor the
                    // reputation gain on — closing the self-deal where a
                    // provider's own bot could pump reputation by hitting
                    // its own endpoint with free traffic.
                    if price > 0 {
                        self.provider_manager
                            .record_settled_success(&provider_address, price as u128);
                    }

                    // EU AI Act Art. 50(2): attach a provenance manifest
                    // before returning. A verified provider-signed manifest
                    // wins — it binds the output to the provider's own key.
                    // Otherwise the router stamps with its own signer as a
                    // fallback disclosure mark. Failure to sign is logged
                    // but non-fatal — the consumer still gets the
                    // `synthetic_content = true` disclosure flag, just no
                    // verifiable signature. This matches the behavior on
                    // dev-mode nodes that don't yet have a provenance key.
                    if let Some(manifest) = provider_manifest {
                        if let Some(store) = &self.provenance_store {
                            store.put(manifest.clone());
                        }
                        response.provenance = Some(manifest);
                    } else if let Some(signer) = &self.provenance_signer {
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

                    if let Some(receipt) = provider_jurisdiction_receipt {
                        response.jurisdiction_receipt = Some(receipt);
                    }

                    Ok(response)
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
                    Err(DispatchFailure::Retryable {
                        provider: provider_address,
                        error: ModelError::InferenceError(format!(
                            "Provider {} returned HTTP {}: {}",
                            provider_address, status, error_body
                        )),
                    })
                }
                Err(e) => {
                    warn!("Provider {} request failed: {}", provider_address, e);
                    self.record_provider_failure(&provider_address);
                    self.provider_manager.record_call_failure(&provider_address);
                    Err(DispatchFailure::Retryable {
                        provider: provider_address,
                        error: ModelError::InferenceError(format!(
                            "Provider {} unreachable: {}",
                            provider_address, e
                        )),
                    })
                }
            }
        }
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

        let prompt_run_hashes = tenzro_types::prefix_run_hashes(&request.input);
        let selected = self.select_provider(providers, &self.default_config, &prompt_run_hashes)?;

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
    fn hedge_delay_clamps_and_defaults() {
        let config = RoutingConfig::new().with_hedge_delay_bounds(40, 500);
        // Cold provider (no latency history) → midpoint of the band.
        assert_eq!(config.hedge_delay_ms(0), 40 + (500 - 40) / 2);
        // Warm provider inside the band → its own tail estimate.
        assert_eq!(config.hedge_delay_ms(120), 120);
        // Below floor → floor.
        assert_eq!(config.hedge_delay_ms(5), 40);
        // Above ceiling → ceiling.
        assert_eq!(config.hedge_delay_ms(10_000), 500);
        // A ceiling below the floor is coerced up to the floor.
        let inverted = RoutingConfig::new().with_hedge_delay_bounds(100, 50);
        assert_eq!(inverted.hedge_delay_ceiling_ms, 100);
        assert_eq!(inverted.hedge_delay_ms(75), 100);
    }

    #[test]
    fn hedgeable_unless_opted_out() {
        let pm = Arc::new(ProviderManager::new());
        let router = InferenceRouter::new(pm);

        let mut req = InferenceRequest::new("m".to_string(), Address::zero(), vec![], 0);
        assert!(router.is_request_hedgeable(&req));

        req.parameters.custom.insert("no_hedge".into(), "1".into());
        assert!(!router.is_request_hedgeable(&req));

        req.parameters
            .custom
            .insert("no_hedge".into(), "true".into());
        assert!(!router.is_request_hedgeable(&req));

        req.parameters.custom.insert("no_hedge".into(), "0".into());
        assert!(router.is_request_hedgeable(&req));
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
        assert!(
            matches!(err, ModelError::ModalityMismatch { .. }),
            "got {err:?}"
        );

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
