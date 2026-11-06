//! Inference SDK for Tenzro Network
//!
//! This module provides AI model inference functionality.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use crate::types::ModelInfo;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Inference client for AI model operations
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let inference = client.inference();
///
/// // List available models
/// let models = inference.list_models().await?;
/// println!("Found {} models", models.len());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct InferenceClient {
    rpc: Arc<RpcClient>,
}

impl InferenceClient {
    /// Creates a new inference client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Lists all available models on the network
    pub async fn list_models(&self) -> SdkResult<Vec<ModelInfo>> {
        self.rpc
            .call("tenzro_listModels", serde_json::json!([]))
            .await
    }

    /// Lists every model the node holds, of every type (chat, vision,
    /// embedding, forecast, segmentation, detection, audio, video, media,
    /// speech), with its engine, visibility, access and state.
    pub async fn list_loaded_models(&self) -> SdkResult<LoadedModels> {
        self.rpc
            .call("tenzro_listModels", serde_json::json!([{ "loaded": true }]))
            .await
    }

    /// Submits an inference request to a model
    pub async fn request(
        &self,
        model_id: &str,
        input: &str,
        max_tokens: Option<u32>,
    ) -> SdkResult<InferenceResult> {
        let mut params = serde_json::json!({
            "model_id": model_id,
            "input": input,
        });

        if let Some(mt) = max_tokens {
            params["max_tokens"] = serde_json::json!(mt);
        }

        self.rpc
            .call("tenzro_inferenceRequest", serde_json::json!([params]))
            .await
    }

    /// What `units` would cost at `provider` for `model_id`, in TNZO base
    /// units: priced on the card the provider publishes in the registry, at
    /// the chain's TNZO/USD rate, by the same rule the node charges with.
    pub async fn estimate_cost(
        &self,
        provider: &str,
        model_id: &str,
        units: &BillableUnits,
    ) -> SdkResult<u128> {
        let registry = crate::pricing::RegistryClient::new(self.rpc.clone());
        let (_, card) = registry
            .price_card(provider, model_id)
            .await?
            .ok_or_else(|| {
                crate::error::SdkError::InvalidParameter(format!(
                    "{provider} publishes no card for {model_id}"
                ))
            })?;
        let rate = registry.tnzo_usd_nano().await?;
        card.rates
            .charge_wei(units, crate::pricing::default_billable, rate)
    }

    /// Resolves an intent to the best model without naming one. Discovery
    /// only: no provider is dialed and no spend is recorded, but the per-DID
    /// budget gate and the wallet-balance ceiling are still consulted, so an
    /// unaffordable request is rejected at discovery time. Feed the returned
    /// `model_id` into [`InferenceClient::request`] or a chat surface to run
    /// it.
    pub async fn route_intent(&self, params: &IntentParams) -> SdkResult<RouteDecision> {
        self.rpc
            .call("tenzro_routeIntent", serde_json::json!([params.to_json()]))
            .await
    }

    /// Resolves an intent to a model and runs a chat completion through the
    /// same path a named-model request takes. `messages` is the rich chat
    /// shape (role/content turns). The chosen route is attached to the
    /// response under `route`. Returns the raw chat response object.
    pub async fn chat_by_intent(
        &self,
        params: &IntentParams,
        messages: serde_json::Value,
    ) -> SdkResult<serde_json::Value> {
        let mut body = params.to_json();
        body["messages"] = messages;
        self.rpc
            .call("tenzro_chatByIntent", serde_json::json!([body]))
            .await
    }

    /// Reports how a routed call turned out, so per-cluster error rates
    /// reflect what happened rather than only what the catalog declares.
    /// `cluster` is the `cluster` from the routing decision.
    ///
    /// In practice this carries [`RouteOutcome::Escalated`] — the outcome only
    /// the caller knows, because it means the caller took the answer to a
    /// stronger model. `resolved` and `failed` are already recorded by
    /// `chat_by_intent` from the dispatch itself. Reporting is advisory:
    /// `retained: false` in the response means the node has no difficulty
    /// index wired, so the feedback was accepted and discarded.
    pub async fn record_route_outcome(
        &self,
        model_id: &str,
        cluster: u32,
        outcome: RouteOutcome,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_recordRouteOutcome",
                serde_json::json!({
                    "model_id": model_id,
                    "cluster": cluster,
                    "outcome": outcome.as_str(),
                }),
            )
            .await
    }

    /// Reads the node's difficulty index: how many clusters it has discovered
    /// and how many prompts landed in each. With `model_id`, also returns that
    /// model's per-cluster outcome counters and error rate. An operator
    /// diagnostic — routing does not depend on it.
    pub async fn route_difficulty_stats(
        &self,
        model_id: Option<&str>,
    ) -> SdkResult<serde_json::Value> {
        let params = match model_id {
            Some(id) => serde_json::json!({ "model_id": id }),
            None => serde_json::json!({}),
        };
        self.rpc.call("tenzro_routeDifficultyStats", params).await
    }

    /// Reads the inference router's live metrics snapshot: total requests
    /// routed, hedges dispatched, hedges won, and requests abandoned on the
    /// whole-request deadline. Returns the raw metrics object.
    pub async fn router_metrics(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getRouterMetrics", serde_json::json!({}))
            .await
    }

    /// Look up the cached provenance manifest for generated content by its
    /// 32-byte hex `content_hash` (with or without `0x` prefix). This is the
    /// machine-readable synthetic-content marker per EU AI Act Art. 50(2).
    /// The node returns JSON-RPC `-32004` when no manifest is cached for the
    /// hash — surfaces as `SdkError::RpcError`.
    pub async fn get_provenance(&self, content_hash: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getContentProvenance",
                serde_json::json!({ "content_hash": content_hash }),
            )
            .await
    }

    /// Reads back what one finished generation consumed and cost, by the id the
    /// caller already holds — a `chatcmpl-…` from a chat completion, or the
    /// `request_id` of a routed inference.
    ///
    /// Useful when a stream was consumed and the terminal chunk went by, or
    /// when reconciling a billing period against your own request log. The node
    /// returns JSON-RPC `-32004` when the id is unknown to it, which also
    /// covers a generation still running or one that failed before it could be
    /// recorded — surfaces as `SdkError::RpcError`.
    pub async fn get_generation(&self, id: &str) -> SdkResult<GenerationStats> {
        self.rpc
            .call("tenzro_getGeneration", serde_json::json!({ "id": id }))
            .await
    }

    /// Reads usage. Which tier comes back follows the filters given: pass both
    /// a model and a provider for the matching records, one for that model's or
    /// provider's rollup, neither for the global rollup plus the per-model and
    /// per-provider breakdowns.
    ///
    /// Records are the node's bounded ring of recent generations; the rollups
    /// are lifetime totals that survive restart.
    pub async fn list_inference_usage(
        &self,
        model_id: Option<&str>,
        provider: Option<&str>,
    ) -> SdkResult<InferenceUsage> {
        let mut params = serde_json::Map::new();
        if let Some(model_id) = model_id {
            params.insert("model_id".to_string(), serde_json::json!(model_id));
        }
        if let Some(provider) = provider {
            params.insert("provider".to_string(), serde_json::json!(provider));
        }
        self.rpc
            .call(
                "tenzro_listInferenceUsage",
                serde_json::Value::Object(params),
            )
            .await
    }
}

/// The shared intent fields consumed by `route_intent` and `chat_by_intent`.
///
/// Build with [`IntentParams::new`] and refine with the `with_*` setters.
/// `budget` is a decimal string in the smallest TNZO unit (a u128 exceeds
/// JSON's safe integer range).
#[derive(Debug, Clone, Default)]
pub struct IntentParams {
    /// Use case: `chat`, `code`, `reasoning`, `research`, `summarize`,
    /// `extract`, or `embed`.
    pub use_case: String,
    /// Per-request cost cap, smallest TNZO unit, decimal string.
    pub budget: Option<String>,
    /// Cost-quality knob in `[0.0, 1.0]`.
    pub optimize: Option<f64>,
    /// Reject any model below this tier (`cheap` | `strong`).
    pub quality_floor: Option<String>,
    /// Estimated input tokens for cost estimation.
    pub est_input_tokens: Option<u64>,
    /// Estimated output tokens for cost estimation.
    pub est_output_tokens: Option<u64>,
    /// Payer DID — enables the per-DID budget gate.
    pub payer_did: Option<String>,
    /// Payer wallet address (hex) — enables the wallet-balance ceiling.
    pub payer_address: Option<String>,
    /// Text the model will answer, used only to place the request in a
    /// difficulty cluster. It is not sent to any provider by `route_intent`.
    /// On `chat_by_intent` the node derives it from the chat turns, so it only
    /// needs setting when routing without dispatching.
    pub prompt: Option<String>,
    /// Where the request may be served (ISO 3166-1 codes and bloc tokens,
    /// comma-separated). An intent no provider satisfies is refused.
    pub jurisdiction: Option<String>,
    /// The p95 latency target in ms; providers observed slower are skipped.
    pub max_p95_ms: Option<u64>,
    /// Continuity level: `none`, `standby` or `hot_successor`. Above `none`
    /// the network assigns a successor that holds the session's KV cache;
    /// it needs `jurisdiction` and `session_id`.
    pub continuity: Option<String>,
    /// The session the turns belong to, when continuity is above `none`.
    pub session_id: Option<String>,
}

impl IntentParams {
    /// Builds intent params for a use case with no other constraints.
    pub fn new(use_case: impl Into<String>) -> Self {
        Self {
            use_case: use_case.into(),
            ..Default::default()
        }
    }

    /// Sets the per-request budget cap (decimal string, smallest TNZO unit).
    #[must_use]
    pub fn with_budget(mut self, budget: impl Into<String>) -> Self {
        self.budget = Some(budget.into());
        self
    }

    /// Sets the cost-quality knob in `[0.0, 1.0]`.
    #[must_use]
    pub fn with_optimize(mut self, optimize: f64) -> Self {
        self.optimize = Some(optimize);
        self
    }

    /// Sets the minimum quality tier (`cheap` | `strong`).
    #[must_use]
    pub fn with_quality_floor(mut self, floor: impl Into<String>) -> Self {
        self.quality_floor = Some(floor.into());
        self
    }

    /// Sets the token estimates used for cost estimation.
    #[must_use]
    pub fn with_tokens(mut self, input: u64, output: u64) -> Self {
        self.est_input_tokens = Some(input);
        self.est_output_tokens = Some(output);
        self
    }

    /// Sets the payer DID (enables the per-DID budget gate).
    #[must_use]
    pub fn with_payer_did(mut self, did: impl Into<String>) -> Self {
        self.payer_did = Some(did.into());
        self
    }

    /// Sets the payer wallet address (enables the wallet-balance ceiling).
    #[must_use]
    pub fn with_payer_address(mut self, addr: impl Into<String>) -> Self {
        self.payer_address = Some(addr.into());
        self
    }

    /// Pins where the request may be served.
    #[must_use]
    pub fn with_jurisdiction(mut self, pin: impl Into<String>) -> Self {
        self.jurisdiction = Some(pin.into());
        self
    }

    /// Sets the p95 latency target in ms.
    #[must_use]
    pub fn with_max_p95_ms(mut self, target: u64) -> Self {
        self.max_p95_ms = Some(target);
        self
    }

    /// Asks for session continuity at `level` for `session_id`.
    #[must_use]
    pub fn with_continuity(
        mut self,
        level: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Self {
        self.continuity = Some(level.into());
        self.session_id = Some(session_id.into());
        self
    }

    /// Sets the prompt used to place the request in a difficulty cluster.
    #[must_use]
    pub fn with_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    /// Serializes into the node's snake_case RPC param object.
    fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({ "use_case": self.use_case });
        if let Some(ref b) = self.budget {
            obj["budget"] = serde_json::json!(b);
        }
        if let Some(o) = self.optimize {
            obj["optimize"] = serde_json::json!(o);
        }
        if let Some(ref f) = self.quality_floor {
            obj["quality_floor"] = serde_json::json!(f);
        }
        if let Some(i) = self.est_input_tokens {
            obj["est_input_tokens"] = serde_json::json!(i);
        }
        if let Some(o) = self.est_output_tokens {
            obj["est_output_tokens"] = serde_json::json!(o);
        }
        if let Some(ref j) = self.jurisdiction {
            obj["jurisdiction"] = serde_json::json!(j);
        }
        if let Some(t) = self.max_p95_ms {
            obj["max_p95_ms"] = serde_json::json!(t);
        }
        if let Some(ref c) = self.continuity {
            obj["continuity"] = serde_json::json!(c);
        }
        if let Some(ref s) = self.session_id {
            obj["session_id"] = serde_json::json!(s);
        }
        if let Some(ref d) = self.payer_did {
            obj["payer_did"] = serde_json::json!(d);
        }
        if let Some(ref a) = self.payer_address {
            obj["payer_address"] = serde_json::json!(a);
        }
        if let Some(ref p) = self.prompt {
            obj["prompt"] = serde_json::json!(p);
        }
        obj
    }
}

/// The model-selection decision returned by `route_intent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDecision {
    /// Chosen model id.
    #[serde(default)]
    pub model_id: String,
    /// Selected tier label.
    #[serde(default)]
    pub tier: String,
    /// Estimated cost, smallest TNZO unit, decimal string.
    #[serde(default)]
    pub estimated_cost: String,
    /// Ordered alternate model ids, best first.
    #[serde(default)]
    pub alternates: Vec<String>,
    /// Difficulty cluster the prompt landed in. `None` when no prompt was
    /// supplied or the node has no embedding model loaded. Echo it back to
    /// [`InferenceClient::record_route_outcome`] so the observation lands on
    /// the right cluster.
    #[serde(default)]
    pub cluster: Option<u32>,
    /// The chosen model's observed adverse-outcome rate in that cluster.
    /// `None` when the cluster has no observations, meaning the decision was
    /// made on declared metadata alone.
    #[serde(default)]
    pub expected_error: Option<f64>,
    /// Wallet address (hex) of the provider whose announced offer won. Absent
    /// when the winner came from this node's own catalog, where the serving
    /// operator is resolved at dispatch time.
    #[serde(default)]
    pub provider: Option<String>,
    /// The winning offer's endpoint, present alongside `provider`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Human-readable selection reason.
    #[serde(default)]
    pub reason: String,
}

/// How a routed call turned out, reported through
/// [`InferenceClient::record_route_outcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOutcome {
    /// The selected model answered acceptably.
    Resolved,
    /// The caller took the answer to a stronger model.
    Escalated,
    /// The call did not produce a usable answer.
    Failed,
}

impl RouteOutcome {
    /// The wire label the node expects.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Escalated => "escalated",
            Self::Failed => "failed",
        }
    }
}

/// Every model a node holds, from [`InferenceClient::list_loaded_models`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedModels {
    /// One row per model
    pub models: Vec<LoadedModel>,
}

/// One model a node holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedModel {
    /// Catalog model id
    pub model_id: String,
    /// `chat`, `vision`, `embedding`, `forecast`, `segmentation`,
    /// `text-segmentation`, `detection`, `audio`, `video`, `media` or `speech`
    #[serde(rename = "type")]
    pub model_type: String,
    /// The engine holding it; `None` when it is served but not resident
    pub engine: Option<String>,
    /// Effective visibility: `public`, `gated` or `private`
    pub visibility: String,
    /// `model` when the model carries its own override, `node` when it
    /// follows the node's visibility
    pub visibility_source: String,
    /// The access that visibility grants: `{"mode": "public",
    /// "price_per_request": ...}`, `{"mode": "gated"}` or `{"mode": "private"}`
    pub access: serde_json::Value,
    /// Resident in memory
    pub loaded: bool,
    /// Offered by this node
    pub serving: bool,
}

/// `tenzro_inferenceRequest`: one completion run on the node, with its bill
/// and receipt.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct InferenceResult {
    /// Model output text
    pub output: String,
    /// The model's reasoning text, when it produced any
    pub thinking: Option<String>,
    /// Model ID that processed the request
    pub model_id: String,
    /// Prompt tokens
    pub input_tokens: u64,
    /// Completion tokens
    pub output_tokens: u64,
    /// Generation time, ms
    pub generation_time_ms: u64,
    /// Decode throughput
    pub tokens_per_second: f64,
    /// What the call cost, wei, decimal string
    pub cost_wei: String,
    /// How the cost settled
    pub settlement: serde_json::Value,
    /// `local` when this node served it
    pub provider: String,
    /// The signed inference receipt, when the node signs one
    pub tenzro_receipt: serde_json::Value,
    /// The verification commitment, when one was asked for
    pub commitment: serde_json::Value,
}

impl InferenceResult {
    /// Prompt and completion tokens together.
    pub fn tokens_used(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }
}

/// What one finished generation consumed and cost, as recorded by the node.
///
/// The dimensions past prompt and completion are written only when the call
/// actually consumed them, so a chat completion carries none of the media
/// fields and they arrive here as zero. Read one back with
/// [`InferenceClient::get_generation`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GenerationStats {
    /// The id the read was keyed on — a `chatcmpl-…` or a `request_id`.
    #[serde(default)]
    pub id: String,
    /// Model that produced it.
    #[serde(default)]
    pub model: String,
    /// Payee address of the node that served it, hex.
    #[serde(default)]
    pub provider: String,
    /// The whole prompt, including anything served from cache.
    #[serde(default)]
    pub input_tokens: u64,
    /// Tokens generated.
    #[serde(default)]
    pub output_tokens: u64,
    /// Every token-denominated dimension summed, image tokens included.
    #[serde(default)]
    pub total_tokens: u64,
    /// Bytes received from the consumer.
    #[serde(default)]
    pub bytes_in: u64,
    /// Bytes sent back to the consumer.
    #[serde(default)]
    pub bytes_out: u64,
    /// Cost in the smallest TNZO unit, as a decimal string.
    #[serde(default)]
    pub cost_wei: String,
    /// Wall time the generation took.
    #[serde(default)]
    pub latency_ms: u64,
    /// Absent when the recorded latency is zero.
    #[serde(default)]
    pub tokens_per_second: Option<f64>,
    /// Unix milliseconds at which it was recorded.
    #[serde(default)]
    pub created: i64,
    /// Every unit the call was metered on, as the receipt states it.
    #[serde(default)]
    pub units: BillableUnits,
}

pub use crate::pricing::BillableUnits;

/// One recorded generation, as it sits in the node's ring of recent records.
///
/// This is the raw record rather than the reshaped [`GenerationStats`]:
/// `provider_id` is the raw 32-byte address, durations stay in milliseconds,
/// and every dimension is present rather than conditional.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageRecord {
    /// Lookup key — the client-visible generation id when the producer minted
    /// one, a timestamp-plus-UUID otherwise.
    #[serde(default)]
    pub record_id: String,
    /// Model that produced it.
    #[serde(default)]
    pub model_id: String,
    /// The serving provider's address, as 32 bytes.
    #[serde(default)]
    pub provider_id: Vec<u8>,
    /// Billable work the call consumed, across every modality.
    #[serde(default)]
    pub units: BillableUnits,
    /// Bytes received from the consumer.
    #[serde(default)]
    pub bytes_in: u64,
    /// Bytes sent back to the consumer.
    #[serde(default)]
    pub bytes_out: u64,
    /// Cost in the smallest TNZO unit.
    #[serde(default, with = "crate::types::u128_wire")]
    pub cost: u128,
    /// Wall time the generation took.
    #[serde(default)]
    pub latency_ms: u64,
    /// Unix milliseconds.
    #[serde(default)]
    pub timestamp: i64,
}

/// Usage rolled up for one model.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelUsageStats {
    /// Model the rollup covers.
    #[serde(default)]
    pub model_id: String,
    /// Requests counted.
    #[serde(default)]
    pub inference_count: u64,
    /// Lifetime totals of every billable dimension.
    #[serde(default)]
    pub total_units: BillableUnits,
    /// Cost in the smallest TNZO unit.
    #[serde(default, with = "crate::types::u128_wire")]
    pub total_cost: u128,
    /// Summed latency, for deriving an average.
    #[serde(default)]
    pub total_latency_ms: u64,
    /// Bytes received from consumers.
    #[serde(default)]
    pub total_bytes_in: u64,
    /// Bytes sent back to consumers.
    #[serde(default)]
    pub total_bytes_out: u64,
    /// Unix milliseconds of the first counted request.
    #[serde(default)]
    pub first_inference: Option<i64>,
    /// Unix milliseconds of the most recent counted request.
    #[serde(default)]
    pub last_inference: Option<i64>,
}

/// Usage rolled up for one provider — the same shape, counted as earnings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderUsageStats {
    /// The provider's address, as 32 bytes.
    #[serde(default)]
    pub provider_id: Vec<u8>,
    /// Requests served.
    #[serde(default)]
    pub inference_count: u64,
    /// Lifetime totals of every billable dimension served.
    #[serde(default)]
    pub total_units: BillableUnits,
    /// Revenue earned in the smallest TNZO unit.
    #[serde(default, with = "crate::types::u128_wire")]
    pub total_revenue: u128,
    /// Summed latency.
    #[serde(default)]
    pub total_latency_ms: u64,
    /// Bytes received from consumers.
    #[serde(default)]
    pub total_bytes_in: u64,
    /// Bytes sent back to consumers.
    #[serde(default)]
    pub total_bytes_out: u64,
    /// Unix milliseconds of the first request served.
    #[serde(default)]
    pub first_inference: Option<i64>,
    /// Unix milliseconds of the most recent request served.
    #[serde(default)]
    pub last_inference: Option<i64>,
}

/// Usage rolled up across everything this node has served or routed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalUsageStats {
    /// Requests counted across all models.
    #[serde(default)]
    pub total_inference_count: u64,
    /// Lifetime totals of every billable dimension.
    #[serde(default)]
    pub total_units: BillableUnits,
    /// Cost in the smallest TNZO unit.
    #[serde(default, with = "crate::types::u128_wire")]
    pub total_cost: u128,
    /// Summed latency.
    #[serde(default)]
    pub total_latency_ms: u64,
    /// Bytes received from consumers.
    #[serde(default)]
    pub total_bytes_in: u64,
    /// Bytes sent back to consumers.
    #[serde(default)]
    pub total_bytes_out: u64,
    /// Distinct models that have been used.
    #[serde(default)]
    pub unique_models: u64,
    /// Distinct providers that have served requests.
    #[serde(default)]
    pub unique_providers: u64,
    /// Unix milliseconds of the first counted request.
    #[serde(default)]
    pub first_inference: Option<i64>,
    /// Unix milliseconds of the most recent counted request.
    #[serde(default)]
    pub last_inference: Option<i64>,
}

/// What [`InferenceClient::list_inference_usage`] returns. Which field is
/// populated follows the filters given: both filters returns the matching
/// `records`, one returns that model's or provider's rollup, neither returns
/// all three tiers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InferenceUsage {
    /// Matching recent records, when both filters were given.
    #[serde(default)]
    pub records: Option<Vec<UsageRecord>>,
    /// One model's rollup, when only `model_id` was given.
    #[serde(default)]
    pub model_stats: Option<ModelUsageStats>,
    /// One provider's rollup, when only `provider` was given.
    #[serde(default)]
    pub provider_stats: Option<ProviderUsageStats>,
    /// Network-wide rollup, when neither filter was given.
    #[serde(default)]
    pub global: Option<GlobalUsageStats>,
    /// Per-model breakdown, alongside `global`.
    #[serde(default)]
    pub models: Option<Vec<ModelUsageStats>>,
    /// Per-provider breakdown, alongside `global`.
    #[serde(default)]
    pub providers: Option<Vec<ProviderUsageStats>>,
}

impl InferenceClient {
    /// Commits a committee vote. `voter_node` is the voting validator's own
    /// node: it signs the commit with its consensus key
    /// (`tenzro_signChallengeVote`), and the signed commit goes to this
    /// client's node (`tenzro_commitChallengeVote`).
    pub async fn commit_challenge_vote(
        &self,
        voter_node: &RpcClient,
        challenge_id: &str,
        commit_hash: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        let signed: serde_json::Value = voter_node
            .call(
                "tenzro_signChallengeVote",
                serde_json::json!({ "challenge_id": challenge_id, "commit_hash": commit_hash }),
            )
            .await?;
        self.rpc.call("tenzro_commitChallengeVote", serde_json::json!({ "challenge_id": challenge_id, "voter": signed["voter"], "commit_hash": commit_hash, "signature": signed["signature"] })).await
    }

    /// Reveals a committed vote: `voter_node` signs `(verdict, salt)`, and the
    /// signed reveal goes to this client's node (`tenzro_revealChallengeVote`).
    /// `salt` is hex and must be the salt the commit was built with.
    pub async fn reveal_challenge_vote(
        &self,
        voter_node: &RpcClient,
        challenge_id: &str,
        verdict: bool,
        salt: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        let signed: serde_json::Value = voter_node.call("tenzro_signChallengeVote", serde_json::json!({ "challenge_id": challenge_id, "verdict": verdict, "salt": salt })).await?;
        self.rpc.call("tenzro_revealChallengeVote", serde_json::json!({ "challenge_id": challenge_id, "voter": signed["voter"], "verdict": verdict, "salt": salt, "signature": signed["signature"] })).await
    }

    /// Calls `tenzro_fileInferenceChallenge`: file inference challenge.
    pub async fn file_inference_challenge(
        &self,
        commitment_hash: &str,
        challenger: &str,
        reason: Option<&str>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_fileInferenceChallenge", serde_json::json!({ "commitment_hash": commitment_hash, "challenger": challenger, "reason": reason })).await
    }

    /// Calls `tenzro_finalizeChallenge`: finalize challenge.
    pub async fn finalize_challenge(
        &self,
        challenge_id: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_finalizeChallenge",
                serde_json::json!({ "challenge_id": challenge_id }),
            )
            .await
    }

    /// Calls `tenzro_getInferenceChallenge`: get inference challenge.
    pub async fn get_inference_challenge(
        &self,
        challenge_id: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getInferenceChallenge",
                serde_json::json!({ "challenge_id": challenge_id }),
            )
            .await
    }

    /// Calls `tenzro_listInferenceChallenges`: list inference challenges.
    pub async fn list_inference_challenges(
        &self,
        status: Option<&str>,
        provider: Option<&str>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_listInferenceChallenges",
                serde_json::json!({ "status": status, "provider": provider }),
            )
            .await
    }

    /// Calls `tenzro_getInferenceCommitment`: get inference commitment.
    pub async fn get_inference_commitment(
        &self,
        commitment_hash: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getInferenceCommitment",
                serde_json::json!({ "commitment_hash": commitment_hash }),
            )
            .await
    }

    /// Calls `tenzro_verifyInferenceCommitment`: re-run the stored commitment
    /// against `prompt`; with the provider's `receipt`, the decode is checked
    /// too.
    pub async fn verify_inference_commitment(
        &self,
        commitment_hash: &str,
        prompt: &str,
        receipt: Option<serde_json::Value>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        let mut params =
            serde_json::json!({ "commitment_hash": commitment_hash, "prompt": prompt });
        if let Some(r) = receipt {
            params["receipt"] = r;
        }
        self.rpc
            .call("tenzro_verifyInferenceCommitment", params)
            .await
    }
}

impl InferenceClient {
    /// Calls `tenzro_auditInferenceChallenge`: audit inference challenge.
    pub async fn audit_inference_challenge(
        &self,
        challenge_id: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_auditInferenceChallenge",
                serde_json::json!({ "challenge_id": challenge_id }),
            )
            .await
    }

    /// Calls `tenzro_verifyInferenceReceipt`: verify inference receipt.
    pub async fn verify_inference_receipt(
        &self,
        level: &str,
        receipt: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_verifyInferenceReceipt",
                serde_json::json!({ "level": level, "receipt": receipt }),
            )
            .await
    }
}

impl InferenceClient {
    /// Calls `tenzro_prefixProbe`: prefix probe.
    pub async fn prefix_probe(
        &self,
        digests: &[String],
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_prefixProbe",
                serde_json::json!({ "digests": digests }),
            )
            .await
    }
}

impl InferenceClient {
    /// Calls `tenzro_moeRoute`: route tokens through one layer's gate.
    /// `hidden_states_b64` is the little-endian f32 activations, base64,
    /// `d_model` wide; `top_k` defaults to the catalog's experts per token.
    pub async fn moe_route(
        &self,
        model_id: &str,
        layer: u32,
        d_model: u32,
        hidden_states_b64: &str,
        top_k: Option<u32>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        let mut params = serde_json::json!({
            "model_id": model_id,
            "layer": layer,
            "d_model": d_model,
            "hidden_states": hidden_states_b64,
        });
        if let Some(k) = top_k {
            params["top_k"] = serde_json::json!(k);
        }
        self.rpc.call("tenzro_moeRoute", params).await
    }

    /// Calls `tenzro_moeExecute`: moe execute.
    pub async fn moe_execute(
        &self,
        request: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_moeExecute", request).await
    }

    /// The signed receipt of the expert dispatch under `key`, to dispute it.
    pub async fn moe_dispute_receipt(
        &self,
        key: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_moeDisputeReceipt",
                serde_json::json!({ "key": key }),
            )
            .await
    }
}
