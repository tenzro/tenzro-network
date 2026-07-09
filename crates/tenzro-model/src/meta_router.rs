//! Budget/use-case model discovery and routing.
//!
//! The [`MetaRouter`] lets a caller state an *intent* — a use case, a budget,
//! and a quality floor — and have the network pick a concrete model for them.
//! It sits above [`InferenceRouter`]: the meta-router resolves intent to a
//! `model_id` (model selection), then hands that `model_id` to the inference
//! router, which picks the operator deployment (provider selection).
//!
//! ## Two tiers
//!
//! - **Model selection (this module).** Intent → `model_id`. Owns
//!   use-case→modality mapping, candidate discovery via [`ModelRegistry`],
//!   quality-tier resolution, budget pre-filtering, usage-stats scoring, and
//!   the cross-model fallback order.
//! - **Provider selection ([`InferenceRouter`]).** `model_id` → operator
//!   address. Unchanged — the meta-router calls it the same way a caller who
//!   named the model would.
//!
//! ## Budget, two scopes
//!
//! A [`RouteIntent`] carries a per-request cost cap ([`Budget`]) enforced at
//! discovery time (a model whose pricing can't fit the cap is never
//! considered). Independently, a per-DID rolling-window cap is enforced through
//! a [`BudgetGate`] — the node adapts its existing spending-policy resolver to
//! this trait so an intent that fits the per-request cap can still be rejected
//! when the DID's daily budget is exhausted.
//!
//! ## Wallet-balance ceiling
//!
//! A third, hard ceiling is the payer's on-chain TNZO balance: no model whose
//! estimated cost exceeds what the payer can actually pay is ever selected. A
//! [`BalanceProvider`] reads the balance for the intent's `payer_address`; the
//! node implements it against `TnzoToken::balance_of` so the model crate gains
//! no token dependency. The ceiling is applied as a discovery pre-filter (a
//! cheaper model still routes even when the strongest one is unaffordable).

use crate::error::{ModelError, Result};
use crate::registry::{ModelFilter, ModelRegistry};
use crate::routing::InferenceRouter;
use crate::usage::UsageTracker;
use tenzro_types::model::{
    InferenceRequest, ModelInfo, ModelModality, ModelStatus,
};
use tenzro_types::primitives::Address;

use std::sync::Arc;

/// The task a caller wants a model for. Maps to a modality and biases quality
/// tiering (a reasoning use case favors a stronger model at the same budget).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseCase {
    /// General conversational text.
    Chat,
    /// Code generation / editing.
    Code,
    /// Multi-step reasoning; biases toward the strong tier.
    Reasoning,
    /// Open-ended research synthesis; biases toward the strong tier.
    Research,
    /// Summarization; tolerates the cheap tier.
    Summarize,
    /// Structured extraction; tolerates the cheap tier.
    Extract,
    /// Text embedding.
    Embed,
}

impl UseCase {
    /// Parses a lowercase string form (`chat`, `code`, `reasoning`,
    /// `research`, `summarize`, `extract`, `embed`). Case-insensitive.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "chat" => Some(Self::Chat),
            "code" => Some(Self::Code),
            "reasoning" | "reason" => Some(Self::Reasoning),
            "research" | "deep-research" => Some(Self::Research),
            "summarize" | "summary" | "summarise" => Some(Self::Summarize),
            "extract" | "extraction" => Some(Self::Extract),
            "embed" | "embedding" => Some(Self::Embed),
            _ => None,
        }
    }

    /// Every valid string form, in canonical order. Used by handlers to build
    /// the error message when [`UseCase::parse`] rejects an unknown use case.
    pub const ALL: &'static [&'static str] = &[
        "chat", "code", "reasoning", "research", "summarize", "extract", "embed",
    ];

    /// Lowercase label, the inverse of [`UseCase::parse`].
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Code => "code",
            Self::Reasoning => "reasoning",
            Self::Research => "research",
            Self::Summarize => "summarize",
            Self::Extract => "extract",
            Self::Embed => "embed",
        }
    }

    /// The registry modality this use case resolves to. v1 maps every text
    /// use case to [`ModelModality::Text`] and `Embed` to `Text` as well
    /// (text embedding); the field on [`RouteIntent`] is what carries other
    /// modalities forward when they land.
    pub fn modality(&self) -> ModelModality {
        ModelModality::Text
    }

    /// Whether this use case biases toward the strong tier when the
    /// cost-quality knob is neutral.
    fn favors_strong(&self) -> bool {
        matches!(self, Self::Reasoning | Self::Code | Self::Research)
    }
}

/// Per-request cost cap. Enforced at discovery time — a model whose estimated
/// cost for the request exceeds the cap is dropped before provider selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Budget {
    /// Hard cap, in the smallest TNZO unit, on the estimated cost of this one
    /// call.
    PerRequestTnzo(u128),
    /// No per-request cap. A per-DID [`BudgetGate`] may still reject the call.
    None,
}

impl Budget {
    /// Returns the cap value if this is a bounded budget.
    fn cap(&self) -> Option<u128> {
        match self {
            Budget::PerRequestTnzo(v) => Some(*v),
            Budget::None => None,
        }
    }
}

/// Coarse model quality band. The cost-quality knob partitions candidates into
/// these two tiers; `quality_floor` on the intent then drops anything below the
/// requested tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QualityTier {
    /// Smaller / cheaper models.
    Cheap,
    /// Larger / stronger models.
    Strong,
}

/// A routing intent: what the caller wants, without naming a model.
#[derive(Debug, Clone)]
pub struct RouteIntent {
    /// The task the model is for.
    pub use_case: UseCase,
    /// The modality to route within. v1 handlers set this from `use_case`;
    /// it is carried explicitly so non-text modalities need only a data
    /// change, not a contract change.
    pub modality: ModelModality,
    /// Per-request cost cap.
    pub budget: Budget,
    /// Reject any model below this tier. `None` accepts either tier.
    pub quality_floor: Option<QualityTier>,
    /// Cost↔quality knob in `[0.0, 1.0]`: `0.0` = cheapest acceptable,
    /// `1.0` = strongest acceptable. Values in between shift the cut point
    /// between the cheap and strong tiers.
    pub optimize: f32,
    /// Estimated input tokens for cost estimation. Handlers derive this from
    /// the prompt.
    pub est_input_tokens: u64,
    /// Estimated output tokens for cost estimation.
    pub est_output_tokens: u64,
    /// Payer DID. When set and a [`BudgetGate`] is wired, the per-DID
    /// rolling-window cap is enforced in addition to the per-request cap.
    pub payer_did: Option<String>,
    /// Payer wallet address. When set and a [`BalanceProvider`] is wired, the
    /// payer's on-chain TNZO balance is a hard ceiling: models whose estimated
    /// cost exceeds it are dropped during discovery.
    pub payer_address: Option<Address>,
}

impl RouteIntent {
    /// Builds a text-modality intent for `use_case` with a neutral
    /// cost-quality knob and no quality floor. Token estimates default to a
    /// short request; callers override them with [`RouteIntent::with_tokens`].
    pub fn new(use_case: UseCase, budget: Budget) -> Self {
        Self {
            use_case,
            modality: use_case.modality(),
            budget,
            quality_floor: None,
            optimize: if use_case.favors_strong() { 0.7 } else { 0.5 },
            est_input_tokens: 256,
            est_output_tokens: 256,
            payer_did: None,
            payer_address: None,
        }
    }

    /// Sets the token estimates used for cost estimation.
    #[must_use]
    pub fn with_tokens(mut self, input: u64, output: u64) -> Self {
        self.est_input_tokens = input;
        self.est_output_tokens = output;
        self
    }

    /// Sets the cost-quality knob, clamped to `[0.0, 1.0]`.
    #[must_use]
    pub fn with_optimize(mut self, optimize: f32) -> Self {
        self.optimize = optimize.clamp(0.0, 1.0);
        self
    }

    /// Sets the quality floor.
    #[must_use]
    pub fn with_quality_floor(mut self, floor: QualityTier) -> Self {
        self.quality_floor = Some(floor);
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
    pub fn with_payer_address(mut self, address: Address) -> Self {
        self.payer_address = Some(address);
        self
    }
}

/// The outcome of running the selection pipeline: the chosen model plus the
/// ordered alternatives and a human-readable trace of why.
#[derive(Debug, Clone)]
pub struct RouteDecision {
    /// The selected model.
    pub model_id: String,
    /// The tier the selected model sits in.
    pub tier: QualityTier,
    /// Estimated cost for the request against the selected model's pricing.
    pub estimated_cost: u128,
    /// Ordered alternative `model_id`s to try if the selected model has no
    /// healthy provider. Same tier, same budget admission.
    pub fallback_chain: Vec<String>,
    /// Human-readable selection trace.
    pub reason: String,
}

/// Per-DID rolling-window budget gate.
///
/// The meta-router is decoupled from `tenzro-payments` — the node implements
/// this trait by adapting its `SpendingPolicyResolver`, so the model crate does
/// not gain a payments dependency. Returning `Ok(())` admits the spend;
/// returning `Err` rejects it. `Ok(())` is also the correct answer when the DID
/// has no policy attached (the per-request cap still applies).
pub trait BudgetGate: Send + Sync {
    /// Checks whether a spend of `amount` (smallest TNZO unit) by `payer_did`
    /// is within the DID's rolling-window budget.
    fn check(&self, payer_did: &str, amount: u128) -> Result<()>;
}

/// Payer wallet-balance ceiling.
///
/// The meta-router is decoupled from `tenzro-token` — the node implements this
/// trait against `TnzoToken::balance_of`, so the model crate gains no token
/// dependency. Returns the on-chain TNZO balance (smallest unit) for
/// `payer_address`. A model whose estimated cost exceeds this balance is never
/// selected.
pub trait BalanceProvider: Send + Sync {
    /// Returns the payer's spendable TNZO balance in the smallest unit.
    fn balance_of(&self, payer_address: &Address) -> u128;
}

/// A model candidate scored during selection.
struct Candidate {
    model: ModelInfo,
    tier: QualityTier,
    est_cost: u128,
    /// Measured average cost from usage history, if any. `None` sorts after
    /// any `Some` (cold-start penalty).
    measured_cost: Option<u64>,
    /// Measured average latency, for tie-breaking within equal cost.
    measured_latency: Option<u64>,
}

/// Resolves an intent to a model and dispatches it through the inference
/// router. See the module docs for the two-tier design.
pub struct MetaRouter {
    registry: Arc<ModelRegistry>,
    usage: Arc<UsageTracker>,
    router: Arc<InferenceRouter>,
    budget_gate: Option<Arc<dyn BudgetGate>>,
    balance_provider: Option<Arc<dyn BalanceProvider>>,
}

impl MetaRouter {
    /// Builds a meta-router over the shared registry, usage tracker, and
    /// inference router. No per-DID budget gate is wired; attach one with
    /// [`MetaRouter::with_budget_gate`].
    pub fn new(
        registry: Arc<ModelRegistry>,
        usage: Arc<UsageTracker>,
        router: Arc<InferenceRouter>,
    ) -> Self {
        Self {
            registry,
            usage,
            router,
            budget_gate: None,
            balance_provider: None,
        }
    }

    /// Attaches a per-DID rolling-window [`BudgetGate`]. When set and the
    /// intent carries a `payer_did`, the gate is a hard admission check on top
    /// of the per-request budget pre-filter.
    #[must_use]
    pub fn with_budget_gate(mut self, gate: Arc<dyn BudgetGate>) -> Self {
        self.budget_gate = Some(gate);
        self
    }

    /// Attaches a [`BalanceProvider`]. When set and the intent carries a
    /// `payer_address`, a model whose estimated cost exceeds the payer's TNZO
    /// balance is dropped during discovery — a hard affordability ceiling.
    #[must_use]
    pub fn with_balance_provider(mut self, provider: Arc<dyn BalanceProvider>) -> Self {
        self.balance_provider = Some(provider);
        self
    }

    /// Runs the selection pipeline and returns a [`RouteDecision`] without
    /// dispatching. Discovery only — no spend, no provider call.
    ///
    /// # Errors
    ///
    /// - [`ModelError::NoProvidersAvailable`] when no active model in the
    ///   modality survives quality and budget filtering.
    /// - [`ModelError::RoutingError`] when the per-DID budget gate rejects the
    ///   estimated cost.
    pub fn route(&self, intent: &RouteIntent) -> Result<RouteDecision> {
        // 1–2. Discover active candidates in the intent's modality.
        let filter = ModelFilter::new()
            .with_modality(intent.modality)
            .with_status(ModelStatus::Active);
        let models = self.registry.search_models(&filter);
        if models.is_empty() {
            return Err(ModelError::NoProvidersAvailable(format!(
                "no active {:?} model for use case {}",
                intent.modality,
                intent.use_case.as_str()
            )));
        }

        // 3. Tier every candidate and 4. estimate + budget pre-filter.
        let cap = intent.budget.cap();

        // Wallet-balance ceiling: the payer's spendable TNZO balance, read once
        // when both an address and a provider are present. A model whose
        // estimated cost exceeds this is unaffordable and dropped in discovery.
        let balance_ceiling = match (&intent.payer_address, &self.balance_provider) {
            (Some(addr), Some(provider)) => Some(provider.balance_of(addr)),
            _ => None,
        };

        let mut candidates: Vec<Candidate> = Vec::new();
        for model in models {
            let tier = quality_tier(&model);

            // Quality floor: drop anything below the requested tier.
            if let Some(floor) = intent.quality_floor
                && tier < floor
            {
                continue;
            }

            let est_cost = estimate_cost(
                &model,
                intent.est_input_tokens,
                intent.est_output_tokens,
            );

            // Per-request budget pre-filter.
            if let Some(cap) = cap
                && est_cost > cap
            {
                continue;
            }

            // Wallet-balance ceiling: never route to a model the payer can't
            // afford.
            if let Some(balance) = balance_ceiling
                && est_cost > balance
            {
                continue;
            }

            let stats = self.usage.get_model_stats(&model.model_id);
            let measured_cost = stats.as_ref().map(|s| s.avg_cost());
            let measured_latency = stats.as_ref().map(|s| s.avg_latency_ms());

            candidates.push(Candidate {
                model,
                tier,
                est_cost,
                measured_cost,
                measured_latency,
            });
        }

        if candidates.is_empty() {
            let affordability = balance_ceiling
                .map(|b| format!(" (wallet balance {b})"))
                .unwrap_or_default();
            return Err(ModelError::NoProvidersAvailable(format!(
                "no {:?} model fits budget/quality for use case {}{affordability}",
                intent.modality,
                intent.use_case.as_str()
            )));
        }

        // Resolve the target tier from the cost-quality knob, then keep only
        // candidates in that tier if any exist; otherwise fall back to the
        // whole survivor set (so a budget that only affords cheap models still
        // routes even when the knob leans strong).
        let target = target_tier(intent);
        let has_target = candidates.iter().any(|c| c.tier == target);
        if has_target {
            candidates.retain(|c| c.tier == target);
        }

        // 5. Score: cheapest measured cost wins within the tier; models with
        // no history sort after models with a record; latency breaks ties.
        candidates.sort_by(|a, b| cost_key(a).cmp(&cost_key(b)));

        let best = &candidates[0];

        // 6. Per-DID rolling-window budget gate.
        if let (Some(did), Some(gate)) = (&intent.payer_did, &self.budget_gate) {
            gate.check(did, best.est_cost).map_err(|e| {
                ModelError::RoutingError(format!(
                    "per-DID budget gate rejected {}: {e}",
                    best.model_id
                ))
            })?;
        }

        let fallback_chain: Vec<String> = candidates
            .iter()
            .skip(1)
            .map(|c| c.model.model_id.clone())
            .collect();

        let reason = format!(
            "use_case={} modality={:?} tier={:?} optimize={:.2} \
             est_cost={} survivors={} (picked {} at {}; {} fallback{})",
            intent.use_case.as_str(),
            intent.modality,
            best.tier,
            intent.optimize,
            best.est_cost,
            candidates.len(),
            best.model.model_id,
            best.measured_cost
                .map(|c| format!("measured avg cost {c}"))
                .unwrap_or_else(|| "no usage history".to_string()),
            fallback_chain.len(),
            if fallback_chain.len() == 1 { "" } else { "s" },
        );

        Ok(RouteDecision {
            model_id: best.model.model_id.clone(),
            tier: best.tier,
            estimated_cost: best.est_cost,
            fallback_chain,
            reason,
        })
    }

    /// Resolves an intent to a model, then selects a provider through the
    /// inference router. Walks the cross-model fallback chain if the chosen
    /// model has no healthy provider.
    ///
    /// Returns the resolved `model_id` and the provider [`Address`] chosen by
    /// the inference router, plus the full [`RouteDecision`] for observability.
    ///
    /// # Errors
    ///
    /// Propagates [`MetaRouter::route`] errors. Returns
    /// [`ModelError::NoProvidersAvailable`] naming every model tried when the
    /// whole chain lacks a healthy provider.
    pub fn route_and_select(
        &self,
        intent: &RouteIntent,
        requester: Address,
    ) -> Result<(String, Address, RouteDecision)> {
        let decision = self.route(intent)?;

        // Build the ordered list of models to try: the winner first, then the
        // fallback chain.
        let mut chain = Vec::with_capacity(1 + decision.fallback_chain.len());
        chain.push(decision.model_id.clone());
        chain.extend(decision.fallback_chain.iter().cloned());

        let max_price = intent
            .budget
            .cap()
            .map(|c| c.min(u64::MAX as u128) as u64)
            .unwrap_or(u64::MAX);

        let mut tried: Vec<String> = Vec::new();
        for model_id in &chain {
            let request = InferenceRequest::new(
                model_id.clone(),
                requester.clone(),
                Vec::new(),
                max_price,
            );
            match self.router.route_request(&request) {
                Ok(provider) => {
                    return Ok((model_id.clone(), provider, decision));
                }
                Err(ModelError::NoProvidersAvailable(_)) => {
                    tried.push(model_id.clone());
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Err(ModelError::NoProvidersAvailable(format!(
            "no healthy provider for use case {} across models: {}",
            intent.use_case.as_str(),
            tried.join(", ")
        )))
    }
}

/// Sort key: `(measured_cost_or_max, est_cost, measured_latency_or_max)`.
/// Models with usage history and lower measured cost sort first; models with no
/// history fall back to the pricing estimate and sort behind any measured
/// model at equal estimate.
fn cost_key(c: &Candidate) -> (u64, u128, u64) {
    (
        c.measured_cost.unwrap_or(u64::MAX),
        c.est_cost,
        c.measured_latency.unwrap_or(u64::MAX),
    )
}

/// Estimates the cost of a request against a model's pricing, in smallest TNZO
/// unit. Honors the `minimum_price` floor.
fn estimate_cost(model: &ModelInfo, input_tokens: u64, output_tokens: u64) -> u128 {
    let p = &model.pricing;
    let input = (p.price_per_input_token as u128).saturating_mul(input_tokens as u128);
    let output = (p.price_per_output_token as u128).saturating_mul(output_tokens as u128);
    input
        .saturating_add(output)
        .max(p.minimum_price as u128)
}

/// Classifies a model into a quality tier from its declared parameters. A
/// larger parameter count, a bigger context window, or an explicit
/// `reasoning`/`code` capability tag lifts a model into the strong tier.
fn quality_tier(model: &ModelInfo) -> QualityTier {
    const STRONG_PARAM_FLOOR: u64 = 30_000_000_000; // 30B
    const STRONG_CTX_FLOOR: u32 = 32_768;

    let big = model
        .parameters
        .parameter_count
        .is_some_and(|c| c >= STRONG_PARAM_FLOOR);
    let long_ctx = model.parameters.context_window >= STRONG_CTX_FLOOR;
    let capable = model.parameters.capabilities.iter().any(|c| {
        let c = c.to_lowercase();
        c.contains("reasoning") || c.contains("code")
    });

    if big || long_ctx || capable {
        QualityTier::Strong
    } else {
        QualityTier::Cheap
    }
}

/// Resolves the target tier from the cost-quality knob. Below the cut point
/// (biased down for use cases that favor strong) we aim cheap; at or above it,
/// strong.
fn target_tier(intent: &RouteIntent) -> QualityTier {
    // Use cases that favor strong lower the bar to reach the strong tier.
    let cut = if intent.use_case.favors_strong() {
        0.4
    } else {
        0.6
    };
    if intent.optimize >= cut {
        QualityTier::Strong
    } else {
        QualityTier::Cheap
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::model::{ModelParameters, PricingConfig};

    fn model(id: &str, params: u64, ctx: u32, in_p: u64, out_p: u64) -> ModelInfo {
        let mut m = ModelInfo::new(
            id.to_string(),
            id.to_string(),
            "1".to_string(),
            ModelModality::Text,
            Address::new([1; 32]),
        );
        m.status = ModelStatus::Active;
        m.parameters = ModelParameters {
            parameter_count: Some(params),
            context_window: ctx,
            ..Default::default()
        };
        m.pricing = PricingConfig {
            price_per_input_token: in_p,
            price_per_output_token: out_p,
            minimum_price: 1,
            ..Default::default()
        };
        m
    }

    fn router_stack() -> (Arc<ModelRegistry>, Arc<UsageTracker>, Arc<InferenceRouter>) {
        let registry = Arc::new(ModelRegistry::new());
        let usage = Arc::new(UsageTracker::new());
        let provider_manager = Arc::new(crate::provider::ProviderManager::new());
        let router = Arc::new(InferenceRouter::new(provider_manager));
        (registry, usage, router)
    }

    #[test]
    fn tiering_by_params() {
        assert_eq!(quality_tier(&model("s", 70_000_000_000, 8192, 1, 1)), QualityTier::Strong);
        assert_eq!(quality_tier(&model("c", 3_000_000_000, 8192, 1, 1)), QualityTier::Cheap);
    }

    #[test]
    fn empty_registry_errors() {
        let (registry, usage, router) = router_stack();
        let mr = MetaRouter::new(registry, usage, router);
        let intent = RouteIntent::new(UseCase::Chat, Budget::None);
        assert!(matches!(mr.route(&intent), Err(ModelError::NoProvidersAvailable(_))));
    }

    #[test]
    fn budget_prefilter_drops_expensive() {
        let (registry, usage, router) = router_stack();
        // Cheap model: 1+1 per token. Expensive model: 1000 per token.
        registry.register_model(model("cheap", 3_000_000_000, 8192, 1, 1)).unwrap();
        registry.register_model(model("pricey", 3_000_000_000, 8192, 1000, 1000)).unwrap();
        let mr = MetaRouter::new(registry, usage, router);
        // Budget only affords the cheap model at 256+256 tokens.
        let intent = RouteIntent::new(UseCase::Chat, Budget::PerRequestTnzo(1000))
            .with_tokens(256, 256);
        let d = mr.route(&intent).unwrap();
        assert_eq!(d.model_id, "cheap");
    }

    #[test]
    fn quality_floor_filters() {
        let (registry, usage, router) = router_stack();
        registry.register_model(model("cheap", 3_000_000_000, 8192, 1, 1)).unwrap();
        registry.register_model(model("strong", 70_000_000_000, 8192, 2, 2)).unwrap();
        let mr = MetaRouter::new(registry, usage, router);
        let intent = RouteIntent::new(UseCase::Reasoning, Budget::None)
            .with_quality_floor(QualityTier::Strong)
            .with_tokens(10, 10);
        let d = mr.route(&intent).unwrap();
        assert_eq!(d.model_id, "strong");
        assert_eq!(d.tier, QualityTier::Strong);
    }

    #[test]
    fn cheapest_wins_within_tier() {
        let (registry, usage, router) = router_stack();
        registry.register_model(model("a", 3_000_000_000, 8192, 5, 5)).unwrap();
        registry.register_model(model("b", 3_000_000_000, 8192, 2, 2)).unwrap();
        let mr = MetaRouter::new(registry, usage, router);
        let intent = RouteIntent::new(UseCase::Chat, Budget::None).with_tokens(10, 10);
        let d = mr.route(&intent).unwrap();
        assert_eq!(d.model_id, "b");
        assert_eq!(d.fallback_chain, vec!["a".to_string()]);
    }

    struct DenyGate;
    impl BudgetGate for DenyGate {
        fn check(&self, _did: &str, _amount: u128) -> Result<()> {
            Err(ModelError::Other("daily budget exhausted".into()))
        }
    }

    #[test]
    fn research_parses_and_favors_strong() {
        assert_eq!(UseCase::parse("research"), Some(UseCase::Research));
        assert_eq!(UseCase::parse("Deep-Research"), Some(UseCase::Research));
        assert_eq!(UseCase::Research.as_str(), "research");
        assert!(UseCase::ALL.contains(&"research"));
        // A neutral knob on a strong-favoring use case reaches the strong tier.
        let (registry, usage, router) = router_stack();
        registry.register_model(model("cheap", 3_000_000_000, 8192, 1, 1)).unwrap();
        registry.register_model(model("strong", 70_000_000_000, 8192, 2, 2)).unwrap();
        let mr = MetaRouter::new(registry, usage, router);
        let intent = RouteIntent::new(UseCase::Research, Budget::None)
            .with_optimize(0.5)
            .with_tokens(10, 10);
        let d = mr.route(&intent).unwrap();
        assert_eq!(d.tier, QualityTier::Strong);
        assert_eq!(d.model_id, "strong");
    }

    #[test]
    fn per_did_gate_rejects() {
        let (registry, usage, router) = router_stack();
        registry.register_model(model("cheap", 3_000_000_000, 8192, 1, 1)).unwrap();
        let mr = MetaRouter::new(registry, usage, router)
            .with_budget_gate(Arc::new(DenyGate));
        let intent = RouteIntent::new(UseCase::Chat, Budget::None)
            .with_tokens(10, 10)
            .with_payer_did("did:tenzro:machine:test");
        assert!(matches!(mr.route(&intent), Err(ModelError::RoutingError(_))));
    }

    struct FixedBalance(u128);
    impl BalanceProvider for FixedBalance {
        fn balance_of(&self, _addr: &Address) -> u128 {
            self.0
        }
    }

    #[test]
    fn wallet_ceiling_drops_unaffordable_but_routes_cheaper() {
        let (registry, usage, router) = router_stack();
        // Cheap: 1+1 per token → 20 at 10+10 tokens. Pricey: 1000 per token.
        registry.register_model(model("cheap", 3_000_000_000, 8192, 1, 1)).unwrap();
        registry.register_model(model("pricey", 70_000_000_000, 8192, 1000, 1000)).unwrap();
        // Balance affords the cheap model but not the pricey one.
        let mr = MetaRouter::new(registry, usage, router)
            .with_balance_provider(Arc::new(FixedBalance(100)));
        let intent = RouteIntent::new(UseCase::Reasoning, Budget::None)
            .with_optimize(1.0)
            .with_tokens(10, 10)
            .with_payer_address(Address::new([9; 32]));
        let d = mr.route(&intent).unwrap();
        assert_eq!(d.model_id, "cheap");
        assert!(d.fallback_chain.is_empty());
    }

    #[test]
    fn wallet_ceiling_rejects_when_nothing_affordable() {
        let (registry, usage, router) = router_stack();
        registry.register_model(model("pricey", 3_000_000_000, 8192, 1000, 1000)).unwrap();
        let mr = MetaRouter::new(registry, usage, router)
            .with_balance_provider(Arc::new(FixedBalance(1)));
        let intent = RouteIntent::new(UseCase::Chat, Budget::None)
            .with_tokens(10, 10)
            .with_payer_address(Address::new([9; 32]));
        assert!(matches!(mr.route(&intent), Err(ModelError::NoProvidersAvailable(_))));
    }
}
