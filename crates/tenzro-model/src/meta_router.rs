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
//!
//! ## Declared tier vs measured difficulty
//!
//! Two scoring paths coexist, and which one runs depends on the evidence
//! available, not on configuration:
//!
//! - **Declared tier.** With no prompt embedding, or in a prompt neighbourhood
//!   nothing has served yet, candidates are partitioned into
//!   [`QualityTier::Cheap`] / [`QualityTier::Strong`] from declared metadata
//!   (parameter count, context window, capability tags) and the cost-quality
//!   knob picks the tier. Cheapest wins within it.
//! - **Measured difficulty.** When the intent carries a prompt (or a
//!   pre-computed embedding) and a [`DifficultyIndex`] is wired, the prompt is
//!   placed in a cluster and each candidate's *observed* error rate for that
//!   cluster is blended with its cost by the same knob. This is what lets a
//!   cheap model win a hard-looking request it has actually been resolving, and
//!   lose an easy-looking one it has been escalating.
//!
//! `quality_floor` is a caller instruction and is honored in both paths.
//! Feedback arrives through [`MetaRouter::record_outcome`].

use crate::difficulty::{DifficultyIndex, PromptEmbedder, RouteOutcome};
use crate::error::{ModelError, Result};
use crate::registry::{ModelFilter, ModelRegistry};
use crate::routing::InferenceRouter;
use crate::usage::UsageTracker;
use tenzro_types::model::{
    AdvertisedCapacity, InferenceRequest, ModelInfo, ModelModality, ModelStatus,
};
use tenzro_types::primitives::Address;
use tracing::debug;

use std::collections::HashMap;
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
        "chat",
        "code",
        "reasoning",
        "research",
        "summarize",
        "extract",
        "embed",
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

/// Where a request is allowed to run.
///
/// `budget` is a cost constraint and was the only thing standing in for this
/// one: setting it to zero happens to exclude paid remote offers. That is not
/// the same guarantee — a free or subsidised provider satisfies a zero budget
/// while still receiving the prompt. An application that promises its users
/// their data stays on their own hardware needs to say so directly, and have it
/// enforced rather than implied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Locality {
    /// Either this machine or a network provider, cheapest acceptable wins.
    #[default]
    Any,
    /// This machine only. A request that cannot be served locally fails rather
    /// than falling back to the network — failing closed is the entire point,
    /// since a silent fallback is exactly the outcome the caller asked to avoid.
    LocalOnly,
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
    /// Where this request may run. Defaults to [`Locality::Any`].
    pub locality: Locality,
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
    /// The prompt this intent will run. Used only to place the request in a
    /// difficulty cluster; never sent anywhere by the router itself.
    pub prompt: Option<String>,
    /// Pre-computed prompt embedding. Set directly by callers that already hold
    /// one, or filled by [`MetaRouter::route_intent`] from `prompt` via the
    /// wired [`PromptEmbedder`].
    pub prompt_embedding: Option<Vec<f32>>,
    /// The conversation prefix to match against providers' advertised warm
    /// caches, hashed with the same rolling scheme they use.
    ///
    /// Deliberately **not** `prompt`. `prompt` is the last user turn, chosen
    /// for difficulty clustering because earlier turns are context that would
    /// blur the placement. Cache affinity needs the opposite: the whole
    /// conversation from byte 0, because the rolling hash is position
    /// dependent and providers warm every message joined by `\n`. Matching on
    /// the last turn alone can never share run 0 with what a provider holds,
    /// so every match scored zero — the multi-turn and shared-system-prompt
    /// cases the feature exists for were exactly the ones it could not serve.
    ///
    /// `None` falls back to `prompt`, which is correct for a single-turn
    /// conversation (the two are then the same bytes) and is why the fallback
    /// is safe rather than a silent reintroduction of the mismatch.
    pub affinity_prefix: Option<String>,
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
            locality: Locality::default(),
            optimize: if use_case.favors_strong() { 0.7 } else { 0.5 },
            est_input_tokens: 256,
            est_output_tokens: 256,
            payer_did: None,
            payer_address: None,
            prompt: None,
            prompt_embedding: None,
            affinity_prefix: None,
        }
    }

    /// Sets the conversation prefix used for cache-affinity matching. Callers
    /// with a multi-turn conversation should set this to every message's
    /// content joined by `\n`, matching what providers hash when they record
    /// a warm prompt.
    #[must_use]
    pub fn with_affinity_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.affinity_prefix = Some(prefix.into());
        self
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
    /// Require that this request never leaves the local machine.
    pub fn local_only(mut self) -> Self {
        self.locality = Locality::LocalOnly;
        self
    }

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

    /// Sets the prompt used for difficulty clustering.
    #[must_use]
    pub fn with_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    /// Supplies a pre-computed prompt embedding, skipping the embedder.
    #[must_use]
    pub fn with_prompt_embedding(mut self, embedding: Vec<f32>) -> Self {
        self.prompt_embedding = Some(embedding);
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
    /// Difficulty cluster the prompt was placed in, when the intent carried an
    /// embedding and a [`DifficultyIndex`] is wired. Callers must echo this back
    /// to [`MetaRouter::record_outcome`] so the observation lands on the right
    /// cluster.
    pub cluster: Option<u32>,
    /// The selected model's observed error rate for `cluster`. `None` when the
    /// declared-tier path ran.
    pub expected_error: Option<f32>,
    /// The provider that will serve the call and receive the provider share,
    /// when the winner came from a live network offer. `None` means the winner
    /// came from this node's own catalog and the serving provider is resolved
    /// through the inference router — [`MetaRouter::route_and_select`] returns the
    /// authoritative address in both cases.
    pub provider: Option<Address>,
    /// Endpoint to dispatch to, set together with `provider`.
    pub endpoint: Option<String>,
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

/// One provider's live offer to serve a model.
///
/// `model.provider` is the address that serves the request and receives the
/// provider share of the settlement, and `model.pricing` is that provider's own
/// advertised rate — two providers offering the same `model_id` are two offers at
/// two prices, scored independently.
#[derive(Debug, Clone)]
pub struct ModelOffer {
    /// The model as the offering provider describes and prices it.
    pub model: ModelInfo,
    /// JSON-RPC endpoint to dispatch the call to.
    pub endpoint: String,
    /// The serving envelope the offering provider signed into its provider
    /// announcement — warm-prefix summary, concurrency, and whether a
    /// speculative drafter is co-loaded.
    ///
    /// `None` when no unexpired provider announcement has been seen for the
    /// offering peer, which is the honest state at cold start: the model
    /// announcement and the provider announcement ride separate topics and
    /// separate TTLs, so an offer can be live before its provider envelope
    /// arrives. Selection treats `None` as "nothing warm, nothing known"
    /// rather than as a penalty, so an offer is never demoted for a gossip
    /// race it did not cause.
    pub capacity: Option<AdvertisedCapacity>,
}

/// The set of model offers live on the network right now.
///
/// Providers gossip signed announcements carrying capabilities, their own price,
/// and a TTL; each node keeps the unexpired set. Implementing this trait hands
/// that set to selection, so routing considers what the network is serving at
/// this moment rather than only what is in this node's own catalog — a node with
/// an empty catalog still routes. The model crate gains no network dependency:
/// the node adapts its announcement map.
pub trait NetworkCatalog: Send + Sync {
    /// Returns every unexpired offer in `modality`. Called once per routing
    /// decision, so implementations should read an in-memory map rather than
    /// hitting storage or the network.
    fn live_offers(&self, modality: ModelModality) -> Vec<ModelOffer>;
}

/// Whether a provider is idle enough for speculative decoding to pay: below
/// half its declared admission ceiling.
///
/// `max == 0` means the provider declared no ceiling, which is *unknown*, not
/// idle — see [`Candidate::speculation_pays`].
///
/// `div_ceil` rather than `/ 2` so a one-slot provider can qualify while
/// genuinely idle: plain truncation makes `1 / 2 == 0`, and `active < 0` is
/// unsatisfiable, which locked every single-slot MTP provider out of the
/// preference no matter how idle it was.
///
/// Written as a comparison against `max` rather than `active * 2 < max`
/// because both values come off a gossiped announcement — a peer can publish
/// any `u32`, and the multiplication would overflow and panic in debug builds.
pub(crate) fn idle_enough(active: u32, max: u32) -> bool {
    max > 0 && active < max.div_ceil(2)
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
    /// Observed error rate for the prompt's difficulty cluster. `None` when no
    /// cluster was resolved.
    expected_error: Option<f32>,
    /// Dispatch endpoint when this candidate came from a live network offer.
    /// `None` for a candidate from this node's own catalog, whose serving provider
    /// is resolved through the inference router instead.
    endpoint: Option<String>,
    /// The offering provider's signed serving envelope, when this candidate
    /// came from a network offer whose provider announcement is also live.
    /// Carries the warm-prefix summary and concurrency that
    /// [`Candidate::warm_match`] and [`Candidate::saturated`] read.
    capacity: Option<AdvertisedCapacity>,
}

impl Candidate {
    /// Bytes of this prompt the offering provider already holds warm, via the
    /// longest chained-run match against its advertised radix summary.
    ///
    /// Zero for a local-catalog candidate, for a provider with no live
    /// envelope, and for an empty prompt — in each case there is no evidence
    /// of a warm prefix, which is the same routing outcome as a genuine miss.
    fn warm_match(&self, prompt_run_hashes: &[u64]) -> u32 {
        self.capacity
            .as_ref()
            .map(|c| c.prefix_cache.longest_match_len(prompt_run_hashes))
            .unwrap_or(0)
    }

    /// Whether the offering provider is at its own declared admission ceiling.
    ///
    /// A saturated provider will queue the call behind work already in flight,
    /// so its measured latency understates what this request would actually
    /// wait. `max_concurrent_requests == 0` means the provider declined to
    /// declare a ceiling and is never treated as saturated.
    fn saturated(&self) -> bool {
        self.capacity.as_ref().is_some_and(|c| {
            c.max_concurrent_requests > 0 && c.active_requests >= c.max_concurrent_requests
        })
    }

    /// Whether speculative decoding is both available here and likely to pay.
    ///
    /// A co-located drafter is worth roughly 1.7-2x on decode at low
    /// concurrency, and *inverts into a slowdown* once the provider is
    /// batching heavily — so availability alone is not enough to prefer it.
    /// The gate is idleness: below half the declared admission ceiling.
    ///
    /// An undeclared ceiling (`0`) counts as **unknown, not idle**. Reading it
    /// as "no limit, therefore never busy" made a missing field the
    /// most-preferred state, so a peer that declared nothing outranked one
    /// that answered honestly — and `0` is also the serde default, so a
    /// truncated announcement landed in the winning bucket for free. It is
    /// also what [`tenzro_types::model::ProviderCapacity::has_capacity`]
    /// already treats as unusable, so this keeps the two readings of the same
    /// field consistent.
    fn speculation_pays(&self) -> bool {
        self.capacity.as_ref().is_some_and(|c| {
            c.mtp_enabled && idle_enough(c.active_requests, c.max_concurrent_requests)
        })
    }
}

/// Resolves an intent to a model and dispatches it through the inference
/// router. See the module docs for the two-tier design.
pub struct MetaRouter {
    registry: Arc<ModelRegistry>,
    usage: Arc<UsageTracker>,
    router: Arc<InferenceRouter>,
    budget_gate: Option<Arc<dyn BudgetGate>>,
    balance_provider: Option<Arc<dyn BalanceProvider>>,
    difficulty: Option<Arc<DifficultyIndex>>,
    embedder: Option<Arc<dyn PromptEmbedder>>,
    network_catalog: Option<Arc<dyn NetworkCatalog>>,
    /// Operator task→model overrides (use-case string → model id). A Cortex
    /// primitive: the operator pins which served model handles which kind of
    /// task. Applied only when the named model is an available candidate for
    /// the request; otherwise intelligent selection stands.
    task_models: HashMap<String, String>,
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
            difficulty: None,
            embedder: None,
            network_catalog: None,
            task_models: HashMap::new(),
        }
    }

    /// Attaches operator task→model overrides (a Cortex primitive): a map from
    /// use-case string (`code`, `reasoning`, …) to the model id the operator
    /// wants that kind of task served by. An override wins outright when the
    /// named model survives filtering for the request; use cases not listed —
    /// and overrides naming a model that is unavailable or unaffordable — fall
    /// back to intelligent (benchmark prior + measured difficulty) selection.
    #[must_use]
    pub fn with_routing_preferences(mut self, task_models: HashMap<String, String>) -> Self {
        self.task_models = task_models;
        self
    }

    /// Attaches the live [`NetworkCatalog`]. Without it, selection sees only this
    /// node's own catalog, which makes routing depend on what the operator
    /// happens to have registered locally.
    #[must_use]
    pub fn with_network_catalog(mut self, catalog: Arc<dyn NetworkCatalog>) -> Self {
        self.network_catalog = Some(catalog);
        self
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

    /// Attaches the measured-difficulty index. Without it the router uses the
    /// declared-tier path for every request.
    #[must_use]
    pub fn with_difficulty_index(mut self, index: Arc<DifficultyIndex>) -> Self {
        self.difficulty = Some(index);
        self
    }

    /// Attaches a [`PromptEmbedder`] so [`MetaRouter::route_intent`] can derive
    /// an embedding from `RouteIntent::prompt`. Callers that supply
    /// `prompt_embedding` directly do not need one.
    #[must_use]
    pub fn with_prompt_embedder(mut self, embedder: Arc<dyn PromptEmbedder>) -> Self {
        self.embedder = Some(embedder);
        self
    }

    /// The wired difficulty index, if any. Exposed so handlers can report
    /// cluster counts and record outcomes without holding a second reference.
    pub fn difficulty_index(&self) -> Option<Arc<DifficultyIndex>> {
        self.difficulty.clone()
    }

    /// Records a serving outcome against the cluster a decision was made in.
    ///
    /// Returns `Ok(false)` when no difficulty index is wired — the caller's
    /// feedback is simply not retained, which is not an error.
    pub fn record_outcome(
        &self,
        model_id: &str,
        cluster: u32,
        outcome: RouteOutcome,
    ) -> Result<bool> {
        match &self.difficulty {
            Some(index) => {
                index.record_outcome(model_id, cluster, outcome)?;
                Ok(true)
            }
            None => Ok(false),
        }
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
        // Discovery spans two sources, scored together: this node's own catalog,
        // and the offers other providers are announcing on the network right now.
        // A cheaper or better-performing remote offer therefore wins on its
        // merits, and a node with an empty local catalog still routes.
        let mut discovered: Vec<(ModelInfo, Option<String>, Option<AdvertisedCapacity>)> = self
            .registry
            .search_models(&filter)
            .into_iter()
            .map(|m| (m, None, None))
            .collect();
        if let Some(catalog) = &self.network_catalog {
            for offer in catalog.live_offers(intent.modality) {
                discovered.push((offer.model, Some(offer.endpoint), offer.capacity));
            }
        }
        if discovered.is_empty() {
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

        // Place the prompt in a difficulty cluster. Assignment also refines the
        // cluster map, so every routed prompt improves future placement.
        let cluster = match (&intent.prompt_embedding, &self.difficulty) {
            (Some(embedding), Some(index)) => index.observe_prompt(embedding),
            _ => None,
        };
        // Measured scoring only takes over once something has served this
        // cluster; before that, declared metadata is the only signal there is.
        let measured = cluster.filter(|c| {
            self.difficulty
                .as_ref()
                .is_some_and(|index| index.has_observations(*c))
        });

        let mut candidates: Vec<Candidate> = Vec::new();
        for (model, endpoint, capacity) in discovered {
            let tier = quality_tier(&model);

            // Locality: drop anything this node does not serve itself.
            //
            // Enforced here, beside the quality floor and the budget cap, so it
            // is a discovery constraint rather than a post-hoc check — a
            // candidate that would leave the machine is never considered, and
            // an empty candidate set fails the request instead of quietly
            // routing it out. `endpoint` is `Some` exactly when the candidate
            // came from a live network offer; a local catalog entry has none.
            if intent.locality == Locality::LocalOnly && endpoint.is_some() {
                continue;
            }

            // Quality floor: drop anything below the requested tier.
            if let Some(floor) = intent.quality_floor
                && tier < floor
            {
                continue;
            }

            let est_cost = estimate_cost(&model, intent.est_input_tokens, intent.est_output_tokens);

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

            let expected_error = match (cluster, &self.difficulty) {
                (Some(c), Some(index)) => Some(index.expected_error(&model.model_id, c)),
                _ => None,
            };

            candidates.push(Candidate {
                model,
                endpoint,
                capacity,
                tier,
                est_cost,
                measured_cost,
                measured_latency,
                expected_error,
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

        // 5. Score. Which path runs depends on the evidence available, not on
        // configuration.
        match measured {
            // Measured: blend each candidate's observed error rate for the
            // prompt's cluster with its cost, weighted by the knob. Declared
            // tier is not consulted — observations supersede metadata.
            Some(_) => {
                let (min_cost, max_cost) =
                    candidates.iter().fold((u128::MAX, 0u128), |(lo, hi), c| {
                        (lo.min(c.est_cost), hi.max(c.est_cost))
                    });
                let span = max_cost.saturating_sub(min_cost);
                let w = intent.optimize;
                candidates.sort_by(|a, b| {
                    let sa = blended_score(a, w, min_cost, span);
                    let sb = blended_score(b, w, min_cost, span);
                    sa.total_cmp(&sb)
                        .then_with(|| cost_key(a).cmp(&cost_key(b)))
                });
            }
            // Declared: resolve the target tier from the cost-quality knob and
            // keep only candidates in that tier if any exist; otherwise fall
            // back to the whole survivor set (so a budget that only affords
            // cheap models still routes even when the knob leans strong).
            // Within the tier, cheapest measured cost wins; models with no
            // history sort after models with a record; latency breaks ties.
            None => {
                let target = target_tier(intent);
                if candidates.iter().any(|c| c.tier == target) {
                    candidates.retain(|c| c.tier == target);
                }
                // Benchmark prior: within the target tier, a model with a
                // higher published capability score for this use case outranks
                // a cheaper one at cold start. Cost orders candidates with no
                // prior and breaks ties — so when no candidate has a prior this
                // is exactly the previous cheapest-first behaviour. The measured
                // path above supersedes this the moment a cluster is observed.
                let uc = intent.use_case.as_str();
                candidates.sort_by(|a, b| {
                    let pa = crate::catalog::capability_prior(&a.model.model_id, uc)
                        .unwrap_or(-1.0);
                    let pb = crate::catalog::capability_prior(&b.model.model_id, uc)
                        .unwrap_or(-1.0);
                    pb.total_cmp(&pa)
                        .then_with(|| cost_key(a).cmp(&cost_key(b)))
                });
            }
        }

        // 5b. Operator override (Cortex primitive). If this node's operator
        // pinned a model for this use case and it survived filtering, it wins
        // outright — moved to the front while the intelligent ordering above
        // still decides the fallback chain behind it. An override naming an
        // unavailable/unaffordable model simply does not match any candidate,
        // so selection falls through to the intelligent winner.
        //
        // Every offer of the pinned model moves to the front, not just the
        // first. Moving one left the *old* head at index 1, and since that
        // candidate names a different model, step 5c's tie-group scan stopped
        // at it immediately — so pinning a model silently disabled cache
        // affinity for it, in exactly the case the operator cared enough
        // about to pin. Partition is stable, so the scored order is preserved
        // both among the pinned offers and among the rest.
        if let Some(pinned) = self.task_models.get(intent.use_case.as_str())
            && candidates.iter().any(|c| &c.model.model_id == pinned)
        {
            let (mut front, back): (Vec<Candidate>, Vec<Candidate>) = candidates
                .into_iter()
                .partition(|c| &c.model.model_id == pinned);
            front.extend(back);
            candidates = front;
        }

        // 5c. Cache affinity and load, within the leading tie-group.
        //
        // Providers gossip a radix summary of the prompt prefixes they hold
        // warm, and [`InferenceRouter::select_provider`] has scored it for
        // years of wall-clock — but only on the local path, because a winning
        // network offer returns its own signed provider and never reaches the
        // inference router at all (see [`MetaRouter::route_and_select`]). In a
        // multi-provider network that is exactly the case that matters: turn
        // *N+1* of a conversation would otherwise land wherever price ordering
        // put it, discarding a prefill the previous turn already paid for.
        //
        // The reorder is deliberately confined to the *leading tie-group* —
        // offers of the same model at the same estimated cost, which are
        // fungible on both axes the scoring above decided. So this can never
        // trade cost or quality for a warm cache; it only breaks a tie the
        // scoring left open, which is the same invariant the inference
        // router's own prefix tie-break keeps.
        let prompt_run_hashes = tenzro_types::prefix_run_hashes(
            intent
                .affinity_prefix
                .as_deref()
                .or(intent.prompt.as_deref())
                .map(str::as_bytes)
                .unwrap_or(&[]),
        );
        if candidates.len() > 1 {
            let head_id = candidates[0].model.model_id.clone();
            let head_cost = candidates[0].est_cost;
            let tie_len = candidates
                .iter()
                .take_while(|c| c.model.model_id == head_id && c.est_cost == head_cost)
                .count();
            if tie_len > 1 {
                // Prefer the longest warm prefix; among equally warm offers
                // prefer one that isn't already at its admission ceiling, since
                // a saturated provider queues the call behind work in flight.
                // `Reverse(i)` keeps the *first* best on equal keys, so a tie
                // with nothing warm leaves the order exactly as scored — an
                // affinity rule that reshuffled equal candidates every turn
                // would defeat its own purpose.
                let best_pos = (0..tie_len).max_by_key(|&i| {
                    let c = &candidates[i];
                    (
                        c.warm_match(&prompt_run_hashes),
                        u8::from(!c.saturated()),
                        u8::from(c.speculation_pays()),
                        std::cmp::Reverse(i),
                    )
                });
                if let Some(pos) = best_pos
                    && pos != 0
                {
                    let chosen = candidates.remove(pos);
                    candidates.insert(0, chosen);
                }
            }
        }

        let best = &candidates[0];
        let warm_bytes = best.warm_match(&prompt_run_hashes);

        // 6. Per-DID rolling-window budget gate.
        if let (Some(did), Some(gate)) = (&intent.payer_did, &self.budget_gate) {
            gate.check(did, best.est_cost).map_err(|e| {
                ModelError::RoutingError(format!(
                    "per-DID budget gate rejected {}: {e}",
                    best.model.model_id
                ))
            })?;
        }

        // One model can appear several times — once from the local catalog and
        // once per provider announcing it — so the chain carries each model id
        // once, in score order, with the winner's own id excluded.
        let mut fallback_chain: Vec<String> = Vec::new();
        for c in candidates.iter().skip(1) {
            let id = &c.model.model_id;
            if id != &best.model.model_id && !fallback_chain.iter().any(|f| f == id) {
                fallback_chain.push(id.clone());
            }
        }

        let scoring = match measured {
            Some(c) => format!(
                "measured cluster={c} expected_error={:.3}",
                best.expected_error.unwrap_or(0.5)
            ),
            None => match cluster {
                Some(c) => format!("declared (cluster={c}, no observations yet)"),
                None => "declared (no prompt embedding)".to_string(),
            },
        };

        // Warm-prefix state rides the reason so an operator can tell a
        // cache-affinity hit from a cold dispatch without instrumenting the
        // provider — the two differ by a whole prefill, and nothing else in
        // the decision distinguishes them.
        let affinity = match (warm_bytes, best.saturated()) {
            (0, false) => String::new(),
            (0, true) => " affinity=cold,provider-saturated".to_string(),
            (w, false) => format!(" affinity=warm({w}B)"),
            (w, true) => format!(" affinity=warm({w}B),provider-saturated"),
        };

        let reason = format!(
            "use_case={} modality={:?} tier={:?} optimize={:.2} \
             est_cost={} survivors={} scoring={scoring}{affinity} \
             (picked {} at {}; {} fallback{})",
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
            cluster,
            expected_error: if measured.is_some() {
                best.expected_error
            } else {
                None
            },
            // A network offer names the address that serves it and takes the
            // provider share; a local catalog entry names its creator, which is
            // not necessarily the serving operator, so it is left unset and
            // resolved through the inference router instead.
            provider: best.endpoint.as_ref().map(|_| best.model.provider),
            endpoint: best.endpoint.clone(),
            reason,
        })
    }

    /// Resolves an intent, embedding its prompt first when one is present and a
    /// [`PromptEmbedder`] is wired. Callers that already hold an embedding can
    /// set [`RouteIntent::prompt_embedding`] and call [`MetaRouter::route`]
    /// directly.
    ///
    /// A failing embedder does not fail the route. Difficulty estimation
    /// sharpens the decision; it is not required to make one, so an embedding
    /// failure degrades to the declared-tier path.
    ///
    /// # Errors
    ///
    /// Propagates every [`MetaRouter::route`] error.
    pub async fn route_intent(&self, intent: &RouteIntent) -> Result<RouteDecision> {
        if intent.prompt_embedding.is_none()
            && let (Some(prompt), Some(embedder)) = (&intent.prompt, &self.embedder)
        {
            match embedder.embed_prompt(prompt).await {
                Ok(embedding) => {
                    let mut filled = intent.clone();
                    filled.prompt_embedding = Some(embedding);
                    return self.route(&filled);
                }
                Err(e) => {
                    debug!("prompt embedding unavailable, routing on declared tier: {e}");
                }
            }
        }
        self.route(intent)
    }

    /// Resolves an intent to a model, then selects a provider through the
    /// inference router. Walks the cross-model fallback chain if the chosen
    /// model has no healthy provider.
    ///
    /// Returns the resolved `model_id`, the address that will serve the call and
    /// take the provider share, and the full [`RouteDecision`] for
    /// observability. When the winner is a live network offer, that address
    /// comes from the signed announcement itself; otherwise the inference router
    /// selects among the operators serving the model locally.
    ///
    /// # Errors
    ///
    /// Propagates [`MetaRouter::route`] errors. Returns
    /// [`ModelError::NoProvidersAvailable`] naming every model tried when the
    /// whole chain lacks a healthy provider.
    pub async fn route_and_select(
        &self,
        intent: &RouteIntent,
        requester: Address,
    ) -> Result<(String, Address, RouteDecision)> {
        let decision = self.route_intent(intent).await?;

        // A network offer was scored on the price and capabilities its provider
        // signed, so that provider is the one to dispatch to and pay — there is
        // nothing left for the inference router to choose.
        if let Some(provider) = decision.provider {
            return Ok((decision.model_id.clone(), provider, decision));
        }

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

        // The prompt is what makes provider selection cache-aware: the
        // inference router derives the incoming prompt's rolling run hashes
        // from `request.input` and matches them against each provider's
        // advertised warm-prefix summary. Passing an empty input — as this did
        // — left `prefix_run_hashes` empty, which zeroes `prefix_bias` and
        // guards off the prefix tie-break, so the whole affinity path was
        // inert from this entry point however warm the providers were.
        //
        // Uses the same bytes as step 5c, for the same reason: the last user
        // turn alone shares no run 0 with what providers warm.
        //
        // Routing reads these bytes and never transmits them — traced: the
        // only wire use of `InferenceRequest.input` is `dispatch_to_provider`,
        // which this path never calls. Dispatch re-sends the original request
        // separately.
        let routing_input: Vec<u8> = intent
            .affinity_prefix
            .as_deref()
            .or(intent.prompt.as_deref())
            .map(|p| p.as_bytes().to_vec())
            .unwrap_or_default();

        let mut tried: Vec<String> = Vec::new();
        for model_id in &chain {
            let request = InferenceRequest::new(
                model_id.clone(),
                requester,
                routing_input.clone(),
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

/// Blended objective, lower is better: `optimize` weights the observed error
/// rate against cost normalized across the surviving candidates. A candidate
/// with no observation in the cluster scores at the neutral prior.
fn blended_score(c: &Candidate, optimize: f32, min_cost: u128, span: u128) -> f32 {
    let norm_cost = if span == 0 {
        0.0
    } else {
        (c.est_cost.saturating_sub(min_cost) as f64 / span as f64) as f32
    };
    let error = c.expected_error.unwrap_or(0.5);
    optimize * error + (1.0 - optimize) * norm_cost
}

/// Estimates the cost of a request against a model's pricing, in smallest TNZO
/// unit. Honors the `minimum_price` floor.
fn estimate_cost(model: &ModelInfo, input_tokens: u64, output_tokens: u64) -> u128 {
    let p = &model.pricing;
    let input = (p.price_per_input_token as u128).saturating_mul(input_tokens as u128);
    let output = (p.price_per_output_token as u128).saturating_mul(output_tokens as u128);
    input.saturating_add(output).max(p.minimum_price as u128)
}

/// Classifies a model into a quality tier from its declared parameters.
///
/// Size is the primary signal; an explicit `reasoning`/`code` capability tag
/// also lifts a model, but only once it is large enough for the claim to mean
/// anything.
///
/// **Context window is deliberately not a signal.** It used to be, as a third
/// independent `||` term at a 32k floor, and that made the classifier
/// degenerate: essentially every model shipping today clears 32k, including
/// 0.8B ones at 131k, so every model classified `Strong`. With every candidate
/// in the strong tier, the cost term then picked the *smallest* model for every
/// rung — `qwen3.5-0.8b` was answering `quality_floor=strong` for code tasks
/// while a 35B sat in the fallback chain. A long window means a model can read
/// a lot at once, not that it can reason; conflating the two inverted the
/// ladder it was meant to order.
fn quality_tier(model: &ModelInfo) -> QualityTier {
    const STRONG_PARAM_FLOOR: u64 = 30_000_000_000; // 30B
    /// A `code`/`reasoning` tag is a publisher's claim, and below this size it
    /// describes what the model was *trained for*, not what it can carry.
    const TAG_PARAM_FLOOR: u64 = 7_000_000_000; // 7B

    let params = model.parameters.parameter_count;
    let big = params.is_some_and(|c| c >= STRONG_PARAM_FLOOR);
    let tagged_and_substantial = params.is_some_and(|c| c >= TAG_PARAM_FLOOR)
        && model.parameters.capabilities.iter().any(|c| {
            let c = c.to_lowercase();
            c.contains("reasoning") || c.contains("code")
        });

    if big || tagged_and_substantial {
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
        // `ModelInfo::new` leaves `model_hash` zero, and `ModelRegistry::
        // register_model` refuses a zero hash outright. Derive a distinct
        // non-zero hash per id, matching `registry.rs::create_test_model`.
        {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(id.as_bytes());
            m.model_hash = tenzro_types::primitives::Hash::from_bytes(&hasher.finalize())
                .expect("SHA-256 produces 32 bytes");
        }
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

    // ---- cache affinity / speculative preference over network offers ------
    //
    // These cover the seam where a *network* offer wins: `route` returns the
    // announcement's own provider and the inference router is never consulted,
    // so any preference that lives only in `InferenceRouter::select_provider`
    // cannot fire here. That is the case a multi-provider network runs in.

    /// A [`NetworkCatalog`] returning a fixed offer set.
    struct StaticCatalog(Vec<ModelOffer>);

    impl NetworkCatalog for StaticCatalog {
        fn live_offers(&self, _modality: ModelModality) -> Vec<ModelOffer> {
            self.0.clone()
        }
    }

    /// Long enough to yield whole `PREFIX_RUN_BYTES` runs — a shorter prompt
    /// hashes to nothing and every affinity assertion would pass vacuously.
    fn warm_prompt() -> String {
        "the quick brown fox jumps over the lazy dog. ".repeat(64)
    }

    /// An offer for `id` at `price`, served by provider byte-tag `tag`.
    fn offer(
        id: &str,
        tag: u8,
        price: u64,
        capacity: Option<AdvertisedCapacity>,
    ) -> (ModelOffer, Address) {
        let mut m = model(id, 8_000_000_000, 8192, price, price);
        let provider = Address::new([tag; 32]);
        m.provider = provider;
        (
            ModelOffer {
                model: m,
                endpoint: format!("http://provider-{tag}:8545"),
                capacity,
            },
            provider,
        )
    }

    fn capacity(warm: Option<&str>, active: u32, max: u32, mtp: bool) -> Option<AdvertisedCapacity> {
        Some(AdvertisedCapacity {
            max_concurrent_requests: max,
            active_requests: active,
            mtp_enabled: mtp,
            prefix_cache: warm
                .map(|p| {
                    tenzro_types::model::PrefixCacheSummary::from_warm_prompt(p.as_bytes())
                })
                .unwrap_or_default(),
            ..Default::default()
        })
    }

    fn decide(offers: Vec<ModelOffer>, prompt: Option<&str>) -> RouteDecision {
        let (registry, usage, router) = router_stack();
        let meta = MetaRouter::new(registry, usage, router)
            .with_network_catalog(Arc::new(StaticCatalog(offers)));
        let mut intent = RouteIntent::new(UseCase::Chat, Budget::None).with_tokens(64, 64);
        intent.prompt = prompt.map(str::to_string);
        meta.route(&intent).expect("an offer should win")
    }

    /// The production shape: the provider warmed the whole conversation, and
    /// the router is handed only the *last user turn* as `prompt`.
    ///
    /// This is the case the original suite could not see, because every test
    /// fed byte-identical strings to both sides. The rolling hash chains from
    /// byte 0, so matching on the last turn alone shares no run with what the
    /// provider holds — affinity scored zero for exactly the multi-turn and
    /// shared-system-prompt traffic it was built to serve. `affinity_prefix`
    /// is what carries the right bytes.
    #[test]
    fn affinity_matches_the_conversation_not_just_the_last_turn() {
        let system = "you are a careful assistant. ".repeat(48);
        let turn_1 = "explain rolling hashes";
        let latest = "now compare to a radix tree";
        // What a provider warms: every message's content joined by '\n'.
        let warmed = format!("{system}\n{turn_1}");
        // What the router sees as `prompt`: the last user turn only.
        let conversation = format!("{warmed}\n{latest}");

        let (cold, _) = offer("m", 1, 10, capacity(None, 0, 8, false));
        let (warm, warm_addr) = offer("m", 2, 10, capacity(Some(&warmed), 0, 8, false));

        // Without the affinity prefix the warm provider is invisible.
        let (c1, _) = offer("m", 1, 10, capacity(None, 0, 8, false));
        let (w1, _) = offer("m", 2, 10, capacity(Some(&warmed), 0, 8, false));
        let blind = decide(vec![c1, w1], Some(latest));
        assert!(
            !blind.reason.contains("affinity=warm"),
            "last-turn-only matching should find nothing warm: {}",
            blind.reason
        );

        // With it, the provider holding the conversation prefix wins.
        let (registry, usage, router) = router_stack();
        let meta = MetaRouter::new(registry, usage, router)
            .with_network_catalog(Arc::new(StaticCatalog(vec![cold, warm])));
        let intent = RouteIntent::new(UseCase::Chat, Budget::None)
            .with_tokens(64, 64)
            .with_affinity_prefix(conversation);
        let d = meta.route(&intent).expect("an offer should win");
        assert_eq!(d.provider, Some(warm_addr), "{}", d.reason);
        assert!(d.reason.contains("affinity=warm"), "{}", d.reason);
    }

    /// A peer can put anything in a gossiped announcement — a signature proves
    /// who sent it, not that it is true. A forged `run_len` must not let a
    /// provider holding nothing outrank one holding the real prefix.
    #[test]
    fn forged_run_len_cannot_win_the_tie_break() {
        let w = warm_prompt();
        let honest_cap = capacity(Some(&w), 0, 8, false).unwrap();
        assert!(
            honest_cap.prefix_cache.longest_match_len(&tenzro_types::prefix_run_hashes(
                w.as_bytes()
            )) > 0,
            "fixture must genuinely match, else this proves nothing"
        );

        // One node claiming a saturating run length, matching only run 0.
        let mut forged = tenzro_types::model::PrefixCacheSummary::from_warm_prompt(w.as_bytes());
        forged.nodes.truncate(1);
        forged.nodes[0].run_len = u32::MAX;
        let forged_json = serde_json::to_string(&forged).expect("summary serializes");
        let decoded: tenzro_types::model::PrefixCacheSummary =
            serde_json::from_str(&forged_json).expect("summary deserializes");
        assert!(
            decoded.nodes.is_empty(),
            "a run_len the honest producer never emits must be rejected at the \
             deserialization boundary, leaving the peer advertising nothing"
        );
    }

    /// Declaring no concurrency ceiling must not be better than answering
    /// honestly — `0` is also the serde default, so a truncated announcement
    /// would otherwise land in the most-preferred bucket for free.
    #[test]
    fn undeclared_ceiling_is_not_treated_as_idle() {
        assert!(!idle_enough(0, 0), "no declared ceiling is unknown, not idle");
        assert!(!idle_enough(u32::MAX, 0));
        // A genuinely idle single-slot provider still qualifies.
        assert!(idle_enough(0, 1), "1/2 truncating to 0 locked these out");
        assert!(idle_enough(3, 8));
        assert!(!idle_enough(4, 8));
    }

    #[test]
    fn warm_offer_wins_at_equal_cost() {
        let (cold, _) = offer("m", 1, 10, capacity(None, 0, 8, false));
        let (warm, warm_addr) = offer("m", 2, 10, capacity(Some(&warm_prompt()), 0, 8, false));
        let d = decide(vec![cold, warm], Some(&warm_prompt()));
        assert_eq!(d.provider, Some(warm_addr), "{}", d.reason);
        assert!(d.reason.contains("affinity=warm"), "{}", d.reason);
    }

    /// Affinity breaks ties; it never buys its way past price. This is the
    /// invariant that keeps the tie-break safe to apply unconditionally.
    #[test]
    fn cheaper_cold_offer_still_beats_a_warm_one() {
        let (cheap, cheap_addr) = offer("m", 1, 1, capacity(None, 0, 8, false));
        let (warm, _) = offer("m", 2, 10, capacity(Some(&warm_prompt()), 0, 8, false));
        let d = decide(vec![warm, cheap], Some(&warm_prompt()));
        assert_eq!(d.provider, Some(cheap_addr), "{}", d.reason);
    }

    /// With nothing warm and no prompt, the scored order must survive intact —
    /// an affinity rule that reshuffles equal candidates every turn would
    /// destroy the very stickiness it exists to create.
    #[test]
    fn nothing_warm_leaves_scored_order_untouched() {
        let (first, first_addr) = offer("m", 1, 10, capacity(None, 0, 8, false));
        let (second, _) = offer("m", 2, 10, capacity(None, 0, 8, false));
        let d = decide(vec![first, second], None);
        assert_eq!(d.provider, Some(first_addr), "{}", d.reason);
    }

    /// Equally warm: the provider not already at its admission ceiling wins,
    /// because the saturated one would queue the call behind work in flight.
    #[test]
    fn saturated_provider_loses_to_an_idle_equal() {
        let w = warm_prompt();
        let (full, _) = offer("m", 1, 10, capacity(Some(&w), 8, 8, false));
        let (free, free_addr) = offer("m", 2, 10, capacity(Some(&w), 1, 8, false));
        let d = decide(vec![full, free], Some(&w));
        assert_eq!(d.provider, Some(free_addr), "{}", d.reason);
    }

    /// Speculation is preferred automatically — no `draft_n`, no operator
    /// config — but only when the provider is idle enough for it to pay.
    #[test]
    fn idle_speculative_provider_preferred_when_nothing_is_warm() {
        let (plain, _) = offer("m", 1, 10, capacity(None, 0, 8, false));
        let (spec, spec_addr) = offer("m", 2, 10, capacity(None, 0, 8, true));
        let d = decide(vec![plain, spec], Some(&warm_prompt()));
        assert_eq!(d.provider, Some(spec_addr), "{}", d.reason);
    }

    /// Speculative decoding inverts into a slowdown once a provider is
    /// batching heavily, so a busy MTP provider must not be preferred.
    #[test]
    fn busy_speculative_provider_is_not_preferred() {
        let (plain, plain_addr) = offer("m", 1, 10, capacity(None, 0, 8, false));
        let (spec, _) = offer("m", 2, 10, capacity(None, 7, 8, true));
        let d = decide(vec![plain, spec], Some(&warm_prompt()));
        assert_eq!(d.provider, Some(plain_addr), "{}", d.reason);
    }

    /// A warm prefix outranks speculation: skipping a whole prefill is the
    /// larger and more certain saving.
    #[test]
    fn warm_prefix_outranks_speculation() {
        let (spec, _) = offer("m", 1, 10, capacity(None, 0, 8, true));
        let (warm, warm_addr) = offer("m", 2, 10, capacity(Some(&warm_prompt()), 0, 8, false));
        let d = decide(vec![spec, warm], Some(&warm_prompt()));
        assert_eq!(d.provider, Some(warm_addr), "{}", d.reason);
    }

    /// Pinning a model must not switch off cache affinity for it.
    ///
    /// The override used to move only the *first* matching offer to the
    /// front, which left a differently-named candidate at index 1 and made
    /// the tie-group scan stop there — so the operator's pinned model was
    /// precisely the one that lost warm-prefix routing. Regression test: with
    /// a cheaper unpinned model present, a cold pinned offer must not beat a
    /// warm pinned offer at the same price.
    #[test]
    fn pinning_a_model_still_honours_cache_affinity() {
        let w = warm_prompt();
        // `a` is cheaper, so it heads the scored order; `b` is pinned.
        let (cheap_other, cheap_addr) = offer("a", 1, 1, capacity(None, 0, 8, false));
        let (pinned_cold, cold_addr) = offer("b", 2, 10, capacity(None, 0, 8, false));
        let (pinned_warm, warm_addr) = offer("b", 3, 10, capacity(Some(&w), 0, 8, false));

        let (registry, usage, router) = router_stack();
        let meta = MetaRouter::new(registry, usage, router)
            .with_network_catalog(Arc::new(StaticCatalog(vec![
                cheap_other,
                pinned_cold,
                pinned_warm,
            ])))
            .with_routing_preferences(HashMap::from([(
                UseCase::Chat.as_str().to_string(),
                "b".to_string(),
            )]));
        let mut intent = RouteIntent::new(UseCase::Chat, Budget::None).with_tokens(64, 64);
        intent.prompt = Some(w.clone());
        let d = meta.route(&intent).expect("an offer should win");

        assert_ne!(d.provider, Some(cheap_addr), "the pin must still win: {}", d.reason);
        assert_eq!(
            d.provider,
            Some(warm_addr),
            "pinned model must still prefer its warm offer, not {:?}: {}",
            cold_addr,
            d.reason
        );
        assert!(d.reason.contains("affinity=warm"), "{}", d.reason);
    }

    /// An offer whose provider announcement has not arrived carries no
    /// capacity, and must not be demoted for a gossip race it did not cause.
    #[test]
    fn offer_without_announced_capacity_keeps_its_position() {
        let (unknown, unknown_addr) = offer("m", 1, 10, None);
        let (known, _) = offer("m", 2, 10, capacity(None, 0, 8, false));
        let d = decide(vec![unknown, known], Some(&warm_prompt()));
        assert_eq!(d.provider, Some(unknown_addr), "{}", d.reason);
    }

    #[test]
    fn tiering_by_params() {
        assert_eq!(
            quality_tier(&model("s", 70_000_000_000, 8192, 1, 1)),
            QualityTier::Strong
        );
        assert_eq!(
            quality_tier(&model("c", 3_000_000_000, 8192, 1, 1)),
            QualityTier::Cheap
        );
    }

    /// A long window is capacity, not capability. Every model shipping today
    /// clears the old 32k floor, so counting it lifted *everything* into the
    /// strong tier — after which the cost term picked the smallest candidate
    /// for every rung, and a 0.8B answered `quality_floor=strong`.
    #[test]
    fn a_long_context_window_alone_is_not_strength() {
        // The exact shape that broke routing: 0.8B at 131k.
        assert_eq!(
            quality_tier(&model("tiny-long-ctx", 800_000_000, 131_072, 1, 1)),
            QualityTier::Cheap
        );
    }

    /// A `code`/`reasoning` tag on a tiny model describes what it was trained
    /// for, not what it can carry.
    #[test]
    fn a_capability_tag_needs_size_behind_it() {
        let mut small = model("tagged-tiny", 800_000_000, 131_072, 1, 1);
        small.parameters.capabilities = vec!["code".into()];
        assert_eq!(quality_tier(&small), QualityTier::Cheap);

        let mut mid = model("tagged-mid", 8_000_000_000, 131_072, 1, 1);
        mid.parameters.capabilities = vec!["reasoning".into()];
        assert_eq!(quality_tier(&mid), QualityTier::Strong);
    }

    #[test]
    fn empty_registry_errors() {
        let (registry, usage, router) = router_stack();
        let mr = MetaRouter::new(registry, usage, router);
        let intent = RouteIntent::new(UseCase::Chat, Budget::None);
        assert!(matches!(
            mr.route(&intent),
            Err(ModelError::NoProvidersAvailable(_))
        ));
    }

    /// Two strong models; the cheaper one wins by default. The operator's
    /// task→model override for `code` pins the pricier one, and it wins
    /// outright — the Cortex primitive.
    #[test]
    fn operator_override_pins_the_task_model() {
        let (registry, usage, router) = router_stack();
        registry
            .register_model(model("alpha", 35_000_000_000, 8192, 1, 1))
            .unwrap();
        registry
            .register_model(model("beta", 35_000_000_000, 8192, 10, 10))
            .unwrap();
        let intent = RouteIntent::new(UseCase::Code, Budget::None).with_tokens(64, 64);

        // Default: cheapest strong model.
        let mr = MetaRouter::new(registry.clone(), usage.clone(), router.clone());
        assert_eq!(mr.route(&intent).unwrap().model_id, "alpha");

        // Override code → beta: beta wins despite costing more, and alpha
        // remains in the fallback chain.
        let mr = MetaRouter::new(registry, usage, router)
            .with_routing_preferences(HashMap::from([("code".to_string(), "beta".to_string())]));
        let d = mr.route(&intent).unwrap();
        assert_eq!(d.model_id, "beta");
        assert!(d.fallback_chain.iter().any(|f| f == "alpha"));
    }

    /// An override naming a model that is not an available candidate is
    /// ignored — selection falls back to the intelligent winner.
    #[test]
    fn operator_override_ignored_when_model_unavailable() {
        let (registry, usage, router) = router_stack();
        registry
            .register_model(model("alpha", 35_000_000_000, 8192, 1, 1))
            .unwrap();
        registry
            .register_model(model("beta", 35_000_000_000, 8192, 10, 10))
            .unwrap();
        let mr = MetaRouter::new(registry, usage, router).with_routing_preferences(HashMap::from([
            ("code".to_string(), "ghost".to_string()),
        ]));
        let intent = RouteIntent::new(UseCase::Code, Budget::None).with_tokens(64, 64);
        assert_eq!(mr.route(&intent).unwrap().model_id, "alpha");
    }

    /// An override applies only to its named use case; other use cases keep
    /// intelligent selection.
    #[test]
    fn operator_override_only_affects_named_use_case() {
        let (registry, usage, router) = router_stack();
        registry
            .register_model(model("alpha", 35_000_000_000, 8192, 1, 1))
            .unwrap();
        registry
            .register_model(model("beta", 35_000_000_000, 8192, 10, 10))
            .unwrap();
        let mr = MetaRouter::new(registry, usage, router)
            .with_routing_preferences(HashMap::from([("code".to_string(), "beta".to_string())]));
        // Code is pinned to beta; chat is not, so it keeps the cheaper winner.
        let code = RouteIntent::new(UseCase::Code, Budget::None).with_tokens(64, 64);
        let chat = RouteIntent::new(UseCase::Chat, Budget::None).with_tokens(64, 64);
        assert_eq!(mr.route(&code).unwrap().model_id, "beta");
        assert_eq!(mr.route(&chat).unwrap().model_id, "alpha");
    }

    #[test]
    fn budget_prefilter_drops_expensive() {
        let (registry, usage, router) = router_stack();
        // Cheap model: 1+1 per token. Expensive model: 1000 per token.
        registry
            .register_model(model("cheap", 3_000_000_000, 8192, 1, 1))
            .unwrap();
        registry
            .register_model(model("pricey", 3_000_000_000, 8192, 1000, 1000))
            .unwrap();
        let mr = MetaRouter::new(registry, usage, router);
        // Budget only affords the cheap model at 256+256 tokens.
        let intent =
            RouteIntent::new(UseCase::Chat, Budget::PerRequestTnzo(1000)).with_tokens(256, 256);
        let d = mr.route(&intent).unwrap();
        assert_eq!(d.model_id, "cheap");
    }

    #[test]
    fn quality_floor_filters() {
        let (registry, usage, router) = router_stack();
        registry
            .register_model(model("cheap", 3_000_000_000, 8192, 1, 1))
            .unwrap();
        registry
            .register_model(model("strong", 70_000_000_000, 8192, 2, 2))
            .unwrap();
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
        registry
            .register_model(model("a", 3_000_000_000, 8192, 5, 5))
            .unwrap();
        registry
            .register_model(model("b", 3_000_000_000, 8192, 2, 2))
            .unwrap();
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
        registry
            .register_model(model("cheap", 3_000_000_000, 8192, 1, 1))
            .unwrap();
        registry
            .register_model(model("strong", 70_000_000_000, 8192, 2, 2))
            .unwrap();
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
        registry
            .register_model(model("cheap", 3_000_000_000, 8192, 1, 1))
            .unwrap();
        let mr = MetaRouter::new(registry, usage, router).with_budget_gate(Arc::new(DenyGate));
        let intent = RouteIntent::new(UseCase::Chat, Budget::None)
            .with_tokens(10, 10)
            .with_payer_did("did:tenzro:machine:test");
        assert!(matches!(
            mr.route(&intent),
            Err(ModelError::RoutingError(_))
        ));
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
        registry
            .register_model(model("cheap", 3_000_000_000, 8192, 1, 1))
            .unwrap();
        registry
            .register_model(model("pricey", 70_000_000_000, 8192, 1000, 1000))
            .unwrap();
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
        registry
            .register_model(model("pricey", 3_000_000_000, 8192, 1000, 1000))
            .unwrap();
        let mr = MetaRouter::new(registry, usage, router)
            .with_balance_provider(Arc::new(FixedBalance(1)));
        let intent = RouteIntent::new(UseCase::Chat, Budget::None)
            .with_tokens(10, 10)
            .with_payer_address(Address::new([9; 32]));
        assert!(matches!(
            mr.route(&intent),
            Err(ModelError::NoProvidersAvailable(_))
        ));
    }

    /// Two same-priced candidates, one cheap-tier and one strong-tier, plus a
    /// knob that leans cheap. Cost cannot separate them, so measurement is the
    /// only differentiator once it exists.
    fn measured_stack() -> (MetaRouter, Arc<DifficultyIndex>) {
        let (registry, usage, router) = router_stack();
        registry
            .register_model(model("cheap", 3_000_000_000, 8192, 1, 1))
            .unwrap();
        registry
            .register_model(model("strong", 70_000_000_000, 8192, 1, 1))
            .unwrap();
        let index = Arc::new(DifficultyIndex::new(
            crate::difficulty::DEFAULT_CLUSTER_CAPACITY,
        ));
        let mr = MetaRouter::new(registry, usage, router).with_difficulty_index(index.clone());
        (mr, index)
    }

    fn measured_intent(embedding: Vec<f32>) -> RouteIntent {
        RouteIntent::new(UseCase::Chat, Budget::None)
            .with_optimize(0.5)
            .with_tokens(10, 10)
            .with_prompt_embedding(embedding)
    }

    /// The default admits both, so nothing changes for callers that do not ask.
    #[test]
    fn locality_defaults_to_any() {
        let intent = RouteIntent::new(UseCase::Chat, Budget::None);
        assert_eq!(intent.locality, Locality::Any);
    }

    /// `local_only` is what an application promising "your data stays on your
    /// machine" actually needs.
    ///
    /// `budget` was the only thing standing in for it — setting it to zero
    /// happens to exclude *paid* remote offers — but that is a cost constraint
    /// wearing a privacy constraint's clothes: a free or subsidised provider
    /// satisfies a zero budget and still receives the prompt.
    #[test]
    fn local_only_is_distinct_from_a_zero_budget() {
        let free_remote_is_allowed = RouteIntent::new(UseCase::Chat, Budget::PerRequestTnzo(0));
        assert_eq!(
            free_remote_is_allowed.locality,
            Locality::Any,
            "a zero budget must not be mistaken for a locality guarantee"
        );

        let intent = RouteIntent::new(UseCase::Chat, Budget::None).local_only();
        assert_eq!(intent.locality, Locality::LocalOnly);
    }

    /// It must fail closed.
    ///
    /// A caller that asked for local-only and got a network provider anyway has
    /// been handed the exact outcome they asked to avoid, silently. When the
    /// only candidates are network offers, the route must fail.
    #[test]
    fn local_only_rejects_a_network_offer() {
        let (network_offer, _provider) = offer("remote-model", 9, 1_000, None);
        let (registry, usage, router) = router_stack();
        let meta = MetaRouter::new(registry, usage, router)
            .with_network_catalog(Arc::new(StaticCatalog(vec![network_offer])));

        // Unconstrained, a network offer is a legitimate answer.
        let open = RouteIntent::new(UseCase::Chat, Budget::None).with_tokens(64, 64);
        assert!(
            meta.route(&open).is_ok(),
            "the fixture must route without the constraint, or the test below \
             proves nothing"
        );

        // Local-only must not accept it, and must not fall back to it either.
        let restricted = RouteIntent::new(UseCase::Chat, Budget::None)
            .with_tokens(64, 64)
            .local_only();
        match meta.route(&restricted) {
            Err(_) => {}
            Ok(d) => {
                // The router stack also carries local registry models, so a
                // local win is acceptable — a *remote* one is not.
                assert!(
                    !d.model_id.starts_with("remote-"),
                    "local_only routed to the network offer '{}'",
                    d.model_id
                );
            }
        }
    }

    /// And a node that serves nothing locally cannot satisfy local-only at all.
    #[test]
    fn local_only_fails_when_nothing_is_served_locally() {
        let (network_offer, _provider) = offer("remote-only", 7, 1_000, None);
        //  gives an empty local registry, which is the point:
        // nothing is served here, so only the network offer is a candidate.
        let (registry, usage, router) = router_stack();
        let meta = MetaRouter::new(registry, usage, router)
            .with_network_catalog(Arc::new(StaticCatalog(vec![network_offer])));

        let intent = RouteIntent::new(UseCase::Chat, Budget::None)
            .with_tokens(64, 64)
            .local_only();
        assert!(
            meta.route(&intent).is_err(),
            "with an empty local registry, local_only must fail rather than \
             reach for the network"
        );
    }

    #[test]
    fn no_embedding_takes_the_declared_path() {
        let (mr, _index) = measured_stack();
        let intent = RouteIntent::new(UseCase::Chat, Budget::None)
            .with_optimize(0.5)
            .with_tokens(10, 10);
        let d = mr.route(&intent).unwrap();
        assert_eq!(d.cluster, None);
        assert_eq!(d.expected_error, None);
        assert_eq!(d.model_id, "cheap");
    }

    #[test]
    fn embedding_without_observations_takes_the_declared_path() {
        let (mr, index) = measured_stack();
        let d = mr.route(&measured_intent(vec![1.0, 0.0, 0.0])).unwrap();
        // The prompt was placed, so future requests can be scored against it,
        // but with nothing served yet declared metadata still decides.
        assert_eq!(d.cluster, Some(0));
        assert_eq!(d.expected_error, None);
        assert_eq!(d.model_id, "cheap");
        assert_eq!(index.cluster_count(), 1);
    }

    #[test]
    fn escalations_flip_the_winner_within_the_cluster() {
        let (mr, _index) = measured_stack();
        let embedding = vec![1.0, 0.0, 0.0];

        // First request places the prompt and takes the declared path.
        let first = mr.route(&measured_intent(embedding.clone())).unwrap();
        assert_eq!(first.model_id, "cheap");
        let cluster = first.cluster.unwrap();

        // The cheap model repeatedly failed to resolve prompts here.
        for _ in 0..20 {
            assert!(
                mr.record_outcome("cheap", cluster, RouteOutcome::Escalated)
                    .unwrap()
            );
        }

        // Same neighbourhood, same knob, same cost — now the strong model wins.
        let second = mr.route(&measured_intent(embedding)).unwrap();
        assert_eq!(second.cluster, Some(cluster));
        assert_eq!(second.model_id, "strong");
        assert!(second.expected_error.is_some());
        assert_eq!(second.fallback_chain, vec!["cheap".to_string()]);
    }

    #[test]
    fn quality_floor_binds_in_the_measured_path() {
        let (mr, _index) = measured_stack();
        let embedding = vec![0.0, 1.0, 0.0];
        let cluster = mr
            .route(&measured_intent(embedding.clone()))
            .unwrap()
            .cluster
            .unwrap();
        // The cheap model measures well here, so unconstrained routing would
        // pick it. A caller-declared floor overrides the measurement.
        for _ in 0..20 {
            mr.record_outcome("cheap", cluster, RouteOutcome::Resolved)
                .unwrap();
        }
        let intent = measured_intent(embedding).with_quality_floor(QualityTier::Strong);
        let d = mr.route(&intent).unwrap();
        assert_eq!(d.model_id, "strong");
        assert_eq!(d.tier, QualityTier::Strong);
    }

    #[test]
    fn outcome_without_an_index_is_not_an_error() {
        let (registry, usage, router) = router_stack();
        registry
            .register_model(model("cheap", 3_000_000_000, 8192, 1, 1))
            .unwrap();
        let mr = MetaRouter::new(registry, usage, router);
        assert!(!mr.record_outcome("cheap", 0, RouteOutcome::Failed).unwrap());
    }

    struct ConstantEmbedder(Vec<f32>);

    #[async_trait::async_trait]
    impl PromptEmbedder for ConstantEmbedder {
        async fn embed_prompt(&self, _prompt: &str) -> Result<Vec<f32>> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn route_intent_embeds_the_prompt() {
        let (registry, usage, router) = router_stack();
        registry
            .register_model(model("cheap", 3_000_000_000, 8192, 1, 1))
            .unwrap();
        let index = Arc::new(DifficultyIndex::new(
            crate::difficulty::DEFAULT_CLUSTER_CAPACITY,
        ));
        let mr = MetaRouter::new(registry, usage, router)
            .with_difficulty_index(index.clone())
            .with_prompt_embedder(Arc::new(ConstantEmbedder(vec![0.0, 0.0, 1.0])));
        let intent = RouteIntent::new(UseCase::Chat, Budget::None)
            .with_tokens(10, 10)
            .with_prompt("summarize this contract");
        let d = mr.route_intent(&intent).await.unwrap();
        assert_eq!(d.cluster, Some(0));
        assert_eq!(index.cluster_count(), 1);
    }
}
