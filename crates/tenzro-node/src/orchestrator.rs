//! Node-layer intent Orchestrator.
//!
//! The Orchestrator is the tier above [`MetaRouter`]. Where the meta-router
//! answers "which *model* serves this intent, within budget", the Orchestrator
//! answers the broader "which *capabilities* — models, skills, tools, agents —
//! compose to satisfy this intent, and in what order". It is the only place in
//! the workspace that reads the model catalog, the skill/tool registries, the
//! agent runtime, and the wallet ceiling together, so like
//! [`crate::spending_policy_bridge`] it lives at the node layer.
//!
//! # Design
//!
//! Planning is separated from execution behind the [`OrchestrationPlanner`]
//! trait, a pure function `intent + catalog snapshot -> OrchestrationPlan`. Two
//! implementations exist:
//!
//! - [`DeterministicPlanner`] — rule-based, always available, never calls a
//!   model. It maps a use case onto a small ordered plan (optionally a skill or
//!   tool prelude, then a model step). This is the guardrail and the default.
//! - [`LlmPlanner`] — routes its own planning call through the meta-router's
//!   reasoning intent, asking a strong model to emit a plan over the catalog
//!   snapshot. On *any* failure (no model, budget rejection, unparseable plan)
//!   it falls back to the wrapped [`DeterministicPlanner`]. The orchestrator is
//!   therefore never blocked by planner unavailability.
//!
//! Execution ([`Orchestrator::execute`]) is single-shot with a bounded
//! re-plan loop seam ([`OrchestrationRequest::max_iterations`]): the plan runs,
//! and if a step signals `needs_replan` the planner is consulted again with the
//! accumulated context, up to the iteration bound. Cost is summed against the
//! wallet ceiling *before* any step runs (fail-fast), so an under-funded caller
//! is rejected at plan time rather than mid-execution.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tenzro_model::meta_router::{Budget, MetaRouter, RouteIntent, UseCase};
use tenzro_types::primitives::Address;
use tracing::{debug, info, warn};

/// The most capability steps a single plan may contain. Bounds planner output
/// (an LLM plan is untrusted) and the per-request execution fan-out.
const MAX_PLAN_STEPS: usize = 8;

/// Default re-plan iteration bound when the caller does not set one. One pass
/// (no re-plan) is the common case; the seam exists for agentic callers.
const DEFAULT_MAX_ITERATIONS: u32 = 1;

/// Hard ceiling on the re-plan loop regardless of caller request, so a runaway
/// planner cannot spin.
const ITERATION_HARD_CAP: u32 = 6;

/// Errors surfaced by the orchestrator. Mapped to JSON-RPC codes by the handler.
#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    /// The intent could not be satisfied by any available capability.
    #[error("no capability satisfies intent: {0}")]
    NoCapability(String),
    /// The plan's aggregate estimated cost exceeds the payer's wallet balance.
    #[error("plan estimated cost {estimated} exceeds wallet balance {balance}")]
    OverBudget {
        /// Aggregate estimated cost of the plan, smallest TNZO unit.
        estimated: u128,
        /// Payer's spendable balance, smallest TNZO unit.
        balance: u128,
    },
    /// A required subsystem is not initialized on this node.
    #[error("subsystem unavailable: {0}")]
    Unavailable(String),
    /// The planner produced an invalid plan (empty, too long, malformed step).
    #[error("invalid plan: {0}")]
    InvalidPlan(String),
    /// A step failed during execution.
    #[error("step {index} ({kind}) failed: {reason}")]
    StepFailed {
        /// Zero-based index of the failing step within the plan.
        index: usize,
        /// The step's capability kind label.
        kind: String,
        /// Underlying error text.
        reason: String,
    },
}

/// Result alias for orchestrator operations.
pub type Result<T> = std::result::Result<T, OrchestratorError>;

/// One capability invocation in a plan. Each variant names *what* to invoke; the
/// executor resolves it to a concrete dispatch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanStep {
    /// Route an intent to a model and run inference. `model_id` is optional —
    /// when absent, the meta-router selects it from the step's use case at
    /// execution time (so the plan need not pin a model the planner guessed).
    Model {
        /// Use-case label (see [`UseCase::ALL`]).
        use_case: String,
        /// Optional pre-resolved model id. Absent => meta-router selects.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model_id: Option<String>,
        /// The prompt / input text for this step.
        input: String,
    },
    /// Invoke a registered skill by id.
    Skill {
        /// `skill_id` in `CF_SKILLS`.
        skill_id: String,
        /// JSON input matching the skill's `input_schema`.
        #[serde(default)]
        input: serde_json::Value,
    },
    /// Invoke a registered tool by id.
    Tool {
        /// `tool_id` in `CF_TOOLS`.
        tool_id: String,
        /// JSON input for the tool.
        #[serde(default)]
        input: serde_json::Value,
    },
    /// Delegate a task to a single spawned agent.
    Agent {
        /// Capabilities the agent must have (used to select/spawn).
        capabilities: Vec<String>,
        /// Task text delegated to the agent.
        task: String,
    },
    /// Fan a task out to a swarm of agents and gather their responses.
    Swarm {
        /// Per-member `(name, capabilities)` specs.
        members: Vec<SwarmMemberSpec>,
        /// Task broadcast to every member.
        task: String,
    },
}

impl PlanStep {
    /// Short label for logs and error messages.
    pub fn kind_label(&self) -> &'static str {
        match self {
            PlanStep::Model { .. } => "model",
            PlanStep::Skill { .. } => "skill",
            PlanStep::Tool { .. } => "tool",
            PlanStep::Agent { .. } => "agent",
            PlanStep::Swarm { .. } => "swarm",
        }
    }
}

/// A swarm member spec: a name and the capabilities it should carry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SwarmMemberSpec {
    /// Human-readable member name.
    pub name: String,
    /// Capabilities the member agent should have.
    pub capabilities: Vec<String>,
}

/// An ordered plan: the capability steps that satisfy an intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestrationPlan {
    /// Ordered steps; run front-to-back, each step's output appended to context.
    pub steps: Vec<PlanStep>,
    /// Human-readable rationale for the decomposition.
    pub rationale: String,
    /// Which planner produced this plan (`deterministic` | `llm`).
    pub planner: String,
}

impl OrchestrationPlan {
    /// Validates plan shape: non-empty, within [`MAX_PLAN_STEPS`], every step
    /// well-formed.
    fn validate(&self) -> Result<()> {
        if self.steps.is_empty() {
            return Err(OrchestratorError::InvalidPlan("plan has no steps".into()));
        }
        if self.steps.len() > MAX_PLAN_STEPS {
            return Err(OrchestratorError::InvalidPlan(format!(
                "plan has {} steps (max {MAX_PLAN_STEPS})",
                self.steps.len()
            )));
        }
        for (i, step) in self.steps.iter().enumerate() {
            if let PlanStep::Model { use_case, .. } = step
                && UseCase::parse(use_case).is_none()
            {
                return Err(OrchestratorError::InvalidPlan(format!(
                    "step {i}: unknown use_case '{use_case}'"
                )));
            }
        }
        Ok(())
    }
}

/// A read-only snapshot of what capabilities are available, handed to a planner
/// so it reasons over real inventory rather than guessing. Cheap to build; the
/// registries themselves stay owned by the node.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CatalogSnapshot {
    /// Skill ids + one-line descriptions available to this caller.
    pub skills: Vec<CapabilityCard>,
    /// Tool ids + one-line descriptions available to this caller.
    pub tools: Vec<CapabilityCard>,
    /// Whether the agent runtime is available for `Agent`/`Swarm` steps.
    pub agents_available: bool,
}

/// A compact catalog entry for the planner: an id, a label, and a description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityCard {
    /// Registry id (`skill_id` / `tool_id`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// One-line description.
    pub description: String,
    /// Capability tags, for planner matching.
    pub tags: Vec<String>,
}

/// The request an orchestrator serves: the natural-language / structured intent,
/// the payer, budget, and the re-plan bound.
#[derive(Debug, Clone)]
pub struct OrchestrationRequest {
    /// The intent text the caller wants satisfied.
    pub intent: String,
    /// Primary use case hint (guides the deterministic planner and the model
    /// steps). Defaults to `Chat` when the caller gives none.
    pub use_case: UseCase,
    /// Per-request budget cap (smallest TNZO unit). `None` = no per-request cap.
    pub budget: Budget,
    /// Payer DID, enabling the per-DID budget gate on model steps.
    pub payer_did: Option<String>,
    /// Payer wallet address, enabling the wallet-balance ceiling.
    pub payer_address: Option<Address>,
    /// Max re-plan iterations. Clamped to `[1, ITERATION_HARD_CAP]`.
    pub max_iterations: u32,
}

impl OrchestrationRequest {
    /// Builds a single-shot request for `intent` with a chat use case and no
    /// budget cap. Callers refine with the `with_*` setters.
    pub fn new(intent: impl Into<String>) -> Self {
        Self {
            intent: intent.into(),
            use_case: UseCase::Chat,
            budget: Budget::None,
            payer_did: None,
            payer_address: None,
            max_iterations: DEFAULT_MAX_ITERATIONS,
        }
    }

    /// Sets the primary use case.
    #[must_use]
    pub fn with_use_case(mut self, use_case: UseCase) -> Self {
        self.use_case = use_case;
        self
    }

    /// Sets the per-request budget cap.
    #[must_use]
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = budget;
        self
    }

    /// Sets the payer DID.
    #[must_use]
    pub fn with_payer_did(mut self, did: impl Into<String>) -> Self {
        self.payer_did = Some(did.into());
        self
    }

    /// Sets the payer wallet address.
    #[must_use]
    pub fn with_payer_address(mut self, addr: Address) -> Self {
        self.payer_address = Some(addr);
        self
    }

    /// Sets the re-plan iteration bound.
    #[must_use]
    pub fn with_max_iterations(mut self, n: u32) -> Self {
        self.max_iterations = n;
        self
    }

    /// The effective iteration bound after clamping.
    fn effective_iterations(&self) -> u32 {
        self.max_iterations.clamp(1, ITERATION_HARD_CAP)
    }

    /// Builds the [`RouteIntent`] a model step routes under, inheriting payer
    /// identity and budget from the request.
    fn model_route_intent(&self, use_case: UseCase, input_tokens: u64) -> RouteIntent {
        let mut intent = RouteIntent::new(use_case, self.budget)
            .with_tokens(input_tokens, input_tokens.max(256));
        if let Some(ref did) = self.payer_did {
            intent = intent.with_payer_did(did.clone());
        }
        if let Some(addr) = self.payer_address {
            intent = intent.with_payer_address(addr);
        }
        intent
    }
}

/// The outcome of running a plan: per-step results plus aggregate accounting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestrationOutcome {
    /// The plan that ran (post any re-planning, the final plan).
    pub plan: OrchestrationPlan,
    /// One result per executed step, in order.
    pub steps: Vec<StepResult>,
    /// Sum of estimated cost across model steps, smallest TNZO unit.
    pub estimated_cost: u128,
    /// Number of re-plan iterations consumed (1 = single-shot).
    pub iterations: u32,
}

/// The result of a single executed step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    /// Capability kind (`model`/`skill`/`tool`/`agent`/`swarm`).
    pub kind: String,
    /// Free-form output text (model completion, tool output, agent reply).
    pub output: String,
    /// Structured detail (model id chosen, route trace, member replies).
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub detail: serde_json::Value,
}

/// Planner abstraction: decide a plan for a request over a catalog snapshot.
///
/// Implementations are pure with respect to the network — they must not perform
/// side effects other than (for the LLM planner) routing a single planning call.
/// The executor owns all capability dispatch.
pub trait OrchestrationPlanner: Send + Sync {
    /// Produces a plan for `request` given `catalog`. `prior` carries context
    /// from earlier iterations (empty on the first pass) so a re-plan can react
    /// to what already ran.
    fn plan(
        &self,
        request: &OrchestrationRequest,
        catalog: &CatalogSnapshot,
        prior: &[StepResult],
    ) -> Result<OrchestrationPlan>;
}

/// Rule-based planner. Always available, never calls a model. Maps the request's
/// use case onto a minimal ordered plan: an optional single tag-matched skill or
/// tool prelude (when the catalog has an obvious match) followed by one model
/// step carrying the intent. This is the guardrail and the default.
#[derive(Debug, Default, Clone)]
pub struct DeterministicPlanner;

impl DeterministicPlanner {
    /// Finds the highest-signal capability card whose tags or name intersect the
    /// intent words. Returns `None` when nothing clearly matches — the planner
    /// then emits a model-only plan rather than forcing an irrelevant tool.
    fn best_match<'a>(
        cards: &'a [CapabilityCard],
        intent_words: &[String],
    ) -> Option<&'a CapabilityCard> {
        cards
            .iter()
            .map(|c| {
                let score = c
                    .tags
                    .iter()
                    .chain(std::iter::once(&c.name))
                    .filter(|t| {
                        let t = t.to_lowercase();
                        intent_words.iter().any(|w| t.contains(w.as_str()))
                    })
                    .count();
                (c, score)
            })
            .filter(|(_, s)| *s > 0)
            .max_by_key(|(_, s)| *s)
            .map(|(c, _)| c)
    }
}

impl OrchestrationPlanner for DeterministicPlanner {
    fn plan(
        &self,
        request: &OrchestrationRequest,
        catalog: &CatalogSnapshot,
        _prior: &[StepResult],
    ) -> Result<OrchestrationPlan> {
        let intent_words: Vec<String> = request
            .intent
            .split_whitespace()
            .filter(|w| w.len() > 3)
            .map(|w| w.to_lowercase())
            .collect();

        let mut steps = Vec::new();

        // A single skill or tool prelude when the catalog has an obvious match.
        // Skills are preferred over tools when both match (skills are the
        // higher-level, priced capability surface).
        if let Some(card) = Self::best_match(&catalog.skills, &intent_words) {
            steps.push(PlanStep::Skill {
                skill_id: card.id.clone(),
                input: serde_json::json!({ "query": request.intent }),
            });
        } else if let Some(card) = Self::best_match(&catalog.tools, &intent_words) {
            steps.push(PlanStep::Tool {
                tool_id: card.id.clone(),
                input: serde_json::json!({ "query": request.intent }),
            });
        }

        // The terminal model step carries the intent. Always present so a plan
        // never resolves to a bare tool call with no synthesis.
        steps.push(PlanStep::Model {
            use_case: request.use_case.as_str().to_string(),
            model_id: None,
            input: request.intent.clone(),
        });

        let plan = OrchestrationPlan {
            steps,
            rationale: "deterministic use-case decomposition with catalog-matched prelude".into(),
            planner: "deterministic".into(),
        };
        plan.validate()?;
        Ok(plan)
    }
}

/// Model-backed planner. Routes a single planning call through the meta-router's
/// reasoning intent, asking a strong model to emit a JSON plan over the catalog
/// snapshot, then falls back to the wrapped [`DeterministicPlanner`] on any
/// failure. The fallback is what makes the orchestrator resilient: planner
/// unavailability degrades to the rule-based plan instead of failing the call.
pub struct LlmPlanner {
    meta_router: Arc<MetaRouter>,
    fallback: DeterministicPlanner,
    /// How the plan-generation model call is executed. Injected so the node can
    /// wire it to the same inference path a chat request uses without the
    /// planner depending on the RPC layer.
    completion: Arc<dyn PlanCompletion>,
}

/// The seam the [`LlmPlanner`] uses to run its own plan-generation inference,
/// decoupling the planner from the node's chat/inference dispatch. The node
/// implements this against the meta-router + inference router.
pub trait PlanCompletion: Send + Sync {
    /// Runs a completion for `prompt` against `model_id` and returns the text.
    fn complete(&self, model_id: &str, prompt: &str) -> Result<String>;
}

impl LlmPlanner {
    /// Wraps a meta-router and a completion seam. The deterministic fallback is
    /// constructed internally.
    pub fn new(meta_router: Arc<MetaRouter>, completion: Arc<dyn PlanCompletion>) -> Self {
        Self {
            meta_router,
            fallback: DeterministicPlanner,
            completion,
        }
    }

    /// Builds the planning prompt: the intent, the catalog inventory, and a
    /// strict JSON output contract.
    fn planning_prompt(request: &OrchestrationRequest, catalog: &CatalogSnapshot) -> String {
        let skills = catalog
            .skills
            .iter()
            .map(|c| format!("  - skill \"{}\": {} [{}]", c.id, c.description, c.tags.join(",")))
            .collect::<Vec<_>>()
            .join("\n");
        let tools = catalog
            .tools
            .iter()
            .map(|c| format!("  - tool \"{}\": {} [{}]", c.id, c.description, c.tags.join(",")))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "You are a task planner. Decompose the intent into an ordered plan of \
capability steps drawn ONLY from the inventory below, ending in a model step \
that synthesizes the answer. Emit ONLY a JSON object of the form \
{{\"steps\":[...],\"rationale\":\"...\"}} where each step is one of: \
{{\"kind\":\"model\",\"use_case\":\"<{use_cases}>\",\"input\":\"...\"}}, \
{{\"kind\":\"skill\",\"skill_id\":\"...\",\"input\":{{}}}}, \
{{\"kind\":\"tool\",\"tool_id\":\"...\",\"input\":{{}}}}, \
{{\"kind\":\"agent\",\"capabilities\":[...],\"task\":\"...\"}}. \
Max {max} steps. No prose outside the JSON.\n\n\
INTENT: {intent}\n\nAVAILABLE SKILLS:\n{skills}\n\nAVAILABLE TOOLS:\n{tools}\n\
AGENTS_AVAILABLE: {agents}",
            use_cases = UseCase::ALL.join("|"),
            max = MAX_PLAN_STEPS,
            intent = request.intent,
            skills = if skills.is_empty() { "  (none)".into() } else { skills },
            tools = if tools.is_empty() { "  (none)".into() } else { tools },
            agents = catalog.agents_available,
        )
    }

    /// Extracts a plan from a model completion. Tolerates the model wrapping the
    /// JSON in prose by scanning for the outermost `{...}`.
    fn parse_plan(text: &str) -> Result<OrchestrationPlan> {
        let start = text.find('{');
        let end = text.rfind('}');
        let json = match (start, end) {
            (Some(s), Some(e)) if e > s => &text[s..=e],
            _ => {
                return Err(OrchestratorError::InvalidPlan(
                    "planner output contained no JSON object".into(),
                ));
            }
        };
        #[derive(Deserialize)]
        struct RawPlan {
            steps: Vec<PlanStep>,
            #[serde(default)]
            rationale: String,
        }
        let raw: RawPlan = serde_json::from_str(json)
            .map_err(|e| OrchestratorError::InvalidPlan(format!("plan JSON: {e}")))?;
        let plan = OrchestrationPlan {
            steps: raw.steps,
            rationale: raw.rationale,
            planner: "llm".into(),
        };
        plan.validate()?;
        Ok(plan)
    }
}

impl OrchestrationPlanner for LlmPlanner {
    fn plan(
        &self,
        request: &OrchestrationRequest,
        catalog: &CatalogSnapshot,
        prior: &[StepResult],
    ) -> Result<OrchestrationPlan> {
        // Route the planning call itself through the reasoning intent so it
        // picks a strong model within the request's budget/payer envelope.
        let plan_intent = request.model_route_intent(UseCase::Reasoning, 1024);
        let decision = match self.meta_router.route(&plan_intent) {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "LLM planner: routing planning call failed, using deterministic fallback");
                return self.fallback.plan(request, catalog, prior);
            }
        };

        let prompt = Self::planning_prompt(request, catalog);
        let text = match self.completion.complete(&decision.model_id, &prompt) {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, model = %decision.model_id, "LLM planner: completion failed, using deterministic fallback");
                return self.fallback.plan(request, catalog, prior);
            }
        };

        match Self::parse_plan(&text) {
            Ok(plan) => {
                debug!(steps = plan.steps.len(), model = %decision.model_id, "LLM planner produced plan");
                Ok(plan)
            }
            Err(e) => {
                warn!(error = %e, "LLM planner: plan parse failed, using deterministic fallback");
                self.fallback.plan(request, catalog, prior)
            }
        }
    }
}

/// The seam through which the orchestrator dispatches each resolved step. The
/// node implements this against the model/skill/tool/agent subsystems, keeping
/// the orchestrator's execution loop free of RPC-layer detail and letting the
/// planner + loop be unit-tested against a stub executor.
#[async_trait::async_trait]
pub trait StepExecutor: Send + Sync {
    /// Runs one model step. `intent` carries the payer/budget envelope; the
    /// executor selects the provider (honoring `model_id` when the plan pinned
    /// one) and returns `(output_text, estimated_cost, detail)`.
    async fn run_model(
        &self,
        model_id: Option<&str>,
        intent: &RouteIntent,
        input: &str,
    ) -> Result<(String, u128, serde_json::Value)>;

    /// Runs a skill invocation, returning `(output_text, detail)`.
    async fn run_skill(&self, skill_id: &str, input: &serde_json::Value) -> Result<(String, serde_json::Value)>;

    /// Runs a tool invocation, returning `(output_text, detail)`.
    async fn run_tool(&self, tool_id: &str, input: &serde_json::Value) -> Result<(String, serde_json::Value)>;

    /// Delegates a task to an agent, returning `(reply_text, detail)`.
    async fn run_agent(&self, capabilities: &[String], task: &str) -> Result<(String, serde_json::Value)>;

    /// Fans a task to a swarm, returning `(aggregated_text, detail)`.
    async fn run_swarm(&self, members: &[SwarmMemberSpec], task: &str) -> Result<(String, serde_json::Value)>;

    /// Estimates the cost of a model step at plan time, for the wallet-ceiling
    /// pre-check, without dispatching. Returns `0` when the step is free or
    /// unpriceable ahead of time.
    fn estimate_model_cost(&self, model_id: Option<&str>, intent: &RouteIntent) -> u128;

    /// The payer's spendable balance, for the fail-fast ceiling. `u128::MAX`
    /// when no balance provider is wired (ceiling disabled).
    fn wallet_balance(&self, payer: Option<&Address>) -> u128;
}

/// Composes a planner with a step executor and a catalog source into the
/// intent → capabilities runtime.
pub struct Orchestrator {
    planner: Arc<dyn OrchestrationPlanner>,
    executor: Arc<dyn StepExecutor>,
}

impl Orchestrator {
    /// Builds an orchestrator over a planner and an executor.
    pub fn new(planner: Arc<dyn OrchestrationPlanner>, executor: Arc<dyn StepExecutor>) -> Self {
        Self { planner, executor }
    }

    /// Runs `request` against `catalog`: plan, cost-check against the wallet
    /// ceiling, execute front-to-back, re-plan up to the iteration bound if a
    /// step signals `needs_replan`. Returns the final plan and per-step results.
    pub async fn execute(
        &self,
        request: &OrchestrationRequest,
        catalog: &CatalogSnapshot,
    ) -> Result<OrchestrationOutcome> {
        let max_iterations = request.effective_iterations();
        let mut all_results: Vec<StepResult> = Vec::new();
        let mut total_cost: u128 = 0;
        let mut iterations = 0u32;
        let final_plan: OrchestrationPlan;

        loop {
            iterations += 1;
            let plan = self.planner.plan(request, catalog, &all_results)?;
            info!(
                planner = %plan.planner,
                steps = plan.steps.len(),
                iteration = iterations,
                "orchestrator: planned"
            );

            // Fail-fast wallet ceiling: sum the estimated cost of the model
            // steps in this plan and reject before running any of them.
            let balance = self.executor.wallet_balance(request.payer_address.as_ref());
            let plan_cost: u128 = plan
                .steps
                .iter()
                .map(|s| match s {
                    PlanStep::Model { use_case, model_id, .. } => {
                        let uc = UseCase::parse(use_case).unwrap_or(request.use_case);
                        let intent = request.model_route_intent(uc, 256);
                        self.executor.estimate_model_cost(model_id.as_deref(), &intent)
                    }
                    _ => 0,
                })
                .sum();
            if total_cost.saturating_add(plan_cost) > balance {
                return Err(OrchestratorError::OverBudget {
                    estimated: total_cost.saturating_add(plan_cost),
                    balance,
                });
            }

            let mut needs_replan = false;
            for (index, step) in plan.steps.iter().enumerate() {
                let (result, step_cost, replan) = self.run_step(request, index, step).await?;
                total_cost = total_cost.saturating_add(step_cost);
                all_results.push(result);
                if replan {
                    needs_replan = true;
                    break;
                }
            }

            if !needs_replan || iterations >= max_iterations {
                final_plan = plan;
                break;
            }
            debug!(iteration = iterations, "orchestrator: re-planning");
        }

        Ok(OrchestrationOutcome {
            plan: final_plan,
            steps: all_results,
            estimated_cost: total_cost,
            iterations,
        })
    }

    /// Dispatches one step through the executor. Returns
    /// `(result, cost, needs_replan)`. `needs_replan` is reserved for the loop
    /// seam; the current executors never request it, so a step is terminal.
    async fn run_step(
        &self,
        request: &OrchestrationRequest,
        index: usize,
        step: &PlanStep,
    ) -> Result<(StepResult, u128, bool)> {
        let map_fail = |e: OrchestratorError| OrchestratorError::StepFailed {
            index,
            kind: step.kind_label().to_string(),
            reason: e.to_string(),
        };

        match step {
            PlanStep::Model { use_case, model_id, input } => {
                let uc = UseCase::parse(use_case).unwrap_or(request.use_case);
                let intent = request.model_route_intent(uc, (input.len() / 4).max(1) as u64);
                let (output, cost, detail) = self
                    .executor
                    .run_model(model_id.as_deref(), &intent, input)
                    .await
                    .map_err(map_fail)?;
                Ok((StepResult { kind: "model".into(), output, detail }, cost, false))
            }
            PlanStep::Skill { skill_id, input } => {
                let (output, detail) =
                    self.executor.run_skill(skill_id, input).await.map_err(map_fail)?;
                Ok((StepResult { kind: "skill".into(), output, detail }, 0, false))
            }
            PlanStep::Tool { tool_id, input } => {
                let (output, detail) =
                    self.executor.run_tool(tool_id, input).await.map_err(map_fail)?;
                Ok((StepResult { kind: "tool".into(), output, detail }, 0, false))
            }
            PlanStep::Agent { capabilities, task } => {
                let (output, detail) =
                    self.executor.run_agent(capabilities, task).await.map_err(map_fail)?;
                Ok((StepResult { kind: "agent".into(), output, detail }, 0, false))
            }
            PlanStep::Swarm { members, task } => {
                let (output, detail) =
                    self.executor.run_swarm(members, task).await.map_err(map_fail)?;
                Ok((StepResult { kind: "swarm".into(), output, detail }, 0, false))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(id: &str, name: &str, tags: &[&str]) -> CapabilityCard {
        CapabilityCard {
            id: id.into(),
            name: name.into(),
            description: format!("{name} capability"),
            tags: tags.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn empty_catalog() -> CatalogSnapshot {
        CatalogSnapshot::default()
    }

    /// Records what the stub executor was asked to run.
    #[derive(Default)]
    struct StubExecutor {
        balance: u128,
        model_cost: u128,
    }

    #[async_trait::async_trait]
    impl StepExecutor for StubExecutor {
        async fn run_model(
            &self,
            model_id: Option<&str>,
            _intent: &RouteIntent,
            input: &str,
        ) -> Result<(String, u128, serde_json::Value)> {
            Ok((
                format!("model-out:{input}"),
                self.model_cost,
                serde_json::json!({ "model_id": model_id }),
            ))
        }
        async fn run_skill(&self, skill_id: &str, _input: &serde_json::Value) -> Result<(String, serde_json::Value)> {
            Ok((format!("skill-out:{skill_id}"), serde_json::Value::Null))
        }
        async fn run_tool(&self, tool_id: &str, _input: &serde_json::Value) -> Result<(String, serde_json::Value)> {
            Ok((format!("tool-out:{tool_id}"), serde_json::Value::Null))
        }
        async fn run_agent(&self, _caps: &[String], task: &str) -> Result<(String, serde_json::Value)> {
            Ok((format!("agent-out:{task}"), serde_json::Value::Null))
        }
        async fn run_swarm(&self, _members: &[SwarmMemberSpec], task: &str) -> Result<(String, serde_json::Value)> {
            Ok((format!("swarm-out:{task}"), serde_json::Value::Null))
        }
        fn estimate_model_cost(&self, _model_id: Option<&str>, _intent: &RouteIntent) -> u128 {
            self.model_cost
        }
        fn wallet_balance(&self, _payer: Option<&Address>) -> u128 {
            self.balance
        }
    }

    #[test]
    fn deterministic_model_only_when_no_catalog_match() {
        let planner = DeterministicPlanner;
        let req = OrchestrationRequest::new("write a haiku about rust");
        let plan = planner.plan(&req, &empty_catalog(), &[]).unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert!(matches!(plan.steps[0], PlanStep::Model { .. }));
    }

    #[test]
    fn deterministic_prepends_matched_skill() {
        let planner = DeterministicPlanner;
        let catalog = CatalogSnapshot {
            skills: vec![card("web-search", "web search", &["search", "web", "retrieval"])],
            ..Default::default()
        };
        let req = OrchestrationRequest::new("search the web for rust release notes");
        let plan = planner.plan(&req, &catalog, &[]).unwrap();
        assert_eq!(plan.steps.len(), 2);
        assert!(matches!(&plan.steps[0], PlanStep::Skill { skill_id, .. } if skill_id == "web-search"));
        assert!(matches!(plan.steps[1], PlanStep::Model { .. }));
    }

    #[test]
    fn deterministic_prefers_skill_over_tool() {
        let planner = DeterministicPlanner;
        let catalog = CatalogSnapshot {
            skills: vec![card("analysis", "data analysis", &["analysis", "data"])],
            tools: vec![card("analysis-tool", "analysis tool", &["analysis", "data"])],
            ..Default::default()
        };
        let req = OrchestrationRequest::new("run a data analysis over this dataset");
        let plan = planner.plan(&req, &catalog, &[]).unwrap();
        assert!(matches!(&plan.steps[0], PlanStep::Skill { .. }));
    }

    #[test]
    fn plan_validation_rejects_bad_use_case() {
        let plan = OrchestrationPlan {
            steps: vec![PlanStep::Model {
                use_case: "not-a-use-case".into(),
                model_id: None,
                input: "x".into(),
            }],
            rationale: String::new(),
            planner: "test".into(),
        };
        assert!(plan.validate().is_err());
    }

    #[test]
    fn plan_validation_rejects_empty_and_oversized() {
        let empty = OrchestrationPlan {
            steps: vec![],
            rationale: String::new(),
            planner: "test".into(),
        };
        assert!(empty.validate().is_err());

        let big = OrchestrationPlan {
            steps: (0..MAX_PLAN_STEPS + 1)
                .map(|_| PlanStep::Model {
                    use_case: "chat".into(),
                    model_id: None,
                    input: "x".into(),
                })
                .collect(),
            rationale: String::new(),
            planner: "test".into(),
        };
        assert!(big.validate().is_err());
    }

    #[tokio::test]
    async fn execute_runs_plan_and_sums_cost() {
        let planner: Arc<dyn OrchestrationPlanner> = Arc::new(DeterministicPlanner);
        let executor: Arc<dyn StepExecutor> = Arc::new(StubExecutor {
            balance: 1_000_000,
            model_cost: 42,
        });
        let orch = Orchestrator::new(planner, executor);
        let req = OrchestrationRequest::new("hello world");
        let outcome = orch.execute(&req, &empty_catalog()).await.unwrap();
        assert_eq!(outcome.steps.len(), 1);
        assert_eq!(outcome.estimated_cost, 42);
        assert_eq!(outcome.iterations, 1);
        assert_eq!(outcome.steps[0].kind, "model");
    }

    #[tokio::test]
    async fn execute_rejects_over_wallet_ceiling() {
        let planner: Arc<dyn OrchestrationPlanner> = Arc::new(DeterministicPlanner);
        let executor: Arc<dyn StepExecutor> = Arc::new(StubExecutor {
            balance: 10,
            model_cost: 100,
        });
        let orch = Orchestrator::new(planner, executor);
        let req = OrchestrationRequest::new("expensive")
            .with_payer_address(Address::default());
        let err = orch.execute(&req, &empty_catalog()).await.unwrap_err();
        assert!(matches!(err, OrchestratorError::OverBudget { .. }));
    }

    #[test]
    fn llm_parse_plan_tolerates_prose_wrapping() {
        let text = "Here is the plan you asked for:\n\
            {\"steps\":[{\"kind\":\"model\",\"use_case\":\"chat\",\"input\":\"hi\"}],\"rationale\":\"trivial\"}\n\
            Hope that helps!";
        let plan = LlmPlanner::parse_plan(text).unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.planner, "llm");
    }

    #[test]
    fn llm_parse_plan_rejects_no_json() {
        assert!(LlmPlanner::parse_plan("no json here").is_err());
    }
}
