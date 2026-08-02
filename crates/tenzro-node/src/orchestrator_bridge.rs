//! Node-side wiring for the intent [`Orchestrator`].
//!
//! [`crate::orchestrator`] is deliberately RPC- and node-free: it composes a
//! planner with a [`StepExecutor`] trait and unit-tests against a stub. This
//! module is the only place that implements that trait against the node's live
//! subsystems — the meta-router, the inference/chat path, the `CF_SKILLS` /
//! `CF_TOOLS` registries, the swarm manager, and the wallet ledger — mirroring
//! how [`crate::spending_policy_bridge`] glues two otherwise-decoupled crates.
//!
//! Every capability step reuses the same code path a direct RPC call would take:
//! a model step routes through [`crate::rpc::handle_chat`] (one inference path,
//! so provenance, usage recording, and settlement stay identical), skill and
//! tool steps route through [`crate::rpc::handle_use_skill`] /
//! [`crate::rpc::handle_use_tool`] (so commission settlement still fires), and
//! agent/swarm steps route through [`SwarmManager`]. Nothing here re-implements
//! dispatch; it adapts the orchestrator's typed steps onto the existing handlers.

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_model::meta_router::RouteIntent;
use tenzro_storage::KvStore;
use tenzro_types::agent::SwarmConfig;
use tenzro_types::primitives::Address;

use crate::node::TenzroNode;
use crate::orchestrator::{
    CapabilityCard, CatalogSnapshot, DeterministicPlanner, LlmPlanner, Orchestrator,
    OrchestratorError, PlanCompletion, Result as OrchResult, StepExecutor, SwarmMemberSpec,
};
use crate::rpc::AuthContext;

/// The agent id the orchestrator spawns swarm/agent members under when it needs
/// to delegate. Present in the runtime only when this node runs an agent
/// runtime; agent/swarm steps degrade to [`OrchestratorError::Unavailable`]
/// otherwise, matching the "no subsystem, clean rejection" contract.
const ORCHESTRATOR_COORDINATOR_ID: &str = "swarm-coordinator";

/// Implements [`StepExecutor`] and [`PlanCompletion`] against a live node.
///
/// Holds an `Arc<TenzroNode>` and dispatches each step through the node's
/// existing handlers. `run_model` is `async` on the executor trait, so the
/// blocking pieces (none here — the handlers are already async) compose
/// directly.
pub struct NodeStepExecutor {
    node: Arc<TenzroNode>,
    /// The orchestrating caller's own auth context, carried down into
    /// skill and tool steps. A plan spends on the caller's behalf, so the
    /// caller's controller keeps the same leash it would have on a direct
    /// `tenzro_useSkill` / `tenzro_useTool` call.
    auth_ctx: AuthContext,
}

impl NodeStepExecutor {
    /// Wraps a node handle plus the caller's auth context.
    pub fn new(node: Arc<TenzroNode>, auth_ctx: AuthContext) -> Self {
        Self { node, auth_ctx }
    }

    /// Extracts the assistant text from a `tenzro_chat` rich-shape response,
    /// concatenating every text block. Non-text blocks are ignored.
    fn chat_text(response: &Value) -> String {
        response
            .get("content")
            .and_then(|c| c.as_array())
            .map(|blocks| {
                blocks
                    .iter()
                    .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default()
    }

    /// Pulls a settlement cost (smallest TNZO unit) out of a chat response's
    /// `cost_wei` string, defaulting to 0 when absent or unparseable.
    fn chat_cost(response: &Value) -> u128 {
        response
            .get("cost_wei")
            .and_then(|c| c.as_str())
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0)
    }

    /// Extracts a human-readable output from a skill/tool handler response,
    /// preferring a top-level `output`/`result`/`text` string and falling back
    /// to the compact JSON form.
    fn registry_output(response: &Value) -> String {
        for key in ["output", "result", "text", "content"] {
            if let Some(s) = response.get(key).and_then(|v| v.as_str()) {
                return s.to_string();
            }
        }
        response.to_string()
    }
}

#[async_trait::async_trait]
impl StepExecutor for NodeStepExecutor {
    async fn run_model(
        &self,
        model_id: Option<&str>,
        intent: &RouteIntent,
        input: &str,
    ) -> OrchResult<(String, u128, Value)> {
        // Resolve the concrete model: honor a plan-pinned id, otherwise let the
        // meta-router pick one for the step's intent.
        let resolved = match model_id {
            Some(m) => m.to_string(),
            None => {
                let meta = self
                    .node
                    .meta_router()
                    .ok_or_else(|| OrchestratorError::Unavailable("meta-router".into()))?;
                // The step's input is the text the model will answer, so it is
                // what places this call in a difficulty cluster.
                let step_intent = intent.clone().with_prompt(input);
                meta.route_intent(&step_intent)
                    .await
                    .map_err(|e| OrchestratorError::NoCapability(e.to_string()))?
                    .model_id
            }
        };

        // Reuse the single chat inference path (rich shape) so provenance,
        // usage recording, and settlement are identical to a direct call.
        let params = json!({
            "model_id": resolved,
            "messages": [{ "role": "user", "content": input }],
        });
        let response = crate::rpc::handle_chat(&self.node, Some(params))
            .await
            .map_err(|e| OrchestratorError::NoCapability(e.message))?;

        let text = Self::chat_text(&response);
        let cost = Self::chat_cost(&response);
        let detail = json!({ "model_id": resolved });
        Ok((text, cost, detail))
    }

    async fn run_skill(&self, skill_id: &str, input: &Value) -> OrchResult<(String, Value)> {
        let params = json!({ "skill_id": skill_id, "input": input });
        let response = crate::rpc::handle_use_skill(self.node.clone(), params, &self.auth_ctx)
            .await
            .map_err(|e| OrchestratorError::NoCapability(e.message))?;
        let output = Self::registry_output(&response);
        Ok((output, response))
    }

    async fn run_tool(&self, tool_id: &str, input: &Value) -> OrchResult<(String, Value)> {
        let params = json!({ "tool_id": tool_id, "input": input });
        let response = crate::rpc::handle_use_tool(self.node.clone(), params, None, &self.auth_ctx)
            .await
            .map_err(|e| OrchestratorError::NoCapability(e.message))?;
        let output = Self::registry_output(&response);
        Ok((output, response))
    }

    async fn run_agent(&self, capabilities: &[String], task: &str) -> OrchResult<(String, Value)> {
        // A single-agent delegation is a one-member swarm: it reuses the swarm
        // spawn + broadcast path rather than duplicating agent lifecycle here.
        let members = vec![SwarmMemberSpec {
            name: "delegate".to_string(),
            capabilities: capabilities.to_vec(),
        }];
        self.run_swarm(&members, task).await
    }

    async fn run_swarm(
        &self,
        members: &[SwarmMemberSpec],
        task: &str,
    ) -> OrchResult<(String, Value)> {
        let swarm = self
            .node
            .swarm_manager()
            .ok_or_else(|| OrchestratorError::Unavailable("swarm-manager".into()))?;

        let specs: Vec<(String, Vec<String>)> = members
            .iter()
            .map(|m| (m.name.clone(), m.capabilities.clone()))
            .collect();

        let swarm_id = swarm
            .create_swarm(ORCHESTRATOR_COORDINATOR_ID, specs, SwarmConfig::default())
            .await
            .map_err(|e| OrchestratorError::Unavailable(format!("swarm create: {e}")))?;

        let replies = swarm
            .broadcast_task(&swarm_id, task)
            .await
            .map_err(|e| OrchestratorError::NoCapability(format!("swarm dispatch: {e}")))?;

        let output = replies.join("\n");
        let detail = json!({ "swarm_id": swarm_id, "replies": replies });
        Ok((output, detail))
    }

    fn estimate_model_cost(&self, model_id: Option<&str>, intent: &RouteIntent) -> u128 {
        // Ask the meta-router for the routing decision it would make and read
        // its pre-computed estimate. When a model is pinned, the router still
        // estimates against the intent's use case; the estimate is advisory for
        // the fail-fast ceiling, so a miss defaults to 0 (admit) rather than
        // blocking.
        let _ = model_id;
        self.node
            .meta_router()
            .and_then(|m| m.route(intent).ok())
            .map(|d| d.estimated_cost)
            .unwrap_or(0)
    }

    fn wallet_balance(&self, payer: Option<&Address>) -> u128 {
        // No payer address, or no token ledger => ceiling disabled (u128::MAX).
        match (payer, self.node.token()) {
            (Some(addr), Some(token)) => token.balance_of(addr),
            _ => u128::MAX,
        }
    }
}

impl PlanCompletion for NodeStepExecutor {
    fn complete(&self, model_id: &str, prompt: &str) -> OrchResult<String> {
        // The LLM planner runs its plan-generation call synchronously from
        // within `plan()`. Bridge to the async chat path on the node's own
        // runtime handle via `block_in_place` + `Handle::block_on`, so the
        // planner stays a pure `fn` while still reusing the one inference path.
        let node = self.node.clone();
        let model_id = model_id.to_string();
        let prompt = prompt.to_string();
        let response = tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async move {
                let params = json!({
                    "model_id": model_id,
                    "messages": [{ "role": "user", "content": prompt }],
                });
                crate::rpc::handle_chat(&node, Some(params)).await
            })
        })
        .map_err(|e| OrchestratorError::NoCapability(e.message))?;
        Ok(Self::chat_text(&response))
    }
}

/// Reads the `CF_SKILLS` and `CF_TOOLS` registries into a [`CatalogSnapshot`]
/// the planner reasons over. Best-effort: a storage miss yields an empty
/// catalog (the deterministic planner then emits a model-only plan), never an
/// error, because catalog absence must not fail an orchestration.
pub fn build_catalog_snapshot(node: &Arc<TenzroNode>) -> CatalogSnapshot {
    let Some(storage) = node.storage() else {
        return CatalogSnapshot::default();
    };

    let skills = storage
        .get_keys_with_prefix(tenzro_storage::CF_SKILLS, b"")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|key| storage.get(tenzro_storage::CF_SKILLS, &key).ok().flatten())
        .filter_map(|bytes| serde_json::from_slice::<tenzro_types::SkillDefinition>(&bytes).ok())
        .filter(|s| s.is_available())
        .map(|s| CapabilityCard {
            id: s.skill_id,
            name: s.name,
            description: s.description,
            tags: s.tags,
        })
        .collect();

    let tools = storage
        .get_keys_with_prefix(tenzro_storage::CF_TOOLS, b"")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|key| storage.get(tenzro_storage::CF_TOOLS, &key).ok().flatten())
        .filter_map(|bytes| serde_json::from_slice::<tenzro_types::ToolDefinition>(&bytes).ok())
        .map(|t| CapabilityCard {
            id: t.tool_id,
            name: t.name,
            description: t.description,
            // Tools carry `capabilities`, not `tags`; they serve the same
            // planner-matching role, so map them onto the card's tag axis.
            tags: t.capabilities,
        })
        .collect();

    CatalogSnapshot {
        skills,
        tools,
        agents_available: node.agent_runtime().is_some() && node.swarm_manager().is_some(),
    }
}

/// Constructs the node's [`Orchestrator`].
///
/// Planner selection: when a meta-router is present, the [`LlmPlanner`] plans
/// over the catalog (falling back to the [`DeterministicPlanner`] on any model
/// failure — see the orchestrator module docs). With no meta-router the
/// deterministic planner is used directly, so an inference-less node still
/// orchestrates skills/tools.
pub fn build_orchestrator(node: Arc<TenzroNode>, auth_ctx: AuthContext) -> Orchestrator {
    let executor = Arc::new(NodeStepExecutor::new(node.clone(), auth_ctx));

    match node.meta_router() {
        Some(meta) => {
            let planner = Arc::new(LlmPlanner::new(meta.clone(), executor.clone()));
            Orchestrator::new(planner, executor)
        }
        None => {
            let planner = Arc::new(DeterministicPlanner);
            Orchestrator::new(planner, executor)
        }
    }
}
