//! Workflow template catalog types.
//!
//! Operator-curated reusable workflow specs that tenants discover and
//! instantiate via `tenzro_instantiateWorkflow`. Distinct from
//! running-workflow state (which lives in `tenzro-workflow`'s own
//! storage); this registry holds the *blueprints*.
//!
//! A workflow template is a sequence of steps where each step is one
//! of:
//!
//! - **Use a tool / MCP** — call a registered tool with given params
//! - **Use a model** — call a registered model with given params
//! - **Use a knowledge resource** — query a registered knowledge
//!   resource
//! - **Spawn a child agent** — atomic create+fund+scope+install
//! - **Wait** — sleep / wait on an external signal / wait on a
//!   gossipsub event / wait for an on-chain finality
//! - **Branch** — conditional dispatch based on a previous step's
//!   output
//! - **Parallel** — fan-out multiple sub-workflows and join on
//!   completion (compensation cascades inward)
//!
//! When a tenant calls `tenzro_instantiateWorkflow(template_id,
//! inputs)`, the node validates inputs against the template's
//! `required_inputs` schema, opens a saga in `tenzro-workflow`, and
//! returns the running workflow id for status polling.

use crate::primitives::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowTemplateStatus {
    #[default]
    Active,
    Inactive,
    Deprecated,
}

/// Type of a single step in a workflow template. Each variant
/// carries the parameters that step's executor needs.
///
/// Conditional dispatch (branch) and fan-out (parallel) are
/// represented as `Compound` steps with their sub-steps encoded as
/// an array of step ids referenced from the workflow's flat step
/// table. This keeps the enum non-recursive (recursive `Box<Self>`
/// variants don't compose with internally-tagged serde derivation)
/// while still expressing the full control flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum WorkflowStepSpec {
    /// Invoke a tool / MCP. `tool_id` is resolved against `CF_TOOLS`
    /// at instantiate time; the params block can reference earlier
    /// step outputs via `{{ steps.<n>.output.<path> }}` tokens.
    UseTool {
        tool_id: String,
        tool_name: String,
        params: serde_json::Value,
        /// Optional output binding name — later steps refer to this
        /// step's output via this name.
        #[serde(default)]
        output_as: Option<String>,
    },
    /// Invoke a model.
    UseModel {
        model_id: String,
        params: serde_json::Value,
        #[serde(default)]
        output_as: Option<String>,
    },
    /// Query a knowledge resource.
    UseKnowledge {
        knowledge_id: String,
        params: serde_json::Value,
        #[serde(default)]
        output_as: Option<String>,
    },
    /// Spawn a child agent under the parent's sub-budget.
    SpawnAgent {
        agent_template_id: String,
        tnzo_budget: u128,
        #[serde(default)]
        valid_until: Option<i64>,
        scope_overrides: serde_json::Value,
        #[serde(default)]
        output_as: Option<String>,
    },
    /// Wait for a duration or an external signal.
    Wait {
        wait_kind: String,
        params: serde_json::Value,
    },
    /// Conditional dispatch / fan-out. `op` is "branch" or "parallel".
    /// For `branch`: `condition` is a CEL-style expression over earlier
    /// step outputs; `if_true_step_ids` and `if_false_step_ids` reference
    /// other step ids in the workflow's `steps` array by index. For
    /// `parallel`: `step_ids` lists the sub-step indices to fan out.
    Compound {
        op: String,
        #[serde(default)]
        condition: Option<String>,
        #[serde(default)]
        if_true_step_ids: Vec<usize>,
        #[serde(default)]
        if_false_step_ids: Vec<usize>,
        #[serde(default)]
        step_ids: Vec<usize>,
        #[serde(default)]
        fail_fast: bool,
    },
}

/// A workflow template — the blueprint for a reusable multi-step
/// saga.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTemplate {
    pub template_id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub category: String,
    pub capabilities: Vec<String>,
    pub creator_did: Option<String>,
    pub creator_wallet: Option<Address>,
    /// One-time TNZO cost to instantiate this template. Goes to
    /// creator_wallet with the same 5% commission split as tools.
    /// Free templates (price_per_instantiate == 0) may omit
    /// creator_wallet.
    #[serde(with = "crate::primitives::u128_serde")]
    pub price_per_instantiate: u128,
    pub status: WorkflowTemplateStatus,
    pub created_at: u64,
    pub instantiation_count: u64,
    #[serde(default = "default_last_seen")]
    pub last_seen_at: u64,

    /// JSON-Schema (or schema-like description) of the inputs the
    /// instantiation accepts. The node validates the tenant's
    /// invocation against this schema before opening the saga.
    pub required_inputs: serde_json::Value,

    /// JSON-Schema of the workflow's final output shape.
    pub expected_outputs: serde_json::Value,

    /// The ordered sequence of steps. Cleanup steps (per-step
    /// compensation) ride on the corresponding `WorkflowStepSpec`'s
    /// metadata in `tenzro-workflow`'s own saga model.
    pub steps: Vec<WorkflowStepSpec>,

    #[serde(default)]
    pub allowed_to_subjects: Option<Vec<String>>,
}

fn default_last_seen() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl WorkflowTemplate {
    pub fn new(
        name: String,
        version: String,
        description: String,
        category: String,
        steps: Vec<WorkflowStepSpec>,
    ) -> Self {
        let template_id = uuid::Uuid::new_v4().to_string();
        let created_at = default_last_seen();
        Self {
            template_id,
            name,
            version,
            description,
            category,
            capabilities: Vec::new(),
            creator_did: None,
            creator_wallet: None,
            price_per_instantiate: 0,
            status: WorkflowTemplateStatus::Active,
            created_at,
            instantiation_count: 0,
            last_seen_at: created_at,
            required_inputs: serde_json::json!({}),
            expected_outputs: serde_json::json!({}),
            steps,
            allowed_to_subjects: None,
        }
    }

    pub fn is_paid(&self) -> bool {
        self.price_per_instantiate > 0
    }

    pub fn validate_for_registration(&self) -> Result<(), &'static str> {
        if self.is_paid() && self.creator_wallet.is_none() {
            return Err("Paid workflow template requires a creator_wallet");
        }
        if self.steps.is_empty() {
            return Err("Workflow template must declare at least one step");
        }
        Ok(())
    }

    pub fn is_available(&self) -> bool {
        self.status == WorkflowTemplateStatus::Active
    }

    pub fn touch(&mut self) {
        self.last_seen_at = default_last_seen();
    }

    pub fn is_subject_allowed(&self, subject: Option<&str>) -> bool {
        match (&self.allowed_to_subjects, subject) {
            (None, _) => true,
            (Some(list), Some(s)) => list.iter().any(|x| x == s),
            (Some(_), None) => false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkflowTemplateFilter {
    pub category: Option<String>,
    pub status: Option<String>,
    pub creator_did: Option<String>,
    pub query: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowInstantiationResult {
    pub template_id: String,
    pub workflow_id: String,
    pub started_at: u64,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_steps_rejected() {
        let t = WorkflowTemplate::new(
            "x".to_string(),
            "1".to_string(),
            "x".to_string(),
            "x".to_string(),
            Vec::new(),
        );
        assert!(t.validate_for_registration().is_err());
    }

    #[test]
    fn paid_without_wallet_rejected() {
        let mut t = WorkflowTemplate::new(
            "x".to_string(),
            "1".to_string(),
            "x".to_string(),
            "x".to_string(),
            vec![WorkflowStepSpec::Wait {
                wait_kind: "duration".to_string(),
                params: serde_json::json!({"seconds": 1}),
            }],
        );
        t.price_per_instantiate = 100;
        assert!(t.validate_for_registration().is_err());
    }

    #[test]
    fn step_serialization_roundtrip() {
        let step = WorkflowStepSpec::UseTool {
            tool_id: "tool-123".to_string(),
            tool_name: "search".to_string(),
            params: serde_json::json!({"q": "test"}),
            output_as: Some("search_result".to_string()),
        };
        let json = serde_json::to_string(&step).unwrap();
        let parsed: WorkflowStepSpec = serde_json::from_str(&json).unwrap();
        match parsed {
            WorkflowStepSpec::UseTool { tool_id, .. } => assert_eq!(tool_id, "tool-123"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn wait_step_roundtrip() {
        let step = WorkflowStepSpec::Wait {
            wait_kind: "duration".to_string(),
            params: serde_json::json!({"seconds": 1}),
        };
        let json = serde_json::to_string(&step).unwrap();
        let _: WorkflowStepSpec = serde_json::from_str(&json).unwrap();
    }
}
