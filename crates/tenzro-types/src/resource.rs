//! Unified resource discovery + invocation type.
//!
//! Tenzro Network's resource registries (tools, skills, knowledge,
//! workflow templates, agent templates, models) are each separate
//! catalogs with their own type model. The discovery layer collapses
//! them into a single shape so an agent can ask "what resources match
//! this filter?" once and pick from a single result set.
//!
//! The `ResourceDescriptor` is the cross-registry projection. It
//! carries enough metadata for an agent to decide whether to use the
//! resource — class, name, capabilities, price, reputation — and
//! enough to invoke it via `tenzro_useResource(resource_id, params)`.

use crate::primitives::Address;
use serde::{Deserialize, Serialize};

/// Which registry a resource lives in. Drives the dispatch target
/// for `tenzro_useResource`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ResourceClass {
    /// `CF_TOOLS` — invocable MCP servers, API tools, native ops.
    Tool,
    /// `CF_SKILLS` — declarative capability descriptors.
    Skill,
    /// `CF_KNOWLEDGE` — queryable data resources (vector DBs, feeds, etc).
    Knowledge,
    /// `CF_WORKFLOW_TEMPLATES` — reusable workflow blueprints.
    WorkflowTemplate,
    /// `CF_AGENT_TEMPLATES` — reusable agent specs.
    AgentTemplate,
    /// `CF_MODELS` — AI inference models.
    Model,
}

impl ResourceClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceClass::Tool => "tool",
            ResourceClass::Skill => "skill",
            ResourceClass::Knowledge => "knowledge",
            ResourceClass::WorkflowTemplate => "workflow_template",
            ResourceClass::AgentTemplate => "agent_template",
            ResourceClass::Model => "model",
        }
    }

    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "tool" => Some(ResourceClass::Tool),
            "skill" => Some(ResourceClass::Skill),
            "knowledge" => Some(ResourceClass::Knowledge),
            "workflow_template" => Some(ResourceClass::WorkflowTemplate),
            "agent_template" => Some(ResourceClass::AgentTemplate),
            "model" => Some(ResourceClass::Model),
            _ => None,
        }
    }
}

/// Cross-registry projection of a single resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDescriptor {
    /// Which registry this resource lives in.
    pub class: ResourceClass,

    /// Unique id in the source registry. Caller passes this back to
    /// `tenzro_useResource(resource_id, params)` for invocation.
    pub resource_id: String,

    pub name: String,
    pub version: String,
    pub description: String,
    pub category: String,

    /// Capability tags lifted from the source registry. Used for the
    /// post-filter on `tenzro_listResources(capability_tags=...)`.
    pub capabilities: Vec<String>,

    pub creator_did: Option<String>,

    /// Operator payout wallet. Tenants pay TNZO; the protocol splits
    /// 5% to treasury, 95% to this wallet.
    pub creator_wallet: Option<Address>,

    /// Per-invocation cost in atto-TNZO. `0` = free.
    #[serde(with = "crate::primitives::u128_serde")]
    pub price_per_call: u128,

    /// `true` when the resource is `Active` in the source registry.
    pub is_available: bool,

    /// Last liveness heartbeat (seconds). Helps the discovery layer
    /// surface staleness without filtering aggressively.
    pub last_seen_at: u64,

    /// Optional kind / sub-type from the source registry, projected
    /// as a plain string. E.g. for `Tool` this is the transport mode
    /// (`mcp` / `mcp-stdio` / `api` / `native`); for
    /// `Knowledge` this is the kind (`vector_index` / `feed` / ...).
    pub subtype: Option<String>,

    /// Reputation score (0..=1000). `None` when the source registry
    /// doesn't track reputation (only Models do today).
    pub reputation: Option<u64>,
}

/// Filter for `tenzro_listResources`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceFilter {
    /// Subset of resource classes to query. Empty = all classes.
    #[serde(default)]
    pub classes: Vec<String>,

    /// Free-text query — matches name, description, capabilities.
    #[serde(default)]
    pub query: Option<String>,

    /// Capability tags — AND-match. Empty = no filter.
    #[serde(default)]
    pub capability_tags: Vec<String>,

    /// Optional category filter.
    #[serde(default)]
    pub category: Option<String>,

    /// Cost ceiling in atto-TNZO. Resources whose `price_per_call`
    /// exceeds this are filtered out. `None` = no ceiling.
    #[serde(default)]
    pub max_tnzo_price: Option<u128>,

    /// Filter by creator DID.
    #[serde(default)]
    pub creator_did: Option<String>,

    #[serde(default)]
    pub limit: Option<usize>,

    #[serde(default)]
    pub offset: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_class_roundtrip() {
        for c in [
            ResourceClass::Tool,
            ResourceClass::Skill,
            ResourceClass::Knowledge,
            ResourceClass::WorkflowTemplate,
            ResourceClass::AgentTemplate,
            ResourceClass::Model,
        ] {
            assert_eq!(ResourceClass::parse_str(c.as_str()), Some(c));
        }
        assert_eq!(ResourceClass::parse_str("nope"), None);
    }
}
