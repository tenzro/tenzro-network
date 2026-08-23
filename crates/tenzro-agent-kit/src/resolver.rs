//! Auto-discovery of tools and skills from the Tenzro registries.
//!
//! Given an [`ExecutionSpec`]'s `required_tool_tags` and `required_skill_tags`,
//! the resolver queries the live registries (`CF_TOOLS`, `CF_SKILLS`) via the
//! existing `tenzro_searchTools` / `tenzro_searchSkills` JSON-RPC methods and
//! binds the first `Active` match for each tag.
//!
//! ## Why a separate type?
//!
//! Auto-discovery is the **single most important property** of `tenzro-agent-kit`:
//! it is what lets the crate stay zero-hardcoding. Putting the resolver in its own
//! module makes it easy to swap discovery strategies (substring search vs. exact
//! tag match vs. semantic search) without touching the spawner.
//!
//! ## Discovery rules
//!
//! - Each tag is a free-text query against the registry's substring-search RPC.
//! - The first result whose `status` is `Active` is bound.
//! - A tag with **zero** active matches returns
//!   [`AgentKitError::UnresolvedToolTag`] / [`AgentKitError::UnresolvedSkillTag`].
//! - The resolver does **no** caching: every spawn re-queries the live registry,
//!   so an agent always picks up the freshest tool/skill versions.

use std::sync::Arc;

use tenzro_types::agent_template::ExecutionSpec;
use tenzro_types::skill::{SkillDefinition, SkillFilter, SkillStatus};
use tenzro_types::tool::{ToolDefinition, ToolFilter, ToolStatus};

use crate::error::AgentKitError;
use crate::registry::RegistryClient;

/// Bag of tools and skills discovered for a single template spawn.
///
/// Indexes are kept as parallel `(tag, definition)` pairs so the executor
/// can look up the resolved id by the original tag from the spec.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DiscoveredResources {
    /// Tag → tool definition pairs (in the order they appear in the spec).
    pub tools: Vec<(String, ToolDefinition)>,

    /// Tag → skill definition pairs (in the order they appear in the spec).
    pub skills: Vec<(String, SkillDefinition)>,
}

impl DiscoveredResources {
    /// Returns the tool registered under the given tag, if any.
    pub fn tool_by_tag(&self, tag: &str) -> Option<&ToolDefinition> {
        self.tools
            .iter()
            .find_map(|(t, def)| (t == tag).then_some(def))
    }

    /// Returns the skill registered under the given tag, if any.
    pub fn skill_by_tag(&self, tag: &str) -> Option<&SkillDefinition> {
        self.skills
            .iter()
            .find_map(|(t, def)| (t == tag).then_some(def))
    }

    /// Number of resolved tools.
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Number of resolved skills.
    pub fn skill_count(&self) -> usize {
        self.skills.len()
    }
}

/// Resolves tool and skill tags against the live registry.
#[derive(Debug, Clone)]
pub struct TemplateResolver {
    registry: Arc<RegistryClient>,
}

impl TemplateResolver {
    /// Constructs a resolver wrapping a shared registry client.
    pub fn new(registry: Arc<RegistryClient>) -> Self {
        Self { registry }
    }

    /// Walks the spec's `required_tool_tags` + `required_skill_tags` and
    /// resolves each one against the live registry.
    pub async fn resolve(
        &self,
        spec: &ExecutionSpec,
    ) -> Result<DiscoveredResources, AgentKitError> {
        let mut out = DiscoveredResources::default();

        for tag in &spec.required_tool_tags {
            let tool = self.resolve_tool_tag(tag).await?;
            out.tools.push((tag.clone(), tool));
        }

        for tag in &spec.required_skill_tags {
            let skill = self.resolve_skill_tag(tag).await?;
            out.skills.push((tag.clone(), skill));
        }

        Ok(out)
    }

    /// Resolves a single tool tag. Returns the first `Active` match, or
    /// [`AgentKitError::UnresolvedToolTag`] if none exist.
    pub async fn resolve_tool_tag(&self, tag: &str) -> Result<ToolDefinition, AgentKitError> {
        let filter = ToolFilter {
            query: Some(tag.to_string()),
            status: Some("active".to_string()),
            limit: Some(20),
            ..Default::default()
        };

        let mut results = self.registry.search_tools(filter).await?;

        // Prefer category exact match if available, then fall through to first active.
        if let Some(idx) = results.iter().position(|t| t.category == tag) {
            return Ok(results.swap_remove(idx));
        }
        if let Some(idx) = results
            .iter()
            .position(|t| t.capabilities.iter().any(|c| c == tag))
        {
            return Ok(results.swap_remove(idx));
        }
        results
            .into_iter()
            .find(|t| t.status == ToolStatus::Active)
            .ok_or_else(|| AgentKitError::UnresolvedToolTag(tag.to_string()))
    }

    /// Resolves a single skill tag. Returns the first `Active` match, or
    /// [`AgentKitError::UnresolvedSkillTag`] if none exist.
    pub async fn resolve_skill_tag(&self, tag: &str) -> Result<SkillDefinition, AgentKitError> {
        let filter = SkillFilter {
            query: Some(tag.to_string()),
            tag: Some(tag.to_string()),
            active_only: Some(true),
            limit: Some(20),
            ..Default::default()
        };

        let mut results = self.registry.search_skills(filter).await?;

        // Prefer skills whose `tags` array contains the tag exactly.
        if let Some(idx) = results.iter().position(|s| s.tags.iter().any(|t| t == tag)) {
            return Ok(results.swap_remove(idx));
        }

        results
            .into_iter()
            .find(|s| s.status == SkillStatus::Active)
            .ok_or_else(|| AgentKitError::UnresolvedSkillTag(tag.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovered_resources_lookup_by_tag() {
        let mut bag = DiscoveredResources::default();
        let tool = ToolDefinition::new(
            "yield-source".to_string(),
            "1.0.0".to_string(),
            tenzro_types::ToolTransportMode::Mcp,
            "https://tools.tenzro.xyz/yield".to_string(),
            "yield discovery tool".to_string(),
            "yield-source".to_string(),
        );
        bag.tools.push(("yield-source".to_string(), tool.clone()));

        assert!(bag.tool_by_tag("yield-source").is_some());
        assert!(bag.tool_by_tag("missing").is_none());
        assert_eq!(bag.tool_count(), 1);
        assert_eq!(bag.skill_count(), 0);
    }

    #[test]
    fn discovered_resources_skill_lookup() {
        let mut bag = DiscoveredResources::default();
        let skill = SkillDefinition::new(
            "rebalance".to_string(),
            "1.0.0".to_string(),
            "did:tenzro:machine:test".to_string(),
            "Rebalance a portfolio".to_string(),
            0,
        );
        bag.skills.push(("rebalance".to_string(), skill));
        assert!(bag.skill_by_tag("rebalance").is_some());
        assert!(bag.skill_by_tag("nope").is_none());
    }
}
