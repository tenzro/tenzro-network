//! Tool registry types for Tenzro Network
//!
//! Defines types for the decentralized tools registry where
//! agents and providers can publish MCP server endpoints and other
//! tools for others to discover, install, and invoke autonomously.
//!
//! Tools are MCP servers (or API/native endpoints) that agents use to
//! take actions in the world. Skills teach agents HOW to use tools;
//! tools ARE the actual capabilities being invoked.

use serde::{Deserialize, Serialize};

/// Status of a tool in the registry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ToolStatus {
    /// Tool is published and available for use
    #[default]
    Active,
    /// Tool has been deactivated by its creator
    Inactive,
    /// Tool has been deprecated (superseded by a newer version)
    Deprecated,
}


/// A tool (MCP server, API endpoint, or native capability) published
/// to the Tenzro Network tools registry.
///
/// Tools are discovered by agents and invoked to take real-world actions:
/// web search, code execution, file access, API calls, etc.
/// Unlike skills (which encode reasoning/logic), tools are the actual
/// external interfaces agents connect to.
///
/// Tool types:
/// - `"mcp"` — MCP server at `endpoint` (JSON-RPC 2.0 Streamable HTTP)
/// - `"api"` — OpenAPI-compatible REST endpoint
/// - `"native"` — built-in node capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Unique tool identifier (UUID v4)
    pub tool_id: String,

    /// Human-readable tool name (e.g., "web-search-mcp", "code-executor")
    pub name: String,

    /// Semantic version string (e.g., "1.0.0")
    pub version: String,

    /// Tool type: "mcp", "api", or "native"
    pub tool_type: String,

    /// MCP/API endpoint URL (required for mcp and api types)
    pub endpoint: String,

    /// Description of what this tool does
    pub description: String,

    /// Capabilities provided by this tool (e.g., ["web-search", "read-url"])
    pub capabilities: Vec<String>,

    /// Category for discovery (e.g., "search", "code", "data", "automation")
    pub category: String,

    /// DID of the agent or human who registered this tool
    pub creator_did: Option<String>,

    /// Current status of the tool
    pub status: ToolStatus,

    /// Unix timestamp (seconds) when the tool was registered
    pub created_at: u64,

    /// Number of times this tool has been invoked
    pub invocation_count: u64,

    /// Unix timestamp (seconds) of the last liveness signal. Liveness
    /// sweeper flips `status` to `Inactive` once the tool stays silent past
    /// the configured TTL. Charitable serde default keeps pre-upgrade rows
    /// alive until they actually go silent.
    #[serde(default = "default_last_seen")]
    pub last_seen_at: u64,
}

fn default_last_seen() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl ToolDefinition {
    /// Creates a new tool definition with default values
    pub fn new(
        name: String,
        version: String,
        tool_type: String,
        endpoint: String,
        description: String,
        category: String,
    ) -> Self {
        let tool_id = uuid::Uuid::new_v4().to_string();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            tool_id,
            name,
            version,
            tool_type,
            endpoint,
            description,
            capabilities: Vec::new(),
            category,
            creator_did: None,
            status: ToolStatus::Active,
            created_at,
            invocation_count: 0,
            last_seen_at: created_at,
        }
    }

    /// Returns true if the tool is available for invocation
    pub fn is_available(&self) -> bool {
        self.status == ToolStatus::Active
    }

    /// Bumps `last_seen_at` to current wall-clock time.
    pub fn touch(&mut self) {
        self.last_seen_at = default_last_seen();
    }
}

/// Filter parameters for listing and searching tools
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolFilter {
    /// Filter by tool type ("mcp", "api", "native")
    pub tool_type: Option<String>,

    /// Filter by category
    pub category: Option<String>,

    /// Filter by status ("active", "inactive")
    pub status: Option<String>,

    /// Filter by creator DID
    pub creator_did: Option<String>,

    /// Free-text search in name, description, and capabilities
    pub query: Option<String>,

    /// Maximum number of results to return
    pub limit: Option<usize>,

    /// Pagination offset
    pub offset: Option<usize>,
}

/// Result of invoking a tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocationResult {
    /// The tool that was invoked
    pub tool_id: String,

    /// Invocation identifier for tracking
    pub invocation_id: String,

    /// The output payload returned by the tool
    pub output: serde_json::Value,

    /// Unix timestamp when the invocation completed
    pub completed_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_definition_new() {
        let tool = ToolDefinition::new(
            "web-search".to_string(),
            "1.0.0".to_string(),
            "mcp".to_string(),
            "http://localhost:3001/mcp".to_string(),
            "MCP server providing web search capability".to_string(),
            "search".to_string(),
        );

        assert!(!tool.tool_id.is_empty());
        assert_eq!(tool.name, "web-search");
        assert_eq!(tool.version, "1.0.0");
        assert_eq!(tool.tool_type, "mcp");
        assert!(tool.is_available());
        assert_eq!(tool.status, ToolStatus::Active);
        assert_eq!(tool.invocation_count, 0);
    }

    #[test]
    fn test_tool_status_default() {
        assert_eq!(ToolStatus::default(), ToolStatus::Active);
    }

    #[test]
    fn test_tool_filter_default() {
        let filter = ToolFilter::default();
        assert!(filter.tool_type.is_none());
        assert!(filter.category.is_none());
        assert!(filter.status.is_none());
        assert!(filter.query.is_none());
    }

    #[test]
    fn test_tool_serialization() {
        let mut tool = ToolDefinition::new(
            "code-executor".to_string(),
            "2.0.0".to_string(),
            "mcp".to_string(),
            "https://tools.tenzro.network/code-executor/mcp".to_string(),
            "Executes code in sandboxed environments".to_string(),
            "code".to_string(),
        );
        tool.capabilities = vec!["python".to_string(), "javascript".to_string()];
        tool.creator_did = Some("did:tenzro:human:test-123".to_string());

        let json = serde_json::to_string(&tool).unwrap();
        let deserialized: ToolDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(tool.tool_id, deserialized.tool_id);
        assert_eq!(tool.name, deserialized.name);
        assert_eq!(tool.capabilities.len(), 2);
    }
}
