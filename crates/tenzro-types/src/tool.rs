//! Tool registry types for Tenzro Network
//!
//! Defines types for the decentralized tools registry where
//! agents and providers can publish MCP server endpoints and other
//! tools for others to discover, install, and invoke autonomously.
//!
//! Tools are MCP servers (or API/native endpoints) that agents use to
//! take actions in the world. Skills teach agents HOW to use tools;
//! tools ARE the actual capabilities being invoked.
//!
//! Three transport modes are supported for MCP servers:
//!
//! - `mcp` — remote MCP over JSON-RPC 2.0 Streamable HTTP (POST). This is
//!   how hosted MCPs are distributed today (Anthropic-hosted MCPs, partner MCPs).
//! - `mcp-stdio` — local MCP subprocess. The operator declares the
//!   command + args + env vars in `spawn_spec`; the node spawns and
//!   supervises the subprocess and speaks JSON-RPC over stdin/stdout.
//!   This is how most third-party MCPs are distributed (Stripe MCP, GitHub MCP,
//!   Notion MCP, Linear MCP, Slack MCP, etc.).
//! - `mcp-sse` — legacy SSE transport. Some older MCPs still use this.
//!
//! For all three modes, the operator's upstream credentials (their
//! Stripe secret, OpenAI key, etc.) are injected into the MCP via
//! `upstream_auth`, sealed at rest, and NEVER exposed to the tenant
//! that presents a Tenzro API key. The tenant only sees the MCP's
//! tool output.

use crate::primitives::Address;
use serde::{Deserialize, Serialize};

/// Transport mode for an MCP / tool resource.
///
/// Old code that stored `tool_type: String` is preserved via
/// `ToolDefinition::tool_type`; new code should prefer
/// `transport_mode` which is strongly typed. The two are kept in sync
/// at write time via `ToolDefinition::set_transport_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolTransportMode {
    /// Remote MCP over JSON-RPC 2.0 Streamable HTTP POST.
    Mcp,
    /// Local MCP subprocess speaking JSON-RPC over stdin/stdout.
    /// Requires `spawn_spec` to be set.
    McpStdio,
    /// Legacy MCP over Server-Sent Events.
    McpSse,
    /// OpenAPI-compatible REST endpoint (POST JSON body).
    Api,
    /// Built-in node capability — handled inline.
    Native,
}

impl ToolTransportMode {
    /// Wire-format string for the legacy `tool_type` field. Used to
    /// keep old clients reading the type as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            ToolTransportMode::Mcp => "mcp",
            ToolTransportMode::McpStdio => "mcp-stdio",
            ToolTransportMode::McpSse => "mcp-sse",
            ToolTransportMode::Api => "api",
            ToolTransportMode::Native => "native",
        }
    }

    /// Inverse of `as_str`. Returns `None` for unknown strings rather
    /// than panicking so the registry can refuse to load unknown
    /// transport modes safely.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "mcp" => Some(ToolTransportMode::Mcp),
            "mcp-stdio" => Some(ToolTransportMode::McpStdio),
            "mcp-sse" => Some(ToolTransportMode::McpSse),
            "api" => Some(ToolTransportMode::Api),
            "native" => Some(ToolTransportMode::Native),
            _ => None,
        }
    }
}

/// How the operator's upstream credentials are injected into an MCP
/// invocation. The actual secret is NOT stored in this struct — it is
/// stored separately by the node in a sealed credential vault, keyed
/// by `sealed_secret_ref`. The operator's secret is fetched only at
/// invocation time and zeroized after the request completes.
///
/// Tenants who present a Tenzro API key never see `sealed_secret_ref`
/// or the underlying secret. They see only the MCP's response payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UpstreamAuth {
    /// `Authorization: Bearer <secret>` header on the outbound request.
    Bearer {
        /// Opaque reference into the operator's sealed credential
        /// vault. The node maps this to the actual secret at
        /// invocation time.
        sealed_secret_ref: String,
    },
    /// Arbitrary header injection: `<header_name>: <secret>`.
    Header {
        header_name: String,
        sealed_secret_ref: String,
    },
    /// For stdio MCPs only: secret is injected as an environment
    /// variable in the spawned subprocess. Common for npm-package
    /// MCPs that expect e.g. `OPENAI_API_KEY`, `STRIPE_API_KEY`, etc.
    EnvVar {
        env_var_name: String,
        sealed_secret_ref: String,
    },
    /// Query-string parameter on the endpoint URL (rare; some legacy
    /// services). Discouraged for new integrations because of URL
    /// logging concerns, but supported for completeness.
    QueryParam {
        param_name: String,
        sealed_secret_ref: String,
    },
}

impl UpstreamAuth {
    /// Returns the sealed-secret reference for vault lookup.
    pub fn sealed_secret_ref(&self) -> &str {
        match self {
            UpstreamAuth::Bearer { sealed_secret_ref }
            | UpstreamAuth::Header {
                sealed_secret_ref, ..
            }
            | UpstreamAuth::EnvVar {
                sealed_secret_ref, ..
            }
            | UpstreamAuth::QueryParam {
                sealed_secret_ref, ..
            } => sealed_secret_ref,
        }
    }
}

/// Spawn specification for stdio MCP subprocesses. Required when
/// `transport_mode == ToolTransportMode::McpStdio`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StdioSpawnSpec {
    /// Executable command. Looked up via `$PATH` on the operator's
    /// node. E.g. `npx`, `python`, `/usr/local/bin/stripe-mcp`.
    pub command: String,

    /// Arguments passed to the command. E.g. `["-y", "@stripe/mcp",
    /// "--tools=all"]` for the Stripe MCP via npx.
    pub args: Vec<String>,

    /// Working directory for the subprocess. `None` = node's cwd.
    pub working_dir: Option<String>,

    /// Environment variables (key → value). The `UpstreamAuth::EnvVar`
    /// variant injects the operator's sealed credential as an
    /// additional env var at spawn time — it is NOT stored here.
    /// Use this map for non-secret config like `LOG_LEVEL`, `REGION`,
    /// `STRIPE_TEST_MODE`, etc.
    pub env: std::collections::BTreeMap<String, String>,

    /// Per-call timeout in seconds. Default 30s if `None`.
    pub timeout_secs: Option<u64>,

    /// Whether to keep the subprocess alive between invocations
    /// (persistent mode) or spawn-per-call (ephemeral mode). Most MCPs
    /// support persistent mode and respond faster that way; some legacy
    /// MCPs require per-call spawn. Default: persistent.
    #[serde(default = "default_persistent")]
    pub persistent: bool,
}

fn default_persistent() -> bool {
    true
}

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

    /// Payout wallet for the creator's share of paid invocations.
    /// **Mandatory** for any non-zero `price_per_call`; registration
    /// fails (`ToolError::MissingCreatorWallet`) if omitted for a paid
    /// tool. Free tools (`price_per_call == 0`) may leave this `None`.
    pub creator_wallet: Option<Address>,

    /// Price per invocation in TNZO atto-tokens (1 TNZO = 10^18 atto).
    /// Set to `0` for a free tool. The split is identical to the agent
    /// template marketplace: `MARKETPLACE_COMMISSION_BPS` (5%) to the
    /// treasury, remainder to `creator_wallet`.
    pub price_per_call: u128,

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

    // ── Plugin-host extensions (operator brokerage of custom + third-
    // party MCPs). All optional; default-None preserves the legacy
    // remote-Streamable-HTTP behavior for existing entries.

    /// Upstream credential injection for this tool. When `Some`, the
    /// operator's sealed secret (looked up by `sealed_secret_ref` at
    /// invocation time) is injected per the variant rules — into a
    /// request header for `Mcp` / `McpSse` / `Api`, into an env var
    /// for `McpStdio`. Tenants NEVER see the underlying secret.
    /// Default `None` means no credentials are injected (public MCPs).
    #[serde(default)]
    pub upstream_auth: Option<UpstreamAuth>,

    /// Subprocess spawn specification for `McpStdio` transport.
    /// Required when `tool_type == "mcp-stdio"`. Ignored for other
    /// transports.
    #[serde(default)]
    pub spawn_spec: Option<StdioSpawnSpec>,

    /// Optional subject-level access list. When `Some(vec)`, only
    /// API-key subjects whose `subject` appears in `vec` are permitted
    /// to invoke this tool. `None` (the default) means the tool is
    /// open to any API key that is allowed by `AgentDelegation`.
    #[serde(default)]
    pub allowed_to_subjects: Option<Vec<String>>,
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
            creator_wallet: None,
            price_per_call: 0,
            status: ToolStatus::Active,
            created_at,
            invocation_count: 0,
            last_seen_at: created_at,
            upstream_auth: None,
            spawn_spec: None,
            allowed_to_subjects: None,
        }
    }

    /// Returns the typed transport mode derived from the legacy
    /// `tool_type` string. Returns `None` for unknown strings so the
    /// caller can refuse to invoke an unknown transport safely.
    pub fn transport_mode(&self) -> Option<ToolTransportMode> {
        ToolTransportMode::parse_str(&self.tool_type)
    }

    /// Sets both the typed transport mode and the legacy `tool_type`
    /// string field in lockstep. Use this from the registration RPC
    /// when the caller passes a strongly-typed transport mode.
    pub fn set_transport_mode(&mut self, mode: ToolTransportMode) {
        self.tool_type = mode.as_str().to_string();
    }

    /// Returns `true` when `subject` is permitted to invoke this tool
    /// per the optional subject-level access list. When the list is
    /// `None`, the tool is open to any API key (subject-gating is
    /// disabled). When `Some(vec)`, only subjects in `vec` are allowed.
    pub fn is_subject_allowed(&self, subject: Option<&str>) -> bool {
        match (&self.allowed_to_subjects, subject) {
            (None, _) => true,
            (Some(list), Some(s)) => list.iter().any(|x| x == s),
            (Some(_), None) => false,
        }
    }

    /// Returns `true` when this tool is paid (non-zero `price_per_call`).
    pub fn is_paid(&self) -> bool {
        self.price_per_call > 0
    }

    /// Validate registration invariants. Any paid tool must declare a
    /// `creator_wallet` to receive the creator share of each invocation.
    /// Free tools (`price_per_call == 0`) may omit `creator_wallet`.
    pub fn validate_for_registration(&self) -> Result<(), &'static str> {
        if self.is_paid() && self.creator_wallet.is_none() {
            return Err("Paid tool (price_per_call > 0) requires a creator_wallet");
        }
        Ok(())
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

    /// Settlement transaction hash, if a payment was made. `None` for
    /// free tools or for the in-process token transfer path (which
    /// settles via the live `TnzoToken` ledger rather than a discrete
    /// chain transaction).
    pub settlement_tx: Option<String>,

    /// Amount paid by the invoker in atto-TNZO. `0` for free tools.
    pub amount_paid: u128,

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
        assert_eq!(tool.price_per_call, 0);
        assert!(!tool.is_paid());
        assert!(tool.creator_wallet.is_none());
        assert_eq!(tool.status, ToolStatus::Active);
        assert_eq!(tool.invocation_count, 0);
    }

    #[test]
    fn paid_tool_without_wallet_fails_validation() {
        let mut tool = ToolDefinition::new(
            "premium-mcp".to_string(),
            "1.0.0".to_string(),
            "mcp".to_string(),
            "https://example.com/mcp".to_string(),
            "Paid MCP server".to_string(),
            "data".to_string(),
        );
        tool.price_per_call = 1_000;
        assert!(tool.validate_for_registration().is_err());
    }

    #[test]
    fn free_tool_without_wallet_passes_validation() {
        let tool = ToolDefinition::new(
            "free-mcp".to_string(),
            "1.0.0".to_string(),
            "mcp".to_string(),
            "https://example.com/mcp".to_string(),
            "Free MCP server".to_string(),
            "data".to_string(),
        );
        assert!(tool.validate_for_registration().is_ok());
    }

    #[test]
    fn paid_tool_with_wallet_passes_validation() {
        let mut tool = ToolDefinition::new(
            "paid-mcp".to_string(),
            "1.0.0".to_string(),
            "mcp".to_string(),
            "https://example.com/mcp".to_string(),
            "Paid MCP server".to_string(),
            "data".to_string(),
        );
        tool.price_per_call = 1_000;
        tool.creator_wallet = Some(Address::default());
        assert!(tool.validate_for_registration().is_ok());
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
            "https://tools.tenzro.xyz/code-executor/mcp".to_string(),
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
