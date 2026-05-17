//! Agent marketplace types for Tenzro Network
//!
//! Defines types for the decentralized agent marketplace where
//! providers can publish agent templates for others to discover,
//! download, and deploy.
//!
//! ## Execution Spec
//!
//! In addition to the static metadata above, an `AgentTemplate` may carry an
//! `execution_spec: Option<ExecutionSpec>` describing how an autonomous
//! runtime (e.g. `tenzro-agent-kit`) should execute the agent without any
//! hardcoded Rust code: which backend (EVM/SVM/DAML/MultiVm/Bridge/Mpp/X402),
//! which delegation scope to provision, which tools and skills to
//! auto-discover from the registry by tag, and a declarative list of
//! `ExecutionStep`s that map 1:1 to existing subsystems.

use crate::primitives::{Address, Timestamp, u128_serde};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Status of an agent template in the marketplace
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTemplateStatus {
    /// Template is published and available for download
    Published,
    /// Template is under review
    Pending,
    /// Template has been deprecated by its creator
    Deprecated,
    /// Template has been suspended (policy violation)
    Suspended,
}

/// The type of agent template
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTemplateType {
    /// Standalone autonomous agent
    Autonomous,
    /// Tool/function calling agent that wraps external APIs
    ToolAgent,
    /// Workflow orchestrator that coordinates other agents
    Orchestrator,
    /// Specialist agent optimized for a specific domain
    Specialist,
    /// Multi-modal agent handling text, image, audio, etc.
    MultiModal,
    /// Custom agent type
    Custom(String),
}

/// A specific capability that an agent template provides
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCapability {
    /// Capability identifier (e.g., "code_generation", "web_search")
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Description of what the capability does
    pub description: String,

    /// Input schema (JSON Schema string)
    pub input_schema: Option<String>,

    /// Output schema (JSON Schema string)
    pub output_schema: Option<String>,
}

/// Runtime requirements for deploying the agent template
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgentRuntimeRequirements {
    /// Minimum model size required (e.g., "1b", "7b", "70b")
    #[serde(default)]
    pub min_model_size: Option<String>,

    /// Preferred model ID for best results
    #[serde(default)]
    pub preferred_model_id: Option<String>,

    /// Required MCP tool names
    #[serde(default)]
    pub required_mcp_tools: Vec<String>,

    /// Required external API access (e.g., "web_search", "code_execution")
    #[serde(default)]
    pub required_permissions: Vec<String>,

    /// Estimated TNZO cost per execution (in micro-units)
    #[serde(default)]
    pub estimated_cost_per_run: Option<u128>,

    /// Whether TEE execution is required
    #[serde(default)]
    pub requires_tee: bool,

    /// Minimum memory in MB (from execution manifests)
    #[serde(default)]
    pub min_memory_mb: Option<u64>,

    /// Minimum storage in MB (from execution manifests)
    #[serde(default)]
    pub min_storage_mb: Option<u64>,

    /// Whether GPU is required
    #[serde(default)]
    pub gpu_required: bool,

    /// Whether network access is required
    #[serde(default)]
    pub network_access: bool,

    /// Supported platforms (e.g., "linux-x86_64", "macos-aarch64")
    #[serde(default)]
    pub supported_platforms: Vec<String>,
}



/// Pricing model for using an agent template
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum AgentPricingModel {
    /// Free to use
    #[default]
    Free,
    /// Fixed price per execution
    PerExecution { price: u128 },
    /// Price per token processed
    PerToken { price_per_token: u128 },
    /// Subscription-based (monthly rate in TNZO)
    Subscription { monthly_rate: u128 },
    /// Revenue sharing with the template creator
    RevenueShare { creator_share_bps: u16 },
}

impl AgentPricingModel {
    /// Returns true when this template is free to invoke.
    pub fn is_free(&self) -> bool {
        matches!(self, AgentPricingModel::Free)
    }

    /// Gross fee (in TNZO base units) charged for a single invocation.
    /// For `PerToken`, `tokens` is multiplied by the unit price.
    /// `Subscription` and `RevenueShare` return 0 here — they are
    /// settled out-of-band (subscription channel, downstream revenue split).
    pub fn fee_for_invocation(&self, tokens: u64) -> u128 {
        match self {
            AgentPricingModel::Free => 0,
            AgentPricingModel::PerExecution { price } => *price,
            AgentPricingModel::PerToken { price_per_token } => {
                price_per_token.saturating_mul(tokens as u128)
            }
            AgentPricingModel::Subscription { .. } => 0,
            AgentPricingModel::RevenueShare { .. } => 0,
        }
    }
}

/// An agent template published to the Tenzro Network marketplace
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTemplate {
    /// Unique template identifier (UUID v4)
    pub template_id: String,

    /// Template name
    pub name: String,

    /// Detailed description
    pub description: String,

    /// Template type
    pub template_type: AgentTemplateType,

    /// Address of the template creator/publisher
    pub creator: Address,

    /// Optional DID binding — when present, the template is attributable to a
    /// Tenzro identity (`did:tenzro:human:...` or `did:tenzro:machine:...`).
    /// The DID is bound at registration time and cannot be changed; creators
    /// who prefer wallet-only attribution may omit this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_did: Option<String>,

    /// Wallet that receives creator payouts for paid invocations.
    /// MUST be `Some(_)` whenever `pricing != Free`. For free templates
    /// this may be `None` and the creator simply publishes under `creator`.
    #[serde(default)]
    pub creator_wallet: Option<Address>,

    /// Cumulative count of successful paid invocations against this template.
    #[serde(default)]
    pub invocation_count: u64,

    /// Cumulative gross TNZO revenue (in base units) routed to the creator
    /// across all invocations — this is the amount that landed in
    /// `creator_wallet`, i.e. the net-of-commission creator share.
    #[serde(default)]
    pub total_revenue: u128,

    /// Version string (semver, e.g., "1.0.0")
    pub version: String,

    /// Current status
    pub status: AgentTemplateStatus,

    /// When the template was first published
    pub created_at: Timestamp,

    /// When the template was last updated
    pub updated_at: Timestamp,

    /// List of capabilities this agent provides
    pub capabilities: Vec<AgentCapability>,

    /// Runtime requirements for deployment
    pub runtime_requirements: AgentRuntimeRequirements,

    /// Pricing model
    pub pricing: AgentPricingModel,

    /// System prompt / agent instructions
    pub system_prompt: String,

    /// Example user messages and expected behavior (for documentation)
    pub examples: Vec<AgentExample>,

    /// Tags for discoverability (e.g., ["coding", "rust", "debugging"])
    pub tags: Vec<String>,

    /// Number of times this template has been downloaded/deployed
    pub download_count: u64,

    /// Average rating (0-100, weighted by stake)
    pub rating: u8,

    /// IPFS or content hash of the full template payload
    pub content_hash: Option<String>,

    /// Link to documentation or repository
    pub docs_url: Option<String>,

    /// Additional metadata
    pub metadata: HashMap<String, String>,

    /// Optional declarative execution spec consumed by autonomous runtimes
    /// (e.g. `tenzro-agent-kit`). When present, a runtime can instantiate
    /// the agent end-to-end (identity, wallet, delegation, tools, skills,
    /// execution steps) from the spec alone — no Rust code required.
    ///
    /// Templates without this field still deserialize cleanly via
    /// `#[serde(default)]`.
    #[serde(default)]
    pub execution_spec: Option<ExecutionSpec>,

    /// Unix timestamp (seconds) of the last liveness signal — registration,
    /// update, invocation, or explicit `tenzro_heartbeatTemplate` call.
    /// The liveness sweeper flips `status` to `Deprecated` once the template
    /// stays silent past the configured TTL (templates are kept on-record
    /// rather than purged — they have audit value as a marketplace history).
    /// Pre-upgrade rows hydrate with the current time (charitable default)
    /// so they only appear stale once they actually go silent.
    #[serde(default = "default_last_seen_ts")]
    pub last_seen_at: Timestamp,
}

fn default_last_seen_ts() -> Timestamp {
    Timestamp(chrono::Utc::now().timestamp())
}

/// An example interaction demonstrating agent capabilities
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentExample {
    /// Description of the example scenario
    pub description: String,

    /// Example user input
    pub user_input: String,

    /// Expected agent output (may be abbreviated)
    pub expected_output: String,
}

impl AgentTemplate {
    /// Creates a new agent template
    pub fn new(
        name: String,
        description: String,
        template_type: AgentTemplateType,
        creator: Address,
        system_prompt: String,
    ) -> Self {
        let template_id = uuid::Uuid::new_v4().to_string();
        let now = Timestamp(chrono::Utc::now().timestamp());
        Self {
            template_id,
            name,
            description,
            template_type,
            creator,
            creator_did: None,
            creator_wallet: None,
            invocation_count: 0,
            total_revenue: 0,
            version: "1.0.0".to_string(),
            status: AgentTemplateStatus::Published,
            created_at: now,
            updated_at: now,
            capabilities: Vec::new(),
            runtime_requirements: AgentRuntimeRequirements::default(),
            pricing: AgentPricingModel::Free,
            system_prompt,
            examples: Vec::new(),
            tags: Vec::new(),
            download_count: 0,
            rating: 0,
            content_hash: None,
            docs_url: None,
            metadata: HashMap::new(),
            execution_spec: None,
            last_seen_at: now,
        }
    }

    /// Bumps `last_seen_at` to the current wall-clock time. Called by the
    /// heartbeat RPC and any successful invocation that should keep the
    /// template from being marked Deprecated by the liveness sweeper.
    pub fn touch(&mut self) {
        self.last_seen_at = default_last_seen_ts();
    }

    /// Attach an optional DID binding for creator attribution.
    pub fn with_creator_did(mut self, did: impl Into<String>) -> Self {
        self.creator_did = Some(did.into());
        self
    }

    /// Attach a payout wallet — REQUIRED for any non-Free pricing.
    pub fn with_creator_wallet(mut self, wallet: Address) -> Self {
        self.creator_wallet = Some(wallet);
        self
    }

    /// Attach a pricing model.
    pub fn with_pricing(mut self, pricing: AgentPricingModel) -> Self {
        self.pricing = pricing;
        self
    }

    /// Returns true if the template is publicly available
    pub fn is_available(&self) -> bool {
        self.status == AgentTemplateStatus::Published
    }

    /// Validates publisher-side invariants required before persisting the
    /// template in the marketplace: if `pricing != Free` then
    /// `creator_wallet` must be set (so payouts have a destination).
    ///
    /// Returns `Err(<reason>)` when the invariant is violated. Called from
    /// every `registerAgentTemplate` code path (RPC + MCP).
    pub fn validate_marketplace_invariants(&self) -> Result<(), String> {
        if !self.pricing.is_free() && self.creator_wallet.is_none() {
            return Err(format!(
                "creator_wallet is mandatory for non-Free pricing (pricing={:?})",
                self.pricing
            ));
        }
        Ok(())
    }

    /// Records a successful paid invocation against this template.
    /// `creator_share` is the net-of-commission amount that was transferred
    /// to `creator_wallet`.
    pub fn record_invocation(&mut self, creator_share: u128) {
        self.invocation_count = self.invocation_count.saturating_add(1);
        self.total_revenue = self.total_revenue.saturating_add(creator_share);
        self.updated_at = Timestamp(chrono::Utc::now().timestamp());
    }
}

/// Filter parameters for listing agent templates
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentTemplateFilter {
    /// Filter by template type
    pub template_type: Option<AgentTemplateType>,

    /// Filter by creator address
    pub creator: Option<String>,

    /// Filter by tag (must have this tag)
    pub tag: Option<String>,

    /// Filter by required model capability
    pub required_model: Option<String>,

    /// Only show free templates
    pub free_only: Option<bool>,

    /// Filter by status
    pub status: Option<AgentTemplateStatus>,

    /// Maximum number of results
    pub limit: Option<usize>,

    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Summary of a downloaded/deployed agent template instance
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTemplateInstance {
    /// Instance identifier
    pub instance_id: String,

    /// The template this instance is based on
    pub template_id: String,

    /// Owner of this instance
    pub owner: Address,

    /// Optional custom name given by the deployer
    pub custom_name: Option<String>,

    /// Any configuration overrides applied at deploy time
    pub config_overrides: HashMap<String, String>,

    /// When this instance was deployed
    pub deployed_at: Timestamp,
}

// =====================================================================
// ExecutionSpec — declarative runtime spec for autonomous agent kits
// =====================================================================
//
// Every type below maps 1:1 to an existing Tenzro subsystem
// (`MultiVmRuntime`, `BridgeRouter`, `MppClient`, `X402Client`,
// `DamlExecutor`, `IdentityRegistry`, registry RPCs). The agent-kit
// crate adds NO new execution logic — it only interprets these structs
// and dispatches to the existing subsystems.

/// Top-level declarative execution spec for an autonomous agent template.
///
/// A runtime that consumes this spec must:
///
///   1. Provision identity + wallet + delegation per `delegation`
///   2. Auto-discover tools whose tags match `required_tool_tags`
///      from `CF_TOOLS` via `tenzro_searchTools`
///   3. Auto-discover skills whose tags match `required_skill_tags`
///      from `CF_SKILLS` via `tenzro_searchSkills`
///   4. Walk `steps` in order, gating each step by
///      `IdentityRegistry::enforce_operation()` against `hard_caps`
///   5. Dispatch each step to the matching subsystem (`backend`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSpec {
    /// Which Tenzro execution backend the agent dispatches against
    pub backend: ExecutionBackend,

    /// Delegation scope to provision when spawning the agent
    pub delegation: DelegationSpec,

    /// Tag queries used to auto-discover required tools from `CF_TOOLS`.
    /// At spawn time, the agent-kit calls `tenzro_searchTools` for each
    /// tag and binds the first matching `Active` tool.
    #[serde(default)]
    pub required_tool_tags: Vec<String>,

    /// Tag queries used to auto-discover required skills from `CF_SKILLS`.
    /// At spawn time, the agent-kit calls `tenzro_searchSkills` for each
    /// tag and binds the first matching active skill.
    #[serde(default)]
    pub required_skill_tags: Vec<String>,

    /// Declarative list of execution steps. Walked in order at run time.
    pub steps: Vec<ExecutionStep>,

    /// Hard caps enforced by the runtime in addition to the delegation
    /// scope. These guarantee that even a misbehaving step body cannot
    /// exceed the per-operation or per-day value limit.
    pub hard_caps: HardCaps,
}

/// The execution backend an agent dispatches against. Each variant maps
/// to an existing Tenzro subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionBackend {
    /// Dispatch raw EVM transactions through `MultiVmRuntime`
    Evm { chain_id: u64 },

    /// Dispatch SVM transactions through `MultiVmRuntime`
    Svm { cluster: String },

    /// Submit DAML commands to a Canton participant via `DamlExecutor`
    Daml {
        participant_host: String,
        participant_port: u16,
    },

    /// Cross-VM workflow that may touch EVM, SVM, and DAML in one run
    MultiVm,

    /// Pure machine-payment flow over MPP (no on-chain VM dispatch)
    MppPayment { endpoint: String },

    /// Pure machine-payment flow over x402 (no on-chain VM dispatch)
    X402Payment { endpoint: String },

    /// Cross-chain bridge workflow via `BridgeRouter`
    Bridge {
        /// Adapter ids registered with the router, e.g.
        /// `["layer_zero", "chainlink_ccip", "debridge"]`
        adapters: Vec<String>,
    },
}

/// Delegation scope to provision for a spawned agent. Translated into
/// `tenzro_identity::DelegationScope` by the spawner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationSpec {
    /// Maximum value of a single transaction (raw u128, base units).
    /// Accepts JSON numbers (≤ u64::MAX) or strings (any u128). Serialized
    /// as a number when it fits u64 and as a decimal string otherwise.
    #[serde(with = "u128_serde")]
    pub max_transaction_value: u128,

    /// Maximum cumulative spend per day (raw u128, base units).
    /// Accepts JSON numbers (≤ u64::MAX) or strings (any u128). Serialized
    /// as a number when it fits u64 and as a decimal string otherwise.
    #[serde(with = "u128_serde")]
    pub max_daily_spend: u128,

    /// Operation labels the agent is allowed to perform
    /// (e.g. `["bridge", "deposit", "rebalance"]`)
    pub allowed_operations: Vec<String>,

    /// Chain identifiers the agent is allowed to reach
    /// (e.g. `["ethereum", "arbitrum", "base"]`)
    #[serde(default)]
    pub allowed_chains: Vec<String>,

    /// Time bound for the delegation, in days from spawn time
    pub time_bound_days: u32,

    /// Required KYC tier on the controller identity:
    /// `"Unverified" | "Basic" | "Enhanced" | "Full"`
    pub kyc_tier: String,
}

/// Hard caps enforced by the runtime as a second line of defense
/// independent of the delegation scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardCaps {
    /// Per-operation value cap (raw u128, base units).
    /// Accepts JSON numbers (≤ u64::MAX) or strings (any u128).
    #[serde(with = "u128_serde")]
    pub per_operation_value: u128,

    /// Per-day cumulative value cap (raw u128, base units).
    /// Accepts JSON numbers (≤ u64::MAX) or strings (any u128).
    #[serde(with = "u128_serde")]
    pub per_day_value: u128,
}

/// A single declarative step in an `ExecutionSpec`. Each variant maps
/// directly to an existing subsystem invocation.
///
/// Template variables: any `String` field that contains `{{name}}`
/// substrings is interpolated at run time against the agent's context
/// (spawn args + accumulated step output).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStep {
    /// Hand-craft an EVM transaction and dispatch it through
    /// `MultiVmRuntime::execute_transaction(VmType::Evm, ...)`.
    EvmDispatch {
        /// 20-byte hex `to` address (with or without `0x` prefix)
        to: String,
        /// Hex-encoded u128 value
        value: String,
        /// Hex-encoded calldata template with optional `{{var}}` substitutions
        calldata_template: String,
        gas_limit: u64,
    },

    /// Move tokens across chains via `BridgeRouter::compare_fees` →
    /// pick the chosen route → call the winning adapter.
    BridgeTransfer {
        from_chain: String,
        to_chain: String,
        asset: String,
        /// Decimal amount string (resolved against asset decimals at run time)
        amount: String,
        /// Selection strategy: `"cheapest" | "fastest" | "most_reliable"`
        strategy: String,
    },

    /// Create an MPP payment challenge, sign it with the agent wallet,
    /// and submit the credential via `MppClient`.
    MppPay {
        amount: String,
        asset: String,
        recipient: String,
        /// Optional session TTL in seconds
        #[serde(default)]
        session_ttl_secs: Option<u64>,
    },

    /// Stateless x402 pay-resource call via `X402Client`.
    X402Pay {
        /// Resource URL to pay for (alternative to `recipient`)
        #[serde(default)]
        resource_url: Option<String>,
        amount: String,
        asset: String,
        /// Recipient address (alternative to resource_url)
        #[serde(default)]
        recipient: Option<String>,
        /// Facilitator address
        #[serde(default)]
        facilitator: Option<String>,
    },

    /// Submit a DAML command to a Canton participant via `DamlExecutor`.
    DamlSubmit {
        /// Template package (e.g. "com.tenzro.trade")
        #[serde(default)]
        template_package: Option<String>,
        /// DAML module name
        #[serde(default)]
        module: Option<String>,
        /// DAML entity/template name
        #[serde(default)]
        entity: Option<String>,
        /// Command variant: "Create" | "Exercise" etc.
        #[serde(default)]
        command_variant: Option<String>,
        /// JSON object with optional `{{var}}` substitutions
        #[serde(default)]
        fields_json: Option<String>,
        /// Template ID (alternative to template_package+module+entity)
        #[serde(default)]
        template_id: Option<String>,
        /// Choice name (alternative to command_variant for Exercise)
        #[serde(default)]
        choice: Option<String>,
        /// Acting party
        #[serde(default)]
        party: Option<String>,
        /// Args template with `{{var}}` substitutions (alternative to fields_json)
        #[serde(default)]
        args_template: Option<String>,
    },

    /// Look up a tool from `CF_TOOLS` (auto-discovered at spawn time
    /// via `required_tool_tags`) and invoke it via `tenzro_useTool`.
    ToolInvoke {
        /// Tag used to look up the resolved tool id
        tool_tag: String,
        /// Method name on the tool (e.g. "get_balances", "quote_inference_pricing")
        #[serde(default)]
        method: Option<String>,
        /// JSON object with optional `{{var}}` substitutions (alternative
        /// to `params_template`)
        #[serde(default)]
        arguments_json: Option<String>,
        /// JSON template with optional `{{var}}` substitutions (preferred)
        #[serde(default)]
        params_template: Option<String>,
    },

    /// Look up a skill from `CF_SKILLS` (auto-discovered at spawn time
    /// via `required_skill_tags`) and invoke it via `tenzro_useSkill`.
    SkillInvoke {
        /// Tag used to look up the resolved skill id
        skill_tag: String,
        /// Method name on the skill
        #[serde(default)]
        method: Option<String>,
        /// JSON object with optional `{{var}}` substitutions
        #[serde(default)]
        input_json: Option<String>,
        /// JSON template with optional `{{var}}` substitutions (alternative)
        #[serde(default)]
        params_template: Option<String>,
    },

    /// Loop over a discovered opportunity set returned by a registered
    /// tool. The body steps execute once per item, with the item bound
    /// to the runtime context as `opportunity` (or whatever the agent-kit
    /// chooses for binding).
    ForEach {
        /// Tool tag whose `tenzro_useTool` output is a JSON array
        source_tool_tag: String,
        body: Vec<ExecutionStep>,
    },

    /// Conditional gate: only run the body if the JMESPath expression
    /// evaluated against the current context is truthy.
    When {
        /// JMESPath expression
        jmespath_expr: String,
        body: Vec<ExecutionStep>,
    },
}

#[cfg(test)]
mod execution_spec_tests {
    use super::*;

    #[test]
    fn execution_spec_round_trips_through_json() {
        let spec = ExecutionSpec {
            backend: ExecutionBackend::Bridge {
                adapters: vec!["layer_zero".to_string(), "debridge".to_string()],
            },
            delegation: DelegationSpec {
                max_transaction_value: 500_000_000_000_000_000_000u128,
                max_daily_spend: 2_000_000_000_000_000_000_000u128,
                allowed_operations: vec!["bridge".to_string(), "deposit".to_string()],
                allowed_chains: vec!["ethereum".to_string(), "arbitrum".to_string()],
                time_bound_days: 7,
                kyc_tier: "Full".to_string(),
            },
            required_tool_tags: vec!["yield-source".to_string()],
            required_skill_tags: vec![],
            hard_caps: HardCaps {
                per_operation_value: 500_000_000_000_000_000_000u128,
                per_day_value: 2_000_000_000_000_000_000_000u128,
            },
            steps: vec![ExecutionStep::ForEach {
                source_tool_tag: "yield-source".to_string(),
                body: vec![ExecutionStep::When {
                    jmespath_expr: "apy > `5.0`".to_string(),
                    body: vec![ExecutionStep::BridgeTransfer {
                        from_chain: "ethereum".to_string(),
                        to_chain: "{{opportunity.chain}}".to_string(),
                        asset: "USDC".to_string(),
                        amount: "{{opportunity.amount}}".to_string(),
                        strategy: "cheapest".to_string(),
                    }],
                }],
            }],
        };

        let json = serde_json::to_string(&spec).expect("serialize");
        let back: ExecutionSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, spec);
    }

    #[test]
    fn agent_template_without_execution_spec_still_deserializes() {
        // A template without execution_spec must round-trip cleanly through
        // serde. We build it from a real `AgentTemplate::new()` (so the
        // Address shape is correct), then serialize, strip the
        // execution_spec field from the JSON, then deserialize the stripped
        // JSON and confirm the field defaults to None.
        let original = AgentTemplate::new(
            "Spec-less".to_string(),
            "no execution_spec field".to_string(),
            AgentTemplateType::Autonomous,
            crate::primitives::Address::default(),
            "".to_string(),
        );
        let mut value: serde_json::Value = serde_json::to_value(&original).unwrap();
        // Strip the new field as if this JSON came from a pre-execution-spec node.
        let removed = value
            .as_object_mut()
            .unwrap()
            .remove("execution_spec");
        assert!(removed.is_some(), "execution_spec should have been present");
        let stripped = serde_json::to_string(&value).unwrap();
        // Confirm the key is no longer in the JSON object (the field is fully absent,
        // not just `null`).
        assert!(
            !stripped.contains("\"execution_spec\""),
            "execution_spec key should be absent from stripped JSON"
        );

        let tmpl: AgentTemplate =
            serde_json::from_str(&stripped).expect("spec-less template should deserialize");
        assert!(tmpl.execution_spec.is_none());
        assert_eq!(tmpl.name, "Spec-less");
    }

    #[test]
    fn new_template_initializes_execution_spec_to_none() {
        let tmpl = AgentTemplate::new(
            "Test".to_string(),
            "desc".to_string(),
            AgentTemplateType::Autonomous,
            crate::primitives::Address::default(),
            "system prompt".to_string(),
        );
        assert!(tmpl.execution_spec.is_none());
    }

    #[test]
    fn validate_rejects_paid_template_without_wallet() {
        let mut tmpl = AgentTemplate::new(
            "Paid".to_string(),
            "desc".to_string(),
            AgentTemplateType::Autonomous,
            crate::primitives::Address::default(),
            "prompt".to_string(),
        );
        tmpl.pricing = AgentPricingModel::PerExecution { price: 1_000 };
        // creator_wallet is None by default
        assert!(tmpl.validate_marketplace_invariants().is_err());
    }

    #[test]
    fn validate_accepts_paid_template_with_wallet() {
        let mut tmpl = AgentTemplate::new(
            "Paid".to_string(),
            "desc".to_string(),
            AgentTemplateType::Autonomous,
            crate::primitives::Address::default(),
            "prompt".to_string(),
        );
        tmpl.pricing = AgentPricingModel::PerExecution { price: 1_000 };
        tmpl.creator_wallet = Some(crate::primitives::Address::default());
        assert!(tmpl.validate_marketplace_invariants().is_ok());
    }

    #[test]
    fn validate_accepts_free_template_without_wallet() {
        let tmpl = AgentTemplate::new(
            "Free".to_string(),
            "desc".to_string(),
            AgentTemplateType::Autonomous,
            crate::primitives::Address::default(),
            "prompt".to_string(),
        );
        // Free + no wallet is valid
        assert!(tmpl.validate_marketplace_invariants().is_ok());
    }

    #[test]
    fn record_invocation_increments_counters() {
        let mut tmpl = AgentTemplate::new(
            "Paid".to_string(),
            "desc".to_string(),
            AgentTemplateType::Autonomous,
            crate::primitives::Address::default(),
            "prompt".to_string(),
        );
        assert_eq!(tmpl.invocation_count, 0);
        assert_eq!(tmpl.total_revenue, 0);
        tmpl.record_invocation(950_000_000_000_000_000u128);
        assert_eq!(tmpl.invocation_count, 1);
        assert_eq!(tmpl.total_revenue, 950_000_000_000_000_000u128);
        tmpl.record_invocation(950_000_000_000_000_000u128);
        assert_eq!(tmpl.invocation_count, 2);
        assert_eq!(tmpl.total_revenue, 1_900_000_000_000_000_000u128);
    }

    #[test]
    fn fee_for_invocation_computes_correctly() {
        let free = AgentPricingModel::Free;
        assert_eq!(free.fee_for_invocation(1000), 0);

        let per_exec = AgentPricingModel::PerExecution { price: 500_000_000_000_000_000u128 };
        assert_eq!(per_exec.fee_for_invocation(1000), 500_000_000_000_000_000u128);

        let per_token = AgentPricingModel::PerToken { price_per_token: 1_000_000_000u128 };
        assert_eq!(per_token.fee_for_invocation(500), 500_000_000_000u128);

        let subscription = AgentPricingModel::Subscription { monthly_rate: 1_000_000u128 };
        assert_eq!(subscription.fee_for_invocation(1000), 0); // settled out-of-band
    }
}
