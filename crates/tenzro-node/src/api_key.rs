//! Per-client API key management for proxied service access.
//!
//! Tenzro mediates access to credentials that clients should not hold
//! directly — most notably the Canton devnet JWT, which authorizes the
//! shared Splice validator party `tenzro-validator-1`. External callers
//! authenticate to the Tenzro node via an API key (presented in the
//! `X-Tenzro-Api-Key` HTTP header on REST routes, or as the `api_key`
//! parameter on the corresponding JSON-RPC methods); the node then
//! makes the upstream Canton request on the caller's behalf using its
//! own bearer token.
//!
//! The raw key material is **never** persisted — only the SHA-256 hash
//! is stored in `CF_API_KEYS`. The plaintext is returned exactly once,
//! at issuance time.
//!
//! # Key format
//!
//! Issued keys are 32-byte random tokens, base64url-encoded without
//! padding, with a `tnz_` prefix for visual identification. Example:
//! `tnz_3v8q7s2X...`.
//!
//! # Scopes
//!
//! Each key is bound to a set of `ApiKeyScope` values that gate which
//! RPC namespaces it can access. A key with no scopes is invalid.

use std::sync::Arc;

use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_storage::{KvStore, CF_API_KEYS};

use crate::error::{NodeError, Result};

/// Scopes an API key can be granted.
///
/// Each scope corresponds to a logical surface the node mediates on
/// behalf of the caller. New scopes added here MUST also be threaded
/// into [`gate_rpc_method`] so the middleware actually enforces them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyScope {
    /// Canton JSON Ledger API mediated by this node's bearer token.
    /// Gates `tenzro_*Canton*` RPC methods and the Canton MCP tools.
    Canton,
    /// EVM contract execution + queries that the operator has chosen
    /// to gate (e.g. private model-router contracts, paid model
    /// inference, premium TEE attestation). Gates `eth_call`,
    /// `eth_estimateGas`, `eth_sendRawTransaction` when the operator
    /// has enabled the EVM gate. Disabled by default — operators
    /// running a public RPC can leave EVM ungated; operators running
    /// a private/B2B RPC turn it on.
    Evm,
    /// SVM program execution that the operator has chosen to gate.
    /// Mirror of `Evm` for solana_rbpf-routed dispatches.
    Svm,
    /// Model inference + serving endpoints
    /// (`tenzro_chat`, `tenzro_inferenceRequest`, the multi-modal
    /// runtimes). Used by operators that monetise inference.
    Inference,
    /// TEE attestation + ZK verification endpoints. Operators that
    /// monetise the verification surface (or that want to rate-limit
    /// it) gate it with this scope.
    Tee,
    /// Cross-chain bridge dispatch (LayerZero, CCIP, Wormhole,
    /// deBridge, Hyperlane, Axelar). Operators of public RPCs may
    /// gate this to prevent unbounded gas use through their relays.
    Bridge,
    /// Chainlink Data Feeds — `eth_call` against AggregatorV3Interface
    /// on the operator's configured Ethereum mainnet RPC. The upstream
    /// RPC quota is operator-paid (Alchemy/Infura/dRPC paid tier);
    /// callers must hold a `chainlink`-scoped key so the operator can
    /// attribute the cost and apply per-tenant rate limits. Gates
    /// `tenzro_quoteBridgeFeeInTnzo`, `tenzro_sponsorBridgeFee`,
    /// `tenzro_listBridgeSponsorshipPools` when the
    /// `ChainlinkFeedFeeOracle` backing is active. Same operator-gated
    /// model as `Canton` per the established hard rule.
    Chainlink,
}

impl ApiKeyScope {
    /// Returns the canonical string form used in JSON-RPC params and
    /// `CF_API_KEYS` records.
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiKeyScope::Canton => "canton",
            ApiKeyScope::Evm => "evm",
            ApiKeyScope::Svm => "svm",
            ApiKeyScope::Inference => "inference",
            ApiKeyScope::Tee => "tee",
            ApiKeyScope::Bridge => "bridge",
            ApiKeyScope::Chainlink => "chainlink",
        }
    }
}

/// Trust class of an issued key.
///
/// Determines the revocation policy. All classes are **node-scoped**:
/// they only authorize the issuing node's API surface, never network-wide
/// state. Network-wide changes (validator set, treasury, fee schedule,
/// system contracts, protocol params) require the on-chain governance
/// path (`tenzro-token::GovernanceEngine` + the `0x1005` GOVERNANCE
/// precompile) regardless of which class of key is presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyClass {
    /// The operator's own self-imposed lockdown key. Not revokable via
    /// any RPC — including by an admin holding `X-Tenzro-Admin-Token`.
    /// Rotation requires updating the operator's secret store + node
    /// restart. Use this for keys the node itself or critical
    /// infrastructure depends on, where accidental RPC-side revoke would
    /// take the node offline.
    OperatorProtected,
    /// Operator-issued for a developer / external caller. Both the
    /// subject (presenting their own `X-Tenzro-Api-Key` to
    /// `tenzro_revokeMyApiKey`) and the operator (presenting
    /// `X-Tenzro-Admin-Token` to `tenzro_revokeApiKey`) can revoke.
    Subject,
    /// Operator-internal ops key (CI pipelines, monitoring agents, etc.).
    /// No subject revoke applies; only the operator (via admin token) can
    /// revoke.
    OperatorInternal,
}

impl KeyClass {
    /// Canonical wire-format string used in JSON-RPC params and records.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyClass::OperatorProtected => "operator_protected",
            KeyClass::Subject => "subject",
            KeyClass::OperatorInternal => "operator_internal",
        }
    }

    /// Parses the wire-format string. Returns `None` for unknown values
    /// so callers can produce a structured `-32602` error.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "operator_protected" => Some(KeyClass::OperatorProtected),
            "subject" => Some(KeyClass::Subject),
            "operator_internal" => Some(KeyClass::OperatorInternal),
            _ => None,
        }
    }
}

/// Default class for any record (handles deserialization of records
/// persisted before `class` was introduced — they pre-date the
/// `OperatorProtected` lockdown semantics and so are correctly modeled
/// as `Subject`).
fn default_key_class() -> KeyClass {
    KeyClass::Subject
}

/// Outcome of an admin-issued revoke attempt against a specific record.
/// Surfaced by [`ApiKeyManager::revoke_by_id_admin`] so callers (the RPC
/// handler) can map the four states to distinct JSON-RPC errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminRevokeOutcome {
    /// Key was active and is now revoked.
    Revoked,
    /// No active record with this `key_id` exists (already revoked, or
    /// never minted on this node).
    NotFound,
    /// Record exists but is `KeyClass::OperatorProtected` — the operator
    /// has self-locked this key against RPC-side revoke. Rotation
    /// requires updating the secret store + restarting the node.
    Protected,
}

/// Outcome of a subject-issued revoke attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectRevokeOutcome {
    /// Caller's subject matches the record's subject and the key is
    /// now revoked.
    Revoked,
    /// No active record with this `key_id` exists.
    NotFound,
    /// Record exists but its subject does not match the caller's
    /// presented key — surfaced as `-32004` so the caller cannot infer
    /// which other subject owns it.
    NotYours,
    /// Record exists and the subject matches, but the class is not
    /// subject-revokable (`OperatorProtected` or `OperatorInternal`).
    /// Surfaced separately from `NotYours` because the subject does in
    /// fact own the record — they just can't revoke it via this path.
    NotSubjectRevokable,
}

/// Persisted record for an issued API key.
///
/// The raw key is hashed with SHA-256 and never stored. The key id
/// (first 8 bytes of the hash, hex-encoded) is a non-secret handle
/// used for revocation and audit.
/// Agent-delegation parameters passed at key-issuance time.
///
/// All fields are optional and individually opt-in. The empty default
/// produces a legacy-shaped key with no per-party / per-template /
/// per-command authorization. Setting any field activates the
/// corresponding enforcement check on the RPC path.
///
/// Wire format on the `tenzro_createApiKey` JSON-RPC params mirrors
/// the field names exactly (snake_case).
#[derive(Debug, Clone, Default)]
pub struct AgentDelegation {
    /// Fully-qualified party ids the key is allowed to act for.
    pub can_act_as_parties: Vec<String>,
    /// Fully-qualified party ids the key is allowed to observe.
    pub can_read_as_parties: Vec<String>,
    /// DAML template ids the key is allowed to query or submit against.
    pub allowed_templates: Vec<String>,
    /// DAML choice / command shapes the key is allowed to exercise.
    pub allowed_commands: Vec<String>,
    /// Per-command value ceiling in amulet smallest units.
    pub max_per_command_amulet: Option<u128>,
    /// Rolling-day cumulative value ceiling in amulet smallest units.
    pub max_per_day_amulet: Option<u128>,
    /// Command shapes that require an AP2 cart mandate.
    pub requires_mandate_for: Vec<String>,
    /// Unix timestamp (seconds) after which the key is rejected.
    pub valid_until: Option<i64>,

    // ── Per-resource-class allow-lists ────────────────────────────
    //
    // Each list is empty-by-default. Empty means "no per-resource
    // restriction in this class" (legacy unrestricted behavior). Non-
    // empty means the RPC layer refuses invocations against
    // resources outside the set. The seven resource classes mirror
    // the operator-brokerage model.

    /// Tool / MCP resource_ids the key is allowed to invoke. Gated at
    /// `tenzro_useTool` / `tenzro_invokeMcpTool`. Includes stdio
    /// MCPs, remote MCPs, and API tools alike.
    pub allowed_tools: Vec<String>,

    /// Skill ids the key is allowed to invoke. Gated at
    /// `tenzro_useSkill`.
    pub allowed_skills: Vec<String>,

    /// Knowledge resource_ids the key is allowed to query. Gated at
    /// `tenzro_useKnowledge` (added with the knowledge registry).
    pub allowed_knowledge: Vec<String>,

    /// Workflow template_ids the key is allowed to instantiate.
    /// Gated at `tenzro_instantiateWorkflow` (added with the workflow
    /// template catalog).
    pub allowed_workflow_templates: Vec<String>,

    /// Agent template_ids the key is allowed to instantiate. Gated at
    /// `tenzro_spawnAgentFromTemplate` and the related agent-kit RPCs.
    pub allowed_agent_templates: Vec<String>,

    /// Model_ids the key is allowed to call for inference. Gated at
    /// `tenzro_chat` / `tenzro_inferenceRequest` / the multi-modal
    /// `*` family. Empty = no model restriction.
    pub allowed_models: Vec<String>,

    /// Per-resource TNZO ceiling override. Maps resource_id to the
    /// per-invocation max in atto-TNZO. Caller refused if the
    /// resource's posted `price_per_call` exceeds the cap for that
    /// resource_id. Empty = no per-resource cap (only the resource's
    /// own price applies).
    pub max_per_resource_tnzo: std::collections::BTreeMap<String, u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    /// Non-secret handle for revocation (8-byte hex prefix of the hash).
    pub key_id: String,
    /// Optional subject identifier (typically a Tenzro DID).
    pub subject: Option<String>,
    /// Free-form label set at issuance.
    pub label: String,
    /// Granted scopes. Empty = invalid.
    pub scopes: Vec<ApiKeyScope>,
    /// Trust class. Drives the revoke policy — see [`KeyClass`].
    #[serde(default = "default_key_class")]
    pub class: KeyClass,
    /// Unix timestamp (seconds) of issuance.
    pub created_at: i64,
    /// Unix timestamp (seconds) of revocation, if any.
    pub revoked_at: Option<i64>,
    /// Optional Canton User Management Service user id this key acts as
    /// (e.g. `tenzro-labs@clients`). When set, the node forwards Canton
    /// calls with `actAs = primaryParty(canton_user_id)` and Canton's
    /// AuthService enforces per-user CanActAs rights. When `None`, the
    /// node falls back to the operator's primary party (legacy shared
    /// path). See `docs/operators/CANTON_MULTITENANT.md` for the
    /// multi-tenant architecture decision.
    #[serde(default)]
    pub canton_user_id: Option<String>,

    /// Stage 2.b: the Canton IdentityProviderConfig id
    /// auto-registered for this tenant at issuance. Used by
    /// `tenzro_revokeApiKey` to tear down the IDP in lockstep with
    /// revoking the key.
    #[serde(default)]
    pub canton_identity_provider_id: Option<String>,

    /// Stage 2.b: the upstream OAuth client_id minted for this
    /// tenant. Used by `tenzro_revokeApiKey` to delete the upstream
    /// client. The `client_secret` is NOT stored — the tenant holds
    /// it exclusively.
    #[serde(default)]
    pub tenant_oauth_client_id: Option<String>,

    /// Agent delegation: fully-qualified party ids the key is allowed
    /// to act for. Empty = no per-party restriction (legacy keys before
    /// the agentic-Canton feature shipped). Non-empty = the RPC layer
    /// refuses requests targeting parties outside this set, and on
    /// Canton-side the corresponding `CanActAs` rights are provisioned
    /// when the key is issued.
    #[serde(default)]
    pub can_act_as_parties: Vec<String>,

    /// Agent delegation: fully-qualified party ids the key is allowed
    /// to observe. Same semantics as `can_act_as_parties` but for read
    /// surfaces (`tenzro_canton_watchParty`, `tenzro_canton_streamEvents`).
    #[serde(default)]
    pub can_read_as_parties: Vec<String>,

    /// Agent delegation: DAML template ids the key is allowed to query
    /// or submit commands against. Format matches Canton template ids
    /// (`#package:Module:Template` or `package-id:Module:Template`).
    /// Empty = no template restriction.
    #[serde(default)]
    pub allowed_templates: Vec<String>,

    /// Agent delegation: DAML choice / command shapes the key is
    /// allowed to exercise (e.g. `Transfer`, `Redeem`, `Approve`).
    /// Empty = no command restriction. Applies to write paths only.
    #[serde(default)]
    pub allowed_commands: Vec<String>,

    /// Agent delegation: per-command value ceiling, denominated in
    /// the underlying asset's smallest unit (e.g. amulet `1e-10` units).
    /// `None` = no per-command cap.
    #[serde(default)]
    pub max_per_command_amulet: Option<u128>,

    /// Agent delegation: rolling-day cumulative value ceiling. The
    /// runtime tracks `current_day_spend_amulet` across all commands
    /// the key has exercised. `None` = no per-day cap.
    #[serde(default)]
    pub max_per_day_amulet: Option<u128>,

    /// Agent delegation: command shapes that require an AP2 cart
    /// mandate signed by the controlling party. Refusal without a
    /// mandate even if the command is in `allowed_commands`. Maps
    /// directly to the AP2 mandate flow already implemented for
    /// HTTP-payment paths.
    #[serde(default)]
    pub requires_mandate_for: Vec<String>,

    /// Agent delegation: expiration. Unix timestamp (seconds) after
    /// which the key is rejected even if not explicitly revoked.
    /// Defense-in-depth alongside `revoked_at`. `None` = no expiration.
    #[serde(default)]
    pub valid_until: Option<i64>,

    // ── Per-resource-class allow-lists (cross-class delegation) ────
    //
    // Empty-by-default means "no restriction in this class" (legacy
    // unrestricted). Non-empty means the RPC layer refuses invocations
    // against resources outside the set. The seven classes mirror the
    // operator-brokerage model: tools / skills / knowledge / workflow
    // templates / agent templates / models / per-resource TNZO caps.

    /// Tool / MCP resource_ids the key is allowed to invoke. Gated at
    /// `tenzro_useTool` and the `tenzro_invokeMcpTool` wrapper.
    /// Includes stdio + remote MCPs + native + API tools alike.
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    /// Skill ids the key is allowed to invoke. Gated at
    /// `tenzro_useSkill`.
    #[serde(default)]
    pub allowed_skills: Vec<String>,

    /// Knowledge resource_ids the key is allowed to query. Gated at
    /// `tenzro_useKnowledge` (knowledge registry).
    #[serde(default)]
    pub allowed_knowledge: Vec<String>,

    /// Workflow template_ids the key is allowed to instantiate.
    /// Gated at `tenzro_instantiateWorkflow`.
    #[serde(default)]
    pub allowed_workflow_templates: Vec<String>,

    /// Agent template_ids the key is allowed to instantiate. Gated at
    /// the agent-kit spawn RPCs. Distinct from `allowed_templates`
    /// (which is Canton DAML template ids).
    #[serde(default)]
    pub allowed_agent_templates: Vec<String>,

    /// Model_ids the key is allowed to call for inference. Gated at
    /// `tenzro_chat` + `tenzro_inferenceRequest` + the multi-modal
    /// family (`tenzro_forecast`, `tenzro_imageEmbed`, etc.).
    #[serde(default)]
    pub allowed_models: Vec<String>,

    /// Per-resource TNZO ceiling override. Maps resource_id to the
    /// per-invocation max in atto-TNZO. Caller refused if the
    /// resource's posted `price_per_call` exceeds the cap for that
    /// resource_id. Empty = no per-resource cap (only the resource's
    /// own price applies, plus any wallet-level spending policy).
    #[serde(default)]
    pub max_per_resource_tnzo: std::collections::BTreeMap<String, u128>,
}

impl ApiKeyRecord {
    /// Returns true if the record is still active.
    ///
    /// Active means: not revoked, has at least one scope, and (if the
    /// agent delegation `valid_until` is set) the expiration is in the
    /// future. The expiration check uses wall-clock at call time —
    /// callers in critical paths should re-check on every request,
    /// not cache the active flag.
    pub fn is_active(&self) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        if self.scopes.is_empty() {
            return false;
        }
        if let Some(expiry) = self.valid_until {
            let now = chrono::Utc::now().timestamp();
            if now >= expiry {
                return false;
            }
        }
        true
    }

    /// Returns true if the record carries the given scope.
    pub fn has_scope(&self, scope: ApiKeyScope) -> bool {
        self.scopes.contains(&scope)
    }

    /// Returns true if the agent-delegation fields restrict the key to
    /// specific parties. When false, the key has the legacy unrestricted
    /// behavior (act for the operator-default party). When true, the
    /// RPC enforcement layer must check per-party + per-template +
    /// per-command authorization on every Canton call.
    pub fn has_party_delegation(&self) -> bool {
        !self.can_act_as_parties.is_empty() || !self.can_read_as_parties.is_empty()
    }

    /// Returns true if this key is authorized to act as the given
    /// fully-qualified party id. Returns true if the key has no
    /// `can_act_as_parties` restriction (legacy unrestricted) or if
    /// the requested party is in the allowed set.
    pub fn can_act_as(&self, party_fq: &str) -> bool {
        self.can_act_as_parties.is_empty()
            || self.can_act_as_parties.iter().any(|p| p == party_fq)
    }

    /// Returns true if this key is authorized to read for the given
    /// fully-qualified party id. `can_act_as` implies `can_read_as`
    /// (the actor-class includes the reader-class).
    pub fn can_read_as(&self, party_fq: &str) -> bool {
        self.can_read_as_parties.is_empty()
            || self.can_read_as_parties.iter().any(|p| p == party_fq)
            || self.can_act_as(party_fq)
    }

    /// Returns true if this key is authorized for the given template id.
    /// Returns true if the key has no `allowed_templates` restriction.
    pub fn allows_template(&self, template_id: &str) -> bool {
        self.allowed_templates.is_empty()
            || self.allowed_templates.iter().any(|t| t == template_id)
    }

    /// Returns true if this key is authorized for the given command
    /// shape (DAML choice name or command kind like `Transfer`).
    /// Returns true if the key has no `allowed_commands` restriction.
    pub fn allows_command(&self, command: &str) -> bool {
        self.allowed_commands.is_empty()
            || self.allowed_commands.iter().any(|c| c == command)
    }

    /// Returns true if the given command shape requires a mandate to
    /// be presented. When true, the RPC handler refuses without an
    /// AP2 cart mandate signed by the controlling party.
    pub fn requires_mandate(&self, command: &str) -> bool {
        self.requires_mandate_for.iter().any(|c| c == command)
    }

    /// Returns true if this key is authorized to invoke the given
    /// tool / MCP resource_id. Returns true if the key has no
    /// `allowed_tools` restriction (legacy unrestricted behavior) or
    /// if the resource_id is in the allow-list.
    pub fn allows_tool(&self, tool_id: &str) -> bool {
        self.allowed_tools.is_empty() || self.allowed_tools.iter().any(|t| t == tool_id)
    }

    /// Returns true if this key is authorized to invoke the given
    /// skill_id. Same semantics as [`allows_tool`].
    pub fn allows_skill(&self, skill_id: &str) -> bool {
        self.allowed_skills.is_empty() || self.allowed_skills.iter().any(|s| s == skill_id)
    }

    /// Returns true if this key is authorized to query the given
    /// knowledge resource_id. Same semantics as [`allows_tool`].
    pub fn allows_knowledge(&self, knowledge_id: &str) -> bool {
        self.allowed_knowledge.is_empty()
            || self.allowed_knowledge.iter().any(|k| k == knowledge_id)
    }

    /// Returns true if this key is authorized to instantiate the
    /// given workflow template_id. Same semantics as [`allows_tool`].
    pub fn allows_workflow_template(&self, template_id: &str) -> bool {
        self.allowed_workflow_templates.is_empty()
            || self
                .allowed_workflow_templates
                .iter()
                .any(|t| t == template_id)
    }

    /// Returns true if this key is authorized to instantiate the
    /// given agent template_id. Same semantics as [`allows_tool`].
    pub fn allows_agent_template(&self, template_id: &str) -> bool {
        self.allowed_agent_templates.is_empty()
            || self
                .allowed_agent_templates
                .iter()
                .any(|t| t == template_id)
    }

    /// Returns true if this key is authorized to call the given
    /// model_id for inference. Same semantics as [`allows_tool`].
    pub fn allows_model(&self, model_id: &str) -> bool {
        self.allowed_models.is_empty() || self.allowed_models.iter().any(|m| m == model_id)
    }

    /// Returns the per-resource TNZO ceiling for `resource_id`, if
    /// one is configured. The caller is refused if the resource's
    /// posted price exceeds this cap. `None` = no cap for that
    /// resource_id (only the resource's own price applies, plus any
    /// wallet-level spending policy).
    pub fn max_tnzo_for_resource(&self, resource_id: &str) -> Option<u128> {
        self.max_per_resource_tnzo.get(resource_id).copied()
    }

    /// Bundles all per-resource-class checks for a given resource into
    /// a single result. Returns `Ok(())` when the key is allowed to
    /// invoke the resource AND the resource's price fits under the
    /// per-resource TNZO ceiling. Returns `Err` with a one-line
    /// reason describing which check failed.
    ///
    /// `class` is one of `"tool"`, `"skill"`, `"knowledge"`,
    /// `"workflow_template"`, `"agent_template"`, `"model"`. Caller
    /// of this method must use the matching string — RPC handlers
    /// have a single source of truth so we don't drift names.
    pub fn check_resource_authorization(
        &self,
        class: &str,
        resource_id: &str,
        posted_price: u128,
    ) -> std::result::Result<(), String> {
        let allowed = match class {
            "tool" => self.allows_tool(resource_id),
            "skill" => self.allows_skill(resource_id),
            "knowledge" => self.allows_knowledge(resource_id),
            "workflow_template" => self.allows_workflow_template(resource_id),
            "agent_template" => self.allows_agent_template(resource_id),
            "model" => self.allows_model(resource_id),
            _ => return Err(format!("unknown resource class: {}", class)),
        };
        if !allowed {
            return Err(format!(
                "key not authorized for {} resource {}: not in allow-list",
                class, resource_id
            ));
        }
        if let Some(cap) = self.max_tnzo_for_resource(resource_id)
            && posted_price > cap
        {
            return Err(format!(
                "resource {} price {} exceeds per-key cap {}",
                resource_id, posted_price, cap
            ));
        }
        Ok(())
    }
}

/// Result of issuing a new API key.
#[derive(Debug, Clone)]
pub struct IssuedApiKey {
    /// The plaintext API key. Returned exactly once.
    pub key: String,
    /// The persisted record (without the plaintext).
    pub record: ApiKeyRecord,
}

/// In-memory + persistent API-key registry.
///
/// Lookups hit an in-memory cache (`DashMap` semantics via `RwLock`-wrapped
/// `HashMap`) for the hot path; writes go through to `CF_API_KEYS`.
/// On construction, the registry hydrates from RocksDB so issued keys
/// survive node restarts.
pub struct ApiKeyManager {
    storage: Arc<dyn KvStore>,
    cache: RwLock<std::collections::HashMap<String, ApiKeyRecord>>,
}

impl std::fmt::Debug for ApiKeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyManager")
            .field("cached", &self.cache.read().len())
            .finish()
    }
}

impl ApiKeyManager {
    /// Constructs a manager backed by the given KV store and hydrates the
    /// in-memory cache from `CF_API_KEYS`.
    pub fn new(storage: Arc<dyn KvStore>) -> Result<Arc<Self>> {
        let mgr = Self {
            storage,
            cache: RwLock::new(std::collections::HashMap::new()),
        };
        mgr.hydrate()?;
        Ok(Arc::new(mgr))
    }

    /// Loads all existing records from `CF_API_KEYS` into the cache.
    fn hydrate(&self) -> Result<()> {
        let entries = self
            .storage
            .scan_prefix(CF_API_KEYS, b"apikey:")
            .map_err(|e| NodeError::Internal(format!("api_key hydrate scan failed: {}", e)))?;

        let mut cache = self.cache.write();
        for (key, value) in entries {
            let hash_hex = match std::str::from_utf8(&key) {
                Ok(k) => k.trim_start_matches("apikey:").to_string(),
                Err(_) => continue,
            };
            let record: ApiKeyRecord = match serde_json::from_slice(&value) {
                Ok(r) => r,
                Err(_) => continue,
            };
            cache.insert(hash_hex, record);
        }
        Ok(())
    }

    /// Generates a new key, persists its hash + record, and returns the
    /// plaintext exactly once. Scopes must be non-empty.
    ///
    /// `canton_user_id` optionally binds this key to a Canton User
    /// Management Service user id (e.g. `tenzro-labs@clients`). When
    /// present, the node uses this user's primary party as `actAs` for
    /// every canton-scoped call made with this key, and Canton's
    /// AuthService enforces per-user CanActAs rights. See
    /// `docs/operators/CANTON_MULTITENANT.md`.
    pub fn issue(
        &self,
        subject: Option<String>,
        label: impl Into<String>,
        scopes: Vec<ApiKeyScope>,
        class: KeyClass,
        canton_user_id: Option<String>,
        canton_identity_provider_id: Option<String>,
        tenant_oauth_client_id: Option<String>,
    ) -> Result<IssuedApiKey> {
        self.issue_with_delegation(
            subject,
            label,
            scopes,
            class,
            canton_user_id,
            canton_identity_provider_id,
            tenant_oauth_client_id,
            AgentDelegation::default(),
        )
    }

    /// Issue a key with the optional agent-delegation parameters set.
    /// When [`AgentDelegation::default`] is used, the resulting key has
    /// the same shape and behavior as a legacy key issued via
    /// [`Self::issue`]. When any delegation field is non-default, the
    /// RPC enforcement layer applies per-party / per-template /
    /// per-command authorization on every Canton call presenting the
    /// key.
    pub fn issue_with_delegation(
        &self,
        subject: Option<String>,
        label: impl Into<String>,
        scopes: Vec<ApiKeyScope>,
        class: KeyClass,
        canton_user_id: Option<String>,
        canton_identity_provider_id: Option<String>,
        tenant_oauth_client_id: Option<String>,
        delegation: AgentDelegation,
    ) -> Result<IssuedApiKey> {
        if scopes.is_empty() {
            return Err(NodeError::Internal(
                "api_key issue: at least one scope required".to_string(),
            ));
        }

        // 32 bytes of CSPRNG, base64url-no-pad, tnz_ prefix.
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        use base64::Engine;
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let key = format!("tnz_{}", body);

        let hash_hex = hash_key(&key);
        let key_id = hash_hex[..16].to_string();
        let created_at = chrono::Utc::now().timestamp();

        let record = ApiKeyRecord {
            key_id,
            subject,
            label: label.into(),
            scopes,
            class,
            created_at,
            revoked_at: None,
            canton_user_id,
            canton_identity_provider_id,
            tenant_oauth_client_id,
            can_act_as_parties: delegation.can_act_as_parties,
            can_read_as_parties: delegation.can_read_as_parties,
            allowed_templates: delegation.allowed_templates,
            allowed_commands: delegation.allowed_commands,
            max_per_command_amulet: delegation.max_per_command_amulet,
            max_per_day_amulet: delegation.max_per_day_amulet,
            requires_mandate_for: delegation.requires_mandate_for,
            valid_until: delegation.valid_until,
            allowed_tools: delegation.allowed_tools,
            allowed_skills: delegation.allowed_skills,
            allowed_knowledge: delegation.allowed_knowledge,
            allowed_workflow_templates: delegation.allowed_workflow_templates,
            allowed_agent_templates: delegation.allowed_agent_templates,
            allowed_models: delegation.allowed_models,
            max_per_resource_tnzo: delegation.max_per_resource_tnzo,
        };

        let storage_key = format!("apikey:{}", hash_hex);
        let value = serde_json::to_vec(&record)
            .map_err(|e| NodeError::Internal(format!("api_key serialize: {}", e)))?;
        self.storage
            .put(CF_API_KEYS, storage_key.as_bytes(), &value)
            .map_err(|e| NodeError::Internal(format!("api_key put: {}", e)))?;

        self.cache.write().insert(hash_hex, record.clone());

        Ok(IssuedApiKey { key, record })
    }

    /// Looks up a key by its plaintext value. Returns `Ok(None)` if the
    /// key is unknown or revoked.
    pub fn lookup(&self, plaintext: &str) -> Option<ApiKeyRecord> {
        let hash_hex = hash_key(plaintext);
        let cache = self.cache.read();
        cache.get(&hash_hex).filter(|r| r.is_active()).cloned()
    }

    /// Admin-path revoke by `key_id`. Refuses to revoke records with
    /// `KeyClass::OperatorProtected` — those keys are locked against
    /// RPC-side revoke as a self-imposed safety net for the operator
    /// (rotation requires updating the secret store + restarting the
    /// node).
    pub fn revoke_by_id_admin(&self, key_id: &str) -> Result<AdminRevokeOutcome> {
        let mut cache = self.cache.write();
        let (hash_hex, mut record) = match cache
            .iter()
            .find(|(_, r)| r.key_id == key_id && r.is_active())
            .map(|(k, r)| (k.clone(), r.clone()))
        {
            Some(pair) => pair,
            None => return Ok(AdminRevokeOutcome::NotFound),
        };

        if matches!(record.class, KeyClass::OperatorProtected) {
            return Ok(AdminRevokeOutcome::Protected);
        }

        record.revoked_at = Some(chrono::Utc::now().timestamp());
        let storage_key = format!("apikey:{}", hash_hex);
        let value = serde_json::to_vec(&record)
            .map_err(|e| NodeError::Internal(format!("api_key serialize: {}", e)))?;
        self.storage
            .put(CF_API_KEYS, storage_key.as_bytes(), &value)
            .map_err(|e| NodeError::Internal(format!("api_key put: {}", e)))?;
        cache.insert(hash_hex, record);
        Ok(AdminRevokeOutcome::Revoked)
    }

    /// Subject-path revoke. The caller presents their own active key
    /// (resolved by `gate_api_key` upstream), and supplies its
    /// `subject` value here for ownership matching against the target
    /// `key_id`. Only `KeyClass::Subject` records are revokable via
    /// this path; OperatorProtected and OperatorInternal records refuse.
    pub fn revoke_by_subject(
        &self,
        caller_subject: &str,
        target_key_id: &str,
    ) -> Result<SubjectRevokeOutcome> {
        let mut cache = self.cache.write();
        let (hash_hex, mut record) = match cache
            .iter()
            .find(|(_, r)| r.key_id == target_key_id && r.is_active())
            .map(|(k, r)| (k.clone(), r.clone()))
        {
            Some(pair) => pair,
            None => return Ok(SubjectRevokeOutcome::NotFound),
        };

        let record_subject = match record.subject.as_deref() {
            Some(s) => s,
            None => return Ok(SubjectRevokeOutcome::NotYours),
        };
        if record_subject != caller_subject {
            return Ok(SubjectRevokeOutcome::NotYours);
        }
        if !matches!(record.class, KeyClass::Subject) {
            return Ok(SubjectRevokeOutcome::NotSubjectRevokable);
        }

        record.revoked_at = Some(chrono::Utc::now().timestamp());
        let storage_key = format!("apikey:{}", hash_hex);
        let value = serde_json::to_vec(&record)
            .map_err(|e| NodeError::Internal(format!("api_key serialize: {}", e)))?;
        self.storage
            .put(CF_API_KEYS, storage_key.as_bytes(), &value)
            .map_err(|e| NodeError::Internal(format!("api_key put: {}", e)))?;
        cache.insert(hash_hex, record);
        Ok(SubjectRevokeOutcome::Revoked)
    }

    /// Lists all known records (active and revoked). The plaintext keys
    /// are not stored and cannot be returned.
    pub fn list(&self) -> Vec<ApiKeyRecord> {
        self.cache.read().values().cloned().collect()
    }

    /// Looks up a record by its non-secret `key_id`. Returns the
    /// active record (or the revoked one if no active record exists)
    /// so callers can introspect tenant metadata for cleanup.
    pub fn find_by_key_id(&self, key_id: &str) -> Option<ApiKeyRecord> {
        let cache = self.cache.read();
        cache
            .values()
            .find(|r| r.key_id == key_id && r.is_active())
            .cloned()
            .or_else(|| cache.values().find(|r| r.key_id == key_id).cloned())
    }

    /// Lists records whose `subject` matches `caller_subject` (active +
    /// revoked). Used by the subject-gated `tenzro_listMyApiKeys` RPC.
    pub fn list_by_subject(&self, caller_subject: &str) -> Vec<ApiKeyRecord> {
        self.cache
            .read()
            .values()
            .filter(|r| r.subject.as_deref() == Some(caller_subject))
            .cloned()
            .collect()
    }

    /// Authorizes a request for the given RPC method.
    ///
    /// When `plaintext` is `None`, the request is allowed only if the
    /// method is not gated by any scope.
    pub fn authorize(&self, plaintext: Option<&str>, method: &str) -> AuthorizeOutcome {
        let required = match required_scope_for_method(method) {
            None => return AuthorizeOutcome::Allowed,
            Some(s) => s,
        };

        let plaintext = match plaintext {
            Some(p) => p,
            None => return AuthorizeOutcome::MissingKey(required),
        };

        match self.lookup(plaintext) {
            Some(record) if record.has_scope(required) => AuthorizeOutcome::Allowed,
            Some(_) => AuthorizeOutcome::InsufficientScope(required),
            None => AuthorizeOutcome::UnknownOrRevoked,
        }
    }
}

/// Result of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeOutcome {
    /// Either the method requires no scope, or the key carries the
    /// required scope and is active.
    Allowed,
    /// The method requires a scope but no API key was presented.
    MissingKey(ApiKeyScope),
    /// The presented key is unknown to the registry or revoked.
    UnknownOrRevoked,
    /// The key is active but does not carry the required scope.
    InsufficientScope(ApiKeyScope),
}

/// SHA-256 hash of an API key, hex-encoded. Used as the persistence and
/// cache key. Constant-time comparison is not required because the
/// attacker cannot influence which key we look up — we hash the
/// presented plaintext first.
pub fn hash_key(plaintext: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant-time comparison of a presented admin token against the
/// expected operator secret.
///
/// The admin token gates operator-only mutation RPCs (API-key issuance,
/// staking, provider registration). It is a single shared secret held by
/// the node operator, loaded from `TENZRO_ADMIN_TOKEN` at startup and
/// kept off-disk: it is never serialized into `NodeConfig` snapshots,
/// never written to RocksDB, and redacted in `Debug` output.
///
/// Both sides are compared as raw bytes via [`subtle::ConstantTimeEq`]
/// to avoid leaking the length-prefix of a matching token through a
/// length-dependent fast-path. Empty `expected` always returns `false`
/// — a node started without an admin token cannot be unlocked by an
/// empty presentation.
pub fn verify_admin_token(presented: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    if expected.is_empty() {
        return false;
    }
    // Equal-length comparison is required for ConstantTimeEq; differing
    // lengths short-circuit to false without revealing the expected length.
    if presented.len() != expected.len() {
        return false;
    }
    presented.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Returns the scope that gates the given JSON-RPC method, if any.
///
/// New gates should be added here in lock-step with the underlying
/// handler — the gate is the only authoritative source for which
/// methods cost which scope.
pub fn required_scope_for_method(method: &str) -> Option<ApiKeyScope> {
    // Canton-mediated namespaces: the node proxies the call to the
    // shared Canton validator party using its own bearer JWT, so the
    // caller must hold a key with the `canton` scope. Both `*Canton*`
    // and `*Daml*` method names route to the same upstream — the gate
    // must catch both substrings.
    // Match both the legacy CamelCase form (`tenzro_listCantonDomains`,
    // `tenzro_submitDamlCommand`) and the modern snake-case form
    // (`tenzro_canton_uploadDar`, `tenzro_canton_health`, etc.).
    if method.starts_with("tenzro_")
        && (method.contains("Canton")
            || method.contains("canton")
            || method.contains("Daml")
            || method.contains("daml"))
    {
        return Some(ApiKeyScope::Canton);
    }
    // Chainlink-mediated bridge fee oracle paths. The upstream
    // Ethereum mainnet RPC quota is operator-paid, so these calls are
    // gated the same way as `Canton` — per-tenant attribution +
    // rate-limit. The mutation surfaces (`tenzro_setBridgeFeeRate`,
    // `tenzro_setBridgeFeeFeed`, `tenzro_setSponsorshipRefillThreshold`)
    // are admin-token-gated separately and don't fall under the
    // tenant-scope here.
    if matches!(
        method,
        "tenzro_quoteBridgeFeeInTnzo"
            | "tenzro_sponsorBridgeFee"
            | "tenzro_listBridgeSponsorshipPools"
            | "tenzro_listBridgeFeeFeeds"
            | "tenzro_getBridgeFeeFeed"
            | "tenzro_getBridgeAnalytics"
    ) {
        return Some(ApiKeyScope::Chainlink);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;

    fn mem_store() -> Arc<dyn KvStore> {
        Arc::new(MemoryStore::new())
    }

    #[test]
    fn issue_and_lookup_roundtrip() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        let issued = mgr
            .issue(
                Some("did:tenzro:human:abc".to_string()),
                "test key",
                vec![ApiKeyScope::Canton],
                KeyClass::Subject,
                None,
                None,
                None,
            )
            .unwrap();
        assert!(issued.key.starts_with("tnz_"));
        let found = mgr.lookup(&issued.key).expect("key must resolve");
        assert!(found.has_scope(ApiKeyScope::Canton));
        assert_eq!(found.key_id, issued.record.key_id);
        assert_eq!(found.class, KeyClass::Subject);
    }

    #[test]
    fn admin_revoke_makes_key_unusable() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        let issued = mgr
            .issue(None, "to revoke", vec![ApiKeyScope::Canton], KeyClass::Subject, None, None, None)
            .unwrap();
        let outcome = mgr.revoke_by_id_admin(&issued.record.key_id).unwrap();
        assert_eq!(outcome, AdminRevokeOutcome::Revoked);
        assert!(mgr.lookup(&issued.key).is_none());
    }

    #[test]
    fn admin_revoke_refuses_operator_protected() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        let issued = mgr
            .issue(
                None,
                "locked",
                vec![ApiKeyScope::Canton],
                KeyClass::OperatorProtected,
                None,
                None,
                None,
            )
            .unwrap();
        let outcome = mgr.revoke_by_id_admin(&issued.record.key_id).unwrap();
        assert_eq!(outcome, AdminRevokeOutcome::Protected);
        // Still usable.
        assert!(mgr.lookup(&issued.key).is_some());
    }

    #[test]
    fn admin_revoke_not_found_is_distinct_from_protected() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        let outcome = mgr.revoke_by_id_admin("0000000000000000").unwrap();
        assert_eq!(outcome, AdminRevokeOutcome::NotFound);
    }

    #[test]
    fn subject_revoke_only_own_key() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        let alice = mgr
            .issue(
                Some("did:tenzro:human:alice".to_string()),
                "alice",
                vec![ApiKeyScope::Canton],
                KeyClass::Subject,
                None,
                None,
                None,
            )
            .unwrap();
        let bob = mgr
            .issue(
                Some("did:tenzro:human:bob".to_string()),
                "bob",
                vec![ApiKeyScope::Canton],
                KeyClass::Subject,
                None,
                None,
                None,
            )
            .unwrap();

        // Alice cannot revoke bob's key.
        let outcome = mgr
            .revoke_by_subject("did:tenzro:human:alice", &bob.record.key_id)
            .unwrap();
        assert_eq!(outcome, SubjectRevokeOutcome::NotYours);
        assert!(mgr.lookup(&bob.key).is_some());

        // Alice can revoke her own.
        let outcome = mgr
            .revoke_by_subject("did:tenzro:human:alice", &alice.record.key_id)
            .unwrap();
        assert_eq!(outcome, SubjectRevokeOutcome::Revoked);
        assert!(mgr.lookup(&alice.key).is_none());
    }

    #[test]
    fn subject_revoke_refuses_non_subject_class() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        for class in [KeyClass::OperatorProtected, KeyClass::OperatorInternal] {
            let issued = mgr
                .issue(
                    Some("did:tenzro:machine:ops".to_string()),
                    "ops",
                    vec![ApiKeyScope::Canton],
                    class,
                    None,
                    None,
                    None,
                )
                .unwrap();
            let outcome = mgr
                .revoke_by_subject("did:tenzro:machine:ops", &issued.record.key_id)
                .unwrap();
            assert_eq!(
                outcome,
                SubjectRevokeOutcome::NotSubjectRevokable,
                "class {:?} must refuse subject revoke",
                class,
            );
        }
    }

    #[test]
    fn list_by_subject_filters() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        mgr.issue(
            Some("did:tenzro:human:alice".to_string()),
            "alice-1",
            vec![ApiKeyScope::Canton],
            KeyClass::Subject,
            None,
            None,
            None,
        )
        .unwrap();
        mgr.issue(
            Some("did:tenzro:human:alice".to_string()),
            "alice-2",
            vec![ApiKeyScope::Canton],
            KeyClass::Subject,
            None,
            None,
            None,
        )
        .unwrap();
        mgr.issue(
            Some("did:tenzro:human:bob".to_string()),
            "bob-1",
            vec![ApiKeyScope::Canton],
            KeyClass::Subject,
            None,
            None,
            None,
        )
        .unwrap();

        let alice = mgr.list_by_subject("did:tenzro:human:alice");
        assert_eq!(alice.len(), 2);
        assert!(alice.iter().all(|r| {
            r.subject.as_deref() == Some("did:tenzro:human:alice")
        }));
    }

    #[test]
    fn authorize_blocks_unauthenticated_canton() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        let outcome = mgr.authorize(None, "tenzro_listCantonDomains");
        assert_eq!(outcome, AuthorizeOutcome::MissingKey(ApiKeyScope::Canton));
    }

    #[test]
    fn authorize_blocks_unauthenticated_daml() {
        // `*Daml*` method names route to the same upstream Canton
        // participant as `*Canton*` and must share the same gate.
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        for method in [
            "tenzro_listDamlContracts",
            "tenzro_submitDamlCommand",
            "tenzro_consumeDamlEvents",
        ] {
            let outcome = mgr.authorize(None, method);
            assert_eq!(
                outcome,
                AuthorizeOutcome::MissingKey(ApiKeyScope::Canton),
                "method {} must be gated by canton scope",
                method,
            );
        }
    }

    #[test]
    fn authorize_allows_ungated_method_without_key() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        let outcome = mgr.authorize(None, "tenzro_blockNumber");
        assert_eq!(outcome, AuthorizeOutcome::Allowed);
    }

    #[test]
    fn authorize_rejects_revoked_key() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        let issued = mgr
            .issue(None, "tmp", vec![ApiKeyScope::Canton], KeyClass::Subject, None, None, None)
            .unwrap();
        mgr.revoke_by_id_admin(&issued.record.key_id).unwrap();
        let outcome = mgr.authorize(Some(&issued.key), "tenzro_listCantonDomains");
        assert_eq!(outcome, AuthorizeOutcome::UnknownOrRevoked);
    }

    #[test]
    fn hydrate_restores_from_storage() {
        let store = mem_store();
        let mgr = ApiKeyManager::new(store.clone()).unwrap();
        let issued = mgr
            .issue(
                None,
                "persisted",
                vec![ApiKeyScope::Canton],
                KeyClass::Subject,
                None,
                None,
                None,
            )
            .unwrap();
        // Drop and rebuild against the same backing store.
        drop(mgr);
        let mgr2 = ApiKeyManager::new(store).unwrap();
        let found = mgr2.lookup(&issued.key);
        assert!(found.is_some());
        assert_eq!(found.unwrap().class, KeyClass::Subject);
    }

    #[test]
    fn admin_token_accepts_exact_match() {
        assert!(verify_admin_token("s3cret-token-value", "s3cret-token-value"));
    }

    #[test]
    fn admin_token_rejects_mismatch() {
        assert!(!verify_admin_token("wrong", "s3cret-token-value"));
        // Same length, different bytes — exercises the ct_eq path rather
        // than the length-prefix short-circuit.
        assert!(!verify_admin_token("s3cret-token-valuX", "s3cret-token-value"));
    }

    #[test]
    fn admin_token_rejects_empty_expected() {
        // A node configured without TENZRO_ADMIN_TOKEN must be unreachable
        // through the gate — including by a caller presenting the empty
        // string.
        assert!(!verify_admin_token("", ""));
        assert!(!verify_admin_token("anything", ""));
    }

    #[test]
    fn admin_token_rejects_empty_presented_against_real_secret() {
        assert!(!verify_admin_token("", "s3cret-token-value"));
    }

    #[test]
    fn admin_token_rejects_prefix() {
        // Confirms that a partial prefix does not authenticate — the
        // length-prefix check short-circuits before ct_eq.
        assert!(!verify_admin_token("s3cret", "s3cret-token-value"));
        assert!(!verify_admin_token("s3cret-token-value-extra", "s3cret-token-value"));
    }
}
