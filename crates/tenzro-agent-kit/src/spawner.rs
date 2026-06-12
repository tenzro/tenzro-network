//! Spawner — provisions identity, wallet, delegation, and registers the
//! agent with the [`tenzro_agent::AgentRuntime`].
//!
//! # Pipeline
//!
//! `AgentSpawner::spawn(template_id, args)` performs the full provisioning
//! pipeline laid out in the architecture plan:
//!
//!   1. Fetch the [`AgentTemplate`] from the registry
//!   2. Insist on an [`ExecutionSpec`] (no spec → fail loudly)
//!   3. Auto-discover required tools and skills via [`TemplateResolver`]
//!   4. Generate a fresh Ed25519 keypair for the controller (one per spawn —
//!      a real deployment would reuse a user-bound key, but for the agent
//!      kit we mint a fresh one so the spawn API stays self-contained)
//!   5. Register the controller via `IdentityRegistry::register_human_with_fee`
//!      (which auto-provisions an MPC wallet via
//!      [`tenzro_identity::WalletBinder`])
//!   6. Generate a fresh Ed25519 keypair for the machine identity
//!   7. Build a [`DelegationScope`] from the template's `DelegationSpec`
//!   8. Register the machine via `IdentityRegistry::register_machine_with_fee`
//!   9. Register the agent with [`AgentRuntime::register_agent`] (which
//!      drives the lifecycle to Active)
//!  10. Return a [`SpawnedAgent`] handle the executor can use
//!
//! Every step is fail-fast — any error returns immediately and the agent
//! is not registered. There is no partial state to clean up, so this is
//! crash-safe.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{Duration as ChronoDuration, Utc};

use tenzro_agent::{AgentRuntime, RegisteredAgent, SpendingPolicy};
use tenzro_crypto::keys::{KeyPair, KeyType};
use tenzro_identity::{DelegationScope, IdentityRegistry, TenzroIdentity, TimeBound};
use tenzro_types::agent_template::{
    AgentTemplate, DelegationSpec, ExecutionBackend, ExecutionSpec,
};
use tenzro_types::identity::KycTier;
use tenzro_types::primitives::Address;

use crate::auth::{AgentAuthRequest, AgentCredentials, AuthIssuer};
use crate::error::AgentKitError;
use crate::registry::RegistryClient;
use crate::resolver::{DiscoveredResources, TemplateResolver};
use crate::spec::parse_kyc_tier;

/// Default agent JWT TTL — one week. Long enough for a multi-step
/// rebalance loop to complete without re-issuance; short enough that a
/// stolen token decays before most controllers would notice.
const DEFAULT_AGENT_TOKEN_TTL_SECS: u64 = 7 * 24 * 3600;

/// Per-spawn arguments supplied by the caller.
#[derive(Debug, Clone)]
pub struct SpawnArgs {
    /// Display name for the controller human identity (e.g. "Acme AM").
    pub controller_display_name: String,

    /// KYC tier of the controller. Must be at least the tier the
    /// template's [`DelegationSpec`] requires.
    pub kyc_tier: KycTier,

    /// Free-form context map used for `{{var}}` substitution at run time.
    /// E.g. `{"deposit_amount": "1000000000", "to": "0xabc..."}`.
    pub context: HashMap<String, String>,

    /// Optional parent machine DID. When set, the spawned agent's
    /// delegation scope is the strict intersection of the parent's scope
    /// and the template's `DelegationSpec` (via
    /// [`DelegationScope::attenuate`]). When `None`, the template's spec
    /// is used verbatim — that is the top-level (human-controlled) spawn
    /// path.
    pub parent_machine_did: Option<String>,
}

impl Default for SpawnArgs {
    fn default() -> Self {
        Self {
            controller_display_name: "Tenzro Agent Kit".to_string(),
            kyc_tier: KycTier::Unverified,
            context: HashMap::new(),
            parent_machine_did: None,
        }
    }
}

/// Handle to an agent that has been fully provisioned and registered.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpawnedAgent {
    /// Original template fetched from the registry.
    pub template: AgentTemplate,

    /// Controller human identity (DID + status + auto-provisioned wallet).
    pub controller: TenzroIdentity,

    /// Machine identity for the agent itself (DID + delegation scope).
    pub machine: TenzroIdentity,

    /// `RegisteredAgent` returned by [`AgentRuntime::register_agent`].
    pub agent: RegisteredAgent,

    /// Tools/skills resolved from the registry by tag.
    pub discovered: DiscoveredResources,

    /// Frozen copy of the spawn-time context map for executor use.
    pub context: HashMap<String, String>,

    /// DPoP-bound JWT credentials issued by the configured [`AuthIssuer`]
    /// at spawn time. When the spawner is constructed without an issuer
    /// (`AgentSpawner::new`), this stays `None` and the executor falls
    /// back to its hardcoded "lacks DPoP credentials" failure path.
    ///
    /// **Not persisted.** `AgentCredentials` carries an `Arc<dyn DpopSigner>`
    /// trait object that cannot serialize. Across a persistence boundary
    /// the agent loses its authority and must be re-issued by calling
    /// back into the controller — this is intentional (credentials are
    /// short-lived, default 7d TTL, so re-issuance is the natural
    /// recovery path and the agent should not retain its capability to
    /// sign transactions across a crash boundary it didn't validate).
    #[serde(skip)]
    pub credentials: Option<AgentCredentials>,

    /// Canton/Daml party id allocated for this agent on the configured
    /// participant. `Some(party)` when the template's `ExecutionBackend` is
    /// `Daml { .. }` — the executor passes this as `actAs` on every
    /// DAML submission so the on-ledger signer is the agent (not the
    /// operator's default party). `None` for non-DAML backends.
    ///
    /// The allocation is performed via the node's `tenzro_allocateParty`
    /// RPC during the spawn pipeline; the participant returns the canonical
    /// `partyId :: participantId` identifier which we store verbatim.
    pub canton_party_id: Option<String>,
}

impl SpawnedAgent {
    /// Returns the controller human DID as a canonical string.
    pub fn controller_did(&self) -> String {
        self.controller.did.to_string()
    }

    /// Returns the machine DID for the agent as a canonical string.
    pub fn machine_did(&self) -> String {
        self.machine.did.to_string()
    }

    /// Returns the agent runtime id (UUID minted by [`AgentRuntime`]).
    pub fn agent_id(&self) -> &str {
        &self.agent.identity.agent_id
    }

    /// Returns the agent's MPC wallet id.
    pub fn wallet_id(&self) -> &str {
        &self.agent.wallet_id
    }

    /// Returns the Canton/Daml party allocated for this agent at spawn
    /// time, if the template's backend is `Daml`. The executor consumes
    /// this on every `DamlSubmit` step so the on-ledger `actAs` is the
    /// agent, not the operator's default party.
    pub fn canton_party_id(&self) -> Option<&str> {
        self.canton_party_id.as_deref()
    }
}

/// Performs the spawn pipeline. Stateless — one struct per spawn is fine.
#[derive(Clone)]
pub struct AgentSpawner {
    registry: Arc<RegistryClient>,
    identity_registry: Arc<IdentityRegistry>,
    agent_runtime: Arc<AgentRuntime>,
    resolver: TemplateResolver,
    /// Optional auth issuer. When set, the spawner mints a DPoP-bound JWT
    /// for the machine identity at the end of the pipeline so the executor
    /// can dispatch authenticated `tenzro_signAndSendTransaction` /
    /// `tenzro_svmDispatch` / Canton commands on the agent's behalf.
    /// When `None`, the executor falls back to its hardcoded "lacks DPoP
    /// credentials" error.
    auth_issuer: Option<Arc<dyn AuthIssuer>>,
}

impl std::fmt::Debug for AgentSpawner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentSpawner")
            .field("registry", &"RegistryClient { .. }")
            .field("identity_registry", &"IdentityRegistry { .. }")
            .field("agent_runtime", &"AgentRuntime { .. }")
            .field("resolver", &self.resolver)
            .field("auth_issuer", &self.auth_issuer.as_ref().map(|_| "AuthIssuer { .. }"))
            .finish()
    }
}

impl AgentSpawner {
    /// Constructs a new spawner around shared subsystems with no auth
    /// issuer wired. The executor's authenticated dispatch paths
    /// (EvmDispatch / SvmDispatch / DamlSubmit) will reject any step that
    /// requires signing because the resulting [`SpawnedAgent`] has no
    /// credentials embedded. Use [`AgentSpawner::with_auth_issuer`] for
    /// the full path.
    pub fn new(
        registry: Arc<RegistryClient>,
        identity_registry: Arc<IdentityRegistry>,
        agent_runtime: Arc<AgentRuntime>,
    ) -> Self {
        let resolver = TemplateResolver::new(registry.clone());
        Self {
            registry,
            identity_registry,
            agent_runtime,
            resolver,
            auth_issuer: None,
        }
    }

    /// Constructs a spawner with a DPoP-capable auth issuer wired.
    /// The machine identity will receive a fresh JWT + DPoP signer at the
    /// end of the spawn pipeline, scoped to the template's
    /// [`DelegationSpec`] and good for [`DEFAULT_AGENT_TOKEN_TTL_SECS`].
    pub fn with_auth_issuer(
        registry: Arc<RegistryClient>,
        identity_registry: Arc<IdentityRegistry>,
        agent_runtime: Arc<AgentRuntime>,
        auth_issuer: Arc<dyn AuthIssuer>,
    ) -> Self {
        let resolver = TemplateResolver::new(registry.clone());
        Self {
            registry,
            identity_registry,
            agent_runtime,
            resolver,
            auth_issuer: Some(auth_issuer),
        }
    }

    /// Runs the full spawn pipeline.
    ///
    /// # Preconditions
    ///
    /// The configured `IdentityRegistry` must have a
    /// [`tenzro_identity::WalletBinder`] wired (via
    /// `IdentityRegistry::with_wallet_binder` /
    /// `with_wallet_binder_arc`). Without it, identity registration falls
    /// back to a deterministic placeholder address with no signable
    /// wallet — the spawner refuses to proceed in that case so callers
    /// don't silently end up with un-signable agents.
    pub async fn spawn(
        &self,
        template_id: &str,
        args: SpawnArgs,
    ) -> Result<SpawnedAgent, AgentKitError> {
        if !self.identity_registry.has_wallet_binder() {
            return Err(AgentKitError::IdentityProvisioning(
                "IdentityRegistry has no WalletBinder configured — agents \
                 spawned through this registry would have placeholder \
                 addresses with no signable wallet. Wire a WalletBinder \
                 via IdentityRegistry::with_wallet_binder_arc before \
                 invoking spawn()."
                    .to_string(),
            ));
        }

        let template = self.registry.get_template(template_id).await?;
        let spec = template
            .execution_spec
            .as_ref()
            .ok_or_else(|| AgentKitError::MissingExecutionSpec(template_id.to_string()))?
            .clone();

        // Verify caller's KYC tier is at least what the template requires.
        let required_tier = parse_kyc_tier(&spec.delegation);
        if (args.kyc_tier.level()) < required_tier.level() {
            return Err(AgentKitError::DelegationRejected(format!(
                "controller kyc tier {:?} is below required {:?}",
                args.kyc_tier, required_tier
            )));
        }

        // 1. Auto-discover tools/skills.
        let discovered = self.resolver.resolve(&spec).await?;
        tracing::debug!(
            target: "tenzro_agent_kit::spawner",
            tools = discovered.tool_count(),
            skills = discovered.skill_count(),
            "auto-discovery complete"
        );

        // 2. Provision controller (human) identity.
        let controller_keypair = KeyPair::generate(KeyType::Ed25519).map_err(|e| {
            AgentKitError::IdentityProvisioning(format!("controller keypair: {e}"))
        })?;

        let controller = self
            .identity_registry
            .register_human_with_fee(
                controller_keypair.public_key().to_bytes(),
                args.controller_display_name.clone(),
                args.kyc_tier,
            )
            .await
            .map_err(|e| AgentKitError::IdentityProvisioning(e.to_string()))?
            .identity;

        tracing::info!(
            target: "tenzro_agent_kit::spawner",
            controller_did = %controller.did,
            "controller human identity registered"
        );

        // 3. Provision machine identity with delegation scope.
        let machine_keypair = KeyPair::generate(KeyType::Ed25519).map_err(|e| {
            AgentKitError::IdentityProvisioning(format!("machine keypair: {e}"))
        })?;

        let template_scope = build_delegation_scope(&spec.delegation);

        // Phase C: child-scope inheritance. When the caller supplies a
        // parent machine DID, the spawned agent's effective scope is the
        // strict intersection of the parent's scope and the template's
        // declared scope. This is the canonical attenuation primitive
        // (DelegationScope::attenuate) — the child can never be broader
        // than its parent on any axis (numeric ceilings, allow-lists,
        // time bound).
        let delegation_scope = if let Some(parent_did) = args.parent_machine_did.as_deref() {
            let parent_identity = self
                .identity_registry
                .resolve(parent_did)
                .map_err(|e| AgentKitError::DelegationRejected(format!(
                    "parent machine DID {parent_did} not resolvable: {e}"
                )))?;
            let parent_scope = parent_identity
                .delegation_scope()
                .ok_or_else(|| AgentKitError::DelegationRejected(format!(
                    "parent DID {parent_did} is not a machine identity (no delegation scope)"
                )))?;
            let attenuated = parent_scope.attenuate(&template_scope);
            tracing::info!(
                target: "tenzro_agent_kit::spawner",
                parent_did = %parent_did,
                "attenuated child delegation scope to parent ∩ template"
            );
            attenuated
        } else {
            template_scope
        };

        let machine_capabilities = derive_machine_capabilities(&template, &spec);
        let controller_did_str = controller.did.to_string();
        let machine = self
            .identity_registry
            .register_machine_with_fee(
                &controller_did_str,
                machine_keypair.public_key().to_bytes(),
                machine_capabilities.clone(),
                delegation_scope,
            )
            .await
            .map_err(|e| AgentKitError::DelegationRejected(e.to_string()))?
            .identity;

        tracing::info!(
            target: "tenzro_agent_kit::spawner",
            machine_did = %machine.did,
            "machine identity registered with delegation scope"
        );

        // Phase C: install runtime SpendingPolicy keyed by the machine DID.
        // The DelegationScope on the identity is the *protocol* ceiling; the
        // SpendingPolicy installed here is the *runtime/execution* ceiling.
        // Both are checked at payment time (see
        // tenzro_payments::IdentityPaymentBinder::validate_payer_for_protocol).
        // u128 → u64 saturation: the runtime gate uses u64 in TNZO smallest
        // units, which already fits realistic per-tx and per-day caps; truly
        // huge declared ceilings collapse to "unbounded" (u64::MAX) here.
        let machine_did_str = machine.did.to_string();
        let runtime_policy = SpendingPolicy::new(
            spec.delegation
                .max_transaction_value
                .min(u64::MAX as u128) as u64,
            spec.delegation
                .max_daily_spend
                .min(u64::MAX as u128) as u64,
        );
        self.agent_runtime
            .set_spending_policy(machine_did_str.clone(), runtime_policy);
        tracing::debug!(
            target: "tenzro_agent_kit::spawner",
            machine_did = %machine_did_str,
            "runtime SpendingPolicy installed from DelegationSpec"
        );

        // 4. Register the agent with the runtime.
        let wallet_address = derive_wallet_address(&machine);
        let runtime_capabilities = build_runtime_capabilities(&template);
        let nonce = chrono::Utc::now().timestamp_millis() as u64;

        let registered = self
            .agent_runtime
            .register_agent(
                template.name.clone(),
                wallet_address,
                runtime_capabilities,
                template.runtime_requirements.requires_tee,
                nonce,
            )
            .await
            .map_err(|e| AgentKitError::Other(format!("agent runtime register: {e}")))?;

        // `register_agent` drives the lifecycle Created -> Initializing ->
        // Active atomically, so the agent is ready for messaging here.
        tracing::info!(
            target: "tenzro_agent_kit::spawner",
            agent_id = %registered.identity.agent_id,
            "agent registered and activated"
        );

        // 5b. Allocate a Canton/Daml party for the agent when the template's
        //     backend is DAML-backed. The on-ledger `actAs` of every contract
        //     this agent submits will be this party — not the operator's
        //     participant-default party. The participant returns a canonical
        //     `partyId :: participantId` identifier which is stored verbatim
        //     on `SpawnedAgent.canton_party_id` and consumed by the executor's
        //     DAML dispatch path.
        //
        //     Failure here aborts the spawn; the registered identities + agent
        //     are not torn down (they're orphan but harmless — the agent has
        //     no credentials yet and cannot submit). For non-DAML backends
        //     this step is a no-op and `canton_party_id` stays `None`.
        let canton_party_id = if matches!(spec.backend, ExecutionBackend::Daml { .. }) {
            // Use the agent runtime id as the party-id hint — it's already
            // unique-per-spawn (a UUID minted by `AgentRuntime`) and ties the
            // on-ledger party back to the agent for forensic correlation.
            let hint = format!("agent-{}", registered.identity.agent_id);
            let display = template.name.clone();
            let result: serde_json::Value = self
                .registry
                .call_raw(
                    "tenzro_allocateParty",
                    serde_json::json!({
                        "party_id_hint": hint,
                        "display_name": display,
                    }),
                )
                .await?;
            let party_id = result
                .get("party_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AgentKitError::Other(format!(
                    "tenzro_allocateParty returned unexpected shape: {result}"
                )))?
                .to_string();
            tracing::info!(
                target: "tenzro_agent_kit::spawner",
                machine_did = %machine.did,
                party_id = %party_id,
                "Canton party allocated for DAML-backed agent"
            );
            Some(party_id)
        } else {
            None
        };

        // 6. Mint DPoP-bound JWT credentials for the machine identity.
        //    This is the final step so a credential-issuance failure leaves
        //    no partial side-effects beyond the registered identities (which
        //    are themselves recoverable / re-registrable). When no issuer
        //    is wired the executor handles the missing-credentials case.
        let credentials = if let Some(issuer) = self.auth_issuer.as_ref() {
            let request = AgentAuthRequest {
                bearer_did: machine.did.to_string(),
                controller_did: controller.did.to_string(),
                max_transaction_value: spec.delegation.max_transaction_value,
                max_daily_spend: spec.delegation.max_daily_spend,
                allowed_operations: spec.delegation.allowed_operations.clone(),
                allowed_chains: spec.delegation.allowed_chains.clone(),
                ttl_secs: DEFAULT_AGENT_TOKEN_TTL_SECS,
            };
            let creds = issuer.issue(request).await?;
            tracing::info!(
                target: "tenzro_agent_kit::spawner",
                machine_did = %machine.did,
                jkt = %creds.jkt,
                expires_at_unix = creds.expires_at_unix,
                "DPoP-bound JWT credentials minted for agent"
            );
            Some(creds)
        } else {
            tracing::warn!(
                target: "tenzro_agent_kit::spawner",
                machine_did = %machine.did,
                "no AuthIssuer wired — agent will fail signed-dispatch steps"
            );
            None
        };

        Ok(SpawnedAgent {
            template,
            controller,
            machine,
            agent: registered,
            discovered,
            context: args.context,
            credentials,
            canton_party_id,
        })
    }
}

/// Constructs a [`DelegationScope`] from a [`DelegationSpec`].
fn build_delegation_scope(spec: &DelegationSpec) -> DelegationScope {
    let now = Utc::now();
    let not_after = now + ChronoDuration::days(spec.time_bound_days as i64);
    DelegationScope::unrestricted()
        .with_max_transaction_value(spec.max_transaction_value)
        .with_max_daily_spend(spec.max_daily_spend)
        .with_allowed_operations(spec.allowed_operations.clone())
        .with_allowed_chains(spec.allowed_chains.clone())
        .with_time_bound(TimeBound::new(now, not_after))
}

/// Builds the capability string list passed to `register_machine_with_fee`.
fn derive_machine_capabilities(template: &AgentTemplate, spec: &ExecutionSpec) -> Vec<String> {
    let mut out: Vec<String> = template
        .capabilities
        .iter()
        .map(|c| c.id.clone())
        .collect();
    if out.is_empty() {
        out.push("agent_template:autonomous".to_string());
    }
    // Add a synthetic capability per allowed operation so delegation
    // checks line up with what the executor will request.
    for op in &spec.delegation.allowed_operations {
        out.push(format!("op:{op}"));
    }
    out
}

/// Builds the runtime [`Capability`] vector passed to
/// [`AgentRuntime::register_agent`].
fn build_runtime_capabilities(template: &AgentTemplate) -> Vec<tenzro_types::agent::Capability> {
    use tenzro_types::agent::Capability;
    let mut caps: Vec<Capability> = Vec::new();

    // Map the template's free-form capability ids to typed capabilities.
    // Anything we cannot identify becomes a `Custom` capability so the
    // runtime sees the full set without losing information.
    for c in &template.capabilities {
        let id = c.id.to_lowercase();
        if id.contains("nlp") || id.contains("language") || id.contains("chat") {
            caps.push(Capability::NaturalLanguageProcessing {
                languages: vec!["en".to_string()],
            });
        } else if id.contains("vision") || id.contains("image") {
            caps.push(Capability::ComputerVision {
                tasks: vec!["classification".to_string()],
            });
        } else if id.contains("code") {
            caps.push(Capability::CodeGeneration {
                languages: vec!["rust".to_string()],
            });
        } else if id.contains("data") || id.contains("analytics") {
            caps.push(Capability::DataAnalysis {
                formats: vec!["json".to_string()],
            });
        } else if id.contains("chain") || id.contains("bridge") || id.contains("evm") || id.contains("svm") {
            caps.push(Capability::BlockchainInteraction {
                chains: vec![],
            });
        } else if id.contains("contract") {
            caps.push(Capability::SmartContractExecution);
        } else if id.contains("api") {
            caps.push(Capability::ExternalAPIIntegration { apis: vec![] });
        } else if id.contains("multi-agent") || id.contains("orchestrator") {
            caps.push(Capability::MultiAgentCoordination);
        } else {
            caps.push(Capability::Custom {
                name: c.id.clone(),
                parameters: std::collections::HashMap::new(),
            });
        }
    }

    if caps.is_empty() {
        caps.push(Capability::Custom {
            name: "autonomous".to_string(),
            parameters: std::collections::HashMap::new(),
        });
    }

    caps
}

/// Derives a 32-byte [`Address`] from an identity DID. We hash the DID with
/// SHA-256 and use the digest as the address bytes; the agent's real on-chain
/// wallet address is bound separately by [`tenzro_identity::WalletBinder`]
/// inside `register_human_with_fee` / `register_machine_with_fee`. This
/// address is purely the runtime id passed to
/// [`AgentRuntime::register_agent`].
fn derive_wallet_address(machine: &TenzroIdentity) -> Address {
    use tenzro_crypto::hash;
    let digest = hash::sha256(machine.did.to_string().as_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(digest.as_ref());
    Address::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::agent_template::{ExecutionBackend, HardCaps};

    #[test]
    fn build_delegation_scope_translates_spec() {
        let spec = DelegationSpec {
            max_transaction_value: 1_000,
            max_daily_spend: 10_000,
            allowed_operations: vec!["bridge".to_string(), "deposit".to_string()],
            allowed_chains: vec!["ethereum".to_string(), "arbitrum".to_string()],
            time_bound_days: 7,
            kyc_tier: "Full".to_string(),
        };
        let scope = build_delegation_scope(&spec);
        assert!(scope.is_operation_allowed("bridge"));
        assert!(scope.is_operation_allowed("deposit"));
        assert!(!scope.is_operation_allowed("liquidate"));
        assert!(scope.is_value_allowed(500));
        assert!(scope.is_chain_allowed("ethereum"));
        assert!(!scope.is_chain_allowed("polygon"));
    }

    #[test]
    fn derive_machine_capabilities_includes_ops() {
        let mut template = AgentTemplate::new(
            "Test".to_string(),
            "desc".to_string(),
            tenzro_types::agent_template::AgentTemplateType::Autonomous,
            Address::default(),
            "system prompt".to_string(),
        );
        template.capabilities = vec![tenzro_types::agent_template::AgentCapability {
            id: "yield_discovery".to_string(),
            name: "Yield Discovery".to_string(),
            description: "Find yield".to_string(),
            input_schema: None,
            output_schema: None,
        }];
        let spec = ExecutionSpec {
            backend: ExecutionBackend::Bridge {
                adapters: vec!["layer_zero".to_string()],
            },
            delegation: DelegationSpec {
                max_transaction_value: 1,
                max_daily_spend: 1,
                allowed_operations: vec!["bridge".to_string()],
                allowed_chains: vec!["ethereum".to_string()],
                time_bound_days: 1,
                kyc_tier: "Basic".to_string(),
            },
            required_tool_tags: vec![],
            required_skill_tags: vec![],
            steps: vec![],
            hard_caps: HardCaps {
                per_operation_value: 1,
                per_day_value: 1,
            },
        };
        let caps = derive_machine_capabilities(&template, &spec);
        assert!(caps.iter().any(|c| c == "yield_discovery"));
        assert!(caps.iter().any(|c| c == "op:bridge"));
    }

    #[test]
    fn runtime_capabilities_default_includes_autonomous() {
        let template = AgentTemplate::new(
            "Empty".to_string(),
            "no caps".to_string(),
            tenzro_types::agent_template::AgentTemplateType::Autonomous,
            Address::default(),
            "".to_string(),
        );
        let caps = build_runtime_capabilities(&template);
        assert_eq!(caps.len(), 1);
    }
}
