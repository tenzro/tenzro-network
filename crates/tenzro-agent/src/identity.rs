//! Agent identity management for Tenzro Network.
//!
//! This module handles registration, tracking, and verification of AI agents
//! on the network. Each agent has a unique identity, associated wallet, and
//! capability set.
//!
//! # Blockchain binding (HIGH #105)
//!
//! Agent identities can **optionally** be bound to a `did:tenzro:machine:`
//! record in the TDIP `IdentityRegistry`. The binding is opt-in because it
//! **costs gas**: TDIP charges a `machine_identity_registration` fee
//! (currently 5 TNZO) for every autonomous machine identity it mints.
//!
//! Two construction paths are supported:
//!
//! 1. **Local-only mode** — `AgentIdentityManager::new()` or
//!    `with_storage_path()`. No registry is attached, no gas is owed, the
//!    agent lives only in this manager's `DashMap` (and optional JSON
//!    storage). This is the path used by unit tests and lightweight CLI
//!    callers.
//! 2. **Blockchain-bound mode** — `with_identity_registry(registry)` followed
//!    by an explicit `gas_policy`. Every call to `register_agent` will then
//!    also call `IdentityRegistry::register_autonomous_machine_with_fee`,
//!    surface the resulting `fee_required` on the returned
//!    `RegisteredAgent.registration_fee`, and link the local `agent_id` to
//!    the new DID via `IdentityRegistry::link_tenzro_agent`. The fee value
//!    is propagated up to the caller (e.g. `AgentRuntime` or the node) so
//!    that gas can actually be deducted at the transaction layer — the
//!    registry itself does NOT collect the fee, it only reports what is
//!    owed (see `IdentityRegistry` docs).
//!
//! ## Gas policy
//!
//! When the registry is attached, the caller must also supply a [`GasPolicy`]
//! that says how much gas the agent creator has authorised for the binding:
//!
//! - [`GasPolicy::PayUpTo(budget)`] — accept the binding only if
//!   `fee_required <= budget`. Otherwise return
//!   [`AgentError::InsufficientGas`] with both numbers so the caller can
//!   surface the gap.
//! - [`GasPolicy::AcceptAny`] — pay whatever the registry asks. Useful for
//!   trusted local nodes that want to absorb the fee unconditionally.
//!
//! The fee is **not** debited by this module — collection happens at the
//! node/transaction level. This module only enforces the gas budget and
//! records the fee on `RegisteredAgent.registration_fee` for downstream
//! collection.

use crate::error::{AgentError, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::path::{Path, PathBuf};
use tenzro_crypto::hash::sha256;
use tenzro_identity::registry::IdentityRegistry;
use tenzro_types::{agent::Capability, primitives::Address, AgentIdentity};
use tenzro_wallet::WalletProvisioner;
use tracing::{debug, info, warn};

/// Status of an agent on the network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    /// Agent is active and operational
    Active,
    /// Agent is temporarily suspended
    Suspended,
    /// Agent is permanently terminated
    Terminated,
}

/// Gas budget policy for blockchain-bound agent registration (HIGH #105).
///
/// When the manager is attached to a TDIP `IdentityRegistry`, every
/// `register_agent` call mints a `did:tenzro:machine:` record and incurs the
/// `machine_identity_registration` fee (currently 5 TNZO). The caller must
/// state up-front how much gas it has authorised for that fee:
///
/// - [`GasPolicy::PayUpTo(budget)`] — accept the registration only if
///   `fee_required <= budget`. Otherwise return [`AgentError::InsufficientGas`].
/// - [`GasPolicy::AcceptAny`] — accept whatever the registry asks. Useful
///   for trusted local nodes / tests / operators that absorb the fee.
///
/// The fee itself is **not** deducted by this module — collection happens at
/// the node/transaction level. This policy only gates whether the binding is
/// allowed to proceed and surfaces the resulting fee to the caller via
/// `RegisteredAgent.registration_fee`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum GasPolicy {
    /// Pay any fee the registry asks for. The actual fee will be reported on
    /// `RegisteredAgent.registration_fee` for downstream collection.
    #[default]
    AcceptAny,
    /// Only proceed if `fee_required <= budget`. Returns
    /// [`AgentError::InsufficientGas`] otherwise.
    PayUpTo(u128),
}

impl GasPolicy {
    /// Returns true if the supplied registry-quoted fee is allowed under this
    /// gas policy.
    pub fn allows(&self, fee_required: u128) -> bool {
        match self {
            GasPolicy::AcceptAny => true,
            GasPolicy::PayUpTo(budget) => fee_required <= *budget,
        }
    }

    /// Returns the configured budget if any, or `None` for `AcceptAny`.
    pub fn budget(&self) -> Option<u128> {
        match self {
            GasPolicy::AcceptAny => None,
            GasPolicy::PayUpTo(b) => Some(*b),
        }
    }
}


impl AgentStatus {
    /// Returns the status as a string
    pub fn as_str(&self) -> &str {
        match self {
            AgentStatus::Active => "active",
            AgentStatus::Suspended => "suspended",
            AgentStatus::Terminated => "terminated",
        }
    }
}

/// A registered agent on the Tenzro Network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredAgent {
    /// Agent's identity
    pub identity: AgentIdentity,
    /// Associated wallet address
    pub wallet_address: Address,
    /// Agent's capabilities
    pub capabilities: Vec<Capability>,
    /// Whether the agent is TEE-backed
    pub tee_backed: bool,
    /// Registration timestamp
    pub created_at: DateTime<Utc>,
    /// Current status
    pub status: AgentStatus,
    /// Reputation score (0-100)
    pub reputation_score: u8,
    /// Associated wallet ID
    pub wallet_id: String,
    /// Canonical TDIP DID for this agent (HIGH #105). When the manager is
    /// constructed without an `IdentityRegistry` this is `None` and the
    /// agent is local-only; otherwise it carries the `did:tenzro:machine:`
    /// string returned by the registry.
    #[serde(default)]
    pub tenzro_did: Option<String>,
    /// Gas/fee owed to TDIP for the blockchain binding (HIGH #105), in
    /// smallest TNZO unit. `0` for local-only agents (no binding requested),
    /// otherwise the `fee_required` reported by
    /// `IdentityRegistry::register_autonomous_machine_with_fee` (currently
    /// 5 TNZO = `5_000_000_000_000_000_000`). The actual deduction is
    /// performed by the node/transaction layer; this field exists so that
    /// callers can surface the cost and collect it.
    #[serde(default)]
    pub registration_fee: u128,
}

/// Maps a typed `Capability` enum to a stable string label suitable for the
/// TDIP `IdentityRegistry`. TDIP records capabilities as opaque strings, so
/// we just need a deterministic conversion that preserves the variant name
/// and any obvious payload (like the language list for NLP).
fn capability_label(cap: &Capability) -> String {
    match cap {
        Capability::NaturalLanguageProcessing { languages } => {
            format!("nlp:{}", languages.join(","))
        }
        Capability::ComputerVision { tasks } => {
            format!("cv:{}", tasks.join(","))
        }
        Capability::CodeGeneration { languages } => {
            format!("codegen:{}", languages.join(","))
        }
        Capability::DataAnalysis { formats } => {
            format!("data:{}", formats.join(","))
        }
        Capability::BlockchainInteraction { chains } => {
            format!("chain:{}", chains.join(","))
        }
        Capability::SmartContractExecution => "smart-contract".to_string(),
        Capability::ExternalAPIIntegration { apis } => {
            format!("api:{}", apis.join(","))
        }
        Capability::MultiAgentCoordination => "multi-agent".to_string(),
        Capability::Custom { name, .. } => format!("custom:{}", name),
    }
}

impl RegisteredAgent {
    /// Creates a new registered agent
    pub fn new(
        identity: AgentIdentity,
        wallet_address: Address,
        wallet_id: String,
        capabilities: Vec<Capability>,
        tee_backed: bool,
    ) -> Self {
        Self {
            identity,
            wallet_address,
            wallet_id,
            capabilities,
            tee_backed,
            created_at: Utc::now(),
            status: AgentStatus::Active,
            reputation_score: 50, // Start with neutral reputation
            tenzro_did: None,
            registration_fee: 0,
        }
    }

    /// Returns the canonical TDIP DID for this agent, if one was registered.
    pub fn tenzro_did(&self) -> Option<&str> {
        self.tenzro_did.as_deref()
    }

    /// Returns true if this agent is bound to a `did:tenzro:machine:` record
    /// in TDIP. Equivalent to `self.tenzro_did.is_some()`.
    pub fn is_blockchain_bound(&self) -> bool {
        self.tenzro_did.is_some()
    }

    /// Returns the gas/fee owed to TDIP for the blockchain binding, in
    /// smallest TNZO unit. `0` for local-only agents.
    pub fn registration_fee(&self) -> u128 {
        self.registration_fee
    }

    /// Checks if the agent has a specific capability
    pub fn has_capability(&self, capability: &Capability) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }

    /// Updates the reputation score
    pub fn update_reputation(&mut self, delta: i8) {
        let new_score = (self.reputation_score as i16 + delta as i16).clamp(0, 100) as u8;
        self.reputation_score = new_score;
    }

    /// Checks if the agent is active
    pub fn is_active(&self) -> bool {
        self.status == AgentStatus::Active
    }
}

/// Manages agent identities on the network
pub struct AgentIdentityManager {
    /// Registered agents indexed by agent_id
    agents: Arc<DashMap<String, RegisteredAgent>>,
    /// Wallet provisioner for creating agent wallets
    wallet_provisioner: Arc<WalletProvisioner>,
    /// Storage path for persisting identities
    storage_path: Option<PathBuf>,
    /// Optional TDIP identity registry for blockchain-anchored agent identities (HIGH #105).
    ///
    /// When set, every `register_agent` call also calls
    /// `IdentityRegistry::register_autonomous_machine_with_fee` to mint a
    /// `did:tenzro:machine:` record (which **costs gas**) and links the local
    /// agent_id to it via `IdentityRegistry::link_tenzro_agent`. This makes
    /// agent identities resolvable, revocable, and persistent through the
    /// standard TDIP code path (RocksDB-backed when the registry is itself
    /// constructed with storage). When `None`, the manager retains its
    /// legacy local-only behaviour for backwards compatibility with tests and
    /// lightweight callers.
    identity_registry: Option<Arc<IdentityRegistry>>,
    /// Default gas policy for blockchain-bound registrations (HIGH #105).
    ///
    /// Only consulted when `identity_registry` is `Some`. Defaults to
    /// `GasPolicy::AcceptAny` so a node attaching a registry without
    /// specifying a budget pays whatever the registry asks. Callers that
    /// need per-registration control can override via
    /// `register_agent_with_gas_policy`.
    gas_policy: GasPolicy,
}

impl AgentIdentityManager {
    /// Creates a new agent identity manager
    pub fn new() -> Result<Self> {
        let wallet_provisioner = WalletProvisioner::new();

        Ok(Self {
            agents: Arc::new(DashMap::new()),
            wallet_provisioner: Arc::new(wallet_provisioner),
            storage_path: None,
            identity_registry: None,
            gas_policy: GasPolicy::AcceptAny,
        })
    }

    /// Creates a new agent identity manager with persistent storage
    pub fn with_storage_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let wallet_provisioner = WalletProvisioner::new();
        let storage_path = path.as_ref().to_path_buf();

        // Create storage directory if it doesn't exist
        if let Some(parent) = storage_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AgentError::StorageError(format!("Failed to create storage directory: {}", e)))?;
        }

        Ok(Self {
            agents: Arc::new(DashMap::new()),
            wallet_provisioner: Arc::new(wallet_provisioner),
            storage_path: Some(storage_path),
            identity_registry: None,
            gas_policy: GasPolicy::AcceptAny,
        })
    }

    /// Attaches a TDIP identity registry for blockchain-anchored agent
    /// identities (HIGH #105).
    ///
    /// When this is set, subsequent calls to `register_agent` will also
    /// register the agent in the TDIP registry as an autonomous machine via
    /// `register_autonomous_machine_with_fee` (which **costs gas**) and link
    /// the local agent_id to the resulting DID. The returned
    /// `RegisteredAgent` carries the canonical DID in `tenzro_did` and the
    /// fee owed in `registration_fee`.
    ///
    /// This call alone uses [`GasPolicy::AcceptAny`] as the default gas
    /// budget — meaning the manager pays whatever the registry quotes. To
    /// cap the budget, chain `with_gas_policy(GasPolicy::PayUpTo(...))` or
    /// use `register_agent_with_gas_policy` for per-call control.
    pub fn with_identity_registry(mut self, registry: Arc<IdentityRegistry>) -> Self {
        self.identity_registry = Some(registry);
        self
    }

    /// Sets the default gas policy used when blockchain binding is enabled
    /// (HIGH #105). Has no effect unless an `IdentityRegistry` has been
    /// attached via `with_identity_registry`. Returns `self` for chaining.
    pub fn with_gas_policy(mut self, policy: GasPolicy) -> Self {
        self.gas_policy = policy;
        self
    }

    /// Returns a reference to the attached identity registry, if any.
    pub fn identity_registry(&self) -> Option<&Arc<IdentityRegistry>> {
        self.identity_registry.as_ref()
    }

    /// Returns the current default gas policy. Only applies when
    /// `identity_registry()` returns `Some`.
    pub fn gas_policy(&self) -> GasPolicy {
        self.gas_policy
    }

    /// Generates a deterministic agent ID from owner address and nonce
    fn generate_agent_id(owner: &Address, nonce: u64) -> String {
        let data = format!("{}:{}", owner, nonce);
        let hash = sha256(data.as_bytes());
        hex::encode(&hash.as_bytes()[0..16]) // Use first 16 bytes
    }

    /// Registers a new agent on the network using the manager's default
    /// gas policy (HIGH #105).
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable agent name
    /// * `creator` - Address of the agent creator/owner
    /// * `capabilities` - List of agent capabilities
    /// * `tee_backed` - Whether the agent runs in a TEE
    /// * `nonce` - Nonce for deterministic ID generation
    ///
    /// # Blockchain binding (HIGH #105)
    ///
    /// If this manager was constructed with `with_identity_registry`, the
    /// agent is also registered in the TDIP `IdentityRegistry` as an
    /// autonomous machine via `register_autonomous_machine_with_fee`. **This
    /// costs gas** — the registry quotes a `fee_required` (currently 5 TNZO
    /// in smallest unit) and the manager checks it against the configured
    /// `gas_policy`:
    ///
    /// - With [`GasPolicy::AcceptAny`] (the default), any quoted fee is
    ///   accepted and recorded on `RegisteredAgent.registration_fee` for
    ///   the caller to collect at the transaction layer.
    /// - With [`GasPolicy::PayUpTo(budget)`], the call returns
    ///   [`AgentError::InsufficientGas`] if `fee_required > budget`, and
    ///   the local agent registration is **not** persisted.
    ///
    /// On any TDIP failure (invalid pubkey, registry rejection, link
    /// failure, etc.) the local registration is rolled back via
    /// [`AgentError::BlockchainBindingFailed`] so the manager is never left
    /// in an inconsistent half-bound state.
    ///
    /// To override the gas policy on a per-call basis, use
    /// [`Self::register_agent_with_gas_policy`].
    pub async fn register_agent(
        &self,
        name: String,
        creator: Address,
        capabilities: Vec<Capability>,
        tee_backed: bool,
        nonce: u64,
    ) -> Result<RegisteredAgent> {
        self.register_agent_with_gas_policy(
            name,
            creator,
            capabilities,
            tee_backed,
            nonce,
            self.gas_policy,
        )
        .await
    }

    /// Registers a new agent on the network with an explicit gas policy
    /// for the optional blockchain binding (HIGH #105).
    ///
    /// This is the primary entry point when the caller (e.g. `AgentRuntime`
    /// or the node's RPC layer) wants per-call gas control. Behaves the same
    /// as [`Self::register_agent`] except that the supplied `gas_policy`
    /// overrides the manager's default.
    ///
    /// When `identity_registry` is `None` the gas policy is ignored — local
    /// registrations never owe gas.
    pub async fn register_agent_with_gas_policy(
        &self,
        name: String,
        creator: Address,
        capabilities: Vec<Capability>,
        tee_backed: bool,
        nonce: u64,
        gas_policy: GasPolicy,
    ) -> Result<RegisteredAgent> {
        // Generate deterministic agent ID
        let agent_id = Self::generate_agent_id(&creator, nonce);

        // Check if agent already exists
        if self.agents.contains_key(&agent_id) {
            return Err(AgentError::AgentAlreadyExists(agent_id));
        }

        debug!("Registering agent {} with ID {}", name, agent_id);

        // Provision an MPC wallet for the agent
        let wallet = self
            .wallet_provisioner
            .provision_wallet()
            .map_err(|e| AgentError::WalletError(e.to_string()))?;

        let wallet_address = wallet.address;
        let wallet_id = wallet.wallet_id.clone();

        // Create agent identity
        let identity = AgentIdentity::new(agent_id.clone(), wallet_address, name.clone(), creator);

        // Create registered agent
        let mut agent = RegisteredAgent::new(
            identity,
            wallet_address,
            wallet_id.to_string(),
            capabilities.clone(),
            tee_backed,
        );

        // HIGH #105: Bind to TDIP IdentityRegistry if configured. This mints a
        // `did:tenzro:machine:` record that other nodes can resolve and that
        // is persisted by the registry's storage backend (when present). The
        // binding **costs gas**: we use the fee-aware variant of the registry
        // and validate the quoted fee against `gas_policy` before storing the
        // local agent record.
        if let Some(ref registry) = self.identity_registry {
            // Use the wallet's public key bytes as the identity's public key.
            // The wallet provisioner returns a real key, so this binds the
            // TDIP record to the same key material that signs transactions.
            let public_key = wallet_address.as_bytes().to_vec();

            // Convert typed agent capabilities to string labels for TDIP.
            let cap_strings: Vec<String> = capabilities
                .iter()
                .map(capability_label)
                .collect();

            // Agents in this manager are autonomous from TDIP's perspective:
            // they have a creator Address but not a controlling DID. Use the
            // fee-aware variant so we get the registration fee back for the
            // caller to collect at the transaction layer.
            let registration = registry
                .register_autonomous_machine_with_fee(public_key, cap_strings)
                .await
                .map_err(|e| AgentError::BlockchainBindingFailed(format!(
                    "TDIP registration failed for agent {}: {}",
                    agent_id, e
                )))?;

            let fee_required = registration.fee_required;
            let machine_identity = registration.identity;

            // Gas policy enforcement. Even with `AcceptAny` we record the
            // fee so callers can deduct it; with `PayUpTo` we reject the
            // binding when the quoted fee exceeds the supplied budget.
            if !gas_policy.allows(fee_required) {
                let supplied = gas_policy.budget().unwrap_or(0);
                warn!(
                    "Refusing to bind agent {} to TDIP DID {}: fee {} > budget {}",
                    agent_id,
                    machine_identity.did_string(),
                    fee_required,
                    supplied
                );
                return Err(AgentError::InsufficientGas {
                    required: fee_required,
                    supplied,
                });
            }

            let machine_did = machine_identity.did_string();

            // Link the local agent_id to the TDIP DID so the registry can map
            // either way (DID -> agent, agent -> DID). A link failure does not
            // unwind the registration — the DID is still valid — but it is
            // surfaced to the caller as a binding failure so they know the
            // bidirectional mapping is broken.
            if let Err(e) = registry.link_tenzro_agent(&machine_did, agent_id.clone()) {
                return Err(AgentError::BlockchainBindingFailed(format!(
                    "Failed to link agent {} to TDIP DID {}: {}",
                    agent_id, machine_did, e
                )));
            }

            agent.tenzro_did = Some(machine_did.clone());
            agent.registration_fee = fee_required;
            info!(
                "Agent {} bound to TDIP DID {} (wallet {}, fee {} smallest TNZO)",
                agent_id, machine_did, wallet_id, fee_required
            );
        } else {
            debug!(
                "Agent {} registered without TDIP binding (local-only mode, no gas owed)",
                agent_id
            );
        }

        // Store the agent
        self.agents.insert(agent_id.clone(), agent.clone());

        info!(
            "Agent {} registered successfully with wallet {}",
            agent_id, wallet_id
        );

        Ok(agent)
    }

    /// Inserts a pre-existing `RegisteredAgent` directly into the in-memory
    /// map without provisioning a new wallet or calling into the TDIP
    /// registry.
    ///
    /// This is the rehydration entry point used when a node boots and reads
    /// previously persisted agents from RocksDB (CF_AGENTS). The agent's
    /// wallet, DID, and registration fee are already baked into the
    /// serialized record, so we must NOT re-invoke
    /// `WalletProvisioner::provision_wallet()` (which would mint a brand-new
    /// wallet, breaking on-chain continuity) nor
    /// `IdentityRegistry::register_autonomous_machine_with_fee` (which would
    /// charge gas a second time for the same agent).
    ///
    /// Returns `AgentAlreadyExists` if the agent_id is already present, so
    /// callers can safely call this idempotently across restarts.
    pub fn insert_hydrated(&self, agent: RegisteredAgent) -> Result<()> {
        let agent_id = agent.identity.agent_id.clone();
        if self.agents.contains_key(&agent_id) {
            return Err(AgentError::AgentAlreadyExists(agent_id));
        }
        self.agents.insert(agent_id, agent);
        Ok(())
    }

    /// Retrieves an agent by ID
    pub fn get_agent(&self, agent_id: &str) -> Result<RegisteredAgent> {
        self.agents
            .get(agent_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))
    }

    /// Updates an existing agent
    pub fn update_agent(&self, agent_id: &str, update_fn: impl FnOnce(&mut RegisteredAgent)) -> Result<()> {
        self.agents
            .get_mut(agent_id)
            .map(|mut entry| update_fn(entry.value_mut()))
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))
    }

    /// Deactivates an agent (sets status to Terminated)
    pub fn deactivate_agent(&self, agent_id: &str) -> Result<()> {
        self.update_agent(agent_id, |agent| {
            agent.status = AgentStatus::Terminated;
        })?;

        info!("Agent {} deactivated", agent_id);
        Ok(())
    }

    /// Suspends an agent
    pub fn suspend_agent(&self, agent_id: &str) -> Result<()> {
        self.update_agent(agent_id, |agent| {
            agent.status = AgentStatus::Suspended;
        })?;

        info!("Agent {} suspended", agent_id);
        Ok(())
    }

    /// Reactivates a suspended agent
    pub fn reactivate_agent(&self, agent_id: &str) -> Result<()> {
        let agent = self.get_agent(agent_id)?;

        if agent.status == AgentStatus::Terminated {
            return Err(AgentError::LifecycleError(
                "Cannot reactivate a terminated agent".to_string(),
            ));
        }

        self.update_agent(agent_id, |agent| {
            agent.status = AgentStatus::Active;
        })?;

        info!("Agent {} reactivated", agent_id);
        Ok(())
    }

    /// Lists all agents with optional status filter
    pub fn list_agents(&self, status_filter: Option<AgentStatus>) -> Vec<RegisteredAgent> {
        self.agents
            .iter()
            .filter(|entry| {
                status_filter
                    .map(|status| entry.value().status == status)
                    .unwrap_or(true)
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Verifies an agent's identity
    ///
    /// Checks that the agent exists and matches expected parameters
    pub fn verify_agent_identity(&self, agent_id: &str, expected_creator: &Address) -> Result<bool> {
        let agent = self.get_agent(agent_id)?;
        Ok(agent.identity.creator == *expected_creator && agent.is_active())
    }

    /// Gets the total number of registered agents
    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    /// Gets the number of active agents
    pub fn active_agent_count(&self) -> usize {
        self.agents
            .iter()
            .filter(|entry| entry.value().is_active())
            .count()
    }

    /// Adds a capability to an agent
    pub fn add_capability(&self, agent_id: &str, capability: Capability) -> Result<()> {
        self.update_agent(agent_id, |agent| {
            if !agent.has_capability(&capability) {
                agent.capabilities.push(capability);
            }
        })
    }

    /// Removes a capability from an agent
    pub fn remove_capability(&self, agent_id: &str, capability: &Capability) -> Result<()> {
        self.update_agent(agent_id, |agent| {
            agent.capabilities.retain(|c| c != capability);
        })
    }

    /// Saves an agent identity to persistent storage
    pub fn save_identity(&self, agent_id: &str) -> Result<()> {
        let storage_path = self
            .storage_path
            .as_ref()
            .ok_or_else(|| AgentError::StorageError("No storage path configured".to_string()))?;

        let agent = self.get_agent(agent_id)?;

        // Serialize agent to JSON
        let json = serde_json::to_string_pretty(&agent)
            .map_err(|e| AgentError::StorageError(format!("Serialization failed: {}", e)))?;

        // Write to file
        let file_path = storage_path.join(format!("{}.json", agent_id));
        std::fs::write(&file_path, json)
            .map_err(|e| AgentError::StorageError(format!("Failed to write file: {}", e)))?;

        info!("Saved identity for agent {} to {:?}", agent_id, file_path);
        Ok(())
    }

    /// Loads an agent identity from persistent storage
    pub fn load_identity(&self, agent_id: &str) -> Result<RegisteredAgent> {
        let storage_path = self
            .storage_path
            .as_ref()
            .ok_or_else(|| AgentError::StorageError("No storage path configured".to_string()))?;

        let file_path = storage_path.join(format!("{}.json", agent_id));

        // Read file
        let json = std::fs::read_to_string(&file_path)
            .map_err(|e| AgentError::StorageError(format!("Failed to read file: {}", e)))?;

        // Deserialize
        let agent: RegisteredAgent = serde_json::from_str(&json)
            .map_err(|e| AgentError::StorageError(format!("Deserialization failed: {}", e)))?;

        // Store in memory
        self.agents.insert(agent_id.to_string(), agent.clone());

        info!("Loaded identity for agent {} from {:?}", agent_id, file_path);
        Ok(agent)
    }

    /// Lists all saved agent identities from persistent storage
    pub fn list_identities(&self) -> Result<Vec<String>> {
        let storage_path = self
            .storage_path
            .as_ref()
            .ok_or_else(|| AgentError::StorageError("No storage path configured".to_string()))?;

        let mut identities = Vec::new();

        // Check if directory exists
        if !storage_path.exists() {
            return Ok(identities);
        }

        // Read directory
        let entries = std::fs::read_dir(storage_path)
            .map_err(|e| AgentError::StorageError(format!("Failed to read directory: {}", e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| AgentError::StorageError(format!("Failed to read entry: {}", e)))?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    identities.push(stem.to_string());
                }
            }
        }

        Ok(identities)
    }

    /// Loads all identities from persistent storage
    pub fn load_all_identities(&self) -> Result<Vec<RegisteredAgent>> {
        let agent_ids = self.list_identities()?;
        let mut agents = Vec::new();

        for agent_id in agent_ids {
            match self.load_identity(&agent_id) {
                Ok(agent) => agents.push(agent),
                Err(e) => {
                    warn!("Failed to load identity {}: {}", agent_id, e);
                }
            }
        }

        Ok(agents)
    }
}

impl Default for AgentIdentityManager {
    fn default() -> Self {
        Self::new().expect("Failed to create AgentIdentityManager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::primitives::Address;

    #[tokio::test]
    async fn test_agent_registration() {
        let manager = AgentIdentityManager::new().unwrap();
        let creator = Address::from([1u8; 32]);
        let capabilities = vec![Capability::MultiAgentCoordination];

        let agent = manager
            .register_agent("TestAgent".to_string(), creator, capabilities, false, 0)
            .await
            .unwrap();

        assert_eq!(agent.identity.name, "TestAgent");
        assert_eq!(agent.status, AgentStatus::Active);
        assert_eq!(agent.reputation_score, 50);
    }

    #[tokio::test]
    async fn test_duplicate_registration() {
        let manager = AgentIdentityManager::new().unwrap();
        let creator = Address::from([1u8; 32]);
        let capabilities = vec![Capability::MultiAgentCoordination];

        manager
            .register_agent("Agent1".to_string(), creator, capabilities.clone(), false, 0)
            .await
            .unwrap();

        let result = manager
            .register_agent("Agent2".to_string(), creator, capabilities, false, 0)
            .await;

        assert!(matches!(result, Err(AgentError::AgentAlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_agent_lifecycle() {
        let manager = AgentIdentityManager::new().unwrap();
        let creator = Address::from([1u8; 32]);

        let agent = manager
            .register_agent("Agent".to_string(), creator, vec![], false, 0)
            .await
            .unwrap();

        let agent_id = &agent.identity.agent_id;

        // Suspend
        manager.suspend_agent(agent_id).unwrap();
        let agent = manager.get_agent(agent_id).unwrap();
        assert_eq!(agent.status, AgentStatus::Suspended);

        // Reactivate
        manager.reactivate_agent(agent_id).unwrap();
        let agent = manager.get_agent(agent_id).unwrap();
        assert_eq!(agent.status, AgentStatus::Active);

        // Deactivate
        manager.deactivate_agent(agent_id).unwrap();
        let agent = manager.get_agent(agent_id).unwrap();
        assert_eq!(agent.status, AgentStatus::Terminated);

        // Cannot reactivate terminated agent
        let result = manager.reactivate_agent(agent_id);
        assert!(matches!(result, Err(AgentError::LifecycleError(_))));
    }

    // ---------------- HIGH #105: blockchain binding tests ----------------

    #[tokio::test]
    async fn test_local_only_mode_does_not_owe_gas() {
        // No identity registry attached → no DID, no fee.
        let manager = AgentIdentityManager::new().unwrap();
        let creator = Address::from([7u8; 32]);

        let agent = manager
            .register_agent(
                "LocalAgent".to_string(),
                creator,
                vec![Capability::MultiAgentCoordination],
                false,
                0,
            )
            .await
            .unwrap();

        assert!(agent.tenzro_did.is_none(), "local-only agent must not have a DID");
        assert!(!agent.is_blockchain_bound());
        assert_eq!(
            agent.registration_fee, 0,
            "local-only agents owe zero gas"
        );
    }

    #[tokio::test]
    async fn test_blockchain_bound_mode_surfaces_gas_fee() {
        // Attach a real TDIP registry → fee should be reported on the agent.
        let registry = Arc::new(IdentityRegistry::new());
        let manager = AgentIdentityManager::new()
            .unwrap()
            .with_identity_registry(registry.clone());

        let creator = Address::from([8u8; 32]);
        let agent = manager
            .register_agent(
                "BoundAgent".to_string(),
                creator,
                vec![Capability::MultiAgentCoordination],
                false,
                0,
            )
            .await
            .unwrap();

        assert!(
            agent.is_blockchain_bound(),
            "registry-attached agent must be blockchain-bound"
        );
        let did = agent.tenzro_did().expect("DID must be set");
        assert!(
            did.starts_with("did:tenzro:machine:"),
            "DID should be a tenzro machine DID, got: {}",
            did
        );
        assert!(
            agent.registration_fee > 0,
            "blockchain-bound registration must surface a non-zero gas fee, got {}",
            agent.registration_fee
        );

        // The DID must be resolvable in the registry → confirms the binding
        // actually wrote to TDIP rather than just decorating the local agent.
        assert!(registry.resolve(did).is_ok());
    }

    #[tokio::test]
    async fn test_gas_policy_pay_up_to_rejects_oversized_fee() {
        // Budget of 1 wei is far below the registry fee (5 TNZO) → must
        // reject with `InsufficientGas` and refuse to persist the agent.
        let registry = Arc::new(IdentityRegistry::new());
        let manager = AgentIdentityManager::new()
            .unwrap()
            .with_identity_registry(registry)
            .with_gas_policy(GasPolicy::PayUpTo(1));

        let creator = Address::from([9u8; 32]);
        let result = manager
            .register_agent(
                "BrokeAgent".to_string(),
                creator,
                vec![Capability::SmartContractExecution],
                false,
                0,
            )
            .await;

        match result {
            Err(AgentError::InsufficientGas { required, supplied }) => {
                assert!(required > supplied, "required {} should exceed supplied {}", required, supplied);
                assert_eq!(supplied, 1);
            }
            other => panic!("expected InsufficientGas, got {:?}", other),
        }

        // Local agent table must NOT contain the rejected registration.
        assert_eq!(
            manager.agent_count(),
            0,
            "rejected registrations must not be persisted locally"
        );
    }

    #[tokio::test]
    async fn test_gas_policy_pay_up_to_accepts_sufficient_budget() {
        // Generous budget (1000 TNZO) covers the 5 TNZO registration fee.
        let registry = Arc::new(IdentityRegistry::new());
        let big_budget: u128 = 1_000 * 1_000_000_000_000_000_000;
        let manager = AgentIdentityManager::new()
            .unwrap()
            .with_identity_registry(registry)
            .with_gas_policy(GasPolicy::PayUpTo(big_budget));

        let creator = Address::from([10u8; 32]);
        let agent = manager
            .register_agent_with_gas_policy(
                "RichAgent".to_string(),
                creator,
                vec![],
                false,
                0,
                GasPolicy::PayUpTo(big_budget),
            )
            .await
            .unwrap();

        assert!(agent.is_blockchain_bound());
        assert!(agent.registration_fee > 0);
        assert!(agent.registration_fee <= big_budget);
    }

    #[tokio::test]
    async fn test_per_call_gas_policy_overrides_default() {
        // Manager default = AcceptAny, but per-call PayUpTo(1) should be
        // honoured and reject the binding.
        let registry = Arc::new(IdentityRegistry::new());
        let manager = AgentIdentityManager::new()
            .unwrap()
            .with_identity_registry(registry);
        // No `with_gas_policy` → defaults to AcceptAny.

        let creator = Address::from([11u8; 32]);
        let result = manager
            .register_agent_with_gas_policy(
                "PerCallAgent".to_string(),
                creator,
                vec![],
                false,
                0,
                GasPolicy::PayUpTo(1),
            )
            .await;

        assert!(matches!(result, Err(AgentError::InsufficientGas { .. })));
    }

    #[test]
    fn test_gas_policy_allows() {
        assert!(GasPolicy::AcceptAny.allows(u128::MAX));
        assert!(GasPolicy::AcceptAny.allows(0));
        assert!(GasPolicy::PayUpTo(100).allows(50));
        assert!(GasPolicy::PayUpTo(100).allows(100));
        assert!(!GasPolicy::PayUpTo(100).allows(101));
        assert_eq!(GasPolicy::AcceptAny.budget(), None);
        assert_eq!(GasPolicy::PayUpTo(42).budget(), Some(42));
    }

    #[test]
    fn test_capability_label_conversion() {
        assert_eq!(
            capability_label(&Capability::SmartContractExecution),
            "smart-contract"
        );
        assert_eq!(
            capability_label(&Capability::MultiAgentCoordination),
            "multi-agent"
        );
        assert_eq!(
            capability_label(&Capability::NaturalLanguageProcessing {
                languages: vec!["en".to_string(), "es".to_string()],
            }),
            "nlp:en,es"
        );
        assert_eq!(
            capability_label(&Capability::Custom {
                name: "weather".to_string(),
                parameters: std::collections::HashMap::new(),
            }),
            "custom:weather"
        );
    }
}
