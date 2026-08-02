//! Agent runtime environment for Tenzro Network.
//!
//! This module provides the main runtime that ties together all agent
//! subsystems: identity, lifecycle, messaging, capabilities, and protocol
//! handling.

use crate::{
    a2a_protocol::A2aProtocol,
    autonomy::SpendingPolicy,
    capabilities::CapabilityRegistry,
    error::{AgentError, Result},
    identity::{AgentIdentityManager, AgentStatus, RegisteredAgent},
    lifecycle::{
        AgentLifecycle, AgentLifecycleEvent, AgentLifecycleInfo, AgentState, HeartbeatConfig,
    },
    messaging::{AgentVerifyingKeys, MessageRouter},
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::kv::{CF_AGENTS, KvStore};
use tenzro_types::{
    AgentIdentity, AgentMessage, AgentMessageType,
    agent::{Capability, ResourceLimits},
    primitives::Address,
};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Storage key prefix for persisted `RegisteredAgent` records in CF_AGENTS.
const AGENT_KEY_PREFIX: &[u8] = b"agent:";
/// Storage key prefix for persisted `AgentLifecycleInfo` records in CF_AGENTS.
const LIFECYCLE_KEY_PREFIX: &[u8] = b"lifecycle:";
/// Storage key prefix for persisted parent → children mappings in CF_AGENTS.
const CHILDREN_KEY_PREFIX: &[u8] = b"children:";
/// Storage key prefix for persisted `AgentTransactionRecord`s in CF_AGENTS.
///
/// Layout: `agenttx:<machine_did>:<seq_be_u64>` where `seq_be_u64` is a
/// big-endian-encoded monotonically-increasing per-DID counter so prefix
/// scans return records in chronological order. The 8-byte BE encoding
/// keeps the iterator lexicographic-ordered without padding the DID.
const AGENT_TX_KEY_PREFIX: &[u8] = b"agenttx:";

/// Per-agent record of a successful service payment. Persisted under
/// `agenttx:<machine_did>:<seq_be_u64>` in CF_AGENTS so the wallet kernel
/// can render audit history across restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTransactionRecord {
    /// Machine DID that initiated the payment (canonical
    /// `did:tenzro:machine:...` form, matches `payer_did` on the payment gate).
    pub agent_did: String,
    /// Provider counterparty (provider DID, hex address, or service URL —
    /// whatever the caller passed; the runtime is opaque).
    pub provider: String,
    /// Service category label (e.g. "inference", "tee", "settlement",
    /// "model-download"). Free-form so callers can categorize as needed.
    pub service_type: String,
    /// Settled amount in smallest TNZO unit.
    pub amount: u64,
    /// Unix-seconds timestamp when the payment cleared.
    pub timestamp: i64,
    /// Receipt or session identifier returned by the payment gateway.
    /// Empty string for protocols that don't surface one.
    pub receipt_id: String,
}

/// Configuration for the agent runtime
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRuntimeConfig {
    /// Maximum number of concurrent agents
    pub max_agents: usize,
    /// Enable TEE verification
    pub enable_tee_verification: bool,
    /// Heartbeat interval in seconds
    pub heartbeat_interval: u64,
    /// Maximum message queue size per agent
    pub max_message_queue_size: usize,
    /// Default resource limits
    pub default_resource_limits: ResourceLimits,
}

impl Default for AgentRuntimeConfig {
    fn default() -> Self {
        Self {
            max_agents: 10000,
            enable_tee_verification: false,
            heartbeat_interval: 30,
            max_message_queue_size: 1000,
            default_resource_limits: ResourceLimits::default(),
        }
    }
}

/// Statistics for the agent runtime
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStatistics {
    /// Total number of registered agents
    pub total_agents: usize,
    /// Number of active agents
    pub active_agents: usize,
    /// Number of operationally suspended agents (heartbeat / idle TTL)
    pub suspended_agents: usize,
    /// Number of agents paused via the kill-switch precompile
    pub paused_agents: usize,
    /// Number of agents quarantined via the kill-switch precompile
    pub quarantined_agents: usize,
    /// Number of terminated agents
    pub terminated_agents: usize,
    /// Total messages processed
    pub messages_processed: u64,
    /// Total tasks delegated
    pub tasks_delegated: u64,
}

/// Main agent runtime that coordinates all subsystems
pub struct AgentRuntime {
    /// Configuration
    config: AgentRuntimeConfig,
    /// Identity manager
    identity_manager: Arc<AgentIdentityManager>,
    /// Lifecycle manager
    lifecycle_manager: Arc<AgentLifecycle>,
    /// Message router
    message_router: Arc<MessageRouter>,
    /// Capability registry
    capability_registry: Arc<CapabilityRegistry>,
    /// A2A protocol handler
    a2a_protocol: Arc<A2aProtocol>,
    /// Runtime statistics
    statistics: Arc<RwLock<RuntimeStatistics>>,
    /// Parent → child agent ID mapping (for spawn tracking)
    child_agents: Arc<DashMap<String, Vec<String>>>,
    /// Per-machine-DID runtime spending policy registry.
    ///
    /// Phase C of the agentic 2026 upgrade introduces a *runtime* execution
    /// ceiling that lives alongside the *protocol* ceiling encoded in
    /// `DelegationScope`. The protocol ceiling answers "what is this
    /// machine structurally allowed to do"; the runtime ceiling answers
    /// "what is this machine currently configured to spend." The payment
    /// gate at `IdentityPaymentBinder::validate_payer_for_protocol` checks
    /// both — a violation on either axis aborts the payment.
    ///
    /// Keyed by the machine DID string (e.g. `did:tenzro:machine:...`)
    /// because that is what the payment layer sees on `payer_did`.
    /// `tenzro-agent-kit::AgentSpawner` populates the entry at spawn time
    /// from the template's `DelegationSpec`.
    spending_policies: Arc<DashMap<String, SpendingPolicy>>,
    /// Per-machine-DID monotonic transaction sequence counter. Used to mint
    /// the BE-encoded suffix in `agenttx:<machine_did>:<seq_be_u64>` keys
    /// so prefix scans return records in insertion order. Hydrated on
    /// `with_storage` from the highest existing seq per DID, so post-restart
    /// keys never collide with persisted ones.
    agent_tx_counters: Arc<DashMap<String, u64>>,
    /// Optional durable backing store (RocksDB via CF_AGENTS) for
    /// agent identity, lifecycle, and spawn-tree persistence across restarts.
    ///
    /// When present, every mutating call (`register_agent`, `activate_agent`,
    /// `suspend_agent`, `terminate_agent`, `spawn_agent`) writes through to
    /// the store before the in-memory state is updated. Hydration on startup
    /// happens in [`AgentRuntime::with_storage`].
    storage: Option<Arc<dyn KvStore>>,
    /// Phase B agent memory tier — optional [`crate::memory::MemoryManager`]
    /// composing a Lance vector backend, a Tantivy text backend, and a DA
    /// archival backend. Wired by the node at startup
    /// (`init_ai_infrastructure`) rooted at `{data_dir}/agent_memory/`. When
    /// present, the agent-memory RPCs / MCP tools / A2A skill route through
    /// this manager.
    ///
    /// Stored behind a `OnceLock` so the runtime can be constructed first
    /// (with the network transport) and the memory manager attached later
    /// (after the data directory is known) without requiring `&mut self` or a
    /// `Clone` impl on the runtime — both would force the rest of the node
    /// to learn about the memory tier just to forward construction.
    memory_manager: std::sync::OnceLock<Arc<crate::memory::MemoryManager>>,
}

impl AgentRuntime {
    /// Creates a new agent runtime
    pub fn new() -> Result<Self> {
        Self::with_config(AgentRuntimeConfig::default())
    }

    /// Creates a new agent runtime with custom configuration
    pub fn with_config(config: AgentRuntimeConfig) -> Result<Self> {
        let identity_manager = Arc::new(AgentIdentityManager::new()?);
        let lifecycle_manager = Arc::new(AgentLifecycle::with_heartbeat_config(HeartbeatConfig {
            interval_secs: config.heartbeat_interval as i64,
            timeout_multiplier: 1,
        }));
        let message_router = Arc::new(MessageRouter::new());
        let capability_registry = Arc::new(CapabilityRegistry::new());
        let a2a_protocol = Arc::new(A2aProtocol::new());

        let statistics = Arc::new(RwLock::new(RuntimeStatistics {
            total_agents: 0,
            active_agents: 0,
            suspended_agents: 0,
            paused_agents: 0,
            quarantined_agents: 0,
            terminated_agents: 0,
            messages_processed: 0,
            tasks_delegated: 0,
        }));

        Ok(Self {
            config,
            identity_manager,
            lifecycle_manager,
            message_router,
            capability_registry,
            a2a_protocol,
            statistics,
            child_agents: Arc::new(DashMap::new()),
            spending_policies: Arc::new(DashMap::new()),
            agent_tx_counters: Arc::new(DashMap::new()),
            storage: None,
            memory_manager: std::sync::OnceLock::new(),
        })
    }

    /// Creates a new agent runtime with a network transport for cross-node messaging.
    ///
    /// The transport is injected into the internal `MessageRouter`, enabling
    /// agent messages to be published/received via gossipsub.
    pub fn with_network_transport(
        transport: Arc<dyn crate::messaging::NetworkTransport>,
    ) -> Result<Self> {
        let config = AgentRuntimeConfig::default();
        let identity_manager = Arc::new(AgentIdentityManager::new()?);
        let lifecycle_manager = Arc::new(AgentLifecycle::with_heartbeat_config(HeartbeatConfig {
            interval_secs: config.heartbeat_interval as i64,
            timeout_multiplier: 1,
        }));
        let message_router = Arc::new(MessageRouter::new().with_network_transport(transport));
        let capability_registry = Arc::new(CapabilityRegistry::new());
        let a2a_protocol = Arc::new(A2aProtocol::new());

        let statistics = Arc::new(RwLock::new(RuntimeStatistics {
            total_agents: 0,
            active_agents: 0,
            suspended_agents: 0,
            paused_agents: 0,
            quarantined_agents: 0,
            terminated_agents: 0,
            messages_processed: 0,
            tasks_delegated: 0,
        }));

        Ok(Self {
            config,
            identity_manager,
            lifecycle_manager,
            message_router,
            capability_registry,
            a2a_protocol,
            statistics,
            child_agents: Arc::new(DashMap::new()),
            spending_policies: Arc::new(DashMap::new()),
            agent_tx_counters: Arc::new(DashMap::new()),
            storage: None,
            memory_manager: std::sync::OnceLock::new(),
        })
    }

    /// Creates a new agent runtime backed by a durable `KvStore` (RocksDB via
    /// CF_AGENTS) and hydrates previously-persisted agents, lifecycles, and
    /// spawn trees from it.
    ///
    /// # Hydration order
    ///
    /// 1. All `agent:<agent_id>` records are deserialized into
    ///    `AgentIdentityManager` via `insert_hydrated` (bypasses wallet
    ///    provisioning and TDIP binding so no new gas is owed).
    /// 2. For each hydrated agent, every capability is re-registered in the
    ///    in-memory `CapabilityRegistry` (capabilities are derived from the
    ///    agent record rather than stored separately).
    /// 3. Every `lifecycle:<agent_id>` record is restored into
    ///    `AgentLifecycle` via `insert_hydrated` (preserves terminal states
    ///    without walking the state machine or emitting synthetic events).
    /// 4. If a hydrated agent has no matching lifecycle record (e.g. after a
    ///    partial crash), a fresh `AgentLifecycleInfo` is seeded so message
    ///    routing sanity checks continue to work.
    /// 5. All `children:<parent_id>` records are restored into the parent→
    ///    children map used by `spawn_agent`.
    /// 6. `MessageRouter::register_agent` is called for every hydrated agent
    ///    so their inbound queues are immediately addressable.
    ///
    /// Hydration failures on individual records are logged and skipped —
    /// one corrupted entry must not block the rest of the registry from
    /// coming up.
    pub fn with_storage(
        storage: Arc<dyn KvStore>,
        transport: Option<Arc<dyn crate::messaging::NetworkTransport>>,
    ) -> Result<Self> {
        let config = AgentRuntimeConfig::default();
        let identity_manager = Arc::new(AgentIdentityManager::new()?);
        let lifecycle_manager = Arc::new(AgentLifecycle::with_heartbeat_config(HeartbeatConfig {
            interval_secs: config.heartbeat_interval as i64,
            timeout_multiplier: 1,
        }));
        // Wire storage into the router so accepted agent messages are
        // wrapped in `ReceiptEnvelope { kind: AgentMessage, OffloadedDA }`
        // and persisted to `CF_AGENTS / message:<agent_id>:...`.
        let mut router = MessageRouter::new().with_storage(storage.clone());
        if let Some(t) = transport {
            router = router.with_network_transport(t);
        }
        let message_router = Arc::new(router);
        let capability_registry = Arc::new(CapabilityRegistry::new());
        let a2a_protocol = Arc::new(A2aProtocol::new());

        let child_agents: Arc<DashMap<String, Vec<String>>> = Arc::new(DashMap::new());

        // -- Hydration (steps 1–6) -------------------------------------------

        // Step 1: restore RegisteredAgent records.
        let agent_keys = storage
            .get_keys_with_prefix(CF_AGENTS, AGENT_KEY_PREFIX)
            .map_err(|e| AgentError::StorageError(format!("Failed to scan agent keys: {}", e)))?;

        let mut hydrated_agent_ids: Vec<String> = Vec::new();
        for key in agent_keys {
            match storage.get(CF_AGENTS, &key) {
                Ok(Some(bytes)) => {
                    match serde_json::from_slice::<RegisteredAgent>(&bytes) {
                        Ok(agent) => {
                            let agent_id = agent.identity.agent_id.clone();
                            let caps = agent.capabilities.clone();
                            match identity_manager.insert_hydrated(agent) {
                                Ok(()) => {
                                    // Step 2: rehydrate capabilities.
                                    for cap in caps {
                                        if let Err(e) = capability_registry
                                            .register_capability(agent_id.clone(), cap)
                                        {
                                            warn!(
                                                "Failed to restore capability for agent {}: {}",
                                                agent_id, e
                                            );
                                        }
                                    }
                                    hydrated_agent_ids.push(agent_id);
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to hydrate agent from key {:?}: {}",
                                        String::from_utf8_lossy(&key),
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => warn!(
                            "Corrupt agent record at key {:?}: {}",
                            String::from_utf8_lossy(&key),
                            e
                        ),
                    }
                }
                Ok(None) => {}
                Err(e) => warn!(
                    "Failed to read agent key {:?}: {}",
                    String::from_utf8_lossy(&key),
                    e
                ),
            }
        }

        // Step 3: restore AgentLifecycleInfo records.
        let lifecycle_keys = storage
            .get_keys_with_prefix(CF_AGENTS, LIFECYCLE_KEY_PREFIX)
            .map_err(|e| {
                AgentError::StorageError(format!("Failed to scan lifecycle keys: {}", e))
            })?;

        let mut hydrated_lifecycle_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for key in lifecycle_keys {
            match storage.get(CF_AGENTS, &key) {
                Ok(Some(bytes)) => match serde_json::from_slice::<AgentLifecycleInfo>(&bytes) {
                    Ok(info) => {
                        let id = info.agent_id.clone();
                        if let Err(e) = lifecycle_manager.insert_hydrated(info) {
                            warn!("Failed to hydrate lifecycle for agent {}: {}", id, e);
                        } else {
                            hydrated_lifecycle_ids.insert(id);
                        }
                    }
                    Err(e) => warn!(
                        "Corrupt lifecycle record at key {:?}: {}",
                        String::from_utf8_lossy(&key),
                        e
                    ),
                },
                Ok(None) => {}
                Err(e) => warn!(
                    "Failed to read lifecycle key {:?}: {}",
                    String::from_utf8_lossy(&key),
                    e
                ),
            }
        }

        // Step 4: seed missing lifecycles for agents that were persisted but
        // had no matching lifecycle record (e.g. mid-registration crash).
        for agent_id in &hydrated_agent_ids {
            if !hydrated_lifecycle_ids.contains(agent_id) {
                let info = AgentLifecycleInfo::new(agent_id.clone());
                if let Err(e) = lifecycle_manager.insert_hydrated(info) {
                    warn!("Failed to seed lifecycle for agent {}: {}", agent_id, e);
                }
            }
        }

        // Step 5: restore parent → children spawn tree.
        let children_keys = storage
            .get_keys_with_prefix(CF_AGENTS, CHILDREN_KEY_PREFIX)
            .map_err(|e| {
                AgentError::StorageError(format!("Failed to scan children keys: {}", e))
            })?;

        for key in children_keys {
            match storage.get(CF_AGENTS, &key) {
                Ok(Some(bytes)) => {
                    match serde_json::from_slice::<Vec<String>>(&bytes) {
                        Ok(children) => {
                            // Parent id is the suffix after CHILDREN_KEY_PREFIX.
                            if let Some(parent_bytes) = key.strip_prefix(CHILDREN_KEY_PREFIX)
                                && let Ok(parent_id) =
                                    std::str::from_utf8(parent_bytes).map(|s| s.to_string())
                            {
                                child_agents.insert(parent_id, children);
                            }
                        }
                        Err(e) => warn!(
                            "Corrupt children record at key {:?}: {}",
                            String::from_utf8_lossy(&key),
                            e
                        ),
                    }
                }
                Ok(None) => {}
                Err(e) => warn!(
                    "Failed to read children key {:?}: {}",
                    String::from_utf8_lossy(&key),
                    e
                ),
            }
        }

        // Step 5b: rehydrate per-DID transaction sequence counters from
        // existing `agenttx:<did>:<seq>` keys so newly-minted keys after
        // restart never collide with persisted ones. We track only the max
        // seq per DID — record contents are read on-demand by
        // `list_agent_transactions`.
        let agent_tx_counters: Arc<DashMap<String, u64>> = Arc::new(DashMap::new());
        let tx_keys = storage
            .get_keys_with_prefix(CF_AGENTS, AGENT_TX_KEY_PREFIX)
            .map_err(|e| {
                AgentError::StorageError(format!("Failed to scan agent transaction keys: {}", e))
            })?;
        for key in tx_keys {
            // Key layout: `agenttx:<did>:<seq_be_u64>`. The DID itself can
            // contain `:` so we slice off the trailing 8 bytes (BE seq) and
            // the single ':' separator just before it; whatever remains
            // between `agenttx:` and that boundary is the DID.
            let Some(rest) = key.strip_prefix(AGENT_TX_KEY_PREFIX) else {
                continue;
            };
            if rest.len() < 9 {
                // Need at least ':' + 8 bytes of BE seq.
                continue;
            }
            let split = rest.len() - 9;
            // The byte before the trailing 8 bytes must be ':' for a
            // well-formed key. Anything else is corrupt and skipped.
            if rest[split] != b':' {
                continue;
            }
            let did_bytes = &rest[..split];
            let seq_bytes = &rest[split + 1..];
            let Ok(did) = std::str::from_utf8(did_bytes).map(|s| s.to_string()) else {
                continue;
            };
            let mut seq_arr = [0u8; 8];
            seq_arr.copy_from_slice(seq_bytes);
            let seq = u64::from_be_bytes(seq_arr);
            agent_tx_counters
                .entry(did)
                .and_modify(|cur| {
                    if seq > *cur {
                        *cur = seq;
                    }
                })
                .or_insert(seq);
        }

        // Step 6: register hydrated agents with the message router and bind
        // their hybrid verifying keys back into the local resolver so signed
        // AgentMessages keep verifying after a node restart.
        for agent_id in &hydrated_agent_ids {
            if let Err(e) = message_router.register_agent(agent_id.clone()) {
                warn!(
                    "Failed to register hydrated agent {} with message router: {}",
                    agent_id, e
                );
                continue;
            }
            if let Ok(agent) = identity_manager.get_agent(agent_id) {
                if let Some(keys) = build_agent_verifying_keys(&agent) {
                    let _ = message_router.register_local_key(agent_id.clone(), keys);
                } else {
                    warn!(
                        "Hydrated agent {} has no classical/PQ verifying keys on \
                         file — signed message verification will fail until \
                         it is re-registered",
                        agent_id
                    );
                }
            }
        }

        // Initial statistics reflect the hydrated state. Computed before the
        // RwLock is constructed so we don't need to acquire a lock that
        // might be awaited on by a caller under a tokio runtime.
        let total = identity_manager.agent_count();
        let active = lifecycle_manager
            .get_agents_in_state(AgentState::Active)
            .len();
        let suspended = lifecycle_manager
            .get_agents_in_state(AgentState::Suspended)
            .len();
        let paused = lifecycle_manager
            .get_agents_in_state(AgentState::Paused)
            .len();
        let quarantined = lifecycle_manager
            .get_agents_in_state(AgentState::Quarantined)
            .len();
        let terminated = lifecycle_manager
            .get_agents_in_state(AgentState::Terminated)
            .len();
        let statistics = Arc::new(RwLock::new(RuntimeStatistics {
            total_agents: total,
            active_agents: active,
            suspended_agents: suspended,
            paused_agents: paused,
            quarantined_agents: quarantined,
            terminated_agents: terminated,
            messages_processed: 0,
            tasks_delegated: 0,
        }));

        info!(
            "AgentRuntime hydrated from CF_AGENTS: {} agents ({} active, {} suspended, {} paused, {} quarantined, {} terminated)",
            total, active, suspended, paused, quarantined, terminated
        );

        Ok(Self {
            config,
            identity_manager,
            lifecycle_manager,
            message_router,
            capability_registry,
            a2a_protocol,
            statistics,
            child_agents,
            spending_policies: Arc::new(DashMap::new()),
            agent_tx_counters,
            storage: Some(storage),
            memory_manager: std::sync::OnceLock::new(),
        })
    }

    /// Attach a [`crate::memory::MemoryManager`] to this runtime. Idempotent —
    /// the first attachment wins; subsequent calls are silently ignored
    /// (returns `false` to signal the manager was already set). The node
    /// calls this exactly once during `init_ai_infrastructure`.
    pub fn set_memory_manager(&self, memory_manager: Arc<crate::memory::MemoryManager>) -> bool {
        self.memory_manager.set(memory_manager).is_ok()
    }

    /// Borrow the attached memory manager, if any.
    pub fn memory_manager(&self) -> Option<&Arc<crate::memory::MemoryManager>> {
        self.memory_manager.get()
    }

    // ---- Persistence helpers ------------------------------------------------

    /// Builds the CF_AGENTS storage key for a `RegisteredAgent` record.
    fn agent_key(agent_id: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(AGENT_KEY_PREFIX.len() + agent_id.len());
        k.extend_from_slice(AGENT_KEY_PREFIX);
        k.extend_from_slice(agent_id.as_bytes());
        k
    }

    /// Builds the CF_AGENTS storage key for an `AgentLifecycleInfo` record.
    fn lifecycle_key(agent_id: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(LIFECYCLE_KEY_PREFIX.len() + agent_id.len());
        k.extend_from_slice(LIFECYCLE_KEY_PREFIX);
        k.extend_from_slice(agent_id.as_bytes());
        k
    }

    /// Builds the CF_AGENTS storage key for a parent → children record.
    fn children_key(parent_id: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(CHILDREN_KEY_PREFIX.len() + parent_id.len());
        k.extend_from_slice(CHILDREN_KEY_PREFIX);
        k.extend_from_slice(parent_id.as_bytes());
        k
    }

    /// Persists a single `RegisteredAgent` to CF_AGENTS. No-op when storage
    /// is not configured.
    fn persist_agent(&self, agent: &RegisteredAgent) -> Result<()> {
        if let Some(ref storage) = self.storage {
            let bytes = serde_json::to_vec(agent).map_err(|e| {
                AgentError::StorageError(format!("Failed to serialize agent: {}", e))
            })?;
            let key = Self::agent_key(&agent.identity.agent_id);
            storage
                .put(CF_AGENTS, &key, &bytes)
                .map_err(|e| AgentError::StorageError(format!("Failed to persist agent: {}", e)))?;
        }
        Ok(())
    }

    /// Persists the latest lifecycle info for an agent. No-op when storage
    /// is not configured.
    fn persist_lifecycle(&self, agent_id: &str) -> Result<()> {
        if let Some(ref storage) = self.storage {
            let info = self.lifecycle_manager.get_lifecycle_info(agent_id)?;
            let bytes = serde_json::to_vec(&info).map_err(|e| {
                AgentError::StorageError(format!("Failed to serialize lifecycle: {}", e))
            })?;
            let key = Self::lifecycle_key(agent_id);
            storage.put(CF_AGENTS, &key, &bytes).map_err(|e| {
                AgentError::StorageError(format!("Failed to persist lifecycle: {}", e))
            })?;
        }
        Ok(())
    }

    /// Persists the current parent → children mapping for `parent_id`.
    fn persist_children(&self, parent_id: &str) -> Result<()> {
        if let Some(ref storage) = self.storage {
            let children: Vec<String> = self
                .child_agents
                .get(parent_id)
                .map(|v| v.clone())
                .unwrap_or_default();
            let bytes = serde_json::to_vec(&children).map_err(|e| {
                AgentError::StorageError(format!("Failed to serialize children: {}", e))
            })?;
            let key = Self::children_key(parent_id);
            storage.put(CF_AGENTS, &key, &bytes).map_err(|e| {
                AgentError::StorageError(format!("Failed to persist children: {}", e))
            })?;
        }
        Ok(())
    }

    /// Refreshes the persisted agent record for `agent_id` from the current
    /// in-memory state.
    fn resync_agent(&self, agent_id: &str) -> Result<()> {
        if self.storage.is_some() {
            let agent = self.identity_manager.get_agent(agent_id)?;
            self.persist_agent(&agent)?;
        }
        Ok(())
    }

    /// Registers a new agent on the network
    pub async fn register_agent(
        &self,
        name: String,
        creator: Address,
        capabilities: Vec<Capability>,
        tee_backed: bool,
        nonce: u64,
    ) -> Result<RegisteredAgent> {
        // Check if we've reached the maximum number of agents
        if self.identity_manager.agent_count() >= self.config.max_agents {
            return Err(AgentError::ResourceLimitExceeded(
                "Maximum number of agents reached".to_string(),
            ));
        }

        // Register the agent identity and wallet
        let agent = self
            .identity_manager
            .register_agent(name, creator, capabilities.clone(), tee_backed, nonce)
            .await?;

        let agent_id = agent.identity.agent_id.clone();

        // Initialize lifecycle (Created state)
        self.lifecycle_manager.initialize(agent_id.clone())?;

        // Immediately drive the lifecycle to Active so downstream operations
        // like `send_message` (which require AgentState::Active) work without
        // a separate out-of-band activation step. The lifecycle manager's
        // `activate()` handles the Created -> Initializing -> Active path
        // atomically.
        self.lifecycle_manager.activate(&agent_id)?;

        // Register with message router
        self.message_router.register_agent(agent_id.clone())?;

        // Bind the agent's hybrid verifying keys into the router's
        // resolver so it can verify Ed25519 + ML-DSA-65 signatures on
        // inbound `AgentMessage`s. Without this the router rejects every
        // signed message with "no public key on file". For routers wired
        // with a custom (non-local) resolver this is a no-op — that
        // resolver is expected to be populated out-of-band.
        if let Some(keys) = build_agent_verifying_keys(&agent) {
            let _ = self
                .message_router
                .register_local_key(agent_id.clone(), keys);
        } else {
            warn!(
                "Agent {} registered without classical/PQ verifying keys — \
                 signed message verification will fail until keys are bound",
                agent_id
            );
        }

        // Register capabilities
        for capability in capabilities {
            self.capability_registry
                .register_capability(agent_id.clone(), capability)?;
        }

        // Write-through persistence so this agent survives node restarts.
        // `persist_lifecycle` must run AFTER `activate` so the persisted
        // lifecycle reflects the Active state (otherwise a restart would
        // rehydrate the agent in Created and block `send_message`).
        self.persist_agent(&agent)?;
        self.persist_lifecycle(&agent_id)?;

        // Update statistics
        self.update_statistics().await;

        info!(
            "Agent {} registered successfully with {} capabilities (state: Active)",
            agent_id,
            agent.capabilities.len()
        );

        Ok(agent)
    }

    /// Registers a new agent using **caller-supplied** classical (Ed25519),
    /// post-quantum (ML-DSA-65), and BLS12-381 verifying keys (BYOK path).
    ///
    /// No wallet is provisioned on the node — the agent's address is
    /// derived deterministically from the supplied Ed25519 key. The
    /// agent's hybrid keys are bound into the message router's resolver
    /// so the caller can sign `AgentMessage`s off-node and have the
    /// router verify them. The BLS key is propagated to the bound TDIP
    /// identity so the agent inherits the public key needed for
    /// HotStuff-2 vote aggregation if it later stakes as a validator.
    pub async fn register_agent_with_keys(
        &self,
        name: String,
        creator: Address,
        capabilities: Vec<Capability>,
        tee_backed: bool,
        nonce: u64,
        classical_public_key: Vec<u8>,
        pq_verifying_key: Vec<u8>,
        bls_verifying_key: Vec<u8>,
    ) -> Result<RegisteredAgent> {
        if self.identity_manager.agent_count() >= self.config.max_agents {
            return Err(AgentError::ResourceLimitExceeded(
                "Maximum number of agents reached".to_string(),
            ));
        }

        let agent = self
            .identity_manager
            .register_agent_with_keys(
                name,
                creator,
                capabilities.clone(),
                tee_backed,
                nonce,
                classical_public_key,
                pq_verifying_key,
                bls_verifying_key,
                crate::identity::GasPolicy::AcceptAny,
            )
            .await?;

        let agent_id = agent.identity.agent_id.clone();

        self.lifecycle_manager.initialize(agent_id.clone())?;
        self.lifecycle_manager.activate(&agent_id)?;

        self.message_router.register_agent(agent_id.clone())?;

        // Bind the caller-supplied verifying keys into the router's
        // resolver. This is the whole point of BYOK — the caller signs
        // off-node and we verify here.
        if let Some(keys) = build_agent_verifying_keys(&agent) {
            let _ = self
                .message_router
                .register_local_key(agent_id.clone(), keys);
        } else {
            warn!(
                "BYOK agent {} registered without verifying keys after construction \
                 — this is a bug, signed message verification will fail",
                agent_id
            );
        }

        for capability in capabilities {
            self.capability_registry
                .register_capability(agent_id.clone(), capability)?;
        }

        self.persist_agent(&agent)?;
        self.persist_lifecycle(&agent_id)?;

        self.update_statistics().await;

        info!(
            "BYOK agent {} registered successfully with {} capabilities (state: Active, no server-side wallet)",
            agent_id,
            agent.capabilities.len()
        );

        Ok(agent)
    }

    /// Activates an agent
    pub async fn activate_agent(&self, agent_id: &str) -> Result<()> {
        // Verify agent exists
        let agent = self.identity_manager.get_agent(agent_id)?;

        if agent.status != AgentStatus::Active {
            return Err(AgentError::LifecycleError(format!(
                "Agent {} is not in active status",
                agent_id
            )));
        }

        // Activate in lifecycle manager
        self.lifecycle_manager.activate(agent_id)?;

        // Write-through: lifecycle state advanced, refresh persisted copy.
        self.persist_lifecycle(agent_id)?;

        // Update statistics
        self.update_statistics().await;

        Ok(())
    }

    /// Suspends an agent
    pub async fn suspend_agent(&self, agent_id: &str, reason: String) -> Result<()> {
        // Suspend in identity manager
        self.identity_manager.suspend_agent(agent_id)?;

        // Suspend in lifecycle manager
        self.lifecycle_manager.suspend(agent_id, reason)?;

        // Write-through: status + lifecycle both changed.
        self.resync_agent(agent_id)?;
        self.persist_lifecycle(agent_id)?;

        // Update statistics
        self.update_statistics().await;

        Ok(())
    }

    /// Resumes a Suspended agent back to Active.
    ///
    /// Companion to [`suspend_agent`] — the recovery path for agents flipped to
    /// `Suspended` by the heartbeat monitor (`AgentLifecycle::check_heartbeats`)
    /// or by an operational suspend. Distinct from `resume_paused_agent` /
    /// `resume_quarantined_agent`, which operate on the kill-switch axes
    /// (`Paused` and `Quarantined`).
    ///
    /// Re-flips the identity status from `Suspended` to `Active`
    /// (`AgentIdentityManager::reactivate_agent`) and the lifecycle FSM from
    /// `Suspended` to `Active` (`AgentLifecycle::resume`). Both transitions
    /// are persisted.
    pub async fn resume_agent(&self, agent_id: &str) -> Result<()> {
        // Reactivate in identity manager (Suspended → Active).
        self.identity_manager.reactivate_agent(agent_id)?;

        // Resume in lifecycle manager (Suspended → Active).
        self.lifecycle_manager.resume(agent_id)?;

        // Write-through: status + lifecycle both changed.
        self.resync_agent(agent_id)?;
        self.persist_lifecycle(agent_id)?;

        // Update statistics
        self.update_statistics().await;

        Ok(())
    }

    /// Pauses an agent via the kill-switch primitive.
    ///
    /// Drives the lifecycle Active → Paused. Identity-level status is
    /// **not** flipped to Suspended (operational `suspend_agent` already
    /// owns that field) — pause is its own axis. Persists the lifecycle
    /// transition to CF_AGENTS for restart safety.
    pub async fn pause_agent(
        &self,
        agent_id: &str,
        controller_did: String,
        reason_code: u32,
        reason_text: Option<String>,
    ) -> Result<()> {
        self.lifecycle_manager
            .pause(agent_id, controller_did, reason_code, reason_text)?;
        self.persist_lifecycle(agent_id)?;
        self.update_statistics().await;
        Ok(())
    }

    /// Resumes a paused agent back to Active.
    pub async fn resume_paused_agent(&self, agent_id: &str, controller_did: String) -> Result<()> {
        self.lifecycle_manager
            .resume_from_pause(agent_id, controller_did)?;
        self.persist_lifecycle(agent_id)?;
        self.update_statistics().await;
        Ok(())
    }

    /// Quarantines an agent via the kill-switch primitive.
    ///
    /// Drives the lifecycle Active → Quarantined (or Paused → Quarantined
    /// for escalation). The payment binder + staking manager treat
    /// `Quarantined` as a freeze — no settlements, no reward distribution,
    /// no stake withdrawals — but stake remains intact pending the
    /// resume-or-terminate decision.
    pub async fn quarantine_agent(
        &self,
        agent_id: &str,
        controller_did: String,
        reason_code: u32,
        reason_text: Option<String>,
    ) -> Result<()> {
        self.lifecycle_manager
            .quarantine(agent_id, controller_did, reason_code, reason_text)?;
        self.persist_lifecycle(agent_id)?;
        self.update_statistics().await;
        Ok(())
    }

    /// Returns a quarantined agent to Active after investigation.
    pub async fn resume_quarantined_agent(
        &self,
        agent_id: &str,
        controller_did: String,
    ) -> Result<()> {
        self.lifecycle_manager
            .resume_from_quarantine(agent_id, controller_did)?;
        self.persist_lifecycle(agent_id)?;
        self.update_statistics().await;
        Ok(())
    }

    /// Terminates an agent
    pub async fn terminate_agent(&self, agent_id: &str, reason: String) -> Result<()> {
        // Deactivate in identity manager
        self.identity_manager.deactivate_agent(agent_id)?;

        // Terminate in lifecycle manager
        self.lifecycle_manager.terminate(agent_id, reason)?;

        // Unregister from message router
        self.message_router.unregister_agent(agent_id)?;

        // Remove capabilities
        self.capability_registry.remove_agent(agent_id)?;

        // Write-through: persist final Terminated state. We deliberately keep
        // the record in CF_AGENTS rather than deleting it so that the audit
        // trail (state_history, registration_fee, tenzro_did) survives.
        self.resync_agent(agent_id)?;
        self.persist_lifecycle(agent_id)?;

        // Update statistics
        self.update_statistics().await;

        info!("Agent {} terminated", agent_id);

        Ok(())
    }

    /// Sends a message to another agent
    pub async fn send_message(&self, message: AgentMessage) -> Result<()> {
        // Verify sender is active
        let sender_state = self.lifecycle_manager.get_state(&message.from.agent_id)?;
        if sender_state != AgentState::Active {
            return Err(AgentError::LifecycleError(format!(
                "Sender agent {} is not active",
                message.from.agent_id
            )));
        }

        // Verify receiver exists and is active
        let receiver_state = self.lifecycle_manager.get_state(&message.to.agent_id)?;
        if receiver_state != AgentState::Active {
            return Err(AgentError::LifecycleError(format!(
                "Receiver agent {} is not active",
                message.to.agent_id
            )));
        }

        // Send the message
        self.message_router.send_message(message).await?;

        // Update statistics
        let mut stats = self.statistics.write().await;
        stats.messages_processed += 1;

        Ok(())
    }

    /// Broadcasts a message to multiple agents
    pub async fn broadcast_message(
        &self,
        sender: AgentIdentity,
        recipients: Vec<AgentIdentity>,
        message_type: AgentMessageType,
        payload: Vec<u8>,
    ) -> Result<Vec<String>> {
        let message_ids = self
            .message_router
            .broadcast_message(sender, recipients, message_type, payload)
            .await?;

        // Update statistics
        let mut stats = self.statistics.write().await;
        stats.messages_processed += message_ids.len() as u64;

        Ok(message_ids)
    }

    /// Delegates a task to another agent
    pub async fn delegate_task(
        &self,
        sender: AgentIdentity,
        receiver: AgentIdentity,
        task_type: String,
        parameters: std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<String> {
        // Verify both agents are active
        let sender_state = self.lifecycle_manager.get_state(&sender.agent_id)?;
        let receiver_state = self.lifecycle_manager.get_state(&receiver.agent_id)?;

        if sender_state != AgentState::Active || receiver_state != AgentState::Active {
            return Err(AgentError::LifecycleError(
                "Both agents must be active for task delegation".to_string(),
            ));
        }

        // Create A2A message
        let a2a_message = self.a2a_protocol.delegate_task(
            sender.clone(),
            receiver.clone(),
            task_type,
            parameters,
        )?;

        let task_id = a2a_message.message_id.clone();

        // Convert to AgentMessage and send
        let payload = a2a_message.to_bytes()?.to_vec();
        let agent_message =
            AgentMessage::new(sender, receiver, AgentMessageType::TaskRequest, payload);

        self.send_message(agent_message).await?;

        // Update statistics
        let mut stats = self.statistics.write().await;
        stats.tasks_delegated += 1;

        debug!("Task {} delegated successfully", task_id);

        Ok(task_id)
    }

    /// Records a heartbeat from an agent
    pub async fn record_heartbeat(&self, agent_id: &str) -> Result<()> {
        self.lifecycle_manager.heartbeat(agent_id)?;
        debug!("Heartbeat recorded for agent {}", agent_id);
        Ok(())
    }

    /// Finds agents with a specific capability
    pub fn find_agents_with_capability(&self, capability: &Capability) -> Vec<String> {
        self.capability_registry
            .find_agents_with_capability(capability)
    }

    /// Gets an agent by ID
    pub fn get_agent(&self, agent_id: &str) -> Result<RegisteredAgent> {
        self.identity_manager.get_agent(agent_id)
    }

    /// Spawns a new sub-agent as a child of the given parent agent.
    /// Maximum 50 children per parent agent.
    pub async fn spawn_agent(
        &self,
        parent_id: &str,
        name: &str,
        capabilities: Vec<String>,
    ) -> Result<RegisteredAgent> {
        // Enforce max 50 children per parent
        let child_count = self
            .child_agents
            .get(parent_id)
            .map(|v| v.len())
            .unwrap_or(0);
        if child_count >= 50 {
            return Err(AgentError::ResourceLimitExceeded(format!(
                "Agent {} has reached the maximum child agent limit (50)",
                parent_id
            )));
        }

        // Look up parent to inherit creator address
        let parent = self.get_agent(parent_id)?;
        let creator = parent.identity.creator;

        // Convert string capability names to typed Capability::Custom variants
        let typed_caps: Vec<Capability> = capabilities
            .iter()
            .map(|c| Capability::Custom {
                name: c.clone(),
                parameters: std::collections::HashMap::new(),
            })
            .collect();

        // Register child agent with a unique nonce to avoid ID collision with parent
        let nonce = uuid::Uuid::new_v4().as_u128() as u64;
        let child = self
            .register_agent(name.to_string(), creator, typed_caps, false, nonce)
            .await?;

        // Track parent→child relationship
        self.child_agents
            .entry(parent_id.to_string())
            .or_default()
            .push(child.identity.agent_id.clone());

        // Write-through: the spawn tree must survive restarts so sub-agents
        // can be correctly attributed to their owner.
        self.persist_children(parent_id)?;

        info!(
            parent_id = %parent_id,
            child_id = %child.identity.agent_id,
            "Agent spawned"
        );
        Ok(child)
    }

    /// Returns the IDs of all child agents spawned by the given parent.
    pub fn get_children(&self, parent_id: &str) -> Vec<String> {
        self.child_agents
            .get(parent_id)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Gets the current state of an agent
    pub fn get_agent_state(&self, agent_id: &str) -> Result<AgentState> {
        self.lifecycle_manager.get_state(agent_id)
    }

    /// Returns a handle to the lifecycle manager. Used by external sweepers
    /// (e.g. the node's liveness layer) that need to drive `purge_suspended`
    /// alongside the registry-level TTL passes.
    pub fn lifecycle_manager(&self) -> Arc<AgentLifecycle> {
        self.lifecycle_manager.clone()
    }

    /// Returns a handle to the identity manager. Used by the node-side
    /// `LifecycleStateResolver` bridge to resolve `payer_did → agent_id`
    /// when projecting the kill-switch posture into the payment gate.
    pub fn identity_manager(&self) -> Arc<AgentIdentityManager> {
        self.identity_manager.clone()
    }

    /// Returns a handle to the capability registry. Used by the node RPC,
    /// MCP, and A2A surfaces to enumerate registered capabilities, fetch
    /// per-capability attestation lists, and resolve per-agent attestations
    /// for capability discovery and trust scoring.
    pub fn capability_registry(&self) -> Arc<CapabilityRegistry> {
        self.capability_registry.clone()
    }

    // ---- SpendingPolicy registry (Phase C) ---------------------------------

    /// Installs or replaces the runtime [`SpendingPolicy`] for a machine
    /// identity. Called by `tenzro-agent-kit::AgentSpawner` at spawn time
    /// from the template's `DelegationSpec` so every machine identity has a
    /// runtime-axis spend ceiling bound to its DID before the executor runs
    /// any task.
    ///
    /// The DID key matches what the payment gate sees on `payer_did`
    /// (canonical `TenzroIdentity::did_string()` form, e.g.
    /// `did:tenzro:machine:<controller>:<uuid>`).
    pub fn set_spending_policy(&self, machine_did: String, policy: SpendingPolicy) {
        self.spending_policies.insert(machine_did, policy);
    }

    /// Returns a clone of the current [`SpendingPolicy`] for a machine DID.
    /// Used by the node-level adapter that implements
    /// `tenzro_payments::SpendingPolicyResolver` to drive the runtime gate
    /// alongside the protocol-level `DelegationScope` checks.
    ///
    /// Returns `None` when the DID has no policy bound — that is interpreted
    /// upstream as "no runtime ceiling, fall back to protocol scope only."
    /// In practice every spawned machine has one because `AgentSpawner`
    /// installs it; the fallback exists so legacy / hand-registered machine
    /// identities (created outside the kit) don't bypass the payment path.
    pub fn get_spending_policy(&self, machine_did: &str) -> Option<SpendingPolicy> {
        self.spending_policies.get(machine_did).map(|v| v.clone())
    }

    /// Records a successful payment against the machine's runtime daily
    /// counter. Called by the payment gate after settlement so the daily
    /// window correctly reflects committed spends. Returns `Ok(())` and is
    /// a no-op if the DID has no policy bound.
    pub fn record_spend(&self, machine_did: &str, amount: u64) -> Result<()> {
        if let Some(mut entry) = self.spending_policies.get_mut(machine_did) {
            entry.record_transaction(amount)?;
        }
        Ok(())
    }

    /// Builds the CF_AGENTS storage key for an `AgentTransactionRecord`.
    /// Layout: `agenttx:<machine_did>:<seq_be_u64>` — the BE-encoded seq
    /// keeps lex-order aligned with insertion order.
    fn agent_tx_key(machine_did: &str, seq: u64) -> Vec<u8> {
        let mut k = Vec::with_capacity(AGENT_TX_KEY_PREFIX.len() + machine_did.len() + 1 + 8);
        k.extend_from_slice(AGENT_TX_KEY_PREFIX);
        k.extend_from_slice(machine_did.as_bytes());
        k.push(b':');
        k.extend_from_slice(&seq.to_be_bytes());
        k
    }

    /// Records a successful service payment for a machine agent. Persists
    /// the record under `agenttx:<machine_did>:<seq_be_u64>` in CF_AGENTS
    /// when storage is configured; otherwise the call is a no-op (in-memory
    /// callers can still rely on the `record_spend` daily counter for
    /// rate-limit enforcement).
    ///
    /// Note: this is the *audit trail* writer. The *runtime ceiling*
    /// enforcement happens in `record_spend`, which checks per-tx and
    /// daily caps. The wallet-kernel-facing RPC `tenzro_agentPayForService`
    /// calls both — first `record_spend` (gate), then settles, then this
    /// (history).
    pub fn record_agent_transaction(&self, record: AgentTransactionRecord) -> Result<()> {
        let Some(ref storage) = self.storage else {
            return Ok(());
        };
        let did = record.agent_did.clone();
        let seq = self
            .agent_tx_counters
            .entry(did.clone())
            .and_modify(|cur| *cur = cur.saturating_add(1))
            .or_insert(1);
        let seq_val: u64 = *seq;
        // Drop the entry guard before any storage call to avoid holding a
        // DashMap shard lock across IO.
        drop(seq);
        let key = Self::agent_tx_key(&did, seq_val);
        let bytes = serde_json::to_vec(&record).map_err(|e| {
            AgentError::StorageError(format!("Failed to serialize agent transaction: {}", e))
        })?;
        storage.put(CF_AGENTS, &key, &bytes).map_err(|e| {
            AgentError::StorageError(format!("Failed to persist agent transaction: {}", e))
        })?;
        Ok(())
    }

    /// Lists transaction history for a machine agent in chronological
    /// order (oldest first). When `limit` is `Some(n)`, only the most
    /// recent `n` records are returned (still in chronological order).
    /// Returns an empty vec when storage is not configured or no records
    /// exist for the DID.
    pub fn list_agent_transactions(
        &self,
        machine_did: &str,
        limit: Option<usize>,
    ) -> Result<Vec<AgentTransactionRecord>> {
        let Some(ref storage) = self.storage else {
            return Ok(Vec::new());
        };
        // Prefix scan over `agenttx:<did>:` — note the trailing ':' so we
        // don't pick up sibling DIDs that share a string prefix.
        let mut prefix = Vec::with_capacity(AGENT_TX_KEY_PREFIX.len() + machine_did.len() + 1);
        prefix.extend_from_slice(AGENT_TX_KEY_PREFIX);
        prefix.extend_from_slice(machine_did.as_bytes());
        prefix.push(b':');

        let mut keys = storage
            .get_keys_with_prefix(CF_AGENTS, &prefix)
            .map_err(|e| {
                AgentError::StorageError(format!("Failed to scan agent transaction keys: {}", e))
            })?;
        // RocksDB iterators return lex-ordered keys; in-memory backends
        // (e.g. `MemoryStore` for tests) use a HashMap whose iteration
        // order is non-deterministic. Sort here so chronology is
        // backend-agnostic — BE-seq encoding makes lex order = insertion
        // order regardless of DID length.
        keys.sort_unstable();

        let mut records: Vec<AgentTransactionRecord> = Vec::with_capacity(keys.len());
        for key in keys {
            match storage.get(CF_AGENTS, &key) {
                Ok(Some(bytes)) => match serde_json::from_slice::<AgentTransactionRecord>(&bytes) {
                    Ok(rec) => records.push(rec),
                    Err(e) => warn!(
                        "Corrupt agent transaction record at key {:?}: {}",
                        String::from_utf8_lossy(&key),
                        e
                    ),
                },
                Ok(None) => {}
                Err(e) => warn!(
                    "Failed to read agent transaction key {:?}: {}",
                    String::from_utf8_lossy(&key),
                    e
                ),
            }
        }

        // Keys are returned in lex order which matches BE-seq order which
        // matches insertion order, so `records` is already chronological.
        // If a limit is given, take the *tail* (most recent), preserving
        // chronological order for the returned slice.
        if let Some(n) = limit
            && records.len() > n
        {
            let drop_count = records.len() - n;
            records.drain(..drop_count);
        }
        Ok(records)
    }

    /// Lists all agents
    pub fn list_agents(&self, status_filter: Option<AgentStatus>) -> Vec<RegisteredAgent> {
        self.identity_manager.list_agents(status_filter)
    }

    /// Gets runtime statistics
    pub async fn get_statistics(&self) -> RuntimeStatistics {
        self.statistics.read().await.clone()
    }

    /// Updates runtime statistics
    async fn update_statistics(&self) {
        let mut stats = self.statistics.write().await;
        stats.total_agents = self.identity_manager.agent_count();
        stats.active_agents = self
            .lifecycle_manager
            .get_agents_in_state(AgentState::Active)
            .len();
        stats.suspended_agents = self
            .lifecycle_manager
            .get_agents_in_state(AgentState::Suspended)
            .len();
        stats.paused_agents = self
            .lifecycle_manager
            .get_agents_in_state(AgentState::Paused)
            .len();
        stats.quarantined_agents = self
            .lifecycle_manager
            .get_agents_in_state(AgentState::Quarantined)
            .len();
        stats.terminated_agents = self
            .lifecycle_manager
            .get_agents_in_state(AgentState::Terminated)
            .len();
    }

    /// Subscribes to lifecycle events
    pub fn subscribe_to_lifecycle_events(
        &self,
    ) -> tokio::sync::broadcast::Receiver<AgentLifecycleEvent> {
        self.lifecycle_manager.subscribe()
    }

    /// Gets unhealthy agents (missing heartbeats)
    pub fn get_unhealthy_agents(&self) -> Vec<String> {
        self.lifecycle_manager.get_unhealthy_agents()
    }

    /// Sweeps all agents against a caller-supplied idle TTL and auto-suspends
    /// any whose last heartbeat (or most recent state change, if no heartbeat
    /// has been received) is older than `ttl_secs`.
    ///
    /// For each suspended agent this method also:
    ///   * Marks the corresponding identity as `AgentStatus::Suspended` so
    ///     that the `RegisteredAgent` record stays consistent with the
    ///     lifecycle FSM.
    ///   * Writes through to CF_AGENTS when durable storage is configured,
    ///     so the suspension survives node restarts.
    ///
    /// Intended to be driven from the node's long-horizon reconciliation
    /// loop (e.g. the 60-second `agent_heartbeat` tick in `event_loop`)
    /// using a TTL of 3600 seconds, mirroring the model-registry sweep.
    ///
    /// Returns the list of agent IDs that were suspended in this sweep.
    pub async fn check_idle_agents(&self, ttl_secs: i64) -> Vec<String> {
        let suspended = match self.lifecycle_manager.check_idle_ttl(ttl_secs) {
            Ok(ids) => ids,
            Err(e) => {
                error!("Idle-TTL sweep failed: {}", e);
                return Vec::new();
            }
        };

        for agent_id in &suspended {
            // Mirror the suspend into the identity manager so status stays
            // consistent with lifecycle state, and persist write-through.
            if let Err(e) = self.identity_manager.suspend_agent(agent_id) {
                warn!("Failed to mark identity suspended for {}: {}", agent_id, e);
            }
            if let Err(e) = self.resync_agent(agent_id) {
                warn!("Failed to persist suspended agent {}: {}", agent_id, e);
            }
            if let Err(e) = self.persist_lifecycle(agent_id) {
                warn!(
                    "Failed to persist lifecycle for suspended agent {}: {}",
                    agent_id, e
                );
            }
        }

        if !suspended.is_empty() {
            self.update_statistics().await;
        }

        suspended
    }

    /// Monitors agent health and auto-suspends unhealthy agents
    pub async fn monitor_agent_health(&self) -> Result<()> {
        let unhealthy = self.get_unhealthy_agents();

        for agent_id in unhealthy {
            warn!("Agent {} is unhealthy (missing heartbeat)", agent_id);

            // Auto-suspend unhealthy agents
            if let Err(e) = self
                .suspend_agent(&agent_id, "Missing heartbeat".to_string())
                .await
            {
                error!("Failed to suspend unhealthy agent {}: {}", agent_id, e);
            }
        }

        Ok(())
    }

    /// Starts background tasks for the runtime
    pub async fn start_background_tasks(self: Arc<Self>) {
        let runtime = self.clone();

        // Health monitoring task
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
                runtime.config.heartbeat_interval,
            ));

            loop {
                interval.tick().await;
                if let Err(e) = runtime.monitor_agent_health().await {
                    error!("Error monitoring agent health: {}", e);
                }
            }
        });

        info!("Agent runtime background tasks started");
    }

    /// Shuts down the runtime
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down agent runtime");

        // Terminate all active agents
        let active_agents = self
            .lifecycle_manager
            .get_agents_in_state(AgentState::Active);

        for agent_id in active_agents {
            if let Err(e) = self
                .terminate_agent(&agent_id, "Runtime shutdown".to_string())
                .await
            {
                error!(
                    "Error terminating agent {} during shutdown: {}",
                    agent_id, e
                );
            }
        }

        info!("Agent runtime shutdown complete");
        Ok(())
    }
}

impl Default for AgentRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create AgentRuntime")
    }
}

/// Build an `AgentVerifyingKeys` bundle from a `RegisteredAgent`'s stored
/// classical (Ed25519) and post-quantum (ML-DSA-65) verifying keys.
///
/// Returns `None` when either key is empty (e.g. a pre-existing record
/// hydrated from storage that predates the keys being captured), or when
/// the classical key's length doesn't fit Ed25519's 32-byte format. The
/// caller must surface this gap — verification will fail until the agent
/// is re-registered with valid keys.
fn build_agent_verifying_keys(agent: &RegisteredAgent) -> Option<AgentVerifyingKeys> {
    let classical_bytes = agent.classical_public_key();
    let pq_bytes = agent.pq_verifying_key();
    if classical_bytes.is_empty() || pq_bytes.is_empty() {
        return None;
    }
    let classical = tenzro_crypto::keys::PublicKey::new(
        tenzro_crypto::keys::KeyType::Ed25519,
        classical_bytes.to_vec(),
    );
    Some(AgentVerifyingKeys::new(classical, pq_bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::primitives::Address;

    #[tokio::test]
    async fn test_runtime_creation() {
        let runtime = AgentRuntime::new().unwrap();
        let stats = runtime.get_statistics().await;
        assert_eq!(stats.total_agents, 0);
    }

    #[tokio::test]
    async fn test_agent_registration() {
        let runtime = AgentRuntime::new().unwrap();
        let creator = Address::from([1u8; 32]);
        let capabilities = vec![Capability::MultiAgentCoordination];

        let agent = runtime
            .register_agent("TestAgent".to_string(), creator, capabilities, false, 0)
            .await
            .unwrap();

        assert_eq!(agent.identity.name, "TestAgent");

        let stats = runtime.get_statistics().await;
        assert_eq!(stats.total_agents, 1);
    }

    #[tokio::test]
    async fn test_agent_lifecycle() {
        let runtime = AgentRuntime::new().unwrap();
        let creator = Address::from([1u8; 32]);

        let agent = runtime
            .register_agent("Agent".to_string(), creator, vec![], false, 0)
            .await
            .unwrap();

        let agent_id = &agent.identity.agent_id;

        // `register_agent` now auto-activates the agent (see runtime.rs:559),
        // so the agent should already be Active on return. Calling
        // `activate_agent` again would be an InvalidStateTransition.
        let state = runtime.get_agent_state(agent_id).unwrap();
        assert_eq!(state, AgentState::Active);

        // Suspend
        runtime
            .suspend_agent(agent_id, "Testing".to_string())
            .await
            .unwrap();
        let state = runtime.get_agent_state(agent_id).unwrap();
        assert_eq!(state, AgentState::Suspended);

        // Terminate
        runtime
            .terminate_agent(agent_id, "Testing".to_string())
            .await
            .unwrap();
        let state = runtime.get_agent_state(agent_id).unwrap();
        assert_eq!(state, AgentState::Terminated);
    }

    #[tokio::test]
    async fn test_capability_discovery() {
        let runtime = AgentRuntime::new().unwrap();
        let creator = Address::from([1u8; 32]);
        let capability = Capability::MultiAgentCoordination;

        runtime
            .register_agent(
                "Agent1".to_string(),
                creator,
                vec![capability.clone()],
                false,
                0,
            )
            .await
            .unwrap();

        runtime
            .register_agent(
                "Agent2".to_string(),
                creator,
                vec![capability.clone()],
                false,
                1,
            )
            .await
            .unwrap();

        let agents = runtime.find_agents_with_capability(&capability);
        assert_eq!(agents.len(), 2);
    }

    #[tokio::test]
    async fn test_agent_transaction_history_roundtrip() {
        use tenzro_storage::kv::MemoryStore;

        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let runtime = AgentRuntime::with_storage(storage.clone(), None).unwrap();

        let did = "did:tenzro:machine:abc123";

        // Insert three records in order; their seq counters should preserve
        // chronological order across the prefix scan.
        for i in 0..3u64 {
            runtime
                .record_agent_transaction(AgentTransactionRecord {
                    agent_did: did.to_string(),
                    provider: format!("provider-{}", i),
                    service_type: "inference".to_string(),
                    amount: 100 + i,
                    timestamp: 1_700_000_000 + i as i64,
                    receipt_id: format!("receipt-{}", i),
                })
                .unwrap();
        }

        // Sibling DID — must not leak into the other DID's prefix scan.
        runtime
            .record_agent_transaction(AgentTransactionRecord {
                agent_did: "did:tenzro:machine:other".to_string(),
                provider: "other-provider".to_string(),
                service_type: "tee".to_string(),
                amount: 9999,
                timestamp: 1_700_000_000,
                receipt_id: "other-receipt".to_string(),
            })
            .unwrap();

        let all = runtime.list_agent_transactions(did, None).unwrap();
        assert_eq!(all.len(), 3, "expected 3 records for {}", did);
        assert_eq!(all[0].provider, "provider-0");
        assert_eq!(all[1].provider, "provider-1");
        assert_eq!(all[2].provider, "provider-2");

        // limit=2 returns the *most recent* 2 in chronological order.
        let tail = runtime.list_agent_transactions(did, Some(2)).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].provider, "provider-1");
        assert_eq!(tail[1].provider, "provider-2");

        // Rehydrate from the same backing store: the per-DID seq counter
        // must be recovered so a subsequent write doesn't collide with the
        // pre-existing seq=3 entry.
        drop(runtime);
        let runtime2 = AgentRuntime::with_storage(storage.clone(), None).unwrap();
        runtime2
            .record_agent_transaction(AgentTransactionRecord {
                agent_did: did.to_string(),
                provider: "provider-3".to_string(),
                service_type: "inference".to_string(),
                amount: 103,
                timestamp: 1_700_000_010,
                receipt_id: "receipt-3".to_string(),
            })
            .unwrap();

        let after = runtime2.list_agent_transactions(did, None).unwrap();
        assert_eq!(
            after.len(),
            4,
            "post-restart write should append, not collide"
        );
        assert_eq!(after[3].provider, "provider-3");
    }

    #[tokio::test]
    async fn test_agent_transaction_history_no_storage() {
        // Without a storage backend, the tx history methods are no-ops
        // and reads return empty rather than erroring.
        let runtime = AgentRuntime::new().unwrap();
        runtime
            .record_agent_transaction(AgentTransactionRecord {
                agent_did: "did:tenzro:machine:nostore".to_string(),
                provider: "p".to_string(),
                service_type: "x".to_string(),
                amount: 1,
                timestamp: 0,
                receipt_id: "r".to_string(),
            })
            .unwrap();
        let recs = runtime
            .list_agent_transactions("did:tenzro:machine:nostore", None)
            .unwrap();
        assert!(recs.is_empty());
    }
}
