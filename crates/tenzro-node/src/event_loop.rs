//! Node event loop that coordinates all subsystems
//!
//! This module wires together Network ↔ Consensus ↔ VM ↔ Storage into a working pipeline.
//! It handles events from the network and RPC, processes transactions, and finalizes blocks.
//!
//! # Transaction Pipeline
//!
//! 1. RPC/Network submits `NodeEvent::NewTransaction` via the event sender
//! 2. Event loop validates signature, gas limit, public key
//! 3. Validated transactions are forwarded to the consensus mempool
//! 4. Consensus engine proposes blocks from the mempool
//! 5. When consensus finalizes a block, `FinalityNotification` is broadcast
//! 6. Event loop subscribes to finality notifications and executes transactions via VM
//! 7. State changes are committed to RocksDB with fsync

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, Mutex};
use tracing::{debug, error, info, warn};
use dashmap::DashMap;

use tenzro_consensus::{BlockProvider, ConsensusOutMessage, FinalityNotification, HotStuff2Engine, StateRootProvider, VoteType as ConsVoteType};
use tenzro_network::{ConsensusMessage, NetworkMessage, MessagePayload, NetworkService, TenzroNetworkService, VoteType as NetVoteType};
use tenzro_storage::{RocksDbStore, KvStore, BlockStoreImpl, WriteOp, CF_MODELS, CF_MODEL_SERVICES, CF_TRANSACTIONS};
use tenzro_storage::traits::BlockStore;
use tenzro_vm::{MultiVmRuntime, StateAdapter, VmTransaction, VmType};
use tenzro_types::block::Block;
use tenzro_types::transaction::{SignedTransaction, TransactionType};
use tenzro_types::primitives::{BlockHeight, Hash};

use crate::error::{NodeError, Result};
use crate::metrics::MetricsCollector;

/// Event types flowing through the node
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// New transaction received (from RPC or network)
    NewTransaction(SignedTransaction),
    /// New block finalized by local consensus
    BlockFinalized(Block),
    /// Block received from the network via gossipsub (from another node's consensus)
    NetworkBlock(Block),
    /// Model registration received from gossipsub
    ModelAnnouncement(tenzro_network::ModelRegistrationMessage),
    /// Agent announcement received from gossipsub (from another node)
    AgentAnnouncement(tenzro_network::AgentAnnouncementMessage),
    /// Provider announcement received from gossipsub (from another node)
    ProviderAnnouncement(tenzro_network::ProviderAnnouncementMessage),
    /// Cortex advertisement received from gossipsub (signed JSON payload).
    ///
    /// Carries the raw serde_json-encoded `CortexAdvertisement` bytes so the
    /// event loop can decode, cryptographically verify, and ingest them into
    /// the node's `RemoteWorkerRegistry` without blocking the gossipsub
    /// receiver task.
    CortexAdvertisementReceived(Vec<u8>),
    /// Shutdown signal
    Shutdown,
}

/// Persisted per-transaction receipt record written to `CF_TRANSACTIONS`
/// under the key `receipt:<hex_tx_hash>` after each block is finalized.
///
/// This is the source of truth consumed by `eth_getTransactionReceipt` —
/// it lets the RPC layer report the *real* execution status, gas used,
/// emitted logs, and any deployed contract address rather than fabricating
/// a synthetic `0x1` / `gas_limit` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TxReceiptRecord {
    /// Whether VM execution succeeded (false on revert or VM error).
    pub success: bool,
    /// Actual gas consumed by this transaction.
    pub gas_used: u64,
    /// Sum of `gas_used` for this tx and every preceding tx in the same block.
    pub cumulative_gas_used: u64,
    /// Effective gas price the sender paid (post-EIP-1559 base fee burn semantics).
    pub effective_gas_price: u64,
    /// Revert reason, when `success == false`.
    pub revert_reason: Option<String>,
    /// Contract address (raw 20 bytes, hex without 0x prefix) for deployment txs.
    pub contract_address: Option<String>,
    /// Raw logs emitted during execution. Encoded with hex addresses/topics/data
    /// so the receipt JSON can be served without re-decoding VM types.
    pub logs: Vec<TxReceiptLog>,
}

/// Per-log entry inside a `TxReceiptRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TxReceiptLog {
    /// Hex-encoded contract address that emitted the log (no 0x prefix).
    pub address: String,
    /// Hex-encoded indexed topics (no 0x prefix).
    pub topics: Vec<String>,
    /// Hex-encoded log data payload (no 0x prefix).
    pub data: String,
}

/// Provides the current state root to the consensus block proposer.
///
/// Uses `parking_lot::Mutex` (a synchronous mutex) because the `StateRootProvider` trait
/// requires a synchronous `current_state_root()` method, and this is called from within
/// the tokio runtime's consensus loop. `tokio::sync::Mutex::blocking_lock()` panics when
/// called from inside a tokio runtime, so we use `parking_lot::Mutex` instead.
///
/// `compute_state_root()` is a fast, CPU-bound operation (Merkle trie hash), so holding
/// a synchronous lock briefly is appropriate and won't block the runtime meaningfully.
pub struct NodeStateRootProvider {
    state_adapter: Arc<parking_lot::Mutex<StateAdapter>>,
}

impl NodeStateRootProvider {
    /// Creates a new state root provider wrapping the given state adapter.
    pub fn new(state_adapter: Arc<parking_lot::Mutex<StateAdapter>>) -> Self {
        Self { state_adapter }
    }
}

impl StateRootProvider for NodeStateRootProvider {
    fn current_state_root(&self) -> Hash {
        self.state_adapter
            .lock()
            .compute_state_root()
    }
}

/// Provides finalized blocks to the consensus engine, backed by RocksDB.
///
/// `BlockProvider::get_block(height)` is **synchronous** because it is invoked
/// inside the consensus loop's hot path during proposal validation
/// (`HotStuff2Engine::handle_prepare_phase` → `proposer.validate_base_fee`)
/// and during proposal construction
/// (`propose_block_internal` → `proposer.propose_block`). The
/// `tenzro_storage::traits::BlockStore` trait is async, so we cannot call it
/// from sync code without spawning a runtime; instead we read the underlying
/// `KvStore` directly using the same key layout that `BlockStoreImpl` writes:
///   `height_hash:<u64-be>` (in `CF_BLOCKS`) → 32-byte block hash
///   `block_hash:<hash>`    (in `CF_BLOCKS`) → JSON-encoded `Block`
///
/// The decode is `serde_json` to match `BlockStoreImpl::decode_block`
/// (bincode 1.x cannot round-trip the internally-tagged `TransactionType`
/// enum — see the comment on `BlockStoreImpl::encode_block`).
///
/// This provider is consulted *after* `FinalityTracker::get_finalized_block`,
/// so it only carries the load on post-restart resume scenarios where the
/// in-memory cache has not yet been re-populated.
pub struct NodeBlockProvider {
    kv_store: Arc<dyn KvStore>,
}

impl NodeBlockProvider {
    /// Creates a new block provider backed by the given key-value store.
    pub fn new(kv_store: Arc<dyn KvStore>) -> Self {
        Self { kv_store }
    }
}

impl BlockProvider for NodeBlockProvider {
    fn get_block(&self, height: BlockHeight) -> Option<Block> {
        // Step 1: height → hash via the height_hash: index.
        let mut hash_key = b"height_hash:".to_vec();
        hash_key.extend_from_slice(&height.0.to_be_bytes());
        let hash_bytes = match self.kv_store.get(tenzro_storage::CF_BLOCKS, &hash_key) {
            Ok(Some(b)) => b,
            Ok(None) => return None,
            Err(e) => {
                warn!(height = ?height, error = %e, "NodeBlockProvider: height_hash lookup failed");
                return None;
            }
        };
        let hash = match Hash::from_bytes(&hash_bytes) {
            Some(h) => h,
            None => {
                warn!(height = ?height, "NodeBlockProvider: invalid hash bytes at height_hash key");
                return None;
            }
        };

        // Step 2: hash → block bytes via the block_hash: index.
        let mut block_key = b"block_hash:".to_vec();
        block_key.extend_from_slice(hash.as_bytes());
        let block_bytes = match self.kv_store.get(tenzro_storage::CF_BLOCKS, &block_key) {
            Ok(Some(b)) => b,
            Ok(None) => {
                warn!(height = ?height, "NodeBlockProvider: hash index points to missing block");
                return None;
            }
            Err(e) => {
                warn!(height = ?height, error = %e, "NodeBlockProvider: block_hash lookup failed");
                return None;
            }
        };

        // Step 3: JSON decode (matches BlockStoreImpl::encode_block).
        match serde_json::from_slice::<Block>(&block_bytes) {
            Ok(block) => Some(block),
            Err(e) => {
                warn!(height = ?height, error = %e, "NodeBlockProvider: block JSON decode failed");
                None
            }
        }
    }
}

/// The node event loop coordinates all subsystems
pub struct EventLoop {
    /// Event sender for submitting events (used by RPC/network)
    event_tx: mpsc::Sender<NodeEvent>,
    /// Event receiver
    event_rx: mpsc::Receiver<NodeEvent>,
    /// Shutdown broadcast
    shutdown_tx: broadcast::Sender<()>,
    /// Storage
    storage: Arc<RocksDbStore>,
    /// VM runtime
    vm_runtime: Arc<MultiVmRuntime>,
    /// State adapter for VM execution (tokio::Mutex for async-safe access during block execution)
    state_adapter: Arc<Mutex<StateAdapter>>,
    /// Consensus engine (optional, only for validators)
    consensus: Option<Arc<HotStuff2Engine>>,
    /// Network service (for broadcasting blocks to gossipsub)
    network: Option<Arc<TenzroNetworkService>>,
    /// Outbound consensus messages (votes, proposals) from the HotStuff-2 engine.
    ///
    /// The consensus engine produces these messages and they must be broadcast via
    /// gossipsub so peer validators can form quorum certificates. Without draining
    /// this channel, votes/proposals are silently dropped and the chain stalls.
    consensus_out_rx: Option<tokio::sync::mpsc::UnboundedReceiver<ConsensusOutMessage>>,
    /// Pending transactions (fallback for non-validator nodes without consensus)
    pending_txs: Vec<SignedTransaction>,
    /// Current finalized block height (synced from storage on startup)
    current_height: u64,
    /// Hash of the last finalized block
    last_block_hash: Hash,
    /// Live chain tip — shared with TenzroNode so RPC handlers can read it without
    /// storage I/O. Updated atomically on every finalized block (both local consensus
    /// and gossipsub network blocks). Initialized from storage on startup.
    ///
    /// Why not read CF_METADATA:latest_height?  BlockStoreImpl::put_block has a
    /// `should_update = height > latest` guard that freezes CF_METADATA when new
    /// blocks arrive at heights below the stored max (e.g. after a fresh start
    /// with stale PVC data).  This atomic bypasses that guard entirely.
    chain_tip: Arc<AtomicU64>,
    /// Metrics collector — updated on every finalized block (block count,
    /// transaction count, and live peer count from the network service).
    metrics: Arc<MetricsCollector>,
    /// Shared reference to the node's network_models map for gossipsub model discovery
    network_models: Option<Arc<DashMap<String, crate::node::NetworkModelEntry>>>,
    /// Shared reference to the node's served_models for heartbeat re-announcements
    served_models: Option<Arc<DashMap<String, bool>>>,
    /// Shared reference to the node's provider pricing for heartbeat announcements
    provider_pricing: Option<Arc<parking_lot::RwLock<crate::node::ProviderPricing>>>,
    /// Shared reference to the node's provider schedule for heartbeat announcements
    provider_schedule: Option<Arc<parking_lot::RwLock<crate::node::ProviderSchedule>>>,
    /// RPC address for constructing rpc_endpoint in announcements
    rpc_addr: String,
    /// Shared reference to model_services for cleanup of expired network endpoints
    model_services: Option<Arc<DashMap<String, tenzro_types::model::ModelServiceInstance>>>,
    /// Agent runtime for agent heartbeat announcements
    agent_runtime: Option<Arc<tenzro_agent::AgentRuntime>>,
    /// Swarm manager for periodic liveness sweep (auto-complete swarms whose
    /// members are all Terminated). Wired by `init_ai_infrastructure()` after
    /// `SwarmManager::with_storage()` has been constructed.
    swarm_manager: Option<Arc<tenzro_agent::SwarmManager>>,
    /// Shared reference to the node's network_agents map for gossipsub agent discovery
    network_agents: Option<Arc<DashMap<String, crate::node::NetworkAgentEntry>>>,
    /// Shared reference to the node's network_providers map for gossipsub provider discovery
    network_providers: Option<Arc<DashMap<String, crate::node::NetworkProviderEntry>>>,
    /// Shared reference to the ModelRuntime for idle-TTL liveness checks of
    /// local model service instances.
    model_runtime: Option<Arc<tenzro_model::ModelRuntime>>,
    /// Shared reference to the node's load tracker, so that when we evict an
    /// idle local model service we also unregister the per-model concurrency
    /// slot.
    load_tracker: Option<Arc<tenzro_model::LoadTracker>>,
    /// Shared reference to the node's `RemoteWorkerRegistry` used to ingest
    /// verified Cortex advertisements received over the
    /// `tenzro/cortex/1.0.0` gossipsub topic.
    remote_cortex_workers: Option<Arc<tenzro_cortex::RemoteWorkerRegistry>>,
}

impl EventLoop {
    /// Creates a new event loop
    ///
    /// # Arguments
    ///
    /// * `storage` - RocksDB storage backend
    /// * `vm_runtime` - Multi-VM runtime for executing transactions
    /// * `consensus` - Optional consensus engine (for validators)
    /// * `network` - Optional network service (for P2P communication)
    /// * `chain_tip` - Shared atomic tracking the live chain tip height (owned by TenzroNode,
    ///   updated here on every finalized block so RPC can read it lock-free)
    pub fn new(
        storage: Arc<RocksDbStore>,
        vm_runtime: Arc<MultiVmRuntime>,
        consensus: Option<Arc<HotStuff2Engine>>,
        network: Option<Arc<TenzroNetworkService>>,
        chain_tip: Arc<AtomicU64>,
        metrics: Arc<MetricsCollector>,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(10000);
        let (shutdown_tx, _) = broadcast::channel(1);

        // Create state adapter with storage backend, behind Mutex for shared access
        let state_adapter = Arc::new(Mutex::new(
            StateAdapter::with_storage(storage.clone() as Arc<dyn KvStore>)
        ));

        Self {
            event_tx,
            event_rx,
            shutdown_tx,
            storage,
            vm_runtime,
            state_adapter,
            consensus,
            network,
            consensus_out_rx: None,
            pending_txs: Vec::new(),
            current_height: 0,
            last_block_hash: Hash::zero(),
            chain_tip,
            metrics,
            network_models: None,
            served_models: None,
            provider_pricing: None,
            provider_schedule: None,
            rpc_addr: String::new(),
            model_services: None,
            agent_runtime: None,
            swarm_manager: None,
            network_agents: None,
            network_providers: None,
            model_runtime: None,
            load_tracker: None,
            remote_cortex_workers: None,
        }
    }

    /// Returns a clone of the event sender for RPC/network to submit events
    pub fn event_sender(&self) -> mpsc::Sender<NodeEvent> {
        self.event_tx.clone()
    }

    /// Wires the outbound consensus message receiver into the event loop.
    ///
    /// Called by `init_event_loop()` in `node.rs` after `init_consensus()` has created
    /// the channel and given the TX end to the `HotStuff2Engine`. The event loop's `run()`
    /// method drains this channel and broadcasts each vote/proposal over gossipsub so peer
    /// validators can observe them and form quorum certificates.
    pub fn with_consensus_out_rx(
        mut self,
        rx: tokio::sync::mpsc::UnboundedReceiver<ConsensusOutMessage>,
    ) -> Self {
        self.consensus_out_rx = Some(rx);
        self
    }

    /// Wires the network model discovery state into the event loop.
    pub fn with_model_discovery(
        mut self,
        network_models: Arc<DashMap<String, crate::node::NetworkModelEntry>>,
        served_models: Arc<DashMap<String, bool>>,
        provider_pricing: Arc<parking_lot::RwLock<crate::node::ProviderPricing>>,
        provider_schedule: Arc<parking_lot::RwLock<crate::node::ProviderSchedule>>,
        rpc_addr: String,
    ) -> Self {
        self.network_models = Some(network_models);
        self.served_models = Some(served_models);
        self.provider_pricing = Some(provider_pricing);
        self.provider_schedule = Some(provider_schedule);
        self.rpc_addr = rpc_addr;
        self
    }

    /// Wires the agent runtime into the event loop for gossipsub heartbeat announcements.
    pub fn with_agent_runtime(
        mut self,
        agent_runtime: Arc<tenzro_agent::AgentRuntime>,
    ) -> Self {
        self.agent_runtime = Some(agent_runtime);
        self
    }

    /// Wires the swarm manager into the event loop for periodic liveness sweep.
    pub fn with_swarm_manager(
        mut self,
        swarm_manager: Arc<tenzro_agent::SwarmManager>,
    ) -> Self {
        self.swarm_manager = Some(swarm_manager);
        self
    }

    /// Wires the model_services map for periodic cleanup of expired endpoints.
    pub fn with_model_services(
        mut self,
        model_services: Arc<DashMap<String, tenzro_types::model::ModelServiceInstance>>,
    ) -> Self {
        self.model_services = Some(model_services);
        self
    }

    /// Wires the ModelRuntime + load_tracker so the heartbeat tick can run the
    /// 1-hour idle TTL cleanup against live runtime state.
    pub fn with_model_runtime(
        mut self,
        model_runtime: Arc<tenzro_model::ModelRuntime>,
        load_tracker: Arc<tenzro_model::LoadTracker>,
    ) -> Self {
        self.model_runtime = Some(model_runtime);
        self.load_tracker = Some(load_tracker);
        self
    }

    /// Wires the network_agents map for gossipsub-discovered agent merging.
    pub fn with_agent_discovery(
        mut self,
        network_agents: Arc<DashMap<String, crate::node::NetworkAgentEntry>>,
    ) -> Self {
        self.network_agents = Some(network_agents);
        self
    }

    /// Wires the network_providers map for gossipsub-discovered provider merging.
    pub fn with_provider_discovery(
        mut self,
        network_providers: Arc<DashMap<String, crate::node::NetworkProviderEntry>>,
    ) -> Self {
        self.network_providers = Some(network_providers);
        self
    }

    /// Wires the shared `RemoteWorkerRegistry` so the event loop can ingest
    /// verified Cortex advertisements received on the
    /// `tenzro/cortex/1.0.0` gossipsub topic.
    pub fn with_cortex_registry(
        mut self,
        registry: Arc<tenzro_cortex::RemoteWorkerRegistry>,
    ) -> Self {
        self.remote_cortex_workers = Some(registry);
        self
    }

    /// Returns a reference to the state adapter for wiring into other subsystems.
    ///
    /// This allows `init_event_loop()` in `node.rs` to access the event loop's state
    /// adapter and create a `NodeStateRootProvider` that shares the same state, ensuring
    /// the consensus block proposer always reads the latest committed state root.
    pub fn state_adapter(&self) -> &Arc<Mutex<StateAdapter>> {
        &self.state_adapter
    }

    /// Returns the current finalized block height as a `BlockHeight`.
    ///
    /// Used by RPC handlers (e.g., `eth_blockNumber`) and consensus to query
    /// the latest finalized height without needing direct storage access.
    pub fn current_height(&self) -> BlockHeight {
        BlockHeight::from(self.current_height)
    }

    /// Returns the hash of the last finalized block.
    pub fn last_block_hash(&self) -> Hash {
        self.last_block_hash
    }

    /// Processes a `FinalityNotification` from the consensus engine.
    ///
    /// This is the typed entry point for the finality subscription in `run()`.
    /// It logs the notification details and delegates to `handle_block_finalized()`.
    async fn process_finality_notification(&mut self, notification: FinalityNotification) -> Result<()> {
        info!(
            height = notification.height.0,
            hash = %notification.hash,
            tx_count = notification.block.tx_count(),
            "Processing finality notification"
        );
        self.handle_block_finalized(notification.block).await
    }

    /// Submits a finalized block to the event loop for execution
    pub fn submit_block(&self, block: Block) -> std::result::Result<(), Box<mpsc::error::TrySendError<NodeEvent>>> {
        self.event_tx.try_send(NodeEvent::BlockFinalized(block)).map_err(Box::new)
    }

    /// Syncs the current block height from storage on startup.
    ///
    /// This ensures the event loop knows where to continue from after a restart,
    /// so block execution resumes at the correct height.
    async fn sync_height_from_storage(&mut self) -> Result<()> {
        let block_store = BlockStoreImpl::new(self.storage.clone())
            .map_err(|e| NodeError::Other(format!("Block store error: {}", e)))?;

        match block_store.latest_height().await {
            Ok(Some(height)) => {
                self.current_height = height.0;
                // Publish to the shared atomic so RPC can read it without storage I/O
                self.chain_tip.store(self.current_height, Ordering::Release);
                // Seed the consensus engine so it proposes blocks at N+1 (not 1) after restart.
                // resume_from_height() updates both the FinalityTracker's finalized height and
                // the ViewState's next proposal height, preventing duplicate block production.
                if let Some(ref consensus) = self.consensus {
                    consensus.resume_from_height(height);
                }
                info!(height = self.current_height, "Synced block height from storage");
            }
            Ok(None) => {
                self.current_height = 0;
                self.chain_tip.store(0, Ordering::Release);
                info!("No blocks in storage, starting from height 0");
            }
            Err(e) => {
                warn!(error = %e, "Failed to read latest height from storage, starting from 0");
                self.current_height = 0;
                self.chain_tip.store(0, Ordering::Release);
            }
        }

        Ok(())
    }

    /// Main event loop - processes events until shutdown
    ///
    /// This is the core coordination point. It:
    /// 1. Syncs block height from storage on startup
    /// 2. Subscribes to consensus finality notifications (if consensus is active)
    /// 3. Processes RPC/network events (new transactions, manual block submissions)
    /// 4. On finality notification: executes transactions, commits state, persists block
    /// 5. Periodically refreshes peer count (every 30s) so non-validator nodes report
    ///    accurate peer_count even when they never finalize blocks locally.
    pub async fn run(mut self) -> Result<()> {
        info!("Event loop starting");

        // Sync block height from persistent storage
        self.sync_height_from_storage().await?;

        // Admitted-mesh warm-up gate: before draining outbound consensus
        // messages, wait for the gossipsub mesh on `tenzro/consensus/1.0.0`
        // to form AND for at least one mesh peer to be admitted to the
        // local validator registry via the identify handshake.
        //
        // Two distinct races compose here:
        //
        // 1. **Mesh formation.** Without it, the very first proposal/vote
        //    fails with `NoPeersSubscribedToTopic` (rust-libp2p
        //    `behaviour.rs:1064`).
        //
        // 2. **Identify-driven admission.** Even after the mesh forms,
        //    receivers' `authorize_peer_for_topic` rejects messages from
        //    PeerIds not yet in the validator registry. Identify is a
        //    separate libp2p protocol from gossipsub — its single
        //    round-trip per peer can finish *after* gossipsub's GRAFT
        //    handshake. The window in between is where consensus messages
        //    are silently dropped, manifesting as `votes=1 threshold=N`
        //    on every validator and the chain stuck at height 0.
        //
        // `wait_for_admitted_mesh` collapses both gates: it returns once at
        // least `min_admitted` mesh peers are also in the validator
        // registry. In permissive mode (no registry installed — pre-genesis
        // or single-node), it falls back to the plain mesh peer count.
        //
        // **Retry until ready** (lesson from 2026-04-30 wedge — see
        // `hotstuff2.rs::resume_from_height` regression). Previously we
        // proceeded after a 30s timeout in "degraded mode", which in
        // production meant validator-0 booted with admitted=0, broadcast
        // proposals into the void, and never received the SyncInfo gossip
        // it needed to advance its pacemaker — so the wedge persisted
        // until manual intervention. Lighthouse and Lotus both rely on
        // flood_publish for liveness rather than gating, but they also do
        // not start consensus before the mesh has at least one peer. We
        // do the same: poll in 30s windows indefinitely, logging each
        // iteration so operators can diagnose stalls. A node that never
        // achieves admitted ≥ 1 is genuinely isolated and should not be
        // pretending to participate in consensus.
        // Subscribe to shutdown early so the warm-up loop below can be
        // interrupted cleanly while waiting for mesh peers.
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        if let Some(ref network) = self.network {
            const CONSENSUS_TOPIC: &str = "tenzro/consensus/1.0.0";
            const ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
            let warmup_start = std::time::Instant::now();
            let mut attempt: u32 = 0;
            'warmup: loop {
                attempt = attempt.saturating_add(1);
                tokio::select! {
                    biased;
                    _ = shutdown_rx.recv() => {
                        info!("Shutdown requested during mesh warm-up — exiting event loop");
                        return Ok(());
                    }
                    res = network.wait_for_admitted_mesh(CONSENSUS_TOPIC, 1, ATTEMPT_TIMEOUT) => {
                        match res {
                            Ok(count) if count >= 1 => {
                                info!(
                                    topic = CONSENSUS_TOPIC,
                                    admitted_mesh_peers = count,
                                    attempts = attempt,
                                    elapsed_secs = warmup_start.elapsed().as_secs(),
                                    "Admitted-mesh warm-up complete — first consensus publish safe"
                                );
                                break 'warmup;
                            }
                            Ok(count) => {
                                warn!(
                                    topic = CONSENSUS_TOPIC,
                                    admitted_mesh_peers = count,
                                    attempts = attempt,
                                    elapsed_secs = warmup_start.elapsed().as_secs(),
                                    "Admitted-mesh warm-up: still no admitted peers — \
                                     retrying (consensus will not start until at least 1 peer is admitted)"
                                );
                            }
                            Err(e) => {
                                warn!(
                                    topic = CONSENSUS_TOPIC,
                                    attempts = attempt,
                                    elapsed_secs = warmup_start.elapsed().as_secs(),
                                    error = %e,
                                    "Admitted-mesh warm-up: query failed — retrying"
                                );
                            }
                        }
                    }
                }
                // Brief backoff between attempts. wait_for_admitted_mesh
                // already polls every 100ms internally, so this just
                // adds a small breath between full 30s windows.
                tokio::select! {
                    biased;
                    _ = shutdown_rx.recv() => {
                        info!("Shutdown requested during mesh warm-up backoff — exiting event loop");
                        return Ok(());
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                }
            }
        }

        // Subscribe to consensus finality notifications if consensus is available.
        // This is how finalized blocks flow from HotStuff-2 into the execution pipeline.
        let mut finality_rx = self.consensus.as_ref().map(|c| c.subscribe_finality());

        // Periodic peer-count refresh: runs every 30 seconds regardless of block production.
        // Without this, non-validator nodes (model-provider, light clients) that never call
        // handle_block_finalized() would always report peer_count=0 in /status even when
        // they have active P2P connections.
        let mut peer_refresh = tokio::time::interval(std::time::Duration::from_secs(30));
        peer_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Heartbeat: re-announce locally served models every 60s so peers know they're still alive.
        // Also evicts expired entries from network_models.
        let mut model_heartbeat = tokio::time::interval(std::time::Duration::from_secs(60));
        model_heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Heartbeat: re-announce registered agents every 60s so peers can discover them via gossipsub.
        let mut agent_heartbeat = tokio::time::interval(std::time::Duration::from_secs(60));
        agent_heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Heartbeat: evict expired provider entries every 60s.
        let mut provider_heartbeat = tokio::time::interval(std::time::Duration::from_secs(60));
        provider_heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Registry reconcile: every 5 minutes, enforce task deadlines and purge
        // stale terminal tasks (30d), inactive/deprecated tools (30d), and
        // inactive/deprecated skills (30d). Runs out of the node event loop so
        // the expiry work happens even when no RPC pruning is triggered.
        let mut registry_reconcile = tokio::time::interval(std::time::Duration::from_secs(300));
        registry_reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip immediate fire at startup — startup hydration already did the work.
        registry_reconcile.tick().await;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Event loop shutting down");
                    break;
                }
                // Periodic peer count refresh — independent of block finalization.
                // Ensures /status always reflects the current P2P connection state.
                _ = peer_refresh.tick() => {
                    if let Some(ref network) = self.network {
                        if let Ok(peers) = network.connected_peers().await {
                            let count = peers.len() as u64;
                            self.metrics.set_peer_count(count);
                            debug!(peer_count = count, "Periodic peer count refresh");
                        }
                    }
                }
                // Model heartbeat: re-announce served models + evict expired network entries
                _ = model_heartbeat.tick() => {
                    // 1. Evict expired network model entries
                    if let Some(ref nm) = self.network_models {
                        let now = std::time::Instant::now();
                        nm.retain(|_key, entry| {
                            let ttl = std::time::Duration::from_secs(entry.registration.ttl_secs);
                            now.duration_since(entry.last_seen) < ttl
                        });
                    }

                    // 1b. Evict expired model service instances (network endpoints)
                    // Removes from in-memory DashMap AND persists deletion to RocksDB
                    if let Some(ref services) = self.model_services {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let ttl = 300; // 5 minutes
                        let expired: Vec<String> = services.iter()
                            .filter(|e| {
                                let svc = e.value();
                                matches!(svc.location, tenzro_types::model::ModelLocation::Network)
                                    && svc.last_seen > 0
                                    && now.saturating_sub(svc.last_seen) > ttl
                            })
                            .map(|e| e.key().clone())
                            .collect();
                        for id in &expired {
                            services.remove(id);
                            let _ = self.storage.delete(CF_MODEL_SERVICES, id.as_bytes());
                            info!("Removed expired network model service: {}", id);
                        }
                    }

                    // 1c. Idle-TTL cleanup for LOCAL model service instances.
                    // If the ModelRuntime is not currently serving the model AND
                    // the entry has been silent for >= 1 hour, evict it and
                    // clear the corresponding served_models flag.
                    // Runtime-live entries have their last_seen refreshed so the
                    // idle clock resets on every heartbeat.
                    if let (Some(services), Some(runtime)) =
                        (&self.model_services, &self.model_runtime)
                    {
                        const IDLE_TTL_SECS: u64 = 3600; // 1 hour
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();

                        let local_entries: Vec<(String, String, u64)> = services.iter()
                            .filter(|e| matches!(
                                e.value().location,
                                tenzro_types::model::ModelLocation::Local,
                            ))
                            .map(|e| (
                                e.key().clone(),
                                e.value().model_id.clone(),
                                e.value().last_seen,
                            ))
                            .collect();

                        let mut evicted = 0usize;
                        for (instance_id, model_id, last_seen) in local_entries {
                            if runtime.is_loaded(&model_id) {
                                // Runtime-live — refresh last_seen and persist
                                if let Some(mut svc) = services.get_mut(&instance_id) {
                                    if svc.last_seen < now {
                                        svc.last_seen = now;
                                        if let Ok(data) = serde_json::to_vec(svc.value()) {
                                            let _ = self.storage.put(
                                                CF_MODEL_SERVICES,
                                                instance_id.as_bytes(),
                                                &data,
                                            );
                                        }
                                    }
                                }
                                continue;
                            }

                            let idle = last_seen == 0
                                || now.saturating_sub(last_seen) >= IDLE_TTL_SECS;
                            if !idle {
                                continue;
                            }

                            services.remove(&instance_id);
                            let _ = self.storage.delete(
                                CF_MODEL_SERVICES,
                                instance_id.as_bytes(),
                            );
                            evicted += 1;

                            // Clear served_models flag + CF_MODELS if no other
                            // live Local instance exists for this model.
                            let still_served_locally = services.iter().any(|e| {
                                e.value().model_id == model_id
                                    && matches!(
                                        e.value().location,
                                        tenzro_types::model::ModelLocation::Local,
                                    )
                            });
                            if !still_served_locally {
                                if let Some(ref served) = self.served_models {
                                    served.remove(&model_id);
                                }
                                if let Some(ref lt) = self.load_tracker {
                                    lt.unregister_model(&model_id);
                                }
                                let _ = self.storage.delete(
                                    CF_MODELS,
                                    model_id.as_bytes(),
                                );
                                info!(
                                    "Cleared idle local serving state for model: {}",
                                    model_id,
                                );
                            }
                        }
                        if evicted > 0 {
                            info!(
                                "Evicted {} idle local model service(s) after 1h TTL",
                                evicted,
                            );
                        }
                    }

                    // 2. Re-announce locally served models via gossipsub
                    if let (Some(network), Some(served)) = (&self.network, &self.served_models) {
                        let pricing = self.provider_pricing.as_ref().map(|p| p.read().clone());
                        let schedule = self.provider_schedule.as_ref().map(|s| s.read().clone());
                        let rpc_addr = self.rpc_addr.clone();

                        for entry in served.iter() {
                            let model_id = entry.key().clone();
                            let pricing_info = tenzro_network::PricingInfo {
                                per_request: 0,
                                per_token: pricing.as_ref().map(|p| {
                                    (p.input_price_per_token * 1_000_000.0) as u64
                                }),
                            };
                            let msg_schedule = schedule.as_ref().and_then(|s| {
                                if s.enabled {
                                    let days: Vec<u8> = s.days_of_week.iter()
                                        .enumerate()
                                        .filter_map(|(i, &enabled)| if enabled { Some(i as u8) } else { None })
                                        .collect();
                                    Some(tenzro_network::ModelSchedule {
                                        enabled: true,
                                        start_hour: s.start_hour,
                                        end_hour: s.end_hour,
                                        timezone: s.timezone.clone(),
                                        days_of_week: days,
                                    })
                                } else {
                                    None
                                }
                            });
                            let reg = tenzro_network::ModelRegistrationMessage {
                                model_id: model_id.clone(),
                                name: model_id.clone(),
                                description: String::new(),
                                modality: "text".to_string(),
                                category: String::new(),
                                parameters: String::new(),
                                context_length: 0,
                                provider: String::new(),
                                peer_id: String::new(),
                                pricing: pricing_info,
                                schedule: msg_schedule,
                                visibility: "network".to_string(),
                                ttl_secs: 120,
                                withdrawn: false,
                                rpc_endpoint: format!("http://{}", rpc_addr),
                                ..Default::default()
                            };
                            let broadcast_msg = tenzro_network::NetworkMessage::new(
                                tenzro_network::MessagePayload::ModelRegistration(reg),
                            );
                            let net = network.clone();
                            tokio::spawn(async move {
                                if let Err(e) = net.broadcast("tenzro/models/1.0.0", broadcast_msg).await {
                                    debug!(error = %e, model_id = %model_id, "Failed to broadcast model heartbeat");
                                }
                            });
                        }
                    }
                }
                // Agent heartbeat: broadcast each registered agent as a typed AgentAnnouncement
                // every 60s + evict expired network_agents entries + auto-suspend agents
                // idle beyond the 1h TTL (mirrors the model-registry reconciliation sweep).
                _ = agent_heartbeat.tick() => {
                    // 1. Evict expired network agent entries
                    if let Some(ref na) = self.network_agents {
                        let now = std::time::Instant::now();
                        na.retain(|_key, entry| {
                            let ttl = std::time::Duration::from_secs(entry.announcement.ttl_secs);
                            now.duration_since(entry.last_seen) < ttl
                        });
                    }

                    // 2. Sweep locally registered agents for idle-TTL expiry. Any agent whose
                    // last heartbeat (or most recent state change, if no heartbeat has been
                    // received) is older than 3600s is auto-suspended. This prevents stale
                    // Active entries from accumulating across long-running nodes and mirrors
                    // the 1h idle TTL applied to served models in the model registry.
                    if let Some(ref ar) = self.agent_runtime {
                        let suspended = ar.check_idle_agents(3600).await;
                        if !suspended.is_empty() {
                            tracing::info!(
                                count = suspended.len(),
                                "Auto-suspended idle agents (1h TTL)"
                            );
                        }
                    }

                    // 3. Re-announce locally registered agents via gossipsub
                    if let (Some(network), Some(ar)) = (&self.network, &self.agent_runtime) {
                        let agents = ar.list_agents(None);
                        let rpc_addr = self.rpc_addr.clone();
                        for a in agents.iter() {
                            let cap_names: Vec<String> = a.capabilities.iter().map(|c| {
                                match c {
                                    tenzro_types::agent::Capability::NaturalLanguageProcessing { .. } => "NaturalLanguageProcessing".to_string(),
                                    tenzro_types::agent::Capability::ComputerVision { .. } => "ComputerVision".to_string(),
                                    tenzro_types::agent::Capability::CodeGeneration { .. } => "CodeGeneration".to_string(),
                                    tenzro_types::agent::Capability::DataAnalysis { .. } => "DataAnalysis".to_string(),
                                    tenzro_types::agent::Capability::BlockchainInteraction { .. } => "BlockchainInteraction".to_string(),
                                    tenzro_types::agent::Capability::SmartContractExecution => "SmartContractExecution".to_string(),
                                    tenzro_types::agent::Capability::ExternalAPIIntegration { .. } => "ExternalAPIIntegration".to_string(),
                                    tenzro_types::agent::Capability::MultiAgentCoordination => "MultiAgentCoordination".to_string(),
                                    tenzro_types::agent::Capability::Custom { name, .. } => name.clone(),
                                }
                            }).collect();
                            let ann = tenzro_network::AgentAnnouncementMessage {
                                agent_id: a.identity.agent_id.clone(),
                                name: a.identity.name.clone(),
                                agent_type: "tenzroclaw".to_string(),
                                capabilities: cap_names,
                                status: a.status.as_str().to_string(),
                                origin_peer_id: String::new(),
                                rpc_endpoint: format!("http://{}", rpc_addr),
                                timestamp: chrono::Utc::now().timestamp_millis(),
                                ttl_secs: 180,
                            };
                            let broadcast_msg = tenzro_network::NetworkMessage::new(
                                tenzro_network::MessagePayload::AgentAnnouncement(ann),
                            );
                            let net = network.clone();
                            let agent_id = a.identity.agent_id.clone();
                            tokio::spawn(async move {
                                if let Err(e) = net.broadcast("tenzro/agents/1.0.0", broadcast_msg).await {
                                    tracing::debug!(error = %e, agent_id = %agent_id, "Failed to broadcast agent heartbeat");
                                }
                            });
                        }
                    }
                }
                // Provider heartbeat: evict expired network_providers entries every 60s.
                _ = provider_heartbeat.tick() => {
                    if let Some(ref np) = self.network_providers {
                        let now = std::time::Instant::now();
                        np.retain(|_key, entry| {
                            let ttl = std::time::Duration::from_secs(entry.announcement.ttl_secs);
                            now.duration_since(entry.last_seen) < ttl
                        });
                    }
                }
                // Registry reconcile (5 min): enforce task deadlines + purge
                // stale terminal tasks / inactive tools / inactive skills.
                // Runs out of the event loop so the expiry happens passively
                // without waiting on operator-triggered RPC prunes.
                _ = registry_reconcile.tick() => {
                    // 30 day default for terminal purge.
                    const PURGE_TERMINAL_AFTER_SECS_I64: i64 = 30 * 24 * 3600;
                    const PURGE_TERMINAL_AFTER_SECS_U64: u64 = 30 * 24 * 3600;

                    let (expired, purged) = crate::node::reconcile_task_registry_storage(
                        &self.storage,
                        PURGE_TERMINAL_AFTER_SECS_I64,
                    );
                    if expired > 0 || purged > 0 {
                        info!(
                            expired, purged,
                            "Periodic task registry reconcile",
                        );
                    }

                    let tool_purged = crate::node::reconcile_tool_registry_storage(
                        &self.storage,
                        PURGE_TERMINAL_AFTER_SECS_U64,
                    );
                    if tool_purged > 0 {
                        info!(purged = tool_purged, "Periodic tool registry reconcile");
                    }

                    let skill_purged = crate::node::reconcile_skill_registry_storage(
                        &self.storage,
                        PURGE_TERMINAL_AFTER_SECS_U64,
                    );
                    if skill_purged > 0 {
                        info!(purged = skill_purged, "Periodic skill registry reconcile");
                    }

                    // Swarm liveness: auto-complete any swarm whose members
                    // are all in AgentState::Terminated. Persists the status
                    // transition to CF_AGENTS so it survives a restart.
                    if let Some(ref sm) = self.swarm_manager {
                        let completed = sm.check_swarm_liveness();
                        if !completed.is_empty() {
                            info!(
                                count = completed.len(),
                                "Periodic swarm liveness sweep: auto-completed swarms"
                            );
                        }
                    }
                }
                // Handle finality notifications from consensus engine.
                // When consensus finalizes a block (PREPARE → COMMIT → DECIDE),
                // the FinalityTracker broadcasts it here for execution.
                notification = async {
                    match finality_rx.as_mut() {
                        Some(rx) => rx.recv().await.ok(),
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(notification) = notification {
                        if let Err(e) = self.process_finality_notification(notification).await {
                            error!("Failed to handle finalized block: {}", e);
                        }
                    }
                }
                // Broadcast outbound consensus messages (votes, proposals) to peer validators.
                //
                // The HotStuff-2 engine produces ConsensusOutMessage values for every vote
                // cast and every block proposal made. Without draining this channel and
                // forwarding them over gossipsub, no validator can ever observe another
                // validator's vote and quorum certificates can never be formed — causing
                // the chain to stall permanently.
                outbound_consensus = async {
                    match self.consensus_out_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(msg) = outbound_consensus {
                        let dbg_kind = match &msg {
                            ConsensusOutMessage::Vote(_) => "Vote",
                            ConsensusOutMessage::Proposal { .. } => "Proposal",
                            ConsensusOutMessage::Timeout(_) => "Timeout",
                        };
                        info!(kind = dbg_kind, "event_loop.outbound_consensus: received msg from consensus engine");
                        if let Some(ref network) = self.network {
                            let net_payload = match msg {
                                ConsensusOutMessage::Vote(vote) => {
                                    let net_vote_type = match vote.vote_type {
                                        ConsVoteType::Prepare => NetVoteType::Prevote,
                                        ConsVoteType::Commit => NetVoteType::Precommit,
                                    };
                                    // Serialize hybrid signature and public key
                                    // for over-the-wire consumption. Bincode is
                                    // the canonical encoding used elsewhere in
                                    // the protocol. On encode failure, drop the
                                    // outbound message rather than killing the
                                    // event loop.
                                    let encoded = bincode::serialize(&vote.signature)
                                        .and_then(|s| bincode::serialize(&vote.public_key).map(|p| (s, p)));
                                    match encoded {
                                        Ok((sig_bytes, pk_bytes)) => {
                                            Some(MessagePayload::Consensus(ConsensusMessage::Vote {
                                                block_hash: vote.block_hash,
                                                voter: hex::encode(vote.voter.as_bytes()),
                                                vote_type: net_vote_type,
                                                round: vote.view,
                                                height: vote.height.0,
                                                high_qc_view: vote.high_qc_view,
                                                signature: sig_bytes,
                                                public_key: pk_bytes,
                                            }))
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "Failed to encode hybrid vote payload; dropping");
                                            None
                                        }
                                    }
                                }
                                ConsensusOutMessage::Proposal {
                                    block,
                                    proposer,
                                    round,
                                    view: _,
                                    high_qc_view,
                                    timeout_certificate,
                                } => {
                                    // Serialize TC if present. Drop encode failures
                                    // (the proposal still goes out without it; the
                                    // leader's high_qc will sit at the previous view
                                    // anyway, so peers only lose the safe_to_extend
                                    // amplification — they fall back to vote on the
                                    // happy path criterion).
                                    let tc_bytes = timeout_certificate.as_ref().and_then(|tc| {
                                        match bincode::serialize(tc) {
                                            Ok(b) => Some(b),
                                            Err(e) => {
                                                warn!(error = %e, "Failed to encode TC; dropping from proposal");
                                                None
                                            }
                                        }
                                    });
                                    Some(MessagePayload::Consensus(ConsensusMessage::Proposal {
                                        block,
                                        proposer: hex::encode(proposer.as_bytes()),
                                        round,
                                        high_qc_view,
                                        timeout_certificate: tc_bytes,
                                    }))
                                }
                                ConsensusOutMessage::Timeout(timeout_msg) => {
                                    // Serialize hybrid signature and composite
                                    // public key for over-the-wire consumption.
                                    // Same encoding strategy as Vote — bincode
                                    // round-trippable on the receiver, drop the
                                    // outbound message on encode failure rather
                                    // than crash the pacemaker.
                                    let encoded = bincode::serialize(&timeout_msg.signature)
                                        .and_then(|s| bincode::serialize(&timeout_msg.public_key).map(|p| (s, p)));
                                    match encoded {
                                        Ok((sig_bytes, pk_bytes)) => {
                                            Some(MessagePayload::Consensus(ConsensusMessage::Timeout {
                                                format_version: timeout_msg.format_version,
                                                view: timeout_msg.view,
                                                high_qc_view: timeout_msg.high_qc_view,
                                                voter: timeout_msg.voter,
                                                signature: sig_bytes,
                                                public_key: pk_bytes,
                                            }))
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "Failed to encode hybrid timeout payload; dropping");
                                            None
                                        }
                                    }
                                }
                            };
                            if let Some(payload) = net_payload {
                                let broadcast_msg = NetworkMessage::new(payload);
                                let network_clone = network.clone();
                                info!("event_loop.outbound_consensus: spawning broadcast to tenzro/consensus/1.0.0");
                                tokio::spawn(async move {
                                    match network_clone.broadcast("tenzro/consensus/1.0.0", broadcast_msg).await {
                                        Ok(_) => info!("event_loop.outbound_consensus: broadcast OK"),
                                        Err(e) => warn!(error = %e, "event_loop.outbound_consensus: broadcast FAILED"),
                                    }
                                });
                            } else {
                                warn!("event_loop.outbound_consensus: net_payload was None (encoding failed)");
                            }
                        }
                    }
                }
                // Handle events from RPC/network
                Some(event) = self.event_rx.recv() => {
                    match event {
                        NodeEvent::NewTransaction(tx) => {
                            if let Err(e) = self.handle_new_transaction(tx).await {
                                error!("Failed to handle transaction: {}", e);
                            }
                        }
                        NodeEvent::BlockFinalized(block) => {
                            if let Err(e) = self.handle_block_finalized(block).await {
                                error!("Failed to handle finalized block: {}", e);
                            }
                        }
                        NodeEvent::NetworkBlock(block) => {
                            // Dedup against our finalized chain head BEFORE doing any
                            // work. Without this, gossiped historical blocks (whose
                            // libp2p dedup window has expired) re-enter the local
                            // execution pipeline, get re-finalized, get re-broadcast,
                            // and the resulting feedback loop pins all four validators
                            // at OOM in ~4 hours while consensus loses CPU and stops
                            // electing leaders. See also handle_block_finalized() —
                            // both entry points must be idempotent on already-known
                            // heights.
                            if block.height().0 <= self.current_height {
                                debug!(
                                    received = block.height().0,
                                    current = self.current_height,
                                    "Dropping gossiped block at or below finalized height"
                                );
                                continue;
                            }
                            // Submit for finalization so the execution pipeline runs
                            // even when this node is not the active consensus proposer
                            let _ = self.submit_block(block.clone());
                            if let Err(e) = self.handle_network_block(block).await {
                                error!("Failed to handle network block: {}", e);
                            }
                        }
                        NodeEvent::ModelAnnouncement(reg) => {
                            if let Some(ref nm) = self.network_models {
                                let key = format!("{}:{}", reg.model_id, reg.provider);
                                if reg.withdrawn {
                                    nm.remove(&key);
                                    // Remove from persistent storage
                                    {
                                        let storage_key = format!("net_model:{}", key);
                                        let _ = self.storage.delete(tenzro_storage::CF_MODEL_SERVICES, storage_key.as_bytes());
                                    }
                                    info!(
                                        model_id = %reg.model_id,
                                        provider = %reg.provider,
                                        "Network model withdrawn"
                                    );
                                } else if reg.visibility == "network" {
                                    nm.insert(key.clone(), crate::node::NetworkModelEntry {
                                        registration: reg.clone(),
                                        last_seen: std::time::Instant::now(),
                                    });
                                    // Persist to RocksDB so model endpoints survive restart
                                    {
                                        let storage_key = format!("net_model:{}", key);
                                        if let Ok(bytes) = serde_json::to_vec(&reg) {
                                            let _ = self.storage.put(tenzro_storage::CF_MODEL_SERVICES, storage_key.as_bytes(), &bytes);
                                        }
                                    }
                                    info!(
                                        model_id = %reg.model_id,
                                        provider = %reg.provider,
                                        rpc_endpoint = %reg.rpc_endpoint,
                                        "Network model discovered via gossipsub (persisted)"
                                    );
                                }
                            }
                        }
                        NodeEvent::AgentAnnouncement(ann) => {
                            if let Some(ref na) = self.network_agents {
                                na.insert(ann.agent_id.clone(), crate::node::NetworkAgentEntry {
                                    announcement: ann.clone(),
                                    last_seen: std::time::Instant::now(),
                                });
                                info!(
                                    agent_id = %ann.agent_id,
                                    origin_peer_id = %ann.origin_peer_id,
                                    rpc_endpoint = %ann.rpc_endpoint,
                                    "Network agent discovered via gossipsub"
                                );
                            }
                        }
                        NodeEvent::ProviderAnnouncement(ann) => {
                            if let Some(ref np) = self.network_providers {
                                np.insert(ann.peer_id.clone(), crate::node::NetworkProviderEntry {
                                    announcement: ann.clone(),
                                    last_seen: std::time::Instant::now(),
                                });
                                info!(
                                    peer_id = %ann.peer_id,
                                    provider_type = %ann.provider_type,
                                    rpc_endpoint = %ann.rpc_endpoint,
                                    "Network provider discovered via gossipsub"
                                );
                            }
                        }
                        NodeEvent::CortexAdvertisementReceived(bytes) => {
                            match serde_json::from_slice::<tenzro_cortex::CortexAdvertisement>(&bytes) {
                                Ok(ad) => {
                                    let worker_did = ad.worker_did.clone();
                                    let model_id = ad.model_id.clone();
                                    if let Err(e) = ad.verify() {
                                        warn!(
                                            worker_did = %worker_did,
                                            error = %e,
                                            "Rejecting cortex advertisement (signature/expiry verification failed)"
                                        );
                                    } else if let Some(ref registry) = self.remote_cortex_workers {
                                        match registry.ingest(ad) {
                                            Ok(()) => {
                                                info!(
                                                    worker_did = %worker_did,
                                                    model_id = %model_id,
                                                    "Ingested cortex advertisement from gossipsub"
                                                );
                                            }
                                            Err(e) => warn!(
                                                worker_did = %worker_did,
                                                error = %e,
                                                "Failed to ingest cortex advertisement"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            worker_did = %worker_did,
                                            "Dropping cortex advertisement (registry not wired into event loop)"
                                        );
                                    }
                                }
                                Err(e) => warn!(
                                    error = %e,
                                    "Failed to decode cortex advertisement JSON payload"
                                ),
                            }
                        }
                        NodeEvent::Shutdown => {
                            info!("Shutdown event received");
                            break;
                        }
                    }
                }
            }
        }

        info!("Event loop stopped");
        self.shutdown();
        Ok(())
    }

    /// Handles a new transaction from RPC or network.
    ///
    /// Validates the transaction (signature, gas, public key) and forwards it
    /// to the consensus mempool for inclusion in a future block. If no consensus
    /// engine is available (non-validator node), stores locally as a fallback.
    async fn handle_new_transaction(&mut self, mut tx: SignedTransaction) -> Result<()> {
        let tx_hash = tx.hash();

        // Basic validation
        if tx.signature.bytes.is_empty() {
            warn!("Rejecting transaction with empty signature: {}", tx_hash);
            return Err(NodeError::InvalidTransaction("Empty signature".to_string()));
        }

        if tx.signature.public_key.is_empty() {
            warn!("Rejecting transaction with empty public key: {}", tx_hash);
            return Err(NodeError::InvalidTransaction("Empty public key".to_string()));
        }

        if tx.transaction.gas_limit == 0 {
            warn!("Rejecting transaction with zero gas limit: {}", tx_hash);
            return Err(NodeError::InvalidTransaction("Zero gas limit".to_string()));
        }

        // Verify transaction signature cryptographically.
        // This prevents unauthorized transactions from entering the mempool/consensus.
        if let Err(e) = verify_transaction_signature(&tx) {
            warn!(
                hash = %tx_hash,
                error = %e,
                "Rejecting transaction with invalid signature"
            );
            return Err(NodeError::InvalidTransaction(format!("Invalid signature: {}", e)));
        }

        info!(
            hash = %tx_hash,
            from = %tx.transaction.from,
            to = %tx.transaction.to,
            gas_limit = tx.transaction.gas_limit,
            gas_price = tx.transaction.gas_price,
            "New transaction received and validated"
        );

        // Forward to consensus mempool if consensus engine is available.
        // This is the primary path: validated transactions enter the mempool,
        // where the block proposer selects them for inclusion in new blocks.
        let mut admitted_locally = false;
        if let Some(consensus) = &self.consensus {
            match consensus.submit_transaction(tx.clone()) {
                Ok(()) => {
                    info!(
                        hash = %tx_hash,
                        "Transaction submitted to consensus mempool"
                    );
                    admitted_locally = true;
                }
                Err(e) => {
                    warn!(
                        hash = %tx_hash,
                        error = %e,
                        "Failed to submit to consensus mempool, storing locally"
                    );
                    self.pending_txs.push(tx.clone());
                }
            }
        }

        // Gossip to peers regardless of local consensus admission so other
        // validators (and follower nodes) can pick up the tx and include it in
        // blocks they propose. This dual-path admission ensures tx propagation
        // whether the current node is the next proposer or not, and survives
        // transient single-node mempool rejection.
        if let Some(ref network) = self.network {
            let payload = serde_json::to_vec(&tx).unwrap_or_default();
            let topic = "tenzro/transactions/1.0.0".to_string();
            let msg = tenzro_network::NetworkMessage::new(
                tenzro_network::MessagePayload::Custom { topic: topic.clone(), data: payload },
            );
            if let Err(e) = network.broadcast(&topic, msg).await {
                warn!(hash = %tx_hash, error = %e, "Failed to broadcast transaction to gossipsub");
                if !admitted_locally {
                    self.pending_txs.push(tx);
                }
            } else {
                info!(hash = %tx_hash, "Transaction forwarded to peers via gossipsub");
            }
        } else if !admitted_locally {
            // No network and no local consensus admission — store locally as last resort
            self.pending_txs.push(tx);
            info!(hash = %tx_hash, "Transaction stored locally (no network)");
        }

        Ok(())
    }

    /// Handles a finalized block from consensus.
    ///
    /// This is the block execution pipeline:
    /// 1. Verify each transaction signature (defense-in-depth)
    /// 2. Execute each transaction via the VM runtime
    /// 3. Commit all state changes to RocksDB with fsync
    /// 4. Persist the block to storage
    /// 5. Update local height/hash tracking
    /// 6. Clean up finalized transactions from pending pool
    async fn handle_block_finalized(&mut self, block: Block) -> Result<()> {
        let block_hash = block.hash();
        let block_height = block.height();
        let tx_count = block.tx_count();

        // Idempotency guard: if we've already finalized this height locally, do
        // not re-execute. Re-execution against current state writes garbage
        // state roots, double-broadcasts the block back into gossipsub, and
        // amplifies a self-sustaining storm with peers — the underlying cause
        // of the testnet OOMKill cycle. The first dedup happens at the
        // NetworkBlock entry point in run(); this guard catches any other
        // event source (consensus emitting BlockFinalized, RPC submit_block,
        // future paths) that bypasses that check.
        if block_height.0 <= self.current_height {
            debug!(
                received = %block_height,
                current = self.current_height,
                hash = %block_hash,
                "Skipping finalized-block event at or below current height"
            );
            return Ok(());
        }

        info!(
            height = %block_height,
            hash = %block_hash,
            tx_count = tx_count,
            "Processing finalized block"
        );

        // Update block/transaction metrics
        self.metrics.record_block();
        self.metrics.record_transaction(tx_count as u64);
        // Refresh peer count on every finalized block so the metric stays current
        if let Some(ref network) = self.network {
            if let Ok(peers) = network.connected_peers().await {
                self.metrics.set_peer_count(peers.len() as u64);
            }
        }

        // Execute all transactions in the block
        let mut gas_used_total = 0u64;
        let mut successful_txs = 0;
        let mut failed_txs = 0;

        // Per-tx receipts collected during execution; persisted alongside the
        // tx index after the block commits so `eth_getTransactionReceipt` can
        // report real status/gas_used/logs instead of fabricating values.
        let mut receipts_for_index: Vec<(Hash, TxReceiptRecord)> =
            Vec::with_capacity(block.transactions.len());

        for signed_tx in &block.transactions {
            let tx_hash = signed_tx.transaction.hash();

            // Defense-in-depth: verify signature even for consensus-approved transactions.
            // This catches any bugs in consensus signature verification.
            if let Err(e) = verify_transaction_signature(signed_tx) {
                error!(
                    tx_hash = %tx_hash,
                    error = %e,
                    "Skipping transaction with invalid signature in finalized block"
                );
                failed_txs += 1;
                // No receipt is emitted: a sig-invalid tx that reached a finalized
                // block represents a consensus-level violation, not a normal failure
                // observable via eth_getTransactionReceipt.
                continue;
            }

            let vm_tx = convert_transaction(signed_tx);

            debug!(
                tx_hash = %tx_hash,
                from = hex::encode(&vm_tx.from),
                gas_limit = vm_tx.gas_limit,
                "Executing transaction"
            );

            // Acquire state adapter lock for VM execution (tokio::Mutex, safe to hold across .await)
            let result = {
                let mut state_adapter = self.state_adapter.lock().await;
                self.vm_runtime.execute_transaction(&vm_tx, &mut *state_adapter).await
            };

            match result {
                Ok(result) => {
                    gas_used_total += result.gas_used;
                    if result.success {
                        successful_txs += 1;
                        debug!(
                            tx_hash = %tx_hash,
                            gas_used = result.gas_used,
                            "Transaction executed successfully"
                        );
                    } else {
                        failed_txs += 1;
                        warn!(
                            tx_hash = %tx_hash,
                            gas_used = result.gas_used,
                            revert_reason = ?result.revert_reason,
                            "Transaction execution reverted"
                        );
                    }

                    let logs: Vec<TxReceiptLog> = result.logs.iter().map(|l| TxReceiptLog {
                        address: hex::encode(&l.address),
                        topics: l.topics.iter().map(hex::encode).collect(),
                        data: hex::encode(&l.data),
                    }).collect();

                    receipts_for_index.push((
                        tx_hash,
                        TxReceiptRecord {
                            success: result.success,
                            gas_used: result.gas_used,
                            cumulative_gas_used: gas_used_total,
                            effective_gas_price: signed_tx.transaction.gas_price,
                            revert_reason: result.revert_reason.clone(),
                            contract_address: result.contract_address
                                .as_ref()
                                .map(hex::encode),
                            logs,
                        },
                    ));
                }
                Err(e) => {
                    failed_txs += 1;
                    error!(
                        tx_hash = %tx_hash,
                        error = %e,
                        "Transaction execution failed"
                    );
                    // Record an explicit failure receipt so downstream callers
                    // get a deterministic answer rather than a missing-record
                    // null. EVM convention for execution errors is to charge
                    // the full gas_limit (no partial-consumption accounting
                    // when execution didn't return a result).
                    let charged = signed_tx.transaction.gas_limit;
                    gas_used_total = gas_used_total.saturating_add(charged);
                    receipts_for_index.push((
                        tx_hash,
                        TxReceiptRecord {
                            success: false,
                            gas_used: charged,
                            cumulative_gas_used: gas_used_total,
                            effective_gas_price: signed_tx.transaction.gas_price,
                            revert_reason: Some(format!("vm_error: {}", e)),
                            contract_address: None,
                            logs: Vec::new(),
                        },
                    ));
                }
            }
        }

        // Commit state changes to storage.
        // Use spawn_blocking to offload synchronous RocksDB writes to the blocking thread
        // pool (separate from tokio worker threads). This keeps worker threads free to
        // respond to health probes and RPC requests even when only 1 worker thread is
        // available (as is the case with 500m CPU limit on GKE).
        //
        // block_in_place() would NOT work here because it "migrates async tasks to other
        // worker threads" — but with only 1 worker thread, there are no other threads to
        // migrate to, so the health endpoint still starves. spawn_blocking() uses a
        // completely separate thread pool (default: up to 512 threads) and immediately
        // yields the worker thread back to the async scheduler.
        let state_arc = self.state_adapter.clone();
        let state_root = tokio::task::spawn_blocking(move || -> std::result::Result<Hash, NodeError> {
            let state_adapter = state_arc.blocking_lock();
            state_adapter.commit()
                .map_err(|e| NodeError::Other(format!("State commit error: {}", e)))?;
            Ok(state_adapter.compute_state_root())
        })
        .await
        .map_err(|e| NodeError::Other(format!("State commit task panicked: {}", e)))??;

        info!(
            height = %block_height,
            state_root = %state_root,
            "State committed"
        );

        // Persist the block to storage via the blocking thread pool.
        // Also index each transaction into CF_TRANSACTIONS keyed by its hex-encoded
        // hash so `tenzro_getTransaction` can look them up after finalization,
        // and persist the per-tx receipts collected during execution so
        // `eth_getTransactionReceipt` reports real status/gas_used/logs.
        let block_for_store = block.clone();
        let storage_for_store = self.storage.clone();
        let txs_for_index: Vec<SignedTransaction> = block.transactions.clone();
        let receipts_for_persist = receipts_for_index;
        tokio::task::spawn_blocking(move || -> std::result::Result<(), NodeError> {
            tokio::runtime::Handle::current().block_on(async move {
                let mut block_store = BlockStoreImpl::new(storage_for_store.clone())
                    .map_err(NodeError::Storage)?;
                block_store.put_block(&block_for_store).await
                    .map_err(NodeError::Storage)?;

                // Build a batched, fsync'd write of per-transaction records.
                //
                // Three kinds of records under CF_TRANSACTIONS:
                //   1. `<hex_hash>` → JSON-encoded SignedTransaction
                //      (format matches rpc::handle_get_transaction reader)
                //   2. `idx:<hex_hash>` → JSON { block_height, block_hash, tx_index }
                //      (lets eth_getTransactionReceipt locate the containing block
                //      without scanning CF_BLOCKS)
                //   3. `receipt:<hex_hash>` → JSON-encoded TxReceiptRecord
                //      (real exec status, gas_used, logs — read by
                //      eth_getTransactionReceipt instead of fabricating)
                if !txs_for_index.is_empty() {
                    let block_hash_hex = block_hash.to_string();
                    let block_height_u64 = block_height.0;
                    let mut ops: Vec<WriteOp> = Vec::with_capacity(txs_for_index.len() * 3);
                    for (tx_index, signed_tx) in txs_for_index.iter().enumerate() {
                        let tx_hash = signed_tx.transaction.hash();
                        let hex_key = tx_hash.to_string();
                        match serde_json::to_vec(signed_tx) {
                            Ok(value) => ops.push(WriteOp::Put {
                                cf: CF_TRANSACTIONS.to_string(),
                                key: hex_key.as_bytes().to_vec(),
                                value,
                            }),
                            Err(e) => {
                                warn!(
                                    tx_hash = %tx_hash,
                                    error = %e,
                                    "Failed to serialize transaction for CF_TRANSACTIONS index; skipping"
                                );
                                continue;
                            }
                        }
                        let idx_value = serde_json::json!({
                            "block_height": block_height_u64,
                            "block_hash": block_hash_hex,
                            "tx_index": tx_index,
                        });
                        if let Ok(idx_bytes) = serde_json::to_vec(&idx_value) {
                            ops.push(WriteOp::Put {
                                cf: CF_TRANSACTIONS.to_string(),
                                key: format!("idx:{}", hex_key).into_bytes(),
                                value: idx_bytes,
                            });
                        }
                    }

                    // Persist per-tx receipts. A sig-invalid tx in a finalized
                    // block has no receipt entry by design (see exec loop).
                    for (tx_hash, receipt) in &receipts_for_persist {
                        let hex_key = tx_hash.to_string();
                        match serde_json::to_vec(receipt) {
                            Ok(value) => ops.push(WriteOp::Put {
                                cf: CF_TRANSACTIONS.to_string(),
                                key: format!("receipt:{}", hex_key).into_bytes(),
                                value,
                            }),
                            Err(e) => {
                                warn!(
                                    tx_hash = %tx_hash,
                                    error = %e,
                                    "Failed to serialize tx receipt; skipping"
                                );
                            }
                        }
                    }

                    if !ops.is_empty() {
                        storage_for_store
                            .write_batch_sync(ops)
                            .map_err(NodeError::Storage)?;
                    }
                }

                Ok::<(), NodeError>(())
            })
        })
        .await
        .map_err(|e| NodeError::Other(format!("Block persist task panicked: {}", e)))??;

        // Update local height and hash tracking — only when this block extends the tip.
        // During gossip-driven catch-up the network may deliver historical blocks (out-of-order
        // or fork-resolution backfills) that finalize successfully but must NOT rewind the tip.
        // The block_hash mirror is only valid for the actual tip, so it's only updated alongside.
        if block_height.0 > self.current_height {
            self.current_height = block_height.0;
            self.last_block_hash = block_hash;
        }

        // Publish the new chain tip to the shared atomic so RPC can read the live height
        // without any storage I/O.  Use fetch_max so historical-block finalization (out-of-order
        // gossip during catch-up, fork-resolution backfills) cannot rewind the published tip.
        // Release ordering ensures all prior writes (block persist, state commit) are visible
        // to the Acquire load in the RPC handler.
        self.chain_tip.fetch_max(block_height.0, Ordering::Release);

        info!(
            height = %block_height,
            hash = %block_hash,
            tx_count = tx_count,
            successful = successful_txs,
            failed = failed_txs,
            gas_used = gas_used_total,
            state_root = %state_root,
            "Block finalized and persisted"
        );

        // Advance the EIP-1559 fee market. The oracle's `on_block_finalized`
        // pushes a new entry onto the base-fee history and adjusts the
        // next-block base fee per EIP-1559 §3. This is a no-op when no
        // FeeMarket is wired (single-node test harness paths).
        self.vm_runtime
            .gas_oracle()
            .on_block_finalized(gas_used_total)
            .await;

        // Remove finalized transactions from pending pool
        let finalized_hashes: Vec<Hash> = block.transactions.iter()
            .map(|tx| tx.transaction.hash())
            .collect();

        self.pending_txs.retain(|tx| !finalized_hashes.contains(&tx.transaction.hash()));

        // Broadcast finalized block to gossipsub so other nodes can sync.
        // Only the block producer (node with consensus engine) broadcasts.
        // Non-validators receive blocks via gossipsub and should NOT re-broadcast
        // (gossipsub handles propagation internally).
        //
        // IMPORTANT: This is done via tokio::spawn (fire-and-forget) to prevent
        // deadlocking the event loop. If called inline with .await, the following
        // deadlock can occur when the validator broadcasts its own block:
        //   1. broadcast().await waits for the network service's command channel
        //   2. The network service receives the block back via gossipsub self-loop
        //   3. It tries to deliver to the block-sync subscriber channel
        //   4. That channel's receiver (this event loop) is blocked in step 1
        //   5. DEADLOCK — with limited CPU (500m), this starves the web server too
        if self.consensus.is_some() {
            if let Some(ref network) = self.network {
                let network_clone = network.clone();
                let msg = NetworkMessage::new(MessagePayload::Block(block.clone()));
                let height_for_log = block_height;
                let hash_for_log = block_hash;
                tokio::spawn(async move {
                    if let Err(e) = network_clone.broadcast("tenzro/blocks/1.0.0", msg).await {
                        warn!(
                            height = %height_for_log,
                            error = %e,
                            "Failed to broadcast finalized block to gossipsub"
                        );
                    } else {
                        info!(
                            height = %height_for_log,
                            hash = %hash_for_log,
                            "Broadcast finalized block to network"
                        );
                    }
                });
            }
        }

        Ok(())
    }

    /// Handles a block received from the network via gossipsub.
    ///
    /// This is the block import pipeline for non-producing nodes:
    /// 1. Skip blocks at or behind our current height (duplicates)
    /// 2. Validate sequential height (warn on gaps for testnet)
    /// 3. Validate prev_hash chain continuity (warn on mismatch for testnet)
    /// 4. Delegate to `handle_block_finalized()` for execution + persistence
    ///
    /// On testnet, blocks with height gaps or prev_hash mismatches are accepted
    /// with warnings. In production, strict validation with gap recovery via
    /// BlockRequest/BlockResponse would be required.
    async fn handle_network_block(&mut self, block: Block) -> Result<()> {
        let block_height = block.height();
        let block_hash = block.hash();
        let expected_height = self.current_height + 1;

        // Skip blocks we already have (at or behind our height)
        if block_height.0 <= self.current_height {
            debug!(
                received = block_height.0,
                current = self.current_height,
                "Skipping network block at or behind current height"
            );
            return Ok(());
        }

        // Check for sequential height
        if block_height.0 != expected_height {
            warn!(
                expected = expected_height,
                received = block_height.0,
                "Received out-of-order block from network (gap detected)"
            );
            // Testnet: accept anyway to avoid getting stuck
            // Production: would request missing blocks via BlockRequest
        }

        // Validate prev_hash continuity (skip for height 1 where prev is genesis)
        if self.current_height > 0 && block.header.prev_hash != self.last_block_hash {
            warn!(
                height = block_height.0,
                expected_prev = %self.last_block_hash,
                actual_prev = %block.header.prev_hash,
                "Network block prev_hash mismatch — possible fork"
            );
            // Testnet: accept anyway to maintain sync
            // Production: fork choice rule would decide
        }

        info!(
            height = block_height.0,
            hash = %block_hash,
            tx_count = block.tx_count(),
            "Importing block from network"
        );

        // Execute and persist via the same pipeline as locally-finalized blocks
        self.handle_block_finalized(block).await
    }

    /// Initiates shutdown
    pub fn shutdown(&self) {
        let _ = self.event_tx.try_send(NodeEvent::Shutdown);
        let _ = self.shutdown_tx.send(());
    }
}

/// Verifies the hybrid (classical + ML-DSA-65) signature of a transaction.
///
/// Per Wave 3d of the post-quantum migration, every admitted transaction must
/// satisfy both legs of the composite signature:
///
/// 1. Classical Ed25519 over `Transaction::hash()` using the public key carried
///    in `signed_tx.signature.public_key`.
/// 2. ML-DSA-65 (FIPS 204) over `Transaction::hash()` using the verifying key
///    carried in `signed_tx.transaction.pq_public_key`.
///
/// Both legs are mandatory. There is no fallback to classical-only — an
/// adversary forging a transaction must therefore break both Ed25519 AND
/// ML-DSA-65, which is the entire point of the hybrid window.
///
/// Returns `Ok(())` only when both legs verify; `Err(InvalidTransaction)`
/// otherwise.
fn verify_transaction_signature(signed_tx: &SignedTransaction) -> Result<()> {
    use tenzro_crypto::{PublicKey, KeyType, signatures};

    // Compute the transaction hash (this is the signed message for both legs).
    let tx_hash = signed_tx.transaction.hash();
    let message = tx_hash.as_bytes();

    // 1. Classical Ed25519 leg.
    let crypto_sig = tenzro_crypto::Signature::new(
        KeyType::Ed25519,
        signed_tx.signature.bytes.clone(),
    );
    let public_key = PublicKey::new(KeyType::Ed25519, signed_tx.signature.public_key.clone());
    signatures::verify(&public_key, message, &crypto_sig).map_err(|e| {
        NodeError::InvalidTransaction(format!(
            "Classical Ed25519 signature verification failed: {}",
            e
        ))
    })?;

    // 2. Post-quantum ML-DSA-65 leg. The verifying key (1952 bytes) is bound
    //    to the transaction hash via `Transaction::hash()` itself — see
    //    `tenzro_types::transaction::Transaction::hash` which commits to
    //    `pq_public_key`. The signature (3309 bytes) is in `signed_tx.pq_signature`.
    tenzro_crypto::pq::ml_dsa_verify(
        &signed_tx.transaction.pq_public_key,
        message,
        &signed_tx.pq_signature,
    )
    .map_err(|e| {
        NodeError::InvalidTransaction(format!(
            "ML-DSA-65 signature verification failed: {}",
            e
        ))
    })?;

    Ok(())
}

/// Converts a SignedTransaction to a VmTransaction
fn convert_transaction(signed_tx: &SignedTransaction) -> VmTransaction {
    let tx = &signed_tx.transaction;

    // Extract value, data, and VM type based on transaction type
    let (value, data, vm_type) = match &tx.tx_type {
        TransactionType::Transfer { amount } => (*amount, Vec::new(), VmType::Tenzro),
        TransactionType::ContractCall { function, args } => {
            let mut data = function.as_bytes().to_vec();
            data.extend_from_slice(args);
            (0, data, VmType::Evm)
        }
        TransactionType::ContractDeploy { code, args } => {
            let mut data = code.clone();
            data.extend_from_slice(args);
            (0, data, VmType::Evm)
        }
        // All Tenzro-native transaction types (agents, models, staking, TEE)
        _ => (0, Vec::new(), VmType::Tenzro),
    };

    let mut vm_tx = VmTransaction::new(
        tx.from.as_bytes().to_vec(),
        Some(tx.to.as_bytes().to_vec()),
        value,
        data,
        tx.gas_limit,
        tx.gas_price as u128,
        tx.nonce.0,
        vm_type,
        tx.chain_id.0,
    );

    // Carry over signature and public key from the signed transaction
    // so the VM runtime can perform cryptographic verification
    if !signed_tx.signature.bytes.is_empty() {
        vm_tx.signature = Some(signed_tx.signature.bytes.clone());
    }
    if !signed_tx.signature.public_key.is_empty() {
        vm_tx.public_key = Some(signed_tx.signature.public_key.clone());
    }

    vm_tx
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_types::primitives::{Address, ChainId, Nonce};
    use tenzro_types::transaction::Transaction;
    use tenzro_types::Signature;

    fn create_test_transaction(nonce: u64) -> SignedTransaction {
        let pq_key = MlDsaSigningKey::generate();
        let tx = Transaction::new(
            ChainId::from(1),
            Address::default(),
            Address::default(),
            Nonce::from(nonce),
            TransactionType::Transfer { amount: 1000 },
            21000,
            100,
            pq_key.verifying_key_bytes().to_vec(),
        );
        let pq_sig = pq_key.sign(tx.hash().as_bytes()).to_vec();
        SignedTransaction::new(tx, Signature::default(), pq_sig)
    }

    #[test]
    fn test_convert_transfer_transaction() {
        let tx = create_test_transaction(1);
        let vm_tx = convert_transaction(&tx);

        assert_eq!(vm_tx.value, 1000);
        assert_eq!(vm_tx.gas_limit, 21000);
        assert_eq!(vm_tx.gas_price, 100);
        assert_eq!(vm_tx.nonce, 1);
        assert_eq!(vm_tx.chain_id, 1);
    }

    #[test]
    fn test_convert_contract_call() {
        let pq_key = MlDsaSigningKey::generate();
        let tx = Transaction::new(
            ChainId::from(1),
            Address::default(),
            Address::default(),
            Nonce::from(5),
            TransactionType::ContractCall {
                function: "transfer".to_string(),
                args: vec![1, 2, 3, 4],
            },
            100000,
            200,
            pq_key.verifying_key_bytes().to_vec(),
        );
        let pq_sig = pq_key.sign(tx.hash().as_bytes()).to_vec();
        let signed_tx = SignedTransaction::new(tx, Signature::default(), pq_sig);
        let vm_tx = convert_transaction(&signed_tx);

        assert_eq!(vm_tx.value, 0);
        assert!(vm_tx.data.starts_with(b"transfer"));
        assert_eq!(vm_tx.gas_limit, 100000);
    }

    #[tokio::test]
    async fn test_submit_block_and_shutdown() {
        use tenzro_types::block::{BlockHeader, ConsensusProof, ConsensusAlgorithm};
        use tenzro_types::primitives::{BlockHeight, Hash};
        use tenzro_vm::VmConfig;

        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(RocksDbStore::open_default(dir.path()).unwrap());
        let vm_runtime = Arc::new(MultiVmRuntime::new(VmConfig::default()).await.unwrap());

        let chain_tip = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let metrics = Arc::new(MetricsCollector::new());
        let event_loop = EventLoop::new(storage, vm_runtime, None, None, chain_tip, metrics);

        // submit_block sends BlockFinalized event
        let header = BlockHeader::new(
            BlockHeight::from(0),
            Hash::zero(),
            Hash::zero(),
            Hash::zero(),
            Address::default(),
            ConsensusProof::new(ConsensusAlgorithm::PBFT, vec![]),
        );
        let block = Block::new(header, vec![]);
        assert!(event_loop.submit_block(block).is_ok());

        // shutdown sends both Shutdown event and broadcast
        event_loop.shutdown();
    }

    #[test]
    fn test_convert_contract_deploy() {
        let code = vec![0x60, 0x80, 0x60, 0x40];
        let args = vec![1, 2, 3];

        let pq_key = MlDsaSigningKey::generate();
        let tx = Transaction::new(
            ChainId::from(1),
            Address::default(),
            Address::default(),
            Nonce::from(0),
            TransactionType::ContractDeploy {
                code: code.clone(),
                args: args.clone(),
            },
            500000,
            300,
            pq_key.verifying_key_bytes().to_vec(),
        );
        let pq_sig = pq_key.sign(tx.hash().as_bytes()).to_vec();
        let signed_tx = SignedTransaction::new(tx, Signature::default(), pq_sig);
        let vm_tx = convert_transaction(&signed_tx);

        assert_eq!(vm_tx.value, 0);
        assert!(vm_tx.data.starts_with(&code));
        assert_eq!(&vm_tx.data[code.len()..], &args[..]);
    }
}
