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
use tenzro_identity::IdentityRegistry;
use tenzro_network::{ConsensusMessage, NetworkMessage, MessagePayload, NetworkService, TenzroNetworkService, VoteType as NetVoteType};
use tenzro_storage::{RocksDbStore, KvStore, BlockStoreImpl, WriteOp, CF_MODELS, CF_MODEL_SERVICES, CF_TRANSACTIONS};
use tenzro_storage::traits::BlockStore;
use tenzro_token::StakingManager;
use tenzro_token::bond::BondManager;
use tenzro_types::kill_switch::{KillSwitchAction, KillSwitchReceipt};
use tenzro_vm::{MultiVmRuntime, StateAdapter, VmTransaction, VmType};
use tenzro_types::block::Block;
use tenzro_types::transaction::{SignedTransaction, TransactionType};
use tenzro_types::primitives::{Address, BlockHeight, Hash};
use tenzro_iroh::IrohResolver;

use crate::error::{NodeError, Result};
use crate::metrics::MetricsCollector;

/// Static context needed to assemble periodic `ProviderAnnouncementMessage`
/// broadcasts from inside the event loop.
///
/// Snapshot semantics: `hardware`, `geography`, `provider_address`,
/// `provider_type`, `capabilities`, `rpc_endpoint` are captured once at node
/// startup. Per-tick we still re-read `served_models` from the live
/// `Arc<DashMap>` so additions / withdrawals propagate without a node restart.
#[derive(Clone, Debug)]
pub struct ProviderAnnouncementContext {
    /// `tenzro_types::HardwareCapabilities::detect()` evaluated once at startup.
    pub hardware: tenzro_types::HardwareCapabilities,
    /// Operator-declared geography (`NodeConfig::geography`). `None` means
    /// "unknown" — receivers must NOT treat it as a wildcard.
    pub geography: Option<String>,
    /// Provider wallet address (hex-encoded with `0x` prefix or empty if
    /// the node has no provisioned identity yet).
    pub provider_address: String,
    /// Provider class string (`"llm"`, `"tee"`, `"general"`).
    pub provider_type: String,
    /// Capability labels (e.g. `"inference"`, `"tee-attestation"`).
    pub capabilities: Vec<String>,
    /// External (advertised) RPC endpoint URL — what peers should dial for
    /// inference. Built from `external_rpc_addr` if set, otherwise from
    /// `rpc_addr`.
    pub rpc_endpoint: String,
    /// TTL in seconds for each announcement record. Receivers evict entries
    /// whose `last_seen + ttl_secs < now`.
    pub ttl_secs: u64,
    /// LAN-cluster serving profile, present only when this node serves AI and
    /// is willing to join LAN pipeline clusters. `None` means single-box
    /// serving only — peers will not auto-cluster this node. Captured once at
    /// startup from the local ggml device profile + linked llama.cpp commit.
    pub cluster_profile: Option<tenzro_types::ClusterProfile>,
    /// Advertised serving throughput/concurrency envelope broadcast on each
    /// provider heartbeat. Captured from the node's `ProviderCapacity` at the
    /// point the announcement context is built.
    pub capacity: tenzro_types::AdvertisedCapacity,
    /// Per-hour TNZO price this operator quotes to host an app deployment — the
    /// operator's hosting bid, from `HostingConfig::price_per_hour`. `0` = free.
    pub hosting_price_per_hour: u128,
}

/// Maximum tolerated forward clock skew for announcement timestamps (ms).
/// Announcements dated further into the future than this are rejected —
/// a signer can't pre-date announcements to extend their replay window.
const ANNOUNCE_MAX_FUTURE_SKEW_MS: i64 = 60_000;

/// Replay-window check applied to every signed announcement on ingest.
/// The signature covers `timestamp` + `ttl_secs`, so a captured
/// announcement is only replayable inside its own TTL window; after the
/// provider stops serving (or changes endpoint), the stale capture expires.
fn check_announcement_freshness(timestamp_ms: i64, ttl_secs: u64) -> std::result::Result<(), String> {
    let now = chrono::Utc::now().timestamp_millis();
    let age_ms = now.saturating_sub(timestamp_ms);
    let ttl_ms = (ttl_secs as i64).saturating_mul(1000);
    if age_ms > ttl_ms {
        return Err(format!(
            "stale announcement: age {}ms exceeds ttl {}s",
            age_ms, ttl_secs
        ));
    }
    if age_ms < -ANNOUNCE_MAX_FUTURE_SKEW_MS {
        return Err(format!(
            "future-dated announcement: {}ms ahead of local clock",
            -age_ms
        ));
    }
    Ok(())
}

/// The app-hosting runtime classes this build can serve, advertised in the
/// provider announcement so placement can filter deployments to capable nodes.
/// `static` is always served (content-addressed assets need no special host).
/// `function` (a `wasi:http` component sandbox) needs the `wasi-skills` feature.
/// `machine` (an unmodified server in a Firecracker microVM) needs the
/// `firecracker` feature and, at runtime, a Linux host with KVM — placement
/// still filters on the runtime facts before assigning, so advertising the
/// class only claims the binary can serve it.
fn hosting_runtime_classes() -> Vec<String> {
    let mut classes = vec!["static".to_string()];
    if cfg!(feature = "wasi-skills") {
        classes.push("function".to_string());
    }
    if cfg!(feature = "firecracker") {
        classes.push("machine".to_string());
    }
    classes
}

/// Map an announced reachability tier string onto the storage placement tier.
/// A peer also seen on the local mDNS segment is promoted to `LocalDirect`
/// regardless of its announced WAN tier — the LAN path is the one shard
/// transfers actually use. Announced `"direct"` maps to `Direct`, `"relay_only"`
/// to `RelayOnly`; anything else (unreachable / unreported) maps to
/// `SymmetricNat`, which tiered self-selection excludes.
fn member_reachability_from_announcement(
    tier: &str,
    on_local_segment: bool,
) -> tenzro_storage_provider::MemberReachability {
    use tenzro_storage_provider::MemberReachability;
    if on_local_segment {
        return MemberReachability::LocalDirect;
    }
    match tier {
        "direct" => MemberReachability::Direct,
        "relay_only" => MemberReachability::RelayOnly,
        _ => MemberReachability::SymmetricNat,
    }
}

/// Event types flowing through the node
// In-process event message; the largest variant is the common hot path, so
// boxing to equalize variant sizes would pessimize the common case.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// New transaction received (from network gossipsub or unauthenticated RPC fallback).
    /// The event loop runs full validation + consensus admission for these.
    NewTransaction(SignedTransaction),
    /// Transaction that was already admitted to the local consensus mempool by
    /// the RPC layer (`eth_sendRawTransaction` / `tenzro_signAndSendTransaction`).
    /// The event loop skips re-admission (which would double-charge the Spec 2
    /// per-DID token bucket) and only handles gossip propagation + local pending
    /// bookkeeping.
    LocallyAdmittedTransaction(SignedTransaction),
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
    /// Blob availability announcement received from gossipsub (from another
    /// node). Verified and folded into the iroh resolver's blob-provider
    /// hint cache.
    BlobAnnouncement(tenzro_network::BlobAnnouncementMessage),
    /// Shard replication request received from gossipsub. Storage-serving
    /// nodes run rendezvous (HRW) self-selection per shard and pin the
    /// shards they rank for into their local iroh blob store, spreading the
    /// object across independent providers.
    ShardReplication(tenzro_network::ShardReplicationMessage),
    /// Cortex advertisement received from gossipsub (signed JSON payload).
    ///
    /// Carries the raw serde_json-encoded `CortexAdvertisement` bytes so the
    /// event loop can decode, cryptographically verify, and ingest them into
    /// the node's `RemoteWorkerRegistry` without blocking the gossipsub
    /// receiver task.
    CortexAdvertisementReceived(Vec<u8>),
    /// Tenzro Train gossip message received on either `tenzro/training`
    /// (`OuterGradient` payloads from remote trainers) or
    /// `tenzro/training/syncer` (`SyncRound` payloads from remote syncers).
    ///
    /// The event loop decodes via `tenzro_training::decode_for_topic`,
    /// enforces topic discipline, and dispatches into the local
    /// `TrainingRuntime` for idempotent application. The
    /// `accept_outer_gradient` path dedups by `trainer_did`, so
    /// re-receiving a self-published gradient is a no-op.
    TrainingGossipReceived { topic: String, bytes: Vec<u8> },
    /// Generative-media gossip message received on `tenzro/media-gen`.
    ///
    /// Carries one of the five variants in
    /// [`tenzro_media_gen::MediaGenGossipMessage`]: `WorkerEnrolled`,
    /// `JobPosted`, `JobClaimed`, `HandoffPublished`, `ReceiptSubmitted`.
    ///
    /// Dispatch goes through the runtime's observer methods, which keep the
    /// invariants that belong to the job itself and drop the ones that only
    /// hold on the node doing the work. Each is idempotent, so a publisher
    /// receiving its own announcement back is a no-op.
    ///
    /// The two bulk-carrying variants also carry a transport locator. When
    /// present it is recorded against the content hash so a node that did not
    /// render the bytes can still fetch them.
    MediaGenGossipReceived { topic: String, bytes: Vec<u8> },
    /// SeedAgent (Spec 10) gossip message received on `tenzro/seed-agents`.
    ///
    /// Carries one of the five variants in
    /// [`tenzro_token::SeedAgentGossipMessage`]: `CharterUpserted`,
    /// `EarmarkUpdated`, `AgentRegistered`, `AgentStatusChanged`, or
    /// `MonthlyRefillCompleted`. The event loop decodes via
    /// `tenzro_token::decode_seed_agent_for_topic` and applies the variant
    /// idempotently against the local `SeedAgentEarmarkManager`.
    /// `MonthlyRefillCompleted` is informational only — receivers do NOT
    /// replay the refill, only update their earmark snapshot.
    SeedAgentGossipReceived { topic: String, bytes: Vec<u8> },
    /// Distributed-database gossip message received on `tenzro/databases`.
    ///
    /// Carries a bincode-encoded [`tenzro_database::DatabaseGossipMessage`]
    /// (`Registered` or `Rescaled`). The event loop decodes via
    /// `tenzro_database::decode_for_topic` and upserts the descriptor into the
    /// local `DatabaseRegistry` idempotently — re-receiving a descriptor a node
    /// already holds is a no-op.
    DatabaseGossipReceived { topic: String, bytes: Vec<u8> },
    /// TDIP identity gossip message received on `tenzro/identity`.
    ///
    /// Carries a bincode-encoded
    /// [`tenzro_identity::IdentityGossipMessage`] — currently the single
    /// `RevocationBroadcast` variant wrapping a
    /// [`tenzro_identity::registry::SignedRevocationEntry`]. The event loop
    /// decodes via `tenzro_identity::decode_identity_for_topic` and applies
    /// the entry through `IdentityRegistry::apply_remote_revocation`, which
    /// verifies both hybrid signature legs and is idempotent for
    /// already-revoked DIDs.
    IdentityGossipReceived { topic: String, bytes: Vec<u8> },
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
    served_models: Option<Arc<DashMap<String, tenzro_types::model::ModelVisibility>>>,
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
    /// ZK quorum store — when wired, closed fraud windows are pruned on each
    /// finalized-block advance so the attested map does not grow unboundedly.
    zk_quorum_store: Option<Arc<tenzro_consensus::ZkQuorumStore>>,
    /// Shared reference to the node's network_agents map for gossipsub agent discovery
    network_agents: Option<Arc<DashMap<String, crate::node::NetworkAgentEntry>>>,
    /// Shared reference to the node's network_providers map for gossipsub provider discovery
    network_providers: Option<Arc<DashMap<String, crate::node::NetworkProviderEntry>>>,
    /// Same-segment peer set (mDNS / private range). Storage-shard
    /// self-selection prefers holders on this segment before spilling onto the
    /// wider network, so a deal served within one LAN keeps its replicas local.
    /// `None` when networking is not running (light clients never replicate).
    local_peers: Option<Arc<tenzro_network::LocalPeerSet>>,
    /// Shared reference to the node's `ProviderManager`. Verified provider
    /// announcements are bridged into it (`upsert_from_announcement`) so the
    /// `InferenceRouter` scoring path — which routes real chat traffic —
    /// actually sees gossip-discovered providers with their advertised
    /// `HardwareCapabilities`. `None` on nodes with no router (light clients).
    provider_manager: Option<Arc<tenzro_model::ProviderManager>>,
    /// Provider announcement broadcast context. When `Some`, the periodic
    /// `provider_heartbeat` tick rebuilds a `ProviderAnnouncementMessage`
    /// from the current `served_models` / `provider_pricing` / hardware
    /// snapshot and broadcasts it on `tenzro/providers` so peers can
    /// merge it into their `network_providers` cache. `None` on light
    /// clients that never serve.
    provider_announcement_ctx: Option<ProviderAnnouncementContext>,
    /// Node Ed25519 announce signer. Signs every outbound model, provider,
    /// and agent announcement so peers can reject spoofed or replayed
    /// announcements. `None` disables announcement broadcast (unsigned
    /// announcements are rejected network-wide).
    announce_signer: Option<Arc<dyn tenzro_crypto::signatures::Signer + Send + Sync>>,
    /// Shared reference to the ModelRuntime for idle-TTL liveness checks of
    /// local model service instances.
    model_runtime: Option<Arc<tenzro_model::ModelRuntime>>,
    /// Shared reference to the node's load tracker, so that when we evict an
    /// idle local model service we also unregister the per-model concurrency
    /// slot.
    load_tracker: Option<Arc<tenzro_model::LoadTracker>>,
    /// Shared reference to the node's `RemoteWorkerRegistry` used to ingest
    /// verified Cortex advertisements received over the
    /// `tenzro/cortex` gossipsub topic.
    remote_cortex_workers: Option<Arc<tenzro_cortex::RemoteWorkerRegistry>>,
    /// Shared reference to the node's iroh resolver. The periodic
    /// `blob_heartbeat` tick enumerates the local blob store and broadcasts
    /// signed `BlobAnnouncementMessage`s on `tenzro/blobs`; inbound
    /// announcements from peers are folded into the resolver's
    /// blob-provider hint cache so `tenzro://blob/...` URIs resolve
    /// cross-node without an explicit provider hint.
    iroh_resolver: Option<Arc<tenzro_iroh::IrohBackedResolver>>,
    /// Shared reference to the node's `TrainingRuntime` used to ingest
    /// `OuterGradient` payloads received on the `tenzro/training` topic
    /// and observe `SyncRound` payloads on `tenzro/training/syncer`. The
    /// dispatch goes through `SyncerState::accept_outer_gradient`, which
    /// dedups by `trainer_did`, so re-receiving a self-published gradient
    /// (the publisher is also subscribed to its own topic) is a no-op.
    training_runtime: Option<Arc<tenzro_training::TrainingRuntime>>,
    /// Shared reference to the node's `MediaGenRuntime`, used to mirror job
    /// state announced on the `tenzro/media-gen` topic so local workers know
    /// what is already taken. Absent on nodes that don't initialize the
    /// subsystem, in which case inbound messages are decoded and logged only.
    media_gen_runtime: Option<Arc<tenzro_media_gen::MediaGenRuntime>>,
    /// Concrete handle on the iroh-backed generative-media output store.
    ///
    /// The runtime holds the same store behind `dyn MediaGenOutputStore`,
    /// which is the fetch-and-verify surface. Recording a locator learned
    /// from gossip is specific to the iroh adapter — it is the translation
    /// from the SHA-256 a receipt commits to into the BLAKE3 iroh-blobs
    /// indexes by — so it needs the concrete type.
    media_gen_output_store: Option<Arc<tenzro_iroh::IrohMediaGenOutputStore>>,
    /// Shared reference to the node's `SeedAgentEarmarkManager` (Spec 10)
    /// used to apply idempotent state updates received over the
    /// `tenzro/seed-agents` gossipsub topic. Absent on light clients or
    /// nodes that don't initialize the seed-agent subsystem; in that case
    /// inbound seed-agent gossip messages are decoded and logged but not
    /// applied.
    seed_agent_manager: Option<Arc<tenzro_token::seed_agent::SeedAgentEarmarkManager>>,
    /// Distributed-database registry. Wired from the node so the event loop can
    /// upsert descriptors received on the `tenzro/databases` gossipsub topic
    /// into the same registry the RPC handlers serve from. Absent on nodes that
    /// don't initialize the database subsystem; in that case inbound database
    /// gossip is decoded and logged but not applied.
    database_registry: Option<Arc<tenzro_database::DatabaseRegistry>>,
    /// Persistent kill-switch receipt store. Wired from the node so that the
    /// post-execute scan in `handle_block_finalized` can record the
    /// canonical `KillSwitchReceipt` (with the real `frozen_at_block`)
    /// emitted by the VM precompiles.
    kill_switch_store: Option<Arc<tenzro_settlement::KillSwitchStore>>,
    /// Staking manager. Wired so the post-execute scan can freeze stakes on
    /// pause/quarantine, thaw on resume, and slash on terminate. Required
    /// to keep the kill-switch invariant: `Quarantined` and `Terminated`
    /// agents cannot withdraw stake.
    staking: Option<Arc<StakingManager>>,
    /// Identity registry. Wired so the post-execute scan can resolve a
    /// machine DID (carried on the kill-switch log) to the staker
    /// `Address` that the staking manager keys on.
    identity_registry: Option<Arc<IdentityRegistry>>,
    /// AgentBond manager (Spec 9). Wired so the post-execute scan can
    /// reflect VM-emitted `BondPosted` / `BondIncreased` /
    /// `BondWithdrawInitiated` / `BondSlashed` / `InsuranceClaimPaid`
    /// logs into the off-chain `BondManager` cache + RocksDB write-through.
    /// The VM is the source of truth for vault balances and the on-chain
    /// marker; this manager is the authoritative read model that lane
    /// resolution and receipt envelopes consult.
    bond_manager: Option<Arc<BondManager>>,
    /// On-chain escrow query index. Wired so the post-execute scan can
    /// reflect VM-emitted `EscrowCreated` / `EscrowReleased` / `EscrowRefunded`
    /// logs into the off-chain `EscrowManager`. The Native VM is the source
    /// of truth for escrow state and vault balances; this manager is the
    /// read model that `tenzro_listEscrowsByPayer` / `tenzro_listEscrowsByPayee`
    /// query. Without this wired, escrow transactions execute on chain
    /// (vault balances + the `escrow:<hex>` marker under `SYSTEM_ADDRESS`)
    /// but the by-payer/by-payee read indices stay empty.
    escrow_manager: Option<Arc<tenzro_settlement::EscrowManager>>,
    /// Permissionless validator registry (Dynamic Validator Set).
    ///
    /// The on-chain source of truth for who is a validator. The post-execute
    /// scan mirrors VM-emitted `ValidatorRegister` / `ValidatorExit` /
    /// `ValidatorMetadataUpdate` logs into this registry; the periodic epoch
    /// hook calls `compute_epoch_transition()` and feeds the resulting plan
    /// to the consensus `EpochManager`'s `pending_validators` /
    /// `pending_removals` queues. Persistence is RocksDB-backed under
    /// `CF_TOKENS / validator:*` so the active set survives restarts.
    validator_registry: Option<Arc<tenzro_token::ValidatorRegistry>>,

    /// Workflow runtime — typed mirror of the privileged-VM workflow
    /// selectors (`0x01000040`–`0x0100004B`). The post-execute scan in
    /// `handle_block_finalized` decodes the 12 typed `Workflow*` log topics
    /// and dispatches into `WorkflowManager` / `PrivacyDomainRegistry`,
    /// which write through to RocksDB and emit chained `WorkflowReceipt`s.
    /// Without this wired, workflow transactions execute on chain (markers
    /// land under `SYSTEM_ADDRESS`) but the typed read model that RPC /
    /// MCP / A2A consult never updates.
    workflow_runtime: Option<Arc<crate::workflow_runtime::WorkflowRuntime>>,

    /// Adaptive burn rate manager — receives `SupplyMetricsSnapshot` records
    /// at every epoch boundary so the transfer function can score
    /// inflationary / deflationary deviation and surface a burn-rate
    /// recommendation through `tenzro_getBurnRateRecommendation`.
    /// Without this wired, `record_metrics` never gets called and the
    /// recommendation engine reports against stale/empty metrics.
    burn_rate_manager: Option<Arc<tenzro_token::adaptive_burn::BurnRateConfigManager>>,

    /// Token reference — used by the epoch observer to read total supply
    /// for the snapshot, and (with `staking`) compute the staker /
    /// treasury emission split.
    token: Option<Arc<tenzro_token::TnzoToken>>,

    /// Work-gated reward engine. Every finalized block records consensus
    /// participation (proposer + QC signers) as verified work; at each
    /// epoch boundary the cumulative provider usage meters are ingested
    /// and the closing epoch's minting rights are converted into reward
    /// coupons. Without this wired, no work is metered and `close_epoch`
    /// never runs — claims return nothing.
    reward_engine: Option<Arc<tenzro_token::RewardEngine>>,
    /// Foundation sponsorship manager — the epoch boundary hook runs the
    /// slot expiry sweep (`expire_due`) so 24-month slots wind down and
    /// their delegations return to the revolving pool without operator
    /// action.
    sponsorship_manager: Option<Arc<tenzro_token::SponsorshipManager>>,
    /// Usage tracker — read at each epoch boundary to feed the reward
    /// engine's cumulative provider meters (`ingest_cumulative`). Settled
    /// usage only; the tracker records real routed inference, never
    /// self-reported capacity.
    usage_tracker: Option<Arc<tenzro_model::UsageTracker>>,

    /// Fee accounting for the gas the executor debits from transaction
    /// senders. The native VM subtracts `gas_price * gas_used` and credits
    /// nobody, so this is what records where that TNZO went.
    fee_processor: Option<Arc<tenzro_token::FeeProcessor>>,
    /// Whether the fee anchors below hold a real reference point yet. The
    /// counters they track are cumulative over the chain's whole history and
    /// the balances behind them are already durable, so the first observation
    /// after boot anchors instead of settling — otherwise every restart would
    /// credit the treasury the full history a second time. A separate flag
    /// rather than a zero test, so a fresh chain's first fee-bearing block is
    /// still settled.
    fee_anchor_set: bool,
    /// Cumulative `FeeMarket::total_to_treasury()` already settled onto the
    /// ledger.
    last_settled_fee_treasury: u128,
    /// Cumulative `FeeMarket::total_burned()` already settled onto the
    /// ledger. Distinct from `last_observed_base_fee_burn`, which anchors
    /// the epoch-boundary adaptive-burn metrics rather than ledger movement.
    last_settled_fee_burn: u128,

    /// Circulating supply at the most recent epoch boundary, captured
    /// after a successful `record_metrics` call. Used to compute the
    /// `epoch_supply_delta` field of the *next* snapshot. Reset to the
    /// current supply on first observation, so the very first epoch
    /// reports a zero delta (no prior reference point).
    last_observed_epoch_supply: u128,
    /// Cumulative `FeeMarket::total_burned()` at the previous epoch
    /// observation. Used to compute the per-epoch `BurnBreakdown.base_fee`
    /// delta. Zero on first observation → first epoch reports zero base-fee
    /// burn (no prior anchor), then the running delta from this point
    /// forward.
    last_observed_base_fee_burn: u128,
    /// Cumulative `StakingManager::total_slashed()` at the previous epoch
    /// observation. Used to compute the per-epoch `BurnBreakdown.slash`
    /// delta. Same first-observation semantics as the base-fee anchor.
    last_observed_slash_burn: u128,
    /// Receives `BlockImport` requests from the `BlockSyncEngine`. Each item
    /// carries a `Block` that has already passed per-block QC verification at
    /// the engine boundary, plus a oneshot `result` channel that the event
    /// loop replies on after `handle_block_imported_from_sync` returns.
    ///
    /// Initialized lazily inside `run()` once the engine has been spawned;
    /// `None` on a node with no network service (e.g. light-client mode).
    block_import_rx: Option<mpsc::Receiver<crate::block_sync::BlockImport>>,

    /// Cosmos-style snapshot ABCI store. On producer nodes, the
    /// post-finality hook calls `produce_at(height, state_root)` at the
    /// configured [`crate::snapshot::SnapshotConfig::interval_blocks`]
    /// cadence. `None` until wired by the node.
    snapshot_store: Option<Arc<crate::snapshot::SnapshotStore>>,

    /// Ring of the most recent locally computed post-commit state roots
    /// (newest at the back). Execution is deferred: the proposer stamps its
    /// latest *executed* root into the header, which can lag the proposed
    /// height by a few blocks. A strict per-height equality check would
    /// therefore false-positive; instead the header claim is validated by
    /// membership in this window. All honest nodes compute identical roots
    /// per height, so a claim absent from a full window means the proposer
    /// executed a divergent state — a fork signal, raised as an alarm
    /// (the block is already finalized; halting would only break local
    /// liveness without protecting anyone).
    recent_state_roots: std::collections::VecDeque<Hash>,

    /// Desired replica count per shard for storage placement. `Some(r)`
    /// marks this node as storage-serving: inbound `ShardReplication`
    /// requests trigger rendezvous (HRW) self-selection against the local
    /// membership view, and shards this node ranks in the top `r` are pinned
    /// into its iroh blob store. `None` on non-storage nodes — they ignore
    /// replication requests entirely.
    storage_replicas: Option<usize>,

    /// Weak-subjectivity checkpoint `(height, state_root)` enforced on the
    /// block-sync import path. QC verification proves each imported block
    /// carries a valid commit certificate, but a long-range fork forged by
    /// an old validator supermajority is self-consistent under that check.
    /// The anchor pins one finalized `(height, state_root)` the node trusts
    /// a priori: when import reaches `height`, the block's `state_root` must
    /// match or the block (and everything built on it) is rejected. `None`
    /// disables the check — the historical block-sync behaviour.
    weak_subjectivity_anchor: Option<(u64, Hash)>,
}

/// Capacity of [`EventLoop::recent_state_roots`]. Proposer execution lag is
/// bounded by pipeline depth (single digits); 128 gives orders-of-magnitude
/// headroom while keeping the membership scan trivial.
const STATE_ROOT_WINDOW: usize = 128;

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
            zk_quorum_store: None,
            network_agents: None,
            network_providers: None,
            local_peers: None,
            provider_manager: None,
            provider_announcement_ctx: None,
            announce_signer: None,
            model_runtime: None,
            load_tracker: None,
            remote_cortex_workers: None,
            iroh_resolver: None,
            training_runtime: None,
            media_gen_runtime: None,
            media_gen_output_store: None,
            seed_agent_manager: None,
            database_registry: None,
            kill_switch_store: None,
            staking: None,
            identity_registry: None,
            bond_manager: None,
            escrow_manager: None,
            validator_registry: None,
            workflow_runtime: None,
            block_import_rx: None,
            burn_rate_manager: None,
            token: None,
            reward_engine: None,
            sponsorship_manager: None,
            usage_tracker: None,
            fee_processor: None,
            fee_anchor_set: false,
            last_settled_fee_treasury: 0,
            last_settled_fee_burn: 0,
            last_observed_epoch_supply: 0,
            last_observed_base_fee_burn: 0,
            last_observed_slash_burn: 0,
            snapshot_store: None,
            recent_state_roots: std::collections::VecDeque::with_capacity(STATE_ROOT_WINDOW),
            storage_replicas: None,
            weak_subjectivity_anchor: None,
        }
    }

    /// Pins the weak-subjectivity checkpoint `(height, state_root)` enforced
    /// on the block-sync import path. When a block-sync import reaches
    /// `height`, its `state_root` must match `root` byte-for-byte or the
    /// import is rejected — defeating long-range forks that pass QC
    /// verification. Left unset, block-sync imports are accepted on QC
    /// verification alone.
    pub fn with_weak_subjectivity_anchor(
        mut self,
        height: u64,
        root: Hash,
    ) -> Self {
        self.weak_subjectivity_anchor = Some((height, root));
        self
    }

    /// Marks this node as storage-serving with the given per-shard replica
    /// target. Inbound `ShardReplication` requests then run rendezvous (HRW)
    /// self-selection and pin the shards this node ranks for.
    pub fn with_storage_replicas(mut self, replicas: usize) -> Self {
        self.storage_replicas = Some(replicas.max(1));
        self
    }

    /// Wires the snapshot ABCI store. Once set, `process_finality_notification`
    /// triggers `produce_at` at the store's configured interval on producer
    /// nodes (a no-op when the producer is disabled).
    pub fn with_snapshot_store(
        mut self,
        snapshot_store: Arc<crate::snapshot::SnapshotStore>,
    ) -> Self {
        self.snapshot_store = Some(snapshot_store);
        self
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
        served_models: Arc<DashMap<String, tenzro_types::model::ModelVisibility>>,
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

    /// Wires the ZK quorum store so closed fraud windows are pruned on each
    /// finalized-block advance.
    pub fn with_zk_quorum_store(
        mut self,
        zk_quorum_store: Arc<tenzro_consensus::ZkQuorumStore>,
    ) -> Self {
        self.zk_quorum_store = Some(zk_quorum_store);
        self
    }

    /// Wires the persistent kill-switch receipt store. Required for the
    /// post-execute log scan that records the canonical
    /// `KillSwitchReceipt` (with the real `frozen_at_block`) emitted by the
    /// kill-switch precompiles.
    pub fn with_kill_switch_store(
        mut self,
        kill_switch_store: Arc<tenzro_settlement::KillSwitchStore>,
    ) -> Self {
        self.kill_switch_store = Some(kill_switch_store);
        self
    }

    /// Wires the staking manager. Required so the post-execute scan can
    /// freeze stakes on Pause/Quarantine, thaw on resume, and slash on
    /// Terminate. Without this, kill-switch transitions land in the
    /// lifecycle FSM and receipt store but stake stays liquid — defeating
    /// the EU AI Act intervention guarantee.
    pub fn with_staking(mut self, staking: Arc<StakingManager>) -> Self {
        self.staking = Some(staking);
        self
    }

    /// Wires the identity registry. Required to map the machine DID
    /// carried on a kill-switch log to the staker `Address` that
    /// `StakingManager` keys on.
    pub fn with_identity_registry(
        mut self,
        identity_registry: Arc<IdentityRegistry>,
    ) -> Self {
        self.identity_registry = Some(identity_registry);
        self
    }

    /// Wires the AgentBond manager (Spec 9). Required for the
    /// post-execute log scan to mirror VM-emitted bond events into the
    /// off-chain manager state. Without this, the VM applies bond ops on
    /// chain (vault balances + marker JSON) but the read model used by
    /// lane resolution and receipt envelopes never updates — so freshly
    /// posted bonds never promote their agents into Bonded lanes.
    pub fn with_bond_manager(mut self, bond_manager: Arc<BondManager>) -> Self {
        self.bond_manager = Some(bond_manager);
        self
    }

    /// Wires the on-chain escrow query index. Required for the post-execute
    /// log scan to mirror VM-emitted escrow events into the off-chain
    /// `EscrowManager`. Without this, escrow transactions execute on chain
    /// (vault balances + `escrow:<hex>` marker under `SYSTEM_ADDRESS`) but
    /// the by-payer/by-payee read indices stay empty, so
    /// `tenzro_listEscrowsByPayer` / `tenzro_listEscrowsByPayee` return
    /// empty arrays.
    pub fn with_escrow_manager(
        mut self,
        escrow_manager: Arc<tenzro_settlement::EscrowManager>,
    ) -> Self {
        self.escrow_manager = Some(escrow_manager);
        self
    }

    /// Wires the permissionless validator registry (Dynamic Validator Set).
    ///
    /// The post-execute scan in `handle_block_finalized` consumes the
    /// VM-emitted `ValidatorRegister` / `ValidatorExit` /
    /// `ValidatorMetadataUpdate` logs and applies them to this registry; the
    /// per-block epoch hook calls `compute_epoch_transition()` at every epoch
    /// boundary and stages the resulting plan into the consensus
    /// `EpochManager`'s `pending_validators` / `pending_removals` queues.
    /// Without this manager wired, validator transactions are accepted by
    /// the VM (logs land in receipts) but the consensus active set never
    /// rotates.
    pub fn with_validator_registry(
        mut self,
        validator_registry: Arc<tenzro_token::ValidatorRegistry>,
    ) -> Self {
        self.validator_registry = Some(validator_registry);
        self
    }

    /// Wires the workflow runtime. Required so the post-execute scan in
    /// `handle_block_finalized` can decode the 12 typed `Workflow*` log
    /// topics emitted by the privileged-VM workflow selectors and apply
    /// them to the typed `WorkflowManager` / `PrivacyDomainRegistry`.
    /// Without this, workflow transactions execute (markers persisted under
    /// `SYSTEM_ADDRESS`) but the read model surfaced through RPC / MCP /
    /// A2A never advances.
    pub fn with_workflow_runtime(
        mut self,
        workflow_runtime: Arc<crate::workflow_runtime::WorkflowRuntime>,
    ) -> Self {
        self.workflow_runtime = Some(workflow_runtime);
        self
    }

    /// Wires the adaptive-burn manager + the canonical TNZO token.
    ///
    /// At every epoch transition the event loop computes a
    /// `SupplyMetricsSnapshot` (current circulating supply, epoch
    /// supply delta, rolling-window bps) and feeds it into
    /// `BurnRateConfigManager::record_metrics`. The transfer function
    /// (`current_recommendation()`) and the
    /// `tenzro_getBurnRateRecommendation` RPC then read from the
    /// freshly-persisted snapshot. Without this wire, `record_metrics`
    /// is dead code and the recommendation engine scores against
    /// `SupplyMetricsSnapshot::default()`.
    pub fn with_burn_rate_manager(
        mut self,
        burn_rate_manager: Arc<tenzro_token::adaptive_burn::BurnRateConfigManager>,
        token: Arc<tenzro_token::TnzoToken>,
    ) -> Self {
        self.burn_rate_manager = Some(burn_rate_manager);
        self.token = Some(token);
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

    /// Wires the same-segment peer set so storage-shard self-selection can
    /// prefer local-segment holders before spilling onto the wider network.
    pub fn with_local_peers(
        mut self,
        local_peers: Arc<tenzro_network::LocalPeerSet>,
    ) -> Self {
        self.local_peers = Some(local_peers);
        self
    }

    /// Wires the `ProviderManager` so verified provider announcements are
    /// bridged into the `InferenceRouter` scoring path. Without this, a
    /// gossip-discovered provider lives only in `network_providers` and is
    /// invisible to the router that dispatches chat traffic.
    pub fn with_provider_manager(
        mut self,
        provider_manager: Arc<tenzro_model::ProviderManager>,
    ) -> Self {
        self.provider_manager = Some(provider_manager);
        self
    }

    /// Wires the static context required to broadcast `ProviderAnnouncementMessage`
    /// from the periodic `provider_heartbeat` tick.
    ///
    /// Without this wired, the heartbeat only evicts stale `network_providers`
    /// entries — peers will never learn about this node's served models /
    /// hardware / geography.
    pub fn with_provider_announcement(
        mut self,
        ctx: ProviderAnnouncementContext,
    ) -> Self {
        self.provider_announcement_ctx = Some(ctx);
        self
    }

    /// Wires the node's Ed25519 announce signer used to sign every outbound
    /// model, provider, and agent announcement. Without it the heartbeat
    /// ticks skip broadcasting, because unsigned announcements are rejected
    /// by every consumer.
    pub fn with_announce_signer(
        mut self,
        signer: Arc<dyn tenzro_crypto::signatures::Signer + Send + Sync>,
    ) -> Self {
        self.announce_signer = Some(signer);
        self
    }

    /// Wires the node's iroh resolver so the `blob_heartbeat` tick can
    /// announce locally held blobs on `tenzro/blobs` and inbound peer
    /// announcements can populate the resolver's blob-provider hint cache.
    pub fn with_iroh_resolver(
        mut self,
        resolver: Arc<tenzro_iroh::IrohBackedResolver>,
    ) -> Self {
        self.iroh_resolver = Some(resolver);
        self
    }

    /// Wires the shared `RemoteWorkerRegistry` so the event loop can ingest
    /// verified Cortex advertisements received on the
    /// `tenzro/cortex` gossipsub topic.
    pub fn with_cortex_registry(
        mut self,
        registry: Arc<tenzro_cortex::RemoteWorkerRegistry>,
    ) -> Self {
        self.remote_cortex_workers = Some(registry);
        self
    }

    /// Wires the shared `TrainingRuntime` so the event loop can dispatch
    /// `TrainingGossipReceived` events into the local syncer state. Without
    /// this wired, training payloads decoded off the wire are dropped with
    /// a debug-level log.
    pub fn with_training_runtime(
        mut self,
        runtime: Arc<tenzro_training::TrainingRuntime>,
    ) -> Self {
        self.training_runtime = Some(runtime);
        self
    }

    /// Wires the shared `MediaGenRuntime` so the event loop can mirror job
    /// state announced on `tenzro/media-gen`. Without this wired, media-gen
    /// payloads decoded off the wire are dropped with a debug-level log.
    pub fn with_media_gen_runtime(
        mut self,
        runtime: Arc<tenzro_media_gen::MediaGenRuntime>,
    ) -> Self {
        self.media_gen_runtime = Some(runtime);
        self
    }

    /// Wires the iroh-backed generative-media output store so locators
    /// carried by inbound receipts and handoffs can be recorded against the
    /// content hash they name. Without this wired, a job's bytes remain
    /// reachable only from the node that rendered them.
    pub fn with_media_gen_output_store(
        mut self,
        store: Arc<tenzro_iroh::IrohMediaGenOutputStore>,
    ) -> Self {
        self.media_gen_output_store = Some(store);
        self
    }

    /// Wires the shared `SeedAgentEarmarkManager` (Spec 10) so the event
    /// loop can apply idempotent state updates received on the
    /// `tenzro/seed-agents` gossipsub topic. Without this wired,
    /// seed-agent payloads decoded off the wire are dropped with a
    /// debug-level log.
    pub fn with_seed_agent_manager(
        mut self,
        manager: Arc<tenzro_token::seed_agent::SeedAgentEarmarkManager>,
    ) -> Self {
        self.seed_agent_manager = Some(manager);
        self
    }

    /// Wires the shared `DatabaseRegistry` so the event loop can upsert
    /// descriptors received on the `tenzro/databases` gossipsub topic. Without
    /// this wired, database gossip payloads decoded off the wire are dropped
    /// with a debug-level log.
    pub fn with_database_registry(
        mut self,
        registry: Arc<tenzro_database::DatabaseRegistry>,
    ) -> Self {
        self.database_registry = Some(registry);
        self
    }

    /// Wires the work-gated reward engine. Every finalized block records
    /// consensus participation; every epoch boundary ingests provider
    /// usage meters and closes the epoch into reward coupons.
    pub fn with_reward_engine(
        mut self,
        engine: Arc<tenzro_token::RewardEngine>,
    ) -> Self {
        self.reward_engine = Some(engine);
        self
    }

    /// Wires the foundation sponsorship manager so the epoch boundary
    /// hook can run the slot expiry sweep.
    pub fn with_sponsorship_manager(
        mut self,
        manager: Arc<tenzro_token::SponsorshipManager>,
    ) -> Self {
        self.sponsorship_manager = Some(manager);
        self
    }

    /// Wires the usage tracker consumed by the reward engine's epoch
    /// boundary ingestion of cumulative provider meters.
    pub fn with_usage_tracker(
        mut self,
        tracker: Arc<tenzro_model::UsageTracker>,
    ) -> Self {
        self.usage_tracker = Some(tracker);
        self
    }

    /// Wires the fee processor that accounts for the gas debited by the
    /// executor. Without it, gas fees leave payer balances and are recorded
    /// nowhere.
    ///
    /// Takes the canonical token alongside it because settlement credits the
    /// treasury balance directly; the token is otherwise only wired by
    /// [`Self::with_burn_rate_manager`], and fee settlement must not depend
    /// on the adaptive-burn dial being configured.
    pub fn with_fee_processor(
        mut self,
        processor: Arc<tenzro_token::FeeProcessor>,
        token: Arc<tenzro_token::TnzoToken>,
    ) -> Self {
        self.fee_processor = Some(processor);
        self.token = Some(token);
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
        let height = notification.height.0;

        // Prune ZK commitment fraud windows that closed at or before this
        // height, so the attested map stays bounded.
        if let Some(store) = self.zk_quorum_store.as_ref() {
            let pruned = store.prune_closed_windows(height);
            if pruned > 0 {
                debug!(height, pruned, "zk-quorum: pruned closed fraud windows");
            }
        }

        let res = self.handle_block_finalized(notification.block).await;

        // Snapshot ABCI: produce a state-sync snapshot at the configured
        // block interval, but only on nodes that opt in as producers
        // (dedicated RPC / archival). We only attempt this after
        // `handle_block_finalized` has run so the live KV store reflects the
        // block we're snapshotting at. The recorded root is the LOCALLY
        // computed post-commit root (window back), not the proposer's header
        // claim — the header root lags execution and is unverified input.
        if let Some(store) = self.snapshot_store.as_ref()
            && store.should_produce_at(height)
        {
            let local_root = self
                .recent_state_roots
                .back()
                .copied()
                .unwrap_or_else(Hash::zero);
            let mut sr = [0u8; 32];
            let bytes = local_root.as_bytes();
            let n = bytes.len().min(32);
            sr[..n].copy_from_slice(&bytes[..n]);
            let store = store.clone();
            // Snapshot production walks 27 column families and is
            // I/O-bound; run it off the event-loop thread so finality
            // processing stays unblocked.
            tokio::task::spawn_blocking(move || {
                match store.produce_at(height, sr) {
                    Ok(m) => info!(
                        height = m.height,
                        num_chunks = m.num_chunks,
                        "Produced state-sync snapshot"
                    ),
                    Err(e) => warn!(
                        height = height,
                        error = %e,
                        "Failed to produce state-sync snapshot"
                    ),
                }
            });
        }

        res
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
            // The `latest_height` metadata key can outlive the blocks it points
            // at after a genesis reset (the chain CF is cleared but the key is
            // not), leaving an orphan height with no backing block. Trust the
            // marker only when the block it names is actually present; otherwise
            // the store is effectively empty and we resume from genesis.
            Ok(Some(height))
                if height.0 == 0
                    || block_store
                        .get_block_by_height(height)
                        .await
                        .ok()
                        .flatten()
                        .is_some() =>
            {
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
            Ok(Some(orphan)) => {
                warn!(
                    orphan_height = orphan.0,
                    "latest_height marker has no backing block (stale after genesis reset); resuming from height 0"
                );
                self.current_height = 0;
                self.chain_tip.store(0, Ordering::Release);
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

        // Spawn the block-sync engine BEFORE the consensus warm-up gate.
        //
        // Block-sync serving (answering peers' `GetBlockRange` / `GetTipInfo`)
        // and requesting (catching up our own height) must never be gated
        // behind consensus liveness. The warm-up gate below waits for ≥ 2f+1
        // admitted validator peers before starting consensus; on a wedged or
        // freshly-restarted fleet a node can sit in that gate indefinitely.
        // If the block-sync subscriber only attaches after the gate, a node
        // stuck in warm-up rejects every inbound block-sync request with
        // "subscriber not yet attached" — so the one mechanism that would let
        // a behind-by-one node catch up and let the fleet re-form quorum is
        // disabled exactly when it is needed. Serving is a pure storage read
        // and requesting only advances local height via the verified
        // commit-QC import path, so neither depends on our consensus being
        // live. Attaching here breaks the deadlock: every node can serve the
        // blocks it already has, and a behind node catches up while its own
        // pacemaker is still warming, after which `resume_from_synced_height`
        // reconciles consensus to the synced tip.
        //
        // Light-client / no-network nodes have no engine — the channel stays
        // `None` and the corresponding select arm in the main loop is a noop.
        if let Some(network) = self.network.clone() {
            match (
                network.subscribe_block_sync_requests().await,
                network.subscribe_block_sync_results().await,
                network.subscribe_peer_events().await,
            ) {
                (Ok(inbound_rx), Ok(outbound_rx), Ok(peer_events_rx)) => {
                    let (importer_tx, importer_rx) =
                        mpsc::channel::<crate::block_sync::BlockImport>(64);
                    self.block_import_rx = Some(importer_rx);

                    let engine = crate::block_sync::BlockSyncEngine::new(
                        network,
                        self.storage.clone(),
                        self.consensus.clone(),
                        inbound_rx,
                        outbound_rx,
                        peer_events_rx,
                        importer_tx,
                    );
                    let engine_shutdown = self.shutdown_tx.subscribe();
                    tokio::spawn(engine.run(engine_shutdown));
                    info!("Block-sync engine spawned");
                }
                (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                    warn!(
                        error = %e,
                        "Block-sync engine NOT spawned — network subscribe failed; \
                         node will not catch up if it falls behind"
                    );
                }
            }
        }

        // Validator-connectivity warm-up gate: before draining outbound
        // consensus messages, wait for at least one peer to be (a) connected
        // at the libp2p layer AND (b) admitted to the local validator
        // registry via the identify handshake.
        //
        // The previous gate (#143 era) waited for the gossipsub mesh on
        // `tenzro/consensus`. Since #144 moved HotStuff-2 vote / proposal /
        // timeout / NEC publishing onto the consensus-direct request-response
        // overlay, gossipsub mesh state is no longer the right signal —
        // `tenzro/consensus` carries zero traffic on a steady fleet (the
        // topic is only kept subscribable for observers). The meaningful
        // liveness condition for direct-overlay broadcast is "I have a
        // dialable connection open to a validator I'm willing to send to."
        //
        // The identify-driven admission race remains: `try_register_validator_on_identify`
        // fires asynchronously after the libp2p connection is up, and any
        // `BroadcastToValidators` issued before it completes dispatches to
        // an empty validator set (`Ok(0)` — silently no-op). Polling
        // `connected_validator_count` collapses both conditions: a non-zero
        // count means at least one peer is both connected AND admitted.
        //
        // **Retry until ready** (lesson from 2026-04-30 wedge — see
        // `hotstuff2.rs::resume_from_height` regression). Previously we
        // proceeded after a 30s timeout in "degraded mode", which in
        // production meant validator-0 booted with admitted=0, broadcast
        // proposals into the void, and never received the SyncInfo gossip
        // it needed to advance its pacemaker — so the wedge persisted
        // until manual intervention. We poll in 30s windows indefinitely,
        // logging each iteration so operators can diagnose stalls. A node
        // that never achieves admitted ≥ 1 is genuinely isolated and
        // should not be pretending to participate in consensus.
        // Subscribe to shutdown early so the warm-up loop below can be
        // interrupted cleanly while waiting for validator peers.
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        // Edge nodes (no consensus engine — ModelProvider-only, storage-
        // only, etc.) MUST NOT enter the validator warm-up. They have no
        // consensus role, so waiting for admitted validator peers is
        // (a) pointless — they can't participate anyway — and (b) noisy
        // in the log, emitting a 30 s "Bootstrap quorum not yet reached"
        // warning every attempt until infinity. Fixed 2026-07-16 after
        // a Studio dev launch spent minutes emitting this warning for
        // a NAT'd edge ModelProvider that never intended to validate.
        if self.consensus.is_some()
            && let Some(network) = self.network.as_ref()
        {
            const ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
            let warmup_start = std::time::Instant::now();
            let mut attempt: u32 = 0;

            // **Bootstrap quorum threshold.** Wait for ≥ 2f+1 admitted
            // validator peers (the BFT safety threshold) before starting
            // consensus, not just ≥ 1. This is the standard production pattern
            // (wait-for-supermajority at genesis plus per-peer round-state
            // gossip): on a freshly-bootstrapped
            // fleet, starting consensus with only 1 peer admitted means the
            // first many views proceed without quorum, the pacemaker burns
            // through its timeout schedule, and validators end up at
            // wildly skewed views by the time the rest catch up. Gating on
            // ≥ 2f+1 ensures view 0 begins with enough peers to actually
            // finalize a block on the first round. The threshold is
            // computed from the active validator set at start time.
            //
            // `connected_validator_count` counts admitted validator PEERS —
            // it excludes the local peer. A single-node validator set (solo
            // bootstrap: `--roles validator` with no genesis file) therefore
            // has no peer that could ever satisfy the gate; the local
            // validator IS the quorum, so the gate is skipped entirely.
            let validator_set_len = self
                .consensus
                .as_ref()
                .map(|c| c.epoch_manager().current_validator_set().len());
            let admitted_threshold = if let Some(n) = validator_set_len {
                // 2f+1 where f = (n-1)/3. Equivalent to n - f.
                let f = (n.saturating_sub(1)) / 3;
                n.saturating_sub(f).max(1)
            } else {
                1
            };
            let solo_validator_set = validator_set_len == Some(1);

            'warmup: loop {
                if solo_validator_set {
                    info!(
                        "Single-node validator set — local validator is the quorum; \
                         skipping validator connectivity warm-up"
                    );
                    break 'warmup;
                }
                attempt = attempt.saturating_add(1);
                tokio::select! {
                    biased;
                    _ = shutdown_rx.recv() => {
                        info!("Shutdown requested during validator warm-up — exiting event loop");
                        return Ok(());
                    }
                    res = network.wait_for_connected_validators(admitted_threshold, ATTEMPT_TIMEOUT) => {
                        match res {
                            Ok(count) if count >= admitted_threshold => {
                                info!(
                                    connected_validators = count,
                                    admitted_threshold = admitted_threshold,
                                    attempts = attempt,
                                    elapsed_secs = warmup_start.elapsed().as_secs(),
                                    "Bootstrap quorum reached — starting consensus with ≥ 2f+1 admitted peers"
                                );
                                break 'warmup;
                            }
                            Ok(count) => {
                                warn!(
                                    connected_validators = count,
                                    admitted_threshold = admitted_threshold,
                                    attempts = attempt,
                                    elapsed_secs = warmup_start.elapsed().as_secs(),
                                    "Bootstrap quorum not yet reached — waiting for ≥ 2f+1 admitted peers \
                                     before starting consensus (avoids pacemaker race on staggered boot)"
                                );
                            }
                            Err(e) => {
                                warn!(
                                    attempts = attempt,
                                    elapsed_secs = warmup_start.elapsed().as_secs(),
                                    error = %e,
                                    "Validator warm-up: query failed — retrying"
                                );
                            }
                        }
                    }
                }
                // Brief backoff between attempts. wait_for_connected_validators
                // already polls every 100ms internally, so this just adds a
                // small breath between full 30s windows.
                tokio::select! {
                    biased;
                    _ = shutdown_rx.recv() => {
                        info!("Shutdown requested during validator warm-up backoff — exiting event loop");
                        return Ok(());
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                }
            }
        }

        // Subscribe to consensus finality notifications if consensus is available.
        // This is how finalized blocks flow from HotStuff-2 into the execution pipeline.
        let mut finality_rx = self.consensus.as_ref().map(|c| c.subscribe_finality());

        // Periodic peer-count refresh: runs every 3 seconds regardless of block production.
        // Without this, non-validator nodes (model-provider, light clients) that never call
        // handle_block_finalized() would always report peer_count=0 in /status even when
        // they have active P2P connections. The interval is deliberately short (was 30s) so
        // the desktop UI status bar flips from "Connecting · Peers 0" to "Connected" within a
        // few seconds of the first peer handshake instead of lagging up to half a minute —
        // `connected_peers()` is a cheap in-memory swarm query, so polling at 3s is fine.
        let mut peer_refresh = tokio::time::interval(std::time::Duration::from_secs(3));
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

        // Heartbeat: announce locally held iroh blobs every 60s so peers can
        // populate their blob-provider hint caches and fetch
        // `tenzro://blob/...` URIs without an explicit provider hint.
        let mut blob_heartbeat = tokio::time::interval(std::time::Duration::from_secs(60));
        blob_heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

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
                // Block-sync engine has a peer-served block ready to import.
                // The engine has already extracted and verified the embedded
                // commit-QC against the active validator set; here we simply
                // run the block through the same execution pipeline used by
                // organic finality, with `from_sync = true` so we skip
                // gossip rebroadcast and per-block epoch-transition hooks
                // (validators producing the chain handle those).
                //
                // Branch is gated by `block_import_rx.is_some()`: nodes
                // without a network service have no engine and therefore no
                // channel — the inner future stays pending forever.
                Some(import) = async {
                    match self.block_import_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending::<Option<crate::block_sync::BlockImport>>().await,
                    }
                } => {
                    let crate::block_sync::BlockImport { block, serving_peer: _, result } = import;
                    let height = block.height();
                    let outcome = self.handle_block_imported_from_sync(block).await;
                    let reply = match outcome {
                        Ok(()) => Ok(()),
                        Err(e) => Err(format!("import height {} failed: {}", height, e)),
                    };
                    // The engine drops the receiver if it has lost interest
                    // (peer disconnected, sync run aborted) — silent send
                    // failure is not an error here.
                    let _ = result.send(reply);
                }
                // Periodic peer count refresh — independent of block finalization.
                // Ensures /status always reflects the current P2P connection state.
                _ = peer_refresh.tick() => {
                    if let Some(ref network) = self.network
                        && let Ok(peers) = network.connected_peers().await {
                            let count = peers.len() as u64;
                            self.metrics.set_peer_count(count);
                            debug!(peer_count = count, "Periodic peer count refresh");
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
                                if let Some(mut svc) = services.get_mut(&instance_id)
                                    && svc.last_seen < now {
                                        svc.last_seen = now;
                                        if let Ok(data) = serde_json::to_vec(svc.value()) {
                                            let _ = self.storage.put(
                                                CF_MODEL_SERVICES,
                                                instance_id.as_bytes(),
                                                &data,
                                            );
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
                                    format!("served:{}", model_id).as_bytes(),
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

                    // 2. Re-announce locally served models via gossipsub.
                    // Requires the provider-announcement context (provider address +
                    // signer) so the heartbeat carries the same `provider` key and
                    // signature that consumers require — an unsigned or provider-empty
                    // heartbeat is dropped on ingest and never refreshes the TTL.
                    if let (Some(network), Some(served), Some(ctx), Some(signer)) = (
                        &self.network,
                        &self.served_models,
                        &self.provider_announcement_ctx,
                        &self.announce_signer,
                    ) {
                        let local_peer_id = match network.local_peer_id().await {
                            Ok(pid) => pid.to_string(),
                            Err(e) => {
                                debug!(error = %e, "Skipping model heartbeat: local_peer_id unavailable");
                                continue;
                            }
                        };
                        let provider_address = ctx.provider_address.clone();
                        let signer = signer.clone();
                        let pricing = self.provider_pricing.as_ref().map(|p| p.read().clone());
                        let schedule = self.provider_schedule.as_ref().map(|s| s.read().clone());
                        let rpc_addr = self.rpc_addr.clone();

                        for entry in served.iter() {
                            // Private models are never announced — no heartbeat,
                            // no TTL refresh on remote nodes, no discovery.
                            if !entry.value().is_network() {
                                continue;
                            }
                            let model_id = entry.key().clone();
                            let pricing_info = tenzro_network::PricingInfo {
                                per_request: 0,
                                per_token: pricing.as_ref().map(|p| {
                                    p.input_price_per_token_wei.min(u64::MAX as u128) as u64
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
                            let mut reg = tenzro_network::ModelRegistrationMessage {
                                model_id: model_id.clone(),
                                name: model_id.clone(),
                                description: String::new(),
                                modality: "text".to_string(),
                                category: String::new(),
                                parameters: String::new(),
                                context_length: 0,
                                provider: provider_address.clone(),
                                peer_id: local_peer_id.clone(),
                                pricing: pricing_info,
                                schedule: msg_schedule,
                                visibility: "network".to_string(),
                                ttl_secs: 120,
                                timestamp: chrono::Utc::now().timestamp_millis(),
                                withdrawn: false,
                                rpc_endpoint: format!("http://{}", rpc_addr),
                                iroh_endpoint_id: self
                                    .iroh_resolver
                                    .as_ref()
                                    .map(|r| r.endpoint_id().to_string())
                                    .unwrap_or_default(),
                                ..Default::default()
                            };
                            if let Err(e) = reg.sign(signer.as_ref()) {
                                warn!(error = %e, model_id = %model_id, "Skipping model heartbeat: signing failed");
                                continue;
                            }
                            let broadcast_msg = tenzro_network::NetworkMessage::new(
                                tenzro_network::MessagePayload::ModelRegistration(reg),
                            );
                            let net = network.clone();
                            tokio::spawn(async move {
                                if let Err(e) = net.broadcast("tenzro/models", broadcast_msg).await {
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

                    // 3. Re-announce locally registered agents via gossipsub.
                    // Requires the announce signer — unsigned agent announcements
                    // are rejected by every consumer.
                    if let (Some(network), Some(ar), Some(signer)) =
                        (&self.network, &self.agent_runtime, &self.announce_signer)
                    {
                        let local_peer_id = match network.local_peer_id().await {
                            Ok(pid) => pid.to_string(),
                            Err(e) => {
                                debug!(error = %e, "Skipping agent heartbeat: local_peer_id unavailable");
                                continue;
                            }
                        };
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
                            let mut ann = tenzro_network::AgentAnnouncementMessage {
                                agent_id: a.identity.agent_id.clone(),
                                name: a.identity.name.clone(),
                                agent_type: "tenzroclaw".to_string(),
                                capabilities: cap_names,
                                status: a.status.as_str().to_string(),
                                origin_peer_id: local_peer_id.clone(),
                                rpc_endpoint: format!("http://{}", rpc_addr),
                                timestamp: chrono::Utc::now().timestamp_millis(),
                                ttl_secs: 180,
                                pubkey: Vec::new(),
                                signature: Vec::new(),
                            };
                            if let Err(e) = ann.sign(signer.as_ref()) {
                                warn!(error = %e, agent_id = %a.identity.agent_id, "Skipping agent heartbeat: signing failed");
                                continue;
                            }
                            let broadcast_msg = tenzro_network::NetworkMessage::new(
                                tenzro_network::MessagePayload::AgentAnnouncement(ann),
                            );
                            let net = network.clone();
                            let agent_id = a.identity.agent_id.clone();
                            tokio::spawn(async move {
                                if let Err(e) = net.broadcast("tenzro/agents", broadcast_msg).await {
                                    tracing::debug!(error = %e, agent_id = %agent_id, "Failed to broadcast agent heartbeat");
                                }
                            });
                        }
                    }
                }
                // Provider heartbeat: evict expired network_providers entries every 60s
                // AND re-broadcast a `ProviderAnnouncementMessage` so peers learn about
                // this node's served models, hardware envelope, and declared geography.
                _ = provider_heartbeat.tick() => {
                    if let Some(ref np) = self.network_providers {
                        let now = std::time::Instant::now();
                        // Collect the provider addresses evicted this pass so
                        // the ProviderManager can prune them too — an expired
                        // gossip entry must stop being routable, not just
                        // vanish from the discovery cache.
                        let mut evicted: Vec<String> = Vec::new();
                        np.retain(|_key, entry| {
                            let ttl = std::time::Duration::from_secs(entry.announcement.ttl_secs);
                            let alive = now.duration_since(entry.last_seen) < ttl;
                            if !alive {
                                evicted.push(entry.announcement.provider_address.clone());
                            }
                            alive
                        });
                        if let Some(ref pm) = self.provider_manager {
                            for addr_hex in &evicted {
                                if let Ok(address) =
                                    tenzro_types::primitives::Address::from_hex(addr_hex)
                                {
                                    pm.remove_provider(&address);
                                }
                            }
                        }
                    }

                    // Broadcast our own provider announcement (only if context +
                    // announce signer wired — unsigned announcements are rejected
                    // by every consumer).
                    if let (Some(network), Some(ctx), Some(signer)) = (
                        &self.network,
                        &self.provider_announcement_ctx,
                        &self.announce_signer,
                    ) {
                        // Private models are excluded from provider announcements —
                        // the served list on the wire only carries network-visible ids.
                        let served: Vec<String> = self.served_models
                            .as_ref()
                            .map(|m| {
                                m.iter()
                                    .filter(|e| e.value().is_network())
                                    .map(|e| e.key().clone())
                                    .collect()
                            })
                            .unwrap_or_default();

                        let local_peer_id = match network.local_peer_id().await {
                            Ok(pid) => pid.to_string(),
                            Err(e) => {
                                debug!(error = %e, "Skipping provider announcement: local_peer_id unavailable");
                                continue;
                            }
                        };

                        // A storage-serving node advertises its iroh EndpointId
                        // so HRW replica self-selection has a stable candidate id
                        // per peer. Empty on nodes without a bound resolver.
                        let iroh_endpoint_id = self
                            .iroh_resolver
                            .as_ref()
                            .map(|r| r.endpoint_id().to_string())
                            .unwrap_or_default();

                        // Advertised capacity is read live from the self entry
                        // in the ProviderManager each tick — MoE expert-shard
                        // declarations installed after startup (expert/gate
                        // loads) must ride the next heartbeat, so the static
                        // context snapshot is only the no-entry fallback.
                        let capacity = self
                            .provider_manager
                            .as_ref()
                            .and_then(|pm| {
                                let hexstr = ctx
                                    .provider_address
                                    .strip_prefix("0x")
                                    .unwrap_or(&ctx.provider_address);
                                tenzro_types::primitives::Address::from_hex(hexstr)
                                    .ok()
                                    .and_then(|addr| pm.get_provider(&addr).ok())
                            })
                            .map(|p| {
                                let mut c = p.capacity.advertised();
                                c.verifiable_inference =
                                    c.verifiable_inference || ctx.capacity.verifiable_inference;
                                // Node config is the single source of truth for
                                // this node's jurisdiction claim — a self
                                // provider entry never overrides it.
                                c.jurisdiction = ctx.capacity.jurisdiction.clone();
                                c
                            })
                            .unwrap_or_else(|| ctx.capacity.clone());

                        // Refresh the advertised warm-prefix summary from the
                        // serving runtime each tick, so prefix-affinity routing
                        // reflects the prompts this provider currently holds
                        // warm rather than a startup snapshot. Fingerprints
                        // only (see `PrefixCacheSummary`); no KV bytes ride the
                        // announcement.
                        let mut capacity = capacity;
                        if let Some(ref rt) = self.model_runtime {
                            capacity.prefix_cache = rt.merged_warm_prefix_summary();
                        }

                        let mut ann = tenzro_network::ProviderAnnouncementMessage {
                            peer_id: local_peer_id,
                            provider_address: ctx.provider_address.clone(),
                            provider_type: ctx.provider_type.clone(),
                            served_models: served,
                            capabilities: ctx.capabilities.clone(),
                            rpc_endpoint: ctx.rpc_endpoint.clone(),
                            status: "active".to_string(),
                            timestamp: chrono::Utc::now().timestamp_millis(),
                            ttl_secs: ctx.ttl_secs,
                            runtime_support: tenzro_types::RuntimeSupport {
                                hosting_runtimes: hosting_runtime_classes(),
                                hosting_price_per_hour: ctx.hosting_price_per_hour,
                                ..Default::default()
                            },
                            network_profile: tenzro_types::NodeNetworkProfile {
                                reachability: network.reachability().tier().as_str().to_string(),
                                ..Default::default()
                            },
                            trust_profile: tenzro_types::TrustProfile::default(),
                            worker_roles: Vec::new(),
                            hardware: ctx.hardware.clone(),
                            capacity,
                            geography: ctx.geography.clone(),
                            iroh_endpoint_id,
                            cluster_profile: ctx.cluster_profile.clone(),
                            pubkey: Vec::new(),
                            signature: Vec::new(),
                        };
                        if let Err(e) = ann.sign(signer.as_ref()) {
                            warn!(error = %e, "Skipping provider announcement: signing failed");
                            continue;
                        }
                        let broadcast_msg = tenzro_network::NetworkMessage::new(
                            tenzro_network::MessagePayload::ProviderAnnouncement(ann),
                        );
                        let net = network.clone();
                        tokio::spawn(async move {
                            if let Err(e) = net.broadcast("tenzro/providers", broadcast_msg).await {
                                debug!(error = %e, "Failed to broadcast provider heartbeat");
                            }
                        });
                    }
                }
                // Blob availability heartbeat: enumerate the local iroh blob
                // store and broadcast signed announcements on `tenzro/blobs`.
                // Skipped when the resolver / network / signer are not wired
                // (unsigned announcements are rejected by every consumer).
                _ = blob_heartbeat.tick() => {
                    if let (Some(network), Some(resolver), Some(signer)) = (
                        &self.network,
                        &self.iroh_resolver,
                        &self.announce_signer,
                    ) {
                        let hashes = match resolver.local_blob_hashes().await {
                            Ok(h) => h,
                            Err(e) => {
                                debug!(error = %e, "Skipping blob announcement: blob enumeration failed");
                                continue;
                            }
                        };
                        if hashes.is_empty() {
                            continue;
                        }

                        let local_peer_id = match network.local_peer_id().await {
                            Ok(pid) => pid.to_string(),
                            Err(e) => {
                                debug!(error = %e, "Skipping blob announcement: local_peer_id unavailable");
                                continue;
                            }
                        };
                        let endpoint_id = resolver.endpoint_id().to_string();

                        // Chunk large stores so a single announcement stays
                        // well under gossipsub message-size limits (each hash
                        // is 64 hex chars; 512 per message ≈ 34 KiB payload).
                        const HASHES_PER_ANNOUNCEMENT: usize = 512;
                        for chunk in hashes.chunks(HASHES_PER_ANNOUNCEMENT) {
                            let mut ann = tenzro_network::BlobAnnouncementMessage {
                                endpoint_id: endpoint_id.clone(),
                                blob_hashes: chunk.to_vec(),
                                origin_peer_id: local_peer_id.clone(),
                                timestamp: chrono::Utc::now().timestamp_millis(),
                                ttl_secs: 180,
                                pubkey: Vec::new(),
                                signature: Vec::new(),
                            };
                            if let Err(e) = ann.sign(signer.as_ref()) {
                                warn!(error = %e, "Skipping blob announcement: signing failed");
                                break;
                            }
                            let broadcast_msg = tenzro_network::NetworkMessage::new(
                                tenzro_network::MessagePayload::BlobAnnouncement(ann),
                            );
                            let net = network.clone();
                            tokio::spawn(async move {
                                if let Err(e) = net.broadcast("tenzro/blobs", broadcast_msg).await {
                                    debug!(error = %e, "Failed to broadcast blob heartbeat");
                                }
                            });
                        }
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
                    if let Some(notification) = notification
                        && let Err(e) = self.process_finality_notification(notification).await {
                            error!("Failed to handle finalized block: {}", e);
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
                        // G6 batch-availability plane. Batch bodies, acks, and
                        // availability certificates travel on the dedicated
                        // `tenzro/batches` gossipsub topic (not the
                        // consensus-direct overlay), as opaque bincode blobs the
                        // consensus crate decodes on receipt — the network crate
                        // does not depend on the consensus crate. Peel these off
                        // before the consensus-message mapping below.
                        let batch_payload: Option<MessagePayload> = match &msg {
                            ConsensusOutMessage::Batch(batch) => {
                                match bincode::serialize(batch) {
                                    Ok(b) => Some(MessagePayload::BatchBody(b)),
                                    Err(e) => {
                                        warn!(error = %e, "batch_cert: failed to encode batch body; dropping");
                                        None
                                    }
                                }
                            }
                            ConsensusOutMessage::BatchAck { ack, .. } => {
                                match bincode::serialize(ack) {
                                    Ok(b) => Some(MessagePayload::BatchAvailability(b)),
                                    Err(e) => {
                                        warn!(error = %e, "batch_cert: failed to encode batch ack; dropping");
                                        None
                                    }
                                }
                            }
                            ConsensusOutMessage::BatchCertificate(cert) => {
                                match bincode::serialize(cert) {
                                    Ok(b) => Some(MessagePayload::BatchAvailability(b)),
                                    Err(e) => {
                                        warn!(error = %e, "batch_cert: failed to encode batch certificate; dropping");
                                        None
                                    }
                                }
                            }
                            _ => None,
                        };
                        if let Some(payload) = batch_payload {
                            if let Some(ref network) = self.network {
                                let network_clone = network.clone();
                                let net_msg = NetworkMessage::new(payload);
                                tokio::spawn(async move {
                                    if let Err(e) = network_clone.broadcast("tenzro/batches", net_msg).await {
                                        warn!(error = %e, "batch_cert: tenzro/batches broadcast failed");
                                    }
                                });
                            }
                            continue;
                        }
                        let dbg_kind = match &msg {
                            ConsensusOutMessage::Vote(_) => "Vote",
                            ConsensusOutMessage::Proposal { .. } => "Proposal",
                            ConsensusOutMessage::Timeout(_) => "Timeout",
                            ConsensusOutMessage::NoEndorsement(_) => "NoEndorsement",
                            // Batch variants are handled and `continue`d above.
                            ConsensusOutMessage::Batch(_)
                            | ConsensusOutMessage::BatchAck { .. }
                            | ConsensusOutMessage::BatchCertificate(_) => unreachable!(),
                        };
                        info!(kind = dbg_kind, "event_loop.outbound_consensus: received msg from consensus engine");
                        if let Some(ref network) = self.network {
                            // Build the wire-format `ConsensusMessage` for the
                            // consensus-direct overlay. Replaces the previous
                            // gossipsub `tenzro/consensus` publish path (#144).
                            // The `tenzro/consensus` topic is no longer
                            // published to anywhere in the codebase; observers
                            // (RPC nodes, light clients) follow consensus by
                            // subscribing to it for the legacy wire shape, but
                            // on a steady fleet of validators it carries zero
                            // traffic.
                            let net_msg: Option<ConsensusMessage> = match msg {
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
                                            Some(ConsensusMessage::Vote {
                                                block_hash: vote.block_hash,
                                                voter: hex::encode(vote.voter.as_bytes()),
                                                vote_type: net_vote_type,
                                                round: vote.view,
                                                height: vote.height.0,
                                                high_qc_view: vote.high_qc_view,
                                                signature: sig_bytes,
                                                public_key: pk_bytes,
                                                bls_signature: vote.bls_signature.to_bytes().to_vec(),
                                            })
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
                                    no_endorsement_certificate,
                                    proposer_signature,
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
                                    // NEC tail-fork defence: same encoding
                                    // strategy as TC. If the bytes drop, the receiver
                                    // will reject the fresh-after-TC proposal — the
                                    // chain falls back to a repropose-of-high-tip on
                                    // the next view, which is the safe behaviour.
                                    let nec_bytes = no_endorsement_certificate.as_ref().and_then(|nec| {
                                        match bincode::serialize(nec) {
                                            Ok(b) => Some(b),
                                            Err(e) => {
                                                warn!(error = %e, "Failed to encode NEC; dropping from proposal");
                                                None
                                            }
                                        }
                                    });
                                    // The proposer signature is mandatory —
                                    // receivers reject unsigned proposals, so
                                    // on encode failure drop the whole
                                    // outbound message rather than broadcast
                                    // one that every peer will discard.
                                    match bincode::serialize(&proposer_signature) {
                                        Ok(sig_bytes) => Some(ConsensusMessage::Proposal {
                                            block: Box::new(block),
                                            proposer: hex::encode(proposer.as_bytes()),
                                            round,
                                            high_qc_view,
                                            timeout_certificate: tc_bytes,
                                            no_endorsement_certificate: nec_bytes,
                                            proposer_signature: sig_bytes,
                                        }),
                                        Err(e) => {
                                            warn!(error = %e, "Failed to encode proposer signature; dropping proposal");
                                            None
                                        }
                                    }
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
                                            Some(ConsensusMessage::Timeout {
                                                format_version: timeout_msg.format_version,
                                                view: timeout_msg.view,
                                                high_qc_view: timeout_msg.high_qc_view,
                                                finalized_height: timeout_msg.finalized_height,
                                                voter: timeout_msg.voter,
                                                signature: sig_bytes,
                                                public_key: pk_bytes,
                                            })
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "Failed to encode hybrid timeout payload; dropping");
                                            None
                                        }
                                    }
                                }
                                ConsensusOutMessage::NoEndorsement(nec_msg) => {
                                    // No-endorsement attestation (NEC tail-fork
                                    // defence). Same hybrid signature
                                    // encoding as Timeout.
                                    let encoded = bincode::serialize(&nec_msg.signature)
                                        .and_then(|s| bincode::serialize(&nec_msg.public_key).map(|p| (s, p)));
                                    match encoded {
                                        Ok((sig_bytes, pk_bytes)) => {
                                            Some(ConsensusMessage::NoEndorsement {
                                                format_version: nec_msg.format_version,
                                                view: nec_msg.view,
                                                voter: nec_msg.voter,
                                                signature: sig_bytes,
                                                public_key: pk_bytes,
                                            })
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "Failed to encode hybrid no-endorsement payload; dropping");
                                            None
                                        }
                                    }
                                }
                                // Batch variants are handled and `continue`d above.
                                ConsensusOutMessage::Batch(_)
                                | ConsensusOutMessage::BatchAck { .. }
                                | ConsensusOutMessage::BatchCertificate(_) => unreachable!(),
                            };
                            if let Some(consensus_msg) = net_msg {
                                let network_clone = network.clone();
                                info!("event_loop.outbound_consensus: spawning consensus-direct broadcast to validator set");
                                tokio::spawn(async move {
                                    match network_clone.broadcast_to_validators(consensus_msg).await {
                                        Ok(n) => info!(dispatched = n, "event_loop.outbound_consensus: consensus-direct broadcast OK"),
                                        Err(e) => warn!(error = %e, "event_loop.outbound_consensus: consensus-direct broadcast FAILED"),
                                    }
                                });
                            } else {
                                warn!("event_loop.outbound_consensus: consensus_msg was None (encoding failed)");
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
                        NodeEvent::LocallyAdmittedTransaction(tx) => {
                            if let Err(e) = self.handle_locally_admitted_transaction(tx).await {
                                error!("Failed to handle locally-admitted transaction: {}", e);
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
                            if let Err(e) = reg.verify() {
                                warn!(
                                    model_id = %reg.model_id,
                                    provider = %reg.provider,
                                    error = %e,
                                    "Rejecting model announcement (signature verification failed)"
                                );
                            } else if let Err(e) = check_announcement_freshness(reg.timestamp, reg.ttl_secs) {
                                warn!(
                                    model_id = %reg.model_id,
                                    provider = %reg.provider,
                                    error = %e,
                                    "Rejecting model announcement (replay window)"
                                );
                            } else if let Some(ref nm) = self.network_models {
                                let key = format!("{}:{}", reg.model_id, reg.provider);
                                // First-seen pubkey pinning + monotonic timestamps:
                                // the map key is attacker-choosable, so a signature
                                // alone only proves self-consistency. Pin the pubkey
                                // that first claimed this (model, provider) pair and
                                // reject updates — including withdrawals — signed by
                                // any other key, plus replays of older signed states.
                                // Read prior fields into locals and drop the Ref
                                // before mutating the same map (DashMap deadlock rule).
                                let prior = nm
                                    .get(&key)
                                    .map(|e| (e.registration.pubkey.clone(), e.registration.timestamp));
                                if let Some((pinned_pubkey, prev_ts)) = prior {
                                    if pinned_pubkey != reg.pubkey {
                                        warn!(
                                            model_id = %reg.model_id,
                                            provider = %reg.provider,
                                            "Rejecting model announcement (pubkey differs from pinned key)"
                                        );
                                        continue;
                                    }
                                    if reg.timestamp <= prev_ts {
                                        debug!(
                                            model_id = %reg.model_id,
                                            provider = %reg.provider,
                                            "Dropping model announcement (non-monotonic timestamp)"
                                        );
                                        continue;
                                    }
                                }
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
                            if let Err(e) = ann.verify() {
                                warn!(
                                    agent_id = %ann.agent_id,
                                    origin_peer_id = %ann.origin_peer_id,
                                    error = %e,
                                    "Rejecting agent announcement (signature verification failed)"
                                );
                            } else if let Err(e) = check_announcement_freshness(ann.timestamp, ann.ttl_secs) {
                                warn!(
                                    agent_id = %ann.agent_id,
                                    error = %e,
                                    "Rejecting agent announcement (replay window)"
                                );
                            } else if let Some(ref na) = self.network_agents {
                                // First-seen pubkey pinning + monotonic timestamps
                                // (see ModelAnnouncement handler for rationale).
                                let prior = na
                                    .get(&ann.agent_id)
                                    .map(|e| (e.announcement.pubkey.clone(), e.announcement.timestamp));
                                if let Some((pinned_pubkey, prev_ts)) = prior {
                                    if pinned_pubkey != ann.pubkey {
                                        warn!(
                                            agent_id = %ann.agent_id,
                                            "Rejecting agent announcement (pubkey differs from pinned key)"
                                        );
                                        continue;
                                    }
                                    if ann.timestamp <= prev_ts {
                                        debug!(
                                            agent_id = %ann.agent_id,
                                            "Dropping agent announcement (non-monotonic timestamp)"
                                        );
                                        continue;
                                    }
                                }
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
                            if let Err(e) = ann.verify() {
                                warn!(
                                    peer_id = %ann.peer_id,
                                    provider_type = %ann.provider_type,
                                    error = %e,
                                    "Rejecting provider announcement (signature verification failed)"
                                );
                            } else if let Err(e) = check_announcement_freshness(ann.timestamp, ann.ttl_secs) {
                                warn!(
                                    peer_id = %ann.peer_id,
                                    error = %e,
                                    "Rejecting provider announcement (replay window)"
                                );
                            } else if let Some(ref np) = self.network_providers {
                                // First-seen pubkey pinning + monotonic timestamps
                                // (see ModelAnnouncement handler for rationale).
                                let prior = np
                                    .get(&ann.peer_id)
                                    .map(|e| (e.announcement.pubkey.clone(), e.announcement.timestamp));
                                if let Some((pinned_pubkey, prev_ts)) = prior {
                                    if pinned_pubkey != ann.pubkey {
                                        warn!(
                                            peer_id = %ann.peer_id,
                                            "Rejecting provider announcement (pubkey differs from pinned key)"
                                        );
                                        continue;
                                    }
                                    if ann.timestamp <= prev_ts {
                                        debug!(
                                            peer_id = %ann.peer_id,
                                            "Dropping provider announcement (non-monotonic timestamp)"
                                        );
                                        continue;
                                    }
                                }
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

                                // Bridge the verified announcement into the
                                // ProviderManager so the InferenceRouter can
                                // score and dispatch to this provider by its
                                // advertised HardwareCapabilities. Skip
                                // providers with no reachable endpoint, and
                                // providers that neither serve models nor
                                // declare MoE expert shards — those cannot be
                                // routed to. A pure expert holder (empty
                                // served_models, non-empty moe_holdings) must
                                // be admitted or the MoE shard view never sees
                                // it.
                                if let Some(ref pm) = self.provider_manager
                                    && !ann.rpc_endpoint.is_empty()
                                    && (!ann.served_models.is_empty()
                                        || !ann.capacity.moe_holdings.is_empty()
                                        || !ann.capacity.moe_roles.is_empty())
                                    && let Ok(address) =
                                        tenzro_types::primitives::Address::from_hex(&ann.provider_address)
                                {
                                    let has_tee = ann.hardware.tee_available
                                        || ann
                                            .capabilities
                                            .iter()
                                            .any(|c| c.contains("tee"));
                                    let status = match ann.status.as_str() {
                                        "active" | "" => {
                                            tenzro_types::model::ProviderStatus::Active
                                        }
                                        "draining" | "inactive" => {
                                            tenzro_types::model::ProviderStatus::Inactive
                                        }
                                        _ => tenzro_types::model::ProviderStatus::Active,
                                    };
                                    let signing_pubkey = if ann.pubkey.is_empty() {
                                        None
                                    } else {
                                        Some(ann.pubkey.clone())
                                    };
                                    let iroh_endpoint_id = if ann.iroh_endpoint_id.is_empty() {
                                        None
                                    } else {
                                        Some(ann.iroh_endpoint_id.clone())
                                    };
                                    pm.upsert_from_announcement(
                                        address,
                                        ann.peer_id.clone(),
                                        Some(ann.rpc_endpoint.clone()),
                                        ann.served_models.clone(),
                                        ann.hardware.clone(),
                                        ann.capacity.clone(),
                                        status,
                                        has_tee,
                                        signing_pubkey,
                                        iroh_endpoint_id,
                                    );
                                }
                            }
                        }
                        NodeEvent::BlobAnnouncement(ann) => {
                            if let Err(e) = ann.verify() {
                                warn!(
                                    endpoint_id = %ann.endpoint_id,
                                    error = %e,
                                    "Rejecting blob announcement (signature verification failed)"
                                );
                            } else if let Err(e) = check_announcement_freshness(ann.timestamp, ann.ttl_secs) {
                                warn!(
                                    endpoint_id = %ann.endpoint_id,
                                    error = %e,
                                    "Rejecting blob announcement (replay window)"
                                );
                            } else if let Some(ref resolver) = self.iroh_resolver {
                                match ann.endpoint_id.parse::<tenzro_iroh::EndpointId>() {
                                    Ok(provider) => {
                                        for hash in &ann.blob_hashes {
                                            resolver.record_blob_provider(hash, provider);
                                        }
                                        debug!(
                                            endpoint_id = %ann.endpoint_id,
                                            blobs = ann.blob_hashes.len(),
                                            "Recorded blob providers from gossipsub announcement"
                                        );
                                    }
                                    Err(e) => warn!(
                                        endpoint_id = %ann.endpoint_id,
                                        error = %e,
                                        "Rejecting blob announcement (unparseable endpoint id)"
                                    ),
                                }
                            }
                        }
                        NodeEvent::ShardReplication(req) => {
                            if let Err(e) = req.verify() {
                                warn!(
                                    object_id = %req.object_id,
                                    error = %e,
                                    "Rejecting shard replication request (signature verification failed)"
                                );
                            } else if let Err(e) =
                                check_announcement_freshness(req.timestamp, req.ttl_secs)
                            {
                                warn!(
                                    object_id = %req.object_id,
                                    error = %e,
                                    "Rejecting shard replication request (replay window)"
                                );
                            } else if let (Some(replicas), Some(resolver)) =
                                (self.storage_replicas, self.iroh_resolver.as_ref())
                            {
                                let own_endpoint = resolver.endpoint_id().to_string();
                                // Never pin from ourselves — the origin already
                                // holds every shard.
                                if own_endpoint != req.origin_endpoint_id {
                                    // Candidate membership view: storage-capable
                                    // providers discovered via gossip, plus the
                                    // origin, plus self — each tagged with its
                                    // data-plane reachability. Self and any peer
                                    // on the local mDNS segment are LocalDirect;
                                    // remote providers map their announced WAN
                                    // tier. Self-selection prefers local-segment
                                    // holders and only spills onto the wider
                                    // network when the segment is too small. The
                                    // view is a local snapshot; skew self-heals
                                    // as heartbeats converge.
                                    use tenzro_storage_provider::TieredCandidate;
                                    let mut candidates: Vec<TieredCandidate> = vec![
                                        // Self is always on its own segment.
                                        TieredCandidate::local(own_endpoint.clone()),
                                        // The origin is directly reachable — it
                                        // just published the shards.
                                        TieredCandidate::direct(req.origin_endpoint_id.clone()),
                                    ];
                                    if let Some(ref np) = self.network_providers {
                                        for entry in np.iter() {
                                            let ann = &entry.value().announcement;
                                            if ann
                                                .capabilities
                                                .iter()
                                                .any(|c| c == "storage")
                                                && !ann.iroh_endpoint_id.is_empty()
                                            {
                                                let on_local_segment = self
                                                    .local_peers
                                                    .as_ref()
                                                    .map(|set| set.contains(&ann.peer_id))
                                                    .unwrap_or(false);
                                                let reachability =
                                                    member_reachability_from_announcement(
                                                        &ann.network_profile.reachability,
                                                        on_local_segment,
                                                    );
                                                candidates.push(TieredCandidate {
                                                    endpoint_id: ann.iroh_endpoint_id.clone(),
                                                    reachability,
                                                });
                                            }
                                        }
                                    }

                                    let origin = req.origin_endpoint_id.clone();
                                    let mut pinned = 0usize;
                                    for shard in &req.shards {
                                        if tenzro_storage_provider::should_replicate_tiered(
                                            &shard.commitment,
                                            &own_endpoint,
                                            true,
                                            &candidates,
                                            replicas,
                                        ) {
                                            resolver.record_blob_provider(
                                                &shard.blob_hash,
                                                match origin.parse::<tenzro_iroh::EndpointId>() {
                                                    Ok(ep) => ep,
                                                    Err(e) => {
                                                        warn!(
                                                            object_id = %req.object_id,
                                                            origin = %origin,
                                                            error = %e,
                                                            "Shard replication: unparseable origin endpoint id"
                                                        );
                                                        break;
                                                    }
                                                },
                                            );
                                            let uri = tenzro_iroh::TenzroUri::Blob {
                                                hash: shard.blob_hash.clone(),
                                                provider_hint: Some(origin.clone()),
                                            };
                                            match resolver.fetch_bytes(&uri).await {
                                                Ok(_) => pinned += 1,
                                                Err(e) => warn!(
                                                    object_id = %req.object_id,
                                                    shard_index = shard.index,
                                                    error = %e,
                                                    "Shard replication: failed to pin shard"
                                                ),
                                            }
                                        }
                                    }
                                    if pinned > 0 {
                                        info!(
                                            object_id = %req.object_id,
                                            pinned,
                                            total_shards = req.shards.len(),
                                            "Pinned shards via rendezvous self-selection"
                                        );
                                    }
                                }
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
                        NodeEvent::TrainingGossipReceived { topic, bytes } => {
                            match tenzro_training::decode_for_topic(&topic, &bytes) {
                                Ok(tenzro_training::TrainingGossipMessage::OuterGradient(g)) => {
                                    let task_id = g.task_id.clone();
                                    let round = g.round;
                                    let fragment = g.fragment;
                                    let trainer_did = g.trainer_did.clone();
                                    if let Some(ref runtime) = self.training_runtime {
                                        // Clone the Arc out of the DashMap before any
                                        // `.await` so we never hold a `Ref` guard across
                                        // the eviction await (DashMap deadlock safety).
                                        let state = runtime.syncers.get(&task_id).map(|s| s.clone());
                                        match state {
                                            Some(state) => match state.accept_outer_gradient(g) {
                                                Ok(()) => info!(
                                                    %task_id,
                                                    round,
                                                    fragment,
                                                    %trainer_did,
                                                    "Ingested OuterGradient from gossip"
                                                ),
                                                Err(e) => {
                                                    // A submission that deviates from the task
                                                    // spec it enrolled under (bad signature,
                                                    // wrong quantization, out-of-stage fragment,
                                                    // missing attestation, malformed payload) is
                                                    // slashed + evicted. Benign timing/scope
                                                    // races (stale round, inactive shard) are not.
                                                    if e.is_slashable_rejection() {
                                                        warn!(
                                                            %task_id,
                                                            %trainer_did,
                                                            error = %e,
                                                            "Slashing + evicting trainer for poison OuterGradient"
                                                        );
                                                        state
                                                            .evict_trainer(
                                                                &trainer_did,
                                                                tenzro_training::slashing::EvictionReason::AcceptRejected,
                                                            )
                                                            .await;
                                                    } else {
                                                        warn!(
                                                            %task_id,
                                                            %trainer_did,
                                                            error = %e,
                                                            "Failed to accept gossiped OuterGradient"
                                                        );
                                                    }
                                                }
                                            },
                                            None => debug!(
                                                %task_id,
                                                "Dropping gossiped OuterGradient for unknown task"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            %task_id,
                                            "Dropping gossiped OuterGradient (training runtime not wired)"
                                        );
                                    }
                                }
                                Ok(tenzro_training::TrainingGossipMessage::SyncRound(r)) => {
                                    // Multi-syncer witness pattern: every node that holds
                                    // the run's syncer state attempts to apply the round
                                    // locally. `finalize_round` is idempotent on
                                    // matching (round, state_root) and surfaces
                                    // `ConflictingFinalize` on divergence — that is the
                                    // fork-detection signal.
                                    let task_id = r.task_id.clone();
                                    let round = r.round;
                                    let state_root = r.state_root;
                                    let is_nec = r.no_quorum_witnesses.is_some();
                                    if let Some(ref runtime) = self.training_runtime {
                                        if let Some(state) = runtime.syncers.get(&task_id) {
                                            match state.finalize_round(round, state_root) {
                                                Ok(()) => {
                                                    if let Err(e) = runtime.persist_run(&state) {
                                                        warn!(
                                                            %task_id,
                                                            error = %e,
                                                            "Failed to persist run after gossiped SyncRound apply"
                                                        );
                                                    }
                                                    info!(
                                                        %task_id,
                                                        round,
                                                        %state_root,
                                                        nec = is_nec,
                                                        "Applied SyncRound from gossip"
                                                    );
                                                }
                                                Err(tenzro_training::TrainingError::ConflictingFinalize {
                                                    expected,
                                                    got,
                                                    ..
                                                }) => {
                                                    // Fork: a peer witness committed a
                                                    // different state_root for the same
                                                    // round. Log loudly — fraud-proof
                                                    // path is not implemented yet.
                                                    warn!(
                                                        %task_id,
                                                        round,
                                                        expected = %expected,
                                                        got = %got,
                                                        "Fork detected on training round (ConflictingFinalize)"
                                                    );
                                                }
                                                Err(e) => debug!(
                                                    %task_id,
                                                    round,
                                                    error = %e,
                                                    "SyncRound apply skipped"
                                                ),
                                            }
                                        } else {
                                            debug!(
                                                %task_id,
                                                round,
                                                "Observed SyncRound for unknown task"
                                            );
                                        }
                                    } else {
                                        debug!(
                                            %task_id,
                                            round,
                                            %state_root,
                                            "Observed SyncRound (training runtime not wired)"
                                        );
                                    }
                                }
                                Ok(tenzro_training::TrainingGossipMessage::InstallSealedManifest(
                                    manifest,
                                )) => {
                                    // Phase B2 (#217): enrolled trainers in any
                                    // region learn the sponsor-signed binding
                                    // from `tenzro/training`. `install_sealed_manifest`
                                    // is idempotent on (task_id, manifest_hash) and
                                    // also verifies the manifest binds the task spec's
                                    // `tee://<hex>` dataset_ref — so re-receiving the
                                    // publisher's own broadcast or a duplicate from a
                                    // neighbor witness is a safe no-op.
                                    let task_id = manifest.task_id.clone();
                                    let envelope_count = manifest.envelopes.len();
                                    if let Some(ref runtime) = self.training_runtime {
                                        match runtime.install_sealed_manifest(manifest) {
                                            Ok(_) => info!(
                                                %task_id,
                                                envelope_count,
                                                "Installed SealedDatasetManifest from gossip"
                                            ),
                                            Err(e) => debug!(
                                                %task_id,
                                                error = %e,
                                                "SealedDatasetManifest install skipped"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            %task_id,
                                            "Observed SealedDatasetManifest (training runtime not wired)"
                                        );
                                    }
                                }
                                Err(e) => warn!(
                                    %topic,
                                    error = %e,
                                    "Failed to decode TrainingGossip payload"
                                ),
                            }
                        }
                        NodeEvent::MediaGenGossipReceived { topic, bytes } => {
                            match tenzro_media_gen::decode_for_topic(&topic, &bytes) {
                                Ok(tenzro_media_gen::MediaGenGossipMessage::WorkerEnrolled(
                                    capability,
                                )) => {
                                    // Announcement only. The runtime's worker
                                    // registry is what `claim_job` authorizes
                                    // against, so a remote capability must not
                                    // enter it — otherwise a local RPC caller
                                    // could claim work on a remote worker's
                                    // behalf. Nothing on this node reads a
                                    // remote worker's capability, so nothing
                                    // stores it.
                                    debug!(
                                        worker_did = %capability.worker_did,
                                        models = capability.supported_models.len(),
                                        experts = capability.expert_holdings.len(),
                                        "Observed media-gen worker enrollment on a remote node"
                                    );
                                }
                                Ok(tenzro_media_gen::MediaGenGossipMessage::JobPosted(spec)) => {
                                    // Whether a job splits is a property of the
                                    // model, not of the spec: the protocol crate
                                    // is catalog-free, so the posting side reads
                                    // the catalog and the receiving side has to
                                    // read it too to reconstruct the same job.
                                    let job_id = spec.job_id.clone();
                                    let splits =
                                        tenzro_model::media_gen_model_splits(&spec.model_id);
                                    if let Some(ref runtime) = self.media_gen_runtime {
                                        let posted = if splits {
                                            runtime.post_split_job(spec)
                                        } else {
                                            runtime.post_job(spec)
                                        };
                                        match posted {
                                            Ok(job) => info!(
                                                %job_id,
                                                model_id = %job.task_spec.model_id,
                                                split = splits,
                                                "Mirrored media-gen job posted on a remote node"
                                            ),
                                            Err(
                                                tenzro_media_gen::MediaGenError::JobAlreadyExists {
                                                    ..
                                                },
                                            ) => debug!(
                                                %job_id,
                                                "Media-gen job already held; re-delivery ignored"
                                            ),
                                            Err(e) => warn!(
                                                %job_id,
                                                error = %e,
                                                "Rejected gossiped media-gen job"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            %job_id,
                                            "Observed media-gen job (runtime not wired)"
                                        );
                                    }
                                }
                                Ok(tenzro_media_gen::MediaGenGossipMessage::JobClaimed(claim)) => {
                                    let job_id = claim.job_id.clone();
                                    if let Some(ref runtime) = self.media_gen_runtime {
                                        match runtime.observe_claim(&claim) {
                                            Ok(job) => info!(
                                                %job_id,
                                                worker_did = %claim.worker_did,
                                                role = ?claim.role,
                                                status = %job.status,
                                                "Mirrored media-gen claim"
                                            ),
                                            Err(e) => debug!(
                                                %job_id,
                                                error = %e,
                                                "Media-gen claim not applied"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            %job_id,
                                            "Observed media-gen claim (runtime not wired)"
                                        );
                                    }
                                }
                                Ok(tenzro_media_gen::MediaGenGossipMessage::HandoffPublished {
                                    handoff,
                                    latent_locator,
                                }) => {
                                    // Record the locator before the commitment.
                                    // The low-noise worker on this node reads
                                    // the handoff to decide it can start, and
                                    // the fetch it makes next needs the
                                    // translation from the SHA-256 the handoff
                                    // names into the BLAKE3 iroh-blobs indexes.
                                    let job_id = handoff.job_id.clone();
                                    if let (Some(store), Some(locator)) =
                                        (&self.media_gen_output_store, latent_locator)
                                    {
                                        store.record_blake3(handoff.latent_hash, locator);
                                    }
                                    if let Some(ref runtime) = self.media_gen_runtime {
                                        match runtime.observe_handoff(handoff) {
                                            Ok(job) => info!(
                                                %job_id,
                                                steps_completed = job
                                                    .handoff
                                                    .as_ref()
                                                    .map(|h| h.steps_completed)
                                                    .unwrap_or(0),
                                                "Mirrored media-gen handoff"
                                            ),
                                            Err(e) => debug!(
                                                %job_id,
                                                error = %e,
                                                "Media-gen handoff not applied"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            %job_id,
                                            "Observed media-gen handoff (runtime not wired)"
                                        );
                                    }
                                }
                                Ok(tenzro_media_gen::MediaGenGossipMessage::ReceiptSubmitted {
                                    receipt,
                                    output_locator,
                                }) => {
                                    let job_id = receipt.job_id.clone();
                                    if let (Some(store), Some(locator)) =
                                        (&self.media_gen_output_store, output_locator)
                                    {
                                        store.record_blake3(receipt.output_hash, locator);
                                    }
                                    if let Some(ref runtime) = self.media_gen_runtime {
                                        match runtime.observe_receipt(receipt) {
                                            Ok(job) => info!(
                                                %job_id,
                                                status = %job.status,
                                                "Mirrored media-gen receipt"
                                            ),
                                            Err(e) => debug!(
                                                %job_id,
                                                error = %e,
                                                "Media-gen receipt not applied"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            %job_id,
                                            "Observed media-gen receipt (runtime not wired)"
                                        );
                                    }
                                }
                                Err(e) => warn!(
                                    %topic,
                                    error = %e,
                                    "Failed to decode MediaGenGossip payload"
                                ),
                            }
                        }
                        NodeEvent::SeedAgentGossipReceived { topic, bytes } => {
                            match tenzro_token::decode_seed_agent_for_topic(&topic, &bytes) {
                                Ok(tenzro_token::SeedAgentGossipMessage::CharterUpserted(
                                    charter,
                                )) => {
                                    let charter_id = charter.charter_id;
                                    let name = charter.name.clone();
                                    if let Some(ref manager) = self.seed_agent_manager {
                                        match manager.upsert_charter(charter) {
                                            Ok(()) => info!(
                                                charter_id = ?charter_id,
                                                %name,
                                                "Applied gossiped SeedAgent CharterUpserted"
                                            ),
                                            Err(e) => warn!(
                                                charter_id = ?charter_id,
                                                error = %e,
                                                "Failed to apply gossiped CharterUpserted"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            charter_id = ?charter_id,
                                            "Dropping gossiped CharterUpserted (seed-agent manager not wired)"
                                        );
                                    }
                                }
                                Ok(tenzro_token::SeedAgentGossipMessage::EarmarkUpdated(
                                    earmark,
                                )) => {
                                    let allocation_remaining = earmark.allocation_remaining_wei;
                                    let charter_count = earmark.charter_ids.len();
                                    if let Some(ref manager) = self.seed_agent_manager {
                                        match manager.apply_earmark(earmark) {
                                            Ok(()) => info!(
                                                allocation_remaining,
                                                charter_count,
                                                "Applied gossiped SeedAgent EarmarkUpdated"
                                            ),
                                            Err(e) => warn!(
                                                error = %e,
                                                "Failed to apply gossiped EarmarkUpdated"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            "Dropping gossiped EarmarkUpdated (seed-agent manager not wired)"
                                        );
                                    }
                                }
                                Ok(tenzro_token::SeedAgentGossipMessage::AgentRegistered(
                                    record,
                                )) => {
                                    let agent_did = record.agent_did.clone();
                                    let charter_id = record.charter_id;
                                    if let Some(ref manager) = self.seed_agent_manager {
                                        match manager.register_agent(record) {
                                            Ok(()) => info!(
                                                %agent_did,
                                                charter_id = ?charter_id,
                                                "Applied gossiped SeedAgent AgentRegistered"
                                            ),
                                            Err(e) => debug!(
                                                %agent_did,
                                                error = %e,
                                                "AgentRegistered apply skipped (likely already known)"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            %agent_did,
                                            "Dropping gossiped AgentRegistered (seed-agent manager not wired)"
                                        );
                                    }
                                }
                                Ok(tenzro_token::SeedAgentGossipMessage::AgentStatusChanged {
                                    agent_did,
                                    status,
                                }) => {
                                    if let Some(ref manager) = self.seed_agent_manager {
                                        match manager.set_agent_status(&agent_did, status) {
                                            Ok(()) => info!(
                                                %agent_did,
                                                ?status,
                                                "Applied gossiped SeedAgent AgentStatusChanged"
                                            ),
                                            Err(e) => warn!(
                                                %agent_did,
                                                error = %e,
                                                "Failed to apply gossiped AgentStatusChanged"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            %agent_did,
                                            "Dropping gossiped AgentStatusChanged (seed-agent manager not wired)"
                                        );
                                    }
                                }
                                Ok(
                                    tenzro_token::SeedAgentGossipMessage::MonthlyRefillCompleted {
                                        agent_did,
                                        granted_wei,
                                        month,
                                        earmark_snapshot,
                                    },
                                ) => {
                                    // INFORMATIONAL ONLY — do not replay
                                    // `refill_agent_monthly` (that would
                                    // double-spend). Refresh the local
                                    // earmark snapshot so passive observers
                                    // can answer `tenzro_getTreasuryEarmark`
                                    // without polling the origin node.
                                    if let Some(ref manager) = self.seed_agent_manager {
                                        let allocation_remaining =
                                            earmark_snapshot.allocation_remaining_wei;
                                        let month_drawn = earmark_snapshot.month_drawn_wei;
                                        match manager.apply_earmark(earmark_snapshot) {
                                            Ok(()) => info!(
                                                %agent_did,
                                                granted_wei,
                                                month,
                                                allocation_remaining,
                                                month_drawn,
                                                "Refreshed earmark snapshot from gossiped MonthlyRefillCompleted"
                                            ),
                                            Err(e) => warn!(
                                                %agent_did,
                                                error = %e,
                                                "Failed to refresh earmark snapshot from MonthlyRefillCompleted"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            %agent_did,
                                            granted_wei,
                                            month,
                                            "Dropping gossiped MonthlyRefillCompleted (seed-agent manager not wired)"
                                        );
                                    }
                                }
                                Err(e) => warn!(
                                    %topic,
                                    error = %e,
                                    "Failed to decode SeedAgentGossip payload"
                                ),
                            }
                        }
                        NodeEvent::DatabaseGossipReceived { topic, bytes } => {
                            match tenzro_database::decode_for_topic(&topic, &bytes) {
                                Ok(msg) => {
                                    let desc = msg.descriptor().clone();
                                    let database_id = desc.database_id.clone();
                                    let kind = match msg {
                                        tenzro_database::DatabaseGossipMessage::Registered(_) => {
                                            "Registered"
                                        }
                                        tenzro_database::DatabaseGossipMessage::Rescaled(_) => {
                                            "Rescaled"
                                        }
                                    };
                                    if let Some(ref registry) = self.database_registry {
                                        match registry.upsert_descriptor(desc) {
                                            Ok(()) => info!(
                                                %database_id,
                                                kind,
                                                "Applied gossiped database descriptor"
                                            ),
                                            Err(e) => warn!(
                                                %database_id,
                                                kind,
                                                error = %e,
                                                "Failed to apply gossiped database descriptor"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            %database_id,
                                            kind,
                                            "Dropping gossiped database descriptor (registry not wired)"
                                        );
                                    }
                                }
                                Err(e) => warn!(
                                    %topic,
                                    error = %e,
                                    "Failed to decode DatabaseGossip payload"
                                ),
                            }
                        }
                        NodeEvent::IdentityGossipReceived { topic, bytes } => {
                            match tenzro_identity::decode_identity_for_topic(&topic, &bytes) {
                                Ok(tenzro_identity::IdentityGossipMessage::RevocationBroadcast(
                                    signed,
                                )) => {
                                    let did = signed.entry.did.clone();
                                    if let Some(ref registry) = self.identity_registry {
                                        match registry.apply_remote_revocation(signed) {
                                            Ok(()) => info!(
                                                %did,
                                                "Applied gossiped identity revocation"
                                            ),
                                            Err(e) => warn!(
                                                %did,
                                                error = %e,
                                                "Rejected gossiped identity revocation"
                                            ),
                                        }
                                    } else {
                                        debug!(
                                            %did,
                                            "Dropping gossiped identity revocation (identity registry not wired)"
                                        );
                                    }
                                }
                                Err(e) => warn!(
                                    %topic,
                                    error = %e,
                                    "Failed to decode IdentityGossip payload"
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

        // Off-chain spend-ceiling enforcement on the gossip-relay path.
        // Closes the same gap as the RPC-side `enforce_typed_tx_spend_ceilings`:
        // a delegated machine identity that has not installed an ERC-7579
        // validator module would otherwise have NO spend ceiling at all
        // when its transactions arrive via gossip. Mirrors the
        // DelegationScope + SpendingPolicy check enforced on the RPC
        // raw-tx admission path.
        if let Err(e) = self.enforce_relay_spend_ceilings(&tx.transaction) {
            warn!(
                hash = %tx_hash,
                error = %e,
                "Rejecting relayed transaction at spend-ceiling gate"
            );
            return Err(e);
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
        //
        // This handler is invoked from two callers:
        //   (a) the gossipsub `tenzro/transactions` subscriber in `node.rs`
        //       when a peer publishes a tx onto the mesh, and
        //   (b) the legacy fallback path on light/boot nodes that have no
        //       consensus engine wired (the RPC layer dispatches
        //       `NewTransaction` only when `node.consensus()` is `None`).
        //
        // In both cases the tx must NOT be re-broadcast here. libp2p's
        // gossipsub mesh propagates received messages to other peers
        // automatically — calling `network.broadcast()` again on receipt
        // would re-publish under a fresh `NetworkMessage` envelope (which
        // carries a per-call `Uuid`), defeating gossipsub's content-id
        // dedup and producing an exponential amplification loop. A
        // permanently-unadmittable tx (e.g. one that fails the Spec 2 fee
        // floor) accumulates mass on every relay and pins all validators
        // on tx replay, starving block production.
        //
        // RPC paths that *originate* a tx use the
        // `LocallyAdmittedTransaction` pattern: admit synchronously via
        // `consensus.submit_transaction()`, then dispatch the event so
        // the event loop publishes once into the mesh.
        if let Some(consensus) = &self.consensus {
            match consensus.submit_transaction(tx.clone()) {
                Ok(()) => {
                    info!(
                        hash = %tx_hash,
                        "Transaction submitted to consensus mempool"
                    );
                }
                Err(e) => {
                    // Drop, don't store. A tx the local mempool refuses
                    // (fee floor, rate limit, nonce, capacity) cannot be
                    // rescued by retrying locally and must not be relayed
                    // further — gossipsub already delivered it once;
                    // re-publishing under a new envelope is what created
                    // the storm. The originator is responsible for
                    // resubmitting with corrected parameters.
                    debug!(
                        hash = %tx_hash,
                        error = %e,
                        "Dropping non-admittable transaction received from network"
                    );
                }
            }
        } else {
            // No consensus engine wired (light/boot node). Hold locally so
            // the tx isn't lost; once consensus comes up, the next sweep
            // can flush it. No re-broadcast for the same storm-prevention
            // reason as above.
            self.pending_txs.push(tx);
            debug!(hash = %tx_hash, "Transaction queued locally (no consensus engine)");
        }

        Ok(())
    }

    /// Handles a transaction that was already admitted to the consensus
    /// mempool synchronously by the RPC layer.
    ///
    /// The Spec 2 admission controller is consume-on-admit (each accepted tx
    /// drains one token from the controller's bucket). RPC paths that report
    /// `RateLimited` synchronously (via JSON-RPC error -32011) call
    /// `consensus.submit_transaction` *first*, then dispatch this event for
    /// gossip propagation. We must NOT re-submit through the consensus
    /// mempool here — that would double-charge the bucket and reject the
    /// second attempt as a "transaction already in mempool" anyway.
    ///
    /// Path skipped vs. `handle_new_transaction`:
    ///   1. signature verify  — already done at RPC
    ///   2. consensus admission — already done at RPC
    ///
    /// Path executed:
    ///   3. broadcast on `tenzro/transactions` so peers can pick it up
    async fn handle_locally_admitted_transaction(&mut self, mut tx: SignedTransaction) -> Result<()> {
        let tx_hash = tx.hash();

        if let Some(ref network) = self.network {
            // Same typed-variant rationale as `handle_new_transaction` above:
            // peers route on `MessagePayload::Transaction(_)`, so wrapping in
            // `Custom` would silently drop the message on every receiver.
            let topic = "tenzro/transactions".to_string();
            let msg = tenzro_network::NetworkMessage::new(
                tenzro_network::MessagePayload::Transaction(tx.clone()),
            );
            if let Err(e) = network.broadcast(&topic, msg).await {
                warn!(
                    hash = %tx_hash,
                    error = %e,
                    "Failed to broadcast locally-admitted transaction to gossipsub"
                );
            } else {
                debug!(
                    hash = %tx_hash,
                    "Locally-admitted transaction forwarded to peers via gossipsub"
                );
            }
        } else {
            debug!(
                hash = %tx_hash,
                "Locally-admitted transaction has no gossipsub network — skipping broadcast"
            );
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
    ///
    /// Process a finalized block — execute its transactions, commit state,
    /// persist the block + tx index + receipts, and (optionally) drive the
    /// epoch transition + gossip rebroadcast hooks.
    ///
    /// `from_sync` toggles two behaviors that are appropriate for organic
    /// finality (`false`) but **MUST be skipped** during block-sync catch-up
    /// (`true`):
    ///
    ///   1. **Gossip rebroadcast.** Sync-imported blocks come from a unicast
    ///      RPC; rebroadcasting them would amplify into the gossipsub mesh
    ///      with no benefit (the proposer already broadcast at finalization
    ///      time on the live network) and would interleave historical
    ///      blocks with live ones, defeating gossipsub's recency dedup.
    ///   2. **Consensus epoch hook.** During sync we are by definition
    ///      *behind* the network's current epoch. The epoch transition plan
    ///      for block N is computed at block N-1; replaying that hook on a
    ///      historical block would mutate the live `EpochManager` state and
    ///      potentially queue obsolete pending validators. The epoch state
    ///      is repaired authoritatively when the sync engine calls
    ///      `HotStuff2Engine::resume_from_synced_height`.
    ///
    /// Both code paths still run: state execution, state-root commit, block
    /// persistence, transaction-index persistence, kill-switch / bond /
    /// validator log scans, and `current_height` advancement. State
    /// divergence between sync and live nodes would be a consensus bug.
    async fn handle_block_finalized(&mut self, block: Block) -> Result<()> {
        self.handle_block_finalized_inner(block, false).await
    }

    /// Block-sync entry point. Same as [`Self::handle_block_finalized`] but
    /// suppresses gossip rebroadcast and epoch-transition setup — see
    /// `handle_block_finalized` rustdoc for why.
    ///
    /// Before delegating to `_inner`, this method **verifies the block's
    /// embedded commit-QC against the current validator set**:
    ///
    /// 1. Extracts the QC from `block.header.consensus_proof.proof_data`
    ///    via [`tenzro_consensus::QuorumCertificate::extract_from_block`].
    ///    A block whose proof_data is empty or fails to deserialize is rejected.
    /// 2. Calls [`tenzro_consensus::QuorumCertificate::verify`] which
    ///    re-verifies every contained vote (format version, validator
    ///    membership, key binding, hybrid signature, no duplicate voters)
    ///    and checks the aggregated voting power meets the quorum threshold.
    /// 3. Confirms the QC's `block_hash`/`height` match the block being imported.
    ///
    /// A block that fails any of these checks is dropped without touching state,
    /// and the caller (BlockSyncEngine) is expected to score the serving peer
    /// down. This is the security boundary that lets us trust historical blocks
    /// from non-validator peers without re-running consensus.
    ///
    /// Cross-epoch verification: the QC is verified against the validator
    /// set that was active at the *block's* height, not the current epoch.
    /// This is what lets a node catching up across an epoch boundary import
    /// historical blocks without false-positive `InvalidValidatorSet`
    /// rejections — the May 2026 testnet stall root cause. If the validator
    /// set for the block's height is not in the working set or persistent
    /// store (i.e., predates available history), the block is rejected and
    /// the caller falls back to snapshot sync.
    pub(crate) async fn handle_block_imported_from_sync(&mut self, block: Block) -> Result<()> {
        // Need a consensus engine to know the validator set we're verifying against.
        let consensus = self.consensus.as_ref().ok_or_else(|| {
            crate::error::NodeError::Other(
                "block-sync import requires a consensus engine".to_string(),
            )
        })?;

        // (1) Extract QC.
        let qc = tenzro_consensus::QuorumCertificate::extract_from_block(&block)
            .ok_or_else(|| {
                crate::error::NodeError::Other(format!(
                    "block-sync rejected block at height {}: no embedded commit-QC \
                     (consensus_proof.proof_data empty or undeserializable)",
                    block.height()
                ))
            })?;

        // (3) QC must reference the block being imported.
        let block_hash = block.hash();
        if qc.block_hash != block_hash || qc.height != block.height() {
            return Err(crate::error::NodeError::Other(format!(
                "block-sync rejected block at height {}: embedded QC references \
                 block_hash={}/height={}, expected block_hash={}/height={}",
                block.height(),
                qc.block_hash,
                qc.height,
                block_hash,
                block.height(),
            )));
        }
        if qc.vote_type != tenzro_consensus::VoteType::Commit {
            return Err(crate::error::NodeError::Other(format!(
                "block-sync rejected block at height {}: embedded QC is not a Commit-QC \
                 (got {:?})",
                block.height(),
                qc.vote_type,
            )));
        }

        // Forward epoch catch-up: a sync-imported block at an epoch boundary
        // must cross the boundary exactly like the live path did. Live nodes
        // transition at `end_height` (transition fires at finalized+1, which
        // equals `end_height` exactly), so the boundary block itself is signed
        // by the *new* epoch's validator set — without transitioning first,
        // `validator_set_for_height(end_height)` finds no covering epoch and
        // the import stalls (the June 2026 testnet halt on v1). The loop walks
        // across *every* due boundary (a node rejoining after >1 epoch offline
        // needs more than one transition), staging the registry plan before
        // each. Gated by `should_transition`, so this is strictly forward
        // catch-up, never historical replay.
        while consensus
            .epoch_manager()
            .should_transition(block.height())
        {
            if let Some(registry) = self.validator_registry.as_ref() {
                Self::stage_registry_epoch_plan(&consensus.epoch_manager(), registry);
            }
            let transitioned = consensus
                .transition_epoch_if_due(block.height())
                .map_err(|e| {
                    crate::error::NodeError::Other(format!(
                        "block-sync epoch transition at height {} failed: {}",
                        block.height(),
                        e
                    ))
                })?;
            if !transitioned {
                // Lost a benign race with the engine's own finalize path —
                // the boundary is already crossed.
                break;
            }
        }

        // (2) Verify QC: every vote's signature, validator membership, key binding,
        // no duplicates, voting power meets quorum threshold.
        //
        // CRITICAL: use the validator set active at the *block's* height, not
        // the current epoch's set. A node catching up across one or more
        // epoch transitions would otherwise reject every historical block
        // whose signers no longer (or don't yet) match the current epoch.
        // `validator_set_for_height` returns `None` only if the epoch
        // covering `block.height()` has been pruned beyond the working set
        // *and* the persistent store doesn't have it — in that case we
        // refuse the block and the caller falls back to snapshot sync.
        let validator_set = consensus
            .validator_set_for_height(block.height())
            .ok_or_else(|| {
                crate::error::NodeError::Other(format!(
                    "block-sync rejected block at height {}: no validator set \
                     available for that height (history pruned beyond working set); \
                     snapshot sync required",
                    block.height()
                ))
            })?;
        qc.verify_bls_aggregate(&validator_set).map_err(|e| {
            crate::error::NodeError::Other(format!(
                "block-sync rejected block at height {} (hash={}): QC verification \
                 failed against epoch validator set ({} members): {}",
                block.height(),
                block_hash,
                validator_set.len(),
                e
            ))
        })?;

        // (4) Weak-subjectivity checkpoint. A valid commit-QC proves this
        // block was signed by a supermajority of the validator set active at
        // its height — but that is exactly what a long-range fork forges: an
        // attacker holding an old supermajority's keys can build a
        // self-consistent alternate history from any past epoch, and every
        // block on it passes step (2). The anchor is the a-priori-trusted
        // finalized `(height, state_root)`. When import reaches the anchor
        // height, the block's committed state root must match the anchor
        // byte-for-byte; a fork diverging before the anchor produces a
        // different root here and is rejected, taking every block built on it
        // down with it. Blocks below the anchor height are still QC-verified
        // (step 2) but not root-pinned — the anchor is the single point the
        // node trusts without derivation, and the QC chain vouches for the
        // prefix leading up to it.
        Self::check_weak_subjectivity_anchor(
            self.weak_subjectivity_anchor,
            block.height().as_u64(),
            block.header.state_root,
        )?;

        debug!(
            height = %block.height(),
            hash = %block_hash,
            qc_view = qc.view,
            qc_signers = qc.signer_count(),
            "Block-sync: commit-QC verified, accepting block"
        );

        self.handle_block_finalized_inner(block, true).await
    }

    /// Enforces the weak-subjectivity checkpoint on a block-sync import.
    ///
    /// A no-op unless `anchor` is set and `block_height` equals the anchor
    /// height. At the anchor height, `block_state_root` must equal the
    /// trusted root or the import is rejected. Pure over its inputs so the
    /// rejection/acceptance logic is unit-testable without a consensus
    /// engine.
    fn check_weak_subjectivity_anchor(
        anchor: Option<(u64, Hash)>,
        block_height: u64,
        block_state_root: Hash,
    ) -> Result<()> {
        let Some((anchor_height, anchor_root)) = anchor else {
            return Ok(());
        };
        if block_height != anchor_height {
            return Ok(());
        }
        if block_state_root != anchor_root {
            return Err(crate::error::NodeError::Other(format!(
                "block-sync rejected block at weak-subjectivity anchor height \
                 {anchor_height}: committed state_root {block_state_root} does \
                 not match trusted checkpoint {anchor_root} — refusing a \
                 long-range fork",
            )));
        }
        debug!(
            height = %anchor_height,
            root = %anchor_root,
            "Block-sync: block matches weak-subjectivity checkpoint"
        );
        Ok(())
    }

    /// Stages the validator-registry transition plan for the next epoch onto
    /// the `EpochManager` pending queues (`add_pending_validator` /
    /// `remove_pending_validator`). The HotStuff-2 engine drains those queues
    /// inside `transition_epoch`. Idempotent within an epoch window. Called
    /// from the live finalize hook (one block before the boundary) and the
    /// block-sync import path (at the boundary block itself).
    fn stage_registry_epoch_plan(
        em: &Arc<tenzro_consensus::EpochManager>,
        registry: &Arc<tenzro_token::ValidatorRegistry>,
    ) {
        let next_epoch = em.current_epoch().number + 1;
        let plan = registry.compute_epoch_transition(next_epoch);
        debug!(
            next_epoch = next_epoch,
            activations = plan.effective_activations.len(),
            exits = plan.effective_exits.len(),
            "Computed registry epoch transition plan"
        );

        // Effective activations → ValidatorInfo upsert into pending.
        for addr in &plan.effective_activations {
            let entry = match registry.get(addr) {
                Some(e) => e,
                None => {
                    warn!(
                        address = %addr,
                        "Registry returned activation for unknown entry; skipping"
                    );
                    continue;
                }
            };
            if entry.consensus_pubkey.len() != 32 {
                warn!(
                    address = %addr,
                    len = entry.consensus_pubkey.len(),
                    "Skipping activation: consensus pubkey not 32 bytes"
                );
                continue;
            }
            let pk = tenzro_crypto::PublicKey::new(
                tenzro_crypto::KeyType::Ed25519,
                entry.consensus_pubkey.clone(),
            );
            let info = tenzro_consensus::validator::ValidatorInfo::new(
                entry.address,
                pk,
                entry.pq_pubkey.clone(),
                entry.bls_pubkey.clone(),
                entry.self_stake,
            );
            em.add_pending_validator(info);
        }

        // Effective exits → drop from active set in next epoch.
        for addr in &plan.effective_exits {
            em.remove_pending_validator(addr);
        }
    }

    /// Moves this block's gas fees onto the ledger.
    ///
    /// `FeeMarket` accumulates gross base-fee revenue into two monotonic
    /// counters — `total_to_treasury` and `total_burned` — split by the
    /// adaptive burn dial. This reads both, takes the delta against what has
    /// already been settled, credits the treasury balance, decrements
    /// `total_supply` by the burned share, and records the movement in the
    /// fee processor's statistics.
    ///
    /// The first observation after boot anchors rather than settles: the
    /// counters are cumulative over the chain's whole history, and the
    /// balances they correspond to are already durable in RocksDB, so
    /// treating the full cumulative value as a delta would credit the
    /// treasury a second time on every restart.
    async fn settle_block_fees(&mut self) {
        let Some(token) = self.token.clone() else {
            return;
        };
        let Some(treasury) = token.treasury_address_ref() else {
            return;
        };
        let Some(fee_market) = self.vm_runtime.gas_oracle().fee_market_snapshot().await else {
            return;
        };

        let cumulative_treasury = fee_market.total_to_treasury();
        let cumulative_burn = fee_market.total_burned();

        if !self.fee_anchor_set {
            self.fee_anchor_set = true;
            self.last_settled_fee_treasury = cumulative_treasury;
            self.last_settled_fee_burn = cumulative_burn;
            return;
        }

        let to_treasury = cumulative_treasury.saturating_sub(self.last_settled_fee_treasury);
        let burned = cumulative_burn.saturating_sub(self.last_settled_fee_burn);
        if to_treasury == 0 && burned == 0 {
            return;
        }

        if let Err(e) = token.settle_collected_fees(&treasury, to_treasury, burned) {
            // Leave the anchors untouched so the next block retries the same
            // delta rather than silently dropping it.
            warn!(
                error = %e,
                to_treasury = %to_treasury,
                burned = %burned,
                "Gas fee settlement failed"
            );
            return;
        }

        self.last_settled_fee_treasury = cumulative_treasury;
        self.last_settled_fee_burn = cumulative_burn;

        // Recorded with the split the ledger actually applied. Gas carries no
        // staker share: the fee market divides base-fee revenue between the
        // treasury and the burn only.
        if let Some(processor) = self.fee_processor.as_ref()
            && let Err(e) = processor.process_fee(
                tenzro_types::asset::AssetId::tnzo(),
                tenzro_token::FeeSource::Transaction,
                to_treasury,
                burned,
                0,
            )
        {
            // Accounting only — the ledger movement above already succeeded.
            warn!(error = %e, "Fee processor accounting failed");
        }

        debug!(
            to_treasury = %to_treasury,
            burned = %burned,
            "Settled block gas fees"
        );
    }

    async fn handle_block_finalized_inner(
        &mut self,
        block: Block,
        from_sync: bool,
    ) -> Result<()> {
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
        if let Some(ref network) = self.network
            && let Ok(peers) = network.connected_peers().await {
                self.metrics.set_peer_count(peers.len() as u64);
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

        // Hot-state local fee market (Spec 6): per-account contention samples for
        // this block. Sequential VM path produces zero reexecutions, so the
        // attribution is `writes=1 per unique address per tx, reexecutions=0`.
        // Block-STM parallel path (when wired) will populate the reexecution
        // counter directly via `ParallelExecutionResult.account_contention`.
        let mut block_contention: std::collections::HashMap<
            Vec<u8>,
            tenzro_vm::AccountSample,
        > = std::collections::HashMap::new();

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

            // Stamp the finalized block's timestamp onto the VmTransaction
            // so native-VM handlers that depend on wall-clock state read
            // a deterministic value across all validators (vs each one's
            // `Utc::now()`). Without this, escrow-expiry / time-bound
            // delegation / lifecycle TTL checks could diverge between
            // validators and split finalized state.
            let vm_tx = convert_transaction(signed_tx)
                .with_block_timestamp_ms(block.header.timestamp.as_millis());

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

                    // Spec 6 hot-state attribution: every distinct address
                    // touched by a successful or reverted tx counts as one
                    // write toward this block's contention sample. Sequential
                    // execution → reexecutions=0; the surcharge fires on
                    // sustained write volume + (eventual) Block-STM reexec
                    // signal over the 64-block window.
                    {
                        let mut seen: std::collections::HashSet<Vec<u8>> =
                            std::collections::HashSet::new();
                        for sc in &result.state_changes {
                            if seen.insert(sc.address.clone()) {
                                let entry = block_contention
                                    .entry(sc.address.clone())
                                    .or_default();
                                entry.merge(tenzro_vm::AccountSample {
                                    reexecutions: 0,
                                    writes: 1,
                                });
                            }
                        }
                    }

                    if result.success {
                        successful_txs += 1;
                        debug!(
                            tx_hash = %tx_hash,
                            gas_used = result.gas_used,
                            "Transaction executed successfully"
                        );

                        // Post-execute kill-switch scan: drives `AgentRuntime`
                        // lifecycle FSM, persists the canonical
                        // `KillSwitchReceipt` (with the real
                        // `frozen_at_block`), freezes/thaws/slashes the
                        // agent's stake, and (for terminate-cascade) recurses
                        // through the spawn tree. The VM emits the log + state
                        // change blob; everything cross-crate happens here.
                        self.process_kill_switch_logs(&result, block_height).await;

                        // Post-execute AgentBond scan (Spec 9): mirrors VM-
                        // emitted `BondPosted` / `BondIncreased` /
                        // `BondWithdrawInitiated` / `BondSlashed` /
                        // `InsuranceClaimPaid` logs into the off-chain
                        // `BondManager`, which is the read model used by
                        // lane resolution and receipt envelopes. Vault
                        // balances and on-chain markers are already
                        // committed by the VM at this point.
                        self.process_bond_logs(&result, block_height).await;

                        // Post-execute ERC-8004 `Registered` scan: reflects
                        // the canonical `IdentityRegistry` proxy's
                        // `Registered(uint256,string,address)` event into
                        // the off-chain `erc8004_did_index:` keyspace in
                        // CF_IDENTITIES and patches the matching TDIP
                        // `Machine` identity's `erc8004_agent_id` field.
                        // This is the listener half of the
                        // `NativeErc8004Mirror` async-detached-spawn
                        // architecture — the EVM tx is submitted by the
                        // mirror's `tokio::spawn`, and the resulting log
                        // lands here when the block applies.
                        self.process_erc8004_registered_logs(&result, block_height).await;

                        // Post-execute escrow scan: mirrors VM-emitted
                        // `EscrowCreated` / `EscrowReleased` / `EscrowRefunded`
                        // logs into the off-chain `EscrowManager` query index
                        // (CF_SETTLEMENTS / `escrow:` + `escrow_payer:` +
                        // `escrow_payee:` keys). The VM has already moved
                        // funds and persisted the canonical `EscrowAccount`
                        // under SYSTEM_ADDRESS; this populates the by-payer
                        // and by-payee indices that `tenzro_listEscrowsByPayer`
                        // / `tenzro_listEscrowsByPayee` read.
                        self.process_escrow_logs(&result, block_height).await;

                        // Same pattern for ValidatorRegister / ValidatorExit /
                        // ValidatorMetadataUpdate logs — drive the off-chain
                        // ValidatorRegistry from VM-emitted events. The VM
                        // has already deducted gas and persisted markers.
                        self.process_validator_logs(&result, block_height).await;

                        // Workflow scan — same pattern across the 12
                        // privileged workflow selectors (0x01000040–0x0100004B).
                        // The VM has already validated payload size, JSON
                        // well-formedness, charged gas, and persisted the
                        // `wf:<op>:<id>` marker under SYSTEM_ADDRESS. Here we
                        // decode the typed JSON and dispatch into the
                        // off-chain `WorkflowManager` / `PrivacyDomainRegistry`,
                        // which write through to RocksDB and emit chained
                        // `WorkflowReceipt`s. Decode failures are warned and
                        // skipped — divergence is recoverable on restart via
                        // hydration from CF_SETTLEMENTS / CF_APPROVALS.
                        self.process_workflow_logs(&result, block_height).await;
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

        // Track the locally computed root and validate the proposer's header
        // claim against the window. The claim is the proposer's latest
        // *executed* root at proposal time (deferred execution), so it must
        // appear among our recently computed roots. Skip while the window is
        // warming up (fresh start / restart) and skip the zero root, which a
        // proposer without a state-root provider stamps by default.
        self.recent_state_roots.push_back(state_root);
        if self.recent_state_roots.len() > STATE_ROOT_WINDOW {
            self.recent_state_roots.pop_front();
        }
        let claimed_root = block.header.state_root;
        if self.recent_state_roots.len() == STATE_ROOT_WINDOW
            && claimed_root != Hash::zero()
            && !self.recent_state_roots.contains(&claimed_root)
        {
            error!(
                height = %block_height,
                block_hash = %block_hash,
                claimed_root = %claimed_root,
                local_root = %state_root,
                window = STATE_ROOT_WINDOW,
                "STATE-ROOT DIVERGENCE: finalized header claims a state root \
                 absent from the local execution window — proposer executed a \
                 divergent state or this node's state has forked"
            );
        }

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

        // Settle the gas the executor debited this block.
        //
        // The native VM subtracts `gas_price * gas_used` from each sender and
        // credits nobody, so the TNZO leaves circulation without leaving
        // `total_supply`. `FeeMarket` splits the gross revenue into a burn
        // share and a treasury share as accounting counters; this is where
        // that split becomes ledger movement.
        //
        // Placement is deliberate. This hook runs on every node that
        // finalizes a block, including gossip-received ones, so all replicas
        // converge on the same treasury balance. The epoch-boundary
        // adaptive-burn block below is gated on the consensus engine and
        // would only run on validators.
        self.settle_block_fees().await;

        // Spec 6: roll the hot-state contention window forward by exactly one
        // block. The window is per-account, length-bounded at
        // `HOT_STATE_WINDOW_BLOCKS`; eviction happens inside the market.
        // Surcharge collection on hot accounts will be charged at admission
        // time (RPC) once per-tx fee accounting is wired through; this hook
        // is the per-block sample feed.
        self.vm_runtime
            .gas_oracle()
            .record_block_contention(block_contention);

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
        // Skip gossip rebroadcast for sync-imported blocks. Rebroadcasting
        // historical blocks would amplify into the live mesh and interleave
        // with current-tip blocks, defeating gossipsub recency dedup.
        if !from_sync
            && self.consensus.is_some()
            && let Some(ref network) = self.network {
                let network_clone = network.clone();
                let msg = NetworkMessage::new(MessagePayload::Block(block.clone()));
                let height_for_log = block_height;
                let hash_for_log = block_hash;
                tokio::spawn(async move {
                    if let Err(e) = network_clone.broadcast("tenzro/blocks", msg).await {
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

        // Epoch boundary hook: every block, ask the consensus EpochManager
        // whether the next block will trigger an epoch transition. If yes,
        // compute the registry's transition plan for the *upcoming* epoch
        // and translate it into pending_validators / pending_removals on
        // the EpochManager. The HotStuff-2 engine itself drains those
        // queues during transition_epoch() and rebuilds the validator set.
        //
        // This runs strictly *before* HotStuff-2 calls transition_epoch
        // (which happens on its own block-finalized handler). We rely on
        // both paths observing the same height threshold; queueing pending
        // entries is idempotent within an epoch.
        //
        // Skip for sync-imported blocks: the import path
        // (`handle_block_imported_from_sync`) stages the plan and crosses
        // the boundary itself, at the moment it imports the boundary block —
        // a forward catch-up that mirrors this live hook one boundary at a
        // time, in order.
        if !from_sync
            && let (Some(consensus), Some(registry)) =
            (self.consensus.as_ref(), self.validator_registry.as_ref())
        {
            let em = consensus.epoch_manager();
            // Will the *next* block trigger transition? Use block_height + 1
            // so we set up the plan before HotStuff-2 finalizes its own.
            let next_height =
                tenzro_types::primitives::BlockHeight::from(block_height.0 + 1);
            if em.should_transition(next_height) {
                Self::stage_registry_epoch_plan(&em, registry);
            }
        }

        // Follower epoch catch-up: on a node whose engine is not running the
        // finalize path (gossip-imported blocks advance storage without the
        // engine voting — the June 2026 v1 stall), nothing else crosses the
        // epoch boundary. The EpochManager goes stale, `validator_set_for_height`
        // stops resolving for new blocks, and the stage-early hook above floods
        // logs every block. Walk forward across every due boundary here. On a
        // healthy validator the engine's own finalize handler has already
        // transitioned before this runs, so `should_transition(block_height)`
        // is false and this is a no-op; a benign race resolves inside
        // `transition_epoch` under the epoch write lock (loser sees `false`).
        // Live path never fails finalization on a transition error — warn and
        // retry on the next block.
        if !from_sync && let Some(consensus) = self.consensus.as_ref() {
            let em = consensus.epoch_manager();
            while em.should_transition(block_height) {
                if let Some(registry) = self.validator_registry.as_ref() {
                    Self::stage_registry_epoch_plan(&em, registry);
                }
                match consensus.transition_epoch_if_due(block_height) {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(e) => {
                        warn!(
                            height = %block_height,
                            error = %e,
                            "Follower epoch catch-up transition failed; retrying next block"
                        );
                        break;
                    }
                }
            }
        }

        // Adaptive-burn supply metrics observation (Spec 8). Runs once per
        // epoch boundary, immediately after the validator transition plan
        // is staged but before HotStuff-2 finalizes the rotation. This is
        // the canonical place to feed `BurnRateConfigManager::record_metrics`
        // so the recommendation engine has fresh data the moment governance
        // queries `tenzro_getBurnRateRecommendation`.
        //
        // Skip during sync replay (same reasoning as the validator
        // transition above): the snapshot reflects historical supply that
        // doesn't represent the live network's current state.
        if !from_sync
            && let (Some(consensus), Some(burn_rate), Some(token)) = (
                self.consensus.as_ref(),
                self.burn_rate_manager.as_ref(),
                self.token.as_ref(),
            )
        {
            let em = consensus.epoch_manager();
            let next_height =
                tenzro_types::primitives::BlockHeight::from(block_height.0 + 1);
            if em.should_transition(next_height) {
                use tenzro_token::adaptive_burn::{
                    BurnBreakdown, EmissionBreakdown, SupplyMetricsSnapshot,
                };

                // Per-epoch base-fee burn delta from the live EIP-1559 fee
                // market. The gas oracle owns the `FeeMarket` (wired in
                // `init_vm_runtime`); `total_burned()` is monotonic and
                // we anchor against the previous observation to derive the
                // per-epoch increment. Absent fee market → zero delta.
                let cumulative_base_fee_burn = self
                    .vm_runtime
                    .gas_oracle()
                    .fee_market_snapshot()
                    .await
                    .map(|fm| fm.total_burned())
                    .unwrap_or(0);

                // Per-epoch slash burn delta from the staking manager. Net
                // of governance-authorized restorations. Skipped when the
                // staking manager is not wired (light client).
                let cumulative_slash_burn = self
                    .staking
                    .as_ref()
                    .map(|s| s.total_slashed())
                    .unwrap_or(0);

                let circulating = token.circulating_supply();
                let prior = self.last_observed_epoch_supply;
                // First observation → zero delta (no prior reference point);
                // initialize the running anchor.
                let epoch_delta: i128 = if prior == 0 {
                    0
                } else {
                    (circulating as i128).saturating_sub(prior as i128)
                };

                // Annualize the current epoch delta to bps of circulating
                // supply, using the configured rolling-window length as the
                // averaging horizon. We use the targets snapshot rather than
                // accumulating a persisted ring buffer for now — the transfer
                // function's `compute_recommendation` only consumes the
                // already-annualized bps, so a per-epoch annualization is
                // numerically equivalent on a steady-state network. A true
                // rolling-window aggregator can replace this once the
                // historical-snapshot ring buffer exists.
                let rolling_bps: i32 = if circulating == 0 {
                    0
                } else {
                    let window_epochs =
                        burn_rate.targets().rolling_window_epochs.max(1) as i128;
                    let annualized = epoch_delta.saturating_mul(window_epochs);
                    let bps = annualized
                        .saturating_mul(10_000)
                        .checked_div(circulating as i128)
                        .unwrap_or(0);
                    bps.clamp(i32::MIN as i128, i32::MAX as i128) as i32
                };

                // Derive per-epoch deltas from monotonic cumulative
                // counters. First observation (anchor == 0 && cumulative
                // > 0) is treated as zero delta — we don't have a prior
                // reference point, and double-counting historical burn at
                // the first epoch boundary post-boot would bias the
                // recommendation engine. The very next epoch sees the
                // running delta from this anchor forward.
                let base_fee_burn_delta = if self.last_observed_base_fee_burn == 0 {
                    0
                } else {
                    cumulative_base_fee_burn
                        .saturating_sub(self.last_observed_base_fee_burn)
                };
                let slash_burn_delta = if self.last_observed_slash_burn == 0 {
                    0
                } else {
                    cumulative_slash_burn
                        .saturating_sub(self.last_observed_slash_burn)
                };

                // Remaining `BurnBreakdown` lanes (local_fee, paymaster)
                // and the full `EmissionBreakdown` (staking_rewards,
                // treasury_emissions) are left at zero until their
                // respective cumulative counters land. The transfer
                // function `compute_recommendation` only consumes the
                // already-annualized `rolling_window_supply_delta_bps`,
                // so these are observational fields for the
                // `tenzro_getSupplyMetrics` RPC — not inputs to the dial.
                let burn_breakdown = BurnBreakdown {
                    base_fee: base_fee_burn_delta,
                    local_fee: 0,
                    paymaster: 0,
                    slash: slash_burn_delta,
                };

                let snapshot = SupplyMetricsSnapshot {
                    block_height,
                    captured_at: tenzro_types::primitives::Timestamp::now(),
                    circulating_supply: circulating,
                    epoch_supply_delta: epoch_delta,
                    rolling_window_supply_delta_bps: rolling_bps,
                    burn_breakdown,
                    emission_breakdown: EmissionBreakdown::default(),
                };

                if let Err(e) = burn_rate.record_metrics(snapshot) {
                    warn!(
                        error = %e,
                        height = block_height.0,
                        "Adaptive-burn record_metrics failed"
                    );
                } else {
                    debug!(
                        height = block_height.0,
                        circulating = circulating,
                        epoch_delta = epoch_delta,
                        rolling_bps = rolling_bps,
                        base_fee_burn_delta = base_fee_burn_delta,
                        slash_burn_delta = slash_burn_delta,
                        "Recorded adaptive-burn epoch snapshot"
                    );
                    self.last_observed_epoch_supply = circulating;
                    self.last_observed_base_fee_burn = cumulative_base_fee_burn;
                    self.last_observed_slash_burn = cumulative_slash_burn;
                }
            }
        }

        // Work-gated reward metering. Two layers:
        //
        // (1) Every finalized block: the proposer earns a BlockProposal
        //     work unit and each commit-QC signer earns a ConsensusVote
        //     unit for the epoch covering this height. Runs after the
        //     follower epoch catch-up above so the current epoch is the
        //     one that actually covers `block_height`.
        // (2) At the epoch boundary (same `should_transition(next_height)`
        //     gate as the adaptive-burn observer, i.e. on the last block
        //     of the closing epoch): ingest the usage tracker's cumulative
        //     per-provider revenue meters as InferenceServed work, close
        //     the epoch (minting rights -> pro-rata coupons, expired-coupon
        //     sweep), and run the sponsorship slot expiry sweep.
        //
        // Skip during sync replay: work is metered by the network as it
        // happens; a node replaying history must not issue coupons for
        // epochs the live network already closed.
        if !from_sync
            && let (Some(consensus), Some(rewards)) =
                (self.consensus.as_ref(), self.reward_engine.as_ref())
        {
            let em = consensus.epoch_manager();
            let epoch = em.current_epoch().number;

            let voters: Vec<Address> = block
                .header
                .consensus_proof
                .signatures
                .iter()
                .map(|s| s.validator)
                .collect();
            if let Err(e) =
                rewards.record_block_participation(epoch, &block.header.proposer, &voters)
            {
                warn!(
                    height = block_height.0,
                    epoch,
                    error = %e,
                    "Reward engine rejected block participation record"
                );
            }

            let next_height =
                tenzro_types::primitives::BlockHeight::from(block_height.0 + 1);
            if em.should_transition(next_height) {
                // Settled provider usage only — the tracker records real
                // routed inference, never self-reported capacity.
                if let Some(tracker) = self.usage_tracker.as_ref() {
                    for stats in tracker.list_provider_stats() {
                        if let Err(e) = rewards.ingest_cumulative(
                            epoch,
                            stats.provider_id,
                            tenzro_token::WorkClass::InferenceServed,
                            stats.total_revenue as u128,
                        ) {
                            warn!(
                                provider = %hex::encode(stats.provider_id.as_bytes()),
                                epoch,
                                error = %e,
                                "Reward engine rejected provider usage ingestion"
                            );
                        }
                    }
                }

                match rewards.close_epoch(epoch) {
                    Ok(summary) => info!(
                        epoch,
                        rights_issued = %summary.rights_issued,
                        matched = %summary.matched,
                        expired_unmatched = %summary.expired_unmatched,
                        coupon_count = summary.coupon_count,
                        "Closed reward epoch"
                    ),
                    Err(e) => warn!(
                        epoch,
                        error = %e,
                        "Reward epoch close failed"
                    ),
                }

                if let Some(sponsorship) = self.sponsorship_manager.as_ref() {
                    match sponsorship
                        .expire_due(tenzro_types::primitives::Timestamp::now())
                    {
                        Ok(expired) if !expired.is_empty() => info!(
                            expired = expired.len(),
                            "Sponsorship expiry sweep returned delegations to pool"
                        ),
                        Ok(_) => {}
                        Err(e) => warn!(
                            error = %e,
                            "Sponsorship expiry sweep failed"
                        ),
                    }
                }
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

    /// Scans a successful VM execution result for kill-switch logs and
    /// dispatches the cross-crate side-effects:
    ///
    /// 1. Decode the receipt blob the VM stashed in `state_changes` under
    ///    `SYSTEM_ADDRESS / killswitch:<receipt_id>`.
    /// 2. Rewrite `frozen_at_block` from the VM's nonce-stand-in to the
    ///    real finalized `block_height`.
    /// 3. Drive the matching `AgentRuntime` lifecycle FSM (Pause /
    ///    Quarantine / Terminate).
    /// 4. Resolve the agent's machine DID to a staker `Address` and
    ///    freeze (Pause/Quarantine) or slash (Terminate) the stake.
    /// 5. For Terminate with `cascade=true`, BFS through the
    ///    `children:<parent_id>` spawn tree and apply the same termination
    ///    + slash recursively (depth-bounded to 32).
    /// 6. Persist the canonical `KillSwitchReceipt` to `KillSwitchStore`.
    ///
    /// All failures are logged at `warn`/`error` and swallowed: a partial
    /// kill-switch transition is preferable to halting block finalization.
    /// The on-chain log + receipt store is the durable audit trail; the
    /// runtime side-effects are best-effort.
    async fn process_kill_switch_logs(
        &self,
        result: &tenzro_vm::ExecutionResult,
        block_height: BlockHeight,
    ) {
        // Cheap early exit: most blocks contain zero kill-switch logs.
        let any_killswitch = result.logs.iter().any(|l| {
            l.topics.first().map(|t| {
                t.as_slice() == b"KillSwitchPause"
                    || t.as_slice() == b"KillSwitchQuarantine"
                    || t.as_slice() == b"KillSwitchTerminate"
            }).unwrap_or(false)
        });
        if !any_killswitch {
            return;
        }

        for log in &result.logs {
            let topic = match log.topics.first() {
                Some(t) => t.as_slice(),
                None => continue,
            };
            let action = match topic {
                b"KillSwitchPause" => KillSwitchAction::Pause,
                b"KillSwitchQuarantine" => KillSwitchAction::Quarantine,
                b"KillSwitchTerminate" => KillSwitchAction::Terminate,
                _ => continue,
            };

            // Decode `agent_did_len(4) || agent_did || controller_did_len(4)
            // || controller_did || receipt_id(32)`.
            let (agent_did, _controller_did, receipt_id_hex) =
                match decode_killswitch_log_data(&log.data) {
                    Some(v) => v,
                    None => {
                        warn!(
                            action = ?action,
                            data_len = log.data.len(),
                            "Malformed kill-switch log payload, skipping"
                        );
                        continue;
                    }
                };

            // Recover the receipt blob the VM stashed under
            // SYSTEM_ADDRESS storage with key `killswitch:<id>`.
            let storage_key = format!("killswitch:{}", receipt_id_hex);
            let receipt_blob = result.state_changes.iter().find(|sc| {
                sc.key.as_slice() == storage_key.as_bytes() && sc.new_value.is_some()
            });
            let mut receipt: KillSwitchReceipt = match receipt_blob
                .and_then(|sc| sc.new_value.as_ref())
                .and_then(|v| serde_json::from_slice(v).ok())
            {
                Some(r) => r,
                None => {
                    warn!(
                        receipt_id = %receipt_id_hex,
                        "Kill-switch log has no matching state-change receipt blob, skipping"
                    );
                    continue;
                }
            };

            // Rewrite the frozen_at_block placeholder (VM used tx.nonce as
            // a stand-in) with the real finalized block height.
            receipt.frozen_at_block = block_height;

            self.apply_kill_switch_action(&action, &agent_did, &receipt).await;

            // Persist the canonical receipt last so the audit trail
            // matches what actually happened (lifecycle + stake side
            // effects already attempted above; receipt store is the
            // durable record either way).
            if let Some(ref store) = self.kill_switch_store {
                if let Err(e) = store.record(receipt.clone()) {
                    error!(
                        receipt_id = %receipt.receipt_id,
                        error = %e,
                        "Failed to persist KillSwitchReceipt"
                    );
                }
            } else {
                debug!(
                    receipt_id = %receipt.receipt_id,
                    "KillSwitchStore not wired; receipt observed but not persisted"
                );
            }

            // Cascade traversal for Terminate with cascade=true: BFS
            // through children:<parent_id> in CF_AGENTS and apply the
            // same termination (+ proportional slash) to each
            // descendant. Depth-bounded to 32 to defend against
            // pathological spawn graphs.
            if matches!(action, KillSwitchAction::Terminate)
                && receipt.cascade.unwrap_or(false)
            {
                self.cascade_terminate(&agent_did, &receipt, block_height).await;
            }
        }
    }

    /// Post-execute AgentBond scan (Spec 9). Iterates `result.logs` and
    /// reflects each VM-emitted bond event into the off-chain
    /// `BondManager`. The VM has already mutated chain state (vault
    /// balances + `bond:<agent_did>` storage marker); this scan is the
    /// authoritative read model used by lane resolution and Spec-5
    /// receipt envelopes (`actor_bond` / `controller_bond_aggregate`).
    ///
    /// Cheap early-exit if no relevant log is present in this tx.
    ///
    /// Log layouts (mirror the VM emit sites in
    /// `tenzro_vm::native::execute_post/increase/withdraw_agent_bond`,
    /// `execute_terminate_agent` slash branch, `execute_pay_insurance_claim`):
    ///
    /// - `BondPosted` / `BondIncreased` / `BondWithdrawInitiated`:
    ///   `agent_did_len_le(4) || agent_did || controller_did_len_le(4)
    ///    || controller_did || amount_le(16) || op_tag(1)`
    ///
    /// - `BondSlashed`:
    ///   `agent_did_len_le(4) || agent_did || controller_did_len_le(4)
    ///    || controller_did || slashed_amount_le(16) || bps_le(2)
    ///    || terminal(1)`
    ///
    /// - `InsuranceClaimPaid`:
    ///   `claim_id_len_le(4) || claim_id_bytes || claimant(32)
    ///    || amount_le(16)`
    async fn process_bond_logs(
        &self,
        result: &tenzro_vm::ExecutionResult,
        block_height: BlockHeight,
    ) {
        let any_bond = result.logs.iter().any(|l| {
            l.topics.first().map(|t| {
                let s = t.as_slice();
                s == b"BondPosted"
                    || s == b"BondIncreased"
                    || s == b"BondWithdrawInitiated"
                    || s == b"BondSlashed"
                    || s == b"InsuranceClaimPaid"
            }).unwrap_or(false)
        });
        if !any_bond {
            return;
        }

        let bond_manager = match self.bond_manager.as_ref() {
            Some(m) => m.clone(),
            None => {
                debug!(
                    block_height = block_height.0,
                    "Bond log observed but BondManager not wired; skipping reflection"
                );
                return;
            }
        };
        let block_height_u64 = block_height.0;

        for log in &result.logs {
            let topic = match log.topics.first() {
                Some(t) => t.as_slice(),
                None => continue,
            };

            match topic {
                b"BondPosted" | b"BondIncreased" | b"BondWithdrawInitiated" => {
                    let (agent_did, controller_did, amount, op_tag) =
                        match decode_bond_lifecycle_log(&log.data) {
                            Some(v) => v,
                            None => {
                                warn!(
                                    topic = %String::from_utf8_lossy(topic),
                                    data_len = log.data.len(),
                                    "Malformed bond log payload, skipping"
                                );
                                continue;
                            }
                        };
                    let outcome = match op_tag {
                        0 => bond_manager
                            .post(&agent_did, &controller_did, amount, block_height_u64)
                            .map(|_| ()),
                        1 => bond_manager
                            .increase(&agent_did, amount, block_height_u64)
                            .map(|_| ()),
                        2 => bond_manager
                            .withdraw(&agent_did, block_height_u64)
                            .map(|_| ()),
                        other => {
                            warn!(
                                op_tag = other,
                                agent = %agent_did,
                                "Unknown bond op_tag in log payload"
                            );
                            continue;
                        }
                    };
                    if let Err(e) = outcome {
                        warn!(
                            topic = %String::from_utf8_lossy(topic),
                            agent = %agent_did,
                            controller = %controller_did,
                            amount,
                            error = %e,
                            "BondManager rejected reflected log; on-chain marker and \
                             off-chain state may have diverged"
                        );
                    } else {
                        debug!(
                            topic = %String::from_utf8_lossy(topic),
                            agent = %agent_did,
                            controller = %controller_did,
                            amount,
                            "BondManager reflected bond lifecycle log"
                        );
                    }
                }

                b"BondSlashed" => {
                    let (agent_did, _controller_did, slashed_amount, bps, terminal) =
                        match decode_bond_slashed_log(&log.data) {
                            Some(v) => v,
                            None => {
                                warn!(
                                    data_len = log.data.len(),
                                    "Malformed BondSlashed log payload, skipping"
                                );
                                continue;
                            }
                        };
                    // VM-driven slash (e.g. Terminate slash): no claim_id,
                    // recipient is the InsurancePool. The VM already moved
                    // funds; we only mirror lifecycle/amount state.
                    match bond_manager.slash(
                        &agent_did,
                        bps,
                        None,
                        "InsurancePool",
                        block_height_u64,
                    ) {
                        Ok((reflected_amount, _state)) => {
                            if reflected_amount != slashed_amount {
                                warn!(
                                    agent = %agent_did,
                                    vm_slashed = slashed_amount,
                                    manager_slashed = reflected_amount,
                                    "BondSlashed amount mismatch between VM and BondManager — \
                                     slash math drift?"
                                );
                            }
                            debug!(
                                agent = %agent_did,
                                bps,
                                slashed_amount,
                                terminal,
                                "BondManager reflected BondSlashed log"
                            );
                        }
                        Err(e) => {
                            warn!(
                                agent = %agent_did,
                                bps,
                                error = %e,
                                "BondManager rejected reflected BondSlashed; \
                                 on-chain and off-chain may have diverged"
                            );
                        }
                    }
                }

                b"InsuranceClaimPaid" => {
                    let (claim_id_hex, _claimant_addr, amount) =
                        match decode_insurance_claim_paid_log(&log.data) {
                            Some(v) => v,
                            None => {
                                warn!(
                                    data_len = log.data.len(),
                                    "Malformed InsuranceClaimPaid log payload, skipping"
                                );
                                continue;
                            }
                        };
                    match bond_manager.pay_claim(&claim_id_hex) {
                        Ok(record) => {
                            debug!(
                                claim_id = %claim_id_hex,
                                amount,
                                claim_status = ?record.status,
                                "BondManager reflected InsuranceClaimPaid log"
                            );
                        }
                        Err(e) => {
                            warn!(
                                claim_id = %claim_id_hex,
                                amount,
                                error = %e,
                                "BondManager rejected reflected InsuranceClaimPaid; \
                                 claim may have been settled out-of-band"
                            );
                        }
                    }
                }

                _ => {}
            }
        }
    }

    /// Reflect the canonical ERC-8004 `Registered(uint256 indexed
    /// agentId, string agentURI, address indexed owner)` event emitted
    /// by the on-chain `IdentityRegistry` proxy at
    /// `tenzro_identity::erc8004::addresses::IDENTITY_REGISTRY` into the
    /// off-chain `did → agentId` index stored in `CF_IDENTITIES` under
    /// the `erc8004_did_index:` prefix (see
    /// `crate::erc8004_mirror::ERC8004_DID_INDEX_PREFIX`), and patch
    /// the matching TDIP `Machine` identity's `erc8004_agent_id` field
    /// via `IdentityRegistry::apply_erc8004_registered_event`.
    ///
    /// This is the **other half** of the locked async-detached-spawn
    /// architecture (see `project_erc8004_evm_architecture` memory):
    /// `NativeErc8004Mirror::mirror_register_agent` dispatches the
    /// signed EVM tx and returns immediately; the resulting
    /// `Registered` event lands here when the block is applied, and
    /// this function closes the loop by populating the off-chain
    /// index that `lookup_agent_id_by_did` reads.
    ///
    /// The function is filter-by-address + filter-by-topic[0]: it only
    /// considers logs whose address matches `IDENTITY_REGISTRY` and
    /// whose first topic is
    /// `keccak256("Registered(uint256,string,address)")`. Logs that
    /// fail either filter are ignored.
    ///
    /// Decoded event layout (per Solidity ABI):
    /// - `topics[0]` = 32-byte event signature hash
    /// - `topics[1]` = 32-byte big-endian `uint256 agentId` (indexed)
    /// - `topics[2]` = 32-byte left-padded `address owner` (indexed)
    /// - `data`      = ABI-encoded `string agentURI`:
    ///   `offset(32)=0x20 || length_be(32) || padded_utf8_bytes`
    ///
    /// **DID derivation:** the canonical contract has no DID concept;
    /// the `did:tenzro:...` is conveyed in the `agentURI` payload
    /// itself. We parse it by recognising the well-known prefix
    /// `did:tenzro:` at the very start of the decoded URI string. Any
    /// other URI shape (HTTP, IPFS, plain text) is logged and skipped
    /// — it's a legitimate non-Tenzro agent registration that we have
    /// no DID to index.
    ///
    /// Idempotent: re-applying the same `Registered` event after a
    /// reorg / restart writes the same `(did, agent_id)` pair and
    /// leaves the TDIP record's `erc8004_agent_id` unchanged.
    async fn process_erc8004_registered_logs(
        &self,
        result: &tenzro_vm::ExecutionResult,
        block_height: BlockHeight,
    ) {
        use std::sync::OnceLock;
        use tenzro_identity::erc8004::addresses;

        // Lazy-compute the event signature hash once per process.
        // `keccak256("Registered(uint256,string,address)")`.
        static REGISTERED_TOPIC: OnceLock<[u8; 32]> = OnceLock::new();
        let registered_topic = REGISTERED_TOPIC.get_or_init(|| {
            tenzro_crypto::hash::keccak256(b"Registered(uint256,string,address)").to_bytes()
        });

        // Fast-path: most blocks have no ERC-8004 logs at all.
        let any_registered = result.logs.iter().any(|l| {
            l.address.as_slice() == addresses::IDENTITY_REGISTRY
                && l.topics
                    .first()
                    .map(|t| t.as_slice() == registered_topic.as_slice())
                    .unwrap_or(false)
        });
        if !any_registered {
            return;
        }

        for log in &result.logs {
            if log.address.as_slice() != addresses::IDENTITY_REGISTRY {
                continue;
            }
            if log.topics.first().map(|t| t.as_slice()) != Some(registered_topic.as_slice()) {
                continue;
            }
            // Need topics[0..=2] for sig / agentId / owner.
            if log.topics.len() < 3 {
                warn!(
                    target: "tenzro::erc8004::listener",
                    block_height = block_height.0,
                    topic_count = log.topics.len(),
                    "Registered log has fewer than 3 topics; skipping"
                );
                continue;
            }

            // Decode agentId from topics[1] (32-byte big-endian uint256).
            // We accept anything that fits in u64 — Tenzro genesis allocates
            // ids from 1 and will not overflow u64 within any realistic
            // testnet/mainnet horizon. Values with non-zero high 192 bits
            // are rejected loudly.
            let id_bytes = log.topics[1].as_slice();
            if id_bytes.len() != 32 {
                warn!(
                    target: "tenzro::erc8004::listener",
                    block_height = block_height.0,
                    len = id_bytes.len(),
                    "Registered topic[1] (agentId) has unexpected length; skipping"
                );
                continue;
            }
            if id_bytes[..24].iter().any(|b| *b != 0) {
                warn!(
                    target: "tenzro::erc8004::listener",
                    block_height = block_height.0,
                    "Registered agentId exceeds u64 — high 192 bits non-zero; skipping"
                );
                continue;
            }
            let mut id_buf = [0u8; 8];
            id_buf.copy_from_slice(&id_bytes[24..32]);
            let agent_id = u64::from_be_bytes(id_buf);

            // Decode the `string agentURI` from `data`. The ABI layout
            // for a single dynamic string is:
            //   offset (32)  = always 0x20
            //   length (32)  = big-endian byte count
            //   payload      = utf-8 bytes, right-padded to 32-byte word
            let did = match decode_single_string_abi(&log.data) {
                Some(s) => s,
                None => {
                    warn!(
                        target: "tenzro::erc8004::listener",
                        block_height = block_height.0,
                        agent_id,
                        data_len = log.data.len(),
                        "Registered.agentURI ABI-decode failed; skipping"
                    );
                    continue;
                }
            };

            // Only index DIDs that start with `did:tenzro:`. Any other URI
            // shape (HTTPS metadata, IPFS, opaque agentURI from a
            // non-Tenzro registrant) is a legitimate canonical-contract
            // registration but carries no DID we can key on.
            if !did.starts_with("did:tenzro:") {
                debug!(
                    target: "tenzro::erc8004::listener",
                    block_height = block_height.0,
                    agent_id,
                    uri_prefix = %did.chars().take(16).collect::<String>(),
                    "Registered.agentURI is not a did:tenzro: URI; not indexed"
                );
                continue;
            }

            // 1. Write the off-chain did → agentId index.
            let key = crate::erc8004_mirror::did_index_key(&did);
            let val = agent_id.to_be_bytes();
            if let Err(e) =
                self.storage.put(tenzro_storage::CF_IDENTITIES, &key, &val)
            {
                warn!(
                    target: "tenzro::erc8004::listener",
                    did = %did,
                    agent_id,
                    error = %e,
                    "Failed to write erc8004_did_index entry; subsequent lookups will miss"
                );
                continue;
            }

            // 1b. Write the reverse owner-address → agentId index. The owner
            //     is topics[2] (32-byte word, address in the low 20 bytes).
            //     This is what the autonomous-agent bootstrap paymaster
            //     consults via `AgentRegistryLookup::is_registered`.
            let owner_topic = log.topics[2].as_slice();
            if owner_topic.len() == 32 {
                let owner_addr = &owner_topic[12..32];
                let owner_key = crate::erc8004_mirror::owner_index_key(owner_addr);
                if let Err(e) =
                    self.storage.put(tenzro_storage::CF_IDENTITIES, &owner_key, &val)
                {
                    warn!(
                        target: "tenzro::erc8004::listener",
                        owner = %hex::encode(owner_addr),
                        agent_id,
                        error = %e,
                        "Failed to write erc8004_owner_index entry; paymaster lookups will miss"
                    );
                }
            }

            // 2. Patch the in-memory TDIP record's `erc8004_agent_id`
            //    field so callers reading the identity see the bound
            //    agent id without an extra RocksDB hop. The patch is a
            //    no-op on remote-node records that haven't been
            //    locally registered.
            if let Some(registry) = self.identity_registry.as_ref() {
                match registry.apply_erc8004_registered_event(&did, agent_id) {
                    Ok(true) => {
                        debug!(
                            target: "tenzro::erc8004::listener",
                            block_height = block_height.0,
                            did = %did,
                            agent_id,
                            "ERC-8004 Registered event reflected into TDIP identity"
                        );
                    }
                    Ok(false) => {
                        debug!(
                            target: "tenzro::erc8004::listener",
                            block_height = block_height.0,
                            did = %did,
                            agent_id,
                            "ERC-8004 Registered event indexed in RocksDB; \
                             no local TDIP identity to patch (foreign-node registration)"
                        );
                    }
                    Err(e) => {
                        warn!(
                            target: "tenzro::erc8004::listener",
                            block_height = block_height.0,
                            did = %did,
                            agent_id,
                            error = %e,
                            "Failed to apply Registered event to TDIP identity"
                        );
                    }
                }
            }
        }
    }

    /// Reflect VM-emitted escrow logs into the off-chain
    /// `EscrowManager` query index.
    ///
    /// The Native VM is the source of truth for escrow state and vault
    /// balances. The VM persists the canonical `EscrowAccount` JSON under
    /// `SYSTEM_ADDRESS` at storage key `escrow:<hex(escrow_id)>` and emits
    /// one of three log topics:
    ///
    /// | Topic            | Data layout                                         |
    /// |------------------|-----------------------------------------------------|
    /// | `EscrowCreated`  | `escrow_id(32) ‖ payer_addr(32) ‖ vault_bytes(32)` |
    /// | `EscrowReleased` | `escrow_id(32) ‖ payee_bytes(32) ‖ amount(16 LE)`  |
    /// | `EscrowRefunded` | `escrow_id(32) ‖ payer(32)       ‖ amount(16 LE)`  |
    ///
    /// We extract the escrow id from the log, locate the matching
    /// `StateChange` written by the VM at the same height (the new value
    /// is `serde_json::to_vec(&EscrowAccount{...})`), deserialize it, and
    /// reflect it into `EscrowManager`. The reflection methods do **not**
    /// touch balances and do **not** check ordering — the VM has already
    /// validated the transition. Errors are logged but never abort the
    /// block; divergence is recoverable on restart via
    /// `EscrowManager::with_storage`'s hydrate path.
    async fn process_escrow_logs(
        &self,
        result: &tenzro_vm::ExecutionResult,
        block_height: BlockHeight,
    ) {
        let any_escrow = result.logs.iter().any(|l| {
            l.topics.first().map(|t| {
                let s = t.as_slice();
                s == b"EscrowCreated" || s == b"EscrowReleased" || s == b"EscrowRefunded"
            }).unwrap_or(false)
        });
        if !any_escrow {
            return;
        }

        let escrow_manager = match self.escrow_manager.as_ref() {
            Some(m) => m.clone(),
            None => {
                debug!(
                    block_height = block_height.0,
                    "Escrow log observed but EscrowManager not wired; skipping reflection"
                );
                return;
            }
        };

        // VM `SYSTEM_ADDRESS` is `[0xFF; 20]` (private to tenzro-vm).
        const SYSTEM_ADDRESS_BYTES: [u8; 20] = [0xFF; 20];
        const ESCROW_KEY_PREFIX: &[u8] = b"escrow:";

        for log in &result.logs {
            let topic = match log.topics.first() {
                Some(t) => t.as_slice(),
                None => continue,
            };

            // All three topics start their data with the 32-byte escrow_id.
            if log.data.len() < 32 {
                warn!(
                    topic = %String::from_utf8_lossy(topic),
                    data_len = log.data.len(),
                    "Escrow log payload shorter than 32 bytes; skipping"
                );
                continue;
            }
            let escrow_id_bytes = &log.data[..32];
            let escrow_id_hex = hex::encode(escrow_id_bytes);
            let storage_key = format!("escrow:{}", escrow_id_hex);

            // Locate the matching state change: address == SYSTEM_ADDRESS,
            // key == "escrow:<hex>", new_value carries the canonical
            // EscrowAccount JSON.
            let escrow_blob = result.state_changes.iter().find_map(|sc| {
                if sc.address.as_slice() == SYSTEM_ADDRESS_BYTES.as_slice()
                    && sc.key.as_slice() == storage_key.as_bytes()
                    && sc.key.starts_with(ESCROW_KEY_PREFIX)
                {
                    sc.new_value.as_deref()
                } else {
                    None
                }
            });

            let escrow_blob = match escrow_blob {
                Some(b) => b,
                None => {
                    warn!(
                        topic = %String::from_utf8_lossy(topic),
                        escrow_id = %escrow_id_hex,
                        "Escrow log has no matching SYSTEM_ADDRESS state change; skipping"
                    );
                    continue;
                }
            };

            let escrow: tenzro_settlement::escrow::EscrowAccount =
                match serde_json::from_slice(escrow_blob) {
                    Ok(e) => e,
                    Err(e) => {
                        warn!(
                            topic = %String::from_utf8_lossy(topic),
                            escrow_id = %escrow_id_hex,
                            error = %e,
                            "Failed to decode EscrowAccount from VM state change; skipping"
                        );
                        continue;
                    }
                };

            let outcome = match topic {
                b"EscrowCreated" => escrow_manager.reflect_escrow_created(escrow),
                b"EscrowReleased" => escrow_manager.reflect_escrow_released(&escrow_id_hex),
                b"EscrowRefunded" => escrow_manager.reflect_escrow_refunded(&escrow_id_hex),
                _ => continue,
            };

            match outcome {
                Ok(()) => debug!(
                    topic = %String::from_utf8_lossy(topic),
                    escrow_id = %escrow_id_hex,
                    "EscrowManager reflected escrow log"
                ),
                Err(e) => warn!(
                    topic = %String::from_utf8_lossy(topic),
                    escrow_id = %escrow_id_hex,
                    error = %e,
                    "EscrowManager rejected reflected escrow log; \
                     on-chain and off-chain may have diverged"
                ),
            }
        }
    }

    /// Reflect VM-emitted validator-registry logs into the off-chain
    /// `ValidatorRegistry` (Dynamic Validator Set).
    ///
    /// Decodes `ValidatorRegister` / `ValidatorExit` / `ValidatorMetadataUpdate`
    /// log payloads matching the wire layouts produced by the native VM
    /// handlers in `tenzro-vm/src/native/mod.rs` and applies them to the
    /// registry. The registry is the read model consensus reads from at
    /// epoch boundaries; the VM is the source of truth for the on-chain
    /// `validator_register:<hex>` / `validator_exit:<hex>` markers.
    ///
    /// Errors are logged but never abort the block — divergence between
    /// the VM marker and the registry is recoverable on restart via
    /// `load_from_storage`.
    async fn process_validator_logs(
        &self,
        result: &tenzro_vm::ExecutionResult,
        block_height: BlockHeight,
    ) {
        let any_validator = result.logs.iter().any(|l| {
            l.topics.first().map(|t| {
                let s = t.as_slice();
                s == b"ValidatorRegister"
                    || s == b"ValidatorExit"
                    || s == b"ValidatorMetadataUpdate"
            }).unwrap_or(false)
        });
        if !any_validator {
            return;
        }

        let registry = match self.validator_registry.as_ref() {
            Some(r) => r.clone(),
            None => {
                debug!(
                    block_height = block_height.0,
                    "Validator log observed but ValidatorRegistry not wired; skipping reflection"
                );
                return;
            }
        };

        // Map block height → epoch via the consensus engine, falling back to
        // 0 when no consensus is wired (e.g. unit tests). The registry only
        // uses the epoch number for ordering and cooldown gating, so a
        // monotonic stand-in is acceptable in degraded mode.
        // EpochManager::current_epoch() is sync and returns Epoch (with .number).
        let current_epoch = match self.consensus.as_ref() {
            Some(c) => c.epoch_manager().current_epoch().number,
            None => 0,
        };

        for log in &result.logs {
            let topic = match log.topics.first() {
                Some(t) => t.as_slice(),
                None => continue,
            };

            match topic {
                b"ValidatorRegister" => {
                    let parsed = match decode_validator_register_log(&log.data) {
                        Some(v) => v,
                        None => {
                            warn!(
                                data_len = log.data.len(),
                                "Malformed ValidatorRegister log payload, skipping"
                            );
                            continue;
                        }
                    };
                    let from_addr = parsed.from;
                    if let Err(e) = registry.register_candidate(
                        from_addr,
                        parsed.consensus_pubkey,
                        parsed.pq_pubkey,
                        parsed.bls_pubkey,
                        parsed.withdrawal_address,
                        parsed.self_stake,
                        current_epoch,
                        parsed.metadata_uri,
                    ) {
                        warn!(
                            address = %from_addr,
                            error = %e,
                            "ValidatorRegistry rejected register_candidate; \
                             on-chain marker may have outpaced registry state"
                        );
                    } else {
                        debug!(
                            address = %from_addr,
                            self_stake = parsed.self_stake,
                            epoch = current_epoch,
                            "ValidatorRegistry reflected ValidatorRegister log"
                        );
                    }
                }

                b"ValidatorExit" => {
                    let from_addr = match tenzro_types::primitives::Address::from_bytes(&log.data) {
                        Some(a) => a,
                        None => {
                            warn!(
                                data_len = log.data.len(),
                                "Malformed ValidatorExit log payload (expected 32 bytes), skipping"
                            );
                            continue;
                        }
                    };
                    if let Err(e) = registry.request_exit(&from_addr) {
                        warn!(
                            address = %from_addr,
                            error = %e,
                            "ValidatorRegistry rejected request_exit"
                        );
                    } else {
                        debug!(
                            address = %from_addr,
                            "ValidatorRegistry reflected ValidatorExit log"
                        );
                    }
                }

                b"ValidatorMetadataUpdate" => {
                    let parsed = match decode_validator_metadata_update_log(&log.data) {
                        Some(v) => v,
                        None => {
                            warn!(
                                data_len = log.data.len(),
                                "Malformed ValidatorMetadataUpdate log payload, skipping"
                            );
                            continue;
                        }
                    };
                    let from_addr = parsed.from;
                    let uri = if parsed.metadata_uri.is_empty() {
                        None
                    } else {
                        Some(parsed.metadata_uri)
                    };
                    if let Err(e) = registry.update_metadata(
                        &from_addr,
                        uri,
                        parsed.tee_attestation_hash,
                    ) {
                        warn!(
                            address = %from_addr,
                            error = %e,
                            "ValidatorRegistry rejected update_metadata"
                        );
                    } else {
                        debug!(
                            address = %from_addr,
                            "ValidatorRegistry reflected ValidatorMetadataUpdate log"
                        );
                    }
                }

                _ => {}
            }
        }
    }

    /// Reflect VM-emitted workflow logs into the off-chain `WorkflowManager`
    /// + `PrivacyDomainRegistry`.
    ///
    /// Topics matched (mirror the 12 privileged-VM workflow selectors at
    /// `0x01000040`–`0x0100004B`):
    ///
    /// - `WorkflowCreate`
    /// - `WorkflowSign`
    /// - `WorkflowTransition`
    /// - `WorkflowObligationRegister`
    /// - `WorkflowObligationDischarge`
    /// - `WorkflowObligationDefault`
    /// - `WorkflowGateRegister`
    /// - `WorkflowApprovalOpen`
    /// - `WorkflowApprovalDecision`
    /// - `WorkflowKillSwitch`
    /// - `WorkflowPrivacyDomainRegister`
    /// - `WorkflowPrivacyDomainFreeze`
    ///
    /// The runtime is the read model RPC / MCP / A2A consult; the VM
    /// markers under `SYSTEM_ADDRESS` are the on-chain source of truth and
    /// drive hydration on restart.
    async fn process_workflow_logs(
        &self,
        result: &tenzro_vm::ExecutionResult,
        block_height: BlockHeight,
    ) {
        let any_workflow = result.logs.iter().any(|l| {
            l.topics.first().map(|t| {
                let s = t.as_slice();
                s == b"WorkflowCreate"
                    || s == b"WorkflowSign"
                    || s == b"WorkflowTransition"
                    || s == b"WorkflowObligationRegister"
                    || s == b"WorkflowObligationDischarge"
                    || s == b"WorkflowObligationDefault"
                    || s == b"WorkflowGateRegister"
                    || s == b"WorkflowApprovalOpen"
                    || s == b"WorkflowApprovalDecision"
                    || s == b"WorkflowKillSwitch"
                    || s == b"WorkflowPrivacyDomainRegister"
                    || s == b"WorkflowPrivacyDomainFreeze"
            }).unwrap_or(false)
        });
        if !any_workflow {
            return;
        }

        let runtime = match self.workflow_runtime.as_ref() {
            Some(rt) => rt.clone(),
            None => {
                debug!(
                    block_height = block_height.0,
                    "Workflow log observed but WorkflowRuntime not wired; skipping mirror"
                );
                return;
            }
        };

        for log in &result.logs {
            let topic = match log.topics.first() {
                Some(t) => t.as_slice(),
                None => continue,
            };
            match topic {
                b"WorkflowCreate" => runtime.apply_create(&log.data, block_height),
                b"WorkflowSign" => runtime.apply_sign(&log.data, block_height),
                b"WorkflowTransition" => runtime.apply_transition(&log.data, block_height),
                b"WorkflowObligationRegister" => {
                    runtime.apply_register_obligation(&log.data, block_height)
                }
                b"WorkflowObligationDischarge" => {
                    runtime.apply_discharge_obligation(&log.data, block_height)
                }
                b"WorkflowObligationDefault" => {
                    runtime.apply_default_obligation(&log.data, block_height)
                }
                b"WorkflowGateRegister" => runtime.apply_register_gate(&log.data, block_height),
                b"WorkflowApprovalOpen" => runtime.apply_open_approval(&log.data, block_height),
                b"WorkflowApprovalDecision" => {
                    runtime.apply_submit_decision(&log.data, block_height)
                }
                b"WorkflowKillSwitch" => runtime.apply_kill_switch(&log.data, block_height),
                b"WorkflowPrivacyDomainRegister" => {
                    runtime.apply_register_privacy_domain(&log.data, block_height)
                }
                b"WorkflowPrivacyDomainFreeze" => {
                    runtime.apply_freeze_privacy_domain(&log.data, block_height)
                }
                _ => {}
            }
        }
    }

    /// Apply a single (non-cascade) kill-switch action to one agent: drive
    /// the lifecycle FSM and adjust stake. Side-effects are independent —
    /// a failure on one does not block the other.
    async fn apply_kill_switch_action(
        &self,
        action: &KillSwitchAction,
        agent_did: &str,
        receipt: &KillSwitchReceipt,
    ) {
        // Lifecycle FSM transition.
        if let Some(ref runtime) = self.agent_runtime {
            let result = match action {
                KillSwitchAction::Pause => {
                    runtime.pause_agent(
                        agent_did,
                        receipt.controller_did.clone(),
                        receipt.reason_code as u32,
                        receipt.reason_text.clone(),
                    ).await
                }
                KillSwitchAction::Quarantine => {
                    runtime.quarantine_agent(
                        agent_did,
                        receipt.controller_did.clone(),
                        receipt.reason_code as u32,
                        receipt.reason_text.clone(),
                    ).await
                }
                KillSwitchAction::Terminate => {
                    let reason = receipt.reason_text.clone()
                        .unwrap_or_else(|| format!(
                            "kill-switch terminate (code={})",
                            receipt.reason_code
                        ));
                    runtime.terminate_agent(agent_did, reason).await
                }
            };
            if let Err(e) = result {
                warn!(
                    action = ?action,
                    agent_did = %agent_did,
                    error = %e,
                    "Lifecycle transition failed for kill-switch action"
                );
            }
        } else {
            debug!(
                "AgentRuntime not wired; kill-switch lifecycle transition skipped"
            );
        }

        // Stake side-effects.
        let staker_address = match self.resolve_staker_address(agent_did) {
            Some(a) => a,
            None => {
                debug!(
                    agent_did = %agent_did,
                    "No staker address resolvable for agent; skipping stake side-effect"
                );
                return;
            }
        };
        let staking = match self.staking.as_ref() {
            Some(s) => s,
            None => {
                debug!("StakingManager not wired; stake side-effect skipped");
                return;
            }
        };

        match action {
            KillSwitchAction::Pause | KillSwitchAction::Quarantine => {
                if let Err(e) = staking.freeze_stake(&staker_address) {
                    warn!(
                        agent_did = %agent_did,
                        staker = %staker_address,
                        error = %e,
                        "Failed to freeze stake under kill-switch"
                    );
                }
            }
            KillSwitchAction::Terminate => {
                let stake_amount = staking
                    .get_stake(&staker_address)
                    .map(|s| s.amount)
                    .unwrap_or(0);
                let bps = receipt.slash_bps.unwrap_or(0) as u128;
                let slash_amount = stake_amount.saturating_mul(bps) / 10_000u128;
                if slash_amount > 0 {
                    let slashed_by = staker_address;
                    let reason = receipt.reason_text.clone().unwrap_or_else(|| {
                        format!(
                            "kill-switch terminate (code={}, controller={})",
                            receipt.reason_code, receipt.controller_did
                        )
                    });
                    if let Err(e) = staking.slash(
                        &staker_address,
                        slash_amount,
                        reason,
                        slashed_by,
                    ) {
                        warn!(
                            agent_did = %agent_did,
                            staker = %staker_address,
                            slash_amount = slash_amount,
                            error = %e,
                            "Failed to slash stake under kill-switch terminate"
                        );
                    }
                }
            }
        }
    }

    /// BFS through the spawn tree (`AgentRuntime::get_children`) and
    /// terminate every descendant of `root_did`. Depth-bounded so a
    /// cyclic or deeply nested graph cannot stall block finalization.
    async fn cascade_terminate(
        &self,
        root_did: &str,
        receipt: &KillSwitchReceipt,
        _block_height: BlockHeight,
    ) {
        const MAX_DEPTH: usize = 32;
        let runtime = match self.agent_runtime.as_ref() {
            Some(r) => r,
            None => return,
        };

        let mut frontier: Vec<(String, usize)> = vec![(root_did.to_string(), 0)];
        let mut visited: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        visited.insert(root_did.to_string());

        while let Some((parent, depth)) = frontier.pop() {
            if depth >= MAX_DEPTH {
                warn!(
                    parent = %parent,
                    depth = depth,
                    "Kill-switch cascade depth bound reached; halting traversal"
                );
                continue;
            }
            for child in runtime.get_children(&parent) {
                if !visited.insert(child.clone()) {
                    continue;
                }
                // Apply termination to the child as a non-cascading event.
                // We synthesize a per-child receipt anchored to the same
                // controller and reason so the audit trail explains the
                // chain of consequence.
                let child_receipt = KillSwitchReceipt {
                    receipt_id: format!("{}:cascade:{}", receipt.receipt_id, child),
                    action: KillSwitchAction::Terminate,
                    agent_did: child.clone(),
                    controller_did: receipt.controller_did.clone(),
                    reason_code: receipt.reason_code,
                    reason_text: receipt.reason_text.clone(),
                    evidence_hash: receipt.evidence_hash.clone(),
                    slash_bps: receipt.slash_bps,
                    cascade: Some(false),
                    pause_until: None,
                    frozen_at_block: receipt.frozen_at_block,
                    timestamp: receipt.timestamp,
                };
                self.apply_kill_switch_action(
                    &KillSwitchAction::Terminate,
                    &child,
                    &child_receipt,
                ).await;
                if let Some(ref store) = self.kill_switch_store
                    && let Err(e) = store.record(child_receipt) {
                        error!(
                            parent = %parent,
                            child = %child,
                            error = %e,
                            "Failed to persist cascade KillSwitchReceipt"
                        );
                    }
                frontier.push((child, depth + 1));
            }
        }
    }

    /// Resolve a machine DID to the staker `Address` that the
    /// `StakingManager` keys on. Returns `None` if the DID is unknown or
    /// the identity has no wallet binding.
    fn resolve_staker_address(
        &self,
        agent_did: &str,
    ) -> Option<tenzro_types::primitives::Address> {
        let registry = self.identity_registry.as_ref()?;
        registry.resolve(agent_did).ok().map(|id| id.wallet_address)
    }

    /// Off-chain spend-ceiling enforcement on the gossip-relay path.
    /// Mirrors `enforce_typed_tx_spend_ceilings` in `rpc.rs` — both
    /// admission paths now consult the same DelegationScope + runtime
    /// SpendingPolicy gate so a delegated machine identity cannot
    /// bypass enforcement by signing locally and submitting via gossip
    /// instead of RPC.
    ///
    /// Returns `Ok(())` for:
    ///   - Senders that do not resolve to a registered DID (human EOAs).
    ///   - Lifecycle/validator/TEE ops (authorized via separate gates).
    ///   - Nodes without an identity registry wired (early bootstrap).
    fn enforce_relay_spend_ceilings(
        &self,
        tx: &tenzro_types::Transaction,
    ) -> Result<()> {
        let registry = match self.identity_registry.as_ref() {
            Some(r) => r,
            None => return Ok(()),
        };
        let did = match registry.find_did_by_address(&tx.from) {
            Some(d) => d,
            None => return Ok(()),
        };

        let (operation, value): (&str, u128) = match &tx.tx_type {
            tenzro_types::TransactionType::Transfer { amount } => ("transfer", *amount),
            tenzro_types::TransactionType::ContractCall { .. } => ("contract_call", 0),
            tenzro_types::TransactionType::ContractDeploy { .. } => ("contract_deploy", 0),
            tenzro_types::TransactionType::AgentRegister { .. } => ("agent_register", 0),
            tenzro_types::TransactionType::AgentExecute { .. } => ("agent_execute", 0),
            tenzro_types::TransactionType::ModelInference { .. } => ("model_inference", 0),
            tenzro_types::TransactionType::ProviderStake { amount, .. } => ("stake", *amount),
            tenzro_types::TransactionType::ProviderUnstake { .. } => ("unstake", 0),
            tenzro_types::TransactionType::CreateEscrow { amount, .. } => ("create_escrow", *amount),
            tenzro_types::TransactionType::ReleaseEscrow { .. } => ("release_escrow", 0),
            tenzro_types::TransactionType::RefundEscrow { .. } => ("refund_escrow", 0),
            tenzro_types::TransactionType::BridgeTransfer { amount, .. } => ("bridge", *amount),
            tenzro_types::TransactionType::GovernancePropose { .. } => ("governance_propose", 0),
            tenzro_types::TransactionType::GovernanceVote { .. } => ("governance_vote", 0),
            tenzro_types::TransactionType::PostAgentBond { amount, .. } => ("post_bond", *amount),
            tenzro_types::TransactionType::IncreaseAgentBond { amount, .. } => ("increase_bond", *amount),
            tenzro_types::TransactionType::WithdrawAgentBond { .. } => ("withdraw_bond", 0),
            tenzro_types::TransactionType::PayInsuranceClaim { amount, .. } => ("insurance_claim", *amount),
            tenzro_types::TransactionType::PauseAgent { .. }
            | tenzro_types::TransactionType::QuarantineAgent { .. }
            | tenzro_types::TransactionType::TerminateAgent { .. } => return Ok(()),
            // x402 settlement is dispatched by the node's system key after the
            // credential was verified off-chain; there is no payer DELEGATION
            // scope to enforce here (the settling parties never signed this
            // tx). Skip the delegation/spending-policy pre-check.
            tenzro_types::TransactionType::X402Settle { .. } => return Ok(()),
            tenzro_types::TransactionType::TeeProviderRegister { .. }
            | tenzro_types::TransactionType::RegisterValidator { .. }
            | tenzro_types::TransactionType::UpdateValidatorMetadata { .. }
            | tenzro_types::TransactionType::ExitValidator => return Ok(()),
        };

        // (1) DelegationScope. Humans pass through inside enforce_operation.
        let value_opt = if value == 0 { None } else { Some(value) };
        if let Err(e) = registry.enforce_operation(&did, operation, value_opt) {
            return Err(NodeError::InvalidTransaction(format!(
                "DelegationScope violation on relayed transaction: {e}"
            )));
        }

        // (2) Runtime SpendingPolicy.
        if value > 0
            && let Some(runtime) = self.agent_runtime.as_ref()
            && let Some(policy) = runtime.get_spending_policy(&did)
        {
            if !policy.enabled {
                return Err(NodeError::InvalidTransaction(format!(
                    "Runtime SpendingPolicy disabled for {did}"
                )));
            }
            if value > policy.max_per_transaction as u128 {
                return Err(NodeError::InvalidTransaction(format!(
                    "Runtime SpendingPolicy: value {value} exceeds max_per_transaction {} for {did}",
                    policy.max_per_transaction
                )));
            }
            let projected = (policy.current_daily_spend as u128).saturating_add(value);
            if projected > policy.max_daily_spend as u128 {
                return Err(NodeError::InvalidTransaction(format!(
                    "Runtime SpendingPolicy: projected daily spend {projected} exceeds max_daily_spend {} for {did}",
                    policy.max_daily_spend
                )));
            }
        }

        Ok(())
    }
}

/// Decode a Solidity ABI-encoded single dynamic `string` from a log
/// `data` payload. Layout:
///
/// ```text
///   offset (32 bytes, big-endian) — always 0x20 for a single dynamic head
///   length (32 bytes, big-endian) — utf-8 byte count
///   payload (length bytes, right-padded to a 32-byte word)
/// ```
///
/// Returns `None` if the payload is shorter than 64 bytes, the offset
/// word is not 0x20, the declared length overflows the remaining buffer,
/// or the payload bytes are not valid UTF-8. Trailing zero-padding bytes
/// after `length` are tolerated — only the first `length` bytes are
/// decoded.
fn decode_single_string_abi(data: &[u8]) -> Option<String> {
    if data.len() < 64 {
        return None;
    }
    // Offset word: must be exactly 0x20 (32-byte big-endian) for a
    // single dynamic-string head. Anything else is a malformed payload
    // (or a multi-arg event we shouldn't be decoding with this helper).
    if data[..31].iter().any(|b| *b != 0) || data[31] != 0x20 {
        return None;
    }
    // Length word: u256 big-endian; we reject anything that doesn't
    // fit in usize on this platform.
    if data[32..56].iter().any(|b| *b != 0) {
        return None;
    }
    let mut len_buf = [0u8; 8];
    len_buf.copy_from_slice(&data[56..64]);
    let len = u64::from_be_bytes(len_buf) as usize;
    let body = data.get(64..64usize.checked_add(len)?)?;
    std::str::from_utf8(body).ok().map(|s| s.to_string())
}

/// Decode the kill-switch log `data` field per the VM wire format:
/// `agent_did_len_le(4) || agent_did || controller_did_len_le(4) ||
///  controller_did || receipt_id(32)`.
///
/// Returns `(agent_did, controller_did, receipt_id_hex)` on success, or
/// `None` on malformed input.
fn decode_killswitch_log_data(data: &[u8]) -> Option<(String, String, String)> {
    if data.len() < 4 {
        return None;
    }
    let agent_len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let cursor = 4usize.checked_add(agent_len)?;
    if data.len() < cursor + 4 {
        return None;
    }
    let agent_did = std::str::from_utf8(&data[4..cursor]).ok()?.to_string();
    let ctrl_len = u32::from_le_bytes(data[cursor..cursor + 4].try_into().ok()?) as usize;
    let cursor2 = cursor.checked_add(4)?.checked_add(ctrl_len)?;
    if data.len() < cursor2 + 32 {
        return None;
    }
    let controller_did =
        std::str::from_utf8(&data[cursor + 4..cursor2]).ok()?.to_string();
    let receipt_id_hex = hex::encode(&data[cursor2..cursor2 + 32]);
    Some((agent_did, controller_did, receipt_id_hex))
}

/// Decode a `BondPosted` / `BondIncreased` / `BondWithdrawInitiated` log.
///
/// Layout (mirror of `tenzro_vm::native::encode_bond_log_data`):
/// `agent_did_len_le(4) || agent_did || controller_did_len_le(4) ||
///  controller_did || amount_le(16) || op_tag(1)`
/// where `op_tag ∈ {0=Posted, 1=Increased, 2=WithdrawInitiated}`.
///
/// Returns `(agent_did, controller_did, amount, op_tag)`.
fn decode_bond_lifecycle_log(data: &[u8]) -> Option<(String, String, u128, u8)> {
    if data.len() < 4 {
        return None;
    }
    let agent_len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let after_agent = 4usize.checked_add(agent_len)?;
    if data.len() < after_agent + 4 {
        return None;
    }
    let agent_did = std::str::from_utf8(&data[4..after_agent]).ok()?.to_string();
    let ctrl_len =
        u32::from_le_bytes(data[after_agent..after_agent + 4].try_into().ok()?) as usize;
    let after_ctrl = after_agent.checked_add(4)?.checked_add(ctrl_len)?;
    if data.len() < after_ctrl + 16 + 1 {
        return None;
    }
    let controller_did = std::str::from_utf8(&data[after_agent + 4..after_ctrl])
        .ok()?
        .to_string();
    let amount = u128::from_le_bytes(data[after_ctrl..after_ctrl + 16].try_into().ok()?);
    let op_tag = data[after_ctrl + 16];
    Some((agent_did, controller_did, amount, op_tag))
}

/// Decode a `BondSlashed` log.
///
/// Layout (mirror of the inline emit in
/// `tenzro_vm::native::execute_terminate_agent` slash branch):
/// `agent_did_len_le(4) || agent_did || controller_did_len_le(4) ||
///  controller_did || slashed_amount_le(16) || bps_le(2) || terminal(1)`.
///
/// Returns `(agent_did, controller_did, slashed_amount, bps, terminal)`.
fn decode_bond_slashed_log(data: &[u8]) -> Option<(String, String, u128, u16, bool)> {
    if data.len() < 4 {
        return None;
    }
    let agent_len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let after_agent = 4usize.checked_add(agent_len)?;
    if data.len() < after_agent + 4 {
        return None;
    }
    let agent_did = std::str::from_utf8(&data[4..after_agent]).ok()?.to_string();
    let ctrl_len =
        u32::from_le_bytes(data[after_agent..after_agent + 4].try_into().ok()?) as usize;
    let after_ctrl = after_agent.checked_add(4)?.checked_add(ctrl_len)?;
    if data.len() < after_ctrl + 16 + 2 + 1 {
        return None;
    }
    let controller_did = std::str::from_utf8(&data[after_agent + 4..after_ctrl])
        .ok()?
        .to_string();
    let slashed_amount =
        u128::from_le_bytes(data[after_ctrl..after_ctrl + 16].try_into().ok()?);
    let bps = u16::from_le_bytes(
        data[after_ctrl + 16..after_ctrl + 18].try_into().ok()?,
    );
    let terminal = data[after_ctrl + 18] != 0;
    Some((agent_did, controller_did, slashed_amount, bps, terminal))
}

/// Decode an `InsuranceClaimPaid` log.
///
/// Layout (mirror of the inline emit in
/// `tenzro_vm::native::execute_pay_insurance_claim`):
/// `claim_id_len_le(4) || claim_id_bytes || claimant(32) || amount_le(16)`.
///
/// Returns `(claim_id_hex, claimant_address_bytes, amount)`.
fn decode_insurance_claim_paid_log(data: &[u8]) -> Option<(String, [u8; 32], u128)> {
    if data.len() < 4 {
        return None;
    }
    let claim_id_len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let after_claim_id = 4usize.checked_add(claim_id_len)?;
    if data.len() < after_claim_id + 32 + 16 {
        return None;
    }
    let claim_id_hex = std::str::from_utf8(&data[4..after_claim_id])
        .ok()?
        .to_string();
    let mut claimant = [0u8; 32];
    claimant.copy_from_slice(&data[after_claim_id..after_claim_id + 32]);
    let amount = u128::from_le_bytes(
        data[after_claim_id + 32..after_claim_id + 48].try_into().ok()?,
    );
    Some((claim_id_hex, claimant, amount))
}

/// Parsed payload of a `ValidatorRegister` log.
struct ParsedValidatorRegister {
    from: tenzro_types::primitives::Address,
    self_stake: u128,
    consensus_pubkey: Vec<u8>,
    bls_pubkey: Vec<u8>,
    pq_pubkey: Vec<u8>,
    withdrawal_address: tenzro_types::primitives::Address,
    metadata_uri: String,
}

/// Decode a `ValidatorRegister` log.
///
/// Layout (mirror of the inline emit in
/// `tenzro_vm::native::execute_validator_register`):
/// `from(32) || stake_le(16) || consensus_pubkey(32) || bls_pubkey(48) ||
///  pq_pubkey_len_le(4) || pq_pubkey || withdrawal(32) ||
///  metadata_uri_len_le(4) || metadata_uri`.
fn decode_validator_register_log(data: &[u8]) -> Option<ParsedValidatorRegister> {
    // 32 from + 16 stake + 32 consensus_pubkey + 48 bls + 4 pq_len = 132 bytes minimum
    if data.len() < 132 {
        return None;
    }
    let from = tenzro_types::primitives::Address::from_bytes(&data[0..32])?;
    let self_stake = u128::from_le_bytes(data[32..48].try_into().ok()?);
    let mut consensus_pubkey = vec![0u8; 32];
    consensus_pubkey.copy_from_slice(&data[48..80]);
    let mut bls_pubkey = vec![0u8; 48];
    bls_pubkey.copy_from_slice(&data[80..128]);
    let pq_len = u32::from_le_bytes(data[128..132].try_into().ok()?) as usize;
    let after_pq = 132usize.checked_add(pq_len)?;
    // Need pq_pubkey + 32 withdrawal + 4 uri_len after that
    if data.len() < after_pq + 32 + 4 {
        return None;
    }
    let pq_pubkey = data[132..after_pq].to_vec();
    let withdrawal_address =
        tenzro_types::primitives::Address::from_bytes(&data[after_pq..after_pq + 32])?;
    let after_withdrawal = after_pq + 32;
    let uri_len = u32::from_le_bytes(
        data[after_withdrawal..after_withdrawal + 4].try_into().ok()?,
    ) as usize;
    let after_uri_len = after_withdrawal + 4;
    if data.len() < after_uri_len + uri_len {
        return None;
    }
    let metadata_uri =
        std::str::from_utf8(&data[after_uri_len..after_uri_len + uri_len])
            .ok()?
            .to_string();
    Some(ParsedValidatorRegister {
        from,
        self_stake,
        consensus_pubkey,
        bls_pubkey,
        pq_pubkey,
        withdrawal_address,
        metadata_uri,
    })
}

/// Parsed payload of a `ValidatorMetadataUpdate` log.
struct ParsedValidatorMetadataUpdate {
    from: tenzro_types::primitives::Address,
    metadata_uri: String,
    tee_attestation_hash: Option<[u8; 32]>,
}

/// Decode a `ValidatorMetadataUpdate` log.
///
/// Layout (mirror of the inline emit in
/// `tenzro_vm::native::execute_validator_update_metadata`):
/// `from(32) || metadata_uri_len_le(4) || metadata_uri ||
///  tee_hash_present(1) || [tee_hash(32)]`.
fn decode_validator_metadata_update_log(
    data: &[u8],
) -> Option<ParsedValidatorMetadataUpdate> {
    // 32 from + 4 uri_len + 1 tee_present = 37 bytes minimum
    if data.len() < 37 {
        return None;
    }
    let from = tenzro_types::primitives::Address::from_bytes(&data[0..32])?;
    let uri_len = u32::from_le_bytes(data[32..36].try_into().ok()?) as usize;
    let after_uri_len = 36usize;
    let after_uri = after_uri_len.checked_add(uri_len)?;
    if data.len() < after_uri + 1 {
        return None;
    }
    let metadata_uri =
        std::str::from_utf8(&data[after_uri_len..after_uri]).ok()?.to_string();
    let tee_present = data[after_uri];
    let tee_attestation_hash = match tee_present {
        0 => None,
        1 => {
            if data.len() < after_uri + 1 + 32 {
                return None;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&data[after_uri + 1..after_uri + 1 + 32]);
            Some(h)
        }
        _ => return None,
    };
    Some(ParsedValidatorMetadataUpdate {
        from,
        metadata_uri,
        tee_attestation_hash,
    })
}

/// Verifies the hybrid (classical + ML-DSA-65) signature of a transaction.
///
/// Per the post-quantum migration, every admitted transaction must
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
    use subtle::ConstantTimeEq;
    use tenzro_crypto::{PublicKey, KeyType, signatures};

    // Compute the transaction hash (this is the signed message for both legs).
    let tx_hash = signed_tx.transaction.hash();
    let message = tx_hash.as_bytes();

    // 0. Sender-impersonation guard. The classical pubkey MUST derive the
    //    declared `from` address. Without this bind, a peer can sign a tx
    //    with their own key while placing a victim's address in `from`; the
    //    pubkey-bound signature check below would then pass, debiting the
    //    victim on every node that admits the tx via gossip.
    //    Two key-bound `from` conventions exist on this chain and both must
    //    be accepted: (a) the raw 32-byte Ed25519 public key itself (native
    //    convention — faucet system account, participate-provisioned
    //    wallets), and (b) the 20-byte derived address left-aligned in the
    //    canonical 32-byte `tenzro_types::Address` slot (addr20 || 12 zero
    //    bytes, EVM convention). Both bind to the same keypair, so either
    //    match proves control. ct_eq on slices of unequal length is always
    //    false, hence the expansion before comparing.
    let public_key = PublicKey::new(KeyType::Ed25519, signed_tx.signature.public_key.clone());
    let derived = public_key.to_address();
    let mut expected_from = [0u8; 32];
    expected_from[..20].copy_from_slice(derived.as_bytes());
    let from_bytes = signed_tx.transaction.from.as_bytes();
    let matches_derived = expected_from.ct_eq(from_bytes);
    let matches_pubkey = signed_tx.signature.public_key.as_slice().ct_eq(from_bytes);
    if !bool::from(matches_derived | matches_pubkey) {
        return Err(NodeError::InvalidTransaction(
            "Signature public_key does not derive the declared 'from' address".to_string(),
        ));
    }

    // 1. Classical Ed25519 leg.
    let crypto_sig = tenzro_crypto::Signature::new(
        KeyType::Ed25519,
        signed_tx.signature.bytes.clone(),
    );
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
///
/// For native operations dispatched through 4-byte selectors (escrow,
/// kill-switch), this builds `tx.data = SELECTOR || serde_json(payload)`
/// matching the decoders in `tenzro-vm::native`. JSON serialization for
/// these well-typed payloads cannot fail in practice (no non-stringable
/// map keys, no `f32::NAN`); we panic loudly if it ever does so a bug
/// surfaces immediately rather than producing a malformed wire payload.
fn convert_transaction(signed_tx: &SignedTransaction) -> VmTransaction {
    use tenzro_vm::native::{
        SELECTOR_ESCROW_CREATE, SELECTOR_ESCROW_REFUND, SELECTOR_ESCROW_RELEASE,
        SELECTOR_KILLSWITCH_PAUSE, SELECTOR_KILLSWITCH_QUARANTINE,
        SELECTOR_KILLSWITCH_TERMINATE,
        SELECTOR_POST_AGENT_BOND, SELECTOR_INCREASE_AGENT_BOND,
        SELECTOR_WITHDRAW_AGENT_BOND, SELECTOR_PAY_INSURANCE_CLAIM,
        SELECTOR_X402_SETTLE,
        SELECTOR_VALIDATOR_REGISTER, SELECTOR_VALIDATOR_EXIT,
        SELECTOR_VALIDATOR_UPDATE_METADATA,
    };

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
        // ---- Escrow primitive (native VM dispatch) ------------------------
        TransactionType::CreateEscrow { payee, amount, asset_id, expires_at, release_conditions } => {
            #[derive(serde::Serialize)]
            struct CreateEscrowPayload<'a> {
                payee: &'a tenzro_types::primitives::Address,
                amount: u128,
                asset_id: &'a tenzro_types::asset::AssetId,
                expires_at: u64,
                release_conditions: &'a tenzro_types::settlement::ReleaseConditions,
            }
            let payload = CreateEscrowPayload {
                payee,
                amount: *amount,
                asset_id,
                expires_at: *expires_at,
                release_conditions,
            };
            let mut data = SELECTOR_ESCROW_CREATE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("CreateEscrow payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::ReleaseEscrow { escrow_id, proof } => {
            #[derive(serde::Serialize)]
            struct ReleaseEscrowPayload<'a> {
                escrow_id: &'a [u8; 32],
                proof: &'a tenzro_types::settlement::ServiceProof,
            }
            let payload = ReleaseEscrowPayload { escrow_id, proof };
            let mut data = SELECTOR_ESCROW_RELEASE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("ReleaseEscrow payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::RefundEscrow { escrow_id } => {
            #[derive(serde::Serialize)]
            struct RefundEscrowPayload<'a> {
                escrow_id: &'a [u8; 32],
            }
            let payload = RefundEscrowPayload { escrow_id };
            let mut data = SELECTOR_ESCROW_REFUND.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("RefundEscrow payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // ---- Kill-switch (Agent-Swarm Spec 1, native VM dispatch) ---------
        TransactionType::PauseAgent { agent_did, controller_did, reason_code, reason_text, until } => {
            #[derive(serde::Serialize)]
            struct PauseAgentPayload<'a> {
                agent_did: &'a str,
                controller_did: &'a str,
                reason_code: u16,
                #[serde(skip_serializing_if = "Option::is_none")]
                reason_text: Option<&'a str>,
                /// `until` projected to millis-since-epoch for the VM's `u64` field.
                #[serde(skip_serializing_if = "Option::is_none")]
                until: Option<u64>,
            }
            let payload = PauseAgentPayload {
                agent_did,
                controller_did,
                reason_code: *reason_code,
                reason_text: reason_text.as_deref(),
                until: until.map(|t| t.as_millis() as u64),
            };
            let mut data = SELECTOR_KILLSWITCH_PAUSE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("PauseAgent payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::QuarantineAgent { agent_did, controller_did, reason_code, reason_text, evidence_hash } => {
            #[derive(serde::Serialize)]
            struct QuarantineAgentPayload<'a> {
                agent_did: &'a str,
                controller_did: &'a str,
                reason_code: u16,
                #[serde(skip_serializing_if = "Option::is_none")]
                reason_text: Option<&'a str>,
                /// VM-side payload expects the evidence commitment as 64-char
                /// lowercase hex. We project the byte array here.
                #[serde(skip_serializing_if = "Option::is_none")]
                evidence_hash: Option<String>,
            }
            let payload = QuarantineAgentPayload {
                agent_did,
                controller_did,
                reason_code: *reason_code,
                reason_text: reason_text.as_deref(),
                evidence_hash: evidence_hash.as_ref().map(hex::encode),
            };
            let mut data = SELECTOR_KILLSWITCH_QUARANTINE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("QuarantineAgent payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::TerminateAgent { agent_did, controller_did, reason_code, slash_bps, cascade } => {
            #[derive(serde::Serialize)]
            struct TerminateAgentPayload<'a> {
                agent_did: &'a str,
                controller_did: &'a str,
                reason_code: u16,
                slash_bps: u16,
                cascade: bool,
            }
            let payload = TerminateAgentPayload {
                agent_did,
                controller_did,
                reason_code: *reason_code,
                slash_bps: *slash_bps,
                cascade: *cascade,
            };
            let mut data = SELECTOR_KILLSWITCH_TERMINATE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("TerminateAgent payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // ---- AgentBond surety (Agent-Swarm Spec 9, native VM dispatch) ----
        // Payload field names MUST match the VM-side `PostAgentBondPayload`,
        // `IncreaseAgentBondPayload`, `WithdrawAgentBondPayload`, and
        // `PayInsuranceClaimPayload` structs in
        // `tenzro-vm/src/native/mod.rs` — they are deserialized via
        // `serde_json::from_slice(&tx.data[4..])`.
        TransactionType::PostAgentBond { agent_did, controller_did, amount } => {
            #[derive(serde::Serialize)]
            struct PostAgentBondPayload<'a> {
                agent_did: &'a str,
                controller_did: &'a str,
                amount: u128,
            }
            let payload = PostAgentBondPayload {
                agent_did,
                controller_did,
                amount: *amount,
            };
            let mut data = SELECTOR_POST_AGENT_BOND.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("PostAgentBond payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::IncreaseAgentBond { agent_did, amount } => {
            #[derive(serde::Serialize)]
            struct IncreaseAgentBondPayload<'a> {
                agent_did: &'a str,
                amount: u128,
            }
            let payload = IncreaseAgentBondPayload {
                agent_did,
                amount: *amount,
            };
            let mut data = SELECTOR_INCREASE_AGENT_BOND.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("IncreaseAgentBond payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::WithdrawAgentBond { agent_did } => {
            #[derive(serde::Serialize)]
            struct WithdrawAgentBondPayload<'a> {
                agent_did: &'a str,
            }
            let payload = WithdrawAgentBondPayload { agent_did };
            let mut data = SELECTOR_WITHDRAW_AGENT_BOND.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("WithdrawAgentBond payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::PayInsuranceClaim { claim_id_hex, claimant, amount } => {
            #[derive(serde::Serialize)]
            struct PayInsuranceClaimPayload<'a> {
                claim_id_hex: &'a str,
                claimant: &'a tenzro_types::primitives::Address,
                amount: u128,
            }
            let payload = PayInsuranceClaimPayload {
                claim_id_hex,
                claimant,
                amount: *amount,
            };
            let mut data = SELECTOR_PAY_INSURANCE_CLAIM.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("PayInsuranceClaim payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // Field names MUST match the VM-side `X402SettlePayload` in
        // `tenzro-vm/src/native/mod.rs`.
        TransactionType::X402Settle {
            payer,
            payee,
            amount,
            payment_id,
            app_wallet,
            margin_bps,
        } => {
            #[derive(serde::Serialize)]
            struct X402SettlePayload<'a> {
                payer: &'a tenzro_types::primitives::Address,
                payee: &'a tenzro_types::primitives::Address,
                amount: u128,
                payment_id: &'a str,
                app_wallet: Option<&'a tenzro_types::primitives::Address>,
                margin_bps: u32,
            }
            let payload = X402SettlePayload {
                payer,
                payee,
                amount: *amount,
                payment_id,
                app_wallet: app_wallet.as_ref(),
                margin_bps: *margin_bps,
            };
            let mut data = SELECTOR_X402_SETTLE.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("X402Settle payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // ---- Dynamic validator set (native VM dispatch) -------------------
        // Payload field names MUST match `ValidatorRegisterPayload` and
        // `ValidatorUpdateMetadataPayload` in `tenzro-vm/src/native/mod.rs`.
        TransactionType::RegisterValidator {
            consensus_pubkey,
            pq_pubkey,
            bls_pubkey,
            withdrawal_address,
            self_stake,
            metadata_uri,
        } => {
            #[derive(serde::Serialize)]
            struct ValidatorRegisterPayload<'a> {
                consensus_pubkey: &'a [u8],
                pq_pubkey: &'a [u8],
                bls_pubkey: &'a [u8],
                withdrawal_address: &'a tenzro_types::primitives::Address,
                self_stake: u128,
                metadata_uri: &'a str,
            }
            let payload = ValidatorRegisterPayload {
                consensus_pubkey,
                pq_pubkey,
                bls_pubkey,
                withdrawal_address,
                self_stake: *self_stake,
                metadata_uri,
            };
            let mut data = SELECTOR_VALIDATOR_REGISTER.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("RegisterValidator payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        TransactionType::ExitValidator => {
            // No payload — selector alone signals voluntary exit.
            (0, SELECTOR_VALIDATOR_EXIT.to_vec(), VmType::Tenzro)
        }
        TransactionType::UpdateValidatorMetadata { metadata_uri, tee_attestation_hash } => {
            #[derive(serde::Serialize)]
            struct ValidatorUpdateMetadataPayload<'a> {
                #[serde(skip_serializing_if = "Option::is_none")]
                metadata_uri: Option<&'a str>,
                /// 32-byte SHA-256 commitment (raw bytes), serialized as a
                /// JSON array — matches the VM-side `Vec<u8>` field.
                #[serde(skip_serializing_if = "Option::is_none")]
                tee_attestation_hash: Option<&'a [u8]>,
            }
            let payload = ValidatorUpdateMetadataPayload {
                metadata_uri: metadata_uri.as_deref(),
                tee_attestation_hash: tee_attestation_hash.as_ref().map(|h| h.as_slice()),
            };
            let mut data = SELECTOR_VALIDATOR_UPDATE_METADATA.to_vec();
            data.extend_from_slice(
                &serde_json::to_vec(&payload)
                    .expect("UpdateValidatorMetadata payload is JSON-safe"),
            );
            (0, data, VmType::Tenzro)
        }
        // All other Tenzro-native transaction types (agents, models, staking, TEE)
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

    // Carry the canonical signing digest (Transaction::hash()) so the runtime
    // verifies against the same preimage the admission boundary verified
    // against, rather than recomputing a different hash from VmTransaction
    // fields.
    vm_tx.signing_digest = Some(signed_tx.transaction.hash().as_bytes().to_vec());

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
    fn weak_subjectivity_disabled_accepts_any_root() {
        // No anchor configured — every height/root passes.
        let root = Hash::new([7u8; 32]);
        assert!(
            EventLoop::check_weak_subjectivity_anchor(None, 100, root).is_ok()
        );
    }

    #[test]
    fn weak_subjectivity_ignores_non_anchor_heights() {
        let anchor = Some((100u64, Hash::new([1u8; 32])));
        // At a height other than the anchor, the committed root is not pinned,
        // even a mismatching one.
        let other_root = Hash::new([2u8; 32]);
        assert!(
            EventLoop::check_weak_subjectivity_anchor(anchor, 99, other_root)
                .is_ok()
        );
        assert!(
            EventLoop::check_weak_subjectivity_anchor(anchor, 101, other_root)
                .is_ok()
        );
    }

    #[test]
    fn weak_subjectivity_accepts_matching_root_at_anchor() {
        let root = Hash::new([1u8; 32]);
        let anchor = Some((100u64, root));
        assert!(
            EventLoop::check_weak_subjectivity_anchor(anchor, 100, root).is_ok()
        );
    }

    #[test]
    fn weak_subjectivity_rejects_forked_root_at_anchor() {
        let anchor = Some((100u64, Hash::new([1u8; 32])));
        let forked_root = Hash::new([9u8; 32]);
        // A block at the anchor height whose committed root differs is a
        // long-range fork and must be rejected.
        assert!(
            EventLoop::check_weak_subjectivity_anchor(anchor, 100, forked_root)
                .is_err()
        );
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

    // ---- Spec 9 AgentBond log decoders + reflection scan -----------------

    /// Encode a `BondPosted` / `BondIncreased` / `BondWithdrawInitiated`
    /// log payload using the same byte layout as the VM emit site.
    /// Lives in the test module so the round-trip test cannot accidentally
    /// drift with the VM-side helper.
    fn encode_bond_lifecycle_log(
        agent_did: &str,
        controller_did: &str,
        amount: u128,
        op_tag: u8,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + agent_did.len() + 4 + controller_did.len() + 16 + 1);
        out.extend_from_slice(&(agent_did.len() as u32).to_le_bytes());
        out.extend_from_slice(agent_did.as_bytes());
        out.extend_from_slice(&(controller_did.len() as u32).to_le_bytes());
        out.extend_from_slice(controller_did.as_bytes());
        out.extend_from_slice(&amount.to_le_bytes());
        out.push(op_tag);
        out
    }

    /// Encode a `BondSlashed` log payload using the same byte layout as
    /// the VM emit site (`execute_terminate_agent` slash branch).
    fn encode_bond_slashed_log(
        agent_did: &str,
        controller_did: &str,
        slashed_amount: u128,
        bps: u16,
        terminal: bool,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            4 + agent_did.len() + 4 + controller_did.len() + 16 + 2 + 1,
        );
        out.extend_from_slice(&(agent_did.len() as u32).to_le_bytes());
        out.extend_from_slice(agent_did.as_bytes());
        out.extend_from_slice(&(controller_did.len() as u32).to_le_bytes());
        out.extend_from_slice(controller_did.as_bytes());
        out.extend_from_slice(&slashed_amount.to_le_bytes());
        out.extend_from_slice(&bps.to_le_bytes());
        out.push(if terminal { 1 } else { 0 });
        out
    }

    /// Encode an `InsuranceClaimPaid` log payload using the same byte
    /// layout as the VM emit site (`execute_pay_insurance_claim`).
    fn encode_insurance_claim_paid_log(
        claim_id_hex: &str,
        claimant: &[u8; 32],
        amount: u128,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + claim_id_hex.len() + 32 + 16);
        out.extend_from_slice(&(claim_id_hex.len() as u32).to_le_bytes());
        out.extend_from_slice(claim_id_hex.as_bytes());
        out.extend_from_slice(claimant);
        out.extend_from_slice(&amount.to_le_bytes());
        out
    }

    #[test]
    fn bond_lifecycle_log_decoder_roundtrip() {
        let encoded = encode_bond_lifecycle_log(
            "did:tenzro:machine:abc",
            "did:tenzro:human:owner",
            1_000_000_000_000_000_000,
            0,
        );
        let (agent, controller, amount, op_tag) =
            decode_bond_lifecycle_log(&encoded).expect("decode");
        assert_eq!(agent, "did:tenzro:machine:abc");
        assert_eq!(controller, "did:tenzro:human:owner");
        assert_eq!(amount, 1_000_000_000_000_000_000);
        assert_eq!(op_tag, 0);

        // op_tag=2 (WithdrawInitiated) round-trips too
        let encoded2 = encode_bond_lifecycle_log("a", "b", 1, 2);
        let (_, _, _, op_tag2) = decode_bond_lifecycle_log(&encoded2).unwrap();
        assert_eq!(op_tag2, 2);

        // Truncated payload returns None instead of panicking
        assert!(decode_bond_lifecycle_log(&encoded[..encoded.len() - 5]).is_none());
        assert!(decode_bond_lifecycle_log(&[]).is_none());
    }

    #[test]
    fn bond_slashed_log_decoder_roundtrip() {
        let encoded = encode_bond_slashed_log(
            "did:tenzro:machine:slashed",
            "did:tenzro:human:ctrl",
            42_000_000,
            500,
            true,
        );
        let (agent, controller, slashed, bps, terminal) =
            decode_bond_slashed_log(&encoded).expect("decode");
        assert_eq!(agent, "did:tenzro:machine:slashed");
        assert_eq!(controller, "did:tenzro:human:ctrl");
        assert_eq!(slashed, 42_000_000);
        assert_eq!(bps, 500);
        assert!(terminal);

        let encoded_nonterm =
            encode_bond_slashed_log("a", "b", 1, 1, false);
        let (_, _, _, _, terminal2) = decode_bond_slashed_log(&encoded_nonterm).unwrap();
        assert!(!terminal2);

        assert!(decode_bond_slashed_log(&encoded[..3]).is_none());
    }

    #[test]
    fn insurance_claim_paid_log_decoder_roundtrip() {
        let claimant_addr = [9u8; 32];
        let encoded = encode_insurance_claim_paid_log(
            "deadbeef",
            &claimant_addr,
            7_000_000_000,
        );
        let (claim_id, recovered_claimant, amount) =
            decode_insurance_claim_paid_log(&encoded).expect("decode");
        assert_eq!(claim_id, "deadbeef");
        assert_eq!(recovered_claimant, claimant_addr);
        assert_eq!(amount, 7_000_000_000);

        assert!(decode_insurance_claim_paid_log(&encoded[..2]).is_none());
    }

    /// Build a minimal `EventLoop` with only the storage + VM runtime
    /// wired (no consensus/network), suitable for exercising the
    /// `process_bond_logs` reflection path in isolation.
    async fn make_event_loop_with_bond_manager(
        bond_manager: Arc<BondManager>,
    ) -> EventLoop {
        use tenzro_vm::VmConfig;

        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(RocksDbStore::open_default(dir.path()).unwrap());
        let vm_runtime = Arc::new(MultiVmRuntime::new(VmConfig::default()).await.unwrap());
        let chain_tip = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let metrics = Arc::new(MetricsCollector::new());
        EventLoop::new(storage, vm_runtime, None, None, chain_tip, metrics)
            .with_bond_manager(bond_manager)
    }

    fn synth_bond_log(topic: &[u8], data: Vec<u8>) -> tenzro_vm::Log {
        tenzro_vm::Log::new(vec![0u8; 32], vec![topic.to_vec()], data)
    }

    #[tokio::test]
    async fn process_bond_logs_reflects_post_increase_withdraw() {
        let bond_manager = Arc::new(BondManager::new());
        let event_loop = make_event_loop_with_bond_manager(bond_manager.clone()).await;

        let agent = "did:tenzro:machine:lifecycle";
        let controller = "did:tenzro:human:ctrl";

        // BondPosted (op=0)
        let post_log = synth_bond_log(
            b"BondPosted",
            encode_bond_lifecycle_log(agent, controller, 5_000, 0),
        );
        let result = tenzro_vm::ExecutionResult::success(0, vec![], vec![post_log], vec![]);
        event_loop.process_bond_logs(&result, BlockHeight::from(10)).await;

        let bond = bond_manager.get(agent).expect("bond exists");
        assert_eq!(bond.amount, 5_000);
        assert_eq!(bond.controller_did, controller);
        assert!(matches!(
            bond.state,
            tenzro_token::bond::BondLifecycle::Active
        ));

        // BondIncreased (op=1) — top up by 2_000
        let inc_log = synth_bond_log(
            b"BondIncreased",
            encode_bond_lifecycle_log(agent, controller, 2_000, 1),
        );
        let result = tenzro_vm::ExecutionResult::success(0, vec![], vec![inc_log], vec![]);
        event_loop.process_bond_logs(&result, BlockHeight::from(11)).await;

        let bond = bond_manager.get(agent).expect("bond exists");
        assert_eq!(bond.amount, 7_000);
        assert!(matches!(
            bond.state,
            tenzro_token::bond::BondLifecycle::Active
        ));

        // BondWithdrawInitiated (op=2) — moves to Cooldown
        let withdraw_log = synth_bond_log(
            b"BondWithdrawInitiated",
            encode_bond_lifecycle_log(agent, controller, 7_000, 2),
        );
        let result =
            tenzro_vm::ExecutionResult::success(0, vec![], vec![withdraw_log], vec![]);
        event_loop.process_bond_logs(&result, BlockHeight::from(12)).await;

        let bond = bond_manager.get(agent).expect("bond exists");
        assert!(matches!(
            bond.state,
            tenzro_token::bond::BondLifecycle::Cooldown
        ));
        assert!(bond.cooldown_until.is_some());
    }

    #[tokio::test]
    async fn process_bond_logs_reflects_slash_into_manager_state() {
        let bond_manager = Arc::new(BondManager::new());
        let event_loop = make_event_loop_with_bond_manager(bond_manager.clone()).await;

        let agent = "did:tenzro:machine:slashvictim";
        let controller = "did:tenzro:human:ctrl";

        // Seed an active bond well above `DEFAULT_MIN_RESIDUAL` (10 TNZO =
        // 10 * 10^18 base units). A 10 % slash must still leave the bond
        // above the residual floor so the slash stays non-terminal.
        // 100 TNZO bond → 10 TNZO slashed → 90 TNZO remainder ≥ 10 TNZO floor.
        let bond_amount: u128 = 100 * 1_000_000_000_000_000_000;
        bond_manager.post(agent, controller, bond_amount, 100).expect("seed bond");

        // VM-driven slash: 1000 bps = 10%. The VM has already moved
        // funds; the log mirrors the math.
        let slashed_amount = bond_amount * 1000 / 10_000;

        let slash_log = synth_bond_log(
            b"BondSlashed",
            encode_bond_slashed_log(agent, controller, slashed_amount, 1000, false),
        );
        let result = tenzro_vm::ExecutionResult::success(0, vec![], vec![slash_log], vec![]);
        event_loop.process_bond_logs(&result, BlockHeight::from(20)).await;

        let bond = bond_manager.get(agent).expect("bond exists");
        assert_eq!(bond.amount, bond_amount - slashed_amount);
        // Non-terminal slash leaves the bond Active in BondManager state.
        assert!(matches!(
            bond.state,
            tenzro_token::bond::BondLifecycle::Active
        ));
    }

    #[tokio::test]
    async fn process_bond_logs_reflects_insurance_claim_paid() {
        use tenzro_types::primitives::Address;

        let bond_manager = Arc::new(BondManager::new());
        let event_loop = make_event_loop_with_bond_manager(bond_manager.clone()).await;

        // Seed the pool from a slash so there's something to pay out.
        let agent = "did:tenzro:machine:claimcase";
        let controller = "did:tenzro:human:ctrl";
        bond_manager
            .post(agent, controller, 1_000_000, 100)
            .expect("seed bond");
        bond_manager
            .slash(agent, 1000, None, "InsurancePool", 101)
            .expect("seed pool via slash");

        // File + approve the claim so it's in Approved state.
        let claimant = Address::new([5u8; 32]);
        let claim = bond_manager
            .file_claim(
                "did:tenzro:human:claimant",
                claimant,
                agent,
                10_000,
                vec![],
                None,
                42,
            )
            .expect("file claim");
        bond_manager
            .approve_claim(&claim.claim_id, 10_000, "gov:proposal:1".to_string())
            .expect("approve");

        // Now reflect the VM-emitted InsuranceClaimPaid log.
        let mut claimant_bytes = [0u8; 32];
        claimant_bytes.copy_from_slice(claimant.as_bytes());
        let paid_log = synth_bond_log(
            b"InsuranceClaimPaid",
            encode_insurance_claim_paid_log(&claim.claim_id, &claimant_bytes, 10_000),
        );
        let result = tenzro_vm::ExecutionResult::success(0, vec![], vec![paid_log], vec![]);
        event_loop.process_bond_logs(&result, BlockHeight::from(30)).await;

        let updated = bond_manager
            .get_claim(&claim.claim_id)
            .expect("claim exists");
        assert!(matches!(
            updated.status,
            tenzro_token::bond::ClaimStatus::Paid
        ));
    }

    #[tokio::test]
    async fn process_bond_logs_no_op_when_manager_unwired() {
        // EventLoop without bond_manager: the early-exit path must not panic
        // even when relevant logs are present. The scan should observe and
        // log at debug, but BondManager state simply never updates because
        // there is no manager.
        use tenzro_vm::VmConfig;

        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(RocksDbStore::open_default(dir.path()).unwrap());
        let vm_runtime = Arc::new(MultiVmRuntime::new(VmConfig::default()).await.unwrap());
        let chain_tip = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let metrics = Arc::new(MetricsCollector::new());
        let event_loop =
            EventLoop::new(storage, vm_runtime, None, None, chain_tip, metrics);

        let log = synth_bond_log(
            b"BondPosted",
            encode_bond_lifecycle_log("a", "b", 1, 0),
        );
        let result = tenzro_vm::ExecutionResult::success(0, vec![], vec![log], vec![]);
        event_loop.process_bond_logs(&result, BlockHeight::from(1)).await;
        // No assertion needed — test passes if no panic.
    }

    #[tokio::test]
    async fn process_bond_logs_skips_unrelated_topics() {
        let bond_manager = Arc::new(BondManager::new());
        let event_loop = make_event_loop_with_bond_manager(bond_manager.clone()).await;

        // A log whose topic isn't a bond event must be silently ignored
        // (the early-exit `any_bond` check skips the whole loop).
        let unrelated = synth_bond_log(b"KillSwitchPause", vec![1, 2, 3, 4]);
        let result = tenzro_vm::ExecutionResult::success(0, vec![], vec![unrelated], vec![]);
        event_loop.process_bond_logs(&result, BlockHeight::from(1)).await;

        // Confirm BondManager is untouched.
        assert!(bond_manager.get("anything").is_none());
    }
}
