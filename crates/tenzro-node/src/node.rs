//! Core Tenzro Network node implementation

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use tenzro_agent::{AgentRuntime, SwarmManager};
use tenzro_bridge::BridgeRouter;
use tenzro_bridge::chainlink_ccip::{ChainlinkCcipAdapter, CcipConfig, FeeToken};
use tenzro_bridge::debridge::{DeBridgeAdapter, DeBridgeConfig};
use tenzro_bridge::layerzero::{LayerZeroAdapter, LayerZeroConfig};
use tenzro_bridge::evm_signer::EvmSignerConfig;
use tenzro_consensus::{
    open_default_file_store, ConsensusEngine, ConsensusOutMessage, EquivocationEvidence,
    EpochManager, HotStuff2Engine, SlashingCallback, ValidatorInfo,
};
use tenzro_crypto::{KeyPair, KeyType};
use tenzro_identity::IdentityRegistry;
use tenzro_model::{
    AudioRuntime, DetectionRuntime, HfDownloader, InferenceRouter, ModelRegistry, ModelRuntime,
    ProviderManager, SegmentationRuntime, TextEmbeddingRuntime, TimeseriesRuntime, VideoRuntime,
    VisionRuntime,
};
use tenzro_network::{MessagePayload, NetworkMessage, NetworkService, TenzroNetworkService};
use tenzro_payments::gateway::TenzroPaymentGateway;
use tenzro_payments::mpp::server::MppPaymentServer;
use tenzro_payments::traits::PaymentGateway as PaymentGatewayTrait;
use tenzro_payments::x402::server::X402PaymentServer;
use tenzro_settlement::{
    BatchProcessor, ChannelManager, EscrowManager, FeeCollector, RocksDbChannelStorage,
    SettlementConfig, SettlementEngine,
};
use tenzro_storage::{KvStore, RocksDbStore, StorageConfig, CF_MODELS, CF_SKILLS, CF_TOOLS, CF_AGENT_TEMPLATES, CF_MODEL_SERVICES};
use tenzro_tee::{detect_tee, TeeProvider, TeeRegistry};
use tenzro_token::{TnzoToken, StakingManager, GovernanceEngine, NetworkTreasury, TokenRegistry};
use tenzro_types::{primitives::Address, NetworkRole};
use tenzro_types::block::Block;
use tenzro_types::model::{ModelServiceInstance, ModelLocation, ServiceStatus};
use tenzro_vm::{eip1559::FeeMarket, MultiVmRuntime, VmConfig};
use tenzro_wallet::TenzroWalletService;

use crate::config::NodeConfig;
use crate::error::{NodeError, Result};
use crate::event_loop::{EventLoop, NodeBlockProvider, NodeEvent, NodeStateRootProvider};
use crate::health::HealthMonitor;
use crate::metrics::MetricsCollector;

use dashmap::DashMap;
use sha2::{Digest, Sha256};

/// Bridges the consensus layer's `SlashingCallback` trait to the token layer's `StakingManager`.
///
/// When the consensus engine detects equivocation (a validator voting for conflicting blocks
/// in the same view), it invokes this callback to slash the misbehaving validator's stake.
/// The default slash amount is 10% of the validator's total stake.
pub struct StakingSlashingCallback {
    staking: Arc<StakingManager>,
}

impl StakingSlashingCallback {
    pub fn new(staking: Arc<StakingManager>) -> Self {
        Self { staking }
    }
}

impl SlashingCallback for StakingSlashingCallback {
    fn report_equivocation(
        &self,
        validator: &Address,
        view: u64,
        evidence: &EquivocationEvidence,
    ) {
        // Slash 10% of the validator's stake for equivocation
        let slash_amount = self.staking.get_stake(validator)
            .map(|info| info.amount / 10)
            .unwrap_or(0);

        if slash_amount == 0 {
            tracing::warn!(
                validator = %validator,
                view = view,
                "Equivocation detected but validator has no stake to slash"
            );
            return;
        }

        let reason = format!(
            "Equivocation in view {}: voted for blocks {} and {}",
            view,
            evidence.vote1.block_hash,
            evidence.vote2.block_hash,
        );

        match self.staking.slash(validator, slash_amount, reason, Address::default()) {
            Ok(()) => {
                tracing::warn!(
                    validator = %validator,
                    view = view,
                    slash_amount = slash_amount,
                    "Slashed validator for equivocation"
                );
            }
            Err(e) => {
                tracing::error!(
                    validator = %validator,
                    view = view,
                    error = %e,
                    "Failed to slash validator for equivocation"
                );
            }
        }
    }
}

/// Node-level validator registry that implements the network's ValidatorRegistry trait.
///
/// This registry maintains a mapping of PeerIds to validator status. Validators are
/// registered when the node starts (for the local validator) and when peers identify
/// themselves as validators via the identify protocol. In single-node / testnet mode,
/// the local validator PeerId is automatically registered.
///
/// The registry is designed to be dynamically updated as the validator set changes
/// across epochs.
pub struct NodeValidatorRegistry {
    /// Set of PeerIds known to be active validators
    validator_peers: DashMap<libp2p::PeerId, ()>,
}

impl Default for NodeValidatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeValidatorRegistry {
    /// Creates a new empty validator registry
    pub fn new() -> Self {
        Self {
            validator_peers: DashMap::new(),
        }
    }

    /// Registers a PeerId as a known validator
    pub fn add_validator(&self, peer_id: libp2p::PeerId) {
        self.validator_peers.insert(peer_id, ());
        tracing::info!(peer = %peer_id, "Registered validator peer");
    }

    /// Removes a PeerId from the validator set (e.g., on epoch change or slashing)
    #[allow(dead_code)]
    pub fn remove_validator(&self, peer_id: &libp2p::PeerId) {
        self.validator_peers.remove(peer_id);
        tracing::info!(peer = %peer_id, "Removed validator peer");
    }
}

impl tenzro_network::ValidatorRegistry for NodeValidatorRegistry {
    fn is_validator(&self, peer_id: &libp2p::PeerId) -> bool {
        self.validator_peers.contains_key(peer_id)
    }

    fn validator_peer_ids(&self) -> std::collections::HashSet<libp2p::PeerId> {
        self.validator_peers.iter().map(|entry| *entry.key()).collect()
    }

    /// Dynamically admit a peer as a validator after it has completed a Tenzro
    /// identify handshake. This closes the "mutual ban" gap where peers that
    /// come online after the static boot-node list was wired would never be
    /// admitted to validator topics (consensus / attestations), resulting in
    /// their messages being rejected and their gossipsub peer-score decaying
    /// below the graylist threshold.
    ///
    /// The network layer only calls this after verifying the peer's protocol
    /// prefix matches `"tenzro/"`, so any admitted peer is at minimum a Tenzro
    /// node. On epoch rotation the full validator set can still be re-synced
    /// from on-chain stake state.
    fn try_add_validator(&self, peer_id: &libp2p::PeerId) {
        if !self.validator_peers.contains_key(peer_id) {
            self.validator_peers.insert(*peer_id, ());
            tracing::info!(
                peer = %peer_id,
                "Dynamically registered validator peer via identify"
            );
        }
    }
}

/// Bridges the payment gateway's `SettlementCallback` to the TNZO token layer and
/// settlement engine, so that protocol-level settlements (MPP, x402, Visa TAP, etc.)
/// are reflected on-chain via `TnzoToken::transfer()` and logged through the
/// `SettlementEngine`.
pub struct TnzoSettlementCallback {
    token: Arc<TnzoToken>,
    settlement_engine: Arc<SettlementEngine>,
}

impl TnzoSettlementCallback {
    pub fn new(token: Arc<TnzoToken>, settlement_engine: Arc<SettlementEngine>) -> Self {
        Self {
            token,
            settlement_engine,
        }
    }
}

#[async_trait::async_trait]
impl tenzro_payments::gateway::SettlementCallback for TnzoSettlementCallback {
    async fn settle_on_chain(
        &self,
        payer: &[u8],
        payee: &[u8],
        amount: u128,
        asset: &str,
        receipt_id: &str,
    ) -> std::result::Result<String, tenzro_payments::PaymentError> {
        // Convert byte slices to 32-byte Address
        let payer_addr = bytes_to_address(payer);
        let payee_addr = bytes_to_address(payee);

        // Only settle TNZO natively; other assets are recorded but not transferred
        if asset == "TNZO" || asset == "tnzo" {
            self.token
                .transfer(&payer_addr, &payee_addr, amount)
                .map_err(|e| {
                    tenzro_payments::PaymentError::SettlementError(format!(
                        "TNZO transfer failed: {}",
                        e
                    ))
                })?;
        }

        // Record in the settlement engine for auditing
        use tenzro_types::settlement::{
            ProofType, ServiceProof, ServiceType, SettlementRequest,
        };
        let proof = ServiceProof::new(ProofType::Cryptographic, receipt_id.as_bytes().to_vec());
        let request = SettlementRequest::new(
            payee_addr,
            payer_addr,
            ServiceType::HttpPayment {
                protocol: asset.to_string(),
                resource: receipt_id.to_string(),
            },
            // SettlementRequest.amount is u64; clamp to u64::MAX for very large values
            amount.min(u64::MAX as u128) as u64,
            proof,
        );

        match self.settlement_engine.settle(request).await {
            Ok(receipt) => {
                info!(
                    "On-chain settlement recorded: receipt_id={}, settlement_receipt={}",
                    receipt_id, receipt.receipt_id
                );
                Ok(receipt.receipt_id)
            }
            Err(e) => {
                // The TNZO transfer already succeeded; log the settlement-engine
                // recording failure but still return success with a synthetic ref
                warn!(
                    "Settlement engine recording failed (TNZO transfer succeeded): {}",
                    e
                );
                Ok(format!("transfer-only:{}", receipt_id))
            }
        }
    }
}

/// Helper: convert a variable-length byte slice to a 32-byte `Address`.
/// Left-pads with zeros if shorter, truncates from the right if longer.
fn bytes_to_address(bytes: &[u8]) -> Address {
    let mut buf = [0u8; 32];
    let len = bytes.len().min(32);
    // Right-align the bytes (zero-pad on the left)
    buf[32 - len..].copy_from_slice(&bytes[..len]);
    Address(buf)
}

/// Build a `ModelInfo` record describing a Cortex recurrent-depth worker so
/// it can be published in the shared `ModelRegistry` catalog. Pricing is
/// mapped from the worker's `CortexPricing` (per-input/per-output tokens)
/// and Cortex-specific parameters (`price_per_loop`, `base_request_fee`,
/// tiers, max_loops) are stashed in `metadata` for discovery clients.
pub(crate) fn cortex_model_info(
    model_id: &str,
    worker: &Arc<tenzro_cortex::CortexWorker>,
    arch_label: &str,
) -> tenzro_types::model::ModelInfo {
    use tenzro_types::model::{
        ModelInfo, ModelModality, ModelParameters, ModelStatus, MoeMetadata,
        MoeRoutingStrategy, PricingConfig, PricingModel,
    };

    let pricing = worker.pricing();
    let family = worker.backend().family();

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("tier".to_string(), "cortex".to_string());
    metadata.insert("arch".to_string(), arch_label.to_string());
    metadata.insert("max_loops".to_string(), family.max_loops.to_string());
    metadata.insert("moe_experts".to_string(), family.moe_experts.to_string());
    metadata.insert(
        "experts_per_token".to_string(),
        family.experts_per_token.to_string(),
    );
    metadata.insert("attn_type".to_string(), family.attn_type.clone());
    metadata.insert(
        "price_per_loop".to_string(),
        pricing.price_per_loop.to_string(),
    );
    metadata.insert(
        "base_request_fee".to_string(),
        pricing.base_request_fee.to_string(),
    );
    metadata.insert("tee_premium".to_string(), pricing.tee_premium.to_string());
    metadata.insert("zk_premium".to_string(), pricing.zk_premium.to_string());
    metadata.insert(
        "worker_did".to_string(),
        worker.worker_did().to_string(),
    );

    let mut info = ModelInfo::new(
        model_id.to_string(),
        format!("Tenzro Cortex — {}", model_id),
        "0.1.0".to_string(),
        ModelModality::Text,
        worker.worker_address(),
    );
    info.description = format!(
        "Recurrent-depth reasoning worker (arch={}, max_loops={}).",
        arch_label, family.max_loops
    );
    info.architecture = arch_label.to_string();
    info.parameters = ModelParameters {
        parameter_count: None,
        context_window: 8192,
        max_output_tokens: 4096,
        input_formats: vec!["text".to_string()],
        output_formats: vec!["text".to_string()],
        capabilities: vec![
            "reasoning".to_string(),
            "recurrent-depth".to_string(),
            "cortex".to_string(),
        ],
    };
    info.pricing = PricingConfig {
        price_per_input_token: pricing.price_per_input_token,
        price_per_output_token: pricing.price_per_output_token,
        minimum_price: pricing.base_request_fee,
        pricing_model: PricingModel::PerToken,
    };
    info.status = ModelStatus::Active;
    info.metadata = metadata;
    if family.moe_experts > 0 && family.experts_per_token > 0 {
        let mut moe = MoeMetadata::new(
            family.moe_experts,
            family.experts_per_token as u8,
            MoeRoutingStrategy::TopK,
        );
        if !family.attn_type.is_empty() {
            moe = moe.with_attention_type(family.attn_type.clone());
        }
        info.moe = Some(moe);
    }
    info
}

/// GPU information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub name: String,
    pub vram_gb: f64,
}

/// Hardware profile detected from the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub cpu_threads: usize,
    pub total_ram_gb: f64,
    pub gpus: Vec<GpuInfo>,
    pub storage_available_gb: f64,
    pub tee_available: bool,
    pub tee_vendor: Option<String>,
    pub os: String,
    pub arch: String,
    pub device_fingerprint: String,
}

/// Provider scheduling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSchedule {
    pub enabled: bool,
    pub start_hour: u8,
    pub end_hour: u8,
    pub timezone: String,
    pub days_of_week: [bool; 7], // Mon-Sun
}

impl Default for ProviderSchedule {
    fn default() -> Self {
        Self {
            enabled: false,
            start_hour: 0,
            end_hour: 24,
            timezone: "UTC".to_string(),
            days_of_week: [true; 7],
        }
    }
}

/// Provider pricing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderPricing {
    pub input_price_per_token: f64,  // TNZO
    pub output_price_per_token: f64, // TNZO
    pub network_max_input: f64,      // enforced max
    pub network_max_output: f64,     // enforced max
}

impl Default for ProviderPricing {
    fn default() -> Self {
        Self {
            input_price_per_token: 0.0001,
            output_price_per_token: 0.0002,
            network_max_input: 0.001,
            network_max_output: 0.002,
        }
    }
}

/// Model download status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDownloadStatus {
    pub model_id: String,
    pub status: String, // "downloading", "completed", "failed", "not_started"
    pub progress_percent: f64,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// User resource tracking (models being used from providers)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResource {
    pub resource_type: String,
    pub resource_id: String,
    pub added_at: u64,
}

/// Transaction history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHistoryEntry {
    pub tx_hash: String,
    pub from: String,
    pub to: String,
    pub amount: String,
    pub asset: String,
    pub status: String,
    pub timestamp: u64,
    pub tx_type: String,
}

/// A model discovered via gossipsub from a remote provider.
/// Entries expire if not refreshed within `ttl_secs`.
#[derive(Debug, Clone)]
pub struct NetworkModelEntry {
    pub registration: tenzro_network::ModelRegistrationMessage,
    pub last_seen: std::time::Instant,
}

/// An agent discovered via gossipsub from a remote node.
/// Entries expire if not refreshed within `ttl_secs`.
#[derive(Debug, Clone)]
pub struct NetworkAgentEntry {
    pub announcement: tenzro_network::AgentAnnouncementMessage,
    pub last_seen: std::time::Instant,
}

/// A provider discovered via gossipsub from a remote node.
/// Entries expire if not refreshed within `ttl_secs`.
#[derive(Debug, Clone)]
pub struct NetworkProviderEntry {
    pub announcement: tenzro_network::ProviderAnnouncementMessage,
    pub last_seen: std::time::Instant,
}

/// Main Tenzro Network node
pub struct TenzroNode {
    config: NodeConfig,
    pub(crate) state: Arc<RwLock<NodeState>>,

    // Core infrastructure
    storage: Option<Arc<RocksDbStore>>,
    network: Option<Arc<TenzroNetworkService>>,

    // Consensus (validators only)
    consensus: Option<Arc<HotStuff2Engine>>,
    /// Outbound consensus messages (votes, proposals) from HotStuff-2 engine.
    /// Consumed once by `init_event_loop()` and wired into the event loop for
    /// gossipsub broadcast.  `None` when consensus is not running on this node.
    consensus_out_rx: Option<tokio::sync::mpsc::UnboundedReceiver<ConsensusOutMessage>>,
    /// Local validator address (32-byte, derived from the node's Ed25519
    /// keypair). Captured at `init_consensus()` time and used by the inbound
    /// consensus gossipsub bridge to skip self-broadcasts — without this
    /// filter, every validator would re-feed its own proposal/vote back into
    /// the engine on the gossipsub echo, causing duplicate votes and
    /// redundant `on_proposal()` invocations.
    local_validator_address: Option<Address>,

    // Execution layer
    vm_runtime: Option<Arc<MultiVmRuntime>>,

    // Services
    wallet_service: Option<Arc<TenzroWalletService>>,
    token: Option<Arc<TnzoToken>>,
    staking: Option<Arc<StakingManager>>,
    governance: Option<Arc<GovernanceEngine>>,
    treasury: Option<Arc<NetworkTreasury>>,
    settlement: Option<Arc<SettlementEngine>>,
    channel_manager: Option<Arc<ChannelManager>>,
    escrow_manager: Option<Arc<EscrowManager>>,
    batch_processor: Option<Arc<BatchProcessor>>,
    fee_collector: Option<Arc<FeeCollector>>,

    /// OAuth 2.1 + DPoP + RAR auth engine. Replaces the legacy
    /// `OnboardingKey` flow. See `tenzro_auth::AuthEngine` for the
    /// trust model and storage layout (CF_AUDIT, CF_APPROVALS).
    auth_engine: Option<Arc<tenzro_auth::AuthEngine>>,

    // AI infrastructure
    model_registry: Option<Arc<ModelRegistry>>,
    provider_manager: Option<Arc<ProviderManager>>,
    inference_router: Option<Arc<InferenceRouter>>,
    /// Usage tracker — recipient of every successful inference's
    /// `UsageRecord`. Persists per-model / per-provider / global stats
    /// to RocksDB CF_MODELS via `UsageTracker::with_storage`. Read by
    /// the `tenzro_listInferenceUsage` RPC.
    usage_tracker: Option<Arc<tenzro_model::UsageTracker>>,
    /// EU AI Act Art. 50(2) provenance store. Populated by the inference
    /// router (writer) and queried by the `tenzro_getProvenance` RPC
    /// (reader). Shared via `Arc` so both producer and consumer see the
    /// same SHA-256-keyed manifest cache.
    provenance_store: Option<Arc<tenzro_model::ProvenanceStore>>,
    agent_runtime: Option<Arc<AgentRuntime>>,
    swarm_manager: Option<Arc<SwarmManager>>,

    // Background liveness sweeper — periodically marks silent skills/tools/
    // templates/tasks/sessions/services as Inactive and purges old terminal
    // rows. Held here so its `Drop` aborts the task on node shutdown.
    liveness_sweeper: Option<crate::liveness::LivenessSweeper>,

    // HuggingFace model integration
    pub hf_downloader: Option<Arc<HfDownloader>>,
    pub model_runtime: Option<Arc<ModelRuntime>>,

    // ONNX-backed runtimes (timeseries forecasting, vision encoders).
    // Default-built nodes carry stub runtimes that error cleanly on use;
    // ONNX-built nodes (cargo --features tenzro-model/onnx) get real ORT
    // sessions through the same handles.
    pub timeseries_runtime: Arc<TimeseriesRuntime>,
    pub vision_runtime: Arc<VisionRuntime>,
    pub text_embedding_runtime: Arc<TextEmbeddingRuntime>,
    pub segmentation_runtime: Arc<SegmentationRuntime>,
    pub detection_runtime: Arc<DetectionRuntime>,
    pub audio_runtime: Arc<AudioRuntime>,
    pub video_runtime: Arc<VideoRuntime>,

    /// Tenzro Train runtime — protocol layer for decentralized training
    /// (see `tenzro_training::TrainingRuntime`). Wired with write-through
    /// persistence to CF_TRAINING_RUNS / CF_TRAINING_RECEIPTS once storage
    /// is available.
    pub training_runtime: Arc<tenzro_training::TrainingRuntime>,

    // Identity & Payments (TDIP + MPP/x402)
    identity_registry: Option<Arc<IdentityRegistry>>,
    payment_gateway: Option<Arc<TenzroPaymentGateway>>,
    x402_server: Option<Arc<X402PaymentServer>>,

    // Agent Kit (registry-driven agent runtime)
    agent_kit: Option<Arc<tenzro_agent_kit::AgentKit>>,

    // Token registry (unified cross-VM token tracking)
    token_registry: Option<Arc<TokenRegistry>>,

    // Interoperability
    bridge_router: Option<Arc<BridgeRouter>>,

    // TEE (optional)
    #[allow(dead_code)]
    tee_provider: Option<Box<dyn TeeProvider>>,
    tee_registry: Option<Arc<TeeRegistry>>,

    /// On-chain registry of validator-attested Plonky3 proof commitments.
    ///
    /// Populated by the consensus / settlement / RPC verify paths after they
    /// successfully run the off-EVM Plonky3 verifier; consumed by the
    /// `PRECOMPILE_ZK_VERIFY` precompile in the EVM. See
    /// `tenzro_vm::precompiles::ZkCommitmentRegistry`.
    zk_commitment_registry: Arc<tenzro_vm::precompiles::ZkCommitmentRegistry>,

    /// ERC-8004 IdentityRegistry (precompile 0x101a). Populated by EVM calls
    /// to `registerAgent` and consumed by the agent runtime auto-mirror so
    /// every TDIP-registered agent gets a native on-chain ERC-8004 record.
    erc8004_identity: Option<Arc<tenzro_vm::Erc8004IdentityRegistry>>,

    /// ERC-8004 ReputationRegistry (precompile 0x101b).
    erc8004_reputation: Option<Arc<tenzro_vm::Erc8004ReputationRegistry>>,

    /// ERC-8004 ValidationRegistry (precompile 0x101c).
    erc8004_validation: Option<Arc<tenzro_vm::Erc8004ValidationRegistry>>,

    // Monitoring
    health_monitor: Arc<HealthMonitor>,
    metrics: Arc<MetricsCollector>,

    // Event loop
    event_loop_tx: Option<mpsc::Sender<NodeEvent>>,

    /// Live chain tip height — shared with EventLoop for lock-free RPC reads.
    ///
    /// The EventLoop updates this atomically on every finalized block (both local
    /// consensus blocks and gossipsub network blocks). RPC handlers read it with
    /// Acquire ordering so they always see the true chain tip without any storage I/O.
    ///
    /// This bypasses BlockStoreImpl::latest_height() which reads CF_METADATA and is
    /// subject to the `should_update = height > latest` guard that freezes metadata
    /// when a fresh chain starts at height 1 while CF_METADATA still holds a stale
    /// value from a prior run (e.g. 9998). The atomic is immune to this because it
    /// is always set unconditionally on every finalized block.
    chain_tip: Arc<AtomicU64>,

    /// Tracks the latest `StatusMessage` height advertised by each peer on
    /// `tenzro/status/1.0.0`. Consumed by `eth_syncing` / `tenzro_syncing` to
    /// report a real network-tip estimate (not just `local_tip`) so external
    /// clients can see when this node is lagging behind the network.
    ///
    /// Populated by the inbound status subscription wired in `init_event_loop`;
    /// queried by RPC handlers via `network_tip()`.
    pub(crate) peer_status: Arc<tenzro_network::PeerStatusTracker>,

    // Provider state
    pub provider_schedule: Arc<RwLock<ProviderSchedule>>,
    pub provider_pricing: Arc<RwLock<ProviderPricing>>,
    pub model_downloads: Arc<DashMap<String, ModelDownloadStatus>>,
    pub served_models: Arc<DashMap<String, bool>>,
    pub model_services: Arc<DashMap<String, ModelServiceInstance>>,
    pub load_tracker: Arc<tenzro_model::LoadTracker>,
    pub hardware_profile: Arc<RwLock<Option<HardwareProfile>>>,
    pub user_resources: Arc<DashMap<String, UserResource>>,
    pub transaction_history: Arc<RwLock<Vec<TransactionHistoryEntry>>>,
    pub runtime_role: Arc<RwLock<NetworkRole>>,
    /// OAuth state for onboarding key management (shared with MCP server)
    pub oauth_state: Arc<RwLock<Option<Arc<crate::mcp::oauth::OAuthState>>>>,
    /// Models discovered from gossipsub network announcements.
    /// Key: "{model_id}:{provider}" to allow multiple providers per model.
    pub network_models: Arc<DashMap<String, NetworkModelEntry>>,
    /// Agents discovered from gossipsub network announcements.
    /// Key: agent_id — last writer wins (most recent heartbeat).
    pub network_agents: Arc<DashMap<String, NetworkAgentEntry>>,
    /// Providers discovered from gossipsub network announcements.
    /// Key: peer_id — last writer wins (most recent heartbeat).
    pub network_providers: Arc<DashMap<String, NetworkProviderEntry>>,

    /// Cortex recurrent-depth workers, keyed by model_id.
    ///
    /// Each entry binds a recurrent-depth model backend (sidecar or mock) to
    /// pricing + receipt signing. Populated dynamically via
    /// `tenzro_registerCortexWorker` and consumed by `tenzro_cortexInference`.
    pub cortex_workers: Arc<DashMap<String, Arc<tenzro_cortex::CortexWorker>>>,

    /// In-memory registry of remote Cortex workers discovered via the
    /// `tenzro/cortex/1.0.0` gossipsub topic. The registry ingests signed
    /// `CortexAdvertisement` payloads, lazily evicts expired entries on
    /// snapshot, and is surfaced to clients via
    /// `tenzro_listRemoteCortexWorkers`.
    pub remote_cortex_workers: Arc<tenzro_cortex::RemoteWorkerRegistry>,

    /// Shared Cortex Prometheus metrics handle. Cloned into every local
    /// `CortexWorker` so per-request counters are aggregated across the
    /// whole node and exposed on the `/metrics` endpoint.
    pub cortex_metrics: tenzro_cortex::CortexMetrics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeState {
    Created,
    Starting,
    Running,
    Stopping,
    Stopped,
}

/// Load the validator's ML-DSA-65 post-quantum signing key from
/// `{data_dir}/validator_pq_key`, or generate and persist a new one if the
/// file does not exist.
///
/// The persisted file is exactly the 32-byte ML-DSA seed; the verifying key
/// (1952 bytes) is rederived deterministically. This pairs with the
/// classical Ed25519 keypair persisted at `validator_key` to form the
/// hybrid signing identity required by the consensus engine.
fn load_or_generate_validator_pq_key(
    data_dir: &std::path::Path,
) -> Result<tenzro_crypto::pq::MlDsaSigningKey> {
    use tenzro_crypto::pq::MlDsaSigningKey;
    let key_path = data_dir.join("validator_pq_key");
    if key_path.exists() {
        match std::fs::read(&key_path) {
            Ok(bytes) => match MlDsaSigningKey::from_seed(&bytes) {
                Ok(k) => {
                    info!(
                        "Loaded persistent validator PQ keypair from {}",
                        key_path.display()
                    );
                    return Ok(k);
                }
                Err(e) => {
                    warn!("Failed to decode validator PQ keypair: {} — generating new", e)
                }
            },
            Err(e) => {
                warn!("Failed to read validator PQ keypair: {} — generating new", e)
            }
        }
    }
    let key = MlDsaSigningKey::generate();
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Err(e) = std::fs::write(&key_path, key.seed_bytes()) {
        warn!("Failed to persist validator PQ keypair: {}", e);
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &key_path,
                std::fs::Permissions::from_mode(0o600),
            );
        }
        info!(
            "Generated and saved validator PQ keypair to {}",
            key_path.display()
        );
    }
    Ok(key)
}

/// Load the validator keypair from `{data_dir}/validator_key`, or generate and
/// persist a new one if the file does not exist.  Uses the same pattern as
/// `load_or_generate_keypair()` in tenzro-network/src/service.rs.
fn load_or_generate_validator_keypair(data_dir: &std::path::Path) -> Result<KeyPair> {
    let key_path = data_dir.join("validator_key");
    if key_path.exists() {
        match std::fs::read(&key_path) {
            Ok(bytes) => {
                match KeyPair::from_bytes(KeyType::Ed25519, &bytes) {
                    Ok(kp) => {
                        info!("Loaded persistent validator keypair from {}", key_path.display());
                        return Ok(kp);
                    }
                    Err(e) => warn!("Failed to decode validator keypair: {} — generating new", e),
                }
            }
            Err(e) => warn!("Failed to read validator keypair: {} — generating new", e),
        }
    }
    let keypair = KeyPair::generate(KeyType::Ed25519)
        .map_err(|e| NodeError::Other(format!("Crypto error: {}", e)))?;
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Err(e) = std::fs::write(&key_path, keypair.to_bytes()) {
        warn!("Failed to persist validator keypair: {}", e);
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &key_path,
                std::fs::Permissions::from_mode(0o600),
            );
        }
        info!("Generated and saved validator keypair to {}", key_path.display());
    }
    Ok(keypair)
}

impl TenzroNode {
    /// Create a new Tenzro Network node
    pub async fn new(config: NodeConfig) -> Result<Self> {
        info!("Initializing Tenzro Network node");
        info!("Role: {:?}", config.role);
        info!("Data directory: {:?}", config.data_dir);

        // Ensure directories exist
        config.ensure_data_dir()?;
        config.ensure_models_dir()?;

        // Initialize monitoring
        let health_monitor = Arc::new(HealthMonitor::new());
        let metrics = Arc::new(MetricsCollector::new());
        let initial_role = config.role;

        // Derive chain_id from genesis (default 1337 for local). Used by the
        // peer status tracker to drop StatusMessages from peers on a different
        // chain — prevents a misconfigured peer or cross-chain noise from
        // poisoning the network-tip estimate consumed by `eth_syncing`.
        let chain_id = config.genesis.as_ref().map(|g| g.chain_id).unwrap_or(1337);
        let peer_status = tenzro_network::PeerStatusTracker::new(chain_id);

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(NodeState::Created)),
            storage: None,
            network: None,
            consensus: None,
            consensus_out_rx: None,
            local_validator_address: None,
            vm_runtime: None,
            wallet_service: None,
            token: None,
            staking: None,
            governance: None,
            treasury: None,
            settlement: None,
            channel_manager: None,
            escrow_manager: None,
            batch_processor: None,
            fee_collector: None,
            auth_engine: None,
            model_registry: None,
            provider_manager: None,
            inference_router: None,
            usage_tracker: None,
            provenance_store: None,
            agent_runtime: None,
            swarm_manager: None,
            liveness_sweeper: None,
            hf_downloader: None,
            model_runtime: None,
            timeseries_runtime: Arc::new(TimeseriesRuntime::new()),
            vision_runtime: Arc::new(VisionRuntime::new()),
            text_embedding_runtime: Arc::new(TextEmbeddingRuntime::new()),
            segmentation_runtime: Arc::new(SegmentationRuntime::new()),
            detection_runtime: Arc::new(DetectionRuntime::new()),
            audio_runtime: Arc::new(AudioRuntime::new()),
            video_runtime: Arc::new(VideoRuntime::new()),
            training_runtime: Arc::new(tenzro_training::TrainingRuntime::new()),
            identity_registry: None,
            payment_gateway: None,
            x402_server: None,
            agent_kit: None,
            token_registry: None,
            bridge_router: None,
            tee_provider: None,
            tee_registry: None,
            zk_commitment_registry: Arc::new(tenzro_vm::precompiles::ZkCommitmentRegistry::new()),
            erc8004_identity: None,
            erc8004_reputation: None,
            erc8004_validation: None,
            health_monitor,
            metrics,
            event_loop_tx: None,
            chain_tip: Arc::new(AtomicU64::new(0)),
            peer_status,
            provider_schedule: Arc::new(RwLock::new(ProviderSchedule::default())),
            provider_pricing: Arc::new(RwLock::new(ProviderPricing::default())),
            model_downloads: Arc::new(DashMap::new()),
            served_models: Arc::new(DashMap::new()),
            model_services: Arc::new(DashMap::new()),
            load_tracker: Arc::new(tenzro_model::LoadTracker::new()),
            hardware_profile: Arc::new(RwLock::new(None)),
            user_resources: Arc::new(DashMap::new()),
            transaction_history: Arc::new(RwLock::new(Vec::new())),
            runtime_role: Arc::new(RwLock::new(initial_role)),
            oauth_state: Arc::new(RwLock::new(None)),
            network_models: Arc::new(DashMap::new()),
            network_agents: Arc::new(DashMap::new()),
            network_providers: Arc::new(DashMap::new()),
            cortex_workers: Arc::new(DashMap::new()),
            remote_cortex_workers: Arc::new(tenzro_cortex::RemoteWorkerRegistry::new()),
            cortex_metrics: tenzro_cortex::CortexMetrics::new(),
        })
    }

    /// Returns the live chain tip height maintained by the event loop.
    ///
    /// Reads the shared `Arc<AtomicU64>` that the event loop updates with
    /// `Ordering::Release` on every finalized block (both locally produced and
    /// gossipsub-received). This load uses `Ordering::Acquire` so all writes
    /// made before the store (block persistence, state commit) are visible.
    ///
    /// No storage I/O. Returns the actual current height regardless of whether
    /// CF_METADATA:latest_height is stale.
    pub fn chain_tip_height(&self) -> u64 {
        self.chain_tip.load(Ordering::Acquire)
    }

    /// Returns the maximum block height advertised by any fresh peer on
    /// `tenzro/status/1.0.0`, or `None` if no fresh peer status is recorded.
    ///
    /// "Fresh" = received within the last 60 seconds. Stale entries are
    /// excluded so that a peer that disconnects without sending an explicit
    /// goodbye doesn't pin the network tip at its last advertised height
    /// indefinitely.
    pub fn network_tip(&self) -> Option<u64> {
        self.peer_status.network_tip()
    }

    /// Returns a snapshot of all non-expired network-discovered models.
    pub fn network_models_snapshot(&self) -> Vec<NetworkModelEntry> {
        let now = std::time::Instant::now();
        self.network_models
            .iter()
            .filter(|entry| {
                let ttl = std::time::Duration::from_secs(entry.registration.ttl_secs);
                now.duration_since(entry.last_seen) < ttl
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Returns a snapshot of all non-expired network-discovered agents.
    pub fn network_agents_snapshot(&self) -> Vec<NetworkAgentEntry> {
        let now = std::time::Instant::now();
        self.network_agents
            .iter()
            .filter(|entry| {
                let ttl = std::time::Duration::from_secs(entry.announcement.ttl_secs);
                now.duration_since(entry.last_seen) < ttl
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Returns a snapshot of all non-expired network-discovered providers.
    pub fn network_providers_snapshot(&self) -> Vec<NetworkProviderEntry> {
        let now = std::time::Instant::now();
        self.network_providers
            .iter()
            .filter(|entry| {
                let ttl = std::time::Duration::from_secs(entry.announcement.ttl_secs);
                now.duration_since(entry.last_seen) < ttl
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Start all subsystems
    pub async fn start(&mut self) -> Result<()> {
        {
            let mut state = self.state.write();
            if *state != NodeState::Created {
                return Err(NodeError::InvalidState(format!(
                    "Cannot start node in state {:?}",
                    *state
                )));
            }
            *state = NodeState::Starting;
        }

        info!("Starting Tenzro Network node...");

        // 1. Initialize storage
        self.init_storage().await?;

        // 2. Initialize network
        self.init_network().await?;

        // 3. Initialize TEE (if enabled)
        if self.config.tee_enabled {
            self.init_tee().await?;
        }

        // 4. Initialize VM runtime
        self.init_vm().await?;

        // 5. Initialize token economics
        self.init_token_economics().await?;

        // 6. Initialize wallet service
        self.init_wallet().await?;

        // 7. Initialize consensus (validators only)
        // Only validators produce blocks. All other roles (ModelProvider, TeeProvider,
        // LightClient) receive blocks from the network via gossipsub block sync.
        let should_init_consensus = matches!(
            self.config.role,
            NetworkRole::Validator
        );
        if should_init_consensus {
            self.init_consensus().await?;
        }

        // 7b. Wire validator registry into the network layer for peer authorization
        if let Some(ref network) = self.network {
            let registry = Arc::new(NodeValidatorRegistry::new());

            // Register the local node's PeerId as a validator if we run consensus.
            if should_init_consensus {
                if let Ok(local_peer_id) = network.local_peer_id().await {
                    registry.add_validator(local_peer_id);
                    info!("Registered local node {} as validator in peer authorization registry", local_peer_id);
                }
            }

            // Register boot node peer IDs as validators. On testnet, boot nodes ARE validators
            // and non-validator nodes need to accept block/consensus messages from them.
            // Peer IDs are extracted from the /p2p/<peer_id> component of boot node multiaddrs.
            for boot_addr in &self.config.network.boot_nodes {
                let mut peer_id_opt = None;
                for proto in boot_addr.iter() {
                    if let libp2p::multiaddr::Protocol::P2p(pid) = proto {
                        peer_id_opt = Some(pid);
                    }
                }
                if let Some(peer_id) = peer_id_opt {
                    registry.add_validator(peer_id);
                    info!(peer = %peer_id, addr = %boot_addr, "Registered boot node as validator in peer authorization registry");
                }
            }

            if let Err(e) = network.set_validator_registry(registry).await {
                warn!("Failed to set validator registry in network layer: {}", e);
            } else {
                info!("Validator registry wired into network peer manager");
            }
        }

        // 8. Initialize settlement
        self.init_settlement().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("settlement", e.to_string());
        })?;

        // 8b. Initialize OAuth 2.1 + DPoP + RAR auth engine
        self.init_auth().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("auth", e.to_string());
        })?;

        // 9. Initialize AI infrastructure
        self.init_ai_infrastructure().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("ai_infrastructure", e.to_string());
        })?;

        // 9a. Auto-register configured Cortex (recurrent-depth) workers.
        //     Best-effort: a failing worker is logged and skipped so the
        //     rest of node startup still proceeds.
        self.init_cortex_workers().await;

        // 9b. Wire VM precompiles to real InferenceRouter + SettlementEngine + ZkCommitmentRegistry.
        //     The VM runtime was created in init_vm() without these service-dependent
        //     precompiles registered, because the services did not yet exist. Now that
        //     init_settlement() and init_ai_infrastructure() have run, we register the
        //     three service-dependent precompiles (MODEL_INFERENCE, SETTLEMENT,
        //     ZK_VERIFY) for the first time via PrecompileRegistry::upgrade_services().
        //
        //     The ZK registry is constructed at node startup (zero-cost wrapper around
        //     a HashSet), so PRECOMPILE_ZK_VERIFY is always wired up here. The other
        //     two are wired only when their backing services exist on this node.
        if let Some(ref vm_runtime) = self.vm_runtime {
            vm_runtime.precompiles().upgrade_services(
                self.inference_router.clone(),
                self.settlement.clone(),
                Some(self.zk_commitment_registry.clone()),
            );
            if self.inference_router.is_some() {
                info!("MODEL_INFERENCE precompile wired to InferenceRouter");
            }
            if self.settlement.is_some() {
                info!("SETTLEMENT precompile wired to SettlementEngine");
            }
            info!(
                "ZK_VERIFY precompile wired to commitment-attestation \
                 (ZkCommitmentRegistry, current size: {})",
                self.zk_commitment_registry.len()
            );

            // ERC-8004 system contracts (0x101a / 0x101b / 0x101c).
            // The handles are stashed on Node so the agent runtime auto-mirror
            // (see init_ai_infrastructure) can write through to the on-chain
            // IdentityRegistry whenever a TDIP agent is registered.
            let (identity, reputation, validation) =
                vm_runtime.precompiles().register_erc8004_precompiles();
            self.erc8004_identity = Some(identity);
            self.erc8004_reputation = Some(reputation);
            self.erc8004_validation = Some(validation);
        }

        // 10. Initialize identity registry (TDIP)
        self.init_identity().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("identity", e.to_string());
        })?;

        // 11. Initialize payment gateway (MPP/x402)
        self.init_payments().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("payments", e.to_string());
        })?;

        // 12. Initialize bridge
        self.init_bridge().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("bridge", e.to_string());
        })?;

        // 13. Bootstrap reference agent templates (best-effort, non-fatal)
        self.bootstrap_agent_templates().await;

        // 13b. Bootstrap ecosystem tools and skills into CF_TOOLS / CF_SKILLS
        self.bootstrap_ecosystem_tools_and_skills();

        // 14. Initialize and start event loop
        self.init_event_loop().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("event_loop", e.to_string());
        })?;

        // 15. Clean up stale model services from previous session
        self.cleanup_expired_model_services();

        // Mark as running
        *self.state.write() = NodeState::Running;
        info!("Tenzro Network node started successfully");

        Ok(())
    }

    /// Stop all subsystems gracefully
    #[allow(dead_code)]
    pub async fn stop(&mut self) -> Result<()> {
        {
            let mut state = self.state.write();
            if *state != NodeState::Running {
                return Err(NodeError::InvalidState(format!(
                    "Cannot stop node in state {:?}",
                    *state
                )));
            }
            *state = NodeState::Stopping;
        }

        info!("Stopping Tenzro Network node...");

        // Stop in reverse order
        // Note: In a full implementation, each subsystem would have a proper shutdown method

        self.bridge_router = None;
        self.payment_gateway = None;
        self.x402_server = None;
        self.identity_registry = None;
        self.agent_runtime = None;
        self.inference_router = None;
        self.provider_manager = None;
        self.model_registry = None;
        self.settlement = None;
        self.channel_manager = None;
        self.escrow_manager = None;
        self.auth_engine = None;
        self.treasury = None;
        self.governance = None;
        self.staking = None;
        self.token = None;
        self.wallet_service = None;
        self.vm_runtime = None;
        self.consensus = None;
        self.tee_registry = None;
        self.tee_provider = None;
        self.network = None;
        self.storage = None;

        *self.state.write() = NodeState::Stopped;
        info!("Tenzro Network node stopped");

        Ok(())
    }

    /// Get node status
    pub async fn status(&self) -> NodeStatus {
        let state = *self.state.read();
        let metrics = self.metrics.get_metrics();
        let health = self.health_monitor.get_status(
            tenzro_types::primitives::BlockHeight::from(0),
            metrics.peer_count as usize,
        );

        NodeStatus {
            state: format!("{:?}", state),
            role: self.config.role,
            health_status: health.overall,
            uptime_secs: metrics.uptime_secs,
            block_height: self.chain_tip_height(),
            peer_count: metrics.peer_count,
            data_dir: self.config.data_dir.clone(),
        }
    }

    /// Get health monitor
    pub fn health_monitor(&self) -> &Arc<HealthMonitor> {
        &self.health_monitor
    }

    /// Get metrics collector
    pub fn metrics(&self) -> &Arc<MetricsCollector> {
        &self.metrics
    }

    // Private initialization methods

    async fn init_storage(&mut self) -> Result<()> {
        info!("Initializing storage...");

        let storage_config = StorageConfig::new(self.config.data_dir.join("db"));
        let store = Arc::new(RocksDbStore::open(&storage_config)?);

        // Initialize genesis block if configured
        if let Some(genesis_config) = &self.config.genesis {
            info!("Initializing genesis block...");
            let _genesis_block = crate::genesis::initialize_genesis(&store, genesis_config).await?;
            info!("Genesis block initialized successfully");

            // One-time bootstrap: if the faucet was configured, make sure a
            // real Ed25519 signing key is provisioned so the RPC faucet
            // handler can submit real signed transactions through consensus
            // instead of bypassing it with direct token.transfer() calls.
            // Idempotent on reboot — no-op after the first successful run.
            if genesis_config.faucet.as_ref().map(|f| f.enabled).unwrap_or(false) {
                crate::genesis::provision_faucet_signing_key(&store).await?;
                // Refill the faucet on every boot if its balance has run dry.
                // Pre-alpha-only safety: a chain-state divergence post-OOM can
                // leave the faucet at zero, which blocks all onboarding flows
                // until manually fixed. This auto-tops-up to 10M TNZO if the
                // balance falls below 1M TNZO.
                crate::genesis::refill_faucet_if_low(&store).await?;
            }
        }

        self.storage = Some(store);
        self.health_monitor.mark_healthy("storage");

        Ok(())
    }

    async fn init_network(&mut self) -> Result<()> {
        info!("Initializing network...");

        // Pass the node's data_dir to the network config for persistent keypair storage
        let mut network_config = self.config.network.clone();
        network_config.data_dir = Some(self.config.data_dir.clone());

        let network = Arc::new(TenzroNetworkService::new(network_config).await?);
        self.network = Some(network);
        self.health_monitor.mark_healthy("network");

        Ok(())
    }

    async fn init_tee(&mut self) -> Result<()> {
        info!("Initializing TEE...");

        match detect_tee().await {
            Some(provider) => {
                info!("Detected TEE vendor: {:?}", provider.vendor());
                let registry = Arc::new(TeeRegistry::new(300));
                self.tee_registry = Some(registry);
                self.health_monitor.mark_healthy("tee");
            }
            None => {
                warn!("No TEE detected, continuing without TEE support");
                self.health_monitor.mark_degraded("tee", "No TEE hardware detected".to_string());
            }
        }

        Ok(())
    }

    async fn init_vm(&mut self) -> Result<()> {
        info!("Initializing VM runtime...");

        let mut vm_config = VmConfig::default();

        // If Canton is not enabled, remove Daml from enabled VMs
        if !self.config.canton.enabled {
            vm_config.enabled_vms.retain(|v| *v != tenzro_vm::VmType::Daml);
            info!("Canton/DAML disabled — DAML VM will not be active");
        }

        let vm_runtime = Arc::new(MultiVmRuntime::with_canton_config(
            vm_config,
            &self.config.canton.host,
            self.config.canton.port,
        ).await?);

        // Wire the EIP-1559 fee market into the VM gas oracle. The oracle owns
        // the live FeeMarket; `eth_gasPrice` / `eth_maxPriorityFeePerGas` /
        // `eth_feeHistory` read it at request time, and the event loop
        // advances it after every block via `on_block_finalized(gas_used)`.
        // Without this wiring the oracle falls back to a static 1 Gwei and
        // the EIP-1559 module is dead code.
        vm_runtime.gas_oracle().set_fee_market(FeeMarket::default()).await;

        self.vm_runtime = Some(vm_runtime);
        self.health_monitor.mark_healthy("vm");

        if self.config.canton.enabled {
            info!(
                "Canton configured at {}:{} (connection deferred until first DAML operation)",
                self.config.canton.host,
                self.config.canton.port,
            );
        }

        Ok(())
    }

    async fn init_token_economics(&mut self) -> Result<()> {
        info!("Initializing token economics...");

        // Initialize TNZO token with persistent storage backend
        let token = if let Some(storage) = &self.storage {
            use tenzro_token::tnzo::RocksDbBackend;
            let backend = Arc::new(RocksDbBackend::new(storage.clone() as Arc<dyn KvStore>));
            Arc::new(TnzoToken::with_storage(backend)
                .map_err(|e| NodeError::Other(format!("Failed to init TNZO token: {}", e)))?)
        } else {
            Arc::new(TnzoToken::new())
        };
        self.token = Some(token);

        // Initialize staking with persistent storage if available
        let staking = if let Some(storage) = &self.storage {
            Arc::new(StakingManager::with_storage(storage.clone() as Arc<dyn KvStore>))
        } else {
            Arc::new(StakingManager::new())
        };
        self.staking = Some(staking);

        // Initialize governance with persistent storage and staking integration
        let governance = if let Some(ref storage) = self.storage {
            if let Some(ref staking) = self.staking {
                Arc::new(GovernanceEngine::with_staking_and_storage(
                    staking.clone(),
                    storage.clone() as Arc<dyn KvStore>,
                ))
            } else {
                Arc::new(GovernanceEngine::with_storage(
                    storage.clone() as Arc<dyn KvStore>,
                ))
            }
        } else if let Some(ref staking) = self.staking {
            Arc::new(GovernanceEngine::with_staking_manager(staking.clone()))
        } else {
            Arc::new(GovernanceEngine::new())
        };
        self.governance = Some(governance);

        // Initialize treasury with persistent storage if available
        let treasury_addr = Address::default(); // In production, this would be a proper address
        let treasury = if let Some(storage) = &self.storage {
            use tenzro_token::treasury::TreasuryStorageBackend;
            let backend = Arc::new(TreasuryStorageBackend::new(storage.clone() as Arc<dyn KvStore>));
            Arc::new(NetworkTreasury::with_storage(treasury_addr, backend))
        } else {
            Arc::new(NetworkTreasury::new(treasury_addr))
        };
        self.treasury = Some(treasury);

        // Initialize unified token registry (cross-VM token tracking)
        let token_registry = if let Some(storage) = &self.storage {
            Arc::new(TokenRegistry::with_storage(storage.clone() as Arc<dyn KvStore>)
                .map_err(|e| NodeError::Other(format!("Failed to init token registry: {}", e)))?)
        } else {
            Arc::new(TokenRegistry::new())
        };
        // Register native TNZO token at startup (wTNZO ERC-20 pointer address)
        if let Err(e) = token_registry.register_tnzo(
            Some([0x10, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]),
            None,
            None,
        ) {
            warn!("TNZO token registration: {} (may already be registered)", e);
        }
        self.token_registry = Some(token_registry);

        self.health_monitor.mark_healthy("token");

        Ok(())
    }

    async fn init_wallet(&mut self) -> Result<()> {
        info!("Initializing wallet service...");

        let wallet_service = Arc::new(TenzroWalletService::new()?);
        self.wallet_service = Some(wallet_service);
        self.health_monitor.mark_healthy("wallet");

        Ok(())
    }

    async fn init_consensus(&mut self) -> Result<()> {
        info!("Initializing consensus engine...");

        let keypair = load_or_generate_validator_keypair(&self.config.data_dir)?;
        let pq_signing_key = load_or_generate_validator_pq_key(&self.config.data_dir)?;
        let local_pq_vk = pq_signing_key.verifying_key_bytes().to_vec();

        // Convert address
        let crypto_addr = keypair.address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = Address::new(addr_bytes);

        // Create validator set.
        //
        // If the operator supplied a `[[validators]]` block in genesis.toml,
        // use those public keys as the canonical BFT validator set. This is
        // what allows multiple nodes in a deployment to actually vote together
        // (n=4, f=1, threshold=2f+1=3) instead of each running solo with
        // threshold=1.
        //
        // If no genesis validators are configured, fall back to a single-node
        // validator set containing only this node — useful for local dev
        // (`tenzro-node --role validator` without a genesis file).
        //
        // The local node's keypair is ALWAYS the signing identity it uses for
        // votes. If the local public key isn't present in the genesis set,
        // this node will produce blocks but its votes will be rejected by
        // peers — this is the correct, fail-loud behavior for an unknown
        // validator.
        let local_pk_hex = hex::encode(keypair.public_key().as_bytes());
        let validators = match self.config.genesis.as_ref() {
            Some(g) if !g.validators.is_empty() => {
                use tenzro_crypto::keys::PublicKey;
                let mut out: Vec<ValidatorInfo> = Vec::with_capacity(g.validators.len());
                for gv in &g.validators {
                    let pk_hex = gv.public_key.strip_prefix("0x").unwrap_or(&gv.public_key);
                    let pk_bytes = hex::decode(pk_hex).map_err(|e| {
                        NodeError::Config(format!(
                            "Invalid genesis validator public key '{}': {}",
                            gv.public_key, e
                        ))
                    })?;
                    if pk_bytes.len() != 32 {
                        return Err(NodeError::Config(format!(
                            "Genesis validator public key '{}' has wrong length: expected 32 bytes for Ed25519, got {}",
                            gv.public_key,
                            pk_bytes.len()
                        )));
                    }
                    let pk = PublicKey::new(KeyType::Ed25519, pk_bytes);

                    // Decode mandatory ML-DSA-65 verifying key for the
                    // hybrid signing scheme. This validator entry is
                    // rejected if the PQ key is missing or wrong-length.
                    let pq_hex = gv
                        .pq_public_key
                        .strip_prefix("0x")
                        .unwrap_or(&gv.pq_public_key);
                    let pq_bytes = hex::decode(pq_hex).map_err(|e| {
                        NodeError::Config(format!(
                            "Invalid genesis validator pq_public_key for '{}': {}",
                            gv.public_key, e
                        ))
                    })?;
                    if pq_bytes.len() != 1952 {
                        return Err(NodeError::Config(format!(
                            "Genesis validator pq_public_key for '{}' has wrong length: \
                             expected 1952 bytes for ML-DSA-65, got {}",
                            gv.public_key,
                            pq_bytes.len()
                        )));
                    }

                    // Derive the 32-byte address by taking the 20-byte crypto
                    // address (Keccak-256 of pubkey, last 20 bytes) and
                    // left-padding into a 32-byte slot — same convention as
                    // `address` above.
                    let crypto_addr = pk.to_address();
                    let mut addr_bytes = [0u8; 32];
                    addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
                    let v_address = Address::new(addr_bytes);
                    out.push(ValidatorInfo::new(v_address, pk, pq_bytes, gv.stake as u128));
                }
                if !out
                    .iter()
                    .any(|v| hex::encode(v.public_key.as_bytes()) == local_pk_hex)
                {
                    warn!(
                        local_validator_pubkey = %local_pk_hex,
                        "Local validator keypair not found in genesis validator set — \
                         this node will produce proposals but its votes will be rejected by peers"
                    );
                }
                info!(
                    validator_count = out.len(),
                    "Loaded validator set from genesis.toml"
                );
                out
            }
            _ => {
                info!("No genesis validators configured, running as single-node validator");
                vec![ValidatorInfo::new(
                    address,
                    keypair.public_key().clone(),
                    local_pq_vk.clone(),
                    1000,
                )]
            }
        };

        // Create epoch manager
        let epoch_manager = EpochManager::new(validators, 10000)?;

        // Create consensus engine with slashing callback wired to StakingManager
        let consensus_config = self.config.consensus.clone().unwrap_or_default();
        let mut engine =
            HotStuff2Engine::new(keypair, pq_signing_key, consensus_config, epoch_manager);

        // Stash the local validator address so the inbound consensus
        // gossipsub bridge (wired in `start()`) can drop self-broadcasts
        // before they re-enter the engine.
        self.local_validator_address = Some(address);

        // Wire slashing callback so equivocation triggers real stake slashing
        if let Some(ref staking) = self.staking {
            let callback = Arc::new(StakingSlashingCallback::new(staking.clone()));
            engine = engine.with_slashing_callback(callback);
            info!("Slashing callback wired to consensus engine");
        }

        // Wire state root provider so block proposals include real state roots.
        // Create a StateAdapter backed by storage and wrap it in a NodeStateRootProvider.
        // Uses parking_lot::Mutex (not tokio::sync::Mutex) because StateRootProvider::current_state_root()
        // is a sync method called from within the tokio runtime's consensus loop.
        // tokio::sync::Mutex::blocking_lock() panics in that context.
        if let Some(ref storage) = self.storage {
            use tenzro_vm::StateAdapter;

            let state_adapter = Arc::new(parking_lot::Mutex::new(
                StateAdapter::with_storage(storage.clone() as Arc<dyn tenzro_storage::KvStore>),
            ));
            let state_root_provider = Arc::new(NodeStateRootProvider::new(state_adapter));
            engine = engine.with_state_root_provider(state_root_provider);
            info!("State root provider wired to consensus engine");

            // Wire block provider so the consensus engine can fetch parent
            // blocks during proposal validation (EIP-1559 base-fee derivation
            // + child→parent header check). The engine consults
            // `FinalityTracker::get_finalized_block` first; this provider is
            // the durable RocksDB fallback for post-restart resume scenarios
            // where the in-memory cache has not yet been re-populated.
            let block_provider = Arc::new(NodeBlockProvider::new(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            ));
            engine = engine.with_block_provider(block_provider);
            info!("Block provider wired to consensus engine");
        }

        // Wire the persistent vote-state store so equivocation can never be
        // self-induced by a crash between sign and broadcast. The store
        // refuses any (view, height, step) ≤ last-persisted, with fsync on
        // record. Mirrors CometBFT `FilePVLastSignState`.
        //
        // ORDER MATTERS: this MUST run before `resume_from_height` below.
        // `resume_from_height` consults the vote-state store to jump
        // `current_view` past the persisted last-vote view at the same
        // height — without this jump the engine starts at view=0, hits the
        // CheckHRS rule, and refuses every vote (height=0 wedge observed
        // 2026-04-28T09:12Z testnet).
        match open_default_file_store(&self.config.data_dir) {
            Ok(store) => {
                engine = engine.with_vote_state_store(store);
                info!(
                    data_dir = ?self.config.data_dir,
                    "Persistent vote-state store wired (last_sign.json)"
                );
            }
            Err(e) => {
                // Refuse to start consensus without durable vote state — the
                // alternative (in-memory store) would silently re-introduce
                // the self-equivocation risk we're trying to eliminate.
                return Err(NodeError::Other(format!(
                    "Failed to open persistent vote-state store: {}", e
                )));
            }
        }

        // Resume consensus from the last persisted block height so the engine
        // doesn't re-propose blocks that are already committed to storage.
        // Without this, FinalityTracker starts at 0 on every restart, causing
        // eth_blockNumber to return stale values and duplicate block proposals.
        // Also: consults the vote_state_store wired above to advance
        // `current_view` past any vote already cast in a prior run at the
        // next-to-be-proposed height (CheckHRS jump).
        if let Some(ref storage) = self.storage {
            use tenzro_storage::block_store::BlockStoreImpl;
            use tenzro_storage::BlockStore;
            match BlockStoreImpl::new(storage.clone()) {
                Ok(block_store) => {
                    match block_store.latest_height().await {
                        Ok(Some(height)) => {
                            engine.resume_from_height(height);
                            info!(height = %height, "Consensus engine resuming from stored height");
                        }
                        Ok(None) => {
                            // No finalized blocks yet — but persisted vote state
                            // may still exist from a prior unproductive run.
                            // Pass height=0 so resume_from_height still consults
                            // vote_state_store and jumps the view if needed.
                            engine.resume_from_height(tenzro_types::BlockHeight(0));
                            info!("No stored blocks found, consensus starting from genesis (vote-state view-jump may still apply)");
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to read stored block height, starting from genesis");
                            engine.resume_from_height(tenzro_types::BlockHeight(0));
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to open block store for height check");
                }
            }
        }

        // Create the outbound channel BEFORE starting the engine so the engine
        // can immediately start sending ConsensusOutMessage values.  The RX half
        // is stored on the node and consumed once by init_event_loop().
        let (consensus_out_tx, consensus_out_rx) =
            tokio::sync::mpsc::unbounded_channel::<ConsensusOutMessage>();
        engine = engine.with_consensus_out(consensus_out_tx);

        // START the consensus engine BEFORE wrapping in Arc.
        // start() takes &mut self — it initializes the vote collector,
        // creates the shutdown channel, and spawns the consensus loop task.
        engine.start().await
            .map_err(|e| NodeError::Other(format!("Failed to start consensus: {}", e)))?;

        info!("Consensus engine started successfully");

        self.consensus = Some(Arc::new(engine));
        self.consensus_out_rx = Some(consensus_out_rx);
        info!("Consensus outbound channel wired");
        self.health_monitor.mark_healthy("consensus");

        Ok(())
    }

    async fn init_settlement(&mut self) -> Result<()> {
        info!("Initializing settlement engine...");

        let treasury_addr = Address::default();
        let config = SettlementConfig::new(treasury_addr);
        let treasury = self.treasury.clone().unwrap();

        // SettlementEngine — when storage is available, persist receipts and
        // per-address indices to `CF_SETTLEMENTS` (`receipt:`, `settlement_addr:`
        // prefixes). Hydrates the receipts cache + per-address history on startup.
        let settlement = if let Some(ref storage) = self.storage {
            let engine = SettlementEngine::with_storage(
                config,
                treasury.clone(),
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            )?;
            info!("SettlementEngine initialized with persistent storage (CF_SETTLEMENTS)");
            Arc::new(engine)
        } else {
            Arc::new(SettlementEngine::new(config, treasury.clone())?)
        };
        self.settlement = Some(settlement);

        // ChannelManager — when storage is available, wrap a `RocksDbChannelStorage`
        // adapter so channels and disputes survive restarts (CF_CHANNELS).
        let channel_manager = if let Some(ref storage) = self.storage {
            let backend: Arc<dyn tenzro_settlement::ChannelStorage> =
                Arc::new(RocksDbChannelStorage::new(
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                ));
            let mgr = ChannelManager::with_storage(backend);
            info!("ChannelManager initialized with persistent storage (CF_CHANNELS)");
            Arc::new(mgr)
        } else {
            Arc::new(ChannelManager::new())
        };
        self.channel_manager = Some(channel_manager);

        // Initialize shared escrow manager. When durable storage is available we
        // wire it through `EscrowManager::with_storage`, which both write-through
        // persists every mutation to `CF_SETTLEMENTS` (under `escrow:`,
        // `escrow_payer:`, `escrow_payee:` prefixes) and rehydrates the in-memory
        // index from disk on startup. Note: this in-memory `EscrowManager` is now
        // a *query index* over escrow records — the Native VM is the source of
        // truth for escrow state and vault balances. The shared `balances`
        // DashMap is kept only to satisfy the legacy constructor contract; it is
        // not consulted for VM-mediated escrows.
        let balances = Arc::new(dashmap::DashMap::new());
        let escrow_manager = if let Some(ref storage) = self.storage {
            let mgr = EscrowManager::with_storage(
                balances,
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            );
            info!("EscrowManager initialized with persistent storage (CF_SETTLEMENTS)");
            Arc::new(mgr)
        } else {
            Arc::new(EscrowManager::new(balances))
        };
        self.escrow_manager = Some(escrow_manager);

        // BatchProcessor — write-through to CF_SETTLEMENTS via the storage
        // builder. `BatchProcessor::with_storage` is a builder method on `new()`.
        let batch_processor = if let Some(ref storage) = self.storage {
            let bp = BatchProcessor::new(100)
                .with_storage(storage.clone() as Arc<dyn tenzro_storage::KvStore>);
            info!("BatchProcessor initialized with persistent storage (CF_SETTLEMENTS)");
            Arc::new(bp)
        } else {
            Arc::new(BatchProcessor::new(100))
        };
        self.batch_processor = Some(batch_processor);

        // FeeCollector — write-through to CF_SETTLEMENTS (`fee:`, `fee_total:`,
        // `fee_count:` prefixes); hydrates totals + counts + history on startup.
        let fee_collector = if let Some(ref storage) = self.storage {
            let fc = FeeCollector::with_storage(
                treasury.clone(),
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            );
            info!("FeeCollector initialized with persistent storage (CF_SETTLEMENTS)");
            Arc::new(fc)
        } else {
            Arc::new(FeeCollector::new(treasury.clone()))
        };
        self.fee_collector = Some(fee_collector);

        self.health_monitor.mark_healthy("settlement");

        Ok(())
    }

    /// Initializes the OAuth 2.1 + DPoP + RAR auth engine.
    ///
    /// The signing secret is loaded from `<data_dir>/auth_secret.bin`,
    /// generated on first boot from the OS RNG (32 bytes). This keeps
    /// the secret stable across restarts (so JWTs survive a node
    /// restart) without sharing it across nodes — JWT validation is
    /// per-node, not federated.
    ///
    /// `issuer` is the node's HTTP RPC URL; `audience` is the same URL
    /// — the RPC server is its own resource server.
    async fn init_auth(&mut self) -> Result<()> {
        info!("Initializing auth engine (OAuth 2.1 + DPoP + RAR)...");

        let storage = match self.storage.as_ref() {
            Some(s) => s.clone() as Arc<dyn tenzro_storage::KvStore>,
            None => {
                warn!("Storage not initialized; skipping auth engine init");
                return Ok(());
            }
        };

        // Load-or-generate a per-node signing secret. Storing it in the
        // data dir (chmod 600 isn't enforced here — operators are
        // expected to run the node under a dedicated user with mode-0700
        // data dir per `deploy/kubernetes` manifests).
        let secret_path = self.config.data_dir.join("auth_secret.bin");
        let signing_secret: Vec<u8> = match std::fs::read(&secret_path) {
            Ok(bytes) if bytes.len() >= 32 => {
                info!("Loaded auth signing secret from {}", secret_path.display());
                bytes
            }
            _ => {
                use rand::RngCore;
                let mut buf = vec![0u8; 32];
                rand::thread_rng().fill_bytes(&mut buf);
                if let Some(parent) = secret_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::write(&secret_path, &buf).map_err(|e| {
                    NodeError::Internal(format!(
                        "failed to persist auth signing secret to {}: {}",
                        secret_path.display(),
                        e
                    ))
                })?;
                info!(
                    "Generated new auth signing secret at {}",
                    secret_path.display()
                );
                buf
            }
        };

        let rpc_addr = if self.config.rpc_addr.is_empty() {
            "127.0.0.1:8545".to_string()
        } else {
            self.config.rpc_addr.clone()
        };
        let issuer = format!("http://{rpc_addr}");
        let audience = issuer.clone();

        let cfg = tenzro_auth::AuthEngineConfig::new(issuer, audience, signing_secret);
        let engine = tenzro_auth::AuthEngine::new(cfg, storage).map_err(|e| {
            NodeError::Internal(format!("auth engine init: {}", e))
        })?;
        self.auth_engine = Some(Arc::new(engine));
        info!("AuthEngine initialized (CF_AUDIT, CF_APPROVALS hydrated)");
        self.health_monitor.mark_healthy("auth");

        Ok(())
    }

    async fn init_ai_infrastructure(&mut self) -> Result<()> {
        info!("Initializing AI infrastructure...");

        // Initialize model registry with durable backing store when available.
        // ModelRegistry::with_storage() scans CF_MODELS for `info:` prefix keys
        // and rehydrates the in-memory catalog so models registered before the
        // restart remain discoverable.
        let registry = if let Some(ref storage) = self.storage {
            Arc::new(ModelRegistry::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            ))
        } else {
            Arc::new(ModelRegistry::new())
        };
        self.model_registry = Some(registry);

        // Initialize provider manager (with storage persistence if available)
        let provider_manager = if let Some(ref storage) = self.storage {
            Arc::new(ProviderManager::with_storage(storage.clone() as Arc<dyn tenzro_storage::KvStore>))
        } else {
            Arc::new(ProviderManager::new())
        };
        self.provider_manager = Some(provider_manager.clone());

        // Initialize usage tracker (with storage persistence if available).
        // The tracker is the producer-side aggregation point for every
        // successful inference's `UsageRecord`; failure to construct with
        // storage falls back to in-memory only so the node still runs.
        let usage_tracker = if let Some(ref storage) = self.storage {
            match tenzro_model::UsageTracker::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            ) {
                Ok(t) => Arc::new(t),
                Err(e) => {
                    tracing::warn!(
                        "UsageTracker storage hydration failed ({}); falling back to in-memory",
                        e
                    );
                    Arc::new(tenzro_model::UsageTracker::new())
                }
            }
        } else {
            Arc::new(tenzro_model::UsageTracker::new())
        };
        self.usage_tracker = Some(usage_tracker.clone());

        // EU AI Act Art. 50(2): every node that serves inference produces a
        // signed provenance manifest for each response. The signer is fresh
        // per node lifetime — when we add long-term provenance keys to the
        // node config, this is the swap point. The store is shared with the
        // `tenzro_getProvenance` RPC so the read and write paths see the
        // same in-memory cache. Failure to mint a key is non-fatal: the
        // router degrades to "synthetic_content=true but no signature",
        // matching dev-mode nodes.
        let provenance_store = Arc::new(tenzro_model::ProvenanceStore::default());
        self.provenance_store = Some(provenance_store.clone());
        let provenance_signer: Option<tenzro_model::SharedProvenanceSigner> =
            match tenzro_model::Ed25519ProvenanceSigner::generate() {
                Ok(s) => Some(s.into_shared()),
                Err(e) => {
                    tracing::warn!(
                        "Failed to mint provenance signer ({}); responses will carry \
                         synthetic_content=true but no signed manifest",
                        e
                    );
                    None
                }
            };

        // Initialize inference router with the tracker attached so every
        // successful inference flows through `record_usage` for durable
        // per-model / per-provider / global aggregation, and stamps a
        // provenance manifest before returning each response.
        let mut router_builder = InferenceRouter::new(provider_manager)
            .with_usage_tracker(usage_tracker)
            .with_provenance_store(provenance_store);
        if let Some(signer) = provenance_signer {
            router_builder = router_builder.with_provenance_signer(signer);
        }
        let router = Arc::new(router_builder);
        self.inference_router = Some(router);

        // Initialize agent runtime with gossipsub network transport
        let agent_runtime = if let Some(ref network) = self.network {
            // Create outbound channel for publishing agent messages to gossipsub
            let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<(String, Vec<u8>)>(1000);

            // Create the transport wired to the network
            let (transport, inbound_tx) =
                tenzro_agent::messaging::GossipsubTransport::with_network(outbound_tx);

            // Spawn outbound bridge: reads from channel → broadcasts via gossipsub
            let net_out = network.clone();
            tokio::spawn(async move {
                while let Some((topic, data)) = outbound_rx.recv().await {
                    let msg = NetworkMessage::new(
                        MessagePayload::Custom {
                            topic: topic.clone(),
                            data: data.clone(),
                        },
                    );
                    if let Err(e) = net_out.broadcast(&topic, msg).await {
                        tracing::warn!("Failed to broadcast agent message on gossipsub: {}", e);
                    }
                }
            });

            // Spawn inbound bridge: subscribes to agents topic → feeds into transport
            let net_in = network.clone();
            tokio::spawn(async move {
                match net_in.subscribe("tenzro/agents/1.0.0").await {
                    Ok(mut rx) => {
                        while let Some(msg) = rx.recv().await {
                            if let tenzro_network::MessagePayload::Custom { data, .. } = msg.payload
                            {
                                match serde_json::from_slice::<tenzro_types::AgentMessage>(&data) {
                                    Ok(agent_msg) => {
                                        let _ = inbound_tx.send(agent_msg).await;
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            "Ignoring non-agent message on agents topic: {}",
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to subscribe to agents gossipsub topic: {}",
                            e
                        );
                    }
                }
            });

            info!("Agent messaging wired to gossipsub (tenzro/agents/1.0.0)");
            // Prefer the storage-backed constructor so RegisteredAgent,
            // AgentLifecycleInfo, and the spawn tree are hydrated on boot and
            // every subsequent mutation is written through to CF_AGENTS.
            if let Some(ref storage) = self.storage {
                Arc::new(AgentRuntime::with_storage(
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                    Some(Arc::new(transport)),
                )?)
            } else {
                Arc::new(AgentRuntime::with_network_transport(Arc::new(transport))?)
            }
        } else {
            // No network available — use local-only message routing
            info!("Agent messaging in local-only mode (no network)");
            if let Some(ref storage) = self.storage {
                Arc::new(AgentRuntime::with_storage(
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                    None,
                )?)
            } else {
                Arc::new(AgentRuntime::new()?)
            }
        };
        // SwarmManager mirrors the same storage so swarm membership and
        // status survive restarts via the `swarm:` prefix in CF_AGENTS.
        let swarm_mgr = if let Some(ref storage) = self.storage {
            Arc::new(SwarmManager::with_storage(
                agent_runtime.clone(),
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            )?)
        } else {
            Arc::new(SwarmManager::new(agent_runtime.clone()))
        };
        self.agent_runtime = Some(agent_runtime);
        self.swarm_manager = Some(swarm_mgr);
        info!("Swarm manager initialized");

        // Background liveness sweeper. Marks silent skills/tools/templates/
        // tasks/sessions/services as Inactive and purges terminal rows past
        // the configured TTL. Also auto-Terminates agents stuck in Suspended
        // past `agent_purge_after_secs`. Only runs when storage is wired —
        // in-memory mode (tests) skips the sweeper entirely so they don't race.
        if let Some(ref storage) = self.storage {
            let lifecycle = self
                .agent_runtime
                .as_ref()
                .map(|ar| ar.lifecycle_manager());
            let sweeper = crate::liveness::spawn_liveness_sweeper(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                crate::liveness::LivenessConfig::default(),
                lifecycle,
            );
            self.liveness_sweeper = Some(sweeper);
            info!("Liveness sweeper spawned (5min cadence)");
        }

        // Auto-register TenzroClaw agents on every startup so they survive restarts
        {
            use tenzro_types::agent::Capability;
            let system_addr = Address::zero();
            let tenzroclaw_caps = vec![
                Capability::NaturalLanguageProcessing { languages: vec!["en".to_string()] },
                Capability::CodeGeneration { languages: vec!["rust".to_string(), "python".to_string(), "typescript".to_string()] },
                Capability::BlockchainInteraction { chains: vec!["tenzro".to_string(), "ethereum".to_string()] },
                Capability::MultiAgentCoordination,
            ];
            if let Some(ref ar) = self.agent_runtime {
                let ar1 = ar.clone();
                let caps1 = tenzroclaw_caps.clone();
                let addr1 = system_addr;
                tokio::spawn(async move {
                    match ar1.register_agent("TenzroClaw-1".to_string(), addr1, caps1, false, 1).await {
                        Ok(a) => info!("Auto-registered TenzroClaw-1: agent_id={}", a.identity.agent_id),
                        Err(e) => warn!("Failed to auto-register TenzroClaw-1: {}", e),
                    }
                });
                let ar2 = ar.clone();
                let addr2 = system_addr;
                tokio::spawn(async move {
                    match ar2.register_agent("TenzroClaw-2".to_string(), addr2, tenzroclaw_caps, false, 2).await {
                        Ok(a) => info!("Auto-registered TenzroClaw-2: agent_id={}", a.identity.agent_id),
                        Err(e) => warn!("Failed to auto-register TenzroClaw-2: {}", e),
                    }
                });
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // AUTO-REGISTER BUILT-IN SKILLS, TOOLS, AND AGENT TEMPLATES
        // Uses deterministic name-based keys for idempotent writes (no duplicates on restart)
        // ═══════════════════════════════════════════════════════════════════════
        if let Some(ref storage) = self.storage {
            use tenzro_types::skill::SkillDefinition;
            use tenzro_types::tool::ToolDefinition;
            use tenzro_types::agent_template::{AgentTemplate, AgentTemplateType};

            // --- Built-in Skills ---
            let builtin_skills: Vec<SkillDefinition> = vec![
                {
                    let mut s = SkillDefinition::new(
                        "web-search".to_string(), "1.0.0".to_string(),
                        "did:tenzro:system:tenzro-network".to_string(),
                        "Search the web and return relevant results".to_string(), 0,
                    );
                    s.tags = vec!["search".to_string(), "web".to_string(), "retrieval".to_string()];
                    s.endpoint = Some("builtin://web-search".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "code-review".to_string(), "1.0.0".to_string(),
                        "did:tenzro:system:tenzro-network".to_string(),
                        "Review code and suggest improvements".to_string(), 0,
                    );
                    s.tags = vec!["code".to_string(), "review".to_string(), "quality".to_string()];
                    s.endpoint = Some("builtin://code-review".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "data-analysis".to_string(), "1.0.0".to_string(),
                        "did:tenzro:system:tenzro-network".to_string(),
                        "Analyze datasets and generate insights".to_string(), 0,
                    );
                    s.tags = vec!["data".to_string(), "analysis".to_string(), "insights".to_string()];
                    s.endpoint = Some("builtin://data-analysis".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "text-summarization".to_string(), "1.0.0".to_string(),
                        "did:tenzro:system:tenzro-network".to_string(),
                        "Summarize long documents into concise summaries".to_string(), 0,
                    );
                    s.tags = vec!["text".to_string(), "summarization".to_string(), "nlp".to_string()];
                    s.endpoint = Some("builtin://text-summarization".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "blockchain-query".to_string(), "1.0.0".to_string(),
                        "did:tenzro:system:tenzro-network".to_string(),
                        "Query blockchain state, balances, and transactions".to_string(), 0,
                    );
                    s.tags = vec!["blockchain".to_string(), "query".to_string(), "ledger".to_string()];
                    s.endpoint = Some("builtin://blockchain-query".to_string());
                    s
                },
            ];

            let mut skills_registered = 0usize;
            for skill in &builtin_skills {
                // Use the UUID skill_id as the storage key so that
                // list_skills → get_skill lookups (by skill_id) resolve correctly.
                let key = skill.skill_id.as_bytes();
                // Idempotency: skip only if a builtin with this exact name already exists.
                let already_present = storage
                    .get_keys_with_prefix(CF_SKILLS, b"")
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|k| storage.get(CF_SKILLS, &k).ok().flatten())
                    .filter_map(|v| serde_json::from_slice::<SkillDefinition>(&v).ok())
                    .any(|s| s.name == skill.name && s.creator_did == skill.creator_did);
                if !already_present {
                    if let Ok(value) = serde_json::to_vec(skill) {
                        if storage.put(CF_SKILLS, key, &value).is_ok() {
                            skills_registered += 1;
                        }
                    }
                }
            }
            if skills_registered > 0 {
                info!("Auto-registered {} built-in skill(s) in CF_SKILLS", skills_registered);
            }

            // --- Built-in Tools (MCP servers and native capabilities) ---
            let builtin_tools: Vec<ToolDefinition> = vec![
                {
                    let mut t = ToolDefinition::new(
                        "tenzro-mcp-server".to_string(), "1.0.0".to_string(),
                        "mcp".to_string(), "https://mcp.tenzro.network/mcp".to_string(),
                        "Tenzro Network MCP server with 24 tools for wallet, identity, payments, models, bridge, staking".to_string(),
                        "blockchain".to_string(),
                    );
                    t.capabilities = vec![
                        "wallet".to_string(), "identity".to_string(), "payments".to_string(),
                        "models".to_string(), "bridge".to_string(), "staking".to_string(),
                        "verification".to_string(), "network".to_string(),
                    ];
                    t.creator_did = Some("did:tenzro:system:tenzro-network".to_string());
                    t
                },
                {
                    let mut t = ToolDefinition::new(
                        "web-search-mcp".to_string(), "1.0.0".to_string(),
                        "mcp".to_string(), "builtin://web-search-mcp".to_string(),
                        "MCP server providing web search capabilities".to_string(),
                        "search".to_string(),
                    );
                    t.capabilities = vec!["web-search".to_string(), "url-fetch".to_string()];
                    t.creator_did = Some("did:tenzro:system:tenzro-network".to_string());
                    t
                },
                {
                    let mut t = ToolDefinition::new(
                        "code-executor".to_string(), "1.0.0".to_string(),
                        "mcp".to_string(), "builtin://code-executor".to_string(),
                        "Execute code in sandboxed environments (Python, JavaScript, Rust)".to_string(),
                        "code".to_string(),
                    );
                    t.capabilities = vec!["python".to_string(), "javascript".to_string(), "rust".to_string()];
                    t.creator_did = Some("did:tenzro:system:tenzro-network".to_string());
                    t
                },
                {
                    let mut t = ToolDefinition::new(
                        "file-manager".to_string(), "1.0.0".to_string(),
                        "native".to_string(), "builtin://file-manager".to_string(),
                        "Read, write, and manage files in agent workspaces".to_string(),
                        "storage".to_string(),
                    );
                    t.capabilities = vec!["read".to_string(), "write".to_string(), "list".to_string()];
                    t.creator_did = Some("did:tenzro:system:tenzro-network".to_string());
                    t
                },
                {
                    let mut t = ToolDefinition::new(
                        "tenzro-a2a-server".to_string(), "1.0.0".to_string(),
                        "api".to_string(), "https://a2a.tenzro.network".to_string(),
                        "Agent-to-Agent protocol server for inter-agent communication (Google A2A spec)".to_string(),
                        "communication".to_string(),
                    );
                    t.capabilities = vec!["agent-messaging".to_string(), "task-delegation".to_string(), "sse-streaming".to_string()];
                    t.creator_did = Some("did:tenzro:system:tenzro-network".to_string());
                    t
                },
            ];

            let mut tools_registered = 0usize;
            for tool in &builtin_tools {
                // Use the UUID tool_id as the storage key so that
                // list_tools → get_tool / use_tool lookups (by tool_id) resolve correctly.
                let key = tool.tool_id.as_bytes();
                let already_present = storage
                    .get_keys_with_prefix(CF_TOOLS, b"")
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|k| storage.get(CF_TOOLS, &k).ok().flatten())
                    .filter_map(|v| serde_json::from_slice::<ToolDefinition>(&v).ok())
                    .any(|t| t.name == tool.name && t.creator_did == tool.creator_did);
                if !already_present {
                    if let Ok(value) = serde_json::to_vec(tool) {
                        if storage.put(CF_TOOLS, key, &value).is_ok() {
                            tools_registered += 1;
                        }
                    }
                }
            }
            if tools_registered > 0 {
                info!("Auto-registered {} built-in tool(s) in CF_TOOLS", tools_registered);
            }

            // --- Built-in Agent Templates ---
            let system_addr = Address::zero();
            let builtin_templates: Vec<AgentTemplate> = vec![
                {
                    let mut t = AgentTemplate::new(
                        "Research Agent".to_string(),
                        "Autonomous research agent that searches the web, analyzes sources, and produces comprehensive reports".to_string(),
                        AgentTemplateType::Autonomous,
                        system_addr,
                        "You are a research agent. Search for information, analyze sources, synthesize findings, and produce clear reports.".to_string(),
                    );
                    t.tags = vec!["research".to_string(), "analysis".to_string(), "autonomous".to_string()];
                    t
                },
                {
                    let mut t = AgentTemplate::new(
                        "Code Assistant".to_string(),
                        "Tool-augmented coding agent with code execution, review, and debugging capabilities".to_string(),
                        AgentTemplateType::ToolAgent,
                        system_addr,
                        "You are a coding assistant. Help users write, review, debug, and optimize code across multiple languages.".to_string(),
                    );
                    t.tags = vec!["code".to_string(), "development".to_string(), "debugging".to_string()];
                    t
                },
                {
                    let mut t = AgentTemplate::new(
                        "Trading Agent".to_string(),
                        "Specialist agent for DeFi trading, portfolio management, and market analysis on Tenzro Network".to_string(),
                        AgentTemplateType::Specialist,
                        system_addr,
                        "You are a DeFi trading specialist on Tenzro Network. Analyze markets, execute trades, and manage portfolios using TNZO.".to_string(),
                    );
                    t.tags = vec!["trading".to_string(), "defi".to_string(), "finance".to_string()];
                    t
                },
                {
                    let mut t = AgentTemplate::new(
                        "Orchestrator Agent".to_string(),
                        "Multi-agent orchestrator that decomposes complex tasks and delegates to specialized agents".to_string(),
                        AgentTemplateType::Orchestrator,
                        system_addr,
                        "You are an orchestrator agent. Break down complex tasks, delegate subtasks to specialized agents, and synthesize results.".to_string(),
                    );
                    t.tags = vec!["orchestration".to_string(), "multi-agent".to_string(), "coordination".to_string()];
                    t
                },
                {
                    let mut t = AgentTemplate::new(
                        "Data Analyst".to_string(),
                        "Multimodal data analysis agent that processes text, images, and structured data to generate insights".to_string(),
                        AgentTemplateType::MultiModal,
                        system_addr,
                        "You are a data analyst agent. Process and analyze datasets, create visualizations, and generate actionable insights.".to_string(),
                    );
                    t.tags = vec!["data".to_string(), "analytics".to_string(), "visualization".to_string()];
                    t
                },
            ];

            // Storage key scheme for CF_AGENT_TEMPLATES is raw UUID bytes so that
            // list_agent_templates → get_agent_template / spawn_agent_from_template
            // lookups (by template_id) resolve correctly.
            //
            // Migration-safe seed: for each built-in template,
            //   1. Check if a record exists at the raw-UUID key specifically.
            //   2. If not, sweep any legacy entries matching by (name, creator)
            //      under a non-matching key and delete them, then write the
            //      canonical raw-UUID-keyed record.
            // This prevents stale prefixed-key seeds written by older node images
            // from silently blocking re-seed under the canonical key scheme.
            let mut templates_registered = 0usize;
            let mut templates_migrated = 0usize;
            let all_keys = storage
                .get_keys_with_prefix(CF_AGENT_TEMPLATES, b"")
                .unwrap_or_default();
            for template in &builtin_templates {
                let key = template.template_id.as_bytes().to_vec();
                let canonical_present = storage
                    .get(CF_AGENT_TEMPLATES, &key)
                    .ok()
                    .flatten()
                    .and_then(|v| serde_json::from_slice::<AgentTemplate>(&v).ok())
                    .map(|t| t.name == template.name && t.creator == template.creator)
                    .unwrap_or(false);
                if canonical_present {
                    continue;
                }
                // Purge any legacy entries at non-canonical keys that match by (name, creator).
                for legacy_key in &all_keys {
                    if legacy_key == &key {
                        continue;
                    }
                    if let Ok(Some(v)) = storage.get(CF_AGENT_TEMPLATES, legacy_key) {
                        if let Ok(t) = serde_json::from_slice::<AgentTemplate>(&v) {
                            if t.name == template.name && t.creator == template.creator
                                && storage.delete(CF_AGENT_TEMPLATES, legacy_key).is_ok() {
                                    templates_migrated += 1;
                                }
                        }
                    }
                }
                if let Ok(value) = serde_json::to_vec(template) {
                    if storage.put(CF_AGENT_TEMPLATES, &key, &value).is_ok() {
                        templates_registered += 1;
                    }
                }
            }
            if templates_registered > 0 || templates_migrated > 0 {
                info!(
                    "Agent templates seeded: {} new, {} legacy-key entries migrated in CF_AGENT_TEMPLATES",
                    templates_registered, templates_migrated
                );
            }
        }

        // Initialize HuggingFace downloader
        // Default to ~/.tenzro/models/ to match where the CLI downloads models
        let models_dir = self.config.models_dir
            .clone()
            .unwrap_or_else(|| {
                std::path::PathBuf::from(
                    std::env::var("HOME").unwrap_or_else(|_| "/home/tenzro".to_string())
                )
                .join(".tenzro")
                .join("models")
            });
        std::fs::create_dir_all(&models_dir).map_err(|e| {
            NodeError::Internal(format!("Failed to create models directory: {}", e))
        })?;
        let hf_downloader = Arc::new(HfDownloader::new(models_dir));
        self.hf_downloader = Some(hf_downloader);
        info!("HuggingFace downloader initialized");

        // Initialize model runtime (candle GGUF inference)
        let model_runtime = Arc::new(ModelRuntime::new());
        self.model_runtime = Some(model_runtime);
        info!("Model runtime initialized");

        // ═══════════════════════════════════════════════════════════════════════
        // STARTUP RESTORATION: Restore served_models from RocksDB CF_MODELS
        // The existing gossipsub heartbeat will re-announce restored models to peers.
        // ═══════════════════════════════════════════════════════════════════════
        if let Some(ref storage) = self.storage {
            match storage.get_keys_with_prefix(CF_MODELS, b"") {
                Ok(keys) => {
                    let mut restored = 0usize;
                    for key_bytes in &keys {
                        if let Ok(model_id) = std::str::from_utf8(key_bytes) {
                            self.served_models.insert(model_id.to_string(), true);
                            restored += 1;
                        }
                    }
                    if restored > 0 {
                        info!("Restored {} served model(s) from RocksDB CF_MODELS on startup", restored);
                    }
                }
                Err(e) => {
                    warn!("Failed to restore served models from CF_MODELS on startup: {}", e);
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // STARTUP RESTORATION: Restore model_services from RocksDB CF_MODEL_SERVICES
        // ═══════════════════════════════════════════════════════════════════════
        if let Some(ref storage) = self.storage {
            match storage.get_keys_with_prefix(CF_MODEL_SERVICES, b"") {
                Ok(keys) => {
                    let mut restored = 0usize;
                    for key_bytes in &keys {
                        if let Ok(instance_id) = std::str::from_utf8(key_bytes) {
                            if let Ok(Some(data)) = storage.get(CF_MODEL_SERVICES, key_bytes) {
                                if let Ok(instance) = serde_json::from_slice::<tenzro_types::model::ModelServiceInstance>(&data) {
                                    self.model_services.insert(instance_id.to_string(), instance);
                                    restored += 1;
                                }
                            }
                        }
                    }
                    if restored > 0 {
                        info!("Restored {} model service(s) from RocksDB CF_MODEL_SERVICES on startup", restored);
                    }

                    // Also restore network-discovered model endpoints (from gossipsub, persisted)
                    let mut net_restored = 0usize;
                    for key_bytes in &keys {
                        if let Ok(key_str) = std::str::from_utf8(key_bytes) {
                            if key_str.starts_with("net_model:") {
                                if let Ok(Some(data)) = storage.get(CF_MODEL_SERVICES, key_bytes) {
                                    if let Ok(reg) = serde_json::from_slice::<tenzro_network::ModelRegistrationMessage>(&data) {
                                        // Only restore non-withdrawn, non-expired entries
                                        if !reg.withdrawn {
                                            let model_key = key_str.trim_start_matches("net_model:").to_string();
                                            self.network_models.insert(model_key, NetworkModelEntry {
                                                registration: reg,
                                                last_seen: std::time::Instant::now(), // reset TTL
                                            });
                                            net_restored += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if net_restored > 0 {
                        info!("Restored {} network model endpoint(s) from RocksDB on startup", net_restored);
                    }
                }
                Err(e) => {
                    warn!("Failed to restore model services from CF_MODEL_SERVICES on startup: {}", e);
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // STARTUP RECONCILE: auto-reload served models from disk, evict stale
        // entries whose GGUF file is gone or that no longer match the catalog.
        // This fixes the "model listed as serving but runtime says not loaded"
        // gap that occurred after restarts, because CF_MODELS/CF_MODEL_SERVICES
        // survive process death but the in-memory ModelRuntime starts empty.
        // ═══════════════════════════════════════════════════════════════════════
        let (reloaded, cleared_models, cleared_services) =
            self.reconcile_model_registry().await;
        if reloaded > 0 || cleared_models > 0 || cleared_services > 0 {
            info!(
                "Startup reconcile: auto-reloaded {} model(s), cleared {} served flag(s), pruned {} endpoint(s)",
                reloaded, cleared_models, cleared_services,
            );
        }

        // ═══════════════════════════════════════════════════════════════════════
        // STARTUP: AgentRuntime::with_storage() and SwarmManager::with_storage()
        // already performed full hydration from CF_AGENTS above (agents,
        // lifecycles, spawn tree, swarms). Report the final counts so
        // operators can confirm rehydration succeeded.
        // ═══════════════════════════════════════════════════════════════════════
        if let Some(ref ar) = self.agent_runtime {
            let restored = ar.list_agents(None).len();
            if restored > 0 {
                info!(
                    "AgentRuntime restored {} agent(s) from CF_AGENTS on startup",
                    restored
                );
            }
        }
        if let Some(ref sm) = self.swarm_manager {
            let restored = sm.swarm_count();
            if restored > 0 {
                info!(
                    "SwarmManager restored {} swarm(s) from CF_AGENTS on startup",
                    restored
                );
            }
        }

        self.health_monitor.mark_healthy("ai");

        Ok(())
    }

    /// Auto-register Cortex (recurrent-depth) workers declared in `NodeConfig.cortex.workers`.
    ///
    /// Each entry builds an HTTP `SidecarModel` + `CortexWorker` and inserts it into
    /// `self.cortex_workers` so `tenzro_cortexInference` / the `cortex_reason` MCP tool
    /// can route requests to it without an explicit RPC registration step.
    ///
    /// Best-effort: workers whose construction fails are logged and skipped so a
    /// mis-configured sidecar cannot block the rest of node startup.
    async fn init_cortex_workers(&mut self) {
        use tenzro_cortex::{CortexWorker, PersistentCortexSigner, SidecarConfig, SidecarModel};
        use tenzro_crypto::signatures::Signer;
        use tenzro_types::cortex::{CortexModelFamily, CortexPricing, ReasoningTier};

        if !self.config.cortex.enabled {
            return;
        }
        if self.config.cortex.workers.is_empty() {
            info!("Cortex subsystem enabled but no workers configured");
            return;
        }

        info!(
            count = self.config.cortex.workers.len(),
            "Auto-registering configured Cortex workers"
        );

        for wc in &self.config.cortex.workers {
            let model_id = wc.model_id.clone();
            let family = CortexModelFamily {
                arch: wc.arch.clone(),
                max_loops: wc.max_loops,
                moe_experts: wc.moe_experts,
                experts_per_token: wc.experts_per_token,
                attn_type: wc.attn_type.clone(),
                supported_tiers: vec![
                    ReasoningTier::Fast,
                    ReasoningTier::Standard,
                    ReasoningTier::Deep,
                    ReasoningTier::Institutional,
                ],
            };

            let pricing: CortexPricing = wc
                .pricing
                .clone()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();

            let worker_did = wc
                .worker_did
                .clone()
                .unwrap_or_else(|| format!("did:tenzro:machine:cortex-{}", model_id));

            // Per-worker persistent Ed25519 signer. Keys are stored at
            // <data_dir>/cortex/<sanitized-model-id>.key with mode 0o600
            // on Unix, so `worker_did` remains stable across node restarts.
            let sanitized = model_id.replace(['/', ':'], "_");
            let key_path = self
                .config
                .data_dir
                .join("cortex")
                .join(format!("{}.key", sanitized));
            let signer: Arc<dyn Signer + Send + Sync> =
                match PersistentCortexSigner::load_or_generate(&key_path) {
                    Ok(s) => s.into_arc(),
                    Err(e) => {
                        warn!(
                            model_id = %model_id,
                            key_path = %key_path.display(),
                            "Skipping Cortex worker: failed to load/generate persistent signer: {e}"
                        );
                        continue;
                    }
                };
            let worker_address = Address::default();

            let cfg = SidecarConfig {
                base_url: wc.sidecar_url.clone(),
                timeout: std::time::Duration::from_secs(wc.timeout_secs),
                bearer_token: wc.bearer_token.clone(),
            };

            // Clone family + pricing so we can hand copies to the backend/worker
            // as well as to the advertisement broadcaster below.
            let family_for_backend = family.clone();
            let pricing_for_worker = pricing;

            let backend = match SidecarModel::new(
                model_id.clone(),
                family_for_backend,
                worker_did.clone(),
                worker_address,
                signer.clone(),
                cfg,
            ) {
                Ok(b) => Arc::new(b),
                Err(e) => {
                    warn!(
                        model_id = %model_id,
                        "Skipping Cortex worker: sidecar init failed: {e}"
                    );
                    continue;
                }
            };

            let worker = Arc::new(
                CortexWorker::new(
                    backend,
                    pricing_for_worker,
                    signer.clone(),
                    worker_did.clone(),
                    worker_address,
                )
                .with_metrics(self.cortex_metrics.clone()),
            );

            self.cortex_workers.insert(model_id.clone(), worker.clone());

            // Also advertise this worker in the shared ModelRegistry so
            // `tenzro_listModels` / discovery surfaces Cortex models alongside
            // llama.cpp-served models. Best-effort: a registry error is
            // logged but does not block startup.
            if let Some(ref registry) = self.model_registry {
                let info = cortex_model_info(&model_id, &worker, &wc.arch);
                if let Err(e) = registry.register_model(info) {
                    warn!(
                        model_id = %model_id,
                        "Failed to publish Cortex model in ModelRegistry: {e}"
                    );
                }
            }

            // Spawn a periodic advertisement broadcaster so peers can discover
            // this cortex worker over the `tenzro/cortex/1.0.0` gossipsub
            // topic. Requires libp2p `NetworkService` to be live — if the node
            // is running in single-process mode (e.g. an in-process test
            // harness with `network = None`) we skip the spawn and the worker
            // is only reachable via local RPC.
            if let Some(ref net) = self.network {
                use crate::cortex_gossip::NetworkCortexPublisher;
                let publisher_net: Arc<dyn tenzro_network::NetworkService> = net.clone();
                let publisher: Arc<dyn tenzro_cortex::CortexGossipPublisher> =
                    Arc::new(NetworkCortexPublisher::new(publisher_net));

                // Advertisement TTL/interval defaults — the cortex config
                // currently has no explicit fields for these, so pick
                // conservative values: re-advertise every 60s with a 120s TTL
                // so peers drop stale workers ~1 minute after a node
                // disappears.
                let ttl_secs: u64 = 120;
                let interval = std::time::Duration::from_secs(60);

                let broadcaster = tenzro_cortex::AdvertisementBroadcaster {
                    publisher,
                    signer: signer.clone(),
                    worker_did: worker_did.clone(),
                    worker_address,
                    model_id: model_id.clone(),
                    family: family.clone(),
                    pricing,
                    endpoint: Some(wc.sidecar_url.clone()),
                    ttl_secs,
                };

                let adv_model_id = model_id.clone();
                let adv_worker_did = worker_did.clone();
                tokio::spawn(async move {
                    // Brief startup delay so the gossipsub mesh has time to
                    // form before the first publish attempt.
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    loop {
                        match broadcaster.broadcast_once().await {
                            Ok(()) => {
                                debug!(
                                    model_id = %adv_model_id,
                                    worker_did = %adv_worker_did,
                                    "Published cortex advertisement to gossipsub"
                                );
                            }
                            Err(e) => {
                                warn!(
                                    model_id = %adv_model_id,
                                    worker_did = %adv_worker_did,
                                    error = %e,
                                    "Cortex advertisement broadcast failed"
                                );
                            }
                        }
                        tokio::time::sleep(interval).await;
                    }
                });

                info!(
                    model_id = %model_id,
                    worker_did = %worker_did,
                    ttl_secs = ttl_secs,
                    interval_secs = interval.as_secs(),
                    "Spawned cortex advertisement broadcaster"
                );
            } else {
                debug!(
                    model_id = %model_id,
                    "Skipping cortex advertisement broadcaster (no NetworkService)"
                );
            }

            info!(
                model_id = %model_id,
                worker_did = %worker_did,
                sidecar = %wc.sidecar_url,
                "Cortex worker auto-registered from config"
            );
        }
    }

    async fn init_bridge(&mut self) -> Result<()> {
        info!("Initializing bridge router...");

        let bridge_router = Arc::new(BridgeRouter::new());
        let bridge_cfg = &self.config.bridge;

        if !bridge_cfg.enabled {
            info!("Bridge subsystem disabled — router initialized with no adapters");
            self.bridge_router = Some(bridge_router);
            self.health_monitor.mark_healthy("bridge");
            return Ok(());
        }

        // LayerZero V2 adapter
        if let Some(lz_cfg) = &bridge_cfg.layerzero {
            if lz_cfg.enabled {
                // LayerZero V2 EndpointV2 address is the same across all EVM chains
                let lz_config = LayerZeroConfig::new(
                    "0x1a44076050125825900e736c501f859c50fE728c",
                    30101, // default to ethereum EID; operators override via peers
                    "0x0000000000000000000000000000000000000001",
                    "0x0000000000000000000000000000000000000002",
                );
                let mut adapter = LayerZeroAdapter::new(lz_config);

                match lz_cfg.resolve_private_key() {
                    Ok(Some(pk_hex)) => {
                        let signer_cfg = EvmSignerConfig::custom(
                            pk_hex,
                            lz_cfg.chain_id,
                            lz_cfg.rpc_url.clone(),
                        );
                        match signer_cfg.build() {
                            Ok(signer) => {
                                info!(
                                    "LayerZero signer configured: chain_id={}, sender={}",
                                    lz_cfg.chain_id, signer.sender_address()
                                );
                                adapter = adapter.with_signer(signer);
                            }
                            Err(e) => warn!("LayerZero signer build failed: {} — adapter will be quote-only", e),
                        }
                    }
                    Ok(None) => info!("LayerZero adapter registered without signer (quote-only)"),
                    Err(e) => warn!("LayerZero signer config error: {}", e),
                }

                bridge_router.register_adapter("layerzero", Box::new(adapter)).await;
                info!("Registered LayerZero V2 bridge adapter");
            }
        }

        // Chainlink CCIP adapter
        if let Some(ccip_cfg) = &bridge_cfg.ccip {
            if ccip_cfg.enabled {
                let mut adapter = ChainlinkCcipAdapter::new(
                    CcipConfig::ethereum_mainnet(FeeToken::Native),
                );

                match ccip_cfg.resolve_private_key() {
                    Ok(Some(pk_hex)) => {
                        let signer_cfg = EvmSignerConfig::custom(
                            pk_hex,
                            ccip_cfg.chain_id,
                            ccip_cfg.rpc_url.clone(),
                        );
                        match signer_cfg.build() {
                            Ok(signer) => {
                                info!(
                                    "CCIP signer configured: chain_id={}, sender={}",
                                    ccip_cfg.chain_id, signer.sender_address()
                                );
                                adapter = adapter.with_signer(signer);
                            }
                            Err(e) => warn!("CCIP signer build failed: {} — adapter will be quote-only", e),
                        }
                    }
                    Ok(None) => info!("CCIP adapter registered without signer (quote-only)"),
                    Err(e) => warn!("CCIP signer config error: {}", e),
                }

                bridge_router.register_adapter("ccip", Box::new(adapter)).await;
                info!("Registered Chainlink CCIP bridge adapter");
            }
        }

        // deBridge DLN adapter
        if let Some(db_cfg) = &bridge_cfg.debridge {
            if db_cfg.enabled {
                let debridge_config = DeBridgeConfig::new(
                    "https://dln.debridge.finance",
                    db_cfg.chain_id,
                    "0x0000000000000000000000000000000000000000",
                    "0x0000000000000000000000000000000000000000",
                );
                let mut adapter = DeBridgeAdapter::new(debridge_config);

                match db_cfg.resolve_private_key() {
                    Ok(Some(pk_hex)) => {
                        let signer_cfg = EvmSignerConfig::custom(
                            pk_hex,
                            db_cfg.chain_id,
                            db_cfg.rpc_url.clone(),
                        );
                        match signer_cfg.build() {
                            Ok(signer) => {
                                info!(
                                    "deBridge signer configured: chain_id={}, sender={}",
                                    db_cfg.chain_id, signer.sender_address()
                                );
                                adapter = adapter.with_signer(signer);
                            }
                            Err(e) => warn!("deBridge signer build failed: {} — adapter will be quote-only", e),
                        }
                    }
                    Ok(None) => info!("deBridge adapter registered without signer (quote-only)"),
                    Err(e) => warn!("deBridge signer config error: {}", e),
                }

                bridge_router.register_adapter("debridge", Box::new(adapter)).await;
                info!("Registered deBridge DLN bridge adapter");
            }
        }

        self.bridge_router = Some(bridge_router);
        self.health_monitor.mark_healthy("bridge");

        Ok(())
    }

    async fn init_identity(&mut self) -> Result<()> {
        info!("Initializing identity registry (TDIP)...");

        let mut registry = if let Some(storage) = &self.storage {
            info!("Identity registry initialized with persistent RocksDB storage");
            IdentityRegistry::with_storage(storage.clone() as Arc<dyn KvStore>)
        } else {
            warn!("Identity registry initialized without persistent storage — data will be lost on restart");
            IdentityRegistry::new()
        };

        // Wire ERC-8004 auto-mirror: when a TDIP machine identity is
        // registered, write an `AgentRecord` straight into the precompile-
        // backed `Erc8004IdentityRegistry` so EVM contracts at 0x101a see
        // the agent immediately. Only wires if the VM precompile registry
        // was initialized (it is, in normal node bootstraps).
        if let Some(erc8004_identity) = self.erc8004_identity.clone() {
            let mirror = Arc::new(crate::erc8004_mirror::NativeErc8004Mirror::new(
                erc8004_identity,
            ));
            registry = registry.with_on_chain_agent_registry(mirror);
            info!("ERC-8004 auto-mirror wired: TDIP machine registrations replicate to 0x101a");
        }

        self.identity_registry = Some(Arc::new(registry));
        self.health_monitor.mark_healthy("identity");

        Ok(())
    }

    async fn init_payments(&mut self) -> Result<()> {
        info!("Initializing payment gateway (MPP/x402/Visa TAP/Mastercard Agent Pay)...");

        let gateway = if let Some(ref storage) = self.storage {
            info!("Payment gateway initialized with persistent storage");
            TenzroPaymentGateway::with_storage(storage.clone() as Arc<dyn KvStore>)
        } else {
            warn!("Payment gateway initialized without persistent storage — challenges will be lost on restart");
            TenzroPaymentGateway::new()
        };
        let challenge_store = gateway.challenge_store();

        // Register MPP protocol server (session-based streaming payments)
        let mpp_server = MppPaymentServer::new("0x0000000000000000000000000000000000000001")
            .with_default_asset("USDC")
            .with_default_chain("tenzro")
            .with_challenge_store(challenge_store.clone());
        gateway.register_protocol(Arc::new(mpp_server));

        // Register x402 protocol server (stateless one-shot payments)
        let x402_server = Arc::new(
            X402PaymentServer::new(
                "0x0000000000000000000000000000000000000001",
                vec!["tenzro".to_string(), "base".to_string(), "ethereum".to_string()],
            )
            .with_default_asset("USDC")
            .with_challenge_store(challenge_store.clone()),
        );
        gateway.register_protocol(x402_server.clone());
        self.x402_server = Some(x402_server);

        // Register Visa TAP server (RFC 9421 HTTP Message Signatures)
        #[cfg(feature = "visa-tap")]
        {
            use tenzro_payments::visa_tap::VisaTapServer;
            let visa_tap_server = VisaTapServer::new(
                "0x0000000000000000000000000000000000000001",
                "api.tenzro.network",
            )
            .with_default_asset("TNZO")
            .with_default_chain("tenzro")
            .with_challenge_store(challenge_store.clone());
            gateway.register_protocol(Arc::new(visa_tap_server));
            info!("Registered Visa TAP payment protocol");
        }

        // Register Mastercard Agent Pay server (KYA + agentic tokens)
        #[cfg(feature = "mastercard-agent-pay")]
        {
            use tenzro_payments::mastercard::MastercardAgentPayServer;
            let mastercard_server = MastercardAgentPayServer::new(
                "0x0000000000000000000000000000000000000001",
                "tenzro-network",
            )
            .with_default_asset("TNZO")
            .with_default_chain("tenzro")
            .with_challenge_store(challenge_store.clone());
            gateway.register_protocol(Arc::new(mastercard_server));
            info!("Registered Mastercard Agent Pay payment protocol");
        }

        info!("Registered payment protocols: {:?}", gateway.supported_protocols());

        // Wire on-chain settlement callback (TNZO token transfer + settlement engine recording)
        let gateway = if let (Some(token), Some(settlement)) =
            (self.token.clone(), self.settlement.clone())
        {
            let callback = Arc::new(TnzoSettlementCallback::new(token, settlement));
            info!("Payment gateway wired to on-chain settlement (TNZO token + SettlementEngine)");
            gateway.with_settlement_callback(callback)
        } else {
            warn!("Payment gateway initialized without on-chain settlement — token or settlement engine not available");
            gateway
        };

        self.payment_gateway = Some(Arc::new(gateway));
        self.health_monitor.mark_healthy("payments");

        Ok(())
    }

    /// Initializes the AgentKit runtime and bootstraps reference templates.
    /// Non-fatal: logs warnings on failure so the node still starts.
    async fn bootstrap_agent_templates(&mut self) {
        let rpc_addr = if self.config.rpc_addr.is_empty() {
            "127.0.0.1:8545".to_string()
        } else {
            self.config.rpc_addr.clone()
        };
        let rpc_url = format!("http://{rpc_addr}");

        // Build the AgentKit instance if both identity_registry and agent_runtime are available.
        if let (Some(identity_registry), Some(agent_runtime)) =
            (self.identity_registry.clone(), self.agent_runtime.clone())
        {
            let kit = tenzro_agent_kit::AgentKit::new(
                rpc_url.clone(),
                identity_registry,
                agent_runtime,
            );
            self.agent_kit = Some(Arc::new(kit));
            info!("AgentKit runtime initialized");
        } else {
            tracing::warn!(
                "AgentKit not initialized: identity_registry or agent_runtime unavailable"
            );
        }

        // Bootstrap reference templates (idempotent).
        let registry = std::sync::Arc::new(tenzro_agent_kit::RegistryClient::new(rpc_url));
        match tenzro_agent_kit::bootstrap_reference_templates(&registry).await {
            Ok(report) => {
                if !report.published.is_empty() {
                    info!(
                        published = report.published.len(),
                        skipped = report.skipped.len(),
                        "Bootstrapped reference agent templates"
                    );
                } else {
                    tracing::debug!(
                        skipped = report.skipped.len(),
                        "All reference agent templates already registered"
                    );
                }
                for (label, err) in &report.failed {
                    tracing::warn!(template = %label, error = %err, "Failed to bootstrap template");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Agent template bootstrap failed (non-fatal)");
            }
        }
    }

    /// Bootstrap ecosystem MCP server tools and skills into CF_TOOLS / CF_SKILLS.
    /// Idempotent: skips entries that already exist (matched by name).
    fn bootstrap_ecosystem_tools_and_skills(&self) {
        let storage = match self.storage.as_ref() {
            Some(s) => s,
            None => {
                tracing::warn!("Storage not available, skipping ecosystem tool/skill bootstrap");
                return;
            }
        };

        // ─── Tools (MCP servers) ───
        let tools: Vec<(&str, &str, &str, &str, &[&str])> = vec![
            // (name, tool_type, endpoint, description, capabilities)
            ("tenzro-solana-mcp", "mcp", "/mcp", "Solana blockchain tools — DeFi (Jupiter), tokens (SPL), NFTs (Metaplex), network queries", &["solana", "defi", "swap", "nft", "spl"]),
            ("tenzro-ethereum-mcp", "mcp", "/mcp", "Ethereum blockchain tools — DeFi, ERC-20/721, ENS, ERC-8004 agent registry, EAS attestations", &["ethereum", "defi", "erc20", "ens", "erc8004", "eas"]),
            ("tenzro-canton-mcp", "mcp", "/mcp", "Canton Network / DAML tools — smart contracts, parties, CIP-56 tokens, DvP settlement, tokenized assets", &["canton", "daml", "enterprise", "tokenization", "dvp"]),
            ("tenzro-layerzero-mcp", "mcp", "/mcp", "LayerZero V2 cross-chain messaging — fee quoting, message tracking, OFT transfers, DVN configuration", &["layerzero", "cross-chain", "bridge", "omnichain", "oft"]),
            ("tenzro-chainlink-mcp", "mcp", "/mcp", "Chainlink tools — CCIP cross-chain messaging, data feeds (price oracles), automation, functions", &["chainlink", "ccip", "oracle", "data-feeds", "automation"]),
            ("debridge-mcp", "mcp", "https://agents.debridge.com/mcp", "deBridge DLN cross-chain swaps — intent-based bridging, order creation, tracking. Official hosted MCP.", &["debridge", "cross-chain", "bridge", "dln", "swap"]),
            ("1inch-mcp", "mcp", "https://api.1inch.dev", "1inch DEX aggregator — swap across 400+ DEXes, Fusion+ cross-chain, portfolio tracking. Requires API key.", &["1inch", "dex", "aggregator", "swap", "defi", "fusion"]),
        ];

        let mut tool_registered = 0u32;
        let mut tool_skipped = 0u32;

        for (name, tool_type, endpoint, description, caps) in &tools {
            // Check if already exists by scanning for matching name
            let existing = storage.get_keys_with_prefix(CF_TOOLS, b"").ok().unwrap_or_default();
            let already_exists = existing.iter().any(|key| {
                if let Ok(Some(bytes)) = storage.get(CF_TOOLS, key) {
                    if let Ok(t) = serde_json::from_slice::<tenzro_types::ToolDefinition>(&bytes) {
                        return t.name == *name;
                    }
                }
                false
            });

            if already_exists {
                tool_skipped += 1;
                continue;
            }

            let category = if caps.contains(&"cross-chain") || caps.contains(&"bridge") {
                "bridge"
            } else if caps.contains(&"defi") || caps.contains(&"swap") || caps.contains(&"dex") {
                "defi"
            } else if caps.contains(&"enterprise") || caps.contains(&"daml") {
                "enterprise"
            } else if caps.contains(&"oracle") {
                "oracle"
            } else {
                "blockchain"
            };

            let mut tool = tenzro_types::ToolDefinition::new(
                name.to_string(),
                "0.1.0".to_string(),
                tool_type.to_string(),
                endpoint.to_string(),
                description.to_string(),
                category.to_string(),
            );
            tool.capabilities = caps.iter().map(|s| s.to_string()).collect();
            tool.creator_did = Some("did:tenzro:human:tenzro-network".to_string());

            if let Ok(bytes) = serde_json::to_vec(&tool) {
                if storage.put(CF_TOOLS, tool.tool_id.as_bytes(), &bytes).is_ok() {
                    tool_registered += 1;
                }
            }
        }

        // ─── Skills ───
        let skills: Vec<(&str, &str, &[&str], &str)> = vec![
            // (name, description, tags, category)
            ("solana-defi", "Solana DeFi — swap via Jupiter, get prices, stake SOL, query balances, transfer SPL tokens, browse NFTs via Metaplex DAS, resolve .sol domains", &["solana", "defi", "swap", "jupiter", "nft", "metaplex", "spl", "staking"], "defi"),
            ("ethereum-defi", "Ethereum DeFi — query balances, Chainlink prices, estimate gas, resolve ENS, call smart contracts, ABI-encode, ERC-8004 agent registry, EAS attestations", &["ethereum", "defi", "erc20", "ens", "chainlink", "erc8004", "eas", "smart_contracts"], "defi"),
            ("canton-enterprise", "Canton enterprise — DAML contracts, party management, CIP-56 tokens, tokenized assets, atomic DvP settlement, DAR uploads", &["canton", "daml", "enterprise", "tokenization", "dvp", "cip56", "rwa", "institutional"], "enterprise"),
            ("layerzero-bridge", "LayerZero V2 cross-chain — quote messaging fees, send omnichain messages, track delivery, OFT transfers, list DVNs, encode options", &["layerzero", "cross-chain", "bridge", "omnichain", "oft", "messaging"], "bridge"),
            ("chainlink-oracle", "Chainlink — CCIP cross-chain messaging, price data feeds, automation upkeeps, Functions (DON serverless)", &["chainlink", "ccip", "cross-chain", "oracle", "data-feeds", "automation", "functions"], "oracle"),
            ("debridge-cross-chain", "deBridge DLN — intent-based cross-chain bridging, get quotes, create orders, track status, list supported chains/tokens", &["debridge", "cross-chain", "bridge", "dln", "intent", "swap"], "bridge"),
            ("oneinch-aggregator", "1inch DEX aggregator — swap tokens across 400+ DEXes, get quotes, check approvals, Fusion+ cross-chain, portfolio tracking", &["1inch", "dex", "aggregator", "swap", "defi", "fusion", "cross-chain"], "defi"),
        ];

        let mut skill_registered = 0u32;
        let mut skill_skipped = 0u32;

        for (name, description, tags, category) in &skills {
            let existing = storage.get_keys_with_prefix(CF_SKILLS, b"").ok().unwrap_or_default();
            let already_exists = existing.iter().any(|key| {
                if let Ok(Some(bytes)) = storage.get(CF_SKILLS, key) {
                    if let Ok(s) = serde_json::from_slice::<tenzro_types::SkillDefinition>(&bytes) {
                        return s.name == *name;
                    }
                }
                false
            });

            if already_exists {
                skill_skipped += 1;
                continue;
            }

            let mut skill = tenzro_types::SkillDefinition::new(
                name.to_string(),
                "0.1.0".to_string(),
                "did:tenzro:human:tenzro-network".to_string(),
                description.to_string(),
                0, // free for now
            );
            skill.tags = tags.iter().map(|s| s.to_string()).collect();
            skill.category = category.to_string();

            if let Ok(bytes) = serde_json::to_vec(&skill) {
                if storage.put(CF_SKILLS, skill.skill_id.as_bytes(), &bytes).is_ok() {
                    skill_registered += 1;
                }
            }
        }

        if tool_registered > 0 || skill_registered > 0 {
            info!(
                tools_registered = tool_registered,
                tools_skipped = tool_skipped,
                skills_registered = skill_registered,
                skills_skipped = skill_skipped,
                "Bootstrapped ecosystem tools and skills"
            );
        } else {
            tracing::debug!(
                tools_skipped = tool_skipped,
                skills_skipped = skill_skipped,
                "All ecosystem tools and skills already registered"
            );
        }
    }

    async fn init_event_loop(&mut self) -> Result<()> {
        info!("Initializing event loop...");

        // Ensure required subsystems are initialized
        let storage = self.storage.as_ref()
            .ok_or_else(|| NodeError::Internal("Storage not initialized".to_string()))?
            .clone();

        let vm_runtime = self.vm_runtime.as_ref()
            .ok_or_else(|| NodeError::Internal("VM runtime not initialized".to_string()))?
            .clone();

        // Create event loop with optional consensus and network.
        // Pass the shared chain_tip atomic so the event loop can update it on
        // every finalized block — enabling lock-free RPC reads via chain_tip_height().
        let event_loop = EventLoop::new(
            storage,
            vm_runtime,
            self.consensus.clone(),
            self.network.clone(),
            self.chain_tip.clone(),
            self.metrics.clone(),
        );

        // Wire outbound consensus messages into the event loop so that votes
        // and proposals produced by HotStuff-2 are broadcast over gossipsub.
        // `take()` ensures the RX is consumed exactly once.
        let event_loop = if let Some(rx) = self.consensus_out_rx.take() {
            event_loop.with_consensus_out_rx(rx)
        } else {
            event_loop
        };

        // Wire model services for periodic cleanup of expired network endpoints
        let event_loop = event_loop.with_model_services(self.model_services.clone());

        // Wire ModelRuntime + LoadTracker into the event loop so the heartbeat
        // can run the 1-hour idle TTL reconciler against live runtime state.
        let event_loop = if let Some(ref runtime) = self.model_runtime {
            event_loop.with_model_runtime(runtime.clone(), self.load_tracker.clone())
        } else {
            event_loop
        };

        // Wire model discovery state into the event loop for P2P model announcements
        let event_loop = event_loop.with_model_discovery(
            self.network_models.clone(),
            self.served_models.clone(),
            self.provider_pricing.clone(),
            self.provider_schedule.clone(),
            self.config.rpc_addr.clone(),
        );

        // Wire agent runtime into event loop for gossipsub agent heartbeat announcements
        let event_loop = if let Some(ref ar) = self.agent_runtime {
            event_loop.with_agent_runtime(ar.clone())
        } else {
            event_loop
        };

        // Wire swarm manager into event loop for periodic liveness sweep.
        let event_loop = if let Some(ref sm) = self.swarm_manager {
            event_loop.with_swarm_manager(sm.clone())
        } else {
            event_loop
        };

        // Wire network_agents map for gossipsub-discovered agent merging
        let event_loop = event_loop.with_agent_discovery(self.network_agents.clone());

        // Wire network_providers map for gossipsub-discovered provider merging
        let event_loop = event_loop.with_provider_discovery(self.network_providers.clone());

        // Wire the shared RemoteWorkerRegistry so the event loop can ingest verified
        // Cortex advertisements received over the tenzro/cortex/1.0.0 gossipsub topic.
        let event_loop = event_loop.with_cortex_registry(self.remote_cortex_workers.clone());

        // Store the event sender for RPC to submit transactions
        self.event_loop_tx = Some(event_loop.event_sender());

        // Log the startup chain state using the event loop's chain-tip getters.
        // These calls produce valuable observability on every node restart and ensure
        // the getters are exercised at runtime rather than just sitting unused.
        {
            let initial_height = event_loop.current_height();
            let initial_hash = event_loop.last_block_hash();
            let initial_state_root = event_loop.state_adapter().lock().await.compute_state_root();
            info!(
                height = initial_height.0,
                last_hash = %initial_hash,
                state_root = %initial_state_root,
                "Event loop initialized, resuming from stored chain tip"
            );
        }

        // Wire block sync: subscribe to gossipsub blocks topic and forward to event loop.
        // This follows the same pattern as the agent gossipsub bridge (init_ai_infrastructure).
        // All nodes subscribe — validators will receive their own blocks back from gossipsub
        // but the event loop's height check will skip duplicates.
        if let Some(ref network) = self.network {
            let event_tx = event_loop.event_sender();
            let net_in = network.clone();
            tokio::spawn(async move {
                match net_in.subscribe("tenzro/blocks/1.0.0").await {
                    Ok(mut rx) => {
                        tracing::info!("Block sync: subscribed to tenzro/blocks/1.0.0");
                        while let Some(msg) = rx.recv().await {
                            if let tenzro_network::MessagePayload::Block(block) = msg.payload {
                                let height = block.height();
                                tracing::debug!(height = %height, "Received block from gossipsub");
                                if let Err(e) = event_tx.send(NodeEvent::NetworkBlock(block)).await {
                                    tracing::error!("Failed to forward network block to event loop: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to subscribe to blocks gossipsub topic: {}", e);
                    }
                }
            });
            info!("Block sync wired to gossipsub (tenzro/blocks/1.0.0)");

            // Wire status gossip: subscribe to tenzro/status/1.0.0 and feed
            // peer heights into the PeerStatusTracker so eth_syncing /
            // tenzro_syncing can report a real network-tip estimate.
            //
            // Outbound: every 10s broadcast our own StatusMessage with the
            // current chain tip. The PeerStatusTracker drops entries from
            // peers whose chain_id doesn't match (silent), so cross-chain
            // noise can't poison the estimate.
            {
                use std::str::FromStr;
                let net_status = network.clone();
                let peer_status_tracker = self.peer_status.clone();
                let local_chain_id = self
                    .config
                    .genesis
                    .as_ref()
                    .map(|g| g.chain_id)
                    .unwrap_or(1337);
                tokio::spawn(async move {
                    let mut rx = match net_status.subscribe("tenzro/status/1.0.0").await {
                        Ok(rx) => rx,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Failed to subscribe to status gossipsub topic"
                            );
                            return;
                        }
                    };
                    tracing::info!("Status sync: subscribed to tenzro/status/1.0.0");
                    while let Some(msg) = rx.recv().await {
                        if let tenzro_network::MessagePayload::Status(status) = msg.payload {
                            // Drop messages from a different chain — defense
                            // against cross-chain gossip leak. Tracker also
                            // re-checks this, but doing it here keeps the log
                            // signal cleaner.
                            if status.chain_id != local_chain_id {
                                continue;
                            }
                            let peer_id = match libp2p::PeerId::from_str(&status.peer_id) {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::debug!(
                                        peer = %status.peer_id,
                                        error = %e,
                                        "Dropping StatusMessage with malformed peer_id"
                                    );
                                    continue;
                                }
                            };
                            tracing::trace!(
                                peer = %peer_id,
                                height = status.height,
                                "Recorded peer status"
                            );
                            peer_status_tracker.record(peer_id, status.height, status.chain_id);
                        }
                    }
                });
                info!("Status sync wired to gossipsub (tenzro/status/1.0.0)");
            }

            // Outbound status broadcast tick: every 10s, broadcast our own
            // best block + height so peers can track our chain tip.
            {
                let net_out = network.clone();
                let chain_tip_atomic = self.chain_tip.clone();
                let peer_status_tracker = self.peer_status.clone();
                let local_chain_id = self
                    .config
                    .genesis
                    .as_ref()
                    .map(|g| g.chain_id)
                    .unwrap_or(1337);
                let protocol_version = format!("tenzro/{}", env!("CARGO_PKG_VERSION"));
                tokio::spawn(async move {
                    // Resolve our local PeerId once (the network service spawns
                    // its own swarm task, so the PeerId is stable for the
                    // lifetime of the process).
                    let local_peer_id = match net_out.local_peer_id().await {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Status broadcast: failed to resolve local PeerId; aborting"
                            );
                            return;
                        }
                    };
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    // Skip the immediate fire so we don't broadcast height=0
                    // before the chain tip has been hydrated from storage.
                    tick.tick().await;
                    loop {
                        tick.tick().await;
                        // Periodically prune stale entries from the tracker
                        // so the map stays bounded as peers drop off.
                        peer_status_tracker.prune_stale();

                        let height = chain_tip_atomic.load(std::sync::atomic::Ordering::Acquire);
                        let status = tenzro_network::StatusMessage {
                            peer_id: local_peer_id.to_string(),
                            best_block: tenzro_types::Hash::zero(),
                            height,
                            chain_id: local_chain_id,
                            protocol_version: protocol_version.clone(),
                        };
                        let msg = tenzro_network::NetworkMessage::new(
                            tenzro_network::MessagePayload::Status(status),
                        );
                        if let Err(e) = net_out.broadcast("tenzro/status/1.0.0", msg).await {
                            tracing::debug!(
                                error = %e,
                                "Status broadcast failed (likely no mesh peers yet)"
                            );
                        }
                    }
                });
                info!("Status broadcast wired (every 10s on tenzro/status/1.0.0)");
            }

            // Wire inbound consensus: subscribe to gossipsub consensus topic and dispatch
            // proposals + votes into the local HotStuff-2 engine.
            //
            // Without this bridge, every validator only sees its own self-vote produced
            // by `consensus.on_proposal()`. Quorum threshold (2f+1 = 3 of 4) can never be
            // reached, so block height stays at 0 forever. The outbound side already
            // exists (event_loop.rs:849-907) — this is the missing inbound counterpart.
            //
            // Gossipsub echoes our own broadcasts back to us. We filter those by
            // comparing proposer/voter against `local_validator_address` to avoid:
            //   - re-invoking `on_proposal()` on our own block (would generate a
            //     duplicate vote and could trip phase-state assertions),
            //   - re-feeding our own vote into the collector (the collector would
            //     dedupe but we'd still pay deserialization cost on every echo).
            if let (Some(consensus), Some(local_addr)) =
                (self.consensus.clone(), self.local_validator_address)
            {
                let net_consensus = network.clone();
                tokio::spawn(async move {
                    let mut rx = match net_consensus.subscribe("tenzro/consensus/1.0.0").await {
                        Ok(rx) => rx,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Failed to subscribe to consensus gossipsub topic"
                            );
                            return;
                        }
                    };
                    tracing::info!(
                        local = %hex::encode(local_addr.as_bytes()),
                        "Consensus inbound: subscribed to tenzro/consensus/1.0.0"
                    );
                    while let Some(msg) = rx.recv().await {
                        let consensus_msg = match msg.payload {
                            tenzro_network::MessagePayload::Consensus(c) => c,
                            _ => continue,
                        };
                        match consensus_msg {
                            tenzro_network::ConsensusMessage::Proposal {
                                block,
                                proposer,
                                round,
                                high_qc_view,
                                timeout_certificate,
                            } => {
                                // Decode hex proposer → Address. On malformed input,
                                // log and drop — the proposer field is informational
                                // for the self-loop filter; the engine doesn't rely
                                // on it for proposal admission.
                                let proposer_addr = match hex::decode(&proposer)
                                    .ok()
                                    .and_then(|b| Address::from_bytes(&b))
                                {
                                    Some(a) => a,
                                    None => {
                                        tracing::warn!(
                                            proposer = %proposer,
                                            "Dropping consensus proposal with malformed proposer address"
                                        );
                                        continue;
                                    }
                                };
                                if proposer_addr == local_addr {
                                    // Echo of our own proposal — already processed
                                    // locally by the engine; skip.
                                    continue;
                                }
                                // Decode the optional TC. A bincode failure here
                                // means the proposer attached a malformed TC —
                                // drop the proposal entirely rather than vote on
                                // an unverified view jump.
                                let tc = match timeout_certificate
                                    .as_deref()
                                    .map(bincode::deserialize::<tenzro_consensus::TimeoutCertificate>)
                                {
                                    None => None,
                                    Some(Ok(tc)) => Some(tc),
                                    Some(Err(e)) => {
                                        tracing::warn!(
                                            proposer = %hex::encode(proposer_addr.as_bytes()),
                                            error = %e,
                                            "Dropping proposal with malformed TC"
                                        );
                                        continue;
                                    }
                                };
                                let height = block.height();
                                tracing::debug!(
                                    height = %height,
                                    round = round,
                                    proposer = %hex::encode(proposer_addr.as_bytes()),
                                    has_tc = tc.is_some(),
                                    "Received consensus proposal from peer"
                                );
                                match consensus.on_proposal(&block, tc, high_qc_view).await {
                                    Ok(_vote) => {
                                        // The vote is also emitted on `consensus_out_rx`
                                        // by the engine, which the event loop picks up
                                        // and broadcasts on the consensus topic. We do
                                        // not need to broadcast it here.
                                        tracing::debug!(
                                            height = %height,
                                            "Voted on peer proposal"
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            height = %height,
                                            error = %e,
                                            "Failed to handle peer proposal"
                                        );
                                    }
                                }
                            }
                            tenzro_network::ConsensusMessage::Vote {
                                block_hash,
                                voter,
                                vote_type,
                                round,
                                height,
                                high_qc_view,
                                signature,
                                public_key,
                            } => {
                                let voter_addr = match hex::decode(&voter)
                                    .ok()
                                    .and_then(|b| Address::from_bytes(&b))
                                {
                                    Some(a) => a,
                                    None => {
                                        tracing::warn!(
                                            voter = %voter,
                                            "Dropping consensus vote with malformed voter address"
                                        );
                                        continue;
                                    }
                                };
                                if voter_addr == local_addr {
                                    // Echo of our own vote — collector would dedupe
                                    // anyway; skip the deserialization cost.
                                    continue;
                                }
                                let sig: tenzro_crypto::composite::CompositeSignature =
                                    match bincode::deserialize(&signature) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::warn!(
                                                voter = %hex::encode(voter_addr.as_bytes()),
                                                error = %e,
                                                "Dropping vote: failed to bincode-decode CompositeSignature"
                                            );
                                            continue;
                                        }
                                    };
                                let pk: tenzro_crypto::composite::CompositePublicKey =
                                    match bincode::deserialize(&public_key) {
                                        Ok(p) => p,
                                        Err(e) => {
                                            tracing::warn!(
                                                voter = %hex::encode(voter_addr.as_bytes()),
                                                error = %e,
                                                "Dropping vote: failed to bincode-decode CompositePublicKey"
                                            );
                                            continue;
                                        }
                                    };
                                let cons_vote_type = match vote_type {
                                    tenzro_network::VoteType::Prevote => {
                                        tenzro_consensus::VoteType::Prepare
                                    }
                                    tenzro_network::VoteType::Precommit => {
                                        tenzro_consensus::VoteType::Commit
                                    }
                                };
                                let vote = tenzro_consensus::Vote::new(
                                    round,
                                    tenzro_types::primitives::BlockHeight(height),
                                    block_hash,
                                    voter_addr,
                                    sig,
                                    pk,
                                    cons_vote_type,
                                    high_qc_view,
                                );
                                tracing::debug!(
                                    height = height,
                                    round = round,
                                    voter = %hex::encode(voter_addr.as_bytes()),
                                    vote_type = ?cons_vote_type,
                                    "Received consensus vote from peer"
                                );
                                if let Err(e) = consensus.on_vote(&vote).await {
                                    // Equivocation errors are expected to be loud — the
                                    // engine logs + slashes. Other errors (NotStarted,
                                    // dedup-style) we just trace.
                                    tracing::warn!(
                                        height = height,
                                        error = %e,
                                        "on_vote rejected peer vote"
                                    );
                                }
                            }
                            tenzro_network::ConsensusMessage::Timeout {
                                format_version,
                                view,
                                high_qc_view,
                                voter,
                                signature,
                                public_key,
                            } => {
                                if voter == local_addr {
                                    // Echo of our own timeout — skip the deserialization cost.
                                    continue;
                                }
                                let sig: tenzro_crypto::composite::CompositeSignature =
                                    match bincode::deserialize(&signature) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::warn!(
                                                voter = %hex::encode(voter.as_bytes()),
                                                error = %e,
                                                "Dropping timeout: failed to bincode-decode CompositeSignature"
                                            );
                                            continue;
                                        }
                                    };
                                let pk: tenzro_crypto::composite::CompositePublicKey =
                                    match bincode::deserialize(&public_key) {
                                        Ok(p) => p,
                                        Err(e) => {
                                            tracing::warn!(
                                                voter = %hex::encode(voter.as_bytes()),
                                                error = %e,
                                                "Dropping timeout: failed to bincode-decode CompositePublicKey"
                                            );
                                            continue;
                                        }
                                    };
                                let timeout_msg = tenzro_consensus::TimeoutMsg {
                                    format_version,
                                    view,
                                    high_qc_view,
                                    voter,
                                    signature: sig,
                                    public_key: pk,
                                };
                                tracing::debug!(
                                    view = view,
                                    voter = %hex::encode(voter.as_bytes()),
                                    "Received pacemaker TimeoutMsg from peer"
                                );
                                if let Err(e) = consensus.on_timeout_msg(&timeout_msg).await {
                                    // on_timeout_msg rejects unknown voters,
                                    // bad signatures, format-version mismatches.
                                    // Log and move on — pacemaker is best-effort.
                                    tracing::warn!(
                                        view = view,
                                        error = %e,
                                        "on_timeout_msg rejected peer timeout"
                                    );
                                }
                            }
                            tenzro_network::ConsensusMessage::Commit { .. } => {
                                // Commit messages are not currently consumed by the
                                // engine — finality is driven by QC formation in the
                                // vote collector. Drop silently.
                            }
                        }
                    }
                });
                info!("Consensus inbound wired to gossipsub (tenzro/consensus/1.0.0)");
            } else {
                // Non-validator nodes (LightClient, ModelProvider without consensus)
                // skip this wiring entirely — they have nothing to vote with.
                tracing::debug!(
                    "Skipping consensus inbound wiring: no consensus engine on this node"
                );
            }

            // Wire model discovery: subscribe to gossipsub models topic and forward to event loop.
            // This enables decentralized P2P model discovery — no centralized registry required.
            let event_tx_models = event_loop.event_sender();
            let net_models = network.clone();
            tokio::spawn(async move {
                match net_models.subscribe("tenzro/models/1.0.0").await {
                    Ok(mut rx) => {
                        tracing::info!("Model discovery: subscribed to tenzro/models/1.0.0");
                        while let Some(msg) = rx.recv().await {
                            if let tenzro_network::MessagePayload::ModelRegistration(reg) = msg.payload {
                                if let Err(e) = event_tx_models.send(NodeEvent::ModelAnnouncement(reg)).await {
                                    tracing::error!("Failed to forward model announcement to event loop: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to subscribe to models gossipsub topic: {}", e);
                    }
                }
            });
            info!("Model discovery wired to gossipsub (tenzro/models/1.0.0)");

            // Wire agent discovery: subscribe to gossipsub agents topic and forward to event loop.
            // This enables decentralized P2P agent discovery — every node learns about every agent
            // on the network via gossipsub heartbeats, with no central registry required.
            let event_tx_agents = event_loop.event_sender();
            let net_agents = network.clone();
            tokio::spawn(async move {
                match net_agents.subscribe("tenzro/agents/1.0.0").await {
                    Ok(mut rx) => {
                        tracing::info!("Agent discovery: subscribed to tenzro/agents/1.0.0");
                        while let Some(msg) = rx.recv().await {
                            if let tenzro_network::MessagePayload::AgentAnnouncement(ann) = msg.payload {
                                if let Err(e) = event_tx_agents.send(NodeEvent::AgentAnnouncement(ann)).await {
                                    tracing::error!("Failed to forward agent announcement to event loop: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to subscribe to agents gossipsub topic: {}", e);
                    }
                }
            });
            info!("Agent discovery wired to gossipsub (tenzro/agents/1.0.0)");

            // Wire provider discovery: subscribe to gossipsub providers topic and forward to event loop.
            // This enables decentralized P2P provider discovery — every node learns about every provider
            // on the network via gossipsub heartbeats, with no central registry required.
            let event_tx_providers = event_loop.event_sender();
            let net_providers = network.clone();
            tokio::spawn(async move {
                match net_providers.subscribe("tenzro/providers/1.0.0").await {
                    Ok(mut rx) => {
                        tracing::info!("Provider discovery: subscribed to tenzro/providers/1.0.0");
                        while let Some(msg) = rx.recv().await {
                            if let tenzro_network::MessagePayload::ProviderAnnouncement(ann) = msg.payload {
                                if let Err(e) = event_tx_providers.send(NodeEvent::ProviderAnnouncement(ann)).await {
                                    tracing::error!("Failed to forward provider announcement to event loop: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to subscribe to providers gossipsub topic: {}", e);
                    }
                }
            });
            info!("Provider discovery wired to gossipsub (tenzro/providers/1.0.0)");

            // Wire cortex advertisement discovery: subscribe to gossipsub cortex topic
            // and forward opaque payloads to the event loop for signature verification
            // and ingestion into the RemoteWorkerRegistry. Cortex advertisements are
            // serialized as JSON and carried over the generic MessagePayload::Custom
            // envelope so no cortex-specific knowledge is required in the networking
            // layer.
            let event_tx_cortex = event_loop.event_sender();
            let net_cortex = network.clone();
            tokio::spawn(async move {
                match net_cortex.subscribe(tenzro_cortex::CORTEX_TOPIC).await {
                    Ok(mut rx) => {
                        tracing::info!(
                            topic = tenzro_cortex::CORTEX_TOPIC,
                            "Cortex discovery: subscribed to gossipsub topic"
                        );
                        while let Some(msg) = rx.recv().await {
                            if let tenzro_network::MessagePayload::Custom { topic, data } = msg.payload {
                                if topic != tenzro_cortex::CORTEX_TOPIC {
                                    continue;
                                }
                                if let Err(e) = event_tx_cortex
                                    .send(NodeEvent::CortexAdvertisementReceived(data))
                                    .await
                                {
                                    tracing::error!(
                                        "Failed to forward cortex advertisement to event loop: {}",
                                        e
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            topic = tenzro_cortex::CORTEX_TOPIC,
                            error = %e,
                            "Failed to subscribe to cortex gossipsub topic"
                        );
                    }
                }
            });
            info!(
                topic = tenzro_cortex::CORTEX_TOPIC,
                "Cortex discovery wired to gossipsub"
            );
        }

        // Spawn the event loop in the background
        tokio::spawn(async move {
            if let Err(e) = event_loop.run().await {
                tracing::error!(error = %e, "Event loop error");
            }
        });

        self.health_monitor.mark_healthy("event_loop");
        info!("Event loop started");

        Ok(())
    }

    /// Returns the identity registry (TDIP) if initialized
    pub fn identity_registry(&self) -> Option<&Arc<IdentityRegistry>> {
        self.identity_registry.as_ref()
    }

    /// Returns the payment gateway if initialized
    pub fn payment_gateway(&self) -> Option<&Arc<TenzroPaymentGateway>> {
        self.payment_gateway.as_ref()
    }

    /// Returns the registered x402 payment server (with its scheme registry) if initialized.
    pub fn x402_server(&self) -> Option<&Arc<X402PaymentServer>> {
        self.x402_server.as_ref()
    }

    /// Returns the model registry if initialized
    pub fn model_registry(&self) -> Option<&Arc<ModelRegistry>> {
        self.model_registry.as_ref()
    }

    /// Returns the provider manager if initialized
    /// Public API method for external use
    #[allow(dead_code)]
    pub fn provider_manager(&self) -> Option<&Arc<ProviderManager>> {
        self.provider_manager.as_ref()
    }

    /// Returns the inference router if initialized
    /// Public API method for external use
    #[allow(dead_code)]
    pub fn inference_router(&self) -> Option<&Arc<InferenceRouter>> {
        self.inference_router.as_ref()
    }

    /// Returns the durable usage tracker, the producer-side recipient of
    /// every successful inference's `UsageRecord`. Used by the
    /// `tenzro_listInferenceUsage` and `tenzro_getProviderReputation`
    /// RPC handlers to surface marketplace observability data.
    pub fn usage_tracker(&self) -> Option<&Arc<tenzro_model::UsageTracker>> {
        self.usage_tracker.as_ref()
    }

    /// Returns the EU AI Act Art. 50(2) provenance store. Populated by the
    /// inference router on every successful response and queried by the
    /// `tenzro_getProvenance` RPC handler.
    pub fn provenance_store(&self) -> Option<&Arc<tenzro_model::ProvenanceStore>> {
        self.provenance_store.as_ref()
    }

    /// Returns the event loop sender for submitting transactions
    pub fn event_sender(&self) -> Option<&mpsc::Sender<NodeEvent>> {
        self.event_loop_tx.as_ref()
    }

    /// Returns the storage backend if initialized
    pub fn storage(&self) -> Option<&Arc<RocksDbStore>> {
        self.storage.as_ref()
    }

    /// Returns the staking manager if initialized
    pub fn staking(&self) -> Option<&Arc<StakingManager>> {
        self.staking.as_ref()
    }

    /// Returns the token if initialized
    pub fn token(&self) -> Option<&Arc<TnzoToken>> {
        self.token.as_ref()
    }

    /// Returns the unified token registry if initialized
    pub fn token_registry(&self) -> Option<&Arc<TokenRegistry>> {
        self.token_registry.as_ref()
    }

    /// Returns the VM runtime if initialized
    pub fn vm_runtime(&self) -> Option<&Arc<MultiVmRuntime>> {
        self.vm_runtime.as_ref()
    }

    /// Returns the wallet service if initialized
    pub fn wallet_service(&self) -> Option<&Arc<TenzroWalletService>> {
        self.wallet_service.as_ref()
    }

    /// Returns the governance engine if initialized
    pub fn governance(&self) -> Option<&Arc<GovernanceEngine>> {
        self.governance.as_ref()
    }

    pub fn settlement(&self) -> Option<&Arc<SettlementEngine>> {
        self.settlement.as_ref()
    }

    pub fn channel_manager(&self) -> Option<&Arc<ChannelManager>> {
        self.channel_manager.as_ref()
    }

    pub fn escrow_manager(&self) -> Option<&Arc<EscrowManager>> {
        self.escrow_manager.as_ref()
    }

    /// Returns the OAuth 2.1 + DPoP + RAR auth engine if initialized.
    pub fn auth_engine(&self) -> Option<&Arc<tenzro_auth::AuthEngine>> {
        self.auth_engine.as_ref()
    }

    /// Returns the active liveness sweeper config, if the sweeper is running.
    pub fn liveness_config(&self) -> Option<crate::liveness::LivenessConfig> {
        self.liveness_sweeper.as_ref().map(|s| s.config.clone())
    }

    pub fn agent_runtime(&self) -> Option<&Arc<AgentRuntime>> {
        self.agent_runtime.as_ref()
    }

    pub fn agent_kit(&self) -> Option<&Arc<tenzro_agent_kit::AgentKit>> {
        self.agent_kit.as_ref()
    }

    pub fn swarm_manager(&self) -> Option<&Arc<SwarmManager>> {
        self.swarm_manager.as_ref()
    }

    /// Returns the network service if initialized
    pub fn network(&self) -> Option<&Arc<TenzroNetworkService>> {
        self.network.as_ref()
    }

    /// Returns the bridge router if initialized
    pub fn bridge_router(&self) -> Option<&Arc<BridgeRouter>> {
        self.bridge_router.as_ref()
    }

    /// Returns the node config
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Submit a finalized block to the event loop for execution
    pub async fn submit_block(&self, block: Block) -> Result<()> {
        let event_sender = self.event_loop_tx.as_ref()
            .ok_or_else(|| NodeError::Internal("Event loop not initialized".to_string()))?;
        event_sender.send(NodeEvent::BlockFinalized(block)).await
            .map_err(|e| NodeError::Internal(format!("Failed to submit block: {}", e)))
    }

    /// Register a model service instance (local or network)
    pub fn register_model_service(
        &self,
        model_id: &str,
        model_name: &str,
        provider_name: &str,
        location: ModelLocation,
        api_endpoint: &str,
        mcp_endpoint: &str,
        parameters: &str,
    ) -> String {
        use tenzro_types::model::PricingConfig;

        let instance_id = uuid::Uuid::new_v4().to_string();
        let pricing = self.provider_pricing.read();

        let instance = ModelServiceInstance {
            instance_id: instance_id.clone(),
            model_id: model_id.to_string(),
            model_name: model_name.to_string(),
            provider_address: Address::default(),
            provider_name: provider_name.to_string(),
            location,
            api_endpoint: api_endpoint.to_string(),
            mcp_endpoint: mcp_endpoint.to_string(),
            status: ServiceStatus::Online,
            parameters: parameters.to_string(),
            pricing: PricingConfig {
                price_per_input_token: (pricing.input_price_per_token * 1_000_000.0) as u64,
                price_per_output_token: (pricing.output_price_per_token * 1_000_000.0) as u64,
                ..PricingConfig::default()
            },
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            load_info: None,
        };

        self.model_services.insert(instance_id.clone(), instance.clone());

        // Persist to RocksDB
        if let Some(ref storage) = self.storage {
            if let Ok(data) = serde_json::to_vec(&instance) {
                if let Err(e) = storage.put(CF_MODEL_SERVICES, instance_id.as_bytes(), &data) {
                    warn!("Failed to persist model service {} to RocksDB: {}", instance_id, e);
                }
            }
        }

        info!("Registered model service: {} ({}) [{}]", model_id, instance_id, location);
        instance_id
    }

    /// Unregister a model service instance
    pub fn unregister_model_service(&self, instance_id: &str) {
        if let Some((_, instance)) = self.model_services.remove(instance_id) {
            if let Some(ref storage) = self.storage {
                let _ = storage.delete(CF_MODEL_SERVICES, instance_id.as_bytes());
            }
            info!("Unregistered model service: {} ({})", instance.model_id, instance_id);
        }
    }

    /// Unregister all model service instances for a given model_id
    pub fn unregister_model_services_by_model(&self, model_id: &str) {
        let ids: Vec<String> = self.model_services.iter()
            .filter(|entry| entry.value().model_id == model_id)
            .map(|entry| entry.key().clone())
            .collect();
        for id in &ids {
            self.model_services.remove(id);
            if let Some(ref storage) = self.storage {
                let _ = storage.delete(CF_MODEL_SERVICES, id.as_bytes());
            }
        }
        info!("Unregistered all services for model: {}", model_id);
    }

    /// Remove expired network model service instances (TTL-based cleanup).
    /// Called periodically from the event loop's heartbeat tick.
    pub fn cleanup_expired_model_services(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ttl = 300; // 5 minutes
        let expired: Vec<String> = self.model_services.iter()
            .filter(|e| {
                let svc = e.value();
                matches!(svc.location, tenzro_types::model::ModelLocation::Network)
                    && svc.last_seen > 0
                    && now.saturating_sub(svc.last_seen) > ttl
            })
            .map(|e| e.key().clone())
            .collect();
        for id in &expired {
            self.model_services.remove(id);
            if let Some(ref storage) = self.storage {
                let _ = storage.delete(CF_MODEL_SERVICES, id.as_bytes());
            }
            info!("Removed expired network model service: {}", id);
        }
        if !expired.is_empty() {
            info!("Cleaned up {} expired model services", expired.len());
        }
    }

    /// Resolve the GGUF file path for a given model_id by checking all known
    /// storage locations. Returns the first existing path or None.
    ///
    /// Mirrors the path-resolution logic in handle_serve_model.
    pub fn resolve_gguf_path(&self, model_id: &str) -> Option<std::path::PathBuf> {
        // 1. HfDownloader storage path (node-managed models directory)
        if let Some(ref hf) = self.hf_downloader {
            let p = hf.model_path(model_id);
            if p.exists() {
                return Some(p);
            }
        }

        // 2. CLI flat file layout: ~/.tenzro/models/<model_id>.gguf
        let home_models = std::path::PathBuf::from(
                std::env::var("HOME").unwrap_or_else(|_| "/home/tenzro".to_string()),
            )
            .join(".tenzro/models");
        let flat = home_models.join(format!("{}.gguf", model_id));
        if flat.exists() {
            return Some(flat);
        }

        // 3. CLI subdirectory layout: ~/.tenzro/models/<model_id>/*.gguf
        let sub = home_models.join(model_id);
        if sub.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&sub) {
                for e in entries.flatten() {
                    let path = e.path();
                    if path.extension().map(|ext| ext == "gguf").unwrap_or(false) {
                        return Some(path);
                    }
                }
            }
        }

        None
    }

    /// Evict Local ModelServiceInstance entries whose model is no longer loaded
    /// in the runtime AND have been idle (no `last_seen` update) for >= 1 hour.
    ///
    /// A model is considered "live" when `ModelRuntime::is_loaded()` returns true.
    /// If a local service still has a live runtime, its last_seen is refreshed
    /// (treated as liveness heartbeat). Otherwise, if it has been silent for
    /// more than 1 hour, the entry is removed from CF_MODEL_SERVICES and the
    /// served_models flag in CF_MODELS is cleared as well.
    #[allow(dead_code)]
    pub fn cleanup_idle_local_model_services(&self) {
        const IDLE_TTL_SECS: u64 = 3600; // 1 hour

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Collect candidates first to avoid holding DashMap refs across mutations
        let local_entries: Vec<(String, String, u64)> = self.model_services.iter()
            .filter(|e| matches!(e.value().location, tenzro_types::model::ModelLocation::Local))
            .map(|e| (e.key().clone(), e.value().model_id.clone(), e.value().last_seen))
            .collect();

        let mut evicted_instances: Vec<String> = Vec::new();
        let mut cleared_served: Vec<String> = Vec::new();

        for (instance_id, model_id, last_seen) in local_entries {
            let runtime_loaded = self
                .model_runtime
                .as_ref()
                .map(|rt| rt.is_loaded(&model_id))
                .unwrap_or(false);

            if runtime_loaded {
                // Live — refresh last_seen as a heartbeat so idle timer is bound
                // to the most recent successful liveness check, not registration.
                if let Some(mut svc) = self.model_services.get_mut(&instance_id) {
                    if svc.last_seen < now {
                        svc.last_seen = now;
                        if let Some(ref storage) = self.storage {
                            if let Ok(data) = serde_json::to_vec(svc.value()) {
                                let _ = storage.put(
                                    CF_MODEL_SERVICES,
                                    instance_id.as_bytes(),
                                    &data,
                                );
                            }
                        }
                    }
                }
                continue;
            }

            // Runtime is not serving this model. If the entry has been silent
            // for >= IDLE_TTL_SECS (or has never been seen), evict it.
            let idle = last_seen == 0 || now.saturating_sub(last_seen) >= IDLE_TTL_SECS;
            if idle {
                self.model_services.remove(&instance_id);
                if let Some(ref storage) = self.storage {
                    let _ = storage.delete(CF_MODEL_SERVICES, instance_id.as_bytes());
                }
                evicted_instances.push(instance_id.clone());

                // If no other Local instance still exists for this model, clear
                // the served_models flag as well (CF_MODELS).
                let still_served_locally = self
                    .model_services
                    .iter()
                    .any(|e| {
                        e.value().model_id == model_id
                            && matches!(
                                e.value().location,
                                tenzro_types::model::ModelLocation::Local,
                            )
                    });
                if !still_served_locally {
                    self.served_models.remove(&model_id);
                    self.load_tracker.unregister_model(&model_id);
                    if let Some(ref storage) = self.storage {
                        let _ = storage.delete(CF_MODELS, model_id.as_bytes());
                    }
                    cleared_served.push(model_id);
                }
            }
        }

        if !evicted_instances.is_empty() {
            info!(
                "Evicted {} idle local model service(s); cleared {} served_models flag(s)",
                evicted_instances.len(),
                cleared_served.len(),
            );
        }
    }

    /// Run a full reconciliation of the model registry against on-disk state
    /// and the in-memory runtime. Used both at startup and on-demand via
    /// `tenzro_pruneModelRegistry`.
    ///
    /// Behaviour:
    /// 1. For every entry in `served_models`:
    ///    - If the model is NOT in the catalog → clear the flag + remove any
    ///      matching ModelServiceInstance rows.
    ///    - If the model file is missing on disk → clear the flag + rows.
    ///    - If the model file exists but is not loaded in the runtime →
    ///      attempt `load_model_with_context()`. On failure → clear.
    /// 2. For every Local `ModelServiceInstance`:
    ///    - If the runtime is not serving the model_id → remove the row.
    ///      (Orphaned endpoints from previous process lifetimes.)
    ///
    /// Returns a tuple `(reloaded, cleared_models, cleared_services)`.
    pub async fn reconcile_model_registry(&self) -> (usize, usize, usize) {
        use tenzro_model::get_model_by_id;

        let mut reloaded: usize = 0;
        let mut cleared_models: usize = 0;
        let mut cleared_services: usize = 0;

        // Snapshot the served_models keys to avoid holding a DashMap iterator
        // while we mutate the map.
        let served_ids: Vec<String> = self
            .served_models
            .iter()
            .map(|e| e.key().clone())
            .collect();

        for model_id in &served_ids {
            let catalog = get_model_by_id(model_id);
            let gguf_path = self.resolve_gguf_path(model_id);

            let ok = match (catalog, gguf_path) {
                (Some(entry), Some(path)) => {
                    // Catalog entry + file present. Try to load into runtime if
                    // not already loaded.
                    if let Some(ref runtime) = self.model_runtime {
                        if runtime.is_loaded(model_id) {
                            true
                        } else {
                            match runtime
                                .load_model_with_context(
                                    model_id,
                                    &path,
                                    entry.architecture,
                                    Some(entry.context_length),
                                )
                                .await
                            {
                                Ok(()) => {
                                    reloaded += 1;
                                    info!(
                                        model_id = %model_id,
                                        path = %path.display(),
                                        "Auto-reloaded model into runtime after restart",
                                    );
                                    // Re-register load tracker (same logic as serve_model)
                                    let max_concurrent = {
                                        let hw = self.hardware_profile.read();
                                        if let Some(ref profile) = *hw {
                                            let gpu_vram = profile
                                                .gpus
                                                .first()
                                                .map(|g| g.vram_gb)
                                                .unwrap_or(0.0);
                                            let has_gpu = !profile.gpus.is_empty()
                                                && gpu_vram > 0.0;
                                            tenzro_model::estimate_max_concurrent(
                                                entry.min_ram_gb,
                                                profile.total_ram_gb,
                                                gpu_vram,
                                                has_gpu,
                                            )
                                        } else {
                                            tenzro_model::estimate_max_concurrent(
                                                entry.min_ram_gb,
                                                4.0,
                                                0.0,
                                                false,
                                            )
                                        }
                                    };
                                    self.load_tracker
                                        .register_model(model_id, max_concurrent);
                                    true
                                }
                                Err(e) => {
                                    warn!(
                                        model_id = %model_id,
                                        path = %path.display(),
                                        "Auto-reload failed: {} — clearing serve flag",
                                        e,
                                    );
                                    false
                                }
                            }
                        }
                    } else {
                        // No runtime available at all — can't serve. Keep file,
                        // but don't keep the flag advertising we serve it.
                        warn!(
                            model_id = %model_id,
                            "ModelRuntime not initialized — clearing serve flag",
                        );
                        false
                    }
                }
                (None, _) => {
                    warn!(
                        model_id = %model_id,
                        "Served model not found in catalog — clearing serve flag",
                    );
                    false
                }
                (_, None) => {
                    warn!(
                        model_id = %model_id,
                        "GGUF file missing for served model — clearing serve flag",
                    );
                    false
                }
            };

            if !ok {
                self.served_models.remove(model_id);
                self.load_tracker.unregister_model(model_id);
                if let Some(ref storage) = self.storage {
                    let _ = storage.delete(CF_MODELS, model_id.as_bytes());
                }
                cleared_models += 1;

                // Also clear any matching ModelServiceInstance rows for this model
                let svc_ids: Vec<String> = self
                    .model_services
                    .iter()
                    .filter(|e| e.value().model_id == *model_id)
                    .map(|e| e.key().clone())
                    .collect();
                for id in &svc_ids {
                    self.model_services.remove(id);
                    if let Some(ref storage) = self.storage {
                        let _ = storage.delete(CF_MODEL_SERVICES, id.as_bytes());
                    }
                    cleared_services += 1;
                }
            }
        }

        // Second pass: drop any orphaned Local ModelServiceInstance rows whose
        // model is not loaded and is no longer in served_models.
        let orphans: Vec<String> = self
            .model_services
            .iter()
            .filter(|e| {
                let svc = e.value();
                if !matches!(svc.location, tenzro_types::model::ModelLocation::Local) {
                    return false;
                }
                let loaded = self
                    .model_runtime
                    .as_ref()
                    .map(|rt| rt.is_loaded(&svc.model_id))
                    .unwrap_or(false);
                let flagged = self.served_models.contains_key(&svc.model_id);
                !loaded && !flagged
            })
            .map(|e| e.key().clone())
            .collect();

        for id in &orphans {
            self.model_services.remove(id);
            if let Some(ref storage) = self.storage {
                let _ = storage.delete(CF_MODEL_SERVICES, id.as_bytes());
            }
            cleared_services += 1;
            info!("Removed orphaned local model service: {}", id);
        }

        if reloaded > 0 || cleared_models > 0 || cleared_services > 0 {
            info!(
                "Model registry reconcile complete: reloaded={} cleared_models={} cleared_services={}",
                reloaded, cleared_models, cleared_services,
            );
        }

        (reloaded, cleared_models, cleared_services)
    }

    /// Refresh the `last_seen` timestamp of every Local ModelServiceInstance
    /// for the given model_id. Called from the tenzro_chat handler after a
    /// successful local inference so the 1-hour idle TTL is bound to actual
    /// usage, not registration time.
    pub fn touch_local_model_service(&self, model_id: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let ids: Vec<String> = self
            .model_services
            .iter()
            .filter(|e| {
                e.value().model_id == model_id
                    && matches!(
                        e.value().location,
                        tenzro_types::model::ModelLocation::Local,
                    )
            })
            .map(|e| e.key().clone())
            .collect();

        for id in ids {
            if let Some(mut svc) = self.model_services.get_mut(&id) {
                svc.last_seen = now;
                if let Some(ref storage) = self.storage {
                    if let Ok(data) = serde_json::to_vec(svc.value()) {
                        let _ = storage.put(CF_MODEL_SERVICES, id.as_bytes(), &data);
                    }
                }
            }
        }
    }

    /// List all model service instances
    pub fn list_model_services(&self) -> Vec<ModelServiceInstance> {
        self.model_services.iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get a model service instance by instance_id
    pub fn get_model_service(&self, instance_id: &str) -> Option<ModelServiceInstance> {
        self.model_services.get(instance_id).map(|entry| entry.value().clone())
    }

    /// Find a model service instance by model_id (returns first match)
    pub fn find_model_service_by_model_id(&self, model_id: &str) -> Option<ModelServiceInstance> {
        self.model_services.iter()
            .find(|entry| entry.value().model_id == model_id)
            .map(|entry| entry.value().clone())
    }

    /// Reconciles the task registry (CF_TASKS).
    ///
    /// For every persisted `TaskInfo`:
    ///   1. If the status is non-terminal (`Open | Assigned | InProgress | Disputed`)
    ///      and the task has a `deadline` in the past, transition it to `Expired`
    ///      and persist. This enforces the deadline that is otherwise never
    ///      acted on after `postTask`.
    ///   2. If the status is terminal (`Completed | Cancelled | Expired`) and the
    ///      task was created more than `purge_terminal_after_secs` ago, delete it.
    ///      Defaults: 30 days. Disputed tasks are never auto-purged.
    ///
    /// Returns `(expired, purged)`.
    pub fn reconcile_task_registry(&self, purge_terminal_after_secs: i64) -> (usize, usize) {
        match &self.storage {
            Some(s) => reconcile_task_registry_storage(s, purge_terminal_after_secs),
            None => (0, 0),
        }
    }

    /// Reconciles the tool registry (CF_TOOLS).
    ///
    /// Deletes entries whose status is `Inactive | Deprecated` and that were
    /// created more than `purge_after_secs` ago. Active tools are always
    /// retained.
    ///
    /// Returns the number of tool records purged.
    pub fn reconcile_tool_registry(&self, purge_after_secs: u64) -> usize {
        match &self.storage {
            Some(s) => reconcile_tool_registry_storage(s, purge_after_secs),
            None => 0,
        }
    }

    /// Reconciles the skill registry (CF_SKILLS).
    ///
    /// Same semantics as [`reconcile_tool_registry`]: drop Inactive/Deprecated
    /// skills that are older than `purge_after_secs`.
    pub fn reconcile_skill_registry(&self, purge_after_secs: u64) -> usize {
        match &self.storage {
            Some(s) => reconcile_skill_registry_storage(s, purge_after_secs),
            None => 0,
        }
    }

    /// Reconciles the agent registry (CF_AGENTS).
    ///
    /// Performs two actions:
    ///   1. Invokes the 1h idle-TTL sweep on the agent runtime so that any
    ///      Active agents without a recent heartbeat are auto-suspended (and
    ///      their lifecycle persisted). This is identical to the sweep driven
    ///      from `event_loop` but is also safe to call from admin RPC / CLI.
    ///   2. Returns the count of agents suspended in step (1).
    ///
    /// Terminated agents are preserved on purpose: the audit trail (state
    /// history, registration fee, DID) is retained indefinitely.
    pub async fn reconcile_agent_registry(&self) -> usize {
        if let Some(ref ar) = self.agent_runtime {
            ar.check_idle_agents(3600).await.len()
        } else {
            0
        }
    }
}

/// Storage-only task registry reconcile.
///
/// Free-function variant that runs the same logic as
/// [`TenzroNode::reconcile_task_registry`] against a raw storage handle, so it
/// can be driven from the node event loop (which holds only
/// `Arc<RocksDbStore>`, not a `TenzroNode`).
pub fn reconcile_task_registry_storage(
    storage: &Arc<RocksDbStore>,
    purge_terminal_after_secs: i64,
) -> (usize, usize) {
    use tenzro_storage::CF_TASKS;
    use tenzro_types::task::{TaskInfo, TaskStatus};

    let now = chrono::Utc::now().timestamp();
    let mut expired: usize = 0;
    let mut purged: usize = 0;

    let keys = match storage.get_keys_with_prefix(CF_TASKS, b"") {
        Ok(k) => k,
        Err(e) => {
            warn!("Failed to scan CF_TASKS during reconcile: {}", e);
            return (0, 0);
        }
    };

    for key in keys {
        let bytes = match storage.get(CF_TASKS, &key) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let mut task: TaskInfo = match serde_json::from_slice(&bytes) {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    "Corrupt task record {:?} — deleting: {}",
                    String::from_utf8_lossy(&key),
                    e
                );
                let _ = storage.delete(CF_TASKS, &key);
                purged += 1;
                continue;
            }
        };

        // 1. Deadline enforcement for non-terminal tasks.
        let non_terminal = matches!(
            task.status,
            TaskStatus::Open | TaskStatus::Assigned | TaskStatus::InProgress
        );
        if non_terminal {
            if let Some(deadline) = task.deadline {
                if (deadline as i64) < now {
                    task.status = TaskStatus::Expired;
                    if let Ok(updated) = serde_json::to_vec(&task) {
                        let _ = storage.put(CF_TASKS, &key, &updated);
                    }
                    expired += 1;
                    info!(
                        task_id = %task.task_id,
                        deadline,
                        "Task auto-expired by reconcile sweep",
                    );
                    continue;
                }
            }
        }

        // 2. Purge old terminal tasks (Completed / Cancelled / Expired).
        //    Disputed is retained until manually resolved.
        let is_purgeable_terminal = matches!(
            task.status,
            TaskStatus::Completed | TaskStatus::Cancelled | TaskStatus::Expired
        );
        if is_purgeable_terminal {
            let age_secs = now.saturating_sub(task.created_at.0);
            if age_secs > purge_terminal_after_secs {
                let _ = storage.delete(CF_TASKS, &key);
                purged += 1;
                info!(
                    task_id = %task.task_id,
                    age_secs,
                    "Purged stale terminal task",
                );
            }
        }
    }

    if expired > 0 || purged > 0 {
        info!(
            "Task registry reconcile complete: expired={} purged={}",
            expired, purged,
        );
    }

    (expired, purged)
}

/// Storage-only tool registry reconcile. See
/// [`TenzroNode::reconcile_tool_registry`] for semantics.
pub fn reconcile_tool_registry_storage(
    storage: &Arc<RocksDbStore>,
    purge_after_secs: u64,
) -> usize {
    use tenzro_types::tool::{ToolDefinition, ToolStatus};

    let now = chrono::Utc::now().timestamp() as u64;
    let mut purged: usize = 0;

    let keys = match storage.get_keys_with_prefix(CF_TOOLS, b"") {
        Ok(k) => k,
        Err(e) => {
            warn!("Failed to scan CF_TOOLS during reconcile: {}", e);
            return 0;
        }
    };

    for key in keys {
        let bytes = match storage.get(CF_TOOLS, &key) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let tool: ToolDefinition = match serde_json::from_slice(&bytes) {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    "Corrupt tool record {:?} — deleting: {}",
                    String::from_utf8_lossy(&key),
                    e
                );
                let _ = storage.delete(CF_TOOLS, &key);
                purged += 1;
                continue;
            }
        };

        let inactive = matches!(
            tool.status,
            ToolStatus::Inactive | ToolStatus::Deprecated
        );
        if !inactive {
            continue;
        }
        let age = now.saturating_sub(tool.created_at);
        if age > purge_after_secs {
            let _ = storage.delete(CF_TOOLS, &key);
            purged += 1;
            info!(
                tool_id = %tool.tool_id,
                age_secs = age,
                status = ?tool.status,
                "Purged stale tool",
            );
        }
    }

    if purged > 0 {
        info!("Tool registry reconcile complete: purged={}", purged);
    }
    purged
}

/// Storage-only skill registry reconcile. See
/// [`TenzroNode::reconcile_skill_registry`] for semantics.
pub fn reconcile_skill_registry_storage(
    storage: &Arc<RocksDbStore>,
    purge_after_secs: u64,
) -> usize {
    use tenzro_types::skill::{SkillDefinition, SkillStatus};

    let now = chrono::Utc::now().timestamp() as u64;
    let mut purged: usize = 0;

    let keys = match storage.get_keys_with_prefix(CF_SKILLS, b"") {
        Ok(k) => k,
        Err(e) => {
            warn!("Failed to scan CF_SKILLS during reconcile: {}", e);
            return 0;
        }
    };

    for key in keys {
        let bytes = match storage.get(CF_SKILLS, &key) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let skill: SkillDefinition = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Corrupt skill record {:?} — deleting: {}",
                    String::from_utf8_lossy(&key),
                    e
                );
                let _ = storage.delete(CF_SKILLS, &key);
                purged += 1;
                continue;
            }
        };

        let inactive = matches!(
            skill.status,
            SkillStatus::Inactive | SkillStatus::Deprecated
        );
        if !inactive {
            continue;
        }
        let age = now.saturating_sub(skill.created_at);
        if age > purge_after_secs {
            let _ = storage.delete(CF_SKILLS, &key);
            purged += 1;
            info!(
                skill_id = %skill.skill_id,
                age_secs = age,
                status = ?skill.status,
                "Purged stale skill",
            );
        }
    }

    if purged > 0 {
        info!("Skill registry reconcile complete: purged={}", purged);
    }
    purged
}

/// Detect hardware profile of the current system
pub async fn detect_hardware(data_dir: &std::path::Path) -> Result<HardwareProfile> {
    use sysinfo::{System, Disks};

    // Initialize system info
    let mut sys = System::new_all();
    sys.refresh_all();

    // CPU info
    let cpu_model = sys.cpus().first()
        .map(|cpu| cpu.brand().to_string())
        .unwrap_or_else(|| "Unknown CPU".to_string());
    let cpu_cores = sys.physical_core_count().unwrap_or(1);
    let cpu_threads = sys.cpus().len();

    // RAM info (convert bytes to GB)
    let total_ram_gb = sys.total_memory() as f64 / 1_073_741_824.0; // 1024^3

    // Storage info
    let disks = Disks::new_with_refreshed_list();
    let storage_available_gb = disks.iter()
        .find(|disk| {
            data_dir.starts_with(disk.mount_point())
        })
        .map(|disk| disk.available_space() as f64 / 1_073_741_824.0)
        .unwrap_or(0.0);

    // OS and architecture
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();

    // GPU detection
    let gpus = detect_gpus(&os).await;

    // TEE detection
    let (tee_available, tee_vendor) = match detect_tee().await {
        Some(provider) => (true, Some(format!("{:?}", provider.vendor()))),
        None => (false, None),
    };

    // Device fingerprint (SHA-256 hash of hardware characteristics)
    let fingerprint_input = format!(
        "{}|{}|{}|{}|{}|{}",
        cpu_model,
        cpu_cores,
        total_ram_gb as u64,
        gpus.iter().map(|g| g.name.as_str()).collect::<Vec<_>>().join(","),
        os,
        arch
    );
    let mut hasher = Sha256::new();
    hasher.update(fingerprint_input.as_bytes());
    let device_fingerprint = format!("{:x}", hasher.finalize());

    Ok(HardwareProfile {
        cpu_model,
        cpu_cores,
        cpu_threads,
        total_ram_gb,
        gpus,
        storage_available_gb,
        tee_available,
        tee_vendor,
        os,
        arch,
        device_fingerprint,
    })
}

/// Detect GPUs on the system
async fn detect_gpus(os: &str) -> Vec<GpuInfo> {
    let mut gpus = Vec::new();

    match os {
        "macos" => {
            // Use system_profiler to get GPU info
            if let Ok(output) = tokio::process::Command::new("system_profiler")
                .args(["SPDisplaysDataType", "-json"])
                .output()
                .await
            {
                if output.status.success() {
                    if let Ok(json_str) = String::from_utf8(output.stdout) {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                            if let Some(displays) = json.get("SPDisplaysDataType").and_then(|v| v.as_array()) {
                                for display in displays {
                                    if let Some(chipset) = display.get("sppci_model").and_then(|v| v.as_str()) {
                                        // Try to extract VRAM
                                        let vram_str = display.get("sppci_vram").and_then(|v| v.as_str()).unwrap_or("0 MB");
                                        let vram_gb = parse_vram(vram_str);

                                        gpus.push(GpuInfo {
                                            name: chipset.to_string(),
                                            vram_gb,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        "linux" => {
            // Try nvidia-smi first
            if let Ok(output) = tokio::process::Command::new("nvidia-smi")
                .args(["--query-gpu=name,memory.total", "--format=csv,noheader"])
                .output()
                .await
            {
                if output.status.success() {
                    if let Ok(stdout) = String::from_utf8(output.stdout) {
                        for line in stdout.lines() {
                            let parts: Vec<&str> = line.split(',').collect();
                            if parts.len() >= 2 {
                                let name = parts[0].trim().to_string();
                                let vram_str = parts[1].trim();
                                let vram_gb = parse_vram(vram_str);

                                gpus.push(GpuInfo { name, vram_gb });
                            }
                        }
                    }
                }
            }

            // If no NVIDIA GPUs found, check /proc for other info
            if gpus.is_empty() {
                if let Ok(entries) = std::fs::read_dir("/proc/driver") {
                    for entry in entries.flatten() {
                        if entry.file_name() == "nvidia" {
                            // NVIDIA driver exists but nvidia-smi failed
                            gpus.push(GpuInfo {
                                name: "NVIDIA GPU (details unavailable)".to_string(),
                                vram_gb: 0.0,
                            });
                        }
                    }
                }
            }
        }
        _ => {
            // Windows or other platforms - not implemented
        }
    }

    gpus
}

/// Parse VRAM string to GB (handles formats like "8 GB", "8192 MB", etc.)
fn parse_vram(vram_str: &str) -> f64 {
    let cleaned = vram_str.trim().to_lowercase();

    if let Some(gb_pos) = cleaned.find("gb") {
        let num_str = &cleaned[..gb_pos].trim();
        num_str.parse::<f64>().unwrap_or(0.0)
    } else if let Some(mb_pos) = cleaned.find("mb") {
        let num_str = &cleaned[..mb_pos].trim();
        let mb = num_str.parse::<f64>().unwrap_or(0.0);
        mb / 1024.0
    } else if let Some(mib_pos) = cleaned.find("mib") {
        let num_str = &cleaned[..mib_pos].trim();
        let mib = num_str.parse::<f64>().unwrap_or(0.0);
        mib / 1024.0
    } else {
        // Try to parse as plain number (assume MB)
        cleaned.split_whitespace()
            .next()
            .and_then(|s| s.parse::<f64>().ok())
            .map(|mb| mb / 1024.0)
            .unwrap_or(0.0)
    }
}

/// Node status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub state: String,
    pub role: NetworkRole,
    pub health_status: crate::health::OverallHealth,
    pub uptime_secs: u64,
    pub block_height: u64,
    pub peer_count: u64,
    pub data_dir: PathBuf,
}
