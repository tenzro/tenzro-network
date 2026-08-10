//! Node configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tenzro_consensus::ConsensusConfig;
use tenzro_network::NetworkConfig;
use tenzro_types::{NetworkRole, RoleSet};

use crate::error::{NodeError, Result};

/// Serde helper for u128 values — serializes as string for TOML compatibility
/// (the `toml` crate does not support u128 natively)
mod u128_as_string {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Accept both string and integer representations
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrInt {
            String(String),
            Int(u64),
        }
        match StringOrInt::deserialize(deserializer)? {
            StringOrInt::String(s) => s.parse::<u128>().map_err(serde::de::Error::custom),
            StringOrInt::Int(v) => Ok(v as u128),
        }
    }
}

/// The exact genesis schema version this build accepts.
///
/// The current schema mandates the full three-key validator identity: a
/// classical Ed25519 `public_key`, a post-quantum ML-DSA-65 `pq_public_key`
/// (hex-encoded 1952-byte verifying key), and a BLS12-381 `bls_public_key`
/// for HotStuff-2 vote aggregation. A genesis file whose `version` is missing
/// or not exactly this value is rejected at startup — no backward or forward
/// compat.
pub const GENESIS_SCHEMA_VERSION: u32 = 1;

/// Genesis configuration for network initialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Genesis schema version. Must equal GENESIS_SCHEMA_VERSION (1) exactly;
    /// the field is mandatory (no serde default). Distinct from the block
    /// metadata `protocol_version` (PQ_HYBRID_PROTOCOL_VERSION), which marks the
    /// post-quantum signature era and is a separate number.
    pub version: u32,

    /// Chain ID
    pub chain_id: u64,

    /// Timestamp for genesis block (Unix seconds, 0 = use current time)
    pub timestamp: u64,

    /// Initial validators
    pub validators: Vec<GenesisValidator>,

    /// Pre-funded accounts
    pub accounts: Vec<GenesisAccount>,

    /// Faucet configuration
    pub faucet: Option<FaucetConfig>,

    /// Weak-subjectivity anchor for snapshot-based auto-catchup.
    ///
    /// When set, a freshly-booted validator (empty DB) auto-discovers a
    /// healthy peer via `--bootstrap-dns`, fetches the newest snapshot
    /// at or above `height`, verifies its declared state_root matches
    /// `state_root_hex` bit-for-bit, then commits it as the local
    /// starting state. Without this anchor the snapshot bootstrap
    /// path is unauthenticated and refuses to run — the same fail-closed
    /// invariant `bootstrap_from_peer` already enforces, just declared
    /// inline in the genesis instead of passed via CLI.
    #[serde(default)]
    pub weak_subjectivity: Option<WeakSubjectivityAnchor>,

    /// True only for a genesis fabricated by `default_testnet()` for solo/dev
    /// operation. Never serialized: an operator-supplied genesis.toml is by
    /// definition not solo, and a solo genesis is never written to disk. This
    /// marker is what lets consensus distinguish "the operator handed me a
    /// legitimately single-validator network" from "I invented this because no
    /// genesis was provided" — only the latter is allowed to self-quorum.
    #[serde(skip)]
    pub solo: bool,
}

/// Chain ID of the canonical public Tenzro network. A node joining the public
/// network without an explicit `--genesis` verifies against the built-in
/// genesis carrying this id (see [`public_network_genesis`]).
pub const PUBLIC_NETWORK_CHAIN_ID: u64 = 1338;

/// The canonical public-network genesis, compiled into the binary.
///
/// A self-serve operator running `tenzro-node --roles validator` with default
/// bootstrap has no way to obtain the fleet's `genesis-prod.toml` (it ships
/// out-of-band via terraform). Embedding it here means "join the public
/// network" works with zero manual genesis distribution, and the node
/// verifies against the real validator set instead of fabricating its own.
/// This file contains only public key material + genesis parameters — the
/// same information every validator already gossips — so compiling it in
/// leaks nothing.
const PUBLIC_NETWORK_GENESIS_TOML: &str = include_str!("../genesis/public-testnet.toml");

/// Parse the built-in public-network genesis. Fails loudly if the bundled
/// file is malformed or its chain_id has drifted from
/// [`PUBLIC_NETWORK_CHAIN_ID`] — a compiled-in genesis that disagrees with the
/// constant would be a silent footgun.
pub fn public_network_genesis() -> Result<GenesisConfig> {
    let g: GenesisConfig = toml::from_str(PUBLIC_NETWORK_GENESIS_TOML).map_err(|e| {
        NodeError::Config(format!("built-in public-network genesis is malformed: {e}"))
    })?;
    if g.chain_id != PUBLIC_NETWORK_CHAIN_ID {
        return Err(NodeError::Config(format!(
            "built-in public-network genesis chain_id {} != PUBLIC_NETWORK_CHAIN_ID {}",
            g.chain_id, PUBLIC_NETWORK_CHAIN_ID
        )));
    }
    if g.validators.is_empty() {
        return Err(NodeError::Config(
            "built-in public-network genesis has no validators".to_string(),
        ));
    }
    Ok(g)
}

/// Weak-subjectivity checkpoint embedded in genesis.toml.
///
/// The operator publishes an out-of-band-verified `(height, state_root)`
/// pair signed by the active validator set. Fresh validators trust this
/// checkpoint by virtue of trusting the genesis file itself — same trust
/// boundary that already covers the validator set, accounts, and
/// predeploy bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakSubjectivityAnchor {
    /// Block height the anchor applies to.
    pub height: u64,
    /// Hex-encoded 32-byte state root at that height. The snapshot
    /// manifest's declared state_root must match this exactly.
    pub state_root_hex: String,
}

impl GenesisConfig {
    pub fn default_testnet() -> Self {
        Self {
            version: GENESIS_SCHEMA_VERSION,
            chain_id: 1337,
            timestamp: 0,
            validators: Vec::new(),
            accounts: Vec::new(),
            faucet: Some(FaucetConfig {
                address: "0".repeat(64),
                amount_per_request: 1_000,
                cooldown_seconds: 86400,
                enabled: true,
            }),
            weak_subjectivity: None,
            solo: false,
        }
    }
}

/// A genesis validator
///
/// Every validator in genesis carries THREE keys: a classical Ed25519 public
/// key, a post-quantum ML-DSA-65 verifying key, and a BLS12-381 G1-compressed
/// verifying key (`min_pk` scheme) for HotStuff-2 vote aggregation. All three
/// legs are mandatory — there is no fallback path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Hex-encoded Ed25519 public key (32 bytes)
    pub public_key: String,
    /// Hex-encoded ML-DSA-65 verifying key (1952 bytes)
    pub pq_public_key: String,
    /// Hex-encoded BLS12-381 G1-compressed verifying key (`min_pk` scheme,
    /// 48 bytes). Used by the consensus engine to aggregate per-validator
    /// BLS vote signatures into a single QC-level aggregate.
    pub bls_public_key: String,
    /// Stake amount in TNZO (whole units, will be multiplied by 10^18)
    pub stake: u64,
}

/// A pre-funded genesis account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAccount {
    /// Hex-encoded 32-byte address
    pub address: String,
    /// Balance in TNZO (whole units, will be multiplied by 10^18)
    #[serde(with = "u128_as_string")]
    pub balance: u128,
}

/// Faucet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaucetConfig {
    /// Faucet account address (hex-encoded)
    pub address: String,
    /// Amount to dispense per request (in TNZO whole units)
    #[serde(with = "u128_as_string")]
    pub amount_per_request: u128,
    /// Cooldown period in seconds between requests from same address
    pub cooldown_seconds: u64,
    /// Whether faucet is enabled
    pub enabled: bool,
}

/// Cross-chain bridge adapter configuration.
///
/// Controls which bridge adapters are registered with the `BridgeRouter` at
/// node startup and whether they are wired to submit real on-chain transactions
/// via configured `EvmTransactionSigner`s.
///
/// Private keys should **never** be committed to version control. Prefer setting
/// them via environment variables (e.g. `TENZRO_CCIP_PRIVATE_KEY`) and
/// referencing them from a machine-local config file.
/// Configuration for Tenzro Cortex recurrent-depth reasoning workers.
///
/// Each worker binds a Python HTTP sidecar (OpenMythos-style) to a Tenzro
/// model_id, TNZO pricing schedule, and receipt-signing key. Workers
/// listed here are auto-registered during node startup and appear in
/// `tenzro_listCortexWorkers`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CortexConfig {
    /// Master enable flag for the Cortex subsystem.
    #[serde(default)]
    pub enabled: bool,

    /// Worker specifications to auto-register at startup.
    #[serde(default)]
    pub workers: Vec<CortexWorkerConfig>,
}

/// A single Cortex worker specification.
#[derive(Clone, Serialize, Deserialize)]
pub struct CortexWorkerConfig {
    /// Stable model identifier exposed to clients (e.g. "mythos-3b").
    pub model_id: String,

    /// Sidecar base URL (e.g. "http://127.0.0.1:8799").
    #[serde(default = "default_sidecar_url")]
    pub sidecar_url: String,

    /// Optional bearer token for sidecar auth.
    ///
    /// Marked `#[serde(skip_serializing)]` so the token never round-trips
    /// out of `NodeConfig::save_to_file`; the `Debug` impl below redacts
    /// presence as `<redacted>` / `<unset>`.
    #[serde(default, skip_serializing)]
    pub bearer_token: Option<String>,

    /// Architecture identifier — informational, passed into CortexModelFamily.
    #[serde(default = "default_arch")]
    pub arch: String,

    /// Maximum loops supported by the model.
    #[serde(default = "default_max_loops")]
    pub max_loops: u32,

    /// Total number of MoE experts.
    #[serde(default = "default_moe_experts")]
    pub moe_experts: u32,

    /// Experts activated per token.
    #[serde(default = "default_experts_per_token")]
    pub experts_per_token: u32,

    /// Attention mechanism ("mla" or "gqa").
    #[serde(default = "default_attn_type")]
    pub attn_type: String,

    /// Worker DID — defaults to `did:tenzro:machine:cortex-<model_id>`.
    #[serde(default)]
    pub worker_did: Option<String>,

    /// Optional inline pricing override (JSON value matching CortexPricing).
    #[serde(default)]
    pub pricing: Option<serde_json::Value>,

    /// Request timeout in seconds.
    #[serde(default = "default_cortex_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_sidecar_url() -> String {
    "http://127.0.0.1:8799".to_string()
}
fn default_arch() -> String {
    "rdt-moe".to_string()
}
fn default_max_loops() -> u32 {
    32
}
fn default_moe_experts() -> u32 {
    64
}
fn default_experts_per_token() -> u32 {
    2
}
fn default_attn_type() -> String {
    "mla".to_string()
}
fn default_cortex_timeout_secs() -> u64 {
    120
}

impl std::fmt::Debug for CortexWorkerConfig {
    /// Custom `Debug` that redacts the sidecar `bearer_token`. Presence
    /// is reported as `<redacted>` / `<unset>`; all other fields pass
    /// through unchanged.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CortexWorkerConfig")
            .field("model_id", &self.model_id)
            .field("sidecar_url", &self.sidecar_url)
            .field(
                "bearer_token",
                &if self.bearer_token.is_some() {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            .field("arch", &self.arch)
            .field("max_loops", &self.max_loops)
            .field("moe_experts", &self.moe_experts)
            .field("experts_per_token", &self.experts_per_token)
            .field("attn_type", &self.attn_type)
            .field("worker_did", &self.worker_did)
            .field("pricing", &self.pricing)
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

/// Configuration for the Tenzro Train auto-provisioning daemon.
///
/// When enabled, the node runs a leader-gated poll loop that discovers
/// every active training run held in the local `TrainingRuntime` and
/// spawns the Python reference trainer (`tenzro-trainer run`) as a
/// supervised subprocess for each run this node participates in. The
/// trainer speaks JSON-RPC back to the node's local RPC endpoint to
/// enroll, submit outer gradients, and finalize rounds — the node never
/// links a tensor library; all tensor math stays in the Python process.
///
/// Disabled by default. Opt-in per operator. Initialization failure is
/// non-fatal: a mis-configured trainer runtime logs and continues so it
/// cannot block the rest of node startup.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrainingConfig {
    /// Master enable flag for the trainer auto-provisioning daemon.
    #[serde(default)]
    pub enabled: bool,

    /// Path to the Python interpreter that has `tenzro-trainer` installed.
    /// When `None`, the daemon resolves in order: `<venv_path>/bin/python`
    /// (if `venv_path` is set), then `python3`, then `python` on `PATH`.
    #[serde(default)]
    pub python_executable: Option<String>,

    /// Path to a Python virtual environment root that has the
    /// `tenzro-trainer` package installed. When set, the daemon prefers
    /// `<venv_path>/bin/python` as the interpreter.
    #[serde(default)]
    pub venv_path: Option<String>,

    /// Maximum number of trainer subprocesses this node runs concurrently.
    /// Bounds resource use on a node that participates in many runs at
    /// once; additional eligible runs wait for a free slot.
    #[serde(default = "default_max_concurrent_trainers")]
    pub max_concurrent_trainers: usize,

    /// Poll interval in seconds between reconcile ticks.
    #[serde(default = "default_trainer_poll_interval_secs")]
    pub poll_interval_secs: u64,

    /// Base backoff in milliseconds for the supervised-restart schedule.
    /// A trainer that exits (crash or non-zero status) is respawned no
    /// sooner than `backoff_base_ms * 2^(retries-1)`, capped at
    /// `backoff_max_ms`.
    #[serde(default = "default_trainer_backoff_base_ms")]
    pub backoff_base_ms: u64,

    /// Ceiling for the exponential restart backoff in milliseconds.
    #[serde(default = "default_trainer_backoff_max_ms")]
    pub backoff_max_ms: u64,

    /// Maximum consecutive restarts per run before the daemon gives up on
    /// that run and stops respawning it (until the run's state changes or
    /// the node restarts). Guards against a permanently-broken trainer
    /// pinning a subprocess slot in a restart loop.
    #[serde(default = "default_trainer_max_restarts")]
    pub max_restarts: u32,

    /// Extra CLI arguments appended verbatim to every `tenzro-trainer run`
    /// invocation (e.g. adapter-specific flags). Empty by default.
    #[serde(default)]
    pub trainer_extra_args: Vec<String>,
}

fn default_max_concurrent_trainers() -> usize {
    1
}
fn default_trainer_poll_interval_secs() -> u64 {
    30
}
fn default_trainer_backoff_base_ms() -> u64 {
    2_000
}
fn default_trainer_backoff_max_ms() -> u64 {
    300_000
}
fn default_trainer_max_restarts() -> u32 {
    8
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Whether the bridge subsystem is enabled.
    #[serde(default = "BridgeConfig::default_enabled")]
    pub enabled: bool,

    /// LayerZero V2 adapter configuration (optional).
    #[serde(default = "BridgeConfig::default_adapter_enabled")]
    pub layerzero: Option<BridgeAdapterConfig>,

    /// Chainlink CCIP adapter configuration (optional).
    #[serde(default = "BridgeConfig::default_adapter_enabled")]
    pub ccip: Option<BridgeAdapterConfig>,

    /// deBridge DLN adapter configuration (optional).
    #[serde(default = "BridgeConfig::default_adapter_enabled")]
    pub debridge: Option<BridgeAdapterConfig>,

    /// LI.FI aggregator adapter configuration (optional).
    #[serde(default = "BridgeConfig::default_adapter_enabled")]
    pub lifi: Option<BridgeAdapterConfig>,

    /// Wormhole adapter configuration (optional).
    #[serde(default = "BridgeConfig::default_adapter_enabled")]
    pub wormhole: Option<BridgeAdapterConfig>,

    /// Hyperlane V3 adapter configuration (optional). The adapter itself
    /// is always constructed (it serves the `tenzro_hyperlane*` RPC
    /// namespace); this entry supplies the per-origin-domain validator
    /// sets consumed by inbound ISM verification.
    #[serde(default = "BridgeConfig::default_adapter_enabled")]
    pub hyperlane: Option<BridgeAdapterConfig>,

    /// Axelar GMP adapter configuration (optional). The adapter itself
    /// is always constructed (it serves the `tenzro_axelar*` RPC
    /// namespace); this entry supplies the validator set consumed by
    /// inbound GMP signature verification.
    #[serde(default = "BridgeConfig::default_adapter_enabled")]
    pub axelar: Option<BridgeAdapterConfig>,

    /// Chainlink Data Feeds configuration for the fee-in-TNZO oracle.
    /// When set + `enabled = true`, the bridge router's fee surface uses
    /// `ChainlinkFeedFeeOracle` (with live `eth_call` to AggregatorV3Interface)
    /// instead of falling back to the governance-set rate table.
    #[serde(default)]
    pub chainlink_feeds: Option<ChainlinkFeedsConfig>,

    /// Asset USD price oracle configuration. When set + `enabled = true`, the
    /// node exposes `tenzro_getPrice` backed by Chainlink `SYMBOL/USD` feeds.
    /// Independent of the fee oracle above (this surfaces raw per-symbol USD
    /// prices for portfolio views, not bridge fee cross-rates).
    #[serde(default)]
    pub prices: Option<PriceFeedsConfig>,
}

/// Chainlink Data Feeds configuration for the bridge fee oracle.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainlinkFeedsConfig {
    /// Master switch. Off by default; operators opt in.
    #[serde(default)]
    pub enabled: bool,

    /// Ethereum mainnet RPC URL for `eth_call` queries against the
    /// AggregatorV3 proxy contracts. Operators should point at a private
    /// dRPC endpoint or self-hosted Ethereum node in production.
    #[serde(default)]
    pub rpc_url: Option<String>,

    /// TNZO/USD feed address (hex). When `None`, the oracle cannot derive
    /// cross-feed rates and falls back to the governance table.
    #[serde(default)]
    pub tnzo_usd_feed: Option<String>,

    /// Per-(adapter, dest_chain) destination-native USD feed addresses
    /// (hex). Format: `vec![("layerzero", "eip155:1", "0x5f4e...")]`.
    #[serde(default)]
    pub dest_native_feeds: Vec<DestNativeFeedConfig>,

    /// Markup applied to live-feed-derived quotes, basis points. Default 100 (1%).
    #[serde(default = "ChainlinkFeedsConfig::default_markup_bps")]
    pub markup_bps: u32,

    /// Quote validity window for live-feed-backed quotes, ms. Default 60_000.
    #[serde(default = "ChainlinkFeedsConfig::default_valid_window_ms")]
    pub valid_window_ms: u64,
}

impl ChainlinkFeedsConfig {
    fn default_markup_bps() -> u32 {
        100
    }
    fn default_valid_window_ms() -> u64 {
        60_000
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DestNativeFeedConfig {
    /// Bridge adapter id: `layerzero` | `ccip` | `wormhole` | `debridge` |
    /// `hyperlane` | `axelar` | `lifi` | `canton`.
    pub adapter: String,
    /// Destination chain CAIP-2 identifier (e.g. `eip155:1`, `solana:mainnet-beta`).
    pub dest_chain: String,
    /// AggregatorV3 proxy address for `(dest_native / USD)`.
    pub feed_address: String,
    /// Optional staleness tier: `major` | `longtail`. Default `major`.
    #[serde(default)]
    pub tier: Option<String>,
}

/// Asset USD price oracle configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PriceFeedsConfig {
    /// Master switch. Off by default; operators opt in.
    #[serde(default)]
    pub enabled: bool,

    /// Ethereum mainnet RPC URL for `eth_call` against the AggregatorV3 proxy
    /// contracts. Point at a private dRPC endpoint or self-hosted node.
    #[serde(default)]
    pub rpc_url: Option<String>,

    /// `SYMBOL/USD` feeds to register. Each priced by ticker via
    /// `tenzro_getPrice`.
    #[serde(default)]
    pub symbols: Vec<SymbolFeedConfig>,
}

/// One `SYMBOL/USD` Chainlink feed registration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SymbolFeedConfig {
    /// Ticker (e.g. `TNZO`, `ETH`, `BTC`).
    pub symbol: String,
    /// AggregatorV3 proxy address for `(symbol / USD)`.
    pub feed_address: String,
    /// Optional staleness tier: `major` | `longtail`. Default `major`.
    #[serde(default)]
    pub tier: Option<String>,
}

impl BridgeConfig {
    fn default_enabled() -> bool {
        true
    }

    /// Default to a quote-only adapter (no signer). The chain catalog
    /// from `supported_chains()` still populates `tenzro_listChains`,
    /// and read-only paths (fee quotes, route discovery, pool lookups)
    /// work without an EVM signing key. Adapters that need to *settle*
    /// require an explicit signer config — set `private_key_env` or
    /// `tee_sealed = true` in node config to enable.
    fn default_adapter_enabled() -> Option<BridgeAdapterConfig> {
        Some(BridgeAdapterConfig {
            enabled: true,
            ..Default::default()
        })
    }
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            layerzero: Self::default_adapter_enabled(),
            ccip: Self::default_adapter_enabled(),
            debridge: Self::default_adapter_enabled(),
            lifi: Self::default_adapter_enabled(),
            wormhole: Self::default_adapter_enabled(),
            hyperlane: Self::default_adapter_enabled(),
            axelar: Self::default_adapter_enabled(),
            chainlink_feeds: None,
            prices: None,
        }
    }
}

/// Generic bridge adapter configuration.
///
/// Captures the minimum RPC / chain / signer information needed to wire any
/// EVM-based adapter. Individual adapters may read additional protocol-specific
/// parameters from environment variables.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct BridgeAdapterConfig {
    /// Whether this adapter is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// EVM chain id this signer operates on.
    #[serde(default)]
    pub chain_id: u64,

    /// JSON-RPC URL for the chain.
    #[serde(default)]
    pub rpc_url: String,

    /// Hex-encoded private key for the signer (32 bytes, no 0x prefix).
    /// Prefer reading from env var `private_key_env` instead of inlining.
    ///
    /// Marked `#[serde(skip_serializing)]` so `NodeConfig::save_to_file`
    /// never round-trips a private key from a config that was loaded with
    /// the key inlined. The corresponding `Debug` impl below also redacts
    /// the field — `tracing::debug!("{:?}", config)` will not leak it.
    #[serde(default, skip_serializing)]
    pub private_key: Option<String>,

    /// Name of an environment variable that holds the signer private key.
    /// Takes precedence over `private_key` when set.
    #[serde(default)]
    pub private_key_env: Option<String>,

    /// Use a TEE-sealed signing key derived inside the local enclave
    /// (AMD SEV-SNP via `SNP_GET_DERIVED_KEY`, or Intel TDX via
    /// MRTD-as-IKM through HKDF-SHA256). When `true`, the signer is built
    /// via `EvmTransactionSigner::with_tee_sealed` and `private_key` /
    /// `private_key_env` are ignored. Off-hardware deployments error
    /// loudly rather than silently falling back to a raw key.
    ///
    /// Production posture for the bridge custody key.
    #[serde(default)]
    pub tee_sealed: bool,

    /// HKDF salt label for TEE-sealed key derivation (only used when
    /// `tee_sealed = true`). Distinct labels produce unrelated keys from
    /// the same enclave — separates bridge custody from MPC, settlement,
    /// etc. Defaults to `"tenzro/bridge/evm-signer"` if unset.
    #[serde(default)]
    pub tee_label: Option<String>,

    /// DKLS23 t-of-n threshold-ECDSA backend.
    ///
    /// When set, takes precedence over both `tee_sealed` and the raw-key
    /// paths: the bridge signer dispatches every signing request through
    /// the node-layer `NodeThresholdSigner`, which closes over the local
    /// `KeyshareEnvelope` (RocksDB-persisted), a `KeyshareSealer`
    /// (TEE-rooted in production), the libp2p `/tenzro/mpc/v1` transport,
    /// and a chain-anchored entropy source (finalized block hash) for
    /// committee draw. No single party — including this node — holds the
    /// full private scalar.
    #[serde(default)]
    pub mpc_threshold: Option<MpcThresholdConfig>,

    /// Inbound verifier set(s). Required for `receive_message` to admit
    /// any cross-chain payload. Each adapter chooses its own subset:
    ///   - LayerZero V2: one `InboundVerifierSet` per source EID under
    ///     the canonical `kind = "dvn"`.
    ///   - Chainlink CCIP: TWO entries per source-chain selector,
    ///     `kind = "ccip_commit"` and `kind = "ccip_rmn"`; both must
    ///     verify for delivery.
    ///   - deBridge DLN: one entry per source chain id, `kind = "dln"`.
    ///   - Hyperlane: one entry per origin domain, `kind = "hyperlane"`
    ///     (`source_id` = Hyperlane origin domain id).
    ///   - Axelar: one entry, `kind = "axelar"` (single global set;
    ///     `source_id` ignored).
    ///   - Wormhole: optional override, `kind = "wormhole_guardian"`
    ///     (`source_id` = guardian set index; `threshold` ignored —
    ///     Wormhole quorum is always `floor(2n/3) + 1`). When absent,
    ///     the pinned mainnet Guardian set (`GuardianSet::mainnet()`)
    ///     is installed.
    ///
    /// Absent entry = adapter refuses inbound traffic at startup
    /// (fail-closed; Wormhole falls back to the pinned mainnet set).
    /// This is the required production posture.
    #[serde(default)]
    pub inbound_verifier_sets: Vec<InboundVerifierSet>,
}

/// One inbound verifier set entry. The calling adapter is responsible
/// for scoping `source_id` correctly (EID, chain selector, origin
/// domain, etc) and dispatching to the right `kind`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboundVerifierSet {
    /// Verifier kind. Recognized values:
    /// `"dvn"`, `"ccip_commit"`, `"ccip_rmn"`, `"dln"`, `"hyperlane"`,
    /// `"axelar"`, `"wormhole_guardian"`. Unknown kinds are logged and
    /// skipped at startup.
    pub kind: String,
    /// Source-chain identifier. Interpretation depends on `kind`:
    /// LayerZero EID (u32), CCIP selector (u64), Hyperlane domain (u32),
    /// etc. Encoded as a JSON number so operators can paste the value
    /// directly from the upstream config.
    pub source_id: u64,
    /// Hex-encoded 20-byte authorised signer addresses (with or without
    /// `0x` prefix). MUST match the upstream chain's published validator
    /// set; copy them from the canonical source (LZ docs, CCIP commit-store
    /// committee, DLN admin, Hyperlane registry, etc).
    pub addresses: Vec<String>,
    /// Quorum threshold (number of distinct signatures required).
    pub threshold: u8,
}

/// Per-adapter DKLS23 t-of-n threshold-signer configuration.
///
/// All fields describe the *signing group* this adapter belongs to. The
/// actual share material lives in RocksDB under `CF_MPC_KEYSHARES` keyed
/// by `group_id` and is loaded at signing time by `NodeKeyshareStore`.
///
/// `local_did` identifies *this node* within `group_members`; every signing
/// attempt runs a chain-anchored committee draw and this node either
/// participates, observes (sufficient quorum drawn without it), or surfaces
/// `UnderQuorum` (group too small to assemble `threshold` participants).
#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct MpcThresholdConfig {
    /// Hex-encoded 32-byte DKLS23 group identifier (stable across epoch
    /// boundaries — only share material rotates on refresh).
    #[serde(default)]
    pub group_id_hex: String,

    /// This node's DID within the signing group. Must be a member of
    /// `group_members`.
    #[serde(default)]
    pub local_did: String,

    /// All party DIDs in the signing group, in canonical order. Length
    /// must equal `total_parties`.
    #[serde(default)]
    pub group_members: Vec<String>,

    /// Hex-encoded 33-byte SEC1-compressed secp256k1 group public key
    /// (matches `KeyshareEnvelope::group_public_key_compressed`). The
    /// derived 20-byte Ethereum address becomes the bridge signer's
    /// `sender_address`.
    #[serde(default)]
    pub group_public_key_hex: String,

    /// Signing threshold `t` — at least `t` parties must cooperate to
    /// produce a signature. Invariant: `2 <= threshold <= total_parties`.
    #[serde(default)]
    pub threshold: u8,

    /// Total party count `n` — there are exactly `n` keyshares in the
    /// distribution. Invariant: `threshold <= total_parties <= 32`.
    #[serde(default)]
    pub total_parties: u8,
}

impl BridgeAdapterConfig {
    /// Resolves the signer private key from either the inline value or env var.
    ///
    /// Returns `None` if neither is set. Returns an error if an env var is
    /// specified but not present in the environment.
    pub fn resolve_private_key(&self) -> Result<Option<String>> {
        if let Some(env_var) = &self.private_key_env {
            return std::env::var(env_var).map(Some).map_err(|_| {
                NodeError::Config(format!("Bridge signer env var '{}' is not set", env_var))
            });
        }
        Ok(self.private_key.clone())
    }

    /// HKDF label bytes used for TEE-sealed key derivation, defaulting to
    /// `"tenzro/bridge/evm-signer"` when no override is set in config.
    pub fn tee_label_bytes(&self) -> Vec<u8> {
        self.tee_label
            .as_deref()
            .unwrap_or("tenzro/bridge/evm-signer")
            .as_bytes()
            .to_vec()
    }
}

impl std::fmt::Debug for BridgeAdapterConfig {
    /// Custom `Debug` that redacts the inline `private_key` field so
    /// secret material never reaches logs via `tracing::debug!("{:?}", ...)`.
    /// Presence is reported as `<redacted>` / `<unset>`; all other fields
    /// pass through unchanged.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeAdapterConfig")
            .field("enabled", &self.enabled)
            .field("chain_id", &self.chain_id)
            .field("rpc_url", &self.rpc_url)
            .field(
                "private_key",
                &if self.private_key.is_some() {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            .field("private_key_env", &self.private_key_env)
            .field("tee_sealed", &self.tee_sealed)
            .field("tee_label", &self.tee_label)
            .field("mpc_threshold", &self.mpc_threshold)
            .finish()
    }
}

/// HTTP 402 payment gate configuration for Web API endpoints
///
/// Controls automatic payment-required responses for selected web routes.
/// When `enabled = true`, requests to paths in `paid_routes` without a
/// valid payment credential are answered with HTTP 402 + a challenge JSON
/// body. Verified credentials forward the request to the underlying handler.
/// Container-level `#[serde(default)]` so an operator may write only the keys
/// they care about. Without it, omitting any single key — `default_protocol`,
/// say — fails the whole config parse with `missing field`, which is a poor
/// trade for a section whose every field already has a sensible fallback in
/// [`PaymentsConfig::default`].
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PaymentsConfig {
    /// Whether the payment gate middleware is wired into the Web API.
    ///
    /// Tri-state on purpose. The role-driven default (see
    /// [`PaymentsConfig::effective`]) turns the gate on for a node that serves
    /// `ai` and can name a recipient, and the documented way to opt out is an
    /// explicit `enabled = false`. A plain `bool` cannot express that: omitted
    /// and `false` both arrive as `false`, so the opt-out has to be guessed at
    /// from surrounding fields — and the previous heuristic guessed that a
    /// operator who set a `recipient` had opted *out*, which inverts the one
    /// signal that most clearly means "I want this on".
    ///
    /// - `Some(true)`  — gate on, unconditionally
    /// - `Some(false)` — gate off, unconditionally (the explicit opt-out)
    /// - `None`        — unset; the role-driven default decides
    #[serde(default)]
    pub enabled: Option<bool>,

    /// Default payment protocol used to issue challenges (e.g. "mpp", "x402")
    pub default_protocol: String,

    /// Default amount charged when issuing a challenge (smallest unit)
    #[serde(with = "u128_as_string")]
    pub default_amount: u128,

    /// Default asset symbol (e.g. "USDC", "TNZO")
    pub default_asset: String,

    /// Recipient address or DID that payments are settled to
    pub recipient: String,

    /// List of Web API paths that are gated behind payment.
    /// Paths must match exactly (e.g. "/chat", "/api/inference").
    /// Routes not in this list bypass the payment gate entirely.
    #[serde(default)]
    pub paid_routes: Vec<String>,

    /// Stripe secret API key (e.g. `sk_test_...`).
    ///
    /// When set, the node constructs a [`StripeClient`] and wires a
    /// `SptCeilingResolver` into the [`IdentityPaymentBinder`], which adds
    /// Stripe SharedPaymentToken `usage_limits` enforcement as the third
    /// ceiling at payment time (alongside TDIP DelegationScope and runtime
    /// SpendingPolicy). Absent this key, SPT-authorized payments fall back
    /// to scope+policy enforcement only.
    ///
    /// Marked `#[serde(skip_serializing)]` so the key never round-trips
    /// out of `NodeConfig::save_to_file`; the `Debug` impl on
    /// [`PaymentsConfig`] redacts presence as `<redacted>` / `<unset>`.
    ///
    /// [`StripeClient`]: tenzro_payments::mpp::StripeClient
    /// [`IdentityPaymentBinder`]: tenzro_payments::identity_binding::IdentityPaymentBinder
    #[serde(default, skip_serializing)]
    pub stripe_api_key: Option<String>,

    /// Stripe API base URL override. Defaults to `https://api.stripe.com`.
    /// Useful for testing against a Stripe mock server.
    #[serde(default)]
    pub stripe_api_base: Option<String>,

    /// Operator-supplied canonical Tempo L1 TIP-20 stablecoin addresses,
    /// keyed by symbol (e.g. `"USDC" -> "0xabc..."`). When present, these
    /// override the placeholder addresses seeded by `init_token()` so the
    /// `TokenRegistry` `by_tempo_address` index resolves the same `TokenId`
    /// regardless of whether routing comes from this node or from a peer
    /// citing the operator's canonical Tempo issuance.
    ///
    /// Addresses must be 20-byte EVM-style hex with optional `0x` prefix;
    /// malformed entries are logged and skipped at startup.
    #[serde(default)]
    pub tempo_stablecoins: std::collections::HashMap<String, String>,

    /// Self-hosted x402 facilitation for the EIP-3009 / Permit2 schemes.
    ///
    /// When set, the node runs the eight exact/EVM verification checks against
    /// `evm_rpc_url` itself and settles `transferWithAuthorization` through a
    /// relayer signer keyed by `evm_relayer_key` — no dependency on a remote
    /// Coinbase CDP facilitator. Absent this block, the EIP-3009 / Permit2
    /// backends resolve through the remote CDP verifier.
    #[serde(default)]
    pub x402_facilitator: Option<X402FacilitatorConfig>,
}

/// Operator config for self-hosted x402 (EIP-3009 / Permit2) facilitation.
///
/// The relayer settles the buyer's signed `transferWithAuthorization` on the
/// external EVM chain where the stablecoin lives (e.g. Base Sepolia for the
/// USDC-testnet round-trip). The buyer never pays gas; the operator's relayer
/// broadcasts the meta-transaction and is reimbursed out of band.
#[derive(Clone, Serialize, Deserialize)]
pub struct X402FacilitatorConfig {
    /// EVM JSON-RPC endpoint used for the read checks (nonce state, balance,
    /// transfer simulation) and the settlement broadcast.
    pub evm_rpc_url: String,

    /// EVM chain id the relayer signs for (e.g. `84532` for Base Sepolia).
    pub chain_id: u64,

    /// Relayer private key (32-byte hex, optional `0x` prefix). Read from the
    /// `TENZRO_X402_RELAYER_KEY` environment variable when this field is unset
    /// so the secret need not live in a config file.
    ///
    /// `#[serde(skip_serializing)]` keeps the key out of any config written
    /// back by `NodeConfig::save_to_file`.
    #[serde(default, skip_serializing)]
    pub evm_relayer_key: Option<String>,
}

impl X402FacilitatorConfig {
    /// Resolve the relayer key from the config field or the
    /// `TENZRO_X402_RELAYER_KEY` env var. Returns `None` when neither is set.
    pub fn resolve_relayer_key(&self) -> Option<String> {
        self.evm_relayer_key
            .clone()
            .filter(|k| !k.trim().is_empty())
            .or_else(|| {
                std::env::var("TENZRO_X402_RELAYER_KEY")
                    .ok()
                    .filter(|k| !k.trim().is_empty())
            })
    }
}

impl std::fmt::Debug for X402FacilitatorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402FacilitatorConfig")
            .field("evm_rpc_url", &self.evm_rpc_url)
            .field("chain_id", &self.chain_id)
            .field(
                "evm_relayer_key",
                &if self.resolve_relayer_key().is_some() {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            .finish()
    }
}

impl Default for PaymentsConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            default_protocol: "mpp".to_string(),
            default_amount: 0,
            default_asset: "USDC".to_string(),
            recipient: String::new(),
            paid_routes: Vec::new(),
            stripe_api_key: None,
            stripe_api_base: None,
            tempo_stablecoins: std::collections::HashMap::new(),
            x402_facilitator: None,
        }
    }
}

/// The payment posture a node actually runs with, after folding in its
/// roles. Serving models (the `ai` role) is what the network pays providers
/// for, so a node that serves `ai` and can name a recipient gates its
/// inference routes by default. An operator turns this off by setting
/// `payments.enabled = false` explicitly.
#[derive(Debug, Clone)]
pub struct EffectivePayments {
    /// Whether the payment gate is wired at all.
    pub gate_on: bool,
    /// Address or DID payments settle to.
    pub recipient: String,
    /// Amount charged per challenge (smallest unit). Zero means the gate is
    /// wired but nothing is actually withheld — the mechanism runs, the price
    /// is not yet set.
    pub amount: u128,
    /// Asset the amount is denominated in.
    pub asset: String,
    /// Protocol used to issue challenges.
    pub protocol: String,
    /// Web paths gated behind payment.
    pub paid_routes: Vec<String>,
}

impl PaymentsConfig {
    /// Routes auto-gated for a node that serves the `ai` role: the inference
    /// surface. Operator-supplied `paid_routes` are merged on top.
    const AI_ROUTES: &'static [&'static str] = &["/chat"];

    /// Fold the node's roles and its own address into an effective payment
    /// posture.
    ///
    /// A node serving the `ai` role auto-gates its inference routes to
    /// `default_recipient` (its own validator/proposer address) unless the
    /// operator set `recipient` explicitly. The gate is on by default for
    /// `ai` nodes; setting `enabled = false` in config is the opt-out for
    /// operators who want to serve inference for free. Explicit
    /// `enabled = true` also forces the gate on regardless of role, using the
    /// operator-supplied `paid_routes`.
    ///
    /// `amount` defaults to whatever the config carries (0 for a freshly
    /// launched node), so the mechanism can be wired and proven on the fleet
    /// before a real price is set.
    pub fn effective(&self, roles: &RoleSet, default_recipient: Option<&str>) -> EffectivePayments {
        // Operator opt-out is now stated, not inferred: `enabled` is tri-state,
        // so `Some(false)` is unambiguously "turn it off" and `None` leaves the
        // decision to the role default. No need to read intent out of whether
        // other fields happen to be populated.
        let explicitly_disabled = self.enabled == Some(false);

        let recipient = if self.recipient.is_empty() {
            default_recipient.unwrap_or_default().to_string()
        } else {
            self.recipient.clone()
        };

        let role_gate = roles.serves_ai() && !recipient.is_empty() && !explicitly_disabled;
        let gate_on = self.enabled == Some(true) || role_gate;

        let mut paid_routes = self.paid_routes.clone();
        if role_gate {
            for r in Self::AI_ROUTES {
                if !paid_routes.iter().any(|p| p == r) {
                    paid_routes.push((*r).to_string());
                }
            }
        }

        EffectivePayments {
            gate_on,
            recipient,
            amount: self.default_amount,
            asset: self.default_asset.clone(),
            protocol: self.default_protocol.clone(),
            paid_routes,
        }
    }
}

impl std::fmt::Debug for PaymentsConfig {
    /// Custom `Debug` that redacts the Stripe secret key. Presence is
    /// reported as `<redacted>` / `<unset>`; all other fields pass through.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaymentsConfig")
            .field("enabled", &self.enabled)
            .field("default_protocol", &self.default_protocol)
            .field("default_amount", &self.default_amount)
            .field("default_asset", &self.default_asset)
            .field("recipient", &self.recipient)
            .field("paid_routes", &self.paid_routes)
            .field(
                "stripe_api_key",
                &if self.stripe_api_key.is_some() {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            .field("stripe_api_base", &self.stripe_api_base)
            .field("tempo_stablecoins", &self.tempo_stablecoins)
            .field("x402_facilitator", &self.x402_facilitator)
            .finish()
    }
}

/// Which Canton Global Synchronizer network a participant is joined to.
///
/// An operator may run one participant per network. The RPC resolves the
/// target network per request from the presenting API key
/// (`ApiKeyRecord::canton_networks`), falling back to
/// [`CantonConfig::default_network`] when the key authorizes exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum CantonNetwork {
    #[default]
    Devnet,
    Mainnet,
}

impl CantonNetwork {
    /// Canonical wire string, as accepted by the `canton_network` RPC
    /// parameter and stored on API key records.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Mainnet => "mainnet",
        }
    }

    /// Parse from the canonical wire string. Case-insensitive.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "devnet" => Some(Self::Devnet),
            "mainnet" => Some(Self::Mainnet),
            _ => None,
        }
    }
}

impl std::fmt::Display for CantonNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Connection + auth settings for one Canton participant.
///
/// One of these exists per network the operator serves. Auth is either an
/// OAuth2 client-credentials grant ([`Self::oauth`]) or a long-lived bearer
/// ([`Self::static_jwt`]); they are mutually exclusive, and `oauth` wins.
#[derive(Clone, Serialize, Deserialize)]
pub struct CantonNetworkConfig {
    /// Canton participant JSON Ledger API host.
    pub host: String,

    /// Canton participant JSON Ledger API port — the HTTP port serving
    /// `/v2/...`, not the gRPC Ledger API port. Every call this node makes
    /// to Canton is JSON over HTTP.
    pub port: u16,

    /// Use TLS when talking to the Ledger API. Leave `false` only when the
    /// participant is reached over a private network path (VPC peering, a
    /// WireGuard tunnel); anything crossing the public internet must set
    /// this.
    #[serde(default)]
    pub tls: bool,

    /// Override the DAML template id the workflow dispatcher uses when
    /// mirroring saga completions to this participant. When `None`, the
    /// canonical `#tenzro-workflow:Tenzro.Workflow:Receipt` is used. Format
    /// is `#<package-name>:<Module>:<Template>` so the participant resolves
    /// the latest installed version of the package.
    ///
    /// Declared ahead of [`Self::oauth`] because TOML forbids scalars after
    /// a nested table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_receipt_template: Option<String>,

    /// Long-lived bearer JWT for the Ledger API. Honoured only when
    /// [`Self::oauth`] is absent.
    #[serde(skip_serializing, default)]
    pub static_jwt: Option<String>,

    /// OAuth2 client-credentials grant for the Ledger API. All four of
    /// `token_url` / `client_id` / `client_secret` / `audience` are
    /// required; `scope` defaults to `daml_ledger_api`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<CantonOAuthConfig>,
}

impl std::fmt::Debug for CantonNetworkConfig {
    /// Redacts `static_jwt`; `oauth` redacts its own secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CantonNetworkConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("oauth", &self.oauth)
            .field(
                "static_jwt",
                &self.static_jwt.as_ref().map(|_| "<redacted>"),
            )
            .field("workflow_receipt_template", &self.workflow_receipt_template)
            .finish()
    }
}

/// Canton/DAML participant configuration.
///
/// The node fronts one participant per Canton network. Which participant a
/// canton-scoped RPC reaches is decided by the presenting API key, never by
/// the caller alone — see `ApiKeyRecord::canton_networks`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonConfig {
    /// Whether the Canton/DAML surface is enabled at all. When `false`, no
    /// adapter is built and every canton-scoped RPC errors.
    pub enabled: bool,

    /// Network used when a key authorizes more than one and the request
    /// does not name one explicitly.
    #[serde(default)]
    pub default_network: CantonNetwork,

    /// Devnet participant. `None` when this operator does not serve devnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devnet: Option<CantonNetworkConfig>,

    /// Mainnet participant. `None` when this operator does not serve
    /// mainnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mainnet: Option<CantonNetworkConfig>,

    /// Per-tenant identity-provider configuration (Stage 2). When
    /// enabled, `tenzro_createApiKey` provisions each tenant with
    /// their own upstream OAuth2 client, registers a dedicated Canton
    /// IdentityProviderConfig for that client, creates the user under
    /// that IDP, allocates a party under that IDP, and grants
    /// CanActAs. The tenant holds their own client_secret (returned
    /// once at issuance) and presents their own Canton JWT via
    /// `X-Canton-Auth: Bearer <jwt>` on subsequent canton-scoped
    /// requests; the Tenzro node forwards it as-is.
    ///
    /// Off by default — devnet uses the Stage 1 shared-principal
    /// model. Flip on for testnet/mainnet.
    #[serde(default)]
    pub identity_providers: CantonIdentityProvidersConfig,
}

/// Per-tenant IDP (Stage 2) configuration. Disabled by default —
/// devnet keeps the Stage 1 shared-principal flow until the operator
/// explicitly enables this block.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CantonIdentityProvidersConfig {
    /// Master switch. Off in devnet, on for testnet/mainnet.
    #[serde(default)]
    pub enabled: bool,

    /// Upstream IdP Management API base URL (e.g. the operator's own
    /// Auth0 domain or an equivalent OIDC management surface).
    /// Required when `enabled` is true so the node can mint per-tenant
    /// upstream clients. Loaded from `CANTON_IDP_MGMT_URL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mgmt_url: Option<String>,

    /// M2M client id authorized for the IdP Management API audience
    /// (needs `create:clients` + `delete:clients` +
    /// `create:client_grants`). Loaded from
    /// `CANTON_IDP_MGMT_CLIENT_ID`. The provisioner mints + refreshes
    /// its own short-lived Management API tokens from this pair, so
    /// no static token ever needs rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mgmt_client_id: Option<String>,

    /// M2M client secret. Loaded from `CANTON_IDP_MGMT_CLIENT_SECRET`
    /// and never serialized.
    #[serde(skip_serializing, default)]
    pub mgmt_client_secret: Option<String>,

    /// Audience to use when registering the shared Canton
    /// IdentityProviderConfig and when minting tenant client-grants.
    /// Typically the Canton participant's API audience. Loaded from
    /// `CANTON_IDP_AUDIENCE`. The issuer + JWKS URLs are derived from
    /// `mgmt_url` by the provisioner — they are not configured
    /// separately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canton_audience: Option<String>,
}

impl std::fmt::Debug for CantonIdentityProvidersConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CantonIdentityProvidersConfig")
            .field("enabled", &self.enabled)
            .field("mgmt_url", &self.mgmt_url)
            .field("mgmt_client_id", &self.mgmt_client_id)
            .field(
                "mgmt_client_secret",
                &self.mgmt_client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("canton_audience", &self.canton_audience)
            .finish()
    }
}

/// Operator-supplied OAuth2 client-credentials configuration for talking
/// to a self-hosted Canton validator. Mirrors the fields of
/// `tenzro_bridge::canton_auth::CantonAuthConfig` so the node can build
/// the upstream provider without leaking that type into config.
#[derive(Clone, Serialize, Deserialize)]
pub struct CantonOAuthConfig {
    pub token_url: String,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret: String,
    pub audience: String,
    #[serde(default = "default_oauth_scope")]
    pub scope: String,
}

impl std::fmt::Debug for CantonOAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CantonOAuthConfig")
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("audience", &self.audience)
            .field("scope", &self.scope)
            .finish()
    }
}

fn default_oauth_scope() -> String {
    "daml_ledger_api".to_string()
}

impl Default for CantonConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_network: CantonNetwork::Devnet,
            devnet: None,
            mainnet: None,
            identity_providers: CantonIdentityProvidersConfig::default(),
        }
    }
}

impl CantonNetworkConfig {
    /// Load one participant's settings from `CANTON_<NET>_*` env vars.
    ///
    /// Returns `None` unless `CANTON_<NET>_LEDGER_API_HOST` is set and
    /// non-empty — the presence of a host is what declares that this
    /// operator serves the network at all.
    fn from_env(net: CantonNetwork) -> Option<Self> {
        let prefix = format!("CANTON_{}", net.as_str().to_ascii_uppercase());
        let var = |suffix: &str| {
            std::env::var(format!("{prefix}_{suffix}"))
                .ok()
                .filter(|v| !v.is_empty())
        };

        let host = var("LEDGER_API_HOST")?;
        let port = var("LEDGER_API_PORT")
            .and_then(|p| p.parse().ok())
            .unwrap_or(7575);
        let tls = var("TLS").and_then(|v| v.parse().ok()).unwrap_or(false);

        let oauth = match (
            var("OAUTH_TOKEN_URL"),
            var("OAUTH_CLIENT_ID"),
            var("OAUTH_CLIENT_SECRET"),
            var("OAUTH_AUDIENCE"),
        ) {
            (Some(token_url), Some(client_id), Some(client_secret), Some(audience)) => {
                Some(CantonOAuthConfig {
                    token_url,
                    client_id,
                    client_secret,
                    audience,
                    scope: var("OAUTH_SCOPE").unwrap_or_else(default_oauth_scope),
                })
            }
            _ => None,
        };

        // A long-lived bearer is honoured only when no grant is configured.
        let static_jwt = if oauth.is_none() {
            var("JWT_TOKEN")
        } else {
            None
        };

        Some(Self {
            host,
            port,
            tls,
            oauth,
            static_jwt,
            workflow_receipt_template: var("WORKFLOW_RECEIPT_TEMPLATE"),
        })
    }
}

impl CantonConfig {
    /// Create from environment variables, falling back to defaults.
    ///
    /// `CANTON_ENABLED=true` turns the surface on. Each network is declared
    /// by setting its host, and configured independently:
    ///
    /// ```text
    /// CANTON_DEVNET_LEDGER_API_HOST     CANTON_MAINNET_LEDGER_API_HOST
    /// CANTON_DEVNET_LEDGER_API_PORT     CANTON_MAINNET_LEDGER_API_PORT
    /// CANTON_DEVNET_TLS                 CANTON_MAINNET_TLS
    /// CANTON_DEVNET_OAUTH_TOKEN_URL     CANTON_MAINNET_OAUTH_TOKEN_URL
    /// CANTON_DEVNET_OAUTH_CLIENT_ID     CANTON_MAINNET_OAUTH_CLIENT_ID
    /// CANTON_DEVNET_OAUTH_CLIENT_SECRET CANTON_MAINNET_OAUTH_CLIENT_SECRET
    /// CANTON_DEVNET_OAUTH_AUDIENCE      CANTON_MAINNET_OAUTH_AUDIENCE
    /// CANTON_DEVNET_OAUTH_SCOPE         CANTON_MAINNET_OAUTH_SCOPE
    /// CANTON_DEVNET_JWT_TOKEN           CANTON_MAINNET_JWT_TOKEN
    /// ```
    ///
    /// `CANTON_DEFAULT_NETWORK` (`devnet` | `mainnet`) picks the network
    /// used when a request carries no `canton_network` param and no API
    /// key to read an authorized set from — the admin-token path, and the
    /// workflow saga mirror. A key that authorizes several networks must
    /// name one on the request.
    pub fn from_env() -> Self {
        let enabled = std::env::var("CANTON_ENABLED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false);

        let default_network = std::env::var("CANTON_DEFAULT_NETWORK")
            .ok()
            .and_then(|v| CantonNetwork::from_str_opt(&v))
            .unwrap_or_default();

        Self {
            enabled,
            default_network,
            devnet: CantonNetworkConfig::from_env(CantonNetwork::Devnet),
            mainnet: CantonNetworkConfig::from_env(CantonNetwork::Mainnet),
            identity_providers: CantonIdentityProvidersConfig::from_env(),
        }
    }

    /// Settings for one network, or `None` when this operator does not
    /// serve it.
    pub fn network(&self, net: CantonNetwork) -> Option<&CantonNetworkConfig> {
        match net {
            CantonNetwork::Devnet => self.devnet.as_ref(),
            CantonNetwork::Mainnet => self.mainnet.as_ref(),
        }
    }

    /// Every network this operator serves, in canonical order.
    pub fn configured_networks(&self) -> Vec<CantonNetwork> {
        [CantonNetwork::Devnet, CantonNetwork::Mainnet]
            .into_iter()
            .filter(|net| self.network(*net).is_some())
            .collect()
    }
}

impl CantonIdentityProvidersConfig {
    /// Load Stage 2 IDP config from environment variables.
    ///
    /// All fields are optional; the master switch `enabled` defaults
    /// to `false`, keeping the Stage 1 shared-principal flow active
    /// in devnet. Flip `CANTON_IDP_ENABLED=true` in testnet/mainnet
    /// configs after also supplying the management URL + M2M client
    /// credentials + audience.
    pub fn from_env() -> Self {
        let enabled = std::env::var("CANTON_IDP_ENABLED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false);
        Self {
            enabled,
            mgmt_url: std::env::var("CANTON_IDP_MGMT_URL")
                .ok()
                .filter(|v| !v.is_empty()),
            mgmt_client_id: std::env::var("CANTON_IDP_MGMT_CLIENT_ID")
                .ok()
                .filter(|v| !v.is_empty()),
            mgmt_client_secret: std::env::var("CANTON_IDP_MGMT_CLIENT_SECRET")
                .ok()
                .filter(|v| !v.is_empty()),
            canton_audience: std::env::var("CANTON_IDP_AUDIENCE")
                .ok()
                .filter(|v| !v.is_empty()),
        }
    }
}

/// Which data-availability backend the node uses for off-loaded receipt and
/// agent-memory payloads.
///
/// Only the async DA consumers (agent-memory archival) honor `IrohBlobs`; the
/// settlement-channel receipt path is a synchronous storage trait and always
/// uses the in-process inline store regardless of this setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaBackendSelector {
    /// Use the iroh-blobs backend when the iroh resolver is bound, otherwise
    /// fall back to the in-process inline store. This is the default.
    #[default]
    Auto,
    /// Force the in-process inline store even when iroh is available. Useful
    /// for minimal single-node operators who do not want blobs advertised on
    /// the iroh data plane.
    Inline,
    /// Require the iroh-blobs backend. Node startup fails if the iroh resolver
    /// is not bound.
    IrohBlobs,
    /// Require the committee-resident erasure-coded store. Slivers are
    /// distributed across the validator committee and an availability
    /// certificate (2f+1 signed attestations) anchors each pointer. Node
    /// startup fails if the committee backend is not bound (non-validator
    /// roles, or consensus not initialized).
    Committee,
}

/// How the node divides memory between models and everything else.
///
/// The node serves models out of the same pool that holds RocksDB's block
/// cache, the iroh endpoint, the web/MCP/A2A surfaces, and the OS. Left
/// unmanaged, models expand into memory that storage needs and the machine
/// dies under an OOM kill. These settings draw the line.
///
/// All fields are in **GiB** rather than bytes: an operator sets these by
/// hand, and `reserve_gb = 16` is legible where `17179869184` is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MemoryConfig {
    /// Total memory the node may account for. `None` detects the machine's
    /// physical memory, which is right when the node owns the box. Set it
    /// lower when sharing a host with other workloads — the node cannot see
    /// those and will otherwise count their memory as its own.
    pub total_gb: Option<u32>,

    /// Held back from models for the OS, this process, RocksDB, iroh, and the
    /// service surfaces. Never lent to a model at any load.
    ///
    /// Raise it on a node carrying a deep RocksDB working set or co-hosting
    /// other services; a node that only serves models can lower it.
    pub reserve_gb: u32,

    /// Ceiling for always-resident models: language models, embeddings,
    /// forecasting, ASR, TTS. `None` gives them 60% of what remains after the
    /// reserve.
    pub resident_ceiling_gb: Option<u32>,

    /// Ceiling for pipelines loaded per job and evicted afterwards — image
    /// and video generation. `None` gives them whatever the resident tier
    /// does not take.
    ///
    /// Separate from the resident ceiling on purpose: a chat model must not
    /// be able to crowd out the diffusion worker, and a video pipeline must
    /// not evict the model currently answering requests.
    pub on_demand_ceiling_gb: Option<u32>,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            total_gb: None,
            reserve_gb: (tenzro_model::memory_budget::DEFAULT_RESERVE_BYTES / (1024 * 1024 * 1024))
                as u32,
            resident_ceiling_gb: None,
            on_demand_ceiling_gb: None,
        }
    }
}

impl MemoryConfig {
    /// Project into the model layer's budget configuration.
    ///
    /// Detects physical memory when `total_gb` is unset. GiB are widened to
    /// bytes here so the operator-facing units and the accounting units stay
    /// separate.
    pub fn to_budget_config(&self) -> tenzro_model::memory_budget::BudgetConfig {
        const GIB: u64 = 1024 * 1024 * 1024;
        let total_bytes = match self.total_gb {
            Some(gb) => u64::from(gb) * GIB,
            None => {
                let mut sys = sysinfo::System::new();
                sys.refresh_memory();
                sys.total_memory()
            }
        };
        tenzro_model::memory_budget::BudgetConfig {
            total_bytes,
            reserve_bytes: u64::from(self.reserve_gb) * GIB,
            resident_ceiling_bytes: self.resident_ceiling_gb.map(|gb| u64::from(gb) * GIB),
            on_demand_ceiling_bytes: self.on_demand_ceiling_gb.map(|gb| u64::from(gb) * GIB),
        }
    }
}

/// What the operator is willing to rent out.
///
/// Distinct from [`MemoryConfig`], which bounds what the node's own models may
/// take. This bounds what *tenants* may take, and the two are different
/// decisions with different owners: an operator happy to rent 40 GB of
/// accelerator memory may still want their own models to keep 60.
///
/// Every figure is what the operator CHOSE to offer, not what the machine
/// has. A 121 GB box may offer 60; the other 61 is retained, not undersold.
/// All-zero — the default — means nothing is for rent, which is the right
/// default because an operator who has not said what is for sale has not
/// opted in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RentalConfig {
    /// CPU cores offered to tenants.
    pub cpu_cores: u32,
    /// System memory offered, GiB.
    pub memory_gb: u32,
    /// Per-accelerator memory offered, keyed by host index, GiB.
    ///
    /// On unified-memory hardware this is the figure that matters: granting a
    /// whole accelerator there hands over the pool the node itself runs from,
    /// so an operator renting a GPU without renting the machine has to slice
    /// it by memory.
    pub accelerator_gb: std::collections::HashMap<u32, u32>,
    /// Disk offered, GiB.
    pub storage_gb: u32,
}

impl RentalConfig {
    /// Whether the operator has offered anything at all.
    pub fn offers_anything(&self) -> bool {
        self.cpu_cores > 0
            || self.memory_gb > 0
            || self.storage_gb > 0
            || self.accelerator_gb.values().any(|&gb| gb > 0)
    }

    /// Project into the rental ledger's capacity type.
    pub fn to_rentable_capacity(&self) -> crate::remote_access::RentableCapacity {
        crate::remote_access::RentableCapacity {
            cpu_cores: self.cpu_cores,
            memory_mib: u64::from(self.memory_gb) * 1024,
            accelerator_mib: self
                .accelerator_gb
                .iter()
                .map(|(&i, &gb)| (i, u64::from(gb) * 1024))
                .collect(),
            storage_mib: u64::from(self.storage_gb) * 1024,
        }
    }
}

/// Economic settings an operator declares for this node.
///
/// The *rates* are not here — those are governance's, held in
/// [`tenzro_types::economics::EconomicPolicy`] and applied network-wide. What
/// an operator declares locally is only who they are paying alongside
/// themselves, which is a fact about their own arrangement rather than a price.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EconomicsConfig {
    /// The RPC provider validating on this node's behalf, as a hex address.
    ///
    /// Required only when this node advertises a capability *and does not run
    /// the validator role* — someone is validating for its users, and that
    /// party is owed a share. A node that validates for itself leaves this
    /// unset.
    ///
    /// Settlement refuses rather than defaulting when it is missing, because
    /// the alternative — quietly paying that share to the treasury — pays the
    /// wrong party and reports nothing wrong.
    #[serde(default)]
    pub rpc_provider_payee: Option<String>,
}

/// Public DNS suffix node aliases render under during the testnet.
///
/// A domain is required at all because WebAuthn scopes every credential to a
/// registrable domain — a raw IP or a DID cannot be an RP ID. It is therefore
/// a presentation detail with an expected shelf life, which is why a claim
/// stores only its bare label and this suffix lives in configuration.
pub const DEFAULT_PUBLIC_NODE_SUFFIX: &str = "network.tenzro.com";

fn default_public_node_suffix() -> Option<String> {
    Some(DEFAULT_PUBLIC_NODE_SUFFIX.to_string())
}

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    /// Every role this node serves. A node stakes once and may hold many roles
    /// at once (e.g. validator + AI + storage). Parsed from `--roles
    /// validator,storage,ai`.
    pub roles: RoleSet,

    /// Self-stake (wei) committed when a validator-role node auto-registers
    /// itself into the ValidatorRegistry on boot (permissionless / first-boot
    /// onboarding). `None` disables self-registration. Must be >= the registry
    /// minimum (10,000 TNZO). The node's own validator-derived account must be
    /// funded with this stake plus gas before boot.
    #[serde(default)]
    pub validator_self_stake: Option<u128>,

    /// Data directory for storage
    pub data_dir: PathBuf,

    /// Network configuration
    pub network: NetworkConfig,

    /// Consensus configuration (for validators)
    pub consensus: Option<ConsensusConfig>,

    /// Enable TEE features
    pub tee_enabled: bool,

    /// Models directory for inference providers
    pub models_dir: Option<PathBuf>,

    /// How the node divides memory between models and everything else.
    pub memory: MemoryConfig,

    /// What the operator is willing to rent out to tenants.
    #[serde(default)]
    pub rental: RentalConfig,

    /// Whether and how the node tunes its own serving configuration.
    ///
    /// Off by default: a node that rewrites its own dials is one an operator
    /// has to reason about during an incident, so it is opted into. When off
    /// the controller still runs and records what it *would* have done, which
    /// is the sensible way to build confidence before enabling it.
    #[serde(default)]
    pub autotune: crate::autotune_sampler::AutotuneConfig,

    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,

    /// SHA-256 digests (hex) of service keys that may reach this node's
    /// service surface — JSON-RPC, MCP, A2A and the web API.
    ///
    /// Empty is the default and means the gate is off: the network is
    /// permissionless and a node that configures nothing serves anyone.
    /// Setting even one digest turns the gate on for all four surfaces at
    /// once; `/health` and `/ready` stay reachable regardless so an
    /// orchestrator can still see the node.
    ///
    /// Digests rather than plaintext, because a config file is the wrong
    /// place to keep a secret. Generate one with
    /// `printf %s "<key>" | sha256sum`, or let the node hash it by passing
    /// the plaintext through `TENZRO_SERVICE_KEYS` instead.
    ///
    /// This gate covers the service surface only. A gated node still
    /// validates, votes and gossips.
    #[serde(default)]
    pub service_keys: Vec<String>,

    /// This node's own TDIP identity, named explicitly.
    ///
    /// A node is a *machine*. Under TDIP that is either
    /// `did:tenzro:machine:<controller>:<uuid>` — a machine a human operator
    /// delegates, which is the usual shape — or `did:tenzro:machine:<uuid>`
    /// for one that acts autonomously. Everything the node owns (files,
    /// databases, sites, receipts) is attributed to it, so getting it wrong
    /// misattributes all of them.
    ///
    /// Set it. Left unset the node *infers* one from its registry, and
    /// inference is only ever a guess: a registry holds the operator's own
    /// human identity, every agent the node has spawned, and every machine it
    /// has enrolled, with nothing in the data marking which one is the node
    /// itself. The inference is documented at `resolve_operator_identity` and
    /// deliberately prefers machines over humans, but a node that has enrolled
    /// several machines can still be handed the wrong one — naming it here is
    /// how that stops being a guess.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_did: Option<String>,

    /// RPC server listen address
    pub rpc_addr: String,

    /// Web Verification API listen address
    pub web_addr: String,

    /// MCP server listen address
    pub mcp_addr: String,

    /// A2A protocol server listen address
    pub a2a_addr: String,

    /// Solana MCP server listen address
    pub solana_mcp_addr: String,

    /// Ethereum MCP server listen address
    pub ethereum_mcp_addr: String,

    /// Canton MCP server listen address
    pub canton_mcp_addr: String,

    /// LayerZero MCP server listen address
    pub layerzero_mcp_addr: String,

    /// Chainlink MCP server listen address
    pub chainlink_mcp_addr: String,

    /// LI.FI MCP server listen address
    pub lifi_mcp_addr: String,

    /// Enable metrics collection
    pub metrics_enabled: bool,

    /// Enable health monitoring
    pub health_enabled: bool,

    /// Genesis configuration
    pub genesis: Option<GenesisConfig>,

    /// Canton/DAML participant configuration
    #[serde(default)]
    pub canton: CantonConfig,

    /// MCP plugin host configuration. Operator-curated MCP runtime.
    /// Empty default = vault root auto-derived from node identity,
    /// no subprocess cap.
    #[serde(default)]
    pub mcp_plugin_host: McpPluginHostConfig,

    /// Upstreams for the `builtin://` skills and tools. Unset upstreams
    /// keep the corresponding builtins unregistered on this node.
    #[serde(default)]
    pub builtins: BuiltinsConfig,

    /// Economic settings for this node. Rates are governance's; this is only
    /// who the operator pays alongside themselves.
    #[serde(default)]
    pub economics: EconomicsConfig,

    /// Vendor attestation roots this node pins, as base64 DER certificates.
    ///
    /// A device binding is graded hardware-bound only when its attestation
    /// chain reaches one of these — the FIDO Metadata Service entry for the
    /// credential's AAGUID, or the platform vendor's root. **Empty is a safe
    /// default, not a permissive one**: with no roots configured, devices still
    /// bind and still authenticate, but none grades as hardware-bound, so the
    /// wallet gate refuses and says why rather than silently accepting a
    /// software key.
    #[serde(default)]
    pub webauthn_trusted_roots: Vec<String>,

    /// HTTP 402 payment gate configuration for the Web API
    #[serde(default)]
    pub payments: PaymentsConfig,

    /// Cross-chain bridge adapter configuration (LayerZero/CCIP/deBridge/LI.FI).
    #[serde(default)]
    pub bridge: BridgeConfig,

    /// Tenzro Cortex recurrent-depth reasoning workers. Each entry is
    /// auto-registered at node startup and becomes available via
    /// `tenzro_cortexInference` RPC and `cortex_reason` MCP tool.
    #[serde(default)]
    pub cortex: CortexConfig,

    /// Tenzro Train auto-provisioning daemon. When enabled, the node
    /// discovers active training runs it participates in and spawns the
    /// Python reference trainer as a supervised subprocess per run.
    /// Disabled by default.
    #[serde(default)]
    pub training: TrainingConfig,

    /// Allowed CORS origins for RPC/Web/A2A servers.
    /// Empty list means allow all origins (development mode).
    /// In production, set to specific domains like `["https://app.tenzro.com"]`.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,

    /// External (advertised) RPC endpoint URL. Used when gossiping model
    /// service registrations so peers can dial this node from outside its
    /// local network. When `None`, constructed from `rpc_addr` (which may
    /// be a non-routable bind address like `0.0.0.0:8545`).
    /// Example: `Some("https://rpc.tenzro.xyz".to_string())`.
    #[serde(default)]
    pub external_rpc_addr: Option<String>,

    /// Public DNS suffix that node aliases are rendered under, e.g.
    /// `network.tenzro.com` — a node claiming the alias `alice` is then
    /// reachable at `alice.network.tenzro.com`.
    ///
    /// Deliberately configuration rather than a constant, and deliberately
    /// absent from the stored claim: the claim records a bare label, and the
    /// suffix exists only because WebAuthn requires a registrable domain for
    /// its RP ID. That makes the domain a temporary, swappable presentation
    /// detail — retiring or changing it must not invalidate a single claim.
    ///
    /// `None` disables public hostname resolution on this node entirely: a
    /// node with no configured suffix must not claim to answer for any
    /// public hostname.
    ///
    /// Defaults to [`DEFAULT_PUBLIC_NODE_SUFFIX`]. Safe as a default because
    /// resolution additionally requires a *bound* alias, so a node that has
    /// claimed nothing answers for nothing regardless of the suffix.
    #[serde(default = "default_public_node_suffix")]
    pub public_node_suffix: Option<String>,

    /// External (advertised) MCP endpoint URL. Used when gossiping model
    /// service registrations so peers can dial the MCP server from outside
    /// the local network. When `None`, constructed from `mcp_addr`.
    /// Example: `Some("https://mcp.tenzro.xyz/mcp".to_string())`.
    #[serde(default)]
    pub external_mcp_addr: Option<String>,

    /// Upstream JSON-RPC endpoint consulted when a DID is absent from the
    /// local identity registry (remote fallback resolution). Typically a
    /// bootstrap validator, e.g. `Some("https://rpc.tenzro.xyz".to_string())`.
    /// `None` disables remote fallback — unknown DIDs resolve to NotFound.
    #[serde(default)]
    pub did_fallback_rpc: Option<String>,

    /// Geographic locality of this node (free-form identifier such as
    /// `us-east`, `eu-west`, `ap-southeast`). Carried through to
    /// the gossiped `ProviderAnnouncementMessage::geography` so peers can
    /// route inference / TEE work by region. `None` means the operator
    /// declined to declare; consumers must treat `None` as "unknown",
    /// not as a wildcard.
    #[serde(default)]
    pub geography: Option<String>,

    /// Declared jurisdiction of this node: ISO 3166-1 alpha-2 country
    /// code (e.g. `DE`, `SG`, `US`). Unlike `geography` (a free-form
    /// routing hint), this is the machine-checkable locality claim that
    /// jurisdiction-pinned inference filters on and that jurisdiction
    /// receipts attest. When the node runs inside a TEE, the claim is
    /// bound to the attestation report hash at announcement time. `None`
    /// means the node never satisfies a jurisdiction pin (fail-closed).
    #[serde(default)]
    pub jurisdiction_country: Option<String>,

    /// Regulatory blocs this node's jurisdiction belongs to, as free-form
    /// uppercase tokens (e.g. `EU`, `EEA`, `GDPR`). Matched verbatim
    /// (case-insensitive) against jurisdiction pins — the protocol imposes
    /// no bloc vocabulary. Ignored unless `jurisdiction_country` is set.
    #[serde(default)]
    pub jurisdiction_blocs: Vec<String>,

    /// Tenzro iroh integration. The node always constructs a single
    /// `IrohBackedResolver` at startup and shares it across every consumer
    /// that needs an iroh endpoint: the training `GradientPayloadStore`,
    /// the storage `IrohBlobsDaBackend`, agent-memory archival, and any
    /// direct `tenzro://blob/<hash>` URI fetches.
    ///
    /// The default (`TenzroIrohConfig::default()`) anchors discovery to the
    /// Tenzro-operated Pkarr relay (`https://pkarr.tenzro.xyz`) with
    /// the n0 fallback disabled so discovery cannot leak off-network. The
    /// resolver binds **alongside** libp2p — it does not replace the
    /// libp2p control plane. Per the locked model statement (2026-05-17):
    /// "Tenzro uses Iroh as a performance-oriented P2P data plane while
    /// retaining libp2p-style interoperability for decentralized
    /// coordination."
    #[serde(default)]
    pub iroh: tenzro_iroh::TenzroIrohConfig,

    /// Data-availability backend selector for off-loaded payloads (agent-memory
    /// archival). `Auto` (default) prefers iroh-blobs when the resolver is
    /// bound; `Inline` forces the in-process store; `IrohBlobs` requires iroh.
    #[serde(default)]
    pub da_backend: DaBackendSelector,

    /// Optional Canton/DAML ERC-8004 mirror wiring. When present, every
    /// TDIP machine registration also buffers (or, with a wired
    /// `DamlMirrorTransport`, submits) a `RegistryAdmin.Register`
    /// command against the in-tree DAML port of the canonical
    /// ERC-8004 IdentityRegistry (see
    /// `vendor/erc8004-daml/daml/Tenzro/Erc8004/`).
    ///
    /// All four fields are participant-side identifiers unknown to
    /// `tenzro-identity`: they must be supplied by the operator after
    /// (a) running `daml build` on the vendored DAR (the resulting
    /// SHA-256 is `package_id`), (b) allocating the Tenzro Network
    /// admin party on the target Canton participant (`admin_party`),
    /// and (c) one-time creating the long-lived `RegistryAdmin`
    /// contract under the admin party (`admin_contract_id`).
    ///
    /// `None` is the default and disables the DAML mirror entirely —
    /// the EVM + SVM mirrors are unaffected.
    #[serde(default)]
    pub erc8004_daml: Option<Erc8004DamlConfig>,

    /// State-sync snapshot producer cadence + retention. Disabled by
    /// default — only dedicated RPC / archival operators should produce
    /// snapshots, since every snapshot is a multi-GB copy of the full
    /// state. Validators run with the default (disabled) so they never
    /// accumulate snapshot directories on their data volume.
    #[serde(default)]
    pub snapshot: crate::snapshot::SnapshotConfig,

    /// Managed-database engine endpoints this node serves. Each configured
    /// endpoint registers a live [`crate::db_engine_registry::EngineRegistry`]
    /// backend for that engine id, so a `tenzro_databaseQuery` against a
    /// partition this node holds dispatches to a real engine. Default serves
    /// no engines.
    #[serde(default)]
    pub databases: DatabasesConfig,

    /// Application-hosting edge configuration. Each operator serves deployed
    /// sites under its own domain — there is no network-wide edge. `None`
    /// (default) means this node advertises no auto-subdomain suffix and the
    /// custom-domain onboarding records are emitted with placeholders the
    /// operator fills in. An RPC-public operator sets `app_domain` to the
    /// domain it terminates TLS for (e.g. its own `apps.<operator>.tld`).
    #[serde(default)]
    pub hosting: HostingConfig,

    /// Rates this operator charges for the metered provider runtimes —
    /// storage capacity and accelerator rental. Both are quoted per billing
    /// epoch ([`crate::node::BILLING_EPOCH_INTERVAL_SECS`], one hour), so the
    /// compute rate is wei per card-hour and the storage rate is wei per
    /// byte-hour. Defaults match the network's reference rates.
    #[serde(default)]
    pub provider_rates: ProviderRatesConfig,

    /// Operator model-license acceptance policy. Governs which catalog models
    /// this node will register/serve: Permissive and Attribution tiers are
    /// always admitted; NonCommercial requires `accept_non_commercial`;
    /// CommercialCustom requires the model's license id to be listed in
    /// `accepted_license_ids`. Set from `--accept-non-commercial` and
    /// `--accept-license <id>` (repeatable). Default admits open-weight
    /// (permissive/attribution) models only.
    #[serde(default)]
    pub model_licensing: tenzro_types::model::AcceptancePolicy,

    /// The USD price of one TNZO this operator lists at, in micro-USD
    /// (1e-6 USD) — `Some(50_000)` declares $0.05. It is a commercial
    /// declaration by the gateway operator, not an oracle reading: TNZO
    /// stays the settlement unit, the per-token wei prices in `GET
    /// /v1/models` remain authoritative, and this rate only derives the
    /// USD-denominated listing prices that external aggregators ingest.
    /// `None` (the default) omits the USD keys from the listing rather
    /// than publishing a rate the operator never quoted.
    #[serde(default)]
    pub listing_tnzo_usd_micro: Option<u64>,
}

/// Application-hosting edge configuration.
///
/// Site hosting is operator-served, not network-served: each operator runs its
/// own ingress under its own domain, so nothing here is baked into the
/// protocol. The node reports whatever the operator configured so onboarding
/// records (auto subdomains, custom-domain CNAME targets) name the operator's
/// edge rather than any single canonical host.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HostingConfig {
    /// The domain this operator's edge serves deployed sites under. When set,
    /// auto-assigned site subdomains are `<name>-<hash>.<app_domain>` and a
    /// custom-domain subdomain claim is told to `CNAME` to `<app_domain>`.
    /// When `None`, the node advertises no suffix and onboarding output uses a
    /// `<your-operator-app-domain>` placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_domain: Option<String>,

    /// Public IPv4 the edge answers on, printed as the `A` record for apex
    /// custom domains. `None` leaves an `<edge-ipv4>` placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_ipv4: Option<String>,

    /// Public IPv6 the edge answers on, printed as the `AAAA` record for apex
    /// custom domains. `None` leaves an `<edge-ipv6>` placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_ipv6: Option<String>,

    /// Per-hour price in TNZO this operator quotes to host an app deployment.
    /// Advertised in the provider announcement as the operator's hosting bid;
    /// placement ranks capable nodes cheapest first. `0` (the default) means the
    /// operator hosts for free — the most competitive bid.
    #[serde(default, with = "u128_as_string")]
    pub price_per_hour: u128,
}

/// Rates the provider runtimes spawn with.
///
/// One billing epoch is [`crate::node::BILLING_EPOCH_INTERVAL_SECS`] seconds,
/// so the metered rates are per hour: the compute rate is what a renter pays
/// for an hour of this node's accelerators, the storage rate what a depositor
/// pays to hold one byte for an hour. An operator that wants either to follow
/// demand configures [`crate::pricing::PricingPolicy::Dynamic`] with a capacity
/// and a band; the runtime then steps it each epoch from metered utilization.
///
/// Inference is priced per token instead of per epoch, so it carries the full
/// [`crate::node::ProviderPricing`] card rather than a policy. It is clamped to
/// the network maximums when the node reads it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProviderRatesConfig {
    /// How the storage runtime prices a byte-epoch.
    #[serde(default = "default_storage_policy")]
    pub storage: crate::pricing::PricingPolicy,

    /// How the compute-rental runtime prices an epoch.
    #[serde(default = "default_compute_policy")]
    pub compute: crate::pricing::PricingPolicy,

    /// What this provider charges per token, per modality unit, and under
    /// which pricing model.
    #[serde(default)]
    pub inference: crate::node::ProviderPricing,
}

fn default_storage_policy() -> crate::pricing::PricingPolicy {
    crate::pricing::PricingPolicy::Fixed {
        rate: crate::node::DEFAULT_STORAGE_RATE_PER_BYTE_EPOCH,
    }
}

fn default_compute_policy() -> crate::pricing::PricingPolicy {
    crate::pricing::PricingPolicy::Fixed {
        rate: crate::node::DEFAULT_COMPUTE_RATE_PER_EPOCH,
    }
}

impl Default for ProviderRatesConfig {
    fn default() -> Self {
        Self {
            storage: default_storage_policy(),
            compute: default_compute_policy(),
            inference: crate::node::ProviderPricing::default(),
        }
    }
}

/// Operator-supplied Canton/DAML mirror config for the ERC-8004
/// IdentityRegistry. See [`NodeConfig::erc8004_daml`] for the activation
/// contract.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Erc8004DamlConfig {
    /// SHA-256 (64 hex chars) of the compiled `Tenzro.Erc8004.*` DAR
    /// artifact. Printed by `daml build` and also queryable via the
    /// Canton participant's `PackageManagementService.ListKnownPackages`
    /// RPC. Same package id covers all three modules (Identity /
    /// Reputation / Validation).
    pub package_id: String,

    /// The Tenzro Network admin party id allocated on the target
    /// Canton participant (e.g. `TenzroAdmin::123abc...`).
    pub admin_party: String,

    /// Contract id of the single long-lived `RegistryAdmin` contract
    /// held by the admin party. Allocated once at participant setup
    /// via `RegistryAdmin` template create + a stored cid lookup.
    pub admin_contract_id: String,

    /// Default controller party id used when a TDIP machine
    /// registration has no Canton-side party binding (the common case
    /// today — Canton parties are operator-allocated, not
    /// per-machine).
    pub default_controller_party: String,
}

/// Upstreams the `builtin://` skills and tools dispatch to.
///
/// A builtin whose upstream is unset is not registered on this node, so
/// callers discover only what the node can actually serve.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BuiltinsConfig {
    /// Base URL of a SearXNG-compatible JSON search endpoint, e.g.
    /// `https://search.example.org`. Backs the `web-search` skill and the
    /// `web_search` tool call on `web-search-mcp`.
    #[serde(default)]
    pub search_url: Option<String>,

    /// Bearer token for `search_url`, when the operator's instance
    /// requires one.
    #[serde(default)]
    pub search_api_key: Option<String>,

    /// 1inch Developer Portal API key. Backs the `oneinch-aggregator`
    /// skill; the operator's key, per the resource-brokerage model.
    #[serde(default)]
    pub oneinch_api_key: Option<String>,
}

/// Configuration for the MCP plugin host. Lets operators run custom +
/// third-party MCPs on their node without recompiling.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct McpPluginHostConfig {
    /// 64-hex-character root master secret for the operator credential
    /// vault. AES-256-GCM root IKM via HKDF-SHA256. When set, every
    /// `tenzro_storeMcpSecret` call seals the secret under this IKM and
    /// persists the envelope to `CF_VALIDATOR_MODULES`.
    ///
    /// When unset, the node auto-derives the IKM from a deterministic
    /// HKDF over the node's persistent identity key (graceful default
    /// for single-operator dev). On production multi-tenant operators,
    /// set this explicitly so the vault root is auditable and rotatable
    /// independent of the node identity.
    #[serde(default)]
    pub master_secret_hex: Option<String>,

    /// Hard cap on the number of stdio MCP subprocesses kept alive in
    /// persistent mode. When the cap is hit, the oldest subprocess is
    /// evicted to make room. `None` = no cap (each operator-registered
    /// stdio MCP gets its own subprocess for the lifetime of the node).
    #[serde(default)]
    pub max_persistent_subprocesses: Option<usize>,
}

/// Managed-database engine endpoints this node serves.
///
/// The `tenzro-database` protocol layer records *what* databases exist and
/// *where* their partitions land; a query against a partition this node holds
/// dispatches to a live engine backend. This config supplies the operator-run
/// engine endpoints the node connects to (connect-to-existing model): the node
/// does not spawn the engine, it holds a client to one the operator runs.
///
/// Absent an endpoint for an engine, the node serves no backend of that kind —
/// a query for it returns a routing error, not a panic. Embedded engines
/// (Lance / Tantivy) need no endpoint; they serve in-process under `data_dir`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DatabasesConfig {
    /// PostgreSQL connection string (`host=… port=… user=… password=…`). When
    /// set, the node serves the `postgres` engine against it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres_url: Option<String>,

    /// Qdrant REST base URL (`http://host:6333`). When set, the node serves the
    /// `qdrant` engine against it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qdrant_url: Option<String>,

    /// Optional Qdrant API key, sent as the `api-key` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qdrant_api_key: Option<String>,

    /// Valkey connection URL (`redis://host:6379`). When set, the node serves
    /// the `valkey` engine against it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valkey_url: Option<String>,

    /// Serve the embedded Lance vector store in-process. Data lives under
    /// `{data_dir}/databases/lance/`.
    #[serde(default)]
    pub lance_embedded: bool,

    /// Serve the embedded Tantivy full-text index in-process. Data lives under
    /// `{data_dir}/databases/tantivy/`.
    #[serde(default)]
    pub tantivy_embedded: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self::default_user()
    }
}

impl NodeConfig {
    /// Create a default validator configuration
    pub fn default_validator() -> Self {
        // Validators are the public, well-connected node class — they run
        // both halves of the NAT-traversal stack: relay v2 server +
        // AutoNAT v2 server, so community joiners behind NAT can reach
        // the network through them. Relay client + AutoNAT client + DCUtR
        // are also on (kept inherited from `enable_hole_punching=true`)
        // so a validator that itself starts behind NAT (e.g. dev laptop)
        // still completes hole-punching against another validator. See
        // `tenzro-network::TenzroBehaviour` for the full toggle matrix.
        let network = NetworkConfig {
            enable_relay: true,
            ..NetworkConfig::default()
        };
        Self {
            roles: RoleSet::validator_only(),
            validator_self_stake: None,
            data_dir: tenzro_types::paths::instance_data_dir("validator"),
            network,
            consensus: Some(ConsensusConfig::default()),
            tee_enabled: true,
            models_dir: None,
            memory: MemoryConfig::default(),
            autotune: crate::autotune_sampler::AutotuneConfig::default(),
            rental: RentalConfig::default(),
            log_level: "info".to_string(),
            // Validators are the public infrastructure class — they serve
            // RPC to wallets / dApps / joiner nodes in addition to producing
            // blocks. Binding loopback by default would leave the network
            // with decentralized consensus but a single public gateway,
            // which is functionally a centralized chain on the access axis.
            // Override with `--rpc-addr 127.0.0.1:8545` for a private node.
            service_keys: Vec::new(),
            operator_did: None,
            rpc_addr: "0.0.0.0:8545".to_string(),
            web_addr: "0.0.0.0:8080".to_string(),
            mcp_addr: "0.0.0.0:3001".to_string(),
            a2a_addr: "0.0.0.0:3002".to_string(),
            solana_mcp_addr: "0.0.0.0:3003".to_string(),
            ethereum_mcp_addr: "0.0.0.0:3004".to_string(),
            canton_mcp_addr: "0.0.0.0:3005".to_string(),
            layerzero_mcp_addr: "0.0.0.0:3006".to_string(),
            chainlink_mcp_addr: "0.0.0.0:3007".to_string(),
            lifi_mcp_addr: "0.0.0.0:3008".to_string(),
            metrics_enabled: true,
            health_enabled: true,
            genesis: Some(GenesisConfig::default_testnet()),
            canton: CantonConfig::default(),
            mcp_plugin_host: McpPluginHostConfig::default(),
            builtins: BuiltinsConfig::default(),
            economics: EconomicsConfig::default(),
            webauthn_trusted_roots: Vec::new(),
            payments: PaymentsConfig::default(),
            bridge: BridgeConfig::default(),
            cortex: CortexConfig::default(),
            training: TrainingConfig::default(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            public_node_suffix: Some(DEFAULT_PUBLIC_NODE_SUFFIX.to_string()),
            external_mcp_addr: None,
            did_fallback_rpc: None,
            geography: None,
            jurisdiction_country: None,
            jurisdiction_blocs: Vec::new(),
            iroh: tenzro_iroh::TenzroIrohConfig::default(),
            da_backend: DaBackendSelector::default(),
            erc8004_daml: None,
            snapshot: crate::snapshot::SnapshotConfig::default(),
            databases: DatabasesConfig::default(),
            hosting: HostingConfig::default(),
            provider_rates: ProviderRatesConfig::default(),
            model_licensing: tenzro_types::model::AcceptancePolicy::default(),
            listing_tnzo_usd_micro: None,
        }
    }

    /// Create a default inference provider configuration
    pub fn default_provider() -> Self {
        Self {
            roles: RoleSet::from(NetworkRole::ModelProvider),
            validator_self_stake: None,
            data_dir: tenzro_types::paths::instance_data_dir("provider"),
            network: NetworkConfig::default(),
            consensus: None,
            tee_enabled: true,
            models_dir: None,
            memory: MemoryConfig::default(),
            autotune: crate::autotune_sampler::AutotuneConfig::default(),
            rental: RentalConfig::default(),
            log_level: "info".to_string(),
            service_keys: Vec::new(),
            operator_did: None,
            rpc_addr: "127.0.0.1:8545".to_string(),
            web_addr: "0.0.0.0:8080".to_string(),
            mcp_addr: "0.0.0.0:3001".to_string(),
            a2a_addr: "0.0.0.0:3002".to_string(),
            solana_mcp_addr: "0.0.0.0:3003".to_string(),
            ethereum_mcp_addr: "0.0.0.0:3004".to_string(),
            canton_mcp_addr: "0.0.0.0:3005".to_string(),
            layerzero_mcp_addr: "0.0.0.0:3006".to_string(),
            chainlink_mcp_addr: "0.0.0.0:3007".to_string(),
            lifi_mcp_addr: "0.0.0.0:3008".to_string(),
            metrics_enabled: true,
            health_enabled: true,
            genesis: None,
            canton: CantonConfig::default(),
            mcp_plugin_host: McpPluginHostConfig::default(),
            builtins: BuiltinsConfig::default(),
            economics: EconomicsConfig::default(),
            webauthn_trusted_roots: Vec::new(),
            payments: PaymentsConfig::default(),
            bridge: BridgeConfig::default(),
            cortex: CortexConfig::default(),
            training: TrainingConfig::default(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            public_node_suffix: Some(DEFAULT_PUBLIC_NODE_SUFFIX.to_string()),
            external_mcp_addr: None,
            did_fallback_rpc: None,
            geography: None,
            jurisdiction_country: None,
            jurisdiction_blocs: Vec::new(),
            iroh: tenzro_iroh::TenzroIrohConfig::default(),
            da_backend: DaBackendSelector::default(),
            erc8004_daml: None,
            snapshot: crate::snapshot::SnapshotConfig::default(),
            databases: DatabasesConfig::default(),
            hosting: HostingConfig::default(),
            provider_rates: ProviderRatesConfig::default(),
            model_licensing: tenzro_types::model::AcceptancePolicy::default(),
            listing_tnzo_usd_micro: None,
        }
    }

    /// Create a default TEE provider configuration
    pub fn default_tee_provider() -> Self {
        Self {
            roles: RoleSet::from(NetworkRole::TeeProvider),
            validator_self_stake: None,
            data_dir: tenzro_types::paths::instance_data_dir("tee-provider"),
            network: NetworkConfig::default(),
            consensus: None,
            tee_enabled: true,
            models_dir: None,
            memory: MemoryConfig::default(),
            autotune: crate::autotune_sampler::AutotuneConfig::default(),
            rental: RentalConfig::default(),
            log_level: "info".to_string(),
            service_keys: Vec::new(),
            operator_did: None,
            rpc_addr: "127.0.0.1:8545".to_string(),
            web_addr: "0.0.0.0:8080".to_string(),
            mcp_addr: "0.0.0.0:3001".to_string(),
            a2a_addr: "0.0.0.0:3002".to_string(),
            solana_mcp_addr: "0.0.0.0:3003".to_string(),
            ethereum_mcp_addr: "0.0.0.0:3004".to_string(),
            canton_mcp_addr: "0.0.0.0:3005".to_string(),
            layerzero_mcp_addr: "0.0.0.0:3006".to_string(),
            chainlink_mcp_addr: "0.0.0.0:3007".to_string(),
            lifi_mcp_addr: "0.0.0.0:3008".to_string(),
            metrics_enabled: true,
            health_enabled: true,
            genesis: None,
            canton: CantonConfig::default(),
            mcp_plugin_host: McpPluginHostConfig::default(),
            builtins: BuiltinsConfig::default(),
            economics: EconomicsConfig::default(),
            webauthn_trusted_roots: Vec::new(),
            payments: PaymentsConfig::default(),
            bridge: BridgeConfig::default(),
            cortex: CortexConfig::default(),
            training: TrainingConfig::default(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            public_node_suffix: Some(DEFAULT_PUBLIC_NODE_SUFFIX.to_string()),
            external_mcp_addr: None,
            did_fallback_rpc: None,
            geography: None,
            jurisdiction_country: None,
            jurisdiction_blocs: Vec::new(),
            iroh: tenzro_iroh::TenzroIrohConfig::default(),
            da_backend: DaBackendSelector::default(),
            erc8004_daml: None,
            snapshot: crate::snapshot::SnapshotConfig::default(),
            databases: DatabasesConfig::default(),
            hosting: HostingConfig::default(),
            provider_rates: ProviderRatesConfig::default(),
            model_licensing: tenzro_types::model::AcceptancePolicy::default(),
            listing_tnzo_usd_micro: None,
        }
    }

    /// Create a default user node configuration
    pub fn default_user() -> Self {
        Self {
            roles: RoleSet::from(NetworkRole::LightClient),
            validator_self_stake: None,
            data_dir: tenzro_types::paths::default_data_dir(),
            network: NetworkConfig::default(),
            consensus: None,
            tee_enabled: true,
            models_dir: None,
            memory: MemoryConfig::default(),
            autotune: crate::autotune_sampler::AutotuneConfig::default(),
            rental: RentalConfig::default(),
            log_level: "info".to_string(),
            service_keys: Vec::new(),
            operator_did: None,
            rpc_addr: "127.0.0.1:8545".to_string(),
            web_addr: "0.0.0.0:8080".to_string(),
            mcp_addr: "0.0.0.0:3001".to_string(),
            a2a_addr: "0.0.0.0:3002".to_string(),
            solana_mcp_addr: "0.0.0.0:3003".to_string(),
            ethereum_mcp_addr: "0.0.0.0:3004".to_string(),
            canton_mcp_addr: "0.0.0.0:3005".to_string(),
            layerzero_mcp_addr: "0.0.0.0:3006".to_string(),
            chainlink_mcp_addr: "0.0.0.0:3007".to_string(),
            lifi_mcp_addr: "0.0.0.0:3008".to_string(),
            metrics_enabled: false,
            health_enabled: true,
            genesis: None,
            canton: CantonConfig::from_env(),
            mcp_plugin_host: McpPluginHostConfig::default(),
            builtins: BuiltinsConfig::default(),
            economics: EconomicsConfig::default(),
            webauthn_trusted_roots: Vec::new(),
            payments: PaymentsConfig::default(),
            bridge: BridgeConfig::default(),
            cortex: CortexConfig::default(),
            training: TrainingConfig::default(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            public_node_suffix: Some(DEFAULT_PUBLIC_NODE_SUFFIX.to_string()),
            external_mcp_addr: None,
            did_fallback_rpc: None,
            geography: None,
            jurisdiction_country: None,
            jurisdiction_blocs: Vec::new(),
            iroh: tenzro_iroh::TenzroIrohConfig::default(),
            da_backend: DaBackendSelector::default(),
            erc8004_daml: None,
            snapshot: crate::snapshot::SnapshotConfig::default(),
            databases: DatabasesConfig::default(),
            hosting: HostingConfig::default(),
            provider_rates: ProviderRatesConfig::default(),
            model_licensing: tenzro_types::model::AcceptancePolicy::default(),
            listing_tnzo_usd_micro: None,
        }
    }

    /// Load configuration from a TOML file
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| NodeError::Config(format!("Failed to read config file: {}", e)))?;

        let config: NodeConfig = toml::from_str(&contents)
            .map_err(|e| NodeError::Config(format!("Failed to parse config: {}", e)))?;

        config.validate()?;
        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| NodeError::Config(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, contents)
            .map_err(|e| NodeError::Config(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate data directory is set
        if self.data_dir.as_os_str().is_empty() {
            return Err(NodeError::Config("Data directory must be set".to_string()));
        }

        // Validators must have consensus config
        if self.roles.is_validator() && self.consensus.is_none() {
            return Err(NodeError::Config(
                "Validators must have consensus configuration".to_string(),
            ));
        }

        // Validate log level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.log_level.as_str()) {
            return Err(NodeError::Config(format!(
                "Invalid log level: {}. Must be one of: {:?}",
                self.log_level, valid_levels
            )));
        }

        // Validate network config
        self.network
            .validate()
            .map_err(|e| NodeError::Config(format!("Invalid network config: {}", e)))?;

        // Validate genesis schema version and PQ keys.
        //
        // Hybrid post-quantum signing is mandatory: every validator must
        // carry a ML-DSA-65 verifying key. Reject genesis files that
        // predate the PQ migration.
        if let Some(g) = &self.genesis {
            if g.version != GENESIS_SCHEMA_VERSION {
                return Err(NodeError::Config(format!(
                    "Genesis schema version {} is not supported; this build requires \
                     version {} exactly. This build requires hybrid PQ validator keys \
                     (ML-DSA-65). Regenerate genesis with `pq_public_key` set on every \
                     validator.",
                    g.version, GENESIS_SCHEMA_VERSION
                )));
            }
            for (i, gv) in g.validators.iter().enumerate() {
                if gv.pq_public_key.trim().is_empty() {
                    return Err(NodeError::Config(format!(
                        "Genesis validator [{}] has empty pq_public_key. \
                         All validators must publish a 1952-byte ML-DSA-65 verifying key.",
                        i
                    )));
                }
            }
        }

        // Validate payments config when enabled
        if self.payments.enabled == Some(true) {
            if self.payments.recipient.trim().is_empty() {
                return Err(NodeError::Config(
                    "payments.recipient must be set when payments.enabled = true".to_string(),
                ));
            }
            if self.payments.default_protocol.trim().is_empty() {
                return Err(NodeError::Config(
                    "payments.default_protocol must be set when payments.enabled = true"
                        .to_string(),
                ));
            }
            if self.payments.default_asset.trim().is_empty() {
                return Err(NodeError::Config(
                    "payments.default_asset must be set when payments.enabled = true".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Create data directory if it doesn't exist
    pub fn ensure_data_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)
            .map_err(|e| NodeError::Config(format!("Failed to create data directory: {}", e)))?;
        Ok(())
    }

    /// Create models directory if it doesn't exist and is configured
    pub fn ensure_models_dir(&self) -> Result<()> {
        if let Some(models_dir) = &self.models_dir {
            std::fs::create_dir_all(models_dir).map_err(|e| {
                NodeError::Config(format!("Failed to create models directory: {}", e))
            })?;
        }
        Ok(())
    }

    /// Resolve the directory where GGUF model weights are stored and served.
    ///
    /// Uses the explicit `models_dir` when configured, otherwise the shared
    /// machine-wide model store under the Tenzro root.
    ///
    /// Shared rather than per-instance, and deliberately not a subdirectory of
    /// `data_dir`. Weights are content-addressed and read-only once written,
    /// so two nodes on one machine have no reason to hold separate copies of
    /// the same tens of gigabytes — and when they did, the CLI wrote to one
    /// copy while the node served from another, which is how a machine ended
    /// up with several half-populated model directories and no way to say
    /// which was current.
    ///
    /// Operators who keep weights on a separate volume set `models_dir`
    /// explicitly; that path still wins.
    pub fn effective_models_dir(&self) -> PathBuf {
        self.models_dir
            .clone()
            .map(tenzro_types::paths::expand_tilde)
            .unwrap_or_else(tenzro_types::paths::models_dir)
    }
}

// Remove the stub toml module - we use the real toml crate from dependencies

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_configs() {
        let validator = NodeConfig::default_validator();
        assert!(validator.roles.is_validator());
        assert!(validator.consensus.is_some());

        let provider = NodeConfig::default_provider();
        assert!(provider.roles.serves_ai());
        // `models_dir` unset means "the shared machine-wide store", which is
        // what a provider should use — it is the same directory the CLI
        // downloads into. Asserting on the resolved path rather than on the
        // override being present is the check that actually matters: a
        // provider must have somewhere to serve weights from.
        assert!(provider.models_dir.is_none());
        assert_eq!(
            provider.effective_models_dir(),
            tenzro_types::paths::models_dir()
        );

        let user = NodeConfig::default_user();
        assert!(user.roles.has(NetworkRole::LightClient));
        assert!(user.consensus.is_none());
    }

    #[test]
    fn test_validator_validation() {
        let mut config = NodeConfig::default_validator();
        assert!(config.validate().is_ok());

        // Validator without consensus should fail
        config.consensus = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_log_level_validation() {
        let mut config = NodeConfig {
            log_level: "invalid".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        config.log_level = "debug".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_genesis_config_serialization() {
        let genesis = GenesisConfig::default_testnet();
        let toml_str = toml::to_string_pretty(&genesis).unwrap();
        let parsed: GenesisConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.chain_id, genesis.chain_id);
    }

    #[test]
    fn test_node_config_toml_roundtrip() {
        let config = NodeConfig::default_validator();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(toml_str.contains("roles"));
        // Parse it back
        let parsed: NodeConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.roles, config.roles);
    }

    #[test]
    fn test_save_and_load_config() {
        use std::env;
        let config = NodeConfig::default_validator();
        let temp_dir = env::temp_dir();
        let temp_file = temp_dir.join("test_node_config.toml");

        // Save config
        config.save_to_file(&temp_file).unwrap();

        // Load it back
        let loaded = NodeConfig::load_from_file(&temp_file).unwrap();
        assert_eq!(loaded.roles, config.roles);
        assert_eq!(loaded.rpc_addr, config.rpc_addr);

        // Clean up
        let _ = std::fs::remove_file(temp_file);
    }

    /// Proves that secret-bearing canton fields marked `#[serde(skip_serializing,
    /// default)]` survive a load via `load_from_file`. This is the contract the
    /// RPC-node-only canton persistence design depends on: the secret is hand-
    /// placed in `/etc/tenzro/node-config.toml` by the fetch-on-boot service,
    /// the node reads it via `--config`, and the serializer never writes it back
    /// out even if the loaded config is re-saved.
    #[test]
    fn test_canton_devnet_secret_loads_from_toml() {
        use std::env;

        // Build on default_validator() so every other field has a value the
        // schema is happy with; only canton matters here.
        let mut config = NodeConfig::default_validator();
        config.canton = CantonConfig {
            enabled: true,
            default_network: CantonNetwork::Devnet,
            devnet: Some(CantonNetworkConfig {
                host: "participant.devnet.internal".to_string(),
                port: 7575,
                tls: false,
                workflow_receipt_template: None,
                static_jwt: Some("must-not-be-saved".to_string()),
                oauth: None,
            }),
            mainnet: None,
            identity_providers: CantonIdentityProvidersConfig::default(),
        };

        // Save: the serializer must drop the secret. This is the half of the
        // contract that protects us from accidentally persisting it on
        // save_to_file (e.g. via a future admin RPC).
        let temp_file = env::temp_dir().join("test_canton_secret_load.toml");
        config.save_to_file(&temp_file).unwrap();
        let on_disk = std::fs::read_to_string(&temp_file).unwrap();
        assert!(
            !on_disk.contains("must-not-be-saved"),
            "save_to_file must not emit static_jwt — #[serde(skip_serializing)] \
             is the only defence against leaking the secret if we ever re-save \
             a loaded config",
        );
        assert!(
            on_disk.contains("[canton.devnet]"),
            "non-secret per-network canton fields must persist",
        );

        // Now hand-edit the secret in, the way the fetch-on-boot service does
        // it on the RPC node.
        let mut injected = on_disk.clone();
        let header = "[canton.devnet]";
        let after_header = on_disk
            .find(header)
            .expect("[canton.devnet] table must be rendered")
            + header.len();
        injected.insert_str(after_header, "\nstatic_jwt = \"injected-by-fetch-on-boot\"");
        std::fs::write(&temp_file, &injected).unwrap();

        // Load: the deserializer must populate the secret despite the
        // skip_serializing attribute. This is the half of the contract that
        // makes hand-placed config work.
        let loaded = NodeConfig::load_from_file(&temp_file).unwrap();
        assert!(loaded.canton.enabled);
        assert_eq!(loaded.canton.default_network, CantonNetwork::Devnet);
        assert_eq!(
            loaded.canton.configured_networks(),
            vec![CantonNetwork::Devnet],
        );
        let devnet = loaded.canton.network(CantonNetwork::Devnet).unwrap();
        assert_eq!(devnet.port, 7575);
        assert_eq!(
            devnet.static_jwt.as_deref(),
            Some("injected-by-fetch-on-boot"),
            "load_from_file must populate static_jwt from TOML — the \
             persistent canton config design depends on this",
        );

        let _ = std::fs::remove_file(temp_file);
    }

    #[test]
    fn ai_role_gates_by_default_settling_to_own_address() {
        let roles: RoleSet = "validator,ai,storage".parse().unwrap();
        let cfg = PaymentsConfig::default();
        let eff = cfg.effective(&roles, Some("addr-of-this-node"));
        assert!(eff.gate_on, "an ai node with a recipient gates by default");
        assert_eq!(eff.recipient, "addr-of-this-node");
        assert!(eff.paid_routes.iter().any(|r| r == "/chat"));
        // Zero-price at launch: mechanism wired, nothing withheld yet.
        assert_eq!(eff.amount, 0);
    }

    #[test]
    fn non_ai_role_does_not_gate() {
        let roles: RoleSet = "validator".parse().unwrap();
        let cfg = PaymentsConfig::default();
        let eff = cfg.effective(&roles, Some("addr-of-this-node"));
        assert!(
            !eff.gate_on,
            "a validator that serves no models does not gate"
        );
        assert!(eff.paid_routes.is_empty());
    }

    #[test]
    fn ai_role_without_recipient_does_not_gate() {
        let roles: RoleSet = "ai".parse().unwrap();
        let cfg = PaymentsConfig::default();
        let eff = cfg.effective(&roles, None);
        assert!(!eff.gate_on, "no recipient means nothing to settle to");
    }

    #[test]
    fn operator_opts_out_by_disabling_with_explicit_recipient() {
        let roles: RoleSet = "validator,ai".parse().unwrap();
        // An explicit `enabled = false` is the documented opt-out and now
        // says so directly, rather than being inferred from the recipient
        // being populated.
        let cfg = PaymentsConfig {
            enabled: Some(false),
            recipient: "operator-picked".to_string(),
            ..PaymentsConfig::default()
        };
        let eff = cfg.effective(&roles, Some("own-addr"));
        assert!(!eff.gate_on, "explicit disable turns the ai gate off");
    }

    #[test]
    fn explicit_enable_forces_gate_regardless_of_role() {
        let roles: RoleSet = "validator".parse().unwrap();
        let cfg = PaymentsConfig {
            enabled: Some(true),
            recipient: "operator-picked".to_string(),
            paid_routes: vec!["/settle".to_string()],
            ..PaymentsConfig::default()
        };
        let eff = cfg.effective(&roles, None);
        assert!(eff.gate_on);
        assert_eq!(eff.recipient, "operator-picked");
        assert!(eff.paid_routes.iter().any(|r| r == "/settle"));
    }

    #[test]
    fn operator_recipient_overrides_own_address() {
        let roles: RoleSet = "ai".parse().unwrap();
        let cfg = PaymentsConfig {
            recipient: "treasury-addr".to_string(),
            ..PaymentsConfig::default()
        };
        let eff = cfg.effective(&roles, Some("own-addr"));
        assert!(eff.gate_on);
        assert_eq!(eff.recipient, "treasury-addr");
    }

    /// A minimal `[payments]`-only TOML must parse: the container-level
    /// `#[serde(default)]` on `NodeConfig` fills every absent field from
    /// `NodeConfig::default()` so an operator can drop in a payments block
    /// without restating the whole config.
    #[test]
    fn partial_payments_only_toml_parses() {
        let toml_src = r#"
[payments]
enabled = true
default_amount = "1000"
default_asset = "USDC"
recipient = "treasury-addr"
paid_routes = ["/chat"]
"#;
        let cfg: NodeConfig = toml::from_str(toml_src).unwrap();
        assert_eq!(cfg.payments.enabled, Some(true));
        assert_eq!(cfg.payments.default_amount, 1000);
        assert_eq!(cfg.payments.recipient, "treasury-addr");
        assert!(cfg.payments.paid_routes.iter().any(|r| r == "/chat"));
    }
}
