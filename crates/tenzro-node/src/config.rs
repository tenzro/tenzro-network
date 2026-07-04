//! Node configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tenzro_network::NetworkConfig;
use tenzro_consensus::ConsensusConfig;
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

/// Minimum genesis schema version supported by this build.
///
/// Version 2 introduces mandatory hybrid post-quantum signing keys:
/// every `[[validators]]` entry must carry a `pq_public_key` (hex-encoded
/// 1952-byte ML-DSA-65 verifying key) alongside the classical Ed25519
/// `public_key`. Any genesis file with `version < 2` (or no `version`
/// field) is rejected at startup.
pub const MIN_GENESIS_VERSION: u32 = 2;

/// Genesis configuration for network initialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Genesis schema version. Must be >= MIN_GENESIS_VERSION (2).
    #[serde(default)]
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
            version: MIN_GENESIS_VERSION,
            chain_id: 1337,
            timestamp: 0,
            validators: Vec::new(),
            accounts: Vec::new(),
            faucet: Some(FaucetConfig {
                address: "0".repeat(64),
                amount_per_request: 100,
                cooldown_seconds: 86400,
                enabled: true,
            }),
            weak_subjectivity: None,
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

fn default_sidecar_url() -> String { "http://127.0.0.1:8799".to_string() }
fn default_arch() -> String { "rdt-moe".to_string() }
fn default_max_loops() -> u32 { 32 }
fn default_moe_experts() -> u32 { 64 }
fn default_experts_per_token() -> u32 { 2 }
fn default_attn_type() -> String { "mla".to_string() }
fn default_cortex_timeout_secs() -> u64 { 120 }

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
                &if self.bearer_token.is_some() { "<redacted>" } else { "<unset>" },
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

fn default_max_concurrent_trainers() -> usize { 1 }
fn default_trainer_poll_interval_secs() -> u64 { 30 }
fn default_trainer_backoff_base_ms() -> u64 { 2_000 }
fn default_trainer_backoff_max_ms() -> u64 { 300_000 }
fn default_trainer_max_restarts() -> u32 { 8 }

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
            return std::env::var(env_var)
                .map(Some)
                .map_err(|_| NodeError::Config(format!(
                    "Bridge signer env var '{}' is not set", env_var
                )));
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
                &if self.private_key.is_some() { "<redacted>" } else { "<unset>" },
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
#[derive(Clone, Serialize, Deserialize)]
pub struct PaymentsConfig {
    /// Whether the payment gate middleware is wired into the Web API
    pub enabled: bool,

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
}

impl Default for PaymentsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_protocol: "mpp".to_string(),
            default_amount: 0,
            default_asset: "USDC".to_string(),
            recipient: String::new(),
            paid_routes: Vec::new(),
            stripe_api_key: None,
            stripe_api_base: None,
            tempo_stablecoins: std::collections::HashMap::new(),
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
                &if self.stripe_api_key.is_some() { "<redacted>" } else { "<unset>" },
            )
            .field("stripe_api_base", &self.stripe_api_base)
            .field("tempo_stablecoins", &self.tempo_stablecoins)
            .finish()
    }
}

/// Canton/DAML participant configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonConfig {
    /// Canton participant Ledger API host
    pub host: String,

    /// Canton participant Ledger API port
    pub port: u16,

    /// Whether Canton/DAML VM is enabled
    pub enabled: bool,

    /// When `true`, the node uses the bundled devnet participant
    /// profile (TLS:443, OAuth2 client-credentials). Overrides
    /// `host`/`port`. Set via the `CANTON_DEVNET=true` env var.
    #[serde(default)]
    pub devnet: bool,

    /// Upstream client_secret for the Canton devnet client-credentials
    /// grant. Loaded from the `CANTON_DEVNET_CLIENT_SECRET` env var
    /// when `devnet` is true. Never serialized to config files even
    /// if set programmatically.
    #[serde(skip_serializing, default)]
    pub devnet_client_secret: Option<String>,

    /// Use TLS when talking to the Canton Ledger API.
    ///
    /// Defaults to `true` when `devnet` is on. Operator-run profiles (an
    /// RPC provider running their own Canton validator) should set this
    /// to `true` whenever the participant is reachable over a public
    /// network. Set via `CANTON_TLS=true|false`.
    #[serde(default)]
    pub tls: bool,

    /// Custom OAuth2 client-credentials configuration for an operator-run
    /// Canton validator. When set, the node uses this in place of the
    /// bundled devnet credentials. Mutually exclusive with `static_jwt`.
    ///
    /// All four fields must be present: `token_url`, `client_id`,
    /// `client_secret`, `audience`. `scope` is optional and defaults to
    /// `daml_ledger_api`. Env vars: `CANTON_OAUTH_TOKEN_URL`,
    /// `CANTON_OAUTH_CLIENT_ID`, `CANTON_OAUTH_CLIENT_SECRET`,
    /// `CANTON_OAUTH_AUDIENCE`, `CANTON_OAUTH_SCOPE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<CantonOAuthConfig>,

    /// Static bearer JWT for the Canton Ledger API. Use this when the
    /// operator's Canton participant is configured to accept a long-lived
    /// JWT instead of an OAuth2 client-credentials grant. Mutually
    /// exclusive with `oauth`. Env var: `CANTON_JWT_TOKEN`.
    #[serde(skip_serializing, default)]
    pub static_jwt: Option<String>,

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

    /// Override the DAML template id the workflow dispatcher uses
    /// when mirroring saga completions to Canton via the
    /// `submitCreateCommand` path. When `None`, the node uses the
    /// canonical Tenzro workflow receipt template
    /// (`#tenzro-workflow:Tenzro.Workflow:Receipt`). Format must be
    /// `#<package-name>:<Module>:<Template>` so the participant
    /// resolves the latest installed version of the package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_receipt_template: Option<String>,
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
            host: "localhost".to_string(),
            port: 5001,
            enabled: false,
            devnet: false,
            devnet_client_secret: None,
            tls: false,
            oauth: None,
            static_jwt: None,
            identity_providers: CantonIdentityProvidersConfig::default(),
            workflow_receipt_template: None,
        }
    }
}

impl CantonConfig {
    /// Create from environment variables, falling back to defaults.
    ///
    /// Three profiles are supported:
    ///
    /// 1. **Tenzro-operated devnet** — `CANTON_DEVNET=true`. Forces
    ///    `json.devnet.tenzro.network:443` over TLS with the Tenzro Auth0
    ///    issuer. Client secret from `CANTON_DEVNET_CLIENT_SECRET`.
    ///
    /// 2. **Operator-run validator** (RPC providers running their own
    ///    Canton validator) — `CANTON_ENABLED=true` with custom host/port.
    ///    Auth is configured via EITHER:
    ///    - `CANTON_OAUTH_TOKEN_URL` + `CANTON_OAUTH_CLIENT_ID` +
    ///      `CANTON_OAUTH_CLIENT_SECRET` + `CANTON_OAUTH_AUDIENCE`
    ///      (+ optional `CANTON_OAUTH_SCOPE`), OR
    ///    - `CANTON_JWT_TOKEN` (long-lived bearer).
    ///    `CANTON_TLS=true` for HTTPS upstream.
    ///
    /// 3. **Local unauth** — `CANTON_ENABLED=true` with no auth env vars.
    ///    Plaintext HTTP to localhost. Dev/test only.
    pub fn from_env() -> Self {
        let devnet = std::env::var("CANTON_DEVNET")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false);

        if devnet {
            return Self {
                host: "json.devnet.tenzro.network".to_string(),
                port: 443,
                enabled: true,
                devnet: true,
                devnet_client_secret: std::env::var("CANTON_DEVNET_CLIENT_SECRET").ok(),
                tls: true,
                oauth: None,
                static_jwt: None,
                identity_providers: CantonIdentityProvidersConfig::from_env(),
                workflow_receipt_template: std::env::var("CANTON_WORKFLOW_RECEIPT_TEMPLATE").ok(),
            };
        }

        let host = std::env::var("CANTON_LEDGER_API_HOST")
            .unwrap_or_else(|_| "localhost".to_string());
        let port = std::env::var("CANTON_LEDGER_API_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(5001);
        let enabled = std::env::var("CANTON_ENABLED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false);
        let tls = std::env::var("CANTON_TLS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false);

        // Operator OAuth2 — all four fields required, scope optional.
        let oauth = match (
            std::env::var("CANTON_OAUTH_TOKEN_URL").ok(),
            std::env::var("CANTON_OAUTH_CLIENT_ID").ok(),
            std::env::var("CANTON_OAUTH_CLIENT_SECRET").ok(),
            std::env::var("CANTON_OAUTH_AUDIENCE").ok(),
        ) {
            (Some(token_url), Some(client_id), Some(client_secret), Some(audience))
                if !token_url.is_empty()
                    && !client_id.is_empty()
                    && !client_secret.is_empty()
                    && !audience.is_empty() =>
            {
                Some(CantonOAuthConfig {
                    token_url,
                    client_id,
                    client_secret,
                    audience,
                    scope: std::env::var("CANTON_OAUTH_SCOPE")
                        .unwrap_or_else(|_| default_oauth_scope()),
                })
            }
            _ => None,
        };

        // Static JWT only honored when OAuth2 is not configured.
        let static_jwt = if oauth.is_none() {
            std::env::var("CANTON_JWT_TOKEN")
                .ok()
                .filter(|v| !v.is_empty())
        } else {
            None
        };

        Self {
            host,
            port,
            enabled,
            devnet: false,
            devnet_client_secret: None,
            tls,
            oauth,
            static_jwt,
            identity_providers: CantonIdentityProvidersConfig::from_env(),
            workflow_receipt_template: std::env::var("CANTON_WORKFLOW_RECEIPT_TEMPLATE").ok(),
        }
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
            mgmt_url: std::env::var("CANTON_IDP_MGMT_URL").ok().filter(|v| !v.is_empty()),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaBackendSelector {
    /// Use the iroh-blobs backend when the iroh resolver is bound, otherwise
    /// fall back to the in-process inline store. This is the default.
    Auto,
    /// Force the in-process inline store even when iroh is available. Useful
    /// for minimal single-node operators who do not want blobs advertised on
    /// the iroh data plane.
    Inline,
    /// Require the iroh-blobs backend. Node startup fails if the iroh resolver
    /// is not bound.
    IrohBlobs,
}

impl Default for DaBackendSelector {
    fn default() -> Self {
        Self::Auto
    }
}

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Every role this node serves. A node stakes once and may hold many roles
    /// at once (e.g. validator + AI + storage). Parsed from `--roles
    /// validator,storage,ai`.
    pub roles: RoleSet,

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

    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,

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
    /// Example: `Some("https://rpc.tenzro.network".to_string())`.
    #[serde(default)]
    pub external_rpc_addr: Option<String>,

    /// External (advertised) MCP endpoint URL. Used when gossiping model
    /// service registrations so peers can dial the MCP server from outside
    /// the local network. When `None`, constructed from `mcp_addr`.
    /// Example: `Some("https://mcp.tenzro.network/mcp".to_string())`.
    #[serde(default)]
    pub external_mcp_addr: Option<String>,

    /// Geographic locality of this node (free-form identifier such as
    /// `us-east`, `eu-west`, `ap-southeast`). Carried through to
    /// the gossiped `ProviderAnnouncementMessage::geography` so peers can
    /// route inference / TEE work by region. `None` means the operator
    /// declined to declare; consumers must treat `None` as "unknown",
    /// not as a wildcard.
    #[serde(default)]
    pub geography: Option<String>,

    /// Tenzro iroh integration. The node always constructs a single
    /// `IrohBackedResolver` at startup and shares it across every consumer
    /// that needs an iroh endpoint: the training `GradientPayloadStore`,
    /// the storage `IrohBlobsDaBackend`, agent-memory archival, and any
    /// direct `tenzro://blob/<hash>` URI fetches.
    ///
    /// The default (`TenzroIrohConfig::default()`) anchors discovery to the
    /// Tenzro-operated Pkarr relay (`https://pkarr.tenzro.network`) with
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
            data_dir: PathBuf::from("./data/validator"),
            network,
            consensus: Some(ConsensusConfig::default()),
            tee_enabled: true,
            models_dir: None,
            log_level: "info".to_string(),
            // Validators are the public infrastructure class — they serve
            // RPC to wallets / dApps / joiner nodes in addition to producing
            // blocks. Binding loopback by default would leave the network
            // with decentralized consensus but a single public gateway,
            // which is functionally a centralized chain on the access axis.
            // Override with `--rpc-addr 127.0.0.1:8545` for a private node.
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
            payments: PaymentsConfig::default(),
            bridge: BridgeConfig::default(),
            cortex: CortexConfig::default(),
            training: TrainingConfig::default(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            external_mcp_addr: None,
            geography: None,
            iroh: tenzro_iroh::TenzroIrohConfig::default(),
            da_backend: DaBackendSelector::default(),
            erc8004_daml: None,
            snapshot: crate::snapshot::SnapshotConfig::default(),
        }
    }

    /// Create a default inference provider configuration
    pub fn default_provider() -> Self {
        Self {
            roles: RoleSet::from(NetworkRole::ModelProvider),
            data_dir: PathBuf::from("./data/provider"),
            network: NetworkConfig::default(),
            consensus: None,
            tee_enabled: true,
            models_dir: Some(PathBuf::from("./models")),
            log_level: "info".to_string(),
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
            payments: PaymentsConfig::default(),
            bridge: BridgeConfig::default(),
            cortex: CortexConfig::default(),
            training: TrainingConfig::default(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            external_mcp_addr: None,
            geography: None,
            iroh: tenzro_iroh::TenzroIrohConfig::default(),
            da_backend: DaBackendSelector::default(),
            erc8004_daml: None,
            snapshot: crate::snapshot::SnapshotConfig::default(),
        }
    }

    /// Create a default TEE provider configuration
    pub fn default_tee_provider() -> Self {
        Self {
            roles: RoleSet::from(NetworkRole::TeeProvider),
            data_dir: PathBuf::from("./data/tee-provider"),
            network: NetworkConfig::default(),
            consensus: None,
            tee_enabled: true,
            models_dir: Some(PathBuf::from("./models")),
            log_level: "info".to_string(),
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
            payments: PaymentsConfig::default(),
            bridge: BridgeConfig::default(),
            cortex: CortexConfig::default(),
            training: TrainingConfig::default(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            external_mcp_addr: None,
            geography: None,
            iroh: tenzro_iroh::TenzroIrohConfig::default(),
            da_backend: DaBackendSelector::default(),
            erc8004_daml: None,
            snapshot: crate::snapshot::SnapshotConfig::default(),
        }
    }

    /// Create a default user node configuration
    pub fn default_user() -> Self {
        Self {
            roles: RoleSet::from(NetworkRole::LightClient),
            data_dir: PathBuf::from("./data/user"),
            network: NetworkConfig::default(),
            consensus: None,
            tee_enabled: true,
            models_dir: None,
            log_level: "info".to_string(),
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
            payments: PaymentsConfig::default(),
            bridge: BridgeConfig::default(),
            cortex: CortexConfig::default(),
            training: TrainingConfig::default(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            external_mcp_addr: None,
            geography: None,
            iroh: tenzro_iroh::TenzroIrohConfig::default(),
            da_backend: DaBackendSelector::default(),
            erc8004_daml: None,
            snapshot: crate::snapshot::SnapshotConfig::default(),
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
            if g.version < MIN_GENESIS_VERSION {
                return Err(NodeError::Config(format!(
                    "Genesis schema version {} is too old; required version is {}. \
                     This build requires hybrid PQ validator keys (ML-DSA-65). \
                     Regenerate genesis with `pq_public_key` set on every validator.",
                    g.version, MIN_GENESIS_VERSION
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
        if self.payments.enabled {
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
    /// Uses the explicit `models_dir` when configured, otherwise a `models`
    /// subdirectory of `data_dir`. Rooting under `data_dir` keeps downloaded
    /// weights on the same persistent volume as chain state, so they survive a
    /// process/container restart instead of being re-downloaded every boot.
    pub fn effective_models_dir(&self) -> PathBuf {
        self.models_dir
            .clone()
            .unwrap_or_else(|| self.data_dir.join("models"))
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
        assert!(provider.models_dir.is_some());

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
            host: "json.devnet.tenzro.network".to_string(),
            port: 443,
            enabled: true,
            devnet: true,
            devnet_client_secret: Some("must-not-be-saved".to_string()),
            tls: true,
            oauth: None,
            static_jwt: None,
            identity_providers: CantonIdentityProvidersConfig::default(),
            workflow_receipt_template: None,
        };

        // Save: the serializer must drop the secret. This is the half of the
        // contract that protects us from accidentally persisting it on
        // save_to_file (e.g. via a future admin RPC).
        let temp_file = env::temp_dir().join("test_canton_secret_load.toml");
        config.save_to_file(&temp_file).unwrap();
        let on_disk = std::fs::read_to_string(&temp_file).unwrap();
        assert!(
            !on_disk.contains("must-not-be-saved"),
            "save_to_file must not emit devnet_client_secret — \
             #[serde(skip_serializing)] is the only defence against \
             leaking the secret if we ever re-save a loaded config",
        );
        assert!(
            on_disk.contains("devnet = true"),
            "non-secret canton fields must persist",
        );

        // Now hand-edit the secret in, the way fetch-canton-config does it
        // at boot time on validator-0.
        let with_secret = format!(
            "{}\ndevnet_client_secret = \"injected-by-fetch-on-boot\"\n",
            on_disk
        );
        // The secret line must land inside the [canton] table — append works
        // because [canton] is the last table in the default_validator render
        // (the iroh table comes after but we'll insert at the canton table
        // explicitly instead of relying on layout).
        let injected = if let Some(pos) = on_disk.find("[canton]") {
            // Insert the secret right after the [canton] header so it
            // unambiguously belongs to that table regardless of what trails it.
            let mut s = on_disk.clone();
            let insertion = "\ndevnet_client_secret = \"injected-by-fetch-on-boot\"";
            let after_header = pos + "[canton]".len();
            s.insert_str(after_header, insertion);
            s
        } else {
            with_secret
        };
        std::fs::write(&temp_file, &injected).unwrap();

        // Load: the deserializer must populate the secret despite the
        // skip_serializing attribute. This is the half of the contract that
        // makes hand-placed config work.
        let loaded = NodeConfig::load_from_file(&temp_file).unwrap();
        assert!(loaded.canton.enabled);
        assert!(loaded.canton.devnet);
        assert!(loaded.canton.tls);
        assert_eq!(
            loaded.canton.devnet_client_secret.as_deref(),
            Some("injected-by-fetch-on-boot"),
            "load_from_file must populate devnet_client_secret from TOML — \
             the persistent canton config design depends on this",
        );

        let _ = std::fs::remove_file(temp_file);
    }
}
