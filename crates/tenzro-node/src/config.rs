//! Node configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tenzro_network::NetworkConfig;
use tenzro_consensus::ConsensusConfig;
use tenzro_types::NetworkRole;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CortexWorkerConfig {
    /// Stable model identifier exposed to clients (e.g. "mythos-3b").
    pub model_id: String,

    /// Sidecar base URL (e.g. "http://127.0.0.1:8799").
    #[serde(default = "default_sidecar_url")]
    pub sidecar_url: String,

    /// Optional bearer token for sidecar auth.
    #[serde(default)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BridgeConfig {
    /// Whether the bridge subsystem is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// LayerZero V2 adapter configuration (optional).
    #[serde(default)]
    pub layerzero: Option<BridgeAdapterConfig>,

    /// Chainlink CCIP adapter configuration (optional).
    #[serde(default)]
    pub ccip: Option<BridgeAdapterConfig>,

    /// deBridge DLN adapter configuration (optional).
    #[serde(default)]
    pub debridge: Option<BridgeAdapterConfig>,

    /// LI.FI aggregator adapter configuration (optional).
    #[serde(default)]
    pub lifi: Option<BridgeAdapterConfig>,
}

/// Generic bridge adapter configuration.
///
/// Captures the minimum RPC / chain / signer information needed to wire any
/// EVM-based adapter. Individual adapters may read additional protocol-specific
/// parameters from environment variables.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    #[serde(default)]
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

/// HTTP 402 payment gate configuration for Web API endpoints
///
/// Controls automatic payment-required responses for selected web routes.
/// When `enabled = true`, requests to paths in `paid_routes` without a
/// valid payment credential are answered with HTTP 402 + a challenge JSON
/// body. Verified credentials forward the request to the underlying handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// [`StripeClient`]: tenzro_payments::mpp::StripeClient
    /// [`IdentityPaymentBinder`]: tenzro_payments::identity_binding::IdentityPaymentBinder
    #[serde(default)]
    pub stripe_api_key: Option<String>,

    /// Stripe API base URL override. Defaults to `https://api.stripe.com`.
    /// Useful for testing against a Stripe mock server.
    #[serde(default)]
    pub stripe_api_base: Option<String>,
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
        }
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
}

impl Default for CantonConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 5001,
            enabled: false,
        }
    }
}

impl CantonConfig {
    /// Create from environment variables, falling back to defaults
    pub fn from_env() -> Self {
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

        Self { host, port, enabled }
    }
}

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node role (Validator, InferenceProvider, TeeProvider, or User)
    pub role: NetworkRole,

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
    /// `us-central1-a`, `eu-west`, `ap-southeast-1`). Carried through to
    /// the gossiped `ProviderAnnouncementMessage::geography` so peers can
    /// route inference / TEE work by region. `None` means the operator
    /// declined to declare; consumers must treat `None` as "unknown",
    /// not as a wildcard.
    #[serde(default)]
    pub geography: Option<String>,

    /// Tenzro iroh integration (Phase C1, #219). When `Some`, the node
    /// constructs a single `IrohBackedResolver` at startup and shares it
    /// across every consumer that needs an iroh endpoint: the training
    /// `GradientPayloadStore`, the storage `IrohBlobsDaBackend`, and any
    /// direct `tenzro://blob/<hash>` URI fetches. When `None`, the node
    /// runs with the inline DA fallback and no `GradientPayloadStore`.
    ///
    /// The resolver binds **alongside** libp2p — it does not replace the
    /// libp2p control plane. Per the locked model statement (2026-05-17):
    /// "Tenzro uses Iroh as a performance-oriented P2P data plane while
    /// retaining libp2p-style interoperability for decentralized
    /// coordination."
    #[serde(default)]
    pub iroh: Option<tenzro_iroh::TenzroIrohConfig>,
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
            role: NetworkRole::Validator,
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
            payments: PaymentsConfig::default(),
            bridge: BridgeConfig::default(),
            cortex: CortexConfig::default(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            external_mcp_addr: None,
            geography: None,
            iroh: None,
        }
    }

    /// Create a default inference provider configuration
    pub fn default_provider() -> Self {
        Self {
            role: NetworkRole::ModelProvider,
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
            payments: PaymentsConfig::default(),
            bridge: BridgeConfig::default(),
            cortex: CortexConfig::default(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            external_mcp_addr: None,
            geography: None,
            iroh: None,
        }
    }

    /// Create a default TEE provider configuration
    pub fn default_tee_provider() -> Self {
        Self {
            role: NetworkRole::TeeProvider,
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
            payments: PaymentsConfig::default(),
            bridge: BridgeConfig::default(),
            cortex: CortexConfig::default(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            external_mcp_addr: None,
            geography: None,
            iroh: None,
        }
    }

    /// Create a default user node configuration
    pub fn default_user() -> Self {
        Self {
            role: NetworkRole::LightClient,
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
            payments: PaymentsConfig::default(),
            bridge: BridgeConfig::default(),
            cortex: CortexConfig::default(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            external_mcp_addr: None,
            geography: None,
            iroh: None,
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
        if self.role == NetworkRole::Validator && self.consensus.is_none() {
            return Err(NodeError::Config(
                "Validators must have consensus configuration".to_string(),
            ));
        }

        // Model providers should have models directory
        if self.role == NetworkRole::ModelProvider && self.models_dir.is_none() {
            tracing::warn!("Model provider without models directory");
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
}

// Remove the stub toml module - we use the real toml crate from dependencies

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_configs() {
        let validator = NodeConfig::default_validator();
        assert_eq!(validator.role, NetworkRole::Validator);
        assert!(validator.consensus.is_some());

        let provider = NodeConfig::default_provider();
        assert_eq!(provider.role, NetworkRole::ModelProvider);
        assert!(provider.models_dir.is_some());

        let user = NodeConfig::default_user();
        assert_eq!(user.role, NetworkRole::LightClient);
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
        assert!(toml_str.contains("role"));
        // Parse it back
        let parsed: NodeConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.role, config.role);
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
        assert_eq!(loaded.role, config.role);
        assert_eq!(loaded.rpc_addr, config.rpc_addr);

        // Clean up
        let _ = std::fs::remove_file(temp_file);
    }
}
