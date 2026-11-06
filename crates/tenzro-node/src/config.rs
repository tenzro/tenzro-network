//! Node configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tenzro_consensus::ConsensusConfig;
use tenzro_types::{NetworkRole, RoleSet};

use crate::error::{NodeError, Result};

/// Serde helper for u128 values — serializes as string for TOML compatibility
/// (the `toml` crate does not support u128 natively)
pub(crate) mod u128_as_string {
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
/// Every validator entry of the current schema carries the validator's
/// address, the two halves of its hardware composite consensus key
/// (`ml_dsa_public_key`, `p256_public_key`), its node `endpoint`, and a
/// `proof_of_possession` of the key over all of them. A genesis file whose
/// `version` is missing or not exactly this value is rejected at startup.
pub use tenzro_types::constants::GENESIS_SCHEMA_VERSION;

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

    /// Weak-subjectivity checkpoint: a finalized block every import path
    /// pins, and the anchor for state sync.
    ///
    /// When set on a node started with state-sync peers, the node restores
    /// the committed state this block commits from the genesis validators
    /// over iroh, verified against the block, then block-syncs forward.
    #[serde(default)]
    pub weak_subjectivity: Option<WeakSubjectivityAnchor>,
    /// The network's time rules (`[time]`): checkpoint cadence, epoch
    /// length, handover, announcement lifetime and compact-certificate
    /// cadence. Required; the genesis state root commits to them. A test
    /// network compresses time by choosing shorter ones.
    pub time: tenzro_consensus::TimeRules,
    /// Starting values of governed network parameters (`[network_params]`,
    /// `key = value`). A key left out starts at the registry's genesis
    /// value; an unknown key or a value outside the key's bounds refuses
    /// the genesis. Genesis writes every governed parameter into state.
    #[serde(default)]
    pub network_params: std::collections::BTreeMap<String, u64>,
    /// Bridge, TPM-root, finality-program, agent-chain and guardian records
    /// (`[economy]`), written where the enacting governance action would
    /// write them. An omitted section takes [`EconomyGenesis::default`].
    #[serde(default)]
    pub economy: EconomyGenesis,
    /// Role stakes bonded at genesis for the non-validator roles
    /// (`[[role_stakes]]`), so a bootstrap node serving them boots on the
    /// genesis alone. The genesis state root commits to them.
    #[serde(default)]
    pub role_stakes: Vec<GenesisRoleStake>,
}

/// Governed records the network starts with. Governance replaces each later
/// with the matching proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EconomyGenesis {
    /// TPM manufacturer roots (PEM) an endorsement certificate must chain to
    /// where the network asks for a manufacturer-certified TPM.
    #[serde(default)]
    pub tpm_endorsement_roots_pem: Vec<String>,
    /// Network-wide cap on one bridge mint through any route, whole TNZO.
    pub bridge_mint_per_mint_tnzo: u64,
    /// Network-wide limit on what one bridge route mints per epoch, whole
    /// TNZO.
    pub bridge_mint_per_epoch_tnzo: u64,
    /// Cap on one mint through a route without a light client, whole TNZO;
    /// below `bridge_mint_per_mint_tnzo`.
    pub bridge_attested_per_mint_tnzo: u64,
    /// Limit on what one route without a light client mints per epoch, whole
    /// TNZO; below `bridge_mint_per_epoch_tnzo`.
    pub bridge_attested_per_epoch_tnzo: u64,
    /// Ceiling on one mint through a route whose destination verifies only
    /// classical signatures, whole TNZO. Every route is one today; the
    /// tighter of this and the route's tier applies.
    #[serde(default = "default_bridge_classical_per_mint_tnzo")]
    pub bridge_classical_per_mint_tnzo: u64,
    /// Ceiling on what one such route mints per epoch, whole TNZO.
    #[serde(default = "default_bridge_classical_per_epoch_tnzo")]
    pub bridge_classical_per_epoch_tnzo: u64,
    /// The most of each unit that may leave Tenzro over every bridge route
    /// together in one epoch, in the unit's smallest denomination
    /// (`bridge_outflow`, entries of `unit` and `per_epoch`). A unit not
    /// named here cannot leave until governance gives it a cap.
    pub bridge_outflow: Vec<tenzro_types::bridge_route::OutflowCap>,
    /// Image id (hex) of the finality program whose wrapped proofs the chain
    /// accepts. Without one, finality-proving tasks take no deliveries until
    /// governance sets it.
    #[serde(default)]
    pub finality_program: Option<String>,
    /// Image id (hex) of the handover program whose proofs of the epoch
    /// handover chain nodes keep in place of the handovers. Without one,
    /// every node keeps the handovers from genesis until governance sets it.
    #[serde(default)]
    pub handover_program: Option<String>,
    /// Bridge routes the network starts with (`[[economy.bridge_routes]]`).
    #[serde(default)]
    pub bridge_routes: Vec<GenesisBridgeRoute>,
    /// Chains agents hold accounts on (`[[economy.agent_account_chains]]`),
    /// written where an enacted `SetAgentAccountChain` would write them. A
    /// chain whose deployment is not yet known starts closed.
    #[serde(default)]
    pub agent_account_chains: Vec<tenzro_types::omni_account::AgentAccountChain>,
    /// Guardian seats the network starts with (`[[economy.guardians]]`).
    #[serde(default)]
    pub guardians: Vec<GenesisGuardian>,
}

/// A guardian seat written at genesis where an enacted `SetGuardian`
/// proposal would write it. Its term is a hard expiry within the governed
/// maximum term of the genesis time; after it, only governance seats
/// guardians.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisGuardian {
    /// Whether the seat is still to be filled. A placeholder seat is not
    /// written; governance fills it with `SetGuardian`.
    pub placeholder: bool,
    /// The account the guardian signs from, hex.
    pub address: String,
    /// The guardian's human DID.
    pub did: String,
    /// The power the seat holds.
    pub role: tenzro_vm::governance::GuardianRole,
    /// Block time (Unix ms) the seat lapses at.
    pub term_ends_ms: i64,
    /// What the seat's signing key is rooted in. Required unless the seat
    /// is a placeholder.
    #[serde(default)]
    pub key_root: Option<tenzro_vm::governance::SeatKeyRoot>,
}

/// A bridge route written at genesis where an enacted `SetBridgeRoute`
/// proposal would write it, checked against the same route rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisBridgeRoute {
    /// Whether the route carries traffic from genesis. A closed route
    /// starts with its circuit breaker held by governance; only an enacted
    /// policy update opens it.
    pub open: bool,
    /// The route fields still to be filled in, by name (`verifiers`, `ramp`,
    /// `light_client`, ...). A route with any is a placeholder: it starts
    /// disabled with zero caps, and governance opens it only after a vote has
    /// installed it whole.
    #[serde(default)]
    pub placeholders: Vec<String>,
    /// The route.
    pub route: tenzro_types::bridge_route::BridgeRoute,
}

/// The route fields a genesis placeholder may name.
const ROUTE_FIELDS: [&str; 14] = [
    "adapter",
    "family",
    "source_chain",
    "source_chain_id",
    "local_selector",
    "peer",
    "ramp",
    "local_endpoint",
    "remote_token",
    "verifiers",
    "blessing",
    "light_client",
    "lane_limits",
    "assets",
];

impl GenesisBridgeRoute {
    /// Refuse a placeholder route that is open, carries caps, or names a
    /// field routes do not have: a placeholder starts disabled with zero caps
    /// until governance fills and opens it.
    pub fn check_placeholders(&self) -> std::result::Result<(), String> {
        let key = self.route.storage_key();
        // Carried assets ship disabled: only an enacted route update enables
        // one.
        if let Some(a) = self.route.assets.iter().find(|a| a.enabled) {
            return Err(format!(
                "genesis bridge route {key}: carried asset {} must start disabled",
                a.symbol
            ));
        }
        if self.placeholders.is_empty() {
            return Ok(());
        }
        if let Some(unknown) = self
            .placeholders
            .iter()
            .find(|f| !ROUTE_FIELDS.contains(&f.as_str()))
        {
            return Err(format!(
                "genesis bridge route {key}: '{unknown}' is not a route field"
            ));
        }
        let lanes_shut = self.route.outflow.capacity == 0
            && self
                .route
                .lane_limits
                .is_none_or(|l| l.inbound.capacity == 0);
        let assets_shut = self.route.assets.iter().all(|a| {
            a.max_outstanding == 0
                && a.mint_limit.per_mint == 0
                && a.mint_limit.per_epoch == 0
                && a.outflow.capacity == 0
                && a.lane.is_none_or(|l| l.inbound.capacity == 0)
        });
        if self.open
            || self.route.mint_limit.per_mint != 0
            || self.route.mint_limit.per_epoch != 0
            || !lanes_shut
            || !assets_shut
        {
            return Err(format!(
                "genesis bridge route {key} holds placeholders, so it must be closed with zero caps"
            ));
        }
        Ok(())
    }
}

impl Default for EconomyGenesis {
    fn default() -> Self {
        Self {
            tpm_endorsement_roots_pem: Vec::new(),
            bridge_mint_per_mint_tnzo:
                tenzro_vm::native::bridge_circuit::DEFAULT_BRIDGE_MINT_PER_MINT_TNZO,
            bridge_mint_per_epoch_tnzo:
                tenzro_vm::native::bridge_circuit::DEFAULT_BRIDGE_MINT_PER_EPOCH_TNZO,
            bridge_attested_per_mint_tnzo:
                tenzro_vm::native::bridge_circuit::DEFAULT_BRIDGE_ATTESTED_PER_MINT_TNZO,
            bridge_attested_per_epoch_tnzo:
                tenzro_vm::native::bridge_circuit::DEFAULT_BRIDGE_ATTESTED_PER_EPOCH_TNZO,
            bridge_classical_per_mint_tnzo:
                tenzro_vm::native::bridge_circuit::DEFAULT_BRIDGE_CLASSICAL_PER_MINT_TNZO,
            bridge_classical_per_epoch_tnzo:
                tenzro_vm::native::bridge_circuit::DEFAULT_BRIDGE_CLASSICAL_PER_EPOCH_TNZO,
            bridge_outflow: tenzro_vm::native::bridge_circuit::default_bridge_outflow().caps,
            finality_program: None,
            handover_program: None,
            bridge_routes: Vec::new(),
            agent_account_chains: Vec::new(),
            guardians: Vec::new(),
        }
    }
}

fn default_bridge_classical_per_mint_tnzo() -> u64 {
    tenzro_vm::native::bridge_circuit::DEFAULT_BRIDGE_CLASSICAL_PER_MINT_TNZO
}

fn default_bridge_classical_per_epoch_tnzo() -> u64 {
    tenzro_vm::native::bridge_circuit::DEFAULT_BRIDGE_CLASSICAL_PER_EPOCH_TNZO
}

impl EconomyGenesis {
    /// The network-wide outflow limits the chain starts with, refused when
    /// governance could not set them.
    pub fn bridge_outflow_limits(
        &self,
    ) -> std::result::Result<tenzro_types::bridge_route::NetworkOutflowLimits, String> {
        let limits = tenzro_types::bridge_route::NetworkOutflowLimits {
            caps: self.bridge_outflow.clone(),
        };
        limits
            .validate()
            .map_err(|e| format!("bridge outflow limits: {e}"))?;
        Ok(limits)
    }

    /// The network-wide bridge mint limits, in the smallest unit, refused
    /// when governance could not set them.
    pub fn bridge_mint_limits(
        &self,
    ) -> std::result::Result<tenzro_types::bridge_route::NetworkMintLimits, String> {
        use tenzro_types::bridge_route::{MintRateLimit, NetworkMintLimits};
        const WEI_PER_TNZO: u128 = 1_000_000_000_000_000_000;
        let limits = NetworkMintLimits {
            proven: MintRateLimit {
                per_mint: u128::from(self.bridge_mint_per_mint_tnzo) * WEI_PER_TNZO,
                per_epoch: u128::from(self.bridge_mint_per_epoch_tnzo) * WEI_PER_TNZO,
            },
            attested: MintRateLimit {
                per_mint: u128::from(self.bridge_attested_per_mint_tnzo) * WEI_PER_TNZO,
                per_epoch: u128::from(self.bridge_attested_per_epoch_tnzo) * WEI_PER_TNZO,
            },
            classical: MintRateLimit {
                per_mint: u128::from(self.bridge_classical_per_mint_tnzo) * WEI_PER_TNZO,
                per_epoch: u128::from(self.bridge_classical_per_epoch_tnzo) * WEI_PER_TNZO,
            },
        };
        limits
            .validate()
            .map_err(|e| format!("bridge mint limits: {e}"))?;
        Ok(limits)
    }
}

impl EconomyGenesis {
    /// Refuses TPM roots that do not parse.
    pub fn check_tpm_roots(&self) -> std::result::Result<(), String> {
        tenzro_tee::tpm_attest::parse_roots(&self.tpm_endorsement_roots_pem)
            .map(|_| ())
            .map_err(|e| format!("tpm_endorsement_roots_pem: {e}"))
    }
}

/// Chain ID of the canonical public Tenzro network. A node joining the public
/// network without an explicit `--genesis` verifies against the built-in
/// genesis carrying this id (see [`public_network_genesis`]).
pub const PUBLIC_NETWORK_CHAIN_ID: u64 = 13380;

/// The canonical public-network genesis, compiled into the binary.
///
/// A self-serve operator running `tenzro-node --roles validator` with default
/// bootstrap has no way to obtain the fleet's `genesis-prod.toml` (it ships
/// out-of-band). Embedding it here means "join the public
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
/// A finalized block, by hash, published out of band. Fresh nodes trust
/// this checkpoint by virtue of trusting the genesis file itself — same
/// trust boundary that already covers the validator set, accounts, and
/// predeploy bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakSubjectivityAnchor {
    /// Height of the checkpoint block.
    pub height: u64,
    /// Hex-encoded 32-byte hash of the checkpoint block. Every import path
    /// refuses another block at `height`, and state sync restores the state
    /// root this block commits.
    pub block_hash_hex: String,
}

impl GenesisConfig {
    /// Every governed parameter with its starting value: the registry's
    /// genesis value unless `[network_params]` names another. Keys in the
    /// `feature.` namespace are left out unless the file names them (see
    /// `tenzro_vm::feature_gate`). Refused when
    /// the file names a key outside the registry, a value outside the key's
    /// bounds, or values that break a rule binding parameters together.
    pub fn network_params(&self) -> std::result::Result<Vec<(&'static str, u64)>, String> {
        for (key, value) in &self.network_params {
            let p = tenzro_vm::governance::governed_param(key)
                .ok_or_else(|| format!("network_params: {key} is not a governed parameter"))?;
            if *value < p.min || *value > p.max {
                return Err(format!(
                    "network_params: {key} = {value} is outside {}..={}",
                    p.min, p.max
                ));
            }
            let start = |k: &str| self.network_param(k);
            tenzro_vm::governance::joint_change_allowed(key, *value, &start)
                .map_err(|e| format!("network_params: {e}"))?;
        }
        Ok(tenzro_vm::governance::GOVERNED_PARAMS
            .iter()
            .filter(|p| {
                tenzro_vm::feature_gate::in_genesis_root(
                    p.key,
                    self.network_params.contains_key(p.key),
                )
            })
            .map(|p| {
                (
                    p.key,
                    self.network_params.get(p.key).copied().unwrap_or(p.genesis),
                )
            })
            .collect())
    }

    /// The bond amounts in force at genesis: the governed `stake.*`
    /// parameters as `[network_params]` sets them, or their genesis values.
    pub fn stake_ladder(&self) -> tenzro_types::network::StakeLadder {
        tenzro_types::network::StakeLadder::from_whole_tnzo(|key| self.network_param(key))
    }

    /// Starting value of one governed parameter.
    pub fn network_param(&self, key: &str) -> u64 {
        self.network_params
            .get(key)
            .copied()
            .unwrap_or_else(|| tenzro_vm::governance::genesis_param(key))
    }

    /// A local developer chain's genesis: `validator` alone, every account
    /// in `fund` (32-byte hex) holding [`DEV_ACCOUNT_TNZO`] TNZO, one-minute
    /// epochs of quarter-second checkpoints, and an idle round every quarter
    /// second so a transaction lands at once.
    pub fn developer(validator: GenesisValidator, fund: &[String]) -> Result<Self> {
        let mut g = Self::default_testnet();
        g.validators = vec![validator];
        for address in fund {
            let hex_addr = address.trim().trim_start_matches("0x").to_ascii_lowercase();
            let valid = hex::decode(&hex_addr).is_ok_and(|b| b.len() == 32);
            if !valid {
                return Err(NodeError::Config(format!(
                    "--fund {address}: an account is 32 bytes of hex"
                )));
            }
            if g.accounts.iter().all(|a| a.address != hex_addr) {
                g.accounts.push(GenesisAccount {
                    address: hex_addr,
                    balance: DEV_ACCOUNT_TNZO,
                });
            }
        }
        g.time = tenzro_consensus::TimeRules {
            checkpoint_interval_ms: 250,
            epoch_checkpoints: 240,
            compact_interval_ms: 15_000,
            compact_handoff_ms: 15_000,
            idle_round_interval_ms: 250,
            ..tenzro_consensus::TimeRules::default()
        };
        g.time.validate().map_err(NodeError::Config)?;
        Ok(g)
    }

    pub fn default_testnet() -> Self {
        Self {
            version: GENESIS_SCHEMA_VERSION,
            chain_id: tenzro_types::constants::TESTNET_CHAIN_ID,
            timestamp: 0,
            validators: Vec::new(),
            accounts: Vec::new(),
            weak_subjectivity: None,
            time: tenzro_consensus::TimeRules::default(),
            network_params: Default::default(),
            economy: EconomyGenesis::default(),
            role_stakes: Vec::new(),
        }
    }
}

/// TNZO each funded account holds at a developer chain's genesis.
pub const DEV_ACCOUNT_TNZO: u128 = 1_000_000;

/// Why a developer chain is refused on a machine without a hardware key store.
pub const DEV_NEEDS_HARDWARE: &str = "a developer chain keeps its keys in this machine's hardware key store \
     (a TPM 2.0 on Linux or Windows, the Secure Enclave on macOS), and this machine has none. \
     Keys are never held in software or in files, so run it on a machine with a TPM or a Secure Enclave.";

/// A genesis validator
///
/// Every validator carries its hardware-held composite consensus key
/// (ML-DSA-65 and ECDSA-P256) and a proof that it holds the key: the key's
/// composite signature over the registration. A genesis with a validator
/// whose proof does not verify is refused. Where to reach a validator is not
/// in the genesis: each boot announces its network endpoint signed by this
/// key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Hex-encoded 32-byte validator account address.
    pub address: String,
    /// Hex-encoded ML-DSA-65 verifying key (1952 bytes).
    pub ml_dsa_public_key: String,
    /// Hex-encoded uncompressed SEC1 P-256 key (65 bytes).
    pub p256_public_key: String,
    /// Hex-encoded Ed25519 node key (32 bytes), derived from the node's
    /// hardware; it signs the node's peer bindings and availability
    /// attestations.
    pub node_key: String,
    /// Hex-encoded proof of possession of the consensus key.
    pub proof_of_possession: String,
    /// Hex-encoded Ed25519 signature by the node key over the registration.
    pub node_key_proof: String,
    /// Hex-encoded VRF key (32 bytes), derived from the node's hardware apart
    /// from the node key: the key its beacon contributions verify under.
    pub vrf_key: String,
    /// Hex-encoded VRF proof by the VRF key over the registration.
    pub vrf_key_proof: String,
    /// Stake amount in TNZO (whole units, will be multiplied by 10^18)
    pub stake: u64,
    /// URL of the relay the validator is reachable through, when it names
    /// one. Nodes join the network by the validators' machine identities,
    /// asking this relay for their signed endpoint records.
    pub relay: Option<String>,
}

impl GenesisValidator {
    /// This machine's entry: the node account, the public halves of its
    /// hardware consensus key, its node key, and the two proofs of
    /// possession: the consensus key's and the node key's, each signed over
    /// the registration. Every key is derived from or held by this machine's
    /// TPM 2.0 or Secure Enclave; a machine without one has no entry.
    pub fn from_local_hardware(data_dir: &std::path::Path, stake: u64) -> Result<Self> {
        let keys = crate::keygen::NodeKeys::open(data_dir)?;
        let identity = tenzro_device_key::HardwareHybridSigner::open_or_create(
            crate::machine_admission::MACHINE_WALLET_KEY_LABEL,
        )
        .map_err(|e| NodeError::Config(format!("no hardware identity key: {e}")))?;
        let address = tenzro_crypto::composite::HybridSigner::public_key(&identity).account_slot();
        let node_signer = keys.ed25519_signer()?;
        let node_key: [u8; 32] = tenzro_crypto::Signer::public_key(&node_signer)
            .as_bytes()
            .try_into()
            .map_err(|_| NodeError::Config("the node key is not a 32-byte Ed25519 key".into()))?;
        let signer = crate::validator_signer::HardwareValidatorSigner::open()
            .map_err(|e| NodeError::Config(format!("no hardware consensus key: {e}")))?;
        let key = tenzro_consensus::ValidatorSigner::public_key(&signer);
        let proof =
            tenzro_consensus::validator_key::prove_registration(&signer, &address, &node_key)
                .map_err(|e| NodeError::Config(format!("the hardware refused to sign: {e}")))?;
        let node_key_proof = tenzro_crypto::Signer::sign(
            &node_signer,
            &tenzro_consensus::validator_key::node_key_registration_message(
                &address, key, &node_key,
            ),
        )
        .map_err(|e| NodeError::Config(format!("the node key refused to sign: {e}")))?;
        let vrf = keys.vrf_prover()?;
        let vrf_key = tenzro_crypto::vrf::VrfProver::public_key(&vrf).0;
        let vrf_key_proof = tenzro_crypto::vrf::VrfProver::prove(
            &vrf,
            &tenzro_consensus::validator_key::vrf_key_registration_alpha(
                &address, key, &node_key, &vrf_key,
            ),
        )
        .map_err(|e| NodeError::Config(format!("the VRF key refused to prove: {e}")))?;
        Ok(Self {
            address: hex::encode(address),
            ml_dsa_public_key: hex::encode(&key.ml_dsa),
            p256_public_key: hex::encode(&key.p256),
            node_key: hex::encode(node_key),
            proof_of_possession: hex::encode(proof),
            node_key_proof: hex::encode(node_key_proof.as_bytes()),
            vrf_key: hex::encode(vrf_key),
            vrf_key_proof: hex::encode(vrf_key_proof.as_bytes()),
            stake,
            relay: None,
        })
    }

    /// The entry as a `[[validators]]` TOML table.
    pub fn to_toml(&self) -> String {
        let mut toml = format!(
            "[[validators]]\naddress = \"{}\"\nml_dsa_public_key = \"{}\"\np256_public_key = \"{}\"\n\
             node_key = \"{}\"\nproof_of_possession = \"{}\"\nnode_key_proof = \"{}\"\n\
             vrf_key = \"{}\"\nvrf_key_proof = \"{}\"\nstake = {}\n",
            self.address,
            self.ml_dsa_public_key,
            self.p256_public_key,
            self.node_key,
            self.proof_of_possession,
            self.node_key_proof,
            self.vrf_key,
            self.vrf_key_proof,
            self.stake
        );
        if let Some(relay) = &self.relay {
            toml.push_str(&format!("relay = \"{relay}\"\n"));
        }
        toml
    }

    /// Decodes the entry and checks its proofs of possession.
    pub fn decode(&self) -> Result<tenzro_consensus::ValidatorInfo> {
        self.decode_with_vrf_key().map(|(info, _)| info)
    }

    /// Decodes the entry with its VRF key, checking every proof of
    /// possession, the VRF key's included.
    pub fn decode_with_vrf_key(&self) -> Result<(tenzro_consensus::ValidatorInfo, [u8; 32])> {
        let hex_field = |name: &str, v: &str| {
            hex::decode(v.trim().trim_start_matches("0x"))
                .map_err(|e| NodeError::Config(format!("genesis validator {name}: {e}")))
        };
        let address: [u8; 32] = hex_field("address", &self.address)?
            .try_into()
            .map_err(|_| NodeError::Config("genesis validator address must be 32 bytes".into()))?;
        let node_key: [u8; 32] = hex_field("node_key", &self.node_key)?
            .try_into()
            .map_err(|_| NodeError::Config("genesis validator node_key must be 32 bytes".into()))?;
        let key = tenzro_consensus::ValidatorPublicKey::new(
            hex_field("ml_dsa_public_key", &self.ml_dsa_public_key)?,
            hex_field("p256_public_key", &self.p256_public_key)?,
        )
        .map_err(|e| NodeError::Config(format!("genesis validator key: {e}")))?;
        tenzro_consensus::validator_key::verify_registration(
            &address,
            &key,
            &node_key,
            &hex_field("proof_of_possession", &self.proof_of_possession)?,
        )
        .map_err(|e| NodeError::Config(format!("genesis validator {}: {e}", self.address)))?;
        tenzro_consensus::validator_key::verify_node_key_registration(
            &address,
            &key,
            &node_key,
            &hex_field("node_key_proof", &self.node_key_proof)?,
        )
        .map_err(|e| NodeError::Config(format!("genesis validator {}: {e}", self.address)))?;
        let vrf_key: [u8; 32] = hex_field("vrf_key", &self.vrf_key)?
            .try_into()
            .map_err(|_| NodeError::Config("genesis validator vrf_key must be 32 bytes".into()))?;
        tenzro_consensus::validator_key::verify_vrf_key_registration(
            &address,
            &key,
            &node_key,
            &vrf_key,
            &hex_field("vrf_key_proof", &self.vrf_key_proof)?,
        )
        .map_err(|e| NodeError::Config(format!("genesis validator {}: {e}", self.address)))?;
        Ok((
            tenzro_consensus::ValidatorInfo::new(
                tenzro_types::primitives::Address::new(address),
                key,
                node_key,
                self.stake as u128,
            ),
            vrf_key,
        ))
    }
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

/// A role stake bonded at genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisRoleStake {
    /// Hex-encoded 32-byte bonding account: the operator account of the node
    /// that serves the role.
    pub address: String,
    /// The role, as `--roles` names it (`rpc`, `storage`, `ai`...).
    pub role: String,
    /// Stake in whole TNZO. Omitted, the bond the role requires for its
    /// `capacity` under the genesis governed parameters (`stake.*` in
    /// `[network_params]`, or their genesis values).
    #[serde(default)]
    pub stake: Option<u64>,
    /// The capacity the bond backs, for a role whose bond scales.
    #[serde(default)]
    pub capacity: tenzro_types::token::StakeCapacity,
    /// The public URL the role is served at: for `edge`, the relay URL every
    /// node finds on chain.
    #[serde(default)]
    pub endpoint: Option<String>,
}

impl GenesisRoleStake {
    /// The bond as the VM applies it, under the genesis bond amounts `ladder`.
    pub fn decode(
        &self,
        ladder: &tenzro_types::network::StakeLadder,
    ) -> Result<tenzro_vm::native::GenesisRoleBond> {
        let account: [u8; 32] = hex::decode(self.address.trim_start_matches("0x"))
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                NodeError::Config(format!(
                    "role stake address {} is not 32-byte hex",
                    self.address
                ))
            })?;
        let role: tenzro_types::network::NetworkRole = self
            .role
            .parse()
            .map_err(|e| NodeError::Config(format!("role stake {}: {e}", self.role)))?;
        let amount = match self.stake {
            Some(stake) => (stake as u128)
                .checked_mul(1_000_000_000_000_000_000u128)
                .ok_or_else(|| {
                    NodeError::Config(format!("role stake overflow for {}", self.address))
                })?,
            None => role.required_stake(&self.capacity, ladder),
        };
        Ok(tenzro_vm::native::GenesisRoleBond {
            account,
            role,
            amount,
            capacity: self.capacity.clone(),
            endpoint: self.endpoint.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Whether the bridge subsystem is enabled.
    #[serde(default = "BridgeConfig::default_enabled")]
    pub enabled: bool,

    /// Hardware signer for the node's ERC-8004 mirror writes (agent
    /// registrations and settlement-derived feedback). Absent, the mirror and
    /// the reputation dispatchers stay disabled.
    pub erc8004_system_signer: Option<HardwareSignerConfig>,
}

impl BridgeConfig {
    fn default_enabled() -> bool {
        true
    }
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            erc8004_system_signer: None,
        }
    }
}

/// A hardware secp256k1 signer the node sends transaction hashes to. The key
/// never leaves the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSignerConfig {
    /// `"ledger"`, `"trezor"` or `"gridplus"`.
    pub device_kind: String,
    /// BIP-32 derivation path of the key on the device, such as
    /// `m/44'/60'/0'/0/0`.
    pub derivation_path: String,
    /// GridPlus Lattice device id (GridPlus only).
    pub device_id: Option<String>,
    /// GridPlus wallet UUID the key belongs to (GridPlus only).
    pub wallet_uuid: Option<String>,
}

/// A platform's declared fee per settled call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformFeeConfig {
    /// The account the fee is paid to, hex.
    pub wallet: String,
    /// The fee in basis points of the price, on top of it.
    pub bps: u32,
}

impl PlatformFeeConfig {
    /// The fee as the leg a payer signs.
    pub fn leg(
        &self,
    ) -> std::result::Result<tenzro_types::payment_authorization::AppMargin, String> {
        let bytes = hex::decode(self.wallet.trim_start_matches("0x"))
            .map_err(|_| "platform_fee.wallet is not hex".to_string())?;
        let wallet = tenzro_types::primitives::Address::from_bytes(&bytes)
            .ok_or_else(|| "platform_fee.wallet is not an account address".to_string())?;
        if self.bps == 0 {
            return Err("platform_fee.bps must be above 0".to_string());
        }
        Ok(tenzro_types::payment_authorization::AppMargin {
            app_wallet: wallet,
            margin_bps: self.bps,
        })
    }
}

/// The operator's terms for sponsored inference (`tenzro_sponsoredInference`):
/// calls a public page offers without a key, paid by a delegated agent this
/// machine serves. Absent, the method is off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredInferenceConfig {
    /// The sponsoring agent's DID. Its terms on chain must name this
    /// machine as a serving node and allow paying this node's payee.
    pub sponsor: String,
    /// The models it pays for; each must be served by this node.
    pub models: Vec<String>,
    /// Most output tokens one call may ask for.
    pub max_tokens: u32,
    /// Calls one source address may make per minute.
    pub per_source_per_minute: u32,
    /// Calls per minute from all sources together.
    pub global_per_minute: u32,
    /// Most the sponsor pays per UTC day, TNZO base units.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub daily_budget: u128,
}

/// HTTP 402 payment gate configuration.
///
/// The gate collects the payments the access policy asks for: a `paid` rule
/// names the price, and a request without a valid payment credential is
/// answered with HTTP 402 + a challenge JSON body. Verified credentials
/// forward the request to the underlying handler.
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

    /// Settle `upto` payments at the metered cost of the work instead of the
    /// amount the buyer declared before it ran. On by default.
    ///
    /// An AI node issues `upto` challenges, where the amount is a ceiling the
    /// buyer signs. The gate checks the credential, serves the request, and
    /// settles the `cost_wei` the handler reports, capped at the signed
    /// ceiling, with a usage record the node's meter signs; a stream settles
    /// when it ends, at the last cost it reported. A failed response is not
    /// charged. Set `false` to settle the buyer's declared amount before
    /// serving instead.
    #[serde(default = "default_metered_settlement")]
    pub metered_settlement: bool,

    /// Tokens on the Tenzro ledger this node accepts as payment besides TNZO
    /// (0x-prefixed token ids): a stablecoin issued natively or bridged in.
    /// Opt-in: empty accepts TNZO only. A payment in a token carries its USD
    /// price and passes the token's own eligibility rules on the ledger.
    #[serde(default)]
    pub ledger_assets: Vec<String>,

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
    /// `evm_rpc_url` itself and confirms each settlement on it. Settlements
    /// broadcast through the relayer held by `relayer_signer` when one is
    /// configured, otherwise through `settlement_facilitator_url`. Absent this
    /// block, the node offers no EIP-3009 or Permit2 scheme.
    #[serde(default)]
    pub x402_facilitator: Option<X402FacilitatorConfig>,

    /// Base URL of the x402 facilitator that settles the payments A2A tasks
    /// ask for (`POST {url}/settle`). Without one, an A2A task that needs a
    /// payment cannot be paid on this node.
    #[serde(default)]
    pub facilitator_url: Option<String>,
}

/// Operator config for self-hosted x402 (EIP-3009 / Permit2) facilitation.
///
/// The node runs every admission check itself against `evm_rpc_url`. The
/// `transferWithAuthorization` transaction is broadcast either by the
/// operator's relayer, whose key is on the hardware device named by
/// `relayer_signer`, or by the x402 facilitator at `settlement_facilitator_url`;
/// either way the node then confirms on `evm_rpc_url` that it executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402FacilitatorConfig {
    /// EVM JSON-RPC endpoint used for the admission checks and to confirm
    /// the settlement transaction.
    pub evm_rpc_url: String,

    /// EVM chain id the facilitation serves (e.g. `84532` for Base Sepolia).
    pub chain_id: u64,

    /// Base URL of the x402 facilitator that broadcasts settlements when no
    /// relayer device is configured.
    pub settlement_facilitator_url: Option<String>,
    /// The hardware device holding the relayer key, when the operator
    /// broadcasts settlements itself.
    pub relayer_signer: Option<HardwareSignerConfig>,
}

fn default_metered_settlement() -> bool {
    true
}

impl Default for PaymentsConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            default_protocol: "mpp".to_string(),
            default_amount: 0,
            default_asset: "USDC".to_string(),
            recipient: String::new(),
            metered_settlement: default_metered_settlement(),
            ledger_assets: Vec::new(),
            tempo_stablecoins: std::collections::HashMap::new(),
            x402_facilitator: None,
            facilitator_url: None,
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
    /// Settle `upto` payments at the metered cost (see
    /// [`PaymentsConfig::metered_settlement`]).
    pub metered_settlement: bool,
}

impl PaymentsConfig {
    /// Fold the node's roles and its own address into an effective payment
    /// posture.
    ///
    /// A node serving the `ai` role auto-gates its inference routes to
    /// `default_recipient` (its own validator/proposer address) unless the
    /// operator set `recipient` explicitly. The gate is on by default for
    /// `ai` nodes; setting `enabled = false` in config is the opt-out for
    /// operators who want to serve inference for free. Explicit
    /// `enabled = true` also forces the gate on regardless of role.
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

        EffectivePayments {
            gate_on,
            recipient,
            amount: self.default_amount,
            asset: self.default_asset.clone(),
            protocol: self.default_protocol.clone(),
            metered_settlement: self.metered_settlement,
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
            .field("metered_settlement", &self.metered_settlement)
            .field("ledger_assets", &self.ledger_assets)
            .field("tempo_stablecoins", &self.tempo_stablecoins)
            .field("x402_facilitator", &self.x402_facilitator)
            .field("facilitator_url", &self.facilitator_url)
            .finish()
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
        let mut reserve_bytes = u64::from(self.reserve_gb) * GIB;
        // The default reserve is sized for servers. On a machine with less
        // than twice that, it is a quarter of the machine, as the budget
        // derived from detected memory takes; a reserve the operator set
        // stays as set and is checked as given.
        if self.reserve_gb == Self::default().reserve_gb && total_bytes <= reserve_bytes * 2 {
            reserve_bytes = total_bytes / 4;
        }
        tenzro_model::memory_budget::BudgetConfig {
            total_bytes,
            reserve_bytes,
            resident_ceiling_bytes: self.resident_ceiling_gb.map(|gb| u64::from(gb) * GIB),
            on_demand_ceiling_bytes: self.on_demand_ceiling_gb.map(|gb| u64::from(gb) * GIB),
        }
    }
}

/// Gossiped transactions this node's mempool refused for a reason that
/// passes (the sender's nonce window, its pending cap, the rate limit, the
/// fee floor, a full mempool): how long they are held, how many, and how
/// often they are offered to the mempool again. Held transactions are never
/// relayed again. Local mempool policy, set per node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HeldTransactionsConfig {
    /// How long one is held before it is dropped, in seconds.
    pub max_age_secs: u64,
    /// How many are held at most; past it the oldest is dropped.
    pub max_held: usize,
    /// How often the held ones are offered to the mempool again, in
    /// milliseconds.
    pub retry_interval_ms: u64,
}

impl Default for HeldTransactionsConfig {
    fn default() -> Self {
        Self {
            max_age_secs: 300,
            max_held: 4_096,
            retry_interval_ms: 1_000,
        }
    }
}

/// How this node catches up when it falls behind: when it asks peers for
/// their tips, how long it waits on them, and how it scores the ones that
/// fail. The range sizes a server answers with are protocol limits and are
/// not set here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlockSyncConfig {
    /// How often peers are asked for their tips, in milliseconds.
    pub tip_probe_interval_ms: u64,
    /// How long a tip probe may take, in milliseconds.
    pub tip_request_timeout_ms: u64,
    /// How long one range request may take, in milliseconds.
    pub range_request_timeout_ms: u64,
    /// Connected peers asked for their tips each round besides the
    /// committee members that disclosed their endpoints to this node: the
    /// best-scored gossip peers, up to this many. A node outside the
    /// committee (an RPC node) syncs from these alone.
    pub max_connected_peers: usize,
    /// Blocks this node may trail a peer by and still count as synced:
    /// gossip closes a gap that small.
    pub tolerance_blocks: u64,
    /// Certified checkpoints a validator may trail a peer by while no block
    /// is behind: checkpoints that order no block still carry the epoch on.
    /// A node not validating follows them with no slack.
    pub tolerance_checkpoints: u64,
    /// How long the node may trail by any amount before it fetches the gap
    /// regardless of `tolerance_blocks`, in milliseconds.
    pub max_behind_ms: u64,
    /// How long a certificate past the local tip keeps the node fetching any
    /// gap from any peer not hard-banned, in milliseconds.
    pub behind_hint_ms: u64,
    /// Score change for a peer that failed a request or served something
    /// unusable.
    pub score_penalty: i32,
    /// Score change for a peer whose range imported.
    pub score_success: i32,
    /// Highest score a peer can bank.
    pub score_ceiling: i32,
    /// Score below which a peer is not asked while the node is current.
    pub score_drop_threshold: i32,
    /// Score below which a peer is not asked even while the node is behind.
    pub score_hard_ban_threshold: i32,
    /// Points a peer below zero regains every probe round, so a peer that
    /// was down or slow for a while is asked again once it may be back.
    pub score_recovery_per_round: i32,
}

impl Default for BlockSyncConfig {
    fn default() -> Self {
        Self {
            tip_probe_interval_ms: 15_000,
            tip_request_timeout_ms: 10_000,
            range_request_timeout_ms: 30_000,
            max_connected_peers: 8,
            tolerance_blocks: 8,
            tolerance_checkpoints: 4,
            max_behind_ms: 45_000,
            behind_hint_ms: 60_000,
            score_penalty: -10,
            score_success: 5,
            score_ceiling: 50,
            score_drop_threshold: -50,
            score_hard_ban_threshold: -500,
            score_recovery_per_round: 2,
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

/// The WebAuthn relying-party ID the network's passkeys are scoped to. Every
/// node verifies assertions against it unless `TENZRO_WEBAUTHN_RP_ID` says
/// otherwise, so one passkey is one identity on every node.
pub const DEFAULT_WEBAUTHN_RP_ID: &str = "tenzro.com";

/// Refuses an operator's node configuration that tries to set a governed
/// network value. Governed values, the treasury's among them, live in
/// consensus state and change only by an enacted proposal at an epoch
/// boundary; a node never reads them from its own file, so a file that names
/// one is refused rather than silently ignored.
pub fn refuse_governed_values(contents: &str) -> Result<()> {
    let Ok(toml::Value::Table(top)) = contents.parse::<toml::Value>() else {
        // Not a table: the typed parse reports it.
        return Ok(());
    };
    fn walk(table: &toml::value::Table, depth: usize, found: &mut Vec<String>) {
        for (key, value) in table {
            let governed = (depth == 0 && (key == "network_params" || key == "treasury"))
                || (key.contains('.') && tenzro_vm::governance::governed_param(key).is_some());
            if governed {
                found.push(key.clone());
            } else if let toml::Value::Table(t) = value {
                walk(t, depth + 1, found);
            }
        }
    }
    let mut found = Vec::new();
    walk(&top, 0, &mut found);
    if found.is_empty() {
        return Ok(());
    }
    Err(NodeError::Config(format!(
        "the node configuration names governed network values ({}); these are set only \
         by on-chain governance and every node reads them from chain state. Remove them.",
        found.join(", ")
    )))
}

/// Default least time between two KV checkpoints of one continuity session.
pub const DEFAULT_SESSION_CHECKPOINT_INTERVAL_SECS: u64 = 5;

/// How long a guardian recovery waits before it can complete, by the kinds of
/// guardian that approved it. Recovery only enrols a new passkey, and any of
/// the account's existing passkeys can cancel it during the wait, so the wait
/// is how long the owner has to notice. The weaker the factors, the longer it
/// is. A test network may shorten all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryDelays {
    /// A recovery key and an email verifier both approved.
    pub recovery_key_and_email_secs: u64,
    /// Only a recovery key approved.
    pub recovery_key_secs: u64,
    /// Only an email verifier approved.
    pub email_secs: u64,
}

impl Default for RecoveryDelays {
    fn default() -> Self {
        Self {
            recovery_key_and_email_secs: 60 * 60,
            recovery_key_secs: 48 * 60 * 60,
            email_secs: 7 * 24 * 60 * 60,
        }
    }
}

impl RecoveryDelays {
    /// The wait for a recovery approved by these kinds of guardian, or `None`
    /// when neither kind approved.
    pub fn for_approvals(&self, recovery_key: bool, email: bool) -> u64 {
        match (recovery_key, email) {
            (true, true) => self.recovery_key_and_email_secs,
            (true, false) => self.recovery_key_secs,
            (false, true) => self.email_secs,
            // Approvals from any other role (a device) wait the longest.
            (false, false) => self.longest_secs(),
        }
    }

    /// The longest wait any approval can require.
    pub fn longest_secs(&self) -> u64 {
        self.recovery_key_and_email_secs
            .max(self.recovery_key_secs)
            .max(self.email_secs)
    }
}

/// A consensus key scheme in a node config, by its composite name.
mod consensus_key_scheme_name {
    use serde::{Deserialize, Deserializer, Serializer};
    use tenzro_consensus::validator_key::SignatureScheme;

    pub fn serialize<S: Serializer>(
        scheme: &SignatureScheme,
        ser: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        ser.serialize_str(std::str::from_utf8(scheme.label()).unwrap_or_default())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> std::result::Result<SignatureScheme, D::Error> {
        let name = String::deserialize(de)?;
        SignatureScheme::from_name(&name).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown consensus key scheme {name:?}: the schemes are \
                 COMPSIG-MLDSA65-ECDSA-P256 and COMPSIG-MLDSA87-ECDSA-P384"
            ))
        })
    }
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

    /// The signature scheme of this node's consensus key, by its composite
    /// name (`COMPSIG-MLDSA65-ECDSA-P256`, the default, or
    /// `COMPSIG-MLDSA87-ECDSA-P384`). A scheme this machine's hardware
    /// cannot hold stops the node at startup. A validator registered under
    /// another scheme asks the chain to rotate to the key of this one, and
    /// validates again from the epoch boundary that seats it.
    #[serde(default, with = "consensus_key_scheme_name")]
    pub consensus_key_scheme: tenzro_consensus::validator_key::SignatureScheme,

    /// Data directory for storage
    pub data_dir: PathBuf,

    /// Consensus configuration (for validators)
    pub consensus: Option<ConsensusConfig>,

    /// Enable TEE features
    pub tee_enabled: bool,

    /// Path to the NVIDIA attestation service's JWKS document.
    ///
    /// GPU confidential-computing evidence is signed by that service, so
    /// without its keys there is nothing to verify a GPU claim against and
    /// every NVIDIA report is refused. Supplying the path is how an operator
    /// opts into accepting GPU evidence; CPU evidence (TDX, SEV-SNP, Nitro)
    /// chains to roots this build pins and needs no configuration.
    #[serde(default)]
    pub nvidia_attestation_jwks_path: Option<PathBuf>,

    /// Models directory for inference providers
    pub models_dir: Option<PathBuf>,

    /// How the node divides memory between models and everything else.
    pub memory: MemoryConfig,

    /// How the node catches up when it falls behind.
    pub block_sync: BlockSyncConfig,

    /// Gossiped transactions refused for a reason that passes: how long,
    /// how many and how often they are offered to the mempool again.
    #[serde(default)]
    pub held_transactions: HeldTransactionsConfig,

    /// Storage memory, background I/O pacing, epoch snapshots kept, and the
    /// disk watermarks.
    pub storage: crate::storage_maintenance::StoragePolicy,

    /// The resource tier (`auto`, `edge`, `validator`, `provider`): the
    /// defaults for the store's memory and background work and the runtime's
    /// threads (see [`crate::tier`]). Values set under `[storage]` win.
    #[serde(default)]
    pub tier: crate::tier::TierSetting,

    /// Opt-in surge loading: which catalogued models the node may load when
    /// forecast regional demand crosses the operator's threshold. Off by
    /// default.
    pub surge: crate::surge::SurgeConfig,

    /// Least time between two KV checkpoints of one continuity session (see
    /// `kv_continuity`), in seconds. A checkpoint of a model with recurrent
    /// layers carries its whole recurrent state, so checkpoints are taken at
    /// turn boundaries and no more often than this.
    pub session_checkpoint_interval_secs: u64,

    /// Opt-in standby replicas: models staged in host memory without holding
    /// the GPU, and the fee charged while holding a session as its successor.
    pub standby: crate::standby::StandbyConfig,

    /// Whether and how the node tunes its own serving configuration.
    ///
    /// Off by default: a node that rewrites its own dials is one an operator
    /// has to reason about during an incident, so it is opted into. When off
    /// the controller still runs and records what it *would* have done, which
    /// is the sensible way to build confidence before enabling it.
    #[serde(default)]
    pub autotune: crate::autotune_sampler::AutotuneConfig,

    /// Limits applied to every ONNX runtime (forecast, vision, embedding,
    /// segmentation, detection, audio, video): session thread count,
    /// concurrent requests per runtime and how many may wait. Unset values
    /// are derived from the detected core count.
    #[serde(default)]
    pub onnx: tenzro_model::OnnxConfig,

    /// Engines the node runs out of process, each in a confined runtime host
    /// it supervises: the pinned environment of each hosted backend (vLLM,
    /// SGLang, TensorRT-LLM, MLX) and which models they serve in place of
    /// llama.cpp, the default.
    #[serde(default)]
    pub engines: tenzro_model::EnginesConfig,

    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,

    /// This node's own TDIP identity, named explicitly.
    ///
    /// A node is a *machine*. Under TDIP that is either
    /// `did:tenzro:machine:<controller>:<uuid>` — a machine a human operator
    /// delegates, which is the usual shape — or `did:tenzro:machine:<device-key-id>`
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

    /// Enable metrics collection
    pub metrics_enabled: bool,

    /// Enable health monitoring
    pub health_enabled: bool,

    /// Genesis configuration
    pub genesis: Option<GenesisConfig>,

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

    /// Sponsored inference, off unless set.
    #[serde(default)]
    pub sponsored_inference: Option<SponsoredInferenceConfig>,

    /// Operators this node hosts, each with the models it serves through the
    /// node. A call to one of those models settles to that operator's wallet,
    /// never to this node's payee.
    #[serde(default)]
    pub hosted_operators: Vec<crate::hosted_operators::HostedOperator>,

    /// The fee a platform node declares on every call it settles for a
    /// payer: a leg of its own on top of the price, signed by the payer in
    /// the payment it authorizes and paid to `wallet` from the payer's
    /// amount, never from a balance the platform holds. Absent, no fee.
    #[serde(default)]
    pub platform_fee: Option<PlatformFeeConfig>,

    /// Bridge configuration: fee oracle and price feeds.
    #[serde(default)]
    pub bridge: BridgeConfig,

    /// Operator overrides mapping a task's use case (`code`, `reasoning`,
    /// `research`, `chat`, `summarize`, `extract`, `embed`) to a preferred
    /// model id. When a request's use case is listed here and that model is an
    /// available candidate for the request, the router selects it outright;
    /// otherwise it uses its benchmark prior and measured difficulty. This lets
    /// an operator pin, e.g., `code = "qwen3.8-27b"` without disabling
    /// automatic routing for the use cases they leave out.
    #[serde(default)]
    pub task_models: std::collections::HashMap<String, String>,

    /// Browser origins allowed to call the RPC/Web/A2A servers cross-origin,
    /// e.g. `["https://app.tenzro.com"]`. Empty means none: pages on other
    /// origins cannot read the node's responses. Non-browser clients are not
    /// affected either way.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,

    /// Public https URL of the operator's own edge in front of this node's
    /// loopback RPC listener, if they chose to expose it. It is the only RPC
    /// URL the node ever publishes; `None` (the default) publishes none, and a
    /// bind address is never published. Startup refuses a value that is not
    /// https or whose host is loopback, private, CGNAT or link-local.
    #[serde(default)]
    pub external_rpc_addr: Option<String>,

    /// Public https URL of the operator's own edge in front of this node's
    /// loopback MCP listener, if any. Same rules as `external_rpc_addr`.
    #[serde(default)]
    pub external_mcp_addr: Option<String>,

    /// Public https URL of the operator's own edge in front of this node's
    /// loopback A2A listener, if any. Same rules as `external_rpc_addr`.
    /// Without it the Agent Card addresses the node by machine identity.
    #[serde(default)]
    pub external_a2a_addr: Option<String>,

    /// Coarse region of this node: a country code (`DE`) or a wide region
    /// (`europe`), never anything finer (see
    /// [`tenzro_types::provider_listing::coarse_region`]). Carried through to
    /// the gossiped `ProviderAnnouncementMessage::region` so peers and
    /// discovery apps can choose providers by region. `None` (the default,
    /// and the right choice for a private node) means the operator declined
    /// to declare; consumers treat it as unknown, not as a wildcard.
    #[serde(default)]
    pub region: Option<String>,

    /// Declared jurisdiction of this node: ISO 3166-1 alpha-2 country
    /// code (e.g. `DE`, `SG`, `US`). Unlike `region` (a coarse
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
    /// that needs an iroh endpoint: the storage `IrohBlobsDaBackend` and any
    /// direct `tenzro://blob/<hash>` URI fetches.
    ///
    /// The default (`TenzroIrohConfig::default()`) names no relay, pkarr
    /// host or peer: the node joins through the machine identities in
    /// `boot` and the genesis validators, via the relays they name (see
    /// [`crate::identity_bootstrap`]).
    #[serde(default)]
    pub iroh: tenzro_iroh::TenzroIrohConfig,

    /// Peers to restore state from at start, as `<EndpointId>` or
    /// `<EndpointId>@<ip:port>`; the `--state-sync-from` flag adds to these.
    /// A bare id is found by discovery, an id with an address is dialled there
    /// (for a network with no discovery). Needs a weak-subjectivity
    /// checkpoint.
    #[serde(default)]
    pub state_sync_from: Vec<String>,

    /// Data-availability backend selector for off-loaded payloads (agent-memory
    /// archival). `Auto` (default) prefers iroh-blobs when the resolver is
    /// bound; `Inline` forces the in-process store; `IrohBlobs` requires iroh.
    #[serde(default)]
    pub da_backend: DaBackendSelector,

    /// State-sync snapshot producer cadence + retention. Disabled by
    /// default — only dedicated RPC / archival operators should produce
    /// snapshots, since every snapshot is a multi-GB copy of the full
    /// state. Validators run with the default (disabled) so they never
    /// accumulate snapshot directories on their data volume.
    #[serde(default)]
    pub snapshot: crate::snapshot::SnapshotConfig,

    /// Rates this operator charges for the metered provider runtimes —
    /// storage capacity and accelerator rental. Both are quoted per billing
    /// epoch ([`crate::node::BILLING_EPOCH_INTERVAL_SECS`], one hour), so the
    /// compute rate is wei per card-hour and the storage rate is wei per
    /// byte-hour. Defaults match the network's reference rates.
    #[serde(default)]
    pub provider_rates: ProviderRatesConfig,

    /// Serve models from an endpoint the operator already runs instead of
    /// this node's own engines: the endpoint, its models and how long a call
    /// to it may take. Absent, the node serves only what its engines load.
    /// See [`crate::connector`].
    #[serde(default)]
    pub connector: Option<crate::connector::ConnectorConfig>,

    /// The operator's own Hugging Face access token, for an operator who
    /// neither seals it (`tenzro-node credentials set huggingface`) nor sets
    /// `TENZRO_HUGGINGFACE_CREDENTIAL`; both of those win over it. Stored
    /// unsealed, at the operator's own risk, and never written back out.
    #[serde(default, skip_serializing)]
    pub huggingface_credential: Option<crate::credentials::ConfigSecret>,

    /// Operator model-license acceptance policy. Governs which catalog models
    /// this node will register/serve: Permissive and Attribution tiers are
    /// always admitted; NonCommercial requires `accept_non_commercial`;
    /// CommercialCustom requires the model's license id to be listed in
    /// `accepted_license_ids`. Set from `--accept-non-commercial` and
    /// `--accept-license <id>` (repeatable). Default admits open-weight
    /// (permissive/attribution) models only.
    #[serde(default)]
    pub model_licensing: tenzro_types::model::AcceptancePolicy,

    /// DIDs of the publishers this node serves catalog models from. Empty
    /// means every publisher holding a catalog publisher bond. Set from
    /// `--catalog-publisher <did>`.
    #[serde(default)]
    pub catalog_publishers: Vec<String>,

    /// DIDs of the publishers whose engine releases this node reports as
    /// available. Releases are never installed by the node; its operator
    /// applies them. Set from `--release-publisher <did>`.
    #[serde(default)]
    pub release_publishers: Vec<String>,

    /// Token ids (hex) of the assets whose policies name the KYC issuers this
    /// node recognises: an identity's KYC tier is the best live `kyc` grade
    /// its wallet holds from one of those issuers. Empty means every
    /// identity is unverified. Set from `--kyc-asset <token id>`.
    #[serde(default)]
    pub kyc_assets: Vec<String>,

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

    /// The node's visibility: `public`, `gated` or `private`.
    ///
    /// Applies to every resource this node offers (models of every type,
    /// compute, storage, databases, hosting, tools) unless that resource
    /// carries its own override:
    ///
    /// - `public` — announced; anyone may use a resource by paying
    ///   `payments.default_amount` per use (`0` = free).
    /// - `gated` — announced as access-required; usable only by callers the
    ///   access policy names.
    /// - `private` — nothing is announced; only this node's own callers are
    ///   served. The node still validates if it runs the validator role.
    ///
    /// `tenzro_setNodeVisibility` changes it at runtime; that choice is
    /// persisted and takes precedence over this value on the next start.
    #[serde(default)]
    pub visibility: tenzro_types::Visibility,

    /// Whether this node serves delegated agents: holds a hardware key per
    /// agent assigned to it and signs their actions within their approved
    /// terms. Unset, a node serving AI serves agents and any other does not.
    /// `serve_agents = true` requires a TPM 2.0 that can certify keys.
    #[serde(default)]
    pub serve_agents: Option<bool>,

    /// Outbound fetches to destinations a caller names (skill and tool
    /// endpoints, `url_fetch`, webhooks, `did:web` hosts, hosted functions,
    /// provider and expert endpoints other nodes advertise). Private and
    /// metadata ranges are refused unless the machine owner signed a grant
    /// for them (see [`crate::machine_access`]).
    #[serde(default)]
    pub egress: crate::egress_guard::EgressConfig,

    /// HTTP listener hygiene: which proxies may set `X-Forwarded-For`, which
    /// `Host` names the listeners answer to, and the JSON-RPC batch cap.
    #[serde(default)]
    pub http_surface: crate::http_surface::HttpSurfaceConfig,

    /// Administrative access: the networks administrative calls are accepted
    /// from, and what the administrative audit log records.
    #[serde(default)]
    pub admin: crate::admin_audit::AdminConfig,

    /// How long a guardian recovery waits, by the factors that approved it,
    /// before it can complete. Any of the account's passkeys can cancel it
    /// during the wait.
    #[serde(default)]
    pub recovery_delays: RecoveryDelays,

    /// Where a validator reads the USD rates it reports each epoch, per
    /// symbol. A symbol needs sources from at least two independent
    /// providers; with fewer the validator does not report it.
    #[serde(default)]
    pub fee_rate_sources: Vec<FeeRateSource>,

    /// The namespace this node's hardware keys are labelled under. A machine
    /// runs one node under the default labels, which make its machine
    /// identity; each further node on the same machine names its own
    /// namespace (`a-z`, `0-9`, `-`, `_`), so it holds its own keys in the
    /// same TPM or Secure Enclave and has its own identity. It names keys
    /// only: no key is ever read from configuration.
    #[serde(default)]
    pub hardware_key_namespace: Option<String>,

    /// Limits on this node's use of the TPM, which it shares with every
    /// other process on the machine (the `[tpm]` table).
    #[serde(default)]
    pub tpm: TpmConfig,

    /// Whether this node asks an OCSP responder about the certificates
    /// behind each GPU proof it receives, and keeps refused proofs out of its
    /// pool (the `[gpu_revocation]` table). Off by default.
    #[serde(default)]
    pub gpu_revocation: GpuRevocationConfig,

    /// One model served across several of the operator's own machines (the
    /// `[layer_pipeline]` table). Every machine of the pipeline carries the
    /// same table and finds its place by its machine DID.
    #[serde(default)]
    pub layer_pipeline: Option<LayerPipelineConfig>,
}

/// A model whose blocks are split across machines on one local network, each
/// machine holding a contiguous range and passing its hidden states to the
/// next. See `docs/layer-pipeline.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerPipelineConfig {
    /// The catalog model to serve. Every machine must hold the same weights.
    pub model_id: String,
    /// The machines in pipeline order. The first drives generation and serves
    /// the model; it needs no address.
    pub stages: Vec<LayerPipelineStage>,
    /// Largest micro-batch, in tokens. A prompt is split into micro-batches so
    /// every machine works on a different one at the same time.
    #[serde(default = "default_pipeline_micro_batch")]
    pub micro_batch: u32,
    /// Context length served.
    #[serde(default = "default_pipeline_context")]
    pub context_length: u32,
    /// Seconds without any answer from the pipeline before a request fails.
    #[serde(default = "default_pipeline_timeout")]
    pub answer_timeout_secs: u64,
}

/// One machine of a layer pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerPipelineStage {
    /// The machine's DID (`did:tenzro:machine:...`), derived from its hardware
    /// key. It must be an accepted member of this operator's cluster.
    pub machine_did: String,
    /// `host:port` the stage listens on, on the local network. Empty for the
    /// first machine.
    #[serde(default)]
    pub address: String,
    /// Blocks `[begin, end)` this machine holds. Either every stage names its
    /// blocks or none does; with none, blocks are split by `weight`.
    #[serde(default)]
    pub layers: Option<[u32; 2]>,
    /// Relative share of the blocks when no stage names its own (for example
    /// the machine's memory in GB). Defaults to 1.
    #[serde(default)]
    pub weight: Option<u64>,
}

fn default_pipeline_micro_batch() -> u32 {
    64
}

fn default_pipeline_context() -> u32 {
    8192
}

fn default_pipeline_timeout() -> u64 {
    120
}

/// How this node uses the TPM. Every TPM command runs on one dedicated
/// thread, one at a time; these bound how long one may take and how often
/// the node signs and quotes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TpmConfig {
    /// Seconds one TPM command may take before it fails with an error.
    pub call_timeout_secs: u64,
    /// Sustained TPM signatures per second.
    pub signs_per_second: u32,
    /// Sustained TPM quotes and certifications per second.
    pub quotes_per_second: u32,
    /// Persistent handle of the key that authorises the TPM derivation root:
    /// a restricted signing key in the endorsement hierarchy, certified by
    /// this TPM's endorsement key at start. Every use of the root needs its
    /// fresh signature. The default is the attestation key `tenzro-node tpm
    /// provision` makes.
    #[serde(default = "default_root_authorization_handle")]
    pub root_authorization_handle: u32,
}

/// Revocation of the certificates behind a GPU proof, asked online before
/// the proof enters this node's pool (see `crate::gpu_revocation`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GpuRevocationConfig {
    /// Ask. Off by default.
    pub enabled: bool,
    /// The OCSP responder; NVIDIA's by default.
    pub ocsp_url: String,
    /// Seconds one answer may take.
    pub timeout_secs: u64,
}

impl Default for GpuRevocationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ocsp_url: "https://ocsp.ndis.nvidia.com/".into(),
            timeout_secs: 10,
        }
    }
}

fn default_root_authorization_handle() -> u32 {
    tenzro_device_key::tpm_wire::NODE_ATTESTATION_HANDLE
}

impl Default for TpmConfig {
    fn default() -> Self {
        Self {
            call_timeout_secs: 10,
            signs_per_second: 30,
            quotes_per_second: 2,
            root_authorization_handle: default_root_authorization_handle(),
        }
    }
}

/// One USD price source a validator quotes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRateSource {
    /// The provider behind the price, reported on chain with the quote.
    /// Entries sharing a name are one provider: their quotes collapse to
    /// their median, so one provider never counts as two independent
    /// sources.
    pub name: String,
    /// The priced asset (`TNZO`, `ETH`, ...); TNZO when absent.
    #[serde(default = "default_rate_symbol")]
    pub symbol: String,
    /// Where the price is read.
    #[serde(flatten)]
    pub feed: FeeRateFeed,
}

fn default_rate_symbol() -> String {
    "TNZO".to_string()
}

/// How a [`FeeRateSource`] is read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FeeRateFeed {
    /// An HTTPS endpoint answering JSON.
    Json {
        /// The endpoint.
        url: String,
        /// JSON pointer (RFC 6901) to the USD price of one unit of the
        /// symbol, a number or a decimal string.
        pointer: String,
    },
    /// An `AggregatorV3Interface` USD price feed for the symbol, read with
    /// `eth_call` over an EVM chain's JSON-RPC. Stale or non-positive
    /// rounds are refused.
    Aggregator {
        /// The chain's JSON-RPC endpoint.
        rpc_url: String,
        /// The feed contract, `0x` hex.
        address: String,
    },
    /// Signed schema-v3 reports from a Data Streams endpoint. A report counts
    /// only with the signatures the stream's governed signer set requires
    /// (installed on chain by a `SetRateStream` proposal), and only for the
    /// symbol that set names; no operator configuration names the signers.
    DataStream {
        /// The streams REST endpoint.
        url: String,
        /// The stream's feed id, `0x` hex.
        feed_id: String,
        /// API client id.
        client_id: String,
        /// Environment variable holding the API HMAC secret.
        secret_env: String,
        /// Oldest observation accepted, seconds.
        max_age_secs: u64,
    },
}

/// Rates the provider runtimes spawn with.
///
/// One billing epoch is [`crate::node::BILLING_EPOCH_INTERVAL_SECS`] seconds,
/// so the metered rates are per hour: the compute rate is what a renter pays
/// for an hour of this node's accelerators, the storage rate what a depositor
/// pays to hold one byte for an hour. Both are fixed rates: neither follows
/// demand.
///
/// Inference is priced per unit of metered work instead of per epoch, so it
/// carries the operator's [`crate::node::ProviderPricing`] cards rather than a
/// policy.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProviderRatesConfig {
    /// How the storage runtime prices a byte-epoch.
    #[serde(default = "default_storage_policy")]
    pub storage: crate::pricing::PricingPolicy,

    /// How the compute-rental runtime prices an epoch.
    #[serde(default = "default_compute_policy")]
    pub compute: crate::pricing::PricingPolicy,

    /// What this provider charges per unit of metered work: a default card
    /// and per-model cards.
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

impl Default for NodeConfig {
    fn default() -> Self {
        Self::default_user()
    }
}

impl NodeConfig {
    /// The chain id of the chain this node runs, as its genesis sets it.
    ///
    /// A node configured without a genesis (an embedded or test node; the
    /// binary always sets one) runs a local chain under
    /// [`TESTNET_CHAIN_ID`](tenzro_types::constants::TESTNET_CHAIN_ID), the id
    /// [`GenesisConfig::default_testnet`] gives, and records that id in state
    /// as a genesis would. Every surface that signs, checks or names the chain
    /// reads it here, so none of them can disagree.
    pub fn chain_id(&self) -> u64 {
        self.genesis
            .as_ref()
            .map_or(tenzro_types::constants::TESTNET_CHAIN_ID, |g| g.chain_id)
    }

    /// The resource tier this configuration resolves to on this machine.
    pub fn resolved_tier(&self) -> crate::tier::Tier {
        let memory = match self.memory.total_gb {
            Some(gb) => u64::from(gb) << 30,
            None => crate::tier::machine_memory(),
        };
        self.tier.resolve(&self.roles, memory)
    }

    /// Whether this node serves delegated agents: `serve_agents` when set,
    /// otherwise whether it serves AI.
    pub fn serves_agents(&self) -> bool {
        self.serve_agents.unwrap_or_else(|| self.roles.serves_ai())
    }

    /// Create a default validator configuration
    pub fn default_validator() -> Self {
        Self {
            roles: RoleSet::validator_only(),
            validator_self_stake: None,
            consensus_key_scheme: Default::default(),
            data_dir: tenzro_types::paths::instance_data_dir("validator"),
            consensus: Some(ConsensusConfig::default()),
            tee_enabled: true,
            nvidia_attestation_jwks_path: None,
            models_dir: None,
            memory: MemoryConfig::default(),
            block_sync: BlockSyncConfig::default(),
            held_transactions: HeldTransactionsConfig::default(),
            storage: crate::storage_maintenance::StoragePolicy::default(),
            tier: crate::tier::TierSetting::Auto,
            surge: crate::surge::SurgeConfig::default(),
            session_checkpoint_interval_secs: DEFAULT_SESSION_CHECKPOINT_INTERVAL_SECS,
            standby: crate::standby::StandbyConfig::default(),
            autotune: crate::autotune_sampler::AutotuneConfig::default(),
            onnx: tenzro_model::OnnxConfig::default(),
            engines: tenzro_model::EnginesConfig::default(),
            log_level: "info".to_string(),
            // Every listener binds loopback: a node speaks to peers over the
            // network's own transport, and any public exposure is the
            // operator's own edge in front of these addresses.
            operator_did: None,
            rpc_addr: "127.0.0.1:8545".to_string(),
            web_addr: "127.0.0.1:8080".to_string(),
            mcp_addr: "127.0.0.1:3001".to_string(),
            a2a_addr: "127.0.0.1:3002".to_string(),
            metrics_enabled: true,
            health_enabled: true,
            genesis: Some(GenesisConfig::default_testnet()),
            economics: EconomicsConfig::default(),
            webauthn_trusted_roots: Vec::new(),
            payments: PaymentsConfig::default(),
            sponsored_inference: None,
            hosted_operators: Vec::new(),
            platform_fee: None,
            bridge: BridgeConfig::default(),
            task_models: std::collections::HashMap::new(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            external_mcp_addr: None,
            external_a2a_addr: None,
            region: None,
            jurisdiction_country: None,
            jurisdiction_blocs: Vec::new(),
            iroh: tenzro_iroh::TenzroIrohConfig::default(),
            state_sync_from: Vec::new(),
            da_backend: DaBackendSelector::default(),
            snapshot: crate::snapshot::SnapshotConfig::default(),
            provider_rates: ProviderRatesConfig::default(),
            connector: None,
            huggingface_credential: None,
            model_licensing: tenzro_types::model::AcceptancePolicy::default(),
            catalog_publishers: Vec::new(),
            release_publishers: Vec::new(),
            kyc_assets: Vec::new(),
            listing_tnzo_usd_micro: None,
            visibility: tenzro_types::Visibility::Public,
            serve_agents: None,
            egress: Default::default(),
            http_surface: Default::default(),
            admin: Default::default(),
            recovery_delays: Default::default(),
            fee_rate_sources: Vec::new(),
            hardware_key_namespace: None,
            tpm: TpmConfig::default(),
            gpu_revocation: GpuRevocationConfig::default(),
            layer_pipeline: None,
        }
    }

    /// Create a default inference provider configuration
    pub fn default_provider() -> Self {
        Self {
            roles: RoleSet::from(NetworkRole::ModelProvider),
            validator_self_stake: None,
            consensus_key_scheme: Default::default(),
            data_dir: tenzro_types::paths::instance_data_dir("provider"),
            consensus: None,
            tee_enabled: true,
            nvidia_attestation_jwks_path: None,
            models_dir: None,
            memory: MemoryConfig::default(),
            block_sync: BlockSyncConfig::default(),
            held_transactions: HeldTransactionsConfig::default(),
            storage: crate::storage_maintenance::StoragePolicy::default(),
            tier: crate::tier::TierSetting::Auto,
            surge: crate::surge::SurgeConfig::default(),
            session_checkpoint_interval_secs: DEFAULT_SESSION_CHECKPOINT_INTERVAL_SECS,
            standby: crate::standby::StandbyConfig::default(),
            autotune: crate::autotune_sampler::AutotuneConfig::default(),
            onnx: tenzro_model::OnnxConfig::default(),
            engines: tenzro_model::EnginesConfig::default(),
            log_level: "info".to_string(),
            operator_did: None,
            rpc_addr: "127.0.0.1:8545".to_string(),
            web_addr: "127.0.0.1:8080".to_string(),
            mcp_addr: "127.0.0.1:3001".to_string(),
            a2a_addr: "127.0.0.1:3002".to_string(),
            metrics_enabled: true,
            health_enabled: true,
            genesis: None,
            economics: EconomicsConfig::default(),
            webauthn_trusted_roots: Vec::new(),
            payments: PaymentsConfig::default(),
            sponsored_inference: None,
            hosted_operators: Vec::new(),
            platform_fee: None,
            bridge: BridgeConfig::default(),
            task_models: std::collections::HashMap::new(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            external_mcp_addr: None,
            external_a2a_addr: None,
            region: None,
            jurisdiction_country: None,
            jurisdiction_blocs: Vec::new(),
            iroh: tenzro_iroh::TenzroIrohConfig::default(),
            state_sync_from: Vec::new(),
            da_backend: DaBackendSelector::default(),
            snapshot: crate::snapshot::SnapshotConfig::default(),
            provider_rates: ProviderRatesConfig::default(),
            connector: None,
            huggingface_credential: None,
            model_licensing: tenzro_types::model::AcceptancePolicy::default(),
            catalog_publishers: Vec::new(),
            release_publishers: Vec::new(),
            kyc_assets: Vec::new(),
            listing_tnzo_usd_micro: None,
            visibility: tenzro_types::Visibility::Public,
            serve_agents: None,
            egress: Default::default(),
            http_surface: Default::default(),
            admin: Default::default(),
            recovery_delays: Default::default(),
            fee_rate_sources: Vec::new(),
            hardware_key_namespace: None,
            tpm: TpmConfig::default(),
            gpu_revocation: GpuRevocationConfig::default(),
            layer_pipeline: None,
        }
    }

    /// Create a default TEE provider configuration
    pub fn default_tee_provider() -> Self {
        Self {
            roles: RoleSet::from(NetworkRole::TeeProvider),
            validator_self_stake: None,
            consensus_key_scheme: Default::default(),
            data_dir: tenzro_types::paths::instance_data_dir("tee-provider"),
            consensus: None,
            tee_enabled: true,
            nvidia_attestation_jwks_path: None,
            models_dir: None,
            memory: MemoryConfig::default(),
            block_sync: BlockSyncConfig::default(),
            held_transactions: HeldTransactionsConfig::default(),
            storage: crate::storage_maintenance::StoragePolicy::default(),
            tier: crate::tier::TierSetting::Auto,
            surge: crate::surge::SurgeConfig::default(),
            session_checkpoint_interval_secs: DEFAULT_SESSION_CHECKPOINT_INTERVAL_SECS,
            standby: crate::standby::StandbyConfig::default(),
            autotune: crate::autotune_sampler::AutotuneConfig::default(),
            onnx: tenzro_model::OnnxConfig::default(),
            engines: tenzro_model::EnginesConfig::default(),
            log_level: "info".to_string(),
            operator_did: None,
            rpc_addr: "127.0.0.1:8545".to_string(),
            web_addr: "127.0.0.1:8080".to_string(),
            mcp_addr: "127.0.0.1:3001".to_string(),
            a2a_addr: "127.0.0.1:3002".to_string(),
            metrics_enabled: true,
            health_enabled: true,
            genesis: None,
            economics: EconomicsConfig::default(),
            webauthn_trusted_roots: Vec::new(),
            payments: PaymentsConfig::default(),
            sponsored_inference: None,
            hosted_operators: Vec::new(),
            platform_fee: None,
            bridge: BridgeConfig::default(),
            task_models: std::collections::HashMap::new(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            external_mcp_addr: None,
            external_a2a_addr: None,
            region: None,
            jurisdiction_country: None,
            jurisdiction_blocs: Vec::new(),
            iroh: tenzro_iroh::TenzroIrohConfig::default(),
            state_sync_from: Vec::new(),
            da_backend: DaBackendSelector::default(),
            snapshot: crate::snapshot::SnapshotConfig::default(),
            provider_rates: ProviderRatesConfig::default(),
            connector: None,
            huggingface_credential: None,
            model_licensing: tenzro_types::model::AcceptancePolicy::default(),
            catalog_publishers: Vec::new(),
            release_publishers: Vec::new(),
            kyc_assets: Vec::new(),
            listing_tnzo_usd_micro: None,
            visibility: tenzro_types::Visibility::Public,
            serve_agents: None,
            egress: Default::default(),
            http_surface: Default::default(),
            admin: Default::default(),
            recovery_delays: Default::default(),
            fee_rate_sources: Vec::new(),
            hardware_key_namespace: None,
            tpm: TpmConfig::default(),
            gpu_revocation: GpuRevocationConfig::default(),
            layer_pipeline: None,
        }
    }

    /// Create a default user node configuration
    pub fn default_user() -> Self {
        Self {
            roles: RoleSet::from(NetworkRole::LightClient),
            validator_self_stake: None,
            consensus_key_scheme: Default::default(),
            data_dir: tenzro_types::paths::default_data_dir(),
            consensus: None,
            tee_enabled: true,
            nvidia_attestation_jwks_path: None,
            models_dir: None,
            memory: MemoryConfig::default(),
            block_sync: BlockSyncConfig::default(),
            held_transactions: HeldTransactionsConfig::default(),
            storage: crate::storage_maintenance::StoragePolicy::default(),
            tier: crate::tier::TierSetting::Auto,
            surge: crate::surge::SurgeConfig::default(),
            session_checkpoint_interval_secs: DEFAULT_SESSION_CHECKPOINT_INTERVAL_SECS,
            standby: crate::standby::StandbyConfig::default(),
            autotune: crate::autotune_sampler::AutotuneConfig::default(),
            onnx: tenzro_model::OnnxConfig::default(),
            engines: tenzro_model::EnginesConfig::default(),
            log_level: "info".to_string(),
            operator_did: None,
            rpc_addr: "127.0.0.1:8545".to_string(),
            web_addr: "127.0.0.1:8080".to_string(),
            mcp_addr: "127.0.0.1:3001".to_string(),
            a2a_addr: "127.0.0.1:3002".to_string(),
            metrics_enabled: false,
            health_enabled: true,
            genesis: None,
            economics: EconomicsConfig::default(),
            webauthn_trusted_roots: Vec::new(),
            payments: PaymentsConfig::default(),
            sponsored_inference: None,
            hosted_operators: Vec::new(),
            platform_fee: None,
            bridge: BridgeConfig::default(),
            task_models: std::collections::HashMap::new(),
            cors_allowed_origins: Vec::new(),
            external_rpc_addr: None,
            external_mcp_addr: None,
            external_a2a_addr: None,
            region: None,
            jurisdiction_country: None,
            jurisdiction_blocs: Vec::new(),
            iroh: tenzro_iroh::TenzroIrohConfig::default(),
            state_sync_from: Vec::new(),
            da_backend: DaBackendSelector::default(),
            snapshot: crate::snapshot::SnapshotConfig::default(),
            provider_rates: ProviderRatesConfig::default(),
            connector: None,
            huggingface_credential: None,
            model_licensing: tenzro_types::model::AcceptancePolicy::default(),
            catalog_publishers: Vec::new(),
            release_publishers: Vec::new(),
            kyc_assets: Vec::new(),
            listing_tnzo_usd_micro: None,
            visibility: tenzro_types::Visibility::Public,
            serve_agents: None,
            egress: Default::default(),
            http_surface: Default::default(),
            admin: Default::default(),
            recovery_delays: Default::default(),
            fee_rate_sources: Vec::new(),
            hardware_key_namespace: None,
            tpm: TpmConfig::default(),
            gpu_revocation: GpuRevocationConfig::default(),
            layer_pipeline: None,
        }
    }

    /// Load configuration from a TOML file
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| NodeError::Config(format!("Failed to read config file: {}", e)))?;

        refuse_governed_values(&contents)?;
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

        if let Some(connector) = &self.connector {
            connector
                .validate()
                .map_err(|e| NodeError::Config(format!("connector: {e}")))?;
        }

        crate::hosted_operators::validate(&self.hosted_operators)
            .map_err(|e| NodeError::Config(format!("hosted_operators: {e}")))?;
        if let Some(fee) = &self.platform_fee {
            fee.leg().map_err(NodeError::Config)?;
        }

        if let Some(pipeline) = &self.layer_pipeline {
            #[cfg(feature = "inference")]
            crate::layer_pipeline::check_config(pipeline)
                .map_err(|e| NodeError::Config(format!("layer_pipeline: {e}")))?;
            // A pipeline stage runs part of a model, which the light build
            // cannot.
            #[cfg(not(feature = "inference"))]
            return Err(NodeError::Config(format!(
                "layer_pipeline: this is the light build of tenzro-node, which runs no model, so \
                 it cannot serve a stage of {}",
                pipeline.model_id
            )));
        }

        // Opted-in ledger assets are token ids, not names.
        for asset in &self.payments.ledger_assets {
            if !matches!(
                tenzro_types::payment_authorization::asset_token_id(asset),
                Ok(Some(_))
            ) {
                return Err(NodeError::Config(format!(
                    "payments.ledger_assets: {asset} is not a 0x-prefixed 32-byte token id"
                )));
            }
        }

        // A region is coarse: a country or a wide region, never a site.
        if let Some(region) = &self.region {
            tenzro_types::provider_listing::coarse_region(region).map_err(NodeError::Config)?;
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

        // Only a public https URL from the operator's own edge may be published.
        crate::exposure::validate(self).map_err(NodeError::Config)?;

        // Validate the genesis schema version and every validator entry
        // (keys well formed, proof of possession verifies).
        if let Some(g) = &self.genesis {
            if g.version != GENESIS_SCHEMA_VERSION {
                return Err(NodeError::Config(format!(
                    "Genesis schema version {} is not supported; this build requires \
                     version {} exactly. Regenerate genesis with each validator's \
                     composite consensus key, endpoint and proof of possession.",
                    g.version, GENESIS_SCHEMA_VERSION
                )));
            }
            for (i, gv) in g.validators.iter().enumerate() {
                gv.decode()
                    .map_err(|e| NodeError::Config(format!("Genesis validator [{i}]: {e}")))?;
            }
            g.time
                .validate()
                .map_err(|e| NodeError::Config(format!("Genesis time rules: {e}")))?;
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

    #[test]
    fn a_developer_genesis_funds_each_account_once_on_fast_valid_time_rules() {
        let validator = GenesisValidator {
            address: "11".repeat(32),
            ml_dsa_public_key: String::new(),
            p256_public_key: String::new(),
            node_key: String::new(),
            proof_of_possession: String::new(),
            node_key_proof: String::new(),
            vrf_key: String::new(),
            vrf_key_proof: String::new(),
            stake: 1_000_000,
            relay: None,
        };
        let a = format!("0x{}", "ab".repeat(32));
        let g = GenesisConfig::developer(
            validator.clone(),
            &[
                a.clone(),
                a.to_uppercase().replace("0X", "0x"),
                "cd".repeat(32),
            ],
        )
        .unwrap();
        assert_eq!(g.validators.len(), 1);
        assert_eq!(
            g.accounts.len(),
            2,
            "an account listed twice is funded once"
        );
        assert!(g.accounts.iter().all(|x| x.balance == DEV_ACCOUNT_TNZO));
        assert_eq!(g.accounts[0].address, "ab".repeat(32));
        assert!(g.time.validate().is_ok());
        assert!(
            g.time.idle_round_interval_ms
                < tenzro_consensus::TimeRules::default().idle_round_interval_ms
        );
        assert!(
            GenesisConfig::developer(validator, &["abcd".into()]).is_err(),
            "a short account is refused"
        );
    }

    /// Genesis declares validator stake in whole TNZO; consensus counts in wei.
    ///
    /// `GenesisValidator::stake` is documented as "whole units, will be
    /// multiplied by 10^18", and for a long time nothing multiplied it — a
    /// genesis validator holding 10,000,000 TNZO entered the set recorded as
    /// 10,000,000 *wei*, a hundred-billionth of a token.
    ///
    /// Everything it is compared against is in base units: `MIN_VALIDATOR_STAKE`
    /// is `10_000 * ONE_TNZO`, and a `RegisterValidator` self-stake arrives in
    /// wei. So any node that self-registered the bare minimum out-voted the
    /// founding validator by fifteen orders of magnitude. This pins the
    /// relationship rather than the numbers, so changing either side without the
    /// other fails here instead of silently re-weighting consensus.
    #[test]
    fn genesis_stake_is_whole_tnzo_and_consensus_counts_base_units() {
        use tenzro_types::constants::{MIN_VALIDATOR_STAKE, ONE_TNZO};

        // A genesis entry the size of the registry minimum, in the units genesis
        // uses, must clear the minimum once converted — and must fail to clear it
        // if the conversion is dropped.
        let declared_whole_tnzo: u64 = 10_000;
        let converted = (declared_whole_tnzo as u128).saturating_mul(ONE_TNZO);

        assert_eq!(
            converted, MIN_VALIDATOR_STAKE,
            "10,000 whole TNZO must equal the registry minimum once converted"
        );
        assert!(
            (declared_whole_tnzo as u128) < MIN_VALIDATOR_STAKE,
            "the unconverted value must be far below the minimum, which is exactly \
             why passing it through unconverted was invisible rather than an error"
        );
    }

    use super::*;

    /// A node never exposes its machine: every HTTP listener of every preset
    /// binds loopback, so nothing is reachable from off the box unless the
    /// operator puts their own edge in front of it.
    #[test]
    fn every_preset_binds_every_listener_to_loopback() {
        for c in [
            NodeConfig::default_validator(),
            NodeConfig::default_provider(),
            NodeConfig::default_tee_provider(),
            NodeConfig::default_user(),
        ] {
            for addr in [&c.rpc_addr, &c.web_addr, &c.mcp_addr, &c.a2a_addr] {
                let sock: std::net::SocketAddr = addr.parse().expect("bind address parses");
                assert!(sock.ip().is_loopback(), "{addr} is not loopback");
            }
            assert!(c.validate().is_ok());
        }
    }

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

    #[test]
    fn ai_role_gates_by_default_settling_to_own_address() {
        let roles: RoleSet = "validator,ai,storage".parse().unwrap();
        let cfg = PaymentsConfig::default();
        let eff = cfg.effective(&roles, Some("addr-of-this-node"));
        assert!(eff.gate_on, "an ai node with a recipient gates by default");
        assert_eq!(eff.recipient, "addr-of-this-node");
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
            ..PaymentsConfig::default()
        };
        let eff = cfg.effective(&roles, None);
        assert!(eff.gate_on);
        assert_eq!(eff.recipient, "operator-picked");
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
"#;
        let cfg: NodeConfig = toml::from_str(toml_src).unwrap();
        assert_eq!(cfg.payments.enabled, Some(true));
        assert_eq!(cfg.payments.default_amount, 1000);
        assert_eq!(cfg.payments.recipient, "treasury-addr");
    }

    /// The one `[onnx]` setting reaches the limits every ONNX runtime and
    /// session builder uses; unset values stay derived from the cores.
    #[test]
    fn onnx_limits_come_from_the_node_config() {
        let cfg: NodeConfig = toml::from_str("[onnx]\nthreads = 3\nconcurrency = 2\n").unwrap();
        let settings = tenzro_model::OnnxSettings::resolve(&cfg.onnx, 64);
        assert_eq!(settings.threads, 3);
        assert_eq!(settings.concurrency, 2);
        assert_eq!(settings.queue_depth, 8);

        let unset: NodeConfig = toml::from_str("").unwrap();
        let derived = tenzro_model::OnnxSettings::resolve(&unset.onnx, 64);
        assert_eq!(derived.threads, 16);
    }

    /// A node's own configuration cannot reach a governed treasury value:
    /// naming one refuses the file, so no operator runs on a value of its
    /// own while the network runs on the governed one.
    #[test]
    fn a_node_configuration_cannot_set_a_governed_treasury_value() {
        for src in [
            "[network_params]\n\"treasury.reserve_fill_share_bps\" = 1\n",
            "[treasury]\nreserve_fill_share_bps = 1\n",
            "\"treasury.sale_volume_share_bps\" = 10000\n",
            "[economics]\n\"treasury.reserve_drawdown_bps\" = 10000\n",
        ] {
            let err = super::refuse_governed_values(src)
                .expect_err(src)
                .to_string();
            assert!(err.contains("on-chain governance"), "{err}");
            let dir = std::env::temp_dir().join(format!(
                "tenzro-governed-{}-{}",
                std::process::id(),
                src.len()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("node.toml");
            std::fs::write(&path, src).unwrap();
            assert!(NodeConfig::load_from_file(&path).is_err(), "{src}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
        // Operators still differ in everything that is theirs to set.
        let own = "[[fee_rate_sources]]\nname = \"a\"\nkind = \"json\"\nurl = \"https://a.example\"\npointer = \"/p\"\n";
        assert!(super::refuse_governed_values(own).is_ok());
        let cfg: NodeConfig = toml::from_str(own).unwrap();
        assert_eq!(cfg.fee_rate_sources.len(), 1);
    }

    /// A node started without a genesis file runs on the built-in public
    /// network genesis. The bundled file must parse; until the operator-owned
    /// validator set is in it, the only refusal is the one that names the
    /// missing validators, never a malformed file.
    #[test]
    fn the_built_in_public_network_genesis_parses() {
        match super::public_network_genesis() {
            Ok(genesis) => assert!(!genesis.validators.is_empty()),
            Err(e) => assert!(
                e.to_string().contains("has no validators"),
                "the bundled genesis does not parse: {e}"
            ),
        }
    }
}
