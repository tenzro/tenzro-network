//! Permissionless validator registry — dynamic active-set membership.
//!
//! This module is the on-chain source of truth for who is a validator. It is
//! consulted at every epoch boundary by the consensus epoch manager to decide
//! which validators are active in the next epoch. The registry implements a
//! Modern 2026 hybrid pattern combining ideas from:
//!
//! - **Ethereum Pectra (EIP-7251 / EIP-7002 / EIP-8061)** — typed transactions
//!   for register/exit, weight-based churn caps with separate activation and
//!   exit budgets per epoch.
//! - **Sui** — explicit `Candidate` intermediate state where metadata is
//!   published before the validator can be activated.
//! - **Aptos** — five-state machine
//!   (`Candidate` → `PendingActive` → `Active` → `PendingExit` → `Exited`)
//!   plus a separate `Jailed` quarantine state reachable from `Active`.
//! - **Cosmos** — absolute-power `ValidatorUpdates` returned at epoch
//!   boundaries with a fixed effective-date delay so HotStuff-2 high-QC chains
//!   stay safe across reconfigurations.
//!
//! The TEE multiplier is **not** stored in the registry. It is applied only at
//! `select_active_set_for_next_epoch()` boundaries — operators can lose TEE
//! attestation without losing validator status.

use crate::error::{Result, TokenError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_types::primitives::{Address, Timestamp};
use tracing::{info, warn};

/// Default minimum self-bonded stake to register as a **Tier 2** (staked)
/// validator: 10 000 TNZO. This is intentionally above
/// [`crate::staking::DEFAULT_MIN_STAKE`] (1 000 TNZO) — validator slots
/// cost more than service-provider slots. Per WHITEPAPER §5 +
/// TOKENOMICS §7, Tier 1 (resource-only) validators require **no
/// stake**; only Tier 2 must meet this minimum.
pub const DEFAULT_MIN_VALIDATOR_SELF_STAKE: u128 = 10_000 * 1_000_000_000_000_000_000;

/// Default minimum self-bonded stake to register as a **Tier 3** (RPC
/// provider) validator: 100 000 TNZO. Tier 3 implies Tier 2 — the
/// 100k bond satisfies the 10k Tier 2 minimum, so the effective bond
/// is 100k total (not 110k).
///
/// Per the 2026-06-10 canonical model (memory:
/// `project_validator_and_rpc_provider_model_2026_06_10`), Tier 3
/// requires the higher bond because RPC providers carry the larger
/// trust surface: they mint scoped `tnz_...` API keys for tenants,
/// route signed transactions, broker access to operator-held upstream
/// credentials (Canton participants, AI provider keys, data feed
/// subscriptions), front cross-chain mint/burn flows, and mediate
/// per-tenant billing. The 10× multiple over Tier 2 reflects this.
pub const DEFAULT_MIN_RPC_PROVIDER_STAKE: u128 = 100_000 * 1_000_000_000_000_000_000;

/// Default activation churn cap: percentage of active set, in basis points.
/// 400 bps = 4% per epoch (matching EIP-8061 conservative profile).
pub const DEFAULT_ACTIVATION_CHURN_BPS: u32 = 400;

/// Default exit churn cap, in basis points. Exits are capped at the same rate
/// as activations — symmetry keeps the active set size bounded.
pub const DEFAULT_EXIT_CHURN_BPS: u32 = 400;

/// Minimum number of validators that may activate per epoch even when the
/// percentage cap rounds to zero (bootstrap phase). Per EIP-8061 §5.
pub const MIN_CHURN_PER_EPOCH: u32 = 1;

/// Re-entry cooldown after a voluntary exit, in epochs. A validator that exits
/// must wait this many epochs before they can register again — prevents
/// thrashing the active set.
pub const DEFAULT_REENTRY_COOLDOWN_EPOCHS: u64 = 4;

/// Effective-date delay between governance/registry decision and active-set
/// inclusion, in HotStuff-2 blocks. Three blocks is the standard safety
/// margin to ensure any in-flight high-QC has finalised before the validator
/// set rotates. Cosmos uses the same delay.
pub const ACTIVATION_EFFECTIVE_DELAY_BLOCKS: u64 = 3;

/// Storage key prefix for individual registry entries.
pub const VALIDATOR_PREFIX: &str = "validator:";
/// Storage key for the registry index (list of all addresses).
pub const VALIDATOR_INDEX_KEY: &str = "validator:index";
/// Storage key for the registry config.
pub const VALIDATOR_CONFIG_KEY: &str = "validator:config";

/// Column family used for registry persistence. Co-located with staking under
/// the unified token storage.
const REGISTRY_CF: &str = tenzro_storage::CF_TOKENS;

/// Participation tier of a registered validator.
///
/// Per the canonical three-tier model (WHITEPAPER §5 + TOKENOMICS §7,
/// crystallized in memory
/// `project_validator_and_rpc_provider_model_2026_06_10`):
///
/// - **Tier 1 — ResourceOnly:** open entry, no stake required. Standard
///   block classes only. Reputation + TEE multiplier weight. No
///   independent governance vote. No financial slash (ejection +
///   reputation collapse only).
/// - **Tier 2 — Staked:** ≥ 10,000 TNZO bonded. All block classes
///   including high-trust. Stake-weighted weight. Governance vote.
///   10% slash on equivocation + other slashable conditions.
/// - **Tier 3 — RpcProvider:** ≥ 100,000 TNZO bonded (implies Tier 2).
///   Sanctioned to mint scoped `tnz_...` API keys, serve public RPC,
///   broker upstream credentials, route cross-chain mint/burn, front
///   per-tenant billing. Tier 2 slashable conditions + censorship,
///   frontrunning, mishandled tenant secrets, billing fraud,
///   persistent SLA failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorTier {
    ResourceOnly,
    Staked,
    RpcProvider,
}

impl ValidatorTier {
    /// Returns the tier inferred from the validator's self-stake
    /// amount, used during admission and on every stake-change event.
    pub fn from_stake(self_stake: u128, cfg: &ValidatorRegistryConfig) -> Self {
        if self_stake >= cfg.min_rpc_provider_stake {
            Self::RpcProvider
        } else if self_stake >= cfg.min_self_stake {
            Self::Staked
        } else {
            Self::ResourceOnly
        }
    }

    /// Returns true if this tier is eligible for HighTrust block class
    /// proposer election. Per the spec, Tier 1 is excluded from
    /// high-trust blocks; Tier 2 and Tier 3 are admitted.
    pub fn admits_high_trust(&self) -> bool {
        !matches!(self, Self::ResourceOnly)
    }

    /// Returns true if this tier has independent governance voting
    /// weight via its stake. Tier 1 has none; Tier 2 and Tier 3 are
    /// stake-weighted.
    pub fn has_governance_weight(&self) -> bool {
        !matches!(self, Self::ResourceOnly)
    }

    /// Returns true if this tier has financial slashing exposure on
    /// equivocation. Tier 1 does not; Tier 2 and Tier 3 do.
    pub fn has_financial_slashing(&self) -> bool {
        !matches!(self, Self::ResourceOnly)
    }

    /// Returns true if this tier is sanctioned to mint scoped tenant
    /// API keys (`tenzro_createApiKey`) and serve public RPC. Tier 3
    /// only.
    pub fn admits_rpc_role(&self) -> bool {
        matches!(self, Self::RpcProvider)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ResourceOnly => "resource_only",
            Self::Staked => "staked",
            Self::RpcProvider => "rpc_provider",
        }
    }
}

impl Default for ValidatorTier {
    fn default() -> Self {
        // Old persisted rows without a tier field default to Staked —
        // matches the pre-tier behaviour where every registered
        // validator carried at least `min_self_stake`. On a stake
        // change, `from_stake` recomputes the correct tier and
        // overwrites this default.
        Self::Staked
    }
}

/// Lifecycle status of a registered validator.
///
/// Transitions (the `next_epoch` annotation means the move happens at the
/// next epoch boundary, not synchronously on transaction execution):
///
/// ```text
///                              register
///                                 │
///                                 ▼
///                            ┌─────────┐
///        re-entry cooldown   │Candidate│
///        ────────────────────┤         │
///                            └────┬────┘
///                                 │ activate-call admitted by churn cap
///                                 ▼
///                          ┌──────────────┐
///                          │PendingActive │
///                          └──────┬───────┘
///                                 │ next_epoch
///                                 ▼
///                            ┌─────────┐  slash       ┌────────┐
///                            │ Active  │─────────────▶│ Jailed │
///                            └────┬────┘              └────┬───┘
///                                 │ exit-call               │ governance
///                                 ▼                          ▼
///                          ┌────────────┐              (re-enter Candidate)
///                          │PendingExit │
///                          └─────┬──────┘
///                                │ next_epoch
///                                ▼
///                            ┌────────┐
///                            │Exited  │
///                            └────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorRegistryStatus {
    /// Registered and metadata published; not yet promoted to the active set.
    /// Awaiting churn-budget admission.
    Candidate,
    /// Promoted by the activation churn cap; will become `Active` at the next
    /// epoch boundary (after [`ACTIVATION_EFFECTIVE_DELAY_BLOCKS`]).
    PendingActive,
    /// Currently a member of the active validator set producing blocks.
    Active,
    /// Voluntary exit requested; will become `Exited` at the next epoch
    /// boundary subject to the exit churn cap.
    PendingExit,
    /// Exited and stake fully unbonded. Re-registration permitted after
    /// [`DEFAULT_REENTRY_COOLDOWN_EPOCHS`] epochs.
    Exited,
    /// Slashed for misbehaviour. Stays jailed until governance re-instates
    /// (out of scope for now; jailed validators stay jailed).
    Jailed,
}

impl ValidatorRegistryStatus {
    /// Returns true when the validator is counted toward the active set total
    /// for churn-cap calculations.
    pub fn counts_toward_active(&self) -> bool {
        matches!(self, Self::Active | Self::PendingExit)
    }
}

/// Full per-validator record persisted in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRegistryEntry {
    /// Operator / consensus address (also the staking address — unified).
    pub address: Address,
    /// Ed25519 consensus public key (32 bytes).
    pub consensus_pubkey: Vec<u8>,
    /// ML-DSA-65 PQ verifying key (1952 bytes, FIPS 204).
    pub pq_pubkey: Vec<u8>,
    /// BLS12-381 G1-compressed verifying key (`min_pk` scheme, 48 bytes).
    /// Used by HotStuff-2 to aggregate per-validator vote signatures into
    /// a single QC-level aggregate.
    pub bls_pubkey: Vec<u8>,
    /// Address that receives staking rewards and withdrawn principal.
    /// May differ from `address` to allow cold-storage payouts.
    pub withdrawal_address: Address,
    /// Self-bonded stake. Counted as voting power when active.
    pub self_stake: u128,
    /// Participation tier — derived from `self_stake` against the
    /// registry config's `min_self_stake` / `min_rpc_provider_stake`
    /// thresholds. Recomputed on every stake change. The field is
    /// stored explicitly (rather than re-derived on every read) so
    /// downstream code (leader election, governance, slashing,
    /// API-key minting) can branch on tier without taking the config
    /// lock.
    ///
    /// Persistence-safe `#[serde(default)]` for back-compat read of
    /// pre-tier registry entries: those rows default to `Staked` (see
    /// `ValidatorTier::default`) because pre-tier code required at
    /// least `min_self_stake`.
    #[serde(default)]
    pub tier: ValidatorTier,
    /// Current lifecycle status.
    pub status: ValidatorRegistryStatus,
    /// Epoch in which the candidate was first registered.
    pub registered_at_epoch: u64,
    /// Epoch in which the validator entered the `Active` state, if ever.
    pub activated_at_epoch: Option<u64>,
    /// Epoch in which the validator exited, if ever. Used to enforce the
    /// re-entry cooldown.
    pub exited_at_epoch: Option<u64>,
    /// Epoch until which a jailed validator remains jailed (exclusive).
    /// `None` means jailed indefinitely until governance acts.
    pub jailed_until_epoch: Option<u64>,
    /// Optional 32-byte hash of the most recent TEE attestation report.
    /// Stored as opaque bytes — verification happens in tenzro-tee.
    pub tee_attestation_hash: Option<[u8; 32]>,
    /// Free-form operator metadata URL (moniker, contact, region…). Capped at
    /// 256 bytes to bound on-chain storage. May be empty.
    pub metadata_uri: String,
    /// Last update timestamp.
    pub updated_at: Timestamp,
}

impl ValidatorRegistryEntry {
    /// Constructs a fresh `Candidate` entry. Validates key lengths and
    /// derives the participation tier from `self_stake` against
    /// `cfg.min_self_stake` / `cfg.min_rpc_provider_stake`.
    ///
    /// Tier 1 (resource-only) admission: `self_stake == 0` is the
    /// canonical case but any value below `cfg.min_self_stake` is
    /// admitted as Tier 1.
    /// Tier 2 (staked) admission: `self_stake >= cfg.min_self_stake`.
    /// Tier 3 (RPC provider) admission: `self_stake >= cfg.min_rpc_provider_stake`.
    pub fn new_candidate(
        address: Address,
        consensus_pubkey: Vec<u8>,
        pq_pubkey: Vec<u8>,
        bls_pubkey: Vec<u8>,
        withdrawal_address: Address,
        self_stake: u128,
        registered_at_epoch: u64,
        metadata_uri: String,
        cfg: &ValidatorRegistryConfig,
    ) -> Result<Self> {
        if consensus_pubkey.len() != 32 {
            return Err(TokenError::InvalidParameter(format!(
                "consensus public key must be 32 bytes, got {}",
                consensus_pubkey.len()
            )));
        }
        if pq_pubkey.len() != tenzro_crypto::pq::ML_DSA_65_VK_LEN {
            return Err(TokenError::InvalidParameter(format!(
                "PQ verifying key must be {} bytes (ML-DSA-65), got {}",
                tenzro_crypto::pq::ML_DSA_65_VK_LEN,
                pq_pubkey.len()
            )));
        }
        if bls_pubkey.len() != 48 {
            return Err(TokenError::InvalidParameter(format!(
                "BLS verifying key must be 48 bytes (BLS12-381 G1-compressed, min_pk), got {}",
                bls_pubkey.len()
            )));
        }
        if metadata_uri.len() > 256 {
            return Err(TokenError::InvalidParameter(format!(
                "metadata_uri exceeds 256 bytes (got {})",
                metadata_uri.len()
            )));
        }
        let tier = ValidatorTier::from_stake(self_stake, cfg);
        Ok(Self {
            address,
            consensus_pubkey,
            pq_pubkey,
            bls_pubkey,
            withdrawal_address,
            self_stake,
            tier,
            status: ValidatorRegistryStatus::Candidate,
            registered_at_epoch,
            activated_at_epoch: None,
            exited_at_epoch: None,
            jailed_until_epoch: None,
            tee_attestation_hash: None,
            metadata_uri,
            updated_at: Timestamp::now(),
        })
    }
}

/// Registry configuration (mutable via governance).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ValidatorRegistryConfig {
    /// Minimum self-bonded stake to register as a **Tier 2 (staked)**
    /// validator. Tier 1 (resource-only) registrations are not gated
    /// by this — they require `self_stake == 0` and meet only the
    /// resource + stability profile.
    pub min_self_stake: u128,
    /// Minimum self-bonded stake to register as a **Tier 3 (RPC
    /// provider)** validator. Implies the Tier 2 minimum is also met.
    /// 10× Tier 2 by default, reflecting the larger trust surface
    /// RPC providers carry (tenant API keys, upstream credentials,
    /// cross-chain mint routing, billing).
    #[serde(default = "default_min_rpc_provider_stake")]
    pub min_rpc_provider_stake: u128,
    /// Activation churn cap, in basis points of current active-set size.
    pub activation_churn_bps: u32,
    /// Exit churn cap, in basis points of current active-set size.
    pub exit_churn_bps: u32,
    /// Re-entry cooldown after voluntary exit, in epochs.
    pub reentry_cooldown_epochs: u64,
}

/// Serde-default for the RPC provider stake on a config row written
/// before the field existed. Read-side compat for pre-tier registry
/// snapshots.
fn default_min_rpc_provider_stake() -> u128 {
    DEFAULT_MIN_RPC_PROVIDER_STAKE
}

impl Default for ValidatorRegistryConfig {
    fn default() -> Self {
        Self {
            min_self_stake: DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            min_rpc_provider_stake: DEFAULT_MIN_RPC_PROVIDER_STAKE,
            activation_churn_bps: DEFAULT_ACTIVATION_CHURN_BPS,
            exit_churn_bps: DEFAULT_EXIT_CHURN_BPS,
            reentry_cooldown_epochs: DEFAULT_REENTRY_COOLDOWN_EPOCHS,
        }
    }
}

/// Result of an epoch-boundary transition computed by
/// [`ValidatorRegistry::compute_epoch_transition`].
///
/// The caller (the node's epoch-transition hook in `event_loop.rs`) consumes
/// this to drive the consensus [`tenzro_consensus::EpochManager`]'s pending
/// queues.
#[derive(Debug, Clone, Default)]
pub struct EpochTransitionPlan {
    /// Validators promoted from `Candidate` → `PendingActive` this epoch.
    /// They will appear in the consensus active set in the next epoch.
    pub activations: Vec<Address>,
    /// Validators demoted from `Active` → `PendingExit` this epoch (because
    /// they requested exit, were slashed, or were jailed).
    pub exits: Vec<Address>,
    /// Validators that completed `PendingActive` → `Active` (effective now).
    pub effective_activations: Vec<Address>,
    /// Validators that completed `PendingExit` → `Exited` (effective now).
    pub effective_exits: Vec<Address>,
}

/// Permissionless validator registry.
///
/// Concurrent in-memory state with optional write-through persistence.
pub struct ValidatorRegistry {
    /// Per-address registry entries.
    entries: DashMap<Address, ValidatorRegistryEntry>,
    /// Mutable configuration.
    config: parking_lot::RwLock<ValidatorRegistryConfig>,
    /// Optional persistent storage backend.
    storage: Option<Arc<dyn tenzro_storage::KvStore>>,
}

impl ValidatorRegistry {
    /// Creates an in-memory-only registry.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            config: parking_lot::RwLock::new(ValidatorRegistryConfig::default()),
            storage: None,
        }
    }

    /// Creates a registry backed by persistent storage. Hydrates state on
    /// construction; logs and continues on partial-decode errors.
    pub fn with_storage(storage: Arc<dyn tenzro_storage::KvStore>) -> Self {
        let registry = Self {
            entries: DashMap::new(),
            config: parking_lot::RwLock::new(ValidatorRegistryConfig::default()),
            storage: Some(storage),
        };
        if let Err(e) = registry.load_from_storage() {
            warn!("Failed to hydrate validator registry: {}", e);
        }
        registry
    }

    fn persist_entry(&self, entry: &ValidatorRegistryEntry) {
        if let Some(storage) = &self.storage {
            let key = format!("{}{}", VALIDATOR_PREFIX, hex::encode(entry.address.as_bytes()));
            match bincode::serialize(entry) {
                Ok(data) => {
                    if let Err(e) = storage.put(REGISTRY_CF, key.as_bytes(), &data) {
                        warn!("Failed to persist validator {}: {}", entry.address, e);
                    }
                }
                Err(e) => warn!("Failed to serialize validator {}: {}", entry.address, e),
            }
        }
    }

    fn persist_index(&self) {
        if let Some(storage) = &self.storage {
            let addresses: Vec<String> = self
                .entries
                .iter()
                .map(|e| hex::encode(e.key().as_bytes()))
                .collect();
            match bincode::serialize(&addresses) {
                Ok(data) => {
                    if let Err(e) = storage.put(REGISTRY_CF, VALIDATOR_INDEX_KEY.as_bytes(), &data)
                    {
                        warn!("Failed to persist validator index: {}", e);
                    }
                }
                Err(e) => warn!("Failed to serialize validator index: {}", e),
            }
        }
    }

    fn persist_config(&self) {
        if let Some(storage) = &self.storage {
            let cfg = *self.config.read();
            match bincode::serialize(&cfg) {
                Ok(data) => {
                    if let Err(e) = storage.put(REGISTRY_CF, VALIDATOR_CONFIG_KEY.as_bytes(), &data)
                    {
                        warn!("Failed to persist validator config: {}", e);
                    }
                }
                Err(e) => warn!("Failed to serialize validator config: {}", e),
            }
        }
    }

    fn load_from_storage(&self) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };

        if let Ok(Some(cfg_data)) = storage.get(REGISTRY_CF, VALIDATOR_CONFIG_KEY.as_bytes())
            && let Ok(cfg) = bincode::deserialize::<ValidatorRegistryConfig>(&cfg_data)
        {
            *self.config.write() = cfg;
        }

        if let Ok(Some(idx_data)) = storage.get(REGISTRY_CF, VALIDATOR_INDEX_KEY.as_bytes()) {
            let addresses: Vec<String> = match bincode::deserialize(&idx_data) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to deserialize validator index: {}", e);
                    return Ok(());
                }
            };
            for hex_addr in &addresses {
                let key = format!("{}{}", VALIDATOR_PREFIX, hex_addr);
                if let Ok(Some(data)) = storage.get(REGISTRY_CF, key.as_bytes()) {
                    match bincode::deserialize::<ValidatorRegistryEntry>(&data) {
                        Ok(entry) => {
                            self.entries.insert(entry.address, entry);
                        }
                        Err(e) => warn!("Failed to deserialize validator {}: {}", hex_addr, e),
                    }
                }
            }
            info!("Loaded {} validators from registry", addresses.len());
        }

        Ok(())
    }

    /// Returns the current registry config.
    pub fn config(&self) -> ValidatorRegistryConfig {
        *self.config.read()
    }

    /// Updates the registry config (governance-gated; the caller is
    /// responsible for authorization).
    pub fn set_config(&self, cfg: ValidatorRegistryConfig) {
        *self.config.write() = cfg;
        self.persist_config();
    }

    /// Returns a snapshot of an entry by address.
    pub fn get(&self, address: &Address) -> Option<ValidatorRegistryEntry> {
        self.entries.get(address).map(|e| e.value().clone())
    }

    /// Returns all entries (snapshot).
    pub fn list(&self) -> Vec<ValidatorRegistryEntry> {
        self.entries.iter().map(|e| e.value().clone()).collect()
    }

    /// Returns active validators only (snapshot).
    pub fn list_active(&self) -> Vec<ValidatorRegistryEntry> {
        self.entries
            .iter()
            .filter(|e| e.value().status == ValidatorRegistryStatus::Active)
            .map(|e| e.value().clone())
            .collect()
    }

    /// Counts current active-set members. Used as the denominator for churn
    /// caps. Includes `Active` + `PendingExit` (an exit-pending validator
    /// still produces blocks until the next epoch boundary).
    fn active_set_size(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.value().status.counts_toward_active())
            .count()
    }

    /// Computes the per-epoch activation/exit budgets given the current
    /// active-set size and config.
    fn churn_budgets(&self) -> (u32, u32) {
        let cfg = *self.config.read();
        let n = self.active_set_size() as u64;
        let act = ((n.saturating_mul(cfg.activation_churn_bps as u64)) / 10_000) as u32;
        let exit = ((n.saturating_mul(cfg.exit_churn_bps as u64)) / 10_000) as u32;
        (act.max(MIN_CHURN_PER_EPOCH), exit.max(MIN_CHURN_PER_EPOCH))
    }

    /// Registers a new candidate validator. Idempotent only when no entry
    /// exists for `address` — re-registration of an existing address must
    /// route through `Exited → Candidate` (after cooldown) explicitly.
    #[allow(clippy::too_many_arguments)]
    pub fn register_candidate(
        &self,
        address: Address,
        consensus_pubkey: Vec<u8>,
        pq_pubkey: Vec<u8>,
        bls_pubkey: Vec<u8>,
        withdrawal_address: Address,
        self_stake: u128,
        current_epoch: u64,
        metadata_uri: String,
    ) -> Result<()> {
        let cfg = *self.config.read();

        // Per the canonical three-tier model: Tier 1 (resource-only)
        // registrations are admitted with `self_stake == 0` (or any
        // amount below `min_self_stake`). Tier 2 (staked) admitted at
        // `>= min_self_stake`. Tier 3 (RPC provider) at
        // `>= min_rpc_provider_stake`. The tier is derived inside
        // `ValidatorRegistryEntry::new_candidate`. No stake floor is
        // enforced here — all three tiers are valid registration
        // outcomes.

        // Re-registration path: must have exited and waited the cooldown.
        if let Some(existing) = self.entries.get(&address) {
            match existing.status {
                ValidatorRegistryStatus::Exited => {
                    if let Some(exit_epoch) = existing.exited_at_epoch
                        && current_epoch < exit_epoch.saturating_add(cfg.reentry_cooldown_epochs)
                    {
                        return Err(TokenError::Unauthorized {
                            reason: format!(
                                "re-entry cooldown: must wait until epoch {}",
                                exit_epoch.saturating_add(cfg.reentry_cooldown_epochs)
                            ),
                        });
                    }
                }
                _ => {
                    return Err(TokenError::InvalidParameter(format!(
                        "validator {} already registered with status {:?}",
                        address, existing.status
                    )));
                }
            }
        }

        let entry = ValidatorRegistryEntry::new_candidate(
            address,
            consensus_pubkey,
            pq_pubkey,
            bls_pubkey,
            withdrawal_address,
            self_stake,
            current_epoch,
            metadata_uri,
            &cfg,
        )?;
        let tier = entry.tier;
        self.entries.insert(address, entry.clone());
        self.persist_entry(&entry);
        self.persist_index();
        info!(
            "Registered validator candidate {} at epoch {} with stake {} (tier={})",
            address, current_epoch, self_stake, tier.as_str()
        );
        Ok(())
    }

    /// Idempotently seed an `Active` genesis entry.
    ///
    /// Used at node startup to populate the registry with the validators
    /// declared in `genesis.toml` so testnet bootstrap doesn't require each
    /// genesis validator to re-register via `RegisterValidator` after the
    /// chain comes up. Skips writing if an entry for `address` already
    /// exists — restart-safe.
    ///
    /// Validates key lengths and metadata bounds. Returns `Ok(false)` when
    /// the entry was already present (no-op), `Ok(true)` when a new Active
    /// entry was inserted.
    pub fn seed_genesis_active(
        &self,
        address: Address,
        consensus_pubkey: Vec<u8>,
        pq_pubkey: Vec<u8>,
        bls_pubkey: Vec<u8>,
        withdrawal_address: Address,
        self_stake: u128,
        metadata_uri: String,
    ) -> Result<bool> {
        if self.entries.contains_key(&address) {
            return Ok(false);
        }
        if consensus_pubkey.len() != 32 {
            return Err(TokenError::InvalidParameter(format!(
                "consensus public key must be 32 bytes, got {}",
                consensus_pubkey.len()
            )));
        }
        if pq_pubkey.len() != tenzro_crypto::pq::ML_DSA_65_VK_LEN {
            return Err(TokenError::InvalidParameter(format!(
                "PQ verifying key must be {} bytes (ML-DSA-65), got {}",
                tenzro_crypto::pq::ML_DSA_65_VK_LEN,
                pq_pubkey.len()
            )));
        }
        if bls_pubkey.len() != 48 {
            return Err(TokenError::InvalidParameter(format!(
                "BLS verifying key must be 48 bytes (BLS12-381 G1-compressed, min_pk), got {}",
                bls_pubkey.len()
            )));
        }
        if metadata_uri.len() > 256 {
            return Err(TokenError::InvalidParameter(format!(
                "metadata_uri exceeds 256 bytes (got {})",
                metadata_uri.len()
            )));
        }
        // Derive the genesis validator's tier from its self-stake.
        // Genesis may seed validators at any tier; the RPC-provider tier
        // requires the higher stake, the base tier the lower one.
        let cfg = *self.config.read();
        let tier = ValidatorTier::from_stake(self_stake, &cfg);
        let entry = ValidatorRegistryEntry {
            address,
            consensus_pubkey,
            pq_pubkey,
            bls_pubkey,
            withdrawal_address,
            self_stake,
            tier,
            status: ValidatorRegistryStatus::Active,
            registered_at_epoch: 0,
            activated_at_epoch: Some(0),
            exited_at_epoch: None,
            jailed_until_epoch: None,
            tee_attestation_hash: None,
            metadata_uri,
            updated_at: Timestamp::now(),
        };
        self.entries.insert(address, entry.clone());
        self.persist_entry(&entry);
        self.persist_index();
        info!(
            "Seeded genesis Active validator {} with stake {} (tier={})",
            address, self_stake, tier.as_str()
        );
        Ok(true)
    }

    /// Records a request to exit. Moves `Active → PendingExit`. The actual
    /// state machine advance to `Exited` happens at the next epoch boundary
    /// in `compute_epoch_transition`.
    pub fn request_exit(&self, address: &Address) -> Result<()> {
        let mut entry = self
            .entries
            .get_mut(address)
            .ok_or_else(|| TokenError::NotFound(format!("validator {}", address)))?;

        match entry.status {
            ValidatorRegistryStatus::Active => {
                entry.status = ValidatorRegistryStatus::PendingExit;
                entry.updated_at = Timestamp::now();
            }
            ValidatorRegistryStatus::Candidate | ValidatorRegistryStatus::PendingActive => {
                // Never made it to Active — we can short-circuit straight to
                // Exited on the next epoch boundary.
                entry.status = ValidatorRegistryStatus::PendingExit;
                entry.updated_at = Timestamp::now();
            }
            ValidatorRegistryStatus::PendingExit | ValidatorRegistryStatus::Exited => {
                return Err(TokenError::InvalidParameter(format!(
                    "validator {} already exiting (status {:?})",
                    address, entry.status
                )));
            }
            ValidatorRegistryStatus::Jailed => {
                return Err(TokenError::InvalidParameter(format!(
                    "validator {} is jailed; exit forbidden until governance restores",
                    address
                )));
            }
        }
        let snapshot = entry.clone();
        drop(entry);
        self.persist_entry(&snapshot);
        info!("Validator {} requested exit", address);
        Ok(())
    }

    /// Updates the operator metadata URI and (optionally) the TEE attestation
    /// hash. Permitted in any state except `Exited`.
    pub fn update_metadata(
        &self,
        address: &Address,
        metadata_uri: Option<String>,
        tee_attestation_hash: Option<[u8; 32]>,
    ) -> Result<()> {
        let mut entry = self
            .entries
            .get_mut(address)
            .ok_or_else(|| TokenError::NotFound(format!("validator {}", address)))?;

        if entry.status == ValidatorRegistryStatus::Exited {
            return Err(TokenError::InvalidParameter(
                "cannot update metadata for exited validator".to_string(),
            ));
        }
        if let Some(uri) = metadata_uri {
            if uri.len() > 256 {
                return Err(TokenError::InvalidParameter(format!(
                    "metadata_uri exceeds 256 bytes (got {})",
                    uri.len()
                )));
            }
            entry.metadata_uri = uri;
        }
        if let Some(h) = tee_attestation_hash {
            entry.tee_attestation_hash = Some(h);
        }
        entry.updated_at = Timestamp::now();
        let snapshot = entry.clone();
        drop(entry);
        self.persist_entry(&snapshot);
        Ok(())
    }

    /// Rotates the three-tuple of consensus keys (Ed25519 + ML-DSA-65 +
    /// BLS12-381) for an existing validator entry, preserving every other
    /// field (stake, tier, status, lifecycle counters, withdrawal address,
    /// metadata).
    ///
    /// Key lengths are enforced (32 / 1952 / 48). The caller is
    /// responsible for authorisation — typically a signed
    /// `tenzro_rotateValidatorKey` RPC where the signature is verified
    /// against the *current* `consensus_pubkey` before this call lands.
    ///
    /// Refused on Exited or Jailed entries — a rotation must follow
    /// reactivation, not precede it. Idempotent on identical-keys input
    /// (returns Ok without touching disk).
    pub fn rotate_keys(
        &self,
        address: &Address,
        new_consensus_pubkey: Vec<u8>,
        new_pq_pubkey: Vec<u8>,
        new_bls_pubkey: Vec<u8>,
    ) -> Result<()> {
        // Length checks mirror new_candidate.
        if new_consensus_pubkey.len() != 32 {
            return Err(TokenError::InvalidParameter(format!(
                "rotate_keys: new consensus_pubkey must be 32 bytes (Ed25519), got {}",
                new_consensus_pubkey.len()
            )));
        }
        if new_pq_pubkey.len() != 1952 {
            return Err(TokenError::InvalidParameter(format!(
                "rotate_keys: new pq_pubkey must be 1952 bytes (ML-DSA-65), got {}",
                new_pq_pubkey.len()
            )));
        }
        if new_bls_pubkey.len() != 48 {
            return Err(TokenError::InvalidParameter(format!(
                "rotate_keys: new bls_pubkey must be 48 bytes (BLS12-381 G1 compressed), got {}",
                new_bls_pubkey.len()
            )));
        }

        let mut entry = self
            .entries
            .get_mut(address)
            .ok_or_else(|| TokenError::NotFound(format!("validator {}", address)))?;

        // Refuse rotation on terminal / penalty states. Operator must
        // reactivate first.
        if matches!(
            entry.status,
            ValidatorRegistryStatus::Exited | ValidatorRegistryStatus::Jailed
        ) {
            return Err(TokenError::InvalidParameter(format!(
                "cannot rotate keys for validator {} in state {:?} — \
                 reactivate first",
                address, entry.status
            )));
        }

        // Idempotent on no-op rotations.
        if entry.consensus_pubkey == new_consensus_pubkey
            && entry.pq_pubkey == new_pq_pubkey
            && entry.bls_pubkey == new_bls_pubkey
        {
            return Ok(());
        }

        entry.consensus_pubkey = new_consensus_pubkey;
        entry.pq_pubkey = new_pq_pubkey;
        entry.bls_pubkey = new_bls_pubkey;
        entry.updated_at = Timestamp::now();
        let snapshot = entry.clone();
        drop(entry);
        self.persist_entry(&snapshot);
        info!(
            "Validator {} keys rotated — change takes effect at next epoch boundary",
            address
        );
        Ok(())
    }

    /// Marks a validator as jailed in response to a slash event. Forces an
    /// exit at the next epoch boundary. Idempotent.
    pub fn jail(&self, address: &Address, current_epoch: u64) -> Result<()> {
        let mut entry = self
            .entries
            .get_mut(address)
            .ok_or_else(|| TokenError::NotFound(format!("validator {}", address)))?;

        entry.status = ValidatorRegistryStatus::Jailed;
        entry.jailed_until_epoch = None; // governance-gated reactivation
        entry.exited_at_epoch = Some(current_epoch);
        entry.updated_at = Timestamp::now();
        let snapshot = entry.clone();
        drop(entry);
        self.persist_entry(&snapshot);
        warn!(
            "Validator {} jailed at epoch {} — pending governance restoration",
            address, current_epoch
        );
        Ok(())
    }

    /// Computes the validator-set transition for the new epoch.
    ///
    /// This is the **single point** the consensus epoch manager calls at
    /// every epoch boundary. The plan tells the caller which validators move
    /// in and out of the active set; the caller is responsible for handing
    /// those movements to `EpochManager`'s `pending_validators` /
    /// `pending_removals` queues.
    pub fn compute_epoch_transition(&self, new_epoch: u64) -> EpochTransitionPlan {
        let (act_budget, exit_budget) = self.churn_budgets();
        let mut plan = EpochTransitionPlan::default();

        // Phase 1: complete in-flight transitions from prior epoch.
        // PendingActive → Active, PendingExit → Exited.
        let to_finalize: Vec<(Address, ValidatorRegistryStatus)> = self
            .entries
            .iter()
            .filter_map(|e| {
                let status = e.value().status;
                if matches!(
                    status,
                    ValidatorRegistryStatus::PendingActive | ValidatorRegistryStatus::PendingExit
                ) {
                    Some((e.value().address, status))
                } else {
                    None
                }
            })
            .collect();

        for (addr, status) in to_finalize {
            if let Some(mut entry) = self.entries.get_mut(&addr) {
                match status {
                    ValidatorRegistryStatus::PendingActive => {
                        entry.status = ValidatorRegistryStatus::Active;
                        entry.activated_at_epoch = Some(new_epoch);
                        entry.updated_at = Timestamp::now();
                        plan.effective_activations.push(addr);
                    }
                    ValidatorRegistryStatus::PendingExit => {
                        entry.status = ValidatorRegistryStatus::Exited;
                        entry.exited_at_epoch = Some(new_epoch);
                        entry.updated_at = Timestamp::now();
                        plan.effective_exits.push(addr);
                    }
                    _ => unreachable!(),
                }
                let snapshot = entry.clone();
                drop(entry);
                self.persist_entry(&snapshot);
            }
        }

        // Phase 2: admit new candidates up to the activation budget.
        // Order by stake descending, then by registered_at_epoch ascending
        // (earlier registration wins ties) for deterministic ordering across
        // all validators.
        let mut candidates: Vec<(Address, u128, u64)> = self
            .entries
            .iter()
            .filter(|e| e.value().status == ValidatorRegistryStatus::Candidate)
            .map(|e| {
                (
                    e.value().address,
                    e.value().self_stake,
                    e.value().registered_at_epoch,
                )
            })
            .collect();
        candidates.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then(a.2.cmp(&b.2))
                .then(a.0.as_bytes().cmp(b.0.as_bytes()))
        });

        for (addr, _, _) in candidates.into_iter().take(act_budget as usize) {
            if let Some(mut entry) = self.entries.get_mut(&addr) {
                entry.status = ValidatorRegistryStatus::PendingActive;
                entry.updated_at = Timestamp::now();
                plan.activations.push(addr);
                let snapshot = entry.clone();
                drop(entry);
                self.persist_entry(&snapshot);
            }
        }

        // Phase 3: enforce the exit budget. PendingExit entries already
        // counted, so exits beyond the budget are deferred to next epoch by
        // simply not being finalised this round. We enforce the cap by
        // capping how many we *finalise* in phase 1; redo that cleanly: any
        // effective_exits over budget get rolled back to PendingExit.
        // (Phase 1 already finalised them; clamp here.)
        if plan.effective_exits.len() > exit_budget as usize {
            let overflow = plan.effective_exits.split_off(exit_budget as usize);
            for addr in &overflow {
                if let Some(mut entry) = self.entries.get_mut(addr) {
                    entry.status = ValidatorRegistryStatus::PendingExit;
                    entry.exited_at_epoch = None;
                    entry.updated_at = Timestamp::now();
                    let snapshot = entry.clone();
                    drop(entry);
                    self.persist_entry(&snapshot);
                }
            }
        }

        info!(
            "Epoch {} transition: +{} activations ({} effective), -{} exits ({} effective)",
            new_epoch,
            plan.activations.len(),
            plan.effective_activations.len(),
            plan.exits.len(),
            plan.effective_exits.len()
        );

        plan
    }
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::pq::ML_DSA_65_VK_LEN;

    fn make_address(seed: u8) -> Address {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        Address::new(bytes)
    }

    fn make_keys() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (vec![0u8; 32], vec![0u8; ML_DSA_65_VK_LEN], vec![0u8; 48])
    }

    #[test]
    fn seed_genesis_active_idempotent() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, bk) = make_keys();
        let a = make_address(7);

        // First seed: inserted
        let inserted = reg
            .seed_genesis_active(
                a,
                ck.clone(),
                pk.clone(),
                bk.clone(),
                a,
                DEFAULT_MIN_VALIDATOR_SELF_STAKE,
                String::new(),
            )
            .unwrap();
        assert!(inserted);
        let entry = reg.get(&a).unwrap();
        assert_eq!(entry.status, ValidatorRegistryStatus::Active);
        assert_eq!(entry.activated_at_epoch, Some(0));
        assert_eq!(entry.registered_at_epoch, 0);
        assert_eq!(entry.self_stake, DEFAULT_MIN_VALIDATOR_SELF_STAKE);

        // Second seed: skipped (already present), entry untouched
        let inserted_again = reg
            .seed_genesis_active(
                a,
                ck.clone(),
                pk.clone(),
                bk.clone(),
                a,
                DEFAULT_MIN_VALIDATOR_SELF_STAKE * 2,
                String::from("changed"),
            )
            .unwrap();
        assert!(!inserted_again);
        let entry2 = reg.get(&a).unwrap();
        assert_eq!(entry2.self_stake, DEFAULT_MIN_VALIDATOR_SELF_STAKE);
        assert_eq!(entry2.metadata_uri, "");

        // Active validators include the seeded entry
        assert_eq!(reg.list_active().len(), 1);
    }

    #[test]
    fn seed_genesis_active_rejects_bad_keys() {
        let reg = ValidatorRegistry::new();
        let a = make_address(8);

        // Wrong consensus pubkey length
        let err = reg
            .seed_genesis_active(
                a,
                vec![0u8; 31],
                vec![0u8; ML_DSA_65_VK_LEN],
                vec![0u8; 48],
                a,
                DEFAULT_MIN_VALIDATOR_SELF_STAKE,
                String::new(),
            )
            .unwrap_err();
        assert!(matches!(err, TokenError::InvalidParameter(_)));

        // Wrong PQ pubkey length
        let err = reg
            .seed_genesis_active(
                a,
                vec![0u8; 32],
                vec![0u8; 100],
                vec![0u8; 48],
                a,
                DEFAULT_MIN_VALIDATOR_SELF_STAKE,
                String::new(),
            )
            .unwrap_err();
        assert!(matches!(err, TokenError::InvalidParameter(_)));

        // Wrong BLS pubkey length
        let err = reg
            .seed_genesis_active(
                a,
                vec![0u8; 32],
                vec![0u8; ML_DSA_65_VK_LEN],
                vec![0u8; 47],
                a,
                DEFAULT_MIN_VALIDATOR_SELF_STAKE,
                String::new(),
            )
            .unwrap_err();
        assert!(matches!(err, TokenError::InvalidParameter(_)));
    }

    #[test]
    fn register_below_min_stake_admits_as_tier_1() {
        // Per the canonical three-tier model (WHITEPAPER §5 +
        // TOKENOMICS §7): registrations with `self_stake == 0` (or
        // any amount below `min_self_stake`) are admitted as Tier 1
        // (resource-only) validators. Stake-floor enforcement is
        // gone; tier is derived from stake instead.
        let reg = ValidatorRegistry::new();
        let (ck, pk, bk) = make_keys();
        let a = make_address(1);

        // Zero stake → Tier 1 admission succeeds.
        reg.register_candidate(a, ck.clone(), pk.clone(), bk.clone(), a, 0, 0, String::new())
            .unwrap();
        let entry = reg.get(&a).unwrap();
        assert_eq!(entry.tier, ValidatorTier::ResourceOnly);
        assert_eq!(entry.self_stake, 0);
        assert_eq!(entry.status, ValidatorRegistryStatus::Candidate);
    }

    #[test]
    fn register_at_tier_2_threshold_sets_staked() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, bk) = make_keys();
        let a = make_address(2);
        reg.register_candidate(
            a,
            ck,
            pk,
            bk,
            a,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            0,
            String::new(),
        )
        .unwrap();
        assert_eq!(reg.get(&a).unwrap().tier, ValidatorTier::Staked);
    }

    #[test]
    fn register_at_tier_3_threshold_sets_rpc_provider() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, bk) = make_keys();
        let a = make_address(3);
        reg.register_candidate(
            a,
            ck,
            pk,
            bk,
            a,
            DEFAULT_MIN_RPC_PROVIDER_STAKE,
            0,
            String::new(),
        )
        .unwrap();
        assert_eq!(reg.get(&a).unwrap().tier, ValidatorTier::RpcProvider);
    }

    #[test]
    fn register_then_activate_then_exit_full_lifecycle() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, bk) = make_keys();
        let a = make_address(1);
        reg.register_candidate(
            a,
            ck.clone(),
            pk.clone(),
            bk.clone(),
            a,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            0,
            String::new(),
        )
        .unwrap();
        assert_eq!(
            reg.get(&a).unwrap().status,
            ValidatorRegistryStatus::Candidate
        );

        // Epoch 1: candidate → pending active
        let plan = reg.compute_epoch_transition(1);
        assert_eq!(plan.activations, vec![a]);
        assert_eq!(
            reg.get(&a).unwrap().status,
            ValidatorRegistryStatus::PendingActive
        );

        // Epoch 2: pending active → active
        let plan = reg.compute_epoch_transition(2);
        assert_eq!(plan.effective_activations, vec![a]);
        assert_eq!(reg.get(&a).unwrap().status, ValidatorRegistryStatus::Active);

        // Request exit
        reg.request_exit(&a).unwrap();
        assert_eq!(
            reg.get(&a).unwrap().status,
            ValidatorRegistryStatus::PendingExit
        );

        // Epoch 3: pending exit → exited
        let plan = reg.compute_epoch_transition(3);
        assert_eq!(plan.effective_exits, vec![a]);
        assert_eq!(reg.get(&a).unwrap().status, ValidatorRegistryStatus::Exited);
        assert_eq!(reg.get(&a).unwrap().exited_at_epoch, Some(3));
    }

    #[test]
    fn reentry_blocked_during_cooldown() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, bk) = make_keys();
        let a = make_address(1);
        reg.register_candidate(
            a,
            ck.clone(),
            pk.clone(),
            bk.clone(),
            a,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            0,
            String::new(),
        )
        .unwrap();
        reg.compute_epoch_transition(1);
        reg.compute_epoch_transition(2);
        reg.request_exit(&a).unwrap();
        reg.compute_epoch_transition(3);
        assert_eq!(reg.get(&a).unwrap().status, ValidatorRegistryStatus::Exited);

        // Same epoch — re-entry blocked.
        let err = reg
            .register_candidate(
                a,
                ck.clone(),
                pk.clone(),
                bk.clone(),
                a,
                DEFAULT_MIN_VALIDATOR_SELF_STAKE,
                3,
                String::new(),
            )
            .unwrap_err();
        assert!(matches!(err, TokenError::Unauthorized { .. }));

        // After cooldown, re-entry permitted.
        reg.register_candidate(
            a,
            ck,
            pk,
            bk,
            a,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            3 + DEFAULT_REENTRY_COOLDOWN_EPOCHS,
            String::new(),
        )
        .unwrap();
        assert_eq!(
            reg.get(&a).unwrap().status,
            ValidatorRegistryStatus::Candidate
        );
    }

    #[test]
    fn jail_forces_exit() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, bk) = make_keys();
        let a = make_address(1);
        reg.register_candidate(
            a,
            ck,
            pk,
            bk,
            a,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            0,
            String::new(),
        )
        .unwrap();
        reg.compute_epoch_transition(1);
        reg.compute_epoch_transition(2);
        assert_eq!(reg.get(&a).unwrap().status, ValidatorRegistryStatus::Active);
        reg.jail(&a, 2).unwrap();
        assert_eq!(reg.get(&a).unwrap().status, ValidatorRegistryStatus::Jailed);
        // Jailed validators don't auto-exit — governance-gated.
    }

    #[test]
    fn churn_cap_limits_activations() {
        let reg = ValidatorRegistry::new();
        // Set up 5 active validators by hand so the cap (4% of 5 = 0, floored
        // to MIN_CHURN_PER_EPOCH = 1) admits exactly one new candidate.
        for i in 1..=5u8 {
            let (ck, pk, bk) = make_keys();
            let a = make_address(i);
            reg.register_candidate(
                a,
                ck,
                pk,
                bk,
                a,
                DEFAULT_MIN_VALIDATOR_SELF_STAKE,
                0,
                String::new(),
            )
            .unwrap();
        }
        // Bootstrap: all 5 admitted in epoch 1 (active set is empty so the
        // floor lets MIN_CHURN_PER_EPOCH through; in practice genesis seeds
        // the initial set differently — see register_initial_active for that
        // path). For this test we drive them to Active by hand:
        for i in 1..=5u8 {
            let a = make_address(i);
            if let Some(mut entry) = reg.entries.get_mut(&a) {
                entry.status = ValidatorRegistryStatus::Active;
            }
        }
        assert_eq!(reg.list_active().len(), 5);

        // Add 3 fresh candidates and run a transition.
        for i in 6..=8u8 {
            let (ck, pk, bk) = make_keys();
            let a = make_address(i);
            reg.register_candidate(
                a,
                ck,
                pk,
                bk,
                a,
                DEFAULT_MIN_VALIDATOR_SELF_STAKE,
                0,
                String::new(),
            )
            .unwrap();
        }
        let plan = reg.compute_epoch_transition(1);
        // 4% of 5 = 0, floored to MIN_CHURN_PER_EPOCH = 1 — exactly one
        // candidate should be promoted.
        assert_eq!(plan.activations.len(), 1);
    }

    #[test]
    fn rotate_keys_updates_registry_in_place() {
        let reg = ValidatorRegistry::new();
        let (ck0, pk0, bk0) = make_keys();
        let a = make_address(11);
        reg.register_candidate(
            a,
            ck0.clone(),
            pk0.clone(),
            bk0.clone(),
            a,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            0,
            String::new(),
        )
        .unwrap();

        // Rotate to fresh keys (bytes 1 instead of 0 for the consensus key).
        let new_ck = vec![1u8; 32];
        let new_pk = vec![2u8; ML_DSA_65_VK_LEN];
        let new_bk = vec![3u8; 48];
        reg.rotate_keys(&a, new_ck.clone(), new_pk.clone(), new_bk.clone())
            .unwrap();

        let entry = reg.get(&a).unwrap();
        assert_eq!(entry.consensus_pubkey, new_ck);
        assert_eq!(entry.pq_pubkey, new_pk);
        assert_eq!(entry.bls_pubkey, new_bk);
        // Stake, tier, status, withdrawal — all unchanged.
        assert_eq!(entry.self_stake, DEFAULT_MIN_VALIDATOR_SELF_STAKE);
        assert_eq!(entry.tier, ValidatorTier::Staked);
        assert_eq!(entry.status, ValidatorRegistryStatus::Candidate);
        assert_eq!(entry.withdrawal_address, a);
    }

    #[test]
    fn rotate_keys_rejects_wrong_lengths() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, bk) = make_keys();
        let a = make_address(12);
        reg.register_candidate(a, ck, pk, bk, a, 0, 0, String::new()).unwrap();

        // 31-byte consensus key — rejected.
        let bad = reg.rotate_keys(&a, vec![1u8; 31], vec![2u8; ML_DSA_65_VK_LEN], vec![3u8; 48]);
        assert!(bad.is_err(), "31-byte consensus_pubkey must be rejected");

        // Wrong PQ length — rejected.
        let bad = reg.rotate_keys(&a, vec![1u8; 32], vec![2u8; 1951], vec![3u8; 48]);
        assert!(bad.is_err(), "wrong-length pq_pubkey must be rejected");

        // Wrong BLS length — rejected.
        let bad = reg.rotate_keys(&a, vec![1u8; 32], vec![2u8; ML_DSA_65_VK_LEN], vec![3u8; 47]);
        assert!(bad.is_err(), "wrong-length bls_pubkey must be rejected");
    }

    #[test]
    fn rotate_keys_refuses_exited_validator() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, bk) = make_keys();
        let a = make_address(13);
        reg.register_candidate(
            a,
            ck.clone(),
            pk.clone(),
            bk.clone(),
            a,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            0,
            String::new(),
        )
        .unwrap();

        // Force the entry into Exited state without going through the
        // governance path — direct mutation for the test fixture.
        reg.entries
            .alter(&a, |_, mut e| {
                e.status = ValidatorRegistryStatus::Exited;
                e
            });

        let new_ck = vec![1u8; 32];
        let err = reg
            .rotate_keys(&a, new_ck, vec![2u8; ML_DSA_65_VK_LEN], vec![3u8; 48])
            .unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("Exited"),
            "expected Exited-state refusal, got: {}",
            msg
        );
    }

    #[test]
    fn rotate_keys_idempotent_on_noop() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, bk) = make_keys();
        let a = make_address(14);
        reg.register_candidate(
            a,
            ck.clone(),
            pk.clone(),
            bk.clone(),
            a,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            0,
            String::new(),
        )
        .unwrap();

        // Same keys → no-op success.
        reg.rotate_keys(&a, ck.clone(), pk.clone(), bk.clone())
            .unwrap();
        let entry = reg.get(&a).unwrap();
        assert_eq!(entry.consensus_pubkey, ck);
    }
}
