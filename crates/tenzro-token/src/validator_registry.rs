//! Permissionless validator registry — dynamic active-set membership.
//!
//! This module is the on-chain source of truth for who is a validator. It is
//! consulted at every epoch boundary by the consensus epoch manager to decide
//! which validators are active in the next epoch. The registry combines
//! several established mechanisms:
//!
//! - **Ethereum Pectra (EIP-7251 / EIP-7002 / EIP-8061)** — typed transactions
//!   for register/exit, weight-based churn caps with separate activation and
//!   exit budgets per epoch.
//! - An explicit `Candidate` intermediate state where metadata is published
//!   before the validator can be activated.
//! - A five-state machine
//!   (`Candidate` → `PendingActive` → `Active` → `PendingExit` → `Exited`)
//!   plus a separate `Jailed` quarantine state reachable from `Active`.
//! - Absolute-power validator-set updates applied at epoch boundaries with a
//!   fixed effective-date delay.
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
/// validator. Reads the validator rung of the ladder in
/// [`tenzro_types::constants`], which sits above the governance floor in
/// [`crate::staking::DEFAULT_MIN_STAKE`] — validator slots cost more than
/// service-provider slots. Per WHITEPAPER §5 + TOKENOMICS §7, Tier 1
/// (resource-only) validators require **no stake**; only Tier 2 must meet
/// this minimum.
pub const DEFAULT_MIN_VALIDATOR_SELF_STAKE: u128 = tenzro_types::constants::MIN_VALIDATOR_STAKE;

/// Default minimum self-bonded stake to register as a **Tier 3** (RPC
/// provider) validator. Tier 3 implies Tier 2 — the RPC bond satisfies the
/// Tier 2 minimum, so the effective bond is the RPC figure alone, not the
/// sum of the two.
///
/// Per the 2026-06-10 canonical model (memory:
/// `project_validator_and_rpc_provider_model_2026_06_10`), Tier 3
/// requires the higher bond because RPC providers carry the larger
/// trust surface: they mint scoped `tnz_...` API keys for tenants,
/// route signed transactions, broker access to operator-held upstream
/// credentials (archive nodes, AI provider keys, data feed
/// subscriptions), front cross-chain mint/burn flows, and mediate
/// per-tenant billing. The 10× multiple over Tier 2 reflects this.
pub const DEFAULT_MIN_RPC_PROVIDER_STAKE: u128 = tenzro_types::constants::MIN_RPC_OPERATOR_STAKE;

/// Default activation churn cap: percentage of active set, in basis points.
/// 400 bps = 4% per epoch (matching EIP-8061 conservative profile).
pub const DEFAULT_ACTIVATION_CHURN_BPS: u32 = 400;

/// Default exit churn cap: share of the active set's self-stake that may
/// finish exiting in one epoch, in basis points. Governed on chain as
/// `staking.exit_churn_bps`; the node sets it at every boundary.
pub const DEFAULT_EXIT_CHURN_BPS: u32 = 400;

/// Default number of consecutive epochs without a certified signature after
/// which a validator is moved to exit. Governed on chain as
/// `staking.inactivity_limit_epochs`; 0 turns ejection off.
pub const DEFAULT_INACTIVITY_LIMIT_EPOCHS: u64 = 5_000;

/// Default floor under the active set for ejection: the fewest validators a
/// launch accepts (`3f + 1`, f = 1), so ejection never takes an accepted set
/// below the launch minimum. Governed on chain as `staking.active_set_floor`;
/// ejection also refuses any step that fails the launch arithmetic by stake,
/// whatever the floor.
pub const DEFAULT_ACTIVE_SET_FLOOR: u64 = tenzro_types::launch_rule::MIN_LAUNCH_VALIDATORS as u64;

/// Default jail term, in epochs: how long a validator slashed for misbehaviour
/// stays out of the active set before it returns as a candidate. Governed on
/// chain as `slashing.jail_term_epochs`; the node sets it at every boundary.
/// Governance can also reinstate a jailed validator sooner.
pub const DEFAULT_JAIL_TERM_EPOCHS: u64 = 720;

/// Minimum number of validators that may activate per epoch even when the
/// percentage cap rounds to zero (bootstrap phase). Per EIP-8061 §5.
pub const MIN_CHURN_PER_EPOCH: u32 = 1;

/// Re-entry cooldown after a voluntary exit, in epochs. A validator that exits
/// must wait this many epochs before they can register again — prevents
/// thrashing the active set.
pub const DEFAULT_REENTRY_COOLDOWN_EPOCHS: u64 = 4;

/// Effective-date delay between governance/registry decision and active-set
/// inclusion, in blocks.
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
/// Prefix of a validator's consensus key waiting for the next epoch.
const PENDING_KEY_PREFIX: &str = "valreg_pending_key:";
/// Prefix of the epoch from which a seated key's scheme was no longer
/// admitted.
const UNADMITTED_PREFIX: &str = "valreg_unadmitted:";
/// Epochs a seated key keeps its seat after governance stops admitting its
/// scheme, so its operator can rotate to an admitted one.
pub const RETIRED_SCHEME_GRACE_EPOCHS: u64 = 1;

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

    /// Returns true if this tier is sanctioned to broker tenant access
    /// to external networks and serve public RPC. Tier 3 only.
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
///                                 │ exit-call               │ term ends or governance
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
    /// Slashed for misbehaviour. Stays jailed for the governed jail term, or
    /// until a governance proposal reinstates it, then returns as a
    /// `Candidate` ([`ValidatorRegistry::release_jailed`]).
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
    /// ML-DSA-65 verifying key of the hardware-held consensus key (1952
    /// bytes, FIPS 204).
    pub ml_dsa_pubkey: Vec<u8>,
    /// Uncompressed SEC1 P-256 key of the same composite key (65 bytes).
    pub p256_pubkey: Vec<u8>,
    /// The node's Ed25519 key, derived from its hardware; `address` is its
    /// address. Not a network address: the validator announces where to
    /// reach it on every boot.
    pub node_key: [u8; 32],
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
    /// Economic tier of the validator (self-staked vs. delegated-backed, etc.).
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
    /// First epoch at which the jail term in force releases a jailed
    /// validator. `None` when the validator is not jailed. A governance
    /// reinstatement releases it earlier.
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
        ml_dsa_pubkey: Vec<u8>,
        p256_pubkey: Vec<u8>,
        node_key: [u8; 32],
        withdrawal_address: Address,
        self_stake: u128,
        registered_at_epoch: u64,
        metadata_uri: String,
        cfg: &ValidatorRegistryConfig,
    ) -> Result<Self> {
        if ml_dsa_pubkey.len() != tenzro_crypto::pq::ML_DSA_65_VK_LEN {
            return Err(TokenError::InvalidParameter(format!(
                "ML-DSA verifying key must be {} bytes (ML-DSA-65), got {}",
                tenzro_crypto::pq::ML_DSA_65_VK_LEN,
                ml_dsa_pubkey.len()
            )));
        }
        if p256_pubkey.len() != 65 || p256_pubkey[0] != 0x04 {
            return Err(TokenError::InvalidParameter(
                "P-256 key must be a 65-byte uncompressed SEC1 point".to_string(),
            ));
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
            ml_dsa_pubkey,
            p256_pubkey,
            node_key,
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
    pub min_rpc_provider_stake: u128,
    /// Activation churn cap, in basis points of current active-set size.
    pub activation_churn_bps: u32,
    /// Exit churn cap, in basis points of the active set's self-stake: the
    /// stake that may finish exiting in one epoch. At least one exit always
    /// completes, so a validator larger than the budget still leaves.
    pub exit_churn_bps: u32,
    /// Re-entry cooldown after voluntary exit, in epochs.
    pub reentry_cooldown_epochs: u64,
    /// Epochs a slashed validator stays jailed before it returns as a
    /// candidate.
    pub jail_term_epochs: u64,
}

impl Default for ValidatorRegistryConfig {
    fn default() -> Self {
        Self {
            min_self_stake: DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            min_rpc_provider_stake: DEFAULT_MIN_RPC_PROVIDER_STAKE,
            activation_churn_bps: DEFAULT_ACTIVATION_CHURN_BPS,
            exit_churn_bps: DEFAULT_EXIT_CHURN_BPS,
            reentry_cooldown_epochs: DEFAULT_REENTRY_COOLDOWN_EPOCHS,
            jail_term_epochs: DEFAULT_JAIL_TERM_EPOCHS,
        }
    }
}

/// When a validator that signs nothing is moved out of the active set. Both
/// numbers are governed on-chain parameters; the registry holds neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InactivityPolicy {
    /// Consecutive epochs without a certified signature after which a
    /// validator is moved to exit. `0` turns ejection off.
    pub max_missed_epochs: u64,
    /// The active set is never reduced below this many validators.
    pub keep_active_at_least: usize,
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
    /// Validators still `PendingExit` after this transition: the exit budget
    /// was spent, so their exits wait for a later epoch.
    pub exits: Vec<Address>,
    /// Validators that completed `PendingActive` → `Active` (effective now).
    pub effective_activations: Vec<Address>,
    /// Validators that completed `PendingExit` → `Exited` (effective now).
    pub effective_exits: Vec<Address>,
    /// Validators whose consensus key was replaced at this boundary.
    pub key_rotations: Vec<Address>,
    /// Validators unseated at this boundary because governance no longer
    /// admits the scheme of their key and its grace has passed. They stay
    /// registered and bonded and return once they rotate to an admitted key.
    pub unseated: Vec<Address>,
}

/// A validator of a recovery successor set, as
/// [`ValidatorRegistry::replace_active_set`] takes it.
#[derive(Debug, Clone)]
pub struct RecoveryMember {
    /// Validator address.
    pub address: Address,
    /// ML-DSA half of the consensus key.
    pub ml_dsa_pubkey: Vec<u8>,
    /// ECDSA half of the consensus key.
    pub p256_pubkey: Vec<u8>,
    /// The node's Ed25519 key.
    pub node_key: [u8; 32],
    /// Self-bonded stake in base units.
    pub self_stake: u128,
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
    /// Consensus keys waiting for the next epoch boundary: (ML-DSA leg,
    /// ECDSA leg).
    pending_keys: DashMap<Address, (Vec<u8>, Vec<u8>)>,
    /// First epoch at which a seated key's scheme was not admitted.
    unadmitted_since: DashMap<Address, u64>,
}

impl ValidatorRegistry {
    /// Creates an in-memory-only registry.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            config: parking_lot::RwLock::new(ValidatorRegistryConfig::default()),
            storage: None,
            pending_keys: DashMap::new(),
            unadmitted_since: DashMap::new(),
        }
    }

    /// Creates a registry backed by persistent storage. Hydrates state on
    /// construction; logs and continues on partial-decode errors.
    pub fn with_storage(storage: Arc<dyn tenzro_storage::KvStore>) -> Self {
        let registry = Self {
            entries: DashMap::new(),
            config: parking_lot::RwLock::new(ValidatorRegistryConfig::default()),
            storage: Some(storage),
            pending_keys: DashMap::new(),
            unadmitted_since: DashMap::new(),
        };
        if let Err(e) = registry.load_from_storage() {
            warn!("Failed to hydrate validator registry: {}", e);
        }
        registry
    }

    fn persist_entry(&self, entry: &ValidatorRegistryEntry) {
        if let Some(storage) = &self.storage {
            let key = format!(
                "{}{}",
                VALIDATOR_PREFIX,
                hex::encode(entry.address.as_bytes())
            );
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
        for (k, v) in storage
            .scan_prefix(REGISTRY_CF, PENDING_KEY_PREFIX.as_bytes())
            .unwrap_or_default()
        {
            if let (Some(addr), Ok(key)) = (
                address_after(&k, PENDING_KEY_PREFIX),
                bincode::deserialize::<(Vec<u8>, Vec<u8>)>(&v),
            ) {
                self.pending_keys.insert(addr, key);
            }
        }
        for (k, v) in storage
            .scan_prefix(REGISTRY_CF, UNADMITTED_PREFIX.as_bytes())
            .unwrap_or_default()
        {
            if let (Some(addr), Ok(epoch)) = (
                address_after(&k, UNADMITTED_PREFIX),
                <[u8; 8]>::try_from(v.as_slice()),
            ) {
                self.unadmitted_since
                    .insert(addr, u64::from_be_bytes(epoch));
            }
        }

        Ok(())
    }

    fn put_side(&self, key: String, value: Option<Vec<u8>>) {
        if let Some(storage) = &self.storage {
            let r = match value {
                Some(v) => storage.put(REGISTRY_CF, key.as_bytes(), &v),
                None => storage.delete(REGISTRY_CF, key.as_bytes()),
            };
            if let Err(e) = r {
                warn!("Failed to persist validator registry record {}: {}", key, e);
            }
        }
    }

    /// Replaces `address`'s consensus key with (`ml_dsa_pubkey`,
    /// `p256_pubkey`) at the next epoch boundary, without an exit. The VM
    /// has already checked the new key's proof of possession and scheme.
    pub fn request_key_rotation(
        &self,
        address: &Address,
        ml_dsa_pubkey: Vec<u8>,
        p256_pubkey: Vec<u8>,
    ) -> Result<()> {
        let entry = self
            .entries
            .get(address)
            .ok_or_else(|| TokenError::InvalidParameter(format!("{address} is not registered")))?;
        if entry.status == ValidatorRegistryStatus::Exited {
            return Err(TokenError::InvalidParameter(format!(
                "{address} has exited; it registers again instead"
            )));
        }
        drop(entry);
        let key = (ml_dsa_pubkey, p256_pubkey);
        self.put_side(
            format!("{PENDING_KEY_PREFIX}{}", hex::encode(address.as_bytes())),
            bincode::serialize(&key).ok(),
        );
        self.pending_keys.insert(*address, key);
        Ok(())
    }

    /// The key rotation `address` has requested and the next epoch
    /// boundary applies, if any.
    pub fn pending_key(&self, address: &Address) -> Option<(Vec<u8>, Vec<u8>)> {
        self.pending_keys.get(address).map(|e| e.value().clone())
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

    /// Add to a live validator's self-stake.
    ///
    /// The registry could create a stake and end one, and nothing in between:
    /// `register_candidate` refuses an address that has not exited, and exiting
    /// to re-register costs the re-entry cooldown and the validator's place in
    /// the set. So a validator set could never rebalance, which matters most
    /// where it is least visible — a network that starts from a single funded
    /// genesis validator has no way to dilute it, and stays dependent on that
    /// one node for every block no matter how many others join.
    ///
    /// Returns the new total. Only ever adds: reducing a stake is unbonding,
    /// which has its own path, its own delay, and its own slashing exposure,
    /// and must not be reachable by passing a smaller number here.
    ///
    /// The tier is recomputed, so crossing `min_self_stake` or
    /// `min_rpc_provider_stake` promotes the validator exactly as it would at
    /// registration.
    pub fn increase_self_stake(&self, address: &Address, additional: u128) -> Result<u128> {
        if additional == 0 {
            return Err(TokenError::InvalidParameter(
                "stake increase must be greater than zero".to_string(),
            ));
        }

        let cfg = *self.config.read();
        let updated = {
            let mut entry = self.entries.get_mut(address).ok_or_else(|| {
                TokenError::InvalidParameter(format!("validator {address} is not registered"))
            })?;

            if matches!(entry.status, ValidatorRegistryStatus::Exited) {
                return Err(TokenError::Unauthorized {
                    reason: format!("validator {address} has exited; re-register instead"),
                });
            }

            entry.self_stake = entry.self_stake.checked_add(additional).ok_or_else(|| {
                TokenError::InvalidParameter("stake increase overflows".to_string())
            })?;
            entry.tier = ValidatorTier::from_stake(entry.self_stake, &cfg);
            entry.clone()
        };

        self.persist_entry(&updated);
        Ok(updated.self_stake)
    }

    /// Mirrors a governance recall of `amount` of sponsored stake that had
    /// been counted toward `address`'s bond: the stake falls by it, never
    /// below zero, and the tier is recomputed. The chain moved the stake
    /// into unbonding; this is the read model following it.
    pub fn recall_sponsored_stake(&self, address: &Address, amount: u128) -> Result<u128> {
        let cfg = *self.config.read();
        let updated = {
            let mut entry = self.entries.get_mut(address).ok_or_else(|| {
                TokenError::InvalidParameter(format!("validator {address} is not registered"))
            })?;
            entry.self_stake = entry.self_stake.saturating_sub(amount);
            entry.tier = ValidatorTier::from_stake(entry.self_stake, &cfg);
            entry.clone()
        };

        self.persist_entry(&updated);
        Ok(updated.self_stake)
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

    /// The per-epoch budgets: how many candidates may activate, a share of
    /// the active-set size; and how much self-stake may finish exiting, a
    /// share of the active set's self-stake.
    fn churn_budgets(&self) -> (u32, u128) {
        let cfg = *self.config.read();
        let n = self.active_set_size() as u64;
        let act = ((n.saturating_mul(cfg.activation_churn_bps as u64)) / 10_000) as u32;
        let stake = self
            .entries
            .iter()
            .filter(|e| e.value().status.counts_toward_active())
            .fold(0u128, |a, e| a.saturating_add(e.value().self_stake));
        let exit = stake.saturating_mul(u128::from(cfg.exit_churn_bps)) / 10_000;
        (act.max(MIN_CHURN_PER_EPOCH), exit)
    }

    /// Registers a new candidate validator. Idempotent only when no entry
    /// exists for `address` — re-registration of an existing address must
    /// route through `Exited → Candidate` (after cooldown) explicitly.
    #[allow(clippy::too_many_arguments)]
    pub fn register_candidate(
        &self,
        address: Address,
        ml_dsa_pubkey: Vec<u8>,
        p256_pubkey: Vec<u8>,
        node_key: [u8; 32],
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
            ml_dsa_pubkey,
            p256_pubkey,
            node_key,
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
            address,
            current_epoch,
            self_stake,
            tier.as_str()
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
        ml_dsa_pubkey: Vec<u8>,
        p256_pubkey: Vec<u8>,
        node_key: [u8; 32],
        withdrawal_address: Address,
        self_stake: u128,
        metadata_uri: String,
    ) -> Result<bool> {
        // Idempotent: an address already in the registry is left alone.
        //
        // This briefly repaired a stored stake that looked "too small", on the
        // theory that genesis had seeded whole TNZO where base units were
        // expected. The theory was wrong in the direction that matters:
        // ValidatorInfo::stake IS consensus voting power, every historical QC
        // was tallied against the genesis numbers exactly as declared, and
        // rescaling them makes those QCs unverifiable — a fresh node cannot
        // sync past height 1:
        //
        //   QC claims voting_power=10000000 but bitmap-tallied power is
        //   10000000000000000000000000
        //
        // There is a genuine unit mismatch between genesis (whole TNZO) and the
        // registry floors (MIN_VALIDATOR_STAKE is 10_000 * ONE_TNZO), but it
        // cannot be repaired by reinterpreting stored state. It needs a
        // coordinated upgrade that rescales both sides at a known height.
        if self.entries.contains_key(&address) {
            return Ok(false);
        }
        // Genesis may seed validators at any tier; the key and metadata
        // checks are the ones every registration passes.
        let cfg = *self.config.read();
        let mut entry = ValidatorRegistryEntry::new_candidate(
            address,
            ml_dsa_pubkey,
            p256_pubkey,
            node_key,
            withdrawal_address,
            self_stake,
            0,
            metadata_uri,
            &cfg,
        )?;
        entry.status = ValidatorRegistryStatus::Active;
        entry.activated_at_epoch = Some(0);
        let tier = entry.tier;
        self.entries.insert(address, entry.clone());
        self.persist_entry(&entry);
        self.persist_index();
        info!(
            "Seeded genesis Active validator {} with stake {} (tier={})",
            address,
            self_stake,
            tier.as_str()
        );
        Ok(true)
    }

    /// Makes `members` the whole active set and every other entry `Exited`,
    /// as `epoch` begins. Used once, by a recovery restart after a halt
    /// below quorum: the halted chain's registry cannot be changed by any
    /// certified transaction, so the manifest the operators agreed on
    /// replaces it. A member already present keeps its entry with its keys
    /// and stake set to the manifest's, `Active` and no longer jailed or
    /// exiting; a new one is inserted `Active`. Pending key rotations of the
    /// halted chain are dropped. Applying the same members again changes
    /// nothing.
    pub fn replace_active_set(&self, members: &[RecoveryMember], epoch: u64) -> Result<()> {
        let cfg = *self.config.read();
        let mut changed: Vec<ValidatorRegistryEntry> = Vec::new();
        for member in members {
            let entry = match self.entries.get(&member.address).map(|e| e.value().clone()) {
                Some(mut e) => {
                    e.ml_dsa_pubkey = member.ml_dsa_pubkey.clone();
                    e.p256_pubkey = member.p256_pubkey.clone();
                    e.node_key = member.node_key;
                    e.self_stake = member.self_stake;
                    e.tier = ValidatorTier::from_stake(e.self_stake, &cfg);
                    e.status = ValidatorRegistryStatus::Active;
                    e.activated_at_epoch.get_or_insert(epoch);
                    e.exited_at_epoch = None;
                    e.jailed_until_epoch = None;
                    e
                }
                None => {
                    let mut e = ValidatorRegistryEntry::new_candidate(
                        member.address,
                        member.ml_dsa_pubkey.clone(),
                        member.p256_pubkey.clone(),
                        member.node_key,
                        member.address,
                        member.self_stake,
                        epoch,
                        String::new(),
                        &cfg,
                    )?;
                    e.status = ValidatorRegistryStatus::Active;
                    e.activated_at_epoch = Some(epoch);
                    e
                }
            };
            changed.push(entry);
        }
        for e in self.entries.iter() {
            let entry = e.value();
            if !members.iter().any(|m| m.address == entry.address)
                && entry.status != ValidatorRegistryStatus::Exited
            {
                let mut gone = entry.clone();
                gone.status = ValidatorRegistryStatus::Exited;
                gone.exited_at_epoch = Some(epoch);
                gone.jailed_until_epoch = None;
                changed.push(gone);
            }
        }
        for mut entry in changed {
            entry.updated_at = Timestamp::now();
            self.entries.insert(entry.address, entry.clone());
            self.persist_entry(&entry);
        }
        self.pending_keys.clear();
        self.persist_index();
        Ok(())
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

    /// The stakes of the `Active` validators other than `leaving`: the set
    /// that remains if `leaving` goes.
    fn stakes_without(&self, leaving: &Address) -> Vec<u128> {
        self.entries
            .iter()
            .filter(|e| e.value().status == ValidatorRegistryStatus::Active)
            .filter(|e| &e.value().address != leaving)
            .map(|e| tenzro_types::launch_rule::voting_power(e.value().self_stake))
            .collect()
    }

    /// Whether the active set that remains after `leaving` goes still holds
    /// the launch arithmetic by stake: enough members, and a live spare.
    /// Ejection and the slash path use it.
    pub fn set_without_is_accepted(&self, leaving: &Address) -> bool {
        tenzro_types::launch_rule::all_live_set_accepted(&self.stakes_without(leaving))
    }

    /// Moves validators that have been absent for too long from `Active` to
    /// `PendingExit`, so a validator that is gone cannot hold the quorum
    /// threshold above what the live set can reach.
    ///
    /// `missed_epochs` is each validator's count of consecutive epochs in
    /// which it signed nothing the chain certified; the caller derives it
    /// from certified data, so every node computes the same map. The limit
    /// and the floor are `policy`, read from the chain's governed
    /// parameters by the caller: nothing here fixes either. An exit follows
    /// the ordinary path (`PendingExit`, then `Exited` within the exit
    /// churn budget at the next boundary), and the stake stays bonded and
    /// returns on a normal re-registration.
    ///
    /// Validators are taken longest-absent first, ties by address, so the
    /// outcome does not depend on map order. No ejection leaves fewer than
    /// `policy.keep_active_at_least` validators counting toward the active
    /// set. Returns the validators moved.
    pub fn eject_inactive(
        &self,
        policy: &InactivityPolicy,
        missed_epochs: &std::collections::HashMap<Address, u64>,
    ) -> Vec<Address> {
        if policy.max_missed_epochs == 0 {
            return Vec::new();
        }
        let mut candidates: Vec<(u64, Address)> = self
            .entries
            .iter()
            .filter(|e| e.value().status == ValidatorRegistryStatus::Active)
            .filter_map(|e| {
                let missed = missed_epochs.get(&e.value().address).copied().unwrap_or(0);
                (missed >= policy.max_missed_epochs).then_some((missed, e.value().address))
            })
            .collect();
        candidates.sort_unstable_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| a.1.as_bytes().cmp(b.1.as_bytes()))
        });
        let mut remaining = self.active_set_size();
        let mut ejected = Vec::new();
        for (missed, addr) in candidates {
            if remaining <= policy.keep_active_at_least {
                break;
            }
            // Whatever the governed floor, never take the set below what a
            // launch accepts: weighed by stake, with a live spare.
            // A refusal is about this validator only: a lighter absent one may
            // still leave a set that passes, so go on to the next.
            if !self.set_without_is_accepted(&addr) {
                continue;
            }
            if self.request_exit(&addr).is_ok() {
                remaining -= 1;
                warn!(
                    "Validator {} moved to exit after {} epochs without a certified signature",
                    addr, missed
                );
                ejected.push(addr);
            }
        }
        ejected
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

    /// Marks a validator as jailed in response to a slash event. Forces an
    /// exit at the next epoch boundary. The jail lasts the governed term
    /// ([`ValidatorRegistryConfig::jail_term_epochs`]) from the epoch of the
    /// first jailing; jailing a validator that is already jailed changes
    /// nothing.
    pub fn jail(&self, address: &Address, current_epoch: u64) -> Result<()> {
        let term = self.config.read().jail_term_epochs;
        let mut entry = self
            .entries
            .get_mut(address)
            .ok_or_else(|| TokenError::NotFound(format!("validator {}", address)))?;

        if entry.status != ValidatorRegistryStatus::Jailed {
            entry.status = ValidatorRegistryStatus::Jailed;
            entry.exited_at_epoch = Some(current_epoch);
            entry.jailed_until_epoch = Some(current_epoch.saturating_add(term));
        }
        entry.updated_at = Timestamp::now();
        let snapshot = entry.clone();
        drop(entry);
        self.persist_entry(&snapshot);
        warn!(
            "Validator {} jailed at epoch {} for {} epochs unless governance reinstates it sooner",
            address, current_epoch, term
        );
        // A slash removes a counted validator and is not refused: keeping an
        // equivocator seated is worse. It can still leave the set without the
        // tolerance a launch requires, so say so for the alert.
        if !self.set_without_is_accepted(address) {
            warn!(
                "The active set after jailing {} no longer holds the launch arithmetic: it has no live spare or fewer than the launch minimum",
                address
            );
        }
        Ok(())
    }

    /// Returns jailed validators to `Candidate` at the start of `epoch`: those
    /// whose jail term in force has run out (jailed at epoch `j`, released
    /// from epoch `j + jail_term_epochs`), and those `reinstated` says
    /// governance reinstated. `reinstated` takes the validator and the epoch
    /// it was jailed in, and answers whether a reinstatement enacted since
    /// then is on chain. A released validator is admitted again like any
    /// candidate: by the activation churn cap and the self-stake floor.
    /// Still-jailed entries have their release epoch brought in line with the
    /// term in force. Returns the released validators, in address order.
    pub fn release_jailed(
        &self,
        epoch: u64,
        reinstated: &dyn Fn(&Address, u64) -> bool,
    ) -> Vec<Address> {
        let term = self.config.read().jail_term_epochs;
        let mut jailed: Vec<(Address, u64)> = self
            .entries
            .iter()
            .filter(|e| e.value().status == ValidatorRegistryStatus::Jailed)
            .map(|e| (e.value().address, e.value().exited_at_epoch.unwrap_or(0)))
            .collect();
        jailed.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let mut released = Vec::new();
        for (addr, jailed_at) in jailed {
            let until = jailed_at.saturating_add(term);
            let free = epoch >= until || reinstated(&addr, jailed_at);
            let Some(mut entry) = self.entries.get_mut(&addr) else {
                continue;
            };
            if free {
                entry.status = ValidatorRegistryStatus::Candidate;
                entry.jailed_until_epoch = None;
                entry.exited_at_epoch = None;
                released.push(addr);
            } else if entry.jailed_until_epoch == Some(until) {
                continue;
            } else {
                entry.jailed_until_epoch = Some(until);
            }
            entry.updated_at = Timestamp::now();
            let snapshot = entry.clone();
            drop(entry);
            self.persist_entry(&snapshot);
        }
        if !released.is_empty() {
            info!(
                "Epoch {}: {} jailed validators released to candidacy",
                epoch,
                released.len()
            );
        }
        released
    }

    /// Computes the validator-set transition for the new epoch.
    ///
    /// This is the **single point** the consensus epoch manager calls at
    /// every epoch boundary. The plan tells the caller which validators move
    /// in and out of the active set; the caller is responsible for handing
    /// those movements to `EpochManager`'s `pending_validators` /
    /// `pending_removals` queues.
    pub fn compute_epoch_transition(&self, new_epoch: u64) -> EpochTransitionPlan {
        self.compute_epoch_transition_with(new_epoch, &|_| true)
    }

    /// [`Self::compute_epoch_transition`], applying first the key rotations
    /// requested since the last boundary, then unseating validators whose
    /// key governance no longer admits once [`RETIRED_SCHEME_GRACE_EPOCHS`]
    /// have passed; `admitted` judges a key by its ML-DSA leg. A candidate
    /// whose key is not admitted is not activated.
    pub fn compute_epoch_transition_with(
        &self,
        new_epoch: u64,
        admitted: &dyn Fn(&[u8]) -> bool,
    ) -> EpochTransitionPlan {
        let (act_budget, exit_budget) = self.churn_budgets();
        let mut plan = EpochTransitionPlan::default();

        // Phase 0: key rotations, then seats of keys no longer admitted.
        let mut rotating: Vec<Address> = self.pending_keys.iter().map(|e| *e.key()).collect();
        rotating.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for addr in rotating {
            let Some((_, (ml_dsa, p256))) = self.pending_keys.remove(&addr) else {
                continue;
            };
            self.put_side(
                format!("{PENDING_KEY_PREFIX}{}", hex::encode(addr.as_bytes())),
                None,
            );
            if let Some(mut entry) = self.entries.get_mut(&addr) {
                entry.ml_dsa_pubkey = ml_dsa;
                entry.p256_pubkey = p256;
                entry.updated_at = Timestamp::now();
                plan.key_rotations.push(addr);
                let snapshot = entry.clone();
                drop(entry);
                self.persist_entry(&snapshot);
            }
        }
        let mut seated: Vec<(Address, bool)> = self
            .entries
            .iter()
            .filter(|e| e.value().status == ValidatorRegistryStatus::Active)
            .map(|e| (e.value().address, admitted(&e.value().ml_dsa_pubkey)))
            .collect();
        seated.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        for (addr, ok) in seated {
            let key = format!("{UNADMITTED_PREFIX}{}", hex::encode(addr.as_bytes()));
            if ok {
                if self.unadmitted_since.remove(&addr).is_some() {
                    self.put_side(key, None);
                }
                continue;
            }
            let since = *self.unadmitted_since.entry(addr).or_insert_with(|| {
                self.put_side(key.clone(), Some(new_epoch.to_be_bytes().to_vec()));
                new_epoch
            });
            if new_epoch >= since + RETIRED_SCHEME_GRACE_EPOCHS
                && let Some(mut entry) = self.entries.get_mut(&addr)
            {
                entry.status = ValidatorRegistryStatus::Candidate;
                entry.updated_at = Timestamp::now();
                plan.unseated.push(addr);
                let snapshot = entry.clone();
                drop(entry);
                self.persist_entry(&snapshot);
                self.unadmitted_since.remove(&addr);
                self.put_side(key, None);
            }
        }

        // Phase 1: complete in-flight transitions from prior epoch.
        // PendingActive -> Active, and PendingExit -> Exited within the exit
        // budget. Both lists are sorted by address, so every node finalises
        // the same validators whatever its map's iteration order. Exits are
        // taken in that order while their self-stake fits the budget (the
        // first always does); the rest stay PendingExit, never recorded as
        // Exited, and wait for a later epoch.
        let mut activating = Vec::new();
        let mut exiting = Vec::new();
        for e in self.entries.iter() {
            match e.value().status {
                ValidatorRegistryStatus::PendingActive => activating.push(e.value().address),
                ValidatorRegistryStatus::PendingExit => {
                    exiting.push((e.value().address, e.value().self_stake))
                }
                _ => {}
            }
        }
        activating.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        exiting.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let mut spent = 0u128;
        let mut taken = 0usize;
        for (_, stake) in &exiting {
            let next = spent.saturating_add(*stake);
            if taken >= MIN_CHURN_PER_EPOCH as usize && next > exit_budget {
                break;
            }
            spent = next;
            taken += 1;
        }
        let deferred: Vec<Address> = exiting
            .split_off(taken)
            .into_iter()
            .map(|(a, _)| a)
            .collect();

        for addr in activating {
            if let Some(mut entry) = self.entries.get_mut(&addr) {
                entry.status = ValidatorRegistryStatus::Active;
                entry.activated_at_epoch = Some(new_epoch);
                entry.updated_at = Timestamp::now();
                plan.effective_activations.push(addr);
                let snapshot = entry.clone();
                drop(entry);
                self.persist_entry(&snapshot);
            }
        }
        for (addr, _) in exiting {
            if let Some(mut entry) = self.entries.get_mut(&addr) {
                entry.status = ValidatorRegistryStatus::Exited;
                entry.exited_at_epoch = Some(new_epoch);
                entry.updated_at = Timestamp::now();
                plan.effective_exits.push(addr);
                let snapshot = entry.clone();
                drop(entry);
                self.persist_entry(&snapshot);
            }
        }
        plan.exits = deferred;

        // Phase 2: admit new candidates up to the activation budget.
        // Only candidates meeting the configured minimum self-stake are
        // admissible — this is the single policy floor for the validator set.
        // The VM already guarantees the declared stake is really bonded, so a
        // candidate below the floor simply stays a Candidate until it bonds
        // more or exits (no free admission). Order by stake descending, then by
        // registered_at_epoch ascending (earlier registration wins ties) for
        // deterministic ordering across all validators.
        let min_self_stake = self.config.read().min_self_stake;
        let mut candidates: Vec<(Address, u128, u64)> = self
            .entries
            .iter()
            .filter(|e| {
                e.value().status == ValidatorRegistryStatus::Candidate
                    && e.value().self_stake >= min_self_stake
                    && admitted(&e.value().ml_dsa_pubkey)
                    && !plan.unseated.contains(&e.value().address)
            })
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

        info!(
            "Epoch {} transition: +{} activations ({} effective), -{} exits effective ({} deferred)",
            new_epoch,
            plan.activations.len(),
            plan.effective_activations.len(),
            plan.effective_exits.len(),
            plan.exits.len()
        );

        plan
    }
}

/// The address hex-encoded after `prefix` in a side-record key.
fn address_after(key: &[u8], prefix: &str) -> Option<Address> {
    let hex_addr = std::str::from_utf8(key.strip_prefix(prefix.as_bytes())?).ok()?;
    Address::from_bytes(&hex::decode(hex_addr).ok()?)
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

    fn p256_key() -> Vec<u8> {
        let mut k = vec![0u8; 65];
        k[0] = 0x04;
        k
    }

    /// ML-DSA-65 key, P-256 key, node key.
    fn make_keys() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        (vec![0u8; ML_DSA_65_VK_LEN], p256_key(), [9u8; 32])
    }

    /// A live validator can add to its stake.
    ///
    /// The registry could create a stake and end one, and nothing between —
    /// registration refuses an address that has not exited. So a set
    /// bootstrapped from one heavily-funded genesis validator could never
    /// dilute it, and stayed dependent on that node for every block.
    #[test]
    fn a_live_validator_can_add_to_its_stake() {
        let reg = ValidatorRegistry::new();
        let addr = Address::new([5u8; 32]);
        let base = tenzro_types::constants::MIN_VALIDATOR_STAKE;

        reg.seed_genesis_active(
            addr,
            vec![2u8; 1952],
            p256_key(),
            [3u8; 32],
            addr,
            base,
            String::new(),
        )
        .unwrap();

        let total = reg.increase_self_stake(&addr, base * 2).unwrap();
        assert_eq!(total, base * 3);
        assert_eq!(reg.get(&addr).unwrap().self_stake, base * 3);
    }

    /// Only ever adds. Reducing a stake is unbonding, with its own delay and
    /// slashing exposure, and must not be reachable through this path.
    #[test]
    fn a_stake_increase_of_zero_is_refused() {
        let reg = ValidatorRegistry::new();
        let addr = Address::new([6u8; 32]);
        reg.seed_genesis_active(
            addr,
            vec![2u8; 1952],
            p256_key(),
            [3u8; 32],
            addr,
            tenzro_types::constants::MIN_VALIDATOR_STAKE,
            String::new(),
        )
        .unwrap();
        assert!(reg.increase_self_stake(&addr, 0).is_err());
    }

    /// An unregistered address cannot acquire a stake this way — registration
    /// requires consensus keys and a withdrawal address, and creating an entry
    /// here would bypass all of it.
    #[test]
    fn an_unregistered_address_cannot_increase_a_stake() {
        let reg = ValidatorRegistry::new();
        assert!(
            reg.increase_self_stake(&Address::new([7u8; 32]), 1_000)
                .is_err()
        );
    }

    #[test]
    fn seed_genesis_active_idempotent() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, nk) = make_keys();
        let a = make_address(7);

        // First seed: inserted
        let inserted = reg
            .seed_genesis_active(
                a,
                ck.clone(),
                pk.clone(),
                nk,
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
                nk,
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

        // Wrong ML-DSA key length
        let err = reg
            .seed_genesis_active(
                a,
                vec![0u8; 100],
                p256_key(),
                [0u8; 32],
                a,
                DEFAULT_MIN_VALIDATOR_SELF_STAKE,
                String::new(),
            )
            .unwrap_err();
        assert!(matches!(err, TokenError::InvalidParameter(_)));

        // Wrong P-256 key length
        let err = reg
            .seed_genesis_active(
                a,
                vec![0u8; ML_DSA_65_VK_LEN],
                vec![4u8; 64],
                [0u8; 32],
                a,
                DEFAULT_MIN_VALIDATOR_SELF_STAKE,
                String::new(),
            )
            .unwrap_err();
        assert!(matches!(err, TokenError::InvalidParameter(_)));

        // A compressed P-256 point is refused
        let mut compressed = p256_key();
        compressed[0] = 0x02;
        let err = reg
            .seed_genesis_active(
                a,
                vec![0u8; ML_DSA_65_VK_LEN],
                compressed,
                [0u8; 32],
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
        let (ck, pk, nk) = make_keys();
        let a = make_address(1);

        // Zero stake → Tier 1 admission succeeds.
        reg.register_candidate(a, ck.clone(), pk.clone(), nk, a, 0, 0, String::new())
            .unwrap();
        let entry = reg.get(&a).unwrap();
        assert_eq!(entry.tier, ValidatorTier::ResourceOnly);
        assert_eq!(entry.self_stake, 0);
        assert_eq!(entry.status, ValidatorRegistryStatus::Candidate);
    }

    #[test]
    fn register_at_tier_2_threshold_sets_staked() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, nk) = make_keys();
        let a = make_address(2);
        reg.register_candidate(
            a,
            ck,
            pk,
            nk,
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
        let (ck, pk, nk) = make_keys();
        let a = make_address(3);
        reg.register_candidate(
            a,
            ck,
            pk,
            nk,
            a,
            DEFAULT_MIN_RPC_PROVIDER_STAKE,
            0,
            String::new(),
        )
        .unwrap();
        assert_eq!(reg.get(&a).unwrap().tier, ValidatorTier::RpcProvider);
    }

    fn active(reg: &ValidatorRegistry, byte: u8) -> Address {
        let (ck, pk, nk) = make_keys();
        let a = make_address(byte);
        reg.register_candidate(
            a,
            ck,
            pk,
            nk,
            a,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            0,
            String::new(),
        )
        .unwrap();
        reg.compute_epoch_transition(1);
        reg.compute_epoch_transition(2);
        assert_eq!(reg.get(&a).unwrap().status, ValidatorRegistryStatus::Active);
        a
    }

    /// A seated validator replaces its consensus key at the next epoch
    /// boundary and keeps its seat: no exit, no re-registration.
    #[test]
    fn a_seated_validator_rotates_its_key_at_the_next_boundary_without_exiting() {
        let reg = ValidatorRegistry::new();
        let a = active(&reg, 7);
        let (ml, p) = (vec![0x11u8; 2594], vec![0x04u8; 97]);
        reg.request_key_rotation(&a, ml.clone(), p.clone()).unwrap();
        assert_ne!(
            reg.get(&a).unwrap().ml_dsa_pubkey,
            ml,
            "not before the boundary"
        );
        let plan = reg.compute_epoch_transition(3);
        assert_eq!(plan.key_rotations, vec![a]);
        let e = reg.get(&a).unwrap();
        assert_eq!((e.ml_dsa_pubkey, e.p256_pubkey), (ml, p));
        assert_eq!(e.status, ValidatorRegistryStatus::Active);
        assert!(plan.effective_exits.is_empty() && plan.unseated.is_empty());
    }

    /// Once governance stops admitting a seated key's scheme, the key keeps
    /// its seat for the grace epoch, is unseated after it, and is not
    /// activated again until its validator rotates to an admitted key.
    #[test]
    fn a_seated_key_of_a_retired_scheme_is_unseated_after_its_grace_and_returns_after_rotation() {
        let reg = ValidatorRegistry::new();
        let a = active(&reg, 8);
        let old = reg.get(&a).unwrap().ml_dsa_pubkey;
        let admitted = |ml: &[u8]| ml != old.as_slice();
        let plan = reg.compute_epoch_transition_with(3, &admitted);
        assert!(plan.unseated.is_empty(), "the grace epoch");
        assert_eq!(reg.get(&a).unwrap().status, ValidatorRegistryStatus::Active);
        let plan = reg.compute_epoch_transition_with(4, &admitted);
        assert_eq!(plan.unseated, vec![a]);
        assert_eq!(
            reg.get(&a).unwrap().status,
            ValidatorRegistryStatus::Candidate
        );
        let plan = reg.compute_epoch_transition_with(5, &admitted);
        assert!(
            !plan.activations.contains(&a),
            "a retired key is not activated"
        );
        reg.request_key_rotation(&a, vec![0x22u8; 2594], vec![0x04u8; 97])
            .unwrap();
        let plan = reg.compute_epoch_transition_with(6, &admitted);
        assert_eq!(plan.key_rotations, vec![a]);
        assert_eq!(plan.activations, vec![a]);
        reg.compute_epoch_transition_with(7, &admitted);
        assert_eq!(reg.get(&a).unwrap().status, ValidatorRegistryStatus::Active);
    }

    #[test]
    fn register_then_activate_then_exit_full_lifecycle() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, nk) = make_keys();
        let a = make_address(1);
        reg.register_candidate(
            a,
            ck.clone(),
            pk.clone(),
            nk,
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
    fn epoch_gate_rejects_below_min_self_stake() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, nk) = make_keys();
        let low = make_address(1);
        let ok = make_address(2);

        // Below the floor: registers fine (correctness invariant lives in the
        // VM, which bonded whatever was declared) but must NOT be admitted.
        reg.register_candidate(
            low,
            ck.clone(),
            pk.clone(),
            nk,
            low,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE - 1,
            0,
            String::new(),
        )
        .unwrap();
        // At the floor: admissible.
        reg.register_candidate(
            ok,
            ck,
            pk,
            nk,
            ok,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            0,
            String::new(),
        )
        .unwrap();

        let plan = reg.compute_epoch_transition(1);
        assert!(
            !plan.activations.contains(&low),
            "below-min candidate must not be promoted"
        );
        assert!(
            plan.activations.contains(&ok),
            "at-min candidate must be promoted"
        );
        assert_eq!(
            reg.get(&low).unwrap().status,
            ValidatorRegistryStatus::Candidate,
            "below-min candidate stays a Candidate"
        );
        assert_eq!(
            reg.get(&ok).unwrap().status,
            ValidatorRegistryStatus::PendingActive
        );
    }

    #[test]
    fn reentry_blocked_during_cooldown() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, nk) = make_keys();
        let a = make_address(1);
        reg.register_candidate(
            a,
            ck.clone(),
            pk.clone(),
            nk,
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
                nk,
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
            nk,
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

    fn active_registry(n: u8) -> (ValidatorRegistry, Vec<Address>) {
        let reg = ValidatorRegistry::new();
        let mut addrs = Vec::new();
        for i in 1..=n {
            let (ck, pk, nk) = make_keys();
            let a = make_address(i);
            reg.register_candidate(
                a,
                ck,
                pk,
                nk,
                a,
                DEFAULT_MIN_VALIDATOR_SELF_STAKE,
                0,
                String::new(),
            )
            .unwrap();
            addrs.push(a);
        }
        for e in 1..=(u64::from(n) + 2) {
            reg.compute_epoch_transition(e);
        }
        for a in &addrs {
            assert_eq!(reg.get(a).unwrap().status, ValidatorRegistryStatus::Active);
        }
        (reg, addrs)
    }

    #[test]
    fn a_validator_absent_past_the_governed_limit_is_moved_to_exit() {
        let (reg, a) = active_registry(5);
        let policy = InactivityPolicy {
            max_missed_epochs: 3,
            keep_active_at_least: 1,
        };
        let missed = std::collections::HashMap::from([(a[0], 2), (a[1], 3), (a[2], 0)]);
        assert_eq!(reg.eject_inactive(&policy, &missed), vec![a[1]]);
        assert_eq!(
            reg.get(&a[1]).unwrap().status,
            ValidatorRegistryStatus::PendingExit
        );
        assert_eq!(
            reg.get(&a[0]).unwrap().status,
            ValidatorRegistryStatus::Active
        );
    }

    #[test]
    fn ejection_is_off_when_governance_sets_the_limit_to_zero() {
        let (reg, a) = active_registry(3);
        let policy = InactivityPolicy {
            max_missed_epochs: 0,
            keep_active_at_least: 1,
        };
        let missed = std::collections::HashMap::from([(a[0], 1000)]);
        assert!(reg.eject_inactive(&policy, &missed).is_empty());
    }

    #[test]
    fn ejection_never_empties_the_set_below_the_governed_floor() {
        let (reg, a) = active_registry(6);
        let policy = InactivityPolicy {
            max_missed_epochs: 1,
            keep_active_at_least: 5,
        };
        // all six absent; longest absent goes first, then the floor stops it
        let missed = std::collections::HashMap::from([
            (a[0], 5),
            (a[1], 9),
            (a[2], 7),
            (a[3], 5),
            (a[4], 5),
            (a[5], 5),
        ]);
        assert_eq!(reg.eject_inactive(&policy, &missed), vec![a[1]]);
    }

    fn registry_with_stakes(stakes: &[u128]) -> (ValidatorRegistry, Vec<Address>) {
        let reg = ValidatorRegistry::new();
        let mut addrs = Vec::new();
        for (i, stake) in stakes.iter().enumerate() {
            let (ck, pk, nk) = make_keys();
            let a = make_address(i as u8 + 1);
            reg.register_candidate(a, ck, pk, nk, a, *stake, 0, String::new())
                .unwrap();
            addrs.push(a);
        }
        for e in 1..=(stakes.len() as u64 + 2) {
            reg.compute_epoch_transition(e);
        }
        (reg, addrs)
    }

    /// Counterexample from the membership model (bug 1): with a floor below
    /// the launch minimum, validators absent one after another used to shrink
    /// an accepted set of 5 to 3, which has no spare.
    #[test]
    fn ejection_never_takes_an_accepted_set_below_the_launch_minimum() {
        let (reg, a) = active_registry(5);
        let policy = InactivityPolicy {
            max_missed_epochs: 1,
            keep_active_at_least: 1, // a floor far below the launch minimum
        };
        let missed: std::collections::HashMap<_, _> = a.iter().map(|x| (*x, 9)).collect();
        let ejected = reg.eject_inactive(&policy, &missed);
        assert_eq!(ejected.len(), 1, "5 accepted members lose one, not more");
        let left: Vec<_> = a
            .iter()
            .filter(|x| reg.get(x).unwrap().status == ValidatorRegistryStatus::Active)
            .collect();
        assert!(left.len() >= tenzro_types::launch_rule::MIN_LAUNCH_VALIDATORS);
    }

    /// Counterexample (bug 2): stakes [2,1,1,1,1,1,1] with a count floor of
    /// 4 could eject down to [2,1,1,1], which fails the stake-weighted spare
    /// rule. The guard stops before that.
    #[test]
    fn ejection_uses_the_stake_weighted_rule_not_a_member_count() {
        let big = DEFAULT_MIN_VALIDATOR_SELF_STAKE;
        let (reg, a) = registry_with_stakes(&[big * 2, big, big, big, big, big, big]);
        let policy = InactivityPolicy {
            max_missed_epochs: 1,
            keep_active_at_least: 4,
        };
        // the five light validators are absent, longest first; the heavy one is not.
        let missed: std::collections::HashMap<_, _> = a[1..]
            .iter()
            .enumerate()
            .map(|(i, x)| (*x, 10 - i as u64))
            .collect();
        reg.eject_inactive(&policy, &missed);
        let stakes: Vec<u128> = a
            .iter()
            .filter(|x| reg.get(x).unwrap().status == ValidatorRegistryStatus::Active)
            .map(|x| reg.get(x).unwrap().self_stake)
            .collect();
        assert!(
            tenzro_types::launch_rule::all_live_set_accepted(&stakes),
            "left {stakes:?}"
        );
    }

    /// Review case D2: the heavy absent validator cannot be ejected (without
    /// it [4,4,3,1] has no spare) but the lightest absent one can ([5,4,4,3]
    /// keeps one). The old loop stopped at the heavy one and ejected nothing.
    #[test]
    fn a_refused_candidate_does_not_block_the_next_eligible_one() {
        let m = DEFAULT_MIN_VALIDATOR_SELF_STAKE;
        let (reg, a) = registry_with_stakes(&[m * 5, m * 4, m * 4, m * 3, m]);
        let policy = InactivityPolicy {
            max_missed_epochs: 1,
            keep_active_at_least: 1,
        };
        let missed = std::collections::HashMap::from([(a[0], 9), (a[4], 5)]);
        let ejected = reg.eject_inactive(&policy, &missed);
        assert_eq!(ejected, vec![a[4]]);
        assert_eq!(
            reg.get(&a[0]).unwrap().status,
            ValidatorRegistryStatus::Active
        );
    }

    /// When every absent validator's removal is refused nothing is ejected.
    #[test]
    fn ejection_with_every_candidate_refused_ejects_nobody() {
        let (reg, a) = active_registry(4); // 4 equal: removing any leaves 3, refused
        let policy = InactivityPolicy {
            max_missed_epochs: 1,
            keep_active_at_least: 1,
        };
        let missed: std::collections::HashMap<_, _> = a.iter().map(|x| (*x, 9)).collect();
        assert!(reg.eject_inactive(&policy, &missed).is_empty());
    }

    /// With one more validator than the governed floor, exactly one goes.
    #[test]
    fn ejection_at_the_floor_plus_one_ejects_exactly_one() {
        let (reg, a) = active_registry(6);
        let policy = InactivityPolicy {
            max_missed_epochs: 1,
            keep_active_at_least: 5,
        };
        let missed: std::collections::HashMap<_, _> = a.iter().map(|x| (*x, 9)).collect();
        assert_eq!(reg.eject_inactive(&policy, &missed).len(), 1);
    }

    /// A registry whose validators hold no stake has no voting power: the
    /// guard refuses every removal, so ejection acts on nobody.
    #[test]
    fn an_all_zero_stake_registry_ejects_nobody() {
        let (reg, a) = registry_with_stakes(&[0, 0, 0, 0, 0]);
        let policy = InactivityPolicy {
            max_missed_epochs: 1,
            keep_active_at_least: 1,
        };
        let missed: std::collections::HashMap<_, _> = a.iter().map(|x| (*x, 9)).collect();
        assert!(reg.eject_inactive(&policy, &missed).is_empty());
    }

    #[test]
    fn the_default_floor_is_the_launch_minimum() {
        assert_eq!(
            DEFAULT_ACTIVE_SET_FLOOR,
            tenzro_types::launch_rule::MIN_LAUNCH_VALIDATORS as u64
        );
    }

    /// The slash path removes a counted validator without a guard; the
    /// registry reports whether the remaining set still holds the rule.
    #[test]
    fn a_slash_that_leaves_no_spare_is_reported() {
        let (reg, a) = active_registry(4);
        assert!(!reg.set_without_is_accepted(&a[0])); // 3 members: below the minimum
        let (reg7, b) = active_registry(7);
        assert!(reg7.set_without_is_accepted(&b[0]));
    }

    #[test]
    fn jail_forces_exit() {
        let reg = ValidatorRegistry::new();
        let (ck, pk, nk) = make_keys();
        let a = make_address(1);
        reg.register_candidate(
            a,
            ck,
            pk,
            nk,
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
        assert_eq!(
            reg.get(&a).unwrap().jailed_until_epoch,
            Some(2 + DEFAULT_JAIL_TERM_EPOCHS)
        );
    }

    /// A registry holding one jailed validator (address 1, jailed at epoch 2).
    fn jailed_registry(term: u64) -> (ValidatorRegistry, Address) {
        let reg = ValidatorRegistry::new();
        let mut cfg = reg.config();
        cfg.jail_term_epochs = term;
        reg.set_config(cfg);
        let (ck, pk, nk) = make_keys();
        let a = make_address(1);
        reg.register_candidate(
            a,
            ck,
            pk,
            nk,
            a,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            0,
            String::new(),
        )
        .unwrap();
        reg.compute_epoch_transition(1);
        reg.compute_epoch_transition(2);
        reg.jail(&a, 2).unwrap();
        (reg, a)
    }

    #[test]
    fn a_jailed_validator_is_released_when_the_term_runs_out() {
        let (reg, a) = jailed_registry(10);
        let never = |_: &Address, _: u64| false;
        assert!(reg.release_jailed(11, &never).is_empty());
        assert_eq!(reg.get(&a).unwrap().status, ValidatorRegistryStatus::Jailed);
        assert_eq!(reg.get(&a).unwrap().jailed_until_epoch, Some(12));
        assert_eq!(reg.release_jailed(12, &never), vec![a]);
        let e = reg.get(&a).unwrap();
        assert_eq!(e.status, ValidatorRegistryStatus::Candidate);
        assert_eq!((e.jailed_until_epoch, e.exited_at_epoch), (None, None));
        // The released validator is admitted again by the ordinary churn cap.
        let plan = reg.compute_epoch_transition(13);
        assert_eq!(plan.activations, vec![a]);
    }

    #[test]
    fn a_governed_reinstatement_releases_a_jailed_validator_before_its_term() {
        let (reg, a) = jailed_registry(DEFAULT_JAIL_TERM_EPOCHS);
        let reinstated = |who: &Address, jailed_at: u64| *who == a && jailed_at == 2;
        assert_eq!(reg.release_jailed(5, &reinstated), vec![a]);
        assert_eq!(
            reg.get(&a).unwrap().status,
            ValidatorRegistryStatus::Candidate
        );
    }

    #[test]
    fn a_shorter_governed_term_applies_to_a_validator_already_jailed() {
        let (reg, a) = jailed_registry(DEFAULT_JAIL_TERM_EPOCHS);
        let mut cfg = reg.config();
        cfg.jail_term_epochs = 3;
        reg.set_config(cfg);
        let never = |_: &Address, _: u64| false;
        assert!(reg.release_jailed(4, &never).is_empty());
        assert_eq!(reg.get(&a).unwrap().jailed_until_epoch, Some(5));
        assert_eq!(reg.release_jailed(5, &never), vec![a]);
    }

    #[test]
    fn jailing_a_jailed_validator_again_does_not_restart_its_term() {
        let (reg, a) = jailed_registry(10);
        reg.jail(&a, 9).unwrap();
        let e = reg.get(&a).unwrap();
        assert_eq!(
            (e.exited_at_epoch, e.jailed_until_epoch),
            (Some(2), Some(12))
        );
    }

    #[test]
    fn churn_cap_limits_activations() {
        let reg = ValidatorRegistry::new();
        // Set up 5 active validators by hand so the cap (4% of 5 = 0, floored
        // to MIN_CHURN_PER_EPOCH = 1) admits exactly one new candidate.
        for i in 1..=5u8 {
            let (ck, pk, nk) = make_keys();
            let a = make_address(i);
            reg.register_candidate(
                a,
                ck,
                pk,
                nk,
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
            let (ck, pk, nk) = make_keys();
            let a = make_address(i);
            reg.register_candidate(
                a,
                ck,
                pk,
                nk,
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

    fn active_set(stakes: &[(u8, u128)]) -> ValidatorRegistry {
        let reg = ValidatorRegistry::new();
        for (i, stake) in stakes {
            let (ck, pk, nk) = make_keys();
            let a = make_address(*i);
            reg.register_candidate(a, ck, pk, nk, a, *stake, 0, String::new())
                .unwrap();
            reg.entries.get_mut(&a).unwrap().status = ValidatorRegistryStatus::Active;
        }
        reg
    }

    /// When more validators wait to exit than the exit budget allows, every
    /// registry finalises the same ones (lowest address first), whatever its
    /// map's iteration order, and the others stay `PendingExit` without ever
    /// having been recorded as `Exited`.
    #[test]
    fn the_exit_cap_picks_the_same_exits_on_every_node() {
        let stakes: Vec<(u8, u128)> = (1..=20u8)
            .map(|i| (i, DEFAULT_MIN_VALIDATOR_SELF_STAKE))
            .collect();
        // 4% of 20 equal stakes is under one validator's, so exactly one
        // exit completes.
        for _ in 0..16 {
            let reg = active_set(&stakes);
            for i in [17u8, 4, 11] {
                reg.request_exit(&make_address(i)).unwrap();
            }
            let plan = reg.compute_epoch_transition(1);
            assert_eq!(plan.effective_exits, vec![make_address(4)]);
            assert_eq!(plan.exits, vec![make_address(11), make_address(17)]);
            for i in [11u8, 17] {
                let e = reg.get(&make_address(i)).unwrap();
                assert_eq!(e.status, ValidatorRegistryStatus::PendingExit);
                assert_eq!(e.exited_at_epoch, None);
            }
        }
    }

    /// A third of the stake asks to leave at once: each epoch lets out at
    /// most `exit_churn_bps` of the active set's stake (or a single
    /// validator, when one alone is larger), until every exit completes.
    #[test]
    fn exits_are_paced_by_stake_not_by_head_count() {
        let unit = DEFAULT_MIN_VALIDATOR_SELF_STAKE;
        // 20 validators of five units and 50 of one: the 50 small ones,
        // a third of the stake, ask to leave at once.
        let stakes: Vec<(u8, u128)> = (1..=70u8)
            .map(|i| (i, if i <= 20 { 5 * unit } else { unit }))
            .collect();
        let leaving: Vec<u8> = (21..=70).collect();
        let reg = active_set(&stakes);
        for i in &leaving {
            reg.request_exit(&make_address(*i)).unwrap();
        }
        let cfg = reg.config();
        assert_eq!(cfg.exit_churn_bps, DEFAULT_EXIT_CHURN_BPS);
        let mut epoch = 1;
        let mut done = 0;
        while done < leaving.len() {
            let total: u128 = reg
                .entries
                .iter()
                .filter(|e| e.value().status.counts_toward_active())
                .map(|e| e.value().self_stake)
                .sum();
            let budget = total * u128::from(cfg.exit_churn_bps) / 10_000;
            let plan = reg.compute_epoch_transition(epoch);
            let out: Vec<u128> = plan
                .effective_exits
                .iter()
                .map(|a| reg.get(a).unwrap().self_stake)
                .collect();
            assert!(!out.is_empty(), "an exit completes every epoch");
            let sum: u128 = out.iter().sum();
            assert!(
                sum <= budget || out.len() == 1,
                "epoch {epoch}: {sum} left against a budget of {budget}"
            );
            done += out.len();
            epoch += 1;
            assert!(epoch < 100);
        }
        // By head count, 4% of 70 is two a epoch: 25 epochs. By stake the
        // small validators leave several at a time.
        assert!(epoch - 1 <= 13, "{} epochs", epoch - 1);
    }

    #[test]
    fn a_recovery_replaces_the_active_set_and_is_idempotent() {
        let reg = ValidatorRegistry::new();
        let (ml, p, nk) = make_keys();
        for seed in 1..=4u8 {
            reg.seed_genesis_active(
                make_address(seed),
                ml.clone(),
                p.clone(),
                nk,
                make_address(seed),
                100,
                String::new(),
            )
            .unwrap();
        }
        // Two of the four stay, one new member joins.
        let members: Vec<RecoveryMember> = [1u8, 2, 9]
            .iter()
            .map(|s| RecoveryMember {
                address: make_address(*s),
                ml_dsa_pubkey: ml.clone(),
                p256_pubkey: p.clone(),
                node_key: [*s; 32],
                self_stake: 700,
            })
            .collect();
        reg.replace_active_set(&members, 12).unwrap();
        let status = |s: u8| reg.get(&make_address(s)).map(|e| e.status);
        assert_eq!(status(1), Some(ValidatorRegistryStatus::Active));
        assert_eq!(status(9), Some(ValidatorRegistryStatus::Active));
        assert_eq!(status(3), Some(ValidatorRegistryStatus::Exited));
        assert_eq!(status(4), Some(ValidatorRegistryStatus::Exited));
        assert_eq!(reg.get(&make_address(3)).unwrap().exited_at_epoch, Some(12));
        assert_eq!(reg.get(&make_address(1)).unwrap().self_stake, 700);
        assert_eq!(reg.list_active().len(), 3);

        let snapshot = || -> Vec<Vec<u8>> {
            let mut l = reg.list();
            l.sort_by(|a, b| a.address.as_bytes().cmp(b.address.as_bytes()));
            l.into_iter()
                .map(|mut e| {
                    e.updated_at = Timestamp::default();
                    bincode::serialize(&e).unwrap()
                })
                .collect()
        };
        let before = snapshot();
        reg.replace_active_set(&members, 12).unwrap();
        assert_eq!(before, snapshot());
    }
}
