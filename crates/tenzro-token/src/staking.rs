//! Staking system for validators and service providers
//!
//! This module implements staking mechanics for validators, inference providers,
//! and TEE providers with unbonding periods and slashing.

use crate::error::{Result, TokenError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_types::token::ProviderType;
use tracing::{info, warn};

/// Default unbonding period: 7 days in milliseconds
pub const DEFAULT_UNBONDING_PERIOD_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Default minimum stake: 1000 TNZO
pub const DEFAULT_MIN_STAKE: u128 = 1000 * 1_000_000_000_000_000_000; // 1000 * 10^18

/// Staking information for a provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeInfo {
    /// Staker address
    pub staker: Address,
    /// Amount staked
    pub amount: u128,
    /// Provider type
    pub provider_type: ProviderType,
    /// Timestamp when staked
    pub staked_at: Timestamp,
    /// Unbonding timestamp (if unbonding)
    pub unbonding_at: Option<Timestamp>,
    /// Slashing history
    pub slashing_history: Vec<SlashEvent>,
    /// Restoration history (governance-authorized un-slashings)
    #[serde(default)]
    pub restoration_history: Vec<RestoreEvent>,
    /// Total rewards earned
    pub total_rewards: u128,
    /// Stake status
    pub status: StakeStatus,
    /// Kill-switch lifecycle freeze (Agent-Swarm Spec 1).
    ///
    /// Set by the node post-execute scan when a `KillSwitchPause` or
    /// `KillSwitchQuarantine` log is observed for the machine DID that
    /// owns this stake address; cleared on `ResumedFromPause` /
    /// `ResumedFromQuarantine`. While frozen, `unstake`, `withdraw`, and
    /// reward accrual are rejected. `slash` is not gated — terminate
    /// flow needs to slash even when frozen.
    #[serde(default)]
    pub lifecycle_freeze: bool,
}

impl StakeInfo {
    /// Creates a new stake info
    pub fn new(staker: Address, amount: u128, provider_type: ProviderType) -> Self {
        Self {
            staker,
            amount,
            provider_type,
            staked_at: Timestamp::now(),
            unbonding_at: None,
            slashing_history: Vec::new(),
            restoration_history: Vec::new(),
            total_rewards: 0,
            status: StakeStatus::Active,
            lifecycle_freeze: false,
        }
    }

    /// Checks if the stake is locked (either active or unbonding)
    pub fn is_locked(&self) -> bool {
        matches!(self.status, StakeStatus::Active | StakeStatus::Unbonding)
    }

    /// Checks if unbonding period has completed
    pub fn is_unbonding_complete(&self) -> bool {
        if let Some(unbonding_at) = self.unbonding_at {
            Timestamp::now() >= unbonding_at
        } else {
            false
        }
    }

    /// Adds a slash event
    ///
    /// Note: Caller must verify `self.amount >= event.amount` before calling.
    pub fn add_slash(&mut self, event: SlashEvent) {
        self.amount = self.amount.checked_sub(event.amount)
            .expect("BUG: add_slash called without prior balance check");
        self.slashing_history.push(event);
    }

    /// Adds rewards.
    ///
    /// Rejected when the stake is under a kill-switch lifecycle freeze
    /// (Paused / Quarantined). The terminate path slashes via
    /// `StakingManager::slash` directly and never reaches this method.
    pub fn add_rewards(&mut self, amount: u128) -> Result<()> {
        if self.lifecycle_freeze {
            return Err(TokenError::InvalidAmount(format!(
                "stake for {} is frozen by kill-switch; rewards rejected",
                self.staker
            )));
        }
        self.total_rewards = self.total_rewards.checked_add(amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "stake add_rewards".to_string(),
            })?;
        Ok(())
    }
}

/// Slash event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashEvent {
    /// Timestamp of slash
    pub timestamp: Timestamp,
    /// Amount slashed
    pub amount: u128,
    /// Reason for slashing
    pub reason: String,
    /// Slashed by (validator/system address)
    pub slashed_by: Address,
}

impl SlashEvent {
    /// Creates a new slash event
    pub fn new(amount: u128, reason: String, slashed_by: Address) -> Self {
        Self {
            timestamp: Timestamp::now(),
            amount,
            reason,
            slashed_by,
        }
    }
}

/// Governance-authorized restoration of previously slashed stake.
///
/// Used as an audit trail for the (rare) case where a stake was slashed in
/// error — for example, the testnet equivocation cascade at view=62 on
/// 2026-04-27, where validators self-equivocated due to a missing persistent
/// vote-state and were correctly slashed by the protocol, but the underlying
/// fault was a bug, not Byzantine behavior.
///
/// Restoration is gated by an on-chain governance proposal; the
/// `proposal_id` field binds the restoration to the proposal that
/// authorized it for full auditability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreEvent {
    /// Timestamp of restoration
    pub timestamp: Timestamp,
    /// Amount restored
    pub amount: u128,
    /// Governance proposal authorizing the restoration
    pub proposal_id: String,
    /// Reason for restoration
    pub reason: String,
    /// Address that executed the restoration (typically the governance
    /// executor / treasury multisig)
    pub authorized_by: Address,
}

impl RestoreEvent {
    /// Creates a new restoration event
    pub fn new(amount: u128, proposal_id: String, reason: String, authorized_by: Address) -> Self {
        Self {
            timestamp: Timestamp::now(),
            amount,
            proposal_id,
            reason,
            authorized_by,
        }
    }
}

/// Status of a stake
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StakeStatus {
    /// Stake is active
    Active,
    /// Stake is unbonding
    Unbonding,
    /// Stake has been withdrawn
    Withdrawn,
}

/// Staking manager
///
/// Manages staking for validators and service providers.
pub struct StakingManager {
    /// Stakes by address
    stakes: DashMap<Address, StakeInfo>,
    /// Total staked per provider type
    total_staked_by_type: DashMap<ProviderType, u128>,
    /// Minimum stake required
    min_stake: parking_lot::RwLock<u128>,
    /// Unbonding period in milliseconds
    unbonding_period_ms: parking_lot::RwLock<i64>,
    /// Optional persistent storage backend
    storage: Option<Arc<dyn tenzro_storage::KvStore>>,
}

/// Storage key prefix for individual stakes
const STAKE_PREFIX: &str = "stake:";
/// Storage key for staking config
const STAKING_CONFIG_KEY: &str = "staking:config";
/// Storage key for staking index
const STAKING_INDEX_KEY: &str = "staking:index";
/// Column family to use
const STAKING_CF: &str = tenzro_storage::CF_STATE;

/// Helper to convert hex string to Address
fn parse_hex_to_address(hex_str: &str) -> Address {
    let bytes = hex::decode(hex_str).unwrap_or_default();
    let mut addr_bytes = [0u8; 32];
    let len = bytes.len().min(32);
    addr_bytes[..len].copy_from_slice(&bytes[..len]);
    Address::new(addr_bytes)
}

impl StakingManager {
    /// Creates a new staking manager
    pub fn new() -> Self {
        Self {
            stakes: DashMap::new(),
            total_staked_by_type: DashMap::new(),
            min_stake: parking_lot::RwLock::new(DEFAULT_MIN_STAKE),
            unbonding_period_ms: parking_lot::RwLock::new(DEFAULT_UNBONDING_PERIOD_MS),
            storage: None,
        }
    }

    /// Creates a new staking manager with persistent storage
    pub fn with_storage(storage: Arc<dyn tenzro_storage::KvStore>) -> Self {
        let manager = Self {
            stakes: DashMap::new(),
            total_staked_by_type: DashMap::new(),
            min_stake: parking_lot::RwLock::new(DEFAULT_MIN_STAKE),
            unbonding_period_ms: parking_lot::RwLock::new(DEFAULT_UNBONDING_PERIOD_MS),
            storage: Some(storage),
        };

        // Load existing state from storage
        if let Err(e) = manager.load_from_storage() {
            warn!("Failed to load staking state from storage: {}", e);
        }

        manager
    }

    /// Persists a single stake to storage.
    ///
    /// Uses a synced (fsync'd) write: stake mutations include slashing
    /// outcomes that consensus has already acted on — a crash must not
    /// resurrect slashed stake.
    fn persist_stake(&self, address: &Address, stake_info: &StakeInfo) {
        if let Some(storage) = &self.storage {
            let key = format!("{}{}", STAKE_PREFIX, hex::encode(address.as_bytes()));
            match bincode::serialize(stake_info) {
                Ok(data) => {
                    if let Err(e) = storage.write_batch_sync(vec![tenzro_storage::WriteOp::Put {
                        cf: STAKING_CF.to_string(),
                        key: key.into_bytes(),
                        value: data,
                    }]) {
                        warn!("Failed to persist stake for {}: {}", address, e);
                    }
                }
                Err(e) => warn!("Failed to serialize stake for {}: {}", address, e),
            }
        }
    }

    /// Persists total staked for a provider type (synced write — moves with
    /// stake/slash mutations and must survive a crash together with them).
    fn persist_total_staked(&self, provider_type: ProviderType, amount: u128) {
        if let Some(storage) = &self.storage {
            let key = format!("total_staked:{:?}", provider_type);
            if let Err(e) = storage.write_batch_sync(vec![tenzro_storage::WriteOp::Put {
                cf: STAKING_CF.to_string(),
                key: key.into_bytes(),
                value: amount.to_le_bytes().to_vec(),
            }]) {
                warn!("Failed to persist total staked for {:?}: {}", provider_type, e);
            }
        }
    }

    /// Loads all staking state from storage
    fn load_from_storage(&self) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };

        // Load all stakes by scanning the index
        if let Ok(Some(index_data)) = storage.get(STAKING_CF, STAKING_INDEX_KEY.as_bytes()) {
            let addresses: Vec<String> = match bincode::deserialize(&index_data) {
                Ok(a) => a,
                Err(e) => {
                    warn!("Failed to deserialize staking index: {}", e);
                    return Ok(());
                }
            };

            for addr_hex in &addresses {
                let key = format!("{}{}", STAKE_PREFIX, addr_hex);
                if let Ok(Some(data)) = storage.get(STAKING_CF, key.as_bytes()) {
                    match bincode::deserialize::<StakeInfo>(&data) {
                        Ok(stake_info) => {
                            let addr = parse_hex_to_address(addr_hex);

                            // Update total staked
                            if stake_info.status == StakeStatus::Active || stake_info.status == StakeStatus::Unbonding {
                                let mut total = self.total_staked_by_type.entry(stake_info.provider_type).or_insert(0);
                                *total = total.checked_add(stake_info.amount).unwrap_or(u128::MAX);
                            }

                            self.stakes.insert(addr, stake_info);
                        }
                        Err(e) => warn!("Failed to deserialize stake {}: {}", addr_hex, e),
                    }
                }
            }

            info!("Loaded {} stakes from storage", addresses.len());
        }

        // Load staking config
        if let Ok(Some(config_data)) = storage.get(STAKING_CF, STAKING_CONFIG_KEY.as_bytes())
            && config_data.len() >= 24
        {
            let min_stake = u128::from_le_bytes(config_data[0..16].try_into().unwrap());
            let unbonding_ms = i64::from_le_bytes(config_data[16..24].try_into().unwrap());
            *self.min_stake.write() = min_stake;
            *self.unbonding_period_ms.write() = unbonding_ms;
            info!("Loaded staking config: min_stake={}, unbonding_period={}ms", min_stake, unbonding_ms);
        }

        Ok(())
    }

    /// Persists the staker address index
    fn persist_index(&self) {
        if let Some(storage) = &self.storage {
            let addresses: Vec<String> = self.stakes.iter()
                .map(|entry| hex::encode(entry.key().as_bytes()))
                .collect();

            match bincode::serialize(&addresses) {
                Ok(data) => {
                    if let Err(e) = storage.write_batch_sync(vec![tenzro_storage::WriteOp::Put {
                        cf: STAKING_CF.to_string(),
                        key: STAKING_INDEX_KEY.as_bytes().to_vec(),
                        value: data,
                    }]) {
                        warn!("Failed to persist staking index: {}", e);
                    }
                }
                Err(e) => warn!("Failed to serialize staking index: {}", e),
            }
        }
    }

    /// Persists staking config (min_stake and unbonding period)
    fn persist_config(&self) {
        if let Some(storage) = &self.storage {
            let min_stake = *self.min_stake.read();
            let unbonding_ms = *self.unbonding_period_ms.read();

            let mut config_data = Vec::with_capacity(24);
            config_data.extend_from_slice(&min_stake.to_le_bytes());
            config_data.extend_from_slice(&unbonding_ms.to_le_bytes());

            if let Err(e) = storage.write_batch_sync(vec![tenzro_storage::WriteOp::Put {
                cf: STAKING_CF.to_string(),
                key: STAKING_CONFIG_KEY.as_bytes().to_vec(),
                value: config_data,
            }]) {
                warn!("Failed to persist staking config: {}", e);
            }
        }
    }

    /// Stakes tokens for a provider
    ///
    /// # Arguments
    ///
    /// * `staker` - Address staking
    /// * `amount` - Amount to stake
    /// * `provider_type` - Type of provider
    pub fn stake(&self, staker: Address, amount: u128, provider_type: ProviderType) -> Result<()> {
        // Validate minimum stake
        let min_stake = *self.min_stake.read();
        if amount < min_stake {
            return Err(TokenError::MinimumStakeNotMet {
                required: min_stake,
                provided: amount,
            });
        }

        // Check if already staked
        if let Some(existing) = self.stakes.get(&staker)
            && existing.is_locked()
        {
            return Err(TokenError::InvalidAmount(
                "Already have an active stake. Unstake first.".to_string(),
            ));
        }

        // Create stake info
        let stake_info = StakeInfo::new(staker, amount, provider_type);
        self.stakes.insert(staker, stake_info.clone());

        // Update total staked
        let mut total = self.total_staked_by_type.entry(provider_type).or_insert(0);
        *total = total.checked_add(amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "staking total staked".to_string(),
            })?;

        // Persist to storage
        self.persist_stake(&staker, &stake_info);
        self.persist_total_staked(provider_type, *total);
        self.persist_index();

        info!("Staked {} for {:?} provider at {}", amount, provider_type, staker);
        Ok(())
    }

    /// Initiates unstaking (starts unbonding period)
    ///
    /// # Arguments
    ///
    /// * `staker` - Address unstaking
    pub fn unstake(&self, staker: &Address) -> Result<()> {
        let mut stake = self.stakes.get_mut(staker)
            .ok_or_else(|| TokenError::StakeNotFound {
                address: staker.to_string(),
            })?;

        // Kill-switch lifecycle freeze (Agent-Swarm Spec 1). Pause /
        // quarantine block voluntary unstake; only `slash` (called by the
        // terminate handler) can move funds out of a frozen stake.
        if stake.lifecycle_freeze {
            return Err(TokenError::InvalidAmount(format!(
                "stake for {} is frozen by kill-switch; unstake rejected",
                staker
            )));
        }

        // Check if already unbonding
        if stake.status == StakeStatus::Unbonding {
            return Err(TokenError::InvalidAmount(
                "Already unbonding".to_string()
            ));
        }

        if stake.status != StakeStatus::Active {
            return Err(TokenError::InvalidAmount(
                "Stake is not active".to_string()
            ));
        }

        // Set unbonding period
        let unbonding_period = *self.unbonding_period_ms.read();
        let unbonding_at = Timestamp::new(Timestamp::now().as_millis() + unbonding_period);
        stake.unbonding_at = Some(unbonding_at);
        stake.status = StakeStatus::Unbonding;

        // Clone before persisting to avoid holding the RefMut
        let stake_clone = stake.clone();
        drop(stake); // Drop the DashMap RefMut before calling persist

        // Persist updated stake
        self.persist_stake(staker, &stake_clone);

        info!("Initiated unstaking for {}. Unbonding completes at {}", staker, unbonding_at);
        Ok(())
    }

    /// Completes withdrawal after unbonding period
    ///
    /// # Arguments
    ///
    /// * `staker` - Address withdrawing stake
    ///
    /// Returns the withdrawn amount
    pub fn withdraw(&self, staker: &Address) -> Result<u128> {
        let mut stake = self.stakes.get_mut(staker)
            .ok_or_else(|| TokenError::StakeNotFound {
                address: staker.to_string(),
            })?;

        // Kill-switch freeze blocks completion of an in-flight unbonding
        // window — a controller can pause/quarantine a validator that is
        // already unbonding to keep stake claimable for slash.
        if stake.lifecycle_freeze {
            return Err(TokenError::InvalidAmount(format!(
                "stake for {} is frozen by kill-switch; withdraw rejected",
                staker
            )));
        }

        // Check unbonding status
        if stake.status != StakeStatus::Unbonding {
            return Err(TokenError::InvalidAmount(
                "Stake must be unbonding to withdraw".to_string()
            ));
        }

        // Check if unbonding period is complete
        if !stake.is_unbonding_complete() {
            let unbonding_at = stake.unbonding_at.unwrap();
            return Err(TokenError::StakeLocked {
                unlock_time: unbonding_at.as_millis(),
            });
        }

        let amount = stake.amount;
        let provider_type = stake.provider_type;

        // Update status
        stake.status = StakeStatus::Withdrawn;
        stake.amount = 0;

        // Clone before persisting to avoid holding the RefMut
        let stake_clone = stake.clone();
        drop(stake); // Drop the DashMap RefMut before calling persist

        // Update total staked
        let new_total = if let Some(mut total) = self.total_staked_by_type.get_mut(&provider_type) {
            *total = total.checked_sub(amount)
                .ok_or_else(|| TokenError::ArithmeticOverflow {
                    operation: "staking withdraw total".to_string(),
                })?;
            *total
        } else {
            0
        };

        // Persist updated stake
        self.persist_stake(staker, &stake_clone);
        self.persist_total_staked(provider_type, new_total);

        info!("Withdrew {} from stake for {}", amount, staker);
        Ok(amount)
    }

    /// Slashes a stake
    ///
    /// # Arguments
    ///
    /// * `staker` - Address to slash
    /// * `amount` - Amount to slash
    /// * `reason` - Reason for slashing
    /// * `slashed_by` - Address performing the slash
    ///
    /// Note: Slashing enforces the minimum unbonding period. The slashed stake
    /// cannot be withdrawn until the full unbonding period has elapsed from the
    /// slash event, even if it was already unbonding.
    pub fn slash(&self, staker: &Address, amount: u128, reason: String, slashed_by: Address) -> Result<()> {
        let mut stake = self.stakes.get_mut(staker)
            .ok_or_else(|| TokenError::StakeNotFound {
                address: staker.to_string(),
            })?;

        if stake.amount < amount {
            return Err(TokenError::InsufficientStake {
                required: amount,
                available: stake.amount,
            });
        }

        // Enforce minimum stake after slashing (safe: checked above that stake.amount >= amount)
        let min_stake = *self.min_stake.read();
        let new_amount = stake.amount.checked_sub(amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "staking slash amount".to_string(),
            })?;

        // If slashing would bring stake below minimum and stake is active,
        // force it into unbonding state with fresh unbonding period
        if new_amount > 0 && new_amount < min_stake && stake.status == StakeStatus::Active {
            let unbonding_period = *self.unbonding_period_ms.read();
            let unbonding_at = Timestamp::new(Timestamp::now().as_millis() + unbonding_period);
            stake.unbonding_at = Some(unbonding_at);
            stake.status = StakeStatus::Unbonding;
            warn!(
                "Slashing {} brought stake below minimum {}. Forcing unbonding until {}",
                staker, min_stake, unbonding_at
            );
        }

        // If already unbonding, reset the unbonding period (penalty for misbehavior)
        if stake.status == StakeStatus::Unbonding {
            let unbonding_period = *self.unbonding_period_ms.read();
            let new_unbonding_at = Timestamp::new(Timestamp::now().as_millis() + unbonding_period);
            stake.unbonding_at = Some(new_unbonding_at);
            warn!(
                "Slashing {} reset unbonding period to {}",
                staker, new_unbonding_at
            );
        }

        // Create slash event
        let slash_event = SlashEvent::new(amount, reason.clone(), slashed_by);

        // Update stake
        let provider_type = stake.provider_type;
        stake.add_slash(slash_event);

        // Clone before persisting to avoid holding the RefMut
        let stake_clone = stake.clone();
        drop(stake); // Drop the DashMap RefMut before calling persist

        // Update total staked
        let new_total = if let Some(mut total) = self.total_staked_by_type.get_mut(&provider_type) {
            *total = total.checked_sub(amount)
                .ok_or_else(|| TokenError::ArithmeticOverflow {
                    operation: "staking slash total".to_string(),
                })?;
            *total
        } else {
            0
        };

        // Persist updated stake
        self.persist_stake(staker, &stake_clone);
        self.persist_total_staked(provider_type, new_total);

        warn!("Slashed {} from {} for reason: {}", amount, staker, reason);
        Ok(())
    }

    /// Restores previously-slashed stake under governance authorization.
    ///
    /// This is intended for the rare case where the protocol slashed a
    /// validator due to a bug (e.g., the equivocation cascade at view=62
    /// on 2026-04-27 caused by a missing persistent vote-state, *not*
    /// Byzantine intent). The restoration must be authorized by an
    /// on-chain governance proposal — `proposal_id` is required and
    /// recorded on the audit trail. The caller is responsible for
    /// verifying the proposal has passed and that `authorized_by` is the
    /// legitimate executor of that proposal; this manager does not own
    /// governance state.
    ///
    /// # Arguments
    ///
    /// * `staker` - Address whose stake is being restored
    /// * `amount` - Amount to add back to the stake
    /// * `proposal_id` - Governance proposal authorizing the restoration
    ///   (non-empty; required for audit)
    /// * `reason` - Human-readable reason
    /// * `authorized_by` - Address executing the restoration (typically
    ///   the governance executor / treasury multisig)
    ///
    /// # Errors
    ///
    /// * `Unauthorized` if `proposal_id` is empty.
    /// * `InvalidAmount` if `amount` is zero or exceeds the total
    ///   previously-slashed amount on this stake (cannot restore more
    ///   than was slashed).
    /// * `StakeNotFound` if no stake exists for `staker`.
    /// * `ArithmeticOverflow` on amount overflow.
    pub fn restore_slashed_stake(
        &self,
        staker: &Address,
        amount: u128,
        proposal_id: String,
        reason: String,
        authorized_by: Address,
    ) -> Result<()> {
        // Governance gate: require a non-empty proposal_id binding this
        // restoration to a passed on-chain governance vote.
        if proposal_id.trim().is_empty() {
            return Err(TokenError::Unauthorized {
                reason: "restore_slashed_stake requires a governance proposal_id".to_string(),
            });
        }
        if amount == 0 {
            return Err(TokenError::InvalidAmount(
                "restore amount must be positive".to_string(),
            ));
        }

        let mut stake = self.stakes.get_mut(staker)
            .ok_or_else(|| TokenError::StakeNotFound {
                address: staker.to_string(),
            })?;

        // Cap restoration at the cumulative slashed amount minus what has
        // already been restored — cannot mint more than was slashed.
        let total_slashed: u128 = stake.slashing_history.iter()
            .map(|s| s.amount)
            .fold(0u128, |acc, a| acc.saturating_add(a));
        let total_restored: u128 = stake.restoration_history.iter()
            .map(|r| r.amount)
            .fold(0u128, |acc, a| acc.saturating_add(a));
        let restorable = total_slashed.saturating_sub(total_restored);
        if amount > restorable {
            return Err(TokenError::InvalidAmount(format!(
                "restore amount {} exceeds restorable {} (total_slashed={}, already_restored={})",
                amount, restorable, total_slashed, total_restored
            )));
        }

        // Add amount back to the stake balance.
        let new_amount = stake.amount.checked_add(amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "staking restore amount".to_string(),
            })?;
        stake.amount = new_amount;

        // Record the restoration event for audit.
        let restore_event = RestoreEvent::new(amount, proposal_id.clone(), reason.clone(), authorized_by);
        stake.restoration_history.push(restore_event);

        // If the stake was forced into Unbonding by a prior slash that
        // brought it below min_stake, and the restoration brings it back
        // above min_stake, allow it to return to Active. Withdrawn stakes
        // stay Withdrawn — restoration into a withdrawn stake is purely
        // accounting (the funds have already left the system).
        let provider_type = stake.provider_type;
        let min_stake = *self.min_stake.read();
        let return_to_active = stake.status == StakeStatus::Unbonding
            && stake.amount >= min_stake;
        if return_to_active {
            stake.status = StakeStatus::Active;
            stake.unbonding_at = None;
            info!(
                "Restoration brought {} back above min_stake {}; returning to Active",
                staker, min_stake
            );
        }

        let counts_toward_total = matches!(
            stake.status,
            StakeStatus::Active | StakeStatus::Unbonding
        );

        // Clone before persisting to avoid holding the RefMut.
        let stake_clone = stake.clone();
        drop(stake);

        // Update total staked only if this stake is in a state that
        // contributes to the total (Active or Unbonding).
        let new_total = if counts_toward_total {
            let mut total = self.total_staked_by_type.entry(provider_type).or_insert(0);
            *total = total.checked_add(amount)
                .ok_or_else(|| TokenError::ArithmeticOverflow {
                    operation: "staking restore total".to_string(),
                })?;
            *total
        } else {
            self.total_staked_by_type
                .get(&provider_type)
                .map(|v| *v)
                .unwrap_or(0)
        };

        // Persist updated stake
        self.persist_stake(staker, &stake_clone);
        if counts_toward_total {
            self.persist_total_staked(provider_type, new_total);
        }

        info!(
            "Restored {} TNZO to {} under governance proposal {} (reason: {})",
            amount, staker, proposal_id, reason
        );
        Ok(())
    }

    /// Freezes a stake under kill-switch authority (Agent-Swarm Spec 1).
    ///
    /// Called by the node post-execute scan when a `KillSwitchPause` or
    /// `KillSwitchQuarantine` log is observed for the machine DID that
    /// owns this stake address. While frozen, `unstake`, `withdraw`, and
    /// reward accrual (`add_rewards`) are rejected. Idempotent — freezing
    /// an already-frozen stake is a no-op.
    ///
    /// `slash` is intentionally NOT gated by `lifecycle_freeze`: the
    /// terminate flow must be able to slash a frozen stake.
    pub fn freeze_stake(&self, staker: &Address) -> Result<()> {
        let mut stake = self.stakes.get_mut(staker)
            .ok_or_else(|| TokenError::StakeNotFound {
                address: staker.to_string(),
            })?;

        if stake.lifecycle_freeze {
            return Ok(());
        }
        stake.lifecycle_freeze = true;

        let stake_clone = stake.clone();
        drop(stake);

        self.persist_stake(staker, &stake_clone);
        warn!("Froze stake for {} under kill-switch authority", staker);
        Ok(())
    }

    /// Thaws a previously-frozen stake (Agent-Swarm Spec 1).
    ///
    /// Called by the node post-execute scan when a `ResumedFromPause` or
    /// `ResumedFromQuarantine` log is observed. Idempotent — thawing an
    /// already-thawed stake is a no-op.
    pub fn thaw_stake(&self, staker: &Address) -> Result<()> {
        let mut stake = self.stakes.get_mut(staker)
            .ok_or_else(|| TokenError::StakeNotFound {
                address: staker.to_string(),
            })?;

        if !stake.lifecycle_freeze {
            return Ok(());
        }
        stake.lifecycle_freeze = false;

        let stake_clone = stake.clone();
        drop(stake);

        self.persist_stake(staker, &stake_clone);
        info!("Thawed stake for {} (kill-switch released)", staker);
        Ok(())
    }

    /// Returns stake information for an address
    pub fn get_stake(&self, staker: &Address) -> Option<StakeInfo> {
        self.stakes.get(staker).map(|s| s.clone())
    }

    /// Returns total staked for a provider type
    pub fn get_total_staked(&self, provider_type: ProviderType) -> u128 {
        self.total_staked_by_type.get(&provider_type).map(|v| *v).unwrap_or(0)
    }

    /// Returns total staked across all provider types
    pub fn get_total_staked_all(&self) -> u128 {
        self.total_staked_by_type.iter().map(|entry| *entry.value()).sum()
    }

    /// Returns the cumulative slash burn across all stakes, net of any
    /// governance restorations. Computed by summing `slashing_history` and
    /// subtracting `restore_history` per stake.
    ///
    /// Saturating arithmetic — `u128` can hold the full TNZO supply (1B
    /// scaled by 1e18) many times over, so an overflow here would indicate
    /// data corruption rather than legitimate flow. Consumed by the
    /// adaptive-burn observer at every epoch boundary to populate
    /// `BurnBreakdown.slash`.
    pub fn total_slashed(&self) -> u128 {
        self.stakes
            .iter()
            .map(|entry| {
                let stake = entry.value();
                let slashed: u128 = stake
                    .slashing_history
                    .iter()
                    .map(|s| s.amount)
                    .fold(0u128, |a, b| a.saturating_add(b));
                let restored: u128 = stake
                    .restoration_history
                    .iter()
                    .map(|r| r.amount)
                    .fold(0u128, |a, b| a.saturating_add(b));
                slashed.saturating_sub(restored)
            })
            .fold(0u128, |a, b| a.saturating_add(b))
    }

    /// Updates minimum stake requirement
    pub fn set_min_stake(&self, min_stake: u128) {
        *self.min_stake.write() = min_stake;
        self.persist_config();
        info!("Updated minimum stake to {}", min_stake);
    }

    /// Updates unbonding period
    pub fn set_unbonding_period(&self, period_ms: i64) {
        *self.unbonding_period_ms.write() = period_ms;
        self.persist_config();
        info!("Updated unbonding period to {} ms", period_ms);
    }

    /// Returns all active stakes
    pub fn get_all_stakes(&self) -> Vec<(Address, StakeInfo)> {
        self.stakes
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect()
    }
}

impl Default for StakingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for StakingManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StakingManager")
            .field("stakes_count", &self.stakes.len())
            .field("min_stake", &self.min_stake)
            .field("unbonding_period_ms", &self.unbonding_period_ms)
            .field("has_storage", &self.storage.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::RocksDbStore;

    #[test]
    fn test_stake() {
        let manager = StakingManager::new();
        let staker = Address::new([1u8; 32]);
        let amount = DEFAULT_MIN_STAKE;

        manager.stake(staker, amount, ProviderType::Validator).unwrap();

        let stake_info = manager.get_stake(&staker).unwrap();
        assert_eq!(stake_info.amount, amount);
        assert_eq!(stake_info.status, StakeStatus::Active);
    }

    #[test]
    fn test_unstake() {
        let manager = StakingManager::new();
        let staker = Address::new([1u8; 32]);
        let amount = DEFAULT_MIN_STAKE;

        manager.stake(staker, amount, ProviderType::Validator).unwrap();
        manager.unstake(&staker).unwrap();

        let stake_info = manager.get_stake(&staker).unwrap();
        assert_eq!(stake_info.status, StakeStatus::Unbonding);
        assert!(stake_info.unbonding_at.is_some());
    }

    #[test]
    fn test_slash() {
        let manager = StakingManager::new();
        let staker = Address::new([1u8; 32]);
        let slasher = Address::new([2u8; 32]);
        let amount = DEFAULT_MIN_STAKE;
        let slash_amount = amount / 10; // 10%

        manager.stake(staker, amount, ProviderType::Validator).unwrap();
        manager.slash(&staker, slash_amount, "Misbehavior".to_string(), slasher).unwrap();

        let stake_info = manager.get_stake(&staker).unwrap();
        assert_eq!(stake_info.amount, amount - slash_amount);
        assert_eq!(stake_info.slashing_history.len(), 1);
    }

    #[test]
    fn test_restore_slashed_stake_round_trip() {
        let manager = StakingManager::new();
        let staker = Address::new([1u8; 32]);
        let slasher = Address::new([2u8; 32]);
        let governance = Address::new([3u8; 32]);
        let amount = DEFAULT_MIN_STAKE * 2;
        let slash_amount = amount / 10;

        manager.stake(staker, amount, ProviderType::Validator).unwrap();
        let total_before_slash = manager.get_total_staked(ProviderType::Validator);
        manager
            .slash(&staker, slash_amount, "buggy equivocation detector".to_string(), slasher)
            .unwrap();

        // Restore the full slashed amount under a governance proposal.
        manager
            .restore_slashed_stake(
                &staker,
                slash_amount,
                "TGP-1".to_string(),
                "view=62 cascade was a bug, not Byzantine".to_string(),
                governance,
            )
            .unwrap();

        let stake_info = manager.get_stake(&staker).unwrap();
        assert_eq!(stake_info.amount, amount, "balance fully restored");
        assert_eq!(stake_info.slashing_history.len(), 1);
        assert_eq!(stake_info.restoration_history.len(), 1);
        assert_eq!(stake_info.restoration_history[0].proposal_id, "TGP-1");
        assert_eq!(stake_info.restoration_history[0].amount, slash_amount);
        assert_eq!(
            manager.get_total_staked(ProviderType::Validator),
            total_before_slash,
            "total_staked restored to pre-slash value"
        );
    }

    #[test]
    fn test_restore_slashed_stake_requires_proposal_id() {
        let manager = StakingManager::new();
        let staker = Address::new([1u8; 32]);
        let slasher = Address::new([2u8; 32]);
        let governance = Address::new([3u8; 32]);
        let amount = DEFAULT_MIN_STAKE * 2;
        let slash_amount = amount / 10;

        manager.stake(staker, amount, ProviderType::Validator).unwrap();
        manager
            .slash(&staker, slash_amount, "fault".to_string(), slasher)
            .unwrap();

        // Empty proposal_id must be rejected as Unauthorized.
        let err = manager
            .restore_slashed_stake(
                &staker,
                slash_amount,
                "   ".to_string(),
                "no proposal".to_string(),
                governance,
            )
            .unwrap_err();
        match err {
            TokenError::Unauthorized { .. } => {}
            other => panic!("expected Unauthorized, got {:?}", other),
        }
    }

    #[test]
    fn test_restore_cannot_exceed_slashed_amount() {
        let manager = StakingManager::new();
        let staker = Address::new([1u8; 32]);
        let slasher = Address::new([2u8; 32]);
        let governance = Address::new([3u8; 32]);
        let amount = DEFAULT_MIN_STAKE * 2;
        let slash_amount = amount / 10;

        manager.stake(staker, amount, ProviderType::Validator).unwrap();
        manager
            .slash(&staker, slash_amount, "fault".to_string(), slasher)
            .unwrap();

        // Restoring more than was slashed must fail.
        let err = manager
            .restore_slashed_stake(
                &staker,
                slash_amount + 1,
                "TGP-1".to_string(),
                "over-restore attempt".to_string(),
                governance,
            )
            .unwrap_err();
        match err {
            TokenError::InvalidAmount(_) => {}
            other => panic!("expected InvalidAmount, got {:?}", other),
        }

        // Restoring exact amount must succeed.
        manager
            .restore_slashed_stake(
                &staker,
                slash_amount,
                "TGP-1".to_string(),
                "ok".to_string(),
                governance,
            )
            .unwrap();

        // Second restoration of any amount must now fail (already fully restored).
        let err = manager
            .restore_slashed_stake(
                &staker,
                1,
                "TGP-2".to_string(),
                "double-restore attempt".to_string(),
                governance,
            )
            .unwrap_err();
        match err {
            TokenError::InvalidAmount(_) => {}
            other => panic!("expected InvalidAmount on double-restore, got {:?}", other),
        }
    }

    #[test]
    fn test_restore_returns_unbonding_to_active_when_above_min() {
        let manager = StakingManager::new();
        let staker = Address::new([1u8; 32]);
        let slasher = Address::new([2u8; 32]);
        let governance = Address::new([3u8; 32]);
        // Stake exactly at min, then slash a sliver — that forces Unbonding.
        let amount = DEFAULT_MIN_STAKE;
        let slash_amount = 1u128;

        manager.stake(staker, amount, ProviderType::Validator).unwrap();
        manager
            .slash(&staker, slash_amount, "below-min nudge".to_string(), slasher)
            .unwrap();

        // After slash: amount < min_stake, status == Unbonding.
        let stake_after_slash = manager.get_stake(&staker).unwrap();
        assert_eq!(stake_after_slash.status, StakeStatus::Unbonding);

        // Restore: amount goes back to min, status returns to Active.
        manager
            .restore_slashed_stake(
                &staker,
                slash_amount,
                "TGP-1".to_string(),
                "restore".to_string(),
                governance,
            )
            .unwrap();

        let stake_after_restore = manager.get_stake(&staker).unwrap();
        assert_eq!(stake_after_restore.amount, amount);
        assert_eq!(stake_after_restore.status, StakeStatus::Active);
        assert!(stake_after_restore.unbonding_at.is_none());
    }

    #[test]
    fn test_persistence_stake_and_reload() {
        // Create a temporary directory for this test
        let temp_dir = std::env::temp_dir().join(format!("tenzro_test_staking_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Create storage and staking manager with persistence
        let storage = Arc::new(RocksDbStore::open_default(&temp_dir).unwrap());
        let manager = StakingManager::with_storage(storage.clone());

        // Stake some tokens
        let staker1 = Address::new([1u8; 32]);
        let staker2 = Address::new([2u8; 32]);
        let amount1 = DEFAULT_MIN_STAKE;
        let amount2 = DEFAULT_MIN_STAKE * 2;

        manager.stake(staker1, amount1, ProviderType::Validator).unwrap();
        manager.stake(staker2, amount2, ProviderType::ModelProvider).unwrap();

        // Verify stakes were created
        assert!(manager.get_stake(&staker1).is_some());
        assert!(manager.get_stake(&staker2).is_some());
        assert_eq!(manager.get_total_staked(ProviderType::Validator), amount1);
        assert_eq!(manager.get_total_staked(ProviderType::ModelProvider), amount2);

        // Drop the manager to simulate shutdown
        drop(manager);

        // Create a new manager with the same storage - should reload state
        let manager2 = StakingManager::with_storage(storage);

        // Verify stakes were loaded
        let stake1 = manager2.get_stake(&staker1).unwrap();
        assert_eq!(stake1.amount, amount1);
        assert_eq!(stake1.provider_type, ProviderType::Validator);
        assert_eq!(stake1.status, StakeStatus::Active);

        let stake2 = manager2.get_stake(&staker2).unwrap();
        assert_eq!(stake2.amount, amount2);
        assert_eq!(stake2.provider_type, ProviderType::ModelProvider);
        assert_eq!(stake2.status, StakeStatus::Active);

        // Verify total staked was recomputed
        assert_eq!(manager2.get_total_staked(ProviderType::Validator), amount1);
        assert_eq!(manager2.get_total_staked(ProviderType::ModelProvider), amount2);

        // Clean up
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_persistence_config() {
        // Create a temporary directory for this test
        let temp_dir = std::env::temp_dir().join(format!("tenzro_test_staking_config_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Create storage and staking manager with persistence
        let storage = Arc::new(RocksDbStore::open_default(&temp_dir).unwrap());
        let manager = StakingManager::with_storage(storage.clone());

        // Update config
        let new_min_stake = DEFAULT_MIN_STAKE * 2;
        let new_unbonding = DEFAULT_UNBONDING_PERIOD_MS * 2;
        manager.set_min_stake(new_min_stake);
        manager.set_unbonding_period(new_unbonding);

        // Drop the manager
        drop(manager);

        // Create a new manager - should load config
        let manager2 = StakingManager::with_storage(storage);
        assert_eq!(*manager2.min_stake.read(), new_min_stake);
        assert_eq!(*manager2.unbonding_period_ms.read(), new_unbonding);

        // Clean up
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_persistence_unstake_and_withdraw() {
        // Create a temporary directory for this test
        let temp_dir = std::env::temp_dir().join(format!("tenzro_test_staking_unstake_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Create storage and staking manager with persistence
        let storage = Arc::new(RocksDbStore::open_default(&temp_dir).unwrap());
        let manager = StakingManager::with_storage(storage.clone());

        // Stake and unstake
        let staker = Address::new([1u8; 32]);
        let amount = DEFAULT_MIN_STAKE;
        manager.stake(staker, amount, ProviderType::Validator).unwrap();
        manager.unstake(&staker).unwrap();

        // Verify unbonding state before reload
        let stake_before = manager.get_stake(&staker).unwrap();
        assert_eq!(stake_before.status, StakeStatus::Unbonding);
        let unbonding_at = stake_before.unbonding_at.unwrap();

        // Drop and reload
        drop(manager);
        let manager2 = StakingManager::with_storage(storage);

        // Verify unbonding state persisted
        let stake_after = manager2.get_stake(&staker).unwrap();
        assert_eq!(stake_after.status, StakeStatus::Unbonding);
        assert_eq!(stake_after.unbonding_at, Some(unbonding_at));
        assert_eq!(stake_after.amount, amount);

        // Clean up
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_persistence_slash() {
        // Create a temporary directory for this test
        let temp_dir = std::env::temp_dir().join(format!("tenzro_test_staking_slash_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Create storage and staking manager with persistence
        let storage = Arc::new(RocksDbStore::open_default(&temp_dir).unwrap());
        let manager = StakingManager::with_storage(storage.clone());

        // Stake and slash
        let staker = Address::new([1u8; 32]);
        let slasher = Address::new([2u8; 32]);
        let amount = DEFAULT_MIN_STAKE;
        let slash_amount = amount / 10;

        manager.stake(staker, amount, ProviderType::Validator).unwrap();
        manager.slash(&staker, slash_amount, "Test slash".to_string(), slasher).unwrap();

        // Verify slash before reload
        let stake_before = manager.get_stake(&staker).unwrap();
        assert_eq!(stake_before.amount, amount - slash_amount);
        assert_eq!(stake_before.slashing_history.len(), 1);

        // Drop and reload
        drop(manager);
        let manager2 = StakingManager::with_storage(storage);

        // Verify slash persisted
        let stake_after = manager2.get_stake(&staker).unwrap();
        assert_eq!(stake_after.amount, amount - slash_amount);
        assert_eq!(stake_after.slashing_history.len(), 1);
        assert_eq!(stake_after.slashing_history[0].amount, slash_amount);
        assert_eq!(stake_after.slashing_history[0].reason, "Test slash");

        // Verify total staked was updated
        assert_eq!(manager2.get_total_staked(ProviderType::Validator), amount - slash_amount);

        // Clean up
        std::fs::remove_dir_all(&temp_dir).ok();
    }
}
