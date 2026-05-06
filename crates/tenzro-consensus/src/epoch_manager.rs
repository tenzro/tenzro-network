//! Epoch management for validator set transitions

use crate::error::{ConsensusError, Result};
use crate::validator::{ValidatorInfo, ValidatorSet};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_types::primitives::{BlockHeight, Timestamp};

/// Epoch information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Epoch {
    /// Epoch number
    pub number: u64,

    /// Start height of the epoch
    pub start_height: BlockHeight,

    /// End height of the epoch (exclusive)
    pub end_height: BlockHeight,

    /// Validator set for this epoch
    pub validator_set: ValidatorSet,

    /// Epoch start timestamp
    pub start_time: Timestamp,
}

impl Epoch {
    /// Creates a new epoch
    pub fn new(
        number: u64,
        start_height: BlockHeight,
        end_height: BlockHeight,
        validator_set: ValidatorSet,
    ) -> Self {
        Self {
            number,
            start_height,
            end_height,
            validator_set,
            start_time: Timestamp::now(),
        }
    }

    /// Checks if the given height is in this epoch
    pub fn contains(&self, height: BlockHeight) -> bool {
        height >= self.start_height && height < self.end_height
    }

    /// Returns the duration of the epoch in blocks
    pub fn duration(&self) -> u64 {
        self.end_height.as_u64() - self.start_height.as_u64()
    }
}

/// Manages epoch transitions and validator set updates
///
/// # Atomicity Guarantees
///
/// - `current_epoch` is protected by RwLock, ensuring atomic reads and writes
/// - Epoch transitions use a write lock that prevents any concurrent access
/// - All state updates (history, pending validators, current epoch) happen
///   within the critical section to prevent split-brain scenarios
/// - The validator set change becomes visible atomically when the write lock
///   is released
pub struct EpochManager {
    /// Current epoch (protected by RwLock for atomic access)
    current_epoch: Arc<RwLock<Epoch>>,

    /// Epoch duration in blocks
    epoch_duration: u64,

    /// Pending validator additions/updates for next epoch.
    ///
    /// Each entry is upserted into the next epoch's validator set on
    /// transition: a matching address is replaced; new addresses are added.
    pending_validators: Arc<RwLock<Vec<ValidatorInfo>>>,

    /// Pending validator removals for next epoch (e.g. unstake or slashing).
    ///
    /// On transition, every address in this list is dropped from the next
    /// epoch's validator set before pending_validators is upserted in.
    pending_removals: Arc<RwLock<Vec<tenzro_types::primitives::Address>>>,

    /// History of past epochs (protected by RwLock)
    epoch_history: Arc<RwLock<Vec<Epoch>>>,

    /// Maximum epochs to keep in history
    max_history: usize,
}

impl EpochManager {
    /// Creates a new epoch manager
    pub fn new(
        initial_validators: Vec<ValidatorInfo>,
        epoch_duration: u64,
    ) -> Result<Self> {
        let validator_set = ValidatorSet::new(0, initial_validators)?;

        let current_epoch = Epoch::new(
            0,
            BlockHeight::from(0),
            BlockHeight::from(epoch_duration),
            validator_set,
        );

        Ok(Self {
            current_epoch: Arc::new(RwLock::new(current_epoch)),
            epoch_duration,
            pending_validators: Arc::new(RwLock::new(Vec::new())),
            pending_removals: Arc::new(RwLock::new(Vec::new())),
            epoch_history: Arc::new(RwLock::new(Vec::new())),
            max_history: 10, // Keep last 10 epochs
        })
    }

    /// Returns the current epoch
    ///
    /// This is an atomic snapshot of the current epoch state.
    pub fn current_epoch(&self) -> Epoch {
        self.current_epoch.read().clone()
    }

    /// Returns the current validator set
    ///
    /// This is an atomic snapshot of the current validator set.
    /// During epoch transitions, this will either return the old or new set,
    /// never a partial/inconsistent state.
    pub fn current_validator_set(&self) -> ValidatorSet {
        self.current_epoch.read().validator_set.clone()
    }

    /// Checks if it's time to transition to the next epoch
    pub fn should_transition(&self, height: BlockHeight) -> bool {
        height >= self.current_epoch.read().end_height
    }

    /// Transitions to the next epoch
    ///
    /// This operation is atomic - the write lock on current_epoch ensures
    /// no other thread can read or modify the epoch during transition.
    /// History and pending validators are updated atomically within the same
    /// critical section to prevent split-brain scenarios.
    pub fn transition_epoch(&self, height: BlockHeight) -> Result<ValidatorSet> {
        // Acquire write lock for atomic transition
        // This prevents any concurrent reads or writes to the current epoch
        let mut current = self.current_epoch.write();

        if height < current.end_height {
            return Err(ConsensusError::EpochTransition(format!(
                "Too early to transition: current height {}, epoch ends at {}",
                height, current.end_height
            )));
        }

        let next_epoch_number = current.number + 1;

        // Compute next validator set as: current set, with pending_removals
        // dropped, then pending_validators upserted (matching address replaces;
        // new address appends). This makes pending entries deltas rather than
        // a full replacement, so a single stake event doesn't reset the set.
        let next_validators: Vec<ValidatorInfo> = {
            let pending_adds = self.pending_validators.read();
            let pending_drops = self.pending_removals.read();

            let mut next: Vec<ValidatorInfo> = current
                .validator_set
                .iter()
                .filter(|v| !pending_drops.iter().any(|addr| addr == &v.address))
                .cloned()
                .collect();

            for upsert in pending_adds.iter() {
                if let Some(existing) = next.iter_mut().find(|v| v.address == upsert.address) {
                    *existing = upsert.clone();
                } else {
                    next.push(upsert.clone());
                }
            }

            next
        };

        // Create new validator set - this can fail, so we do it before modifying state
        let validator_set = ValidatorSet::new(next_epoch_number, next_validators)?;

        // Calculate next epoch boundaries
        let start_height = height;
        let end_height = height + self.epoch_duration;

        // Create new epoch
        let new_epoch = Epoch::new(
            next_epoch_number,
            start_height,
            end_height,
            validator_set.clone(),
        );

        // Now perform all state updates atomically within this critical section

        // 1. Store current epoch in history
        {
            let mut history = self.epoch_history.write();
            history.push(current.clone());

            // Trim history if needed
            if history.len() > self.max_history {
                history.remove(0);
            }
            // history lock is released here
        }

        // 2. Clear pending validator deltas (both adds and removals)
        {
            self.pending_validators.write().clear();
            self.pending_removals.write().clear();
            // pending_validators / pending_removals locks are released here
        }

        // 3. Update current epoch (this is the commit point)
        // Once this happens, all readers will see the new epoch
        *current = new_epoch.clone();

        // current lock is released here, making the transition visible

        tracing::info!(
            epoch = next_epoch_number,
            start_height = %start_height,
            end_height = %end_height,
            validator_count = validator_set.len(),
            "Epoch transition completed atomically"
        );

        Ok(validator_set)
    }

    /// Queues a validator add/update for the next epoch. If `validator.address`
    /// is already present in the pending queue, the prior entry is replaced.
    /// Also clears any pending removal for the same address (an add wins over
    /// a prior queued remove within the same epoch window).
    pub fn add_pending_validator(&self, validator: ValidatorInfo) {
        let addr = validator.address;
        let stake = validator.stake;

        {
            let mut pending = self.pending_validators.write();
            if let Some(existing) = pending.iter_mut().find(|v| v.address == addr) {
                *existing = validator;
            } else {
                pending.push(validator);
            }
        }
        self.pending_removals.write().retain(|a| a != &addr);

        tracing::debug!(
            address = %addr,
            stake = stake,
            "Pending validator add/update queued for next epoch"
        );
    }

    /// Queues a validator removal for the next epoch. Idempotent: queueing the
    /// same address twice records one removal. Also drops any pending add for
    /// the same address (a remove wins over a prior queued add within the same
    /// epoch window).
    pub fn remove_pending_validator(&self, address: &tenzro_types::primitives::Address) {
        self.pending_validators
            .write()
            .retain(|v| &v.address != address);

        let mut removals = self.pending_removals.write();
        if !removals.iter().any(|a| a == address) {
            removals.push(*address);
        }

        tracing::debug!(address = %address, "Pending validator removal queued for next epoch");
    }

    /// Returns the pending validator additions/updates for the next epoch
    pub fn pending_validators(&self) -> Vec<ValidatorInfo> {
        self.pending_validators.read().clone()
    }

    /// Returns the pending validator removals for the next epoch
    pub fn pending_removals(&self) -> Vec<tenzro_types::primitives::Address> {
        self.pending_removals.read().clone()
    }

    /// Returns an epoch from history
    pub fn get_epoch(&self, epoch_number: u64) -> Option<Epoch> {
        let current = self.current_epoch.read();
        if current.number == epoch_number {
            return Some(current.clone());
        }

        self.epoch_history
            .read()
            .iter()
            .find(|e| e.number == epoch_number)
            .cloned()
    }

    /// Returns the validator set for a specific epoch
    pub fn get_validator_set(&self, epoch_number: u64) -> Option<ValidatorSet> {
        self.get_epoch(epoch_number)
            .map(|epoch| epoch.validator_set)
    }

    /// Returns the epoch for a given block height
    pub fn get_epoch_for_height(&self, height: BlockHeight) -> Option<Epoch> {
        let current = self.current_epoch.read();
        if current.contains(height) {
            return Some(current.clone());
        }

        self.epoch_history
            .read()
            .iter()
            .find(|e| e.contains(height))
            .cloned()
    }

    /// Returns epoch statistics
    pub fn stats(&self) -> EpochStats {
        let current = self.current_epoch.read();
        let pending_count = self.pending_validators.read().len();

        EpochStats {
            current_epoch: current.number,
            start_height: current.start_height,
            end_height: current.end_height,
            validator_count: current.validator_set.len(),
            pending_validator_changes: pending_count,
            epoch_duration: self.epoch_duration,
        }
    }
}

/// Epoch statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochStats {
    /// Current epoch number
    pub current_epoch: u64,

    /// Start height of current epoch
    pub start_height: BlockHeight,

    /// End height of current epoch
    pub end_height: BlockHeight,

    /// Number of validators in current epoch
    pub validator_count: usize,

    /// Number of pending validator changes
    pub pending_validator_changes: usize,

    /// Epoch duration in blocks
    pub epoch_duration: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::{KeyPair, KeyType};

    fn create_test_validator(stake: u128) -> ValidatorInfo {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let crypto_addr = keypair.address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = tenzro_types::primitives::Address::new(addr_bytes);
        let pq = MlDsaSigningKey::generate();
        ValidatorInfo::new(
            address,
            keypair.public_key().clone(),
            pq.verifying_key_bytes().to_vec(),
            stake,
        )
    }

    #[test]
    fn test_epoch_creation() {
        let validators = vec![
            create_test_validator(1000),
            create_test_validator(2000),
        ];

        let manager = EpochManager::new(validators, 100).unwrap();

        let epoch = manager.current_epoch();
        assert_eq!(epoch.number, 0);
        assert_eq!(epoch.start_height, BlockHeight::from(0));
        assert_eq!(epoch.end_height, BlockHeight::from(100));
    }

    #[test]
    fn test_epoch_transition() {
        let validators = vec![create_test_validator(1000)];
        let manager = EpochManager::new(validators, 100).unwrap();

        assert!(!manager.should_transition(BlockHeight::from(50)));
        assert!(manager.should_transition(BlockHeight::from(100)));

        // Transition to next epoch
        let _new_validators = manager.transition_epoch(BlockHeight::from(100)).unwrap();

        let epoch = manager.current_epoch();
        assert_eq!(epoch.number, 1);
        assert_eq!(epoch.start_height, BlockHeight::from(100));
        assert_eq!(epoch.end_height, BlockHeight::from(200));
    }

    #[test]
    fn test_pending_validators_merge_add() {
        // 3 initial validators + 1 pending add → 4 in next epoch (merge, not replace)
        let v0 = create_test_validator(1000);
        let v1 = create_test_validator(2000);
        let v2 = create_test_validator(3000);
        let manager =
            EpochManager::new(vec![v0.clone(), v1.clone(), v2.clone()], 100).unwrap();

        let v3 = create_test_validator(4000);
        manager.add_pending_validator(v3.clone());
        assert_eq!(manager.pending_validators().len(), 1);

        let next = manager.transition_epoch(BlockHeight::from(100)).unwrap();

        assert_eq!(next.len(), 4, "next epoch must MERGE pending into current");
        assert!(next.iter().any(|v| v.address == v0.address));
        assert!(next.iter().any(|v| v.address == v1.address));
        assert!(next.iter().any(|v| v.address == v2.address));
        assert!(next.iter().any(|v| v.address == v3.address));

        // Both queues cleared
        assert_eq!(manager.pending_validators().len(), 0);
        assert_eq!(manager.pending_removals().len(), 0);
    }

    #[test]
    fn test_pending_validators_remove() {
        // 3 initial - 1 pending removal → 2 in next epoch
        let v0 = create_test_validator(1000);
        let v1 = create_test_validator(2000);
        let v2 = create_test_validator(3000);
        let manager =
            EpochManager::new(vec![v0.clone(), v1.clone(), v2.clone()], 100).unwrap();

        manager.remove_pending_validator(&v1.address);
        assert_eq!(manager.pending_removals().len(), 1);

        let next = manager.transition_epoch(BlockHeight::from(100)).unwrap();

        assert_eq!(next.len(), 2);
        assert!(next.iter().any(|v| v.address == v0.address));
        assert!(!next.iter().any(|v| v.address == v1.address));
        assert!(next.iter().any(|v| v.address == v2.address));

        assert_eq!(manager.pending_removals().len(), 0);
    }

    #[test]
    fn test_pending_validators_upsert_existing() {
        // Pending add for existing address replaces (stake updated)
        let v0 = create_test_validator(1000);
        let v0_addr = v0.address;
        let v0_pk = v0.public_key.clone();
        let v0_pq = v0.pq_public_key.clone();
        let manager = EpochManager::new(vec![v0.clone()], 100).unwrap();

        // Same address, larger stake
        let v0_updated = ValidatorInfo::new(v0_addr, v0_pk, v0_pq, 5000);
        manager.add_pending_validator(v0_updated);

        let next = manager.transition_epoch(BlockHeight::from(100)).unwrap();

        assert_eq!(next.len(), 1, "upsert must not duplicate");
        let only = next.get(0).unwrap();
        assert_eq!(only.address, v0_addr);
        assert_eq!(only.stake, 5000, "stake must be updated to new value");
    }

    #[test]
    fn test_pending_validators_add_then_remove_same_address() {
        // Conflict resolution: add then remove for same address → final state respects last op (remove)
        let v0 = create_test_validator(1000);
        let manager = EpochManager::new(vec![v0.clone()], 100).unwrap();

        let v_new = create_test_validator(2000);
        let v_new_addr = v_new.address;

        manager.add_pending_validator(v_new);
        manager.remove_pending_validator(&v_new_addr);

        // After remove, the add for the same address should have been dropped
        assert!(
            !manager
                .pending_validators()
                .iter()
                .any(|v| v.address == v_new_addr),
            "add must be dropped when subsequent remove targets same address"
        );

        let next = manager.transition_epoch(BlockHeight::from(100)).unwrap();

        // Only original v0 remains; v_new was added then removed
        assert_eq!(next.len(), 1);
        assert_eq!(next.get(0).unwrap().address, v0.address);
    }

    #[test]
    fn test_pending_validators_remove_then_add_same_address() {
        // Inverse conflict: remove then add for same existing address → add wins (re-stake)
        let v0 = create_test_validator(1000);
        let v0_addr = v0.address;
        let v0_pk = v0.public_key.clone();
        let v0_pq = v0.pq_public_key.clone();
        let manager = EpochManager::new(vec![v0.clone()], 100).unwrap();

        manager.remove_pending_validator(&v0_addr);
        // Now re-stake same address with new amount
        let v0_restaked = ValidatorInfo::new(v0_addr, v0_pk, v0_pq, 7777);
        manager.add_pending_validator(v0_restaked);

        // The add should clear the prior pending removal for the same address
        assert!(
            !manager
                .pending_removals()
                .iter()
                .any(|addr| addr == &v0_addr),
            "subsequent add for same address must clear pending removal"
        );

        let next = manager.transition_epoch(BlockHeight::from(100)).unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next.get(0).unwrap().stake, 7777);
    }

    #[test]
    fn test_epoch_history() {
        let validators = vec![create_test_validator(1000)];
        let manager = EpochManager::new(validators, 100).unwrap();

        manager.transition_epoch(BlockHeight::from(100)).unwrap();
        manager.transition_epoch(BlockHeight::from(200)).unwrap();

        // Should have epoch 0 in history
        let epoch0 = manager.get_epoch(0);
        assert!(epoch0.is_some());
        assert_eq!(epoch0.unwrap().number, 0);

        // Current epoch should be 2
        assert_eq!(manager.current_epoch().number, 2);
    }

    #[test]
    fn test_get_epoch_for_height() {
        let validators = vec![create_test_validator(1000)];
        let manager = EpochManager::new(validators, 100).unwrap();

        manager.transition_epoch(BlockHeight::from(100)).unwrap();

        // Height 50 should be in epoch 0
        let epoch = manager.get_epoch_for_height(BlockHeight::from(50));
        assert!(epoch.is_some());
        assert_eq!(epoch.unwrap().number, 0);

        // Height 150 should be in epoch 1
        let epoch = manager.get_epoch_for_height(BlockHeight::from(150));
        assert!(epoch.is_some());
        assert_eq!(epoch.unwrap().number, 1);
    }
}
