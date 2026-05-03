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

    /// Pending validator changes for next epoch (protected by RwLock)
    pending_validators: Arc<RwLock<Vec<ValidatorInfo>>>,

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

        // Get validators for next epoch (atomic snapshot)
        let next_validators = {
            let pending = self.pending_validators.read();
            if pending.is_empty() {
                // No changes, reuse current validators
                current.validator_set.iter().cloned().collect()
            } else {
                // Use pending validators
                pending.clone()
            }
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

        // 2. Clear pending validators
        {
            self.pending_validators.write().clear();
            // pending_validators lock is released here
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

    /// Adds a pending validator change for the next epoch
    pub fn add_pending_validator(&self, validator: ValidatorInfo) {
        let addr = validator.address;
        let stake = validator.stake;
        self.pending_validators.write().push(validator);

        tracing::debug!(
            address = %addr,
            stake = stake,
            "Pending validator added for next epoch"
        );
    }

    /// Removes a pending validator
    pub fn remove_pending_validator(&self, address: &tenzro_types::primitives::Address) {
        self.pending_validators
            .write()
            .retain(|v| &v.address != address);
    }

    /// Returns the pending validators for the next epoch
    pub fn pending_validators(&self) -> Vec<ValidatorInfo> {
        self.pending_validators.read().clone()
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
    fn test_pending_validators() {
        let validators = vec![create_test_validator(1000)];
        let manager = EpochManager::new(validators, 100).unwrap();

        let new_validator = create_test_validator(2000);
        manager.add_pending_validator(new_validator.clone());

        let pending = manager.pending_validators();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].stake, 2000);

        // Transition should apply pending changes
        manager.transition_epoch(BlockHeight::from(100)).unwrap();

        // Pending should be cleared
        assert_eq!(manager.pending_validators().len(), 0);
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
