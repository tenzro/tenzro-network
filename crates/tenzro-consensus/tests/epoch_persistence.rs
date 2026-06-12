//! Regression tests for cross-epoch validator-set persistence and lookup.
//!
//! These guard the May 2026 testnet stall fix: a node falling behind across
//! one or more epoch transitions must be able to verify each historical
//! block's commit-QC against the validator set that signed it, not the
//! current epoch's set. Without persistent epoch history, a restart would
//! lose all past validator sets and reject every historical block as
//! `InvalidValidatorSet`, deadlocking liveness.
//!
//! Two invariants:
//!
//! 1. `EpochManager::with_store` must hydrate `current_epoch` + history
//!    from a previously-populated store, so a restart resumes at the same
//!    epoch state without needing to rerun all prior transitions.
//!
//! 2. `EpochManager::transition_epoch` must write through to the store on
//!    every transition, so that an unclean shutdown still leaves a
//!    recoverable epoch trail.
//!
//! These tests use an in-memory store implementation rather than RocksDB —
//! the persistence semantics are at the trait boundary, and the
//! RocksDB-backed `RocksDbEpochStateStore` adapter has its own unit tests
//! in `tenzro-node::epoch_state_store`.

use std::sync::Arc;

use parking_lot::Mutex;
use tenzro_consensus::epoch_manager::{EpochManager, EpochStateStore};
use tenzro_consensus::error::{ConsensusError, Result};
use tenzro_consensus::validator::ValidatorInfo;
use tenzro_crypto::bls::BlsKeyPair;
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::{KeyPair, KeyType};
use tenzro_types::primitives::{Address, BlockHeight};

/// In-memory test double for `EpochStateStore`.
///
/// Stored entries are keyed by epoch number so the test can re-instantiate
/// `EpochManager::with_store` against the same backing store to simulate a
/// restart.
#[derive(Default, Clone)]
struct MemEpochStore {
    inner: Arc<Mutex<std::collections::BTreeMap<u64, Vec<u8>>>>,
}

impl EpochStateStore for MemEpochStore {
    fn put_epoch(&self, epoch_number: u64, bytes: Vec<u8>) -> Result<()> {
        self.inner.lock().insert(epoch_number, bytes);
        Ok(())
    }

    fn load_all_epochs(&self) -> Result<Vec<Vec<u8>>> {
        // BTreeMap iteration is ascending by key; matches the production
        // RocksDB adapter's big-endian key encoding.
        Ok(self.inner.lock().values().cloned().collect())
    }
}

/// Test double that always fails — used to confirm write-through failures
/// don't roll back the in-memory transition.
#[derive(Default)]
struct FailingEpochStore;

impl EpochStateStore for FailingEpochStore {
    fn put_epoch(&self, _epoch_number: u64, _bytes: Vec<u8>) -> Result<()> {
        Err(ConsensusError::Internal("simulated put failure".into()))
    }

    fn load_all_epochs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }
}

fn test_validator(stake: u128) -> ValidatorInfo {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let crypto_addr = keypair.address();
    let mut addr_bytes = [0u8; 32];
    addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
    let address = Address::new(addr_bytes);
    let pq = MlDsaSigningKey::generate();
    let bls = BlsKeyPair::generate().unwrap();
    ValidatorInfo::new(
        address,
        keypair.public_key().clone(),
        pq.verifying_key_bytes().to_vec(),
        bls.public_key().to_bytes().to_vec(),
        stake,
    )
}

/// Bootstrap from an empty store writes epoch 0 through immediately, so a
/// crash before the first transition still leaves something recoverable.
#[test]
fn bootstrap_persists_initial_epoch() {
    let store = Arc::new(MemEpochStore::default());
    let validators = vec![test_validator(1000), test_validator(2000)];

    let _mgr = EpochManager::with_store(validators, 100, store.clone()).unwrap();

    let persisted = store.load_all_epochs().unwrap();
    assert_eq!(
        persisted.len(),
        1,
        "epoch 0 must be persisted at bootstrap so a crash before the first \
         transition still leaves a recoverable record"
    );
}

/// Each `transition_epoch` writes the new current epoch through.
#[test]
fn transition_persists_each_new_epoch() {
    let store = Arc::new(MemEpochStore::default());
    let validators = vec![test_validator(1000)];

    let mgr = EpochManager::with_store(validators, 100, store.clone()).unwrap();
    mgr.transition_epoch(BlockHeight::from(100), |_| None).unwrap();
    mgr.transition_epoch(BlockHeight::from(200), |_| None).unwrap();

    let persisted = store.load_all_epochs().unwrap();
    assert_eq!(
        persisted.len(),
        3,
        "epochs 0, 1, 2 must all be persisted"
    );
}

/// Simulating a restart: drop the manager and reconstruct over the same
/// store. The new instance must come up with the same `current_epoch` —
/// not start over at epoch 0.
#[test]
fn restart_hydrates_to_latest_persisted_epoch() {
    let store = Arc::new(MemEpochStore::default());
    let validators = vec![test_validator(1000), test_validator(2000)];

    // Boot 1: advance to epoch 2.
    {
        let mgr =
            EpochManager::with_store(validators.clone(), 100, store.clone()).unwrap();
        mgr.transition_epoch(BlockHeight::from(100), |_| None).unwrap();
        mgr.transition_epoch(BlockHeight::from(200), |_| None).unwrap();
        assert_eq!(mgr.current_epoch().number, 2);
    }

    // Boot 2: same store. Must hydrate at epoch 2.
    let mgr2 = EpochManager::with_store(validators, 100, store).unwrap();
    let current = mgr2.current_epoch();
    assert_eq!(
        current.number, 2,
        "restart must hydrate to latest persisted epoch, not restart at 0"
    );
    assert_eq!(current.start_height, BlockHeight::from(200));
    assert_eq!(current.end_height, BlockHeight::from(300));
}

/// Cross-epoch validator-set lookup: after multiple transitions, the
/// manager must answer `get_epoch_for_height` for blocks that fall in past
/// epochs — including across a simulated restart. This is the load-bearing
/// query for `HotStuff2Engine::validator_set_for_height` which the
/// block-sync engine consults to verify historical commit-QCs.
#[test]
fn cross_epoch_validator_set_lookup_survives_restart() {
    let store = Arc::new(MemEpochStore::default());

    // Use distinct validator sets per epoch so we can verify the right
    // set comes back. Initial set for epoch 0:
    let epoch_0_validators = vec![test_validator(1000), test_validator(2000)];
    let epoch_0_addrs: Vec<Address> =
        epoch_0_validators.iter().map(|v| v.address).collect();

    // Boot 1: run through 3 transitions (epoch 0 → 3), each adding one new
    // validator so the set grows.
    let final_size;
    {
        let mgr = EpochManager::with_store(
            epoch_0_validators.clone(),
            100,
            store.clone(),
        )
        .unwrap();

        mgr.add_pending_validator(test_validator(3000));
        mgr.transition_epoch(BlockHeight::from(100), |_| None).unwrap();

        mgr.add_pending_validator(test_validator(4000));
        mgr.transition_epoch(BlockHeight::from(200), |_| None).unwrap();

        mgr.add_pending_validator(test_validator(5000));
        mgr.transition_epoch(BlockHeight::from(300), |_| None).unwrap();

        final_size = mgr.current_validator_set().len();
        assert_eq!(final_size, 5, "set grew by 1 per epoch (2 → 3 → 4 → 5)");
    }

    // Boot 2: simulated restart.
    let mgr2 = EpochManager::with_store(epoch_0_validators, 100, store).unwrap();

    // Current set: 5 validators.
    assert_eq!(mgr2.current_validator_set().len(), 5);

    // Historical lookups:
    let h_50 = mgr2.get_epoch_for_height(BlockHeight::from(50)).unwrap();
    assert_eq!(h_50.number, 0);
    assert_eq!(
        h_50.validator_set.len(),
        2,
        "epoch 0 set must have its original 2 members"
    );
    for addr in &epoch_0_addrs {
        assert!(
            h_50.validator_set.is_validator(addr),
            "epoch 0 validator must be present in restored epoch 0 set"
        );
    }

    let h_150 = mgr2.get_epoch_for_height(BlockHeight::from(150)).unwrap();
    assert_eq!(h_150.number, 1);
    assert_eq!(h_150.validator_set.len(), 3);

    let h_250 = mgr2.get_epoch_for_height(BlockHeight::from(250)).unwrap();
    assert_eq!(h_250.number, 2);
    assert_eq!(h_250.validator_set.len(), 4);

    let h_350 = mgr2.get_epoch_for_height(BlockHeight::from(350)).unwrap();
    assert_eq!(h_350.number, 3);
    assert_eq!(h_350.validator_set.len(), 5);
}

/// `EpochManager::new` (ephemeral, no store) must still work — tests and
/// short-lived nodes don't need persistence, and the ephemeral path is the
/// fallback in node.rs when storage is absent.
#[test]
fn ephemeral_new_works_without_store() {
    let mgr = EpochManager::new(vec![test_validator(1000)], 100).unwrap();
    mgr.transition_epoch(BlockHeight::from(100), |_| None).unwrap();
    assert_eq!(mgr.current_epoch().number, 1);
}

/// Persistence failures during transition are non-fatal. The in-memory
/// transition still completes — durability is best-effort because the
/// next leader's commit-QC will re-anchor the chain. This invariant
/// keeps liveness during transient disk issues (full disk, slow
/// fsync, etc.) at the cost of needing to rebuild history on restart.
#[test]
fn failing_store_does_not_abort_transition() {
    let store = Arc::new(FailingEpochStore);
    // `with_store` will try to persist bootstrap epoch 0; that fails but
    // is logged-and-continued. Manager construction itself succeeds.
    let mgr = EpochManager::with_store(
        vec![test_validator(1000)],
        100,
        store,
    )
    .unwrap();

    // Transition should also succeed in-memory despite the store failing.
    let _ = mgr.transition_epoch(BlockHeight::from(100), |_| None).unwrap();
    assert_eq!(mgr.current_epoch().number, 1);
}
