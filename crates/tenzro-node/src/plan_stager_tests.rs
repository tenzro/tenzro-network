use crate::consensus_driver::EpochPlanner;
use crate::node::*;
use std::sync::Arc;
use tenzro_storage::KvStore;
use tenzro_token::validator_registry::{ValidatorRegistry, ValidatorRegistryStatus};
use tenzro_types::Address;

/// A validator key pair from the test signer, in the registry's encoding.
fn validator_key(seed: u8) -> tenzro_consensus::ValidatorPublicKey {
    use tenzro_crypto::composite::HybridSigner;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    let public = TestHybridSigner::hybrid(seed).public_key().clone();
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&public.p256);
    tenzro_consensus::ValidatorPublicKey::new(public.pq.expect("hybrid"), sec1).unwrap()
}

/// The registry's RPC provider minimum is the governed `stake.rpc_tnzo`,
/// read from chain state at the boundary: a vote that changes it moves
/// the registry at the next boundary, on every node alike.
#[test]
fn a_governed_rpc_bond_change_moves_the_registry_minimum_at_the_next_boundary() {
    let key = validator_key(1);
    let seated = tenzro_consensus::validator::ValidatorInfo::new(
        Address::new([1; 32]),
        key,
        [1; 32],
        1 << 40,
    );
    let epoch_manager = Arc::new(tenzro_consensus::EpochManager::new(vec![seated], 100).unwrap());
    let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
    let registry = Arc::new(ValidatorRegistry::with_storage(store.clone()));
    let stager = RegistryEpochPlanStager {
        epoch_manager,
        registry: registry.clone(),
        store: Some(store.clone()),
    };
    stager.stage_next_epoch().unwrap();
    let chain = tenzro_vm::StateAdapter::with_storage(store.clone());
    let before = tenzro_vm::native::entry_stake_ladder(&chain).rpc;
    assert_eq!(registry.config().min_rpc_provider_stake, before);

    // An enacted change of stake.rpc_tnzo, as it lands in chain state.
    let key = format!(
        "storage:{}:{}",
        hex::encode(tenzro_vm::native::SYSTEM_ADDRESS),
        hex::encode(tenzro_vm::native::governed_param_key("stake.rpc_tnzo"))
    );
    store
        .put(
            tenzro_storage::CF_STATE,
            key.as_bytes(),
            &40_000u64.to_le_bytes(),
        )
        .unwrap();
    let chain = tenzro_vm::StateAdapter::with_storage(store.clone());
    let after = tenzro_vm::native::entry_stake_ladder(&chain).rpc;
    assert_ne!(after, before);
    assert_eq!(
        registry.config().min_rpc_provider_stake,
        before,
        "not before the boundary"
    );
    stager.stage_next_epoch().unwrap();
    assert_eq!(registry.config().min_rpc_provider_stake, after);
}

/// Staging a boundary twice would step a candidate from pending to active
/// in one epoch. A staging that is undone leaves the registry as before, so
/// the retry steps it once.
#[test]
fn a_staging_that_is_undone_is_not_applied_twice_on_the_retry() {
    let key = validator_key(2);
    let seated = tenzro_consensus::validator::ValidatorInfo::new(
        Address::new([1; 32]),
        key.clone(),
        [1; 32],
        1 << 40,
    );
    let epoch_manager = Arc::new(tenzro_consensus::EpochManager::new(vec![seated], 100).unwrap());
    let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
    let registry = Arc::new(ValidatorRegistry::with_storage(store));
    let candidate = Address::new([2; 32]);
    let cand_key = validator_key(3);
    const ONE_TNZO: u128 = 1_000_000_000_000_000_000;
    registry
        .register_candidate(
            candidate,
            cand_key.ml_dsa.clone(),
            cand_key.p256.clone(),
            [2; 32],
            candidate,
            1_000_000 * ONE_TNZO,
            0,
            String::new(),
        )
        .unwrap();
    let status = || registry.get(&candidate).unwrap().status;
    assert_eq!(status(), ValidatorRegistryStatus::Candidate);

    let stager = RegistryEpochPlanStager {
        epoch_manager,
        registry: registry.clone(),
        store: None,
    };
    let token = stager.stage_next_epoch().unwrap();
    assert_eq!(status(), ValidatorRegistryStatus::PendingActive);
    // The derivation failed: the staging is undone.
    stager.unstage_next_epoch(&token);
    assert_eq!(status(), ValidatorRegistryStatus::Candidate);
    // The retry steps the candidate once, not twice.
    stager.stage_next_epoch().unwrap();
    assert_eq!(status(), ValidatorRegistryStatus::PendingActive);
    // Staging again, with no undo in between (a second caller at the same
    // boundary), still steps it once.
    stager.stage_next_epoch().unwrap();
    assert_eq!(status(), ValidatorRegistryStatus::PendingActive);
    // And after an undo that could not be written back, the next staging
    // puts the registry back first.
    stager.stage_next_epoch().unwrap();
    stager.stage_next_epoch().unwrap();
    assert_eq!(status(), ValidatorRegistryStatus::PendingActive);
}
