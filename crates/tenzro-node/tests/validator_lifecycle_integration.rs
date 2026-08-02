//! Validator lifecycle integration tests (Dynamic Validator Set, task #413).
//!
//! The unit tests in `tenzro-token` cover the registry state machine
//! (Candidate → PendingActive → Active → PendingExit → Exited) in isolation,
//! and the unit tests in `tenzro-consensus` cover the EpochManager pending
//! queues. What neither layer catches is the *bridge* implemented in
//! `node::event_loop` — the post-finalize hook that calls
//! `ValidatorRegistry::compute_epoch_transition` and feeds the resulting plan
//! into `EpochManager::add_pending_validator` / `remove_pending_validator`.
//!
//! These tests exercise the bridge directly without a full `TenzroNode` boot
//! (which would require a 200+ MB RocksDB + libp2p + rpc startup just to
//! verify a handful of in-memory state transitions). The hook in question
//! is intentionally pure: registry → plan → epoch-manager mutations. We
//! reproduce it here against in-process instances of both registries.

use std::sync::Arc;

use tenzro_consensus::epoch_manager::EpochManager;
use tenzro_consensus::validator::ValidatorInfo;
use tenzro_crypto::pq::ML_DSA_65_VK_LEN;
use tenzro_crypto::{KeyPair, KeyType, PublicKey};
use tenzro_token::validator_registry::{
    DEFAULT_MIN_VALIDATOR_SELF_STAKE, ValidatorRegistry, ValidatorRegistryStatus,
};
use tenzro_types::primitives::Address;

/// Reproduces the post-finalize bridge logic from `event_loop::handle_block_finalized`.
///
/// In production this is invoked once per epoch boundary. It pulls the plan
/// from the registry and applies the activation/exit deltas to the
/// EpochManager's pending queues. The EpochManager's own `transition_epoch`
/// (called by HotStuff-2 at the same boundary) then promotes those pending
/// entries into the next epoch's active set.
fn apply_epoch_transition(registry: &ValidatorRegistry, em: &EpochManager, new_epoch: u64) {
    let plan = registry.compute_epoch_transition(new_epoch);

    for addr in &plan.effective_activations {
        let entry = match registry.get(addr) {
            Some(e) => e,
            None => continue,
        };
        let pk = PublicKey::new(KeyType::Ed25519, entry.consensus_pubkey.clone());
        let info = ValidatorInfo::new(
            entry.address,
            pk,
            entry.pq_pubkey.clone(),
            entry.bls_pubkey.clone(),
            entry.self_stake,
        );
        em.add_pending_validator(info);
    }

    for addr in &plan.effective_exits {
        em.remove_pending_validator(addr);
    }
}

/// Returns a `(consensus_address, ed25519_keypair, pq_vk, bls_vk)` tuple.
fn fresh_validator_keys(seed: u8) -> (Address, KeyPair, Vec<u8>, Vec<u8>) {
    // Deterministic-ish address by repeating seed across the 32 bytes —
    // good enough for an in-process unit test where uniqueness is the only
    // requirement (no on-chain derivation, no signing through this addr).
    let addr_bytes = [seed; 32];
    let address = Address::new(addr_bytes);

    let kp = KeyPair::generate(KeyType::Ed25519).expect("keypair gen");
    let pq_vk = vec![0u8; ML_DSA_65_VK_LEN]; // Stub PQ key for registry.
    let bls_vk = vec![0u8; 48]; // Stub BLS12-381 G1-compressed verifying key.

    (address, kp, pq_vk, bls_vk)
}

#[tokio::test]
async fn full_lifecycle_register_activate_produce_exit() {
    // ---- Setup ----
    // Genesis validator (always active) + a candidate that joins later.
    let (genesis_addr, genesis_kp, genesis_pq, genesis_bls) = fresh_validator_keys(0x01);
    let (cand_addr, cand_kp, cand_pq, cand_bls) = fresh_validator_keys(0x02);

    // Bootstrap EpochManager with just the genesis validator so the active
    // set can produce blocks before the candidate is admitted.
    let genesis_validator = ValidatorInfo::new(
        genesis_addr,
        genesis_kp.public_key().clone(),
        genesis_pq.clone(),
        genesis_bls.clone(),
        DEFAULT_MIN_VALIDATOR_SELF_STAKE,
    );
    let em = Arc::new(EpochManager::new(vec![genesis_validator], 100).expect("epoch manager"));

    // Bootstrap ValidatorRegistry with the genesis validator pre-seeded as
    // Active (mirrors `Node::start()` post task #413).
    let registry = ValidatorRegistry::new();
    let inserted = registry
        .seed_genesis_active(
            genesis_addr,
            genesis_kp.public_key().as_bytes().to_vec(),
            genesis_pq.clone(),
            genesis_bls.clone(),
            genesis_addr,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            String::new(),
        )
        .expect("seed genesis");
    assert!(inserted);
    assert_eq!(registry.list_active().len(), 1);

    // ---- Register candidate ----
    registry
        .register_candidate(
            cand_addr,
            cand_kp.public_key().as_bytes().to_vec(),
            cand_pq.clone(),
            cand_bls.clone(),
            cand_addr,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            0,
            String::from("test-candidate"),
        )
        .expect("register candidate");
    assert_eq!(
        registry.get(&cand_addr).unwrap().status,
        ValidatorRegistryStatus::Candidate,
        "fresh registration must enter as Candidate"
    );

    // ---- Epoch 1: Candidate → PendingActive ----
    apply_epoch_transition(&registry, &em, 1);
    assert_eq!(
        registry.get(&cand_addr).unwrap().status,
        ValidatorRegistryStatus::PendingActive,
        "first transition must move Candidate → PendingActive"
    );

    // ---- Epoch 2: PendingActive → Active, EpochManager picks it up ----
    apply_epoch_transition(&registry, &em, 2);
    assert_eq!(
        registry.get(&cand_addr).unwrap().status,
        ValidatorRegistryStatus::Active,
        "second transition must promote to Active"
    );
    assert_eq!(
        registry.get(&cand_addr).unwrap().activated_at_epoch,
        Some(2),
        "activation epoch recorded"
    );
    let active = registry.list_active();
    assert_eq!(active.len(), 2, "genesis + candidate now both Active");
    let active_addrs: Vec<Address> = active.iter().map(|e| e.address).collect();
    assert!(active_addrs.contains(&genesis_addr));
    assert!(active_addrs.contains(&cand_addr));

    // ---- Voluntary exit ----
    registry
        .request_exit(&cand_addr)
        .expect("request_exit on Active validator");
    assert_eq!(
        registry.get(&cand_addr).unwrap().status,
        ValidatorRegistryStatus::PendingExit,
        "exit request flips Active → PendingExit"
    );

    // ---- Epoch 3: PendingExit → Exited, EpochManager removes from pending ----
    apply_epoch_transition(&registry, &em, 3);
    assert_eq!(
        registry.get(&cand_addr).unwrap().status,
        ValidatorRegistryStatus::Exited,
        "exit transition must complete"
    );
    assert_eq!(
        registry.get(&cand_addr).unwrap().exited_at_epoch,
        Some(3),
        "exit epoch recorded"
    );

    // After exit, only genesis remains in the Active set.
    let active = registry.list_active();
    assert_eq!(active.len(), 1, "only genesis remains Active after exit");
    assert_eq!(active[0].address, genesis_addr);
}

#[tokio::test]
async fn jail_blocks_reactivation_until_governance() {
    // ---- Setup: registry + EpochManager with one Active validator ----
    let (v_addr, v_kp, v_pq, v_bls) = fresh_validator_keys(0x03);

    let registry = ValidatorRegistry::new();
    registry
        .seed_genesis_active(
            v_addr,
            v_kp.public_key().as_bytes().to_vec(),
            v_pq.clone(),
            v_bls.clone(),
            v_addr,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            String::new(),
        )
        .expect("seed");

    // ---- Equivocation slash → jail at epoch 5 ----
    registry.jail(&v_addr, 5).expect("jail");
    assert_eq!(
        registry.get(&v_addr).unwrap().status,
        ValidatorRegistryStatus::Jailed,
        "jail flips status to Jailed"
    );
    assert_eq!(
        registry.list_active().len(),
        0,
        "Jailed leaves the active set"
    );

    // ---- Future epoch transitions must NOT silently re-promote a jailed entry ----
    let plan_6 = registry.compute_epoch_transition(6);
    assert!(
        !plan_6.effective_activations.contains(&v_addr),
        "jailed validator must not be re-activated by epoch transition"
    );
    assert!(
        !plan_6.activations.contains(&v_addr),
        "jailed validator must not be staged for activation"
    );

    let plan_10 = registry.compute_epoch_transition(10);
    assert!(
        !plan_10.effective_activations.contains(&v_addr),
        "jailed validator must remain jailed across multiple epochs"
    );

    // ---- Re-registering through the candidate flow must also fail ----
    let err = registry
        .register_candidate(
            v_addr,
            v_kp.public_key().as_bytes().to_vec(),
            v_pq,
            v_bls,
            v_addr,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            10,
            String::new(),
        )
        .unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.to_lowercase().contains("already registered") || msg.to_lowercase().contains("jailed"),
        "re-registration must reject the address while it has any non-Exited entry; got: {}",
        msg
    );
}
