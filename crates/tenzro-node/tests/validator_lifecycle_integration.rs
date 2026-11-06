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
//! (which would require a 200+ MB RocksDB + iroh + rpc startup just to
//! verify a handful of in-memory state transitions). The hook in question
//! is intentionally pure: registry → plan → epoch-manager mutations. We
//! reproduce it here against in-process instances of both registries.

use std::sync::Arc;

use tenzro_consensus::ValidatorPublicKey;
use tenzro_consensus::epoch_manager::EpochManager;
use tenzro_consensus::validator::ValidatorInfo;
use tenzro_token::validator_registry::{
    DEFAULT_MIN_VALIDATOR_SELF_STAKE, ValidatorRegistry, ValidatorRegistryStatus,
};
use tenzro_types::primitives::Address;

/// Reproduces the post-finalize bridge logic from `event_loop::handle_block_finalized`.
///
/// In production this is invoked once per epoch boundary. It pulls the plan
/// from the registry and applies the activation/exit deltas to the
/// EpochManager's pending queues. The EpochManager's own `transition_epoch`
/// (run by consensus when it derives the next committee) then promotes
/// those pending entries into the next epoch's active set.
fn apply_epoch_transition(registry: &ValidatorRegistry, em: &EpochManager, new_epoch: u64) {
    let plan = registry.compute_epoch_transition(new_epoch);
    let info = |entry: &tenzro_token::validator_registry::ValidatorRegistryEntry| {
        let key = ValidatorPublicKey::new(entry.ml_dsa_pubkey.clone(), entry.p256_pubkey.clone())
            .expect("registered keys are well formed");
        ValidatorInfo::new(entry.address, key, entry.node_key, entry.self_stake)
    };

    for addr in &plan.effective_activations {
        let entry = match registry.get(addr) {
            Some(e) => e,
            None => continue,
        };
        em.add_pending_validator(info(&entry));
    }

    for addr in &plan.effective_exits {
        em.remove_pending_validator(addr);
    }

    // Continuing members whose stake moved. Mirrors the production hook: a
    // validator that stays Active appears in neither list above, so without
    // this its voting power never tracks the registry.
    let live_set = em.current_validator_set();
    for entry in registry.list_active() {
        let Some(seated) = live_set.get_by_address(&entry.address) else {
            continue;
        };
        if seated.stake == entry.self_stake {
            continue;
        }
        em.add_pending_validator(info(&entry));
    }
}

/// Returns a `(address, composite consensus key, endpoint)` tuple.
fn fresh_validator_keys(seed: u8) -> (Address, ValidatorPublicKey, [u8; 32]) {
    // Deterministic-ish address by repeating seed across the 32 bytes —
    // good enough for an in-process unit test where uniqueness is the only
    // requirement (no on-chain derivation, no signing through this addr).
    let address = Address::new([seed; 32]);
    let key = ValidatorPublicKey::new(
        tenzro_crypto::pq::MlDsaSigningKey::generate()
            .verifying_key_bytes()
            .to_vec(),
        tenzro_crypto::P256KeyPair::generate()
            .public_key_sec1()
            .to_vec(),
    )
    .expect("well-formed key");
    (address, key, [seed; 32])
}

#[tokio::test]
async fn full_lifecycle_register_activate_produce_exit() {
    // ---- Setup ----
    // Genesis validator (always active) + a candidate that joins later.
    let (genesis_addr, genesis_key, genesis_endpoint) = fresh_validator_keys(0x01);
    let (cand_addr, cand_key, cand_endpoint) = fresh_validator_keys(0x02);

    // Bootstrap EpochManager with just the genesis validator so the active
    // set can produce blocks before the candidate is admitted.
    let genesis_validator = ValidatorInfo::new(
        genesis_addr,
        genesis_key.clone(),
        genesis_endpoint,
        DEFAULT_MIN_VALIDATOR_SELF_STAKE,
    );
    let em = Arc::new(EpochManager::new(vec![genesis_validator], 100).expect("epoch manager"));

    // Bootstrap ValidatorRegistry with the genesis validator pre-seeded as
    // Active (mirrors `Node::start()` post task #413).
    let registry = ValidatorRegistry::new();
    let inserted = registry
        .seed_genesis_active(
            genesis_addr,
            genesis_key.ml_dsa.clone(),
            genesis_key.p256.clone(),
            genesis_endpoint,
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
            cand_key.ml_dsa.clone(),
            cand_key.p256.clone(),
            cand_endpoint,
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
    let (v_addr, v_key, v_endpoint) = fresh_validator_keys(0x03);

    let registry = ValidatorRegistry::new();
    registry
        .seed_genesis_active(
            v_addr,
            v_key.ml_dsa.clone(),
            v_key.p256.clone(),
            v_endpoint,
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
            v_key.ml_dsa,
            v_key.p256,
            v_endpoint,
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

/// A stake increase on a validator that never leaves the set must reach
/// consensus, phased in under the per-epoch churn budget.
///
/// The bridge carries activations and exits. A continuing member appears in
/// neither, so before the restage block its voting power stayed frozen at
/// whatever it registered with: the registry reported the new stake, the RPC
/// reported the new stake, and quorum arithmetic kept using the old one.
///
/// That is the operation a network bootstrapped from one heavily-funded
/// genesis validator depends on — diluting the founder, or topping up the
/// others, is the only route to a set that survives losing a node. Failing
/// silently is the worst possible way for it to not work.
#[tokio::test]
async fn a_stake_increase_on_a_continuing_validator_reaches_consensus() {
    let (addr, key, endpoint) = fresh_validator_keys(0x41);

    let seated = ValidatorInfo::new(
        addr,
        key.clone(),
        endpoint,
        DEFAULT_MIN_VALIDATOR_SELF_STAKE,
    );
    let em = Arc::new(EpochManager::new(vec![seated], 100).expect("epoch manager"));

    let registry = ValidatorRegistry::new();
    registry
        .seed_genesis_active(
            addr,
            key.ml_dsa.clone(),
            key.p256.clone(),
            endpoint,
            addr,
            DEFAULT_MIN_VALIDATOR_SELF_STAKE,
            String::new(),
        )
        .expect("seed genesis");

    // Triple the stake. Nothing about the validator's membership changes, so
    // the plan's activation and exit lists both stay empty.
    let topped_up = DEFAULT_MIN_VALIDATOR_SELF_STAKE * 3;
    let new_total = registry
        .increase_self_stake(&addr, DEFAULT_MIN_VALIDATOR_SELF_STAKE * 2)
        .expect("increase self stake");
    assert_eq!(new_total, topped_up);

    let plan = registry.compute_epoch_transition(1);
    assert!(
        plan.effective_activations.is_empty() && plan.effective_exits.is_empty(),
        "a continuing member must not show up as an entry or a departure"
    );

    // New voting power is admitted at up to half the continuing stake per
    // epoch, so the increase phases in: 10k -> 15k -> 22.5k -> 30k.
    let mut stake = DEFAULT_MIN_VALIDATOR_SELF_STAKE;
    for epoch in 1..=3u64 {
        apply_epoch_transition(&registry, &em, epoch);
        let next = em
            .transition_epoch(tenzro_types::primitives::BlockHeight::from(epoch * 100))
            .expect("transition")
            .expect("a due transition returns the new set");
        assert_eq!(next.len(), 1, "restaging must not duplicate the validator");
        let now = next
            .get_by_address(&addr)
            .map(|v| v.stake)
            .expect("still seated");
        assert!(
            now > stake,
            "epoch {epoch}: the increase must keep phasing in"
        );
        assert!(
            now - stake <= stake / 2,
            "epoch {epoch}: growth beyond the churn budget"
        );
        stake = now;
    }
    assert_eq!(
        stake, topped_up,
        "consensus voting power must track the registry, not the stake the \
         validator happened to register with"
    );
}
