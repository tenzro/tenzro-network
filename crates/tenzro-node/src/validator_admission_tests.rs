//! Validator admission at the node: the committee, the peer gate and the RPC
//! answers, with closed and open mode.

use std::sync::Arc;

use tenzro_consensus::ValidatorPublicKey;
use tenzro_consensus::epoch_manager::EpochManager;
use tenzro_consensus::validator::{ValidatorInfo, ValidatorSet};
use tenzro_token::validator_registry::ValidatorRegistry;
use tenzro_types::constants::ONE_TNZO;
use tenzro_types::primitives::{Address, BlockHeight};
use tenzro_vm::StateAdapter;
use tenzro_vm::native::{
    SYSTEM_ADDRESS, VALIDATOR_ADMISSION_APPROVAL_PARAM, genesis_validator_bonds, set_genesis_param,
};
use tenzro_vm::traits::VmState;
use tenzro_vm::validator_admission as rule;

use crate::event_loop::EventLoop;
use crate::validator_admission::{PeerGate, enforce_committee, rpc_refusal, status_json};

fn keys(seed: u8) -> (Address, ValidatorPublicKey, [u8; 32]) {
    let key = ValidatorPublicKey::new(
        tenzro_crypto::pq::MlDsaSigningKey::generate()
            .verifying_key_bytes()
            .to_vec(),
        tenzro_crypto::P256KeyPair::generate()
            .public_key_sec1()
            .to_vec(),
    )
    .expect("well-formed key");
    (Address::new([seed; 32]), key, [seed; 32])
}

fn mode(state: &mut StateAdapter, closed: bool) {
    set_genesis_param(state, VALIDATOR_ADMISSION_APPROVAL_PARAM, u64::from(closed));
}

fn admit(state: &mut StateAdapter, who: &Address) {
    for (k, v) in rule::genesis_entries(&[who.0]) {
        state.set_storage(&SYSTEM_ADDRESS, &k, v);
    }
}

/// Bonds `who` in state with its consensus key indexed, as a registration does.
fn bond(state: &mut StateAdapter, who: &Address, key: &ValidatorPublicKey, tnzo: u128) {
    let (entries, _) =
        genesis_validator_bonds(&[(who.0, key.fingerprint(), [9; 32], tnzo * ONE_TNZO)])
            .expect("bond");
    for (k, v) in entries {
        state.set_storage(&SYSTEM_ADDRESS, &k, v);
    }
}

fn seed(registry: &ValidatorRegistry, who: &Address, key: &ValidatorPublicKey, tnzo: u128) {
    registry
        .seed_genesis_active(
            *who,
            key.ml_dsa.clone(),
            key.p256.clone(),
            who.0,
            *who,
            tnzo * ONE_TNZO,
            String::new(),
        )
        .expect("seed");
}

/// One epoch boundary: stage the registry plan, enforce admission, transition.
fn boundary(
    em: &Arc<EpochManager>,
    registry: &Arc<ValidatorRegistry>,
    state: &StateAdapter,
    height: u64,
) -> ValidatorSet {
    EventLoop::stage_registry_epoch_plan(em, registry, &|_| true);
    enforce_committee(em, state);
    em.transition_epoch(BlockHeight::from(height))
        .expect("transition")
        .expect("a due transition returns the new set")
}

/// A bonded, registered account that is not admitted never reaches the
/// committee in closed mode; in open mode the same account is seated.
#[tokio::test]
async fn validator_admission_closed_keeps_a_bonded_account_off_the_committee() {
    let (a, ka, ea) = keys(0x11);
    let (b, kb, _) = keys(0x12);
    for closed in [true, false] {
        let em = Arc::new(
            EpochManager::new(vec![ValidatorInfo::new(a, ka.clone(), ea, 10_000_000)], 100)
                .unwrap(),
        );
        let registry = Arc::new(ValidatorRegistry::new());
        seed(&registry, &a, &ka, 10_000_000);
        seed(&registry, &b, &kb, 10_000);
        let mut state = StateAdapter::new();
        mode(&mut state, closed);
        admit(&mut state, &a);
        bond(&mut state, &b, &kb, 10_000);

        let next = boundary(&em, &registry, &state, 100);
        assert!(next.get_by_address(&a).is_some());
        assert_eq!(
            next.get_by_address(&b).is_some(),
            !closed,
            "closed: {closed}"
        );
    }
}

/// A seated validator taken off the admitted set leaves at the next boundary,
/// and an account added to the set joins at the next boundary after it.
#[tokio::test]
async fn validator_admission_set_changes_take_effect_at_the_next_boundary() {
    let (a, ka, ea) = keys(0x21);
    let (c, kc, _) = keys(0x22);
    let (d, kd, ed) = keys(0x23);
    let em = Arc::new(
        EpochManager::new(
            vec![
                ValidatorInfo::new(a, ka.clone(), ea, 10_000_000),
                ValidatorInfo::new(d, kd.clone(), ed, 1_000),
            ],
            100,
        )
        .unwrap(),
    );
    let registry = Arc::new(ValidatorRegistry::new());
    seed(&registry, &a, &ka, 10_000_000);
    seed(&registry, &d, &kd, 1_000);
    seed(&registry, &c, &kc, 10_000);
    let mut state = StateAdapter::new();
    mode(&mut state, true);
    admit(&mut state, &a);
    admit(&mut state, &d);

    // C is not admitted: not seated. D and A are: seated.
    let one = boundary(&em, &registry, &state, 100);
    assert!(one.get_by_address(&c).is_none());
    assert!(one.get_by_address(&d).is_some());

    // Governance admits C and takes D off: the next boundary seats C and
    // drops D.
    admit(&mut state, &c);
    state.set_storage(
        &SYSTEM_ADDRESS,
        tenzro_vm::native::validator_approval_key(d.as_bytes()).as_bytes(),
        Vec::new(),
    );
    let two = boundary(&em, &registry, &state, 200);
    assert!(two.get_by_address(&c).is_some(), "admitted: seated");
    assert!(two.get_by_address(&d).is_none(), "taken off: removed");
    assert!(two.get_by_address(&a).is_some());
}

/// Closed mode refuses an announcement from a key that is not an admitted
/// account's; open mode, an admitted key and a node with no state let it by.
#[test]
fn validator_admission_peer_gate_refuses_a_key_that_is_not_admitted() {
    let (a, ka, _) = keys(0x31);
    let (b, kb, _) = keys(0x32);
    let mut state = StateAdapter::new();
    mode(&mut state, true);
    bond(&mut state, &a, &ka, 10_000);
    bond(&mut state, &b, &kb, 10_000);
    admit(&mut state, &a);

    let gate = PeerGate::default();
    let chain: Option<&dyn VmState> = Some(&state);
    assert!(gate.allows(chain, &ka.fingerprint()));
    assert!(!gate.allows(chain, &kb.fingerprint()));
    assert!(
        !gate.allows(chain, &[7; 32]),
        "an unknown key is not admitted"
    );
    assert_eq!(gate.refused(), 2);
    assert!(
        gate.allows(None, &kb.fingerprint()),
        "no state: nothing refused"
    );

    mode(&mut state, false);
    let chain: Option<&dyn VmState> = Some(&state);
    assert!(gate.allows(chain, &kb.fingerprint()), "open");
    assert_eq!(gate.refused(), 2);
}

/// The raw RPC refusal has its own code and says what to do; the status read
/// reports the mode and whether an address is admitted.
#[test]
fn validator_admission_rpc_refusal_and_status_read() {
    let err = rpc_refusal(&[1; 32]);
    assert_eq!(err.code, rule::REFUSAL_RPC_CODE);
    assert!(
        err.message.starts_with(rule::REFUSAL_CODE),
        "{}",
        err.message
    );
    assert!(err.message.contains("operator"), "{}", err.message);
    let data = err.data.expect("data");
    assert_eq!(data["reason"], rule::REFUSAL_CODE);
    assert_eq!(data["contact"], "team@tenzro.com");

    let (a, _, _) = keys(0x41);
    let mut state = StateAdapter::new();
    mode(&mut state, true);
    admit(&mut state, &a);
    let admitted = status_json(&state, Some(&a.0[..]));
    assert_eq!(admitted["mode"], "closed");
    assert_eq!(admitted["admitted"], true);
    let stranger = status_json(&state, Some(&[9u8; 32][..]));
    assert_eq!(stranger["admitted"], false);
    assert_eq!(stranger["on_admitted_set"], false);
    assert!(status_json(&state, None)["admitted"].is_null());

    mode(&mut state, false);
    let open = status_json(&state, Some(&[9u8; 32][..]));
    assert_eq!(open["mode"], "open");
    assert_eq!(open["admitted"], true);
}

/// What a node that kept running and a node that restarted in the middle of
/// an epoch derive for the next boundary, given the same chain state.
fn restarted_twin(seated: &Arc<EpochManager>) -> Arc<EpochManager> {
    let set: Vec<ValidatorInfo> = seated.current_validator_set().iter().cloned().collect();
    Arc::new(EpochManager::new(set, 100).unwrap())
}

/// A removal admission closed queues is taken from the chain at every
/// boundary, so a node restarted mid-epoch queues the same one and derives the
/// same next set as a node that never stopped.
#[tokio::test]
async fn an_admission_refusal_is_derived_again_after_a_restart() {
    let (a, ka, ea) = keys(0x31);
    let (d, kd, ed) = keys(0x32);
    let (e, ke, ee) = keys(0x33);
    let running = Arc::new(
        EpochManager::new(
            vec![
                ValidatorInfo::new(a, ka.clone(), ea, 1_000),
                ValidatorInfo::new(d, kd.clone(), ed, 1_000),
                ValidatorInfo::new(e, ke.clone(), ee, 1_000),
            ],
            100,
        )
        .unwrap(),
    );
    let registry = Arc::new(ValidatorRegistry::new());
    seed(&registry, &a, &ka, 1_000);
    seed(&registry, &d, &kd, 1_000);
    seed(&registry, &e, &ke, 1_000);
    let mut state = StateAdapter::new();
    mode(&mut state, true);
    admit(&mut state, &a);

    // Two seated validators are refused; the churn budget lets one go now.
    let one = boundary(&running, &registry, &state, 100);
    assert_eq!(one.len(), 2, "one removal applied, one deferred");
    // The node restarts: its queue is empty, its seated set is the same.
    let restarted = restarted_twin(&running);
    restarted.transition_epoch(BlockHeight::from(100)).unwrap();
    let kept = boundary(&running, &registry, &state, 200);
    let again = boundary(&restarted, &registry, &state, 200);
    let addrs = |s: &ValidatorSet| s.iter().map(|v| v.address).collect::<Vec<_>>();
    assert_eq!(addrs(&kept), addrs(&again));
    assert!(kept.get_by_address(&a).is_some());
}

/// A validator the registry holds Jailed leaves at the next boundary whether
/// the node saw the evidence run or restarted since: the removal is taken from
/// the registry, not only from a queue held in memory.
#[tokio::test]
async fn a_slashed_validator_is_removed_after_a_restart() {
    let (a, ka, ea) = keys(0x41);
    let (d, kd, ed) = keys(0x42);
    let (e, ke, ee) = keys(0x43);
    let validators = vec![
        ValidatorInfo::new(a, ka.clone(), ea, 1_000),
        ValidatorInfo::new(d, kd.clone(), ed, 1_000),
        ValidatorInfo::new(e, ke.clone(), ee, 1_000),
    ];
    let registry = Arc::new(ValidatorRegistry::new());
    seed(&registry, &a, &ka, 1_000);
    seed(&registry, &d, &kd, 1_000);
    seed(&registry, &e, &ke, 1_000);
    let state = StateAdapter::new();

    // The node that ran when the evidence executed: queue and registry.
    let running = Arc::new(EpochManager::new(validators.clone(), 100).unwrap());
    running.remove_pending_validator(&e);
    registry.jail(&e, 0).unwrap();
    // The restarted node: the registry is back, the queue is not.
    let restarted = Arc::new(EpochManager::new(validators, 100).unwrap());

    let kept = boundary(&running, &registry, &state, 100);
    let again = boundary(&restarted, &registry, &state, 100);
    assert!(kept.get_by_address(&e).is_none());
    assert!(
        again.get_by_address(&e).is_none(),
        "the restart still removes it"
    );
    let addrs = |s: &ValidatorSet| s.iter().map(|v| v.address).collect::<Vec<_>>();
    assert_eq!(addrs(&kept), addrs(&again));
}

/// Two removals the churn budget cannot apply at once: one goes at the first
/// boundary, the other at the next. A node that restarted in between queues
/// the remaining one again from the registry and derives the same sets.
#[tokio::test]
async fn a_removal_the_budget_deferred_is_applied_after_a_restart() {
    let (a, ka, ea) = keys(0x51);
    let (d, kd, ed) = keys(0x52);
    let (e, ke, ee) = keys(0x53);
    let validators = vec![
        ValidatorInfo::new(a, ka.clone(), ea, 1_000),
        ValidatorInfo::new(d, kd.clone(), ed, 1_000),
        ValidatorInfo::new(e, ke.clone(), ee, 1_000),
    ];
    let registry = Arc::new(ValidatorRegistry::new());
    seed(&registry, &a, &ka, 1_000);
    seed(&registry, &d, &kd, 1_000);
    seed(&registry, &e, &ke, 1_000);
    registry.jail(&d, 0).unwrap();
    registry.jail(&e, 0).unwrap();
    let state = StateAdapter::new();

    let running = Arc::new(EpochManager::new(validators, 100).unwrap());
    let one = boundary(&running, &registry, &state, 100);
    assert_eq!(
        one.len(),
        2,
        "the budget removed one and deferred the other"
    );
    let restarted = restarted_twin(&running);
    restarted.transition_epoch(BlockHeight::from(100)).unwrap();

    let kept = boundary(&running, &registry, &state, 200);
    let again = boundary(&restarted, &registry, &state, 200);
    let addrs = |s: &ValidatorSet| s.iter().map(|v| v.address).collect::<Vec<_>>();
    assert_eq!(addrs(&kept), addrs(&again));
    assert_eq!(kept.len(), 1, "both removals have been applied by now");
}

/// A validator the growth budget held back stays out of the next set on every
/// node once it has asked to leave, whether the node kept its queue or
/// restarted in the middle of the epoch and lost it.
#[tokio::test]
async fn a_held_back_entrant_that_asks_to_leave_is_not_seated_by_a_node_that_kept_its_queue() {
    let (s1, k1, e1) = keys(0x60);
    let (s2, k2, e2) = keys(0x61);
    let (s3, k3, e3) = keys(0x62);
    let (w, kw, _) = keys(0x71);
    let (v, kv, _) = keys(0x72);
    let seated = vec![
        ValidatorInfo::new(s1, k1.clone(), e1, 1_000),
        ValidatorInfo::new(s2, k2.clone(), e2, 1_000),
        ValidatorInfo::new(s3, k3.clone(), e3, 1_000),
    ];
    let registry = Arc::new(ValidatorRegistry::new());
    seed(&registry, &s1, &k1, 1_000);
    seed(&registry, &s2, &k2, 1_000);
    seed(&registry, &s3, &k3, 1_000);
    // Two entrants that together want more than the growth budget allows.
    seed(&registry, &w, &kw, 10_000);
    seed(&registry, &v, &kv, 10_000);
    let state = StateAdapter::new();

    let running = Arc::new(EpochManager::new(seated, 100).unwrap());
    let first = boundary(&running, &registry, &state, 100);
    assert!(
        first.get_by_address(&w).is_some(),
        "the first entrant takes the budget"
    );
    assert!(
        first.get_by_address(&v).is_none(),
        "the second is held back"
    );
    // One node restarts in the middle of the epoch and loses its queue.
    let restarted = restarted_twin(&running);
    restarted.transition_epoch(BlockHeight::from(100)).unwrap();

    // Both entrants ask to leave; the exit budget lets one go at a time.
    registry.request_exit(&w).unwrap();
    registry.request_exit(&v).unwrap();
    let kept = boundary(&running, &registry, &state, 200);
    let again = boundary(&restarted, &registry, &state, 200);
    let addrs = |s: &ValidatorSet| s.iter().map(|x| x.address).collect::<Vec<_>>();
    assert_eq!(addrs(&kept), addrs(&again));
    assert!(
        kept.get_by_address(&v).is_none(),
        "a validator that is leaving is not seated"
    );
}

/// The epoch manager writes its epochs through to disk apart from the block
/// commit, and that write can be the one that is lost. A boundary's undo record
/// is final when the chain shows the next epoch, so a restart does not put the
/// registry back over a whole epoch of committed changes.
#[test]
fn a_boundary_record_is_final_when_the_chain_shows_the_next_epoch() {
    // The manager lost its write (still in epoch 0); the chain is in epoch 1.
    assert!(!EventLoop::registry_tag_uncommitted(
        "boundary:1",
        9,
        Some(0),
        1
    ));
    // Neither the manager nor the chain has reached it.
    assert!(EventLoop::registry_tag_uncommitted(
        "boundary:1",
        9,
        Some(0),
        0
    ));
    // The manager has it.
    assert!(!EventLoop::registry_tag_uncommitted(
        "boundary:1",
        9,
        Some(1),
        0
    ));
    assert!(EventLoop::registry_tag_uncommitted(
        "block:10",
        9,
        Some(1),
        1
    ));
    assert!(!EventLoop::registry_tag_uncommitted(
        "block:9",
        9,
        Some(1),
        1
    ));

    let store: Arc<dyn tenzro_storage::KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
    let registry = ValidatorRegistry::with_storage(store);
    let (a, ka, _) = keys(0x81);
    seed(&registry, &a, &ka, 1_000);
    assert!(registry.write_undo("boundary:1", &registry.checkpoint()));
    // The epoch's blocks changed the registry and committed.
    let changed = registry.increase_self_stake(&a, 5).unwrap();
    let undone = registry
        .recover_uncommitted(|t| EventLoop::registry_tag_uncommitted(t, 9, Some(0), 1))
        .unwrap();
    assert_eq!(undone, 0);
    assert_eq!(
        registry.get(&a).unwrap().self_stake,
        changed,
        "the committed changes survive"
    );
}

/// A record in the chain's state gives the epoch manager's validators back.
#[test]
fn an_epoch_record_gives_back_its_validator_set() {
    let (a, ka, ea) = keys(0x91);
    let (b, kb, eb) = keys(0x92);
    let em = EpochManager::new(
        vec![
            ValidatorInfo::new(a, ka, ea, 1_000),
            ValidatorInfo::new(b, kb, eb, 2_000),
        ],
        100,
    )
    .unwrap();
    let record = crate::state_commitment::epoch_open_record(&em, BlockHeight::from(1), 0, 0)
        .unwrap()
        .expect("the first block opens epoch 0");
    let set = record.validator_set().unwrap();
    let want = em.current_validator_set();
    let addrs = |s: &ValidatorSet| s.iter().map(|v| (v.address, v.stake)).collect::<Vec<_>>();
    assert_eq!(addrs(&set), addrs(&want));
}

/// The operator command opens only a store that is there.
#[test]
fn a_missing_store_is_refused_not_created() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let config = tenzro_storage::StorageConfig::new(path.clone());
    assert!(tenzro_storage::RocksDbStore::open_existing(&config).is_err());
    assert!(!path.exists(), "nothing was created");
    drop(tenzro_storage::RocksDbStore::open(&config).unwrap());
    assert!(tenzro_storage::RocksDbStore::open_existing(&config).is_ok());
}
