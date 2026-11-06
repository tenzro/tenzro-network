//! An account is named by its P-256 key, and the ML-DSA-65 key it enrolls in
//! state is the only one its ML-DSA-65 leg verifies against. Once enrolled,
//! the hybrid is mandatory: the P-256 key alone no longer spends.

use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{CompositeSignature, HybridSigner, SignatureContext};
use tenzro_vm::account_keys::set_enrolled_pq_key;
use tenzro_vm::traits::VmState;
use tenzro_vm::{MultiVmRuntime, StateAdapter, VmConfig, VmTransaction, VmType};

const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

fn digest(nonce: u64) -> [u8; 32] {
    let mut d = [0u8; 32];
    d[..8].copy_from_slice(&nonce.to_le_bytes());
    d[8] = 0x5a;
    d
}

fn transfer(
    from: &[u8],
    p256: &[u8],
    to: &[u8],
    nonce: u64,
    sig: CompositeSignature,
) -> VmTransaction {
    let mut tx = VmTransaction::new(
        from.to_vec(),
        Some(to.to_vec()),
        ONE_TNZO,
        Vec::new(),
        21_000,
        1_000_000_000,
        nonce,
        VmType::Tenzro,
        VmConfig::default().chain_id,
    );
    tx.signature = Some(sig);
    tx.public_key = Some(p256.to_vec());
    tx.signing_digest = Some(digest(nonce).to_vec());
    tx.valid_until_ms = Some(tenzro_types::primitives::Timestamp::now().0 + 60_000);
    tx
}

/// A victim with an ML-DSA-65 key enrolled, funded.
fn enrolled_victim(state: &mut StateAdapter) -> (TestHybridSigner, Vec<u8>) {
    let victim = TestHybridSigner::hybrid(7);
    let account = victim.address().as_bytes().to_vec();
    let pk = victim.public_key().clone();
    let mut changes = Vec::new();
    set_enrolled_pq_key(state, &pk.p256, pk.pq.clone().unwrap(), &mut changes);
    state.set_balance(&account, 10 * ONE_TNZO);
    (victim, account)
}

#[tokio::test]
async fn a_stolen_p256_key_alone_cannot_spend_an_account_with_ml_dsa_enrolled() {
    let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
    let mut state = StateAdapter::new();
    let (victim, account) = enrolled_victim(&mut state);
    let to = vec![0x44u8; 20];

    // The thief holds the victim's P-256 key (same seed) and nothing else.
    let thief = TestHybridSigner::p256_only(7);
    assert_eq!(thief.public_key().p256, victim.public_key().p256);
    let stripped = thief
        .sign(SignatureContext::Transaction, &digest(0))
        .unwrap();
    assert!(stripped.pq.is_none());
    let tx = transfer(&account, &thief.public_key().p256, &to, 0, stripped);
    assert!(runtime.execute_transaction(&tx, &mut state).await.is_err());
    assert_eq!(state.get_balance(&account), 10 * ONE_TNZO);
    assert_eq!(state.get_balance(&to), 0);
    assert_eq!(state.get_nonce(&account), 0);

    // An ML-DSA-65 leg under the thief's own ML-DSA-65 key is refused too:
    // only the key enrolled in state counts.
    let foreign = TestHybridSigner::hybrid(9)
        .sign(SignatureContext::Transaction, &digest(0))
        .unwrap();
    let mut grafted = thief
        .sign(SignatureContext::Transaction, &digest(0))
        .unwrap();
    grafted.pq = foreign.pq;
    let tx = transfer(&account, &thief.public_key().p256, &to, 0, grafted);
    assert!(runtime.execute_transaction(&tx, &mut state).await.is_err());
    assert_eq!(state.get_balance(&to), 0);

    // The victim's hardware, holding both keys, spends.
    let honest = victim
        .sign(SignatureContext::Transaction, &digest(0))
        .unwrap();
    let tx = transfer(&account, &victim.public_key().p256, &to, 0, honest);
    assert!(
        runtime
            .execute_transaction(&tx, &mut state)
            .await
            .unwrap()
            .success
    );
    assert_eq!(state.get_balance(&to), ONE_TNZO);
}

#[tokio::test]
async fn an_account_without_ml_dsa_enrolled_spends_nothing() {
    let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
    let signer = TestHybridSigner::hybrid(3);
    let p256_alone = TestHybridSigner::p256_only(3);
    let account = signer.address().as_bytes().to_vec();
    let to = vec![0x46u8; 20];
    let mut state = StateAdapter::new();
    state.set_balance(&account, 10 * ONE_TNZO);

    // P-256 alone is refused, and so is a hybrid signature while no ML-DSA-65
    // key is enrolled for the account to verify it against.
    for sig in [
        p256_alone
            .sign(SignatureContext::Transaction, &digest(0))
            .unwrap(),
        signer
            .sign(SignatureContext::Transaction, &digest(0))
            .unwrap(),
    ] {
        let tx = transfer(&account, &signer.public_key().p256, &to, 0, sig);
        let mut probe = state.fork();
        assert!(!succeeded(
            &runtime.execute_transaction(&tx, &mut probe).await
        ));
        assert_eq!(probe.get_balance(&to), 0);
    }

    // Once enrolled, the hybrid spends; the same key cannot name another account.
    let enrol = keys_tx(
        &signer,
        0,
        enrollment(&signer, &signer),
        signer
            .sign(SignatureContext::Transaction, &digest(0))
            .unwrap(),
    );
    assert!(succeeded(
        &runtime.execute_transaction(&enrol, &mut state).await
    ));
    let sig = signer
        .sign(SignatureContext::Transaction, &digest(1))
        .unwrap();
    let tx = transfer(&account, &signer.public_key().p256, &to, 1, sig);
    assert!(succeeded(
        &runtime.execute_transaction(&tx, &mut state).await
    ));

    let other = vec![0x47u8; 32];
    state.set_balance(&other, 10 * ONE_TNZO);
    let sig = signer
        .sign(SignatureContext::Transaction, &digest(0))
        .unwrap();
    let tx = transfer(&other, &signer.public_key().p256, &to, 0, sig);
    assert!(runtime.execute_transaction(&tx, &mut state).await.is_err());
}

#[tokio::test]
async fn a_transaction_signature_minted_for_another_protocol_is_refused() {
    let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
    let mut state = StateAdapter::new();
    let (victim, account) = enrolled_victim(&mut state);
    let to = vec![0x45u8; 20];
    let sig = victim
        .sign(SignatureContext::AgentMessage, &digest(0))
        .unwrap();
    let tx = transfer(&account, &victim.public_key().p256, &to, 0, sig);
    assert!(runtime.execute_transaction(&tx, &mut state).await.is_err());
    assert_eq!(state.get_balance(&to), 0);
}

fn enrollment(owner: &TestHybridSigner, pq: &TestHybridSigner) -> Vec<u8> {
    use tenzro_types::account_signature::{AccountKeysOp, pq_enrollment_message};
    let key = pq.public_key().pq.clone().unwrap();
    let msg = pq_enrollment_message(&owner.public_key().account_slot(), &key);
    let possession = pq
        .sign(SignatureContext::PqKeyEnrollment, &msg)
        .unwrap()
        .pq
        .unwrap();
    let op = AccountKeysOp::EnrollPqKey {
        ml_dsa_public_key: key,
        possession,
    };
    let mut data = tenzro_vm::account_keys::SELECTOR_ACCOUNT_KEYS.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&op).unwrap());
    data
}

fn keys_tx(
    owner: &TestHybridSigner,
    nonce: u64,
    data: Vec<u8>,
    sig: CompositeSignature,
) -> VmTransaction {
    let mut tx = transfer(
        owner.address().as_bytes(),
        &owner.public_key().p256,
        tenzro_vm::native::SYSTEM_ADDRESS.as_slice(),
        nonce,
        sig,
    );
    tx.value = 0;
    tx.data = data;
    tx.gas_limit = 200_000;
    tx
}

fn succeeded(r: &tenzro_vm::Result<tenzro_vm::ExecutionResult>) -> bool {
    matches!(r, Ok(x) if x.success)
}

#[tokio::test]
async fn enrolling_an_ml_dsa_key_takes_both_legs_and_rotating_it_takes_the_old_one() {
    let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
    let mut state = StateAdapter::new();
    let owner = TestHybridSigner::hybrid(21);
    let p256_alone = TestHybridSigner::p256_only(21);
    let account = owner.address().as_bytes().to_vec();
    state.set_balance(&account, 10 * ONE_TNZO);

    // A refused operation still consumes its nonce, so each attempt signs the
    // account's next one.
    // P-256 alone cannot enroll, not even the key it would carry.
    let n = state.get_nonce(&account);
    let sig = p256_alone
        .sign(SignatureContext::Transaction, &digest(n))
        .unwrap();
    let r = runtime
        .execute_transaction(
            &keys_tx(&owner, n, enrollment(&owner, &owner), sig),
            &mut state,
        )
        .await;
    assert!(!succeeded(&r));
    assert!(tenzro_vm::account_keys::enrolled_pq_key(&state, &owner.public_key().p256).is_none());

    // A proof of possession by another key does not enroll this one.
    let other = TestHybridSigner::hybrid(22);
    let real = enrollment(&owner, &other);
    let mut forged = real[..4].to_vec();
    let mut op: serde_json::Value =
        serde_json::from_slice(&enrollment(&owner, &owner)[4..]).unwrap();
    let other_op: serde_json::Value = serde_json::from_slice(&real[4..]).unwrap();
    op["enroll_pq_key"]["possession"] = other_op["enroll_pq_key"]["possession"].clone();
    forged.extend_from_slice(&serde_json::to_vec(&op).unwrap());
    let n = state.get_nonce(&account);
    let sig = owner
        .sign(SignatureContext::Transaction, &digest(n))
        .unwrap();
    assert!(!succeeded(
        &runtime
            .execute_transaction(&keys_tx(&owner, n, forged, sig), &mut state)
            .await
    ));

    // Both legs by the key being enrolled.
    let n = state.get_nonce(&account);
    let sig = owner
        .sign(SignatureContext::Transaction, &digest(n))
        .unwrap();
    let r = runtime
        .execute_transaction(
            &keys_tx(&owner, n, enrollment(&owner, &owner), sig),
            &mut state,
        )
        .await;
    assert!(succeeded(&r), "{r:?}");
    assert_eq!(
        tenzro_vm::account_keys::enrolled_pq_key(&state, &owner.public_key().p256),
        owner.public_key().pq.clone()
    );

    // Rotation signed by the new key alone is refused: it needs the old one.
    let next = TestHybridSigner::hybrid(23);
    let n = state.get_nonce(&account);
    let mut sig = owner
        .sign(SignatureContext::Transaction, &digest(n))
        .unwrap();
    sig.pq = next
        .sign(SignatureContext::Transaction, &digest(n))
        .unwrap()
        .pq;
    let r = runtime
        .execute_transaction(
            &keys_tx(&owner, n, enrollment(&owner, &next), sig),
            &mut state,
        )
        .await;
    assert!(!succeeded(&r));
    assert_eq!(
        tenzro_vm::account_keys::enrolled_pq_key(&state, &owner.public_key().p256),
        owner.public_key().pq.clone()
    );

    // The P-256 key alone cannot rotate either.
    let n = state.get_nonce(&account);
    let sig = p256_alone
        .sign(SignatureContext::Transaction, &digest(n))
        .unwrap();
    let r = runtime
        .execute_transaction(
            &keys_tx(&owner, n, enrollment(&owner, &next), sig),
            &mut state,
        )
        .await;
    assert!(!succeeded(&r));

    // P-256 plus the enrolled key rotates.
    let n = state.get_nonce(&account);
    let sig = owner
        .sign(SignatureContext::Transaction, &digest(n))
        .unwrap();
    let r = runtime
        .execute_transaction(
            &keys_tx(&owner, n, enrollment(&owner, &next), sig),
            &mut state,
        )
        .await;
    assert!(succeeded(&r), "{r:?}");
    assert_eq!(
        tenzro_vm::account_keys::enrolled_pq_key(&state, &owner.public_key().p256),
        next.public_key().pq.clone()
    );
}

/// An account moves to the hybrid on a running chain, then rotates its
/// ML-DSA-65 key, with no restart. Nothing spends before the enrolment, which
/// is the account's first transaction; its balance and nonce carry through
/// every step, and the enrolment still executes against the state it was made
/// in, which is what replaying the chain from genesis does.
#[tokio::test]
async fn an_account_moves_to_ml_dsa_and_rotates_it_while_its_enrolment_still_verifies() {
    let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
    let mut state = StateAdapter::new();
    let owner = TestHybridSigner::hybrid(31);
    let p256_alone = TestHybridSigner::p256_only(31);
    let account = owner.address().as_bytes().to_vec();
    let to = vec![0x55u8; 20];
    state.set_balance(&account, 10 * ONE_TNZO);

    // Before enrolment the P-256 key alone spends nothing.
    let before_enrolment = state.fork();
    let first = transfer(
        &account,
        &owner.public_key().p256,
        &to,
        0,
        p256_alone
            .sign(SignatureContext::Transaction, &digest(0))
            .unwrap(),
    );
    let mut probe = state.fork();
    assert!(!succeeded(
        &runtime.execute_transaction(&first, &mut probe).await
    ));
    assert_eq!(probe.get_balance(&to), 0);

    // Enroll ML-DSA-65 alongside P-256.
    let n = state.get_nonce(&account);
    let sig = owner
        .sign(SignatureContext::Transaction, &digest(n))
        .unwrap();
    let enrolment_tx = keys_tx(&owner, n, enrollment(&owner, &owner), sig);
    let r = runtime.execute_transaction(&enrolment_tx, &mut state).await;
    assert!(succeeded(&r), "{r:?}");

    // From here the P-256 key alone still spends nothing; the hybrid does.
    let n = state.get_nonce(&account);
    let alone = transfer(
        &account,
        &owner.public_key().p256,
        &to,
        n,
        p256_alone
            .sign(SignatureContext::Transaction, &digest(n))
            .unwrap(),
    );
    assert!(!succeeded(
        &runtime.execute_transaction(&alone, &mut state).await
    ));
    let n = state.get_nonce(&account);
    let hybrid = transfer(
        &account,
        &owner.public_key().p256,
        &to,
        n,
        owner
            .sign(SignatureContext::Transaction, &digest(n))
            .unwrap(),
    );
    assert!(succeeded(
        &runtime.execute_transaction(&hybrid, &mut state).await
    ));
    assert_eq!(state.get_balance(&to), ONE_TNZO);

    // Rotate the ML-DSA-65 key: the old key signs the hand-over, then only
    // the new one verifies.
    let next = TestHybridSigner::hybrid(32);
    let n = state.get_nonce(&account);
    let sig = owner
        .sign(SignatureContext::Transaction, &digest(n))
        .unwrap();
    let r = runtime
        .execute_transaction(
            &keys_tx(&owner, n, enrollment(&owner, &next), sig),
            &mut state,
        )
        .await;
    assert!(succeeded(&r), "{r:?}");
    let with_key = |pq: &TestHybridSigner, n: u64| {
        let mut sig = owner
            .sign(SignatureContext::Transaction, &digest(n))
            .unwrap();
        sig.pq = pq
            .sign(SignatureContext::Transaction, &digest(n))
            .unwrap()
            .pq;
        transfer(&account, &owner.public_key().p256, &to, n, sig)
    };
    let n = state.get_nonce(&account);
    assert!(!succeeded(
        &runtime
            .execute_transaction(&with_key(&owner, n), &mut state)
            .await
    ));
    let n = state.get_nonce(&account);
    assert!(succeeded(
        &runtime
            .execute_transaction(&with_key(&next, n), &mut state)
            .await
    ));
    assert_eq!(state.get_balance(&to), 2 * ONE_TNZO);

    // The enrolment, replayed on the state it was made in, executes exactly
    // as it did.
    let mut replay = before_enrolment;
    assert_eq!(replay.get_nonce(&account), 0);
    assert!(succeeded(
        &runtime
            .execute_transaction(&enrolment_tx, &mut replay)
            .await
    ));
    assert_eq!(
        tenzro_vm::account_keys::enrolled_pq_key(&replay, &owner.public_key().p256),
        owner.public_key().pq.clone()
    );
    assert_eq!(replay.get_nonce(&account), 1);
}

fn retire() -> Vec<u8> {
    use tenzro_types::account_signature::AccountKeysOp;
    let mut data = tenzro_vm::account_keys::SELECTOR_ACCOUNT_KEYS.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&AccountKeysOp::RetireP256 {}).unwrap());
    data
}

/// Retiring the P-256 leg: once an account holds an ML-DSA-65 key it can stop
/// depending on P-256, so that hardware without P-256, or a break of P-256,
/// does not strand it. Before it retires the leg an ML-DSA-65-only signature
/// is refused; the retirement is signed with both legs; after it the
/// ML-DSA-65 leg alone spends and the P-256 key alone still spends nothing.
/// An account without an ML-DSA-65 key cannot retire its P-256 leg.
#[tokio::test]
async fn an_account_with_ml_dsa_enrolled_can_retire_its_p256_leg() {
    use tenzro_types::account_signature::ClassicalProof;
    let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
    let mut state = StateAdapter::new();
    let (owner, account) = enrolled_victim(&mut state);
    let p256_alone = TestHybridSigner::p256_only(7);
    let to = vec![0x66u8; 20];
    let pq_only = |n: u64| {
        let mut sig = owner
            .sign(SignatureContext::Transaction, &digest(n))
            .unwrap();
        sig.classical = ClassicalProof::Raw {
            signature: Vec::new(),
        };
        transfer(&account, &owner.public_key().p256, &to, n, sig)
    };

    let n = state.get_nonce(&account);
    assert!(!succeeded(
        &runtime.execute_transaction(&pq_only(n), &mut state).await
    ));

    let n = state.get_nonce(&account);
    let sig = owner
        .sign(SignatureContext::Transaction, &digest(n))
        .unwrap();
    let r = runtime
        .execute_transaction(&keys_tx(&owner, n, retire(), sig), &mut state)
        .await;
    assert!(succeeded(&r), "{r:?}");
    assert!(tenzro_vm::account_keys::p256_retired(
        &state,
        &owner.public_key().p256
    ));

    let n = state.get_nonce(&account);
    let r = runtime.execute_transaction(&pq_only(n), &mut state).await;
    assert!(succeeded(&r), "{r:?}");
    assert_eq!(state.get_balance(&to), ONE_TNZO);

    let n = state.get_nonce(&account);
    let alone = transfer(
        &account,
        &owner.public_key().p256,
        &to,
        n,
        p256_alone
            .sign(SignatureContext::Transaction, &digest(n))
            .unwrap(),
    );
    assert!(!succeeded(
        &runtime.execute_transaction(&alone, &mut state).await
    ));
    assert_eq!(state.get_balance(&to), ONE_TNZO);

    let plain = TestHybridSigner::p256_only(40);
    state.set_balance(plain.address().as_bytes(), 10 * ONE_TNZO);
    let sig = plain
        .sign(SignatureContext::Transaction, &digest(0))
        .unwrap();
    let r = runtime
        .execute_transaction(&keys_tx(&plain, 0, retire(), sig), &mut state)
        .await;
    assert!(!succeeded(&r));
    assert!(!tenzro_vm::account_keys::p256_retired(
        &state,
        &plain.public_key().p256
    ));
}

fn require_pq_leg() -> Vec<u8> {
    use tenzro_types::account_signature::AccountKeysOp;
    let mut data = tenzro_vm::account_keys::SELECTOR_ACCOUNT_KEYS.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&AccountKeysOp::RequirePqLeg {}).unwrap());
    data
}

/// An account named by its own P-256 key requires the ML-DSA-65 leg, with
/// both legs, once it has a key enrolled, and cannot without one.
#[tokio::test]
async fn an_account_requires_the_ml_dsa_leg_only_once_it_holds_an_ml_dsa_key() {
    use tenzro_vm::account_keys::pq_required;
    let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
    let mut state = StateAdapter::new();

    let plain = TestHybridSigner::p256_only(41);
    state.set_balance(plain.address().as_bytes(), 10 * ONE_TNZO);
    let sig = plain
        .sign(SignatureContext::Transaction, &digest(0))
        .unwrap();
    let r = runtime
        .execute_transaction(&keys_tx(&plain, 0, require_pq_leg(), sig), &mut state)
        .await;
    assert!(!succeeded(&r));
    assert!(!pq_required(&state, plain.address().as_bytes()));

    let (owner, account) = enrolled_victim(&mut state);
    let n = state.get_nonce(&account);
    let stripped = TestHybridSigner::p256_only(7)
        .sign(SignatureContext::Transaction, &digest(n))
        .unwrap();
    let r = runtime
        .execute_transaction(&keys_tx(&owner, n, require_pq_leg(), stripped), &mut state)
        .await;
    assert!(!succeeded(&r));
    assert!(!pq_required(&state, &account));

    let n = state.get_nonce(&account);
    let sig = owner
        .sign(SignatureContext::Transaction, &digest(n))
        .unwrap();
    let r = runtime
        .execute_transaction(&keys_tx(&owner, n, require_pq_leg(), sig), &mut state)
        .await;
    assert!(succeeded(&r), "{r:?}");
    assert!(pq_required(&state, &account));
}

/// While governance enables the leg-on-enrolment lever, as the launch
/// genesis does from block 0, an account that enrolls an ML-DSA-65 key
/// requires that leg of every key acting for it from then on. Paused, the
/// default, enrolment requires nothing more.
#[tokio::test]
async fn enrolling_requires_the_ml_dsa_leg_once_the_lever_is_enabled() {
    use tenzro_vm::account_keys::{PQ_LEG_ON_ENROLMENT_STATUS, pq_required};
    let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
    for (enabled, seed) in [(false, 41u8), (true, 42u8)] {
        let mut state = StateAdapter::new();
        if enabled {
            state.set_storage(
                &tenzro_vm::native::SYSTEM_ADDRESS,
                tenzro_vm::native::governed_param_key(PQ_LEG_ON_ENROLMENT_STATUS).as_bytes(),
                0u64.to_le_bytes().to_vec(),
            );
        }
        let owner = TestHybridSigner::hybrid(seed);
        let account = owner.address().as_bytes().to_vec();
        state.set_balance(&account, 10 * ONE_TNZO);
        let n = state.get_nonce(&account);
        let sig = owner
            .sign(SignatureContext::Transaction, &digest(n))
            .unwrap();
        let r = runtime
            .execute_transaction(
                &keys_tx(&owner, n, enrollment(&owner, &owner), sig),
                &mut state,
            )
            .await;
        assert!(succeeded(&r), "{r:?}");
        assert!(
            tenzro_vm::account_keys::enrolled_pq_key(&state, &owner.public_key().p256).is_some()
        );
        assert_eq!(
            pq_required(&state, &account),
            enabled,
            "lever enabled: {enabled}"
        );
    }
}
