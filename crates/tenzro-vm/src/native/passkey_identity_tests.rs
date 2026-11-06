//! A person enrolled with a passkey registers their identity on chain, bound
//! to their smart account, with a WebAuthn assertion and the ML-DSA-65 leg of
//! the key enrolled with the passkey; the identity then answers for agents
//! bonded from that account.

use super::*;
use crate::VmConfig;
use crate::VmType;
use crate::state_adapter::StateAdapter;
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
use tenzro_types::identity::{RegisterIdentityPayload, RegistrationProof};

const CHAIN: u64 = 1337;
const TNZO: u128 = 1_000_000_000_000_000_000;
/// User present and user verified.
const UP_UV: u8 = 0x05;

fn did_of(person: &TestHybridSigner) -> String {
    format!(
        "did:tenzro:human:{}",
        tenzro_types::did_derivation::human_id(&person.public_key().p256)
    )
}

/// A smart account address in its 32-byte slot: 20 bytes, zero padded.
fn smart_account(tag: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[..20].copy_from_slice(&[tag; 20]);
    a
}

/// The registration a passkey enrolment submits, unsigned.
fn payload(person: &TestHybridSigner, wallet: [u8; 32]) -> RegisterIdentityPayload {
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert(
        "smart_account_address".to_string(),
        format!("0x{}", hex::encode(&wallet[..20])),
    );
    RegisterIdentityPayload {
        did: did_of(person),
        identity_type: "human".to_string(),
        display_name: "Passkey User".to_string(),
        controller_pubkey: person.public_key().p256.clone(),
        key_type: "P-256".to_string(),
        wallet_id: format!("0x{}", hex::encode(&wallet[..20])),
        wallet_address: Address::new(wallet),
        pq_verifying_key: person.public_key().pq.clone().expect("hybrid"),
        metadata,
        proof: RegistrationProof::Hardware {
            signature: CompositeSignature::classical(ClassicalProof::Raw {
                signature: Vec::new(),
            }),
        },
    }
}

/// The passkey's assertion over the registration statement and the ML-DSA-65
/// leg of `pq_signer` over the same statement.
fn sign(p: &mut RegisterIdentityPayload, passkey: &TestHybridSigner, pq_signer: &TestHybridSigner) {
    let statement = tenzro_types::identity::registration_statement(p);
    let classical = passkey.sign_passkey(UP_UV, SignatureContext::IdentityRegistration, &statement);
    let pq = pq_signer
        .sign(SignatureContext::IdentityRegistration, &statement)
        .unwrap()
        .pq
        .expect("hybrid");
    p.proof = RegistrationProof::Hardware {
        signature: CompositeSignature::hybrid(classical, pq),
    };
}

async fn send(
    state: &mut StateAdapter,
    from: &[u8],
    selector: [u8; 4],
    body: Vec<u8>,
) -> Result<bool> {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut data = selector.to_vec();
    data.extend(body);
    let mut t = VmTransaction::new(
        from.to_vec(),
        None,
        0,
        data,
        5_000_000,
        0,
        state.get_nonce(from),
        VmType::Tenzro,
        CHAIN,
    );
    t.block_timestamp_ms = Some(1_000);
    ex.execute_transaction(&t, state).await.map(|r| r.success)
}

async fn register(state: &mut StateAdapter, p: &RegisterIdentityPayload) -> Result<bool> {
    // The node relays the registration from its own account.
    state.set_balance(&[0x0E; 32], TNZO);
    send(
        state,
        &[0x0E; 32],
        SELECTOR_IDENTITY_REGISTER,
        serde_json::to_vec(p).unwrap(),
    )
    .await
}

/// An agent DID delegated under `root_did`.
fn agent_under(root_did: &str) -> String {
    let root = root_did.rsplit(':').next().unwrap();
    format!(
        "did:tenzro:machine:{root}:{}",
        tenzro_types::did_derivation::delegated_machine_id(root, b"agent device key")
    )
}

#[tokio::test]
async fn a_passkey_person_is_registered_on_chain_with_their_smart_account() {
    let person = TestHybridSigner::hybrid(41);
    let wallet = smart_account(0xA1);
    let mut state = StateAdapter::new();
    let mut p = payload(&person, wallet);
    sign(&mut p, &person, &person);
    assert!(
        register(&mut state, &p)
            .await
            .expect("the registration executes")
    );
    assert_eq!(identity_did_of(&state, &wallet), Some(did_of(&person)));
}

#[tokio::test]
async fn the_registered_person_bonds_an_agent_delegated_under_them() {
    let person = TestHybridSigner::hybrid(42);
    let wallet = smart_account(0xA2);
    let mut state = StateAdapter::new();
    let mut p = payload(&person, wallet);
    sign(&mut p, &person, &person);
    assert!(
        register(&mut state, &p)
            .await
            .expect("the registration executes")
    );
    state.set_balance(&wallet, 5 * TNZO);
    let did = did_of(&person);
    let bond = serde_json::json!({
        "agent_did": agent_under(&did), "controller_did": did, "amount": TNZO,
    });
    let bonded = send(
        &mut state,
        &wallet,
        SELECTOR_POST_AGENT_BOND,
        serde_json::to_vec(&bond).unwrap(),
    )
    .await;
    assert!(matches!(bonded, Ok(true)), "{bonded:?}");
}

#[tokio::test]
async fn a_second_identity_for_the_same_wallet_is_refused() {
    let first = TestHybridSigner::hybrid(43);
    let second = TestHybridSigner::hybrid(44);
    let wallet = smart_account(0xA3);
    let mut state = StateAdapter::new();
    let mut p = payload(&first, wallet);
    sign(&mut p, &first, &first);
    assert!(
        register(&mut state, &p)
            .await
            .expect("the registration executes")
    );

    let mut q = payload(&second, wallet);
    sign(&mut q, &second, &second);
    let refused = register(&mut state, &q).await;
    assert!(
        matches!(&refused, Err(e) if e.to_string().contains("already bound to another identity")),
        "{refused:?}"
    );
    assert_eq!(identity_did_of(&state, &wallet), Some(did_of(&first)));
}

#[tokio::test]
async fn an_invalid_assertion_or_ml_dsa_leg_is_refused() {
    let person = TestHybridSigner::hybrid(45);
    let stranger = TestHybridSigner::hybrid(46);
    let wallet = smart_account(0xA4);
    let mut state = StateAdapter::new();

    // The assertion is by another passkey.
    let mut p = payload(&person, wallet);
    sign(&mut p, &stranger, &person);
    assert!(register(&mut state, &p).await.is_err());

    // The assertion was made for another registration statement.
    let mut p = payload(&person, wallet);
    sign(&mut p, &person, &person);
    p.display_name = "Someone Else".to_string();
    assert!(register(&mut state, &p).await.is_err());

    // The ML-DSA-65 leg is not by the key the registration names.
    let mut p = payload(&person, wallet);
    sign(&mut p, &person, &stranger);
    assert!(register(&mut state, &p).await.is_err());

    // The assertion was made without user verification.
    let mut p = payload(&person, wallet);
    let statement = tenzro_types::identity::registration_statement(&p);
    let pq = person
        .sign(SignatureContext::IdentityRegistration, &statement)
        .unwrap()
        .pq
        .unwrap();
    p.proof = RegistrationProof::Hardware {
        signature: CompositeSignature::hybrid(
            person.sign_passkey(0x01, SignatureContext::IdentityRegistration, &statement),
            pq,
        ),
    };
    assert!(register(&mut state, &p).await.is_err());

    assert_eq!(identity_did_of(&state, &wallet), None);
}

/// The person's approval of `target` under `op` as their passkey assertion
/// over the custody challenge, with the ML-DSA-65 leg of `pq_signer` when
/// given.
fn approval(
    state: &StateAdapter,
    op: &[u8],
    target: &[u8],
    passkey: &TestHybridSigner,
    pq_signer: Option<&TestHybridSigner>,
) -> tenzro_types::agent_terms::AgentTermsApproval {
    let nonce = [5u8; 16];
    let account = vec![1u8; 32];
    let digest = tenzro_types::agent_terms::custody_challenge_digest(
        network_chain_id(state),
        &account,
        op,
        target,
        &nonce,
    );
    let classical = passkey.sign_passkey(UP_UV, SignatureContext::AccountOwner, &digest);
    let signature = match pq_signer {
        Some(s) => CompositeSignature::hybrid(
            classical,
            s.sign(SignatureContext::AccountOwner, &digest)
                .unwrap()
                .pq
                .expect("hybrid"),
        ),
        None => CompositeSignature::classical(classical),
    };
    tenzro_types::agent_terms::AgentTermsApproval {
        account,
        nonce,
        root_public_key: passkey.public_key().p256.clone(),
        signature,
    }
}

#[tokio::test]
async fn the_registration_enrols_the_passkeys_ml_dsa_key_in_state() {
    let person = TestHybridSigner::hybrid(47);
    let wallet = smart_account(0xA5);
    let mut state = StateAdapter::new();
    assert_eq!(
        crate::account_keys::enrolled_pq_key(&state, &person.public_key().p256),
        None
    );
    let mut p = payload(&person, wallet);
    sign(&mut p, &person, &person);
    assert!(
        register(&mut state, &p)
            .await
            .expect("the registration executes")
    );
    assert_eq!(
        crate::account_keys::enrolled_pq_key(&state, &person.public_key().p256),
        person.public_key().pq.clone(),
        "the ML-DSA-65 key the registration names is the key enrolled for the passkey"
    );
}

#[tokio::test]
async fn once_registered_an_approval_needs_both_legs_by_the_enrolled_keys() {
    let person = TestHybridSigner::hybrid(48);
    let stranger = TestHybridSigner::hybrid(49);
    let wallet = smart_account(0xA6);
    let mut state = StateAdapter::new();
    let mut p = payload(&person, wallet);
    sign(&mut p, &person, &person);
    assert!(
        register(&mut state, &p)
            .await
            .expect("the registration executes")
    );
    let did = did_of(&person);
    let op = tenzro_types::agent_terms::OP_DELEGATE_AGENT;
    let target = b"terms of the agent".as_slice();
    let verify = |a: &tenzro_types::agent_terms::AgentTermsApproval| {
        agent_terms::verify_root_approval(&state, &did, op, target, a, 1_000)
    };

    let both = verify(&approval(&state, op, target, &person, Some(&person)));
    assert!(both.is_ok(), "{both:?}");

    let webauthn_only = verify(&approval(&state, op, target, &person, None));
    assert!(
        webauthn_only.is_err(),
        "the WebAuthn leg alone no longer approves once the ML-DSA-65 key is enrolled"
    );

    let other_leg = verify(&approval(&state, op, target, &person, Some(&stranger)));
    assert!(
        other_leg.is_err(),
        "an ML-DSA-65 leg by another key is refused"
    );
}

#[tokio::test]
async fn a_registration_without_the_ml_dsa_leg_enrols_nothing() {
    let person = TestHybridSigner::hybrid(50);
    let wallet = smart_account(0xA7);
    let mut state = StateAdapter::new();
    let mut p = payload(&person, wallet);
    let statement = tenzro_types::identity::registration_statement(&p);
    p.proof = RegistrationProof::Hardware {
        signature: CompositeSignature::classical(person.sign_passkey(
            UP_UV,
            SignatureContext::IdentityRegistration,
            &statement,
        )),
    };
    let _ = register(&mut state, &p).await;
    assert_eq!(
        crate::account_keys::enrolled_pq_key(&state, &person.public_key().p256),
        None,
        "a key no leg has proven is never enrolled"
    );
}
