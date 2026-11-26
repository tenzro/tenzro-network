//! An identity's key history on chain, read by a verifier of hardware batch
//! signatures.
//!
//! A person registers, then records, rotates, declares compromised and
//! revokes through key changes (native calls) the native executor applies.
//! A `ChainIssuerResolver` reads the resulting chain state through a
//! `LedgerView` and judges batch root signatures made with those keys:
//!
//! 1. a stored record made before a rotation still verifies after it, and a
//!    signature by the replaced key made after the rotation does not;
//! 2. a key declared compromised vouches for nothing made from the
//!    declaration on, and for what was made before it;
//! 3. a revoked delegation vouches for nothing made from the revocation on,
//!    and only the identity that issued it can revoke it;
//! 4. a key the chain committed to in advance is the only one that follows;
//! 5. the head the chain keeps for an identity is its logs folded in order:
//!    registration, key changes and revocation.
//!
//! `cargo test -p tenzro-node --test identity_key_history`

use std::sync::{Arc, Mutex};

use ed25519_dalek::Signer as _;
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{CompositeSignature, HybridSigner, SignatureContext};
use tenzro_crypto::pq::{MlDsaSigningKey, context};
use tenzro_device_key::batch_signer::RootSignature;
use tenzro_device_key::delegation::{Clock, DelegationError, DelegationResult};
use tenzro_device_key::issuer_chain::{
    ChainIssuerResolver, IdentityHistory, KeyEpoch, LedgerView, ResolverParams, commitment_of,
};
use tenzro_native_ops::identity_keys::{
    IDENTITY_KEY_COMPROMISED_TOPIC, IDENTITY_KEY_UPDATED_TOPIC, IdentityHead, IdentityKeyChange,
    IdentityKeyOp, OP_IDENTITY_KEYS,
};
use tenzro_types::agent_terms::{AgentTermsApproval, custody_challenge_digest};
use tenzro_types::identity::{
    IdentityRevocationOp, OP_REVOKE_IDENTITY, RegisterIdentityPayload, RegistrationProof,
    registration_statement, revocation_target,
};
use tenzro_types::primitives::Address;
use tenzro_vm::native::{
    SELECTOR_IDENTITY_KEYS, SELECTOR_IDENTITY_REGISTER, SELECTOR_IDENTITY_REVOKE,
    delegation_revoked_at_ms, read_identity_head, read_identity_keys,
};
use tenzro_vm::{
    NativeExecutor, StateAdapter, VmConfig, VmExecutor, VmState, VmTransaction, VmType,
};

const RELAYER: [u8; 32] = [0x51; 32];
const CHAIN: u64 = 1337;
const T0: u64 = 1_700_000_000_000;

/// The head of one chain: its state and the block time of the latest
/// transaction.
struct Head {
    state: StateAdapter,
    at_ms: u64,
}

type Shared = Arc<Mutex<Head>>;

/// One chain: its head, and the executor that applies transactions to it.
struct Chain {
    head: Shared,
    executor: NativeExecutor,
}

fn chain() -> Chain {
    let mut state = StateAdapter::new();
    state.set_balance(&RELAYER, u128::MAX / 4);
    state.set_storage(
        &tenzro_vm::native::SYSTEM_ADDRESS,
        tenzro_vm::native::NETWORK_CHAIN_ID_KEY.as_bytes(),
        CHAIN.to_le_bytes().to_vec(),
    );
    // The key history and native calls are in force from the first epoch,
    // as after their votes.
    for gate in [
        tenzro_vm::native::identity_keys::GATE,
        tenzro_vm::native::native_call::GATE,
    ] {
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::governed_param_key(gate).as_bytes(),
            0u64.to_le_bytes().to_vec(),
        );
    }
    Chain {
        head: Arc::new(Mutex::new(Head { state, at_ms: T0 })),
        executor: NativeExecutor::new(VmConfig::default()).unwrap(),
    }
}

/// Apply `data` as the next transaction, one second after the last. Returns
/// its block time when the chain accepted it.
async fn apply(chain: &Chain, data: Vec<u8>) -> Option<u64> {
    execute(chain, data).await.map(|(at_ms, _)| at_ms)
}

/// [`apply`], returning the logs the transaction emitted as well.
async fn execute(chain: &Chain, data: Vec<u8>) -> Option<(u64, Vec<tenzro_vm::Log>)> {
    let (mut state, at_ms) = {
        let mut head = chain.head.lock().unwrap();
        head.at_ms += 1_000;
        (
            std::mem::replace(&mut head.state, StateAdapter::new()),
            head.at_ms,
        )
    };
    let mut tx = VmTransaction::new(
        RELAYER.to_vec(),
        None,
        0,
        data,
        10_000_000,
        1,
        0,
        VmType::Evm,
        CHAIN,
    );
    tx.block_timestamp_ms = Some(at_ms as i64);
    let result = chain.executor.execute_transaction(&tx, &mut state).await;
    chain.head.lock().unwrap().state = state;
    match result {
        Ok(r) if r.success => Some((at_ms, r.logs)),
        _ => None,
    }
}

fn call(selector: [u8; 4], body: &impl serde::Serialize) -> Vec<u8> {
    // An operation a native call reaches is sent as one.
    let mut data = if tenzro_vm::native::native_call::LISTED
        .iter()
        .any(|(s, _)| *s == selector)
    {
        tenzro_vm::native::native_call::SELECTOR_NATIVE_CALL.to_vec()
    } else {
        Vec::new()
    };
    data.extend(selector);
    data.extend_from_slice(&serde_json::to_vec(body).unwrap());
    data
}

/// The chain state as a verifier reads it.
struct View(Shared);

impl LedgerView for View {
    fn history(&self, identity: &str) -> DelegationResult<IdentityHistory> {
        let chain = self.0.lock().unwrap();
        Ok(IdentityHistory {
            epochs: read_identity_keys(&chain.state, identity)
                .epochs
                .into_iter()
                .map(|e| KeyEpoch {
                    version: e.version,
                    ed25519: e.ed25519,
                    ml_dsa: e.ml_dsa,
                    effective_from_ms: e.effective_from_ms,
                    compromised_from_ms: e.compromised_from_ms,
                    next_commitment: e.next_commitment,
                })
                .collect(),
        })
    }
    fn revoked_at_ms(&self, identity: &str, delegation_id: &[u8; 32]) -> Option<u64> {
        delegation_revoked_at_ms(&self.0.lock().unwrap().state, identity, delegation_id)
    }
    fn head_time_ms(&self) -> u64 {
        self.0.lock().unwrap().at_ms
    }
}

/// A verifier whose clock is the chain's head.
struct HeadClock(Shared);

impl Clock for HeadClock {
    fn now_ms(&self) -> u64 {
        self.0.lock().unwrap().at_ms
    }
}

/// A resolver that reads every history afresh.
fn resolver(chain: &Chain) -> ChainIssuerResolver {
    ChainIssuerResolver::new(
        Arc::new(View(chain.head.clone())),
        Arc::new(HeadClock(chain.head.clone())),
        ResolverParams {
            overlap_ms: 0,
            max_staleness_ms: 60_000,
            history_ttl_ms: 0,
        },
    )
}

/// One identity key: both legs.
struct IdentityKey {
    ed: ed25519_dalek::SigningKey,
    ml: MlDsaSigningKey,
}

impl IdentityKey {
    fn new(seed: u8) -> Self {
        Self {
            ed: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            ml: MlDsaSigningKey::from_seed(&[seed; 32]).unwrap(),
        }
    }
    fn ed25519(&self) -> [u8; 32] {
        self.ed.verifying_key().to_bytes()
    }
    fn ml_dsa(&self) -> Vec<u8> {
        self.ml.verifying_key_bytes().to_vec()
    }
    fn update(&self, version: u64, next: Option<&IdentityKey>) -> IdentityKeyChange {
        IdentityKeyChange::Update {
            version,
            ed25519: self.ed25519(),
            ml_dsa: self.ml_dsa(),
            next_commitment: next.map(|n| commitment_of(&n.ed25519(), &n.ml_dsa())),
        }
    }
    /// A batch root signed by this key as `version` of `identity`.
    fn sign_root(&self, identity: &str, version: u64, signed_at_ms: u64) -> RootSignature {
        let mut sig = RootSignature {
            identity: identity.to_string(),
            issuer_version: version,
            issuer_ed25519: self.ed25519(),
            issuer_ml_dsa: self.ml_dsa(),
            signed_at_ms,
            count: 1,
            root: [0xab; 32],
            ed_signature: [0; 64],
            ml_dsa_signature: Vec::new(),
        };
        let statement = sig.statement();
        sig.ed_signature = self.ed.sign(&statement).to_bytes();
        sig.ml_dsa_signature = self.ml.sign(context::BATCH_ROOT, &statement);
        sig
    }
}

/// A person: its passkey and the human DID that derives from it.
struct Person {
    passkey: TestHybridSigner,
    did: String,
}

impl Person {
    fn new(seed: u8) -> Self {
        let passkey = TestHybridSigner::hybrid(seed);
        let did = format!(
            "did:tenzro:human:{}",
            tenzro_types::did_derivation::human_id(&passkey.public_key().p256)
        );
        Self { passkey, did }
    }

    fn registration(&self, wallet: u8) -> Vec<u8> {
        let mut payload = RegisterIdentityPayload {
            did: self.did.clone(),
            identity_type: "human".into(),
            display_name: "person".into(),
            controller_pubkey: self.passkey.public_key().p256.clone(),
            key_type: "P-256".into(),
            wallet_id: format!("wallet-{wallet}"),
            wallet_address: Address::new([wallet; 32]),
            pq_verifying_key: self.passkey.public_key().pq.clone().expect("hybrid"),
            metadata: Default::default(),
            proof: RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        let statement = registration_statement(&payload);
        let classical =
            self.passkey
                .sign_passkey(0x05, SignatureContext::IdentityRegistration, &statement);
        let pq = self
            .passkey
            .sign(SignatureContext::IdentityRegistration, &statement)
            .unwrap()
            .pq
            .expect("hybrid");
        payload.proof = RegistrationProof::Hardware {
            signature: CompositeSignature::hybrid(classical, pq),
        };
        call(SELECTOR_IDENTITY_REGISTER, &payload)
    }

    /// This person's passkey assertion over the custody challenge for `op`
    /// over `target`.
    fn approve(&self, op: &[u8], target: &[u8]) -> AgentTermsApproval {
        let account = vec![0x0a; 32];
        let nonce = [7u8; 16];
        let digest = custody_challenge_digest(CHAIN, &account, op, target, &nonce);
        AgentTermsApproval {
            account,
            nonce,
            root_public_key: self.passkey.public_key().p256.clone(),
            signature: self.passkey.sign_passkey_composite(
                0x05,
                SignatureContext::AccountOwner,
                &digest,
            ),
        }
    }

    /// `change` to the keys of `did`, approved by this person's passkey.
    fn keys(&self, did: &str, change: IdentityKeyChange) -> Vec<u8> {
        let mut op = IdentityKeyOp {
            did: did.to_string(),
            change,
            approver_did: self.did.clone(),
            // Replaced below: the approval covers the target, which does not
            // cover the approval.
            approval: self.approve(OP_IDENTITY_KEYS, &[]),
        };
        op.approval = self.approve(OP_IDENTITY_KEYS, &op.target());
        call(SELECTOR_IDENTITY_KEYS, &op)
    }

    /// This person's revocation of its own identity.
    fn revoke(&self, reason: &str) -> Vec<u8> {
        call(
            SELECTOR_IDENTITY_REVOKE,
            &IdentityRevocationOp {
                did: self.did.clone(),
                reason: reason.to_string(),
                approver_did: self.did.clone(),
                approval: self.approve(OP_REVOKE_IDENTITY, &revocation_target(&self.did, reason)),
            },
        )
    }
}

async fn registered(chain: &Chain, seed: u8) -> Person {
    let person = Person::new(seed);
    assert!(
        apply(chain, person.registration(seed)).await.is_some(),
        "registration lands"
    );
    person
}

#[tokio::test]
async fn a_record_made_before_a_rotation_outlives_it() {
    let chain = chain();
    let alice = registered(&chain, 1).await;
    let (first, second) = (IdentityKey::new(11), IdentityKey::new(12));
    let from_1 = apply(&chain, alice.keys(&alice.did, first.update(1, None)))
        .await
        .expect("the first key is recorded");
    let old = first.sign_root(&alice.did, 1, from_1 + 10);
    resolver(&chain).verify_stored(&old, from_1 + 10).unwrap();

    let from_2 = apply(&chain, alice.keys(&alice.did, second.update(2, None)))
        .await
        .expect("the rotation is recorded");
    let r = resolver(&chain);
    // What the first key signed while it was in force still stands.
    r.verify_stored(&old, from_1 + 10).unwrap();
    // The first key signs nothing after its replacement.
    let late = first.sign_root(&alice.did, 1, from_2 + 1);
    assert!(matches!(
        r.verify_stored(&late, from_2 + 1),
        Err(DelegationError::WrongIssuer(_))
    ));
    // A key the chain does not record for that version is refused.
    let impostor = IdentityKey::new(13).sign_root(&alice.did, 2, from_2 + 1);
    assert!(matches!(
        r.verify_stored(&impostor, from_2 + 1),
        Err(DelegationError::WrongIssuer(_))
    ));
    r.verify_stored(&second.sign_root(&alice.did, 2, from_2 + 1), from_2 + 1)
        .unwrap();
}

#[tokio::test]
async fn a_compromised_key_vouches_for_nothing_made_after_the_declaration() {
    let chain = chain();
    let alice = registered(&chain, 2).await;
    let key = IdentityKey::new(21);
    let from = apply(&chain, alice.keys(&alice.did, key.update(1, None)))
        .await
        .unwrap();
    let before = key.sign_root(&alice.did, 1, from + 10);
    let declared = apply(
        &chain,
        alice.keys(&alice.did, IdentityKeyChange::Compromised { version: 1 }),
    )
    .await
    .expect("the declaration is recorded");
    let r = resolver(&chain);
    r.verify_stored(&before, from + 10).unwrap();
    let after = key.sign_root(&alice.did, 1, declared);
    assert!(matches!(
        r.verify_stored(&after, declared),
        Err(DelegationError::WrongIssuer(_))
    ));
    // A record that claims an earlier signing time but was made after the
    // declaration is refused as well.
    assert!(matches!(
        r.verify_stored(&before, declared + 5),
        Err(DelegationError::WrongIssuer(_))
    ));
}

#[tokio::test]
async fn a_delegation_is_revoked_only_by_the_identity_that_issued_it() {
    let chain = chain();
    let alice = registered(&chain, 3).await;
    let mallory = registered(&chain, 4).await;
    let key = IdentityKey::new(31);
    let from = apply(&chain, alice.keys(&alice.did, key.update(1, None)))
        .await
        .unwrap();
    let sig = key.sign_root(&alice.did, 1, from + 10);
    let revoke = IdentityKeyChange::RevokeDelegation {
        delegation_id: sig.id(),
    };

    // Mallory cannot revoke for Alice, and what it revokes under its own
    // identity does not reach Alice's delegation.
    assert!(
        apply(&chain, mallory.keys(&alice.did, revoke.clone()))
            .await
            .is_none()
    );
    let mallory_at = apply(&chain, mallory.keys(&mallory.did, revoke.clone()))
        .await
        .expect("its own record");
    resolver(&chain)
        .verify_stored(&sig, mallory_at + 1)
        .unwrap();

    let revoked = apply(&chain, alice.keys(&alice.did, revoke))
        .await
        .expect("the revocation is recorded");
    let r = resolver(&chain);
    r.verify_stored(&sig, revoked - 1).unwrap();
    assert!(matches!(
        r.verify_stored(&sig, revoked),
        Err(DelegationError::Revoked)
    ));
}

#[tokio::test]
async fn a_committed_key_is_the_only_one_that_follows() {
    let chain = chain();
    let alice = registered(&chain, 5).await;
    let (first, standby, other) = (
        IdentityKey::new(41),
        IdentityKey::new(42),
        IdentityKey::new(43),
    );
    apply(
        &chain,
        alice.keys(&alice.did, first.update(1, Some(&standby))),
    )
    .await
    .expect("the first key and its commitment are recorded");
    assert!(
        apply(&chain, alice.keys(&alice.did, other.update(2, None)))
            .await
            .is_none(),
        "the chain refuses a successor the key in force did not commit to"
    );
    let from_2 = apply(&chain, alice.keys(&alice.did, standby.update(2, None)))
        .await
        .expect("the committed key follows");
    resolver(&chain)
        .verify_stored(&standby.sign_root(&alice.did, 2, from_2), from_2)
        .unwrap();
}

#[tokio::test]
async fn the_head_in_state_is_an_identitys_logs_folded_in_order() {
    let chain = chain();
    let alice = Person::new(6);
    let key = IdentityKey::new(51);
    let mut logs = Vec::new();
    for data in [
        alice.registration(6),
        alice.keys(&alice.did, key.update(1, None)),
        alice.keys(&alice.did, IdentityKeyChange::Compromised { version: 1 }),
        alice.revoke("device lost"),
    ] {
        let (_, emitted) = execute(&chain, data).await.expect("the change lands");
        logs.extend(emitted);
    }
    let topics: [&[u8]; 4] = [
        b"IdentityRegister",
        IDENTITY_KEY_UPDATED_TOPIC,
        IDENTITY_KEY_COMPROMISED_TOPIC,
        b"IdentityRevoked",
    ];
    let about_alice: Vec<_> = logs
        .iter()
        .filter(|l| topics.contains(&l.topics[0].as_slice()))
        .collect();
    assert_eq!(
        about_alice
            .iter()
            .map(|l| l.topics[0].as_slice())
            .collect::<Vec<_>>(),
        topics
    );
    let folded = about_alice
        .iter()
        .fold(IdentityHead::default(), |head, log| {
            head.advanced(&alice.did, &log.topics[0], &log.data)
        });
    let head = read_identity_head(&chain.head.lock().unwrap().state, &alice.did);
    assert_eq!(head, folded);
    assert_eq!(head.sequence, 4);
    // A stranger's logs do not move it.
    let bob = registered(&chain, 7).await;
    apply(&chain, bob.keys(&bob.did, key.update(1, None)))
        .await
        .unwrap();
    assert_eq!(
        read_identity_head(&chain.head.lock().unwrap().state, &alice.did),
        folded
    );
}
