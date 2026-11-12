//! Enforcement by default: a node of chain 13380 on the shipped network profile and the
//! shipped launch genesis refuses a transaction or a peer that has no registered identity, and lets
//! a registered one through.
//!
//! The node-config default stays `audit` (a local or `--dev` chain ships no profile and refuses
//! nothing); the network profile `config/network/13380.toml` is what turns the gate to `enforce`
//! for the network, and `config/genesis-launch.toml` seeds the execution-layer gate at epoch 0.

use std::sync::Arc;

use tenzro_consensus::{ConsensusConfig, ConsensusError, Mempool};
use tenzro_crypto::HybridSigner;
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_iroh::identity_gate::{Admit, IdentityGate};
use tenzro_node::identity_gate::{ChainRegistry, OnboardingConfig, install_mempool_gate};
use tenzro_node::network_profile::{NetworkProfile, onboarding_mode};
use tenzro_onboarding_types::onboarding::GateMode;
use tenzro_storage::{KvStore, MemoryStore};
use tenzro_types::primitives::{Address, ChainId, Nonce};
use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};
use tenzro_vm::StateAdapter;
use tenzro_vm::traits::VmState;

const PROFILE: &str = include_str!("../../../config/network/13380.toml");

/// The gate configuration of a node with no `[onboarding]` setting of its own on the shipped profile.
fn shipped_default() -> OnboardingConfig {
    let profile = NetworkProfile::parse(PROFILE, 13380).expect("the shipped profile parses");
    let mut cfg = OnboardingConfig::default();
    assert_eq!(
        cfg.policy.mode,
        GateMode::Audit,
        "the node-config default is what a chain with no profile runs"
    );
    cfg.policy.mode = profile.onboarding.expect("the profile sets the gate").mode;
    cfg
}

fn transfer_from(sender: u8, nonce: u64) -> SignedTransaction {
    let tx = Transaction::new(
        ChainId::from(13380),
        Address::new([sender; 32]),
        Address::default(),
        Nonce::from(nonce),
        TransactionType::Transfer { amount: 1 },
        21_000,
        1_000_000_000,
    );
    let signer = TestHybridSigner::p256_only(1);
    let signature = signer
        .sign(
            tenzro_crypto::SignatureContext::Transaction,
            tx.hash().as_bytes(),
        )
        .unwrap();
    SignedTransaction::new(tx, signer.public_key().p256.clone(), signature)
}

/// Writes what RegisterIdentity leaves behind: the identity record and the wallet index.
fn register(chain: &Arc<dyn KvStore>, did: &str, wallet: &[u8]) {
    let mut state = StateAdapter::with_storage(chain.clone());
    state.set_storage(
        &tenzro_vm::native::SYSTEM_ADDRESS,
        tenzro_types::identity::identity_slot(did).as_bytes(),
        b"{}".to_vec(),
    );
    state.set_storage(
        &tenzro_vm::native::SYSTEM_ADDRESS,
        format!("identity_wallet:{}", hex::encode(wallet)).as_bytes(),
        did.as_bytes().to_vec(),
    );
    state.commit().expect("commit the registration");
}

#[test]
fn the_shipped_profile_enforces_and_the_env_file_reaches_the_node() {
    assert_eq!(shipped_default().policy.mode, GateMode::Enforce);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("13380.toml");
    std::fs::write(&file, PROFILE).unwrap();
    let mode = onboarding_mode(13380, None, file.to_str()).unwrap();
    assert_eq!(mode, Some(GateMode::Enforce));
}

#[test]
fn a_profile_with_no_onboarding_table_leaves_the_node_default_alone() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("13380.toml");
    std::fs::write(&file, "version = 1\nchain_id = 13380\n").unwrap();
    assert_eq!(onboarding_mode(13380, None, file.to_str()).unwrap(), None);
}

#[test]
fn a_transaction_without_a_registered_identity_is_refused_and_a_registered_one_passes() {
    let chain: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
    let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
    install_mempool_gate(&shipped_default(), &mempool, chain.clone());

    let refused = mempool.add_transaction(transfer_from(2, 0)).unwrap_err();
    assert!(
        matches!(
            refused,
            ConsensusError::SenderNotRegistered {
                reason: "no registered identity",
                ..
            }
        ),
        "{refused:?}"
    );
    assert_eq!(mempool.len(), 0);

    register(&chain, "did:tenzro:machine:aa", &[2; 32]);
    mempool
        .add_transaction(transfer_from(2, 0))
        .expect("the same sender passes once its identity is registered");
    assert_eq!(mempool.len(), 1);
}

#[test]
fn audit_mode_would_have_admitted_the_same_transaction() {
    let chain: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
    let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
    install_mempool_gate(&OnboardingConfig::default(), &mempool, chain);
    mempool
        .add_transaction(transfer_from(3, 0))
        .expect("audit logs and admits");
}

#[tokio::test]
async fn a_peer_without_a_registered_identity_gets_onboarding_only_and_a_registered_peer_is_served()
{
    let chain: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
    let cfg = shipped_default();
    let gate = IdentityGate::new(cfg.policy, None);
    tenzro_node::identity_gate::install_peer_gate(
        &cfg,
        &gate,
        Arc::new(ChainRegistry::new(chain.clone(), Arc::new(|| true))),
        Default::default(),
    );
    let peer = iroh::SecretKey::from_bytes(&[7; 32]).public();
    let other_protocol = b"tenzro/anything-else/1";
    let did = "did:tenzro:machine:bb";

    let stranger = gate.evaluate(0, peer, Some(did), None, other_protocol);
    assert!(matches!(stranger, Admit::Refuse { .. }), "{stranger:?}");
    let onboarding = gate.evaluate(0, peer, Some(did), None, tenzro_iroh::ALPN_ONBOARD);
    assert!(
        matches!(onboarding, Admit::Onboarding { .. }),
        "{onboarding:?}"
    );

    register(&chain, did, &[8; 32]);
    let member = gate.evaluate(1, peer, Some(did), None, other_protocol);
    assert_eq!(member, Admit::Allow);
}
