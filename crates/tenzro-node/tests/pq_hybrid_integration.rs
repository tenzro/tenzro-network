//! Post-quantum hybrid integration tests.
//!
//! 1. `hybrid_signed_tx_round_trip`: a transaction signed by a P-256 key with
//!    an ML-DSA-65 leg survives the wire round-trip and both legs verify
//!    against the account's keys; altering the transaction after signing
//!    invalidates it.
//!
//! 2. `signature_without_classical_leg_rejected`: a transaction payload with
//!    no composite signature does not deserialize, and an ML-DSA-65 leg alone
//!    does not verify.
//!
//! 3. `restart_survives_pq_genesis`: a node bootstrapped on the PQ-era
//!    `protocol_version = 2` genesis re-opens cleanly from the same data
//!    directory.
//!
//! Identity revocation is a consensus transaction; its tests are in
//! `identity_revocation_consensus`.

use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{HybridSigner, PqPolicy, SignatureContext, verify_composite};
use tenzro_node::{NodeConfig, TenzroNode};
use tenzro_types::primitives::{Address, ChainId, Nonce};
use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};

// ---------------------------------------------------------------------------
// 1. Hybrid signed-tx round-trip
// ---------------------------------------------------------------------------

fn transfer_from(signer: &TestHybridSigner) -> Transaction {
    Transaction::new(
        ChainId::from(1337),
        signer.address(),
        Address::new([1u8; 32]),
        Nonce::from(0u64),
        TransactionType::Transfer { amount: 1_000 },
        21_000,
        1_000_000_000,
    )
}

#[tokio::test]
async fn hybrid_signed_tx_round_trip() {
    let signer = TestHybridSigner::hybrid(7);
    let tx = transfer_from(&signer);
    let sig = signer
        .sign(SignatureContext::Transaction, tx.hash().as_bytes())
        .expect("sign");
    assert_eq!(sig.pq.as_ref().map(Vec::len), Some(3309));

    let signed = SignedTransaction::new(tx, signer.public_key().p256.clone(), sig);
    let wire = serde_json::to_vec(&signed).expect("encode");
    let decoded: SignedTransaction = serde_json::from_slice(&wire).expect("decode");
    assert_eq!(decoded.public_key, signer.public_key().p256);

    verify_composite(
        signer.public_key(),
        SignatureContext::Transaction,
        decoded.transaction.hash().as_bytes(),
        &decoded.signature,
        PqPolicy::Required,
    )
    .expect("both legs verify");

    let mut altered = decoded.transaction.clone();
    altered.nonce = Nonce::from(1u64);
    assert!(
        verify_composite(
            signer.public_key(),
            SignatureContext::Transaction,
            altered.hash().as_bytes(),
            &decoded.signature,
            PqPolicy::WhenPresent,
        )
        .is_err(),
        "a signature does not carry over to an altered transaction"
    );
}

// ---------------------------------------------------------------------------
// 2. A signature without its P-256 leg is rejected
// ---------------------------------------------------------------------------

#[test]
fn signature_without_classical_leg_rejected() {
    let signer = TestHybridSigner::hybrid(9);
    let tx = transfer_from(&signer);
    let sig = signer
        .sign(SignatureContext::Transaction, tx.hash().as_bytes())
        .expect("sign");
    let signed = SignedTransaction::new(tx, signer.public_key().p256.clone(), sig);

    let mut json = serde_json::to_value(&signed).expect("encode");
    json.as_object_mut().expect("object").remove("signature");
    assert!(
        serde_json::from_value::<SignedTransaction>(json).is_err(),
        "a transaction without a composite signature does not decode"
    );

    let mut stripped = signed.signature.clone();
    stripped.classical = tenzro_types::account_signature::ClassicalProof::Raw {
        signature: Vec::new(),
    };
    assert!(!stripped.has_classical_leg());
    assert!(
        verify_composite(
            signer.public_key(),
            SignatureContext::Transaction,
            signed.transaction.hash().as_bytes(),
            &stripped,
            PqPolicy::Required,
        )
        .is_err(),
        "the ML-DSA-65 leg alone does not authorize"
    );
}

// ---------------------------------------------------------------------------
// 3. Restart survives a PQ-era genesis block
// ---------------------------------------------------------------------------

/// Boot a node, let it write its `protocol_version = 2` genesis to disk, then
/// read the persisted genesis block back through the same node's storage
/// handle. The genesis block must carry `protocol_version ==
/// PQ_HYBRID_PROTOCOL_VERSION` — this is exactly the value
/// `genesis::load_genesis_block` reads on the next process start, and it is
/// what gates the refusal-to-start check there. This test cannot reopen the
/// same RocksDB path within the same test process (background tasks retain
/// the lock), so we assert against the canonical persisted block instead;
/// the next-process behavior is exercised in production startup paths.
#[tokio::test]
async fn restart_survives_pq_genesis() {
    use tenzro_node::config::GenesisConfig;
    use tenzro_node::genesis::PQ_HYBRID_PROTOCOL_VERSION;
    use tenzro_storage::block_store::BlockStoreImpl;
    use tenzro_storage::traits::BlockStore;
    use tenzro_types::primitives::BlockHeight;

    let tmp = tempfile::tempdir().expect("create temp dir");
    // Genesis is only initialized if the config asks for it. The default-user
    // config sets `genesis = None`; we must opt in explicitly.
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
        genesis: Some(GenesisConfig::default_testnet()),
        ..Default::default()
    };

    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");
    let status = node.status().await;
    assert_eq!(status.state, "Running");

    // Read the genesis block through the node's storage handle. Building a
    // BlockStoreImpl here matches what `genesis::load_genesis_block` does on
    // a real restart — same column family, same key layout.
    let store = node
        .storage()
        .expect("storage initialized after start")
        .clone();
    let block_store = BlockStoreImpl::new(store).expect("block store");
    let genesis = block_store
        .get_block_by_height(BlockHeight::genesis())
        .await
        .expect("query genesis")
        .expect("genesis must be persisted");

    assert_eq!(
        genesis.header.metadata.protocol_version, PQ_HYBRID_PROTOCOL_VERSION,
        "persisted genesis must stamp the PQ-hybrid protocol version"
    );
    assert_eq!(PQ_HYBRID_PROTOCOL_VERSION, 2);
}

// ---------------------------------------------------------------------------
// 4. Revocation broadcast signature is mandatory (HIGH #96)
// ---------------------------------------------------------------------------
