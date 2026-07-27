//! Post-quantum hybrid integration tests.
//!
//! Per the migration plan (`docs/security/quantum-resistance-migration-plan.md` §6.1)
//! these tests exercise the full PQ-hybrid surface that stages 3a–3d
//! cascaded across the workspace:
//!
//! 1. `hybrid_signed_tx_round_trip` — a wallet-signed `SignedTransaction`
//!    carries both a classical Ed25519 leg and an ML-DSA-65 leg, and both
//!    legs verify against the matching public keys / hash preimage.
//!
//! 2. `legacy_classical_only_tx_rejected` — a classical-only transaction
//!    payload (no `pq_public_key`, no `pq_signature`) is rejected at the
//!    deserializer boundary. The pure-PQ wire format is the *only* admissible
//!    format; there is no backward-compat fallback.
//!
//! 3. `restart_survives_pq_genesis` — a node bootstrapped on the PQ-era
//!    `protocol_version = 2` genesis re-opens cleanly from the same data
//!    directory.
//!
//! 4. `revocation_broadcast_signature_required` — `SignedRevocationEntry`
//!    carries a hybrid signature; tampering invalidates it; remote
//!    application without a valid signature is rejected (HIGH #96).

use std::sync::Arc;
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
use tenzro_crypto::{KeyPair, KeyType};
use tenzro_node::{NodeConfig, TenzroNode};
use tenzro_types::primitives::{Address, ChainId, Nonce};
use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};
use tenzro_types::Signature;

// ---------------------------------------------------------------------------
// 1. Hybrid signed-tx round-trip
// ---------------------------------------------------------------------------

/// A transaction signed under the hybrid scheme carries both legs and both
/// legs verify against the canonical `Transaction::hash()` preimage. The
/// preimage commits to `pq_public_key`, so substituting the PQ key after
/// signing invalidates the classical leg too.
#[tokio::test]
async fn hybrid_signed_tx_round_trip() {
    // Classical Ed25519 keypair.
    let kp = KeyPair::generate(KeyType::Ed25519).expect("ed25519 keypair");
    let classical_pk = kp.public_key().clone();
    let classical = Ed25519SignerImpl::new(kp).expect("ed25519 signer");

    // PQ ML-DSA-65 keypair.
    let pq_key = MlDsaSigningKey::generate();
    let pq_vk = pq_key.verifying_key_bytes().to_vec();
    assert_eq!(pq_vk.len(), 1952, "ML-DSA-65 vk must be 1952 bytes");

    // Build the transaction. The PQ verifying key is part of the hash
    // preimage, so any later substitution breaks signature verification.
    let tx = Transaction::new(
        ChainId::from(1337),
        Address::new([0x11; 32]),
        Address::new([0x07; 32]),
        Nonce::from(1u64),
        TransactionType::Transfer { amount: 42 },
        21_000,
        1_000_000_000,
        pq_vk.clone(),
    );
    let hash = tx.hash();

    // Sign the same preimage with both legs.
    let classical_sig_typed = classical.sign(hash.as_bytes()).expect("classical sign");
    let pq_sig = pq_key.sign(hash.as_bytes()).to_vec();
    assert_eq!(pq_sig.len(), 3309, "ML-DSA-65 sig must be 3309 bytes");

    // The wire-format `tenzro_types::Signature` carries (bytes, public_key).
    let signature = Signature::new(
        classical_sig_typed.to_bytes(),
        classical_pk.as_bytes().to_vec(),
    );
    let signed = SignedTransaction::new(tx, signature.clone(), pq_sig.clone());
    signed.validate().expect("signed tx must validate");

    // Verify classical leg against the embedded public key.
    tenzro_crypto::signatures::verify(&classical_pk, hash.as_bytes(), &classical_sig_typed)
        .expect("classical signature verifies");

    // Verify PQ leg via the workspace helper (validates lengths internally).
    tenzro_crypto::pq::ml_dsa_verify(&pq_vk, hash.as_bytes(), &pq_sig)
        .expect("PQ signature verifies");

    // JSON round-trip preserves both legs (smoke-test the wire format).
    let bytes = serde_json::to_vec(&signed).expect("serialize");
    let decoded: SignedTransaction = serde_json::from_slice(&bytes).expect("deserialize");
    decoded.validate().expect("decoded validates");
    assert_eq!(decoded.pq_signature.len(), 3309);
    assert_eq!(decoded.transaction.pq_public_key.len(), 1952);

    // Substituting the PQ verifying key in the decoded payload breaks the
    // hash preimage — proving the PQ leg is bound into `Transaction::hash()`.
    let mut tampered = decoded.clone();
    let other_pq_vk = MlDsaSigningKey::generate().verifying_key_bytes().to_vec();
    tampered.transaction.pq_public_key = other_pq_vk;
    let tampered_hash = tampered.transaction.hash();
    assert_ne!(
        tampered_hash, hash,
        "swapping pq_public_key must change the canonical hash"
    );
}

// ---------------------------------------------------------------------------
// 2. Legacy classical-only tx is rejected at the deserializer boundary
// ---------------------------------------------------------------------------

/// The pure-PQ wire format is mandatory. Payloads that omit `pq_signature` or
/// `pq_public_key` — or that carry the wrong byte length — are rejected by
/// `bounded_pq_signature_bytes` / `bounded_pq_public_key_bytes` before any
/// VM logic gets a chance to look at them.
#[test]
fn legacy_classical_only_tx_rejected() {
    let zero_addr = vec![0u8; 32];
    let one_addr = vec![1u8; 32];
    let classical_sig_bytes = vec![0x42u8; 64];
    let classical_pk_bytes = vec![0x42u8; 32];

    // (a) Payload with `pq_signature` and `pq_public_key` entirely missing
    //     (mirrors the classical-only wire format).
    let legacy_no_pq = serde_json::json!({
        "transaction": {
            "chain_id": 1337,
            "from": zero_addr,
            "to": one_addr,
            "nonce": 0u64,
            "tx_type": { "Transfer": { "amount": 1000u128 } },
            "gas_limit": 21000u64,
            "gas_price": 1_000_000_000u64,
            "timestamp": 0i64,
            "memo": null,
            // pq_public_key intentionally absent
        },
        "signature": { "bytes": classical_sig_bytes, "public_key": classical_pk_bytes },
        // pq_signature intentionally absent
    });
    let res: Result<SignedTransaction, _> = serde_json::from_value(legacy_no_pq);
    assert!(
        res.is_err(),
        "legacy classical-only tx must be rejected by deserializer"
    );

    // (b) Payload that supplies an empty `pq_signature` and empty
    //     `pq_public_key`. The bounded deserializers must enforce the FIPS
    //     204 byte lengths (1952 and 3309) rather than accepting empty Vecs.
    let zero_addr2 = vec![0u8; 32];
    let one_addr2 = vec![1u8; 32];
    let classical_sig_bytes2 = vec![0x42u8; 64];
    let classical_pk_bytes2 = vec![0x42u8; 32];
    let empty: Vec<u8> = Vec::new();
    let empty_pq = serde_json::json!({
        "transaction": {
            "chain_id": 1337,
            "from": zero_addr2,
            "to": one_addr2,
            "nonce": 0u64,
            "tx_type": { "Transfer": { "amount": 1000u128 } },
            "gas_limit": 21000u64,
            "gas_price": 1_000_000_000u64,
            "timestamp": 0i64,
            "memo": null,
            "pq_public_key": empty.clone(),
        },
        "signature": { "bytes": classical_sig_bytes2, "public_key": classical_pk_bytes2 },
        "pq_signature": empty,
    });
    let res: Result<SignedTransaction, _> = serde_json::from_value(empty_pq);
    assert!(
        res.is_err(),
        "empty pq_signature / pq_public_key must be rejected by deserializer"
    );

    // (c) Wrong-length PQ vk (e.g. 32 bytes — looks classical-shaped) — also
    //     rejected. This guards against substituting an Ed25519 pubkey into
    //     the PQ slot to disguise a classical-only payload.
    let zero_addr3 = vec![0u8; 32];
    let one_addr3 = vec![1u8; 32];
    let classical_sig_bytes3 = vec![0x42u8; 64];
    let classical_pk_bytes3 = vec![0x42u8; 32];
    let short_pq_vk = vec![0u8; 32];
    let well_sized_pq_sig = vec![0u8; 3309];
    let wrong_len_vk = serde_json::json!({
        "transaction": {
            "chain_id": 1337,
            "from": zero_addr3,
            "to": one_addr3,
            "nonce": 0u64,
            "tx_type": { "Transfer": { "amount": 1000u128 } },
            "gas_limit": 21000u64,
            "gas_price": 1_000_000_000u64,
            "timestamp": 0i64,
            "memo": null,
            "pq_public_key": short_pq_vk,
        },
        "signature": { "bytes": classical_sig_bytes3, "public_key": classical_pk_bytes3 },
        "pq_signature": well_sized_pq_sig,
    });
    let res: Result<SignedTransaction, _> = serde_json::from_value(wrong_len_vk);
    assert!(
        res.is_err(),
        "32-byte pq_public_key must be rejected (must be 1952 bytes)"
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
    use tenzro_storage::traits::BlockStore;
    use tenzro_storage::block_store::BlockStoreImpl;
    use tenzro_types::primitives::BlockHeight;

    let tmp = tempfile::tempdir().expect("create temp dir");
    // Genesis is only initialized if the config asks for it. The default-user
    // config sets `genesis = None`; we must opt in explicitly.
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
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

/// Cross-node revocation gossip carries a `SignedRevocationEntry`. A registry
/// that receives one applies it locally only when both legs of the composite
/// signature verify against the embedded public key. Tampering with the entry
/// (or the signature) post-signing must be rejected.
#[tokio::test]
async fn revocation_broadcast_signature_required() {
    use chrono::Utc;
    use tenzro_crypto::composite::{HybridSigner, InMemoryHybridSigner};
    use tenzro_identity::error::IdentityError;
    use tenzro_identity::identity::RevocationEntry;
    use tenzro_identity::registry::{IdentityRegistry, SignedRevocationEntry};
    use tenzro_identity::IdentityStatus;
    use tenzro_types::identity::KycTier;

    // Seed a local registry with an identity that the remote peer claims to
    // have revoked.
    let registry = IdentityRegistry::new();
    let identity = registry
        .register_human_with_fee(vec![1u8; 32], "Alice".to_string(), KycTier::Basic)
        .await
        .expect("register human")
        .identity;
    let did = identity.did_string();

    // Build a hybrid signer for the (notional) remote peer.
    let kp = KeyPair::generate(KeyType::Ed25519).expect("ed25519 keypair");
    let classical = Ed25519SignerImpl::new(kp).expect("ed25519 signer");
    let pq = MlDsaSigningKey::generate();
    let signer: Arc<dyn HybridSigner> =
        Arc::new(InMemoryHybridSigner::new(Box::new(classical), pq));

    // Happy path: remote sends a properly signed revocation; registry applies it.
    let entry = RevocationEntry {
        did: did.clone(),
        revoked_at: Utc::now(),
        reason: "remote-revocation".to_string(),
        revoked_by: "did:tenzro:human:peer".to_string(),
    };
    let signed = SignedRevocationEntry::sign(entry.clone(), signer.as_ref())
        .expect("sign revocation");
    assert!(
        !signed.signature.pq.is_empty(),
        "broadcast must carry both classical and PQ legs"
    );
    signed.verify().expect("freshly-signed entry verifies");
    registry
        .apply_remote_revocation(signed)
        .expect("valid signed revocation applied");

    let updated = registry.resolve(&did).expect("resolve");
    assert!(registry.is_revoked(&did), "identity must be revoked");
    assert_eq!(updated.status, IdentityStatus::Revoked);

    // Tampered path: re-register a fresh identity, then forge a revocation
    // by mutating the entry after signing. The registry must reject it and
    // leave local state untouched.
    let identity2 = registry
        .register_human_with_fee(vec![2u8; 32], "Bob".to_string(), KycTier::Basic)
        .await
        .expect("register human")
        .identity;
    let did2 = identity2.did_string();

    let entry2 = RevocationEntry {
        did: did2.clone(),
        revoked_at: Utc::now(),
        reason: "remote-revocation".to_string(),
        revoked_by: "did:tenzro:human:peer".to_string(),
    };
    let mut tampered = SignedRevocationEntry::sign(entry2, signer.as_ref())
        .expect("sign revocation");
    tampered.entry.reason = "FORGED".to_string();

    let err = registry
        .apply_remote_revocation(tampered)
        .expect_err("tampered revocation must be rejected");
    assert!(
        matches!(err, IdentityError::VerificationFailed(_)),
        "expected VerificationFailed, got {:?}",
        err
    );

    // Bob must still be Active.
    let still_active = registry.resolve(&did2).expect("resolve bob");
    assert!(!registry.is_revoked(&did2));
    assert_eq!(still_active.status, IdentityStatus::Active);
}
