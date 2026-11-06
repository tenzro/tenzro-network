//! Agentic commerce integration tests
//!
//! Exercises the identity / payment / settlement layers in one pass against
//! the concrete subsystem implementations (no mocks, no node startup):
//!
//! 1. Identity provisioning + wallet binding via TDIP
//! 2. MPP payment challenge → credential → settle (hardware-shaped P-256 + ML-DSA-65 signing)
//!
//! These tests deliberately call the lower-level crates directly rather than
//! booting a full `TenzroNode`; the node integration is covered by
//! `integration.rs`. This keeps the agentic-commerce surface area small,
//! deterministic, and fast.

use std::sync::Arc;
use tenzro_crypto::composite::HybridSigner as _;
use tenzro_crypto::composite::testing::TestHybridSigner;

use tenzro_identity::{IdentityRegistry, WalletBinder};

use tenzro_payments::mpp::MppPaymentServer;
use tenzro_payments::traits::PaymentProtocol;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a fresh `IdentityRegistry` with wallet auto-provisioning enabled.
fn fresh_identity_registry() -> IdentityRegistry {
    let binder = Arc::new(WalletBinder::new().expect("wallet binder init"));
    IdentityRegistry::with_wallet_binder(binder)
}

// ---------------------------------------------------------------------------
// 1. Identity provisioning + wallet binding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identity_provision_and_wallet_bind() {
    let registry = fresh_identity_registry();

    // The human's passkey P-256 public key.
    let public_key = TestHybridSigner::p256_only(1).public_key().p256.to_vec();

    let identity = registry
        .register_human_via_binder(
            // Stand-in for the credential id a WebAuthn ceremony returns.
            b"test-passkey-alice".to_vec(),
            public_key.clone(),
            "Alice (test)".to_string(),
        )
        .await
        .expect("register human")
        .identity;

    // The DID should round-trip cleanly.
    let did_string = identity.did_string();
    assert!(
        did_string.starts_with("did:tenzro:human:"),
        "expected TDIP human DID, got {}",
        did_string
    );

    // The identity should be Active and classified as a human.
    assert!(identity.is_human(), "registered identity should be human");
    assert!(
        identity.is_active(),
        "newly registered identity should be Active"
    );
    assert_eq!(identity.display_name(), "Alice (test)");

    // The auto-provisioned wallet should be non-zero and the wallet ID set.
    assert_ne!(
        identity.wallet_address.as_bytes(),
        &[0u8; 32],
        "wallet binder should produce a non-zero address"
    );
    assert!(
        !identity.wallet_id.is_empty(),
        "wallet id must be populated"
    );

    // The public key we registered must round-trip on the identity record.
    assert_eq!(identity.public_keys.len(), 1);
    assert_eq!(identity.public_keys[0].public_key, public_key);
    assert_eq!(identity.public_keys[0].key_type, "P-256");

    // Resolve the DID through the registry and verify it matches.
    let resolved = registry.resolve(&did_string).expect("resolve DID");
    assert_eq!(resolved.did_string(), did_string);
    assert_eq!(resolved.wallet_id, identity.wallet_id);
}

// ---------------------------------------------------------------------------
// 2. MPP challenge → credential → verify → settle
// ---------------------------------------------------------------------------

fn payer_signer() -> tenzro_crypto::composite::testing::TestHybridSigner {
    static SEED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0x40);
    tenzro_crypto::composite::testing::TestHybridSigner::hybrid(
        SEED.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    )
}

/// Each payer's account has enrolled the ML-DSA-65 key its signer carries,
/// as the chain state reader would report after an enrollment.
struct EnrolledPayers;

impl tenzro_payments::EnrolledKeys for EnrolledPayers {
    fn enrolled_pq_key(&self, p256_xy: &[u8]) -> tenzro_payments::Result<Option<Vec<u8>>> {
        Ok(tenzro_crypto::composite::testing::TestHybridSigner::hybrid_pq_key(p256_xy))
    }
}

fn keys() -> Arc<dyn tenzro_payments::EnrolledKeys> {
    Arc::new(EnrolledPayers)
}

const MPP_PAYEE: &str = "0909090909090909090909090909090909090909";

async fn stamped_mpp_challenge(
    server: &MppPaymentServer,
    amount: u128,
) -> tenzro_payments::types::PaymentChallenge {
    let mut challenge = server
        .create_challenge("/api/inference", amount, "TNZO", MPP_PAYEE)
        .await
        .expect("create challenge");
    challenge.extra.insert(
        tenzro_payments::payer_auth::CHAIN_ID_KEY.to_string(),
        serde_json::json!(1337u64),
    );
    challenge
}

#[tokio::test]
async fn mpp_payment_challenge_credential_settle() {
    let server = MppPaymentServer::new(keys());
    let challenge = stamped_mpp_challenge(&server, 1_000).await;
    assert_eq!(challenge.amount, 1_000);
    assert_eq!(challenge.protocol, "mpp");

    let signer = payer_signer();
    let credential = server
        .create_credential(&challenge, "", &signer)
        .await
        .expect("credential");
    let verification = server
        .verify_credential(&challenge, &credential)
        .await
        .expect("verify credential");
    assert_eq!(verification.credential_id, credential.credential_id);
    assert_eq!(verification.amount, 1_000);
    match &verification.leg {
        tenzro_payments::SettlementLeg::Payer(p) => assert_eq!(
            p.address,
            tenzro_types::Address::new(
                tenzro_crypto::composite::HybridSigner::public_key(&signer).account_slot()
            )
        ),
        other => panic!("expected a payer leg, got {other:?}"),
    }

    let receipt = server
        .settle(&challenge, &credential, &verification)
        .await
        .expect("receipt");
    assert_eq!(receipt.amount, 1_000);
    assert_eq!(receipt.protocol, "mpp");
    assert_eq!(receipt.challenge_id, challenge.challenge_id);
}

#[tokio::test]
async fn mpp_payment_rejects_tampered_credential() {
    let server = MppPaymentServer::new(keys());
    let challenge = stamped_mpp_challenge(&server, 2_000).await;
    let mut credential = server
        .create_credential(&challenge, "", &payer_signer())
        .await
        .expect("credential");
    credential.amount = 1;
    assert!(
        server
            .verify_credential(&challenge, &credential)
            .await
            .is_err(),
        "tampered credential should be rejected"
    );
}
