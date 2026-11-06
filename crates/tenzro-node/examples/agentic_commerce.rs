//! Agentic commerce walkthrough
//!
//! Exercises the identity / payment / settlement layers in one pass against
//! the concrete subsystem implementations (no mocks, no node startup):
//!
//!   1. Identity provisioning + wallet binding via TDIP
//!   2. MPP payment challenge → credential → verify (real hybrid signing)
//!   3. MPP tamper rejection
//!
//! Run it with:
//!
//! ```bash
//! cargo run --example agentic_commerce -p tenzro-node
//! ```
//!
//! Every step prints what it just executed against the live subsystems
//! so you can read it as a step-by-step walkthrough.

use std::sync::Arc;
use tenzro_crypto::keys::{KeyPair, KeyType};

use tenzro_identity::{IdentityRegistry, WalletBinder};

use tenzro_payments::mpp::MppPaymentServer;
use tenzro_payments::traits::PaymentProtocol;
use tenzro_payments::types::PaymentChallenge;

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

fn fresh_identity_registry() -> IdentityRegistry {
    let binder = Arc::new(WalletBinder::new().expect("wallet binder init"));
    IdentityRegistry::with_wallet_binder(binder)
}

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

/// The payee of every walkthrough challenge.
const PAYEE: &str = "0909090909090909090909090909090909090909";

/// A challenge stamped with the chain id, as the gateway stamps it.
fn stamped(mut challenge: PaymentChallenge) -> PaymentChallenge {
    challenge.extra.insert(
        tenzro_payments::payer_auth::CHAIN_ID_KEY.to_string(),
        serde_json::json!(1337u64),
    );
    challenge
}

// ----------------------------------------------------------------------
// 1. Identity provisioning + wallet binding
// ----------------------------------------------------------------------

async fn identity_provision_and_wallet_bind() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Step 1: Identity provisioning + wallet binding ===");

    let registry = fresh_identity_registry();

    let keypair = KeyPair::generate(KeyType::Ed25519)?;
    let public_key = keypair.public_key().as_bytes().to_vec();

    let identity = registry
        .register_human_via_binder(
            // Stand-in for the credential id a WebAuthn ceremony returns.
            b"demo-passkey-alice-walkthrough".to_vec(),
            public_key.clone(),
            "Alice (walkthrough)".to_string(),
        )
        .await?
        .identity;

    let did_string = identity.did_string();
    println!("→ registered human DID: {}", did_string);
    println!("  is_human       = {}", identity.is_human());
    println!("  is_active      = {}", identity.is_active());
    println!("  display_name   = {}", identity.display_name());
    println!(
        "  wallet_address = 0x{}...",
        hex::encode(&identity.wallet_address.as_bytes()[..8])
    );
    println!("  wallet_id      = {}", identity.wallet_id);
    println!(
        "  registered key bytes = {}",
        identity.public_keys[0].public_key.len()
    );

    let resolved = registry.resolve(&did_string)?;
    println!("→ resolved DID round-trip: {}", resolved.did_string());

    Ok(())
}

// ----------------------------------------------------------------------
// 2. MPP challenge → credential → verify
// ----------------------------------------------------------------------

async fn mpp_payment_challenge_credential_settle() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Step 2: MPP challenge → credential → verify ===");

    let server = MppPaymentServer::new(keys());
    let challenge = stamped(
        server
            .create_challenge("/api/inference", 1_000, "TNZO", PAYEE)
            .await?,
    );
    println!("→ created challenge {}", challenge.challenge_id);
    println!("  amount   = {} {}", challenge.amount, challenge.asset);

    let credential = server
        .create_credential(&challenge, "", &payer_signer())
        .await?;
    let verification = server.verify_credential(&challenge, &credential).await?;
    println!("→ verified credential {}", verification.credential_id);
    if let tenzro_payments::SettlementLeg::Payer(payer) = &verification.leg {
        println!(
            "  debits   = 0x{}",
            hex::encode(&payer.address.as_bytes()[..20])
        );
    }
    println!("  (a node settles it on the ledger rail before issuing a receipt)");

    Ok(())
}

// ----------------------------------------------------------------------
// 3. MPP tamper rejection
// ----------------------------------------------------------------------

async fn mpp_payment_rejects_tampered_credential() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Step 3: MPP rejects tampered credential ===");

    let server = MppPaymentServer::new(keys());
    let challenge = stamped(
        server
            .create_challenge("/api/inference", 2_000, "TNZO", PAYEE)
            .await?,
    );
    let mut credential = server
        .create_credential(&challenge, "", &payer_signer())
        .await?;
    credential.amount = 3_000;
    match server.verify_credential(&challenge, &credential).await {
        Ok(_) => println!("→ unexpected: tampered credential was accepted"),
        Err(err) => println!("→ tampered credential rejected: {err}"),
    }

    Ok(())
}

// ----------------------------------------------------------------------
// Entry point
// ----------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Tenzro agentic commerce walkthrough");
    println!("===================================");

    identity_provision_and_wallet_bind().await?;
    mpp_payment_challenge_credential_settle().await?;
    mpp_payment_rejects_tampered_credential().await?;

    println!("\nAll walkthroughs completed.");
    Ok(())
}
