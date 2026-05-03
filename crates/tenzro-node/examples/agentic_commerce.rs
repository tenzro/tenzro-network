//! Agentic commerce walkthrough
//!
//! Exercises the identity / payment / settlement layers end-to-end against
//! the real subsystem implementations (no mocks, no node startup):
//!
//!   1. Identity provisioning + wallet binding via TDIP
//!   2. MPP payment challenge → credential → settle (real Ed25519 signing)
//!   3. MPP tamper rejection
//!   4. x402 pay-resource flow against the facilitator
//!   5. Settlement engine escrow release with a real signed proof
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
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

use tenzro_identity::{IdentityRegistry, WalletBinder};
use tenzro_types::identity::KycTier;

use tenzro_payments::mpp::MppPaymentServer;
use tenzro_payments::traits::PaymentProtocol;
use tenzro_payments::types::PaymentCredential;
use tenzro_payments::x402::payment_required::X402PaymentRequirement;
use tenzro_payments::x402::{X402Facilitator, X402PaymentPayload, X402PaymentRequired};

use tenzro_settlement::engine::{SettlementConfig, SettlementEngine};

use tenzro_token::NetworkTreasury;

use tenzro_types::primitives::Address;
use tenzro_types::settlement::{
    ProofSignature, ProofType, ServiceProof, ServiceType, SettlementRequest, SettlementStatus,
    SignerRole,
};

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

fn fresh_identity_registry() -> IdentityRegistry {
    let binder = Arc::new(WalletBinder::new().expect("wallet binder init"));
    IdentityRegistry::with_wallet_binder(binder)
}

fn fresh_settlement_engine() -> (Arc<SettlementEngine>, Address) {
    let treasury_addr = Address::new([0xAA; 32]);
    let treasury = Arc::new(NetworkTreasury::new(treasury_addr));
    let config = SettlementConfig::new(treasury_addr);
    let engine = SettlementEngine::new(config, treasury).expect("settlement engine");
    (Arc::new(engine), treasury_addr)
}

/// Sign an MPP credential message exactly the way `MppPaymentServer` expects.
///
/// Canonical message: `challenge_id ++ payer_did ++ amount.to_le_bytes() ++ asset`
/// Returns `(classical_pubkey, classical_sig, pq_pubkey, pq_sig)` so callers
/// can populate the full hybrid `PaymentCredential` (Wave 3d).
fn sign_mpp_credential(
    challenge_id: &str,
    payer_did: &str,
    amount: u128,
    asset: &str,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    use tenzro_crypto::composite::{HybridSigner, InMemoryHybridSigner};
    use tenzro_crypto::pq::MlDsaSigningKey;

    let mut message = Vec::new();
    message.extend_from_slice(challenge_id.as_bytes());
    message.extend_from_slice(payer_did.as_bytes());
    message.extend_from_slice(&amount.to_le_bytes());
    message.extend_from_slice(asset.as_bytes());

    let keypair = KeyPair::generate(KeyType::Ed25519).expect("keypair");
    let public_key_bytes = keypair.public_key().as_bytes().to_vec();
    let classical = Ed25519SignerImpl::new(keypair).expect("signer");
    let pq = MlDsaSigningKey::generate();
    let pq_public_key_bytes = pq.verifying_key_bytes().to_vec();
    let hybrid = InMemoryHybridSigner::new(Box::new(classical), pq);
    let composite = hybrid.sign(&message).expect("hybrid sign");
    let pq_signature = composite.pq.expect("pq sig");

    (public_key_bytes, composite.classical, pq_public_key_bytes, pq_signature)
}

/// Build a settlement-engine `ServiceProof` carrying a real Ed25519 signature
/// over `proof_data`. Returns the provider address (derived from the public
/// key) alongside the proof so callers can use it as the settlement payee.
fn make_signed_service_proof(proof_data: &[u8]) -> (Address, ServiceProof) {
    let keypair = KeyPair::generate(KeyType::Ed25519).expect("keypair");
    let pk_bytes = keypair.public_key().as_bytes().to_vec();
    let signer = Ed25519SignerImpl::new(keypair).expect("signer");
    let crypto_sig = signer.sign(proof_data).expect("sign");

    let mut addr_bytes = [0u8; 32];
    let len = pk_bytes.len().min(32);
    addr_bytes[..len].copy_from_slice(&pk_bytes[..len]);
    let signer_addr = Address::new(addr_bytes);

    let mut proof = ServiceProof::new(ProofType::Cryptographic, proof_data.to_vec());
    proof.add_signature(ProofSignature {
        signer: signer_addr,
        signature: crypto_sig.as_bytes().to_vec(),
        role: SignerRole::Provider,
    });

    (signer_addr, proof)
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
        .register_human_with_fee(
            public_key.clone(),
            "Alice (walkthrough)".to_string(),
            KycTier::Enhanced,
        )
        .await?
        .identity;

    let did_string = identity.did_string();
    println!("→ registered human DID: {}", did_string);
    println!("  is_human       = {}", identity.is_human());
    println!("  is_active      = {}", identity.is_active());
    println!("  kyc_tier       = {:?}", identity.kyc_tier());
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
// 2. MPP challenge → credential → verify → settle
// ----------------------------------------------------------------------

async fn mpp_payment_challenge_credential_settle() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Step 2: MPP challenge → credential → settle ===");

    let server = MppPaymentServer::new("0xrecipient");

    let challenge = server
        .create_challenge("/api/inference", 1_000, "USDC", "0xrecipient")
        .await?;
    println!("→ created challenge {}", challenge.challenge_id);
    println!("  amount   = {}", challenge.amount);
    println!("  asset    = {}", challenge.asset);
    println!("  protocol = {}", challenge.protocol);

    let payer_did = "did:tenzro:human:walkthrough-payer";
    let (public_key_bytes, signature_bytes, pq_public_key_bytes, pq_signature_bytes) =
        sign_mpp_credential(
            &challenge.challenge_id,
            payer_did,
            challenge.amount,
            &challenge.asset,
        );

    let mut extra = std::collections::HashMap::new();
    extra.insert(
        "public_key".to_string(),
        serde_json::json!(hex::encode(&public_key_bytes)),
    );

    let credential = PaymentCredential {
        credential_id: "cred-walkthrough-1".to_string(),
        challenge_id: challenge.challenge_id.clone(),
        protocol: "mpp".to_string(),
        payer_did: payer_did.to_string(),
        payer_address: hex::encode(&public_key_bytes),
        amount: challenge.amount,
        asset: challenge.asset.clone(),
        signature: signature_bytes,
        pq_signature: pq_signature_bytes,
        pq_public_key: pq_public_key_bytes,
        extra,
    };

    let verification = server.verify_credential(&challenge, &credential).await?;
    println!("→ verified credential");
    println!("  verified       = {}", verification.verified);
    println!("  credential_id  = {}", verification.credential_id);
    println!("  payer_did      = {}", verification.payer_did);

    let receipt = server.settle(&verification).await?;
    println!("→ settled payment");
    println!("  amount        = {}", receipt.amount);
    println!("  asset         = {}", receipt.asset);
    println!("  protocol      = {}", receipt.protocol);
    println!("  challenge_id  = {}", receipt.challenge_id);

    let still_present = server.challenge_store().get(&challenge.challenge_id).is_ok();
    println!("  challenge still in store after settle = {}", still_present);

    Ok(())
}

// ----------------------------------------------------------------------
// 3. MPP tamper rejection
// ----------------------------------------------------------------------

async fn mpp_payment_rejects_tampered_credential() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Step 3: MPP rejects tampered credential ===");

    let server = MppPaymentServer::new("0xrecipient");

    let challenge = server
        .create_challenge("/api/inference", 2_000, "USDC", "0xrecipient")
        .await?;

    let payer_did = "did:tenzro:human:walkthrough-payer";
    let (public_key_bytes, signature_bytes, pq_public_key_bytes, pq_signature_bytes) =
        sign_mpp_credential(
            &challenge.challenge_id,
            payer_did,
            challenge.amount,
            &challenge.asset,
        );

    let mut extra = std::collections::HashMap::new();
    extra.insert(
        "public_key".to_string(),
        serde_json::json!(hex::encode(&public_key_bytes)),
    );

    // Submit a credential with tampered amount (signature was for 2_000)
    let bad_credential = PaymentCredential {
        credential_id: "cred-walkthrough-tampered".to_string(),
        challenge_id: challenge.challenge_id.clone(),
        protocol: "mpp".to_string(),
        payer_did: payer_did.to_string(),
        payer_address: hex::encode(&public_key_bytes),
        amount: 1, // tampered
        asset: challenge.asset.clone(),
        signature: signature_bytes,
        pq_signature: pq_signature_bytes,
        pq_public_key: pq_public_key_bytes,
        extra,
    };

    match server.verify_credential(&challenge, &bad_credential).await {
        Ok(_) => println!("→ unexpected: tampered credential was accepted"),
        Err(err) => println!("→ tampered credential rejected: {err}"),
    }

    Ok(())
}

// ----------------------------------------------------------------------
// 4. x402 pay-resource flow
// ----------------------------------------------------------------------

async fn x402_pay_resource() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Step 4: x402 pay-resource flow ===");

    let facilitator = X402Facilitator::new(vec!["tenzro".to_string()]);

    let requirement = X402PaymentRequirement {
        chain: "tenzro".to_string(),
        asset: "USDC".to_string(),
        amount: "1000".to_string(),
        recipient: "0xrecipient".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        // Default scheme is `tenzro-hybrid` — Ed25519 signature over the
        // canonical preimage (chain || asset || amount || recipient || payer).
        extra: serde_json::json!({"scheme": "tenzro-hybrid"}),
    };
    let requirements = X402PaymentRequired::new(vec![requirement.clone()]);

    // Build a real Ed25519-signed payload so the facilitator's scheme
    // dispatch (now verified through SchemeRegistry) accepts it.
    let kp = KeyPair::generate(KeyType::Ed25519)?;
    let payer_hex = hex::encode(kp.public_key().as_bytes());

    let mut signing_message = Vec::new();
    signing_message.extend_from_slice(requirement.chain.as_bytes());
    signing_message.extend_from_slice(requirement.asset.as_bytes());
    signing_message.extend_from_slice(requirement.amount.as_bytes());
    signing_message.extend_from_slice(requirement.recipient.as_bytes());
    signing_message.extend_from_slice(payer_hex.as_bytes());

    let signer = Ed25519SignerImpl::new(kp)?;
    let signature = signer.sign(&signing_message)?;

    let mut payload = X402PaymentPayload::new(
        "tenzro",
        "USDC",
        "1000",
        &payer_hex,
        hex::encode(&signing_message),
    );
    payload.signature = hex::encode(signature.as_bytes());

    let accepted = facilitator.verify(&requirements, &payload).await?;
    println!("→ valid payload accepted = {}", accepted);

    let underpay = X402PaymentPayload::new("tenzro", "USDC", "500", &payer_hex, "auth-blob");
    let underpay_accepted = facilitator.verify(&requirements, &underpay).await?;
    println!("→ underpaid payload accepted = {}", underpay_accepted);

    let wrong_chain =
        X402PaymentPayload::new("ethereum", "USDC", "1000", &payer_hex, "auth-blob");
    let wrong_chain_accepted = facilitator.verify(&requirements, &wrong_chain).await?;
    println!("→ wrong-chain payload accepted = {}", wrong_chain_accepted);

    let settle_ref = facilitator.settle(&requirements, &payload).await?;
    println!("→ settled, reference = {settle_ref}");

    Ok(())
}

// ----------------------------------------------------------------------
// 5. Settlement engine escrow release with signed proof
// ----------------------------------------------------------------------

async fn settlement_escrow_release_with_signed_proof() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Step 5: Settlement engine escrow release ===");

    let (engine, _treasury_addr) = fresh_settlement_engine();

    let customer = Address::new([0x11; 32]);
    let asset_id = tenzro_types::asset::AssetId::tnzo();
    engine.set_balance(&customer, &asset_id, 100_000);
    println!(
        "→ customer pre-funded balance = {}",
        engine.get_balance(&customer, &asset_id)
    );

    let proof_data = b"agentic-inference-receipt";
    let (provider, proof) = make_signed_service_proof(proof_data);
    println!(
        "→ provider derived from signing key, address bytes = 0x{}...",
        hex::encode(&provider.as_bytes()[..8])
    );

    let request = SettlementRequest::new(
        provider,
        customer,
        ServiceType::ModelInference {
            model_id: "tenzro-walkthrough-model".to_string(),
            tokens: 1_234,
        },
        10_000,
        proof,
    );

    let receipt = engine.settle(request).await?;
    println!("→ settlement receipt:");
    println!(
        "  status   = {}",
        if receipt.status == SettlementStatus::Completed {
            "Completed"
        } else {
            "Other"
        }
    );
    println!("  amount   = {}", receipt.amount);

    println!(
        "  customer balance after settle = {}",
        engine.get_balance(&customer, &asset_id)
    );
    println!(
        "  provider balance after settle = {} (10_000 minus 0.5%% network fee)",
        engine.get_balance(&provider, &asset_id)
    );

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
    x402_pay_resource().await?;
    settlement_escrow_release_with_signed_proof().await?;

    println!("\nAll walkthroughs completed.");
    Ok(())
}
