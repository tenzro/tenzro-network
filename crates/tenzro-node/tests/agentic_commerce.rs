//! Agentic commerce integration tests
//!
//! Exercises the identity / payment / settlement layers end-to-end against
//! the real subsystem implementations (no mocks, no node startup):
//!
//! 1. Identity provisioning + wallet binding via TDIP
//! 2. MPP payment challenge → credential → settle (real Ed25519 signing)
//! 3. x402 pay-resource flow against the facilitator
//! 4. Settlement engine escrow release with a real signed proof
//!
//! These tests deliberately call the lower-level crates directly rather than
//! booting a full `TenzroNode`; the node integration is covered by
//! `integration.rs`. This keeps the agentic-commerce surface area small,
//! deterministic, and fast.

use std::sync::Arc;

use tenzro_crypto::keys::{KeyPair, KeyType};
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

use tenzro_identity::{IdentityRegistry, WalletBinder};
use tenzro_types::identity::KycTier;

use tenzro_payments::mpp::MppPaymentServer;
use tenzro_payments::traits::PaymentProtocol;
use tenzro_payments::types::PaymentCredential;
use tenzro_payments::x402::payment_required::X402PaymentRequirement;
use tenzro_payments::x402::{
    ExactAuthorization, ExactSchemePayload, X402Facilitator, X402PaymentPayload,
    X402PaymentRequired,
};

use tenzro_settlement::engine::{SettlementConfig, SettlementEngine};

use tenzro_token::NetworkTreasury;

use tenzro_types::primitives::Address;
use tenzro_types::settlement::{
    ProofSignature, ProofType, ServiceProof, ServiceType, SettlementRequest, SettlementStatus,
    SignerRole,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a fresh `IdentityRegistry` with wallet auto-provisioning enabled.
fn fresh_identity_registry() -> IdentityRegistry {
    let binder = Arc::new(WalletBinder::new().expect("wallet binder init"));
    IdentityRegistry::with_wallet_binder(binder)
}

/// Build a settlement engine backed by a fresh in-memory treasury.
fn fresh_settlement_engine() -> (Arc<SettlementEngine>, Address) {
    let treasury_addr = Address::new([0xAA; 32]);
    let treasury = Arc::new(NetworkTreasury::new(treasury_addr));
    let config = SettlementConfig::new(treasury_addr);
    let engine = SettlementEngine::new(config, treasury).expect("settlement engine");
    (Arc::new(engine), treasury_addr)
}

/// Sign an MPP credential message exactly the way `MppPaymentServer` expects.
///
/// The MPP server constructs the canonical message as:
///   challenge_id ++ payer_did ++ amount.to_le_bytes() ++ asset
/// and verifies an Ed25519 signature whose public key is encoded as a hex
/// string under `credential.extra["public_key"]`.
/// Returns `(classical_pubkey, classical_sig, pq_pubkey, pq_sig)` for the
/// hybrid `PaymentCredential` schema (Wave 3d).
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
    (public_key_bytes, composite.classical, pq_public_key_bytes, composite.pq)
}

/// Build a settlement-engine `ServiceProof` carrying a real Ed25519 signature
/// over `proof_data`. Returns the provider address (derived from the public
/// key) alongside the proof so callers can use it as the settlement payee.
fn make_signed_service_proof(proof_data: &[u8]) -> (Address, ServiceProof) {
    let keypair = KeyPair::generate(KeyType::Ed25519).expect("keypair");
    let pk_bytes = keypair.public_key().as_bytes().to_vec();
    let signer = Ed25519SignerImpl::new(keypair).expect("signer");
    let crypto_sig = signer.sign(proof_data).expect("sign");

    // Derive a 32-byte address from the public key.
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

// ---------------------------------------------------------------------------
// 1. Identity provisioning + wallet binding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identity_provision_and_wallet_bind() {
    let registry = fresh_identity_registry();

    // Generate a real Ed25519 public key for the human identity.
    let keypair = KeyPair::generate(KeyType::Ed25519).expect("keypair");
    let public_key = keypair.public_key().as_bytes().to_vec();

    let identity = registry
        .register_human_with_fee(
            public_key.clone(),
            "Alice (test)".to_string(),
            KycTier::Enhanced,
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
    assert!(identity.is_active(), "newly registered identity should be Active");
    assert_eq!(identity.kyc_tier(), Some(KycTier::Enhanced));
    assert_eq!(identity.display_name(), "Alice (test)");

    // The auto-provisioned wallet should be non-zero and the wallet ID set.
    assert_ne!(
        identity.wallet_address.as_bytes(),
        &[0u8; 32],
        "wallet binder should produce a non-zero address"
    );
    assert!(!identity.wallet_id.is_empty(), "wallet id must be populated");

    // The public key we registered must round-trip on the identity record.
    assert_eq!(identity.public_keys.len(), 1);
    assert_eq!(identity.public_keys[0].public_key, public_key);
    assert_eq!(identity.public_keys[0].key_type, "Ed25519");

    // Resolve the DID through the registry and verify it matches.
    let resolved = registry.resolve(&did_string).expect("resolve DID");
    assert_eq!(resolved.did_string(), did_string);
    assert_eq!(resolved.wallet_id, identity.wallet_id);
}

// ---------------------------------------------------------------------------
// 2. MPP challenge → credential → verify → settle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mpp_payment_challenge_credential_settle() {
    let server = MppPaymentServer::new("0xrecipient");

    // Create the payment challenge.
    let challenge = server
        .create_challenge("/api/inference", 1_000, "USDC", "0xrecipient")
        .await
        .expect("create challenge");

    assert_eq!(challenge.amount, 1_000);
    assert_eq!(challenge.asset, "USDC");
    assert_eq!(challenge.protocol, "mpp");
    assert!(!challenge.challenge_id.is_empty());

    // Build a signed MPP credential whose canonical message matches the
    // server's `construct_credential_message` exactly.
    let payer_did = "did:tenzro:human:test-payer";
    let (public_key_bytes, signature_bytes, pq_public_key_bytes, pq_signature_bytes) =
        sign_mpp_credential(&challenge.challenge_id, payer_did, challenge.amount, &challenge.asset);

    let mut extra = std::collections::HashMap::new();
    extra.insert(
        "public_key".to_string(),
        serde_json::json!(hex::encode(&public_key_bytes)),
    );

    let credential = PaymentCredential {
        credential_id: "cred-test-1".to_string(),
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

    // Verify the credential against the challenge — must succeed.
    let verification = server
        .verify_credential(&challenge, &credential)
        .await
        .expect("verify credential");
    assert!(verification.verified);
    assert_eq!(verification.credential_id, credential.credential_id);
    assert_eq!(verification.challenge_id, challenge.challenge_id);
    assert_eq!(verification.payer_did, payer_did);

    // Settle the verified payment. With no settlement engine attached, the
    // server should still issue a receipt drawn from the stored challenge.
    let receipt = server.settle(&verification).await.expect("settle");
    assert_eq!(receipt.amount, 1_000);
    assert_eq!(receipt.asset, "USDC");
    assert_eq!(receipt.protocol, "mpp");
    assert_eq!(receipt.challenge_id, challenge.challenge_id);

    // After settlement, the challenge should no longer be in the store.
    assert!(server.challenge_store().get(&challenge.challenge_id).is_err());
}

#[tokio::test]
async fn mpp_payment_rejects_tampered_credential() {
    let server = MppPaymentServer::new("0xrecipient");

    let challenge = server
        .create_challenge("/api/inference", 2_000, "USDC", "0xrecipient")
        .await
        .expect("create challenge");

    // Sign over the *original* challenge fields...
    let payer_did = "did:tenzro:human:test-payer";
    let (public_key_bytes, signature_bytes, pq_public_key_bytes, pq_signature_bytes) =
        sign_mpp_credential(
            &challenge.challenge_id,
            payer_did,
            challenge.amount,
            &challenge.asset,
        );

    // ...but submit a credential whose `amount` does not match the challenge.
    let mut extra = std::collections::HashMap::new();
    extra.insert(
        "public_key".to_string(),
        serde_json::json!(hex::encode(&public_key_bytes)),
    );

    let bad_credential = PaymentCredential {
        credential_id: "cred-test-tampered".to_string(),
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

    let result = server.verify_credential(&challenge, &bad_credential).await;
    assert!(result.is_err(), "tampered credential should be rejected");
}

// ---------------------------------------------------------------------------
// 3. x402 pay-resource flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn x402_pay_resource() {
    let facilitator = X402Facilitator::new(vec!["tenzro".to_string()]);

    // x402 V2 wire shape (Coinbase upstream): top-level scheme + CAIP-2
    // network. tenzro-hybrid signs Ed25519 over canonical preimage:
    // network || asset || max_amount_required || pay_to || payer.
    let requirement = X402PaymentRequirement::new(
        "tenzro-hybrid",
        "tenzro",
        "1000",
        "0xrecipient",
        "USDC",
        "https://api.tenzro.network/paid/resource",
        "Test resource",
        "application/json",
        300,
    );
    let requirements = X402PaymentRequired::new(vec![requirement.clone()]);

    // Build a real Ed25519-signed payload. SchemeRegistry dispatches to
    // the tenzro-hybrid backend which verifies the signature against the
    // canonical preimage.
    let kp = KeyPair::generate(KeyType::Ed25519).expect("keypair");
    let payer_hex = hex::encode(kp.public_key().as_bytes());

    let mut signing_message = Vec::new();
    signing_message.extend_from_slice(requirement.network.as_bytes());
    signing_message.extend_from_slice(requirement.asset.as_bytes());
    signing_message.extend_from_slice(requirement.max_amount_required.as_bytes());
    signing_message.extend_from_slice(requirement.pay_to.as_bytes());
    signing_message.extend_from_slice(payer_hex.as_bytes());

    let signer = Ed25519SignerImpl::new(kp).expect("signer");
    let signature = signer.sign(&signing_message).expect("sign");

    let authorization = ExactAuthorization {
        from: payer_hex.clone(),
        to: requirement.pay_to.clone(),
        value: requirement.max_amount_required.clone(),
        valid_after: 0,
        valid_before: u64::MAX,
        nonce: format!("0x{}", hex::encode([0u8; 32])),
    };
    let payload = X402PaymentPayload::new(
        &requirement.scheme,
        &requirement.network,
        ExactSchemePayload {
            signature: hex::encode(signature.as_bytes()),
            authorization,
        },
    );

    let accepted = facilitator
        .verify(&requirements, &payload)
        .await
        .expect("verify");
    assert!(accepted, "valid x402 payload must be accepted");

    // A payload with insufficient amount must be rejected before signature
    // verification is even reached.
    let underpay_auth = ExactAuthorization {
        from: payer_hex.clone(),
        to: requirement.pay_to.clone(),
        value: "500".to_string(),
        valid_after: 0,
        valid_before: u64::MAX,
        nonce: format!("0x{}", hex::encode([1u8; 32])),
    };
    let underpay = X402PaymentPayload::new(
        &requirement.scheme,
        &requirement.network,
        ExactSchemePayload {
            signature: hex::encode(signature.as_bytes()),
            authorization: underpay_auth,
        },
    );
    let rejected = facilitator
        .verify(&requirements, &underpay)
        .await
        .expect("verify");
    assert!(!rejected, "underpaid x402 payload must be rejected");

    // A payload on an unsupported network must be rejected.
    let wrong_network_auth = ExactAuthorization {
        from: payer_hex.clone(),
        to: requirement.pay_to.clone(),
        value: requirement.max_amount_required.clone(),
        valid_after: 0,
        valid_before: u64::MAX,
        nonce: format!("0x{}", hex::encode([2u8; 32])),
    };
    let wrong_network = X402PaymentPayload::new(
        &requirement.scheme,
        "ethereum",
        ExactSchemePayload {
            signature: hex::encode(signature.as_bytes()),
            authorization: wrong_network_auth,
        },
    );
    let rejected = facilitator
        .verify(&requirements, &wrong_network)
        .await
        .expect("verify");
    assert!(!rejected, "x402 payload on unsupported network must be rejected");

    // A payload missing the signature must be rejected.
    let mut unsigned = payload.clone();
    unsigned.payload.signature.clear();
    let rejected = facilitator
        .verify(&requirements, &unsigned)
        .await
        .expect("verify");
    assert!(!rejected, "unsigned x402 payload must be rejected");

    // Settle the accepted payload. With no settlement engine attached and
    // tenzro-hybrid returning None from settle_payload, the facilitator
    // falls through to the synthetic reference id path.
    let settle_ref = facilitator
        .settle(&requirements, &payload)
        .await
        .expect("settle");
    assert!(
        settle_ref.starts_with("x402-settlement-"),
        "expected synthetic settlement reference, got {}",
        settle_ref
    );
}

// ---------------------------------------------------------------------------
// 4. Settlement engine escrow release with signed proof
// ---------------------------------------------------------------------------

#[tokio::test]
async fn settlement_escrow_release_with_zk_stub() {
    let (engine, _treasury_addr) = fresh_settlement_engine();

    // Customer with a pre-funded balance.
    let customer = Address::new([0x11; 32]);
    let asset_id = tenzro_types::asset::AssetId::tnzo();
    engine.set_balance(&customer, &asset_id, 100_000);

    // Provider derived from a real signing key.
    let proof_data = b"agentic-inference-receipt";
    let (provider, proof) = make_signed_service_proof(proof_data);

    // Settle 10_000 units for a model inference job.
    let request = SettlementRequest::new(
        provider,
        customer,
        ServiceType::ModelInference {
            model_id: "tenzro-test-model".to_string(),
            tokens: 1_234,
        },
        10_000,
        proof,
    );

    let receipt = engine.settle(request).await.expect("settle");
    assert_eq!(receipt.status, SettlementStatus::Completed);
    assert_eq!(receipt.amount, 10_000);

    // Default network fee is 0.5% (50 bps). Customer should be debited by
    // the full amount; provider should receive amount - fee.
    assert_eq!(engine.get_balance(&customer, &asset_id), 90_000);
    assert_eq!(engine.get_balance(&provider, &asset_id), 9_950);
}
