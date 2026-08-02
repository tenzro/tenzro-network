//! Dollar-cost averaging (DCA) agent walkthrough
//!
//! Builds an autonomous DCA agent that:
//!
//! 1. Provisions a human controller identity via TDIP
//! 2. Provisions a machine identity under the human, with a fine-grained
//!    delegation scope (per-buy cap, daily cap, allowed operations)
//! 3. For each scheduled buy:
//!    a. Creates an MPP payment challenge against the on-chain price oracle
//!    b. Signs and submits a credential with a real Ed25519 signature
//!    c. Verifies and settles the credential through `MppPaymentServer`
//!    d. Pre-funds the customer in the settlement engine and asks the
//!    engine to release the payment to the provider against a signed
//!    service proof — exercising the real `SettlementEngine`
//! 4. Enforces the delegation scope BEFORE every buy, so the agent cannot
//!    exceed its per-buy cap or invoke disallowed operations
//! 5. Demonstrates that the delegation scope rejects an oversized buy
//!
//! Run it with:
//!
//! ```bash
//! cargo run --example dca_agent -p tenzro-node
//! ```

use std::sync::Arc;

use tenzro_crypto::keys::{KeyPair, KeyType};
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

use tenzro_identity::{DelegationScope, IdentityRegistry, TimeBound, WalletBinder};
use tenzro_types::identity::KycTier;

use tenzro_payments::mpp::MppPaymentServer;
use tenzro_payments::traits::PaymentProtocol;
use tenzro_payments::types::PaymentCredential;

use tenzro_settlement::engine::{SettlementConfig, SettlementEngine};

use tenzro_token::NetworkTreasury;

use tenzro_types::primitives::Address;
use tenzro_types::settlement::{
    ProofSignature, ProofType, ServiceProof, ServiceType, SettlementRequest, SettlementStatus,
    SignerRole,
};

/// 1 USDC in 6-decimal base units.
const ONE_USDC: u128 = 1_000_000;

#[derive(Debug, Clone, Copy)]
struct ScheduledBuy {
    /// Symbolic asset being bought (e.g., BTC, ETH).
    asset: &'static str,
    /// Amount of USDC being spent on this buy.
    spend_usdc: u128,
}

/// Sign an MPP credential message exactly the way `MppPaymentServer` expects.
///
/// Canonical message: `challenge_id ++ payer_did ++ amount.to_le_bytes() ++ asset`
fn sign_mpp_credential(
    challenge_id: &str,
    payer_did: &str,
    amount: u128,
    asset: &str,
) -> (Vec<u8>, Vec<u8>) {
    let mut message = Vec::new();
    message.extend_from_slice(challenge_id.as_bytes());
    message.extend_from_slice(payer_did.as_bytes());
    message.extend_from_slice(&amount.to_le_bytes());
    message.extend_from_slice(asset.as_bytes());

    let keypair = KeyPair::generate(KeyType::Ed25519).expect("keypair");
    let public_key_bytes = keypair.public_key().as_bytes().to_vec();
    let signer = Ed25519SignerImpl::new(keypair).expect("signer");
    let signature = signer.sign(&message).expect("sign");

    (public_key_bytes, signature.to_bytes())
}

/// Build a settlement-engine `ServiceProof` carrying a real Ed25519 signature
/// over `proof_data`.
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Tenzro DCA agent walkthrough");
    println!("============================");

    // ------------------------------------------------------------------
    // Step 1: provision the human controller via TDIP
    // ------------------------------------------------------------------
    println!("\n=== Step 1: Provision human controller identity ===");
    let registry = IdentityRegistry::with_wallet_binder(Arc::new(WalletBinder::new()?));

    let human_keypair = KeyPair::generate(KeyType::Ed25519)?;
    let human_pubkey = human_keypair.public_key().as_bytes().to_vec();
    let human = registry
        .register_human_with_fee(
            human_pubkey,
            "DCA Strategist".to_string(),
            KycTier::Enhanced,
        )
        .await?
        .identity;
    let human_did = human.did_string();
    println!("→ controller DID: {}", human_did);
    println!("  wallet         : {}", human.wallet_id);

    // ------------------------------------------------------------------
    // Step 2: provision the DCA agent with a delegation scope
    // ------------------------------------------------------------------
    println!("\n=== Step 2: Provision DCA agent under controller ===");
    let agent_keypair = KeyPair::generate(KeyType::Ed25519)?;
    let agent_pubkey = agent_keypair.public_key().as_bytes().to_vec();

    let now = chrono::Utc::now();
    let scope = DelegationScope::unrestricted()
        .with_max_transaction_value(100 * ONE_USDC)
        .with_max_daily_spend(1_000 * ONE_USDC)
        .with_allowed_operations(vec!["dca-buy".to_string(), "trade".to_string()])
        .with_time_bound(TimeBound::new(now, now + chrono::Duration::days(30)));

    let agent = registry
        .register_machine_with_fee(
            &human_did,
            agent_pubkey,
            vec!["dca".to_string(), "trade".to_string()],
            scope,
        )
        .await?
        .identity;
    let agent_did = agent.did_string();
    println!("→ agent DID         : {}", agent_did);
    println!("  agent wallet      : {}", agent.wallet_id);
    println!("  max per-buy value : 100 USDC");
    println!("  max daily spend   : 1000 USDC");
    println!("  allowed ops       : dca-buy, trade");
    println!("  time bound        : 30 days");

    // ------------------------------------------------------------------
    // Step 3: build the MPP server and the SettlementEngine
    // ------------------------------------------------------------------
    println!("\n=== Step 3: Construct MPP server and SettlementEngine ===");
    let mpp_server = MppPaymentServer::new("0xdca-recipient");

    let treasury_addr = Address::new([0xAA; 32]);
    let treasury = Arc::new(NetworkTreasury::new(treasury_addr));
    let settlement_config = SettlementConfig::new(treasury_addr);
    let settlement_engine = Arc::new(SettlementEngine::new(settlement_config, treasury)?);

    // The DCA agent's customer wallet — pre-fund it with enough USDC equivalent
    // (the settlement engine uses TNZO as its native asset id).
    let customer = Address::new([0x11; 32]);
    let asset_id = tenzro_types::asset::AssetId::tnzo();
    settlement_engine.set_balance(&customer, &asset_id, 1_000_000_000); // 1000 USDC worth
    println!(
        "→ customer pre-funded balance = {}",
        settlement_engine.get_balance(&customer, &asset_id)
    );

    // ------------------------------------------------------------------
    // Step 4: run the DCA schedule — for each buy, MPP + settlement
    // ------------------------------------------------------------------
    println!("\n=== Step 4: Execute DCA schedule ===");
    let schedule = [
        ScheduledBuy {
            asset: "BTC",
            spend_usdc: 25 * ONE_USDC,
        },
        ScheduledBuy {
            asset: "ETH",
            spend_usdc: 25 * ONE_USDC,
        },
        ScheduledBuy {
            asset: "SOL",
            spend_usdc: 25 * ONE_USDC,
        },
        ScheduledBuy {
            asset: "BTC",
            spend_usdc: 75 * ONE_USDC,
        },
    ];

    let mut total_spent = 0u128;
    let mut total_settled_amount: u64 = 0;
    let mut completed_buys = 0;

    for (i, buy) in schedule.iter().enumerate() {
        println!(
            "\n→ Buy #{}: {} USDC of {}",
            i + 1,
            buy.spend_usdc / ONE_USDC,
            buy.asset
        );

        // (4a) Enforce the delegation scope BEFORE doing anything else.
        match registry.enforce_operation(&agent_did, "dca-buy", Some(buy.spend_usdc)) {
            Ok(()) => println!(
                "  delegation OK ({} USDC ≤ 100 USDC per-buy cap)",
                buy.spend_usdc / ONE_USDC
            ),
            Err(e) => {
                println!("  BLOCKED by delegation: {e}");
                continue;
            }
        }

        // (4b) Create an MPP challenge for this buy.
        let challenge = mpp_server
            .create_challenge(
                &format!("/dca/buy/{}", buy.asset),
                buy.spend_usdc,
                "USDC",
                "0xdca-recipient",
            )
            .await?;
        println!("  challenge {} created", challenge.challenge_id);

        // (4c) Sign a credential with a real Ed25519 signature.
        let payer_did = "did:tenzro:human:dca-walkthrough-payer";
        let (public_key_bytes, signature_bytes) = sign_mpp_credential(
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
            credential_id: format!("dca-cred-{}", i + 1),
            challenge_id: challenge.challenge_id.clone(),
            protocol: "mpp".to_string(),
            payer_did: payer_did.to_string(),
            payer_address: hex::encode(&public_key_bytes),
            amount: challenge.amount,
            asset: challenge.asset.clone(),
            signature: signature_bytes,
            // External-protocol passthroughs (this MPP demo) leave the PQ leg empty —
            // the hybrid verifier is exercised by the production credential path, not
            // this walkthrough.
            pq_signature: Vec::new(),
            pq_public_key: Vec::new(),
            extra,
        };

        // (4d) Verify and settle through the MPP server.
        let verification = mpp_server
            .verify_credential(&challenge, &credential)
            .await?;
        let receipt = mpp_server.settle(&verification).await?;
        println!(
            "  MPP receipt: {} {} settled via {}",
            receipt.amount, receipt.asset, receipt.protocol
        );

        // (4e) Settle on-chain via the SettlementEngine with a signed proof.
        // The DCA agent acts as the verifier and the asset provider gets paid
        // a proportional amount of TNZO equivalent.
        let proof_data = format!("dca-buy-{}-{}", buy.asset, i + 1);
        let (provider, proof) = make_signed_service_proof(proof_data.as_bytes());

        let settlement_amount: u64 = ((buy.spend_usdc / ONE_USDC) * 1_000) as u64; // mock conversion
        let request = SettlementRequest::new(
            provider,
            customer,
            ServiceType::ModelInference {
                model_id: format!("dca-asset-{}", buy.asset),
                tokens: 1,
            },
            settlement_amount,
            proof,
        );

        let settlement_receipt = settlement_engine.settle(request).await?;
        let status_label = if settlement_receipt.status == SettlementStatus::Completed {
            "Completed"
        } else {
            "Other"
        };
        println!(
            "  on-chain settlement: status = {}, amount = {}",
            status_label, settlement_receipt.amount
        );
        println!(
            "  customer balance after buy = {}",
            settlement_engine.get_balance(&customer, &asset_id)
        );
        println!(
            "  provider balance after buy = {} (after 0.5% network fee)",
            settlement_engine.get_balance(&provider, &asset_id)
        );

        total_spent += buy.spend_usdc;
        total_settled_amount += settlement_receipt.amount;
        completed_buys += 1;
    }

    println!(
        "\n→ DCA schedule complete: {} buys executed, total {} USDC spent, {} settled on-chain",
        completed_buys,
        total_spent / ONE_USDC,
        total_settled_amount
    );

    // ------------------------------------------------------------------
    // Step 5: demonstrate that the delegation scope rejects an oversized buy
    // ------------------------------------------------------------------
    println!("\n=== Step 5: Confirm delegation rejects an oversized buy ===");
    let oversized = 250 * ONE_USDC; // exceeds max_transaction_value (100 USDC)
    match registry.enforce_operation(&agent_did, "dca-buy", Some(oversized)) {
        Ok(()) => println!("→ unexpected: oversized buy was allowed"),
        Err(err) => println!(
            "→ oversized {} USDC buy rejected by delegation: {err}",
            oversized / ONE_USDC
        ),
    }

    println!("\nDCA agent walkthrough complete.");
    Ok(())
}
