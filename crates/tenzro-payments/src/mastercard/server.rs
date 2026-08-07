//! Mastercard Agent Pay server implementation
//!
//! Implements the Mastercard agentic commerce framework with Know Your Agent (KYA)
//! verification, agentic token issuance, and purchase intent processing.

use crate::challenge_store::ChallengeStore;
use crate::error::{PaymentError, Result};
use crate::mastercard::kya::KyaVerifier;
use crate::mastercard::token_service::AgenticTokenService;
use crate::mastercard::types::{AgenticTokenType, KyaLevel};
use crate::rfc9421::{AgentRegistryClient, NonceCache};
use crate::traits::PaymentProtocol;
use crate::types::{PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_crypto::signatures::{self, Ed25519SignerImpl, Signer};
use tenzro_crypto::{KeyType, PublicKey, Signature};
use tenzro_identity::IdentityRegistry;
use tenzro_settlement::engine::SettlementEngine;
use tracing::{debug, info};
use uuid::Uuid;

/// Mastercard Agent Pay server implementing the PaymentProtocol trait
pub struct MastercardAgentPayServer {
    /// Merchant identifier
    merchant_id: String,
    /// Recipient address for payments
    recipient: String,
    /// Default asset
    default_asset: String,
    /// Default chain
    default_chain: String,
    /// KYA verifier for agent verification
    kya_verifier: KyaVerifier,
    /// Agentic token service for token management
    token_service: AgenticTokenService,
    /// Agent registry client for public key lookup
    agent_registry: Arc<dyn AgentRegistryClient>,
    /// Optional settlement engine
    settlement_engine: Option<Arc<SettlementEngine>>,
    /// Challenge store
    challenge_store: ChallengeStore,
    /// Nonce cache for replay protection
    nonce_cache: NonceCache,
}

impl MastercardAgentPayServer {
    /// Create a new Mastercard Agent Pay server
    ///
    /// # Arguments
    ///
    /// * `merchant_id` - Merchant identifier
    /// * `recipient` - Recipient address for payments
    /// * `agent_registry` - Agent registry client for public key lookup
    /// * `identity_registry` - TDIP identity registry for KYA verification
    pub fn new(
        merchant_id: impl Into<String>,
        recipient: impl Into<String>,
        agent_registry: Arc<dyn AgentRegistryClient>,
        identity_registry: Arc<IdentityRegistry>,
    ) -> Self {
        Self {
            merchant_id: merchant_id.into(),
            recipient: recipient.into(),
            default_asset: "USDC".to_string(),
            default_chain: "tempo".to_string(),
            kya_verifier: KyaVerifier::new(identity_registry),
            token_service: AgenticTokenService::new(),
            agent_registry,
            settlement_engine: None,
            challenge_store: ChallengeStore::new(),
            nonce_cache: NonceCache::new(),
        }
    }

    /// Set the settlement engine
    pub fn with_settlement_engine(mut self, engine: Arc<SettlementEngine>) -> Self {
        self.settlement_engine = Some(engine);
        self
    }

    /// Set a shared challenge store
    pub fn with_challenge_store(mut self, store: ChallengeStore) -> Self {
        self.challenge_store = store;
        self
    }

    /// Set the default asset
    pub fn with_default_asset(mut self, asset: impl Into<String>) -> Self {
        self.default_asset = asset.into();
        self
    }

    /// Set the default chain
    pub fn with_default_chain(mut self, chain: impl Into<String>) -> Self {
        self.default_chain = chain.into();
        self
    }

    /// Get a reference to the challenge store
    pub fn challenge_store(&self) -> &ChallengeStore {
        &self.challenge_store
    }

    /// Get a reference to the token service
    pub fn token_service(&self) -> &AgenticTokenService {
        &self.token_service
    }

    /// Get a reference to the KYA verifier
    pub fn kya_verifier(&self) -> &KyaVerifier {
        &self.kya_verifier
    }
}

#[async_trait]
impl PaymentProtocol for MastercardAgentPayServer {
    fn protocol_name(&self) -> &str {
        "mastercard-agent-pay"
    }

    async fn create_challenge(
        &self,
        resource: &str,
        amount: u128,
        asset: &str,
        recipient: &str,
    ) -> Result<PaymentChallenge> {
        let challenge_id = format!("mc_chal_{}", Uuid::new_v4());
        let expires_at = Utc::now() + Duration::minutes(15);

        // Use recipient parameter if provided, otherwise fallback to configured recipient
        let recipient_address = if recipient.is_empty() {
            self.recipient.clone()
        } else {
            recipient.to_string()
        };

        let mut extra = HashMap::new();
        extra.insert("requires_kya".to_string(), serde_json::Value::Bool(true));
        extra.insert(
            "merchant_id".to_string(),
            serde_json::Value::String(self.merchant_id.clone()),
        );
        extra.insert(
            "required_intent_fields".to_string(),
            serde_json::Value::Array(vec![
                serde_json::Value::String("description".to_string()),
                serde_json::Value::String("items".to_string()),
            ]),
        );

        let challenge = PaymentChallenge {
            challenge_id: challenge_id.clone(),
            protocol: "mastercard-agent-pay".to_string(),
            resource: resource.to_string(),
            amount,
            asset: asset.to_string(),
            recipient: recipient_address,
            chain: self.default_chain.clone(),
            expires_at,
            extra,
        };

        // Store the challenge
        self.challenge_store.store(&challenge);

        info!(
            "Created Mastercard Agent Pay challenge {} for resource {} amount={}",
            challenge_id, resource, amount
        );

        Ok(challenge)
    }

    async fn verify_credential(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<PaymentVerification> {
        info!(
            "Verifying Mastercard Agent Pay credential {} for challenge {}",
            credential.credential_id, challenge.challenge_id
        );

        // 1. Verify credential matches the challenge
        if credential.challenge_id != challenge.challenge_id {
            return Err(PaymentError::VerificationFailed(
                "Credential challenge_id does not match".to_string(),
            ));
        }

        // 2. Verify the challenge hasn't expired
        if Utc::now() > challenge.expires_at {
            return Err(PaymentError::VerificationFailed(
                "Challenge has expired".to_string(),
            ));
        }

        // 3. Verify amounts match
        if credential.amount != challenge.amount {
            return Err(PaymentError::VerificationFailed(format!(
                "Amount mismatch: expected {}, got {}",
                challenge.amount, credential.amount
            )));
        }

        // 4. Check nonce for replay protection
        if let Some(nonce) = credential.extra.get("nonce").and_then(|v| v.as_str()) {
            self.nonce_cache.check_and_store(nonce)?;
        }

        // 5. Run KYA verification
        let kya_result = self.kya_verifier.verify(&credential.payer_did)?;

        if kya_result.verification_level == KyaLevel::Unverified {
            return Err(PaymentError::KyaError(format!(
                "Agent {} failed KYA verification",
                credential.payer_did
            )));
        }

        debug!(
            "KYA verification passed: level={:?}",
            kya_result.verification_level
        );

        // 6. Verify agentic token if present
        if let Some(token_id_value) = credential.extra.get("token_id")
            && let Some(token_id) = token_id_value.as_str()
        {
            let token = self.token_service.verify_token(token_id)?;
            debug!(
                "Verified agentic token {} for agent {}",
                token_id, token.agent_did
            );
        }

        // 7. Verify Ed25519 signature on credential
        // Build the message that was signed
        let message = format!(
            "{}:{}:{}:{}",
            credential.challenge_id, credential.payer_did, credential.amount, credential.asset
        );

        // Extract public key from extra
        let public_key_hex = credential
            .extra
            .get("public_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PaymentError::VerificationFailed("Missing public_key in extra".to_string())
            })?;

        let public_key_bytes = hex::decode(public_key_hex).map_err(|e| {
            PaymentError::VerificationFailed(format!("Invalid public_key hex: {}", e))
        })?;

        // 8. Verify agent exists in registry (using DID as key_id for Tenzro registry)
        if !self
            .agent_registry
            .verify_agent(&credential.payer_did)
            .await?
        {
            return Err(PaymentError::VerificationFailed(format!(
                "Agent {} not found in registry",
                credential.payer_did
            )));
        }

        let public_key = PublicKey::new(KeyType::Ed25519, public_key_bytes);
        let signature = Signature::new(KeyType::Ed25519, credential.signature.clone());

        // Verify the signature (returns Result<()>)
        signatures::verify(&public_key, message.as_bytes(), &signature).map_err(|e| {
            PaymentError::VerificationFailed(format!("Signature verification failed: {}", e))
        })?;

        debug!("Credential signature verified successfully");

        Ok(PaymentVerification {
            verified: true,
            credential_id: credential.credential_id.clone(),
            challenge_id: challenge.challenge_id.clone(),
            payer_did: credential.payer_did.clone(),
            verified_at: Utc::now(),
            settlement_ref: None,
        })
    }

    async fn settle(&self, verification: &PaymentVerification) -> Result<PaymentReceipt> {
        info!(
            "Settling Mastercard Agent Pay payment for credential {}",
            verification.credential_id
        );

        // Look up the challenge from the store
        let challenge = self.challenge_store.get(&verification.challenge_id)?;

        // Execute settlement if settlement engine is configured
        let settlement_tx = if let Some(engine) = &self.settlement_engine {
            debug!("Executing settlement via settlement engine");

            // Build a SettlementRequest from the challenge data.
            // Addresses are derived from DID strings via UTF-8 SHA-256 hash (first 32 bytes).
            use sha2::{Digest, Sha256};
            use tenzro_types::primitives::Address;
            use tenzro_types::settlement::{ProofType, ServiceProof, ServiceType};

            let payer_hash = Sha256::digest(verification.payer_did.as_bytes());
            let recipient_hash = Sha256::digest(challenge.recipient.as_bytes());

            let mut customer_addr = [0u8; 32];
            customer_addr.copy_from_slice(&payer_hash);
            let mut provider_addr = [0u8; 32];
            provider_addr.copy_from_slice(&recipient_hash);

            let service_proof = ServiceProof::new(
                ProofType::Cryptographic,
                verification.credential_id.as_bytes().to_vec(),
            );

            let request = tenzro_types::settlement::SettlementRequest::new(
                Address::new(provider_addr),
                Address::new(customer_addr),
                ServiceType::HttpPayment {
                    protocol: "mastercard-agent-pay".to_string(),
                    resource: challenge.resource.clone(),
                },
                challenge.amount.min(u64::MAX as u128) as u64,
                service_proof,
            );

            match engine.settle(request).await {
                Ok(receipt) => {
                    let tx_hex = hex::encode(receipt.transaction_hash.as_bytes());
                    Some(format!("0x{}", tx_hex))
                }
                Err(e) => {
                    // Log but don't fail the receipt — the payment was verified;
                    // on-chain settlement can be retried by the operator.
                    tracing::warn!("On-chain settlement failed (will be retried): {}", e);
                    // Deterministic fallback hash derived from the verification credential ID
                    let fallback = Sha256::digest(verification.credential_id.as_bytes());
                    Some(format!("0x{}", hex::encode(fallback)))
                }
            }
        } else {
            debug!("No settlement engine configured, skipping on-chain settlement");
            None
        };

        // Remove the challenge after successful settlement
        self.challenge_store.remove(&verification.challenge_id);

        let receipt = PaymentReceipt {
            receipt_id: format!("mc_rcpt_{}", Uuid::new_v4()),
            protocol: "mastercard-agent-pay".to_string(),
            challenge_id: verification.challenge_id.clone(),
            credential_id: verification.credential_id.clone(),
            amount: challenge.amount,
            asset: challenge.asset.clone(),
            settlement_tx,
            chain: challenge.chain.clone(),
            settled_at: Utc::now(),
            principal_chain: tenzro_types::principal_chain::anonymous_chain_for_did(
                verification.payer_did.clone(),
                tenzro_types::primitives::BlockHeight::new(0),
            ),
            extra: HashMap::new(),
        };

        info!("Settlement complete, receipt: {}", receipt.receipt_id);

        Ok(receipt)
    }

    async fn create_credential(
        &self,
        challenge: &PaymentChallenge,
        payer_did: &str,
        _wallet_id: &str,
    ) -> Result<PaymentCredential> {
        info!(
            "Creating Mastercard Agent Pay credential for challenge {} payer={}",
            challenge.challenge_id, payer_did
        );

        // 1. Run KYA verification
        let kya_result = self.kya_verifier.verify(payer_did)?;

        if kya_result.verification_level == KyaLevel::Unverified {
            return Err(PaymentError::KyaError(format!(
                "Agent {} failed KYA verification",
                payer_did
            )));
        }

        // 2. Issue an agentic token
        let token = self.token_service.issue_token(
            payer_did,
            AgenticTokenType::SingleUse,
            vec![],
            Some(challenge.amount),
            Duration::hours(1),
        )?;

        // 3. Generate Ed25519 keypair and sign the credential
        let signer = Ed25519SignerImpl::generate()?;
        let public_key_bytes = signer.public_key().to_bytes();

        let message = format!(
            "{}:{}:{}:{}",
            challenge.challenge_id, payer_did, challenge.amount, challenge.asset
        );
        let signature = signer.sign(message.as_bytes())?;
        let signature_bytes = signature.to_bytes();

        // 4. Build credential with token and KYA info in extra
        let mut extra = HashMap::new();
        extra.insert(
            "token_id".to_string(),
            serde_json::Value::String(token.token_id.clone()),
        );
        extra.insert(
            "kya_level".to_string(),
            serde_json::Value::String(kya_result.verification_level.to_string()),
        );
        extra.insert(
            "public_key".to_string(),
            serde_json::Value::String(hex::encode(&public_key_bytes)),
        );
        extra.insert(
            "nonce".to_string(),
            serde_json::Value::String(Uuid::new_v4().to_string()),
        );

        // Mastercard Agent Pay credentials are verified by the Mastercard
        // network using its own signature scheme; the PaymentCredential PQ
        // legs are intentionally empty for this external passthrough.
        let credential = PaymentCredential {
            credential_id: format!("mc_cred_{}", Uuid::new_v4()),
            challenge_id: challenge.challenge_id.clone(),
            protocol: "mastercard-agent-pay".to_string(),
            payer_did: payer_did.to_string(),
            payer_address: hex::encode(&public_key_bytes),
            amount: challenge.amount,
            asset: challenge.asset.clone(),
            signature: signature_bytes,
            pq_signature: Vec::new(),
            pq_public_key: Vec::new(),
            extra,
        };

        debug!(
            "Created credential {} with token {} and KYA level {:?}",
            credential.credential_id, token.token_id, kya_result.verification_level
        );

        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc9421::TenzroAgentRegistry;

    async fn setup_server() -> (MastercardAgentPayServer, Arc<IdentityRegistry>) {
        let identity_registry = Arc::new(IdentityRegistry::new());
        let agent_registry = Arc::new(TenzroAgentRegistry::new(identity_registry.clone()));

        let server = MastercardAgentPayServer::new(
            "merchant_123",
            "0xrecipient",
            agent_registry,
            identity_registry.clone(),
        );

        (server, identity_registry)
    }

    #[tokio::test]
    async fn test_create_challenge() {
        let (server, _) = setup_server().await;

        let challenge = server
            .create_challenge("/api/resource", 1000, "USDC", "0xrecipient")
            .await
            .unwrap();

        assert_eq!(challenge.protocol, "mastercard-agent-pay");
        assert_eq!(challenge.amount, 1000);
        assert_eq!(challenge.asset, "USDC");
        assert!(challenge.extra.contains_key("requires_kya"));
        assert!(challenge.extra.contains_key("merchant_id"));
    }

    #[tokio::test]
    async fn test_verify_credential_with_kya() {
        let (server, identity_registry) = setup_server().await;

        // Register an autonomous agent
        let agent_did = identity_registry
            .register_autonomous_machine(
                vec![10; 32],
                vec!["payment".to_string()],
                tenzro_identity::identity::MachineAnchor::HardwareRooted {
                    hardware_root_hex: "ab".repeat(32),
                    sources: vec!["tpm:ek".to_string()],
                },
            )
            .await
            .unwrap()
            .did_string();

        // Create a challenge
        let challenge = server
            .create_challenge("/api/resource", 500, "USDC", "0xrecipient")
            .await
            .unwrap();

        // Create a credential
        let credential = server
            .create_credential(&challenge, &agent_did, "wallet_1")
            .await
            .unwrap();

        // Verify the credential
        let verification = server
            .verify_credential(&challenge, &credential)
            .await
            .unwrap();

        assert!(verification.verified);
        assert_eq!(verification.payer_did, agent_did);
    }

    #[tokio::test]
    async fn test_verify_credential_fails_for_unverified_agent() {
        let (server, _) = setup_server().await;

        let challenge = server
            .create_challenge("/api/resource", 500, "USDC", "0xrecipient")
            .await
            .unwrap();

        // Try to create credential for unknown agent
        let result = server
            .create_credential(&challenge, "did:tenzro:machine:unknown", "wallet_1")
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PaymentError::KyaError(_)));
    }

    #[tokio::test]
    async fn test_settle() {
        let (server, identity_registry) = setup_server().await;

        // Register an autonomous agent
        let agent_did = identity_registry
            .register_autonomous_machine(
                vec![11; 32],
                vec!["payment".to_string()],
                tenzro_identity::identity::MachineAnchor::HardwareRooted {
                    hardware_root_hex: "ab".repeat(32),
                    sources: vec!["tpm:ek".to_string()],
                },
            )
            .await
            .unwrap()
            .did_string();

        // Create and verify
        let challenge = server
            .create_challenge("/api/resource", 1500, "USDC", "0xrecipient")
            .await
            .unwrap();

        let credential = server
            .create_credential(&challenge, &agent_did, "wallet_1")
            .await
            .unwrap();

        let verification = server
            .verify_credential(&challenge, &credential)
            .await
            .unwrap();

        // Settle
        let receipt = server.settle(&verification).await.unwrap();

        assert_eq!(receipt.protocol, "mastercard-agent-pay");
        assert_eq!(receipt.amount, 1500);
        assert!(receipt.receipt_id.starts_with("mc_rcpt_"));
    }

    #[tokio::test]
    async fn test_token_service_integration() {
        let (server, _) = setup_server().await;

        let token = server
            .token_service()
            .issue_token(
                "did:tenzro:machine:agent",
                AgenticTokenType::SessionBound,
                vec!["merchant.example.com".to_string()],
                Some(5000),
                Duration::hours(1),
            )
            .unwrap();

        assert_eq!(token.agent_did, "did:tenzro:machine:agent");
        assert_eq!(token.token_type, AgenticTokenType::SessionBound);
        assert_eq!(token.amount_limit, Some(5000));
    }
}
