//! MPP server-side payment protocol implementation

use crate::challenge_store::ChallengeStore;
use crate::error::{PaymentError, Result};
use crate::mpp::challenge::MppChallenge;
use crate::mpp::credential::MppCredential;
use crate::traits::PaymentProtocol;
use crate::types::{PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_crypto::composite::{
    CompositePublicKey, CompositeSignature, HybridSigner, HybridVerifier,
    InMemoryHybridSigner, StandardHybridVerifier,
};
use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_settlement::engine::SettlementEngine;
use tenzro_types::settlement::{ProofType, ServiceProof, ServiceType};
use tenzro_types::Address;
use tracing::{debug, info};

/// MPP server-side payment handler
pub struct MppPaymentServer {
    /// Recipient address for payments
    _recipient: String,
    /// Default asset
    default_asset: String,
    /// Default chain
    default_chain: String,
    /// Settlement engine for executing payments
    settlement_engine: Option<Arc<SettlementEngine>>,
    /// Challenge store for looking up challenges during settlement
    challenge_store: ChallengeStore,
}

impl MppPaymentServer {
    /// Creates a new MPP payment server
    pub fn new(recipient: impl Into<String>) -> Self {
        Self {
            _recipient: recipient.into(),
            default_asset: "USDC".to_string(),
            default_chain: "tempo".to_string(),
            settlement_engine: None,
            challenge_store: ChallengeStore::new(),
        }
    }

    /// Sets the default asset
    pub fn with_default_asset(mut self, asset: impl Into<String>) -> Self {
        self.default_asset = asset.into();
        self
    }

    /// Sets the default chain
    pub fn with_default_chain(mut self, chain: impl Into<String>) -> Self {
        self.default_chain = chain.into();
        self
    }

    /// Sets the settlement engine
    pub fn with_settlement_engine(mut self, engine: Arc<SettlementEngine>) -> Self {
        self.settlement_engine = Some(engine);
        self
    }

    /// Sets a shared challenge store (e.g., shared with gateway)
    pub fn with_challenge_store(mut self, store: ChallengeStore) -> Self {
        self.challenge_store = store;
        self
    }

    /// Returns a reference to the challenge store
    pub fn challenge_store(&self) -> &ChallengeStore {
        &self.challenge_store
    }
}

/// Parses a hex string into a 32-byte Address, zero-padding if needed
fn parse_address(hex_str: &str) -> Address {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).unwrap_or_default();
    let mut addr = [0u8; 32];
    let len = bytes.len().min(32);
    addr[32 - len..].copy_from_slice(&bytes[..len]);
    Address::new(addr)
}

#[async_trait]
impl PaymentProtocol for MppPaymentServer {
    fn protocol_name(&self) -> &str {
        "mpp"
    }

    async fn create_challenge(
        &self,
        resource: &str,
        amount: u128,
        asset: &str,
        recipient: &str,
    ) -> Result<PaymentChallenge> {
        let mpp_challenge =
            MppChallenge::new(resource, amount, asset, recipient).with_chain(&self.default_chain);

        info!(
            "Created MPP challenge {} for resource {} amount={}",
            mpp_challenge.challenge_id, resource, amount
        );

        let challenge = PaymentChallenge {
            challenge_id: mpp_challenge.challenge_id,
            protocol: "mpp".to_string(),
            resource: mpp_challenge.resource,
            amount: mpp_challenge.amount,
            asset: mpp_challenge.asset,
            recipient: mpp_challenge.recipient,
            chain: mpp_challenge.chain,
            expires_at: mpp_challenge.expires_at,
            extra: HashMap::new(),
        };

        // Store the challenge for later lookup during settlement
        self.challenge_store.store(&challenge);

        Ok(challenge)
    }

    async fn verify_credential(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<PaymentVerification> {
        info!(
            "Verifying MPP credential {} for challenge {}",
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

        // 4. Verify hybrid signature (Ed25519 + ML-DSA-65, both legs mandatory)
        let message = self.construct_credential_message(credential)?;
        let classical_pk = self.extract_public_key(credential)?;
        if credential.pq_public_key.is_empty() {
            return Err(PaymentError::VerificationFailed(
                "Internal Tenzro MPP credential is missing pq_public_key (ML-DSA-65)".to_string(),
            ));
        }
        if credential.pq_signature.is_empty() {
            return Err(PaymentError::VerificationFailed(
                "Internal Tenzro MPP credential is missing pq_signature (ML-DSA-65)".to_string(),
            ));
        }
        let composite_pk =
            CompositePublicKey::new(classical_pk, Some(credential.pq_public_key.clone()));
        let composite_sig = CompositeSignature::new(
            credential.signature.clone(),
            Some(credential.pq_signature.clone()),
        );
        let verifier = StandardHybridVerifier::new(composite_pk);
        verifier.verify(&message, &composite_sig).map_err(|e| {
            PaymentError::VerificationFailed(format!(
                "Hybrid signature verification failed: {}",
                e
            ))
        })?;

        debug!("Credential hybrid signature verified successfully");

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
            "Settling MPP payment for credential {}",
            verification.credential_id
        );

        // Look up the original challenge from the store
        let challenge = self
            .challenge_store
            .get(&verification.challenge_id)
            .map_err(|_| {
                PaymentError::SettlementError(format!(
                    "Challenge {} not found in store — cannot determine settlement amount",
                    verification.challenge_id
                ))
            })?;

        // If a settlement engine is configured, execute real settlement
        if let Some(engine) = &self.settlement_engine {
            debug!("Executing settlement via engine for amount={}", challenge.amount);

            let amount_u64 = u64::try_from(challenge.amount).map_err(|_| {
                PaymentError::SettlementError("Settlement amount exceeds u64 range".to_string())
            })?;

            let provider_addr = parse_address(&challenge.recipient);
            let customer_addr = parse_address(&verification.payer_did);

            let request = tenzro_types::settlement::SettlementRequest::new(
                provider_addr,
                customer_addr,
                ServiceType::HttpPayment {
                    protocol: "mpp".to_string(),
                    resource: challenge.resource.clone(),
                },
                amount_u64,
                ServiceProof {
                    proof_type: ProofType::Cryptographic,
                    proof_data: verification.credential_id.as_bytes().to_vec(),
                    signatures: vec![],
                    attestation: None,
                },
            );

            let receipt = engine
                .settle(request)
                .await
                .map_err(|e| PaymentError::SettlementError(e.to_string()))?;

            // Remove the challenge after successful settlement
            self.challenge_store.remove(&challenge.challenge_id);

            return Ok(PaymentReceipt {
                receipt_id: receipt.receipt_id,
                protocol: "mpp".to_string(),
                challenge_id: challenge.challenge_id,
                credential_id: verification.credential_id.clone(),
                amount: receipt.amount as u128,
                asset: challenge.asset,
                settlement_tx: Some(hex::encode(receipt.transaction_hash.as_bytes())),
                chain: challenge.chain,
                settled_at: Utc::now(),
                principal_chain: receipt.principal_chain,
                extra: HashMap::new(),
            });
        }

        // No settlement engine — generate receipt with real amount from challenge
        info!(
            "No settlement engine configured, generating receipt for amount={}",
            challenge.amount
        );
        self.challenge_store.remove(&challenge.challenge_id);

        Ok(PaymentReceipt {
            receipt_id: uuid::Uuid::new_v4().to_string(),
            protocol: "mpp".to_string(),
            challenge_id: challenge.challenge_id,
            credential_id: verification.credential_id.clone(),
            amount: challenge.amount,
            asset: challenge.asset,
            settlement_tx: verification.settlement_ref.clone(),
            chain: challenge.chain,
            settled_at: Utc::now(),
            principal_chain: tenzro_types::principal_chain::anonymous_chain_for_did(
                verification.payer_did.clone(),
                tenzro_types::primitives::BlockHeight::new(0),
            ),
            extra: HashMap::new(),
        })
    }

    async fn create_credential(
        &self,
        challenge: &PaymentChallenge,
        payer_did: &str,
        wallet_id: &str,
    ) -> Result<PaymentCredential> {
        let cred = MppCredential::new(
            &challenge.challenge_id,
            payer_did,
            wallet_id,
            challenge.amount,
            &challenge.asset,
        );

        // Construct the credential message and sign it
        let mut message = Vec::new();
        message.extend_from_slice(challenge.challenge_id.as_bytes());
        message.extend_from_slice(payer_did.as_bytes());
        message.extend_from_slice(&challenge.amount.to_le_bytes());
        message.extend_from_slice(challenge.asset.as_bytes());

        // Generate an Ed25519 keypair for the classical leg.
        // In production, this would use the wallet service to get the keypair for wallet_id.
        let keypair = tenzro_crypto::KeyPair::generate(tenzro_crypto::KeyType::Ed25519)
            .map_err(|e| PaymentError::CredentialError(format!("Failed to generate keypair: {}", e)))?;

        // Extract public key bytes before consuming keypair (KeyPair doesn't implement Clone for security)
        let public_key_bytes = keypair.public_key().as_bytes().to_vec();

        let classical = tenzro_crypto::signatures::Ed25519SignerImpl::new(keypair)
            .map_err(|e| PaymentError::CredentialError(format!("Failed to create signer: {}", e)))?;

        // Generate the post-quantum leg (ML-DSA-65).
        let pq = MlDsaSigningKey::generate();
        let pq_public_key = pq.verifying_key_bytes().to_vec();

        let hybrid = InMemoryHybridSigner::new(Box::new(classical), pq);
        let composite = hybrid.sign(&message).map_err(|e| {
            PaymentError::CredentialError(format!("Failed to hybrid-sign credential: {}", e))
        })?;
        let pq_signature = composite.pq.clone().ok_or_else(|| {
            PaymentError::CredentialError(
                "Hybrid signer produced no PQ leg for MPP credential".to_string(),
            )
        })?;

        let mut extra = HashMap::new();
        extra.insert(
            "public_key".to_string(),
            serde_json::json!(hex::encode(&public_key_bytes)),
        );

        Ok(PaymentCredential {
            credential_id: cred.credential_id,
            challenge_id: cred.challenge_id,
            protocol: "mpp".to_string(),
            payer_did: cred.payer_did,
            payer_address: hex::encode(&public_key_bytes),
            amount: cred.amount,
            asset: cred.asset,
            signature: composite.classical,
            pq_signature,
            pq_public_key,
            extra,
        })
    }
}

// Helper methods for MPP payment server (not part of PaymentProtocol trait)
impl MppPaymentServer {
    /// Constructs the message that should be signed in a credential
    fn construct_credential_message(&self, credential: &PaymentCredential) -> Result<Vec<u8>> {
        let mut message = Vec::new();
        message.extend_from_slice(credential.challenge_id.as_bytes());
        message.extend_from_slice(credential.payer_did.as_bytes());
        message.extend_from_slice(&credential.amount.to_le_bytes());
        message.extend_from_slice(credential.asset.as_bytes());
        Ok(message)
    }

    /// Extracts the public key from the credential's metadata
    fn extract_public_key(&self, credential: &PaymentCredential) -> Result<PublicKey> {
        // Look for public key in the credential's extra metadata
        if let Some(pk_value) = credential.extra.get("public_key")
            && let Some(pk_hex) = pk_value.as_str()
        {
            let pk_bytes = hex::decode(pk_hex).map_err(|e| {
                PaymentError::CredentialError(format!("Invalid public key hex: {}", e))
            })?;
            return Ok(PublicKey::new(KeyType::Ed25519, pk_bytes));
        }

        // If no public key in metadata, derive from payer_address (simplified)
        if !credential.payer_address.is_empty() {
            let pk_bytes = hex::decode(&credential.payer_address).map_err(|_| {
                PaymentError::CredentialError(
                    "Credential must include public_key in extra metadata or valid payer_address"
                        .to_string(),
                )
            })?;
            return Ok(PublicKey::new(KeyType::Ed25519, pk_bytes));
        }

        Err(PaymentError::CredentialError(
            "No public key found in credential".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_stored_on_creation() {
        let server = MppPaymentServer::new("0xrecipient");
        let challenge = server
            .create_challenge("/api/test", 1000, "USDC", "0xrecipient")
            .await
            .unwrap();

        // The challenge should be stored
        let stored = server.challenge_store().get(&challenge.challenge_id);
        assert!(stored.is_ok());
        assert_eq!(stored.unwrap().amount, 1000);
    }

    #[tokio::test]
    async fn test_settle_uses_stored_challenge_amount() {
        let server = MppPaymentServer::new("0xrecipient");

        // Create a challenge (this stores it)
        let challenge = server
            .create_challenge("/api/test", 5000, "USDC", "0xrecipient")
            .await
            .unwrap();

        // Simulate verification
        let verification = PaymentVerification {
            verified: true,
            credential_id: "cred-1".to_string(),
            challenge_id: challenge.challenge_id.clone(),
            payer_did: "did:tenzro:human:alice".to_string(),
            verified_at: Utc::now(),
            settlement_ref: None,
        };

        // Settle — should use stored challenge amount (5000), not 0
        let receipt = server.settle(&verification).await.unwrap();
        assert_eq!(receipt.amount, 5000);
        assert_eq!(receipt.asset, "USDC");
    }

    #[tokio::test]
    async fn test_settle_removes_challenge() {
        let server = MppPaymentServer::new("0xrecipient");
        let challenge = server
            .create_challenge("/api/test", 1000, "USDC", "0xrecipient")
            .await
            .unwrap();

        let verification = PaymentVerification {
            verified: true,
            credential_id: "cred-1".to_string(),
            challenge_id: challenge.challenge_id.clone(),
            payer_did: "payer".to_string(),
            verified_at: Utc::now(),
            settlement_ref: None,
        };

        server.settle(&verification).await.unwrap();

        // Challenge should be removed after settlement
        assert!(server
            .challenge_store()
            .get(&challenge.challenge_id)
            .is_err());
    }

    #[tokio::test]
    async fn test_settle_fails_for_unknown_challenge() {
        let server = MppPaymentServer::new("0xrecipient");

        let verification = PaymentVerification {
            verified: true,
            credential_id: "cred-1".to_string(),
            challenge_id: "nonexistent".to_string(),
            payer_did: "payer".to_string(),
            verified_at: Utc::now(),
            settlement_ref: None,
        };

        let result = server.settle(&verification).await;
        assert!(result.is_err());
    }
}
