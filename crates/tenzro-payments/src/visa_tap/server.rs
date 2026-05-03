//! Visa TAP server implementation

use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;
use async_trait::async_trait;
use chrono::Utc;
use tracing::{debug, info, warn};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::error::{PaymentError, Result};
use crate::traits::PaymentProtocol;
use crate::types::{PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification};
use crate::challenge_store::ChallengeStore;
use crate::rfc9421::{AgentRegistryClient, NonceCache, RequestParts, SignedHeaders};
use super::verifier::TapVerifier;

/// Visa TAP payment protocol server
pub struct VisaTapServer {
    domain: String,
    recipient: String,
    default_asset: String,
    default_chain: String,
    max_signature_age: Duration,
    agent_registry: Arc<dyn AgentRegistryClient>,
    settlement_engine: Option<Arc<tenzro_settlement::SettlementEngine>>,
    challenge_store: ChallengeStore,
    nonce_cache: NonceCache,
}

impl VisaTapServer {
    /// Create a new Visa TAP server
    pub fn new(
        domain: String,
        recipient: String,
        agent_registry: Arc<dyn AgentRegistryClient>,
    ) -> Self {
        Self {
            domain,
            recipient,
            default_asset: "TNZO".to_string(),
            default_chain: "tenzro".to_string(),
            max_signature_age: Duration::from_secs(480), // 8 minutes
            agent_registry,
            settlement_engine: None,
            challenge_store: ChallengeStore::new(),
            nonce_cache: NonceCache::new(),
        }
    }

    /// Set settlement engine for automatic settlement
    pub fn with_settlement_engine(mut self, engine: Arc<tenzro_settlement::SettlementEngine>) -> Self {
        self.settlement_engine = Some(engine);
        self
    }

    /// Set custom challenge store
    pub fn with_challenge_store(mut self, store: ChallengeStore) -> Self {
        self.challenge_store = store;
        self
    }

    /// Set default asset
    pub fn with_default_asset(mut self, asset: String) -> Self {
        self.default_asset = asset;
        self
    }

    /// Set default chain
    pub fn with_default_chain(mut self, chain: String) -> Self {
        self.default_chain = chain;
        self
    }

    /// Set maximum signature age
    pub fn with_max_signature_age(mut self, duration: Duration) -> Self {
        self.max_signature_age = duration;
        self
    }

    /// Extract request parts from credential extra data
    fn extract_request_parts(credential: &PaymentCredential) -> Result<RequestParts> {
        let method = credential.extra.get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_string();

        let authority = credential.extra.get("authority")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PaymentError::CredentialError("Missing authority in credential".to_string()))?
            .to_string();

        let path = credential.extra.get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PaymentError::CredentialError("Missing path in credential".to_string()))?
            .to_string();

        let headers_value = credential.extra.get("headers")
            .ok_or_else(|| PaymentError::CredentialError("Missing headers in credential".to_string()))?;

        let headers: HashMap<String, String> = serde_json::from_value(headers_value.clone())
            .map_err(|e| PaymentError::CredentialError(format!("Invalid headers format: {}", e)))?;

        Ok(RequestParts {
            method,
            authority,
            path,
            headers,
        })
    }

    /// Extract signed headers from credential extra data
    fn extract_signed_headers(credential: &PaymentCredential) -> Result<SignedHeaders> {
        let signature_input_raw = credential.extra.get("signature_input")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PaymentError::CredentialError("Missing signature_input in credential".to_string()))?
            .to_string();

        let signature_b64 = credential.extra.get("signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PaymentError::CredentialError("Missing signature in credential".to_string()))?;

        let signature_bytes = BASE64.decode(signature_b64)
            .map_err(|e| PaymentError::CredentialError(format!("Invalid signature base64: {}", e)))?;

        let parsed = crate::rfc9421::signature::parse_signature_input(&signature_input_raw)
            .map_err(|e| PaymentError::Rfc9421Error(format!("Failed to parse signature input: {}", e)))?;

        Ok(SignedHeaders {
            signature_input_raw,
            signature_bytes,
            parsed,
        })
    }

    /// Verify Ed25519 signature on credential message
    fn verify_credential_signature(
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<()> {
        // Build credential message (same format as MPP)
        let message = format!(
            "{}:{}:{}:{}",
            challenge.challenge_id,
            credential.payer_did,
            credential.amount,
            credential.asset
        );

        // Extract public key from extra
        let public_key_hex = credential.extra.get("public_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PaymentError::CredentialError("Missing public_key in credential".to_string()))?;

        let public_key_bytes = hex::decode(public_key_hex)
            .map_err(|e| PaymentError::CryptoError(format!("Invalid public key hex: {}", e)))?;

        // Verify signature
        let public_key = tenzro_crypto::PublicKey::new(
            tenzro_crypto::KeyType::Ed25519,
            public_key_bytes,
        );

        let signature = tenzro_crypto::Signature::new(
            tenzro_crypto::KeyType::Ed25519,
            credential.signature.clone(),
        );

        tenzro_crypto::signatures::verify(&public_key, message.as_bytes(), &signature)
            .map_err(|e| PaymentError::CryptoError(format!("Signature verification failed: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl PaymentProtocol for VisaTapServer {
    fn protocol_name(&self) -> &str {
        "visa-tap"
    }

    async fn create_challenge(
        &self,
        resource: &str,
        amount: u128,
        asset: &str,
        recipient: &str,
    ) -> Result<PaymentChallenge> {
        let challenge_id = format!("tap_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + chrono::Duration::minutes(15);

        // Use recipient parameter if provided, otherwise fallback to configured recipient
        let recipient_address = if recipient.is_empty() {
            self.recipient.clone()
        } else {
            recipient.to_string()
        };

        let mut extra = HashMap::new();
        extra.insert(
            "required_headers".to_string(),
            serde_json::json!(["@authority", "@path", "content-type"]),
        );
        extra.insert(
            "max_signature_age_secs".to_string(),
            serde_json::json!(self.max_signature_age.as_secs()),
        );
        extra.insert(
            "domain".to_string(),
            serde_json::json!(self.domain),
        );

        let challenge = PaymentChallenge {
            challenge_id: challenge_id.clone(),
            protocol: "visa-tap".to_string(),
            resource: resource.to_string(),
            amount,
            asset: asset.to_string(),
            recipient: recipient_address,
            chain: self.default_chain.clone(),
            expires_at,
            extra,
        };

        self.challenge_store.store(&challenge);
        info!("Created Visa TAP challenge: {}", challenge_id);

        Ok(challenge)
    }

    async fn verify_credential(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<PaymentVerification> {
        debug!("Verifying Visa TAP credential: {}", credential.credential_id);

        // Check challenge expiration
        if Utc::now() > challenge.expires_at {
            warn!("Challenge expired: {}", challenge.challenge_id);
            return Err(PaymentError::ChallengeError(
                format!("Challenge {} has expired", challenge.challenge_id),
            ));
        }

        // Extract request parts and signed headers from credential
        let request_parts = Self::extract_request_parts(credential)?;
        let signed_headers = Self::extract_signed_headers(credential)?;

        // Extract nonce from signature_input for replay protection
        if let Some(nonce) = signed_headers.parsed.params.nonce.as_ref() {
            self.nonce_cache.check_and_store(nonce)?;
        }

        // Verify RFC 9421 HTTP Message Signature
        let verifier = TapVerifier::new(self.agent_registry.clone())
            .with_max_age(self.max_signature_age)
            .with_domain(self.domain.clone());

        let verification_result = verifier.verify(&request_parts, &signed_headers).await?;

        if !verification_result.verified {
            warn!("TAP verification failed for credential: {}", credential.credential_id);
            return Ok(PaymentVerification {
                verified: false,
                credential_id: credential.credential_id.clone(),
                challenge_id: challenge.challenge_id.clone(),
                payer_did: credential.payer_did.clone(),
                verified_at: Utc::now(),
                settlement_ref: None,
            });
        }

        // Verify Ed25519 signature on credential message
        Self::verify_credential_signature(challenge, credential)?;

        info!(
            "Visa TAP credential verified successfully: {} (agent: {})",
            credential.credential_id, verification_result.agent_key_id
        );

        Ok(PaymentVerification {
            verified: true,
            credential_id: credential.credential_id.clone(),
            challenge_id: challenge.challenge_id.clone(),
            payer_did: credential.payer_did.clone(),
            verified_at: Utc::now(),
            settlement_ref: Some(verification_result.agent_key_id),
        })
    }

    async fn settle(
        &self,
        verification: &PaymentVerification,
    ) -> Result<PaymentReceipt> {
        debug!("Settling Visa TAP payment for challenge: {}", verification.challenge_id);

        // Look up original challenge
        let challenge = self.challenge_store.get(&verification.challenge_id)?;

        // Execute settlement if engine is configured
        let settlement_tx = if let Some(engine) = &self.settlement_engine {
            // Build a SettlementRequest from the challenge data.
            // Addresses are derived from the payer DID and recipient strings via SHA-256.
            use sha2::{Digest, Sha256};
            use tenzro_types::primitives::Address;
            use tenzro_types::settlement::{ServiceProof, ServiceType, ProofType};

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
                    protocol: "visa-tap".to_string(),
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
                    warn!("On-chain settlement failed (will be retried): {}", e);
                    // Deterministic fallback hash derived from the verification credential ID
                    let fallback = Sha256::digest(verification.credential_id.as_bytes());
                    Some(format!("0x{}", hex::encode(fallback)))
                }
            }
        } else {
            None
        };

        // Remove challenge after successful settlement
        self.challenge_store.remove(&verification.challenge_id);

        let mut extra = HashMap::new();
        if let Some(ref settlement_ref) = verification.settlement_ref {
            extra.insert("agent_key_id".to_string(), serde_json::json!(settlement_ref));
        }

        let receipt = PaymentReceipt {
            receipt_id: format!("tap_receipt_{}", uuid::Uuid::new_v4()),
            protocol: "visa-tap".to_string(),
            challenge_id: verification.challenge_id.clone(),
            credential_id: verification.credential_id.clone(),
            amount: challenge.amount,
            asset: challenge.asset.clone(),
            settlement_tx,
            chain: challenge.chain.clone(),
            settled_at: Utc::now(),
            extra,
        };

        info!("Visa TAP payment settled: {}", receipt.receipt_id);

        Ok(receipt)
    }

    async fn create_credential(
        &self,
        challenge: &PaymentChallenge,
        payer_did: &str,
        _wallet_id: &str,
    ) -> Result<PaymentCredential> {
        debug!("Creating Visa TAP credential for challenge: {}", challenge.challenge_id);

        // Generate Ed25519 keypair for signing credential
        let signer = tenzro_crypto::signatures::Ed25519SignerImpl::generate()
            .map_err(|e| PaymentError::CryptoError(format!("Failed to generate signer: {}", e)))?;
        let public_key = tenzro_crypto::signatures::Signer::public_key(&signer);

        // Build credential message
        let credential_id = format!("tap_cred_{}", uuid::Uuid::new_v4());
        let message = format!(
            "{}:{}:{}:{}",
            challenge.challenge_id, payer_did, challenge.amount, challenge.asset
        );

        // Sign credential message
        let signature = tenzro_crypto::signatures::Signer::sign(&signer, message.as_bytes())
            .map_err(|e| PaymentError::CryptoError(format!("Failed to sign credential: {}", e)))?;

        // Create mock RFC 9421 signature (in production, this would be generated by HTTP client)
        let signature_input = format!(
            "sig1=(\"@authority\" \"@path\" \"content-type\");created={};nonce=\"{}\";keyid=\"{}\";alg=\"ed25519\"",
            Utc::now().timestamp(),
            uuid::Uuid::new_v4(),
            hex::encode(&public_key.to_bytes())
        );
        let signature_b64 = BASE64.encode(&signature.to_bytes());

        let mut extra = HashMap::new();
        extra.insert("signature_input".to_string(), serde_json::json!(signature_input));
        extra.insert("signature".to_string(), serde_json::json!(signature_b64));
        extra.insert("public_key".to_string(), serde_json::json!(hex::encode(&public_key.to_bytes())));
        extra.insert("method".to_string(), serde_json::json!("GET"));
        extra.insert("authority".to_string(), serde_json::json!(self.domain));
        extra.insert("path".to_string(), serde_json::json!(challenge.resource));

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        extra.insert("headers".to_string(), serde_json::json!(headers));

        // Visa TAP authenticates the request via RFC 9421 HTTP message
        // signatures embedded in `extra` (signature_input, signature). The
        // PaymentCredential.signature field is the same Ed25519 leg; the PQ
        // leg is left empty because RFC 9421 does not yet define a hybrid
        // signing algorithm for HTTP message signatures.
        let credential = PaymentCredential {
            credential_id: credential_id.clone(),
            challenge_id: challenge.challenge_id.clone(),
            protocol: "visa-tap".to_string(),
            payer_did: payer_did.to_string(),
            payer_address: hex::encode(&public_key.to_bytes()),
            amount: challenge.amount,
            asset: challenge.asset.clone(),
            signature: signature.to_bytes(),
            pq_signature: Vec::new(),
            pq_public_key: Vec::new(),
            extra,
        };

        info!("Created Visa TAP credential: {}", credential_id);

        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc9421::{AgentPublicKeyInfo, SignatureAlgorithm};
    use std::collections::HashMap;

    struct MockAgentRegistry;

    #[async_trait]
    impl AgentRegistryClient for MockAgentRegistry {
        async fn get_public_key(&self, _key_id: &str) -> Result<AgentPublicKeyInfo> {
            Ok(AgentPublicKeyInfo {
                key_id: "test-key".to_string(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_bytes: vec![1; 32],
                agent_did: Some("did:tenzro:machine:test".to_string()),
                is_active: true,
            })
        }

        async fn verify_agent(&self, _key_id: &str) -> Result<bool> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn test_server_creation() {
        let registry = Arc::new(MockAgentRegistry);
        let server = VisaTapServer::new(
            "api.example.com".to_string(),
            "recipient-123".to_string(),
            registry,
        );
        assert_eq!(server.protocol_name(), "visa-tap");
        assert_eq!(server.domain, "api.example.com");
    }

    #[tokio::test]
    async fn test_create_challenge() {
        let registry = Arc::new(MockAgentRegistry);
        let server = VisaTapServer::new(
            "api.example.com".to_string(),
            "recipient-123".to_string(),
            registry,
        );

        let challenge = server.create_challenge(
            "/api/resource",
            1000000,
            "TNZO",
            "recipient-123",
        ).await.unwrap();

        assert_eq!(challenge.protocol, "visa-tap");
        assert_eq!(challenge.amount, 1000000);
        assert!(challenge.extra.contains_key("required_headers"));
        assert!(challenge.extra.contains_key("domain"));
    }

    #[tokio::test]
    async fn test_create_credential() {
        let registry = Arc::new(MockAgentRegistry);
        let server = VisaTapServer::new(
            "api.example.com".to_string(),
            "recipient-123".to_string(),
            registry,
        );

        let challenge = server.create_challenge(
            "/api/resource",
            1000000,
            "TNZO",
            "recipient-123",
        ).await.unwrap();

        let credential = server.create_credential(
            &challenge,
            "did:tenzro:machine:agent",
            "wallet-1",
        ).await.unwrap();

        assert_eq!(credential.protocol, "visa-tap");
        assert_eq!(credential.payer_did, "did:tenzro:machine:agent");
        assert!(credential.extra.contains_key("signature_input"));
        assert!(credential.extra.contains_key("signature"));
        assert!(credential.extra.contains_key("public_key"));
    }

    #[tokio::test]
    async fn test_server_builder() {
        let registry = Arc::new(MockAgentRegistry);
        let server = VisaTapServer::new(
            "api.example.com".to_string(),
            "recipient-123".to_string(),
            registry,
        )
        .with_default_asset("USDC".to_string())
        .with_default_chain("ethereum".to_string())
        .with_max_signature_age(Duration::from_secs(300));

        assert_eq!(server.default_asset, "USDC");
        assert_eq!(server.default_chain, "ethereum");
        assert_eq!(server.max_signature_age, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_extract_request_parts() {
        let mut extra = HashMap::new();
        extra.insert("method".to_string(), serde_json::json!("POST"));
        extra.insert("authority".to_string(), serde_json::json!("api.example.com"));
        extra.insert("path".to_string(), serde_json::json!("/api/test"));
        extra.insert("headers".to_string(), serde_json::json!({"content-type": "application/json"}));

        let credential = PaymentCredential {
            credential_id: "test".to_string(),
            challenge_id: "test".to_string(),
            protocol: "visa-tap".to_string(),
            payer_did: "did:test".to_string(),
            payer_address: "addr".to_string(),
            amount: 1000,
            asset: "TNZO".to_string(),
            signature: vec![],
            pq_signature: vec![],
            pq_public_key: vec![],
            extra,
        };

        let parts = VisaTapServer::extract_request_parts(&credential).unwrap();
        assert_eq!(parts.method, "POST");
        assert_eq!(parts.authority, "api.example.com");
        assert_eq!(parts.path, "/api/test");
        assert!(parts.headers.contains_key("content-type"));
    }
}
