//! x402 server-side payment protocol implementation

use crate::challenge_store::ChallengeStore;
use crate::error::{PaymentError, Result};
use crate::traits::PaymentProtocol;
use crate::types::{PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification};
use crate::x402::receipt::X402SettlementReceiptBody;
use crate::x402::scheme::{build_credential_preimage, SchemeRegistry};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_crypto::composite::{HybridSigner, InMemoryHybridSigner};
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_settlement::engine::SettlementEngine;
use tenzro_types::settlement::{ProofType, ServiceProof, ServiceType};
use tenzro_types::Address;
use tracing::{debug, info};

/// x402 server-side payment handler.
///
/// Credentials are verified via a [`SchemeRegistry`] that maps the scheme id
/// from `challenge.extra["scheme"]` (e.g. `"exact-eip3009"`, `"permit2"`,
/// `"erc7710"`, or the wave-1 internal `"tenzro-hybrid"` default) to a
/// [`crate::x402::scheme::SchemeBackend`]. Use
/// [`X402PaymentServer::with_scheme_registry`] to inject custom backends.
pub struct X402PaymentServer {
    /// Recipient address
    _recipient: String,
    /// Supported chains
    supported_chains: Vec<String>,
    /// Default asset
    default_asset: String,
    /// Settlement engine for executing payments
    settlement_engine: Option<Arc<SettlementEngine>>,
    /// Challenge store for looking up challenges during settlement
    challenge_store: ChallengeStore,
    /// Registry of credential-verification backends, dispatched per
    /// `challenge.extra["scheme"]`.
    scheme_registry: SchemeRegistry,
}

impl X402PaymentServer {
    /// Creates a new x402 payment server with the default scheme registry
    /// ([`SchemeRegistry::with_defaults`]).
    pub fn new(recipient: impl Into<String>, supported_chains: Vec<String>) -> Self {
        Self {
            _recipient: recipient.into(),
            supported_chains,
            default_asset: "USDC".to_string(),
            settlement_engine: None,
            challenge_store: ChallengeStore::new(),
            scheme_registry: SchemeRegistry::with_defaults(),
        }
    }

    /// Sets the settlement engine
    pub fn with_settlement_engine(mut self, engine: Arc<SettlementEngine>) -> Self {
        self.settlement_engine = Some(engine);
        self
    }

    /// Sets the default asset
    pub fn with_default_asset(mut self, asset: impl Into<String>) -> Self {
        self.default_asset = asset.into();
        self
    }

    /// Sets a shared challenge store
    pub fn with_challenge_store(mut self, store: ChallengeStore) -> Self {
        self.challenge_store = store;
        self
    }

    /// Replace the scheme registry. Use this to register additional backends
    /// or to swap the default verifiers (e.g. point a custom facilitator at
    /// the EIP-3009 backend).
    pub fn with_scheme_registry(mut self, registry: SchemeRegistry) -> Self {
        self.scheme_registry = registry;
        self
    }

    /// Returns a reference to the challenge store
    pub fn challenge_store(&self) -> &ChallengeStore {
        &self.challenge_store
    }

    /// Returns a reference to the configured scheme registry.
    pub fn scheme_registry(&self) -> &SchemeRegistry {
        &self.scheme_registry
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
impl PaymentProtocol for X402PaymentServer {
    fn protocol_name(&self) -> &str {
        "x402"
    }

    async fn create_challenge(
        &self,
        resource: &str,
        amount: u128,
        asset: &str,
        recipient: &str,
    ) -> Result<PaymentChallenge> {
        info!("Creating x402 challenge for resource {}", resource);

        let challenge = PaymentChallenge {
            challenge_id: uuid::Uuid::new_v4().to_string(),
            protocol: "x402".to_string(),
            resource: resource.to_string(),
            amount,
            asset: asset.to_string(),
            recipient: recipient.to_string(),
            chain: self
                .supported_chains
                .first()
                .cloned()
                .unwrap_or_else(|| "tenzro".to_string()),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            extra: {
                let mut extra = HashMap::new();
                extra.insert(
                    "scheme".to_string(),
                    serde_json::json!(crate::x402::DEFAULT_SCHEME),
                );
                extra.insert(
                    "network".to_string(),
                    serde_json::json!(format!("eip155:{}", 1337)),
                );
                extra
            },
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
            "Verifying x402 credential {} for challenge {}",
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

        // 4. Verify chain is supported
        if !self.supported_chains.contains(&challenge.chain) && !self.supported_chains.is_empty() {
            return Err(PaymentError::VerificationFailed(format!(
                "Unsupported chain: {}",
                challenge.chain
            )));
        }

        // 5. Dispatch credential verification to the scheme backend
        // declared by the challenge (`challenge.extra["scheme"]`). The
        // wave-1 default is `tenzro-hybrid` (Ed25519 + ML-DSA-65). Other
        // schemes (`exact-eip3009`, `permit2`, `erc7710`) are honored via
        // the same registry — see `x402::scheme`.
        let backend = self.scheme_registry.lookup_for_challenge(challenge)?;
        backend.verify(challenge, credential).await?;
        debug!(
            "x402 credential {} verified under scheme '{}'",
            credential.credential_id,
            backend.name()
        );

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
        info!("Settling x402 payment for {}", verification.credential_id);

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
            debug!(
                "Executing x402 settlement via engine for amount={}",
                challenge.amount
            );

            let amount_u64 = u64::try_from(challenge.amount).map_err(|_| {
                PaymentError::SettlementError("Settlement amount exceeds u64 range".to_string())
            })?;

            let provider_addr = parse_address(&challenge.recipient);
            let customer_addr = parse_address(&verification.payer_did);

            let request = tenzro_types::settlement::SettlementRequest::new(
                provider_addr,
                customer_addr,
                ServiceType::HttpPayment {
                    protocol: "x402".to_string(),
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

            self.challenge_store.remove(&challenge.challenge_id);

            // Tenzro x402 extension: emit a settlement-AIR commitment +
            // cross-VM `network` field as the `X-PAYMENT-RESPONSE` body.
            // We bind it by stashing the JSON receipt body in `extra` under
            // the key `x_payment_response`. Transport layers
            // (axum middleware, CLI, MCP) base64-encode this string and
            // emit it as the `X-PAYMENT-RESPONSE` header.
            let scheme_id = challenge
                .extra
                .get("scheme")
                .and_then(|v| v.as_str())
                .unwrap_or(crate::x402::DEFAULT_SCHEME)
                .to_string();
            let tx_hash_hex = hex::encode(receipt.transaction_hash.as_bytes());
            let mut extra: HashMap<String, serde_json::Value> = HashMap::new();
            // Receipt body construction can fail only on malformed network
            // string — in that case skip the extension and return the bare
            // receipt rather than failing settlement.
            if let Ok(body) = X402SettlementReceiptBody::finalized(
                &scheme_id,
                &challenge.chain,
                &challenge.challenge_id,
                &verification.credential_id,
                &challenge.resource,
                &challenge.asset,
                &challenge.amount.to_string(),
                &verification.payer_did,
                &challenge.recipient,
                &tx_hash_hex,
            ) {
                if let Ok(body_value) = serde_json::to_value(&body) {
                    extra.insert("x_payment_response".to_string(), body_value);
                }
                if let Some(ref c) = body.tenzro_commitment {
                    extra.insert(
                        "tenzro_commitment".to_string(),
                        serde_json::Value::String(c.clone()),
                    );
                }
                if let Some(ref vm) = body.tenzro_vm {
                    extra.insert(
                        "tenzro_vm".to_string(),
                        serde_json::Value::String(vm.clone()),
                    );
                }
            }

            return Ok(PaymentReceipt {
                receipt_id: receipt.receipt_id,
                protocol: "x402".to_string(),
                challenge_id: challenge.challenge_id,
                credential_id: verification.credential_id.clone(),
                amount: receipt.amount as u128,
                asset: challenge.asset,
                settlement_tx: Some(tx_hash_hex),
                chain: challenge.chain,
                settled_at: Utc::now(),
                principal_chain: receipt.principal_chain,
                extra,
            });
        }

        // No settlement engine — generate receipt with real amount from challenge
        info!(
            "No settlement engine configured, generating x402 receipt for amount={}",
            challenge.amount
        );
        self.challenge_store.remove(&challenge.challenge_id);

        Ok(PaymentReceipt {
            receipt_id: uuid::Uuid::new_v4().to_string(),
            protocol: "x402".to_string(),
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
        _wallet_id: &str,
    ) -> Result<PaymentCredential> {
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

        // Build the canonical signing preimage for a Tenzro-hybrid x402
        // credential — same layout the verifier reconstructs.
        let preimage_credential = PaymentCredential {
            credential_id: String::new(),
            challenge_id: challenge.challenge_id.clone(),
            protocol: "x402".to_string(),
            payer_did: payer_did.to_string(),
            payer_address: String::new(),
            amount: challenge.amount,
            asset: challenge.asset.clone(),
            signature: vec![],
            pq_signature: vec![],
            pq_public_key: vec![],
            extra: HashMap::new(),
        };
        let message = build_credential_preimage(&preimage_credential);

        let hybrid = InMemoryHybridSigner::new(Box::new(classical), pq);
        let composite = hybrid.sign(&message).map_err(|e| {
            PaymentError::CredentialError(format!("Failed to hybrid-sign credential: {}", e))
        })?;
        if composite.pq.is_empty() {
            return Err(PaymentError::CredentialError(
                "Hybrid signer produced no PQ leg for x402 credential".to_string(),
            ));
        }
        let pq_signature = composite.pq.clone();

        let mut extra = HashMap::new();
        extra.insert(
            "public_key".to_string(),
            serde_json::json!(hex::encode(&public_key_bytes)),
        );

        Ok(PaymentCredential {
            credential_id: uuid::Uuid::new_v4().to_string(),
            challenge_id: challenge.challenge_id.clone(),
            protocol: "x402".to_string(),
            payer_did: payer_did.to_string(),
            payer_address: hex::encode(&public_key_bytes),
            amount: challenge.amount,
            asset: challenge.asset.clone(),
            signature: composite.classical,
            pq_signature,
            pq_public_key,
            extra,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_x402_challenge_stored_on_creation() {
        let server = X402PaymentServer::new("0xrecipient", vec!["tenzro".to_string()]);
        let challenge = server
            .create_challenge("/api/resource", 2000, "USDC", "0xrecipient")
            .await
            .unwrap();

        let stored = server.challenge_store().get(&challenge.challenge_id);
        assert!(stored.is_ok());
        assert_eq!(stored.unwrap().amount, 2000);
    }

    #[tokio::test]
    async fn test_x402_challenge_pins_default_scheme() {
        let server = X402PaymentServer::new("0xrecipient", vec!["tenzro".to_string()]);
        let challenge = server
            .create_challenge("/api/resource", 1000, "USDC", "0xrecipient")
            .await
            .unwrap();

        assert_eq!(
            challenge.extra.get("scheme").unwrap(),
            crate::x402::DEFAULT_SCHEME
        );
        assert!(challenge.extra.contains_key("network"));
    }

    #[tokio::test]
    async fn test_x402_settle_uses_stored_amount() {
        let server = X402PaymentServer::new("0xrecipient", vec!["tenzro".to_string()]);
        let challenge = server
            .create_challenge("/api/resource", 7500, "USDC", "0xrecipient")
            .await
            .unwrap();

        let verification = PaymentVerification {
            verified: true,
            credential_id: "cred-x".to_string(),
            challenge_id: challenge.challenge_id.clone(),
            payer_did: "did:tenzro:human:bob".to_string(),
            verified_at: Utc::now(),
            settlement_ref: None,
        };

        let receipt = server.settle(&verification).await.unwrap();
        assert_eq!(receipt.amount, 7500);
        assert_eq!(receipt.protocol, "x402");
    }

    #[tokio::test]
    async fn test_x402_settle_fails_for_unknown_challenge() {
        let server = X402PaymentServer::new("0xrecipient", vec!["tenzro".to_string()]);

        let verification = PaymentVerification {
            verified: true,
            credential_id: "cred-x".to_string(),
            challenge_id: "nonexistent".to_string(),
            payer_did: "payer".to_string(),
            verified_at: Utc::now(),
            settlement_ref: None,
        };

        assert!(server.settle(&verification).await.is_err());
    }

    #[tokio::test]
    async fn test_x402_verify_credential_round_trips_via_registry() {
        // Default registry routes the default scheme ("tenzro-hybrid") to
        // TenzroHybridBackend, so a credential minted by `create_credential`
        // must verify against a challenge minted by `create_challenge` with
        // no extra wiring.
        let server = X402PaymentServer::new("0xrecipient", vec!["tenzro".to_string()]);
        let challenge = server
            .create_challenge("/api/resource", 1234, "USDC", "0xrecipient")
            .await
            .unwrap();
        let credential = server
            .create_credential(&challenge, "did:tenzro:human:alice", "wallet-0")
            .await
            .unwrap();

        let verification = server
            .verify_credential(&challenge, &credential)
            .await
            .unwrap();
        assert!(verification.verified);
    }

    #[tokio::test]
    async fn test_x402_verify_dispatches_to_registered_scheme() {
        use crate::x402::scheme::{SchemeBackend, SchemeRegistry};
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct Counting {
            calls: AtomicUsize,
        }
        #[async_trait]
        impl SchemeBackend for Counting {
            fn name(&self) -> &'static str {
                "test-only"
            }
            async fn verify(
                &self,
                _challenge: &PaymentChallenge,
                _credential: &PaymentCredential,
            ) -> Result<()> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let counter = Arc::new(Counting {
            calls: AtomicUsize::new(0),
        });

        let mut registry = SchemeRegistry::with_defaults();
        registry.register("test-only", counter.clone());

        let server = X402PaymentServer::new("0xrecipient", vec!["tenzro".to_string()])
            .with_scheme_registry(registry);

        // Mint a challenge then override its scheme to point at the stub.
        let mut challenge = server
            .create_challenge("/api/r", 100, "USDC", "0xrecipient")
            .await
            .unwrap();
        challenge
            .extra
            .insert("scheme".to_string(), serde_json::json!("test-only"));

        // Re-store the mutated challenge so settle/verify can find it
        // (verify_credential itself doesn't read from the store, but this
        // keeps the test honest about end-to-end flow).
        server.challenge_store().store(&challenge);

        let credential = PaymentCredential {
            credential_id: "cred-stub".to_string(),
            challenge_id: challenge.challenge_id.clone(),
            protocol: "x402".to_string(),
            payer_did: "did:tenzro:human:alice".to_string(),
            payer_address: "0xpayer".to_string(),
            amount: 100,
            asset: "USDC".to_string(),
            signature: vec![],
            pq_signature: vec![],
            pq_public_key: vec![],
            extra: HashMap::new(),
        };

        let v = server
            .verify_credential(&challenge, &credential)
            .await
            .unwrap();
        assert!(v.verified);
        assert_eq!(counter.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_x402_verify_unknown_scheme_fails() {
        let server = X402PaymentServer::new("0xrecipient", vec!["tenzro".to_string()]);
        let mut challenge = server
            .create_challenge("/api/r", 100, "USDC", "0xrecipient")
            .await
            .unwrap();
        challenge
            .extra
            .insert("scheme".to_string(), serde_json::json!("definitely-not-real"));

        let credential = PaymentCredential {
            credential_id: "cred".to_string(),
            challenge_id: challenge.challenge_id.clone(),
            protocol: "x402".to_string(),
            payer_did: "did:tenzro:human:x".to_string(),
            payer_address: "0xpayer".to_string(),
            amount: 100,
            asset: "USDC".to_string(),
            signature: vec![],
            pq_signature: vec![],
            pq_public_key: vec![],
            extra: HashMap::new(),
        };

        let err = server
            .verify_credential(&challenge, &credential)
            .await
            .unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }
}
