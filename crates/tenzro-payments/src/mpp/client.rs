//! MPP client for automatic HTTP 402 payment handling
//!
//! Wraps reqwest to automatically handle 402 responses by creating
//! and submitting payment credentials.

use crate::error::{PaymentError, Result};
use crate::types::{PaymentChallenge, PaymentCredential};
use std::sync::Arc;
use tenzro_wallet::WalletService;
use tracing::{debug, info};

/// MPP-aware HTTP client that handles 402 Payment Required responses
pub struct MppClient {
    http_client: reqwest::Client,
    payer_did: String,
    wallet_id: String,
    /// Optional wallet service for signing credentials
    wallet_service: Option<Arc<dyn WalletService>>,
}

impl MppClient {
    /// Creates a new MPP client
    pub fn new(payer_did: impl Into<String>, wallet_id: impl Into<String>) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            payer_did: payer_did.into(),
            wallet_id: wallet_id.into(),
            wallet_service: None,
        }
    }

    /// Sets the wallet service for signing payment credentials
    pub fn with_wallet_service(mut self, wallet_service: Arc<dyn WalletService>) -> Self {
        self.wallet_service = Some(wallet_service);
        self
    }

    /// Makes an HTTP request, automatically handling 402 responses
    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        info!("Making HTTP GET request to {}", url);

        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(e.to_string()))?;

        // Check for HTTP 402 Payment Required
        if response.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
            debug!("Received 402 from {}, handling payment", url);

            // 1. Parse the payment challenge from the response body
            let body = response.text().await
                .map_err(|e| PaymentError::NetworkError(format!("Failed to read 402 response: {}", e)))?;

            let challenge = Self::parse_challenge(&body)?;

            info!(
                "Parsed payment challenge: amount={} asset={} expires={:?}",
                challenge.amount, challenge.asset, challenge.expires_at
            );

            // 2. Create a payment credential
            let credential = self.create_credential(&challenge).await?;

            // 3. Retry the request with the payment credential
            let retry_response = self
                .http_client
                .get(url)
                .header("Payment-Credential", serde_json::to_string(&credential)?)
                .send()
                .await
                .map_err(|e| PaymentError::NetworkError(e.to_string()))?;

            // Check if the retry succeeded
            if retry_response.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
                return Err(PaymentError::ChallengeError(
                    "Payment credential rejected by server".to_string(),
                ));
            }

            debug!("Payment credential accepted, request succeeded");
            return Ok(retry_response);
        }

        Ok(response)
    }

    /// Creates a payment credential for a challenge
    async fn create_credential(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential> {
        debug!("Creating payment credential for challenge {}", challenge.challenge_id);

        // Get the wallet service
        let wallet_service = self.wallet_service.as_ref()
            .ok_or_else(|| PaymentError::CredentialError(
                "No wallet service configured for signing credentials".to_string()
            ))?;

        // Get the wallet
        let wallet_id = tenzro_wallet::WalletId::from_string(self.wallet_id.clone());
        let wallet = wallet_service.get_wallet(&wallet_id).await
            .map_err(|e| PaymentError::CredentialError(format!("Failed to get wallet: {}", e)))?
            .ok_or_else(|| PaymentError::CredentialError(format!("Wallet {} not found", self.wallet_id)))?;

        let payer_address = wallet.address;
        let public_key = wallet.public_key.clone();
        let pq_public_key = wallet.pq_verifying_key.clone();

        // Construct the message to sign
        let mut message = Vec::new();
        message.extend_from_slice(challenge.challenge_id.as_bytes());
        message.extend_from_slice(self.payer_did.as_bytes());
        message.extend_from_slice(&challenge.amount.to_le_bytes());
        message.extend_from_slice(challenge.asset.as_bytes());

        // Sign the message using the wallet — produces a hybrid (classical +
        // ML-DSA-65) signature. Wave 3d: surface BOTH legs into the credential.
        let hybrid_sig = wallet_service.sign_data(&wallet_id, &message).await
            .map_err(|e| PaymentError::CredentialError(format!("Failed to sign credential: {}", e)))?;
        let signature_bytes = hybrid_sig.classical;
        // `HybridSignatureBytes.pq` is mandatory `Vec<u8>` (not Option).
        let pq_signature_bytes = hybrid_sig.pq;
        if pq_signature_bytes.is_empty() {
            return Err(PaymentError::CredentialError(
                "Wallet hybrid signer produced an empty ML-DSA-65 leg for MPP credential".to_string(),
            ));
        }

        // Get the public key for inclusion in the credential
        let public_key_hex = hex::encode(public_key.as_bytes());

        // Create the credential
        let mut credential = PaymentCredential {
            credential_id: uuid::Uuid::new_v4().to_string(),
            challenge_id: challenge.challenge_id.clone(),
            protocol: "mpp".to_string(),
            payer_did: self.payer_did.clone(),
            payer_address: payer_address.to_string(),
            amount: challenge.amount,
            asset: challenge.asset.clone(),
            signature: signature_bytes,
            pq_signature: pq_signature_bytes,
            pq_public_key,
            extra: std::collections::HashMap::new(),
        };

        // Add the public key to the extra metadata
        credential.extra.insert("public_key".to_string(), serde_json::json!(public_key_hex));

        debug!("Payment credential created: {}", credential.credential_id);

        Ok(credential)
    }

    /// Parses an MPP challenge from a 402 response body
    pub fn parse_challenge(body: &str) -> Result<PaymentChallenge> {
        serde_json::from_str(body)
            .map_err(|e| PaymentError::ChallengeError(format!("failed to parse challenge: {}", e)))
    }

    /// Returns the payer DID
    pub fn payer_did(&self) -> &str {
        &self.payer_did
    }
}
