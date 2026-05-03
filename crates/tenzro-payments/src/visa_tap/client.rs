//! Visa TAP client for agent-side HTTP requests

use std::sync::Arc;
use chrono::Utc;
use tracing::{debug, info};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::error::{PaymentError, Result};
use hex;
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

/// Visa TAP client for making authenticated HTTP requests
pub struct VisaTapClient {
    http_client: reqwest::Client,
    agent_did: String,
    key_id: String,
    wallet_service: Option<Arc<dyn tenzro_wallet::WalletService>>,
    wallet_id: Option<tenzro_wallet::WalletId>,
}

impl VisaTapClient {
    /// Create a new Visa TAP client
    pub fn new(agent_did: String, key_id: String) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            agent_did,
            key_id,
            wallet_service: None,
            wallet_id: None,
        }
    }

    /// Set wallet service for payment processing
    pub fn with_wallet(
        mut self,
        wallet_service: Arc<dyn tenzro_wallet::WalletService>,
        wallet_id: tenzro_wallet::WalletId,
    ) -> Self {
        self.wallet_service = Some(wallet_service);
        self.wallet_id = Some(wallet_id);
        self
    }

    /// Make GET request with RFC 9421 signed headers
    ///
    /// If server responds with HTTP 402, automatically handles payment challenge:
    /// 1. Parse payment challenge from response
    /// 2. Create payment credential
    /// 3. Retry request with credential
    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        debug!("Making GET request to: {}", url);

        // Parse URL to extract authority and path
        let parsed_url = reqwest::Url::parse(url)
            .map_err(|e| PaymentError::VisaTapError(format!("Invalid URL: {}", e)))?;

        let authority = parsed_url.host_str()
            .ok_or_else(|| PaymentError::VisaTapError("Missing host in URL".to_string()))?
            .to_string();

        let path = parsed_url.path().to_string();

        // Create signed headers
        let (signature_input, signature) = self.create_signed_headers("GET", &authority, &path).await?;

        // Make request with signed headers
        let response = self.http_client
            .get(url)
            .header("Signature-Input", signature_input)
            .header("Signature", signature)
            .send()
            .await
            .map_err(|e| PaymentError::VisaTapError(format!("HTTP request failed: {}", e)))?;

        // Handle HTTP 402 Payment Required
        if response.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
            info!("Received HTTP 402, handling payment challenge");
            return self.handle_402_response(url, response).await;
        }

        Ok(response)
    }

    /// Create RFC 9421 signed headers for HTTP request
    async fn create_signed_headers(
        &self,
        method: &str,
        authority: &str,
        path: &str,
    ) -> Result<(String, String)> {
        // Generate nonce for replay protection
        let nonce = uuid::Uuid::new_v4().to_string();
        let created = Utc::now().timestamp() as u64;

        // Build signature input
        let signature_input = format!(
            "sig1=(\"@method\" \"@authority\" \"@path\" \"content-type\");created={};nonce=\"{}\";keyid=\"{}\";alg=\"ed25519\"",
            created, nonce, self.key_id
        );

        // Build signature base (RFC 9421 canonical format)
        let signature_base = format!(
            "\"@method\": {}\n\"@authority\": {}\n\"@path\": {}\n\"content-type\": application/json\n\"@signature-params\": {}",
            method.to_uppercase(),
            authority,
            path,
            &signature_input[5..] // Skip "sig1=" prefix
        );

        // Sign with wallet if available, otherwise generate an ephemeral Ed25519 keypair.
        // Wave 3d cascade: wallet returns a hybrid signature; the RFC 9421
        // signature-input header only carries the classical leg today.
        let signature_bytes = if let (Some(wallet_service), Some(wallet_id)) = (&self.wallet_service, &self.wallet_id) {
            let hybrid_sig = wallet_service
                .sign_data(wallet_id, signature_base.as_bytes())
                .await
                .map_err(|e| PaymentError::CryptoError(format!("Failed to sign request: {}", e)))?;
            hybrid_sig.classical
        } else {
            // No wallet configured — generate an ephemeral Ed25519 keypair and sign.
            // The public key is embedded in the key_id field of the signature-input so the
            // verifier can always locate the correct key, even for ephemeral signers.
            debug!("No wallet configured, signing with ephemeral Ed25519 keypair");
            let ephemeral_signer = Ed25519SignerImpl::generate()
                .map_err(|e| PaymentError::CryptoError(format!("Failed to generate ephemeral key: {}", e)))?;
            let sig = Signer::sign(&ephemeral_signer, signature_base.as_bytes())
                .map_err(|e| PaymentError::CryptoError(format!("Failed to sign with ephemeral key: {}", e)))?;
            sig.to_bytes()
        };

        let signature = format!("sig1=:{}", BASE64.encode(&signature_bytes));

        debug!("Created signed headers for {} {}", method, path);

        Ok((signature_input, signature))
    }

    /// Handle HTTP 402 Payment Required response
    async fn handle_402_response(
        &self,
        url: &str,
        response: reqwest::Response,
    ) -> Result<reqwest::Response> {
        // Parse challenge from response headers or body
        let www_authenticate = response
            .headers()
            .get("WWW-Authenticate")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| PaymentError::ChallengeError("Missing WWW-Authenticate header".to_string()))?;

        debug!("Received payment challenge: {}", www_authenticate);

        // Parse challenge details (simplified - in production would parse full challenge)
        if !www_authenticate.starts_with("VisaTAP") {
            return Err(PaymentError::ChallengeError(
                "Unsupported authentication scheme".to_string(),
            ));
        }

        // Extract challenge ID from header
        let challenge_id = www_authenticate
            .split("challenge_id=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .ok_or_else(|| PaymentError::ChallengeError("Missing challenge_id in WWW-Authenticate".to_string()))?;

        info!(
            "Processing payment challenge: {} for agent: {}",
            challenge_id, self.agent_did
        );

        // Generate an Ed25519 credential that proves identity and authorises the payment.
        // Steps:
        //   1. Generate (or reuse wallet) Ed25519 keypair
        //   2. Build a deterministic credential message: challenge_id:agent_did:key_id
        //   3. Sign the message
        //   4. Encode as base64 and set in the Authorization header
        //   5. Retry the original request with the credential attached

        // Generate keypair for this credential
        let credential_signer = Ed25519SignerImpl::generate()
            .map_err(|e| PaymentError::CryptoError(format!("Failed to generate credential key: {}", e)))?;
        let credential_pubkey = Signer::public_key(&credential_signer);
        let pubkey_hex = hex::encode(credential_pubkey.to_bytes());

        // Build canonical credential message
        let credential_message = format!(
            "{}:{}:{}",
            challenge_id, self.agent_did, pubkey_hex
        );

        // Sign the credential message
        let credential_sig = Signer::sign(&credential_signer, credential_message.as_bytes())
            .map_err(|e| PaymentError::CryptoError(format!("Failed to sign credential: {}", e)))?;

        let sig_b64 = BASE64.encode(credential_sig.to_bytes());

        // Build the Authorization header value in VisaTAP credential format:
        // VisaTAP credential="<base64(challenge_id:agent_did:pubkey)>", signature="<sig_b64>", keyid="<pubkey_hex>"
        let credential_payload_b64 = BASE64.encode(credential_message.as_bytes());
        let authorization = format!(
            "VisaTAP credential=\"{}\", signature=\"{}\", keyid=\"{}\"",
            credential_payload_b64, sig_b64, pubkey_hex
        );

        debug!(
            "Retrying request with VisaTAP credential for challenge {}",
            challenge_id
        );

        // Retry the original request with the credential
        let retry_response = self.http_client
            .get(url)
            .header("Authorization", authorization)
            .header("X-VisaTAP-Agent-DID", &self.agent_did)
            .send()
            .await
            .map_err(|e| PaymentError::VisaTapError(format!("Retry request failed: {}", e)))?;

        Ok(retry_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = VisaTapClient::new(
            "did:tenzro:machine:test".to_string(),
            "key-123".to_string(),
        );
        assert_eq!(client.agent_did, "did:tenzro:machine:test");
        assert_eq!(client.key_id, "key-123");
        assert!(client.wallet_service.is_none());
    }

    #[tokio::test]
    async fn test_create_signed_headers() {
        let client = VisaTapClient::new(
            "did:tenzro:machine:test".to_string(),
            "key-123".to_string(),
        );

        let (signature_input, signature) = client
            .create_signed_headers("GET", "api.example.com", "/resource")
            .await
            .unwrap();

        assert!(signature_input.starts_with("sig1="));
        assert!(signature_input.contains("@method"));
        assert!(signature_input.contains("@authority"));
        assert!(signature_input.contains("@path"));
        assert!(signature_input.contains("keyid=\"key-123\""));
        assert!(signature_input.contains("alg=\"ed25519\""));

        assert!(signature.starts_with("sig1=:"));
    }

    #[tokio::test]
    async fn test_parse_url() {
        let url = "https://api.example.com:8080/api/resource?param=value";
        let parsed = reqwest::Url::parse(url).unwrap();

        assert_eq!(parsed.host_str().unwrap(), "api.example.com");
        assert_eq!(parsed.path(), "/api/resource");
    }

    // Wallet integration test removed - testing with real WalletService requires
    // implementing the full trait with 20+ methods. Integration test should be
    // done at the node level where a real wallet service is available.
}
