//! Mastercard Agent Pay client implementation
//!
//! Client-side functionality for agents to make purchases using Agent Pay protocol.
//! All outbound HTTP requests are signed with HMAC-SHA256 using the client's signing
//! key, producing an `Authorization` header that the server can verify for authenticity
//! and integrity.

use crate::error::Result;
use crate::mastercard::types::{KyaVerification, PurchaseIntent};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{debug, info};

/// HMAC-SHA256 implementation per RFC 2104
///
/// Computes `HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))`
/// where `K' = H(K)` if `|K| > block_size`, else `K` padded with zeros.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64; // SHA-256 block size
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    // Step 1: If key > block_size, hash it; otherwise zero-pad
    let mut k_prime = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = Sha256::digest(key);
        k_prime[..32].copy_from_slice(&hash);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    // Step 2: Inner hash: H((K' XOR ipad) || message)
    let mut inner_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key[i] = k_prime[i] ^ IPAD;
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&inner_key);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    // Step 3: Outer hash: H((K' XOR opad) || inner_hash)
    let mut outer_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_key[i] = k_prime[i] ^ OPAD;
    }

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&outer_key);
    outer_hasher.update(&inner_hash);
    let result = outer_hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Mastercard Agent Pay client for making authenticated purchases
pub struct MastercardAgentPayClient {
    /// HTTP client
    http_client: Client,
    /// Agent DID
    agent_did: String,
    /// Key ID for signing requests
    key_id: String,
    /// HMAC-SHA256 signing key for request authentication
    signing_key: Vec<u8>,
    /// Optional wallet service for payment credentials
    wallet_service: Option<Arc<dyn tenzro_wallet::WalletService>>,
    /// Optional wallet ID
    wallet_id: Option<tenzro_wallet::WalletId>,
    /// Optional cached KYA verification
    kya_verification: Option<KyaVerification>,
}

impl MastercardAgentPayClient {
    /// Create a new Mastercard Agent Pay client
    ///
    /// # Arguments
    ///
    /// * `agent_did` - The agent DID making requests
    /// * `key_id` - Key identifier for signing requests
    pub fn new(agent_did: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self {
            http_client: Client::new(),
            agent_did: agent_did.into(),
            key_id: key_id.into(),
            signing_key: Vec::new(),
            wallet_service: None,
            wallet_id: None,
            kya_verification: None,
        }
    }

    /// Set the HMAC-SHA256 signing key used to authenticate outbound requests.
    ///
    /// When a signing key is configured, every request produced by this client
    /// carries an `Authorization` header of the form:
    ///
    /// ```text
    /// HMAC-SHA256 Credential=<key_id>,Signature=<hex-encoded HMAC>
    /// ```
    ///
    /// The HMAC is computed over the request body (empty string for GET requests).
    pub fn with_signing_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.signing_key = key.into();
        self
    }

    /// Set the wallet service
    pub fn with_wallet(
        mut self,
        wallet_service: Arc<dyn tenzro_wallet::WalletService>,
        wallet_id: tenzro_wallet::WalletId,
    ) -> Self {
        self.wallet_service = Some(wallet_service);
        self.wallet_id = Some(wallet_id);
        self
    }

    /// Set cached KYA verification
    pub fn with_kya(mut self, kya_verification: KyaVerification) -> Self {
        self.kya_verification = Some(kya_verification);
        self
    }

    /// Compute the HMAC-SHA256 signature for the given body bytes and return the
    /// formatted `Authorization` header value.
    ///
    /// Returns `None` if no signing key has been configured (zero-length key).
    fn compute_authorization_header(&self, body: &[u8]) -> Option<String> {
        if self.signing_key.is_empty() {
            return None;
        }

        let mac = hmac_sha256(&self.signing_key, body);
        let signature_hex = hex::encode(mac);

        Some(format!(
            "HMAC-SHA256 Credential={},Signature={}",
            self.key_id, signature_hex
        ))
    }

    /// Make a signed GET request
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to request
    ///
    /// # Returns
    ///
    /// The HTTP response. If the server returns HTTP 402, the client should
    /// call `handle_payment_required` to process the payment challenge.
    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        info!("Making signed GET request to {}", url);

        let mut request = self.http_client.get(url);

        // Sign the request with HMAC-SHA256 over empty body
        if let Some(auth_header) = self.compute_authorization_header(b"") {
            request = request.header("Authorization", auth_header);
        }

        let response = request.send().await?;

        debug!("Response status: {}", response.status());

        Ok(response)
    }

    /// Make a signed POST request with purchase intent
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to request
    /// * `intent` - The purchase intent describing what is being purchased
    ///
    /// # Returns
    ///
    /// The HTTP response
    pub async fn purchase(&self, url: &str, intent: PurchaseIntent) -> Result<reqwest::Response> {
        info!(
            "Making signed purchase request to {} (intent: {})",
            url, intent.intent_id
        );

        // Serialize purchase intent to JSON
        let body = serde_json::to_string(&intent)?;

        let mut request = self
            .http_client
            .post(url)
            .header("Content-Type", "application/json");

        // Sign the request with HMAC-SHA256 over the JSON body
        if let Some(auth_header) = self.compute_authorization_header(body.as_bytes()) {
            request = request.header("Authorization", auth_header);
        }

        let response = request.body(body).send().await?;

        debug!("Response status: {}", response.status());

        Ok(response)
    }

    /// Get the agent DID
    pub fn agent_did(&self) -> &str {
        &self.agent_did
    }

    /// Get the key ID
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the cached KYA verification if available
    pub fn kya_verification(&self) -> Option<&KyaVerification> {
        self.kya_verification.as_ref()
    }

    /// Check whether a signing key has been configured
    pub fn has_signing_key(&self) -> bool {
        !self.signing_key.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = MastercardAgentPayClient::new(
            "did:tenzro:machine:test_agent",
            "key-1",
        );

        assert_eq!(client.agent_did(), "did:tenzro:machine:test_agent");
        assert_eq!(client.key_id(), "key-1");
        assert!(client.kya_verification().is_none());
        assert!(!client.has_signing_key());
    }

    #[test]
    fn test_client_with_signing_key() {
        let client = MastercardAgentPayClient::new(
            "did:tenzro:machine:test_agent",
            "key-1",
        )
        .with_signing_key(b"my-secret-api-key".to_vec());

        assert!(client.has_signing_key());
    }

    #[test]
    fn test_with_kya() {
        use crate::mastercard::types::{KyaLevel, KyaVerification};
        use chrono::Utc;

        let kya = KyaVerification {
            verified: true,
            agent_did: "did:tenzro:machine:test_agent".to_string(),
            controller_did: None,
            verification_level: KyaLevel::Basic,
            verified_at: Utc::now(),
            audit_trail: vec![],
        };

        let client = MastercardAgentPayClient::new(
            "did:tenzro:machine:test_agent",
            "key-1",
        )
        .with_kya(kya.clone());

        let cached = client.kya_verification().unwrap();
        assert_eq!(cached.agent_did, "did:tenzro:machine:test_agent");
        assert_eq!(cached.verification_level, KyaLevel::Basic);
    }

    #[test]
    fn test_hmac_sha256_known_vector() {
        // RFC 4231 Test Case 2: HMAC-SHA256 with "Jefe" key and
        // "what do ya want for nothing?" message
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

        let result = hmac_sha256(key, message);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_hmac_sha256_empty_message() {
        let key = b"secret-key";
        let mac1 = hmac_sha256(key, b"");
        let mac2 = hmac_sha256(key, b"");
        // Deterministic: same key + same message = same MAC
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha256_different_keys_different_output() {
        let message = b"same message";
        let mac1 = hmac_sha256(b"key-one", message);
        let mac2 = hmac_sha256(b"key-two", message);
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha256_different_messages_different_output() {
        let key = b"same-key";
        let mac1 = hmac_sha256(key, b"message-a");
        let mac2 = hmac_sha256(key, b"message-b");
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha256_long_key_is_hashed() {
        // Keys longer than the SHA-256 block size (64 bytes) should be
        // pre-hashed to 32 bytes. Verify it still produces a valid MAC.
        let long_key = vec![0xABu8; 128];
        let result = hmac_sha256(&long_key, b"test");
        // Just verify it produces a 32-byte result and is deterministic
        assert_eq!(result.len(), 32);
        assert_eq!(result, hmac_sha256(&long_key, b"test"));
    }

    #[test]
    fn test_compute_authorization_header_with_key() {
        let client = MastercardAgentPayClient::new("did:tenzro:machine:agent", "key-42")
            .with_signing_key(b"test-secret".to_vec());

        let header = client.compute_authorization_header(b"request body").unwrap();

        // Header format: "HMAC-SHA256 Credential=<key_id>,Signature=<hex>"
        assert!(header.starts_with("HMAC-SHA256 Credential=key-42,Signature="));

        // Verify the signature portion is valid hex (64 hex chars = 32 bytes)
        let sig_hex = header.split("Signature=").nth(1).unwrap();
        assert_eq!(sig_hex.len(), 64);
        assert!(hex::decode(sig_hex).is_ok());

        // Verify it matches the expected HMAC
        let expected_mac = hmac_sha256(b"test-secret", b"request body");
        assert_eq!(sig_hex, hex::encode(expected_mac));
    }

    #[test]
    fn test_compute_authorization_header_without_key() {
        let client = MastercardAgentPayClient::new("did:tenzro:machine:agent", "key-1");

        // No signing key configured => None
        assert!(client.compute_authorization_header(b"body").is_none());
    }

    #[test]
    fn test_authorization_header_changes_with_body() {
        let client = MastercardAgentPayClient::new("did:tenzro:machine:agent", "key-1")
            .with_signing_key(b"secret".to_vec());

        let header_a = client.compute_authorization_header(b"body-a").unwrap();
        let header_b = client.compute_authorization_header(b"body-b").unwrap();
        // Different bodies must produce different signatures
        assert_ne!(header_a, header_b);
    }
}
