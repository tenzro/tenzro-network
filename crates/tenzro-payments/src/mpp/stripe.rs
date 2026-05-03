//! Stripe API integration for MPP credential verification
//!
//! MPP is co-authored by Stripe and Tempo. When an MPP credential is received,
//! the server can verify it against Stripe's Payment Intents API to confirm
//! that a real payment was made before releasing the resource.
//!
//! # Stripe API Integration
//!
//! - **Payment Intents**: Create and confirm payments via `POST /v1/payment_intents`
//! - **Webhook Verification**: HMAC-SHA256 signature verification for `whsec_` secrets
//! - **Idempotency**: All mutating requests use `Idempotency-Key` headers
//!
//! # Usage
//!
//! ```no_run
//! use tenzro_payments::mpp::stripe::StripeClient;
//!
//! # async fn example() -> tenzro_payments::Result<()> {
//! let client = StripeClient::new("sk_test_...");
//!
//! // Create a payment intent
//! let intent = client.create_payment_intent(
//!     1000,       // amount in smallest currency unit (cents)
//!     "usd",      // currency
//!     Some("Payment for AI inference"),
//! ).await?;
//!
//! // Verify a webhook signature
//! let valid = StripeClient::verify_webhook_signature(
//!     b"raw_body",
//!     "t=1234,v1=...",
//!     "whsec_...",
//!     300, // tolerance in seconds
//! );
//! # Ok(())
//! # }
//! ```

use crate::error::{PaymentError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tracing::{debug, info, warn};

/// Stripe API base URL
const STRIPE_API_BASE: &str = "https://api.stripe.com";

/// Stripe API version header value
const STRIPE_API_VERSION: &str = "2025-12-18.acacia";

/// Stripe Payment Intent status values
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentIntentStatus {
    RequiresPaymentMethod,
    RequiresConfirmation,
    RequiresAction,
    Processing,
    RequiresCapture,
    Canceled,
    Succeeded,
}

/// Stripe Payment Intent object (subset of fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentIntent {
    /// Payment Intent ID (pi_...)
    pub id: String,
    /// Object type (always "payment_intent")
    pub object: String,
    /// Amount in smallest currency unit (e.g., cents for USD)
    pub amount: u64,
    /// Three-letter ISO currency code
    pub currency: String,
    /// Payment Intent status
    pub status: PaymentIntentStatus,
    /// Client secret for frontend confirmation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Description of the payment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Metadata key-value pairs
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
    /// Charge ID if payment succeeded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_charge: Option<String>,
    /// Whether the payment was captured
    #[serde(default)]
    pub capture_method: String,
    /// Created timestamp
    #[serde(default)]
    pub created: i64,
}

/// Stripe API client for MPP payment verification
pub struct StripeClient {
    /// Stripe secret key (sk_test_... or sk_live_...)
    api_key: String,
    /// HTTP client
    http_client: reqwest::Client,
    /// API base URL (overridable for testing)
    api_base: String,
}

impl StripeClient {
    /// Creates a new Stripe API client
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            http_client: reqwest::Client::new(),
            api_base: STRIPE_API_BASE.to_string(),
        }
    }

    /// Overrides the API base URL (for testing with mock servers)
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// Creates a Payment Intent via `POST /v1/payment_intents`
    ///
    /// # Arguments
    /// - `amount`: Amount in smallest currency unit (e.g., 1000 = $10.00 USD)
    /// - `currency`: Three-letter ISO currency code (e.g., "usd")
    /// - `description`: Optional payment description
    ///
    /// # Returns
    /// The created PaymentIntent with client_secret for frontend confirmation
    pub async fn create_payment_intent(
        &self,
        amount: u64,
        currency: &str,
        description: Option<&str>,
    ) -> Result<PaymentIntent> {
        info!(
            "Creating Stripe Payment Intent: amount={} currency={}",
            amount, currency
        );

        let mut form = vec![
            ("amount", amount.to_string()),
            ("currency", currency.to_string()),
            ("automatic_payment_methods[enabled]", "true".to_string()),
        ];

        if let Some(desc) = description {
            form.push(("description", desc.to_string()));
        }

        let response = self
            .http_client
            .post(format!("{}/v1/payment_intents", self.api_base))
            .basic_auth(&self.api_key, Option::<&str>::None)
            .header("Stripe-Version", STRIPE_API_VERSION)
            .header(
                "Idempotency-Key",
                uuid::Uuid::new_v4().to_string(),
            )
            .form(&form)
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Stripe API request failed: {}", e)))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Failed to read Stripe response: {}", e)))?;

        if !status.is_success() {
            let error = Self::parse_stripe_error(&body);
            return Err(PaymentError::SettlementError(format!(
                "Stripe API error ({}): {}",
                status, error
            )));
        }

        let intent: PaymentIntent = serde_json::from_str(&body).map_err(|e| {
            PaymentError::SerializationError(format!(
                "Failed to parse Stripe PaymentIntent: {}",
                e
            ))
        })?;

        debug!(
            "Created Payment Intent: id={} status={:?}",
            intent.id, intent.status
        );

        Ok(intent)
    }

    /// Creates a Payment Intent with MPP metadata for tracking
    pub async fn create_mpp_payment_intent(
        &self,
        amount: u64,
        currency: &str,
        challenge_id: &str,
        payer_did: &str,
        resource: &str,
    ) -> Result<PaymentIntent> {
        info!(
            "Creating MPP Payment Intent: challenge={} amount={} currency={}",
            challenge_id, amount, currency
        );

        let form = vec![
            ("amount", amount.to_string()),
            ("currency", currency.to_string()),
            ("automatic_payment_methods[enabled]", "true".to_string()),
            (
                "description",
                format!("MPP payment for {}", resource),
            ),
            ("metadata[protocol]", "mpp".to_string()),
            ("metadata[challenge_id]", challenge_id.to_string()),
            ("metadata[payer_did]", payer_did.to_string()),
            ("metadata[resource]", resource.to_string()),
        ];

        let response = self
            .http_client
            .post(format!("{}/v1/payment_intents", self.api_base))
            .basic_auth(&self.api_key, Option::<&str>::None)
            .header("Stripe-Version", STRIPE_API_VERSION)
            .header("Idempotency-Key", format!("mpp-{}", challenge_id))
            .form(&form)
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Stripe API request failed: {}", e)))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Failed to read Stripe response: {}", e)))?;

        if !status.is_success() {
            let error = Self::parse_stripe_error(&body);
            return Err(PaymentError::SettlementError(format!(
                "Stripe API error ({}): {}",
                status, error
            )));
        }

        serde_json::from_str(&body).map_err(|e| {
            PaymentError::SerializationError(format!(
                "Failed to parse Stripe PaymentIntent: {}",
                e
            ))
        })
    }

    /// Retrieves a Payment Intent by ID via `GET /v1/payment_intents/:id`
    pub async fn get_payment_intent(&self, intent_id: &str) -> Result<PaymentIntent> {
        debug!("Retrieving Stripe Payment Intent: {}", intent_id);

        let response = self
            .http_client
            .get(format!("{}/v1/payment_intents/{}", self.api_base, intent_id))
            .basic_auth(&self.api_key, Option::<&str>::None)
            .header("Stripe-Version", STRIPE_API_VERSION)
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Stripe API request failed: {}", e)))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Failed to read Stripe response: {}", e)))?;

        if !status.is_success() {
            let error = Self::parse_stripe_error(&body);
            return Err(PaymentError::SettlementError(format!(
                "Stripe API error ({}): {}",
                status, error
            )));
        }

        serde_json::from_str(&body).map_err(|e| {
            PaymentError::SerializationError(format!(
                "Failed to parse Stripe PaymentIntent: {}",
                e
            ))
        })
    }

    /// Confirms a Payment Intent via `POST /v1/payment_intents/:id/confirm`
    pub async fn confirm_payment_intent(
        &self,
        intent_id: &str,
        payment_method: Option<&str>,
    ) -> Result<PaymentIntent> {
        info!("Confirming Stripe Payment Intent: {}", intent_id);

        let mut form: Vec<(&str, String)> = Vec::new();
        if let Some(pm) = payment_method {
            form.push(("payment_method", pm.to_string()));
        }

        let response = self
            .http_client
            .post(format!(
                "{}/v1/payment_intents/{}/confirm",
                self.api_base, intent_id
            ))
            .basic_auth(&self.api_key, Option::<&str>::None)
            .header("Stripe-Version", STRIPE_API_VERSION)
            .form(&form)
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Stripe API request failed: {}", e)))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Failed to read Stripe response: {}", e)))?;

        if !status.is_success() {
            let error = Self::parse_stripe_error(&body);
            return Err(PaymentError::SettlementError(format!(
                "Stripe confirm failed ({}): {}",
                status, error
            )));
        }

        serde_json::from_str(&body).map_err(|e| {
            PaymentError::SerializationError(format!(
                "Failed to parse Stripe PaymentIntent: {}",
                e
            ))
        })
    }

    /// Cancels a Payment Intent via `POST /v1/payment_intents/:id/cancel`
    pub async fn cancel_payment_intent(&self, intent_id: &str) -> Result<PaymentIntent> {
        info!("Cancelling Stripe Payment Intent: {}", intent_id);

        let response = self
            .http_client
            .post(format!(
                "{}/v1/payment_intents/{}/cancel",
                self.api_base, intent_id
            ))
            .basic_auth(&self.api_key, Option::<&str>::None)
            .header("Stripe-Version", STRIPE_API_VERSION)
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Stripe API request failed: {}", e)))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Failed to read Stripe response: {}", e)))?;

        if !status.is_success() {
            let error = Self::parse_stripe_error(&body);
            return Err(PaymentError::SettlementError(format!(
                "Stripe cancel failed ({}): {}",
                status, error
            )));
        }

        serde_json::from_str(&body).map_err(|e| {
            PaymentError::SerializationError(format!(
                "Failed to parse Stripe PaymentIntent: {}",
                e
            ))
        })
    }

    /// Verifies an MPP credential by checking the associated Stripe Payment Intent
    ///
    /// This confirms that:
    /// 1. The Payment Intent exists and has succeeded
    /// 2. The amount matches the challenge
    /// 3. The MPP metadata (challenge_id, payer_did) matches
    pub async fn verify_mpp_credential(
        &self,
        payment_intent_id: &str,
        expected_challenge_id: &str,
        expected_amount: u64,
    ) -> Result<bool> {
        info!(
            "Verifying MPP credential via Stripe: pi={} challenge={}",
            payment_intent_id, expected_challenge_id
        );

        let intent = self.get_payment_intent(payment_intent_id).await?;

        // 1. Check payment succeeded
        if intent.status != PaymentIntentStatus::Succeeded {
            warn!(
                "Payment Intent {} has status {:?}, expected Succeeded",
                payment_intent_id, intent.status
            );
            return Ok(false);
        }

        // 2. Check amount matches
        if intent.amount != expected_amount {
            warn!(
                "Payment amount mismatch: expected={}, got={}",
                expected_amount, intent.amount
            );
            return Ok(false);
        }

        // 3. Check MPP challenge_id in metadata
        if let Some(meta_challenge) = intent.metadata.get("challenge_id") {
            if meta_challenge != expected_challenge_id {
                warn!(
                    "Challenge ID mismatch: expected={}, got={}",
                    expected_challenge_id, meta_challenge
                );
                return Ok(false);
            }
        } else {
            debug!("No challenge_id in Payment Intent metadata — skipping metadata check");
        }

        info!(
            "MPP credential verified via Stripe: pi={} amount={}",
            payment_intent_id, intent.amount
        );
        Ok(true)
    }

    /// Verifies a Stripe webhook signature (HMAC-SHA256)
    ///
    /// Stripe webhook signatures use the `Stripe-Signature` header with the format:
    /// `t=<timestamp>,v1=<signature>[,v1=<signature>...]`
    ///
    /// The signed payload is: `<timestamp>.<raw_body>`
    /// The HMAC key is the webhook signing secret (`whsec_...`).
    ///
    /// # Arguments
    /// - `payload`: Raw request body bytes
    /// - `signature_header`: Value of the `Stripe-Signature` header
    /// - `webhook_secret`: Webhook signing secret (`whsec_...`)
    /// - `tolerance_seconds`: Maximum age of the signature in seconds (typically 300)
    ///
    /// # Returns
    /// `true` if the signature is valid and within the tolerance window
    pub fn verify_webhook_signature(
        payload: &[u8],
        signature_header: &str,
        webhook_secret: &str,
        tolerance_seconds: i64,
    ) -> bool {
        // Parse the signature header
        let mut timestamp: Option<i64> = None;
        let mut signatures: Vec<String> = Vec::new();

        for part in signature_header.split(',') {
            let part = part.trim();
            if let Some(ts) = part.strip_prefix("t=") {
                timestamp = ts.parse().ok();
            } else if let Some(sig) = part.strip_prefix("v1=") {
                signatures.push(sig.to_string());
            }
        }

        let timestamp = match timestamp {
            Some(ts) => ts,
            None => {
                warn!("No timestamp found in Stripe-Signature header");
                return false;
            }
        };

        if signatures.is_empty() {
            warn!("No v1 signatures found in Stripe-Signature header");
            return false;
        }

        // Check timestamp is within tolerance
        let now = chrono::Utc::now().timestamp();
        if (now - timestamp).abs() > tolerance_seconds {
            warn!(
                "Stripe webhook timestamp too old: {} (now: {}, tolerance: {}s)",
                timestamp, now, tolerance_seconds
            );
            return false;
        }

        // Compute expected signature: HMAC-SHA256(key=secret, msg="<timestamp>.<body>")
        let signed_payload = format!(
            "{}.{}",
            timestamp,
            String::from_utf8_lossy(payload)
        );

        let expected = hex::encode(hmac_sha256(
            webhook_secret.as_bytes(),
            signed_payload.as_bytes(),
        ));

        // Check if any of the v1 signatures match
        for sig in &signatures {
            if constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
                debug!("Stripe webhook signature verified successfully");
                return true;
            }
        }

        warn!("No matching Stripe webhook signature found");
        false
    }

    /// Parses a Stripe API error from a JSON response body
    fn parse_stripe_error(body: &str) -> String {
        #[derive(Deserialize)]
        struct StripeErrorResponse {
            error: StripeErrorDetail,
        }
        #[derive(Deserialize)]
        struct StripeErrorDetail {
            message: Option<String>,
            #[serde(rename = "type")]
            error_type: Option<String>,
            code: Option<String>,
        }

        match serde_json::from_str::<StripeErrorResponse>(body) {
            Ok(err) => {
                let msg = err.error.message.unwrap_or_default();
                let code = err.error.code.unwrap_or_default();
                let error_type = err.error.error_type.unwrap_or_default();
                format!("{} ({}/{})", msg, error_type, code)
            }
            Err(_) => body.chars().take(200).collect(),
        }
    }

    /// Returns the API key (masked for logging)
    pub fn masked_key(&self) -> String {
        if self.api_key.len() > 12 {
            format!("{}...{}", &self.api_key[..8], &self.api_key[self.api_key.len() - 4..])
        } else {
            "***".to_string()
        }
    }
}

/// HMAC-SHA256 implementation per RFC 2104
///
/// HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
/// where K' = H(K) if |K| > block_size, else K padded with zeros
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64; // SHA-256 block size
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    // Step 1: If key > block_size, hash it
    let mut k_prime = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = Sha256::digest(key);
        k_prime[..32].copy_from_slice(&hash);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    // Step 2: Compute inner hash: H((K' XOR ipad) || message)
    let mut inner_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key[i] = k_prime[i] ^ IPAD;
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(inner_key);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    // Step 3: Compute outer hash: H((K' XOR opad) || inner_hash)
    let mut outer_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_key[i] = k_prime[i] ^ OPAD;
    }

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(outer_key);
    outer_hasher.update(inner_hash);
    let result = outer_hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Constant-time byte comparison to prevent timing attacks on signature verification
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Stripe webhook event types relevant to MPP
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MppWebhookEvent {
    /// payment_intent.succeeded — payment completed
    PaymentIntentSucceeded,
    /// payment_intent.payment_failed — payment failed
    PaymentIntentFailed,
    /// payment_intent.canceled — payment canceled
    PaymentIntentCanceled,
    /// Unrecognized event type
    Unknown(String),
}

impl MppWebhookEvent {
    /// Parses an event type string from a Stripe webhook
    pub fn from_type(event_type: &str) -> Self {
        match event_type {
            "payment_intent.succeeded" => Self::PaymentIntentSucceeded,
            "payment_intent.payment_failed" => Self::PaymentIntentFailed,
            "payment_intent.canceled" => Self::PaymentIntentCanceled,
            other => Self::Unknown(other.to_string()),
        }
    }
}

/// Stripe webhook event envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// Event ID
    pub id: String,
    /// Event type (e.g., "payment_intent.succeeded")
    #[serde(rename = "type")]
    pub event_type: String,
    /// Event data containing the object
    pub data: WebhookEventData,
    /// Created timestamp
    pub created: i64,
}

/// Webhook event data wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEventData {
    /// The event object (usually a PaymentIntent for MPP)
    pub object: serde_json::Value,
}

impl WebhookEvent {
    /// Parses the event type
    pub fn mpp_event_type(&self) -> MppWebhookEvent {
        MppWebhookEvent::from_type(&self.event_type)
    }

    /// Extracts the PaymentIntent from the event data
    pub fn payment_intent(&self) -> Result<PaymentIntent> {
        serde_json::from_value(self.data.object.clone()).map_err(|e| {
            PaymentError::SerializationError(format!(
                "Failed to parse PaymentIntent from webhook: {}",
                e
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_signature_verification() {
        // Known test vector
        let payload = b"test_payload";
        let secret = "whsec_test_secret";
        let timestamp = chrono::Utc::now().timestamp();

        // Compute expected signature using our HMAC-SHA256
        let signed = format!("{}.test_payload", timestamp);
        let sig = hex::encode(hmac_sha256(secret.as_bytes(), signed.as_bytes()));

        let header = format!("t={},v1={}", timestamp, sig);

        assert!(StripeClient::verify_webhook_signature(
            payload,
            &header,
            secret,
            300,
        ));
    }

    #[test]
    fn test_webhook_rejects_wrong_signature() {
        let payload = b"test_payload";
        let secret = "whsec_test_secret";
        let timestamp = chrono::Utc::now().timestamp();

        let header = format!("t={},v1=deadbeef", timestamp);

        assert!(!StripeClient::verify_webhook_signature(
            payload,
            &header,
            secret,
            300,
        ));
    }

    #[test]
    fn test_webhook_rejects_expired_timestamp() {
        let payload = b"test_payload";
        let secret = "whsec_test_secret";
        let old_timestamp = chrono::Utc::now().timestamp() - 600; // 10 minutes ago

        let signed = format!("{}.test_payload", old_timestamp);
        let sig = hex::encode(hmac_sha256(secret.as_bytes(), signed.as_bytes()));

        let header = format!("t={},v1={}", old_timestamp, sig);

        // Tolerance of 300 seconds should reject 600-second-old timestamp
        assert!(!StripeClient::verify_webhook_signature(
            payload,
            &header,
            secret,
            300,
        ));
    }

    #[test]
    fn test_webhook_rejects_missing_timestamp() {
        assert!(!StripeClient::verify_webhook_signature(
            b"payload",
            "v1=deadbeef",
            "secret",
            300,
        ));
    }

    #[test]
    fn test_webhook_rejects_missing_signature() {
        let timestamp = chrono::Utc::now().timestamp();
        let header = format!("t={}", timestamp);
        assert!(!StripeClient::verify_webhook_signature(
            b"payload",
            &header,
            "secret",
            300,
        ));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_payment_intent_status_deserialization() {
        let json = r#"{"id":"pi_test","object":"payment_intent","amount":1000,"currency":"usd","status":"succeeded","metadata":{},"capture_method":"automatic","created":1234}"#;
        let intent: PaymentIntent = serde_json::from_str(json).unwrap();
        assert_eq!(intent.id, "pi_test");
        assert_eq!(intent.amount, 1000);
        assert_eq!(intent.status, PaymentIntentStatus::Succeeded);
    }

    #[test]
    fn test_mpp_webhook_event_types() {
        assert_eq!(
            MppWebhookEvent::from_type("payment_intent.succeeded"),
            MppWebhookEvent::PaymentIntentSucceeded
        );
        assert_eq!(
            MppWebhookEvent::from_type("payment_intent.payment_failed"),
            MppWebhookEvent::PaymentIntentFailed
        );
        assert_eq!(
            MppWebhookEvent::from_type("payment_intent.canceled"),
            MppWebhookEvent::PaymentIntentCanceled
        );
        assert_eq!(
            MppWebhookEvent::from_type("unknown.event"),
            MppWebhookEvent::Unknown("unknown.event".to_string())
        );
    }

    #[test]
    fn test_stripe_error_parsing() {
        let error_json = r#"{"error":{"message":"Your card was declined.","type":"card_error","code":"card_declined"}}"#;
        let parsed = StripeClient::parse_stripe_error(error_json);
        assert!(parsed.contains("Your card was declined"));
        assert!(parsed.contains("card_error"));
        assert!(parsed.contains("card_declined"));
    }

    #[test]
    fn test_stripe_error_parsing_invalid_json() {
        let error = StripeClient::parse_stripe_error("not json");
        assert_eq!(error, "not json");
    }

    #[test]
    fn test_masked_key() {
        let client = StripeClient::new("sk_test_abcdefghijklmnop");
        let masked = client.masked_key();
        assert!(masked.starts_with("sk_test_"));
        assert!(masked.ends_with("mnop"));
        assert!(masked.contains("..."));
    }

    #[test]
    fn test_masked_key_short() {
        let client = StripeClient::new("short");
        assert_eq!(client.masked_key(), "***");
    }

    #[test]
    fn test_webhook_event_deserialization() {
        let json = r#"{
            "id": "evt_test",
            "type": "payment_intent.succeeded",
            "data": {
                "object": {
                    "id": "pi_test",
                    "object": "payment_intent",
                    "amount": 5000,
                    "currency": "usd",
                    "status": "succeeded",
                    "metadata": {"challenge_id": "ch-123", "protocol": "mpp"},
                    "capture_method": "automatic",
                    "created": 1234
                }
            },
            "created": 1234
        }"#;

        let event: WebhookEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "payment_intent.succeeded");
        assert_eq!(
            event.mpp_event_type(),
            MppWebhookEvent::PaymentIntentSucceeded
        );

        let pi = event.payment_intent().unwrap();
        assert_eq!(pi.id, "pi_test");
        assert_eq!(pi.amount, 5000);
        assert_eq!(pi.metadata.get("challenge_id").unwrap(), "ch-123");
    }

    #[test]
    fn test_webhook_multiple_v1_signatures() {
        // Stripe can send multiple v1= signatures (key rotation)
        let payload = b"test_payload";
        let secret = "whsec_test_secret";
        let timestamp = chrono::Utc::now().timestamp();

        let signed = format!("{}.test_payload", timestamp);
        let sig = hex::encode(hmac_sha256(secret.as_bytes(), signed.as_bytes()));

        // First sig is wrong, second is correct
        let header = format!("t={},v1=deadbeef,v1={}", timestamp, sig);

        assert!(StripeClient::verify_webhook_signature(
            payload,
            &header,
            secret,
            300,
        ));
    }
}
