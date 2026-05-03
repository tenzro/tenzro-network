//! x402 Payment Required types
//!
//! Implements the x402 specification for HTTP 402-based payment requirements.
//! Payment requirements are transported via the `X-PAYMENT-REQUIRED` header
//! as base64-encoded JSON.
//!
//! Tenzro-owned wire — per pre-launch hygiene there is no `version` field on
//! `X402PaymentRequired`. The negotiated semantics are pinned by the scheme
//! id carried in `X402PaymentRequirement.extra.scheme` (see
//! [`crate::x402::scheme::SchemeRegistry`]).

use crate::error::{PaymentError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// x402 payment requirements returned in a 402 response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentRequired {
    /// Payment requirement options
    pub accepts: Vec<X402PaymentRequirement>,
    /// Error message describing why payment is required
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A single payment requirement option
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentRequirement {
    /// Chain to pay on (e.g., "base", "tempo", "tenzro")
    pub chain: String,
    /// Asset address or symbol (e.g., "USDC", "0x...")
    pub asset: String,
    /// Amount required (string for arbitrary precision)
    pub amount: String,
    /// Recipient address
    pub recipient: String,
    /// Expiration time for this requirement
    pub expires_at: DateTime<Utc>,
    /// Additional parameters (V2: scheme, network, description, etc.)
    #[serde(default)]
    pub extra: serde_json::Value,
}

impl X402PaymentRequired {
    /// Creates a new x402 payment required response
    pub fn new(accepts: Vec<X402PaymentRequirement>) -> Self {
        Self {
            accepts,
            error: None,
        }
    }

    /// Sets an error message
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Encodes as base64 for transport in the X-PAYMENT-REQUIRED header
    pub fn to_base64(&self) -> Result<String> {
        let json = serde_json::to_string(self)
            .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            json.as_bytes(),
        ))
    }

    /// Decodes from a base64-encoded X-PAYMENT-REQUIRED header value
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            encoded,
        )
        .map_err(|e| {
            PaymentError::ChallengeError(format!("Invalid base64 in payment header: {}", e))
        })?;

        let json_str = String::from_utf8(decoded).map_err(|e| {
            PaymentError::ChallengeError(format!("Invalid UTF-8 in payment header: {}", e))
        })?;

        serde_json::from_str(&json_str)
            .map_err(|e| PaymentError::ChallengeError(format!("Invalid payment JSON: {}", e)))
    }
}

impl X402PaymentRequirement {
    /// Creates a new payment requirement with scheme and network
    pub fn new(
        chain: impl Into<String>,
        asset: impl Into<String>,
        amount: impl Into<String>,
        recipient: impl Into<String>,
        scheme: &str,
        network: &str,
    ) -> Self {
        Self {
            chain: chain.into(),
            asset: asset.into(),
            amount: amount.into(),
            recipient: recipient.into(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            extra: serde_json::json!({
                "scheme": scheme,
                "network": network
            }),
        }
    }

    /// Checks if this requirement has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_required_serialization_has_no_version_field() {
        let req = X402PaymentRequired::new(vec![X402PaymentRequirement::new(
            "tenzro",
            "USDC",
            "1000",
            "0xrecipient",
            "tenzro-hybrid",
            "eip155:1337",
        )]);

        let json = serde_json::to_string(&req).unwrap();
        // Tenzro-owned wire: no version field on X402PaymentRequired.
        assert!(!json.contains("\"version\""));
        assert!(json.contains("\"scheme\""));
        assert!(json.contains("\"network\""));
    }

    #[test]
    fn test_base64_roundtrip() {
        let req = X402PaymentRequired::new(vec![X402PaymentRequirement {
            chain: "tenzro".to_string(),
            asset: "USDC".to_string(),
            amount: "5000".to_string(),
            recipient: "0xrecipient".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            extra: serde_json::json!({"scheme": "tenzro-hybrid"}),
        }]);

        let encoded = req.to_base64().unwrap();
        let decoded = X402PaymentRequired::from_base64(&encoded).unwrap();

        assert_eq!(decoded.accepts.len(), 1);
        assert_eq!(decoded.accepts[0].amount, "5000");
        assert_eq!(decoded.accepts[0].chain, "tenzro");
    }

    #[test]
    fn test_requirement_expiration() {
        let expired = X402PaymentRequirement {
            chain: "tenzro".to_string(),
            asset: "USDC".to_string(),
            amount: "100".to_string(),
            recipient: "0x".to_string(),
            expires_at: Utc::now() - chrono::Duration::minutes(1),
            extra: serde_json::Value::Null,
        };
        assert!(expired.is_expired());

        let fresh = X402PaymentRequirement {
            chain: "tenzro".to_string(),
            asset: "USDC".to_string(),
            amount: "100".to_string(),
            recipient: "0x".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            extra: serde_json::Value::Null,
        };
        assert!(!fresh.is_expired());
    }
}
