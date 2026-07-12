//! x402 Payment Required types
//!
//! Implements Coinbase's x402 V2 wire format for HTTP 402 payment requirements.
//! Payment requirements are transported via the `X-PAYMENT-REQUIRED` header as
//! base64-encoded JSON.
//!
//! The `x402Version` field is Coinbase's upstream spec field — it pins wire
//! semantics, not Tenzro identifier semantics, so it is exempt from the
//! "no version segment in tenzro-owned strings" rule that applies to our own
//! namespace. The scheme registry (`crate::x402::scheme::SchemeRegistry`)
//! continues to pin backend semantics; `x402Version` is a literal upstream
//! constant — bump only if Coinbase publishes a new wire version.

use crate::error::{PaymentError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Current x402 wire version, per Coinbase upstream spec.
pub const X402_WIRE_VERSION: u32 = 1;

/// x402 payment requirements returned in a 402 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentRequired {
    /// Upstream x402 wire version (Coinbase spec field).
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    /// Payment requirement options
    pub accepts: Vec<X402PaymentRequirement>,
    /// Error message describing why payment is required
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A single payment requirement option, per Coinbase x402 V2 spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentRequirement {
    /// Scheme identifier (e.g., "tenzro-hybrid", "exact-eip3009", "permit2",
    /// "erc7710"). Routes to the scheme backend in `SchemeRegistry`.
    pub scheme: String,
    /// CAIP-2 network identifier (e.g., "eip155:1337", "tenzro-mainnet").
    pub network: String,
    /// Maximum amount required for this resource (string for arbitrary precision).
    pub max_amount_required: String,
    /// Resource URL being protected by this 402 challenge.
    pub resource: String,
    /// Human-readable description of the resource.
    pub description: String,
    /// MIME type of the resource that will be returned on settlement.
    pub mime_type: String,
    /// Recipient address that receives the payment.
    pub pay_to: String,
    /// Maximum time (seconds) the payer has to settle this requirement.
    pub max_timeout_seconds: u64,
    /// Asset address or symbol (e.g., "USDC", "0x...").
    pub asset: String,
    /// Optional output schema describing the response payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    /// Expiration time for this requirement (Tenzro-side challenge expiry).
    pub expires_at: DateTime<Utc>,
    /// Additional scheme-specific parameters.
    #[serde(default, skip_serializing_if = "is_null_or_empty_object")]
    pub extra: serde_json::Value,
}

fn is_null_or_empty_object(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => true,
        serde_json::Value::Object(m) => m.is_empty(),
        _ => false,
    }
}

impl X402PaymentRequired {
    /// Creates a new x402 payment required response (wire version = 1).
    pub fn new(accepts: Vec<X402PaymentRequirement>) -> Self {
        Self {
            x402_version: X402_WIRE_VERSION,
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
    /// Creates a new payment requirement.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scheme: impl Into<String>,
        network: impl Into<String>,
        max_amount_required: impl Into<String>,
        pay_to: impl Into<String>,
        asset: impl Into<String>,
        resource: impl Into<String>,
        description: impl Into<String>,
        mime_type: impl Into<String>,
        max_timeout_seconds: u64,
    ) -> Self {
        Self {
            scheme: scheme.into(),
            network: network.into(),
            max_amount_required: max_amount_required.into(),
            resource: resource.into(),
            description: description.into(),
            mime_type: mime_type.into(),
            pay_to: pay_to.into(),
            max_timeout_seconds,
            asset: asset.into(),
            output_schema: None,
            expires_at: Utc::now() + chrono::Duration::seconds(max_timeout_seconds as i64),
            extra: serde_json::Value::Null,
        }
    }

    /// Attaches an output schema describing the response payload.
    pub fn with_output_schema(mut self, schema: serde_json::Value) -> Self {
        self.output_schema = Some(schema);
        self
    }

    /// Attaches scheme-specific extra parameters.
    pub fn with_extra(mut self, extra: serde_json::Value) -> Self {
        self.extra = extra;
        self
    }

    /// Checks if this requirement has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_requirement() -> X402PaymentRequirement {
        X402PaymentRequirement::new(
            "tenzro-hybrid",
            "tenzro-mainnet",
            "1000",
            "0xrecipient",
            "USDC",
            "https://api.tenzro.xyz/paid/resource",
            "Test resource",
            "application/json",
            60,
        )
    }

    #[test]
    fn test_payment_required_serializes_x402_version_field() {
        let req = X402PaymentRequired::new(vec![sample_requirement()]);

        let json = serde_json::to_string(&req).unwrap();
        // Coinbase x402 V2 spec: x402Version is the literal upstream field name.
        assert!(json.contains("\"x402Version\":1"));
        assert!(json.contains("\"scheme\":\"tenzro-hybrid\""));
        assert!(json.contains("\"network\":\"tenzro-mainnet\""));
        assert!(json.contains("\"maxAmountRequired\":\"1000\""));
        assert!(json.contains("\"payTo\":\"0xrecipient\""));
        assert!(json.contains("\"maxTimeoutSeconds\":60"));
    }

    #[test]
    fn test_base64_roundtrip() {
        let req = X402PaymentRequired::new(vec![sample_requirement()]);

        let encoded = req.to_base64().unwrap();
        let decoded = X402PaymentRequired::from_base64(&encoded).unwrap();

        assert_eq!(decoded.x402_version, 1);
        assert_eq!(decoded.accepts.len(), 1);
        assert_eq!(decoded.accepts[0].max_amount_required, "1000");
        assert_eq!(decoded.accepts[0].network, "tenzro-mainnet");
        assert_eq!(decoded.accepts[0].scheme, "tenzro-hybrid");
        assert_eq!(decoded.accepts[0].pay_to, "0xrecipient");
    }

    #[test]
    fn test_requirement_expiration() {
        let mut expired = sample_requirement();
        expired.expires_at = Utc::now() - chrono::Duration::minutes(1);
        assert!(expired.is_expired());

        let fresh = sample_requirement();
        assert!(!fresh.is_expired());
    }
}
