//! x402 payment requirements: the body of the `PAYMENT-REQUIRED` header.
//!
//! A 402 response carries `PAYMENT-REQUIRED: <base64 JSON>` holding an
//! [`X402PaymentRequired`]: the protocol version, the resource being sold,
//! and one [`X402PaymentRequirement`] per way the seller accepts payment.
//! The buyer answers with `PAYMENT-SIGNATURE` (an
//! [`X402PaymentPayload`](super::payment_payload::X402PaymentPayload)) and the
//! seller reports settlement in `PAYMENT-RESPONSE` (an
//! [`X402SettlementResponse`](super::receipt::X402SettlementResponse)).
//!
//! `x402Version` is the protocol's own field; its value is set by the x402
//! specification, not by Tenzro.

use crate::error::{PaymentError, Result};
use serde::{Deserialize, Serialize};

/// The x402 protocol version these types speak.
pub const X402_WIRE_VERSION: u32 = 2;

/// Header carrying the base64 [`X402PaymentRequired`] on a 402 response.
pub const PAYMENT_REQUIRED_HEADER: &str = "PAYMENT-REQUIRED";

/// Header carrying the buyer's base64 payment payload on the retried request.
pub const PAYMENT_SIGNATURE_HEADER: &str = "PAYMENT-SIGNATURE";

/// Header carrying the base64 settlement response on the paid response.
pub const PAYMENT_RESPONSE_HEADER: &str = "PAYMENT-RESPONSE";

/// The resource a 402 response sells.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    /// URL (or node-local resource path) of the protected resource.
    pub url: String,
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type of the paid response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

impl ResourceInfo {
    /// A resource with only its URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            description: None,
            mime_type: None,
        }
    }
}

/// The body of `PAYMENT-REQUIRED`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentRequired {
    /// Protocol version ([`X402_WIRE_VERSION`]).
    pub x402_version: u32,
    /// Why payment is required, when the 402 answers a failed attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The resource being sold.
    pub resource: ResourceInfo,
    /// The payment options the seller accepts.
    pub accepts: Vec<X402PaymentRequirement>,
    /// Protocol extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// One way the seller accepts payment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentRequirement {
    /// Scheme identifier (`tenzro-hybrid`, `upto`, `batch-settlement`,
    /// `exact-eip3009`, `permit2`, `erc7710`). Selects the scheme backend.
    pub scheme: String,
    /// CAIP-2 network (`tenzro:<chain id>`, `eip155:8453`, ...).
    pub network: String,
    /// Amount in the asset's smallest unit, as a decimal string. Under
    /// `upto` it is the ceiling the buyer authorizes.
    pub amount: String,
    /// Asset symbol or token address.
    pub asset: String,
    /// Address that receives the payment.
    pub pay_to: String,
    /// Seconds the buyer has to complete payment.
    pub max_timeout_seconds: u64,
    /// Scheme-specific parameters. On a Tenzro-issued requirement this holds
    /// the `challengeId` the payment answers and the signed offer, when the
    /// seller signs its offers.
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

/// Base64 (standard, padded) JSON, as every x402 header carries.
pub(crate) fn encode_header<T: Serialize>(value: &T) -> Result<String> {
    let json =
        serde_json::to_vec(value).map_err(|e| PaymentError::SerializationError(e.to_string()))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        json,
    ))
}

/// Decode a base64 JSON x402 header.
pub(crate) fn decode_header<T: serde::de::DeserializeOwned>(encoded: &str) -> Result<T> {
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded.trim())
            .map_err(|e| PaymentError::ChallengeError(format!("x402 header is not base64: {e}")))?;
    serde_json::from_slice(&decoded)
        .map_err(|e| PaymentError::ChallengeError(format!("x402 header JSON: {e}")))
}

impl X402PaymentRequired {
    /// A requirement set for `resource`.
    pub fn new(resource: ResourceInfo, accepts: Vec<X402PaymentRequirement>) -> Self {
        Self {
            x402_version: X402_WIRE_VERSION,
            error: None,
            resource,
            accepts,
            extensions: None,
        }
    }

    /// Sets the error message.
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Sets the extensions object.
    pub fn with_extensions(mut self, extensions: serde_json::Value) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// The `PAYMENT-REQUIRED` header value.
    pub fn to_base64(&self) -> Result<String> {
        encode_header(self)
    }

    /// Parse a `PAYMENT-REQUIRED` header value. A different protocol version
    /// is refused rather than guessed at.
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let required: Self = decode_header(encoded)?;
        if required.x402_version != X402_WIRE_VERSION {
            return Err(PaymentError::ChallengeError(format!(
                "x402 version {} is not supported (expected {})",
                required.x402_version, X402_WIRE_VERSION
            )));
        }
        Ok(required)
    }
}

impl X402PaymentRequirement {
    /// A payment option.
    pub fn new(
        scheme: impl Into<String>,
        network: impl Into<String>,
        amount: impl Into<String>,
        pay_to: impl Into<String>,
        asset: impl Into<String>,
        max_timeout_seconds: u64,
    ) -> Self {
        Self {
            scheme: scheme.into(),
            network: network.into(),
            amount: amount.into(),
            asset: asset.into(),
            pay_to: pay_to.into(),
            max_timeout_seconds,
            extra: serde_json::Value::Null,
        }
    }

    /// Attaches scheme-specific parameters.
    pub fn with_extra(mut self, extra: serde_json::Value) -> Self {
        self.extra = extra;
        self
    }

    /// A string entry of `extra`.
    pub fn extra_str(&self, key: &str) -> Option<&str> {
        self.extra.get(key).and_then(|v| v.as_str())
    }

    /// Insert one `extra` entry, turning a null `extra` into an object.
    pub fn set_extra(&mut self, key: &str, value: serde_json::Value) {
        if !self.extra.is_object() {
            self.extra = serde_json::Value::Object(serde_json::Map::new());
        }
        if let Some(obj) = self.extra.as_object_mut() {
            obj.insert(key.to_string(), value);
        }
    }

    /// The amount as an integer.
    pub fn amount_u128(&self) -> Result<u128> {
        self.amount.parse().map_err(|_| {
            PaymentError::ChallengeError(format!(
                "x402 amount '{}' is not a decimal integer",
                self.amount
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> X402PaymentRequired {
        X402PaymentRequired::new(
            ResourceInfo::new("https://api.example/paid"),
            vec![
                X402PaymentRequirement::new(
                    "tenzro-hybrid",
                    "tenzro:1337",
                    "1000",
                    "0xabc",
                    "TNZO",
                    60,
                )
                .with_extra(serde_json::json!({ "challengeId": "ch-1" })),
            ],
        )
    }

    #[test]
    fn serializes_the_protocol_field_names() {
        let json = serde_json::to_value(sample()).unwrap();
        assert_eq!(json["x402Version"], 2);
        assert_eq!(json["resource"]["url"], "https://api.example/paid");
        let accept = &json["accepts"][0];
        assert_eq!(accept["amount"], "1000");
        assert_eq!(accept["payTo"], "0xabc");
        assert_eq!(accept["maxTimeoutSeconds"], 60);
        assert_eq!(accept["extra"]["challengeId"], "ch-1");
        assert!(accept.get("maxAmountRequired").is_none());
    }

    #[test]
    fn the_header_round_trips() {
        let required = sample();
        let decoded = X402PaymentRequired::from_base64(&required.to_base64().unwrap()).unwrap();
        assert_eq!(decoded, required);
    }

    #[test]
    fn another_protocol_version_is_refused() {
        let mut required = sample();
        required.x402_version = 1;
        assert!(X402PaymentRequired::from_base64(&required.to_base64().unwrap()).is_err());
    }
}
