//! x402 payment payloads: the body of the `PAYMENT-SIGNATURE` header.
//!
//! The buyer echoes the [`X402PaymentRequirement`] it chose as `accepted` and
//! attaches a scheme-specific `payload`:
//!
//! - `exact-eip3009`, `permit2`, `erc7710`: an [`ExactSchemePayload`], the
//!   EIP-3009 authorization `{from, to, value, validAfter, validBefore, nonce}`
//!   and its signature.
//! - `tenzro-hybrid`, `upto`, `batch-settlement`: the signed Tenzro
//!   [`PaymentCredential`](crate::types::PaymentCredential), whose signature
//!   covers the canonical payment authorization (or escrow voucher).

use serde::{Deserialize, Serialize};

use crate::error::{PaymentError, Result};
use crate::x402::payment_required::{
    ResourceInfo, X402_WIRE_VERSION, X402PaymentRequirement, decode_header, encode_header,
};

/// Unix-second bounds travel as decimal strings on the wire.
mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        String::deserialize(d)?.parse().map_err(D::Error::custom)
    }
}

/// The EIP-3009 `transferWithAuthorization` tuple.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExactAuthorization {
    /// Payer address (0x-prefixed hex).
    pub from: String,
    /// Recipient address.
    pub to: String,
    /// Amount, decimal string in the token's smallest unit.
    pub value: String,
    /// Unix second after which the authorization is valid.
    #[serde(with = "decimal_u64")]
    pub valid_after: u64,
    /// Unix second before which the authorization is valid.
    #[serde(with = "decimal_u64")]
    pub valid_before: u64,
    /// 32-byte nonce, 0x-prefixed hex.
    pub nonce: String,
}

/// The payload of the EVM `exact`-family schemes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExactSchemePayload {
    /// Signature over the scheme's typed data (65-byte secp256k1, hex), or
    /// for `erc7710` the encoded redemption proof.
    pub signature: String,
    /// The authorization tuple.
    pub authorization: ExactAuthorization,
}

/// The body of `PAYMENT-SIGNATURE`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentPayload {
    /// Protocol version ([`X402_WIRE_VERSION`]).
    pub x402_version: u32,
    /// The resource paid for, echoed from the 402.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    /// The payment option the buyer chose.
    pub accepted: X402PaymentRequirement,
    /// Scheme-specific payment data.
    pub payload: serde_json::Value,
    /// Protocol extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl X402PaymentPayload {
    /// A payload answering `accepted`.
    pub fn new(accepted: X402PaymentRequirement, payload: serde_json::Value) -> Self {
        Self {
            x402_version: X402_WIRE_VERSION,
            resource: None,
            accepted,
            payload,
            extensions: None,
        }
    }

    /// A payload carrying an EVM exact-scheme authorization.
    pub fn exact(accepted: X402PaymentRequirement, exact: &ExactSchemePayload) -> Result<Self> {
        let payload = serde_json::to_value(exact)
            .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
        Ok(Self::new(accepted, payload))
    }

    /// Echo the resource from the 402.
    pub fn with_resource(mut self, resource: ResourceInfo) -> Self {
        self.resource = Some(resource);
        self
    }

    /// The scheme the buyer chose.
    pub fn scheme(&self) -> &str {
        &self.accepted.scheme
    }

    /// The network the buyer chose.
    pub fn network(&self) -> &str {
        &self.accepted.network
    }

    /// The payload as an EVM exact-scheme authorization.
    pub fn exact_payload(&self) -> Result<ExactSchemePayload> {
        serde_json::from_value(self.payload.clone()).map_err(|e| {
            PaymentError::CredentialError(format!(
                "{} payload is not an exact-scheme authorization: {e}",
                self.accepted.scheme
            ))
        })
    }

    /// The `PAYMENT-SIGNATURE` header value.
    pub fn to_base64(&self) -> Result<String> {
        encode_header(self)
    }

    /// Parse a `PAYMENT-SIGNATURE` header value. A different protocol version
    /// is refused.
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let payload: Self = decode_header(encoded)
            .map_err(|e| PaymentError::CredentialError(format!("PAYMENT-SIGNATURE: {e}")))?;
        if payload.x402_version != X402_WIRE_VERSION {
            return Err(PaymentError::CredentialError(format!(
                "x402 version {} is not supported (expected {})",
                payload.x402_version, X402_WIRE_VERSION
            )));
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact() -> ExactSchemePayload {
        ExactSchemePayload {
            signature: "0xsig".into(),
            authorization: ExactAuthorization {
                from: "0xfrom".into(),
                to: "0xto".into(),
                value: "10000".into(),
                valid_after: 1_740_672_089,
                valid_before: 1_740_672_154,
                nonce: "0x01".into(),
            },
        }
    }

    #[test]
    fn exact_payloads_use_decimal_string_bounds() {
        let req = X402PaymentRequirement::new(
            "exact-eip3009",
            "eip155:8453",
            "10000",
            "0xto",
            "0xusdc",
            60,
        );
        let p = X402PaymentPayload::exact(req, &exact()).unwrap();
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["x402Version"], 2);
        assert_eq!(json["accepted"]["scheme"], "exact-eip3009");
        assert_eq!(json["payload"]["authorization"]["validAfter"], "1740672089");
        let back = X402PaymentPayload::from_base64(&p.to_base64().unwrap()).unwrap();
        assert_eq!(back.exact_payload().unwrap(), exact());
    }

    #[test]
    fn a_non_exact_payload_is_not_read_as_one() {
        let req =
            X402PaymentRequirement::new("tenzro-hybrid", "tenzro:1337", "1", "0xto", "TNZO", 60);
        let p = X402PaymentPayload::new(req, serde_json::json!({ "credential_id": "c" }));
        assert!(p.exact_payload().is_err());
    }
}
