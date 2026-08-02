//! x402 Payment Payload types
//!
//! Coinbase x402 V2 wire format — the payment submitted by the client in the
//! `X-PAYMENT` header. The payload nests an `ExactSchemePayload` carrying the
//! EIP-3009-style `signature` + `authorization { from, to, value, valid_after,
//! valid_before, nonce }` substructure. Scheme semantics are pinned by the
//! `scheme` field; `network` is the CAIP-2 chain identifier.
//!
//! `x402Version` is Coinbase's upstream spec field, exempt from the Tenzro
//! no-version-in-identifiers rule for the same reason as other third-party
//! wire fields.

use serde::{Deserialize, Serialize};

/// Current x402 wire version, mirroring `payment_required::X402_WIRE_VERSION`.
pub const X402_WIRE_VERSION: u32 = 1;

/// The exact-scheme authorization substructure (EIP-3009 shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactAuthorization {
    /// Payer address (hex, 0x-prefixed for EVM; DID/address string otherwise).
    pub from: String,
    /// Recipient address.
    pub to: String,
    /// Amount being transferred (string for arbitrary precision).
    pub value: String,
    /// Unix timestamp after which the authorization becomes valid.
    pub valid_after: u64,
    /// Unix timestamp before which the authorization is valid.
    pub valid_before: u64,
    /// 32-byte unique nonce (hex, 0x-prefixed) to prevent replay.
    pub nonce: String,
}

/// The nested payload for the `exact*` family of schemes (Tenzro-hybrid,
/// EIP-3009, Permit2, ERC-7710). Other scheme families would introduce
/// alternative payload-shape enums alongside this one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExactSchemePayload {
    /// Signature over the canonical preimage for the scheme.
    ///
    /// - `tenzro-hybrid`: hex-encoded composite Ed25519 + ML-DSA-65 signature
    ///   (length depends on hybrid wire format).
    /// - `exact-eip3009`: 65-byte secp256k1 signature, hex-encoded.
    /// - `permit2`: 65-byte secp256k1 signature, hex-encoded.
    /// - `erc7710`: 65-byte secp256k1 signature, hex-encoded.
    pub signature: String,
    /// Authorization substructure.
    pub authorization: ExactAuthorization,
}

/// x402 payment payload submitted by the client in the `X-PAYMENT` header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentPayload {
    /// Upstream x402 wire version (Coinbase spec field).
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    /// Scheme identifier (must match the requirement scheme).
    pub scheme: String,
    /// CAIP-2 network identifier (must match the requirement network).
    pub network: String,
    /// Scheme-specific payload (currently only `ExactSchemePayload` family).
    pub payload: ExactSchemePayload,
}

impl X402PaymentPayload {
    /// Creates a new x402 payment payload.
    pub fn new(
        scheme: impl Into<String>,
        network: impl Into<String>,
        payload: ExactSchemePayload,
    ) -> Self {
        Self {
            x402_version: X402_WIRE_VERSION,
            scheme: scheme.into(),
            network: network.into(),
            payload,
        }
    }
}

impl ExactSchemePayload {
    /// Creates a new exact-scheme payload with an empty signature placeholder.
    pub fn new(authorization: ExactAuthorization) -> Self {
        Self {
            signature: String::new(),
            authorization,
        }
    }
}
