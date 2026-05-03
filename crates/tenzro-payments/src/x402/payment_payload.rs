//! x402 Payment Payload types
//!
//! Tenzro-owned wire — per pre-launch hygiene there is no `version` field on
//! the payload. The negotiated semantics are pinned by the scheme id carried
//! in the matching `X402PaymentRequirement.extra.scheme` (see
//! [`crate::x402::scheme::SchemeRegistry`]).

use serde::{Deserialize, Serialize};

/// x402 payment payload submitted by the client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentPayload {
    /// Chain used for payment
    pub chain: String,
    /// Asset used
    pub asset: String,
    /// Amount paid
    pub amount: String,
    /// Payer address
    pub payer: String,
    /// Transaction hash or signed authorization
    pub authorization: String,
    /// Signature over the payload
    pub signature: String,
}

impl X402PaymentPayload {
    /// Creates a new x402 payment payload
    pub fn new(
        chain: impl Into<String>,
        asset: impl Into<String>,
        amount: impl Into<String>,
        payer: impl Into<String>,
        authorization: impl Into<String>,
    ) -> Self {
        Self {
            chain: chain.into(),
            asset: asset.into(),
            amount: amount.into(),
            payer: payer.into(),
            authorization: authorization.into(),
            signature: String::new(),
        }
    }
}
