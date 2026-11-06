//! The HTTP Payment receipt: `Payment-Receipt: <base64url JSON>` on a paid
//! response, `{status, method, timestamp, reference}`. The reference is the
//! settlement: the Tenzro Ledger transaction for a charge, or the escrow a
//! session voucher draws on.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::{PaymentError, Result};
use crate::types::PaymentReceipt;

/// Header carrying the receipt.
pub const PAYMENT_RECEIPT_HEADER: &str = "Payment-Receipt";

/// The body of `Payment-Receipt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MppReceipt {
    /// `success`.
    pub status: String,
    /// The payment method (`tenzro`).
    pub method: String,
    /// RFC 3339 settlement time.
    pub timestamp: String,
    /// The settlement reference.
    pub reference: String,
    /// The challenge paid.
    pub challenge_id: String,
}

impl MppReceipt {
    /// The receipt for a settled payment; `None` without a settlement
    /// reference.
    pub fn from_receipt(receipt: &PaymentReceipt) -> Option<Self> {
        Some(Self {
            status: "success".to_string(),
            method: "tenzro".to_string(),
            timestamp: receipt.settled_at.to_rfc3339(),
            reference: receipt.settlement_tx.clone()?,
            challenge_id: receipt.challenge_id.clone(),
        })
    }

    /// The header value.
    pub fn to_header(&self) -> Result<String> {
        let json = serde_json::to_vec(self)
            .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
    }
}
