//! MPP Receipt types (payment confirmation)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An MPP receipt confirming payment was received and settled
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppReceipt {
    /// Receipt ID
    pub receipt_id: String,
    /// Credential ID this receipt is for
    pub credential_id: String,
    /// Challenge ID
    pub challenge_id: String,
    /// Amount settled
    pub amount: u128,
    /// Asset
    pub asset: String,
    /// Settlement transaction hash (if on-chain)
    pub settlement_tx: Option<String>,
    /// Settlement chain
    pub chain: String,
    /// Receipt timestamp
    pub settled_at: DateTime<Utc>,
}

impl MppReceipt {
    /// Creates a new MPP receipt
    pub fn new(credential_id: impl Into<String>, challenge_id: impl Into<String>, amount: u128) -> Self {
        Self {
            receipt_id: uuid::Uuid::new_v4().to_string(),
            credential_id: credential_id.into(),
            challenge_id: challenge_id.into(),
            amount,
            asset: "USDC".to_string(),
            settlement_tx: None,
            chain: "tempo".to_string(),
            settled_at: Utc::now(),
        }
    }
}
