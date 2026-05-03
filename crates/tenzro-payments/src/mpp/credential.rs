//! MPP Credential types (payment proof)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An MPP payment credential that proves payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppCredential {
    /// Credential ID
    pub credential_id: String,
    /// Challenge this responds to
    pub challenge_id: String,
    /// Payer DID
    pub payer_did: String,
    /// Payer wallet address
    pub payer_address: String,
    /// Payment amount
    pub amount: u128,
    /// Asset
    pub asset: String,
    /// Settlement chain
    pub chain: String,
    /// Signature over the credential data
    pub signature: Vec<u8>,
    /// Timestamp
    pub created_at: DateTime<Utc>,
    /// Additional fields
    pub extensions: HashMap<String, serde_json::Value>,
}

impl MppCredential {
    /// Creates a new MPP credential
    pub fn new(
        challenge_id: impl Into<String>,
        payer_did: impl Into<String>,
        payer_address: impl Into<String>,
        amount: u128,
        asset: impl Into<String>,
    ) -> Self {
        Self {
            credential_id: uuid::Uuid::new_v4().to_string(),
            challenge_id: challenge_id.into(),
            payer_did: payer_did.into(),
            payer_address: payer_address.into(),
            amount,
            asset: asset.into(),
            chain: "tempo".to_string(),
            signature: Vec::new(),
            created_at: Utc::now(),
            extensions: HashMap::new(),
        }
    }
}
