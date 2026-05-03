//! MPP Challenge types (HTTP 402 response body)
//!
//! Tenzro-owned wire — per pre-launch hygiene there is no `version` field on
//! `MppChallenge`. The MPP interop spec (co-authored with Stripe + Tempo) is
//! still in development; once it lands a normative version field, it will be
//! reintroduced here in lock-step with the upstream definition. Until then,
//! a dead-set field would just be deserialized and ignored.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An MPP payment challenge returned in an HTTP 402 response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppChallenge {
    /// Unique challenge identifier
    pub challenge_id: String,
    /// Resource URL being paid for
    pub resource: String,
    /// Required payment amount (in smallest unit)
    pub amount: u128,
    /// Asset/currency for payment (e.g., "USDC")
    pub asset: String,
    /// Recipient address
    pub recipient: String,
    /// Settlement chain (e.g., "tempo", "tenzro")
    pub chain: String,
    /// Challenge expiration
    pub expires_at: DateTime<Utc>,
    /// Whether sessions are supported for streaming
    pub supports_sessions: bool,
    /// Additional MPP-specific fields
    pub extensions: HashMap<String, serde_json::Value>,
}

impl MppChallenge {
    /// Creates a new MPP challenge
    pub fn new(
        resource: impl Into<String>,
        amount: u128,
        asset: impl Into<String>,
        recipient: impl Into<String>,
    ) -> Self {
        Self {
            challenge_id: uuid::Uuid::new_v4().to_string(),
            resource: resource.into(),
            amount,
            asset: asset.into(),
            recipient: recipient.into(),
            chain: "tempo".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            supports_sessions: true,
            extensions: HashMap::new(),
        }
    }

    /// Sets the settlement chain
    pub fn with_chain(mut self, chain: impl Into<String>) -> Self {
        self.chain = chain.into();
        self
    }

    /// Checks if the challenge has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}
