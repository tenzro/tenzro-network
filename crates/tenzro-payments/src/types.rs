//! Common payment types used across all protocols

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A payment challenge issued by a server (HTTP 402 response)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentChallenge {
    /// Unique challenge ID
    pub challenge_id: String,
    /// Protocol that issued this challenge (e.g., "mpp", "x402")
    pub protocol: String,
    /// Resource being paid for
    pub resource: String,
    /// Required payment amount (in smallest unit)
    pub amount: u128,
    /// Asset/currency for payment
    pub asset: String,
    /// Recipient address or DID
    pub recipient: String,
    /// Chain to settle on
    pub chain: String,
    /// Challenge expiration
    pub expires_at: DateTime<Utc>,
    /// Additional protocol-specific data
    pub extra: HashMap<String, serde_json::Value>,
}

/// A payment credential submitted by a client
///
/// Wave 3d hybrid signing: every internal Tenzro credential carries BOTH
/// classical (Ed25519) and post-quantum (ML-DSA-65) signatures plus the
/// corresponding public keys. External-protocol passthroughs (Stripe,
/// Coinbase, EIP-3009) leave the PQ leg empty and are verified through
/// their own gateway-specific paths, not the hybrid verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCredential {
    /// Credential ID
    pub credential_id: String,
    /// Challenge this credential responds to
    pub challenge_id: String,
    /// Protocol
    pub protocol: String,
    /// Payer DID
    pub payer_did: String,
    /// Payer wallet address
    pub payer_address: String,
    /// Payment amount
    pub amount: u128,
    /// Asset
    pub asset: String,
    /// Classical Ed25519 signature over the credential message
    pub signature: Vec<u8>,
    /// Post-quantum ML-DSA-65 signature over the same canonical message
    /// (3309 bytes for internal Tenzro credentials; empty for external
    /// passthroughs verified by external facilitators).
    pub pq_signature: Vec<u8>,
    /// Payer's ML-DSA-65 verifying key (1952 bytes for internal
    /// Tenzro credentials; empty for external passthroughs).
    pub pq_public_key: Vec<u8>,
    /// Additional protocol-specific data
    pub extra: HashMap<String, serde_json::Value>,
}

/// Result of verifying a payment credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentVerification {
    /// Whether verification passed
    pub verified: bool,
    /// The credential that was verified
    pub credential_id: String,
    /// The challenge it responds to
    pub challenge_id: String,
    /// Payer identity DID
    pub payer_did: String,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
    /// Settlement reference (e.g., tx hash)
    pub settlement_ref: Option<String>,
}

/// A receipt for a completed payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentReceipt {
    /// Receipt ID
    pub receipt_id: String,
    /// Protocol used
    pub protocol: String,
    /// Challenge ID
    pub challenge_id: String,
    /// Credential ID
    pub credential_id: String,
    /// Amount settled
    pub amount: u128,
    /// Asset
    pub asset: String,
    /// Settlement transaction hash
    pub settlement_tx: Option<String>,
    /// Settlement chain
    pub chain: String,
    /// Receipt timestamp
    pub settled_at: DateTime<Utc>,
    /// Additional data
    pub extra: HashMap<String, serde_json::Value>,
}
