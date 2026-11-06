//! Common payment types used across all protocols

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tenzro_types::principal_chain::PrincipalChain;

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
/// Hybrid signing: every internal Tenzro credential carries BOTH
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
    /// Composite signature over the credential message (P-256 leg, plus the
    /// ML-DSA-65 leg when the payer has one); `None` for external
    /// passthroughs verified by external facilitators.
    #[serde(default)]
    pub signature: Option<tenzro_crypto::composite::CompositeSignature>,
    /// Additional protocol-specific data
    pub extra: HashMap<String, serde_json::Value>,
}

/// A credential that passed verification.
///
/// There is no "failed" value of this type: every negative verification is an
/// `Err`, so a value reaching settlement has been verified.
#[derive(Debug, Clone)]
pub struct PaymentVerification {
    /// The credential that was verified
    pub credential_id: String,
    /// The challenge it responds to
    pub challenge_id: String,
    /// Payer identity DID as presented (confirmed against the signing key
    /// for ledger-settled payments)
    pub payer_did: String,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
    /// The charge this verification authorizes, never above the challenge
    /// amount.
    pub amount: u128,
    /// How the verified payment moves value.
    pub leg: SettlementLeg,
    /// Protocol-specific detail for the receipt (e.g. the TAP agent key id).
    pub detail: Option<String>,
}

/// How a verified payment moves value.
#[derive(Debug, Clone)]
pub enum SettlementLeg {
    /// The payer signed a Tenzro payment authorization; the gateway settles it
    /// on a settlement rail (the Tenzro Ledger for TNZO).
    Payer(crate::payer_auth::VerifiedPayer),
    /// The payer signed a cumulative voucher against an on-chain escrow it
    /// funded; the charge is the voucher's advance over the last one.
    Voucher(tenzro_types::payment_authorization::EscrowVoucher),
    /// The scheme settles on another chain through its facilitator (EIP-3009,
    /// Permit2); the protocol's `settle` returns that chain's transaction.
    Foreign,
}

/// A receipt for a completed payment.
///
/// Carries the frozen `PrincipalChain` of the payer at
/// the time of settlement, resolved from the credential's payer DID; a
/// synthetic anonymous chain when no DID is bound to the payer.
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
    /// Frozen principal chain for the payer at settlement time
    ///.
    pub principal_chain: PrincipalChain,
    /// Additional data
    pub extra: HashMap<String, serde_json::Value>,
}
