//! Mastercard Agent Pay types
//!
//! Types specific to Mastercard's agentic commerce framework with Know Your Agent
//! (KYA) verification and agentic token management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Agentic token type (maps to Mastercard MDES tokenization)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgenticTokenType {
    /// Single-use token for one transaction
    SingleUse,
    /// Session-bound token valid for a browsing session
    SessionBound,
    /// Recurring token for subscription payments
    Recurring,
}

impl std::fmt::Display for AgenticTokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgenticTokenType::SingleUse => write!(f, "single-use"),
            AgenticTokenType::SessionBound => write!(f, "session-bound"),
            AgenticTokenType::Recurring => write!(f, "recurring"),
        }
    }
}

/// Agentic token representing a tokenized payment credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticToken {
    /// Unique token identifier
    pub token_id: String,
    /// Agent DID this token is issued to
    pub agent_did: String,
    /// Token type
    pub token_type: AgenticTokenType,
    /// Encrypted token data (represents underlying payment credential)
    pub token_data: String,
    /// Issuance timestamp
    pub issued_at: DateTime<Utc>,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Domains this token is restricted to (empty = unrestricted)
    pub domain_restrictions: Vec<String>,
    /// Maximum amount limit for this token (None = unrestricted)
    pub amount_limit: Option<u128>,
}

/// Mastercard Agent Pay specific challenge data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPayChallenge {
    /// Challenge identifier
    pub challenge_id: String,
    /// Resource being purchased
    pub resource: String,
    /// Required payment amount
    pub amount: u128,
    /// Asset/currency
    pub asset: String,
    /// Recipient merchant
    pub recipient: String,
    /// Whether KYA verification is required
    pub requires_kya: bool,
    /// Required purchase intent fields
    pub required_intent_fields: Vec<String>,
    /// Merchant identifier
    pub merchant_id: String,
    /// Challenge expiration
    pub expires_at: DateTime<Utc>,
}

/// Purchase intent representing what the agent intends to purchase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurchaseIntent {
    /// Intent identifier
    pub intent_id: String,
    /// Agent DID making the purchase
    pub agent_did: String,
    /// Human-readable description of purchase
    pub description: String,
    /// List of items being purchased
    pub items: Vec<PurchaseItem>,
    /// Total amount
    pub total_amount: u128,
    /// Asset/currency
    pub asset: String,
    /// Merchant identifier
    pub merchant_id: String,
    /// Intent creation timestamp
    pub created_at: DateTime<Utc>,
    /// Optional human authorization signature (if agent is controlled)
    pub human_authorization: Option<String>,
}

/// Individual item in a purchase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurchaseItem {
    /// Item name/description
    pub name: String,
    /// Quantity
    pub quantity: u32,
    /// Unit price
    pub unit_price: u128,
}

/// Know Your Agent verification level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum KyaLevel {
    /// Agent identity not verified
    Unverified = 0,
    /// Basic verification (identity exists and is active)
    Basic = 1,
    /// Enhanced verification (controlled agent with active controller)
    Enhanced = 2,
    /// Full verification (controlled + delegation scope configured)
    Full = 3,
}

impl std::fmt::Display for KyaLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KyaLevel::Unverified => write!(f, "unverified"),
            KyaLevel::Basic => write!(f, "basic"),
            KyaLevel::Enhanced => write!(f, "enhanced"),
            KyaLevel::Full => write!(f, "full"),
        }
    }
}

/// Know Your Agent verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyaVerification {
    /// Whether verification succeeded
    pub verified: bool,
    /// Agent DID being verified
    pub agent_did: String,
    /// Controller DID (if agent is controlled)
    pub controller_did: Option<String>,
    /// Verification level achieved
    pub verification_level: KyaLevel,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
    /// Audit trail of verification steps
    pub audit_trail: Vec<String>,
}

/// Domain events for Agent Pay lifecycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentPayDomainEvent {
    /// Agent identity was verified via KYA
    IdentityVerified {
        /// Agent DID
        agent_did: String,
        /// KYA level achieved
        level: KyaLevel,
    },
    /// Authenticator bound to agent
    AuthenticatorBound {
        /// Agent DID
        agent_did: String,
        /// Key identifier
        key_id: String,
    },
    /// Agentic token issued
    AgenticTokenIssued {
        /// Token ID
        token_id: String,
        /// Agent DID
        agent_did: String,
    },
    /// Checkout initiated with purchase intent
    CheckoutInitiated {
        /// Purchase intent ID
        intent_id: String,
        /// Token used
        token_id: String,
    },
    /// Payment completed successfully
    PaymentCompleted {
        /// Receipt ID
        receipt_id: String,
        /// Amount settled
        amount: u128,
    },
}
