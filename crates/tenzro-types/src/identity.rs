//! Identity types for the Tenzro Decentralized Identity Protocol (TDIP)
//!
//! TDIP is the primary identity standard. PDIS remains fully supported
//! as a secondary standard.
//!
//! This module defines foundation types used by the `tenzro-identity` crate
//! and throughout the Tenzro Network for unified human and machine identity.

use serde::{Deserialize, Serialize};

/// KYC (Know Your Customer) verification tiers for identities
///
/// Tiers are ordered by verification strength. `PartialOrd` enables
/// comparisons like `tier >= KycTier::Enhanced`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum KycTier {
    /// No verification performed (Tier 0)
    Unverified = 0,
    /// Basic email verification (Tier 1)
    Basic = 1,
    /// Enhanced verification with ID document (Tier 2)
    Enhanced = 2,
    /// Full verification with biometric + institutional verification (Tier 3)
    Full = 3,
}

impl KycTier {
    /// Returns the tier as a human-readable string
    pub fn as_str(&self) -> &str {
        match self {
            KycTier::Unverified => "unverified",
            KycTier::Basic => "basic",
            KycTier::Enhanced => "enhanced",
            KycTier::Full => "full",
        }
    }

    /// Returns the numeric tier level
    pub fn level(&self) -> u8 {
        *self as u8
    }
}

/// Payment protocol identifiers for supported payment rails
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PaymentProtocolId {
    /// Machine Payments Protocol (Stripe/Tempo)
    Mpp,
    /// x402 protocol (Coinbase)
    X402,
    /// Direct on-chain settlement (Tenzro native)
    Direct,
    /// Micropayment channel (off-chain)
    Channel,
    /// Custom protocol
    Custom(String),
}

impl PaymentProtocolId {
    /// Returns the protocol name as a string
    pub fn as_str(&self) -> &str {
        match self {
            PaymentProtocolId::Mpp => "mpp",
            PaymentProtocolId::X402 => "x402",
            PaymentProtocolId::Direct => "direct",
            PaymentProtocolId::Channel => "channel",
            PaymentProtocolId::Custom(name) => name,
        }
    }
}

impl std::fmt::Display for PaymentProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Type of identity in the Tenzro Decentralized Identity Protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityType {
    /// Human identity (formerly PDIS-1 Guardian)
    Human,
    /// Machine/Agent identity (formerly PDIS-2 Agent)
    Machine,
}

impl IdentityType {
    /// Returns the type as a string
    pub fn as_str(&self) -> &str {
        match self {
            IdentityType::Human => "human",
            IdentityType::Machine => "machine",
        }
    }
}

impl std::fmt::Display for IdentityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
