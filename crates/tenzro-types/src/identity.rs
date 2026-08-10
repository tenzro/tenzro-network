//! Identity types for the Tenzro Decentralized Identity Protocol (TDIP)
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

/// Type of identity in the Tenzro Decentralized Identity Protocol.
///
/// The protocol recognises three identity classes — the enum collapses
/// the two machine classes into a single tag, distinguished at runtime
/// by the `controller_did` field on `IdentityData::Machine`:
///
/// - **Human** (`did:tenzro:human:{uuid}`)
/// - **Delegated agent** — machine with a human controller
///   (`did:tenzro:machine:{controller}:{uuid}`)
/// - **Autonomous agent** — machine with no controller
///   (`did:tenzro:machine:{uuid}`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityType {
    /// Human identity
    Human,
    /// Machine/Agent identity (delegated or autonomous)
    Machine,
    /// Institution identity (`did:tenzro:institution:<lei>:<uuid>`).
    Institution,
}

impl IdentityType {
    /// Returns the type as a string
    pub fn as_str(&self) -> &str {
        match self {
            IdentityType::Human => "human",
            IdentityType::Machine => "machine",
            IdentityType::Institution => "institution",
        }
    }
}

impl std::fmt::Display for IdentityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Wire payload for a `RegisterIdentity` native transaction (TDIP).
///
/// Carries the **replicable** portion of an identity record — the DID, its
/// public keys, wallet bindings, and display metadata — so an identity
/// created on one node becomes consensus-state that every node re-executes
/// and converges on. Key MATERIAL (FROST shares / TEE-sealed signing keys)
/// stays node-local by design; only this public record replicates.
///
/// Mirrors the node-alias exemplar ([`crate::node_alias::NodeAlias`]): the
/// event-loop tx encoder serializes it as JSON into `tx.data[4..]` after
/// `SELECTOR_IDENTITY_REGISTER`, the VM decodes it, enforces DID uniqueness
/// against `SYSTEM_ADDRESS` storage, and re-emits it verbatim as the
/// `IdentityRegistered` log body the node-side registry mirror consumes.
///
/// Field ordering is fixed and the map is a `BTreeMap` so the JSON body is
/// deterministic across nodes — the record is part of consensus state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterIdentityPayload {
    /// The DID being registered. Uniqueness is consensus-enforced on this key.
    pub did: String,
    /// Identity class: `"human"` | `"machine"` | `"institution"`.
    pub identity_type: String,
    /// Human-readable display / legal name.
    pub display_name: String,
    /// Classical controller public key (Ed25519 / Secp256k1) — becomes
    /// `public_keys[0]` on the reconstructed identity record.
    pub controller_pubkey: Vec<u8>,
    /// Key type string for `controller_pubkey` (`"Ed25519"` / `"Secp256k1"`).
    pub key_type: String,
    /// Wallet ID bound to the identity's primary wallet.
    pub wallet_id: String,
    /// On-chain address of the identity's primary wallet.
    pub wallet_address: crate::primitives::Address,
    /// ML-DSA-65 (FIPS 204) verifying key. Empty when unset.
    #[serde(default)]
    pub pq_verifying_key: Vec<u8>,
    /// BLS12-381 G1-compressed verifying key (`min_pk`). Empty when unset.
    #[serde(default)]
    pub bls_verifying_key: Vec<u8>,
    /// Additional public metadata. `BTreeMap` for deterministic ordering.
    #[serde(default)]
    pub metadata: std::collections::BTreeMap<String, String>,
}
