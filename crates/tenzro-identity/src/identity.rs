//! Unified identity types for the Tenzro Decentralized Identity Protocol
//!
//! The core `TenzroIdentity` struct represents both human and machine
//! identities in a single type, with identity-specific data stored in the
//! `IdentityData` enum.

use crate::credential::VerifiableCredential;
use crate::delegation::DelegationScope;
use crate::did::TenzroDid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use tenzro_types::identity::KycTier;
use tenzro_types::primitives::Address;

/// FIPS-204 ML-DSA-65 verifying key length (bytes).
pub const ML_DSA_65_VERIFYING_KEY_LEN: usize = 1952;

/// BLS12-381 G1-compressed verifying key length (bytes), `min_pk` scheme.
///
/// Used for HotStuff-2 vote-signature aggregation per ROADMAP B.1. Every
/// identity carries this alongside the classical Ed25519 + ML-DSA-65 hybrid
/// so its wallet-bound validator key can be promoted to a HotStuff-2
/// aggregator slot without an out-of-band key handshake.
pub const BLS_G1_COMPRESSED_LEN: usize = 48;

/// Deserialize and length-validate an ML-DSA-65 verifying key.
///
/// Under the hybrid migration, every identity carries a mandatory PQ verifying
/// key. Reject any payload whose length doesn't match exactly so attackers
/// can't sneak in a truncated/expanded key.
fn validate_pq_verifying_key<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
    if bytes.len() != ML_DSA_65_VERIFYING_KEY_LEN {
        return Err(serde::de::Error::custom(format!(
            "ML-DSA-65 verifying key must be exactly {} bytes, got {}",
            ML_DSA_65_VERIFYING_KEY_LEN,
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Deserialize and length-validate a BLS12-381 G1-compressed verifying key.
///
/// HotStuff-2 BLS aggregation requires the validator's BLS public key to be
/// known at identity-resolution time. Reject any payload whose length doesn't
/// match exactly so a peer can't substitute a malformed key that would later
/// cause an aggregate signature verification panic.
fn validate_bls_verifying_key<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
    // Absent is legal; wrong-length is not.
    //
    // A BLS key exists so its holder can sign HotStuff-2 votes. Identities that
    // never vote — a human wallet rooted in a passkey — have no key and no use
    // for one, and minting one would mean this node generating and holding key
    // material the owner does not control, on an identity whose whole premise is
    // that it has exactly one root.
    //
    // Requiring 48 bytes here made every such identity unreadable the moment it
    // was written: web/wallet_new.rs and passkey_rpc.rs both store an empty vec,
    // so passkey-provisioned identities failed on this field for every read. The
    // records were never corrupt — the writer and this validator disagreed.
    //
    // Nothing is weakened by allowing empty, because the place that matters
    // already checks: validator enrolment in rpc.rs gates on !bls_vk.is_empty()
    // before adding anyone to an epoch, so a keyless identity simply never
    // becomes a validator. The invariant lives at the point of use, where it can
    // see whether this identity is claiming to vote.
    if !bytes.is_empty() && bytes.len() != BLS_G1_COMPRESSED_LEN {
        return Err(serde::de::Error::custom(format!(
            "BLS12-381 G1-compressed verifying key must be exactly {} bytes when present, got {}",
            BLS_G1_COMPRESSED_LEN,
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Status of an identity in the registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityStatus {
    /// Identity is active and can be used
    Active,
    /// Identity is temporarily suspended
    Suspended,
    /// Identity has been permanently revoked
    Revoked,
}

impl std::fmt::Display for IdentityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityStatus::Active => write!(f, "active"),
            IdentityStatus::Suspended => write!(f, "suspended"),
            IdentityStatus::Revoked => write!(f, "revoked"),
        }
    }
}

/// Information about a public key associated with an identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    /// Key identifier (e.g., "key-1")
    pub key_id: String,
    /// Key type (e.g., "Ed25519", "Secp256k1")
    pub key_type: String,
    /// The public key bytes
    pub public_key: Vec<u8>,
    /// Purposes this key can be used for
    pub purposes: Vec<KeyPurpose>,
}

/// Purposes a key can serve in the identity system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPurpose {
    /// Authentication
    Authentication,
    /// Assertion / credential signing
    AssertionMethod,
    /// Key agreement (encryption)
    KeyAgreement,
    /// Capability invocation
    CapabilityInvocation,
    /// Capability delegation
    CapabilityDelegation,
}

/// W3C DID service endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    /// Service identifier
    pub id: String,
    /// Service type (e.g., "MessagingService", "InferenceEndpoint")
    pub service_type: String,
    /// Service endpoint URL
    pub service_endpoint: String,
}

/// Identity-specific data that differs between human and machine identities
/// What holds a machine identity to the world.
///
/// A machine cannot be the sole authority for its own identity. Something has
/// to be able to answer for it — a person who delegated it, or hardware that
/// can prove which machine it is. A machine that answers only to itself is a
/// self-issued claim: nothing distinguishes it from ten thousand identical
/// claims minted by the same script, and there is nobody to hold to account
/// when it misbehaves.
///
/// So every machine identity carries one of these, and there is no third
/// option. This is the type that makes the rule impossible to bypass by
/// forgetting a check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MachineAnchor {
    /// A human delegated this machine, and remains accountable for it.
    ///
    /// The ordinary case. The controller's own identity is the accountability
    /// surface: revoking it cascades, and its delegation scope bounds what the
    /// machine may do.
    Delegated {
        /// The controlling human's DID.
        controller_did: String,
    },
    /// An institution delegated this machine.
    ///
    /// Accountability runs to a legal entity anchored by an LEI rather than to
    /// a natural person. An institution carries `controlled_machines` for
    /// exactly this purpose, so refusing it would have left that field
    /// unfillable.
    InstitutionDelegated {
        /// The controlling institution's DID.
        controller_did: String,
    },
    /// No human delegated it; a hardware root of trust stands in their place.
    ///
    /// The TPM (or equivalent secure element) takes the human's seat: it can
    /// prove *this machine* is speaking, so the identity is anchored in silicon
    /// that cannot be cloned by copying a keyfile. The machine still does not
    /// hold sole authority — the anchor is a fact about the hardware, not a
    /// claim the software can make about itself.
    ///
    /// A readable serial is **not** sufficient here. Anything running on the
    /// machine can read a fused serial, and anything anywhere can claim one;
    /// only an attestable root proves possession.
    HardwareRooted {
        /// The 32-byte machine root the anchor was derived from, hex-encoded.
        hardware_root_hex: String,
        /// Which identifier sources contributed, as
        /// [`tenzro_types::machine_id::IdentifierSource`] wire labels. At least
        /// one must grade as attestable.
        sources: Vec<String>,
    },
}

impl MachineAnchor {
    /// The DID accountable for this machine, when a party is.
    ///
    /// `None` for a hardware-rooted machine: the hardware answers for it, and
    /// there is no other identity to cascade a revocation through.
    pub fn controller_did(&self) -> Option<&str> {
        match self {
            MachineAnchor::Delegated { controller_did }
            | MachineAnchor::InstitutionDelegated { controller_did } => Some(controller_did),
            MachineAnchor::HardwareRooted { .. } => None,
        }
    }

    /// Whether a party — rather than hardware — answers for this machine.
    pub fn is_delegated(&self) -> bool {
        self.controller_did().is_some()
    }

    /// Whether this anchor is coherent enough to register.
    ///
    /// A hardware anchor must name at least one *attestable* source. A machine
    /// that could only read a fused serial has not proven anything: it has read
    /// a number that any observer could also read and any impostor could also
    /// claim.
    pub fn is_valid(&self) -> bool {
        match self {
            MachineAnchor::Delegated { controller_did }
            | MachineAnchor::InstitutionDelegated { controller_did } => !controller_did.is_empty(),
            MachineAnchor::HardwareRooted {
                hardware_root_hex,
                sources,
            } => {
                hardware_root_hex.len() == 64
                    && hardware_root_hex.chars().all(|c| c.is_ascii_hexdigit())
                    && sources.iter().any(|label| {
                        tenzro_types::machine_id::IdentifierSource::parse(label)
                            .is_some_and(|src| src.grade().is_attestable())
                    })
            }
        }
    }

    /// Why this anchor was refused, for an error a caller can act on.
    pub fn rejection_reason(&self) -> Option<&'static str> {
        if self.is_valid() {
            return None;
        }
        Some(match self {
            MachineAnchor::Delegated { .. } | MachineAnchor::InstitutionDelegated { .. } => {
                "a delegated machine must name the DID accountable for it"
            }
            MachineAnchor::HardwareRooted { .. } => {
                "a machine with no human controller must be anchored by a hardware root of trust \
                 that can prove possession — a TPM, secure enclave or secure element. A readable \
                 serial is not enough: anything on the machine can read one, and anything anywhere \
                 can claim one"
            }
        })
    }
}

/// Who authorised a change of machine ownership.
///
/// The authority required is whatever *anchors* the machine — the same fact
/// that made the identity admissible in the first place. There is no third
/// party who can move a machine, and the two authorities are not
/// interchangeable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "authority", rename_all = "snake_case")]
pub enum TransferAuthority {
    /// The delegating party authorised it.
    ///
    /// For a machine a human or institution controls, ownership is theirs to
    /// give: they are the accountable party, and possession of the hardware
    /// does not override that. Someone who gains root on a delegated machine
    /// has compromised a machine, not acquired it.
    Controller {
        /// DID of the controller signing the transfer.
        controller_did: String,
    },
    /// Whoever holds the machine's hardware root authorised it.
    ///
    /// For a machine no one delegated, the TPM *is* the accountable party, so
    /// demonstrating control of it is the ownership fact. That is the honest
    /// model for selling or decommissioning a box: the buyer ends up holding
    /// the silicon, and nothing else could distinguish them from the seller.
    HardwareRoot {
        /// The 32-byte machine root proven, hex-encoded. Must equal the root
        /// the machine is anchored on — a different TPM is a different machine.
        hardware_root_hex: String,
    },
}

/// Why an ownership transfer was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    /// The authority presented is not the one anchoring this machine.
    WrongAuthority,
    /// A controller-authorised transfer named a controller that does not
    /// control this machine.
    NotTheController {
        /// The DID that actually controls it.
        expected: String,
    },
    /// A hardware-authorised transfer proved a root this machine is not
    /// anchored on.
    WrongHardwareRoot,
    /// The new owner is empty, or is already the owner.
    InvalidNewOwner,
    /// The transfer's validity window has passed.
    Expired,
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongAuthority => write!(
                f,
                "the authority presented does not anchor this machine. A machine a human \
                 delegated moves only on that controller's authority — holding the hardware does \
                 not override an accountable party. A machine nobody delegated moves only on \
                 proof of its hardware root"
            ),
            Self::NotTheController { expected } => write!(
                f,
                "this machine is controlled by {expected}, and only that identity can transfer it"
            ),
            Self::WrongHardwareRoot => write!(
                f,
                "the hardware root proven is not the one this machine is anchored on — a \
                 different root of trust is a different machine"
            ),
            Self::InvalidNewOwner => write!(
                f,
                "the new owner must be a real identity, and a different one from the current owner"
            ),
            Self::Expired => write!(
                f,
                "this transfer's validity window has passed; issue a fresh one rather than \
                 replaying an old authorisation"
            ),
        }
    }
}

impl std::error::Error for TransferError {}

/// A request to move administrative ownership of a machine to another identity.
///
/// # Why ownership moves at all
///
/// Machines are sold, redeployed, and handed between teams. Without a transfer
/// the only ways to re-own one are to leave it under an identity that no longer
/// operates it — so the accountable party is wrong — or to re-register it,
/// which mints a second identity for one physical machine and breaks every
/// receipt that named the first.
///
/// # Ownership moves in one step
///
/// The old owner is replaced, not added to. A machine has exactly one
/// administering identity at a time; a window with two would mean two parties
/// could each issue credentials on it, and a window with none would mean an
/// unowned machine still holding keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipTransfer {
    /// The machine being transferred.
    pub machine_did: String,
    /// The identity taking ownership.
    pub new_owner_did: String,
    /// Who authorised it.
    pub authority: TransferAuthority,
    /// When the authorisation stops being valid, in milliseconds since the Unix
    /// epoch. Bounded so a signed transfer cannot be replayed later — against a
    /// machine that has since changed hands, or been decommissioned.
    pub expires_at_ms: u64,
}

impl OwnershipTransfer {
    /// Check this transfer against the machine's current anchor.
    ///
    /// Returns the anchor the machine should hold afterwards. A delegated
    /// machine's controller changes; a hardware-rooted machine keeps its root
    /// — the silicon did not move, only the identity administering it — and
    /// becomes delegated to the new owner, because it now has an accountable
    /// party where before it had only hardware.
    ///
    /// # Errors
    ///
    /// [`TransferError`] naming the single unmet requirement.
    pub fn authorize(
        &self,
        current: &MachineAnchor,
        now_ms: u64,
    ) -> Result<MachineAnchor, TransferError> {
        if now_ms >= self.expires_at_ms {
            return Err(TransferError::Expired);
        }
        if self.new_owner_did.trim().is_empty() {
            return Err(TransferError::InvalidNewOwner);
        }
        if current.controller_did() == Some(self.new_owner_did.as_str()) {
            return Err(TransferError::InvalidNewOwner);
        }

        match (&self.authority, current) {
            // A delegated machine moves on its controller's authority alone.
            (
                TransferAuthority::Controller { controller_did },
                MachineAnchor::Delegated {
                    controller_did: actual,
                }
                | MachineAnchor::InstitutionDelegated {
                    controller_did: actual,
                },
            ) => {
                if controller_did != actual {
                    return Err(TransferError::NotTheController {
                        expected: actual.clone(),
                    });
                }
                Ok(MachineAnchor::Delegated {
                    controller_did: self.new_owner_did.clone(),
                })
            }

            // A machine nobody delegated moves on proof of its hardware root.
            (
                TransferAuthority::HardwareRoot { hardware_root_hex },
                MachineAnchor::HardwareRooted {
                    hardware_root_hex: actual,
                    sources,
                },
            ) => {
                if hardware_root_hex != actual {
                    return Err(TransferError::WrongHardwareRoot);
                }
                // The root is retained: this is the same machine, and it must
                // still be able to prove that after changing hands. What
                // changes is that it now has an accountable party.
                let _ = sources;
                Ok(MachineAnchor::Delegated {
                    controller_did: self.new_owner_did.clone(),
                })
            }

            // Anything else is an authority that does not anchor this machine.
            _ => Err(TransferError::WrongAuthority),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum IdentityData {
    /// Human identity data
    Human {
        /// Display name
        display_name: String,
        /// KYC verification tier
        kyc_tier: KycTier,
        /// DIDs of machines controlled by this human
        controlled_machines: Vec<String>,
    },
    /// Machine identity data
    Machine {
        /// Machine capabilities (e.g., "inference", "trading", "monitoring")
        capabilities: Vec<String>,
        /// Delegation scope from controller
        delegation_scope: DelegationScope,
        /// Controller DID, when a party rather than hardware answers for this
        /// machine. `None` means the machine is hardware-anchored — never that
        /// it answers to nobody.
        ///
        /// Which of the two it is was decided at registration by
        /// [`MachineAnchor`], and a machine that could satisfy neither was
        /// refused before this record existed.
        controller_did: Option<String>,
        /// Reputation score (0-1000)
        reputation: u32,
        /// Optional link to native Tenzro agent ID
        tenzro_agent_id: Option<String>,
        /// Immutable flag set at registration time when this machine is a
        /// protocol-owned SeedAgent (Agent-Swarm Spec 10). SeedAgents are
        /// counterparty-filtered out of other SeedAgent transactions and
        /// excluded from "organic activity" metrics. This flag is set
        /// once at provisioning and never mutated; reverting it would
        /// allow wash trading. Default `false` for ordinary machines.
        is_seed_agent: bool,
        /// Sequential ERC-8004 `agentId` (uint256) allocated by the
        /// IdentityRegistry mirror at registration time. `None` when no
        /// mirror is wired (e.g. a node without ERC-8004 enabled) or
        /// when the mirror call failed — the TDIP record stays
        /// authoritative either way.
        erc8004_agent_id: Option<u64>,
    },
    /// Institution identity data — anchored to a GLEIF Legal Entity
    /// Identifier (ISO 17442). The institution can hold any KYC tier and
    /// owns a set of delegated agent DIDs via `controlled_machines`.
    Institution {
        /// Legal name (matches the GLEIF record).
        legal_name: String,
        /// 20-character LEI (ISO 17442). The DID parser already validates
        /// the Mod 97-10 check digits before this struct is constructed.
        lei: String,
        /// KYB verification tier (re-uses `KycTier` so downstream
        /// rate-limit + privilege gates stay uniform).
        kyb_tier: KycTier,
        /// Optional vLEI ACDC credential id binding this identity to its
        /// GLEIF vLEI Ecosystem Governance Framework record.
        vlei_credential_id: Option<String>,
        /// DIDs of agents controlled by this institution.
        controlled_machines: Vec<String>,
        /// Optional ISO 3166-1 alpha-2 country code (place of formation).
        country_iso2: Option<String>,
    },
}

/// A signable wallet bound to an identity beyond its primary wallet.
///
/// D2b: an identity may hold more than one MPC wallet so a lost or corrupt
/// wallet is a degraded state, not a full lockout. The primary wallet still
/// lives directly on [`TenzroIdentity`] (`wallet_id` / `wallet_address` and
/// the two verifying keys); each *additional* wallet an identity accrues via
/// `tenzro_addWallet` is recorded as one of these, keyed by DID in the
/// registry's wallet index.
///
/// Every field mirrors the per-wallet material the primary carries, so
/// `tenzro_setPrimaryWallet` can promote an additional wallet to primary by a
/// straight swap — including the ML-DSA-65 and BLS verifying keys the identity
/// exposes for hybrid auth and HotStuff-2 vote aggregation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletRef {
    /// Wallet ID for signing operations (resolvable by the shared `WalletService`).
    pub wallet_id: String,
    /// On-chain address this wallet owns — matched against a request's `from`.
    pub address: Address,
    /// ML-DSA-65 (FIPS 204) verifying key bound to this wallet.
    #[serde(default)]
    pub pq_verifying_key: Vec<u8>,
    /// BLS12-381 G1-compressed verifying key (`min_pk`) bound to this wallet.
    #[serde(default)]
    pub bls_verifying_key: Vec<u8>,
}

/// A unified Tenzro identity
///
/// Represents both human and machine identities in a single type.
/// Every identity has an auto-provisioned MPC wallet, a set of public keys,
/// verifiable credentials, and optional W3C DID service endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenzroIdentity {
    /// The DID for this identity
    pub did: TenzroDid,
    /// Public keys associated with this identity
    pub public_keys: Vec<PublicKeyInfo>,
    /// Identity-specific data (Human or Machine)
    pub identity_data: IdentityData,
    /// Current status
    pub status: IdentityStatus,
    /// Auto-provisioned wallet address
    pub wallet_address: Address,
    /// Wallet ID for signing operations
    pub wallet_id: String,
    /// ML-DSA-65 verifying key (FIPS 204) bound to this identity's wallet.
    ///
    /// Mandatory under the hybrid migration — every identity exposes both
    /// its classical key (in `public_keys`) and its post-quantum verifying key.
    /// The corresponding signing key lives in the wallet keystore and is only
    /// loaded for signing operations.
    ///
    /// Length-validated on deserialization to be exactly 1952 bytes, so
    /// stored / network-received identities cannot carry a malformed PQ key.
    #[serde(deserialize_with = "validate_pq_verifying_key")]
    pub pq_verifying_key: Vec<u8>,
    /// BLS12-381 G1-compressed verifying key (48 bytes, `min_pk` scheme) bound
    /// to this identity's wallet.
    ///
    /// Mandatory under ROADMAP B.1: every identity exposes a BLS public key so
    /// the corresponding signing key can sign HotStuff-2 votes that aggregate
    /// into a single threshold signature per QC. The signing key lives in the
    /// wallet keystore alongside the Ed25519 + ML-DSA-65 hybrid.
    ///
    /// Length-validated on deserialization to be exactly 48 bytes.
    #[serde(deserialize_with = "validate_bls_verifying_key")]
    pub bls_verifying_key: Vec<u8>,
    /// Verifiable credentials held by this identity
    pub credentials: Vec<VerifiableCredential>,
    /// W3C DID service endpoints
    pub services: Vec<ServiceEndpoint>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Optional unique username (lowercase alphanumeric + underscores, 3-20 chars)
    ///
    /// `default` but deliberately **not** `skip_serializing_if`:
    /// [`TenzroIdentity::to_bytes`] is bincode, and `skip_serializing_if` drops
    /// the field from the output while the derived `Deserialize` still expects
    /// it. In a self-describing format the decoder matches on field names and
    /// copes; in bincode the stream desynchronises, so every identity without a
    /// username failed to decode from its own canonical bytes with
    /// `UnexpectedEof`.
    #[serde(default)]
    pub username: Option<String>,
}

impl TenzroIdentity {
    /// Returns true if this identity is a human identity
    pub fn is_human(&self) -> bool {
        matches!(self.identity_data, IdentityData::Human { .. })
    }

    /// Returns true if this identity is a machine identity
    pub fn is_machine(&self) -> bool {
        matches!(self.identity_data, IdentityData::Machine { .. })
    }

    /// Returns true if this identity is an institution identity.
    pub fn is_institution(&self) -> bool {
        matches!(self.identity_data, IdentityData::Institution { .. })
    }

    /// Returns the LEI for institution identities (None otherwise).
    pub fn lei(&self) -> Option<&str> {
        match &self.identity_data {
            IdentityData::Institution { lei, .. } => Some(lei),
            _ => None,
        }
    }

    /// Returns true if the identity is active
    pub fn is_active(&self) -> bool {
        self.status == IdentityStatus::Active
    }

    /// Returns the DID as a string
    pub fn did_string(&self) -> String {
        self.did.to_string()
    }

    /// Serializes the identity to bytes using bincode — the canonical
    /// CF_IDENTITIES persistence format shared with the registry's
    /// write-through and startup hydration paths.
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserializes an identity from canonical bincode bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Returns the display name (for humans / institutions) or the DID
    /// (for machines).
    pub fn display_name(&self) -> String {
        match &self.identity_data {
            IdentityData::Human { display_name, .. } => display_name.clone(),
            IdentityData::Machine { .. } => self.did.to_string(),
            IdentityData::Institution { legal_name, .. } => legal_name.clone(),
        }
    }

    /// Returns the KYC tier if this is a human identity, or the KYB tier
    /// if this is an institution identity.
    pub fn kyc_tier(&self) -> Option<KycTier> {
        match &self.identity_data {
            IdentityData::Human { kyc_tier, .. } => Some(*kyc_tier),
            IdentityData::Institution { kyb_tier, .. } => Some(*kyb_tier),
            IdentityData::Machine { .. } => None,
        }
    }

    /// Returns the delegation scope if this is a machine identity
    pub fn delegation_scope(&self) -> Option<&DelegationScope> {
        match &self.identity_data {
            IdentityData::Machine {
                delegation_scope, ..
            } => Some(delegation_scope),
            _ => None,
        }
    }

    /// Returns the controller DID if this is a controlled machine
    pub fn controller_did(&self) -> Option<&str> {
        match &self.identity_data {
            IdentityData::Machine { controller_did, .. } => controller_did.as_deref(),
            _ => None,
        }
    }

    /// Returns the list of machine DIDs controlled by this human or
    /// institution.
    pub fn controlled_machines(&self) -> Option<&[String]> {
        match &self.identity_data {
            IdentityData::Human {
                controlled_machines,
                ..
            } => Some(controlled_machines),
            IdentityData::Institution {
                controlled_machines,
                ..
            } => Some(controlled_machines),
            IdentityData::Machine { .. } => None,
        }
    }

    /// Returns true if this identity is a protocol-owned SeedAgent
    /// (Agent-Swarm Spec 10). Always `false` for human identities and
    /// for ordinary machine identities; `true` only for machines
    /// provisioned by the SeedAgent controller at registration time.
    pub fn is_seed_agent(&self) -> bool {
        match &self.identity_data {
            IdentityData::Machine { is_seed_agent, .. } => *is_seed_agent,
            _ => false,
        }
    }

    /// Returns the sequential ERC-8004 `agentId` allocated for this
    /// machine identity by the on-chain IdentityRegistry mirror, if any.
    /// `None` for humans, institutions, for machines registered without a
    /// mirror, and for machines whose mirror call failed.
    pub fn erc8004_agent_id(&self) -> Option<u64> {
        match &self.identity_data {
            IdentityData::Machine {
                erc8004_agent_id, ..
            } => *erc8004_agent_id,
            _ => None,
        }
    }

    /// Set the ERC-8004 `agentId` returned by the on-chain mirror.
    /// Idempotent — overwrites any previous value. No-op for humans.
    pub(crate) fn set_erc8004_agent_id(&mut self, id: u64) {
        if let IdentityData::Machine {
            erc8004_agent_id, ..
        } = &mut self.identity_data
        {
            *erc8004_agent_id = Some(id);
        }
    }

    /// Adds a service endpoint after validating the URL.
    ///
    /// Returns `InvalidServiceEndpoint` if the URL is malformed,
    /// uses a disallowed scheme, or exceeds length limits.
    pub fn add_service(&mut self, service: ServiceEndpoint) -> crate::error::Result<()> {
        tenzro_types::validation::validate_service_endpoint_url(&service.service_endpoint)
            .map_err(|e| crate::error::IdentityError::InvalidServiceEndpoint(e.to_string()))?;

        self.services.push(service);
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Adds a credential
    pub fn add_credential(&mut self, credential: VerifiableCredential) {
        self.credentials.push(credential);
        self.updated_at = Utc::now();
    }

    /// Adds metadata
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
        self.updated_at = Utc::now();
    }

    /// Validates and sets a username on this identity.
    ///
    /// Usernames must be lowercase alphanumeric with underscores, 3-20 characters,
    /// and must not start or end with an underscore.
    pub fn set_username(&mut self, username: &str) -> crate::error::Result<()> {
        validate_username(username)?;
        self.username = Some(username.to_string());
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Returns the username if set
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Returns the bytes of the bound ML-DSA-65 verifying key.
    pub fn pq_verifying_key_bytes(&self) -> &[u8] {
        &self.pq_verifying_key
    }

    /// Returns the bytes of the bound BLS12-381 G1-compressed verifying key.
    pub fn bls_verifying_key_bytes(&self) -> &[u8] {
        &self.bls_verifying_key
    }
}

/// Validates a username against the Tenzro naming rules.
///
/// Rules:
/// - 3 to 20 characters
/// - Lowercase alphanumeric and underscores only
/// - Must not start or end with an underscore
pub fn validate_username(username: &str) -> crate::error::Result<()> {
    if username.len() < 3 {
        return Err(crate::error::IdentityError::UsernameInvalid(
            "username must be at least 3 characters".to_string(),
        ));
    }
    if username.len() > 20 {
        return Err(crate::error::IdentityError::UsernameInvalid(
            "username must be at most 20 characters".to_string(),
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(crate::error::IdentityError::UsernameInvalid(
            "username must contain only lowercase letters, digits, and underscores".to_string(),
        ));
    }
    if username.starts_with('_') || username.ends_with('_') {
        return Err(crate::error::IdentityError::UsernameInvalid(
            "username must not start or end with an underscore".to_string(),
        ));
    }
    Ok(())
}

/// Entry for a revoked identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// DID that was revoked
    pub did: String,
    /// Timestamp of revocation
    pub revoked_at: DateTime<Utc>,
    /// Reason for revocation
    pub reason: String,
    /// DID of the entity that performed the revocation
    pub revoked_by: String,
}

#[cfg(test)]
mod ownership_transfer_tests {
    use super::*;

    const ROOT: &str = "ab";
    fn root_hex() -> String {
        ROOT.repeat(32)
    }

    fn delegated(controller: &str) -> MachineAnchor {
        MachineAnchor::Delegated {
            controller_did: controller.to_string(),
        }
    }

    fn hardware() -> MachineAnchor {
        MachineAnchor::HardwareRooted {
            hardware_root_hex: root_hex(),
            sources: vec!["tpm:ek".to_string()],
        }
    }

    fn transfer(to: &str, authority: TransferAuthority) -> OwnershipTransfer {
        OwnershipTransfer {
            machine_did: "did:tenzro:machine:box".to_string(),
            new_owner_did: to.to_string(),
            authority,
            expires_at_ms: 10_000,
        }
    }

    /// The ordinary case: the accountable party hands the machine on.
    #[test]
    fn a_controller_transfers_the_machine_it_controls() {
        let t = transfer(
            "did:tenzro:human:bob",
            TransferAuthority::Controller {
                controller_did: "did:tenzro:human:alice".into(),
            },
        );
        let next = t
            .authorize(&delegated("did:tenzro:human:alice"), 1_000)
            .expect("the controller may transfer");
        assert_eq!(next.controller_did(), Some("did:tenzro:human:bob"));
    }

    /// Someone who gains root on a delegated machine has compromised a machine,
    /// not acquired it. Possession must not override an accountable party.
    #[test]
    fn holding_the_hardware_cannot_take_a_delegated_machine() {
        let t = transfer(
            "did:tenzro:human:thief",
            TransferAuthority::HardwareRoot {
                hardware_root_hex: root_hex(),
            },
        );
        let err = t
            .authorize(&delegated("did:tenzro:human:alice"), 1_000)
            .expect_err("possession must not override delegation");
        assert_eq!(err, TransferError::WrongAuthority);
        assert!(err.to_string().contains("does not override"), "{err}");
    }

    /// A machine nobody delegated moves on proof of its hardware root — the
    /// honest model for selling a box.
    #[test]
    fn the_hardware_holder_transfers_a_machine_nobody_delegated() {
        let t = transfer(
            "did:tenzro:human:buyer",
            TransferAuthority::HardwareRoot {
                hardware_root_hex: root_hex(),
            },
        );
        let next = t.authorize(&hardware(), 1_000).expect("the TPM holder may");
        // It now has an accountable party where before it had only hardware.
        assert_eq!(next.controller_did(), Some("did:tenzro:human:buyer"));
        assert!(next.is_delegated());
    }

    /// A different root of trust is a different machine.
    #[test]
    fn a_transfer_proving_the_wrong_root_is_refused() {
        let t = transfer(
            "did:tenzro:human:buyer",
            TransferAuthority::HardwareRoot {
                hardware_root_hex: "cd".repeat(32),
            },
        );
        assert_eq!(
            t.authorize(&hardware(), 1_000),
            Err(TransferError::WrongHardwareRoot)
        );
    }

    /// A controller who does not control this machine cannot move it.
    #[test]
    fn a_stranger_claiming_to_be_the_controller_is_refused() {
        let t = transfer(
            "did:tenzro:human:bob",
            TransferAuthority::Controller {
                controller_did: "did:tenzro:human:mallory".into(),
            },
        );
        let err = t
            .authorize(&delegated("did:tenzro:human:alice"), 1_000)
            .expect_err("only the real controller may transfer");
        assert_eq!(
            err,
            TransferError::NotTheController {
                expected: "did:tenzro:human:alice".into()
            }
        );
    }

    /// A controller signature cannot move a machine that has no controller —
    /// there is nothing for it to have authorised.
    #[test]
    fn a_controller_cannot_move_a_machine_that_has_none() {
        let t = transfer(
            "did:tenzro:human:bob",
            TransferAuthority::Controller {
                controller_did: "did:tenzro:human:alice".into(),
            },
        );
        assert_eq!(
            t.authorize(&hardware(), 1_000),
            Err(TransferError::WrongAuthority)
        );
    }

    /// Replaying an old authorisation against a machine that has since changed
    /// hands is the reason the window exists.
    #[test]
    fn an_expired_authorisation_is_refused() {
        let t = transfer(
            "did:tenzro:human:bob",
            TransferAuthority::Controller {
                controller_did: "did:tenzro:human:alice".into(),
            },
        );
        assert_eq!(
            t.authorize(&delegated("did:tenzro:human:alice"), 10_000),
            Err(TransferError::Expired),
            "expiry is exclusive"
        );
        t.authorize(&delegated("did:tenzro:human:alice"), 9_999)
            .expect("still inside the window");
    }

    #[test]
    fn a_transfer_to_the_current_owner_or_to_nobody_is_refused() {
        let to_self = transfer(
            "did:tenzro:human:alice",
            TransferAuthority::Controller {
                controller_did: "did:tenzro:human:alice".into(),
            },
        );
        assert_eq!(
            to_self.authorize(&delegated("did:tenzro:human:alice"), 1_000),
            Err(TransferError::InvalidNewOwner)
        );

        let to_nobody = transfer(
            "   ",
            TransferAuthority::Controller {
                controller_did: "did:tenzro:human:alice".into(),
            },
        );
        assert_eq!(
            to_nobody.authorize(&delegated("did:tenzro:human:alice"), 1_000),
            Err(TransferError::InvalidNewOwner)
        );
    }

    /// An institution's machine moves on the institution's authority, the same
    /// way a person's does.
    #[test]
    fn an_institution_transfers_its_own_machine() {
        let anchor = MachineAnchor::InstitutionDelegated {
            controller_did: "did:tenzro:institution:acme".into(),
        };
        let t = transfer(
            "did:tenzro:human:bob",
            TransferAuthority::Controller {
                controller_did: "did:tenzro:institution:acme".into(),
            },
        );
        let next = t.authorize(&anchor, 1_000).expect("the institution may");
        assert_eq!(next.controller_did(), Some("did:tenzro:human:bob"));
    }

    /// Ownership replaces, never accumulates: a machine has exactly one
    /// administering identity at a time.
    #[test]
    fn ownership_replaces_rather_than_accumulating() {
        let mut anchor = delegated("did:tenzro:human:alice");
        for owner in ["did:tenzro:human:bob", "did:tenzro:human:carol"] {
            let previous = anchor.controller_did().expect("a controller").to_string();
            let t = transfer(
                owner,
                TransferAuthority::Controller {
                    controller_did: previous.clone(),
                },
            );
            anchor = t.authorize(&anchor, 1_000).expect("each hop authorises");
            assert_eq!(anchor.controller_did(), Some(owner));
        }
        // And the party who held it two hops ago can no longer move it.
        let stale = transfer(
            "did:tenzro:human:mallory",
            TransferAuthority::Controller {
                controller_did: "did:tenzro:human:alice".into(),
            },
        );
        assert!(stale.authorize(&anchor, 1_000).is_err());
    }

    /// Whatever the transfer produces must still be a valid anchor, or the
    /// machine would end up in a state registration would have refused.
    #[test]
    fn the_resulting_anchor_is_always_valid() {
        let from_hardware = transfer(
            "did:tenzro:human:buyer",
            TransferAuthority::HardwareRoot {
                hardware_root_hex: root_hex(),
            },
        )
        .authorize(&hardware(), 1_000)
        .expect("authorised");
        assert!(from_hardware.is_valid());
        assert!(from_hardware.rejection_reason().is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pq_vk() -> Vec<u8> {
        tenzro_crypto::pq::MlDsaSigningKey::generate()
            .verifying_key_bytes()
            .to_vec()
    }

    fn test_bls_vk() -> Vec<u8> {
        tenzro_crypto::bls::BlsKeyPair::generate()
            .unwrap()
            .public_key()
            .to_bytes()
            .to_vec()
    }

    fn make_test_human() -> TenzroIdentity {
        TenzroIdentity {
            did: TenzroDid::new_human(),
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "Ed25519".to_string(),
                public_key: vec![1; 32],
                purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod],
            }],
            identity_data: IdentityData::Human {
                display_name: "Alice".to_string(),
                kyc_tier: KycTier::Enhanced,
                controlled_machines: Vec::new(),
            },
            status: IdentityStatus::Active,
            wallet_address: Address::new([0u8; 32]),
            wallet_id: "wallet-1".to_string(),
            pq_verifying_key: test_pq_vk(),
            bls_verifying_key: test_bls_vk(),
            credentials: Vec::new(),
            services: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
            username: None,
        }
    }

    fn make_test_machine(controller: &str) -> TenzroIdentity {
        TenzroIdentity {
            did: TenzroDid::new_machine("ctrl-id"),
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "Ed25519".to_string(),
                public_key: vec![2; 32],
                purposes: vec![KeyPurpose::Authentication],
            }],
            identity_data: IdentityData::Machine {
                capabilities: vec!["inference".to_string()],
                delegation_scope: DelegationScope::unrestricted(),
                controller_did: Some(controller.to_string()),
                reputation: 500,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
                is_seed_agent: false,
            },
            status: IdentityStatus::Active,
            wallet_address: Address::new([1u8; 32]),
            wallet_id: "wallet-2".to_string(),
            pq_verifying_key: test_pq_vk(),
            bls_verifying_key: test_bls_vk(),
            credentials: Vec::new(),
            services: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
            username: None,
        }
    }

    #[test]
    fn test_human_identity() {
        let identity = make_test_human();
        assert!(identity.is_human());
        assert!(!identity.is_machine());
        assert!(identity.is_active());
        assert_eq!(identity.display_name(), "Alice");
        assert_eq!(identity.kyc_tier(), Some(KycTier::Enhanced));
        assert!(identity.delegation_scope().is_none());
        assert!(identity.controller_did().is_none());
        assert_eq!(identity.controlled_machines().unwrap().len(), 0);
    }

    #[test]
    fn test_machine_identity() {
        let identity = make_test_machine("did:tenzro:human:alice");
        assert!(identity.is_machine());
        assert!(!identity.is_human());
        assert!(identity.is_active());
        assert_eq!(identity.controller_did(), Some("did:tenzro:human:alice"));
        assert!(identity.delegation_scope().is_some());
        assert!(identity.kyc_tier().is_none());
        assert!(identity.controlled_machines().is_none());
    }

    #[test]
    fn test_identity_status() {
        assert_eq!(format!("{}", IdentityStatus::Active), "active");
        assert_eq!(format!("{}", IdentityStatus::Suspended), "suspended");
        assert_eq!(format!("{}", IdentityStatus::Revoked), "revoked");
    }

    #[test]
    fn test_add_service() {
        let mut identity = make_test_human();
        identity
            .add_service(ServiceEndpoint {
                id: "svc-1".to_string(),
                service_type: "InferenceEndpoint".to_string(),
                service_endpoint: "https://example.com/inference".to_string(),
            })
            .unwrap();
        assert_eq!(identity.services.len(), 1);
    }

    #[test]
    fn test_add_service_rejects_invalid_url() {
        let mut identity = make_test_human();
        let result = identity.add_service(ServiceEndpoint {
            id: "svc-bad".to_string(),
            service_type: "InferenceEndpoint".to_string(),
            service_endpoint: "ftp://files.example.com/model".to_string(),
        });
        assert!(result.is_err());
        assert_eq!(identity.services.len(), 0);
    }

    #[test]
    fn test_add_service_rejects_empty_url() {
        let mut identity = make_test_human();
        assert!(
            identity
                .add_service(ServiceEndpoint {
                    id: "svc-bad".to_string(),
                    service_type: "InferenceEndpoint".to_string(),
                    service_endpoint: "".to_string(),
                })
                .is_err()
        );
    }

    #[test]
    fn test_set_metadata() {
        let mut identity = make_test_human();
        identity.set_metadata("org", "TenzroLabs");
        assert_eq!(
            identity.metadata.get("org"),
            Some(&"TenzroLabs".to_string())
        );
    }

    #[test]
    fn test_identity_serialization() {
        let identity = make_test_human();
        let bytes = identity.to_bytes().unwrap();
        assert!(!bytes.is_empty());

        let deserialized = TenzroIdentity::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.did.to_string(), identity.did.to_string());
        assert_eq!(deserialized.display_name(), identity.display_name());
        assert_eq!(deserialized.status, identity.status);
    }

    #[test]
    fn test_machine_identity_serialization() {
        let identity = make_test_machine("did:tenzro:human:ctrl");
        let bytes = identity.to_bytes().unwrap();
        let deserialized = TenzroIdentity::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.controller_did(), identity.controller_did());
        assert!(deserialized.is_machine());
    }
    /// A passkey-provisioned identity carries no BLS key, and must still load.
    ///
    /// The regression that made every wallet identity unreadable:
    /// web/wallet_new.rs writes bls_verifying_key: Vec::new(), and the
    /// deserializer demanded 48 bytes, so the record failed on its last
    /// mandatory field on every read. Nothing was corrupt — the writer and the
    /// reader disagreed from the start.
    #[test]
    fn identity_without_bls_key_round_trips() {
        let mut identity = make_test_human();
        identity.bls_verifying_key = Vec::new();

        let bytes = bincode::serialize(&identity).expect("serialize");
        let back: TenzroIdentity = bincode::deserialize(&bytes).expect("deserialize");
        assert!(back.bls_verifying_key.is_empty());
    }

    /// Present-but-wrong-length is still rejected. Absent means "does not vote";
    /// 47 bytes means a truncated key, which must never load silently.
    #[test]
    fn identity_with_malformed_bls_key_is_rejected() {
        let mut identity = make_test_human();
        identity.bls_verifying_key = vec![0u8; BLS_G1_COMPRESSED_LEN - 1];

        let bytes = bincode::serialize(&identity).expect("serialize");
        let err = bincode::deserialize::<TenzroIdentity>(&bytes)
            .expect_err("a truncated BLS key must not deserialize");
        assert!(
            err.to_string().contains("when present"),
            "unexpected: {err}"
        );
    }

    /// A correct key still round-trips, so validators are unaffected.
    #[test]
    fn identity_with_valid_bls_key_round_trips() {
        let mut identity = make_test_human();
        identity.bls_verifying_key = vec![7u8; BLS_G1_COMPRESSED_LEN];

        let bytes = bincode::serialize(&identity).expect("serialize");
        let back: TenzroIdentity = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(back.bls_verifying_key.len(), BLS_G1_COMPRESSED_LEN);
    }
}
