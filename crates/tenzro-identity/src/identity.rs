//! Unified identity types for the Tenzro Decentralized Identity Protocol
//!
//! The core `TenzroIdentity` struct represents both human and machine
//! identities in a single type, with identity-specific data stored in the
//! `IdentityData` enum.

use crate::did::TenzroDid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use tenzro_types::primitives::Address;

/// FIPS-204 ML-DSA-65 verifying key length (bytes).
pub const ML_DSA_65_VERIFYING_KEY_LEN: usize = 1952;

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
    // Absent is legal; wrong-length is not. An identity holds an ML-DSA-65 key
    // only once its holder adds one from hardware that can keep it; nothing
    // here mints one on its behalf.
    if !bytes.is_empty() && bytes.len() != ML_DSA_65_VERIFYING_KEY_LEN {
        return Err(serde::de::Error::custom(format!(
            "ML-DSA-65 verifying key must be exactly {} bytes when present, got {}",
            ML_DSA_65_VERIFYING_KEY_LEN,
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
    /// No party delegated it; the machine answers for itself with its own key.
    ///
    /// Its DID is derived from that key, so the identifier cannot be claimed
    /// without holding it, and every change to it needs a signature by it.
    /// Whether the key is certified as living in a manufacturer's TPM is a
    /// reputation fact recorded beside the identity, not part of the anchor.
    SelfKeyed,
}

impl MachineAnchor {
    /// The DID accountable for this machine, when a party is.
    ///
    /// `None` for a self-keyed machine: its own key answers for it, and there
    /// is no other identity to cascade a revocation through.
    pub fn controller_did(&self) -> Option<&str> {
        match self {
            MachineAnchor::Delegated { controller_did }
            | MachineAnchor::InstitutionDelegated { controller_did } => Some(controller_did),
            MachineAnchor::SelfKeyed => None,
        }
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
    /// The machine's own registered key signed the transfer.
    ///
    /// For a machine no one delegated, its key *is* the accountable party, so
    /// a signature by it is the ownership fact. The signature itself is
    /// checked by the caller before this authority is constructed.
    MachineKey,
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
                 a signature by its own key"
            ),
            Self::NotTheController { expected } => write!(
                f,
                "this machine is controlled by {expected}, and only that identity can transfer it"
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
    /// machine's controller changes; a self-keyed machine keeps its key and
    /// DID and becomes delegated to the new owner, because it now has an
    /// accountable party.
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

            // A machine nobody delegated moves on its own key's signature, and
            // becomes delegated to the new owner.
            (TransferAuthority::MachineKey, MachineAnchor::SelfKeyed) => {
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
        /// DIDs of machines controlled by this human
        controlled_machines: Vec<String>,
    },
    /// Machine identity data
    Machine {
        /// Machine capabilities (e.g., "inference", "trading", "monitoring")
        capabilities: Vec<String>,
        /// Controller DID, when a party answers for this machine. `None`
        /// means the machine answers with its own key — never that it answers
        /// to nobody.
        ///
        /// Which of the two it is was decided at registration by
        /// [`MachineAnchor`], and a machine that could satisfy neither was
        /// refused before this record existed.
        controller_did: Option<String>,
        /// Reputation score (0-1000)
        reputation: u32,
        /// Optional link to native Tenzro agent ID
        tenzro_agent_id: Option<String>,
        /// Sequential ERC-8004 `agentId` (uint256) allocated by the
        /// IdentityRegistry mirror at registration time. `None` when no
        /// mirror is wired (e.g. a node without ERC-8004 enabled) or
        /// when the mirror call failed — the TDIP record stays
        /// authoritative either way.
        erc8004_agent_id: Option<u64>,
    },
    /// Institution identity data — anchored to a GLEIF Legal Entity
    /// Identifier (ISO 17442). The institution owns a set of delegated agent
    /// DIDs via `controlled_machines`. Its KYB tier is not stored: a relying
    /// party derives it from the certifications it recognises.
    Institution {
        /// Legal name (matches the GLEIF record).
        legal_name: String,
        /// 20-character LEI (ISO 17442). The DID parser already validates
        /// the Mod 97-10 check digits before this struct is constructed.
        lei: String,
        /// Optional vLEI ACDC credential id binding this identity to its
        /// GLEIF vLEI Ecosystem Governance Framework record.
        vlei_credential_id: Option<String>,
        /// DIDs of agents controlled by this institution.
        controlled_machines: Vec<String>,
        /// Optional ISO 3166-1 alpha-2 country code (place of formation).
        country_iso2: Option<String>,
    },
}

/// A unified Tenzro identity
///
/// Represents both human and machine identities in a single type.
/// Every identity has an identity-bound wallet, a set of public keys,
/// and optional W3C DID service endpoints.
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
    /// ML-DSA-65 verifying key (FIPS 204) of the holder, or empty when the
    /// holder has none. The signing key is the holder's, never this node's.
    ///
    /// Length-validated on deserialization: empty or exactly 1952 bytes, so
    /// stored / network-received identities cannot carry a malformed PQ key.
    #[serde(deserialize_with = "validate_pq_verifying_key")]
    pub pq_verifying_key: Vec<u8>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
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

    /// Adds metadata
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
        self.updated_at = Utc::now();
    }

    /// Returns the bytes of the bound ML-DSA-65 verifying key.
    pub fn pq_verifying_key_bytes(&self) -> &[u8] {
        &self.pq_verifying_key
    }
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

    fn delegated(controller: &str) -> MachineAnchor {
        MachineAnchor::Delegated {
            controller_did: controller.to_string(),
        }
    }

    fn hardware() -> MachineAnchor {
        MachineAnchor::SelfKeyed
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
        let t = transfer("did:tenzro:human:thief", TransferAuthority::MachineKey);
        let err = t
            .authorize(&delegated("did:tenzro:human:alice"), 1_000)
            .expect_err("possession must not override delegation");
        assert_eq!(err, TransferError::WrongAuthority);
        assert!(err.to_string().contains("does not override"), "{err}");
    }

    /// A machine nobody delegated moves on its own key's signature.
    #[test]
    fn the_hardware_holder_transfers_a_machine_nobody_delegated() {
        let t = transfer("did:tenzro:human:buyer", TransferAuthority::MachineKey);
        let next = t
            .authorize(&hardware(), 1_000)
            .expect("the machine key may");
        // It now has an accountable party.
        assert_eq!(next.controller_did(), Some("did:tenzro:human:buyer"));
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pq_vk() -> Vec<u8> {
        tenzro_crypto::pq::MlDsaSigningKey::generate()
            .verifying_key_bytes()
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
                controlled_machines: Vec::new(),
            },
            status: IdentityStatus::Active,
            wallet_address: Address::new([0u8; 32]),
            wallet_id: "wallet-1".to_string(),
            pq_verifying_key: test_pq_vk(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    fn make_test_machine(controller: &str) -> TenzroIdentity {
        TenzroIdentity {
            did: TenzroDid::delegated_machine("ctrl-id", &[2; 32]).unwrap(),
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "Ed25519".to_string(),
                public_key: vec![2; 32],
                purposes: vec![KeyPurpose::Authentication],
            }],
            identity_data: IdentityData::Machine {
                capabilities: vec!["inference".to_string()],
                controller_did: Some(controller.to_string()),
                reputation: 500,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
            },
            status: IdentityStatus::Active,
            wallet_address: Address::new([1u8; 32]),
            wallet_id: "wallet-2".to_string(),
            pq_verifying_key: test_pq_vk(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_human_identity() {
        let identity = make_test_human();
        assert!(identity.is_human());
        assert!(!identity.is_machine());
        assert!(identity.is_active());
        assert_eq!(identity.display_name(), "Alice");
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
        assert!(identity.controlled_machines().is_none());
    }

    #[test]
    fn test_identity_status() {
        assert_eq!(format!("{}", IdentityStatus::Active), "active");
        assert_eq!(format!("{}", IdentityStatus::Suspended), "suspended");
        assert_eq!(format!("{}", IdentityStatus::Revoked), "revoked");
    }

    #[test]
    fn test_set_metadata() {
        let mut identity = make_test_human();
        identity.set_metadata("org", "ExampleOrg");
        assert_eq!(
            identity.metadata.get("org"),
            Some(&"ExampleOrg".to_string())
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
}
