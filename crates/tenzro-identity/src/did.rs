//! Tenzro DID parsing and types
//!
//! Implements the `did:tenzro:` method with support for human and machine identities.
//!
//! # DID Formats
//!
//! ```text
//! did:tenzro:human:{uuid}                    — Human identity
//! did:tenzro:machine:{parent_uuid}:{uuid}    — Machine under a controller
//! did:tenzro:machine:{uuid}                  — Autonomous machine (no controller)
//! ```
//!
//! See `TDIP.md` for the full identity model.

use crate::error::{IdentityError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The type of a Tenzro DID.
///
/// The protocol recognises three identity classes; the `Machine` variant
/// covers both the delegated and autonomous sub-classes, distinguished
/// by the presence of `controller_id` on the parsed `TenzroDid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DidType {
    /// Human identity (`did:tenzro:human:{uuid}`)
    Human,
    /// Machine/agent identity — delegated (`did:tenzro:machine:{controller}:{uuid}`)
    /// or autonomous (`did:tenzro:machine:{uuid}`)
    Machine,
    /// Institution identity (`did:tenzro:institution:{lei}:{uuid}`). The 20-
    /// character LEI is the ISO 17442 Legal Entity Identifier and anchors
    /// the institution to its GLEIF record. The trailing UUID lets one
    /// legal entity hold multiple identities (e.g. one per desk / fund /
    /// subsidiary) without re-issuing LEIs.
    Institution,
}

impl fmt::Display for DidType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DidType::Human => write!(f, "human"),
            DidType::Machine => write!(f, "machine"),
            DidType::Institution => write!(f, "institution"),
        }
    }
}

/// ISO 17442 Legal Entity Identifier length (20 chars: 4 LOU + 2 reserved
/// `00` + 12 entity-specific + 2 ISO 7064 Mod 97-10 check digits).
pub const LEI_LEN: usize = 20;

/// Validate an LEI's check digits using ISO 7064 Mod 97-10. Letters convert
/// to digits via `A=10, B=11, ..., Z=35`, the resulting integer mod 97 must
/// equal 1. Implemented in streaming mod-97 to avoid the multi-precision
/// path.
pub fn validate_lei(lei: &str) -> Result<()> {
    if lei.len() != LEI_LEN {
        return Err(IdentityError::InvalidDid(format!(
            "LEI must be exactly {} characters, got {}",
            LEI_LEN,
            lei.len()
        )));
    }
    let mut rem: u32 = 0;
    for c in lei.chars() {
        let value: u32 = match c {
            '0'..='9' => c as u32 - '0' as u32,
            'A'..='Z' => 10 + (c as u32 - 'A' as u32),
            _ => {
                return Err(IdentityError::InvalidDid(format!(
                    "LEI contains illegal character: {}",
                    c
                )));
            }
        };
        if value < 10 {
            rem = (rem * 10 + value) % 97;
        } else {
            rem = (rem * 100 + value) % 97;
        }
    }
    if rem != 1 {
        return Err(IdentityError::InvalidDid(
            "LEI check digits failed ISO 7064 Mod 97-10".to_string(),
        ));
    }
    Ok(())
}

/// Whether `name` is a valid delegated-agent name: 1 to 64 characters of
/// `a-z`, `0-9`, `-`, `_` or `.`.
pub fn is_valid_agent_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        })
}

use tenzro_types::did_derivation::{
    delegated_machine_id, human_id as human_id_from_passkey,
    machine_device_id as machine_id_from_device_key,
};

/// A parsed Tenzro DID
///
/// Represents either a human or machine identity on the Tenzro network.
/// Each DID includes a unique identifier and, for machine identities,
/// an optional controller reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenzroDid {
    /// The DID type (human or machine)
    pub did_type: DidType,
    /// The unique identifier portion of the DID
    pub id: String,
    /// For machine DIDs: the controller's UUID (human that controls this machine)
    pub controller_id: Option<String>,
}

impl TenzroDid {
    /// Tests only: a human DID with a random identifier. Every production
    /// identity derives from its key ([`from_passkey`](Self::from_passkey)).
    #[cfg(test)]
    pub fn new_human() -> Self {
        Self {
            did_type: DidType::Human,
            id: uuid::Uuid::new_v4().to_string(),
            controller_id: None,
        }
    }

    /// Creates a human DID derived from the passkey credential public key.
    ///
    /// Deterministic: the same passkey always produces the same DID, so an
    /// identity survives being removed and re-enrolled unchanged — the identity
    /// is the key. The machine counterpart is [`from_device_key`](Self::from_device_key).
    pub fn from_passkey(passkey_public_key: &[u8]) -> Self {
        Self {
            did_type: DidType::Human,
            id: human_id_from_passkey(passkey_public_key),
            controller_id: None,
        }
    }

    /// Whether this DID is the one [`from_passkey`](Self::from_passkey) produces
    /// for `passkey_public_key` — the check a relying party runs to confirm the
    /// DID in front of it is the one that passkey derives.
    pub fn matches_passkey(&self, passkey_public_key: &[u8]) -> bool {
        self.did_type == DidType::Human
            && self.controller_id.is_none()
            && self.id == human_id_from_passkey(passkey_public_key)
    }

    /// A machine DID delegated by `controller_id`, derived from the machine's
    /// own device key. Two machines under one controller have two keys and
    /// therefore two DIDs; the same machine re-registering keeps its DID.
    pub fn delegated_machine(controller_id: &str, device_public_key: &[u8]) -> Result<Self> {
        if device_public_key.is_empty() {
            return Err(IdentityError::MissingHardwareRoot);
        }
        Ok(Self {
            did_type: DidType::Machine,
            id: delegated_machine_id(controller_id, device_public_key),
            controller_id: Some(controller_id.to_string()),
        })
    }

    /// The DID of the agent `agent_name` delegated by `controller_id` with a
    /// passkey. The agent has no device key; its identifier derives from the
    /// controller and the name, so `(controller, name)` is unique.
    pub fn delegated_agent(controller_id: &str, agent_name: &str) -> Result<Self> {
        use sha2::{Digest, Sha256};
        if !is_valid_agent_name(agent_name) {
            return Err(IdentityError::InvalidDid(format!(
                "agent name {agent_name:?} must be 1 to 64 characters of a-z, 0-9, '-', '_' or '.'"
            )));
        }
        let name_hash: [u8; 32] = Sha256::new()
            .chain_update(b"tenzro/agent-name")
            .chain_update(agent_name.as_bytes())
            .finalize()
            .into();
        Self::delegated_machine(controller_id, &name_hash)
    }

    /// Creates an autonomous machine DID derived from the device public key
    /// held in this machine's secure element (TPM 2.0, or the Secure Enclave
    /// on Apple hardware).
    ///
    /// This is the only autonomous machine DID: its identifier is a function
    /// of a key the machine holds (for a TPM-admitted machine, its attestation
    /// key), so the same key re-derives the same DID, a verifier recomputes it
    /// from the key presented, and nobody can claim it without that key.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MissingHardwareRoot`] when `device_public_key`
    /// is empty, which is what a caller with no secure element supplies.
    pub fn from_device_key(device_public_key: &[u8]) -> Result<Self> {
        if device_public_key.is_empty() {
            return Err(IdentityError::MissingHardwareRoot);
        }
        Ok(Self {
            did_type: DidType::Machine,
            id: machine_id_from_device_key(device_public_key),
            controller_id: None,
        })
    }

    /// LEI for institution DIDs (None for human/machine).
    pub fn lei(&self) -> Option<&str> {
        match self.did_type {
            DidType::Institution => self.controller_id.as_deref(),
            _ => None,
        }
    }

    /// Returns true if this is an institution DID.
    pub fn is_institution(&self) -> bool {
        self.did_type == DidType::Institution
    }

    /// Parses a DID string into a TenzroDid
    pub fn parse(did: &str) -> Result<Self> {
        if let Some(rest) = did.strip_prefix("did:tenzro:") {
            return Self::parse_tenzro(rest);
        }

        Err(IdentityError::InvalidDid(format!(
            "unrecognized DID method: {}",
            did
        )))
    }

    /// Parses the `did:tenzro:` portion after the method prefix
    fn parse_tenzro(rest: &str) -> Result<Self> {
        if let Some(id) = rest.strip_prefix("human:") {
            if id.is_empty() {
                return Err(IdentityError::InvalidDid(
                    "human DID missing identifier".to_string(),
                ));
            }
            Ok(Self {
                did_type: DidType::Human,
                id: id.to_string(),
                controller_id: None,
            })
        } else if let Some(rest) = rest.strip_prefix("machine:") {
            // machine:{controller_uuid}:{uuid} or machine:{uuid}
            let parts: Vec<&str> = rest.splitn(2, ':').collect();
            match parts.len() {
                1 => {
                    if parts[0].is_empty() {
                        return Err(IdentityError::InvalidDid(
                            "machine DID missing identifier".to_string(),
                        ));
                    }
                    Ok(Self {
                        did_type: DidType::Machine,
                        id: parts[0].to_string(),
                        controller_id: None,
                    })
                }
                2 => Ok(Self {
                    did_type: DidType::Machine,
                    id: parts[1].to_string(),
                    controller_id: Some(parts[0].to_string()),
                }),
                _ => Err(IdentityError::InvalidDid(format!(
                    "invalid machine DID format: {}",
                    rest
                ))),
            }
        } else if let Some(rest) = rest.strip_prefix("institution:") {
            // institution:{lei}:{uuid} — both segments required, LEI Mod 97-10
            // validated so a malformed LEI never lands in the identity registry.
            let (lei, uuid) = rest.split_once(':').ok_or_else(|| {
                IdentityError::InvalidDid(
                    "institution DID requires `institution:{lei}:{uuid}`".to_string(),
                )
            })?;
            validate_lei(lei)?;
            if uuid.is_empty() {
                return Err(IdentityError::InvalidDid(
                    "institution DID missing uuid".to_string(),
                ));
            }
            Ok(Self {
                did_type: DidType::Institution,
                id: uuid.to_string(),
                controller_id: Some(lei.to_string()),
            })
        } else {
            Err(IdentityError::InvalidDid(format!(
                "unknown DID type in did:tenzro:{}",
                rest
            )))
        }
    }

    /// Returns the full DID string in canonical `did:tenzro:` format
    pub fn to_string_canonical(&self) -> String {
        match self.did_type {
            DidType::Human => format!("did:tenzro:human:{}", self.id),
            DidType::Machine => {
                if let Some(ref controller) = self.controller_id {
                    format!("did:tenzro:machine:{}:{}", controller, self.id)
                } else {
                    format!("did:tenzro:machine:{}", self.id)
                }
            }
            DidType::Institution => {
                let lei = self.controller_id.as_deref().unwrap_or("");
                format!("did:tenzro:institution:{}:{}", lei, self.id)
            }
        }
    }

    /// Returns true if this is a human DID
    pub fn is_human(&self) -> bool {
        self.did_type == DidType::Human
    }

    /// Returns true if this is a machine DID
    pub fn is_machine(&self) -> bool {
        self.did_type == DidType::Machine
    }

    /// Returns true if this machine DID has a controller
    pub fn has_controller(&self) -> bool {
        self.controller_id.is_some()
    }
}

impl fmt::Display for TenzroDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_canonical())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_human_did() {
        let did = TenzroDid::new_human();
        assert!(did.is_human());
        assert!(!did.is_machine());
        assert!(!did.has_controller());
        assert!(did.to_string().starts_with("did:tenzro:human:"));
    }

    #[test]
    fn passkey_did_is_the_same_every_time_for_one_key() {
        // The identity is the passkey: enrol, remove, enrol again — the same
        // credential key must resolve to the identical DID, never a fresh one.
        let pubkey = vec![0xA1u8; 64];
        let a = TenzroDid::from_passkey(&pubkey);
        let b = TenzroDid::from_passkey(&pubkey);
        assert_eq!(a, b);
        assert!(a.is_human());
        assert!(!a.has_controller());
        assert!(a.matches_passkey(&pubkey));
    }

    #[test]
    fn passkey_did_separates_distinct_keys() {
        let a = TenzroDid::from_passkey(&[0x11u8; 64]);
        let b = TenzroDid::from_passkey(&[0x22u8; 64]);
        assert_ne!(a, b);
        assert!(!a.matches_passkey(&[0x22u8; 64]));
    }

    #[test]
    fn passkey_did_round_trips_through_parse() {
        let pubkey = vec![0x7Cu8; 64];
        let did = TenzroDid::from_passkey(&pubkey);
        let parsed = TenzroDid::parse(&did.to_string()).unwrap();
        assert_eq!(parsed, did);
        assert!(parsed.matches_passkey(&pubkey));
    }

    #[test]
    fn delegated_machine_did_derives_from_its_device_key() {
        let did = TenzroDid::delegated_machine("parent-uuid", &[4u8; 65]).unwrap();
        assert!(did.is_machine());
        assert!(did.has_controller());
        assert_eq!(did.controller_id, Some("parent-uuid".to_string()));
        assert!(did.to_string().contains("parent-uuid"));
        assert_eq!(
            did,
            TenzroDid::delegated_machine("parent-uuid", &[4u8; 65]).unwrap()
        );
        assert!(tenzro_types::did_derivation::did_derives_from_key(
            &did.to_string(),
            &[4u8; 65]
        ));
        assert!(!tenzro_types::did_derivation::did_derives_from_key(
            &did.to_string(),
            &[5u8; 65]
        ));
        let sibling = TenzroDid::delegated_machine("parent-uuid", &[5u8; 65]).unwrap();
        assert_ne!(
            did, sibling,
            "two machines under one controller must not collapse"
        );
        assert!(TenzroDid::delegated_machine("parent-uuid", &[]).is_err());
    }

    #[test]
    fn a_machine_without_a_key_gets_no_autonomous_identity() {
        // There is no random fallback to take instead — that is the point.
        assert!(matches!(
            TenzroDid::from_device_key(&[]),
            Err(IdentityError::MissingHardwareRoot)
        ));
    }

    #[test]
    fn device_key_did_is_reproducible_and_separates_machines() {
        let key = [0xA1u8; 32];
        let a = TenzroDid::from_device_key(&key).unwrap();
        let b = TenzroDid::from_device_key(&key).unwrap();
        assert_eq!(a, b, "same secure element must re-derive the same DID");
        assert!(tenzro_types::did_derivation::did_derives_from_key(
            &a.to_string(),
            &key
        ));
        assert!(a.is_machine());
        assert!(!a.has_controller());

        let other = TenzroDid::from_device_key(&[0xB2u8; 32]).unwrap();
        assert_ne!(a, other);
        assert!(!tenzro_types::did_derivation::did_derives_from_key(
            &a.to_string(),
            &[0xB2u8; 32]
        ));
    }

    #[test]
    fn test_parse_tenzro_human() {
        let did = TenzroDid::parse("did:tenzro:human:abc-123").unwrap();
        assert_eq!(did.did_type, DidType::Human);
        assert_eq!(did.id, "abc-123");
        assert!(did.controller_id.is_none());
    }

    #[test]
    fn test_parse_tenzro_machine_with_controller() {
        let did = TenzroDid::parse("did:tenzro:machine:parent-id:child-id").unwrap();
        assert_eq!(did.did_type, DidType::Machine);
        assert_eq!(did.id, "child-id");
        assert_eq!(did.controller_id, Some("parent-id".to_string()));
    }

    #[test]
    fn test_parse_tenzro_autonomous_machine() {
        let did = TenzroDid::parse("did:tenzro:machine:solo-id").unwrap();
        assert_eq!(did.did_type, DidType::Machine);
        assert_eq!(did.id, "solo-id");
        assert!(did.controller_id.is_none());
    }

    #[test]
    fn test_canonical_roundtrip() {
        let original = TenzroDid::delegated_machine("ctrl-123", &[1u8; 65]).unwrap();
        let canonical = original.to_string_canonical();
        let parsed = TenzroDid::parse(&canonical).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_invalid_did() {
        assert!(TenzroDid::parse("not-a-did").is_err());
        assert!(TenzroDid::parse("did:other:method:id").is_err());
        assert!(TenzroDid::parse("did:tenzro:unknown:id").is_err());
        assert!(TenzroDid::parse("did:tenzro:human:").is_err());
        assert!(TenzroDid::parse("did:tenzro:machine:").is_err());
    }

    #[test]
    fn test_has_controller() {
        let machine = TenzroDid::delegated_machine("human-id", &[1u8; 65]).unwrap();
        assert!(machine.has_controller());
        assert_eq!(machine.controller_id.as_deref(), Some("human-id"));

        let autonomous = TenzroDid::from_device_key(&[0x55u8; 65]).unwrap();
        assert!(!autonomous.has_controller());
    }

    #[test]
    fn test_display() {
        let did = TenzroDid::parse("did:tenzro:human:test-id").unwrap();
        assert_eq!(format!("{}", did), "did:tenzro:human:test-id");
    }
}
