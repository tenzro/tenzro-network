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
                )))
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
    /// Creates a new human DID with a random UUID
    pub fn new_human() -> Self {
        Self {
            did_type: DidType::Human,
            id: uuid::Uuid::new_v4().to_string(),
            controller_id: None,
        }
    }

    /// Creates a new machine DID with a controller (human parent)
    pub fn new_machine(controller_id: &str) -> Self {
        Self {
            did_type: DidType::Machine,
            id: uuid::Uuid::new_v4().to_string(),
            controller_id: Some(controller_id.to_string()),
        }
    }

    /// Creates a new autonomous machine DID (no controller)
    pub fn new_autonomous_machine() -> Self {
        Self {
            did_type: DidType::Machine,
            id: uuid::Uuid::new_v4().to_string(),
            controller_id: None,
        }
    }

    /// Creates a new institution DID anchored to a GLEIF Legal Entity
    /// Identifier (ISO 17442). The LEI is validated with the Mod 97-10
    /// algorithm; an invalid LEI returns an error rather than allowing the
    /// caller to construct an unverifiable institution identity.
    pub fn new_institution(lei: &str) -> Result<Self> {
        validate_lei(lei)?;
        Ok(Self {
            did_type: DidType::Institution,
            id: uuid::Uuid::new_v4().to_string(),
            controller_id: Some(lei.to_string()),
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

    /// Returns the controller DID string if this is a controlled machine
    pub fn controller_did(&self) -> Option<String> {
        self.controller_id
            .as_ref()
            .map(|cid| format!("did:tenzro:human:{}", cid))
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
    fn test_new_machine_did_with_controller() {
        let did = TenzroDid::new_machine("parent-uuid");
        assert!(did.is_machine());
        assert!(did.has_controller());
        assert_eq!(did.controller_id, Some("parent-uuid".to_string()));
        assert!(did.to_string().contains("parent-uuid"));
    }

    #[test]
    fn test_new_autonomous_machine() {
        let did = TenzroDid::new_autonomous_machine();
        assert!(did.is_machine());
        assert!(!did.has_controller());
        assert!(did.to_string().starts_with("did:tenzro:machine:"));
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
        let original = TenzroDid::new_machine("ctrl-123");
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
    fn test_controller_did() {
        let machine = TenzroDid::new_machine("human-id");
        assert_eq!(
            machine.controller_did(),
            Some("did:tenzro:human:human-id".to_string())
        );

        let autonomous = TenzroDid::new_autonomous_machine();
        assert_eq!(autonomous.controller_did(), None);
    }

    #[test]
    fn test_display() {
        let did = TenzroDid::parse("did:tenzro:human:test-id").unwrap();
        assert_eq!(format!("{}", did), "did:tenzro:human:test-id");
    }
}
