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
//! Tenzro also supports the secondary `did:pdis:` method (`guardian` and `agent`
//! variants) — both `did:tenzro:` and `did:pdis:` formats are parsed and
//! interoperable; PDIS DIDs are internally mapped to the same [`TenzroDid`]
//! structure. See `TDIP.md` for the full identity model.

use crate::error::{IdentityError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The type of a Tenzro DID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DidType {
    /// Human identity (formerly PDIS-1 Guardian)
    Human,
    /// Machine identity with a human controller (formerly PDIS-2 Agent)
    Machine,
}

impl fmt::Display for DidType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DidType::Human => write!(f, "human"),
            DidType::Machine => write!(f, "machine"),
        }
    }
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

    /// Parses a DID string into a TenzroDid
    ///
    /// Supports both the primary `did:tenzro:` method and the secondary
    /// `did:pdis:` method.
    pub fn parse(did: &str) -> Result<Self> {
        // Try Tenzro (primary) method first
        if let Some(rest) = did.strip_prefix("did:tenzro:") {
            return Self::parse_tenzro(rest);
        }

        // Try PDIS (secondary) method
        if let Some(rest) = did.strip_prefix("did:pdis:") {
            return Self::parse_pdis(rest);
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
        } else {
            Err(IdentityError::InvalidDid(format!(
                "unknown DID type in did:tenzro:{}",
                rest
            )))
        }
    }

    /// Parses `did:pdis:guardian:` and `did:pdis:agent:` formats (PDIS
    /// secondary DID method).
    fn parse_pdis(rest: &str) -> Result<Self> {
        if let Some(id) = rest.strip_prefix("guardian:") {
            if id.is_empty() {
                return Err(IdentityError::InvalidDid(
                    "guardian DID missing identifier".to_string(),
                ));
            }
            Ok(Self {
                did_type: DidType::Human,
                id: id.to_string(),
                controller_id: None,
            })
        } else if let Some(rest) = rest.strip_prefix("agent:") {
            // agent:{guardian_id}:{agent_id}
            let parts: Vec<&str> = rest.splitn(2, ':').collect();
            match parts.len() {
                1 => {
                    if parts[0].is_empty() {
                        return Err(IdentityError::InvalidDid(
                            "agent DID missing identifier".to_string(),
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
                    "invalid agent DID format: {}",
                    rest
                ))),
            }
        } else {
            Err(IdentityError::InvalidDid(format!(
                "unknown PDIS DID type: {}",
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
    fn test_parse_pdis_guardian() {
        let did = TenzroDid::parse("did:pdis:guardian:guardian-uuid").unwrap();
        assert_eq!(did.did_type, DidType::Human);
        assert_eq!(did.id, "guardian-uuid");
    }

    #[test]
    fn test_parse_pdis_agent() {
        let did = TenzroDid::parse("did:pdis:agent:guardian-uuid:agent-uuid").unwrap();
        assert_eq!(did.did_type, DidType::Machine);
        assert_eq!(did.id, "agent-uuid");
        assert_eq!(did.controller_id, Some("guardian-uuid".to_string()));
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
