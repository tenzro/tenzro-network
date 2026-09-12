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

/// Domain separation tag for machine identifiers derived from a hardware root.
const MACHINE_DID_DOMAIN: &[u8] = b"tenzro/machine-did";

/// Domain separation tag for human identifiers derived from a passkey.
const HUMAN_DID_DOMAIN: &[u8] = b"tenzro/human-did";

/// Domain separation tag for machine identifiers derived from a secure
/// element's device key.
///
/// Separate from [`MACHINE_DID_DOMAIN`] so that a machine identified by its
/// device key and one identified by its platform root cannot be made to
/// collide by feeding one derivation the other's input.
const MACHINE_DEVICE_KEY_DID_DOMAIN: &[u8] = b"tenzro/machine-did/device-key";

/// Derives the identifier portion of a human DID from the passkey credential
/// public key that roots the identity.
///
/// A human's identity is their passkey, exactly as a machine's is its hardware
/// root: the DID is a one-way function of the credential public key, so the
/// *same* authenticator always yields the *same* DID — enrol it, remove it,
/// enrol it again, and the identity is unchanged. The identity is the key, not
/// a record we happened to mint. Shaped as a UUIDv8 (RFC 9562 §5.8) so it reads
/// and parses like every other identifier. One-way, so publishing the DID does
/// not disclose the key.
fn human_id_from_passkey(passkey_public_key: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(HUMAN_DID_DOMAIN);
    hasher.update(passkey_public_key);
    let digest = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

/// Derives the identifier portion of an autonomous machine DID from a
/// machine-identity root.
///
/// The output is shaped as a UUIDv8 (RFC 9562 §5.8 — custom layout, the
/// variant reserved for application-defined derivations) so it reads the
/// same as the random identifiers the other constructors mint and parses
/// through the same path. Truncating the digest to 16 bytes is what a UUID
/// can hold; the full 32-byte root remains the thing an attestation commits
/// to, and the derivation is one-way, so publishing the DID does not
/// disclose the root.
fn machine_id_from_hardware_root(hardware_root: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(MACHINE_DID_DOMAIN);
    hasher.update(hardware_root);
    let digest = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

/// Derives the identifier portion of a machine DID from the device public key
/// held in the machine's secure element.
///
/// Used where the caller presents a TPM- or Secure-Enclave-resident device key
/// rather than a folded platform root: the key is non-exportable, so the same
/// element re-registers under the same identifier, and a verifier can recompute
/// it from the key the machine presents.
fn machine_id_from_device_key(device_public_key: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(MACHINE_DEVICE_KEY_DID_DOMAIN);
    hasher.update(device_public_key);
    let digest = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
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
    /// Creates a new human DID with a random UUID.
    ///
    /// Prefer [`from_passkey`](Self::from_passkey) for any identity rooted in a
    /// passkey: a random id makes the identity a record that can change, which
    /// it must not. This remains for the few callers that mint a human identity
    /// with no authenticator to derive from (tests, placeholders).
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
    /// is the key. The machine counterpart is [`from_hardware_root`](Self::from_hardware_root).
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

    /// Creates a new machine DID with a controller (human parent)
    pub fn new_machine(controller_id: &str) -> Self {
        Self {
            did_type: DidType::Machine,
            id: uuid::Uuid::new_v4().to_string(),
            controller_id: Some(controller_id.to_string()),
        }
    }

    /// Creates an autonomous machine DID whose identifier is derived from a
    /// machine-identity root rather than drawn at random.
    ///
    /// The root comes from `tenzro_tee::HardwareIdentity::root()` — a fold
    /// over per-unit identifiers (SMBIOS system UUID, baseboard serial, GPU
    /// UUIDs) that survives a reboot, an OS reinstall, and a software
    /// upgrade. Deriving the identifier from it means the same physical box
    /// re-registers under the same DID instead of accumulating a new
    /// identity every time the process restarts, and it lets a verifier
    /// holding an attestation over the root confirm that the DID being
    /// presented is the one that root produces.
    ///
    /// A machine identity has no other constructor. There is deliberately no
    /// random fallback: an identifier drawn at random changes on every
    /// re-registration, which is the opposite of an identity, and two hosts
    /// that both took the fallback could not be told apart afterwards from
    /// the DID alone. A host that cannot produce a root cannot have an
    /// autonomous identity, and must be delegated by a human or an
    /// institution instead — see [`new_machine`](Self::new_machine).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MissingHardwareRoot`] when `hardware_root` is
    /// all zeroes, the value an unrooted host folds to. Every such host folds
    /// to that same value, so accepting it would collide every unrooted
    /// machine on one shared DID.
    pub fn from_hardware_root(hardware_root: &[u8; 32]) -> Result<Self> {
        if hardware_root == &[0u8; 32] {
            return Err(IdentityError::MissingHardwareRoot);
        }
        Ok(Self {
            did_type: DidType::Machine,
            id: machine_id_from_hardware_root(hardware_root),
            controller_id: None,
        })
    }

    /// Creates an autonomous machine DID derived from the device public key
    /// held in this machine's secure element (TPM 2.0, or the Secure Enclave
    /// on Apple hardware).
    ///
    /// The counterpart to [`from_hardware_root`](Self::from_hardware_root) for
    /// callers that hold a device key rather than a folded platform root. The
    /// key cannot be exported from the element that generated it, so the same
    /// machine derives the same DID on every registration, and a verifier can
    /// recompute the identifier from the key the machine presents.
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

    /// Whether this DID is the one [`from_device_key`](Self::from_device_key)
    /// produces for `device_public_key`.
    ///
    /// The check a relying party runs to confirm the machine DID in front of
    /// it is the one that device key derives.
    pub fn matches_device_key(&self, device_public_key: &[u8]) -> bool {
        self.did_type == DidType::Machine
            && self.controller_id.is_none()
            && self.id == machine_id_from_device_key(device_public_key)
    }

    /// Whether this DID is the one [`from_hardware_root`](Self::from_hardware_root)
    /// produces for `hardware_root`.
    ///
    /// The check a relying party runs after verifying an attestation: the
    /// report proves the enclave signed over some root, this proves the DID
    /// in front of it is the one that root derives.
    pub fn matches_hardware_root(&self, hardware_root: &[u8; 32]) -> bool {
        self.did_type == DidType::Machine
            && self.controller_id.is_none()
            && self.id == machine_id_from_hardware_root(hardware_root)
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
    fn hardware_rooted_did_is_reproducible() {
        // The premise of a machine identity: the same box comes back as the
        // same DID rather than accumulating one per restart.
        let root = [0x5Au8; 32];
        let a = TenzroDid::from_hardware_root(&root).unwrap();
        let b = TenzroDid::from_hardware_root(&root).unwrap();
        assert_eq!(a, b);
        assert!(a.is_machine());
        assert!(!a.has_controller());
        assert!(a.matches_hardware_root(&root));
    }

    #[test]
    fn hardware_rooted_did_separates_machines() {
        let a = TenzroDid::from_hardware_root(&[0x11u8; 32]).unwrap();
        let b = TenzroDid::from_hardware_root(&[0x22u8; 32]).unwrap();
        assert_ne!(a, b);
        assert!(!a.matches_hardware_root(&[0x22u8; 32]));
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
    fn hardware_rooted_did_round_trips_through_parse() {
        let root = [0x7Cu8; 32];
        let did = TenzroDid::from_hardware_root(&root).unwrap();
        let parsed = TenzroDid::parse(&did.to_string()).unwrap();
        assert_eq!(parsed, did);
        assert!(parsed.matches_hardware_root(&root));
    }

    #[test]
    fn hardware_rooted_id_is_uuid_shaped() {
        let did = TenzroDid::from_hardware_root(&[0x01u8; 32]).unwrap();
        let parsed = uuid::Uuid::parse_str(&did.id).unwrap();
        // RFC 9562 §5.8 custom layout, RFC 4122 variant.
        assert_eq!(parsed.get_version_num(), 8);
        assert_eq!(parsed.as_bytes()[8] & 0xc0, 0x80);
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
    fn autonomous_machine_did_comes_only_from_hardware() {
        let did = TenzroDid::from_hardware_root(&[0x33u8; 32]).unwrap();
        assert!(did.is_machine());
        assert!(!did.has_controller());
        assert!(did.to_string().starts_with("did:tenzro:machine:"));
    }

    #[test]
    fn unrooted_host_gets_no_autonomous_identity() {
        // The zero root is what a host with no TPM, Secure Enclave, PPIN or
        // SMBIOS UUID folds to. Every such host folds to the same value, so
        // deriving from it would put every unrooted machine on one DID.
        // There is no random fallback to take instead — that is the point.
        assert!(matches!(
            TenzroDid::from_hardware_root(&[0u8; 32]),
            Err(IdentityError::MissingHardwareRoot)
        ));
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
        assert!(a.matches_device_key(&key));
        assert!(a.is_machine());
        assert!(!a.has_controller());

        let other = TenzroDid::from_device_key(&[0xB2u8; 32]).unwrap();
        assert_ne!(a, other);
        assert!(!a.matches_device_key(&[0xB2u8; 32]));
    }

    #[test]
    fn device_key_and_hardware_root_domains_are_separated() {
        // Feeding one derivation the other's input must not collide.
        let same = [0x44u8; 32];
        assert_ne!(
            TenzroDid::from_device_key(&same).unwrap(),
            TenzroDid::from_hardware_root(&same).unwrap()
        );
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

        let autonomous = TenzroDid::from_hardware_root(&[0x55u8; 32]).unwrap();
        assert_eq!(autonomous.controller_did(), None);
    }

    #[test]
    fn test_display() {
        let did = TenzroDid::parse("did:tenzro:human:test-id").unwrap();
        assert_eq!(format!("{}", did), "did:tenzro:human:test-id");
    }
}
