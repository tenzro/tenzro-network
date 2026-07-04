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
    if bytes.len() != BLS_G1_COMPRESSED_LEN {
        return Err(serde::de::Error::custom(format!(
            "BLS12-381 G1-compressed verifying key must be exactly {} bytes, got {}",
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
        /// Controller (human) DID, if any
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
            IdentityData::Machine { erc8004_agent_id, .. } => *erc8004_agent_id,
            _ => None,
        }
    }

    /// Set the ERC-8004 `agentId` returned by the on-chain mirror.
    /// Idempotent — overwrites any previous value. No-op for humans.
    pub(crate) fn set_erc8004_agent_id(&mut self, id: u64) {
        if let IdentityData::Machine { erc8004_agent_id, .. } = &mut self.identity_data {
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
        assert_eq!(
            identity.controller_did(),
            Some("did:tenzro:human:alice")
        );
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
        identity.add_service(ServiceEndpoint {
            id: "svc-1".to_string(),
            service_type: "InferenceEndpoint".to_string(),
            service_endpoint: "https://example.com/inference".to_string(),
        }).unwrap();
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
        assert!(identity.add_service(ServiceEndpoint {
            id: "svc-bad".to_string(),
            service_type: "InferenceEndpoint".to_string(),
            service_endpoint: "".to_string(),
        }).is_err());
    }

    #[test]
    fn test_set_metadata() {
        let mut identity = make_test_human();
        identity.set_metadata("org", "TenzroLabs");
        assert_eq!(identity.metadata.get("org"), Some(&"TenzroLabs".to_string()));
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
