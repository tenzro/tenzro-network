//! Praecise Digital Identity Standard (PDIS) for Tenzro Network
//!
//! This module implements the PDIS multi-hierarchy DID (Decentralized Identifier) system,
//! which complements Tenzro Network's existing flat agent DIDs with a two-level hierarchical
//! identity structure designed for regulatory compliance, trust chains, and credential inheritance.
//!
//! # PDIS Overview
//!
//! The Praecise Digital Identity Standard (PDIS) defines a hierarchical identity model
//! specifically designed for AI agent ecosystems requiring regulatory compliance and
//! verifiable credentials:
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │           Guardian DIDs (PDIS-1)                         │
//! │  Human-controlled root identities with KYC attestation   │
//! │  Format: did:pdis:guardian:{id}                          │
//! └──────────────────┬───────────────────────────────────────┘
//!                    │
//!       ┌────────────┴────────────┬────────────┐
//!       │                         │            │
//! ┌─────▼─────┐            ┌──────▼────┐   ┌──▼───────┐
//! │  Agent 1  │            │  Agent 2  │   │  Agent N │
//! │  (PDIS-2) │            │  (PDIS-2) │   │ (PDIS-2) │
//! └───────────┘            └───────────┘   └──────────┘
//! Format: did:pdis:agent:{guardian_id}:{agent_id}
//! ```
//!
//! # Hierarchy Levels
//!
//! ## PDIS-1: Guardian DIDs
//!
//! Guardian DIDs represent human-controlled root identities that:
//! - Undergo KYC (Know Your Customer) verification at multiple tiers
//! - Control and are responsible for their agent DIDs
//! - Issue and manage credentials that can be inherited by agents
//! - Provide accountability and regulatory compliance anchors
//!
//! ## PDIS-2: Agent DIDs
//!
//! Agent DIDs represent AI agent identities that:
//! - Are owned and controlled by a Guardian DID
//! - Inherit credentials from their guardian
//! - Can optionally link to native Tenzro agent identities
//! - Operate within delegation scopes defined by their guardian
//! - Provide verifiable attribution to human controllers
//!
//! # Credential Inheritance
//!
//! The key innovation of PDIS is credential inheritance. When a Guardian DID receives
//! a verifiable credential (e.g., accredited investor status), their Agent DIDs can
//! inherit and use these credentials, enabling:
//!
//! - Regulatory compliance: Agents operate under human accountability
//! - Trust chains: Verify agent credentials through guardian verification
//! - Permission delegation: Guardians define what agents can do
//! - Auditability: Clear responsibility chains for agent actions
//!
//! # Integration with Tenzro Network
//!
//! PDIS integrates with Tenzro Network's native agent system:
//!
//! - Native Tenzro agents get self-sovereign identities with MPC wallets
//! - PDIS agents provide an additional hierarchical identity layer
//! - Agents can have both a native Tenzro ID and a PDIS DID
//! - The `link_tenzro_agent` method connects these two identity systems
//!
//! # Examples
//!
//! ## Registering a Guardian and Agent
//!
//! ```no_run
//! use tenzro_agent::pdis::{PdisRegistry, KycTier, DelegationScope};
//!
//! # async fn example() -> tenzro_agent::error::Result<()> {
//! let registry = PdisRegistry::new();
//!
//! // Register a guardian with KYC
//! let guardian = registry.register_guardian(
//!     vec![1, 2, 3], // public key
//!     "Alice".to_string(),
//!     KycTier::Enhanced,
//! )?;
//!
//! // Register an agent under the guardian
//! let agent = registry.register_agent(
//!     &guardian.did,
//!     vec![4, 5, 6], // agent public key
//!     vec!["trading".to_string()],
//!     DelegationScope {
//!         max_transaction_value: Some(10_000),
//!         allowed_operations: vec!["trade".to_string()],
//!         allowed_contracts: vec![],
//!         time_bound: None,
//!     },
//! )?;
//!
//! println!("Agent DID: {}", agent.did);
//! # Ok(())
//! # }
//! ```
//!
//! ## Credential Issuance and Inheritance
//!
//! ```no_run
//! use tenzro_agent::pdis::{PdisRegistry, InheritedCredential, CredentialType};
//! use std::collections::HashMap;
//!
//! # fn example(registry: &tenzro_agent::pdis::PdisRegistry, guardian_did: &str, agent_did: &str) -> tenzro_agent::error::Result<()> {
//! // Issue a credential to the guardian
//! let credential = InheritedCredential {
//!     credential_type: CredentialType::AccreditedInvestor,
//!     issuer_did: "did:pdis:guardian:issuer".to_string(),
//!     issued_at: chrono::Utc::now(),
//!     expires_at: None,
//!     claims: HashMap::new(),
//!     proof: vec![],
//! };
//!
//! registry.issue_credential(guardian_did, credential)?;
//!
//! // Agent inherits the credential
//! registry.inherit_credential(agent_did, &CredentialType::AccreditedInvestor)?;
//!
//! // Verify the credential chain
//! let is_valid = registry.verify_credential_chain(agent_did)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```

use crate::error::{AgentError, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_storage::kv::{KvStore, CF_IDENTITIES};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// KYC (Know Your Customer) verification tiers for Guardian DIDs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KycTier {
    /// No verification performed
    Unverified,
    /// Basic email verification
    Basic,
    /// Enhanced verification with ID document
    Enhanced,
    /// Full verification with institutional or biometric verification
    Full,
}

/// Identity status for both Guardian and Agent DIDs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdentityStatus {
    /// Identity is active and can be used
    Active,
    /// Identity is temporarily suspended
    Suspended,
    /// Identity has been permanently revoked
    Revoked,
}

/// Credential types supported by PDIS
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CredentialType {
    /// KYC attestation credential
    KycAttestation,
    /// Age verification credential
    AgeVerification,
    /// Residency proof credential
    ResidencyProof,
    /// Accredited investor status
    AccreditedInvestor,
    /// Institutional membership credential
    InstitutionalMember,
    /// Custom credential type
    Custom(String),
}

/// Time boundaries for delegation scopes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBound {
    /// Delegation is not valid before this time
    pub not_before: DateTime<Utc>,
    /// Delegation expires after this time
    pub not_after: DateTime<Utc>,
}

/// Delegation scope defining what an agent is allowed to do
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationScope {
    /// Maximum transaction value the agent can execute (in smallest unit)
    pub max_transaction_value: Option<u128>,
    /// List of allowed operation types
    pub allowed_operations: Vec<String>,
    /// List of allowed smart contract addresses
    pub allowed_contracts: Vec<Vec<u8>>,
    /// Time bounds for this delegation
    pub time_bound: Option<TimeBound>,
}

/// Credential inherited from a guardian
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InheritedCredential {
    /// Type of the credential
    pub credential_type: CredentialType,
    /// DID of the credential issuer
    pub issuer_did: String,
    /// Timestamp when the credential was issued
    pub issued_at: DateTime<Utc>,
    /// Optional expiration timestamp
    pub expires_at: Option<DateTime<Utc>>,
    /// Credential claims (key-value pairs)
    pub claims: HashMap<String, serde_json::Value>,
    /// Cryptographic proof of the credential
    pub proof: Vec<u8>,
}

impl InheritedCredential {
    /// Check if the credential is currently valid (not expired and already
    /// issued).
    ///
    /// HIGH #106: a credential is valid only when:
    /// 1. `issued_at <= now` (rejects future-dated / forged credentials)
    /// 2. `expires_at` is `None` OR `expires_at > now`
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        if self.issued_at > now {
            return false;
        }
        match self.expires_at {
            Some(expires_at) => now < expires_at,
            None => true,
        }
    }

    /// Returns true if the credential is past its `expires_at`.
    ///
    /// Distinct from `!is_valid()` because future-dated credentials are
    /// invalid but not yet expired.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires_at) => Utc::now() >= expires_at,
            None => false,
        }
    }

    /// Returns the duration until expiry, or `None` if the credential never
    /// expires. Returns `Some(zero)` if the credential has already expired.
    pub fn time_until_expiry(&self) -> Option<chrono::Duration> {
        self.expires_at.map(|exp| {
            let now = Utc::now();
            if exp > now {
                exp - now
            } else {
                chrono::Duration::zero()
            }
        })
    }
}

/// PDIS-1 Guardian DID identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianIdentity {
    /// Guardian DID in format: did:pdis:guardian:{id}
    pub did: String,
    /// Public key for verification
    pub public_key: Vec<u8>,
    /// KYC verification tier
    pub kyc_tier: KycTier,
    /// Display name for the guardian
    pub display_name: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Current identity status
    pub status: IdentityStatus,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// List of agent DIDs owned by this guardian
    pub agents: Vec<String>,
    /// Credentials held by this guardian
    pub credentials: Vec<InheritedCredential>,
}

/// PDIS-2 Agent DID identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdisAgentIdentity {
    /// Agent DID in format: did:pdis:agent:{guardian_id}:{agent_id}
    pub did: String,
    /// Guardian DID that owns this agent
    pub guardian_did: String,
    /// Optional link to native Tenzro agent ID
    pub tenzro_agent_id: Option<String>,
    /// Public key for verification
    pub public_key: Vec<u8>,
    /// Agent capabilities
    pub capabilities: Vec<String>,
    /// Credentials inherited from the guardian
    pub inherited_credentials: Vec<InheritedCredential>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Current identity status
    pub status: IdentityStatus,
    /// Delegation scope defining agent permissions
    pub delegation_scope: DelegationScope,
}

/// Schema definition for credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSchema {
    /// Unique schema identifier
    pub schema_id: String,
    /// Human-readable schema name
    pub name: String,
    /// Schema version
    pub version: String,
    /// Required fields in this credential type
    pub required_fields: Vec<String>,
    /// Optional fields in this credential type
    pub optional_fields: Vec<String>,
}

/// Entry for a revoked DID
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

/// Result of DID resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidResolutionResult {
    /// The resolved DID
    pub did: String,
    /// Whether this is a guardian DID (true) or agent DID (false)
    pub is_guardian: bool,
    /// Current status of the identity
    pub status: IdentityStatus,
    /// Public key for verification
    pub public_key: Vec<u8>,
    /// Associated credentials
    pub credentials: Vec<InheritedCredential>,
    /// Guardian DID (None for guardian DIDs, Some for agent DIDs)
    pub guardian_did: Option<String>,
}

/// Remote DID resolution backend (CRITICAL #53).
///
/// When the local PDIS cache does not contain a DID, the registry can fall
/// back to a remote backend — typically a JSON-RPC call to a Tenzro node that
/// holds the on-chain PDIS state. Successful remote lookups are cached locally
/// and persisted (when storage is configured).
pub trait PdisResolutionBackend: Send + Sync {
    /// Attempt to resolve a guardian DID from a remote source.
    fn resolve_guardian_remote(&self, did: &str) -> crate::error::Result<Option<GuardianIdentity>>;
    /// Attempt to resolve an agent DID from a remote source.
    fn resolve_agent_remote(&self, did: &str) -> crate::error::Result<Option<PdisAgentIdentity>>;
}

/// Revocation broadcaster (CRITICAL #53).
///
/// When a local DID is revoked, the registry can broadcast the revocation to
/// peer nodes so they can update their caches. The inbound counterpart is
/// [`PdisRegistry::apply_remote_revocation`].
pub trait PdisRevocationBroadcaster: Send + Sync {
    /// Broadcast a revocation entry to peer nodes.
    fn broadcast_revocation(&self, entry: &RevocationEntry) -> crate::error::Result<()>;
}

/// Central registry for PDIS DIDs
///
/// This is the main entry point for PDIS operations. It maintains the registry
/// of all guardian and agent DIDs, manages credential issuance and inheritance,
/// and provides DID resolution services.
///
/// ## Persistent Storage (CRITICAL #53)
///
/// When constructed via [`PdisRegistry::with_storage`], all mutations are
/// written through to the underlying [`KvStore`] (typically RocksDB). On
/// construction the registry hydrates its in-memory caches from the store so
/// that DIDs survive node restarts.
///
/// PDIS DIDs are stored in the `CF_IDENTITIES` column family alongside TDIP
/// DIDs. They are namespaced by their DID prefix (`did:pdis:guardian:` /
/// `did:pdis:agent:`) so there is no collision with `did:tenzro:` entries.
pub struct PdisRegistry {
    /// Registry of guardian identities
    guardians: DashMap<String, GuardianIdentity>,
    /// Registry of agent identities
    agents: DashMap<String, PdisAgentIdentity>,
    /// Registry of credential schemas
    _credential_schemas: DashMap<String, CredentialSchema>,
    /// Registry of revoked DIDs
    revocations: DashMap<String, RevocationEntry>,
    /// Optional persistent storage backend (RocksDB) — CRITICAL #53
    storage: Option<Arc<dyn KvStore>>,
    /// Optional remote DID resolution backend — CRITICAL #53
    resolution_backend: Option<Arc<dyn PdisResolutionBackend>>,
    /// Optional revocation broadcaster — CRITICAL #53
    revocation_broadcaster: Option<Arc<dyn PdisRevocationBroadcaster>>,
}

impl PdisRegistry {
    /// Creates a new in-memory PDIS registry (no persistence).
    pub fn new() -> Self {
        info!("Initializing PDIS registry (in-memory)");
        Self {
            guardians: DashMap::new(),
            agents: DashMap::new(),
            _credential_schemas: DashMap::new(),
            revocations: DashMap::new(),
            storage: None,
            resolution_backend: None,
            revocation_broadcaster: None,
        }
    }

    /// Creates a PDIS registry backed by persistent storage (CRITICAL #53).
    ///
    /// On construction the registry scans `CF_IDENTITIES` for keys prefixed
    /// with `did:pdis:guardian:` and `did:pdis:agent:`, deserializes them, and
    /// populates the in-memory caches. Revocations are loaded from keys
    /// prefixed with `revocation:pdis:`.
    ///
    /// All subsequent mutations (register, revoke, credential issuance, etc.)
    /// are written through to the store so that DIDs survive node restarts.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let guardians = DashMap::new();
        let agents = DashMap::new();
        let revocations = DashMap::new();

        // Hydrate guardians
        match storage.get_keys_with_prefix(CF_IDENTITIES, b"did:pdis:guardian:") {
            Ok(keys) => {
                let mut loaded = 0usize;
                for key in &keys {
                    if let Ok(Some(data)) = storage.get(CF_IDENTITIES, key)
                        && let Ok(guardian) = bincode::deserialize::<GuardianIdentity>(&data)
                    {
                        let did = guardian.did.clone();
                        if guardian.status == IdentityStatus::Revoked {
                            revocations.insert(did.clone(), RevocationEntry {
                                did: did.clone(),
                                revoked_at: guardian.updated_at,
                                reason: "loaded as revoked".to_string(),
                                revoked_by: "storage".to_string(),
                            });
                        }
                        guardians.insert(did, guardian);
                        loaded += 1;
                    }
                }
                info!("Loaded {} PDIS guardians from persistent storage", loaded);
            }
            Err(e) => warn!("Failed to load PDIS guardians from storage: {}", e),
        }

        // Hydrate agents
        match storage.get_keys_with_prefix(CF_IDENTITIES, b"did:pdis:agent:") {
            Ok(keys) => {
                let mut loaded = 0usize;
                for key in &keys {
                    if let Ok(Some(data)) = storage.get(CF_IDENTITIES, key)
                        && let Ok(agent) = bincode::deserialize::<PdisAgentIdentity>(&data)
                    {
                        let did = agent.did.clone();
                        if agent.status == IdentityStatus::Revoked {
                            revocations.insert(did.clone(), RevocationEntry {
                                did: did.clone(),
                                revoked_at: agent.created_at,
                                reason: "loaded as revoked".to_string(),
                                revoked_by: "storage".to_string(),
                            });
                        }
                        agents.insert(did, agent);
                        loaded += 1;
                    }
                }
                info!("Loaded {} PDIS agents from persistent storage", loaded);
            }
            Err(e) => warn!("Failed to load PDIS agents from storage: {}", e),
        }

        // Hydrate explicit revocations
        match storage.get_keys_with_prefix(CF_IDENTITIES, b"revocation:pdis:") {
            Ok(keys) => {
                let mut loaded = 0usize;
                for key in &keys {
                    if let Ok(Some(data)) = storage.get(CF_IDENTITIES, key)
                        && let Ok(entry) = bincode::deserialize::<RevocationEntry>(&data)
                    {
                        revocations.insert(entry.did.clone(), entry);
                        loaded += 1;
                    }
                }
                if loaded > 0 {
                    info!("Loaded {} PDIS revocations from persistent storage", loaded);
                }
            }
            Err(e) => warn!("Failed to load PDIS revocations from storage: {}", e),
        }

        Self {
            guardians,
            agents,
            _credential_schemas: DashMap::new(),
            revocations,
            storage: Some(storage),
            resolution_backend: None,
            revocation_broadcaster: None,
        }
    }

    /// Attach a remote DID resolution backend (CRITICAL #53).
    pub fn with_resolution_backend(mut self, backend: Arc<dyn PdisResolutionBackend>) -> Self {
        self.resolution_backend = Some(backend);
        self
    }

    /// Attach a revocation broadcaster (CRITICAL #53).
    pub fn with_revocation_broadcaster(mut self, broadcaster: Arc<dyn PdisRevocationBroadcaster>) -> Self {
        self.revocation_broadcaster = Some(broadcaster);
        self
    }

    // ── Write-through persistence helpers (CRITICAL #53) ─────────────

    /// Persist a guardian identity to the backing store.
    fn persist_guardian(&self, did: &str, guardian: &GuardianIdentity) {
        if let Some(ref store) = self.storage {
            match bincode::serialize(guardian) {
                Ok(data) => {
                    if let Err(e) = store.put(CF_IDENTITIES, did.as_bytes(), &data) {
                        warn!("Failed to persist PDIS guardian {}: {}", did, e);
                    }
                }
                Err(e) => warn!("Failed to serialize PDIS guardian {}: {}", did, e),
            }
        }
    }

    /// Persist an agent identity to the backing store.
    fn persist_agent(&self, did: &str, agent: &PdisAgentIdentity) {
        if let Some(ref store) = self.storage {
            match bincode::serialize(agent) {
                Ok(data) => {
                    if let Err(e) = store.put(CF_IDENTITIES, did.as_bytes(), &data) {
                        warn!("Failed to persist PDIS agent {}: {}", did, e);
                    }
                }
                Err(e) => warn!("Failed to serialize PDIS agent {}: {}", did, e),
            }
        }
    }

    /// Persist a revocation entry to the backing store.
    fn persist_revocation(&self, entry: &RevocationEntry) {
        if let Some(ref store) = self.storage {
            let key = format!("revocation:pdis:{}", entry.did);
            match bincode::serialize(entry) {
                Ok(data) => {
                    if let Err(e) = store.put(CF_IDENTITIES, key.as_bytes(), &data) {
                        warn!("Failed to persist PDIS revocation {}: {}", entry.did, e);
                    }
                }
                Err(e) => warn!("Failed to serialize PDIS revocation {}: {}", entry.did, e),
            }
        }
    }

    /// Apply a revocation received from a remote peer (CRITICAL #53).
    ///
    /// This is the inbound counterpart to [`PdisRevocationBroadcaster`].
    /// When a peer gossips a revocation, the node calls this method to apply
    /// it locally. If the DID is not present locally, the revocation is still
    /// recorded so that future resolution attempts respect it.
    pub fn apply_remote_revocation(&self, entry: RevocationEntry) {
        let did = entry.did.clone();
        info!("Applying remote PDIS revocation for {}", did);

        // Mark guardian or agent as revoked if present locally
        if let Some(mut guardian) = self.guardians.get_mut(&did) {
            guardian.status = IdentityStatus::Revoked;
            guardian.updated_at = entry.revoked_at;
            self.persist_guardian(&did, &guardian);

            // Cascade to agents
            let agent_dids = guardian.agents.clone();
            drop(guardian);
            for agent_did in agent_dids {
                if let Some(mut agent) = self.agents.get_mut(&agent_did) {
                    agent.status = IdentityStatus::Revoked;
                    self.persist_agent(&agent_did, &agent);
                }
            }
        } else if let Some(mut agent) = self.agents.get_mut(&did) {
            agent.status = IdentityStatus::Revoked;
            self.persist_agent(&did, &agent);
        }

        self.persist_revocation(&entry);
        self.revocations.insert(did, entry);
    }

    /// Registers a new Guardian DID (PDIS-1)
    ///
    /// # Arguments
    ///
    /// * `public_key` - Public key for the guardian identity
    /// * `display_name` - Human-readable name for the guardian
    /// * `kyc_tier` - KYC verification tier
    ///
    /// # Returns
    ///
    /// The newly created `GuardianIdentity`
    pub fn register_guardian(
        &self,
        public_key: Vec<u8>,
        display_name: String,
        kyc_tier: KycTier,
    ) -> Result<GuardianIdentity> {
        let guardian_id = Uuid::new_v4().to_string();
        let did = format!("did:pdis:guardian:{}", guardian_id);

        let guardian = GuardianIdentity {
            did: did.clone(),
            public_key,
            kyc_tier,
            display_name: display_name.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            status: IdentityStatus::Active,
            metadata: HashMap::new(),
            agents: Vec::new(),
            credentials: Vec::new(),
        };

        info!(
            "Registering guardian DID: {} (name: {}, kyc_tier: {:?})",
            did, display_name, guardian.kyc_tier
        );

        self.guardians.insert(did.clone(), guardian.clone());
        self.persist_guardian(&did, &guardian);
        Ok(guardian)
    }

    /// Registers a new Agent DID (PDIS-2) under a guardian
    ///
    /// # Arguments
    ///
    /// * `guardian_did` - DID of the guardian that owns this agent
    /// * `public_key` - Public key for the agent identity
    /// * `capabilities` - List of agent capabilities
    /// * `delegation_scope` - Permissions and constraints for the agent
    ///
    /// # Returns
    ///
    /// The newly created `PdisAgentIdentity`
    pub fn register_agent(
        &self,
        guardian_did: &str,
        public_key: Vec<u8>,
        capabilities: Vec<String>,
        delegation_scope: DelegationScope,
    ) -> Result<PdisAgentIdentity> {
        // Validate guardian exists and is active
        let mut guardian = self
            .guardians
            .get_mut(guardian_did)
            .ok_or_else(|| AgentError::AgentNotFound(format!("Guardian not found: {}", guardian_did)))?;

        if guardian.status != IdentityStatus::Active {
            return Err(AgentError::PermissionDenied(format!(
                "Guardian is not active: {:?}",
                guardian.status
            )));
        }

        // Extract guardian ID from DID
        let guardian_id = guardian_did
            .strip_prefix("did:pdis:guardian:")
            .ok_or_else(|| AgentError::InvalidAgentId(format!("Invalid guardian DID: {}", guardian_did)))?;

        let agent_id = Uuid::new_v4().to_string();
        let did = format!("did:pdis:agent:{}:{}", guardian_id, agent_id);

        let agent = PdisAgentIdentity {
            did: did.clone(),
            guardian_did: guardian_did.to_string(),
            tenzro_agent_id: None,
            public_key,
            capabilities: capabilities.clone(),
            inherited_credentials: Vec::new(),
            created_at: Utc::now(),
            status: IdentityStatus::Active,
            delegation_scope,
        };

        info!(
            "Registering agent DID: {} under guardian: {} with capabilities: {:?}",
            did, guardian_did, capabilities
        );

        // Add agent to guardian's list
        guardian.agents.push(did.clone());
        self.persist_guardian(guardian_did, &guardian);
        drop(guardian); // Release the DashMap write lock

        self.agents.insert(did.clone(), agent.clone());
        self.persist_agent(&did, &agent);
        Ok(agent)
    }

    /// Links a PDIS agent DID to a native Tenzro agent ID
    ///
    /// This allows PDIS agents to be associated with native Tenzro Network
    /// agent identities, enabling both identity systems to work together.
    ///
    /// # Arguments
    ///
    /// * `pdis_agent_did` - The PDIS agent DID to link
    /// * `tenzro_agent_id` - The native Tenzro agent ID to link to
    pub fn link_tenzro_agent(&self, pdis_agent_did: &str, tenzro_agent_id: String) -> Result<()> {
        let mut agent = self
            .agents
            .get_mut(pdis_agent_did)
            .ok_or_else(|| AgentError::AgentNotFound(format!("Agent not found: {}", pdis_agent_did)))?;

        debug!(
            "Linking PDIS agent {} to Tenzro agent {}",
            pdis_agent_did, tenzro_agent_id
        );

        agent.tenzro_agent_id = Some(tenzro_agent_id.clone());
        self.persist_agent(pdis_agent_did, &agent);
        Ok(())
    }

    /// Resolves a PDIS DID to its current identity information.
    ///
    /// HIGH #106: only credentials that pass `is_valid()` (i.e. issued in the
    /// past and not yet expired) are returned. Use
    /// [`Self::resolve_did_with_history`] when you need the full credential
    /// history including expired entries.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID to resolve (guardian or agent)
    ///
    /// # Returns
    ///
    /// `DidResolutionResult` containing the resolved identity information
    pub fn resolve_did(&self, did: &str) -> Result<DidResolutionResult> {
        let mut result = self.resolve_did_with_history(did)?;
        result.credentials.retain(|c| c.is_valid());
        Ok(result)
    }

    /// Resolves a PDIS DID and returns ALL credentials including expired
    /// ones. Use this when you need to audit historical credentials.
    pub fn resolve_did_with_history(&self, did: &str) -> Result<DidResolutionResult> {
        // Check if it's a guardian DID
        if let Some(guardian) = self.guardians.get(did) {
            return Ok(DidResolutionResult {
                did: guardian.did.clone(),
                is_guardian: true,
                status: guardian.status.clone(),
                public_key: guardian.public_key.clone(),
                credentials: guardian.credentials.clone(),
                guardian_did: None,
            });
        }

        // Check if it's an agent DID
        if let Some(agent) = self.agents.get(did) {
            return Ok(DidResolutionResult {
                did: agent.did.clone(),
                is_guardian: false,
                status: agent.status.clone(),
                public_key: agent.public_key.clone(),
                credentials: agent.inherited_credentials.clone(),
                guardian_did: Some(agent.guardian_did.clone()),
            });
        }

        // CRITICAL #53: attempt remote resolution if a backend is configured
        if let Some(ref backend) = self.resolution_backend {
            // Try guardian resolution
            if did.starts_with("did:pdis:guardian:") {
                match backend.resolve_guardian_remote(did) {
                    Ok(Some(guardian)) => {
                        let result = DidResolutionResult {
                            did: guardian.did.clone(),
                            is_guardian: true,
                            status: guardian.status.clone(),
                            public_key: guardian.public_key.clone(),
                            credentials: guardian.credentials.clone(),
                            guardian_did: None,
                        };
                        // Cache locally and persist
                        self.persist_guardian(&guardian.did, &guardian);
                        self.guardians.insert(guardian.did.clone(), guardian);
                        return Ok(result);
                    }
                    Ok(None) => {} // fall through to error
                    Err(e) => {
                        warn!("Remote PDIS guardian resolution failed for {}: {}", did, e);
                    }
                }
            }
            // Try agent resolution
            if did.starts_with("did:pdis:agent:") {
                match backend.resolve_agent_remote(did) {
                    Ok(Some(agent)) => {
                        let result = DidResolutionResult {
                            did: agent.did.clone(),
                            is_guardian: false,
                            status: agent.status.clone(),
                            public_key: agent.public_key.clone(),
                            credentials: agent.inherited_credentials.clone(),
                            guardian_did: Some(agent.guardian_did.clone()),
                        };
                        // Cache locally and persist
                        self.persist_agent(&agent.did, &agent);
                        self.agents.insert(agent.did.clone(), agent);
                        return Ok(result);
                    }
                    Ok(None) => {} // fall through to error
                    Err(e) => {
                        warn!("Remote PDIS agent resolution failed for {}: {}", did, e);
                    }
                }
            }
        }

        Err(AgentError::AgentNotFound(format!("DID not found: {}", did)))
    }

    /// Issues a credential to a guardian
    ///
    /// # Arguments
    ///
    /// * `guardian_did` - The guardian DID to issue the credential to
    /// * `credential` - The credential to issue
    pub fn issue_credential(&self, guardian_did: &str, credential: InheritedCredential) -> Result<()> {
        let mut guardian = self
            .guardians
            .get_mut(guardian_did)
            .ok_or_else(|| AgentError::AgentNotFound(format!("Guardian not found: {}", guardian_did)))?;

        if guardian.status != IdentityStatus::Active {
            return Err(AgentError::PermissionDenied(format!(
                "Guardian is not active: {:?}",
                guardian.status
            )));
        }

        info!(
            "Issuing credential {:?} to guardian {}",
            credential.credential_type, guardian_did
        );

        guardian.credentials.push(credential);
        guardian.updated_at = Utc::now();
        self.persist_guardian(guardian_did, &guardian);
        Ok(())
    }

    /// Allows an agent to inherit a credential from its guardian.
    ///
    /// HIGH #106: this method enforces credential expiration at inheritance
    /// time. If the guardian holds a credential of the requested type but it
    /// is expired (or future-dated), `AgentError::CredentialExpired` is
    /// returned and nothing is added to the agent. If the guardian holds
    /// no credential of that type at all, `AgentError::PermissionDenied` is
    /// returned (unchanged behaviour).
    ///
    /// # Arguments
    ///
    /// * `agent_did` - The agent DID that will inherit the credential
    /// * `credential_type` - The type of credential to inherit
    pub fn inherit_credential(&self, agent_did: &str, credential_type: &CredentialType) -> Result<()> {
        // Get the agent
        let mut agent = self
            .agents
            .get_mut(agent_did)
            .ok_or_else(|| AgentError::AgentNotFound(format!("Agent not found: {}", agent_did)))?;

        if agent.status != IdentityStatus::Active {
            return Err(AgentError::PermissionDenied(format!(
                "Agent is not active: {:?}",
                agent.status
            )));
        }

        let guardian_did = agent.guardian_did.clone();

        // Get the guardian's credentials
        let guardian = self
            .guardians
            .get(&guardian_did)
            .ok_or_else(|| AgentError::AgentNotFound(format!("Guardian not found: {}", guardian_did)))?;

        // First locate ANY credential of the requested type so we can
        // distinguish "not held" (PermissionDenied) from "expired"
        // (CredentialExpired). HIGH #106: explicit typed expiration error.
        let any_match = guardian
            .credentials
            .iter()
            .find(|c| &c.credential_type == credential_type)
            .ok_or_else(|| {
                AgentError::PermissionDenied(format!(
                    "Guardian does not have credential of type: {:?}",
                    credential_type
                ))
            })?;

        if !any_match.is_valid() {
            return Err(AgentError::CredentialExpired {
                credential_type: format!("{:?}", credential_type),
                did: guardian_did.clone(),
            });
        }

        // Take the first valid match (there may be several issuances of the
        // same type; prefer the one with the latest expires_at).
        let credential = guardian
            .credentials
            .iter()
            .filter(|c| &c.credential_type == credential_type && c.is_valid())
            .max_by_key(|c| c.expires_at.unwrap_or(chrono::DateTime::<Utc>::MAX_UTC))
            .expect("at least one valid credential exists");

        info!(
            "Agent {} inheriting credential {:?} from guardian {}",
            agent_did, credential_type, guardian_did
        );

        // Clone the credential to the agent
        agent.inherited_credentials.push(credential.clone());
        self.persist_agent(agent_did, &agent);
        Ok(())
    }

    /// Returns true if the agent currently holds a non-expired credential of
    /// the given type. HIGH #106: filters by `is_valid()` so callers cannot
    /// rely on the raw `inherited_credentials` vector.
    pub fn agent_has_valid_credential(&self, agent_did: &str, credential_type: &CredentialType) -> Result<bool> {
        let agent = self
            .agents
            .get(agent_did)
            .ok_or_else(|| AgentError::AgentNotFound(format!("Agent not found: {}", agent_did)))?;
        Ok(agent
            .inherited_credentials
            .iter()
            .any(|c| &c.credential_type == credential_type && c.is_valid()))
    }

    /// Returns true if the guardian currently holds a non-expired credential
    /// of the given type.
    pub fn guardian_has_valid_credential(
        &self,
        guardian_did: &str,
        credential_type: &CredentialType,
    ) -> Result<bool> {
        let guardian = self
            .guardians
            .get(guardian_did)
            .ok_or_else(|| AgentError::AgentNotFound(format!("Guardian not found: {}", guardian_did)))?;
        Ok(guardian
            .credentials
            .iter()
            .any(|c| &c.credential_type == credential_type && c.is_valid()))
    }

    /// Removes all expired credentials from the given agent's inherited
    /// credential list. HIGH #106: callers may invoke this periodically (or
    /// during gossipsub heartbeat) to keep stale credentials from
    /// accumulating. Returns the number of credentials pruned.
    pub fn prune_expired_credentials_for_agent(&self, agent_did: &str) -> Result<usize> {
        let mut agent = self
            .agents
            .get_mut(agent_did)
            .ok_or_else(|| AgentError::AgentNotFound(format!("Agent not found: {}", agent_did)))?;
        let before = agent.inherited_credentials.len();
        agent.inherited_credentials.retain(|c| c.is_valid());
        let pruned = before - agent.inherited_credentials.len();
        if pruned > 0 {
            info!("Pruned {} expired credentials from agent {}", pruned, agent_did);
            self.persist_agent(agent_did, &agent);
        }
        Ok(pruned)
    }

    /// Removes all expired credentials from every guardian and every agent
    /// in the registry. HIGH #106: convenience for batch maintenance.
    /// Returns the total number of credentials pruned across all entities.
    pub fn prune_all_expired_credentials(&self) -> usize {
        let mut total = 0usize;
        for mut guardian in self.guardians.iter_mut() {
            let before = guardian.credentials.len();
            guardian.credentials.retain(|c| c.is_valid());
            let pruned = before - guardian.credentials.len();
            if pruned > 0 {
                info!(
                    "Pruned {} expired credentials from guardian {}",
                    pruned, guardian.did
                );
                guardian.updated_at = Utc::now();
                self.persist_guardian(&guardian.did.clone(), &guardian);
            }
            total += pruned;
        }
        for mut agent in self.agents.iter_mut() {
            let before = agent.inherited_credentials.len();
            agent.inherited_credentials.retain(|c| c.is_valid());
            let pruned = before - agent.inherited_credentials.len();
            if pruned > 0 {
                info!("Pruned {} expired credentials from agent {}", pruned, agent.did);
                self.persist_agent(&agent.did.clone(), &agent);
            }
            total += pruned;
        }
        total
    }

    /// Re-validates all of an agent's inherited credentials against the
    /// current time AND against the guardian's current credential list. If a
    /// credential has expired or has been removed/revoked at the guardian
    /// level, it is removed from the agent. HIGH #106: enforces that
    /// inheritance is not "permanent" — guardian-side revocation flows down.
    /// Returns the number of credentials revoked.
    pub fn revalidate_agent_credentials(&self, agent_did: &str) -> Result<usize> {
        let guardian_did = {
            let agent = self
                .agents
                .get(agent_did)
                .ok_or_else(|| AgentError::AgentNotFound(format!("Agent not found: {}", agent_did)))?;
            agent.guardian_did.clone()
        };
        let guardian_creds = {
            let guardian = self.guardians.get(&guardian_did).ok_or_else(|| {
                AgentError::AgentNotFound(format!("Guardian not found: {}", guardian_did))
            })?;
            guardian.credentials.clone()
        };

        let mut agent = self
            .agents
            .get_mut(agent_did)
            .ok_or_else(|| AgentError::AgentNotFound(format!("Agent not found: {}", agent_did)))?;
        let before = agent.inherited_credentials.len();
        agent.inherited_credentials.retain(|ic| {
            if !ic.is_valid() {
                return false;
            }
            // Guardian must still hold a valid credential of the same type
            // and issuer.
            guardian_creds
                .iter()
                .any(|gc| gc.credential_type == ic.credential_type && gc.issuer_did == ic.issuer_did && gc.is_valid())
        });
        let removed = before - agent.inherited_credentials.len();
        if removed > 0 {
            info!(
                "Revalidation removed {} stale credentials from agent {}",
                removed, agent_did
            );
            self.persist_agent(agent_did, &agent);
        }
        Ok(removed)
    }

    /// Revokes a DID (guardian or agent)
    ///
    /// # Arguments
    ///
    /// * `did` - The DID to revoke
    /// * `reason` - Reason for revocation
    /// * `revoked_by` - DID of the entity performing the revocation
    pub fn revoke_did(&self, did: &str, reason: String, revoked_by: String) -> Result<()> {
        // Try to revoke guardian
        if let Some(mut guardian) = self.guardians.get_mut(did) {
            warn!("Revoking guardian DID: {} (reason: {})", did, reason);
            guardian.status = IdentityStatus::Revoked;
            guardian.updated_at = Utc::now();
            self.persist_guardian(did, &guardian);

            // Also revoke all agents under this guardian
            let agent_dids = guardian.agents.clone();
            drop(guardian); // Release the lock

            for agent_did in agent_dids {
                if let Some(mut agent) = self.agents.get_mut(&agent_did) {
                    agent.status = IdentityStatus::Revoked;
                    self.persist_agent(&agent_did, &agent);
                }
            }
        } else if let Some(mut agent) = self.agents.get_mut(did) {
            warn!("Revoking agent DID: {} (reason: {})", did, reason);
            agent.status = IdentityStatus::Revoked;
            self.persist_agent(did, &agent);
        } else {
            return Err(AgentError::AgentNotFound(format!("DID not found: {}", did)));
        }

        let revocation = RevocationEntry {
            did: did.to_string(),
            revoked_at: Utc::now(),
            reason,
            revoked_by,
        };

        self.persist_revocation(&revocation);

        // Broadcast to peers if a broadcaster is configured (CRITICAL #53)
        if let Some(ref broadcaster) = self.revocation_broadcaster
            && let Err(e) = broadcaster.broadcast_revocation(&revocation)
        {
            warn!("Failed to broadcast PDIS revocation for {}: {}", did, e);
        }

        self.revocations.insert(did.to_string(), revocation);
        Ok(())
    }

    /// Verifies the credential inheritance chain for an agent
    ///
    /// This checks that:
    /// 1. The agent exists and is active
    /// 2. The guardian exists and is active
    /// 3. All inherited credentials are valid and match guardian credentials
    ///
    /// # Arguments
    ///
    /// * `agent_did` - The agent DID to verify
    ///
    /// # Returns
    ///
    /// `true` if the credential chain is valid, `false` otherwise
    pub fn verify_credential_chain(&self, agent_did: &str) -> Result<bool> {
        // Get the agent
        let agent = self
            .agents
            .get(agent_did)
            .ok_or_else(|| AgentError::AgentNotFound(format!("Agent not found: {}", agent_did)))?;

        if agent.status != IdentityStatus::Active {
            return Ok(false);
        }

        // Get the guardian
        let guardian = self
            .guardians
            .get(&agent.guardian_did)
            .ok_or_else(|| AgentError::AgentNotFound(format!("Guardian not found: {}", agent.guardian_did)))?;

        if guardian.status != IdentityStatus::Active {
            return Ok(false);
        }

        // Verify all inherited credentials exist in guardian and are valid
        for agent_cred in &agent.inherited_credentials {
            if !agent_cred.is_valid() {
                return Ok(false);
            }

            let guardian_has_cred = guardian.credentials.iter().any(|gc| {
                gc.credential_type == agent_cred.credential_type
                    && gc.issuer_did == agent_cred.issuer_did
                    && gc.is_valid()
            });

            if !guardian_has_cred {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Gets all agents owned by a guardian
    ///
    /// # Arguments
    ///
    /// * `guardian_did` - The guardian DID
    ///
    /// # Returns
    ///
    /// Vector of agent identities owned by the guardian
    pub fn get_guardian_agents(&self, guardian_did: &str) -> Result<Vec<PdisAgentIdentity>> {
        let guardian = self
            .guardians
            .get(guardian_did)
            .ok_or_else(|| AgentError::AgentNotFound(format!("Guardian not found: {}", guardian_did)))?;

        let agents: Vec<PdisAgentIdentity> = guardian
            .agents
            .iter()
            .filter_map(|agent_did| self.agents.get(agent_did).map(|a| a.clone()))
            .collect();

        Ok(agents)
    }

    /// Updates the KYC tier for a guardian
    ///
    /// # Arguments
    ///
    /// * `guardian_did` - The guardian DID
    /// * `new_tier` - The new KYC tier
    pub fn update_kyc_tier(&self, guardian_did: &str, new_tier: KycTier) -> Result<()> {
        let mut guardian = self
            .guardians
            .get_mut(guardian_did)
            .ok_or_else(|| AgentError::AgentNotFound(format!("Guardian not found: {}", guardian_did)))?;

        info!(
            "Updating KYC tier for guardian {} from {:?} to {:?}",
            guardian_did, guardian.kyc_tier, new_tier
        );

        guardian.kyc_tier = new_tier;
        guardian.updated_at = Utc::now();
        self.persist_guardian(guardian_did, &guardian);
        Ok(())
    }

    /// Returns the total number of registered guardians
    pub fn guardian_count(&self) -> usize {
        self.guardians.len()
    }

    /// Returns the total number of registered agents
    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }
}

impl Default for PdisRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Re-export the storage trait for callers that need to construct a
// storage-backed registry.
pub use tenzro_storage::kv::KvStore as PdisKvStore;

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::kv::MemoryStore;

    fn create_test_public_key(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    /// Helper: create a MemoryStore-backed registry for persistence tests
    fn create_persistent_registry() -> (PdisRegistry, Arc<MemoryStore>) {
        let store = Arc::new(MemoryStore::new());
        let registry = PdisRegistry::with_storage(store.clone());
        (registry, store)
    }

    #[test]
    fn test_register_guardian() {
        let registry = PdisRegistry::new();
        let public_key = create_test_public_key(1);

        let guardian = registry
            .register_guardian(public_key.clone(), "Alice".to_string(), KycTier::Enhanced)
            .unwrap();

        assert!(guardian.did.starts_with("did:pdis:guardian:"));
        assert_eq!(guardian.public_key, public_key);
        assert_eq!(guardian.display_name, "Alice");
        assert_eq!(guardian.kyc_tier, KycTier::Enhanced);
        assert_eq!(guardian.status, IdentityStatus::Active);
        assert_eq!(guardian.agents.len(), 0);
        assert_eq!(registry.guardian_count(), 1);
    }

    #[test]
    fn test_register_agent_under_guardian() {
        let registry = PdisRegistry::new();
        let guardian_pubkey = create_test_public_key(1);
        let agent_pubkey = create_test_public_key(2);

        let guardian = registry
            .register_guardian(guardian_pubkey, "Alice".to_string(), KycTier::Full)
            .unwrap();

        let delegation_scope = DelegationScope {
            max_transaction_value: Some(10_000),
            allowed_operations: vec!["trade".to_string()],
            allowed_contracts: vec![],
            time_bound: None,
        };

        let agent = registry
            .register_agent(
                &guardian.did,
                agent_pubkey.clone(),
                vec!["trading".to_string()],
                delegation_scope,
            )
            .unwrap();

        assert!(agent.did.starts_with("did:pdis:agent:"));
        assert_eq!(agent.guardian_did, guardian.did);
        assert_eq!(agent.public_key, agent_pubkey);
        assert_eq!(agent.capabilities, vec!["trading".to_string()]);
        assert_eq!(agent.status, IdentityStatus::Active);
        assert_eq!(registry.agent_count(), 1);

        // Verify guardian's agent list was updated
        let guardian_agents = registry.get_guardian_agents(&guardian.did).unwrap();
        assert_eq!(guardian_agents.len(), 1);
        assert_eq!(guardian_agents[0].did, agent.did);
    }

    #[test]
    fn test_link_tenzro_agent() {
        let registry = PdisRegistry::new();
        let guardian_pubkey = create_test_public_key(1);
        let agent_pubkey = create_test_public_key(2);

        let guardian = registry
            .register_guardian(guardian_pubkey, "Alice".to_string(), KycTier::Basic)
            .unwrap();

        let delegation_scope = DelegationScope {
            max_transaction_value: None,
            allowed_operations: vec![],
            allowed_contracts: vec![],
            time_bound: None,
        };

        let agent = registry
            .register_agent(&guardian.did, agent_pubkey, vec![], delegation_scope)
            .unwrap();

        assert!(agent.tenzro_agent_id.is_none());

        let tenzro_id = "tenzro-agent-123".to_string();
        registry.link_tenzro_agent(&agent.did, tenzro_id.clone()).unwrap();

        let updated_agent = registry.agents.get(&agent.did).unwrap();
        assert_eq!(updated_agent.tenzro_agent_id, Some(tenzro_id));
    }

    #[test]
    fn test_resolve_guardian_did() {
        let registry = PdisRegistry::new();
        let public_key = create_test_public_key(1);

        let guardian = registry
            .register_guardian(public_key.clone(), "Alice".to_string(), KycTier::Enhanced)
            .unwrap();

        let result = registry.resolve_did(&guardian.did).unwrap();

        assert_eq!(result.did, guardian.did);
        assert!(result.is_guardian);
        assert_eq!(result.status, IdentityStatus::Active);
        assert_eq!(result.public_key, public_key);
        assert!(result.guardian_did.is_none());
    }

    #[test]
    fn test_resolve_agent_did() {
        let registry = PdisRegistry::new();
        let guardian_pubkey = create_test_public_key(1);
        let agent_pubkey = create_test_public_key(2);

        let guardian = registry
            .register_guardian(guardian_pubkey, "Alice".to_string(), KycTier::Full)
            .unwrap();

        let delegation_scope = DelegationScope {
            max_transaction_value: Some(5_000),
            allowed_operations: vec![],
            allowed_contracts: vec![],
            time_bound: None,
        };

        let agent = registry
            .register_agent(&guardian.did, agent_pubkey.clone(), vec![], delegation_scope)
            .unwrap();

        let result = registry.resolve_did(&agent.did).unwrap();

        assert_eq!(result.did, agent.did);
        assert!(!result.is_guardian);
        assert_eq!(result.status, IdentityStatus::Active);
        assert_eq!(result.public_key, agent_pubkey);
        assert_eq!(result.guardian_did, Some(guardian.did));
    }

    #[test]
    fn test_issue_credential_to_guardian() {
        let registry = PdisRegistry::new();
        let public_key = create_test_public_key(1);

        let guardian = registry
            .register_guardian(public_key, "Alice".to_string(), KycTier::Full)
            .unwrap();

        let credential = InheritedCredential {
            credential_type: CredentialType::AccreditedInvestor,
            issuer_did: "did:pdis:guardian:issuer".to_string(),
            issued_at: Utc::now(),
            expires_at: None,
            claims: HashMap::new(),
            proof: vec![1, 2, 3],
        };

        registry.issue_credential(&guardian.did, credential).unwrap();

        let updated_guardian = registry.guardians.get(&guardian.did).unwrap();
        assert_eq!(updated_guardian.credentials.len(), 1);
        assert_eq!(
            updated_guardian.credentials[0].credential_type,
            CredentialType::AccreditedInvestor
        );
    }

    #[test]
    fn test_credential_inheritance() {
        let registry = PdisRegistry::new();
        let guardian_pubkey = create_test_public_key(1);
        let agent_pubkey = create_test_public_key(2);

        let guardian = registry
            .register_guardian(guardian_pubkey, "Alice".to_string(), KycTier::Full)
            .unwrap();

        let delegation_scope = DelegationScope {
            max_transaction_value: None,
            allowed_operations: vec![],
            allowed_contracts: vec![],
            time_bound: None,
        };

        let agent = registry
            .register_agent(&guardian.did, agent_pubkey, vec![], delegation_scope)
            .unwrap();

        // Issue credential to guardian
        let credential = InheritedCredential {
            credential_type: CredentialType::AccreditedInvestor,
            issuer_did: "did:pdis:guardian:issuer".to_string(),
            issued_at: Utc::now(),
            expires_at: None,
            claims: HashMap::new(),
            proof: vec![1, 2, 3],
        };

        registry.issue_credential(&guardian.did, credential).unwrap();

        // Agent inherits the credential
        registry
            .inherit_credential(&agent.did, &CredentialType::AccreditedInvestor)
            .unwrap();

        let updated_agent = registry.agents.get(&agent.did).unwrap();
        assert_eq!(updated_agent.inherited_credentials.len(), 1);
        assert_eq!(
            updated_agent.inherited_credentials[0].credential_type,
            CredentialType::AccreditedInvestor
        );
    }

    #[test]
    fn test_verify_credential_chain() {
        let registry = PdisRegistry::new();
        let guardian_pubkey = create_test_public_key(1);
        let agent_pubkey = create_test_public_key(2);

        let guardian = registry
            .register_guardian(guardian_pubkey, "Alice".to_string(), KycTier::Full)
            .unwrap();

        let delegation_scope = DelegationScope {
            max_transaction_value: None,
            allowed_operations: vec![],
            allowed_contracts: vec![],
            time_bound: None,
        };

        let agent = registry
            .register_agent(&guardian.did, agent_pubkey, vec![], delegation_scope)
            .unwrap();

        // Initially, chain should be valid (no credentials)
        assert!(registry.verify_credential_chain(&agent.did).unwrap());

        // Issue and inherit credential
        let credential = InheritedCredential {
            credential_type: CredentialType::KycAttestation,
            issuer_did: "did:pdis:guardian:issuer".to_string(),
            issued_at: Utc::now(),
            expires_at: None,
            claims: HashMap::new(),
            proof: vec![1, 2, 3],
        };

        registry.issue_credential(&guardian.did, credential).unwrap();
        registry
            .inherit_credential(&agent.did, &CredentialType::KycAttestation)
            .unwrap();

        // Chain should still be valid
        assert!(registry.verify_credential_chain(&agent.did).unwrap());
    }

    #[test]
    fn test_guardian_with_multiple_agents() {
        let registry = PdisRegistry::new();
        let guardian_pubkey = create_test_public_key(1);

        let guardian = registry
            .register_guardian(guardian_pubkey, "Alice".to_string(), KycTier::Enhanced)
            .unwrap();

        let delegation_scope = DelegationScope {
            max_transaction_value: None,
            allowed_operations: vec![],
            allowed_contracts: vec![],
            time_bound: None,
        };

        // Register multiple agents
        let agent1 = registry
            .register_agent(
                &guardian.did,
                create_test_public_key(2),
                vec!["trading".to_string()],
                delegation_scope.clone(),
            )
            .unwrap();

        let agent2 = registry
            .register_agent(
                &guardian.did,
                create_test_public_key(3),
                vec!["analytics".to_string()],
                delegation_scope.clone(),
            )
            .unwrap();

        let agent3 = registry
            .register_agent(
                &guardian.did,
                create_test_public_key(4),
                vec!["monitoring".to_string()],
                delegation_scope,
            )
            .unwrap();

        let agents = registry.get_guardian_agents(&guardian.did).unwrap();
        assert_eq!(agents.len(), 3);

        let agent_dids: Vec<String> = agents.iter().map(|a| a.did.clone()).collect();
        assert!(agent_dids.contains(&agent1.did));
        assert!(agent_dids.contains(&agent2.did));
        assert!(agent_dids.contains(&agent3.did));
    }

    #[test]
    fn test_revoke_guardian_revokes_agents() {
        let registry = PdisRegistry::new();
        let guardian_pubkey = create_test_public_key(1);
        let agent_pubkey = create_test_public_key(2);

        let guardian = registry
            .register_guardian(guardian_pubkey, "Alice".to_string(), KycTier::Basic)
            .unwrap();

        let delegation_scope = DelegationScope {
            max_transaction_value: None,
            allowed_operations: vec![],
            allowed_contracts: vec![],
            time_bound: None,
        };

        let agent = registry
            .register_agent(&guardian.did, agent_pubkey, vec![], delegation_scope)
            .unwrap();

        // Revoke the guardian
        registry
            .revoke_did(&guardian.did, "Test revocation".to_string(), "admin".to_string())
            .unwrap();

        // Both guardian and agent should be revoked
        let guardian_result = registry.resolve_did(&guardian.did).unwrap();
        assert_eq!(guardian_result.status, IdentityStatus::Revoked);

        let agent_result = registry.resolve_did(&agent.did).unwrap();
        assert_eq!(agent_result.status, IdentityStatus::Revoked);

        // Credential chain verification should fail
        assert!(!registry.verify_credential_chain(&agent.did).unwrap());
    }

    #[test]
    fn test_revoke_agent_only() {
        let registry = PdisRegistry::new();
        let guardian_pubkey = create_test_public_key(1);
        let agent_pubkey = create_test_public_key(2);

        let guardian = registry
            .register_guardian(guardian_pubkey, "Alice".to_string(), KycTier::Basic)
            .unwrap();

        let delegation_scope = DelegationScope {
            max_transaction_value: None,
            allowed_operations: vec![],
            allowed_contracts: vec![],
            time_bound: None,
        };

        let agent = registry
            .register_agent(&guardian.did, agent_pubkey, vec![], delegation_scope)
            .unwrap();

        // Revoke only the agent
        registry
            .revoke_did(&agent.did, "Agent compromised".to_string(), guardian.did.clone())
            .unwrap();

        // Guardian should still be active
        let guardian_result = registry.resolve_did(&guardian.did).unwrap();
        assert_eq!(guardian_result.status, IdentityStatus::Active);

        // Agent should be revoked
        let agent_result = registry.resolve_did(&agent.did).unwrap();
        assert_eq!(agent_result.status, IdentityStatus::Revoked);
    }

    #[test]
    fn test_update_kyc_tier() {
        let registry = PdisRegistry::new();
        let public_key = create_test_public_key(1);

        let guardian = registry
            .register_guardian(public_key, "Alice".to_string(), KycTier::Basic)
            .unwrap();

        assert_eq!(guardian.kyc_tier, KycTier::Basic);

        registry.update_kyc_tier(&guardian.did, KycTier::Enhanced).unwrap();

        {
            let updated_guardian = registry.guardians.get(&guardian.did).unwrap();
            assert_eq!(updated_guardian.kyc_tier, KycTier::Enhanced);
        } // Drop the Ref guard before the next get_mut call to avoid deadlock

        registry.update_kyc_tier(&guardian.did, KycTier::Full).unwrap();

        let updated_guardian = registry.guardians.get(&guardian.did).unwrap();
        assert_eq!(updated_guardian.kyc_tier, KycTier::Full);
    }

    #[test]
    fn test_invalid_guardian_did_rejection() {
        let registry = PdisRegistry::new();
        let agent_pubkey = create_test_public_key(2);

        let delegation_scope = DelegationScope {
            max_transaction_value: None,
            allowed_operations: vec![],
            allowed_contracts: vec![],
            time_bound: None,
        };

        let result = registry.register_agent(
            "did:pdis:guardian:nonexistent",
            agent_pubkey,
            vec![],
            delegation_scope,
        );

        assert!(result.is_err());
        match result {
            Err(AgentError::AgentNotFound(_)) => {}
            _ => panic!("Expected AgentNotFound error"),
        }
    }

    #[test]
    fn test_inherit_credential_without_guardian_having_it() {
        let registry = PdisRegistry::new();
        let guardian_pubkey = create_test_public_key(1);
        let agent_pubkey = create_test_public_key(2);

        let guardian = registry
            .register_guardian(guardian_pubkey, "Alice".to_string(), KycTier::Full)
            .unwrap();

        let delegation_scope = DelegationScope {
            max_transaction_value: None,
            allowed_operations: vec![],
            allowed_contracts: vec![],
            time_bound: None,
        };

        let agent = registry
            .register_agent(&guardian.did, agent_pubkey, vec![], delegation_scope)
            .unwrap();

        // Try to inherit a credential the guardian doesn't have
        let result = registry.inherit_credential(&agent.did, &CredentialType::AccreditedInvestor);

        assert!(result.is_err());
        match result {
            Err(AgentError::PermissionDenied(_)) => {}
            _ => panic!("Expected PermissionDenied error"),
        }
    }

    #[test]
    fn test_delegation_scope_enforcement() {
        let registry = PdisRegistry::new();
        let guardian_pubkey = create_test_public_key(1);
        let agent_pubkey = create_test_public_key(2);

        let guardian = registry
            .register_guardian(guardian_pubkey, "Alice".to_string(), KycTier::Full)
            .unwrap();

        let delegation_scope = DelegationScope {
            max_transaction_value: Some(10_000),
            allowed_operations: vec!["read".to_string(), "write".to_string()],
            allowed_contracts: vec![vec![1, 2, 3]],
            time_bound: Some(TimeBound {
                not_before: Utc::now(),
                not_after: Utc::now() + chrono::Duration::days(30),
            }),
        };

        let agent = registry
            .register_agent(&guardian.did, agent_pubkey, vec![], delegation_scope)
            .unwrap();

        let updated_agent = registry.agents.get(&agent.did).unwrap();
        assert_eq!(
            updated_agent.delegation_scope.max_transaction_value,
            Some(10_000)
        );
        assert_eq!(updated_agent.delegation_scope.allowed_operations.len(), 2);
        assert_eq!(updated_agent.delegation_scope.allowed_contracts.len(), 1);
        assert!(updated_agent.delegation_scope.time_bound.is_some());
    }

    #[test]
    fn test_credential_expiration() {
        let expired_credential = InheritedCredential {
            credential_type: CredentialType::AgeVerification,
            issuer_did: "did:pdis:guardian:issuer".to_string(),
            issued_at: Utc::now() - chrono::Duration::days(100),
            expires_at: Some(Utc::now() - chrono::Duration::days(1)),
            claims: HashMap::new(),
            proof: vec![],
        };

        assert!(!expired_credential.is_valid());

        let valid_credential = InheritedCredential {
            credential_type: CredentialType::AgeVerification,
            issuer_did: "did:pdis:guardian:issuer".to_string(),
            issued_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            claims: HashMap::new(),
            proof: vec![],
        };

        assert!(valid_credential.is_valid());

        let never_expires_credential = InheritedCredential {
            credential_type: CredentialType::AgeVerification,
            issuer_did: "did:pdis:guardian:issuer".to_string(),
            issued_at: Utc::now(),
            expires_at: None,
            claims: HashMap::new(),
            proof: vec![],
        };

        assert!(never_expires_credential.is_valid());
    }

    #[test]
    fn test_registry_counts() {
        let registry = PdisRegistry::new();
        assert_eq!(registry.guardian_count(), 0);
        assert_eq!(registry.agent_count(), 0);

        let guardian1 = registry
            .register_guardian(create_test_public_key(1), "Alice".to_string(), KycTier::Basic)
            .unwrap();
        assert_eq!(registry.guardian_count(), 1);

        let guardian2 = registry
            .register_guardian(create_test_public_key(2), "Bob".to_string(), KycTier::Enhanced)
            .unwrap();
        assert_eq!(registry.guardian_count(), 2);

        let delegation_scope = DelegationScope {
            max_transaction_value: None,
            allowed_operations: vec![],
            allowed_contracts: vec![],
            time_bound: None,
        };

        registry
            .register_agent(&guardian1.did, create_test_public_key(3), vec![], delegation_scope.clone())
            .unwrap();
        assert_eq!(registry.agent_count(), 1);

        registry
            .register_agent(&guardian1.did, create_test_public_key(4), vec![], delegation_scope.clone())
            .unwrap();
        assert_eq!(registry.agent_count(), 2);

        registry
            .register_agent(&guardian2.did, create_test_public_key(5), vec![], delegation_scope)
            .unwrap();
        assert_eq!(registry.agent_count(), 3);
    }

    #[test]
    fn test_resolve_nonexistent_did() {
        let registry = PdisRegistry::new();
        let result = registry.resolve_did("did:pdis:guardian:nonexistent");

        assert!(result.is_err());
        match result {
            Err(AgentError::AgentNotFound(_)) => {}
            _ => panic!("Expected AgentNotFound error"),
        }
    }

    // ----- HIGH #106 credential expiration enforcement tests -----

    /// Helper that builds a guardian + agent and returns their DIDs.
    fn setup_guardian_with_agent(registry: &PdisRegistry) -> (String, String) {
        let guardian = registry
            .register_guardian(create_test_public_key(11), "Carol".to_string(), KycTier::Full)
            .unwrap();
        let agent = registry
            .register_agent(
                &guardian.did,
                create_test_public_key(12),
                vec![],
                DelegationScope {
                    max_transaction_value: None,
                    allowed_operations: vec![],
                    allowed_contracts: vec![],
                    time_bound: None,
                },
            )
            .unwrap();
        (guardian.did, agent.did)
    }

    #[test]
    fn test_inherit_expired_credential_returns_typed_error() {
        let registry = PdisRegistry::new();
        let (guardian_did, agent_did) = setup_guardian_with_agent(&registry);

        let expired = InheritedCredential {
            credential_type: CredentialType::AccreditedInvestor,
            issuer_did: guardian_did.clone(),
            issued_at: Utc::now() - chrono::Duration::days(400),
            expires_at: Some(Utc::now() - chrono::Duration::days(1)),
            claims: HashMap::new(),
            proof: vec![1, 2, 3],
        };
        registry.issue_credential(&guardian_did, expired).unwrap();

        let result = registry.inherit_credential(&agent_did, &CredentialType::AccreditedInvestor);
        assert!(matches!(result, Err(AgentError::CredentialExpired { .. })));

        let agent = registry.agents.get(&agent_did).unwrap();
        assert_eq!(agent.inherited_credentials.len(), 0);
    }

    #[test]
    fn test_future_dated_credential_is_invalid() {
        let future = InheritedCredential {
            credential_type: CredentialType::AccreditedInvestor,
            issuer_did: "did:pdis:guardian:issuer".to_string(),
            issued_at: Utc::now() + chrono::Duration::days(7),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            claims: HashMap::new(),
            proof: vec![],
        };
        assert!(!future.is_valid(), "future-dated credential must not be valid");
        assert!(!future.is_expired(), "future-dated credential is not expired, just not yet valid");
    }

    #[test]
    fn test_resolve_did_filters_expired_credentials() {
        let registry = PdisRegistry::new();
        let (guardian_did, agent_did) = setup_guardian_with_agent(&registry);

        let valid = InheritedCredential {
            credential_type: CredentialType::AccreditedInvestor,
            issuer_did: guardian_did.clone(),
            issued_at: Utc::now() - chrono::Duration::days(1),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            claims: HashMap::new(),
            proof: vec![1],
        };
        let expired = InheritedCredential {
            credential_type: CredentialType::AgeVerification,
            issuer_did: guardian_did.clone(),
            issued_at: Utc::now() - chrono::Duration::days(400),
            expires_at: Some(Utc::now() - chrono::Duration::days(1)),
            claims: HashMap::new(),
            proof: vec![2],
        };

        // Push directly so we bypass the issue-time validation and simulate a
        // credential that has aged out after being inherited.
        {
            let mut agent = registry.agents.get_mut(&agent_did).unwrap();
            agent.inherited_credentials.push(valid.clone());
            agent.inherited_credentials.push(expired.clone());
        }

        let result = registry.resolve_did(&agent_did).unwrap();
        assert_eq!(result.credentials.len(), 1, "expired credential must be filtered");
        assert_eq!(
            result.credentials[0].credential_type,
            CredentialType::AccreditedInvestor
        );

        let history = registry.resolve_did_with_history(&agent_did).unwrap();
        assert_eq!(history.credentials.len(), 2, "history must include expired credentials");
    }

    #[test]
    fn test_prune_expired_credentials_removes_stale_entries() {
        let registry = PdisRegistry::new();
        let (guardian_did, agent_did) = setup_guardian_with_agent(&registry);

        {
            let mut guardian = registry.guardians.get_mut(&guardian_did).unwrap();
            guardian.credentials.push(InheritedCredential {
                credential_type: CredentialType::AccreditedInvestor,
                issuer_did: guardian_did.clone(),
                issued_at: Utc::now() - chrono::Duration::days(400),
                expires_at: Some(Utc::now() - chrono::Duration::days(1)),
                claims: HashMap::new(),
                proof: vec![],
            });
            guardian.credentials.push(InheritedCredential {
                credential_type: CredentialType::AgeVerification,
                issuer_did: guardian_did.clone(),
                issued_at: Utc::now(),
                expires_at: None,
                claims: HashMap::new(),
                proof: vec![],
            });
        }
        {
            let mut agent = registry.agents.get_mut(&agent_did).unwrap();
            agent.inherited_credentials.push(InheritedCredential {
                credential_type: CredentialType::AccreditedInvestor,
                issuer_did: guardian_did.clone(),
                issued_at: Utc::now() - chrono::Duration::days(400),
                expires_at: Some(Utc::now() - chrono::Duration::days(1)),
                claims: HashMap::new(),
                proof: vec![],
            });
        }

        let pruned = registry.prune_all_expired_credentials();
        assert_eq!(pruned, 2, "one guardian + one agent credential should be pruned");

        let guardian = registry.guardians.get(&guardian_did).unwrap();
        assert_eq!(guardian.credentials.len(), 1);
        assert_eq!(guardian.credentials[0].credential_type, CredentialType::AgeVerification);

        let agent = registry.agents.get(&agent_did).unwrap();
        assert_eq!(agent.inherited_credentials.len(), 0);
    }

    #[test]
    fn test_revalidate_agent_credentials_drops_guardian_revoked() {
        let registry = PdisRegistry::new();
        let (guardian_did, agent_did) = setup_guardian_with_agent(&registry);

        let cred = InheritedCredential {
            credential_type: CredentialType::AccreditedInvestor,
            issuer_did: guardian_did.clone(),
            issued_at: Utc::now() - chrono::Duration::hours(1),
            expires_at: Some(Utc::now() + chrono::Duration::days(30)),
            claims: HashMap::new(),
            proof: vec![],
        };
        registry.issue_credential(&guardian_did, cred).unwrap();
        registry
            .inherit_credential(&agent_did, &CredentialType::AccreditedInvestor)
            .unwrap();

        // Guardian later loses the credential (e.g. revocation upstream).
        {
            let mut guardian = registry.guardians.get_mut(&guardian_did).unwrap();
            guardian.credentials.clear();
        }

        let removed = registry.revalidate_agent_credentials(&agent_did).unwrap();
        assert_eq!(removed, 1, "agent must lose credential when guardian no longer holds it");

        let agent = registry.agents.get(&agent_did).unwrap();
        assert_eq!(agent.inherited_credentials.len(), 0);
    }

    #[test]
    fn test_agent_has_valid_credential_query() {
        let registry = PdisRegistry::new();
        let (guardian_did, agent_did) = setup_guardian_with_agent(&registry);

        // Inject one valid + one expired credential directly so the query
        // method has to do the filtering.
        {
            let mut agent = registry.agents.get_mut(&agent_did).unwrap();
            agent.inherited_credentials.push(InheritedCredential {
                credential_type: CredentialType::AccreditedInvestor,
                issuer_did: guardian_did.clone(),
                issued_at: Utc::now() - chrono::Duration::days(1),
                expires_at: Some(Utc::now() + chrono::Duration::days(30)),
                claims: HashMap::new(),
                proof: vec![],
            });
            agent.inherited_credentials.push(InheritedCredential {
                credential_type: CredentialType::AgeVerification,
                issuer_did: guardian_did.clone(),
                issued_at: Utc::now() - chrono::Duration::days(400),
                expires_at: Some(Utc::now() - chrono::Duration::days(1)),
                claims: HashMap::new(),
                proof: vec![],
            });
        }

        assert!(registry
            .agent_has_valid_credential(&agent_did, &CredentialType::AccreditedInvestor)
            .unwrap());
        assert!(!registry
            .agent_has_valid_credential(&agent_did, &CredentialType::AgeVerification)
            .unwrap());
    }

    #[test]
    fn test_inherit_picks_credential_with_latest_expiry() {
        let registry = PdisRegistry::new();
        let (guardian_did, agent_did) = setup_guardian_with_agent(&registry);

        // Two valid credentials of the same type, different expiries.
        let near = InheritedCredential {
            credential_type: CredentialType::AccreditedInvestor,
            issuer_did: guardian_did.clone(),
            issued_at: Utc::now() - chrono::Duration::days(1),
            expires_at: Some(Utc::now() + chrono::Duration::days(7)),
            claims: HashMap::new(),
            proof: vec![1],
        };
        let far = InheritedCredential {
            credential_type: CredentialType::AccreditedInvestor,
            issuer_did: guardian_did.clone(),
            issued_at: Utc::now() - chrono::Duration::days(1),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            claims: HashMap::new(),
            proof: vec![2],
        };
        registry.issue_credential(&guardian_did, near).unwrap();
        registry.issue_credential(&guardian_did, far).unwrap();

        registry
            .inherit_credential(&agent_did, &CredentialType::AccreditedInvestor)
            .unwrap();

        let agent = registry.agents.get(&agent_did).unwrap();
        assert_eq!(agent.inherited_credentials.len(), 1);
        assert_eq!(agent.inherited_credentials[0].proof, vec![2], "must inherit the longer-lived credential");
    }

    #[test]
    fn test_time_until_expiry_helper() {
        let no_expiry = InheritedCredential {
            credential_type: CredentialType::AccreditedInvestor,
            issuer_did: "x".into(),
            issued_at: Utc::now(),
            expires_at: None,
            claims: HashMap::new(),
            proof: vec![],
        };
        assert!(no_expiry.time_until_expiry().is_none());

        let expired = InheritedCredential {
            credential_type: CredentialType::AccreditedInvestor,
            issuer_did: "x".into(),
            issued_at: Utc::now() - chrono::Duration::days(400),
            expires_at: Some(Utc::now() - chrono::Duration::days(1)),
            claims: HashMap::new(),
            proof: vec![],
        };
        assert_eq!(expired.time_until_expiry(), Some(chrono::Duration::zero()));

        let live = InheritedCredential {
            credential_type: CredentialType::AccreditedInvestor,
            issuer_did: "x".into(),
            issued_at: Utc::now() - chrono::Duration::days(1),
            expires_at: Some(Utc::now() + chrono::Duration::days(30)),
            claims: HashMap::new(),
            proof: vec![],
        };
        let remaining = live.time_until_expiry().unwrap();
        assert!(remaining.num_days() >= 29);
    }

    // ----- CRITICAL #53 persistence tests -----

    #[test]
    fn test_register_guardian_persists_to_storage() {
        let (registry, store) = create_persistent_registry();
        let guardian = registry
            .register_guardian(create_test_public_key(1), "Alice".to_string(), KycTier::Enhanced)
            .unwrap();

        // Verify data was written to the backing store
        let raw = store.get(CF_IDENTITIES, guardian.did.as_bytes()).unwrap();
        assert!(raw.is_some(), "guardian must be persisted to CF_IDENTITIES");
        let loaded: GuardianIdentity = bincode::deserialize(&raw.unwrap()).unwrap();
        assert_eq!(loaded.did, guardian.did);
        assert_eq!(loaded.display_name, "Alice");
        assert_eq!(loaded.kyc_tier, KycTier::Enhanced);
    }

    #[test]
    fn test_register_agent_persists_to_storage() {
        let (registry, store) = create_persistent_registry();
        let guardian = registry
            .register_guardian(create_test_public_key(1), "Alice".to_string(), KycTier::Full)
            .unwrap();
        let scope = DelegationScope {
            max_transaction_value: Some(5_000),
            allowed_operations: vec!["trade".to_string()],
            allowed_contracts: vec![],
            time_bound: None,
        };
        let agent = registry
            .register_agent(&guardian.did, create_test_public_key(2), vec!["trading".to_string()], scope)
            .unwrap();

        // Agent entry
        let raw = store.get(CF_IDENTITIES, agent.did.as_bytes()).unwrap();
        assert!(raw.is_some(), "agent must be persisted to CF_IDENTITIES");
        let loaded: PdisAgentIdentity = bincode::deserialize(&raw.unwrap()).unwrap();
        assert_eq!(loaded.did, agent.did);
        assert_eq!(loaded.guardian_did, guardian.did);

        // Guardian entry must have been updated (agent list)
        let graw = store.get(CF_IDENTITIES, guardian.did.as_bytes()).unwrap().unwrap();
        let gloaded: GuardianIdentity = bincode::deserialize(&graw).unwrap();
        assert!(gloaded.agents.contains(&agent.did));
    }

    #[test]
    fn test_with_storage_hydrates_on_init() {
        let store = Arc::new(MemoryStore::new());

        // Phase 1: register entries
        {
            let registry = PdisRegistry::with_storage(store.clone());
            let guardian = registry
                .register_guardian(create_test_public_key(1), "Bob".to_string(), KycTier::Basic)
                .unwrap();
            let scope = DelegationScope {
                max_transaction_value: None,
                allowed_operations: vec![],
                allowed_contracts: vec![],
                time_bound: None,
            };
            registry
                .register_agent(&guardian.did, create_test_public_key(2), vec![], scope)
                .unwrap();
        } // PdisRegistry dropped; only store survives

        // Phase 2: reconstruct from the same store — entries must be hydrated
        let registry2 = PdisRegistry::with_storage(store.clone());
        assert_eq!(registry2.guardian_count(), 1, "guardians must survive restart");
        assert_eq!(registry2.agent_count(), 1, "agents must survive restart");
    }

    #[test]
    fn test_revocation_persists_and_hydrates() {
        let store = Arc::new(MemoryStore::new());

        let guardian_did;
        let agent_did;
        {
            let registry = PdisRegistry::with_storage(store.clone());
            let guardian = registry
                .register_guardian(create_test_public_key(1), "Charlie".to_string(), KycTier::Full)
                .unwrap();
            guardian_did = guardian.did.clone();
            let scope = DelegationScope {
                max_transaction_value: None,
                allowed_operations: vec![],
                allowed_contracts: vec![],
                time_bound: None,
            };
            let agent = registry
                .register_agent(&guardian.did, create_test_public_key(2), vec![], scope)
                .unwrap();
            agent_did = agent.did.clone();

            // Revoke the guardian — should cascade to agent
            registry
                .revoke_did(&guardian.did, "test".to_string(), "admin".to_string())
                .unwrap();
        }

        // Reconstruct: revoked state must be preserved
        let registry2 = PdisRegistry::with_storage(store.clone());
        let gresult = registry2.resolve_did(&guardian_did).unwrap();
        assert_eq!(gresult.status, IdentityStatus::Revoked);

        let aresult = registry2.resolve_did(&agent_did).unwrap();
        assert_eq!(aresult.status, IdentityStatus::Revoked);
    }

    #[test]
    fn test_credential_issuance_persists() {
        let store = Arc::new(MemoryStore::new());
        let guardian_did;
        {
            let registry = PdisRegistry::with_storage(store.clone());
            let guardian = registry
                .register_guardian(create_test_public_key(1), "Dana".to_string(), KycTier::Enhanced)
                .unwrap();
            guardian_did = guardian.did.clone();
            let cred = InheritedCredential {
                credential_type: CredentialType::AccreditedInvestor,
                issuer_did: guardian_did.clone(),
                issued_at: Utc::now() - chrono::Duration::hours(1),
                expires_at: Some(Utc::now() + chrono::Duration::days(365)),
                claims: HashMap::new(),
                proof: vec![42],
            };
            registry.issue_credential(&guardian_did, cred).unwrap();
        }

        let registry2 = PdisRegistry::with_storage(store.clone());
        let result = registry2.resolve_did(&guardian_did).unwrap();
        assert_eq!(result.credentials.len(), 1);
        assert_eq!(
            result.credentials[0].credential_type,
            CredentialType::AccreditedInvestor
        );
    }

    #[test]
    fn test_kyc_update_persists() {
        let store = Arc::new(MemoryStore::new());
        let guardian_did;
        {
            let registry = PdisRegistry::with_storage(store.clone());
            let guardian = registry
                .register_guardian(create_test_public_key(1), "Eve".to_string(), KycTier::Basic)
                .unwrap();
            guardian_did = guardian.did.clone();
            registry.update_kyc_tier(&guardian_did, KycTier::Full).unwrap();
        }

        let registry2 = PdisRegistry::with_storage(store.clone());
        let g = registry2.guardians.get(&guardian_did).unwrap();
        assert_eq!(g.kyc_tier, KycTier::Full);
    }

    #[test]
    fn test_link_tenzro_agent_persists() {
        let store = Arc::new(MemoryStore::new());
        let agent_did;
        {
            let registry = PdisRegistry::with_storage(store.clone());
            let guardian = registry
                .register_guardian(create_test_public_key(1), "Frank".to_string(), KycTier::Basic)
                .unwrap();
            let scope = DelegationScope {
                max_transaction_value: None,
                allowed_operations: vec![],
                allowed_contracts: vec![],
                time_bound: None,
            };
            let agent = registry
                .register_agent(&guardian.did, create_test_public_key(2), vec![], scope)
                .unwrap();
            agent_did = agent.did.clone();
            registry.link_tenzro_agent(&agent_did, "tenzro-42".to_string()).unwrap();
        }

        let registry2 = PdisRegistry::with_storage(store.clone());
        let a = registry2.agents.get(&agent_did).unwrap();
        assert_eq!(a.tenzro_agent_id, Some("tenzro-42".to_string()));
    }

    #[test]
    fn test_remote_resolution_backend_fallback() {
        /// Dummy remote backend that always returns a fixed guardian
        struct FixedBackend {
            guardian: GuardianIdentity,
        }
        impl PdisResolutionBackend for FixedBackend {
            fn resolve_guardian_remote(&self, _did: &str) -> crate::error::Result<Option<GuardianIdentity>> {
                Ok(Some(self.guardian.clone()))
            }
            fn resolve_agent_remote(&self, _did: &str) -> crate::error::Result<Option<PdisAgentIdentity>> {
                Ok(None)
            }
        }

        let remote_guardian = GuardianIdentity {
            did: "did:pdis:guardian:remote-123".to_string(),
            public_key: vec![99; 32],
            kyc_tier: KycTier::Full,
            display_name: "Remote".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            status: IdentityStatus::Active,
            metadata: HashMap::new(),
            agents: vec![],
            credentials: vec![],
        };

        let registry = PdisRegistry::new()
            .with_resolution_backend(Arc::new(FixedBackend {
                guardian: remote_guardian.clone(),
            }));

        // First resolution should succeed via remote fallback
        let result = registry.resolve_did("did:pdis:guardian:remote-123").unwrap();
        assert!(result.is_guardian);
        assert_eq!(result.did, "did:pdis:guardian:remote-123");

        // Second resolution should use the local cache
        assert_eq!(registry.guardian_count(), 1);
        let result2 = registry.resolve_did("did:pdis:guardian:remote-123").unwrap();
        assert_eq!(result2.did, result.did);
    }

    #[test]
    fn test_apply_remote_revocation() {
        let (registry, _store) = create_persistent_registry();
        let guardian = registry
            .register_guardian(create_test_public_key(1), "Grace".to_string(), KycTier::Full)
            .unwrap();

        let scope = DelegationScope {
            max_transaction_value: None,
            allowed_operations: vec![],
            allowed_contracts: vec![],
            time_bound: None,
        };
        let agent = registry
            .register_agent(&guardian.did, create_test_public_key(2), vec![], scope)
            .unwrap();

        // Simulate receiving a revocation from a peer node
        let entry = RevocationEntry {
            did: guardian.did.clone(),
            revoked_at: Utc::now(),
            reason: "peer-reported compromise".to_string(),
            revoked_by: "peer-node".to_string(),
        };
        registry.apply_remote_revocation(entry);

        let g = registry.resolve_did(&guardian.did).unwrap();
        assert_eq!(g.status, IdentityStatus::Revoked);

        let a = registry.resolve_did(&agent.did).unwrap();
        assert_eq!(a.status, IdentityStatus::Revoked);
    }
}
