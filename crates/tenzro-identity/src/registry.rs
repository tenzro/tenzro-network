//! Identity registry for the Tenzro Decentralized Identity Protocol
//!
//! The `IdentityRegistry` is the central store for all TDIP identities,
//! handling both human and machine identities through a unified type.

use crate::credential::{TenzroCredentialType, VerifiableCredential};
use crate::delegation::DelegationScope;
use crate::did::TenzroDid;
use crate::error::{IdentityError, Result};
use crate::identity::{
    IdentityData, IdentityStatus, KeyPurpose, PublicKeyInfo, RevocationEntry, TenzroIdentity,
};
use crate::wallet_binding::WalletBinder;
use chrono::Utc;
use dashmap::{DashMap, DashSet};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_crypto::composite::{
    CompositePublicKey, CompositeSignature, HybridSigner, HybridVerifier, StandardHybridVerifier,
};
use tenzro_storage::kv::{KvStore, CF_CREDENTIALS, CF_IDENTITIES};
use tenzro_types::fees::ServiceFeeSchedule;
use tenzro_types::identity::{IdentityType as TenzroIdentityType, KycTier};
use tenzro_types::primitives::{Address, BlockHeight};
use tenzro_types::principal_chain::{
    anonymous_chain_for_address, BondLookup, PrincipalChain, PrincipalChainResolver,
    PrincipalLink, PrincipalRole, MAX_DELEGATION_DEPTH,
};
use tracing::{debug, info, warn};

/// Optional remote DID resolution backend for HIGH #93.
///
/// When the local registry does not have a DID, the registry can fall back
/// to a configured backend (typically a JSON-RPC client to a Tenzro node)
/// to fetch the canonical identity record from the blockchain.
///
/// Implementations must be thread-safe.
pub trait DidResolutionBackend: Send + Sync {
    /// Resolve a DID from the blockchain. Returns `Ok(None)` if the DID is
    /// not registered anywhere, or an error if the lookup itself failed.
    fn resolve_remote(&self, did: &str) -> crate::error::Result<Option<TenzroIdentity>>;
}

/// A revocation entry signed by the revoker's hybrid (Ed25519 + ML-DSA-65)
/// keys (Wave 3d post-quantum migration).
///
/// Replaces the unsigned `RevocationEntry` payload that was previously
/// gossiped between nodes — under the no-backward-compat hybrid migration,
/// every cross-node revocation must carry both a classical and a PQ
/// signature so that downstream nodes can verify it before applying. The
/// canonical signing message is `bincode::serialize(&entry)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRevocationEntry {
    /// The bare revocation entry being signed.
    pub entry: RevocationEntry,
    /// Composite signature over `bincode::serialize(&entry)`.
    pub signature: CompositeSignature,
    /// Composite public key the signature was produced under.
    pub public_key: CompositePublicKey,
}

impl SignedRevocationEntry {
    /// Build a signed entry by serializing `entry` (canonical bincode form),
    /// signing the bytes with the supplied hybrid signer, and capturing the
    /// signer's composite public key.
    pub fn sign(entry: RevocationEntry, signer: &dyn HybridSigner) -> Result<Self> {
        let msg = bincode::serialize(&entry).map_err(|e| {
            IdentityError::SerializationError(format!(
                "failed to serialize revocation entry for signing: {}",
                e
            ))
        })?;
        let signature = signer.sign(&msg).map_err(|e| {
            IdentityError::CryptoError(format!("hybrid revocation sign failed: {}", e))
        })?;
        Ok(Self {
            entry,
            signature,
            public_key: signer.public_key().clone(),
        })
    }

    /// Verify the signature against the stored entry. Both legs of the
    /// composite signature must validate against the embedded public key,
    /// otherwise an `IdentityError::VerificationFailed` is returned.
    pub fn verify(&self) -> Result<()> {
        let msg = bincode::serialize(&self.entry).map_err(|e| {
            IdentityError::SerializationError(format!(
                "failed to serialize revocation entry for verification: {}",
                e
            ))
        })?;
        let verifier = StandardHybridVerifier::new(self.public_key.clone());
        verifier.verify(&msg, &self.signature).map_err(|e| {
            IdentityError::VerificationFailed(format!(
                "hybrid revocation signature did not verify: {}",
                e
            ))
        })
    }
}

/// Optional broadcaster for cross-node revocation events (HIGH #96).
///
/// When an identity is revoked locally, the registry calls this broadcaster
/// so that other nodes in the network can update their caches and the
/// revocation can eventually be anchored on-chain. Under the Wave 3d
/// hybrid PQ migration the broadcaster receives a [`SignedRevocationEntry`]
/// — every gossiped revocation carries an Ed25519 + ML-DSA-65 composite
/// signature that downstream nodes verify before applying.
pub trait RevocationBroadcaster: Send + Sync {
    /// Publish a signed revocation event to peers and (optionally) the chain.
    fn broadcast_revocation(&self, entry: &SignedRevocationEntry) -> crate::error::Result<()>;
}

/// Configurable enforcement policy for delegation scopes (HIGH #94).
#[derive(Debug, Clone, Copy)]
pub struct DelegationPolicy {
    /// Minimum reputation a machine must have for an operation to be allowed.
    pub min_reputation: u32,
    /// If true, machines whose controller is not Active have all operations denied.
    pub require_active_controller: bool,
}

impl Default for DelegationPolicy {
    fn default() -> Self {
        Self {
            min_reputation: 0,
            require_active_controller: true,
        }
    }
}

/// Result of an identity registration operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResult {
    /// The registered identity
    pub identity: TenzroIdentity,
    /// The fee required for this registration (in smallest TNZO unit)
    pub fee_required: u128,
}

/// Central registry for Tenzro Decentralized Identity Protocol identities
///
/// Thread-safe (DashMap-backed) registry supporting concurrent identity
/// operations on both human and machine identities through a unified type.
///
/// # Persistence
///
/// Identities are stored in-memory using DashMap. For persistence, use
/// `TenzroIdentity::to_bytes()` and `TenzroIdentity::from_bytes()` to
/// serialize/deserialize identities to/from a storage backend (e.g., RocksDB).
///
/// Future versions may add an optional `StorageBackend` trait for automatic
/// persistence without breaking existing in-memory-only usage.
///
/// # Registration Fees
///
/// The registry tracks registration fee requirements using `ServiceFeeSchedule`.
/// Fees are NOT deducted by the registry - actual fee collection happens at
/// the node/transaction level. The registry only reports what fee is required.
pub struct IdentityRegistry {
    /// All registered identities, keyed by DID string
    identities: DashMap<String, TenzroIdentity>,
    /// Revocation records
    revocations: DashMap<String, RevocationEntry>,
    /// Seen credential IDs for replay protection (MEDIUM #129).
    /// Every credential ID that has been issued or inherited is tracked
    /// here so duplicate submissions are rejected. Persisted to
    /// `CF_CREDENTIALS` when a storage backend is configured.
    seen_credential_ids: DashSet<String>,
    /// Username → DID mapping for on-chain username uniqueness
    usernames: DashMap<String, String>,
    /// Optional wallet binder for auto-provisioning
    wallet_binder: Option<Arc<WalletBinder>>,
    /// Fee schedule for registration operations
    fee_schedule: ServiceFeeSchedule,
    /// Optional persistent storage backend (RocksDB)
    storage: Option<Arc<dyn KvStore>>,
    /// Optional remote DID resolution backend (HIGH #93)
    resolution_backend: Option<Arc<dyn DidResolutionBackend>>,
    /// Optional revocation broadcaster (HIGH #96)
    revocation_broadcaster: Option<Arc<dyn RevocationBroadcaster>>,
    /// Delegation enforcement policy (HIGH #94)
    delegation_policy: DelegationPolicy,
    /// Optional ERC-8004 on-chain mirror.
    ///
    /// When set, every machine identity registration is automatically
    /// reflected into the on-chain ERC-8004 IdentityRegistry (typically
    /// the precompile at `0x101a` on Tenzro). The hook is best-effort —
    /// failures are logged but never roll back the TDIP registration.
    on_chain_agent_registry: Option<Arc<dyn crate::erc8004::OnChainAgentRegistry>>,
    /// Optional ERC-8004 SVM (Solana) mirror.
    ///
    /// When set, every machine identity registration is also reflected
    /// into the canonical QuantuLabs `agent_registry_8004` Anchor program
    /// (see [`crate::erc8004_svm::addresses::AGENT_REGISTRY_PROGRAM_ID_MAINNET_BETA`]).
    /// Best-effort, same semantics as the EVM mirror: failures are
    /// logged but never fail the TDIP registration.
    on_chain_agent_svm_registry: Option<Arc<dyn crate::erc8004_svm::OnChainAgentSvmRegistry>>,
    /// Optional ERC-8004 DAML (Canton) mirror.
    ///
    /// When set, every machine identity registration is also reflected
    /// into the canonical `Tenzro.Erc8004.Identity.RegistryAdmin.Register`
    /// choice (see `vendor/erc8004-daml/`). Best-effort, same semantics
    /// as the EVM and SVM mirrors: failures are logged but never fail
    /// the TDIP registration.
    on_chain_agent_daml_registry:
        Option<Arc<dyn crate::erc8004_daml::OnChainAgentDamlRegistry>>,
    /// Optional AgentBond lookup (Spec 9). When wired, the principal-chain
    /// resolver populates `actor_bond` and `controller_bond_aggregate` on
    /// every receipt. Implemented by `tenzro_token::bond::BondManager` at
    /// node startup; tests may pass a fake.
    bond_lookup: Option<Arc<dyn BondLookup>>,
}

impl IdentityRegistry {
    /// Creates a new identity registry without wallet auto-provisioning
    pub fn new() -> Self {
        info!("Initializing Tenzro Identity Registry");
        Self {
            identities: DashMap::new(),
            revocations: DashMap::new(),
            seen_credential_ids: DashSet::new(),
            usernames: DashMap::new(),
            wallet_binder: None,
            fee_schedule: ServiceFeeSchedule::default(),
            storage: None,
            resolution_backend: None,
            revocation_broadcaster: None,
            delegation_policy: DelegationPolicy::default(),
            on_chain_agent_registry: None,
            on_chain_agent_svm_registry: None,
            on_chain_agent_daml_registry: None,
            bond_lookup: None,
        }
    }

    /// Creates a new identity registry with wallet auto-provisioning
    pub fn with_wallet_binder(wallet_binder: Arc<WalletBinder>) -> Self {
        info!("Initializing Tenzro Identity Registry with wallet binding");
        Self {
            identities: DashMap::new(),
            revocations: DashMap::new(),
            seen_credential_ids: DashSet::new(),
            usernames: DashMap::new(),
            wallet_binder: Some(wallet_binder),
            fee_schedule: ServiceFeeSchedule::default(),
            storage: None,
            resolution_backend: None,
            revocation_broadcaster: None,
            delegation_policy: DelegationPolicy::default(),
            on_chain_agent_registry: None,
            on_chain_agent_svm_registry: None,
            on_chain_agent_daml_registry: None,
            bond_lookup: None,
        }
    }

    /// Creates a new identity registry with custom fee schedule
    pub fn with_fee_schedule(fee_schedule: ServiceFeeSchedule) -> Self {
        info!("Initializing Tenzro Identity Registry with custom fee schedule");
        Self {
            identities: DashMap::new(),
            revocations: DashMap::new(),
            seen_credential_ids: DashSet::new(),
            usernames: DashMap::new(),
            wallet_binder: None,
            fee_schedule,
            storage: None,
            resolution_backend: None,
            revocation_broadcaster: None,
            delegation_policy: DelegationPolicy::default(),
            on_chain_agent_registry: None,
            on_chain_agent_svm_registry: None,
            on_chain_agent_daml_registry: None,
            bond_lookup: None,
        }
    }

    /// Creates a new identity registry with persistent RocksDB storage
    ///
    /// Loads all existing identities from storage into the in-memory DashMap
    /// on initialization, then writes through to storage on every mutation.
    /// Also hydrates the `seen_credential_ids` set from `CF_CREDENTIALS`
    /// so replay protection survives restarts (MEDIUM #129).
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        info!("Initializing Tenzro Identity Registry with persistent storage");
        let identities = DashMap::new();
        let revocations = DashMap::new();
        let seen_credential_ids = DashSet::new();

        // Load existing identities from storage
        match storage.get_keys_with_prefix(CF_IDENTITIES, b"did:") {
            Ok(keys) => {
                let mut loaded = 0usize;
                for key in &keys {
                    if let Ok(Some(data)) = storage.get(CF_IDENTITIES, key)
                        && let Ok(identity) = bincode::deserialize::<TenzroIdentity>(&data)
                    {
                        let did_string = identity.did.to_string();
                        if identity.status == IdentityStatus::Revoked {
                            revocations.insert(did_string.clone(), RevocationEntry {
                                did: did_string.clone(),
                                revoked_at: identity.updated_at,
                                reason: "loaded from storage".to_string(),
                                revoked_by: "system".to_string(),
                            });
                        }
                        identities.insert(did_string, identity);
                        loaded += 1;
                    }
                }
                info!("Loaded {} identities from persistent storage", loaded);
            }
            Err(e) => {
                warn!("Failed to load identities from storage: {}", e);
            }
        }

        // Hydrate seen credential IDs from CF_CREDENTIALS (MEDIUM #129)
        match storage.get_keys_with_prefix(CF_CREDENTIALS, b"cred:") {
            Ok(keys) => {
                let mut loaded_creds = 0usize;
                for key in &keys {
                    if let Ok(cred_id) = std::str::from_utf8(key) {
                        let id = cred_id.strip_prefix("cred:").unwrap_or(cred_id);
                        seen_credential_ids.insert(id.to_string());
                        loaded_creds += 1;
                    }
                }
                if loaded_creds > 0 {
                    info!("Loaded {} seen credential IDs from storage", loaded_creds);
                }
            }
            Err(e) => {
                warn!("Failed to load credential IDs from storage: {}", e);
            }
        }

        // Hydrate username → DID mappings from storage
        let usernames = DashMap::new();
        match storage.get_keys_with_prefix(CF_IDENTITIES, b"username:") {
            Ok(keys) => {
                let mut loaded_usernames = 0usize;
                for key in &keys {
                    if let Ok(Some(data)) = storage.get(CF_IDENTITIES, key)
                        && let Ok(did) = std::str::from_utf8(&data)
                        && let Ok(uname) = std::str::from_utf8(key)
                    {
                        let uname = uname.strip_prefix("username:").unwrap_or(uname);
                        usernames.insert(uname.to_string(), did.to_string());
                        loaded_usernames += 1;
                    }
                }
                if loaded_usernames > 0 {
                    info!("Loaded {} username mappings from storage", loaded_usernames);
                }
            }
            Err(e) => {
                warn!("Failed to load username mappings from storage: {}", e);
            }
        }

        Self {
            identities,
            revocations,
            seen_credential_ids,
            usernames,
            wallet_binder: None,
            fee_schedule: ServiceFeeSchedule::default(),
            storage: Some(storage),
            resolution_backend: None,
            revocation_broadcaster: None,
            delegation_policy: DelegationPolicy::default(),
            on_chain_agent_registry: None,
            on_chain_agent_svm_registry: None,
            on_chain_agent_daml_registry: None,
            bond_lookup: None,
        }
    }

    /// Sets the storage backend (builder pattern)
    pub fn with_storage_backend(mut self, storage: Arc<dyn KvStore>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Attaches a wallet binder (builder pattern).
    ///
    /// Composes with `with_storage`, `with_resolution_backend`, etc. so the
    /// node can stack persistent storage and a shared wallet service onto a
    /// single registry instance. When set, `register_human_with_fee` and
    /// `register_machine_with_fee` provision real MPC wallets through the
    /// binder's `WalletService`; without it, those calls fall back to a
    /// deterministic placeholder address with no signable wallet — useful for
    /// tests but never correct for a live node.
    pub fn with_wallet_binder_arc(mut self, wallet_binder: Arc<WalletBinder>) -> Self {
        self.wallet_binder = Some(wallet_binder);
        self
    }

    /// Returns `true` when this registry has a [`WalletBinder`] configured.
    ///
    /// Callers that require auto-provisioned wallets (e.g. the agent-kit
    /// spawner, which mints both controller and machine identities and
    /// expects each to come back with a signable on-chain address) can
    /// assert this up-front rather than discover the missing-binder
    /// fallback path silently. Returns `false` for in-memory test
    /// registries constructed via [`Self::new`] / [`Self::with_storage`]
    /// without a binder, where `register_*_with_fee` falls back to a
    /// deterministic placeholder address with no signable wallet.
    pub fn has_wallet_binder(&self) -> bool {
        self.wallet_binder.is_some()
    }

    /// Attaches a remote DID resolution backend (HIGH #93).
    ///
    /// When `resolve()` cannot find the DID locally, the registry will fall
    /// back to this backend (typically a JSON-RPC client to a Tenzro node)
    /// to look up the canonical record.
    pub fn with_resolution_backend(mut self, backend: Arc<dyn DidResolutionBackend>) -> Self {
        self.resolution_backend = Some(backend);
        self
    }

    /// Attaches a revocation broadcaster (HIGH #96).
    ///
    /// When `revoke()` is called, the registry will publish the revocation
    /// event through this broadcaster after the local cascade completes so
    /// peer nodes can update their caches.
    pub fn with_revocation_broadcaster(mut self, broadcaster: Arc<dyn RevocationBroadcaster>) -> Self {
        self.revocation_broadcaster = Some(broadcaster);
        self
    }

    /// Configures the delegation enforcement policy (HIGH #94).
    pub fn with_delegation_policy(mut self, policy: DelegationPolicy) -> Self {
        self.delegation_policy = policy;
        self
    }

    /// Wires an ERC-8004 on-chain mirror so every machine identity
    /// registration is reflected into the on-chain IdentityRegistry
    /// (typically the Tenzro precompile at `0x101a`). Best-effort:
    /// failures are logged but never fail the TDIP registration.
    pub fn with_on_chain_agent_registry(
        mut self,
        registry: Arc<dyn crate::erc8004::OnChainAgentRegistry>,
    ) -> Self {
        self.on_chain_agent_registry = Some(registry);
        self
    }

    /// Wires a Solana-side ERC-8004 mirror so every machine identity
    /// registration is reflected into the canonical QuantuLabs
    /// `agent_registry_8004` Anchor program at
    /// [`crate::erc8004_svm::addresses::AGENT_REGISTRY_PROGRAM_ID_MAINNET_BETA`].
    /// Best-effort, same semantics as
    /// [`Self::with_on_chain_agent_registry`]: failures are logged but
    /// never fail the TDIP registration.
    pub fn with_on_chain_agent_svm_registry(
        mut self,
        registry: Arc<dyn crate::erc8004_svm::OnChainAgentSvmRegistry>,
    ) -> Self {
        self.on_chain_agent_svm_registry = Some(registry);
        self
    }

    /// Wires a Canton/DAML-side ERC-8004 mirror so every machine
    /// identity registration is reflected into the in-tree
    /// `Tenzro.Erc8004.Identity.RegistryAdmin.Register` choice (see
    /// `vendor/erc8004-daml/`). Best-effort, same semantics as
    /// [`Self::with_on_chain_agent_registry`] and
    /// [`Self::with_on_chain_agent_svm_registry`]: failures are logged
    /// but never fail the TDIP registration.
    pub fn with_on_chain_agent_daml_registry(
        mut self,
        registry: Arc<dyn crate::erc8004_daml::OnChainAgentDamlRegistry>,
    ) -> Self {
        self.on_chain_agent_daml_registry = Some(registry);
        self
    }

    /// Wires an AgentBond lookup (Spec 9). When set, the principal-chain
    /// resolver populates `actor_bond` and `controller_bond_aggregate` on
    /// every receipt. Implemented by `tenzro_token::bond::BondManager` at
    /// node startup.
    pub fn with_bond_lookup(mut self, lookup: Arc<dyn BondLookup>) -> Self {
        self.bond_lookup = Some(lookup);
        self
    }

    /// Returns the active delegation policy (HIGH #94).
    pub fn delegation_policy(&self) -> DelegationPolicy {
        self.delegation_policy
    }

    /// Persists an identity to storage (write-through)
    /// Apply a canonical ERC-8004 `Registered(uint256 indexed agentId,
    /// string agentURI, address indexed owner)` event to the cached TDIP
    /// identity record + persistent store.
    ///
    /// Called by the node's `erc8004_event_listener` once the
    /// `register(string agentURI)` tx submitted by `NativeErc8004Mirror`
    /// is included on-chain. Patches `IdentityData::Machine.erc8004_agent_id`
    /// on the in-memory `DashMap` and re-serializes the record to
    /// `CF_IDENTITIES`.
    ///
    /// Returns `Ok(true)` if a matching identity existed and was patched;
    /// `Ok(false)` if no identity is cached under `did` (e.g. the event
    /// fired against a TDIP record on a different node). Errors only on
    /// non-machine identities (humans don't carry an `erc8004_agent_id`).
    ///
    /// Idempotent — re-applying the same event is a no-op write of the
    /// same value.
    pub fn apply_erc8004_registered_event(
        &self,
        did: &str,
        agent_id: u64,
    ) -> Result<bool> {
        let Some(mut entry) = self.identities.get_mut(did) else {
            return Ok(false);
        };
        if !entry.is_machine() {
            return Err(IdentityError::VerificationFailed(format!(
                "ERC-8004 Registered event applied to non-machine DID '{}'",
                did
            )));
        }
        entry.set_erc8004_agent_id(agent_id);
        let patched = entry.clone();
        // Release the DashMap write guard before any other map access.
        drop(entry);
        self.persist_identity(did, &patched);
        Ok(true)
    }

    fn persist_identity(&self, did: &str, identity: &TenzroIdentity) {
        if let Some(ref store) = self.storage {
            match bincode::serialize(identity) {
                Ok(data) => {
                    if let Err(e) = store.put(CF_IDENTITIES, did.as_bytes(), &data) {
                        warn!("Failed to persist identity {}: {}", did, e);
                    }
                }
                Err(e) => {
                    warn!("Failed to serialize identity {}: {}", did, e);
                }
            }
        }
    }

    /// Records a credential ID as seen, rejecting duplicates (MEDIUM #129).
    ///
    /// Returns `Err(DuplicateCredential)` if the credential ID has already
    /// been issued. On success, persists the ID to `CF_CREDENTIALS` so the
    /// replay check survives node restarts.
    fn record_credential_id(&self, credential_id: &str) -> Result<()> {
        if !self.seen_credential_ids.insert(credential_id.to_string()) {
            return Err(IdentityError::DuplicateCredential(
                credential_id.to_string(),
            ));
        }
        // Persist to storage
        if let Some(ref store) = self.storage {
            let key = format!("cred:{}", credential_id);
            // Value is a timestamp for auditability
            let ts = Utc::now().timestamp().to_le_bytes();
            if let Err(e) = store.put(CF_CREDENTIALS, key.as_bytes(), &ts) {
                warn!("Failed to persist credential ID {}: {}", credential_id, e);
            }
        }
        Ok(())
    }

    /// Hard-deletes an identity record from RocksDB.
    ///
    /// Used by [`Self::forget_identity`] to satisfy TDIP/GDPR Article 17
    /// right-to-erasure: the identity must already be `Revoked` (logical
    /// delete) before the record can be physically removed from storage.
    /// This is distinct from `revoke()`, which keeps the row for audit.
    fn remove_from_storage(&self, did: &str) {
        if let Some(ref store) = self.storage
            && let Err(e) = store.delete(CF_IDENTITIES, did.as_bytes())
        {
            warn!("Failed to delete identity {} from storage: {}", did, e);
        }
    }

    /// TDIP/GDPR Article 17 right-to-erasure.
    ///
    /// Hard-deletes a previously-revoked identity from both the in-memory
    /// registry and persistent storage. The identity MUST already be in
    /// `IdentityStatus::Revoked` — callers must `revoke()` first, observe the
    /// revocation has propagated, and only then call `forget_identity()`.
    /// This two-phase approach gives downstream consumers (cascading revoke,
    /// remote nodes via `RevocationBroadcaster`) a chance to react to the
    /// status change before the record vanishes.
    pub fn forget_identity(&self, did: &str) -> Result<()> {
        let identity = self
            .identities
            .get(did)
            .ok_or_else(|| IdentityError::NotFound(did.to_string()))?;
        if identity.status != IdentityStatus::Revoked {
            return Err(IdentityError::PermissionDenied(format!(
                "identity {} must be Revoked before erasure (current: {:?})",
                did, identity.status
            )));
        }
        drop(identity);
        self.identities.remove(did);
        self.remove_from_storage(did);
        Ok(())
    }

    /// Returns the current fee schedule
    pub fn fee_schedule(&self) -> &ServiceFeeSchedule {
        &self.fee_schedule
    }

    /// Returns the registration fee for a human identity
    pub fn human_registration_fee(&self) -> u128 {
        self.fee_schedule.human_identity_registration
    }

    /// Returns the registration fee for a machine identity
    pub fn machine_registration_fee(&self) -> u128 {
        self.fee_schedule.machine_identity_registration
    }

    /// Returns the credential issuance fee
    pub fn credential_issuance_fee(&self) -> u128 {
        self.fee_schedule.credential_issuance
    }

    /// Registers a new human identity and returns fee information
    ///
    /// Creates a human DID, optionally provisions a wallet, and stores
    /// the identity in the registry. Returns both the identity and the
    /// registration fee required.
    pub async fn register_human_with_fee(
        &self,
        public_key: Vec<u8>,
        display_name: String,
        kyc_tier: KycTier,
    ) -> Result<RegistrationResult> {
        let did = TenzroDid::new_human();
        let did_string = did.to_string();

        let (wallet_address, wallet_id, pq_verifying_key, bls_verifying_key) =
            self.provision_or_default(&did_string).await?;

        let identity = TenzroIdentity {
            did,
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "Ed25519".to_string(),
                public_key,
                purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod],
            }],
            identity_data: IdentityData::Human {
                display_name: display_name.clone(),
                kyc_tier,
                controlled_machines: Vec::new(),
            },
            status: IdentityStatus::Active,
            wallet_address,
            wallet_id,
            pq_verifying_key,
            bls_verifying_key,
            credentials: Vec::new(),
            services: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
            username: None,
        };

        let fee_required = self.fee_schedule.human_identity_registration;

        info!(
            "Registered human identity: {} (name: {}, kyc: {:?}, fee: {} TNZO)",
            did_string, display_name, kyc_tier, fee_required / 1_000_000_000_000_000_000
        );

        self.persist_identity(&did_string, &identity);
        self.identities.insert(did_string, identity.clone());
        Ok(RegistrationResult {
            identity,
            fee_required,
        })
    }

    /// Registers a human identity by provisioning the wallet through the
    /// configured `WalletBinder`, then using that wallet's classical public
    /// key as the identity's `public_keys[0]`.
    ///
    /// This is the production onboarding path used by `tenzro_onboardHuman`,
    /// `tenzro_participate`, and the desktop Setup flow: a single MPC wallet
    /// is provisioned in the shared `WalletService`, its `wallet_id` is
    /// stored on the identity, and the same keypair signs both at the
    /// authentication layer (key purposes Authentication + AssertionMethod)
    /// and at the wallet-mediated transaction layer. The auth-mediated
    /// signing path (`AuthEngine::resolve_authority` →
    /// `find_wallet_id_for_did`) returns the same `wallet_id` that the
    /// onboarding response carried, so signing succeeds immediately.
    ///
    /// Returns `IdentityError::WalletError("no wallet binder configured")`
    /// if called on a registry without a binder — production node startup
    /// must wire one via `with_wallet_binder_arc`.
    pub async fn register_human_via_binder(
        &self,
        display_name: String,
        kyc_tier: KycTier,
    ) -> Result<RegistrationResult> {
        let did = TenzroDid::new_human();
        let did_string = did.to_string();

        let binder = self.wallet_binder.as_ref().ok_or_else(|| {
            IdentityError::WalletError("no wallet binder configured".to_string())
        })?;
        let binding = binder.provision_wallet(&did_string).await?;

        let identity = TenzroIdentity {
            did,
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: binding.key_type.clone(),
                public_key: binding.public_key.clone(),
                purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod],
            }],
            identity_data: IdentityData::Human {
                display_name: display_name.clone(),
                kyc_tier,
                controlled_machines: Vec::new(),
            },
            status: IdentityStatus::Active,
            wallet_address: binding.address,
            wallet_id: binding.wallet_id,
            pq_verifying_key: binding.pq_verifying_key,
            bls_verifying_key: binding.bls_verifying_key,
            credentials: Vec::new(),
            services: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
            username: None,
        };

        let fee_required = self.fee_schedule.human_identity_registration;

        info!(
            "Registered human identity via binder: {} (name: {}, kyc: {:?}, fee: {} TNZO)",
            did_string,
            display_name,
            kyc_tier,
            fee_required / 1_000_000_000_000_000_000
        );

        self.persist_identity(&did_string, &identity);
        self.identities.insert(did_string, identity.clone());
        Ok(RegistrationResult {
            identity,
            fee_required,
        })
    }

    /// Registers a machine identity by provisioning the wallet through the
    /// configured `WalletBinder`. The binder-provisioned wallet's classical
    /// public key becomes the identity's `public_keys[0]`, and the binder's
    /// `wallet_id` is what `find_wallet_id_for_did` returns later — so the
    /// auth-mediated signing path resolves to a wallet the shared
    /// `WalletService` can actually sign with.
    ///
    /// Pass `controller_did = "self"` for an autonomous machine (the registry
    /// stores `controller_did = None` for self-controlled machines per the
    /// `did:tenzro:machine:<uuid>` convention); otherwise pass the human
    /// controller's DID.
    pub async fn register_machine_via_binder(
        &self,
        controller_did: &str,
        capabilities: Vec<String>,
        delegation_scope: DelegationScope,
    ) -> Result<RegistrationResult> {
        let is_autonomous = controller_did == "self";

        // Validate controller (skip for autonomous self-controlled machines)
        let controller_id = if is_autonomous {
            uuid::Uuid::new_v4().to_string()
        } else {
            let controller = self
                .identities
                .get(controller_did)
                .ok_or_else(|| IdentityError::NotFound(controller_did.to_string()))?;

            if controller.status != IdentityStatus::Active {
                return Err(IdentityError::NotActive(format!(
                    "controller {} is {:?}",
                    controller_did, controller.status
                )));
            }
            if !controller.is_human() {
                return Err(IdentityError::PermissionDenied(
                    "controller must be a human identity".to_string(),
                ));
            }
            controller.did.id.clone()
        };

        let did = if is_autonomous {
            TenzroDid::new_autonomous_machine()
        } else {
            TenzroDid::new_machine(&controller_id)
        };
        let did_string = did.to_string();

        let binder = self.wallet_binder.as_ref().ok_or_else(|| {
            IdentityError::WalletError("no wallet binder configured".to_string())
        })?;
        let binding = binder.provision_wallet(&did_string).await?;

        let identity = TenzroIdentity {
            did,
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: binding.key_type.clone(),
                public_key: binding.public_key.clone(),
                purposes: vec![KeyPurpose::Authentication],
            }],
            identity_data: IdentityData::Machine {
                capabilities: capabilities.clone(),
                delegation_scope,
                controller_did: if is_autonomous {
                    None
                } else {
                    Some(controller_did.to_string())
                },
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
                is_seed_agent: false,
            },
            status: IdentityStatus::Active,
            wallet_address: binding.address,
            wallet_id: binding.wallet_id,
            pq_verifying_key: binding.pq_verifying_key,
            bls_verifying_key: binding.bls_verifying_key,
            credentials: Vec::new(),
            services: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
            username: None,
        };

        let fee_required = self.fee_schedule.machine_identity_registration;

        info!(
            "Registered machine identity via binder: {} (controller: {}, capabilities: {:?}, fee: {} TNZO)",
            did_string,
            controller_did,
            capabilities,
            fee_required / 1_000_000_000_000_000_000
        );

        // Append child to controller's controlled_machines list
        if !is_autonomous
            && let Some(mut controller) = self.identities.get_mut(controller_did)
            && let IdentityData::Human {
                ref mut controlled_machines,
                ..
            } = controller.identity_data
        {
            controlled_machines.push(did_string.clone());
            controller.updated_at = Utc::now();
            let snapshot = controller.clone();
            drop(controller);
            self.persist_identity(controller_did, &snapshot);
        }

        // Dispatch the ERC-8004 mirror as a detached signed-tx submission.
        // The allocated `agentId` is NOT available synchronously — the off-chain
        // `Registered(uint256,string,address)` event listener in `tenzro-node`
        // patches `IdentityData::Machine.erc8004_agent_id` on the cached TDIP
        // record once the mirror tx is included.
        self.mirror_to_erc8004(&did_string, &identity);

        self.persist_identity(&did_string, &identity);
        self.identities.insert(did_string, identity.clone());
        Ok(RegistrationResult {
            identity,
            fee_required,
        })
    }

    /// Registers a new machine identity under a human controller with fee information
    pub async fn register_machine_with_fee(
        &self,
        controller_did: &str,
        public_key: Vec<u8>,
        capabilities: Vec<String>,
        delegation_scope: DelegationScope,
    ) -> Result<RegistrationResult> {
        // Validate controller exists and is active
        let controller_id = {
            let controller = self
                .identities
                .get(controller_did)
                .ok_or_else(|| IdentityError::NotFound(controller_did.to_string()))?;

            if controller.status != IdentityStatus::Active {
                return Err(IdentityError::NotActive(format!(
                    "controller {} is {:?}",
                    controller_did, controller.status
                )));
            }

            if !controller.is_human() {
                return Err(IdentityError::PermissionDenied(
                    "controller must be a human identity".to_string(),
                ));
            }

            // Extract the UUID from the controller DID for the child DID
            controller.did.id.clone()
        };

        let did = TenzroDid::new_machine(&controller_id);
        let did_string = did.to_string();

        let (wallet_address, wallet_id, pq_verifying_key, bls_verifying_key) =
            self.provision_or_default(&did_string).await?;

        let identity = TenzroIdentity {
            did,
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "Ed25519".to_string(),
                public_key,
                purposes: vec![KeyPurpose::Authentication],
            }],
            identity_data: IdentityData::Machine {
                capabilities: capabilities.clone(),
                delegation_scope,
                controller_did: Some(controller_did.to_string()),
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
                is_seed_agent: false,
            },
            status: IdentityStatus::Active,
            wallet_address,
            wallet_id,
            pq_verifying_key,
            bls_verifying_key,
            credentials: Vec::new(),
            services: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
            username: None,
        };

        let fee_required = self.fee_schedule.machine_identity_registration;

        info!(
            "Registered machine identity: {} under controller: {} with capabilities: {:?}, fee: {} TNZO",
            did_string, controller_did, capabilities, fee_required / 1_000_000_000_000_000_000
        );

        // Add machine to controller's list
        if let Some(mut controller) = self.identities.get_mut(controller_did) {
            if let IdentityData::Human {
                ref mut controlled_machines,
                ..
            } = controller.identity_data
            {
                controlled_machines.push(did_string.clone());
            }
            // Persist updated controller
            self.persist_identity(controller_did, &controller);
        }

        // Dispatch the ERC-8004 mirror as a detached signed-tx submission.
        // The allocated `agentId` is NOT available synchronously — the off-chain
        // `Registered(uint256,string,address)` event listener in `tenzro-node`
        // patches `IdentityData::Machine.erc8004_agent_id` on the cached TDIP
        // record once the mirror tx is included.
        self.mirror_to_erc8004(&did_string, &identity);

        self.persist_identity(&did_string, &identity);
        self.identities.insert(did_string, identity.clone());
        Ok(RegistrationResult {
            identity,
            fee_required,
        })
    }

    /// Registers an autonomous machine identity (no human controller, backward compatible)
    ///
    /// **Note:** This method does not return fee information. Use `register_autonomous_machine_with_fee()`
    /// if you need to know the required registration fee.
    pub async fn register_autonomous_machine(
        &self,
        public_key: Vec<u8>,
        capabilities: Vec<String>,
    ) -> Result<TenzroIdentity> {
        let result = self.register_autonomous_machine_with_fee(public_key, capabilities).await?;
        Ok(result.identity)
    }

    /// Registers an autonomous machine identity with fee information
    pub async fn register_autonomous_machine_with_fee(
        &self,
        public_key: Vec<u8>,
        capabilities: Vec<String>,
    ) -> Result<RegistrationResult> {
        let did = TenzroDid::new_autonomous_machine();
        let did_string = did.to_string();

        let (wallet_address, wallet_id, pq_verifying_key, bls_verifying_key) =
            self.provision_or_default(&did_string).await?;

        let identity = TenzroIdentity {
            did,
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "Ed25519".to_string(),
                public_key,
                purposes: vec![KeyPurpose::Authentication],
            }],
            identity_data: IdentityData::Machine {
                capabilities: capabilities.clone(),
                delegation_scope: DelegationScope::unrestricted(),
                controller_did: None,
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
                is_seed_agent: false,
            },
            status: IdentityStatus::Active,
            wallet_address,
            wallet_id,
            pq_verifying_key,
            bls_verifying_key,
            credentials: Vec::new(),
            services: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
            username: None,
        };

        let fee_required = self.fee_schedule.machine_identity_registration;

        info!(
            "Registered autonomous machine identity: {} with capabilities: {:?}, fee: {} TNZO",
            did_string, capabilities, fee_required / 1_000_000_000_000_000_000
        );

        // Dispatch the ERC-8004 mirror as a detached signed-tx submission.
        // The allocated `agentId` is NOT available synchronously — the off-chain
        // `Registered(uint256,string,address)` event listener in `tenzro-node`
        // patches `IdentityData::Machine.erc8004_agent_id` on the cached TDIP
        // record once the mirror tx is included.
        self.mirror_to_erc8004(&did_string, &identity);

        self.persist_identity(&did_string, &identity);
        self.identities.insert(did_string, identity.clone());
        Ok(RegistrationResult {
            identity,
            fee_required,
        })
    }

    /// Registers an autonomous machine identity using **caller-supplied
    /// keys** instead of provisioning a server-side wallet (BYOK path).
    ///
    /// The caller passes their own classical (Ed25519) and post-quantum
    /// (ML-DSA-65) verifying keys. The wallet binder is **not** invoked —
    /// no `WalletBinding` is created and no FROST shares are minted on the
    /// node. The identity's `wallet_address` is derived deterministically
    /// from the supplied Ed25519 key as `Address(SHA-256(public_key))` so
    /// it is reproducible by the caller without a round-trip.
    ///
    /// This is the path used by self-custodial agent operators that hold
    /// their own private keys (typically inside a hardware wallet, MPC
    /// network, or another node) and don't want the registry node to be
    /// able to sign on their behalf.
    ///
    /// # Arguments
    ///
    /// * `public_key` — 32-byte Ed25519 verifying key.
    /// * `pq_verifying_key` — 1952-byte ML-DSA-65 (FIPS 204) verifying key.
    /// * `bls_verifying_key` — 48-byte BLS12-381 G1-compressed verifying key
    ///   (`min_pk` scheme), used for HotStuff-2 vote aggregation.
    /// * `capabilities` — opaque capability strings stored on the identity.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::InvalidPublicKey` when the classical key is
    /// not 32 bytes, the post-quantum key is not 1952 bytes, or the BLS key
    /// is not 48 bytes.
    pub async fn register_autonomous_machine_with_keys(
        &self,
        public_key: Vec<u8>,
        pq_verifying_key: Vec<u8>,
        bls_verifying_key: Vec<u8>,
        capabilities: Vec<String>,
    ) -> Result<RegistrationResult> {
        if public_key.len() != 32 {
            return Err(IdentityError::InvalidPublicKey(format!(
                "Ed25519 verifying key must be exactly 32 bytes, got {}",
                public_key.len()
            )));
        }
        if pq_verifying_key.len() != 1952 {
            return Err(IdentityError::InvalidPublicKey(format!(
                "ML-DSA-65 verifying key must be exactly 1952 bytes, got {}",
                pq_verifying_key.len()
            )));
        }
        if bls_verifying_key.len() != 48 {
            return Err(IdentityError::InvalidPublicKey(format!(
                "BLS12-381 G1-compressed verifying key must be exactly 48 bytes, got {}",
                bls_verifying_key.len()
            )));
        }

        let did = TenzroDid::new_autonomous_machine();
        let did_string = did.to_string();

        // Deterministic wallet_address from the Ed25519 verifying key. The
        // caller can reproduce this off-node without any registry round-trip.
        let hash = tenzro_crypto::sha256(&public_key);
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(hash.as_bytes());
        let wallet_address = Address::new(addr_bytes);

        // Self-custodial wallets have no node-side wallet_id; use a stable,
        // public marker derived from the DID so audit logs can correlate.
        let wallet_id = format!("byok-{}", &did_string[did_string.len().saturating_sub(12)..]);

        let identity = TenzroIdentity {
            did,
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "Ed25519".to_string(),
                public_key,
                purposes: vec![KeyPurpose::Authentication],
            }],
            identity_data: IdentityData::Machine {
                capabilities: capabilities.clone(),
                delegation_scope: DelegationScope::unrestricted(),
                controller_did: None,
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
                is_seed_agent: false,
            },
            status: IdentityStatus::Active,
            wallet_address,
            wallet_id,
            pq_verifying_key,
            bls_verifying_key,
            credentials: Vec::new(),
            services: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
            username: None,
        };

        let fee_required = self.fee_schedule.machine_identity_registration;

        info!(
            "Registered autonomous machine identity (BYOK): {} with capabilities: {:?}, fee: {} TNZO",
            did_string,
            capabilities,
            fee_required / 1_000_000_000_000_000_000
        );

        // Dispatch the ERC-8004 mirror as a detached signed-tx submission.
        // The allocated `agentId` is NOT available synchronously — see the
        // companion mirror calls earlier in this file for the rationale.
        self.mirror_to_erc8004(&did_string, &identity);

        self.persist_identity(&did_string, &identity);
        self.identities.insert(did_string, identity.clone());
        Ok(RegistrationResult {
            identity,
            fee_required,
        })
    }

    /// Mirror a freshly-registered machine identity into the on-chain
    /// ERC-8004 IdentityRegistry contract at
    /// [`tenzro_identity::erc8004::addresses::IDENTITY_REGISTRY`], if a
    /// mirror is wired. Best-effort — any error is logged at warn level
    /// and dropped so the TDIP registration succeeds regardless.
    ///
    /// The on-chain `agentId` is **not** returned synchronously: the
    /// mirror dispatches a signed EIP-1559 tx as a detached tokio task
    /// and the `agentId` is allocated by the contract at inclusion time.
    /// The off-chain event listener (`Registered(uint256,string,address)`)
    /// in `tenzro-node` is responsible for writing the resulting
    /// `(did → agentId)` pair into the `erc8004_did_index:` keyspace and
    /// patching `IdentityData::Machine.erc8004_agent_id` on the cached
    /// TDIP record. Callers that need the `agentId` immediately should
    /// poll via `OnChainAgentRegistry::lookup_agent_id_by_did`.
    fn mirror_to_erc8004(&self, did_string: &str, identity: &TenzroIdentity) {
        let Some(registry) = self.on_chain_agent_registry.as_ref() else {
            return;
        };
        // Only machines are mirrored — humans don't have an ERC-8004 record.
        if !identity.is_machine() {
            return;
        }
        // Map the bound wallet's hex string to a 20-byte EVM address. If the
        // wallet binder produced a non-EVM placeholder (legacy stub), zero out
        // the address — the on-chain record still resolves, just without a
        // wallet pointer.
        let agent_address = derive_evm_address(&identity.wallet_address);
        // Metadata URI = the canonical DID URL. Future: route through a
        // gateway that resolves to the W3C DID document JSON.
        let metadata_uri = format!("did:{}", did_string.trim_start_matches("did:"));
        if let Err(e) =
            registry.mirror_register_agent(did_string, &agent_address, &metadata_uri)
        {
            tracing::warn!(
                "ERC-8004 mirror dispatch failed for {}: {} (TDIP registration unaffected)",
                did_string,
                e
            );
        } else {
            tracing::debug!(
                "ERC-8004 mirror dispatched for {}: signed tx submitted, agentId arrives via event",
                did_string,
            );
        }

        // Parallel SVM mirror — same best-effort semantics. The Anchor
        // program assigns the asset Pubkey at instruction inclusion time;
        // the off-chain event listener in `tenzro-node`
        // (`process_erc8004_svm_agent_registered_logs`) is responsible
        // for writing the resulting `(did → asset)` pair into the
        // `erc8004_svm_did_index:` keyspace.
        if let Some(svm_registry) = self.on_chain_agent_svm_registry.as_ref() {
            if let Err(e) = svm_registry.mirror_register_agent(did_string, &metadata_uri) {
                tracing::warn!(
                    "ERC-8004 SVM mirror dispatch failed for {}: {} (TDIP registration unaffected)",
                    did_string,
                    e
                );
            } else {
                tracing::debug!(
                    "ERC-8004 SVM mirror dispatched for {}: signed Anchor ix submitted, asset arrives via event",
                    did_string,
                );
            }
        }

        // Parallel DAML mirror — same best-effort semantics. The DAML
        // `RegistryAdmin.Register` choice allocates `agentId` from the
        // admin-controlled counter at submit-and-wait inclusion time;
        // the off-chain Canton event listener in `tenzro-node`
        // (`process_erc8004_daml_registered_events`) is responsible for
        // writing the resulting `(did → agentId)` pair into the
        // `erc8004_daml_did_index:` keyspace.
        if let Some(daml_registry) = self.on_chain_agent_daml_registry.as_ref() {
            if let Err(e) = daml_registry.mirror_register_agent(did_string, &metadata_uri) {
                tracing::warn!(
                    "ERC-8004 DAML mirror dispatch failed for {}: {} (TDIP registration unaffected)",
                    did_string,
                    e
                );
            } else {
                tracing::debug!(
                    "ERC-8004 DAML mirror dispatched for {}: submit-and-wait command queued, agentId arrives via event",
                    did_string,
                );
            }
        }
    }

    /// Resolves a DID to its identity.
    ///
    /// Resolution order (HIGH #93):
    ///   1. Direct DashMap lookup by the supplied string.
    ///   2. Lookup by canonical form (after `TenzroDid::parse`).
    ///   3. Optional remote `DidResolutionBackend` (e.g. JSON-RPC to a node).
    ///      A successful remote hit is cached locally so subsequent reads
    ///      avoid the network round-trip.
    pub fn resolve(&self, did: &str) -> Result<TenzroIdentity> {
        // Try direct lookup first
        if let Some(identity) = self.identities.get(did) {
            return Ok(identity.clone());
        }

        // Try parsing and canonicalizing the DID
        let canonical = match TenzroDid::parse(did) {
            Ok(parsed) => parsed.to_string_canonical(),
            // If the DID can't even be parsed, fall through to remote lookup
            // using the raw string — the backend may handle other formats.
            Err(_) => did.to_string(),
        };

        if let Some(id) = self.identities.get(&canonical) {
            return Ok(id.clone());
        }

        // Remote fallback: blockchain / RPC lookup (HIGH #93)
        if let Some(ref backend) = self.resolution_backend {
            match backend.resolve_remote(&canonical) {
                Ok(Some(identity)) => {
                    debug!("Resolved DID {} via remote backend", canonical);
                    let key = identity.did.to_string();
                    // Cache locally so future lookups skip the round-trip.
                    self.identities.insert(key.clone(), identity.clone());
                    return Ok(identity);
                }
                Ok(None) => {
                    debug!("Remote backend has no record of {}", canonical);
                }
                Err(e) => {
                    warn!("Remote DID resolution for {} failed: {}", canonical, e);
                }
            }
        }

        Err(IdentityError::NotFound(did.to_string()))
    }

    /// Resolves a DID to its bound MPC wallet id.
    ///
    /// Convenience wrapper over [`Self::resolve`] that drops everything
    /// except the wallet handle. The auth-mediated signing path
    /// ([`tenzro-auth`]'s `AuthEngine::resolve_authority`) calls this
    /// to translate a JWT's `controller_did` into the wallet id that
    /// the wallet service needs for signing.
    ///
    /// Returns the same errors as `resolve` (`NotFound` if the DID is
    /// unknown locally and not resolvable via the configured remote
    /// backend).
    pub fn find_wallet_id_for_did(&self, did: &str) -> Result<String> {
        Ok(self.resolve(did)?.wallet_id)
    }

    /// Finds the local identity owning the given raw public key, if any.
    ///
    /// Used by `tenzro_linkWalletForAuth` to bind a fresh OAuth session
    /// to an existing TDIP DID instead of minting a duplicate identity
    /// every time the same wallet is linked. Match is on **any** entry
    /// of `public_keys[i].public_key` — humans and machines typically
    /// have a single key, but the API tolerates multi-key identities.
    ///
    /// Returns `None` if no local record matches; the caller decides
    /// whether to fall back to minting a new identity.
    pub fn find_identity_by_pubkey(&self, public_key: &[u8]) -> Option<TenzroIdentity> {
        self.identities
            .iter()
            .find(|entry| {
                entry
                    .value()
                    .public_keys
                    .iter()
                    .any(|pk| pk.public_key.as_slice() == public_key)
            })
            .map(|entry| entry.value().clone())
    }

    /// Reverse-lookup: find the local DID bound to `address` via its
    /// auto-provisioned MPC wallet.
    ///
    /// Linear scan over `identities` — fine for testnet sizes; if the
    /// registry grows beyond ~10⁵ entries this should be replaced with a
    /// `DashMap<Address, String>` reverse index maintained on every
    /// `register_*` mutation. Used by [`Self::resolve_by_address`] to
    /// build principal chains for receipts that key on EVM/SVM addresses
    /// rather than DIDs.
    pub fn find_did_by_address(&self, address: &Address) -> Option<String> {
        self.identities
            .iter()
            .find(|entry| entry.value().wallet_address == *address)
            .map(|entry| entry.key().clone())
    }

    /// Resolve the principal chain for a DID (Agent-Swarm Spec 5).
    ///
    /// Walks the controller chain bottom-up starting at `did`, capturing
    /// each link as a `PrincipalLink` and snapshotting the controller's
    /// KYC tier. Behavior:
    ///
    /// * The actor itself becomes either `chain[n-1]` (when it has a
    ///   controller) or the controller link (when it acts directly).
    /// * Walks `controller_did` up at most `MAX_DELEGATION_DEPTH` levels.
    ///   Cycles are detected via a visited-DID set; the cycle is broken
    ///   by tombstoning the offending link.
    /// * Unresolvable controllers (revoked, not-found, remote-resolution
    ///   failed) are recorded with `tombstone: true` rather than
    ///   returning an error — receipt writes never fail because identity
    ///   is unavailable.
    /// * KYC tier is taken from the topmost human controller. If the
    ///   chain terminates at an autonomous machine (no controller), tier
    ///   defaults to 0.
    /// * `controller_bond`, `actor_bond`, and `controller_bond_aggregate`
    ///   are populated when a `BondLookup` is wired via
    ///   `with_bond_lookup` (Spec 9). Without one, all bond fields are
    ///   `None`.
    ///
    /// `frozen_at_block` is stamped into the returned chain so callers do
    /// not need to mutate it. The chain is regulator-grade evidence and
    /// must not be mutated after this call.
    pub fn resolve_principal_chain(
        &self,
        did: &str,
        frozen_at_block: impl Into<BlockHeight>,
    ) -> PrincipalChain {
        let frozen_at_block: BlockHeight = frozen_at_block.into();
        // Spec 9 bond lookup helper — resolves actor_bond + controller_bond
        // (singular, on the controller's own DID) + controller aggregate.
        let actor_bond = self
            .bond_lookup
            .as_ref()
            .and_then(|b| b.actor_bond(did));

        // Resolve the actor itself; if unresolvable, return a synthetic
        // tombstoned chain rooted at the supplied DID.
        let actor = match self.resolve(did) {
            Ok(id) => id,
            Err(_) => {
                let mut chain = PrincipalChain::direct(
                    did.to_string(),
                    TenzroIdentityType::Machine,
                    0,
                    None,
                    frozen_at_block,
                )
                .with_actor_bond(actor_bond);
                chain.controller.tombstone = true;
                return chain;
            }
        };

        let actor_did = actor.did.to_string();
        let actor_type = identity_type_of(&actor);

        // If actor is human, or autonomous machine (no controller_did),
        // it is itself the controller. The controller and the actor are
        // the same DID, so controller_bond == actor_bond and the
        // controller aggregate also keys off the same DID.
        let controller_did_opt = actor.controller_did().map(|s| s.to_string());
        if controller_did_opt.is_none() {
            let kyc = match actor_type {
                TenzroIdentityType::Human => actor.kyc_tier().map(|t| t.level()).unwrap_or(0),
                TenzroIdentityType::Machine => 0,
            };
            let controller_aggregate = self
                .bond_lookup
                .as_ref()
                .and_then(|b| b.controller_aggregate(&actor_did));
            return PrincipalChain::direct(
                actor_did,
                actor_type,
                kyc,
                actor_bond,
                frozen_at_block,
            )
            .with_actor_bond(actor_bond)
            .with_controller_bond_aggregate(controller_aggregate);
        }

        // Walk up the controller chain. We accumulate links top-down; the
        // actor becomes the last entry. Order of construction is
        // bottom-up: we push the actor first, then walk parents, then
        // reverse at the end.
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        visited.insert(actor_did.clone());

        let mut chain_top_down: Vec<PrincipalLink> = Vec::new();
        // Start with the actor as the bottom link (DelegatedAgent or
        // AutonomousAgent decided after we know whether we found a
        // controller).
        let actor_link = PrincipalLink::new(
            actor_did.clone(),
            actor_type,
            None, // delegation_scope_id captured per-action, not here
            PrincipalRole::DelegatedAgent,
        );
        chain_top_down.push(actor_link);

        let mut current_controller_did = controller_did_opt;
        let mut controller_kyc_tier: u8 = 0;

        while let Some(parent_did) = current_controller_did.take() {
            // Cycle detection — break with a tombstone on the offending
            // link rather than looping forever.
            if !visited.insert(parent_did.clone()) {
                chain_top_down.push(PrincipalLink::tombstoned(
                    parent_did,
                    PrincipalRole::Controller,
                ));
                break;
            }

            // Depth bound — stop walking after MAX_DELEGATION_DEPTH
            // links. The accumulated chain is what regulators need; an
            // overly-deep chain is itself signal.
            if chain_top_down.len() as u8 >= MAX_DELEGATION_DEPTH {
                chain_top_down.push(PrincipalLink::tombstoned(
                    parent_did,
                    PrincipalRole::Controller,
                ));
                break;
            }

            match self.resolve(&parent_did) {
                Ok(parent) => {
                    let parent_type = identity_type_of(&parent);
                    let role = if parent.controller_did().is_some() {
                        PrincipalRole::DelegatedAgent
                    } else {
                        PrincipalRole::Controller
                    };
                    chain_top_down.push(PrincipalLink::new(
                        parent.did.to_string(),
                        parent_type,
                        None,
                        role,
                    ));
                    let next = parent.controller_did().map(|s| s.to_string());
                    if next.is_none() {
                        // Reached the top — snapshot KYC tier from this link.
                        if let TenzroIdentityType::Human = parent_type {
                            controller_kyc_tier =
                                parent.kyc_tier().map(|t| t.level()).unwrap_or(0);
                        }
                    }
                    current_controller_did = next;
                }
                Err(_) => {
                    // Unresolvable controller — tombstone and stop walking.
                    chain_top_down.push(PrincipalLink::tombstoned(
                        parent_did,
                        PrincipalRole::Controller,
                    ));
                    break;
                }
            }
        }

        // Reverse so chain[0] is the controller and chain[n-1] is the
        // actor's direct delegator. PrincipalChain::from_chain does the
        // rest (sets controller from chain[0], computes depth, etc.).
        chain_top_down.reverse();

        // Spec 9: snapshot the controller's bond on its own DID and the
        // aggregate across every agent it owns. Both are `None` when no
        // resolver was wired or the controller has no Active bonds.
        let controller_did_str = chain_top_down
            .first()
            .map(|l| l.did.clone())
            .unwrap_or_default();
        let controller_bond = self
            .bond_lookup
            .as_ref()
            .filter(|_| !controller_did_str.is_empty())
            .and_then(|b| b.actor_bond(&controller_did_str));
        let controller_aggregate = self
            .bond_lookup
            .as_ref()
            .filter(|_| !controller_did_str.is_empty())
            .and_then(|b| b.controller_aggregate(&controller_did_str));

        PrincipalChain::from_chain(
            actor_did,
            chain_top_down,
            controller_kyc_tier,
            controller_bond,
            frozen_at_block,
        )
        .with_actor_bond(actor_bond)
        .with_controller_bond_aggregate(controller_aggregate)
    }

    /// Links a native Tenzro agent ID to a machine identity
    pub fn link_tenzro_agent(&self, machine_did: &str, tenzro_agent_id: String) -> Result<()> {
        let mut identity = self
            .identities
            .get_mut(machine_did)
            .ok_or_else(|| IdentityError::NotFound(machine_did.to_string()))?;

        if let IdentityData::Machine {
            tenzro_agent_id: ref mut existing_id,
            ..
        } = identity.identity_data
        {
            debug!(
                "Linking machine {} to Tenzro agent {}",
                machine_did, tenzro_agent_id
            );
            *existing_id = Some(tenzro_agent_id);
            identity.updated_at = Utc::now();
            self.persist_identity(machine_did, &identity);
            Ok(())
        } else {
            Err(IdentityError::PermissionDenied(
                "can only link Tenzro agents to machine identities".to_string(),
            ))
        }
    }

    /// Issues a credential to an identity.
    ///
    /// Rejects duplicate credential IDs (MEDIUM #129 replay protection).
    pub fn issue_credential(
        &self,
        did: &str,
        credential: VerifiableCredential,
    ) -> Result<()> {
        // Replay protection: reject duplicate credential IDs (MEDIUM #129)
        self.record_credential_id(&credential.id)?;

        let mut identity = self
            .identities
            .get_mut(did)
            .ok_or_else(|| IdentityError::NotFound(did.to_string()))?;

        if identity.status != IdentityStatus::Active {
            return Err(IdentityError::NotActive(format!(
                "{} is {:?}",
                did, identity.status
            )));
        }

        info!(
            "Issuing credential {:?} to {}",
            credential.tenzro_type, did
        );

        identity.credentials.push(credential);
        identity.updated_at = Utc::now();
        self.persist_identity(did, &identity);
        Ok(())
    }

    /// Adds a W3C DID Document service endpoint to an existing identity.
    ///
    /// Mutates the registry in place (DashMap `get_mut`) and writes through to
    /// `CF_IDENTITIES`. The previous code path resolved by clone, mutated the
    /// clone, and dropped the result — this is the persistent replacement.
    ///
    /// `service.id` is recorded verbatim; callers conventionally format it as
    /// `<did>#<service_type>`. Duplicate `service.id` values are *not* rejected
    /// (W3C DID Core does not prohibit duplicates), but a future helper may
    /// add that check.
    ///
    /// Used by the `tenzro_addService` JSON-RPC and by the KYA federation flow
    /// to register `MastercardKYA` / `VisaTAP` pointers on a machine identity.
    pub fn add_service_to_identity(
        &self,
        did: &str,
        service: crate::identity::ServiceEndpoint,
    ) -> Result<()> {
        // Validate the URL before taking the lock so we don't leave the
        // identity untouched on a bad input.
        tenzro_types::validation::validate_service_endpoint_url(&service.service_endpoint)
            .map_err(|e| IdentityError::InvalidServiceEndpoint(e.to_string()))?;

        let snapshot = {
            let mut identity = self
                .identities
                .get_mut(did)
                .ok_or_else(|| IdentityError::NotFound(did.to_string()))?;

            if identity.status != IdentityStatus::Active {
                return Err(IdentityError::NotActive(format!(
                    "{} is {:?}",
                    did, identity.status
                )));
            }

            identity.services.push(service);
            identity.updated_at = Utc::now();
            identity.clone()
        };

        self.persist_identity(did, &snapshot);
        Ok(())
    }

    /// Project a TDIP machine identity into a [`KyaRecord`] for DID-anchored
    /// KYA federation.
    ///
    /// Returns `Err(NotFound)` if the DID is unknown, and `Err(PermissionDenied)`
    /// if the identity is a human (KYA records are machine-only).
    pub fn kya_record_for(&self, did: &str) -> Result<crate::kya::KyaRecord> {
        let identity = self.resolve(did)?;
        crate::kya::KyaRecord::from_identity(&identity).ok_or_else(|| {
            IdentityError::PermissionDenied(format!(
                "KYA record requested for non-machine identity: {}",
                did
            ))
        })
    }

    /// Allows a machine to inherit a credential from its controller.
    ///
    /// The inherited credential receives a new unique ID so that each
    /// issuance is tracked independently for replay protection (MEDIUM #129).
    pub fn inherit_credential(
        &self,
        machine_did: &str,
        credential_type: &TenzroCredentialType,
    ) -> Result<()> {
        // Get the machine's controller DID
        let controller_did = {
            let machine = self
                .identities
                .get(machine_did)
                .ok_or_else(|| IdentityError::NotFound(machine_did.to_string()))?;

            if machine.status != IdentityStatus::Active {
                return Err(IdentityError::NotActive(machine_did.to_string()));
            }

            match &machine.identity_data {
                IdentityData::Machine { controller_did, .. } => controller_did
                    .clone()
                    .ok_or_else(|| {
                        IdentityError::PermissionDenied(
                            "autonomous machines cannot inherit credentials".to_string(),
                        )
                    })?,
                _ => {
                    return Err(IdentityError::PermissionDenied(
                        "only machine identities can inherit credentials".to_string(),
                    ))
                }
            }
        };

        // Find the credential in the controller's credentials
        let mut credential = {
            let controller = self
                .identities
                .get(&controller_did)
                .ok_or_else(|| IdentityError::NotFound(controller_did.clone()))?;

            controller
                .credentials
                .iter()
                .find(|c| &c.tenzro_type == credential_type && c.is_valid())
                .cloned()
                .ok_or_else(|| {
                    IdentityError::CredentialError(format!(
                        "controller does not have valid credential of type: {:?}",
                        credential_type
                    ))
                })?
        };

        // Assign a new unique ID for the inherited copy (MEDIUM #129)
        credential.id = format!("urn:uuid:{}", uuid::Uuid::new_v4());

        // Replay protection: record the new credential ID
        self.record_credential_id(&credential.id)?;

        // Add credential to machine
        let mut machine = self
            .identities
            .get_mut(machine_did)
            .ok_or_else(|| IdentityError::NotFound(machine_did.to_string()))?;

        info!(
            "Machine {} inheriting credential {:?} from controller {}",
            machine_did, credential_type, controller_did
        );

        machine.credentials.push(credential);
        machine.updated_at = Utc::now();
        self.persist_identity(machine_did, &machine);
        Ok(())
    }

    /// Revokes an identity and, for humans, cascades to all controlled machines.
    ///
    /// HIGH #96 + Wave 3d hybrid PQ migration: every revocation event is
    /// signed by the revoker's hybrid (Ed25519 + ML-DSA-65) keys via the
    /// supplied [`HybridSigner`]. After the local cascade completes, the
    /// configured [`RevocationBroadcaster`] (if any) receives one
    /// [`SignedRevocationEntry`] per affected DID so peer nodes can verify
    /// and apply the revocation.
    ///
    /// `revoked_by` is the DID string recorded inside the entry (typically
    /// the revoker's identity DID); the cryptographic identity of the
    /// revoker is captured in the composite public key embedded in each
    /// `SignedRevocationEntry`.
    pub fn revoke(
        &self,
        did: &str,
        reason: String,
        revoked_by: String,
        revoker_signer: &dyn HybridSigner,
    ) -> Result<()> {
        let machine_dids: Vec<String>;

        // Revoke the identity
        {
            let mut identity = self
                .identities
                .get_mut(did)
                .ok_or_else(|| IdentityError::NotFound(did.to_string()))?;

            warn!("Revoking identity: {} (reason: {})", did, reason);
            identity.status = IdentityStatus::Revoked;
            identity.updated_at = Utc::now();

            // Collect machine DIDs for cascading revocation
            machine_dids = match &identity.identity_data {
                IdentityData::Human {
                    controlled_machines,
                    ..
                } => controlled_machines.clone(),
                IdentityData::Machine { .. } => Vec::new(),
            };

            self.persist_identity(did, &identity);
        }

        // Cascade revocation to controlled machines
        let mut cascaded: Vec<RevocationEntry> = Vec::new();
        for machine_did in &machine_dids {
            if let Some(mut machine) = self.identities.get_mut(machine_did) {
                machine.status = IdentityStatus::Revoked;
                machine.updated_at = Utc::now();
                self.persist_identity(machine_did, &machine);
                cascaded.push(RevocationEntry {
                    did: machine_did.clone(),
                    revoked_at: Utc::now(),
                    reason: format!("cascaded from {}", did),
                    revoked_by: revoked_by.clone(),
                });
            }
        }

        // Record revocation
        let entry = RevocationEntry {
            did: did.to_string(),
            revoked_at: Utc::now(),
            reason,
            revoked_by,
        };
        self.revocations.insert(did.to_string(), entry.clone());
        for c in &cascaded {
            self.revocations.insert(c.did.clone(), c.clone());
        }

        // HIGH #96: broadcast to peers (best effort — failures are logged
        // but do not roll back the local revocation, which is authoritative
        // for this node). Wave 3d: every broadcast carries a hybrid
        // (Ed25519 + ML-DSA-65) signature.
        if let Some(ref broadcaster) = self.revocation_broadcaster {
            match SignedRevocationEntry::sign(entry.clone(), revoker_signer) {
                Ok(signed) => {
                    if let Err(e) = broadcaster.broadcast_revocation(&signed) {
                        warn!("Failed to broadcast revocation for {}: {}", did, e);
                    }
                }
                Err(e) => {
                    warn!("Failed to sign revocation entry for {}: {}", did, e);
                }
            }
            for c in &cascaded {
                match SignedRevocationEntry::sign(c.clone(), revoker_signer) {
                    Ok(signed) => {
                        if let Err(e) = broadcaster.broadcast_revocation(&signed) {
                            warn!(
                                "Failed to broadcast cascaded revocation for {}: {}",
                                c.did, e
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to sign cascaded revocation entry for {}: {}",
                            c.did, e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Records a revocation that arrived from a remote node (HIGH #96).
    ///
    /// This is the inbound counterpart of
    /// [`RevocationBroadcaster::broadcast_revocation`]. Wave 3d: the entry
    /// is verified via its embedded hybrid (Ed25519 + ML-DSA-65) signature
    /// before any local state mutation. Verification failure returns
    /// `IdentityError::VerificationFailed` and leaves the cache untouched.
    pub fn apply_remote_revocation(&self, signed: SignedRevocationEntry) -> Result<()> {
        // Verify hybrid signature first — refuse to mutate state on bad sigs.
        signed.verify()?;

        let entry = signed.entry;
        if let Some(mut identity) = self.identities.get_mut(&entry.did)
            && identity.status != IdentityStatus::Revoked
        {
            warn!("Applying remote revocation for {}", entry.did);
            identity.status = IdentityStatus::Revoked;
            identity.updated_at = Utc::now();
            self.persist_identity(&entry.did, &identity);
        }
        self.revocations.insert(entry.did.clone(), entry);
        Ok(())
    }

    /// Suspends an identity temporarily
    pub fn suspend(&self, did: &str) -> Result<()> {
        let mut identity = self
            .identities
            .get_mut(did)
            .ok_or_else(|| IdentityError::NotFound(did.to_string()))?;

        info!("Suspending identity: {}", did);
        identity.status = IdentityStatus::Suspended;
        identity.updated_at = Utc::now();
        self.persist_identity(did, &identity);
        Ok(())
    }

    /// Reactivates a suspended identity
    pub fn reactivate(&self, did: &str) -> Result<()> {
        let mut identity = self
            .identities
            .get_mut(did)
            .ok_or_else(|| IdentityError::NotFound(did.to_string()))?;

        if identity.status != IdentityStatus::Suspended {
            return Err(IdentityError::PermissionDenied(format!(
                "can only reactivate suspended identities, {} is {:?}",
                did, identity.status
            )));
        }

        info!("Reactivating identity: {}", did);
        identity.status = IdentityStatus::Active;
        identity.updated_at = Utc::now();
        self.persist_identity(did, &identity);
        Ok(())
    }

    /// Updates the KYC tier for a human identity, requiring a signed
    /// `KycAttestation` credential (HIGH #95).
    ///
    /// The credential must:
    ///   1. Be of type `TenzroCredentialType::KycAttestation`
    ///   2. Have its subject ID equal to the target DID
    ///   3. Carry a non-expired proof
    ///   4. Be signed by an issuer that is registered locally and whose
    ///      first public key verifies the proof
    ///   5. Carry a `tier` claim that matches the requested `new_tier`
    ///
    /// On success the credential is also attached to the identity for audit.
    pub fn update_kyc_tier_with_credential(
        &self,
        did: &str,
        new_tier: KycTier,
        credential: VerifiableCredential,
    ) -> Result<()> {
        // Verify credential type
        if credential.tenzro_type != TenzroCredentialType::KycAttestation {
            return Err(IdentityError::CredentialError(format!(
                "expected KycAttestation credential, got {:?}",
                credential.tenzro_type
            )));
        }

        // Verify subject matches
        if credential.credential_subject.id != did {
            return Err(IdentityError::CredentialError(format!(
                "credential subject {} does not match target DID {}",
                credential.credential_subject.id, did
            )));
        }

        // Verify the requested tier matches the credential claim. Tiers are
        // serialized as their numeric variant (0..3) by serde, so accept
        // either an integer or the string form to be tolerant.
        let claimed_tier = credential
            .credential_subject
            .claims
            .get("tier")
            .ok_or_else(|| {
                IdentityError::CredentialError("credential is missing 'tier' claim".to_string())
            })?;
        let claimed_matches = match claimed_tier {
            serde_json::Value::Number(n) => n.as_u64() == Some(new_tier as u64),
            serde_json::Value::String(s) => s.eq_ignore_ascii_case(&format!("{:?}", new_tier)),
            _ => false,
        };
        if !claimed_matches {
            return Err(IdentityError::CredentialError(format!(
                "credential tier claim {:?} does not match requested {:?}",
                claimed_tier, new_tier
            )));
        }

        // Verify the cryptographic proof against the issuer's public key.
        if !self.verify_credential(&credential)? {
            return Err(IdentityError::VerificationFailed(
                "KYC credential signature did not verify".to_string(),
            ));
        }

        // All checks passed — update the tier and store the credential.
        {
            let mut identity = self
                .identities
                .get_mut(did)
                .ok_or_else(|| IdentityError::NotFound(did.to_string()))?;

            match &mut identity.identity_data {
                IdentityData::Human { kyc_tier, .. } => {
                    info!(
                        "KYC tier for {} updated from {:?} to {:?} via signed credential",
                        did, kyc_tier, new_tier
                    );
                    *kyc_tier = new_tier;
                    identity.credentials.push(credential);
                    identity.updated_at = Utc::now();
                    self.persist_identity(did, &identity);
                    Ok(())
                }
                _ => Err(IdentityError::PermissionDenied(
                    "KYC tier can only be set on human identities".to_string(),
                )),
            }
        }
    }

    /// Actively enforces the delegation scope for a machine identity (HIGH #94).
    ///
    /// Returns `Ok(())` only if the operation is allowed. Unlike
    /// `IdentityVerifier::validate_operation` (which returns `Ok(false)` on
    /// denial and is easy to misuse), this method returns a typed
    /// `DelegationViolation` error so callers cannot accidentally ignore
    /// the result.
    pub fn enforce_operation(
        &self,
        machine_did: &str,
        operation: &str,
        value: Option<u128>,
    ) -> Result<()> {
        let identity = self.resolve(machine_did)?;
        if identity.status != IdentityStatus::Active {
            return Err(IdentityError::NotActive(format!(
                "{} is {:?}",
                machine_did, identity.status
            )));
        }

        let (delegation_scope, controller_did, reputation) = match &identity.identity_data {
            IdentityData::Machine {
                delegation_scope,
                controller_did,
                reputation,
                ..
            } => (delegation_scope.clone(), controller_did.clone(), *reputation),
            IdentityData::Human { .. } => {
                // Humans bypass delegation enforcement entirely.
                return Ok(());
            }
        };

        if !delegation_scope.is_active() {
            return Err(IdentityError::DelegationViolation(
                "delegation scope expired or revoked".to_string(),
            ));
        }
        if !delegation_scope.is_operation_allowed(operation) {
            return Err(IdentityError::DelegationViolation(format!(
                "operation '{}' not in allowed list",
                operation
            )));
        }
        if let Some(v) = value
            && !delegation_scope.is_value_allowed(v)
        {
            return Err(IdentityError::DelegationViolation(format!(
                "value {} exceeds max_transaction_value",
                v
            )));
        }

        if reputation < self.delegation_policy.min_reputation {
            return Err(IdentityError::DelegationViolation(format!(
                "reputation {} below required {}",
                reputation, self.delegation_policy.min_reputation
            )));
        }

        if self.delegation_policy.require_active_controller
            && let Some(ctrl) = controller_did
        {
            let controller = self.resolve(&ctrl)?;
            if controller.status != IdentityStatus::Active {
                return Err(IdentityError::DelegationViolation(format!(
                    "controller {} is {:?}",
                    ctrl, controller.status
                )));
            }
        }

        Ok(())
    }

    /// Updates the delegation scope for a machine identity
    pub fn update_delegation_scope(&self, did: &str, new_scope: DelegationScope) -> Result<()> {
        let mut identity = self
            .identities
            .get_mut(did)
            .ok_or_else(|| IdentityError::NotFound(did.to_string()))?;

        match &mut identity.identity_data {
            IdentityData::Machine { delegation_scope, .. } => {
                info!(
                    "Updating delegation scope for machine identity: {}",
                    did
                );
                *delegation_scope = new_scope;
                identity.updated_at = Utc::now();
                self.persist_identity(did, &identity);
                Ok(())
            }
            _ => Err(IdentityError::PermissionDenied(
                "delegation scope can only be set on machine identities".to_string(),
            )),
        }
    }

    /// Gets all machines controlled by a human identity
    pub fn get_controlled_machines(&self, human_did: &str) -> Result<Vec<TenzroIdentity>> {
        let identity = self
            .identities
            .get(human_did)
            .ok_or_else(|| IdentityError::NotFound(human_did.to_string()))?;

        let machine_dids = match &identity.identity_data {
            IdentityData::Human {
                controlled_machines,
                ..
            } => controlled_machines.clone(),
            _ => {
                return Err(IdentityError::PermissionDenied(
                    "only human identities have controlled machines".to_string(),
                ))
            }
        };
        drop(identity);

        Ok(machine_dids
            .iter()
            .filter_map(|did| self.identities.get(did).map(|id| id.clone()))
            .collect())
    }

    /// Returns the total number of identities by type
    pub fn count(&self) -> (usize, usize) {
        let mut humans = 0;
        let mut machines = 0;
        for entry in self.identities.iter() {
            match entry.value().identity_data {
                IdentityData::Human { .. } => humans += 1,
                IdentityData::Machine { .. } => machines += 1,
            }
        }
        (humans, machines)
    }

    /// Returns the total number of registered identities
    pub fn total_count(&self) -> usize {
        self.identities.len()
    }

    /// Returns all registered identities as (DID, TenzroIdentity) pairs
    pub fn list_all(&self) -> Vec<(String, TenzroIdentity)> {
        self.identities
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Checks if a DID is revoked
    pub fn is_revoked(&self, did: &str) -> bool {
        self.revocations.contains_key(did)
    }

    /// Verifies a credential's cryptographic proof by looking up the issuer
    ///
    /// This method resolves the issuer identity and verifies the credential's
    /// proof using the issuer's first public key (typically the assertion key).
    pub fn verify_credential(&self, credential: &VerifiableCredential) -> Result<bool> {
        // Resolve the issuer identity
        let issuer = self.resolve(&credential.issuer)?;

        // Get the first public key for verification
        let pubkey = issuer
            .public_keys
            .first()
            .ok_or_else(|| IdentityError::VerificationFailed("issuer has no public keys".to_string()))?;

        // Verify the credential proof
        credential
            .verify_proof(&pubkey.public_key)
    }

    /// Test-only helper that overwrites (or installs) an identity record by DID.
    ///
    /// This is used by trust-chain-traversal tests (CRITICAL #41) to patch
    /// identities after `register_*()` so the test can install real
    /// `AssertionMethod` public keys and pre-built credentials matching the
    /// Ed25519 keypairs used to sign chain credentials. Production code must
    /// not call this — use the typed `register_*` / `issue_credential` /
    /// `update_*` methods instead.
    #[doc(hidden)]
    pub fn upsert_identity_for_test(&self, identity: TenzroIdentity) {
        let key = identity.did.to_string();
        self.persist_identity(&key, &identity);
        self.identities.insert(key, identity);
    }

    /// Append a free-form metadata key/value to an existing identity.
    /// Used by the passkey-first onboarding path to record
    /// `smart_account_address` / `passkey_credential_id` against the
    /// freshly-registered human identity. Updates both the in-memory
    /// cache AND writes through to `CF_IDENTITIES` so subsequent
    /// `resolve()` calls and restarts both see the binding.
    ///
    /// Returns `Err` if the identity is unknown.
    pub fn set_identity_metadata(
        &self,
        did: &str,
        kv: impl IntoIterator<Item = (String, String)>,
    ) -> crate::error::Result<()> {
        let mut entry = self
            .identities
            .get_mut(did)
            .ok_or_else(|| crate::error::IdentityError::NotFound(did.to_string()))?;
        for (k, v) in kv {
            entry.metadata.insert(k, v);
        }
        self.persist_identity(did, entry.value());
        Ok(())
    }

    /// Insert an identity into the registry from an externally produced
    /// record — used by the CARv1 import flow (C.6) to land an identity on
    /// a new node from an export bundle. Persists to RocksDB if storage is
    /// configured, then publishes to the in-memory cache so subsequent
    /// `resolve` / `find_wallet_id_for_did` calls see it.
    ///
    /// Refuses to overwrite an existing identity with the same DID: the
    /// import flow is "land it on a fresh machine", not "patch a live
    /// record". Callers that genuinely want to replace must
    /// [`Self::forget_identity`] first.
    pub fn import_identity(&self, identity: TenzroIdentity) -> Result<()> {
        let key = identity.did.to_string();
        if self.identities.contains_key(&key) {
            return Err(IdentityError::AlreadyExists(key));
        }
        self.persist_identity(&key, &identity);
        if let Some(ref username) = identity.username {
            // Best-effort: claim the username on this node too. If the name
            // is already taken locally we keep the identity (the user can
            // re-register a new name) rather than reject the whole import.
            let _ = self.usernames.insert(username.clone(), key.clone());
            self.persist_username(username, &key);
        }
        self.identities.insert(key, identity);
        Ok(())
    }

    /// Registers a unique username for an identity.
    ///
    /// Validates the username format (lowercase alphanumeric + underscores,
    /// 3-20 chars, no leading/trailing underscore) and checks uniqueness
    /// against the registry. On success, sets the username on the identity
    /// and persists both the identity and the username mapping to storage.
    pub fn register_username(&self, did: &str, username: &str) -> Result<()> {
        use crate::identity::validate_username;

        // Validate format
        validate_username(username)?;

        // Check that the identity exists and is active
        let mut identity = self
            .identities
            .get_mut(did)
            .ok_or_else(|| IdentityError::NotFound(did.to_string()))?;

        if identity.status != IdentityStatus::Active {
            return Err(IdentityError::NotActive(did.to_string()));
        }

        // Release old username if this identity already has one
        if let Some(ref old_username) = identity.username {
            self.usernames.remove(old_username);
            self.persist_remove_username(old_username);
        }

        // Check uniqueness — use DashMap::entry for atomicity
        use dashmap::mapref::entry::Entry;
        match self.usernames.entry(username.to_string()) {
            Entry::Occupied(e) => {
                let existing_did = e.get().clone();
                if existing_did != did {
                    return Err(IdentityError::UsernameTaken(username.to_string()));
                }
                // Same DID re-registering the same username — no-op
            }
            Entry::Vacant(e) => {
                e.insert(did.to_string());
            }
        }

        // Set on the identity and persist
        identity.username = Some(username.to_string());
        identity.updated_at = Utc::now();
        let identity_clone = identity.clone();
        drop(identity); // release DashMap lock before persisting
        self.persist_identity(did, &identity_clone);
        self.persist_username(username, did);

        info!("Registered username @{} for DID {}", username, did);
        Ok(())
    }

    /// Resolves a username to its DID.
    ///
    /// Returns `None` if the username is not registered.
    pub fn resolve_username(&self, username: &str) -> Option<String> {
        self.usernames.get(username).map(|r| r.value().clone())
    }

    /// Releases the username associated with an identity.
    ///
    /// Removes the username mapping so the name becomes available again.
    pub fn release_username(&self, did: &str) {
        if let Some(mut identity) = self.identities.get_mut(did) {
            if let Some(ref username) = identity.username {
                let uname = username.clone();
                self.usernames.remove(&uname);
                self.persist_remove_username(&uname);
                info!("Released username @{} from DID {}", uname, did);
            }
            identity.username = None;
            identity.updated_at = Utc::now();
            let identity_clone = identity.clone();
            drop(identity);
            self.persist_identity(did, &identity_clone);
        }
    }

    /// Persists a username → DID mapping to storage (write-through)
    fn persist_username(&self, username: &str, did: &str) {
        if let Some(ref store) = self.storage {
            let key = format!("username:{}", username);
            if let Err(e) = store.put(CF_IDENTITIES, key.as_bytes(), did.as_bytes()) {
                warn!("Failed to persist username mapping {}: {}", username, e);
            }
        }
    }

    /// Removes a username mapping from storage
    fn persist_remove_username(&self, username: &str) {
        if let Some(ref store) = self.storage {
            let key = format!("username:{}", username);
            if let Err(e) = store.delete(CF_IDENTITIES, key.as_bytes()) {
                warn!("Failed to remove username mapping {}: {}", username, e);
            }
        }
    }

    /// Provisions a wallet or returns default values if no binder is configured.
    ///
    /// Returns `(address, wallet_id, pq_verifying_key_bytes)`. Wave 3d hybrid
    /// migration: every identity carries a mandatory ML-DSA-65 verifying key.
    /// When a `WalletBinder` is configured, the key comes from the wallet's
    /// keystore; otherwise we generate an ephemeral one so the identity still
    /// satisfies the structural invariant (test/no-binder paths only).
    async fn provision_or_default(
        &self,
        did: &str,
    ) -> Result<(Address, String, Vec<u8>, Vec<u8>)> {
        if let Some(ref binder) = self.wallet_binder {
            let binding = binder.provision_wallet(did).await?;
            Ok((
                binding.address,
                binding.wallet_id,
                binding.pq_verifying_key,
                binding.bls_verifying_key,
            ))
        } else {
            // Default: generate a placeholder address from the DID
            let hash = tenzro_crypto::sha256(did.as_bytes());
            let mut addr_bytes = [0u8; 32];
            addr_bytes.copy_from_slice(hash.as_bytes());
            let address = Address::new(addr_bytes);
            let wallet_id = format!("wallet-{}", &did[did.len().saturating_sub(12)..]);
            let pq_verifying_key = tenzro_crypto::pq::MlDsaSigningKey::generate()
                .verifying_key_bytes()
                .to_vec();
            let bls_verifying_key = tenzro_crypto::bls::BlsKeyPair::generate()
                .map_err(|e| IdentityError::WalletError(e.to_string()))?
                .public_key()
                .to_bytes()
                .to_vec();
            Ok((address, wallet_id, pq_verifying_key, bls_verifying_key))
        }
    }
}

/// Derive a 20-byte EVM address from a 32-byte Tenzro address.
///
/// Tenzro addresses are 32 bytes (Ed25519 public-key-derived); ERC-8004 uses
/// 20-byte EVM addresses. The convention is to take the last 20 bytes — this
/// is deterministic, collision-resistant in practice (since the underlying
/// Tenzro address is already a hash output), and lets us reuse the same
/// wallet binding without a separate EVM keypair.
fn derive_evm_address(tenzro_addr: &tenzro_types::Address) -> [u8; 20] {
    let bytes = tenzro_addr.as_bytes();
    let mut addr = [0u8; 20];
    // tenzro_types::Address is always 32 bytes — take the trailing 20.
    let start = bytes.len().saturating_sub(20);
    addr.copy_from_slice(&bytes[start..start + 20]);
    addr
}

/// Project a [`TenzroIdentity`] onto the public
/// [`tenzro_types::identity::IdentityType`] enum used by principal chains.
fn identity_type_of(identity: &TenzroIdentity) -> TenzroIdentityType {
    match identity.identity_data {
        IdentityData::Human { .. } => TenzroIdentityType::Human,
        IdentityData::Machine { .. } => TenzroIdentityType::Machine,
    }
}

/// Adapter that lets [`IdentityRegistry`] act as the live
/// [`PrincipalChainResolver`] for receipt-write paths in the settlement
/// engine, escrow manager, payment binder, and kill-switch dispatcher.
///
/// The settlement crate cannot depend on `tenzro-identity` (would create
/// a cycle through `tenzro-wallet`), so the trait lives in `tenzro-types`
/// and the live impl lives here. Node startup constructs the registry,
/// wraps it in `Arc`, and calls `SettlementEngine::with_principal_resolver`.
impl PrincipalChainResolver for IdentityRegistry {
    fn resolve_by_did(&self, did: &str, frozen_at_block: BlockHeight) -> PrincipalChain {
        self.resolve_principal_chain(did, frozen_at_block)
    }

    fn resolve_by_address(
        &self,
        address: &Address,
        frozen_at_block: BlockHeight,
    ) -> PrincipalChain {
        match self.find_did_by_address(address) {
            Some(did) => self.resolve_principal_chain(&did, frozen_at_block),
            None => anonymous_chain_for_address(address, frozen_at_block),
        }
    }
}

impl Default for IdentityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    /// Build a fresh hybrid signer for revocation tests. Tests don't care
    /// what key the revoker uses — they just need a valid (Ed25519,
    /// ML-DSA-65) pair that produces verifiable composite signatures.
    fn test_hybrid_signer() -> tenzro_crypto::composite::InMemoryHybridSigner {
        use tenzro_crypto::composite::InMemoryHybridSigner;
        use tenzro_crypto::pq::MlDsaSigningKey;
        use tenzro_crypto::signatures::Ed25519SignerImpl;
        use tenzro_crypto::{KeyPair, KeyType};
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let classical = Ed25519SignerImpl::new(kp).unwrap();
        InMemoryHybridSigner::new(Box::new(classical), MlDsaSigningKey::generate())
    }

    #[tokio::test]
    async fn test_register_human() {
        let registry = IdentityRegistry::new();
        let identity = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Enhanced)
            .await
            .unwrap()
            .identity;

        assert!(identity.is_human());
        assert!(identity.is_active());
        assert_eq!(identity.display_name(), "Alice");
        assert_eq!(identity.kyc_tier(), Some(KycTier::Enhanced));
        assert_eq!(registry.total_count(), 1);
    }

    #[tokio::test]
    async fn test_register_machine_under_human() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        let machine = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(2),
                vec!["inference".to_string()],
                DelegationScope::unrestricted().with_max_transaction_value(10_000),
            )
            .await
            .unwrap()
            .identity;

        assert!(machine.is_machine());
        assert!(machine.is_active());
        assert_eq!(
            machine.controller_did(),
            Some(human.did_string().as_str())
        );
        assert_eq!(registry.total_count(), 2);

        // Verify controller's machine list was updated
        let machines = registry.get_controlled_machines(&human.did_string()).unwrap();
        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0].did_string(), machine.did_string());
    }

    #[tokio::test]
    async fn test_register_autonomous_machine() {
        let registry = IdentityRegistry::new();
        let machine = registry
            .register_autonomous_machine(test_pubkey(1), vec!["monitoring".to_string()])
            .await
            .unwrap();

        assert!(machine.is_machine());
        assert!(machine.controller_did().is_none());
    }

    #[tokio::test]
    async fn test_resolve_did() {
        let registry = IdentityRegistry::new();
        let identity = registry
            .register_human_with_fee(test_pubkey(1), "Bob".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        let resolved = registry.resolve(&identity.did_string()).unwrap();
        assert_eq!(resolved.did_string(), identity.did_string());
    }

    #[tokio::test]
    async fn test_link_tenzro_agent() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        let machine = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(2),
                vec![],
                DelegationScope::default(),
            )
            .await
            .unwrap()
            .identity;

        registry
            .link_tenzro_agent(&machine.did_string(), "tenzro-agent-123".to_string())
            .unwrap();

        let updated = registry.resolve(&machine.did_string()).unwrap();
        if let IdentityData::Machine {
            tenzro_agent_id, ..
        } = &updated.identity_data
        {
            assert_eq!(tenzro_agent_id, &Some("tenzro-agent-123".to_string()));
        } else {
            panic!("expected machine identity");
        }
    }

    #[tokio::test]
    async fn test_credential_issuance_and_inheritance() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        let machine = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(2),
                vec![],
                DelegationScope::default(),
            )
            .await
            .unwrap()
            .identity;

        // Issue credential to human
        let cred = VerifiableCredential::new(
            TenzroCredentialType::AccreditedInvestor,
            "did:tenzro:human:issuer",
            human.did_string(),
        );
        registry
            .issue_credential(&human.did_string(), cred)
            .unwrap();

        // Machine inherits credential
        registry
            .inherit_credential(
                &machine.did_string(),
                &TenzroCredentialType::AccreditedInvestor,
            )
            .unwrap();

        let updated_machine = registry.resolve(&machine.did_string()).unwrap();
        assert_eq!(updated_machine.credentials.len(), 1);
    }

    #[tokio::test]
    async fn test_revoke_cascading() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        let machine = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(2),
                vec![],
                DelegationScope::default(),
            )
            .await
            .unwrap()
            .identity;

        let signer = test_hybrid_signer();
        registry
            .revoke(
                &human.did_string(),
                "Test revocation".to_string(),
                "admin".to_string(),
                &signer,
            )
            .unwrap();

        let revoked_human = registry.resolve(&human.did_string()).unwrap();
        assert_eq!(revoked_human.status, IdentityStatus::Revoked);

        let revoked_machine = registry.resolve(&machine.did_string()).unwrap();
        assert_eq!(revoked_machine.status, IdentityStatus::Revoked);

        assert!(registry.is_revoked(&human.did_string()));
    }

    #[tokio::test]
    async fn test_revoke_cascading_multiple_machines() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        // Register multiple machines under the same human
        let machine1 = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(2),
                vec!["inference".to_string()],
                DelegationScope::default(),
            )
            .await
            .unwrap()
            .identity;

        let machine2 = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(3),
                vec!["trading".to_string()],
                DelegationScope::default(),
            )
            .await
            .unwrap()
            .identity;

        let machine3 = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(4),
                vec!["monitoring".to_string()],
                DelegationScope::default(),
            )
            .await
            .unwrap()
            .identity;

        // Revoke the human
        let signer = test_hybrid_signer();
        registry
            .revoke(
                &human.did_string(),
                "Account closure".to_string(),
                "admin".to_string(),
                &signer,
            )
            .unwrap();

        // Verify human is revoked
        let revoked_human = registry.resolve(&human.did_string()).unwrap();
        assert_eq!(revoked_human.status, IdentityStatus::Revoked);

        // Verify ALL machines are cascaded revoked
        let revoked_machine1 = registry.resolve(&machine1.did_string()).unwrap();
        assert_eq!(revoked_machine1.status, IdentityStatus::Revoked, "Machine 1 should be revoked");

        let revoked_machine2 = registry.resolve(&machine2.did_string()).unwrap();
        assert_eq!(revoked_machine2.status, IdentityStatus::Revoked, "Machine 2 should be revoked");

        let revoked_machine3 = registry.resolve(&machine3.did_string()).unwrap();
        assert_eq!(revoked_machine3.status, IdentityStatus::Revoked, "Machine 3 should be revoked");
    }

    #[tokio::test]
    async fn test_revoke_machine_does_not_affect_controller() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        let machine = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(2),
                vec![],
                DelegationScope::default(),
            )
            .await
            .unwrap()
            .identity;

        // Revoke only the machine
        let signer = test_hybrid_signer();
        registry
            .revoke(
                &machine.did_string(),
                "Machine compromised".to_string(),
                "admin".to_string(),
                &signer,
            )
            .unwrap();

        // Verify machine is revoked
        let revoked_machine = registry.resolve(&machine.did_string()).unwrap();
        assert_eq!(revoked_machine.status, IdentityStatus::Revoked);

        // Verify human is still active
        let active_human = registry.resolve(&human.did_string()).unwrap();
        assert_eq!(active_human.status, IdentityStatus::Active, "Human should remain active");
    }

    #[tokio::test]
    async fn test_suspend_and_reactivate() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        registry.suspend(&human.did_string()).unwrap();
        let suspended = registry.resolve(&human.did_string()).unwrap();
        assert_eq!(suspended.status, IdentityStatus::Suspended);

        registry.reactivate(&human.did_string()).unwrap();
        let reactivated = registry.resolve(&human.did_string()).unwrap();
        assert_eq!(reactivated.status, IdentityStatus::Active);
    }

    #[tokio::test]
    async fn test_count() {
        let registry = IdentityRegistry::new();
        assert_eq!(registry.count(), (0, 0));

        let h1 = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;
        let h2 = registry
            .register_human_with_fee(test_pubkey(2), "Bob".to_string(), KycTier::Enhanced)
            .await
            .unwrap()
            .identity;
        registry
            .register_machine_with_fee(
                &h1.did_string(),
                test_pubkey(3),
                vec![],
                DelegationScope::default(),
            )
            .await
            .unwrap();
        registry
            .register_machine_with_fee(
                &h2.did_string(),
                test_pubkey(4),
                vec![],
                DelegationScope::default(),
            )
            .await
            .unwrap();

        assert_eq!(registry.count(), (2, 2));
        assert_eq!(registry.total_count(), 4);
    }

    #[tokio::test]
    async fn test_reject_nonexistent_controller() {
        let registry = IdentityRegistry::new();
        let result = registry
            .register_machine_with_fee(
                "did:tenzro:human:nonexistent",
                test_pubkey(1),
                vec![],
                DelegationScope::default(),
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_inherit_without_controller_credential() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        let machine = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(2),
                vec![],
                DelegationScope::default(),
            )
            .await
            .unwrap()
            .identity;

        let result = registry.inherit_credential(
            &machine.did_string(),
            &TenzroCredentialType::AccreditedInvestor,
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_registration_fees() {
        let registry = IdentityRegistry::new();

        // Check default fees
        assert_eq!(registry.human_registration_fee(), 10_000_000_000_000_000_000); // 10 TNZO
        assert_eq!(registry.machine_registration_fee(), 5_000_000_000_000_000_000); // 5 TNZO
        assert_eq!(registry.credential_issuance_fee(), 2_000_000_000_000_000_000); // 2 TNZO

        // Register with fee info
        let result = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Full)
            .await
            .unwrap();

        assert_eq!(result.fee_required, 10_000_000_000_000_000_000);
        assert!(result.identity.is_human());

        let machine_result = registry
            .register_machine_with_fee(
                &result.identity.did_string(),
                test_pubkey(2),
                vec![],
                DelegationScope::default(),
            )
            .await
            .unwrap();

        assert_eq!(machine_result.fee_required, 5_000_000_000_000_000_000);
        assert!(machine_result.identity.is_machine());
    }

    #[tokio::test]
    async fn test_verify_credential_via_registry() {
        use tenzro_crypto::{KeyPair, KeyType};
        use tenzro_crypto::signatures::{Signer, Ed25519SignerImpl};
        use crate::credential::{CredentialProof, TenzroCredentialType, VerifiableCredential};

        let registry = IdentityRegistry::new();

        // Register the issuer with a real Ed25519 public key
        let issuer_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let issuer_pubkey = issuer_keypair.public_key().as_bytes().to_vec();
        let issuer_signer = Ed25519SignerImpl::new(issuer_keypair).unwrap();

        let issuer = registry
            .register_human_with_fee(issuer_pubkey, "Issuer Authority".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        // Register the subject
        let subject = registry
            .register_human_with_fee(test_pubkey(99), "Subject".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        // Create a credential for the subject
        let mut cred = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            issuer.did_string(),
            subject.did_string(),
        );

        // Sign the credential subject with issuer's key
        let message = serde_json::to_vec(&cred.credential_subject).unwrap();
        let signature = issuer_signer.sign(&message).unwrap();
        cred = cred.with_proof(CredentialProof::new(
            "Ed25519Signature2020",
            format!("{}#key-1", issuer.did_string()),
            signature.to_bytes(),
        ));

        // Issue to subject
        registry
            .issue_credential(&subject.did_string(), cred.clone())
            .unwrap();

        // Verify via registry (resolves issuer, checks proof)
        let result = registry.verify_credential(&cred).unwrap();
        assert!(result, "Credential signed by registered issuer should verify");

        // Credential with wrong issuer DID should fail
        let mut bad_cred = cred.clone();
        bad_cred.issuer = "did:tenzro:human:nonexistent".to_string();
        assert!(registry.verify_credential(&bad_cred).is_err());
    }

    #[tokio::test]
    async fn test_verify_credential_tampered_fails() {
        use tenzro_crypto::{KeyPair, KeyType};
        use tenzro_crypto::signatures::{Signer, Ed25519SignerImpl};
        use crate::credential::{CredentialProof, TenzroCredentialType, VerifiableCredential};

        let registry = IdentityRegistry::new();

        let issuer_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let issuer_pubkey = issuer_keypair.public_key().as_bytes().to_vec();
        let issuer_signer = Ed25519SignerImpl::new(issuer_keypair).unwrap();

        let issuer = registry
            .register_human_with_fee(issuer_pubkey, "Issuer".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        let subject = registry
            .register_human_with_fee(test_pubkey(42), "Subject".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        let mut cred = VerifiableCredential::new(
            TenzroCredentialType::AccreditedInvestor,
            issuer.did_string(),
            subject.did_string(),
        )
        .with_claim("status", serde_json::json!("verified"));

        // Sign the credential
        let message = serde_json::to_vec(&cred.credential_subject).unwrap();
        let signature = issuer_signer.sign(&message).unwrap();
        cred = cred.with_proof(CredentialProof::new(
            "Ed25519Signature2020",
            format!("{}#key-1", issuer.did_string()),
            signature.to_bytes(),
        ));

        // Tamper with the credential after signing
        cred.credential_subject.claims.insert(
            "status".to_string(),
            serde_json::json!("premium"),
        );

        // Verify should fail — message was tampered
        let result = registry.verify_credential(&cred).unwrap();
        assert!(!result, "Tampered credential should not verify");
    }

    #[tokio::test]
    async fn test_custom_fee_schedule() {
        use tenzro_types::fees::ServiceFeeSchedule;

        let custom_fees = ServiceFeeSchedule::new(
            1_000_000_000_000_000_000,  // 1 TNZO for human
            500_000_000_000_000_000,    // 0.5 TNZO for machine
            500_000_000_000_000_000,    // 0.5 TNZO for agent
            100_000_000_000_000_000,    // 0.1 TNZO for credential
            50_000_000_000_000_000,     // 0.05 TNZO for verification
            10_000_000_000_000_000_000, // 10 TNZO for model
            100_000_000_000_000_000,    // 0.1 TNZO for bridge
        );

        let registry = IdentityRegistry::with_fee_schedule(custom_fees);
        assert_eq!(registry.human_registration_fee(), 1_000_000_000_000_000_000);
        assert_eq!(registry.machine_registration_fee(), 500_000_000_000_000_000);
    }

    // ----- HIGH #93: DID resolution blockchain fallback -----

    /// Mock backend that returns identities from a fixed map.
    struct MockResolutionBackend {
        records: std::sync::Mutex<HashMap<String, TenzroIdentity>>,
    }

    impl MockResolutionBackend {
        fn new() -> Self {
            Self {
                records: std::sync::Mutex::new(HashMap::new()),
            }
        }
        fn insert(&self, identity: TenzroIdentity) {
            self.records
                .lock()
                .unwrap()
                .insert(identity.did.to_string(), identity);
        }
    }

    impl DidResolutionBackend for MockResolutionBackend {
        fn resolve_remote(
            &self,
            did: &str,
        ) -> crate::error::Result<Option<TenzroIdentity>> {
            Ok(self.records.lock().unwrap().get(did).cloned())
        }
    }

    #[tokio::test]
    async fn test_resolution_backend_fallback_hits_remote() {
        // Build a "remote" registry, register an identity there, then
        // populate the mock backend with that identity.
        let remote = IdentityRegistry::new();
        let remote_identity = remote
            .register_human_with_fee(test_pubkey(7), "Remote Bob".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        let backend = Arc::new(MockResolutionBackend::new());
        backend.insert(remote_identity.clone());

        // Local registry: empty, but with the backend wired in.
        let local = IdentityRegistry::new().with_resolution_backend(backend.clone());

        // Direct lookup is a miss, but the backend should serve it.
        let resolved = local.resolve(&remote_identity.did_string()).unwrap();
        assert_eq!(resolved.did_string(), remote_identity.did_string());
        assert!(local.identities.contains_key(&remote_identity.did_string()));

        // Second lookup should hit the local cache (no need to mutate backend).
        let again = local.resolve(&remote_identity.did_string()).unwrap();
        assert_eq!(again.did_string(), remote_identity.did_string());
    }

    #[tokio::test]
    async fn test_resolution_backend_returns_not_found_when_remote_empty() {
        let backend = Arc::new(MockResolutionBackend::new());
        let local = IdentityRegistry::new().with_resolution_backend(backend);
        let result = local.resolve("did:tenzro:human:00000000-0000-0000-0000-000000000000");
        assert!(matches!(result, Err(IdentityError::NotFound(_))));
    }

    // ----- HIGH #94: delegation enforcement -----

    #[tokio::test]
    async fn test_enforce_operation_returns_error_on_violation() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        let machine = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(2),
                vec![],
                DelegationScope::unrestricted()
                    .with_allowed_operations(vec!["inference".to_string()])
                    .with_max_transaction_value(1_000),
            )
            .await
            .unwrap()
            .identity;

        // Allowed operation within limits succeeds.
        registry
            .enforce_operation(&machine.did_string(), "inference", Some(500))
            .unwrap();

        // Wrong operation must error with DelegationViolation.
        let err = registry
            .enforce_operation(&machine.did_string(), "admin", None)
            .unwrap_err();
        assert!(matches!(err, IdentityError::DelegationViolation(_)));

        // Value over the limit must error.
        let err = registry
            .enforce_operation(&machine.did_string(), "inference", Some(2_000))
            .unwrap_err();
        assert!(matches!(err, IdentityError::DelegationViolation(_)));
    }

    #[tokio::test]
    async fn test_enforce_operation_rejects_inactive_controller() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;
        let machine = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(2),
                vec![],
                DelegationScope::unrestricted()
                    .with_allowed_operations(vec!["inference".to_string()]),
            )
            .await
            .unwrap()
            .identity;

        // Suspend the controller — operation must now be denied.
        registry.suspend(&human.did_string()).unwrap();
        let err = registry
            .enforce_operation(&machine.did_string(), "inference", None)
            .unwrap_err();
        assert!(matches!(err, IdentityError::DelegationViolation(_)));
    }

    #[tokio::test]
    async fn test_enforce_operation_human_bypasses() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;
        // Humans bypass delegation enforcement.
        registry
            .enforce_operation(&human.did_string(), "anything", Some(u128::MAX))
            .unwrap();
    }

    // ----- HIGH #95: KYC tier requires signed credential -----

    #[tokio::test]
    async fn test_update_kyc_tier_requires_credential() {
        use crate::credential::{CredentialProof, TenzroCredentialType, VerifiableCredential};
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
        use tenzro_crypto::{KeyPair, KeyType};

        let registry = IdentityRegistry::new();

        // Register the issuer with a real key.
        let issuer_kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let issuer_pub = issuer_kp.public_key().as_bytes().to_vec();
        let issuer_signer = Ed25519SignerImpl::new(issuer_kp).unwrap();
        let issuer = registry
            .register_human_with_fee(issuer_pub, "Authority".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;

        // Subject starts at Basic.
        let subject = registry
            .register_human_with_fee(test_pubkey(99), "Bob".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        // Build a KycAttestation credential claiming Full.
        let mut cred = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            issuer.did_string(),
            subject.did_string(),
        )
        .with_claim("tier", serde_json::json!(KycTier::Full as u64));

        // Sign the credential subject.
        let msg = serde_json::to_vec(&cred.credential_subject).unwrap();
        let sig = issuer_signer.sign(&msg).unwrap();
        cred = cred.with_proof(CredentialProof::new(
            "Ed25519Signature2020",
            format!("{}#key-1", issuer.did_string()),
            sig.to_bytes(),
        ));

        // Apply with credential — must succeed.
        registry
            .update_kyc_tier_with_credential(&subject.did_string(), KycTier::Full, cred.clone())
            .unwrap();

        let updated = registry.resolve(&subject.did_string()).unwrap();
        assert_eq!(updated.kyc_tier(), Some(KycTier::Full));
        assert_eq!(updated.credentials.len(), 1);
    }

    #[tokio::test]
    async fn test_update_kyc_tier_rejects_mismatched_tier_claim() {
        use crate::credential::{CredentialProof, TenzroCredentialType, VerifiableCredential};
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
        use tenzro_crypto::{KeyPair, KeyType};

        let registry = IdentityRegistry::new();
        let issuer_kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let issuer_pub = issuer_kp.public_key().as_bytes().to_vec();
        let issuer_signer = Ed25519SignerImpl::new(issuer_kp).unwrap();
        let issuer = registry
            .register_human_with_fee(issuer_pub, "Authority".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;
        let subject = registry
            .register_human_with_fee(test_pubkey(11), "Eve".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        // Credential claims "Enhanced" but caller asks for "Full".
        let mut cred = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            issuer.did_string(),
            subject.did_string(),
        )
        .with_claim("tier", serde_json::json!(KycTier::Enhanced as u64));

        let msg = serde_json::to_vec(&cred.credential_subject).unwrap();
        let sig = issuer_signer.sign(&msg).unwrap();
        cred = cred.with_proof(CredentialProof::new(
            "Ed25519Signature2020",
            format!("{}#key-1", issuer.did_string()),
            sig.to_bytes(),
        ));

        let err = registry
            .update_kyc_tier_with_credential(&subject.did_string(), KycTier::Full, cred)
            .unwrap_err();
        assert!(matches!(err, IdentityError::CredentialError(_)));
    }

    #[tokio::test]
    async fn test_update_kyc_tier_rejects_bad_signature() {
        use crate::credential::{CredentialProof, TenzroCredentialType, VerifiableCredential};
        use tenzro_crypto::{KeyPair, KeyType};

        let registry = IdentityRegistry::new();
        // Register an issuer whose public key won't match the credential proof.
        let real_kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let real_pub = real_kp.public_key().as_bytes().to_vec();
        let issuer = registry
            .register_human_with_fee(real_pub, "Authority".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;
        let subject = registry
            .register_human_with_fee(test_pubkey(22), "Mallory".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        // Build a credential with an obviously invalid signature.
        let cred = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            issuer.did_string(),
            subject.did_string(),
        )
        .with_claim("tier", serde_json::json!(KycTier::Full as u64))
        .with_proof(CredentialProof::new(
            "Ed25519Signature2020",
            format!("{}#key-1", issuer.did_string()),
            vec![0u8; 64],
        ));

        let err = registry
            .update_kyc_tier_with_credential(&subject.did_string(), KycTier::Full, cred)
            .unwrap_err();
        assert!(matches!(err, IdentityError::VerificationFailed(_)));
    }

    // ----- HIGH #96: cross-node revocation broadcaster -----

    struct MockBroadcaster {
        sent: std::sync::Mutex<Vec<SignedRevocationEntry>>,
    }
    impl MockBroadcaster {
        fn new() -> Self {
            Self {
                sent: std::sync::Mutex::new(Vec::new()),
            }
        }
    }
    impl RevocationBroadcaster for MockBroadcaster {
        fn broadcast_revocation(
            &self,
            entry: &SignedRevocationEntry,
        ) -> crate::error::Result<()> {
            self.sent.lock().unwrap().push(entry.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_revoke_invokes_broadcaster_for_human_and_cascade() {
        let broadcaster = Arc::new(MockBroadcaster::new());
        let registry =
            IdentityRegistry::new().with_revocation_broadcaster(broadcaster.clone());

        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;
        let machine = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(2),
                vec![],
                DelegationScope::unrestricted(),
            )
            .await
            .unwrap()
            .identity;

        let signer = test_hybrid_signer();
        registry
            .revoke(
                &human.did_string(),
                "test".to_string(),
                "admin".to_string(),
                &signer,
            )
            .unwrap();

        let sent = broadcaster.sent.lock().unwrap();
        assert_eq!(sent.len(), 2, "primary + 1 cascaded revocation");
        let dids: Vec<&str> = sent.iter().map(|s| s.entry.did.as_str()).collect();
        assert!(dids.contains(&human.did_string().as_str()));
        assert!(dids.contains(&machine.did_string().as_str()));
        // Wave 3d: every broadcast carries a verifiable hybrid signature.
        for s in sent.iter() {
            s.verify().expect("signed revocation must verify");
            assert!(!s.signature.pq.is_empty(), "must carry PQ leg");
        }
    }

    #[tokio::test]
    async fn test_apply_remote_revocation_marks_local_identity() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        // Remote node tells us this identity has been revoked.
        let entry = RevocationEntry {
            did: human.did_string(),
            revoked_at: Utc::now(),
            reason: "remote".to_string(),
            revoked_by: "peer".to_string(),
        };
        let signer = test_hybrid_signer();
        let signed = SignedRevocationEntry::sign(entry, &signer).unwrap();
        registry.apply_remote_revocation(signed).unwrap();

        let updated = registry.resolve(&human.did_string()).unwrap();
        assert_eq!(updated.status, IdentityStatus::Revoked);
        assert!(registry.is_revoked(&human.did_string()));
    }

    #[tokio::test]
    async fn test_apply_remote_revocation_rejects_tampered_signature() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        let entry = RevocationEntry {
            did: human.did_string(),
            revoked_at: Utc::now(),
            reason: "remote".to_string(),
            revoked_by: "peer".to_string(),
        };
        let signer = test_hybrid_signer();
        let mut signed = SignedRevocationEntry::sign(entry, &signer).unwrap();
        // Tamper with the entry — the signature now no longer covers it.
        signed.entry.reason = "FORGED".to_string();

        let err = registry.apply_remote_revocation(signed).unwrap_err();
        assert!(matches!(err, IdentityError::VerificationFailed(_)));
        // Local state must remain unchanged.
        let still_active = registry.resolve(&human.did_string()).unwrap();
        assert_eq!(still_active.status, IdentityStatus::Active);
    }

    #[tokio::test]
    async fn test_credential_replay_rejected() {
        use crate::credential::{TenzroCredentialType, VerifiableCredential};

        let registry = IdentityRegistry::new();
        let identity = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Enhanced)
            .await
            .unwrap()
            .identity;

        let cred = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            "did:tenzro:human:issuer",
            identity.did_string(),
        );

        // First issuance should succeed
        registry
            .issue_credential(&identity.did_string(), cred.clone())
            .unwrap();

        // Second issuance of the same credential ID should fail
        let result = registry.issue_credential(&identity.did_string(), cred);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), IdentityError::DuplicateCredential(_)),
            "Expected DuplicateCredential error"
        );
    }

    #[tokio::test]
    async fn test_different_credentials_allowed() {
        use crate::credential::{TenzroCredentialType, VerifiableCredential};

        let registry = IdentityRegistry::new();
        let identity = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Enhanced)
            .await
            .unwrap()
            .identity;

        let cred1 = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            "did:tenzro:human:issuer",
            identity.did_string(),
        );
        let cred2 = VerifiableCredential::new(
            TenzroCredentialType::ModelProvider,
            "did:tenzro:human:issuer",
            identity.did_string(),
        );

        // Both should succeed (different IDs)
        registry.issue_credential(&identity.did_string(), cred1).unwrap();
        registry.issue_credential(&identity.did_string(), cred2).unwrap();
    }

    // ----- Principal-chain resolver tests (Agent-Swarm Spec 5) -----

    #[tokio::test]
    async fn principal_chain_for_human_acting_directly() {
        let registry = IdentityRegistry::new();
        let alice = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Enhanced)
            .await
            .unwrap()
            .identity;

        let pc = registry.resolve_principal_chain(&alice.did_string(), 100u64);

        assert_eq!(pc.delegation_depth, 0);
        assert!(pc.chain.is_empty());
        assert_eq!(pc.actor, alice.did_string());
        assert_eq!(pc.controller_did(), alice.did_string());
        assert_eq!(pc.controller.role, PrincipalRole::Controller);
        assert_eq!(pc.controller_kyc_tier, KycTier::Enhanced.level());
        assert_eq!(pc.frozen_at_block, BlockHeight::new(100));
        assert!(!pc.has_tombstone());
    }

    #[tokio::test]
    async fn principal_chain_for_machine_under_human_controller() {
        let registry = IdentityRegistry::new();
        let alice = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;
        let bot = registry
            .register_machine_with_fee(
                &alice.did_string(),
                test_pubkey(2),
                vec!["inference".to_string()],
                DelegationScope::unrestricted(),
            )
            .await
            .unwrap()
            .identity;

        let pc = registry.resolve_principal_chain(&bot.did_string(), 200u64);

        assert_eq!(pc.delegation_depth, 2);
        assert_eq!(pc.controller_did(), alice.did_string());
        assert_eq!(pc.controller.role, PrincipalRole::Controller);
        assert_eq!(pc.controller_kyc_tier, KycTier::Full.level());
        assert_eq!(pc.actor, bot.did_string());
        // chain[0] is the controller, chain[1] is the actor.
        assert_eq!(pc.chain.len(), 2);
        assert_eq!(pc.chain[0].did, alice.did_string());
        assert_eq!(pc.chain[1].did, bot.did_string());
        assert!(!pc.has_tombstone());
    }

    #[tokio::test]
    async fn principal_chain_for_autonomous_machine() {
        let registry = IdentityRegistry::new();
        let bot = registry
            .register_autonomous_machine(test_pubkey(1), vec!["monitoring".to_string()])
            .await
            .unwrap();

        let pc = registry.resolve_principal_chain(&bot.did_string(), 50u64);

        assert_eq!(pc.delegation_depth, 0);
        assert!(pc.chain.is_empty());
        assert_eq!(pc.controller.role, PrincipalRole::AutonomousAgent);
        assert_eq!(pc.controller_kyc_tier, 0);
    }

    #[tokio::test]
    async fn principal_chain_for_unresolvable_did_returns_tombstone() {
        let registry = IdentityRegistry::new();
        let pc = registry.resolve_principal_chain("did:tenzro:human:ghost:uuid", 7u64);

        assert!(pc.has_tombstone());
        assert_eq!(pc.controller_kyc_tier, 0);
        assert_eq!(pc.frozen_at_block, BlockHeight::new(7));
    }

    #[tokio::test]
    async fn resolver_trait_resolves_by_address() {
        let registry = IdentityRegistry::new();
        let alice = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        let resolver: &dyn PrincipalChainResolver = &registry;
        let pc = resolver.resolve_by_address(&alice.wallet_address, BlockHeight::new(9));

        assert_eq!(pc.controller_did(), alice.did_string());
        assert_eq!(pc.controller_kyc_tier, KycTier::Basic.level());
    }

    #[tokio::test]
    async fn resolver_trait_returns_anonymous_chain_for_unbound_address() {
        let registry = IdentityRegistry::new();
        let resolver: &dyn PrincipalChainResolver = &registry;
        let unbound = Address::new([0xAB; 32]);

        let pc = resolver.resolve_by_address(&unbound, BlockHeight::new(11));

        assert!(pc.controller.tombstone);
        assert!(pc.controller.did.starts_with("did:tenzro:anonymous:"));
        assert_eq!(pc.controller_kyc_tier, 0);
    }

    // ----- Spec 9 BondLookup wiring tests -----

    /// In-test `BondLookup` impl. Wraps DID→amount maps in `RwLock` so
    /// tests can wire the lookup into the registry *before* DIDs are
    /// minted, then populate the maps after registration. `TenzroDid::new_*`
    /// mints a fresh UUID per call, so the lookup must be keyed by the
    /// actual DIDs the registry produced.
    struct FakeBondLookup {
        actor: parking_lot::RwLock<std::collections::HashMap<String, u128>>,
        aggregate: parking_lot::RwLock<std::collections::HashMap<String, u128>>,
    }

    impl FakeBondLookup {
        fn new() -> Self {
            Self {
                actor: parking_lot::RwLock::new(std::collections::HashMap::new()),
                aggregate: parking_lot::RwLock::new(std::collections::HashMap::new()),
            }
        }
    }

    impl BondLookup for FakeBondLookup {
        fn actor_bond(&self, did: &str) -> Option<u128> {
            self.actor.read().get(did).copied()
        }
        fn controller_aggregate(&self, controller_did: &str) -> Option<u128> {
            self.aggregate.read().get(controller_did).copied()
        }
    }

    #[tokio::test]
    async fn principal_chain_populates_spec9_bond_fields_when_lookup_wired() {
        // Use Arc<RwLock<...>> so we can wire the lookup into the registry
        // *before* the DIDs are minted, then populate the maps after
        // registration. `TenzroDid::new_*` mints a fresh UUID per call, so
        // the lookup map must be keyed by the actual DIDs the registry
        // produced — not by DIDs from a separate parallel registry.
        let actor_amount = 5_000_000_000_000_000_000u128;
        let aggregate_amount = 25_000_000_000_000_000_000u128;

        let lookup = Arc::new(FakeBondLookup::new());
        let registry = IdentityRegistry::new()
            .with_bond_lookup(lookup.clone() as Arc<dyn BondLookup>);

        let alice = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;
        let bot = registry
            .register_machine_with_fee(
                &alice.did_string(),
                test_pubkey(2),
                vec!["inference".to_string()],
                DelegationScope::unrestricted(),
            )
            .await
            .unwrap()
            .identity;

        // Populate the lookup with the registry's actual DIDs.
        lookup.actor.write().insert(bot.did_string(), actor_amount);
        lookup
            .aggregate
            .write()
            .insert(alice.did_string(), aggregate_amount);

        let pc = registry.resolve_principal_chain(&bot.did_string(), 100u64);

        assert_eq!(pc.actor_bond, Some(actor_amount));
        assert_eq!(pc.controller_bond_aggregate, Some(aggregate_amount));
        // controller_bond is the bond on the controller's *own* DID,
        // which the lookup doesn't have an entry for.
        assert_eq!(pc.controller_bond, None);
    }

    #[tokio::test]
    async fn principal_chain_bond_fields_none_without_lookup() {
        let registry = IdentityRegistry::new();
        let alice = registry
            .register_human_with_fee(test_pubkey(1), "Alice".to_string(), KycTier::Full)
            .await
            .unwrap()
            .identity;
        let bot = registry
            .register_machine_with_fee(
                &alice.did_string(),
                test_pubkey(2),
                vec!["inference".to_string()],
                DelegationScope::unrestricted(),
            )
            .await
            .unwrap()
            .identity;

        let pc = registry.resolve_principal_chain(&bot.did_string(), 1u64);
        assert_eq!(pc.actor_bond, None);
        assert_eq!(pc.controller_bond_aggregate, None);
        assert_eq!(pc.controller_bond, None);
    }

    #[tokio::test]
    async fn principal_chain_autonomous_machine_uses_self_as_controller_for_aggregate() {
        // Autonomous machine (no controller) — actor IS the controller,
        // so controller_aggregate keys off the actor's own DID. Wire the
        // lookup before registration and populate using the registry's
        // actual minted DID (UUIDs are fresh per call).
        let amount = 10_000_000_000_000_000_000u128;

        let lookup = Arc::new(FakeBondLookup::new());
        let registry = IdentityRegistry::new()
            .with_bond_lookup(lookup.clone() as Arc<dyn BondLookup>);
        let bot = registry
            .register_autonomous_machine(test_pubkey(7), vec!["monitoring".to_string()])
            .await
            .unwrap();

        lookup.actor.write().insert(bot.did_string(), amount);
        lookup.aggregate.write().insert(bot.did_string(), amount);

        let pc = registry.resolve_principal_chain(&bot.did_string(), 1u64);

        assert_eq!(pc.actor_bond, Some(amount));
        assert_eq!(pc.controller_bond_aggregate, Some(amount));
    }
}
