//! Identity registry for the Tenzro Decentralized Identity Protocol
//!
//! The `IdentityRegistry` is the central store for all TDIP identities,
//! handling both human and machine identities through a unified type.

use crate::did::TenzroDid;
use crate::error::{IdentityError, Result};
use crate::identity::{
    IdentityData, IdentityStatus, KeyPurpose, PublicKeyInfo, RevocationEntry, TenzroIdentity,
};
use crate::wallet_binding::{WalletBinder, WalletBinding};
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_crypto::composite::CompositePublicKey;
use tenzro_storage::kv::{CF_IDENTITIES, KvStore};
use tenzro_types::fees::ServiceFeeSchedule;
use tenzro_types::identity::{IdentityType as TenzroIdentityType, KycTier};
use tenzro_types::primitives::{Address, BlockHeight};
use tenzro_types::principal_chain::{
    BondLookup, MAX_DELEGATION_DEPTH, PrincipalChain, PrincipalLink, PrincipalRole,
};
use tracing::{debug, info, warn};

/// Derives the KYC (or, for an institution, KYB) tier an identity holds.
///
/// No identity stores a tier of its own. The node supplies a resolver that
/// reads the certifications its relying party recognises;
/// without one every identity is `Unverified`.
pub trait KycResolver: Send + Sync {
    /// The tier of `did`, whose wallet is `wallet`.
    fn kyc_tier(&self, did: &str, wallet: &tenzro_types::Address) -> KycTier;
}

/// Configurable enforcement policy for delegation scopes.
#[derive(Debug, Clone, Copy)]
pub struct DelegationPolicy {
    /// Minimum reputation a machine must have for an operation to be allowed.
    pub min_reputation: u32,
    /// If true, machines whose controller is not Active have all operations denied.
    pub require_active_controller: bool,
    /// Minimum KYC tier the party answering for an operation must hold, as
    /// derived by the registry's [`KycResolver`]. `Unverified` requires
    /// nothing.
    pub min_kyc_tier: KycTier,
}

impl Default for DelegationPolicy {
    fn default() -> Self {
        Self {
            min_reputation: 0,
            require_active_controller: true,
            min_kyc_tier: KycTier::Unverified,
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

/// A registration checked and built but not yet written. The registry writes
/// nothing until [`IdentityRegistry::admit`] takes it, so a caller that must
/// first get the registration into consensus writes nothing when that fails.
#[derive(Debug, Clone)]
pub struct PendingRegistration {
    /// The identity to register
    pub identity: TenzroIdentity,
    /// The fee required for this registration (in smallest TNZO unit)
    pub fee_required: u128,
    controller_did: Option<String>,
    mirror: bool,
}

/// Checks the hardware evidence recorded with a root-derived machine identity.
pub type EvidenceVerifier = Arc<dyn Fn(&TenzroIdentity) -> bool + Send + Sync>;

/// Reads whether an agent holds consensus Terms (its only authority).
pub trait AgentTermsLookup: Send + Sync {
    fn has_terms(&self, agent_did: &str) -> bool;
}

/// Central registry for Tenzro Decentralized Identity Protocol identities
///
/// Thread-safe (DashMap-backed) registry supporting concurrent identity
/// operations on both human and machine identities through a unified type.
///
/// # Persistence
///
/// Identities live in-memory in a DashMap. Construct via
/// [`Self::with_storage`] for RocksDB write-through persistence and
/// startup hydration; the canonical on-disk format is bincode
/// (`TenzroIdentity::to_bytes` / `from_bytes`).
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
    /// DID → *additional* identity-bound wallets bound to that identity.
    ///
    /// Optional wallet binder for auto-provisioning
    wallet_binder: Option<Arc<WalletBinder>>,
    /// Fee schedule for registration operations
    fee_schedule: ServiceFeeSchedule,
    /// Optional persistent storage backend (RocksDB)
    storage: Option<Arc<dyn KvStore>>,
    /// Verifies the TPM evidence of a machine whose DID derives from its
    /// attestation key rather than from its registered key. Supplied by the
    /// node, which holds the attestation verifiers; without one such records
    /// are not accepted.
    evidence_verifier: Option<EvidenceVerifier>,
    /// Delegation enforcement policy
    delegation_policy: DelegationPolicy,
    /// Optional ERC-8004 on-chain mirror.
    ///
    /// When set, every machine identity registration is automatically
    /// reflected into the on-chain ERC-8004 IdentityRegistry (the contract
    /// at [`crate::erc8004::addresses::IDENTITY_REGISTRY`]). The hook is best-effort —
    /// failures are logged but never roll back the TDIP registration.
    on_chain_agent_registry: Option<Arc<dyn crate::erc8004::OnChainAgentRegistry>>,
    /// Optional AgentBond lookup. When wired, the principal-chain
    /// resolver populates `actor_bond` and `controller_bond_aggregate` on
    /// every receipt. The node wires a chain-state reader; tests may pass a
    /// fake.
    bond_lookup: Option<Arc<dyn BondLookup>>,
    /// Whether an agent holds consensus Terms. The node wires a chain-state
    /// reader; without one no agent counts as bound by Terms.
    terms_lookup: Option<Arc<dyn AgentTermsLookup>>,
    /// Derives identities' KYC tiers. `None` means every identity is
    /// `Unverified`.
    kyc_resolver: Option<Arc<dyn KycResolver>>,
}

/// The key set an identity inherits from the wallet binding that created it.
///
/// `key-1` is the binding's own classical key, good for both authenticating as
/// the identity and signing statements under it.
///
/// The single P-256 key (`key-1`) authenticates as the identity and signs
/// what it asserts (reserve attestations among them), as a composite
/// signature from the hardware that holds it.
fn binding_public_keys(binding: &WalletBinding) -> Vec<PublicKeyInfo> {
    vec![PublicKeyInfo {
        key_id: "key-1".to_string(),
        key_type: "P-256".to_string(),
        public_key: binding.public_key.clone(),
        purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod],
    }]
}

/// The wallet key of a passkey or TPM / Secure Enclave P-256 public key, given
/// as `x || y` or as the SEC1 uncompressed point.
fn wallet_key(p256: &[u8]) -> Result<CompositePublicKey> {
    let xy = match p256 {
        [0x04, rest @ ..] if rest.len() == 64 => rest,
        _ => p256,
    };
    CompositePublicKey::new(xy.to_vec(), None)
        .map_err(|e| IdentityError::WalletError(format!("not a P-256 hardware key: {e}")))
}

impl IdentityRegistry {
    /// Creates a new identity registry without wallet auto-provisioning
    pub fn new() -> Self {
        info!("Initializing Tenzro Identity Registry");
        Self {
            identities: DashMap::new(),
            revocations: DashMap::new(),
            // Under test, back the registry with an in-process binder so
            // registrations produce *signable* wallets.
            //
            // Registration used to fall back, with no binder, to an address
            // hashed from the DID that no key can sign for — documented as
            // "never correct for a live node" and now refused outright. Tests
            // relied on that fallback, so without this they would either need a
            // binder wired at dozens of call sites, or the dead-address path
            // would have to stay alive — and its whole problem is that it looks
            // like it worked.
            //
            // `WalletBinder::new` is documented as suitable for exactly this.
            // Production wires its own through `with_wallet_binder_arc`, which
            // replaces whatever is here.
            #[cfg(test)]
            wallet_binder: WalletBinder::new().ok().map(Arc::new),
            #[cfg(not(test))]
            wallet_binder: None,
            fee_schedule: ServiceFeeSchedule::default(),
            storage: None,
            delegation_policy: DelegationPolicy::default(),
            on_chain_agent_registry: None,
            bond_lookup: None,
            terms_lookup: None,
            kyc_resolver: None,
            evidence_verifier: None,
        }
    }

    /// Creates a new identity registry with wallet auto-provisioning
    pub fn with_wallet_binder(wallet_binder: Arc<WalletBinder>) -> Self {
        info!("Initializing Tenzro Identity Registry with wallet binding");
        Self {
            identities: DashMap::new(),
            revocations: DashMap::new(),
            wallet_binder: Some(wallet_binder),
            fee_schedule: ServiceFeeSchedule::default(),
            storage: None,
            delegation_policy: DelegationPolicy::default(),
            on_chain_agent_registry: None,
            bond_lookup: None,
            terms_lookup: None,
            kyc_resolver: None,
            evidence_verifier: None,
        }
    }

    /// Creates a new identity registry with custom fee schedule
    pub fn with_fee_schedule(fee_schedule: ServiceFeeSchedule) -> Self {
        info!("Initializing Tenzro Identity Registry with custom fee schedule");
        Self {
            identities: DashMap::new(),
            revocations: DashMap::new(),
            // Under test, back the registry with an in-process binder so
            // registrations produce *signable* wallets.
            //
            // Registration used to fall back, with no binder, to an address
            // hashed from the DID that no key can sign for — documented as
            // "never correct for a live node" and now refused outright. Tests
            // relied on that fallback, so without this they would either need a
            // binder wired at dozens of call sites, or the dead-address path
            // would have to stay alive — and its whole problem is that it looks
            // like it worked.
            //
            // `WalletBinder::new` is documented as suitable for exactly this.
            // Production wires its own through `with_wallet_binder_arc`, which
            // replaces whatever is here.
            #[cfg(test)]
            wallet_binder: WalletBinder::new().ok().map(Arc::new),
            #[cfg(not(test))]
            wallet_binder: None,
            fee_schedule,
            storage: None,
            delegation_policy: DelegationPolicy::default(),
            on_chain_agent_registry: None,
            bond_lookup: None,
            terms_lookup: None,
            kyc_resolver: None,
            evidence_verifier: None,
        }
    }

    /// Creates a new identity registry with persistent RocksDB storage
    ///
    /// Loads all existing identities from storage into the in-memory DashMap
    /// on initialization, then writes through to storage on every mutation.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        info!("Initializing Tenzro Identity Registry with persistent storage");
        let identities = DashMap::new();
        let revocations = DashMap::new();

        // Hydrate persisted revocation records first — these carry the real
        // reason / revoked_by / revoked_at, so the identity scan below only
        // synthesizes a fallback entry when no persisted record exists.
        match storage.get_keys_with_prefix(CF_IDENTITIES, b"revocation:") {
            Ok(keys) => {
                let mut loaded_revocations = 0usize;
                for key in &keys {
                    if let Ok(Some(data)) = storage.get(CF_IDENTITIES, key)
                        && let Ok(entry) = bincode::deserialize::<RevocationEntry>(&data)
                    {
                        revocations.insert(entry.did.clone(), entry);
                        loaded_revocations += 1;
                    }
                }
                if loaded_revocations > 0 {
                    info!(
                        "Loaded {} revocation records from storage",
                        loaded_revocations
                    );
                }
            }
            Err(e) => {
                warn!("Failed to load revocation records from storage: {}", e);
            }
        }

        // Load existing identities from storage
        match storage.get_keys_with_prefix(CF_IDENTITIES, b"did:") {
            Ok(keys) => {
                let mut loaded = 0usize;
                for key in &keys {
                    if let Ok(Some(data)) = storage.get(CF_IDENTITIES, key)
                        && let Ok(identity) = bincode::deserialize::<TenzroIdentity>(&data)
                    {
                        let did_string = identity.did.to_string();
                        if identity.status == IdentityStatus::Revoked
                            && !revocations.contains_key(&did_string)
                        {
                            revocations.insert(
                                did_string.clone(),
                                RevocationEntry {
                                    did: did_string.clone(),
                                    revoked_at: identity.updated_at,
                                    reason: "loaded from storage".to_string(),
                                    revoked_by: "system".to_string(),
                                },
                            );
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

        Self {
            identities,
            revocations,
            // Under test, back the registry with an in-process binder so
            // registrations produce *signable* wallets.
            //
            // Registration used to fall back, with no binder, to an address
            // hashed from the DID that no key can sign for — documented as
            // "never correct for a live node" and now refused outright. Tests
            // relied on that fallback, so without this they would either need a
            // binder wired at dozens of call sites, or the dead-address path
            // would have to stay alive — and its whole problem is that it looks
            // like it worked.
            //
            // `WalletBinder::new` is documented as suitable for exactly this.
            // Production wires its own through `with_wallet_binder_arc`, which
            // replaces whatever is here.
            #[cfg(test)]
            wallet_binder: WalletBinder::new().ok().map(Arc::new),
            #[cfg(not(test))]
            wallet_binder: None,
            fee_schedule: ServiceFeeSchedule::default(),
            storage: Some(storage),
            delegation_policy: DelegationPolicy::default(),
            on_chain_agent_registry: None,
            bond_lookup: None,
            terms_lookup: None,
            kyc_resolver: None,
            evidence_verifier: None,
        }
    }

    /// Sets the storage backend (builder pattern)
    pub fn with_storage_backend(mut self, storage: Arc<dyn KvStore>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Attaches a wallet binder (builder pattern).
    ///
    /// Composes with `with_storage` and the other builders so the
    /// node can stack persistent storage and a shared wallet service onto a
    /// single registry instance. When set, `register_human_via_binder` and
    /// `register_machine_with_fee` provision identity-bound wallets through the
    /// binder's `WalletService`; without it, those calls now *refuse* rather
    /// than assigning a placeholder address no key can sign for.
    pub fn with_wallet_binder_arc(mut self, wallet_binder: Arc<WalletBinder>) -> Self {
        self.wallet_binder = Some(wallet_binder);
        self
    }

    /// A registry backed by a fresh in-process [`WalletBinder`].
    ///
    /// For tests and single-process development, where registrations must yield
    /// *signable* wallets but there is no shared node wallet service to bind to.
    ///
    /// A registry with no binder now refuses to register rather than assigning a
    /// placeholder address hashed from the DID — an address no key can sign for,
    /// which looks like an ordinary account until someone tries to spend from
    /// it. That refusal is right for a live node and useless for a test, so
    /// tests ask for this explicitly instead of being handed a dead address.
    ///
    /// Not for production node startup: the wallets live in a service private to
    /// this registry, so the node's own signing paths would not know about them.
    /// Production wires the shared service via [`Self::with_wallet_binder_arc`].
    pub fn with_in_process_binder() -> Result<Self> {
        let binder = Arc::new(WalletBinder::new()?);
        Ok(Self::new().with_wallet_binder_arc(binder))
    }

    /// Returns `true` when this registry has a [`WalletBinder`] configured.
    ///
    /// Callers that require auto-provisioned wallets (identities that must
    /// come back with a signable on-chain address) can assert this up-front
    /// rather than discover the missing binder at registration time. Returns `false` for
    /// in-memory registries constructed via [`Self::new`] /
    /// [`Self::with_storage`] without a binder, where `register_*_with_fee`
    /// refuses rather than producing an unsignable wallet.
    pub fn has_wallet_binder(&self) -> bool {
        self.wallet_binder.is_some()
    }

    /// Attaches the verifier for root-derived machine identities' evidence.
    pub fn with_evidence_verifier(mut self, verifier: EvidenceVerifier) -> Self {
        self.evidence_verifier = Some(verifier);
        self
    }

    /// Whether `identity`'s DID provably belongs to its keys: the DID derives
    /// from one of its public keys, or it derives from a TPM attestation key
    /// whose recorded quote the evidence verifier accepts. The check every
    /// record must pass before it is trusted.
    pub fn binding_holds(&self, identity: &TenzroIdentity) -> bool {
        use tenzro_types::did_derivation::did_derives_from_key;
        let did = identity.did.to_string();
        if identity
            .public_keys
            .iter()
            .any(|k| did_derives_from_key(&did, &k.public_key))
        {
            return true;
        }
        self.evidence_verifier
            .as_ref()
            .is_some_and(|verify| verify(identity))
    }

    /// Apply a signed post-quantum rotation: from now on `rotation.new_pq_key`
    /// governs the identity, and its DID is unchanged.
    ///
    /// The governing key is the identity's root key until the first rotation
    /// and the last installed ML-DSA key after it (see
    /// [`crate::pq_rotation`]). The new key is added as `pq-1` for
    /// authentication and assertion, and the identity's post-quantum
    /// verifying key becomes it.
    pub fn apply_pq_rotation(
        &self,
        rotation: &crate::pq_rotation::PqRotation,
    ) -> Result<TenzroIdentity> {
        use crate::pq_rotation::{Authority, META_PQ_AUTHORITY, META_PQ_BACKEND, META_PQ_SEQUENCE};
        let mut entry = self
            .identities
            .get_mut(&rotation.did)
            .ok_or_else(|| IdentityError::NotFound(rotation.did.clone()))?;
        let identity = entry.value_mut();
        if !identity.is_active() {
            return Err(IdentityError::NotActive(rotation.did.clone()));
        }
        let last_sequence: u64 = identity
            .metadata
            .get(META_PQ_SEQUENCE)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let authority_key = identity
            .metadata
            .get(META_PQ_AUTHORITY)
            .and_then(|h| hex::decode(h).ok());
        let root_key = identity
            .public_keys
            .first()
            .map(|k| k.public_key.clone())
            .unwrap_or_default();
        let authority = match authority_key.as_deref() {
            Some(pq) => crate::pq_rotation::Authority::PqKey(pq),
            None => Authority::RootKey(&root_key),
        };
        rotation.verify(authority, last_sequence)?;

        identity.public_keys.retain(|k| k.key_id != "pq-1");
        identity.public_keys.push(PublicKeyInfo {
            key_id: "pq-1".to_string(),
            key_type: "ML-DSA-65".to_string(),
            public_key: rotation.new_pq_key.clone(),
            purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod],
        });
        identity.pq_verifying_key = rotation.new_pq_key.clone();
        identity.metadata.insert(
            META_PQ_AUTHORITY.to_string(),
            hex::encode(&rotation.new_pq_key),
        );
        identity
            .metadata
            .insert(META_PQ_SEQUENCE.to_string(), rotation.sequence.to_string());
        identity.metadata.insert(
            META_PQ_BACKEND.to_string(),
            rotation.backend.as_str().to_string(),
        );
        identity.updated_at = Utc::now();
        let updated = identity.clone();
        drop(entry);
        self.persist_identity(&rotation.did, &updated);
        info!(did = %rotation.did, sequence = rotation.sequence, backend = rotation.backend.as_str(), "identity governed by a post-quantum key");
        Ok(updated)
    }

    /// Configures the delegation enforcement policy.
    pub fn with_delegation_policy(mut self, policy: DelegationPolicy) -> Self {
        self.delegation_policy = policy;
        self
    }

    /// Wires an ERC-8004 on-chain mirror so every machine identity
    /// registration is reflected into the on-chain IdentityRegistry
    /// (the contract at [`crate::erc8004::addresses::IDENTITY_REGISTRY`]). Best-effort:
    /// failures are logged but never fail the TDIP registration.
    pub fn with_on_chain_agent_registry(
        mut self,
        registry: Arc<dyn crate::erc8004::OnChainAgentRegistry>,
    ) -> Self {
        self.on_chain_agent_registry = Some(registry);
        self
    }

    /// Wires the reader of agents' consensus Terms.
    pub fn with_terms_lookup(mut self, lookup: Arc<dyn AgentTermsLookup>) -> Self {
        self.terms_lookup = Some(lookup);
        self
    }

    /// Whether `agent_did` holds consensus Terms.
    pub fn has_agent_terms(&self, agent_did: &str) -> bool {
        self.terms_lookup
            .as_ref()
            .is_some_and(|l| l.has_terms(agent_did))
    }

    /// Wires an AgentBond lookup. When set, the principal-chain
    /// resolver populates `actor_bond` and `controller_bond_aggregate` on
    /// every receipt. The node wires a chain-state reader.
    pub fn with_bond_lookup(mut self, lookup: Arc<dyn BondLookup>) -> Self {
        self.bond_lookup = Some(lookup);
        self
    }

    /// Wire the resolver that derives identities' KYC tiers.
    pub fn with_kyc_resolver(mut self, resolver: Arc<dyn KycResolver>) -> Self {
        self.kyc_resolver = Some(resolver);
        self
    }

    /// The KYC tier `did` holds, as the wired [`KycResolver`] derives it for
    /// the identity's wallet. A revoked or unknown identity, or a registry
    /// without a resolver, holds `Unverified`.
    pub fn kyc_tier(&self, did: &str) -> KycTier {
        if self.is_revoked(did) {
            return KycTier::Unverified;
        }
        let Some(resolver) = self.kyc_resolver.as_ref() else {
            return KycTier::Unverified;
        };
        match self.resolve(did) {
            Ok(identity) => resolver.kyc_tier(did, &identity.wallet_address),
            Err(_) => KycTier::Unverified,
        }
    }

    /// Returns the active delegation policy.
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
    pub fn apply_erc8004_registered_event(&self, did: &str, agent_id: u64) -> Result<bool> {
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

    /// Persists a revocation record under `revocation:<did>` so the reason,
    /// revoker, and timestamp survive restarts (hydrated in `with_storage`
    /// before the identity scan).
    fn persist_revocation(&self, entry: &RevocationEntry) {
        if let Some(ref store) = self.storage {
            let key = format!("revocation:{}", entry.did);
            match bincode::serialize(entry) {
                Ok(data) => {
                    if let Err(e) = store.put(CF_IDENTITIES, key.as_bytes(), &data) {
                        warn!("Failed to persist revocation for {}: {}", entry.did, e);
                    }
                }
                Err(e) => {
                    warn!("Failed to serialize revocation for {}: {}", entry.did, e);
                }
            }
        }
    }

    /// Hard-deletes an identity record from RocksDB.
    ///
    /// Used by [`Self::forget_identity`] to satisfy TDIP/GDPR Article 17
    /// right-to-erasure: the identity must already be `Revoked` (logical
    /// delete) before the record can be physically removed from storage.
    /// This is distinct from a revocation ([`Self::revoke_from_chain`]),
    /// which keeps the row for audit.
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
    /// `IdentityStatus::Revoked` — the revocation is decided in consensus and
    /// mirrored here by [`Self::revoke_from_chain`], and only then may
    /// `forget_identity()` run. The two phases give downstream consumers
    /// (cascading revoke, every node's read model) a chance to react to the
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

    /// Registers a new human identity and returns fee information
    ///
    /// Creates a human DID, optionally provisions a wallet, and stores
    /// the identity in the registry. Returns both the identity and the
    /// registration fee required.
    /// A human identity is rooted in a passkey, so `passkey_credential_id` is
    /// required alongside its public key. Both come from the WebAuthn ceremony;
    /// the private half never leaves the authenticator.
    pub async fn prepare_human(
        &self,
        passkey_credential_id: Vec<u8>,
        public_key: Vec<u8>,
        display_name: String,
    ) -> Result<PendingRegistration> {
        // The identity is the passkey: derive the DID from the credential key so
        // the same authenticator always resolves to the same identity.
        let did = TenzroDid::from_passkey(&public_key);
        let did_string = did.to_string();

        let (wallet_address, wallet_id, pq_verifying_key) = self
            .provision_or_default(
                &did_string,
                tenzro_wallet::WalletIdentity::human(
                    passkey_credential_id.clone(),
                    wallet_key(&public_key)?,
                )
                .map_err(|e| IdentityError::WalletError(e.to_string()))?,
            )
            .await?;

        let identity = TenzroIdentity {
            did,
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "P-256".to_string(),
                public_key,
                purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod],
            }],
            identity_data: IdentityData::Human {
                display_name: display_name.clone(),
                controlled_machines: Vec::new(),
            },
            status: IdentityStatus::Active,
            wallet_address,
            wallet_id,
            pq_verifying_key,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
        };

        let fee_required = self.fee_schedule.human_identity_registration;

        info!(
            "Registered human identity: {} (name: {}, fee: {} TNZO)",
            did_string,
            display_name,
            fee_required / 1_000_000_000_000_000_000
        );

        Ok(PendingRegistration {
            identity,
            fee_required,
            controller_did: None,
            mirror: false,
        })
    }

    /// Registers a human identity by provisioning the wallet through the
    /// configured `WalletBinder`, then using that wallet's classical public
    /// key as the identity's `public_keys[0]`.
    ///
    /// This is the production onboarding path used by `tenzro_onboardHuman`,
    /// `tenzro_participate`, and the desktop Setup flow: a single identity-bound wallet
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
    /// A **human** identity is rooted in a passkey, so the credential and its
    /// public key are required. They are not optional and there is no path that
    /// omits them: a human wallet whose signing key was minted by the service
    /// would be custodial, and one with no credential could never be
    /// authenticated by the person it belongs to.
    ///
    /// Machines do not use this path — they root in a TPM or Secure Enclave;
    /// see `tenzro_wallet::WalletIdentity::machine`.
    pub async fn register_human_via_binder(
        &self,
        passkey_credential_id: Vec<u8>,
        passkey_public_key: Vec<u8>,
        display_name: String,
    ) -> Result<RegistrationResult> {
        // The identity is the passkey: derive the DID from the credential key so
        // the same authenticator always resolves to the same identity, even
        // after a remove-and-re-enrol.
        let did = TenzroDid::from_passkey(&passkey_public_key);
        let did_string = did.to_string();
        // One passkey, one identity: registering it again would provision a
        // second wallet and replace the identity that already holds this DID.
        if self.identities.contains_key(&did_string) {
            return Err(IdentityError::AlreadyExists(did_string));
        }

        let binder = self
            .wallet_binder
            .as_ref()
            .ok_or_else(|| IdentityError::WalletError("no wallet binder configured".to_string()))?;
        let identity = tenzro_wallet::WalletIdentity::human(
            passkey_credential_id,
            wallet_key(&passkey_public_key)?,
        )
        .map_err(|e| IdentityError::WalletError(e.to_string()))?;
        let binding = binder.provision_wallet(&did_string, identity).await?;

        let identity = TenzroIdentity {
            did,
            public_keys: binding_public_keys(&binding),
            identity_data: IdentityData::Human {
                display_name: display_name.clone(),
                controlled_machines: Vec::new(),
            },
            status: IdentityStatus::Active,
            wallet_address: binding.address,
            wallet_id: binding.wallet_id,
            pq_verifying_key: binding.pq_verifying_key,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
        };

        let fee_required = self.fee_schedule.human_identity_registration;

        info!(
            "Registered human identity via binder: {} (name: {}, fee: {} TNZO)",
            did_string,
            display_name,
            fee_required / 1_000_000_000_000_000_000
        );

        self.persist_identity(&did_string, &identity);
        self.identities.insert(did_string, identity.clone());
        Ok(RegistrationResult {
            identity,
            fee_required,
        })
    }

    /// Registers a human identity from a client-produced [`WalletBinding`]
    /// (device-ceremony self-custody path). Mirror of
    /// [`Self::register_autonomous_machine_with_binding`] for the human class.
    ///
    /// The caller (node RPC) has already run a device ceremony — a passkey /
    /// WebAuthn enrollment plus, on TEE-equipped hardware, a sealed key
    /// derivation — and provisioned a watch-only [`Wallet`] whose address /
    /// classical pubkey / ML-DSA-65 vk come from device- or
    /// enclave-held material. No wallet is provisioned inside this method: the
    /// binder is not invoked and no server-side share reconstruction occurs.
    /// Signatures are minted by the client-bound signer against the same
    /// `wallet_id`.
    ///
    /// This is the self-custody option for humans. Runners without a device
    /// ceremony continue to use [`Self::register_human_via_binder`], which
    /// server-provisions the wallet — a permanent supported tier. Both paths
    /// coexist; the node selects per enrollment/hardware.
    pub async fn register_human_with_binding(
        &self,
        did: TenzroDid,
        display_name: String,
        binding: WalletBinding,
    ) -> Result<RegistrationResult> {
        // The DID must be the one the bound passkey derives; anything else
        // would let a caller attach a passkey to someone else's identity.
        if !did.matches_passkey(&binding.public_key) {
            return Err(IdentityError::PermissionDenied(
                "the DID does not derive from the bound passkey".to_string(),
            ));
        }
        let did_string = did.to_string();

        // Re-enrolling the same passkey keeps what the identity accumulated:
        // its keys, services, controlled machines,
        // metadata and creation time. Only the wallet binding is refreshed.
        // A different post-quantum key is refused: moving the identity's
        // post-quantum authority is a signed rotation, not an enrolment.
        let prior = self.identities.get(&did_string).map(|e| e.value().clone());
        if let Some(p) = prior.as_ref()
            && !p.pq_verifying_key.is_empty()
            && p.pq_verifying_key != binding.pq_verifying_key
        {
            return Err(IdentityError::PermissionDenied(
                "this identity already has a post-quantum key; replacing it needs a signed \
                 rotation, not a re-enrolment"
                    .to_string(),
            ));
        }
        let controlled_machines = match prior.as_ref().map(|p| &p.identity_data) {
            Some(IdentityData::Human {
                controlled_machines,
                ..
            }) => controlled_machines.clone(),
            _ => Vec::new(),
        };
        let public_keys = match prior.as_ref() {
            Some(p) => {
                let mut keys = p.public_keys.clone();
                for k in binding_public_keys(&binding) {
                    if !keys.iter().any(|e| e.key_id == k.key_id) {
                        keys.push(k);
                    }
                }
                keys
            }
            None => binding_public_keys(&binding),
        };
        let identity = TenzroIdentity {
            did,
            public_keys,
            identity_data: IdentityData::Human {
                display_name: display_name.clone(),
                controlled_machines,
            },
            status: IdentityStatus::Active,
            wallet_address: binding.address,
            wallet_id: binding.wallet_id,
            pq_verifying_key: binding.pq_verifying_key,
            created_at: prior
                .as_ref()
                .map(|p| p.created_at)
                .unwrap_or_else(Utc::now),
            updated_at: Utc::now(),
            metadata: prior
                .as_ref()
                .map(|p| p.metadata.clone())
                .unwrap_or_default(),
        };

        let fee_required = self.fee_schedule.human_identity_registration;

        info!(
            "Registered human identity (device-ceremony self-custody): {} (name: {}, fee: {} TNZO)",
            did_string,
            display_name,
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
    /// `did:tenzro:machine:<device-key-id>` convention); otherwise pass the human
    /// controller's DID.
    /// A **machine** identity is rooted in a secure element — TPM 2.0 on
    /// Linux/Windows, the Secure Enclave on Apple — so the device key is
    /// required. Machines do not use passkeys: there is no person present to
    /// satisfy an authenticator ceremony on a node.
    ///
    /// `machine_id` and `device_public_key` come from the hardware root; the
    /// private half cannot be exported from it. See
    /// `tenzro_wallet::WalletIdentity::machine` and `tenzro_secure_enclave`.
    pub async fn register_machine_via_binder(
        &self,
        controller_did: &str,
        machine_id: String,
        device_public_key: Vec<u8>,
        capabilities: Vec<String>,
    ) -> Result<RegistrationResult> {
        let is_autonomous = controller_did == "self";

        // Validate controller (skip for autonomous self-controlled machines,
        // which have none by definition — their DID is derived from the device
        // key below rather than from a controller).
        let controller_id = if is_autonomous {
            String::new()
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

        // An autonomous machine is identified by the secure element it cannot
        // export a key from, so the same hardware always lands on the same DID.
        // Registering twice updates one identity instead of minting a second.
        let did = if is_autonomous {
            TenzroDid::from_device_key(&device_public_key)?
        } else {
            TenzroDid::delegated_machine(&controller_id, &device_public_key)?
        };
        let did_string = did.to_string();

        let binder = self
            .wallet_binder
            .as_ref()
            .ok_or_else(|| IdentityError::WalletError("no wallet binder configured".to_string()))?;
        let identity =
            tenzro_wallet::WalletIdentity::machine(machine_id, wallet_key(&device_public_key)?)
                .map_err(|e| IdentityError::WalletError(e.to_string()))?;
        let binding = binder.provision_wallet(&did_string, identity).await?;

        let identity = TenzroIdentity {
            did,
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "P-256".to_string(),
                public_key: binding.public_key.clone(),
                purposes: vec![KeyPurpose::Authentication],
            }],
            identity_data: IdentityData::Machine {
                capabilities: capabilities.clone(),
                controller_did: if is_autonomous {
                    None
                } else {
                    Some(controller_did.to_string())
                },
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
            },
            status: IdentityStatus::Active,
            wallet_address: binding.address,
            wallet_id: binding.wallet_id,
            pq_verifying_key: binding.pq_verifying_key,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
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

    /// Registers an agent a human controller delegated with their passkey.
    ///
    /// The agent holds no key of its own: its DID derives from the
    /// controller's identity and the agent's name, so the same controller
    /// naming the same agent always lands on the same DID and nobody else
    /// can. Its wallet is watch-only: the address derives from the DID and
    /// no signing key exists for it. The caller has already verified the
    /// controller's approval of the terms.
    pub fn register_delegated_agent(
        &self,
        controller_did: &str,
        agent_name: &str,
        capabilities: Vec<String>,
        metadata: HashMap<String, String>,
    ) -> Result<TenzroIdentity> {
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
            // A root is a human (passkey) or an autonomous machine (its own
            // TPM or Secure Enclave key); a delegated machine roots nothing.
            if !(controller.is_human()
                || (controller.is_machine() && !controller.did.has_controller()))
            {
                return Err(IdentityError::PermissionDenied(
                    "controller must be a human or an autonomous machine identity".to_string(),
                ));
            }
            controller.did.id.clone()
        };
        let did = TenzroDid::delegated_agent(&controller_id, agent_name)?;
        let did_string = did.to_string();
        if self.identities.contains_key(&did_string) {
            return Err(IdentityError::AlreadyExists(did_string));
        }
        // The ledger's account for the agent: the one its escrows and payments debit.
        let wallet = tenzro_types::agent_terms::agent_wallet(&did_string);
        let now = Utc::now();
        let identity = TenzroIdentity {
            did,
            public_keys: Vec::new(),
            identity_data: IdentityData::Machine {
                capabilities,
                controller_did: Some(controller_did.to_string()),
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
            },
            status: IdentityStatus::Active,
            wallet_address: Address::new(wallet),
            wallet_id: format!("watch:{did_string}"),
            pq_verifying_key: Vec::new(),
            created_at: now,
            updated_at: now,
            metadata,
        };
        if let Some(mut controller) = self.identities.get_mut(controller_did)
            && let IdentityData::Human {
                ref mut controlled_machines,
                ..
            } = controller.identity_data
        {
            controlled_machines.push(did_string.clone());
            controller.updated_at = now;
            let snapshot = controller.clone();
            drop(controller);
            self.persist_identity(controller_did, &snapshot);
        }
        info!(
            "Registered delegated agent {} under {}",
            did_string, controller_did
        );
        self.persist_identity(&did_string, &identity);
        self.identities.insert(did_string, identity.clone());
        Ok(identity)
    }

    /// Replace a delegated agent's approved terms: its capabilities and the
    /// metadata that records them. The DID does
    /// not change. The caller has already verified the controller's
    /// approval of the new terms.
    pub fn update_delegated_agent(
        &self,
        did: &str,
        new_capabilities: Vec<String>,
        metadata: HashMap<String, String>,
    ) -> Result<TenzroIdentity> {
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
        match &mut identity.identity_data {
            IdentityData::Machine { capabilities, .. } => {
                *capabilities = new_capabilities;
            }
            _ => {
                return Err(IdentityError::PermissionDenied(
                    "terms can only be set on a delegated agent".to_string(),
                ));
            }
        }
        identity.metadata.extend(metadata);
        identity.updated_at = Utc::now();
        let snapshot = identity.clone();
        drop(identity);
        self.persist_identity(did, &snapshot);
        Ok(snapshot)
    }

    /// Registers a new machine identity under a human controller with fee information
    pub async fn prepare_machine(
        &self,
        controller_did: &str,
        public_key: Vec<u8>,
        capabilities: Vec<String>,
    ) -> Result<PendingRegistration> {
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

        let did = TenzroDid::delegated_machine(&controller_id, &public_key)?;
        let did_string = did.to_string();

        let (wallet_address, wallet_id, pq_verifying_key) = self
            .provision_or_default(
                &did_string,
                tenzro_wallet::WalletIdentity::machine(
                    did_string.clone(),
                    wallet_key(&public_key)?,
                )
                .map_err(|e| IdentityError::WalletError(e.to_string()))?,
            )
            .await?;

        let identity = TenzroIdentity {
            did,
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "P-256".to_string(),
                public_key,
                purposes: vec![KeyPurpose::Authentication],
            }],
            identity_data: IdentityData::Machine {
                capabilities: capabilities.clone(),
                controller_did: Some(controller_did.to_string()),
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
            },
            status: IdentityStatus::Active,
            wallet_address,
            wallet_id,
            pq_verifying_key,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
        };

        let fee_required = self.fee_schedule.machine_identity_registration;

        info!(
            "Registered machine identity: {} under controller: {} with capabilities: {:?}, fee: {} TNZO",
            did_string,
            controller_did,
            capabilities,
            fee_required / 1_000_000_000_000_000_000
        );

        Ok(PendingRegistration {
            identity,
            fee_required,
            controller_did: Some(controller_did.to_string()),
            mirror: true,
        })
    }

    /// [`Self::prepare_machine`], written at once with [`Self::admit`].
    pub async fn register_machine_with_fee(
        &self,
        controller_did: &str,
        public_key: Vec<u8>,
        capabilities: Vec<String>,
    ) -> Result<RegistrationResult> {
        let pending = self
            .prepare_machine(controller_did, public_key, capabilities)
            .await?;
        Ok(self.admit(pending))
    }

    /// Registers an agent as a machine delegated by the host machine that runs
    /// it.
    ///
    /// The agent's DID is derived from the host's identifier and the agent's
    /// own public key ([`TenzroDid::delegated_machine`]), so every agent on a
    /// host has its own identity, the same agent re-registering keeps its
    /// DID, and no agent can land on another's record. The host must be an
    /// active machine identity: it is the party that answers for the agent.
    pub async fn register_agent_machine_with_fee(
        &self,
        host_did: &str,
        agent_public_key: Vec<u8>,
        capabilities: Vec<String>,
    ) -> Result<RegistrationResult> {
        let did = self.agent_did(host_did, &agent_public_key)?;
        let did_string = did.to_string();
        let (wallet_address, wallet_id, pq_verifying_key) = self
            .provision_or_default(
                &did_string,
                tenzro_wallet::WalletIdentity::machine(
                    did_string.clone(),
                    wallet_key(&agent_public_key)?,
                )
                .map_err(|e| IdentityError::WalletError(e.to_string()))?,
            )
            .await?;
        self.insert_agent_machine(
            host_did,
            did,
            agent_public_key,
            wallet_address,
            wallet_id,
            pq_verifying_key,
            capabilities,
        )
    }

    /// [`Self::register_agent_machine_with_fee`] for an agent that holds its
    /// own keys: nothing is provisioned on the node, and the wallet address is
    /// `SHA-256(agent_public_key)` so the agent can reproduce it.
    pub async fn register_agent_machine_with_keys(
        &self,
        host_did: &str,
        agent_public_key: Vec<u8>,
        pq_verifying_key: Vec<u8>,
        capabilities: Vec<String>,
    ) -> Result<RegistrationResult> {
        let did = self.agent_did(host_did, &agent_public_key)?;
        let hash = tenzro_crypto::sha256(&agent_public_key);
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(hash.as_bytes());
        let wallet_id = format!("byok-{}", hex::encode(&hash.as_bytes()[..6]));
        self.insert_agent_machine(
            host_did,
            did,
            agent_public_key,
            Address::new(addr_bytes),
            wallet_id,
            pq_verifying_key,
            capabilities,
        )
    }

    /// The DID an agent with `agent_public_key` gets under `host_did`, after
    /// checking the host is an active machine and the DID is not already
    /// held by another key.
    fn agent_did(&self, host_did: &str, agent_public_key: &[u8]) -> Result<TenzroDid> {
        let host_id = {
            let host = self
                .identities
                .get(host_did)
                .ok_or_else(|| IdentityError::NotFound(host_did.to_string()))?;
            if host.status != IdentityStatus::Active {
                return Err(IdentityError::NotActive(format!(
                    "host {host_did} is {:?}",
                    host.status
                )));
            }
            if !host.is_machine() {
                return Err(IdentityError::PermissionDenied(
                    "an agent's host must be a machine identity".to_string(),
                ));
            }
            host.did.id.clone()
        };
        let did = TenzroDid::delegated_machine(&host_id, agent_public_key)?;
        if let Some(existing) = self.identities.get(&did.to_string())
            && existing
                .public_keys
                .first()
                .map(|k| k.public_key.as_slice())
                != Some(agent_public_key)
        {
            return Err(IdentityError::AlreadyExists(did.to_string()));
        }
        Ok(did)
    }

    fn insert_agent_machine(
        &self,
        host_did: &str,
        did: TenzroDid,
        agent_public_key: Vec<u8>,
        wallet_address: Address,
        wallet_id: String,
        pq_verifying_key: Vec<u8>,
        capabilities: Vec<String>,
    ) -> Result<RegistrationResult> {
        let did_string = did.to_string();
        let identity = TenzroIdentity {
            did,
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "P-256".to_string(),
                public_key: agent_public_key,
                purposes: vec![KeyPurpose::Authentication],
            }],
            identity_data: IdentityData::Machine {
                capabilities,
                controller_did: Some(host_did.to_string()),
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
            },
            status: IdentityStatus::Active,
            wallet_address,
            wallet_id,
            pq_verifying_key,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
        };
        let fee_required = self.fee_schedule.machine_identity_registration;
        info!(
            "Registered agent machine identity {} under host {}",
            did_string, host_did
        );
        self.mirror_to_erc8004(&did_string, &identity);
        self.persist_identity(&did_string, &identity);
        self.identities.insert(did_string, identity.clone());
        Ok(RegistrationResult {
            identity,
            fee_required,
        })
    }

    /// Registers an autonomous machine identity from a pre-provisioned
    /// watch-only wallet binding: the machine's own keys, admitted by the node
    /// after TPM attestation or bound by derivation from its own key.
    ///
    /// No wallet is provisioned here and no key material is held. `metadata`
    /// carries the evidence the admitting node verified, so any relying party
    /// can re-run the checks.
    ///
    /// Refused unless the binding holds ([`Self::binding_holds`]), and refused
    /// if the DID is already held by a different key: a machine cannot be
    /// re-registered over another's identity.
    pub async fn prepare_autonomous_machine_with_binding(
        &self,
        did: TenzroDid,
        binding: WalletBinding,
        capabilities: Vec<String>,
        metadata: HashMap<String, String>,
    ) -> Result<PendingRegistration> {
        let did_string = did.to_string();
        let prior = self.identities.get(&did_string).map(|e| e.value().clone());
        if let Some(existing) = prior.as_ref() {
            // Registering the same key again refreshes the machine's
            // capabilities and evidence; it never revives a revoked machine
            // or moves its wallet or post-quantum key, and it keeps what the
            // identity accumulated.
            if existing.public_keys.first().map(|k| &k.public_key) != Some(&binding.public_key) {
                return Err(IdentityError::AlreadyExists(did_string));
            }
            if existing.status == IdentityStatus::Revoked {
                return Err(IdentityError::PermissionDenied(
                    "a revoked machine is not registered again".to_string(),
                ));
            }
            if existing.wallet_address != binding.address
                || existing.pq_verifying_key != binding.pq_verifying_key
            {
                return Err(IdentityError::PermissionDenied(
                    "registering a machine again does not change its wallet or post-quantum key"
                        .to_string(),
                ));
            }
            let mut identity = existing.clone();
            if let IdentityData::Machine {
                capabilities: held, ..
            } = &mut identity.identity_data
            {
                *held = capabilities;
            }
            identity.metadata.extend(metadata);
            identity.updated_at = Utc::now();
            if !self.binding_holds(&identity) {
                return Err(IdentityError::PermissionDenied(
                    "the DID neither derives from the bound key nor carries TPM evidence rooting it"
                        .to_string(),
                ));
            }
            return Ok(PendingRegistration {
                identity,
                fee_required: 0,
                controller_did: None,
                mirror: false,
            });
        }

        let identity = TenzroIdentity {
            did,
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "P-256".to_string(),
                public_key: binding.public_key.clone(),
                purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod],
            }],
            identity_data: IdentityData::Machine {
                capabilities: capabilities.clone(),
                controller_did: None,
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
            },
            status: IdentityStatus::Active,
            wallet_address: binding.address,
            wallet_id: binding.wallet_id,
            pq_verifying_key: binding.pq_verifying_key,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata,
        };
        if !self.binding_holds(&identity) {
            return Err(IdentityError::PermissionDenied(
                "the DID neither derives from the bound key nor carries TPM evidence rooting it"
                    .to_string(),
            ));
        }

        let fee_required = self.fee_schedule.machine_identity_registration;

        info!(
            "Registered autonomous machine identity: {} with capabilities: {:?}, fee: {} TNZO",
            did_string,
            capabilities,
            fee_required / 1_000_000_000_000_000_000
        );

        Ok(PendingRegistration {
            identity,
            fee_required,
            controller_did: None,
            mirror: true,
        })
    }

    /// [`Self::prepare_autonomous_machine_with_binding`], written at once with
    /// [`Self::admit`].
    pub async fn register_autonomous_machine_with_binding(
        &self,
        did: TenzroDid,
        binding: WalletBinding,
        capabilities: Vec<String>,
        metadata: HashMap<String, String>,
    ) -> Result<RegistrationResult> {
        let pending = self
            .prepare_autonomous_machine_with_binding(did, binding, capabilities, metadata)
            .await?;
        Ok(self.admit(pending))
    }

    /// Writes a prepared registration: the identity record, a machine in its
    /// controller's list, and the ERC-8004 mirror of a new machine.
    pub fn admit(&self, pending: PendingRegistration) -> RegistrationResult {
        let PendingRegistration {
            identity,
            fee_required,
            controller_did,
            mirror,
        } = pending;
        let did_string = identity.did_string();
        if let Some(controller_did) = controller_did
            && let Some(mut controller) = self.identities.get_mut(&controller_did)
        {
            if let IdentityData::Human {
                ref mut controlled_machines,
                ..
            } = controller.identity_data
            {
                controlled_machines.push(did_string.clone());
            }
            self.persist_identity(&controller_did, &controller);
        }
        if mirror {
            // Dispatch the ERC-8004 mirror as a detached signed-tx submission.
            // The allocated `agentId` is NOT available synchronously — the
            // off-chain `Registered(uint256,string,address)` event listener in
            // `tenzro-node` patches `IdentityData::Machine.erc8004_agent_id` on
            // the cached TDIP record once the mirror tx is included.
            self.mirror_to_erc8004(&did_string, &identity);
        }
        self.persist_identity(&did_string, &identity);
        self.identities.insert(did_string, identity.clone());
        RegistrationResult {
            identity,
            fee_required,
        }
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
        // The bound wallet's EVM address: the same ledger account, named by
        // its first 20 bytes. A wallet with no EVM form is not mirrored.
        let Some(agent_address) = identity.wallet_address.evm_address() else {
            tracing::warn!(
                "ERC-8004 mirror skipped for {}: its wallet has no EVM address",
                did_string
            );
            return;
        };
        // Metadata URI = the canonical DID URL. Future: route through a
        // gateway that resolves to the W3C DID document JSON.
        let metadata_uri = format!("did:{}", did_string.trim_start_matches("did:"));
        if let Err(e) = registry.mirror_register_agent(did_string, &agent_address, &metadata_uri) {
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
    }

    /// Resolves a DID to its identity.
    ///
    /// The registry is the replicated read model of the identities consensus
    /// holds, so a DID it does not hold is not registered: there is no
    /// second source to ask. Lookup is by the supplied string, then by its
    /// canonical form.
    pub fn resolve(&self, did: &str) -> Result<TenzroIdentity> {
        // Try direct lookup first
        if let Some(identity) = self.identities.get(did) {
            return Ok(identity.clone());
        }

        // Try parsing and canonicalizing the DID
        let canonical = match TenzroDid::parse(did) {
            Ok(parsed) => parsed.to_string_canonical(),
            Err(_) => did.to_string(),
        };

        if let Some(id) = self.identities.get(&canonical) {
            return Ok(id.clone());
        }

        Err(IdentityError::NotFound(did.to_string()))
    }

    /// Resolves a DID to its bound wallet id, for signing with the wallet
    /// service. Which address a DID owns is consensus state (its registered
    /// identity record); this is only the local handle to the wallet.
    ///
    /// Returns the same errors as `resolve` (`NotFound` if the DID is
    /// unknown locally and not resolvable via the configured remote
    /// backend).
    pub fn find_wallet_id_for_did(&self, did: &str) -> Result<String> {
        Ok(self.resolve(did)?.wallet_id)
    }

    /// Reverse-lookup: find the local DID whose identity-bound wallet
    /// is `wallet_id`.
    ///
    /// The inverse of [`Self::find_wallet_id_for_did`]. Records that key on a
    /// wallet rather than a DID — a custody session, a spending limit — need
    /// this to answer "who owns this wallet?" before authorizing a mutation
    /// against it. Without it such a record has no owner to check, and the
    /// caller-supplied `wallet_id` ends up being both the subject and the
    /// whole of the authorization.
    ///
    /// Linear scan, with the same caveat as [`Self::find_did_by_address`]:
    /// fine at testnet sizes, wants a maintained reverse index past ~10⁵
    /// identities.
    pub fn find_did_by_wallet_id(&self, wallet_id: &str) -> Option<String> {
        self.identities
            .iter()
            .find(|entry| entry.value().wallet_id == wallet_id)
            .map(|entry| entry.key().clone())
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

    /// Resolve the principal chain for a DID.
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
    ///   `with_bond_lookup`. Without one, all bond fields are
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
        // AgentBond lookup helper — resolves actor_bond + controller_bond
        // (singular, on the controller's own DID) + controller aggregate.
        let actor_bond = self.bond_lookup.as_ref().and_then(|b| b.actor_bond(did));

        // Resolve the actor itself; if unresolvable, return a synthetic
        // tombstoned chain rooted at the supplied DID.
        let actor = match self.resolve(did) {
            Ok(id) => id,
            Err(_) => {
                let mut chain = PrincipalChain::direct(
                    did.to_string(),
                    TenzroIdentityType::Machine,
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
            let controller_aggregate = self
                .bond_lookup
                .as_ref()
                .and_then(|b| b.controller_aggregate(&actor_did));
            return PrincipalChain::direct(actor_did, actor_type, actor_bond, frozen_at_block)
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
                    current_controller_did = parent.controller_did().map(|s| s.to_string());
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

        // snapshot the controller's bond on its own DID and the
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

        PrincipalChain::from_chain(actor_did, chain_top_down, controller_bond, frozen_at_block)
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

    /// Apply a revocation the chain decided, mirroring an `IdentityRevoked`
    /// consensus log into the local read model.
    ///
    /// The counterpart to [`Self::upsert_from_chain`], and it exists for the
    /// same reason: a decision reached in consensus has to reach the map the
    /// resolve path reads, or the network will have revoked an identity that
    /// every node still answers questions about.
    ///
    /// Every revocation is decided in consensus: a carried governance
    /// proposal, or a `RevokeIdentity` transaction whose root approval every
    /// validator verified against keys in chain state. Every node observed the
    /// same log, so there is nothing to verify or broadcast here.
    ///
    /// Idempotent: a DID already recorded as revoked returns `Ok(false)`, so
    /// re-org and restart replays are safe. Cascades to the controlled machines
    /// this registry records — a sanction that left them running would not be
    /// one.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::NotFound`] if the DID is unknown locally. That
    /// is a real divergence — consensus revoked something this node never
    /// mirrored — and the caller logs it rather than aborting the block, since
    /// `load_from_storage` reconciles the read model on restart.
    pub fn revoke_from_chain(&self, did: &str, reason: String, revoked_by: String) -> Result<bool> {
        if self.revocations.contains_key(did) {
            return Ok(false);
        }

        let machine_dids: Vec<String>;
        {
            let mut identity = self
                .identities
                .get_mut(did)
                .ok_or_else(|| IdentityError::NotFound(did.to_string()))?;

            warn!(
                "Revoking identity by consensus: {} (reason: {})",
                did, reason
            );
            identity.status = IdentityStatus::Revoked;
            identity.updated_at = Utc::now();

            machine_dids = match &identity.identity_data {
                IdentityData::Human {
                    controlled_machines,
                    ..
                } => controlled_machines.clone(),
                IdentityData::Institution {
                    controlled_machines,
                    ..
                } => controlled_machines.clone(),
                IdentityData::Machine { .. } => Vec::new(),
            };

            self.persist_identity(did, &identity);
        }

        for machine_did in &machine_dids {
            if let Some(mut machine) = self.identities.get_mut(machine_did) {
                machine.status = IdentityStatus::Revoked;
                machine.updated_at = Utc::now();
                self.persist_identity(machine_did, &machine);
                let entry = RevocationEntry {
                    did: machine_did.clone(),
                    revoked_at: Utc::now(),
                    reason: format!("cascaded from {}", did),
                    revoked_by: revoked_by.clone(),
                };
                self.revocations.insert(entry.did.clone(), entry.clone());
                self.persist_revocation(&entry);
            }
        }

        let entry = RevocationEntry {
            did: did.to_string(),
            revoked_at: Utc::now(),
            reason,
            revoked_by,
        };
        self.revocations.insert(did.to_string(), entry.clone());
        self.persist_revocation(&entry);
        Ok(true)
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

    /// Record a machine's new controlling identity after an authorised
    /// [`crate::identity::OwnershipTransfer`].
    ///
    /// Deliberately *not* a general setter: it is called only after
    /// `OwnershipTransfer::authorize` has checked the transfer against the
    /// machine's current anchor. Exposing it as an unguarded "set the
    /// controller" would let a caller skip the authority check that makes
    /// ownership mean anything.
    ///
    /// The old controller's `controlled_machines` entry is dropped and the new
    /// one gains it in the same call, so ownership replaces rather than
    /// accumulating — a machine listed under two owners would let both issue
    /// credentials on it.
    pub fn set_machine_controller(&self, machine_did: &str, new_controller: &str) -> Result<()> {
        if new_controller.trim().is_empty() {
            return Err(IdentityError::PermissionDenied(
                "a machine must be transferred to a real identity".to_string(),
            ));
        }

        let previous = {
            let mut identity = self
                .identities
                .get_mut(machine_did)
                .ok_or_else(|| IdentityError::NotFound(machine_did.to_string()))?;
            match &mut identity.identity_data {
                IdentityData::Machine { controller_did, .. } => {
                    let previous = controller_did.clone();
                    *controller_did = Some(new_controller.to_string());
                    identity.updated_at = Utc::now();
                    self.persist_identity(machine_did, &identity);
                    previous
                }
                _ => {
                    return Err(IdentityError::PermissionDenied(
                        "only a machine identity has a controller to transfer".to_string(),
                    ));
                }
            }
        };

        // Detach from the previous owner, if there was one.
        if let Some(prev) = previous.as_deref()
            && prev != new_controller
            && let Some(mut old) = self.identities.get_mut(prev)
        {
            let changed = match &mut old.identity_data {
                IdentityData::Human {
                    controlled_machines,
                    ..
                }
                | IdentityData::Institution {
                    controlled_machines,
                    ..
                } => {
                    let before = controlled_machines.len();
                    controlled_machines.retain(|m| m != machine_did);
                    before != controlled_machines.len()
                }
                _ => false,
            };
            if changed {
                old.updated_at = Utc::now();
                self.persist_identity(prev, &old);
            }
        }

        // Attach to the new owner.
        if let Some(mut owner) = self.identities.get_mut(new_controller) {
            let changed = match &mut owner.identity_data {
                IdentityData::Human {
                    controlled_machines,
                    ..
                }
                | IdentityData::Institution {
                    controlled_machines,
                    ..
                } => {
                    if controlled_machines.iter().any(|m| m == machine_did) {
                        false
                    } else {
                        controlled_machines.push(machine_did.to_string());
                        true
                    }
                }
                _ => false,
            };
            if changed {
                owner.updated_at = Utc::now();
                self.persist_identity(new_controller, &owner);
            }
        }

        info!(
            "Machine {} ownership transferred from {:?} to {}",
            machine_did, previous, new_controller
        );
        Ok(())
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
            IdentityData::Institution {
                controlled_machines,
                ..
            } => controlled_machines.clone(),
            _ => {
                return Err(IdentityError::PermissionDenied(
                    "only human / institution identities have controlled machines".to_string(),
                ));
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
                // Institutions are counted via `institution_count` so the
                // (humans, machines) tuple stays compatible with existing
                // callers.
                IdentityData::Institution { .. } => {}
            }
        }
        (humans, machines)
    }

    /// Returns the total number of registered identities
    pub fn total_count(&self) -> usize {
        self.identities.len()
    }

    /// Returns the count of registered institution identities.
    pub fn institution_count(&self) -> usize {
        self.identities
            .iter()
            .filter(|entry| {
                matches!(
                    entry.value().identity_data,
                    IdentityData::Institution { .. }
                )
            })
            .count()
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

    /// Test-only helper that overwrites (or installs) an identity record by DID.
    ///
    /// This is used by trust-chain-traversal tests to patch
    /// identities after `register_*()` so the test can install real
    /// `AssertionMethod` public keys matching the Ed25519 keypairs the test
    /// signs with. Production code must not call this — use the typed
    /// `register_*` / `update_*` methods instead.
    #[doc(hidden)]
    pub fn upsert_identity_for_test(&self, identity: TenzroIdentity) {
        let key = identity.did.to_string();
        self.persist_identity(&key, &identity);
        self.identities.insert(key, identity);
    }

    /// Record the ML-DSA-65 verifying key a human enrolled with their
    /// passkey, after the caller checked they hold it. Recording the same key
    /// again is a no-op; a different key is refused, since moving the
    /// identity's post-quantum authority is a signed rotation.
    pub fn record_pq_verifying_key(
        &self,
        did: &str,
        key: &[u8],
    ) -> crate::error::Result<TenzroIdentity> {
        let mut entry = self
            .identities
            .get_mut(did)
            .ok_or_else(|| crate::error::IdentityError::NotFound(did.to_string()))?;
        if !entry.pq_verifying_key.is_empty() && entry.pq_verifying_key != key {
            return Err(crate::error::IdentityError::PermissionDenied(
                "this identity already has a post-quantum key; replacing it needs a signed \
                 rotation, not a re-enrolment"
                    .to_string(),
            ));
        }
        entry.pq_verifying_key = key.to_vec();
        entry.updated_at = Utc::now();
        self.persist_identity(did, entry.value());
        Ok(entry.value().clone())
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

    /// Mirror a `RegisterIdentity` record decoded from an `IdentityRegister`
    /// consensus log into the local read model.
    ///
    /// This is what makes an identity created on ANY node resolve on ALL
    /// nodes: the VM already enforced DID uniqueness against consensus state
    /// and every node re-executed the same ordered transaction, so here we
    /// only reflect that decision into the DID→identity map + RocksDB
    /// (`CF_IDENTITIES`) that `resolve` reads from.
    ///
    /// Idempotent and origin-safe: if the DID already exists locally we leave
    /// it untouched — the origin node holds the authoritative, richer record
    /// (credentials, services, full wallet metadata), and re-org / restart
    /// replays must not clobber it with the leaner wire projection. Returns
    /// `Ok(true)` when a new record was landed, `Ok(false)` when the DID was
    /// already known.
    ///
    /// Fail-closed on malformed keys: the identity's ML-DSA-65 verifying key
    /// must be present and exactly 1952 bytes. Consensus refuses to register an
    /// identity whose hardware holds none, so a record without one is not
    /// landed, and a short or long key would fail to hydrate from its own
    /// canonical bytes on restart.
    pub fn upsert_from_chain(
        &self,
        payload: &tenzro_types::identity::RegisterIdentityPayload,
    ) -> Result<bool> {
        use crate::identity::ML_DSA_65_VERIFYING_KEY_LEN;

        if self.identities.contains_key(&payload.did) {
            return Ok(false);
        }

        if payload.pq_verifying_key.len() != ML_DSA_65_VERIFYING_KEY_LEN {
            return Err(IdentityError::InvalidPublicKey(format!(
                "replicated identity {} has malformed ML-DSA-65 verifying key ({} bytes)",
                payload.did,
                payload.pq_verifying_key.len()
            )));
        }

        let did = TenzroDid::parse(&payload.did)
            .map_err(|e| IdentityError::InvalidDid(format!("{}: {e}", payload.did)))?;

        let identity_data = match payload.identity_type.as_str() {
            "human" => IdentityData::Human {
                display_name: payload.display_name.clone(),
                controlled_machines: Vec::new(),
            },
            "institution" => IdentityData::Institution {
                legal_name: payload.display_name.clone(),
                lei: String::new(),
                vlei_credential_id: None,
                controlled_machines: Vec::new(),
                country_iso2: None,
            },
            "machine" => IdentityData::Machine {
                capabilities: Vec::new(),
                controller_did: None,
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
            },
            other => {
                return Err(IdentityError::InvalidDid(format!(
                    "replicated identity {} has unknown identity_type '{other}'",
                    payload.did
                )));
            }
        };

        let identity = TenzroIdentity {
            did,
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: payload.key_type.clone(),
                public_key: payload.controller_pubkey.clone(),
                purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod],
            }],
            identity_data,
            status: IdentityStatus::Active,
            wallet_address: payload.wallet_address,
            wallet_id: payload.wallet_id.clone(),
            pq_verifying_key: payload.pq_verifying_key.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: payload
                .metadata
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };

        if !self.binding_holds(&identity) {
            return Err(IdentityError::PermissionDenied(format!(
                "replicated identity {} does not derive from its controller key",
                payload.did
            )));
        }

        self.persist_identity(&payload.did, &identity);
        self.identities.insert(payload.did.clone(), identity);
        info!(did = %payload.did, "Mirrored replicated identity from consensus");
        Ok(true)
    }

    /// Provisions a wallet or returns default values if no binder is configured.
    ///
    /// Returns `(address, wallet_id, pq_verifying_key_bytes)`. Under the hybrid
    /// migration, every identity carries a mandatory ML-DSA-65 verifying key.
    /// When a `WalletBinder` is configured, the key comes from the wallet's
    /// keystore; otherwise we generate an ephemeral one so the identity still
    /// satisfies the structural invariant (test/no-binder paths only).
    /// Provision this identity a wallet, or refuse to register it.
    ///
    /// This used to fall back, with no binder configured, to a "deterministic
    /// placeholder address" hashed from the DID, paired with freshly generated
    /// PQ keys that were then dropped. The registry documents that
    /// fallback as "useful for tests but never correct for a live node", and
    /// the node only wires a binder `if let Some(wallet_service)` — so a node
    /// that came up without one logged a warning and then handed every identity
    /// a wallet address no key in existence can sign for. Anything paid to one
    /// is unrecoverable, and it looks like a perfectly ordinary account until
    /// someone tries to spend from it.
    ///
    /// Refusing is the honest failure. A registration that cannot produce a
    /// signable wallet has not succeeded, and reporting that lets an operator
    /// fix the wiring instead of discovering it through lost funds.
    async fn provision_or_default(
        &self,
        did: &str,
        identity: tenzro_wallet::WalletIdentity,
    ) -> Result<(Address, String, Vec<u8>)> {
        let Some(ref binder) = self.wallet_binder else {
            return Err(IdentityError::WalletError(format!(
                "cannot register {did}: no wallet binder is configured, so this registry \
                 cannot provision a signable wallet. Refusing rather than assigning a \
                 placeholder address no key can sign for."
            )));
        };
        let binding = binder.provision_wallet(did, identity).await?;
        Ok((binding.address, binding.wallet_id, binding.pq_verifying_key))
    }
}

/// Project a [`TenzroIdentity`] onto the public
/// [`tenzro_types::identity::IdentityType`] enum used by principal chains.
fn identity_type_of(identity: &TenzroIdentity) -> TenzroIdentityType {
    match identity.identity_data {
        IdentityData::Human { .. } => TenzroIdentityType::Human,
        IdentityData::Machine { .. } => TenzroIdentityType::Machine,
        IdentityData::Institution { .. } => TenzroIdentityType::Institution,
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
        use tenzro_crypto::HybridSigner;
        tenzro_crypto::composite::testing::TestHybridSigner::p256_only(seed)
            .public_key()
            .p256
            .clone()
    }

    #[tokio::test]
    async fn test_register_human() {
        let registry = IdentityRegistry::new();
        let identity = registry
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Alice".to_string(),
            )
            .await
            .unwrap()
            .identity;

        assert!(identity.is_human());
        assert!(identity.is_active());
        assert_eq!(identity.display_name(), "Alice");
        assert_eq!(registry.total_count(), 1);
    }

    /// The wallet a delegated agent is registered with is the ledger account
    /// its escrows and payments debit, so what a person funds the agent can spend.
    #[tokio::test]
    async fn a_delegated_agent_wallet_is_its_ledger_account() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_via_binder(b"cred".to_vec(), test_pubkey(1), "Alice".to_string())
            .await
            .unwrap()
            .identity;
        let agent = registry
            .register_delegated_agent(&human.did_string(), "buyer-1", vec![], HashMap::new())
            .unwrap();
        assert_eq!(
            agent.wallet_address.as_bytes(),
            &tenzro_types::agent_terms::agent_wallet(&agent.did_string())
        );
    }

    #[tokio::test]
    async fn test_register_machine_under_human() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Alice".to_string(),
            )
            .await
            .unwrap()
            .identity;

        let machine = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(2),
                vec!["inference".to_string()],
            )
            .await
            .unwrap()
            .identity;

        assert!(machine.is_machine());
        assert!(machine.is_active());
        assert_eq!(machine.controller_did(), Some(human.did_string().as_str()));
        assert_eq!(registry.total_count(), 2);

        // Verify controller's machine list was updated
        let machines = registry
            .get_controlled_machines(&human.did_string())
            .unwrap();
        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0].did_string(), machine.did_string());
    }

    /// An autonomous machine whose DID derives from its own bound key.
    async fn test_autonomous(registry: &IdentityRegistry, key: u8) -> Result<TenzroIdentity> {
        registry
            .register_autonomous_machine_with_binding(
                TenzroDid::from_device_key(&test_pubkey(key))?,
                test_binding(key),
                vec!["monitoring".to_string()],
                HashMap::new(),
            )
            .await
            .map(|r| r.identity)
    }

    fn test_binding(key: u8) -> WalletBinding {
        WalletBinding {
            wallet_id: format!("wallet-{key}"),
            address: Address::new([key; 32]),
            public_key: test_pubkey(key),
            pq_verifying_key: vec![key; crate::identity::ML_DSA_65_VERIFYING_KEY_LEN],
        }
    }

    #[tokio::test]
    async fn test_register_autonomous_machine() {
        let registry = IdentityRegistry::new();
        let machine = test_autonomous(&registry, 1).await.unwrap();
        assert!(machine.is_machine());
        assert!(machine.controller_did().is_none());
        assert!(registry.binding_holds(&machine));
    }

    /// A DID that neither derives from the bound key nor carries evidence is
    /// refused, and so is one whose evidence the verifier rejects.
    #[tokio::test]
    async fn autonomous_registration_requires_a_binding() {
        let registry = IdentityRegistry::new();
        let err = registry
            .register_autonomous_machine_with_binding(
                TenzroDid::from_device_key(&test_pubkey(2)).unwrap(),
                test_binding(1),
                vec![],
                HashMap::new(),
            )
            .await;
        assert!(
            err.is_err(),
            "the DID of another key must not bind this one"
        );

        let refusing = IdentityRegistry::new().with_evidence_verifier(Arc::new(|_| false));
        let err = refusing
            .register_autonomous_machine_with_binding(
                TenzroDid::from_device_key(&[0xEE; 65]).unwrap(),
                test_binding(1),
                vec![],
                HashMap::from([("tpm_attestation".to_string(), "{}".to_string())]),
            )
            .await;
        assert!(err.is_err(), "rejected evidence must not bind");

        let accepting = IdentityRegistry::new().with_evidence_verifier(Arc::new(|_| true));
        assert!(
            accepting
                .register_autonomous_machine_with_binding(
                    TenzroDid::from_device_key(&[0xEE; 65]).unwrap(),
                    test_binding(1),
                    vec![],
                    HashMap::new(),
                )
                .await
                .is_ok(),
            "evidence the verifier accepts binds the attestation-key DID"
        );
    }

    /// Another key cannot take over a machine's DID by re-registering it.
    #[tokio::test]
    async fn a_machine_cannot_be_re_registered_over_by_another_key() {
        let registry = IdentityRegistry::new().with_evidence_verifier(Arc::new(|_| true));
        let did = TenzroDid::from_device_key(&[0xEE; 65]).unwrap();
        let first = registry
            .register_autonomous_machine_with_binding(
                did.clone(),
                test_binding(1),
                vec![],
                HashMap::new(),
            )
            .await
            .unwrap()
            .identity;
        assert!(matches!(
            registry
                .register_autonomous_machine_with_binding(
                    did.clone(),
                    test_binding(2),
                    vec![],
                    HashMap::new()
                )
                .await,
            Err(IdentityError::AlreadyExists(_))
        ));
        assert_eq!(
            registry.resolve(&first.did_string()).unwrap().public_keys[0].public_key,
            test_pubkey(1)
        );
        assert!(
            registry
                .register_autonomous_machine_with_binding(
                    did,
                    test_binding(1),
                    vec![],
                    HashMap::new()
                )
                .await
                .is_ok(),
            "the same key may refresh"
        );
    }

    /// Registering a machine's key again neither revives a revoked machine
    /// nor replaces its wallet, post-quantum key or what it accumulated.
    #[tokio::test]
    async fn re_registering_a_machine_keeps_its_state_and_revocation() {
        let registry = IdentityRegistry::new();
        let machine = test_autonomous(&registry, 1).await.unwrap();
        let did = machine.did_string();
        if let Some(mut entry) = registry.identities.get_mut(&did)
            && let IdentityData::Machine { reputation, .. } = &mut entry.identity_data
        {
            *reputation = 42;
        }
        let mut other_wallet = test_binding(1);
        other_wallet.address = Address::new([9; 32]);
        let reregister = |binding: WalletBinding| {
            registry.register_autonomous_machine_with_binding(
                TenzroDid::from_device_key(&test_pubkey(1)).unwrap(),
                binding,
                vec!["monitoring".to_string()],
                HashMap::new(),
            )
        };
        assert!(reregister(other_wallet).await.is_err(), "another wallet");
        let mut other_pq = test_binding(1);
        other_pq.pq_verifying_key = vec![9; crate::identity::ML_DSA_65_VERIFYING_KEY_LEN];
        assert!(
            reregister(other_pq).await.is_err(),
            "another post-quantum key"
        );
        let again = reregister(test_binding(1)).await.unwrap().identity;
        assert!(matches!(
            again.identity_data,
            IdentityData::Machine { reputation: 42, .. }
        ));

        registry
            .revoke_from_chain(&did, "compromised".into(), "owner".into())
            .unwrap();
        assert!(reregister(test_binding(1)).await.is_err(), "revoked");
        assert_eq!(
            registry.resolve(&did).unwrap().status,
            IdentityStatus::Revoked
        );
    }

    /// Re-enrolling a passkey keeps the identity's KYC tier and keys, and a
    /// re-enrolment carrying a different post-quantum key is refused.
    #[tokio::test]
    async fn re_enrolment_keeps_what_the_identity_accumulated() {
        use crate::pq_rotation::tests::root;
        let registry = IdentityRegistry::new();
        let (_, raw) = root(8);
        let did = TenzroDid::from_passkey(&raw);
        let binding = |pq: u8| WalletBinding {
            wallet_id: "w".to_string(),
            address: Address::new([8; 32]),
            public_key: raw.clone(),
            pq_verifying_key: vec![pq; crate::identity::ML_DSA_65_VERIFYING_KEY_LEN],
        };
        registry
            .register_human_with_binding(did.clone(), "a".into(), binding(1))
            .await
            .unwrap();
        if let Some(mut entry) = registry.identities.get_mut(&did.to_string()) {
            entry.metadata.insert("accumulated".into(), "kept".into());
        }
        let again = registry
            .register_human_with_binding(did.clone(), "a".into(), binding(1))
            .await
            .unwrap()
            .identity;
        assert_eq!(
            again.metadata.get("accumulated").map(String::as_str),
            Some("kept")
        );
        assert!(
            registry
                .register_human_with_binding(did, "a".into(), binding(2))
                .await
                .is_err(),
            "a different post-quantum key must not replace the enrolled one"
        );
    }

    /// A human's identity moves to an ML-DSA key through the registry and
    /// keeps its DID; afterwards the passkey alone cannot rotate it again.
    #[tokio::test]
    async fn a_pq_rotation_keeps_the_did_and_takes_authority_from_the_passkey() {
        use crate::pq_rotation::tests::{pq, root, rotation_by_root};
        let registry = IdentityRegistry::new();
        let (passkey, raw) = root(7);
        let did = TenzroDid::from_passkey(&raw);
        let binding = WalletBinding {
            wallet_id: "w".to_string(),
            address: Address::new([7; 32]),
            public_key: raw.clone(),
            pq_verifying_key: vec![1; crate::identity::ML_DSA_65_VERIFYING_KEY_LEN],
        };
        registry
            .register_human_with_binding(did.clone(), "alice".into(), binding)
            .await
            .unwrap();

        let first = pq(2);
        let rotated = registry
            .apply_pq_rotation(&rotation_by_root(&passkey, &did.to_string(), &first, 1))
            .unwrap();
        assert_eq!(rotated.did, did);
        assert_eq!(
            rotated.pq_verifying_key,
            first.verifying_key_bytes().to_vec()
        );
        assert!(rotated.public_keys.iter().any(|k| k.key_id == "pq-1"));

        assert!(
            registry
                .apply_pq_rotation(&rotation_by_root(&passkey, &did.to_string(), &pq(3), 2))
                .is_err(),
            "the P-256 passkey no longer governs"
        );
        assert!(
            registry
                .apply_pq_rotation(&rotation_by_root(&passkey, &did.to_string(), &first, 1))
                .is_err(),
            "a rotation cannot be replayed"
        );
    }

    /// Two agents on one host get two DIDs, each derived from its own key.
    #[tokio::test]
    async fn agents_on_one_host_do_not_collapse() {
        let registry = IdentityRegistry::new();
        let host = test_autonomous(&registry, 1).await.unwrap();
        let a = registry
            .register_agent_machine_with_fee(&host.did_string(), test_pubkey(10), vec![])
            .await
            .unwrap()
            .identity;
        let b = registry
            .register_agent_machine_with_fee(&host.did_string(), test_pubkey(11), vec![])
            .await
            .unwrap()
            .identity;
        assert_ne!(a.did, b.did);
        assert!(tenzro_types::did_derivation::did_derives_from_key(
            &a.did_string(),
            &test_pubkey(10)
        ));
        assert_eq!(
            registry.resolve(&host.did_string()).unwrap().public_keys[0].public_key,
            test_pubkey(1)
        );
        assert!(registry.binding_holds(&a) && registry.binding_holds(&b));
    }

    #[tokio::test]
    async fn test_resolve_did() {
        let registry = IdentityRegistry::new();
        let identity = registry
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Bob".to_string(),
            )
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
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Alice".to_string(),
            )
            .await
            .unwrap()
            .identity;

        let machine = registry
            .register_machine_with_fee(&human.did_string(), test_pubkey(2), vec![])
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
    async fn test_revoke_cascading() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Alice".to_string(),
            )
            .await
            .unwrap()
            .identity;

        let machine = registry
            .register_machine_with_fee(&human.did_string(), test_pubkey(2), vec![])
            .await
            .unwrap()
            .identity;

        registry
            .revoke_from_chain(
                &human.did_string(),
                "Test revocation".to_string(),
                "admin".to_string(),
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
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Alice".to_string(),
            )
            .await
            .unwrap()
            .identity;

        // Register multiple machines under the same human
        let machine1 = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(2),
                vec!["inference".to_string()],
            )
            .await
            .unwrap()
            .identity;

        let machine2 = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(3),
                vec!["trading".to_string()],
            )
            .await
            .unwrap()
            .identity;

        let machine3 = registry
            .register_machine_with_fee(
                &human.did_string(),
                test_pubkey(4),
                vec!["monitoring".to_string()],
            )
            .await
            .unwrap()
            .identity;

        // Revoke the human
        registry
            .revoke_from_chain(
                &human.did_string(),
                "Account closure".to_string(),
                "admin".to_string(),
            )
            .unwrap();

        // Verify human is revoked
        let revoked_human = registry.resolve(&human.did_string()).unwrap();
        assert_eq!(revoked_human.status, IdentityStatus::Revoked);

        // Verify ALL machines are cascaded revoked
        let revoked_machine1 = registry.resolve(&machine1.did_string()).unwrap();
        assert_eq!(
            revoked_machine1.status,
            IdentityStatus::Revoked,
            "Machine 1 should be revoked"
        );

        let revoked_machine2 = registry.resolve(&machine2.did_string()).unwrap();
        assert_eq!(
            revoked_machine2.status,
            IdentityStatus::Revoked,
            "Machine 2 should be revoked"
        );

        let revoked_machine3 = registry.resolve(&machine3.did_string()).unwrap();
        assert_eq!(
            revoked_machine3.status,
            IdentityStatus::Revoked,
            "Machine 3 should be revoked"
        );
    }

    #[tokio::test]
    async fn test_revoke_machine_does_not_affect_controller() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Alice".to_string(),
            )
            .await
            .unwrap()
            .identity;

        let machine = registry
            .register_machine_with_fee(&human.did_string(), test_pubkey(2), vec![])
            .await
            .unwrap()
            .identity;

        // Revoke only the machine
        registry
            .revoke_from_chain(
                &machine.did_string(),
                "Machine compromised".to_string(),
                "admin".to_string(),
            )
            .unwrap();

        // Verify machine is revoked
        let revoked_machine = registry.resolve(&machine.did_string()).unwrap();
        assert_eq!(revoked_machine.status, IdentityStatus::Revoked);

        // Verify human is still active
        let active_human = registry.resolve(&human.did_string()).unwrap();
        assert_eq!(
            active_human.status,
            IdentityStatus::Active,
            "Human should remain active"
        );
    }

    #[tokio::test]
    async fn test_suspend_and_reactivate() {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Alice".to_string(),
            )
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
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Alice".to_string(),
            )
            .await
            .unwrap()
            .identity;
        let h2 = registry
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(2),
                "Bob".to_string(),
            )
            .await
            .unwrap()
            .identity;
        registry
            .register_machine_with_fee(&h1.did_string(), test_pubkey(3), vec![])
            .await
            .unwrap();
        registry
            .register_machine_with_fee(&h2.did_string(), test_pubkey(4), vec![])
            .await
            .unwrap();

        assert_eq!(registry.count(), (2, 2));
        assert_eq!(registry.total_count(), 4);
    }

    #[tokio::test]
    async fn test_reject_nonexistent_controller() {
        let registry = IdentityRegistry::new();
        let result = registry
            .register_machine_with_fee("did:tenzro:human:nonexistent", test_pubkey(1), vec![])
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_registration_fees() {
        let registry = IdentityRegistry::new();

        // Check default fees
        assert_eq!(
            registry.human_registration_fee(),
            10_000_000_000_000_000_000
        ); // 10 TNZO
        assert_eq!(
            registry.machine_registration_fee(),
            5_000_000_000_000_000_000
        ); // 5 TNZO

        // Register with fee info
        let result = registry
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Alice".to_string(),
            )
            .await
            .unwrap();

        assert_eq!(result.fee_required, 10_000_000_000_000_000_000);
        assert!(result.identity.is_human());

        let machine_result = registry
            .register_machine_with_fee(&result.identity.did_string(), test_pubkey(2), vec![])
            .await
            .unwrap();

        assert_eq!(machine_result.fee_required, 5_000_000_000_000_000_000);
        assert!(machine_result.identity.is_machine());
    }

    #[tokio::test]
    async fn test_custom_fee_schedule() {
        use tenzro_types::fees::ServiceFeeSchedule;

        let custom_fees = ServiceFeeSchedule::new(
            1_000_000_000_000_000_000,  // 1 TNZO for human
            500_000_000_000_000_000,    // 0.5 TNZO for machine
            500_000_000_000_000_000,    // 0.5 TNZO for agent
            10_000_000_000_000_000_000, // 10 TNZO for model
            100_000_000_000_000_000,    // 0.1 TNZO for bridge
        );

        let registry = IdentityRegistry::with_fee_schedule(custom_fees);
        assert_eq!(registry.human_registration_fee(), 1_000_000_000_000_000_000);
        assert_eq!(registry.machine_registration_fee(), 500_000_000_000_000_000);
    }

    // ----- delegation enforcement -----

    // ----- KYC tier requires signed credential -----

    /// Grades one wallet, standing in for the node's resolver.
    struct WalletKyc(tenzro_types::Address, KycTier);
    impl KycResolver for WalletKyc {
        fn kyc_tier(&self, _did: &str, wallet: &tenzro_types::Address) -> KycTier {
            if *wallet == self.0 {
                self.1
            } else {
                KycTier::Unverified
            }
        }
    }

    #[tokio::test]
    async fn the_resolver_grades_the_identitys_wallet_and_none_means_unverified() {
        let registry = IdentityRegistry::new();
        let alice = registry
            .register_human_via_binder(b"k".to_vec(), test_pubkey(41), "Alice".to_string())
            .await
            .unwrap()
            .identity;
        assert_eq!(registry.kyc_tier(&alice.did_string()), KycTier::Unverified);
        let graded =
            registry.with_kyc_resolver(Arc::new(WalletKyc(alice.wallet_address, KycTier::Full)));
        assert_eq!(graded.kyc_tier(&alice.did_string()), KycTier::Full);
        assert_eq!(
            graded.kyc_tier("did:tenzro:human:unknown"),
            KycTier::Unverified
        );
    }

    // ----- Principal-chain resolver tests -----

    #[tokio::test]
    async fn principal_chain_for_human_acting_directly() {
        let registry = IdentityRegistry::new();
        let alice = registry
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Alice".to_string(),
            )
            .await
            .unwrap()
            .identity;

        let pc = registry.resolve_principal_chain(&alice.did_string(), 100u64);

        assert_eq!(pc.delegation_depth, 0);
        assert!(pc.chain.is_empty());
        assert_eq!(pc.actor, alice.did_string());
        assert_eq!(pc.controller_did(), alice.did_string());
        assert_eq!(pc.controller.role, PrincipalRole::Controller);
        assert_eq!(pc.frozen_at_block, BlockHeight::new(100));
        assert!(!pc.has_tombstone());
    }

    #[tokio::test]
    async fn principal_chain_for_machine_under_human_controller() {
        let registry = IdentityRegistry::new();
        let alice = registry
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Alice".to_string(),
            )
            .await
            .unwrap()
            .identity;
        let bot = registry
            .register_machine_with_fee(
                &alice.did_string(),
                test_pubkey(2),
                vec!["inference".to_string()],
            )
            .await
            .unwrap()
            .identity;

        let pc = registry.resolve_principal_chain(&bot.did_string(), 200u64);

        assert_eq!(pc.delegation_depth, 2);
        assert_eq!(pc.controller_did(), alice.did_string());
        assert_eq!(pc.controller.role, PrincipalRole::Controller);
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
        let bot = test_autonomous(&registry, 1).await.unwrap();

        let pc = registry.resolve_principal_chain(&bot.did_string(), 50u64);

        assert_eq!(pc.delegation_depth, 0);
        assert!(pc.chain.is_empty());
        assert_eq!(pc.controller.role, PrincipalRole::AutonomousAgent);
    }

    #[tokio::test]
    async fn principal_chain_for_unresolvable_did_returns_tombstone() {
        let registry = IdentityRegistry::new();
        let pc = registry.resolve_principal_chain("did:tenzro:human:ghost:uuid", 7u64);

        assert!(pc.has_tombstone());
        assert_eq!(pc.frozen_at_block, BlockHeight::new(7));
    }

    // ----- BondLookup wiring tests -----

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
        let registry =
            IdentityRegistry::new().with_bond_lookup(lookup.clone() as Arc<dyn BondLookup>);

        let alice = registry
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Alice".to_string(),
            )
            .await
            .unwrap()
            .identity;
        let bot = registry
            .register_machine_with_fee(
                &alice.did_string(),
                test_pubkey(2),
                vec!["inference".to_string()],
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
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(1),
                "Alice".to_string(),
            )
            .await
            .unwrap()
            .identity;
        let bot = registry
            .register_machine_with_fee(
                &alice.did_string(),
                test_pubkey(2),
                vec!["inference".to_string()],
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
        let registry =
            IdentityRegistry::new().with_bond_lookup(lookup.clone() as Arc<dyn BondLookup>);
        let bot = test_autonomous(&registry, 7).await.unwrap();

        lookup.actor.write().insert(bot.did_string(), amount);
        lookup.aggregate.write().insert(bot.did_string(), amount);

        let pc = registry.resolve_principal_chain(&bot.did_string(), 1u64);

        assert_eq!(pc.actor_bond, Some(amount));
        assert_eq!(pc.controller_bond_aggregate, Some(amount));
    }

    // ----- multiple wallets per identity + from-aware resolution -----

    fn chain_identity_payload(did: &str) -> tenzro_types::identity::RegisterIdentityPayload {
        tenzro_types::identity::RegisterIdentityPayload {
            did: did.to_string(),
            identity_type: "human".to_string(),
            display_name: "Remote Alice".to_string(),
            controller_pubkey: vec![9u8; 32],
            key_type: "Ed25519".to_string(),
            wallet_id: "remote-wallet".to_string(),
            wallet_address: Address::from_bytes(&[3u8; 32]).unwrap(),
            pq_verifying_key: vec![1u8; 1952],
            metadata: Default::default(),
            proof: tenzro_types::identity::RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: vec![0u8; 64],
                    },
                ),
            },
        }
    }

    #[tokio::test]
    async fn upsert_from_chain_lands_replicated_identity() {
        // Mirrors what a node does when it observes an `IdentityRegister`
        // consensus log for a DID it has never seen: the identity
        // becomes resolvable locally.
        let registry = IdentityRegistry::new();
        let did_owned = TenzroDid::from_passkey(&[9u8; 32]).to_string();
        let did = did_owned.as_str();
        assert!(
            registry.resolve(did).is_err(),
            "unknown DID must not resolve yet"
        );

        let landed = registry
            .upsert_from_chain(&chain_identity_payload(did))
            .unwrap();
        assert!(landed, "a new DID must be landed");

        let resolved = registry.resolve(did).unwrap();
        assert_eq!(resolved.did_string(), did);
        assert_eq!(resolved.wallet_id, "remote-wallet");
    }

    /// A replicated record whose DID its controller key does not derive is
    /// refused, so no node mirrors a squatted DID.
    #[tokio::test]
    async fn upsert_from_chain_refuses_a_did_its_key_does_not_derive() {
        let registry = IdentityRegistry::new();
        let did = "did:tenzro:human:remote1";
        assert!(
            registry
                .upsert_from_chain(&chain_identity_payload(did))
                .is_err()
        );
        assert!(registry.resolve(did).is_err());
        let mut payload = chain_identity_payload(&TenzroDid::from_passkey(&[9u8; 32]).to_string());
        payload.identity_type = "robot".to_string();
        assert!(
            registry.upsert_from_chain(&payload).is_err(),
            "unknown identity types are refused"
        );
    }

    #[tokio::test]
    async fn upsert_from_chain_is_origin_safe_noop_when_did_exists() {
        // The origin node already holds the authoritative (richer) record; the
        // mirror must not clobber it on re-org / restart replay.
        let registry = IdentityRegistry::new();
        let alice = registry
            .register_human_via_binder(
                b"test-credential".to_vec(),
                test_pubkey(7),
                "Alice".to_string(),
            )
            .await
            .unwrap()
            .identity;
        let did = alice.did_string();

        let mut payload = chain_identity_payload(&did);
        payload.display_name = "Overwrite Attempt".to_string();
        let landed = registry.upsert_from_chain(&payload).unwrap();
        assert!(!landed, "an already-known DID must be a no-op");

        // KYC tier / display name from the authoritative record are preserved.
        let resolved = registry.resolve(&did).unwrap();
        assert_eq!(resolved.display_name(), "Alice");
    }

    #[tokio::test]
    async fn upsert_from_chain_rejects_malformed_keys() {
        let registry = IdentityRegistry::new();
        let mut payload = chain_identity_payload("did:tenzro:human:badkey");
        payload.pq_verifying_key = vec![1u8; 10]; // wrong length
        assert!(
            registry.upsert_from_chain(&payload).is_err(),
            "a record with a malformed PQ key must be rejected fail-closed"
        );
    }

    /// Hardware that holds no ML-DSA-65 key registers nothing: the mirror
    /// refuses a record that names none.
    #[tokio::test]
    async fn upsert_from_chain_refuses_an_identity_without_an_ml_dsa_key() {
        let registry = IdentityRegistry::new();
        let sec1: Vec<u8> = [&[0x04u8][..], &[7u8; 64][..]].concat();
        let did = tenzro_types::did_derivation::machine_did(&sec1);
        let mut payload = chain_identity_payload(&did);
        payload.identity_type = "machine".to_string();
        payload.key_type = "P-256".to_string();
        payload.controller_pubkey = sec1;
        payload.pq_verifying_key = Vec::new();

        assert!(registry.upsert_from_chain(&payload).is_err());
        assert!(registry.resolve(&did).is_err());
    }

    #[tokio::test]
    async fn upsert_from_chain_rejects_a_wrong_length_ml_dsa_key_on_a_valid_did() {
        let registry = IdentityRegistry::new();
        let did = TenzroDid::from_passkey(&[9u8; 32]).to_string();
        let mut payload = chain_identity_payload(&did);
        payload.pq_verifying_key = vec![1u8; 10];
        assert!(registry.upsert_from_chain(&payload).is_err());
        assert!(registry.resolve(&did).is_err());
    }

    #[tokio::test]
    async fn two_machines_never_share_a_did() {
        // The other half: recognition must not collapse distinct machines.
        let registry = IdentityRegistry::new();
        let a = test_autonomous(&registry, 42)
            .await
            .expect("first machine registers");
        let b = test_autonomous(&registry, 43)
            .await
            .expect("second machine registers");

        assert_ne!(
            a.did, b.did,
            "distinct hardware must derive distinct identities"
        );
    }
}
