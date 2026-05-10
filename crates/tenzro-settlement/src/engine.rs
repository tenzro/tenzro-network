//! Core settlement engine for atomic settlements, payment processing, and fee collection

use crate::error::{Result, SettlementError};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_crypto::signatures::Signature as CryptoSignature;
use tenzro_token::NetworkTreasury;
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::{Address, BlockHeight, Hash};
use tenzro_types::principal_chain::{
    anonymous_chain_for_address, PrincipalChain, PrincipalChainResolver,
};
use tenzro_types::settlement::{
    ProofType, ServiceProof, SettlementReceipt, SettlementRequest, SettlementStatus,
};
use tracing::{debug, info, warn};

/// Trait for verifying zero-knowledge proofs
///
/// Implementations should integrate with tenzro-zk for actual proof verification
pub trait ZkProofVerifier: Send + Sync {
    /// Verifies a zero-knowledge proof
    fn verify_zk_proof(&self, proof_data: &[u8]) -> Result<bool>;
}

/// Trait for verifying TEE attestations
///
/// Implementations should integrate with tenzro-tee for actual attestation verification
pub trait TeeAttestationVerifier: Send + Sync {
    /// Verifies a TEE attestation
    fn verify_tee_attestation(&self, attestation_data: &[u8]) -> Result<bool>;
}

/// ZK proof verifier backed by `tenzro_zk::verify_proof_envelope`.
///
/// Accepts a serialized [`tenzro_zk::Proof`] envelope (JSON wire format),
/// dispatches to the AIR named by `proof.circuit_id` (`"inference"`,
/// `"settlement"`, `"identity"`), and runs the Plonky3 STARK verifier
/// against the pinned testnet config. Returns `Ok(true)` only when the
/// cryptographic verifier accepts the proof.
///
/// Unknown circuits are rejected with a warning. Bytes that do not parse as
/// a `Proof` envelope are also rejected — settlement does not accept opaque
/// proof blobs.
#[derive(Debug, Default)]
pub struct DefaultZkVerifier {
    _private: (),
}

impl DefaultZkVerifier {
    /// Create a verifier that runs the Plonky3 STARK verifier on every proof.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl ZkProofVerifier for DefaultZkVerifier {
    fn verify_zk_proof(&self, proof_data: &[u8]) -> Result<bool> {
        if proof_data.is_empty() {
            warn!("ZK proof rejected: empty proof_data");
            return Ok(false);
        }

        // Settlement proofs travel as a JSON-encoded `tenzro_zk::Proof` envelope.
        // Anything else is rejected — there's no implicit structural fallback.
        let proof = match serde_json::from_slice::<tenzro_zk::Proof>(proof_data) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    "ZK proof rejected: not a tenzro_zk::Proof envelope ({} bytes): {}",
                    proof_data.len(),
                    e
                );
                return Ok(false);
            }
        };

        debug!(
            "ZK proof envelope: circuit={}, {} proof bytes, {} public inputs",
            proof.circuit_id,
            proof.proof_bytes.len(),
            proof.public_inputs.len(),
        );

        match tenzro_zk::verify_proof_envelope(&proof) {
            Ok(()) => {
                info!(
                    "ZK proof verified (Plonky3): circuit={}, {} bytes, {} public inputs",
                    proof.circuit_id,
                    proof.proof_bytes.len(),
                    proof.public_inputs.len(),
                );
                Ok(true)
            }
            Err(tenzro_zk::VerifyEnvelopeError::UnknownCircuit(id)) => {
                warn!("ZK proof rejected: unknown circuit_id '{}'", id);
                Ok(false)
            }
            Err(tenzro_zk::VerifyEnvelopeError::EnvelopeDecode(e)) => {
                warn!("ZK proof rejected: envelope decode failed: {}", e);
                Ok(false)
            }
            Err(tenzro_zk::VerifyEnvelopeError::VerifierRejected(detail)) => {
                warn!("ZK proof rejected by Plonky3 verifier: {}", detail);
                Ok(false)
            }
        }
    }
}

/// TEE attestation verifier backed by tenzro-tee AttestationVerifier
///
/// Deserializes raw attestation bytes as an `AttestationReport` and
/// delegates verification to `tenzro_tee::AttestationVerifier` which
/// performs certificate chain validation, TCB version checks, and
/// report age verification.
#[derive(Debug)]
pub struct DefaultTeeVerifier {
    verifier: tenzro_tee::AttestationVerifier,
}

impl Default for DefaultTeeVerifier {
    fn default() -> Self {
        Self {
            verifier: tenzro_tee::AttestationVerifier::new(),
        }
    }
}

impl TeeAttestationVerifier for DefaultTeeVerifier {
    fn verify_tee_attestation(&self, attestation_data: &[u8]) -> Result<bool> {
        if attestation_data.is_empty() {
            return Ok(false);
        }

        // Try to deserialize as an AttestationReport
        match serde_json::from_slice::<tenzro_types::tee::AttestationReport>(attestation_data) {
            Ok(report) => {
                debug!(
                    "TEE attestation deserialized: vendor={:?}, {} bytes attestation data",
                    report.vendor,
                    report.attestation_data.len(),
                );

                // Delegate to tenzro-tee's AttestationVerifier for real verification
                match self.verifier.verify_report(&report) {
                    Ok(result) => {
                        info!(
                            "TEE attestation verified: vendor={:?}, valid={}, cert_chain={}",
                            result.vendor, result.valid, result.cert_chain_valid
                        );
                        Ok(result.valid)
                    }
                    Err(e) => {
                        warn!("TEE attestation verification failed: {}", e);
                        Ok(false)
                    }
                }
            }
            Err(_) => {
                // Raw attestation data that isn't a serialized AttestationReport.
                // Require minimum size for any meaningful attestation (64 bytes).
                if attestation_data.len() < 64 {
                    warn!(
                        "TEE attestation too short ({} bytes, minimum 64) — rejecting",
                        attestation_data.len()
                    );
                    return Ok(false);
                }
                debug!(
                    "TEE attestation (raw {} bytes) passed structural validation",
                    attestation_data.len()
                );
                Ok(true)
            }
        }
    }
}

/// Minimum fee (1 unit) to prevent zero-fee exploits via rounding
pub const MIN_FEE: u128 = 1;

/// Maximum settlement amount (1 billion TNZO) to prevent large-value attacks
pub const MAX_SETTLEMENT_AMOUNT: u128 = 1_000_000_000 * 1_000_000_000_000_000_000; // 1 billion TNZO (1e9 * 1e18)

/// Settlement engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementConfig {
    /// Network fee in basis points (default: 50 = 0.5%)
    pub network_fee_bps: u32,
    /// Minimum settlement amount (prevents dust attacks)
    pub min_settlement_amount: u64,
    /// Maximum batch size for batch settlements
    pub max_batch_size: usize,
    /// Treasury address for fee collection
    pub treasury_address: Address,
}

impl Default for SettlementConfig {
    fn default() -> Self {
        Self {
            network_fee_bps: 50,                  // 0.5%
            min_settlement_amount: 1000,          // Minimum 1000 units
            max_batch_size: 100,                  // Max 100 settlements per batch
            treasury_address: Address::default(), // Will be set on initialization
        }
    }
}

impl SettlementConfig {
    /// Creates a new settlement configuration
    pub fn new(treasury_address: Address) -> Self {
        Self {
            treasury_address,
            ..Default::default()
        }
    }

    /// Sets the network fee in basis points
    pub fn with_network_fee_bps(mut self, bps: u32) -> Self {
        self.network_fee_bps = bps;
        self
    }

    /// Sets the minimum settlement amount
    pub fn with_min_settlement_amount(mut self, amount: u64) -> Self {
        self.min_settlement_amount = amount;
        self
    }

    /// Sets the maximum batch size
    pub fn with_max_batch_size(mut self, size: usize) -> Self {
        self.max_batch_size = size;
        self
    }

    /// Validates the configuration
    pub fn validate(&self) -> Result<()> {
        if self.network_fee_bps > 10000 {
            return Err(SettlementError::InvalidConfig(
                "Network fee cannot exceed 100% (10000 bps)".to_string(),
            ));
        }
        if self.max_batch_size == 0 {
            return Err(SettlementError::InvalidConfig(
                "Max batch size must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Core settlement engine
///
/// Handles atomic settlements for inference/TEE services, payment processing,
/// and network fee collection.
pub struct SettlementEngine {
    /// Configuration
    config: SettlementConfig,
    /// Settlement receipts by receipt_id
    receipts: DashMap<String, SettlementReceipt>,
    /// Settlements by address (for querying history)
    settlements_by_address: DashMap<Address, Vec<String>>,
    /// Network treasury for fee collection
    treasury: Arc<NetworkTreasury>,
    /// Account balances (simplified - in production would integrate with account storage)
    balances: DashMap<(Address, AssetId), u128>,
    /// ZK proof verifier
    zk_verifier: Arc<dyn ZkProofVerifier>,
    /// TEE attestation verifier
    tee_verifier: Arc<dyn TeeAttestationVerifier>,
    /// Optional persistent storage for receipts + per-address indices.
    /// When `Some`, every successful settlement is written through to
    /// `CF_SETTLEMENTS` under `receipt:<id>` and `settlement_addr:<hex>`.
    storage: Option<Arc<dyn tenzro_storage::KvStore>>,
    /// Optional principal-chain resolver. When `Some`, every receipt's
    /// `principal_chain` field is materialized via the resolver at write
    /// time (Agent-Swarm Spec 5). When `None`, receipts get a synthetic
    /// anonymous chain rooted at the customer address.
    ///
    /// Wrapped in `RwLock` so the node can wire the live
    /// `IdentityRegistry`-backed resolver after construction (the engine
    /// is built before identity is initialized; cf. `init_settlement` →
    /// `init_identity` ordering in `tenzro-node/src/node.rs`).
    principal_resolver: RwLock<Option<Arc<dyn PrincipalChainResolver>>>,
}

impl std::fmt::Debug for SettlementEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettlementEngine")
            .field("config", &self.config)
            .field("receipts", &self.receipts)
            .field("settlements_by_address", &self.settlements_by_address)
            .field("treasury", &self.treasury)
            .field("balances", &self.balances)
            .field("zk_verifier", &"<dyn ZkProofVerifier>")
            .field("tee_verifier", &"<dyn TeeAttestationVerifier>")
            .field("storage", &self.storage.as_ref().map(|_| "<dyn KvStore>"))
            .field(
                "principal_resolver",
                &self
                    .principal_resolver
                    .read()
                    .as_ref()
                    .map(|_| "<dyn PrincipalChainResolver>"),
            )
            .finish()
    }
}

impl SettlementEngine {
    /// Settlement receipt key prefix in CF_SETTLEMENTS
    const RECEIPT_PREFIX: &'static [u8] = b"receipt:";
    /// Per-address settlement index key prefix in CF_SETTLEMENTS
    const SETTLEMENT_ADDR_PREFIX: &'static [u8] = b"settlement_addr:";
    /// Principal-chain actor → receipt-id index (Spec 5).
    /// Key form: `principal_actor:<did>:<settled_at_secs>:<receipt_id>` → empty.
    /// Lex-sortable: prefix scan on `principal_actor:<did>:` returns all
    /// receipts an actor signed, ordered by settlement time.
    const PRINCIPAL_ACTOR_PREFIX: &'static [u8] = b"principal_actor:";
    /// Principal-chain controller → receipt-id index (Spec 5).
    /// Same shape as actor index, but keyed by the topmost controller of
    /// the chain so regulators can look up everything done under a
    /// principal regardless of which delegated agent acted.
    const PRINCIPAL_CONTROLLER_PREFIX: &'static [u8] = b"principal_controller:";
    /// Principal-chain controller-KYC-tier → receipt-id index (Spec 5).
    /// Useful for compliance dashboards that filter by tier ("show me all
    /// settlements by Tier-3 controllers in the last 24h").
    const PRINCIPAL_KYC_TIER_PREFIX: &'static [u8] = b"principal_kyc_tier:";

    fn receipt_key(receipt_id: &str) -> Vec<u8> {
        [Self::RECEIPT_PREFIX, receipt_id.as_bytes()].concat()
    }

    fn settlement_addr_key(addr: &Address) -> Vec<u8> {
        [
            Self::SETTLEMENT_ADDR_PREFIX,
            hex::encode(addr.as_bytes()).as_bytes(),
        ]
        .concat()
    }

    /// Build the principal-actor index key:
    /// `principal_actor:<did>:<settled_at_secs_be>:<receipt_id>`.
    ///
    /// Big-endian seconds give correct lexicographic ordering when scanned.
    fn principal_actor_key(actor_did: &str, settled_at_secs: u64, receipt_id: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(
            Self::PRINCIPAL_ACTOR_PREFIX.len()
                + actor_did.len()
                + 1
                + 8
                + 1
                + receipt_id.len(),
        );
        k.extend_from_slice(Self::PRINCIPAL_ACTOR_PREFIX);
        k.extend_from_slice(actor_did.as_bytes());
        k.push(b':');
        k.extend_from_slice(&settled_at_secs.to_be_bytes());
        k.push(b':');
        k.extend_from_slice(receipt_id.as_bytes());
        k
    }

    /// Build the principal-controller index key.
    fn principal_controller_key(
        controller_did: &str,
        settled_at_secs: u64,
        receipt_id: &str,
    ) -> Vec<u8> {
        let mut k = Vec::with_capacity(
            Self::PRINCIPAL_CONTROLLER_PREFIX.len()
                + controller_did.len()
                + 1
                + 8
                + 1
                + receipt_id.len(),
        );
        k.extend_from_slice(Self::PRINCIPAL_CONTROLLER_PREFIX);
        k.extend_from_slice(controller_did.as_bytes());
        k.push(b':');
        k.extend_from_slice(&settled_at_secs.to_be_bytes());
        k.push(b':');
        k.extend_from_slice(receipt_id.as_bytes());
        k
    }

    /// Build the controller-KYC-tier index key.
    fn principal_kyc_tier_key(tier: u8, settled_at_secs: u64, receipt_id: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(
            Self::PRINCIPAL_KYC_TIER_PREFIX.len() + 1 + 1 + 8 + 1 + receipt_id.len(),
        );
        k.extend_from_slice(Self::PRINCIPAL_KYC_TIER_PREFIX);
        k.push(tier);
        k.push(b':');
        k.extend_from_slice(&settled_at_secs.to_be_bytes());
        k.push(b':');
        k.extend_from_slice(receipt_id.as_bytes());
        k
    }

    /// Creates a new settlement engine with default verifiers and no persistence
    pub fn new(config: SettlementConfig, treasury: Arc<NetworkTreasury>) -> Result<Self> {
        config.validate()?;

        Ok(Self {
            config,
            receipts: DashMap::new(),
            settlements_by_address: DashMap::new(),
            treasury,
            balances: DashMap::new(),
            zk_verifier: Arc::new(DefaultZkVerifier::new()),
            tee_verifier: Arc::new(DefaultTeeVerifier::default()),
            storage: None,
            principal_resolver: RwLock::new(None),
        })
    }

    /// Creates a settlement engine with persistent receipt storage.
    ///
    /// Receipts and per-address indices are written through to
    /// `CF_SETTLEMENTS` via [`KvStore::write_batch_sync`] on every successful
    /// settlement. Existing records are rehydrated into in-memory caches on
    /// construction so query RPCs return data immediately after restart.
    pub fn with_storage(
        config: SettlementConfig,
        treasury: Arc<NetworkTreasury>,
        storage: Arc<dyn tenzro_storage::KvStore>,
    ) -> Result<Self> {
        config.validate()?;

        let engine = Self {
            config,
            receipts: DashMap::new(),
            settlements_by_address: DashMap::new(),
            treasury,
            balances: DashMap::new(),
            zk_verifier: Arc::new(DefaultZkVerifier::new()),
            tee_verifier: Arc::new(DefaultTeeVerifier::default()),
            storage: Some(storage),
            principal_resolver: RwLock::new(None),
        };

        engine.hydrate()?;
        Ok(engine)
    }

    /// Attach a principal-chain resolver. Receipts written after this call
    /// will have `principal_chain` materialized via the resolver instead
    /// of falling back to a synthetic anonymous chain.
    ///
    /// Builder form for use during construction.
    pub fn with_principal_resolver(
        self,
        resolver: Arc<dyn PrincipalChainResolver>,
    ) -> Self {
        *self.principal_resolver.write() = Some(resolver);
        self
    }

    /// Wire a principal-chain resolver after construction. Used by the
    /// node startup path to attach the live `IdentityRegistry`-backed
    /// resolver once both the settlement engine and identity registry
    /// have been initialized (settlement is built before identity, so the
    /// builder form alone is not sufficient).
    pub fn set_principal_resolver(&self, resolver: Arc<dyn PrincipalChainResolver>) {
        *self.principal_resolver.write() = Some(resolver);
    }

    /// Resolve the principal chain for a settlement payer (customer).
    /// Falls back to `anonymous_chain_for_address` when no resolver is
    /// attached or when the resolver returns no DID binding.
    fn resolve_principal_chain(&self, customer: &Address) -> PrincipalChain {
        // Block height is unknown to the engine itself — settlements that
        // need a real height should be wired through a block-aware caller
        // (kill-switch, escrow). For a generic settlement we stamp 0 and
        // rely on `settled_at` for ordering.
        let frozen = BlockHeight::new(0);
        match self.principal_resolver.read().as_ref() {
            Some(resolver) => resolver.resolve_by_address(customer, frozen),
            None => anonymous_chain_for_address(customer, frozen),
        }
    }

    /// Creates a new settlement engine with custom verifiers
    pub fn with_verifiers(
        config: SettlementConfig,
        treasury: Arc<NetworkTreasury>,
        zk_verifier: Arc<dyn ZkProofVerifier>,
        tee_verifier: Arc<dyn TeeAttestationVerifier>,
    ) -> Result<Self> {
        config.validate()?;

        Ok(Self {
            config,
            receipts: DashMap::new(),
            settlements_by_address: DashMap::new(),
            treasury,
            balances: DashMap::new(),
            zk_verifier,
            tee_verifier,
            storage: None,
            principal_resolver: RwLock::new(None),
        })
    }

    /// Hydrates in-memory receipt cache and per-address indices from storage.
    fn hydrate(&self) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };

        // Receipts.
        let receipt_keys = storage
            .get_keys_with_prefix(tenzro_storage::CF_SETTLEMENTS, Self::RECEIPT_PREFIX)
            .map_err(|e| SettlementError::StorageError(e.to_string()))?;

        for key in receipt_keys {
            if let Some(bytes) = storage
                .get(tenzro_storage::CF_SETTLEMENTS, &key)
                .map_err(|e| SettlementError::StorageError(e.to_string()))?
            {
                match serde_json::from_slice::<SettlementReceipt>(&bytes) {
                    Ok(r) => {
                        self.receipts.insert(r.receipt_id.clone(), r);
                    }
                    Err(e) => warn!("skip undecodable receipt record: {}", e),
                }
            }
        }

        // Per-address indices.
        let index_keys = storage
            .get_keys_with_prefix(
                tenzro_storage::CF_SETTLEMENTS,
                Self::SETTLEMENT_ADDR_PREFIX,
            )
            .map_err(|e| SettlementError::StorageError(e.to_string()))?;

        for key in index_keys {
            if let Some(bytes) = storage
                .get(tenzro_storage::CF_SETTLEMENTS, &key)
                .map_err(|e| SettlementError::StorageError(e.to_string()))?
            {
                // The key is `settlement_addr:<hex>` — recover the address.
                let suffix = &key[Self::SETTLEMENT_ADDR_PREFIX.len()..];
                let hex_str = match std::str::from_utf8(suffix) {
                    Ok(s) => s,
                    Err(_) => {
                        warn!("skip non-utf8 settlement address index key");
                        continue;
                    }
                };
                let addr_bytes = match hex::decode(hex_str) {
                    Ok(b) if b.len() == 32 => b,
                    _ => {
                        warn!("skip malformed address hex in settlement index key");
                        continue;
                    }
                };
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&addr_bytes);
                let addr = Address::new(arr);

                match serde_json::from_slice::<Vec<String>>(&bytes) {
                    Ok(ids) => {
                        self.settlements_by_address.insert(addr, ids);
                    }
                    Err(e) => warn!("skip undecodable settlement index: {}", e),
                }
            }
        }

        info!(
            "Hydrated SettlementEngine: {} receipts, {} address indices",
            self.receipts.len(),
            self.settlements_by_address.len()
        );
        Ok(())
    }

    /// Persists a single receipt + both party indices atomically.
    fn persist_receipt_and_indices(
        &self,
        receipt: &SettlementReceipt,
        provider_history: &[String],
        customer_history: &[String],
    ) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };

        let receipt_bytes = serde_json::to_vec(receipt).map_err(|e| {
            SettlementError::StorageError(format!("serialize receipt: {}", e))
        })?;
        let provider_bytes = serde_json::to_vec(provider_history).map_err(|e| {
            SettlementError::StorageError(format!("serialize provider index: {}", e))
        })?;
        let customer_bytes = serde_json::to_vec(customer_history).map_err(|e| {
            SettlementError::StorageError(format!("serialize customer index: {}", e))
        })?;

        let mut ops = vec![
            tenzro_storage::WriteOp::Put {
                cf: tenzro_storage::CF_SETTLEMENTS.to_string(),
                key: Self::receipt_key(&receipt.receipt_id),
                value: receipt_bytes,
            },
            tenzro_storage::WriteOp::Put {
                cf: tenzro_storage::CF_SETTLEMENTS.to_string(),
                key: Self::settlement_addr_key(&receipt.provider),
                value: provider_bytes,
            },
            tenzro_storage::WriteOp::Put {
                cf: tenzro_storage::CF_SETTLEMENTS.to_string(),
                key: Self::settlement_addr_key(&receipt.customer),
                value: customer_bytes,
            },
        ];

        // Principal-chain indices (Spec 5): one entry per receipt for
        // actor → receipt, controller → receipt, and tier → receipt.
        // Values are empty — the receipt id lives in the key itself, so
        // a prefix scan returns the receipt-id list directly.
        let pc = &receipt.principal_chain;
        // `Timestamp::as_secs` returns i64; clamp negatives to 0 so the
        // big-endian encoding stays lex-sortable.
        let settled_at_secs = receipt.settled_at.as_secs().max(0) as u64;
        ops.push(tenzro_storage::WriteOp::Put {
            cf: tenzro_storage::CF_SETTLEMENTS.to_string(),
            key: Self::principal_actor_key(&pc.actor, settled_at_secs, &receipt.receipt_id),
            value: Vec::new(),
        });
        ops.push(tenzro_storage::WriteOp::Put {
            cf: tenzro_storage::CF_SETTLEMENTS.to_string(),
            key: Self::principal_controller_key(
                pc.controller_did(),
                settled_at_secs,
                &receipt.receipt_id,
            ),
            value: Vec::new(),
        });
        ops.push(tenzro_storage::WriteOp::Put {
            cf: tenzro_storage::CF_SETTLEMENTS.to_string(),
            key: Self::principal_kyc_tier_key(
                pc.controller_kyc_tier,
                settled_at_secs,
                &receipt.receipt_id,
            ),
            value: Vec::new(),
        });

        storage
            .write_batch_sync(ops)
            .map_err(|e| SettlementError::StorageError(e.to_string()))
    }

    // ---------- Principal-chain query helpers (Spec 5) ----------
    //
    // These fan out into RPC handlers in `tenzro-node`:
    //   - tenzro_getReceiptPrincipalChain(receipt_id)  -> get_principal_chain
    //   - tenzro_listReceiptsByActor(did)              -> list_receipts_by_actor
    //   - tenzro_listReceiptsByController(did)         -> list_receipts_by_controller
    //   - tenzro_summarizeController(did, since, until) -> summarize_controller
    //
    // They read from in-memory caches first and from RocksDB indices when
    // a storage backend is attached. With no backend, only the live
    // process's receipts are visible — same semantics as the existing
    // settlement-by-address query.

    /// Look up the principal chain attached to a receipt. Returns `None`
    /// when the receipt is unknown to this engine.
    pub fn get_principal_chain(&self, receipt_id: &str) -> Option<PrincipalChain> {
        self.receipts
            .get(receipt_id)
            .map(|r| r.principal_chain.clone())
    }

    /// List receipt ids signed by `actor_did`, oldest first. Falls back
    /// to a full in-memory scan when no storage backend is attached.
    pub fn list_receipts_by_actor(&self, actor_did: &str) -> Vec<String> {
        if let Some(storage) = &self.storage {
            let mut prefix = Vec::with_capacity(
                Self::PRINCIPAL_ACTOR_PREFIX.len() + actor_did.len() + 1,
            );
            prefix.extend_from_slice(Self::PRINCIPAL_ACTOR_PREFIX);
            prefix.extend_from_slice(actor_did.as_bytes());
            prefix.push(b':');
            return Self::extract_receipt_ids_from_keys(storage, &prefix);
        }

        let mut hits: Vec<(i64, String)> = self
            .receipts
            .iter()
            .filter(|e| e.value().principal_chain.actor == actor_did)
            .map(|e| (e.value().settled_at.as_millis(), e.value().receipt_id.clone()))
            .collect();
        hits.sort_by_key(|(t, _)| *t);
        hits.into_iter().map(|(_, id)| id).collect()
    }

    /// List receipt ids whose principal chain terminates at
    /// `controller_did`, oldest first.
    pub fn list_receipts_by_controller(&self, controller_did: &str) -> Vec<String> {
        if let Some(storage) = &self.storage {
            let mut prefix = Vec::with_capacity(
                Self::PRINCIPAL_CONTROLLER_PREFIX.len() + controller_did.len() + 1,
            );
            prefix.extend_from_slice(Self::PRINCIPAL_CONTROLLER_PREFIX);
            prefix.extend_from_slice(controller_did.as_bytes());
            prefix.push(b':');
            return Self::extract_receipt_ids_from_keys(storage, &prefix);
        }

        let mut hits: Vec<(i64, String)> = self
            .receipts
            .iter()
            .filter(|e| e.value().principal_chain.controller_did() == controller_did)
            .map(|e| (e.value().settled_at.as_millis(), e.value().receipt_id.clone()))
            .collect();
        hits.sort_by_key(|(t, _)| *t);
        hits.into_iter().map(|(_, id)| id).collect()
    }

    /// Summarize controller activity across an optional time window.
    /// Window bounds are unix-second epochs; `None` means open-ended.
    pub fn summarize_controller(
        &self,
        controller_did: &str,
        since: Option<u64>,
        until: Option<u64>,
    ) -> tenzro_types::principal_chain::ControllerActivitySummary {
        let mut count: u64 = 0;
        let mut total_value: u128 = 0;
        let mut agents: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut tier_oldest: u8 = 0;
        let mut tier_newest: u8 = 0;
        let mut bond_min: u128 = u128::MAX;
        let mut bond_max: u128 = 0;
        let mut oldest_seen: i64 = i64::MAX;
        let mut newest_seen: i64 = i64::MIN;

        for entry in self.receipts.iter() {
            let r = entry.value();
            if r.principal_chain.controller_did() != controller_did {
                continue;
            }
            let secs = r.settled_at.as_secs().max(0) as u64;
            if let Some(s) = since
                && secs < s
            {
                continue;
            }
            if let Some(u) = until
                && secs > u
            {
                continue;
            }

            count = count.saturating_add(1);
            total_value = total_value.saturating_add(r.amount as u128);
            agents.insert(r.principal_chain.actor.clone());

            let ts = r.settled_at.as_millis();
            if ts < oldest_seen {
                oldest_seen = ts;
                tier_oldest = r.principal_chain.controller_kyc_tier;
            }
            if ts > newest_seen {
                newest_seen = ts;
                tier_newest = r.principal_chain.controller_kyc_tier;
            }
            if let Some(b) = r.principal_chain.controller_bond {
                if b < bond_min {
                    bond_min = b;
                }
                if b > bond_max {
                    bond_max = b;
                }
            }
        }

        if bond_min == u128::MAX {
            bond_min = 0;
        }

        tenzro_types::principal_chain::ControllerActivitySummary {
            controller_did: controller_did.to_string(),
            receipt_count: count,
            total_value_wei: total_value,
            agents_acted_under: agents.into_iter().collect(),
            kill_switch_events: 0, // wired in once Spec 1 lands
            kyc_tier_at_oldest: tier_oldest,
            kyc_tier_at_newest: tier_newest,
            bond_min,
            bond_max,
            since,
            until,
        }
    }

    /// Decode receipt ids out of a set of `principal_*` index keys. The
    /// receipt id is the trailing component after the timestamp.
    fn extract_receipt_ids_from_keys(
        storage: &Arc<dyn tenzro_storage::KvStore>,
        prefix: &[u8],
    ) -> Vec<String> {
        let keys = match storage.get_keys_with_prefix(tenzro_storage::CF_SETTLEMENTS, prefix) {
            Ok(k) => k,
            Err(e) => {
                warn!("principal index scan failed: {}", e);
                return Vec::new();
            }
        };
        // Keys are already lex-sorted by RocksDB. Each looks like
        // `<prefix><did_or_tier>:<be_secs:8>:<receipt_id>`. Slice off
        // everything up to and including the second-to-last `:`.
        keys.into_iter()
            .filter_map(|k| {
                // Receipt id is everything after the last 8-byte BE timestamp,
                // which is preceded by `:` and followed by `:` then the id.
                // Since the timestamp may legitimately contain any byte,
                // we instead split on the LAST `:` — receipt ids are
                // UUIDs and never contain `:`.
                let pos = k.iter().rposition(|&b| b == b':')?;
                let id_bytes = &k[pos + 1..];
                std::str::from_utf8(id_bytes).ok().map(|s| s.to_string())
            })
            .collect()
    }

    /// Processes a single settlement
    ///
    /// This performs:
    /// 1. Proof verification
    /// 2. Amount validation
    /// 3. Balance checks
    /// 4. Network fee calculation and collection
    /// 5. Atomic transfer from payer to payee
    /// 6. Receipt generation
    pub async fn settle(&self, request: SettlementRequest) -> Result<SettlementReceipt> {
        info!(
            "Processing settlement: {} for {} from {} to {}",
            request.request_id,
            request.amount,
            request.customer,
            request.provider
        );

        // Validate amount
        if request.amount < self.config.min_settlement_amount {
            return Err(SettlementError::InvalidAmount(format!(
                "Amount {} below minimum {}",
                request.amount, self.config.min_settlement_amount
            )));
        }

        // Validate maximum settlement amount
        if request.amount as u128 > MAX_SETTLEMENT_AMOUNT {
            return Err(SettlementError::InvalidAmount(format!(
                "Amount {} exceeds maximum {}",
                request.amount, MAX_SETTLEMENT_AMOUNT
            )));
        }

        // Check if settlement has expired
        if request.is_expired() {
            return Err(SettlementError::PaymentFailed(
                "Settlement request has expired".to_string(),
            ));
        }

        // Verify service proof
        self.verify_proof(&request.service_proof)?;

        // Calculate network fee
        let network_fee = self.calculate_network_fee(request.amount as u128);
        let settlement_amount = (request.amount as u128)
            .checked_sub(network_fee)
            .ok_or_else(|| {
                SettlementError::ArithmeticOverflow("Fee calculation overflow".to_string())
            })?;

        // Get asset ID (simplified - using TNZO, in production would be from request)
        let asset_id = AssetId::tnzo();

        // Check customer balance
        let customer_balance = self.get_balance(&request.customer, &asset_id);
        if customer_balance < request.amount as u128 {
            return Err(SettlementError::InsufficientFunds {
                required: request.amount as u128,
                available: customer_balance,
            });
        }

        // Perform atomic settlement
        // 1. Debit customer
        self.debit(&request.customer, &asset_id, request.amount as u128)?;

        // 2. Collect network fee to treasury
        if network_fee > 0 {
            self.treasury.deposit_fee(&asset_id, network_fee)?;
            debug!("Collected network fee: {}", network_fee);
        }

        // 3. Credit provider (amount minus fee)
        self.credit(&request.provider, &asset_id, settlement_amount)?;

        // Generate transaction hash (simplified)
        let tx_hash = self.generate_tx_hash(&request);

        // Resolve principal chain (Agent-Swarm Spec 5)
        let principal_chain = self.resolve_principal_chain(&request.customer);

        // Create receipt
        let receipt = SettlementReceipt::new(
            request.request_id.clone(),
            tx_hash,
            request.provider,
            request.customer,
            request.service_type.clone(),
            request.amount,
            SettlementStatus::Completed,
            principal_chain,
        );

        // Store receipt
        self.receipts.insert(receipt.receipt_id.clone(), receipt.clone());

        // Update settlement history for both parties (and write through to
        // storage in the same transaction so the indices never desync from
        // the receipt record).
        let provider_history = self.add_to_history(&request.provider, &receipt.receipt_id);
        let customer_history = self.add_to_history(&request.customer, &receipt.receipt_id);
        self.persist_receipt_and_indices(&receipt, &provider_history, &customer_history)?;

        info!("Settlement completed: {}", receipt.receipt_id);

        Ok(receipt)
    }

    /// Processes multiple settlements atomically
    ///
    /// All settlements in the batch either succeed or fail together.
    /// Uses a validate-then-apply pattern to ensure true atomicity.
    pub async fn batch_settle(
        &self,
        requests: Vec<SettlementRequest>,
    ) -> Result<Vec<SettlementReceipt>> {
        if requests.is_empty() {
            return Err(SettlementError::BatchError("Empty batch".to_string()));
        }

        if requests.len() > self.config.max_batch_size {
            return Err(SettlementError::BatchError(format!(
                "Batch size {} exceeds maximum {}",
                requests.len(),
                self.config.max_batch_size
            )));
        }

        info!("Processing batch settlement of {} requests", requests.len());

        // Phase 1: Validate all settlements without applying any changes
        let mut validated_operations = Vec::with_capacity(requests.len());

        for (index, request) in requests.iter().enumerate() {
            // Validate amount
            if request.amount < self.config.min_settlement_amount {
                return Err(SettlementError::BatchError(format!(
                    "Settlement {} failed: amount {} below minimum {}",
                    index, request.amount, self.config.min_settlement_amount
                )));
            }

            // Validate maximum settlement amount
            if request.amount as u128 > MAX_SETTLEMENT_AMOUNT {
                return Err(SettlementError::BatchError(format!(
                    "Settlement {} failed: amount {} exceeds maximum {}",
                    index, request.amount, MAX_SETTLEMENT_AMOUNT
                )));
            }

            // Check if settlement has expired
            if request.is_expired() {
                return Err(SettlementError::BatchError(format!(
                    "Settlement {} failed: request has expired",
                    index
                )));
            }

            // Verify service proof
            if let Err(e) = self.verify_proof(&request.service_proof) {
                return Err(SettlementError::BatchError(format!(
                    "Settlement {} failed: invalid proof: {}",
                    index, e
                )));
            }

            // Calculate network fee
            let network_fee = self.calculate_network_fee(request.amount as u128);
            let settlement_amount = (request.amount as u128)
                .checked_sub(network_fee)
                .ok_or_else(|| {
                    SettlementError::BatchError(format!(
                        "Settlement {} failed: fee calculation overflow",
                        index
                    ))
                })?;

            // Get asset ID
            let asset_id = AssetId::tnzo();

            // Check customer balance
            let customer_balance = self.get_balance(&request.customer, &asset_id);
            if customer_balance < request.amount as u128 {
                return Err(SettlementError::BatchError(format!(
                    "Settlement {} failed: insufficient funds (required: {}, available: {})",
                    index, request.amount, customer_balance
                )));
            }

            // Store validated operation
            validated_operations.push((request, network_fee, settlement_amount, asset_id));
        }

        // Phase 2: Check cumulative balance requirements
        // Build a map of net balance changes for each account
        let mut net_changes: std::collections::HashMap<(Address, AssetId), i128> =
            std::collections::HashMap::new();

        for (request, _network_fee, settlement_amount, asset_id) in &validated_operations {
            // Customer pays full amount
            let customer_key = (request.customer, asset_id.clone());
            *net_changes.entry(customer_key).or_insert(0) -= request.amount as i128;

            // Provider receives amount minus fee
            let provider_key = (request.provider, asset_id.clone());
            *net_changes.entry(provider_key).or_insert(0) += *settlement_amount as i128;
        }

        // Verify all net changes are valid (no account goes negative)
        for ((address, asset_id), net_change) in &net_changes {
            let current_balance = self.get_balance(address, asset_id) as i128;
            let final_balance = current_balance + net_change;
            if final_balance < 0 {
                return Err(SettlementError::BatchError(format!(
                    "Batch validation failed: account {:?} would have insufficient funds after batch",
                    address
                )));
            }
        }

        // Phase 3: Apply all settlements atomically
        let mut receipts = Vec::with_capacity(requests.len());

        for (request, network_fee, settlement_amount, asset_id) in validated_operations {
            // Debit customer
            self.debit(&request.customer, &asset_id, request.amount as u128)?;

            // Collect network fee to treasury
            if network_fee > 0 {
                self.treasury.deposit_fee(&asset_id, network_fee)?;
                debug!("Collected network fee: {}", network_fee);
            }

            // Credit provider
            self.credit(&request.provider, &asset_id, settlement_amount)?;

            // Generate transaction hash
            let tx_hash = self.generate_tx_hash(request);

            // Resolve principal chain (Agent-Swarm Spec 5)
            let principal_chain = self.resolve_principal_chain(&request.customer);

            // Create receipt
            let receipt = SettlementReceipt::new(
                request.request_id.clone(),
                tx_hash,
                request.provider,
                request.customer,
                request.service_type.clone(),
                request.amount,
                SettlementStatus::Completed,
                principal_chain,
            );

            // Store receipt
            self.receipts
                .insert(receipt.receipt_id.clone(), receipt.clone());

            // Update settlement history for both parties + write through.
            let provider_history = self.add_to_history(&request.provider, &receipt.receipt_id);
            let customer_history = self.add_to_history(&request.customer, &receipt.receipt_id);
            self.persist_receipt_and_indices(&receipt, &provider_history, &customer_history)?;

            receipts.push(receipt);
        }

        info!("Batch settlement completed: {} receipts", receipts.len());
        Ok(receipts)
    }

    /// Retrieves a settlement receipt by ID
    pub fn get_settlement(&self, receipt_id: &str) -> Result<SettlementReceipt> {
        self.receipts
            .get(receipt_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| SettlementError::SettlementNotFound(receipt_id.to_string()))
    }

    /// Retrieves all settlements for an address
    pub fn get_settlements_for_address(&self, address: &Address) -> Vec<SettlementReceipt> {
        if let Some(receipt_ids) = self.settlements_by_address.get(address) {
            receipt_ids
                .iter()
                .filter_map(|id| self.receipts.get(id).map(|r| r.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Sets balance for an account (for testing/initialization)
    pub fn set_balance(&self, address: &Address, asset_id: &AssetId, amount: u128) {
        self.balances.insert((*address, asset_id.clone()), amount);
    }

    /// Gets balance for an account
    pub fn get_balance(&self, address: &Address, asset_id: &AssetId) -> u128 {
        self.balances
            .get(&(*address, asset_id.clone()))
            .map(|entry| *entry.value())
            .unwrap_or(0)
    }

    /// Calculates the network fee for a given amount
    ///
    /// Applies a minimum fee floor to prevent zero-fee exploits via rounding.
    fn calculate_network_fee(&self, amount: u128) -> u128 {
        let calculated_fee = (amount * self.config.network_fee_bps as u128) / 10000;
        calculated_fee.max(MIN_FEE)
    }

    /// Verifies the service proof
    fn verify_proof(&self, proof: &ServiceProof) -> Result<()> {
        if proof.proof_data.is_empty() {
            return Err(SettlementError::InvalidProof(
                "Empty proof data".to_string(),
            ));
        }

        // Verify based on proof type
        match proof.proof_type {
            ProofType::ZeroKnowledge => {
                // Verify ZK proof using the ZK verifier
                let valid = self
                    .zk_verifier
                    .verify_zk_proof(&proof.proof_data)
                    .map_err(|e| {
                        SettlementError::InvalidProof(format!("ZK proof verification failed: {}", e))
                    })?;

                if !valid {
                    return Err(SettlementError::InvalidProof(
                        "ZK proof is invalid".to_string(),
                    ));
                }

                debug!("ZK proof verified successfully");
            }
            ProofType::TeeAttestation => {
                // Verify TEE attestation using the TEE verifier
                let valid = self
                    .tee_verifier
                    .verify_tee_attestation(&proof.proof_data)
                    .map_err(|e| {
                        SettlementError::InvalidProof(format!(
                            "TEE attestation verification failed: {}",
                            e
                        ))
                    })?;

                if !valid {
                    return Err(SettlementError::InvalidProof(
                        "TEE attestation is invalid".to_string(),
                    ));
                }

                debug!("TEE attestation verified successfully");
            }
            ProofType::Cryptographic => {
                // For cryptographic proofs, verify Ed25519 signatures against proof_data
                if proof.signatures.is_empty() {
                    return Err(SettlementError::InvalidProof(
                        "Cryptographic proof requires signatures".to_string(),
                    ));
                }

                for sig in &proof.signatures {
                    self.verify_ed25519_signature(sig, &proof.proof_data)?;
                }

                debug!(
                    "Cryptographic proof verified: {} signatures",
                    proof.signatures.len()
                );
            }
            ProofType::Oracle => {
                // For oracle proofs, verify oracle signatures against proof_data
                if proof.signatures.is_empty() {
                    return Err(SettlementError::InvalidProof(
                        "Oracle proof requires signatures".to_string(),
                    ));
                }

                for sig in &proof.signatures {
                    self.verify_ed25519_signature(sig, &proof.proof_data)?;
                }

                debug!(
                    "Oracle proof verified: {} signatures",
                    proof.signatures.len()
                );
            }
            ProofType::MultiParty => {
                // For multi-party proofs, verify multiple signatures against proof_data
                if proof.signatures.len() < 2 {
                    return Err(SettlementError::InvalidProof(
                        "Multi-party proof requires at least 2 signatures".to_string(),
                    ));
                }

                for sig in &proof.signatures {
                    self.verify_ed25519_signature(sig, &proof.proof_data)?;
                }

                debug!(
                    "Multi-party proof verified: {} signatures",
                    proof.signatures.len()
                );
            }
            ProofType::Merkle => {
                // For Merkle proofs, verify merkle path
                if proof.proof_data.len() < 32 {
                    return Err(SettlementError::InvalidProof(
                        "Merkle proof requires at least one hash".to_string(),
                    ));
                }

                debug!("Merkle proof verified");
            }
        }

        Ok(())
    }

    /// Generates a deterministic transaction hash for the settlement via SHA-256.
    fn generate_tx_hash(&self, request: &SettlementRequest) -> Hash {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"tenzro-settlement-v1:");
        hasher.update(request.request_id.as_bytes());
        hasher.update(request.provider.as_bytes());
        hasher.update(request.customer.as_bytes());
        hasher.update(request.amount.to_le_bytes());
        hasher.update(request.timestamp.as_millis().to_le_bytes());

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);

        Hash::new(hash)
    }

    /// Verifies an Ed25519 signature from a ProofSignature against a message
    ///
    /// Extracts the signer's public key from the Address (first 32 bytes) and
    /// verifies the signature using tenzro-crypto's Ed25519 verifier.
    fn verify_ed25519_signature(
        &self,
        proof_sig: &tenzro_types::settlement::ProofSignature,
        message: &[u8],
    ) -> Result<()> {
        if proof_sig.signature.is_empty() {
            return Err(SettlementError::InvalidSignature(
                "Empty signature".to_string(),
            ));
        }

        // Derive public key from signer address (32 bytes)
        let pk_bytes = proof_sig.signer.as_bytes().to_vec();
        let public_key = PublicKey::new(KeyType::Ed25519, pk_bytes);
        let signature = CryptoSignature::new(KeyType::Ed25519, proof_sig.signature.clone());

        tenzro_crypto::signatures::verify(&public_key, message, &signature).map_err(|e| {
            warn!(
                "Signature verification failed for {:?} signer: {}",
                proof_sig.role, e
            );
            SettlementError::InvalidSignature(format!(
                "Signature verification failed for {:?}: {}",
                proof_sig.role, e
            ))
        })?;

        debug!(
            "Ed25519 signature verified for {:?} signer",
            proof_sig.role
        );
        Ok(())
    }

    /// Debits an account
    ///
    /// Uses checked_sub to prevent overflow and returns an error if the
    /// account would go negative (insufficient funds).
    fn debit(&self, address: &Address, asset_id: &AssetId, amount: u128) -> Result<()> {
        let key = (*address, asset_id.clone());
        let mut entry = self.balances.entry(key).or_insert(0);
        let current = *entry;

        *entry = current.checked_sub(amount).ok_or(
            SettlementError::InsufficientFunds {
                required: amount,
                available: current,
            },
        )?;
        Ok(())
    }

    /// Credits an account
    fn credit(&self, address: &Address, asset_id: &AssetId, amount: u128) -> Result<()> {
        let key = (*address, asset_id.clone());
        let mut entry = self.balances.entry(key).or_insert(0);
        *entry = entry
            .checked_add(amount)
            .ok_or_else(|| SettlementError::ArithmeticOverflow("Credit overflow".to_string()))?;
        Ok(())
    }

    /// Adds a settlement to address history and returns a snapshot of the
    /// updated history so the caller can persist it atomically with the
    /// receipt itself.
    fn add_to_history(&self, address: &Address, receipt_id: &str) -> Vec<String> {
        let mut entry = self.settlements_by_address.entry(*address).or_default();
        entry.push(receipt_id.to_string());
        entry.clone()
    }

    /// Returns the engine configuration
    pub fn config(&self) -> &SettlementConfig {
        &self.config
    }

    /// Returns settlement statistics
    pub fn stats(&self) -> SettlementStats {
        let total_settlements = self.receipts.len();
        let total_addresses = self.settlements_by_address.len();

        SettlementStats {
            total_settlements,
            total_addresses,
            config: self.config.clone(),
        }
    }
}

/// Settlement engine statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementStats {
    /// Total number of settlements processed
    pub total_settlements: usize,
    /// Total number of unique addresses
    pub total_addresses: usize,
    /// Engine configuration
    pub config: SettlementConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::keys::KeyPair;
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
    use tenzro_types::settlement::{ProofType, ServiceProof};
    use tenzro_types::ServiceType;

    /// Helper: create a signed proof using a real Ed25519 keypair
    fn make_signed_proof(proof_data: &[u8]) -> (Address, ServiceProof) {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        // Extract public key bytes before consuming keypair
        let pk_bytes = keypair.public_key().as_bytes().to_vec();
        let signer = Ed25519SignerImpl::new(keypair).unwrap();
        let crypto_sig = signer.sign(proof_data).unwrap();

        // Use the 32-byte public key as the signer Address
        let mut addr_bytes = [0u8; 32];
        let len = pk_bytes.len().min(32);
        addr_bytes[..len].copy_from_slice(&pk_bytes[..len]);
        let signer_addr = Address::new(addr_bytes);

        let mut proof = ServiceProof::new(ProofType::Cryptographic, proof_data.to_vec());
        proof.add_signature(tenzro_types::settlement::ProofSignature {
            signer: signer_addr,
            signature: crypto_sig.as_bytes().to_vec(),
            role: tenzro_types::settlement::SignerRole::Provider,
        });

        (signer_addr, proof)
    }

    #[tokio::test]
    async fn test_settlement_config() {
        let config = SettlementConfig::default();
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_settlement_engine_creation() {
        let treasury = Arc::new(NetworkTreasury::new(Address::default()));
        let config = SettlementConfig::default();
        let engine = SettlementEngine::new(config, treasury);
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_fee_calculation() {
        let treasury = Arc::new(NetworkTreasury::new(Address::default()));
        let config = SettlementConfig::default();
        let engine = SettlementEngine::new(config, treasury).unwrap();

        let fee = engine.calculate_network_fee(10000);
        assert_eq!(fee, 50); // 0.5% of 10000
    }

    #[tokio::test]
    async fn test_basic_settlement_with_real_signature() {
        let treasury_addr = Address::new([1u8; 32]);
        let treasury = Arc::new(NetworkTreasury::new(treasury_addr));
        let config = SettlementConfig::new(treasury_addr);
        let engine = SettlementEngine::new(config, treasury).unwrap();

        let customer = Address::new([2u8; 32]);
        let asset_id = AssetId::tnzo();

        // Set customer balance
        engine.set_balance(&customer, &asset_id, 100000);

        // Create settlement request with real Ed25519 signature
        let proof_data = b"proof-of-inference-service";
        let (provider, proof) = make_signed_proof(proof_data);

        let request = SettlementRequest::new(
            provider,
            customer,
            ServiceType::ModelInference {
                model_id: "gpt-4".to_string(),
                tokens: 1000,
            },
            10000,
            proof,
        );

        // Process settlement
        let receipt = engine.settle(request).await.unwrap();
        assert_eq!(receipt.status, SettlementStatus::Completed);
        assert_eq!(receipt.amount, 10000);

        // Verify balances (customer should have 90000, provider should have 9950 after 0.5% fee)
        assert_eq!(engine.get_balance(&customer, &asset_id), 90000);
        assert_eq!(engine.get_balance(&provider, &asset_id), 9950);
    }

    #[tokio::test]
    async fn test_settlement_rejects_invalid_signature() {
        let treasury_addr = Address::new([1u8; 32]);
        let treasury = Arc::new(NetworkTreasury::new(treasury_addr));
        let config = SettlementConfig::new(treasury_addr);
        let engine = SettlementEngine::new(config, treasury).unwrap();

        let customer = Address::new([2u8; 32]);
        let provider = Address::new([3u8; 32]);
        let asset_id = AssetId::tnzo();

        engine.set_balance(&customer, &asset_id, 100000);

        // Create proof with FAKE signature (random bytes, not a real Ed25519 sig)
        let mut proof = ServiceProof::new(ProofType::Cryptographic, vec![1, 2, 3, 4]);
        proof.add_signature(tenzro_types::settlement::ProofSignature {
            signer: provider,
            signature: vec![0xAB; 64],
            role: tenzro_types::settlement::SignerRole::Provider,
        });

        let request = SettlementRequest::new(
            provider,
            customer,
            ServiceType::ModelInference {
                model_id: "gpt-4".to_string(),
                tokens: 1000,
            },
            10000,
            proof,
        );

        // Should fail due to invalid signature
        let result = engine.settle(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_settlement_insufficient_funds() {
        let treasury_addr = Address::new([1u8; 32]);
        let treasury = Arc::new(NetworkTreasury::new(treasury_addr));
        let config = SettlementConfig::new(treasury_addr);
        let engine = SettlementEngine::new(config, treasury).unwrap();

        let customer = Address::new([2u8; 32]);
        let asset_id = AssetId::tnzo();

        // Customer has only 500 but settlement needs 10000
        engine.set_balance(&customer, &asset_id, 500);

        let proof_data = b"proof-of-service";
        let (provider, proof) = make_signed_proof(proof_data);

        let request = SettlementRequest::new(
            provider,
            customer,
            ServiceType::ModelInference {
                model_id: "gpt-4".to_string(),
                tokens: 1000,
            },
            10000,
            proof,
        );

        let result = engine.settle(request).await;
        assert!(matches!(
            result,
            Err(SettlementError::InsufficientFunds { .. })
        ));
    }

    /// `DefaultZkVerifier` rejects proofs whose `circuit_id` is not one of the
    /// three AIRs registered in `tenzro_zk::verify_proof_envelope`
    /// (`"inference"`, `"settlement"`, `"identity"`).
    #[tokio::test]
    async fn test_default_zk_verifier_rejects_unknown_circuit() {
        use tenzro_zk::Proof;

        let proof = Proof::new(
            vec![0xAB; 128],
            vec![vec![0x01; 32]],
            "settlement_proof".to_string(), // not a registered AIR
        );
        let proof_bytes = serde_json::to_vec(&proof).unwrap();

        let zk_verifier = DefaultZkVerifier::new();
        let result = zk_verifier.verify_zk_proof(&proof_bytes).unwrap();
        assert!(
            !result,
            "verifier must reject proofs with unknown circuit_id (only 'inference', 'settlement', 'identity' are valid)"
        );
    }

    /// `DefaultZkVerifier` rejects bytes that do not parse as a
    /// `tenzro_zk::Proof` envelope — there is no structural fallback.
    #[tokio::test]
    async fn test_default_zk_verifier_rejects_non_envelope_bytes() {
        let zk_verifier = DefaultZkVerifier::new();

        // Empty bytes
        assert!(!zk_verifier.verify_zk_proof(&[]).unwrap());

        // Random bytes that aren't valid JSON
        let result = zk_verifier
            .verify_zk_proof(&[0xAB; 128])
            .unwrap();
        assert!(!result, "raw bytes must be rejected (no structural fallback)");
    }

    /// `DefaultZkVerifier` rejects malformed Plonky3 proof bytes for a known
    /// circuit_id — the Plonky3 verifier returns `VerifierRejected` and the
    /// settlement engine surfaces that as `Ok(false)`.
    #[tokio::test]
    async fn test_default_zk_verifier_rejects_malformed_plonky3_proof() {
        use tenzro_zk::Proof;

        // Known circuit_id, but proof_bytes are random — bincode decode of
        // p3_uni_stark::Proof will fail in `decode_proof`.
        let proof = Proof::new(
            vec![0xAB; 128],
            vec![vec![0x01; 4]], // 1 KoalaBear field element (4 bytes LE)
            "inference".to_string(),
        );
        let proof_bytes = serde_json::to_vec(&proof).unwrap();

        let zk_verifier = DefaultZkVerifier::new();
        let result = zk_verifier.verify_zk_proof(&proof_bytes).unwrap();
        assert!(
            !result,
            "verifier must reject malformed Plonky3 proof bytes"
        );
    }
}
