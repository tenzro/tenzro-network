//! Escrow system for pre-funded settlements with release conditions.
//!
//! # On-chain primitive
//!
//! Escrow is a **consensus-mediated** primitive. Funds are locked on-chain at
//! a vault address derived deterministically from the escrow id; only the
//! original signing payer can later release funds to the payee or refund them
//! to themselves. The Native VM is the source of truth for funds and state.
//!
//! Clients submit signed `CreateEscrow` / `ReleaseEscrow` / `RefundEscrow`
//! transactions through the standard transaction pipeline (mempool → block →
//! VM dispatch). The convenience RPC handlers `tenzro_createEscrow` and
//! `tenzro_releaseEscrow` have been removed; the only writes are signed
//! transactions.
//!
//! ## Deterministic identifiers
//!
//! - **`escrow_id`** = `SHA-256("tenzro/escrow/id" || payer || nonce_le)`,
//!   derived by the VM at `CreateEscrow` execution time and surfaced via the
//!   receipt log.
//! - **Vault address** = `Address(SHA-256("tenzro/escrow/vault" || escrow_id))`.
//!   Has no private key. Release/refund payouts are a privileged VM operation
//!   that calls `state.set_balance` directly via a single auditable helper,
//!   never via normal `TnzoToken::transfer`.
//!
//! ## Authorization invariants (enforced by VM)
//!
//! - `CreateEscrow.from` must match the signing payer (verified at mempool
//!   admission). The payload has no separate `payer` field.
//! - `ReleaseEscrow` requires `tx.from == escrow.payer`, status `Funded`,
//!   not expired, and a proof that satisfies the recorded `release_conditions`.
//! - `RefundEscrow` requires `tx.from == escrow.payer` AND (the escrow is
//!   expired OR `release_conditions ∈ {Timeout, Custom}`).
//!
//! # Manager role
//!
//! The [`EscrowManager`] in this module is a **denormalized query cache** for
//! read RPCs (`tenzro_getEscrow`, `tenzro_listEscrowsByPayer`,
//! `tenzro_listEscrowsByPayee`) and the VM's write path. It is **not** the
//! source of truth for funds. The VM's account state is.
//!
//! # Persistence
//!
//! When constructed via [`EscrowManager::with_storage`], escrow records are
//! persisted to `CF_SETTLEMENTS` under the following key prefixes and
//! rehydrated on startup:
//!
//! | Prefix              | Value                              |
//! |---------------------|------------------------------------|
//! | `escrow:<id>`       | `EscrowAccount` (JSON)             |
//! | `escrow_payer:<addr>` | `Vec<String>` of escrow IDs (JSON) |
//! | `escrow_payee:<addr>` | `Vec<String>` of escrow IDs (JSON) |
//!
//! All multi-key mutations use `KvStore::write_batch_sync` for atomic, fsync'd
//! writes.

use crate::error::{Result, SettlementError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_crypto::signatures::Signature as CryptoSignature;
use tenzro_storage::{KvStore, WriteOp, CF_SETTLEMENTS};
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_types::settlement::{ReleaseConditions, ServiceProof};
use tracing::{debug, info, warn};

/// Storage key prefix for `EscrowAccount` records in `CF_SETTLEMENTS`.
const ESCROW_KEY_PREFIX: &[u8] = b"escrow:";
/// Storage key prefix for the per-payer index of escrow IDs.
const ESCROW_PAYER_KEY_PREFIX: &[u8] = b"escrow_payer:";
/// Storage key prefix for the per-payee index of escrow IDs.
const ESCROW_PAYEE_KEY_PREFIX: &[u8] = b"escrow_payee:";

/// Status of an escrow account
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscrowStatus {
    /// Funds are locked in escrow
    Funded,
    /// Funds have been released to payee
    Released,
    /// Funds have been refunded to payer
    Refunded,
    /// Escrow has expired
    Expired,
}

/// An escrow account holding funds for a settlement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowAccount {
    /// Unique escrow identifier
    pub escrow_id: String,
    /// Address of the payer (funds locked from this address)
    pub payer: Address,
    /// Address of the payee (funds will be released to this address)
    pub payee: Address,
    /// Amount held in escrow
    pub amount: u128,
    /// Asset being held
    pub asset_id: AssetId,
    /// Timestamp when escrow was created
    pub created_at: Timestamp,
    /// Timestamp when escrow expires
    pub expires_at: Timestamp,
    /// Current status
    pub status: EscrowStatus,
    /// Conditions for release
    pub release_conditions: ReleaseConditions,
}

impl EscrowAccount {
    /// Creates a new escrow account
    pub fn new(
        payer: Address,
        payee: Address,
        amount: u128,
        asset_id: AssetId,
        expires_at: Timestamp,
        release_conditions: ReleaseConditions,
    ) -> Self {
        Self {
            escrow_id: uuid::Uuid::new_v4().to_string(),
            payer,
            payee,
            amount,
            asset_id,
            created_at: Timestamp::now(),
            expires_at,
            status: EscrowStatus::Funded,
            release_conditions,
        }
    }

    /// Checks if the escrow has expired
    pub fn is_expired(&self) -> bool {
        Timestamp::now() > self.expires_at
    }

    /// Checks if the escrow can be released
    pub fn can_release(&self) -> bool {
        self.status == EscrowStatus::Funded && !self.is_expired()
    }

    /// Checks if the escrow can be refunded
    pub fn can_refund(&self) -> bool {
        self.status == EscrowStatus::Funded
            && (self.is_expired()
                || matches!(
                    self.release_conditions,
                    ReleaseConditions::Timeout | ReleaseConditions::Custom { .. }
                ))
    }
}

/// Escrow manager for handling pre-funded settlements
pub struct EscrowManager {
    /// Escrow accounts by ID
    escrows: DashMap<String, EscrowAccount>,
    /// Escrows by payer address
    escrows_by_payer: DashMap<Address, Vec<String>>,
    /// Escrows by payee address
    escrows_by_payee: DashMap<Address, Vec<String>>,
    /// Account balances (simplified - in production would integrate with account storage)
    balances: Arc<DashMap<(Address, AssetId), u128>>,
    /// Optional persistent storage backend. When set, all mutations write
    /// through to `CF_SETTLEMENTS` so the catalog survives restarts.
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for EscrowManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EscrowManager")
            .field("escrows", &self.escrows.len())
            .field("escrows_by_payer", &self.escrows_by_payer.len())
            .field("escrows_by_payee", &self.escrows_by_payee.len())
            .field("storage", &self.storage.as_ref().map(|_| "Some(Arc<dyn KvStore>)"))
            .finish()
    }
}

impl EscrowManager {
    /// Creates a new in-memory escrow manager (no persistence).
    ///
    /// Use [`EscrowManager::with_storage`] for a persistent manager that
    /// rehydrates from `CF_SETTLEMENTS` on construction.
    pub fn new(balances: Arc<DashMap<(Address, AssetId), u128>>) -> Self {
        Self {
            escrows: DashMap::new(),
            escrows_by_payer: DashMap::new(),
            escrows_by_payee: DashMap::new(),
            balances,
            storage: None,
        }
    }

    /// Creates an escrow manager backed by persistent RocksDB storage.
    ///
    /// On construction, scans `CF_SETTLEMENTS` for `escrow:` records and
    /// rebuilds in-memory indices. Subsequent mutations
    /// (`create_escrow`, `release_escrow`, `refund_escrow`, `check_expired`)
    /// write through atomically via `write_batch_sync`.
    pub fn with_storage(
        balances: Arc<DashMap<(Address, AssetId), u128>>,
        storage: Arc<dyn KvStore>,
    ) -> Self {
        let mgr = Self {
            escrows: DashMap::new(),
            escrows_by_payer: DashMap::new(),
            escrows_by_payee: DashMap::new(),
            balances,
            storage: Some(storage),
        };
        mgr.hydrate();
        mgr
    }

    /// Storage key for an escrow record: `escrow:<escrow_id>`.
    fn escrow_storage_key(escrow_id: &str) -> Vec<u8> {
        [ESCROW_KEY_PREFIX, escrow_id.as_bytes()].concat()
    }

    /// Storage key for a payer index: `escrow_payer:<address_hex>`.
    fn payer_index_key(addr: &Address) -> Vec<u8> {
        [ESCROW_PAYER_KEY_PREFIX, hex::encode(addr.as_bytes()).as_bytes()].concat()
    }

    /// Storage key for a payee index: `escrow_payee:<address_hex>`.
    fn payee_index_key(addr: &Address) -> Vec<u8> {
        [ESCROW_PAYEE_KEY_PREFIX, hex::encode(addr.as_bytes()).as_bytes()].concat()
    }

    /// Rehydrates the in-memory state from persistent storage.
    fn hydrate(&self) {
        let storage = match &self.storage {
            Some(s) => s,
            None => return,
        };

        let keys = match storage.get_keys_with_prefix(CF_SETTLEMENTS, ESCROW_KEY_PREFIX) {
            Ok(keys) => keys,
            Err(e) => {
                warn!("Failed to scan CF_SETTLEMENTS for escrow hydration: {}", e);
                return;
            }
        };

        let mut hydrated = 0usize;
        for key_bytes in &keys {
            match storage.get(CF_SETTLEMENTS, key_bytes) {
                Ok(Some(data)) => match serde_json::from_slice::<EscrowAccount>(&data) {
                    Ok(escrow) => {
                        let id = escrow.escrow_id.clone();
                        // Rebuild indices in memory (do not re-persist; they
                        // already exist in storage under their own prefixes).
                        self.escrows_by_payer
                            .entry(escrow.payer)
                            .or_default()
                            .push(id.clone());
                        self.escrows_by_payee
                            .entry(escrow.payee)
                            .or_default()
                            .push(id.clone());
                        self.escrows.insert(id, escrow);
                        hydrated += 1;
                    }
                    Err(e) => {
                        let key_str = std::str::from_utf8(key_bytes).unwrap_or("<binary>");
                        warn!("Failed to deserialize escrow at key {}: {}", key_str, e);
                    }
                },
                Ok(None) => {}
                Err(e) => warn!("Storage read failure during EscrowManager hydration: {}", e),
            }
        }

        if hydrated > 0 {
            info!("Hydrated {} escrow(s) from RocksDB CF_SETTLEMENTS", hydrated);
        }
    }

    /// Atomically persists an escrow record and its payer/payee index entries.
    fn persist_escrow_atomic(&self, escrow: &EscrowAccount, indices_changed: bool) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };

        let escrow_data = serde_json::to_vec(escrow)
            .map_err(|e| SettlementError::StorageError(format!("serialize escrow: {}", e)))?;
        let mut ops = vec![WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: Self::escrow_storage_key(&escrow.escrow_id),
            value: escrow_data,
        }];

        if indices_changed {
            // Rewrite the payer + payee index lists to reflect current in-memory state.
            let payer_ids: Vec<String> = self
                .escrows_by_payer
                .get(&escrow.payer)
                .map(|v| v.value().clone())
                .unwrap_or_default();
            let payee_ids: Vec<String> = self
                .escrows_by_payee
                .get(&escrow.payee)
                .map(|v| v.value().clone())
                .unwrap_or_default();

            let payer_data = serde_json::to_vec(&payer_ids)
                .map_err(|e| SettlementError::StorageError(format!("serialize payer index: {}", e)))?;
            let payee_data = serde_json::to_vec(&payee_ids)
                .map_err(|e| SettlementError::StorageError(format!("serialize payee index: {}", e)))?;

            ops.push(WriteOp::Put {
                cf: CF_SETTLEMENTS.to_string(),
                key: Self::payer_index_key(&escrow.payer),
                value: payer_data,
            });
            ops.push(WriteOp::Put {
                cf: CF_SETTLEMENTS.to_string(),
                key: Self::payee_index_key(&escrow.payee),
                value: payee_data,
            });
        }

        storage
            .write_batch_sync(ops)
            .map_err(|e| SettlementError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Creates a new escrow and locks funds from payer
    pub fn create_escrow(
        &self,
        payer: Address,
        payee: Address,
        amount: u128,
        asset_id: AssetId,
        expires_at: Timestamp,
        release_conditions: ReleaseConditions,
    ) -> Result<EscrowAccount> {
        if amount == 0 {
            return Err(SettlementError::InvalidAmount(
                "Amount must be greater than zero".to_string(),
            ));
        }

        // Check payer balance
        let key = (payer, asset_id.clone());
        let balance = self.balances.get(&key).map(|e| *e.value()).unwrap_or(0);

        if balance < amount {
            return Err(SettlementError::InsufficientFunds {
                required: amount,
                available: balance,
            });
        }

        // Lock funds from payer
        let mut entry = self.balances.entry(key).or_insert(0);
        *entry = entry
            .checked_sub(amount)
            .ok_or_else(|| SettlementError::ArithmeticOverflow("Debit overflow".to_string()))?;
        drop(entry);

        // Create escrow account
        let escrow = EscrowAccount::new(
            payer,
            payee,
            amount,
            asset_id,
            expires_at,
            release_conditions,
        );

        let escrow_id = escrow.escrow_id.clone();

        // Store escrow
        self.escrows.insert(escrow_id.clone(), escrow.clone());

        // Index by payer
        self.escrows_by_payer
            .entry(payer)
            .or_default()
            .push(escrow_id.clone());

        // Index by payee
        self.escrows_by_payee
            .entry(payee)
            .or_default()
            .push(escrow_id.clone());

        // Write-through to persistent storage (atomic across record + indices).
        self.persist_escrow_atomic(&escrow, true)?;

        info!(
            "Created escrow {} for {} from {} to {}",
            escrow.escrow_id, amount, payer, payee
        );

        Ok(escrow)
    }

    /// Releases escrow to payee upon proof verification
    pub fn release_escrow(&self, escrow_id: &str, proof: &ServiceProof) -> Result<()> {
        let mut escrow_entry = self
            .escrows
            .get_mut(escrow_id)
            .ok_or_else(|| SettlementError::EscrowNotFound(escrow_id.to_string()))?;

        let escrow = escrow_entry.value_mut();

        // Check if escrow can be released
        if escrow.status != EscrowStatus::Funded {
            return Err(SettlementError::EscrowAlreadyReleased(escrow_id.to_string()));
        }

        if escrow.is_expired() {
            return Err(SettlementError::EscrowExpired(escrow_id.to_string()));
        }

        // Verify proof matches release conditions
        self.verify_release_conditions(&escrow.release_conditions, proof)?;

        // Credit payee
        let key = (escrow.payee, escrow.asset_id.clone());
        let mut balance_entry = self.balances.entry(key).or_insert(0);
        *balance_entry = balance_entry.checked_add(escrow.amount).ok_or_else(|| {
            SettlementError::ArithmeticOverflow("Credit overflow".to_string())
        })?;
        drop(balance_entry);

        // Update escrow status
        escrow.status = EscrowStatus::Released;

        // Snapshot for persistence after dropping the mutable guard.
        let snapshot = escrow.clone();
        drop(escrow_entry);
        self.persist_escrow_atomic(&snapshot, false)?;

        info!("Released escrow {} to {}", escrow_id, snapshot.payee);

        Ok(())
    }

    /// Refunds escrow to payer (timeout or dispute)
    pub fn refund_escrow(&self, escrow_id: &str) -> Result<()> {
        let mut escrow_entry = self
            .escrows
            .get_mut(escrow_id)
            .ok_or_else(|| SettlementError::EscrowNotFound(escrow_id.to_string()))?;

        let escrow = escrow_entry.value_mut();

        // Check if escrow can be refunded
        if escrow.status != EscrowStatus::Funded {
            return Err(SettlementError::EscrowAlreadyReleased(escrow_id.to_string()));
        }

        // Credit payer (refund)
        let key = (escrow.payer, escrow.asset_id.clone());
        let mut balance_entry = self.balances.entry(key).or_insert(0);
        *balance_entry = balance_entry.checked_add(escrow.amount).ok_or_else(|| {
            SettlementError::ArithmeticOverflow("Credit overflow".to_string())
        })?;
        drop(balance_entry);

        // Update escrow status
        escrow.status = EscrowStatus::Refunded;

        // Snapshot for persistence after dropping the mutable guard.
        let snapshot = escrow.clone();
        drop(escrow_entry);
        self.persist_escrow_atomic(&snapshot, false)?;

        info!("Refunded escrow {} to {}", escrow_id, snapshot.payer);

        Ok(())
    }

    /// Gets an escrow by ID
    pub fn get_escrow(&self, escrow_id: &str) -> Result<EscrowAccount> {
        self.escrows
            .get(escrow_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| SettlementError::EscrowNotFound(escrow_id.to_string()))
    }

    /// Gets all escrows for a payer
    pub fn get_escrows_by_payer(&self, payer: &Address) -> Vec<EscrowAccount> {
        if let Some(escrow_ids) = self.escrows_by_payer.get(payer) {
            escrow_ids
                .iter()
                .filter_map(|id| self.escrows.get(id).map(|e| e.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Gets all escrows for a payee
    pub fn get_escrows_by_payee(&self, payee: &Address) -> Vec<EscrowAccount> {
        if let Some(escrow_ids) = self.escrows_by_payee.get(payee) {
            escrow_ids
                .iter()
                .filter_map(|id| self.escrows.get(id).map(|e| e.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Checks and refunds expired escrows
    pub fn check_expired(&self) -> usize {
        let expired_ids: Vec<String> = self
            .escrows
            .iter()
            .filter(|entry| {
                let escrow = entry.value();
                escrow.status == EscrowStatus::Funded && escrow.is_expired()
            })
            .map(|entry| entry.key().clone())
            .collect();

        let count = expired_ids.len();

        for escrow_id in expired_ids {
            if let Err(e) = self.refund_escrow(&escrow_id) {
                warn!("Failed to refund expired escrow {}: {}", escrow_id, e);
            } else {
                debug!("Auto-refunded expired escrow: {}", escrow_id);
            }
        }

        if count > 0 {
            info!("Processed {} expired escrows", count);
        }

        count
    }

    /// Verifies release conditions against provided proof
    fn verify_release_conditions(
        &self,
        conditions: &ReleaseConditions,
        proof: &ServiceProof,
    ) -> Result<()> {
        verify_release_conditions(conditions, proof)
    }

    /// Returns escrow statistics
    pub fn stats(&self) -> EscrowStats {
        let total_escrows = self.escrows.len();
        let mut funded = 0;
        let mut released = 0;
        let mut refunded = 0;
        let mut expired = 0;

        for entry in self.escrows.iter() {
            match entry.value().status {
                EscrowStatus::Funded => funded += 1,
                EscrowStatus::Released => released += 1,
                EscrowStatus::Refunded => refunded += 1,
                EscrowStatus::Expired => expired += 1,
            }
        }

        EscrowStats {
            total_escrows,
            funded,
            released,
            refunded,
            expired,
        }
    }
}

/// Escrow statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowStats {
    /// Total number of escrows
    pub total_escrows: usize,
    /// Number of funded escrows
    pub funded: usize,
    /// Number of released escrows
    pub released: usize,
    /// Number of refunded escrows
    pub refunded: usize,
    /// Number of expired escrows
    pub expired: usize,
}

/// Stand-alone verification of release conditions against a proof.
///
/// Mirrors [`EscrowManager::verify_release_conditions`] but does not depend on a
/// manager instance, so it can be invoked directly by the Native VM during
/// `ReleaseEscrow` execution.
pub fn verify_release_conditions(
    conditions: &ReleaseConditions,
    proof: &ServiceProof,
) -> Result<()> {
    match conditions {
        ReleaseConditions::ProviderSignature => {
            if proof.signatures.is_empty() {
                return Err(SettlementError::InvalidProof(
                    "No provider signature found".to_string(),
                ));
            }
            verify_signature(&proof.signatures[0], &proof.proof_data)?;
            debug!("Verified provider signature");
            Ok(())
        }
        ReleaseConditions::ConsumerSignature => {
            if proof.signatures.is_empty() {
                return Err(SettlementError::InvalidProof(
                    "No consumer signature found".to_string(),
                ));
            }
            verify_signature(&proof.signatures[0], &proof.proof_data)?;
            debug!("Verified consumer signature");
            Ok(())
        }
        ReleaseConditions::BothSignatures => {
            if proof.signatures.len() < 2 {
                return Err(SettlementError::InvalidProof(
                    "Insufficient signatures (need 2)".to_string(),
                ));
            }
            verify_signature(&proof.signatures[0], &proof.proof_data)?;
            verify_signature(&proof.signatures[1], &proof.proof_data)?;
            debug!("Verified both signatures");
            Ok(())
        }
        ReleaseConditions::VerifierSignature => {
            if proof.signatures.is_empty() {
                return Err(SettlementError::InvalidProof(
                    "No verifier signature found".to_string(),
                ));
            }
            verify_signature(&proof.signatures[0], &proof.proof_data)?;
            debug!("Verified verifier signature");
            Ok(())
        }
        ReleaseConditions::Timeout => Ok(()),
        ReleaseConditions::Custom { condition } => {
            if proof.proof_data.is_empty() {
                return Err(SettlementError::InvalidProof(
                    "No proof data for custom condition".to_string(),
                ));
            }
            debug!("Verifying custom condition: {}", condition);
            Ok(())
        }
    }
}

/// Stand-alone Ed25519 signature verification used by [`verify_release_conditions`].
fn verify_signature(
    proof_signature: &tenzro_types::settlement::ProofSignature,
    message: &[u8],
) -> Result<()> {
    if proof_signature.signature.is_empty() {
        return Err(SettlementError::InvalidSignature(
            "Empty signature".to_string(),
        ));
    }

    // Extract public key from signer address (first 32 bytes = Ed25519 public key)
    let pk_bytes = proof_signature.signer.as_bytes().to_vec();
    let public_key = PublicKey::new(KeyType::Ed25519, pk_bytes);
    let signature = CryptoSignature::new(KeyType::Ed25519, proof_signature.signature.clone());

    tenzro_crypto::signatures::verify(&public_key, message, &signature).map_err(|e| {
        warn!(
            "Escrow signature verification failed for {:?} signer: {}",
            proof_signature.role, e
        );
        SettlementError::InvalidSignature(format!(
            "Signature verification failed for {:?}: {}",
            proof_signature.role, e
        ))
    })?;

    debug!(
        "Ed25519 signature verified for {:?} signer in escrow",
        proof_signature.role
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::keys::{KeyPair, KeyType};
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
    use tenzro_types::settlement::ProofType;

    /// Helper: generate a real Ed25519 keypair, sign message, return (Address, ProofSignature)
    fn make_signed_proof_sig(
        message: &[u8],
        role: tenzro_types::settlement::SignerRole,
    ) -> (Address, tenzro_types::settlement::ProofSignature) {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        // Extract public key bytes before consuming keypair
        let pk_bytes = keypair.public_key().as_bytes().to_vec();
        let signer = Ed25519SignerImpl::new(keypair).unwrap();
        let crypto_sig = signer.sign(message).unwrap();

        let mut addr_bytes = [0u8; 32];
        let len = pk_bytes.len().min(32);
        addr_bytes[..len].copy_from_slice(&pk_bytes[..len]);
        let signer_addr = Address::new(addr_bytes);

        let proof_sig = tenzro_types::settlement::ProofSignature {
            signer: signer_addr,
            signature: crypto_sig.as_bytes().to_vec(),
            role,
        };

        (signer_addr, proof_sig)
    }

    #[test]
    fn test_escrow_creation() {
        let balances = Arc::new(DashMap::new());
        let manager = EscrowManager::new(balances.clone());

        let payer = Address::new([1u8; 32]);
        let payee = Address::new([2u8; 32]);
        let asset_id = AssetId::tnzo();

        // Set payer balance
        balances.insert((payer, asset_id.clone()), 10000);

        let expires_at = Timestamp::now().as_millis() + 86400000; // 24 hours
        let escrow = manager
            .create_escrow(
                payer,
                payee,
                5000,
                asset_id.clone(),
                Timestamp::new(expires_at),
                ReleaseConditions::ProviderSignature,
            )
            .unwrap();

        assert_eq!(escrow.amount, 5000);
        assert_eq!(escrow.status, EscrowStatus::Funded);

        // Verify payer balance was deducted
        let balance = balances.get(&(payer, asset_id)).unwrap();
        assert_eq!(*balance, 5000);
    }

    #[test]
    fn test_escrow_release_with_real_signature() {
        let balances = Arc::new(DashMap::new());
        let manager = EscrowManager::new(balances.clone());

        let payer = Address::new([1u8; 32]);
        let asset_id = AssetId::tnzo();

        balances.insert((payer, asset_id.clone()), 10000);

        let proof_data = b"service completed successfully";

        // Generate a real Ed25519 signature for the proof
        let (provider_addr, provider_sig) = make_signed_proof_sig(
            proof_data,
            tenzro_types::settlement::SignerRole::Provider,
        );

        let expires_at = Timestamp::now().as_millis() + 86400000;
        let escrow = manager
            .create_escrow(
                payer,
                provider_addr,
                5000,
                asset_id.clone(),
                Timestamp::new(expires_at),
                ReleaseConditions::ProviderSignature,
            )
            .unwrap();

        // Create proof with real provider signature
        let mut proof = ServiceProof::new(ProofType::Cryptographic, proof_data.to_vec());
        proof.add_signature(provider_sig);

        // Release escrow — should succeed with real signature
        manager.release_escrow(&escrow.escrow_id, &proof).unwrap();

        // Verify payee received funds
        let balance = balances.get(&(provider_addr, asset_id)).unwrap();
        assert_eq!(*balance, 5000);

        // Verify escrow status
        let updated_escrow = manager.get_escrow(&escrow.escrow_id).unwrap();
        assert_eq!(updated_escrow.status, EscrowStatus::Released);
    }

    #[test]
    fn test_escrow_release_rejects_invalid_signature() {
        let balances = Arc::new(DashMap::new());
        let manager = EscrowManager::new(balances.clone());

        let payer = Address::new([1u8; 32]);
        let payee = Address::new([2u8; 32]);
        let asset_id = AssetId::tnzo();

        balances.insert((payer, asset_id.clone()), 10000);

        let expires_at = Timestamp::now().as_millis() + 86400000;
        let escrow = manager
            .create_escrow(
                payer,
                payee,
                5000,
                asset_id.clone(),
                Timestamp::new(expires_at),
                ReleaseConditions::ProviderSignature,
            )
            .unwrap();

        // Create proof with FAKE signature (random bytes)
        let mut proof = ServiceProof::new(ProofType::Cryptographic, vec![1, 2, 3]);
        proof.add_signature(tenzro_types::settlement::ProofSignature {
            signer: payee,
            signature: vec![0xAB; 64],
            role: tenzro_types::settlement::SignerRole::Provider,
        });

        // Release should fail — fake signature won't verify
        let result = manager.release_escrow(&escrow.escrow_id, &proof);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), SettlementError::InvalidSignature(_)),
            "Expected InvalidSignature error"
        );
    }

    #[test]
    fn test_escrow_refund() {
        let balances = Arc::new(DashMap::new());
        let manager = EscrowManager::new(balances.clone());

        let payer = Address::new([1u8; 32]);
        let payee = Address::new([2u8; 32]);
        let asset_id = AssetId::tnzo();

        balances.insert((payer, asset_id.clone()), 10000);

        let expires_at = Timestamp::now().as_millis() + 86400000;
        let escrow = manager
            .create_escrow(
                payer,
                payee,
                5000,
                asset_id.clone(),
                Timestamp::new(expires_at),
                ReleaseConditions::Timeout,
            )
            .unwrap();

        // Refund escrow
        manager.refund_escrow(&escrow.escrow_id).unwrap();

        // Verify payer got refund
        let balance = balances.get(&(payer, asset_id)).unwrap();
        assert_eq!(*balance, 10000);

        // Verify escrow status
        let updated_escrow = manager.get_escrow(&escrow.escrow_id).unwrap();
        assert_eq!(updated_escrow.status, EscrowStatus::Refunded);
    }

    #[test]
    fn test_escrow_both_signatures_required() {
        let balances = Arc::new(DashMap::new());
        let manager = EscrowManager::new(balances.clone());

        let payer = Address::new([1u8; 32]);
        let asset_id = AssetId::tnzo();
        let proof_data = b"both parties agree";

        // Generate two real signatures
        let (provider_addr, provider_sig) = make_signed_proof_sig(
            proof_data,
            tenzro_types::settlement::SignerRole::Provider,
        );
        let (_consumer_addr, consumer_sig) = make_signed_proof_sig(
            proof_data,
            tenzro_types::settlement::SignerRole::Consumer,
        );

        balances.insert((payer, asset_id.clone()), 10000);

        let expires_at = Timestamp::now().as_millis() + 86400000;
        let escrow = manager
            .create_escrow(
                payer,
                provider_addr,
                5000,
                asset_id.clone(),
                Timestamp::new(expires_at),
                ReleaseConditions::BothSignatures,
            )
            .unwrap();

        // Create proof with both signatures
        let mut proof = ServiceProof::new(ProofType::Cryptographic, proof_data.to_vec());
        proof.add_signature(provider_sig);
        proof.add_signature(consumer_sig);

        // Release should succeed with both valid signatures
        manager.release_escrow(&escrow.escrow_id, &proof).unwrap();

        let updated_escrow = manager.get_escrow(&escrow.escrow_id).unwrap();
        assert_eq!(updated_escrow.status, EscrowStatus::Released);
    }

    #[test]
    fn test_escrow_persistence_and_hydration() {
        use tenzro_storage::MemoryStore;

        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let balances = Arc::new(DashMap::new());

        let payer = Address::new([7u8; 32]);
        let payee = Address::new([8u8; 32]);
        let asset_id = AssetId::tnzo();
        balances.insert((payer, asset_id.clone()), 10_000);

        let expires_at = Timestamp::now().as_millis() + 86_400_000;
        let escrow_id = {
            let manager = EscrowManager::with_storage(balances.clone(), storage.clone());
            let escrow = manager
                .create_escrow(
                    payer,
                    payee,
                    5_000,
                    asset_id.clone(),
                    Timestamp::new(expires_at),
                    ReleaseConditions::Timeout,
                )
                .unwrap();
            assert_eq!(escrow.status, EscrowStatus::Funded);
            escrow.escrow_id
        };

        // Drop the manager and rebuild from the same storage. The escrow record
        // and indices must rehydrate.
        let manager2 = EscrowManager::with_storage(balances, storage);
        let restored = manager2.get_escrow(&escrow_id).unwrap();
        assert_eq!(restored.payer, payer);
        assert_eq!(restored.payee, payee);
        assert_eq!(restored.amount, 5_000);
        assert_eq!(restored.status, EscrowStatus::Funded);

        // Indices must rebuild too.
        let by_payer = manager2.get_escrows_by_payer(&payer);
        assert_eq!(by_payer.len(), 1);
        assert_eq!(by_payer[0].escrow_id, escrow_id);
        let by_payee = manager2.get_escrows_by_payee(&payee);
        assert_eq!(by_payee.len(), 1);

        // Mutating after rehydration should still write through.
        manager2.refund_escrow(&escrow_id).unwrap();
        let manager3 = EscrowManager::with_storage(
            Arc::new(DashMap::new()),
            // Rehydrate from a fresh manager; balances DashMap is volatile by design.
            // We only verify the escrow record/status persisted.
            manager2.storage.as_ref().unwrap().clone(),
        );
        let after_refund = manager3.get_escrow(&escrow_id).unwrap();
        assert_eq!(after_refund.status, EscrowStatus::Refunded);
    }
}
