//! ComputeBond surety primitive (Phase A #153)
//!
//! Each provider (`Validator` / `ModelProvider` / `TeeProvider` / `StorageProvider`)
//! that wants to register on the network must post a `ComputeBond` first. The
//! bond is held in a deterministic, key-less per-provider vault address and
//! provides skin-in-the-game collateral that consumers can rely on when they
//! discover and route inference traffic to the provider.
//!
//! Lifecycle (mirrors `AgentBondState` from `bond.rs` but simpler — no
//! insurance pool, no slashing math, no claims):
//!
//! - `post`     — provider commits TNZO. Bond becomes Active.
//! - `increase` — top up an Active bond.
//! - `withdraw` — initiate the 7-day unbonding cooldown. Bond is no longer
//!   eligible to back a registration but remains held in the vault.
//! - `finalize_withdrawal` — once cooldown elapses, mark Returned and
//!   surface the funds for VM-level credit back to the provider.
//!
//! State persists in `CF_PROVIDERS` under the `compute_bond:<provider_did>`
//! key prefix. Hydration on startup rebuilds the in-memory cache so the
//! `register_provider` admission gate sees the durable state.

use crate::error::{Result, TokenError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_storage::{KvStore, WriteOp, CF_PROVIDERS};
use tenzro_types::primitives::{Address, Timestamp};
use tracing::{debug, info};

/// Domain prefix for the deterministic per-provider compute-bond vault address.
const COMPUTE_BOND_VAULT_DOMAIN: &[u8] = b"tenzro/compute-bond/vault";

/// Storage key prefix for `ComputeBondState` records under `CF_PROVIDERS`.
pub const COMPUTE_BOND_KEY_PREFIX: &[u8] = b"compute_bond:";

/// Default unbonding cooldown for ComputeBond: 7 days in milliseconds.
pub const DEFAULT_COMPUTE_BOND_COOLDOWN_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Default minimum bond amount required to register a provider: 100 TNZO
/// (in 1e18 units). Governance-tunable. Set to 0 to disable bond gating
/// (development only).
pub const DEFAULT_COMPUTE_BOND_MIN: u128 = 100 * 1_000_000_000_000_000_000;

/// Lifecycle of a `ComputeBondState`. Mirrors `BondLifecycle` from `bond.rs`
/// but without the `Frozen` state — there is no Quarantine flow for
/// providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ComputeBondStatus {
    /// Posted, not in cooldown — eligible to back a `register_provider` call.
    Active,
    /// Withdrawal initiated, cooldown timer running.
    Cooldown,
    /// Cooldown elapsed; bond is no longer slashable and the controller
    /// has reclaimed the funds. Terminal — record retained for audit.
    Returned,
    /// Bond fully consumed by SLA slashing — provider ejected, terminal.
    /// Record retained for audit and to prevent re-registration under the
    /// same DID without governance review.
    Slashed,
}

impl ComputeBondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ComputeBondStatus::Active => "Active",
            ComputeBondStatus::Cooldown => "Cooldown",
            ComputeBondStatus::Returned => "Returned",
            ComputeBondStatus::Slashed => "Slashed",
        }
    }
}

/// One historical event in `ComputeBondState.history`. Append-only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ComputeBondEvent {
    Posted { amount: u128, at: Timestamp },
    Increased { amount: u128, at: Timestamp },
    WithdrawInitiated { cooldown_until: Timestamp, at: Timestamp },
    Returned { at: Timestamp },
    /// One SLA-driven slash. `reason` is a short structured code such as
    /// `"sla:probe_timeout"` or `"sla:probe_invalid_sig"`. `remaining` is
    /// the post-slash bond balance.
    Slashed {
        amount: u128,
        remaining: u128,
        reason: String,
        at: Timestamp,
    },
}

/// Persistent state for one provider's compute bond. RocksDB row under
/// `CF_PROVIDERS/compute_bond:<provider_did>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeBondState {
    pub provider_did: String,
    pub provider_address: Address,
    /// Current bond balance.
    pub amount: u128,
    pub status: ComputeBondStatus,
    /// `Some(at)` once `withdraw` is called.
    pub cooldown_until: Option<Timestamp>,
    /// Block height at the most recent state-mutating operation.
    pub last_modified_block: u64,
    /// Count of SLA probe failures attributed to this provider since the
    /// bond was posted. Drives the SLA slashing threshold check in
    /// `tenzro-model::sla`. Does NOT decay — only resets when the bond
    /// is re-posted after a `Returned` terminal state.
    #[serde(default)]
    pub failure_count: u32,
    pub history: Vec<ComputeBondEvent>,
}

impl ComputeBondState {
    /// `true` if the bond is Active and therefore eligible to back a
    /// `register_provider` admission.
    pub fn is_eligible(&self) -> bool {
        matches!(self.status, ComputeBondStatus::Active)
    }

    /// Amount eligible to back registration. Active → `amount`, else 0.
    pub fn effective_amount(&self) -> u128 {
        if self.is_eligible() {
            self.amount
        } else {
            0
        }
    }
}

/// Free helper: derive the deterministic 32-byte vault address for a
/// provider's compute bond. The vault has no private key — only
/// `ComputeBondManager` may debit/credit it via VM-level state writes.
pub fn derive_compute_bond_vault_address(provider_did: &str) -> Address {
    let mut hasher = Sha256::new();
    hasher.update(COMPUTE_BOND_VAULT_DOMAIN);
    hasher.update(provider_did.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Address::new(bytes)
}

/// ComputeBond manager — in-memory cache + RocksDB write-through under
/// `CF_PROVIDERS`. Cheap concurrent reads for the `register_provider`
/// admission hot path.
///
/// Construction options:
/// - [`ComputeBondManager::new`] — pure in-memory (tests).
/// - [`ComputeBondManager::with_storage`] — write-through + hydrated.
pub struct ComputeBondManager {
    /// `provider_did -> ComputeBondState`
    bonds: DashMap<String, ComputeBondState>,
    /// Optional persistence backend. When set, every mutation calls
    /// `write_batch_sync` for fsync durability.
    storage: Option<Arc<dyn KvStore>>,
    /// Cooldown duration in milliseconds (governance-tunable).
    cooldown_ms: i64,
    /// Minimum bond required for a `register_provider` call. The
    /// `register_provider` RPC enforces this against the bonded amount.
    min_bond: u128,
}

impl Default for ComputeBondManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ComputeBondManager {
    /// Construct an in-memory manager. Use [`with_storage`] to enable
    /// persistence + hydration.
    pub fn new() -> Self {
        Self {
            bonds: DashMap::new(),
            storage: None,
            cooldown_ms: DEFAULT_COMPUTE_BOND_COOLDOWN_MS,
            min_bond: DEFAULT_COMPUTE_BOND_MIN,
        }
    }

    /// Construct with RocksDB write-through and hydrate from disk.
    /// Hydration scans `CF_PROVIDERS/compute_bond:`.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let mgr = Self {
            bonds: DashMap::new(),
            storage: Some(storage.clone()),
            cooldown_ms: DEFAULT_COMPUTE_BOND_COOLDOWN_MS,
            min_bond: DEFAULT_COMPUTE_BOND_MIN,
        };
        mgr.hydrate_from_storage()?;
        Ok(mgr)
    }

    /// Override governance dials. Used at node startup if a custom
    /// governance config has been loaded.
    pub fn with_governance(mut self, cooldown_ms: i64, min_bond: u128) -> Self {
        self.cooldown_ms = cooldown_ms;
        self.min_bond = min_bond;
        self
    }

    /// Currently configured minimum-bond gate.
    pub fn min_bond(&self) -> u128 {
        self.min_bond
    }

    /// Currently configured cooldown duration (ms).
    pub fn cooldown_ms(&self) -> i64 {
        self.cooldown_ms
    }

    fn hydrate_from_storage(&self) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s.clone(),
            None => return Ok(()),
        };

        let mut count = 0usize;
        let rows = storage
            .scan_prefix(CF_PROVIDERS, COMPUTE_BOND_KEY_PREFIX)
            .map_err(|e| TokenError::StorageError(format!("scan compute_bond: {}", e)))?;
        for (_key, value) in rows {
            let bond: ComputeBondState = serde_json::from_slice(&value)
                .map_err(|e| TokenError::StorageError(format!("decode compute_bond: {}", e)))?;
            self.bonds.insert(bond.provider_did.clone(), bond);
            count += 1;
        }

        info!(count, "ComputeBondManager hydrated from storage");
        Ok(())
    }

    fn persist(&self, bond: &ComputeBondState) -> Result<()> {
        if let Some(storage) = &self.storage {
            let mut key = COMPUTE_BOND_KEY_PREFIX.to_vec();
            key.extend_from_slice(bond.provider_did.as_bytes());
            let value = serde_json::to_vec(bond)
                .map_err(|e| TokenError::StorageError(format!("encode compute_bond: {}", e)))?;
            storage
                .write_batch_sync(vec![WriteOp::Put {
                    cf: CF_PROVIDERS.to_string(),
                    key,
                    value,
                }])
                .map_err(|e| TokenError::StorageError(format!("persist compute_bond: {}", e)))?;
        }
        Ok(())
    }

    // ---- Bond operations ----------------------------------------------------

    /// Post a compute bond. Caller's wallet has already been debited and
    /// the bond vault credited at the VM layer; this method records state.
    ///
    /// Rejects:
    /// - Existing Active/Cooldown bond (use `increase` to top up).
    /// - Zero amount.
    pub fn post(
        &self,
        provider_did: &str,
        provider_address: Address,
        amount: u128,
        block_height: u64,
    ) -> Result<ComputeBondState> {
        if amount == 0 {
            return Err(TokenError::InvalidParameter(
                "compute bond amount must be greater than zero".to_string(),
            ));
        }
        if let Some(existing) = self.bonds.get(provider_did)
            && !matches!(existing.status, ComputeBondStatus::Returned)
        {
            return Err(TokenError::InvalidParameter(format!(
                "provider {} already has a compute bond (status={})",
                provider_did,
                existing.status.as_str()
            )));
        }
        let now = Timestamp::now();
        let state = ComputeBondState {
            provider_did: provider_did.to_string(),
            provider_address,
            amount,
            status: ComputeBondStatus::Active,
            cooldown_until: None,
            last_modified_block: block_height,
            failure_count: 0,
            history: vec![ComputeBondEvent::Posted { amount, at: now }],
        };
        self.persist(&state)?;
        self.bonds.insert(provider_did.to_string(), state.clone());
        debug!(
            provider = %provider_did,
            amount,
            "ComputeBond posted"
        );
        Ok(state)
    }

    /// Top up an Active bond. Cooldown/Returned bonds reject.
    pub fn increase(
        &self,
        provider_did: &str,
        amount: u128,
        block_height: u64,
    ) -> Result<ComputeBondState> {
        if amount == 0 {
            return Err(TokenError::InvalidParameter(
                "increase amount must be greater than zero".to_string(),
            ));
        }
        let mut bond_ref = self
            .bonds
            .get_mut(provider_did)
            .ok_or_else(|| TokenError::NotFound(format!("no compute bond for {}", provider_did)))?;
        if bond_ref.status != ComputeBondStatus::Active {
            return Err(TokenError::InvalidParameter(format!(
                "cannot increase compute bond in {} state",
                bond_ref.status.as_str()
            )));
        }
        bond_ref.amount = bond_ref.amount.checked_add(amount).ok_or_else(|| {
            TokenError::InvalidParameter("compute bond amount overflow".to_string())
        })?;
        bond_ref.last_modified_block = block_height;
        bond_ref.history.push(ComputeBondEvent::Increased {
            amount,
            at: Timestamp::now(),
        });
        let snapshot = bond_ref.clone();
        drop(bond_ref);
        self.persist(&snapshot)?;
        debug!(
            provider = %provider_did,
            amount,
            total = snapshot.amount,
            "ComputeBond increased"
        );
        Ok(snapshot)
    }

    /// Initiate withdrawal. Active → Cooldown. Cooldown timer set to
    /// `now + cooldown_ms`. Caller must invoke `finalize_withdrawal`
    /// once the cooldown timer expires to mark the bond Returned and
    /// trigger the VM-layer credit back to the provider.
    pub fn withdraw(
        &self,
        provider_did: &str,
        block_height: u64,
    ) -> Result<ComputeBondState> {
        let mut bond_ref = self
            .bonds
            .get_mut(provider_did)
            .ok_or_else(|| TokenError::NotFound(format!("no compute bond for {}", provider_did)))?;
        if bond_ref.status != ComputeBondStatus::Active {
            return Err(TokenError::InvalidParameter(format!(
                "cannot withdraw compute bond in {} state",
                bond_ref.status.as_str()
            )));
        }
        let now = Timestamp::now();
        let cooldown_until = Timestamp::new(now.0.saturating_add(self.cooldown_ms));
        bond_ref.status = ComputeBondStatus::Cooldown;
        bond_ref.cooldown_until = Some(cooldown_until);
        bond_ref.last_modified_block = block_height;
        bond_ref.history.push(ComputeBondEvent::WithdrawInitiated {
            cooldown_until,
            at: now,
        });
        let snapshot = bond_ref.clone();
        drop(bond_ref);
        self.persist(&snapshot)?;
        info!(
            provider = %provider_did,
            cooldown_until = ?cooldown_until,
            "ComputeBond withdrawal initiated"
        );
        Ok(snapshot)
    }

    /// Mark a Cooldown bond as Returned once cooldown has elapsed. The
    /// VM-layer credit back to the provider's wallet is the caller's
    /// responsibility (transactional with this call).
    pub fn finalize_withdrawal(
        &self,
        provider_did: &str,
        block_height: u64,
    ) -> Result<ComputeBondState> {
        let mut bond_ref = self
            .bonds
            .get_mut(provider_did)
            .ok_or_else(|| TokenError::NotFound(format!("no compute bond for {}", provider_did)))?;
        if bond_ref.status != ComputeBondStatus::Cooldown {
            return Err(TokenError::InvalidParameter(format!(
                "cannot finalize compute bond withdrawal: status is {}",
                bond_ref.status.as_str()
            )));
        }
        let cooldown_until = bond_ref.cooldown_until.ok_or_else(|| {
            TokenError::InvalidParameter(
                "cooldown compute bond missing cooldown_until".to_string(),
            )
        })?;
        if Timestamp::now() < cooldown_until {
            return Err(TokenError::InvalidParameter(format!(
                "cooldown not yet elapsed (until {:?})",
                cooldown_until
            )));
        }
        bond_ref.status = ComputeBondStatus::Returned;
        bond_ref.amount = 0;
        bond_ref.last_modified_block = block_height;
        bond_ref
            .history
            .push(ComputeBondEvent::Returned { at: Timestamp::now() });
        let snapshot = bond_ref.clone();
        drop(bond_ref);
        self.persist(&snapshot)?;
        info!(provider = %provider_did, "ComputeBond returned to provider");
        Ok(snapshot)
    }

    /// Increment the provider's SLA failure counter without touching the
    /// bond balance. Returns the new counter value. Hot path for the SLA
    /// fault detector — it calls this on every observed probe miss and
    /// only escalates to [`slash`] once the counter crosses a threshold.
    pub fn record_failure(&self, provider_did: &str) -> Result<u32> {
        let mut bond_ref = self
            .bonds
            .get_mut(provider_did)
            .ok_or_else(|| TokenError::NotFound(format!("no compute bond for {}", provider_did)))?;
        bond_ref.failure_count = bond_ref.failure_count.saturating_add(1);
        let new_count = bond_ref.failure_count;
        let snapshot = bond_ref.clone();
        drop(bond_ref);
        self.persist(&snapshot)?;
        Ok(new_count)
    }

    /// Reset the failure counter to zero. Called when a successful probe
    /// response is received from a previously-flaky provider — gives them
    /// credit for recovering without crossing the slash threshold.
    pub fn reset_failure_count(&self, provider_did: &str) -> Result<()> {
        let mut bond_ref = self
            .bonds
            .get_mut(provider_did)
            .ok_or_else(|| TokenError::NotFound(format!("no compute bond for {}", provider_did)))?;
        if bond_ref.failure_count == 0 {
            return Ok(());
        }
        bond_ref.failure_count = 0;
        let snapshot = bond_ref.clone();
        drop(bond_ref);
        self.persist(&snapshot)?;
        Ok(())
    }

    /// Slash an Active compute bond. Reduces `amount` by `slash_amount`
    /// (capped at the current balance) and appends a `Slashed` history
    /// event. If the post-slash balance is zero, the bond transitions to
    /// `Slashed` terminal state — provider is ejected from the registry.
    ///
    /// Cooldown / Returned / Slashed bonds reject (terminal or unbonding).
    ///
    /// Returns the post-slash bond snapshot. The caller is responsible for
    /// the VM-layer debit from the bond vault (slashed funds typically
    /// flow to an insurance pool or the treasury).
    pub fn slash(
        &self,
        provider_did: &str,
        slash_amount: u128,
        reason: &str,
        block_height: u64,
    ) -> Result<ComputeBondState> {
        if slash_amount == 0 {
            return Err(TokenError::InvalidParameter(
                "slash amount must be greater than zero".to_string(),
            ));
        }
        let mut bond_ref = self
            .bonds
            .get_mut(provider_did)
            .ok_or_else(|| TokenError::NotFound(format!("no compute bond for {}", provider_did)))?;
        if bond_ref.status != ComputeBondStatus::Active {
            return Err(TokenError::InvalidParameter(format!(
                "cannot slash compute bond in {} state",
                bond_ref.status.as_str()
            )));
        }
        let applied = slash_amount.min(bond_ref.amount);
        bond_ref.amount = bond_ref.amount.saturating_sub(applied);
        if bond_ref.amount == 0 {
            bond_ref.status = ComputeBondStatus::Slashed;
        }
        bond_ref.last_modified_block = block_height;
        let remaining = bond_ref.amount;
        bond_ref.history.push(ComputeBondEvent::Slashed {
            amount: applied,
            remaining,
            reason: reason.to_string(),
            at: Timestamp::now(),
        });
        let snapshot = bond_ref.clone();
        drop(bond_ref);
        self.persist(&snapshot)?;
        info!(
            provider = %provider_did,
            slashed = applied,
            remaining = snapshot.amount,
            reason = %reason,
            terminal = matches!(snapshot.status, ComputeBondStatus::Slashed),
            "ComputeBond slashed"
        );
        Ok(snapshot)
    }

    // ---- Read accessors -----------------------------------------------------

    pub fn get(&self, provider_did: &str) -> Option<ComputeBondState> {
        self.bonds.get(provider_did).map(|r| r.clone())
    }

    pub fn list(&self) -> Vec<ComputeBondState> {
        self.bonds.iter().map(|r| r.value().clone()).collect()
    }

    /// Lookup eligible bond amount for the `register_provider` admission
    /// gate. Returns `amount` when status is Active, else 0.
    pub fn effective_for_registration(&self, provider_did: &str) -> u128 {
        self.bonds
            .get(provider_did)
            .map(|r| r.effective_amount())
            .unwrap_or(0)
    }

    /// `true` if the provider currently has an Active bond at or above
    /// the manager's `min_bond` gate. Hot path for `register_provider`.
    pub fn meets_minimum(&self, provider_did: &str) -> bool {
        self.effective_for_registration(provider_did) >= self.min_bond
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::new([byte; 32])
    }

    #[test]
    fn post_creates_active_bond() {
        let m = ComputeBondManager::new();
        let bond = m
            .post("did:tenzro:provider:p1", addr(1), 5_000, 100)
            .unwrap();
        assert_eq!(bond.status, ComputeBondStatus::Active);
        assert_eq!(bond.amount, 5_000);
        assert_eq!(
            m.effective_for_registration("did:tenzro:provider:p1"),
            5_000
        );
    }

    #[test]
    fn double_post_rejects_when_active() {
        let m = ComputeBondManager::new();
        m.post("p1", addr(1), 100, 1).unwrap();
        assert!(m.post("p1", addr(1), 100, 2).is_err());
    }

    #[test]
    fn post_after_returned_succeeds() {
        // After a Returned terminal state, a fresh post is allowed —
        // mirror semantics for re-registration after a complete unbond.
        let m = ComputeBondManager::new().with_governance(0, 0);
        m.post("p1", addr(1), 100, 1).unwrap();
        m.withdraw("p1", 2).unwrap();
        // Cooldown is 0ms so finalize is immediate.
        m.finalize_withdrawal("p1", 3).unwrap();
        assert!(m.post("p1", addr(1), 200, 4).is_ok());
        assert_eq!(m.get("p1").unwrap().amount, 200);
    }

    #[test]
    fn increase_only_active() {
        let m = ComputeBondManager::new();
        m.post("p1", addr(1), 100, 1).unwrap();
        m.increase("p1", 50, 2).unwrap();
        assert_eq!(m.get("p1").unwrap().amount, 150);
        m.withdraw("p1", 3).unwrap();
        assert!(m.increase("p1", 50, 4).is_err());
    }

    #[test]
    fn withdraw_demotes_eligibility() {
        let m = ComputeBondManager::new();
        m.post("p1", addr(1), 100, 1).unwrap();
        assert_eq!(m.effective_for_registration("p1"), 100);
        m.withdraw("p1", 2).unwrap();
        assert_eq!(m.effective_for_registration("p1"), 0);
    }

    #[test]
    fn finalize_rejects_before_cooldown_elapsed() {
        let m = ComputeBondManager::new();
        m.post("p1", addr(1), 100, 1).unwrap();
        m.withdraw("p1", 2).unwrap();
        // Default cooldown is 7 days — finalize should reject.
        assert!(m.finalize_withdrawal("p1", 3).is_err());
    }

    #[test]
    fn meets_minimum_gate() {
        let m = ComputeBondManager::new().with_governance(
            DEFAULT_COMPUTE_BOND_COOLDOWN_MS,
            500,
        );
        m.post("p1", addr(1), 400, 1).unwrap();
        assert!(!m.meets_minimum("p1"));
        m.increase("p1", 200, 2).unwrap();
        assert!(m.meets_minimum("p1"));
    }

    #[test]
    fn slash_reduces_amount_and_appends_history() {
        let m = ComputeBondManager::new();
        m.post("p1", addr(1), 1000, 1).unwrap();
        let snap = m.slash("p1", 250, "sla:probe_timeout", 2).unwrap();
        assert_eq!(snap.amount, 750);
        assert_eq!(snap.status, ComputeBondStatus::Active);
        assert!(matches!(
            snap.history.last().unwrap(),
            ComputeBondEvent::Slashed { amount: 250, remaining: 750, .. }
        ));
    }

    #[test]
    fn slash_to_zero_transitions_to_slashed_terminal() {
        let m = ComputeBondManager::new();
        m.post("p1", addr(1), 1000, 1).unwrap();
        let snap = m.slash("p1", 1000, "sla:probe_timeout", 2).unwrap();
        assert_eq!(snap.amount, 0);
        assert_eq!(snap.status, ComputeBondStatus::Slashed);
        // Slashed bond is ineligible — registration must fail.
        assert_eq!(m.effective_for_registration("p1"), 0);
        // Further slashes reject (terminal).
        assert!(m.slash("p1", 1, "sla:probe_timeout", 3).is_err());
    }

    #[test]
    fn slash_caps_at_balance() {
        // Slash amount larger than balance is capped, not an error.
        let m = ComputeBondManager::new();
        m.post("p1", addr(1), 500, 1).unwrap();
        let snap = m.slash("p1", 999_999, "sla:probe_timeout", 2).unwrap();
        assert_eq!(snap.amount, 0);
        assert_eq!(snap.status, ComputeBondStatus::Slashed);
    }

    #[test]
    fn slash_rejects_cooldown_and_returned() {
        let m = ComputeBondManager::new().with_governance(0, 0);
        m.post("p1", addr(1), 100, 1).unwrap();
        m.withdraw("p1", 2).unwrap();
        assert!(m.slash("p1", 10, "sla:probe_timeout", 3).is_err());
        m.finalize_withdrawal("p1", 4).unwrap();
        assert!(m.slash("p1", 10, "sla:probe_timeout", 5).is_err());
    }

    #[test]
    fn post_after_slashed_rejects() {
        // Slashed is terminal — same DID cannot re-register without
        // governance review (different from Returned which is a clean
        // unbond).
        let m = ComputeBondManager::new();
        m.post("p1", addr(1), 100, 1).unwrap();
        m.slash("p1", 100, "sla:probe_timeout", 2).unwrap();
        assert!(m.post("p1", addr(1), 200, 3).is_err());
    }

    #[test]
    fn failure_counter_increments_and_resets() {
        let m = ComputeBondManager::new();
        m.post("p1", addr(1), 100, 1).unwrap();
        assert_eq!(m.record_failure("p1").unwrap(), 1);
        assert_eq!(m.record_failure("p1").unwrap(), 2);
        assert_eq!(m.record_failure("p1").unwrap(), 3);
        m.reset_failure_count("p1").unwrap();
        assert_eq!(m.get("p1").unwrap().failure_count, 0);
    }

    #[test]
    fn deterministic_vault_address() {
        let a = derive_compute_bond_vault_address("did:tenzro:provider:p1");
        let b = derive_compute_bond_vault_address("did:tenzro:provider:p1");
        let c = derive_compute_bond_vault_address("did:tenzro:provider:p2");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
