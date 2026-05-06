//! AgentBond surety primitive (Agent-Swarm Spec 9)
//!
//! Each autonomous agent identity (`did:tenzro:machine:...`) may have a
//! bond posted *by its controller* on its behalf. The bond is held in a
//! deterministic, key-less vault address derived per-agent. Three lifecycle
//! operations expose it:
//!
//! - `post`     — controller commits TNZO to the agent's bond. Active.
//! - `increase` — top up an Active bond.
//! - `withdraw` — initiate cooldown; bond stays bind-able for slashing
//!   during cooldown, returns to controller after.
//!
//! Plus two slashing paths:
//!
//! - `freeze` (Quarantine) flips Active → Frozen. Bond remains slashable
//!   but not withdraw-able.
//! - `slash` (Terminate or adjudicated dispute) debits the bond and
//!   credits the InsurancePool — with a residual floor (`min_residual`)
//!   below which the bond is fully drained and marked `Slashed`.
//!
//! State persists in `CF_AGENTS` under the `bond:<agent_did>` key prefix
//! plus a `bond_by_controller:<controller_did>:<agent_did>` reverse index
//! that lets `tenzro_listAgentBondsByController` enumerate without a
//! full-table scan.
//!
//! # Lane interaction (Spec 2)
//!
//! `effective_bond_for_promotion(agent_did)` returns the amount eligible
//! for lane promotion: `amount` when `state == Active`, else 0. The
//! `lane_resolver` consults this on every admission. A bond drained by a
//! partial slash below `bond_min_for_promotion` immediately demotes the
//! agent — no caching, no cooldown.

use crate::error::{Result, TokenError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_storage::{KvStore, WriteOp, CF_AGENTS};
use tenzro_types::primitives::{Address, Timestamp};
use tracing::{debug, info, warn};

/// Domain prefix for the deterministic per-agent bond vault address.
const BOND_VAULT_DOMAIN: &[u8] = b"tenzro/agent-bond/vault";
/// Domain prefix for the deterministic InsurancePool vault address.
const INSURANCE_VAULT_DOMAIN: &[u8] = b"tenzro/insurance-pool/vault";

/// Storage key prefix for `AgentBondState` records under `CF_AGENTS`.
pub const BOND_KEY_PREFIX: &[u8] = b"bond:";
/// Storage key prefix for `controller_did → agent_did` reverse index.
pub const BOND_BY_CONTROLLER_PREFIX: &[u8] = b"bond_by_controller:";
/// Storage key prefix for `ClaimRecord` under `CF_AGENTS`.
pub const CLAIM_KEY_PREFIX: &[u8] = b"insurance_claim:";
/// Singleton key for `InsurancePoolState` under `CF_AGENTS`.
pub const INSURANCE_POOL_KEY: &[u8] = b"insurance_pool:singleton";

/// Default bond cooldown: 14 days in milliseconds.
pub const DEFAULT_COOLDOWN_MS: i64 = 14 * 24 * 60 * 60 * 1000;
/// Default minimum residual: 10 TNZO (in 1e18 units).
pub const DEFAULT_MIN_RESIDUAL: u128 = 10 * 1_000_000_000_000_000_000;
/// Default maximum slash per single dispute: 50% (5000 bps).
pub const DEFAULT_MAX_SINGLE_SLASH_BPS: u16 = 5000;

/// Lifecycle of an `AgentBondState`. See agent-bond.md §"Bond lifecycle".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum BondLifecycle {
    /// Posted, not Quarantined, not in cooldown — eligible for lane promotion.
    Active,
    /// Withdrawal initiated, cooldown timer running. Still slashable.
    /// Demoted to Open lane during cooldown (effective_bond = 0).
    Cooldown,
    /// Quarantine has frozen the bond. Cannot be withdrawn; remains slashable.
    Frozen,
    /// Terminate (or full slash) drained the bond. Terminal state.
    Slashed,
    /// Cooldown elapsed without slashing; controller has reclaimed the funds.
    /// Terminal state. The record is retained for audit; the agent's
    /// `effective_bond_for_promotion` is 0.
    Returned,
}

impl BondLifecycle {
    pub fn as_str(self) -> &'static str {
        match self {
            BondLifecycle::Active => "Active",
            BondLifecycle::Cooldown => "Cooldown",
            BondLifecycle::Frozen => "Frozen",
            BondLifecycle::Slashed => "Slashed",
            BondLifecycle::Returned => "Returned",
        }
    }
}

/// One historical event in `AgentBondState.history`. Append-only; never
/// pruned. Retains full audit trail for downstream regulators.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BondEvent {
    Posted { amount: u128, at: Timestamp },
    Increased { amount: u128, at: Timestamp },
    WithdrawInitiated { cooldown_until: Timestamp, at: Timestamp },
    Frozen { reason: String, at: Timestamp },
    Slashed { amount: u128, recipient_kind: String, claim_id: Option<String>, at: Timestamp },
    Returned { at: Timestamp },
}

/// Persistent state for one agent's bond. RocksDB row under
/// `CF_AGENTS/bond:<agent_did>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBondState {
    pub agent_did: String,
    pub controller_did: String,
    /// Current bond balance. Drops on `slash`; restored only by `increase`.
    pub amount: u128,
    pub state: BondLifecycle,
    /// `Some(at)` once `withdraw` is called; `state` is always `Cooldown`
    /// while this is set and not yet elapsed.
    pub cooldown_until: Option<Timestamp>,
    /// Block height at the most recent state-mutating operation. Useful
    /// for reorg-safety diagnostics on operator dashboards.
    pub last_modified_block: u64,
    pub history: Vec<BondEvent>,
}

impl AgentBondState {
    /// `true` if `state == Active`. Drives Spec 2 lane promotion.
    pub fn is_promotion_eligible(&self) -> bool {
        matches!(self.state, BondLifecycle::Active)
    }

    /// Amount eligible for lane promotion. Active → `amount`, else 0.
    pub fn effective_for_promotion(&self) -> u128 {
        if self.is_promotion_eligible() {
            self.amount
        } else {
            0
        }
    }
}

/// Status of an `InsurancePool` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ClaimStatus {
    /// Filed; awaiting governance proposal adjudication.
    Open,
    /// Governance approved; payout queued (or already executed).
    Approved,
    /// Governance rejected. Terminal.
    Rejected,
    /// Approved AND payout executed against the pool. Terminal.
    Paid,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ClaimStatus::Open => "Open",
            ClaimStatus::Approved => "Approved",
            ClaimStatus::Rejected => "Rejected",
            ClaimStatus::Paid => "Paid",
        }
    }
}

/// Insurance claim filed against a bonded agent. RocksDB row under
/// `CF_AGENTS/insurance_claim:<claim_id_hex>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRecord {
    /// Hex-encoded SHA-256 commitment derived from
    /// `(claimant_did, against_agent_did, nonce_le)`.
    pub claim_id: String,
    pub claimant_did: String,
    pub against_agent_did: String,
    pub amount_requested: u128,
    /// On-chain receipt references (Spec 5) — chain-anchored evidence.
    pub receipt_refs: Vec<String>,
    /// Optional human narrative — capped at 1024 bytes by the RPC handler
    /// before reaching this layer.
    pub narrative: Option<String>,
    pub status: ClaimStatus,
    /// Governance proposal ID if one has been opened to adjudicate.
    pub governance_ref: Option<String>,
    pub paid_amount: Option<u128>,
    pub filed_at: Timestamp,
    /// Address of the claimant — used to credit `paid_amount` on Approved → Paid.
    pub claimant_address: Address,
}

/// Top-of-pool aggregate: total balance + claim accounting. Singleton row
/// at `CF_AGENTS/insurance_pool:singleton`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InsurancePoolState {
    pub balance_tnzo: u128,
    pub paid_claims: u64,
    pub total_paid_tnzo: u128,
    pub open_claim_count: u64,
}

/// Free helper: derive the deterministic 32-byte vault address for an
/// agent's bond. The vault has no private key — only `BondManager` may
/// debit/credit it via `state.set_balance` writes through
/// [`tenzro_vm::native`].
pub fn derive_bond_vault_address(agent_did: &str) -> Address {
    let mut hasher = Sha256::new();
    hasher.update(BOND_VAULT_DOMAIN);
    hasher.update(agent_did.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Address::new(bytes)
}

/// Free helper: deterministic InsurancePool vault address (singleton).
pub fn derive_insurance_pool_address() -> Address {
    let mut hasher = Sha256::new();
    hasher.update(INSURANCE_VAULT_DOMAIN);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Address::new(bytes)
}

/// Free helper: derive a deterministic claim_id from filer + target + nonce.
pub fn derive_claim_id(claimant_did: &str, against_agent_did: &str, nonce_le: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"tenzro/insurance-claim/id");
    hasher.update(claimant_did.as_bytes());
    hasher.update(against_agent_did.as_bytes());
    hasher.update(nonce_le.to_le_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

/// Bond manager — in-memory cache + RocksDB write-through under
/// `CF_AGENTS`. Cheap concurrent reads for the lane resolver hot path.
///
/// Construction options:
/// - [`BondManager::new`] — pure in-memory (tests, light client).
/// - [`BondManager::with_storage`] — write-through + hydrated from disk.
pub struct BondManager {
    /// `agent_did -> AgentBondState`
    bonds: DashMap<String, AgentBondState>,
    /// `controller_did -> Vec<agent_did>` reverse index.
    by_controller: DashMap<String, Vec<String>>,
    /// `claim_id -> ClaimRecord`
    claims: DashMap<String, ClaimRecord>,
    /// Singleton pool state.
    pool: parking_lot::RwLock<InsurancePoolState>,
    /// Optional persistence backend — when set, every mutation calls
    /// `write_batch_sync` for fsync durability.
    storage: Option<Arc<dyn KvStore>>,
    /// Cooldown duration in milliseconds (governance-tunable).
    cooldown_ms: i64,
    /// Floor below which `slash` drains to zero and marks `Slashed`.
    min_residual: u128,
    /// Cap on a single slash bps; `slash` rejects above this.
    max_single_slash_bps: u16,
}

impl Default for BondManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BondManager {
    /// Construct an in-memory manager. Use [`with_storage`] to enable
    /// persistence + hydration.
    pub fn new() -> Self {
        Self {
            bonds: DashMap::new(),
            by_controller: DashMap::new(),
            claims: DashMap::new(),
            pool: parking_lot::RwLock::new(InsurancePoolState::default()),
            storage: None,
            cooldown_ms: DEFAULT_COOLDOWN_MS,
            min_residual: DEFAULT_MIN_RESIDUAL,
            max_single_slash_bps: DEFAULT_MAX_SINGLE_SLASH_BPS,
        }
    }

    /// Construct with RocksDB write-through and hydrate from disk.
    /// Hydration scans `CF_AGENTS/bond:`, `CF_AGENTS/insurance_claim:`, and
    /// the singleton `CF_AGENTS/insurance_pool:singleton`.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let mgr = Self {
            bonds: DashMap::new(),
            by_controller: DashMap::new(),
            claims: DashMap::new(),
            pool: parking_lot::RwLock::new(InsurancePoolState::default()),
            storage: Some(storage.clone()),
            cooldown_ms: DEFAULT_COOLDOWN_MS,
            min_residual: DEFAULT_MIN_RESIDUAL,
            max_single_slash_bps: DEFAULT_MAX_SINGLE_SLASH_BPS,
        };
        mgr.hydrate_from_storage()?;
        Ok(mgr)
    }

    /// Override governance dials. Only used by `tenzro-node` startup
    /// when a custom governance config has been loaded.
    pub fn with_governance(
        mut self,
        cooldown_ms: i64,
        min_residual: u128,
        max_single_slash_bps: u16,
    ) -> Self {
        self.cooldown_ms = cooldown_ms;
        self.min_residual = min_residual;
        self.max_single_slash_bps = max_single_slash_bps;
        self
    }

    fn hydrate_from_storage(&self) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s.clone(),
            None => return Ok(()),
        };

        let mut bond_count = 0usize;
        let bond_rows = storage
            .scan_prefix(CF_AGENTS, BOND_KEY_PREFIX)
            .map_err(|e| TokenError::StorageError(format!("scan bonds: {}", e)))?;
        for (_key, value) in bond_rows {
            let bond: AgentBondState = serde_json::from_slice(&value)
                .map_err(|e| TokenError::StorageError(format!("decode bond: {}", e)))?;
            // Rebuild the controller index in-memory (we don't persist it
            // separately because it's derivable; cheaper to re-walk than
            // to keep two sources of truth in sync).
            self.by_controller
                .entry(bond.controller_did.clone())
                .or_default()
                .push(bond.agent_did.clone());
            self.bonds.insert(bond.agent_did.clone(), bond);
            bond_count += 1;
        }

        let mut claim_count = 0usize;
        let claim_rows = storage
            .scan_prefix(CF_AGENTS, CLAIM_KEY_PREFIX)
            .map_err(|e| TokenError::StorageError(format!("scan claims: {}", e)))?;
        for (_key, value) in claim_rows {
            let claim: ClaimRecord = serde_json::from_slice(&value)
                .map_err(|e| TokenError::StorageError(format!("decode claim: {}", e)))?;
            self.claims.insert(claim.claim_id.clone(), claim);
            claim_count += 1;
        }

        if let Some(value) = storage
            .get(CF_AGENTS, INSURANCE_POOL_KEY)
            .map_err(|e| TokenError::StorageError(format!("get pool: {}", e)))?
        {
            let pool: InsurancePoolState = serde_json::from_slice(&value)
                .map_err(|e| TokenError::StorageError(format!("decode pool: {}", e)))?;
            *self.pool.write() = pool;
        }

        info!(
            bond_count,
            claim_count,
            pool_balance = self.pool.read().balance_tnzo,
            "BondManager hydrated from storage"
        );
        Ok(())
    }

    fn persist_bond(&self, bond: &AgentBondState) -> Result<()> {
        if let Some(storage) = &self.storage {
            let mut key = BOND_KEY_PREFIX.to_vec();
            key.extend_from_slice(bond.agent_did.as_bytes());
            let value = serde_json::to_vec(bond).map_err(|e| {
                TokenError::StorageError(format!("encode bond: {}", e))
            })?;
            storage
                .write_batch_sync(vec![WriteOp::Put {
                    cf: CF_AGENTS.to_string(),
                    key,
                    value,
                }])
                .map_err(|e| TokenError::StorageError(format!("persist bond: {}", e)))?;
        }
        Ok(())
    }

    fn persist_claim(&self, claim: &ClaimRecord) -> Result<()> {
        if let Some(storage) = &self.storage {
            let mut key = CLAIM_KEY_PREFIX.to_vec();
            key.extend_from_slice(claim.claim_id.as_bytes());
            let value = serde_json::to_vec(claim).map_err(|e| {
                TokenError::StorageError(format!("encode claim: {}", e))
            })?;
            storage
                .write_batch_sync(vec![WriteOp::Put {
                    cf: CF_AGENTS.to_string(),
                    key,
                    value,
                }])
                .map_err(|e| TokenError::StorageError(format!("persist claim: {}", e)))?;
        }
        Ok(())
    }

    fn persist_pool(&self, pool: &InsurancePoolState) -> Result<()> {
        if let Some(storage) = &self.storage {
            let value = serde_json::to_vec(pool).map_err(|e| {
                TokenError::StorageError(format!("encode pool: {}", e))
            })?;
            storage
                .write_batch_sync(vec![WriteOp::Put {
                    cf: CF_AGENTS.to_string(),
                    key: INSURANCE_POOL_KEY.to_vec(),
                    value,
                }])
                .map_err(|e| TokenError::StorageError(format!("persist pool: {}", e)))?;
        }
        Ok(())
    }

    // ---- Bond operations ----------------------------------------------------

    /// Post a bond. Caller (the VM `execute_post_agent_bond` handler)
    /// has already debited the controller's wallet and credited the bond
    /// vault address; this method is the bookkeeping layer that records
    /// state for the lane resolver and history.
    ///
    /// Rejects:
    /// - Existing Active/Cooldown/Frozen bond (use `increase` to top up).
    /// - Zero amount.
    pub fn post(
        &self,
        agent_did: &str,
        controller_did: &str,
        amount: u128,
        block_height: u64,
    ) -> Result<AgentBondState> {
        if amount == 0 {
            return Err(TokenError::InvalidParameter(
                "bond amount must be greater than zero".to_string(),
            ));
        }
        if let Some(existing) = self.bonds.get(agent_did) {
            return Err(TokenError::InvalidParameter(format!(
                "agent {} already has a bond (state={})",
                agent_did,
                existing.state.as_str()
            )));
        }
        let now = Timestamp::now();
        let state = AgentBondState {
            agent_did: agent_did.to_string(),
            controller_did: controller_did.to_string(),
            amount,
            state: BondLifecycle::Active,
            cooldown_until: None,
            last_modified_block: block_height,
            history: vec![BondEvent::Posted { amount, at: now }],
        };
        self.persist_bond(&state)?;
        self.bonds.insert(agent_did.to_string(), state.clone());
        self.by_controller
            .entry(controller_did.to_string())
            .or_default()
            .push(agent_did.to_string());
        debug!(agent = %agent_did, controller = %controller_did, amount, "AgentBond posted");
        Ok(state)
    }

    /// Top up an Active bond. Cooldown/Frozen/Slashed bonds reject (use
    /// `post` after a Returned/Slashed terminal state — only one bond
    /// at a time per agent).
    pub fn increase(
        &self,
        agent_did: &str,
        amount: u128,
        block_height: u64,
    ) -> Result<AgentBondState> {
        if amount == 0 {
            return Err(TokenError::InvalidParameter(
                "increase amount must be greater than zero".to_string(),
            ));
        }
        let mut bond_ref = self
            .bonds
            .get_mut(agent_did)
            .ok_or_else(|| TokenError::NotFound(format!("no bond for agent {}", agent_did)))?;
        if bond_ref.state != BondLifecycle::Active {
            return Err(TokenError::InvalidParameter(format!(
                "cannot increase bond in {} state",
                bond_ref.state.as_str()
            )));
        }
        bond_ref.amount = bond_ref.amount.checked_add(amount).ok_or_else(|| {
            TokenError::InvalidParameter("bond amount overflow".to_string())
        })?;
        bond_ref.last_modified_block = block_height;
        bond_ref.history.push(BondEvent::Increased {
            amount,
            at: Timestamp::now(),
        });
        let snapshot = bond_ref.clone();
        drop(bond_ref);
        self.persist_bond(&snapshot)?;
        debug!(agent = %agent_did, amount, total = snapshot.amount, "AgentBond increased");
        Ok(snapshot)
    }

    /// Initiate withdrawal. Active → Cooldown. Cooldown timer set to
    /// `now + cooldown_ms`. Bond remains slashable for the entire cooldown.
    /// Caller is responsible for kicking off the cooldown-elapsed callback
    /// path (`finalize_withdrawal`) once the timer expires.
    pub fn withdraw(
        &self,
        agent_did: &str,
        block_height: u64,
    ) -> Result<AgentBondState> {
        let mut bond_ref = self
            .bonds
            .get_mut(agent_did)
            .ok_or_else(|| TokenError::NotFound(format!("no bond for agent {}", agent_did)))?;
        if bond_ref.state != BondLifecycle::Active {
            return Err(TokenError::InvalidParameter(format!(
                "cannot withdraw bond in {} state",
                bond_ref.state.as_str()
            )));
        }
        let now = Timestamp::now();
        let cooldown_until = Timestamp::new(now.0.saturating_add(self.cooldown_ms));
        bond_ref.state = BondLifecycle::Cooldown;
        bond_ref.cooldown_until = Some(cooldown_until);
        bond_ref.last_modified_block = block_height;
        bond_ref.history.push(BondEvent::WithdrawInitiated {
            cooldown_until,
            at: now,
        });
        let snapshot = bond_ref.clone();
        drop(bond_ref);
        self.persist_bond(&snapshot)?;
        info!(agent = %agent_did, cooldown_until = ?cooldown_until, "AgentBond withdrawal initiated");
        Ok(snapshot)
    }

    /// Mark a Cooldown bond as Returned once cooldown has elapsed. The
    /// VM handler is responsible for crediting the controller's wallet
    /// from the bond vault before/after this call (transactional).
    pub fn finalize_withdrawal(
        &self,
        agent_did: &str,
        block_height: u64,
    ) -> Result<AgentBondState> {
        let mut bond_ref = self
            .bonds
            .get_mut(agent_did)
            .ok_or_else(|| TokenError::NotFound(format!("no bond for agent {}", agent_did)))?;
        if bond_ref.state != BondLifecycle::Cooldown {
            return Err(TokenError::InvalidParameter(format!(
                "cannot finalize withdrawal: bond is in {} state",
                bond_ref.state.as_str()
            )));
        }
        let cooldown_until = bond_ref.cooldown_until.ok_or_else(|| {
            TokenError::InvalidParameter("cooldown bond missing cooldown_until".to_string())
        })?;
        if Timestamp::now() < cooldown_until {
            return Err(TokenError::InvalidParameter(format!(
                "cooldown not yet elapsed (until {:?})",
                cooldown_until
            )));
        }
        bond_ref.state = BondLifecycle::Returned;
        bond_ref.amount = 0;
        bond_ref.last_modified_block = block_height;
        bond_ref.history.push(BondEvent::Returned { at: Timestamp::now() });
        let snapshot = bond_ref.clone();
        drop(bond_ref);
        self.persist_bond(&snapshot)?;
        info!(agent = %agent_did, "AgentBond returned to controller");
        Ok(snapshot)
    }

    /// Freeze (Quarantine integration). Active → Frozen. Cooldown bonds
    /// are *also* frozen (cooldown timer is paused — no return until
    /// resumed). Frozen / Slashed / Returned bonds reject.
    pub fn freeze(
        &self,
        agent_did: &str,
        reason: &str,
        block_height: u64,
    ) -> Result<AgentBondState> {
        let mut bond_ref = self
            .bonds
            .get_mut(agent_did)
            .ok_or_else(|| TokenError::NotFound(format!("no bond for agent {}", agent_did)))?;
        if !matches!(
            bond_ref.state,
            BondLifecycle::Active | BondLifecycle::Cooldown
        ) {
            return Err(TokenError::InvalidParameter(format!(
                "cannot freeze bond in {} state",
                bond_ref.state.as_str()
            )));
        }
        bond_ref.state = BondLifecycle::Frozen;
        bond_ref.last_modified_block = block_height;
        bond_ref.history.push(BondEvent::Frozen {
            reason: reason.to_string(),
            at: Timestamp::now(),
        });
        let snapshot = bond_ref.clone();
        drop(bond_ref);
        self.persist_bond(&snapshot)?;
        warn!(agent = %agent_did, reason, "AgentBond frozen by Quarantine");
        Ok(snapshot)
    }

    /// Resume a frozen bond back to Active (Quarantine cleared by
    /// governance). If a withdraw cooldown was in flight, the timer
    /// effectively resets — callers can re-issue `withdraw` to start fresh.
    pub fn unfreeze(&self, agent_did: &str, block_height: u64) -> Result<AgentBondState> {
        let mut bond_ref = self
            .bonds
            .get_mut(agent_did)
            .ok_or_else(|| TokenError::NotFound(format!("no bond for agent {}", agent_did)))?;
        if bond_ref.state != BondLifecycle::Frozen {
            return Err(TokenError::InvalidParameter(format!(
                "cannot unfreeze bond in {} state",
                bond_ref.state.as_str()
            )));
        }
        bond_ref.state = BondLifecycle::Active;
        bond_ref.cooldown_until = None;
        bond_ref.last_modified_block = block_height;
        let snapshot = bond_ref.clone();
        drop(bond_ref);
        self.persist_bond(&snapshot)?;
        info!(agent = %agent_did, "AgentBond unfrozen");
        Ok(snapshot)
    }

    /// Slash a bond. Triggered by Terminate (Spec 1) or by an approved
    /// insurance claim (governance dispute path). Debits `bond × bps /
    /// 10000`, credits the InsurancePool, and (if the result drops below
    /// `min_residual`) marks the bond `Slashed` and zeroes it.
    ///
    /// Returns `(slashed_amount, new_bond_state)`.
    ///
    /// Rejects:
    /// - `bps > max_single_slash_bps`.
    /// - Bond in Slashed/Returned terminal states.
    pub fn slash(
        &self,
        agent_did: &str,
        bps: u16,
        claim_id: Option<String>,
        recipient_kind: &str,
        block_height: u64,
    ) -> Result<(u128, AgentBondState)> {
        if bps == 0 {
            return Err(TokenError::InvalidParameter(
                "slash bps must be > 0".to_string(),
            ));
        }
        if bps > self.max_single_slash_bps {
            return Err(TokenError::InvalidParameter(format!(
                "slash bps {} exceeds max_single_slash_bps {}",
                bps, self.max_single_slash_bps
            )));
        }
        let mut bond_ref = self
            .bonds
            .get_mut(agent_did)
            .ok_or_else(|| TokenError::NotFound(format!("no bond for agent {}", agent_did)))?;
        if matches!(
            bond_ref.state,
            BondLifecycle::Slashed | BondLifecycle::Returned
        ) {
            return Err(TokenError::InvalidParameter(format!(
                "cannot slash bond in {} terminal state",
                bond_ref.state.as_str()
            )));
        }
        // Slash math — full u128 width, no precision loss for typical bond sizes.
        let slashed = (bond_ref.amount / 10_000)
            .saturating_mul(bps as u128)
            .saturating_add(((bond_ref.amount % 10_000) * bps as u128) / 10_000);
        let remainder = bond_ref.amount.saturating_sub(slashed);
        // If remainder drops below floor, fully drain.
        let (final_slashed, terminal) = if remainder < self.min_residual {
            (bond_ref.amount, true)
        } else {
            (slashed, false)
        };
        bond_ref.amount = bond_ref.amount.saturating_sub(final_slashed);
        if terminal {
            bond_ref.state = BondLifecycle::Slashed;
        }
        bond_ref.last_modified_block = block_height;
        bond_ref.history.push(BondEvent::Slashed {
            amount: final_slashed,
            recipient_kind: recipient_kind.to_string(),
            claim_id,
            at: Timestamp::now(),
        });
        let snapshot = bond_ref.clone();
        drop(bond_ref);
        self.persist_bond(&snapshot)?;

        // Credit the InsurancePool aggregate.
        {
            let mut pool = self.pool.write();
            pool.balance_tnzo = pool.balance_tnzo.saturating_add(final_slashed);
            self.persist_pool(&pool)?;
        }

        warn!(
            agent = %agent_did,
            slashed = final_slashed,
            terminal,
            recipient = recipient_kind,
            "AgentBond slashed → InsurancePool credited"
        );
        Ok((final_slashed, snapshot))
    }

    // ---- Read accessors -----------------------------------------------------

    pub fn get(&self, agent_did: &str) -> Option<AgentBondState> {
        self.bonds.get(agent_did).map(|r| r.clone())
    }

    pub fn list_by_controller(&self, controller_did: &str) -> Vec<AgentBondState> {
        let agent_dids = match self.by_controller.get(controller_did) {
            Some(r) => r.clone(),
            None => return Vec::new(),
        };
        agent_dids
            .into_iter()
            .filter_map(|did| self.bonds.get(&did).map(|r| r.clone()))
            .collect()
    }

    /// Sum of `amount` across every Active bond owned by `controller_did`.
    /// Used for the receipt `controller_bond_aggregate` field (Spec 5).
    pub fn aggregate_bond(&self, controller_did: &str) -> u128 {
        self.list_by_controller(controller_did)
            .iter()
            .filter(|b| b.is_promotion_eligible())
            .map(|b| b.amount)
            .fold(0u128, |acc, a| acc.saturating_add(a))
    }

    /// Lane-promotion query for the resolver. Returns the bond amount
    /// if eligible (Active state), else 0.
    pub fn effective_bond_for_promotion(&self, agent_did: &str) -> u128 {
        self.bonds
            .get(agent_did)
            .map(|r| r.effective_for_promotion())
            .unwrap_or(0)
    }

    /// `true` if the agent has an Active bond at or above `threshold`.
    /// Hot path — called per-admission by the lane resolver.
    pub fn has_active_bond_at_least(&self, agent_did: &str, threshold: u128) -> bool {
        self.effective_bond_for_promotion(agent_did) >= threshold
    }

    // ---- Insurance claims ---------------------------------------------------

    /// File a new insurance claim. Returns the deterministic claim_id and
    /// inserts an `Open` claim record.
    pub fn file_claim(
        &self,
        claimant_did: &str,
        claimant_address: Address,
        against_agent_did: &str,
        amount_requested: u128,
        receipt_refs: Vec<String>,
        narrative: Option<String>,
        nonce_le: u64,
    ) -> Result<ClaimRecord> {
        if amount_requested == 0 {
            return Err(TokenError::InvalidParameter(
                "claim amount must be > 0".to_string(),
            ));
        }
        let claim_id = derive_claim_id(claimant_did, against_agent_did, nonce_le);
        let claim_id_hex = hex::encode(claim_id);
        if self.claims.contains_key(&claim_id_hex) {
            return Err(TokenError::InvalidParameter(format!(
                "claim {} already exists",
                claim_id_hex
            )));
        }
        let record = ClaimRecord {
            claim_id: claim_id_hex.clone(),
            claimant_did: claimant_did.to_string(),
            against_agent_did: against_agent_did.to_string(),
            amount_requested,
            receipt_refs,
            narrative,
            status: ClaimStatus::Open,
            governance_ref: None,
            paid_amount: None,
            filed_at: Timestamp::now(),
            claimant_address,
        };
        self.persist_claim(&record)?;
        self.claims.insert(claim_id_hex.clone(), record.clone());
        {
            let mut pool = self.pool.write();
            pool.open_claim_count = pool.open_claim_count.saturating_add(1);
            self.persist_pool(&pool)?;
        }
        info!(
            claim = %claim_id_hex,
            claimant = %claimant_did,
            against = %against_agent_did,
            amount_requested,
            "Insurance claim filed"
        );
        Ok(record)
    }

    /// Approve a claim with a payout amount (governance proposal passed).
    /// Stays in `Approved` state until the pool can fund the payout via
    /// [`pay_claim`].
    pub fn approve_claim(
        &self,
        claim_id_hex: &str,
        approved_amount: u128,
        governance_ref: String,
    ) -> Result<ClaimRecord> {
        let mut claim_ref = self
            .claims
            .get_mut(claim_id_hex)
            .ok_or_else(|| TokenError::NotFound(format!("claim {} not found", claim_id_hex)))?;
        if claim_ref.status != ClaimStatus::Open {
            return Err(TokenError::InvalidParameter(format!(
                "cannot approve claim in {} state",
                claim_ref.status.as_str()
            )));
        }
        if approved_amount == 0 || approved_amount > claim_ref.amount_requested {
            return Err(TokenError::InvalidParameter(format!(
                "approved_amount {} must be > 0 and <= requested {}",
                approved_amount, claim_ref.amount_requested
            )));
        }
        claim_ref.status = ClaimStatus::Approved;
        claim_ref.paid_amount = Some(approved_amount);
        claim_ref.governance_ref = Some(governance_ref);
        let snapshot = claim_ref.clone();
        drop(claim_ref);
        self.persist_claim(&snapshot)?;
        info!(claim = %claim_id_hex, approved_amount, "Insurance claim approved");
        Ok(snapshot)
    }

    /// Reject a claim (governance vote against).
    pub fn reject_claim(
        &self,
        claim_id_hex: &str,
        governance_ref: String,
    ) -> Result<ClaimRecord> {
        let mut claim_ref = self
            .claims
            .get_mut(claim_id_hex)
            .ok_or_else(|| TokenError::NotFound(format!("claim {} not found", claim_id_hex)))?;
        if claim_ref.status != ClaimStatus::Open {
            return Err(TokenError::InvalidParameter(format!(
                "cannot reject claim in {} state",
                claim_ref.status.as_str()
            )));
        }
        claim_ref.status = ClaimStatus::Rejected;
        claim_ref.governance_ref = Some(governance_ref);
        let snapshot = claim_ref.clone();
        drop(claim_ref);
        self.persist_claim(&snapshot)?;
        {
            let mut pool = self.pool.write();
            pool.open_claim_count = pool.open_claim_count.saturating_sub(1);
            self.persist_pool(&pool)?;
        }
        info!(claim = %claim_id_hex, "Insurance claim rejected");
        Ok(snapshot)
    }

    /// Execute a payout for an Approved claim. Debits the pool, marks
    /// the claim Paid, and updates aggregates. The VM handler is
    /// responsible for crediting the claimant's wallet from the
    /// InsurancePool vault address.
    ///
    /// Rejects if pool balance is insufficient (claim stays Approved
    /// pending refill).
    pub fn pay_claim(&self, claim_id_hex: &str) -> Result<ClaimRecord> {
        let mut claim_ref = self
            .claims
            .get_mut(claim_id_hex)
            .ok_or_else(|| TokenError::NotFound(format!("claim {} not found", claim_id_hex)))?;
        if claim_ref.status != ClaimStatus::Approved {
            return Err(TokenError::InvalidParameter(format!(
                "cannot pay claim in {} state",
                claim_ref.status.as_str()
            )));
        }
        let amount = claim_ref.paid_amount.ok_or_else(|| {
            TokenError::InvalidParameter("approved claim missing paid_amount".to_string())
        })?;
        let mut pool = self.pool.write();
        if pool.balance_tnzo < amount {
            return Err(TokenError::InsufficientBalance {
                required: amount,
                available: pool.balance_tnzo,
            });
        }
        pool.balance_tnzo = pool.balance_tnzo.saturating_sub(amount);
        pool.paid_claims = pool.paid_claims.saturating_add(1);
        pool.total_paid_tnzo = pool.total_paid_tnzo.saturating_add(amount);
        pool.open_claim_count = pool.open_claim_count.saturating_sub(1);
        self.persist_pool(&pool)?;
        drop(pool);

        claim_ref.status = ClaimStatus::Paid;
        let snapshot = claim_ref.clone();
        drop(claim_ref);
        self.persist_claim(&snapshot)?;
        info!(claim = %claim_id_hex, amount, "Insurance claim paid");
        Ok(snapshot)
    }

    pub fn get_claim(&self, claim_id_hex: &str) -> Option<ClaimRecord> {
        self.claims.get(claim_id_hex).map(|r| r.clone())
    }

    pub fn list_claims(&self) -> Vec<ClaimRecord> {
        self.claims.iter().map(|r| r.value().clone()).collect()
    }

    pub fn pool_state(&self) -> InsurancePoolState {
        self.pool.read().clone()
    }
}

/// Bridge from `BondManager` to the principal-chain receipt envelope
/// (Spec 5 + Spec 9). Implemented here, not in `tenzro-types`, because
/// `BondManager` is the live source of truth and `tenzro-types` has no
/// dependency on the token crate.
///
/// The mapping:
/// - `actor_bond(did)` → `effective_for_promotion()` of the agent's
///   `AgentBondState` when present, else `None`. Returning `None` for
///   states like `Slashed`/`Returned` (which have `effective == 0`)
///   keeps the receipt field clean — only meaningful, promotion-eligible
///   bonds appear.
/// - `controller_aggregate(did)` → `BondManager::aggregate_bond(did)`,
///   wrapped in `Some` only when non-zero so the JSON omits the field
///   for controllers with no Active bonds.
impl tenzro_types::principal_chain::BondLookup for BondManager {
    fn actor_bond(&self, did: &str) -> Option<u128> {
        let amount = self.effective_bond_for_promotion(did);
        if amount == 0 {
            None
        } else {
            Some(amount)
        }
    }

    fn controller_aggregate(&self, controller_did: &str) -> Option<u128> {
        let total = self.aggregate_bond(controller_did);
        if total == 0 {
            None
        } else {
            Some(total)
        }
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
        let m = BondManager::new();
        let bond = m
            .post("did:tenzro:machine:a", "did:tenzro:human:c", 5_000, 100)
            .unwrap();
        assert_eq!(bond.state, BondLifecycle::Active);
        assert_eq!(bond.amount, 5_000);
        assert_eq!(m.effective_bond_for_promotion("did:tenzro:machine:a"), 5_000);
    }

    #[test]
    fn double_post_rejects() {
        let m = BondManager::new();
        m.post("a", "c", 100, 1).unwrap();
        assert!(m.post("a", "c", 100, 2).is_err());
    }

    #[test]
    fn increase_only_active() {
        let m = BondManager::new();
        m.post("a", "c", 100, 1).unwrap();
        m.increase("a", 50, 2).unwrap();
        assert_eq!(m.get("a").unwrap().amount, 150);
        m.withdraw("a", 3).unwrap();
        assert!(m.increase("a", 50, 4).is_err());
    }

    #[test]
    fn withdraw_demotes_lane() {
        let m = BondManager::new();
        m.post("a", "c", 100, 1).unwrap();
        assert_eq!(m.effective_bond_for_promotion("a"), 100);
        m.withdraw("a", 2).unwrap();
        // Cooldown is not promotion-eligible.
        assert_eq!(m.effective_bond_for_promotion("a"), 0);
    }

    #[test]
    fn freeze_blocks_withdrawal() {
        let m = BondManager::new();
        m.post("a", "c", 100, 1).unwrap();
        m.freeze("a", "quarantine_test", 2).unwrap();
        assert!(m.withdraw("a", 3).is_err());
        assert_eq!(m.get("a").unwrap().state, BondLifecycle::Frozen);
    }

    #[test]
    fn slash_credits_pool_and_demotes() {
        let m = BondManager::new();
        m.post("a", "c", 1_000_000_000_000_000_000_000u128, 1).unwrap(); // 1000 TNZO
        let (slashed, bond) = m.slash("a", 2500, None, "terminate", 2).unwrap();
        // 25% of 1000 = 250
        assert_eq!(slashed, 250_000_000_000_000_000_000u128);
        assert_eq!(bond.amount, 750_000_000_000_000_000_000u128);
        assert_eq!(m.pool_state().balance_tnzo, 250_000_000_000_000_000_000u128);
        assert_eq!(bond.state, BondLifecycle::Active);
    }

    #[test]
    fn slash_below_residual_drains_fully() {
        let m = BondManager::new();
        // Bond of 12 TNZO, residual floor is 10 TNZO. A 50% slash leaves 6 → fully drains.
        m.post("a", "c", 12 * 1_000_000_000_000_000_000u128, 1).unwrap();
        let (slashed, bond) = m.slash("a", 5000, None, "terminate", 2).unwrap();
        assert_eq!(slashed, 12 * 1_000_000_000_000_000_000u128);
        assert_eq!(bond.amount, 0);
        assert_eq!(bond.state, BondLifecycle::Slashed);
    }

    #[test]
    fn slash_rejects_above_max_bps() {
        let m = BondManager::new();
        m.post("a", "c", 1_000, 1).unwrap();
        assert!(m.slash("a", 6000, None, "terminate", 2).is_err());
    }

    #[test]
    fn aggregate_bond_only_active() {
        let m = BondManager::new();
        m.post("a", "ctrl", 1_000, 1).unwrap();
        m.post("b", "ctrl", 5_000, 2).unwrap();
        m.post("c", "ctrl", 10_000, 3).unwrap();
        m.withdraw("a", 4).unwrap(); // Cooldown — excluded
        assert_eq!(m.aggregate_bond("ctrl"), 15_000);
    }

    #[test]
    fn claim_full_flow() {
        let m = BondManager::new();
        // Seed pool via slashing.
        m.post("a", "c", 100_000_000_000_000_000_000_000u128, 1).unwrap(); // 100k
        m.slash("a", 5000, None, "terminate", 2).unwrap();
        let pool_before = m.pool_state().balance_tnzo;
        assert!(pool_before >= 50_000_000_000_000_000_000_000u128);

        let claim = m
            .file_claim(
                "did:tenzro:human:victim",
                addr(0xab),
                "did:tenzro:machine:bad",
                10_000_000_000_000_000_000u128, // 10 TNZO
                vec!["receipt:1".into()],
                Some("agent didn't deliver".into()),
                42,
            )
            .unwrap();
        m.approve_claim(&claim.claim_id, 5_000_000_000_000_000_000u128, "prop:99".into())
            .unwrap();
        let paid = m.pay_claim(&claim.claim_id).unwrap();
        assert_eq!(paid.status, ClaimStatus::Paid);
        assert_eq!(paid.paid_amount, Some(5_000_000_000_000_000_000u128));
        assert_eq!(m.pool_state().total_paid_tnzo, 5_000_000_000_000_000_000u128);
        assert_eq!(
            m.pool_state().balance_tnzo,
            pool_before - 5_000_000_000_000_000_000u128
        );
    }

    #[test]
    fn pay_claim_rejects_when_pool_underfunded() {
        let m = BondManager::new();
        let claim = m
            .file_claim(
                "did:tenzro:human:victim",
                addr(0xab),
                "did:tenzro:machine:bad",
                100,
                vec!["receipt:1".into()],
                None,
                7,
            )
            .unwrap();
        m.approve_claim(&claim.claim_id, 100, "prop:1".into()).unwrap();
        // Pool is empty — pay should fail.
        assert!(m.pay_claim(&claim.claim_id).is_err());
        // Claim stays Approved, eligible for retry once pool refills.
        assert_eq!(
            m.get_claim(&claim.claim_id).unwrap().status,
            ClaimStatus::Approved
        );
    }
}
