//! BurnQuota primitive (Agent-Swarm Spec 3 — wave 1).
//!
//! The full spec ([dual-rail-gas.md](../../../docs/architecture/agent-swarm/dual-rail-gas.md))
//! describes a stablecoin paymaster that sponsors TNZO gas to the EntryPoint
//! drawn from a treasury-funded **burn quota**. This module lands the
//! protocol-side accounting primitive: a singleton `BurnQuota` record with
//! `try_drain` / `refill` operations, write-through persistence under
//! `CF_TOKENS`, and read access via `state()`.
//!
//! Wave 1 ships only the primitive — the `StablecoinPaymaster`,
//! Chainlink/Pyth oracle, and AMM TWAP swap-and-burn refill loop are
//! deferred until the bridge mesh (Wormhole NTT USDC pool) and oracle
//! integrations land. Once those are in place, the paymaster will plug into
//! this exact API: the validate path consults `try_drain(tnzo_gas_estimate,
//! now)` and fails closed if it returns `Err(QuotaExhausted)`; the daily
//! replenisher calls `refill(amount, now)` after a successful TWAP swap.
//!
//! Storage layout (`CF_TOKENS`):
//! - `burn_quota:singleton` → JSON-encoded [`BurnQuota`].
//!
//! All amounts are in 18-decimal TNZO base units (i.e. `1 TNZO = 10^18`),
//! consistent with the rest of `tenzro-token`.

use crate::error::{Result, TokenError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::{KvStore, WriteOp, CF_TOKENS};
use tenzro_types::primitives::Timestamp;
use tracing::{debug, info};

/// Singleton storage key for the `BurnQuota` record under `CF_TOKENS`.
pub const BURN_QUOTA_KEY: &[u8] = b"burn_quota:singleton";

/// Default daily refill target: 1,000,000 TNZO (in 1e18 units).
/// Matches `daily_refill_target` from dual-rail-gas.md §"Governance dials".
pub const DEFAULT_DAILY_REFILL_TARGET: u128 = 1_000_000 * 1_000_000_000_000_000_000;

/// Default cap on the quota balance: 10× the daily target. Caps the
/// treasury's outstanding sponsorship at any moment.
pub const DEFAULT_CAP: u128 = 10 * DEFAULT_DAILY_REFILL_TARGET;

/// Default minimum reserve as a fraction of `cap`, in basis points.
/// `1000 bps = 10%`. Below this, the paymaster fails closed — see
/// dual-rail-gas.md §"Burn quota": *"users never get USDC-paid gas without
/// an equivalent TNZO burn waiting in the quota."*
pub const DEFAULT_MIN_RESERVE_BPS: u16 = 1000;

/// Persistent state for the protocol's TNZO burn quota.
///
/// Singleton: at any time there is exactly one `BurnQuota` record, stored
/// under `CF_TOKENS/burn_quota:singleton`. It tracks the TNZO that the
/// stablecoin paymaster is allowed to sponsor before the next refill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnQuota {
    /// TNZO currently available to sponsor (18-decimal base units).
    pub balance: u128,
    /// Maximum balance. Refills above this are clamped.
    pub cap: u128,
    /// Refill target per epoch. Governance-tunable.
    pub daily_target: u128,
    /// Minimum reserve as a fraction of `cap`, in basis points.
    /// `try_drain` rejects when post-drain balance would drop below this.
    pub min_reserve_bps: u16,
    /// Last time `refill` was called (genesis: 0).
    pub last_refill: Timestamp,
    /// Cumulative TNZO drained since genesis. Audit-only.
    pub total_drained: u128,
    /// Cumulative TNZO refilled since genesis. Audit-only.
    pub total_refilled: u128,
    /// Negative if the prior epoch failed to refill the full target —
    /// carried forward into the next epoch. Positive surplus is *not*
    /// accumulated here (it stays in the paymaster's USDC reserve as
    /// treasury surplus per dual-rail-gas.md §"Treasury accounting").
    pub deficit: i128,
}

impl Default for BurnQuota {
    fn default() -> Self {
        Self {
            balance: 0,
            cap: DEFAULT_CAP,
            daily_target: DEFAULT_DAILY_REFILL_TARGET,
            min_reserve_bps: DEFAULT_MIN_RESERVE_BPS,
            last_refill: Timestamp::default(),
            total_drained: 0,
            total_refilled: 0,
            deficit: 0,
        }
    }
}

impl BurnQuota {
    /// `min_reserve` in TNZO base units, derived from `cap × bps / 10_000`.
    /// Uses quotient/remainder decomposition so the bps math stays precise
    /// even when `cap < 10_000` (where integer-division-first would round
    /// the reserve to zero).
    pub fn min_reserve(&self) -> u128 {
        let q = self.cap / 10_000;
        let r = self.cap % 10_000;
        let bps = self.min_reserve_bps as u128;
        q.saturating_mul(bps)
            .saturating_add(r.saturating_mul(bps) / 10_000)
    }

    /// True iff a drain of `amount` would leave `balance >= min_reserve`.
    pub fn can_drain(&self, amount: u128) -> bool {
        self.balance.saturating_sub(amount) >= self.min_reserve()
    }
}

/// Manages the singleton `BurnQuota` with optional RocksDB write-through.
///
/// Construction:
/// - [`BurnQuotaManager::new`] — pure in-memory (tests).
/// - [`BurnQuotaManager::with_storage`] — write-through + hydrated from disk.
pub struct BurnQuotaManager {
    state: parking_lot::RwLock<BurnQuota>,
    storage: Option<Arc<dyn KvStore>>,
}

impl Default for BurnQuotaManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BurnQuotaManager {
    /// In-memory manager with default genesis parameters.
    pub fn new() -> Self {
        Self {
            state: parking_lot::RwLock::new(BurnQuota::default()),
            storage: None,
        }
    }

    /// Construct with RocksDB write-through and hydrate from
    /// `CF_TOKENS/burn_quota:singleton`. If the key is absent the
    /// manager initializes with `BurnQuota::default()` and persists
    /// the genesis record so subsequent reads see a consistent row.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let mgr = Self {
            state: parking_lot::RwLock::new(BurnQuota::default()),
            storage: Some(storage.clone()),
        };
        mgr.hydrate_from_storage()?;
        Ok(mgr)
    }

    /// Override governance dials after construction. Persists immediately.
    pub fn set_governance_params(
        &self,
        cap: u128,
        daily_target: u128,
        min_reserve_bps: u16,
    ) -> Result<()> {
        if min_reserve_bps > 10_000 {
            return Err(TokenError::InvalidParameter(format!(
                "min_reserve_bps {} > 10000",
                min_reserve_bps
            )));
        }
        let snapshot = {
            let mut guard = self.state.write();
            guard.cap = cap;
            guard.daily_target = daily_target;
            guard.min_reserve_bps = min_reserve_bps;
            // Clamp balance to new cap.
            if guard.balance > cap {
                guard.balance = cap;
            }
            guard.clone()
        };
        self.persist(&snapshot)?;
        info!(
            cap,
            daily_target,
            min_reserve_bps,
            "BurnQuota governance params updated"
        );
        Ok(())
    }

    /// Read a snapshot of the current state.
    pub fn state(&self) -> BurnQuota {
        self.state.read().clone()
    }

    /// Attempt to drain `amount` TNZO from the quota. Used by the
    /// paymaster's `validatePaymasterUserOp` path. Returns
    /// `Err(QuotaExhausted)` when post-drain balance would drop below
    /// `min_reserve`, and `Err(InvalidAmount)` when `amount == 0`.
    ///
    /// On success the quota balance is debited, `total_drained` is
    /// incremented, and the new state is fsync-persisted.
    pub fn try_drain(&self, amount: u128) -> Result<()> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount("burn quota drain == 0".into()));
        }
        let snapshot = {
            let mut guard = self.state.write();
            if !guard.can_drain(amount) {
                return Err(TokenError::InsufficientBalance {
                    required: amount.saturating_add(guard.min_reserve()),
                    available: guard.balance,
                });
            }
            guard.balance = guard
                .balance
                .checked_sub(amount)
                .ok_or_else(|| TokenError::ArithmeticOverflow {
                    operation: "burn_quota.drain".into(),
                })?;
            guard.total_drained = guard.total_drained.saturating_add(amount);
            guard.clone()
        };
        self.persist(&snapshot)?;
        debug!(
            amount,
            balance = snapshot.balance,
            total_drained = snapshot.total_drained,
            "BurnQuota drained"
        );
        Ok(())
    }

    /// Top up the quota with `amount` TNZO at `now`. Used by the daily
    /// replenisher after a successful TWAP swap-and-burn (or, in wave 1,
    /// by the genesis bootstrap and operator-controlled refill RPC).
    ///
    /// Refills above `cap` are clamped — the excess is reported via the
    /// returned `RefillReceipt.excess_clamped` so the caller can credit it
    /// back to the treasury sponsorship allocation.
    pub fn refill(&self, amount: u128, now: Timestamp) -> Result<RefillReceipt> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount("burn quota refill == 0".into()));
        }
        let receipt;
        let snapshot = {
            let mut guard = self.state.write();
            let new_balance = guard.balance.saturating_add(amount);
            let (credited, excess) = if new_balance > guard.cap {
                let credited = guard.cap - guard.balance;
                (credited, amount - credited)
            } else {
                (amount, 0u128)
            };
            guard.balance = guard.balance.saturating_add(credited);
            guard.total_refilled = guard.total_refilled.saturating_add(credited);
            guard.last_refill = now;
            // Reduce deficit by the credited amount; clamped at zero.
            if guard.deficit > 0 {
                let reduce = (credited as i128).min(guard.deficit);
                guard.deficit -= reduce;
            }
            receipt = RefillReceipt {
                requested: amount,
                credited,
                excess_clamped: excess,
                new_balance: guard.balance,
                last_refill: guard.last_refill,
            };
            guard.clone()
        };
        self.persist(&snapshot)?;
        info!(
            requested = receipt.requested,
            credited = receipt.credited,
            excess = receipt.excess_clamped,
            new_balance = receipt.new_balance,
            "BurnQuota refilled"
        );
        Ok(receipt)
    }

    /// Record a refill miss for the current epoch — increments `deficit`
    /// by `target_minus_refilled`. Called by the replenisher when it
    /// could not source enough USDC to swap for the full daily target.
    pub fn record_deficit(&self, missed_amount: u128) -> Result<()> {
        if missed_amount == 0 {
            return Ok(());
        }
        let snapshot = {
            let mut guard = self.state.write();
            guard.deficit = guard.deficit.saturating_add(missed_amount as i128);
            guard.clone()
        };
        self.persist(&snapshot)?;
        Ok(())
    }

    fn hydrate_from_storage(&self) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s.clone(),
            None => return Ok(()),
        };
        match storage
            .get(CF_TOKENS, BURN_QUOTA_KEY)
            .map_err(|e| TokenError::StorageError(format!("get burn quota: {}", e)))?
        {
            Some(value) => {
                let quota: BurnQuota = serde_json::from_slice(&value).map_err(|e| {
                    TokenError::StorageError(format!("decode burn quota: {}", e))
                })?;
                info!(
                    balance = quota.balance,
                    cap = quota.cap,
                    daily_target = quota.daily_target,
                    "BurnQuota hydrated from storage"
                );
                *self.state.write() = quota;
            }
            None => {
                // Genesis: persist the default record so subsequent reads
                // are consistent across restarts.
                let genesis = self.state.read().clone();
                self.persist(&genesis)?;
                info!("BurnQuota initialized from genesis defaults");
            }
        }
        Ok(())
    }

    fn persist(&self, quota: &BurnQuota) -> Result<()> {
        if let Some(storage) = &self.storage {
            let value = serde_json::to_vec(quota).map_err(|e| {
                TokenError::StorageError(format!("encode burn quota: {}", e))
            })?;
            storage
                .write_batch_sync(vec![WriteOp::Put {
                    cf: CF_TOKENS.to_string(),
                    key: BURN_QUOTA_KEY.to_vec(),
                    value,
                }])
                .map_err(|e| {
                    TokenError::StorageError(format!("persist burn quota: {}", e))
                })?;
        }
        Ok(())
    }
}

/// Result of a successful `refill`. Caller uses `excess_clamped` to credit
/// the un-deposited TNZO back to the treasury sponsorship allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefillReceipt {
    pub requested: u128,
    pub credited: u128,
    pub excess_clamped: u128,
    pub new_balance: u128,
    pub last_refill: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_quota() -> BurnQuotaManager {
        let mgr = BurnQuotaManager::new();
        // 1000 TNZO cap, 100 TNZO daily target, 10% min reserve = 100.
        mgr.set_governance_params(1000, 100, 1000).unwrap();
        mgr
    }

    #[test]
    fn default_quota_is_empty() {
        let mgr = BurnQuotaManager::new();
        let s = mgr.state();
        assert_eq!(s.balance, 0);
        assert_eq!(s.cap, DEFAULT_CAP);
        assert_eq!(s.daily_target, DEFAULT_DAILY_REFILL_TARGET);
        assert_eq!(s.min_reserve_bps, DEFAULT_MIN_RESERVE_BPS);
    }

    #[test]
    fn drain_fails_when_balance_below_reserve() {
        let mgr = small_quota();
        // No refill yet — balance 0, so any drain fails.
        let err = mgr.try_drain(10).unwrap_err();
        assert!(matches!(err, TokenError::InsufficientBalance { .. }));
    }

    #[test]
    fn refill_then_drain_above_reserve() {
        let mgr = small_quota();
        let r = mgr.refill(500, Timestamp::new(1_000)).unwrap();
        assert_eq!(r.credited, 500);
        assert_eq!(r.excess_clamped, 0);
        assert_eq!(r.new_balance, 500);
        // min_reserve = 1000 / 10000 * 1000 = 100.
        // Drain 300: post-drain 200 >= 100 → OK.
        mgr.try_drain(300).unwrap();
        assert_eq!(mgr.state().balance, 200);
        assert_eq!(mgr.state().total_drained, 300);
    }

    #[test]
    fn drain_rejected_when_post_drain_below_reserve() {
        let mgr = small_quota();
        mgr.refill(500, Timestamp::new(1_000)).unwrap();
        // min_reserve = 100. Post-drain would be 500 - 410 = 90 < 100.
        let err = mgr.try_drain(410).unwrap_err();
        assert!(matches!(err, TokenError::InsufficientBalance { .. }));
        // Balance unchanged.
        assert_eq!(mgr.state().balance, 500);
    }

    #[test]
    fn refill_clamps_to_cap() {
        let mgr = small_quota();
        mgr.refill(800, Timestamp::new(1_000)).unwrap();
        let r = mgr.refill(500, Timestamp::new(2_000)).unwrap();
        // cap = 1000; balance was 800; can take 200, excess = 300.
        assert_eq!(r.credited, 200);
        assert_eq!(r.excess_clamped, 300);
        assert_eq!(r.new_balance, 1000);
    }

    #[test]
    fn deficit_accumulates_and_clears_on_refill() {
        let mgr = small_quota();
        mgr.record_deficit(50).unwrap();
        mgr.record_deficit(30).unwrap();
        assert_eq!(mgr.state().deficit, 80);
        mgr.refill(100, Timestamp::new(1_000)).unwrap();
        // Credited 100 reduces deficit to 0 (clamped, not negative).
        assert_eq!(mgr.state().deficit, 0);
    }

    #[test]
    fn zero_drain_rejected() {
        let mgr = small_quota();
        let err = mgr.try_drain(0).unwrap_err();
        assert!(matches!(err, TokenError::InvalidAmount(_)));
    }

    #[test]
    fn zero_refill_rejected() {
        let mgr = small_quota();
        let err = mgr.refill(0, Timestamp::new(1_000)).unwrap_err();
        assert!(matches!(err, TokenError::InvalidAmount(_)));
    }

    #[test]
    fn invalid_min_reserve_bps_rejected() {
        let mgr = BurnQuotaManager::new();
        let err = mgr.set_governance_params(1000, 100, 10_001).unwrap_err();
        assert!(matches!(err, TokenError::InvalidParameter(_)));
    }

    #[test]
    fn governance_params_clamp_balance_to_new_cap() {
        let mgr = BurnQuotaManager::new();
        mgr.set_governance_params(1000, 100, 1000).unwrap();
        mgr.refill(900, Timestamp::new(1_000)).unwrap();
        // Lower cap to 500 — balance must clamp.
        mgr.set_governance_params(500, 100, 1000).unwrap();
        assert_eq!(mgr.state().balance, 500);
    }
}
