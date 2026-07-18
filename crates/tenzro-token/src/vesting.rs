//! Vesting primitive for non-fee TNZO flows.
//!
//! Every non-fee TNZO flow passes through a vesting schedule
//! (tokenomics economic model §5):
//!
//! | Flow | Liquid at claim | Vesting |
//! |---|---|---|
//! | Earned rewards (T1/T2 operators, providers, apps) | 25% | 75% linear over 12 months |
//! | Earned rewards (T3 RPC / governance tier) | 30% | 70% linear over 12 months |
//! | Sponsored operators | 0% until graduated | rewards auto-convert to self-owned stake |
//! | Grants | per-charter | default 6-month linear per tranche |
//! | Core contributors | 0% | 12-month cliff + 36-month linear |
//!
//! The liquid/vesting split itself is computed by the caller (the
//! [`RewardEngine`](crate::rewards::RewardEngine) claim path for rewards,
//! the treasury charter machinery for grants); this module owns the
//! vesting side: schedule accrual, release accounting, and the slashing
//! order hook (junior bond → **vesting balance** → owned stake).
//!
//! Vesting balances are non-transferable and non-stakeable — there is no
//! transfer surface on this type. Sponsored-operator reward conversion
//! bypasses vesting entirely (it becomes stake, not a schedule) and is
//! owned by the sponsorship manager.
//!
//! Accrual semantics: nothing accrues before `start + cliff`; from that
//! point the total accrues linearly over `duration`; everything is
//! accrued at `start + cliff + duration`.
//!
//! Storage layout (`CF_TOKENS`):
//! - `vesting:<addr hex>` → JSON-encoded `Vec<VestingSchedule>` for that
//!   address (all schedules under one key so write-through is atomic per
//!   address).
//!
//! All TNZO amounts are 18-decimal base units.

use crate::error::{Result, TokenError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::{KvStore, WriteOp, CF_TOKENS};
use tenzro_types::primitives::{Address, Timestamp};
use tracing::{debug, info, warn};

/// Prefix for per-address vesting records: `vesting:<addr hex>`.
pub const VESTING_PREFIX: &[u8] = b"vesting:";

/// One day in milliseconds.
pub const DAY_MILLIS: i64 = 86_400_000;

/// Reward vesting duration: 12 months (365 days), linear, no cliff.
pub const REWARD_VESTING_MS: i64 = 365 * DAY_MILLIS;

/// Default grant tranche vesting duration: 6 months, linear, no cliff.
pub const GRANT_VESTING_MS: i64 = 180 * DAY_MILLIS;

/// Core-contributor cliff: 12 months of zero accrual.
pub const CONTRIBUTOR_CLIFF_MS: i64 = 365 * DAY_MILLIS;

/// Core-contributor accrual window after the cliff: 36 months linear.
pub const CONTRIBUTOR_VESTING_MS: i64 = 3 * 365 * DAY_MILLIS;

/// Which flow created a schedule. Determines nothing mechanically —
/// accrual is fully described by `(start, cliff, duration)` — but is
/// surfaced in RPC listings so operators can distinguish reward vesting
/// from grant tranches and contributor locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VestingKind {
    /// Vesting portion of a claimed reward coupon (§5 row 1–2).
    Reward,
    /// Milestone tranche of a development grant (§5 row 4).
    Grant,
    /// Core-contributor allocation lock (§5 row 5).
    Contributor,
}

impl VestingKind {
    pub fn as_key(&self) -> &'static str {
        match self {
            VestingKind::Reward => "reward",
            VestingKind::Grant => "grant",
            VestingKind::Contributor => "contributor",
        }
    }
}

/// A single vesting schedule. Multiple schedules per address are normal
/// (every reward claim appends one).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Per-address sequence number, assigned at creation.
    pub seq: u64,
    /// Beneficiary.
    pub address: Address,
    /// Originating flow.
    pub kind: VestingKind,
    /// Total amount placed under this schedule. Reduced by slashing.
    pub total: u128,
    /// Amount already released to the beneficiary.
    pub released: u128,
    /// Accrual clock origin (ms since Unix epoch).
    pub start_ms: i64,
    /// Zero-accrual window after `start_ms`.
    pub cliff_ms: i64,
    /// Linear accrual window after the cliff. Always > 0.
    pub duration_ms: i64,
    /// When the schedule was created.
    pub created_at: Timestamp,
}

impl VestingSchedule {
    /// Amount accrued at `now_ms`: 0 before `start + cliff`, linear over
    /// `duration` after it, `total` once the window has fully elapsed.
    pub fn vested_at(&self, now_ms: i64) -> u128 {
        let accrual_start = self.start_ms.saturating_add(self.cliff_ms);
        if now_ms < accrual_start {
            return 0;
        }
        let elapsed = (now_ms - accrual_start) as u128;
        let duration = self.duration_ms as u128;
        if elapsed >= duration {
            return self.total;
        }
        // Quotient/remainder decomposition to avoid overflow on
        // total * elapsed.
        (self.total / duration) * elapsed + (self.total % duration) * elapsed / duration
    }

    /// Accrued but not yet released at `now_ms`.
    pub fn releasable_at(&self, now_ms: i64) -> u128 {
        self.vested_at(now_ms).saturating_sub(self.released)
    }

    /// Everything not yet released — the slashable vesting balance.
    pub fn outstanding(&self) -> u128 {
        self.total.saturating_sub(self.released)
    }
}

/// Owns all vesting schedules with optional RocksDB write-through.
pub struct VestingManager {
    schedules: DashMap<Address, Vec<VestingSchedule>>,
    storage: Option<Arc<dyn KvStore>>,
}

impl VestingManager {
    /// In-memory manager (tests, storage-less nodes).
    pub fn new() -> Self {
        Self {
            schedules: DashMap::new(),
            storage: None,
        }
    }

    /// Manager with RocksDB write-through. Hydrates all per-address
    /// records from `CF_TOKENS`; unreadable records are dropped and
    /// deleted (pre-launch flag-day policy).
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let schedules: DashMap<Address, Vec<VestingSchedule>> = DashMap::new();
        let mut drops: Vec<WriteOp> = Vec::new();
        let mut restored = 0usize;

        for key in storage.get_keys_with_prefix(CF_TOKENS, VESTING_PREFIX)? {
            let list = storage
                .get(CF_TOKENS, &key)?
                .and_then(|bytes| serde_json::from_slice::<Vec<VestingSchedule>>(&bytes).ok());
            let parsed = parse_vesting_key(&key).zip(list);
            match parsed {
                Some((address, list)) => {
                    restored += list.len();
                    schedules.insert(address, list);
                }
                None => {
                    warn!(
                        key = %String::from_utf8_lossy(&key),
                        "dropping unreadable vesting record"
                    );
                    drops.push(WriteOp::Delete {
                        cf: CF_TOKENS.to_string(),
                        key,
                    });
                }
            }
        }
        if !drops.is_empty() {
            storage.write_batch_sync(drops)?;
        }
        info!(schedules = restored, "vesting manager hydrated");

        Ok(Self {
            schedules,
            storage: Some(storage),
        })
    }

    /// Create a schedule with explicit accrual parameters.
    pub fn create_schedule(
        &self,
        address: Address,
        kind: VestingKind,
        total: u128,
        start_ms: i64,
        cliff_ms: i64,
        duration_ms: i64,
    ) -> Result<VestingSchedule> {
        if total == 0 {
            return Err(TokenError::InvalidAmount(
                "vesting amount must be non-zero".to_string(),
            ));
        }
        if duration_ms <= 0 {
            return Err(TokenError::InvalidParameter(
                "vesting duration must be positive".to_string(),
            ));
        }
        if cliff_ms < 0 {
            return Err(TokenError::InvalidParameter(
                "vesting cliff must be non-negative".to_string(),
            ));
        }

        let mut entry = self.schedules.entry(address).or_default();
        let schedule = VestingSchedule {
            seq: entry.len() as u64,
            address,
            kind,
            total,
            released: 0,
            start_ms,
            cliff_ms,
            duration_ms,
            created_at: Timestamp::now(),
        };
        entry.push(schedule.clone());
        let snapshot = entry.clone();
        drop(entry);

        self.persist(&address, &snapshot)?;
        debug!(
            address = %hex::encode(address.as_bytes()),
            kind = kind.as_key(),
            total,
            "vesting schedule created"
        );
        Ok(schedule)
    }

    /// Reward-claim vesting portion: 12-month linear, no cliff.
    pub fn create_reward_vesting(
        &self,
        address: Address,
        amount: u128,
        start_ms: i64,
    ) -> Result<VestingSchedule> {
        self.create_schedule(address, VestingKind::Reward, amount, start_ms, 0, REWARD_VESTING_MS)
    }

    /// Grant tranche: 6-month linear, no cliff.
    pub fn create_grant_vesting(
        &self,
        address: Address,
        amount: u128,
        start_ms: i64,
    ) -> Result<VestingSchedule> {
        self.create_schedule(address, VestingKind::Grant, amount, start_ms, 0, GRANT_VESTING_MS)
    }

    /// Core-contributor lock: 12-month cliff, then 36-month linear.
    pub fn create_contributor_vesting(
        &self,
        address: Address,
        amount: u128,
        start_ms: i64,
    ) -> Result<VestingSchedule> {
        self.create_schedule(
            address,
            VestingKind::Contributor,
            amount,
            start_ms,
            CONTRIBUTOR_CLIFF_MS,
            CONTRIBUTOR_VESTING_MS,
        )
    }

    /// Total releasable across all of an address's schedules at `now_ms`.
    pub fn releasable(&self, address: &Address, now_ms: i64) -> u128 {
        self.schedules
            .get(address)
            .map(|list| list.iter().map(|s| s.releasable_at(now_ms)).sum())
            .unwrap_or(0)
    }

    /// Release everything releasable at `now_ms`. Returns the released
    /// amount; the caller credits the beneficiary (mint or balance
    /// transfer — the manager only does accounting).
    pub fn release(&self, address: &Address, now_ms: i64) -> Result<u128> {
        let mut entry = self.schedules.get_mut(address).ok_or_else(|| {
            TokenError::NotFound(format!(
                "no vesting schedules for {}",
                hex::encode(address.as_bytes())
            ))
        })?;

        let mut released = 0u128;
        for schedule in entry.iter_mut() {
            let amount = schedule.releasable_at(now_ms);
            if amount > 0 {
                schedule.released = schedule.released.saturating_add(amount);
                released = released.saturating_add(amount);
            }
        }
        if released == 0 {
            return Err(TokenError::NotFound(
                "no releasable vesting balance".to_string(),
            ));
        }
        let snapshot = entry.clone();
        drop(entry);

        self.persist(address, &snapshot)?;
        info!(
            address = %hex::encode(address.as_bytes()),
            released,
            "vesting balance released"
        );
        Ok(released)
    }

    /// Consume up to `amount` from the address's unreleased vesting
    /// balance for slashing (order: junior bond → vesting → owned stake;
    /// the staking layer calls this between the other two). Consumes
    /// newest schedules first so the longest-standing accrual position
    /// survives longest. Returns the amount actually consumed — the
    /// caller slashes the remainder from owned stake.
    pub fn slash(&self, address: &Address, amount: u128) -> Result<u128> {
        if amount == 0 {
            return Ok(0);
        }
        let Some(mut entry) = self.schedules.get_mut(address) else {
            return Ok(0);
        };

        let mut remaining = amount;
        for schedule in entry.iter_mut().rev() {
            if remaining == 0 {
                break;
            }
            let take = schedule.outstanding().min(remaining);
            if take > 0 {
                schedule.total = schedule.total.saturating_sub(take);
                remaining -= take;
            }
        }
        let consumed = amount - remaining;
        if consumed == 0 {
            return Ok(0);
        }
        let snapshot = entry.clone();
        drop(entry);

        self.persist(address, &snapshot)?;
        warn!(
            address = %hex::encode(address.as_bytes()),
            consumed,
            "vesting balance slashed"
        );
        Ok(consumed)
    }

    /// Total unreleased vesting balance for an address.
    pub fn total_outstanding(&self, address: &Address) -> u128 {
        self.schedules
            .get(address)
            .map(|list| list.iter().map(|s| s.outstanding()).sum())
            .unwrap_or(0)
    }

    /// Network-wide unreleased vesting balance (supply metrics input).
    pub fn outstanding_total(&self) -> u128 {
        self.schedules
            .iter()
            .map(|entry| entry.value().iter().map(|s| s.outstanding()).sum::<u128>())
            .sum()
    }

    /// All schedules for an address.
    pub fn list_schedules(&self, address: &Address) -> Vec<VestingSchedule> {
        self.schedules
            .get(address)
            .map(|list| list.clone())
            .unwrap_or_default()
    }

    fn persist(&self, address: &Address, list: &[VestingSchedule]) -> Result<()> {
        if let Some(storage) = &self.storage {
            storage.write_batch_sync(vec![WriteOp::Put {
                cf: CF_TOKENS.to_string(),
                key: vesting_key(address),
                value: serde_json::to_vec(list)
                    .map_err(|e| TokenError::StorageError(e.to_string()))?,
            }])?;
        }
        Ok(())
    }
}

impl Default for VestingManager {
    fn default() -> Self {
        Self::new()
    }
}

/// `vesting:<addr hex>` storage key.
pub fn vesting_key(address: &Address) -> Vec<u8> {
    let mut key = VESTING_PREFIX.to_vec();
    key.extend_from_slice(hex::encode(address.as_bytes()).as_bytes());
    key
}

/// Decode the address back out of a `vesting:` storage key.
fn parse_vesting_key(key: &[u8]) -> Option<Address> {
    let suffix = key.strip_prefix(VESTING_PREFIX)?;
    let bytes: [u8; 32] = hex::decode(std::str::from_utf8(suffix).ok()?)
        .ok()?
        .try_into()
        .ok()?;
    Some(Address::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::new([byte; 32])
    }

    #[test]
    fn linear_accrual_midpoint() {
        let m = VestingManager::new();
        let a = addr(1);
        let s = m
            .create_reward_vesting(a, 1_000_000, 0)
            .expect("create");
        assert_eq!(s.vested_at(-1), 0);
        assert_eq!(s.vested_at(0), 0);
        assert_eq!(s.vested_at(REWARD_VESTING_MS / 2), 500_000);
        assert_eq!(s.vested_at(REWARD_VESTING_MS), 1_000_000);
        assert_eq!(s.vested_at(REWARD_VESTING_MS * 2), 1_000_000);
    }

    #[test]
    fn cliff_gates_accrual() {
        let m = VestingManager::new();
        let a = addr(2);
        let s = m
            .create_contributor_vesting(a, 3_600_000, 0)
            .expect("create");
        // Nothing through the entire cliff.
        assert_eq!(s.vested_at(CONTRIBUTOR_CLIFF_MS - 1), 0);
        assert_eq!(s.vested_at(CONTRIBUTOR_CLIFF_MS), 0);
        // Linear from the cliff onward.
        let one_third = CONTRIBUTOR_CLIFF_MS + CONTRIBUTOR_VESTING_MS / 3;
        assert_eq!(s.vested_at(one_third), 1_200_000);
        assert_eq!(
            s.vested_at(CONTRIBUTOR_CLIFF_MS + CONTRIBUTOR_VESTING_MS),
            3_600_000
        );
    }

    #[test]
    fn release_accounting() {
        let m = VestingManager::new();
        let a = addr(3);
        m.create_reward_vesting(a, 1_000_000, 0).expect("create");

        let half = REWARD_VESTING_MS / 2;
        assert_eq!(m.releasable(&a, half), 500_000);
        assert_eq!(m.release(&a, half).expect("release"), 500_000);
        assert_eq!(m.releasable(&a, half), 0);
        // Second release at the same instant has nothing to release.
        assert!(matches!(m.release(&a, half), Err(TokenError::NotFound(_))));
        // Full window releases the remainder.
        assert_eq!(
            m.release(&a, REWARD_VESTING_MS).expect("release rest"),
            500_000
        );
        assert_eq!(m.total_outstanding(&a), 0);
    }

    #[test]
    fn release_unknown_address_errors() {
        let m = VestingManager::new();
        assert!(matches!(
            m.release(&addr(9), 0),
            Err(TokenError::NotFound(_))
        ));
    }

    #[test]
    fn slash_consumes_newest_first_and_floors_at_released() {
        let m = VestingManager::new();
        let a = addr(4);
        m.create_reward_vesting(a, 600, 0).expect("older");
        m.create_reward_vesting(a, 400, 0).expect("newer");

        // Release half of everything first (500 of 1000).
        let half = REWARD_VESTING_MS / 2;
        assert_eq!(m.release(&a, half).expect("release"), 500);
        assert_eq!(m.total_outstanding(&a), 500);

        // Slash 350: newest schedule outstanding is 200 (400 - 200
        // released), older is 300 — take 200 from newest, 150 from older.
        assert_eq!(m.slash(&a, 350).expect("slash"), 350);
        assert_eq!(m.total_outstanding(&a), 150);

        let list = m.list_schedules(&a);
        assert_eq!(list[1].total, 200); // newest fully consumed to floor
        assert_eq!(list[1].outstanding(), 0);
        assert_eq!(list[0].total, 450);
        assert_eq!(list[0].outstanding(), 150);

        // Slashing beyond the balance consumes only what exists.
        assert_eq!(m.slash(&a, 10_000).expect("overslash"), 150);
        assert_eq!(m.total_outstanding(&a), 0);
        // Nothing left: zero consumed, remainder falls to owned stake.
        assert_eq!(m.slash(&a, 100).expect("empty"), 0);
    }

    #[test]
    fn slash_unknown_address_consumes_nothing() {
        let m = VestingManager::new();
        assert_eq!(m.slash(&addr(8), 100).expect("slash"), 0);
    }

    #[test]
    fn multiple_schedules_aggregate() {
        let m = VestingManager::new();
        let a = addr(5);
        m.create_reward_vesting(a, 1_000, 0).expect("r");
        m.create_grant_vesting(a, 2_000, 0).expect("g");

        // Grant (180d) fully vested at 365d; reward fully vested too.
        assert_eq!(m.releasable(&a, REWARD_VESTING_MS), 3_000);
        assert_eq!(m.total_outstanding(&a), 3_000);
        assert_eq!(m.outstanding_total(), 3_000);

        let list = m.list_schedules(&a);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].seq, 0);
        assert_eq!(list[1].seq, 1);
        assert_eq!(list[0].kind.as_key(), "reward");
        assert_eq!(list[1].kind.as_key(), "grant");
    }

    #[test]
    fn create_validation() {
        let m = VestingManager::new();
        assert!(matches!(
            m.create_reward_vesting(addr(6), 0, 0),
            Err(TokenError::InvalidAmount(_))
        ));
        assert!(matches!(
            m.create_schedule(addr(6), VestingKind::Reward, 100, 0, 0, 0),
            Err(TokenError::InvalidParameter(_))
        ));
        assert!(matches!(
            m.create_schedule(addr(6), VestingKind::Reward, 100, 0, -1, 100),
            Err(TokenError::InvalidParameter(_))
        ));
    }

    #[test]
    fn vesting_key_roundtrip() {
        let a = addr(7);
        let key = vesting_key(&a);
        assert!(key.starts_with(VESTING_PREFIX));
        assert_eq!(parse_vesting_key(&key), Some(a));
        assert_eq!(parse_vesting_key(b"vesting:zzzz"), None);
        assert_eq!(parse_vesting_key(b"other:00"), None);
    }

    #[test]
    fn dust_bound_no_over_release() {
        let m = VestingManager::new();
        let a = addr(10);
        // Awkward total vs duration to force rounding.
        let s = m
            .create_schedule(a, VestingKind::Reward, 1_000_003, 0, 0, 7)
            .expect("create");
        let mut cumulative = 0u128;
        for t in 0..=7 {
            let v = s.vested_at(t);
            assert!(v >= cumulative, "monotone");
            assert!(v <= 1_000_003, "never exceeds total");
            cumulative = v;
        }
        assert_eq!(s.vested_at(7), 1_000_003);
    }
}
