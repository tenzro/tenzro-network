//! Vesting schedules for non-fee TNZO flows.
//!
//! Every non-fee TNZO flow passes through a vesting schedule
//! (tokenomics economic model §5):
//!
//! | Flow | Liquid at claim | Vesting |
//! |---|---|---|
//! | Earned rewards (T1/T2 operators, providers, apps) | 25% | 75% linear over 12 months |
//! | Earned rewards (T3 RPC / governance tier) | 30% | 70% linear over 12 months |
//! | Grants | per grant proposal | 6-month linear per tranche |
//! | Core contributors | 0% | 12-month cliff + 36-month linear per tranche |
//!
//! This module defines a schedule and its accrual. The schedules themselves
//! live in consensus state, written by the reward claim transaction and by
//! enacted treasury grants (each tranche as the grant proposal's vesting
//! says), and released by the vesting release transaction, so every node
//! holds the same ones.
//!
//! Vesting balances are non-transferable and non-stakeable — there is no
//! transfer surface on a schedule.
//!
//! Accrual semantics: nothing accrues before `start + cliff`; from that
//! point the total accrues linearly over `duration`; everything is
//! accrued at `start + cliff + duration`.
//!
//! All TNZO amounts are 18-decimal base units.

use serde::{Deserialize, Serialize};
use tenzro_types::primitives::{Address, Timestamp};

/// Prefix of the per-address schedule list in consensus state:
/// `vesting:<addr hex>`.
pub const VESTING_PREFIX: &[u8] = b"vesting:";

/// Domain for the vesting escrow account address.
const VESTING_ESCROW_DOMAIN: &[u8] = b"tenzro/vesting-escrow/v1";

/// The account holding every schedule's unreleased TNZO.
///
/// A schedule is funded when it is created, by a transfer into this account
/// from wherever the tokens come from (the rewards pool for reward vesting,
/// the treasury for grants);
/// a release is a transfer out of it. So a schedule can only ever pay out
/// tokens that already exist.
pub fn vesting_escrow_address() -> Address {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(VESTING_ESCROW_DOMAIN);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Address::new(out)
}

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Per-address sequence number, assigned at creation.
    pub seq: u64,
    /// Beneficiary.
    pub address: Address,
    /// Originating flow.
    pub kind: VestingKind,
    /// Total amount placed under this schedule.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub total: u128,
    /// Amount already released to the beneficiary.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
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
        let duration = self.duration_ms.max(1) as u128;
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

    /// Everything not yet released.
    pub fn outstanding(&self) -> u128 {
        self.total.saturating_sub(self.released)
    }
}

/// `vesting:<addr hex>` key of an address's schedule list.
pub fn vesting_key(address: &Address) -> Vec<u8> {
    let mut key = VESTING_PREFIX.to_vec();
    key.extend_from_slice(hex::encode(address.as_bytes()).as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(total: u128, cliff_ms: i64, duration_ms: i64) -> VestingSchedule {
        VestingSchedule {
            seq: 0,
            address: Address::new([1; 32]),
            kind: VestingKind::Reward,
            total,
            released: 0,
            start_ms: 0,
            cliff_ms,
            duration_ms,
            created_at: Timestamp::new(0),
        }
    }

    #[test]
    fn linear_accrual_midpoint() {
        let s = schedule(1_000_000, 0, REWARD_VESTING_MS);
        assert_eq!(s.vested_at(-1), 0);
        assert_eq!(s.vested_at(0), 0);
        assert_eq!(s.vested_at(REWARD_VESTING_MS / 2), 500_000);
        assert_eq!(s.vested_at(REWARD_VESTING_MS), 1_000_000);
        assert_eq!(s.vested_at(REWARD_VESTING_MS * 2), 1_000_000);
    }

    #[test]
    fn cliff_gates_accrual() {
        let s = schedule(4_000, CONTRIBUTOR_CLIFF_MS, CONTRIBUTOR_VESTING_MS);
        assert_eq!(s.vested_at(CONTRIBUTOR_CLIFF_MS - 1), 0);
        assert_eq!(
            s.vested_at(CONTRIBUTOR_CLIFF_MS + CONTRIBUTOR_VESTING_MS / 2),
            2_000
        );
    }

    #[test]
    fn dust_bound_no_over_release() {
        // Awkward total vs duration to force rounding.
        let s = schedule(1_000_003, 0, 7);
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
