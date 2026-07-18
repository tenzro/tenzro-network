//! Hot-state local fee market (Agent-Swarm Spec 6).
//!
//! A single global base fee is the wrong abstraction for parallel execution
//! chains: when one
//! address is hot (everyone wants to write to it), surcharging *every*
//! transaction in the block is over-correction. Block-STM already isolates
//! the contention to the conflicting accounts via its per-tx reexecution
//! counter — the right response is to surcharge writes to those specific
//! accounts, not the block as a whole.
//!
//! This module is the off-EVM contention tracker that turns Block-STM's
//! reexecution + write signals into a per-account multiplier on the
//! EIP-1559 base fee. The surcharge is **burned**, not collected — there is
//! no rent extraction, no validator capture. A hot account costs more to
//! write to because the network is paying for the wasted work of the
//! conflicting transactions, and TNZO supply contracts to match.
//!
//! # Inputs
//!
//! Every block, the executor calls [`HotStateMarket::record_block`] with a
//! per-account snapshot of `(reexecutions, writes)` aggregated from
//! `ParallelExecutionResult`. The market keeps a 64-block rolling window
//! per account.
//!
//! # Outputs
//!
//! [`HotStateMarket::contention`] returns a [`ContentionScore`] for any
//! address: the windowed reexecution rate, total writes in the window, and
//! whether the account currently exceeds the eligibility floor (≥0.20
//! score AND ≥50 writes).
//!
//! [`HotStateMarket::local_multiplier`] returns the 4-segment piecewise
//! multiplier (1.0× → 5.0×, capped). [`HotStateMarket::surcharge`] applies
//! it to a base fee for one account.
//!
//! For multi-write transactions, [`HotStateMarket::surcharge_multi`]
//! computes the **max** surcharge across written accounts — not the sum.
//! This matches Solana's local fee market construction: a tx touching one
//! hot and three cold accounts pays the hot rate, not the hot rate plus
//! three cold rates.
//!
//! # Bounds and constants
//!
//! - **Window size**: 64 blocks (~10 minutes at 10s blocks). Long enough to
//!   absorb single-block spikes, short enough to track real demand.
//! - **Score floor**: 0.20 reexecution rate. Below this, the multiplier is
//!   1.0× regardless of write volume.
//! - **Write floor**: 50 writes in the window. Below this, the account is
//!   not "hot" yet — sparse writers don't trigger surcharge even if their
//!   reexecution rate is briefly high.
//! - **Cap**: 5.0× the global base fee. Beyond this, the local market
//!   stops adjusting and the global EIP-1559 base fee absorbs the demand.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// Number of blocks in the rolling contention window.
pub const HOT_STATE_WINDOW_BLOCKS: usize = 64;

/// Minimum reexecution rate (`reexec / writes`) to qualify for surcharge.
pub const HOT_STATE_SCORE_FLOOR: f64 = 0.20;

/// Minimum writes in the window to qualify for surcharge. Sparse writers
/// don't get surcharged even if they're briefly at high reexec rate.
pub const HOT_STATE_WRITE_FLOOR: u64 = 50;

/// Maximum multiplier the local market can apply to the base fee.
pub const HOT_STATE_MAX_MULTIPLIER: f64 = 5.0;

/// Per-block, per-account contention sample.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct AccountSample {
    /// Number of times a transaction writing to this account was
    /// re-executed in this block due to a Block-STM conflict.
    pub reexecutions: u64,
    /// Number of writes (committed or rolled back) targeting this account
    /// in this block.
    pub writes: u64,
}

impl AccountSample {
    /// Combine this sample with another (per-block aggregation across txs).
    pub fn merge(&mut self, other: AccountSample) {
        self.reexecutions = self.reexecutions.saturating_add(other.reexecutions);
        self.writes = self.writes.saturating_add(other.writes);
    }
}

/// Public view of an account's contention level over the rolling window.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ContentionScore {
    /// `reexecutions / writes` over the window. NaN-free: zero writes
    /// reports 0.0, not NaN.
    pub score: f64,
    /// Total reexecutions in the window.
    pub reexecutions: u64,
    /// Total writes in the window.
    pub writes: u64,
    /// Whether the account currently exceeds both the score floor (0.20)
    /// and the write floor (50). Only when this is `true` does the local
    /// multiplier rise above 1.0×.
    pub is_hot: bool,
}

impl ContentionScore {
    /// The multiplier this contention score applies to the base fee.
    /// Implements the 4-segment piecewise curve described in the module
    /// docs. Always returns a value in `[1.0, 5.0]`.
    pub fn multiplier(&self) -> f64 {
        if !self.is_hot {
            return 1.0;
        }
        local_multiplier_for_score(self.score)
    }
}

/// 4-segment piecewise multiplier curve. Pure function so it can be unit-
/// tested independently of the rolling window.
///
/// - `s < 0.20` → 1.0×
/// - `0.20 ≤ s < 0.40` → linear 1.0× → 2.0×
/// - `0.40 ≤ s < 0.60` → linear 2.0× → 3.5×
/// - `s ≥ 0.60` → linear 3.5× → 5.0× (saturates at 5.0× when `s ≥ 1.0`)
pub fn local_multiplier_for_score(score: f64) -> f64 {
    if score < 0.20 {
        return 1.0;
    }
    if score < 0.40 {
        // Map [0.20, 0.40) → [1.0, 2.0)
        let t = (score - 0.20) / 0.20;
        return 1.0 + t * 1.0;
    }
    if score < 0.60 {
        // Map [0.40, 0.60) → [2.0, 3.5)
        let t = (score - 0.40) / 0.20;
        return 2.0 + t * 1.5;
    }
    // [0.60, ∞) → [3.5, 5.0], capped
    let t = ((score - 0.60) / 0.40).min(1.0);
    let m = 3.5 + t * 1.5;
    m.min(HOT_STATE_MAX_MULTIPLIER)
}

/// Hot-state local fee market. Maintains a rolling 64-block window of
/// per-account contention samples and computes per-address multipliers
/// over the EIP-1559 base fee.
///
/// Cheap to clone: all state lives behind an `Arc<RwLock<_>>`.
#[derive(Debug, Clone)]
pub struct HotStateMarket {
    inner: Arc<RwLock<HotStateInner>>,
}

#[derive(Debug)]
struct HotStateInner {
    /// One snapshot per block in the window. The newest block is at the
    /// back of the deque; the oldest at the front. Each snapshot is a
    /// `HashMap<address, AccountSample>`.
    window: VecDeque<HashMap<Vec<u8>, AccountSample>>,
    /// Window size cap.
    window_blocks: usize,
}

impl HotStateMarket {
    /// Create a new hot-state market with the default 64-block window.
    pub fn new() -> Self {
        Self::with_window(HOT_STATE_WINDOW_BLOCKS)
    }

    /// Create with a custom window size. Used by tests; production should
    /// stick to [`HOT_STATE_WINDOW_BLOCKS`].
    pub fn with_window(window_blocks: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HotStateInner {
                window: VecDeque::with_capacity(window_blocks),
                window_blocks,
            })),
        }
    }

    /// Record a block's per-account samples. The map is moved in; any
    /// account not present in the map for this block contributes a zero
    /// sample (it didn't write).
    pub fn record_block(&self, samples: HashMap<Vec<u8>, AccountSample>) {
        let mut inner = self.inner.write();
        if inner.window.len() == inner.window_blocks {
            inner.window.pop_front();
        }
        inner.window.push_back(samples);
    }

    /// Compute the rolling contention score for `address` over the current
    /// window. Returns a [`ContentionScore`] with `is_hot = false` if
    /// either floor is unmet.
    pub fn contention(&self, address: &[u8]) -> ContentionScore {
        let inner = self.inner.read();
        let mut reex = 0u64;
        let mut writes = 0u64;
        for block in inner.window.iter() {
            if let Some(sample) = block.get(address) {
                reex = reex.saturating_add(sample.reexecutions);
                writes = writes.saturating_add(sample.writes);
            }
        }
        let score = if writes == 0 {
            0.0
        } else {
            reex as f64 / writes as f64
        };
        let is_hot = score >= HOT_STATE_SCORE_FLOOR && writes >= HOT_STATE_WRITE_FLOOR;
        ContentionScore { score, reexecutions: reex, writes, is_hot }
    }

    /// Convenience: the [`local_multiplier_for_score`] applied to the
    /// account's current contention score, returning 1.0 when not hot.
    pub fn local_multiplier(&self, address: &[u8]) -> f64 {
        self.contention(address).multiplier()
    }

    /// Compute the surcharge over `base_fee` (per gas) for a single
    /// account. Returns `(effective_base_fee, surcharge_per_gas)` where
    /// `effective_base_fee = base_fee + surcharge`.
    ///
    /// The surcharge is the burn delta: callers should add it to the
    /// FeeMarket's burn counter, not route it to validators.
    pub fn surcharge(&self, address: &[u8], base_fee: u128) -> (u128, u128) {
        let mult = self.local_multiplier(address);
        if mult <= 1.0 {
            return (base_fee, 0);
        }
        // We work in integer math to avoid f64 rounding drift on large
        // base fees. Multiplier is at most 5.0× ⇒ scale by 10000 (4 decimal
        // digits of precision) and divide back.
        let scaled = (mult * 10_000.0).round() as u128;
        let effective = base_fee.saturating_mul(scaled) / 10_000;
        let surcharge = effective.saturating_sub(base_fee);
        (effective, surcharge)
    }

    /// Multi-write surcharge: returns the **max** surcharge across all
    /// addresses written by a single transaction, not the sum. Matches
    /// Solana's local-fee-market convention — a tx touching one hot and
    /// many cold accounts pays the hot rate exactly once.
    ///
    /// `addresses` may be empty; in that case the result is
    /// `(base_fee, 0)`.
    pub fn surcharge_multi(
        &self,
        addresses: &[&[u8]],
        base_fee: u128,
    ) -> (u128, u128) {
        let mut max_effective = base_fee;
        let mut max_surcharge: u128 = 0;
        for addr in addresses {
            let (eff, surch) = self.surcharge(addr, base_fee);
            if eff > max_effective {
                max_effective = eff;
                max_surcharge = surch;
            }
        }
        (max_effective, max_surcharge)
    }

    /// Number of blocks currently in the window. Useful for tests and
    /// metrics.
    pub fn window_len(&self) -> usize {
        self.inner.read().window.len()
    }

    /// Clear the window. Used after consensus reorgs that invalidate the
    /// recorded samples.
    pub fn reset(&self) {
        let mut inner = self.inner.write();
        inner.window.clear();
    }
}

impl Default for HotStateMarket {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn multiplier_curve_segments() {
        // Segment 1: below floor → 1.0×
        assert_eq!(local_multiplier_for_score(0.0), 1.0);
        assert_eq!(local_multiplier_for_score(0.19), 1.0);
        // Segment 2 boundary
        assert!((local_multiplier_for_score(0.20) - 1.0).abs() < 1e-9);
        assert!((local_multiplier_for_score(0.30) - 1.5).abs() < 1e-9);
        // Segment 3 boundary
        assert!((local_multiplier_for_score(0.40) - 2.0).abs() < 1e-9);
        assert!((local_multiplier_for_score(0.50) - 2.75).abs() < 1e-9);
        // Segment 4
        assert!((local_multiplier_for_score(0.60) - 3.5).abs() < 1e-9);
        // 0.60 + 0.40 * (1.5/0.40) hitting 5.0× exactly at score 1.0
        assert!((local_multiplier_for_score(1.00) - 5.0).abs() < 1e-9);
    }

    #[test]
    fn multiplier_capped_at_5x() {
        // Pathological scores never exceed the cap.
        assert!((local_multiplier_for_score(2.0) - 5.0).abs() < 1e-9);
        assert!((local_multiplier_for_score(100.0) - 5.0).abs() < 1e-9);
    }

    #[test]
    fn cold_account_not_hot() {
        let market = HotStateMarket::new();
        // Empty window: zero everything.
        let score = market.contention(&addr(0xAA));
        assert_eq!(score.writes, 0);
        assert_eq!(score.reexecutions, 0);
        assert_eq!(score.score, 0.0);
        assert!(!score.is_hot);
        assert_eq!(score.multiplier(), 1.0);
    }

    #[test]
    fn write_floor_blocks_surcharge() {
        // High score (50% reexec) but only 10 writes — under floor of 50.
        let market = HotStateMarket::new();
        let mut samples = HashMap::new();
        samples.insert(addr(0xAA), AccountSample { reexecutions: 5, writes: 10 });
        market.record_block(samples);

        let score = market.contention(&addr(0xAA));
        assert_eq!(score.writes, 10);
        assert!(score.score > HOT_STATE_SCORE_FLOOR);
        assert!(!score.is_hot, "writes < 50 must not promote to hot");
        assert_eq!(score.multiplier(), 1.0);
    }

    #[test]
    fn score_floor_blocks_surcharge() {
        // High write volume but low reexec rate (well under 0.20).
        let market = HotStateMarket::new();
        let mut samples = HashMap::new();
        samples.insert(addr(0xAA), AccountSample { reexecutions: 5, writes: 100 });
        market.record_block(samples);

        let score = market.contention(&addr(0xAA));
        assert_eq!(score.writes, 100);
        assert!(score.score < HOT_STATE_SCORE_FLOOR);
        assert!(!score.is_hot);
        assert_eq!(score.multiplier(), 1.0);
    }

    #[test]
    fn hot_account_gets_surcharge() {
        // 30% reexec rate, 100 writes — passes both floors.
        let market = HotStateMarket::new();
        let mut samples = HashMap::new();
        samples.insert(addr(0xAA), AccountSample { reexecutions: 30, writes: 100 });
        market.record_block(samples);

        let score = market.contention(&addr(0xAA));
        assert!(score.is_hot);
        // Score 0.30 should be in segment 2 (1.0× → 2.0×), at midpoint = 1.5×.
        let mult = score.multiplier();
        assert!((mult - 1.5).abs() < 1e-9, "expected 1.5×, got {mult}");

        // Surcharge: base_fee 1 Gwei × 1.5× = 1.5 Gwei, surcharge = 0.5 Gwei.
        let (effective, surcharge) = market.surcharge(&addr(0xAA), 1_000_000_000);
        assert_eq!(effective, 1_500_000_000);
        assert_eq!(surcharge, 500_000_000);
    }

    #[test]
    fn rolling_window_evicts_old_blocks() {
        // Use a small window for deterministic eviction.
        let market = HotStateMarket::with_window(3);

        // Block 1: hot
        let mut s1 = HashMap::new();
        s1.insert(addr(0xAA), AccountSample { reexecutions: 30, writes: 100 });
        market.record_block(s1);
        assert!(market.contention(&addr(0xAA)).is_hot);

        // Blocks 2 + 3: no activity for the account
        market.record_block(HashMap::new());
        market.record_block(HashMap::new());
        // Still in window of 3 — should still be hot.
        assert!(market.contention(&addr(0xAA)).is_hot);

        // Block 4: pushes block 1 out.
        market.record_block(HashMap::new());
        let score = market.contention(&addr(0xAA));
        assert_eq!(score.writes, 0);
        assert!(!score.is_hot);
    }

    #[test]
    fn multi_write_uses_max_not_sum() {
        // Two hot accounts and one cold one. The surcharge of the
        // tx must equal the max of the two hot surcharges, not the sum.
        let market = HotStateMarket::new();
        let mut s = HashMap::new();
        // Account A: score 0.30 → mult 1.5×
        s.insert(addr(0xAA), AccountSample { reexecutions: 30, writes: 100 });
        // Account B: score 0.50 → mult 2.75×
        s.insert(addr(0xBB), AccountSample { reexecutions: 50, writes: 100 });
        // Account C: cold
        s.insert(addr(0xCC), AccountSample { reexecutions: 0, writes: 100 });
        market.record_block(s);

        let base = 1_000_000_000u128;
        let a = addr(0xAA);
        let b = addr(0xBB);
        let c = addr(0xCC);
        let (eff, surch) =
            market.surcharge_multi(&[a.as_slice(), b.as_slice(), c.as_slice()], base);

        // B is the hottest at 2.75× → effective 2.75 Gwei, surcharge 1.75 Gwei.
        assert_eq!(eff, 2_750_000_000);
        assert_eq!(surch, 1_750_000_000);
    }

    #[test]
    fn empty_multi_write_no_surcharge() {
        let market = HotStateMarket::new();
        let (eff, surch) = market.surcharge_multi(&[], 1_000_000_000);
        assert_eq!(eff, 1_000_000_000);
        assert_eq!(surch, 0);
    }

    #[test]
    fn aggregates_across_window() {
        // Hot in 4 separate blocks: window-level totals must sum.
        let market = HotStateMarket::new();
        for _ in 0..4 {
            let mut s = HashMap::new();
            s.insert(addr(0xAA), AccountSample { reexecutions: 8, writes: 25 });
            market.record_block(s);
        }
        let score = market.contention(&addr(0xAA));
        assert_eq!(score.reexecutions, 32);
        assert_eq!(score.writes, 100);
        assert!((score.score - 0.32).abs() < 1e-9);
        assert!(score.is_hot);
    }

    #[test]
    fn reset_clears_window() {
        let market = HotStateMarket::new();
        let mut s = HashMap::new();
        s.insert(addr(0xAA), AccountSample { reexecutions: 30, writes: 100 });
        market.record_block(s);
        assert!(market.contention(&addr(0xAA)).is_hot);
        market.reset();
        assert!(!market.contention(&addr(0xAA)).is_hot);
        assert_eq!(market.window_len(), 0);
    }

    #[test]
    fn account_sample_merge() {
        let mut a = AccountSample { reexecutions: 1, writes: 5 };
        a.merge(AccountSample { reexecutions: 2, writes: 3 });
        assert_eq!(a.reexecutions, 3);
        assert_eq!(a.writes, 8);
    }
}
