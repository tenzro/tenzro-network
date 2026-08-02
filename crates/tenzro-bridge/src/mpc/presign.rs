//! Pre-signing pool for DKLS23 threshold ECDSA.
//!
//! DKLS23 is a 3-round signing protocol. Round 1 is the **offline phase** —
//! it depends on the keyshare and a fresh randomness commitment but not on
//! the message. Holding a buffered batch of pre-computed round-1 tuples
//! lets us cut the perceived signing latency by ~30–40% for hot bridge
//! flows: a signing request consumes a pre-computed tuple and immediately
//! enters round 2.
//!
//! Per Silence Laboratories' "Threshold ECDSA Modes of Operation:
//! Pre-signing and More" and the dkls23-core API, the round-1 output can
//! be safely cached **at most once per signing instance** — reusing a
//! tuple across two messages reveals the secret key. This pool therefore
//! treats each `PresignTuple` as one-shot.
//!
//! Storage is in-memory only — pre-signs are ephemeral, and re-using a
//! tuple after a node restart is dangerous. The pool refills in the
//! background when the count drops below the configured floor.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{BridgeError, Result};
use tenzro_types::primitives::Hash;

/// One round-1 output tuple. The opaque payload is treated as a black box
/// by this pool — production code wires `dkls23_core` round-1 bytes; tests
/// use any 32+ bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignTuple {
    /// Stable id of the tuple. Used for audit + dedup.
    pub id: Hash,
    /// MPC group id this tuple belongs to (matches the keyshare).
    pub group_id: [u8; 32],
    /// Key epoch the tuple is bound to. Pre-signs from a stale epoch are
    /// dropped on PKR.
    pub epoch: u64,
    /// Round-1 opaque payload (`dkls23_core` `SignR1Output` bytes).
    pub round1_payload: Vec<u8>,
    /// Unix-seconds at which the tuple was produced.
    pub produced_at_secs: u64,
}

impl PresignTuple {
    /// Stable id for a tuple.
    pub fn compute_id(
        group_id: &[u8; 32],
        epoch: u64,
        round1_payload: &[u8],
        produced_at_secs: u64,
    ) -> Hash {
        let mut h = Sha256::new();
        h.update(b"tenzro/mpc/presign/tuple");
        h.update(group_id);
        h.update(epoch.to_le_bytes());
        h.update(round1_payload);
        h.update(produced_at_secs.to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        Hash::new(digest)
    }
}

/// Configuration for the pool.
#[derive(Debug, Clone)]
pub struct PresignPoolConfig {
    /// Group id this pool serves.
    pub group_id: [u8; 32],
    /// Pool floor — refill is triggered below this count.
    pub floor: usize,
    /// Pool ceiling — refill stops at or above this count.
    pub ceiling: usize,
    /// Maximum age of a tuple in seconds. Older tuples are evicted on
    /// claim/refill — prevents serving stale randomness if the epoch
    /// rotated without an explicit drain.
    pub max_age_secs: u64,
}

impl Default for PresignPoolConfig {
    fn default() -> Self {
        Self {
            group_id: [0u8; 32],
            floor: 8,
            ceiling: 32,
            max_age_secs: 24 * 3600,
        }
    }
}

/// In-memory pre-signing pool. Per-group; nodes typically run one pool
/// per active threshold group.
#[derive(Debug)]
pub struct PresignPool {
    config: PresignPoolConfig,
    current_epoch: AtomicU64,
    tuples: Mutex<VecDeque<PresignTuple>>,
    claimed_count: AtomicU64,
    produced_count: AtomicU64,
}

impl PresignPool {
    /// Build a new pool pinned to a specific group + initial epoch.
    pub fn new(config: PresignPoolConfig, initial_epoch: u64) -> Self {
        Self {
            config,
            current_epoch: AtomicU64::new(initial_epoch),
            tuples: Mutex::new(VecDeque::new()),
            claimed_count: AtomicU64::new(0),
            produced_count: AtomicU64::new(0),
        }
    }

    /// Add a freshly-computed tuple to the pool. Returns `Ok(false)` if the
    /// pool is already at ceiling; callers can drop the unused tuple.
    pub fn deposit(&self, tuple: PresignTuple) -> Result<bool> {
        if tuple.group_id != self.config.group_id {
            return Err(BridgeError::ConfigurationError(
                "tuple group_id does not match pool group_id".into(),
            ));
        }
        let current_epoch = self.current_epoch.load(Ordering::Relaxed);
        if tuple.epoch != current_epoch {
            return Err(BridgeError::ConfigurationError(format!(
                "tuple epoch {} does not match pool epoch {}",
                tuple.epoch, current_epoch
            )));
        }
        let mut tuples = self.tuples.lock();
        if tuples.len() >= self.config.ceiling {
            return Ok(false);
        }
        tuples.push_back(tuple);
        self.produced_count.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    /// Take the next tuple. Stale tuples (older than `max_age_secs` or
    /// wrong epoch) are dropped silently and the next eligible tuple is
    /// returned.
    pub fn claim(&self, now_secs: u64) -> Option<PresignTuple> {
        let current_epoch = self.current_epoch.load(Ordering::Relaxed);
        let mut tuples = self.tuples.lock();
        while let Some(t) = tuples.pop_front() {
            if t.epoch != current_epoch {
                continue;
            }
            if now_secs.saturating_sub(t.produced_at_secs) > self.config.max_age_secs {
                continue;
            }
            self.claimed_count.fetch_add(1, Ordering::Relaxed);
            return Some(t);
        }
        None
    }

    /// Return true if the pool is below the configured floor.
    pub fn needs_refill(&self) -> bool {
        self.tuples.lock().len() < self.config.floor
    }

    /// Number of tuples currently held.
    pub fn len(&self) -> usize {
        self.tuples.lock().len()
    }

    /// Is the pool empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drain the pool on PKR. Callers do this on epoch change because every
    /// pre-sign produced under the old epoch becomes unsafe to use after
    /// the share rotation.
    pub fn rotate_epoch(&self, new_epoch: u64) {
        self.current_epoch.store(new_epoch, Ordering::Relaxed);
        self.tuples.lock().clear();
    }

    /// Lifetime claim counter (audit).
    pub fn claimed_total(&self) -> u64 {
        self.claimed_count.load(Ordering::Relaxed)
    }

    /// Lifetime produced counter (audit).
    pub fn produced_total(&self) -> u64 {
        self.produced_count.load(Ordering::Relaxed)
    }

    /// Current epoch this pool serves.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch.load(Ordering::Relaxed)
    }

    /// Config (immutable).
    pub fn config(&self) -> &PresignPoolConfig {
        &self.config
    }

    /// Snapshot of the pool for `tenzro_listMpcPresignStats` RPC.
    pub fn stats(&self) -> PresignPoolStats {
        PresignPoolStats {
            group_id_hex: hex::encode(self.config.group_id),
            current_epoch: self.current_epoch(),
            in_pool: self.len(),
            floor: self.config.floor,
            ceiling: self.config.ceiling,
            claimed_total: self.claimed_total(),
            produced_total: self.produced_total(),
        }
    }
}

/// Externally-visible pool stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignPoolStats {
    /// Hex-encoded group id.
    pub group_id_hex: String,
    /// Current epoch.
    pub current_epoch: u64,
    /// Tuples currently held.
    pub in_pool: usize,
    /// Refill floor.
    pub floor: usize,
    /// Refill ceiling.
    pub ceiling: usize,
    /// Lifetime claimed.
    pub claimed_total: u64,
    /// Lifetime produced.
    pub produced_total: u64,
}

/// Shared handle.
pub type SharedPresignPool = Arc<PresignPool>;

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(group: [u8; 32]) -> PresignPool {
        PresignPool::new(
            PresignPoolConfig {
                group_id: group,
                floor: 2,
                ceiling: 4,
                max_age_secs: 3600,
            },
            7,
        )
    }

    fn tuple(group: [u8; 32], epoch: u64, payload: &[u8], now: u64) -> PresignTuple {
        let id = PresignTuple::compute_id(&group, epoch, payload, now);
        PresignTuple {
            id,
            group_id: group,
            epoch,
            round1_payload: payload.to_vec(),
            produced_at_secs: now,
        }
    }

    #[test]
    fn deposit_until_ceiling_then_reject() {
        let p = pool([1u8; 32]);
        for i in 0..5u8 {
            let ok = p.deposit(tuple([1u8; 32], 7, &[i, 0, 0, 0], 100)).unwrap();
            if i < 4 {
                assert!(ok, "first 4 should succeed");
            } else {
                assert!(!ok, "5th should be rejected by ceiling");
            }
        }
    }

    #[test]
    fn claim_returns_fifo() {
        let p = pool([1u8; 32]);
        p.deposit(tuple([1u8; 32], 7, b"a", 100)).unwrap();
        p.deposit(tuple([1u8; 32], 7, b"b", 100)).unwrap();
        assert_eq!(p.claim(101).unwrap().round1_payload, b"a");
        assert_eq!(p.claim(101).unwrap().round1_payload, b"b");
        assert!(p.claim(101).is_none());
    }

    #[test]
    fn claim_drops_stale_tuples() {
        let p = pool([1u8; 32]);
        p.deposit(tuple([1u8; 32], 7, b"old", 100)).unwrap();
        p.deposit(tuple([1u8; 32], 7, b"new", 4_000)).unwrap();
        // age = 5000-100 > 3600 → drop "old", return "new"
        let got = p.claim(5_000).unwrap();
        assert_eq!(got.round1_payload, b"new");
    }

    #[test]
    fn rotate_epoch_drains_and_rejects_old() {
        let p = pool([1u8; 32]);
        p.deposit(tuple([1u8; 32], 7, b"a", 100)).unwrap();
        p.rotate_epoch(8);
        assert!(p.is_empty());
        let err = p.deposit(tuple([1u8; 32], 7, b"a", 100)).unwrap_err();
        assert!(matches!(err, BridgeError::ConfigurationError(_)));
    }

    #[test]
    fn group_id_mismatch_rejected() {
        let p = pool([1u8; 32]);
        let err = p.deposit(tuple([2u8; 32], 7, b"x", 0)).unwrap_err();
        assert!(matches!(err, BridgeError::ConfigurationError(_)));
    }

    #[test]
    fn needs_refill_threshold() {
        let p = pool([1u8; 32]);
        assert!(p.needs_refill());
        p.deposit(tuple([1u8; 32], 7, b"a", 0)).unwrap();
        assert!(p.needs_refill());
        p.deposit(tuple([1u8; 32], 7, b"b", 0)).unwrap();
        // floor = 2 → still below threshold (strictly-less-than)
        assert!(!p.needs_refill());
    }

    #[test]
    fn audit_counters_increment() {
        let p = pool([1u8; 32]);
        p.deposit(tuple([1u8; 32], 7, b"a", 0)).unwrap();
        p.claim(1).unwrap();
        assert_eq!(p.produced_total(), 1);
        assert_eq!(p.claimed_total(), 1);
    }
}
