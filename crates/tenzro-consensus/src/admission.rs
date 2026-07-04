//! Per-DID flow control & admission lanes (Agent-Swarm Spec 2).
//!
//! This module sits at the mempool ingress and enforces two complementary
//! mechanisms before a transaction is admitted to consensus:
//!
//! 1. **Three-lane assignment.** Every transaction is deterministically
//!    bucketed into `Verified`, `Delegated`, or `Open` based on the
//!    submitter's KYC tier, bonded stake, delegation chain, and (optional)
//!    posted bond. Lane assignment is a pure function of those inputs —
//!    nothing the submitter can opt into.
//!
//! 2. **Per-controller token buckets.** Each lane has its own refill rate
//!    and burst capacity. A submitter that exhausts its bucket is rejected
//!    with a typed `MempoolError::RateLimited` carrying a `retry_after_ms`
//!    hint so well-behaved clients can back off.
//!
//! Lane-aware fee floors compose with the EIP-1559 base fee: an Open-lane
//! transaction must clear `lane.floor_multiplier × base_fee`. The fee-floor
//! check itself lives in `tenzro-vm`; admission only resolves the lane and
//! exposes its multiplier.
//!
//! ## Crate boundary
//!
//! `tenzro-consensus` cannot depend on `tenzro-identity` or `tenzro-token`
//! (would cycle through `tenzro-node`). Lane resolution is therefore
//! abstracted behind the [`LaneResolver`] trait. The concrete implementation
//! that walks the `IdentityRegistry` and queries `StakingManager` lives in
//! `tenzro-node`.
//!
//! ## Per-validator scope
//!
//! Buckets are local to each validator. A submitter rejected by validator A
//! can retry against B; B independently applies its own bucket. Net
//! per-controller throughput is bounded by `N × spec'd_rate` where N is the
//! validator count — acceptable for testnet. Mainnet may need
//! gossip-coordinated buckets; out of scope for now.
//!
//! ## Restart semantics
//!
//! Buckets are **not persisted**. A node restart effectively resets every
//! controller to a full bucket. This is intentional — capacity bounds the
//! worst case, and validators restart independently so the network
//! observes only a brief rate spike, never a stuck-at-zero submitter.

use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tenzro_types::primitives::Address;
use tenzro_types::transaction::SignedTransaction;

/// Three admission lanes per the Agent-Swarm Spec 2 design.
///
/// Lane discriminants are stable u8 values (0=Verified, 1=Delegated,
/// 2=Open) so they can be used as array indices for hot-path stats
/// without a `match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lane {
    /// Controller has KYC tier ≥ Enhanced AND ≥ `min_verified_stake`
    /// bonded. Highest priority, no fee multiplier.
    Verified = 0,
    /// Delegated identity rooted in a Verified controller, transaction
    /// within the `DelegationScope`. Mid-priority, 1.5× fee floor.
    Delegated = 1,
    /// Default lane for everyone else (anonymous, faucet-funded,
    /// unverified, paused/quarantined controllers, out-of-scope
    /// delegations). Low priority, 4× fee floor.
    Open = 2,
}

impl Lane {
    /// Stable string label for metrics/logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Lane::Verified => "verified",
            Lane::Delegated => "delegated",
            Lane::Open => "open",
        }
    }

    /// All lanes in priority order (Verified → Delegated → Open). Useful
    /// for round-robin block-builder draws.
    pub fn all() -> [Lane; 3] {
        [Lane::Verified, Lane::Delegated, Lane::Open]
    }
}

/// Governance-tunable parameters. Genesis defaults match the Spec 2 doc.
///
/// All rates are per-controller. Burst capacities are absolute token
/// counts. `lane_weights` are block-builder draw ratios; weights of
/// `(8, 4, 1)` mean Verified gets 8 of every 13 slots, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionConfig {
    pub verified_refill_rate_per_sec: f64,
    pub verified_burst: u32,
    pub delegated_refill_rate_per_sec: f64,
    pub delegated_burst: u32,
    pub open_refill_rate_per_sec: f64,
    pub open_burst: u32,
    /// Minimum bonded stake (in smallest TNZO unit) for a controller to
    /// qualify for Verified lane.
    pub min_verified_stake: u128,
    /// Block-builder draw weights `(verified, delegated, open)`. Open's
    /// weight is always >= 1 to guarantee non-starvation.
    pub lane_weights: (u32, u32, u32),
    pub verified_floor_mult: f64,
    pub delegated_floor_mult: f64,
    pub open_floor_mult: f64,
    /// If `true`, an agent with a posted bond ≥ `bond_min_for_promotion`
    /// is promoted from Open to Delegated regardless of controller KYC
    /// (Agent-Swarm Spec 9 hook).
    pub bond_promotes_to_delegated: bool,
    pub bond_min_for_promotion: u128,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            verified_refill_rate_per_sec: 50.0,
            verified_burst: 500,
            delegated_refill_rate_per_sec: 10.0,
            delegated_burst: 100,
            open_refill_rate_per_sec: 1.0,
            open_burst: 20,
            min_verified_stake: 10_000u128 * 10u128.pow(18), // 10k TNZO
            lane_weights: (8, 4, 1),
            verified_floor_mult: 1.0,
            delegated_floor_mult: 1.5,
            open_floor_mult: 4.0,
            bond_promotes_to_delegated: true,
            bond_min_for_promotion: 1_000u128 * 10u128.pow(18), // 1k TNZO
        }
    }
}

impl AdmissionConfig {
    pub fn fee_floor_mult(&self, lane: Lane) -> f64 {
        match lane {
            Lane::Verified => self.verified_floor_mult,
            Lane::Delegated => self.delegated_floor_mult,
            Lane::Open => self.open_floor_mult,
        }
    }

    pub fn refill_rate(&self, lane: Lane) -> f64 {
        match lane {
            Lane::Verified => self.verified_refill_rate_per_sec,
            Lane::Delegated => self.delegated_refill_rate_per_sec,
            Lane::Open => self.open_refill_rate_per_sec,
        }
    }

    pub fn burst_capacity(&self, lane: Lane) -> u32 {
        match lane {
            Lane::Verified => self.verified_burst,
            Lane::Delegated => self.delegated_burst,
            Lane::Open => self.open_burst,
        }
    }

    /// Block-builder draw weight, clamped so Open never starves (≥1).
    pub fn weight(&self, lane: Lane) -> u32 {
        let (v, d, o) = self.lane_weights;
        match lane {
            Lane::Verified => v.max(1),
            Lane::Delegated => d.max(1),
            Lane::Open => o.max(1),
        }
    }
}

/// Pluggable lane resolver — abstract over identity/staking lookups so
/// `tenzro-consensus` doesn't need to depend on `tenzro-identity`.
///
/// The `tenzro-node` implementation reads from `IdentityRegistry` +
/// `StakingManager`. Tests can supply a deterministic fixture.
pub trait LaneResolver: Send + Sync {
    /// Resolve the lane assignment for a transaction. Implementations
    /// should be cheap (in-memory map lookups) — this runs on every
    /// admission attempt.
    ///
    /// Per Spec 2, the function is pure with respect to the supplied tx
    /// and current registry state: the same inputs always yield the same
    /// lane. Promotion/demotion happen automatically as the underlying
    /// identity state mutates.
    fn assign_lane(&self, tx: &SignedTransaction) -> Lane;

    /// Bucket key — the principal whose rate is being limited. For a
    /// signed tx with a registered controller this is the controller
    /// DID's wallet address; for anonymous Open-lane traffic this falls
    /// back to `tx.from`.
    fn bucket_key(&self, tx: &SignedTransaction) -> Address;
}

/// Default resolver: every transaction goes to Open lane, keyed by
/// `tx.from`. Used when the node has no identity registry wired (e.g.
/// early bootstrap, light client). The mempool degrades gracefully —
/// admission still applies Open-lane rate limits.
pub struct DefaultLaneResolver;

impl LaneResolver for DefaultLaneResolver {
    fn assign_lane(&self, _tx: &SignedTransaction) -> Lane {
        Lane::Open
    }

    fn bucket_key(&self, tx: &SignedTransaction) -> Address {
        tx.transaction.from
    }
}

/// Token bucket: capacity, current tokens, refill rate, lane.
///
/// Stored in a `Mutex` so the inner state can be mutated through a
/// shared `&self` reference from the admission hot path. The mutex is
/// uncontended in practice — at most one admission attempt per
/// controller is in-flight at a time on any given validator.
#[derive(Debug)]
struct Bucket {
    capacity: u32,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Instant,
    lane: Lane,
}

impl Bucket {
    fn new(lane: Lane, capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64, // start full
            refill_per_sec,
            last_refill: Instant::now(),
            lane,
        }
    }

    /// Refill, then attempt to consume one token. Returns `Ok(())` on
    /// admission, `Err(retry_after_ms)` on rejection.
    fn try_admit(&mut self) -> std::result::Result<(), u64> {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity as f64);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Time to accumulate enough for one token.
            let needed = 1.0 - self.tokens;
            let secs = needed / self.refill_per_sec.max(f64::MIN_POSITIVE);
            let ms = (secs * 1000.0).ceil().max(1.0) as u64;
            Err(ms)
        }
    }

    fn snapshot(&mut self) -> BucketSnapshot {
        // Refill first so the snapshot reflects the current logical state.
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity as f64);
        self.last_refill = now;
        BucketSnapshot {
            lane: self.lane,
            capacity: self.capacity,
            tokens: self.tokens,
            refill_per_sec: self.refill_per_sec,
        }
    }
}

/// A read-only view of a bucket's state, suitable for RPC responses
/// and metrics export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketSnapshot {
    pub lane: Lane,
    pub capacity: u32,
    pub tokens: f64,
    pub refill_per_sec: f64,
}

/// Cumulative admission counters per lane. All counters use saturating
/// adds so a long-running node cannot panic on overflow.
///
/// Rejection counters are split by *reason* so operators can distinguish
/// rate-limit pressure (controller bucket exhausted) from fee-floor
/// pressure (under-priced submissions) from capacity pressure (mempool
/// full and incoming tx not high-enough-priced to evict). All three
/// surface separately on `/metrics` as `tenzro_mempool_rejected_total{lane,reason}`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LaneStats {
    pub admitted: [u64; 3],
    pub rejected_rate_limited: [u64; 3],
    pub rejected_fee_floor: [u64; 3],
    pub rejected_mempool_full: [u64; 3],
    /// Active bucket count (resets across restarts).
    pub bucket_count: u64,
}

impl LaneStats {
    pub fn admitted(&self, lane: Lane) -> u64 { self.admitted[lane as usize] }
    pub fn rejected_rate_limited(&self, lane: Lane) -> u64 {
        self.rejected_rate_limited[lane as usize]
    }
    pub fn rejected_fee_floor(&self, lane: Lane) -> u64 {
        self.rejected_fee_floor[lane as usize]
    }
    pub fn rejected_mempool_full(&self, lane: Lane) -> u64 {
        self.rejected_mempool_full[lane as usize]
    }
}

/// Result of an admission attempt against the controller's bucket.
#[derive(Debug, Clone)]
pub enum AdmissionDecision {
    /// Tx may enter the mempool. The lane is reported so the caller can
    /// route it to the correct queue and apply the lane fee floor.
    Admit { lane: Lane },
    /// Tx is rejected for exceeding its bucket. `retry_after_ms` is a
    /// best-effort estimate of when the bucket will accumulate one
    /// token — not a guarantee.
    RateLimited {
        lane: Lane,
        retry_after_ms: u64,
        burst_remaining: u32,
        current_rate: f64,
    },
}

/// The admission controller. Owns the bucket map, lane resolver, and
/// stats. One per validator.
pub struct AdmissionController {
    config: AdmissionConfig,
    resolver: Arc<dyn LaneResolver>,
    /// `Address → (Mutex<Bucket>)` keyed on `LaneResolver::bucket_key`.
    /// `DashMap` gives us shard-level concurrency; the per-bucket mutex
    /// serializes only attempts against the same controller.
    buckets: Arc<DashMap<Address, Arc<Mutex<Bucket>>>>,
    /// Cumulative counters. Read by `tenzro_getMempoolStats`.
    stats: Arc<Mutex<LaneStats>>,
}

impl AdmissionController {
    pub fn new(config: AdmissionConfig, resolver: Arc<dyn LaneResolver>) -> Self {
        Self {
            config,
            resolver,
            buckets: Arc::new(DashMap::new()),
            stats: Arc::new(Mutex::new(LaneStats::default())),
        }
    }

    pub fn with_default_resolver(config: AdmissionConfig) -> Self {
        Self::new(config, Arc::new(DefaultLaneResolver))
    }

    /// Lane assignment without rate-limit consumption. Used for
    /// inspection RPCs and pre-flight fee-floor lookups.
    pub fn assign_lane(&self, tx: &SignedTransaction) -> Lane {
        self.resolver.assign_lane(tx)
    }

    /// Resolve the bucket key the controller would use for `tx`. For
    /// identified senders this walks the delegation chain to the
    /// controller wallet; for anonymous Open-lane traffic it returns
    /// `tx.from`. Used by `tenzro_getMempoolLane` so RPC responses can
    /// report *where* the bucket actually lives, not just where the
    /// caller was looking.
    pub fn bucket_key(&self, tx: &SignedTransaction) -> Address {
        self.resolver.bucket_key(tx)
    }

    pub fn fee_floor_mult(&self, lane: Lane) -> f64 {
        self.config.fee_floor_mult(lane)
    }

    pub fn config(&self) -> &AdmissionConfig {
        &self.config
    }

    /// The hot path: resolve lane, find or create the controller's
    /// bucket, attempt to consume one token, emit a stats event.
    pub fn try_admit(&self, tx: &SignedTransaction) -> AdmissionDecision {
        let lane = self.resolver.assign_lane(tx);
        let key = self.resolver.bucket_key(tx);

        let bucket = self.get_or_create_bucket(&key, lane);
        let mut guard = bucket.lock();

        // Lane may have changed since the bucket was created (controller
        // crossed a KYC threshold, slashing happened, etc). Reconcile so
        // the controller is always rate-limited at its current lane's
        // parameters. This makes promotion/demotion seamless without a
        // separate "rebucket" step. On any lane change we reset the token
        // count to the new lane's full burst capacity — promotion (e.g.
        // Open → Verified) gives the controller a fresh budget so an
        // exhausted Open lane doesn't penalize the now-verified caller,
        // and demotion clamps to the new (smaller) lane's capacity.
        if guard.lane != lane {
            guard.lane = lane;
            guard.capacity = self.config.burst_capacity(lane);
            guard.refill_per_sec = self.config.refill_rate(lane);
            guard.tokens = guard.capacity as f64;
        }

        let decision = match guard.try_admit() {
            Ok(()) => AdmissionDecision::Admit { lane },
            Err(retry_after_ms) => AdmissionDecision::RateLimited {
                lane,
                retry_after_ms,
                burst_remaining: guard.tokens.floor().max(0.0) as u32,
                current_rate: guard.refill_per_sec,
            },
        };

        // Update stats outside the bucket guard.
        drop(guard);
        let mut stats = self.stats.lock();
        match decision {
            AdmissionDecision::Admit { .. } => {
                stats.admitted[lane as usize] = stats.admitted[lane as usize].saturating_add(1);
            }
            AdmissionDecision::RateLimited { .. } => {
                stats.rejected_rate_limited[lane as usize] =
                    stats.rejected_rate_limited[lane as usize].saturating_add(1);
            }
        }
        stats.bucket_count = self.buckets.len() as u64;

        decision
    }

    /// Record a fee-floor rejection — the submitter's `gas_price` was
    /// below `mempool_min_gas_price × fee_floor_mult(lane)`. Surfaced as
    /// `tenzro_mempool_rejected_total{lane, reason="fee_floor"}` and on
    /// `tenzro_getMempoolStats` so operators can spot under-priced spam.
    pub fn record_rejected_fee_floor(&self, lane: Lane) {
        let mut stats = self.stats.lock();
        stats.rejected_fee_floor[lane as usize] =
            stats.rejected_fee_floor[lane as usize].saturating_add(1);
    }

    /// Record a mempool-capacity rejection — count or size limit hit and
    /// the new tx wasn't high-enough-priced to evict an existing one.
    /// Surfaced as `tenzro_mempool_rejected_total{lane, reason="mempool_full"}`.
    pub fn record_rejected_mempool_full(&self, lane: Lane) {
        let mut stats = self.stats.lock();
        stats.rejected_mempool_full[lane as usize] =
            stats.rejected_mempool_full[lane as usize].saturating_add(1);
    }

    /// Snapshot the bucket for `key` (or `None` if it has never been
    /// touched). Used by `tenzro_getMempoolLane` for RPC-driven
    /// inspection. Refills before returning so callers see the current
    /// effective token count.
    pub fn bucket_snapshot(&self, key: &Address) -> Option<BucketSnapshot> {
        self.buckets.get(key).map(|b| b.lock().snapshot())
    }

    /// Lifetime stats snapshot.
    pub fn stats(&self) -> LaneStats {
        self.stats.lock().clone()
    }

    fn get_or_create_bucket(&self, key: &Address, lane: Lane) -> Arc<Mutex<Bucket>> {
        if let Some(existing) = self.buckets.get(key) {
            return existing.clone();
        }
        let bucket = Arc::new(Mutex::new(Bucket::new(
            lane,
            self.config.burst_capacity(lane),
            self.config.refill_rate(lane),
        )));
        // `entry().or_insert_with` to handle the racy case where two
        // threads admit the same controller simultaneously.
        self.buckets
            .entry(*key)
            .or_insert_with(|| bucket)
            .clone()
    }

    /// Drop buckets that have been idle for at least `idle_for`. Call
    /// periodically from the node tick to bound memory under
    /// pathological signer churn (e.g. an attacker rotating addresses).
    /// O(N) over the bucket count; acceptable at testnet scale.
    pub fn prune_idle(&self, idle_for: Duration) {
        let cutoff = Instant::now() - idle_for;
        self.buckets.retain(|_addr, bucket| {
            let g = bucket.lock();
            g.last_refill > cutoff
        });
    }

    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_types::primitives::{Address, ChainId, Nonce, Signature, Timestamp};
    use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};

    fn dummy_tx(from_byte: u8) -> SignedTransaction {
        let mut from = [0u8; 32];
        from[0] = from_byte;
        let pq = MlDsaSigningKey::generate();
        let tx = Transaction {
            chain_id: ChainId::from(1337u64),
            from: Address::new(from),
            to: Address::new([0u8; 32]),
            nonce: Nonce::from(0u64),
            tx_type: TransactionType::Transfer { amount: 0 },
            gas_limit: 21000,
            gas_price: 1_000_000_000,
            timestamp: Timestamp::now(),
            memo: None,
            pq_public_key: pq.verifying_key_bytes().to_vec(),
        };
        SignedTransaction::new(tx, Signature::new(vec![0u8; 64], vec![0u8; 32]), vec![0u8; 3309])
    }

    #[test]
    fn open_lane_burst_then_throttle() {
        let cfg = AdmissionConfig {
            open_burst: 3,
            open_refill_rate_per_sec: 0.1, // very slow refill
            ..AdmissionConfig::default()
        };
        let ctrl = AdmissionController::with_default_resolver(cfg);
        let tx = dummy_tx(1);

        // First three admit (burst).
        for _ in 0..3 {
            assert!(matches!(ctrl.try_admit(&tx), AdmissionDecision::Admit { lane: Lane::Open }));
        }
        // Fourth should be rate-limited.
        match ctrl.try_admit(&tx) {
            AdmissionDecision::RateLimited { lane, retry_after_ms, .. } => {
                assert_eq!(lane, Lane::Open);
                assert!(retry_after_ms > 0);
            }
            other => panic!("expected RateLimited, got {:?}", other),
        }

        let stats = ctrl.stats();
        assert_eq!(stats.admitted(Lane::Open), 3);
        assert_eq!(stats.rejected_rate_limited(Lane::Open), 1);
    }

    #[test]
    fn separate_addresses_have_independent_buckets() {
        let cfg = AdmissionConfig {
            open_burst: 1,
            open_refill_rate_per_sec: 0.0001,
            ..AdmissionConfig::default()
        };
        let ctrl = AdmissionController::with_default_resolver(cfg);

        let tx_a = dummy_tx(1);
        let tx_b = dummy_tx(2);

        assert!(matches!(ctrl.try_admit(&tx_a), AdmissionDecision::Admit { .. }));
        // A's bucket is now empty.
        assert!(matches!(ctrl.try_admit(&tx_a), AdmissionDecision::RateLimited { .. }));
        // B has its own full bucket.
        assert!(matches!(ctrl.try_admit(&tx_b), AdmissionDecision::Admit { .. }));
    }

    #[test]
    fn lane_change_resizes_bucket() {
        struct PromotingResolver {
            calls: std::sync::atomic::AtomicU64,
        }
        impl LaneResolver for PromotingResolver {
            fn assign_lane(&self, _tx: &SignedTransaction) -> Lane {
                let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n < 2 { Lane::Open } else { Lane::Verified }
            }
            fn bucket_key(&self, tx: &SignedTransaction) -> Address {
                tx.transaction.from
            }
        }
        let resolver = Arc::new(PromotingResolver {
            calls: std::sync::atomic::AtomicU64::new(0),
        });
        let cfg = AdmissionConfig {
            open_burst: 1,
            open_refill_rate_per_sec: 0.0001,
            verified_burst: 1000,
            verified_refill_rate_per_sec: 1000.0,
            ..AdmissionConfig::default()
        };
        let ctrl = AdmissionController::new(cfg, resolver);
        let tx = dummy_tx(1);

        // First admit: Open lane, burst=1.
        assert!(matches!(ctrl.try_admit(&tx), AdmissionDecision::Admit { lane: Lane::Open }));
        // Second: Open exhausted.
        assert!(matches!(ctrl.try_admit(&tx), AdmissionDecision::RateLimited { lane: Lane::Open, .. }));
        // Third: resolver flips to Verified — bucket should resize and
        // accept immediately since the verified bucket has fresh capacity.
        match ctrl.try_admit(&tx) {
            AdmissionDecision::Admit { lane } => assert_eq!(lane, Lane::Verified),
            other => panic!("expected Verified admit, got {:?}", other),
        }
    }

    #[test]
    fn weights_clamp_open_to_at_least_one() {
        let cfg = AdmissionConfig {
            lane_weights: (10, 5, 0), // attempt to starve Open
            ..AdmissionConfig::default()
        };
        assert_eq!(cfg.weight(Lane::Open), 1, "Open weight must be clamped to >= 1");
    }
}
