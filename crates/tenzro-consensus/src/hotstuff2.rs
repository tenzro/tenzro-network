//! HotStuff-2 BFT consensus implementation
//!
//! HotStuff-2 is a two-phase BFT consensus protocol with:
//! - O(n) linear communication complexity per view
//! - Two phases: PREPARE and COMMIT (simplified from original HotStuff)
//! - Optimistic responsiveness
//! - Leader rotation for liveness
//!
//! Protocol flow:
//! 1. PREPARE: Leader proposes block, validators vote
//! 2. COMMIT: Leader collects prepare QC, validators vote again
//! 3. DECIDE: Leader collects commit QC, block is finalized

use crate::config::{ConsensusConfig, ProposerElectionKind};
use crate::epoch_manager::EpochManager;
use crate::error::{ConsensusError, Result};
use crate::finality::{FinalityNotification, FinalityTracker, ForkChoice};
use crate::leader_reputation::LeaderReputation;
use crate::mempool::Mempool;
use crate::proposer::BlockProposer;
use crate::traits::{ConsensusEngine, SlashingCallback};
use crate::validator::{ProposerElection, ReputationProposer, RoundRobinProposer, ValidatorSet};
use crate::vote_state::{
    LastSignState, MemoryVoteStateStore, VoteStateStore, VoteStep, VrsDecision,
};
use crate::voter::{QuorumCertificate, Vote, VoteCollector, VoteType};
use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tenzro_crypto::KeyPair;
use tenzro_crypto::bls::BlsKeyPair;
use tenzro_crypto::composite::{
    CompositePublicKey, CompositeSignature, HybridSigner, HybridVerifier, InMemoryHybridSigner,
    StandardHybridVerifier,
};
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::signatures::Ed25519SignerImpl;
use tenzro_types::block::Block;
use tenzro_types::primitives::{Address, BlockHeight, Hash};
use tenzro_types::transaction::{SignedTransaction, Transaction};
use tokio::sync::broadcast;
use tokio::time::sleep;

/// Cap on the exponent applied to [`ViewChangeTimer::on_timeout`]. With
/// `backoff_multiplier = 2.0` and `base_timeout = 1000ms`, a cap of 3 yields
/// the schedule `1s → 2s → 4s → 8s` (saturated). Short cap matches
/// production BFT tuning — long view timeouts on a
/// multi-region fleet cause a pacemaker race where the proposer's block
/// reaches nearby peers in time but distant peers (cross-Pacific RTT
/// ~180ms) have already timed out and broadcast `TimeoutMsg`. The
/// `max_timeout` constant in `HotStuff2Engine::new` provides an absolute
/// 8-second ceiling on top of this exponent cap.
const MAX_BACKOFF_EXPONENT: u32 = 3;

/// Upper bound on failed rounds derived from a single committed view gap.
///
/// After a long stall the view gap between a block and its parent can be
/// large; deriving a failure for every view would be O(gap) work for data
/// that mostly falls outside the reputation window anyway. The cap keeps
/// derivation bounded while staying deterministic — it is computed purely
/// from committed metadata, so every node truncates identically.
const MAX_DERIVED_GAP_FAILURES: u64 = 128;

/// Trait for providing the current state root to the block proposer.
///
/// This provides clean dependency inversion: consensus calls this trait
/// to get the state root without knowing about VM or storage internals.
pub trait StateRootProvider: Send + Sync {
    /// Returns the current state root hash.
    fn current_state_root(&self) -> Hash;
}

/// Trait for fetching a finalized block by height.
///
/// Required for EIP-1559 base-fee derivation: the leader must read the
/// parent block's metadata (`base_fee_per_gas`, `gas_used`, `gas_limit`)
/// when proposing the next block, and validators must read the same
/// parent when re-deriving the expected base fee. After a node restart
/// `FinalityTracker::finalized_blocks` may be empty for old heights, so
/// the implementation falls back to RocksDB via `BlockStorage`.
pub trait BlockProvider: Send + Sync {
    /// Returns the finalized block at the given height, or `None` if
    /// missing. Implementations should consult the in-memory finality
    /// tracker first and fall back to durable storage.
    fn get_block(&self, height: BlockHeight) -> Option<Block>;
}

/// The current phase of the HotStuff-2 protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Preparing a new block
    Prepare,
    /// Committing a prepared block
    Commit,
    /// Deciding (finalizing) a committed block
    Decide,
}

/// View state for HotStuff-2
#[derive(Debug, Clone)]
struct ViewState {
    /// Current view number
    view: u64,

    /// Current phase
    phase: Phase,

    /// Current block height
    height: BlockHeight,

    /// Proposed block for this view (if any)
    proposed_block: Option<Block>,

    /// Prepare QC for current block
    prepare_qc: Option<QuorumCertificate>,

    /// Commit QC for current block
    commit_qc: Option<QuorumCertificate>,

    /// Timestamp when this view started
    view_start_time: Instant,
}

/// Streaming quantile estimator using the P² algorithm (Jain & Chlamtac,
/// "The P² Algorithm for Dynamic Calculation of Quantiles and Histograms
/// Without Storing Observations", CACM 1985).
///
/// The view timer needs the *tail* of quorum-formation latency, not its
/// mean — per the tail-at-scale insight (Dean & Barroso, "The Tail at
/// Scale", CACM 2013), the mean systematically under-provisions the
/// timeout for slow rounds, so a mean-derived timeout trips spurious
/// view changes whenever a round lands in the tail. P² tracks a chosen
/// quantile (e.g. p99) in O(1) memory and O(1) per-observation work by
/// maintaining five markers and adjusting them with a piecewise-parabolic
/// interpolation as each observation arrives. No stored history, no
/// windowing — it converges to the true quantile of the running stream.
#[derive(Debug, Clone)]
struct P2Quantile {
    /// Target quantile in `(0, 1)`, e.g. `0.99` for p99.
    p: f64,
    /// Observation count. The estimator warms up on the first five.
    count: usize,
    /// The five initial observations, kept sorted, used to seed markers.
    init: Vec<f64>,
    /// Marker heights (the estimated values at each marker position).
    q: [f64; 5],
    /// Marker positions (1-indexed integer counts of observations).
    n: [f64; 5],
    /// Desired marker positions (fractional).
    np: [f64; 5],
    /// Increments to the desired positions per observation.
    dn: [f64; 5],
}

impl P2Quantile {
    fn new(p: f64) -> Self {
        Self {
            p,
            count: 0,
            init: Vec::with_capacity(5),
            q: [0.0; 5],
            n: [0.0; 5],
            np: [0.0; 5],
            dn: [0.0; 5],
        }
    }

    /// Records one observation and updates the running quantile estimate.
    fn observe(&mut self, x: f64) {
        if self.count < 5 {
            self.init.push(x);
            self.count += 1;
            if self.count == 5 {
                self.init
                    .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                for i in 0..5 {
                    self.q[i] = self.init[i];
                    self.n[i] = (i + 1) as f64;
                }
                self.np = [
                    1.0,
                    1.0 + 2.0 * self.p,
                    1.0 + 4.0 * self.p,
                    3.0 + 2.0 * self.p,
                    5.0,
                ];
                self.dn = [0.0, self.p / 2.0, self.p, (1.0 + self.p) / 2.0, 1.0];
            }
            return;
        }

        self.count += 1;

        // Locate the cell k such that q[k] <= x < q[k+1], clamping the ends.
        let k = if x < self.q[0] {
            self.q[0] = x;
            0
        } else if x >= self.q[4] {
            self.q[4] = x;
            3
        } else {
            let mut cell = 0;
            for i in 0..4 {
                if self.q[i] <= x && x < self.q[i + 1] {
                    cell = i;
                    break;
                }
            }
            cell
        };

        for i in (k + 1)..5 {
            self.n[i] += 1.0;
        }
        for i in 0..5 {
            self.np[i] += self.dn[i];
        }

        // Adjust the three interior markers.
        for i in 1..4 {
            let d = self.np[i] - self.n[i];
            let can_up = d >= 1.0 && (self.n[i + 1] - self.n[i]) > 1.0;
            let can_down = d <= -1.0 && (self.n[i - 1] - self.n[i]) < -1.0;
            if can_up || can_down {
                let dsign = if d >= 0.0 { 1.0 } else { -1.0 };
                let parabolic = self.parabolic(i, dsign);
                if self.q[i - 1] < parabolic && parabolic < self.q[i + 1] {
                    self.q[i] = parabolic;
                } else {
                    self.q[i] = self.linear(i, dsign);
                }
                self.n[i] += dsign;
            }
        }
    }

    fn parabolic(&self, i: usize, d: f64) -> f64 {
        let a = d / (self.n[i + 1] - self.n[i - 1]);
        let b = (self.n[i] - self.n[i - 1] + d) * (self.q[i + 1] - self.q[i])
            / (self.n[i + 1] - self.n[i])
            + (self.n[i + 1] - self.n[i] - d) * (self.q[i] - self.q[i - 1])
                / (self.n[i] - self.n[i - 1]);
        self.q[i] + a * b
    }

    fn linear(&self, i: usize, d: f64) -> f64 {
        let j = if d >= 0.0 { i + 1 } else { i - 1 };
        self.q[i] + d * (self.q[j] - self.q[i]) / (self.n[j] - self.n[i])
    }

    /// Current quantile estimate, or `None` before warm-up completes
    /// (fewer than five observations).
    fn estimate(&self) -> Option<f64> {
        if self.count < 5 {
            // During warm-up, the best available estimate is the max seen —
            // conservative for a tail quantile (never under-estimates).
            self.init.iter().copied().fold(None, |acc: Option<f64>, v| {
                Some(acc.map_or(v, |a| a.max(v)))
            })
        } else {
            Some(self.q[2])
        }
    }
}

/// Manages view change timeouts with exponential backoff AND adaptive
/// base-timeout tuning.
///
/// The base timeout self-tunes to the cluster's observed
/// quorum-formation latency rather than relying on a hard-coded
/// default. This is what makes consensus work across an open,
/// permissionless validator set with arbitrary cross-region
/// topology — a validator in Frankfurt joining a fleet whose other
/// members are in Tokyo and São Paulo cannot share a fixed default
/// with a single-datacenter testnet.
///
/// **Algorithm**: every successful view (Commit QC observed) records
/// the wall-clock time it took from view-start to QC-formation. Two
/// statistics track the stream: an EWMA of the mean and a P² estimate
/// of the p99 tail. The base timeout is set to
/// `max(safety_multiplier × ewma, p99_tail)`, clamped to
/// `[base_floor, base_ceiling]`. Taking the max of a mean-multiple and
/// a measured tail means the timeout tracks the actual slow-round
/// latency rather than approximating it with a static floor — the
/// tail-at-scale correction. The mean-multiple still dominates when the
/// distribution is tight; the measured p99 takes over when the tail is
/// heavy (cross-region, congested links).
///
/// **Convergence**: when the cluster composition shifts (validator
/// joins or leaves, region distribution changes), the EWMA tracks the
/// new steady-state within `~5/alpha` views. With `alpha=0.15` that's
/// ~33 views. During the transient, exponential backoff (which is
/// PRESERVED unchanged) absorbs spikes.
///
/// **Safety floor + ceiling**: `base_floor` (default 1000ms, set from
/// `ConsensusConfig::adaptive_timeout_floor_ms`) is now a pure lower
/// clamp against tight loops — the measured p99 does the job the floor
/// used to approximate. `base_ceiling=10000ms` prevents runaway when an
/// outlier delay would otherwise push the estimate into the seconds range.
#[derive(Debug, Clone)]
struct ViewChangeTimer {
    /// Adaptive base timeout, retuned after every successful view.
    base_timeout: Duration,

    /// Current timeout duration (with backoff)
    current_timeout: Duration,

    /// Maximum timeout duration
    max_timeout: Duration,

    /// Backoff multiplier (default: 2.0)
    backoff_multiplier: f64,

    /// Number of consecutive timeouts
    consecutive_timeouts: u32,

    /// EWMA of observed view-to-QC formation latency, in milliseconds.
    /// `None` until the first successful view completes.
    observed_latency_ewma_ms: Option<f64>,

    /// P² streaming estimate of the p99 tail of view-to-QC latency, in
    /// milliseconds. Provides the measured tail the base timeout must
    /// clear so a slow round doesn't trip a spurious view change.
    p99_latency: P2Quantile,

    /// Smoothing factor for the EWMA. 0.15 = ~6-7 view memory.
    ewma_alpha: f64,

    /// Safety-multiplier applied to EWMA to derive base_timeout.
    /// 2.0 = "wait 2× the observed mean before assuming view stalled".
    safety_multiplier: f64,

    /// Floor on the adaptive base timeout. Prevents tight loops.
    base_floor: Duration,

    /// Ceiling on the adaptive base timeout. Prevents runaway.
    base_ceiling: Duration,
}

impl ViewState {
    fn new(view: u64, height: BlockHeight) -> Self {
        Self {
            view,
            phase: Phase::Prepare,
            height,
            proposed_block: None,
            prepare_qc: None,
            commit_qc: None,
            view_start_time: Instant::now(),
        }
    }

    fn reset_timer(&mut self) {
        self.view_start_time = Instant::now();
    }

    fn time_in_view(&self) -> Duration {
        Instant::now().duration_since(self.view_start_time)
    }
}

impl ViewChangeTimer {
    /// Constructs the timer with an explicit adaptive base-timeout floor.
    /// The floor must exceed the *tail* of observed quorum latency (not its
    /// median) on the target topology, or successful-round EWMA tuning will
    /// drive the timeout below the slow rounds and cause spurious view
    /// changes. See `ConsensusConfig::adaptive_timeout_floor_ms`.
    fn with_floor(base_timeout: Duration, max_timeout: Duration, base_floor: Duration) -> Self {
        Self {
            base_timeout: base_timeout.max(base_floor),
            current_timeout: base_timeout.max(base_floor),
            max_timeout,
            backoff_multiplier: 2.0,
            consecutive_timeouts: 0,
            observed_latency_ewma_ms: None,
            p99_latency: P2Quantile::new(0.99),
            ewma_alpha: 0.15,
            safety_multiplier: 2.0,
            base_floor,
            base_ceiling: Duration::from_millis(10_000),
        }
    }

    /// Returns the current timeout duration
    fn current_timeout(&self) -> Duration {
        self.current_timeout
    }

    /// Records a timeout and applies exponential backoff.
    ///
    /// The exponent is **capped** at [`MAX_BACKOFF_EXPONENT`] so that two
    /// honest replicas at different consecutive-timeout counters converge to
    /// the same tick rate within a bounded number of timeouts. Without the
    /// cap, replicas at counters 8 and 12 ticked at 256× and 4096× base —
    /// and `max_timeout` saturated them at different *real* schedules
    /// because saturation depended on how recently the counter was last
    /// reset. Capping the exponent makes saturation deterministic.
    ///
    /// See task #164 for the testnet halt this prevents.
    fn on_timeout(&mut self) {
        self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);

        let exponent = self.consecutive_timeouts.min(MAX_BACKOFF_EXPONENT) as i32;
        let backoff_factor = self.backoff_multiplier.powi(exponent);
        let new_timeout = self.base_timeout.mul_f64(backoff_factor);

        self.current_timeout = new_timeout.min(self.max_timeout);

        tracing::debug!(
            consecutive_timeouts = self.consecutive_timeouts,
            exponent = exponent,
            current_timeout_ms = self.current_timeout.as_millis(),
            "View timeout with capped exponential backoff"
        );
    }

    /// Records the observed view-to-QC formation latency for a
    /// successful view and updates the adaptive base timeout.
    ///
    /// This is where the timeout adapts. Each successful
    /// view contributes its wall-clock latency to the EWMA; the
    /// updated base timeout is `safety_multiplier × ewma`, clamped to
    /// `[base_floor, base_ceiling]`. The timer then resets backoff
    /// state (delegated to `on_success`).
    ///
    /// Call this from the consensus path that observes Commit QC
    /// formation. Must be called from `on_success` so a single code
    /// path owns the post-view bookkeeping.
    fn record_observed_view_latency(&mut self, observed: Duration) {
        let observed_ms = observed.as_millis() as f64;
        let new_ewma = match self.observed_latency_ewma_ms {
            Some(prev) => self.ewma_alpha * observed_ms + (1.0 - self.ewma_alpha) * prev,
            None => observed_ms,
        };
        self.observed_latency_ewma_ms = Some(new_ewma);
        self.p99_latency.observe(observed_ms);

        // The target must clear both the mean-derived estimate and the
        // measured tail. `safety_multiplier × ewma` handles the tight
        // (single-datacenter) case; the p99 estimate takes over when the
        // distribution is heavy-tailed (cross-region) — this is the
        // tail-at-scale correction that a static floor could only
        // approximate.
        let mean_target_ms = new_ewma * self.safety_multiplier;
        let tail_target_ms = self.p99_latency.estimate().unwrap_or(0.0);
        let target_ms = mean_target_ms.max(tail_target_ms);
        let target = Duration::from_millis(target_ms as u64)
            .max(self.base_floor)
            .min(self.base_ceiling);

        if target != self.base_timeout {
            tracing::info!(
                old_base_ms = self.base_timeout.as_millis(),
                new_base_ms = target.as_millis(),
                ewma_ms = new_ewma,
                p99_ms = tail_target_ms,
                observed_ms = observed_ms,
                "Adaptive view_timeout retuned from observed cluster latency"
            );
            self.base_timeout = target;
        }
    }

    /// Resets the timeout on successful view completion.
    ///
    /// Caller should pass the observed view latency so the adaptive
    /// algorithm can retune the base timeout. Pass `None` when the
    /// caller does not have a clean view-start timestamp (e.g.
    /// recovery paths); the timer then preserves the existing base
    /// without retuning.
    fn on_success(&mut self, observed: Option<Duration>) {
        if let Some(o) = observed {
            self.record_observed_view_latency(o);
        }
        self.consecutive_timeouts = 0;
        self.current_timeout = self.base_timeout;

        tracing::debug!(
            base_ms = self.base_timeout.as_millis(),
            "View completed successfully, timeout reset to adaptive base"
        );
    }
}

/// Messages the consensus engine needs to broadcast via gossipsub.
/// Uses an mpsc channel to avoid a circular crate dependency:
/// tenzro-consensus cannot import tenzro-network.
// `Proposal` carries a full `Block` plus optional TC and NEC; the enum is
// intentionally large because it crosses an mpsc boundary exactly once per
// view. Boxing every variant for the sake of one large arm would add an
// allocation on the consensus hot path and obscure the wire shape — the
// workspace `Cargo.toml` already lists `large_enum_variant = "allow"` for
// exactly this reason.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum ConsensusOutMessage {
    /// A vote this node cast that peers must receive to form quorum
    Vote(Vote),
    /// A block proposal the leader is broadcasting to all validators.
    /// `timeout_certificate` is `Some(_)` only when the leader is recovering
    /// from a view timeout — it carries 2f+1 timeout signatures from the
    /// previous view so peers can verify the new view was legitimately
    /// abandoned (the safe-to-extend vote rule).
    ///
    /// `no_endorsement_certificate` is `Some(_)` when the leader is proposing
    /// a *new* block at view N+1 after view N timed out — it carries f+1
    /// no-endorsement signatures from view N proving the predecessor's QC
    /// was not withheld (the NEC tail-fork defence) — closes the tail-fork
    /// MEV vulnerability. If absent, receivers must require the proposal to
    /// repropose the high-tip block; a fresh block with neither a NEC nor
    /// a high-tip parent is rejected.
    ///
    /// `high_qc_view` is the leader's local highest-Prepare-QC view at the
    /// moment of proposing (#171, the SyncInfo pattern). Receivers use it to
    /// fast-forward their own `high_qc_view` if the proposer is ahead, which
    /// shrinks the gap a lagging replica has to close before it can vote.
    /// Must satisfy `high_qc_view < view`.
    /// `proposer_signature` is the leader's hybrid (Ed25519 + ML-DSA-65)
    /// signature over `crate::validator::proposal_signing_payload(view,
    /// height, &block_hash, high_qc_view)`. Receivers verify it against the
    /// proposer's REGISTERED composite key — it makes proposals attributable
    /// (proposal-equivocation slashing) and authenticates the SyncInfo hint.
    Proposal {
        block: Block,
        proposer: Address,
        round: u64,
        view: u64,
        high_qc_view: u64,
        timeout_certificate: Option<crate::timeout::TimeoutCertificate>,
        no_endorsement_certificate: Option<crate::timeout::NoEndorsementCertificate>,
        proposer_signature: CompositeSignature,
    },
    /// A pacemaker timeout broadcast emitted on local view-timer expiry.
    /// Carries the sender's current view so a lagging peer can fast-forward
    /// (the backward-sync channel; phase 1 of #164).
    Timeout(crate::timeout::TimeoutMsg),
    /// A no-endorsement attestation broadcast emitted on local view-timer
    /// expiry. Aggregates into an f+1 NoEndorsementCertificate that the next
    /// leader attaches to its proposal when proposing a new block (the NEC
    /// tail-fork defence).
    NoEndorsement(crate::timeout::NoEndorsementMsg),
    /// A batch body this replica produced, fanned out over `tenzro/batches`
    /// so peer validators can store it and return an availability ack (G6
    /// data-dissemination plane). Peers verify `Batch::verify_id` before
    /// storing and acking.
    Batch(crate::batch_cert::Batch),
    /// An availability ack this replica emitted after storing a peer's batch
    /// body. Carries the producer address so the ack can be routed back to
    /// the producer collecting the availability certificate.
    BatchAck {
        /// Address of the producer that disseminated the batch (ack target).
        producer: Address,
        /// The signed availability ack.
        ack: crate::batch_cert::BatchAck,
    },
    /// A completed batch availability certificate (k-of-N BLS-aggregated)
    /// this replica formed as producer, broadcast so the ordering path on
    /// every replica can reference the batch by its 32-byte hash.
    BatchCertificate(crate::batch_cert::BatchAvailabilityCertificate),
}

/// HotStuff-2 consensus engine
pub struct HotStuff2Engine {
    /// Node's classical keypair (Ed25519). Used for the classical leg of the
    /// composite signature and to derive the on-chain address.
    keypair: Arc<KeyPair>,

    /// Node's ML-DSA-65 signing key (FIPS 204). Used for the post-quantum leg
    /// of the composite vote signature. Mandatory — there is no
    /// classical-only fallback.
    pq_signing_key: Arc<MlDsaSigningKey>,

    /// Node's BLS12-381 (min_pk) keypair. Used for the third signature leg
    /// emitted with every vote (`Vote.bls_signature`); per-vote BLS sigs at a
    /// given (view, height, block, vote_type) aggregate into the QC's
    /// `bls_aggregate` 96-byte G2 point. Mandatory — there is no fallback to
    /// classical-only or hybrid-only QCs.
    bls_signing_key: Arc<BlsKeyPair>,

    /// Cached composite public key (classical + ML-DSA-65 verifying key) that
    /// is embedded into every vote this node casts. Validators receiving the
    /// vote bind this against the registered hybrid key for the voter address.
    composite_public_key: CompositePublicKey,

    /// Node's address
    address: Address,

    /// Consensus configuration
    config: Arc<ConsensusConfig>,

    /// Epoch manager
    epoch_manager: Arc<EpochManager>,

    /// Transaction mempool
    mempool: Arc<Mempool>,

    /// Block proposer
    proposer: Arc<BlockProposer>,

    /// Vote collector
    vote_collector: Arc<RwLock<Option<Arc<VoteCollector>>>>,

    /// Finality tracker
    finality_tracker: Arc<FinalityTracker>,

    /// Current view state
    view_state: Arc<RwLock<ViewState>>,

    /// View change timer
    view_timer: Arc<RwLock<ViewChangeTimer>>,

    /// Proposed blocks by hash
    blocks: Arc<DashMap<Hash, Block>>,

    /// Fork choice: indexes proposed blocks alongside their QCs (when known)
    /// and resolves "best block at height" via the highest-Prepare-QC-view
    /// rule. Mirrors `self.blocks` for insert/evict and is updated with QCs
    /// at QC-formation time (driven from `try_form_qc_and_drive_phase`).
    /// Block production reads `select_best_block(parent_height)` to pick
    /// a non-finalized parent on the canonical fork; falls back to the
    /// finality tracker's last finalized hash when fork choice has no
    /// candidate (cold start, post-restart pre-warmup).
    fork_choice: Arc<ForkChoice>,

    /// Running state
    is_running: Arc<RwLock<bool>>,

    /// Operator drain flag. When `true`, this replica stops proposing new
    /// blocks while elected leader but keeps voting on peers' proposals —
    /// used by `tenzro node drain` (the `tenzro_setDraining` admin RPC) for
    /// graceful validator rollout. Mirrors the `is_running` lock idiom.
    drain: Arc<RwLock<bool>>,

    /// Shutdown signal
    shutdown_tx: Arc<RwLock<Option<broadcast::Sender<()>>>>,

    /// Slashing callback for punishing equivocating validators
    slashing_callback: Option<Arc<dyn SlashingCallback>>,

    /// Long-lived equivocation detector shared with every [`VoteCollector`]
    /// rebuild (epoch transitions rebuild the collector but must NOT reset
    /// conviction state). Also runs the proposal-equivocation check in
    /// `on_proposal`. Storage-backed when [`Self::with_audit_storage`] is
    /// used, so votes/proposals/evidence survive node restarts — without
    /// persistence an equivocator escapes slashing by restarting.
    equivocation_detector: Arc<crate::validator::EquivocationDetector>,

    /// State root provider for block proposals
    state_root_provider: Option<Arc<dyn StateRootProvider>>,

    /// Parent-block provider used during proposal and validation to
    /// re-derive the EIP-1559 base fee. Optional only for tests; in
    /// production the node wires a `BlockProvider` backed by the
    /// finality tracker + RocksDB block store.
    block_provider: Option<Arc<dyn BlockProvider>>,

    /// Outbound channel for broadcasting consensus messages via gossipsub.
    /// Uses mpsc to avoid a circular crate dependency (tenzro-consensus cannot
    /// import tenzro-network). The event_loop in tenzro-node drains this channel
    /// and publishes messages to the gossipsub swarm.
    consensus_out_tx: Option<tokio::sync::mpsc::UnboundedSender<ConsensusOutMessage>>,

    /// Persistent vote state — refuses to sign any (view, height, step) ≤
    /// last persisted, and persists each new vote with fsync **before** the
    /// vote is broadcast. Follows the persistent last-sign-state pattern. Defaults to
    /// an in-memory store for tests; production wires a `FileVoteStateStore`
    /// rooted at `<data_dir>/consensus/last_sign.json`.
    vote_state_store: Arc<dyn VoteStateStore>,

    /// The highest view at which this replica has observed a Prepare QC.
    /// Used as the `high_qc_view` field of any [`crate::timeout::TimeoutMsg`]
    /// this replica emits. The new leader after a TC formation extends from
    /// `max{tc.signers[i].high_qc_view}` so this monotonic value is what
    /// forces the next view's proposal to extend the freshest committed
    /// branch.
    ///
    /// Monotonic: only updated when a strictly higher view's Prepare QC is
    /// observed, never reset on view advance. Initial value 0 means "no QC
    /// observed yet" — the genesis case.
    high_qc_view: Arc<RwLock<u64>>,

    /// The most recent [`crate::timeout::TimeoutCertificate`] this replica
    /// has formed or learned of. Set by `on_timeout_msg` once 2f+1 timeouts
    /// at the same view aggregate; cleared (or replaced) when a new TC at a
    /// higher view is formed. The leader at view N+1 attaches this TC to
    /// its proposal so receivers can run `safe_to_extend` (the safe-to-extend
    /// vote rule).
    last_round_tc: Arc<RwLock<Option<crate::timeout::TimeoutCertificate>>>,

    /// 2f+1 [`crate::timeout::TimeoutMsg`] aggregator. Initialized lazily on
    /// `start()` once the validator set is known. Re-built on epoch
    /// transition alongside the vote collector.
    timeout_collector: Arc<RwLock<Option<Arc<crate::timeout::TimeoutCollector>>>>,

    /// The most recent [`crate::timeout::NoEndorsementCertificate`] this
    /// replica has formed or learned of. Set by `on_no_endorsement_msg` once
    /// f+1 attestations at the same view aggregate; cleared (or replaced)
    /// when a new NEC at a higher view is formed. The leader at view N+1
    /// attaches this NEC to its proposal when it cannot repropose a high-tip
    /// block — closes the tail-fork MEV vulnerability (the NEC tail-fork
    /// defence).
    last_round_nec: Arc<RwLock<Option<crate::timeout::NoEndorsementCertificate>>>,

    /// f+1 [`crate::timeout::NoEndorsementMsg`] aggregator. Initialized
    /// lazily on `start()` and rebuilt on epoch transition alongside
    /// `timeout_collector`.
    nec_collector: Arc<RwLock<Option<Arc<crate::timeout::NoEndorsementCollector>>>>,

    /// Highest view at which this replica has emitted a proposal. Acts as a
    /// monotonic guard so a leader CANNOT broadcast two different proposals
    /// for the same view — even if `propose_block_internal()` awaited long
    /// enough for the pacemaker to advance the view (e.g. Bracha boost from
    /// remote TimeoutMsgs) and the next tick re-enters the propose path on
    /// the new view. Production HotStuff-family BFT implementations gate
    /// proposal generation on this same monotonic-round invariant (via their
    /// certificate-processing and new-round handlers); without it, the
    /// honest leader can self-equivocate by racing a mempool-snapshot-drift
    /// rebuild against its own view-change handler. Sentinel value `u64::MAX`
    /// means "never proposed" (no view will compare-and-swap past it because
    /// `view < u64::MAX` always); we initialise to `0` and use a CAS-style
    /// fetch_max to enforce strict monotonicity.
    last_proposed_view: Arc<AtomicU64>,

    /// Cumulative count of local view timeouts since process start.
    /// Unlike `ViewTimer::consecutive_timeouts` (which resets on
    /// progress), this never resets — exported as
    /// `tenzro_consensus_view_timeouts_total` so on-call can alert on
    /// the timeout *rate*.
    view_timeouts_total: Arc<AtomicU64>,

    /// Receiver-side proposal dedup keyed by `(proposer, view, block_hash)`.
    /// Set of `(view, proposer_addr_first_4_bytes_u32, block_hash)` so a
    /// duplicate of a proposal we've already seen at this view from this
    /// proposer is dropped at the door — BEFORE running the catchup, vote,
    /// and vote-state-store paths. Follows the standard
    /// message-processing seen-set dedup. Without this, gossipsub
    /// IHAVE/IWANT replay (and any pre-fix in-flight proposals from the buggy
    /// run before the equivocation patch) keep firing the vote-state-store's
    /// double-sign refuse path and noise up the equivocation telemetry —
    /// even though the local replica correctly refuses to vote twice. The
    /// dedup set is bounded by `PROPOSAL_DEDUP_VIEW_WINDOW` and pruned in
    /// `advance_view` alongside the other per-view caches.
    proposal_dedup: Arc<DashMap<(u64, Hash), ()>>,

    /// Strategy for selecting the leader of a given round/view. Resolved
    /// from [`ConsensusConfig::proposer_election`] at construction time.
    /// `RoundRobinProposer` (`view % N`) for tests, `ReputationProposer`
    /// (reputation-weighted proposer election) for production.
    proposer_election: Arc<dyn ProposerElection>,

    /// Optional shared reputation state. Populated when
    /// `config.proposer_election == ProposerElectionKind::Reputation`. The
    /// engine feeds this with `record_round_outcome` and `record_round_voters`
    /// after each round closes so the proposer-election strategy reflects
    /// observed behaviour.
    reputation: Option<Arc<LeaderReputation>>,

    /// Behind-tip hint published to the block-sync engine.
    ///
    /// When a peer proposal arrives at a height strictly above our local
    /// height (`on_proposal` rejects it with `InvalidHeight`), the rejected
    /// height is sent here. Block-sync subscribes via
    /// [`subscribe_behind_hint`](Self::subscribe_behind_hint) and temporarily
    /// drops its engage tolerance to zero, closing the 1..=SLOT_IMPORT_TOLERANCE
    /// dead zone where catchup-on-proposal (exactly +1, in-memory parent only)
    /// can't help but block-sync wouldn't normally engage. `watch` notifies on
    /// every send, so repeated proposals keep re-arming the hint.
    behind_hint_tx: tokio::sync::watch::Sender<u64>,

    /// Wall-clock instant of the last block this replica proposed or
    /// observed finalized. Drives empty-block suppression: when the
    /// mempool is empty the leader proposes only after
    /// `config.empty_block_heartbeat()` has elapsed since this instant,
    /// instead of minting an empty block on every pacemaker beat. Updated
    /// whenever a fresh block is proposed. Initialised to engine-start so
    /// the first heartbeat fires one interval after boot, not immediately.
    last_block_time: Arc<RwLock<Instant>>,

    /// Batch availability-certificate store (G6 data-dissemination plane).
    ///
    /// Decouples data bandwidth from ordering bandwidth: a producer snapshots
    /// pending transactions into a [`crate::batch_cert::Batch`], disseminates
    /// the body over `tenzro/batches`, and collects a k-of-N BLS-aggregated
    /// [`crate::batch_cert::BatchAvailabilityCertificate`]. The ordering path
    /// then references only 32-byte cert hashes (via
    /// [`crate::batch_cert::agree_prefix`]) rather than full transaction
    /// bodies. `None` until [`Self::with_batch_cert_store`] is called (tests
    /// and single-node bootstrap run without the availability plane and fall
    /// back to direct mempool selection).
    batch_cert_store: Option<Arc<crate::batch_cert::BatchCertStore>>,
}

/// Evicts the lowest-`view` cached blocks until the map holds at most
/// `max_entries`. Returns the number evicted.
///
/// The height-keyed `retain` that runs before this cannot bound growth when
/// consensus is wedged at a single height: every failed view there proposes a
/// *distinct* block hash all sharing the stuck height, so the height window
/// reclaims none of them. This count cap is the backstop. Evicting the
/// lowest-`view` entries is safe — those are stale competing proposals from
/// old failed views; a future winning proposal extends the QC'd chain, never a
/// stale same-height sibling, so none of the evicted blocks can be a future
/// proposal's parent.
fn evict_excess_blocks_by_view(blocks: &DashMap<Hash, Block>, max_entries: usize) -> usize {
    if blocks.len() <= max_entries {
        return 0;
    }
    let mut by_view: Vec<(Hash, u64)> = blocks
        .iter()
        .map(|e| (*e.key(), e.value().header.view))
        .collect();
    by_view.sort_unstable_by_key(|(_, view)| *view);
    let excess = blocks.len().saturating_sub(max_entries);
    let mut evicted = 0;
    for (hash, _) in by_view.into_iter().take(excess) {
        if blocks.remove(&hash).is_some() {
            evicted += 1;
        }
    }
    evicted
}

impl HotStuff2Engine {
    /// Creates a new HotStuff-2 consensus engine.
    ///
    /// `keypair` is the classical Ed25519 keypair (for the address and the
    /// classical leg of the composite signature). `pq_signing_key` is the
    /// ML-DSA-65 (FIPS 204) signing key for the post-quantum leg.
    /// `bls_signing_key` is the BLS12-381 (min_pk) keypair for the third leg
    /// that aggregates into the QC `bls_aggregate`. All three are **mandatory**
    /// — there is no classical-only or hybrid-only fallback path.
    pub fn new(
        keypair: KeyPair,
        pq_signing_key: MlDsaSigningKey,
        bls_signing_key: BlsKeyPair,
        config: ConsensusConfig,
        epoch_manager: EpochManager,
    ) -> Self {
        // Convert tenzro_crypto::Address (20 bytes) to tenzro_types::Address (32 bytes)
        let crypto_addr = keypair.address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = Address::new(addr_bytes);
        let config = Arc::new(config);
        let epoch_manager = Arc::new(epoch_manager);
        let mempool = Arc::new(Mempool::new(config.clone()));
        let proposer = Arc::new(BlockProposer::new(mempool.clone(), config.clone()));
        let finality_tracker = Arc::new(FinalityTracker::new());
        let fork_choice = Arc::new(ForkChoice::new(finality_tracker.clone()));

        let initial_height = finality_tracker.finalized_height() + 1u64;
        let view_state = ViewState::new(0, initial_height);

        // Create view timer with base timeout from config and an absolute
        // 8-second ceiling. The exponent cap (`MAX_BACKOFF_EXPONENT = 3`)
        // alone yields `base × 2^3 = 8×` base; for the default 1s base this
        // is 8s. The explicit `max_timeout` here is the safety floor in case
        // a deployment overrides `view_timeout_ms` upward.
        let base_timeout = config.view_timeout();
        let max_timeout = Duration::from_secs(8);
        let view_timer =
            ViewChangeTimer::with_floor(base_timeout, max_timeout, config.adaptive_timeout_floor());

        let composite_public_key = CompositePublicKey::new(
            keypair.public_key().clone(),
            pq_signing_key.verifying_key_bytes().to_vec(),
        );

        // Resolve proposer-election strategy from config. The `Reputation`
        // path also constructs the shared `LeaderReputation` state that the
        // engine feeds with round outcomes — `RoundRobin` skips it entirely.
        let n = epoch_manager.current_validator_set().len();
        let (proposer_election, reputation): (
            Arc<dyn ProposerElection>,
            Option<Arc<LeaderReputation>>,
        ) = match config.proposer_election {
            ProposerElectionKind::RoundRobin => (Arc::new(RoundRobinProposer::new()), None),
            ProposerElectionKind::Reputation => {
                let rep = Arc::new(LeaderReputation::new(n));
                (Arc::new(ReputationProposer::new(rep.clone())), Some(rep))
            }
        };

        Self {
            keypair: Arc::new(keypair),
            pq_signing_key: Arc::new(pq_signing_key),
            bls_signing_key: Arc::new(bls_signing_key),
            composite_public_key,
            address,
            config,
            epoch_manager,
            mempool,
            proposer,
            vote_collector: Arc::new(RwLock::new(None)),
            finality_tracker,
            view_state: Arc::new(RwLock::new(view_state)),
            view_timer: Arc::new(RwLock::new(view_timer)),
            blocks: Arc::new(DashMap::new()),
            fork_choice,
            is_running: Arc::new(RwLock::new(false)),
            drain: Arc::new(RwLock::new(false)),
            shutdown_tx: Arc::new(RwLock::new(None)),
            slashing_callback: None,
            equivocation_detector: Arc::new(crate::validator::EquivocationDetector::new()),
            state_root_provider: None,
            block_provider: None,
            consensus_out_tx: None,
            vote_state_store: Arc::new(MemoryVoteStateStore::new()),
            high_qc_view: Arc::new(RwLock::new(0)),
            last_round_tc: Arc::new(RwLock::new(None)),
            timeout_collector: Arc::new(RwLock::new(None)),
            last_round_nec: Arc::new(RwLock::new(None)),
            nec_collector: Arc::new(RwLock::new(None)),
            last_proposed_view: Arc::new(AtomicU64::new(0)),
            view_timeouts_total: Arc::new(AtomicU64::new(0)),
            proposal_dedup: Arc::new(DashMap::new()),
            proposer_election,
            reputation,
            behind_hint_tx: tokio::sync::watch::Sender::new(0),
            last_block_time: Arc::new(RwLock::new(Instant::now())),
            batch_cert_store: None,
        }
    }

    /// Sets the slashing callback for punishing equivocating validators
    pub fn with_slashing_callback(mut self, callback: Arc<dyn SlashingCallback>) -> Self {
        self.slashing_callback = Some(callback);
        self
    }

    /// Installs a storage-backed equivocation detector (write-through to
    /// `CF_AUDIT` under `equivocation/*`, hydrated on construction) so
    /// vote/proposal observations and conviction evidence survive node
    /// restarts. Must be called before `start()` — collectors built at
    /// start and at epoch transitions capture whichever detector is
    /// current.
    pub fn with_audit_storage(mut self, storage: Arc<dyn tenzro_storage::KvStore>) -> Self {
        self.equivocation_detector = Arc::new(
            crate::validator::EquivocationDetector::with_storage(storage),
        );
        self
    }

    /// Sets the state root provider for block proposals.
    ///
    /// When set, the block proposer will query the current state root
    /// from this provider instead of using a default empty hash.
    pub fn with_state_root_provider(mut self, provider: Arc<dyn StateRootProvider>) -> Self {
        self.state_root_provider = Some(provider);
        self
    }

    /// Sets the parent-block provider used for EIP-1559 base-fee
    /// derivation. Required in production; absent providers cause the
    /// engine to fall back to a genesis-edge base fee on every block,
    /// which is wrong on any non-genesis block.
    pub fn with_block_provider(mut self, provider: Arc<dyn BlockProvider>) -> Self {
        self.block_provider = Some(provider);
        self
    }

    /// Wires up the outbound gossipsub channel so votes and proposals are
    /// broadcast to peers. Must be called before `start()`.
    pub fn with_consensus_out(
        mut self,
        tx: tokio::sync::mpsc::UnboundedSender<ConsensusOutMessage>,
    ) -> Self {
        self.consensus_out_tx = Some(tx);
        self
    }

    /// Installs the batch availability-certificate store (G6 data-dissemination
    /// plane). When set, [`Self::produce_batch`] snapshots pending transactions
    /// into a batch and disseminates it, and the ingest methods
    /// ([`Self::ingest_batch_body`], [`Self::ingest_batch_ack`],
    /// [`Self::ingest_batch_certificate`]) drive availability-certificate
    /// formation. Absent this, the engine runs the direct mempool-selection
    /// path with no availability plane. Must be called before `start()`.
    pub fn with_batch_cert_store(mut self, store: Arc<crate::batch_cert::BatchCertStore>) -> Self {
        self.batch_cert_store = Some(store);
        self
    }

    /// Returns the installed batch availability-certificate store, if any.
    pub fn batch_cert_store(&self) -> Option<Arc<crate::batch_cert::BatchCertStore>> {
        self.batch_cert_store.clone()
    }

    /// Snapshots up to `config.max_transactions_per_block` pending mempool
    /// transactions into a [`crate::batch_cert::Batch`], stores the body
    /// locally, and emits it over `tenzro/batches` for peer validators to
    /// store and ack (G6 producer path). Returns the batch id, or `None` when
    /// no batch-cert store is installed or the mempool is empty.
    ///
    /// This is the availability-dissemination step that runs *ahead* of
    /// ordering: the producer proves the data is stored by 2f+1 stake-weight
    /// before the ordering path references the batch by hash.
    pub fn produce_batch(&self) -> Option<Hash> {
        let store = self.batch_cert_store.as_ref()?;
        self.mempool.cleanup_expired();
        let txs = self.mempool.select_transactions(
            self.config.max_transactions_per_block,
            self.config.max_gas_per_block,
        );
        if txs.is_empty() {
            return None;
        }
        let batch = store.produce(txs);
        let id = batch.id;
        let validator_set = self.validator_set();
        // Erasure-coded broadcast decision (G6 stage 2): at or above the
        // activation threshold the batch is Reed-Solomon-coded (n = 3f+1
        // slivers, any 2f+1 reconstruct) so no single node uploads the full
        // body to every peer; below it, direct gossip of the full body is
        // cheaper. The threshold and fault bound are pure functions of the
        // validator-set size — no fixed region count.
        let validator_count = validator_set.active_validators().len();
        match store.encode_for_broadcast(&batch, validator_count) {
            Ok(Some(encoded)) => tracing::debug!(
                n = validator_count,
                slivers = encoded.slivers.len(),
                commitment = %hex::encode(&encoded.commitment.as_bytes()[..8]),
                "batch_cert: erasure-coded batch for broadcast"
            ),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, "batch_cert: erasure encode failed; falling back to direct gossip")
            }
        }
        // Sign our own availability ack (the producer stored the body) so the
        // producer's own stake counts toward the certificate.
        let ack = store.sign_ack(&id);
        let _ = store.record_ack(id, ack, &validator_set);
        self.send_out(ConsensusOutMessage::Batch(batch));
        Some(id)
    }

    /// Ingests a peer's batch body (received over `tenzro/batches`): verifies
    /// the batch id binds to its transactions, stores the body, and emits a
    /// signed availability ack back toward the producer. No-op without a
    /// batch-cert store.
    pub fn ingest_batch_body(&self, batch: crate::batch_cert::Batch) {
        let Some(store) = self.batch_cert_store.as_ref() else {
            return;
        };
        if !batch.verify_id() {
            tracing::warn!("batch_cert: rejecting batch body with mismatched id");
            return;
        }
        let producer = batch.producer;
        let batch_id = batch.id;
        store.store_body(batch);
        let ack = store.sign_ack(&batch_id);
        self.send_out(ConsensusOutMessage::BatchAck { producer, ack });
    }

    /// Ingests an availability ack for a batch this replica produced (received
    /// over `tenzro/batches`): records it, and — once 2f+1 stake-weight of
    /// acks accumulate — forms and broadcasts the availability certificate.
    /// No-op without a batch-cert store.
    pub fn ingest_batch_ack(&self, batch_id: Hash, ack: crate::batch_cert::BatchAck) {
        let Some(store) = self.batch_cert_store.as_ref() else {
            return;
        };
        let validator_set = self.validator_set();
        match store.record_ack(batch_id, ack, &validator_set) {
            Ok(Some(cert)) => {
                tracing::info!(
                    batch = %hex::encode(&batch_id.as_bytes()[..8]),
                    "batch_cert: availability certificate formed"
                );
                self.send_out(ConsensusOutMessage::BatchCertificate(cert));
            }
            Ok(None) => {}
            Err(e) => tracing::debug!(error = %e, "batch_cert: ack rejected"),
        }
    }

    /// Ingests a completed availability certificate (received over
    /// `tenzro/batches`): verifies its BLS aggregate against the active
    /// validator set and installs it so the ordering path can reference the
    /// batch by hash. No-op without a batch-cert store.
    pub fn ingest_batch_certificate(&self, cert: crate::batch_cert::BatchAvailabilityCertificate) {
        let Some(store) = self.batch_cert_store.as_ref() else {
            return;
        };
        let validator_set = self.validator_set();
        // `install_cert` verifies the 2f+1 BLS aggregate against the active set
        // before persisting; a certificate that fails verification is rejected.
        match store.install_cert(cert, &validator_set) {
            Ok(()) => {
                // Recompute the certified prefix (G6 prefix consensus): the newly
                // installed certificate may extend the ordered frontier of
                // availability-certified batches the ordering path can reference
                // by hash. The prefix is the longest deterministically-ordered
                // run of certs whose bodies are held, so two honest nodes on the
                // same certified history derive the same reference list.
                let prefix = store.certified_prefix();
                tracing::debug!(
                    certified_frontier = prefix.len(),
                    "batch_cert: availability certificate installed"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "batch_cert: rejecting invalid availability certificate");
            }
        }
    }

    /// Installs a persistent vote-state store. Production callers should use
    /// `vote_state::open_default_file_store(data_dir)` to get a fsync-backed
    /// `FileVoteStateStore`. Tests can pass a `MemoryVoteStateStore` (which
    /// is also the default if this builder is never called).
    pub fn with_vote_state_store(mut self, store: Arc<dyn VoteStateStore>) -> Self {
        self.vote_state_store = store;
        self
    }

    /// Wires the Spec-2 per-DID admission controller into the engine's
    /// mempool. Forwards to [`Mempool::set_admission`]. May be called at
    /// most once per engine instance (the underlying `OnceLock` rejects
    /// double-wiring with `ConsensusError::AlreadyStarted`).
    ///
    /// Must be called **after** `HotStuff2Engine::new` (which constructs
    /// the mempool) but **before** the engine starts admitting traffic in
    /// production. Until this is called, the mempool falls back to the
    /// legacy size/count-only path — fine for tests and the very first
    /// genesis tick, not fine for a public-facing node.
    pub fn set_admission(
        &self,
        admission: Arc<crate::admission::AdmissionController>,
    ) -> crate::Result<()> {
        self.mempool.set_admission(admission)
    }

    /// Wires a live account state reader into the engine's mempool for
    /// stateful admission (nonce ordering + balance coverage). Forwards to
    /// [`Mempool::set_state_reader`]; same at-most-once contract as
    /// [`Self::set_admission`].
    pub fn set_state_reader(
        &self,
        reader: Arc<dyn crate::mempool::AccountStateReader>,
    ) -> crate::Result<()> {
        self.mempool.set_state_reader(reader)
    }

    /// Read-only access to the mempool — exposed so node startup can hand
    /// the same `Arc<Mempool>` to RPC handlers (`tenzro_getMempoolStats`,
    /// `tenzro_getMempoolLane`) without going through this engine.
    pub fn mempool(&self) -> &Arc<Mempool> {
        &self.mempool
    }

    /// Snapshot of the highest view at which this replica has observed a
    /// Prepare QC. Monotonic; 0 means "no QC observed yet" (genesis).
    ///
    /// Used by the HTTP `/ready` endpoint to gate liveness on consensus
    /// progress: a pod that has caught up on block height but whose
    /// `high_qc_view` lags the network is still mid-bootstrap and must
    /// not be marked Ready.
    pub fn high_qc_view(&self) -> u64 {
        *self.high_qc_view.read()
    }

    /// Snapshot of the local view counter. Read-only — use carefully
    /// (the view advances asynchronously as messages arrive).
    pub fn current_view(&self) -> u64 {
        self.view_state.read().view
    }

    /// Cumulative count of local view timeouts since process start.
    /// Exported as `tenzro_consensus_view_timeouts_total`.
    pub fn view_timeouts_total(&self) -> u64 {
        self.view_timeouts_total.load(Ordering::Relaxed)
    }

    /// Seconds since the last block finalized on this replica, or `None`
    /// if nothing has finalized since process start. Exported as
    /// `tenzro_consensus_last_finalized_age_seconds`.
    pub fn seconds_since_last_finalized(&self) -> Option<u64> {
        self.finality_tracker.seconds_since_last_finalized()
    }

    /// Counts of detected (vote, proposal) equivocations on this replica.
    /// Exported as `tenzro_consensus_equivocation_evidence{kind}` — any
    /// non-zero value is a page-worthy event.
    pub fn equivocation_evidence_counts(&self) -> (usize, usize) {
        (
            self.equivocation_detector.evidence_count(),
            self.equivocation_detector.proposal_evidence_count(),
        )
    }

    /// Snapshot of the engine's working height — the NEXT height it will
    /// vote on or propose (storage tip + 1 on a healthy node). Used by
    /// block-sync to detect an engine that has fallen behind local storage
    /// (gossip imports advance storage without touching the engine).
    pub fn current_height(&self) -> BlockHeight {
        self.view_state.read().height
    }

    /// Sets the operator drain flag. While draining, this replica does not
    /// propose blocks as leader (it keeps voting on peers' proposals).
    /// Toggled by the `tenzro_setDraining` admin RPC / `tenzro node drain`.
    pub fn set_draining(&self, draining: bool) {
        *self.drain.write() = draining;
    }

    /// Returns `true` if this replica is currently draining (not proposing).
    pub fn is_draining(&self) -> bool {
        *self.drain.read()
    }

    /// Returns `true` if this replica is the elected leader for *any* of
    /// the next `lookahead_views` consecutive views. Used by the
    /// `tenzro_gracefulExit` admin RPC to wait until we can step down
    /// without forcing a TC round on the next leader rotation.
    ///
    /// Conservative: if leader election fails for any view in the window
    /// (e.g. validator set unknown), returns `true` so the operator
    /// keeps waiting rather than exiting blindly.
    pub fn is_leader_in_next_views(&self, lookahead_views: u64) -> bool {
        let base_view = self.view_state.read().view;
        let validator_set = self.validator_set();
        let current_epoch = self.epoch_manager.current_epoch();
        let epoch = current_epoch.number;
        // Per-epoch fixed seed anchor — identical on every node for the
        // whole epoch, unlike the local finalized tip which differs by a
        // block or two across the fleet at any instant.
        let prev_block_id = current_epoch.seed_anchor.0;

        for offset in 0..lookahead_views {
            let view = base_view.saturating_add(offset);
            match self
                .proposer_election
                .select_leader(view, epoch, prev_block_id, &validator_set)
            {
                Ok(leader) if leader == self.address => return true,
                Ok(_) => continue,
                Err(_) => return true, // conservative
            }
        }
        false
    }

    /// Sends a message to the outbound gossipsub channel.
    /// Silently drops the message if no channel has been wired up.
    fn send_out(&self, msg: ConsensusOutMessage) {
        let kind = match &msg {
            ConsensusOutMessage::Vote(_) => "Vote",
            ConsensusOutMessage::Proposal { .. } => "Proposal",
            ConsensusOutMessage::Timeout(_) => "Timeout",
            ConsensusOutMessage::NoEndorsement(_) => "NoEndorsement",
            ConsensusOutMessage::Batch(_) => "Batch",
            ConsensusOutMessage::BatchAck { .. } => "BatchAck",
            ConsensusOutMessage::BatchCertificate(_) => "BatchCertificate",
        };
        match self.consensus_out_tx {
            Some(ref tx) => match tx.send(msg) {
                Ok(()) => tracing::info!(kind = kind, "consensus.send_out: queued to event_loop"),
                Err(e) => {
                    tracing::warn!(kind = kind, error = %e, "consensus.send_out: tx.send FAILED (rx dropped?)")
                }
            },
            None => {
                tracing::warn!(
                    kind = kind,
                    "consensus.send_out: NO TX wired (consensus_out_tx is None)"
                );
            }
        }
    }

    /// Resumes consensus from a previously persisted block height.
    ///
    /// Called during node startup to seed the consensus engine with the
    /// last known finalized height from storage. Without this, the engine
    /// always starts proposing from height 1, creating duplicate blocks
    /// that overlap with already-persisted data.
    ///
    /// Also consults `vote_state_store` to advance the local view past any
    /// vote already cast in a prior run. Without this jump, after an
    /// unproductive run that votes through (say) view=62 at height=1
    /// without finalizing, a fresh boot would propose at view=0,1,2,…
    /// and every vote would be refused by the height-round-step (HRS) check
    /// (`vote_state.rs::check_vrs`) — wedging the chain.
    ///
    /// **The persisted `last_signed_view` is a strict, height-independent
    /// signing ceiling.** This follows the standard Safety-Rules patterns:
    ///   - `last_voted_round` — checked
    ///     synchronously in `verify_and_update_last_vote_round()` against
    ///     `round`, never against `(round, height)`.
    ///   - Persistent `LastSignState{Height,Round,Step}` —
    ///     `is_strictly_after` enforces lex order with view first, so a
    ///     persisted `(v=N, h=H-1, Commit)` blocks signing any
    ///     `(v ≤ N, h=H, *)` next height.
    ///
    /// The previous implementation gated the view-jump on
    /// `persisted.height == next_height.0`, which is wrong: in the
    /// 2026-04-30 testnet wedge we observed persisted `(v=29999, h=29988,
    /// Commit)` and `next_height = 29989`, so the guard skipped, the
    /// engine booted at view ~29988, advanced via timeouts up to view
    /// 29997 < persisted ceiling 29999, and `vote_state` correctly
    /// refused → wedge. The fix: adopt the persisted view ceiling
    /// unconditionally — `state.view = max(state.view, persisted.view + 1)`.
    ///
    /// Must be called **before** `start()`.
    pub fn resume_from_height(&self, height: BlockHeight) {
        // Compute the next height we're going to propose at:
        //   - if storage has a finalized tip > 0, propose at tip+1
        //   - if nothing has finalized (height=0), propose at height=1
        let next_height = if height.0 == 0 {
            BlockHeight(1)
        } else {
            // Update the finality tracker so it knows the chain tip
            self.finality_tracker.set_initial_height(height);
            height + 1u64
        };

        // Recover the certifying view of the latest finalized block via the
        // wired BlockProvider. The block at `height` was finalized through a
        // 2f+1 Commit-QC at `block.header.view`; this view is the highest
        // Prepare-QC the network has produced, so `high_qc_view` must be at
        // least `block.header.view` on boot. Without this, a freshly-booted
        // leader proposes from a stale lock (default 0), the network already
        // holds a higher lock and refuses to vote, the view times out, and
        // the chain live-locks across all validators rebooting in sequence.
        //
        // This is the Safety-Rules pattern: persisted highest_qc
        // is restored on boot so the engine cannot regress its lock.
        // Mirrors the `commit_qc_view` parameter accepted by
        // `resume_from_synced_height`, but recovered from storage instead of
        // passed by the block-sync caller.
        let recovered_commit_qc_view: Option<u64> = if height.0 > 0 {
            self.block_provider
                .as_ref()
                .and_then(|bp| bp.get_block(height))
                .map(|block| block.header.view)
        } else {
            None
        };

        let mut state = self.view_state.write();
        state.height = next_height;
        // Set view to at least match height for consistency
        if height.0 > state.view {
            state.view = height.0;
        }
        // Bump view past the certifying QC view — we must not propose or
        // vote at any view ≤ the view that already produced a Commit-QC.
        if let Some(commit_qc_view) = recovered_commit_qc_view {
            let target_view = commit_qc_view.saturating_add(1);
            if target_view > state.view {
                state.view = target_view;
            }
        }

        // Consult persisted vote state. The persisted view is a
        // monotonic signing ceiling regardless of which height it was
        // recorded for — adopt it unconditionally so the engine cannot
        // boot below the safety floor and wedge.
        match self.vote_state_store.load() {
            Ok(persisted) => {
                let ceiling = persisted.view.saturating_add(1);
                if ceiling > state.view {
                    let prev_view = state.view;
                    state.view = ceiling;
                    tracing::info!(
                        prev_view,
                        resumed_view = ceiling,
                        next_height = %next_height,
                        persisted_last_vote_view = persisted.view,
                        persisted_last_vote_height = persisted.height,
                        cross_height = persisted.height != next_height.0,
                        "Consensus engine: jumping view past persisted last_vote ceiling to avoid CheckHRS wedge"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "vote_state_store.load() failed during resume — view not adjusted");
            }
        }

        // Drop the view_state lock before acquiring high_qc_view to keep
        // lock acquisition order consistent with the rest of the engine.
        drop(state);

        // Restore high_qc_view from the recovered commit-QC view. In
        // HotStuff-2, high_qc_view tracks the highest Prepare-QC view; a
        // Commit-QC at view V implies a Prepare-QC at view V (commits are
        // produced one phase after Prepare in the same view), so using
        // `recovered_commit_qc_view` here is sound.
        if let Some(commit_qc_view) = recovered_commit_qc_view {
            let mut hqc = self.high_qc_view.write();
            if commit_qc_view > *hqc {
                let prev_hqc = *hqc;
                *hqc = commit_qc_view;
                tracing::info!(
                    prev_high_qc_view = prev_hqc,
                    restored_high_qc_view = commit_qc_view,
                    from_height = %height,
                    "Consensus engine: restored high_qc_view from finalized block header"
                );
            }

            // Record a synthetic LastSignState at (view = commit_qc_view,
            // height = height, step = Commit) so the persistent signing
            // ceiling reflects the certified state. A future
            // `is_strictly_after` check will refuse any vote at
            // (v ≤ commit_qc_view, *) on this height.
            let synthetic = LastSignState {
                version: 1,
                view: commit_qc_view,
                height: height.0,
                step: VoteStep::Commit,
                block_hash: None,
                signature: None,
            };
            if let Err(e) = self.vote_state_store.record(&synthetic) {
                tracing::warn!(
                    error = %e,
                    resumed_height = %height,
                    commit_qc_view,
                    "vote_state_store.record() failed during resume — engine \
                     will still advance its in-memory state, but a crash \
                     before the next legitimate vote could regress the \
                     signing ceiling"
                );
            }
        } else if height.0 > 0 {
            // We have a finalized height but couldn't recover the block —
            // either no block_provider is wired (test paths) or storage
            // returned None. Log a warning so this is visible in operator
            // dashboards; the engine will still boot but with the lock
            // unrestored, which is the pre-fix wedge condition.
            tracing::warn!(
                resumed_height = %height,
                block_provider_wired = self.block_provider.is_some(),
                "Consensus engine: could not recover commit_qc_view from \
                 storage on boot — high_qc_view NOT restored. This may \
                 cause a consensus live-lock if peers hold a higher lock."
            );
        }

        let final_view = self.view_state.read().view;
        tracing::info!(
            stored_height = %height,
            next_height = %next_height,
            view = final_view,
            recovered_commit_qc_view = ?recovered_commit_qc_view,
            "Consensus engine resuming from stored height"
        );
    }

    /// Resumes the consensus engine after catching up to `height` via the
    /// block-sync RPC, with the certifying commit-QC view `commit_qc_view`.
    ///
    /// This differs from [`Self::resume_from_height`] in two ways:
    ///
    /// 1. It is called **mid-life** (after `start()` is already running on
    ///    other nodes) — the local engine just imported a sequence of
    ///    finalized blocks and needs to slot back into the live view
    ///    cadence without proposing or voting at any view ≤ `commit_qc_view`.
    /// 2. The caller has a verified `QuorumCertificate` for the block at
    ///    `height`, so we know the network has *already* committed at
    ///    view `commit_qc_view`. The local view ceiling must be at least
    ///    `commit_qc_view + 1` — anything lower would let us double-vote
    ///    in a view that has already produced a 2f+1 commit.
    ///
    /// Concretely:
    ///   * Updates the finality tracker to `height` so transaction
    ///     execution and RPC `getBlock` queries return correct values.
    ///   * Advances `view_state.height` to `height + 1` (next height to
    ///     propose / vote at).
    ///   * Sets `view_state.view = max(state.view, commit_qc_view + 1)`.
    ///   * Bumps the persistent `vote_state_store` ceiling so that an
    ///     immediate crash-and-restart cannot re-vote below
    ///     `commit_qc_view`.
    ///   * Updates `high_qc_view` to `commit_qc_view`. NOTE: `high_qc_view`
    ///     in HotStuff-2 tracks the highest *Prepare-QC* view; a
    ///     **commit-QC** at view V implies a Prepare-QC at view V (commits
    ///     are produced one phase after Prepare in the same view), so
    ///     using `commit_qc_view` here is sound.
    ///
    /// Modeled on the standard post-sync consensus-state reset performed
    /// once a replica has synced to a finalized block.
    ///
    /// **Caller contract:** the QC at `commit_qc_view` MUST already be
    /// signature-verified against the validator set known at the
    /// certifying epoch. This method does NOT re-verify — it trusts the
    /// caller. The block-sync engine in `tenzro-node` is the canonical
    /// caller and performs verification before invoking this.
    pub fn resume_from_synced_height(&self, height: BlockHeight, commit_qc_view: u64) {
        // Tell the finality tracker we're synced to `height`. Mirrors the
        // genesis path in `resume_from_height`.
        self.finality_tracker.set_initial_height(height);

        // Compute the next height we'll propose/vote at.
        let next_height = if height.0 == 0 {
            BlockHeight(1)
        } else {
            height + 1u64
        };

        // Adopt the QC view as a signing ceiling. View must satisfy:
        //   view > commit_qc_view  (so we can't re-vote in the certified view)
        //   view ≥ next_height     (HRS lex order: view is leading dimension)
        let target_view = commit_qc_view.saturating_add(1).max(next_height.0);

        // Apply the view-state update under one write lock.
        {
            let mut state = self.view_state.write();
            let prev_height = state.height;
            let prev_view = state.view;

            state.height = next_height;
            if target_view > state.view {
                state.view = target_view;
            }
            // Reset phase/proposed_block/qc fields — we're crossing a sync
            // boundary; whatever in-flight state we had for the old view is
            // stale.
            state.phase = Phase::Prepare;
            state.proposed_block = None;
            state.prepare_qc = None;
            state.commit_qc = None;
            state.view_start_time = Instant::now();

            tracing::info!(
                prev_view,
                resumed_view = state.view,
                prev_height = %prev_height,
                resumed_height = %next_height,
                synced_height = %height,
                commit_qc_view,
                "Consensus engine resuming after block-sync catchup"
            );
        }

        // Advance the persisted high_qc_view so future TimeoutMsgs carry
        // the correct ceiling — without this, a TC built post-catchup
        // would advertise a stale max_high_qc_view and the next leader
        // could pick a too-low next-view target.
        {
            let mut hqc = self.high_qc_view.write();
            if commit_qc_view > *hqc {
                *hqc = commit_qc_view;
            }
        }

        // Bump the persistent signing ceiling. We record a synthetic
        // `LastSignState` at (view = commit_qc_view, height = height,
        // step = Commit) — this is the strongest legal claim, since the
        // 2f+1 commit aggregate at that (view, height) is already on
        // chain. A future `vote_state.is_strictly_after` check will
        // refuse any vote at (v ≤ commit_qc_view, *) on this height,
        // closing the post-sync re-vote window.
        let synthetic = LastSignState {
            version: 1,
            view: commit_qc_view,
            height: height.0,
            step: VoteStep::Commit,
            // We don't have the actual signed bytes (sync arrived as a 2f+1
            // aggregate, not as our own vote), so we leave hash/signature
            // unset. The is_strictly_after check uses (view, height, step)
            // tuple ordering and does not require the hash.
            block_hash: None,
            signature: None,
        };
        if let Err(e) = self.vote_state_store.record(&synthetic) {
            tracing::warn!(
                error = %e,
                synced_height = %height,
                commit_qc_view,
                "vote_state_store.record() failed during sync resume — engine \
                 will still advance its in-memory view, but a crash before the \
                 next legitimate vote could allow re-signing below the commit \
                 QC ceiling"
            );
        }
    }

    /// Submit a validated transaction to the consensus mempool.
    ///
    /// Called by the event loop after transaction validation (signature, gas, nonce checks).
    /// The mempool orders transactions by gas price priority and enforces size limits.
    pub fn submit_transaction(&self, tx: SignedTransaction) -> Result<()> {
        self.mempool.add_transaction(tx)
    }

    /// Subscribe to behind-tip hints.
    ///
    /// The receiver fires whenever `on_proposal` rejects a peer proposal at a
    /// height above ours — i.e. the network has finalized blocks we don't
    /// have and the in-band catchup path couldn't recover them. The carried
    /// value is the rejected proposal height. Block-sync uses this to drop
    /// its engage tolerance to zero so small gaps (1..=SLOT_IMPORT_TOLERANCE)
    /// don't strand a restarted replica one block behind the tip.
    pub fn subscribe_behind_hint(&self) -> tokio::sync::watch::Receiver<u64> {
        self.behind_hint_tx.subscribe()
    }

    /// Subscribe to finality notifications.
    ///
    /// Returns a broadcast receiver that emits `FinalityNotification` each time
    /// a block is finalized by consensus. The event loop subscribes to this
    /// to execute transactions and persist state.
    pub fn subscribe_finality(&self) -> broadcast::Receiver<FinalityNotification> {
        self.finality_tracker.subscribe()
    }

    /// Returns the current finalized block height.
    pub fn current_finalized_height(&self) -> BlockHeight {
        self.finality_tracker.finalized_height()
    }

    /// Records that the chain has finalized up to `height` without this
    /// engine having driven the commit.
    ///
    /// A node that verifies blocks but does not vote never runs the finalize
    /// path, so its tracker would only move when block-sync completes a
    /// catch-up run. Once such a node is at the tip it takes new blocks off
    /// gossip instead, and everything reading `current_finalized_height` — the
    /// chain-entropy seed for committee selection, audit-event height stamps —
    /// would keep quoting the height it last synced at.
    ///
    /// Monotone: a height at or below the tracker's is ignored. Touches only
    /// the finalized height, never view state or the signing ceiling, so it is
    /// not a substitute for [`Self::resume_from_synced_height`] on a node that
    /// votes.
    pub fn observe_finalized_height(&self, height: BlockHeight) {
        self.finality_tracker.set_initial_height(height);
    }

    /// Returns a clone of the shared epoch manager handle.
    ///
    /// Used by the staking lifecycle in `tenzro-node` to enqueue / dequeue
    /// validators for the next epoch (`add_pending_validator` /
    /// `remove_pending_validator`) when stake/unstake RPCs land or when
    /// slashing drops a validator below the minimum stake.
    pub fn epoch_manager(&self) -> Arc<EpochManager> {
        Arc::clone(&self.epoch_manager)
    }

    /// Returns a clone of the shared fork-choice handle.
    ///
    /// Block production reads `select_best_block(parent_height)` to pick
    /// the canonical parent on a non-finalized fork; tests can inspect
    /// the index via `block_count` / `get_block` / `get_qc`.
    pub fn fork_choice(&self) -> Arc<ForkChoice> {
        Arc::clone(&self.fork_choice)
    }

    /// Returns the current validator set
    pub fn validator_set(&self) -> ValidatorSet {
        self.epoch_manager.current_validator_set()
    }

    /// Returns the validator set that was active at the given block height.
    ///
    /// This is the accessor cross-epoch block-sync depends on: a node
    /// catching up from far behind must verify each historical block's
    /// commit-QC against the validator set that signed it, not the current
    /// epoch's set. Returns `None` if the epoch covering `height` has been
    /// pruned from history (signals "snapshot sync required" to the caller).
    pub fn validator_set_for_height(&self, height: BlockHeight) -> Option<ValidatorSet> {
        self.epoch_manager
            .get_epoch_for_height(height)
            .map(|e| e.validator_set)
    }

    /// Checks if this node is a validator
    fn is_validator(&self) -> bool {
        self.validator_set().is_validator(&self.address)
    }

    /// Gets the leader for the current view via the configured
    /// [`ProposerElection`] strategy.
    ///
    /// `prev_block_id` for the reputation seed is the epoch's fixed
    /// `seed_anchor` — the finalized block hash at the epoch's canonical
    /// boundary. Anchoring per-epoch (rather than on the local finalized
    /// tip, which differs by a block or two across nodes at any instant)
    /// makes leader election deterministic fleet-wide while preserving
    /// the anti-grinding invariant: the anchor is a finalized hash no
    /// proposer can grind on — see
    /// [`crate::leader_reputation::reputation_seed`].
    fn get_leader(&self) -> Result<Address> {
        let view = self.view_state.read().view;
        let validator_set = self.validator_set();
        let current_epoch = self.epoch_manager.current_epoch();
        self.proposer_election.select_leader(
            view,
            current_epoch.number,
            current_epoch.seed_anchor.0,
            &validator_set,
        )
    }

    /// Resolves the elected leader for an arbitrary `view` under the
    /// current epoch's fixed seed anchor. Used by proposal-side proposer
    /// enforcement and committed-metadata reputation derivation.
    fn leader_for_view(&self, view: u64) -> Result<Address> {
        let validator_set = self.validator_set();
        let current_epoch = self.epoch_manager.current_epoch();
        self.proposer_election.select_leader(
            view,
            current_epoch.number,
            current_epoch.seed_anchor.0,
            &validator_set,
        )
    }

    /// Advances to the next view
    async fn advance_view(&self) -> Result<()> {
        let new_view = {
            let mut state = self.view_state.write();

            state.view += 1;
            state.phase = Phase::Prepare;
            state.proposed_block = None;
            state.prepare_qc = None;
            state.commit_qc = None;
            state.reset_timer();

            tracing::info!(
                view = state.view,
                height = %state.height,
                "Advanced to new view"
            );
            state.view
        };

        // Bound consensus memory. Without this, three caches accumulate
        // forever and eventually OOMKill the validator:
        //   1. `self.blocks` is inserted into on every `on_proposal` and
        //      `propose_block_internal` but never evicted — each restart of
        //      the gossipsub dedup window for an old block re-inserts it.
        //   2. `vote_collector.votes` and `.quorum_certificates` retain every
        //      vote forever; with ML-DSA-65 hybrid signatures (~3.3 KB each)
        //      and a stalled view counter that keeps ticking, this is the
        //      dominant growth term.
        //   3. `finality_tracker.finalized_blocks` keeps full Block payloads
        //      for every finalized height since genesis.
        // We retain `BLOCK_CACHE_HEIGHT_WINDOW` blocks/finality entries below
        // the current finalized height for ancestry checks and late gossip,
        // and `VOTE_CACHE_VIEW_WINDOW` views of vote/QC history. Both windows
        // are generous enough to absorb timeout backoff and short partitions
        // without wedging consensus.
        const BLOCK_CACHE_HEIGHT_WINDOW: u64 = 256;
        const VOTE_CACHE_VIEW_WINDOW: u64 = 256;
        // Hard ceiling on the number of cached blocks. The height window alone
        // cannot bound growth when consensus is wedged at a single height: every
        // failed view at that height proposes a *distinct* block hash, all
        // sharing the stuck height, so `retain(height >= min_height)` reclaims
        // none of them. A chain stuck for tens of thousands of views then
        // accumulates one full Block per view until the process OOMs — which in
        // turn starves the block-sync serving path that peers need to catch up,
        // wedging the whole fleet. We cap the cache by count and, on overflow,
        // evict the lowest-`view` entries (the stalest competing proposals)
        // first. The cap is comfortably above any legitimate working set:
        // BLOCK_CACHE_HEIGHT_WINDOW distinct heights plus generous slack for
        // concurrent same-height forks during a partition.
        const BLOCK_CACHE_MAX_ENTRIES: usize = 4096;

        let finalized_height = self.finality_tracker.finalized_height();
        let min_height = BlockHeight(finalized_height.0.saturating_sub(BLOCK_CACHE_HEIGHT_WINDOW));

        let blocks_before = self.blocks.len();
        self.blocks.retain(|_, block| block.height() >= min_height);

        // Count-bounded backstop: if the height window left more than the cap
        // (single-height view churn), drop the lowest-view entries until under
        // it. We never evict the freshest views — sorting by view ascending
        // evicts the stale competing proposals first.
        evict_excess_blocks_by_view(&self.blocks, BLOCK_CACHE_MAX_ENTRIES);

        let blocks_after = self.blocks.len();

        if blocks_before != blocks_after {
            tracing::debug!(
                evicted = blocks_before - blocks_after,
                retained = blocks_after,
                min_height = %min_height,
                "Evicted old blocks from consensus cache"
            );
        }

        // Mirror the eviction into the fork-choice index so it doesn't
        // hold references to blocks below the safe-to-evict watermark.
        // ForkChoice's `prune_below_finalized` reads finalized_height
        // from the FinalityTracker we share with it, so the prune
        // boundary stays consistent across the two structures.
        self.fork_choice.prune_below_finalized();
        self.finality_tracker.prune_blocks_below(min_height);

        if let Some(collector) = self.vote_collector.read().as_ref() {
            let min_view = new_view.saturating_sub(VOTE_CACHE_VIEW_WINDOW);
            collector.cleanup_old_votes(min_view);
        }

        // Prune the receiver-side proposal-dedup set the same way as
        // vote/timeout caches. Keep the last `VOTE_CACHE_VIEW_WINDOW`
        // views' worth of proposal-id sentinels so late-arriving gossip
        // replays can still be deduplicated. Anything older is dead
        // weight and gets evicted.
        {
            let min_view = new_view.saturating_sub(VOTE_CACHE_VIEW_WINDOW);
            self.proposal_dedup
                .retain(|(view, _hash), _| *view >= min_view);
        }

        // Drop the TimeoutCollector's per-view caches for views that can no
        // longer be useful. New TC formation is only meaningful at view ≥
        // current view; everything below the cleanup window is dead weight.
        if let Some(tc_collector) = self.timeout_collector.read().as_ref() {
            let min_view = new_view.saturating_sub(VOTE_CACHE_VIEW_WINDOW);
            tc_collector.cleanup_below(min_view);
        }

        // Same cleanup discipline for the NEC collector.
        if let Some(nec_collector) = self.nec_collector.read().as_ref() {
            let min_view = new_view.saturating_sub(VOTE_CACHE_VIEW_WINDOW);
            nec_collector.cleanup_below(min_view);
        }

        // If our last_round_tc is for a view older than the new local view
        // it can never be attached to a future proposal — drop it. We keep
        // it if it's at-or-above the new view so the next leader has it.
        {
            let mut maybe_tc = self.last_round_tc.write();
            if let Some(tc) = maybe_tc.as_ref()
                && tc.view + 1 < new_view
            {
                *maybe_tc = None;
            }
        }

        // Same discipline for the NEC: a NEC for view v authorises a fresh
        // proposal at view v+1. If new_view > v+1 the NEC is no longer
        // attachable.
        {
            let mut maybe_nec = self.last_round_nec.write();
            if let Some(nec) = maybe_nec.as_ref()
                && nec.view + 1 < new_view
            {
                *maybe_nec = None;
            }
        }

        Ok(())
    }

    /// Checks if the current view has timed out
    fn check_view_timeout(&self) -> bool {
        let state = self.view_state.read();
        let timer = self.view_timer.read();
        let time_in_view = state.time_in_view();

        time_in_view >= timer.current_timeout()
    }

    /// Handles view timeout.
    ///
    /// Per the standard `process_local_timeout` rule, this **must
    /// broadcast** a signed timeout message before advancing locally. The
    /// broadcast is the channel that lets a lagging peer fast-forward to
    /// our view (backward-sync). Silent `view += 1` — the previous
    /// behaviour — is the textbook livelock fault: under partial
    /// synchrony two replicas drift apart by N views and never reconverge,
    /// because the only existing forward-sync channel (`on_proposal`)
    /// requires the lagging proposer to produce a valid proposal at the
    /// higher view, which it cannot do (#164).
    async fn on_view_timeout(&self) -> Result<()> {
        self.view_timeouts_total.fetch_add(1, Ordering::Relaxed);
        let current_view = self.view_state.read().view;
        let (timeout_ms, prior_consecutive) = {
            let timer = self.view_timer.read();
            (
                timer.current_timeout().as_millis(),
                timer.consecutive_timeouts,
            )
        };

        // Tiered logging: an isolated timeout is normal pacemaker behaviour
        // (leader rotation under jitter) and logs at info; repeated
        // consecutive timeouts indicate the cluster is failing to make
        // progress and escalate to warn.
        if prior_consecutive >= 1 {
            tracing::warn!(
                view = current_view,
                timeout_ms = timeout_ms,
                consecutive = prior_consecutive + 1,
                "Repeated view timeout, broadcasting TimeoutMsg and advancing to next view"
            );
        } else {
            tracing::info!(
                view = current_view,
                timeout_ms = timeout_ms,
                "View timeout, broadcasting TimeoutMsg and advancing to next view"
            );
        }

        // Build & sign a TimeoutMsg for the timing-out view. Best-effort:
        // if signing fails (e.g. crypto subsystem error) we still advance
        // locally — silent advance is the existing pre-#164 behaviour, so
        // the worst case is we degrade to that. We do NOT block the
        // pacemaker on signing.
        match self.create_timeout_msg(current_view) {
            Ok(timeout_msg) => {
                self.send_out(ConsensusOutMessage::Timeout(timeout_msg));
            }
            Err(e) => {
                tracing::warn!(
                    view = current_view,
                    error = %e,
                    "Failed to create TimeoutMsg; advancing view without broadcast"
                );
            }
        }

        // Build & sign a NoEndorsementMsg for the timing-out view. The
        // attestation is "I observed no QC for view current_view - 1" — the
        // f+1 aggregation closes the tail-fork MEV vulnerability (the NEC
        // tail-fork defence). Skipped at view 0 (no predecessor) and the same
        // best-effort posture as the timeout broadcast: signing failure does
        // not block the pacemaker.
        if current_view > 0 {
            match self.create_no_endorsement_msg(current_view) {
                Ok(nec_msg) => {
                    self.send_out(ConsensusOutMessage::NoEndorsement(nec_msg));
                }
                Err(e) => {
                    tracing::warn!(
                        view = current_view,
                        error = %e,
                        "Failed to create NoEndorsementMsg; advancing view without NEC broadcast"
                    );
                }
            }
        }

        // Apply capped exponential backoff
        self.view_timer.write().on_timeout();

        // NOTE: reputation is deliberately NOT recorded here. Local view
        // timeouts are node-local observations (two nodes can disagree on
        // whether view V timed out), so feeding them into LeaderReputation
        // would diverge the histories — and therefore the elected leaders —
        // across the fleet. Failed rounds are instead derived
        // deterministically from committed metadata: every view in the gap
        // between a finalized block and its parent is recorded as a failure
        // in `record_committed_round_metadata`.

        // Advance to next view (which will select a new leader via round-robin)
        self.advance_view().await?;

        Ok(())
    }

    /// Builds and hybrid-signs a [`TimeoutMsg`] for the given view.
    ///
    /// Mirrors the shape of `create_vote` but does **not** consult the
    /// double-sign vote-state store: a TimeoutMsg does not bind to a block,
    /// only to a view, so signing two TimeoutMsgs for the same view is
    /// harmless (both carry identical view bytes; receivers dedupe by
    /// `(voter, view)`).
    fn create_timeout_msg(&self, view: u64) -> Result<crate::timeout::TimeoutMsg> {
        // Carry the highest Prepare-QC view we have observed. Capped at
        // `view - 1`: a replica timing out on view V cannot honestly claim
        // it has observed a QC at V or beyond (it would have advanced past
        // V already). The cap also guarantees `high_qc_view < view` which
        // `TimeoutMsg::verify` enforces — so we never emit a self-rejected
        // message.
        let raw_high_qc = *self.high_qc_view.read();
        let high_qc_view = if view == 0 {
            0
        } else {
            raw_high_qc.min(view - 1)
        };

        // Advertise our finalized height so peers stuck behind a
        // finalization skew (one replica finalized via a Commit QC the
        // others never received) can engage block-sync off our timeout.
        let finalized_height = self.finality_tracker.finalized_height().0;

        let placeholder_sig =
            tenzro_crypto::composite::CompositeSignature::new(Vec::new(), Vec::new());
        let unsigned = crate::timeout::TimeoutMsg::new(
            view,
            high_qc_view,
            finalized_height,
            self.address,
            placeholder_sig,
            self.composite_public_key.clone(),
        );
        let payload = unsigned.signing_payload();

        // Reconstruct the hybrid signer (same pattern as create_vote — the
        // engine's long-lived Arc<MlDsaSigningKey> can't be consumed).
        let keypair_bytes = self.keypair.to_bytes();
        let keypair_copy = KeyPair::from_bytes(self.keypair.key_type(), &keypair_bytes)?;
        let classical = Ed25519SignerImpl::new(keypair_copy)?;
        let pq_seed = self.pq_signing_key.seed_bytes();
        let pq_copy = MlDsaSigningKey::from_seed(pq_seed)?;
        let hybrid = InMemoryHybridSigner::new(Box::new(classical), pq_copy);

        let signature = hybrid.sign(&payload)?;

        Ok(crate::timeout::TimeoutMsg::new(
            view,
            high_qc_view,
            finalized_height,
            self.address,
            signature,
            self.composite_public_key.clone(),
        ))
    }

    /// Handles an inbound [`crate::timeout::TimeoutMsg`] from a peer.
    ///
    /// Three layered effects:
    ///
    /// 1. **Backward view-counter sync.** If
    ///    `msg.view > local_view`, advance our local view to match. The
    ///    cryptographic gate is the hybrid signature on `(view,
    ///    high_qc_view, voter)` — no numeric jump cap is applied, since
    ///    a stuck replica may legitimately need to sync forward by many
    ///    thousands of views and the signature itself is the only
    ///    correctness-relevant authentication. Prevents permanent view
    ///    divergence under partial synchrony.
    /// 2. **Bracha boost / `f+1` amplification**. The aggregator emits
    ///    `BrachaBoost` when the f+1 threshold is crossed for the timing-out
    ///    view. We respond by firing our local view-timer immediately —
    ///    even if our timer has not yet expired — so honest replicas
    ///    converge on the timeout decision in O(network) rather than
    ///    waiting for the full local timeout.
    /// 3. **`2f+1` TimeoutCertificate formation**. When the quorum is
    ///    reached the aggregator emits the formed
    ///    [`crate::timeout::TimeoutCertificate`]. We store it as
    ///    `last_round_tc` so the next leader (us, or the next view's leader
    ///    after view-sync) can attach it to their proposal — which is what
    ///    receivers' `safe_to_extend` predicate requires before voting on
    ///    a non-consecutive view.
    pub async fn on_timeout_msg(&self, msg: &crate::timeout::TimeoutMsg) -> Result<()> {
        // Verify signature + validator binding before trusting the view
        // number. Without this, any peer could spoof a TimeoutMsg from a
        // validator address and drag every replica forward. After this
        // returns Ok, the (view, high_qc_view, voter) triple is hybrid-
        // signature-bound to a registered validator.
        //
        // Per the standard `process_remote_timeout` rule, the cryptographic
        // gate is the signature itself — no numeric jump cap is applied. A
        // malicious validator's "I timed out at view N" message costs them
        // a publicly verifiable signature; they cannot drag the protocol
        // past their own observed state without producing one. Stuck
        // replicas may legitimately need to sync forward by tens of
        // thousands of views, and the signature is the only correctness-
        // relevant authentication needed to do so safely.
        let validator_set = self.validator_set();
        msg.verify(&validator_set)?;

        // Finalization-skew heal: if the (signature-verified) sender
        // advertises a finalized height above ours, we may have missed a
        // Commit QC broadcast — the sender finalized a block we never did,
        // and the proposer keeps re-proposing a conflicting block at that
        // height which the sender rejects, deadlocking the view forever.
        // Fire the behind-hint so block-sync fetches the block (its Commit
        // QC is embedded in `consensus_proof.proof_data` and verified
        // cryptographically on import — a Byzantine lie here just triggers
        // a futile, bounded sync probe).
        let local_finalized = self.finality_tracker.finalized_height().0;
        if msg.finalized_height > local_finalized {
            tracing::info!(
                voter = %msg.voter,
                peer_finalized = msg.finalized_height,
                local_finalized = local_finalized,
                "TimeoutMsg advertises higher finalized height — engaging block-sync hint"
            );
            self.behind_hint_tx.send_replace(msg.finalized_height);
        }

        let local_view = self.view_state.read().view;

        // Aggregate into the per-view collector. We aggregate timeouts at
        // the local view *and* at views ahead of us — TC formation at a
        // future view is what lets us produce a safe extension once we
        // catch up.
        let collect_outcome = {
            let guard = self.timeout_collector.read();
            guard.as_ref().map(|collector| collector.add(msg))
        };

        if let Some(outcome) = collect_outcome {
            use crate::timeout::CollectOutcome;
            match outcome {
                CollectOutcome::Added | CollectOutcome::Duplicate => {}
                CollectOutcome::BrachaBoost => {
                    // f+1 honest replicas have timed out on this view —
                    // amplify by treating this as if our own local timer had
                    // expired. This is the Bracha-boost
                    // `process_remote_timeout` path that drives all honest
                    // replicas to converge on the timeout decision in
                    // network-delay time.
                    tracing::warn!(
                        view = msg.view,
                        local_view = local_view,
                        voter = %msg.voter,
                        "Bracha boost: f+1 TimeoutMsgs at view {} — amplifying to local timeout",
                        msg.view
                    );
                    if msg.view >= local_view {
                        // Only amplify if the boosted view is at least our
                        // current view. A boost at a view we've already
                        // passed is irrelevant (we're already ahead).
                        if let Err(e) = self.on_view_timeout().await {
                            tracing::error!(
                                error = %e,
                                "Bracha-boosted local timeout failed"
                            );
                        }
                    }
                }
                CollectOutcome::CertificateFormed(tc) => {
                    tracing::info!(
                        view = tc.view,
                        signers = tc.signers.len(),
                        max_high_qc_view = tc.max_high_qc_view(),
                        "TimeoutCertificate formed for view {}",
                        tc.view
                    );
                    // Store as last_round_tc, replacing any older TC. The
                    // next proposer attaches this to their proposal; the
                    // safe_to_extend predicate at receivers verifies it.
                    let mut slot = self.last_round_tc.write();
                    let should_update = match slot.as_ref() {
                        Some(existing) => tc.view > existing.view,
                        None => true,
                    };
                    if should_update {
                        *slot = Some(tc);
                    }
                }
            }
        }

        // Adopt the TimeoutMsg's high_qc_view as a SyncInfo signal — the
        // signer has seen a Prepare QC at view `msg.high_qc_view`, which
        // is itself a 2f+1 aggregate. Any local view ≤ `high_qc_view` is
        // provably behind. The pacemaker target is `max(msg.view,
        // msg.high_qc_view + 1)` — both are valid evidence of ahead-state.
        {
            let mut hqc = self.high_qc_view.write();
            if msg.high_qc_view > *hqc {
                *hqc = msg.high_qc_view;
            }
        }

        // Backward view-counter sync. Re-check the local view after
        // aggregation in case the Bracha boost above already advanced us.
        let post_agg_local_view = self.view_state.read().view;

        // Pacemaker target combines two SyncInfo channels:
        //   - msg.view: the peer is timing out at this view → engine
        //     must be at least at msg.view to participate.
        //   - msg.high_qc_view + 1: 2f+1 cert evidence; next legal
        //     proposal is at msg.high_qc_view + 1.
        let target = std::cmp::max(msg.view, msg.high_qc_view.saturating_add(1));

        if target <= post_agg_local_view {
            // Stale or equal after aggregation. We never *rewind* on a
            // peer's timeout (that would be a liveness regression and a
            // downgrade attack).
            tracing::trace!(
                msg_view = msg.view,
                msg_high_qc_view = msg.high_qc_view,
                local_view = post_agg_local_view,
                voter = %msg.voter,
                "TimeoutMsg target view ≤ local view after aggregation — no sync needed"
            );
            return Ok(());
        }

        // Advance our local view to the SyncInfo target. Mirror the
        // structure of `on_proposal`'s forward-sync block: re-check
        // under the write lock in case another task already advanced
        // us, and reset all per-view state so the next proposal
        // arriving for `target` doesn't see stale prepare/commit QCs
        // from a previous view.
        let mut state = self.view_state.write();
        if target > state.view {
            tracing::info!(
                from_view = state.view,
                to_view = target,
                msg_view = msg.view,
                msg_high_qc_view = msg.high_qc_view,
                height = %state.height,
                voter = %msg.voter,
                "View sync: advancing local view to match peer TimeoutMsg SyncInfo"
            );
            state.view = target;
            state.phase = Phase::Prepare;
            state.proposed_block = None;
            state.prepare_qc = None;
            state.commit_qc = None;
            state.reset_timer();
        }
        Ok(())
    }

    /// Builds and hybrid-signs a [`crate::timeout::NoEndorsementMsg`] for the
    /// given view. The attestation is "I observed no QC for view v - 1".
    ///
    /// Mirrors `create_timeout_msg` but with the NEC-specific signing
    /// payload (`TENZRO_NO_ENDORSEMENT:`-tagged, no `high_qc_view`).
    fn create_no_endorsement_msg(&self, view: u64) -> Result<crate::timeout::NoEndorsementMsg> {
        let placeholder_sig =
            tenzro_crypto::composite::CompositeSignature::new(Vec::new(), Vec::new());
        let unsigned = crate::timeout::NoEndorsementMsg::new(
            view,
            self.address,
            placeholder_sig,
            self.composite_public_key.clone(),
        );
        let payload = unsigned.signing_payload();

        let keypair_bytes = self.keypair.to_bytes();
        let keypair_copy = KeyPair::from_bytes(self.keypair.key_type(), &keypair_bytes)?;
        let classical = Ed25519SignerImpl::new(keypair_copy)?;
        let pq_seed = self.pq_signing_key.seed_bytes();
        let pq_copy = MlDsaSigningKey::from_seed(pq_seed)?;
        let hybrid = InMemoryHybridSigner::new(Box::new(classical), pq_copy);

        let signature = hybrid.sign(&payload)?;

        Ok(crate::timeout::NoEndorsementMsg::new(
            view,
            self.address,
            signature,
            self.composite_public_key.clone(),
        ))
    }

    /// Handles an inbound [`crate::timeout::NoEndorsementMsg`] from a peer.
    ///
    /// Verifies the message, then aggregates it into the per-view NEC
    /// collector. When f+1 attestations at the same view aggregate, the
    /// collector emits a [`crate::timeout::NoEndorsementCertificate`] which
    /// we store as `last_round_nec` so the next leader can attach it to a
    /// fresh proposal at view+1 (the NEC tail-fork defence).
    ///
    /// Unlike `on_timeout_msg`, this method does NOT advance the local view —
    /// the NEC is purely a certificate-formation channel; view-sync remains
    /// the responsibility of the TimeoutMsg path.
    pub async fn on_no_endorsement_msg(
        &self,
        msg: &crate::timeout::NoEndorsementMsg,
    ) -> Result<()> {
        let validator_set = self.validator_set();
        msg.verify(&validator_set)?;

        let collect_outcome = {
            let guard = self.nec_collector.read();
            guard.as_ref().map(|collector| collector.add(msg))
        };

        if let Some(outcome) = collect_outcome {
            use crate::timeout::NecCollectOutcome;
            match outcome {
                NecCollectOutcome::Added | NecCollectOutcome::Duplicate => {}
                NecCollectOutcome::CertificateFormed(nec) => {
                    tracing::info!(
                        view = nec.view,
                        signers = nec.signers.len(),
                        "NoEndorsementCertificate formed for view {}",
                        nec.view
                    );
                    let mut slot = self.last_round_nec.write();
                    let should_update = match slot.as_ref() {
                        Some(existing) => nec.view > existing.view,
                        None => true,
                    };
                    if should_update {
                        *slot = Some(nec);
                    }
                }
            }
        }

        Ok(())
    }

    /// Creates a vote for a block.
    ///
    /// Hybrid path: rebuilds an `InMemoryHybridSigner` from this
    /// node's classical keypair and ML-DSA-65 signing key, signs the canonical
    /// vote payload with both legs, and embeds the composite public key into
    /// the resulting `Vote` so receiving validators can bind it against the
    /// registered hybrid key.
    ///
    /// # Double-sign protection
    ///
    /// Before signing, consults `vote_state_store` (the persistent
    /// last-sign-state pattern):
    /// - If `(view, height, step)` is strictly past the last persisted tuple,
    ///   sign and **persist with fsync before returning** so the broadcast
    ///   downstream of this function can never reveal a vote that wasn't
    ///   durably recorded.
    /// - If `(view, height, step)` matches the last persisted tuple AND the
    ///   block hash matches, return the previously-persisted signature
    ///   verbatim (idempotent retry).
    /// - Otherwise (same tuple, different hash, or earlier tuple) refuse with
    ///   `ConsensusError::Equivocation` — a self-detected double-sign attempt.
    fn create_vote(&self, block: &Block, vote_type: VoteType) -> Result<Vote> {
        let (view, height) = {
            let state = self.view_state.read();
            (state.view, state.height)
        };
        let block_hash = block.hash();
        let step = VoteStep::from_vote_type(vote_type);

        // SyncInfo piggyback (#171): every vote carries the highest Prepare-QC
        // view this replica has observed, capped at `view - 1` (a vote at view
        // V cannot honestly claim a Prepare-QC at view ≥ V — `add_vote`
        // enforces this on the receiver). Genesis case (view = 0) carries 0.
        let high_qc_view = {
            let raw = *self.high_qc_view.read();
            if view == 0 { 0 } else { raw.min(view - 1) }
        };

        // Step 1: Consult persistent vote state. If we already signed this
        // exact (view, height, step, hash), reuse the persisted signature.
        // If we signed a *different* hash for the same (view, height, step),
        // refuse — this would be self-equivocation.
        let decision = self
            .vote_state_store
            .check_vrs(view, height.0, step, &block_hash)?;

        match decision {
            VrsDecision::Reject { reason } => {
                tracing::error!(
                    view = view,
                    height = %height,
                    step = ?step,
                    block_hash = %block_hash,
                    reason = %reason,
                    "DOUBLE-SIGN PREVENTED: refusing to vote — would equivocate"
                );
                return Err(ConsensusError::Equivocation {
                    validator: self.address.to_string(),
                    view,
                });
            }
            VrsDecision::Reuse {
                signature: sig_bytes,
            } => {
                // Idempotent retry — reconstruct the Vote from persisted
                // signature bytes. Wire format is `CompositeSignature` JSON.
                let signature: tenzro_crypto::composite::CompositeSignature =
                    serde_json::from_slice(&sig_bytes).map_err(|e| {
                        ConsensusError::Internal(format!(
                            "vote_state_store: corrupt persisted signature: {}",
                            e
                        ))
                    })?;
                tracing::info!(
                    view = view,
                    height = %height,
                    step = ?step,
                    block_hash = %block_hash,
                    "Idempotent vote retry — reusing persisted signature"
                );
                // BLS is deterministic over (signing_key, message), so
                // re-signing the BLS leg here is equivalent to persisting
                // and replaying it — the wire bytes are byte-identical.
                // We rebuild the Vote with a placeholder BLS sig first to
                // construct the canonical bls payload, then replace.
                let placeholder_bls = self.bls_signing_key.sign(b"__placeholder__");
                let mut reused = Vote::new(
                    view,
                    height,
                    block_hash,
                    self.address,
                    signature,
                    self.composite_public_key.clone(),
                    placeholder_bls,
                    vote_type,
                    high_qc_view,
                );
                let bls_payload = crate::voter::bls_payload_for_vote(&reused);
                reused.bls_signature = self.bls_signing_key.sign(&bls_payload);
                return Ok(reused);
            }
            VrsDecision::Sign => {
                // Fall through to sign + persist + return.
            }
        }

        // Step 2: Build the unsigned vote (placeholder signature) so we can
        // compute the canonical signing payload — this MUST match what
        // VoteCollector::add_vote feeds to StandardHybridVerifier.
        let placeholder_sig =
            tenzro_crypto::composite::CompositeSignature::new(Vec::new(), Vec::new());
        let placeholder_bls = self.bls_signing_key.sign(b"__placeholder__");
        let unsigned_vote = Vote::new(
            view,
            height,
            block_hash,
            self.address,
            placeholder_sig,
            self.composite_public_key.clone(),
            placeholder_bls,
            vote_type,
            high_qc_view,
        );
        let payload = unsigned_vote.signing_payload();

        // Step 3: Reconstruct the hybrid signer for this call. The classical
        // keypair is rebuilt from bytes (KeyPair is not Clone) and paired
        // with a fresh signing-key view rebuilt from the persisted seed so
        // that the engine's long-lived `Arc<MlDsaSigningKey>` is not
        // consumed.
        let keypair_bytes = self.keypair.to_bytes();
        let keypair_copy = KeyPair::from_bytes(self.keypair.key_type(), &keypair_bytes)?;
        let classical = Ed25519SignerImpl::new(keypair_copy)?;
        let pq_seed = self.pq_signing_key.seed_bytes();
        let pq_copy = MlDsaSigningKey::from_seed(pq_seed)?;
        let hybrid = InMemoryHybridSigner::new(Box::new(classical), pq_copy);

        let signature = hybrid.sign(&payload)?;

        // Step 4: Persist the new sign-state with fsync BEFORE returning the
        // signed vote. This is the critical ordering: if a crash happens
        // between sign and persist, on restart we'll re-sign — but since the
        // old signature never durably escaped, that's safe. If we persisted
        // *after* broadcast, a crash in that window would let us re-sign a
        // different block in the same view on restart, which is the textbook
        // self-equivocation that triggered the cascade.
        let sig_bytes = serde_json::to_vec(&signature).map_err(|e| {
            ConsensusError::Internal(format!(
                "vote_state_store: serialize composite signature: {}",
                e
            ))
        })?;
        let new_state = LastSignState {
            version: 1,
            view,
            height: height.0,
            step,
            block_hash: Some(block_hash),
            signature: Some(sig_bytes),
        };
        self.vote_state_store.record(&new_state)?;

        // Step 5: BLS-sign the canonical QC payload (per
        // `bls_payload_for_vote`). BLS is deterministic over (sk, message)
        // so this is safe to compute after the hybrid persist — equivocation
        // is governed by the hybrid persist gate above; the BLS leg is
        // re-derivable on a clean retry.
        let placeholder_bls_final = self.bls_signing_key.sign(b"__placeholder__");
        let mut signed_vote = Vote::new(
            view,
            height,
            block_hash,
            self.address,
            signature,
            self.composite_public_key.clone(),
            placeholder_bls_final,
            vote_type,
            high_qc_view,
        );
        let bls_payload = crate::voter::bls_payload_for_vote(&signed_vote);
        signed_vote.bls_signature = self.bls_signing_key.sign(&bls_payload);
        Ok(signed_vote)
    }

    /// Handles the prepare phase
    async fn handle_prepare_phase(&self, block: &Block) -> Result<Option<QuorumCertificate>> {
        // Validate the proposal
        let expected_height = self.view_state.read().height;
        self.proposer.validate_proposal(block, expected_height)?;

        // EIP-1559 consensus rule: re-derive the expected base fee
        // from the parent block and reject if the proposer's stamped
        // value diverges. Mirrors go-ethereum
        // `consensus/misc/eip1559.VerifyEIP1559Header`. This MUST run
        // before signing the prepare vote — otherwise a malicious
        // proposer could pick an arbitrary base fee.
        let parent_height = block.header.height - 1u64;
        let parent_block = self
            .finality_tracker
            .get_finalized_block(parent_height)
            .or_else(|| {
                self.block_provider
                    .as_ref()
                    .and_then(|p| p.get_block(parent_height))
            });
        match parent_block {
            Some(parent) => {
                self.proposer.validate_base_fee(block, &parent)?;
            }
            None => {
                // Parent unavailable — refuse to vote rather than
                // rubber-stamping an unverifiable proposal.
                return Err(crate::error::ConsensusError::InvalidProposal(format!(
                    "Cannot validate base fee for block at height {}: parent at height {} is unavailable",
                    block.header.height, parent_height
                )));
            }
        }

        // Create and add vote
        let vote = self.create_vote(block, VoteType::Prepare)?;
        self.send_out(ConsensusOutMessage::Vote(vote.clone()));

        // Add to vote collector
        let vote_collector = self.vote_collector.read();
        if let Some(collector) = vote_collector.as_ref() {
            let qc = collector.add_vote(vote)?;

            if let Some(qc) = qc.clone() {
                // We have a prepare QC, advance to commit phase
                let mut state = self.view_state.write();
                state.phase = Phase::Commit;
                state.prepare_qc = Some(qc.clone());
                // Track the highest prepare QC view we've witnessed — used as the
                // `high_qc_view` field of any future TimeoutMsg, so the resulting
                // TC's `max_high_qc_view()` lets the next leader compute a
                // safe-to-extend predicate.
                let qc_view = state.view;

                tracing::info!(
                    view = state.view,
                    height = %state.height,
                    "Prepare phase completed, advancing to commit"
                );
                drop(state);

                let mut hqc = self.high_qc_view.write();
                if qc_view > *hqc {
                    *hqc = qc_view;
                }
            }

            Ok(qc)
        } else {
            Err(ConsensusError::Internal(
                "Vote collector not initialized".to_string(),
            ))
        }
    }

    /// Handles the commit phase
    async fn handle_commit_phase(&self, block: &Block) -> Result<Option<QuorumCertificate>> {
        let state = self.view_state.read();

        // Ensure we have a prepare QC
        if state.prepare_qc.is_none() {
            return Err(ConsensusError::InvalidProposal(
                "No prepare QC for commit phase".to_string(),
            ));
        }

        drop(state);

        // Create and add commit vote
        let vote = self.create_vote(block, VoteType::Commit)?;
        self.send_out(ConsensusOutMessage::Vote(vote.clone()));

        // FIX: Scope the read lock to JUST the add_vote call, then drop it before
        // the epoch transition which calls vote_collector.write(). Holding the read
        // lock through the epoch transition caused a parking_lot::RwLock deadlock
        // every time the chain reached the epoch boundary (block 9,999 → height 10,000).
        let qc = {
            let vote_collector = self.vote_collector.read();
            if let Some(collector) = vote_collector.as_ref() {
                collector.add_vote(vote)?
            } else {
                return Err(ConsensusError::Internal(
                    "Vote collector not initialized".to_string(),
                ));
            }
        }; // vote_collector read lock DROPPED HERE

        if let Some(qc) = qc.clone() {
            // We have a commit QC, finalize the block
            let mut state = self.view_state.write();
            state.phase = Phase::Decide;
            state.commit_qc = Some(qc.clone());

            tracing::info!(
                view = state.view,
                height = %state.height,
                "Commit phase completed, finalizing block"
            );

            // Finalize the block.
            // If finalization fails due to a height mismatch (e.g. after a restart
            // where the finality tracker is ahead of view state), re-sync state.height
            // to match what the finality tracker expects and return without propagating
            // the error — the next proposal will be at the correct height.
            if let Err(e) = self
                .finality_tracker
                .finalize_block(block.clone(), qc.clone())
            {
                let corrected_height = self.finality_tracker.finalized_height() + 1u64;
                tracing::warn!(
                    error = %e,
                    stale_height = %state.height,
                    corrected_height = %corrected_height,
                    "Finalization failed — re-syncing height to finality tracker"
                );
                state.height = corrected_height;
                state.phase = Phase::Prepare;
                state.proposed_block = None;
                state.prepare_qc = None;
                state.commit_qc = None;
                state.reset_timer();
                drop(state);
                return Ok(None);
            }

            // Reset timeout on successful finalization, feeding the
            // observed view-to-QC latency into the adaptive base-timeout
            // tuner. This lets the cluster's `view_timeout_ms` track
            // whatever cross-region topology actually exists, without
            // any hardcoded default. See `ViewChangeTimer::record_observed_view_latency`.
            let observed_view_latency = state.time_in_view();
            self.view_timer
                .write()
                .on_success(Some(observed_view_latency));

            // Advance height for next block
            state.height = state.height + 1u64;
            state.view += 1;
            state.phase = Phase::Prepare;
            state.proposed_block = None;
            state.prepare_qc = None;
            state.commit_qc = None;
            state.reset_timer();

            // Remove finalized transactions from mempool
            let tx_hashes: Vec<Hash> = block
                .transactions
                .iter()
                .map(|tx| tx.transaction.hash())
                .collect();
            self.mempool.remove_transactions(&tx_hashes);

            // Capture transition height before dropping state write lock
            let transition_height = state.height;
            drop(state);

            // Feed LeaderReputation from committed metadata only — same
            // helper as finalize_with_commit_qc, so leader and followers
            // record identical histories.
            self.record_committed_round_metadata(block, &qc);

            // Check for epoch transition — SAFE: no vote_collector read lock held here
            self.transition_epoch_if_due(transition_height)?;
        }

        Ok(qc)
    }

    /// Transitions the epoch at `height` when due and rebuilds the per-epoch
    /// collectors against the new validator set. Returns `Ok(true)` when a
    /// transition fired, `Ok(false)` when the height is not a boundary.
    ///
    /// Called from both live paths (DECIDE finalization, finalize-on-commit-QC)
    /// and the block-sync import path — a node importing finalized blocks
    /// across an epoch boundary must cross it exactly like a live node did, so
    /// that `validator_set_for_height` resolves for post-boundary blocks and
    /// QC verification runs against the same set.
    ///
    /// Callers must NOT hold the `vote_collector` / `timeout_collector` /
    /// `nec_collector` locks.
    pub fn transition_epoch_if_due(&self, height: BlockHeight) -> Result<bool> {
        if !self.epoch_manager.should_transition(height) {
            return Ok(false);
        }

        // The due-check inside transition_epoch runs under the epoch write
        // lock — if a concurrent caller (engine finalize path vs. node
        // follower path) won the race, we get Ok(None) and report no-op.
        //
        // The anchor closure resolves the finalized hash at the new epoch's
        // canonical boundary (in-memory tracker first, durable BlockProvider
        // fallback for post-restart / catch-up walks) so every node seeds
        // leader election identically for the whole epoch.
        let anchor_of = |boundary: BlockHeight| -> Option<Hash> {
            self.finality_tracker
                .get_finalized_hash(boundary)
                .or_else(|| {
                    self.block_provider
                        .as_ref()
                        .and_then(|p| p.get_block(boundary))
                        .map(|b| b.hash())
                })
        };
        if self
            .epoch_manager
            .transition_epoch(height, anchor_of)?
            .is_none()
        {
            return Ok(false);
        }
        tracing::info!(height = %height, "Epoch transition triggered");

        // Update collectors with the new validator set. The equivocation
        // detector is the engine's long-lived instance — rebuilding the
        // collector must not reset conviction state.
        let new_validator_set = Arc::new(self.validator_set());
        *self.vote_collector.write() = Some(Arc::new(VoteCollector::with_detector(
            new_validator_set.clone(),
            self.equivocation_detector.clone(),
        )));
        *self.timeout_collector.write() = Some(Arc::new(crate::timeout::TimeoutCollector::new(
            new_validator_set.clone(),
        )));
        *self.nec_collector.write() = Some(Arc::new(crate::timeout::NoEndorsementCollector::new(
            new_validator_set,
        )));

        Ok(true)
    }

    /// Main consensus loop
    async fn consensus_loop(&self) -> Result<()> {
        let mut shutdown_rx = {
            let shutdown_tx = self.shutdown_tx.read();
            match shutdown_tx.as_ref() {
                Some(tx) => tx.subscribe(),
                None => {
                    tracing::error!("Consensus loop started without shutdown channel wired");
                    return Err(ConsensusError::NotStarted);
                }
            }
        };

        // Check interval for view timeout (100ms)
        let check_interval = Duration::from_millis(100);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Consensus loop shutting down");
                    break;
                }
                _ = sleep(check_interval) => {
                    // Check for view timeout
                    if self.check_view_timeout()
                        && let Err(e) = self.on_view_timeout().await
                    {
                        tracing::error!(error = %e, "View timeout handling failed");
                    }

                    // Run consensus step
                    if let Err(e) = self.run_consensus_step().await {
                        tracing::error!(error = %e, "Consensus step failed");
                    }
                }
            }
        }

        Ok(())
    }

    /// Runs a single consensus step
    async fn run_consensus_step(&self) -> Result<()> {
        let is_leader = self.is_leader().await;
        let state = self.view_state.read().clone();

        match state.phase {
            Phase::Prepare => {
                // While draining (graceful rollout) a leader skips proposing a
                // fresh block but still votes and re-broadcasts any block it
                // already proposed, so finality of in-flight work is unaffected.
                if is_leader && !self.is_draining() {
                    // Leader proposes a block
                    if state.proposed_block.is_none() {
                        // EMPTY-BLOCK SUPPRESSION (the standard
                        // `create_empty_blocks=false` pattern adapted for HotStuff-2):
                        // on an idle chain, don't mint a fresh empty block on
                        // every pacemaker beat — that accreted ~216k
                        // never-pruned empty headers/day of SST. Hold the view
                        // in Prepare (still voting, still timing out) until we
                        // either have transactions to commit OR the heartbeat
                        // interval elapses. Liveness is unaffected: the
                        // pacemaker's timeout-driven view change runs
                        // independently, so a genuinely dead leader is still
                        // detected. The heartbeat block refreshes the tip's
                        // timestamp/state-root and gives peers a positive
                        // "leader alive" signal. We only gate FRESH proposals;
                        // a TC-recovery repropose (handled inside
                        // `propose_block_internal`) must never be suppressed,
                        // but that path is reached via the same proposal-guard
                        // below and short-circuits before this check matters
                        // because `last_round_tc` is set.
                        if !self.should_propose_now() {
                            tracing::trace!(
                                view = state.view,
                                height = %state.height,
                                "empty-block suppression: idle + within heartbeat window, deferring proposal"
                            );
                            return Ok(());
                        }
                        // PROPOSAL-GUARD (HotStuff-family invariant): atomically
                        // claim the current view as the "I am proposing for
                        // view V" slot before we await the block builder. If
                        // we already proposed for V (or any view ≥ V), bail.
                        // Without this, the await on `propose_block_internal`
                        // is a re-entrancy window: a Bracha-boost amplifying
                        // to `on_view_timeout` can advance the view and the
                        // next tick re-enters this branch, both ending up
                        // calling `propose_block_internal` for the same
                        // height with different mempool snapshots → two
                        // different block hashes → self-equivocation. We use
                        // `fetch_max` for the lock: it returns the previous
                        // max; if `prev >= view` we already proposed for
                        // this view (or a later one) and must NOT re-emit.
                        let view_at_entry = state.view;
                        let prev_proposed = self
                            .last_proposed_view
                            .fetch_max(view_at_entry, Ordering::SeqCst);
                        if prev_proposed >= view_at_entry && view_at_entry != 0 {
                            tracing::debug!(
                                view = view_at_entry,
                                last_proposed_view = prev_proposed,
                                "proposal-guard: already proposed for this view; skipping re-entrant propose"
                            );
                            return Ok(());
                        }
                        drop(state);
                        // G6 availability-dissemination beat: the leader (which
                        // has just won the proposal-guard for this view) snapshots
                        // the mempool into a batch, stores it, self-acks, and
                        // disseminates it over `tenzro/batches` so peers can attest
                        // availability. This runs ahead of ordering: the batch's
                        // 2f+1 availability certificate is what the ordering path
                        // later references by hash (via `agree_prefix`), decoupling
                        // data bandwidth from ordering bandwidth. No-op when no
                        // batch-cert store is installed or the mempool is empty.
                        let _ = self.produce_batch();
                        let block = self.propose_block_internal().await?;
                        // Late-check: by the time the block is built, the
                        // pacemaker may have advanced past the view we
                        // committed to. Don't broadcast a stale-view
                        // proposal — it can't be safely voted on by peers
                        // (the inner `block.header.view` is now < current
                        // view) and broadcasting it conflicts with the
                        // proposal we'll emit for the new view.
                        {
                            let current_view = self.view_state.read().view;
                            if current_view != view_at_entry {
                                tracing::warn!(
                                    view_at_entry = view_at_entry,
                                    current_view = current_view,
                                    "proposal-guard: view advanced during block build; discarding stale proposal"
                                );
                                return Ok(());
                            }
                        }
                        // Atomic check-and-set: only the FIRST winner of
                        // the (view, propose) slot mutates `proposed_block`.
                        // A concurrent re-entry (which we've already
                        // returned from above) cannot reach this line, so
                        // this write is the unique propose-record for the
                        // view.
                        self.view_state.write().proposed_block = Some(block.clone());

                        // Broadcast proposal to all peers so they can vote on it.
                        // If we just recovered from a view timeout, attach the
                        // TC we collected so peers can verify the previous view
                        // was abandoned (the safe_to_extend predicate).
                        let view = self.view_state.read().view;
                        let timeout_certificate = self.last_round_tc.read().clone();
                        // NEC tail-fork defence: when proposing a
                        // fresh block after a TC, attach the f+1 NEC we
                        // collected so peers can verify no Prepare-QC formed at
                        // the timed-out view. When reproposing the high_tip
                        // (because a QC was observed), the NEC is omitted —
                        // `propose_block_internal` returns the existing high_tip
                        // block in that case, and `on_proposal` recognises the
                        // hash match to skip the NEC requirement.
                        let no_endorsement_certificate = {
                            let is_repropose = timeout_certificate.as_ref().is_some_and(|tc| {
                                self.fork_choice
                                    .select_best_block(block.header.height)
                                    .map(|b| b.hash() == block.hash())
                                    .unwrap_or(false)
                                    && *self.high_qc_view.read() >= tc.view
                            });
                            if timeout_certificate.is_some() && !is_repropose {
                                self.last_round_nec.read().clone()
                            } else {
                                None
                            }
                        };
                        // SyncInfo (#171): leader piggybacks its current
                        // high_qc_view, capped at `view - 1` (genesis = 0).
                        let high_qc_view = {
                            let raw = *self.high_qc_view.read();
                            if view == 0 { 0 } else { raw.min(view - 1) }
                        };
                        // Sign the canonical proposal payload with the hybrid
                        // (Ed25519 + ML-DSA-65) key. Binding `high_qc_view`
                        // into the payload authenticates the SyncInfo hint,
                        // and the signature makes the proposal attributable
                        // for proposal-equivocation slashing.
                        let proposer_signature = {
                            let payload = crate::validator::proposal_signing_payload(
                                view,
                                block.header.height.0,
                                &block.hash(),
                                high_qc_view,
                            );
                            let keypair_bytes = self.keypair.to_bytes();
                            let keypair_copy =
                                KeyPair::from_bytes(self.keypair.key_type(), &keypair_bytes)?;
                            let classical = Ed25519SignerImpl::new(keypair_copy)?;
                            let pq_seed = self.pq_signing_key.seed_bytes();
                            let pq_copy = MlDsaSigningKey::from_seed(pq_seed)?;
                            let hybrid = InMemoryHybridSigner::new(Box::new(classical), pq_copy);
                            hybrid.sign(&payload)?
                        };
                        self.send_out(ConsensusOutMessage::Proposal {
                            block: block.clone(),
                            proposer: self.address,
                            round: view,
                            view,
                            high_qc_view,
                            timeout_certificate,
                            no_endorsement_certificate,
                            proposer_signature,
                        });

                        // Vote on our own proposal
                        let _ = self.handle_prepare_phase(&block).await?;
                    }
                } else {
                    // Non-leader: wait for proposal or timeout
                    // In production, this would receive proposals from the network
                }
            }
            Phase::Commit => {
                if is_leader && let Some(block) = state.proposed_block.clone() {
                    drop(state);
                    let _ = self.handle_commit_phase(&block).await?;
                }
            }
            Phase::Decide => {
                // Block finalized, advance to next view
                drop(state);
                self.advance_view().await?;
            }
        }

        Ok(())
    }

    /// Empty-block suppression predicate. Returns `true` when the leader
    /// should mint a block at the current beat, `false` to defer.
    ///
    /// Propose iff ANY of:
    ///   1. Suppression disabled (`empty_block_heartbeat_ms == 0`) — restore
    ///      always-on production.
    ///   2. Mempool is non-empty — there's real work to commit.
    ///   3. An *unhandled* timeout certificate is pending — a TC whose
    ///      recovery view (`tc.view + 1`) we have NOT already proposed at.
    ///      Such a TC genuinely requires a fresh proposal (repropose the
    ///      high_tip to flush a stranded QC, or attach an NEC), so liveness
    ///      and the QC chain take priority over the empty-header budget.
    ///      Crucially we DON'T bypass for a TC we've already extended past:
    ///      `last_round_tc` is only cleared lazily (when `tc.view + 1 <
    ///      new_view`), so on a chain that times out frequently a stale-but-
    ///      not-yet-pruned TC would otherwise defeat suppression on every
    ///      beat. Gating on `last_proposed_view` (the same monotonic guard
    ///      the proposal-guard uses) closes that hole.
    ///   4. The heartbeat interval has elapsed since the last block — emit a
    ///      keepalive block to refresh the tip and signal leader liveness.
    ///
    /// This is the only gate; the proposal-guard `fetch_max` still enforces
    /// the one-proposal-per-view invariant downstream.
    fn should_propose_now(&self) -> bool {
        if !self.config.suppress_empty_blocks() {
            return true;
        }
        if !self.mempool.is_empty() {
            return true;
        }
        if let Some(tc) = self.last_round_tc.read().as_ref() {
            let recovery_view = tc.view + 1;
            let already_handled = self.last_proposed_view.load(Ordering::SeqCst) >= recovery_view;
            if !already_handled {
                return true;
            }
        }
        let elapsed = self.last_block_time.read().elapsed();
        elapsed >= self.config.empty_block_heartbeat()
    }

    /// Records that a fresh block was proposed, resetting the heartbeat
    /// clock so the next idle keepalive fires one full interval later.
    fn mark_block_proposed(&self) {
        *self.last_block_time.write() = Instant::now();
    }

    /// Internal block proposal (called by consensus loop)
    async fn propose_block_internal(&self) -> Result<Block> {
        let (height, view) = {
            let state = self.view_state.read();
            (state.height, state.view)
        };

        // NEC tail-fork defence:
        // If we're recovering from a view timeout AND we observed a Prepare-QC
        // for the timed-out view (i.e. `high_qc_view >= tc.view`), we MUST
        // repropose the existing high_tip block at our current height — we
        // cannot legally fork it off without producing an NEC, which is
        // impossible in this state (an honest replica that saw the QC will
        // refuse to sign an NEC for that view). Honest leaders therefore
        // repropose; only when no QC was observed do they propose fresh
        // (with an attached NEC, which `run_consensus_step` builds before
        // broadcasting).
        let last_tc = self.last_round_tc.read().clone();
        let high_qc_view_local = *self.high_qc_view.read();
        if let Some(tc) = last_tc.as_ref()
            && high_qc_view_local >= tc.view
            && let Some(high_tip) = self.fork_choice.select_best_block(height)
        {
            tracing::info!(
                height = %height,
                view = %view,
                tc_view = tc.view,
                high_qc_view = high_qc_view_local,
                hash = %high_tip.hash(),
                "Reproposing high_tip after TC (QC observed at timed-out view)"
            );
            // The high_tip block is already in `self.blocks` and `fork_choice`.
            return Ok(high_tip);
        }

        // Parent selection: prefer the fork-choice "highest QC view at
        // parent height" rule. Falls back to the last finalized hash if
        // fork choice has no candidate yet (cold start, post-restart pre-
        // warmup), preserving the previous behaviour as a safety net.
        let parent_height = height - 1u64;
        let prev_hash = self
            .fork_choice
            .select_best_block(parent_height)
            .map(|b| b.hash())
            .or_else(|| self.finality_tracker.get_finalized_hash(parent_height))
            .unwrap_or_default();

        let state_root = self
            .state_root_provider
            .as_ref()
            .map(|p| p.current_state_root())
            .unwrap_or_default();

        // Fetch parent metadata for EIP-1559 base-fee derivation. Try
        // the in-memory finality tracker first (fast path), then fall
        // back to the durable BlockProvider (post-restart path).
        // For the genesis-child case (height=1, parent height=0) this
        // resolves to the genesis block; if not found anywhere we fall
        // back to genesis-edge values which trigger `initial_base_fee`.
        let parent_block = self
            .finality_tracker
            .get_finalized_block(parent_height)
            .or_else(|| {
                self.block_provider
                    .as_ref()
                    .and_then(|p| p.get_block(parent_height))
            });
        let (parent_base_fee, parent_gas_used, parent_gas_limit) = match parent_block {
            Some(b) => (
                b.header.metadata.base_fee_per_gas,
                b.header.metadata.gas_used,
                b.header.metadata.gas_limit,
            ),
            None => {
                tracing::warn!(
                    parent_height = %parent_height,
                    "Parent block unavailable for base-fee derivation; falling back to initial fee"
                );
                (None, 0, 0)
            }
        };

        // G6: when the batch-availability plane is wired and this node holds a
        // certified prefix whose bodies are all locally reconstructable, source
        // the proposal from those certified batches rather than the raw
        // mempool. The transactions were already disseminated + `2f+1`-certified
        // over the availability mesh, so the proposal references a small,
        // already-available set; the block still carries the full ordered
        // transaction list, so execution/storage/RPC read paths are unchanged.
        // Fall back to the mempool path when no store is wired, the certified
        // prefix is empty, or any referenced body is missing locally (a body we
        // cannot reconstruct must not enter a block we propose).
        let batch_sourced = self.batch_cert_store.as_ref().and_then(|store| {
            let prefix = store.certified_prefix();
            if prefix.is_empty() {
                return None;
            }
            let mut txs: Vec<tenzro_types::transaction::SignedTransaction> = Vec::new();
            for batch_id in &prefix {
                let body = store.get_body(batch_id)?;
                txs.extend(body.transactions);
            }
            if txs.is_empty() {
                None
            } else {
                tracing::debug!(
                    batches = prefix.len(),
                    tx_count = txs.len(),
                    "batch_cert: sourcing proposal from certified prefix"
                );
                Some(txs)
            }
        });

        let block = match batch_sourced {
            Some(transactions) => self.proposer.propose_block_from_transactions(
                height,
                view,
                prev_hash,
                self.address,
                state_root,
                parent_base_fee,
                parent_gas_used,
                parent_gas_limit,
                transactions,
            )?,
            None => self.proposer.propose_block(
                height,
                view,
                prev_hash,
                self.address,
                state_root,
                parent_base_fee,
                parent_gas_used,
                parent_gas_limit,
            )?,
        };

        // Validate block size before broadcasting
        self.proposer.validate_block_size(&block)?;

        self.blocks.insert(block.hash(), block.clone());
        // Mirror into fork choice (no QC yet — it'll be recorded by
        // `try_form_qc_and_drive_phase` once 2f+1 votes aggregate).
        self.fork_choice.add_block(block.clone(), None);

        // Reset the heartbeat clock: this is a freshly minted block (the
        // TC-recovery repropose path returns earlier and intentionally does
        // NOT reset, so a stuck-at-height view doesn't keep arming the
        // keepalive). Whether empty or full, a real proposal restarts the
        // idle window.
        self.mark_block_proposed();

        tracing::info!(
            height = %height,
            hash = %block.hash(),
            tx_count = block.tx_count(),
            "Block proposed"
        );

        Ok(block)
    }

    /// Finalizes a block on observation of a Commit QC.
    ///
    /// Replaces the trailing half of the original `handle_commit_phase` so the
    /// finalize logic is reachable from `on_vote` (peer-driven) as well as from
    /// the leader-driven step. Idempotent: if the block has already been
    /// finalized at a lower local height, the FinalityTracker rejects with
    /// `InvalidHeight` and we re-sync state without propagating the error.
    async fn finalize_with_commit_qc(
        &self,
        block: &Block,
        commit_qc: QuorumCertificate,
    ) -> Result<()> {
        // Idempotency guard — if we already finalized this height, skip.
        if self.finality_tracker.finalized_height() >= block.header.height {
            return Ok(());
        }

        // A Commit QC at view V implies a Prepare QC at view V was observed —
        // bump high_qc_view if this is the highest we've seen.
        {
            let mut hqc = self.high_qc_view.write();
            if commit_qc.view > *hqc {
                *hqc = commit_qc.view;
            }
        }

        // Embed the Commit QC into the block's `consensus_proof.proof_data` so
        // it persists alongside the block in storage and is carried over the
        // wire by the block-sync protocol. Without this, QCs live only in
        // memory and are lost on restart, and a syncing peer has no way to
        // verify that a served block was actually finalized.
        //
        // Pattern: HotStuff family (each block carries a `quorum_cert` /
        // `qc` field) — each
        // block carries the QC certifying its parent. Here the block is the
        // newly-finalized block carrying the Commit QC over itself; the next
        // block produced will also point back to this block via `prev_hash`,
        // and the parent's QC chain is reconstructible from each successor's
        // embedded QC.
        //
        // Safety: `BlockHeader::hash()` does NOT cover `consensus_proof`, so
        // populating `proof_data` here does not change the block's hash.
        // Existing on-disk blocks (with empty `proof_data`) keep their
        // identities; new blocks finalized after this point carry verifiable
        // QCs.
        let mut block_with_qc = block.clone();
        match bincode::serialize(&commit_qc) {
            Ok(qc_bytes) => {
                block_with_qc.header.consensus_proof.proof_data = qc_bytes;
            }
            Err(e) => {
                // Serialization of an in-memory QC should never fail; if it
                // somehow does, we still proceed with the empty proof_data
                // path so finalization is not blocked. The receiving side
                // will simply be unable to verify this block via block-sync.
                tracing::error!(
                    error = %e,
                    height = %block.header.height,
                    "Failed to serialize commit QC into block; proceeding without embedded QC"
                );
            }
        }

        let transition_height = {
            let mut state = self.view_state.write();
            state.phase = Phase::Decide;
            state.commit_qc = Some(commit_qc.clone());

            tracing::info!(
                view = state.view,
                height = %state.height,
                block_hash = %block_with_qc.hash(),
                "Commit QC observed — finalizing block"
            );

            // Try to finalize. If the tracker disagrees with our height (rare,
            // happens after a restart where storage tip ≠ view state), re-sync
            // and bail without propagating.
            if let Err(e) = self
                .finality_tracker
                .finalize_block(block_with_qc.clone(), commit_qc.clone())
            {
                let corrected_height = self.finality_tracker.finalized_height() + 1u64;
                tracing::warn!(
                    error = %e,
                    stale_height = %state.height,
                    corrected_height = %corrected_height,
                    "Finalization failed — re-syncing height to finality tracker"
                );
                state.height = corrected_height;
                state.phase = Phase::Prepare;
                state.proposed_block = None;
                state.prepare_qc = None;
                state.commit_qc = None;
                state.reset_timer();
                return Ok(());
            }

            // Feed the observed view latency into the adaptive base-
            // timeout tuner. The base_timeout self-tracks the cluster's
            // empirical quorum-formation latency so an open validator
            // set with heterogeneous topology converges to a stable
            // rate without operator hand-tuning.
            let observed_view_latency = state.time_in_view();
            self.view_timer
                .write()
                .on_success(Some(observed_view_latency));

            // Advance height + view, reset phase
            state.height = state.height + 1u64;
            state.view += 1;
            state.phase = Phase::Prepare;
            state.proposed_block = None;
            state.prepare_qc = None;
            state.commit_qc = None;
            state.reset_timer();
            state.height
        };

        // Reset the empty-block heartbeat clock on every finalization,
        // self- or peer-proposed. This keeps each replica's idle window
        // anchored to the real chain tip, so a freshly-elected leader on an
        // idle chain waits a full heartbeat interval before minting a
        // keepalive instead of firing one the instant it takes the view.
        self.mark_block_proposed();

        // Feed LeaderReputation from committed metadata only — identical
        // inputs on every node (see record_committed_round_metadata).
        self.record_committed_round_metadata(block, &commit_qc);

        // Remove finalized transactions from mempool
        let tx_hashes: Vec<Hash> = block
            .transactions
            .iter()
            .map(|tx| tx.transaction.hash())
            .collect();
        self.mempool.remove_transactions(&tx_hashes);

        // G6: evict availability certificates whose batches are now finalized
        // on-chain. Their bodies no longer need to be held for availability, so
        // the cert/body/pending-acks are dropped (write-through). Certs whose
        // batches are only partially finalized are retained to back a later
        // block. This bounds the certified-prefix window to the unfinalized
        // frontier the ordering path still references by hash.
        if let Some(store) = self.batch_cert_store.as_ref() {
            let finalized: std::collections::HashSet<Hash> = tx_hashes.iter().copied().collect();
            let evicted = store.evict_finalized(&finalized);
            if evicted > 0 {
                tracing::debug!(
                    evicted,
                    "batch_cert: evicted finalized availability certificates"
                );
            }
        }

        // Epoch transition (vote_collector.write() — must not hold view_state lock here)
        self.transition_epoch_if_due(transition_height)?;

        Ok(())
    }

    /// Records leader-reputation metadata for a freshly-finalized block,
    /// derived exclusively from committed data so every node feeds its
    /// reputation history identical inputs (determinism by induction):
    ///
    /// - **Success** for `(block.header.view, block.header.proposer)` —
    ///   the header binds the view at which the block was built, covering
    ///   TC-justified reproposals too (a reproposed high-tip is
    ///   byte-identical, so view/proposer remain the original leader's).
    /// - **Voters** from the finalizing Commit QC.
    /// - **Failures** for every view in the gap between the parent
    ///   block's view and this block's view — those views demonstrably
    ///   produced no finalized block; the elected leader for each is
    ///   re-derived under the epoch's fixed seed anchor.
    ///
    /// Local view timeouts are deliberately NOT recorded — they are
    /// node-local observations that diverge across the fleet, which would
    /// diverge the reputation histories and therefore the elected
    /// leaders. See `on_view_timeout`.
    fn record_committed_round_metadata(&self, block: &Block, commit_qc: &QuorumCertificate) {
        let Some(reputation) = self.reputation.as_ref() else {
            return;
        };

        let view = block.header.view;
        reputation.record_round_outcome(view, block.header.proposer, true);
        // Voters come from the QC's signer bitmap resolved against the
        // validator set active at the block's epoch — committed data only,
        // so every node derives the identical voter list.
        let voter_set = self
            .validator_set_for_height(block.header.height)
            .unwrap_or_else(|| self.validator_set());
        let voters: Vec<Address> = commit_qc.signers(&voter_set);
        reputation.record_round_voters(view, voters);

        // Derive failed rounds from the committed view gap. The parent
        // block comes from the wired BlockProvider (in-memory tracker
        // first, durable storage fallback); when unavailable (genesis,
        // test harnesses without a provider) gap derivation is skipped.
        let height = block.header.height.as_u64();
        if height == 0 {
            return;
        }
        let parent_height = BlockHeight::from(height - 1);
        let Some(parent_view) = self
            .block_provider
            .as_ref()
            .and_then(|bp| bp.get_block(parent_height))
            .map(|parent| parent.header.view)
        else {
            return;
        };
        if parent_view + 1 >= view {
            return;
        }
        let gap_start = (parent_view + 1).max(view.saturating_sub(MAX_DERIVED_GAP_FAILURES));
        for failed_view in gap_start..view {
            // Skip silently when election cannot resolve (e.g. validator
            // unknown for the view) — better to drop one failure record
            // than to crash the finalize path.
            if let Ok(leader) = self.leader_for_view(failed_view) {
                reputation.record_round_outcome(failed_view, leader, false);
            }
        }
    }
}

#[async_trait]
impl ConsensusEngine for HotStuff2Engine {
    async fn start(&mut self) -> Result<()> {
        let mut is_running = self.is_running.write();
        if *is_running {
            return Err(ConsensusError::AlreadyStarted);
        }

        if !self.is_validator() {
            return Err(ConsensusError::InvalidValidatorSet(format!(
                "Node {} is not a validator",
                self.address
            )));
        }

        // Initialize vote collector around the engine's long-lived
        // equivocation detector
        let validator_set = self.validator_set();
        let validator_set_arc = Arc::new(validator_set);
        *self.vote_collector.write() = Some(Arc::new(VoteCollector::with_detector(
            validator_set_arc.clone(),
            self.equivocation_detector.clone(),
        )));
        // Initialize timeout collector (Bracha boost + 2f+1 TC formation)
        *self.timeout_collector.write() = Some(Arc::new(crate::timeout::TimeoutCollector::new(
            validator_set_arc.clone(),
        )));
        // Initialize no-endorsement collector (f+1 NEC formation, the
        // NEC tail-fork defence)
        *self.nec_collector.write() = Some(Arc::new(crate::timeout::NoEndorsementCollector::new(
            validator_set_arc,
        )));

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel(1);
        *self.shutdown_tx.write() = Some(shutdown_tx);

        *is_running = true;

        tracing::info!(
            address = %self.address,
            validators = self.validator_set().len(),
            "HotStuff-2 consensus engine started"
        );

        // Spawn consensus loop
        let engine = self.clone();
        tokio::spawn(async move {
            if let Err(e) = engine.consensus_loop().await {
                tracing::error!(error = %e, "Consensus loop error");
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        let mut is_running = self.is_running.write();
        if !*is_running {
            return Err(ConsensusError::NotStarted);
        }

        // Send shutdown signal
        if let Some(shutdown_tx) = self.shutdown_tx.read().as_ref() {
            let _ = shutdown_tx.send(());
        }

        *is_running = false;

        tracing::info!("HotStuff-2 consensus engine stopped");

        Ok(())
    }

    async fn propose_block(&self, _transactions: Vec<Transaction>) -> Result<Block> {
        if !self.is_leader().await {
            let view = self.view_state.read().view;
            return Err(ConsensusError::NotLeader(view));
        }

        self.propose_block_internal().await
    }

    async fn on_proposal(
        &self,
        block: &Block,
        timeout_certificate: Option<crate::timeout::TimeoutCertificate>,
        no_endorsement_certificate: Option<crate::timeout::NoEndorsementCertificate>,
        proposer_high_qc_view: u64,
        proposer_signature: &tenzro_crypto::composite::CompositeSignature,
    ) -> Result<Vote> {
        // RECEIVER-SIDE DEDUP (the standard message-processing
        // seen-set pattern): drop duplicate proposals at the door, keyed by
        // `(view, block_hash)`. A gossipsub IHAVE/IWANT replay, a peer-
        // forwarded copy of a proposal we already saw via the consensus-
        // direct overlay, or in-flight proposals from a previous buggy
        // run that were still circulating when we restarted on the fix
        // image — all land at `on_proposal` and would otherwise burn
        // CPU through the catchup / vote-state-store / equivocation
        // detector paths before the local replica's
        // `LastSignState::check_safe_to_sign` finally said "already
        // signed for this view; refusing". The vote-state-store is
        // correct end-of-line defence, but it noise up the equivocation
        // telemetry (each rejected vote logs a `DOUBLE-SIGN PREVENTED`
        // ERROR) and wastes a few hundred microseconds per re-deliver
        // on signature verification. Dropping at the door is cheaper
        // and keeps the equivocation log clean for real Byzantine
        // events. Pruned by `advance_view` alongside other per-view
        // caches.
        let dedup_key = (block.header.view, block.hash());
        // Cheap read-only pre-check: an exact replay (same view + hash) is
        // dropped before any signature work. The authoritative atomic
        // insert happens AFTER signature verification below, so a forged
        // proposal with a bad signature can never poison the dedup slot
        // for the genuine one.
        if self.proposal_dedup.contains_key(&dedup_key) {
            tracing::debug!(
                view = block.header.view,
                hash = %block.hash(),
                "receiver-dedup: dropping duplicate proposal already seen at this view"
            );
            // Return a Vote-shaped error: the caller (event_loop)
            // doesn't broadcast on error, so a duplicate is silently
            // absorbed without re-broadcasting or re-voting.
            return Err(ConsensusError::Internal(
                "duplicate proposal (already processed at this view)".to_string(),
            ));
        }

        // PROPOSER AUTHENTICATION: verify the leader's hybrid signature over
        // the canonical proposal payload against the proposer's REGISTERED
        // composite key from the current validator set. This makes proposals
        // attributable (proposal-equivocation slashing below) and
        // authenticates the `proposer_high_qc_view` SyncInfo hint before we
        // adopt it. Verifying against the registered key — not any key
        // embedded in the message — is the identity binding.
        let proposer = block.header.proposer;
        let registered_key = {
            let validator_set = self.validator_set();
            let Some(validator) = validator_set.get_by_address(&proposer) else {
                return Err(ConsensusError::NonValidator(format!(
                    "proposal from non-validator {}",
                    proposer
                )));
            };
            validator.composite_public_key()
        };
        let proposal_payload = crate::validator::proposal_signing_payload(
            block.header.view,
            block.header.height.0,
            &block.hash(),
            proposer_high_qc_view,
        );
        StandardHybridVerifier::new(registered_key.clone())
            .verify(&proposal_payload, proposer_signature)
            .map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "proposal hybrid signature verification failed for {}: {}",
                    proposer, e
                ))
            })?;

        // PROPOSAL-EQUIVOCATION DETECTION: two verified signatures from the
        // same proposer over DIFFERENT block hashes at the same view is
        // slashable — the evidence embeds both signatures and is
        // independently verifiable. Emitted exactly once per (proposer,
        // view); repeats return `DuplicateProposal` without re-firing the
        // slashing callback.
        let observed = crate::validator::ProposalRecord {
            height: block.header.height.0,
            block_hash: block.hash(),
            high_qc_view: proposer_high_qc_view,
            signature: proposer_signature.clone(),
        };
        match self.equivocation_detector.check_proposal(
            &proposer,
            block.header.view,
            observed,
            &registered_key,
        ) {
            Ok(None) => {}
            Ok(Some(evidence)) => {
                if let Some(ref callback) = self.slashing_callback {
                    callback.report_proposal_equivocation(&proposer, block.header.view, &evidence);
                }
                return Err(ConsensusError::InvalidProposal(format!(
                    "proposal equivocation detected for {} at view {}",
                    proposer, block.header.view
                )));
            }
            Err(e) => return Err(e),
        }

        // Authoritative atomic dedup insert — only reached with a verified,
        // non-equivocating proposal. A concurrent racer that lost the
        // insert drops here.
        if self.proposal_dedup.insert(dedup_key, ()).is_some() {
            return Err(ConsensusError::Internal(
                "duplicate proposal (already processed at this view)".to_string(),
            ));
        }

        // SyncInfo (#171): the proposer piggybacks its current
        // `high_qc_view` on every proposal. We adopt it if higher than our
        // own (subject to `< proposal_view`). This is the steady-state
        // backward-sync channel — a lagging replica that observes any honest
        // proposal can fast-forward without waiting for a TC or Prepare-QC of
        // its own. The bound prevents a Byzantine proposer from inflating the
        // signal to drag honest replicas into a forged future.
        let proposal_view_for_hqc = block.header.view;
        if proposer_high_qc_view < proposal_view_for_hqc {
            let mut hqc = self.high_qc_view.write();
            if proposer_high_qc_view > *hqc {
                tracing::debug!(
                    local_high_qc_view = *hqc,
                    proposer_high_qc_view,
                    proposal_view = proposal_view_for_hqc,
                    "Adopting proposer's high_qc_view from SyncInfo piggyback"
                );
                *hqc = proposer_high_qc_view;
            }
        }

        // View sync: advance local view to match the proposal's view before
        // voting. This is the canonical HotStuff-2 Pacemaker rule and the
        // `ensure_round_and_sync_up` pattern: when a proposal arrives at a higher view
        // than our local view, we sync up so our vote is stamped with the
        // proposer's view and lands in the same vote-collector bucket as the
        // proposer's self-vote and other peers' votes — otherwise validators
        // at drifted views never form a quorum at any single view (the bug
        // that pinned testnet at block_height=0).
        //
        // No numeric jump cap is applied here; safe_to_extend (below) is
        // the cryptographic gate. A proposal that skips views without a
        // verifiable TC for `proposal_view - 1` is rejected outright; a
        // proposal that carries one is provably safe to follow regardless
        // of how large the jump is.
        let proposal_view = block.header.view;
        let proposal_height = block.header.height;
        let (local_view, local_height) = {
            let state = self.view_state.read();
            (state.view, state.height)
        };

        // Catchup-on-proposal (the `ensure_blocks_in_storage` /
        // `process_certificates` pattern): if the proposer is ahead by one
        // height, the proposal carries the parent's Commit QC in
        // `block.header.consensus_proof.proof_data`. We can apply that QC
        // locally to finalize the parent and advance our `view_state.height`
        // by one before height-checking the proposal. This unsticks the
        // 1-block tip fork that occurs when a validator misses a Commit
        // vote window (its view advances past `qc.view` before it can vote
        // Commit, so `on_vote` records the Prepare QC in `high_qc_view` but
        // never finalizes via `finalize_with_commit_qc`).
        //
        // Safe because: (1) the embedded QC is cryptographically verified
        // below (`verify_bls_aggregate` against the validator set active at
        // the parent's height) BEFORE `finalize_with_commit_qc` runs — a forged
        // or under-quorum QC never reaches the finalize path; (2) we only
        // accept catchup-finalize for the parent of the incoming proposal,
        // never arbitrary jumps; (3) the parent block must already be in
        // `self.blocks` (every proposal forward-syncs its block into the
        // cache on `on_proposal`'s prelude).
        // Downward self-heal: `view_state.height` must never exceed
        // `finalized_height + 1`. Both finalize paths (on_vote and
        // finalize_with_commit_qc) advance `state.height` by `+1` relative
        // to its own in-memory value, gated on `finalize_block` SUCCESS.
        // If `view_state.height` ever drifts ahead of the FinalityTracker
        // (a transient finalize the tracker later rolled back, or a view
        // advancement without a matching tracker finalize), the gate at
        // line ~3006 then rejects every genuine `finalized_height + 1`
        // proposal as `InvalidHeight { expected: local_height, actual:
        // proposal_height }` because `proposal_height < local_height` — a
        // self-sustaining wedge, since block-sync can't bridge a NEGATIVE
        // gap either. The existing re-sync-down guards (the
        // `finalize_block` error arms in both finalize paths) only fire on
        // finalize FAILURE; they never catch a view_state that ran ahead
        // while the tracker stayed put.
        //
        // Heal it here: when an incoming proposal is for exactly the next
        // height the tracker expects (`finalized_height + 1`) yet our
        // `view_state.height` sits strictly above that, the proposal is the
        // real next block and we are the diverged node. Resync
        // `view_state.height` down to `finalized_height + 1` and re-read
        // `local_height` so the proposal passes the gate and we vote. This
        // is the mirror of the catchup-on-proposal below (which only heals
        // the proposer-AHEAD case); together they keep `view_state.height`
        // pinned to `finalized_height + 1` from both directions.
        let tracker_next_height = self.finality_tracker.finalized_height() + 1u64;
        if proposal_height == tracker_next_height && local_height > tracker_next_height {
            let mut state = self.view_state.write();
            // Re-check under the write lock — a concurrent finalize may have
            // already advanced the tracker.
            if state.height > tracker_next_height {
                tracing::warn!(
                    stale_height = %state.height,
                    corrected_height = %tracker_next_height,
                    proposal_height = %proposal_height,
                    "view_state.height ran ahead of finality tracker — \
                     re-syncing down to finalized_height + 1 to accept the \
                     genuine next proposal"
                );
                state.height = tracker_next_height;
                state.phase = Phase::Prepare;
                state.proposed_block = None;
                state.prepare_qc = None;
                state.commit_qc = None;
                state.reset_timer();
            }
        }

        // Re-read local_height after the downward heal.
        let local_height = self.view_state.read().height;

        if proposal_height == local_height + 1u64 {
            let parent_hash = block.header.prev_hash;
            let parent_known = self.blocks.contains_key(&parent_hash);
            let qc_bytes = block.header.consensus_proof.proof_data.as_slice();
            if parent_known && !qc_bytes.is_empty() {
                match bincode::deserialize::<QuorumCertificate>(qc_bytes) {
                    Ok(parent_commit_qc)
                        if parent_commit_qc.vote_type == VoteType::Commit
                            && parent_commit_qc.block_hash == parent_hash
                            && parent_commit_qc.height == local_height =>
                    {
                        // The QC arrived over the wire inside the proposal —
                        // it MUST be cryptographically verified against the
                        // validator set that was active at the parent's
                        // height before it is allowed to finalize anything.
                        // A structural match (height/hash/vote_type) alone is
                        // trivially forgeable.
                        let qc_verified = match self.validator_set_for_height(local_height) {
                            Some(parent_set) => {
                                match parent_commit_qc.verify_bls_aggregate(&parent_set) {
                                    Ok(()) => true,
                                    Err(e) => {
                                        tracing::warn!(
                                            error = %e,
                                            proposal_height = %proposal_height,
                                            parent_height = %local_height,
                                            "Catchup-on-proposal: embedded parent QC failed \
                                             signature/quorum verification — rejecting catchup"
                                        );
                                        false
                                    }
                                }
                            }
                            None => {
                                tracing::warn!(
                                    parent_height = %local_height,
                                    "Catchup-on-proposal: no validator set available for \
                                     parent height — skipping catchup, block-sync will bridge"
                                );
                                false
                            }
                        };

                        // Look up the parent block from our local cache and
                        // run the same finalize path that the leader-driven
                        // commit takes. Idempotent if we somehow already
                        // finalized.
                        if qc_verified
                            && let Some(parent_block) =
                                self.blocks.get(&parent_hash).map(|r| r.clone())
                        {
                            tracing::info!(
                                proposal_height = %proposal_height,
                                parent_height = %local_height,
                                qc_view = parent_commit_qc.view,
                                "Catchup-on-proposal: finalizing missed parent \
                                 via verified QC embedded in incoming proposal"
                            );
                            if let Err(e) = self
                                .finalize_with_commit_qc(&parent_block, parent_commit_qc)
                                .await
                            {
                                tracing::warn!(
                                    error = %e,
                                    parent_height = %local_height,
                                    "Catchup-on-proposal: parent finalize failed; \
                                     falling through to regular height-mismatch reject"
                                );
                            }
                        }
                    }
                    Ok(_) => {
                        tracing::debug!(
                            proposal_height = %proposal_height,
                            "Catchup-on-proposal: embedded QC did not match parent (wrong height, \
                             wrong block hash, or wrong vote_type) — skipping catchup"
                        );
                    }
                    Err(e) => {
                        tracing::debug!(
                            error = %e,
                            "Catchup-on-proposal: failed to deserialize parent commit QC; \
                             skipping catchup"
                        );
                    }
                }
            }
        }

        // Re-read local_height after the catchup attempt — finalize_with_commit_qc
        // bumps view_state.height on success.
        let local_height = self.view_state.read().height;

        // Reject proposals for the wrong height outright — `validate_proposal`
        // will catch this too, but failing fast avoids an unnecessary view jump.
        if proposal_height != local_height {
            // We're behind the network and catchup-on-proposal couldn't bridge
            // the gap (parent not in cache, gap > 1, or finalize failed). Hint
            // block-sync so it engages even inside its normal tolerance window.
            if proposal_height > local_height {
                self.behind_hint_tx.send_replace(proposal_height.as_u64());
            }
            return Err(ConsensusError::InvalidHeight {
                expected: local_height,
                actual: proposal_height,
            });
        }

        // Reject stale proposals (proposer was at a strictly lower view than
        // we are now). Voting on a stale proposal would re-introduce the bug.
        if proposal_view < local_view {
            tracing::debug!(
                proposal_view = proposal_view,
                local_view = local_view,
                height = %proposal_height,
                "Dropping stale proposal: proposer view < local view"
            );
            return Err(ConsensusError::InvalidProposal(format!(
                "stale proposal: view {} < local view {}",
                proposal_view, local_view
            )));
        }

        // Proposer enforcement: the block's header must carry the leader
        // elected for the view it was built at. `header.view` binds the
        // original construction view, so this single rule covers both the
        // happy path and TC-justified reproposals (a reproposed high-tip
        // is byte-identical — header.view/proposer are the original
        // leader's, and the election re-derives the same answer). With
        // the per-epoch seed anchor the election is deterministic
        // fleet-wide, so an honest proposer can never be falsely
        // rejected. If election itself fails (validator set unknown for
        // the view) we fall through rather than reject — the QC quorum
        // still gates finalization.
        if let Ok(expected_leader) = self.leader_for_view(block.header.view)
            && block.header.proposer != expected_leader
        {
            tracing::warn!(
                proposal_view = block.header.view,
                proposer = %block.header.proposer,
                expected = %expected_leader,
                height = %proposal_height,
                "Rejecting proposal: proposer is not the elected leader for its view"
            );
            return Err(ConsensusError::InvalidProposal(format!(
                "proposer {} is not the elected leader {} for view {}",
                block.header.proposer, expected_leader, block.header.view
            )));
        }

        // safe_to_extend:
        // A proposal at round r is safe to vote on iff
        //   (a) r == high_qc.round + 1                (happy path), OR
        //   (b) r == tc.round + 1                     (timeout recovery), AND
        //       high_qc.round ≥ max(tc.high_qc_rounds across signers).
        //
        // We don't piggyback `qc` on every proposal yet (#171), so the strongest
        // tractable check is:
        //   - If `proposal_view > local_view + 1`, the proposer skipped views.
        //     They MUST attach a TC for view `proposal_view - 1`. Reject otherwise.
        //   - If a TC is attached, verify its signatures and that
        //     `tc.view + 1 == proposal_view`. Then advance our own
        //     `high_qc_view` if the TC reveals a higher one (Bracha-style sync).
        if let Some(ref tc) = timeout_certificate {
            // Verify the TC is well-formed and signed by 2f+1 validators of the
            // current epoch.
            let validator_set = self.validator_set();
            if let Err(e) = tc.verify(&validator_set) {
                tracing::warn!(
                    proposal_view = proposal_view,
                    tc_view = tc.view,
                    error = %e,
                    "Rejecting proposal: attached TC failed verification"
                );
                return Err(ConsensusError::InvalidProposal(format!(
                    "invalid timeout certificate: {}",
                    e
                )));
            }
            // The TC must be for the round immediately preceding the proposal.
            if tc.view + 1 != proposal_view {
                tracing::warn!(
                    proposal_view = proposal_view,
                    tc_view = tc.view,
                    "Rejecting proposal: TC view + 1 != proposal view"
                );
                return Err(ConsensusError::InvalidProposal(format!(
                    "TC view {} + 1 != proposal view {}",
                    tc.view, proposal_view
                )));
            }
            // Adopt the TC's max high_qc view if higher than ours — this is the
            // backward-sync mechanism that lets a lagging replica catch up to
            // the chain's true high_qc without waiting for a Prepare QC of
            // its own.
            let tc_max_hqc = tc.max_high_qc_view();
            {
                let mut hqc = self.high_qc_view.write();
                if tc_max_hqc > *hqc {
                    *hqc = tc_max_hqc;
                }
            }

            // NEC tail-fork defence:
            // After a TC for view v-1, the leader has two legal options:
            //   (a) repropose the existing `high_tip` (block at the highest
            //       observed Prepare-QC), OR
            //   (b) propose a fresh block, but only if it can prove that no
            //       Prepare-QC formed at the timed-out view v-1 — by attaching
            //       an f+1 NoEndorsementCertificate.
            //
            // Without this rule, a Byzantine leader could silently fork off a
            // QC that 2f+1 honest replicas observed, capturing tail-MEV. The
            // NEC forces public attestation: f+1 validators must sign that
            // they did not see the QC, which is impossible if a QC actually
            // formed (since it took 2f+1 votes — and at most f are Byzantine,
            // so at least f+1 honest replicas saw it and won't sign an NEC).
            let high_qc_view_local = *self.high_qc_view.read();
            let timed_out_view = tc.view;
            let is_repropose_of_high_tip = {
                // Compare against the most-recent fork-choice high_tip at the
                // proposal's height. If we have no high_tip record (cold start
                // or genesis-edge), fall back to permitting reproposal (the
                // safe-to-extend predicate above already filtered stale TCs).
                self.fork_choice
                    .select_best_block(proposal_height)
                    .map(|b| b.hash() == block.hash())
                    .unwrap_or(false)
            };
            let has_qc_at_timed_out_view = high_qc_view_local >= timed_out_view;

            if !is_repropose_of_high_tip {
                // Fresh block after TC: the leader claims no QC formed at the
                // timed-out view. Require an NEC to back that claim.
                let nec = no_endorsement_certificate.as_ref().ok_or_else(|| {
                    tracing::warn!(
                        proposal_view = proposal_view,
                        tc_view = tc.view,
                        block_hash = ?block.hash(),
                        "Rejecting fresh block after TC with no NoEndorsementCertificate"
                    );
                    ConsensusError::InvalidProposal(format!(
                        "fresh block at view {} after TC requires NoEndorsementCertificate \
                         for view {}",
                        proposal_view, timed_out_view
                    ))
                })?;
                if nec.view != timed_out_view {
                    tracing::warn!(
                        proposal_view = proposal_view,
                        tc_view = tc.view,
                        nec_view = nec.view,
                        "Rejecting fresh block after TC: NEC view mismatch"
                    );
                    return Err(ConsensusError::InvalidProposal(format!(
                        "NEC view {} != timed-out view {}",
                        nec.view, timed_out_view
                    )));
                }
                let validator_set = self.validator_set();
                if let Err(e) = nec.verify(&validator_set) {
                    tracing::warn!(
                        proposal_view = proposal_view,
                        nec_view = nec.view,
                        error = %e,
                        "Rejecting fresh block after TC: NEC failed verification"
                    );
                    return Err(ConsensusError::InvalidProposal(format!(
                        "invalid NoEndorsementCertificate: {}",
                        e
                    )));
                }
                if has_qc_at_timed_out_view {
                    tracing::warn!(
                        proposal_view = proposal_view,
                        tc_view = tc.view,
                        local_high_qc_view = high_qc_view_local,
                        "Rejecting fresh block after TC: NEC contradicts locally observed QC"
                    );
                    return Err(ConsensusError::InvalidProposal(format!(
                        "NEC at view {} contradicts locally observed high_qc view {}",
                        timed_out_view, high_qc_view_local
                    )));
                }
            }
        } else if proposal_view > local_view + 1 {
            // No TC, but the leader skipped views. This violates safe_to_extend
            // — refuse to vote rather than risk extending an unsafe branch.
            tracing::warn!(
                proposal_view = proposal_view,
                local_view = local_view,
                "Rejecting proposal: view jump > 1 with no timeout certificate"
            );
            return Err(ConsensusError::InvalidProposal(format!(
                "proposal view {} jumps from local view {} without timeout certificate",
                proposal_view, local_view
            )));
        }

        // Store the received block keyed by hash so that when the Prepare/Commit
        // QC forms (driven by peer votes arriving via `on_vote`), we can look
        // the block back up to drive phase transitions and finalization. Without
        // this, only the leader (which inserts in `propose_block_internal`) can
        // advance past Prepare — the bug that wedged height=1 indefinitely.
        self.blocks.insert(block.hash(), block.clone());
        // Mirror into fork choice — receivers learn about new blocks here
        // before any local QC observation; the QC is recorded later in
        // `try_form_qc_and_drive_phase` once votes aggregate locally.
        self.fork_choice.add_block(block.clone(), None);

        // Advance local view to match the proposer's view. The
        // safe_to_extend block above is the cryptographic
        // gate — by reaching this point the jump has been proven legal:
        // either `proposal_view == local_view + 1` (happy-path consecutive
        // view), or a verified TC for view `proposal_view - 1` was
        // attached, which is itself a 2f+1 cryptographic proof that the
        // timed-out view was abandoned by an honest super-majority. A
        // Byzantine proposer cannot forge that proof, so no numeric jump
        // cap is needed and any cap would simply wedge honest replicas
        // that have legitimately fallen behind by many thousands of views.
        if proposal_view > local_view {
            let mut state = self.view_state.write();
            // Re-check under the write lock — another task may have advanced
            // us in between.
            if proposal_view > state.view {
                tracing::info!(
                    from_view = state.view,
                    to_view = proposal_view,
                    height = %state.height,
                    "View sync: advancing local view to match proposal"
                );
                state.view = proposal_view;
                state.phase = Phase::Prepare;
                state.proposed_block = None;
                state.prepare_qc = None;
                state.commit_qc = None;
                state.reset_timer();
            }
        }

        let phase = {
            let state = self.view_state.read();
            state.phase
        };

        match phase {
            Phase::Prepare => {
                self.handle_prepare_phase(block).await?;
                self.create_vote(block, VoteType::Prepare)
            }
            Phase::Commit => {
                self.handle_commit_phase(block).await?;
                self.create_vote(block, VoteType::Commit)
            }
            Phase::Decide => Err(ConsensusError::InvalidProposal(
                "Already in decide phase".to_string(),
            )),
        }
    }

    async fn on_vote(&self, vote: &Vote) -> Result<()> {
        // SyncInfo (#171): every vote piggybacks the voter's
        // `high_qc_view`. Adopt it if higher than our local view, so a lagging
        // replica receiving votes for a future view can fast-forward without
        // a separate sync RPC. The bound `< vote.view` is enforced upstream
        // by `add_vote()` in the voter — Byzantine voters can't claim a future
        // high_qc beyond what they're voting for.
        {
            let mut hqc = self.high_qc_view.write();
            if vote.high_qc_view > *hqc {
                tracing::debug!(
                    voter = %vote.voter,
                    voter_high_qc = vote.high_qc_view,
                    local_high_qc = *hqc,
                    "Adopting voter's high_qc_view from SyncInfo piggyback"
                );
                *hqc = vote.high_qc_view;
            }
        }

        // Add the peer vote to the collector. If a QC forms, we must drive
        // phase progression (Prepare→Commit→Decide) here — the run_consensus_step
        // loop only progresses the *leader's* phase via handle_prepare/commit;
        // replicas otherwise sit in Phase::Prepare forever, which is exactly
        // the bug that wedged height=1 indefinitely on the live testnet
        // (Prepare QCs at view=135, 136, 137… all formed, all ignored).
        let qc_opt = {
            let vote_collector = self.vote_collector.read();
            let collector = match vote_collector.as_ref() {
                Some(c) => c,
                None => return Err(ConsensusError::NotStarted),
            };
            match collector.add_vote(vote.clone()) {
                Ok(qc) => qc,
                Err(ConsensusError::Equivocation {
                    ref validator,
                    view,
                }) => {
                    // Equivocation detected — trigger slashing via callback
                    tracing::error!(
                        validator = %validator,
                        view = view,
                        "EQUIVOCATION: Validator voted for conflicting blocks. \
                         Triggering slashing."
                    );

                    // Invoke the slashing callback to slash the validator's stake
                    if let Some(ref callback) = self.slashing_callback
                        && let Some(evidence) = collector.get_evidence_for(&vote.voter, view)
                    {
                        callback.report_equivocation(&vote.voter, view, &evidence);
                    }

                    return Err(ConsensusError::Equivocation {
                        validator: validator.clone(),
                        view,
                    });
                }
                Err(e) => return Err(e),
            }
        }; // vote_collector read lock dropped before driving phase progression

        // Pacemaker advance via inbound SyncInfo:
        // a vote whose `high_qc_view = Q` is observable evidence of a 2f+1
        // Prepare QC at view Q — the QC is itself a 2f+1 aggregate, so a
        // single piece of evidence suffices to advance the pacemaker. The
        // next legal proposal will be at view Q+1, so any replica still
        // sitting at view ≤ Q is provably behind and should fast-forward.
        //
        // SECURITY: This adoption runs *after* `add_vote` returned Ok,
        // which means the vote's hybrid signature has been verified
        // against the registered validator's keys (voter.rs:454). The
        // Vote's canonical signing payload binds `(view, voter,
        // high_qc_view, …)` (voter.rs:106), so a Byzantine signer cannot
        // forge a `high_qc_view` value without invalidating their
        // signature. The cryptographic gate is sufficient on its own; no
        // numeric jump cap is applied, since any cap would wedge honest
        // replicas that have legitimately fallen behind by many thousands
        // of views.
        //
        // This is the canonical HotStuff-family recovery channel — the
        // certificate-processing path advances the pacemaker on observed QCs.
        if vote.high_qc_view > 0 {
            let target = vote.high_qc_view.saturating_add(1);
            let mut state = self.view_state.write();
            if target > state.view {
                tracing::info!(
                    from_view = state.view,
                    to_view = target,
                    height = %state.height,
                    voter = %vote.voter,
                    "Pacemaker: advancing local view via vote SyncInfo high_qc_view+1"
                );
                state.view = target;
                state.phase = Phase::Prepare;
                state.proposed_block = None;
                state.prepare_qc = None;
                state.commit_qc = None;
                state.reset_timer();
            }
        }

        let qc = match qc_opt {
            Some(qc) => qc,
            None => return Ok(()), // not a quorum yet, just collected
        };

        // Record the QC into fork choice. `record_qc` is idempotent + monotonic
        // by view, so re-observing a QC for a block we already know is a
        // no-op, and a higher-view QC for the same block hash supersedes
        // a lower-view one. No-ops if the block isn't known locally yet
        // (the same warn path below catches that case).
        self.fork_choice.record_qc(qc.clone());

        // Look up the block this QC commits to. Available locally because
        // `on_proposal` (and `propose_block_internal`) insert into self.blocks.
        let block = match self.blocks.get(&qc.block_hash).map(|r| r.clone()) {
            Some(b) => b,
            None => {
                tracing::warn!(
                    view = qc.view,
                    height = qc.height.0,
                    block_hash = %qc.block_hash,
                    vote_type = ?qc.vote_type,
                    "QC formed but block not in local cache — cannot drive phase progression"
                );
                return Ok(());
            }
        };

        match qc.vote_type {
            VoteType::Prepare => {
                // Emit our Commit vote on observation of the Prepare QC.
                //
                // Previously this was gated by `state.phase == Phase::Prepare
                // && state.view == qc.view`. That gate caused the 2026-06-08
                // testnet stall: when the local pacemaker advanced past `qc.view`
                // (Bracha boost, vote-piggybacked SyncInfo, etc.) before the
                // Prepare QC arrived locally, we'd suppress our Commit vote.
                // Multiple validators in the cluster hit this race per view, so
                // Commit-QC quorum never formed → block never finalized →
                // next-height proposals had no parent QC to carry → 1-block
                // tip fork → live-lock.
                //
                // The fix (the Safety-Rules pattern): drop the
                // local view gate and rely on `create_vote` + `vote_state_store`
                // for the safety guard. `create_vote` calls
                // `vote_state_store.record_or_reject` which enforces strict
                // monotonicity: any attempt to cast a vote at `(v, h, step)`
                // that is not strictly after the last persisted signing tuple
                // returns `Equivocation` and the vote is dropped. So even if
                // we re-enter this path for a Prepare QC after our view has
                // moved on, we cannot double-sign at a conflicting (view,
                // height, step) — the vote-state-store is the cryptographic
                // safety net, the local view was just a stale liveness gate
                // we don't actually need.
                //
                // Idempotency for the recovery case: if `create_vote` returns
                // an Equivocation error we treat it as "already voted, no
                // action" and continue. Phase/state are bumped only when our
                // view actually matched the QC — this preserves the proposer
                // path's invariants while letting recovery emit votes
                // unconditionally.
                let phase_matches = {
                    let mut state = self.view_state.write();
                    if state.phase == Phase::Prepare && state.view == qc.view {
                        state.phase = Phase::Commit;
                        state.prepare_qc = Some(qc.clone());
                        if state.proposed_block.is_none() {
                            state.proposed_block = Some(block.clone());
                        }
                        tracing::info!(
                            view = state.view,
                            height = %state.height,
                            "Prepare QC observed via on_vote — advancing to Commit phase"
                        );
                        true
                    } else {
                        false
                    }
                };

                // Track high_qc_view independent of phase-advance decision —
                // even an "already past Prepare" replica should learn the
                // highest Prepare QC view for future TimeoutMsg construction.
                {
                    let mut hqc = self.high_qc_view.write();
                    if qc.view > *hqc {
                        *hqc = qc.view;
                    }
                }

                // Emit Commit vote unconditionally (subject to vote-state-store
                // double-sign protection inside `create_vote`).
                match self.create_vote(&block, VoteType::Commit) {
                    Ok(commit_vote) => {
                        if !phase_matches {
                            tracing::info!(
                                view = qc.view,
                                local_view = self.view_state.read().view,
                                height = %qc.height,
                                "Recovery: emitting Commit vote for Prepare QC at past view \
                                 — local pacemaker moved on but vote_state_store permits the vote"
                            );
                        }
                        self.send_out(ConsensusOutMessage::Vote(commit_vote.clone()));

                        // Add our own Commit vote to the collector so we count
                        // toward the Commit quorum without waiting for the gossip
                        // round-trip.
                        let collector_qc = {
                            let vote_collector = self.vote_collector.read();
                            match vote_collector.as_ref() {
                                Some(collector) => collector.add_vote(commit_vote)?,
                                None => return Err(ConsensusError::NotStarted),
                            }
                        };

                        // If our self-Commit vote completed the Commit quorum
                        // (e.g. we were the last vote needed), recurse into
                        // finalization immediately.
                        if let Some(commit_qc) = collector_qc
                            && commit_qc.vote_type == VoteType::Commit
                        {
                            self.finalize_with_commit_qc(&block, commit_qc).await?;
                        }
                    }
                    Err(ConsensusError::Equivocation { .. }) => {
                        // Vote-state-store says we've already signed at or
                        // past this (view, height, step). Treat as idempotent
                        // recovery no-op — DO NOT propagate the error: this
                        // path is a recovery channel, not a misbehavior signal.
                        tracing::debug!(
                            view = qc.view,
                            height = %qc.height,
                            "Recovery Commit-vote suppressed by vote_state_store (already signed)"
                        );
                    }
                    Err(e) => return Err(e),
                }
            }
            VoteType::Commit => {
                self.finalize_with_commit_qc(&block, qc).await?;
            }
        }

        Ok(())
    }

    async fn finalized_height(&self) -> BlockHeight {
        self.finality_tracker.finalized_height()
    }

    async fn is_leader(&self) -> bool {
        self.get_leader()
            .map(|l| l == self.address)
            .unwrap_or(false)
    }
}

// Test-only inherent impl: exposes private inbound handlers
// (`on_proposal`, `on_vote`) so multi-engine integration tests can
// wire the cluster directly without spinning the full event-loop
// layer. NOT a production message route — production receives via the
// consensus_out channel + the node's event loop.
impl HotStuff2Engine {
    /// Test-only wrapper around `on_proposal`. See module-level note.
    #[doc(hidden)]
    pub async fn test_on_proposal(
        &self,
        block: &Block,
        timeout_certificate: Option<crate::timeout::TimeoutCertificate>,
        no_endorsement_certificate: Option<crate::timeout::NoEndorsementCertificate>,
        proposer_high_qc_view: u64,
        proposer_signature: &tenzro_crypto::composite::CompositeSignature,
    ) -> Result<Vote> {
        self.on_proposal(
            block,
            timeout_certificate,
            no_endorsement_certificate,
            proposer_high_qc_view,
            proposer_signature,
        )
        .await
    }

    /// Test-only wrapper around `on_vote`. See module-level note.
    #[doc(hidden)]
    pub async fn test_on_vote(&self, vote: &Vote) -> Result<()> {
        self.on_vote(vote).await
    }
}

// Manual Clone implementation
impl Clone for HotStuff2Engine {
    fn clone(&self) -> Self {
        Self {
            keypair: self.keypair.clone(),
            pq_signing_key: self.pq_signing_key.clone(),
            bls_signing_key: self.bls_signing_key.clone(),
            composite_public_key: self.composite_public_key.clone(),
            address: self.address,
            config: self.config.clone(),
            epoch_manager: self.epoch_manager.clone(),
            mempool: self.mempool.clone(),
            proposer: self.proposer.clone(),
            vote_collector: self.vote_collector.clone(),
            finality_tracker: self.finality_tracker.clone(),
            view_state: self.view_state.clone(),
            view_timer: self.view_timer.clone(),
            blocks: self.blocks.clone(),
            fork_choice: self.fork_choice.clone(),
            is_running: self.is_running.clone(),
            drain: self.drain.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            slashing_callback: self.slashing_callback.clone(),
            equivocation_detector: self.equivocation_detector.clone(),
            state_root_provider: self.state_root_provider.clone(),
            block_provider: self.block_provider.clone(),
            consensus_out_tx: self.consensus_out_tx.clone(),
            vote_state_store: self.vote_state_store.clone(),
            high_qc_view: self.high_qc_view.clone(),
            last_round_tc: self.last_round_tc.clone(),
            timeout_collector: self.timeout_collector.clone(),
            last_round_nec: self.last_round_nec.clone(),
            nec_collector: self.nec_collector.clone(),
            last_proposed_view: self.last_proposed_view.clone(),
            proposal_dedup: self.proposal_dedup.clone(),
            proposer_election: self.proposer_election.clone(),
            reputation: self.reputation.clone(),
            behind_hint_tx: self.behind_hint_tx.clone(),
            last_block_time: self.last_block_time.clone(),
            view_timeouts_total: self.view_timeouts_total.clone(),
            batch_cert_store: self.batch_cert_store.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::ValidatorInfo;
    use tenzro_crypto::KeyType;

    fn create_test_validators(count: usize) -> Vec<ValidatorInfo> {
        (0..count)
            .map(|i| {
                let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
                // Convert tenzro_crypto::Address (20 bytes) to tenzro_types::Address (32 bytes)
                let crypto_addr = keypair.address();
                let mut addr_bytes = [0u8; 32];
                addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
                let address = tenzro_types::primitives::Address::new(addr_bytes);
                let pq = MlDsaSigningKey::generate();
                let bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
                ValidatorInfo::new(
                    address,
                    keypair.public_key().clone(),
                    pq.verifying_key_bytes().to_vec(),
                    bls.public_key().to_bytes().to_vec(),
                    1000 * (i as u128 + 1),
                )
            })
            .collect()
    }

    /// In-memory `BlockProvider` used by tests that drive `on_proposal` /
    /// `handle_prepare_phase` directly. Real production wiring uses
    /// `NodeBlockProvider` (RocksDB-backed); the tests need a parent block at
    /// height 0 in scope so the EIP-1559 base-fee validation path can re-derive
    /// the child's base fee from the genesis-edge parent (`gas_limit==0`,
    /// `base_fee_per_gas==Some(initial_base_fee)`).
    struct TestBlockProvider {
        blocks: parking_lot::RwLock<std::collections::HashMap<BlockHeight, Block>>,
    }

    impl TestBlockProvider {
        fn new() -> Self {
            Self {
                blocks: parking_lot::RwLock::new(std::collections::HashMap::new()),
            }
        }

        fn insert(&self, block: Block) {
            self.blocks.write().insert(block.header.height, block);
        }
    }

    impl BlockProvider for TestBlockProvider {
        fn get_block(&self, height: BlockHeight) -> Option<Block> {
            self.blocks.read().get(&height).cloned()
        }
    }

    /// Stamp the expected genesis-edge EIP-1559 base fee on a child block at
    /// height 1. Tests that exercise `on_proposal` against `build_test_engine*`
    /// must use this — the new consensus rule rejects child blocks whose
    /// `base_fee_per_gas` does not match the value derived from the parent.
    fn stamp_genesis_edge_base_fee(mut block: Block) -> Block {
        use tenzro_types::block::FeeMarketParams;
        block.header.metadata.base_fee_per_gas = Some(FeeMarketParams::default().initial_base_fee);
        block
    }

    /// Build a synthetic genesis block (height=0) suitable for satisfying the
    /// `validate_base_fee` parent lookup in tests. Mirrors the real genesis
    /// block stamp from `tenzro_node::genesis`: `gas_limit==0` triggers the
    /// genesis-edge in `calculate_next_base_fee`, so the child at height 1
    /// adopts `FeeMarketParams::default().initial_base_fee`.
    fn build_test_genesis() -> Block {
        use tenzro_types::block::{
            BlockHeader, BlockMetadata, ConsensusAlgorithm, ConsensusProof, FeeMarketParams,
        };
        use tenzro_types::primitives::Address;
        let mut header = BlockHeader::new_at_view(
            BlockHeight::from(0),
            0,
            Hash::default(),
            Hash::default(),
            Hash::default(),
            Address::new([0u8; 32]),
            ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
        );
        header.metadata = BlockMetadata {
            gas_used: 0,
            gas_limit: 0,
            tx_count: 0,
            protocol_version: 1,
            base_fee_per_gas: Some(FeeMarketParams::default().initial_base_fee),
        };
        Block::new(header, vec![])
    }

    /// Build a synthetic competing proposal at a fixed `height` and given
    /// `view`. Distinct views produce distinct block hashes, mirroring the
    /// single-height view churn that drives the OOM the count cap guards.
    fn build_test_block_at_view(height: u64, view: u64) -> Block {
        use tenzro_types::block::{BlockHeader, ConsensusAlgorithm, ConsensusProof};
        use tenzro_types::primitives::Address;
        let header = BlockHeader::new_at_view(
            BlockHeight::from(height),
            view,
            Hash::default(),
            Hash::default(),
            Hash::default(),
            Address::new([0u8; 32]),
            ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
        );
        Block::new(header, vec![])
    }

    #[test]
    fn evict_excess_blocks_keeps_highest_views() {
        // 100 competing proposals at one stuck height, views 0..100.
        let blocks: DashMap<Hash, Block> = DashMap::new();
        for view in 0..100u64 {
            let b = build_test_block_at_view(192_745, view);
            blocks.insert(b.hash(), b);
        }
        assert_eq!(blocks.len(), 100);

        let evicted = evict_excess_blocks_by_view(&blocks, 10);
        assert_eq!(evicted, 90);
        assert_eq!(blocks.len(), 10);

        // The 10 survivors must be the highest views (90..100): eviction
        // drops the stalest competing proposals first.
        let mut surviving_views: Vec<u64> = blocks.iter().map(|e| e.value().header.view).collect();
        surviving_views.sort_unstable();
        assert_eq!(surviving_views, (90..100).collect::<Vec<_>>());
    }

    #[test]
    fn evict_excess_blocks_noop_under_cap() {
        let blocks: DashMap<Hash, Block> = DashMap::new();
        for view in 0..50u64 {
            let b = build_test_block_at_view(192_745, view);
            blocks.insert(b.hash(), b);
        }
        let evicted = evict_excess_blocks_by_view(&blocks, 4096);
        assert_eq!(evicted, 0);
        assert_eq!(blocks.len(), 50);
    }

    /// Regression test for the height=0 testnet wedge surfaced 2026-04-28.
    ///
    /// Failure mode: a previous run of the validator votes through views
    /// 0..62 at height=1 without ever finalizing (because the gossipsub mesh
    /// was not warm). `PersistentVoteState` correctly records the highest
    /// vote (view=62, height=1) before the pod restarts. On restart, the new
    /// run resets `current_view` to 0 — but `vote_state.rs::check_vrs`
    /// (the height-round-step check) refuses every vote whose `(view, height, step)`
    /// is not strictly past the persisted tuple. Since 0..62 are all <= 62
    /// at the same height, EVERY vote the new run tries to cast is refused
    /// as "double-sign prevented", and the chain wedges at height=0 forever.
    ///
    /// `resume_from_height` must consult `vote_state_store` and jump the
    /// local view past the persisted last-vote view at the same height.
    #[tokio::test]
    async fn test_resume_from_height_jumps_view_past_persisted_vote() {
        use crate::vote_state::{LastSignState, MemoryVoteStateStore, VoteStateStore, VoteStep};
        use tenzro_types::primitives::Hash;

        // Pre-load a vote state store with a vote at (view=62, height=1) — the
        // exact shape observed in the live testnet logs at 2026-04-28T08:20:Z.
        let store = Arc::new(MemoryVoteStateStore::new());
        let persisted = LastSignState {
            version: 1,
            view: 62,
            height: 1,
            step: VoteStep::Prepare,
            block_hash: Some(Hash::default()),
            signature: Some(vec![0u8; 64]),
        };
        store.record(&persisted).expect("record");

        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pq = MlDsaSigningKey::generate();
        let bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
        let config = ConsensusConfig::default();
        let validators = create_test_validators(4);
        let epoch_manager = EpochManager::new(validators, 100).unwrap();
        let engine = HotStuff2Engine::new(keypair, pq, bls, config, epoch_manager)
            .with_vote_state_store(store);

        // Storage tip is height=0 (nothing finalized) — exactly the testnet
        // boot state. Without the fix, view stays at 0 and every vote at
        // (view≤62, height=1) is refused. With the fix, view jumps to 63.
        engine.resume_from_height(BlockHeight(0));

        let state = engine.view_state.read();
        assert_eq!(
            state.height,
            BlockHeight(1),
            "height must advance to 1 (next-to-propose)"
        );
        assert!(
            state.view >= 63,
            "view must jump past persisted last_vote view=62 to avoid CheckHRS wedge — got view={}",
            state.view
        );
    }

    /// Regression test for the **cross-height** view-restoration wedge
    /// surfaced 2026-04-30 on testnet (validator-2 logs showed persisted
    /// `(view=29999, height=29988, Commit)` while `next_height=29989`).
    ///
    /// Failure mode: the persisted `(view, height)` tuple is
    /// `(29999, 29988)` — a vote cast in the previous run at the *just-
    /// finalized* height. On restart, the storage tip is height 29988,
    /// so `next_height = 29989`. The previous guard (`persisted.height
    /// == next_height.0`) was `29988 == 29989` — false — so the view
    /// jump was skipped. The engine booted at view ~29988, advanced via
    /// 700 ms timeouts, and got refused by `vote_state.rs::check_vrs`
    /// for every view ≤ 29999 → wedge.
    ///
    /// Fix: adopt the persisted view ceiling **unconditionally**.
    /// `persisted.view` is a height-independent strict signing floor
    /// (`last_voted_round` is checked against `round`,
    /// never against `(round, height)`).
    #[tokio::test]
    async fn test_resume_from_height_jumps_view_past_persisted_vote_cross_height() {
        use crate::vote_state::{LastSignState, MemoryVoteStateStore, VoteStateStore, VoteStep};
        use tenzro_types::primitives::Hash;

        // Pre-load a vote state store with a vote at (view=29999, height=29988, Commit)
        // — exactly the shape observed in the live testnet logs at 2026-04-30.
        let store = Arc::new(MemoryVoteStateStore::new());
        let persisted = LastSignState {
            version: 1,
            view: 29999,
            height: 29988,
            step: VoteStep::Commit,
            block_hash: Some(Hash::default()),
            signature: Some(vec![0u8; 64]),
        };
        store.record(&persisted).expect("record");

        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pq = MlDsaSigningKey::generate();
        let bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
        let config = ConsensusConfig::default();
        let validators = create_test_validators(4);
        let epoch_manager = EpochManager::new(validators, 100).unwrap();
        let engine = HotStuff2Engine::new(keypair, pq, bls, config, epoch_manager)
            .with_vote_state_store(store);

        // Storage tip is 29988 (just-finalized at the moment of the previous vote).
        // next_height becomes 29989 — different from persisted.height. Without the
        // fix, the view-jump guard (`persisted.height == next_height.0`) was false
        // → engine booted at view ~29988 → wedge.
        engine.resume_from_height(BlockHeight(29988));

        let state = engine.view_state.read();
        assert_eq!(
            state.height,
            BlockHeight(29989),
            "height must advance to 29989 (next-to-propose)"
        );
        assert!(
            state.view >= 30000,
            "view must jump past persisted last_vote view=29999 even when \
             persisted.height ({}) != next_height ({}) — got view={}",
            persisted.height,
            29989,
            state.view
        );
    }

    /// Regression test for the **high_qc_view restoration** live-lock
    /// surfaced 2026-05-23 on testnet (block height stalled at 55,539 for
    /// 4 days across all 10 validators).
    ///
    /// Failure mode: validators reboot from storage tip=55,539 (a block
    /// finalized via Commit-QC at some view V ~= 239,800). The old
    /// `resume_from_height` only consulted `vote_state_store` for the
    /// **signing** ceiling — it did NOT restore `high_qc_view` (the
    /// **locking** ceiling). After the resume, `high_qc_view` defaulted
    /// to 0. The leader at view N proposed a block extending a stale
    /// parent (because its lock was unrestored), peers refused to vote
    /// because their locks were at the correct higher view, the view
    /// timed out, NEC formed, and the cycle repeated forever —
    /// observable as `DOUBLE-SIGN PREVENTED` at multiple views with
    /// vote heights spanning 49,282..55,540.
    ///
    /// Fix (the Safety-Rules pattern): on boot, read the latest
    /// finalized block via the wired `BlockProvider`, extract
    /// `header.view` (the certifying Commit-QC view), and restore
    /// `high_qc_view` to that value. Mirrors `resume_from_synced_height`'s
    /// behavior but recovers the QC view from storage instead of taking
    /// it as a parameter.
    #[tokio::test]
    async fn test_resume_from_height_restores_high_qc_view_from_block_header() {
        use tenzro_types::block::{
            BlockHeader, BlockMetadata, ConsensusAlgorithm, ConsensusProof, FeeMarketParams,
        };
        use tenzro_types::primitives::{Address, Hash};

        // Minimal in-memory BlockProvider that returns a single block at a
        // configured height with a configured certifying view.
        struct TestBlockProvider {
            height: BlockHeight,
            view: u64,
        }
        impl BlockProvider for TestBlockProvider {
            fn get_block(&self, height: BlockHeight) -> Option<Block> {
                if height != self.height {
                    return None;
                }
                let mut header = BlockHeader::new_at_view(
                    self.height,
                    self.view,
                    Hash::default(),
                    Hash::default(),
                    Hash::default(),
                    Address::new([0u8; 32]),
                    ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
                );
                header.metadata = BlockMetadata {
                    gas_used: 0,
                    gas_limit: 30_000_000,
                    tx_count: 0,
                    protocol_version: 1,
                    base_fee_per_gas: Some(FeeMarketParams::default().initial_base_fee),
                };
                Some(Block::new(header, vec![]))
            }
        }

        let stored_height = BlockHeight(55_539);
        let certifying_view: u64 = 239_800;

        let provider: Arc<dyn BlockProvider> = Arc::new(TestBlockProvider {
            height: stored_height,
            view: certifying_view,
        });
        let store = Arc::new(crate::vote_state::MemoryVoteStateStore::new());

        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pq = MlDsaSigningKey::generate();
        let bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
        let config = ConsensusConfig::default();
        let validators = create_test_validators(4);
        let epoch_manager = EpochManager::new(validators, 100).unwrap();
        let engine = HotStuff2Engine::new(keypair, pq, bls, config, epoch_manager)
            .with_block_provider(provider)
            .with_vote_state_store(store.clone());

        // Before resume: high_qc_view defaults to 0.
        assert_eq!(*engine.high_qc_view.read(), 0);

        engine.resume_from_height(stored_height);

        // After resume: high_qc_view must be restored to the certifying view.
        assert_eq!(
            *engine.high_qc_view.read(),
            certifying_view,
            "high_qc_view must be restored to the certifying Commit-QC view of the latest finalized block"
        );

        // Current view must be > certifying view so the engine cannot
        // propose or vote at any view ≤ the view that already produced a
        // Commit-QC.
        let state = engine.view_state.read();
        assert_eq!(
            state.height,
            BlockHeight(55_540),
            "height must advance to next-to-propose"
        );
        assert!(
            state.view > certifying_view,
            "view must be > certifying_view={} — got view={}",
            certifying_view,
            state.view
        );
        drop(state);

        // The synthetic LastSignState must have been recorded so that a
        // crash-and-restart cannot regress the signing ceiling below the
        // certified state.
        use crate::vote_state::VoteStateStore;
        let persisted = store
            .load()
            .expect("synthetic LastSignState must be recorded");
        assert_eq!(
            persisted.view, certifying_view,
            "synthetic LastSignState.view must equal certifying_view"
        );
        assert_eq!(
            persisted.height, stored_height.0,
            "synthetic LastSignState.height must equal stored_height"
        );
    }

    #[tokio::test]
    async fn test_hotstuff2_creation() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pq = MlDsaSigningKey::generate();
        let bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
        let config = ConsensusConfig::default();
        let validators = create_test_validators(4);
        let epoch_manager = EpochManager::new(validators, 100).unwrap();

        let engine = HotStuff2Engine::new(keypair, pq, bls, config, epoch_manager);
        assert_eq!(engine.finalized_height().await, BlockHeight::from(0));
    }

    #[tokio::test]
    async fn test_empty_block_suppression_gate() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pq = MlDsaSigningKey::generate();
        let bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
        // Short heartbeat so the test doesn't sleep for the 5s default.
        let config = ConsensusConfig::default().with_empty_block_heartbeat(50);
        let validators = create_test_validators(4);
        let epoch_manager = EpochManager::new(validators, 100).unwrap();
        let engine = HotStuff2Engine::new(keypair, pq, bls, config, epoch_manager);

        // Fresh engine, empty mempool, no TC, clock just reset: within the
        // heartbeat window → suppress.
        engine.mark_block_proposed();
        assert!(
            !engine.should_propose_now(),
            "idle + within heartbeat window must suppress"
        );

        // After the heartbeat interval elapses → propose a keepalive.
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert!(
            engine.should_propose_now(),
            "heartbeat elapsed must allow a keepalive proposal"
        );

        // An UNHANDLED pending TC forces a proposal (QC-chain / liveness
        // priority), even immediately after a fresh block. A TC at view 10
        // has recovery view 11; last_proposed_view is still 0, so it's
        // unhandled.
        engine.mark_block_proposed();
        assert!(!engine.should_propose_now());
        *engine.last_round_tc.write() = Some(crate::timeout::TimeoutCertificate {
            format_version: crate::timeout::TIMEOUT_CERTIFICATE_FORMAT_VERSION,
            view: 10,
            signers: Vec::new(),
        });
        assert!(
            engine.should_propose_now(),
            "unhandled pending TC must never be suppressed"
        );

        // But a TC we've ALREADY extended past (last_proposed_view >=
        // tc.view + 1) must NOT keep defeating suppression — otherwise a
        // chain that times out frequently never suppresses. With the TC at
        // view 10 and last_proposed_view bumped to 11, the recovery is
        // handled, so we fall through to the heartbeat check (just reset →
        // suppress).
        engine
            .last_proposed_view
            .store(11, std::sync::atomic::Ordering::SeqCst);
        engine.mark_block_proposed();
        assert!(
            !engine.should_propose_now(),
            "an already-handled (extended-past) TC must not defeat suppression"
        );
        *engine.last_round_tc.write() = None;
        engine
            .last_proposed_view
            .store(0, std::sync::atomic::Ordering::SeqCst);

        // Disabling suppression (heartbeat = 0) restores always-on
        // production regardless of mempool/clock.
        let config_off = ConsensusConfig::default().with_empty_block_heartbeat(0);
        let validators2 = create_test_validators(4);
        let epoch2 = EpochManager::new(validators2, 100).unwrap();
        let kp2 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pq2 = MlDsaSigningKey::generate();
        let bls2 = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
        let engine_off = HotStuff2Engine::new(kp2, pq2, bls2, config_off, epoch2);
        engine_off.mark_block_proposed();
        assert!(
            engine_off.should_propose_now(),
            "suppression disabled must always propose"
        );
    }

    #[tokio::test]
    async fn test_leader_selection() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pq = MlDsaSigningKey::generate();
        let bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
        let crypto_addr = keypair.address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = tenzro_types::primitives::Address::new(addr_bytes);

        let validators = vec![
            ValidatorInfo::new(
                address,
                keypair.public_key().clone(),
                pq.verifying_key_bytes().to_vec(),
                bls.public_key().to_bytes().to_vec(),
                1000,
            ),
            create_test_validators(3)[0].clone(),
        ];

        let config = ConsensusConfig::default();
        let epoch_manager = EpochManager::new(validators, 100).unwrap();

        let engine = HotStuff2Engine::new(keypair, pq, bls, config, epoch_manager);
        let leader = engine.get_leader().unwrap();

        // Leader should be one of the validators
        assert!(engine.validator_set().is_validator(&leader));
    }

    /// Helper: build an engine where `validators[0]` is this node, plus
    /// `extra` additional validators. Returns the engine and the address of
    /// validators[1] (a remote validator we use as a proposer in tests).
    async fn build_test_engine(
        extra: usize,
    ) -> (
        HotStuff2Engine,
        KeyPair,
        MlDsaSigningKey,
        tenzro_types::primitives::Address,
    ) {
        let mut validators = create_test_validators(extra + 1);
        let local_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let local_pq = MlDsaSigningKey::generate();
        let local_bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
        let local_crypto_addr = local_keypair.address();
        let mut local_addr_bytes = [0u8; 32];
        local_addr_bytes[..20].copy_from_slice(local_crypto_addr.as_bytes());
        let local_address = tenzro_types::primitives::Address::new(local_addr_bytes);
        validators[0] = ValidatorInfo::new(
            local_address,
            local_keypair.public_key().clone(),
            local_pq.verifying_key_bytes().to_vec(),
            local_bls.public_key().to_bytes().to_vec(),
            1000,
        );
        // Replace validators[1] with a proposer whose signing keys the test
        // retains — `on_proposal` verifies the proposer's hybrid signature
        // against the registered key, so tests must sign proposals for real.
        let proposer_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let proposer_pq = MlDsaSigningKey::generate();
        let proposer_bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
        let proposer_crypto_addr = proposer_keypair.address();
        let mut proposer_addr_bytes = [0u8; 32];
        proposer_addr_bytes[..20].copy_from_slice(proposer_crypto_addr.as_bytes());
        let proposer_addr = tenzro_types::primitives::Address::new(proposer_addr_bytes);
        validators[1] = ValidatorInfo::new(
            proposer_addr,
            proposer_keypair.public_key().clone(),
            proposer_pq.verifying_key_bytes().to_vec(),
            proposer_bls.public_key().to_bytes().to_vec(),
            1000,
        );

        let config = ConsensusConfig::default();
        let epoch_manager = EpochManager::new(validators, 100).unwrap();
        let mut engine =
            HotStuff2Engine::new(local_keypair, local_pq, local_bls, config, epoch_manager);

        // Wire a synthetic genesis block at height 0 so EIP-1559
        // `validate_base_fee` can re-derive the child's base fee from a
        // genesis-edge parent. Real production wires `NodeBlockProvider`.
        let block_provider = Arc::new(TestBlockProvider::new());
        block_provider.insert(build_test_genesis());
        engine = engine.with_block_provider(block_provider);

        // Initialize the vote collector — `on_proposal` exercises it via
        // `handle_prepare_phase`. This is what `start()` does, but we don't
        // want to spawn the consensus loop in tests.
        let validator_set = Arc::new(engine.validator_set());
        *engine.vote_collector.write() = Some(Arc::new(VoteCollector::new(validator_set.clone())));
        *engine.timeout_collector.write() = Some(Arc::new(crate::timeout::TimeoutCollector::new(
            validator_set.clone(),
        )));
        *engine.nec_collector.write() = Some(Arc::new(
            crate::timeout::NoEndorsementCollector::new(validator_set),
        ));

        (engine, proposer_keypair, proposer_pq, proposer_addr)
    }

    /// Hybrid-sign the canonical proposal payload for `block` "from" the
    /// given signer, mirroring the propose path in `handle_prepare_phase`.
    fn peer_sign_proposal(
        block: &tenzro_types::block::Block,
        high_qc_view: u64,
        keypair: &KeyPair,
        pq: &MlDsaSigningKey,
    ) -> tenzro_crypto::composite::CompositeSignature {
        let payload = crate::validator::proposal_signing_payload(
            block.header.view,
            block.header.height.0,
            &block.hash(),
            high_qc_view,
        );
        let kp_copy = KeyPair::from_bytes(keypair.key_type(), &keypair.to_bytes()).unwrap();
        let classical = Ed25519SignerImpl::new(kp_copy).unwrap();
        let pq_copy = MlDsaSigningKey::from_seed(pq.seed_bytes()).unwrap();
        let hybrid = InMemoryHybridSigner::new(Box::new(classical), pq_copy);
        hybrid.sign(&payload).unwrap()
    }

    /// Regression test for the height=0 testnet bug: when a proposal arrives at
    /// a higher view than the local view, `on_proposal` must advance the local
    /// view to match the proposer's view BEFORE constructing the vote, so the
    /// vote is bucketed at the proposer's view and a quorum can form.
    ///
    /// Follows the `ensure_round_and_sync_up` pattern and the HotStuff-2
    /// Pacemaker rule.
    ///
    /// Without the fix: each validator votes at its own drifted view, votes
    /// scatter across view-buckets, and no view ever reaches the threshold.
    #[tokio::test]
    async fn test_on_proposal_advances_local_view_to_match_proposer() {
        use tenzro_types::block::{Block, BlockHeader, ConsensusAlgorithm, ConsensusProof};
        use tenzro_types::primitives::{BlockHeight, Hash};

        let (engine, proposer_kp, proposer_pq, proposer_addr) = build_test_engine(3).await;

        // Find a view the proposer is actually elected to lead. Leader
        // election is a seeded weighted draw, so the concrete view number is
        // incidental to what this test checks (view-sync on a next-view
        // proposal) — hardcoding a magic view couples the test to the exact
        // weighting math. Scan for the first view >= 2 that elects the
        // proposer; drive local view to `proposer_view - 1`.
        let proposer_view = (2u64..1000)
            .find(|&v| {
                engine
                    .leader_for_view(v)
                    .map(|l| l == proposer_addr)
                    .unwrap_or(false)
            })
            .expect("proposer is elected leader for some view in range");
        let local_view = proposer_view - 1;

        // Simulate the testnet failure mode: this node's local view is one
        // behind the proposer's (the canonical happy-path next-view case;
        // larger view jumps require a TC and are covered in a dedicated
        // safe_to_extend test).
        {
            let mut state = engine.view_state.write();
            state.view = local_view;
            state.height = BlockHeight::from(1);
            state.phase = Phase::Prepare;
        }

        // Build a proposal at height=1, view=proposer_view from `proposer_addr`.
        let header = BlockHeader::new_at_view(
            BlockHeight::from(1),
            proposer_view,
            Hash::default(),
            Hash::default(),
            Hash::default(),
            proposer_addr,
            ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
        );
        let block = stamp_genesis_edge_base_fee(Block::new(header, vec![]));
        let sig = peer_sign_proposal(&block, 0, &proposer_kp, &proposer_pq);

        // Process the proposal — should advance local view AND produce a vote.
        let vote = engine
            .on_proposal(&block, None, None, 0, &sig)
            .await
            .expect("on_proposal succeeded");

        // The vote MUST be stamped at the proposer's view, not the stale
        // local view. This is the entire point of the fix.
        assert_eq!(
            vote.view, proposer_view,
            "vote must be stamped at proposer's view ({proposer_view}), got {} — \
             without view-sync, votes from drifted-view validators never \
             form a quorum (testnet height=0 bug)",
            vote.view
        );

        // Local view state must have been advanced.
        let final_view = engine.view_state.read().view;
        assert_eq!(
            final_view, proposer_view,
            "local view must advance to proposer's view, got {final_view}",
        );
    }

    /// Stale proposals (proposer at a STRICTLY lower view than local) must be
    /// rejected — voting on them would re-introduce the bucketing bug.
    #[tokio::test]
    async fn test_on_proposal_rejects_stale_view() {
        use tenzro_types::block::{Block, BlockHeader, ConsensusAlgorithm, ConsensusProof};
        use tenzro_types::primitives::{BlockHeight, Hash};

        let (engine, proposer_kp, proposer_pq, proposer_addr) = build_test_engine(3).await;

        // Local view is well ahead of an inbound stale proposal.
        {
            let mut state = engine.view_state.write();
            state.view = 20;
            state.height = BlockHeight::from(1);
            state.phase = Phase::Prepare;
        }

        let header = BlockHeader::new_at_view(
            BlockHeight::from(1),
            5, // stale view
            Hash::default(),
            Hash::default(),
            Hash::default(),
            proposer_addr,
            ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
        );
        let block = Block::new(header, vec![]);
        let sig = peer_sign_proposal(&block, 0, &proposer_kp, &proposer_pq);

        let result = engine.on_proposal(&block, None, None, 0, &sig).await;
        assert!(
            matches!(result, Err(ConsensusError::InvalidProposal(_))),
            "stale proposal must be rejected, got {:?}",
            result
        );

        // Local view must be unchanged.
        assert_eq!(engine.view_state.read().view, 20);
    }

    /// Helper: build an engine plus the keypairs and PQ keys for the OTHER
    /// validators (so tests can hybrid-sign a TimeoutMsg "from" a peer).
    /// Returns (engine, peer_keypair, peer_pq_key, peer_address).
    async fn build_test_engine_with_peer_signer() -> (
        HotStuff2Engine,
        KeyPair,
        MlDsaSigningKey,
        tenzro_types::primitives::Address,
    ) {
        // Inline the body of `create_test_validators` + `build_test_engine`
        // so the peer's keypair stays in scope for the test to sign with.
        let local_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let local_pq = MlDsaSigningKey::generate();
        let local_bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
        let local_crypto_addr = local_keypair.address();
        let mut local_addr_bytes = [0u8; 32];
        local_addr_bytes[..20].copy_from_slice(local_crypto_addr.as_bytes());
        let local_address = tenzro_types::primitives::Address::new(local_addr_bytes);
        let local_validator = ValidatorInfo::new(
            local_address,
            local_keypair.public_key().clone(),
            local_pq.verifying_key_bytes().to_vec(),
            local_bls.public_key().to_bytes().to_vec(),
            1000,
        );

        let peer_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let peer_pq = MlDsaSigningKey::generate();
        let peer_bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
        let peer_crypto_addr = peer_keypair.address();
        let mut peer_addr_bytes = [0u8; 32];
        peer_addr_bytes[..20].copy_from_slice(peer_crypto_addr.as_bytes());
        let peer_address = tenzro_types::primitives::Address::new(peer_addr_bytes);
        let peer_validator = ValidatorInfo::new(
            peer_address,
            peer_keypair.public_key().clone(),
            peer_pq.verifying_key_bytes().to_vec(),
            peer_bls.public_key().to_bytes().to_vec(),
            2000,
        );

        // Two extra filler validators so the set is realistic (4 total => f=1)
        let mut validators = vec![local_validator, peer_validator];
        for i in 0..2 {
            let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
            let crypto_addr = kp.address();
            let mut addr_bytes = [0u8; 32];
            addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
            let addr = tenzro_types::primitives::Address::new(addr_bytes);
            let pq = MlDsaSigningKey::generate();
            let bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
            validators.push(ValidatorInfo::new(
                addr,
                kp.public_key().clone(),
                pq.verifying_key_bytes().to_vec(),
                bls.public_key().to_bytes().to_vec(),
                1000 * (i as u128 + 1),
            ));
        }

        let config = ConsensusConfig::default();
        let epoch_manager = EpochManager::new(validators, 100).unwrap();
        let mut engine =
            HotStuff2Engine::new(local_keypair, local_pq, local_bls, config, epoch_manager);

        // Wire a synthetic genesis block at height 0 so EIP-1559
        // `validate_base_fee` can re-derive the child's base fee.
        let block_provider = Arc::new(TestBlockProvider::new());
        block_provider.insert(build_test_genesis());
        engine = engine.with_block_provider(block_provider);

        let validator_set = Arc::new(engine.validator_set());
        *engine.vote_collector.write() = Some(Arc::new(VoteCollector::new(validator_set.clone())));
        *engine.timeout_collector.write() = Some(Arc::new(crate::timeout::TimeoutCollector::new(
            validator_set.clone(),
        )));
        *engine.nec_collector.write() = Some(Arc::new(
            crate::timeout::NoEndorsementCollector::new(validator_set),
        ));

        (engine, peer_keypair, peer_pq, peer_address)
    }

    /// Hybrid-sign a TimeoutMsg "from" the given peer for the given view.
    fn peer_sign_timeout(
        view: u64,
        peer_address: tenzro_types::primitives::Address,
        peer_keypair: &KeyPair,
        peer_pq: &MlDsaSigningKey,
    ) -> crate::timeout::TimeoutMsg {
        peer_sign_timeout_with_hqc(
            view,
            view.saturating_sub(1),
            peer_address,
            peer_keypair,
            peer_pq,
        )
    }

    /// Hybrid-sign a TimeoutMsg with an explicit `high_qc_view` (must be `< view`).
    fn peer_sign_timeout_with_hqc(
        view: u64,
        high_qc_view: u64,
        peer_address: tenzro_types::primitives::Address,
        peer_keypair: &KeyPair,
        peer_pq: &MlDsaSigningKey,
    ) -> crate::timeout::TimeoutMsg {
        peer_sign_timeout_full(view, high_qc_view, 0, peer_address, peer_keypair, peer_pq)
    }

    /// Hybrid-sign a TimeoutMsg with explicit `high_qc_view` and
    /// `finalized_height`.
    fn peer_sign_timeout_full(
        view: u64,
        high_qc_view: u64,
        finalized_height: u64,
        peer_address: tenzro_types::primitives::Address,
        peer_keypair: &KeyPair,
        peer_pq: &MlDsaSigningKey,
    ) -> crate::timeout::TimeoutMsg {
        use tenzro_crypto::composite::{
            CompositePublicKey, CompositeSignature, HybridSigner, InMemoryHybridSigner,
        };
        use tenzro_crypto::signatures::Ed25519SignerImpl;

        let composite_pk = CompositePublicKey::new(
            peer_keypair.public_key().clone(),
            peer_pq.verifying_key_bytes().to_vec(),
        );
        let placeholder = CompositeSignature::new(Vec::new(), Vec::new());
        let unsigned = crate::timeout::TimeoutMsg::new(
            view,
            high_qc_view,
            finalized_height,
            peer_address,
            placeholder,
            composite_pk.clone(),
        );
        let payload = unsigned.signing_payload();

        let kp_bytes = peer_keypair.to_bytes();
        let kp_copy = KeyPair::from_bytes(peer_keypair.key_type(), &kp_bytes).unwrap();
        let classical = Ed25519SignerImpl::new(kp_copy).unwrap();
        let pq_copy = MlDsaSigningKey::from_seed(peer_pq.seed_bytes()).unwrap();
        let signer = InMemoryHybridSigner::new(Box::new(classical), pq_copy);

        let signature = signer.sign(&payload).unwrap();
        crate::timeout::TimeoutMsg::new(
            view,
            high_qc_view,
            finalized_height,
            peer_address,
            signature,
            composite_pk,
        )
    }

    /// Hybrid-sign a NoEndorsementMsg "from" the given peer for the given view.
    fn peer_sign_no_endorsement(
        view: u64,
        peer_address: tenzro_types::primitives::Address,
        peer_keypair: &KeyPair,
        peer_pq: &MlDsaSigningKey,
    ) -> crate::timeout::NoEndorsementMsg {
        use tenzro_crypto::composite::{
            CompositePublicKey, CompositeSignature, HybridSigner, InMemoryHybridSigner,
        };
        use tenzro_crypto::signatures::Ed25519SignerImpl;

        let composite_pk = CompositePublicKey::new(
            peer_keypair.public_key().clone(),
            peer_pq.verifying_key_bytes().to_vec(),
        );
        let placeholder = CompositeSignature::new(Vec::new(), Vec::new());
        let unsigned = crate::timeout::NoEndorsementMsg::new(
            view,
            peer_address,
            placeholder,
            composite_pk.clone(),
        );
        let payload = unsigned.signing_payload();

        let kp_bytes = peer_keypair.to_bytes();
        let kp_copy = KeyPair::from_bytes(peer_keypair.key_type(), &kp_bytes).unwrap();
        let classical = Ed25519SignerImpl::new(kp_copy).unwrap();
        let pq_copy = MlDsaSigningKey::from_seed(peer_pq.seed_bytes()).unwrap();
        let signer = InMemoryHybridSigner::new(Box::new(classical), pq_copy);

        let signature = signer.sign(&payload).unwrap();
        crate::timeout::NoEndorsementMsg::new(view, peer_address, signature, composite_pk)
    }

    /// Receiving a TimeoutMsg at a strictly higher view must advance the
    /// local view counter — this is the backward-sync channel
    /// (#164).
    #[tokio::test]
    async fn test_on_timeout_msg_advances_local_view() {
        use tenzro_types::primitives::BlockHeight;

        let (engine, peer_kp, peer_pq, peer_addr) = build_test_engine_with_peer_signer().await;

        // Local view stuck at 5; peer is at 17.
        {
            let mut state = engine.view_state.write();
            state.view = 5;
            state.height = BlockHeight::from(1);
            state.phase = Phase::Commit; // arbitrary mid-phase state
            state.proposed_block = None;
        }

        let msg = peer_sign_timeout(17, peer_addr, &peer_kp, &peer_pq);
        engine
            .on_timeout_msg(&msg)
            .await
            .expect("valid timeout accepted");

        let state = engine.view_state.read();
        assert_eq!(state.view, 17, "local view advances to peer view");
        assert!(
            matches!(state.phase, Phase::Prepare),
            "phase reset to Prepare"
        );
        assert!(state.prepare_qc.is_none(), "stale prepare QC cleared");
        assert!(state.commit_qc.is_none(), "stale commit QC cleared");
    }

    /// Receiving a TimeoutMsg at a *lower* view must be a no-op — this is
    /// the downgrade-attack defence: a peer cannot drag us backwards.
    #[tokio::test]
    async fn test_on_timeout_msg_ignores_lower_view() {
        let (engine, peer_kp, peer_pq, peer_addr) = build_test_engine_with_peer_signer().await;

        {
            let mut state = engine.view_state.write();
            state.view = 50;
        }

        let msg = peer_sign_timeout(20, peer_addr, &peer_kp, &peer_pq);
        engine
            .on_timeout_msg(&msg)
            .await
            .expect("verified timeout silently ignored");

        assert_eq!(engine.view_state.read().view, 50, "local view unchanged");
    }

    /// A verified TimeoutMsg advertising a finalized height above ours must
    /// fire the behind-hint watch channel — this is the finalization-skew
    /// heal: the sender finalized a block (via a Commit QC we missed) and
    /// block-sync must fetch it, or the view deadlocks forever on the
    /// proposer re-proposing a conflicting block at that height.
    #[tokio::test]
    async fn test_on_timeout_msg_fires_behind_hint_on_higher_finalized_height() {
        let (engine, peer_kp, peer_pq, peer_addr) = build_test_engine_with_peer_signer().await;

        let mut hint_rx = engine.subscribe_behind_hint();
        assert_eq!(
            *hint_rx.borrow_and_update(),
            0,
            "no hint before any timeout"
        );

        // Peer claims finalized height 7; our fresh tracker is at 0.
        let msg = peer_sign_timeout_full(17, 16, 7, peer_addr, &peer_kp, &peer_pq);
        engine
            .on_timeout_msg(&msg)
            .await
            .expect("valid timeout accepted");

        assert!(hint_rx.has_changed().unwrap(), "behind-hint fired");
        assert_eq!(
            *hint_rx.borrow_and_update(),
            7,
            "hint carries peer finalized height"
        );

        // A second timeout advertising a height we already match must NOT
        // re-fire (peer height 0 == local 0 is not strictly greater).
        let msg2 = peer_sign_timeout_full(18, 17, 0, peer_addr, &peer_kp, &peer_pq);
        engine
            .on_timeout_msg(&msg2)
            .await
            .expect("valid timeout accepted");
        assert!(!hint_rx.has_changed().unwrap(), "no hint when not behind");
    }

    /// A TimeoutMsg with a tampered view (signature won't bind) must be
    /// rejected by the engine — this is the spoofing defence.
    #[tokio::test]
    async fn test_on_timeout_msg_rejects_tampered_signature() {
        let (engine, peer_kp, peer_pq, peer_addr) = build_test_engine_with_peer_signer().await;

        {
            let mut state = engine.view_state.write();
            state.view = 5;
        }

        let mut msg = peer_sign_timeout(20, peer_addr, &peer_kp, &peer_pq);
        msg.view = 99; // mutate after signing — signature no longer binds

        let err = engine
            .on_timeout_msg(&msg)
            .await
            .expect_err("tampered timeout must be rejected");
        assert!(
            matches!(err, ConsensusError::InvalidSignature(_)),
            "got {err:?}"
        );

        assert_eq!(
            engine.view_state.read().view,
            5,
            "view unchanged on bad sig"
        );
    }

    /// Builds a 4-validator engine and returns the local engine + every
    /// signer's (keypair, pq_key, bls_keypair, address). Entries 0..3 are the
    /// three peer validators; the final entry is the LOCAL validator's keys
    /// (the engine holds copies), so tests can sign artifacts as whichever
    /// validator gets elected leader — including the local one. This enables
    /// tests that need to construct multi-signer artifacts (TCs) without
    /// going through the gossip layer.
    async fn build_test_engine_with_all_signers() -> (
        HotStuff2Engine,
        Vec<(
            KeyPair,
            MlDsaSigningKey,
            tenzro_crypto::bls::BlsKeyPair,
            tenzro_types::primitives::Address,
        )>,
    ) {
        let mut peers = Vec::new();
        let mut validators = Vec::new();

        // Local validator (index 0).
        let local_kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let local_pq = MlDsaSigningKey::generate();
        let local_bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
        let local_crypto_addr = local_kp.address();
        let mut local_addr_bytes = [0u8; 32];
        local_addr_bytes[..20].copy_from_slice(local_crypto_addr.as_bytes());
        let local_addr = tenzro_types::primitives::Address::new(local_addr_bytes);
        validators.push(ValidatorInfo::new(
            local_addr,
            local_kp.public_key().clone(),
            local_pq.verifying_key_bytes().to_vec(),
            local_bls.public_key().to_bytes().to_vec(),
            1000,
        ));

        // 3 peers (indices 1..3).
        for i in 0..3 {
            let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
            let pq = MlDsaSigningKey::generate();
            let bls = tenzro_crypto::bls::BlsKeyPair::generate().unwrap();
            let crypto_addr = kp.address();
            let mut addr_bytes = [0u8; 32];
            addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
            let addr = tenzro_types::primitives::Address::new(addr_bytes);
            validators.push(ValidatorInfo::new(
                addr,
                kp.public_key().clone(),
                pq.verifying_key_bytes().to_vec(),
                bls.public_key().to_bytes().to_vec(),
                1000 * (i as u128 + 2),
            ));
            peers.push((kp, pq, bls, addr));
        }

        let local_kp_for_engine =
            KeyPair::from_bytes(local_kp.key_type(), &local_kp.to_bytes()).unwrap();
        let local_pq_for_engine = MlDsaSigningKey::from_seed(local_pq.seed_bytes()).unwrap();
        let local_bls_for_engine = tenzro_crypto::bls::BlsKeyPair::from_secret_key(
            tenzro_crypto::bls::BlsSecretKey::from_bytes(&local_bls.secret_key().to_bytes())
                .unwrap(),
        );
        let config = ConsensusConfig::default();
        let epoch_manager = EpochManager::new(validators, 100).unwrap();
        let mut engine = HotStuff2Engine::new(
            local_kp_for_engine,
            local_pq_for_engine,
            local_bls_for_engine,
            config,
            epoch_manager,
        );

        // Wire a synthetic genesis block at height 0 so EIP-1559
        // `validate_base_fee` can re-derive the child's base fee. See
        // `build_test_genesis` for rationale.
        let block_provider = Arc::new(TestBlockProvider::new());
        block_provider.insert(build_test_genesis());
        engine = engine.with_block_provider(block_provider);

        let validator_set = Arc::new(engine.validator_set());
        *engine.vote_collector.write() = Some(Arc::new(VoteCollector::new(validator_set.clone())));
        *engine.timeout_collector.write() = Some(Arc::new(crate::timeout::TimeoutCollector::new(
            validator_set.clone(),
        )));
        *engine.nec_collector.write() = Some(Arc::new(
            crate::timeout::NoEndorsementCollector::new(validator_set),
        ));

        peers.push((local_kp, local_pq, local_bls, local_addr));
        (engine, peers)
    }

    /// Finds the signer tuple for `addr` in the vec returned by
    /// `build_test_engine_with_all_signers`.
    fn signer_for(
        peers: &[(
            KeyPair,
            MlDsaSigningKey,
            tenzro_crypto::bls::BlsKeyPair,
            tenzro_types::primitives::Address,
        )],
        addr: &tenzro_types::primitives::Address,
    ) -> (KeyPair, MlDsaSigningKey) {
        let (kp, pq, _, _) = peers
            .iter()
            .find(|(_, _, _, a)| a == addr)
            .expect("signer for address present in validator set");
        (
            KeyPair::from_bytes(kp.key_type(), &kp.to_bytes()).unwrap(),
            MlDsaSigningKey::from_seed(pq.seed_bytes()).unwrap(),
        )
    }

    /// safe_to_extend: a proposal at view V where V > local_view + 1
    /// must carry a valid TimeoutCertificate at view V-1 signed by 2f+1 validators.
    /// Without the TC, the proposal must be rejected — the leader could otherwise
    /// fork the chain by skipping views unilaterally.
    #[tokio::test]
    async fn test_on_proposal_rejects_view_jump_without_tc() {
        use tenzro_types::block::{Block, BlockHeader, ConsensusAlgorithm, ConsensusProof};
        use tenzro_types::primitives::{BlockHeight, Hash};

        let (engine, peers) = build_test_engine_with_all_signers().await;
        let proposer_addr = peers[0].3;

        // Local view 0; proposer jumps to view 5 with no TC.
        {
            let mut state = engine.view_state.write();
            state.view = 0;
            state.height = BlockHeight::from(1);
            state.phase = Phase::Prepare;
        }

        let header = BlockHeader::new_at_view(
            BlockHeight::from(1),
            5,
            Hash::default(),
            Hash::default(),
            Hash::default(),
            proposer_addr,
            ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
        );
        let block = Block::new(header, vec![]);
        let sig = peer_sign_proposal(&block, 0, &peers[0].0, &peers[0].1);

        let result = engine.on_proposal(&block, None, None, 0, &sig).await;
        assert!(
            matches!(result, Err(ConsensusError::InvalidProposal(_))),
            "view jump > 1 without TC must be rejected, got {:?}",
            result
        );
        assert_eq!(
            engine.view_state.read().view,
            0,
            "local view unchanged on rejection"
        );
    }

    /// safe_to_extend happy path: a proposal at view V > local_view + 1 with a
    /// valid TC for view V-1 must be accepted, and the local view advances.
    #[tokio::test]
    async fn test_on_proposal_accepts_view_jump_with_valid_tc() {
        use tenzro_types::block::{Block, BlockHeader, ConsensusAlgorithm, ConsensusProof};
        use tenzro_types::primitives::{BlockHeight, Hash};

        let (engine, peers) = build_test_engine_with_all_signers().await;
        // Proposer enforcement: the block must come from the elected leader
        // for its view, so derive the leader rather than hardcoding a peer.
        let proposer_addr = engine.leader_for_view(5).unwrap();

        // Local view 0; proposer jumps to view 5 with a TC at view 4 signed
        // by 3 of 4 validators (2f+1 with f=1).
        {
            let mut state = engine.view_state.write();
            state.view = 0;
            state.height = BlockHeight::from(1);
            state.phase = Phase::Prepare;
        }

        // Build 3 TimeoutMsgs at view 4 (with high_qc_view = 0) from the 3
        // peers, then assemble into a TC.
        let tc_view = 4u64;
        let mut signers: Vec<crate::timeout::TcSigner> = Vec::new();
        for (kp, pq, _bls, addr) in peers.iter() {
            let msg = peer_sign_timeout_with_hqc(tc_view, 0, *addr, kp, pq);
            signers.push(crate::timeout::TcSigner {
                voter: msg.voter,
                high_qc_view: msg.high_qc_view,
                finalized_height: msg.finalized_height,
                signature: msg.signature,
                public_key: msg.public_key,
            });
        }
        let tc = crate::timeout::TimeoutCertificate {
            format_version: crate::timeout::TIMEOUT_CERTIFICATE_FORMAT_VERSION,
            view: tc_view,
            signers,
        };

        // Build a NoEndorsementCertificate for view 4 (f+1 = 2 of 4 signers
        // suffice). NEC tail-fork defence: the proposer claims no QC
        // formed at the timed-out view, and must back that claim with an
        // f+1 attestation. Engine local high_qc_view is 0 < 4, consistent
        // with "no QC observed" so the NEC will be accepted.
        let mut nec_signers: Vec<crate::timeout::NecSigner> = Vec::new();
        for (kp, pq, _bls, addr) in peers.iter().take(2) {
            let nec_msg = peer_sign_no_endorsement(tc_view, *addr, kp, pq);
            nec_signers.push(crate::timeout::NecSigner {
                voter: nec_msg.voter,
                signature: nec_msg.signature,
                public_key: nec_msg.public_key,
            });
        }
        let nec = crate::timeout::NoEndorsementCertificate {
            format_version: crate::timeout::NO_ENDORSEMENT_CERTIFICATE_FORMAT_VERSION,
            view: tc_view,
            signers: nec_signers,
        };

        let header = BlockHeader::new_at_view(
            BlockHeight::from(1),
            5,
            Hash::default(),
            Hash::default(),
            Hash::default(),
            proposer_addr,
            ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
        );
        let block = stamp_genesis_edge_base_fee(Block::new(header, vec![]));
        let (leader_kp, leader_pq) = signer_for(&peers, &proposer_addr);
        let sig = peer_sign_proposal(&block, 0, &leader_kp, &leader_pq);

        let vote = engine
            .on_proposal(&block, Some(tc), Some(nec), 0, &sig)
            .await
            .expect("proposal with valid TC + NEC must be accepted");
        assert_eq!(vote.view, 5, "vote stamped at proposer's view");
        assert_eq!(engine.view_state.read().view, 5, "local view advanced");
    }

    /// A proposal carrying a TC for the wrong view (tc.view + 1 != proposal.view)
    /// must be rejected — even if the TC is otherwise well-formed.
    #[tokio::test]
    async fn test_on_proposal_rejects_tc_with_wrong_view() {
        use tenzro_types::block::{Block, BlockHeader, ConsensusAlgorithm, ConsensusProof};
        use tenzro_types::primitives::{BlockHeight, Hash};

        let (engine, peers) = build_test_engine_with_all_signers().await;
        let proposer_addr = peers[0].3;

        {
            let mut state = engine.view_state.write();
            state.view = 0;
            state.height = BlockHeight::from(1);
            state.phase = Phase::Prepare;
        }

        // TC is at view 3, but the proposal is at view 5 (gap of 2). Rejected
        // because tc.view + 1 (= 4) != proposal_view (= 5).
        let tc_view = 3u64;
        let mut signers: Vec<crate::timeout::TcSigner> = Vec::new();
        for (kp, pq, _bls, addr) in peers.iter() {
            let msg = peer_sign_timeout_with_hqc(tc_view, 0, *addr, kp, pq);
            signers.push(crate::timeout::TcSigner {
                voter: msg.voter,
                high_qc_view: msg.high_qc_view,
                finalized_height: msg.finalized_height,
                signature: msg.signature,
                public_key: msg.public_key,
            });
        }
        let tc = crate::timeout::TimeoutCertificate {
            format_version: crate::timeout::TIMEOUT_CERTIFICATE_FORMAT_VERSION,
            view: tc_view,
            signers,
        };

        let header = BlockHeader::new_at_view(
            BlockHeight::from(1),
            5,
            Hash::default(),
            Hash::default(),
            Hash::default(),
            proposer_addr,
            ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
        );
        let block = Block::new(header, vec![]);
        let sig = peer_sign_proposal(&block, 0, &peers[0].0, &peers[0].1);

        let result = engine.on_proposal(&block, Some(tc), None, 0, &sig).await;
        assert!(
            matches!(result, Err(ConsensusError::InvalidProposal(_))),
            "TC with wrong view must be rejected, got {:?}",
            result
        );
        assert_eq!(engine.view_state.read().view, 0, "local view unchanged");
    }

    /// A proposal carrying a TC signed by < 2f+1 validators must be rejected.
    /// This guards against a leader fabricating a "TC" from f or fewer signers.
    #[tokio::test]
    async fn test_on_proposal_rejects_tc_below_quorum() {
        use tenzro_types::block::{Block, BlockHeader, ConsensusAlgorithm, ConsensusProof};
        use tenzro_types::primitives::{BlockHeight, Hash};

        let (engine, peers) = build_test_engine_with_all_signers().await;
        let proposer_addr = peers[0].3;

        {
            let mut state = engine.view_state.write();
            state.view = 0;
            state.height = BlockHeight::from(1);
            state.phase = Phase::Prepare;
        }

        // Only 1 signer — far below 2f+1 = 3 for a 4-validator set.
        let tc_view = 4u64;
        let (kp, pq, _bls, addr) = &peers[0];
        let msg = peer_sign_timeout_with_hqc(tc_view, 0, *addr, kp, pq);
        let signers = vec![crate::timeout::TcSigner {
            voter: msg.voter,
            high_qc_view: msg.high_qc_view,
            finalized_height: msg.finalized_height,
            signature: msg.signature,
            public_key: msg.public_key,
        }];
        let tc = crate::timeout::TimeoutCertificate {
            format_version: crate::timeout::TIMEOUT_CERTIFICATE_FORMAT_VERSION,
            view: tc_view,
            signers,
        };

        let header = BlockHeader::new_at_view(
            BlockHeight::from(1),
            5,
            Hash::default(),
            Hash::default(),
            Hash::default(),
            proposer_addr,
            ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
        );
        let block = Block::new(header, vec![]);
        let sig = peer_sign_proposal(&block, 0, &peers[0].0, &peers[0].1);

        let result = engine.on_proposal(&block, Some(tc), None, 0, &sig).await;
        assert!(
            matches!(result, Err(ConsensusError::InvalidProposal(_))),
            "TC below quorum must be rejected, got {:?}",
            result
        );
    }
}
