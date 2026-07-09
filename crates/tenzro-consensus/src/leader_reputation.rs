//! Aptos-style LeaderReputation proposer election for HotStuff-2.
//!
//! # Why this exists
//!
//! Naïve `view % N` round-robin is the failure mode that wedges a small
//! validator set whenever any single validator becomes unresponsive: 1-in-N
//! views are scheduled to a dead leader, the network times out, and the
//! healthy super-majority makes progress only in bursts. With 4 validators
//! and one flaky pod, throughput collapses to ~75% of nominal — and once the
//! flaky pod loses too many consecutive views' worth of votes from peers,
//! the chain stalls outright.
//!
//! Aptos LeaderReputation replaces this with a stake-weighted draw whose
//! per-validator weight is multiplied by an *observed-behaviour* term:
//! validators that recently produced QCs win an `active_weight` boost (×1000
//! over baseline), validators that participated as voters but never proposed
//! get `inactive_weight` (×10), and validators whose proposals failed get
//! `failed_weight` (×1). A flaky validator's effective weight collapses to
//! ~0.1% of a healthy peer's within ~20 rounds, so the scheduler stops
//! picking it long before its degradation propagates into chain liveness.
//!
//! # Design parameters
//!
//! Verified against Aptos production source code (consensus/src/liveness/
//! leader_reputation.rs) — these are the constants the Aptos mainnet runs
//! with at ~150 validators:
//!
//! - `FAILED_WEIGHT`   = 1
//! - `INACTIVE_WEIGHT` = 10
//! - `ACTIVE_WEIGHT`   = 1000
//! - `FAILURE_THRESHOLD_PERCENT` = 10
//!
//! Window sizes (n = active validator count):
//! - Proposer window: rounds in `[round - 10·n - 20,  round - 20)`
//! - Voter window:    rounds in `[round - 10·n - 20,  round - 9·n - 20)`
//!
//! The 20-round trailing buffer is critical: the most recent 20 rounds of
//! history are *excluded* from the reputation calculation. Without it, a
//! validator could see the next round's anti-grinding seed before the QC
//! certifying its own most-recent proposal had finalized, opening a brief
//! grinding window. Aptos pinned 20 as the minimum buffer that closes this
//! against the maximum plausible reorder depth at HotStuff-2 finality.
//!
//! # Anti-grinding seed
//!
//! ```text
//! seed = SHA-256(
//!     "TENZRO_LEADER_REPUTATION:"
//!     || epoch.to_be_bytes()    // 8 bytes BE
//!     || round.to_be_bytes()    // 8 bytes BE
//!     || prev_block_id          // 32 bytes
//! )
//! ```
//!
//! `prev_block_id` is the hash of the most recently finalized block at the
//! time of the draw. Using a finalized hash (rather than `view - 1`'s
//! tentative parent) means the seed is fixed by an adversary's block at
//! least one full QC ago — not by the current proposer. This is the same
//! anti-grinding pattern Aptos uses; the domain tag prevents replay against
//! any other Tenzro hash that happens to share the structural inputs.
//!
//! # Capability multiplier
//!
//! On top of stake × observed-behaviour, each validator's draw weight is
//! scaled by a continuous *capability multiplier* in `[1.0×, 1.5×]`. The
//! multiplier folds two advertised inputs: the validator's hardware class
//! (`HardwareClass::Cpu` … `MultiAccelerator`, contributing up to 4000 bps
//! of the 5000 bps bonus span) and a fresh, valid TEE attestation
//! (contributing the remaining 1000 bps). The weakest advertised hardware
//! with no attestation sits at exactly `1.0×` — capability only ever
//! *bonuses*, never punishes below the stake-and-reputation baseline — and a
//! TEE-attested `MultiAccelerator` reaches the `1.5×` ceiling.
//!
//! Capability is *advertised*, so it is a bias, not a gate: the
//! observed-behaviour term is what actually stops a flaky validator from
//! being scheduled, regardless of how strong its self-reported hardware is
//! ("trust advertised, gate on observed"). A high-capability validator with
//! degraded behaviour is still deprioritized — capability cannot exempt a
//! validator from accountability for failed proposals. The `1.5×` ceiling is
//! the same bound the earlier binary TEE multiplier used, now reached by a
//! continuous class-plus-attestation curve rather than a hard on/off boost.
//!
//! References:
//! - Aptos LeaderReputation: `aptos-core/consensus/src/liveness/leader_reputation.rs`
//! - Aptos research blog: "Leader Reputation for Practical BFT Liveness" (2021)
//! - DiemBFT v4 §4.4 (proposer election rationale)
//! - MonadBFT (arXiv:2502.20692, Nov 2025) — production HotStuff-2 deployment

use crate::error::{ConsensusError, Result};
use crate::validator::{ValidatorInfo, ValidatorSet};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tenzro_types::primitives::{Address, Hash};

/// Domain-separation tag for the reputation seed. Distinct from any other
/// SHA-256 domain in the workspace.
const REPUTATION_SEED_DOMAIN: &[u8] = b"TENZRO_LEADER_REPUTATION:";

/// Weight assigned to a validator whose recent proposal(s) failed to form a
/// QC (i.e. they were scheduled as leader and the round timed out without
/// finalizing their block).
pub const FAILED_WEIGHT: u128 = 1;

/// Weight assigned to a validator who recently voted but did not propose
/// (or whose proposals were outside the proposer window). The "showed up
/// but isn't actively driving consensus" tier.
pub const INACTIVE_WEIGHT: u128 = 10;

/// Weight assigned to a validator who recently produced a QC-certified
/// proposal. The 1000× spread between this and `FAILED_WEIGHT` is what
/// makes the scheduler effectively avoid known-flaky validators.
pub const ACTIVE_WEIGHT: u128 = 1000;

/// Percentage of a validator's recent proposals that may have failed before
/// the validator drops from `INACTIVE_WEIGHT` to `FAILED_WEIGHT`. With Aptos
/// pinning this at 10, a validator that fails ≥10% of its proposer window
/// gets the punitive weight.
pub const FAILURE_THRESHOLD_PERCENT: u32 = 10;

/// Baseline capability multiplier in basis points (1× = 10000 bps). A
/// validator with the weakest advertised hardware (`HardwareClass::Cpu`)
/// and no TEE gets exactly this — capability only ever *bonuses* a
/// validator up from baseline, never below it, so an under-resourced node
/// is not excluded from proposing, merely less likely to be drawn.
pub const CAPABILITY_BASELINE_BPS: u128 = 10000;

/// Maximum capability multiplier in basis points (1.5× = 15000 bps). The
/// strongest advertised hardware class (`MultiAccelerator`) reaches this;
/// the TEE bonus is folded inside this ceiling rather than stacking on top,
/// so no validator's advertised capability can push its draw weight beyond
/// 1.5× its stake-and-reputation baseline. This is the same ceiling the
/// earlier binary TEE multiplier used, now reached by a continuous class
/// score rather than a single bit.
pub const CAPABILITY_MAX_BPS: u128 = 15000;

/// Share of the capability bonus span (`CAPABILITY_MAX_BPS -
/// CAPABILITY_BASELINE_BPS`) attributable to TEE attestation. The rest is
/// attributable to the advertised hardware class. 4000 bps of the 5000 bps
/// span comes from the hardware class and 1000 bps from TEE, so a
/// TEE-attested `MultiAccelerator` reaches the full 1.5× and a
/// non-attested one reaches 1.4×.
pub const CAPABILITY_TEE_SPAN_BPS: u128 = 1000;

/// Compute a validator's continuous capability multiplier in basis points,
/// in `[CAPABILITY_BASELINE_BPS, CAPABILITY_MAX_BPS]`.
///
/// The advertised [`HardwareClass`] contributes a fraction of the bonus
/// span via its `advertised_weight()` (`[0.2, 1.0]`), rescaled so that the
/// top class contributes the full class portion; TEE attestation
/// contributes `CAPABILITY_TEE_SPAN_BPS` on top. Both are advertised
/// claims — the observed-reputation tier (ACTIVE/INACTIVE/FAILED) is the
/// gate that stops an over-stated capability from actually helping a flaky
/// validator, per "trust advertised, gate on observed".
pub fn capability_multiplier_bps(
    hardware: &tenzro_types::hardware::HardwareCapabilities,
    tee_attested: bool,
) -> u128 {
    let class_span = CAPABILITY_MAX_BPS - CAPABILITY_BASELINE_BPS - CAPABILITY_TEE_SPAN_BPS;
    // advertised_weight() is in [0.2, 1.0]; rescale to [0.0, 1.0] so CPU-only
    // contributes no class bonus and MultiAccelerator contributes all of it.
    let w = hardware.class().advertised_weight();
    let class_frac = ((w - 0.2) / 0.8).clamp(0.0, 1.0);
    let class_bonus = (class_frac * class_span as f64) as u128;
    let tee_bonus = if tee_attested { CAPABILITY_TEE_SPAN_BPS } else { 0 };
    (CAPABILITY_BASELINE_BPS + class_bonus + tee_bonus).min(CAPABILITY_MAX_BPS)
}

/// One entry in the per-round proposer history. Records the leader of a
/// round that has since been finalized (or definitively timed out).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposerRecord {
    /// The round this record describes.
    pub round: u64,
    /// The validator scheduled as leader for this round.
    pub proposer: Address,
    /// Whether the round produced a QC-certified block from this proposer.
    /// `false` for rounds that timed out, were skipped via TC, or whose
    /// leader's block failed to gather a quorum.
    pub success: bool,
}

/// One entry in the per-round voter history. Records which validators
/// participated in the QC for a finalized round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterRecord {
    /// The round this record describes.
    pub round: u64,
    /// Validators whose Prepare-vote was included in the round's QC.
    pub voters: Vec<Address>,
}

/// Bounded ring buffer of proposer history.
///
/// Capacity is `10·n + 40` rounds, which is the maximum window any
/// reputation calculation will need plus a safety margin for the trailing
/// buffer. Older entries are discarded on `push` once the buffer is full —
/// they're outside every legal window anyway.
#[derive(Debug)]
pub struct ProposerHistory {
    records: VecDeque<ProposerRecord>,
    capacity: usize,
}

impl ProposerHistory {
    /// Builds a proposer history sized for an active set of `n` validators.
    pub fn new(n: usize) -> Self {
        let capacity = (10 * n + 40).max(64);
        Self {
            records: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Records the outcome of a finalized round. Idempotent: re-recording
    /// the same round overwrites the prior entry (used when a round is
    /// re-classified, e.g. from "in progress" to "failed").
    pub fn push(&mut self, record: ProposerRecord) {
        if let Some(existing) = self.records.iter_mut().find(|r| r.round == record.round) {
            *existing = record;
            return;
        }
        if self.records.len() >= self.capacity {
            self.records.pop_front();
        }
        self.records.push_back(record);
    }

    /// Returns all records whose round falls in `[lo, hi)`.
    pub fn range(&self, lo: u64, hi: u64) -> impl Iterator<Item = &ProposerRecord> {
        self.records
            .iter()
            .filter(move |r| r.round >= lo && r.round < hi)
    }

    /// Number of records currently buffered.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Bounded ring buffer of voter history.
///
/// Capacity matches `ProposerHistory` — the voter window is a strict subset
/// of the proposer window plus the trailing buffer.
#[derive(Debug)]
pub struct VoterHistory {
    records: VecDeque<VoterRecord>,
    capacity: usize,
}

impl VoterHistory {
    /// Builds a voter history sized for `n` validators.
    pub fn new(n: usize) -> Self {
        let capacity = (10 * n + 40).max(64);
        Self {
            records: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Records the QC participants of a finalized round.
    pub fn push(&mut self, record: VoterRecord) {
        if let Some(existing) = self.records.iter_mut().find(|r| r.round == record.round) {
            *existing = record;
            return;
        }
        if self.records.len() >= self.capacity {
            self.records.pop_front();
        }
        self.records.push_back(record);
    }

    /// Returns all records whose round falls in `[lo, hi)`.
    pub fn range(&self, lo: u64, hi: u64) -> impl Iterator<Item = &VoterRecord> {
        self.records
            .iter()
            .filter(move |r| r.round >= lo && r.round < hi)
    }

    /// Number of records currently buffered.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Trailing buffer (in rounds) excluded from both proposer and voter
/// windows. This is the anti-grinding margin — the most recent 20 rounds
/// of history are *not* used in the draw because their QCs may not yet be
/// final at the moment the seed is consumed.
pub const TRAILING_BUFFER_ROUNDS: u64 = 20;

/// Compute the proposer window `[lo, hi)` for the given round.
///
/// Returns `None` if the round is too early (less than `10·n + 20`) — at
/// genesis there is no history to draw from, so the engine falls back to
/// stake-weighted selection.
pub fn proposer_window(round: u64, n: usize) -> Option<(u64, u64)> {
    let span = 10u64.saturating_mul(n as u64);
    let buffer = TRAILING_BUFFER_ROUNDS;
    if round < span + buffer {
        return None;
    }
    let lo = round - span - buffer;
    let hi = round - buffer;
    Some((lo, hi))
}

/// Compute the voter window `[lo, hi)` for the given round.
///
/// The voter window is the older two-thirds of the proposer window: it
/// observes who voted on rounds whose QCs have had additional time to
/// finalize, which prevents counting a temporarily-missed vote against a
/// validator that simply hadn't received the QC yet.
pub fn voter_window(round: u64, n: usize) -> Option<(u64, u64)> {
    let span = 10u64.saturating_mul(n as u64);
    let buffer = TRAILING_BUFFER_ROUNDS;
    let voter_hi_offset = 9u64.saturating_mul(n as u64).saturating_add(buffer);
    if round < span + buffer || round < voter_hi_offset {
        return None;
    }
    let lo = round - span - buffer;
    let hi = round - voter_hi_offset;
    if lo >= hi {
        return None;
    }
    Some((lo, hi))
}

/// Computes the SHA-256 anti-grinding seed for the leader draw at
/// `(epoch, round)` with the given previous-block hash.
pub fn reputation_seed(epoch: u64, round: u64, prev_block_id: &Hash) -> [u8; 32] {
    let mut buf = Vec::with_capacity(REPUTATION_SEED_DOMAIN.len() + 8 + 8 + 32);
    buf.extend_from_slice(REPUTATION_SEED_DOMAIN);
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(&round.to_be_bytes());
    buf.extend_from_slice(prev_block_id.as_bytes());
    tenzro_crypto::hash::sha256(&buf).to_bytes()
}

/// Reduce a 32-byte SHA-256 digest into a u128 in the range `[0, total)`.
///
/// We use the leading 16 bytes of the digest as a u128, then mod by total.
/// The bias from non-uniform reduction is bounded by `total / 2^128`, which
/// for any plausible total weight is negligible.
fn seed_to_index(seed: &[u8; 32], total: u128) -> u128 {
    debug_assert!(total > 0);
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&seed[..16]);
    let val = u128::from_be_bytes(buf);
    val % total
}

/// Per-validator weights computed for one specific round. Held only as
/// long as the draw takes — not cached, since the inputs change every
/// round.
#[derive(Debug, Clone)]
pub struct ValidatorWeights {
    /// Map from validator address to that validator's weighted slot in the
    /// draw. Sum of values equals `total`.
    pub weights: HashMap<Address, u128>,
    /// Total weight across the active set (used as the modulus for the
    /// seed reduction).
    pub total: u128,
}

/// LeaderReputation proposer-election engine.
///
/// One instance per consensus engine. Holds bounded histories of proposer
/// success/failure and voter participation, computes weights from the
/// validator set on demand, and selects the leader for a given round via a
/// seeded weighted draw.
///
/// All public methods are thread-safe via interior `RwLock`s. The histories
/// are append-write, range-read.
pub struct LeaderReputation {
    proposer_history: RwLock<ProposerHistory>,
    voter_history: RwLock<VoterHistory>,
    /// Scaling knob for the continuous capability multiplier, in basis
    /// points. `CAPABILITY_BASELINE_BPS` (10000) applies the per-class
    /// multiplier as computed; `0` collapses every validator to a flat 1×
    /// (pure stake × reputation, capability axis disabled). Exposed for
    /// tests and future governance tuning.
    capability_scale_bps: u128,
}

impl LeaderReputation {
    /// Builds a new reputation engine sized for a `n`-validator active set,
    /// applying the capability multiplier at full scale.
    pub fn new(n: usize) -> Self {
        Self::with_capability_scale(n, CAPABILITY_BASELINE_BPS)
    }

    /// Builds a reputation engine with a custom capability scale (basis
    /// points). Pass `0` to disable the capability bias entirely (every
    /// validator draws on stake × reputation alone).
    pub fn with_capability_scale(n: usize, capability_scale_bps: u128) -> Self {
        Self {
            proposer_history: RwLock::new(ProposerHistory::new(n)),
            voter_history: RwLock::new(VoterHistory::new(n)),
            capability_scale_bps,
        }
    }

    /// Records that round `round` was led by `proposer` with outcome
    /// `success` (`true` if the round produced a finalized block).
    pub fn record_round_outcome(&self, round: u64, proposer: Address, success: bool) {
        self.proposer_history.write().push(ProposerRecord {
            round,
            proposer,
            success,
        });
    }

    /// Records that round `round` was finalized with QC participants
    /// `voters`.
    pub fn record_round_voters(&self, round: u64, voters: Vec<Address>) {
        self.voter_history
            .write()
            .push(VoterRecord { round, voters });
    }

    /// For tests / introspection: how many proposer records are currently
    /// buffered.
    pub fn proposer_history_len(&self) -> usize {
        self.proposer_history.read().len()
    }

    /// For tests / introspection: how many voter records are currently
    /// buffered.
    pub fn voter_history_len(&self) -> usize {
        self.voter_history.read().len()
    }

    /// Compute weights for every active validator in `validator_set` at
    /// the given `round`.
    ///
    /// Algorithm:
    ///
    /// 1. Compute the proposer window and voter window for `round`. If
    ///    either is `None` (genesis-adjacent), fall back to pure
    ///    stake-weighted weights (no behavioural multiplier).
    /// 2. For each validator:
    ///    - Tally proposer-window outcomes: `proposed`, `failed`.
    ///    - Tally voter-window participation: `voted` (any).
    ///    - Decide the behavioural tier:
    ///      - If proposed ≥ 1 AND `failed * 100 / proposed < FAILURE_THRESHOLD_PERCENT`
    ///        → ACTIVE_WEIGHT
    ///      - Else if proposed ≥ 1 (failure rate too high)
    ///        → FAILED_WEIGHT
    ///      - Else if voted ≥ 1
    ///        → INACTIVE_WEIGHT
    ///      - Else → FAILED_WEIGHT
    ///    - Multiply by stake. Multiply by TEE multiplier if attested.
    /// 3. Return the map.
    pub fn compute_weights(
        &self,
        round: u64,
        validator_set: &ValidatorSet,
    ) -> ValidatorWeights {
        let n = validator_set.len();
        let p_window = proposer_window(round, n);
        let v_window = voter_window(round, n);

        // Snapshot histories under read locks. Tally per-validator counts.
        let proposer_counts: HashMap<Address, (u64, u64)> = match p_window {
            Some((lo, hi)) => {
                let history = self.proposer_history.read();
                let mut counts: HashMap<Address, (u64, u64)> = HashMap::new();
                for record in history.range(lo, hi) {
                    let entry = counts.entry(record.proposer).or_insert((0, 0));
                    entry.0 += 1; // proposed
                    if !record.success {
                        entry.1 += 1; // failed
                    }
                }
                counts
            }
            None => HashMap::new(),
        };

        let voted: HashSet<Address> = match v_window {
            Some((lo, hi)) => {
                let history = self.voter_history.read();
                let mut set = HashSet::new();
                for record in history.range(lo, hi) {
                    for voter in &record.voters {
                        set.insert(*voter);
                    }
                }
                set
            }
            None => HashSet::new(),
        };

        let bootstrap = p_window.is_none() && v_window.is_none();

        let mut weights = HashMap::with_capacity(n);
        let mut total: u128 = 0;
        for v in validator_set.iter() {
            if !v.is_active() {
                continue;
            }
            let behavioural = if bootstrap {
                // Genesis-adjacent: no history. Everyone gets INACTIVE_WEIGHT
                // so the draw degenerates gracefully into stake-weighted
                // until enough rounds have accumulated for real reputation
                // to take over.
                INACTIVE_WEIGHT
            } else {
                tier_weight(&proposer_counts, &voted, &v.address)
            };

            let stake = v.stake.max(1); // every active validator counts
            let raw = behavioural.saturating_mul(stake);

            // Continuous capability bias: advertised hardware class + TEE,
            // folded into a single multiplier in [1.0×, 1.5×]. Replaces the
            // earlier binary TEE bit. The `capability_scale_bps` knob (default
            // full 10000 = "apply the multiplier as computed") lets tests and
            // future tuning damp the whole capability axis toward 1× without
            // changing the per-class shape.
            let capability = capability_multiplier_bps(&v.capability, v.has_valid_tee_attestation());
            // Interpolate between baseline (1×) and the computed multiplier by
            // capability_scale_bps: scale=10000 → full multiplier, scale=0 → 1×.
            let excess = capability.saturating_sub(CAPABILITY_BASELINE_BPS);
            let multiplier = CAPABILITY_BASELINE_BPS
                + excess.saturating_mul(self.capability_scale_bps) / CAPABILITY_BASELINE_BPS;
            // weight = raw * multiplier / 10000
            let scaled = raw.saturating_mul(multiplier) / CAPABILITY_BASELINE_BPS;
            let final_weight = scaled.max(1);

            weights.insert(v.address, final_weight);
            total = total.saturating_add(final_weight);
        }

        ValidatorWeights { weights, total }
    }

    /// Selects the leader for `round` via a seeded weighted draw.
    ///
    /// `prev_block_id` is the hash of the most recently finalized block
    /// (the parent the new proposal will extend). Using a finalized hash
    /// — not a tentative parent — fixes the seed before the current
    /// proposer can grind on it.
    ///
    /// Errors if the validator set is empty or all weights are zero (which
    /// should be unreachable given the `final_weight = max(1)` floor).
    pub fn select_leader<'a>(
        &self,
        round: u64,
        epoch: u64,
        prev_block_id: &Hash,
        validator_set: &'a ValidatorSet,
    ) -> Result<&'a ValidatorInfo> {
        let weights = self.compute_weights(round, validator_set);

        if weights.total == 0 {
            return Err(ConsensusError::InvalidValidatorSet(
                "leader reputation: total weight is zero".to_string(),
            ));
        }

        let seed = reputation_seed(epoch, round, prev_block_id);
        let target = seed_to_index(&seed, weights.total);

        // Iterate validators in canonical (validator-set) order so the draw
        // is deterministic across replicas. ValidatorSet preserves insertion
        // order; use that as the canonical sort.
        let mut cumulative: u128 = 0;
        for v in validator_set.iter() {
            if !v.is_active() {
                continue;
            }
            let w = weights.weights.get(&v.address).copied().unwrap_or(0);
            cumulative = cumulative.saturating_add(w);
            if target < cumulative {
                return Ok(v);
            }
        }

        // Unreachable: we checked total > 0 and target < total above. Fall
        // back to the last active validator rather than panic.
        validator_set
            .iter()
            .rev()
            .find(|v| v.is_active())
            .ok_or_else(|| {
                ConsensusError::InvalidValidatorSet(
                    "leader reputation: no active validators".to_string(),
                )
            })
    }
}

/// Pure helper: classify a single validator's behavioural tier given
/// pre-tallied proposer and voter snapshots.
fn tier_weight(
    proposer_counts: &HashMap<Address, (u64, u64)>,
    voted: &HashSet<Address>,
    address: &Address,
) -> u128 {
    if let Some(&(proposed, failed)) = proposer_counts.get(address)
        && proposed > 0
    {
        // failed * 100 / proposed < FAILURE_THRESHOLD_PERCENT?
        // Avoid division by computing failed * 100 < proposed * threshold.
        let lhs = failed.saturating_mul(100);
        let rhs = proposed.saturating_mul(FAILURE_THRESHOLD_PERCENT as u64);
        if lhs < rhs {
            return ACTIVE_WEIGHT;
        } else {
            return FAILED_WEIGHT;
        }
    }
    if voted.contains(address) {
        INACTIVE_WEIGHT
    } else {
        FAILED_WEIGHT
    }
}

/// Convenience wrapper so the engine can hand out a shared reference.
pub type SharedLeaderReputation = Arc<LeaderReputation>;

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::bls::BlsKeyPair;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::{KeyPair, KeyType};

    fn convert_address(crypto_addr: tenzro_crypto::Address) -> Address {
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        Address::new(addr_bytes)
    }

    fn validator(stake: u128) -> ValidatorInfo {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let address = convert_address(keypair.address());
        let pq = MlDsaSigningKey::generate();
        let bls = BlsKeyPair::generate().unwrap();
        ValidatorInfo::new(
            address,
            keypair.public_key().clone(),
            pq.verifying_key_bytes().to_vec(),
            bls.public_key().to_bytes().to_vec(),
            stake,
        )
    }

    fn vset(validators: Vec<ValidatorInfo>) -> ValidatorSet {
        ValidatorSet::new(0, validators).unwrap()
    }

    #[test]
    fn proposer_window_genesis_returns_none() {
        // n=4, span=40, buffer=20 → need round >= 60.
        assert_eq!(proposer_window(0, 4), None);
        assert_eq!(proposer_window(59, 4), None);
        assert_eq!(proposer_window(60, 4), Some((0, 40)));
    }

    #[test]
    fn voter_window_genesis_returns_none() {
        // n=4, voter_hi_offset = 9*4 + 20 = 56. Need round >= 60 (proposer
        // gate) AND round >= 56 (voter gate). Effective gate is 60.
        assert_eq!(voter_window(0, 4), None);
        assert_eq!(voter_window(59, 4), None);
        // At round 60: lo = 0, hi = 60 - 56 = 4. Window = [0, 4).
        assert_eq!(voter_window(60, 4), Some((0, 4)));
    }

    #[test]
    fn proposer_window_at_n_4_round_100() {
        // span = 10 * 4 = 40, buffer = 20. lo = 100 - 40 - 20 = 40.
        // hi = 100 - 20 = 80. Window = [40, 80).
        assert_eq!(proposer_window(100, 4), Some((40, 80)));
    }

    #[test]
    fn voter_window_at_n_4_round_100() {
        // span = 40, buffer = 20. lo = 40. hi = 100 - 9*4 - 20 = 44.
        // Window = [40, 44). Strict subset of proposer window's lower end.
        assert_eq!(voter_window(100, 4), Some((40, 44)));
    }

    #[test]
    fn proposer_history_dedupes_same_round() {
        let mut h = ProposerHistory::new(4);
        let addr = convert_address(KeyPair::generate(KeyType::Ed25519).unwrap().address());
        h.push(ProposerRecord {
            round: 5,
            proposer: addr,
            success: false,
        });
        h.push(ProposerRecord {
            round: 5,
            proposer: addr,
            success: true,
        });
        assert_eq!(h.len(), 1);
        let only = h.range(0, 100).next().unwrap();
        assert!(only.success);
    }

    #[test]
    fn proposer_history_evicts_oldest_at_capacity() {
        let mut h = ProposerHistory::new(1); // capacity = max(10*1+40, 64) = 64
        let addr = convert_address(KeyPair::generate(KeyType::Ed25519).unwrap().address());
        for r in 0..70u64 {
            h.push(ProposerRecord {
                round: r,
                proposer: addr,
                success: true,
            });
        }
        assert_eq!(h.len(), 64);
        // Earliest retained should be round 6 (rounds 0..5 evicted).
        let earliest = h.range(0, 100).next().unwrap();
        assert_eq!(earliest.round, 6);
    }

    #[test]
    fn reputation_seed_is_deterministic() {
        let h = Hash::new([7u8; 32]);
        let s1 = reputation_seed(3, 100, &h);
        let s2 = reputation_seed(3, 100, &h);
        assert_eq!(s1, s2);
    }

    #[test]
    fn reputation_seed_diverges_on_round() {
        let h = Hash::new([7u8; 32]);
        let s1 = reputation_seed(3, 100, &h);
        let s2 = reputation_seed(3, 101, &h);
        assert_ne!(s1, s2);
    }

    #[test]
    fn reputation_seed_diverges_on_epoch() {
        let h = Hash::new([7u8; 32]);
        let s1 = reputation_seed(3, 100, &h);
        let s2 = reputation_seed(4, 100, &h);
        assert_ne!(s1, s2);
    }

    #[test]
    fn reputation_seed_diverges_on_prev_block() {
        let h1 = Hash::new([7u8; 32]);
        let h2 = Hash::new([8u8; 32]);
        let s1 = reputation_seed(3, 100, &h1);
        let s2 = reputation_seed(3, 100, &h2);
        assert_ne!(s1, s2);
    }

    #[test]
    fn bootstrap_window_falls_back_to_inactive_weight() {
        // No history yet, round well below the gate. Every active validator
        // should get INACTIVE_WEIGHT × stake (× 1.0 multiplier since no TEE).
        let v1 = validator(1000);
        let v2 = validator(2000);
        let set = vset(vec![v1.clone(), v2.clone()]);
        let lr = LeaderReputation::new(2);

        let weights = lr.compute_weights(5, &set); // round well before window opens
        assert_eq!(weights.weights[&v1.address], INACTIVE_WEIGHT * 1000);
        assert_eq!(weights.weights[&v2.address], INACTIVE_WEIGHT * 2000);
        assert_eq!(weights.total, INACTIVE_WEIGHT * 3000);
    }

    #[test]
    fn active_proposer_gets_active_weight() {
        let v1 = validator(1000);
        let v2 = validator(1000);
        let set = vset(vec![v1.clone(), v2.clone()]);
        let lr = LeaderReputation::new(2);
        // n=2 → span=20, buffer=20. Window for round 100 = [60, 80).
        // Fill v1 with 10 successful proposals in window.
        for r in 60..70u64 {
            lr.record_round_outcome(r, v1.address, true);
        }
        // Fill v2 with 10 successful but in the voter-only band [60, 64).
        // Actually voter window for n=2 round 100 = [60, 100 - 18 - 20)
        // = [60, 62). Just put v2 votes in there.
        for r in 60..62u64 {
            lr.record_round_voters(r, vec![v2.address]);
        }

        let weights = lr.compute_weights(100, &set);
        // v1: 10 proposals, 0 failed → ACTIVE_WEIGHT × 1000 stake = 1_000_000
        assert_eq!(weights.weights[&v1.address], ACTIVE_WEIGHT * 1000);
        // v2: 0 proposals, voted → INACTIVE_WEIGHT × 1000 stake = 10_000
        assert_eq!(weights.weights[&v2.address], INACTIVE_WEIGHT * 1000);
    }

    #[test]
    fn high_failure_rate_proposer_drops_to_failed_weight() {
        let v1 = validator(1000);
        let set = vset(vec![v1.clone()]);
        let lr = LeaderReputation::new(1);
        // For n=1 we need round >= 30. Use round 100 → window depends on
        // span = 10. proposer_window = [100 - 10 - 20, 100 - 20) = [70, 80).
        // 10 slots in window. Set 5 success, 5 fail = 50% failure rate.
        for r in 70..75u64 {
            lr.record_round_outcome(r, v1.address, true);
        }
        for r in 75..80u64 {
            lr.record_round_outcome(r, v1.address, false);
        }
        let weights = lr.compute_weights(100, &set);
        // 50% > 10% threshold → FAILED_WEIGHT × 1000 = 1000.
        assert_eq!(weights.weights[&v1.address], FAILED_WEIGHT * 1000);
    }

    #[test]
    fn select_leader_is_deterministic_across_replicas() {
        let v1 = validator(1000);
        let v2 = validator(1000);
        let v3 = validator(1000);
        let v4 = validator(1000);
        let set = vset(vec![v1.clone(), v2.clone(), v3.clone(), v4.clone()]);
        let lr_a = LeaderReputation::new(4);
        let lr_b = LeaderReputation::new(4);
        let prev = Hash::new([42u8; 32]);

        for r in 100..120u64 {
            let l_a = lr_a.select_leader(r, 0, &prev, &set).unwrap();
            let l_b = lr_b.select_leader(r, 0, &prev, &set).unwrap();
            assert_eq!(l_a.address, l_b.address);
        }
    }

    #[test]
    fn select_leader_skips_flaky_validator() {
        let v1 = validator(1000);
        let v2 = validator(1000);
        let v3 = validator(1000);
        let v4 = validator(1000);
        let set = vset(vec![v1.clone(), v2.clone(), v3.clone(), v4.clone()]);
        let lr = LeaderReputation::new(4);
        // n=4, span=40, buffer=20. Round 100 → window [40, 80).
        // v4 fails every proposal it's given; v1/v2/v3 succeed.
        for r in 40..80u64 {
            let chosen = match r % 4 {
                0 => v1.address,
                1 => v2.address,
                2 => v3.address,
                _ => v4.address,
            };
            let success = chosen != v4.address;
            lr.record_round_outcome(r, chosen, success);
        }
        // Voter window for n=4 round 100 = [40, 44). Mark all 4 as voters
        // there so v4 doesn't get the FAILED_WEIGHT-with-no-votes penalty
        // earned via "not even voting" — we want to isolate the proposer
        // failure penalty.
        for r in 40..44u64 {
            lr.record_round_voters(r, vec![v1.address, v2.address, v3.address, v4.address]);
        }

        let weights = lr.compute_weights(100, &set);
        // v1, v2, v3: proposed 10 times each, 0 fails → ACTIVE × 1000 = 1_000_000
        // v4: proposed 10 times, 10 fails (100% > 10%) → FAILED × 1000 = 1000
        assert_eq!(weights.weights[&v1.address], ACTIVE_WEIGHT * 1000);
        assert_eq!(weights.weights[&v2.address], ACTIVE_WEIGHT * 1000);
        assert_eq!(weights.weights[&v3.address], ACTIVE_WEIGHT * 1000);
        assert_eq!(weights.weights[&v4.address], FAILED_WEIGHT * 1000);
        // v4 is 1/3001 of the draw → over many rounds it should be picked
        // virtually never. Pin the round to 100 (so the proposer window
        // stays [40, 80) and the staged history applies) and vary the
        // epoch to get 1000 different seeds.
        let prev = Hash::new([1u8; 32]);
        let mut v4_count = 0usize;
        for epoch in 0..1000u64 {
            let chosen = lr.select_leader(100, epoch, &prev, &set).unwrap();
            if chosen.address == v4.address {
                v4_count += 1;
            }
        }
        // Expected ≈ 1000 / 3001 ≈ 0.33. Allow up to 5 in 1000 to absorb
        // statistical noise; even at p=0.001, 95% CI is well below 5.
        assert!(v4_count <= 5, "v4 was selected {} times out of 1000", v4_count);
    }

    fn caps(vram_gb: u32) -> tenzro_types::hardware::HardwareCapabilities {
        tenzro_types::hardware::HardwareCapabilities {
            vram_gb,
            detected: true,
            ..Default::default()
        }
    }

    #[test]
    fn capability_multiplier_spans_baseline_to_ceiling() {
        use tenzro_types::hardware::HardwareCapabilities;
        // CPU-only, no TEE → exactly baseline (1×).
        assert_eq!(
            capability_multiplier_bps(&caps(0), false),
            CAPABILITY_BASELINE_BPS
        );
        // Top hardware class + TEE → exactly the ceiling (1.5×).
        assert_eq!(
            capability_multiplier_bps(&caps(200), true),
            CAPABILITY_MAX_BPS
        );
        // TEE alone on CPU hardware lifts only by the TEE span.
        assert_eq!(
            capability_multiplier_bps(&caps(0), true),
            CAPABILITY_BASELINE_BPS + CAPABILITY_TEE_SPAN_BPS
        );
        // Top hardware without TEE reaches ceiling minus the TEE span.
        assert_eq!(
            capability_multiplier_bps(&caps(200), false),
            CAPABILITY_MAX_BPS - CAPABILITY_TEE_SPAN_BPS
        );
        // Monotonic in hardware class: consumer < datacenter < multi.
        let consumer = capability_multiplier_bps(&HardwareCapabilities { vram_gb: 16, detected: true, ..Default::default() }, false);
        let datacenter = capability_multiplier_bps(&HardwareCapabilities { vram_gb: 80, detected: true, ..Default::default() }, false);
        let multi = capability_multiplier_bps(&caps(200), false);
        assert!(consumer < datacenter);
        assert!(datacenter < multi);
    }

    #[test]
    fn capability_weight_lifts_stronger_validator() {
        // Two equally-staked validators; v1 declares top hardware + TEE, v2
        // declares CPU-only, no TEE. v1's draw weight is exactly 1.5× v2's.
        let v1 = validator(1000)
            .with_capability(caps(200))
            .with_tee_attestation(
                tenzro_types::tee::AttestationReport::default(),
                tenzro_types::tee::AttestationResult::success(
                    tenzro_types::tee::TeeVendor::IntelTdx,
                    vec![0u8; 32],
                ),
            );
        let v2 = validator(1000).with_capability(caps(0));

        let set = vset(vec![v1.clone(), v2.clone()]);
        let lr = LeaderReputation::new(2);
        let weights = lr.compute_weights(5, &set); // bootstrap window

        let v1_w = weights.weights[&v1.address];
        let v2_w = weights.weights[&v2.address];
        assert_eq!(v1_w, INACTIVE_WEIGHT * 1000 * CAPABILITY_MAX_BPS / CAPABILITY_BASELINE_BPS);
        assert_eq!(v2_w, INACTIVE_WEIGHT * 1000);
        assert_eq!(v1_w, v2_w * 3 / 2);
    }

    #[test]
    fn capability_scale_zero_disables_the_bias() {
        // With capability_scale_bps = 0, the strongest and weakest validators
        // draw identically — capability axis is off, stake × reputation only.
        let v1 = validator(1000)
            .with_capability(caps(200))
            .with_tee_attestation(
                tenzro_types::tee::AttestationReport::default(),
                tenzro_types::tee::AttestationResult::success(
                    tenzro_types::tee::TeeVendor::IntelTdx,
                    vec![0u8; 32],
                ),
            );
        let v2 = validator(1000).with_capability(caps(0));

        let set = vset(vec![v1.clone(), v2.clone()]);
        let lr = LeaderReputation::with_capability_scale(2, 0);
        let weights = lr.compute_weights(5, &set);

        assert_eq!(weights.weights[&v1.address], weights.weights[&v2.address]);
    }
}
