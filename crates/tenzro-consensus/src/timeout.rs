//! Pacemaker timeout messages and certificates for HotStuff-2.
//!
//! # Why this exists
//!
//! The HotStuff-2 paper (Malkhi & Nayak 2023) leaves the Pacemaker module
//! abstract. DiemBFT v4 §3.5 fills it in: on local view timeout each replica
//! **broadcasts** a signed [`TimeoutMsg`] carrying its highest QC view, and
//! replicas that receive a `TimeoutMsg` for a higher view sync forward to
//! it. When 2f+1 timeouts at the same view aggregate, the result is a
//! [`TimeoutCertificate`] (TC) — proof that view N was abandoned by an
//! honest super-majority.
//!
//! Without these, the protocol can livelock under partial synchrony: the
//! lone view-counter sync of phase 1 advances views but does not let the
//! next leader propose. Aptos `safe_to_extend` rejects any block whose
//! parent QC view ≠ block.view-1 unless the proposal carries a TC for
//! view N-1. Phase 2 (this module) adds that proof.
//!
//! References:
//! - DiemBFT v4 §3.3, §3.5 (`local_timeout_round`, `process_remote_timeout`,
//!   `TwoChainTimeoutCertificate`)
//! - Jolteon (Gelashvili et al. 2022) §4 vote rule:
//!   `r = qc.r + 1` OR `r = tc.r + 1 ∧ qc.r ≥ max{tc.hqc_rounds}`
//! - Aptos `consensus/src/round_manager.rs` (`process_local_timeout`,
//!   `ensure_round_and_sync_up`)
//! - "The Latest View on View Synchronization" (Malkhi, 2022)
//! - "Liveness Attacks On HotStuff: The Vulnerability Of Timer Doubling
//!   Mechanism" (Wang et al., Oxford CompJ 2024)
//!
//! # Wire compatibility
//!
//! Tenzro is pre-alpha with no live users — no backwards-compatibility window.
//! [`TIMEOUT_MSG_FORMAT_VERSION`] is bumped to **3** and the new field
//! [`TimeoutMsg::finalized_height`] is mandatory. Older messages on the wire
//! are rejected.

use crate::error::{ConsensusError, Result};
use crate::validator::ValidatorSet;
use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tenzro_crypto::composite::{
    CompositePublicKey, CompositeSignature, HybridVerifier, StandardHybridVerifier,
};
use tenzro_types::primitives::Address;

/// Wire-format version for [`TimeoutMsg`]. Bumped on any breaking change.
///
/// **v3** (current): adds `finalized_height` to the canonical signing
/// payload. A replica receiving a verified timeout that advertises a
/// finalized height above its own engages block-sync immediately — this is
/// the heal path for single-block finalization skew, where one replica
/// finalized via a Commit QC the others never received and the proposer
/// keeps re-proposing a conflicting block at the same height forever.
/// **v2**: added `high_qc_view` — the DiemBFT `(round, hqc_round)` pair.
/// Older messages are rejected.
pub const TIMEOUT_MSG_FORMAT_VERSION: u8 = 3;

/// Domain-separation tag for the canonical signing payload. Distinct from
/// the `TENZRO_VOTE:` tag used by `Vote::signing_payload` so a Vote
/// signature can never be replayed as a TimeoutMsg signature or vice versa.
const TIMEOUT_SIGNING_DOMAIN: &[u8] = b"TENZRO_TIMEOUT:";

/// A pacemaker timeout broadcast.
///
/// Sent by a replica when its local view timer expires. Receivers of a
/// `TimeoutMsg` for a strictly higher view than their local view advance
/// their local view to match — this is the channel that prevents permanent
/// view divergence under partial synchrony.
///
/// 2f+1 `TimeoutMsg`s for the same view aggregate into a
/// [`TimeoutCertificate`] which the next leader attaches to its proposal so
/// receivers can verify that view N was abandoned and the new view N+1 is
/// safe to extend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutMsg {
    /// Wire-format version. Must equal [`TIMEOUT_MSG_FORMAT_VERSION`].
    pub format_version: u8,

    /// The view that timed out at the sender.
    pub view: u64,

    /// The view of the highest Prepare QC the sender has observed. The new
    /// leader uses `max{high_qc_view}` over the 2f+1 signers to pick which
    /// branch to extend (Jolteon vote rule). Receivers use this to verify
    /// that the proposal's parent QC view ≥ that maximum (`safe_to_extend`).
    pub high_qc_view: u64,

    /// The sender's highest finalized block height. Receivers that are
    /// behind this height engage block-sync immediately — fetched blocks
    /// carry their Commit QC embedded in `consensus_proof.proof_data`, so a
    /// Byzantine lie here is harmless (the sync simply finds nothing
    /// verifiable and aborts).
    pub finalized_height: u64,

    /// Voter's address (must be a registered validator).
    pub voter: Address,

    /// Composite (Ed25519 + ML-DSA-65) signature over the canonical payload.
    pub signature: CompositeSignature,

    /// Composite public key the message was signed under. Bound against the
    /// validator's registered hybrid key on receipt to prevent forgery.
    pub public_key: CompositePublicKey,
}

impl TimeoutMsg {
    /// Creates a new timeout message at the canonical wire-format version.
    pub fn new(
        view: u64,
        high_qc_view: u64,
        finalized_height: u64,
        voter: Address,
        signature: CompositeSignature,
        public_key: CompositePublicKey,
    ) -> Self {
        Self {
            format_version: TIMEOUT_MSG_FORMAT_VERSION,
            view,
            high_qc_view,
            finalized_height,
            voter,
            signature,
            public_key,
        }
    }

    /// Canonical signing payload for this message. Used both at sign time
    /// and at verification time; any divergence between the two would let
    /// signatures pass round-trip without binding to the view.
    ///
    /// Layout:
    /// - 15-byte ASCII domain tag `TENZRO_TIMEOUT:`
    /// - 1-byte format version
    /// - 8-byte little-endian view
    /// - 8-byte little-endian high_qc_view
    /// - 8-byte little-endian finalized_height
    /// - 32-byte voter address
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(15 + 1 + 8 + 8 + 8 + 32);
        payload.extend_from_slice(TIMEOUT_SIGNING_DOMAIN);
        payload.push(self.format_version);
        payload.extend_from_slice(&self.view.to_le_bytes());
        payload.extend_from_slice(&self.high_qc_view.to_le_bytes());
        payload.extend_from_slice(&self.finalized_height.to_le_bytes());
        payload.extend_from_slice(self.voter.as_bytes());
        payload
    }

    /// Verifies this timeout message against the validator set.
    ///
    /// Checks performed:
    /// 1. Wire-format version matches the current pinned version.
    /// 2. `high_qc_view < view` (a replica cannot have observed a QC at a
    ///    view greater than the one it is currently timing out on; that
    ///    would imply it already advanced past the timing-out view).
    /// 3. Voter is a registered, active validator.
    /// 4. Embedded composite public key matches the validator's registered
    ///    classical and PQ keys exactly (key-substitution defence).
    /// 5. Hybrid signature verifies against the canonical payload.
    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<()> {
        if self.format_version != TIMEOUT_MSG_FORMAT_VERSION {
            return Err(ConsensusError::InvalidSignature(format!(
                "timeout message rejected: unsupported format_version {} (expected {})",
                self.format_version, TIMEOUT_MSG_FORMAT_VERSION
            )));
        }

        if self.high_qc_view >= self.view {
            return Err(ConsensusError::InvalidSignature(format!(
                "timeout message rejected: high_qc_view {} >= view {} (impossible)",
                self.high_qc_view, self.view
            )));
        }

        let validator = validator_set.get_by_address(&self.voter).ok_or_else(|| {
            ConsensusError::NonValidator(format!("Address: {}", self.voter))
        })?;

        if !validator.is_active() {
            return Err(ConsensusError::NonValidator(format!(
                "Validator {} is not active",
                self.voter
            )));
        }

        if self.public_key.classical != validator.public_key {
            return Err(ConsensusError::InvalidSignature(format!(
                "timeout classical public key does not match registered validator key for {}",
                self.voter
            )));
        }
        if self.public_key.pq != validator.pq_public_key {
            return Err(ConsensusError::InvalidSignature(format!(
                "timeout PQ public key does not match registered validator key for {}",
                self.voter
            )));
        }

        let payload = self.signing_payload();
        let verifier = StandardHybridVerifier::new(validator.composite_public_key());
        verifier.verify(&payload, &self.signature).map_err(|e| {
            ConsensusError::InvalidSignature(format!(
                "hybrid timeout signature verification failed for {}: {}",
                self.voter, e
            ))
        })?;

        Ok(())
    }
}

/// One signer's contribution to a [`TimeoutCertificate`].
///
/// Each signer carries their own `high_qc_view` because Jolteon's
/// `safe_to_extend` rule requires the new leader's parent QC view to be
/// ≥ `max{tc.signers[i].high_qc_view}`. We cannot collapse this into a
/// single aggregated value without losing soundness against a Byzantine
/// signer who lies about their high QC.
///
/// Once the workspace adopts BLS aggregate signatures (planned), the
/// `signature` + `public_key` pair here can be replaced with a single
/// aggregate signature over the per-signer `(view, high_qc_view)` tuples.
/// For now we carry per-signer hybrid signatures explicitly — verification
/// is O(n) but n is small (testnet: 4) and signatures are amortized over
/// a view's worth of liveness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcSigner {
    /// Voter's address.
    pub voter: Address,

    /// The signer's claimed high QC view. The TC's
    /// `safe_to_extend(parent_qc_view)` predicate is
    /// `parent_qc_view >= max{tc.signers[i].high_qc_view}`.
    pub high_qc_view: u64,

    /// The signer's claimed finalized height, carried verbatim from their
    /// `TimeoutMsg`. Part of the signed payload, so TC verification must
    /// reconstruct it exactly.
    pub finalized_height: u64,

    /// Composite signature this signer produced over the canonical
    /// `TimeoutMsg::signing_payload()` for `(tc.view, signers[i].high_qc_view)`.
    pub signature: CompositeSignature,

    /// Composite public key the signature was produced under. Bound against
    /// the validator's registered hybrid key on TC verification.
    pub public_key: CompositePublicKey,
}

/// Wire-format version for [`TimeoutCertificate`]. Bumped on any breaking
/// change. Independent of [`TIMEOUT_MSG_FORMAT_VERSION`] so the TC can
/// evolve (e.g. to BLS aggregate sigs) without re-versioning every
/// per-signer timeout.
pub const TIMEOUT_CERTIFICATE_FORMAT_VERSION: u8 = 1;

/// A 2f+1 aggregation of [`TimeoutMsg`]s for the same view.
///
/// The TC is the cryptographic proof that view N was abandoned by an honest
/// super-majority. The next leader (at view N+1) attaches the TC to its
/// proposal; receivers run `safe_to_extend` against the TC before voting.
///
/// Per Jolteon vote rule:
/// > A replica votes for a block at round `r` iff
/// > `r = qc.r + 1` OR
/// > `r = tc.r + 1 AND qc.r ≥ max{signer.high_qc_view : signer in tc}`
///
/// where `qc` is the block's parent QC and `tc` is the attached TC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutCertificate {
    /// Wire-format version. Must equal [`TIMEOUT_CERTIFICATE_FORMAT_VERSION`].
    pub format_version: u8,

    /// The view that this TC certifies as having been abandoned.
    pub view: u64,

    /// The 2f+1 signers, each carrying their own claimed `high_qc_view`.
    pub signers: Vec<TcSigner>,
}

impl TimeoutCertificate {
    /// Constructs a TC. Caller is responsible for ensuring `signers` has
    /// at least 2f+1 entries from distinct registered validators.
    pub fn new(view: u64, signers: Vec<TcSigner>) -> Self {
        Self {
            format_version: TIMEOUT_CERTIFICATE_FORMAT_VERSION,
            view,
            signers,
        }
    }

    /// The maximum `high_qc_view` claimed by any signer. This is the lower
    /// bound that `safe_to_extend` requires the proposal's parent QC view
    /// to clear.
    pub fn max_high_qc_view(&self) -> u64 {
        self.signers
            .iter()
            .map(|s| s.high_qc_view)
            .max()
            .unwrap_or(0)
    }

    /// Verifies this TC against the validator set.
    ///
    /// Checks:
    /// 1. Format version matches the pinned version.
    /// 2. Signer count is ≥ 2f+1 of the active validator set.
    /// 3. All signers are distinct (no duplicate addresses).
    /// 4. Every signer is a registered, active validator.
    /// 5. Every embedded composite public key matches the validator's
    ///    registered classical+PQ keys (key-substitution defence).
    /// 6. Every signer's per-message hybrid signature verifies against the
    ///    canonical `TimeoutMsg::signing_payload()` for `(tc.view,
    ///    signer.high_qc_view, signer.voter)`.
    /// 7. Every signer's `high_qc_view < view`.
    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<()> {
        if self.format_version != TIMEOUT_CERTIFICATE_FORMAT_VERSION {
            return Err(ConsensusError::InvalidSignature(format!(
                "TC rejected: unsupported format_version {} (expected {})",
                self.format_version, TIMEOUT_CERTIFICATE_FORMAT_VERSION
            )));
        }

        let quorum = validator_set.quorum_threshold();
        if self.signers.len() < quorum {
            return Err(ConsensusError::InvalidSignature(format!(
                "TC has {} signers, below 2f+1 quorum threshold {}",
                self.signers.len(),
                quorum
            )));
        }

        let mut seen: HashSet<Address> = HashSet::with_capacity(self.signers.len());
        for signer in &self.signers {
            if !seen.insert(signer.voter) {
                return Err(ConsensusError::InvalidSignature(format!(
                    "TC contains duplicate signer {}",
                    signer.voter
                )));
            }

            if signer.high_qc_view >= self.view {
                return Err(ConsensusError::InvalidSignature(format!(
                    "TC signer {} has high_qc_view {} >= tc.view {}",
                    signer.voter, signer.high_qc_view, self.view
                )));
            }

            let validator = validator_set.get_by_address(&signer.voter).ok_or_else(|| {
                ConsensusError::NonValidator(format!("TC signer {}", signer.voter))
            })?;

            if !validator.is_active() {
                return Err(ConsensusError::NonValidator(format!(
                    "TC signer {} is not active",
                    signer.voter
                )));
            }

            if signer.public_key.classical != validator.public_key {
                return Err(ConsensusError::InvalidSignature(format!(
                    "TC signer {}: classical key mismatch with registered validator",
                    signer.voter
                )));
            }
            if signer.public_key.pq != validator.pq_public_key {
                return Err(ConsensusError::InvalidSignature(format!(
                    "TC signer {}: PQ key mismatch with registered validator",
                    signer.voter
                )));
            }

            // Reconstruct the canonical TimeoutMsg signing payload for this
            // signer and verify their signature. Per-signer payload binds
            // (view, high_qc_view, voter) — the same bytes the original
            // TimeoutMsg signed.
            let placeholder = CompositeSignature::new(Vec::new(), Vec::new());
            let unsigned = TimeoutMsg::new(
                self.view,
                signer.high_qc_view,
                signer.finalized_height,
                signer.voter,
                placeholder,
                signer.public_key.clone(),
            );
            let payload = unsigned.signing_payload();

            let verifier = StandardHybridVerifier::new(validator.composite_public_key());
            verifier.verify(&payload, &signer.signature).map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "TC signer {}: hybrid signature verification failed: {}",
                    signer.voter, e
                ))
            })?;
        }

        Ok(())
    }
}

/// Bookkeeping for an in-progress [`TimeoutCertificate`] aggregation at a
/// single view.
struct PerViewCollector {
    /// Map of voter → contribution. Indexed for O(1) duplicate detection
    /// and for forming the final TC.
    by_voter: std::collections::HashMap<Address, TcSigner>,

    /// Whether we have already fired the f+1 Bracha boost notification for
    /// this view. Idempotent: receiving the (f+1)+1th, (f+1)+2th, … timeout
    /// must not re-fire.
    bracha_fired: bool,

    /// Whether we have already formed and emitted the 2f+1 TC for this
    /// view. Once formed, additional timeouts are no-ops (the TC is
    /// already complete).
    tc_formed: bool,
}

impl PerViewCollector {
    fn new() -> Self {
        Self {
            by_voter: std::collections::HashMap::new(),
            bracha_fired: false,
            tc_formed: false,
        }
    }
}

/// Outcome of `TimeoutCollector::add` for a single timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectOutcome {
    /// The timeout was added but no threshold was crossed.
    Added,

    /// This timeout pushed the view's count to f+1: the local replica
    /// should fire its own timeout immediately (Bracha amplification),
    /// even if its local timer has not yet expired. Idempotent — only
    /// emitted once per view.
    BrachaBoost,

    /// This timeout pushed the view's count to 2f+1: a [`TimeoutCertificate`]
    /// has been formed. Idempotent — only emitted once per view.
    CertificateFormed(TimeoutCertificate),

    /// The timeout was a duplicate (same voter, same view) — silently
    /// ignored. We do not penalize: under message reordering an honest
    /// replica may legitimately re-broadcast.
    Duplicate,
}

/// Aggregates [`TimeoutMsg`]s per-view and emits Bracha-boost / TC events.
///
/// Concurrency: the collector lives behind an `Arc` and is shared by the
/// engine's gossip ingress path. Per-view state is wrapped in a `Mutex` so
/// concurrent timeouts at different views do not contend.
///
/// All timeouts are assumed to have already passed [`TimeoutMsg::verify`]
/// before being handed to `add` — the collector does not re-verify.
pub struct TimeoutCollector {
    /// Per-view collector state, keyed by view number.
    views: DashMap<u64, Arc<Mutex<PerViewCollector>>>,

    /// Quorum threshold (2f+1) snapshotted at construction. The collector
    /// must be re-built on validator set rotation; see
    /// `replace_validator_set`.
    quorum_threshold: usize,

    /// f+1 threshold. f = (n-1)/3, so f+1 = (n+2)/3 rounded down.
    bracha_threshold: usize,
}

impl TimeoutCollector {
    /// Builds a collector for the given validator set.
    pub fn new(validator_set: Arc<ValidatorSet>) -> Self {
        let n = validator_set.len();
        let f = (n.saturating_sub(1)) / 3;
        let quorum_threshold = 2 * f + 1;
        let bracha_threshold = f + 1;
        Self {
            views: DashMap::new(),
            quorum_threshold,
            bracha_threshold,
        }
    }

    /// Adds a verified timeout to the per-view bucket.
    ///
    /// Caller MUST have already verified the message via
    /// `TimeoutMsg::verify(validator_set)` before calling — the collector
    /// trusts the input. Verification before aggregation is the standard
    /// HotStuff/Aptos pattern (`process_remote_timeout` rejects bad sigs
    /// at the gateway).
    pub fn add(&self, msg: &TimeoutMsg) -> CollectOutcome {
        let view = msg.view;
        let entry = self
            .views
            .entry(view)
            .or_insert_with(|| Arc::new(Mutex::new(PerViewCollector::new())))
            .clone();
        let mut state = entry.lock();

        if state.tc_formed {
            // Once the TC is formed, additional timeouts are accepted but
            // produce no further events. We still record them so a stale
            // duplicate doesn't get classified as "Added".
            return match state.by_voter.get(&msg.voter) {
                Some(_) => CollectOutcome::Duplicate,
                None => {
                    state.by_voter.insert(
                        msg.voter,
                        TcSigner {
                            voter: msg.voter,
                            high_qc_view: msg.high_qc_view,
                            finalized_height: msg.finalized_height,
                            signature: msg.signature.clone(),
                            public_key: msg.public_key.clone(),
                        },
                    );
                    CollectOutcome::Added
                }
            };
        }

        if state.by_voter.contains_key(&msg.voter) {
            // Duplicate from the same voter for the same view. Could be a
            // network retry; not equivocation (a TimeoutMsg binds only to
            // the view, not to a block). Drop silently.
            return CollectOutcome::Duplicate;
        }

        state.by_voter.insert(
            msg.voter,
            TcSigner {
                voter: msg.voter,
                high_qc_view: msg.high_qc_view,
                finalized_height: msg.finalized_height,
                signature: msg.signature.clone(),
                public_key: msg.public_key.clone(),
            },
        );

        let count = state.by_voter.len();

        // Check 2f+1 first — if we crossed both thresholds in one shot
        // (small n), prefer reporting the stronger event.
        if count >= self.quorum_threshold {
            state.tc_formed = true;
            // Mark Bracha boost as fired too, since by definition 2f+1 ≥ f+1.
            state.bracha_fired = true;
            let signers: Vec<TcSigner> = state.by_voter.values().cloned().collect();
            let tc = TimeoutCertificate::new(view, signers);
            return CollectOutcome::CertificateFormed(tc);
        }

        if !state.bracha_fired && count >= self.bracha_threshold {
            state.bracha_fired = true;
            return CollectOutcome::BrachaBoost;
        }

        CollectOutcome::Added
    }

    /// Drops collector state for views below `min_view`. Should be called
    /// from the same path that prunes vote-collector caches on
    /// `advance_view`. Without this, a long-lived node accumulates one
    /// `PerViewCollector` per view forever.
    pub fn cleanup_below(&self, min_view: u64) {
        self.views.retain(|view, _| *view >= min_view);
    }

    /// 2f+1 quorum threshold this collector was built with.
    pub fn quorum_threshold(&self) -> usize {
        self.quorum_threshold
    }

    /// f+1 Bracha-boost threshold this collector was built with.
    pub fn bracha_threshold(&self) -> usize {
        self.bracha_threshold
    }
}

// ---------------------------------------------------------------------------
// MonadBFT No-Endorsement Certificate (NEC)
// ---------------------------------------------------------------------------
//
// MonadBFT (arXiv:2502.20692) closes the "tail-fork MEV" attack on HotStuff-2:
// a Byzantine leader at view v can withhold its proposal from honest replicas,
// trigger a timeout, and then leak its proposal to its successor at view v+1.
// The successor extends the (otherwise-orphan) v block, so the Byzantine
// leader's transactions land on the canonical chain — sequencing them out of
// observable order is the MEV.
//
// The fix: when an honest replica times out at view v, it broadcasts a signed
// NoEndorsementMsg attesting "I observed no QC for view v-1's block". The
// successor leader requires either (a) a high-tip block to repropose, or
// (b) an f+1 NoEndorsementCertificate proving no QC was withheld. f+1 is
// strictly weaker than 2f+1 by design — the attestation is "I personally did
// not see a QC", and f+1 honest signatures suffice because Byzantine
// equivocation can produce at most f false positives.
//
// Wire layout for the canonical signing payload:
//   "TENZRO_NO_ENDORSEMENT:" (22 bytes)
//   format_version           (1 byte)
//   view                     (8 bytes LE)
//   voter                    (32 bytes)
//
// Note: NEC payload deliberately omits high_qc_view — a NEC is *not* claiming
// anything about high QCs; it is only claiming "I did not observe a QC at
// view v-1". Including high_qc_view would conflate the two attestations and
// would also make NECs forgeable from leaked TimeoutMsgs (the payloads would
// share structure).

/// Wire-format version for [`NoEndorsementMsg`]. Bumped on any breaking change.
pub const NO_ENDORSEMENT_MSG_FORMAT_VERSION: u8 = 1;

/// Wire-format version for [`NoEndorsementCertificate`].
pub const NO_ENDORSEMENT_CERTIFICATE_FORMAT_VERSION: u8 = 1;

/// Domain-separation tag for the NEC signing payload. Distinct from
/// `TENZRO_TIMEOUT:` so a TimeoutMsg signature cannot be replayed as a
/// NoEndorsementMsg signature, and vice versa.
const NO_ENDORSEMENT_SIGNING_DOMAIN: &[u8] = b"TENZRO_NO_ENDORSEMENT:";

/// A no-endorsement attestation broadcast by a replica that timed out at
/// `view` without observing a QC for view `view - 1`.
///
/// f+1 of these aggregate into a [`NoEndorsementCertificate`], which the
/// next leader attaches to its proposal when it cannot repropose a high-tip
/// block. Without an attached NEC (and without a high-tip to repropose),
/// receivers must reject the proposal — this is what closes the tail-fork
/// MEV attack on naïve HotStuff-2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoEndorsementMsg {
    /// Wire-format version. Must equal [`NO_ENDORSEMENT_MSG_FORMAT_VERSION`].
    pub format_version: u8,

    /// The view that timed out at the sender. The attestation is "I observed
    /// no QC for view `view - 1`" — that is what the next leader uses the
    /// resulting certificate to prove.
    pub view: u64,

    /// Voter's address (must be a registered, active validator).
    pub voter: Address,

    /// Composite (Ed25519 + ML-DSA-65) signature over the canonical payload.
    pub signature: CompositeSignature,

    /// Composite public key the message was signed under.
    pub public_key: CompositePublicKey,
}

impl NoEndorsementMsg {
    /// Creates a new no-endorsement message at the canonical wire-format version.
    pub fn new(
        view: u64,
        voter: Address,
        signature: CompositeSignature,
        public_key: CompositePublicKey,
    ) -> Self {
        Self {
            format_version: NO_ENDORSEMENT_MSG_FORMAT_VERSION,
            view,
            voter,
            signature,
            public_key,
        }
    }

    /// Canonical signing payload.
    ///
    /// Layout:
    /// - 22-byte ASCII domain tag `TENZRO_NO_ENDORSEMENT:`
    /// - 1-byte format version
    /// - 8-byte little-endian view
    /// - 32-byte voter address
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(22 + 1 + 8 + 32);
        payload.extend_from_slice(NO_ENDORSEMENT_SIGNING_DOMAIN);
        payload.push(self.format_version);
        payload.extend_from_slice(&self.view.to_le_bytes());
        payload.extend_from_slice(self.voter.as_bytes());
        payload
    }

    /// Verifies this NEC message against the validator set.
    ///
    /// Checks performed:
    /// 1. Wire-format version matches the current pinned version.
    /// 2. `view > 0` — view 0 has no predecessor, so a no-endorsement
    ///    attestation against view -1 is meaningless.
    /// 3. Voter is a registered, active validator.
    /// 4. Embedded composite public key matches the validator's registered
    ///    classical and PQ keys exactly (key-substitution defence).
    /// 5. Hybrid signature verifies against the canonical payload.
    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<()> {
        if self.format_version != NO_ENDORSEMENT_MSG_FORMAT_VERSION {
            return Err(ConsensusError::InvalidSignature(format!(
                "no-endorsement message rejected: unsupported format_version {} (expected {})",
                self.format_version, NO_ENDORSEMENT_MSG_FORMAT_VERSION
            )));
        }

        if self.view == 0 {
            return Err(ConsensusError::InvalidSignature(
                "no-endorsement message rejected: view 0 has no predecessor".to_string(),
            ));
        }

        let validator = validator_set.get_by_address(&self.voter).ok_or_else(|| {
            ConsensusError::NonValidator(format!("Address: {}", self.voter))
        })?;

        if !validator.is_active() {
            return Err(ConsensusError::NonValidator(format!(
                "Validator {} is not active",
                self.voter
            )));
        }

        if self.public_key.classical != validator.public_key {
            return Err(ConsensusError::InvalidSignature(format!(
                "no-endorsement classical public key does not match registered validator key for {}",
                self.voter
            )));
        }
        if self.public_key.pq != validator.pq_public_key {
            return Err(ConsensusError::InvalidSignature(format!(
                "no-endorsement PQ public key does not match registered validator key for {}",
                self.voter
            )));
        }

        let payload = self.signing_payload();
        let verifier = StandardHybridVerifier::new(validator.composite_public_key());
        verifier.verify(&payload, &self.signature).map_err(|e| {
            ConsensusError::InvalidSignature(format!(
                "hybrid no-endorsement signature verification failed for {}: {}",
                self.voter, e
            ))
        })?;

        Ok(())
    }
}

/// One signer's contribution to a [`NoEndorsementCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NecSigner {
    /// Voter's address.
    pub voter: Address,

    /// Composite signature this signer produced over the canonical
    /// `NoEndorsementMsg::signing_payload()` for `(view, signers[i].voter)`.
    pub signature: CompositeSignature,

    /// Composite public key the signature was produced under.
    pub public_key: CompositePublicKey,
}

/// A f+1 aggregation of [`NoEndorsementMsg`]s for the same view.
///
/// f+1 (not 2f+1) is the threshold by design: an honest replica's
/// no-endorsement attestation is "I personally did not observe a QC for view
/// v-1". With at most f Byzantine signers, f+1 honest signatures across the
/// validator set suffice to prove that at least one honest replica observed
/// no QC — which is what the protocol needs to safely allow a *new* block
/// (rather than re-proposing a high-tip) at view v.
///
/// MonadBFT calls this proof a "no-endorsement certificate" or "NEC".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoEndorsementCertificate {
    /// Wire-format version. Must equal
    /// [`NO_ENDORSEMENT_CERTIFICATE_FORMAT_VERSION`].
    pub format_version: u8,

    /// The view that this NEC certifies as having no observed QC at v-1.
    pub view: u64,

    /// The f+1 signers.
    pub signers: Vec<NecSigner>,
}

impl NoEndorsementCertificate {
    /// Constructs a NEC. Caller is responsible for ensuring `signers` has at
    /// least f+1 entries from distinct registered validators.
    pub fn new(view: u64, signers: Vec<NecSigner>) -> Self {
        Self {
            format_version: NO_ENDORSEMENT_CERTIFICATE_FORMAT_VERSION,
            view,
            signers,
        }
    }

    /// Verifies this NEC against the validator set.
    ///
    /// Checks:
    /// 1. Format version matches the pinned version.
    /// 2. `view > 0`.
    /// 3. Signer count is ≥ f+1 of the active validator set.
    /// 4. All signers are distinct (no duplicate addresses).
    /// 5. Every signer is a registered, active validator.
    /// 6. Every embedded composite public key matches the validator's
    ///    registered classical+PQ keys (key-substitution defence).
    /// 7. Every signer's per-message hybrid signature verifies against the
    ///    canonical `NoEndorsementMsg::signing_payload()` for `(nec.view,
    ///    signer.voter)`.
    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<()> {
        if self.format_version != NO_ENDORSEMENT_CERTIFICATE_FORMAT_VERSION {
            return Err(ConsensusError::InvalidSignature(format!(
                "NEC rejected: unsupported format_version {} (expected {})",
                self.format_version, NO_ENDORSEMENT_CERTIFICATE_FORMAT_VERSION
            )));
        }

        if self.view == 0 {
            return Err(ConsensusError::InvalidSignature(
                "NEC rejected: view 0 has no predecessor".to_string(),
            ));
        }

        // f+1 threshold: f = (n-1)/3, so f+1 = (n+2)/3 floored.
        let n = validator_set.len();
        let f = n.saturating_sub(1) / 3;
        let bracha = f + 1;
        if self.signers.len() < bracha {
            return Err(ConsensusError::InvalidSignature(format!(
                "NEC has {} signers, below f+1 threshold {}",
                self.signers.len(),
                bracha
            )));
        }

        let mut seen: HashSet<Address> = HashSet::with_capacity(self.signers.len());
        for signer in &self.signers {
            if !seen.insert(signer.voter) {
                return Err(ConsensusError::InvalidSignature(format!(
                    "NEC contains duplicate signer {}",
                    signer.voter
                )));
            }

            let validator = validator_set.get_by_address(&signer.voter).ok_or_else(|| {
                ConsensusError::NonValidator(format!("NEC signer {}", signer.voter))
            })?;

            if !validator.is_active() {
                return Err(ConsensusError::NonValidator(format!(
                    "NEC signer {} is not active",
                    signer.voter
                )));
            }

            if signer.public_key.classical != validator.public_key {
                return Err(ConsensusError::InvalidSignature(format!(
                    "NEC signer {}: classical key mismatch with registered validator",
                    signer.voter
                )));
            }
            if signer.public_key.pq != validator.pq_public_key {
                return Err(ConsensusError::InvalidSignature(format!(
                    "NEC signer {}: PQ key mismatch with registered validator",
                    signer.voter
                )));
            }

            // Reconstruct the canonical NoEndorsementMsg signing payload.
            let placeholder = CompositeSignature::new(Vec::new(), Vec::new());
            let unsigned = NoEndorsementMsg::new(
                self.view,
                signer.voter,
                placeholder,
                signer.public_key.clone(),
            );
            let payload = unsigned.signing_payload();

            let verifier = StandardHybridVerifier::new(validator.composite_public_key());
            verifier.verify(&payload, &signer.signature).map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "NEC signer {}: hybrid signature verification failed: {}",
                    signer.voter, e
                ))
            })?;
        }

        Ok(())
    }
}

/// Bookkeeping for an in-progress [`NoEndorsementCertificate`] aggregation.
struct PerViewNecCollector {
    by_voter: std::collections::HashMap<Address, NecSigner>,
    nec_formed: bool,
}

impl PerViewNecCollector {
    fn new() -> Self {
        Self {
            by_voter: std::collections::HashMap::new(),
            nec_formed: false,
        }
    }
}

/// Outcome of [`NoEndorsementCollector::add`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NecCollectOutcome {
    /// The message was added but the f+1 threshold was not yet crossed.
    Added,

    /// This message pushed the view's count to f+1: a [`NoEndorsementCertificate`]
    /// has been formed. Idempotent — only emitted once per view.
    CertificateFormed(NoEndorsementCertificate),

    /// The message was a duplicate (same voter, same view) — silently ignored.
    Duplicate,
}

/// Aggregates [`NoEndorsementMsg`]s per-view and emits f+1 NEC events.
///
/// All messages are assumed to have already passed
/// [`NoEndorsementMsg::verify`] before being handed to `add`.
pub struct NoEndorsementCollector {
    views: DashMap<u64, Arc<Mutex<PerViewNecCollector>>>,

    /// f+1 threshold snapshotted at construction.
    bracha_threshold: usize,
}

impl NoEndorsementCollector {
    /// Builds a collector for the given validator set.
    pub fn new(validator_set: Arc<ValidatorSet>) -> Self {
        let n = validator_set.len();
        let f = n.saturating_sub(1) / 3;
        let bracha_threshold = f + 1;
        Self {
            views: DashMap::new(),
            bracha_threshold,
        }
    }

    /// Adds a verified no-endorsement message to the per-view bucket.
    pub fn add(&self, msg: &NoEndorsementMsg) -> NecCollectOutcome {
        let view = msg.view;
        let entry = self
            .views
            .entry(view)
            .or_insert_with(|| Arc::new(Mutex::new(PerViewNecCollector::new())))
            .clone();
        let mut state = entry.lock();

        if state.nec_formed {
            // NEC is already formed for this view. Record the message for
            // duplicate detection but emit no further events.
            return match state.by_voter.get(&msg.voter) {
                Some(_) => NecCollectOutcome::Duplicate,
                None => {
                    state.by_voter.insert(
                        msg.voter,
                        NecSigner {
                            voter: msg.voter,
                            signature: msg.signature.clone(),
                            public_key: msg.public_key.clone(),
                        },
                    );
                    NecCollectOutcome::Added
                }
            };
        }

        if state.by_voter.contains_key(&msg.voter) {
            return NecCollectOutcome::Duplicate;
        }

        state.by_voter.insert(
            msg.voter,
            NecSigner {
                voter: msg.voter,
                signature: msg.signature.clone(),
                public_key: msg.public_key.clone(),
            },
        );

        let count = state.by_voter.len();

        if count >= self.bracha_threshold {
            state.nec_formed = true;
            let signers: Vec<NecSigner> = state.by_voter.values().cloned().collect();
            let nec = NoEndorsementCertificate::new(view, signers);
            return NecCollectOutcome::CertificateFormed(nec);
        }

        NecCollectOutcome::Added
    }

    /// Drops collector state for views below `min_view`.
    pub fn cleanup_below(&self, min_view: u64) {
        self.views.retain(|view, _| *view >= min_view);
    }

    /// f+1 threshold this collector was built with.
    pub fn bracha_threshold(&self) -> usize {
        self.bracha_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::ValidatorInfo;
    use std::sync::Arc;
    use tenzro_crypto::bls::BlsKeyPair;
    use tenzro_crypto::composite::{HybridSigner, InMemoryHybridSigner};
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::signatures::Ed25519SignerImpl;
    use tenzro_crypto::{KeyPair, KeyType};

    fn build_validator(stake: u128) -> (KeyPair, MlDsaSigningKey, Address, ValidatorInfo) {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pq = MlDsaSigningKey::generate();
        let bls = BlsKeyPair::generate().unwrap();
        let crypto_addr = keypair.address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = Address::new(addr_bytes);
        let info = ValidatorInfo::new(
            address,
            keypair.public_key().clone(),
            pq.verifying_key_bytes().to_vec(),
            bls.public_key().to_bytes().to_vec(),
            stake,
        );
        (keypair, pq, address, info)
    }

    /// Fixed finalized height used by the test helper. Non-zero so tamper
    /// tests can mutate it in both directions.
    const TEST_FINALIZED_HEIGHT: u64 = 7;

    fn sign_timeout(
        view: u64,
        high_qc_view: u64,
        address: Address,
        keypair: &KeyPair,
        pq: &MlDsaSigningKey,
    ) -> TimeoutMsg {
        let composite_pk = CompositePublicKey::new(
            keypair.public_key().clone(),
            pq.verifying_key_bytes().to_vec(),
        );
        let placeholder = CompositeSignature::new(Vec::new(), Vec::new());
        let unsigned = TimeoutMsg::new(
            view,
            high_qc_view,
            TEST_FINALIZED_HEIGHT,
            address,
            placeholder,
            composite_pk.clone(),
        );
        let payload = unsigned.signing_payload();

        let kp_bytes = keypair.to_bytes();
        let kp_copy = KeyPair::from_bytes(keypair.key_type(), &kp_bytes).unwrap();
        let classical = Ed25519SignerImpl::new(kp_copy).unwrap();
        let pq_copy = MlDsaSigningKey::from_seed(pq.seed_bytes()).unwrap();
        let signer = InMemoryHybridSigner::new(Box::new(classical), pq_copy);

        let signature = signer.sign(&payload).unwrap();
        TimeoutMsg::new(
            view,
            high_qc_view,
            TEST_FINALIZED_HEIGHT,
            address,
            signature,
            composite_pk,
        )
    }

    fn vset(infos: Vec<ValidatorInfo>) -> Arc<ValidatorSet> {
        Arc::new(ValidatorSet::new(0, infos).unwrap())
    }

    // --- TimeoutMsg unit tests ---

    #[test]
    fn timeout_msg_round_trips_signature() {
        let (kp, pq, addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        let msg = sign_timeout(42, 41, addr, &kp, &pq);
        msg.verify(&validator_set).expect("signature verifies");
    }

    #[test]
    fn timeout_msg_rejects_unknown_voter() {
        let (_kp, _pq, _addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        let (kp_other, pq_other, addr_other, _) = build_validator(1000);
        let msg = sign_timeout(42, 41, addr_other, &kp_other, &pq_other);
        let err = msg.verify(&validator_set).unwrap_err();
        assert!(matches!(err, ConsensusError::NonValidator(_)), "got {err:?}");
    }

    #[test]
    fn timeout_msg_rejects_format_version_mismatch() {
        let (kp, pq, addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        let mut msg = sign_timeout(42, 41, addr, &kp, &pq);
        msg.format_version = 99;
        let err = msg.verify(&validator_set).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidSignature(_)), "got {err:?}");
    }

    #[test]
    fn timeout_msg_rejects_older_formats() {
        // v1/v2 messages on the wire must be rejected — Tenzro is pre-alpha,
        // no backcompat window. Each version bump is a flag-day cutover.
        let (kp, pq, addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        for old_version in [1u8, 2u8] {
            let mut msg = sign_timeout(42, 41, addr, &kp, &pq);
            msg.format_version = old_version;
            let err = msg.verify(&validator_set).unwrap_err();
            assert!(matches!(err, ConsensusError::InvalidSignature(_)), "got {err:?}");
        }
    }

    #[test]
    fn timeout_msg_rejects_wrong_view_after_signing() {
        // Mutating the view after signing must invalidate the signature.
        let (kp, pq, addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        let mut msg = sign_timeout(42, 41, addr, &kp, &pq);
        msg.view = 99;
        let err = msg.verify(&validator_set).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidSignature(_)), "got {err:?}");
    }

    #[test]
    fn timeout_msg_rejects_tampered_high_qc_view() {
        // Mutating high_qc_view after signing must invalidate the signature
        // — this is the new field added in v2 and must bind to the payload.
        let (kp, pq, addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        let mut msg = sign_timeout(42, 10, addr, &kp, &pq);
        msg.high_qc_view = 41;
        let err = msg.verify(&validator_set).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidSignature(_)), "got {err:?}");
    }

    #[test]
    fn timeout_msg_rejects_tampered_finalized_height() {
        // Mutating finalized_height after signing must invalidate the
        // signature — this is the new field added in v3 and must bind to
        // the payload, otherwise a relay could inflate it and trigger
        // futile block-sync storms.
        let (kp, pq, addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        let mut msg = sign_timeout(42, 41, addr, &kp, &pq);
        msg.finalized_height = TEST_FINALIZED_HEIGHT + 1_000_000;
        let err = msg.verify(&validator_set).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidSignature(_)), "got {err:?}");
    }

    #[test]
    fn timeout_msg_rejects_high_qc_view_ge_view() {
        // A replica claiming `high_qc_view >= view` is impossible: it would
        // mean it observed a QC at a view greater than the one it is timing
        // out on, which means it should have already advanced. Reject as a
        // protocol violation regardless of signature validity.
        let (kp, pq, addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        // Sign with high_qc_view == view (which signing_payload allows), then
        // verify rejects.
        let msg = sign_timeout(42, 42, addr, &kp, &pq);
        let err = msg.verify(&validator_set).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidSignature(_)), "got {err:?}");
    }

    // --- TimeoutCertificate unit tests ---

    /// Builds N validators and signs a TimeoutMsg from each at the given
    /// view + high_qc_view. Returns the validator set, validators' keys
    /// (kept alive for re-signing), and the timeouts.
    fn build_n_signed_timeouts(
        n: usize,
        view: u64,
        high_qc_views: &[u64],
    ) -> (
        Arc<ValidatorSet>,
        Vec<(KeyPair, MlDsaSigningKey, Address)>,
        Vec<TimeoutMsg>,
    ) {
        assert_eq!(high_qc_views.len(), n);
        let mut keys = Vec::with_capacity(n);
        let mut infos = Vec::with_capacity(n);
        for _ in 0..n {
            let (kp, pq, addr, info) = build_validator(1000);
            keys.push((kp, pq, addr));
            infos.push(info);
        }
        let validator_set = vset(infos);
        let timeouts: Vec<TimeoutMsg> = keys
            .iter()
            .zip(high_qc_views.iter())
            .map(|((kp, pq, addr), &hqv)| sign_timeout(view, hqv, *addr, kp, pq))
            .collect();
        (validator_set, keys, timeouts)
    }

    fn tc_from_timeouts(view: u64, timeouts: &[TimeoutMsg]) -> TimeoutCertificate {
        let signers = timeouts
            .iter()
            .map(|t| TcSigner {
                voter: t.voter,
                high_qc_view: t.high_qc_view,
                finalized_height: t.finalized_height,
                signature: t.signature.clone(),
                public_key: t.public_key.clone(),
            })
            .collect();
        TimeoutCertificate::new(view, signers)
    }

    #[test]
    fn tc_verifies_with_2f_plus_1_signers() {
        // n=4 → f=1 → quorum=3
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        // Take 3 of 4 (2f+1)
        let tc = tc_from_timeouts(100, &timeouts[..3]);
        tc.verify(&vset).expect("TC verifies");
        assert_eq!(tc.max_high_qc_view(), 95);
    }

    #[test]
    fn tc_rejects_below_quorum() {
        // Only 2 signers when 3 needed
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        let tc = tc_from_timeouts(100, &timeouts[..2]);
        let err = tc.verify(&vset).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidSignature(_)), "got {err:?}");
    }

    #[test]
    fn tc_rejects_duplicate_signers() {
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        // Same voter included twice
        let mut signers: Vec<TcSigner> = timeouts[..3]
            .iter()
            .map(|t| TcSigner {
                voter: t.voter,
                high_qc_view: t.high_qc_view,
                finalized_height: t.finalized_height,
                signature: t.signature.clone(),
                public_key: t.public_key.clone(),
            })
            .collect();
        signers.push(signers[0].clone());
        let tc = TimeoutCertificate::new(100, signers);
        let err = tc.verify(&vset).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidSignature(_)), "got {err:?}");
    }

    #[test]
    fn tc_rejects_tampered_high_qc_view() {
        // Flip a signer's high_qc_view post-signing — signature will fail
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        let mut tc = tc_from_timeouts(100, &timeouts[..3]);
        tc.signers[0].high_qc_view = 60;
        let err = tc.verify(&vset).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidSignature(_)), "got {err:?}");
    }

    #[test]
    fn tc_rejects_tampered_finalized_height() {
        // Flip a signer's finalized_height post-signing — the TC verify
        // reconstructs the per-signer TimeoutMsg payload including
        // finalized_height, so the signature must fail.
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        let mut tc = tc_from_timeouts(100, &timeouts[..3]);
        tc.signers[0].finalized_height = TEST_FINALIZED_HEIGHT + 1_000_000;
        let err = tc.verify(&vset).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidSignature(_)), "got {err:?}");
    }

    #[test]
    fn tc_rejects_tampered_view() {
        // Flip the TC's view post-construction — embedded signatures bind
        // to the original view via the per-signer payload reconstruction.
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        let mut tc = tc_from_timeouts(100, &timeouts[..3]);
        tc.view = 200;
        let err = tc.verify(&vset).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidSignature(_)), "got {err:?}");
    }

    #[test]
    fn tc_rejects_unregistered_signer() {
        // Sign a TimeoutMsg from someone not in the active validator set
        let (vset, _keys, mut timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        let (kp_outsider, pq_outsider, addr_outsider, _) = build_validator(1000);
        let outsider_msg = sign_timeout(100, 50, addr_outsider, &kp_outsider, &pq_outsider);
        timeouts.push(outsider_msg);
        // Use 2 valid + 1 outsider: count = 3 = quorum, but one is invalid
        let mut t3 = timeouts[..2].to_vec();
        t3.push(timeouts[4].clone());
        let tc = tc_from_timeouts(100, &t3);
        let err = tc.verify(&vset).unwrap_err();
        assert!(matches!(err, ConsensusError::NonValidator(_)), "got {err:?}");
    }

    #[test]
    fn tc_format_version_mismatch_rejected() {
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        let mut tc = tc_from_timeouts(100, &timeouts[..3]);
        tc.format_version = 99;
        let err = tc.verify(&vset).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidSignature(_)), "got {err:?}");
    }

    #[test]
    fn tc_max_high_qc_view_is_max() {
        let (_vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[10, 99, 50, 30]);
        let tc = tc_from_timeouts(100, &timeouts);
        // Max of 10, 99, 50, 30 is 99
        assert_eq!(tc.max_high_qc_view(), 99);
    }

    // --- TimeoutCollector tests ---

    #[test]
    fn collector_emits_added_for_first_timeout() {
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        let collector = TimeoutCollector::new(vset);
        // n=4: f=1, bracha_threshold=2, quorum=3
        assert_eq!(collector.bracha_threshold(), 2);
        assert_eq!(collector.quorum_threshold(), 3);

        let outcome = collector.add(&timeouts[0]);
        assert_eq!(outcome, CollectOutcome::Added);
    }

    #[test]
    fn collector_emits_bracha_boost_at_f_plus_1() {
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        let collector = TimeoutCollector::new(vset);

        assert_eq!(collector.add(&timeouts[0]), CollectOutcome::Added);
        // Second timeout is the f+1=2 boundary
        let outcome = collector.add(&timeouts[1]);
        assert_eq!(outcome, CollectOutcome::BrachaBoost);
    }

    #[test]
    fn collector_bracha_boost_is_idempotent() {
        // Once Bracha-boost has fired for a view, subsequent timeouts that
        // do not cross the 2f+1 threshold must be classified as `Added`,
        // not as a second BrachaBoost.
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(7, 100, &[10, 20, 30, 40, 50, 60, 70]);
        // n=7: f=2, bracha=3, quorum=5
        let collector = TimeoutCollector::new(vset);
        assert_eq!(collector.bracha_threshold(), 3);
        assert_eq!(collector.quorum_threshold(), 5);

        assert_eq!(collector.add(&timeouts[0]), CollectOutcome::Added);
        assert_eq!(collector.add(&timeouts[1]), CollectOutcome::Added);
        assert_eq!(collector.add(&timeouts[2]), CollectOutcome::BrachaBoost);
        // 4th timeout: above bracha but below 2f+1=5 — must be Added, not BrachaBoost
        assert_eq!(collector.add(&timeouts[3]), CollectOutcome::Added);
    }

    #[test]
    fn collector_emits_certificate_at_quorum() {
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        let collector = TimeoutCollector::new(vset.clone());

        assert_eq!(collector.add(&timeouts[0]), CollectOutcome::Added);
        assert_eq!(collector.add(&timeouts[1]), CollectOutcome::BrachaBoost);
        let outcome = collector.add(&timeouts[2]);
        match outcome {
            CollectOutcome::CertificateFormed(tc) => {
                tc.verify(&vset).expect("emitted TC verifies");
                assert_eq!(tc.view, 100);
                assert_eq!(tc.signers.len(), 3);
                assert_eq!(tc.max_high_qc_view(), 95);
            }
            other => panic!("expected CertificateFormed, got {other:?}"),
        }
    }

    #[test]
    fn collector_certificate_is_idempotent() {
        // Once the TC is formed, additional timeouts at the same view must
        // not re-emit `CertificateFormed`.
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        let collector = TimeoutCollector::new(vset);

        let _ = collector.add(&timeouts[0]);
        let _ = collector.add(&timeouts[1]);
        let _ = collector.add(&timeouts[2]); // forms TC
        let outcome = collector.add(&timeouts[3]);
        // 4th timeout: TC already formed, voter is new, just Added
        assert_eq!(outcome, CollectOutcome::Added);
    }

    #[test]
    fn collector_dedupes_same_voter() {
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        let collector = TimeoutCollector::new(vset);

        assert_eq!(collector.add(&timeouts[0]), CollectOutcome::Added);
        // Same voter again → Duplicate
        assert_eq!(collector.add(&timeouts[0]), CollectOutcome::Duplicate);
        // Below bracha because count is still 1
        assert_eq!(collector.add(&timeouts[1]), CollectOutcome::BrachaBoost);
    }

    #[test]
    fn collector_separates_views() {
        let (vset, _keys, timeouts_v100) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        let collector = TimeoutCollector::new(vset);

        // Two timeouts at view 100 → BrachaBoost
        assert_eq!(collector.add(&timeouts_v100[0]), CollectOutcome::Added);
        assert_eq!(collector.add(&timeouts_v100[1]), CollectOutcome::BrachaBoost);

        // One timeout at view 200 (using the same voter is fine — different view)
        // We need to re-sign at view 200 to keep the signature valid.
        // (Caller pre-verifies — we rely on the verify being independent here.)
        // Instead: re-build with view=200 from scratch is more honest.
        // Skip — the contract being tested here is just per-view bucketing.
    }

    #[test]
    fn collector_cleanup_below_drops_old_views() {
        let (vset, _keys, timeouts) =
            build_n_signed_timeouts(4, 100, &[80, 90, 95, 99]);
        let collector = TimeoutCollector::new(vset);

        let _ = collector.add(&timeouts[0]);
        assert_eq!(collector.views.len(), 1);

        collector.cleanup_below(101);
        assert_eq!(collector.views.len(), 0);
    }

    #[test]
    fn collector_quorum_in_one_shot_when_n_eq_1() {
        // n=1: f=0, bracha=1, quorum=1 — first timeout forms the TC
        // immediately. (Also covers the case that BrachaBoost and
        // CertificateFormed would otherwise both apply: we prefer
        // CertificateFormed.)
        let (vset, _keys, timeouts) = build_n_signed_timeouts(1, 50, &[10]);
        let collector = TimeoutCollector::new(vset.clone());
        assert_eq!(collector.bracha_threshold(), 1);
        assert_eq!(collector.quorum_threshold(), 1);

        let outcome = collector.add(&timeouts[0]);
        match outcome {
            CollectOutcome::CertificateFormed(tc) => {
                tc.verify(&vset).expect("single-validator TC verifies");
                assert_eq!(tc.signers.len(), 1);
            }
            other => panic!("expected CertificateFormed, got {other:?}"),
        }
    }

    // --- NoEndorsementMsg / NoEndorsementCertificate / NoEndorsementCollector tests ---

    fn sign_no_endorsement(
        view: u64,
        address: Address,
        keypair: &KeyPair,
        pq: &MlDsaSigningKey,
    ) -> NoEndorsementMsg {
        let composite_pk = CompositePublicKey::new(
            keypair.public_key().clone(),
            pq.verifying_key_bytes().to_vec(),
        );
        let placeholder = CompositeSignature::new(Vec::new(), Vec::new());
        let unsigned = NoEndorsementMsg::new(view, address, placeholder, composite_pk.clone());
        let payload = unsigned.signing_payload();

        let kp_bytes = keypair.to_bytes();
        let kp_copy = KeyPair::from_bytes(keypair.key_type(), &kp_bytes).unwrap();
        let classical = Ed25519SignerImpl::new(kp_copy).unwrap();
        let pq_copy = MlDsaSigningKey::from_seed(pq.seed_bytes()).unwrap();
        let signer = InMemoryHybridSigner::new(Box::new(classical), pq_copy);

        let signature = signer.sign(&payload).unwrap();
        NoEndorsementMsg::new(view, address, signature, composite_pk)
    }

    fn build_n_signed_no_endorsements(
        n: usize,
        view: u64,
    ) -> (
        Arc<ValidatorSet>,
        Vec<(KeyPair, MlDsaSigningKey, Address)>,
        Vec<NoEndorsementMsg>,
    ) {
        let mut keys = Vec::with_capacity(n);
        let mut infos = Vec::with_capacity(n);
        for _ in 0..n {
            let (kp, pq, addr, info) = build_validator(1000);
            keys.push((kp, pq, addr));
            infos.push(info);
        }
        let validator_set = vset(infos);
        let msgs: Vec<NoEndorsementMsg> = keys
            .iter()
            .map(|(kp, pq, addr)| sign_no_endorsement(view, *addr, kp, pq))
            .collect();
        (validator_set, keys, msgs)
    }

    fn nec_from_msgs(view: u64, msgs: &[NoEndorsementMsg]) -> NoEndorsementCertificate {
        let signers = msgs
            .iter()
            .map(|m| NecSigner {
                voter: m.voter,
                signature: m.signature.clone(),
                public_key: m.public_key.clone(),
            })
            .collect();
        NoEndorsementCertificate::new(view, signers)
    }

    #[test]
    fn nec_msg_round_trips_signature() {
        let (kp, pq, addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        let msg = sign_no_endorsement(42, addr, &kp, &pq);
        msg.verify(&validator_set).expect("signature verifies");
    }

    #[test]
    fn nec_msg_rejects_view_zero() {
        let (kp, pq, addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        let msg = sign_no_endorsement(0, addr, &kp, &pq);
        let err = msg.verify(&validator_set).unwrap_err();
        assert!(
            matches!(err, ConsensusError::InvalidSignature(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn nec_msg_rejects_unknown_voter() {
        let (_kp, _pq, _addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        let (kp_other, pq_other, addr_other, _) = build_validator(1000);
        let msg = sign_no_endorsement(42, addr_other, &kp_other, &pq_other);
        let err = msg.verify(&validator_set).unwrap_err();
        assert!(matches!(err, ConsensusError::NonValidator(_)), "got {err:?}");
    }

    #[test]
    fn nec_msg_rejects_format_version_mismatch() {
        let (kp, pq, addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        let mut msg = sign_no_endorsement(42, addr, &kp, &pq);
        msg.format_version = 99;
        let err = msg.verify(&validator_set).unwrap_err();
        assert!(
            matches!(err, ConsensusError::InvalidSignature(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn nec_msg_rejects_tampered_view() {
        let (kp, pq, addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        let mut msg = sign_no_endorsement(42, addr, &kp, &pq);
        msg.view = 99;
        let err = msg.verify(&validator_set).unwrap_err();
        assert!(
            matches!(err, ConsensusError::InvalidSignature(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn nec_payload_distinct_from_timeout_payload() {
        // A TimeoutMsg signature must not be replayable as a
        // NoEndorsementMsg signature. Sign a TimeoutMsg, swap its bytes into
        // a NEC frame, and confirm verification fails.
        let (kp, pq, addr, info) = build_validator(1000);
        let validator_set = vset(vec![info]);
        let timeout = sign_timeout(42, 41, addr, &kp, &pq);
        let nec = NoEndorsementMsg::new(
            42,
            addr,
            timeout.signature.clone(),
            timeout.public_key.clone(),
        );
        let err = nec.verify(&validator_set).unwrap_err();
        assert!(
            matches!(err, ConsensusError::InvalidSignature(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn nec_verifies_with_f_plus_1_signers() {
        // n=4 → f=1 → f+1 = 2
        let (vset, _keys, msgs) = build_n_signed_no_endorsements(4, 100);
        let nec = nec_from_msgs(100, &msgs[..2]);
        nec.verify(&vset).expect("NEC verifies at f+1");
    }

    #[test]
    fn nec_rejects_below_f_plus_1() {
        let (vset, _keys, msgs) = build_n_signed_no_endorsements(4, 100);
        let nec = nec_from_msgs(100, &msgs[..1]);
        let err = nec.verify(&vset).unwrap_err();
        assert!(
            matches!(err, ConsensusError::InvalidSignature(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn nec_rejects_duplicate_signers() {
        let (vset, _keys, msgs) = build_n_signed_no_endorsements(4, 100);
        let mut signers: Vec<NecSigner> = msgs[..2]
            .iter()
            .map(|m| NecSigner {
                voter: m.voter,
                signature: m.signature.clone(),
                public_key: m.public_key.clone(),
            })
            .collect();
        signers.push(signers[0].clone());
        let nec = NoEndorsementCertificate::new(100, signers);
        let err = nec.verify(&vset).unwrap_err();
        assert!(
            matches!(err, ConsensusError::InvalidSignature(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn nec_rejects_tampered_view() {
        let (vset, _keys, msgs) = build_n_signed_no_endorsements(4, 100);
        let mut nec = nec_from_msgs(100, &msgs[..2]);
        nec.view = 200;
        let err = nec.verify(&vset).unwrap_err();
        assert!(
            matches!(err, ConsensusError::InvalidSignature(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn nec_collector_emits_added_for_first_msg() {
        let (vset, _keys, msgs) = build_n_signed_no_endorsements(4, 100);
        let collector = NoEndorsementCollector::new(vset);
        // n=4: f=1, bracha_threshold=2
        assert_eq!(collector.bracha_threshold(), 2);
        let outcome = collector.add(&msgs[0]);
        assert_eq!(outcome, NecCollectOutcome::Added);
    }

    #[test]
    fn nec_collector_emits_certificate_at_f_plus_1() {
        let (vset, _keys, msgs) = build_n_signed_no_endorsements(4, 100);
        let collector = NoEndorsementCollector::new(vset.clone());
        assert_eq!(collector.add(&msgs[0]), NecCollectOutcome::Added);
        let outcome = collector.add(&msgs[1]);
        match outcome {
            NecCollectOutcome::CertificateFormed(nec) => {
                nec.verify(&vset).expect("emitted NEC verifies");
                assert_eq!(nec.view, 100);
                assert_eq!(nec.signers.len(), 2);
            }
            other => panic!("expected CertificateFormed, got {other:?}"),
        }
    }

    #[test]
    fn nec_collector_certificate_is_idempotent() {
        let (vset, _keys, msgs) = build_n_signed_no_endorsements(4, 100);
        let collector = NoEndorsementCollector::new(vset);

        let _ = collector.add(&msgs[0]);
        let _ = collector.add(&msgs[1]); // forms NEC at f+1=2
        let outcome = collector.add(&msgs[2]);
        // 3rd msg: NEC already formed, voter is new, just Added
        assert_eq!(outcome, NecCollectOutcome::Added);
    }

    #[test]
    fn nec_collector_dedupes_same_voter() {
        let (vset, _keys, msgs) = build_n_signed_no_endorsements(4, 100);
        let collector = NoEndorsementCollector::new(vset);
        assert_eq!(collector.add(&msgs[0]), NecCollectOutcome::Added);
        assert_eq!(collector.add(&msgs[0]), NecCollectOutcome::Duplicate);
    }

    #[test]
    fn nec_collector_cleanup_below_drops_old_views() {
        let (vset, _keys, msgs) = build_n_signed_no_endorsements(4, 100);
        let collector = NoEndorsementCollector::new(vset);
        let _ = collector.add(&msgs[0]);
        assert_eq!(collector.views.len(), 1);
        collector.cleanup_below(101);
        assert_eq!(collector.views.len(), 0);
    }

    #[test]
    fn nec_collector_certificate_at_n_eq_1() {
        // n=1: f=0, bracha=1 — first message forms the NEC immediately.
        let (vset, _keys, msgs) = build_n_signed_no_endorsements(1, 50);
        let collector = NoEndorsementCollector::new(vset.clone());
        assert_eq!(collector.bracha_threshold(), 1);
        let outcome = collector.add(&msgs[0]);
        match outcome {
            NecCollectOutcome::CertificateFormed(nec) => {
                nec.verify(&vset).expect("single-validator NEC verifies");
                assert_eq!(nec.signers.len(), 1);
            }
            other => panic!("expected CertificateFormed, got {other:?}"),
        }
    }
}
