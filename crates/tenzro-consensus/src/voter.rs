//! Vote handling and quorum certificate formation

use crate::error::{ConsensusError, Result};
use crate::validator::{EquivocationDetector, EquivocationEvidence, ValidatorSet};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_crypto::bls::{BlsPublicKey, BlsSignature};
use tenzro_crypto::composite::{CompositePublicKey, CompositeSignature, HybridVerifier, StandardHybridVerifier};
use tenzro_types::primitives::{Address, BlockHeight, Hash};

/// Length-checked serde for the QC's 96-byte BLS aggregate. `serde` does not
/// auto-derive `Serialize`/`Deserialize` for arrays larger than 32 bytes; we
/// don't want to add a `serde_big_array` dependency for one field, and we don't
/// want to widen `bls_aggregate` to `Vec<u8>` because the 96-byte invariant
/// (BLS12-381 G2 compressed point) is load-bearing for `BlsSignature::from_bytes`.
/// Wire format: a borrowed byte slice; deserialization rejects any length other
/// than 96.
mod bls_aggregate_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 96], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 96], D::Error> {
        let v: Vec<u8> = Vec::<u8>::deserialize(de)?;
        if v.len() != 96 {
            return Err(serde::de::Error::custom(format!(
                "QC bls_aggregate must be exactly 96 bytes, got {}",
                v.len()
            )));
        }
        let mut out = [0u8; 96];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

/// Wire-format version for the [`Vote`] payload.
///
/// History:
/// - `1`: pre-Wave-3d classical-only votes (Ed25519 only). Rejected.
/// - `2`: Wave 3d hybrid (classical + ML-DSA-65). Rejected after #171.
/// - `3`: #171 SyncInfo piggyback — `high_qc_view` field added and bound into
///   the signing payload so a downgrade attempt that strips the field would
///   produce a different signing target than the legitimate signer used.
/// - `4`: ROADMAP B.1 — BLS12-381 (`min_pk`) signature added as the third
///   vote leg alongside Ed25519 + ML-DSA-65 so the [`QuorumCertificate`] can
///   carry a single 96-byte aggregate signature instead of N Composite
///   signatures. The composite per-vote leg is retained for the PQ-hybrid
///   property; BLS provides the QC-level bandwidth/CPU win.
pub const VOTE_FORMAT_VERSION: u8 = 4;

/// A vote on a block proposal
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    /// Wire-format version. Must equal [`VOTE_FORMAT_VERSION`] (= 3) per #171.
    pub vote_format_version: u8,

    /// View number
    pub view: u64,

    /// Block height
    pub height: BlockHeight,

    /// Hash of the block being voted on
    pub block_hash: Hash,

    /// Voter's address
    pub voter: Address,

    /// Composite (classical + ML-DSA-65) signature over the canonical signing
    /// payload. Both legs are required during the hybrid window.
    pub signature: CompositeSignature,

    /// Composite (classical + ML-DSA-65) public key the vote is signed under.
    /// The vote collector binds this against the voter's registered hybrid key
    /// and refuses any mismatch as a forgery defence.
    pub public_key: CompositePublicKey,

    /// BLS12-381 signature (G2-compressed, 96 bytes, `min_pk` scheme) over the
    /// same canonical signing payload as `signature`. Mandatory under format
    /// version 4 — the [`VoteCollector`] aggregates these into the QC's single
    /// `bls_aggregate` field at quorum-formation time, collapsing N×96-byte
    /// QC bandwidth to one 96-byte aggregate plus a signer bitmap.
    ///
    /// Aggregation is sound because every signer commits to the same message
    /// (`signing_payload()` is fully derived from `(view, height, block_hash,
    /// voter, vote_type, high_qc_view)`); receivers re-aggregate the active
    /// validator set's `bls_public_key` entries against the bitmap and verify
    /// in constant time.
    pub bls_signature: BlsSignature,

    /// Vote type (prepare or commit)
    pub vote_type: VoteType,

    /// Highest Prepare-QC view the voter has observed at the moment they
    /// signed this vote. Must satisfy `high_qc_view < view`.
    ///
    /// Aptos `SyncInfo` pattern (#171): every consensus message carries the
    /// sender's view of the highest QC so a lagging peer can fast-forward
    /// without a separate sync RPC. Bound into the signing payload, so a
    /// Byzantine voter cannot tamper with this field after signing.
    pub high_qc_view: u64,
}

impl Vote {
    /// Creates a new vote with the canonical format version.
    ///
    /// `high_qc_view` MUST satisfy `high_qc_view < view`. The check is enforced
    /// by [`VoteCollector::add_vote`] on the receiving side.
    pub fn new(
        view: u64,
        height: BlockHeight,
        block_hash: Hash,
        voter: Address,
        signature: CompositeSignature,
        public_key: CompositePublicKey,
        bls_signature: BlsSignature,
        vote_type: VoteType,
        high_qc_view: u64,
    ) -> Self {
        Self {
            vote_format_version: VOTE_FORMAT_VERSION,
            view,
            height,
            block_hash,
            voter,
            signature,
            public_key,
            bls_signature,
            vote_type,
            high_qc_view,
        }
    }

    /// Returns a unique key for this vote
    pub fn key(&self) -> VoteKey {
        VoteKey {
            view: self.view,
            block_hash: self.block_hash,
            vote_type: self.vote_type,
        }
    }

    /// Computes the canonical signing payload for this vote.
    /// Used both for signing and for verification.
    ///
    /// Format version 3 (#171): `high_qc_view` is bound into the payload so a
    /// Byzantine peer cannot rewrite the SyncInfo piggyback after signing.
    /// The format version byte itself is also prefixed so a downgrade attempt
    /// that strips the field would produce a different signing target than
    /// the legitimate signer used.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"TENZRO_VOTE:");
        payload.push(self.vote_format_version);
        payload.extend_from_slice(&self.view.to_le_bytes());
        payload.extend_from_slice(&self.height.0.to_le_bytes());
        payload.extend_from_slice(self.block_hash.as_bytes());
        payload.extend_from_slice(self.voter.as_bytes());
        match self.vote_type {
            VoteType::Prepare => payload.push(0x01),
            VoteType::Commit => payload.push(0x02),
        }
        payload.extend_from_slice(&self.high_qc_view.to_le_bytes());
        payload
    }
}

/// Type of vote in HotStuff-2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VoteType {
    /// Prepare phase vote
    Prepare,
    /// Commit phase vote
    Commit,
}

/// Canonical BLS signing payload for a single vote (the per-signer message
/// every BLS signature aggregated into the QC commits to).
///
/// Distinct from [`Vote::signing_payload`] — that payload is the
/// per-voter-bound payload covered by the [`CompositeSignature`]. The BLS
/// payload is identical for every signer in a given (view, height, block,
/// vote_type) tuple, which is the precondition for sound BLS aggregation
/// under one DST.
///
/// Must match [`QuorumCertificate::bls_signing_payload`] byte-for-byte.
pub fn bls_payload_for_vote(vote: &Vote) -> Vec<u8> {
    let mut payload = Vec::with_capacity(14 + 1 + 8 + 8 + 32 + 1);
    payload.extend_from_slice(b"TENZRO_QC_BLS:");
    payload.push(VOTE_FORMAT_VERSION);
    payload.extend_from_slice(&vote.view.to_le_bytes());
    payload.extend_from_slice(&vote.height.0.to_le_bytes());
    payload.extend_from_slice(vote.block_hash.as_bytes());
    match vote.vote_type {
        VoteType::Prepare => payload.push(0x01),
        VoteType::Commit => payload.push(0x02),
    }
    payload
}

/// Key for identifying a vote
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VoteKey {
    pub view: u64,
    pub block_hash: Hash,
    pub vote_type: VoteType,
}

/// A quorum certificate aggregating votes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// View number
    pub view: u64,

    /// Block height
    pub height: BlockHeight,

    /// Hash of the certified block
    pub block_hash: Hash,

    /// Vote type
    pub vote_type: VoteType,

    /// Total voting power of the signers in `signer_bitmap`
    pub voting_power: u128,

    /// Aggregated BLS12-381 G2-compressed signature (96 bytes, `min_pk`
    /// scheme) over [`Self::bls_signing_payload`], summing the
    /// `bls_signature` of every contributing vote. The QC carries only this
    /// aggregate plus `signer_bitmap` — individual votes (with their ~3.4KB
    /// PQ-hybrid [`CompositeSignature`]s) stay in the local `VoteCollector`
    /// for forensics; slashing evidence flows through the
    /// `EquivocationDetector`, never through QCs.
    #[serde(with = "bls_aggregate_serde")]
    pub bls_aggregate: [u8; 96],

    /// Bitmap over the QC's epoch validator set (LSB-first within each byte,
    /// least-significant byte first). Bit `i` set ⇔ validator at index `i` of
    /// the active set contributed a vote (and therefore a BLS signature) to
    /// `bls_aggregate`. Receivers reconstruct the aggregated public key by
    /// summing the BLS public keys of the validators whose bits are set.
    ///
    /// Length is `ceil(active_set_len / 8)`.
    pub signer_bitmap: Vec<u8>,
}

impl QuorumCertificate {
    /// Creates a new quorum certificate
    pub fn new(
        view: u64,
        height: BlockHeight,
        block_hash: Hash,
        vote_type: VoteType,
        voting_power: u128,
        bls_aggregate: [u8; 96],
        signer_bitmap: Vec<u8>,
    ) -> Self {
        Self {
            view,
            height,
            block_hash,
            vote_type,
            voting_power,
            bls_aggregate,
            signer_bitmap,
        }
    }

    /// Returns the number of signers set in `signer_bitmap`
    pub fn signer_count(&self) -> usize {
        self.signer_bitmap
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum()
    }

    /// Resolves `signer_bitmap` to the addresses of the contributing
    /// validators, indexed against the given epoch's active set.
    ///
    /// The caller must pass the validator set that was active at this QC's
    /// epoch (`HotStuff2Engine::validator_set_for_height`); out-of-range bits
    /// are skipped rather than erroring because verification is
    /// [`Self::verify_bls_aggregate`]'s job — this is an attribution helper.
    pub fn signers(&self, validator_set: &crate::validator::ValidatorSet) -> Vec<Address> {
        let active = validator_set.active_validators();
        let mut out = Vec::new();
        for bit_index in 0..(self.signer_bitmap.len() * 8) {
            let byte = self.signer_bitmap[bit_index / 8];
            if (byte >> (bit_index % 8)) & 1 == 0 {
                continue;
            }
            if let Some(validator) = active.get(bit_index) {
                out.push(validator.address);
            }
        }
        out
    }

    /// Extracts a QC that was embedded in a block's `consensus_proof.proof_data`
    /// at finalization time by `HotStuff2Engine::finalize_with_commit_qc`.
    ///
    /// Returns `None` if `proof_data` is empty (pre-finalization blocks, or
    /// blocks finalized before the QC-embed change landed) or if the bytes
    /// fail to deserialize as a `QuorumCertificate`.
    ///
    /// This is the read-side counterpart to the embed step in `finalize_with_commit_qc`.
    /// Block-sync uses it to verify that a peer's served block was actually
    /// finalized by quorum without re-running consensus.
    pub fn extract_from_block(block: &tenzro_types::block::Block) -> Option<Self> {
        let bytes = &block.header.consensus_proof.proof_data;
        if bytes.is_empty() {
            return None;
        }
        bincode::deserialize::<Self>(bytes).ok()
    }

    /// Verifies a QC that crossed the network (block-sync import,
    /// catchup-on-proposal): re-aggregates the BLS public keys of validators
    /// whose bit is set in `signer_bitmap` against the active set, then
    /// verifies `bls_aggregate` in a single pairing check.
    ///
    /// The validator set passed in must be the one that was active at the
    /// QC's epoch (`HotStuff2Engine::validator_set_for_height`). Locally
    /// formed QCs (assembled by `VoteCollector` from individually verified
    /// votes) do not need re-verification.
    ///
    /// # Errors
    ///
    /// - Bitmap length does not match `ceil(active_set.len() / 8)`.
    /// - Any out-of-range bit is set (signer index ≥ active set size).
    /// - The set of signers does not meet the validator-set quorum threshold.
    /// - Any signer's `bls_public_key` is not a valid 48-byte G1 point.
    /// - The aggregate signature does not verify against the re-aggregated
    ///   public key over `Self::bls_signing_payload()`.
    pub fn verify_bls_aggregate(
        &self,
        validator_set: &crate::validator::ValidatorSet,
    ) -> Result<()> {
        let active = validator_set.active_validators();
        let n = active.len();
        let expected_bitmap_bytes = n.div_ceil(8);
        if self.signer_bitmap.len() != expected_bitmap_bytes {
            return Err(ConsensusError::InvalidSignature(format!(
                "QC signer_bitmap length {} does not match expected {} bytes for {} active validators",
                self.signer_bitmap.len(),
                expected_bitmap_bytes,
                n
            )));
        }

        // Walk bitmap, collect signer pubkeys + tally voting power. Normalized
        // weights are indexed identically to `active`, so we tally signed
        // stake-weight by bit index.
        let normalized = validator_set.normalized_weights();
        let mut signer_pks: Vec<BlsPublicKey> = Vec::new();
        let mut total_voting_power: u128 = 0;
        let mut signed_power: u128 = 0;
        for bit_index in 0..(expected_bitmap_bytes * 8) {
            let byte = self.signer_bitmap[bit_index / 8];
            if (byte >> (bit_index % 8)) & 1 == 0 {
                continue;
            }
            if bit_index >= n {
                return Err(ConsensusError::InvalidSignature(format!(
                    "QC signer_bitmap has bit {} set but active set only has {} validators",
                    bit_index, n
                )));
            }
            let validator = &active[bit_index];
            let pk = BlsPublicKey::from_bytes(&validator.bls_public_key).map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "QC signer {} has malformed BLS verifying key: {}",
                    validator.address, e
                ))
            })?;
            signer_pks.push(pk);
            total_voting_power = total_voting_power.saturating_add(validator.voting_power());
            if let Some(w) = normalized.get(bit_index) {
                signed_power = signed_power.saturating_add(*w);
            }
        }

        if signer_pks.is_empty() {
            return Err(ConsensusError::InvalidSignature(
                "QC signer_bitmap empty — no signers contributed to BLS aggregate".to_string(),
            ));
        }

        // Stake-weighted quorum on normalized weight (Sui model), not headcount.
        let quorum_power = validator_set.quorum_voting_power();
        if signed_power < quorum_power {
            return Err(ConsensusError::InvalidSignature(format!(
                "QC BLS aggregate carries {} stake-weight from {} signers, below quorum power {}",
                signed_power,
                signer_pks.len(),
                quorum_power
            )));
        }

        // The QC's per-vote `voting_power` field is filled at QC formation
        // from the same active set the bitmap indexes — keep them consistent.
        if self.voting_power != total_voting_power {
            return Err(ConsensusError::InvalidSignature(format!(
                "QC claims voting_power={} but bitmap-tallied power is {}",
                self.voting_power, total_voting_power
            )));
        }

        // Sum signer pubkeys into a single aggregate G1 point, then verify the
        // aggregate signature against the canonical BLS signing payload.
        let agg_pk = tenzro_crypto::bls::aggregate_public_keys(&signer_pks).map_err(|e| {
            ConsensusError::InvalidSignature(format!(
                "QC BLS aggregate public-key reconstruction failed: {}",
                e
            ))
        })?;
        let agg_pk_bytes = agg_pk.to_bytes();
        let agg_pk_single = BlsPublicKey::from_bytes(&agg_pk_bytes).map_err(|e| {
            ConsensusError::InvalidSignature(format!(
                "QC BLS aggregate public-key serialization round-trip failed: {}",
                e
            ))
        })?;

        let agg_sig = BlsSignature::from_bytes(&self.bls_aggregate).map_err(|e| {
            ConsensusError::InvalidSignature(format!(
                "QC bls_aggregate is not a valid BLS signature: {}",
                e
            ))
        })?;

        let payload = self.bls_signing_payload();
        let ok = agg_sig.verify(&agg_pk_single, &payload).map_err(|e| {
            ConsensusError::InvalidSignature(format!(
                "QC BLS aggregate verification raised error: {}",
                e
            ))
        })?;
        if !ok {
            return Err(ConsensusError::InvalidSignature(
                "QC BLS aggregate verification rejected the signature".to_string(),
            ));
        }

        Ok(())
    }

    /// Canonical message that every per-vote BLS signature commits to and that
    /// `bls_aggregate` must verify against.
    ///
    /// Distinct from [`Vote::signing_payload`] — that payload binds a single
    /// voter's address and is keyed per-vote. The BLS aggregate covers a
    /// per-QC payload that is identical for every signer in the bitmap, which
    /// is the precondition for sound BLS aggregation under one DST.
    ///
    /// Format:
    /// `"TENZRO_QC_BLS:" || vote_format_version(1) || view(u64 LE) ||
    ///  height(u64 LE) || block_hash(32) || vote_type(1)`.
    pub fn bls_signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(14 + 1 + 8 + 8 + 32 + 1);
        payload.extend_from_slice(b"TENZRO_QC_BLS:");
        payload.push(VOTE_FORMAT_VERSION);
        payload.extend_from_slice(&self.view.to_le_bytes());
        payload.extend_from_slice(&self.height.0.to_le_bytes());
        payload.extend_from_slice(self.block_hash.as_bytes());
        match self.vote_type {
            VoteType::Prepare => payload.push(0x01),
            VoteType::Commit => payload.push(0x02),
        }
        payload
    }
}

/// Manages vote collection and QC formation
pub struct VoteCollector {
    /// Collected votes by view and block
    votes: Arc<DashMap<VoteKey, Vec<Vote>>>,

    /// Formed quorum certificates
    quorum_certificates: Arc<DashMap<VoteKey, QuorumCertificate>>,

    /// Validator set
    validator_set: Arc<ValidatorSet>,

    /// Equivocation detector — detects validators voting for multiple blocks in the same view.
    /// Shared (`Arc`) so the engine's persistent detector survives the
    /// collector rebuilds that happen at every epoch transition.
    equivocation_detector: Arc<EquivocationDetector>,
}

impl VoteCollector {
    /// Creates a new vote collector with a fresh in-memory equivocation
    /// detector (test path — production uses [`Self::with_detector`]).
    pub fn new(validator_set: Arc<ValidatorSet>) -> Self {
        Self::with_detector(validator_set, Arc::new(EquivocationDetector::new()))
    }

    /// Creates a vote collector around a shared equivocation detector.
    /// The engine passes its long-lived (optionally storage-backed)
    /// detector here so conviction state survives epoch transitions and
    /// node restarts.
    pub fn with_detector(
        validator_set: Arc<ValidatorSet>,
        equivocation_detector: Arc<EquivocationDetector>,
    ) -> Self {
        Self {
            votes: Arc::new(DashMap::new()),
            quorum_certificates: Arc::new(DashMap::new()),
            validator_set,
            equivocation_detector,
        }
    }

    /// Adds a vote and returns a QC if quorum is reached
    ///
    /// # Security
    ///
    /// This method implements critical security checks (Issues #13, #14 - RESOLVED):
    /// 1. **Wave 3d hybrid signature verification**: The vote carries a composite
    ///    (Ed25519 + ML-DSA-65) signature plus the public key it was signed under.
    ///    Both legs must validate. Additionally the embedded `vote.public_key`
    ///    MUST match the validator's registered classical and PQ keys exactly —
    ///    a mismatch is treated as a forgery attempt (key-substitution defence).
    /// 2. **Vote-format-version pinning**: Only `VOTE_FORMAT_VERSION` (= 2) is
    ///    accepted. Older classical-only votes are rejected outright.
    /// 3. **Equivocation detection**: Checks if the validator has voted for multiple
    ///    conflicting blocks in the same view (Byzantine fault).
    ///
    /// All checks are performed BEFORE accepting the vote into the quorum.
    pub fn add_vote(&self, vote: Vote) -> Result<Option<QuorumCertificate>> {
        // Wave 3d: refuse any vote whose wire-format version is not the current
        // hybrid version. There is no fallback path — a peer that sends a v1
        // (classical-only) vote is gossiping pre-migration data and must be
        // dropped.
        if vote.vote_format_version != VOTE_FORMAT_VERSION {
            return Err(ConsensusError::InvalidSignature(format!(
                "vote rejected: unsupported vote_format_version {} (expected {})",
                vote.vote_format_version, VOTE_FORMAT_VERSION
            )));
        }

        // SyncInfo invariant (#171): a voter cannot honestly claim a Prepare-QC
        // at view ≥ the view they're voting in — they would have advanced past
        // it already. The vote rule on the receiver enforces this both as a
        // sanity check and as forgery defence (a Byzantine peer that inflates
        // `high_qc_view` to drag honest replicas forward gets rejected here).
        // The `view == 0` case is genesis; `high_qc_view` must be 0.
        if vote.view == 0 {
            if vote.high_qc_view != 0 {
                return Err(ConsensusError::InvalidSignature(format!(
                    "vote at view 0 must carry high_qc_view = 0, got {}",
                    vote.high_qc_view
                )));
            }
        } else if vote.high_qc_view >= vote.view {
            return Err(ConsensusError::InvalidSignature(format!(
                "vote high_qc_view {} must be < view {}",
                vote.high_qc_view, vote.view
            )));
        }

        // Verify the voter is a validator
        let validator = self
            .validator_set
            .get_by_address(&vote.voter)
            .ok_or_else(|| {
                ConsensusError::NonValidator(format!("Address: {}", vote.voter))
            })?;

        if !validator.is_active() {
            return Err(ConsensusError::NonValidator(format!(
                "Validator {} is not active",
                vote.voter
            )));
        }

        // Wave 3d: bind the embedded composite public key against the
        // validator's registered hybrid keys. Refuse any mismatch — a vote
        // signed under a different key pair is a forgery attempt even if the
        // signature itself would otherwise verify.
        if vote.public_key.classical != validator.public_key {
            return Err(ConsensusError::InvalidSignature(format!(
                "vote classical public key does not match registered validator key for {}",
                vote.voter
            )));
        }
        if vote.public_key.pq != validator.pq_public_key {
            return Err(ConsensusError::InvalidSignature(format!(
                "vote PQ public key does not match registered validator key for {}",
                vote.voter
            )));
        }

        // SECURITY (Issue #13 - RESOLVED): Hybrid signature verification.
        // Both the classical and ML-DSA-65 legs must validate against the
        // canonical signing payload — refuses downgrade attacks.
        let payload = vote.signing_payload();
        let verifier = StandardHybridVerifier::new(validator.composite_public_key());
        verifier
            .verify(&payload, &vote.signature)
            .map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "hybrid vote signature verification failed for {}: {}",
                    vote.voter, e
                ))
            })?;

        // ROADMAP B.1: third leg — BLS12-381. The vote MUST carry a BLS
        // signature over the QC-level canonical payload (`bls_signing_payload`
        // computed for this vote's view/height/hash/type) under the validator's
        // registered `bls_public_key`. Verifying the per-vote leg here
        // guarantees that when we aggregate at quorum the resulting aggregate
        // is sound — every contributing signature is already known-valid.
        let bls_pk = BlsPublicKey::from_bytes(&validator.bls_public_key).map_err(|e| {
            ConsensusError::InvalidSignature(format!(
                "validator {} has malformed BLS verifying key: {}",
                vote.voter, e
            ))
        })?;
        let bls_payload = bls_payload_for_vote(&vote);
        let bls_ok = vote
            .bls_signature
            .verify(&bls_pk, &bls_payload)
            .map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "BLS vote signature raised error for {}: {}",
                    vote.voter, e
                ))
            })?;
        if !bls_ok {
            return Err(ConsensusError::InvalidSignature(format!(
                "BLS vote signature verification failed for {}",
                vote.voter
            )));
        }

        // SECURITY (Issue #14 - RESOLVED): Equivocation detection
        // Check for equivocation BEFORE adding to the per-block vote set.
        // This detects validators voting for different blocks in the same view (Byzantine fault).
        match self.equivocation_detector.check_vote(&vote) {
            Ok(Some(evidence)) => {
                // Equivocation detected — return error with evidence
                tracing::error!(
                    validator = %vote.voter,
                    view = vote.view,
                    block1 = %evidence.vote1.block_hash,
                    block2 = %evidence.vote2.block_hash,
                    "Equivocation detected: validator voted for conflicting blocks"
                );
                return Err(ConsensusError::Equivocation {
                    validator: vote.voter.to_string(),
                    view: vote.view,
                });
            }
            Ok(None) => {
                // No equivocation, proceed normally
            }
            Err(ConsensusError::AlreadyVoted(v)) => {
                // Detector found exact duplicate (same view, same block) — fall through
                // to per-block duplicate check below for consistent error handling
                let _ = v;
            }
            Err(e) => return Err(e),
        }

        let vote_key = vote.key();

        // Check if QC already exists
        if let Some(qc) = self.quorum_certificates.get(&vote_key) {
            return Ok(Some(qc.clone()));
        }

        // Add vote to collection
        let mut votes_entry = self.votes.entry(vote_key.clone()).or_default();

        // Check if already voted on this specific block
        if votes_entry.iter().any(|v| v.voter == vote.voter) {
            return Err(ConsensusError::AlreadyVoted(vote.view));
        }

        votes_entry.push(vote.clone());

        // Raw (uncapped) stake sum — stored in the QC's `voting_power` field
        // and re-checked at verification time for tamper detection.
        let total_voting_power: u128 = votes_entry
            .iter()
            .filter_map(|v| self.validator_set.get_by_address(&v.voter))
            .map(|v| v.voting_power())
            .sum();

        // Quorum is decided on normalized stake weight (Sui model), not on a
        // head-count of voters. Zero-stake signers add zero weight.
        let voter_addrs: Vec<Address> = votes_entry.iter().map(|v| v.voter).collect();
        let signed_power = self.validator_set.voting_power_of(voter_addrs.iter());
        let quorum_power = self.validator_set.quorum_voting_power();

        // Check if we have quorum
        if signed_power >= quorum_power {
            // ROADMAP B.1: collapse the per-vote BLS signatures into a single
            // 96-byte aggregate plus a signer bitmap indexed against the
            // active validator set. Every signature was already verified in
            // the per-vote path above so the aggregate is sound by
            // construction.
            let bls_sigs: Vec<BlsSignature> = votes_entry
                .iter()
                .map(|v| v.bls_signature.clone())
                .collect();
            let agg = tenzro_crypto::bls::aggregate_signatures(&bls_sigs).map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "BLS aggregation at QC formation failed: {}",
                    e
                ))
            })?;
            let bls_aggregate = agg.to_bytes();

            // Bitmap layout: one bit per validator in `active_validators()`,
            // LSB-first within each byte, bytes in active-set order. Bit `i`
            // set ⇔ that validator's address contributed a vote.
            let active = self.validator_set.active_validators();
            let bitmap_bytes = active.len().div_ceil(8);
            let mut signer_bitmap = vec![0u8; bitmap_bytes];
            for v in votes_entry.iter() {
                if let Some(idx) = self.validator_set.index_of(&v.voter) {
                    signer_bitmap[idx / 8] |= 1u8 << (idx % 8);
                }
            }

            let qc = QuorumCertificate::new(
                vote.view,
                vote.height,
                vote.block_hash,
                vote.vote_type,
                total_voting_power,
                bls_aggregate,
                signer_bitmap,
            );

            // Store the QC
            self.quorum_certificates.insert(vote_key, qc.clone());

            tracing::info!(
                view = vote.view,
                height = vote.height.0,
                vote_type = ?vote.vote_type,
                signers = votes_entry.len(),
                signed_power = signed_power,
                quorum_power = quorum_power,
                "Quorum certificate formed"
            );

            Ok(Some(qc))
        } else {
            tracing::debug!(
                view = vote.view,
                height = vote.height.0,
                vote_type = ?vote.vote_type,
                signers = votes_entry.len(),
                signed_power = signed_power,
                quorum_power = quorum_power,
                "Vote collected, waiting for quorum"
            );
            Ok(None)
        }
    }

    /// Gets a quorum certificate for the given view and block
    pub fn get_qc(&self, view: u64, block_hash: Hash, vote_type: VoteType) -> Option<QuorumCertificate> {
        let key = VoteKey {
            view,
            block_hash,
            vote_type,
        };
        self.quorum_certificates.get(&key).map(|qc| qc.clone())
    }

    /// Gets all votes for a specific view and block
    pub fn get_votes(&self, view: u64, block_hash: Hash, vote_type: VoteType) -> Vec<Vote> {
        let key = VoteKey {
            view,
            block_hash,
            vote_type,
        };
        self.votes.get(&key).map(|v| v.clone()).unwrap_or_default()
    }

    /// Clears votes for views below the given height (cleanup)
    pub fn cleanup_old_votes(&self, min_view: u64) {
        self.votes.retain(|key, _| key.view >= min_view);
        self.quorum_certificates.retain(|key, _| key.view >= min_view);
        self.equivocation_detector.cleanup_old_votes(min_view);
    }

    /// Returns the number of votes for a specific proposal
    pub fn vote_count(&self, view: u64, block_hash: Hash, vote_type: VoteType) -> usize {
        let key = VoteKey {
            view,
            block_hash,
            vote_type,
        };
        self.votes.get(&key).map(|v| v.len()).unwrap_or(0)
    }

    /// Returns all detected equivocation evidence
    pub fn get_equivocation_evidence(&self) -> Vec<EquivocationEvidence> {
        self.equivocation_detector.get_all_evidence()
    }

    /// Returns equivocation evidence for a specific validator and view
    pub fn get_evidence_for(
        &self,
        validator: &Address,
        view: u64,
    ) -> Option<EquivocationEvidence> {
        self.equivocation_detector.get_evidence(validator, view)
    }

    /// Returns the number of detected equivocations
    pub fn equivocation_count(&self) -> usize {
        self.equivocation_detector.evidence_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::ValidatorInfo;
    use tenzro_crypto::bls::BlsKeyPair;
    use tenzro_crypto::composite::{HybridSigner, InMemoryHybridSigner};
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::signatures::Ed25519SignerImpl;
    use tenzro_crypto::{KeyPair, KeyType};

    struct TestValidator {
        info: ValidatorInfo,
        signer: InMemoryHybridSigner,
        bls: BlsKeyPair,
    }

    fn create_test_validator(stake: u128) -> TestValidator {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let crypto_addr = keypair.address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = tenzro_types::primitives::Address::new(addr_bytes);
        let pq = MlDsaSigningKey::generate();
        let pq_vk = pq.verifying_key_bytes().to_vec();
        let bls = BlsKeyPair::generate().unwrap();
        let info = ValidatorInfo::new(
            address,
            keypair.public_key().clone(),
            pq_vk,
            bls.public_key().to_bytes().to_vec(),
            stake,
        );
        let classical = Ed25519SignerImpl::new(keypair).unwrap();
        let signer = InMemoryHybridSigner::new(Box::new(classical), pq);
        TestValidator { info, signer, bls }
    }

    fn create_signed_vote(
        view: u64,
        height: BlockHeight,
        voter: tenzro_types::primitives::Address,
        vote_type: VoteType,
        signer: &InMemoryHybridSigner,
        bls: &BlsKeyPair,
    ) -> Vote {
        // Build vote with placeholder signatures first to compute payload.
        // Tests use `high_qc_view = 0` (genesis-like) unless the test
        // explicitly overrides it.
        let placeholder_sig = CompositeSignature::new(Vec::new(), Vec::new());
        let placeholder_bls = bls.sign(b"__placeholder__");
        let pk = signer.public_key().clone();
        let mut vote = Vote::new(
            view,
            height,
            Hash::default(),
            voter,
            placeholder_sig,
            pk,
            placeholder_bls,
            vote_type,
            0,
        );
        let payload = vote.signing_payload();
        let sig = signer.sign(&payload).unwrap();
        vote.signature = sig;
        let bls_payload = bls_payload_for_vote(&vote);
        vote.bls_signature = bls.sign(&bls_payload);
        vote
    }

    #[test]
    fn test_vote_collection() {
        let validators: Vec<TestValidator> = vec![
            create_test_validator(1000),
            create_test_validator(2000),
            create_test_validator(3000),
            create_test_validator(4000),
        ];

        let validator_infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info.clone()).collect();
        let validator_set = Arc::new(ValidatorSet::new(1, validator_infos).unwrap());
        let collector = VoteCollector::new(validator_set.clone());

        let view = 1;
        let height = BlockHeight::from(10);

        // Add first vote
        let vote1 = create_signed_vote(view, height, validators[0].info.address, VoteType::Prepare, &validators[0].signer, &validators[0].bls);
        let result = collector.add_vote(vote1).unwrap();
        assert!(result.is_none());

        // Add second vote
        let vote2 = create_signed_vote(view, height, validators[1].info.address, VoteType::Prepare, &validators[1].signer, &validators[1].bls);
        let result = collector.add_vote(vote2).unwrap();
        assert!(result.is_none());

        // Third vote: cumulative stake 1000+2000+3000 = 6000 of 10000 = 60%,
        // still below the > 2/3 (6667) stake-weighted quorum — no QC yet.
        let vote3 = create_signed_vote(view, height, validators[2].info.address, VoteType::Prepare, &validators[2].signer, &validators[2].bls);
        let result = collector.add_vote(vote3).unwrap();
        assert!(result.is_none());

        // Fourth vote: cumulative stake 10000 = 100% ≥ quorum → QC forms.
        let vote4 = create_signed_vote(view, height, validators[3].info.address, VoteType::Prepare, &validators[3].signer, &validators[3].bls);
        let result = collector.add_vote(vote4).unwrap();
        assert!(result.is_some());

        let qc = result.unwrap();
        assert_eq!(qc.signer_count(), 4);
        assert_eq!(qc.view, view);
    }

    #[test]
    fn test_duplicate_vote() {
        // Use 4 validators so quorum threshold is 3 (f=1, 2f+1=3)
        // This means first vote doesn't immediately form quorum
        let validators = [create_test_validator(1000),
            create_test_validator(1000),
            create_test_validator(1000),
            create_test_validator(1000)];
        let validator_infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info.clone()).collect();
        let validator_set = Arc::new(ValidatorSet::new(1, validator_infos).unwrap());
        let collector = VoteCollector::new(validator_set);

        let vote1 = create_signed_vote(1, BlockHeight::from(1), validators[0].info.address, VoteType::Prepare, &validators[0].signer, &validators[0].bls);
        collector.add_vote(vote1.clone()).unwrap();

        // Try to add same vote again - should error due to duplicate voter
        let result = collector.add_vote(vote1);
        assert!(result.is_err());
    }

    #[test]
    fn test_non_validator_vote() {
        let validators = [create_test_validator(1000)];
        let validator_infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info.clone()).collect();
        let validator_set = Arc::new(ValidatorSet::new(1, validator_infos).unwrap());
        let collector = VoteCollector::new(validator_set);

        // Create vote from non-validator (hybrid-signed but with an unknown identity)
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let crypto_addr = keypair.address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = tenzro_types::primitives::Address::new(addr_bytes);
        let pq = MlDsaSigningKey::generate();
        let classical = Ed25519SignerImpl::new(keypair).unwrap();
        let non_val_signer = InMemoryHybridSigner::new(Box::new(classical), pq);
        let non_val_bls = BlsKeyPair::generate().unwrap();
        let vote = create_signed_vote(1, BlockHeight::from(1), address, VoteType::Prepare, &non_val_signer, &non_val_bls);

        let result = collector.add_vote(vote);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_signature_vote() {
        let validators = [create_test_validator(1000)];
        let validator_infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info.clone()).collect();
        let validator_set = Arc::new(ValidatorSet::new(1, validator_infos).unwrap());
        let collector = VoteCollector::new(validator_set);

        // Create vote with garbage signature (both legs zeroed) but with the
        // legitimate validator's composite public key embedded so we hit the
        // signature verification path rather than the public-key binding check.
        let validator_pk = validators[0].signer.public_key().clone();
        let bad_sig = CompositeSignature::new(vec![0u8; 64], vec![0u8; 3309]);
        let bad_bls = validators[0].bls.sign(b"__garbage_payload__");
        let vote = Vote::new(
            1,
            BlockHeight::from(1),
            Hash::default(),
            validators[0].info.address,
            bad_sig,
            validator_pk,
            bad_bls,
            VoteType::Prepare,
            0,
        );

        let result = collector.add_vote(vote);
        assert!(result.is_err());
    }

    #[test]
    fn test_equivocation_detection_in_vote_collector() {
        // Use 4 validators so quorum isn't immediately formed
        let validators: Vec<TestValidator> = vec![
            create_test_validator(1000),
            create_test_validator(1000),
            create_test_validator(1000),
            create_test_validator(1000),
        ];

        let validator_infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info.clone()).collect();
        let validator_set = Arc::new(ValidatorSet::new(1, validator_infos).unwrap());
        let collector = VoteCollector::new(validator_set);

        let view = 1;
        let height = BlockHeight::from(10);

        // Validator 0 votes for block A (Hash::default())
        let vote_a = create_signed_vote(view, height, validators[0].info.address, VoteType::Prepare, &validators[0].signer, &validators[0].bls);
        let result = collector.add_vote(vote_a);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // No QC yet

        // Validator 0 votes for block B (different hash) in the SAME view
        // Need to create a vote with a different block hash but signed by the same validator
        let mut different_hash_bytes = [0u8; 32];
        different_hash_bytes[0] = 0xFF;
        let placeholder_sig = CompositeSignature::new(Vec::new(), Vec::new());
        let placeholder_bls_b = validators[0].bls.sign(b"__placeholder__");
        let pk_b = validators[0].signer.public_key().clone();
        let mut vote_b = Vote::new(
            view,
            height,
            Hash::new(different_hash_bytes),
            validators[0].info.address,
            placeholder_sig,
            pk_b,
            placeholder_bls_b,
            VoteType::Prepare,
            0,
        );
        let payload_b = vote_b.signing_payload();
        let sig_b = validators[0].signer.sign(&payload_b).unwrap();
        vote_b.signature = sig_b;
        let bls_payload_b = bls_payload_for_vote(&vote_b);
        vote_b.bls_signature = validators[0].bls.sign(&bls_payload_b);

        let result = collector.add_vote(vote_b);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::Equivocation { validator, view: v } => {
                assert_eq!(v, view);
                assert!(validator.contains(&validators[0].info.address.to_string()));
            }
            other => panic!("Expected Equivocation error, got: {:?}", other),
        }

        // Evidence should be preserved
        assert_eq!(collector.equivocation_count(), 1);
        let evidence = collector.get_evidence_for(&validators[0].info.address, view);
        assert!(evidence.is_some());
    }

    #[test]
    fn test_equivocation_cleanup() {
        let validators: Vec<TestValidator> = vec![
            create_test_validator(1000),
            create_test_validator(1000),
            create_test_validator(1000),
            create_test_validator(1000),
        ];

        let validator_infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info.clone()).collect();
        let validator_set = Arc::new(ValidatorSet::new(1, validator_infos).unwrap());
        let collector = VoteCollector::new(validator_set);

        // Add votes for views 1, 2, 3
        for view in 1..=3u64 {
            let vote = create_signed_vote(view, BlockHeight::from(10), validators[0].info.address, VoteType::Prepare, &validators[0].signer, &validators[0].bls);
            let _ = collector.add_vote(vote);
        }

        // Cleanup old votes below view 2
        collector.cleanup_old_votes(2);

        // View 1 votes should be gone; views 2 and 3 should remain
        assert_eq!(collector.vote_count(1, Hash::default(), VoteType::Prepare), 0);
        assert_eq!(collector.vote_count(2, Hash::default(), VoteType::Prepare), 1);
        assert_eq!(collector.vote_count(3, Hash::default(), VoteType::Prepare), 1);
    }

    /// Drives a 4-validator collector to quorum and returns
    /// `(qc, validator_set, validators)` so individual aggregate-verification
    /// tests can mutate the QC and re-verify it against the active set.
    fn build_quorum_qc() -> (
        QuorumCertificate,
        Arc<crate::validator::ValidatorSet>,
        Vec<TestValidator>,
    ) {
        let validators: Vec<TestValidator> = vec![
            create_test_validator(1000),
            create_test_validator(1000),
            create_test_validator(1000),
            create_test_validator(1000),
        ];

        let validator_infos: Vec<ValidatorInfo> =
            validators.iter().map(|v| v.info.clone()).collect();
        let validator_set = Arc::new(ValidatorSet::new(1, validator_infos).unwrap());
        let collector = VoteCollector::new(validator_set.clone());

        let view = 7u64;
        let height = BlockHeight::from(42);
        let block_hash = Hash::default();

        // 3 votes meets the 4-validator (f=1, 2f+1=3) quorum threshold.
        let v0 = create_signed_vote(
            view,
            height,
            validators[0].info.address,
            VoteType::Prepare,
            &validators[0].signer,
            &validators[0].bls,
        );
        let v1 = create_signed_vote(
            view,
            height,
            validators[1].info.address,
            VoteType::Prepare,
            &validators[1].signer,
            &validators[1].bls,
        );
        let v2 = create_signed_vote(
            view,
            height,
            validators[2].info.address,
            VoteType::Prepare,
            &validators[2].signer,
            &validators[2].bls,
        );

        assert!(collector.add_vote(v0).unwrap().is_none());
        assert!(collector.add_vote(v1).unwrap().is_none());
        let qc = collector
            .add_vote(v2)
            .unwrap()
            .expect("third vote should form quorum");

        // Sanity: QC was filed against the (view, block_hash, vote_type) we drove.
        assert_eq!(qc.view, view);
        assert_eq!(qc.height, height);
        assert_eq!(qc.block_hash, block_hash);
        assert_eq!(qc.vote_type, VoteType::Prepare);

        (qc, validator_set, validators)
    }

    #[test]
    fn test_qc_bls_aggregate_verifies_under_quorum() {
        let (qc, validator_set, _validators) = build_quorum_qc();
        qc.verify_bls_aggregate(&validator_set)
            .expect("honest QC should verify via the BLS aggregate fast-path");
    }

    #[test]
    fn test_qc_bls_aggregate_rejects_single_byte_tamper() {
        let (qc, validator_set, _validators) = build_quorum_qc();
        let mut tampered = qc.clone();
        // Flip one bit in the aggregate signature. blst will either reject the
        // point as malformed or the pairing check will fail; either way
        // `verify_bls_aggregate` must not return Ok.
        tampered.bls_aggregate[42] ^= 0x01;
        let res = tampered.verify_bls_aggregate(&validator_set);
        assert!(
            res.is_err(),
            "single-byte tamper of bls_aggregate must fail verification"
        );
    }

    #[test]
    fn test_qc_bls_aggregate_rejects_bitmap_length_mismatch() {
        let (qc, validator_set, _validators) = build_quorum_qc();
        let mut tampered = qc.clone();
        // For 4 validators the bitmap is exactly 1 byte; pad an extra byte to
        // break the length invariant `ceil(active_set.len() / 8)`.
        tampered.signer_bitmap.push(0u8);
        let err = tampered
            .verify_bls_aggregate(&validator_set)
            .expect_err("bitmap length mismatch must fail verification");
        match err {
            ConsensusError::InvalidSignature(msg) => {
                assert!(
                    msg.contains("signer_bitmap length"),
                    "expected length-mismatch error, got: {msg}"
                );
            }
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn test_qc_bls_aggregate_rejects_sub_quorum_bitmap() {
        let (qc, validator_set, _validators) = build_quorum_qc();
        let mut tampered = qc.clone();
        // Clear all signer bits — the aggregate now claims zero contributors,
        // which trips the empty-signers branch (sub-quorum is the same class
        // of failure: signers < threshold).
        for byte in tampered.signer_bitmap.iter_mut() {
            *byte = 0u8;
        }
        let err = tampered
            .verify_bls_aggregate(&validator_set)
            .expect_err("empty signer bitmap must fail verification");
        match err {
            ConsensusError::InvalidSignature(msg) => {
                assert!(
                    msg.contains("signer_bitmap empty")
                        || msg.contains("below quorum threshold"),
                    "expected empty/sub-quorum error, got: {msg}"
                );
            }
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }
}
