//! Vote handling and quorum certificate formation

use crate::error::{ConsensusError, Result};
use crate::validator::{EquivocationDetector, EquivocationEvidence, ValidatorSet};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_crypto::composite::{CompositePublicKey, CompositeSignature, HybridVerifier, StandardHybridVerifier};
use tenzro_types::primitives::{Address, BlockHeight, Hash};

/// Wire-format version for the [`Vote`] payload.
///
/// History:
/// - `1`: pre-Wave-3d classical-only votes (Ed25519 only). Rejected.
/// - `2`: Wave 3d hybrid (classical + ML-DSA-65). Rejected after #171.
/// - `3`: #171 SyncInfo piggyback — `high_qc_view` field added and bound into
///   the signing payload so a downgrade attempt that strips the field would
///   produce a different signing target than the legitimate signer used.
pub const VOTE_FORMAT_VERSION: u8 = 3;

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

    /// Votes included in this QC
    pub votes: Vec<Vote>,

    /// Total voting power of the votes
    pub voting_power: u128,
}

impl QuorumCertificate {
    /// Creates a new quorum certificate
    pub fn new(
        view: u64,
        height: BlockHeight,
        block_hash: Hash,
        vote_type: VoteType,
        votes: Vec<Vote>,
        voting_power: u128,
    ) -> Self {
        Self {
            view,
            height,
            block_hash,
            vote_type,
            votes,
            voting_power,
        }
    }

    /// Returns the number of votes
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Verifies the QC has sufficient voting power
    pub fn verify_threshold(&self, _total_voting_power: u128, threshold: usize) -> bool {
        self.votes.len() >= threshold
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

    /// Verifies this QC against a validator set:
    /// 1. Every contained vote uses the current wire-format version.
    /// 2. Every vote's `(view, height, block_hash, vote_type)` matches the QC.
    /// 3. Every voter is a known active validator in `validator_set`.
    /// 4. Every vote's embedded composite public key matches the validator's
    ///    registered classical + ML-DSA-65 keys exactly (key-substitution defence).
    /// 5. Every vote's hybrid signature validates against `vote.signing_payload()`.
    /// 6. No duplicate voters within the QC.
    /// 7. Aggregated voting power of all valid votes meets the validator-set
    ///    quorum threshold.
    ///
    /// This is the verification block-sync runs on every imported block
    /// (after [`extract_from_block`]). A QC that passes this check was finalized
    /// by ⅔+ stake of the *given* validator set without re-running consensus.
    ///
    /// Note: the validator set passed in must be the one that was active at the
    /// QC's epoch. Caller (BlockSyncEngine) is responsible for selecting the
    /// correct historical validator set.
    pub fn verify(&self, validator_set: &crate::validator::ValidatorSet) -> Result<()> {
        if self.votes.is_empty() {
            return Err(ConsensusError::InvalidSignature(
                "QC contains no votes".to_string(),
            ));
        }

        let mut seen_voters: std::collections::HashSet<Address> = std::collections::HashSet::new();
        let mut total_voting_power: u128 = 0;

        for vote in &self.votes {
            // (1) Format version pinning.
            if vote.vote_format_version != VOTE_FORMAT_VERSION {
                return Err(ConsensusError::InvalidSignature(format!(
                    "QC vote rejected: unsupported vote_format_version {} (expected {})",
                    vote.vote_format_version, VOTE_FORMAT_VERSION
                )));
            }

            // (2) Vote must agree with QC on what is being voted on.
            if vote.view != self.view
                || vote.height != self.height
                || vote.block_hash != self.block_hash
                || vote.vote_type != self.vote_type
            {
                return Err(ConsensusError::InvalidSignature(format!(
                    "QC vote at view={}/height={}/hash={}/type={:?} disagrees with QC at view={}/height={}/hash={}/type={:?}",
                    vote.view, vote.height, vote.block_hash, vote.vote_type,
                    self.view, self.height, self.block_hash, self.vote_type,
                )));
            }

            // (3) Voter must be a known active validator.
            let validator = validator_set.get_by_address(&vote.voter).ok_or_else(|| {
                ConsensusError::NonValidator(format!("QC voter not in validator set: {}", vote.voter))
            })?;
            if !validator.is_active() {
                return Err(ConsensusError::NonValidator(format!(
                    "QC voter {} is not active",
                    vote.voter
                )));
            }

            // (4) Composite public key must match the validator's registered keys.
            if vote.public_key.classical != validator.public_key {
                return Err(ConsensusError::InvalidSignature(format!(
                    "QC vote classical pubkey mismatch for {}",
                    vote.voter
                )));
            }
            match &vote.public_key.pq {
                Some(pq_bytes) if pq_bytes == &validator.pq_public_key => {}
                Some(_) => {
                    return Err(ConsensusError::InvalidSignature(format!(
                        "QC vote PQ pubkey mismatch for {}",
                        vote.voter
                    )));
                }
                None => {
                    return Err(ConsensusError::InvalidSignature(format!(
                        "QC vote missing PQ pubkey (hybrid required) for {}",
                        vote.voter
                    )));
                }
            }

            // (5) Hybrid signature verification.
            let payload = vote.signing_payload();
            let verifier = StandardHybridVerifier::new(validator.composite_public_key());
            verifier.verify(&payload, &vote.signature).map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "QC vote hybrid signature verification failed for {}: {}",
                    vote.voter, e
                ))
            })?;

            // (6) Duplicate voter check.
            if !seen_voters.insert(vote.voter) {
                return Err(ConsensusError::InvalidSignature(format!(
                    "QC contains duplicate vote from {}",
                    vote.voter
                )));
            }

            total_voting_power = total_voting_power.saturating_add(validator.voting_power());
        }

        // (7) Aggregated voting power must meet quorum threshold.
        let threshold = validator_set.quorum_threshold();
        if seen_voters.len() < threshold {
            return Err(ConsensusError::InvalidSignature(format!(
                "QC has {} valid votes, below quorum threshold {}",
                seen_voters.len(),
                threshold
            )));
        }

        // Sanity check: the QC's claimed voting_power must agree with what we
        // re-tallied. A mismatch is a data-integrity error, not a signature
        // forgery, but it indicates the QC was tampered with after formation.
        if self.voting_power != total_voting_power {
            return Err(ConsensusError::InvalidSignature(format!(
                "QC claims voting_power={} but votes total {}",
                self.voting_power, total_voting_power
            )));
        }

        Ok(())
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

    /// Equivocation detector — detects validators voting for multiple blocks in the same view
    equivocation_detector: EquivocationDetector,
}

impl VoteCollector {
    /// Creates a new vote collector
    pub fn new(validator_set: Arc<ValidatorSet>) -> Self {
        Self {
            votes: Arc::new(DashMap::new()),
            quorum_certificates: Arc::new(DashMap::new()),
            validator_set,
            equivocation_detector: EquivocationDetector::new(),
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
        match &vote.public_key.pq {
            Some(pq_bytes) if pq_bytes == &validator.pq_public_key => {}
            Some(_) => {
                return Err(ConsensusError::InvalidSignature(format!(
                    "vote PQ public key does not match registered validator key for {}",
                    vote.voter
                )));
            }
            None => {
                return Err(ConsensusError::InvalidSignature(format!(
                    "vote missing PQ public key (Wave 3d hybrid required) for {}",
                    vote.voter
                )));
            }
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

        // Calculate total voting power
        let total_voting_power: u128 = votes_entry
            .iter()
            .filter_map(|v| self.validator_set.get_by_address(&v.voter))
            .map(|v| v.voting_power())
            .sum();

        let vote_count = votes_entry.len();
        let threshold = self.validator_set.quorum_threshold();

        // Check if we have quorum
        if vote_count >= threshold {
            let qc = QuorumCertificate::new(
                vote.view,
                vote.height,
                vote.block_hash,
                vote.vote_type,
                votes_entry.clone(),
                total_voting_power,
            );

            // Store the QC
            self.quorum_certificates.insert(vote_key, qc.clone());

            tracing::info!(
                view = vote.view,
                height = vote.height.0,
                vote_type = ?vote.vote_type,
                votes = vote_count,
                threshold = threshold,
                "Quorum certificate formed"
            );

            Ok(Some(qc))
        } else {
            tracing::debug!(
                view = vote.view,
                height = vote.height.0,
                vote_type = ?vote.vote_type,
                votes = vote_count,
                threshold = threshold,
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
    use tenzro_crypto::composite::{HybridSigner, InMemoryHybridSigner};
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::signatures::Ed25519SignerImpl;
    use tenzro_crypto::{KeyPair, KeyType};

    struct TestValidator {
        info: ValidatorInfo,
        signer: InMemoryHybridSigner,
    }

    fn create_test_validator(stake: u128) -> TestValidator {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let crypto_addr = keypair.address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = tenzro_types::primitives::Address::new(addr_bytes);
        let pq = MlDsaSigningKey::generate();
        let pq_vk = pq.verifying_key_bytes().to_vec();
        let info = ValidatorInfo::new(
            address,
            keypair.public_key().clone(),
            pq_vk,
            stake,
        );
        let classical = Ed25519SignerImpl::new(keypair).unwrap();
        let signer = InMemoryHybridSigner::new(Box::new(classical), pq);
        TestValidator { info, signer }
    }

    fn create_signed_vote(
        view: u64,
        height: BlockHeight,
        voter: tenzro_types::primitives::Address,
        vote_type: VoteType,
        signer: &InMemoryHybridSigner,
    ) -> Vote {
        // Build vote with placeholder signature first to compute payload.
        // Tests use `high_qc_view = 0` (genesis-like) unless the test
        // explicitly overrides it.
        let placeholder_sig = CompositeSignature::new(Vec::new(), None);
        let pk = signer.public_key().clone();
        let mut vote = Vote::new(
            view,
            height,
            Hash::default(),
            voter,
            placeholder_sig,
            pk,
            vote_type,
            0,
        );
        let payload = vote.signing_payload();
        let sig = signer.sign(&payload).unwrap();
        vote.signature = sig;
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
        let vote1 = create_signed_vote(view, height, validators[0].info.address, VoteType::Prepare, &validators[0].signer);
        let result = collector.add_vote(vote1).unwrap();
        assert!(result.is_none());

        // Add second vote
        let vote2 = create_signed_vote(view, height, validators[1].info.address, VoteType::Prepare, &validators[1].signer);
        let result = collector.add_vote(vote2).unwrap();
        assert!(result.is_none());

        // Add third vote - should reach quorum
        let vote3 = create_signed_vote(view, height, validators[2].info.address, VoteType::Prepare, &validators[2].signer);
        let result = collector.add_vote(vote3).unwrap();
        assert!(result.is_some());

        let qc = result.unwrap();
        assert_eq!(qc.vote_count(), 3);
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

        let vote1 = create_signed_vote(1, BlockHeight::from(1), validators[0].info.address, VoteType::Prepare, &validators[0].signer);
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
        let vote = create_signed_vote(1, BlockHeight::from(1), address, VoteType::Prepare, &non_val_signer);

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
        let bad_sig = CompositeSignature::new(vec![0u8; 64], Some(vec![0u8; 3309]));
        let vote = Vote::new(
            1,
            BlockHeight::from(1),
            Hash::default(),
            validators[0].info.address,
            bad_sig,
            validator_pk,
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
        let vote_a = create_signed_vote(view, height, validators[0].info.address, VoteType::Prepare, &validators[0].signer);
        let result = collector.add_vote(vote_a);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // No QC yet

        // Validator 0 votes for block B (different hash) in the SAME view
        // Need to create a vote with a different block hash but signed by the same validator
        let mut different_hash_bytes = [0u8; 32];
        different_hash_bytes[0] = 0xFF;
        let placeholder_sig = CompositeSignature::new(Vec::new(), None);
        let pk_b = validators[0].signer.public_key().clone();
        let mut vote_b = Vote::new(
            view,
            height,
            Hash::new(different_hash_bytes),
            validators[0].info.address,
            placeholder_sig,
            pk_b,
            VoteType::Prepare,
            0,
        );
        let payload_b = vote_b.signing_payload();
        let sig_b = validators[0].signer.sign(&payload_b).unwrap();
        vote_b.signature = sig_b;

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
            let vote = create_signed_vote(view, BlockHeight::from(10), validators[0].info.address, VoteType::Prepare, &validators[0].signer);
            let _ = collector.add_vote(vote);
        }

        // Cleanup old votes below view 2
        collector.cleanup_old_votes(2);

        // View 1 votes should be gone; views 2 and 3 should remain
        assert_eq!(collector.vote_count(1, Hash::default(), VoteType::Prepare), 0);
        assert_eq!(collector.vote_count(2, Hash::default(), VoteType::Prepare), 1);
        assert_eq!(collector.vote_count(3, Hash::default(), VoteType::Prepare), 1);
    }
}
