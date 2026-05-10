//! Validator set management for consensus

use crate::error::{ConsensusError, Result};
use crate::leader_reputation::LeaderReputation;
use crate::voter::Vote;
use dashmap::DashMap;
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::Arc;
use tenzro_crypto::pq::ML_DSA_65_VK_LEN;
use tenzro_crypto::PublicKey;
use tenzro_types::primitives::{Address, Hash, Timestamp};
use tenzro_types::tee::{AttestationReport, AttestationResult};

/// Deserialize an ML-DSA-65 verifying key, rejecting any byte string that does
/// not match the FIPS 204 length (1952 bytes). This prevents downgrade or
/// truncation attacks at the wire level — every validator MUST advertise a
/// well-formed PQ key per the Wave 3d migration.
fn deserialize_pq_verifying_key<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    if bytes.len() != ML_DSA_65_VK_LEN {
        return Err(serde::de::Error::custom(format!(
            "validator PQ verifying key has wrong length: expected {} bytes (ML-DSA-65), got {}",
            ML_DSA_65_VK_LEN,
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Information about a validator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator's address
    pub address: Address,

    /// Validator's classical public key (Ed25519) for signing
    pub public_key: PublicKey,

    /// Validator's ML-DSA-65 verifying key (1952 bytes, FIPS 204) for the
    /// post-quantum signing leg. Mandatory: every validator in the active set
    /// must advertise a hybrid key per the Wave 3d migration.
    #[serde(deserialize_with = "deserialize_pq_verifying_key")]
    pub pq_public_key: Vec<u8>,

    /// Stake amount (voting power)
    pub stake: u128,

    /// TEE attestation report (optional)
    pub tee_attestation: Option<AttestationReport>,

    /// TEE attestation verification result
    pub tee_attestation_result: Option<AttestationResult>,

    /// Validator status
    pub status: ValidatorStatus,

    /// Registration timestamp
    pub registered_at: Timestamp,

    /// Last attestation update
    pub last_attestation_update: Option<Timestamp>,
}

impl ValidatorInfo {
    /// Creates a new validator info.
    ///
    /// # Panics
    ///
    /// Panics if `pq_public_key.len() != ML_DSA_65_VK_LEN` (1952 bytes). The PQ
    /// verifying key is mandatory in the Wave 3d hybrid signing world; there is
    /// no fallback path. Construct the key via `MlDsaSigningKey::generate()` and
    /// pass `key.verifying_key_bytes().to_vec()`.
    pub fn new(
        address: Address,
        public_key: PublicKey,
        pq_public_key: Vec<u8>,
        stake: u128,
    ) -> Self {
        assert_eq!(
            pq_public_key.len(),
            ML_DSA_65_VK_LEN,
            "validator PQ verifying key has wrong length: expected {} bytes (ML-DSA-65), got {}",
            ML_DSA_65_VK_LEN,
            pq_public_key.len()
        );
        Self {
            address,
            public_key,
            pq_public_key,
            stake,
            tee_attestation: None,
            tee_attestation_result: None,
            status: ValidatorStatus::Active,
            registered_at: Timestamp::now(),
            last_attestation_update: None,
        }
    }

    /// Returns the composite (classical + PQ) public key for this validator,
    /// suitable for hybrid signature verification via `StandardHybridVerifier`.
    pub fn composite_public_key(&self) -> tenzro_crypto::composite::CompositePublicKey {
        tenzro_crypto::composite::CompositePublicKey::new(
            self.public_key.clone(),
            Some(self.pq_public_key.clone()),
        )
    }

    /// Adds TEE attestation to the validator
    pub fn with_tee_attestation(
        mut self,
        attestation: AttestationReport,
        result: AttestationResult,
    ) -> Self {
        self.tee_attestation = Some(attestation);
        self.tee_attestation_result = Some(result);
        self.last_attestation_update = Some(Timestamp::now());
        self
    }

    /// Returns whether the validator has valid TEE attestation
    pub fn has_valid_tee_attestation(&self) -> bool {
        self.tee_attestation_result
            .as_ref()
            .map(|r| r.valid)
            .unwrap_or(false)
    }

    /// Returns whether the validator is active
    pub fn is_active(&self) -> bool {
        self.status == ValidatorStatus::Active
    }

    /// Returns the voting power of the validator
    pub fn voting_power(&self) -> u128 {
        if self.is_active() {
            self.stake
        } else {
            0
        }
    }

    /// Returns the base priority for leader selection.
    ///
    /// This is just the validator's voting power (stake when active, zero
    /// otherwise). Any TEE multiplier is applied by the proposer-election
    /// implementation (see [`ReputationProposer`]), not baked into the
    /// validator's intrinsic priority — so a TEE-attested validator with
    /// degraded behaviour can still be deprioritized by reputation.
    pub fn leader_priority(&self) -> u128 {
        self.voting_power()
    }
}

/// Validator operational status.
///
/// This mirrors the lifecycle in [`tenzro_token::ValidatorRegistryStatus`]
/// but is the local view consensus uses to decide who participates in the
/// current round. The token-side registry is the source of truth across
/// epoch boundaries; consensus only ever sees `Active` / `Inactive` /
/// `Jailed` / `Unbonding` states reflected from the registry's transition
/// plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Active and participating in consensus
    Active,
    /// Temporarily inactive
    Inactive,
    /// Jailed due to misbehavior
    Jailed,
    /// Unbonding (pending removal)
    Unbonding,
}

/// A set of validators for an epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// Current epoch number
    pub epoch: u64,

    /// List of validators
    validators: Vec<ValidatorInfo>,

    /// Total stake across all validators
    total_stake: u128,

    /// Epoch start timestamp
    pub epoch_start: Timestamp,
}

impl ValidatorSet {
    /// Creates a new validator set for the given epoch
    pub fn new(epoch: u64, validators: Vec<ValidatorInfo>) -> Result<Self> {
        if validators.is_empty() {
            return Err(ConsensusError::InvalidValidatorSet(
                "Validator set cannot be empty".to_string(),
            ));
        }

        let total_stake = validators.iter().map(|v| v.voting_power()).sum();

        Ok(Self {
            epoch,
            validators,
            total_stake,
            epoch_start: Timestamp::now(),
        })
    }

    /// Returns the validator at the given index
    pub fn get(&self, index: usize) -> Option<&ValidatorInfo> {
        self.validators.get(index)
    }

    /// Returns the validator with the given address
    pub fn get_by_address(&self, address: &Address) -> Option<&ValidatorInfo> {
        self.validators.iter().find(|v| &v.address == address)
    }

    /// Returns the number of validators
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Returns whether the validator set is empty
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Returns an iterator over the validators
    pub fn iter(&self) -> std::slice::Iter<'_, ValidatorInfo> {
        self.validators.iter()
    }

    /// Returns the total stake
    pub fn total_stake(&self) -> u128 {
        self.total_stake
    }

    /// Returns the total voting power (sum of active validators' stake)
    pub fn total_voting_power(&self) -> u128 {
        self.validators.iter().map(|v| v.voting_power()).sum()
    }

    /// Returns whether the given address is a validator
    pub fn is_validator(&self, address: &Address) -> bool {
        self.get_by_address(address).is_some()
    }

    /// Selects the leader for the given view via deterministic round-robin.
    ///
    /// This is the simplest possible proposer election: `view % N`. It is
    /// retained as a fallback / test path; production deployments should use
    /// [`ReputationProposer`] via [`ProposerElection`] which incorporates
    /// observed-behaviour reputation and a stake-weighted draw.
    pub fn select_leader_round_robin(&self, view: u64) -> Result<&ValidatorInfo> {
        if self.validators.is_empty() {
            return Err(ConsensusError::InvalidValidatorSet(
                "No validators available".to_string(),
            ));
        }
        let index = (view as usize) % self.validators.len();
        Ok(&self.validators[index])
    }

    /// Calculates the quorum threshold (2f+1)
    pub fn quorum_threshold(&self) -> usize {
        let n = self.validators.len();
        let f = (n.saturating_sub(1)) / 3;
        2 * f + 1
    }

    /// Returns the validators with valid TEE attestation
    pub fn tee_attested_validators(&self) -> Vec<&ValidatorInfo> {
        self.validators
            .iter()
            .filter(|v| v.has_valid_tee_attestation())
            .collect()
    }

    /// Returns the percentage of validators with TEE attestation
    pub fn tee_attestation_rate(&self) -> f64 {
        if self.validators.is_empty() {
            return 0.0;
        }
        let attested = self.tee_attested_validators().len();
        (attested as f64 / self.validators.len() as f64) * 100.0
    }
}

/// Evidence of validator equivocation (voting for multiple blocks in the same view)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    /// The validator who equivocated
    pub validator: Address,

    /// View number where equivocation occurred
    pub view: u64,

    /// First vote
    pub vote1: Vote,

    /// Second conflicting vote
    pub vote2: Vote,

    /// Timestamp when evidence was detected
    pub detected_at: Timestamp,
}

impl EquivocationEvidence {
    /// Creates new equivocation evidence
    pub fn new(validator: Address, view: u64, vote1: Vote, vote2: Vote) -> Self {
        Self {
            validator,
            view,
            vote1,
            vote2,
            detected_at: Timestamp::now(),
        }
    }

    /// Verifies that the evidence is valid (same view, different blocks)
    pub fn is_valid(&self) -> bool {
        self.vote1.view == self.vote2.view
            && self.vote1.view == self.view
            && self.vote1.voter == self.vote2.voter
            && self.vote1.voter == self.validator
            && self.vote1.block_hash != self.vote2.block_hash
            && self.vote1.vote_type == self.vote2.vote_type
    }
}

/// Key for tracking votes per (validator, view) pair
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ValidatorViewKey {
    validator: Address,
    view: u64,
}

/// Tracks validator votes to detect equivocation
pub struct EquivocationDetector {
    /// Stores (block_hash, vote_type) for each (validator, view) pair
    /// Key: (validator, view), Value: (block_hash, vote_type)
    votes: Arc<DashMap<ValidatorViewKey, (Hash, crate::voter::VoteType)>>,

    /// Detected equivocation evidence
    evidence: Arc<DashMap<(Address, u64), EquivocationEvidence>>,
}

impl EquivocationDetector {
    /// Creates a new equivocation detector
    pub fn new() -> Self {
        Self {
            votes: Arc::new(DashMap::new()),
            evidence: Arc::new(DashMap::new()),
        }
    }

    /// Records a vote and checks for equivocation
    /// Returns Ok(None) if no equivocation detected
    /// Returns Ok(Some(evidence)) if equivocation detected
    /// Returns Err if the vote itself is invalid
    pub fn check_vote(&self, vote: &Vote) -> Result<Option<EquivocationEvidence>> {
        let key = ValidatorViewKey {
            validator: vote.voter,
            view: vote.view,
        };

        // Check if validator already voted in this view
        if let Some(existing) = self.votes.get(&key) {
            let (existing_hash, existing_type) = *existing;

            // If voting for the same block, it's a duplicate (not equivocation)
            if existing_hash == vote.block_hash && existing_type == vote.vote_type {
                return Err(ConsensusError::AlreadyVoted(vote.view));
            }

            // If voting for a different block in the same view with same type, it's equivocation
            if existing_type == vote.vote_type {
                // Create the evidence
                // We need to reconstruct the first vote from stored data.
                // The original signature/public_key were not stored (we only
                // need the height, hash, voter, and type to prove
                // equivocation), so we synthesise an empty composite signature
                // and reuse the second vote's public key as a stand-in. The
                // EquivocationEvidence::is_valid() check inspects only
                // view/voter/block_hash/vote_type, so this is sufficient for
                // slashing evidence.
                let placeholder_sig = tenzro_crypto::composite::CompositeSignature::new(
                    Vec::new(),
                    None,
                );
                let vote1 = Vote::new(
                    vote.view,
                    vote.height,
                    existing_hash,
                    vote.voter,
                    placeholder_sig,
                    vote.public_key.clone(),
                    existing_type,
                    vote.high_qc_view,
                );

                let evidence = EquivocationEvidence::new(
                    vote.voter,
                    vote.view,
                    vote1,
                    vote.clone(),
                );

                // Store the evidence
                self.evidence.insert((vote.voter, vote.view), evidence.clone());

                tracing::warn!(
                    validator = %vote.voter,
                    view = vote.view,
                    block1 = %existing_hash,
                    block2 = %vote.block_hash,
                    "Equivocation detected"
                );

                return Ok(Some(evidence));
            }
        }

        // Record this vote
        self.votes.insert(key, (vote.block_hash, vote.vote_type));

        Ok(None)
    }

    /// Gets all detected equivocation evidence
    pub fn get_all_evidence(&self) -> Vec<EquivocationEvidence> {
        self.evidence.iter().map(|entry| entry.value().clone()).collect()
    }

    /// Gets equivocation evidence for a specific validator and view
    pub fn get_evidence(&self, validator: &Address, view: u64) -> Option<EquivocationEvidence> {
        self.evidence.get(&(*validator, view)).map(|e| e.clone())
    }

    /// Clears votes for views below the given minimum (cleanup)
    pub fn cleanup_old_votes(&self, min_view: u64) {
        self.votes.retain(|key, _| key.view >= min_view);
        self.evidence.retain(|(_, view), _| *view >= min_view);
    }

    /// Returns the number of tracked votes
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Returns the number of detected equivocations
    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }
}

impl Default for EquivocationDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Proposer election
// ---------------------------------------------------------------------------

/// Strategy interface for selecting the proposer of a given round/view.
///
/// Two concrete implementations are provided:
///
/// - [`RoundRobinProposer`] — naïve `view % N` rotation. Useful for tests and
///   for validator sets so small that reputation history is not yet
///   meaningful. **Not recommended for production.**
/// - [`ReputationProposer`] — Aptos LeaderReputation. Stake-weighted draw
///   whose per-validator weight is multiplied by an observed-behaviour term
///   (active / inactive / failed). A flaky validator's effective weight
///   collapses to ~0.1% of a healthy peer's within ~20 rounds, which is what
///   prevents naïve round-robin from wedging the chain when one of N
///   validators is unresponsive.
///
/// The trait returns an [`Address`] (not a `&ValidatorInfo`) so it composes
/// cleanly with the engine's hot path: the engine resolves the address back
/// to the validator info via `validator_set.get_by_address` only when needed.
pub trait ProposerElection: Send + Sync {
    /// Selects the proposer for `round` in `epoch`.
    ///
    /// `prev_block_id` is the hash of the most recently finalized block —
    /// this is the anti-grinding seed component (the parent the new proposal
    /// will extend). For round-robin this argument is unused; for
    /// reputation-based selection it is mixed into the seed.
    fn select_leader(
        &self,
        round: u64,
        epoch: u64,
        prev_block_id: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<Address>;
}

/// Naïve `view % N` round-robin proposer.
///
/// Retained because some configurations (smoke tests, very small validator
/// sets, deterministic-replay benchmarks) genuinely want it. Production
/// deployments must use [`ReputationProposer`].
#[derive(Debug, Default, Clone, Copy)]
pub struct RoundRobinProposer;

impl RoundRobinProposer {
    pub const fn new() -> Self {
        Self
    }
}

impl ProposerElection for RoundRobinProposer {
    fn select_leader(
        &self,
        round: u64,
        _epoch: u64,
        _prev_block_id: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<Address> {
        validator_set
            .select_leader_round_robin(round)
            .map(|v| v.address)
    }
}

/// Aptos LeaderReputation proposer.
///
/// Wraps a shared [`LeaderReputation`] state and dispatches to its seeded
/// weighted draw. The wrapped state is the same one the engine feeds with
/// `record_round_outcome` / `record_round_voters` after each round closes —
/// so the reputation evolves alongside consensus rather than being a
/// per-call computation.
#[derive(Clone)]
pub struct ReputationProposer {
    reputation: Arc<LeaderReputation>,
}

impl ReputationProposer {
    /// Wraps an existing [`LeaderReputation`] instance.
    pub fn new(reputation: Arc<LeaderReputation>) -> Self {
        Self { reputation }
    }

    /// Borrowed handle to the wrapped reputation state — useful for the
    /// engine to record outcomes / voters after round close without going
    /// through the trait.
    pub fn reputation(&self) -> &Arc<LeaderReputation> {
        &self.reputation
    }
}

impl ProposerElection for ReputationProposer {
    fn select_leader(
        &self,
        round: u64,
        epoch: u64,
        prev_block_id: [u8; 32],
        validator_set: &ValidatorSet,
    ) -> Result<Address> {
        let prev_hash = Hash::new(prev_block_id);
        self.reputation
            .select_leader(round, epoch, &prev_hash, validator_set)
            .map(|v| v.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::{KeyPair, KeyType};

    fn create_test_validator(stake: u128) -> ValidatorInfo {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        // Convert tenzro_crypto::Address (20 bytes) to tenzro_types::Address (32 bytes)
        let crypto_addr = keypair.address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = Address::new(addr_bytes);
        let pq = MlDsaSigningKey::generate();
        ValidatorInfo::new(
            address,
            keypair.public_key().clone(),
            pq.verifying_key_bytes().to_vec(),
            stake,
        )
    }

    #[test]
    fn test_validator_info() {
        let validator = create_test_validator(1000);
        assert_eq!(validator.voting_power(), 1000);
        assert!(validator.is_active());
        assert!(!validator.has_valid_tee_attestation());
    }

    #[test]
    fn test_validator_set_creation() {
        let validators = vec![
            create_test_validator(1000),
            create_test_validator(2000),
            create_test_validator(3000),
        ];

        let set = ValidatorSet::new(1, validators).unwrap();
        assert_eq!(set.len(), 3);
        assert_eq!(set.total_voting_power(), 6000);
        assert_eq!(set.quorum_threshold(), 1); // 2f+1 where f=(n-1)/3=(3-1)/3=0, so 2*0+1=1
    }

    #[test]
    fn test_leader_selection() {
        let validators = vec![
            create_test_validator(1000),
            create_test_validator(2000),
            create_test_validator(3000),
        ];

        let set = ValidatorSet::new(1, validators).unwrap();

        // Round-robin
        let leader0 = set.select_leader_round_robin(0).unwrap();
        let leader1 = set.select_leader_round_robin(1).unwrap();
        let leader2 = set.select_leader_round_robin(2).unwrap();
        let leader3 = set.select_leader_round_robin(3).unwrap();

        assert_eq!(leader0.address, set.validators[0].address);
        assert_eq!(leader1.address, set.validators[1].address);
        assert_eq!(leader2.address, set.validators[2].address);
        assert_eq!(leader3.address, set.validators[0].address); // wraps around
    }

    #[test]
    fn test_empty_validator_set() {
        let result = ValidatorSet::new(1, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_equivocation_detection() {
        use crate::voter::{Vote, VoteType};
        use tenzro_crypto::composite::{CompositePublicKey, CompositeSignature};
        use tenzro_types::primitives::BlockHeight;

        let detector = EquivocationDetector::new();
        let validator = create_test_validator(1000);

        let placeholder_pk = CompositePublicKey::new(
            validator.public_key.clone(),
            Some(validator.pq_public_key.clone()),
        );
        let placeholder_sig = CompositeSignature::new(vec![0u8; 64], Some(vec![0u8; 3309]));

        let vote1 = Vote::new(
            1,
            BlockHeight::from(10),
            Hash::default(),
            validator.address,
            placeholder_sig.clone(),
            placeholder_pk.clone(),
            VoteType::Prepare,
            0,
        );

        // First vote should be recorded without issue
        let result = detector.check_vote(&vote1);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Same vote again should error (already voted)
        let result = detector.check_vote(&vote1);
        assert!(result.is_err());

        // Different block hash in same view should detect equivocation
        let mut different_hash = [0u8; 32];
        different_hash[0] = 1;
        let vote2 = Vote::new(
            1,
            BlockHeight::from(10),
            Hash::new(different_hash),
            validator.address,
            placeholder_sig.clone(),
            placeholder_pk.clone(),
            VoteType::Prepare,
            0,
        );

        let result = detector.check_vote(&vote2);
        assert!(result.is_ok());
        let evidence = result.unwrap();
        assert!(evidence.is_some());

        let evidence = evidence.unwrap();
        assert_eq!(evidence.validator, validator.address);
        assert_eq!(evidence.view, 1);
        assert!(evidence.is_valid());
    }

    #[test]
    fn test_equivocation_detector_cleanup() {
        use crate::voter::{Vote, VoteType};
        use tenzro_crypto::composite::{CompositePublicKey, CompositeSignature};
        use tenzro_types::primitives::BlockHeight;

        let detector = EquivocationDetector::new();
        let validator = create_test_validator(1000);

        let placeholder_pk = CompositePublicKey::new(
            validator.public_key.clone(),
            Some(validator.pq_public_key.clone()),
        );
        let placeholder_sig = CompositeSignature::new(vec![0u8; 64], Some(vec![0u8; 3309]));

        // Add votes for views 1, 2, 3
        for view in 1..=3 {
            let vote = Vote::new(
                view,
                BlockHeight::from(10),
                Hash::default(),
                validator.address,
                placeholder_sig.clone(),
                placeholder_pk.clone(),
                VoteType::Prepare,
                0,
            );
            let _ = detector.check_vote(&vote);
        }

        assert_eq!(detector.vote_count(), 3);

        // Cleanup views below 2
        detector.cleanup_old_votes(2);

        // Should only have views 2 and 3 remaining
        assert_eq!(detector.vote_count(), 2);
    }
}
