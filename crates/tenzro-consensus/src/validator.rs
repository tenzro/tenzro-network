//! Validator set management for consensus

use crate::error::{ConsensusError, Result};
use crate::leader_reputation::LeaderReputation;
use crate::voter::Vote;
use dashmap::DashMap;
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::Arc;
use tenzro_crypto::composite::{
    CompositePublicKey, CompositeSignature, HybridVerifier, StandardHybridVerifier,
};
use tenzro_crypto::pq::ML_DSA_65_VK_LEN;
use tenzro_crypto::PublicKey;

/// BLS12-381 G1-compressed public key length (`min_pk` scheme used by
/// `tenzro_crypto::bls`). Every validator MUST advertise a BLS verifying key
/// for HotStuff-2 vote-signature aggregation.
pub const BLS_G1_COMPRESSED_LEN: usize = 48;

/// Maximum normalized voting weight any single validator may hold, in basis
/// points of the active set's total weight (Sui anti-domination cap). Excess
/// above this cap is redistributed proportionally across the uncapped
/// validators. 1,000 bps = 10%.
pub const MAX_VALIDATOR_WEIGHT_BPS: u32 = 1_000;
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

/// Deserialize a BLS12-381 G1-compressed verifying key, rejecting any byte
/// string that does not match the 48-byte length. Every validator in the
/// active set MUST advertise a well-formed BLS key for HotStuff-2 vote
/// aggregation per ROADMAP B.1.
fn deserialize_bls_verifying_key<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    if bytes.len() != BLS_G1_COMPRESSED_LEN {
        return Err(serde::de::Error::custom(format!(
            "validator BLS verifying key has wrong length: expected {} bytes (BLS12-381 G1 compressed), got {}",
            BLS_G1_COMPRESSED_LEN,
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

    /// Validator's BLS12-381 G1-compressed verifying key (48 bytes, `min_pk`
    /// scheme). Mandatory: every validator MUST advertise a BLS key for
    /// HotStuff-2 vote-signature aggregation per ROADMAP B.1. The aggregation
    /// is the third signature leg alongside the per-vote Ed25519 + ML-DSA-65
    /// `CompositeSignature` — BLS provides O(1) bandwidth and verification
    /// CPU savings on the QC path; Composite preserves the PQ-hybrid property
    /// per individual vote (Composite is pre-quantum on its classical leg
    /// only, BLS12-381 itself is pre-quantum, hence we keep both).
    #[serde(deserialize_with = "deserialize_bls_verifying_key")]
    pub bls_public_key: Vec<u8>,

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
    /// Panics if:
    /// - `pq_public_key.len() != ML_DSA_65_VK_LEN` (1952 bytes), or
    /// - `bls_public_key.len() != BLS_G1_COMPRESSED_LEN` (48 bytes).
    ///
    /// Both keys are mandatory; there is no fallback path. Construct the PQ
    /// key via `MlDsaSigningKey::generate()` and pass
    /// `key.verifying_key_bytes().to_vec()`. Construct the BLS key via
    /// `tenzro_crypto::bls::BlsKeyPair::generate()` and pass
    /// `keypair.public_key().to_bytes().to_vec()`.
    pub fn new(
        address: Address,
        public_key: PublicKey,
        pq_public_key: Vec<u8>,
        bls_public_key: Vec<u8>,
        stake: u128,
    ) -> Self {
        assert_eq!(
            pq_public_key.len(),
            ML_DSA_65_VK_LEN,
            "validator PQ verifying key has wrong length: expected {} bytes (ML-DSA-65), got {}",
            ML_DSA_65_VK_LEN,
            pq_public_key.len()
        );
        assert_eq!(
            bls_public_key.len(),
            BLS_G1_COMPRESSED_LEN,
            "validator BLS verifying key has wrong length: expected {} bytes (BLS12-381 G1 compressed), got {}",
            BLS_G1_COMPRESSED_LEN,
            bls_public_key.len()
        );
        Self {
            address,
            public_key,
            pq_public_key,
            bls_public_key,
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
            self.pq_public_key.clone(),
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

    /// Returns the position of a validator in `self.validators` matching the
    /// given address, or `None` if not present.
    ///
    /// This is the canonical "validator index" used for bitmap-based BLS
    /// signer encoding in [`crate::voter::QuorumCertificate::signer_bitmap`].
    /// The index is stable for the lifetime of the validator set (i.e. the
    /// duration of one epoch); a new epoch may renumber.
    pub fn index_of(&self, address: &Address) -> Option<usize> {
        self.validators.iter().position(|v| &v.address == address)
    }

    /// Returns the validators slice in canonical order (insertion / epoch
    /// order). The position of each entry in this slice is the bit index used
    /// by [`crate::voter::QuorumCertificate::signer_bitmap`] when verifying
    /// the BLS aggregate.
    pub fn active_validators(&self) -> &[ValidatorInfo] {
        &self.validators
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

    /// Calculates the headcount quorum threshold (2f+1).
    ///
    /// Retained only for the legacy/test signer-count paths and for the
    /// degenerate single-validator case. Production safety is decided by
    /// [`quorum_voting_power`](Self::quorum_voting_power) on stake weight, not
    /// by head-count — see the stake-weighted methods below.
    pub fn quorum_threshold(&self) -> usize {
        let n = self.validators.len();
        let f = (n.saturating_sub(1)) / 3;
        2 * f + 1
    }

    /// Normalized total voting power.
    ///
    /// Voting power equals each *active* validator's bonded stake, capped at
    /// [`MAX_VALIDATOR_WEIGHT_BPS`] of the (uncapped) total with the excess
    /// redistributed proportionally across the uncapped validators. This is
    /// the Sui anti-domination model expressed in integer math so formation
    /// and verification agree byte-for-byte. A node with zero stake (or one
    /// that is inactive) contributes zero — unstaked service nodes cannot move
    /// a quorum.
    pub fn normalized_total_voting_power(&self) -> u128 {
        self.normalized_weights().iter().sum()
    }

    /// Per-validator normalized voting power, in canonical (`active_validators`)
    /// order. Applies the [`MAX_VALIDATOR_WEIGHT_BPS`] cap with proportional
    /// redistribution. Indices align with [`Self::active_validators`].
    pub fn normalized_weights(&self) -> Vec<u128> {
        let raw: Vec<u128> = self.validators.iter().map(|v| v.voting_power()).collect();
        let total: u128 = raw.iter().sum();
        if total == 0 {
            return raw;
        }

        // Cap any single validator at MAX_VALIDATOR_WEIGHT_BPS of the total,
        // redistributing the clipped excess proportionally over the uncapped
        // validators. One redistribution pass is sufficient for the 10% cap as
        // long as the set has > 10 validators; for smaller sets the cap simply
        // cannot bind on every node at once, so a single pass converges.
        let cap = total.saturating_mul(MAX_VALIDATOR_WEIGHT_BPS as u128) / 10_000u128;
        if cap == 0 {
            return raw;
        }

        // Feasibility guard: if `n * cap < total` the cap cannot hold for every
        // validator simultaneously (the set is too small for the cap, e.g. a
        // 4-node set under a 10% cap). In that regime capping is meaningless and
        // a single pass would not converge, so leave weights uncapped.
        if (raw.len() as u128).saturating_mul(cap) < total {
            return raw;
        }

        let mut weights = raw.clone();
        let mut excess: u128 = 0;
        let mut uncapped_total: u128 = 0;
        for w in weights.iter_mut() {
            if *w > cap {
                excess = excess.saturating_add(*w - cap);
                *w = cap;
            } else {
                uncapped_total = uncapped_total.saturating_add(*w);
            }
        }

        if excess > 0 && uncapped_total > 0 {
            for w in weights.iter_mut() {
                if *w < cap {
                    // Proportional share of the redistributed excess. Integer
                    // division floors; the small remainder is dropped, which is
                    // safe (it only ever lowers a quorum-meeting tally, never
                    // raises a failing one above threshold).
                    let share = excess.saturating_mul(*w) / uncapped_total;
                    *w = (*w).saturating_add(share);
                }
            }
        }

        weights
    }

    /// Stake-weighted quorum: the smallest integer strictly greater than
    /// two-thirds of [`normalized_total_voting_power`](Self::normalized_total_voting_power).
    ///
    /// `floor(2N/3) + 1` is exactly the smallest integer `> 2N/3` for all
    /// integer `N`, which is the HotStuff-2 safety bound on stake weight.
    pub fn quorum_voting_power(&self) -> u128 {
        let n = self.normalized_total_voting_power();
        if n == 0 {
            return 0;
        }
        (2u128.saturating_mul(n) / 3).saturating_add(1)
    }

    /// Bracha-boost / fault threshold: the smallest integer strictly greater
    /// than one-third of normalized voting power (`floor(N/3) + 1`), the
    /// stake-weighted analogue of `f+1`.
    pub fn bracha_voting_power(&self) -> u128 {
        let n = self.normalized_total_voting_power();
        if n == 0 {
            return 0;
        }
        (n / 3).saturating_add(1)
    }

    /// Sums the normalized voting power of the given signer addresses,
    /// counting each distinct active validator at most once.
    pub fn voting_power_of<'a, I>(&self, signers: I) -> u128
    where
        I: IntoIterator<Item = &'a Address>,
    {
        let weights = self.normalized_weights();
        let mut seen: std::collections::HashSet<&Address> = std::collections::HashSet::new();
        let mut sum: u128 = 0;
        for addr in signers {
            if !seen.insert(addr) {
                continue;
            }
            if let Some(idx) = self.index_of(addr) {
                if let Some(w) = weights.get(idx) {
                    sum = sum.saturating_add(*w);
                }
            }
        }
        sum
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

/// Canonical signing payload for a block proposal. The leader signs this
/// with its hybrid (Ed25519 + ML-DSA-65) key at propose time; every replica
/// verifies it against the proposer's REGISTERED composite public key before
/// acting on the proposal. Binding `high_qc_view` into the payload also
/// authenticates the SyncInfo pacemaker hint that rides on the proposal.
pub fn proposal_signing_payload(
    view: u64,
    height: u64,
    block_hash: &Hash,
    high_qc_view: u64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16 + 8 + 8 + 32 + 8);
    payload.extend_from_slice(b"TENZRO_PROPOSAL:");
    payload.extend_from_slice(&view.to_le_bytes());
    payload.extend_from_slice(&height.to_le_bytes());
    payload.extend_from_slice(block_hash.as_bytes());
    payload.extend_from_slice(&high_qc_view.to_le_bytes());
    payload
}

/// One signed proposal observation recorded by the equivocation detector.
/// Carries everything needed to re-derive the canonical signing payload so
/// the signature stays independently verifiable by third parties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalRecord {
    /// Block height the proposal claimed
    pub height: u64,

    /// Hash of the proposed block
    pub block_hash: Hash,

    /// SyncInfo high-QC view hint bound into the signed payload
    pub high_qc_view: u64,

    /// Proposer's hybrid signature over `proposal_signing_payload(..)`
    pub signature: CompositeSignature,
}

/// Evidence of proposer equivocation: two signed proposals for different
/// blocks in the same view. Unlike vote-equivocation evidence (which relies
/// on the vote pipeline's own signature checks), proposal evidence embeds
/// both real signatures plus the proposer's composite public key, so it is
/// attributable on its own — no replica can frame a proposer without
/// producing two valid signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalEquivocationEvidence {
    /// The proposer who equivocated
    pub proposer: Address,

    /// View number where the equivocation occurred
    pub view: u64,

    /// First signed proposal
    pub proposal1: ProposalRecord,

    /// Second, conflicting signed proposal
    pub proposal2: ProposalRecord,

    /// Proposer's composite public key (must match the registered
    /// validator keys — the consensus engine checks that binding before
    /// recording the observation)
    pub public_key: CompositePublicKey,

    /// Timestamp when evidence was detected
    pub detected_at: Timestamp,
}

impl ProposalEquivocationEvidence {
    /// Verifies the evidence end-to-end: distinct block hashes plus BOTH
    /// hybrid signatures valid over their canonical payloads under the
    /// embedded public key.
    pub fn is_valid(&self) -> bool {
        if self.proposal1.block_hash == self.proposal2.block_hash {
            return false;
        }
        let verifier = StandardHybridVerifier::new(self.public_key.clone());
        for record in [&self.proposal1, &self.proposal2] {
            let payload = proposal_signing_payload(
                self.view,
                record.height,
                &record.block_hash,
                record.high_qc_view,
            );
            if verifier.verify(&payload, &record.signature).is_err() {
                return false;
            }
        }
        true
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

    /// Stores the first signed proposal observed per (proposer, view)
    proposals: Arc<DashMap<ValidatorViewKey, ProposalRecord>>,

    /// Detected proposer-equivocation evidence
    proposal_evidence: Arc<DashMap<(Address, u64), ProposalEquivocationEvidence>>,

    /// Optional persistence backend. When set, every recorded vote
    /// and every detected EquivocationEvidence writes through to a
    /// dedicated `equivocation:*` keyspace in `CF_AUDIT` and is
    /// hydrated on construction. Without persistence, a validator
    /// equivocator can simply restart their node to wipe the
    /// detector's state and avoid slashing.
    storage: Option<Arc<dyn tenzro_storage::KvStore>>,
}

impl EquivocationDetector {
    /// Creates a new equivocation detector (in-memory only — test
    /// path).
    pub fn new() -> Self {
        Self {
            votes: Arc::new(DashMap::new()),
            evidence: Arc::new(DashMap::new()),
            proposals: Arc::new(DashMap::new()),
            proposal_evidence: Arc::new(DashMap::new()),
            storage: None,
        }
    }

    /// Production constructor: write-through to `CF_AUDIT` under
    /// `equivocation/votes/*`, `equivocation/evidence/*`,
    /// `equivocation/proposals/*`, and `equivocation/proposal_evidence/*`.
    /// Hydrates all maps on construction.
    pub fn with_storage(storage: Arc<dyn tenzro_storage::KvStore>) -> Self {
        let d = Self {
            votes: Arc::new(DashMap::new()),
            evidence: Arc::new(DashMap::new()),
            proposals: Arc::new(DashMap::new()),
            proposal_evidence: Arc::new(DashMap::new()),
            storage: Some(storage),
        };
        d.hydrate();
        d
    }

    fn vote_key(validator: &Address, view: u64) -> Vec<u8> {
        let mut k = b"equivocation/votes/".to_vec();
        k.extend_from_slice(validator.as_bytes());
        k.push(b'/');
        k.extend_from_slice(&view.to_le_bytes());
        k
    }
    fn evidence_key(validator: &Address, view: u64) -> Vec<u8> {
        let mut k = b"equivocation/evidence/".to_vec();
        k.extend_from_slice(validator.as_bytes());
        k.push(b'/');
        k.extend_from_slice(&view.to_le_bytes());
        k
    }
    fn proposal_key(proposer: &Address, view: u64) -> Vec<u8> {
        let mut k = b"equivocation/proposals/".to_vec();
        k.extend_from_slice(proposer.as_bytes());
        k.push(b'/');
        k.extend_from_slice(&view.to_le_bytes());
        k
    }
    fn proposal_evidence_key(proposer: &Address, view: u64) -> Vec<u8> {
        let mut k = b"equivocation/proposal_evidence/".to_vec();
        k.extend_from_slice(proposer.as_bytes());
        k.push(b'/');
        k.extend_from_slice(&view.to_le_bytes());
        k
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        if let Ok(entries) =
            storage.scan_prefix(tenzro_storage::CF_AUDIT, b"equivocation/votes/")
        {
            for (key, value) in entries {
                if let Some(vk) = Self::parse_vote_key(&key) {
                    if let Ok(payload) =
                        serde_json::from_slice::<(Hash, crate::voter::VoteType)>(&value)
                    {
                        self.votes.insert(vk, payload);
                    }
                }
            }
        }
        if let Ok(entries) =
            storage.scan_prefix(tenzro_storage::CF_AUDIT, b"equivocation/evidence/")
        {
            for (key, value) in entries {
                if let Some((addr, view)) =
                    Self::parse_addr_view_key(b"equivocation/evidence/", &key)
                {
                    if let Ok(ev) =
                        serde_json::from_slice::<EquivocationEvidence>(&value)
                    {
                        self.evidence.insert((addr, view), ev);
                    }
                }
            }
        }
        if let Ok(entries) =
            storage.scan_prefix(tenzro_storage::CF_AUDIT, b"equivocation/proposals/")
        {
            for (key, value) in entries {
                if let Some((validator, view)) =
                    Self::parse_addr_view_key(b"equivocation/proposals/", &key)
                {
                    if let Ok(record) = serde_json::from_slice::<ProposalRecord>(&value) {
                        self.proposals
                            .insert(ValidatorViewKey { validator, view }, record);
                    }
                }
            }
        }
        if let Ok(entries) = storage
            .scan_prefix(tenzro_storage::CF_AUDIT, b"equivocation/proposal_evidence/")
        {
            for (key, value) in entries {
                if let Some((addr, view)) =
                    Self::parse_addr_view_key(b"equivocation/proposal_evidence/", &key)
                {
                    if let Ok(ev) =
                        serde_json::from_slice::<ProposalEquivocationEvidence>(&value)
                    {
                        self.proposal_evidence.insert((addr, view), ev);
                    }
                }
            }
        }
    }

    fn parse_vote_key(key: &[u8]) -> Option<ValidatorViewKey> {
        Self::parse_addr_view_key(b"equivocation/votes/", key)
            .map(|(validator, view)| ValidatorViewKey { validator, view })
    }

    /// Parses `<prefix><addr bytes>/<view LE u64>` keys shared by every
    /// equivocation keyspace.
    fn parse_addr_view_key(prefix: &[u8], key: &[u8]) -> Option<(Address, u64)> {
        if !key.starts_with(prefix) {
            return None;
        }
        let rest = &key[prefix.len()..];
        if rest.len() < 9 {
            return None;
        }
        let addr_end = rest.len() - 9;
        if rest[addr_end] != b'/' {
            return None;
        }
        let validator = Address::from_bytes(&rest[..addr_end])?;
        let mut view_buf = [0u8; 8];
        view_buf.copy_from_slice(&rest[addr_end + 1..]);
        let view = u64::from_le_bytes(view_buf);
        Some((validator, view))
    }

    // Vote and proposal records are per-view detection inputs; losing one
    // in a crash costs at worst a detection gap for that view, never a
    // double penalty, so they use unsynced writes to keep the per-vote hot
    // path off the WAL-fsync cost. Evidence records are the opposite: they
    // are the guard against re-emitting (and re-slashing) a conviction, so
    // they must be durable before the slashing callback observes them —
    // those go through `write_batch_sync`.
    fn persist_vote(
        &self,
        vk: &ValidatorViewKey,
        payload: &(Hash, crate::voter::VoteType),
    ) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(payload) {
                let _ = storage.put(
                    tenzro_storage::CF_AUDIT,
                    &Self::vote_key(&vk.validator, vk.view),
                    &bytes,
                );
            }
        }
    }

    fn persist_evidence(&self, ev: &EquivocationEvidence) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(ev) {
                let _ = storage.write_batch_sync(vec![tenzro_storage::WriteOp::Put {
                    cf: tenzro_storage::CF_AUDIT.to_string(),
                    key: Self::evidence_key(&ev.validator, ev.view),
                    value: bytes,
                }]);
            }
        }
    }

    fn persist_proposal(&self, key: &ValidatorViewKey, record: &ProposalRecord) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(record) {
                let _ = storage.put(
                    tenzro_storage::CF_AUDIT,
                    &Self::proposal_key(&key.validator, key.view),
                    &bytes,
                );
            }
        }
    }

    fn persist_proposal_evidence(&self, ev: &ProposalEquivocationEvidence) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(ev) {
                let _ = storage.write_batch_sync(vec![tenzro_storage::WriteOp::Put {
                    cf: tenzro_storage::CF_AUDIT.to_string(),
                    key: Self::proposal_evidence_key(&ev.proposer, ev.view),
                    value: bytes,
                }]);
            }
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

        // Once evidence exists for this (validator, view) the offence is
        // already convicted. A third conflicting vote — or a replay of the
        // original pair — must NOT re-emit evidence, because every
        // Ok(Some(..)) fires the slashing callback and would compound the
        // penalty for a single offence.
        if self.evidence.contains_key(&(vote.voter, vote.view)) {
            return Err(ConsensusError::AlreadyVoted(vote.view));
        }

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
                    Vec::new(),
                );
                // BLS signature follows the same stand-in rationale as the
                // composite sig + public key above — `EquivocationEvidence::is_valid`
                // only inspects view/voter/block_hash/vote_type.
                let placeholder_bls = vote.bls_signature.clone();
                let vote1 = Vote::new(
                    vote.view,
                    vote.height,
                    existing_hash,
                    vote.voter,
                    placeholder_sig,
                    vote.public_key.clone(),
                    placeholder_bls,
                    existing_type,
                    vote.high_qc_view,
                );

                let evidence = EquivocationEvidence::new(
                    vote.voter,
                    vote.view,
                    vote1,
                    vote.clone(),
                );

                // Store the evidence — atomic insert-if-absent so two
                // concurrent detections of the same offence convict once.
                match self.evidence.entry((vote.voter, vote.view)) {
                    dashmap::mapref::entry::Entry::Occupied(_) => {
                        return Err(ConsensusError::AlreadyVoted(vote.view));
                    }
                    dashmap::mapref::entry::Entry::Vacant(slot) => {
                        slot.insert(evidence.clone());
                    }
                }
                self.persist_evidence(&evidence);

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
        let payload = (vote.block_hash, vote.vote_type);
        self.votes.insert(key.clone(), payload);
        self.persist_vote(&key, &payload);

        Ok(None)
    }

    /// Records a signed proposal observation and checks for proposer
    /// equivocation. The caller MUST have verified `observed.signature`
    /// over `proposal_signing_payload(view, observed.height,
    /// &observed.block_hash, observed.high_qc_view)` against the
    /// proposer's registered composite key before calling — the detector
    /// stores what it is given.
    ///
    /// Returns Ok(None) when no equivocation is detected (first proposal
    /// for the view, or a benign re-observation of the same block hash).
    /// Returns Ok(Some(evidence)) exactly ONCE per (proposer, view)
    /// offence; replays and third conflicting proposals return
    /// Err(DuplicateProposal) so the slashing callback never re-fires.
    pub fn check_proposal(
        &self,
        proposer: &Address,
        view: u64,
        observed: ProposalRecord,
        public_key: &CompositePublicKey,
    ) -> Result<Option<ProposalEquivocationEvidence>> {
        // Already convicted for this view — do not re-emit evidence.
        if self.proposal_evidence.contains_key(&(*proposer, view)) {
            return Err(ConsensusError::DuplicateProposal(view));
        }

        let key = ValidatorViewKey {
            validator: *proposer,
            view,
        };

        let existing = self.proposals.get(&key).map(|r| r.clone());
        if let Some(first) = existing {
            if first.block_hash == observed.block_hash {
                // Same proposal re-observed (gossip duplicate) — benign.
                return Ok(None);
            }

            let evidence = ProposalEquivocationEvidence {
                proposer: *proposer,
                view,
                proposal1: first,
                proposal2: observed,
                public_key: public_key.clone(),
                detected_at: Timestamp::now(),
            };

            // Atomic insert-if-absent: concurrent detections convict once.
            match self.proposal_evidence.entry((*proposer, view)) {
                dashmap::mapref::entry::Entry::Occupied(_) => {
                    return Err(ConsensusError::DuplicateProposal(view));
                }
                dashmap::mapref::entry::Entry::Vacant(slot) => {
                    slot.insert(evidence.clone());
                }
            }
            self.persist_proposal_evidence(&evidence);

            tracing::warn!(
                proposer = %proposer,
                view,
                block1 = %evidence.proposal1.block_hash,
                block2 = %evidence.proposal2.block_hash,
                "Proposal equivocation detected"
            );

            return Ok(Some(evidence));
        }

        self.proposals.insert(key.clone(), observed.clone());
        self.persist_proposal(&key, &observed);

        Ok(None)
    }

    /// Gets all detected equivocation evidence
    pub fn get_all_evidence(&self) -> Vec<EquivocationEvidence> {
        self.evidence.iter().map(|entry| entry.value().clone()).collect()
    }

    /// Gets all detected proposal-equivocation evidence
    pub fn get_all_proposal_evidence(&self) -> Vec<ProposalEquivocationEvidence> {
        self.proposal_evidence
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Gets proposal-equivocation evidence for a specific proposer and view
    pub fn get_proposal_evidence(
        &self,
        proposer: &Address,
        view: u64,
    ) -> Option<ProposalEquivocationEvidence> {
        self.proposal_evidence
            .get(&(*proposer, view))
            .map(|e| e.clone())
    }

    /// Gets equivocation evidence for a specific validator and view
    pub fn get_evidence(&self, validator: &Address, view: u64) -> Option<EquivocationEvidence> {
        self.evidence.get(&(*validator, view)).map(|e| e.clone())
    }

    /// Clears votes for views below the given minimum (cleanup).
    ///
    /// Prunes both the in-memory vote map AND the persisted
    /// `equivocation/votes/*` rows — without the persisted delete, every
    /// restart re-hydrated an unbounded backlog of stale votes that the
    /// in-memory prune had already discarded (unbounded CF_AUDIT growth
    /// plus stale-vote mis-fires after view-state resets).
    ///
    /// Evidence is deliberately KEPT — in memory and on disk. Evidence is
    /// the slashing record; pruning it by view would let an equivocator
    /// outlast the cleanup window and escape the penalty.
    pub fn cleanup_old_votes(&self, min_view: u64) {
        let mut pruned: Vec<ValidatorViewKey> = Vec::new();
        self.votes.retain(|key, _| {
            let keep = key.view >= min_view;
            if !keep {
                pruned.push(key.clone());
            }
            keep
        });
        if let Some(ref storage) = self.storage {
            for key in &pruned {
                let _ = storage.delete(
                    tenzro_storage::CF_AUDIT,
                    &Self::vote_key(&key.validator, key.view),
                );
            }
        }

        // Proposal observations follow the same retention as votes;
        // proposal EVIDENCE is kept, same as vote evidence.
        let mut pruned_proposals: Vec<ValidatorViewKey> = Vec::new();
        self.proposals.retain(|key, _| {
            let keep = key.view >= min_view;
            if !keep {
                pruned_proposals.push(key.clone());
            }
            keep
        });
        if let Some(ref storage) = self.storage {
            for key in &pruned_proposals {
                let _ = storage.delete(
                    tenzro_storage::CF_AUDIT,
                    &Self::proposal_key(&key.validator, key.view),
                );
            }
        }
    }

    /// Returns the number of tracked votes
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Returns the number of detected equivocations
    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }

    /// Returns the number of detected proposal equivocations
    pub fn proposal_evidence_count(&self) -> usize {
        self.proposal_evidence.len()
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
    use tenzro_crypto::bls::BlsKeyPair;
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
        let bls = BlsKeyPair::generate().unwrap();
        ValidatorInfo::new(
            address,
            keypair.public_key().clone(),
            pq.verifying_key_bytes().to_vec(),
            bls.public_key().to_bytes().to_vec(),
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
    fn stake_weighted_quorum_thresholds() {
        // total 6000 → quorum > 2/3 = floor(12000/3)+1 = 4001;
        // bracha > 1/3 = floor(6000/3)+1 = 2001.
        let set = ValidatorSet::new(
            1,
            vec![
                create_test_validator(1000),
                create_test_validator(2000),
                create_test_validator(3000),
            ],
        )
        .unwrap();
        assert_eq!(set.normalized_total_voting_power(), 6000);
        assert_eq!(set.quorum_voting_power(), 4001);
        assert_eq!(set.bracha_voting_power(), 2001);
    }

    #[test]
    fn zero_stake_validator_carries_no_weight() {
        // Three staked validators + one zero-stake "service" node. The
        // zero-stake node must contribute nothing to a quorum tally, and the
        // quorum must be reachable by the staked nodes alone.
        let staked: Vec<ValidatorInfo> = vec![
            create_test_validator(1000),
            create_test_validator(1000),
            create_test_validator(1000),
        ];
        let zero = create_test_validator(0);
        let mut all = staked.clone();
        all.push(zero.clone());
        let set = ValidatorSet::new(1, all).unwrap();

        // Total normalized power is just the staked 3000; the zero-stake node
        // adds nothing.
        assert_eq!(set.normalized_total_voting_power(), 3000);

        // The zero-stake node alone cannot meet quorum.
        let zero_only = set.voting_power_of([&zero.address]);
        assert_eq!(zero_only, 0);
        assert!(zero_only < set.quorum_voting_power());

        // All three staked nodes meet quorum (3000 > 2/3·3000 = 2001).
        let staked_addrs: Vec<Address> = staked.iter().map(|v| v.address).collect();
        let staked_power = set.voting_power_of(staked_addrs.iter());
        assert_eq!(staked_power, 3000);
        assert!(staked_power >= set.quorum_voting_power());

        // Adding the zero-stake node's "vote" on top changes nothing.
        let with_zero: Vec<Address> =
            staked_addrs.iter().copied().chain(std::iter::once(zero.address)).collect();
        assert_eq!(set.voting_power_of(with_zero.iter()), 3000);
    }

    #[test]
    fn whale_weight_is_capped_at_ten_percent() {
        // 11 small validators (stake 100 each = 1100) + one whale (stake
        // 100000). Uncapped the whale holds ~99% of weight; the 10% cap must
        // bound it. With 12 validators the cap is feasible (12·cap ≥ total).
        let mut infos: Vec<ValidatorInfo> = (0..11).map(|_| create_test_validator(100)).collect();
        let whale = create_test_validator(100_000);
        infos.push(whale.clone());
        let set = ValidatorSet::new(1, infos).unwrap();

        let total = set.normalized_total_voting_power();
        let whale_weight = set.voting_power_of([&whale.address]);
        // Whale must hold no more than 10% (+ rounding) of total weight.
        assert!(
            whale_weight * 10 <= total + 12,
            "whale_weight={whale_weight} total={total} exceeds 10% cap"
        );
    }

    #[test]
    fn cap_is_inert_for_small_sets() {
        // A 4-validator equal-stake set: a 10% cap cannot hold for every node
        // at once (each is 25%), so the cap must be skipped and weights left
        // raw. Quorum is then 3 of 4 by equal weight.
        let set = ValidatorSet::new(
            1,
            vec![
                create_test_validator(1000),
                create_test_validator(1000),
                create_test_validator(1000),
                create_test_validator(1000),
            ],
        )
        .unwrap();
        assert_eq!(set.normalized_total_voting_power(), 4000);
        // quorum = floor(8000/3)+1 = 2667 → needs 3 of 4 (3000 ≥ 2667).
        assert_eq!(set.quorum_voting_power(), 2667);
        for w in set.normalized_weights() {
            assert_eq!(w, 1000, "small-set weights must be uncapped");
        }
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
            validator.pq_public_key.clone(),
        );
        let placeholder_sig = CompositeSignature::new(vec![0u8; 64], vec![0u8; 3309]);
        // EquivocationDetector::check_vote inspects view/voter/block_hash/vote_type
        // only, so a real BLS signature over arbitrary bytes is enough — the
        // detector never re-verifies it.
        let placeholder_bls_kp = BlsKeyPair::generate().unwrap();
        let placeholder_bls = placeholder_bls_kp.sign(b"__placeholder__");

        let vote1 = Vote::new(
            1,
            BlockHeight::from(10),
            Hash::default(),
            validator.address,
            placeholder_sig.clone(),
            placeholder_pk.clone(),
            placeholder_bls.clone(),
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
            placeholder_bls.clone(),
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
            validator.pq_public_key.clone(),
        );
        let placeholder_sig = CompositeSignature::new(vec![0u8; 64], vec![0u8; 3309]);
        let placeholder_bls_kp = BlsKeyPair::generate().unwrap();
        let placeholder_bls = placeholder_bls_kp.sign(b"__placeholder__");

        // Add votes for views 1, 2, 3
        for view in 1..=3 {
            let vote = Vote::new(
                view,
                BlockHeight::from(10),
                Hash::default(),
                validator.address,
                placeholder_sig.clone(),
                placeholder_pk.clone(),
                placeholder_bls.clone(),
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
