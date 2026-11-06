//! Verifiable-inference commitment store and challenge lifecycle.
//!
//! Providers that serve through the built-in runtime produce a TOPLOC
//! commitment per response (top-k logits per generated token, hashed with
//! SHA-256 over the canonical encoding — see `tenzro_model::toploc`). This
//! module persists the full commitment blob so any party holding the same
//! model weights can later re-execute the prompt as a single prefill and
//! fuzzy-compare the recomputed logits against the committed ones.
//!
//! The prompt itself is never stored — the caller who received the response
//! holds it and supplies it at verification time. What persists is the
//! commitment (token ids + top-k logits) plus the serving context (model,
//! provider) needed to route a later dispute.
//!
//! ## Who decides a dispute
//!
//! A committee of staked validators, and nobody else:
//!
//! 1. **Filing** draws the committee ([`select_challenge_committee`]). Seats
//!    are sampled without replacement with probability proportional to stake,
//!    from keys derived from the commitment hash and the finalized block hash
//!    at filing. The commitment hash is fixed by the provider before any
//!    dispute and a commitment can be challenged once, so neither side can
//!    re-draw until the committee suits it. A validator whose consensus key is
//!    the provider's own key is never seated: a provider does not sit on its
//!    own dispute.
//! 2. **Commit.** Each seat submits `H(verdict || salt || challenge_id ||
//!    voter)` together with an Ed25519 signature by its registered consensus
//!    key over [`commit_signing_bytes`]. A commit the seat's key did not sign
//!    is refused, so neither the node holding the dispute nor its operator can
//!    cast a seat's vote.
//! 3. **Reveal.** Once committed stake passes the quorum, or the commit window
//!    closes, seats reveal `(verdict, salt)` with a signature over
//!    [`reveal_signing_bytes`]. Reveals are refused while commits are still
//!    open, so no verdict is visible before every seat could commit.
//! 4. **Finalize** tallies revealed stake. More than two thirds of committee
//!    stake upholds or dismisses. With no quorum, the challenge can only be
//!    closed (as dismissed) once the reveal window has passed.
//!
//! Every vote carries its signature and every seat its key, so any node can
//! re-check a challenge record end to end with [`audit_challenge`] without
//! trusting the node that holds it.
//!
//! Persistence: RocksDB `CF_CHALLENGES`. Commitments under
//! `commitment/<hash_hex>` (bincode), challenges under
//! `challenge/<challenge_id>` (JSON). Challenges hydrate on construction;
//! commitments are read on demand since blobs can be large
//! (k × step_count × 8 bytes).

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_model::toploc::InferenceCommitment;
use tenzro_storage::{CF_CHALLENGES, KvStore};
use tenzro_types::primitives::Hash;

use crate::error::{NodeError, Result};

const COMMITMENT_PREFIX: &str = "commitment/";
const CHALLENGE_PREFIX: &str = "challenge/";

/// Domain tag for the commit hash binding a committee member's verdict.
const VOTE_COMMIT_DOMAIN_TAG: &[u8] = b"tenzro/inference-challenge/vote-commit";
/// Domain tag for a seat's signature over its commit.
const COMMIT_SIGNATURE_TAG: &[u8] = b"tenzro/inference-challenge/commit-signature";
/// Domain tag for a seat's signature over its reveal.
const REVEAL_SIGNATURE_TAG: &[u8] = b"tenzro/inference-challenge/reveal-signature";
/// Domain tag for the per-candidate committee draw key.
const COMMITTEE_DRAW_TAG: &[u8] = b"tenzro/inference-challenge/committee-draw";

/// The commit and reveal windows a challenge runs under, seconds: the
/// governed parameters in force when it is filed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeWindows {
    /// Seconds seats have to commit after filing.
    pub commit_secs: u64,
    /// Seconds seats have to reveal after the commit window.
    pub reveal_secs: u64,
}

impl ChallengeWindows {
    /// The windows in `chain`'s governed parameters, or their genesis values
    /// without chain state.
    pub fn governed(chain: Option<&tenzro_vm::StateAdapter>) -> Self {
        let read = |key| {
            chain.map_or_else(
                || tenzro_vm::governance::genesis_param(key),
                |c| tenzro_vm::native::network_param(c, key),
            )
        };
        Self {
            commit_secs: read(tenzro_vm::native::CHALLENGE_COMMIT_WINDOW_PARAM),
            reveal_secs: read(tenzro_vm::native::CHALLENGE_REVEAL_WINDOW_PARAM),
        }
    }
}

/// A commitment blob plus the serving context a later dispute needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCommitment {
    /// Model the committed response came from.
    pub model_id: String,
    /// Provider that produced it: `0x` + hex of its announcement public key.
    pub provider: String,
    /// Unix seconds at storage time.
    pub created_at: u64,
    pub commitment: InferenceCommitment,
}

/// Where a filed challenge stands in the commit-reveal lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    /// Filed; committee drawn; awaiting vote commits.
    VotingCommit,
    /// Quorum of commits reached (or commit window elapsed); awaiting reveals.
    VotingReveal,
    /// Finalized against the provider — the committee majority found the
    /// commitment did not verify.
    Upheld,
    /// Finalized in the provider's favor — the committee majority found the
    /// commitment verified, or no upheld quorum was reached.
    Dismissed,
}

impl ChallengeStatus {
    /// Parse the snake_case wire form used by the RPC surface.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "voting_commit" => Some(Self::VotingCommit),
            "voting_reveal" => Some(Self::VotingReveal),
            "upheld" => Some(Self::Upheld),
            "dismissed" => Some(Self::Dismissed),
            _ => None,
        }
    }

    /// Whether the challenge has reached a terminal verdict.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Upheld | Self::Dismissed)
    }
}

/// A staked validator eligible for a committee seat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeCandidate {
    /// Registry address, `0x` + 64 lowercase hex.
    pub voter: String,
    /// Self-stake, the seat's vote weight and draw weight.
    pub stake: u128,
    /// P-256 leg (SEC1) of the registered consensus key, which the
    /// validator's machine identity derives from.
    pub consensus_pubkey: Vec<u8>,
}

/// A committee member's stake-weighted seat on one challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeSeat {
    /// Voter identity — the validator's registry address, `0x` + hex.
    pub voter: String,
    /// Self-stake at committee-draw time, used as the vote weight.
    pub stake: u128,
    /// Hex Ed25519 consensus key the seat's votes must be signed with.
    pub consensus_pubkey: String,
}

/// A committed-then-revealed committee vote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeVote {
    /// Voter identity (validator registry address, `0x` + hex).
    pub voter: String,
    /// `H(verdict_byte || salt || challenge_id || voter)` submitted in the
    /// commit phase.
    pub commit_hash: String,
    /// Hex signature by the seat's key over [`commit_signing_bytes`].
    pub commit_signature: String,
    /// Revealed verdict — `true` means "commitment did not verify" (upholds).
    /// `None` until the voter reveals.
    pub verdict: Option<bool>,
    /// Revealed salt (hex) proving the commit. `None` until reveal.
    pub salt: Option<String>,
    /// Hex signature by the seat's key over [`reveal_signing_bytes`].
    pub reveal_signature: Option<String>,
    /// Unix seconds at commit.
    pub committed_at: u64,
    /// Unix seconds at reveal.
    pub revealed_at: Option<u64>,
}

impl ChallengeVote {
    fn is_revealed(&self) -> bool {
        self.verdict.is_some() && self.salt.is_some()
    }
}

/// Canonical form of a voter address: `0x` + lowercase hex.
pub fn canonical_voter(voter: &str) -> String {
    format!(
        "0x{}",
        voter.trim().trim_start_matches("0x").to_ascii_lowercase()
    )
}

/// Recompute the commit hash for a `(verdict, salt, challenge_id, voter)`
/// tuple. The reveal must reproduce the commit exactly. Salt is raw bytes.
pub fn compute_vote_commit(verdict: bool, salt: &[u8], challenge_id: &str, voter: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(VOTE_COMMIT_DOMAIN_TAG);
    hasher.update([verdict as u8]);
    hasher.update((salt.len() as u32).to_le_bytes());
    hasher.update(salt);
    hasher.update(challenge_id.as_bytes());
    hasher.update(voter.as_bytes());
    hex::encode(hasher.finalize())
}

fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// The bytes a seat signs to commit: the challenge and its commit hash.
pub fn commit_signing_bytes(challenge_id: &str, commit_hash: &str) -> Vec<u8> {
    let mut buf = COMMIT_SIGNATURE_TAG.to_vec();
    put(&mut buf, challenge_id.as_bytes());
    put(&mut buf, commit_hash.as_bytes());
    buf
}

/// The bytes a seat signs to reveal: the challenge, the verdict and the salt.
pub fn reveal_signing_bytes(challenge_id: &str, verdict: bool, salt: &[u8]) -> Vec<u8> {
    let mut buf = REVEAL_SIGNATURE_TAG.to_vec();
    put(&mut buf, challenge_id.as_bytes());
    buf.push(verdict as u8);
    put(&mut buf, salt);
    buf
}

/// Checks a seat's vote signature: hex of the voter's 64-byte P-256 key
/// `x || y` followed by its signature (64-byte `r || s` or DER) under the challenge-vote
/// context. The key must be the one the voter's account address commits to.
fn check_seat_signature(seat: &CommitteeSeat, message: &[u8], signature_hex: &str) -> Result<()> {
    let raw = hex::decode(signature_hex.trim_start_matches("0x"))
        .map_err(|_| NodeError::Other("signature is not hex".to_string()))?;
    if !(128..=136).contains(&raw.len()) {
        return Err(NodeError::Other(
            "a vote signature is the 64-byte P-256 key followed by its signature".to_string(),
        ));
    }
    let (key, sig) = raw.split_at(64);
    let voter = hex::decode(seat.voter.trim_start_matches("0x"))
        .map_err(|_| NodeError::Other(format!("seat {} has an unreadable address", seat.voter)))?;
    if !tenzro_crypto::composite::controls_account(key, &voter) {
        return Err(NodeError::Other(format!(
            "the signing key is not the key of {}",
            seat.voter
        )));
    }
    tenzro_crypto::composite::verify_classical_component(
        key,
        tenzro_crypto::composite::SignatureContext::ChallengeVote,
        message,
        &tenzro_crypto::composite::ClassicalProof::Raw {
            signature: sig.to_vec(),
        },
    )
    .map_err(|_| {
        NodeError::Other(format!(
            "signature does not verify against the key of {}",
            seat.voter
        ))
    })
}

/// A draw key in `(0, 1]` per candidate, from the dispute and the entropy.
fn draw_uniform(dispute_key: &str, chain_entropy: &Hash, voter: &str) -> f64 {
    let mut h = Sha256::new();
    h.update(COMMITTEE_DRAW_TAG);
    h.update(chain_entropy.as_bytes());
    h.update((dispute_key.len() as u64).to_le_bytes());
    h.update(dispute_key.as_bytes());
    h.update(voter.as_bytes());
    let d = h.finalize();
    let mut top = [0u8; 8];
    top.copy_from_slice(&d[..8]);
    // 53 uniform bits mapped into (0, 1].
    ((u64::from_be_bytes(top) >> 11) as f64 + 1.0) / (1u64 << 53) as f64
}

/// Draw `k` committee seats, without replacement, each draw weighted by
/// stake: candidate `i` gets the key `u_i^(1/stake_i)` for a uniform `u_i`
/// derived from `dispute_key` and `chain_entropy`, and the `k` largest keys
/// win. The ordering is compared in log space (`ln(u_i) / stake_i`) so large
/// stakes stay exact.
///
/// Zero-stake candidates, and any candidate whose machine identity (derived
/// from its consensus key) is `excluded_machine` (the provider under
/// dispute), are never seated.
pub fn select_challenge_committee(
    dispute_key: &str,
    chain_entropy: Hash,
    candidates: &[CommitteeCandidate],
    excluded_machine: Option<&str>,
    k: usize,
) -> Vec<CommitteeSeat> {
    let mut keyed: Vec<(f64, &CommitteeCandidate)> = candidates
        .iter()
        .filter(|c| c.stake > 0)
        .filter(|c| {
            excluded_machine
                .is_none_or(|x| tenzro_types::did_derivation::machine_did(&c.consensus_pubkey) != x)
        })
        .map(|c| {
            let u = draw_uniform(dispute_key, &chain_entropy, &c.voter);
            (u.ln() / c.stake as f64, c)
        })
        .collect();
    keyed.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.voter.cmp(&b.1.voter))
    });
    keyed
        .into_iter()
        .take(k)
        .map(|(_, c)| CommitteeSeat {
            voter: c.voter.clone(),
            stake: c.stake,
            consensus_pubkey: hex::encode(&c.consensus_pubkey),
        })
        .collect()
}

/// Seats for a committee of `n` candidates: a third of them, between three
/// and seven, never more than there are.
pub fn committee_size(n: usize) -> usize {
    (n / 3).clamp(3, 7).min(n)
}

/// A dispute over one inference commitment, decided by a stake-weighted
/// committee via signed commit-reveal voting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceChallenge {
    /// UUID v4 assigned at filing.
    pub challenge_id: String,
    /// SHA-256 of the commitment's canonical encoding (hex, no 0x).
    pub commitment_hash: String,
    /// Model the committed response claims to come from (read from the
    /// stored commitment envelope at filing time).
    pub model_id: String,
    /// Provider under challenge (read from the stored envelope).
    pub provider: String,
    /// Who filed (address or DID string, caller-supplied).
    pub challenger: String,
    /// Free-form reason from the challenger.
    pub reason: String,
    pub status: ChallengeStatus,
    /// Finalized block hash at filing, hex — the committee-selection entropy.
    pub chain_entropy: String,
    /// The stake-weighted committee drawn at filing time.
    pub committee: Vec<CommitteeSeat>,
    /// Total committee stake weight (sum of seat stakes). The quorum
    /// threshold is derived from this.
    pub total_committee_stake: u128,
    /// Commit-then-reveal votes keyed on insertion order.
    pub votes: Vec<ChallengeVote>,
    /// Unix seconds.
    pub filed_at: u64,
    /// Commits are accepted until this time (Unix seconds).
    pub commit_deadline: u64,
    /// Reveals are accepted until this time; after it a challenge with no
    /// quorum may be closed.
    pub reveal_deadline: u64,
    /// Unix seconds, set when the committee finalizes.
    pub resolved_at: Option<u64>,
    /// Aggregate tally recorded at finalize: revealed-stake for/against and
    /// the derived quorum threshold.
    pub verification: Option<serde_json::Value>,
}

/// Stake a verdict must reach: more than two thirds of `total`
/// (`floor(2 * total / 3) + 1`), computed without overflowing `u128`.
pub fn quorum_threshold(total: u128) -> u128 {
    (total / 3) * 2 + ((total % 3) * 2) / 3 + 1
}

impl InferenceChallenge {
    fn quorum_threshold(&self) -> u128 {
        quorum_threshold(self.total_committee_stake)
    }

    /// Look up a committee seat by voter identity.
    fn seat_for(&self, voter: &str) -> Option<&CommitteeSeat> {
        self.committee.iter().find(|s| s.voter == voter)
    }

    /// Count of vote commits recorded so far.
    fn commit_count(&self) -> usize {
        self.votes.len()
    }

    /// Stake of every seat that has committed.
    fn committed_stake(&self) -> u128 {
        self.votes
            .iter()
            .filter_map(|v| self.seat_for(&v.voter).map(|s| s.stake))
            .sum()
    }

    /// Revealed stake `(uphold, dismiss)`.
    fn revealed_stake(&self) -> (u128, u128) {
        let mut uphold = 0u128;
        let mut dismiss = 0u128;
        for vote in &self.votes {
            let (Some(verdict), Some(seat)) = (vote.verdict, self.seat_for(&vote.voter)) else {
                continue;
            };
            if verdict {
                uphold += seat.stake;
            } else {
                dismiss += seat.stake;
            }
        }
        (uphold, dismiss)
    }
}

/// What [`audit_challenge`] found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChallengeAudit {
    /// Every commit and reveal signature verifies against its seat's key.
    pub signatures_valid: bool,
    /// Every reveal reproduces its commit hash.
    pub reveals_match_commits: bool,
    /// Revealed stake for upholding.
    pub uphold_stake: u128,
    /// Revealed stake for dismissing.
    pub dismiss_stake: u128,
    /// The verdict the signed votes support, if they reach a quorum.
    pub supported_verdict: Option<ChallengeStatus>,
    /// The recorded status agrees with what the signed votes support.
    pub status_consistent: bool,
    /// Problems found, one line each.
    pub problems: Vec<String>,
}

/// Re-check a challenge record from its own contents: each vote's signatures
/// against its seat's key, each reveal against its commit, and the recorded
/// verdict against the stake the signed votes carry. Needs no trust in the
/// node that produced the record.
pub fn audit_challenge(challenge: &InferenceChallenge) -> ChallengeAudit {
    let mut problems = Vec::new();
    let mut signatures_valid = true;
    let mut reveals_match = true;
    let mut uphold = 0u128;
    let mut dismiss = 0u128;
    for vote in &challenge.votes {
        let Some(seat) = challenge.seat_for(&vote.voter) else {
            signatures_valid = false;
            problems.push(format!("{} voted without a seat", vote.voter));
            continue;
        };
        if let Err(e) = check_seat_signature(
            seat,
            &commit_signing_bytes(&challenge.challenge_id, &vote.commit_hash),
            &vote.commit_signature,
        ) {
            signatures_valid = false;
            problems.push(format!("commit of {}: {e}", vote.voter));
        }
        let (Some(verdict), Some(salt_hex)) = (vote.verdict, vote.salt.as_deref()) else {
            continue;
        };
        let salt = hex::decode(salt_hex).unwrap_or_default();
        if compute_vote_commit(verdict, &salt, &challenge.challenge_id, &vote.voter)
            != vote.commit_hash
        {
            reveals_match = false;
            problems.push(format!(
                "reveal of {} does not match its commit",
                vote.voter
            ));
            continue;
        }
        match vote.reveal_signature.as_deref() {
            Some(sig) => match check_seat_signature(
                seat,
                &reveal_signing_bytes(&challenge.challenge_id, verdict, &salt),
                sig,
            ) {
                Ok(()) => {
                    if verdict {
                        uphold += seat.stake;
                    } else {
                        dismiss += seat.stake;
                    }
                }
                Err(e) => {
                    signatures_valid = false;
                    problems.push(format!("reveal of {}: {e}", vote.voter));
                }
            },
            None => {
                signatures_valid = false;
                problems.push(format!("reveal of {} is unsigned", vote.voter));
            }
        }
    }
    let threshold = challenge.quorum_threshold();
    let supported = if uphold >= threshold {
        Some(ChallengeStatus::Upheld)
    } else if dismiss >= threshold {
        Some(ChallengeStatus::Dismissed)
    } else {
        None
    };
    let status_consistent = match (challenge.status, supported) {
        (ChallengeStatus::Upheld, s) => s == Some(ChallengeStatus::Upheld),
        // Dismissed either by a dismiss quorum or by closing without quorum
        // after the reveal window.
        (ChallengeStatus::Dismissed, s) => s != Some(ChallengeStatus::Upheld),
        (_, _) => true,
    };
    if !status_consistent {
        problems.push("recorded status is not what the signed votes support".to_string());
    }
    ChallengeAudit {
        signatures_valid,
        reveals_match_commits: reveals_match,
        uphold_stake: uphold,
        dismiss_stake: dismiss,
        supported_verdict: supported,
        status_consistent,
        problems,
    }
}

/// Commitment store + challenge registry with RocksDB write-through.
pub struct ChallengeManager {
    storage: Arc<dyn KvStore>,
    challenges: DashMap<String, InferenceChallenge>,
}

/// Unix seconds now.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl ChallengeManager {
    /// Construct and hydrate the challenge index from `CF_CHALLENGES`.
    pub fn new(storage: Arc<dyn KvStore>) -> Result<Arc<Self>> {
        let manager = Self {
            storage,
            challenges: DashMap::new(),
        };
        manager.hydrate()?;
        Ok(Arc::new(manager))
    }

    fn hydrate(&self) -> Result<()> {
        let rows = self
            .storage
            .scan_prefix(CF_CHALLENGES, CHALLENGE_PREFIX.as_bytes())?;
        for (_key, value) in rows {
            match serde_json::from_slice::<InferenceChallenge>(&value) {
                Ok(challenge) => {
                    self.challenges
                        .insert(challenge.challenge_id.clone(), challenge);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Skipping undecodable inference challenge row");
                }
            }
        }
        Ok(())
    }

    /// Persist a commitment blob keyed by its canonical hash. Idempotent —
    /// the key is content-addressed. Returns the hash hex.
    pub fn store_commitment(
        &self,
        model_id: &str,
        provider: &str,
        commitment: &InferenceCommitment,
    ) -> Result<String> {
        let hash_hex = commitment.hash_hex();
        let stored = StoredCommitment {
            model_id: model_id.to_string(),
            provider: provider.to_string(),
            created_at: now_secs(),
            commitment: commitment.clone(),
        };
        let key = format!("{COMMITMENT_PREFIX}{hash_hex}");
        let value = bincode::serialize(&stored)
            .map_err(|e| NodeError::Internal(format!("commitment encode: {e}")))?;
        self.storage.put(CF_CHALLENGES, key.as_bytes(), &value)?;
        Ok(hash_hex)
    }

    /// Fetch a stored commitment by hash hex (no 0x prefix).
    pub fn get_commitment(&self, hash_hex: &str) -> Result<Option<StoredCommitment>> {
        let key = format!("{COMMITMENT_PREFIX}{hash_hex}");
        let Some(bytes) = self.storage.get(CF_CHALLENGES, key.as_bytes())? else {
            return Ok(None);
        };
        let stored = bincode::deserialize(&bytes)
            .map_err(|e| NodeError::Internal(format!("commitment decode: {e}")))?;
        Ok(Some(stored))
    }

    /// File a new challenge against a commitment hash and draw its committee.
    ///
    /// The commitment must already be stored on this node — a challenge over
    /// an unknown hash is unverifiable and rejected. Model and provider are
    /// read from the stored envelope so filings can't misattribute. A
    /// commitment can be challenged once: a second filing would let a party
    /// re-draw the committee.
    pub fn file(
        &self,
        commitment_hash: &str,
        challenger: &str,
        reason: &str,
        chain_entropy: Hash,
        candidates: &[CommitteeCandidate],
        windows: ChallengeWindows,
        now: u64,
    ) -> Result<InferenceChallenge> {
        let stored = self.get_commitment(commitment_hash)?.ok_or_else(|| {
            NodeError::Other(format!("no stored commitment with hash {commitment_hash}"))
        })?;
        if self
            .challenges
            .iter()
            .any(|c| c.commitment_hash == commitment_hash)
        {
            return Err(NodeError::Other(format!(
                "commitment {commitment_hash} has already been challenged"
            )));
        }
        let committee = select_challenge_committee(
            commitment_hash,
            chain_entropy,
            candidates,
            Some(stored.provider.as_str()),
            committee_size(candidates.len()),
        );
        if committee.is_empty() {
            return Err(NodeError::Other(
                "cannot file a challenge with an empty committee".to_string(),
            ));
        }
        let total_committee_stake: u128 = committee.iter().map(|s| s.stake).sum();
        let challenge = InferenceChallenge {
            challenge_id: uuid::Uuid::new_v4().to_string(),
            commitment_hash: commitment_hash.to_string(),
            model_id: stored.model_id,
            provider: stored.provider,
            challenger: challenger.to_string(),
            reason: reason.to_string(),
            status: ChallengeStatus::VotingCommit,
            chain_entropy: hex::encode(chain_entropy.as_bytes()),
            committee,
            total_committee_stake,
            votes: Vec::new(),
            filed_at: now,
            commit_deadline: now + windows.commit_secs,
            reveal_deadline: now + windows.commit_secs + windows.reveal_secs,
            resolved_at: None,
            verification: None,
        };
        self.persist(&challenge)?;
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(challenge)
    }

    /// Record a committee member's signed vote **commit**. Rejected if the
    /// voter is not on the committee, if the commit window has closed, if the
    /// voter has already committed, or if the seat's key did not sign it.
    /// When the committed stake reaches the quorum the challenge advances to
    /// the reveal phase.
    pub fn commit_vote(
        &self,
        challenge_id: &str,
        voter: &str,
        commit_hash: &str,
        signature_hex: &str,
        now: u64,
    ) -> Result<InferenceChallenge> {
        let voter = canonical_voter(voter);
        let mut entry = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| NodeError::Other(format!("unknown challenge {challenge_id}")))?;
        if entry.status != ChallengeStatus::VotingCommit || now >= entry.commit_deadline {
            return Err(NodeError::Other(format!(
                "challenge {challenge_id} is not accepting commits"
            )));
        }
        let seat = entry.seat_for(&voter).cloned().ok_or_else(|| {
            NodeError::Other(format!(
                "{voter} is not on the committee for challenge {challenge_id}"
            ))
        })?;
        if entry.votes.iter().any(|v| v.voter == voter) {
            return Err(NodeError::Other(format!(
                "{voter} already committed a vote for challenge {challenge_id}"
            )));
        }
        check_seat_signature(
            &seat,
            &commit_signing_bytes(challenge_id, commit_hash),
            signature_hex,
        )?;
        entry.votes.push(ChallengeVote {
            voter,
            commit_hash: commit_hash.to_string(),
            commit_signature: signature_hex.trim_start_matches("0x").to_string(),
            verdict: None,
            salt: None,
            reveal_signature: None,
            committed_at: now,
            revealed_at: None,
        });
        if entry.committed_stake() >= entry.quorum_threshold() {
            entry.status = ChallengeStatus::VotingReveal;
        }
        let updated = entry.clone();
        drop(entry);
        self.persist(&updated)?;
        Ok(updated)
    }

    /// Record a committee member's signed vote **reveal**. The revealed
    /// `(verdict, salt)` must reproduce the commit hash submitted earlier, and
    /// the seat's key must have signed the reveal. Accepted once commits are
    /// closed (quorum reached or commit window elapsed) and until the reveal
    /// window ends. Salt is raw bytes.
    pub fn reveal_vote(
        &self,
        challenge_id: &str,
        voter: &str,
        verdict: bool,
        salt: &[u8],
        signature_hex: &str,
        now: u64,
    ) -> Result<InferenceChallenge> {
        let voter = canonical_voter(voter);
        let mut entry = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| NodeError::Other(format!("unknown challenge {challenge_id}")))?;
        if entry.status.is_terminal() {
            return Err(NodeError::Other(format!(
                "challenge {challenge_id} already finalized ({:?})",
                entry.status
            )));
        }
        if entry.status == ChallengeStatus::VotingCommit && now < entry.commit_deadline {
            return Err(NodeError::Other(format!(
                "challenge {challenge_id} is still accepting commits; reveals open when they close"
            )));
        }
        if now >= entry.reveal_deadline {
            return Err(NodeError::Other(format!(
                "the reveal window for challenge {challenge_id} has closed"
            )));
        }
        let seat = entry.seat_for(&voter).cloned().ok_or_else(|| {
            NodeError::Other(format!(
                "{voter} is not on the committee for {challenge_id}"
            ))
        })?;
        let expected = compute_vote_commit(verdict, salt, challenge_id, &voter);
        let vote = entry
            .votes
            .iter_mut()
            .find(|v| v.voter == voter)
            .ok_or_else(|| {
                NodeError::Other(format!(
                    "{voter} has no committed vote to reveal for challenge {challenge_id}"
                ))
            })?;
        if vote.is_revealed() {
            return Err(NodeError::Other(format!(
                "{voter} already revealed a vote for challenge {challenge_id}"
            )));
        }
        if vote.commit_hash != expected {
            return Err(NodeError::Other(format!(
                "reveal does not match the commit for {voter}"
            )));
        }
        check_seat_signature(
            &seat,
            &reveal_signing_bytes(challenge_id, verdict, salt),
            signature_hex,
        )?;
        vote.verdict = Some(verdict);
        vote.salt = Some(hex::encode(salt));
        vote.reveal_signature = Some(signature_hex.trim_start_matches("0x").to_string());
        vote.revealed_at = Some(now);
        // Commits closed by their window rather than by quorum.
        entry.status = ChallengeStatus::VotingReveal;
        let updated = entry.clone();
        drop(entry);
        self.persist(&updated)?;
        Ok(updated)
    }

    /// Idempotently finalize a challenge by tallying revealed votes by
    /// committee stake weight.
    ///
    /// - A verdict clears when its revealed stake reaches the quorum.
    ///   "Did not verify" stake upholds; "verified" stake dismisses.
    /// - With no quorum, the challenge stays open until the reveal window has
    ///   passed, and is then dismissed: the burden is on the committee to
    ///   reach an upheld quorum.
    /// - Replaying finalize on an already-terminal challenge returns the same
    ///   verdict (idempotent). It never overwrites a decided challenge.
    pub fn finalize(&self, challenge_id: &str, now: u64) -> Result<InferenceChallenge> {
        let mut entry = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| NodeError::Other(format!("unknown challenge {challenge_id}")))?;
        if entry.status.is_terminal() {
            return Ok(entry.clone());
        }
        let threshold = entry.quorum_threshold();
        let (uphold_stake, dismiss_stake) = entry.revealed_stake();
        let window_closed = now >= entry.reveal_deadline;
        let status = if uphold_stake >= threshold {
            ChallengeStatus::Upheld
        } else if dismiss_stake >= threshold || window_closed {
            ChallengeStatus::Dismissed
        } else {
            return Err(NodeError::Other(format!(
                "challenge {challenge_id} has no quorum yet \
                 (uphold={uphold_stake}, dismiss={dismiss_stake}, threshold={threshold}) \
                 and its reveal window is still open"
            )));
        };

        entry.status = status;
        entry.resolved_at = Some(now);
        entry.verification = Some(serde_json::json!({
            "uphold_stake": uphold_stake.to_string(),
            "dismiss_stake": dismiss_stake.to_string(),
            "quorum_threshold": threshold.to_string(),
            "total_committee_stake": entry.total_committee_stake.to_string(),
            "votes_committed": entry.commit_count(),
            "closed_without_quorum": uphold_stake < threshold && dismiss_stake < threshold,
        }));
        let resolved = entry.clone();
        drop(entry);
        self.persist(&resolved)?;
        Ok(resolved)
    }

    /// Look up a challenge by id.
    pub fn get(&self, challenge_id: &str) -> Option<InferenceChallenge> {
        self.challenges.get(challenge_id).map(|c| c.clone())
    }

    /// List challenges, optionally filtered by status and/or provider.
    pub fn list(
        &self,
        status: Option<ChallengeStatus>,
        provider: Option<&str>,
    ) -> Vec<InferenceChallenge> {
        let mut out: Vec<InferenceChallenge> = self
            .challenges
            .iter()
            .filter(|c| status.is_none_or(|s| c.status == s))
            .filter(|c| provider.is_none_or(|p| c.provider == p))
            .map(|c| c.clone())
            .collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.filed_at));
        out
    }

    fn persist(&self, challenge: &InferenceChallenge) -> Result<()> {
        let key = format!("{CHALLENGE_PREFIX}{}", challenge.challenge_id);
        let value = serde_json::to_vec(challenge)
            .map_err(|e| NodeError::Internal(format!("challenge encode: {e}")))?;
        self.storage.put(CF_CHALLENGES, key.as_bytes(), &value)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_model::toploc::{StepRecord, TopKEntry};
    use tenzro_storage::MemoryStore;

    const T0: u64 = 1_000_000;

    fn sample_commitment() -> InferenceCommitment {
        InferenceCommitment {
            k: 2,
            prompt_tokens: 3,
            steps: vec![StepRecord {
                token_id: 42,
                top_k: vec![
                    TopKEntry {
                        token_id: 42,
                        logit: 1.5,
                    },
                    TopKEntry {
                        token_id: 7,
                        logit: 0.5,
                    },
                ],
            }],
        }
    }

    fn manager() -> Arc<ChallengeManager> {
        ChallengeManager::new(Arc::new(MemoryStore::new())).expect("manager")
    }

    fn entropy(byte: u8) -> Hash {
        Hash::from_bytes(&[byte; 32]).unwrap()
    }

    /// Three validators with equal stake and real keys.
    struct Validators {
        signers: Vec<tenzro_crypto::testing::TestHybridSigner>,
        candidates: Vec<CommitteeCandidate>,
    }

    fn validators(n: usize) -> Validators {
        use tenzro_crypto::composite::HybridSigner as _;
        let signers: Vec<_> = (0..n)
            .map(|i| tenzro_crypto::testing::TestHybridSigner::p256_only(i as u8 + 1))
            .collect();
        let candidates = signers
            .iter()
            .map(|s| CommitteeCandidate {
                voter: canonical_voter(&hex::encode(s.public_key().account_slot())),
                stake: 100,
                consensus_pubkey: s.public_key().p256.clone(),
            })
            .collect();
        Validators {
            signers,
            candidates,
        }
    }

    impl Validators {
        fn signer_for(&self, voter: &str) -> &tenzro_crypto::testing::TestHybridSigner {
            let i = self
                .candidates
                .iter()
                .position(|c| c.voter == voter)
                .unwrap();
            &self.signers[i]
        }

        fn sign(&self, voter: &str, msg: &[u8]) -> String {
            // A committee member signs the vote with the P-256 key its
            // account address commits to, under the challenge-vote context.
            let signer = self.signer_for(voter);
            let tenzro_crypto::composite::ClassicalProof::Raw { signature } = signer
                .sign_classical(
                    tenzro_crypto::composite::SignatureContext::ChallengeVote,
                    msg,
                )
            else {
                unreachable!("the test signer signs raw")
            };
            use tenzro_crypto::composite::HybridSigner as _;
            hex::encode([signer.public_key().p256.as_slice(), signature.as_slice()].concat())
        }

        fn commit(&self, m: &ChallengeManager, ch: &str, voter: &str, verdict: bool, salt: &[u8]) {
            let h = compute_vote_commit(verdict, salt, ch, voter);
            let sig = self.sign(voter, &commit_signing_bytes(ch, &h));
            m.commit_vote(ch, voter, &h, &sig, T0 + 10).expect("commit");
        }

        fn reveal(
            &self,
            m: &ChallengeManager,
            ch: &str,
            voter: &str,
            verdict: bool,
            salt: &[u8],
            now: u64,
        ) -> Result<InferenceChallenge> {
            let sig = self.sign(voter, &reveal_signing_bytes(ch, verdict, salt));
            m.reveal_vote(ch, voter, verdict, salt, &sig, now)
        }
    }

    fn filed(m: &ChallengeManager, v: &Validators) -> InferenceChallenge {
        let hash = m
            .store_commitment("test-model", "0xabc", &sample_commitment())
            .expect("store");
        m.file(
            &hash,
            "0xdef",
            "suspect output",
            entropy(1),
            &v.candidates,
            ChallengeWindows::governed(None),
            T0,
        )
        .expect("file")
    }

    #[test]
    fn signed_commit_reveal_upholds() {
        let m = manager();
        let v = validators(3);
        let ch = filed(&m, &v);
        let id = ch.challenge_id.clone();
        let seats: Vec<String> = ch.committee.iter().map(|s| s.voter.clone()).collect();
        assert_eq!(seats.len(), 3);
        for (i, s) in seats.iter().enumerate() {
            v.commit(&m, &id, s, true, format!("salt-{i}").as_bytes());
        }
        assert_eq!(m.get(&id).unwrap().status, ChallengeStatus::VotingReveal);
        for (i, s) in seats.iter().enumerate() {
            v.reveal(&m, &id, s, true, format!("salt-{i}").as_bytes(), T0 + 20)
                .expect("reveal");
        }
        let done = m.finalize(&id, T0 + 30).expect("finalize");
        assert_eq!(done.status, ChallengeStatus::Upheld);
        let audit = audit_challenge(&done);
        assert!(
            audit.signatures_valid && audit.status_consistent,
            "{audit:?}"
        );
        // Idempotent.
        assert_eq!(
            m.finalize(&id, T0 + 99_999).unwrap().status,
            ChallengeStatus::Upheld
        );
    }

    #[test]
    fn a_commit_the_seat_did_not_sign_is_refused() {
        let m = manager();
        let v = validators(3);
        let ch = filed(&m, &v);
        let seat = ch.committee[0].voter.clone();
        let h = compute_vote_commit(false, b"s", &ch.challenge_id, &seat);
        // The operator of the node holding the dispute has its own key, not
        // the seat's: a vote it signs for the seat does not verify.
        let operator = tenzro_crypto::testing::TestHybridSigner::p256_only(200);
        let tenzro_crypto::composite::ClassicalProof::Raw { signature } = operator.sign_classical(
            tenzro_crypto::composite::SignatureContext::ChallengeVote,
            &commit_signing_bytes(&ch.challenge_id, &h),
        ) else {
            unreachable!("the test signer signs raw")
        };
        use tenzro_crypto::composite::HybridSigner as _;
        let forged =
            hex::encode([operator.public_key().p256.as_slice(), signature.as_slice()].concat());
        assert!(
            m.commit_vote(&ch.challenge_id, &seat, &h, &forged, T0 + 1)
                .is_err()
        );
        // An unsigned commit is refused too.
        assert!(
            m.commit_vote(&ch.challenge_id, &seat, &h, "", T0 + 1)
                .is_err()
        );
        // A signature over a different commit hash does not transfer.
        let other = compute_vote_commit(true, b"s", &ch.challenge_id, &seat);
        let sig_other = v.sign(&seat, &commit_signing_bytes(&ch.challenge_id, &other));
        assert!(
            m.commit_vote(&ch.challenge_id, &seat, &h, &sig_other, T0 + 1)
                .is_err()
        );
    }

    #[test]
    fn reveals_wait_for_commits_to_close() {
        let m = manager();
        let v = validators(4);
        let ch = filed(&m, &v);
        let seat = ch.committee[0].voter.clone();
        v.commit(&m, &ch.challenge_id, &seat, true, b"early");
        // One commit is below quorum and the window is open: no reveal yet.
        assert!(
            v.reveal(&m, &ch.challenge_id, &seat, true, b"early", T0 + 20)
                .is_err()
        );
        // After the commit window closes the reveal is accepted.
        v.reveal(
            &m,
            &ch.challenge_id,
            &seat,
            true,
            b"early",
            T0 + ChallengeWindows::governed(None).commit_secs,
        )
        .expect("reveal after commit window");
    }

    #[test]
    fn no_quorum_cannot_be_closed_before_the_reveal_window_ends() {
        let m = manager();
        let v = validators(3);
        let ch = filed(&m, &v);
        let seat = ch.committee[0].voter.clone();
        v.commit(&m, &ch.challenge_id, &seat, true, b"lonely");
        assert!(m.finalize(&ch.challenge_id, T0 + 20).is_err());
        let done = m
            .finalize(&ch.challenge_id, ch.reveal_deadline)
            .expect("closes after the window");
        assert_eq!(done.status, ChallengeStatus::Dismissed);
    }

    #[test]
    fn the_provider_is_never_seated_on_its_own_dispute() {
        let m = manager();
        let v = validators(3);
        // The provider is one of the validators' machine identities.
        let provider = tenzro_types::did_derivation::machine_did(&v.candidates[1].consensus_pubkey);
        let hash = m
            .store_commitment("test-model", &provider, &sample_commitment())
            .unwrap();
        let ch = m
            .file(
                &hash,
                "0xdef",
                "r",
                entropy(3),
                &v.candidates,
                ChallengeWindows::governed(None),
                T0,
            )
            .unwrap();
        assert!(
            ch.committee
                .iter()
                .all(|s| s.voter != v.candidates[1].voter)
        );
    }

    #[test]
    fn a_commitment_is_challenged_once() {
        let m = manager();
        let v = validators(3);
        let ch = filed(&m, &v);
        assert!(
            m.file(
                &ch.commitment_hash,
                "0xdef",
                "again",
                entropy(2),
                &v.candidates,
                ChallengeWindows::governed(None),
                T0
            )
            .is_err()
        );
    }

    #[test]
    fn quorum_is_strictly_more_than_two_thirds() {
        assert_eq!(quorum_threshold(300), 201);
        // One of two equal seats is not a quorum.
        assert_eq!(quorum_threshold(2), 2);
        assert_eq!(quorum_threshold(3), 3);
        assert!(quorum_threshold(u128::MAX) > u128::MAX / 3 * 2);
    }

    #[test]
    fn selection_is_deterministic_and_follows_stake() {
        let mut cands: Vec<CommitteeCandidate> = (0..30)
            .map(|i| CommitteeCandidate {
                voter: canonical_voter(&format!("{:064x}", i)),
                stake: if i == 0 {
                    0
                } else if i < 5 {
                    1_000_000
                } else {
                    1
                },
                consensus_pubkey: vec![i as u8; 32],
            })
            .collect();
        let a = select_challenge_committee("d", entropy(9), &cands, None, 4);
        let b = select_challenge_committee("d", entropy(9), &cands, None, 4);
        assert_eq!(a, b);
        assert!(a.iter().all(|s| s.stake > 0));
        // Heavily staked validators dominate the draw across many disputes.
        let mut heavy = 0;
        for d in 0..200 {
            let seats = select_challenge_committee(&format!("d{d}"), entropy(9), &cands, None, 4);
            heavy += seats.iter().filter(|s| s.stake == 1_000_000).count();
        }
        assert!(heavy > 700, "heavy seats {heavy} of 800");
        // Removing stake removes the seat.
        cands.iter_mut().for_each(|c| c.stake = 0);
        assert!(select_challenge_committee("d", entropy(9), &cands, None, 4).is_empty());
    }

    #[test]
    fn audit_catches_a_tampered_record() {
        let m = manager();
        let v = validators(3);
        let ch = filed(&m, &v);
        let id = ch.challenge_id.clone();
        for (i, s) in ch.committee.iter().enumerate() {
            v.commit(&m, &id, &s.voter, false, format!("{i}").as_bytes());
        }
        for (i, s) in ch.committee.iter().enumerate() {
            v.reveal(&m, &id, &s.voter, false, format!("{i}").as_bytes(), T0 + 20)
                .unwrap();
        }
        let mut done = m.finalize(&id, T0 + 30).unwrap();
        assert_eq!(done.status, ChallengeStatus::Dismissed);
        assert!(audit_challenge(&done).problems.is_empty());
        // A holder that flips the outcome in storage is caught.
        done.status = ChallengeStatus::Upheld;
        assert!(!audit_challenge(&done).status_consistent);
        // So is one that flips a revealed verdict.
        done.status = ChallengeStatus::Dismissed;
        done.votes[0].verdict = Some(true);
        assert!(!audit_challenge(&done).reveals_match_commits);
    }

    #[test]
    fn hydrate_restores_challenges() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let v = validators(3);
        let (hash, id) = {
            let m = ChallengeManager::new(storage.clone()).expect("manager");
            let ch = filed(&m, &v);
            (ch.commitment_hash.clone(), ch.challenge_id)
        };
        let m2 = ChallengeManager::new(storage).expect("rehydrated manager");
        let restored = m2.get(&id).expect("hydrated challenge");
        assert_eq!(restored.commitment_hash, hash);
        assert_eq!(restored.status, ChallengeStatus::VotingCommit);
        assert_eq!(restored.committee.len(), 3);
        assert!(m2.get_commitment(&hash).expect("get").is_some());
    }

    #[test]
    fn status_parse_roundtrip() {
        for s in ["voting_commit", "voting_reveal", "upheld", "dismissed"] {
            assert!(ChallengeStatus::parse(s).is_some());
        }
        assert_eq!(ChallengeStatus::parse("bogus"), None);
    }
}
