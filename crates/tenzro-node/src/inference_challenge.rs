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
//! The challenge lifecycle is committee-driven — no operator can decide a
//! verdict alone:
//!
//! 1. A caller files a challenge against a commitment hash
//!    (`tenzro_fileInferenceChallenge`). Filing draws a deterministic
//!    stake-weighted committee from the active validator set, seeded by the
//!    finalized block hash at filing time (grinding-resistant), and opens a
//!    commit phase.
//! 2. Committee members re-execute the disputed inference locally
//!    (`tenzro_verifyInferenceCommitment` produces a
//!    [`tenzro_model::toploc::VerificationOutcome`]) and submit a **commit**:
//!    `H(verdict || salt || challenge_id || voter)` binding their vote without
//!    revealing it (`tenzro_commitChallengeVote`).
//! 3. After a quorum of commits (or the commit window elapses) the challenge
//!    moves to the reveal phase; members disclose `(verdict, salt)` which is
//!    checked against their commit (`tenzro_revealChallengeVote`).
//! 4. `tenzro_finalizeChallenge` tallies revealed votes by committee stake
//!    weight. A 2f+1 stake-weighted majority for "did not verify" upholds the
//!    challenge; a 2f+1 majority for "verified" dismisses it. Finalize is
//!    **idempotent** — replaying it after a decision returns the same verdict;
//!    conflicting tallies never overwrite a decided challenge. An upheld
//!    challenge feeds the existing provider penalty paths (reputation
//!    decrement on `ProviderManager` + `ComputeBondManager::record_failure`).
//!
//! The commit-reveal window prevents a late committee member from copying an
//! early voter's disclosed verdict; the stake weighting means committee
//! members with more at stake carry proportional weight, matching the
//! consensus safety model.
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

/// A commitment blob plus the serving context a later dispute needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCommitment {
    /// Model the committed response came from.
    pub model_id: String,
    /// Provider that produced it (hex address string as advertised).
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

/// A committee member's stake-weighted seat on one challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeSeat {
    /// Voter identity — the validator's registry address, hex with `0x`.
    pub voter: String,
    /// Self-stake at committee-draw time, used as the vote weight.
    pub stake: u128,
}

/// A committed-then-revealed committee vote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeVote {
    /// Voter identity (validator registry address, hex with `0x`).
    pub voter: String,
    /// `H(verdict_byte || salt || challenge_id || voter)` submitted in the
    /// commit phase.
    pub commit_hash: String,
    /// Revealed verdict — `true` means "commitment did not verify" (upholds).
    /// `None` until the voter reveals.
    pub verdict: Option<bool>,
    /// Revealed salt (hex) proving the commit. `None` until reveal.
    pub salt: Option<String>,
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

/// Draw a deterministic, stake-weighted committee for a challenge from a set
/// of `(voter, stake)` candidates, seeded by the challenge id and the
/// finalized-block `chain_entropy`.
///
/// The selection reuses the training crate's grinding-resistant scoring
/// ([`tenzro_training::select_witness_committee`]) keyed on `challenge_id` as
/// the task identifier and round 0 — one committee per challenge. Stakes are
/// carried onto the returned seats so `finalize` can weight votes without a
/// second registry read. Candidates with zero stake are excluded (a
/// zero-weight vote cannot move a quorum and would only dilute the committee).
///
/// `k` is typically [`tenzro_training::recommended_committee_size`] over the
/// candidate count.
pub fn select_challenge_committee(
    challenge_id: &str,
    chain_entropy: Hash,
    candidates: &[(String, u128)],
    k: usize,
) -> Vec<CommitteeSeat> {
    let staked: Vec<&(String, u128)> = candidates.iter().filter(|(_, s)| *s > 0).collect();
    if staked.is_empty() || k == 0 {
        return Vec::new();
    }
    let dids: Vec<String> = staked.iter().map(|(v, _)| v.clone()).collect();
    let chosen =
        tenzro_training::select_witness_committee(challenge_id, 0, chain_entropy, &dids, k);
    chosen
        .into_iter()
        .filter_map(|voter| {
            staked
                .iter()
                .find(|(v, _)| *v == voter)
                .map(|(_, stake)| CommitteeSeat {
                    voter,
                    stake: *stake,
                })
        })
        .collect()
}

/// A dispute over one inference commitment, decided by a stake-weighted
/// committee via commit-reveal voting.
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
    /// Total committee stake weight (sum of seat stakes). The 2f+1 quorum
    /// threshold is derived from this.
    pub total_committee_stake: u128,
    /// Commit-then-reveal votes keyed on insertion order.
    pub votes: Vec<ChallengeVote>,
    /// Unix seconds.
    pub filed_at: u64,
    /// Unix seconds, set when the committee finalizes.
    pub resolved_at: Option<u64>,
    /// Aggregate tally recorded at finalize: revealed-stake for/against and
    /// the derived quorum threshold.
    pub verification: Option<serde_json::Value>,
}

impl InferenceChallenge {
    /// Stake threshold a verdict must clear to finalize: strictly greater than
    /// two-thirds of the committee stake (2f+1 semantics).
    fn quorum_threshold(&self) -> u128 {
        // (2/3 of total) + 1, computed to avoid overflow on u128 stakes.
        (self.total_committee_stake / 3) * 2 + 1
    }

    /// Look up a committee seat by voter identity.
    fn seat_for(&self, voter: &str) -> Option<&CommitteeSeat> {
        self.committee.iter().find(|s| s.voter == voter)
    }

    /// Count of vote commits recorded so far.
    fn commit_count(&self) -> usize {
        self.votes.len()
    }
}

/// Commitment store + challenge registry with RocksDB write-through.
pub struct ChallengeManager {
    storage: Arc<dyn KvStore>,
    challenges: DashMap<String, InferenceChallenge>,
}

fn now_secs() -> u64 {
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

    /// File a new challenge against a commitment hash. The commitment must
    /// already be stored on this node — a challenge over an unknown hash is
    /// unverifiable and rejected. Model and provider are read from the
    /// stored envelope so filings can't misattribute.
    ///
    /// `committee` is the stake-weighted committee drawn by the caller from
    /// the active validator set (via `select_challenge_committee`), seeded by
    /// `chain_entropy` (the finalized block hash at filing). A challenge with
    /// an empty committee is rejected — there is nobody to decide it.
    pub fn file(
        &self,
        commitment_hash: &str,
        challenger: &str,
        reason: &str,
        chain_entropy: Hash,
        committee: Vec<CommitteeSeat>,
    ) -> Result<InferenceChallenge> {
        let stored = self.get_commitment(commitment_hash)?.ok_or_else(|| {
            NodeError::Other(format!("no stored commitment with hash {commitment_hash}"))
        })?;
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
            filed_at: now_secs(),
            resolved_at: None,
            verification: None,
        };
        self.persist(&challenge)?;
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(challenge)
    }

    /// Record a committee member's vote **commit**. Rejected if the voter is
    /// not on the committee, if the challenge is not in the commit phase, or
    /// if the voter has already committed. When the committed stake reaches a
    /// 2f+1 quorum the challenge advances to the reveal phase automatically.
    pub fn commit_vote(
        &self,
        challenge_id: &str,
        voter: &str,
        commit_hash: &str,
    ) -> Result<InferenceChallenge> {
        let mut entry = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| NodeError::Other(format!("unknown challenge {challenge_id}")))?;
        if entry.status != ChallengeStatus::VotingCommit {
            return Err(NodeError::Other(format!(
                "challenge {challenge_id} is not accepting commits ({:?})",
                entry.status
            )));
        }
        if entry.seat_for(voter).is_none() {
            return Err(NodeError::Other(format!(
                "{voter} is not on the committee for challenge {challenge_id}"
            )));
        }
        if entry.votes.iter().any(|v| v.voter == voter) {
            return Err(NodeError::Other(format!(
                "{voter} already committed a vote for challenge {challenge_id}"
            )));
        }
        entry.votes.push(ChallengeVote {
            voter: voter.to_string(),
            commit_hash: commit_hash.to_string(),
            verdict: None,
            salt: None,
            committed_at: now_secs(),
            revealed_at: None,
        });
        // Advance to reveal once committed stake clears the quorum threshold.
        let committed_stake: u128 = entry
            .votes
            .iter()
            .filter_map(|v| entry.seat_for(&v.voter).map(|s| s.stake))
            .sum();
        if committed_stake >= entry.quorum_threshold() {
            entry.status = ChallengeStatus::VotingReveal;
        }
        let updated = entry.clone();
        drop(entry);
        self.persist(&updated)?;
        Ok(updated)
    }

    /// Record a committee member's vote **reveal**. The revealed
    /// `(verdict, salt)` must reproduce the commit hash submitted earlier, or
    /// the reveal is rejected. Accepted during the reveal phase; also accepted
    /// during the commit phase so members can reveal early once they have
    /// committed. Salt is raw bytes.
    pub fn reveal_vote(
        &self,
        challenge_id: &str,
        voter: &str,
        verdict: bool,
        salt: &[u8],
    ) -> Result<InferenceChallenge> {
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
        let expected = compute_vote_commit(verdict, salt, challenge_id, voter);
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
        vote.verdict = Some(verdict);
        vote.salt = Some(hex::encode(salt));
        vote.revealed_at = Some(now_secs());
        let updated = entry.clone();
        drop(entry);
        self.persist(&updated)?;
        Ok(updated)
    }

    /// Idempotently finalize a challenge by tallying revealed votes by
    /// committee stake weight.
    ///
    /// - A verdict clears when its revealed stake exceeds the 2f+1 threshold.
    ///   "Did not verify" stake upholds; "verified" stake dismisses.
    /// - If neither side clears the threshold and `force` is set (commit/reveal
    ///   windows have elapsed), the challenge is **dismissed** — the burden is
    ///   on the challenger's committee to reach an upheld quorum.
    /// - Replaying finalize on an already-terminal challenge returns the same
    ///   verdict (idempotent). It never overwrites a decided challenge.
    pub fn finalize(&self, challenge_id: &str, force: bool) -> Result<InferenceChallenge> {
        let mut entry = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| NodeError::Other(format!("unknown challenge {challenge_id}")))?;
        // Idempotent: a decided challenge returns its verdict unchanged.
        if entry.status.is_terminal() {
            return Ok(entry.clone());
        }
        let threshold = entry.quorum_threshold();
        let mut uphold_stake: u128 = 0;
        let mut dismiss_stake: u128 = 0;
        for vote in &entry.votes {
            let Some(verdict) = vote.verdict else {
                continue;
            };
            let Some(seat) = entry.seat_for(&vote.voter) else {
                continue;
            };
            if verdict {
                uphold_stake += seat.stake;
            } else {
                dismiss_stake += seat.stake;
            }
        }

        let decision = if uphold_stake >= threshold {
            Some(ChallengeStatus::Upheld)
        } else if dismiss_stake >= threshold {
            Some(ChallengeStatus::Dismissed)
        } else if force {
            // Windows elapsed with no upheld quorum — the provider prevails.
            Some(ChallengeStatus::Dismissed)
        } else {
            None
        };

        let Some(status) = decision else {
            return Err(NodeError::Other(format!(
                "challenge {challenge_id} has no quorum yet \
                 (uphold={uphold_stake}, dismiss={dismiss_stake}, threshold={threshold}); \
                 pass force after the reveal window"
            )));
        };

        entry.status = status;
        entry.resolved_at = Some(now_secs());
        entry.verification = Some(serde_json::json!({
            "uphold_stake": uphold_stake.to_string(),
            "dismiss_stake": dismiss_stake.to_string(),
            "quorum_threshold": threshold.to_string(),
            "total_committee_stake": entry.total_committee_stake.to_string(),
            "votes_committed": entry.commit_count(),
            "forced": force && uphold_stake < threshold && dismiss_stake < threshold,
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

    /// A 3-seat committee with equal stake — quorum threshold is 2 of 3.
    fn committee_3() -> Vec<CommitteeSeat> {
        vec![
            CommitteeSeat {
                voter: "0xv0".into(),
                stake: 100,
            },
            CommitteeSeat {
                voter: "0xv1".into(),
                stake: 100,
            },
            CommitteeSeat {
                voter: "0xv2".into(),
                stake: 100,
            },
        ]
    }

    fn filed_challenge(m: &ChallengeManager) -> InferenceChallenge {
        let c = sample_commitment();
        let hash = m
            .store_commitment("test-model", "0xabc", &c)
            .expect("store");
        m.file(&hash, "0xdef", "suspect output", entropy(1), committee_3())
            .expect("file")
    }

    #[test]
    fn commitment_roundtrip() {
        let m = manager();
        let c = sample_commitment();
        let hash = m
            .store_commitment("test-model", "0xabc", &c)
            .expect("store");
        assert_eq!(hash, c.hash_hex());
        let fetched = m.get_commitment(&hash).expect("get").expect("present");
        assert_eq!(fetched.commitment.hash_hex(), hash);
        assert_eq!(fetched.model_id, "test-model");
        assert_eq!(fetched.provider, "0xabc");
    }

    #[test]
    fn file_requires_stored_commitment() {
        let m = manager();
        let err = m
            .file(
                "deadbeef",
                "0xdef",
                "suspect output",
                entropy(1),
                committee_3(),
            )
            .expect_err("must reject unknown hash");
        assert!(err.to_string().contains("no stored commitment"));
    }

    #[test]
    fn file_requires_nonempty_committee() {
        let m = manager();
        let c = sample_commitment();
        let hash = m
            .store_commitment("test-model", "0xabc", &c)
            .expect("store");
        let err = m
            .file(&hash, "0xdef", "suspect", entropy(1), Vec::new())
            .expect_err("must reject empty committee");
        assert!(err.to_string().contains("empty committee"));
    }

    #[test]
    fn commit_reveal_uphold_lifecycle() {
        let m = manager();
        let ch = filed_challenge(&m);
        assert_eq!(ch.status, ChallengeStatus::VotingCommit);

        // Two of three commit "did not verify" (verdict = true).
        let salt0 = b"salt-zero";
        let salt1 = b"salt-one";
        let c0 = compute_vote_commit(true, salt0, &ch.challenge_id, "0xv0");
        let c1 = compute_vote_commit(true, salt1, &ch.challenge_id, "0xv1");
        m.commit_vote(&ch.challenge_id, "0xv0", &c0)
            .expect("commit v0");
        let after = m
            .commit_vote(&ch.challenge_id, "0xv1", &c1)
            .expect("commit v1");
        // Committed stake 200 >= threshold ((300/3)*2+1 = 201)? 200 < 201, so
        // still commit phase; a third commit crosses it.
        assert_eq!(after.status, ChallengeStatus::VotingCommit);
        let salt2 = b"salt-two";
        let c2 = compute_vote_commit(true, salt2, &ch.challenge_id, "0xv2");
        let after = m
            .commit_vote(&ch.challenge_id, "0xv2", &c2)
            .expect("commit v2");
        assert_eq!(after.status, ChallengeStatus::VotingReveal);

        // Non-committee voter is rejected.
        assert!(m.commit_vote(&ch.challenge_id, "0xstranger", &c0).is_err());

        // Reveals must match commits.
        assert!(
            m.reveal_vote(&ch.challenge_id, "0xv0", false, salt0)
                .is_err()
        );
        m.reveal_vote(&ch.challenge_id, "0xv0", true, salt0)
            .expect("reveal v0");
        m.reveal_vote(&ch.challenge_id, "0xv1", true, salt1)
            .expect("reveal v1");

        // 200 revealed-uphold stake >= 201? No — needs the third reveal.
        assert!(m.finalize(&ch.challenge_id, false).is_err());
        m.reveal_vote(&ch.challenge_id, "0xv2", true, salt2)
            .expect("reveal v2");
        let done = m.finalize(&ch.challenge_id, false).expect("finalize");
        assert_eq!(done.status, ChallengeStatus::Upheld);
        assert!(done.resolved_at.is_some());
    }

    #[test]
    fn finalize_is_idempotent() {
        let m = manager();
        let ch = filed_challenge(&m);
        for (i, voter) in ["0xv0", "0xv1", "0xv2"].iter().enumerate() {
            let salt = format!("salt-{i}");
            let c = compute_vote_commit(true, salt.as_bytes(), &ch.challenge_id, voter);
            m.commit_vote(&ch.challenge_id, voter, &c).expect("commit");
            m.reveal_vote(&ch.challenge_id, voter, true, salt.as_bytes())
                .expect("reveal");
        }
        let first = m.finalize(&ch.challenge_id, false).expect("finalize");
        assert_eq!(first.status, ChallengeStatus::Upheld);
        // Replaying finalize returns the same verdict, never overwrites.
        let again = m.finalize(&ch.challenge_id, true).expect("idempotent");
        assert_eq!(again.status, ChallengeStatus::Upheld);
        assert_eq!(again.resolved_at, first.resolved_at);
    }

    #[test]
    fn forced_finalize_without_quorum_dismisses() {
        let m = manager();
        let ch = filed_challenge(&m);
        // Only one voter commits + reveals uphold — below the 201 threshold.
        let salt = b"lonely";
        let c = compute_vote_commit(true, salt, &ch.challenge_id, "0xv0");
        m.commit_vote(&ch.challenge_id, "0xv0", &c).expect("commit");
        m.reveal_vote(&ch.challenge_id, "0xv0", true, salt)
            .expect("reveal");
        // Without force, no quorum → error.
        assert!(m.finalize(&ch.challenge_id, false).is_err());
        // With force (windows elapsed), the provider prevails.
        let done = m.finalize(&ch.challenge_id, true).expect("forced");
        assert_eq!(done.status, ChallengeStatus::Dismissed);
    }

    #[test]
    fn select_committee_is_stake_filtered_and_deterministic() {
        let candidates = vec![
            ("0xv0".to_string(), 100u128),
            ("0xv1".to_string(), 0u128), // zero stake — excluded
            ("0xv2".to_string(), 50u128),
            ("0xv3".to_string(), 200u128),
        ];
        let a = select_challenge_committee("chal-1", entropy(9), &candidates, 3);
        let b = select_challenge_committee("chal-1", entropy(9), &candidates, 3);
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.voter, y.voter);
            assert_eq!(x.stake, y.stake);
        }
        // The zero-stake candidate never appears.
        assert!(a.iter().all(|s| s.voter != "0xv1"));
        // Stakes are carried through from the candidate list.
        for seat in &a {
            let expected = candidates.iter().find(|(v, _)| *v == seat.voter).unwrap().1;
            assert_eq!(seat.stake, expected);
        }
    }

    #[test]
    fn hydrate_restores_challenges() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let hash;
        let id;
        {
            let m = ChallengeManager::new(storage.clone()).expect("manager");
            let ch = filed_challenge(&m);
            hash = ch.commitment_hash.clone();
            id = ch.challenge_id;
        }
        let m2 = ChallengeManager::new(storage).expect("rehydrated manager");
        let restored = m2.get(&id).expect("hydrated challenge");
        assert_eq!(restored.commitment_hash, hash);
        assert_eq!(restored.status, ChallengeStatus::VotingCommit);
        assert_eq!(restored.committee.len(), 3);
        assert!(m2.get_commitment(&hash).expect("get").is_some());
    }

    #[test]
    fn status_parse_roundtrip() {
        assert_eq!(
            ChallengeStatus::parse("voting_commit"),
            Some(ChallengeStatus::VotingCommit)
        );
        assert_eq!(
            ChallengeStatus::parse("voting_reveal"),
            Some(ChallengeStatus::VotingReveal)
        );
        assert_eq!(
            ChallengeStatus::parse("upheld"),
            Some(ChallengeStatus::Upheld)
        );
        assert_eq!(
            ChallengeStatus::parse("dismissed"),
            Some(ChallengeStatus::Dismissed)
        );
        assert_eq!(ChallengeStatus::parse("bogus"), None);
    }
}
