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
//! The challenge lifecycle is deliberately small:
//!
//! 1. A caller files a challenge against a commitment hash
//!    (`tenzro_fileInferenceChallenge`).
//! 2. Anyone holding the weights runs `tenzro_verifyInferenceCommitment`
//!    with the original prompt to produce a
//!    [`tenzro_model::toploc::VerificationOutcome`].
//! 3. An operator resolves the challenge (`tenzro_resolveInferenceChallenge`,
//!    admin-token-gated). An upheld challenge feeds the existing provider
//!    penalty paths — reputation decrement on `ProviderManager` and
//!    `ComputeBondManager::record_failure` — rather than introducing a new
//!    slashing mechanism.
//!
//! Persistence: RocksDB `CF_CHALLENGES`. Commitments under
//! `commitment/<hash_hex>` (bincode), challenges under
//! `challenge/<challenge_id>` (JSON). Challenges hydrate on construction;
//! commitments are read on demand since blobs can be large
//! (k × step_count × 8 bytes).

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_model::toploc::InferenceCommitment;
use tenzro_storage::{KvStore, CF_CHALLENGES};

use crate::error::{NodeError, Result};

const COMMITMENT_PREFIX: &str = "commitment/";
const CHALLENGE_PREFIX: &str = "challenge/";

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

/// Where a filed challenge stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    /// Filed, awaiting resolution.
    Filed,
    /// Resolved against the provider — the commitment did not verify.
    Upheld,
    /// Resolved in the provider's favor — the commitment verified or the
    /// challenge was malformed.
    Dismissed,
}

impl ChallengeStatus {
    /// Parse the snake_case wire form used by the RPC surface.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "filed" => Some(Self::Filed),
            "upheld" => Some(Self::Upheld),
            "dismissed" => Some(Self::Dismissed),
            _ => None,
        }
    }
}

/// A dispute over one inference commitment.
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
    /// Unix seconds.
    pub filed_at: u64,
    /// Unix seconds, set at resolution.
    pub resolved_at: Option<u64>,
    /// `VerificationOutcome` JSON recorded at resolution when the resolver
    /// ran a local re-execution.
    pub verification: Option<serde_json::Value>,
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
    pub fn file(
        &self,
        commitment_hash: &str,
        challenger: &str,
        reason: &str,
    ) -> Result<InferenceChallenge> {
        let stored = self.get_commitment(commitment_hash)?.ok_or_else(|| {
            NodeError::Other(format!(
                "no stored commitment with hash {commitment_hash}"
            ))
        })?;
        let challenge = InferenceChallenge {
            challenge_id: uuid::Uuid::new_v4().to_string(),
            commitment_hash: commitment_hash.to_string(),
            model_id: stored.model_id,
            provider: stored.provider,
            challenger: challenger.to_string(),
            reason: reason.to_string(),
            status: ChallengeStatus::Filed,
            filed_at: now_secs(),
            resolved_at: None,
            verification: None,
        };
        self.persist(&challenge)?;
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(challenge)
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
        out.sort_by(|a, b| b.filed_at.cmp(&a.filed_at));
        out
    }

    /// Resolve a filed challenge. `upheld = true` means the commitment did
    /// not verify and the provider penalty paths should fire (the RPC
    /// handler owns that wiring — reputation + compute-bond failure).
    pub fn resolve(
        &self,
        challenge_id: &str,
        upheld: bool,
        verification: Option<serde_json::Value>,
    ) -> Result<InferenceChallenge> {
        let mut entry = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| NodeError::Other(format!("unknown challenge {challenge_id}")))?;
        if entry.status != ChallengeStatus::Filed {
            return Err(NodeError::Other(format!(
                "challenge {challenge_id} already resolved ({:?})",
                entry.status
            )));
        }
        entry.status = if upheld {
            ChallengeStatus::Upheld
        } else {
            ChallengeStatus::Dismissed
        };
        entry.resolved_at = Some(now_secs());
        entry.verification = verification;
        let resolved = entry.clone();
        drop(entry);
        self.persist(&resolved)?;
        Ok(resolved)
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
                    TopKEntry { token_id: 42, logit: 1.5 },
                    TopKEntry { token_id: 7, logit: 0.5 },
                ],
            }],
        }
    }

    fn manager() -> Arc<ChallengeManager> {
        ChallengeManager::new(Arc::new(MemoryStore::new())).expect("manager")
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
            .file("deadbeef", "0xdef", "suspect output")
            .expect_err("must reject unknown hash");
        assert!(err.to_string().contains("no stored commitment"));
    }

    #[test]
    fn file_resolve_lifecycle() {
        let m = manager();
        let c = sample_commitment();
        let hash = m
            .store_commitment("test-model", "0xabc", &c)
            .expect("store");
        let ch = m.file(&hash, "0xdef", "suspect output").expect("file");
        assert_eq!(ch.status, ChallengeStatus::Filed);
        assert_eq!(ch.model_id, "test-model");
        assert_eq!(ch.provider, "0xabc");
        assert_eq!(m.list(Some(ChallengeStatus::Filed), None).len(), 1);
        assert_eq!(m.list(None, Some("0xabc")).len(), 1);
        assert_eq!(m.list(None, Some("0xother")).len(), 0);

        let resolved = m
            .resolve(&ch.challenge_id, true, Some(serde_json::json!({"verified": false})))
            .expect("resolve");
        assert_eq!(resolved.status, ChallengeStatus::Upheld);
        assert!(resolved.resolved_at.is_some());

        // Double-resolution is rejected.
        assert!(m.resolve(&ch.challenge_id, false, None).is_err());
    }

    #[test]
    fn hydrate_restores_challenges() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let hash;
        let id;
        {
            let m = ChallengeManager::new(storage.clone()).expect("manager");
            let c = sample_commitment();
            hash = m
                .store_commitment("test-model", "0xabc", &c)
                .expect("store");
            id = m
                .file(&hash, "0xdef", "suspect output")
                .expect("file")
                .challenge_id;
        }
        let m2 = ChallengeManager::new(storage).expect("rehydrated manager");
        let restored = m2.get(&id).expect("hydrated challenge");
        assert_eq!(restored.commitment_hash, hash);
        assert_eq!(restored.status, ChallengeStatus::Filed);
        assert!(m2.get_commitment(&hash).expect("get").is_some());
    }

    #[test]
    fn status_parse_roundtrip() {
        assert_eq!(ChallengeStatus::parse("filed"), Some(ChallengeStatus::Filed));
        assert_eq!(ChallengeStatus::parse("upheld"), Some(ChallengeStatus::Upheld));
        assert_eq!(
            ChallengeStatus::parse("dismissed"),
            Some(ChallengeStatus::Dismissed)
        );
        assert_eq!(ChallengeStatus::parse("bogus"), None);
    }
}
