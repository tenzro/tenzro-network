//! TOPLOC-style inference commitments.
//!
//! During generation the provider records, for every output token, the
//! top-k raw logits (token id + value) that produced the sample. The
//! canonical serialization of those records is the commitment blob; its
//! SHA-256 is the commitment hash that rides on inference results and
//! receipts.
//!
//! A verifier holding the prompt, the output tokens, and the same model
//! weights re-executes the whole sequence as a single prefill — roughly
//! two orders of magnitude cheaper than the original decode — reads the
//! logits at each output position, and fuzzy-compares them against the
//! committed records. Exact float equality is not required: kernels
//! differ across GPUs, drivers, and batch shapes, so verification
//! tolerates bounded index churn and bounded logit drift per step, and
//! requires a minimum fraction of steps to pass overall.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain tag prefixed to the canonical commitment encoding.
const COMMITMENT_DOMAIN_TAG: &[u8] = b"tenzro/inference/toploc";

/// Default number of logits committed per generated token.
pub const DEFAULT_COMMITMENT_K: u8 = 16;

/// Maximum accepted `commitment_k` — bounds blob size per token.
pub const MAX_COMMITMENT_K: u8 = 64;

/// Minimum fraction of committed top-k token ids that must reappear in
/// the recomputed top-k for a step to pass.
pub const MIN_INDEX_OVERLAP: f32 = 0.75;

/// Maximum mean absolute logit difference over the shared token ids for
/// a step to pass.
pub const MAX_MEAN_LOGIT_DELTA: f32 = 0.25;

/// Minimum fraction of steps that must pass for the commitment as a
/// whole to verify.
pub const MIN_PASSING_STEP_FRACTION: f32 = 0.9;

/// One committed logit: token id and raw (pre-sampler) logit value.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TopKEntry {
    pub token_id: u32,
    pub logit: f32,
}

/// Commitment record for one generated token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepRecord {
    /// The token the provider actually sampled at this step.
    pub token_id: u32,
    /// Top-k raw logits at this step, sorted by logit descending
    /// (ties broken by ascending token id).
    pub top_k: Vec<TopKEntry>,
}

/// Full commitment blob for one inference call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceCommitment {
    /// Number of logits committed per step.
    pub k: u8,
    /// Prompt length in tokens (BOS included), fixing the positions a
    /// verifier must read logits from: step `j` maps to sequence index
    /// `prompt_tokens - 1 + j`.
    pub prompt_tokens: u32,
    /// One record per generated token, in generation order.
    pub steps: Vec<StepRecord>,
}

impl InferenceCommitment {
    /// Deterministic byte encoding hashed into the commitment.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            COMMITMENT_DOMAIN_TAG.len() + 9 + self.steps.len() * (5 + self.k as usize * 8),
        );
        out.extend_from_slice(COMMITMENT_DOMAIN_TAG);
        out.push(self.k);
        out.extend_from_slice(&self.prompt_tokens.to_le_bytes());
        out.extend_from_slice(&(self.steps.len() as u32).to_le_bytes());
        for step in &self.steps {
            out.extend_from_slice(&step.token_id.to_le_bytes());
            out.push(step.top_k.len() as u8);
            for entry in &step.top_k {
                out.extend_from_slice(&entry.token_id.to_le_bytes());
                out.extend_from_slice(&entry.logit.to_le_bytes());
            }
        }
        out
    }

    /// SHA-256 of the canonical encoding.
    pub fn commitment_hash(&self) -> [u8; 32] {
        let digest = Sha256::digest(self.canonical_bytes());
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        hash
    }

    /// Hex form of [`commitment_hash`](Self::commitment_hash).
    pub fn hash_hex(&self) -> String {
        hex::encode(self.commitment_hash())
    }

    /// The generated token ids, in order — what a verifier feeds back
    /// through the model after the prompt.
    pub fn output_token_ids(&self) -> Vec<u32> {
        self.steps.iter().map(|s| s.token_id).collect()
    }
}

/// Per-step comparison between a committed record and recomputed logits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepComparison {
    /// Fraction of committed token ids present in the recomputed top-k.
    pub index_overlap: f32,
    /// Mean absolute logit difference over the shared token ids.
    pub mean_logit_delta: f32,
    pub pass: bool,
}

/// Outcome of verifying a full commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationOutcome {
    pub steps_total: usize,
    pub steps_passed: usize,
    /// Indices of failing steps (capped at 32 for reporting).
    pub failing_steps: Vec<usize>,
    pub pass: bool,
}

/// Select the top-k logits from a full logit row, sorted by logit
/// descending with ties broken by ascending token id — deterministic
/// regardless of the input's memory order.
pub fn top_k_from_logits(logits: &[f32], k: usize) -> Vec<TopKEntry> {
    let k = k.min(logits.len());
    if k == 0 {
        return Vec::new();
    }
    let mut indexed: Vec<(u32, f32)> = logits
        .iter()
        .enumerate()
        .map(|(i, &v)| (i as u32, v))
        .collect();
    let cmp = |a: &(u32, f32), b: &(u32, f32)| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0));
    if k < indexed.len() {
        indexed.select_nth_unstable_by(k - 1, cmp);
        indexed.truncate(k);
    }
    indexed.sort_unstable_by(cmp);
    indexed
        .into_iter()
        .map(|(token_id, logit)| TopKEntry { token_id, logit })
        .collect()
}

/// Compare one committed step against the recomputed top-k at the same
/// position.
pub fn compare_step(committed: &StepRecord, recomputed: &[TopKEntry]) -> StepComparison {
    if committed.top_k.is_empty() {
        return StepComparison {
            index_overlap: 0.0,
            mean_logit_delta: f32::INFINITY,
            pass: false,
        };
    }
    let mut shared = 0usize;
    let mut delta_sum = 0f64;
    for entry in &committed.top_k {
        if let Some(rec) = recomputed.iter().find(|r| r.token_id == entry.token_id) {
            shared += 1;
            delta_sum += (entry.logit - rec.logit).abs() as f64;
        }
    }
    let index_overlap = shared as f32 / committed.top_k.len() as f32;
    let mean_logit_delta = if shared > 0 {
        (delta_sum / shared as f64) as f32
    } else {
        f32::INFINITY
    };
    let pass = index_overlap >= MIN_INDEX_OVERLAP && mean_logit_delta <= MAX_MEAN_LOGIT_DELTA;
    StepComparison {
        index_overlap,
        mean_logit_delta,
        pass,
    }
}

/// Verify a full commitment against recomputed top-k rows, one per
/// step. A length mismatch fails outright — the verifier could not
/// reproduce the committed sequence shape.
pub fn verify_commitment(
    committed: &InferenceCommitment,
    recomputed: &[Vec<TopKEntry>],
) -> VerificationOutcome {
    if committed.steps.is_empty() || committed.steps.len() != recomputed.len() {
        return VerificationOutcome {
            steps_total: committed.steps.len(),
            steps_passed: 0,
            failing_steps: Vec::new(),
            pass: false,
        };
    }
    let mut steps_passed = 0usize;
    let mut failing_steps = Vec::new();
    for (i, (step, rec)) in committed.steps.iter().zip(recomputed.iter()).enumerate() {
        if compare_step(step, rec).pass {
            steps_passed += 1;
        } else if failing_steps.len() < 32 {
            failing_steps.push(i);
        }
    }
    let fraction = steps_passed as f32 / committed.steps.len() as f32;
    VerificationOutcome {
        steps_total: committed.steps.len(),
        steps_passed,
        failing_steps,
        pass: fraction >= MIN_PASSING_STEP_FRACTION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(token_id: u32, logit: f32) -> TopKEntry {
        TopKEntry { token_id, logit }
    }

    fn commitment_with(steps: Vec<StepRecord>) -> InferenceCommitment {
        InferenceCommitment {
            k: 4,
            prompt_tokens: 8,
            steps,
        }
    }

    #[test]
    fn top_k_selects_and_orders_deterministically() {
        let logits = vec![0.1, 5.0, 3.0, 5.0, -1.0, 4.0];
        let top = top_k_from_logits(&logits, 4);
        // Tie between ids 1 and 3 at 5.0 breaks toward the lower id.
        assert_eq!(
            top.iter().map(|e| e.token_id).collect::<Vec<_>>(),
            vec![1, 3, 5, 2]
        );
    }

    #[test]
    fn top_k_handles_short_rows() {
        let logits = vec![2.0, 1.0];
        let top = top_k_from_logits(&logits, 16);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].token_id, 0);
    }

    #[test]
    fn canonical_hash_is_stable_and_sensitive() {
        let c1 = commitment_with(vec![StepRecord {
            token_id: 42,
            top_k: vec![entry(42, 9.5), entry(7, 8.0)],
        }]);
        let c2 = c1.clone();
        assert_eq!(c1.hash_hex(), c2.hash_hex());

        let mut c3 = c1.clone();
        c3.steps[0].top_k[1].logit = 8.0001;
        assert_ne!(c1.hash_hex(), c3.hash_hex());

        let mut c4 = c1.clone();
        c4.prompt_tokens = 9;
        assert_ne!(c1.hash_hex(), c4.hash_hex());
    }

    #[test]
    fn identical_step_passes() {
        let step = StepRecord {
            token_id: 5,
            top_k: vec![entry(5, 10.0), entry(9, 9.0), entry(2, 8.5), entry(1, 7.0)],
        };
        let cmp = compare_step(&step, &step.top_k);
        assert!(cmp.pass);
        assert_eq!(cmp.index_overlap, 1.0);
        assert_eq!(cmp.mean_logit_delta, 0.0);
    }

    #[test]
    fn small_drift_within_tolerance_passes() {
        let step = StepRecord {
            token_id: 5,
            top_k: vec![entry(5, 10.0), entry(9, 9.0), entry(2, 8.5), entry(1, 7.0)],
        };
        // One index swapped out (3/4 = 0.75 overlap) + 0.1 logit drift.
        let recomputed = vec![entry(5, 10.1), entry(9, 8.9), entry(2, 8.6), entry(77, 7.1)];
        let cmp = compare_step(&step, &recomputed);
        assert!(
            cmp.pass,
            "overlap {} delta {}",
            cmp.index_overlap, cmp.mean_logit_delta
        );
    }

    #[test]
    fn large_logit_drift_fails() {
        let step = StepRecord {
            token_id: 5,
            top_k: vec![entry(5, 10.0), entry(9, 9.0)],
        };
        let recomputed = vec![entry(5, 12.0), entry(9, 6.0)];
        assert!(!compare_step(&step, &recomputed).pass);
    }

    #[test]
    fn disjoint_indices_fail() {
        let step = StepRecord {
            token_id: 5,
            top_k: vec![entry(5, 10.0), entry(9, 9.0)],
        };
        let recomputed = vec![entry(1, 10.0), entry(2, 9.0)];
        let cmp = compare_step(&step, &recomputed);
        assert!(!cmp.pass);
        assert_eq!(cmp.index_overlap, 0.0);
    }

    #[test]
    fn verify_requires_passing_fraction() {
        let good = StepRecord {
            token_id: 1,
            top_k: vec![entry(1, 5.0), entry(2, 4.0)],
        };
        let bad = StepRecord {
            token_id: 3,
            top_k: vec![entry(3, 5.0), entry(4, 4.0)],
        };
        // 10 steps: 9 exact matches + 1 disjoint recompute = 0.9 passes.
        let mut steps = vec![good.clone(); 9];
        steps.push(bad.clone());
        let committed = commitment_with(steps);
        let mut recomputed: Vec<Vec<TopKEntry>> = vec![good.top_k.clone(); 9];
        recomputed.push(vec![entry(100, 5.0), entry(101, 4.0)]);
        let outcome = verify_commitment(&committed, &recomputed);
        assert!(outcome.pass);
        assert_eq!(outcome.steps_passed, 9);
        assert_eq!(outcome.failing_steps, vec![9]);

        // 10 steps: 8 passes = 0.8 fails.
        let mut steps = vec![good.clone(); 8];
        steps.push(bad.clone());
        steps.push(bad.clone());
        let committed = commitment_with(steps);
        let mut recomputed: Vec<Vec<TopKEntry>> = vec![good.top_k.clone(); 8];
        recomputed.push(vec![entry(100, 5.0)]);
        recomputed.push(vec![entry(100, 5.0)]);
        assert!(!verify_commitment(&committed, &recomputed).pass);
    }

    #[test]
    fn verify_fails_on_length_mismatch() {
        let step = StepRecord {
            token_id: 1,
            top_k: vec![entry(1, 5.0)],
        };
        let committed = commitment_with(vec![step.clone(), step.clone()]);
        let recomputed = vec![step.top_k.clone()];
        assert!(!verify_commitment(&committed, &recomputed).pass);
    }

    #[test]
    fn empty_commitment_fails() {
        let committed = commitment_with(Vec::new());
        assert!(!verify_commitment(&committed, &[]).pass);
    }
}
