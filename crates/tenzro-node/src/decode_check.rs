//! Checking that the tokens a provider emitted follow from its own logits.
//!
//! A commitment records, for every generated token, the token emitted and
//! the top-k logits the provider computed at that step. Re-executing the
//! prompt (`verify_inference_commitment`) establishes that those logits are
//! the model's logits. This module establishes the other half: that each
//! emitted token is the token the declared sampler picks from those logits,
//! so a provider cannot run the real model for the commitment and emit
//! tokens from somewhere else — a cheaper model, a cached answer, an edit.
//!
//! The check is architecture-agnostic: it reads only logits and the sampling
//! parameters the provider signed into its receipt.
//!
//! * **Greedy** (`temperature == 0`): the emitted token must be the top
//!   logit, within a tolerance for the run-to-run drift of batched kernels.
//! * **Keyed sampling** (`temperature > 0`, receipt declares
//!   `keyed_sampler`): the sampler adds keyed Gumbel noise
//!   `g = -ln(-ln(u))`, `u = PRF(seed, step, token)` ([`keyed_uniform`]) to
//!   `logit / temperature` over the candidates `top_k` / `top_p` / `min_p`
//!   admit, and takes the argmax. Anyone holding the seed recomputes the same
//!   noise, so the emitted token is fixed by the logits and the seed; within
//!   the drift tolerance it must win.
//! * Sampling with any other generator is not checkable from logits, and is
//!   reported as such rather than passed.

use serde::Serialize;
use sha2::{Digest, Sha256};
use tenzro_model::toploc::{InferenceCommitment, StepRecord};

use crate::inference_receipt::SamplingParams;

/// Domain tag for the keyed sampler's noise.
const KEYED_SAMPLER_TAG: &[u8] = b"tenzro/keyed-sampler";

/// Logit drift tolerated between the provider's run and the verifier's, in
/// the units the sampler compares (logit divided by temperature).
pub const DRIFT_TOLERANCE: f64 = 0.05;

/// Fraction of steps that may fail before the decode is judged inconsistent.
/// Nonzero because a verifier's recomputation and the provider's run can
/// disagree on a near-tie beyond [`DRIFT_TOLERANCE`].
pub const MAX_FAILING_FRACTION: f64 = 0.02;

/// A uniform in `(0, 1)` keyed by the request seed, the step and the token.
pub fn keyed_uniform(seed: u64, step: u32, token: u32) -> f64 {
    let mut h = Sha256::new();
    h.update(KEYED_SAMPLER_TAG);
    h.update(seed.to_le_bytes());
    h.update(step.to_le_bytes());
    h.update(token.to_le_bytes());
    let d = h.finalize();
    let mut top = [0u8; 8];
    top.copy_from_slice(&d[..8]);
    ((u64::from_be_bytes(top) >> 11) as f64 + 0.5) / (1u64 << 53) as f64
}

/// The Gumbel noise the keyed sampler adds for `token` at `step`.
pub fn keyed_gumbel(seed: u64, step: u32, token: u32) -> f64 {
    -(-keyed_uniform(seed, step, token).ln()).ln()
}

/// Candidates the sampling filters admit from one committed row, as
/// `(token, logit)`, highest logit first.
fn admitted(step: &StepRecord, sampling: &SamplingParams) -> Vec<(u32, f64)> {
    let mut row: Vec<(u32, f64)> = step
        .top_k
        .iter()
        .map(|e| (e.token_id, e.logit as f64))
        .collect();
    row.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    if let Some(k) = sampling.top_k.filter(|k| *k > 0) {
        row.truncate(k as usize);
    }
    let t = sampling.temperature.max(f64::MIN_POSITIVE);
    let max = row.first().map(|r| r.1).unwrap_or(0.0);
    let weights: Vec<f64> = row.iter().map(|(_, l)| ((l - max) / t).exp()).collect();
    let total: f64 = weights.iter().sum();
    if let Some(min_p) = sampling.min_p.filter(|p| *p > 0.0) {
        let keep = row
            .iter()
            .zip(&weights)
            .filter(|(_, w)| **w >= min_p)
            .count()
            .max(1);
        row.truncate(keep);
    }
    if sampling.top_p < 1.0 && total > 0.0 {
        let mut mass = 0.0;
        let mut keep = 0;
        for w in &weights {
            keep += 1;
            mass += w / total;
            if mass >= sampling.top_p {
                break;
            }
        }
        row.truncate(keep.max(1));
    }
    row
}

/// How one step fared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepVerdict {
    /// The emitted token is the one the sampler picks.
    Consistent,
    /// Another candidate beats the emitted token by more than the drift
    /// tolerance.
    Inconsistent,
    /// The emitted token is not among the committed candidates, so the
    /// logits cannot say whether the sampler would pick it.
    Unverifiable,
}

/// Judge one step under the sampler the receipt declares.
pub fn check_step(step_index: u32, step: &StepRecord, sampling: &SamplingParams) -> StepVerdict {
    let greedy = sampling.temperature <= 0.0;
    let candidates = if greedy {
        let mut row: Vec<(u32, f64)> = step
            .top_k
            .iter()
            .map(|e| (e.token_id, e.logit as f64))
            .collect();
        row.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        row
    } else {
        admitted(step, sampling)
    };
    let score = |(token, logit): (u32, f64)| {
        if greedy {
            logit
        } else {
            logit / sampling.temperature + keyed_gumbel(sampling.seed, step_index, token)
        }
    };
    let Some(emitted) = candidates.iter().find(|(t, _)| *t == step.token_id) else {
        return StepVerdict::Unverifiable;
    };
    let emitted_score = score(*emitted);
    let best = candidates
        .iter()
        .map(|c| score(*c))
        .fold(f64::NEG_INFINITY, f64::max);
    if best - emitted_score <= DRIFT_TOLERANCE {
        StepVerdict::Consistent
    } else {
        StepVerdict::Inconsistent
    }
}

/// The result of checking a whole decode.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DecodeCheck {
    /// `greedy`, `keyed`, or `unsupported`.
    pub mode: &'static str,
    pub steps: usize,
    pub consistent: usize,
    pub inconsistent: usize,
    pub unverifiable: usize,
    /// First inconsistent step, for a verifier to inspect.
    pub first_inconsistent: Option<usize>,
    /// Whether the decode follows from the committed logits. `None` when the
    /// sampler cannot be checked from logits at all.
    pub pass: Option<bool>,
}

/// Check every step of `commitment` against the sampling the provider signed.
pub fn check_decode(commitment: &InferenceCommitment, sampling: &SamplingParams) -> DecodeCheck {
    let mode = if sampling.temperature <= 0.0 {
        "greedy"
    } else if sampling.keyed_sampler {
        "keyed"
    } else {
        "unsupported"
    };
    let mut out = DecodeCheck {
        mode,
        steps: commitment.steps.len(),
        consistent: 0,
        inconsistent: 0,
        unverifiable: 0,
        first_inconsistent: None,
        pass: None,
    };
    if mode == "unsupported" {
        return out;
    }
    for (i, step) in commitment.steps.iter().enumerate() {
        match check_step(i as u32, step, sampling) {
            StepVerdict::Consistent => out.consistent += 1,
            StepVerdict::Unverifiable => out.unverifiable += 1,
            StepVerdict::Inconsistent => {
                out.inconsistent += 1;
                out.first_inconsistent.get_or_insert(i);
            }
        }
    }
    let judged = (out.consistent + out.inconsistent).max(1) as f64;
    out.pass = Some(out.inconsistent as f64 / judged <= MAX_FAILING_FRACTION);
    out
}

/// Check a stored commitment's decode against the receipt its provider
/// signed. The receipt must come from `provider_did` (the machine the
/// commitment is stored under), be signed by `registered` (the key registered
/// for that DID) and name this commitment, so the
/// sampling parameters checked are the ones the provider committed to.
pub fn check_receipted_decode(
    receipt: &crate::inference_receipt::InferenceReceipt,
    provider_did: &str,
    registered: &tenzro_crypto::composite::CompositePublicKey,
    commitment: &InferenceCommitment,
) -> Result<DecodeCheck, String> {
    if receipt.machine_did != provider_did {
        return Err("the receipt names another machine than the commitment's provider".to_string());
    }
    receipt
        .verify_signature(registered)
        .map_err(|e| e.to_string())?;
    if receipt.commitment_hash.as_deref() != Some(commitment.hash_hex().as_str()) {
        return Err("the receipt names a different commitment".to_string());
    }
    Ok(check_decode(commitment, &receipt.sampling))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_model::toploc::TopKEntry;

    fn sampling(temperature: f64, keyed: bool) -> SamplingParams {
        SamplingParams {
            seed: 1234,
            temperature,
            top_p: 1.0,
            top_k: None,
            min_p: None,
            max_output_tokens: 64,
            keyed_sampler: keyed,
        }
    }

    /// A reference "model": deterministic logits for a step over 16 tokens.
    fn logits(step: u32, model: u64) -> Vec<(u32, f32)> {
        (0..16u32)
            .map(|t| {
                let mut h = Sha256::new();
                h.update(model.to_le_bytes());
                h.update(step.to_le_bytes());
                h.update(t.to_le_bytes());
                let d = h.finalize();
                (t, (d[0] as f32) / 32.0)
            })
            .collect()
    }

    /// What an honest provider running the keyed sampler emits.
    fn honest(model: u64, s: &SamplingParams, steps: u32, emit_from: u64) -> InferenceCommitment {
        let steps = (0..steps)
            .map(|i| {
                let committed = logits(i, model);
                let chooser = logits(i, emit_from);
                let token = chooser
                    .iter()
                    .map(|(t, l)| {
                        let score = if s.temperature <= 0.0 {
                            *l as f64
                        } else {
                            *l as f64 / s.temperature + keyed_gumbel(s.seed, i, *t)
                        };
                        (*t, score)
                    })
                    .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
                    .unwrap()
                    .0;
                StepRecord {
                    token_id: token,
                    top_k: committed
                        .into_iter()
                        .map(|(token_id, logit)| TopKEntry { token_id, logit })
                        .collect(),
                }
            })
            .collect();
        InferenceCommitment {
            k: 16,
            prompt_tokens: 4,
            steps,
        }
    }

    #[test]
    fn an_honest_greedy_decode_passes() {
        let s = sampling(0.0, false);
        let c = honest(1, &s, 64, 1);
        let r = check_decode(&c, &s);
        assert_eq!(r.pass, Some(true), "{r:?}");
        assert_eq!(r.consistent, 64);
    }

    #[test]
    fn an_honest_keyed_decode_passes_and_tolerates_drift() {
        let s = sampling(0.8, true);
        let mut c = honest(1, &s, 64, 1);
        // Batched kernels move logits slightly between runs.
        for step in &mut c.steps {
            for e in &mut step.top_k {
                e.logit += 0.01;
            }
        }
        assert_eq!(check_decode(&c, &s).pass, Some(true));
    }

    #[test]
    fn tokens_from_another_model_fail_the_check() {
        // The commitment carries the real model's logits, but the tokens
        // were chosen by a different model.
        for s in [sampling(0.0, false), sampling(0.8, true)] {
            let c = honest(1, &s, 64, 2);
            let r = check_decode(&c, &s);
            assert_eq!(r.pass, Some(false), "{r:?}");
            assert!(r.first_inconsistent.is_some());
        }
    }

    #[test]
    fn a_different_seed_is_detected_under_keyed_sampling() {
        let s = sampling(0.8, true);
        let c = honest(1, &s, 64, 1);
        let mut wrong_seed = s.clone();
        wrong_seed.seed = 999;
        assert_eq!(check_decode(&c, &wrong_seed).pass, Some(false));
    }

    #[test]
    fn a_single_substituted_token_is_found() {
        let s = sampling(0.0, false);
        let mut c = honest(1, &s, 8, 1);
        let best = c.steps[3].token_id;
        c.steps[3].token_id = c.steps[3]
            .top_k
            .iter()
            .map(|e| e.token_id)
            .find(|t| *t != best)
            .unwrap();
        let r = check_decode(&c, &s);
        assert_eq!(r.first_inconsistent, Some(3));
        assert_eq!(r.pass, Some(false));
    }

    #[test]
    fn an_uncheckable_sampler_is_reported_not_passed() {
        let s = sampling(0.8, false);
        let r = check_decode(&honest(1, &sampling(0.8, true), 8, 1), &s);
        assert_eq!(r.mode, "unsupported");
        assert_eq!(r.pass, None);
    }

    #[test]
    fn a_token_outside_the_committed_candidates_is_unverifiable() {
        let s = sampling(0.0, false);
        let mut c = honest(1, &s, 4, 1);
        c.steps[0].token_id = 9_999;
        assert_eq!(check_step(0, &c.steps[0], &s), StepVerdict::Unverifiable);
    }
}
