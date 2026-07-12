//! TOPLOC-class activation-commitment verification for Open-tier training.
//!
//! The Open tier has no TEE attestation; trust comes from stake bonding plus
//! this commitment scheme. Every Open-tier [`OuterGradient`] carries an
//! [`ActivationCommitment`]: the per-inner-step loss trajectory and the top-k
//! probes (largest-magnitude coordinates) of the flattened fragment delta.
//! The commitment hash is bound into the gradient's Ed25519 signature via
//! [`outer_gradient_signing_bytes`](crate::commitments::outer_gradient_signing_bytes),
//! so a trainer cannot swap the commitment after signing.
//!
//! Two verification layers:
//!
//! 1. **Structural, accept-time** — [`validate_activation_commitment`] runs
//!    fail-closed inside
//!    [`accept_outer_gradient`](crate::runtime::SyncerState::accept_outer_gradient)
//!    for Open-tier submissions: `k` in bounds, exactly `k` probes,
//!    trajectory length equal to the task spec's `inner_steps`, all values
//!    finite, probes ordered by descending `|value|` (ties by ascending
//!    index) with unique indices. A violation is slashable — it requires the
//!    submitter to deviate from the task spec they enrolled under.
//! 2. **Fuzzy, challenge-time** — a challenger re-executes the trainer's
//!    inner loop from the same checkpoint and shard, rebuilds the commitment
//!    with [`top_k_delta_probes`], and compares via
//!    [`verify_activation_commitment`]. Floating-point nondeterminism across
//!    GPU architectures, kernel schedules, and reduction orders is expected,
//!    so the comparison is tolerance-based (like the inference-side TOPLOC
//!    verifier in `tenzro-model`): bounded relative loss drift, bounded probe
//!    index churn, bounded relative probe-value drift. A fabricated gradient
//!    — one not produced by running the announced steps on the announced
//!    shard — lands far outside these bands. A failed challenge evicts and
//!    slashes via
//!    [`challenge_activation_commitment`](crate::runtime::SyncerState::challenge_activation_commitment).

use serde::{Deserialize, Serialize};
use tenzro_types::training::{ActivationCommitment, DeltaProbe, MAX_PROBE_K};

use crate::error::{Result, TrainingError};

/// Minimum fraction of probe indices that must appear in both the claimed
/// and the recomputed top-k sets. Looser than the inference-side TOPLOC
/// bound (0.75): after H inner optimizer steps, accumulated nondeterminism
/// reorders near-tied delta coordinates more than a single prefill reorders
/// top-k logits.
pub const MIN_PROBE_INDEX_OVERLAP: f64 = 0.5;

/// Maximum mean relative drift across probe values at shared indices.
pub const MAX_MEAN_PROBE_REL_DELTA: f64 = 0.25;

/// Maximum mean relative drift across the per-step loss trajectories.
/// Honest re-execution reproduces losses to well under a percent even across
/// hardware; 5% leaves room for nondeterministic kernels while rejecting a
/// trajectory that was not produced by the announced steps on the announced
/// shard.
pub const MAX_MEAN_LOSS_REL_DELTA: f64 = 0.05;

/// Guard against division blow-up on near-zero reference values in relative
/// deltas.
const REL_DELTA_EPSILON: f64 = 1e-8;

/// Select the top-k probes from a flattened fragment delta: the `k`
/// largest-magnitude coordinates, ordered by descending `|value|` with ties
/// broken by ascending index. Deterministic for a given input. Used by the
/// challenger to rebuild the commitment from a re-executed delta; the Python
/// trainer implements the identical selection over
/// `flatten_fragment_values` output.
///
/// Non-finite values sort last so a delta containing NaN/Inf never
/// contributes probes (the structural validator rejects non-finite probe
/// values anyway).
pub fn top_k_delta_probes(delta: &[f32], k: u8) -> Vec<DeltaProbe> {
    let k = usize::from(k).min(delta.len());
    if k == 0 {
        return Vec::new();
    }
    let mut indexed: Vec<(u64, f32)> = delta
        .iter()
        .enumerate()
        .map(|(i, &v)| (i as u64, v))
        .collect();
    let cmp = |a: &(u64, f32), b: &(u64, f32)| {
        let ma = if a.1.is_finite() { a.1.abs() } else { f32::NEG_INFINITY };
        let mb = if b.1.is_finite() { b.1.abs() } else { f32::NEG_INFINITY };
        mb.total_cmp(&ma).then_with(|| a.0.cmp(&b.0))
    };
    if k < indexed.len() {
        indexed.select_nth_unstable_by(k - 1, cmp);
        indexed.truncate(k);
    }
    indexed.sort_unstable_by(cmp);
    indexed
        .into_iter()
        .map(|(index, value)| DeltaProbe { index, value })
        .collect()
}

/// Structural validation of a claimed [`ActivationCommitment`], run
/// fail-closed at the accept seam for Open-tier submissions.
///
/// `expected_steps` is the task spec's `inner_steps` — the per-round inner
/// loop length every enrolled trainer committed to.
pub fn validate_activation_commitment(
    commitment: &ActivationCommitment,
    expected_steps: u32,
) -> Result<()> {
    if commitment.k == 0 || commitment.k > MAX_PROBE_K {
        return Err(TrainingError::CommitmentInvalid {
            what: "k out of bounds (1..=MAX_PROBE_K)",
        });
    }
    if commitment.probes.len() != usize::from(commitment.k) {
        return Err(TrainingError::CommitmentInvalid {
            what: "probe count does not equal k",
        });
    }
    if commitment.loss_trajectory.len() != expected_steps as usize {
        return Err(TrainingError::CommitmentInvalid {
            what: "loss trajectory length does not equal task spec inner_steps",
        });
    }
    if commitment.loss_trajectory.iter().any(|l| !l.is_finite()) {
        return Err(TrainingError::CommitmentInvalid {
            what: "non-finite loss in trajectory",
        });
    }
    if commitment.probes.iter().any(|p| !p.value.is_finite()) {
        return Err(TrainingError::CommitmentInvalid {
            what: "non-finite probe value",
        });
    }
    for pair in commitment.probes.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        let ord = b
            .value
            .abs()
            .total_cmp(&a.value.abs())
            .then_with(|| a.index.cmp(&b.index));
        if ord != std::cmp::Ordering::Less {
            return Err(TrainingError::CommitmentInvalid {
                what: "probes not ordered by descending |value| with ascending-index ties",
            });
        }
        if a.index == b.index {
            return Err(TrainingError::CommitmentInvalid {
                what: "duplicate probe index",
            });
        }
    }
    Ok(())
}

/// Outcome of a fuzzy challenge-time comparison between a claimed commitment
/// and one recomputed by re-executing the inner loop.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActivationVerification {
    /// Whether trajectory lengths and `k` matched (a mismatch fails
    /// outright — both sides ran the same task spec).
    pub shape_match: bool,
    /// Mean relative per-step loss drift.
    pub mean_loss_rel_delta: f64,
    /// Fraction of claimed probe indices present in the recomputed top-k.
    pub probe_index_overlap: f64,
    /// Mean relative probe-value drift at shared indices.
    pub mean_probe_rel_delta: f64,
    /// Whether every band was satisfied.
    pub passed: bool,
}

fn mean_rel_delta(pairs: impl Iterator<Item = (f64, f64)>) -> (f64, usize) {
    let mut sum = 0.0f64;
    let mut n = 0usize;
    for (a, b) in pairs {
        let denom = a.abs().max(b.abs()).max(REL_DELTA_EPSILON);
        sum += (a - b).abs() / denom;
        n += 1;
    }
    (if n == 0 { 0.0 } else { sum / n as f64 }, n)
}

/// Fuzzy-compare a claimed [`ActivationCommitment`] against one recomputed
/// by re-executing the trainer's inner loop from the same checkpoint and
/// shard. Tolerances per module docs; a shape mismatch (trajectory length or
/// `k`) fails outright.
pub fn verify_activation_commitment(
    claimed: &ActivationCommitment,
    recomputed: &ActivationCommitment,
) -> ActivationVerification {
    let shape_match = claimed.k == recomputed.k
        && claimed.loss_trajectory.len() == recomputed.loss_trajectory.len()
        && !claimed.probes.is_empty()
        && !recomputed.probes.is_empty();
    if !shape_match {
        return ActivationVerification {
            shape_match,
            mean_loss_rel_delta: f64::INFINITY,
            probe_index_overlap: 0.0,
            mean_probe_rel_delta: f64::INFINITY,
            passed: false,
        };
    }

    let (mean_loss_rel_delta, _) = mean_rel_delta(
        claimed
            .loss_trajectory
            .iter()
            .zip(&recomputed.loss_trajectory)
            .map(|(&a, &b)| (f64::from(a), f64::from(b))),
    );

    let shared: Vec<(f64, f64)> = claimed
        .probes
        .iter()
        .filter_map(|cp| {
            recomputed
                .probes
                .iter()
                .find(|rp| rp.index == cp.index)
                .map(|rp| (f64::from(cp.value), f64::from(rp.value)))
        })
        .collect();
    let probe_index_overlap = shared.len() as f64 / claimed.probes.len() as f64;
    let (mean_probe_rel_delta, shared_count) = mean_rel_delta(shared.into_iter());
    // No shared indices at all: value drift is unmeasurable and the overlap
    // band already fails the verification.
    let mean_probe_rel_delta = if shared_count == 0 {
        f64::INFINITY
    } else {
        mean_probe_rel_delta
    };

    let passed = mean_loss_rel_delta <= MAX_MEAN_LOSS_REL_DELTA
        && probe_index_overlap >= MIN_PROBE_INDEX_OVERLAP
        && mean_probe_rel_delta <= MAX_MEAN_PROBE_REL_DELTA;

    ActivationVerification {
        shape_match,
        mean_loss_rel_delta,
        probe_index_overlap,
        mean_probe_rel_delta,
        passed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitment(losses: Vec<f32>, probes: Vec<DeltaProbe>) -> ActivationCommitment {
        ActivationCommitment {
            k: probes.len() as u8,
            loss_trajectory: losses,
            probes,
        }
    }

    fn probe(index: u64, value: f32) -> DeltaProbe {
        DeltaProbe { index, value }
    }

    // -- top_k_delta_probes ------------------------------------------------

    #[test]
    fn top_k_selects_largest_magnitude_descending() {
        let delta = [0.1f32, -3.0, 0.5, 2.0, -0.2];
        let probes = top_k_delta_probes(&delta, 3);
        assert_eq!(
            probes,
            vec![probe(1, -3.0), probe(3, 2.0), probe(2, 0.5)]
        );
    }

    #[test]
    fn top_k_breaks_magnitude_ties_by_ascending_index() {
        let delta = [1.0f32, -1.0, 1.0];
        let probes = top_k_delta_probes(&delta, 2);
        assert_eq!(probes, vec![probe(0, 1.0), probe(1, -1.0)]);
    }

    #[test]
    fn top_k_is_deterministic() {
        let delta: Vec<f32> = (0..1000).map(|i| ((i * 37) % 101) as f32 - 50.0).collect();
        assert_eq!(top_k_delta_probes(&delta, 16), top_k_delta_probes(&delta, 16));
    }

    #[test]
    fn top_k_clamps_to_delta_length() {
        let delta = [1.0f32, 2.0];
        assert_eq!(top_k_delta_probes(&delta, 16).len(), 2);
        assert!(top_k_delta_probes(&[], 16).is_empty());
    }

    #[test]
    fn top_k_pushes_non_finite_last() {
        let delta = [f32::NAN, 5.0, f32::INFINITY, 1.0];
        // NaN sorts last; +Inf is non-finite and also sorts last.
        let probes = top_k_delta_probes(&delta, 2);
        assert_eq!(probes, vec![probe(1, 5.0), probe(3, 1.0)]);
    }

    // -- validate_activation_commitment -------------------------------------

    fn valid_commitment() -> ActivationCommitment {
        commitment(
            vec![2.5, 2.1, 1.9, 1.8],
            vec![probe(7, -4.0), probe(2, 3.5), probe(9, -1.0)],
        )
    }

    #[test]
    fn structural_valid_passes() {
        assert!(validate_activation_commitment(&valid_commitment(), 4).is_ok());
    }

    #[test]
    fn structural_rejects_k_zero_and_over_max() {
        let mut c = valid_commitment();
        c.k = 0;
        assert!(validate_activation_commitment(&c, 4).is_err());
        let mut c = valid_commitment();
        c.k = MAX_PROBE_K + 1;
        assert!(validate_activation_commitment(&c, 4).is_err());
    }

    #[test]
    fn structural_rejects_probe_count_mismatch() {
        let mut c = valid_commitment();
        c.k = 2;
        assert!(matches!(
            validate_activation_commitment(&c, 4),
            Err(TrainingError::CommitmentInvalid { .. })
        ));
    }

    #[test]
    fn structural_rejects_trajectory_length_mismatch() {
        assert!(validate_activation_commitment(&valid_commitment(), 5).is_err());
    }

    #[test]
    fn structural_rejects_non_finite_values() {
        let mut c = valid_commitment();
        c.loss_trajectory[1] = f32::NAN;
        assert!(validate_activation_commitment(&c, 4).is_err());
        let mut c = valid_commitment();
        c.probes[0].value = f32::INFINITY;
        assert!(validate_activation_commitment(&c, 4).is_err());
    }

    #[test]
    fn structural_rejects_unsorted_probes() {
        let c = commitment(
            vec![1.0; 4],
            vec![probe(2, 3.5), probe(7, -4.0), probe(9, -1.0)],
        );
        assert!(validate_activation_commitment(&c, 4).is_err());
    }

    #[test]
    fn structural_rejects_duplicate_probe_index() {
        // Equal |value| with equal index — duplicate.
        let c = commitment(vec![1.0; 4], vec![probe(7, -4.0), probe(7, 4.0)]);
        assert!(validate_activation_commitment(&c, 4).is_err());
    }

    #[test]
    fn structural_rejects_tie_break_violation() {
        // Equal |value| but descending index order.
        let c = commitment(vec![1.0; 4], vec![probe(9, 4.0), probe(7, -4.0)]);
        assert!(validate_activation_commitment(&c, 4).is_err());
    }

    // -- verify_activation_commitment ---------------------------------------

    #[test]
    fn identical_commitments_verify() {
        let c = valid_commitment();
        let outcome = verify_activation_commitment(&c, &c);
        assert!(outcome.passed);
        assert_eq!(outcome.probe_index_overlap, 1.0);
        assert_eq!(outcome.mean_loss_rel_delta, 0.0);
    }

    #[test]
    fn small_drift_within_bands_passes() {
        let claimed = valid_commitment();
        let recomputed = commitment(
            vec![2.51, 2.09, 1.91, 1.79],
            vec![probe(7, -4.05), probe(2, 3.45), probe(9, -0.98)],
        );
        assert!(verify_activation_commitment(&claimed, &recomputed).passed);
    }

    #[test]
    fn fabricated_loss_trajectory_fails() {
        let claimed = valid_commitment();
        let recomputed = commitment(
            vec![9.0, 8.5, 8.2, 8.0],
            claimed.probes.clone(),
        );
        let outcome = verify_activation_commitment(&claimed, &recomputed);
        assert!(!outcome.passed);
        assert!(outcome.mean_loss_rel_delta > MAX_MEAN_LOSS_REL_DELTA);
    }

    #[test]
    fn disjoint_probe_indices_fail() {
        let claimed = valid_commitment();
        let recomputed = commitment(
            claimed.loss_trajectory.clone(),
            vec![probe(100, -4.0), probe(200, 3.5), probe(300, -1.0)],
        );
        let outcome = verify_activation_commitment(&claimed, &recomputed);
        assert!(!outcome.passed);
        assert_eq!(outcome.probe_index_overlap, 0.0);
        assert!(outcome.mean_probe_rel_delta.is_infinite());
    }

    #[test]
    fn probe_value_drift_beyond_band_fails() {
        let claimed = valid_commitment();
        let recomputed = commitment(
            claimed.loss_trajectory.clone(),
            vec![probe(7, -8.0), probe(2, 7.0), probe(9, -2.0)],
        );
        let outcome = verify_activation_commitment(&claimed, &recomputed);
        assert!(!outcome.passed);
        assert!(outcome.mean_probe_rel_delta > MAX_MEAN_PROBE_REL_DELTA);
    }

    #[test]
    fn overlap_exactly_at_floor_passes() {
        // 2 of 4 claimed indices shared = 0.5 == MIN_PROBE_INDEX_OVERLAP.
        let claimed = commitment(
            vec![1.0; 4],
            vec![probe(1, 8.0), probe(2, 7.0), probe(3, 6.0), probe(4, 5.0)],
        );
        let recomputed = commitment(
            vec![1.0; 4],
            vec![probe(1, 8.0), probe(2, 7.0), probe(30, 6.0), probe(40, 5.0)],
        );
        let outcome = verify_activation_commitment(&claimed, &recomputed);
        assert_eq!(outcome.probe_index_overlap, 0.5);
        assert!(outcome.passed);
    }

    #[test]
    fn shape_mismatch_fails_outright() {
        let claimed = valid_commitment();
        let mut recomputed = valid_commitment();
        recomputed.loss_trajectory.push(1.7);
        let outcome = verify_activation_commitment(&claimed, &recomputed);
        assert!(!outcome.shape_match);
        assert!(!outcome.passed);
    }

    // -- canonical bytes / hash ---------------------------------------------

    #[test]
    fn commitment_hash_is_deterministic_and_sensitive() {
        let a = valid_commitment();
        let b = valid_commitment();
        assert_eq!(a.commitment_hash(), b.commitment_hash());
        let mut c = valid_commitment();
        c.loss_trajectory[0] += 0.001;
        assert_ne!(a.commitment_hash(), c.commitment_hash());
        let mut d = valid_commitment();
        d.probes[0].index += 1;
        assert_ne!(a.commitment_hash(), d.commitment_hash());
    }
}
