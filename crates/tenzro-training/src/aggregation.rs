//! Byzantine-robust aggregation rules over outer gradients.
//!
//! Aggregation operates over already-decoded `ndarray::ArrayView1<f32>` views
//! of safetensors-decoded payloads — **no tensor library lives in this crate**
//! (per the architectural decision in `AI.md` §7.7.1).
//!
//! Phase 1 ships only [`MeanAggregator`]. The remaining rules light up in
//! Phase 2 once Byzantine defense is required (Verified/Confidential tiers).
//!
//! ## Sparse contributions
//!
//! Sparse outer gradients are transmitted as chunked top-k payloads
//! ([`crate::sparse`]), but they are decoded to a **dense, zero-filled**
//! `Vec<f32>` of the full fragment length by [`crate::sparse::sparse_decode`]
//! before they reach an [`Aggregator`]. A coordinate that a peer did not
//! transmit decodes to `0.0`, so the union-of-transmitted-indices semantics
//! fall out of the dense path for free: [`MeanAggregator`] sums over all
//! peers (absent coordinate = 0 contribution), and
//! [`TrimmedMeanAggregator`] / [`CoordinateMedianAggregator`] / [`KrumAggregator`]
//! operate per-coordinate over the same densified views. No separate sparse
//! aggregator is required — the tier admission gate
//! ([`crate::runtime::validate_aggregation_for_tier`]) is unchanged.

use crate::error::{Result, TrainingError};
use ndarray::{Array1, ArrayView1};
use tenzro_types::training::AggregationRule;

/// Trait implemented by every aggregation rule.
///
/// `gradients` is a slice of flattened parameter-fragment views. All views
/// MUST have identical length; the trait returns a fresh `Array1<f32>` of
/// the same length holding the aggregated outer gradient.
pub trait Aggregator: Send + Sync {
    fn aggregate(&self, gradients: &[ArrayView1<'_, f32>]) -> Result<Array1<f32>>;

    fn rule(&self) -> AggregationRule;
}

/// Build the aggregator for a given rule.
pub fn aggregator_for(rule: AggregationRule) -> Box<dyn Aggregator> {
    match rule {
        AggregationRule::Mean => Box::new(MeanAggregator),
        AggregationRule::TrimmedMean { alpha_bps } => Box::new(TrimmedMeanAggregator { alpha_bps }),
        AggregationRule::CoordinateMedian => Box::new(CoordinateMedianAggregator),
        AggregationRule::Krum { f } => Box::new(KrumAggregator { f }),
        // Alternating LoRA: each round only one low-rank factor is
        // live, so the fragment tensors that arrive are a single factor across
        // contributors and per-coordinate mean is the correct aggregation. The
        // "alternating" logic — which of A/B is frozen this round — lives in
        // the Python trainer (it names only the active factor's tensors in the
        // round's delta state-dict); the syncer just means what it receives.
        AggregationRule::LoraAlternating => Box::new(MeanAggregator),
    }
}

fn check_uniform(gradients: &[ArrayView1<'_, f32>]) -> Result<usize> {
    if gradients.is_empty() {
        return Err(TrainingError::Aggregation(
            "no gradients to aggregate".into(),
        ));
    }
    let len = gradients[0].len();
    for (i, g) in gradients.iter().enumerate().skip(1) {
        if g.len() != len {
            return Err(TrainingError::DimensionMismatch(format!(
                "gradient {} has length {}, expected {}",
                i,
                g.len(),
                len
            )));
        }
    }
    Ok(len)
}

// ---------------------------------------------------------------------------
// Norm clipping
// ---------------------------------------------------------------------------

/// L2 norm of a flattened gradient view.
pub fn l2_norm(grad: ArrayView1<'_, f32>) -> f32 {
    grad.iter().map(|v| v * v).sum::<f32>().sqrt()
}

/// Clip a single gradient to an L2-norm cap.
///
/// Returns the (possibly rescaled) gradient plus a flag that is `true` when the
/// input exceeded `cap` and was scaled down. A gradient whose norm is at or
/// below `cap` is returned unchanged with `false`. A non-finite or non-positive
/// `cap` is treated as "no clipping". A zero-norm gradient passes through
/// unchanged (nothing to scale).
pub fn clip_to_l2_norm(grad: ArrayView1<'_, f32>, cap: f32) -> (Array1<f32>, bool) {
    if !cap.is_finite() || cap <= 0.0 {
        return (grad.to_owned(), false);
    }
    let norm = l2_norm(grad);
    if norm <= cap || norm == 0.0 {
        (grad.to_owned(), false)
    } else {
        let scale = cap / norm;
        (grad.mapv(|v| v * scale), true)
    }
}

/// Clip every gradient in a batch to the same L2-norm cap.
///
/// Returns the owned, clipped gradients alongside a parallel `was_clipped` flag
/// vector (same order as the input). The flags are the per-contributor signal
/// consumed by the slashing path: an honest trainer that honored the same cap
/// in its Python outer step never gets clipped at the syncer, so a `true` flag
/// marks a contribution that exceeded the round's norm budget.
pub fn clip_gradients(
    gradients: &[ArrayView1<'_, f32>],
    cap: f32,
) -> (Vec<Array1<f32>>, Vec<bool>) {
    let mut clipped = Vec::with_capacity(gradients.len());
    let mut flags = Vec::with_capacity(gradients.len());
    for g in gradients {
        let (c, was) = clip_to_l2_norm(*g, cap);
        clipped.push(c);
        flags.push(was);
    }
    (clipped, flags)
}

// ---------------------------------------------------------------------------
// Mean
// ---------------------------------------------------------------------------

/// Plain coordinate-wise mean. Phase 1 default. NOT Byzantine-robust.
pub struct MeanAggregator;

impl Aggregator for MeanAggregator {
    fn aggregate(&self, gradients: &[ArrayView1<'_, f32>]) -> Result<Array1<f32>> {
        let len = check_uniform(gradients)?;
        let n = gradients.len() as f32;
        let mut out = Array1::<f32>::zeros(len);
        for g in gradients {
            for (i, v) in g.iter().enumerate() {
                out[i] += *v;
            }
        }
        out.mapv_inplace(|x| x / n);
        Ok(out)
    }

    fn rule(&self) -> AggregationRule {
        AggregationRule::Mean
    }
}

// ---------------------------------------------------------------------------
// TrimmedMean
// ---------------------------------------------------------------------------

/// Coordinate-wise α-trimmed mean. Trims the top and bottom `alpha_bps / 10000`
/// of values per coordinate before averaging.
///
/// Phase 2 — implementation present so Phase 2 lights up without a crate
/// rebuild, but not used in Phase 1 (Mean only).
pub struct TrimmedMeanAggregator {
    pub alpha_bps: u16,
}

impl Aggregator for TrimmedMeanAggregator {
    fn aggregate(&self, gradients: &[ArrayView1<'_, f32>]) -> Result<Array1<f32>> {
        let len = check_uniform(gradients)?;
        let m = gradients.len();
        let alpha = (self.alpha_bps as f32) / 10000.0;
        // Clamp trim: at most ⌊(m-1)/2⌋ from each side (always keep ≥1).
        let trim = ((alpha * m as f32) as usize).min((m.saturating_sub(1)) / 2);
        let kept = m.saturating_sub(2 * trim);
        if kept == 0 {
            return Err(TrainingError::Aggregation(
                "trimmed-mean trim leaves zero gradients".into(),
            ));
        }
        let mut out = Array1::<f32>::zeros(len);
        let mut col = vec![0f32; m];
        for i in 0..len {
            for (j, g) in gradients.iter().enumerate() {
                col[j] = g[i];
            }
            col.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let slice = &col[trim..m - trim];
            let mean: f32 = slice.iter().sum::<f32>() / kept as f32;
            out[i] = mean;
        }
        Ok(out)
    }

    fn rule(&self) -> AggregationRule {
        AggregationRule::TrimmedMean {
            alpha_bps: self.alpha_bps,
        }
    }
}

// ---------------------------------------------------------------------------
// CoordinateMedian
// ---------------------------------------------------------------------------

/// Coordinate-wise median — robust against up to f < M/2 Byzantine learners.
pub struct CoordinateMedianAggregator;

impl Aggregator for CoordinateMedianAggregator {
    fn aggregate(&self, gradients: &[ArrayView1<'_, f32>]) -> Result<Array1<f32>> {
        let len = check_uniform(gradients)?;
        let m = gradients.len();
        let mut out = Array1::<f32>::zeros(len);
        let mut col = vec![0f32; m];
        for i in 0..len {
            for (j, g) in gradients.iter().enumerate() {
                col[j] = g[i];
            }
            col.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let mid = m / 2;
            out[i] = if m.is_multiple_of(2) {
                (col[mid - 1] + col[mid]) / 2.0
            } else {
                col[mid]
            };
        }
        Ok(out)
    }

    fn rule(&self) -> AggregationRule {
        AggregationRule::CoordinateMedian
    }
}

// ---------------------------------------------------------------------------
// Krum
// ---------------------------------------------------------------------------

/// Krum aggregator — pick the gradient with smallest sum-of-squared-distances
/// to its `m - f - 2` nearest neighbors, return that gradient verbatim.
///
/// f is the assumed Byzantine learner count.
pub struct KrumAggregator {
    pub f: u32,
}

impl Aggregator for KrumAggregator {
    fn aggregate(&self, gradients: &[ArrayView1<'_, f32>]) -> Result<Array1<f32>> {
        let _len = check_uniform(gradients)?;
        let m = gradients.len();
        let f = self.f as usize;
        if m <= 2 * f + 2 {
            return Err(TrainingError::Aggregation(format!(
                "Krum requires M > 2f+2: have M={}, f={}",
                m, f
            )));
        }
        let nn_count = m - f - 2;
        // Pairwise squared distances.
        let mut dist = vec![vec![0f32; m]; m];
        for i in 0..m {
            for j in (i + 1)..m {
                let mut d = 0f32;
                for (a, b) in gradients[i].iter().zip(gradients[j].iter()) {
                    let diff = a - b;
                    d += diff * diff;
                }
                dist[i][j] = d;
                dist[j][i] = d;
            }
        }
        // Score: sum of distances to nn_count nearest neighbors.
        let mut best_idx = 0usize;
        let mut best_score = f32::INFINITY;
        for (i, dist_row) in dist.iter().enumerate().take(m) {
            let mut row: Vec<f32> = (0..m).filter(|&j| j != i).map(|j| dist_row[j]).collect();
            row.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let score: f32 = row.iter().take(nn_count).sum();
            if score < best_score {
                best_score = score;
                best_idx = i;
            }
        }
        Ok(gradients[best_idx].to_owned())
    }

    fn rule(&self) -> AggregationRule {
        AggregationRule::Krum { f: self.f }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::arr1;

    #[test]
    fn mean_three_gradients() {
        let a = arr1(&[1.0_f32, 2.0, 3.0]);
        let b = arr1(&[4.0_f32, 5.0, 6.0]);
        let c = arr1(&[7.0_f32, 8.0, 9.0]);
        let agg = MeanAggregator;
        let out = agg
            .aggregate(&[a.view(), b.view(), c.view()])
            .expect("mean ok");
        assert_eq!(out.as_slice().unwrap(), &[4.0, 5.0, 6.0]);
    }

    #[test]
    fn lora_alternating_means_single_factor() {
        // Under alternating LoRA the syncer receives one low-rank factor per
        // round across contributors; the rule is a plain per-coordinate mean.
        let a = arr1(&[2.0_f32, 4.0]);
        let b = arr1(&[4.0_f32, 8.0]);
        let agg = aggregator_for(AggregationRule::LoraAlternating);
        assert_eq!(agg.rule(), AggregationRule::Mean);
        let out = agg.aggregate(&[a.view(), b.view()]).expect("lora ok");
        assert_eq!(out.as_slice().unwrap(), &[3.0, 6.0]);
    }

    #[test]
    fn mean_rejects_empty() {
        let agg = MeanAggregator;
        assert!(agg.aggregate(&[]).is_err());
    }

    #[test]
    fn mean_rejects_dim_mismatch() {
        let a = arr1(&[1.0_f32, 2.0]);
        let b = arr1(&[1.0_f32, 2.0, 3.0]);
        let agg = MeanAggregator;
        assert!(agg.aggregate(&[a.view(), b.view()]).is_err());
    }

    #[test]
    fn coord_median_robust_to_outlier() {
        // Three "honest" 0.0s plus one "Byzantine" 1000.0 — median should be 0.
        let g0 = arr1(&[0.0_f32]);
        let g1 = arr1(&[0.0_f32]);
        let g2 = arr1(&[0.0_f32]);
        let g3 = arr1(&[1000.0_f32]);
        let agg = CoordinateMedianAggregator;
        let out = agg
            .aggregate(&[g0.view(), g1.view(), g2.view(), g3.view()])
            .expect("median ok");
        assert_eq!(out[0], 0.0);
    }

    #[test]
    fn trimmed_mean_drops_extremes() {
        // 5 values: [-100, 1, 2, 3, 100], alpha_bps=2000 (20%) trims 1 from each side.
        // Kept = [1,2,3], mean = 2.
        let g0 = arr1(&[-100.0_f32]);
        let g1 = arr1(&[1.0_f32]);
        let g2 = arr1(&[2.0_f32]);
        let g3 = arr1(&[3.0_f32]);
        let g4 = arr1(&[100.0_f32]);
        let agg = TrimmedMeanAggregator { alpha_bps: 2000 };
        let out = agg
            .aggregate(&[g0.view(), g1.view(), g2.view(), g3.view(), g4.view()])
            .expect("trimmed ok");
        assert!((out[0] - 2.0).abs() < 1e-6);
    }

    #[test]
    fn clip_passes_small_gradient_unchanged() {
        // norm = 3.0, cap = 5.0 → unchanged, flag false.
        let g = arr1(&[3.0_f32, 0.0, 0.0]);
        let (out, was) = clip_to_l2_norm(g.view(), 5.0);
        assert!(!was);
        assert_eq!(out.as_slice().unwrap(), &[3.0, 0.0, 0.0]);
    }

    #[test]
    fn clip_scales_down_large_gradient() {
        // norm = 10.0, cap = 2.0 → scaled to norm 2.0, flag true.
        let g = arr1(&[6.0_f32, 8.0]); // norm 10
        let (out, was) = clip_to_l2_norm(g.view(), 2.0);
        assert!(was);
        assert!((l2_norm(out.view()) - 2.0).abs() < 1e-5);
        // Direction preserved.
        assert!((out[0] - 1.2).abs() < 1e-5);
        assert!((out[1] - 1.6).abs() < 1e-5);
    }

    #[test]
    fn clip_disabled_for_nonpositive_cap() {
        let g = arr1(&[100.0_f32, 100.0]);
        let (out, was) = clip_to_l2_norm(g.view(), 0.0);
        assert!(!was);
        assert_eq!(out.as_slice().unwrap(), &[100.0, 100.0]);
    }

    #[test]
    fn clip_zero_norm_passes_through() {
        let g = arr1(&[0.0_f32, 0.0]);
        let (out, was) = clip_to_l2_norm(g.view(), 1.0);
        assert!(!was);
        assert_eq!(out.as_slice().unwrap(), &[0.0, 0.0]);
    }

    #[test]
    fn clip_batch_flags_only_offenders() {
        let g0 = arr1(&[1.0_f32, 0.0]); // norm 1
        let g1 = arr1(&[6.0_f32, 8.0]); // norm 10 → clipped
        let g2 = arr1(&[0.5_f32, 0.0]); // norm 0.5
        let (out, flags) = clip_gradients(&[g0.view(), g1.view(), g2.view()], 2.0);
        assert_eq!(flags, vec![false, true, false]);
        assert!((l2_norm(out[1].view()) - 2.0).abs() < 1e-5);
    }

    #[test]
    fn krum_picks_cluster_center() {
        // 5 honest gradients near [0, 0], 1 Byzantine at [100, 100]. Krum f=1
        // requires M > 2f+2 = 4 → 6 ≥ 5, OK. nn_count = 6-1-2 = 3.
        let g0 = arr1(&[0.0_f32, 0.0]);
        let g1 = arr1(&[0.1_f32, 0.0]);
        let g2 = arr1(&[0.0_f32, 0.1]);
        let g3 = arr1(&[-0.1_f32, 0.0]);
        let g4 = arr1(&[0.0_f32, -0.1]);
        let g5 = arr1(&[100.0_f32, 100.0]);
        let agg = KrumAggregator { f: 1 };
        let out = agg
            .aggregate(&[
                g0.view(),
                g1.view(),
                g2.view(),
                g3.view(),
                g4.view(),
                g5.view(),
            ])
            .expect("krum ok");
        // Picked gradient must be within the honest cluster.
        assert!(out[0].abs() < 1.0 && out[1].abs() < 1.0);
    }
}
