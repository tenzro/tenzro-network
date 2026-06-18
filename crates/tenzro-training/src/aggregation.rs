//! Byzantine-robust aggregation rules over outer gradients.
//!
//! Aggregation operates over already-decoded `ndarray::ArrayView1<f32>` views
//! of safetensors-decoded payloads — **no tensor library lives in this crate**
//! (per the architectural decision in `AI.md` §7.7.1).
//!
//! Phase 1 ships only [`MeanAggregator`]. The remaining rules light up in
//! Phase 2 once Byzantine defense is required (Verified/Confidential tiers).

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
            .aggregate(&[g0.view(), g1.view(), g2.view(), g3.view(), g4.view(), g5.view()])
            .expect("krum ok");
        // Picked gradient must be within the honest cluster.
        assert!(out[0].abs() < 1.0 && out[1].abs() < 1.0);
    }
}
