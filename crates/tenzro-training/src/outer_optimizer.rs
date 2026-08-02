//! Outer optimizer — Nesterov-momentum SGD applied by
//! the syncer to the aggregated outer gradient before committing the new
//! parameter-fragment state.
//!
//! Operates over `ndarray::Array1<f32>` views of safetensors-decoded
//! parameter fragments. Per the architectural decision, no tensor library
//! lives in this crate — these are plain `f32` slices.

use ndarray::{Array1, ArrayView1, ArrayViewMut1};

/// Configuration for the Nesterov-momentum outer SGD step.
#[derive(Debug, Clone, Copy)]
pub struct NesterovSgdConfig {
    /// Outer learning rate η. Default: 0.7.
    pub lr: f32,
    /// Nesterov momentum coefficient μ. Default: 0.9.
    pub momentum: f32,
    /// Optional adaptive outer-LR scaling driven by inter-trainer gradient
    /// agreement. `None` disables scaling.
    pub adaptive_lr: Option<AdaptiveLrConfig>,
}

impl Default for NesterovSgdConfig {
    fn default() -> Self {
        Self {
            lr: 0.7,
            momentum: 0.9,
            adaptive_lr: None,
        }
    }
}

/// Adaptive outer-LR scaling bounds. The effective learning rate for a round
/// is `lr * scale`, where `scale` interpolates linearly between `min_scale`
/// (zero or negative agreement) and `max_scale` (perfect agreement) based on
/// the mean cosine similarity between each trainer's outer gradient and the
/// aggregate.
///
/// Rationale: when trainer replicas
/// diverge (low agreement), a large outer step amplifies the noise; when they
/// agree, the aggregate direction is trustworthy and a full-strength step is
/// safe.
#[derive(Debug, Clone, Copy)]
pub struct AdaptiveLrConfig {
    /// Scale applied at agreement <= 0. Must be in `(0, max_scale]`.
    pub min_scale: f32,
    /// Scale applied at agreement 1.0. Typically 1.0.
    pub max_scale: f32,
}

impl Default for AdaptiveLrConfig {
    fn default() -> Self {
        Self {
            min_scale: 0.25,
            max_scale: 1.0,
        }
    }
}

impl AdaptiveLrConfig {
    /// Map an agreement score in `[-1, 1]` to an LR scale in
    /// `[min_scale, max_scale]`. Agreement <= 0 clamps to `min_scale`.
    pub fn scale_for_agreement(&self, agreement: f32) -> f32 {
        let a = agreement.clamp(0.0, 1.0);
        self.min_scale + (self.max_scale - self.min_scale) * a
    }
}

/// Mean cosine similarity between each trainer's outer gradient and the
/// aggregate. Pure: no state, no allocation beyond scalars. Returns 1.0 for
/// an empty gradient set or an all-zero aggregate (nothing to disagree with).
pub fn gradient_agreement(
    gradients: &[ArrayView1<'_, f32>],
    aggregate: ArrayView1<'_, f32>,
) -> f32 {
    if gradients.is_empty() {
        return 1.0;
    }
    let agg_norm = aggregate.iter().map(|v| v * v).sum::<f32>().sqrt();
    if agg_norm == 0.0 {
        return 1.0;
    }
    let mut total = 0.0f32;
    for grad in gradients {
        let dot: f32 = grad.iter().zip(aggregate.iter()).map(|(a, b)| a * b).sum();
        let norm = grad.iter().map(|v| v * v).sum::<f32>().sqrt();
        if norm > 0.0 {
            total += dot / (norm * agg_norm);
        }
        // Zero gradients contribute 0 agreement.
    }
    total / gradients.len() as f32
}

/// Per-fragment Nesterov SGD state. The syncer holds one of these per
/// fragment for the lifetime of a training run.
#[derive(Debug, Clone)]
pub struct NesterovSgdState {
    config: NesterovSgdConfig,
    velocity: Array1<f32>,
}

impl NesterovSgdState {
    pub fn new(fragment_len: usize, config: NesterovSgdConfig) -> Self {
        Self {
            config,
            velocity: Array1::<f32>::zeros(fragment_len),
        }
    }

    /// Apply one outer Nesterov step.
    ///
    /// Update rule:
    ///   v ← μ · v + ∇
    ///   θ ← θ − η · (μ · v + ∇)
    ///
    /// `params` is updated in-place. `outer_grad` is the aggregated outer
    /// gradient produced by the [`Aggregator`](crate::aggregation::Aggregator).
    pub fn step(&mut self, params: ArrayViewMut1<'_, f32>, outer_grad: ArrayView1<'_, f32>) {
        self.step_scaled(params, outer_grad, 1.0);
    }

    /// Apply one outer Nesterov step with the effective LR scaled by the
    /// round's gradient-agreement factor (see
    /// [`AdaptiveLrConfig::scale_for_agreement`] and [`gradient_agreement`]).
    /// When `config.adaptive_lr` is `None` the agreement is ignored.
    pub fn step_with_agreement(
        &mut self,
        params: ArrayViewMut1<'_, f32>,
        outer_grad: ArrayView1<'_, f32>,
        agreement: f32,
    ) {
        let scale = self
            .config
            .adaptive_lr
            .map(|a| a.scale_for_agreement(agreement))
            .unwrap_or(1.0);
        self.step_scaled(params, outer_grad, scale);
    }

    fn step_scaled(
        &mut self,
        mut params: ArrayViewMut1<'_, f32>,
        outer_grad: ArrayView1<'_, f32>,
        lr_scale: f32,
    ) {
        debug_assert_eq!(params.len(), outer_grad.len());
        debug_assert_eq!(self.velocity.len(), outer_grad.len());

        let mu = self.config.momentum;
        let lr = self.config.lr * lr_scale;

        // v ← μ·v + g
        for (v, g) in self.velocity.iter_mut().zip(outer_grad.iter()) {
            *v = mu * (*v) + *g;
        }

        // θ ← θ − η·(μ·v + g)
        for ((p, v), g) in params
            .iter_mut()
            .zip(self.velocity.iter())
            .zip(outer_grad.iter())
        {
            let look_ahead = mu * (*v) + *g;
            *p -= lr * look_ahead;
        }
    }

    pub fn config(&self) -> NesterovSgdConfig {
        self.config
    }

    pub fn velocity(&self) -> &Array1<f32> {
        &self.velocity
    }
}

/// Stateless outer update for sparse error-feedback runs. Under [`OuterUpdateMode::SparseEf`]
/// the momentum-equivalent state lives in the trainer-side error-feedback
/// accumulator ([`crate::sparse::ErrorFeedback`]), not in the syncer, so the
/// syncer applies the aggregated sparse update directly at the outer LR with no
/// velocity buffer.
///
/// Update rule:
///   θ ← θ − η · ḡ
///
/// where `ḡ` is the aggregated (densified, zero-filled) sparse outer gradient.
pub fn sparse_ef_step(
    mut params: ArrayViewMut1<'_, f32>,
    outer_grad: ArrayView1<'_, f32>,
    lr: f32,
) {
    debug_assert_eq!(params.len(), outer_grad.len());
    for (p, g) in params.iter_mut().zip(outer_grad.iter()) {
        *p -= lr * (*g);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::arr1;

    #[test]
    fn nesterov_step_decreases_loss() {
        // Toy: params = [1.0, 1.0], outer_grad = [1.0, 1.0]. After one step,
        // params should move toward zero.
        let mut params = arr1(&[1.0_f32, 1.0]);
        let grad = arr1(&[1.0_f32, 1.0]);
        let mut state = NesterovSgdState::new(2, NesterovSgdConfig::default());
        state.step(params.view_mut(), grad.view());
        // After one step: v = [1, 1], θ = 1 - 0.7*(0.9*1 + 1) = 1 - 1.33 = -0.33
        assert!(params[0] < 0.0);
        assert!(params[1] < 0.0);
    }

    #[test]
    fn nesterov_zero_grad_is_identity() {
        let mut params = arr1(&[3.0_f32, 4.0]);
        let grad = arr1(&[0.0_f32, 0.0]);
        let mut state = NesterovSgdState::new(2, NesterovSgdConfig::default());
        state.step(params.view_mut(), grad.view());
        assert_eq!(params[0], 3.0);
        assert_eq!(params[1], 4.0);
    }

    #[test]
    fn nesterov_velocity_accumulates() {
        let mut params = arr1(&[10.0_f32]);
        let grad = arr1(&[1.0_f32]);
        let mut state = NesterovSgdState::new(1, NesterovSgdConfig::default());
        state.step(params.view_mut(), grad.view());
        let v1 = state.velocity()[0];
        state.step(params.view_mut(), grad.view());
        let v2 = state.velocity()[0];
        // v1 = 0.9*0 + 1 = 1; v2 = 0.9*1 + 1 = 1.9
        assert!((v1 - 1.0).abs() < 1e-6);
        assert!((v2 - 1.9).abs() < 1e-6);
    }

    #[test]
    fn agreement_of_identical_gradients_is_one() {
        let g = arr1(&[1.0_f32, 2.0, 3.0]);
        let grads = [g.view(), g.view(), g.view()];
        let a = gradient_agreement(&grads, g.view());
        assert!((a - 1.0).abs() < 1e-6, "{a}");
    }

    #[test]
    fn agreement_of_opposed_gradients_is_low() {
        let g1 = arr1(&[1.0_f32, 0.0]);
        let g2 = arr1(&[-1.0_f32, 0.0]);
        let agg = arr1(&[0.5_f32, 0.0]); // pretend mean tilted toward g1
        let grads = [g1.view(), g2.view()];
        let a = gradient_agreement(&grads, agg.view());
        // cos(g1, agg) = 1, cos(g2, agg) = -1 -> mean 0
        assert!(a.abs() < 1e-6, "{a}");
    }

    #[test]
    fn agreement_empty_or_zero_aggregate_is_one() {
        let agg = arr1(&[0.0_f32, 0.0]);
        assert_eq!(gradient_agreement(&[], agg.view()), 1.0);
        let g = arr1(&[1.0_f32, 1.0]);
        assert_eq!(gradient_agreement(&[g.view()], agg.view()), 1.0);
    }

    #[test]
    fn adaptive_scale_interpolates_and_clamps() {
        let cfg = AdaptiveLrConfig {
            min_scale: 0.2,
            max_scale: 1.0,
        };
        assert!((cfg.scale_for_agreement(1.0) - 1.0).abs() < 1e-6);
        assert!((cfg.scale_for_agreement(0.0) - 0.2).abs() < 1e-6);
        assert!((cfg.scale_for_agreement(-0.5) - 0.2).abs() < 1e-6);
        assert!((cfg.scale_for_agreement(0.5) - 0.6).abs() < 1e-6);
        assert!((cfg.scale_for_agreement(2.0) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn sparse_ef_step_applies_lr_directly() {
        // No momentum buffer: θ ← θ − η·ḡ, one shot.
        let mut params = arr1(&[1.0_f32, 2.0, 3.0]);
        let grad = arr1(&[1.0_f32, 0.0, -1.0]);
        sparse_ef_step(params.view_mut(), grad.view(), 0.7);
        assert!((params[0] - 0.3).abs() < 1e-6, "{}", params[0]);
        assert!((params[1] - 2.0).abs() < 1e-6, "{}", params[1]);
        assert!((params[2] - 3.7).abs() < 1e-6, "{}", params[2]);
    }

    #[test]
    fn step_with_agreement_scales_effective_lr() {
        let cfg = NesterovSgdConfig {
            lr: 1.0,
            momentum: 0.0,
            adaptive_lr: Some(AdaptiveLrConfig {
                min_scale: 0.5,
                max_scale: 1.0,
            }),
        };
        let grad = arr1(&[1.0_f32]);

        let mut full = arr1(&[0.0_f32]);
        let mut state = NesterovSgdState::new(1, cfg);
        state.step_with_agreement(full.view_mut(), grad.view(), 1.0);
        assert!((full[0] + 1.0).abs() < 1e-6, "{}", full[0]);

        let mut damped = arr1(&[0.0_f32]);
        let mut state = NesterovSgdState::new(1, cfg);
        state.step_with_agreement(damped.view_mut(), grad.view(), 0.0);
        assert!((damped[0] + 0.5).abs() < 1e-6, "{}", damped[0]);
    }
}
