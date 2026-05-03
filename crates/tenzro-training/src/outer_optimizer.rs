//! Outer optimizer for Decoupled DiLoCo — Nesterov-momentum SGD applied by
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
    /// Outer learning rate η. DiLoCo paper default: 0.7.
    pub lr: f32,
    /// Nesterov momentum coefficient μ. DiLoCo paper default: 0.9.
    pub momentum: f32,
}

impl Default for NesterovSgdConfig {
    fn default() -> Self {
        Self {
            lr: 0.7,
            momentum: 0.9,
        }
    }
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
    /// Update rule (matches DiLoCo paper):
    ///   v ← μ · v + ∇
    ///   θ ← θ − η · (μ · v + ∇)
    ///
    /// `params` is updated in-place. `outer_grad` is the aggregated outer
    /// gradient produced by the [`Aggregator`](crate::aggregation::Aggregator).
    pub fn step(&mut self, mut params: ArrayViewMut1<'_, f32>, outer_grad: ArrayView1<'_, f32>) {
        debug_assert_eq!(params.len(), outer_grad.len());
        debug_assert_eq!(self.velocity.len(), outer_grad.len());

        let mu = self.config.momentum;
        let lr = self.config.lr;

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
}
