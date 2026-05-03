//! Timeseries forecasting runtime backed by ONNX Runtime.
//!
//! This module is gated behind the `onnx` cargo feature. When the feature
//! is off, a thin stub is exposed so callers can still compile and surface
//! a clean "ONNX backend not enabled" error at runtime — exactly the same
//! shape as the real implementation.
//!
//! # Scope
//!
//! Foundation timeseries models in 2026 (TimesFM 2.5, Chronos-2,
//! Granite-TTM r2, Toto-Open-Base, Moirai-MoE) have similar but not
//! identical I/O signatures. This module ships a common `ForecastModel`
//! trait plus a `GenericForecast` implementation that fits the most
//! common shape:
//!
//!   input  : `[batch=1, context_len]`           (f32 univariate history)
//!   output : `[batch=1, horizon]` or
//!            `[batch=1, horizon, n_quantiles]`  (point or quantile forecast)
//!
//! TimesFM 2.5 200M and Chronos-2 (post-quantizer-fused export) both fit
//! this shape. Patch-based models (Granite-TTM, Moirai) need their own
//! adapter — wired in follow-ups when their catalog entries land.
//!
//! # Threading
//!
//! `TimeseriesRuntime` is `Send + Sync` and holds loaded ONNX sessions
//! in a `DashMap` keyed by model_id. Sessions are thread-safe per ORT 2.x
//! contract. Forecasting calls are routed through `tokio::task::spawn_blocking`
//! since ORT inference is synchronous CPU/GPU work.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// Configuration for a forecasting request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForecastConfig {
    /// Number of future timesteps to predict.
    pub horizon: usize,
    /// Optional quantile levels in (0, 1) to return alongside the point
    /// forecast. Empty = point forecast only.
    #[serde(default)]
    pub quantiles: Vec<f32>,
    /// Frequency hint in seconds per step (e.g. 3600 = hourly). Some
    /// models (TimesFM) use this; others ignore it. `None` = unspecified.
    #[serde(default)]
    pub frequency_seconds: Option<u64>,
}

impl Default for ForecastConfig {
    fn default() -> Self {
        Self {
            horizon: 64,
            quantiles: Vec::new(),
            frequency_seconds: None,
        }
    }
}

/// Result of a forecasting call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForecastResult {
    /// Point forecast: `[horizon]` f32 values.
    pub point: Vec<f32>,
    /// Quantile forecasts: outer = quantile level, inner = horizon.
    /// Empty when no quantiles were requested or the model is point-only.
    #[serde(default)]
    pub quantiles: Vec<Vec<f32>>,
    /// Quantile levels actually emitted (mirrors `ForecastConfig.quantiles`
    /// when supported, may be empty otherwise).
    #[serde(default)]
    pub quantile_levels: Vec<f32>,
    /// Total inference wall time in milliseconds.
    pub generation_time_ms: u64,
}

/// Trait for timeseries forecast models. Implementations adapt their
/// model-specific tensor layout to the common `forecast` signature.
pub trait ForecastModel: Send + Sync {
    /// Run a forecast.
    ///
    /// `history` is the observed univariate series, oldest first. Models
    /// silently truncate or right-pad to fit their native context window.
    fn forecast(&self, history: &[f32], config: &ForecastConfig) -> Result<ForecastResult>;

    /// Native context window length. Histories longer than this are
    /// truncated to the most recent `context_length` points.
    fn context_length(&self) -> usize;

    /// Maximum supported horizon. Requests for longer horizons are
    /// rejected before inference.
    fn max_horizon(&self) -> usize;
}

#[cfg(feature = "onnx")]
mod onnx_backend {
    use super::*;
    use ndarray::Array2;
    use ort::session::{Session, builder::GraphOptimizationLevel};
    use ort::value::Tensor;
    use std::time::Instant;

    /// Generic ONNX forecast model — fits TimesFM 2.5, Chronos-2 (fused),
    /// and similar architectures with `[1, context_len] -> [1, horizon]` shape.
    ///
    /// `Session::run` requires `&mut self` in ort 2.x, so the session is
    /// wrapped in a `Mutex` to expose a `&self` API. ONNX Runtime sessions
    /// are not safe to call concurrently from multiple threads regardless,
    /// so the mutex matches the underlying contract rather than restricting it.
    pub struct GenericForecast {
        session: parking_lot::Mutex<Session>,
        context_length: usize,
        max_horizon: usize,
        input_name: String,
        output_name: String,
    }

    impl GenericForecast {
        /// Load an ONNX file and inspect its input/output names.
        pub fn from_onnx(
            path: impl AsRef<Path>,
            context_length: usize,
            max_horizon: usize,
        ) -> Result<Self> {
            let session = Session::builder()
                .map_err(|e| ModelError::InvalidModel(format!("ORT session builder: {}", e)))?
                .with_optimization_level(GraphOptimizationLevel::Level3)
                .map_err(|e| ModelError::InvalidModel(format!("ORT optimization level: {}", e)))?
                .commit_from_file(path.as_ref())
                .map_err(|e| ModelError::ProviderNotAvailable(format!("ORT load failed: {}", e)))?;

            let input_name = session
                .inputs
                .first()
                .map(|i| i.name.clone())
                .ok_or_else(|| ModelError::InvalidModel("ONNX model has no inputs".to_string()))?;
            let output_name = session
                .outputs
                .first()
                .map(|o| o.name.clone())
                .ok_or_else(|| ModelError::InvalidModel("ONNX model has no outputs".to_string()))?;

            Ok(Self {
                session: parking_lot::Mutex::new(session),
                context_length,
                max_horizon,
                input_name,
                output_name,
            })
        }

        /// Truncate or right-pad a history to exactly `context_length`.
        /// Right-padding uses the last observed value (carry-forward) so
        /// the model sees a flat tail rather than zeros, which most
        /// foundation models handle better.
        fn fit_history(&self, history: &[f32]) -> Vec<f32> {
            if history.len() >= self.context_length {
                history[history.len() - self.context_length..].to_vec()
            } else {
                let mut out = Vec::with_capacity(self.context_length);
                let pad_value = *history.first().unwrap_or(&0.0);
                let pad_len = self.context_length - history.len();
                out.extend(std::iter::repeat(pad_value).take(pad_len));
                out.extend_from_slice(history);
                out
            }
        }
    }

    impl ForecastModel for GenericForecast {
        fn forecast(
            &self,
            history: &[f32],
            config: &ForecastConfig,
        ) -> Result<ForecastResult> {
            if history.is_empty() {
                return Err(ModelError::InvalidModel("history is empty".to_string()));
            }
            if config.horizon == 0 {
                return Err(ModelError::InvalidModel("horizon must be > 0".to_string()));
            }
            if config.horizon > self.max_horizon {
                return Err(ModelError::InvalidModel(format!(
                    "horizon {} exceeds model max {}",
                    config.horizon, self.max_horizon
                )));
            }

            let start = Instant::now();
            let fitted = self.fit_history(history);
            let arr = Array2::<f32>::from_shape_vec((1, self.context_length), fitted)
                .map_err(|e| ModelError::InferenceError(format!("input shape: {}", e)))?;

            let input_tensor = Tensor::from_array(arr)
                .map_err(|e| ModelError::InferenceError(format!("ORT tensor: {}", e)))?;

            // Lock the session for the duration of run() — ORT sessions are
            // not safe to call concurrently. Extract the result into owned
            // memory before releasing the lock.
            let (dims, raw): (Vec<i64>, Vec<f32>) = {
                let mut session = self.session.lock();
                let outputs = session
                    .run(ort::inputs![self.input_name.as_str() => input_tensor])
                    .map_err(|e| ModelError::InferenceError(format!("ORT run: {}", e)))?;

                let out_value = outputs.get(self.output_name.as_str()).ok_or_else(|| {
                    ModelError::InferenceError(format!("missing output '{}'", self.output_name))
                })?;

                let (shape, data) = out_value
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("ORT extract: {}", e)))?;
                // `Shape` derefs to `&[i64]`; copy out so we can drop the lock.
                (shape.iter().copied().collect(), data.to_vec())
            };

            // Expect [1, horizon] or [1, horizon, n_quantiles]. Slice off
            // exactly `config.horizon` rows from the time dimension.
            let (point, quantiles) = match dims.as_slice() {
                [1, t] => {
                    let h = (*t as usize).min(config.horizon);
                    (raw[..h].to_vec(), Vec::new())
                }
                [1, t, q] => {
                    let h = (*t as usize).min(config.horizon);
                    let q = *q as usize;
                    // Layout assumed [batch, time, quantile], row-major.
                    // Median (or middle quantile) becomes the point forecast.
                    let median_idx = q / 2;
                    let mut point = Vec::with_capacity(h);
                    let mut q_series: Vec<Vec<f32>> = vec![Vec::with_capacity(h); q];
                    for ti in 0..h {
                        for qi in 0..q {
                            let v = raw[ti * q + qi];
                            q_series[qi].push(v);
                            if qi == median_idx {
                                point.push(v);
                            }
                        }
                    }
                    (point, q_series)
                }
                other => {
                    return Err(ModelError::InferenceError(format!(
                        "unexpected output shape {:?}, expected [1, T] or [1, T, Q]",
                        other
                    )));
                }
            };

            Ok(ForecastResult {
                point,
                quantiles,
                quantile_levels: config.quantiles.clone(),
                generation_time_ms: start.elapsed().as_millis() as u64,
            })
        }

        fn context_length(&self) -> usize {
            self.context_length
        }

        fn max_horizon(&self) -> usize {
            self.max_horizon
        }
    }
}

#[cfg(feature = "onnx")]
pub use onnx_backend::GenericForecast;

#[cfg(not(feature = "onnx"))]
mod stub_backend {
    use super::*;

    /// Stub for builds without the `onnx` feature. Constructing it always
    /// returns an error so callers can detect the missing backend.
    #[derive(Debug)]
    pub struct GenericForecast;

    impl GenericForecast {
        pub fn from_onnx(
            _path: impl AsRef<Path>,
            _context_length: usize,
            _max_horizon: usize,
        ) -> Result<Self> {
            Err(ModelError::ProviderNotAvailable(
                "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
            ))
        }
    }

    impl ForecastModel for GenericForecast {
        fn forecast(&self, _history: &[f32], _config: &ForecastConfig) -> Result<ForecastResult> {
            Err(ModelError::ProviderNotAvailable(
                "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
            ))
        }
        fn context_length(&self) -> usize {
            0
        }
        fn max_horizon(&self) -> usize {
            0
        }
    }
}

#[cfg(not(feature = "onnx"))]
pub use stub_backend::GenericForecast;

/// Runtime that owns multiple loaded forecast models, keyed by model_id.
///
/// This is the timeseries equivalent of `ModelRuntime` for chat models —
/// the node calls into it when handling `tenzro_forecast` RPC requests.
pub struct TimeseriesRuntime {
    models: dashmap::DashMap<String, Arc<dyn ForecastModel>>,
}

impl Default for TimeseriesRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeseriesRuntime {
    pub fn new() -> Self {
        Self {
            models: dashmap::DashMap::new(),
        }
    }

    /// Register a pre-loaded model under `model_id`. Replaces any
    /// existing registration for the same id.
    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn ForecastModel>) {
        self.models.insert(model_id.into(), model);
    }

    /// Load an ONNX model from disk and register it.
    pub fn load_onnx(
        &self,
        model_id: impl Into<String>,
        path: impl AsRef<Path>,
        context_length: usize,
        max_horizon: usize,
    ) -> Result<()> {
        let model = GenericForecast::from_onnx(path, context_length, max_horizon)?;
        self.models
            .insert(model_id.into(), Arc::new(model) as Arc<dyn ForecastModel>);
        Ok(())
    }

    pub fn unregister(&self, model_id: &str) -> bool {
        self.models.remove(model_id).is_some()
    }

    pub fn is_loaded(&self, model_id: &str) -> bool {
        self.models.contains_key(model_id)
    }

    pub fn loaded_models(&self) -> Vec<String> {
        self.models.iter().map(|kv| kv.key().clone()).collect()
    }

    /// Run a forecast on a registered model. Inference is dispatched to
    /// `spawn_blocking` so the async caller's runtime isn't stalled.
    pub async fn forecast(
        &self,
        model_id: &str,
        history: Vec<f32>,
        config: ForecastConfig,
    ) -> Result<ForecastResult> {
        let model = self
            .models
            .get(model_id)
            .map(|kv| Arc::clone(kv.value()))
            .ok_or_else(|| ModelError::ModelNotFound(format!("forecast model '{}'", model_id)))?;

        tokio::task::spawn_blocking(move || model.forecast(&history, &config))
            .await
            .map_err(|e| ModelError::InferenceError(format!("blocking task panic: {}", e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forecast_config_default() {
        let c = ForecastConfig::default();
        assert_eq!(c.horizon, 64);
        assert!(c.quantiles.is_empty());
        assert!(c.frequency_seconds.is_none());
    }

    #[test]
    fn forecast_result_serializes() {
        let r = ForecastResult {
            point: vec![1.0, 2.0, 3.0],
            quantiles: Vec::new(),
            quantile_levels: Vec::new(),
            generation_time_ms: 42,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"point\""));
        assert!(json.contains("\"generation_time_ms\":42"));
        let back: ForecastResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.point, vec![1.0, 2.0, 3.0]);
    }

    #[test]
    fn runtime_starts_empty() {
        let rt = TimeseriesRuntime::new();
        assert!(rt.loaded_models().is_empty());
        assert!(!rt.is_loaded("anything"));
    }

    #[test]
    fn runtime_unregister_returns_false_when_absent() {
        let rt = TimeseriesRuntime::new();
        assert!(!rt.unregister("missing"));
    }

    #[tokio::test]
    async fn forecast_on_unknown_model_returns_not_found() {
        let rt = TimeseriesRuntime::new();
        let err = rt
            .forecast("nope", vec![1.0; 32], ForecastConfig::default())
            .await
            .unwrap_err();
        match err {
            ModelError::ModelNotFound(_) => {}
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[cfg(not(feature = "onnx"))]
    #[test]
    fn stub_load_returns_not_available() {
        let err = GenericForecast::from_onnx("/nowhere.onnx", 512, 64).unwrap_err();
        match err {
            ModelError::ProviderNotAvailable(msg) => {
                assert!(msg.contains("ONNX"), "expected ONNX hint, got: {}", msg);
            }
            other => panic!("expected NotAvailable, got {:?}", other),
        }
    }

    /// A trivial mock forecast model used to exercise the runtime
    /// dispatch path without requiring ONNX.
    struct EchoForecast;
    impl ForecastModel for EchoForecast {
        fn forecast(&self, history: &[f32], config: &ForecastConfig) -> Result<ForecastResult> {
            // Echo the last value `horizon` times — useful as a sanity
            // baseline (naive forecaster).
            let last = *history.last().unwrap_or(&0.0);
            Ok(ForecastResult {
                point: vec![last; config.horizon],
                quantiles: Vec::new(),
                quantile_levels: Vec::new(),
                generation_time_ms: 0,
            })
        }
        fn context_length(&self) -> usize {
            512
        }
        fn max_horizon(&self) -> usize {
            1024
        }
    }

    #[tokio::test]
    async fn runtime_dispatches_to_registered_model() {
        let rt = TimeseriesRuntime::new();
        rt.register("echo", Arc::new(EchoForecast));
        assert!(rt.is_loaded("echo"));
        let cfg = ForecastConfig {
            horizon: 4,
            ..Default::default()
        };
        let r = rt.forecast("echo", vec![1.0, 2.0, 3.0, 4.2], cfg).await.unwrap();
        assert_eq!(r.point, vec![4.2, 4.2, 4.2, 4.2]);
    }
}
