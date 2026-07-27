//! Timeseries forecasting runtime backed by ONNX Runtime.
//!
//! This module is gated behind the `onnx` cargo feature. When the feature
//! is off, a thin stub is exposed so callers can still compile and surface
//! a clean "ONNX backend not enabled" error at runtime — exactly the same
//! shape as the real implementation.
//!
//! # Scope
//!
//! This module provides a common `ForecastModel` trait plus a
//! `GenericForecast` implementation for ONNX foundation forecasters that
//! fit a single-tensor input contract:
//!
//!   input  : `[batch, context_len]`             (f32 univariate history)
//!   output : `[batch, horizon]` or
//!            `[batch, horizon, n_quantiles]`    (point or quantile forecast)
//!
//! TimesFM 2.5 200M fits this shape and is the active live model.
//! Multi-input encoder-decoder forecasters (T5-based families with
//! `context_mask`, `group_ids`, `future_covariates`, …) need their own
//! adapter — `GenericForecast` will reject them at load time.
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

mod onnx_backend {
    use super::*;
    use ndarray::Array2;
    use ort::session::Session;
    use ort::value::Tensor;
    use std::time::Instant;

    /// Generic ONNX forecast model — fits TimesFM 2.5 and similar
    /// single-input architectures with `[1, context_len] -> [1, horizon]` shape.
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
        batch_size: usize,
    }

    impl GenericForecast {
        /// Load an ONNX file and inspect its input/output names.
        ///
        /// `output_name` is the prediction output to read. If `None`, the
        /// first output is used — fine for single-output forecasters.
        /// Multi-output exports (e.g. TimesFM transformers ONNX which returns
        /// `last_hidden_state`, `mean_predictions`, `full_predictions`) must
        /// pass the explicit prediction tensor name (typically
        /// `"full_predictions"` for the quantile head or `"mean_predictions"`
        /// for the point forecast).
        ///
        /// `batch_size` is the leading input dimension. For most foundation
        /// forecasters this is `None` (treated as 1). TimesFM 2.5
        /// transformers ONNX requires `Some(2)` because its decoder applies
        /// flip-invariance averaging across the batch axis (config flag
        /// `force_flip_invariance: true`). When `batch_size > 1` the history
        /// is tiled across the batch dim and the row `[0, ..]` is read from
        /// the output.
        pub fn from_onnx(
            path: impl AsRef<Path>,
            context_length: usize,
            max_horizon: usize,
            output_name: Option<String>,
            batch_size: Option<usize>,
        ) -> Result<Self> {
            let session = crate::onnx_session::build_onnx_session(path.as_ref(), "model")?;

            let input_name = session
                .inputs
                .first()
                .map(|i| i.name.clone())
                .ok_or_else(|| ModelError::InvalidModel("ONNX model has no inputs".to_string()))?;
            let resolved_output_name = match output_name {
                Some(name) => {
                    if !session.outputs.iter().any(|o| o.name == name) {
                        let available: Vec<&str> =
                            session.outputs.iter().map(|o| o.name.as_str()).collect();
                        return Err(ModelError::InvalidModel(format!(
                            "ONNX output '{}' not found; available outputs: {:?}",
                            name, available
                        )));
                    }
                    name
                }
                None => session
                    .outputs
                    .first()
                    .map(|o| o.name.clone())
                    .ok_or_else(|| {
                        ModelError::InvalidModel("ONNX model has no outputs".to_string())
                    })?,
            };

            let batch_size = batch_size.unwrap_or(1).max(1);

            Ok(Self {
                session: parking_lot::Mutex::new(session),
                context_length,
                max_horizon,
                input_name,
                output_name: resolved_output_name,
                batch_size,
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
                out.extend(std::iter::repeat_n(pad_value, pad_len));
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
            // Tile the fitted history across the batch dimension. For
            // single-batch models this is a single copy; for flip-invariant
            // exports (TimesFM 2.5 requires batch=2) the same row is
            // repeated and the output is read from row 0.
            let mut tiled = Vec::with_capacity(self.batch_size * self.context_length);
            for _ in 0..self.batch_size {
                tiled.extend_from_slice(&fitted);
            }
            let arr = Array2::<f32>::from_shape_vec(
                (self.batch_size, self.context_length),
                tiled,
            )
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

            // Expect [B, horizon] or [B, horizon, n_quantiles] where B is
            // `self.batch_size`. Always read row 0 — when B > 1 the input
            // was tiled across the batch dim so row 0 is the answer for
            // this caller's history. Slice off exactly `config.horizon`
            // rows from the time dimension.
            let (point, quantiles) = match dims.as_slice() {
                [b, t] => {
                    let b = *b as usize;
                    if b == 0 {
                        return Err(ModelError::InferenceError(
                            "output batch dim is 0".to_string(),
                        ));
                    }
                    let t = *t as usize;
                    let h = t.min(config.horizon);
                    // Row 0 starts at index 0 and runs for `t` elements.
                    (raw[..h].to_vec(), Vec::new())
                }
                [b, t, q] => {
                    let b = *b as usize;
                    if b == 0 {
                        return Err(ModelError::InferenceError(
                            "output batch dim is 0".to_string(),
                        ));
                    }
                    let t = *t as usize;
                    let q = *q as usize;
                    let h = t.min(config.horizon);
                    // Layout [batch, time, quantile], row-major. Row 0
                    // occupies indices `0 .. t * q`.
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
                        "unexpected output shape {:?}, expected [B, T] or [B, T, Q]",
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

pub use onnx_backend::GenericForecast;

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
    ///
    /// `output_name` selects which ONNX output to read as the forecast.
    /// `None` means "use the first output" — correct for single-output
    /// exports. Multi-output graphs (TimesFM transformers ONNX returns
    /// `last_hidden_state`, `mean_predictions`, `full_predictions`) must
    /// pass the explicit prediction tensor name.
    ///
    /// `batch_size` is the fixed leading input dimension. `None` defaults
    /// to 1. TimesFM 2.5 transformers ONNX needs `Some(2)`.
    pub fn load_onnx(
        &self,
        model_id: impl Into<String>,
        path: impl AsRef<Path>,
        context_length: usize,
        max_horizon: usize,
        output_name: Option<String>,
        batch_size: Option<usize>,
    ) -> Result<()> {
        let model = GenericForecast::from_onnx(
            path,
            context_length,
            max_horizon,
            output_name,
            batch_size,
        )?;
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
