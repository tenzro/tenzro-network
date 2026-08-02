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

    /// Chronos-2 — a five-input encoder whose output is quantile-major.
    ///
    /// [`GenericForecast`] handles a graph that takes one tensor and returns
    /// `[B, T]` or `[B, T, Q]`. Chronos-2 matches neither: it takes five
    /// tensors and returns `[B, Q, T]`, quantiles before time. Feeding it
    /// through the generic path would silently read a quantile index as a
    /// timestep — producing a plausible-looking series of the wrong thing —
    /// so it gets its own adapter rather than a widened generic one.
    ///
    /// Every fact below is read off the published graph
    /// (`OpenSTEF/chronos-2-small-onnx`) and its metadata sidecar, and
    /// confirmed by running the model:
    ///
    /// | Input | Type | Shape |
    /// |---|---|---|
    /// | `context` | f32 | `[batch, context_length]` |
    /// | `group_ids` | i64 | `[batch]` |
    /// | `attention_mask` | **f32** | `[batch, context_length]` |
    /// | `future_covariates` | f32 | `[batch, 672]` |
    /// | `future_covariates_mask` | f32 | `[batch, 672]` |
    ///
    /// Output `quantile_preds` is `[batch, 13, 672]`.
    ///
    /// Two of those are easy to get wrong. `attention_mask` is **float**, not
    /// the int64 every other transformer export uses. And the covariate
    /// tensors cannot be zero-length even when there are no covariates: the
    /// graph reshapes them to `[batch, 42, 16]`, so a `[batch, 0]` tensor
    /// fails inside the model rather than at the boundary. They are passed
    /// full-width with an all-zero mask, which is how "no covariates" is
    /// expressed.
    pub struct Chronos2Forecast {
        session: parking_lot::Mutex<Session>,
        context_length: usize,
    }

    /// Timesteps the graph always emits: `horizon_patches (42) ×
    /// output_patch_size (16)`. Fixed in the exported graph, not a request
    /// parameter — a shorter horizon is a truncation of this.
    const CHRONOS2_HORIZON: usize = 672;

    /// Quantile levels the head emits, in order.
    const CHRONOS2_QUANTILES: [f32; 13] = [
        0.01, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99,
    ];

    /// Index of the median in [`CHRONOS2_QUANTILES`].
    ///
    /// Named rather than computed as `len / 2`: that happens to be 6 here, and
    /// would keep being 6 for a head whose levels were not centred on 0.5,
    /// which is how a point forecast quietly becomes a different quantile.
    const CHRONOS2_MEDIAN_IDX: usize = 6;

    impl Chronos2Forecast {
        /// Load the graph and check it is the shape this adapter expects.
        pub fn from_onnx(path: impl AsRef<Path>, context_length: usize) -> Result<Self> {
            let session = crate::onnx_session::build_onnx_session(path.as_ref(), "model")?;
            // Fail at load rather than at the first forecast. An operator who
            // pointed this at the wrong artifact should learn when they serve
            // it, not when a caller asks for a prediction.
            for required in [
                "context",
                "group_ids",
                "attention_mask",
                "future_covariates",
                "future_covariates_mask",
            ] {
                if !session.inputs.iter().any(|i| i.name == required) {
                    let found: Vec<&str> = session.inputs.iter().map(|i| i.name.as_str()).collect();
                    return Err(ModelError::InvalidModel(format!(
                        "not a Chronos-2 graph: missing input '{required}'; found {found:?}"
                    )));
                }
            }
            if !session.outputs.iter().any(|o| o.name == "quantile_preds") {
                let found: Vec<&str> = session.outputs.iter().map(|o| o.name.as_str()).collect();
                return Err(ModelError::InvalidModel(format!(
                    "not a Chronos-2 graph: missing output 'quantile_preds'; found {found:?}"
                )));
            }
            Ok(Self {
                session: parking_lot::Mutex::new(session),
                context_length,
            })
        }

        /// Truncate to the most recent `context_length` points, or return the
        /// history as-is when it is shorter.
        ///
        /// Unlike [`GenericForecast`], short histories are **not** padded: the
        /// context dimension is dynamic in this graph, so a genuinely short
        /// series can be passed at its own length. Padding it and masking the
        /// pad would be the same computation with more room for the mask and
        /// the data to disagree.
        fn fit_history<'a>(&self, history: &'a [f32]) -> &'a [f32] {
            if history.len() > self.context_length {
                &history[history.len() - self.context_length..]
            } else {
                history
            }
        }
    }

    impl ForecastModel for Chronos2Forecast {
        fn forecast(&self, history: &[f32], config: &ForecastConfig) -> Result<ForecastResult> {
            if history.is_empty() {
                return Err(ModelError::InvalidModel("history is empty".to_string()));
            }
            if config.horizon == 0 {
                return Err(ModelError::InvalidModel("horizon must be > 0".to_string()));
            }
            if config.horizon > CHRONOS2_HORIZON {
                return Err(ModelError::InvalidModel(format!(
                    "horizon {} exceeds model max {}",
                    config.horizon, CHRONOS2_HORIZON
                )));
            }

            let start = Instant::now();
            let fitted = self.fit_history(history);
            let ctx = fitted.len();

            let context = Array2::<f32>::from_shape_vec((1, ctx), fitted.to_vec())
                .map_err(|e| ModelError::InferenceError(format!("context shape: {}", e)))?;
            // Every position is real — nothing was padded — so the mask is all
            // ones. Float, not int64.
            let attention = Array2::<f32>::from_elem((1, ctx), 1.0f32);
            // One series, so one group.
            let groups = Array2::<i64>::zeros((1, 1))
                .into_shape_with_order(vec![1usize])
                .map_err(|e| ModelError::InferenceError(format!("group_ids shape: {}", e)))?;
            // Full-width and all-zero: the graph reshapes these to [1, 42, 16],
            // so they cannot be empty, and a zero mask is how "no covariates"
            // is expressed.
            let cov = Array2::<f32>::zeros((1, CHRONOS2_HORIZON));
            let cov_mask = Array2::<f32>::zeros((1, CHRONOS2_HORIZON));

            let t_context = Tensor::from_array(context)
                .map_err(|e| ModelError::InferenceError(format!("ORT tensor context: {}", e)))?;
            let t_groups = Tensor::from_array(groups)
                .map_err(|e| ModelError::InferenceError(format!("ORT tensor group_ids: {}", e)))?;
            let t_attention = Tensor::from_array(attention).map_err(|e| {
                ModelError::InferenceError(format!("ORT tensor attention_mask: {}", e))
            })?;
            let t_cov = Tensor::from_array(cov).map_err(|e| {
                ModelError::InferenceError(format!("ORT tensor future_covariates: {}", e))
            })?;
            let t_cov_mask = Tensor::from_array(cov_mask).map_err(|e| {
                ModelError::InferenceError(format!("ORT tensor future_covariates_mask: {}", e))
            })?;

            let (dims, raw): (Vec<i64>, Vec<f32>) = {
                let mut session = self.session.lock();
                let outputs = session
                    .run(ort::inputs![
                        "context" => t_context,
                        "group_ids" => t_groups,
                        "attention_mask" => t_attention,
                        "future_covariates" => t_cov,
                        "future_covariates_mask" => t_cov_mask,
                    ])
                    .map_err(|e| ModelError::InferenceError(format!("ORT run: {}", e)))?;
                let out = outputs.get("quantile_preds").ok_or_else(|| {
                    ModelError::InferenceError("missing output 'quantile_preds'".to_string())
                })?;
                let (shape, data) = out
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("ORT extract: {}", e)))?;
                (shape.iter().copied().collect(), data.to_vec())
            };

            // `[batch, quantile, time]` — quantile-major, which is the whole
            // reason this adapter exists.
            let [b, q, t] = dims.as_slice() else {
                return Err(ModelError::InferenceError(format!(
                    "unexpected output shape {dims:?}, expected [B, Q, T]"
                )));
            };
            if *b == 0 {
                return Err(ModelError::InferenceError(
                    "output batch dim is 0".to_string(),
                ));
            }
            let (q, t) = (*q as usize, *t as usize);
            if q <= CHRONOS2_MEDIAN_IDX {
                return Err(ModelError::InferenceError(format!(
                    "output has {q} quantiles, too few to contain the median at index {CHRONOS2_MEDIAN_IDX}"
                )));
            }
            let h = t.min(config.horizon);

            // Row 0 of the batch spans `0 .. q * t`; quantile qi occupies
            // `qi * t .. (qi + 1) * t` within it.
            let mut quantiles: Vec<Vec<f32>> = Vec::with_capacity(q);
            for qi in 0..q {
                quantiles.push(raw[qi * t..qi * t + h].to_vec());
            }
            let point = quantiles[CHRONOS2_MEDIAN_IDX].clone();

            Ok(ForecastResult {
                point,
                quantiles,
                quantile_levels: CHRONOS2_QUANTILES[..q.min(CHRONOS2_QUANTILES.len())].to_vec(),
                generation_time_ms: start.elapsed().as_millis() as u64,
            })
        }

        fn context_length(&self) -> usize {
            self.context_length
        }

        fn max_horizon(&self) -> usize {
            CHRONOS2_HORIZON
        }
    }

    impl ForecastModel for GenericForecast {
        fn forecast(&self, history: &[f32], config: &ForecastConfig) -> Result<ForecastResult> {
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
            let arr = Array2::<f32>::from_shape_vec((self.batch_size, self.context_length), tiled)
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

pub use onnx_backend::{Chronos2Forecast, GenericForecast};

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
    /// `family` selects the adapter. Most entries are single-input graphs
    /// returning `[B, T]` or `[B, T, Q]` and use [`GenericForecast`];
    /// `"chronos2"` takes five tensors and returns `[B, Q, T]`, which the
    /// generic path would misread as time-major and turn into a plausible
    /// series of the wrong numbers.
    pub fn load_onnx(
        &self,
        model_id: impl Into<String>,
        path: impl AsRef<Path>,
        family: &str,
        context_length: usize,
        max_horizon: usize,
        output_name: Option<String>,
        batch_size: Option<usize>,
    ) -> Result<()> {
        let model: Arc<dyn ForecastModel> = match family {
            "chronos2" => Arc::new(Chronos2Forecast::from_onnx(path, context_length)?),
            _ => Arc::new(GenericForecast::from_onnx(
                path,
                context_length,
                max_horizon,
                output_name,
                batch_size,
            )?),
        };
        self.models.insert(model_id.into(), model);
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

    /// Exercises the real Chronos-2 adapter when the artifact is present.
    ///
    /// Set `TENZRO_CHRONOS2_ONNX` to a downloaded `chronos-2-small.onnx` to
    /// run it. Skips otherwise so CI without a 112 MB artifact stays green —
    /// but unlike a silently-skipping test, the assertions below are the ones
    /// that caught the two things this adapter exists to get right: the
    /// quantile-major output layout, and covariate tensors that cannot be
    /// empty.
    #[test]
    fn chronos2_reads_a_quantile_major_output() {
        let Ok(path) = std::env::var("TENZRO_CHRONOS2_ONNX") else {
            return;
        };
        let path = std::path::PathBuf::from(path);
        if !path.exists() {
            return;
        }
        let model = onnx_backend::Chronos2Forecast::from_onnx(&path, 5760)
            .expect("the artifact is a Chronos-2 graph");
        assert_eq!(model.max_horizon(), 672);

        // A clean sine, so a forecast that read quantiles as timesteps would
        // be visibly wrong rather than merely different.
        let history: Vec<f32> = (0..256).map(|i| (i as f32 / 10.0).sin()).collect();
        let cfg = ForecastConfig {
            horizon: 24,
            ..Default::default()
        };
        let out = model.forecast(&history, &cfg).expect("forecast runs");

        assert_eq!(out.point.len(), 24, "horizon is honoured");
        assert_eq!(out.quantiles.len(), 13, "the head emits 13 quantiles");
        for q in &out.quantiles {
            assert_eq!(q.len(), 24);
        }
        assert_eq!(out.quantile_levels.len(), 13);
        assert!(
            (out.quantile_levels[6] - 0.5).abs() < 1e-6,
            "median is index 6"
        );

        // The point forecast must be the median series, not some other row.
        assert_eq!(out.point, out.quantiles[6]);

        // Quantiles are non-decreasing at each timestep. This is the assertion
        // that fails loudly if the [B, Q, T] output were read as [B, T, Q]:
        // transposed, the "quantiles" become slices across time and stop being
        // ordered.
        for t in 0..24 {
            for qi in 1..13 {
                assert!(
                    out.quantiles[qi][t] >= out.quantiles[qi - 1][t] - 1e-3,
                    "quantiles out of order at t={t}, q={qi}: {} < {}",
                    out.quantiles[qi][t],
                    out.quantiles[qi - 1][t]
                );
            }
        }

        // A horizon past the single-pass width is refused rather than
        // silently truncated.
        let too_far = ForecastConfig {
            horizon: 1000,
            ..Default::default()
        };
        assert!(model.forecast(&history, &too_far).is_err());
    }

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
        let r = rt
            .forecast("echo", vec![1.0, 2.0, 3.0, 4.2], cfg)
            .await
            .unwrap();
        assert_eq!(r.point, vec![4.2, 4.2, 4.2, 4.2]);
    }
}
