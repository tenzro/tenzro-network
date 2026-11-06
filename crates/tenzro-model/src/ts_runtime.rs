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

use crate::error::{ModelError, Result};
use crate::model_host::{Engine, EngineModels, ModelHost};

pub use praecise_onnx::forecast::{
    Chronos2Forecast, ForecastConfig, ForecastModel, ForecastResult, GenericForecast,
    T0_HORIZON_MULTIPLE, T0_MEDIAN_IDX, T0_QUANTILES, T0Forecast, t0_compute_horizon,
};

/// Runtime that owns multiple loaded forecast models, keyed by model_id.
///
/// This is the timeseries equivalent of `ModelRuntime` for chat models —
/// the node calls into it when handling `tenzro_forecast` RPC requests.
pub struct TimeseriesRuntime {
    models: EngineModels<dyn ForecastModel>,
}

impl Default for TimeseriesRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeseriesRuntime {
    pub fn new() -> Self {
        Self::with_host(Arc::default())
    }

    /// A runtime that claims models and admits requests through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            models: EngineModels::new(Engine::Onnx("forecast"), host),
        }
    }

    /// Register a pre-loaded model under `model_id`. Replaces any
    /// existing registration for the same id.
    pub fn register(
        &self,
        model_id: impl Into<String>,
        model: Arc<dyn ForecastModel>,
    ) -> Result<()> {
        self.models.insert(model_id, model)
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
    /// `"t0"` takes five grouped tensors and returns `[B, T, Q]` with the
    /// horizon rounded up to a multiple of 32;
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
        self.models.load(model_id, || {
            crate::onnx_session::declare()?;
            let model: Arc<dyn ForecastModel> = match family {
                "chronos2" => Arc::new(Chronos2Forecast::from_onnx(path, context_length)?),
                "t0" => Arc::new(T0Forecast::from_onnx(path, context_length, max_horizon)?),
                _ => Arc::new(GenericForecast::from_onnx(
                    path,
                    context_length,
                    max_horizon,
                    output_name,
                    batch_size,
                )?),
            };
            Ok(model)
        })
    }

    pub fn unregister(&self, model_id: &str) -> bool {
        self.models.remove(model_id)
    }

    pub fn is_loaded(&self, model_id: &str) -> bool {
        self.models.contains(model_id)
    }

    pub fn loaded_models(&self) -> Vec<String> {
        self.models.ids()
    }

    /// Run a forecast on a registered model, through the runtime's
    /// admission, on a blocking thread.
    pub async fn forecast(
        &self,
        model_id: &str,
        history: Vec<f32>,
        config: ForecastConfig,
    ) -> Result<ForecastResult> {
        self.models
            .run(model_id, move |model| {
                model.forecast(&history, &config).map_err(ModelError::from)
            })
            .await
    }

    /// Run a multivariate forecast: `history` with `covariates` read beside
    /// it. Refused by a model that does not read covariates.
    pub async fn forecast_with_covariates(
        &self,
        model_id: &str,
        history: Vec<f32>,
        covariates: Vec<Vec<f32>>,
        config: ForecastConfig,
    ) -> Result<ForecastResult> {
        self.models
            .run(model_id, move |model| {
                model
                    .forecast_with_covariates(&history, &covariates, &config)
                    .map_err(ModelError::from)
            })
            .await
    }

    /// Whether a registered model reads covariates.
    pub fn takes_covariates(&self, model_id: &str) -> bool {
        self.models
            .get(model_id)
            .is_some_and(|m| m.takes_covariates())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t0_compute_horizon_rounds_up_to_the_patch() {
        assert_eq!(t0_compute_horizon(1), 32);
        assert_eq!(t0_compute_horizon(32), 32);
        assert_eq!(t0_compute_horizon(50), 64);
        assert_eq!(t0_compute_horizon(1024), 1024);
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
        fn forecast(
            &self,
            history: &[f32],
            config: &ForecastConfig,
        ) -> praecise_onnx::Result<ForecastResult> {
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
        rt.register("echo", Arc::new(EchoForecast)).unwrap();
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
