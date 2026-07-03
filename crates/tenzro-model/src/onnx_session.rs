//! Shared ONNX Runtime session construction.
//!
//! Every ONNX-backed runtime (timeseries, vision, text-embedding,
//! segmentation, text-segmentation, detection, audio) builds its
//! [`Session`] through [`build_onnx_session`], which selects execution
//! providers from the compiled feature set and the optional
//! `TENZRO_ONNX_EP` environment override.
//!
//! Selection rules:
//! - `TENZRO_ONNX_EP` is a comma-separated priority list drawn from
//!   `tensorrt`, `cuda`, `coreml`, `cpu`. Names that are unknown or not
//!   compiled into this build log a warning and are skipped. `cpu`
//!   terminates the list — CPU is ONNX Runtime's implicit final
//!   execution provider and is always available, so nothing after it
//!   would ever run.
//! - Without the override, the default priority is `tensorrt`, `cuda`,
//!   `coreml`, restricted to whichever of the `onnx-tensorrt` /
//!   `onnx-cuda` / `onnx-coreml` cargo features are compiled in. The
//!   CPU-only build registers no explicit provider, which is identical
//!   to the previous behavior of every runtime.
//! - A provider whose registration fails at runtime (missing driver,
//!   missing shared library, unsupported hardware) logs a warning and
//!   falls through to the next provider — never a hard error.

use std::path::Path;

use ort::session::Session;
use ort::session::builder::{GraphOptimizationLevel, SessionBuilder};

#[cfg(any(feature = "onnx-cuda", feature = "onnx-tensorrt", feature = "onnx-coreml"))]
use ort::execution_providers::ExecutionProvider;

use crate::error::{ModelError, Result};

/// Environment variable holding the comma-separated execution-provider
/// priority list. Recognized values: `tensorrt`, `cuda`, `coreml`, `cpu`.
pub const ONNX_EP_ENV: &str = "TENZRO_ONNX_EP";

/// Default execution-provider priority when `TENZRO_ONNX_EP` is unset,
/// filtered down to the providers compiled into this build.
const DEFAULT_EP_PRIORITY: [&str; 3] = ["tensorrt", "cuda", "coreml"];

/// Whether the named execution provider is compiled into this build.
fn ep_compiled(name: &str) -> bool {
    match name {
        "tensorrt" => cfg!(feature = "onnx-tensorrt"),
        "cuda" => cfg!(feature = "onnx-cuda"),
        "coreml" => cfg!(feature = "onnx-coreml"),
        "cpu" => true,
        _ => false,
    }
}

/// Parse a `TENZRO_ONNX_EP` override into the effective registration list.
///
/// Unknown and uncompiled names warn and are skipped; `cpu` terminates
/// the list because the CPU provider is ONNX Runtime's implicit final
/// fallback and everything after it is unreachable.
fn parse_ep_override(raw: &str) -> Vec<String> {
    let mut selected = Vec::new();
    for token in raw.split(',') {
        let name = token.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if !matches!(name.as_str(), "tensorrt" | "cuda" | "coreml" | "cpu") {
            tracing::warn!(
                ep = %name,
                "unknown ONNX execution provider in {ONNX_EP_ENV}; skipping"
            );
            continue;
        }
        if name == "cpu" {
            break;
        }
        if !ep_compiled(&name) {
            tracing::warn!(
                ep = %name,
                "ONNX execution provider requested via {ONNX_EP_ENV} is not compiled \
                 into this build (missing `onnx-{name}` cargo feature); skipping"
            );
            continue;
        }
        selected.push(name);
    }
    selected
}

/// Resolve the execution-provider priority list for this process.
fn selected_execution_providers() -> Vec<String> {
    match std::env::var(ONNX_EP_ENV) {
        Ok(raw) => parse_ep_override(&raw),
        Err(_) => DEFAULT_EP_PRIORITY
            .iter()
            .filter(|name| ep_compiled(name))
            .map(|name| name.to_string())
            .collect(),
    }
}

/// Attempt to register the named execution provider on `builder`.
///
/// Returns `true` on success. Registration failures log a warning and
/// return `false` so the caller falls through to the next provider.
fn register_execution_provider(name: &str, builder: &mut SessionBuilder) -> bool {
    // When no ONNX execution-provider feature is enabled, every match arm
    // that consumes `builder` is cfg'd out, so silence the unused-binding lint
    // for that configuration only.
    #[cfg(not(any(
        feature = "onnx-tensorrt",
        feature = "onnx-cuda",
        feature = "onnx-coreml"
    )))]
    let _ = &builder;
    match name {
        #[cfg(feature = "onnx-tensorrt")]
        "tensorrt" => {
            match ort::execution_providers::TensorRTExecutionProvider::default().register(builder)
            {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(
                        error = %ort::Error::from(e),
                        "TensorRT execution provider registration failed; falling back"
                    );
                    false
                }
            }
        }
        #[cfg(feature = "onnx-cuda")]
        "cuda" => {
            match ort::execution_providers::CUDAExecutionProvider::default().register(builder) {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(
                        error = %ort::Error::from(e),
                        "CUDA execution provider registration failed; falling back"
                    );
                    false
                }
            }
        }
        #[cfg(feature = "onnx-coreml")]
        "coreml" => {
            match ort::execution_providers::CoreMLExecutionProvider::default().register(builder) {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(
                        error = %ort::Error::from(e),
                        "CoreML execution provider registration failed; falling back"
                    );
                    false
                }
            }
        }
        other => {
            // Only reachable when a provider name passed the compiled-in
            // check but its registration arm is cfg'd out — kept total so
            // the cfg-gated arms above can drop out cleanly.
            tracing::warn!(
                ep = %other,
                "no registration path for ONNX execution provider; skipping"
            );
            false
        }
    }
}

/// Build an ONNX Runtime session from a model file with Level3 graph
/// optimizations and the execution-provider priority resolved by
/// [`selected_execution_providers`].
///
/// `what` names the artifact for error messages (e.g. `"model"`,
/// `"encoder"`, `"decoder"`).
pub fn build_onnx_session(path: impl AsRef<Path>, what: &str) -> Result<Session> {
    let mut builder = Session::builder()
        .map_err(|e| ModelError::InvalidModel(format!("ORT session builder: {}", e)))?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|e| ModelError::InvalidModel(format!("ORT optimization level: {}", e)))?;

    for ep in selected_execution_providers() {
        if register_execution_provider(&ep, &mut builder) {
            tracing::info!(ep = %ep, "registered ONNX execution provider");
        }
    }

    builder
        .commit_from_file(path.as_ref())
        .map_err(|e| ModelError::ProviderNotAvailable(format!("ORT load {}: {}", what, e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_names_are_skipped() {
        assert!(parse_ep_override("bogus,also-bogus").is_empty());
    }

    #[test]
    fn cpu_terminates_the_list() {
        // Everything after `cpu` is unreachable regardless of features.
        assert!(parse_ep_override("cpu,tensorrt,cuda,coreml").is_empty());
    }

    #[test]
    fn compiled_filter_matches_features() {
        let parsed = parse_ep_override("cuda");
        if cfg!(feature = "onnx-cuda") {
            assert_eq!(parsed, vec!["cuda".to_string()]);
        } else {
            assert!(parsed.is_empty());
        }
    }

    #[test]
    fn cpu_is_always_compiled_and_gpu_names_track_features() {
        assert!(ep_compiled("cpu"));
        assert_eq!(ep_compiled("cuda"), cfg!(feature = "onnx-cuda"));
        assert_eq!(ep_compiled("tensorrt"), cfg!(feature = "onnx-tensorrt"));
        assert_eq!(ep_compiled("coreml"), cfg!(feature = "onnx-coreml"));
        assert!(!ep_compiled("rocm"));
    }

    #[test]
    fn whitespace_and_case_are_normalized() {
        let parsed = parse_ep_override("  CPU  ");
        assert!(parsed.is_empty());
    }
}
