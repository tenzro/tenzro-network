//! Engine settings from the node configuration: the `[onnx]` limits and the
//! `[engines]` table of out-of-process engines.
//!
//! These are configuration data. They build without the `engine` feature so a
//! node configuration parses the same in every build; the modules that act on
//! them (`onnx_session`, `model_host`) need the engine.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Operator settings applied to every ONNX runtime, from the node config's
/// `[onnx]` table. Every field is optional; unset fields are derived from the
/// detected core count.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnnxConfig {
    /// Intra-op and inter-op thread count for every ONNX session.
    #[serde(default)]
    pub threads: Option<usize>,
    /// Requests each ONNX runtime runs at once.
    #[serde(default)]
    pub concurrency: Option<u32>,
    /// Requests each ONNX runtime holds waiting for a slot before it answers
    /// busy.
    #[serde(default)]
    pub queue_depth: Option<u32>,
}

/// Resolved ONNX serving limits for this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnnxSettings {
    /// Intra-op and inter-op thread count passed to every session builder.
    pub threads: usize,
    /// Concurrent requests per ONNX runtime.
    pub concurrency: u32,
    /// Waiting requests per ONNX runtime before new ones are refused as busy.
    pub queue_depth: u32,
}

impl OnnxSettings {
    /// Resolve `config` against a machine with `cores` cores.
    ///
    /// Threads default to a quarter of the cores (at least one). Concurrency
    /// defaults to as many requests as fit the cores at that thread count, so
    /// a runtime at full concurrency uses the machine without oversubscribing
    /// it. The queue holds four waiting requests per slot.
    pub fn resolve(config: &OnnxConfig, cores: usize) -> Self {
        let cores = cores.max(1);
        let threads = config.threads.unwrap_or(cores / 4).max(1);
        let concurrency = config
            .concurrency
            .unwrap_or((cores / threads).max(1) as u32)
            .max(1);
        let queue_depth = config
            .queue_depth
            .unwrap_or_else(|| concurrency.saturating_mul(4));
        Self {
            threads,
            concurrency,
            queue_depth,
        }
    }

    #[cfg(feature = "engine")]
    pub(crate) fn detected() -> Self {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Self::resolve(&OnnxConfig::default(), cores)
    }
}

/// One pinned engine environment, as the operator configures it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentPin {
    /// The hosted backend it runs: `vllm`, `sglang`, `tensorrt-llm` or
    /// `transformers`; or the runtime-host family it serves: `media` or
    /// `speech`.
    pub backend: String,
    /// The provisioned environment directory.
    pub root: PathBuf,
    /// Lowercase hex SHA-256 of the environment's tree.
    pub digest: String,
}

/// The engines a node runs out of process.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnginesConfig {
    /// Directory each runtime host writes its scratch files under, one
    /// subdirectory per model. Required when any model is hosted.
    #[serde(default)]
    pub scratch_dir: Option<PathBuf>,
    /// Pinned environments, at most one per backend.
    #[serde(default)]
    pub environments: Vec<EnvironmentPin>,
    /// Models served by a hosted engine instead of llama.cpp: model id to
    /// backend name.
    #[serde(default)]
    pub models: BTreeMap<String, String>,
}
