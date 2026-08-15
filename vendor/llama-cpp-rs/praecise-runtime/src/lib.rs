//! Praecise general inference-acceleration runtime.
//!
//! Backend-agnostic acceleration on top of an inference backend (llama.cpp
//! first). Provides the generation API — configuration, results, sampling and
//! speculative-decode orchestration (block/DFlash and multi-token-prediction).
//!
//! ## Backend loading is configurable — never loaded twice
//!
//! The llama.cpp backend is an **optional** dependency, enabled by the
//! `bundled-llama` feature:
//!
//! - **Standalone consumer** — enable `bundled-llama` (or an accelerator
//!   feature such as `cuda`, which implies it). Praecise pulls, builds and
//!   initialises the backend.
//! - **Host that already links llama-cpp-2** — depend on this crate WITHOUT
//!   `bundled-llama` and pass in the host's existing backend and model handles.
//!   The native `libllama` and its GPU context are then loaded exactly once
//!   instead of a second copy contending for the device.
//!
//! The backend-agnostic surface — [`config::GenerationConfig`],
//! [`result::InferenceResult`], [`result::StopReason`], [`error::Error`] —
//! compiles and is usable with or without a bundled backend.

pub mod config;
pub mod error;
pub mod prompt;
pub mod result;
pub mod stream;
pub mod toploc;

/// llama.cpp sampler-chain assembly. Compiled only with a bundled backend.
#[cfg(feature = "bundled-llama")]
pub mod sampling;

/// Continuous batching engine. Compiled only with a bundled backend.
#[cfg(feature = "bundled-llama")]
pub mod batching;

/// Loaded model + drafter handles. Compiled only with a bundled backend.
#[cfg(feature = "bundled-llama")]
pub mod loaded;

/// Self-speculative decode (DFlash / MTP). Compiled only with a bundled backend.
#[cfg(feature = "bundled-llama")]
pub mod speculative;

pub use config::GenerationConfig;
pub use error::{Error, Result};
pub use prompt::render_chatml_prompt;
pub use result::{ChatMessage, InferenceResult, StopReason};
pub use stream::{matched_stop_len, StopStream};

#[cfg(feature = "bundled-llama")]
pub use batching::{max_slots, BatchEngine, BatchPrompt, BatchRequest};
#[cfg(feature = "bundled-llama")]
pub use loaded::{LoadedDrafter, LoadedModel};
#[cfg(feature = "bundled-llama")]
pub use sampling::{build_sampler_chain, build_sampler_chain_with_grammar};
#[cfg(feature = "bundled-llama")]
pub use speculative::generate_speculative;
