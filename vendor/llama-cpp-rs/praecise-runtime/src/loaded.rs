//! Loaded model + drafter handles for the bundled llama.cpp backend.
//!
//! Backend-gated. A host that provides its own backend constructs equivalents
//! from its own binding and calls the speculative/batching entry points.

use std::sync::Arc;

use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::model::LlamaModel;

/// A model loaded into the bundled backend, ready to serve.
pub struct LoadedModel {
    /// The loaded weights.
    pub model: LlamaModel,
    /// Shared backend handle.
    pub backend: Arc<LlamaBackend>,
    /// Effective context length (host-capped).
    pub context_length: u32,
}

/// A speculative-decoding drafter paired with a target model.
pub struct LoadedDrafter {
    /// The drafter weights (an MTP/DFlash head, or a small draft model).
    pub model: LlamaModel,
    /// Shared backend handle (echo of the target's, so a draft context can be
    /// constructed without re-resolving the backend).
    pub backend: Arc<LlamaBackend>,
    /// Context length for the draft model's context (same host cap as target).
    pub context_length: u32,
    /// Speculative algorithm for this drafter: 0 = draft-mtp, 1 = draft-dflash.
    pub spec_type: i32,
}
