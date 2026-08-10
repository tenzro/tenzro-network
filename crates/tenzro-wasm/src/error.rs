//! Error type for the WASI component host.

use std::time::Duration;
use thiserror::Error;

/// Result alias for the WASI component host.
pub type WasmResult<T> = Result<T, WasmError>;

/// All ways a WASI component host operation can fail.
#[derive(Debug, Error)]
pub enum WasmError {
    /// The component bytes were rejected by the Wasmtime engine
    /// (malformed binary, unsupported component-model feature, etc.).
    #[error("invalid component bytes: {0}")]
    InvalidComponent(String),

    /// The manifest declared a runtime we do not host.
    #[error("unsupported runtime: {0}")]
    UnsupportedRuntime(String),

    /// A capability requested by the manifest is not granted by the host.
    #[error("missing capability: {0}")]
    MissingCapability(String),

    /// The component exhausted its fuel budget before completing.
    #[error("fuel exhausted after {consumed} units")]
    FuelExhausted {
        /// Fuel consumed before the trap.
        consumed: u64,
    },

    /// The component exceeded its wall-clock deadline.
    #[error("deadline exceeded after {elapsed:?}")]
    DeadlineExceeded {
        /// Wall-clock time before the deadline trap.
        elapsed: Duration,
    },

    /// The component called a host function in a way that violated the
    /// host contract (wrong type, oversize argument, ...).
    #[error("host contract violation: {0}")]
    HostContractViolation(String),

    /// The component trapped.
    #[error("component trap: {0}")]
    Trap(String),

    /// The host could not serialize the input or deserialize the output.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// The on-disk cache could not be read or written.
    #[error("cache error: {0}")]
    Cache(String),

    /// Wrapper for anything Wasmtime returns that doesn't map onto the
    /// other variants.
    #[error("wasmtime: {0}")]
    Wasmtime(String),
}

impl From<anyhow::Error> for WasmError {
    fn from(err: anyhow::Error) -> Self {
        WasmError::Wasmtime(format!("{err:#}"))
    }
}

impl From<serde_json::Error> for WasmError {
    fn from(err: serde_json::Error) -> Self {
        WasmError::Serialization(err.to_string())
    }
}
