//! Errors returned by the iroh-backed resolver.

use thiserror::Error;
use tenzro_types::tenzro_uri::TenzroUriError;

/// Result alias for iroh-backed resolution operations.
pub type IrohResult<T> = Result<T, IrohError>;

/// Errors that can occur while resolving a `tenzro://` URI through the
/// iroh transport.
#[derive(Debug, Error)]
pub enum IrohError {
    /// The input string was not a valid `tenzro://` URI.
    #[error("URI parse error: {0}")]
    Uri(#[from] TenzroUriError),

    /// The URI parsed correctly but the resolver does not implement that
    /// variant yet (e.g. `Manifest` before Phase B2 is implemented).
    #[error("URI variant `{0}` is not supported by this resolver yet")]
    UnsupportedVariant(&'static str),

    /// Underlying iroh endpoint / blobs store / docs replica error.
    #[error("iroh backend error: {0}")]
    Backend(String),

    /// The content referenced by the URI could not be located on the network.
    #[error("content not found: {0}")]
    NotFound(String),

    /// Authorization for the requested resource was denied (e.g. sealed
    /// shard requires Confidential-tier enclave attestation).
    #[error("authorization denied: {0}")]
    Unauthorized(String),

    /// Local I/O error (storage, network socket, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
