//! Error types for the Tenzro SDK
//!
//! This module defines all error types that can occur when using the SDK.

use thiserror::Error;

/// Result type for SDK operations
pub type SdkResult<T> = Result<T, SdkError>;

/// Errors that can occur when using the Tenzro SDK
#[derive(Debug, Error)]
pub enum SdkError {
    /// Connection error
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// Authentication error
    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    /// Inference error
    #[error("Inference error: {0}")]
    InferenceError(String),

    /// Settlement error
    #[error("Settlement error: {0}")]
    SettlementError(String),

    /// Wallet error
    #[error("Wallet error: {0}")]
    WalletError(String),

    /// Agent error
    #[error("Agent error: {0}")]
    AgentError(String),

    /// A transport or decoding failure on the way to or from the node: an
    /// HTTP status, a body that is not JSON-RPC, a result that does not decode.
    #[error("RPC error: {0}")]
    RpcError(String),

    /// A JSON-RPC error the node answered with: its code, message and data.
    #[error("{0}")]
    Node(NodeError),

    /// Serialization error
    #[error("Serialization error")]
    SerializationError,

    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Not found error
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Invalid parameter
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Insufficient funds
    #[error("Insufficient funds: required {required}, available {available}")]
    InsufficientFunds { required: u64, available: u64 },

    /// Transaction failed
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    /// An error the node returned in its `{"error":{..}}` shape, as an HTTP
    /// body or as a frame inside a stream.
    #[error("Node error: {0}")]
    Api(#[from] ApiError),
}

impl SdkError {
    /// The node's JSON-RPC error, when this is one.
    pub fn node_error(&self) -> Option<&NodeError> {
        match self {
            SdkError::Node(e) => Some(e),
            _ => None,
        }
    }
}

/// A JSON-RPC error object the node answered with.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Error)]
#[error("RPC error [{code}] {message}")]
pub struct NodeError {
    /// The JSON-RPC error code: -32602 for invalid params, -32601 for an
    /// unknown method, -32004 for a resource or capability this node does not
    /// have, -32000 and below for application errors.
    pub code: i64,
    /// Human-readable reason.
    pub message: String,
    /// Structured detail, when the node gives any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl NodeError {
    /// True when the node is the light build of tenzro-node, which runs no
    /// model: it refuses a call that needs a local model with code -32004 and
    /// `data.build == "light"`. Send such a call to a provider node instead.
    pub fn is_light_build(&self) -> bool {
        self.code == -32004
            && self
                .data
                .as_ref()
                .and_then(|d| d.get("build"))
                .and_then(serde_json::Value::as_str)
                == Some("light")
    }
}

impl From<serde_json::Error> for SdkError {
    fn from(_: serde_json::Error) -> Self {
        SdkError::SerializationError
    }
}

/// An error the node reports, either as the HTTP response body or as a frame
/// inside a stream: `{"error":{"message","type","code"}}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Error)]
#[error("{kind} ({}): {message}", .code.as_deref().unwrap_or("-"))]
pub struct ApiError {
    /// Human-readable reason.
    pub message: String,
    /// Error class, such as `invalid_request_error` or `server_error`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Machine-readable code, such as `model_not_found`.
    pub code: Option<String>,
}

impl ApiError {
    /// The error an `{"error":{..}}` body carries, if it carries one.
    pub fn from_body(body: &serde_json::Value) -> Option<Self> {
        let e = body.get("error").filter(|e| e.is_object())?;
        Some(Self {
            message: e
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
            kind: e
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
            code: e
                .get("code")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        })
    }

    #[cfg(feature = "inference")]
    pub(crate) fn malformed(detail: String) -> Self {
        Self {
            message: detail,
            kind: "invalid_response".to_string(),
            code: Some("malformed_frame".to_string()),
        }
    }
}
