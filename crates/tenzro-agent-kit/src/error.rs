//! Error types for `tenzro-agent-kit`.

use thiserror::Error;

/// Top-level error type for all agent-kit operations.
#[derive(Debug, Error)]
pub enum AgentKitError {
    /// JSON-RPC transport failure
    #[error("rpc transport error: {0}")]
    RpcTransport(String),

    /// JSON-RPC server returned an error response.
    ///
    /// `data` carries the optional `error.data` field per JSON-RPC 2.0 §5.1
    /// (machine-parseable error context). Propagated so callers can act on
    /// structured error payloads without re-decoding the wire response.
    #[error("rpc error (code={code}): {message}")]
    RpcError {
        code: i64,
        message: String,
        data: Option<serde_json::Value>,
    },

    /// Server response could not be parsed as JSON
    #[error("rpc deserialization error: {0}")]
    RpcDeserialize(String),

    /// Template id was not found in the registry
    #[error("template not found: {0}")]
    TemplateNotFound(String),

    /// Template was found but lacks an execution spec
    #[error("template {0} has no execution_spec — cannot run without one")]
    MissingExecutionSpec(String),

    /// Tool tag could not be resolved to any registered tool
    #[error("no registered tool matches tag '{0}'")]
    UnresolvedToolTag(String),

    /// Skill tag could not be resolved to any registered skill
    #[error("no registered skill matches tag '{0}'")]
    UnresolvedSkillTag(String),

    /// Identity provisioning failed
    #[error("identity provisioning failed: {0}")]
    IdentityProvisioning(String),

    /// Delegation scope was rejected by the registry
    #[error("delegation rejected: {0}")]
    DelegationRejected(String),

    /// Step exceeded its hard cap
    #[error("hard cap exceeded for operation '{operation}': {value} > {cap}")]
    HardCapExceeded {
        operation: String,
        value: u128,
        cap: u128,
    },

    /// JMESPath expression in a `When` step failed to compile or evaluate
    #[error("jmespath error: {0}")]
    JmesPath(String),

    /// Template variable substitution failed
    #[error("template substitution failed: missing variable '{0}'")]
    MissingVariable(String),

    /// IO error reading a bundled reference template
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization error
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Underlying VM execution failure
    #[error("vm execution error: {0}")]
    VmExecution(String),

    /// Underlying bridge failure
    #[error("bridge error: {0}")]
    Bridge(String),

    /// Underlying payment failure
    #[error("payment error: {0}")]
    Payment(String),

    /// AuthIssuer / DPoP credential failure (missing issuer at spawn,
    /// JWT mint failure, DPoP proof signing failure).
    #[error("auth error: {0}")]
    Auth(String),

    /// Sandboxed skill execution failed (WASI component runtime). Only
    /// emitted when the kit is built with `--features wasi-skills`.
    #[error("sandboxed skill execution failed: {0}")]
    ExecutionFailed(String),

    /// Catch-all
    #[error("agent kit error: {0}")]
    Other(String),
}

impl From<reqwest::Error> for AgentKitError {
    fn from(err: reqwest::Error) -> Self {
        AgentKitError::RpcTransport(err.to_string())
    }
}
