//! Error types for `tenzro-workflow`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WorkflowError {
    #[error("workflow not found: {0}")]
    WorkflowNotFound(String),

    #[error("obligation not found: {0}")]
    ObligationNotFound(String),

    #[error("approval request not found: {0}")]
    ApprovalRequestNotFound(String),

    #[error("approval gate not found: {0}")]
    ApprovalGateNotFound(String),

    #[error("privacy domain not found: {0}")]
    PrivacyDomainNotFound(String),

    #[error("fee route not found: {0}")]
    FeeRouteNotFound(String),

    #[error("invalid workflow status transition: {from} -> {to}")]
    InvalidTransition { from: String, to: String },

    #[error("participant {did} is not part of workflow {workflow}")]
    NotAParticipant { did: String, workflow: String },

    #[error("participant {0} has already signed")]
    AlreadySigned(String),

    #[error("approver {did} is not authorized for gate {gate}")]
    UnauthorizedApprover { did: String, gate: String },

    #[error("approval request {0} is already finalized")]
    ApprovalAlreadyFinalized(String),

    #[error("policy denied: {0}")]
    PolicyDenied(String),

    #[error("policy requires approval: {0}")]
    PolicyRequiresApproval(String),

    #[error("invalid signature for {context}")]
    InvalidSignature { context: String },

    #[error("invalid workflow definition: {0}")]
    InvalidWorkflow(String),

    #[error("privacy domain {0} is frozen")]
    DomainFrozen(String),

    #[error("recipient {0} not in privacy domain")]
    RecipientNotInDomain(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("fee splits exceed 10000 bps: total={0}")]
    FeeSplitOverflow(u32),

    #[error("invalid input: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, WorkflowError>;

impl From<tenzro_storage::error::StorageError> for WorkflowError {
    fn from(e: tenzro_storage::error::StorageError) -> Self {
        WorkflowError::Storage(e.to_string())
    }
}

impl From<bincode::Error> for WorkflowError {
    fn from(e: bincode::Error) -> Self {
        WorkflowError::Serialization(e.to_string())
    }
}

impl From<serde_json::Error> for WorkflowError {
    fn from(e: serde_json::Error) -> Self {
        WorkflowError::Serialization(e.to_string())
    }
}
