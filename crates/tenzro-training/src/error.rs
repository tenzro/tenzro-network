//! Error types for `tenzro-training`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrainingError {
    #[error("training task not found: {0}")]
    TaskNotFound(String),

    #[error("invalid task spec: {0}")]
    InvalidTaskSpec(String),

    #[error("trainer already enrolled: {0}")]
    AlreadyEnrolled(String),

    #[error("enrollment closed for task {0}")]
    EnrollmentClosed(String),

    #[error("invalid round: expected {expected}, got {got}")]
    InvalidRound { expected: u32, got: u32 },

    #[error("fragment {fragment} out of range (max {max})")]
    FragmentOutOfRange { fragment: u32, max: u32 },

    #[error("aggregation error: {0}")]
    Aggregation(String),

    #[error("invalid signature on {what}")]
    InvalidSignature { what: &'static str },

    #[error("attestation required for tier {0:?}")]
    AttestationRequired(tenzro_types::training::TrainingTier),

    #[error("payload size mismatch: header says {header}, got {actual}")]
    PayloadSizeMismatch { header: u64, actual: u64 },

    #[error("payload hash mismatch")]
    PayloadHashMismatch,

    #[error("quorum not yet reached for fragment {fragment} (have {have}, need {need})")]
    QuorumNotMet {
        fragment: u32,
        have: u32,
        need: u32,
    },

    #[error("dimension mismatch in aggregation: {0}")]
    DimensionMismatch(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, TrainingError>;
