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

    #[error("trainer {0} is not enrolled in this run; submit-gradient denied")]
    TrainerNotEnrolled(String),

    #[error("enrollment closed for task {0}")]
    EnrollmentClosed(String),

    #[error("invalid round: expected {expected}, got {got}")]
    InvalidRound { expected: u32, got: u32 },

    #[error(
        "conflicting finalize for task {task_id} round {round}: previously committed state_root \
         {expected} but received {got}"
    )]
    ConflictingFinalize {
        task_id: String,
        round: u32,
        expected: tenzro_types::primitives::Hash,
        got: tenzro_types::primitives::Hash,
    },

    #[error("fragment {fragment} out of range (max {max})")]
    FragmentOutOfRange { fragment: u32, max: u32 },

    #[error("aggregation error: {0}")]
    Aggregation(String),

    #[error("invalid signature on {what}")]
    InvalidSignature { what: &'static str },

    #[error("attestation required for tier {0:?}")]
    AttestationRequired(tenzro_types::training::TrainingTier),

    #[error("Confidential-tier task {task_id} has no sealed-shard manifest installed")]
    SealedManifestMissing { task_id: String },

    #[error(
        "sealed-shard manifest hash mismatch for task {task_id}: dataset_ref says {expected}, manifest computes to {actual}"
    )]
    SealedManifestHashMismatch {
        task_id: String,
        expected: String,
        actual: String,
    },

    #[error(
        "trainer {trainer_did} not authorized at Confidential tier (no sealed-shard envelope in manifest for task {task_id})"
    )]
    SealedEnvelopeMissing {
        task_id: String,
        trainer_did: String,
    },

    #[error(
        "Confidential-tier enrollment for {trainer_did} rejected: {field} mismatch (sponsor sealed to a different enclave)"
    )]
    EnclaveBindingMismatch {
        trainer_did: String,
        field: &'static str,
    },

    #[error(
        "aggregation rule {rule:?} requires tier {required:?} or higher; task spec tier is {actual:?}"
    )]
    AggregationRuleTierMismatch {
        rule: tenzro_types::training::AggregationRule,
        required: tenzro_types::training::TrainingTier,
        actual: tenzro_types::training::TrainingTier,
    },

    #[error("payload size mismatch: header says {header}, got {actual}")]
    PayloadSizeMismatch { header: u64, actual: u64 },

    #[error("payload hash mismatch")]
    PayloadHashMismatch,

    #[error(
        "sealed shard ciphertext size mismatch for shard {shard_index}: envelope declares {declared} bytes, fetched {actual}"
    )]
    SealedShardSizeMismatch {
        shard_index: u32,
        declared: u64,
        actual: u64,
    },

    #[error(
        "sealed shard ciphertext hash mismatch for shard {shard_index}: envelope declares {declared}, fetched bytes hash to {actual}"
    )]
    SealedShardHashMismatch {
        shard_index: u32,
        declared: String,
        actual: String,
    },

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
