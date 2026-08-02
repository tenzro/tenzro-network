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

    #[error("activation commitment required for Open-tier submissions")]
    CommitmentRequired,

    #[error("invalid activation commitment: {what}")]
    CommitmentInvalid { what: &'static str },

    #[error("no buffered gradient for trainer {trainer_did} at round {round} fragment {fragment}")]
    GradientNotFound {
        round: u32,
        fragment: u32,
        trainer_did: String,
    },

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
        "no enclave verifier is installed, so a Confidential-tier attestation cannot be \
         checked; enrollment is refused"
    )]
    EnclaveVerifierUnavailable,

    #[error("attestation verification failed for trainer {trainer_did}: {reason}")]
    AttestationVerificationFailed { trainer_did: String, reason: String },

    #[error(
        "aggregation rule {rule:?} requires tier {required:?} or higher; task spec tier is {actual:?}"
    )]
    AggregationRuleTierMismatch {
        rule: tenzro_types::training::AggregationRule,
        required: tenzro_types::training::TrainingTier,
        actual: tenzro_types::training::TrainingTier,
    },

    #[error(
        "fragment {fragment} is not in the active shard for round {round} (fragment shard \
         {shard}, active shard {active_shard})"
    )]
    FragmentNotInActiveShard {
        fragment: u32,
        shard: u32,
        active_shard: u32,
        round: u32,
    },

    #[error(
        "fragment {fragment} belongs to pipeline stage {fragment_stage}, but trainer \
         {trainer_did} is assigned stage {trainer_stage}"
    )]
    PipelineStageMismatch {
        fragment: u32,
        fragment_stage: u32,
        trainer_did: String,
        trainer_stage: u32,
    },

    #[error("quantization mismatch: task spec requires {expected}, submission declares {got}")]
    QuantizationMismatch {
        expected: tenzro_types::training::GradientQuantization,
        got: tenzro_types::training::GradientQuantization,
    },

    #[error("payload-kind mismatch: task spec requires {expected}, submission declares {got}")]
    PayloadKindMismatch {
        expected: tenzro_types::training::PayloadKind,
        got: tenzro_types::training::PayloadKind,
    },

    #[error(
        "outer-update mode {mode} requires a SparseTopK payload kind (SparseEf momentum lives \
         in the trainer-side error-feedback accumulator, not the syncer)"
    )]
    OuterUpdateRequiresSparse { mode: &'static str },

    #[error("malformed quantized payload: {0}")]
    QuantizedPayloadMalformed(String),

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
    QuorumNotMet { fragment: u32, have: u32, need: u32 },

    #[error("dimension mismatch in aggregation: {0}")]
    DimensionMismatch(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl TrainingError {
    /// Whether an accept-time rejection proves intent to poison the round (so
    /// the submitter should be slashed + evicted) versus a benign timing/scope
    /// mismatch (a straggler submitting for a stale round, or for a fragment
    /// outside the current active shard, which honest trainers hit routinely).
    ///
    /// Slashable: bad signature, quantization mismatch, payload-kind mismatch,
    /// pipeline-stage violation, missing attestation at a tier that requires it,
    /// a missing or
    /// structurally invalid activation commitment at the Open tier, and
    /// malformed / hash-mismatched payloads — all of which require the
    /// submitter to deviate from the task spec they enrolled under.
    ///
    /// Not slashable: unenrolled submitter (already rejected, nothing to
    /// slash), wrong round, fragment out of range, fragment not in the active
    /// shard — these are timing/scope races an honest trainer can lose.
    pub fn is_slashable_rejection(&self) -> bool {
        matches!(
            self,
            TrainingError::InvalidSignature { .. }
                | TrainingError::QuantizationMismatch { .. }
                | TrainingError::PayloadKindMismatch { .. }
                | TrainingError::PipelineStageMismatch { .. }
                | TrainingError::AttestationRequired(_)
                | TrainingError::CommitmentRequired
                | TrainingError::CommitmentInvalid { .. }
                | TrainingError::QuantizedPayloadMalformed(_)
                | TrainingError::PayloadSizeMismatch { .. }
                | TrainingError::PayloadHashMismatch
        )
    }
}

pub type Result<T> = std::result::Result<T, TrainingError>;
