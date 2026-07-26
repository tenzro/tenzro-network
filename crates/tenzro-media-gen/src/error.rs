//! Error types for the Tenzro Media Gen protocol layer.

use thiserror::Error;

use tenzro_types::media_gen::{MediaGenExpertRole, MediaGenStatus};

/// Every fallible operation in this crate returns this.
#[derive(Debug, Error)]
pub enum MediaGenError {
    #[error("Job not found: {0}")]
    JobNotFound(String),

    #[error("Job {job_id} already exists")]
    JobAlreadyExists { job_id: String },

    #[error("Worker not enrolled: {0}")]
    WorkerNotEnrolled(String),

    #[error("Worker {worker_did} is already enrolled")]
    WorkerAlreadyEnrolled { worker_did: String },

    #[error("Worker {worker_did} cannot serve job {job_id}")]
    WorkerCannotServe { worker_did: String, job_id: String },

    #[error("Job {job_id} cannot move from {from} to {to}")]
    IllegalTransition {
        job_id: String,
        from: MediaGenStatus,
        to: MediaGenStatus,
    },

    #[error("Job {job_id} is claimed by {holder}, not {caller}")]
    NotJobHolder {
        job_id: String,
        holder: String,
        caller: String,
    },

    #[error("Invalid job spec: {0}")]
    InvalidTaskSpec(String),

    #[error("Job {job_id} does not split its schedule into a {role} expert")]
    RoleNotRequired {
        job_id: String,
        role: MediaGenExpertRole,
    },

    #[error("Job {job_id} splits its schedule; a claim must name an expert role")]
    RoleRequired { job_id: String },

    #[error("The {role} half of job {job_id} is already claimed by {holder}")]
    RoleAlreadyClaimed {
        job_id: String,
        role: MediaGenExpertRole,
        holder: String,
    },

    #[error("Job {job_id} has no handoff latent; the high-noise expert has not finished")]
    HandoffMissing { job_id: String },

    #[error("Job {job_id} already has a handoff latent from {holder}")]
    HandoffAlreadyRecorded { job_id: String, holder: String },

    #[error("Job {job_id} names no input image; its kind conditions on the prompt alone")]
    InputImageMissing { job_id: String },

    #[error(
        "Handoff for job {job_id} claims {completed} of {total} steps, which leaves nothing for \
         either expert"
    )]
    HandoffStepsOutOfRange {
        job_id: String,
        completed: u32,
        total: u32,
    },

    #[error("Receipt for job {job_id} charges {charged} attoTNZO over the {max} attoTNZO ceiling")]
    PriceCeilingExceeded {
        job_id: String,
        charged: u128,
        max: u128,
    },

    #[error("Receipt for job {job_id} does not match the posted spec: {reason}")]
    ReceiptSpecMismatch { job_id: String, reason: String },

    #[error("Output size mismatch: commitment declares {declared} bytes, fetched {actual}")]
    OutputSizeMismatch { declared: u64, actual: u64 },

    #[error("Output hash mismatch: fetched bytes do not hash to the committed hash")]
    OutputHashMismatch,

    #[error("Output not found in the media store for hash {0}")]
    OutputNotFound(String),

    #[error("No output store is attached to the runtime")]
    NoOutputStore,

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, MediaGenError>;
