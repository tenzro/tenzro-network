//! Why the light client refused something.

use tenzro_finality::FinalityError;
use tenzro_state_proof::ProofError;

use crate::client::Conflict;

/// Why the light client refused something.
#[derive(Debug, thiserror::Error)]
pub enum LightError {
    /// A reply or an encoded value could not be read.
    #[error("malformed {what}: {why}")]
    Malformed {
        /// What was being read.
        what: &'static str,
        /// Why it was refused.
        why: String,
    },
    /// A call to the node failed.
    #[error("{method} failed: {why}")]
    Node {
        /// The method called.
        method: &'static str,
        /// What the transport or the node reported.
        why: String,
    },
    /// A certificate or a chain of certificates does not verify.
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),
    /// A committee's members do not hash to the root that commits them.
    #[error("the committee's members do not match the root that commits them")]
    CommitteeMismatch,
    /// A certificate, a session certificate or a committee does not verify.
    #[error(transparent)]
    Finality(#[from] FinalityError),
    /// The checkpoint is older than one already certified.
    #[error("checkpoint {got} is older than checkpoint {held}, already certified")]
    Stale {
        /// Index of the newest checkpoint held.
        held: u64,
        /// Index of the checkpoint offered.
        got: u64,
    },
    /// Two certificates of one committee contradict each other. The client
    /// keeps the pair and stops.
    #[error(
        "two certified checkpoints contradict each other at index {}: the committee signed two histories",
        .0.held.proof.checkpoint().index
    )]
    Conflict(Box<Conflict>),
    /// The client found a conflict earlier and checks nothing until the
    /// caller lets it.
    #[error("the client stopped on conflicting certificates")]
    Stopped,
    /// A saved state is behind the checkpoint the caller saw the client
    /// reach: an older state was put back.
    #[error("the saved state reaches checkpoint {got}; the client had reached {at_least}")]
    SavedStateBehind {
        /// The index the caller last saw the client reach.
        at_least: u64,
        /// The index the saved state reaches.
        got: u64,
    },
    /// A handover was offered on a checkpoint that does not end its epoch.
    #[error("the checkpoint does not end its epoch")]
    NotEpochEnd,
    /// The checkpoint is older than the caller allows.
    #[error("the checkpoint is {age_ms} ms old, more than the {max_age_ms} ms allowed")]
    TooOld {
        /// Age of the checkpoint against the caller's clock.
        age_ms: u64,
        /// The caller's bound.
        max_age_ms: u64,
    },
    /// The checkpoint's time is further ahead of the caller's clock than the
    /// caller tolerates.
    #[error(
        "the checkpoint is {ahead_ms} ms ahead of the clock, more than the {max_ahead_ms} ms allowed"
    )]
    AheadOfClock {
        /// How far ahead of the caller's clock the checkpoint is.
        ahead_ms: u64,
        /// The caller's bound.
        max_ahead_ms: u64,
    },
    /// A state proof is for another height than the checkpoint certifies.
    #[error("the proof is for height {got}; the checkpoint certifies the state at height {want}")]
    HeightMismatch {
        /// Height the checkpoint's state root is of.
        want: u64,
        /// Height the proof names.
        got: u64,
    },
    /// The state trie never hashes with the scheme a proof names.
    #[error("the state trie does not hash with the scheme the proof names")]
    UnknownScheme,
    /// A state proof does not reconstruct the certified root.
    #[error(transparent)]
    Proof(#[from] ProofError),
}

/// Result of a light client check.
pub type Result<T> = std::result::Result<T, LightError>;

pub(crate) fn malformed(what: &'static str, why: impl ToString) -> LightError {
    LightError::Malformed {
        what,
        why: why.to_string(),
    }
}
