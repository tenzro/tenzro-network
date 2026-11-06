//! Tenzro checkpoint finality.
//!
//! The checks that make a checkpoint final, with nothing a node needs to run
//! them: the committee of an epoch and its quorum, the session certificates
//! by which validators' hardware keys vouch for their vote keys, and
//! checkpoints. Consensus builds on these types; a light client
//! runs [`step::FinalityStep::verify`], natively or inside a zkVM whose
//! proof another chain checks.

pub mod chain;
pub mod checkpoint;
pub mod committee;
pub mod error;
pub mod key;
pub mod session;
pub mod step;

/// A 32-byte digest.
pub type Digest = [u8; 32];
/// A consensus round.
pub type Round = u64;

pub use error::{FinalityError, Result};
