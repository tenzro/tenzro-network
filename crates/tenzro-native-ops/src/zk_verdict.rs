//! A validator's verdict that a zero-knowledge proof verifies.
//!
//! A proof is larger than a block can carry, so it reaches validators
//! directly and each runs the verifier on it outside block execution. A
//! bonded validator then states what it verified: the statement, the proof's
//! commitment and the proof system. The rule that records a proof once
//! validators holding two thirds of the bonded stake have stated the same
//! verdict is in `tenzro-vm`.

use serde::{Deserialize, Serialize};

/// The verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkVerdictOp {
    /// The statement's commitment (`tenzro_zk::statement_commitment` of the
    /// circuit and public inputs), 32 bytes, hex.
    #[serde(with = "hex::serde")]
    pub statement: Vec<u8>,
    /// The proof's commitment (the one the ZK_VERIFY registry keys a proof
    /// by), 32 bytes, hex.
    #[serde(with = "hex::serde")]
    pub proof: Vec<u8>,
    /// The proof system's tag (`tenzro_zk::ProofSystem::as_str`).
    pub system: String,
}

impl ZkVerdictOp {
    /// Both commitments are 32 bytes and the system names a tag of
    /// 1..=64 bytes; the VM checks the tag against the proof systems.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.statement.len() != 32 || self.proof.len() != 32 {
            return Err("a ZK verdict carries the 32-byte statement and proof commitments");
        }
        if self.system.is_empty() || self.system.len() > 64 {
            return Err("a ZK verdict names its proof system (1..=64 bytes)");
        }
        Ok(())
    }
}
