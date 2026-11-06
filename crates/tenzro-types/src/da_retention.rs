//! Objects in the data-availability layer, as consensus state records them.
//!
//! A committee member that certifies an object records it on chain with its
//! class and size. Each class has a governed retention; once an object's
//! retention has passed, block execution expires it, every committee member
//! drops its slivers, and storage is no longer owed for it.

use serde::{Deserialize, Serialize};

/// What an object in the data-availability layer holds, which decides how
/// long it is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaObjectClass {
    /// A segment of block history that left validators' local stores.
    History,
    /// Agent audit and telemetry entries with their proofs.
    Audit,
}

impl DaObjectClass {
    /// The class an object written under `namespace` belongs to.
    pub fn of_namespace(namespace: &[u8]) -> Self {
        if namespace.starts_with(b"tenzro/history") {
            Self::History
        } else {
            Self::Audit
        }
    }
}

/// An operation on the object registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaRetentionOp {
    /// A committee member records an object it certified. Retention runs
    /// from the block time the record executes at.
    Record {
        /// The object's commitment, hex.
        commitment: String,
        /// Its class.
        class: DaObjectClass,
        /// Its size, bytes.
        size_bytes: u64,
    },
}

impl DaRetentionOp {
    /// Shape limits.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Record {
                commitment,
                size_bytes,
                ..
            } => {
                if commitment.len() != 64 || hex::decode(commitment).is_err() {
                    return Err("a commitment is 32 bytes of hex");
                }
                if *size_bytes == 0 {
                    return Err("an object has a size");
                }
            }
        }
        Ok(())
    }
}

/// An object as consensus state records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaObject {
    /// The commitment, hex.
    pub commitment: String,
    pub class: DaObjectClass,
    pub size_bytes: u64,
    /// The committee member that recorded it, hex.
    pub recorder: String,
    /// Block time of the record, ms.
    pub recorded_at_ms: i64,
    /// Block time from which it is expired, ms.
    pub expires_at_ms: i64,
    /// Block time it was expired at, once it was.
    pub expired_at_ms: Option<i64>,
}

impl DaObject {
    /// Whether the object is still kept.
    pub fn is_live(&self) -> bool {
        self.expired_at_ms.is_none()
    }
}
