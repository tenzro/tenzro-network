//! The range of chain protocol versions a binary can execute.
//!
//! The chain's protocol version lives in consensus state (see
//! [`crate::native::protocol_version_at`]). Each binary declares the
//! inclusive `[min, max]` it understands; outside it, the node must stop
//! rather than execute blocks it may interpret differently from the network.

use serde::{Deserialize, Serialize};

/// The lowest chain protocol version this binary can execute. The chain's
/// version is the one genesis records (`[protocol] version`) and an enacted
/// upgrade raises at its activation height; the header's
/// `metadata.protocol_version` carries the same number. Version 1 is the
/// retired classical-only wire format; 2 is the PQ-hybrid era.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 2;

/// The highest chain protocol version this binary can execute. A binary
/// that predates a version names its predecessor here, so it stops at the
/// height that version activates instead of forking from the network.
pub const MAX_SUPPORTED_PROTOCOL_VERSION: u32 = 2;

/// An inclusive range of protocol versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolRange {
    /// Lowest version supported.
    pub min: u32,
    /// Highest version supported.
    pub max: u32,
}

/// A chain protocol version outside the range a binary supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolMismatch {
    /// The version the chain runs.
    pub chain: u32,
    /// What the binary supports.
    pub supported: ProtocolRange,
}

impl std::fmt::Display for ProtocolMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let side = if self.chain > self.supported.max {
            "newer than this binary understands; upgrade the node binary"
        } else {
            "older than this binary supports; this binary cannot replay that chain"
        };
        write!(
            f,
            "protocol version mismatch: the chain runs protocol version {} but this binary supports \
             protocol versions {} to {}; the chain's version is {side}. \
             Stopping rather than risk forking from the network.",
            self.chain, self.supported.min, self.supported.max
        )
    }
}

impl std::error::Error for ProtocolMismatch {}

impl ProtocolRange {
    /// The range this binary was built to support.
    pub const fn this_binary() -> Self {
        Self {
            min: MIN_SUPPORTED_PROTOCOL_VERSION,
            max: MAX_SUPPORTED_PROTOCOL_VERSION,
        }
    }

    /// Whether `version` is in the range.
    pub const fn contains(&self, version: u32) -> bool {
        self.min <= version && version <= self.max
    }

    /// `Ok` when the chain's `version` is in the range.
    pub fn check(&self, version: u32) -> Result<(), ProtocolMismatch> {
        if self.contains(version) {
            Ok(())
        } else {
            Err(ProtocolMismatch {
                chain: version,
                supported: *self,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_range_is_inclusive_at_both_ends() {
        let r = ProtocolRange { min: 2, max: 4 };
        assert!(r.check(2).is_ok() && r.check(4).is_ok());
        assert!(r.check(1).is_err() && r.check(5).is_err());
    }

    #[test]
    fn the_message_names_the_versions_and_the_direction() {
        let r = ProtocolRange { min: 2, max: 2 };
        let newer = r.check(3).unwrap_err().to_string();
        assert!(newer.contains("protocol version 3"), "{newer}");
        assert!(newer.contains("2 to 2"), "{newer}");
        assert!(newer.contains("upgrade the node binary"), "{newer}");
        let older = r.check(1).unwrap_err().to_string();
        assert!(older.contains("older than this binary supports"), "{older}");
    }

    #[test]
    fn this_binary_supports_a_non_empty_range() {
        let r = ProtocolRange::this_binary();
        assert!(r.min <= r.max);
    }
}
