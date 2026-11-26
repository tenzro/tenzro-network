//! A builder's attestation that it rebuilt a release binary.
//!
//! An account bonded in the attestor role rebuilds release `version` for
//! `platform` from its published source and states the SHA-256 it got. The
//! rule that counts attestations before a protocol upgrade enacts is in
//! `tenzro-vm`.

use serde::{Deserialize, Serialize};

/// The attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildAttestationOp {
    /// The release, `major.minor.patch`.
    pub version: String,
    /// The target triple it was built for.
    pub platform: String,
    /// SHA-256 of the binary, 32 bytes, hex.
    #[serde(with = "hex::serde")]
    pub code_hash: Vec<u8>,
}

impl BuildAttestationOp {
    /// The version and platform are well formed and the hash is 32 bytes.
    pub fn validate(&self) -> Result<(), &'static str> {
        let platform_ok = !self.platform.is_empty()
            && self.platform.len() <= 64
            && self
                .platform
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if self.version.trim().is_empty() || self.version.len() > 64 || !platform_ok {
            return Err(
                "a build attestation names a version (1..=64 characters) and a target triple",
            );
        }
        if self.code_hash.len() != 32 {
            return Err("a build attestation carries the 32-byte SHA-256 of the binary");
        }
        Ok(())
    }
}
