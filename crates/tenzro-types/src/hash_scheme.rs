//! Hash functions of the chain's commitments, and which one a block header
//! of a given protocol version is hashed with.
//!
//! A header is hashed with the scheme its own `protocol_version` selects,
//! so a block keeps the hash it was made with whatever version came after
//! it, and a change of hash function takes effect at the height a protocol
//! upgrade activates.

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// A hash function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashScheme {
    /// SHA-256 (FIPS 180-4). Every block made before hash schemes were
    /// named is hashed with it.
    #[default]
    Sha256,
    /// SHA3-256 (FIPS 202).
    Sha3_256,
    /// BLAKE3, the checkpoint digest's function before schemes were named.
    Blake3,
}

impl HashScheme {
    /// The scheme's id.
    pub const fn id(self) -> u8 {
        match self {
            Self::Sha256 => 0,
            Self::Sha3_256 => 1,
            Self::Blake3 => 2,
        }
    }

    /// The scheme with `id`.
    pub fn from_id(id: u8) -> Option<Self> {
        [Self::Sha256, Self::Sha3_256, Self::Blake3]
            .into_iter()
            .find(|s| s.id() == id)
    }

    /// The 32-byte digest of `bytes`.
    pub fn digest(self, bytes: &[u8]) -> [u8; 32] {
        match self {
            Self::Sha256 => sha2::Sha256::digest(bytes).into(),
            Self::Sha3_256 => sha3::Sha3_256::digest(bytes).into(),
            Self::Blake3 => blake3::hash(bytes).into(),
        }
    }
}

/// The block header hash scheme from each protocol version on: a header
/// takes the scheme of the last entry whose version is at most its own.
/// Entries are in version order and the first is version 0. A protocol
/// upgrade that changes the hash adds an entry for the version it names.
pub const BLOCK_HASH_SCHEMES: &[(u32, HashScheme)] = &[(0, HashScheme::Sha256)];

/// The scheme `schemes` gives a header of `version`.
pub fn block_hash_scheme(version: u32, schemes: &[(u32, HashScheme)]) -> HashScheme {
    scheme_from(
        u64::from(version),
        schemes.iter().map(|(v, s)| (u64::from(*v), *s)),
    )
}

/// The state trie node hash scheme from each protocol version on. A change
/// re-commits the whole state under the new scheme at the first block of
/// the version that names it.
pub const STATE_TRIE_HASH_SCHEMES: &[(u32, HashScheme)] = &[(0, HashScheme::Sha256)];

/// The checkpoint digest scheme from each epoch on. A checkpoint carries no
/// protocol version but every checkpoint names its epoch, which a light
/// client reads without executing anything, so its digest is selected by
/// epoch: a protocol upgrade that changes it adds an entry for the first
/// epoch after its activation.
pub const CHECKPOINT_DIGEST_SCHEMES: &[(u64, HashScheme)] = &[(0, HashScheme::Blake3)];

/// The transaction hash scheme by `valid_until` (Unix ms): a transaction
/// carries no protocol version, but it names the last time it may execute,
/// which its signer and every node read from the transaction alone. A
/// protocol upgrade that changes the hash adds an entry from a time after
/// its activation.
pub const TX_HASH_SCHEMES: &[(u64, HashScheme)] = &[(0, HashScheme::Sha256)];

/// The scheme of the last entry of `schemes` (in order) at or below `at`.
pub fn scheme_from(at: u64, schemes: impl IntoIterator<Item = (u64, HashScheme)>) -> HashScheme {
    schemes
        .into_iter()
        .take_while(|(from, _)| *from <= at)
        .last()
        .map(|(_, s)| s)
        .unwrap_or_default()
}
