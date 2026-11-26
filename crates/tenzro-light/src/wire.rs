//! Decoding what a node serves: hex bincode of the finality types.

use bincode::Options as _;
use serde::de::DeserializeOwned;
use tenzro_finality::checkpoint::Certificate;
use tenzro_finality::committee::Member;
use tenzro_finality::session::SessionCertificate;

use crate::error::{Result, malformed};

/// Most bytes one encoded value may decode to. A committee of a thousand
/// members, each with an ML-DSA-87 key, a session certificate and a
/// signature, stays under half of it.
pub const MAX_ENCODED_BYTES: usize = 16 << 20;

/// Bytes from hex, with or without a `0x` prefix. Input longer than
/// [`MAX_ENCODED_BYTES`] decoded is refused before anything is allocated.
pub fn bytes(what: &'static str, hex_str: &str) -> Result<Vec<u8>> {
    let digits = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if digits.len() / 2 > MAX_ENCODED_BYTES {
        return Err(malformed(
            what,
            format!("longer than {MAX_ENCODED_BYTES} bytes"),
        ));
    }
    hex::decode(digits).map_err(|e| malformed(what, e))
}

/// 32 bytes from hex.
pub fn digest(what: &'static str, hex_str: &str) -> Result<[u8; 32]> {
    bytes(what, hex_str)?
        .try_into()
        .map_err(|_| malformed(what, "not 32 bytes"))
}

/// Decodes the node's bincode. No length inside the input can ask for more
/// memory than the input is long, and bytes left over are refused.
fn decode<T: DeserializeOwned>(what: &'static str, hex_str: &str) -> Result<T> {
    let raw = bytes(what, hex_str)?;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(raw.len() as u64)
        .deserialize(&raw)
        .map_err(|e| malformed(what, e))
}

/// A checkpoint certificate.
pub fn certificate(hex_str: &str) -> Result<Certificate> {
    decode("certificate", hex_str)
}

/// The session certificates a checkpoint certificate names.
pub fn sessions(hex_str: &str) -> Result<Vec<SessionCertificate>> {
    decode("session certificates", hex_str)
}

/// A compact certificate.
#[cfg(feature = "compact")]
pub fn compact_certificate(hex_str: &str) -> Result<crate::compact::CompactCertificate> {
    decode("compact certificate", hex_str)
}

/// The members of a committee, in committee order.
pub fn members(hex_str: &str) -> Result<Vec<Member>> {
    decode("committee members", hex_str)
}
