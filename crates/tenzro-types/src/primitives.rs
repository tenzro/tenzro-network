//! Core primitive types for Tenzro Network
//!
//! This module defines the fundamental building blocks used throughout
//! the Tenzro Network blockchain.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A 32-byte hash value used throughout Tenzro Network
///
/// Hashes are used for block hashes, transaction hashes, Merkle roots,
/// and other cryptographic commitments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Creates a new Hash from a 32-byte array
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the hash as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Creates a Hash from a byte slice
    ///
    /// Returns None if the slice is not exactly 32 bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(Self(arr))
        } else {
            None
        }
    }

    /// Returns a zero hash (all zeros)
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Combines two hashes using SHA-256
    ///
    /// This method is collision-resistant, unlike XOR-based combination.
    /// It concatenates the two hashes and returns the SHA-256 hash of the result.
    pub fn combine(&self, other: &Hash) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        hasher.update(other.0);
        let result = hasher.finalize();
        Self(result.into())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::zero()
    }
}

/// An address on Tenzro Network
///
/// Addresses are derived from public keys and identify accounts,
/// smart contracts, and other entities on the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// Creates a new Address from a 32-byte array
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the address as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Creates an Address from a byte slice
    ///
    /// Returns None if the slice is not exactly 32 bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(Self(arr))
        } else {
            None
        }
    }

    /// Returns a zero address (all zeros)
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Encodes the address as a base58 string
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// Decodes an address from a base58 string
    pub fn from_base58(s: &str) -> Result<Self, bs58::decode::Error> {
        let bytes = bs58::decode(s).into_vec()?;
        Self::from_bytes(&bytes).ok_or(bs58::decode::Error::BufferTooSmall)
    }

    /// Validates that a hex string is properly formatted
    ///
    /// Returns true if the string is valid hexadecimal (with or without 0x prefix)
    pub fn is_valid_hex(s: &str) -> bool {
        let s = s.strip_prefix("0x").unwrap_or(s);
        s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Creates an address from a hex string.
    ///
    /// For 20-byte Ethereum addresses (40 hex chars), validates EIP-55 checksum.
    /// For 32-byte Tenzro addresses (64 hex chars), validates hex format.
    /// Use this as the default entry point for hex address parsing.
    pub fn from_hex(s: &str) -> Result<Self, crate::error::TenzroError> {
        Self::from_hex_checksummed(s)
    }

    /// Creates an address from a hex string with EIP-55 checksum validation
    ///
    /// For Ethereum-style addresses (20 bytes), this validates the EIP-55 mixed-case
    /// checksum. The hex string should be 40 characters (or 42 with 0x prefix).
    pub fn from_hex_checksummed(s: &str) -> Result<Self, crate::error::TenzroError> {
        let s = s.strip_prefix("0x").unwrap_or(s);

        // For 20-byte Ethereum addresses, validate EIP-55 checksum
        if s.len() == 40 {
            // Decode the hex
            let bytes = hex::decode(s).map_err(|e| {
                crate::error::TenzroError::InvalidAddress(format!("Invalid hex: {}", e))
            })?;

            // Compute Keccak-256 hash of the lowercase address
            use sha3::{Digest, Keccak256};
            let mut hasher = Keccak256::new();
            hasher.update(s.to_lowercase().as_bytes());
            let hash = hasher.finalize();

            // Verify checksum (mixed case encoding)
            for (i, c) in s.chars().enumerate() {
                if c.is_alphabetic() {
                    let hash_byte = hash[i / 2];
                    let hash_nibble = if i % 2 == 0 {
                        hash_byte >> 4
                    } else {
                        hash_byte & 0x0f
                    };

                    let should_be_uppercase = hash_nibble >= 8;
                    if c.is_uppercase() != should_be_uppercase {
                        return Err(crate::error::TenzroError::InvalidAddress(
                            "Invalid EIP-55 checksum".to_string(),
                        ));
                    }
                }
            }

            // Pad to 32 bytes for our Address type
            let mut addr = [0u8; 32];
            addr[12..].copy_from_slice(&bytes);
            Ok(Self(addr))
        } else if s.len() == 64 {
            // 32-byte address (full Tenzro address)
            let bytes = hex::decode(s).map_err(|e| {
                crate::error::TenzroError::InvalidAddress(format!("Invalid hex: {}", e))
            })?;
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&bytes);
            Ok(Self(addr))
        } else {
            Err(crate::error::TenzroError::InvalidAddress(format!(
                "Invalid address length: expected 40 or 64 hex chars, got {}",
                s.len()
            )))
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl From<[u8; 32]> for Address {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::zero()
    }
}

/// A cryptographic signature on Tenzro Network
///
/// Signatures are used to prove ownership and authorize transactions.
///
/// Both `bytes` and `public_key` are bounded at deserialization time to
/// `MAX_SIGNATURE_BYTES` and `MAX_PUBLIC_KEY_BYTES` respectively, to protect
/// against OOM via untrusted payloads (HIGH #69 in the production audit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Signature {
    /// The signature bytes
    #[serde(deserialize_with = "crate::validation::bounded_signature_bytes")]
    pub bytes: Vec<u8>,
    /// The public key used to verify the signature
    #[serde(deserialize_with = "crate::validation::bounded_public_key_bytes")]
    pub public_key: Vec<u8>,
}

impl Signature {
    /// Creates a new Signature
    pub fn new(bytes: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self { bytes, public_key }
    }
}

/// The height of a block in the Tenzro Network blockchain
///
/// Block height starts at 0 for the genesis block and increments by 1 for each block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockHeight(pub u64);

impl BlockHeight {
    /// Creates a new BlockHeight
    pub fn new(height: u64) -> Self {
        Self(height)
    }

    /// Returns the genesis block height (0)
    pub fn genesis() -> Self {
        Self(0)
    }

    /// Returns the next block height
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// Returns the previous block height, or None if this is the genesis block
    pub fn prev(self) -> Option<Self> {
        if self.0 > 0 {
            Some(Self(self.0 - 1))
        } else {
            None
        }
    }
}

impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for BlockHeight {
    fn from(height: u64) -> Self {
        Self(height)
    }
}

impl Default for BlockHeight {
    fn default() -> Self {
        Self::genesis()
    }
}

impl BlockHeight {
    /// Returns the height as a u64
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::ops::Add<u64> for BlockHeight {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl std::ops::Sub<u64> for BlockHeight {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_sub(rhs))
    }
}

/// A transaction nonce for replay protection
///
/// The nonce ensures that each transaction from an account is unique
/// and prevents replay attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Nonce(pub u64);

impl Nonce {
    /// Creates a new Nonce
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the initial nonce (0)
    pub fn initial() -> Self {
        Self(0)
    }

    /// Returns the next nonce
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for Nonce {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

/// A timestamp representing Unix time in milliseconds
///
/// Used for block timestamps and time-based operations.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// Creates a new Timestamp
    pub fn new(millis: i64) -> Self {
        Self(millis)
    }

    /// Returns the current timestamp
    pub fn now() -> Self {
        Self(chrono::Utc::now().timestamp_millis())
    }

    /// Returns the timestamp as milliseconds since Unix epoch
    pub fn as_millis(&self) -> i64 {
        self.0
    }

    /// Returns the timestamp as seconds since Unix epoch
    pub fn as_secs(&self) -> i64 {
        self.0 / 1000
    }
}

impl From<Timestamp> for std::time::SystemTime {
    fn from(ts: Timestamp) -> Self {
        std::time::UNIX_EPOCH + std::time::Duration::from_millis(ts.0 as u64)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<i64> for Timestamp {
    fn from(millis: i64) -> Self {
        Self(millis)
    }
}

/// The chain identifier for Tenzro Network
///
/// Used to prevent cross-chain replay attacks and identify the network.
///
/// Deserialization enforces the EIP-2294 range `[1, (u64::MAX / 2) - 36]`
/// to reject obviously-bad chain ids early (HIGH #70 in the production audit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct ChainId(pub u64);

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        let chain = ChainId(value);
        crate::validation::validate_chain_id(chain).map_err(serde::de::Error::custom)?;
        Ok(chain)
    }
}

impl ChainId {
    /// Mainnet chain ID
    pub const MAINNET: Self = Self(1);

    /// Testnet chain ID
    pub const TESTNET: Self = Self(1337);

    /// Devnet chain ID
    pub const DEVNET: Self = Self(31337);

    /// Creates a new ChainId without validation.
    ///
    /// Prefer [`ChainId::try_new`] when constructing from untrusted input.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Creates a new ChainId, returning an error if `id` is outside the
    /// allowed range `[CHAIN_ID_MIN, CHAIN_ID_MAX]`.
    ///
    /// The upper bound (`(u64::MAX / 2) - 36`) follows EIP-2294 to avoid
    /// overflow when combined with EIP-155 transaction signing.
    pub fn try_new(id: u64) -> Result<Self, crate::error::TenzroError> {
        let chain = Self(id);
        crate::validation::validate_chain_id(chain)?;
        Ok(chain)
    }

    /// Returns the mainnet chain ID
    pub fn mainnet() -> Self {
        Self::MAINNET
    }

    /// Returns the testnet chain ID
    pub fn testnet() -> Self {
        Self::TESTNET
    }

    /// Returns the devnet chain ID
    pub fn devnet() -> Self {
        Self::DEVNET
    }

    /// Returns the inner u64 chain id.
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Validates that the chain ID is within the allowed range.
    ///
    /// Allowed range follows EIP-2294: `[1, (u64::MAX / 2) - 36]`.
    pub fn is_valid(&self) -> bool {
        crate::validation::validate_chain_id(*self).is_ok()
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for ChainId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

/// Serde adapter for `u128` fields that may carry values larger than
/// `u64::MAX` (e.g. base-unit token amounts at 10^18 precision).
///
/// `serde_json`'s default number deserializer falls through `u64 → i64 →
/// f64` and refuses values exceeding `u64::MAX` (~1.84×10^19) — which
/// breaks reference templates whose delegation caps are denominated in
/// 10^18-base-unit TNZO (e.g. `5_000_000_000_000_000_000_000`).
///
/// This adapter accepts both:
///   - JSON numbers (any integer up to `u128::MAX` that fits in a
///     `serde_json::Number`)
///   - JSON strings (decimal digits only, no sign, no underscores)
///
/// On serialization it emits a number when the value fits `u64` and a
/// decimal string otherwise, preserving readability for typical small
/// values while remaining lossless for large ones.
///
/// Apply via `#[serde(with = "u128_serde")]` on a `u128` field.
pub mod u128_serde {
    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        // Only self-describing formats get the number-or-string treatment.
        //
        // Choosing the representation from the *value* means the encoded layout
        // is value-dependent. JSON can cope — the decoder sees a token type and
        // dispatches. A fixed-layout format like bincode cannot: the decoder
        // has only the schema to go on, so a field that is sometimes a u64 and
        // sometimes a string is undecodable. Emitting the native 16-byte u128
        // there keeps the layout constant, which is what such formats require.
        if !serializer.is_human_readable() {
            return serializer.serialize_u128(*value);
        }
        if *value <= u64::MAX as u128 {
            serializer.serialize_u64(*value as u64)
        } else {
            // Beyond u64 a JSON number cannot round-trip through the usual
            // f64-backed parsers without precision loss, so widen to a string.
            serializer.serialize_str(&value.to_string())
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        struct U128Visitor;

        impl<'de> Visitor<'de> for U128Visitor {
            type Value = u128;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a non-negative integer or decimal string fitting in u128")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<u128, E> {
                Ok(v as u128)
            }

            fn visit_u128<E: de::Error>(self, v: u128) -> Result<u128, E> {
                Ok(v)
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<u128, E> {
                if v < 0 {
                    Err(E::custom(format!(
                        "negative integer {v} is not a valid u128"
                    )))
                } else {
                    Ok(v as u128)
                }
            }

            fn visit_i128<E: de::Error>(self, v: i128) -> Result<u128, E> {
                if v < 0 {
                    Err(E::custom(format!(
                        "negative integer {v} is not a valid u128"
                    )))
                } else {
                    Ok(v as u128)
                }
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<u128, E> {
                s.parse::<u128>()
                    .map_err(|e| E::custom(format!("invalid u128 string {s:?}: {e}")))
            }

            fn visit_string<E: de::Error>(self, s: String) -> Result<u128, E> {
                self.visit_str(&s)
            }

            /// serde_json routes any JSON integer literal that exceeds `u64` to
            /// `visit_f64` under `deserialize_any` — `5000000000000000000000`
            /// arrives here as `5e21`, not through `visit_u128`.
            ///
            /// Refuse it. An `f64` carries 53 bits of mantissa, so beyond 2^53
            /// it cannot represent every integer: `5000000000000000000001`
            /// parses to the same `5e21` and would decode as
            /// `5000000000000000000000`. These fields carry billable work units
            /// and token amounts, where silently rounding is far worse than
            /// refusing, and the caller cannot tell it happened.
            ///
            /// There is no loss of expressiveness — `serialize` above emits a
            /// quoted decimal string above `u64::MAX`, so anything this crate
            /// produces round-trips. Only hand-written JSON with a bare oversized
            /// integer lands here, and the message says how to fix it.
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<u128, E> {
                Err(E::custom(format!(
                    "JSON number {v} exceeds u64 and was parsed as floating point, \
                     which cannot represent it exactly; quote it as a decimal \
                     string (e.g. \"{}\") to preserve precision",
                    if v.is_finite() && v >= 0.0 && v.fract() == 0.0 {
                        format!("{v:.0}")
                    } else {
                        "<integer>".to_string()
                    }
                )))
            }
        }

        // `deserialize_any` requires the format to be self-describing. bincode
        // and other fixed-layout formats return
        // `DeserializeAnyNotSupported` for it, which is how a `BillableUnits`
        // (whose `pixel_steps` uses this module) failed to decode from RocksDB
        // and silently hydrated as empty.
        //
        // Ask the format which it is, and pair each branch with the matching
        // arm of `serialize` above.
        if deserializer.is_human_readable() {
            deserializer.deserialize_any(U128Visitor)
        } else {
            deserializer.deserialize_u128(U128Visitor)
        }
    }
}

/// Serde adapter for `serde_json::Value` fields that have to survive a
/// non-self-describing format. Apply via
/// `#[serde(with = "tenzro_types::primitives::json_value_serde")]`.
///
/// `serde_json::Value` deserializes by calling `deserialize_any` — it has to,
/// since the shape is only known from the data. bincode and other fixed-layout
/// formats cannot answer that, so a struct carrying a bare `Value` *encodes*
/// happily and then fails to decode with:
///
/// ```text
/// Bincode does not support the serde::Deserializer::deserialize_any method
/// ```
///
/// which is silent until something tries to read the row back.
///
/// Human-readable formats embed the value inline exactly as before, so JSON
/// output is unchanged. Everything else carries it as its JSON text, which has
/// a definite layout bincode can length-prefix.
pub mod json_value_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_json::Value;

    pub fn serialize<S: Serializer>(value: &Value, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            value.serialize(serializer)
        } else {
            serializer.serialize_str(&value.to_string())
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
        if deserializer.is_human_readable() {
            Value::deserialize(deserializer)
        } else {
            let text = String::deserialize(deserializer)?;
            serde_json::from_str(&text).map_err(serde::de::Error::custom)
        }
    }
}

/// `Option<u128>` adapter mirroring [`u128_serde`] semantics. Apply via
/// `#[serde(default, with = "u128_serde_opt")]` on an `Option<u128>` field.
///
/// Accepts JSON `null`/missing → `None`, JSON number or decimal string → `Some`.
/// Serializes `None` as `null`, `Some(v)` as a number when it fits `u64`,
/// otherwise as a decimal string.
pub mod u128_serde_opt {
    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(
        value: &Option<u128>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        // Same split as `u128_serde::serialize` — see the reasoning there.
        // Non-self-describing formats need `Option` encoded as their own
        // native option representation with a fixed-layout payload.
        if !serializer.is_human_readable() {
            return match value {
                None => serializer.serialize_none(),
                Some(v) => serializer.serialize_some(&U128Native(*v)),
            };
        }
        match value {
            None => serializer.serialize_none(),
            Some(v) if *v <= u64::MAX as u128 => serializer.serialize_u64(*v as u64),
            Some(v) => serializer.serialize_str(&v.to_string()),
        }
    }

    /// Newtype that always serializes as a native `u128`, used for the
    /// non-human-readable `Some(_)` payload so the layout never varies.
    struct U128Native(u128);

    impl serde::Serialize for U128Native {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_u128(self.0)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u128>, D::Error> {
        struct OptU128Visitor;

        impl<'de> Visitor<'de> for OptU128Visitor {
            type Value = Option<u128>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("null, a non-negative integer, or a decimal string fitting in u128")
            }

            fn visit_unit<E: de::Error>(self) -> Result<Option<u128>, E> {
                Ok(None)
            }

            fn visit_none<E: de::Error>(self) -> Result<Option<u128>, E> {
                Ok(None)
            }

            fn visit_some<D2: Deserializer<'de>>(
                self,
                deserializer: D2,
            ) -> Result<Option<u128>, D2::Error> {
                super::u128_serde::deserialize(deserializer).map(Some)
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Option<u128>, E> {
                Ok(Some(v as u128))
            }

            fn visit_u128<E: de::Error>(self, v: u128) -> Result<Option<u128>, E> {
                Ok(Some(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Option<u128>, E> {
                if v < 0 {
                    Err(E::custom(format!(
                        "negative integer {v} is not a valid u128"
                    )))
                } else {
                    Ok(Some(v as u128))
                }
            }

            fn visit_i128<E: de::Error>(self, v: i128) -> Result<Option<u128>, E> {
                if v < 0 {
                    Err(E::custom(format!(
                        "negative integer {v} is not a valid u128"
                    )))
                } else {
                    Ok(Some(v as u128))
                }
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<Option<u128>, E> {
                s.parse::<u128>()
                    .map(Some)
                    .map_err(|e| E::custom(format!("invalid u128 string {s:?}: {e}")))
            }

            fn visit_string<E: de::Error>(self, s: String) -> Result<Option<u128>, E> {
                self.visit_str(&s)
            }
        }

        // See `u128_serde::deserialize` — `deserialize_any` is unavailable on
        // fixed-layout formats, so pair each branch with its `serialize` arm.
        if deserializer.is_human_readable() {
            deserializer.deserialize_any(OptU128Visitor)
        } else {
            deserializer.deserialize_option(OptU128Visitor)
        }
    }
}

#[cfg(test)]
mod u128_serde_tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Wrap {
        #[serde(with = "super::u128_serde")]
        v: u128,
    }

    #[test]
    fn round_trips_small_value_as_number() {
        let w = Wrap { v: 42 };
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, r#"{"v":42}"#);
        let back: Wrap = serde_json::from_str(&json).unwrap();
        assert_eq!(back, w);
    }

    #[test]
    fn round_trips_large_value_as_string() {
        let w = Wrap {
            v: 5_000_000_000_000_000_000_000u128,
        };
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, r#"{"v":"5000000000000000000000"}"#);
        let back: Wrap = serde_json::from_str(&json).unwrap();
        assert_eq!(back, w);
    }

    #[test]
    fn rejects_large_raw_number_rather_than_rounding_it() {
        // serde_json parses a bare integer literal above u64::MAX as f64, so
        // this arrives as 5e21. Accepting it would mean accepting silent
        // rounding: `5000000000000000000001` parses to the *same* f64 and
        // would decode as ...000. These fields carry billable units and token
        // amounts, so the decode is refused instead.
        let json = r#"{"v":5000000000000000000000}"#;
        let err = serde_json::from_str::<Wrap>(json)
            .expect_err("bare integer above u64::MAX must not decode via f64");
        assert!(
            err.to_string().contains("quote it as a decimal string"),
            "error should tell the producer how to fix it, got: {err}"
        );

        // The supported spelling for the same value, which is also what
        // `serialize` emits above u64::MAX.
        let quoted = r#"{"v":"5000000000000000000000"}"#;
        let back: Wrap = serde_json::from_str(quoted).unwrap();
        assert_eq!(back.v, 5_000_000_000_000_000_000_000u128);
    }

    #[test]
    fn deserializes_string_at_u64_boundary() {
        let json = r#"{"v":"18446744073709551616"}"#; // u64::MAX + 1
        let back: Wrap = serde_json::from_str(json).unwrap();
        assert_eq!(back.v, (u64::MAX as u128) + 1);
    }

    #[test]
    fn rejects_negative_string() {
        let json = r#"{"v":"-1"}"#;
        assert!(serde_json::from_str::<Wrap>(json).is_err());
    }

    #[test]
    fn rejects_negative_number() {
        let json = r#"{"v":-1}"#;
        assert!(serde_json::from_str::<Wrap>(json).is_err());
    }
}
