//! Permit2 SignatureTransfer primitive — single-signature token approval
//! and pull for Tenzro EVM.
//!
//! Permit2 lets a token holder sign a one-shot authorization that a third
//! party (a relayer, a settler, a solver) can use to pull `amount` of
//! `token` to a `recipient`, all in one transaction. The authorization
//! is bound to a `nonce` (for replay protection) and a `deadline` (for
//! expiry), and may carry a `witness` payload — an opaque 32-byte hash
//! that ties the permit to an off-chain artifact such as an ERC-7683
//! cross-chain order.
//!
//! This module implements the protocol-level primitive: the
//! `PermitTransferFrom` and `PermitTransferFromWitness` types, the
//! EIP-712 digest computation, the secp256k1 recovery, and the nonce
//! bitmap state. The EVM precompile at `0x1023` calls into this module;
//! see [`crate::precompiles`].

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

use tenzro_types::primitives::Address;

/// EIP-712 domain name — fixed by the Permit2 spec.
pub const PERMIT2_DOMAIN_NAME: &str = "Permit2";

/// `keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)")`.
pub fn eip712_domain_typehash() -> [u8; 32] {
    Keccak256::digest(
        b"EIP712Domain(string name,uint256 chainId,address verifyingContract)",
    )
    .into()
}

/// `keccak256("TokenPermissions(address token,uint256 amount)")`.
pub fn token_permissions_typehash() -> [u8; 32] {
    Keccak256::digest(b"TokenPermissions(address token,uint256 amount)").into()
}

/// `keccak256("PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)")`.
pub fn permit_transfer_typehash() -> [u8; 32] {
    Keccak256::digest(
        b"PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)",
    )
    .into()
}

/// Compute the `PermitTransferFromWitness` typehash for a caller-supplied
/// `witness_type_name` and `witness_type_string`. Per Permit2, the
/// witness piece is inlined into the typehash so that EIP-712 verifiers
/// can render the full struct shape at sign time.
pub fn permit_transfer_witness_typehash(
    witness_type_name: &str,
    witness_type_string: &str,
) -> [u8; 32] {
    let combined = format!(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,{} witness)TokenPermissions(address token,uint256 amount){}",
        witness_type_name, witness_type_string,
    );
    Keccak256::digest(combined.as_bytes()).into()
}

/// Errors arising from Permit2 verification or transfer.
#[derive(Debug, Error)]
pub enum Permit2Error {
    /// The signature could not be recovered.
    #[error("invalid permit signature")]
    InvalidSignature,
    /// The signer does not match the expected owner.
    #[error("signer mismatch: recovered {recovered}, expected owner {owner}")]
    SignerMismatch {
        /// Recovered address, lowercase hex.
        recovered: String,
        /// Expected owner, lowercase hex.
        owner: String,
    },
    /// The permit deadline has passed.
    #[error("permit expired: deadline {deadline}, now {now}")]
    Expired {
        /// Permit deadline (unix seconds).
        deadline: u64,
        /// Current unix-seconds clock.
        now: u64,
    },
    /// The permit's `requested_amount` exceeds the signed `permitted.amount`.
    #[error("requested {requested} exceeds permitted {permitted}")]
    AmountExceedsPermit {
        /// Requested amount.
        requested: String,
        /// Permitted amount.
        permitted: String,
    },
    /// The nonce has already been used by the owner.
    #[error("nonce already used")]
    NonceAlreadyUsed,
    /// The chain id in the permit does not match the current chain id.
    #[error("chain_id mismatch: permit {permit}, current {current}")]
    ChainIdMismatch {
        /// Chain id named in the permit.
        permit: u64,
        /// Current chain id.
        current: u64,
    },
}

/// The signed permit body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPermissions {
    /// Token contract being permitted.
    pub token: Address,
    /// Maximum amount the spender may pull.
    pub amount: [u8; 32],
}

impl TokenPermissions {
    /// `keccak256(token_permissions_typehash() ‖ token32 ‖ amount32)`.
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(&token_permissions_typehash());
        buf.extend_from_slice(&address_as_uint256(&self.token));
        buf.extend_from_slice(&self.amount);
        Keccak256::digest(&buf).into()
    }
}

/// `PermitTransferFrom` body (no witness).
#[derive(Debug, Clone)]
pub struct PermitTransferFrom {
    /// Token permission body.
    pub permitted: TokenPermissions,
    /// Address authorized to spend (typically the settler contract).
    pub spender: Address,
    /// Per-owner nonce (uint256, big-endian).
    pub nonce: [u8; 32],
    /// Expiry, unix-seconds.
    pub deadline: u64,
}

impl PermitTransferFrom {
    /// `keccak256(permit_transfer_typehash() ‖ permitted.struct_hash() ‖ spender ‖ nonce ‖ deadline)`.
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 * 5);
        buf.extend_from_slice(&permit_transfer_typehash());
        buf.extend_from_slice(&self.permitted.struct_hash());
        buf.extend_from_slice(&address_as_uint256(&self.spender));
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&u64_as_uint256(self.deadline));
        Keccak256::digest(&buf).into()
    }

    /// EIP-712 digest: `keccak256(0x19 0x01 ‖ domain_separator ‖ struct_hash)`.
    pub fn digest(&self, domain_separator: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(66);
        buf.push(0x19);
        buf.push(0x01);
        buf.extend_from_slice(domain_separator);
        buf.extend_from_slice(&self.struct_hash());
        Keccak256::digest(&buf).into()
    }
}

/// `PermitTransferFromWitness` body — same shape as
/// [`PermitTransferFrom`] plus a 32-byte witness hash and the witness
/// typestring (used to derive the typehash at verify time).
#[derive(Debug, Clone)]
pub struct PermitTransferFromWitness {
    /// Token permission body.
    pub permitted: TokenPermissions,
    /// Address authorized to spend.
    pub spender: Address,
    /// Per-owner nonce.
    pub nonce: [u8; 32],
    /// Expiry, unix-seconds.
    pub deadline: u64,
    /// Witness hash — typically the ERC-7683 order id.
    pub witness: [u8; 32],
    /// Witness type name (e.g. `"Tenzro7683Order"`).
    pub witness_type_name: String,
    /// Full witness type string (e.g. `"Tenzro7683Order(bytes32 orderId,uint32 originChainId)"`).
    pub witness_type_string: String,
}

impl PermitTransferFromWitness {
    /// Struct hash including the witness.
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 * 6);
        buf.extend_from_slice(&permit_transfer_witness_typehash(
            &self.witness_type_name,
            &self.witness_type_string,
        ));
        buf.extend_from_slice(&self.permitted.struct_hash());
        buf.extend_from_slice(&address_as_uint256(&self.spender));
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&u64_as_uint256(self.deadline));
        buf.extend_from_slice(&self.witness);
        Keccak256::digest(&buf).into()
    }

    /// EIP-712 digest.
    pub fn digest(&self, domain_separator: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(66);
        buf.push(0x19);
        buf.push(0x01);
        buf.extend_from_slice(domain_separator);
        buf.extend_from_slice(&self.struct_hash());
        Keccak256::digest(&buf).into()
    }
}

/// Compute the Permit2 EIP-712 domain separator for a given chain id and
/// verifying-contract address. The name is the constant `"Permit2"`.
pub fn domain_separator(chain_id: u64, verifying_contract: &Address) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 4);
    buf.extend_from_slice(&eip712_domain_typehash());
    let name_hash: [u8; 32] = Keccak256::digest(PERMIT2_DOMAIN_NAME.as_bytes()).into();
    buf.extend_from_slice(&name_hash);
    buf.extend_from_slice(&u64_as_uint256(chain_id));
    buf.extend_from_slice(&address_as_uint256(verifying_contract));
    Keccak256::digest(&buf).into()
}

/// Recover the EVM signer (20 bytes) from a 65-byte secp256k1 signature
/// over `digest`. The signature format is `r(32) || s(32) || v(1)` where
/// `v` is the recovery id `{0, 1}` or the legacy `{27, 28}` form.
pub fn recover_signer(digest: &[u8; 32], signature: &[u8]) -> Result<[u8; 20], Permit2Error> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    if signature.len() != 65 {
        return Err(Permit2Error::InvalidSignature);
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&signature[..64]);
    let signature_obj = Signature::from_slice(&sig_bytes)
        .map_err(|_| Permit2Error::InvalidSignature)?;
    let v = signature[64];
    let recid_byte = if v >= 27 { v - 27 } else { v };
    let recid = RecoveryId::from_byte(recid_byte).ok_or(Permit2Error::InvalidSignature)?;
    let vk = VerifyingKey::recover_from_prehash(digest, &signature_obj, recid)
        .map_err(|_| Permit2Error::InvalidSignature)?;
    let encoded = vk.to_sec1_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(Permit2Error::InvalidSignature);
    }
    let hashed: [u8; 32] = Keccak256::digest(&bytes[1..]).into();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hashed[12..]);
    Ok(addr)
}

/// Process-wide Permit2 nonce bitmap.
///
/// Permit2 uses a 256-bit-per-word bitmap rather than monotonic nonces
/// so users can sign multiple permits in parallel without serializing
/// against a single counter. This implementation mirrors that — each
/// owner has a `HashMap<word_pos: u248, word: U256>` and a nonce of the
/// form `(word_pos << 8) | bit_pos` is considered used when the matching
/// bit in `word` is set.
#[derive(Debug, Default)]
pub struct Permit2NonceBitmap {
    /// Per-owner word storage. The outer key is the owner address; the
    /// inner key is the high-248-bit word position; the inner value is
    /// the 32-byte word.
    words: RwLock<HashMap<[u8; 20], HashMap<[u8; 31], [u8; 32]>>>,
}

impl Permit2NonceBitmap {
    /// Build an empty bitmap.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether `nonce` has been used by `owner` and, if not, mark
    /// it used atomically. Returns `Ok(())` if the nonce was freshly
    /// reserved or `Err(NonceAlreadyUsed)` if it was already set.
    pub fn check_and_use(
        &self,
        owner: &[u8; 20],
        nonce: &[u8; 32],
    ) -> Result<(), Permit2Error> {
        let mut word_pos = [0u8; 31];
        word_pos.copy_from_slice(&nonce[..31]);
        let bit_pos = nonce[31];
        let mut words = self.words.write();
        let owner_words = words.entry(*owner).or_default();
        let word = owner_words.entry(word_pos).or_insert([0u8; 32]);
        let byte_idx = (bit_pos / 8) as usize;
        let mask = 1u8 << (bit_pos % 8);
        if word[byte_idx] & mask != 0 {
            return Err(Permit2Error::NonceAlreadyUsed);
        }
        word[byte_idx] |= mask;
        Ok(())
    }

    /// Returns `true` if `nonce` is already marked used for `owner`.
    pub fn is_used(&self, owner: &[u8; 20], nonce: &[u8; 32]) -> bool {
        let mut word_pos = [0u8; 31];
        word_pos.copy_from_slice(&nonce[..31]);
        let bit_pos = nonce[31];
        let words = self.words.read();
        let Some(owner_words) = words.get(owner) else {
            return false;
        };
        let Some(word) = owner_words.get(&word_pos) else {
            return false;
        };
        let byte_idx = (bit_pos / 8) as usize;
        let mask = 1u8 << (bit_pos % 8);
        word[byte_idx] & mask != 0
    }
}

/// Shareable handle around a [`Permit2NonceBitmap`].
pub type SharedPermit2NonceBitmap = Arc<Permit2NonceBitmap>;

/// Convert a Tenzro 32-byte address into the 32-byte uint256 EIP-712
/// representation (last 20 bytes carry the EVM address, top 12 bytes
/// are zero).
fn address_as_uint256(address: &Address) -> [u8; 32] {
    let bytes = address.as_bytes();
    let mut out = [0u8; 32];
    if bytes.len() >= 20 {
        out[12..].copy_from_slice(&bytes[bytes.len() - 20..]);
    } else {
        let start = 32 - bytes.len();
        out[start..].copy_from_slice(bytes);
    }
    out
}

/// Convert a u64 to the 32-byte big-endian uint256 representation.
fn u64_as_uint256(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_bitmap_marks_used() {
        let bitmap = Permit2NonceBitmap::new();
        let owner = [1u8; 20];
        let mut nonce = [0u8; 32];
        nonce[31] = 5;
        assert!(!bitmap.is_used(&owner, &nonce));
        bitmap.check_and_use(&owner, &nonce).unwrap();
        assert!(bitmap.is_used(&owner, &nonce));
        let err = bitmap.check_and_use(&owner, &nonce).unwrap_err();
        assert!(matches!(err, Permit2Error::NonceAlreadyUsed));
    }

    #[test]
    fn nonce_bitmap_parallel_words() {
        let bitmap = Permit2NonceBitmap::new();
        let owner = [2u8; 20];
        let mut a = [0u8; 32];
        a[0] = 1;
        let mut b = [0u8; 32];
        b[0] = 2;
        bitmap.check_and_use(&owner, &a).unwrap();
        bitmap.check_and_use(&owner, &b).unwrap();
        assert!(bitmap.is_used(&owner, &a));
        assert!(bitmap.is_used(&owner, &b));
    }

    #[test]
    fn domain_separator_deterministic() {
        let addr = Address::new([0u8; 32]);
        let ds_a = domain_separator(1337, &addr);
        let ds_b = domain_separator(1337, &addr);
        assert_eq!(ds_a, ds_b);
        let ds_c = domain_separator(1, &addr);
        assert_ne!(ds_a, ds_c);
    }
}
