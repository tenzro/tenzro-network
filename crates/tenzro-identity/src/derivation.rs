//! Chain-derivation layer (stellar/xrpl/hyperliquid integration, Phase 2).
//!
//! Derives deterministic target-chain public keys and addresses from a TDIP
//! "home" identity + a derivation path, per
//! `docs/architecture/stellar-xrpl-hyperliquid-integration.md` Layer 1.
//!
//! # Curve-dependent derivation strategy
//!
//! Secp256k1 uses **additive** HD key derivation:
//! `target_pk = home_pk + epsilon·G`, where `epsilon = H(home_did, path)`
//! reduced into the curve's scalar field. This is well-defined and safe on
//! **secp256k1**, whose group is prime-order — every scalar tweak maps cleanly.
//!
//! For **Ed25519** additive point derivation is unsafe:
//! - Curve25519 has cofactor 8 (a non-prime-order group), so a public-only
//!   additive tweak can land on a low-order / mixed-order point.
//! - EdDSA *clamps* the scalar (clears the low 3 bits, sets bit 254), so the
//!   "obvious" `s' = s + epsilon` does not correspond to the clamped scalar an
//!   Ed25519 signer would actually use — the derived public key and the key the
//!   MPC signer can sign with diverge.
//!
//! For Ed25519 we therefore use a *hardened* derivation (per SLIP-0010) that
//! produces a **distinct** ed25519 key per path, deterministically from a
//! seed + path, rather than an additive point tweak.
//! Ref: <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>
//! The actual signature for that derived key still goes through Tenzro's MPC
//! `ThresholdSigner`; this module only computes the deterministic public key /
//! address up front (for quoting, auditing, pre-funding).

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Target signature curve for a derived key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetCurve {
    /// Edwards25519 (Stellar, XRPL classic default).
    Ed25519,
    /// secp256k1 (all EVM chains, XRPL secp256k1 option).
    Secp256k1,
}

/// Target chain for address encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetChain {
    /// Stellar public network (StrKey `G...` ed25519 account).
    StellarPubnet,
    /// XRPL livenet classic `r...` address.
    XrplLivenet,
    /// XRPL EVM sidechain (standard EVM `0x...`).
    XrplEvm,
    /// HyperEVM (standard EVM `0x...`).
    HyperEvm,
    /// Ethereum mainnet (standard EVM `0x...`).
    Ethereum,
    /// Base (standard EVM `0x...`).
    Base,
}

/// Errors from chain derivation / address encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationError {
    /// The supplied home/target public key had the wrong length or encoding
    /// for the requested curve.
    InvalidPublicKey(String),
    /// The derived point was the identity / not on the curve (negligible
    /// probability for a random tweak, but checked).
    InvalidDerivedKey(String),
    /// The (curve, chain) combination is not supported.
    UnsupportedCombination { curve: TargetCurve, chain: TargetChain },
    /// Internal encoding failure.
    Encoding(String),
}

impl std::fmt::Display for DerivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPublicKey(m) => write!(f, "invalid public key: {m}"),
            Self::InvalidDerivedKey(m) => write!(f, "invalid derived key: {m}"),
            Self::UnsupportedCombination { curve, chain } => {
                write!(f, "unsupported curve/chain combination: {curve:?}/{chain:?}")
            }
            Self::Encoding(m) => write!(f, "encoding error: {m}"),
        }
    }
}

impl std::error::Error for DerivationError {}

/// Domain-separation prefix for the additive derivation tweak. The epsilon
/// scalar is computed as
/// `epsilon = SHA-256(PREFIX || home_did || "," || path)` reduced into the
/// target curve's scalar field.
///
/// The prefix versions the derivation scheme: changing its value changes every
/// derived key/address, so it is bumped only on an intentional scheme change.
pub const EPSILON_PREFIX: &str = "tenzro chain-derivation v1 epsilon:";

/// Deterministic chain derivation from a home DID + path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainDerivation {
    /// The home (TDIP) DID, e.g. `did:tenzro:machine:0x...`. Identifies the
    /// home account in the epsilon preimage.
    pub home_did: String,
    /// Derivation path string, e.g. `stellar:1`, `xrpl:1`, `hyperevm:1`.
    pub path: String,
}

impl ChainDerivation {
    /// Construct a derivation context.
    pub fn new(home_did: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            home_did: home_did.into(),
            path: path.into(),
        }
    }

    /// Compute the epsilon preimage bytes:
    /// `PREFIX || home_did || "," || path`.
    ///
    /// The `,` separator marks the end of the home DID. See `EPSILON_PREFIX`.
    fn epsilon_preimage(&self) -> Vec<u8> {
        format!("{}{},{}", EPSILON_PREFIX, self.home_did, self.path).into_bytes()
    }

    /// Derive the target-chain **public key** from the home public key.
    ///
    /// - `Secp256k1`: additive tweak. `home_pk` is a SEC1-encoded point
    ///   (33-byte compressed or 65-byte uncompressed). Returns the derived key
    ///   as a 65-byte uncompressed SEC1 point (`0x04 || X || Y`), the form EVM
    ///   address derivation needs.
    /// - `Ed25519`: additive point derivation is unsafe (see module docs), so
    ///   this path requires the *secret* seed. Callers must instead use
    ///   [`ChainDerivation::derive_ed25519_keypair`] and take the verifying key
    ///   from it. We return [`DerivationError::InvalidPublicKey`] here to make
    ///   the unsafe path unreachable.
    pub fn derive_target_pubkey(
        &self,
        home_pk: &[u8],
        curve: TargetCurve,
    ) -> Result<Vec<u8>, DerivationError> {
        match curve {
            TargetCurve::Secp256k1 => self.derive_secp256k1_pubkey(home_pk),
            TargetCurve::Ed25519 => Err(DerivationError::InvalidPublicKey(
                "Ed25519 additive point derivation is unsafe (cofactor 8 + EdDSA \
                 clamping); use derive_ed25519_keypair(seed) instead"
                    .to_string(),
            )),
        }
    }

    /// secp256k1 additive derivation: `target_pk = home_pk + epsilon·G`.
    ///
    /// `epsilon = Sha256(epsilon_preimage())` reduced into the secp256k1 scalar
    /// field, then `target_point = home_point + GENERATOR * epsilon`.
    fn derive_secp256k1_pubkey(&self, home_pk: &[u8]) -> Result<Vec<u8>, DerivationError> {
        use k256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
        use k256::elliptic_curve::Group;
        use k256::{ProjectivePoint, PublicKey as K256PublicKey, Scalar, Sec1Point};

        // Parse the home public key (SEC1 compressed or uncompressed).
        let enc = Sec1Point::from_bytes(home_pk)
            .map_err(|e| DerivationError::InvalidPublicKey(format!("sec1 decode: {e}")))?;
        let home = K256PublicKey::from_sec1_point(&enc);
        let home: K256PublicKey = Option::from(home).ok_or_else(|| {
            DerivationError::InvalidPublicKey("point not on secp256k1 curve".to_string())
        })?;
        let home_point = ProjectivePoint::from(*home.as_affine());

        // epsilon = SHA-256(preimage) reduced mod n (the group order). We use
        // from_repr after a wide-free reduce: SHA-256 output (32 bytes) may be
        // >= n, so reduce it. k256 Scalar::from_repr only accepts canonical
        // (< n) reprs, so reduce manually via Reduce.
        let digest = Sha256::digest(self.epsilon_preimage());
        let epsilon = reduce_be_bytes_to_scalar(&digest);

        // Guard the (negligible) case where SHA-256 reduces to zero.
        if epsilon == Scalar::ZERO {
            return Err(DerivationError::InvalidDerivedKey(
                "epsilon reduced to zero scalar".to_string(),
            ));
        }
        let target_point = home_point + (ProjectivePoint::GENERATOR * epsilon);
        if bool::from(target_point.is_identity()) {
            return Err(DerivationError::InvalidDerivedKey(
                "derived point is the identity".to_string(),
            ));
        }

        // Return uncompressed SEC1 (0x04 || X || Y).
        let affine = target_point.to_affine();
        Ok(affine.to_sec1_point(false).as_bytes().to_vec())
    }

    /// SLIP-0010 hardened Ed25519 derivation producing a DISTINCT ed25519 key
    /// per path (option (b) for the cofactor pitfall — see module docs).
    ///
    /// `home_seed` is the 32-byte master seed bound to the home identity. The
    /// path string is hashed into a single hardened child index so the derived
    /// key is deterministic per (`home_did`, `path`).
    ///
    /// SLIP-0010 ed25519 (ref
    /// <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>):
    /// - master: `I = HMAC-SHA512(key="ed25519 seed", data=seed)`,
    ///   `k = I[0..32]`, `chaincode = I[32..64]`.
    /// - hardened CKDpriv: `I = HMAC-SHA512(key=chaincode,
    ///   data=0x00 || k_par || ser32(index))`, child key `= I[0..32]`.
    ///   (For ed25519 only hardened derivation exists; `I_L` becomes the key
    ///   directly with no curve-order check.)
    ///
    /// Returns `(signing_key, verifying_key)`. The MPC `ThresholdSigner` holds
    /// the real shares in production; this is the deterministic-derivation
    /// helper for address computation / single-signer paths.
    pub fn derive_ed25519_keypair(
        &self,
        home_seed: &[u8; 32],
    ) -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        // Master node.
        let i = hmac_sha512(b"ed25519 seed", home_seed);
        let (mut k, mut chaincode) = split32(&i);

        // Fold the path into a single hardened index. SLIP-0010 ser32 is a
        // 4-byte big-endian index; hardened indices have the high bit set.
        // We take the path-hash's low 31 bits and OR in 0x8000_0000.
        let path_hash = Sha256::digest(self.epsilon_preimage());
        let idx_raw = u32::from_be_bytes([path_hash[0], path_hash[1], path_hash[2], path_hash[3]]);
        let index = idx_raw | 0x8000_0000;

        // Hardened CKDpriv: data = 0x00 || k_par(32) || ser32(index).
        let mut data = Vec::with_capacity(1 + 32 + 4);
        data.push(0x00);
        data.extend_from_slice(&k);
        data.extend_from_slice(&index.to_be_bytes());
        let i_child = hmac_sha512(&chaincode, &data);
        let (k_child, _cc_child) = split32(&i_child);

        let signing = ed25519_dalek::SigningKey::from_bytes(&k_child);
        let verifying = signing.verifying_key();

        // Zeroize intermediate secrets best-effort.
        k.iter_mut().for_each(|b| *b = 0);
        chaincode.iter_mut().for_each(|b| *b = 0);

        (signing, verifying)
    }

    /// Encode a derived public key into the target chain's address string.
    ///
    /// - `StellarPubnet`: `target_pk` is a 32-byte ed25519 key → StrKey `G...`.
    /// - `XrplLivenet`: `target_pk` is a 32-byte ed25519 (encoded with the XRPL
    ///   `0xED` prefix) or a 33-byte compressed secp256k1 key → classic `r...`.
    /// - EVM chains: `target_pk` is an uncompressed (65-byte) secp256k1 key →
    ///   EIP-55 checksummed `0x...`.
    pub fn derive_target_address(
        &self,
        target_pk: &[u8],
        chain: TargetChain,
    ) -> Result<String, DerivationError> {
        match chain {
            TargetChain::StellarPubnet => stellar_strkey(target_pk),
            TargetChain::XrplLivenet => {
                // Disambiguate by length: 32 = raw ed25519, 33 = sec1 (either
                // 0xED-prefixed ed25519 or compressed secp256k1).
                let curve = match target_pk.len() {
                    32 => TargetCurve::Ed25519,
                    33 if target_pk[0] == 0xED => TargetCurve::Ed25519,
                    33 => TargetCurve::Secp256k1,
                    _ => {
                        return Err(DerivationError::InvalidPublicKey(format!(
                            "XRPL pubkey must be 32 (ed25519) or 33 (sec1) bytes, got {}",
                            target_pk.len()
                        )))
                    }
                };
                xrpl_classic_address(target_pk, curve)
            }
            TargetChain::XrplEvm | TargetChain::HyperEvm | TargetChain::Ethereum | TargetChain::Base => {
                evm_address(target_pk)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// secp256k1 scalar reduction helper
// ---------------------------------------------------------------------------

/// Reduce 32 big-endian bytes into a secp256k1 scalar (mod n) for the epsilon
/// tweak. Uses `Reduce` so an input ≥ n is reduced rather than rejected.
fn reduce_be_bytes_to_scalar(bytes: &[u8]) -> k256::Scalar {
    use k256::elliptic_curve::ops::Reduce;
    use k256::U256;
    let n = U256::from_be_slice(bytes);
    <k256::Scalar as Reduce<U256>>::reduce(&n)
}

// ---------------------------------------------------------------------------
// HMAC-SHA512 (SLIP-0010) — small self-contained impl over sha2.
// ---------------------------------------------------------------------------

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    use sha2::Sha512;
    const BLOCK: usize = 128; // SHA-512 block size in bytes.
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = Sha512::digest(key);
        k[..64].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha512::new();
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn split32(i: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&i[..32]);
    b.copy_from_slice(&i[32..]);
    (a, b)
}

// ---------------------------------------------------------------------------
// Stellar StrKey
// ---------------------------------------------------------------------------

/// StrKey version byte for an Ed25519 public key (account `G...`).
/// `6 << 3 | 0 = 48` (0x30). Ref SEP-0023:
/// <https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md>
const STRKEY_VERSION_ED25519_PUBLIC: u8 = 6 << 3; // = 0x30

/// Encode a 32-byte Ed25519 public key as a Stellar StrKey account (`G...`).
///
/// Layout: `version_byte(0x30) || pubkey(32) || crc16_xmodem(le, 2)`, then
/// RFC4648 base32 with no padding. Ref SEP-0023 (see above).
pub fn stellar_strkey(ed25519_pub: &[u8]) -> Result<String, DerivationError> {
    if ed25519_pub.len() != 32 {
        return Err(DerivationError::InvalidPublicKey(format!(
            "Stellar ed25519 key must be 32 bytes, got {}",
            ed25519_pub.len()
        )));
    }
    let mut payload = Vec::with_capacity(1 + 32 + 2);
    payload.push(STRKEY_VERSION_ED25519_PUBLIC);
    payload.extend_from_slice(ed25519_pub);
    // CRC16-XModem, appended little-endian (low byte first). Ref SEP-0023 +
    // stellar-base strkey.js (checksum[0] = crc & 0xff; checksum[1] = crc>>8).
    let crc = crc16_xmodem(&payload);
    payload.push((crc & 0xff) as u8);
    payload.push((crc >> 8) as u8);
    Ok(base32_rfc4648_nopad(&payload))
}

/// CRC16-XModem (poly 0x1021, init 0x0000), as required by Stellar StrKey.
/// Ref SEP-0023: "polynomial x16 + x12 + x5 + 1" (= 0x1021), XModem variant.
fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// RFC4648 base32 (uppercase A-Z2-7), no padding.
fn base32_rfc4648_nopad(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// XRPL classic r-address
// ---------------------------------------------------------------------------

/// XRPL base58 dictionary. Ref
/// <https://xrpl.org/docs/references/protocol/data-types/base58-encodings>.
const XRPL_ALPHABET: &[u8; 58] =
    b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/// XRPL AccountID type-prefix byte for classic `r...` addresses (`0x00`).
const XRPL_ACCOUNT_PREFIX: u8 = 0x00;

/// XRPL Ed25519 public-key prefix byte (`0xED`), prepended to the 32-byte key
/// to form the 33-byte canonical pubkey. Ref xrpl.org cryptographic-keys.
const XRPL_ED25519_PREFIX: u8 = 0xED;

/// Derive an XRPL classic `r...` address from a public key.
///
/// Steps (ref <https://xrpl.org/docs/concepts/accounts/addresses>):
/// 1. Canonicalize the pubkey: ed25519 → `0xED || key(32)` (33 bytes);
///    secp256k1 → 33-byte compressed SEC1 (already prefixed 0x02/0x03).
/// 2. `AccountID = RIPEMD160(SHA256(pubkey))` (20 bytes).
/// 3. `payload = 0x00 || AccountID`.
/// 4. `checksum = SHA256(SHA256(payload))[0..4]`.
/// 5. base58(`payload || checksum`) with the XRPL dictionary.
pub fn xrpl_classic_address(public_key: &[u8], curve: TargetCurve) -> Result<String, DerivationError> {
    // (1) Canonical 33-byte public key.
    let canonical: Vec<u8> = match curve {
        TargetCurve::Ed25519 => match public_key.len() {
            32 => {
                let mut v = Vec::with_capacity(33);
                v.push(XRPL_ED25519_PREFIX);
                v.extend_from_slice(public_key);
                v
            }
            33 if public_key[0] == XRPL_ED25519_PREFIX => public_key.to_vec(),
            n => {
                return Err(DerivationError::InvalidPublicKey(format!(
                    "XRPL ed25519 key must be 32 bytes (or 33 with 0xED prefix), got {n}"
                )))
            }
        },
        TargetCurve::Secp256k1 => match public_key.len() {
            33 => public_key.to_vec(), // compressed SEC1
            _ => {
                return Err(DerivationError::InvalidPublicKey(
                    "XRPL secp256k1 key must be a 33-byte compressed SEC1 point".to_string(),
                ))
            }
        },
    };

    // (2) AccountID = RIPEMD160(SHA256(pubkey)).
    let sha = Sha256::digest(&canonical);
    let account_id = Ripemd160::digest(sha);

    // (3) payload = prefix || accountid.
    let mut payload = Vec::with_capacity(1 + 20);
    payload.push(XRPL_ACCOUNT_PREFIX);
    payload.extend_from_slice(&account_id);

    // (4) checksum = first 4 bytes of double-SHA256.
    let check_full = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&check_full[..4]);

    // (5) base58 with the XRPL dictionary.
    let alphabet = bs58::Alphabet::new(XRPL_ALPHABET)
        .map_err(|e| DerivationError::Encoding(format!("xrpl alphabet: {e}")))?;
    Ok(bs58::encode(payload).with_alphabet(&alphabet).into_string())
}

// ---------------------------------------------------------------------------
// EVM address (EIP-55)
// ---------------------------------------------------------------------------

/// Derive an EIP-55 checksummed EVM `0x...` address from an uncompressed
/// secp256k1 public key.
///
/// `address = keccak256(uncompressed_pubkey[1..])[12..]` (drop the 0x04 SEC1
/// tag, hash the 64-byte X||Y, take the last 20 bytes). Then EIP-55 checksum:
/// uppercase each hex nibble whose corresponding keccak256(lowercase-hex-addr)
/// nibble is ≥ 8. Ref EIP-55 + standard Ethereum address derivation.
pub fn evm_address(secp256k1_uncompressed_pub: &[u8]) -> Result<String, DerivationError> {
    use sha3::Keccak256;

    // Accept the canonical 65-byte (0x04||X||Y) form, or a bare 64-byte X||Y.
    let xy: &[u8] = match secp256k1_uncompressed_pub.len() {
        65 if secp256k1_uncompressed_pub[0] == 0x04 => &secp256k1_uncompressed_pub[1..],
        64 => secp256k1_uncompressed_pub,
        n => {
            return Err(DerivationError::InvalidPublicKey(format!(
                "EVM pubkey must be uncompressed (65 bytes with 0x04, or 64 X||Y), got {n}"
            )))
        }
    };

    let hash = Keccak256::digest(xy);
    let addr = &hash[12..]; // last 20 bytes

    // EIP-55 checksum.
    let lower_hex = hex::encode(addr);
    let hash_of_hex = Keccak256::digest(lower_hex.as_bytes());
    let mut out = String::with_capacity(2 + 40);
    out.push_str("0x");
    for (i, ch) in lower_hex.chars().enumerate() {
        if ch.is_ascii_digit() {
            out.push(ch);
        } else {
            // nibble i of hash_of_hex
            let byte = hash_of_hex[i / 2];
            let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
            if nibble >= 8 {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- CRC16-XModem known-answer ------------------------------------------
    // The string "123456789" → 0x31C3 is the canonical CRC-16/XMODEM check
    // value (check field in the CRC catalogue, e.g. reveng / Boost CRC docs).
    #[test]
    fn crc16_xmodem_known_answer() {
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
    }

    // -- base32 RFC4648 known-answer ----------------------------------------
    // RFC 4648 §10 test vectors (no padding here since we strip it).
    #[test]
    fn base32_rfc4648_known_answers() {
        assert_eq!(base32_rfc4648_nopad(b"f"), "MY");
        assert_eq!(base32_rfc4648_nopad(b"fo"), "MZXQ");
        assert_eq!(base32_rfc4648_nopad(b"foo"), "MZXW6");
        assert_eq!(base32_rfc4648_nopad(b"foobar"), "MZXW6YTBOI");
    }

    // -- Stellar StrKey known-answer ----------------------------------------
    // The raw ed25519 public key below encodes to the G-address asserted here.
    // The expected value is the output of the documented StrKey algorithm
    // (version byte 0x30 ‖ pubkey ‖ CRC16-XMODEM little-endian, RFC4648 base32),
    // independently reproduced; the algorithm's primitives are themselves
    // pinned by the `crc16_xmodem` (official 0x31C3 check) and base32 RFC4648
    // known-answer tests above.
    #[test]
    fn stellar_strkey_known_answer() {
        let raw =
            hex::decode("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
                .unwrap();
        let g = stellar_strkey(&raw).unwrap();
        assert_eq!(
            g,
            "GA5WUJ54Z23KILLCUOUNAKTPBVZWKMQVO4O6EQ5GHLAERIMLLHNCSKYH"
        );
        assert!(g.starts_with('G'));
        assert_eq!(g.len(), 56);
    }

    // -- XRPL r-address known-answer ----------------------------------------
    // From xrpl.org address-encoding worked example:
    // <https://xrpl.org/docs/concepts/accounts/addresses> /
    // xrpl-dev-portal encode_address.js.
    // pubkey_hex 'ED9434...FA32' → rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN
    #[test]
    fn xrpl_ed25519_known_answer() {
        let pubkey = hex::decode(
            "ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32",
        )
        .unwrap();
        // Pass the full 33-byte 0xED-prefixed key.
        let r = xrpl_classic_address(&pubkey, TargetCurve::Ed25519).unwrap();
        assert_eq!(r, "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN");
        // And the bare 32-byte key (we add the 0xED prefix) must match.
        let r2 = xrpl_classic_address(&pubkey[1..], TargetCurve::Ed25519).unwrap();
        assert_eq!(r2, r);
    }

    // -- EVM address known-answer (EIP-55) ----------------------------------
    // Known keypair: secret key = 1, uncompressed pubkey is the secp256k1
    // generator G (0x04 || Gx || Gy). Its Ethereum address is the well-known
    // address of privkey 0x0000...0001:
    // 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf.
    // Gx = 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
    // Gy = 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
    #[test]
    fn evm_address_eip55_known_answer() {
        let mut pk = vec![0x04u8];
        pk.extend_from_slice(
            &hex::decode(
                "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            )
            .unwrap(),
        );
        pk.extend_from_slice(
            &hex::decode(
                "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            )
            .unwrap(),
        );
        let addr = evm_address(&pk).unwrap();
        assert_eq!(addr, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    }

    // -- secp256k1 additive derivation: determinism + tweak consistency -----
    #[test]
    fn secp256k1_additive_derivation_matches_manual_tweak() {
        use k256::elliptic_curve::sec1::ToSec1Point;
        use k256::{ProjectivePoint, PublicKey as K256PublicKey};

        // Home key = generator (privkey 1), so home_point = G.
        let mut home = vec![0x04u8];
        home.extend_from_slice(
            &hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
                .unwrap(),
        );
        home.extend_from_slice(
            &hex::decode("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
                .unwrap(),
        );

        let d = ChainDerivation::new("did:tenzro:machine:abc", "hyperevm:1");
        let derived = d.derive_target_pubkey(&home, TargetCurve::Secp256k1).unwrap();
        // Deterministic.
        let derived2 = d.derive_target_pubkey(&home, TargetCurve::Secp256k1).unwrap();
        assert_eq!(derived, derived2);
        assert_eq!(derived.len(), 65);
        assert_eq!(derived[0], 0x04);

        // Manually recompute target = G + epsilon*G = (1+epsilon)*G and compare.
        let epsilon = reduce_be_bytes_to_scalar(&Sha256::digest(d.epsilon_preimage()));
        let expected = ProjectivePoint::GENERATOR + (ProjectivePoint::GENERATOR * epsilon);
        let expected_pk =
            K256PublicKey::from_affine(expected.to_affine()).unwrap();
        assert_eq!(
            derived,
            expected_pk.to_sec1_point(false).as_bytes().to_vec()
        );

        // Different path → different key.
        let d2 = ChainDerivation::new("did:tenzro:machine:abc", "xrpl_evm:1");
        let other = d2.derive_target_pubkey(&home, TargetCurve::Secp256k1).unwrap();
        assert_ne!(derived, other);
    }

    #[test]
    fn ed25519_additive_path_is_rejected() {
        let d = ChainDerivation::new("did:tenzro:machine:abc", "stellar:1");
        let res = d.derive_target_pubkey(&[0u8; 32], TargetCurve::Ed25519);
        assert!(matches!(res, Err(DerivationError::InvalidPublicKey(_))));
    }

    #[test]
    fn ed25519_slip10_keypair_is_deterministic_and_path_distinct() {
        let seed = [7u8; 32];
        let d1 = ChainDerivation::new("did:tenzro:machine:abc", "stellar:1");
        let (sk1, vk1) = d1.derive_ed25519_keypair(&seed);
        let (sk1b, vk1b) = d1.derive_ed25519_keypair(&seed);
        assert_eq!(sk1.to_bytes(), sk1b.to_bytes());
        assert_eq!(vk1.to_bytes(), vk1b.to_bytes());

        // Different path → distinct key (no additive relationship).
        let d2 = ChainDerivation::new("did:tenzro:machine:abc", "stellar:2");
        let (_sk2, vk2) = d2.derive_ed25519_keypair(&seed);
        assert_ne!(vk1.to_bytes(), vk2.to_bytes());

        // The derived ed25519 verifying key encodes to a valid Stellar address.
        let g = stellar_strkey(&vk1.to_bytes()).unwrap();
        assert!(g.starts_with('G') && g.len() == 56);
    }

    // -- SLIP-0010 ed25519 master/child known-answer ------------------------
    // SLIP-0010 Test vector 1 for ed25519, seed = 000102030405060708090a0b0c0d0e0f.
    // Chain m: private key 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7,
    //          chain code 90046a93de5380a72b5e45010748567d5ea02bcf952191ac... (we check key).
    // m/0H: private key 68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3.
    // Ref https://github.com/satoshilabs/slips/blob/master/slip-0010.md
    #[test]
    fn slip10_ed25519_master_and_hardened_child_known_answer() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        // Master.
        let i = hmac_sha512(b"ed25519 seed", &seed);
        let (k, _cc) = split32(&i);
        assert_eq!(
            hex::encode(k),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        // m/0H.
        let (k_master, cc_master) = split32(&i);
        let mut data = vec![0x00u8];
        data.extend_from_slice(&k_master);
        data.extend_from_slice(&0x8000_0000u32.to_be_bytes());
        let i_child = hmac_sha512(&cc_master, &data);
        let (k_child, _) = split32(&i_child);
        assert_eq!(
            hex::encode(k_child),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
    }

    #[test]
    fn full_pipeline_stellar_and_evm() {
        // Stellar: derive an ed25519 key for path, encode to G-address.
        let seed = [0x11u8; 32];
        let d = ChainDerivation::new("did:tenzro:machine:xyz", "stellar:1");
        let (_sk, vk) = d.derive_ed25519_keypair(&seed);
        let g = d
            .derive_target_address(&vk.to_bytes(), TargetChain::StellarPubnet)
            .unwrap();
        assert!(g.starts_with('G'));

        // EVM: additive secp256k1 then 0x-address.
        let mut home = vec![0x04u8];
        home.extend_from_slice(
            &hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
                .unwrap(),
        );
        home.extend_from_slice(
            &hex::decode("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
                .unwrap(),
        );
        let de = ChainDerivation::new("did:tenzro:machine:xyz", "hyperevm:1");
        let tpk = de.derive_target_pubkey(&home, TargetCurve::Secp256k1).unwrap();
        let addr = de.derive_target_address(&tpk, TargetChain::HyperEvm).unwrap();
        assert!(addr.starts_with("0x") && addr.len() == 42);
    }
}
