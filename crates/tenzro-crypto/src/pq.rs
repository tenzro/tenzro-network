//! Post-quantum cryptographic primitives for Tenzro Network.
//!
//! Wraps the RustCrypto FIPS 203/204 implementations in the same `Vec<u8>`-based
//! shape that the rest of `tenzro-crypto` uses (see `keys.rs` and `signatures.rs`).
//! Higher layers consume composite (classical+pq) keypairs through `composite.rs`;
//! they should not import this module directly except in tests.
//!
//! # Algorithms
//!
//! - **ML-DSA-65** (FIPS 204) — digital signature replacing the security role of
//!   Ed25519 against a CRQC. Verifying key is 1952 bytes; signature is 3309 bytes.
//! - **ML-KEM-768** (FIPS 203) — key encapsulation replacing the security role of
//!   X25519 against a CRQC. Encapsulation key is 1184 bytes; ciphertext is 1088
//!   bytes; shared secret is 32 bytes.
//!
//! # RNG
//!
//! `ml-dsa` (via `signature` 3.0.0-rc) requires a `rand_core` 0.10 `TryCryptoRng`.
//! The rest of the workspace uses `rand` 0.8 + `OsRng`. We adapt the OS RNG
//! locally inside `OsCryptoRng` so callers can keep using a standard `&mut self`
//! method without touching the new trait surface.
//!
//! # Persistence
//!
//! `MlDsaSigningKey` stores the canonical 32-byte FIPS-204 seed (`B32`), not
//! the expanded matrix. The keystore (Argon2id-encrypted) is responsible for
//! sealing this seed at rest; in memory it is wrapped in `Zeroizing` so a `Drop`
//! wipes it. The expanded form is rebuilt every `sign()` via `MlDsa65::from_seed`.

use crate::error::{CryptoError, Result};
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    B32, MlDsa65, Signature as MlDsaSignature, SigningKey as MlDsaSigningKeyInner,
    VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::{
    Ciphertext as MlKemCiphertext, EncapsulationKey as MlKemEncapsulationKey, MlKem768,
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
};
use rand_core::{TryCryptoRng, TryRng, UnwrapErr};
use std::convert::Infallible;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Sizes (FIPS 203/204) — surfaced as constants so wire-format code can length-prefix
// without re-running keygen. Validated by `pq_constants_match_fips` test below.
// ---------------------------------------------------------------------------

/// ML-DSA-65 verifying key size in bytes (FIPS 204 §4 Table 2).
pub const ML_DSA_65_VK_LEN: usize = 1952;
/// ML-DSA-65 signature size in bytes (FIPS 204 §4 Table 2).
pub const ML_DSA_65_SIG_LEN: usize = 3309;
/// ML-DSA-65 seed size — canonical persistable form, FIPS 204 ξ value.
pub const ML_DSA_65_SEED_LEN: usize = 32;
/// ML-KEM-768 encapsulation key size in bytes (FIPS 203 §8 Table 3).
pub const ML_KEM_768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext size in bytes (FIPS 203 §8 Table 3).
pub const ML_KEM_768_CT_LEN: usize = 1088;
/// ML-KEM shared secret size in bytes (FIPS 203, 256-bit symmetric output).
pub const ML_KEM_SS_LEN: usize = 32;

// ---------------------------------------------------------------------------
// OS RNG bridge
// ---------------------------------------------------------------------------

/// `rand_core` 0.10–compatible OS RNG, implemented in terms of `getrandom::fill`.
///
/// `ml-dsa::KeyGen::key_gen` requires a `TryCryptoRng + ?Sized`. We implement
/// `TryRng` and `TryCryptoRng` here and wrap with `UnwrapErr` so the callsite
/// gets a `CryptoRng` that panics only if the host RNG itself fails (which is
/// the same behavior the rest of the workspace already assumes for `OsRng`).
struct OsCryptoRng;

impl TryRng for OsCryptoRng {
    type Error = Infallible;

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
        getrandom::fill(dst).expect("OS RNG failure");
        Ok(())
    }

    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).expect("OS RNG failure");
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).expect("OS RNG failure");
        Ok(u64::from_le_bytes(b))
    }
}

impl TryCryptoRng for OsCryptoRng {}

fn os_rng() -> UnwrapErr<OsCryptoRng> {
    UnwrapErr(OsCryptoRng)
}

// ---------------------------------------------------------------------------
// ML-DSA-65 — FIPS 204 digital signature
// ---------------------------------------------------------------------------

/// ML-DSA-65 signing key (private). Internally stores only the 32-byte FIPS-204
/// seed `ξ`; the expanded matrix is rederived via `MlDsa65::from_seed` on every
/// `sign()`. The seed is held in `Zeroizing<[u8; 32]>` so `Drop` wipes it.
#[derive(Clone)]
pub struct MlDsaSigningKey {
    seed: Zeroizing<[u8; ML_DSA_65_SEED_LEN]>,
    verifying_key_bytes: Vec<u8>,
}

impl MlDsaSigningKey {
    /// Generate a fresh ML-DSA-65 keypair backed by the host OS RNG.
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; ML_DSA_65_SEED_LEN]);
        getrandom::fill(seed.as_mut()).expect("OS RNG failure");
        Self::from_seed_bytes(seed)
    }

    /// Reconstruct a signing key from a previously-persisted seed (e.g. from
    /// the Argon2id-encrypted keystore in `tenzro-wallet`).
    pub fn from_seed(seed_bytes: &[u8]) -> Result<Self> {
        if seed_bytes.len() != ML_DSA_65_SEED_LEN {
            return Err(CryptoError::InvalidSecretKey(format!(
                "ML-DSA-65 seed must be {} bytes, got {}",
                ML_DSA_65_SEED_LEN,
                seed_bytes.len()
            )));
        }
        let mut seed = Zeroizing::new([0u8; ML_DSA_65_SEED_LEN]);
        seed.copy_from_slice(seed_bytes);
        Ok(Self::from_seed_bytes(seed))
    }

    fn from_seed_bytes(seed: Zeroizing<[u8; ML_DSA_65_SEED_LEN]>) -> Self {
        let xi = B32::from(*seed);
        let sk = MlDsaSigningKeyInner::<MlDsa65>::from_seed(&xi);
        let verifying_key_bytes = sk.verifying_key().encode().to_vec();
        Self {
            seed,
            verifying_key_bytes,
        }
    }

    /// Verifying key bytes (1952 bytes, FIPS 204 §4 Table 2).
    pub fn verifying_key_bytes(&self) -> &[u8] {
        &self.verifying_key_bytes
    }

    /// 32-byte canonical seed for keystore persistence. **Treat as secret.**
    pub fn seed_bytes(&self) -> &[u8] {
        self.seed.as_ref()
    }

    /// Sign `msg` and return the encoded signature (3309 bytes, FIPS 204 §4 Table 2).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        // Re-derive the SigningKey from the seed each call. This is
        // ~ms-class work and keeps the in-memory secret surface to 32 bytes.
        let xi = B32::from(*self.seed);
        let sk = MlDsaSigningKeyInner::<MlDsa65>::from_seed(&xi);
        let sig: MlDsaSignature<MlDsa65> = sk.sign(msg);
        sig.encode().to_vec()
    }
}

/// Verify an ML-DSA-65 signature.
///
/// # Errors
///
/// - `CryptoError::InvalidPublicKey` if `vk_bytes.len() != ML_DSA_65_VK_LEN` or
///   the bytes do not decode to a valid lattice element.
/// - `CryptoError::InvalidSignature` if `sig_bytes.len() != ML_DSA_65_SIG_LEN`
///   or the bytes do not decode to a valid signature shape.
/// - `CryptoError::VerificationFailed` if the signature is well-formed but does
///   not bind `msg` to `vk_bytes`.
pub fn ml_dsa_verify(vk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey};

    if vk_bytes.len() != ML_DSA_65_VK_LEN {
        return Err(CryptoError::InvalidPublicKey(format!(
            "ML-DSA-65 verifying key must be {} bytes, got {}",
            ML_DSA_65_VK_LEN,
            vk_bytes.len()
        )));
    }
    if sig_bytes.len() != ML_DSA_65_SIG_LEN {
        return Err(CryptoError::InvalidSignature(format!(
            "ML-DSA-65 signature must be {} bytes, got {}",
            ML_DSA_65_SIG_LEN,
            sig_bytes.len()
        )));
    }

    // Decode verifying key.
    let mut vk_arr: EncodedVerifyingKey<MlDsa65> = Default::default();
    {
        let dst: &mut [u8] = vk_arr.as_mut();
        if dst.len() != vk_bytes.len() {
            return Err(CryptoError::InvalidPublicKey(
                "ML-DSA-65 verifying key encoded slot mismatch".to_string(),
            ));
        }
        dst.copy_from_slice(vk_bytes);
    }
    let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&vk_arr);

    // Decode signature.
    let mut sig_arr: EncodedSignature<MlDsa65> = Default::default();
    {
        let dst: &mut [u8] = sig_arr.as_mut();
        if dst.len() != sig_bytes.len() {
            return Err(CryptoError::InvalidSignature(
                "ML-DSA-65 signature encoded slot mismatch".to_string(),
            ));
        }
        dst.copy_from_slice(sig_bytes);
    }
    let sig = MlDsaSignature::<MlDsa65>::decode(&sig_arr).ok_or_else(|| {
        CryptoError::InvalidSignature("ML-DSA-65 signature failed to decode".to_string())
    })?;

    // CVE GHSA-5x2r-hc65-25f9 (ml-dsa verifier soundness) is fixed in >= 0.1.0-rc.8;
    // pinned at workspace level.
    vk.verify(msg, &sig)
        .map_err(|_| CryptoError::VerificationFailed)?;
    let _ = os_rng; // prevent dead-code warning when only the verify path is tested
    Ok(())
}

// ---------------------------------------------------------------------------
// ML-KEM-768 — FIPS 203 key encapsulation
// ---------------------------------------------------------------------------

/// ML-KEM-768 decapsulation key (private). Caller is responsible for keystore
/// encryption (see `tenzro-wallet`'s Argon2id keystore) — we never persist this
/// in plaintext.
///
/// We hold the actual `DecapsulationKey<MlKem768>` rather than a re-derivable
/// seed because `ml-kem`'s seeding API is more involved and the plaintext key
/// stays inside the keystore-encrypted memory of `tenzro-wallet`.
pub struct MlKemDecapsulationKey {
    inner: ml_kem::DecapsulationKey<MlKem768>,
    encapsulation_key_bytes: Vec<u8>,
}

impl MlKemDecapsulationKey {
    /// Generate a fresh ML-KEM-768 keypair using the OS RNG via the
    /// `getrandom`-feature path on `MlKem768::generate_keypair()`.
    pub fn generate() -> Self {
        let (dk, ek) = <MlKem768 as Kem>::generate_keypair();
        let encapsulation_key_bytes = ek.to_bytes().to_vec();
        Self {
            inner: dk,
            encapsulation_key_bytes,
        }
    }

    /// Encapsulation key bytes (1184 bytes, FIPS 203 §8 Table 3) for publishing.
    pub fn encapsulation_key_bytes(&self) -> &[u8] {
        &self.encapsulation_key_bytes
    }

    /// Decapsulate a shared secret from a ciphertext produced by a peer's
    /// `Encapsulate` call. Returns the 32-byte shared secret.
    pub fn decapsulate(&self, ct_bytes: &[u8]) -> Result<[u8; ML_KEM_SS_LEN]> {
        if ct_bytes.len() != ML_KEM_768_CT_LEN {
            return Err(CryptoError::InvalidCiphertext(format!(
                "ML-KEM-768 ciphertext must be {} bytes, got {}",
                ML_KEM_768_CT_LEN,
                ct_bytes.len()
            )));
        }
        let mut ct: MlKemCiphertext<MlKem768> = Default::default();
        {
            let dst: &mut [u8] = ct.as_mut();
            if dst.len() != ct_bytes.len() {
                return Err(CryptoError::InvalidCiphertext(
                    "ML-KEM-768 ciphertext encoded slot mismatch".to_string(),
                ));
            }
            dst.copy_from_slice(ct_bytes);
        }
        let ss = self.inner.decapsulate(&ct);
        let mut out = [0u8; ML_KEM_SS_LEN];
        out.copy_from_slice(ss.as_slice());
        Ok(out)
    }
}

/// Encapsulate a shared secret to a peer's `ek_bytes` encapsulation key.
///
/// Returns `(ciphertext, shared_secret)`. The peer recovers `shared_secret` by
/// calling `MlKemDecapsulationKey::decapsulate(&ciphertext)`.
pub fn ml_kem_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; ML_KEM_SS_LEN])> {
    if ek_bytes.len() != ML_KEM_768_EK_LEN {
        return Err(CryptoError::InvalidPublicKey(format!(
            "ML-KEM-768 encapsulation key must be {} bytes, got {}",
            ML_KEM_768_EK_LEN,
            ek_bytes.len()
        )));
    }
    let ek =
        MlKemEncapsulationKey::<MlKem768>::new(ek_bytes.try_into().map_err(|_| {
            CryptoError::InvalidPublicKey("ML-KEM-768 encap-key slice".to_string())
        })?)
        .map_err(|e| CryptoError::InvalidPublicKey(format!("ML-KEM-768 decode: {:?}", e)))?;
    let (ct, ss) = ek.encapsulate();
    let mut ss_out = [0u8; ML_KEM_SS_LEN];
    ss_out.copy_from_slice(ss.as_slice());
    Ok((ct.as_slice().to_vec(), ss_out))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_constants_match_fips() {
        // Sanity: keygen produces the canonical sizes required by FIPS 203/204.
        let dsa = MlDsaSigningKey::generate();
        assert_eq!(dsa.verifying_key_bytes().len(), ML_DSA_65_VK_LEN);
        let sig = dsa.sign(b"x");
        assert_eq!(sig.len(), ML_DSA_65_SIG_LEN);

        let kem = MlKemDecapsulationKey::generate();
        assert_eq!(kem.encapsulation_key_bytes().len(), ML_KEM_768_EK_LEN);
        let (ct, _ss) = ml_kem_encapsulate(kem.encapsulation_key_bytes()).unwrap();
        assert_eq!(ct.len(), ML_KEM_768_CT_LEN);
    }

    #[test]
    fn ml_dsa_sign_verify_roundtrip() {
        let sk = MlDsaSigningKey::generate();
        let msg = b"tenzro hybrid signing";
        let sig = sk.sign(msg);
        ml_dsa_verify(sk.verifying_key_bytes(), msg, &sig).unwrap();
    }

    #[test]
    fn ml_dsa_seed_roundtrip_is_deterministic() {
        let sk1 = MlDsaSigningKey::generate();
        let seed = sk1.seed_bytes().to_vec();
        let sk2 = MlDsaSigningKey::from_seed(&seed).unwrap();
        // Same seed => same verifying key (FIPS-204 KeyGen is seed-deterministic).
        assert_eq!(sk1.verifying_key_bytes(), sk2.verifying_key_bytes());
    }

    #[test]
    fn ml_dsa_rejects_tampered_message() {
        let sk = MlDsaSigningKey::generate();
        let sig = sk.sign(b"original");
        let err = ml_dsa_verify(sk.verifying_key_bytes(), b"tampered", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::VerificationFailed));
    }

    #[test]
    fn ml_dsa_rejects_wrong_vk_length() {
        let sk = MlDsaSigningKey::generate();
        let sig = sk.sign(b"m");
        let truncated = &sk.verifying_key_bytes()[..100];
        let err = ml_dsa_verify(truncated, b"m", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidPublicKey(_)));
    }

    #[test]
    fn ml_dsa_rejects_wrong_sig_length() {
        let sk = MlDsaSigningKey::generate();
        let err = ml_dsa_verify(sk.verifying_key_bytes(), b"m", &[0u8; 100]).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature(_)));
    }

    #[test]
    fn ml_kem_encap_decap_roundtrip() {
        let kem = MlKemDecapsulationKey::generate();
        let (ct, ss_a) = ml_kem_encapsulate(kem.encapsulation_key_bytes()).unwrap();
        let ss_b = kem.decapsulate(&ct).unwrap();
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn ml_kem_rejects_wrong_ek_length() {
        let err = ml_kem_encapsulate(&[0u8; 100]).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidPublicKey(_)));
    }

    #[test]
    fn ml_kem_rejects_wrong_ct_length() {
        let kem = MlKemDecapsulationKey::generate();
        let err = kem.decapsulate(&[0u8; 100]).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidCiphertext(_)));
    }

    #[test]
    fn ml_kem_distinct_keypairs_yield_distinct_shared_secrets() {
        let kem_a = MlKemDecapsulationKey::generate();
        let kem_b = MlKemDecapsulationKey::generate();
        let (_ct_a, ss_a) = ml_kem_encapsulate(kem_a.encapsulation_key_bytes()).unwrap();
        let (_ct_b, ss_b) = ml_kem_encapsulate(kem_b.encapsulation_key_bytes()).unwrap();
        assert_ne!(ss_a, ss_b);
    }
}
