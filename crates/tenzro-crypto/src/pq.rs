//! Post-quantum cryptographic primitives for Tenzro Network.
//!
//! Wraps the RustCrypto FIPS 204 implementation in the same `Vec<u8>`-based
//! shape that the rest of `tenzro-crypto` uses (see `keys.rs` and `signatures.rs`).
//! Higher layers consume composite (classical+pq) keypairs through `composite.rs`.
//!
//! # Algorithm
//!
//! **ML-DSA-65** (FIPS 204): the post-quantum signature. Verifying key is 1952
//! bytes; signature is 3309 bytes. Key encapsulation is ML-KEM-768 in
//! [`crate::ml_kem768`]; `encryption::envelope_encrypt` seals to an X25519 +
//! ML-KEM-768 hybrid key.
//!
//! # Context strings
//!
//! Every ML-DSA-65 signature is made and checked under a FIPS 204 context
//! string (`ctx`, at most 255 bytes). Composite signatures use the composite
//! label (see `composite.rs`); protocols that use ML-DSA on its own pass their
//! own protocol string. A signature made under one context does not verify
//! under any other, including the empty context.
//!
//! # Two verifiers
//!
//! Every ML-DSA-65 signature is checked by two independent implementations,
//! RustCrypto `ml-dsa` and the formally verified `libcrux-ml-dsa`, and is
//! accepted only when both accept it. When they disagree the signature is
//! refused with [`CryptoError::VerifierDisagreement`] and the event is
//! logged: a signature one implementation accepts and the other refuses is
//! either an attack on one of them or a bug in one of them.
//!
//! Signing uses the deterministic variant of ML-DSA.Sign, so key generation is
//! the only place that needs randomness (from the OS via `getrandom`).
//!
//! # Persistence
//!
//! `MlDsaSigningKey` stores the canonical 32-byte FIPS-204 seed (`B32`), not
//! the expanded matrix. The keystore (Argon2id-encrypted) is responsible for
//! sealing this seed at rest; in memory it is wrapped in `Zeroizing` so a `Drop`
//! wipes it. The expanded form is rebuilt every `sign()` via `MlDsa65::from_seed`.

use crate::error::{CryptoError, Result};
use ml_dsa::signature::Keypair;
use ml_dsa::{
    B32, MlDsa65, Signature as MlDsaSignature, SigningKey as MlDsaSigningKeyInner,
    VerifyingKey as MlDsaVerifyingKey,
};
use zeroize::Zeroizing;

/// Longest FIPS 204 context string ML-DSA accepts.
pub const ML_DSA_MAX_CONTEXT_LEN: usize = 255;

/// FIPS 204 context strings for protocols that use ML-DSA-65 as a companion
/// to a signature that is not an Ed25519/secp256k1 composite (a WebAuthn
/// assertion, a gossip announcement). Composite signatures use the composite
/// label instead (see `composite.rs`). Each protocol has its own string so an
/// ML-DSA signature minted for one never verifies for another.
pub mod context {
    /// Post-quantum leg of a signed peer announcement.
    pub const PEER_ANNOUNCE: &[u8] = b"tenzro/network/peer-announce";
    /// Post-quantum leg of a machine controller's node delegation.
    pub const NODE_DELEGATION: &[u8] = b"tenzro/network/node-delegation";
    /// ML-DSA-only verifiable-credential proof.
    pub const CREDENTIAL: &[u8] = b"tenzro/credential/ml-dsa";
    /// Rotation of an identity's governing key to ML-DSA-65.
    pub const PQ_ROTATION: &[u8] = b"tenzro/identity/pq-rotation";
    /// An identity key delegating signing to a short-lived session key
    /// (the issuer leg of a session delegation).
    pub const SESSION_DELEGATION: &[u8] = b"tenzro/identity/session-delegation";
    /// A session key signing a message on behalf of the identity that
    /// delegated to it.
    pub const SESSION_SIGNATURE: &[u8] = b"tenzro/identity/session-signature";
    /// An identity key, in hardware, signing the Merkle root of a batch of
    /// messages.
    pub const BATCH_ROOT: &[u8] = b"tenzro/identity/batch-root";
}

// ---------------------------------------------------------------------------
// Sizes (FIPS 204) — surfaced as constants so wire-format code can length-prefix
// without re-running keygen. Validated by `pq_constants_match_fips` test below.
// ---------------------------------------------------------------------------

/// ML-DSA-65 verifying key size in bytes (FIPS 204 §4 Table 2).
pub const ML_DSA_65_VK_LEN: usize = 1952;
/// ML-DSA-65 signature size in bytes (FIPS 204 §4 Table 2).
pub const ML_DSA_65_SIG_LEN: usize = 3309;
/// ML-DSA-65 seed size — canonical persistable form, FIPS 204 ξ value.
pub const ML_DSA_65_SEED_LEN: usize = 32;

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

    /// Sign `msg` under the FIPS 204 context string `ctx` and return the
    /// encoded signature (3309 bytes, FIPS 204 §4 Table 2).
    ///
    /// `ctx` is always a protocol constant, never caller input, so its length
    /// bound (255 bytes) is an invariant of the program rather than a runtime
    /// condition.
    pub fn sign(&self, ctx: &'static [u8], msg: &[u8]) -> Vec<u8> {
        assert!(
            ctx.len() <= ML_DSA_MAX_CONTEXT_LEN,
            "ML-DSA context string longer than 255 bytes"
        );
        // Re-derive the SigningKey from the seed each call. This is
        // ~ms-class work and keeps the in-memory secret surface to 32 bytes.
        let xi = B32::from(*self.seed);
        let sk = MlDsaSigningKeyInner::<MlDsa65>::from_seed(&xi);
        let sig: MlDsaSignature<MlDsa65> = sk
            .expanded_key()
            .sign_deterministic(msg, ctx)
            .expect("context length checked above");
        sig.encode().to_vec()
    }
}

/// Verify an ML-DSA-65 signature made under the FIPS 204 context string `ctx`
/// with both implementations (see the module documentation).
///
/// # Errors
///
/// - `CryptoError::InvalidPublicKey` if `vk_bytes.len() != ML_DSA_65_VK_LEN` or
///   the bytes do not decode to a valid lattice element.
/// - `CryptoError::InvalidSignature` if `sig_bytes.len() != ML_DSA_65_SIG_LEN`,
///   the bytes do not decode to a valid signature shape, or `ctx` is longer
///   than 255 bytes.
/// - `CryptoError::VerificationFailed` if the signature is well-formed but does
///   not bind `(ctx, msg)` to `vk_bytes`.
/// - `CryptoError::VerifierDisagreement` if one implementation accepts the
///   signature and the other refuses it.
pub fn ml_dsa_verify(vk_bytes: &[u8], ctx: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    if ctx.len() > ML_DSA_MAX_CONTEXT_LEN {
        return Err(CryptoError::InvalidSignature(
            "ML-DSA context string longer than 255 bytes".to_string(),
        ));
    }
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
    both_verifiers(
        rustcrypto_ml_dsa_verify,
        libcrux_ml_dsa_verify,
        vk_bytes,
        ctx,
        msg,
        sig_bytes,
    )
}

/// One ML-DSA-65 implementation's verdict on `(vk, ctx, msg, sig)`.
type Verifier = fn(&[u8], &[u8], &[u8], &[u8]) -> Result<()>;

/// Accepts only when `primary` and `second` both accept. When exactly one
/// accepts, the signature is refused with `VerifierDisagreement` and the
/// event is logged with the key and signature fingerprints; when both refuse,
/// the primary's reason is returned.
fn both_verifiers(
    primary: Verifier,
    second: Verifier,
    vk_bytes: &[u8],
    ctx: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    let first = primary(vk_bytes, ctx, msg, sig_bytes);
    let other = second(vk_bytes, ctx, msg, sig_bytes);
    match (first, other) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Err(_)) => Err(e),
        (first, _) => {
            tracing::error!(
                rustcrypto_accepts = first.is_ok(),
                vk = %hex::encode(fingerprint(vk_bytes)),
                sig = %hex::encode(fingerprint(sig_bytes)),
                "ML-DSA-65 implementations disagree; the signature is refused"
            );
            Err(CryptoError::VerifierDisagreement)
        }
    }
}

/// First 8 bytes of SHA-256, to name a key or signature in a log line.
fn fingerprint(bytes: &[u8]) -> [u8; 8] {
    let h = crate::hash::sha256(bytes);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.as_bytes()[..8]);
    out
}

/// RustCrypto `ml-dsa` verification of an ML-DSA-65 signature.
pub fn rustcrypto_ml_dsa_verify(
    vk_bytes: &[u8],
    ctx: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey};

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

    // The ml-dsa version pinned at workspace level rejects duplicate hint
    // indices, so a signature has a single valid encoding.
    if !vk.verify_with_context(msg, ctx, &sig) {
        return Err(CryptoError::VerificationFailed);
    }
    Ok(())
}

/// [`ml_dsa_verify`] for a bare key and signature of `scheme`.
pub fn ml_dsa_verify_scheme(
    scheme: tenzro_types::signature_scheme::SignatureScheme,
    vk_bytes: &[u8],
    ctx: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    use tenzro_types::signature_scheme::SignatureScheme;
    match scheme {
        SignatureScheme::MlDsa65P256 => ml_dsa_verify(vk_bytes, ctx, msg, sig_bytes),
        SignatureScheme::MlDsa87P384 => {
            ml_dsa_verify_params::<ml_dsa::MlDsa87>(vk_bytes, ctx, msg, sig_bytes)
        }
    }
}

fn ml_dsa_verify_params<P: ml_dsa::MlDsaParams>(
    vk_bytes: &[u8],
    ctx: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey};
    if ctx.len() > ML_DSA_MAX_CONTEXT_LEN {
        return Err(CryptoError::InvalidSignature(
            "ML-DSA context string longer than 255 bytes".to_string(),
        ));
    }
    let mut vk_arr: EncodedVerifyingKey<P> = Default::default();
    if vk_arr.len() != vk_bytes.len() {
        return Err(CryptoError::InvalidPublicKey(
            "ML-DSA verifying key has the wrong length for its scheme".to_string(),
        ));
    }
    vk_arr.copy_from_slice(vk_bytes);
    let vk = MlDsaVerifyingKey::<P>::decode(&vk_arr);
    let mut sig_arr: EncodedSignature<P> = Default::default();
    if sig_arr.len() != sig_bytes.len() {
        return Err(CryptoError::InvalidSignature(
            "ML-DSA signature has the wrong length for its scheme".to_string(),
        ));
    }
    sig_arr.copy_from_slice(sig_bytes);
    let sig = MlDsaSignature::<P>::decode(&sig_arr).ok_or_else(|| {
        CryptoError::InvalidSignature("ML-DSA signature failed to decode".to_string())
    })?;
    if !vk.verify_with_context(msg, ctx, &sig) {
        return Err(CryptoError::VerificationFailed);
    }
    Ok(())
}

/// `libcrux-ml-dsa` verification of an ML-DSA-65 signature: the second,
/// formally verified implementation. Public so that a verifier that runs the
/// RustCrypto implementation elsewhere (the consensus finality checks) can
/// compare its verdict with this one.
pub fn libcrux_ml_dsa_verify(
    vk_bytes: &[u8],
    ctx: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    use libcrux_ml_dsa::ml_dsa_65::{MLDSA65Signature, MLDSA65VerificationKey, verify};

    let vk: [u8; ML_DSA_65_VK_LEN] = vk_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey("ML-DSA-65 verifying key length".to_string()))?;
    let sig: [u8; ML_DSA_65_SIG_LEN] = sig_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature("ML-DSA-65 signature length".to_string()))?;
    let vk = Box::new(MLDSA65VerificationKey::new(vk));
    let sig = Box::new(MLDSA65Signature::new(sig));
    verify(&vk, msg, ctx, &sig).map_err(|_| CryptoError::VerificationFailed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_constants_match_fips() {
        // Sanity: keygen produces the canonical sizes required by FIPS 204.
        let dsa = MlDsaSigningKey::generate();
        assert_eq!(dsa.verifying_key_bytes().len(), ML_DSA_65_VK_LEN);
        let sig = dsa.sign(CTX, b"x");
        assert_eq!(sig.len(), ML_DSA_65_SIG_LEN);
    }

    const CTX: &[u8] = b"tenzro/test";

    /// A signature with one bit of a coefficient flipped: well-formed, invalid.
    fn mutated(sig: &[u8]) -> Vec<u8> {
        let mut bad = sig.to_vec();
        bad[100] ^= 0x01;
        bad
    }

    fn accept_all(_: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<()> {
        Ok(())
    }

    #[test]
    fn ml_dsa_both_implementations_accept_a_valid_signature() {
        let sk = MlDsaSigningKey::generate();
        let sig = sk.sign(CTX, b"m");
        rustcrypto_ml_dsa_verify(sk.verifying_key_bytes(), CTX, b"m", &sig).unwrap();
        libcrux_ml_dsa_verify(sk.verifying_key_bytes(), CTX, b"m", &sig).unwrap();
    }

    #[test]
    fn ml_dsa_both_implementations_refuse_a_mutated_signature() {
        let sk = MlDsaSigningKey::generate();
        let bad = mutated(&sk.sign(CTX, b"m"));
        let vk = sk.verifying_key_bytes();
        assert!(rustcrypto_ml_dsa_verify(vk, CTX, b"m", &bad).is_err());
        assert!(libcrux_ml_dsa_verify(vk, CTX, b"m", &bad).is_err());
        assert!(!matches!(
            ml_dsa_verify(vk, CTX, b"m", &bad),
            Ok(()) | Err(CryptoError::VerifierDisagreement)
        ));
    }

    #[test]
    fn ml_dsa_mutated_signature_one_implementation_accepts_is_refused() {
        // One implementation patched to accept anything, as a verifier bug
        // would: the mutated signature it accepts and the other refuses must
        // be refused as a disagreement, whichever side is broken.
        let sk = MlDsaSigningKey::generate();
        let bad = mutated(&sk.sign(CTX, b"m"));
        let vk = sk.verifying_key_bytes();
        assert!(matches!(
            both_verifiers(accept_all, libcrux_ml_dsa_verify, vk, CTX, b"m", &bad),
            Err(CryptoError::VerifierDisagreement)
        ));
        assert!(matches!(
            both_verifiers(rustcrypto_ml_dsa_verify, accept_all, vk, CTX, b"m", &bad),
            Err(CryptoError::VerifierDisagreement)
        ));
        let good = sk.sign(CTX, b"m");
        both_verifiers(
            rustcrypto_ml_dsa_verify,
            libcrux_ml_dsa_verify,
            vk,
            CTX,
            b"m",
            &good,
        )
        .unwrap();
    }

    #[test]
    fn ml_dsa_implementations_agree_on_random_mutations() {
        // Differential check over single-bit mutations of a valid signature,
        // key and message: the two implementations never differ.
        let sk = MlDsaSigningKey::generate();
        let vk = sk.verifying_key_bytes().to_vec();
        let sig = sk.sign(CTX, b"differential");
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let (mut v, mut s, mut m) = (vk.clone(), sig.clone(), b"differential".to_vec());
            let which = next() % 3;
            let (at, bit) = (next() as usize, 1u8 << (next() % 8));
            match which {
                0 => s[at % ML_DSA_65_SIG_LEN] ^= bit,
                1 => v[at % ML_DSA_65_VK_LEN] ^= bit,
                _ => m[at % 12] ^= bit,
            }
            let a = rustcrypto_ml_dsa_verify(&v, CTX, &m, &s).is_ok();
            let b = libcrux_ml_dsa_verify(&v, CTX, &m, &s).is_ok();
            assert_eq!(a, b, "implementations differ");
        }
    }

    #[test]
    fn ml_dsa_sign_verify_roundtrip() {
        let sk = MlDsaSigningKey::generate();
        let msg = b"tenzro hybrid signing";
        let sig = sk.sign(CTX, msg);
        ml_dsa_verify(sk.verifying_key_bytes(), CTX, msg, &sig).unwrap();
    }

    #[test]
    fn ml_dsa_signature_is_bound_to_its_context() {
        let sk = MlDsaSigningKey::generate();
        let sig = sk.sign(CTX, b"m");
        // Neither the empty context nor another protocol's context accepts it.
        assert!(ml_dsa_verify(sk.verifying_key_bytes(), b"", b"m", &sig).is_err());
        assert!(ml_dsa_verify(sk.verifying_key_bytes(), b"tenzro/other", b"m", &sig).is_err());
    }

    #[test]
    fn ml_dsa_rejects_overlong_context() {
        let sk = MlDsaSigningKey::generate();
        let sig = sk.sign(CTX, b"m");
        let long = [0u8; 256];
        let err = ml_dsa_verify(sk.verifying_key_bytes(), &long, b"m", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature(_)));
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
        let sig = sk.sign(CTX, b"original");
        let err = ml_dsa_verify(sk.verifying_key_bytes(), CTX, b"tampered", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::VerificationFailed));
    }

    #[test]
    fn ml_dsa_rejects_wrong_vk_length() {
        let sk = MlDsaSigningKey::generate();
        let sig = sk.sign(CTX, b"m");
        let truncated = &sk.verifying_key_bytes()[..100];
        let err = ml_dsa_verify(truncated, CTX, b"m", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidPublicKey(_)));
    }

    #[test]
    fn ml_dsa_rejects_wrong_sig_length() {
        let sk = MlDsaSigningKey::generate();
        let err = ml_dsa_verify(sk.verifying_key_bytes(), CTX, b"m", &[0u8; 100]).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature(_)));
    }
}
