//! Validator composite keys: ML-DSA-65 together with ECDSA-P256.
//!
//! The construction is the composite ML-DSA-65 / ECDSA-P256-SHA512 scheme of
//! the IETF LAMPS composite-signature specification:
//!
//! ```text
//! M' = PREFIX || LABEL || len(ctx) || ctx || SHA-512(M)
//! mldsa_sig = ML-DSA-65.Sign(sk_mldsa, M', context = LABEL)
//! ecdsa_sig = ECDSA-P256-SHA256.Sign(sk_p256, M')
//! ```
//!
//! A composite verifies only when both legs verify.
//!
//! A key names its [`SignatureScheme`] in its ML-DSA leg (see
//! [`tenzro_types::signature_scheme`]); a signature verifies only under a key
//! of its own scheme.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::error::{FinalityError, Result};

pub use tenzro_types::signature_scheme::SignatureScheme;

/// ML-DSA-65 verifying key length (FIPS 204).
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
/// ML-DSA-65 signature length (FIPS 204).
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
/// Uncompressed SEC1 P-256 public key length.
pub const P256_PUBLIC_KEY_LEN: usize = 65;
/// Raw `r || s` P-256 signature length.
pub const P256_SIGNATURE_LEN: usize = 64;

/// Composite signature prefix of the IETF composite-signature construction.
const COMPOSITE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
/// Composite label for ML-DSA-65 with ECDSA-P256-SHA512. Also the ML-DSA
/// context string.
const COMPOSITE_LABEL: &[u8] = b"COMPSIG-MLDSA65-ECDSA-P256-SHA512";

/// A validator's composite public key.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidatorPublicKey {
    /// ML-DSA-65 verifying key, 1952 bytes.
    pub ml_dsa: Vec<u8>,
    /// Uncompressed SEC1 P-256 public key, 65 bytes.
    pub p256: Vec<u8>,
}

impl std::fmt::Debug for ValidatorPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ValidatorPublicKey({})",
            hex::encode(&self.fingerprint()[..8])
        )
    }
}

impl ValidatorPublicKey {
    /// Builds a key from its parts, checking both lengths and that the P-256
    /// point is on the curve.
    pub fn new(ml_dsa: Vec<u8>, p256: Vec<u8>) -> Result<Self> {
        let key = Self { ml_dsa, p256 };
        key.check_well_formed()?;
        Ok(key)
    }

    /// Refuses a key whose legs have the wrong length or do not decode.
    pub fn check_well_formed(&self) -> Result<()> {
        if SignatureScheme::split_public_key(&self.ml_dsa).is_none() {
            return Err(FinalityError::InvalidValidatorKey(format!(
                "the ML-DSA leg names no known scheme: an ML-DSA-65 key is \
                 {ML_DSA_65_PUBLIC_KEY_LEN} bytes, got {}",
                self.ml_dsa.len()
            )));
        }
        let scheme = self.scheme();
        let ecdsa_len = scheme.ecdsa_public_key_len();
        if self.p256.len() != ecdsa_len || self.p256[0] != 0x04 {
            return Err(FinalityError::InvalidValidatorKey(format!(
                "the ECDSA key of {scheme:?} must be a {ecdsa_len}-byte uncompressed SEC1 point"
            )));
        }
        let on_curve = match scheme {
            SignatureScheme::MlDsa65P256 => {
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.p256).is_ok()
            }
            SignatureScheme::MlDsa87P384 => {
                p384::ecdsa::VerifyingKey::from_sec1_bytes(&self.p256).is_ok()
            }
        };
        if !on_curve {
            return Err(FinalityError::InvalidValidatorKey(
                "the ECDSA key is not a point on its curve".into(),
            ));
        }
        Ok(())
    }

    /// The scheme the key names. A key that names none is refused by
    /// [`Self::check_well_formed`].
    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::split_public_key(&self.ml_dsa)
            .map(|(s, _)| s)
            .unwrap_or_default()
    }

    /// BLAKE3 over both legs; identifies the key in logs and in the
    /// committee root.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"tenzro/consensus/validator-key");
        h.update(&self.ml_dsa);
        h.update(&self.p256);
        h.finalize().into()
    }

    /// Verifies a composite signature made for `domain` over `message`.
    pub fn verify(&self, domain: &[u8], message: &[u8], signature: &CompositeSignature) -> bool {
        let Some((scheme, key)) = SignatureScheme::split_public_key(&self.ml_dsa) else {
            return false;
        };
        let Some((signed_as, ml_dsa)) = SignatureScheme::split_signature(&signature.ml_dsa) else {
            return false;
        };
        if signed_as != scheme || signature.p256.len() != scheme.ecdsa_signature_len() {
            return false;
        }
        let Some(representative) = message_representative_for(scheme, domain, message) else {
            return false;
        };
        verify_ml_dsa_for(scheme, key, &representative, ml_dsa)
            && verify_ecdsa_for(scheme, &self.p256, &representative, &signature.p256)
    }

    /// Verifies the P-256 leg alone of a composite signature made for
    /// `domain` over `message`. For a compact certificate, whose proof
    /// stands in for the ML-DSA legs.
    pub fn verify_p256_leg(&self, domain: &[u8], message: &[u8], p256_signature: &[u8]) -> bool {
        if self.scheme() != SignatureScheme::MlDsa65P256
            || p256_signature.len() != P256_SIGNATURE_LEN
        {
            return false;
        }
        message_representative_for(self.scheme(), domain, message)
            .is_some_and(|representative| verify_p256(&self.p256, &representative, p256_signature))
    }
}

/// A composite signature: both legs are mandatory.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositeSignature {
    /// ML-DSA-65 signature, 3309 bytes.
    pub ml_dsa: Vec<u8>,
    /// ECDSA-P256 signature, raw `r || s`.
    pub p256: Vec<u8>,
}

impl std::fmt::Debug for CompositeSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CompositeSignature(ml_dsa: {} B, p256: {} B)",
            self.ml_dsa.len(),
            self.p256.len()
        )
    }
}

/// The message representative both legs sign, or `None` when the domain is
/// longer than the 255 bytes a context may hold.
pub fn message_representative(domain: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    message_representative_for(SignatureScheme::default(), domain, message)
}

/// [`message_representative`] under `scheme`'s label.
pub fn message_representative_for(
    scheme: SignatureScheme,
    domain: &[u8],
    message: &[u8],
) -> Option<Vec<u8>> {
    let label = scheme.label();
    let ctx_len = u8::try_from(domain.len()).ok()?;
    let mut out = Vec::with_capacity(COMPOSITE_PREFIX.len() + label.len() + 1 + domain.len() + 64);
    out.extend_from_slice(COMPOSITE_PREFIX);
    out.extend_from_slice(label);
    out.push(ctx_len);
    out.extend_from_slice(domain);
    out.extend_from_slice(&Sha512::digest(message));
    Some(out)
}

/// The ML-DSA context string for the composite construction.
pub fn ml_dsa_context() -> &'static [u8] {
    COMPOSITE_LABEL
}

/// Verifies the ML-DSA-65 leg of a composite signature over its message
/// representative.
pub fn verify_ml_dsa(public_key: &[u8], representative: &[u8], signature: &[u8]) -> bool {
    verify_ml_dsa_for(
        SignatureScheme::default(),
        public_key,
        representative,
        signature,
    )
}

/// Verifies a bare ML-DSA leg of `scheme` over its message representative.
pub fn verify_ml_dsa_for(
    scheme: SignatureScheme,
    public_key: &[u8],
    representative: &[u8],
    signature: &[u8],
) -> bool {
    match scheme {
        SignatureScheme::MlDsa65P256 => verify_ml_dsa_with::<ml_dsa::MlDsa65>(
            public_key,
            representative,
            signature,
            scheme.label(),
        ),
        SignatureScheme::MlDsa87P384 => verify_ml_dsa_with::<ml_dsa::MlDsa87>(
            public_key,
            representative,
            signature,
            scheme.label(),
        ),
    }
}

fn verify_ml_dsa_with<P: ml_dsa::MlDsaParams>(
    public_key: &[u8],
    representative: &[u8],
    signature: &[u8],
    label: &[u8],
) -> bool {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Signature, VerifyingKey};
    let mut vk_enc: EncodedVerifyingKey<P> = Default::default();
    if vk_enc.len() != public_key.len() {
        return false;
    }
    vk_enc.copy_from_slice(public_key);
    let vk = VerifyingKey::<P>::decode(&vk_enc);
    let mut sig_enc: EncodedSignature<P> = Default::default();
    if sig_enc.len() != signature.len() {
        return false;
    }
    sig_enc.copy_from_slice(signature);
    let Some(sig) = Signature::<P>::decode(&sig_enc) else {
        return false;
    };
    vk.verify_with_context(representative, label, &sig)
}

/// Verifies the ECDSA leg of `scheme` over its message representative:
/// P-256 over SHA-256 of it, or P-384 over SHA-384 of it.
pub fn verify_ecdsa_for(
    scheme: SignatureScheme,
    public_key: &[u8],
    representative: &[u8],
    signature: &[u8],
) -> bool {
    match scheme {
        SignatureScheme::MlDsa65P256 => verify_p256(public_key, representative, signature),
        SignatureScheme::MlDsa87P384 => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            let Ok(vk) = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key) else {
                return false;
            };
            let Ok(sig) = p384::ecdsa::Signature::from_slice(signature) else {
                return false;
            };
            let sig = sig.normalize_s();
            let digest: [u8; 48] = sha2::Sha384::digest(representative).into();
            vk.verify_prehash(&digest, &sig).is_ok()
        }
    }
}

/// Verifies the P-256 leg of a composite signature over its message
/// representative.
pub fn verify_p256(public_key: &[u8], representative: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(signature) else {
        return false;
    };
    // Hardware returns high-S signatures about half the time; normalising
    // keeps one key verifying consistently. Evidence compares the signed
    // message, never the signature encoding, so malleability is harmless.
    let sig = sig.normalize_s();
    let digest: [u8; 32] = sha2::Sha256::digest(representative).into();
    vk.verify_prehash(&digest, &sig).is_ok()
}
