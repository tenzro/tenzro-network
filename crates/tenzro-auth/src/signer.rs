//! The key access tokens are signed with.
//!
//! Tokens are ES256 JWTs. The signing key is held by the issuing node's
//! hardware root; the engine only ever sees the public key and asks the
//! signer for one signature per token, so no token-signing secret exists in
//! the process or on disk.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Header};
use sha2::{Digest, Sha256};

use crate::error::{AuthError, Result};

/// Signs access tokens with a P-256 key the caller never sees.
pub trait TokenSigner: Send + Sync {
    /// The raw `x || y` public key tokens verify under.
    fn public_key(&self) -> [u8; 64];
    /// An ECDSA signature over a SHA-256 prehash, as raw `r || s`.
    fn sign_prehash(&self, prehash: &[u8; 32]) -> std::result::Result<[u8; 64], String>;
}

/// The key id tokens name: the base64url SHA-256 of the public key.
pub fn key_id(public_key: &[u8; 64]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

/// The public key as a JWK, for relying parties that verify tokens offline.
pub fn public_jwk(public_key: &[u8; 64]) -> serde_json::Value {
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(&public_key[..32]),
        "y": URL_SAFE_NO_PAD.encode(&public_key[32..]),
        "kid": key_id(public_key),
        "alg": "ES256",
        "use": "sig",
    })
}

/// The decoding key for tokens signed under `public_key`.
pub(crate) fn decoding_key(public_key: &[u8; 64]) -> Result<DecodingKey> {
    DecodingKey::from_ec_components(
        &URL_SAFE_NO_PAD.encode(&public_key[..32]),
        &URL_SAFE_NO_PAD.encode(&public_key[32..]),
    )
    .map_err(|e| AuthError::Internal(format!("token public key: {e}")))
}

/// Encode `claims` as an ES256 JWT signed by `signer`.
pub(crate) fn sign_jwt<T: serde::Serialize>(
    signer: &dyn TokenSigner,
    claims: &T,
) -> Result<String> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_id(&signer.public_key()));
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let input = format!("{header}.{payload}");
    let prehash: [u8; 32] = Sha256::digest(input.as_bytes()).into();
    let signature = signer
        .sign_prehash(&prehash)
        .map_err(|e| AuthError::Internal(format!("token signing: {e}")))?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// A software signer for this crate's tests.
#[cfg(test)]
pub struct TestTokenSigner(p256::ecdsa::SigningKey);

#[cfg(test)]
impl TestTokenSigner {
    /// A signer whose key is derived from `seed`.
    pub fn from_seed(seed: u8) -> Self {
        let mut bytes = [seed; 32];
        bytes[0] = 1;
        Self(p256::ecdsa::SigningKey::from_slice(&bytes).expect("a valid P-256 scalar"))
    }
}

#[cfg(test)]
impl TokenSigner for TestTokenSigner {
    fn public_key(&self) -> [u8; 64] {
        let point = self.0.verifying_key().to_sec1_point(false);
        let mut out = [0u8; 64];
        out.copy_from_slice(&point.as_bytes()[1..]);
        out
    }

    fn sign_prehash(&self, prehash: &[u8; 32]) -> std::result::Result<[u8; 64], String> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature =
            self.0.sign_prehash(prehash).map_err(|e| e.to_string())?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        Ok(out)
    }
}
