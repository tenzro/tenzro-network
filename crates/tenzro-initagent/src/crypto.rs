//! Guest-side sealed-env unsealing.
//!
//! Byte-identical to `tenzro_crypto::encryption`'s envelope scheme so an
//! envelope produced by the node (`envelope_encrypt`) unseals here and vice
//! versa. Reimplemented directly on the primitive crates (rather than depending
//! on `tenzro-crypto`) to keep the static guest binary small — the guest needs
//! only the sealing envelope, not the node's full crypto surface (BLS, ML-DSA,
//! FROST, …). The cross-crate compatibility is asserted in the tests, which
//! encrypt with the real `tenzro_crypto` and decrypt here.
//!
//! Scheme (must match `tenzro_crypto::encryption` exactly):
//!   * X25519 ephemeral-static exchange to the recipient key;
//!   * the raw shared point is run through HKDF-SHA256 with the info string
//!     `"tenzro/x25519/envelope/key-wrap"` and a salt equal to the transcript
//!     `ephemeral_pub || recipient_pub` (32+32 bytes);
//!   * the resulting 32-byte key AES-256-GCM-unwraps the data key;
//!   * the data key AES-256-GCM-decrypts the payload.
//!   * every AES-GCM ciphertext is `nonce(12) || ct`.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

const AES_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
/// HKDF `info` for the envelope key-wrapping key. Must match
/// `tenzro_crypto::encryption::ENVELOPE_HKDF_INFO`.
const ENVELOPE_HKDF_INFO: &[u8] = b"tenzro/x25519/envelope/key-wrap";

/// A single sealed environment secret. Mirrors
/// `tenzro_node::machines::SealedEnvVar`: `name` is plaintext, `sealed_value`
/// is the JSON-serialized [`EncryptedEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEnvVar {
    pub name: String,
    pub sealed_value: serde_json::Value,
}

/// Envelope layout, matching `tenzro_crypto::encryption::EncryptedEnvelope`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub encrypted_key: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub sender_public_key: [u8; 32],
}

/// Errors from unsealing.
#[derive(Debug)]
pub enum CryptoError {
    BadKeyLen,
    Decode(String),
    Aead(&'static str),
    NonUtf8(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::BadKeyLen => write!(f, "guest sealing key must be 32 bytes"),
            CryptoError::Decode(e) => write!(f, "envelope decode: {e}"),
            CryptoError::Aead(w) => write!(f, "AES-GCM {w} failed (wrong key or tampered)"),
            CryptoError::NonUtf8(n) => write!(f, "sealed value {n} is not UTF-8"),
        }
    }
}

impl std::error::Error for CryptoError {}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; AES_KEY_SIZE] {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; AES_KEY_SIZE];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand of 32 bytes never exceeds the 255*32 limit");
    okm
}

/// AES-256-GCM decrypt of a `nonce(12) || ciphertext` buffer.
fn aead_open(key: &[u8; AES_KEY_SIZE], buf: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if buf.len() < NONCE_SIZE {
        return Err(CryptoError::Aead("ciphertext too short"));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&buf[..NONCE_SIZE]);
    cipher
        .decrypt(nonce, &buf[NONCE_SIZE..])
        .map_err(|_| CryptoError::Aead("decrypt"))
}

/// Decrypt an envelope with the guest's 32-byte X25519 secret key.
pub fn envelope_decrypt(
    recipient_secret: &[u8; 32],
    envelope: &EncryptedEnvelope,
) -> Result<Vec<u8>, CryptoError> {
    let secret = X25519StaticSecret::from(*recipient_secret);
    let recipient_public = X25519PublicKey::from(&secret);
    let sender_public = X25519PublicKey::from(envelope.sender_public_key);
    let shared = secret.diffie_hellman(&sender_public);

    // Transcript salt: ephemeral (== sender) public then recipient public.
    let mut transcript = [0u8; 64];
    transcript[..32].copy_from_slice(&envelope.sender_public_key);
    transcript[32..].copy_from_slice(recipient_public.as_bytes());
    let wrap_key = hkdf_sha256(shared.as_bytes(), &transcript, ENVELOPE_HKDF_INFO);

    let data_key_bytes = aead_open(&wrap_key, &envelope.encrypted_key)?;
    if data_key_bytes.len() != AES_KEY_SIZE {
        return Err(CryptoError::Aead("unwrapped data key wrong size"));
    }
    let mut data_key = [0u8; AES_KEY_SIZE];
    data_key.copy_from_slice(&data_key_bytes);
    aead_open(&data_key, &envelope.encrypted_data)
}

/// Unseal every [`SealedEnvVar`] to a `(name, value)` pair.
///
/// A secret that fails to unseal is fatal — running the app with a missing
/// secret would silently misconfigure it. Matches the node supervisor's
/// fail-closed `unseal_env`.
pub fn unseal_all(
    recipient_secret: &[u8; 32],
    sealed: &[SealedEnvVar],
) -> Result<Vec<(String, String)>, CryptoError> {
    let mut out = Vec::with_capacity(sealed.len());
    for var in sealed {
        let envelope: EncryptedEnvelope = serde_json::from_value(var.sealed_value.clone())
            .map_err(|e| CryptoError::Decode(format!("{}: {e}", var.name)))?;
        let plaintext = envelope_decrypt(recipient_secret, &envelope)?;
        let value =
            String::from_utf8(plaintext).map_err(|_| CryptoError::NonUtf8(var.name.clone()))?;
        out.push((var.name.clone(), value));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cross-crate wire-compat: encrypt with the node's real crypto, decrypt
    // here. Proves the guest can unseal what the node seals.
    #[test]
    fn decrypts_node_produced_envelope() {
        use tenzro_crypto::encryption as node;

        // Guest keypair: derive the public the node seals to from our secret.
        let secret_bytes = [7u8; 32];
        let secret = X25519StaticSecret::from(secret_bytes);
        let public = X25519PublicKey::from(&secret);
        let node_pub = node::X25519PublicKey::from(public.to_bytes());

        let plaintext = b"postgres://user:pass@db:5432/app";
        let node_env = node::envelope_encrypt(&node_pub, plaintext).unwrap();

        // Serialize the node envelope, deserialize into ours (proves the shapes
        // match), and unseal.
        let as_json = serde_json::to_value(&node_env).unwrap();
        let ours: EncryptedEnvelope = serde_json::from_value(as_json).unwrap();
        let out = envelope_decrypt(&secret_bytes, &ours).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn unseal_all_maps_names_to_values() {
        use tenzro_crypto::encryption as node;
        let secret_bytes = [42u8; 32];
        let public = X25519PublicKey::from(&X25519StaticSecret::from(secret_bytes));
        let node_pub = node::X25519PublicKey::from(public.to_bytes());

        let mk = |v: &str| SealedEnvVar {
            name: "K".into(),
            sealed_value: serde_json::to_value(node::envelope_encrypt(&node_pub, v.as_bytes()).unwrap())
                .unwrap(),
        };
        let sealed = vec![
            SealedEnvVar { name: "A".into(), ..mk("alpha") },
            SealedEnvVar { name: "B".into(), ..mk("beta") },
        ];
        let out = unseal_all(&secret_bytes, &sealed).unwrap();
        assert_eq!(out, vec![("A".to_string(), "alpha".to_string()), ("B".to_string(), "beta".to_string())]);
    }

    #[test]
    fn wrong_key_fails_closed() {
        use tenzro_crypto::encryption as node;
        let public = X25519PublicKey::from(&X25519StaticSecret::from([1u8; 32]));
        let node_pub = node::X25519PublicKey::from(public.to_bytes());
        let env = node::envelope_encrypt(&node_pub, b"secret").unwrap();
        let ours: EncryptedEnvelope =
            serde_json::from_value(serde_json::to_value(&env).unwrap()).unwrap();
        // A different guest secret must not decrypt.
        assert!(envelope_decrypt(&[2u8; 32], &ours).is_err());
    }
}
