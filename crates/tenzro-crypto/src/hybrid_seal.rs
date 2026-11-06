//! Sealing a secret to a hybrid X25519 + ML-KEM-768 key that lives only in
//! memory.
//!
//! The recipient makes a [`HybridSecretKey`] for one exchange and publishes
//! its [`HybridPublicKey`]. The sender runs an ephemeral X25519 agreement
//! and an ML-KEM-768 encapsulation against it and derives one AES-256-GCM
//! key with HKDF-SHA256 over both shared secrets, salted with a transcript
//! of the recipient key, both exchange messages and the caller's context.
//! Reading the secret needs both exchanges broken; a sealed value made for
//! one context does not open under another.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroizing;

pub use tenzro_types::key_release::HybridPublicKey;

use crate::encryption::SymmetricKey;
use crate::error::{CryptoError, Result};
use crate::ml_kem768::{EphemeralKem, ML_KEM_768_CT_LEN, ML_KEM_768_EK_LEN, encapsulate};

/// Identifier of the scheme.
pub const HYBRID_SEAL_ALG: &str = "x25519-mlkem768-hkdf-sha256-aes-256-gcm";

const SEAL_DOMAIN: &[u8] = b"tenzro/hybrid-seal/v1\0";

/// A secret sealed to a [`HybridPublicKey`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HybridSealed {
    /// The sender's ephemeral X25519 public key.
    pub x25519_share: [u8; 32],
    /// The ML-KEM-768 ciphertext.
    pub ml_kem_ciphertext: Vec<u8>,
    /// AES-256-GCM of the secret, nonce first.
    pub ciphertext: Vec<u8>,
}

fn derive(
    recipient: &HybridPublicKey,
    sealed_share: &[u8; 32],
    ml_kem_ciphertext: &[u8],
    context: &[u8],
    dh: &[u8; 32],
    kem: &[u8; 32],
) -> Result<SymmetricKey> {
    let mut t = Sha256::new();
    t.update(SEAL_DOMAIN);
    t.update(recipient.fingerprint());
    t.update(sealed_share);
    t.update(ml_kem_ciphertext);
    t.update((context.len() as u64).to_le_bytes());
    t.update(context);
    let transcript = t.finalize();
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(dh);
    ikm[32..].copy_from_slice(kem);
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&transcript), &ikm[..])
        .expand(SEAL_DOMAIN, &mut okm[..])
        .map_err(|_| CryptoError::Other("hybrid seal key derivation".into()))?;
    SymmetricKey::from_bytes(&okm[..])
}

/// Seal `plaintext` to `recipient` under `context`.
pub fn seal(recipient: &HybridPublicKey, context: &[u8], plaintext: &[u8]) -> Result<HybridSealed> {
    if recipient.ml_kem.len() != ML_KEM_768_EK_LEN {
        return Err(CryptoError::InvalidPublicKey(format!(
            "an ML-KEM-768 encapsulation key is {ML_KEM_768_EK_LEN} bytes, got {}",
            recipient.ml_kem.len()
        )));
    }
    let (ml_kem_ciphertext, kem) = encapsulate(&recipient.ml_kem)?;
    let kem = Zeroizing::new(kem);
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let share = X25519Public::from(&secret).to_bytes();
    let dh = secret.diffie_hellman(&X25519Public::from(recipient.x25519));
    if !dh.was_contributory() {
        return Err(CryptoError::InvalidPublicKey(
            "the X25519 key is a low-order point".into(),
        ));
    }
    let key = derive(
        recipient,
        &share,
        &ml_kem_ciphertext,
        context,
        dh.as_bytes(),
        &kem,
    )?;
    Ok(HybridSealed {
        x25519_share: share,
        ml_kem_ciphertext,
        ciphertext: key.encrypt(plaintext)?,
    })
}

/// A hybrid key held only in memory, for one exchange.
pub struct HybridSecretKey {
    x25519: StaticSecret,
    ml_kem: EphemeralKem,
    public: HybridPublicKey,
}

impl HybridSecretKey {
    /// A fresh key from the OS random source.
    pub fn generate() -> Self {
        let x25519 = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ml_kem = EphemeralKem::generate();
        let public = HybridPublicKey {
            x25519: X25519Public::from(&x25519).to_bytes(),
            ml_kem: ml_kem.encapsulation_key().to_vec(),
        };
        Self {
            x25519,
            ml_kem,
            public,
        }
    }

    /// The public half, sent to the sealer.
    pub fn public(&self) -> &HybridPublicKey {
        &self.public
    }

    /// Open `sealed`, made for this key under `context`.
    pub fn open(&self, sealed: &HybridSealed, context: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        open_with(self, sealed, context)
    }
}

/// The receiving side of a hybrid seal: the public key sealed to and the two
/// key exchanges that open it. Implemented by [`HybridSecretKey`] and by keys
/// derived on demand from hardware, so the private halves need not be held
/// to open a seal.
pub trait HybridRecipient: Send + Sync {
    /// The public key values are sealed to.
    fn public_key(&self) -> HybridPublicKey;
    /// The raw X25519 shared secret with the sealer's share. Refuses a
    /// low-order share.
    fn agree_x25519(&self, share: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>>;
    /// The ML-KEM-768 shared secret `ciphertext` carries.
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>>;
}

impl HybridRecipient for HybridSecretKey {
    fn public_key(&self) -> HybridPublicKey {
        self.public.clone()
    }

    fn agree_x25519(&self, share: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        let dh = self.x25519.diffie_hellman(&X25519Public::from(*share));
        if !dh.was_contributory() {
            return Err(CryptoError::InvalidPublicKey(
                "the sealer's X25519 share is a low-order point".into(),
            ));
        }
        Ok(Zeroizing::new(*dh.as_bytes()))
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        self.ml_kem.decapsulate(ciphertext).map(Zeroizing::new)
    }
}

/// Open `sealed`, made for `recipient` under `context`.
pub fn open_with(
    recipient: &dyn HybridRecipient,
    sealed: &HybridSealed,
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.ml_kem_ciphertext.len() != ML_KEM_768_CT_LEN {
        return Err(CryptoError::InvalidCiphertext(format!(
            "an ML-KEM-768 ciphertext is {ML_KEM_768_CT_LEN} bytes"
        )));
    }
    let kem = recipient.decapsulate(&sealed.ml_kem_ciphertext)?;
    let dh = recipient.agree_x25519(&sealed.x25519_share)?;
    let key = derive(
        &recipient.public_key(),
        &sealed.x25519_share,
        &sealed.ml_kem_ciphertext,
        context,
        &dh,
        &kem,
    )?;
    key.decrypt(&sealed.ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| {
            CryptoError::DecryptionFailed("the sealed value does not open under this key".into())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_key_and_context_it_was_sealed_to_open_it() {
        let key = HybridSecretKey::generate();
        let other = HybridSecretKey::generate();
        let sealed = seal(key.public(), b"ctx", b"content key").unwrap();
        assert_eq!(&key.open(&sealed, b"ctx").unwrap()[..], b"content key");
        assert!(key.open(&sealed, b"other ctx").is_err());
        assert!(other.open(&sealed, b"ctx").is_err());
    }

    #[test]
    fn breaking_one_exchange_is_not_enough() {
        let key = HybridSecretKey::generate();
        let sealed = seal(key.public(), b"ctx", b"secret").unwrap();
        // A substituted ML-KEM ciphertext decapsulates (implicit rejection)
        // to a different secret, and the key no longer opens it.
        let mut kem_swapped = sealed.clone();
        kem_swapped.ml_kem_ciphertext[0] ^= 1;
        assert!(key.open(&kem_swapped, b"ctx").is_err());
        let mut dh_swapped = sealed;
        dh_swapped.x25519_share =
            X25519Public::from(&StaticSecret::random_from_rng(rand::rngs::OsRng)).to_bytes();
        assert!(key.open(&dh_swapped, b"ctx").is_err());
    }

    #[test]
    fn a_malformed_or_low_order_key_is_refused() {
        let mut public = HybridSecretKey::generate().public().clone();
        public.ml_kem.pop();
        assert!(seal(&public, b"", b"x").is_err());
        let mut low = HybridSecretKey::generate().public().clone();
        low.x25519 = [0; 32];
        assert!(seal(&low, b"", b"x").is_err());
    }
}
