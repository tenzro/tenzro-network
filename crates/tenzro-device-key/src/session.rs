//! Ephemeral session keys authenticated by a hardware key.
//!
//! A hardware key signs slowly and cannot sign for every message of a busy
//! exchange. So two parties run one handshake, the hardware key signs it, and
//! both derive a symmetric session key from it. The session key:
//!
//! - is derived from an ephemeral P-256 key agreement, so it exists only for
//!   this handshake and is unrelated to the hardware key itself;
//! - lives only in memory ([`SessionKey`] has no serialization and zeroizes on
//!   drop) and expires at the time the hardware key signed;
//! - is bound to the purpose, both ephemeral keys and the initiator's nonce,
//!   all of which the hardware key signed, so it cannot be moved to another
//!   purpose or replayed into another handshake.
//!
//! The responder holds the hardware key:
//!
//! ```ignore
//! let (initiator, offer) = session::Initiator::new()?;           // peer
//! let (reply, key_r) = session::respond(&*signer, &offer, "rpc", expires_at)?; // hardware holder
//! let key_i = initiator.complete(&reply, &expected_hardware_key, "rpc", now)?; // peer
//! assert_eq!(key_i.expose(), key_r.expose());
//! ```

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::signer::{HardwareSigner, verify_p256_prehash};
use crate::{DeviceKeyError, Result};

const TRANSCRIPT_DOMAIN: &[u8] = b"tenzro/hardware-session/v1\0";
const KEY_INFO: &[u8] = b"tenzro/hardware-session/v1/key";

fn err(msg: impl Into<String>) -> DeviceKeyError {
    DeviceKeyError::Enclave(msg.into())
}

fn random_nonce() -> Result<[u8; 32]> {
    use rand::RngCore;
    let mut n = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut n)
        .map_err(|e| err(format!("OS RNG: {e}")))?;
    Ok(n)
}

fn sec1(pk: &p256::PublicKey) -> [u8; 65] {
    let enc = pk.to_sec1_bytes();
    let mut out = [0u8; 65];
    out.copy_from_slice(&enc);
    out
}

/// What the initiator sends: its ephemeral public key and a fresh nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeOffer {
    pub ephemeral_public: [u8; 65],
    pub nonce: [u8; 32],
}

/// The responder's reply, signed by its hardware key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHandshake {
    /// The responder's hardware public key (uncompressed SEC1).
    pub hardware_public: [u8; 65],
    pub ephemeral_public: [u8; 65],
    /// Unix seconds after which the session key must not be used.
    pub expires_at: u64,
    /// Raw `r || s` over [`transcript_digest`].
    pub signature: [u8; 64],
}

/// A session key. Memory only: it cannot be serialized and is wiped on drop.
pub struct SessionKey {
    key: Zeroizing<[u8; 32]>,
    expires_at: u64,
}

impl SessionKey {
    /// The key bytes, for keying an AEAD or MAC. Do not persist them.
    pub fn expose(&self) -> &[u8; 32] {
        &self.key
    }

    /// Whether the session is still valid at `now` (Unix seconds).
    pub fn is_valid_at(&self, now: u64) -> bool {
        now <= self.expires_at
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// The digest the hardware key signs.
pub fn transcript_digest(
    purpose: &str,
    offer: &HandshakeOffer,
    responder_ephemeral: &[u8; 65],
    hardware_public: &[u8; 65],
    expires_at: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TRANSCRIPT_DOMAIN);
    h.update((purpose.len() as u32).to_be_bytes());
    h.update(purpose.as_bytes());
    h.update(offer.ephemeral_public);
    h.update(offer.nonce);
    h.update(responder_ephemeral);
    h.update(hardware_public);
    h.update(expires_at.to_be_bytes());
    h.finalize().into()
}

fn derive(shared: &[u8], transcript: &[u8; 32], expires_at: u64) -> Result<SessionKey> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(transcript), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(KEY_INFO, key.as_mut())
        .map_err(|_| err("session key derivation failed"))?;
    Ok(SessionKey { key, expires_at })
}

/// The party without the hardware key, starting a handshake.
pub struct Initiator {
    secret: p256::ecdh::EphemeralSecret,
    offer: HandshakeOffer,
}

impl Initiator {
    pub fn new() -> Result<(Self, HandshakeOffer)> {
        let secret = <p256::ecdh::EphemeralSecret as p256::elliptic_curve::Generate>::generate();
        let offer = HandshakeOffer {
            ephemeral_public: sec1(&secret.public_key()),
            nonce: random_nonce()?,
        };
        Ok((
            Self {
                secret,
                offer: offer.clone(),
            },
            offer,
        ))
    }

    /// Check the reply is signed by `expected_hardware_key` for `purpose` and
    /// this offer, is not expired at `now`, and derive the session key.
    pub fn complete(
        self,
        reply: &SignedHandshake,
        expected_hardware_key: &[u8],
        purpose: &str,
        now: u64,
    ) -> Result<SessionKey> {
        if reply.hardware_public.as_slice() != expected_hardware_key {
            return Err(err("the handshake is signed by a different hardware key"));
        }
        if now > reply.expires_at {
            return Err(err("the handshake has expired"));
        }
        let digest = transcript_digest(
            purpose,
            &self.offer,
            &reply.ephemeral_public,
            &reply.hardware_public,
            reply.expires_at,
        );
        if !verify_p256_prehash(&reply.hardware_public, &digest, &reply.signature) {
            return Err(err(
                "the hardware signature over the handshake does not verify",
            ));
        }
        let peer = p256::PublicKey::from_sec1_bytes(&reply.ephemeral_public)
            .map_err(|_| err("malformed responder ephemeral key"))?;
        let shared = self.secret.diffie_hellman(&peer);
        derive(
            shared.raw_secret_bytes().as_slice(),
            &digest,
            reply.expires_at,
        )
    }
}

/// The hardware-key holder's side: sign the handshake and derive the key.
pub fn respond(
    signer: &dyn HardwareSigner,
    offer: &HandshakeOffer,
    purpose: &str,
    expires_at: u64,
) -> Result<(SignedHandshake, SessionKey)> {
    let peer = p256::PublicKey::from_sec1_bytes(&offer.ephemeral_public)
        .map_err(|_| err("malformed initiator ephemeral key"))?;
    let secret = <p256::ecdh::EphemeralSecret as p256::elliptic_curve::Generate>::generate();
    let ephemeral_public = sec1(&secret.public_key());
    let hardware_public = signer.public_key_sec1()?;
    let digest = transcript_digest(
        purpose,
        offer,
        &ephemeral_public,
        &hardware_public,
        expires_at,
    );
    let signature = signer.sign_prehash(&digest)?;
    let shared = secret.diffie_hellman(&peer);
    let key = derive(shared.raw_secret_bytes().as_slice(), &digest, expires_at)?;
    Ok((
        SignedHandshake {
            hardware_public,
            ephemeral_public,
            expires_at,
            signature,
        },
        key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::tests::SoftwareTestSigner;

    fn signer(seed: u8) -> SoftwareTestSigner {
        SoftwareTestSigner(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap())
    }

    #[test]
    fn both_sides_derive_the_same_key() {
        let hw = signer(1);
        let (init, offer) = Initiator::new().unwrap();
        let (reply, kr) = respond(&hw, &offer, "rpc", 1_000).unwrap();
        let ki = init
            .complete(&reply, &hw.public_key_sec1().unwrap(), "rpc", 999)
            .unwrap();
        assert_eq!(ki.expose(), kr.expose());
        assert!(ki.is_valid_at(1_000) && !ki.is_valid_at(1_001));
    }

    #[test]
    fn another_purpose_key_or_expiry_is_refused() {
        let hw = signer(1);
        let pk = hw.public_key_sec1().unwrap();
        let (init, offer) = Initiator::new().unwrap();
        let (reply, _) = respond(&hw, &offer, "rpc", 1_000).unwrap();
        assert!(
            init.complete(&reply, &pk, "payments", 0).is_err(),
            "purpose is signed"
        );

        let (init, offer) = Initiator::new().unwrap();
        let (reply, _) = respond(&hw, &offer, "rpc", 1_000).unwrap();
        let other = signer(2).public_key_sec1().unwrap();
        assert!(
            init.complete(&reply, &other, "rpc", 0).is_err(),
            "a different hardware key"
        );

        let (init, offer) = Initiator::new().unwrap();
        let (mut reply, _) = respond(&hw, &offer, "rpc", 1_000).unwrap();
        reply.expires_at = 9_999;
        assert!(
            init.complete(&reply, &pk, "rpc", 0).is_err(),
            "the expiry is signed"
        );

        let (init, offer) = Initiator::new().unwrap();
        let (reply, _) = respond(&hw, &offer, "rpc", 1_000).unwrap();
        assert!(init.complete(&reply, &pk, "rpc", 1_001).is_err(), "expired");
    }

    #[test]
    fn a_reply_to_another_offer_is_refused() {
        let hw = signer(1);
        let pk = hw.public_key_sec1().unwrap();
        let (init_a, _) = Initiator::new().unwrap();
        let (_, offer_b) = Initiator::new().unwrap();
        let (reply_b, _) = respond(&hw, &offer_b, "rpc", 1_000).unwrap();
        assert!(init_a.complete(&reply_b, &pk, "rpc", 0).is_err());
    }
}
