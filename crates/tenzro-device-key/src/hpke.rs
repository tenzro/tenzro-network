//! HPKE (RFC 9180) base mode, decomposed so a non-extractable key can be a recipient.
//!
//! # Why not a HPKE crate
//!
//! Every Rust HPKE library models the recipient private key as a value —
//! `rust-hpke`'s `DhKeyExchange::PrivateKey` requires `Clone + Serializable +
//! Deserializable`. A Secure Enclave or TPM key cannot honestly satisfy that,
//! and faking it would mean holding the key in memory, which is the whole thing
//! we are avoiding.
//!
//! We do not need to. RFC 9180 §4.1:
//!
//! ```text
//! def Decap(enc, skR):
//!   dh = DH(skR, DeserializePublicKey(enc))     <-- the ONLY private-key op
//!   kem_context = concat(enc, SerializePublicKey(pk(skR)))
//!   return ExtractAndExpand(dh, kem_context)    <-- pure KDF over public inputs
//! ```
//!
//! So decapsulation is *one raw ECDH* plus a KDF we can run in software. Both
//! the Secure Enclave (`sharedSecretFromKeyAgreement`) and TPM 2.0
//! (`TPM2_ECDH_ZGen`) expose exactly that. Apple's own `swift-crypto` DHKEM
//! implementation requires nothing more of a private key than
//! `DiffieHellmanKeyAgreement`, which is the same observation.
//!
//! Per §7.1.1 the P-256 shared secret is `Ndh = 32` bytes — the **x-coordinate
//! only**. Passing a full point, or an x that a length-stripping TPM2B returned
//! as 31 bytes, silently derives a different key. Both are guarded at the call
//! sites in [`crate::envelope`].

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const HPKE_V1: &[u8] = b"HPKE-v1";

/// RFC 9180 §7.1 KEM identifiers.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum KemId {
    /// DHKEM(P-256, HKDF-SHA256). Forced for hardware: the Secure Enclave is
    /// P-256-only and TPM 2.0 ECDH is P-256/P-384.
    DhkemP256 = 0x0010,
    /// DHKEM(X25519, HKDF-SHA256). Used for passphrase/recovery-code recipients
    /// because its `DeriveKeyPair` is clamping, not rejection sampling — see
    /// [`crate::envelope`] for why that matters when the input is low-entropy.
    DhkemX25519 = 0x0020,
}

impl KemId {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0010 => Some(Self::DhkemP256),
            0x0020 => Some(Self::DhkemX25519),
            _ => None,
        }
    }
    pub fn as_u16(self) -> u16 {
        self as u16
    }
    /// Serialized public key length: SEC1 uncompressed for P-256 (65, *with*
    /// the 0x04 prefix), raw for X25519 (32).
    pub fn npk(self) -> usize {
        match self {
            Self::DhkemP256 => 65,
            Self::DhkemX25519 => 32,
        }
    }
    /// Encapsulated-key length. Same as `npk` for both DHKEMs.
    pub fn nenc(self) -> usize {
        self.npk()
    }
}

pub const KDF_HKDF_SHA256: u16 = 0x0001;
pub const AEAD_CHACHA20POLY1305: u16 = 0x0003;

/// AEAD key length for ChaCha20Poly1305.
pub const NK: usize = 32;
/// AEAD nonce length.
pub const NN: usize = 12;
/// DHKEM shared-secret length for both suites we use.
pub const NSECRET: usize = 32;

fn suite_id_kem(kem: KemId) -> [u8; 5] {
    let k = kem.as_u16().to_be_bytes();
    [b'K', b'E', b'M', k[0], k[1]]
}

fn suite_id_hpke(kem: KemId) -> [u8; 10] {
    let k = kem.as_u16().to_be_bytes();
    let d = KDF_HKDF_SHA256.to_be_bytes();
    let a = AEAD_CHACHA20POLY1305.to_be_bytes();
    [b'H', b'P', b'K', b'E', k[0], k[1], d[0], d[1], a[0], a[1]]
}

/// `LabeledExtract(salt, label, ikm)` — RFC 9180 §4.
fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut labeled = Vec::with_capacity(HPKE_V1.len() + suite_id.len() + label.len() + ikm.len());
    labeled.extend_from_slice(HPKE_V1);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    Zeroizing::new(out)
}

/// `LabeledExpand(prk, label, info, L)` — RFC 9180 §4.
fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
    let mut labeled =
        Vec::with_capacity(2 + HPKE_V1.len() + suite_id.len() + label.len() + info.len());
    labeled.extend_from_slice(&(len as u16).to_be_bytes()); // I2OSP(L, 2)
    labeled.extend_from_slice(HPKE_V1);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| HpkeError::Kdf)?;
    let mut out = vec![0u8; len];
    hk.expand(&labeled, &mut out).map_err(|_| HpkeError::Kdf)?;
    Ok(Zeroizing::new(out))
}

/// `ExtractAndExpand(dh, kem_context)` — RFC 9180 §4.1.
///
/// `dh` MUST be the x-coordinate only (32 bytes), left-padded. This is the step
/// that turns a raw ECDH result into the KEM shared secret, and it is the entire
/// reason a hardware key that only does ECDH can serve as an HPKE recipient.
pub fn extract_and_expand(
    kem: KemId,
    dh: &[u8],
    kem_context: &[u8],
) -> Result<Zeroizing<[u8; NSECRET]>, HpkeError> {
    if dh.len() != 32 {
        return Err(HpkeError::BadDhLength(dh.len()));
    }
    let sid = suite_id_kem(kem);
    let eae_prk = labeled_extract(&sid, b"", b"eae_prk", dh);
    let ss = labeled_expand(&sid, &eae_prk, b"shared_secret", kem_context, NSECRET)?;
    let mut out = [0u8; NSECRET];
    out.copy_from_slice(&ss);
    Ok(Zeroizing::new(out))
}

/// The base-mode key schedule (RFC 9180 §5.1, `mode_base = 0x00`, no PSK).
/// Returns `(key, base_nonce)`.
pub fn key_schedule_base(
    kem: KemId,
    shared_secret: &[u8; NSECRET],
    info: &[u8],
) -> Result<(Zeroizing<[u8; NK]>, Zeroizing<[u8; NN]>), HpkeError> {
    let sid = suite_id_hpke(kem);
    let psk_id_hash = labeled_extract(&sid, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&sid, b"", b"info_hash", info);

    let mut ks_context = Vec::with_capacity(1 + 32 + 32);
    ks_context.push(0x00); // mode_base
    ks_context.extend_from_slice(&*psk_id_hash);
    ks_context.extend_from_slice(&*info_hash);

    let secret = labeled_extract(&sid, shared_secret, b"secret", b"");
    let key = labeled_expand(&sid, &secret, b"key", &ks_context, NK)?;
    let nonce = labeled_expand(&sid, &secret, b"base_nonce", &ks_context, NN)?;

    let mut k = [0u8; NK];
    k.copy_from_slice(&key);
    let mut n = [0u8; NN];
    n.copy_from_slice(&nonce);
    Ok((Zeroizing::new(k), Zeroizing::new(n)))
}

#[derive(Debug, thiserror::Error)]
pub enum HpkeError {
    #[error("hpke: KDF failure")]
    Kdf,
    #[error("hpke: DH output must be 32 bytes (the x-coordinate), got {0}")]
    BadDhLength(usize),
    #[error("hpke: malformed public key")]
    BadPublicKey,
    #[error("hpke: AEAD open failed")]
    AeadOpen,
    #[error("hpke: contributory behaviour check failed (all-zero shared secret)")]
    ZeroSharedSecret,
}

/// Seals `secret` to the P-256 key `pk_r` (`0x04 || x || y`): DHKEM(P-256)
/// with a fresh ephemeral key, the base-mode key schedule under `info`, and
/// ChaCha20-Poly1305 with the encapsulated key as associated data. Returns
/// `enc || ciphertext`. Only the holder of `pk_r`'s private half opens it,
/// through [`open_from_p256`]; a key that only does ECDH can.
pub(crate) fn seal_to_p256(
    pk_r: &[u8],
    secret: &[u8],
    info: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    use chacha20poly1305::ChaCha20Poly1305;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    if secret.is_empty() {
        return Err("empty secret".into());
    }
    let eph = <p256::ecdh::EphemeralSecret as p256::elliptic_curve::Generate>::generate();
    let enc = eph.public_key().to_sec1_bytes().to_vec();
    let pk_point = p256::PublicKey::from_sec1_bytes(pk_r)
        .map_err(|_| "malformed recipient key".to_string())?;
    let dh = eph.diffie_hellman(&pk_point);
    let mut kem_context = Vec::with_capacity(enc.len() + pk_r.len());
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(pk_r);
    let shared = extract_and_expand(
        KemId::DhkemP256,
        dh.raw_secret_bytes().as_slice(),
        &kem_context,
    )
    .map_err(|e| e.to_string())?;
    let (key, nonce) =
        key_schedule_base(KemId::DhkemP256, &shared, info).map_err(|e| e.to_string())?;
    let ct = ChaCha20Poly1305::new((&*key).into())
        .encrypt(
            (&*nonce).into(),
            Payload {
                msg: secret,
                aad: &enc,
            },
        )
        .map_err(|_| "AEAD seal failed".to_string())?;
    let mut out = enc;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens what [`seal_to_p256`] sealed to `pk_r` under `info`. `ecdh` is the
/// recipient's raw ECDH with the sender's ephemeral key (`0x04 || x || y`):
/// the x-coordinate of the shared point, computed where the private key is.
pub(crate) fn open_from_p256<E>(
    ciphertext: &[u8],
    pk_r: &[u8],
    info: &[u8],
    ecdh: impl FnOnce(&[u8; 65]) -> std::result::Result<Zeroizing<[u8; 32]>, E>,
) -> std::result::Result<Zeroizing<Vec<u8>>, OpenError<E>> {
    use chacha20poly1305::ChaCha20Poly1305;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    if ciphertext.len() <= 65 || ciphertext[0] != 0x04 {
        return Err(OpenError::Malformed);
    }
    let (enc, ct) = ciphertext.split_at(65);
    let mut peer = [0u8; 65];
    peer.copy_from_slice(enc);
    let z = ecdh(&peer).map_err(OpenError::Ecdh)?;
    let mut kem_context = Vec::with_capacity(enc.len() + pk_r.len());
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(pk_r);
    let shared = extract_and_expand(KemId::DhkemP256, z.as_slice(), &kem_context)
        .map_err(|e| OpenError::Schedule(e.to_string()))?;
    let (key, nonce) = key_schedule_base(KemId::DhkemP256, &shared, info)
        .map_err(|e| OpenError::Schedule(e.to_string()))?;
    ChaCha20Poly1305::new((&*key).into())
        .decrypt((&*nonce).into(), Payload { msg: ct, aad: enc })
        .map(Zeroizing::new)
        .map_err(|_| OpenError::Tampered)
}

/// Why [`open_from_p256`] could not open a ciphertext.
#[derive(Debug)]
pub(crate) enum OpenError<E> {
    /// Not `enc || ciphertext` with an uncompressed point first.
    Malformed,
    /// The recipient's ECDH failed.
    Ecdh(E),
    /// The key schedule failed.
    Schedule(String),
    /// The AEAD did not open: tampered, or sealed to another key.
    Tampered,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_sealed_to_a_p256_key_opens_only_with_that_key_and_info() {
        let sk = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = sk.public_key().to_sec1_bytes().to_vec();
        let ecdh = |sk: &p256::SecretKey| {
            let sk = sk.clone();
            move |peer: &[u8; 65]| -> std::result::Result<Zeroizing<[u8; 32]>, ()> {
                let peer = p256::PublicKey::from_sec1_bytes(peer).map_err(drop)?;
                let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
                let mut z = [0u8; 32];
                z.copy_from_slice(shared.raw_secret_bytes().as_slice());
                Ok(Zeroizing::new(z))
            }
        };
        let ct = seal_to_p256(&pk, b"node secret", b"info/v1").unwrap();
        assert_eq!(
            &*open_from_p256(&ct, &pk, b"info/v1", ecdh(&sk)).unwrap(),
            b"node secret"
        );
        assert!(matches!(
            open_from_p256(&ct, &pk, b"info/v2", ecdh(&sk)),
            Err(OpenError::Tampered)
        ));
        let other = p256::SecretKey::from_slice(&[9u8; 32]).unwrap();
        assert!(matches!(
            open_from_p256(&ct, &pk, b"info/v1", ecdh(&other)),
            Err(OpenError::Tampered)
        ));
        let mut cut = ct.clone();
        cut[0] = 0x02;
        assert!(matches!(
            open_from_p256(&cut, &pk, b"info/v1", ecdh(&sk)),
            Err(OpenError::Malformed)
        ));
        assert!(seal_to_p256(&pk, b"", b"info/v1").is_err());
    }

    /// RFC 9180 Appendix A.5 — DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
    /// ChaCha20Poly1305. Validating the KDF chain against the published vector
    /// is what lets us trust a hand-rolled HPKE before any hardware is involved.
    #[test]
    fn rfc9180_a5_key_schedule() {
        // shared_secret and info from A.5.
        let shared_secret =
            hex_lit("806520f82ef0b03c823b7fc524b6b55a088f566b9751b89551c170f4113bd850");
        let info = hex_lit("4f6465206f6e2061204772656369616e2055726e");
        let mut ss = [0u8; 32];
        ss.copy_from_slice(&shared_secret);

        let (key, base_nonce) =
            key_schedule_base(KemId::DhkemP256, &ss, &info).expect("key schedule");

        assert_eq!(
            hex::encode(*key),
            "a8f45490a92a3b04d1dbf6cf2c3939ad8bfc9bfcb97c04bffe116730c9dfe3fc",
            "A.5 key mismatch"
        );
        assert_eq!(
            hex::encode(*base_nonce),
            "726b4390ed2209809f58c693",
            "A.5 base_nonce mismatch"
        );
    }

    /// RFC 9180 Appendix A.2 — DHKEM(X25519), HKDF-SHA256, ChaCha20Poly1305.
    #[test]
    fn rfc9180_a2_key_schedule() {
        let shared_secret =
            hex_lit("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7");
        let info = hex_lit("4f6465206f6e2061204772656369616e2055726e");
        let mut ss = [0u8; 32];
        ss.copy_from_slice(&shared_secret);

        let (key, base_nonce) =
            key_schedule_base(KemId::DhkemX25519, &ss, &info).expect("key schedule");

        assert_eq!(
            hex::encode(*key),
            "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
            "A.2 key mismatch"
        );
        assert_eq!(
            hex::encode(*base_nonce),
            "5c4d98150661b848853b547f",
            "A.2 base_nonce mismatch"
        );
    }

    fn hex_lit(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex in test vector")
    }
}
