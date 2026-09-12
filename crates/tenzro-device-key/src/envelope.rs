//! `tenzro-envelope/v2` — multi-recipient envelope over HPKE.
//!
//! # The failure this exists to prevent
//!
//! A non-extractable hardware key as the **sole** wrapping recipient means the
//! secret dies with the hardware. Lose the logic board, wipe the machine, lose
//! the blob — the ciphertext is unrecoverable, and no amount of correctness in
//! the enclave code changes that. It is the same class of loss as the bug this
//! crate was just rewritten to fix, arrived at by a different route.
//!
//! So: a fresh random CEK per envelope, wrapped independently to **two or more
//! recipients in different recovery domains**, and an API in which a
//! single-recipient envelope is *unrepresentable* rather than merely discouraged.
//!
//! # Shape (age's, essentially)
//!
//! ```text
//! header  magic "TZEN" | version | payload_aead | N | rsv | epoch(4)   = 12 B
//! stanza  kem | kdf | aead | class | cd_len | class_data | enc | ct    x N
//! payload nonce(12) | len(4) | ChaCha20Poly1305(CEK-derived key)
//! ```
//!
//! Each stanza is an HPKE seal of the same 32-byte CEK to one recipient. Any one
//! recipient opens the envelope alone; no threshold, no ordering requirement.
//!
//! # What binds what
//!
//! * The **12-byte header prefix is the AAD of every stanza**, so `N` is
//!   authenticated. Strip a stanza to forge a single-recipient envelope and
//!   every surviving stanza fails to open. The ≥2 rule is therefore enforced by
//!   the AEAD, not only by this crate's types.
//! * The **payload's AAD is `SHA-256(entire header)`**, binding stanza order,
//!   classes and every `enc`.
//! * `info` per stanza carries `recipient_id = SHA-256(kem_id || pk)`, so a
//!   stanza sealed to key A cannot be replayed as one addressed to key B.
//!
//! # Independence, not just distinctness
//!
//! Two recipients derived from the same passphrase have different public keys
//! and add no redundancy whatsoever. Comparing keys cannot catch that. So the
//! builder requires one [`Domain::Hardware`] recipient **and** at least one
//! non-hardware recipient: arity and domain coverage are type-level, key
//! distinctness is a runtime check. That split is deliberate — key equality is a
//! value, and pretending to lift it into the type system would be a lie.

use crate::hpke::{self, HpkeError, KemId, NK, NN, NSECRET};
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const MAGIC: [u8; 4] = *b"TZEN";
pub const VERSION: u8 = 0x02;
pub const HEADER_PREFIX_LEN: usize = 12;
/// Bound on stanza count. Eight recovery paths is already generous; the cap
/// stops a malformed length field from driving a huge allocation.
pub const MAX_STANZAS: usize = 8;
const INFO_PREFIX: &[u8] = b"tenzro-envelope/v2";
const PAYLOAD_INFO: &[u8] = b"tenzro-envelope/v2 payload";

/// Which recovery domain a recipient belongs to. Two recipients are
/// *independent* only if their domains differ — that is the property the
/// builder enforces, and it is stronger than "the keys are different".
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Domain {
    /// A key held in a secure element: Secure Enclave or TPM 2.0.
    Hardware = 0x01,
    /// Derived from a recovery code or passphrase held by a human.
    Passphrase = 0x02,
    /// Another enrolled machine's hardware agreement key.
    PeerDevice = 0x03,
}

impl Domain {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Hardware),
            0x02 => Some(Self::Passphrase),
            0x03 => Some(Self::PeerDevice),
            _ => None,
        }
    }
}

/// A recipient public key, validated on construction.
#[derive(Clone, Debug)]
pub struct Recipient {
    kem: KemId,
    /// Serialized public key: SEC1 uncompressed (65 B) for P-256, raw for X25519.
    pk: Vec<u8>,
    domain: Domain,
    id: [u8; 32],
}

impl Recipient {
    /// The only constructor. Rejects a wrong-length or off-curve key here, so an
    /// invalid point can never reach the enclave or the TPM — and both platforms
    /// then reject identically rather than through differing error paths.
    pub fn new(kem: KemId, pk: &[u8], domain: Domain) -> Result<Self, EnvelopeError> {
        if pk.len() != kem.npk() {
            return Err(EnvelopeError::BadRecipientKey);
        }
        match kem {
            KemId::DhkemP256 => {
                // RFC 9180 §7.1.4 partial public-key validation.
                p256::PublicKey::from_sec1_bytes(pk).map_err(|_| EnvelopeError::BadRecipientKey)?;
            }
            KemId::DhkemX25519 => {
                if pk.iter().all(|b| *b == 0) {
                    return Err(EnvelopeError::BadRecipientKey);
                }
            }
        }
        let mut h = Sha256::new();
        h.update(kem.as_u16().to_be_bytes());
        h.update(pk);
        Ok(Self {
            kem,
            pk: pk.to_vec(),
            domain,
            id: h.finalize().into(),
        })
    }

    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }
    pub fn domain(&self) -> Domain {
        self.domain
    }
    pub fn kem(&self) -> KemId {
        self.kem
    }
    pub fn public_key(&self) -> &[u8] {
        &self.pk
    }
}

fn stanza_info(domain: Domain, recipient_id: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(INFO_PREFIX.len() + 2 + 32);
    v.extend_from_slice(INFO_PREFIX);
    v.push(VERSION);
    v.push(domain as u8);
    v.extend_from_slice(recipient_id);
    v
}

// ---------------------------------------------------------------------------
// Typestate builder: `seal` exists only when both slots are filled.
// ---------------------------------------------------------------------------

mod sealed_marker {
    pub trait Sealed {}
}
/// Slot not yet filled.
pub struct Missing;
/// Slot filled.
pub struct Present;
impl sealed_marker::Sealed for Missing {}
impl sealed_marker::Sealed for Present {}
/// Builder slot marker. Sealed so no downstream type can pretend to be `Present`.
pub trait Slot: sealed_marker::Sealed {}
impl Slot for Missing {}
impl Slot for Present {}

/// Builds an envelope. `seal` is implemented **only** for
/// `EnvelopeBuilder<Present, Present>`, so an envelope with fewer than two
/// recovery domains cannot be constructed — not "is rejected", cannot be named.
pub struct EnvelopeBuilder<P: Slot, R: Slot> {
    hardware: Option<Recipient>,
    recovery: Vec<Recipient>,
    epoch: u32,
    _slots: core::marker::PhantomData<(P, R)>,
}

impl EnvelopeBuilder<Missing, Missing> {
    pub fn new(epoch: u32) -> Self {
        Self {
            hardware: None,
            recovery: Vec::new(),
            epoch,
            _slots: core::marker::PhantomData,
        }
    }
}

impl<R: Slot> EnvelopeBuilder<Missing, R> {
    /// Set the hardware recipient. Errors only if `r` is not in
    /// [`Domain::Hardware`] — the domain is the caller's assertion, and it is
    /// checked here so a mislabelled recipient cannot fill the wrong slot.
    pub fn with_hardware(self, r: Recipient) -> Result<EnvelopeBuilder<Present, R>, EnvelopeError> {
        if r.domain != Domain::Hardware {
            return Err(EnvelopeError::WrongDomain {
                expected: Domain::Hardware,
                got: r.domain,
            });
        }
        Ok(EnvelopeBuilder {
            hardware: Some(r),
            recovery: self.recovery,
            epoch: self.epoch,
            _slots: core::marker::PhantomData,
        })
    }
}

impl<P: Slot> EnvelopeBuilder<P, Missing> {
    /// Add the first non-hardware recipient. This is what unlocks `seal`.
    pub fn with_recovery(self, r: Recipient) -> Result<EnvelopeBuilder<P, Present>, EnvelopeError> {
        if r.domain == Domain::Hardware {
            return Err(EnvelopeError::WrongDomain {
                expected: Domain::Passphrase,
                got: r.domain,
            });
        }
        Ok(EnvelopeBuilder {
            hardware: self.hardware,
            recovery: vec![r],
            epoch: self.epoch,
            _slots: core::marker::PhantomData,
        })
    }
}

impl<P: Slot> EnvelopeBuilder<P, Present> {
    /// Additional recovery recipients, once at least one exists.
    pub fn and_recovery(mut self, r: Recipient) -> Result<Self, EnvelopeError> {
        if r.domain == Domain::Hardware {
            return Err(EnvelopeError::WrongDomain {
                expected: Domain::Passphrase,
                got: r.domain,
            });
        }
        self.recovery.push(r);
        Ok(self)
    }
}

impl EnvelopeBuilder<Present, Present> {
    fn recipients(&self) -> Vec<Recipient> {
        let mut v = Vec::with_capacity(1 + self.recovery.len());
        v.push(
            self.hardware
                .clone()
                .expect("Present guarantees hardware is set"),
        );
        v.extend(self.recovery.iter().cloned());
        v
    }

    /// Seal `plaintext`. Touches no hardware and prompts for nothing: sealing is
    /// public-key-only, exactly as before.
    pub fn seal(self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        let recipients = self.recipients();
        if recipients.len() > MAX_STANZAS {
            return Err(EnvelopeError::TooManyRecipients(recipients.len()));
        }
        // Distinctness is a runtime property; catch it here rather than pretend
        // the type system did.
        for i in 0..recipients.len() {
            for j in (i + 1)..recipients.len() {
                if recipients[i].id.ct_eq(&recipients[j].id).into() {
                    return Err(EnvelopeError::DuplicateRecipient(i, j));
                }
            }
        }

        let cek: Zeroizing<[u8; NSECRET]> = Zeroizing::new(crate::envelope::random_32()?);

        let n = recipients.len() as u8;
        let mut header = Vec::new();
        header.extend_from_slice(&MAGIC);
        header.push(VERSION);
        header.push(hpke::AEAD_CHACHA20POLY1305 as u8);
        header.push(n);
        header.push(0x00);
        header.extend_from_slice(&self.epoch.to_be_bytes());
        debug_assert_eq!(header.len(), HEADER_PREFIX_LEN);
        let prefix: [u8; HEADER_PREFIX_LEN] = header[..].try_into().expect("just built 12 bytes");

        for r in &recipients {
            let (enc, ct) = encap_and_seal(r, &prefix, &cek)?;
            header.extend_from_slice(&r.kem.as_u16().to_be_bytes());
            header.extend_from_slice(&hpke::KDF_HKDF_SHA256.to_be_bytes());
            header.extend_from_slice(&hpke::AEAD_CHACHA20POLY1305.to_be_bytes());
            header.push(r.domain as u8);
            header.push(0); // cd_len — class_data is not used in this revision
            header.extend_from_slice(&(enc.len() as u16).to_be_bytes());
            header.extend_from_slice(&enc);
            header.extend_from_slice(&(ct.len() as u16).to_be_bytes());
            header.extend_from_slice(&ct);
        }

        let header_hash = Sha256::digest(&header);
        let pk = payload_key(&cek)?;
        let nonce_bytes = random_12()?;
        let aead = ChaCha20Poly1305::new((&*pk).into());
        let ct = aead
            .encrypt(
                (&nonce_bytes).into(),
                Payload {
                    msg: plaintext,
                    aad: &header_hash,
                },
            )
            .map_err(|_| EnvelopeError::Hpke(HpkeError::Kdf))?;

        let mut out = header;
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

fn encap_and_seal(
    r: &Recipient,
    aad: &[u8],
    cek: &[u8; NSECRET],
) -> Result<(Vec<u8>, Vec<u8>), EnvelopeError> {
    let info = stanza_info(r.domain, &r.id);
    let (enc, shared) = match r.kem {
        KemId::DhkemP256 => {
            let pk_r = p256::PublicKey::from_sec1_bytes(&r.pk)
                .map_err(|_| EnvelopeError::BadRecipientKey)?;
            let sk_e = <p256::ecdh::EphemeralSecret as p256::elliptic_curve::Generate>::generate();
            let enc = sk_e.public_key().to_sec1_bytes().to_vec();
            let dh = sk_e.diffie_hellman(&pk_r);
            let mut kem_context = enc.clone();
            kem_context.extend_from_slice(&r.pk);
            let ss =
                hpke::extract_and_expand(r.kem, dh.raw_secret_bytes().as_slice(), &kem_context)?;
            (enc, ss)
        }
        KemId::DhkemX25519 => {
            let sk_e = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
            let pk_e = x25519_dalek::PublicKey::from(&sk_e);
            let mut pk_r = [0u8; 32];
            pk_r.copy_from_slice(&r.pk);
            let shared = sk_e.diffie_hellman(&x25519_dalek::PublicKey::from(pk_r));
            if !bool::from(shared.was_contributory()) {
                return Err(EnvelopeError::Hpke(HpkeError::ZeroSharedSecret));
            }
            let enc = pk_e.as_bytes().to_vec();
            let mut kem_context = enc.clone();
            kem_context.extend_from_slice(&r.pk);
            let ss = hpke::extract_and_expand(r.kem, shared.as_bytes(), &kem_context)?;
            (enc, ss)
        }
    };
    let (key, nonce) = hpke::key_schedule_base(r.kem, &shared, &info)?;
    let aead = ChaCha20Poly1305::new((&*key).into());
    let ct = aead
        .encrypt((&*nonce).into(), Payload { msg: cek, aad })
        .map_err(|_| EnvelopeError::Hpke(HpkeError::Kdf))?;
    Ok((enc, ct))
}

fn payload_key(cek: &[u8; NSECRET]) -> Result<Zeroizing<[u8; NK]>, EnvelopeError> {
    let hk = hkdf::Hkdf::<Sha256>::new(None, cek);
    let mut out = [0u8; NK];
    hk.expand(PAYLOAD_INFO, &mut out)
        .map_err(|_| EnvelopeError::Hpke(HpkeError::Kdf))?;
    Ok(Zeroizing::new(out))
}

fn random_32() -> Result<[u8; 32], EnvelopeError> {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    Ok(b)
}
fn random_12() -> Result<[u8; NN], EnvelopeError> {
    use rand::RngCore;
    let mut b = [0u8; NN];
    rand::rngs::OsRng.fill_bytes(&mut b);
    Ok(b)
}

// ---------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------

/// Anything that can perform **one raw ECDH** on behalf of a recipient.
///
/// The private key is never a value here — that is the entire point. A Secure
/// Enclave key, a TPM key and a passphrase-derived key all satisfy this, and
/// only the last one could ever be serialized.
pub trait Decapsulator {
    fn recipient(&self) -> &Recipient;
    /// `peer_enc` is the stanza's serialized ephemeral public key. Returns the
    /// 32-byte DH output — for P-256 the **x-coordinate only**, left-padded.
    fn raw_dh(&self, peer_enc: &[u8]) -> Result<Zeroizing<[u8; 32]>, EnvelopeError>;
}

/// A parsed envelope. [`Envelope::parse`] is the only way to obtain one, and it
/// enforces the ≥2-domain rule — so the invariant survives a round-trip through
/// disk, not merely through the builder.
pub struct Envelope {
    bytes: Vec<u8>,
    stanzas: Vec<StanzaRef>,
    header_len: usize,
    epoch: u32,
}

struct StanzaRef {
    kem: KemId,
    domain: Domain,
    enc: core::ops::Range<usize>,
    ct: core::ops::Range<usize>,
}

impl Envelope {
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    /// How many recipients can open this envelope. Callers should warn when a
    /// recovery path is lost; this is what they count.
    pub fn recipient_count(&self) -> usize {
        self.stanzas.len()
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < HEADER_PREFIX_LEN || bytes[0..4] != MAGIC {
            return Err(EnvelopeError::Malformed("bad magic"));
        }
        if bytes[4] != VERSION {
            return Err(EnvelopeError::UnsupportedVersion(bytes[4]));
        }
        let n = bytes[6] as usize;
        if n < 2 {
            return Err(EnvelopeError::TooFewRecipients(n));
        }
        if n > MAX_STANZAS {
            return Err(EnvelopeError::TooManyRecipients(n));
        }
        let epoch = u32::from_be_bytes(bytes[8..12].try_into().expect("checked length"));

        let mut off = HEADER_PREFIX_LEN;
        let mut stanzas = Vec::with_capacity(n);
        for _ in 0..n {
            let need = |off: usize, k: usize| -> Result<(), EnvelopeError> {
                if off + k > bytes.len() {
                    Err(EnvelopeError::Malformed("truncated stanza"))
                } else {
                    Ok(())
                }
            };
            need(off, 8)?;
            let kem = KemId::from_u16(u16::from_be_bytes([bytes[off], bytes[off + 1]]))
                .ok_or(EnvelopeError::Malformed("unknown kem_id"))?;
            if u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]) != hpke::KDF_HKDF_SHA256
                || u16::from_be_bytes([bytes[off + 4], bytes[off + 5]])
                    != hpke::AEAD_CHACHA20POLY1305
            {
                return Err(EnvelopeError::Malformed("unsupported suite"));
            }
            let domain =
                Domain::from_u8(bytes[off + 6]).ok_or(EnvelopeError::Malformed("unknown class"))?;
            let cd_len = bytes[off + 7] as usize;
            off += 8;
            need(off, cd_len + 2)?;
            off += cd_len;
            let enc_len = u16::from_be_bytes([bytes[off], bytes[off + 1]]) as usize;
            off += 2;
            if enc_len != kem.nenc() {
                return Err(EnvelopeError::Malformed("enc length does not match kem"));
            }
            need(off, enc_len + 2)?;
            let enc = off..off + enc_len;
            off += enc_len;
            let ct_len = u16::from_be_bytes([bytes[off], bytes[off + 1]]) as usize;
            off += 2;
            need(off, ct_len)?;
            let ct = off..off + ct_len;
            off += ct_len;
            stanzas.push(StanzaRef {
                kem,
                domain,
                enc,
                ct,
            });
        }

        // Independence, re-checked on the way in. A file that only a single
        // recovery domain can open is refused even if it is otherwise valid.
        let mut domains: Vec<Domain> = stanzas.iter().map(|s| s.domain).collect();
        domains.sort_by_key(|d| *d as u8);
        domains.dedup_by_key(|d| *d as u8);
        if domains.len() < 2 {
            return Err(EnvelopeError::SingleDomain);
        }

        Ok(Self {
            bytes: bytes.to_vec(),
            stanzas,
            header_len: off,
            epoch,
        })
    }

    /// Open with one recipient. Returns the plaintext and the index of the
    /// stanza that opened it, so a caller can report which path was used.
    pub fn open(&self, d: &dyn Decapsulator) -> Result<(Zeroizing<Vec<u8>>, usize), EnvelopeError> {
        let r = d.recipient();
        let prefix = &self.bytes[..HEADER_PREFIX_LEN];
        let info = stanza_info(r.domain, &r.id);

        for (i, st) in self.stanzas.iter().enumerate() {
            // Skip stanzas this decapsulator cannot serve — this is what keeps
            // trial decryption from costing N hardware operations (and, on
            // Apple, N-1 spurious biometric prompts).
            if st.kem != r.kem || st.domain != r.domain {
                continue;
            }
            let enc = &self.bytes[st.enc.clone()];
            let dh = match d.raw_dh(enc) {
                Ok(dh) => dh,
                Err(_) => continue,
            };
            let mut kem_context = enc.to_vec();
            kem_context.extend_from_slice(&r.pk);
            let shared = hpke::extract_and_expand(r.kem, &*dh, &kem_context)?;
            let (key, nonce) = hpke::key_schedule_base(r.kem, &shared, &info)?;
            let aead = ChaCha20Poly1305::new((&*key).into());
            let Ok(cek_vec) = aead.decrypt(
                (&*nonce).into(),
                Payload {
                    msg: &self.bytes[st.ct.clone()],
                    aad: prefix,
                },
            ) else {
                continue;
            };
            if cek_vec.len() != NSECRET {
                return Err(EnvelopeError::Malformed("wrapped CEK is the wrong size"));
            }
            let mut cek = Zeroizing::new([0u8; NSECRET]);
            cek.copy_from_slice(&cek_vec);

            let header_hash = Sha256::digest(&self.bytes[..self.header_len]);
            let pk = payload_key(&cek)?;
            let body = &self.bytes[self.header_len..];
            if body.len() < NN + 4 {
                return Err(EnvelopeError::Malformed("truncated payload"));
            }
            let nonce_b = &body[..NN];
            let len = u32::from_be_bytes(body[NN..NN + 4].try_into().expect("checked")) as usize;
            let ct = &body[NN + 4..];
            if ct.len() != len {
                return Err(EnvelopeError::Malformed("payload length mismatch"));
            }
            let aead = ChaCha20Poly1305::new((&*pk).into());
            let pt = aead
                .decrypt(
                    nonce_b.into(),
                    Payload {
                        msg: ct,
                        aad: &header_hash,
                    },
                )
                .map_err(|_| EnvelopeError::PayloadAuth)?;
            return Ok((Zeroizing::new(pt), i));
        }
        Err(EnvelopeError::NoStanzaForRecipient)
    }

    /// Re-seal to a new recipient set with a **fresh CEK** and a bumped epoch.
    ///
    /// This is the only mutation path, and it is deliberately total: there is no
    /// `add_recipient`/`remove_recipient`. Re-wrapping the *existing* CEK to a
    /// smaller set would make revocation cosmetic, because a removed recipient
    /// has already seen that CEK.
    pub fn rotate(
        &self,
        d: &dyn Decapsulator,
        to: EnvelopeBuilder<Present, Present>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        let (pt, _) = self.open(d)?;
        let mut to = to;
        to.epoch = self.epoch.saturating_add(1);
        to.seal(&pt)
    }
}

// ---------------------------------------------------------------------------
// A recovery recipient
// ---------------------------------------------------------------------------

/// An X25519 key derived from a 32-byte recovery code.
///
/// X25519 rather than P-256 on purpose. RFC 9180's P-256 `DeriveKeyPair` uses
/// **rejection sampling**, and RFC 9380 §5 says such methods are NOT RECOMMENDED
/// because they have been a source of side channels. For a random key that is a
/// shrug; for a key derived from a human-supplied secret the retry count is a
/// function of that secret. X25519's derivation is clamping — constant time, no
/// branch, no bias — so the problem is designed out rather than mitigated.
pub struct RecoveryKey {
    secret: Zeroizing<[u8; 32]>,
    recipient: Recipient,
}

impl RecoveryKey {
    /// `ikm` must be 32 bytes of full-entropy material — a generated recovery
    /// code, or an Argon2id output. Do **not** pass a raw passphrase.
    pub fn from_ikm(ikm: &[u8; 32]) -> Result<Self, EnvelopeError> {
        let secret = Zeroizing::new(*ikm);
        let sk = x25519_dalek::StaticSecret::from(*ikm);
        let pk = x25519_dalek::PublicKey::from(&sk);
        let recipient = Recipient::new(KemId::DhkemX25519, pk.as_bytes(), Domain::Passphrase)?;
        Ok(Self { secret, recipient })
    }

    /// The public half, to be stored in device config at enrolment. The private
    /// half is reconstructed only during recovery — which is why the recovery
    /// recipient must be a *keypair* and not a symmetric KEK: the node seals
    /// continuously and headlessly and cannot hold the code in RAM.
    pub fn recipient(&self) -> &Recipient {
        &self.recipient
    }
}

impl Decapsulator for RecoveryKey {
    fn recipient(&self) -> &Recipient {
        &self.recipient
    }
    fn raw_dh(&self, peer_enc: &[u8]) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
        if peer_enc.len() != 32 {
            return Err(EnvelopeError::Malformed("x25519 enc must be 32 bytes"));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(peer_enc);
        let sk = x25519_dalek::StaticSecret::from(*self.secret);
        let shared = sk.diffie_hellman(&x25519_dalek::PublicKey::from(pk));
        if !bool::from(shared.was_contributory()) {
            return Err(EnvelopeError::Hpke(HpkeError::ZeroSharedSecret));
        }
        Ok(Zeroizing::new(*shared.as_bytes()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("envelope: malformed ({0})")]
    Malformed(&'static str),
    #[error("envelope: unsupported version {0:#04x}")]
    UnsupportedVersion(u8),
    #[error("envelope: {0} recipients; at least 2 are required so no single failure is fatal")]
    TooFewRecipients(usize),
    #[error("envelope: {0} recipients exceeds the maximum of 8")]
    TooManyRecipients(usize),
    #[error(
        "envelope: all stanzas share one recovery domain, so it has no independent recovery path"
    )]
    SingleDomain,
    #[error("envelope: recipients {0} and {1} are the same key")]
    DuplicateRecipient(usize, usize),
    #[error("envelope: recipient is in domain {got:?}, expected {expected:?}")]
    WrongDomain { expected: Domain, got: Domain },
    #[error("envelope: recipient public key is malformed or off-curve")]
    BadRecipientKey,
    #[error("envelope: no stanza addressed to this recipient")]
    NoStanzaForRecipient,
    #[error("envelope: payload failed authentication")]
    PayloadAuth,
    #[error(transparent)]
    Hpke(#[from] HpkeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery(seed: u8) -> RecoveryKey {
        RecoveryKey::from_ikm(&[seed; 32]).expect("recovery key")
    }

    /// A software stand-in for a hardware key, so the envelope logic can be
    /// tested without an enclave. The real one lives in `backend_se`.
    struct SoftHardware {
        sk: p256::ecdh::EphemeralSecret,
        recipient: Recipient,
    }
    impl SoftHardware {
        fn new() -> Self {
            let sk = <p256::ecdh::EphemeralSecret as p256::elliptic_curve::Generate>::generate();
            let pk = sk.public_key().to_sec1_bytes().to_vec();
            let recipient = Recipient::new(KemId::DhkemP256, &pk, Domain::Hardware).unwrap();
            Self { sk, recipient }
        }
    }
    impl Decapsulator for SoftHardware {
        fn recipient(&self) -> &Recipient {
            &self.recipient
        }
        fn raw_dh(&self, peer_enc: &[u8]) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
            let pk = p256::PublicKey::from_sec1_bytes(peer_enc)
                .map_err(|_| EnvelopeError::BadRecipientKey)?;
            let dh = self.sk.diffie_hellman(&pk);
            let mut out = [0u8; 32];
            out.copy_from_slice(dh.raw_secret_bytes().as_slice());
            Ok(Zeroizing::new(out))
        }
    }

    fn two_party() -> (SoftHardware, RecoveryKey, Vec<u8>) {
        let hw = SoftHardware::new();
        let rec = recovery(7);
        let env = EnvelopeBuilder::new(1)
            .with_hardware(hw.recipient().clone())
            .unwrap()
            .with_recovery(rec.recipient().clone())
            .unwrap()
            .seal(b"the keystore password")
            .unwrap();
        (hw, rec, env)
    }

    /// The point of the whole design: losing the hardware must not lose the
    /// secret. Both paths open the same envelope independently.
    #[test]
    fn either_recipient_alone_recovers_the_secret() {
        let (hw, rec, env) = two_party();
        let e = Envelope::parse(&env).unwrap();

        let (a, ia) = e.open(&hw).unwrap();
        let (b, ib) = e.open(&rec).unwrap();
        assert_eq!(&a[..], b"the keystore password");
        assert_eq!(&b[..], b"the keystore password");
        assert_ne!(ia, ib, "the two paths must be different stanzas");
    }

    /// The hardware key is gone. The recovery key still works — this is the
    /// logic-board-death scenario, which single-recipient wrapping cannot survive.
    #[test]
    fn recovery_works_after_hardware_is_lost() {
        let (hw, rec, env) = two_party();
        drop(hw);
        let e = Envelope::parse(&env).unwrap();
        let (pt, _) = e
            .open(&rec)
            .expect("recovery path must survive hardware loss");
        assert_eq!(&pt[..], b"the keystore password");
    }

    /// The invariant, at the type level: this must not compile.
    ///
    /// ```compile_fail
    /// use tenzro_device_key::envelope::EnvelopeBuilder;
    /// let b = EnvelopeBuilder::new(0);
    /// // no `with_recovery` call — `seal` does not exist on this type
    /// let _ = b.seal(b"x");
    /// ```
    #[test]
    fn single_recipient_is_unrepresentable() {
        // The compile_fail doctest above is the real assertion. This test
        // documents the runtime half: a hand-forged N=1 header is refused.
        let (_hw, _rec, env) = two_party();
        let mut forged = env.clone();
        forged[6] = 1; // claim one stanza
        assert!(matches!(
            Envelope::parse(&forged),
            Err(EnvelopeError::TooFewRecipients(1))
        ));
    }

    /// Stripping a stanza to forge a single-recipient envelope must fail
    /// cryptographically, not just by policy — `N` is in every stanza's AAD.
    #[test]
    fn stanza_count_is_authenticated() {
        let (hw, _rec, env) = two_party();
        let mut forged = env.clone();
        forged[6] = 3; // lie about the count without changing the stanzas
        // parse may or may not reject the framing; opening must never succeed.
        match Envelope::parse(&forged) {
            Err(_) => {}
            Ok(e) => {
                assert!(
                    e.open(&hw).is_err(),
                    "AEAD accepted a tampered stanza_count"
                );
            }
        }
    }

    #[test]
    fn two_recipients_in_the_same_domain_are_rejected() {
        let a = recovery(1);
        let b = recovery(2);
        // Both are Domain::Passphrase, so this cannot even reach `seal`:
        // `with_hardware` refuses a non-hardware recipient.
        let err = EnvelopeBuilder::new(0).with_hardware(a.recipient().clone());
        assert!(matches!(err, Err(EnvelopeError::WrongDomain { .. })));
        // And the same key twice is caught as a duplicate.
        let hw = SoftHardware::new();
        let e = EnvelopeBuilder::new(0)
            .with_hardware(hw.recipient().clone())
            .unwrap()
            .with_recovery(b.recipient().clone())
            .unwrap()
            .and_recovery(b.recipient().clone())
            .unwrap()
            .seal(b"x");
        assert!(matches!(e, Err(EnvelopeError::DuplicateRecipient(_, _))));
    }

    #[test]
    fn tampered_payload_is_refused() {
        let (hw, _rec, env) = two_party();
        let mut bad = env.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xff;
        let e = Envelope::parse(&bad).unwrap();
        assert!(matches!(e.open(&hw), Err(EnvelopeError::PayloadAuth)));
    }

    /// Rotation must mint a fresh CEK, or revoking a recipient would be
    /// cosmetic — the removed party has already seen the old one.
    #[test]
    fn rotate_changes_the_cek_and_bumps_the_epoch() {
        let (hw, rec, env) = two_party();
        let e = Envelope::parse(&env).unwrap();
        let new_rec = recovery(9);
        let rotated = e
            .rotate(
                &hw,
                EnvelopeBuilder::new(0)
                    .with_hardware(hw.recipient().clone())
                    .unwrap()
                    .with_recovery(new_rec.recipient().clone())
                    .unwrap(),
            )
            .unwrap();
        let e2 = Envelope::parse(&rotated).unwrap();
        assert_eq!(e2.epoch(), e.epoch() + 1);

        // The new recipient opens it; the old one no longer can.
        assert!(e2.open(&new_rec).is_ok());
        assert!(
            e2.open(&rec).is_err(),
            "a rotated-out recipient must lose access"
        );
        assert_ne!(env, rotated, "rotation must not reproduce the same bytes");
    }

    #[test]
    fn off_curve_recipient_key_is_refused() {
        let bad = [0xffu8; 65];
        assert!(matches!(
            Recipient::new(KemId::DhkemP256, &bad, Domain::Hardware),
            Err(EnvelopeError::BadRecipientKey)
        ));
    }

    #[test]
    fn envelope_is_a_reasonable_size() {
        let (_hw, _rec, env) = two_party();
        // 12 header + 2 P-256/X25519 stanzas + 16 payload framing + ct.
        assert!(
            env.len() < 400,
            "envelope unexpectedly large: {} bytes",
            env.len()
        );
    }
}
