//! macOS / iOS Secure Enclave backend, over CryptoKit.
//!
//! # Why this does not use `security-framework`
//!
//! The previous implementation called `SecKeyCreateRandomKey` with
//! `kSecAttrTokenIDSecureEnclave` and asked for persistence via
//! `Location::DefaultFileKeychain`. That combination cannot work:
//!
//! * `security-framework`'s own docs state that keys in the Secure Enclave
//!   **must** use the data-protection keychain — which is entitlement-gated and
//!   returns `-34018 errSecMissingEntitlement` without a provisioning profile.
//! * `Location::DefaultFileKeychain` never reaches the generated dictionary at
//!   all; in `GenerateKeyOptions::to_dictionary` it falls into the catch-all arm,
//!   so its only effect is setting `kSecAttrIsPermanent`.
//!
//! Measured on an M2, macOS 15.1.1: a transient SE key succeeds and is genuine
//! (`kSecAttrTokenID == com.apple.setoken`, private export refused), while the
//! persistent form returns `-34018`. The old `create()` caught that error and
//! fell back to a **session-only** key, so the device public key changed on
//! every process start and any secret wrapped to it became unrecoverable at exit.
//!
//! CryptoKit's `SecureEnclave` API never touches the keychain — it returns a
//! SEP-wrapped blob that the caller stores — so the entitlement gate is simply
//! not in the path. That is what keeps an Apple node permissionless. CryptoKit
//! is Swift-only, hence the shim in `swift/TenzroSE.swift`.
//!
//! # Shape
//!
//! One `SecKey` used to serve both ECDSA and ECIES. CryptoKit's
//! `SecureEnclave.P256.Signing` and `.KeyAgreement` are distinct types with
//! distinct blobs, so a key directory holds **two** files, `sign.key` and
//! `agree.key`. [`DeviceKey::public_key`] returns the *signing* key's public
//! half — that is the device's identity — while wrap/unwrap use the agreement
//! key. [`agreement_public_key`] exposes the other half for callers that wrap a
//! secret from the public side alone.

use super::{Attestation, DeviceKey, DeviceKeyError, DevicePublicKey, DeviceSignature, Result};
use std::ffi::CString;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};

// Mirrors the TZDK_* codes in swift/TenzroSE.swift.
const TZDK_OK: i32 = 0;
const TZDK_ERR_UNAVAILABLE: i32 = -1;
const TZDK_ERR_NOT_FOUND: i32 = -2;
const TZDK_ERR_IO: i32 = -3;
const TZDK_ERR_CRYPTO: i32 = -4;
const TZDK_ERR_BADARG: i32 = -5;
const TZDK_ERR_BUFFER: i32 = -6;
const TZDK_ERR_CORRUPT: i32 = -7;

// Edition 2024 requires extern blocks to be declared unsafe.
unsafe extern "C" {
    fn tzdk_available() -> i32;
    fn tzdk_create(dir: *const c_char, require_user_presence: i32) -> i32;
    fn tzdk_selftest(dir: *const c_char) -> i32;
    fn tzdk_public_key(dir: *const c_char, out: *mut u8) -> i32;
    fn tzdk_agreement_public_key(dir: *const c_char, out: *mut u8) -> i32;
    fn tzdk_sign_prehash(dir: *const c_char, hash: *const u8, out: *mut u8) -> i32;
    fn tzdk_wrap_secret(
        dir: *const c_char,
        secret: *const u8,
        secret_len: usize,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> i32;
    fn tzdk_unwrap_secret(
        dir: *const c_char,
        ct: *const u8,
        ct_len: usize,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> i32;
    fn tzdk_identity(dir: *const c_char, out: *mut u8) -> i32;
    fn tzdk_ecdh(dir: *const c_char, peer_enc: *const u8, peer_enc_len: usize, out: *mut u8)
    -> i32;
    fn tzdk_agreement_public_key_sec1(dir: *const c_char, out: *mut u8) -> i32;
    fn tzdk_delete(dir: *const c_char) -> i32;
}

/// The device's two public halves plus the signature that ties them together.
///
/// Because the device is backed by two hardware keys, something has to say
/// which one speaks for it. `signing` is the identity; `agreement` is a
/// subordinate credential, and `binding` is `signing`'s signature over it. This
/// mirrors MLS (RFC 9420) `LeafNode` and Signal's X3DH signed prekey.
#[derive(Clone, Debug)]
pub struct DeviceIdentity {
    /// Raw `x ‖ y`. This is the device public key — the one to register.
    pub signing: DevicePublicKey,
    /// Raw `x ‖ y`. Wrap secrets to this, never to `signing`.
    pub agreement: DevicePublicKey,
    /// ECDSA `r ‖ s` by `signing` over `SHA256(BINDING_CONTEXT ‖ agreement)`.
    pub binding: DeviceSignature,
}

/// Domain separation for [`DeviceIdentity::binding`]. Must match the Swift side.
pub const BINDING_CONTEXT: &[u8] = b"tenzro/device-binding/v1";

impl DeviceIdentity {
    /// The bytes a verifier must hash and check `binding` against.
    ///
    /// A peer that skips this check can be steered onto an attacker's agreement
    /// key while believing it is talking to `signing` — so verification is not
    /// optional, and this helper exists so no caller has to reconstruct it.
    pub fn binding_message(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(BINDING_CONTEXT.len() + 64);
        m.extend_from_slice(BINDING_CONTEXT);
        m.extend_from_slice(&self.agreement);
        m
    }
}

/// Read this device's identity: both public keys and the binding signature.
pub fn identity(label: &str) -> Result<DeviceIdentity> {
    let d = c_dir(&dir_for(label))?;
    let mut buf = [0u8; 192];
    let rc = unsafe { tzdk_identity(d.as_ptr(), buf.as_mut_ptr()) };
    if rc != TZDK_OK {
        return Err(err(rc, "identity"));
    }
    let mut signing = [0u8; 64];
    let mut agreement = [0u8; 64];
    let mut binding = [0u8; 64];
    signing.copy_from_slice(&buf[0..64]);
    agreement.copy_from_slice(&buf[64..128]);
    binding.copy_from_slice(&buf[128..192]);
    Ok(DeviceIdentity {
        signing,
        agreement,
        binding,
    })
}

fn err(code: i32, op: &str) -> DeviceKeyError {
    match code {
        TZDK_ERR_NOT_FOUND => DeviceKeyError::NotFound(op.to_string()),
        TZDK_ERR_UNAVAILABLE => DeviceKeyError::Enclave("no Secure Enclave on this machine".into()),
        TZDK_ERR_CORRUPT => DeviceKeyError::Enclave(format!(
            "{op}: the stored enclave blob failed its sanity check; the key must be \
             re-enrolled (its secrets are not recoverable)"
        )),
        TZDK_ERR_IO => DeviceKeyError::Enclave(format!("{op}: reading or writing the key blob")),
        TZDK_ERR_CRYPTO => DeviceKeyError::Enclave(format!("{op}: the Secure Enclave refused")),
        TZDK_ERR_BADARG => DeviceKeyError::Enclave(format!("{op}: invalid argument")),
        TZDK_ERR_BUFFER => DeviceKeyError::Enclave(format!("{op}: output buffer too small")),
        other => DeviceKeyError::Enclave(format!("{op}: unexpected shim code {other}")),
    }
}

/// Where a label's key material lives.
///
/// The label is hashed rather than used as a path component: labels come from
/// callers, and a label of `../../x` must not be able to steer writes. Override
/// with `TENZRO_DEVICE_KEY_DIR` — a daemon with no home directory needs that.
fn dir_for(label: &str) -> PathBuf {
    let root = std::env::var_os("TENZRO_DEVICE_KEY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_root);
    root.join(hex::encode(super::credential_id_for_label(label)))
}

fn default_root() -> PathBuf {
    // ~/Library/Application Support/Tenzro/device-keys
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join("Library/Application Support/Tenzro/device-keys");
    }
    PathBuf::from("/var/db/tenzro/device-keys")
}

fn c_dir(dir: &Path) -> Result<CString> {
    CString::new(dir.as_os_str().as_encoded_bytes())
        .map_err(|_| DeviceKeyError::Enclave("key path contains an interior NUL".into()))
}

/// True if this machine has a Secure Enclave at all.
pub fn available() -> bool {
    unsafe { tzdk_available() == 1 }
}

struct SeKey {
    label: String,
    dir: PathBuf,
}

impl SeKey {
    fn cdir(&self) -> Result<CString> {
        c_dir(&self.dir)
    }
}

impl DeviceKey for SeKey {
    fn label(&self) -> &str {
        &self.label
    }

    fn public_key(&self) -> Result<DevicePublicKey> {
        let d = self.cdir()?;
        let mut out = [0u8; 64];
        let rc = unsafe { tzdk_public_key(d.as_ptr(), out.as_mut_ptr()) };
        if rc != TZDK_OK {
            return Err(err(rc, "public_key"));
        }
        Ok(out)
    }

    fn sign_prehash(&self, hash: &[u8; 32]) -> Result<DeviceSignature> {
        let d = self.cdir()?;
        let mut out = [0u8; 64];
        let rc = unsafe { tzdk_sign_prehash(d.as_ptr(), hash.as_ptr(), out.as_mut_ptr()) };
        if rc != TZDK_OK {
            return Err(err(rc, "sign_prehash"));
        }
        Ok(out)
    }

    fn wrap_secret(&self, secret: &[u8]) -> Result<Vec<u8>> {
        if secret.is_empty() {
            return Err(DeviceKeyError::Enclave("wrap_secret: empty secret".into()));
        }
        let d = self.cdir()?;
        // 64 ephemeral public + 12 nonce + 16 tag of overhead; the slack absorbs
        // any future framing without a second call.
        let mut out = vec![0u8; secret.len() + 128];
        let mut n = 0usize;
        let rc = unsafe {
            tzdk_wrap_secret(
                d.as_ptr(),
                secret.as_ptr(),
                secret.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut n,
            )
        };
        if rc != TZDK_OK {
            return Err(err(rc, "wrap_secret"));
        }
        out.truncate(n);
        Ok(out)
    }

    fn unwrap_secret(&self, ciphertext: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let d = self.cdir()?;
        // Plaintext is always shorter than the ciphertext, which carries the
        // ephemeral public key, nonce and tag.
        let mut out = zeroize::Zeroizing::new(vec![0u8; ciphertext.len()]);
        let mut n = 0usize;
        let rc = unsafe {
            tzdk_unwrap_secret(
                d.as_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut n,
            )
        };
        if rc != TZDK_OK {
            return Err(err(rc, "unwrap_secret"));
        }
        out.truncate(n);
        Ok(out)
    }

    fn attest(&self) -> Result<Attestation> {
        // The SEP has no PCRs and issues no quote, so there is nothing honest to
        // return here. Claiming otherwise would put a false assurance claim into
        // whatever ledger records it.
        Err(DeviceKeyError::AttestationUnsupported)
    }
}

/// Raw `x ‖ y` of the key-agreement public half — what a peer needs to wrap a
/// secret to this device without holding the device key.
pub fn agreement_public_key(label: &str) -> Result<DevicePublicKey> {
    let d = c_dir(&dir_for(label))?;
    let mut out = [0u8; 64];
    let rc = unsafe { tzdk_agreement_public_key(d.as_ptr(), out.as_mut_ptr()) };
    if rc != TZDK_OK {
        return Err(err(rc, "agreement_public_key"));
    }
    Ok(out)
}

pub fn open(label: &str) -> Result<Box<dyn DeviceKey>> {
    let dir = dir_for(label);
    let d = c_dir(&dir)?;
    // Prove the enclave answers before handing back a usable-looking key. The
    // failure this replaces was precisely a key that looked fine and was not.
    let rc = unsafe { tzdk_selftest(d.as_ptr()) };
    if rc != TZDK_OK {
        return Err(err(rc, "open"));
    }
    Ok(Box::new(SeKey {
        label: label.to_string(),
        dir,
    }))
}

/// Create a device key. `require_user_presence` gates every private-key use
/// behind Touch ID or the passcode — right for a wallet, wrong for a headless
/// daemon, where the prompt has nobody to answer it.
pub fn create_with_presence(
    label: &str,
    require_user_presence: bool,
) -> Result<Box<dyn DeviceKey>> {
    if !available() {
        return Err(err(TZDK_ERR_UNAVAILABLE, "create"));
    }
    let dir = dir_for(label);
    let d = c_dir(&dir)?;
    let rc = unsafe { tzdk_create(d.as_ptr(), i32::from(require_user_presence)) };
    if rc == TZDK_ERR_BADARG {
        return Err(DeviceKeyError::Enclave(format!(
            "create: a key already exists for {label:?}; delete it explicitly if you \
             intend to discard whatever is wrapped to it"
        )));
    }
    if rc != TZDK_OK {
        return Err(err(rc, "create"));
    }
    open(label)
}

/// Biometry-gated by default, because the common caller is a wallet key and a
/// key that signs without user presence should be an explicit choice rather
/// than something you get by not thinking about it. Daemons call
/// [`create_with_presence`] with `false`.
pub fn create(label: &str) -> Result<Box<dyn DeviceKey>> {
    create_with_presence(label, true)
}

pub fn delete(label: &str) -> Result<()> {
    let d = c_dir(&dir_for(label))?;
    let rc = unsafe { tzdk_delete(d.as_ptr()) };
    if rc != TZDK_OK {
        return Err(err(rc, "delete"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test gets its own key root, so they neither collide nor touch the
    /// real one under ~/Library. `TENZRO_DEVICE_KEY_DIR` is process-wide, so
    /// these must not run concurrently within one process — hence the mutex.
    fn with_root<T>(name: &str, f: impl FnOnce(&str) -> T) -> T {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let root = std::env::temp_dir().join(format!("tzdk-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // SAFETY: guarded by LOCK above, so no other thread in this process is
        // reading or writing the environment concurrently.
        unsafe { std::env::set_var("TENZRO_DEVICE_KEY_DIR", &root) };
        let label = format!("test-{name}");
        let out = f(&label);
        let _ = std::fs::remove_dir_all(&root);
        unsafe { std::env::remove_var("TENZRO_DEVICE_KEY_DIR") };
        out
    }

    #[test]
    fn enclave_is_present() {
        assert!(available(), "these tests require a Secure Enclave");
    }

    /// The regression this whole change exists for: the public key must survive
    /// a reopen. Under the old backend it changed on every process start.
    #[test]
    fn public_key_is_stable_across_reopen() {
        with_root("stable", |label| {
            let a = create_with_presence(label, false)
                .expect("create")
                .public_key()
                .unwrap();
            let b = open(label).expect("reopen").public_key().unwrap();
            assert_eq!(a, b, "public key changed across reopen");
        });
    }

    #[test]
    fn wrapped_secret_survives_reopen() {
        with_root("wrap", |label| {
            let secret = b"keystore-password";
            let ct = create_with_presence(label, false)
                .unwrap()
                .wrap_secret(secret)
                .unwrap();
            // Reopening is the part that used to be impossible.
            let got = open(label).unwrap().unwrap_secret(&ct).unwrap();
            assert_eq!(&got[..], secret);
        });
    }

    #[test]
    fn tampered_ciphertext_is_refused() {
        with_root("tamper", |label| {
            let k = create_with_presence(label, false).unwrap();
            let mut ct = k.wrap_secret(b"a-secret-worth-protecting").unwrap();
            let last = ct.len() - 1;
            ct[last] ^= 0xff; // corrupt the GCM tag
            assert!(
                k.unwrap_secret(&ct).is_err(),
                "AES-GCM accepted a tampered ciphertext"
            );
        });
    }

    /// Creating over an existing key would orphan every secret wrapped to it.
    #[test]
    fn create_refuses_to_clobber() {
        with_root("clobber", |label| {
            create_with_presence(label, false).unwrap();
            assert!(create_with_presence(label, false).is_err());
        });
    }

    #[test]
    fn open_missing_key_is_not_found() {
        with_root("missing", |label| {
            assert!(matches!(open(label), Err(DeviceKeyError::NotFound(_))));
        });
    }

    #[test]
    fn delete_is_idempotent_and_actually_deletes() {
        with_root("delete", |label| {
            create_with_presence(label, false).unwrap();
            delete(label).expect("first delete");
            delete(label).expect("second delete should be a no-op");
            assert!(open(label).is_err(), "key still readable after delete");
        });
    }

    /// The identity binding is what stops a peer being steered onto someone
    /// else's agreement key, so verify it end to end with a real P-256 check.
    #[test]
    fn identity_binding_verifies_and_is_bound_to_this_agreement_key() {
        with_root("identity", |label| {
            create_with_presence(label, false).unwrap();
            let id = identity(label).unwrap();

            assert_eq!(id.signing, open(label).unwrap().public_key().unwrap());
            assert_eq!(id.agreement, agreement_public_key(label).unwrap());
            assert_ne!(id.signing, id.agreement, "the two keys must be distinct");

            // Independently verify with the p256 crate rather than trusting the
            // shim to mark its own homework.
            use p256::ecdsa::signature::Verifier;
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&id.signing);
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).expect("sec1 pubkey");
            let sig = p256::ecdsa::Signature::from_slice(&id.binding).expect("r||s");
            vk.verify(&id.binding_message(), &sig)
                .expect("binding must verify");

            // And it must not verify over some other agreement key.
            let mut forged = id.clone();
            forged.agreement[0] ^= 0xff;
            assert!(vk.verify(&forged.binding_message(), &sig).is_err());
        });
    }

    #[test]
    fn signature_is_ecdsa_over_the_given_prehash() {
        with_root("sign", |label| {
            let k = create_with_presence(label, false).unwrap();
            let pubk = k.public_key().unwrap();
            let msg = b"tenzro attestation payload";
            let digest: [u8; 32] = {
                use sha2::{Digest, Sha256};
                Sha256::digest(msg).into()
            };
            let sig = k.sign_prehash(&digest).unwrap();

            use p256::ecdsa::signature::Verifier;
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&pubk);
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
            let s = p256::ecdsa::Signature::from_slice(&sig).unwrap();
            // Verifying the MESSAGE (not the digest) proves the enclave signed
            // SHA-256(msg) and did not re-hash it — i.e. this interoperates with
            // any standard ECDSA verifier.
            vk.verify(msg, &s)
                .expect("signature must verify as plain ECDSA-P256-SHA256");
        });
    }

    /// End to end on real hardware: seal to (enclave + recovery code), then open
    /// with the enclave. This is the path a node actually takes.
    #[test]
    fn enclave_opens_a_multi_recipient_envelope() {
        use crate::envelope::{Envelope, EnvelopeBuilder, RecoveryKey};
        with_root("env-hw", |label| {
            create_with_presence(label, false).unwrap();
            let hw = EnclaveDecapsulator::open(label).expect("enclave recipient");
            let rec = RecoveryKey::from_ikm(&[0x5a; 32]).unwrap();

            let sealed = EnvelopeBuilder::new(1)
                .with_hardware(hw.recipient().clone())
                .unwrap()
                .with_recovery(rec.recipient().clone())
                .unwrap()
                .seal(b"node signing seed")
                .unwrap();

            let e = Envelope::parse(&sealed).unwrap();
            let (pt, _) = e
                .open(&hw)
                .expect("the Secure Enclave must open its own stanza");
            assert_eq!(&pt[..], b"node signing seed");
        });
    }

    /// The whole reason this exists: destroy the enclave key and the secret is
    /// still recoverable. Under single-recipient wrapping this is unrecoverable.
    #[test]
    fn secret_survives_destruction_of_the_enclave_key() {
        use crate::envelope::{Envelope, EnvelopeBuilder, RecoveryKey};
        with_root("env-loss", |label| {
            create_with_presence(label, false).unwrap();
            let hw = EnclaveDecapsulator::open(label).unwrap();
            let rec = RecoveryKey::from_ikm(&[0x21; 32]).unwrap();
            let sealed = EnvelopeBuilder::new(1)
                .with_hardware(hw.recipient().clone())
                .unwrap()
                .with_recovery(rec.recipient().clone())
                .unwrap()
                .seal(b"ml-dsa-65 seed")
                .unwrap();

            // Simulate a dead logic board: the enclave blobs are gone for good.
            delete(label).unwrap();
            drop(hw);
            assert!(open(label).is_err(), "enclave key should be gone");

            let e = Envelope::parse(&sealed).unwrap();
            let (pt, _) = e.open(&rec).expect("recovery must survive enclave loss");
            assert_eq!(&pt[..], b"ml-dsa-65 seed");
        });
    }

    /// A software ECDH and the enclave's ECDH must agree, or the envelope would
    /// be sealable but not openable. Catches x-vs-full-point and padding bugs.
    #[test]
    fn enclave_ecdh_matches_software_ecdh() {
        use crate::envelope::Decapsulator;
        with_root("ecdh", |label| {
            create_with_presence(label, false).unwrap();
            let hw = EnclaveDecapsulator::open(label).unwrap();

            let eph = <p256::ecdh::EphemeralSecret as p256::elliptic_curve::Generate>::generate();
            let enc = eph.public_key().to_sec1_bytes().to_vec();
            assert_eq!(enc.len(), 65, "HPKE requires uncompressed SEC1");

            let from_enclave = hw.raw_dh(&enc).expect("enclave ecdh");
            let pk_hw = p256::PublicKey::from_sec1_bytes(hw.recipient().public_key()).unwrap();
            let from_software = eph.diffie_hellman(&pk_hw);

            assert_eq!(
                &from_enclave[..],
                from_software.raw_secret_bytes().as_slice(),
                "enclave and software ECDH disagree"
            );
            assert_eq!(from_enclave.len(), 32, "must be the x-coordinate only");
        });
    }

    /// A label must never be able to steer writes out of the key root.
    #[test]
    fn traversal_labels_cannot_escape_the_root() {
        with_root("traversal", |_| {
            let root = std::env::var_os("TENZRO_DEVICE_KEY_DIR")
                .map(PathBuf::from)
                .unwrap();
            for evil in ["../../etc/passwd", "..", "a/../../b", "/tmp/absolute"] {
                assert!(
                    dir_for(evil).starts_with(&root),
                    "{evil:?} escaped the key root"
                );
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Envelope integration
// ---------------------------------------------------------------------------

/// SEC1 uncompressed (65 B, with the `0x04` prefix) agreement public key.
///
/// HPKE's `SerializePublicKey` for P-256 is uncompressed SEC1, and both `enc`
/// and `pkRm` feed the KEM context — so the 64-byte form returned by
/// [`agreement_public_key`] is **not** interchangeable here. Using it silently
/// derives a different shared secret from every peer.
pub fn agreement_public_key_sec1(label: &str) -> Result<[u8; 65]> {
    let d = c_dir(&dir_for(label))?;
    let mut out = [0u8; 65];
    let rc = unsafe { tzdk_agreement_public_key_sec1(d.as_ptr(), out.as_mut_ptr()) };
    if rc != TZDK_OK {
        return Err(err(rc, "agreement_public_key_sec1"));
    }
    Ok(out)
}

/// This device's enclave key, as an envelope recipient.
///
/// The private half never leaves the Secure Enclave; the only operation exposed
/// is a single raw ECDH, which is all HPKE decapsulation actually requires.
pub struct EnclaveDecapsulator {
    dir: PathBuf,
    recipient: crate::envelope::Recipient,
}

impl EnclaveDecapsulator {
    pub fn open(label: &str) -> Result<Self> {
        let pk = agreement_public_key_sec1(label)?;
        let recipient = crate::envelope::Recipient::new(
            crate::hpke::KemId::DhkemP256,
            &pk,
            crate::envelope::Domain::Hardware,
        )
        .map_err(|e| DeviceKeyError::Enclave(format!("enclave recipient: {e}")))?;
        Ok(Self {
            dir: dir_for(label),
            recipient,
        })
    }

    pub fn recipient(&self) -> &crate::envelope::Recipient {
        &self.recipient
    }
}

impl crate::envelope::Decapsulator for EnclaveDecapsulator {
    fn recipient(&self) -> &crate::envelope::Recipient {
        &self.recipient
    }

    fn raw_dh(
        &self,
        peer_enc: &[u8],
    ) -> std::result::Result<zeroize::Zeroizing<[u8; 32]>, crate::envelope::EnvelopeError> {
        use crate::envelope::EnvelopeError;
        if peer_enc.len() != 65 {
            return Err(EnvelopeError::Malformed("p256 enc must be 65 bytes"));
        }
        let d = c_dir(&self.dir).map_err(|_| EnvelopeError::BadRecipientKey)?;
        let mut out = [0u8; 32];
        let rc = unsafe {
            tzdk_ecdh(
                d.as_ptr(),
                peer_enc.as_ptr(),
                peer_enc.len(),
                out.as_mut_ptr(),
            )
        };
        if rc != TZDK_OK {
            return Err(EnvelopeError::BadRecipientKey);
        }
        Ok(zeroize::Zeroizing::new(out))
    }
}
