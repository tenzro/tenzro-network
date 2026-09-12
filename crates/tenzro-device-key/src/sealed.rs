//! [`SealedSecret`] — a secret at rest, sealed to the enclave **and** to a
//! recovery key.
//!
//! # Why this exists
//!
//! Both consumers in this crate previously did the same thing: create a device
//! key, `wrap_secret` to it, and write the ciphertext to a path. That binds the
//! secret to one non-extractable key, so a dead logic board, a wiped machine or
//! a lost blob destroys it permanently. See [`crate::envelope`].
//!
//! Rather than fix that twice — differently, and drift — both now go through
//! this one type, which cannot produce a single-recipient ciphertext because
//! [`crate::envelope::EnvelopeBuilder`] has no such state.
//!
//! # Enrolment is explicit
//!
//! There is deliberately no "create with a recovery key I invented for you".
//! [`SealedSecret::enrol`] takes the recovery recipient from the caller, because
//! the operator has to *keep* the corresponding recovery code — a code generated
//! and silently discarded inside this crate would be worse than no recovery key
//! at all, since it would look like redundancy while providing none.
//!
//! # What is stored
//!
//! One file: the `tenzro-envelope/v2` bytes. The recovery *public* key is inside
//! it, in the clear, which is what lets a later `rotate` re-seal without the
//! operator present. The recovery private key is never written anywhere.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::backend_se::EnclaveDecapsulator;
#[cfg(windows)]
use crate::backend_tpm::TpmDecapsulator;
use crate::envelope::{Decapsulator, Envelope, EnvelopeBuilder, Recipient};
use crate::{DeviceKeyError, Result};

/// Message for every `SealedSecret` entry point that needs a hardware root
/// on a platform with neither the Secure Enclave nor a TPM backend wired up
/// — same wording the cross-platform `backend::open/create/delete` stub in
/// `lib.rs` already uses, so the two surfaces read as one gap rather than
/// two.
#[cfg(not(any(target_os = "macos", target_os = "ios", windows)))]
const NO_ENCLAVE_BACKEND: &str = "device-key backend not yet wired for this platform";

/// A secret sealed to the device enclave plus at least one recovery recipient.
pub struct SealedSecret {
    // Read by the macOS/iOS backend, which keys the enclave by label; the TPM
    // backend derives one deterministic key per machine and never touches it.
    #[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
    label: String,
    path: PathBuf,
}

impl SealedSecret {
    /// Bind to an enclave key tagged `label` with the envelope stored at `path`.
    /// Neither is touched until [`Self::enrol`] or [`Self::open`] is called.
    pub fn new(label: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            label: label.into(),
            path: path.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Seal `secret` for the first time.
    ///
    /// Creates the enclave key if absent. `recovery` must be a non-hardware
    /// recipient — typically [`crate::envelope::RecoveryKey::recipient`] derived
    /// from a recovery code the operator has written down. Refuses to overwrite
    /// an existing envelope: silently replacing one would orphan whatever the
    /// old recovery code protects.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn enrol(
        &self,
        secret: &[u8],
        recovery: &Recipient,
        require_user_presence: bool,
    ) -> Result<()> {
        if self.exists() {
            return Err(DeviceKeyError::Enclave(format!(
                "an envelope already exists at {}; rotate it or remove it deliberately",
                self.path.display()
            )));
        }
        if crate::backend::open(&self.label).is_err() {
            crate::backend::create_with_presence(&self.label, require_user_presence)?;
        }
        let hw = EnclaveDecapsulator::open(&self.label)?;
        let bytes = EnvelopeBuilder::new(1)
            .with_hardware(hw.recipient().clone())
            .map_err(map_env)?
            .with_recovery(recovery.clone())
            .map_err(map_env)?
            .seal(secret)
            .map_err(map_env)?;
        write_atomic(&self.path, &bytes)
    }

    /// Windows counterpart of the Secure Enclave path above. The TPM has no
    /// biometric presence ceremony to gate on — `require_user_presence` is
    /// accepted for signature parity with the other platforms and ignored,
    /// same as the label is: `TpmDecapsulator` derives one deterministic key
    /// per machine, not one per label.
    #[cfg(windows)]
    pub fn enrol(
        &self,
        secret: &[u8],
        recovery: &Recipient,
        _require_user_presence: bool,
    ) -> Result<()> {
        if self.exists() {
            return Err(DeviceKeyError::Enclave(format!(
                "an envelope already exists at {}; rotate it or remove it deliberately",
                self.path.display()
            )));
        }
        let hw = TpmDecapsulator::open()?;
        let bytes = EnvelopeBuilder::new(1)
            .with_hardware(hw.recipient().clone())
            .map_err(map_env)?
            .with_recovery(recovery.clone())
            .map_err(map_env)?
            .seal(secret)
            .map_err(map_env)?;
        write_atomic(&self.path, &bytes)
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios", windows)))]
    pub fn enrol(
        &self,
        _secret: &[u8],
        _recovery: &Recipient,
        _require_user_presence: bool,
    ) -> Result<()> {
        Err(DeviceKeyError::Enclave(NO_ENCLAVE_BACKEND.into()))
    }

    /// Open with the device enclave. This is the ordinary path.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn open(&self) -> Result<Zeroizing<Vec<u8>>> {
        let hw = EnclaveDecapsulator::open(&self.label)?;
        self.open_with(&hw)
    }

    #[cfg(windows)]
    pub fn open(&self) -> Result<Zeroizing<Vec<u8>>> {
        let hw = TpmDecapsulator::open()?;
        self.open_with(&hw)
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios", windows)))]
    pub fn open(&self) -> Result<Zeroizing<Vec<u8>>> {
        Err(DeviceKeyError::Enclave(NO_ENCLAVE_BACKEND.into()))
    }

    /// Open with any recipient — the enclave, or a recovery key when the
    /// hardware is gone. This is the method that makes the hardware
    /// non-load-bearing.
    pub fn open_with(&self, d: &dyn Decapsulator) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = std::fs::read(&self.path).map_err(|e| {
            DeviceKeyError::NotFound(format!("no envelope at {}: {e}", self.path.display()))
        })?;
        let env = Envelope::parse(&bytes).map_err(map_env)?;
        let (pt, _) = env.open(d).map_err(map_env)?;
        Ok(pt)
    }

    /// How many recipients can open this envelope. A caller that finds this at
    /// its floor of 2 should say so: the next loss is unrecoverable.
    pub fn recipient_count(&self) -> Result<usize> {
        let bytes = std::fs::read(&self.path).map_err(|e| {
            DeviceKeyError::NotFound(format!("no envelope at {}: {e}", self.path.display()))
        })?;
        Ok(Envelope::parse(&bytes).map_err(map_env)?.recipient_count())
    }

    /// Re-seal to this device's enclave plus `recovery`, with a **fresh** CEK.
    ///
    /// Used after re-enrolling on new hardware, or to retire a recovery code.
    /// `opener` is whatever can still open the current envelope — on a new
    /// machine that is the recovery key, not the enclave.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn rotate(
        &self,
        opener: &dyn Decapsulator,
        recovery: &Recipient,
        require_user_presence: bool,
    ) -> Result<()> {
        let bytes = std::fs::read(&self.path).map_err(|e| {
            DeviceKeyError::NotFound(format!("no envelope at {}: {e}", self.path.display()))
        })?;
        let env = Envelope::parse(&bytes).map_err(map_env)?;

        if crate::backend::open(&self.label).is_err() {
            crate::backend::create_with_presence(&self.label, require_user_presence)?;
        }
        let hw = EnclaveDecapsulator::open(&self.label)?;
        let to = EnvelopeBuilder::new(0)
            .with_hardware(hw.recipient().clone())
            .map_err(map_env)?
            .with_recovery(recovery.clone())
            .map_err(map_env)?;
        let out = env.rotate(opener, to).map_err(map_env)?;
        write_atomic(&self.path, &out)
    }

    /// Windows counterpart of the Secure Enclave path above — see
    /// [`Self::enrol`]'s doc comment for why `require_user_presence` is
    /// accepted and ignored here.
    #[cfg(windows)]
    pub fn rotate(
        &self,
        opener: &dyn Decapsulator,
        recovery: &Recipient,
        _require_user_presence: bool,
    ) -> Result<()> {
        let bytes = std::fs::read(&self.path).map_err(|e| {
            DeviceKeyError::NotFound(format!("no envelope at {}: {e}", self.path.display()))
        })?;
        let env = Envelope::parse(&bytes).map_err(map_env)?;

        let hw = TpmDecapsulator::open()?;
        let to = EnvelopeBuilder::new(0)
            .with_hardware(hw.recipient().clone())
            .map_err(map_env)?
            .with_recovery(recovery.clone())
            .map_err(map_env)?;
        let out = env.rotate(opener, to).map_err(map_env)?;
        write_atomic(&self.path, &out)
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios", windows)))]
    pub fn rotate(
        &self,
        _opener: &dyn Decapsulator,
        _recovery: &Recipient,
        _require_user_presence: bool,
    ) -> Result<()> {
        Err(DeviceKeyError::Enclave(NO_ENCLAVE_BACKEND.into()))
    }
}

fn map_env(e: crate::envelope::EnvelopeError) -> DeviceKeyError {
    DeviceKeyError::Enclave(e.to_string())
}

/// Write via a temp file and rename. A half-written envelope is indistinguishable
/// from a corrupt one, and would strand every recipient at once.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| DeviceKeyError::Enclave(format!("create dir: {e}")))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)
        .map_err(|e| DeviceKeyError::Enclave(format!("write envelope: {e}")))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| DeviceKeyError::Enclave(format!("rename envelope: {e}")))?;
    Ok(())
}

// These exercise a real enclave key (they create, open and delete one), so they
// can only run where that hardware exists. The platform-neutral sealing logic is
// covered by the envelope tests, which run everywhere. The Windows equivalent
// lives beside `backend_tpm`, not here.
#[cfg(all(test, any(target_os = "macos", target_os = "ios")))]
mod tests {
    use super::*;
    use crate::envelope::RecoveryKey;

    fn with_root<T>(name: &str, f: impl FnOnce(&str, &Path) -> T) -> T {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let root = std::env::temp_dir().join(format!("tzsealed-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // SAFETY: serialized by LOCK, so nothing else reads the environment here.
        unsafe { std::env::set_var("TENZRO_DEVICE_KEY_DIR", root.join("keys")) };
        let out = f(&format!("sealed-{name}"), &root);
        unsafe { std::env::remove_var("TENZRO_DEVICE_KEY_DIR") };
        let _ = std::fs::remove_dir_all(&root);
        out
    }

    /// The whole reason this type exists: the enclave is destroyed and the
    /// secret is still recoverable. Under the previous single-recipient
    /// `wrap_secret` this was unrecoverable by construction.
    #[test]
    fn secret_survives_enclave_destruction() {
        with_root("survive", |label, dir| {
            let rec = RecoveryKey::from_ikm(&[0x42; 32]).unwrap();
            let s = SealedSecret::new(label, dir.join("secret.env"));
            s.enrol(b"wallet-keystore-password", rec.recipient(), false)
                .unwrap();

            assert_eq!(&s.open().unwrap()[..], b"wallet-keystore-password");

            // Dead logic board.
            crate::backend_se::delete(label).unwrap();
            assert!(s.open().is_err(), "enclave path should be gone");

            let out = s.open_with(&rec).expect("recovery must still work");
            assert_eq!(&out[..], b"wallet-keystore-password");
        });
    }

    /// After re-enrolling on new hardware, the secret is re-sealed to the new
    /// enclave and stays openable by both paths.
    #[test]
    fn rotate_onto_new_hardware_after_loss() {
        with_root("rotate", |label, dir| {
            let rec = RecoveryKey::from_ikm(&[0x77; 32]).unwrap();
            let s = SealedSecret::new(label, dir.join("secret.env"));
            s.enrol(b"seed-material", rec.recipient(), false).unwrap();

            crate::backend_se::delete(label).unwrap();
            // New machine: only the recovery key can open, so it drives the rotate.
            s.rotate(&rec, rec.recipient(), false).unwrap();

            assert_eq!(
                &s.open().unwrap()[..],
                b"seed-material",
                "new enclave must open it"
            );
            assert_eq!(&s.open_with(&rec).unwrap()[..], b"seed-material");
        });
    }

    /// Overwriting an envelope would orphan whatever the old recovery code
    /// protects, so enrolling twice must refuse rather than silently replace.
    #[test]
    fn enrol_refuses_to_overwrite() {
        with_root("overwrite", |label, dir| {
            let rec = RecoveryKey::from_ikm(&[1; 32]).unwrap();
            let s = SealedSecret::new(label, dir.join("secret.env"));
            s.enrol(b"first", rec.recipient(), false).unwrap();
            assert!(s.enrol(b"second", rec.recipient(), false).is_err());
            assert_eq!(
                &s.open().unwrap()[..],
                b"first",
                "the original must be untouched"
            );
        });
    }

    #[test]
    fn every_sealed_secret_has_at_least_two_recipients() {
        with_root("count", |label, dir| {
            let rec = RecoveryKey::from_ikm(&[5; 32]).unwrap();
            let s = SealedSecret::new(label, dir.join("secret.env"));
            s.enrol(b"x", rec.recipient(), false).unwrap();
            assert!(s.recipient_count().unwrap() >= 2);
        });
    }

    /// A truncated envelope must fail loudly rather than being treated as absent
    /// — "absent" would send a caller down the first-run path and mint a new
    /// secret over a recoverable one.
    #[test]
    fn truncated_envelope_is_an_error_not_a_fresh_start() {
        with_root("trunc", |label, dir| {
            let rec = RecoveryKey::from_ikm(&[8; 32]).unwrap();
            let p = dir.join("secret.env");
            let s = SealedSecret::new(label, p.clone());
            s.enrol(b"precious", rec.recipient(), false).unwrap();

            let bytes = std::fs::read(&p).unwrap();
            std::fs::write(&p, &bytes[..bytes.len() / 2]).unwrap();

            assert!(s.exists(), "a corrupt envelope must still count as present");
            assert!(s.open().is_err());
            assert!(s.open_with(&rec).is_err());
        });
    }
}
