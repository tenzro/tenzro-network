//! [`SecureEnclaveUnlocker`] — a [`KeystoreUnlocker`] backed by a Secure Enclave
//! device key **and** a recovery recipient.
//!
//! ## Lifecycle
//!
//! The unlocker protects a randomly-generated keystore password inside a
//! [`crate::SealedSecret`] — a `tenzro-envelope/v2` addressed to this device's
//! enclave and to a recovery key the operator holds. The plaintext password only
//! ever exists transiently in memory.
//!
//! - **First run:** no envelope on disk. Mint a random password and seal it to
//!   both recipients. Return the password.
//! - **Later runs:** open the envelope with this device's enclave and return the
//!   SAME password.
//! - **After hardware loss:** the enclave path fails, but the wallet is *not*
//!   gone. [`crate::SealedSecret::open_with`] recovers the password from the
//!   recovery code, and [`crate::SealedSecret::rotate`] re-seals it to the new
//!   machine.
//!
//! ## Why `recovery` is a constructor parameter
//!
//! [`KeystoreUnlocker::unlock_password`] takes no arguments, yet first-run
//! enrolment happens inside it. If the recovery recipient were resolved lazily
//! there, the obvious implementation would mint a single-recipient ciphertext on
//! first run — the exact failure this crate has already shipped once. Requiring
//! it up front makes that unrepresentable rather than merely discouraged.

use std::path::{Path, PathBuf};

use tenzro_keystore_unlock::{KeystoreUnlocker, Result as UnlockResult, UnlockError};
use zeroize::Zeroizing;

use crate::SealedSecret;
use crate::envelope::Recipient;

/// Default device-key label used to derive the keystore password.
pub const DEFAULT_LABEL: &str = "tenzro-keystore-unlock";

/// A [`KeystoreUnlocker`] whose password is sealed to a Secure Enclave key
/// **and** a recovery recipient.
///
/// `recovery` is required at construction rather than at first unlock, because
/// [`KeystoreUnlocker::unlock_password`] takes no arguments and first-run
/// enrolment happens inside it. Making it a constructor parameter is what stops
/// the first unlock from quietly minting a single-recipient ciphertext — which
/// is exactly the failure this crate has already shipped once.
pub struct SecureEnclaveUnlocker {
    label: String,
    ciphertext_path: PathBuf,
    recovery: Recipient,
}

impl SecureEnclaveUnlocker {
    /// Build an unlocker that stores its wrapped-password ciphertext at
    /// `ciphertext_path` and binds to an SE key tagged `label`.
    pub fn new(
        label: impl Into<String>,
        ciphertext_path: impl Into<PathBuf>,
        recovery: Recipient,
    ) -> Self {
        Self {
            label: label.into(),
            ciphertext_path: ciphertext_path.into(),
            recovery,
        }
    }

    /// Convenience: store the ciphertext as `keystore.pwd.enc` under `data_dir`
    /// and use the default label.
    pub fn under_data_dir(data_dir: impl AsRef<Path>, recovery: Recipient) -> Self {
        Self::new(
            DEFAULT_LABEL,
            data_dir.as_ref().join("keystore.pwd.enc"),
            recovery,
        )
    }

    fn sealed(&self) -> SealedSecret {
        SealedSecret::new(self.label.clone(), self.ciphertext_path.clone())
    }

    /// Encode 32 random bytes as a 64-char hex password.
    fn random_password() -> Zeroizing<String> {
        use rand::RngCore;
        use zeroize::Zeroize;
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let pw = Zeroizing::new(hex::encode(raw));
        raw.zeroize();
        pw
    }
}

impl KeystoreUnlocker for SecureEnclaveUnlocker {
    fn unlock_password(&self) -> UnlockResult<Zeroizing<String>> {
        let sealed = self.sealed();
        if sealed.exists() {
            // Returning run: open the envelope with this device's enclave.
            let pt = sealed.open().map_err(|e| match e {
                crate::DeviceKeyError::NotFound(_) => UnlockError::Unavailable(format!(
                    "the Secure Enclave key '{}' is gone, so this device can no longer open the \
                     keystore envelope. The wallet is NOT lost: open it with the recovery code \
                     and re-seal to this machine. See SealedSecret::open_with / rotate.",
                    self.label
                )),
                other => UnlockError::Backend(other.to_string()),
            })?;
            let s = String::from_utf8(pt.to_vec())
                .map_err(|_| UnlockError::Backend("unsealed password not utf-8".into()))?;
            Ok(Zeroizing::new(s))
        } else {
            // First run: mint a password and seal it to the enclave AND recovery.
            let password = Self::random_password();
            sealed
                .enrol(password.as_bytes(), &self.recovery, false)
                .map_err(|e| UnlockError::Backend(format!("enrol keystore secret: {e}")))?;
            Ok(password)
        }
    }
}
