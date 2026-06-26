//! [`SecureEnclaveUnlocker`] — a [`KeystoreUnlocker`] backed by a Secure Enclave
//! device key.
//!
//! ## Lifecycle
//!
//! The unlocker protects a randomly-generated keystore password by ECIES-
//! wrapping it to a Secure Enclave key. The wrapped ciphertext is stored on
//! disk; the plaintext password only ever exists transiently in memory after a
//! biometric unlock.
//!
//! - **First run:** no ciphertext on disk. Create the SE key, generate a random
//!   password, [`DeviceKey::wrap_secret`] it (no prompt), persist the
//!   ciphertext. Return the password.
//! - **Later runs:** ciphertext exists. [`open`](crate::open) the SE key (only
//!   succeeds if the app is provisioned — see crate docs), then
//!   [`DeviceKey::unwrap_secret`] the ciphertext (Touch ID prompt) to recover
//!   the SAME password.
//!
//! ## Provisioning requirement
//!
//! Cross-restart unlock requires the embedding app to ship a
//! `keychain-access-groups` entitlement + an embedded provisioning profile so
//! the SE key persists in the data-protection keychain. This is an
//! app-DEPLOYMENT responsibility (the operator shipping the desktop app), NOT a
//! node concern. On an un-provisioned build, first-run create+wrap+unwrap works
//! within the session, but a restart cannot reopen the key — `unlock_password`
//! returns [`UnlockError::Unavailable`] and the caller should treat the wallet
//! as needing re-creation.

use std::path::{Path, PathBuf};

use tenzro_keystore_unlock::{KeystoreUnlocker, Result as UnlockResult, UnlockError};
use zeroize::Zeroizing;

/// Default device-key label used to derive the keystore password.
pub const DEFAULT_LABEL: &str = "tenzro-keystore-unlock";

/// A [`KeystoreUnlocker`] whose password is bound to a Secure Enclave key.
pub struct SecureEnclaveUnlocker {
    label: String,
    ciphertext_path: PathBuf,
}

impl SecureEnclaveUnlocker {
    /// Build an unlocker that stores its wrapped-password ciphertext at
    /// `ciphertext_path` and binds to an SE key tagged `label`.
    pub fn new(label: impl Into<String>, ciphertext_path: impl Into<PathBuf>) -> Self {
        Self {
            label: label.into(),
            ciphertext_path: ciphertext_path.into(),
        }
    }

    /// Convenience: store the ciphertext as `keystore.pwd.enc` under `data_dir`
    /// and use the default label.
    pub fn under_data_dir(data_dir: impl AsRef<Path>) -> Self {
        Self::new(
            DEFAULT_LABEL,
            data_dir.as_ref().join("keystore.pwd.enc"),
        )
    }

    fn read_ciphertext(&self) -> Option<Vec<u8>> {
        std::fs::read(&self.ciphertext_path).ok()
    }

    fn write_ciphertext(&self, bytes: &[u8]) -> UnlockResult<()> {
        if let Some(parent) = self.ciphertext_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| UnlockError::Backend(format!("create dir: {e}")))?;
        }
        std::fs::write(&self.ciphertext_path, bytes)
            .map_err(|e| UnlockError::Backend(format!("write ciphertext: {e}")))
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
        match self.read_ciphertext() {
            // Returning run: reopen the SE key and decrypt (Touch ID).
            Some(ct) => {
                let key = crate::open(&self.label).map_err(|e| match e {
                    crate::DeviceKeyError::NotFound(_) => UnlockError::Unavailable(format!(
                        "Secure Enclave key '{}' not reopenable across restart — app likely \
                         lacks the keychain-access-groups entitlement + provisioning profile",
                        self.label
                    )),
                    other => UnlockError::Backend(other.to_string()),
                })?;
                let pt = key
                    .unwrap_secret(&ct)
                    .map_err(|e| UnlockError::Backend(format!("unwrap: {e}")))?;
                let s = String::from_utf8(pt.to_vec())
                    .map_err(|_| UnlockError::Backend("unwrapped password not utf-8".into()))?;
                Ok(Zeroizing::new(s))
            }
            // First run: create the SE key, generate + wrap a fresh password.
            None => {
                let key = crate::create(&self.label)
                    .map_err(|e| UnlockError::Backend(format!("create key: {e}")))?;
                let password = Self::random_password();
                let ct = key
                    .wrap_secret(password.as_bytes())
                    .map_err(|e| UnlockError::Backend(format!("wrap: {e}")))?;
                self.write_ciphertext(&ct)?;
                Ok(password)
            }
        }
    }
}
