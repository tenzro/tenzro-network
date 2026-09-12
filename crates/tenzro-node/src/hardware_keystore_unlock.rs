//! Keystore unlock rooted in this machine's own hardware.
//!
//! The wallet keystore needs a password to persist. Reading it from an
//! environment variable made the whole wallet only as good as a string an
//! operator pasted into a unit file — copyable, greppable, and outside the
//! hardware boundary every other Tenzro identity lives inside. Identity is
//! rooted in a TPM, a Secure Enclave or a passkey and in nothing else, so a
//! keystore that guards signing keys cannot be the one exception.
//!
//! The password is derived, never stored: the same chip returns the same
//! secret on every boot, so wallets reopen after a restart without any
//! material on disk to steal. A machine with no TPM gets no persistence
//! rather than a weaker kind — an ephemeral wallet is a legible limitation,
//! whereas a file-backed one looks identical to a real one until it is
//! copied.

use tenzro_keystore_unlock::{KeystoreUnlocker, Result, UnlockError};
use zeroize::Zeroizing;

/// Domain tag for the derivation. Distinct from every other purpose the node
/// derives, so the keystore password cannot be replayed as one of them.
const KEYSTORE_PURPOSE: &str = "tenzro/node/wallet-keystore/v1";

/// Derives the wallet-keystore password from the machine's TPM.
///
/// Stateless: it holds no secret itself and re-derives on each call, so a
/// long-lived process is not carrying the password around in its heap between
/// unlocks.
pub struct HardwareUnlocker;

impl HardwareUnlocker {
    /// Whether this machine can derive a keystore password at all.
    ///
    /// Callers use this to decide between a persistent wallet and an honest
    /// ephemeral one, rather than discovering the difference at first unlock.
    pub fn available() -> bool {
        tenzro_tee::tpm_derive::derivation_available()
    }

    /// A new unlocker. Cheap — the work happens in
    /// [`unlock_password`](KeystoreUnlocker::unlock_password).
    pub fn new() -> Self {
        Self
    }
}

impl Default for HardwareUnlocker {
    fn default() -> Self {
        Self::new()
    }
}

impl KeystoreUnlocker for HardwareUnlocker {
    fn unlock_password(&self) -> Result<Zeroizing<String>> {
        if !tenzro_tee::tpm_derive::derivation_available() {
            return Err(UnlockError::Unavailable(
                "no TPM to derive the wallet-keystore password from. A keystore that guards \
                 signing keys must be rooted in hardware, so this node keeps an ephemeral \
                 wallet rather than falling back to a password on disk"
                    .to_string(),
            ));
        }
        let secret = tenzro_tee::tpm_derive::derive_secret(KEYSTORE_PURPOSE)
            .map_err(|e| UnlockError::Unavailable(format!("TPM derivation failed: {e}")))?;
        // Hex rather than the raw bytes: the keystore takes a string, and a
        // lossy UTF-8 conversion of 32 random bytes would silently collapse
        // distinct secrets onto the replacement character.
        Ok(Zeroizing::new(hex::encode(*secret)))
    }
}
