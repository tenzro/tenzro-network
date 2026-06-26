//! Platform-agnostic keystore-unlock abstraction.
//!
//! The Tenzro wallet keystore (`tenzro-wallet`) encrypts FROST key shares at
//! rest with a password (Argon2id). For wallets to *persist* across restarts,
//! the node must be able to reproduce that password on every launch. WHERE the
//! password comes from is deployment-specific:
//!
//! - **Desktop apps** derive it from a hardware-backed device key gated by
//!   biometrics (macOS Secure Enclave + Touch ID — see `tenzro-device-key`).
//! - **Headless / server nodes** read it from an environment variable, a file,
//!   or a KMS.
//!
//! This crate defines only the [`KeystoreUnlocker`] trait plus two trivial,
//! always-available implementations ([`StaticUnlocker`], [`EnvUnlocker`]). It
//! deliberately has NO platform dependencies so it compiles everywhere and can
//! sit in the public API of `tenzro-wallet`/`tenzro-node` without dragging in
//! `security-framework`. The biometric implementation lives in the separate,
//! macOS-flavored `tenzro-device-key` crate.

use zeroize::Zeroizing;

/// Errors a [`KeystoreUnlocker`] can surface.
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// The unlock source is present but the user/operator denied or cancelled
    /// it (e.g. cancelled the Touch ID prompt).
    #[error("keystore unlock cancelled")]
    Cancelled,
    /// The configured unlock source is missing (e.g. the env var is unset, the
    /// ciphertext file does not exist yet).
    #[error("keystore unlock source unavailable: {0}")]
    Unavailable(String),
    /// The unlock source failed for an implementation-specific reason
    /// (hardware error, decryption failure, malformed ciphertext, …).
    #[error("keystore unlock failed: {0}")]
    Backend(String),
}

/// Result alias for unlock operations.
pub type Result<T> = std::result::Result<T, UnlockError>;

/// Supplies the keystore password used to encrypt/decrypt wallet key shares.
///
/// Implementations must return the SAME password bytes on every call for a
/// given device/deployment, otherwise a keystore written on first run cannot be
/// decrypted on the next launch. The returned value is wrapped in
/// [`Zeroizing`] so it is wiped from memory on drop.
///
/// Calling `unlock_password` MAY block (a biometric prompt) and MAY prompt the
/// user, so callers should invoke it once during wallet-service init and reuse
/// the resulting [`tenzro_wallet`]-side configured password, rather than per
/// keystore access.
pub trait KeystoreUnlocker: Send + Sync {
    /// Resolve the keystore password. See the trait docs for the stability
    /// contract.
    fn unlock_password(&self) -> Result<Zeroizing<String>>;
}

/// A fixed, in-memory password. Useful for tests, ephemeral nodes, or callers
/// that manage the secret themselves. NOT secure at rest (the password lives in
/// process memory and wherever the caller sourced it).
pub struct StaticUnlocker(Zeroizing<String>);

impl StaticUnlocker {
    /// Wrap an already-known password.
    pub fn new(password: impl Into<String>) -> Self {
        Self(Zeroizing::new(password.into()))
    }
}

impl KeystoreUnlocker for StaticUnlocker {
    fn unlock_password(&self) -> Result<Zeroizing<String>> {
        Ok(self.0.clone())
    }
}

/// Reads the keystore password from an environment variable. Intended for
/// headless/server deployments where the operator injects the secret via the
/// process environment or an orchestrator secret mount.
pub struct EnvUnlocker {
    var: String,
}

impl EnvUnlocker {
    /// Read from `var` at unlock time (not construction time), so the value can
    /// be populated after the unlocker is built.
    pub fn new(var: impl Into<String>) -> Self {
        Self { var: var.into() }
    }
}

impl KeystoreUnlocker for EnvUnlocker {
    fn unlock_password(&self) -> Result<Zeroizing<String>> {
        match std::env::var(&self.var) {
            Ok(v) if !v.is_empty() => Ok(Zeroizing::new(v)),
            Ok(_) => Err(UnlockError::Unavailable(format!("${} is empty", self.var))),
            Err(_) => Err(UnlockError::Unavailable(format!("${} unset", self.var))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_is_stable() {
        let u = StaticUnlocker::new("hunter2");
        assert_eq!(&**u.unlock_password().unwrap(), "hunter2");
        assert_eq!(
            u.unlock_password().unwrap(),
            u.unlock_password().unwrap(),
            "must return the same password every call"
        );
    }

    #[test]
    fn env_missing_is_unavailable() {
        let u = EnvUnlocker::new("TENZRO_TEST_UNLOCK_DEFINITELY_UNSET");
        assert!(matches!(
            u.unlock_password(),
            Err(UnlockError::Unavailable(_))
        ));
    }
}
