//! Platform-agnostic keystore-unlock abstraction.
//!
//! The wallet keystore (`tenzro-wallet`) seals a wallet's record at rest with
//! a password (Argon2id). For a wallet to persist across restarts, the node
//! must reproduce that password on every launch, and where it comes from is
//! deployment-specific. It comes from hardware: a device key in a Secure
//! Enclave or a TPM, which `tenzro-keygen` wires up.
//!
//! This crate defines only the [`KeystoreUnlocker`] trait. It deliberately has
//! no platform dependencies, so it compiles everywhere and can sit in the
//! public API of `tenzro-wallet` / `tenzro-node` without dragging in
//! `security-framework`.
//!
//! There is no environment-variable or in-memory implementation here. One
//! would put the password that opens the keystore in the process environment,
//! where it is readable by anything that can read `/proc/<pid>/environ`, a
//! core dump or an orchestrator's secret listing — which is the arrangement
//! hardware custody exists to end.

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

/// Supplies the password that seals and opens a wallet's keystore record.
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
