//! Hardware-backed device keys for Tenzro.
//!
//! A device key is a non-extractable P-256 keypair living in the platform's
//! hardware-rooted secure element. On macOS/iOS that is the Secure Enclave, via
//! **CryptoKit** (see [`backend_se`]). The private key never enters process
//! memory; signing and key agreement happen inside the enclave.
//!
//! Two capabilities:
//! 1. **Signing** ([`DeviceKey::sign_prehash`]) — sign a 32-byte digest.
//! 2. **Secret wrapping** ([`DeviceKey::wrap_secret`] / [`DeviceKey::unwrap_secret`])
//!    — encrypt an arbitrary secret to this device, recoverable only by the same
//!    hardware. The decrypt output is stable across calls, which makes this the
//!    right primitive for a persistent keystore password — see
//!    [`SecureEnclaveUnlocker`].
//!
//! ## Where the key is persisted
//!
//! CryptoKit hands back a **SEP-wrapped blob** which this crate stores itself,
//! under `~/Library/Application Support/Tenzro/device-keys/<sha256(label)>/`
//! (override with `TENZRO_DEVICE_KEY_DIR`). The blob is useless without the
//! originating Secure Enclave, so writing it to an ordinary file is safe.
//!
//! This is deliberately **not** the keychain. `SecKeyCreateRandomKey` with
//! `kSecAttrIsPermanent` persists into the data-protection keychain, which is
//! entitlement-gated and fails `-34018` without a provisioning profile — so a
//! keychain-based design cannot be permissionless on Apple hardware. CryptoKit
//! never touches the keychain, which is the whole reason this crate uses it.
//!
//! Keys written by 0.2.x are **not** read, migrated or detected. That version
//! stored nothing durable — its persistent create always failed and fell back
//! to a session key — so there is no prior state to be compatible with, and no
//! compatibility path is carried for one.
//!
//! ## Two keys, one identity
//!
//! CryptoKit exposes `SecureEnclave.P256.Signing` and `.KeyAgreement` as
//! distinct types with distinct blobs, so a device holds **two** enclave keys.
//! The **signing** key is the device identity — that is what
//! [`DeviceKey::public_key`] returns and what should be registered. The
//! agreement key is a subordinate credential bound to it by a signature; see
//! [`backend_se::DeviceIdentity`]. Verify that binding before wrapping anything
//! to an agreement key you did not read locally.
//!
//! ## Never a single recipient
//!
//! [`envelope`] wraps a secret to **two or more independent recipients** — this
//! device's enclave plus a recovery key held by a human — because a
//! non-extractable key as the sole recipient means the secret dies with the
//! hardware. That is the same class of permanent loss as the bug this crate was
//! rewritten to fix, reached by a different route. The builder makes a
//! single-recipient envelope *unrepresentable*.
//!
//! ⚠ **Guarantee.** Keys are never plaintext at rest and the enclave key cannot
//! be extracted. That is *not* the same as "the secret is always in hardware":
//! [`DeviceKey::unwrap_secret`] returns plaintext into process memory by design.

/// Raw uncompressed SEC1 P-256 public key (`x ‖ y`, no `0x04` prefix).
pub type DevicePublicKey = [u8; 64];

/// Raw `r ‖ s` ECDSA-P-256 signature (no DER wrapper).
pub type DeviceSignature = [u8; 64];

#[derive(Debug, thiserror::Error)]
pub enum DeviceKeyError {
    #[error("secure enclave error: {0}")]
    Enclave(String),
    #[error("attestation not supported by this backend")]
    AttestationUnsupported,
    #[error("key not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, DeviceKeyError>;

/// Hardware attestation evidence. Format is backend-specific.
#[derive(Debug, Clone)]
pub struct Attestation {
    pub backend: &'static str,
    pub evidence: Vec<u8>,
    pub public_key: DevicePublicKey,
}

/// One hardware-resident P-256 keypair. The label is the user-facing key tag;
/// the private key bytes are never returned by any method.
pub trait DeviceKey: Send + Sync {
    /// Stable identifier the backend uses to look up the key.
    fn label(&self) -> &str;

    /// Raw `x ‖ y` P-256 public key (64 bytes).
    fn public_key(&self) -> Result<DevicePublicKey>;

    /// Sign a 32-byte SHA-256 prehash. Returns raw `r ‖ s` (64 bytes).
    fn sign_prehash(&self, hash: &[u8; 32]) -> Result<DeviceSignature>;

    /// ECIES-encrypt `secret` to THIS key's public key. Does NOT trigger a
    /// biometric prompt (encryption only needs the public key). The ciphertext
    /// can only be recovered by this same hardware key via [`Self::unwrap_secret`].
    fn wrap_secret(&self, secret: &[u8]) -> Result<Vec<u8>>;

    /// ECIES-decrypt a ciphertext produced by [`Self::wrap_secret`]. Triggers
    /// the user-presence ceremony. Output is stable across calls.
    fn unwrap_secret(&self, ciphertext: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>>;

    /// Hardware attestation over the public key. Optional.
    fn attest(&self) -> Result<Attestation> {
        Err(DeviceKeyError::AttestationUnsupported)
    }
}

/// Open an existing key by label, or return `NotFound`.
pub fn open(label: &str) -> Result<Box<dyn DeviceKey>> {
    backend::open(label)
}

/// Create a new biometry-gated, non-extractable P-256 key under `label`.
pub fn create(label: &str) -> Result<Box<dyn DeviceKey>> {
    backend::create(label)
}

/// Delete a key. Idempotent.
pub fn delete(label: &str) -> Result<()> {
    backend::delete(label)
}

/// Deterministic credential id for a passkey: the SHA-256 of its device-key
/// label. Stable across runs so `signWithPasskey` can locate the credential
/// without persisting an extra identifier.
pub fn credential_id_for_label(label: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

pub mod envelope;
pub mod hpke;
pub mod sealed;
mod unlocker;
pub use sealed::SealedSecret;
pub use unlocker::SecureEnclaveUnlocker;

#[cfg(feature = "pq-companion")]
pub mod pq_companion;
#[cfg(feature = "pq-companion")]
pub use pq_companion::PqCompanion;

// ---- Backend dispatch ------------------------------------------------------

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod backend {
    pub use super::backend_se::{EnclaveDecapsulator, create, create_with_presence, delete, open};
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod backend_se;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use backend_se::{
    BINDING_CONTEXT, DeviceIdentity, agreement_public_key, available, create_with_presence,
    identity,
};

/// The TPM-backed `Decapsulator` for [`sealed::SealedSecret`] — see its
/// module docs for why this is Windows-only rather than a `DeviceKey`
/// backend: it roots a *machine* identity (the wallet keystore password),
/// not the passkey-adjacent device keys `backend::open`/`create` serve.
#[cfg(windows)]
pub mod backend_tpm;

/// The Windows TPM 2.0 *signing* key — the `DeviceKey` counterpart to
/// [`backend_tpm`]'s decrypt-only decapsulator, and the platform twin of
/// [`backend_se`] on Apple. `backend::open`/`create`/`delete` resolve here on
/// Windows, so `DeviceKey` means a real hardware key on this platform rather
/// than the "not yet wired" stub.
#[cfg(windows)]
pub mod backend_tpm_sign;

#[cfg(windows)]
mod backend {
    pub use super::backend_tpm_sign::{create, delete, open};
}

#[cfg(not(any(target_os = "macos", target_os = "ios", windows)))]
mod backend {
    use super::{DeviceKey, DeviceKeyError, Result};
    const STUB: &str = "device-key backend not yet wired for this platform";
    pub fn open(_label: &str) -> Result<Box<dyn DeviceKey>> {
        Err(DeviceKeyError::Enclave(STUB.into()))
    }
    pub fn create(_label: &str) -> Result<Box<dyn DeviceKey>> {
        Err(DeviceKeyError::Enclave(STUB.into()))
    }
    pub fn delete(_label: &str) -> Result<()> {
        Err(DeviceKeyError::Enclave(STUB.into()))
    }
    pub fn create_with_presence(_label: &str, _require_user_presence: bool) -> Result<()> {
        Err(DeviceKeyError::Enclave(STUB.into()))
    }

    /// The non-Apple stand-in for the enclave decapsulator.
    ///
    /// Uninhabited on purpose: there is no hardware-backed decapsulator on this
    /// platform yet, so a value of this type cannot exist and every path that
    /// would need one stops at `open`. When a TPM backend lands it replaces
    /// this, and `sealed.rs` needs no change because it already goes through
    /// `crate::backend`.
    pub enum EnclaveDecapsulator {}

    impl EnclaveDecapsulator {
        pub fn open(_label: &str) -> Result<Self> {
            Err(DeviceKeyError::Enclave(STUB.into()))
        }
    }

    // Implemented so the sealing code compiles unchanged on this platform.
    // Every method is unreachable: the type has no variants, so `open` above is
    // the only way in and it always fails.
    impl crate::envelope::Decapsulator for EnclaveDecapsulator {
        fn recipient(&self) -> &crate::envelope::Recipient {
            match *self {}
        }
        fn raw_dh(
            &self,
            _peer_enc: &[u8],
        ) -> std::result::Result<zeroize::Zeroizing<[u8; 32]>, crate::envelope::EnvelopeError>
        {
            match *self {}
        }
    }
}
