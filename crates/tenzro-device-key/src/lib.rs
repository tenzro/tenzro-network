//! Hardware-backed device keys for Tenzro.
//!
//! A device key is a non-extractable P-256 keypair living in the platform's
//! hardware-rooted secure element. On macOS/iOS that is the Secure Enclave, via
//! **CryptoKit** (see [`backend_se`]). The private key never enters process
//! memory; signing and key agreement happen inside the enclave.
//!
//! Three capabilities:
//! 1. **Signing** ([`DeviceKey::sign_prehash`]) — sign a 32-byte digest.
//! 2. **Secret wrapping** ([`DeviceKey::wrap_secret`] / [`DeviceKey::unwrap_secret`])
//!    — encrypt an arbitrary secret to this device, recoverable only by the same
//!    hardware.
//! 3. **Derivation** ([`derive`]) — Ed25519, X25519 and ML-DSA-65
//!    keys, which the hardware cannot hold, derived on demand from a hardware
//!    key for one operation and wiped.
//!
//! ## Where the key is persisted
//!
//! CryptoKit hands back a **SEP-wrapped blob** which this crate stores itself,
//! under `~/Library/Application Support/Tenzro/device-keys/<sha256(label)>/`
//! (override with `TENZRO_DEVICE_KEY_DIR`). The blob is useless without the
//! originating Secure Enclave, so writing it to an ordinary file is safe.
//!
//! This is deliberately **not** the keychain. `SecKeyCreateRandomKey` with
//! `kSecAttrIsPermanent` persists into the data-protection keychain and fails
//! `-34018` without a provisioning profile. CryptoKit hands back a blob this
//! crate stores itself, so it manages no keychain items — which is a real
//! simplification and the reason for the choice.
//!
//! It does **not** make Secure Enclave use unprivileged, and this doc used to
//! say it did. Apple DTS (developer forums 786171) states the rule for the
//! Secure Enclave itself, not for one framework: *"Access to the SE is the same
//! as access to the data protection keychain. In short: you need an App ID
//! that's authorised by a profile, and you need to be running in a user
//! context."* TN3137 says the same from the keychain side. An unsigned build
//! creating and reopening an SE key — measured, on an M2 — is incidental
//! success in unsupported territory, and may stop at an OS update or a
//! signing-identity change. Depending on macOS SE identity durably is likely to
//! need Apple signing assets, which is a licensing decision rather than a
//! technical one.
//!
//! There is no Secure Enclave entitlement; DTS attributes requests for one to
//! LLM hallucination.
//!
//! Four properties to know before depending on this, all verified:
//! - **No Secure Enclave in VMs** on Apple silicon; gate on
//!   `SecureEnclave.isAvailable`.
//! - The SEP blob is **device-bound** — the wrapping key is unique per secure
//!   element, so a copy on another Mac will not unwrap. Right for machine
//!   identity, fatal for backup or migration.
//! - The SE offers **no Ed25519**; P-256 is the only classical signing curve
//!   there, which is why [`DeviceKey`] is P-256 on Apple.
//! - **User presence is optional.** CryptoKit's default access control uses
//!   empty flags, so signing prompts for nothing unless `.userPresence` is
//!   requested, and the policy is fixed at key creation. That is what makes
//!   unattended signing possible.
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
//! device's enclave plus a second hardware key — because a
//! non-extractable key as the sole recipient means the secret dies with the
//! hardware. That is the same class of permanent loss as the bug this crate was
//! rewritten to fix, reached by a different route. The builder makes a
//! single-recipient envelope *unrepresentable*.
//!
//! **Guarantee.** Keys are never plaintext at rest and the enclave key cannot
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
    #[error("TPM error: {0}")]
    Tpm(String),
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

/// The namespace every key label of this process lives under, when one is
/// set.
static LABEL_NAMESPACE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Places every key this process opens, creates, deletes or derives from the
/// machine's root under `namespace`: the key labelled `l` becomes
/// `{namespace}/{l}`. A machine
/// runs one node under the default labels; each further node on the same
/// machine sets its own namespace, so it holds its own hardware key and
/// identity rather than the machine's. The namespace names keys only: every
/// key stays in the hardware and is derived there.
///
/// Set once, before any key is opened. `namespace` is 1 to 64 characters of
/// `a-z`, `0-9`, `-` and `_`; setting a second, different namespace is
/// refused.
pub fn set_label_namespace(namespace: &str) -> Result<()> {
    let valid = !namespace.is_empty()
        && namespace.len() <= 64
        && namespace
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if !valid {
        return Err(DeviceKeyError::Enclave(format!(
            "key namespace {namespace:?} must be 1 to 64 characters of a-z, 0-9, '-' and '_'"
        )));
    }
    let set = LABEL_NAMESPACE.get_or_init(|| namespace.to_string());
    if set != namespace {
        return Err(DeviceKeyError::Enclave(format!(
            "key namespace already set to {set:?}"
        )));
    }
    Ok(())
}

/// `label` under this process's namespace.
pub(crate) fn namespaced(label: &str) -> std::borrow::Cow<'_, str> {
    match LABEL_NAMESPACE.get() {
        Some(ns) => format!("{ns}/{label}").into(),
        None => label.into(),
    }
}

/// Open an existing key by label, or return `NotFound`.
pub fn open(label: &str) -> Result<Box<dyn DeviceKey>> {
    backend::open(&namespaced(label))
}

/// Create a new biometry-gated, non-extractable P-256 key under `label`.
pub fn create(label: &str) -> Result<Box<dyn DeviceKey>> {
    backend::create(&namespaced(label))
}

/// Delete a key. Idempotent.
pub fn delete(label: &str) -> Result<()> {
    backend::delete(&namespaced(label))
}

/// Deterministic credential id for a passkey: the SHA-256 of its device-key
/// label. Stable across runs so a signer can locate the credential
/// without persisting an extra identifier.
pub fn credential_id_for_label(label: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

/// TPM credential protection: a secret only an object in the same TPM as an
/// endorsement key can recover.
pub mod batch_signer;
pub mod compact;
pub mod credential;
pub mod delegation;
pub mod derive;
pub use derive::{DerivationRoot, DeriveBackend, Ed25519Key, MlDsa65Key, P256Key, X25519Key};
/// The TPM derivation root behind [`derive::DerivationRoot`] on Linux and Windows.
#[cfg(any(target_os = "linux", windows, test))]
pub mod derive_tpm;
pub mod envelope;
pub mod hpke;
pub mod issuer_chain;
pub mod key_certification;
pub mod remote;
pub mod session;
pub mod signer;
/// The label of the node identity key. On a TPM it is the one labelled key
/// held at a persistent handle, made by provisioning, rather than generated
/// on first use.
pub const IDENTITY_KEY_LABEL: &str = "tenzro/consensus/validator";
/// The one serializing executor every TPM command runs on.
#[cfg(any(target_os = "linux", windows, test))]
pub mod tpm_exec;
/// One-time TPM provisioning: the only place a primary key is created.
#[cfg(any(target_os = "linux", windows, test))]
pub mod tpm_provision;
pub mod tpm_queue;
pub mod tpm_wire;
pub use signer::{
    HardwareBackend, HardwareHybridSigner, HardwareMlDsaSigner, HardwareP384Signer, HardwareSigner,
};

// ---- Backend dispatch ------------------------------------------------------

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod backend {
    pub use super::backend_se::{create, delete, open};
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod backend_se;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use backend_se::{
    BINDING_CONTEXT, DeviceIdentity, agreement_public_key, available, create_with_presence,
    identity,
};

/// The TPM 2.0 signing and key-agreement key, over the kernel resource
/// manager on Linux and TPM Base Services on Windows.
/// `backend::open`/`create`/`delete` resolve here on both.
#[cfg(any(target_os = "linux", windows))]
pub mod backend_tpm;

#[cfg(any(target_os = "linux", windows))]
mod backend {
    pub use super::backend_tpm::{create, delete, open};
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux", windows)))]
mod backend {
    use super::{DeviceKey, DeviceKeyError, Result};
    const STUB: &str = "no TPM or Secure Enclave backend exists for this platform";
    pub fn open(_label: &str) -> Result<Box<dyn DeviceKey>> {
        Err(DeviceKeyError::Enclave(STUB.into()))
    }
    pub fn create(_label: &str) -> Result<Box<dyn DeviceKey>> {
        Err(DeviceKeyError::Enclave(STUB.into()))
    }
    pub fn delete(_label: &str) -> Result<()> {
        Err(DeviceKeyError::Enclave(STUB.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Setting a namespace is process-wide and would change every other
    // test's keys, so this test only exercises the refusals, which set
    // nothing.
    #[test]
    fn a_key_namespace_must_be_a_plain_name() {
        for bad in ["", "Upper", "a/b", "a b", "../x", &"x".repeat(65)] {
            assert!(set_label_namespace(bad).is_err(), "{bad:?} accepted");
        }
        assert_eq!(
            namespaced("machine"),
            "machine",
            "a refused namespace set nothing"
        );
    }
}
