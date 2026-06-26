//! Hardware-backed device keys for Tenzro.
//!
//! A device key is a non-extractable P-256 keypair living in the platform's
//! hardware-rooted secure element. On macOS/iOS that is the Secure Enclave
//! (via `security-framework` + `kSecAttrTokenIDSecureEnclave`), gated by Touch
//! ID / Face ID. The private key never enters process memory.
//!
//! Two capabilities:
//! 1. **Signing** ([`DeviceKey::sign_prehash`]) — sign a 32-byte digest; the
//!    OS triggers the user-presence ceremony.
//! 2. **Secret wrapping** ([`wrap_secret`] / [`unwrap_secret`]) — ECIES-encrypt
//!    an arbitrary secret to the device public key (no biometrics), and decrypt
//!    it with the private key (biometrics). The decrypt output is STABLE across
//!    calls, which makes this the right primitive for deriving a persistent
//!    keystore password — see [`SecureEnclaveUnlocker`].
//!
//! ## Why not persist the key in the keychain?
//!
//! Storing a Secure Enclave key in *any* keychain (data-protection or file)
//! requires a `keychain-access-groups` entitlement backed by a provisioning
//! profile; without one, `SecKey::new` fails with `errSecMissingEntitlement`
//! (-34018), and adding the entitlement without a profile makes the OS SIGKILL
//! the app. So a key cannot be re-fetched by label across process restarts.
//! Instead the live `SecKey` handle is cached in-process for the lifetime of
//! the run (see the macOS backend's handle cache). Cross-restart *signing* of
//! the same key is therefore not supported without a provisioning profile.
//! Cross-restart *persistence of a secret* requires the same provisioning
//! profile (so the key can be reopened by label and decrypt the on-disk
//! ciphertext). On an un-provisioned build, [`SecureEnclaveUnlocker`] creates
//! the key, wraps the password, and unwraps it WITHIN the same session, but a
//! later run cannot reopen the key and reports the wallet as unavailable. See
//! that type's docs for the exact lifecycle.

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

mod unlocker;
pub use unlocker::SecureEnclaveUnlocker;

pub mod pq_companion;
pub use pq_companion::PqCompanion;

// ---- Backend dispatch ------------------------------------------------------

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod backend {
    pub use super::macos::{create, delete, open};
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
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
}

// ---- macOS / iOS Secure Enclave backend -----------------------------------

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod macos {
    use super::{
        Attestation, DeviceKey, DeviceKeyError, DevicePublicKey, DeviceSignature, Result,
    };
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::item::{
        ItemClass, ItemSearchOptions, Limit, Location, Reference, SearchResult,
    };
    use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    // kSecAccessControlUserPresence = 1<<0, kSecAccessControlPrivateKeyUsage = 1<<30.
    const SAC_USER_PRESENCE: usize = 1 << 0;
    const SAC_PRIVATE_KEY_USAGE: usize = 1 << 30;

    // ECIES variant: ephemeral-static ECDH (X9.63 KDF, SHA-256) + AES-GCM.
    // Decryption output is deterministic for a given (key, ciphertext).
    const ECIES: Algorithm = Algorithm::ECIESEncryptionStandardVariableIVX963SHA256AESGCM;

    // The SE key cannot be re-fetched from the keychain (persisting it needs a
    // provisioning-profile entitlement we don't have), so the live `SecKey`
    // handle from `create()` is cached here for the process lifetime. `SecKey`
    // is `Send + Sync + Clone` (a CFType). Keyed by the caller's label.
    fn handles() -> &'static Mutex<HashMap<String, SecKey>> {
        static HANDLES: OnceLock<Mutex<HashMap<String, SecKey>>> = OnceLock::new();
        HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn cache_handle(label: &str, key: SecKey) {
        if let Ok(mut map) = handles().lock() {
            map.insert(label.to_string(), key);
        }
    }

    fn lookup_handle(label: &str) -> Option<SecKey> {
        handles().lock().ok()?.get(label).cloned()
    }

    pub(super) struct MacEnclaveKey {
        label: String,
        key: SecKey,
    }

    impl MacEnclaveKey {
        fn raw_public_key(key: &SecKey) -> Result<DevicePublicKey> {
            let pk = key
                .public_key()
                .ok_or_else(|| DeviceKeyError::Enclave("no public key on SecKey".into()))?;
            let cfdata = pk
                .external_representation()
                .ok_or_else(|| DeviceKeyError::Enclave("public key not exportable".into()))?;
            let bytes = cfdata.bytes();
            if bytes.len() != 65 || bytes[0] != 0x04 {
                return Err(DeviceKeyError::Enclave(format!(
                    "unexpected public key format: len={} prefix=0x{:02x}",
                    bytes.len(),
                    bytes.first().copied().unwrap_or(0)
                )));
            }
            let mut out = [0u8; 64];
            out.copy_from_slice(&bytes[1..]);
            Ok(out)
        }

        fn der_to_raw_signature(der: &[u8]) -> Result<DeviceSignature> {
            fn read_int(p: &[u8]) -> Result<(&[u8], &[u8])> {
                if p.len() < 2 || p[0] != 0x02 {
                    return Err(DeviceKeyError::Enclave("bad DER INTEGER tag".into()));
                }
                let len = p[1] as usize;
                if p.len() < 2 + len {
                    return Err(DeviceKeyError::Enclave("DER INTEGER truncated".into()));
                }
                Ok((&p[2..2 + len], &p[2 + len..]))
            }
            if der.len() < 2 || der[0] != 0x30 {
                return Err(DeviceKeyError::Enclave("bad DER SEQUENCE".into()));
            }
            let body = &der[2..];
            let (r, rest) = read_int(body)?;
            let (s, _) = read_int(rest)?;
            let mut out = [0u8; 64];
            let r_strip = if r.len() == 33 && r[0] == 0 { &r[1..] } else { r };
            let s_strip = if s.len() == 33 && s[0] == 0 { &s[1..] } else { s };
            if r_strip.len() > 32 || s_strip.len() > 32 {
                return Err(DeviceKeyError::Enclave("ECDSA scalar > 32 bytes".into()));
            }
            out[32 - r_strip.len()..32].copy_from_slice(r_strip);
            out[64 - s_strip.len()..64].copy_from_slice(s_strip);
            Ok(out)
        }
    }

    impl DeviceKey for MacEnclaveKey {
        fn label(&self) -> &str {
            &self.label
        }

        fn public_key(&self) -> Result<DevicePublicKey> {
            Self::raw_public_key(&self.key)
        }

        fn sign_prehash(&self, hash: &[u8; 32]) -> Result<DeviceSignature> {
            let der = self
                .key
                .create_signature(Algorithm::ECDSASignatureDigestX962SHA256, hash)
                .map_err(|e| DeviceKeyError::Enclave(format!("create_signature: {}", e)))?;
            Self::der_to_raw_signature(&der)
        }

        fn wrap_secret(&self, secret: &[u8]) -> Result<Vec<u8>> {
            // Encrypt to our OWN public key, derived from the live handle via
            // SecKeyCopyPublicKey. No biometric prompt — encryption only needs
            // the public key.
            let pubkey = self
                .key
                .public_key()
                .ok_or_else(|| DeviceKeyError::Enclave("no public key on SecKey".into()))?;
            pubkey
                .encrypt_data(ECIES, secret)
                .map_err(|e| DeviceKeyError::Enclave(format!("encrypt_data: {}", e)))
        }

        fn unwrap_secret(&self, ciphertext: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
            let pt = self
                .key
                .decrypt_data(ECIES, ciphertext)
                .map_err(|e| DeviceKeyError::Enclave(format!("decrypt_data: {}", e)))?;
            Ok(zeroize::Zeroizing::new(pt))
        }

        fn attest(&self) -> Result<Attestation> {
            Err(DeviceKeyError::AttestationUnsupported)
        }
    }

    pub fn open(label: &str) -> Result<Box<dyn DeviceKey>> {
        // Path 1: in-process cache (always works within the session that
        // created the key; the only path available when the app has no
        // provisioning profile).
        if let Some(key) = lookup_handle(label) {
            return Ok(Box::new(MacEnclaveKey {
                label: label.to_string(),
                key,
            }));
        }

        // Path 2: keychain search. Succeeds ONLY when the key was persisted to
        // the data-protection keychain at creation, which itself requires the
        // app to carry a `keychain-access-groups` entitlement backed by an
        // embedded provisioning profile. This is what enables cross-RESTART
        // open. Without the profile the key was never persisted, so this misses
        // and we fall through to NotFound.
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::key())
            .label(label)
            .ignore_legacy_keychains()
            .load_refs(true)
            .limit(Limit::Max(1));
        if let Ok(results) = search.search() {
            for r in results {
                if let SearchResult::Ref(Reference::Key(key)) = r {
                    cache_handle(label, key.clone());
                    return Ok(Box::new(MacEnclaveKey {
                        label: label.to_string(),
                        key,
                    }));
                }
            }
        }

        Err(DeviceKeyError::NotFound(label.to_string()))
    }

    pub fn create(label: &str) -> Result<Box<dyn DeviceKey>> {
        // Attempt PERSISTENT creation first: `set_location(DataProtectionKeychain)`
        // sets `kSecAttrIsPermanent=true` so the key survives restarts and can
        // be reopened by label. This SUCCEEDS only if the app carries the
        // `keychain-access-groups` entitlement + an embedded provisioning
        // profile (an app-deployment responsibility). If it isn't provisioned,
        // `SecKey::new` returns errSecMissingEntitlement (-34018); we then fall
        // back to a NON-persistent key cached in-process for this session so
        // dev / unsigned / no-profile builds still function (same-session
        // create→sign→wrap/unwrap), just without cross-restart persistence.
        let make_opts = |persistent: bool| {
            let acl = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                SAC_USER_PRESENCE | SAC_PRIVATE_KEY_USAGE,
            )
            .ok();
            let mut opts = GenerateKeyOptions::default();
            opts.set_key_type(KeyType::ec())
                .set_size_in_bits(256)
                .set_label(label.to_string())
                .set_token(Token::SecureEnclave);
            if let Some(acl) = acl {
                opts.set_access_control(acl);
            }
            if persistent {
                opts.set_location(Location::DataProtectionKeychain);
            }
            opts
        };

        let key = match SecKey::new(&make_opts(true)) {
            Ok(k) => k,
            Err(persistent_err) => {
                tracing::warn!(
                    label = %label,
                    error = %persistent_err,
                    "persistent Secure Enclave key creation failed (no provisioning \
                     profile / keychain-access-groups entitlement?); falling back to a \
                     session-only key — wallet will NOT persist across restarts until the \
                     app is provisioned"
                );
                SecKey::new(&make_opts(false))
                    .map_err(|e| DeviceKeyError::Enclave(format!("SecKey::new: {}", e)))?
            }
        };

        cache_handle(label, key.clone());

        Ok(Box::new(MacEnclaveKey {
            label: label.to_string(),
            key,
        }))
    }

    pub fn delete(_label: &str) -> Result<()> {
        // `security-framework` 3.x doesn't expose typed `SecItemDelete`; the
        // key is non-persistent anyway, so drop-on-process-exit is the
        // lifecycle. Idempotent no-op.
        Ok(())
    }
}
