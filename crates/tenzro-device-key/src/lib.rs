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
//! ## Where the key is persisted
//!
//! The Secure-Enclave key is persisted in the legacy file-based (login)
//! keychain via `Location::DefaultFileKeychain`, which sets
//! `kSecAttrIsPermanent=true` *without* the `kSecUseDataProtectionKeychain`
//! attribute. Only the data-protection keychain requires a
//! `keychain-access-groups` entitlement backed by a provisioning profile; the
//! file keychain does not, so a plain Developer-ID build can persist the key
//! and re-`open()` it by label across process restarts. Touch ID / Face ID
//! still gates every signing operation via the key's `SecAccessControl`, and
//! AMFI does not SIGKILL the app. See Apple TN3137 ("On Mac keychains").
//!
//! Cross-restart *persistence of a secret* therefore works: [`SecureEnclaveUnlocker`]
//! creates the key once, wraps the keystore password to its public key, and a
//! later run reopens the key by label to unwrap the on-disk ciphertext. The
//! live `SecKey` handle is additionally cached in-process to avoid repeated
//! keychain queries within a run; in the rare context where file-keychain
//! persistence fails, `create()` falls back to a non-persistent session key
//! that still supports same-session create→sign→wrap/unwrap.

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

mod unlocker;
pub use unlocker::SecureEnclaveUnlocker;

#[cfg(feature = "pq-companion")]
pub mod pq_companion;
#[cfg(feature = "pq-companion")]
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
    use super::{Attestation, DeviceKey, DeviceKeyError, DevicePublicKey, DeviceSignature, Result};
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

    // errSecItemNotFound — returned by SecItemDelete when nothing matches.
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    // The persisted SE key normally round-trips through the file keychain, but
    // we also cache the live `SecKey` handle from `create()`/`open()` here so
    // repeated calls within a session skip the keychain query (and so a
    // same-session create→sign still works even in the rare non-persistent
    // fallback). `SecKey` is `Send + Sync + Clone` (a CFType). Keyed by label.
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

    fn forget_handle(label: &str) {
        if let Ok(mut map) = handles().lock() {
            map.remove(label);
        }
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
            let r_strip = if r.len() == 33 && r[0] == 0 {
                &r[1..]
            } else {
                r
            };
            let s_strip = if s.len() == 33 && s[0] == 0 {
                &s[1..]
            } else {
                s
            };
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
        // Path 1: in-process cache — a fast path within the session that
        // created or last opened the key, avoiding a keychain round-trip.
        if let Some(key) = lookup_handle(label) {
            return Ok(Box::new(MacEnclaveKey {
                label: label.to_string(),
                key,
            }));
        }

        // Path 2: keychain search of the legacy file-based (login) keychain,
        // where `create()` persists the key. We deliberately do NOT call
        // `.ignore_legacy_keychains()` — that flag sets
        // `kSecUseDataProtectionKeychain=true` on the query, which would search
        // the data-protection keychain (empty here) and miss the persisted key.
        // This is the path that enables cross-RESTART open without a
        // provisioning profile.
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::key())
            .label(label)
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
        // Attempt PERSISTENT creation first: `set_location(DefaultFileKeychain)`
        // sets `kSecAttrIsPermanent=true` so the key survives restarts and can
        // be reopened by label, WITHOUT pushing `kSecUseDataProtectionKeychain`.
        // Persisting a Secure-Enclave key in the legacy file-based (login)
        // keychain needs neither a `keychain-access-groups` entitlement nor an
        // embedded provisioning profile — those are required only by the
        // data-protection keychain. Touch ID still gates every signing op via
        // the SecAccessControl below; AMFI does not SIGKILL a Developer-ID build
        // for using the file keychain. See Apple TN3137. If creation still fails
        // (e.g. a sandboxed/headless context), we fall back to a NON-persistent
        // session key cached in-process so dev builds keep working.
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
                opts.set_location(Location::DefaultFileKeychain);
            }
            opts
        };

        let key = match SecKey::new(&make_opts(true)) {
            Ok(k) => k,
            Err(persistent_err) => {
                tracing::warn!(
                    label = %label,
                    error = %persistent_err,
                    "persistent Secure Enclave key creation in the file keychain failed; \
                     falling back to a session-only key — wallet will NOT persist across \
                     restarts in this context"
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

    pub fn delete(label: &str) -> Result<()> {
        // Drop the in-process handle cache so a later `open()` doesn't resurrect
        // a stale reference to a key we're deleting.
        forget_handle(label);

        // Remove the persisted key from the file keychain. As with `open()` we
        // search the legacy keychain (no `.ignore_legacy_keychains()`). Missing
        // the item is fine — deletion is idempotent.
        let mut search = ItemSearchOptions::new();
        search.class(ItemClass::key()).label(label);
        match search.delete() {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(e) => Err(DeviceKeyError::Enclave(format!("SecItemDelete: {}", e))),
        }
    }
}
