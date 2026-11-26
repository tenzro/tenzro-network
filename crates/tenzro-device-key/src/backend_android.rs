//! The Android Keystore backend: a node's P-256 key, its key agreement and
//! its derivation root held by the Keystore, in StrongBox where the device
//! has one and in the trusted environment otherwise.
//!
//! Android has no native Keystore API, so every operation calls the Kotlin
//! class `com.tenzro.keystore.AndroidKeystoreKey` (the
//! `sdk/tenzro-android-node` library) through JNI. The app calls
//! `com.tenzro.keystore.KeystoreBridge.install()` once, on a Java thread,
//! after loading the node's native library: that hands this module the
//! JavaVM and the key class, which a native thread's class loader cannot
//! find on its own.
//!
//! A key the Keystore made in software is refused and deleted: a device with
//! no hardware-backed Keystore is not a root, and is enrolled under another
//! machine of its operator instead.

#[cfg(target_os = "android")]
use crate::{Attestation, DeviceKey, DeviceSignature};
use crate::{DeviceKeyError, DevicePublicKey, Result};
#[cfg(target_os = "android")]
use zeroize::Zeroizing;

/// HPKE `info` for [`DeviceKey::wrap_secret`] on this backend.
#[cfg(target_os = "android")]
const WRAP_INFO: &[u8] = b"tenzro-device-key/backend_android/wrap_secret/v1";

/// The challenge a key is attested over when the Keystore makes it. The
/// Keystore attests a key once, at creation, so the challenge cannot be a
/// verifier's nonce: it binds the attestation to the key's label, and a
/// verifier gets freshness from a signature by the key over its own nonce.
pub(crate) fn attestation_challenge(label: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/device-key/android-keystore/attestation/v1\0");
    h.update(label.as_bytes());
    h.finalize().into()
}

/// Where the Keystore says a key's private half lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecurityLevel {
    Software,
    TrustedEnvironment,
    StrongBox,
}

impl SecurityLevel {
    /// The level from the Kotlin `SecurityLevel` constant's name.
    pub(crate) fn from_name(name: &str) -> Result<Self> {
        match name {
            "SOFTWARE" => Ok(Self::Software),
            "TRUSTED_ENVIRONMENT" => Ok(Self::TrustedEnvironment),
            "STRONGBOX" => Ok(Self::StrongBox),
            other => Err(keystore_err(format!("unknown security level {other:?}"))),
        }
    }

    /// Refuses a key the Keystore holds in software.
    pub(crate) fn require_hardware(self, what: &str) -> Result<Self> {
        match self {
            Self::Software => Err(keystore_err(format!(
                "the Keystore holds the {what} in software on this device, so it cannot be a \
                 hardware root; enrol this device under another machine of its operator"
            ))),
            level => Ok(level),
        }
    }
}

/// `x || y` of the Keystore's `0x04 || x || y` public key.
pub(crate) fn raw_point(sec1: &[u8]) -> Result<DevicePublicKey> {
    if sec1.len() != 65 || sec1[0] != 0x04 {
        return Err(keystore_err(format!(
            "the Keystore returned a {}-byte public key, not an uncompressed P-256 point",
            sec1.len()
        )));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&sec1[1..]);
    Ok(out)
}

/// The attestation evidence of this backend: the certificate chain, leaf
/// first, each certificate as a 4-byte big-endian length and its DER.
pub(crate) fn chain_evidence(chain: &[Vec<u8>]) -> Result<Vec<u8>> {
    if chain.is_empty() {
        return Err(keystore_err(
            "the Keystore holds no attestation chain for the key",
        ));
    }
    let mut out = Vec::with_capacity(chain.iter().map(|c| c.len() + 4).sum());
    for cert in chain {
        let len = u32::try_from(cert.len())
            .map_err(|_| keystore_err("an attestation certificate is over 4 GiB"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(cert);
    }
    Ok(out)
}

fn keystore_err(msg: impl Into<String>) -> DeviceKeyError {
    DeviceKeyError::Enclave(format!("Android Keystore: {}", msg.into()))
}

/// A label names its Keystore aliases (`<label>#p256`, `<label>#hmac`), so
/// it holds no `#`: `x#hmac` would otherwise be another label's alias.
fn check_label(label: &str) -> Result<()> {
    if label.is_empty() || label.len() > 190 || label.contains('#') {
        return Err(keystore_err(
            "a key label is 1 to 190 characters without '#'",
        ));
    }
    Ok(())
}

#[cfg(target_os = "android")]
mod jvm {
    //! The JNI calls into `com.tenzro.keystore.AndroidKeystoreKey`.

    use super::keystore_err;
    use crate::{DeviceKeyError, Result};
    use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JObjectArray, JString, JValue};
    use jni::{JNIEnv, JavaVM};
    use std::sync::OnceLock;

    const KEY_CLASS: &str = "com/tenzro/keystore/AndroidKeystoreKey";
    const KEY_TYPE: &str = "Lcom/tenzro/keystore/AndroidKeystoreKey;";

    struct Bridge {
        vm: JavaVM,
        class: GlobalRef,
    }

    static BRIDGE: OnceLock<Bridge> = OnceLock::new();

    /// Called by `KeystoreBridge.install()` on a Java thread: keeps the VM
    /// and the key class for every later call. Returns false when the class
    /// is not in the app or the bridge could not be kept.
    #[unsafe(no_mangle)]
    pub extern "system" fn Java_com_tenzro_keystore_KeystoreBridge_install(
        mut env: JNIEnv,
        _class: JClass,
    ) -> jni::sys::jboolean {
        let installed = (|| -> std::result::Result<(), jni::errors::Error> {
            if BRIDGE.get().is_some() {
                return Ok(());
            }
            let class = env.find_class(KEY_CLASS)?;
            let class = env.new_global_ref(class)?;
            let vm = env.get_java_vm()?;
            let _ = BRIDGE.set(Bridge { vm, class });
            Ok(())
        })();
        if installed.is_err() {
            let _ = env.exception_clear();
        }
        u8::from(installed.is_ok())
    }

    /// Whether the app installed the bridge.
    pub(crate) fn installed() -> bool {
        BRIDGE.get().is_some()
    }

    fn bridge() -> Result<&'static Bridge> {
        BRIDGE.get().ok_or_else(|| {
            keystore_err(
                "the app has not called com.tenzro.keystore.KeystoreBridge.install(), so the \
                 Keystore cannot be reached",
            )
        })
    }

    /// Runs `f` on this thread's JNI environment; a Java exception becomes
    /// an error carrying its text.
    pub(crate) fn with_env<R>(
        f: impl FnOnce(&mut JNIEnv, &JClass) -> std::result::Result<R, jni::errors::Error>,
    ) -> Result<R> {
        let bridge = bridge()?;
        let mut env = bridge
            .vm
            .attach_current_thread()
            .map_err(|e| keystore_err(format!("attaching this thread to the VM: {e}")))?;
        let class: &JClass = bridge.class.as_obj().into();
        let out = f(&mut env, class);
        out.map_err(|e| java_error(&mut env, e))
    }

    fn java_error(env: &mut JNIEnv, e: jni::errors::Error) -> DeviceKeyError {
        if !matches!(e, jni::errors::Error::JavaException) {
            return keystore_err(e.to_string());
        }
        let text = (|| -> std::result::Result<String, jni::errors::Error> {
            let thrown = env.exception_occurred()?;
            env.exception_clear()?;
            let s = env
                .call_method(&thrown, "toString", "()Ljava/lang/String;", &[])?
                .l()?;
            Ok(env.get_string(&JString::from(s))?.into())
        })();
        let _ = env.exception_clear();
        keystore_err(text.unwrap_or_else(|_| "a Java exception without a readable message".into()))
    }

    pub(crate) fn open(label: &str) -> Result<Option<GlobalRef>> {
        with_env(|env, class| {
            let l = env.new_string(label)?;
            let key = env
                .call_static_method(
                    class,
                    "open",
                    format!("(Ljava/lang/String;){KEY_TYPE}"),
                    &[JValue::Object(&l)],
                )?
                .l()?;
            if key.is_null() {
                Ok(None)
            } else {
                Ok(Some(env.new_global_ref(key)?))
            }
        })
    }

    pub(crate) fn open_or_create(label: &str, challenge: &[u8]) -> Result<GlobalRef> {
        with_env(|env, class| {
            let l = env.new_string(label)?;
            let c = env.byte_array_from_slice(challenge)?;
            let key = env
                .call_static_method(
                    class,
                    "openOrCreate",
                    format!("(Ljava/lang/String;[B){KEY_TYPE}"),
                    &[JValue::Object(&l), JValue::Object(&c)],
                )?
                .l()?;
            env.new_global_ref(key)
        })
    }

    pub(crate) fn delete(label: &str) -> Result<()> {
        with_env(|env, class| {
            let l = env.new_string(label)?;
            env.call_static_method(
                class,
                "delete",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&l)],
            )?;
            Ok(())
        })
    }

    /// A `byte[]` method of `key` with no argument or one `byte[]` argument.
    pub(crate) fn bytes(key: &GlobalRef, method: &str, arg: Option<&[u8]>) -> Result<Vec<u8>> {
        with_env(|env, _| {
            let out = match arg {
                None => env.call_method(key, method, "()[B", &[])?,
                Some(a) => {
                    let a = env.byte_array_from_slice(a)?;
                    env.call_method(key, method, "([B)[B", &[JValue::Object(&a)])?
                }
            }
            .l()?;
            env.convert_byte_array(JByteArray::from(out))
        })
    }

    /// The name of the `SecurityLevel` a level method of `key` returns.
    pub(crate) fn level(key: &GlobalRef, method: &str) -> Result<String> {
        with_env(|env, _| {
            let level = env
                .call_method(key, method, "()Lcom/tenzro/keystore/SecurityLevel;", &[])?
                .l()?;
            let name = env
                .call_method(&level, "name", "()Ljava/lang/String;", &[])?
                .l()?;
            Ok(env.get_string(&JString::from(name))?.into())
        })
    }

    pub(crate) fn chain(key: &GlobalRef) -> Result<Vec<Vec<u8>>> {
        with_env(|env, _| {
            let arr = JObjectArray::from(
                env.call_method(key, "certificateChain", "()[[B", &[])?
                    .l()?,
            );
            let n = env.get_array_length(&arr)?;
            let mut out = Vec::with_capacity(n as usize);
            for i in 0..n {
                let cert: JObject = env.get_object_array_element(&arr, i)?;
                out.push(env.convert_byte_array(JByteArray::from(cert))?);
            }
            Ok(out)
        })
    }
}

/// Whether the app has connected this process to the Keystore.
#[cfg(target_os = "android")]
pub fn available() -> bool {
    jvm::installed()
}

/// One labelled Keystore P-256 key.
#[cfg(target_os = "android")]
pub struct KeystoreKey {
    label: String,
    key: jni::objects::GlobalRef,
}

#[cfg(target_os = "android")]
impl KeystoreKey {
    fn sec1(&self) -> Result<Vec<u8>> {
        jvm::bytes(&self.key, "publicKey", None)
    }

    /// The HMAC-SHA256 of `data` by the label's derivation root, held by the
    /// Keystore; refused when the Keystore holds that root in software.
    pub(crate) fn hmac(&self, data: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        SecurityLevel::from_name(&jvm::level(&self.key, "hmacSecurityLevel")?)?
            .require_hardware("derivation root")?;
        let mac = Zeroizing::new(jvm::bytes(&self.key, "hmac", Some(data))?);
        let out: [u8; 32] = mac
            .as_slice()
            .try_into()
            .map_err(|_| keystore_err(format!("HMAC-SHA256 returned {} bytes", mac.len())))?;
        Ok(Zeroizing::new(out))
    }
}

#[cfg(target_os = "android")]
impl DeviceKey for KeystoreKey {
    fn label(&self) -> &str {
        &self.label
    }

    fn public_key(&self) -> Result<DevicePublicKey> {
        raw_point(&self.sec1()?)
    }

    fn sign_prehash(&self, hash: &[u8; 32]) -> Result<DeviceSignature> {
        let sig = jvm::bytes(&self.key, "signPrehash", Some(hash))?;
        sig.as_slice()
            .try_into()
            .map_err(|_| keystore_err(format!("a {}-byte signature, not r || s", sig.len())))
    }

    fn wrap_secret(&self, secret: &[u8]) -> Result<Vec<u8>> {
        crate::hpke::seal_to_p256(&self.sec1()?, secret, WRAP_INFO)
            .map_err(|e| keystore_err(format!("wrap_secret: {e}")))
    }

    fn unwrap_secret(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        use crate::hpke::OpenError;
        crate::hpke::open_from_p256(ciphertext, &self.sec1()?, WRAP_INFO, |peer| {
            let z = Zeroizing::new(jvm::bytes(&self.key, "agree", Some(peer))?);
            let out: [u8; 32] = z
                .as_slice()
                .try_into()
                .map_err(|_| keystore_err(format!("ECDH returned {} bytes", z.len())))?;
            Ok(Zeroizing::new(out))
        })
        .map_err(|e| match e {
            OpenError::Malformed => keystore_err("unwrap_secret: malformed ciphertext"),
            OpenError::Ecdh(e) => e,
            OpenError::Schedule(e) => keystore_err(format!("unwrap_secret: {e}")),
            OpenError::Tampered => {
                keystore_err("unwrap_secret: AEAD open failed (tampered or wrong key)")
            }
        })
    }

    fn attest(&self) -> Result<Attestation> {
        Ok(Attestation {
            backend: "android-keystore",
            evidence: chain_evidence(&jvm::chain(&self.key)?)?,
            public_key: self.public_key()?,
        })
    }
}

/// Opens the labelled key, refusing one the Keystore holds in software.
#[cfg(target_os = "android")]
pub fn open(label: &str) -> Result<Box<dyn DeviceKey>> {
    check_label(label)?;
    let key = jvm::open(label)?.ok_or_else(|| DeviceKeyError::NotFound(label.to_string()))?;
    SecurityLevel::from_name(&jvm::level(&key, "securityLevel")?)?.require_hardware("key")?;
    Ok(Box::new(KeystoreKey {
        label: label.to_string(),
        key,
    }))
}

/// Makes the labelled key, in StrongBox where the device has one, attested
/// over [`attestation_challenge`]. A key the Keystore could make only in
/// software is deleted and refused.
#[cfg(target_os = "android")]
pub fn create(label: &str) -> Result<Box<dyn DeviceKey>> {
    check_label(label)?;
    let key = jvm::open_or_create(label, &attestation_challenge(label))?;
    let level = SecurityLevel::from_name(&jvm::level(&key, "securityLevel")?)?;
    if let Err(e) = level.require_hardware("key") {
        jvm::delete(label)?;
        return Err(e);
    }
    Ok(Box::new(KeystoreKey {
        label: label.to_string(),
        key,
    }))
}

/// Deletes the labelled key and its derivation root. Idempotent.
#[cfg(target_os = "android")]
pub fn delete(label: &str) -> Result<()> {
    check_label(label)?;
    jvm::delete(label)
}

/// The derivation root's key: the Keystore HMAC key of the hidden root label.
#[cfg(target_os = "android")]
pub(crate) fn root_key() -> Result<KeystoreKey> {
    let label = ROOT_LABEL.to_string();
    let key = jvm::open_or_create(&label, &attestation_challenge(&label))?;
    Ok(KeystoreKey { label, key })
}

/// The label of the key whose HMAC key is this machine's derivation root.
/// It holds a `#`, which [`check_label`] refuses in every other label, so no
/// node key is this one.
#[cfg(target_os = "android")]
const ROOT_LABEL: &str = "#derive-root";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_held_in_software_is_refused_and_hardware_levels_are_kept() {
        assert!(
            SecurityLevel::from_name("SOFTWARE")
                .unwrap()
                .require_hardware("key")
                .is_err()
        );
        assert_eq!(
            SecurityLevel::from_name("STRONGBOX")
                .unwrap()
                .require_hardware("key")
                .unwrap(),
            SecurityLevel::StrongBox
        );
        assert_eq!(
            SecurityLevel::from_name("TRUSTED_ENVIRONMENT")
                .unwrap()
                .require_hardware("key")
                .unwrap(),
            SecurityLevel::TrustedEnvironment
        );
        assert!(SecurityLevel::from_name("UNKNOWN").is_err());
    }

    #[test]
    fn the_public_key_is_the_point_without_its_prefix() {
        let mut sec1 = vec![0x04];
        sec1.extend(1..=64u8);
        let raw = raw_point(&sec1).unwrap();
        assert_eq!(raw[0], 1);
        assert_eq!(raw[63], 64);
        sec1[0] = 0x02;
        assert!(raw_point(&sec1).is_err());
        assert!(raw_point(&sec1[..33]).is_err());
    }

    #[test]
    fn the_evidence_is_the_chain_leaf_first_with_lengths() {
        let ev = chain_evidence(&[vec![0xAA; 3], vec![0xBB; 2]]).unwrap();
        assert_eq!(ev, [0, 0, 0, 3, 0xAA, 0xAA, 0xAA, 0, 0, 0, 2, 0xBB, 0xBB]);
        assert!(chain_evidence(&[]).is_err());
    }

    #[test]
    fn the_attestation_challenge_is_bound_to_the_label() {
        assert_ne!(attestation_challenge("a"), attestation_challenge("b"));
        assert_eq!(attestation_challenge("a"), attestation_challenge("a"));
        assert!(check_label("").is_err());
        assert!(check_label(&"x".repeat(191)).is_err());
        assert!(check_label("x#hmac").is_err());
        assert!(check_label("tenzro/validator/account").is_ok());
    }
}
