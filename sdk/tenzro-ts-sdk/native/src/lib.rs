//! Node.js binding over `tenzro-device-key`.
//!
//! The binding exposes exactly three things about a hardware key: its public
//! key, a signature over a caller-supplied 32-byte digest, and the backend's
//! attestation evidence. There is no call that returns, imports or exports
//! private key material, and no constructor that accepts one: a key object can
//! only come from [`Key::open`], which goes to the TPM (Linux `/dev/tpmrm0`,
//! Windows TBS) or the Apple Secure Enclave. A machine with neither gets an
//! error, never a key held in memory.

use tenzro_device_key::signer::{self, HardwareSigner};
use tenzro_device_key::{Attestation, DeviceKeyError};

/// The refusal a machine without key hardware gets.
pub const NO_HARDWARE: &str = "no TPM 2.0 or Secure Enclave is available on this machine; \
     Tenzro device keys live only in hardware and there is no software fallback";

/// One hardware-resident P-256 key.
pub struct Key {
    signer: Box<dyn HardwareSigner>,
}

/// Attestation evidence as the binding returns it.
#[derive(Debug)]
pub struct KeyAttestation {
    pub backend: String,
    pub evidence: Vec<u8>,
    /// Uncompressed SEC1 (`0x04 || x || y`).
    pub public_key: Vec<u8>,
}

/// The hardware this machine signs with: `"tpm"`, `"secure-enclave"`, or `None`.
pub fn platform_backend() -> Option<&'static str> {
    signer::platform_backend().map(|b| b.as_str())
}

/// Place every key this process opens under `namespace`, as a node with
/// `hardware_key_namespace` does: the key labelled `l` is then `{namespace}/l`
/// and derives under that namespace. A process on a machine that runs more
/// than one node sets the namespace of the node whose keys it uses. Set once,
/// before any key is opened; a second, different namespace is refused.
pub fn set_key_namespace(namespace: &str) -> Result<(), String> {
    tenzro_device_key::set_label_namespace(namespace).map_err(reason)
}

/// The crate's own wording for a TPM that has not been provisioned names the
/// node binary; a package user has the command below instead.
const NODE_PROVISION: &str = "run `tenzro-node tpm provision` once on this machine";
const PACKAGE_PROVISION: &str = "run `npx @tenzro/device-key provision` once on this machine \
     (or `tenzro-node tpm provision` where the Tenzro node is installed)";

fn reason(e: DeviceKeyError) -> String {
    match e {
        DeviceKeyError::AttestationUnsupported => {
            "this key's hardware backend cannot produce attestation evidence".into()
        }
        other => other.to_string().replace(NODE_PROVISION, PACKAGE_PROVISION),
    }
}

/// One-time provisioning of this machine's TPM: creates the persistent storage
/// root, attestation key and identity key every device key hangs from, or finds
/// them already there. Idempotent. Returns one line per slot. A Secure Enclave
/// needs no provisioning, and a machine with no key hardware is refused.
pub fn provision_tpm() -> Result<Vec<String>, String> {
    match signer::platform_backend().map(|b| b.as_str()) {
        None => Err(NO_HARDWARE.into()),
        Some("tpm") => provision_report(),
        Some(_) => Err(
            "this machine's key hardware is the Secure Enclave, which needs no provisioning".into(),
        ),
    }
}

#[cfg(any(target_os = "linux", windows))]
fn provision_report() -> Result<Vec<String>, String> {
    use tenzro_device_key::tpm_provision::{Slot, provision};
    let word = |s: Slot| match s {
        Slot::Present => "already present",
        Slot::Created => "created",
    };
    let r = provision().map_err(reason)?;
    let mut lines = vec![
        format!(
            "storage root      0x{:08x}  {}",
            r.storage_root.0,
            word(r.storage_root.1)
        ),
        format!(
            "attestation key   0x{:08x}  {}",
            r.attestation.0,
            word(r.attestation.1)
        ),
        format!(
            "identity key      0x{:08x}  {}",
            r.identity.0,
            word(r.identity.1)
        ),
    ];
    if let Some(ek) = r.endorsement_key {
        lines.push(format!(
            "endorsement key   0x{:08x}  {} ({})",
            ek.handle,
            word(ek.slot),
            ek.kind
        ));
    } else if r.uncertified_endorsement_key {
        lines.push("endorsement key   present, not certified by the manufacturer".into());
    }
    Ok(lines)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn provision_report() -> Result<Vec<String>, String> {
    Err("TPM provisioning is not available on this platform".into())
}

impl Key {
    /// Open the labelled hardware key, creating it on first use.
    pub fn open(label: &str) -> Result<Self, String> {
        if label.is_empty() {
            return Err("a device key needs a non-empty label".into());
        }
        if signer::platform_backend().is_none() {
            return Err(NO_HARDWARE.into());
        }
        signer::open_or_create(label)
            .map(|signer| Self { signer })
            .map_err(reason)
    }

    /// Wrap a signer the caller already holds. Crate-private: the only
    /// signers the binding's public surface can reach come from [`Key::open`].
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_signer(signer: Box<dyn HardwareSigner>) -> Self {
        Self { signer }
    }

    pub fn backend(&self) -> &'static str {
        self.signer.backend().as_str()
    }

    pub fn label(&self) -> String {
        self.signer.label().to_string()
    }

    /// Uncompressed SEC1 public key (65 bytes).
    pub fn public_key(&self) -> Result<Vec<u8>, String> {
        self.signer
            .public_key_sec1()
            .map(|k| k.to_vec())
            .map_err(reason)
    }

    /// ECDSA-P256 over a 32-byte SHA-256 digest; raw low-S `r || s`.
    pub fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, String> {
        let digest: &[u8; 32] = digest
            .try_into()
            .map_err(|_| format!("expected a 32-byte digest, got {} bytes", digest.len()))?;
        self.signer
            .sign_prehash(digest)
            .map(|s| s.to_vec())
            .map_err(reason)
    }

    /// The backend's attestation evidence over this key.
    pub fn attest(&self) -> Result<KeyAttestation, String> {
        let Attestation {
            backend,
            evidence,
            public_key,
        } = self.signer.attest().map_err(reason)?;
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&public_key);
        Ok(KeyAttestation {
            backend: backend.to_string(),
            evidence,
            public_key: sec1,
        })
    }
}

#[cfg(feature = "node")]
mod node {
    use std::sync::Arc;

    use napi::bindgen_prelude::*;
    use napi_derive::napi;

    /// `"tpm"`, `"secure-enclave"`, or `null` when this machine has neither.
    #[napi(js_name = "platformBackend")]
    #[cfg_attr(test, allow(dead_code))]
    pub fn platform_backend() -> Option<String> {
        super::platform_backend().map(str::to_string)
    }

    /// Provision this machine's TPM (idempotent); one line per slot.
    #[napi(js_name = "provisionTpm")]
    #[cfg_attr(test, allow(dead_code))]
    pub fn provision_tpm() -> Result<Vec<String>> {
        super::provision_tpm().map_err(Error::from_reason)
    }

    #[napi(object)]
    pub struct Attestation {
        pub backend: String,
        pub evidence: Buffer,
        pub public_key: Buffer,
    }

    /// A P-256 key held by this machine's TPM or Secure Enclave.
    #[napi]
    pub struct DeviceKey {
        inner: Arc<super::Key>,
    }

    #[napi]
    impl DeviceKey {
        /// Open the labelled key, creating it on first use. Throws when the
        /// machine has no TPM or Secure Enclave.
        #[napi(factory)]
        pub fn open(label: String) -> Result<Self> {
            super::Key::open(&label)
                .map(|k| Self { inner: Arc::new(k) })
                .map_err(Error::from_reason)
        }

        #[napi(getter)]
        pub fn backend(&self) -> String {
            self.inner.backend().to_string()
        }

        #[napi(getter)]
        pub fn label(&self) -> String {
            self.inner.label()
        }

        /// Uncompressed SEC1 public key (65 bytes).
        #[napi]
        pub fn public_key(&self) -> Result<Buffer> {
            self.inner
                .public_key()
                .map(Buffer::from)
                .map_err(Error::from_reason)
        }

        /// Sign a 32-byte digest off the event loop (a Secure Enclave key may
        /// wait on user presence). Resolves to raw `r || s` (64 bytes).
        #[napi(ts_return_type = "Promise<Buffer>")]
        pub fn sign_digest(&self, digest: Buffer) -> AsyncTask<SignTask> {
            AsyncTask::new(SignTask {
                key: self.inner.clone(),
                digest: digest.to_vec(),
            })
        }

        /// The backend's attestation evidence over this key.
        #[napi(ts_return_type = "Promise<Attestation>")]
        pub fn attest(&self) -> AsyncTask<AttestTask> {
            AsyncTask::new(AttestTask {
                key: self.inner.clone(),
            })
        }
    }

    pub struct SignTask {
        key: Arc<super::Key>,
        digest: Vec<u8>,
    }

    impl Task for SignTask {
        type Output = Vec<u8>;
        type JsValue = Buffer;
        fn compute(&mut self) -> Result<Vec<u8>> {
            self.key
                .sign_digest(&self.digest)
                .map_err(Error::from_reason)
        }
        fn resolve(&mut self, _env: Env, out: Vec<u8>) -> Result<Buffer> {
            Ok(out.into())
        }
    }

    pub struct AttestTask {
        key: Arc<super::Key>,
    }

    impl Task for AttestTask {
        type Output = super::KeyAttestation;
        type JsValue = Attestation;
        fn compute(&mut self) -> Result<super::KeyAttestation> {
            self.key.attest().map_err(Error::from_reason)
        }
        fn resolve(&mut self, _env: Env, a: super::KeyAttestation) -> Result<Attestation> {
            Ok(Attestation {
                backend: a.backend,
                evidence: a.evidence.into(),
                public_key: a.public_key.into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use tenzro_device_key::DeviceSignature;
    use tenzro_device_key::signer::{HardwareBackend, verify_p256_prehash};

    /// Stands in for the hardware behind the `HardwareSigner` seam. Test-only:
    /// nothing outside `cfg(test)` can build a `Key` from it.
    struct MockHardware {
        key: SigningKey,
        attests: bool,
    }

    impl HardwareSigner for MockHardware {
        fn backend(&self) -> HardwareBackend {
            HardwareBackend::Tpm
        }
        fn label(&self) -> &str {
            "mock"
        }
        fn public_key_sec1(&self) -> tenzro_device_key::Result<[u8; 65]> {
            let mut out = [0u8; 65];
            out.copy_from_slice(self.key.verifying_key().to_sec1_point(false).as_bytes());
            Ok(out)
        }
        fn sign_prehash(&self, digest: &[u8; 32]) -> tenzro_device_key::Result<DeviceSignature> {
            let sig: p256::ecdsa::Signature = self.key.sign_prehash(digest).unwrap();
            let sig = sig.normalize_s();
            Ok(sig.to_bytes().into())
        }
        fn attest(&self) -> tenzro_device_key::Result<Attestation> {
            if !self.attests {
                return Err(DeviceKeyError::AttestationUnsupported);
            }
            let sec1 = self.public_key_sec1()?;
            let mut raw = [0u8; 64];
            raw.copy_from_slice(&sec1[1..]);
            Ok(Attestation {
                backend: "tpm",
                evidence: b"quote".to_vec(),
                public_key: raw,
            })
        }
    }

    #[test]
    fn the_unprovisioned_error_names_the_package_command() {
        let e = DeviceKeyError::Tpm(
            "the TPM storage root is missing; run `tenzro-node tpm provision` once on this machine to create its persistent TPM keys".into(),
        );
        let text = reason(e);
        assert!(text.contains("npx @tenzro/device-key provision"));
        assert!(text.contains("where the Tenzro node is installed"));
    }

    #[test]
    fn provisioning_without_hardware_refuses() {
        // Never provision a TPM from a test: with hardware present this does nothing.
        if signer::platform_backend().is_some() {
            return;
        }
        assert_eq!(provision_tpm().unwrap_err(), NO_HARDWARE);
    }

    fn key(attests: bool) -> Key {
        Key::from_signer(Box::new(MockHardware {
            key: SigningKey::from_slice(&[7u8; 32]).unwrap(),
            attests,
        }))
    }

    #[test]
    fn signs_a_digest_that_verifies_under_the_public_key() {
        let k = key(false);
        let pk = k.public_key().unwrap();
        assert_eq!(pk.len(), 65);
        assert_eq!(pk[0], 0x04);
        let digest = [0x42u8; 32];
        let sig = k.sign_digest(&digest).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verify_p256_prehash(&pk, &digest, &sig));
        assert!(!verify_p256_prehash(&pk, &[0x43u8; 32], &sig));
    }

    #[test]
    fn refuses_a_digest_that_is_not_32_bytes() {
        let k = key(false);
        for len in [0usize, 31, 33, 64] {
            let err = k.sign_digest(&vec![1u8; len]).unwrap_err();
            assert!(err.contains("32-byte digest"), "{err}");
        }
    }

    #[test]
    fn attestation_carries_the_sec1_public_key() {
        let k = key(true);
        let a = k.attest().unwrap();
        assert_eq!(a.backend, "tpm");
        assert_eq!(a.evidence, b"quote");
        assert_eq!(a.public_key, k.public_key().unwrap());
    }

    #[test]
    fn a_backend_without_attestation_says_so() {
        let err = key(false).attest().unwrap_err();
        assert!(err.contains("cannot produce attestation"), "{err}");
    }

    #[test]
    fn open_refuses_an_empty_label() {
        assert!(Key::open("").is_err());
    }

    #[test]
    fn open_without_hardware_refuses_with_no_fallback() {
        if platform_backend().is_some() {
            return;
        }
        let err = Key::open("tenzro-test").err().expect("must refuse");
        assert_eq!(err, NO_HARDWARE);
    }
}
