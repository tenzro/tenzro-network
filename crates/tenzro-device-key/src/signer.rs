//! The hardware signer: one interface for every key Tenzro holds on a machine.
//!
//! # The rule this module enforces
//!
//! A private key exists in exactly one of three places: a TPM 2.0, an Apple
//! Secure Enclave, or a person's passkey authenticator. It is created there,
//! used there, and never leaves. There is no software implementation of
//! [`HardwareSigner`] and no constructor that accepts key bytes, so code
//! written against this trait cannot fall back to a key in a file, an
//! environment variable or a configuration field.
//!
//! A trusted execution environment is not one of the three. A TEE proves what
//! code ran; it does not hold a key its operator or its image cannot
//! reproduce. Nothing here derives a key from a TEE measurement.
//!
//! # What the hardware can hold
//!
//! TPM 2.0 and the Secure Enclave both sign with ECDSA over NIST P-256 and
//! nothing else in common, so every [`HardwareSigner`] is P-256/SHA-256. A
//! TPM that implements NIST P-384 also holds the ECDSA leg of ML-DSA-87 /
//! ECDSA-P384 keys ([`HardwareP384Signer`]); the Secure Enclave does not.
//! A TPM implementing TPM 2.0 library v1.85 holds ML-DSA keys
//! ([`HardwareMlDsaSigner`]). On any other hardware an account's ML-DSA-65
//! key is derived from the machine's hardware-held derivation root
//! ([`DerivedMlDsaSigner`]): the seed exists only for one operation and is
//! never stored, as for the consensus key.
//! Protocols that need a key on another curve cannot put it in hardware. For
//! EVM chains the answer is a P-256 smart account (the P-256 verification
//! precompile), not a secp256k1 key held in software.
//!
//! # Passkey-authorised operations
//!
//! Some operations must only happen when a person approved them: binding a
//! device to their identity, unbinding one, moving a machine to a new owner.
//! A [`PasskeyAuthorization`] is a WebAuthn assertion whose challenge is the
//! digest of the exact operation. [`verify_authorization`] checks it against
//! the person's enrolled passkey public key on the relying party it was
//! registered under, with user verification required and synced
//! (backup-eligible) credentials refused.
//!
//! # Usage
//!
//! ```ignore
//! let signer = tenzro_device_key::signer::open_or_create("tenzro/node/identity")?;
//! let sig = signer.sign(b"message")?;
//! assert!(tenzro_device_key::signer::verify_p256(&signer.public_key_sec1()?, b"message", &sig));
//! ```

use sha2::{Digest, Sha256, Sha384};
use tenzro_types::signature_scheme::SignatureScheme;

use crate::{DeviceKey, DeviceKeyError, DeviceSignature, Result};

/// Which hardware holds a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareBackend {
    /// TPM 2.0 (Linux `/dev/tpmrm0`, Windows TBS). Can quote.
    Tpm,
    /// Apple Secure Enclave through CryptoKit. Cannot quote.
    SecureEnclave,
    /// A TPM 2.0 in another machine the operator owns, reached through a
    /// provider (see [`crate::remote`]). The key never leaves that TPM.
    RemoteTpm,
}

impl HardwareBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tpm => "tpm",
            Self::SecureEnclave => "secure-enclave",
            Self::RemoteTpm => "remote-tpm",
        }
    }
}

/// A P-256 signing key that lives in hardware.
pub trait HardwareSigner: Send + Sync {
    /// The hardware this key lives in.
    fn backend(&self) -> HardwareBackend;

    /// The label the key was opened under. Two labels are two unrelated keys.
    fn label(&self) -> &str;

    /// Uncompressed SEC1 public key (`0x04 || x || y`, 65 bytes).
    fn public_key_sec1(&self) -> Result<[u8; 65]>;

    /// ECDSA-P256 over SHA-256(`message`), raw `r || s`.
    fn sign(&self, message: &[u8]) -> Result<DeviceSignature> {
        let digest: [u8; 32] = Sha256::digest(message).into();
        self.sign_prehash(&digest)
    }

    /// ECDSA-P256 over a caller-computed SHA-256 digest, raw `r || s`.
    fn sign_prehash(&self, digest: &[u8; 32]) -> Result<DeviceSignature>;

    /// Hardware attestation over this key's public key, in the backend's
    /// own evidence format. Backends that cannot attest return
    /// [`DeviceKeyError::AttestationUnsupported`].
    fn attest(&self) -> Result<crate::Attestation> {
        Err(DeviceKeyError::AttestationUnsupported)
    }
}

struct DeviceKeySigner {
    key: Box<dyn DeviceKey>,
    backend: HardwareBackend,
}

impl HardwareSigner for DeviceKeySigner {
    fn backend(&self) -> HardwareBackend {
        self.backend
    }
    fn label(&self) -> &str {
        self.key.label()
    }
    fn public_key_sec1(&self) -> Result<[u8; 65]> {
        let raw = self.key.public_key()?;
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..].copy_from_slice(&raw);
        Ok(out)
    }
    fn sign_prehash(&self, digest: &[u8; 32]) -> Result<DeviceSignature> {
        self.key.sign_prehash(digest)
    }
    fn attest(&self) -> Result<crate::Attestation> {
        self.key.attest()
    }
}

/// The hardware this platform signs with, if any.
pub fn platform_backend() -> Option<HardwareBackend> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        crate::backend_se::available().then_some(HardwareBackend::SecureEnclave)
    }
    #[cfg(any(target_os = "linux", windows))]
    {
        crate::backend_tpm::available().then_some(HardwareBackend::Tpm)
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux", windows)))]
    {
        None
    }
}

type SignerFactory = Box<dyn Fn(&str) -> Result<Box<dyn HardwareSigner>> + Send + Sync>;

static REMOTE_SIGNERS: std::sync::OnceLock<SignerFactory> = std::sync::OnceLock::new();

/// Makes every [`open_or_create`] in this process open the labelled key in
/// another machine's TPM through `factory`. Set once, before any key use.
pub fn use_remote_signers(factory: SignerFactory) -> Result<()> {
    REMOTE_SIGNERS
        .set(factory)
        .map_err(|_| DeviceKeyError::Tpm("the remote signers are already set".into()))
}

/// Open the labelled hardware key, creating it on first use.
///
/// Fails when this machine has no TPM or Secure Enclave. There is no software
/// fallback: a caller that cannot get a hardware key must refuse the
/// operation that needed one.
pub fn open_or_create(label: &str) -> Result<Box<dyn HardwareSigner>> {
    if let Some(factory) = REMOTE_SIGNERS.get() {
        return factory(label);
    }
    let backend = platform_backend().ok_or_else(|| {
        DeviceKeyError::Enclave(
            "this machine has no TPM 2.0 or Secure Enclave, so it cannot hold a key".into(),
        )
    })?;
    let key = match crate::open(label) {
        Ok(k) => k,
        Err(DeviceKeyError::NotFound(_)) => crate::create(label)?,
        Err(e) => return Err(e),
    };
    Ok(Box::new(DeviceKeySigner { key, backend }))
}

/// Verify ECDSA-P256 over SHA-256(`message`) against an uncompressed SEC1
/// public key. Accepts only low-S signatures, so a signature has exactly one
/// valid encoding.
pub fn verify_p256(public_key_sec1: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let digest: [u8; 32] = Sha256::digest(message).into();
    verify_p256_prehash(public_key_sec1, &digest, signature)
}

/// [`verify_p256`] over a caller-computed digest.
///
/// Hardware returns high-S signatures about half the time; the signature is
/// normalized before the check so the same key verifies consistently, while
/// the encoding a caller stores is the one it received.
pub fn verify_p256_prehash(public_key_sec1: &[u8], digest: &[u8; 32], signature: &[u8]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key_sec1) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(signature) else {
        return false;
    };
    let sig = sig.normalize_s();
    vk.verify_prehash(digest, &sig).is_ok()
}

// --- ECDSA P-384 keys. -------------------------------------------------------

/// An ECDSA P-384 signing key that lives in hardware: the classical leg of
/// the ML-DSA-87 / ECDSA-P384 composite.
pub trait HardwareP384Signer: Send + Sync {
    fn backend(&self) -> HardwareBackend;
    fn label(&self) -> &str;
    /// Uncompressed SEC1 public key (`0x04 || x || y`, 97 bytes).
    fn public_key_sec1(&self) -> Result<[u8; 97]>;
    /// ECDSA-P384 over SHA-384(`message`), raw `r || s`.
    fn sign(&self, message: &[u8]) -> Result<[u8; 96]> {
        let digest: [u8; 48] = Sha384::digest(message).into();
        self.sign_prehash(&digest)
    }
    /// ECDSA-P384 over a caller-computed SHA-384 digest, raw `r || s`.
    fn sign_prehash(&self, digest: &[u8; 48]) -> Result<[u8; 96]>;
}

/// Open the labelled P-384 key in this machine's TPM, creating it there on
/// first use. Refuses on hardware that does not implement NIST P-384 with
/// SHA-384: the Secure Enclave does not, nor do TPMs with P-256 alone.
/// There is no software stand-in.
pub fn open_or_create_p384(label: &str) -> Result<Box<dyn HardwareP384Signer>> {
    let refuse = |why: String| {
        DeviceKeyError::Enclave(format!(
            "cannot hold the P-384 key '{label}' in hardware: {why}"
        ))
    };
    #[cfg(any(target_os = "linux", windows))]
    {
        use crate::backend_tpm::{ChildKind, TpmChildKey};
        let key = TpmChildKey::open_or_create(label, ChildKind::P384Signing)
            .map_err(|e| refuse(e.to_string()))?;
        Ok(Box::new(TpmP384Signer(key)))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err(refuse(
            "this machine's hardware does not implement NIST P-384".into(),
        ))
    }
}

#[cfg(any(target_os = "linux", windows))]
struct TpmP384Signer(crate::backend_tpm::TpmChildKey);

#[cfg(any(target_os = "linux", windows))]
impl HardwareP384Signer for TpmP384Signer {
    fn backend(&self) -> HardwareBackend {
        HardwareBackend::Tpm
    }
    fn label(&self) -> &str {
        self.0.label()
    }
    fn public_key_sec1(&self) -> Result<[u8; 97]> {
        self.0.p384_sec1()
    }
    fn sign_prehash(&self, digest: &[u8; 48]) -> Result<[u8; 96]> {
        self.0.sign_p384_prehash(digest)
    }
}

/// Verify ECDSA-P384 over SHA-384(`message`) against an uncompressed SEC1
/// public key.
pub fn verify_p384(public_key_sec1: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let digest: [u8; 48] = Sha384::digest(message).into();
    verify_p384_prehash(public_key_sec1, &digest, signature)
}

/// [`verify_p384`] over a caller-computed digest. The signature is
/// normalized to low S before the check, as [`verify_p256_prehash`] does.
pub fn verify_p384_prehash(public_key_sec1: &[u8], digest: &[u8; 48], signature: &[u8]) -> bool {
    use p384::ecdsa::signature::hazmat::PrehashVerifier;
    let Ok(vk) = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key_sec1) else {
        return false;
    };
    let Ok(sig) = p384::ecdsa::Signature::from_slice(signature) else {
        return false;
    };
    let sig = sig.normalize_s();
    vk.verify_prehash(digest, &sig).is_ok()
}

// --- Post-quantum keys. ------------------------------------------------------

/// Where this machine could hold an ML-DSA key, and why not if it cannot.
///
/// A consensus key is held only in hardware. ML-DSA-65 is available in the
/// Apple Secure Enclave from macOS / iOS 26 and in TPMs implementing TPM 2.0
/// library v1.85; on anything else there is no ML-DSA key to be had, and the
/// caller must refuse rather than hold one in software.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlDsaSupport {
    /// The hardware implements ML-DSA.
    Hardware(HardwareBackend),
    /// It does not; the reason names what is missing.
    Unavailable(String),
}

/// Probe this machine's hardware for ML-DSA.
pub fn ml_dsa_support() -> MlDsaSupport {
    #[cfg(any(target_os = "linux", windows))]
    {
        match crate::backend_tpm::TpmDevice::open()
            .and_then(|mut d| d.supports_algorithm(crate::tpm_wire::TPM2_ALG_MLDSA))
        {
            Ok(true) => MlDsaSupport::Hardware(HardwareBackend::Tpm),
            Ok(false) => MlDsaSupport::Unavailable(
                "this TPM does not implement ML-DSA (TPM 2.0 library v1.85 or later is required)"
                    .into(),
            ),
            Err(e) => MlDsaSupport::Unavailable(format!("no usable TPM: {e}")),
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        MlDsaSupport::Unavailable(
            "ML-DSA key creation in this machine's hardware is not supported by this build".into(),
        )
    }
}

/// An ML-DSA (FIPS 204) signing key created inside and held by hardware:
/// the ML-DSA leg of a [`SignatureScheme`].
///
/// This is the post-quantum counterpart of [`HardwareSigner`], and the only
/// form in which a post-quantum consensus key may exist.
pub trait HardwareMlDsaSigner: Send + Sync {
    fn backend(&self) -> HardwareBackend;
    fn label(&self) -> &str;
    /// The scheme whose ML-DSA leg this key is.
    fn scheme(&self) -> SignatureScheme;
    /// The bare verifying key of the scheme's parameter set (1952 bytes for
    /// ML-DSA-65, 2592 for ML-DSA-87).
    fn verifying_key(&self) -> Result<Vec<u8>>;
    /// A bare ML-DSA signature over `message` with the FIPS 204 context
    /// `ctx`.
    fn sign(&self, ctx: &[u8], message: &[u8]) -> Result<Vec<u8>>;
}

fn ml_dsa_name(scheme: SignatureScheme) -> &'static str {
    match scheme {
        SignatureScheme::MlDsa65P256 => "ML-DSA-65",
        SignatureScheme::MlDsa87P384 => "ML-DSA-87",
    }
}

/// Open the labelled ML-DSA key of `scheme`'s parameter set in this
/// machine's hardware, creating it there on first use.
///
/// On a TPM implementing ML-DSA the key is generated by the TPM and signs
/// through `TPM2_SignSequenceStart` / `TPM2_SignSequenceComplete`. Hardware
/// without ML-DSA is refused, with the reason; so is a Secure Enclave, whose
/// ML-DSA this build does not drive. There is no software or sealed
/// stand-in.
pub fn open_or_create_ml_dsa(
    label: &str,
    scheme: SignatureScheme,
) -> Result<Box<dyn HardwareMlDsaSigner>> {
    let refuse = |why: String| {
        DeviceKeyError::Enclave(format!(
            "cannot hold the {} key '{label}' in hardware: {why}. Post-quantum keys are held \
             only in hardware, so it is refused",
            ml_dsa_name(scheme)
        ))
    };
    match ml_dsa_support() {
        MlDsaSupport::Hardware(HardwareBackend::Tpm) => {}
        MlDsaSupport::Hardware(backend) => {
            return Err(refuse(format!(
                "{} implements ML-DSA, but driving it is not implemented in this build",
                backend.as_str()
            )));
        }
        MlDsaSupport::Unavailable(why) => return Err(refuse(why)),
    }
    #[cfg(any(target_os = "linux", windows))]
    {
        use crate::backend_tpm::{ChildKind, TpmChildKey};
        let set = match scheme {
            SignatureScheme::MlDsa65P256 => crate::tpm_wire::TPM2_MLDSA_65,
            SignatureScheme::MlDsa87P384 => crate::tpm_wire::TPM2_MLDSA_87,
        };
        let key = TpmChildKey::open_or_create(label, ChildKind::MlDsa(set))
            .map_err(|e| refuse(e.to_string()))?;
        let signer = TpmMlDsaSigner { key, scheme };
        signer.verifying_key().map_err(|e| refuse(e.to_string()))?;
        Ok(Box::new(signer))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err(refuse("this build drives ML-DSA only in a TPM".into()))
    }
}

#[cfg(any(target_os = "linux", windows))]
struct TpmMlDsaSigner {
    key: crate::backend_tpm::TpmChildKey,
    scheme: SignatureScheme,
}

#[cfg(any(target_os = "linux", windows))]
impl HardwareMlDsaSigner for TpmMlDsaSigner {
    fn backend(&self) -> HardwareBackend {
        HardwareBackend::Tpm
    }
    fn label(&self) -> &str {
        self.key.label()
    }
    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
    fn verifying_key(&self) -> Result<Vec<u8>> {
        let vk = self.key.ml_dsa_public()?;
        if vk.len() != self.scheme.ml_dsa_public_key_len() {
            return Err(DeviceKeyError::Enclave(format!(
                "the TPM returned a {}-byte {} key",
                vk.len(),
                ml_dsa_name(self.scheme)
            )));
        }
        Ok(vk)
    }
    fn sign(&self, ctx: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let sig = self.key.ml_dsa_sign(ctx, message)?;
        if sig.len() != self.scheme.ml_dsa_signature_len() {
            return Err(DeviceKeyError::Enclave(format!(
                "the TPM returned a {}-byte {} signature",
                sig.len(),
                ml_dsa_name(self.scheme)
            )));
        }
        Ok(sig)
    }
}

/// An account's ML-DSA-65 key on hardware that cannot hold one: its seed is
/// derived from the machine's hardware-held derivation root (the TPM, the
/// Secure Enclave, or the TPM of the machine this one delegates to) for each
/// operation and wiped after it. Nothing is stored, so the same machine
/// always derives the same key, and without the hardware there is no key.
pub struct DerivedMlDsaSigner {
    root: crate::derive::DerivationRoot,
    label: String,
}

impl DerivedMlDsaSigner {
    /// The key `label` of this machine's derivation root. Refuses when the
    /// machine has no root.
    pub fn open(label: &str) -> Result<Self> {
        Ok(Self::on_root(
            crate::derive::DerivationRoot::open_or_create()?,
            label,
        ))
    }

    fn on_root(root: crate::derive::DerivationRoot, label: &str) -> Self {
        Self {
            root,
            label: label.to_string(),
        }
    }
}

impl HardwareMlDsaSigner for DerivedMlDsaSigner {
    fn backend(&self) -> HardwareBackend {
        match self.root.backend() {
            crate::derive::DeriveBackend::SecureEnclave => HardwareBackend::SecureEnclave,
            crate::derive::DeriveBackend::RemoteTpm => HardwareBackend::RemoteTpm,
            _ => HardwareBackend::Tpm,
        }
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::MlDsa65P256
    }

    fn verifying_key(&self) -> Result<Vec<u8>> {
        self.root.ml_dsa65_public(&self.label)
    }

    fn sign(&self, ctx: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        self.root
            .ml_dsa65_sign(&self.label, crate::derive::intern_context(ctx)?, message)
    }
}

// --- Account signing: P-256 leg plus the ML-DSA-65 leg. -------------------

/// An account, guardian or machine-identity signer held entirely in this
/// machine's hardware: the P-256 key, and the ML-DSA-65 key either inside the
/// hardware (where it implements ML-DSA) or derived from its derivation root.
/// There is no software path.
pub struct HardwareHybridSigner {
    p256: Box<dyn HardwareSigner>,
    ml_dsa: Option<Box<dyn HardwareMlDsaSigner>>,
    public: tenzro_crypto::CompositePublicKey,
}

impl HardwareHybridSigner {
    /// Opens (or creates) the P-256 key `label` and the ML-DSA-65 key
    /// `label`/ml-dsa-65: inside the hardware where it implements ML-DSA,
    /// otherwise derived from the machine's derivation root. A machine whose
    /// hardware implements ML-DSA but cannot drive it is refused rather than
    /// downgraded. A machine with no derivation root signs with P-256 alone.
    pub fn open_or_create(label: &str) -> Result<Self> {
        let p256 = open_or_create(label)?;
        let pq_label = format!("{label}/ml-dsa-65");
        let ml_dsa: Option<Box<dyn HardwareMlDsaSigner>> = match ml_dsa_support() {
            MlDsaSupport::Hardware(_) => Some(open_or_create_ml_dsa(
                &pq_label,
                SignatureScheme::MlDsa65P256,
            )?),
            MlDsaSupport::Unavailable(_) => match DerivedMlDsaSigner::open(&pq_label) {
                Ok(derived) => Some(Box::new(derived)),
                Err(e) => {
                    tracing::warn!(error = %e, "no derivation root for an ML-DSA-65 account key; signing with P-256 alone");
                    None
                }
            },
        };
        Self::from_parts(p256, ml_dsa)
    }

    /// Wraps signers that are already open.
    pub fn from_parts(
        p256: Box<dyn HardwareSigner>,
        ml_dsa: Option<Box<dyn HardwareMlDsaSigner>>,
    ) -> Result<Self> {
        // An account's classical leg is P-256, so its ML-DSA leg is ML-DSA-65.
        if ml_dsa
            .as_ref()
            .is_some_and(|k| k.scheme() != SignatureScheme::MlDsa65P256)
        {
            return Err(DeviceKeyError::Enclave(
                "an account's ML-DSA key is ML-DSA-65".into(),
            ));
        }
        let sec1 = p256.public_key_sec1()?;
        let pq = ml_dsa.as_ref().map(|k| k.verifying_key()).transpose()?;
        let public = tenzro_crypto::CompositePublicKey::new(sec1[1..].to_vec(), pq)
            .map_err(|e| DeviceKeyError::Enclave(e.to_string()))?;
        Ok(Self {
            p256,
            ml_dsa,
            public,
        })
    }

    /// Whether this signer carries the ML-DSA-65 leg.
    pub fn has_ml_dsa(&self) -> bool {
        self.ml_dsa.is_some()
    }
}

impl tenzro_crypto::HybridSigner for HardwareHybridSigner {
    fn sign(
        &self,
        context: tenzro_crypto::SignatureContext,
        msg: &[u8],
    ) -> tenzro_crypto::Result<tenzro_crypto::CompositeSignature> {
        use tenzro_crypto::composite::{LABEL_MLDSA65_P256, message_representative};
        let hw = |e: DeviceKeyError| {
            tenzro_crypto::CryptoError::Other(format!("hardware signing failed: {e}"))
        };
        // The hardware signs the message, not a digest of it: a remote TPM
        // can then check what it is asked to sign, and a local one hashes
        // the same bytes (`sign` is SHA-256 then `sign_prehash`).
        let rs = self
            .p256
            .sign(&message_representative(context, msg))
            .map_err(hw)?;
        let classical = tenzro_crypto::ClassicalProof::Raw {
            signature: rs.to_vec(),
        };
        Ok(match &self.ml_dsa {
            Some(k) => tenzro_crypto::CompositeSignature::hybrid(
                classical,
                k.sign(LABEL_MLDSA65_P256, &message_representative(context, msg))
                    .map_err(hw)?,
            ),
            None => tenzro_crypto::CompositeSignature::classical(classical),
        })
    }

    fn public_key(&self) -> &tenzro_crypto::CompositePublicKey {
        &self.public
    }

    fn sign_external(&self, data: &[u8]) -> tenzro_crypto::Result<Vec<u8>> {
        tenzro_crypto::composite::check_external_input(data)?;
        let rs = self.p256.sign(data).map_err(|e| {
            tenzro_crypto::CryptoError::Other(format!("hardware signing failed: {e}"))
        })?;
        Ok(rs.to_vec())
    }
}

// --- Passkey-authorised operations. ----------------------------------------

/// Authenticator-data flag: user present.
pub const FLAG_UP: u8 = 0x01;
/// Authenticator-data flag: user verified (PIN or biometric).
pub const FLAG_UV: u8 = 0x04;
/// Authenticator-data flag: backup eligible (a synced credential).
pub const FLAG_BE: u8 = 0x08;
/// Authenticator-data flag: backed up.
pub const FLAG_BS: u8 = 0x10;

/// A WebAuthn assertion approving one operation.
#[derive(Clone, Debug)]
pub struct PasskeyAuthorization {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    /// Raw `r || s` or DER ECDSA signature.
    pub signature: Vec<u8>,
}

/// What an assertion must be checked against.
#[derive(Clone, Debug)]
pub struct PasskeyController {
    /// The enrolled passkey's uncompressed SEC1 P-256 public key.
    pub public_key_sec1: Vec<u8>,
    /// The relying-party id the passkey was registered under.
    pub rp_id: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("authenticator data is malformed")]
    MalformedAuthenticatorData,
    #[error("client data is malformed")]
    MalformedClientData,
    #[error("client data type is not webauthn.get")]
    WrongType,
    #[error("assertion was made in a cross-origin frame")]
    CrossOrigin,
    #[error("assertion was made by a page on another origin than the relying party's")]
    WrongOrigin,
    #[error("assertion answers a different challenge")]
    WrongChallenge,
    #[error("assertion is for a different relying party")]
    WrongRelyingParty,
    #[error("user verification was not performed")]
    NotUserVerified,
    #[error("the credential is synced (backup eligible), not bound to one device")]
    SyncedCredential,
    #[error("assertion signature does not verify against the enrolled passkey")]
    BadSignature,
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .ok()
}

/// Verify that `authz` is the enrolled passkey approving exactly
/// `challenge`, with user verification, from a device-bound credential, on
/// the relying party's own origin `https://<rp_id>`. Any page whose domain
/// sits under the RP ID can ask for an assertion with a matching rpIdHash, so
/// the origin is what tells the relying party's page from the others.
pub fn verify_authorization(
    controller: &PasskeyController,
    challenge: &[u8; 32],
    authz: &PasskeyAuthorization,
) -> std::result::Result<(), AuthorizationError> {
    let ad = &authz.authenticator_data;
    if ad.len() < 37 {
        return Err(AuthorizationError::MalformedAuthenticatorData);
    }
    let rp_hash: [u8; 32] = Sha256::digest(controller.rp_id.as_bytes()).into();
    if ad[..32] != rp_hash {
        return Err(AuthorizationError::WrongRelyingParty);
    }
    let flags = ad[32];
    if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 {
        return Err(AuthorizationError::NotUserVerified);
    }
    if flags & (FLAG_BE | FLAG_BS) != 0 {
        return Err(AuthorizationError::SyncedCredential);
    }

    let client: serde_json::Value = serde_json::from_slice(&authz.client_data_json)
        .map_err(|_| AuthorizationError::MalformedClientData)?;
    if client.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err(AuthorizationError::WrongType);
    }
    if client.get("crossOrigin").and_then(|v| v.as_bool()) == Some(true) {
        return Err(AuthorizationError::CrossOrigin);
    }
    let origin = client
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or(AuthorizationError::MalformedClientData)?;
    if origin != format!("https://{}", controller.rp_id) {
        return Err(AuthorizationError::WrongOrigin);
    }
    let presented = client
        .get("challenge")
        .and_then(|v| v.as_str())
        .and_then(b64url_decode)
        .ok_or(AuthorizationError::MalformedClientData)?;
    if presented.as_slice() != challenge.as_slice() {
        return Err(AuthorizationError::WrongChallenge);
    }

    let mut signed = ad.clone();
    signed.extend_from_slice(&Sha256::digest(&authz.client_data_json));
    let sig = if authz.signature.len() == 64 {
        p256::ecdsa::Signature::from_slice(&authz.signature)
    } else {
        p256::ecdsa::Signature::from_der(&authz.signature)
    }
    .map_err(|_| AuthorizationError::BadSignature)?;
    if !verify_p256(&controller.public_key_sec1, &signed, &sig.to_bytes()) {
        return Err(AuthorizationError::BadSignature);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    /// A test-only signer standing in for hardware. Compiled into tests only;
    /// no release build can construct a software [`HardwareSigner`].
    pub(crate) struct SoftwareTestSigner(pub SigningKey);

    impl HardwareSigner for SoftwareTestSigner {
        fn backend(&self) -> HardwareBackend {
            HardwareBackend::Tpm
        }
        fn label(&self) -> &str {
            "test"
        }
        fn public_key_sec1(&self) -> Result<[u8; 65]> {
            let ep = self.0.verifying_key().to_sec1_point(false);
            let mut out = [0u8; 65];
            out.copy_from_slice(ep.as_bytes());
            Ok(out)
        }
        fn sign_prehash(&self, digest: &[u8; 32]) -> Result<DeviceSignature> {
            let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
            Ok(sig.to_bytes().into())
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn sec1(k: &SigningKey) -> Vec<u8> {
        k.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    pub(crate) fn assertion(
        passkey: &SigningKey,
        rp_id: &str,
        flags: u8,
        challenge: &[u8],
        cross_origin: bool,
    ) -> PasskeyAuthorization {
        assertion_at(
            passkey,
            rp_id,
            &format!("https://{rp_id}"),
            flags,
            challenge,
            cross_origin,
        )
    }

    /// An assertion a page at `origin` obtained for `rp_id`.
    pub(crate) fn assertion_at(
        passkey: &SigningKey,
        rp_id: &str,
        origin: &str,
        flags: u8,
        challenge: &[u8],
        cross_origin: bool,
    ) -> PasskeyAuthorization {
        use base64::Engine;
        let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
        ad.push(flags);
        ad.extend_from_slice(&1u32.to_be_bytes());
        let client = serde_json::json!({
            "type": "webauthn.get",
            "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
            "origin": origin,
            "crossOrigin": cross_origin,
        })
        .to_string()
        .into_bytes();
        let mut signed = ad.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let digest: [u8; 32] = Sha256::digest(&signed).into();
        let sig: p256::ecdsa::Signature = passkey.sign_prehash(&digest).unwrap();
        PasskeyAuthorization {
            authenticator_data: ad,
            client_data_json: client,
            signature: sig.to_der().as_bytes().to_vec(),
        }
    }

    fn controller(k: &SigningKey) -> PasskeyController {
        PasskeyController {
            public_key_sec1: sec1(k),
            rp_id: "tenzro.com".into(),
        }
    }

    #[test]
    fn a_verified_device_bound_approval_is_accepted() {
        let passkey = key(2);
        let ch = [5u8; 32];
        let authz = assertion(&passkey, "tenzro.com", FLAG_UP | FLAG_UV, &ch, false);
        assert_eq!(
            verify_authorization(&controller(&passkey), &ch, &authz),
            Ok(())
        );
        assert_eq!(
            verify_authorization(&controller(&passkey), &[6u8; 32], &authz),
            Err(AuthorizationError::WrongChallenge)
        );
    }

    #[test]
    fn presence_without_verification_is_refused() {
        let passkey = key(2);
        let ch = [5u8; 32];
        let authz = assertion(&passkey, "tenzro.com", FLAG_UP, &ch, false);
        assert_eq!(
            verify_authorization(&controller(&passkey), &ch, &authz),
            Err(AuthorizationError::NotUserVerified)
        );
    }

    #[test]
    fn a_synced_credential_is_refused() {
        let passkey = key(2);
        let ch = [5u8; 32];
        for flag in [FLAG_BE, FLAG_BS, FLAG_BE | FLAG_BS] {
            let authz = assertion(&passkey, "tenzro.com", FLAG_UP | FLAG_UV | flag, &ch, false);
            assert_eq!(
                verify_authorization(&controller(&passkey), &ch, &authz),
                Err(AuthorizationError::SyncedCredential)
            );
        }
    }

    #[test]
    fn another_passkey_or_relying_party_is_refused() {
        let passkey = key(2);
        let ch = [5u8; 32];
        let authz = assertion(&key(3), "tenzro.com", FLAG_UP | FLAG_UV, &ch, false);
        assert_eq!(
            verify_authorization(&controller(&passkey), &ch, &authz),
            Err(AuthorizationError::BadSignature)
        );
        let authz = assertion(&passkey, "evil.example", FLAG_UP | FLAG_UV, &ch, false);
        assert_eq!(
            verify_authorization(&controller(&passkey), &ch, &authz),
            Err(AuthorizationError::WrongRelyingParty)
        );
        let authz = assertion(&passkey, "tenzro.com", FLAG_UP | FLAG_UV, &ch, true);
        assert_eq!(
            verify_authorization(&controller(&passkey), &ch, &authz),
            Err(AuthorizationError::CrossOrigin)
        );
    }

    /// A page on another origin under the relying party's domain can obtain
    /// an assertion with a matching rpIdHash; its origin gives it away.
    #[test]
    fn an_assertion_from_another_origin_is_refused() {
        let passkey = key(2);
        let ch = [5u8; 32];
        for origin in [
            "https://evil.tenzro.com",
            "http://tenzro.com",
            "https://tenzro.com:8443",
        ] {
            let authz = assertion_at(
                &passkey,
                "tenzro.com",
                origin,
                FLAG_UP | FLAG_UV,
                &ch,
                false,
            );
            assert_eq!(
                verify_authorization(&controller(&passkey), &ch, &authz),
                Err(AuthorizationError::WrongOrigin),
                "{origin}"
            );
        }
    }

    #[test]
    fn verify_rejects_a_tampered_message() {
        let s = SoftwareTestSigner(key(7));
        let sig = s.sign(b"a").unwrap();
        let pk = s.public_key_sec1().unwrap();
        assert!(verify_p256(&pk, b"a", &sig));
        assert!(!verify_p256(&pk, b"b", &sig));
    }

    /// Without ML-DSA in hardware, a key of either scheme is refused, naming
    /// its parameter set, rather than made in software. (Hardware with
    /// ML-DSA is exercised by the TPM backend's own test.)
    #[test]
    fn an_ml_dsa_key_is_refused_rather_than_made_in_software() {
        if matches!(ml_dsa_support(), MlDsaSupport::Hardware(_)) {
            return;
        }
        for (scheme, name) in [
            (SignatureScheme::MlDsa65P256, "ML-DSA-65"),
            (SignatureScheme::MlDsa87P384, "ML-DSA-87"),
        ] {
            let err = open_or_create_ml_dsa("tenzro/test/ml-dsa", scheme)
                .err()
                .expect("must refuse");
            assert!(err.to_string().contains("held only in hardware"), "{err}");
            assert!(err.to_string().contains(name), "{err}");
        }
    }

    /// Hardware without ML-DSA still gives an account its ML-DSA-65 key, derived
    /// from the hardware-held root: the same key every time, a hybrid
    /// signature that verifies under `PqPolicy::Required`, and a different
    /// key for another label or another root.
    #[test]
    fn an_account_on_hardware_without_ml_dsa_signs_with_a_derived_ml_dsa_65_key() {
        use tenzro_crypto::HybridSigner;
        use tenzro_crypto::composite::{PqPolicy, SignatureContext, verify_composite};
        let account = |root: u8, label: &str| {
            let pq = DerivedMlDsaSigner::on_root(crate::derive::tests::enclave(root), label);
            HardwareHybridSigner::from_parts(
                Box::new(SoftwareTestSigner(key(7))),
                Some(Box::new(pq)),
            )
            .unwrap()
        };
        let signer = account(40, "tenzro/test/wallet/ml-dsa-65");
        assert!(signer.has_ml_dsa());
        let public = signer.public_key().clone();
        assert_eq!(public.pq.as_ref().map(Vec::len), Some(1952));
        let sig = signer.sign(SignatureContext::Transaction, b"payload").unwrap();
        let legs = verify_composite(
            &public,
            SignatureContext::Transaction,
            b"payload",
            &sig,
            PqPolicy::Required,
        )
        .unwrap();
        assert!(legs.pq);
        assert!(
            verify_composite(
                &public,
                SignatureContext::Transaction,
                b"other",
                &sig,
                PqPolicy::Required
            )
            .is_err()
        );
        assert_eq!(
            account(40, "tenzro/test/wallet/ml-dsa-65").public_key().pq,
            public.pq,
            "the same machine derives the same key"
        );
        assert_ne!(
            account(40, "tenzro/test/other/ml-dsa-65").public_key().pq,
            public.pq
        );
        assert_ne!(
            account(41, "tenzro/test/wallet/ml-dsa-65").public_key().pq,
            public.pq
        );
    }

    #[test]
    fn p384_verification_accepts_both_s_forms_and_rejects_tampering() {
        use p384::ecdsa::signature::hazmat::PrehashSigner;
        let sk = p384::ecdsa::SigningKey::from_slice(&[7u8; 48]).unwrap();
        let pk = sk.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        let digest: [u8; 48] = Sha384::digest(b"a").into();
        let sig: p384::ecdsa::Signature = sk.sign_prehash(&digest).unwrap();
        let low = sig.normalize_s();
        assert!(verify_p384(&pk, b"a", &low.to_bytes()));
        // The high-S form a TPM may return verifies too.
        let (r, s) = low.split_scalars();
        let high = p384::ecdsa::Signature::from_scalars(r, -*s).unwrap();
        assert!(verify_p384(&pk, b"a", &high.to_bytes()));
        assert!(!verify_p384(&pk, b"b", &low.to_bytes()));
        assert!(!verify_p384(&pk[..65], b"a", &low.to_bytes()));
    }
}
