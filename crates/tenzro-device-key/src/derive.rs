//! Keys the hardware cannot hold, derived on demand from a key it does hold.
//!
//! TPM 2.0 and the Secure Enclave sign only with P-256. An Ed25519, X25519
//! or ML-DSA-65 key is therefore derived at the moment it is needed
//! from a non-exportable hardware key, used for one operation and wiped:
//!
//! | Root | Hardware operation | Who can repeat it |
//! |---|---|---|
//! | TPM | HMAC-SHA256 by a keyed-hash key the TPM generated, usable only through a policy session carrying its authorization ([`crate::derive_tpm`]) | a process holding this machine's TPM, the root's wrapped blob and the service authorization |
//! | Secure Enclave | ECDH between an enclave agreement key whose public half is never read, stored or sent and a fixed point whose discrete logarithm nobody knows | a process that can use this machine's enclave key |
//! | Passkey | the WebAuthn `prf` extension (CTAP2 `hmac-secret`) with a per-label salt | the person, with the authenticator, per ceremony |
//!
//! A Secure Enclave holds only P-256 keys, so an enclave root is as strong as
//! the secrecy of a P-256 scalar. A scalar whose public half is known falls to
//! a quantum computer, and with it every key derived from the root. The
//! enclave root therefore agrees with a key kept apart for it
//! (the hidden root): its directory is outside the label-addressed
//! key store, so no label reaches it, and no function reads its public half.
//! Nothing outside the enclave and this process ever carries a multiple of its
//! scalar by a known point.
//!
//! The hardware output is expanded with HKDF-SHA256 under the backend, the key
//! kind and a caller label into a 32-byte seed held in a buffer that wipes
//! itself on drop. The seed builds the key, the key serves one closure, and
//! both are wiped when the closure returns. No public function returns a seed
//! or a key: [`DerivationRoot::with_ed25519`] and its siblings hand the key to
//! a closure by reference, and none of the key types can be cloned, so the key
//! cannot outlive the call. No seed or key is cached, stored, or written
//! anywhere.
//!
//! There is no software root. [`DerivationRoot::open_or_create`] refuses on a
//! machine with neither a TPM nor a Secure Enclave, and a caller that cannot
//! get a root must refuse the operation that needed the key.
//!
//! The same root and label always give the same key, so the public half can
//! be registered once and the private half recomputed whenever it is needed.
//! Different labels, and different key kinds under one label, give unrelated
//! keys.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{DeviceKeyError, Result};

/// Longest label accepted. Labels name a purpose (`tenzro/validator/account`),
/// not data.
pub const MAX_LABEL_LEN: usize = 200;

/// Which hardware a [`DerivationRoot`] draws from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeriveBackend {
    Tpm,
    SecureEnclave,
    PasskeyPrf,
    /// The root is a TPM in another machine the operator owns; every key
    /// operation runs there (see [`crate::remote`]).
    RemoteTpm,
}

impl DeriveBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tpm => "tpm",
            Self::SecureEnclave => "secure-enclave",
            Self::PasskeyPrf => "passkey-prf",
            Self::RemoteTpm => "remote-tpm",
        }
    }

    fn hkdf_salt(self) -> &'static [u8] {
        match self {
            Self::Tpm => b"tenzro/device-key/derive/tpm",
            Self::SecureEnclave => b"tenzro/device-key/derive/secure-enclave",
            Self::PasskeyPrf => b"tenzro/device-key/derive/passkey-prf",
            Self::RemoteTpm => b"tenzro/device-key/derive/remote-tpm",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyKind {
    Ed25519,
    X25519,
    MlDsa65,
    P256,
    /// The `d` half of an ML-KEM-768 key's seed.
    MlKemD,
    /// The `z` half of an ML-KEM-768 key's seed.
    MlKemZ,
}

impl KeyKind {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Ed25519 => b"ed25519",
            Self::X25519 => b"x25519",
            Self::MlDsa65 => b"ml-dsa-65",
            Self::P256 => b"p256",
            Self::MlKemD => b"ml-kem-768-d",
            Self::MlKemZ => b"ml-kem-768-z",
        }
    }
}

/// A 32-byte derived seed. Wiped on drop; never leaves this module.
#[repr(transparent)]
struct Seed([u8; 32]);

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn check_label(label: &str) -> Result<()> {
    if label.is_empty() || label.len() > MAX_LABEL_LEN || label.as_bytes().contains(&0) {
        return Err(DeviceKeyError::Enclave(format!(
            "a derivation label must be 1 to {MAX_LABEL_LEN} bytes with no NUL"
        )));
    }
    Ok(())
}

/// The bytes the TPM root MACs for `label`.
#[cfg(any(target_os = "linux", windows, test))]
pub(crate) fn hardware_input(label: &str) -> Vec<u8> {
    let mut m = b"tenzro/device-key/derive\0".to_vec();
    m.extend_from_slice(label.as_bytes());
    m
}

fn expand(salt: &[u8], ikm: &[u8; 32], kind: KeyKind, label: &str) -> Seed {
    let mut info = b"tenzro/device-key/derive\0".to_vec();
    info.extend_from_slice(kind.tag());
    info.push(0);
    info.extend_from_slice(label.as_bytes());
    let mut seed = Seed([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(&info, &mut seed.0)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    seed
}

/// The value a client passes as the WebAuthn `prf` extension's
/// `eval.first` when it evaluates the passkey for `label`.
pub fn prf_salt(label: &str) -> Result<[u8; 32]> {
    check_label(label)?;
    let mut h = Sha256::new();
    h.update(b"tenzro/device-key/prf-salt\0");
    h.update(label.as_bytes());
    Ok(h.finalize().into())
}

/// The fixed P-256 point the hidden enclave root agrees with.
///
/// Found by hashing a counter until the digest is the x-coordinate of a curve
/// point (even y), so nobody knows its discrete logarithm. Knowing it would
/// let anyone turn the enclave's public agreement key into the shared secret.
#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), cfg(test))]
pub(crate) fn hidden_root_point() -> [u8; 65] {
    curve_point(b"tenzro/device-key/derive/hidden-root-point\0")
}

#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), cfg(test))]
fn curve_point(domain: &[u8]) -> [u8; 65] {
    let mut ctr: u32 = 0;
    loop {
        let mut h = Sha256::new();
        h.update(domain);
        h.update(ctr.to_be_bytes());
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&h.finalize());
        if let Ok(pk) = p256::PublicKey::from_sec1_bytes(&compressed) {
            // P-256 serialises uncompressed: 0x04 || x || y.
            let mut out = [0u8; 65];
            out.copy_from_slice(&pk.to_sec1_bytes());
            return out;
        }
        ctr += 1;
    }
}

/// One raw P-256 ECDH by a Secure Enclave key agreement key: the
/// x-coordinate of the shared point. The private key never leaves the
/// enclave.
#[cfg(any(target_os = "macos", target_os = "ios", test))]
pub(crate) trait EnclaveAgreement: Send + Sync {
    fn raw_dh(&self, peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>>;
}

/// Directory of the hidden enclave root, under the device-key directory.
/// Labelled keys live in directories named by 64 hex digits, so no label
/// reaches this one.
#[cfg(any(target_os = "macos", target_os = "ios", test))]
pub(crate) const HIDDEN_ROOT_DIR: &str = "derive-root-hidden";

enum Root {
    #[cfg(any(target_os = "linux", windows, test))]
    Tpm(crate::derive_tpm::TpmRoot),
    #[cfg(any(target_os = "macos", target_os = "ios", test))]
    Enclave { key: Box<dyn EnclaveAgreement> },
    Passkey {
        label: String,
        output: Zeroizing<[u8; 32]>,
    },
    #[cfg(feature = "test-root")]
    Test(Zeroizing<[u8; 32]>),
    /// Keys derived and used inside another machine's TPM.
    Remote(std::sync::Arc<dyn RemoteDerive>),
}

/// Key operations carried out where the derivation root is: derived, used
/// once and wiped there, so only public keys, signatures and agreements
/// cross to the caller. [`DerivationRoot`] runs them locally; a provider's
/// client runs them in another machine's TPM.
pub trait RemoteDerive: Send + Sync {
    fn ed25519_public(&self, label: &str) -> Result<[u8; 32]>;
    fn ed25519_sign(&self, label: &str, message: &[u8]) -> Result<[u8; 64]>;
    fn vrf_prove(&self, label: &str, alpha: &[u8]) -> Result<tenzro_crypto::vrf::VrfProof>;
    fn x25519_public(&self, label: &str) -> Result<[u8; 32]>;
    fn x25519_agree(&self, label: &str, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>>;
    fn ml_dsa65_public(&self, label: &str) -> Result<Vec<u8>>;
    fn ml_dsa65_sign(&self, label: &str, ctx: &[u8], message: &[u8]) -> Result<Vec<u8>>;
    fn p256_public(&self, label: &str) -> Result<[u8; 64]>;
    fn p256_sign_prehash(&self, label: &str, hash: &[u8; 32]) -> Result<[u8; 64]>;
    fn ml_kem768_public(&self, label: &str) -> Result<Vec<u8>>;
    fn ml_kem768_decapsulate(&self, label: &str, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>>;
}

static REMOTE_ROOT: std::sync::OnceLock<std::sync::Arc<dyn RemoteDerive>> =
    std::sync::OnceLock::new();

/// Makes every [`DerivationRoot::open_or_create`] in this process a root
/// whose keys live in another machine's TPM. Set once, before any key use.
pub fn use_remote_root(root: std::sync::Arc<dyn RemoteDerive>) -> Result<()> {
    REMOTE_ROOT
        .set(root)
        .map_err(|_| DeviceKeyError::Tpm("the remote derivation root is already set".into()))
}

/// A non-exportable hardware key that per-label keys are derived from.
pub struct DerivationRoot {
    root: Root,
}

impl DerivationRoot {
    /// This machine's derivation root: the TPM on Linux and Windows, the Secure Enclave on
    /// Apple platforms. Created on first use.
    ///
    /// Refuses when the machine has neither, and on Linux when the TPM has not
    /// been provisioned with the key that authorises the root (see
    /// [`crate::derive_tpm`]).
    pub fn open_or_create() -> Result<Self> {
        if let Some(remote) = REMOTE_ROOT.get() {
            return Ok(Self {
                root: Root::Remote(remote.clone()),
            });
        }
        #[cfg(any(target_os = "linux", windows))]
        {
            crate::derive_tpm::TpmRoot::open_or_create_on_device()
                .map(|r| Self { root: Root::Tpm(r) })
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            crate::backend_se::probe()?;
            if !crate::backend_se::HiddenRootKey::exists() {
                crate::backend_se::HiddenRootKey::create()?;
            }
            Ok(Self {
                root: Root::Enclave {
                    key: Box::new(crate::backend_se::HiddenRootKey::open()?),
                },
            })
        }
        #[cfg(not(any(target_os = "linux", windows, target_os = "macos", target_os = "ios")))]
        {
            Err(DeviceKeyError::Enclave(
                "deriving keys from hardware is not supported on this platform".into(),
            ))
        }
    }

    /// A root made from one passkey PRF evaluation, valid for `label` only.
    ///
    /// `output` is `prf.results.first` from a WebAuthn assertion whose
    /// `prf.eval.first` was [`prf_salt`]`(label)`. It is moved in and wiped
    /// when the root is dropped, so build the root right before the operation
    /// and drop it right after.
    pub fn from_passkey_prf(label: &str, output: Zeroizing<[u8; 32]>) -> Result<Self> {
        check_label(label)?;
        Ok(Self {
            root: Root::Passkey {
                label: label.to_string(),
                output,
            },
        })
    }

    /// A fixed software root for other crates' tests. Compiled only with the
    /// `test-root` feature, which only dev-dependencies enable.
    #[cfg(feature = "test-root")]
    pub fn for_tests(ikm: [u8; 32]) -> Self {
        Self {
            root: Root::Test(Zeroizing::new(ikm)),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_tpm_root(root: crate::derive_tpm::TpmRoot) -> Self {
        Self {
            root: Root::Tpm(root),
        }
    }

    /// An enclave root over `key`, for testing the derivation without an
    /// enclave.
    #[cfg(test)]
    pub(crate) fn secure_enclave_for_tests(key: Box<dyn EnclaveAgreement>) -> Self {
        Self {
            root: Root::Enclave { key },
        }
    }

    pub fn backend(&self) -> DeriveBackend {
        match &self.root {
            #[cfg(any(target_os = "linux", windows, test))]
            Root::Tpm(_) => DeriveBackend::Tpm,
            #[cfg(any(target_os = "macos", target_os = "ios", test))]
            Root::Enclave { .. } => DeriveBackend::SecureEnclave,
            Root::Passkey { .. } => DeriveBackend::PasskeyPrf,
            #[cfg(feature = "test-root")]
            Root::Test(_) => DeriveBackend::Tpm,
            Root::Remote(_) => DeriveBackend::RemoteTpm,
        }
    }

    fn hkdf_salt(&self) -> &'static [u8] {
        match &self.root {
            #[cfg(any(target_os = "macos", target_os = "ios", test))]
            Root::Enclave { .. } => b"tenzro/device-key/derive/secure-enclave-hidden-root",
            _ => self.backend().hkdf_salt(),
        }
    }

    fn seed(&self, kind: KeyKind, label: &str) -> Result<Seed> {
        check_label(label)?;
        if matches!(self.root, Root::Remote(_)) {
            return Err(DeviceKeyError::Tpm(
                "the keys of a remote root are used where they live, never handed over".into(),
            ));
        }
        // A machine root derives under this process's key namespace, as its
        // hardware keys are labelled (see [`crate::set_label_namespace`]); a
        // passkey belongs to a person, not to a node, and derives as it is.
        let machine_label = crate::namespaced(label);
        let label: &str = match &self.root {
            Root::Passkey { .. } => label,
            _ => &machine_label,
        };
        let ikm: Zeroizing<[u8; 32]> = match &self.root {
            #[cfg(any(target_os = "linux", windows, test))]
            Root::Tpm(r) => r.hmac(&hardware_input(label))?,
            #[cfg(any(target_os = "macos", target_os = "ios", test))]
            Root::Enclave { key } => key.raw_dh(&hidden_root_point())?,
            Root::Passkey {
                label: bound,
                output,
            } => {
                if bound != label {
                    return Err(DeviceKeyError::Enclave(format!(
                        "this passkey evaluation was made for {bound:?}, not {label:?}"
                    )));
                }
                Zeroizing::new(**output)
            }
            #[cfg(feature = "test-root")]
            Root::Test(ikm) => ikm.clone(),
            Root::Remote(_) => unreachable!("refused above"),
        };
        Ok(expand(self.hkdf_salt(), &ikm, kind, label))
    }

    /// Derive the Ed25519 key for `label` and run `op` with it.
    pub fn with_ed25519<R>(&self, label: &str, op: impl FnOnce(&Ed25519Key) -> R) -> Result<R> {
        let seed = self.seed(KeyKind::Ed25519, label)?;
        let key = Ed25519Key(ed25519_dalek::SigningKey::from_bytes(&seed.0));
        drop(seed);
        Ok(op(&key))
    }

    /// Derive the X25519 key for `label` and run `op` with it.
    pub fn with_x25519<R>(&self, label: &str, op: impl FnOnce(&X25519Key) -> R) -> Result<R> {
        let seed = self.seed(KeyKind::X25519, label)?;
        let key = X25519Key(x25519_dalek::StaticSecret::from(seed.0));
        drop(seed);
        Ok(op(&key))
    }

    /// Derive the ML-DSA-65 key for `label` and run `op` with it.
    pub fn with_ml_dsa65<R>(&self, label: &str, op: impl FnOnce(&MlDsa65Key) -> R) -> Result<R> {
        let seed = self.seed(KeyKind::MlDsa65, label)?;
        let key = tenzro_crypto::MlDsaSigningKey::from_seed(&seed.0)
            .map_err(|e| DeviceKeyError::Enclave(format!("ML-DSA-65 from seed: {e}")))?;
        drop(seed);
        Ok(op(&MlDsa65Key(key)))
    }

    /// Derive the ML-KEM-768 key for `label` and run `op` with it. Its seed is
    /// derived apart from the X25519 key of the same label, so breaking one
    /// says nothing about the other.
    pub fn with_ml_kem768<R>(
        &self,
        label: &str,
        op: impl FnOnce(&tenzro_crypto::ml_kem768::EphemeralKem) -> R,
    ) -> Result<R> {
        let d = self.seed(KeyKind::MlKemD, label)?;
        let z = self.seed(KeyKind::MlKemZ, label)?;
        let mut seed = Zeroizing::new([0u8; tenzro_crypto::ml_kem768::SEED_LEN]);
        seed[..32].copy_from_slice(&d.0);
        seed[32..].copy_from_slice(&z.0);
        drop((d, z));
        let key = tenzro_crypto::ml_kem768::EphemeralKem::from_seed_bytes(&seed);
        drop(seed);
        Ok(op(&key))
    }

    /// Derive the P-256 key for `label` and run `op` with it.
    pub fn with_p256<R>(&self, label: &str, op: impl FnOnce(&P256Key) -> R) -> Result<R> {
        let seed = self.seed(KeyKind::P256, label)?;
        let key = p256::ecdsa::SigningKey::from_slice(&seed.0)
            .map_err(|e| DeviceKeyError::Enclave(format!("P-256 from seed: {e}")))?;
        drop(seed);
        Ok(op(&P256Key(key)))
    }

    /// The 32-byte secret of this machine's network endpoint key for
    /// `label`, the same at every boot. It is derived in memory from the
    /// hardware root and never written anywhere; the caller holds it only
    /// for the life of the endpoint, as it would hold a key made at random
    /// for that endpoint. A machine whose root is another machine's TPM gets
    /// none: its keys never leave that TPM.
    pub fn endpoint_secret(&self, label: &str) -> Result<Zeroizing<[u8; 32]>> {
        let seed = self.seed(KeyKind::Ed25519, label)?;
        Ok(Zeroizing::new(seed.0))
    }

    /// The Ed25519 public key for `label`.
    pub fn ed25519_public(&self, label: &str) -> Result<[u8; 32]> {
        match &self.root {
            Root::Remote(r) => r.ed25519_public(label),
            _ => self.with_ed25519(label, |k| k.public_key()),
        }
    }

    /// An Ed25519 signature by the key for `label`.
    pub fn ed25519_sign(&self, label: &str, message: &[u8]) -> Result<[u8; 64]> {
        match &self.root {
            Root::Remote(r) => r.ed25519_sign(label, message),
            _ => self.with_ed25519(label, |k| k.sign(message)),
        }
    }

    /// A VRF proof over `alpha` by the Ed25519-shaped key for `label`.
    pub fn vrf_prove(&self, label: &str, alpha: &[u8]) -> Result<tenzro_crypto::vrf::VrfProof> {
        match &self.root {
            Root::Remote(r) => r.vrf_prove(label, alpha),
            _ => self
                .with_ed25519(label, |k| k.vrf_prove(alpha))?
                .map_err(|e| DeviceKeyError::Enclave(format!("VRF proof: {e}"))),
        }
    }

    /// The X25519 public key for `label`.
    pub fn x25519_public(&self, label: &str) -> Result<[u8; 32]> {
        match &self.root {
            Root::Remote(r) => r.x25519_public(label),
            _ => self.with_x25519(label, |k| k.public_key()),
        }
    }

    /// The X25519 agreement of the key for `label` with `peer`.
    pub fn x25519_agree(&self, label: &str, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        match &self.root {
            Root::Remote(r) => r.x25519_agree(label, peer),
            _ => self.with_x25519(label, |k| k.diffie_hellman(peer))?,
        }
    }

    /// The ML-KEM-768 encapsulation key for `label`.
    pub fn ml_kem768_public(&self, label: &str) -> Result<Vec<u8>> {
        match &self.root {
            Root::Remote(r) => r.ml_kem768_public(label),
            _ => self.with_ml_kem768(label, |k| k.encapsulation_key().to_vec()),
        }
    }

    /// The ML-KEM-768 shared secret `ciphertext` carries to the key for
    /// `label`.
    pub fn ml_kem768_decapsulate(
        &self,
        label: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>> {
        match &self.root {
            Root::Remote(r) => r.ml_kem768_decapsulate(label, ciphertext),
            _ => self
                .with_ml_kem768(label, |k| k.decapsulate(ciphertext))?
                .map(Zeroizing::new)
                .map_err(|e| DeviceKeyError::Enclave(format!("ML-KEM-768 decapsulation: {e}"))),
        }
    }

    /// The ML-DSA-65 verifying key for `label`.
    pub fn ml_dsa65_public(&self, label: &str) -> Result<Vec<u8>> {
        match &self.root {
            Root::Remote(r) => r.ml_dsa65_public(label),
            _ => self.with_ml_dsa65(label, |k| k.verifying_key()),
        }
    }

    /// An ML-DSA-65 signature by the key for `label` under context `ctx`.
    pub fn ml_dsa65_sign(
        &self,
        label: &str,
        ctx: &'static [u8],
        message: &[u8],
    ) -> Result<Vec<u8>> {
        match &self.root {
            Root::Remote(r) => r.ml_dsa65_sign(label, ctx, message),
            _ => self.with_ml_dsa65(label, |k| k.sign(ctx, message)),
        }
    }

    /// The P-256 public key (`x || y`) for `label`.
    pub fn p256_public(&self, label: &str) -> Result<[u8; 64]> {
        match &self.root {
            Root::Remote(r) => r.p256_public(label),
            _ => self.with_p256(label, |k| k.public_key()),
        }
    }

    /// A P-256 signature over `hash` by the key for `label`.
    pub fn p256_sign_prehash(&self, label: &str, hash: &[u8; 32]) -> Result<[u8; 64]> {
        match &self.root {
            Root::Remote(r) => r.p256_sign_prehash(label, hash),
            _ => self.with_p256(label, |k| k.sign_prehash(hash))?,
        }
    }
}

/// The FIPS 204 context strings a root has been asked to sign under. A
/// context is a short protocol constant, so only a few distinct ones are kept
/// (a request naming more is refused), each leaked once.
pub(crate) fn intern_context(ctx: &[u8]) -> Result<&'static [u8]> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    const MAX_CONTEXTS: usize = 16;
    static CONTEXTS: OnceLock<Mutex<HashMap<Vec<u8>, &'static [u8]>>> = OnceLock::new();
    let mut known = CONTEXTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("context table");
    if let Some(c) = known.get(ctx) {
        return Ok(c);
    }
    if ctx.len() > 255 || known.len() >= MAX_CONTEXTS {
        return Err(DeviceKeyError::Tpm("too many signing contexts".into()));
    }
    let leaked: &'static [u8] = Box::leak(ctx.to_vec().into_boxed_slice());
    known.insert(ctx.to_vec(), leaked);
    Ok(leaked)
}

/// A local root runs every operation itself; a provider answers its clients
/// with one.
impl RemoteDerive for DerivationRoot {
    fn ed25519_public(&self, label: &str) -> Result<[u8; 32]> {
        DerivationRoot::ed25519_public(self, label)
    }
    fn ed25519_sign(&self, label: &str, message: &[u8]) -> Result<[u8; 64]> {
        DerivationRoot::ed25519_sign(self, label, message)
    }
    fn vrf_prove(&self, label: &str, alpha: &[u8]) -> Result<tenzro_crypto::vrf::VrfProof> {
        DerivationRoot::vrf_prove(self, label, alpha)
    }
    fn x25519_public(&self, label: &str) -> Result<[u8; 32]> {
        DerivationRoot::x25519_public(self, label)
    }
    fn x25519_agree(&self, label: &str, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        DerivationRoot::x25519_agree(self, label, peer)
    }
    fn ml_dsa65_public(&self, label: &str) -> Result<Vec<u8>> {
        DerivationRoot::ml_dsa65_public(self, label)
    }
    fn ml_dsa65_sign(&self, label: &str, ctx: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        DerivationRoot::ml_dsa65_sign(self, label, intern_context(ctx)?, message)
    }
    fn p256_public(&self, label: &str) -> Result<[u8; 64]> {
        DerivationRoot::p256_public(self, label)
    }
    fn ml_kem768_public(&self, label: &str) -> Result<Vec<u8>> {
        DerivationRoot::ml_kem768_public(self, label)
    }
    fn ml_kem768_decapsulate(&self, label: &str, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        DerivationRoot::ml_kem768_decapsulate(self, label, ciphertext)
    }
    fn p256_sign_prehash(&self, label: &str, hash: &[u8; 32]) -> Result<[u8; 64]> {
        DerivationRoot::p256_sign_prehash(self, label, hash)
    }
}

/// An Ed25519 key derived for one operation. Wiped on drop.
pub struct Ed25519Key(ed25519_dalek::SigningKey);

impl Ed25519Key {
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.0.sign(message).to_bytes()
    }

    /// An RFC 9381 ECVRF proof over `alpha` with this key, which is
    /// byte-compatible with an ECVRF-EDWARDS25519 secret key.
    pub fn vrf_prove(&self, alpha: &[u8]) -> tenzro_crypto::Result<tenzro_crypto::vrf::VrfProof> {
        let mut sk = tenzro_crypto::vrf::VrfSecretKey(self.0.to_bytes());
        let proof = tenzro_crypto::vrf::prove(&sk, alpha);
        sk.0.zeroize();
        proof
    }
}

/// An X25519 key derived for one operation. Wiped on drop.
pub struct X25519Key(x25519_dalek::StaticSecret);

impl X25519Key {
    pub fn public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.0).to_bytes()
    }

    /// The shared secret with `peer`. Refuses a low-order peer point, whose
    /// shared secret would not depend on this key.
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        let shared = self.0.diffie_hellman(&x25519_dalek::PublicKey::from(*peer));
        if !shared.was_contributory() {
            return Err(DeviceKeyError::Enclave(
                "X25519 peer key is a low-order point".into(),
            ));
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

/// A P-256 key derived for one operation. Wiped on drop.
pub struct P256Key(p256::ecdsa::SigningKey);

impl P256Key {
    /// The raw `x || y` public key.
    pub fn public_key(&self) -> [u8; 64] {
        let point = self.0.verifying_key().to_sec1_point(false);
        let mut out = [0u8; 64];
        out.copy_from_slice(&point.as_bytes()[1..]);
        out
    }

    /// An ECDSA signature over a SHA-256 prehash, as raw `r || s`.
    pub fn sign_prehash(&self, hash: &[u8; 32]) -> Result<[u8; 64]> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature = self
            .0
            .sign_prehash(hash)
            .map_err(|e| DeviceKeyError::Enclave(format!("P-256 signing: {e}")))?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        Ok(out)
    }
}

/// An ML-DSA-65 key derived for one operation. Its seed is wiped on drop.
pub struct MlDsa65Key(tenzro_crypto::MlDsaSigningKey);

impl MlDsa65Key {
    /// The 1952-byte verifying key.
    pub fn verifying_key(&self) -> Vec<u8> {
        self.0.verifying_key_bytes().to_vec()
    }

    /// A signature under the FIPS 204 context string `ctx`.
    pub fn sign(&self, ctx: &'static [u8], message: &[u8]) -> Vec<u8> {
        self.0.sign(ctx, message)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A software P-256 key agreement key standing in for an enclave key.
    struct SoftAgreement(p256::SecretKey);

    impl SoftAgreement {
        fn new(byte: u8) -> Box<Self> {
            Box::new(Self(p256::SecretKey::from_slice(&[byte; 32]).unwrap()))
        }
    }

    impl EnclaveAgreement for SoftAgreement {
        fn raw_dh(&self, peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>> {
            let peer = p256::PublicKey::from_sec1_bytes(peer)
                .map_err(|_| DeviceKeyError::Enclave("not a P-256 point".into()))?;
            let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(shared.raw_secret_bytes().as_slice());
            Ok(out)
        }
    }

    const CONSENSUS: &str = "tenzro/test/consensus";

    pub(crate) fn enclave(byte: u8) -> DerivationRoot {
        DerivationRoot::secure_enclave_for_tests(SoftAgreement::new(byte))
    }

    /// The keys of a fresh Mac's root stay out of reach of an attacker who
    /// holds the private scalar of every public key the machine publishes
    /// (its identity key and its agreement key), used as a root.
    #[test]
    fn breaking_every_published_enclave_key_does_not_give_a_fresh_macs_derived_keys() {
        const HIDDEN: u8 = 32;
        const IDENTITY: u8 = 33;
        const AGREEMENT: u8 = 31;
        let machine = enclave(HIDDEN);
        let ml_dsa = machine.ml_dsa65_public(CONSENSUS).unwrap();
        let ed = machine.ed25519_public(CONSENSUS).unwrap();
        for published in [AGREEMENT, IDENTITY] {
            let forged = enclave(published);
            assert_ne!(forged.ml_dsa65_public(CONSENSUS).unwrap(), ml_dsa);
            assert_ne!(forged.ed25519_public(CONSENSUS).unwrap(), ed);
        }
    }

    /// The hidden root derives the same key for a label every time,
    /// unrelated keys for other labels, and keys that differ with the scalar.
    #[test]
    fn the_hidden_root_is_deterministic_and_separated() {
        let a = enclave(41);
        let b = enclave(41);
        let k = a.ml_dsa65_public(CONSENSUS).unwrap();
        assert_eq!(k, b.ml_dsa65_public(CONSENSUS).unwrap());
        assert_ne!(k, a.ml_dsa65_public("tenzro/test/other").unwrap());
        assert_ne!(k, enclave(42).ml_dsa65_public(CONSENSUS).unwrap());
        assert!(p256::PublicKey::from_sec1_bytes(&hidden_root_point()).is_ok());
        let sig = a.ml_dsa65_sign(CONSENSUS, b"ctx", b"m").unwrap();
        assert!(!sig.is_empty());
    }

    /// No label addresses the hidden root's directory: a labelled key's
    /// directory is the 64 hex digits of its credential id.
    #[test]
    fn no_label_reaches_the_hidden_root_directory() {
        assert_ne!(HIDDEN_ROOT_DIR.len(), 64);
        assert!(!HIDDEN_ROOT_DIR.chars().all(|c| c.is_ascii_hexdigit()));
    }

    fn prf_root(label: &str, byte: u8) -> DerivationRoot {
        DerivationRoot::from_passkey_prf(label, Zeroizing::new([byte; 32])).unwrap()
    }

    #[test]
    fn the_same_root_and_label_derive_the_same_key() {
        let a = prf_root("tenzro/test/a", 7);
        let b = prf_root("tenzro/test/a", 7);
        let pa = a.with_ed25519("tenzro/test/a", |k| k.public_key()).unwrap();
        let pb = b.with_ed25519("tenzro/test/a", |k| k.public_key()).unwrap();
        assert_eq!(pa, pb);
        let va = a
            .with_ml_dsa65("tenzro/test/a", |k| k.verifying_key())
            .unwrap();
        let vb = b
            .with_ml_dsa65("tenzro/test/a", |k| k.verifying_key())
            .unwrap();
        assert_eq!(va, vb);
        assert_eq!(va.len(), tenzro_crypto::ML_DSA_65_VK_LEN);
        let xa = a.with_x25519("tenzro/test/a", |k| k.public_key()).unwrap();
        let xb = b.with_x25519("tenzro/test/a", |k| k.public_key()).unwrap();
        assert_eq!(xa, xb);
    }

    #[test]
    fn labels_backends_and_kinds_are_separated() {
        let ikm = [9u8; 32];
        let mut seen = std::collections::HashSet::new();
        for backend in [
            DeriveBackend::Tpm,
            DeriveBackend::SecureEnclave,
            DeriveBackend::PasskeyPrf,
        ] {
            for kind in [KeyKind::Ed25519, KeyKind::X25519, KeyKind::MlDsa65] {
                for label in ["tenzro/a", "tenzro/b", "tenzro/a/b"] {
                    assert!(
                        seen.insert(expand(backend.hkdf_salt(), &ikm, kind, label).0),
                        "{backend:?} {kind:?} {label}"
                    );
                }
            }
        }
        assert_eq!(seen.len(), 27);
    }

    #[test]
    fn a_different_hardware_output_derives_a_different_key() {
        let a = prf_root("tenzro/test/a", 1).with_ed25519("tenzro/test/a", |k| k.public_key());
        let b = prf_root("tenzro/test/a", 2).with_ed25519("tenzro/test/a", |k| k.public_key());
        assert_ne!(a.unwrap(), b.unwrap());
    }

    #[test]
    fn a_prf_evaluation_serves_only_its_own_label() {
        let r = prf_root("tenzro/test/a", 3);
        let err = r
            .with_ed25519("tenzro/test/b", |k| k.public_key())
            .expect_err("must refuse");
        assert!(err.to_string().contains("was made for"), "{err}");
        assert_ne!(
            prf_salt("tenzro/test/a").unwrap(),
            prf_salt("tenzro/test/b").unwrap()
        );
    }

    #[test]
    fn malformed_labels_are_refused() {
        let long = "x".repeat(MAX_LABEL_LEN + 1);
        for bad in ["", "a\0b", long.as_str()] {
            assert!(DerivationRoot::from_passkey_prf(bad, Zeroizing::new([1; 32])).is_err());
            assert!(prf_salt(bad).is_err());
            assert!(prf_root("tenzro/ok", 1).with_ed25519(bad, |_| ()).is_err());
        }
    }

    #[test]
    fn derived_keys_sign_and_verify() {
        let r = prf_root("tenzro/test/sign", 5);
        let l = "tenzro/test/sign";
        let (pk, sig) = r
            .with_ed25519(l, |k| (k.public_key(), k.sign(b"m")))
            .unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
        assert!(
            vk.verify_strict(b"m", &ed25519_dalek::Signature::from_bytes(&sig))
                .is_ok()
        );
        assert!(
            vk.verify_strict(b"n", &ed25519_dalek::Signature::from_bytes(&sig))
                .is_err()
        );

        let ctx: &'static [u8] = b"tenzro/test";
        let (vk, sig) = r
            .with_ml_dsa65(l, |k| (k.verifying_key(), k.sign(ctx, b"m")))
            .unwrap();
        assert!(tenzro_crypto::ml_dsa_verify(&vk, ctx, b"m", &sig).is_ok());
        assert!(tenzro_crypto::ml_dsa_verify(&vk, ctx, b"n", &sig).is_err());
    }

    #[test]
    fn x25519_agreement_matches_and_refuses_low_order_points() {
        let a = prf_root("tenzro/test/x", 1);
        let peer = x25519_dalek::StaticSecret::from([4u8; 32]);
        let peer_pk = x25519_dalek::PublicKey::from(&peer).to_bytes();
        let (pk, ours) = a
            .with_x25519("tenzro/test/x", |k| {
                (k.public_key(), k.diffie_hellman(&peer_pk))
            })
            .unwrap();
        let theirs = peer.diffie_hellman(&x25519_dalek::PublicKey::from(pk));
        assert_eq!(*ours.unwrap(), theirs.to_bytes());
        let low_order = a
            .with_x25519("tenzro/test/x", |k| k.diffie_hellman(&[0u8; 32]))
            .unwrap();
        assert!(low_order.is_err());
    }

    #[test]
    fn an_ml_kem_key_is_derived_per_label_and_opens_what_is_encapsulated() {
        let a = prf_root("tenzro/test/kem", 1);
        let ek = a.ml_kem768_public("tenzro/test/kem").unwrap();
        assert_eq!(ek.len(), 1184);
        assert_eq!(ek, a.ml_kem768_public("tenzro/test/kem").unwrap());
        let (ct, ss) = tenzro_crypto::ml_kem768::encapsulate(&ek).unwrap();
        assert_eq!(
            *a.ml_kem768_decapsulate("tenzro/test/kem", &ct).unwrap(),
            ss
        );
        // Another root derives another key, and a short ciphertext is refused.
        let b = prf_root("tenzro/test/kem", 2);
        assert_ne!(b.ml_kem768_public("tenzro/test/kem").unwrap(), ek);
        assert!(
            a.ml_kem768_decapsulate("tenzro/test/kem", &ct[1..])
                .is_err()
        );
    }

    #[test]
    fn a_seed_is_wiped_when_dropped() {
        use std::mem::MaybeUninit;
        let mut slot = MaybeUninit::<Seed>::uninit();
        slot.write(expand(
            DeriveBackend::PasskeyPrf.hkdf_salt(),
            &[1; 32],
            KeyKind::Ed25519,
            "tenzro/test",
        ));
        let before = unsafe { *(slot.as_ptr() as *const [u8; 32]) };
        assert_ne!(before, [0u8; 32]);
        unsafe { std::ptr::drop_in_place(slot.as_mut_ptr()) };
        let after = unsafe { *(slot.as_ptr() as *const [u8; 32]) };
        assert_eq!(
            after, [0u8; 32],
            "a dropped seed must not leave its bytes behind"
        );
    }

    #[test]
    fn the_endpoint_secret_is_the_same_each_time_and_differs_by_label() {
        let prf = || Zeroizing::new([5u8; 32]);
        let a = DerivationRoot::from_passkey_prf("tenzro/transport/endpoint", prf()).unwrap();
        let b = DerivationRoot::from_passkey_prf("tenzro/transport/endpoint", prf()).unwrap();
        let first = a.endpoint_secret("tenzro/transport/endpoint").unwrap();
        assert_eq!(
            *first,
            *b.endpoint_secret("tenzro/transport/endpoint").unwrap()
        );
        assert_ne!(*first, [0u8; 32]);
        let other = DerivationRoot::from_passkey_prf("tenzro/other", prf()).unwrap();
        assert_ne!(*first, *other.endpoint_secret("tenzro/other").unwrap());
    }

    #[test]
    fn every_derived_key_wipes_itself() {
        fn wipes<T: zeroize::ZeroizeOnDrop>() {}
        wipes::<ed25519_dalek::SigningKey>();
        // x25519-dalek wipes StaticSecret in a derived Drop without the
        // ZeroizeOnDrop marker; check both halves of that instead.
        fn zeroizes<T: zeroize::Zeroize>() {}
        zeroizes::<x25519_dalek::StaticSecret>();
        assert!(std::mem::needs_drop::<x25519_dalek::StaticSecret>());
        wipes::<Zeroizing<[u8; 32]>>();
    }

    #[test]
    fn the_hidden_root_point_is_fixed_and_on_the_curve() {
        let p = hidden_root_point();
        assert_eq!(p, hidden_root_point());
        assert_eq!(p[0], 0x04);
        assert!(p256::PublicKey::from_sec1_bytes(&p).is_ok());
    }

    /// A machine with neither a TPM nor a Secure Enclave must refuse rather
    /// than make a root out of anything else. Where either is present the
    /// root is real, and it is tested in `derive_tpm` and `backend_se` under a
    /// throwaway key directory instead of the user's own.
    #[test]
    fn without_provisioned_hardware_there_is_no_root() {
        #[cfg(any(target_os = "linux", windows))]
        if crate::backend_tpm::available() {
            return;
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        if crate::backend_se::available() {
            return;
        }
        let err = DerivationRoot::open_or_create()
            .err()
            .expect("no root without hardware");
        let msg = err.to_string();
        assert!(
            msg.contains("TPM") || msg.contains("Secure Enclave") || msg.contains("not supported"),
            "{msg}"
        );
    }
}
