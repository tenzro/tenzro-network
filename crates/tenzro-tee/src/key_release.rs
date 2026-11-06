//! Attestation-bound release of a private model's content key (see
//! [`tenzro_types::key_release`]).
//!
//! [`verify_release`] is the one check of an environment's evidence against
//! a model's policy and the governed GPU values; the chain runs it when it
//! records a release, and [`KeyReleaseBroker`] runs it before it asks the
//! chain to. The broker wraps the content key to the environment's release
//! key only after the chain has accepted the release, so every key that
//! leaves the provider has an on-chain release event, and none leaves after
//! the policy is revoked.
//!
//! The broker never stores the content key. A [`ContentKeyHolder`] opens it
//! for one release from wherever the provider keeps it sealed (its TPM,
//! Secure Enclave or passkey-backed envelope) and the broker drops it once
//! it is wrapped.

use async_trait::async_trait;
use tenzro_crypto::hybrid_seal::{self, HybridSealed};
use tenzro_types::key_release::{KeyReleasePolicy, ReleaseEvent, ReleaseRequest};
use tenzro_types::tee::{TeeVendor, pack_user_data_for_vendor};
pub use zeroize::Zeroizing;

use crate::error::{Result, TeeError};
use crate::tpm_attest::{
    TpmEvidence, attestation_key_sec1, machine_did_for_attestation_key, verify_quote,
};
use crate::verify::{VerifyPolicy, verify_report};
use crate::x509::Cert;

fn refuse(msg: impl Into<String>) -> TeeError {
    TeeError::AttestationVerificationFailed(msg.into())
}

/// What [`verify_release`] checks the evidence against besides the policy.
pub struct ReleaseContext<'a> {
    /// The operator's TPM evidence as admitted on chain: its endorsement
    /// and attestation keys. The release quote must be by this attestation
    /// key.
    pub admitted: &'a TpmEvidence,
    /// GPU device roots governance recognises.
    pub gpu_roots: &'a [Cert],
    /// GPU reference values governance sets, `(index, accepted values)`.
    pub gpu_references: &'a [(u8, Vec<Vec<u8>>)],
    /// Verification time, unix seconds.
    pub now: u64,
}

/// What a verified release proved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRelease {
    pub binding: [u8; 32],
    pub pcr_digest: Vec<u8>,
    pub cvm_measurement: Option<Vec<u8>>,
    pub gpu_device: Option<String>,
}

/// Check `request`'s evidence against `policy` and `ctx`.
pub fn verify_release(
    request: &ReleaseRequest,
    policy: &KeyReleasePolicy,
    ctx: &ReleaseContext<'_>,
) -> Result<VerifiedRelease> {
    let evidence = &request.evidence;
    let binding = request.binding();

    // The operator's hardware identity: the admitted attestation key derives
    // the DID the request names, and that key quotes the binding.
    let ak = attestation_key_sec1(ctx.admitted)?;
    if machine_did_for_attestation_key(&ak) != evidence.operator_did {
        return Err(refuse(
            "the admitted attestation key is not the operator's machine identity",
        ));
    }
    let mut quoted = ctx.admitted.clone();
    quoted.quote = evidence.quote.clone();
    quoted.quote_signature = evidence.quote_signature.clone();
    let quote = verify_quote(&quoted, &binding)
        .map_err(|e| refuse(format!("the operator's quote: {e}")))?;
    if !policy.accepts_pcr_digest(&quote.pcr_digest) {
        return Err(refuse(
            "the operator's measured boot is not one the model's policy accepts",
        ));
    }

    let cvm_measurement = if policy.cvm_measurements.is_empty() {
        None
    } else {
        let report = evidence
            .cvm
            .as_ref()
            .ok_or_else(|| refuse("the model's policy requires a confidential VM report"))?
            .to_report();
        if !matches!(report.vendor, TeeVendor::IntelTdx | TeeVendor::AmdSevSnp) {
            return Err(refuse(format!(
                "{} is not a confidential VM report",
                report.vendor.as_str()
            )));
        }
        let mut vp = VerifyPolicy::now(pack_user_data_for_vendor(report.vendor, &binding));
        vp.now = ctx.now;
        let verified = verify_report(&report, &vp)?;
        if !policy.accepts_cvm(verified.vendor, &verified.measurement) {
            return Err(refuse(
                "the confidential VM's launch measurement is not one the model's policy accepts",
            ));
        }
        Some(verified.measurement)
    };

    let gpu_device = if policy.require_gpu {
        let gpu = evidence
            .gpu
            .as_ref()
            .ok_or_else(|| refuse("the model's policy requires an attested GPU"))?;
        let chain = crate::nvidia_device::parse_chain(&gpu.chain)?;
        let device = crate::nvidia_device::verify_device_report(
            &gpu.report,
            &chain,
            ctx.gpu_roots,
            ctx.now,
            &binding,
        )?;
        crate::nvidia_device::check_reference_values(&gpu.report, ctx.gpu_references)?;
        Some(device.device_id)
    } else {
        None
    };

    Ok(VerifiedRelease {
        binding,
        pcr_digest: quote.pcr_digest,
        cvm_measurement,
        gpu_device,
    })
}

/// Opens a model's content key for one release. Implementations unseal it
/// from the provider's hardware-held envelope; the key is never stored in
/// the clear.
pub trait ContentKeyHolder: Send + Sync {
    fn content_key(&self, model_id: &str) -> Result<Zeroizing<[u8; 32]>>;
}

/// The chain as the broker sees it.
#[async_trait]
pub trait ReleaseLedger: Send {
    /// The model's policy and whether it has been revoked.
    async fn policy(&self, model_id: &str) -> Result<Option<(KeyReleasePolicy, bool)>>;
    /// The operator's admitted TPM evidence.
    async fn admitted(&self, operator_did: &str) -> Result<TpmEvidence>;
    /// The governed GPU roots and reference values.
    async fn gpu_governance(&self) -> Result<(Vec<Cert>, Vec<(u8, Vec<Vec<u8>>)>)>;
    /// Record the release on chain; an error means the chain refused it.
    async fn record(&mut self, request: &ReleaseRequest) -> Result<ReleaseEvent>;
}

/// A released key: the content key sealed to the environment's release key
/// under the binding, and the chain's record of the release.
#[derive(Clone, Debug)]
pub struct ReleasedKey {
    pub sealed: HybridSealed,
    pub event: ReleaseEvent,
}

/// Releases content keys to attested environments.
pub struct KeyReleaseBroker<H: ContentKeyHolder> {
    holder: H,
}

impl<H: ContentKeyHolder> KeyReleaseBroker<H> {
    pub fn new(holder: H) -> Self {
        Self { holder }
    }

    /// Release the key `request` asks for, at unix time `now`: refused when
    /// the model has no policy or a revoked one, when the evidence does not
    /// verify, or when the chain refuses the release.
    pub async fn release(
        &self,
        ledger: &mut dyn ReleaseLedger,
        request: &ReleaseRequest,
        now: u64,
    ) -> Result<ReleasedKey> {
        let (policy, revoked) = ledger.policy(&request.model_id).await?.ok_or_else(|| {
            refuse(format!(
                "{} has no key-release policy; its key is never released",
                request.model_id
            ))
        })?;
        if revoked {
            return Err(refuse(format!(
                "{}'s key-release policy is revoked",
                request.model_id
            )));
        }
        let admitted = ledger.admitted(&request.evidence.operator_did).await?;
        let (roots, references) = ledger.gpu_governance().await?;
        let verified = verify_release(
            request,
            &policy,
            &ReleaseContext {
                admitted: &admitted,
                gpu_roots: &roots,
                gpu_references: &references,
                now,
            },
        )?;
        let event = ledger.record(request).await?;
        if event.binding != hex::encode(verified.binding) {
            return Err(refuse("the chain recorded a different release"));
        }
        let key = self.holder.content_key(&request.model_id)?;
        let sealed = hybrid_seal::seal(&request.release_key, &verified.binding, &key[..])
            .map_err(|e| TeeError::CryptoError(format!("sealing the content key: {e}")))?;
        Ok(ReleasedKey { sealed, event })
    }
}

// --- The provider's content key, held by its hardware. ---------------------

/// A content key wrapped to a key the provider's hardware derives: its TPM,
/// its Secure Enclave, or one of its passkeys through the WebAuthn `prf`
/// extension. Only that hardware opens it; this is the only form the key is
/// kept in.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WrappedContentKey {
    pub model_id: String,
    /// The hardware-derived hybrid X25519 + ML-KEM-768 public key it is
    /// wrapped to.
    pub recipient: tenzro_crypto::hybrid_seal::HybridPublicKey,
    pub envelope: tenzro_crypto::encryption::EncryptedEnvelope,
}

/// The derivation label of the key `model_id`'s content key is wrapped to.
/// A passkey answers it with `prf.eval.first` set to
/// `tenzro_device_key::prf_salt(label)`.
pub fn content_key_label(model_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(model_id.as_bytes());
    format!(
        "tenzro/key-release/content-key/{}",
        hex::encode(&digest[..16])
    )
}

fn device(e: impl std::fmt::Display) -> TeeError {
    TeeError::CryptoError(format!("hardware key: {e}"))
}

/// The hardware-derived hybrid public key `model_id`'s content key is
/// wrapped to, under `root`: an X25519 key and an ML-KEM-768 key, derived
/// apart, so reading the key needs both broken.
pub fn content_key_recipient(
    root: &tenzro_device_key::DerivationRoot,
    model_id: &str,
) -> Result<tenzro_crypto::hybrid_seal::HybridPublicKey> {
    let label = content_key_label(model_id);
    Ok(tenzro_crypto::hybrid_seal::HybridPublicKey {
        x25519: root.x25519_public(&label).map_err(device)?,
        ml_kem: root.ml_kem768_public(&label).map_err(device)?,
    })
}

/// Wrap `key` to `recipient`, a public key from [`content_key_recipient`].
/// Wrapping needs only the public key, so the provider can wrap where it
/// encrypts the weights and keep nothing else.
pub fn wrap_content_key(
    model_id: &str,
    recipient: &tenzro_crypto::hybrid_seal::HybridPublicKey,
    key: &[u8; 32],
) -> Result<WrappedContentKey> {
    let envelope = tenzro_crypto::encryption::envelope_encrypt(recipient, key)
        .map_err(|e| TeeError::CryptoError(format!("wrapping the content key: {e}")))?;
    Ok(WrappedContentKey {
        model_id: model_id.to_string(),
        recipient: recipient.clone(),
        envelope,
    })
}

/// The derived key as an envelope recipient: each agreement derives the key
/// inside the root's closure and wipes it.
struct DerivedRecipient<'a> {
    root: &'a tenzro_device_key::DerivationRoot,
    label: String,
    public: tenzro_crypto::hybrid_seal::HybridPublicKey,
}

impl tenzro_crypto::hybrid_seal::HybridRecipient for DerivedRecipient<'_> {
    fn public_key(&self) -> tenzro_crypto::hybrid_seal::HybridPublicKey {
        self.public.clone()
    }

    fn agree_x25519(&self, share: &[u8; 32]) -> tenzro_crypto::Result<Zeroizing<[u8; 32]>> {
        self.root.x25519_agree(&self.label, share).map_err(|e| {
            tenzro_crypto::CryptoError::DecryptionFailed(format!("derived agreement: {e}"))
        })
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> tenzro_crypto::Result<Zeroizing<[u8; 32]>> {
        self.root
            .ml_kem768_decapsulate(&self.label, ciphertext)
            .map_err(|e| {
                tenzro_crypto::CryptoError::DecryptionFailed(format!("derived decapsulation: {e}"))
            })
    }
}

/// Open `wrapped` with `root`: refused unless `root` derives the key it was
/// wrapped to.
pub fn open_content_key(
    root: &tenzro_device_key::DerivationRoot,
    wrapped: &WrappedContentKey,
) -> Result<Zeroizing<[u8; 32]>> {
    let label = content_key_label(&wrapped.model_id);
    let public = content_key_recipient(root, &wrapped.model_id)?;
    if public != wrapped.recipient {
        return Err(TeeError::CryptoError(format!(
            "{}'s content key is wrapped to another hardware key",
            wrapped.model_id
        )));
    }
    let recipient = DerivedRecipient {
        root,
        label,
        public,
    };
    let opened = Zeroizing::new(
        tenzro_crypto::encryption::envelope_decrypt(&recipient, &wrapped.envelope)
            .map_err(|e| TeeError::CryptoError(format!("opening the content key: {e}")))?,
    );
    let key: [u8; 32] = opened
        .as_slice()
        .try_into()
        .map_err(|_| TeeError::CryptoError("a wrapped content key is not 32 bytes".into()))?;
    Ok(Zeroizing::new(key))
}

/// Where a [`HardwareContentKeys`] gets its derivation root for one opening.
pub enum ContentKeyRoot {
    /// This machine's TPM or Secure Enclave.
    Machine,
    /// One passkey `prf` evaluation over [`content_key_label`]'s salt, used
    /// once.
    Passkey(std::sync::Mutex<Option<Zeroizing<[u8; 32]>>>),
    /// A fixed software root, for tests.
    #[cfg(any(test, feature = "test-ca"))]
    Test([u8; 32]),
}

impl ContentKeyRoot {
    /// A passkey root from the `prf.results.first` of one assertion.
    pub fn passkey(output: Zeroizing<[u8; 32]>) -> Self {
        Self::Passkey(std::sync::Mutex::new(Some(output)))
    }

    fn open(&self, model_id: &str) -> Result<tenzro_device_key::DerivationRoot> {
        match self {
            Self::Machine => tenzro_device_key::DerivationRoot::open_or_create().map_err(device),
            Self::Passkey(output) => {
                let output = output
                    .lock()
                    .map_err(|_| device("passkey output lock poisoned"))?
                    .take()
                    .ok_or_else(|| device("the passkey evaluation has already been used"))?;
                tenzro_device_key::DerivationRoot::from_passkey_prf(
                    &content_key_label(model_id),
                    output,
                )
                .map_err(device)
            }
            #[cfg(any(test, feature = "test-ca"))]
            Self::Test(ikm) => Ok(test_root(*ikm)),
        }
    }
}

#[cfg(any(test, feature = "test-ca"))]
fn test_root(ikm: [u8; 32]) -> tenzro_device_key::DerivationRoot {
    tenzro_device_key::DerivationRoot::for_tests(ikm)
}

/// The production [`ContentKeyHolder`]: content keys kept only wrapped to
/// the provider's hardware, opened there for one release at a time.
pub struct HardwareContentKeys {
    root: ContentKeyRoot,
    wrapped: std::collections::BTreeMap<String, WrappedContentKey>,
}

impl HardwareContentKeys {
    pub fn new(root: ContentKeyRoot) -> Self {
        Self {
            root,
            wrapped: Default::default(),
        }
    }

    /// Hold `wrapped` for its model.
    pub fn insert(&mut self, wrapped: WrappedContentKey) {
        self.wrapped.insert(wrapped.model_id.clone(), wrapped);
    }

    /// Every `*.json` [`WrappedContentKey`] in `dir`.
    pub fn load_dir(&mut self, dir: &std::path::Path) -> Result<usize> {
        let mut n = 0;
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let path = entry?.path();
            if path.extension().is_some_and(|x| x == "json") {
                let wrapped: WrappedContentKey = serde_json::from_slice(&std::fs::read(&path)?)?;
                self.insert(wrapped);
                n += 1;
            }
        }
        Ok(n)
    }
}

impl ContentKeyHolder for HardwareContentKeys {
    fn content_key(&self, model_id: &str) -> Result<Zeroizing<[u8; 32]>> {
        let wrapped = self.wrapped.get(model_id).ok_or_else(|| {
            TeeError::CryptoError(format!("this provider holds no content key for {model_id}"))
        })?;
        let root = self.root.open(model_id)?;
        open_content_key(&root, wrapped)
    }
}

#[cfg(test)]
mod content_key_tests {
    use super::*;

    const MODEL: &str = "acme/private-7b";

    #[test]
    fn a_content_key_wrapped_to_the_hardware_opens_only_there() {
        let root = test_root([1; 32]);
        let key = [0x5Au8; 32];
        let wrapped =
            wrap_content_key(MODEL, &content_key_recipient(&root, MODEL).unwrap(), &key).unwrap();
        // Nothing kept holds the key in the clear.
        let kept = serde_json::to_vec(&wrapped).unwrap();
        assert!(!kept.windows(32).any(|w| w == key));
        assert_eq!(*open_content_key(&root, &wrapped).unwrap(), key);
        assert!(open_content_key(&test_root([2; 32]), &wrapped).is_err());

        let mut holder = HardwareContentKeys::new(ContentKeyRoot::Test([1; 32]));
        holder.insert(wrapped.clone());
        assert_eq!(*holder.content_key(MODEL).unwrap(), key);
        assert!(holder.content_key("acme/other").is_err());
        let mut other = HardwareContentKeys::new(ContentKeyRoot::Test([3; 32]));
        other.insert(wrapped);
        assert!(other.content_key(MODEL).is_err());
    }

    /// The wrap is hybrid and versioned: it carries an ML-KEM-768
    /// ciphertext beside the X25519 share, and a changed part of it, or a
    /// key wrapped to the X25519 half alone, does not open.
    #[test]
    fn a_wrapped_content_key_needs_both_exchanges_and_every_part_intact() {
        let root = test_root([1; 32]);
        let key = [0x21u8; 32];
        let recipient = content_key_recipient(&root, MODEL).unwrap();
        assert_eq!(recipient.ml_kem.len(), 1184);
        let wrapped = wrap_content_key(MODEL, &recipient, &key).unwrap();
        assert_eq!(
            wrapped.envelope.version,
            tenzro_crypto::encryption::ENVELOPE_VERSION
        );
        assert_eq!(wrapped.envelope.sealed_key.ml_kem_ciphertext.len(), 1088);

        let mut kem = wrapped.clone();
        kem.envelope.sealed_key.ml_kem_ciphertext[3] ^= 1;
        assert!(open_content_key(&root, &kem).is_err());
        let mut share = wrapped.clone();
        share.envelope.sealed_key.x25519_share[0] ^= 1;
        assert!(open_content_key(&root, &share).is_err());
        let mut data = wrapped.clone();
        data.envelope.encrypted_data[0] ^= 1;
        assert!(open_content_key(&root, &data).is_err());
        let mut version = wrapped.clone();
        version.envelope.version = 1;
        assert!(open_content_key(&root, &version).is_err());

        // Wrapped to the right X25519 key and another root's ML-KEM key, the
        // hardware cannot open it: the ML-KEM exchange is part of the key.
        let mut half = recipient.clone();
        half.ml_kem = content_key_recipient(&test_root([2; 32]), MODEL)
            .unwrap()
            .ml_kem;
        let swapped = wrap_content_key(MODEL, &half, &key).unwrap();
        assert!(open_content_key(&root, &swapped).is_err());
    }

    #[test]
    fn a_passkey_opens_the_key_once_per_evaluation() {
        let prf = [0x33u8; 32];
        let label = content_key_label(MODEL);
        let root = tenzro_device_key::DerivationRoot::from_passkey_prf(&label, Zeroizing::new(prf))
            .unwrap();
        let key = [0x7Eu8; 32];
        let wrapped =
            wrap_content_key(MODEL, &content_key_recipient(&root, MODEL).unwrap(), &key).unwrap();

        let mut holder = HardwareContentKeys::new(ContentKeyRoot::passkey(Zeroizing::new(prf)));
        holder.insert(wrapped.clone());
        assert_eq!(*holder.content_key(MODEL).unwrap(), key);
        assert!(
            holder.content_key(MODEL).is_err(),
            "one evaluation opens one release"
        );
        let mut wrong = HardwareContentKeys::new(ContentKeyRoot::passkey(Zeroizing::new([9; 32])));
        wrong.insert(wrapped);
        assert!(wrong.content_key(MODEL).is_err());
    }
}
