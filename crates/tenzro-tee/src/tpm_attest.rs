//! TPM 2.0 attestation: proving that a key and a quote come from a genuine
//! TPM, and which one.
//!
//! > **Not confidential compute.** A TPM attests that a *machine* holds a key
//! > nobody can copy; it lives here next to the other attestation verifiers
//! > because it shares their X.509 chain code.
//!
//! Three checks, each closing a different gap:
//!
//! 1. **Endorsement.** The endorsement key must match the public key in the
//!    EK certificate, and that certificate must chain by signature to a TPM
//!    manufacturer root. Without this, a software TPM passes every other
//!    check. The EK may be ECC P-256, ECC P-384, RSA-2048 or RSA-3072: a
//!    machine offers the first one its TPM holds a manufacturer certificate
//!    for, read from the persistent handle provisioning keeps it at, never
//!    recreated.
//! 2. **Credential activation.** The verifier encrypts a fresh secret to the
//!    EK, bound to the attestation key's *name* ([`make_credential`]): to an
//!    ECC EK through an ephemeral key agreement, to an RSA EK under RSA-OAEP,
//!    with the EK's own name algorithm throughout. The TPM
//!    releases it only if an object with that exact name is loaded in the same
//!    chip as the EK. Recovering the secret proves the attestation key lives
//!    in the endorsed TPM, which nothing about the key's bytes alone can show.
//! 3. **Quote.** The attestation key is restricted, so it signs only
//!    TPM-generated structures. A quote over the verifier's challenge
//!    (`extraData`) is therefore a statement by this TPM, now, about its PCRs
//!    and about whatever the challenge commits to.
//!
//! The machine's DID is derived from the attestation key, the key that
//! signs the quote, so a verifier holding the evidence recomputes the DID
//! itself and nobody can claim it without that key. Activation is checked by
//! the verifier that ran it; a later relying party re-checks the quote and the
//! DID, and weighs the EK certificate as reputation.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
pub use tenzro_device_key::credential::Credential;
use tenzro_device_key::credential::EndorsementPublic;
use tenzro_device_key::tpm_wire::{self, PublicArea};

use crate::error::{Result, TeeError};
use crate::x509::{self, Cert};

fn fail(msg: impl Into<String>) -> TeeError {
    TeeError::AttestationVerificationFailed(msg.into())
}

/// Parse TPM manufacturer EK roots given as PEM. The set itself is not a
/// constant of this crate: the network holds it in consensus state, seeded
/// at genesis and replaced by governance.
pub fn parse_roots(roots_pem: &[String]) -> Result<Vec<Cert>> {
    let mut out = Vec::new();
    for pem in roots_pem {
        out.extend(x509::parse_pem_chain(pem)?);
    }
    Ok(out)
}

/// Domain tag for the admission challenge a quote must answer.
const ADMISSION_DOMAIN: &[u8] = b"tenzro/machine-admission/v1\0";

/// Evidence a machine presents: its endorsement, its attestation key, and a
/// quote by that key.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TpmEvidence {
    /// `TPMT_PUBLIC` of the endorsement key.
    pub ek_public: Vec<u8>,
    /// DER EK certificate, as provisioned in NV by the manufacturer.
    pub ek_certificate: Vec<u8>,
    /// DER intermediates between the EK certificate and a manufacturer root.
    pub ek_intermediates: Vec<Vec<u8>>,
    /// `TPMT_PUBLIC` of the attestation key.
    pub ak_public: Vec<u8>,
    /// `TPMS_ATTEST` of the quote.
    pub quote: Vec<u8>,
    /// Raw `r || s` ECDSA-P256 signature over SHA-256 of `quote`.
    pub quote_signature: Vec<u8>,
}

/// What a verified quote says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTpmQuote {
    /// SHA-256 name of the endorsement key; the machine identifier.
    pub ek_name: Vec<u8>,
    pub pcr_digest: Vec<u8>,
    pub pcr_selection: Vec<(u16, Vec<u8>)>,
    pub reset_count: u32,
    pub firmware_version: u64,
}

/// Check that `ak` is a restricted P-256 signing key a TPM generated.
fn attestation_key(ak: &PublicArea) -> Result<[u8; 65]> {
    use tpm_wire::*;
    let needed = TPMA_OBJECT_FIXEDTPM
        | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_SENSITIVEDATAORIGIN
        | TPMA_OBJECT_RESTRICTED
        | TPMA_OBJECT_SIGN_ENCRYPT;
    if ak.attributes & needed != needed || ak.attributes & TPMA_OBJECT_DECRYPT != 0 {
        return Err(fail(
            "attestation key is not a restricted, TPM-generated, non-duplicable signing key",
        ));
    }
    match ak.key {
        PublicKey::EccP256 { scheme, .. } if scheme == TPM2_ALG_ECDSA => {}
        PublicKey::MlDsa { .. } => {
            return Err(fail(
                "attestation key is ML-DSA: a quote is verified as ECDSA P-256, so an ML-DSA key cannot sign one; attest with a P-256 key",
            ));
        }
        _ => return Err(fail("attestation key is not ECDSA P-256")),
    }
    ak.p256_sec1()
        .ok_or_else(|| fail("attestation key is not P-256"))
}

/// Most intermediates an EK chain may carry.
const MAX_EK_INTERMEDIATES: usize = 6;

/// Whether `cert` certifies exactly the endorsement key `ek`.
fn certificate_carries(cert: &Cert, ek: &EndorsementPublic) -> bool {
    match ek {
        EndorsementPublic::P256(pk) => cert
            .public_key_bits()
            .ok()
            .and_then(|b| p256::PublicKey::from_sec1_bytes(&b).ok())
            .is_some_and(|c| &c == pk),
        EndorsementPublic::P384(pk) => cert
            .public_key_bits()
            .ok()
            .and_then(|b| p384::PublicKey::from_sec1_bytes(&b).ok())
            .is_some_and(|c| &c == pk),
        EndorsementPublic::Rsa(pk) => x509::rsa_public_key(&cert.spki_der).is_ok_and(|c| &c == pk),
    }
}

/// Whether the EK certificate `cert_der` certifies the endorsement key whose
/// `TPMT_PUBLIC` is `ek`.
pub fn certificate_is_for(cert_der: &[u8], ek: &PublicArea) -> bool {
    match (
        x509::parse(cert_der),
        tenzro_device_key::credential::endorsement_key(ek),
    ) {
        (Ok(cert), Ok(key)) => certificate_carries(&cert, &key.public),
        _ => false,
    }
}

/// The EK certificate followed by the intermediates that lead from it
/// towards a root, in issuing order. The intermediates may be presented in
/// any order (a TPM's chain indices fix none); ones that do not continue the
/// path are left out.
fn ek_path(evidence: &TpmEvidence) -> Result<Vec<Cert>> {
    if evidence.ek_intermediates.len() > MAX_EK_INTERMEDIATES {
        return Err(fail("EK certificate chain carries too many intermediates"));
    }
    let mut pool = evidence
        .ek_intermediates
        .iter()
        .map(|der| x509::parse(der))
        .collect::<Result<Vec<_>>>()?;
    let mut chain = vec![x509::parse(&evidence.ek_certificate)?];
    while let Some(i) = pool.iter().position(|c| {
        let top = chain.last().expect("chain starts with the leaf");
        c.subject_der == top.issuer_der && top.issuer_der != top.subject_der
    }) {
        chain.push(pool.swap_remove(i));
    }
    Ok(chain)
}

/// Check that the EK certificate carries exactly the EK's public key and
/// chains to one of `roots` at `now`.
pub fn verify_endorsement(evidence: &TpmEvidence, roots: &[Cert], now: u64) -> Result<PublicArea> {
    let ek = tpm_wire::parse_public(&evidence.ek_public).map_err(|e| fail(e.to_string()))?;
    let key =
        tenzro_device_key::credential::endorsement_key(&ek).map_err(|e| fail(e.to_string()))?;
    let chain = ek_path(evidence)?;
    if !certificate_carries(&chain[0], &key.public) {
        return Err(fail(
            "EK certificate is for a different key than the endorsement key",
        ));
    }
    x509::verify_chain(&chain, roots, now).map_err(|e| {
        fail(format!(
            "EK certificate does not chain to a manufacturer root: {e}"
        ))
    })?;
    Ok(ek)
}

/// Where to fetch the next certificate of the evidence's EK chain: the
/// `caIssuers` URL of the topmost certificate it carries, when that one is
/// neither a root in `roots` nor issued by one. `None` when the chain
/// already reaches `roots`, or names no issuer to fetch.
///
/// A fetched certificate is only ever a candidate: [`verify_endorsement`]
/// accepts it as an intermediate only when its signatures lead to `roots`.
pub fn missing_issuer_url(evidence: &TpmEvidence, roots: &[Cert]) -> Option<String> {
    let chain = ek_path(evidence).ok()?;
    if chain.len() > MAX_EK_INTERMEDIATES {
        return None;
    }
    let top = chain.last()?;
    if roots
        .iter()
        .any(|r| r.der == top.der || r.subject_der == top.issuer_der)
    {
        return None;
    }
    x509::ca_issuers_url(top)
}

/// Verify the quote in `evidence` answers `expected_extra_data` and was
/// signed by the evidence's attestation key as a primary in the endorsement
/// hierarchy.
pub fn verify_quote(
    evidence: &TpmEvidence,
    expected_extra_data: &[u8],
) -> Result<VerifiedTpmQuote> {
    let ek = tpm_wire::parse_public(&evidence.ek_public).map_err(|e| fail(e.to_string()))?;
    let ak = tpm_wire::parse_public(&evidence.ak_public).map_err(|e| fail(e.to_string()))?;
    let ak_sec1 = attestation_key(&ak)?;
    let ak_name = ak.name().map_err(|e| fail(e.to_string()))?;
    let digest: [u8; 32] = Sha256::digest(&evidence.quote).into();
    if !tenzro_device_key::signer::verify_p256_prehash(&ak_sec1, &digest, &evidence.quote_signature)
    {
        return Err(fail(
            "quote signature does not verify under the attestation key",
        ));
    }
    let info = tpm_wire::parse_quote(&evidence.quote).map_err(|e| fail(e.to_string()))?;
    if !bool::from(info.extra_data.ct_eq(expected_extra_data)) {
        return Err(fail("quote does not answer this challenge"));
    }
    if info.qualified_signer != tpm_wire::endorsement_primary_qualified_name(&ak_name) {
        return Err(fail("quote was not signed by this attestation key"));
    }
    Ok(VerifiedTpmQuote {
        ek_name: ek.name().map_err(|e| fail(e.to_string()))?,
        pcr_digest: info.pcr_digest,
        pcr_selection: info.pcr_selection,
        reset_count: info.reset_count,
        firmware_version: info.firmware_version,
    })
}

/// Verify that the TPM which produced `evidence` (its admitted attestation
/// key) certified the ML-DSA key `ml_dsa_key` over `extra_data`: the
/// certified object `key_public` is a TPM 2.0 library v1.85 ML-DSA key that
/// was generated in that TPM and cannot leave it.
pub fn verify_ml_dsa_certification(
    evidence: &TpmEvidence,
    key_public: &[u8],
    attest: &[u8],
    signature: &[u8],
    ml_dsa_key: &[u8],
    extra_data: &[u8],
) -> Result<tenzro_device_key::key_certification::CertifiedMlDsaKey> {
    use tenzro_device_key::key_certification::{KeyCertification, verify_ml_dsa};
    let ak = attestation_key_sec1(evidence)?;
    let cert = KeyCertification {
        ak_public: evidence.ak_public.clone(),
        key_public: key_public.to_vec(),
        attest: attest.to_vec(),
        signature: signature.to_vec(),
    };
    verify_ml_dsa(&cert, ml_dsa_key, extra_data, &ak).map_err(fail)
}

/// The public point of the evidence's attestation key, checked to be a
/// restricted, TPM-generated, non-duplicable P-256 signing key.
pub fn attestation_key_sec1(evidence: &TpmEvidence) -> Result<[u8; 65]> {
    let ak = tpm_wire::parse_public(&evidence.ak_public).map_err(|e| fail(e.to_string()))?;
    attestation_key(&ak)
}

/// The machine DID an attestation key roots: the device-key form, so the
/// identifier is a function of the key that quotes and nobody can claim it
/// without that key.
pub fn machine_did_for_attestation_key(ak_sec1: &[u8; 65]) -> String {
    format!(
        "did:tenzro:machine:{}",
        tenzro_types::did_derivation::machine_device_id(ak_sec1)
    )
}

/// Constant-time comparison of the secret a TPM released with the one the
/// verifier encrypted.
pub fn activation_matches(issued: &[u8], released: &[u8]) -> bool {
    issued.len() == released.len() && bool::from(issued.ct_eq(released))
}

/// The challenge a machine's admission quote must answer: the machine's DID,
/// the key its wallet signs with, and a verifier nonce.
pub fn admission_challenge(did: &str, wallet_public_key: &[u8], nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ADMISSION_DOMAIN);
    h.update((did.len() as u32).to_be_bytes());
    h.update(did.as_bytes());
    h.update((wallet_public_key.len() as u32).to_be_bytes());
    h.update(wallet_public_key);
    h.update(nonce);
    h.finalize().into()
}

/// DER of the TCG `tpmManufacturer` attribute type, 2.23.133.2.1.
const TCG_TPM_MANUFACTURER: &[u8] = &[0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x01];
/// DER of the TCG `tpmSpecification` attribute type, 2.23.133.2.16.
const TCG_TPM_SPECIFICATION: &[u8] = &[0x06, 0x05, 0x67, 0x81, 0x05, 0x02, 0x10];

/// One short-form DER element at `at`: its tag and contents.
fn der_short(bytes: &[u8], at: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *bytes.get(at)?;
    let len = *bytes.get(at + 1)? as usize;
    if len >= 0x80 {
        return None;
    }
    let body = bytes.get(at + 2..at + 2 + len)?;
    Some((tag, body, at + 2 + len))
}

fn der_text(tag: u8, body: &[u8]) -> Option<String> {
    // UTF8String, PrintableString or IA5String.
    matches!(tag, 0x0C | 0x13 | 0x16)
        .then(|| String::from_utf8(body.to_vec()).ok())
        .flatten()
        .filter(|s| s.len() <= 64 && s.chars().all(|c| c.is_ascii_graphic()))
}

fn der_uint(body: &[u8]) -> Option<u64> {
    if body.is_empty() || body.len() > 8 {
        return None;
    }
    Some(body.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b)))
}

/// The TPM manufacturer and specification an endorsement certificate names:
/// the TCG `tpmManufacturer` from its subject alternative name (for example
/// `id:494E5443`) and `family/level/revision` from its `tpmSpecification`
/// attribute. Each is empty when the certificate does not carry it. Only
/// meaningful for a certificate [`verify_endorsement`] accepted.
pub fn ek_certificate_profile(cert_der: &[u8]) -> (String, String) {
    let find = |oid: &[u8]| {
        cert_der
            .windows(oid.len())
            .position(|w| w == oid)
            .map(|p| p + oid.len())
    };
    let vendor = find(TCG_TPM_MANUFACTURER)
        .and_then(|at| der_short(cert_der, at))
        .and_then(|(tag, body, _)| der_text(tag, body))
        .unwrap_or_default();
    let spec = find(TCG_TPM_SPECIFICATION)
        .and_then(|at| {
            // SET { SEQUENCE { family UTF8String, level INTEGER, revision INTEGER } }
            let (set, set_body, _) = der_short(cert_der, at)?;
            let (seq, seq_body, _) = der_short(set_body, 0)?;
            if set != 0x31 || seq != 0x30 {
                return None;
            }
            let (ft, family, next) = der_short(seq_body, 0)?;
            let (lt, level, next) = der_short(seq_body, next)?;
            let (rt, revision, _) = der_short(seq_body, next)?;
            if lt != 0x02 || rt != 0x02 {
                return None;
            }
            Some(format!(
                "{}/{}/{}",
                der_text(ft, family)?,
                der_uint(level)?,
                der_uint(revision)?
            ))
        })
        .unwrap_or_default();
    (vendor, spec)
}

/// Everything admission records, after it has all been verified.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct MachineAttestation {
    pub evidence: TpmEvidence,
    /// The verifier nonce the quote answers.
    pub nonce: Vec<u8>,
    /// Whether this verifier ran credential activation against the TPM.
    pub activated: bool,
}

/// How far a machine's endorsement key is vouched for by its manufacturer.
///
/// This is a reputation signal, not an admission rule: a machine is admitted
/// on the proof that its attestation key lives beside its endorsement key and
/// quoted the challenge, whoever made the chip. Whether a manufacturer also
/// certified that endorsement key is recorded beside the identity so relying
/// parties can weigh it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndorsementGrade {
    /// The EK certificate carries the EK and chains to a manufacturer root.
    ManufacturerCertified,
    /// No certificate, or one that does not verify; the reason says which.
    Uncertified(String),
}

impl EndorsementGrade {
    /// Stable label for identity metadata and credentials.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ManufacturerCertified => "manufacturer_certified",
            Self::Uncertified(_) => "uncertified",
        }
    }
}

/// Grade the endorsement recorded in `attestation` against `roots` at `now`.
pub fn endorsement_grade(
    attestation: &MachineAttestation,
    roots: &[Cert],
    now: u64,
) -> EndorsementGrade {
    if attestation.evidence.ek_certificate.is_empty() {
        return EndorsementGrade::Uncertified("the TPM holds no EK certificate".into());
    }
    match verify_endorsement(&attestation.evidence, roots, now) {
        Ok(_) => EndorsementGrade::ManufacturerCertified,
        Err(e) => EndorsementGrade::Uncertified(e.to_string()),
    }
}

/// Attest the TPM on this machine to itself: read the endorsement key (and
/// its certificate, when the TPM holds one), create the attestation key, run
/// credential activation with a fresh secret, and take a quote over the
/// admission challenge over the DID the attestation key roots. Activation and
/// the quote are verified before the DID and evidence are returned. The
/// manufacturer certificate is carried but not required; see
/// [`endorsement_grade`].
#[cfg(any(target_os = "linux", windows))]
pub fn attest_local_machine(wallet_public_key: &[u8]) -> Result<(String, MachineAttestation)> {
    attest_local_machine_as(None, wallet_public_key)
}

/// [`attest_local_machine`] for the identity `did`, when given: a machine
/// root whose DID derives from its own identity key (`controller_key`), which
/// records this TPM's attestation so the TPM is admitted under the machine's
/// one identity. Without `did`, the identity is the one the attestation key
/// roots.
#[cfg(any(target_os = "linux", windows))]
pub fn attest_local_machine_as(
    did: Option<&str>,
    wallet_public_key: &[u8],
) -> Result<(String, MachineAttestation)> {
    attest_local_machine_over(did, wallet_public_key, None)
}

/// [`attest_local_machine_as`] whose quote answers the admission challenge
/// over `nonce` when given (a chain challenge the attestation must answer),
/// or over a fresh random nonce.
#[cfg(any(target_os = "linux", windows))]
pub fn attest_local_machine_over(
    did: Option<&str>,
    wallet_public_key: &[u8],
    nonce: Option<[u8; 32]>,
) -> Result<(String, MachineAttestation)> {
    use tenzro_device_key::backend_tpm::TpmDevice;
    use tenzro_device_key::tpm_wire::DEFAULT_QUOTE_PCRS;
    let tpm = |e: tenzro_device_key::DeviceKeyError| fail(format!("TPM: {e}"));

    let mut dev = TpmDevice::open().map_err(tpm)?;
    let LocalKeys {
        ek,
        ek_handle,
        ek_certificate,
        ek_intermediates,
        ak,
        ak_handle,
    } = local_keys(&mut dev)?;

    let mut evidence = TpmEvidence {
        ek_public: ek.raw.clone(),
        ek_certificate: ek_certificate.clone(),
        ek_intermediates: ek_intermediates.clone(),
        ak_public: ak.raw.clone(),
        quote: Vec::new(),
        quote_signature: Vec::new(),
    };
    let mut secret = [0u8; 32];
    let mut random_nonce = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(&mut secret)
        .and_then(|_| rand::rngs::OsRng.try_fill_bytes(&mut random_nonce))
        .map_err(|e| fail(format!("OS RNG: {e}")))?;
    let nonce = nonce.unwrap_or(random_nonce);
    let ak_name = ak.name().map_err(|e| fail(e.to_string()))?;
    let credential = tenzro_device_key::credential::make_credential(ek, &ak_name, &secret)
        .map_err(|e| fail(e.to_string()))?;
    // The credential is encrypted to `ek`, so only the TPM holding that key
    // can release it, and only to the attestation key it names.
    let released = dev
        .activate_credential(
            *ak_handle,
            *ek_handle,
            ek,
            &credential.blob,
            &credential.encrypted_secret,
        )
        .map_err(tpm)?;
    if !activation_matches(&secret, &released) {
        return Err(fail(
            "the TPM did not release the credential for this attestation key",
        ));
    }

    let ak_sec1 = attestation_key(ak)?;
    let did = did.map_or_else(|| machine_did_for_attestation_key(&ak_sec1), str::to_string);
    let challenge = admission_challenge(&did, wallet_public_key, &nonce);
    let (quote, signature) = dev
        .quote(*ak_handle, &challenge, &DEFAULT_QUOTE_PCRS)
        .map_err(tpm)?;
    evidence.quote = quote;
    evidence.quote_signature = signature.to_vec();
    verify_quote(&evidence, &challenge)?;

    Ok((
        did,
        MachineAttestation {
            evidence,
            nonce: nonce.to_vec(),
            activated: true,
        },
    ))
}

/// Quote `extra_data` (at most 64 bytes, normally a digest) with this
/// machine's attestation key, for a statement the machine makes about itself
/// after it was admitted: no credential activation is run. Returns the
/// machine DID the attestation key roots and the evidence, whose quote is
/// verified before it is returned.
#[cfg(any(target_os = "linux", windows))]
pub fn quote_local_machine(extra_data: &[u8]) -> Result<(String, TpmEvidence)> {
    use tenzro_device_key::backend_tpm::TpmDevice;
    use tenzro_device_key::tpm_wire::DEFAULT_QUOTE_PCRS;
    let tpm = |e: tenzro_device_key::DeviceKeyError| fail(format!("TPM: {e}"));
    if extra_data.len() > 64 {
        return Err(fail("a quote carries at most 64 bytes of extra data"));
    }
    let mut dev = TpmDevice::open().map_err(tpm)?;
    let LocalKeys {
        ek,
        ek_certificate,
        ek_intermediates,
        ak,
        ak_handle,
        ..
    } = local_keys(&mut dev)?;
    let (quote, signature) = dev
        .quote(*ak_handle, extra_data, &DEFAULT_QUOTE_PCRS)
        .map_err(tpm)?;
    let evidence = TpmEvidence {
        ek_public: ek.raw.clone(),
        ek_certificate: ek_certificate.clone(),
        ek_intermediates: ek_intermediates.clone(),
        ak_public: ak.raw.clone(),
        quote,
        quote_signature: signature.to_vec(),
    };
    verify_quote(&evidence, extra_data)?;
    let did = machine_did_for_attestation_key(&attestation_key(ak)?);
    Ok((did, evidence))
}

/// This machine's endorsement key, its certificate and chain, and the
/// attestation key: all fixed for the life of the chip, so found once per
/// process. Later attestations and quotes cost only the commands that sign.
#[cfg(any(target_os = "linux", windows))]
struct LocalKeys {
    ek: tenzro_device_key::tpm_wire::PublicArea,
    /// Persistent handle of `ek`.
    ek_handle: u32,
    ek_certificate: Vec<u8>,
    ek_intermediates: Vec<Vec<u8>>,
    ak: tenzro_device_key::tpm_wire::PublicArea,
    ak_handle: u32,
}

#[cfg(any(target_os = "linux", windows))]
fn local_keys(dev: &mut tenzro_device_key::backend_tpm::TpmDevice) -> Result<&'static LocalKeys> {
    use tenzro_device_key::tpm_wire::{
        ATTESTATION_KEY_ATTRIBUTES, EK_ECC_PERSISTENT_HANDLE, NODE_ATTESTATION_HANDLE,
    };
    static LOCAL: std::sync::OnceLock<LocalKeys> = std::sync::OnceLock::new();
    if let Some(keys) = LOCAL.get() {
        return Ok(keys);
    }
    let tpm = |e: tenzro_device_key::DeviceKeyError| fail(format!("TPM: {e}"));
    let (ek, ek_handle, ek_certificate) = match certified_endorsement_key(dev) {
        Some(found) => found,
        // No manufacturer certificate for any key this TPM keeps: the
        // persistent ECC EK, graded uncertified.
        None => (
            dev.read_public(EK_ECC_PERSISTENT_HANDLE).map_err(tpm)?,
            EK_ECC_PERSISTENT_HANDLE,
            Vec::new(),
        ),
    };
    let ek_intermediates = if ek_certificate.is_empty() {
        Vec::new()
    } else {
        ek_chain(dev)
    };
    let ak = dev.read_public(NODE_ATTESTATION_HANDLE).map_err(|e| {
        fail(format!(
            "TPM: the attestation key 0x{NODE_ATTESTATION_HANDLE:08x} cannot be read ({e}); run \
             `tenzro-node tpm provision` once on this machine"
        ))
    })?;
    if ak.attributes != ATTESTATION_KEY_ATTRIBUTES {
        return Err(fail(format!(
            "TPM handle 0x{NODE_ATTESTATION_HANDLE:08x} is not an attestation key"
        )));
    }
    Ok(LOCAL.get_or_init(|| LocalKeys {
        ek,
        ek_handle,
        ek_certificate,
        ek_intermediates,
        ak,
        ak_handle: NODE_ATTESTATION_HANDLE,
    }))
}

/// The first endorsement key, in [`EK_PROFILES`] order, that this TPM keeps
/// at its persistent handle and holds a manufacturer certificate for:
/// `tenzro-node tpm provision` made it persistent there.
///
/// [`EK_PROFILES`]: tenzro_device_key::tpm_wire::EK_PROFILES
#[cfg(any(target_os = "linux", windows))]
fn certified_endorsement_key(
    dev: &mut tenzro_device_key::backend_tpm::TpmDevice,
) -> Option<(PublicArea, u32, Vec<u8>)> {
    tenzro_device_key::tpm_wire::EK_PROFILES
        .into_iter()
        .find_map(|profile| {
            let cert = dev.nv_read_all(profile.cert_index).ok()?;
            let public = dev.read_public(profile.persistent).ok()?;
            certificate_is_for(&cert, &public).then_some((public, profile.persistent, cert))
        })
}

/// The EK certificate chain the TPM carries in its chain NV indices (TCG EK
/// Credential Profile), each index holding one or more DER certificates.
/// Empty when the manufacturer stored none.
#[cfg(any(target_os = "linux", windows))]
fn ek_chain(dev: &mut tenzro_device_key::backend_tpm::TpmDevice) -> Vec<Vec<u8>> {
    use tenzro_device_key::tpm_wire::{EK_CHAIN_NV_FIRST, EK_CHAIN_NV_LAST};
    let mut out = Vec::new();
    for index in EK_CHAIN_NV_FIRST..=EK_CHAIN_NV_LAST {
        match dev.nv_read_all(index) {
            Ok(bytes) if !bytes.is_empty() => out.extend(split_der(&bytes)),
            _ => break,
        }
        if out.len() >= MAX_EK_INTERMEDIATES {
            out.truncate(MAX_EK_INTERMEDIATES);
            break;
        }
    }
    out
}

/// Split concatenated DER certificates, ignoring trailing NV padding.
pub fn split_der(mut bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while bytes.len() >= 2 && bytes[0] == 0x30 {
        let (len, head): (usize, usize) = match bytes[1] {
            n if n < 0x80 => (n as usize, 2),
            0x81 if bytes.len() >= 3 => (bytes[2] as usize, 3),
            0x82 if bytes.len() >= 4 => (u16::from_be_bytes([bytes[2], bytes[3]]) as usize, 4),
            _ => break,
        };
        let Some(end) = head.checked_add(len).filter(|e| *e <= bytes.len()) else {
            break;
        };
        out.push(bytes[..end].to_vec());
        bytes = &bytes[end..];
    }
    out
}

#[cfg(any(test, feature = "test-ca"))]
pub mod tests {
    //! The verifier is exercised against a software model of the TPM side:
    //! a P-256 EK and AK held in test memory, `TPM2_ActivateCredential`
    //! implemented from TPM 2.0 Part 1 section 24, and quotes marshalled the
    //! way Part 2 defines `TPMS_ATTEST`. They need no TPM, so they
    //! check the verifier's logic and its agreement with the
    //! specification, not interoperability with a particular chip.

    use super::*;
    use crate::x509::testca;
    use hmac::{Hmac, Mac};
    use tenzro_device_key::credential::{aes_cfb, kdf_a, kdf_e};
    // Only the tests below use it; the module is also built for `test-ca`.
    #[cfg(test)]
    use tenzro_device_key::credential::make_credential;

    type HmacSha256 = Hmac<Sha256>;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use tenzro_device_key::tpm_wire::*;

    pub const NOW: u64 = 1_800_000_000;

    /// PolicySecret(TPM_RH_ENDORSEMENT), the authPolicy of TCG EK templates.
    const EK_POLICY: [u8; 32] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7,
        0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14,
        0x69, 0xaa,
    ];

    pub struct SoftTpm {
        pub ek: p256::SecretKey,
        pub ak: SigningKey,
    }

    fn point(pk: &p256::PublicKey) -> ([u8; 32], [u8; 32]) {
        let s = pk.to_sec1_bytes();
        (s[1..33].try_into().unwrap(), s[33..65].try_into().unwrap())
    }

    impl SoftTpm {
        pub fn new(seed: u8) -> Self {
            Self {
                ek: p256::SecretKey::from_slice(&[seed; 32]).unwrap(),
                ak: SigningKey::from_slice(&[seed.wrapping_add(1); 32]).unwrap(),
            }
        }

        pub(crate) fn ek_public(&self) -> Vec<u8> {
            let (x, y) = point(&self.ek.public_key());
            let mut p = Writer::new();
            p.u16(TPM2_ALG_ECC).u16(TPM2_ALG_SHA256);
            p.u32(
                TPMA_OBJECT_FIXEDTPM
                    | TPMA_OBJECT_FIXEDPARENT
                    | TPMA_OBJECT_SENSITIVEDATAORIGIN
                    | TPMA_OBJECT_ADMINWITHPOLICY
                    | TPMA_OBJECT_RESTRICTED
                    | TPMA_OBJECT_DECRYPT,
            );
            p.tpm2b(&EK_POLICY);
            p.u16(TPM2_ALG_AES).u16(128).u16(TPM2_ALG_CFB);
            p.u16(TPM2_ALG_NULL)
                .u16(TPM2_ECC_NIST_P256)
                .u16(TPM2_ALG_NULL);
            p.tpm2b(&x).tpm2b(&y);
            p.finish()
        }

        pub fn ak_public(&self) -> Vec<u8> {
            let (x, y) = point(&p256::PublicKey::from(self.ak.verifying_key()));
            let mut p = Writer::new();
            p.u16(TPM2_ALG_ECC).u16(TPM2_ALG_SHA256);
            p.u32(ATTESTATION_KEY_ATTRIBUTES);
            p.tpm2b(&[]);
            p.u16(TPM2_ALG_NULL);
            p.u16(TPM2_ALG_ECDSA).u16(TPM2_ALG_SHA256);
            p.u16(TPM2_ECC_NIST_P256).u16(TPM2_ALG_NULL);
            p.tpm2b(&x).tpm2b(&y);
            p.finish()
        }

        pub(crate) fn ak_name(&self) -> Vec<u8> {
            parse_public(&self.ak_public()).unwrap().name().unwrap()
        }

        /// `TPM2_ActivateCredential`: refuses unless `loaded_name` is the
        /// name the credential was made for.
        pub fn activate(&self, loaded_name: &[u8], cred: &Credential) -> Option<Vec<u8>> {
            let mut r = Reader::new(&cred.encrypted_secret);
            let ex = r.tpm2b().ok()?.to_vec();
            let ey = r.tpm2b().ok()?.to_vec();
            let mut sec1 = vec![0x04];
            sec1.extend_from_slice(&ex);
            sec1.extend_from_slice(&ey);
            let eph = p256::PublicKey::from_sec1_bytes(&sec1).ok()?;
            let z = p256::ecdh::diffie_hellman(self.ek.to_nonzero_scalar(), eph.as_affine());
            let (ekx, _) = point(&self.ek.public_key());
            let seed = kdf_e(z.raw_secret_bytes().as_slice(), "IDENTITY", &ex, &ekx, 256);
            let mut b = Reader::new(&cred.blob);
            let hmac = b.tpm2b().ok()?.to_vec();
            let enc_identity = b.take(b.remaining()).ok()?.to_vec();
            let hmac_key = kdf_a(&seed, "INTEGRITY", &[], &[], 256);
            let mut mac = HmacSha256::new_from_slice(&hmac_key).unwrap();
            mac.update(&enc_identity);
            mac.update(loaded_name);
            mac.verify_slice(&hmac).ok()?;
            let sym = kdf_a(&seed, "STORAGE", loaded_name, &[], 128);
            let plain = aes_cfb(&sym, &enc_identity, false).ok()?;
            Some(Reader::new(&plain).tpm2b().ok()?.to_vec())
        }

        pub(crate) fn quote(&self, extra: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let mut a = Writer::new();
            a.u32(TPM2_GENERATED_VALUE).u16(TPM2_ST_ATTEST_QUOTE);
            a.tpm2b(&endorsement_primary_qualified_name(&self.ak_name()));
            a.tpm2b(extra);
            a.bytes(&42u64.to_be_bytes()).u32(3).u32(0).u8(1);
            a.bytes(&7u64.to_be_bytes());
            a.u32(1)
                .u16(TPM2_ALG_SHA256)
                .u8(3)
                .bytes(&DEFAULT_QUOTE_PCRS);
            a.tpm2b(&[0xAB; 32]);
            let attest = a.finish();
            let digest: [u8; 32] = Sha256::digest(&attest).into();
            let sig: p256::ecdsa::Signature = self.ak.sign_prehash(&digest).unwrap();
            (attest, sig.to_bytes().to_vec())
        }

        /// An ML-DSA-65 key's public area as a TPM 2.0 library v1.85 TPM
        /// reports it; restricted when it is an attestation key.
        pub fn ml_dsa_public(key: &[u8], attestation_key: bool) -> Vec<u8> {
            let attributes = if attestation_key {
                ATTESTATION_KEY_ATTRIBUTES
            } else {
                SIGNING_KEY_ATTRIBUTES
            };
            let mut w = Writer::new();
            w.u16(TPM2_ALG_MLDSA).u16(TPM2_ALG_SHA256);
            w.u32(attributes);
            w.tpm2b(&[]);
            w.u16(TPM2_MLDSA_65);
            w.u8(0);
            w.tpm2b(key);
            w.finish()
        }

        /// `TPM2_Certify` of the object `key_public` by the attestation key
        /// over `extra`: the `TPMS_ATTEST` and its signature.
        pub fn certify(&self, key_public: &[u8], extra: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let name = parse_public(key_public).unwrap().name().unwrap();
            let mut a = Writer::new();
            a.u32(TPM2_GENERATED_VALUE).u16(TPM2_ST_ATTEST_CERTIFY);
            a.tpm2b(&endorsement_primary_qualified_name(&self.ak_name()));
            a.tpm2b(extra);
            a.bytes(&42u64.to_be_bytes()).u32(3).u32(0).u8(1);
            a.bytes(&7u64.to_be_bytes());
            a.tpm2b(&name).tpm2b(&name);
            let attest = a.finish();
            let digest: [u8; 32] = Sha256::digest(&attest).into();
            let sig: p256::ecdsa::Signature = self.ak.sign_prehash(&digest).unwrap();
            (attest, sig.to_bytes().to_vec())
        }
    }

    /// A manufacturer root and an EK certificate it issued for `tpm`'s EK.
    pub(crate) fn endorsed(tpm: &SoftTpm) -> (Cert, Vec<u8>) {
        use spki::EncodePublicKey;
        let root_k = testca::key(40);
        let root = x509::parse(&testca::issue(
            "TPM Root", &root_k, "TPM Root", &root_k, true, 1,
        ))
        .unwrap();
        let spki = tpm.ek.public_key().to_public_key_der().unwrap();
        let ek_cert = testca::issue_with_spki(
            "EK",
            spki.as_bytes(),
            "TPM Root",
            &root_k,
            false,
            2,
            (1_000_000_000, 4_000_000_000),
            &[],
        );
        (root, ek_cert)
    }

    /// `cert` as PEM, the form governance records endorsement roots in.
    pub fn pem(cert: &Cert) -> String {
        use base64::Engine;
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(&cert.der)
        )
    }

    pub fn evidence(tpm: &SoftTpm, extra: &[u8]) -> (TpmEvidence, Cert) {
        let (root, ek_cert) = endorsed(tpm);
        let (quote, sig) = tpm.quote(extra);
        (
            TpmEvidence {
                ek_public: tpm.ek_public(),
                ek_certificate: ek_cert,
                ek_intermediates: vec![],
                ak_public: tpm.ak_public(),
                quote,
                quote_signature: sig,
            },
            root,
        )
    }

    /// Endorsement chain, then the quote.
    #[cfg(test)]
    fn verify_evidence(
        ev: &TpmEvidence,
        roots: &[Cert],
        challenge: &[u8],
        now: u64,
    ) -> Result<VerifiedTpmQuote> {
        verify_endorsement(ev, roots, now)?;
        verify_quote(ev, challenge)
    }

    /// A TPM without a manufacturer certificate still proves its quote; the
    /// missing certificate only lowers its endorsement grade.
    #[test]
    fn an_uncertified_tpm_is_graded_not_refused() {
        let tpm = SoftTpm::new(3);
        let c = admission_challenge("did:a", b"w", &[1; 32]);
        let (mut ev, root) = evidence(&tpm, &c);
        let certified = MachineAttestation {
            evidence: ev.clone(),
            nonce: vec![1; 32],
            activated: true,
        };
        assert_eq!(
            endorsement_grade(&certified, std::slice::from_ref(&root), NOW),
            EndorsementGrade::ManufacturerCertified
        );
        ev.ek_certificate = Vec::new();
        assert!(verify_quote(&ev, &c).is_ok());
        let bare = MachineAttestation {
            evidence: ev,
            nonce: vec![1; 32],
            activated: true,
        };
        assert!(matches!(
            endorsement_grade(&bare, &[root], NOW),
            EndorsementGrade::Uncertified(_)
        ));
    }

    #[test]
    fn activation_releases_the_secret_only_to_the_named_key() {
        let tpm = SoftTpm::new(3);
        let ek = parse_public(&tpm.ek_public()).unwrap();
        let cred = make_credential(&ek, &tpm.ak_name(), b"fresh verifier secret").unwrap();
        assert_eq!(
            tpm.activate(&tpm.ak_name(), &cred).unwrap(),
            b"fresh verifier secret"
        );
        let other = SoftTpm::new(9);
        assert!(
            tpm.activate(&other.ak_name(), &cred).is_none(),
            "a credential must not open for a different attestation key"
        );
        let wrong_ek = SoftTpm::new(11);
        assert!(wrong_ek.activate(&tpm.ak_name(), &cred).is_none());
    }

    #[test]
    fn genuine_evidence_verifies() {
        let tpm = SoftTpm::new(3);
        let challenge = admission_challenge("did:tenzro:machine:x", b"wallet", &[5; 32]);
        let (ev, root) = evidence(&tpm, &challenge);
        let v = verify_evidence(&ev, &[root], &challenge, NOW).unwrap();
        assert_eq!(
            v.ek_name,
            parse_public(&tpm.ek_public()).unwrap().name().unwrap()
        );
        assert_eq!(v.pcr_digest, vec![0xAB; 32]);
    }

    #[test]
    fn a_quote_over_another_challenge_is_refused() {
        let tpm = SoftTpm::new(3);
        let c1 = admission_challenge("did:a", b"w", &[1; 32]);
        let c2 = admission_challenge("did:a", b"w", &[2; 32]);
        let (ev, root) = evidence(&tpm, &c1);
        assert!(verify_evidence(&ev, &[root], &c2, NOW).is_err());
    }

    #[test]
    fn a_self_issued_ek_certificate_does_not_chain_to_a_manufacturer() {
        let tpm = SoftTpm::new(3);
        let c = admission_challenge("did:a", b"w", &[1; 32]);
        let (mut ev, root) = evidence(&tpm, &c);
        // Self-issue an EK certificate under an attacker root with the same name.
        let fake_root_k = testca::key(66);
        use spki::EncodePublicKey;
        let spki = tpm.ek.public_key().to_public_key_der().unwrap();
        ev.ek_certificate = testca::issue_with_spki(
            "EK",
            spki.as_bytes(),
            "TPM Root",
            &fake_root_k,
            false,
            2,
            (1_000_000_000, 4_000_000_000),
            &[],
        );
        assert!(verify_evidence(&ev, &[root], &c, NOW).is_err());
    }

    #[test]
    fn an_ek_certificate_for_another_key_is_refused() {
        let tpm = SoftTpm::new(3);
        let other = SoftTpm::new(20);
        let c = admission_challenge("did:a", b"w", &[1; 32]);
        let (mut ev, root) = evidence(&tpm, &c);
        let (_, other_cert) = endorsed(&other);
        ev.ek_certificate = other_cert;
        assert!(verify_endorsement(&ev, &[root], NOW).is_err());
    }

    #[test]
    fn a_forged_quote_signature_is_refused() {
        let tpm = SoftTpm::new(3);
        let c = admission_challenge("did:a", b"w", &[1; 32]);
        let (mut ev, root) = evidence(&tpm, &c);
        let attacker = SoftTpm::new(30);
        let (q, s) = attacker.quote(&c);
        ev.quote = q;
        ev.quote_signature = s;
        assert!(verify_evidence(&ev, &[root], &c, NOW).is_err());
    }

    /// An ML-DSA key the TPM holds, restricted and signing, is refused as an
    /// attestation key with the reason: quotes are checked as ECDSA P-256.
    #[test]
    fn an_ml_dsa_attestation_key_is_refused_with_the_reason() {
        let ak = PublicArea {
            raw: Vec::new(),
            alg: TPM2_ALG_MLDSA,
            name_alg: TPM2_ALG_SHA256,
            attributes: TPMA_OBJECT_FIXEDTPM
                | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN
                | TPMA_OBJECT_RESTRICTED
                | TPMA_OBJECT_SIGN_ENCRYPT,
            auth_policy: Vec::new(),
            symmetric: None,
            key: PublicKey::MlDsa {
                parameter_set: 3,
                allow_external_mu: false,
                key: vec![7; 2592],
            },
        };
        let err = attestation_key(&ak).unwrap_err().to_string();
        assert!(err.contains("ML-DSA"), "{err}");
    }

    #[test]
    fn an_unrestricted_key_cannot_stand_in_for_an_attestation_key() {
        // An unrestricted signing key can sign any digest, including a forged
        // TPMS_ATTEST; the verifier must refuse it as an attestation key.
        let tpm = SoftTpm::new(3);
        let c = admission_challenge("did:a", b"w", &[1; 32]);
        let (mut ev, root) = evidence(&tpm, &c);
        let ak = parse_public(&ev.ak_public).unwrap();
        let (x, y) = match ak.key {
            PublicKey::EccP256 { x, y, .. } => (x, y),
            _ => unreachable!(),
        };
        let mut p = Writer::new();
        p.u16(TPM2_ALG_ECC)
            .u16(TPM2_ALG_SHA256)
            .u32(SIGNING_KEY_ATTRIBUTES)
            .tpm2b(&[]);
        p.u16(TPM2_ALG_NULL)
            .u16(TPM2_ALG_ECDSA)
            .u16(TPM2_ALG_SHA256);
        p.u16(TPM2_ECC_NIST_P256)
            .u16(TPM2_ALG_NULL)
            .tpm2b(&x)
            .tpm2b(&y);
        ev.ak_public = p.finish();
        assert!(verify_evidence(&ev, &[root], &c, NOW).is_err());
    }

    #[test]
    fn kdfa_matches_its_definition() {
        // KDFa with one iteration is HMAC(key, 1 || label || 0 || u || v || bits).
        let out = kdf_a(b"k", "STORAGE", b"u", b"v", 128);
        let mut mac = HmacSha256::new_from_slice(b"k").unwrap();
        mac.update(&1u32.to_be_bytes());
        mac.update(b"STORAGE\0uv");
        mac.update(&128u32.to_be_bytes());
        assert_eq!(out, mac.finalize().into_bytes()[..16].to_vec());
    }

    #[test]
    fn cfb_round_trips_with_a_partial_block() {
        let key = [7u8; 16];
        let data = b"thirty-three bytes of plaintext!!";
        let ct = aes_cfb(&key, data, true).unwrap();
        assert_ne!(&ct[..], &data[..]);
        assert_eq!(aes_cfb(&key, &ct, false).unwrap(), data.to_vec());
    }
}

/// Endorsement keys of every supported type (ECC P-256, ECC P-384, RSA-2048,
/// RSA-3072), each certified through a test CA that is generated here and
/// exists only in these tests.
#[cfg(test)]
mod endorsement_key_types {
    use super::tests::{NOW, SoftTpm};
    use super::*;
    use crate::x509::testca;
    use tenzro_device_key::credential::make_credential;
    use tenzro_device_key::tpm_wire::*;

    /// `template` with its unique field(s) replaced by the key.
    fn ek_area(template: Vec<u8>, unique: &[&[u8]]) -> Vec<u8> {
        let empty_len = match parse_public(&template).unwrap().key {
            PublicKey::Rsa { modulus, .. } => 2 + modulus.len(),
            PublicKey::EccP256 { .. } => 2 + 32 + 2 + 32,
            PublicKey::EccP384 { .. } => 4,
            PublicKey::MlDsa { key, .. } => 2 + key.len(),
        };
        let mut out = template[..template.len() - empty_len].to_vec();
        let mut w = Writer::new();
        for u in unique {
            w.tpm2b(u);
        }
        out.extend_from_slice(&w.finish());
        out
    }

    /// An EK's `TPMT_PUBLIC` and the SPKI its certificate carries.
    struct Ek {
        public: Vec<u8>,
        spki: Vec<u8>,
    }

    fn p256_ek(seed: u8) -> Ek {
        use spki::EncodePublicKey;
        let pk = p256::SecretKey::from_slice(&[seed; 32])
            .unwrap()
            .public_key();
        let sec1 = pk.to_sec1_bytes();
        Ek {
            public: ek_area(ek_ecc_template(), &[&sec1[1..33], &sec1[33..]]),
            spki: pk.to_public_key_der().unwrap().as_bytes().to_vec(),
        }
    }

    fn p384_ek(seed: u8) -> Ek {
        use spki::EncodePublicKey;
        let pk = p384::SecretKey::from_slice(&[seed; 48])
            .unwrap()
            .public_key();
        let sec1 = pk.to_sec1_bytes();
        Ek {
            public: ek_area(ek_ecc_p384_template(), &[&sec1[1..49], &sec1[49..]]),
            spki: pk.to_public_key_der().unwrap().as_bytes().to_vec(),
        }
    }

    fn rsa_ek(bits: usize, seed: u64) -> Ek {
        use rand::SeedableRng;
        use rsa::pkcs8::EncodePublicKey;
        use rsa::traits::PublicKeyParts;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let pk = rsa::RsaPrivateKey::new(&mut rng, bits)
            .unwrap()
            .to_public_key();
        let template = if bits == 2048 {
            ek_rsa2048_template()
        } else {
            ek_rsa3072_template()
        };
        Ek {
            public: ek_area(template, &[&pk.n().to_bytes_be()]),
            spki: pk.to_public_key_der().unwrap().as_bytes().to_vec(),
        }
    }

    /// A test manufacturer: a root, an intermediate it issued, and an EK
    /// certificate the intermediate issued for `spki`.
    fn manufacturer(
        seed: u8,
        spki: &[u8],
        leaf_ext: &[(&str, Vec<u8>)],
    ) -> (Cert, Vec<u8>, Vec<u8>) {
        let root_k = testca::key(seed);
        let int_k = testca::key(seed + 1);
        let root = x509::parse(&testca::issue(
            "Test TPM Root",
            &root_k,
            "Test TPM Root",
            &root_k,
            true,
            1,
        ))
        .unwrap();
        let int = testca::issue("Test TPM EK CA", &int_k, "Test TPM Root", &root_k, true, 2);
        let leaf = testca::issue_with_spki(
            "",
            spki,
            "Test TPM EK CA",
            &int_k,
            false,
            3,
            (1_000_000_000, 4_000_000_000),
            leaf_ext,
        );
        (root, int, leaf)
    }

    #[test]
    fn ek_certificate_profile_reads_the_tcg_manufacturer_and_specification() {
        let mut der = vec![0x30, 0x00, 0x01];
        der.extend_from_slice(super::TCG_TPM_MANUFACTURER);
        der.push(0x0C);
        der.push(11);
        der.extend_from_slice(b"id:494E5443");
        der.extend_from_slice(&[0x05, 0x00]);
        der.extend_from_slice(super::TCG_TPM_SPECIFICATION);
        der.extend_from_slice(&[
            0x31, 0x0E, 0x30, 0x0C, 0x0C, 0x03, b'2', b'.', b'0', 0x02, 0x01, 0x00, 0x02, 0x02,
            0x00, 0x8A,
        ]);
        assert_eq!(
            super::ek_certificate_profile(&der),
            ("id:494E5443".to_string(), "2.0/0/138".to_string())
        );
        // A certificate that names neither leaves both empty.
        assert_eq!(
            super::ek_certificate_profile(&[0x30, 0x03, 0x02, 0x01, 0x00]),
            (String::new(), String::new())
        );
    }

    fn evidence(ek: &Ek, leaf: Vec<u8>, intermediates: Vec<Vec<u8>>) -> TpmEvidence {
        let tpm = SoftTpm::new(5);
        let (quote, quote_signature) = tpm.quote(b"challenge");
        TpmEvidence {
            ek_public: ek.public.clone(),
            ek_certificate: leaf,
            ek_intermediates: intermediates,
            ak_public: tpm.ak_public(),
            quote,
            quote_signature,
        }
    }

    fn all_types() -> Vec<(&'static str, Ek)> {
        vec![
            ("P-256", p256_ek(11)),
            ("P-384", p384_ek(12)),
            ("RSA-2048", rsa_ek(2048, 13)),
            ("RSA-3072", rsa_ek(3072, 14)),
        ]
    }

    #[test]
    fn every_endorsement_key_type_chains_to_its_manufacturer_root() {
        for (kind, ek) in all_types() {
            let (root, int, leaf) = manufacturer(60, &ek.spki, &[]);
            let ev = evidence(&ek, leaf, vec![int]);
            assert!(
                verify_endorsement(&ev, std::slice::from_ref(&root), NOW).is_ok(),
                "{kind}"
            );
            assert!(certificate_is_for(
                &ev.ek_certificate,
                &parse_public(&ek.public).unwrap()
            ));
            let att = MachineAttestation {
                evidence: ev,
                nonce: vec![1; 32],
                activated: true,
            };
            assert_eq!(
                endorsement_grade(&att, &[root], NOW),
                EndorsementGrade::ManufacturerCertified,
                "{kind}"
            );
        }
    }

    #[test]
    fn a_chain_to_a_root_the_network_does_not_recognise_is_refused() {
        for (kind, ek) in all_types() {
            let (_, int, leaf) = manufacturer(60, &ek.spki, &[]);
            let (other_root, _, _) = manufacturer(70, &ek.spki, &[]);
            let ev = evidence(&ek, leaf.clone(), vec![int]);
            let err = verify_endorsement(&ev, &[other_root], NOW).unwrap_err();
            assert!(
                err.to_string().contains("manufacturer root"),
                "{kind}: {err}"
            );
            // Without its intermediate the certificate reaches no root either.
            let (root, _, _) = manufacturer(60, &ek.spki, &[]);
            assert!(verify_endorsement(&evidence(&ek, leaf, vec![]), &[root], NOW).is_err());
        }
    }

    #[test]
    fn a_certificate_for_another_key_is_refused() {
        let pairs = [
            (p384_ek(12), p384_ek(15)),
            (rsa_ek(2048, 13), rsa_ek(2048, 16)),
            (p384_ek(12), rsa_ek(2048, 13)),
            (rsa_ek(2048, 13), p256_ek(11)),
            (p256_ek(11), p384_ek(12)),
        ];
        for (held, certified) in pairs {
            let (root, int, leaf) = manufacturer(60, &certified.spki, &[]);
            let ev = evidence(&held, leaf, vec![int]);
            let err = verify_endorsement(&ev, &[root], NOW).unwrap_err();
            assert!(err.to_string().contains("different key"), "{err}");
            assert!(!certificate_is_for(
                &ev.ek_certificate,
                &parse_public(&held.public).unwrap()
            ));
        }
    }

    #[test]
    fn the_credential_is_encrypted_to_the_certified_key_only() {
        // The verifier encrypts to the EK the evidence names; a credential
        // for one EK is useless to a TPM holding another, so activation
        // proves the attestation key sits beside the certified key.
        let ak = SoftTpm::new(5);
        for (kind, ek) in all_types() {
            let area = parse_public(&ek.public).unwrap();
            let cred = make_credential(&area, &ak.ak_name(), &[3; 32]).unwrap();
            // The P-256 software TPM holds a different EK: it cannot release it.
            assert_eq!(ak.activate(&ak.ak_name(), &cred), None, "{kind}");
        }
    }

    #[test]
    fn intermediates_are_taken_in_issuing_order_whatever_order_they_arrive_in() {
        let ek = p384_ek(12);
        let root_k = testca::key(80);
        let a_k = testca::key(81);
        let b_k = testca::key(82);
        let root = x509::parse(&testca::issue("R", &root_k, "R", &root_k, true, 1)).unwrap();
        let a = testca::issue("A", &a_k, "R", &root_k, true, 2);
        let b = testca::issue("B", &b_k, "A", &a_k, true, 3);
        let leaf = testca::issue_with_spki(
            "",
            &ek.spki,
            "B",
            &b_k,
            false,
            4,
            (1_000_000_000, 4_000_000_000),
            &[],
        );
        let unrelated = testca::issue("C", &testca::key(83), "R", &root_k, true, 5);
        let ev = evidence(&ek, leaf, vec![a, unrelated, b]);
        assert!(verify_endorsement(&ev, &[root], NOW).is_ok());
    }

    #[test]
    fn the_missing_issuer_is_named_by_the_top_certificate() {
        use der::Encode;
        use x509_cert::ext::pkix::name::GeneralName;
        use x509_cert::ext::pkix::{AccessDescription, AuthorityInfoAccessSyntax};
        let url = "https://tpm.example/ek-ca.cer";
        let aia = AuthorityInfoAccessSyntax(vec![AccessDescription {
            access_method: "1.3.6.1.5.5.7.48.2".parse().unwrap(),
            access_location: GeneralName::UniformResourceIdentifier(
                der::asn1::Ia5String::new(url).unwrap(),
            ),
        }])
        .to_der()
        .unwrap();
        let ek = rsa_ek(2048, 13);
        let (root, int, leaf) = manufacturer(60, &ek.spki, &[("1.3.6.1.5.5.7.1.1", aia)]);
        let bare = evidence(&ek, leaf.clone(), vec![]);
        assert_eq!(
            missing_issuer_url(&bare, std::slice::from_ref(&root)).as_deref(),
            Some(url)
        );
        let complete = evidence(&ek, leaf, vec![int]);
        assert_eq!(missing_issuer_url(&complete, &[root]), None);
    }

    #[test]
    fn concatenated_chain_certificates_split_and_padding_is_ignored() {
        let a = testca::issue("A", &testca::key(1), "A", &testca::key(1), true, 1);
        let b = testca::issue("B", &testca::key(2), "A", &testca::key(1), true, 2);
        let mut nv = [a.clone(), b.clone()].concat();
        nv.extend_from_slice(&[0xFF; 17]);
        assert_eq!(split_der(&nv), vec![a, b]);
        assert!(split_der(&[0xFF; 8]).is_empty());
    }

    /// The swtpm half of scripts/testnet/swtpm-ek-admission.sh (PRIVATE
    /// TEST ONLY): the EK certificate swtpm's test CA issued chains to that
    /// CA's root and carries the EK provisioning kept.
    #[test]
    #[ignore]
    fn swtpm_ek_certificate_chains_to_its_test_ca() {
        let dir = std::path::PathBuf::from(std::env::var("TENZRO_TEST_SWTPM_OUT").unwrap());
        let read = |f: &str| std::fs::read(dir.join(f)).unwrap();
        let roots = parse_roots(&[String::from_utf8(read("root.pem")).unwrap()]).unwrap();
        let intermediates =
            x509::parse_pem_chain(&String::from_utf8(read("intermediate.pem")).unwrap())
                .unwrap()
                .into_iter()
                .map(|c| c.der)
                .collect();
        let ev = TpmEvidence {
            ek_public: read("ek_public.bin"),
            ek_certificate: read("ek_cert.der"),
            ek_intermediates: intermediates,
            ak_public: vec![],
            quote: vec![],
            quote_signature: vec![],
        };
        let now = chrono::Utc::now().timestamp() as u64;
        verify_endorsement(&ev, &roots, now).unwrap();
        let k = testca::key(90);
        let other_root =
            x509::parse(&testca::issue("Other Root", &k, "Other Root", &k, true, 1)).unwrap();
        assert!(verify_endorsement(&ev, &[other_root], now).is_err());
    }

    /// Nuvoton's published ECC P-521 root and the P-384 CA it issued, which
    /// issues the EK certificates of current Nuvoton TPMs: the root signs
    /// with ECDSA P-521 over SHA-512.
    const NUVOTON_ECC521_ROOT: &str = concat!(
        "MIICaTCCAcugAwIBAgIBAjAKBggqhkjOPQQDBDBWMR4wHAYDVQQDExVOUENUeHh4IEVDQzUyMSBSb290Q0ExJzAl",
        "BgNVBAoTHk51dm90b24gVGVjaG5vbG9neSBDb3Jwb3JhdGlvbjELMAkGA1UEBhMCVFcwIBcNMjMwNDI3MTYzNjU4",
        "WhgPMjA1MzA0MjcxNjM2NThaMFYxHjAcBgNVBAMTFU5QQ1R4eHggRUNDNTIxIFJvb3RDQTEnMCUGA1UEChMeTnV2",
        "b3RvbiBUZWNobm9sb2d5IENvcnBvcmF0aW9uMQswCQYDVQQGEwJUVzCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAE",
        "ASz6kM8At31gsD5vmtly3qL5fnciN3Qtmichas8CB8aW2tciXco/WkOYS71M4gxXaIYA5qy3w7ld25FsSdQzki5f",
        "Acgl+CldDPIQB8MovrHCD2W9HPWEccFT3cuJbtwXLyZhAa/pML5cRdkZk3SkOlm7YqLgoOTDH6vUs/fqZjsloy+e",
        "o0UwQzAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUrZPISsSIxh9TsMrewF7u",
        "n+M/CM0wCgYIKoZIzj0EAwQDgYsAMIGHAkIBOEEErw+Y4yMWsXAadaSW6xd/mBVGsXqhMpzj4papN/7GqjXDfuK9",
        "MgsZ7Px8flVvyCwklFaQ3BAmW4tfyl4N9L0CQUkCk38aTqb9ujPyxEr992ohb/fNk4fcaU9h6ghtC0Rwjye33dZG",
        "+uuCoD+UJPXnbELFsVIno4CMU5wrbN/pjkTT",
    );
    const NUVOTON_ECC384_LEAF_CA_022110: &str = concat!(
        "MIIC1jCCAjigAwIBAgIEAgIhEDAKBggqhkjOPQQDAzBWMR4wHAYDVQQDExVOUENUeHh4IEVDQzUyMSBSb290Q0Ex",
        "JzAlBgNVBAoTHk51dm90b24gVGVjaG5vbG9neSBDb3Jwb3JhdGlvbjELMAkGA1UEBhMCVFcwIBcNMjMwNTA0MDgx",
        "NjU5WhgPMjA1MzA1MDQwODE2NTlaMF0xJTAjBgNVBAMMHE5QQ1R4eHggRUNDMzg0IExlYWZDQSAwMjIxMTAxJzAl",
        "BgNVBAoMHk51dm90b24gVGVjaG5vbG9neSBDb3Jwb3JhdGlvbjELMAkGA1UEBhMCVFcwdjAQBgcqhkjOPQIBBgUr",
        "gQQAIgNiAASIHQQDw2xzJUdNV4bshpfFBNYCPqqiT1kkG2bBMOEL02yBAmbFeaMwESmdJ9cKCdyCk8dtYdLfva6a",
        "jqKPEccUd3XcGn1361sQ1T8XFBoFNUHtI6ZxGmWfqIo8b4SOtOOjgc0wgcowEgYDVR0TAQH/BAgwBgEB/wIBATAf",
        "BgNVHSMEGDAWgBStk8hKxIjGH1Owyt7AXu6f4z8IzTAdBgNVHQ4EFgQUYdGdoitPiP7irsQRRt7oZxXRyhUwZAYI",
        "KwYBBQUHAQEEWDBWMFQGCCsGAQUFBzAChkhodHRwczovL3d3dy5udXZvdG9uLmNvbS9zZWN1cml0eS9OVEMtVFBN",
        "LUVLLUNlcnQvTlBDVHh4eEVDQzUyMVJvb3RDQS5jZXIwDgYDVR0PAQH/BAQDAgIEMAoGCCqGSM49BAMDA4GLADCB",
        "hwJCAeE/POGXQq5QgzsiX9nELY1k8CNlcVTmKB+hghYVI935vdLb5LczbUzaw04++6M9jzerk0ye1fxVRjAgL9kn",
        "4bhgAkFvnJQdehic2aRHDVEHKrJiA3tBvVRmCpGycyEiS7uwDkwGMzJcQxjX1CJt88kQdZquEvNd1MZzRrNv4TS3",
        "qTmMrw==",
    );

    #[test]
    fn a_p521_vendor_root_verifies_its_p384_issuing_ca() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let root = x509::parse(&b64.decode(NUVOTON_ECC521_ROOT).unwrap()).unwrap();
        let ca = x509::parse(&b64.decode(NUVOTON_ECC384_LEAF_CA_022110).unwrap()).unwrap();
        assert_eq!(
            x509::verify_chain(std::slice::from_ref(&ca), std::slice::from_ref(&root), NOW)
                .unwrap(),
            0
        );
        // A changed signature byte breaks it.
        let mut forged = ca.clone();
        let last = forged.signature.len() - 3;
        forged.signature[last] ^= 1;
        assert!(x509::verify_chain(&[forged], &[root], NOW).is_err());
    }
}
