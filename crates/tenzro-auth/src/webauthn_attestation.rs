//! Verifying what a WebAuthn registration actually proves about the device.
//!
//! A registration carries an attestation object: the authenticator's own
//! statement about the credential it just made, signed, and (depending on the
//! format) a certificate chain from the vendor vouching for the hardware that
//! holds it. This module verifies that statement as WebAuthn Level 3 section
//! 8 defines it and turns the result into a graded
//! [`tenzro_types::device_binding::AttestationEvidence`].
//!
//! # What is checked
//!
//! - The attestation signature, over `authenticatorData || clientDataHash`,
//!   so the statement is bound to this registration's challenge. A statement
//!   whose signature does not verify is refused, not downgraded.
//! - For every format with a certificate chain, each link by *signature* up
//!   to one of the roots passed in, and the credential public key's binding to
//!   the leaf (the leaf is the credential key for `apple` and `android-key`;
//!   for `tpm` the certified public area is the credential key; for `packed`
//!   the leaf is the attestation key that signed).
//! - Self-attestation (`packed` with no chain) is checked against the
//!   credential key itself: it proves possession, not hardware.
//!
//! # What is graded, and what is not trusted
//!
//! Nothing grades as hardware-bound unless its chain verifies by signature to
//! a supplied root. With no roots supplied, devices still bind, but none
//! counts as hardware-bound. Which roots count is not decided here.
//!
//! The flags, signature counter and AAGUID come out of `authenticatorData`,
//! which the authenticator signed, not from anything the client says.

use sha2::{Digest, Sha256};
use tenzro_types::device_binding::{Aaguid, AttestationEvidence, AttestationFormat, KeyProtection};

/// Bit positions in the `authenticatorData` flags byte, per the WebAuthn spec.
mod flag {
    pub const UP: u8 = 0x01;
    pub const UV: u8 = 0x04;
    pub const BE: u8 = 0x08;
    pub const BS: u8 = 0x10;
    pub const AT: u8 = 0x40;
}

const ANDROID_KEY_ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";
const APPLE_NONCE_OID: &str = "1.2.840.113635.100.8.2";
const FIDO_AAGUID_OID: &str = "1.3.6.1.4.1.45724.1.1.4";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";

const RP_ID_HASH_LEN: usize = 32;
const FLAGS_OFFSET: usize = RP_ID_HASH_LEN;
const COUNTER_OFFSET: usize = FLAGS_OFFSET + 1;
const ATTESTED_DATA_OFFSET: usize = COUNTER_OFFSET + 4;

/// Why an attestation object was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// The CBOR structure or a field in it is not what WebAuthn defines.
    Malformed(String),
    /// `authenticatorData` is shorter than its fixed fields.
    TruncatedAuthData,
    /// An attestation statement format this build does not verify.
    UnknownFormat(String),
    /// Backed up (BS) set on a credential that is not backup eligible (BE).
    ContradictoryBackupFlags,
    /// Registration carried no attested credential data.
    NoCredential,
    /// The attestation signature does not verify over this registration.
    BadSignature(String),
    /// The statement does not bind the credential key it registers.
    KeyMismatch(String),
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "attestation object is malformed: {why}"),
            Self::TruncatedAuthData => write!(
                f,
                "authenticatorData is shorter than the fields WebAuthn requires it to contain"
            ),
            Self::UnknownFormat(fmt) => write!(
                f,
                "attestation statement format '{fmt}' is not one this build can verify; it is \
                 refused rather than treated as unattested"
            ),
            Self::ContradictoryBackupFlags => write!(
                f,
                "the authenticator reported that this credential cannot be backed up and that it \
                 is backed up"
            ),
            Self::NoCredential => write!(f, "the registration carries no credential"),
            Self::BadSignature(why) => write!(f, "attestation signature is invalid: {why}"),
            Self::KeyMismatch(why) => {
                write!(
                    f,
                    "attestation does not bind the registered credential key: {why}"
                )
            }
        }
    }
}

impl std::error::Error for AttestationError {}

/// A registered credential's public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialKey {
    /// Uncompressed SEC1 P-256 point.
    P256([u8; 65]),
    /// RSA public key.
    Rsa {
        /// Modulus, big-endian.
        n: Vec<u8>,
        /// Public exponent, big-endian.
        e: Vec<u8>,
    },
}

/// What a verified registration says about the credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationFacts {
    /// The credential id the authenticator assigned.
    pub credential_id: Vec<u8>,
    /// The credential's public key.
    pub credential_key: CredentialKey,
    /// SHA-256 of the relying-party id the credential was created for.
    pub rp_id_hash: [u8; 32],
    /// Authenticator make and model.
    pub aaguid: Aaguid,
    /// BE: the credential may be synced to other devices.
    pub backup_eligible: bool,
    /// BS: the credential is currently synced.
    pub backed_up: bool,
    /// UP: a person was present.
    pub user_present: bool,
    /// UV: the person was verified (biometric or PIN).
    pub user_verified: bool,
    /// The authenticator's signature counter at registration.
    pub sign_count: u32,
    /// What the verified attestation statement proves about the hardware.
    pub evidence: AttestationEvidence,
}

type AttResult<T> = Result<T, AttestationError>;

/// The credential a registration's `authenticatorData` carries when AT is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCredential {
    /// Authenticator make and model, or the sync provider.
    pub aaguid: Aaguid,
    /// The credential id the authenticator assigned.
    pub credential_id: Vec<u8>,
    /// The credential's public key.
    pub credential_key: CredentialKey,
}

/// The fields of a WebAuthn `authenticatorData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorData {
    /// SHA-256 of the relying-party id.
    pub rp_id_hash: [u8; 32],
    /// UP: a person was present.
    pub user_present: bool,
    /// UV: the person was verified (biometric or PIN).
    pub user_verified: bool,
    /// BE: the credential may be synced to other devices.
    pub backup_eligible: bool,
    /// BS: the credential is currently synced.
    pub backed_up: bool,
    /// The authenticator's signature counter.
    pub sign_count: u32,
    /// Present exactly when the AT flag is set.
    pub attested_credential: Option<AttestedCredential>,
}

/// Read `authenticatorData`: the relying-party hash, the flags, the counter,
/// and, when AT is set, the attested credential data.
///
/// Refuses data shorter than its fixed fields, and a BS flag without BE.
pub fn read_authenticator_data(auth_data: &[u8]) -> AttResult<AuthenticatorData> {
    if auth_data.len() < ATTESTED_DATA_OFFSET {
        return Err(AttestationError::TruncatedAuthData);
    }
    let flags = auth_data[FLAGS_OFFSET];
    let backup_eligible = flags & flag::BE != 0;
    let backed_up = flags & flag::BS != 0;
    if !backup_eligible && backed_up {
        return Err(AttestationError::ContradictoryBackupFlags);
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&auth_data[..RP_ID_HASH_LEN]);
    let mut counter = [0u8; 4];
    counter.copy_from_slice(&auth_data[COUNTER_OFFSET..ATTESTED_DATA_OFFSET]);
    let attested_credential = if flags & flag::AT != 0 {
        let (aaguid, credential_id, credential_key) = read_attested_credential_data(auth_data)?;
        Some(AttestedCredential {
            aaguid,
            credential_id,
            credential_key,
        })
    } else {
        None
    };
    Ok(AuthenticatorData {
        rp_id_hash,
        user_present: flags & flag::UP != 0,
        user_verified: flags & flag::UV != 0,
        backup_eligible,
        backed_up,
        sign_count: u32::from_be_bytes(counter),
        attested_credential,
    })
}

/// Verify and grade a registration's attestation object.
///
/// `client_data_hash` is SHA-256 of the registration's `clientDataJSON`,
/// whose challenge the caller has already checked is one it issued.
/// `trusted_roots` are DER roots a chain may end at; `now` is unix seconds for
/// certificate validity.
pub fn parse_attestation(
    attestation_object: &[u8],
    client_data_hash: &[u8; 32],
    trusted_roots: &[Vec<u8>],
    now: u64,
) -> AttResult<RegistrationFacts> {
    use ciborium::value::Value;
    let value: Value = ciborium::from_reader(attestation_object)
        .map_err(|e| AttestationError::Malformed(format!("CBOR decode failed: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| AttestationError::Malformed("top level is not a CBOR map".into()))?;
    let mut fmt = None;
    let mut auth_data = None;
    let mut att_stmt = None;
    for (k, v) in map {
        match k.as_text() {
            Some("fmt") => fmt = v.as_text().map(str::to_string),
            Some("authData") => auth_data = v.as_bytes().cloned(),
            Some("attStmt") => att_stmt = Some(v.clone()),
            _ => {}
        }
    }
    let fmt = fmt.ok_or_else(|| AttestationError::Malformed("missing fmt".into()))?;
    let auth_data =
        auth_data.ok_or_else(|| AttestationError::Malformed("missing authData".into()))?;
    let att_stmt = att_stmt.unwrap_or(Value::Map(vec![]));
    let format = AttestationFormat::parse(&fmt)
        .ok_or_else(|| AttestationError::UnknownFormat(fmt.clone()))?;

    let parsed = read_authenticator_data(&auth_data)?;
    let AttestedCredential {
        aaguid,
        credential_id,
        credential_key,
    } = parsed
        .attested_credential
        .clone()
        .ok_or(AttestationError::NoCredential)?;
    let AuthenticatorData {
        rp_id_hash,
        user_present,
        user_verified,
        backup_eligible,
        backed_up,
        sign_count,
        ..
    } = parsed;

    let mut signed = auth_data.clone();
    signed.extend_from_slice(client_data_hash);
    let stmt = Statement::read(&att_stmt)?;

    let (protection, chain_verified, verified_boot) = match format {
        AttestationFormat::None => (KeyProtection::Software, false, None),
        AttestationFormat::Packed => match stmt.x5c.first() {
            None => {
                verify_with_credential_key(&credential_key, stmt.alg, &signed, &stmt.sig)?;
                (KeyProtection::Software, false, None)
            }
            Some(leaf) => {
                let leaf_cert = tenzro_tee::x509::parse(leaf)
                    .map_err(|e| AttestationError::Malformed(e.to_string()))?;
                verify_with_cert(&leaf_cert, stmt.alg, &signed, &stmt.sig)?;
                if let Some(ext) = leaf_cert.extension(FIDO_AAGUID_OID)
                    && !ext.ends_with(&aaguid.0)
                {
                    return Err(AttestationError::KeyMismatch(
                        "attestation certificate is for a different authenticator model".into(),
                    ));
                }
                let ok = chain_ok(&stmt.x5c, trusted_roots, now);
                (
                    if ok {
                        KeyProtection::SecureElement
                    } else {
                        KeyProtection::Software
                    },
                    ok,
                    None,
                )
            }
        },
        AttestationFormat::Apple => {
            let leaf = stmt.leaf()?;
            let nonce: [u8; 32] = Sha256::digest(&signed).into();
            let ext = leaf
                .extension(APPLE_NONCE_OID)
                .ok_or_else(|| AttestationError::BadSignature("no Apple nonce extension".into()))?;
            if !ext.ends_with(&nonce) {
                return Err(AttestationError::BadSignature(
                    "Apple nonce does not cover this registration".into(),
                ));
            }
            leaf_key_is_credential(&leaf, &credential_key)?;
            let ok = chain_ok(&stmt.x5c, trusted_roots, now);
            (
                if ok {
                    KeyProtection::SecureElement
                } else {
                    KeyProtection::Software
                },
                ok,
                None,
            )
        }
        AttestationFormat::AndroidKey => {
            let leaf = stmt.leaf()?;
            verify_with_cert(&leaf, stmt.alg, &signed, &stmt.sig)?;
            leaf_key_is_credential(&leaf, &credential_key)?;
            let desc = leaf.extension(ANDROID_KEY_ATTESTATION_OID).ok_or_else(|| {
                AttestationError::Malformed("no Android key description extension".into())
            })?;
            let description = android_key_description(desc)?;
            if description.challenge != client_data_hash.as_slice() {
                return Err(AttestationError::BadSignature(
                    "Android attestation challenge is not this registration".into(),
                ));
            }
            let ok = chain_ok(&stmt.x5c, trusted_roots, now);
            let (level, boot) = (description.protection, description.verified_boot);
            let protection = if ok { level } else { KeyProtection::Software };
            (protection, ok, Some(ok && boot))
        }
        AttestationFormat::Tpm => {
            let leaf = stmt.leaf()?;
            let cert_info = stmt.cert_info.as_ref().ok_or_else(|| {
                AttestationError::Malformed("tpm statement has no certInfo".into())
            })?;
            let pub_area = stmt.pub_area.as_ref().ok_or_else(|| {
                AttestationError::Malformed("tpm statement has no pubArea".into())
            })?;
            verify_with_cert(&leaf, stmt.alg, cert_info, &stmt.sig)?;
            verify_tpm_certify(cert_info, pub_area, &signed, &credential_key)?;
            let ok = chain_ok(&stmt.x5c, trusted_roots, now);
            (
                if ok {
                    KeyProtection::SecureElement
                } else {
                    KeyProtection::Software
                },
                ok,
                None,
            )
        }
    };

    Ok(RegistrationFacts {
        credential_id,
        credential_key,
        rp_id_hash,
        aaguid,
        backup_eligible,
        backed_up,
        user_present,
        user_verified,
        sign_count,
        evidence: AttestationEvidence {
            format,
            protection,
            chain_verified,
            verified_boot,
        },
    })
}

struct Statement {
    alg: i64,
    sig: Vec<u8>,
    x5c: Vec<Vec<u8>>,
    cert_info: Option<Vec<u8>>,
    pub_area: Option<Vec<u8>>,
}

impl Statement {
    fn read(v: &ciborium::value::Value) -> AttResult<Self> {
        let map = v
            .as_map()
            .ok_or_else(|| AttestationError::Malformed("attStmt is not a map".into()))?;
        let mut s = Statement {
            alg: 0,
            sig: Vec::new(),
            x5c: Vec::new(),
            cert_info: None,
            pub_area: None,
        };
        for (k, v) in map {
            match k.as_text() {
                Some("alg") => {
                    s.alg = v
                        .as_integer()
                        .and_then(|i| i64::try_from(i).ok())
                        .ok_or_else(|| {
                            AttestationError::Malformed("alg is not an integer".into())
                        })?
                }
                Some("sig") => s.sig = v.as_bytes().cloned().unwrap_or_default(),
                Some("x5c") => {
                    s.x5c = v
                        .as_array()
                        .map(|a| a.iter().filter_map(|c| c.as_bytes().cloned()).collect())
                        .unwrap_or_default()
                }
                Some("certInfo") => s.cert_info = v.as_bytes().cloned(),
                Some("pubArea") => s.pub_area = v.as_bytes().cloned(),
                _ => {}
            }
        }
        Ok(s)
    }

    fn leaf(&self) -> AttResult<tenzro_tee::x509::Cert> {
        let der = self
            .x5c
            .first()
            .ok_or_else(|| AttestationError::Malformed("statement has no certificate".into()))?;
        tenzro_tee::x509::parse(der).map_err(|e| AttestationError::Malformed(e.to_string()))
    }
}

fn cose_alg_oid(alg: i64) -> AttResult<&'static str> {
    match alg {
        -7 => Ok(OID_ECDSA_SHA256),
        -35 => Ok(OID_ECDSA_SHA384),
        -257 => Ok(OID_RSA_SHA256),
        other => Err(AttestationError::BadSignature(format!(
            "unsupported COSE algorithm {other}"
        ))),
    }
}

fn verify_with_cert(
    cert: &tenzro_tee::x509::Cert,
    alg: i64,
    msg: &[u8],
    sig: &[u8],
) -> AttResult<()> {
    tenzro_tee::x509::verify_signature(cose_alg_oid(alg)?, None, &cert.spki_der, msg, sig)
        .map_err(|e| AttestationError::BadSignature(e.to_string()))
}

fn verify_with_credential_key(
    key: &CredentialKey,
    alg: i64,
    msg: &[u8],
    sig: &[u8],
) -> AttResult<()> {
    match (key, alg) {
        (CredentialKey::P256(pk), -7) => {
            let der = p256::ecdsa::Signature::from_der(sig)
                .map_err(|e| AttestationError::BadSignature(e.to_string()))?;
            if tenzro_device_key::signer::verify_p256(pk, msg, &der.to_bytes()) {
                Ok(())
            } else {
                Err(AttestationError::BadSignature(
                    "self-attestation signature".into(),
                ))
            }
        }
        _ => Err(AttestationError::BadSignature(
            "self-attestation algorithm does not match the credential key".into(),
        )),
    }
}

/// The leaf certificate's subject key must be the registered credential key.
fn leaf_key_is_credential(leaf: &tenzro_tee::x509::Cert, key: &CredentialKey) -> AttResult<()> {
    let bits = leaf
        .public_key_bits()
        .map_err(|e| AttestationError::Malformed(e.to_string()))?;
    match key {
        CredentialKey::P256(pk) if bits.as_slice() == pk.as_slice() => Ok(()),
        _ => Err(AttestationError::KeyMismatch(
            "the certified key is not the registered credential key".into(),
        )),
    }
}

fn chain_ok(x5c: &[Vec<u8>], roots: &[Vec<u8>], now: u64) -> bool {
    if roots.is_empty() || x5c.is_empty() {
        return false;
    }
    let chain: Option<Vec<_>> = x5c
        .iter()
        .map(|d| tenzro_tee::x509::parse(d).ok())
        .collect();
    let roots: Option<Vec<_>> = roots
        .iter()
        .map(|d| tenzro_tee::x509::parse(d).ok())
        .collect();
    match (chain, roots) {
        (Some(c), Some(r)) => tenzro_tee::x509::verify_chain(&c, &r, now).is_ok(),
        _ => false,
    }
}

/// Check a TPM `certInfo` certifies `pubArea` over this registration, and that
/// `pubArea` is the registered credential key.
fn verify_tpm_certify(
    cert_info: &[u8],
    pub_area: &[u8],
    signed: &[u8],
    key: &CredentialKey,
) -> AttResult<()> {
    use tenzro_device_key::tpm_wire::{self, PublicKey, Reader};
    let area =
        tpm_wire::parse_public(pub_area).map_err(|e| AttestationError::Malformed(e.to_string()))?;
    match (&area.key, key) {
        (PublicKey::EccP256 { .. }, CredentialKey::P256(pk))
            if area.p256_sec1().as_ref() == Some(pk) => {}
        (PublicKey::Rsa { modulus, .. }, CredentialKey::Rsa { n, .. }) if modulus == n => {}
        _ => {
            return Err(AttestationError::KeyMismatch(
                "the TPM-certified key is not the registered credential key".into(),
            ));
        }
    }
    let name = area
        .name()
        .map_err(|e| AttestationError::Malformed(e.to_string()))?;
    let mut r = Reader::new(cert_info);
    let bad = |m: &str| AttestationError::BadSignature(m.to_string());
    if r.u32().map_err(|_| bad("certInfo"))? != tpm_wire::TPM2_GENERATED_VALUE {
        return Err(bad("certInfo is not TPM-generated"));
    }
    const TPM2_ST_ATTEST_CERTIFY: u16 = 0x8017;
    if r.u16().map_err(|_| bad("certInfo"))? != TPM2_ST_ATTEST_CERTIFY {
        return Err(bad("certInfo is not a certification"));
    }
    r.tpm2b().map_err(|_| bad("certInfo"))?; // qualifiedSigner
    let extra = r.tpm2b().map_err(|_| bad("certInfo"))?;
    if extra != Sha256::digest(signed).as_slice() {
        return Err(bad("certInfo does not cover this registration"));
    }
    r.skip(17 + 8).map_err(|_| bad("certInfo"))?; // clockInfo, firmwareVersion
    let certified_name = r.tpm2b().map_err(|_| bad("certInfo"))?;
    if certified_name != name.as_slice() {
        return Err(bad("certInfo certifies a different key"));
    }
    Ok(())
}

/// What an Android `KeyDescription` states about the attested key.
struct AndroidKeyDescription<'a> {
    protection: KeyProtection,
    challenge: &'a [u8],
    verified_boot: bool,
}

/// One DER element: its identifier (class and constructed bits with the tag
/// number, high-tag-number form folded in), its contents, and what follows.
fn der_element(input: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    let (&first, mut rest) = input.split_first()?;
    let mut tag = u64::from(first & 0xe0) << 56;
    if first & 0x1f == 0x1f {
        let mut number: u64 = 0;
        loop {
            let (&b, r) = rest.split_first()?;
            rest = r;
            number = number.checked_mul(128)? | u64::from(b & 0x7f);
            if number >> 48 != 0 {
                return None;
            }
            if b & 0x80 == 0 {
                break;
            }
        }
        tag |= number;
    } else {
        tag |= u64::from(first & 0x1f);
    }
    let (&len0, r) = rest.split_first()?;
    rest = r;
    let len = if len0 & 0x80 == 0 {
        usize::from(len0)
    } else {
        let n = usize::from(len0 & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let (bytes, r) = rest.split_at(n);
        rest = r;
        bytes
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b))
    };
    if rest.len() < len {
        return None;
    }
    let (contents, after) = rest.split_at(len);
    Some((tag, contents, after))
}

const DER_UNIVERSAL_INTEGER: u64 = 0x02;
const DER_UNIVERSAL_BOOLEAN: u64 = 0x01;
const DER_UNIVERSAL_OCTET_STRING: u64 = 0x04;
const DER_UNIVERSAL_ENUMERATED: u64 = 0x0a;
const DER_SEQUENCE: u64 = (0x20 << 56) | 0x10;
/// `rootOfTrust [704] EXPLICIT RootOfTrust` in an `AuthorizationList`.
const DER_ROOT_OF_TRUST: u64 = (0xa0 << 56) | 704;

fn der_expect(input: &[u8], tag: u64) -> AttResult<(&[u8], &[u8])> {
    match der_element(input) {
        Some((t, contents, rest)) if t == tag => Ok((contents, rest)),
        _ => Err(AttestationError::Malformed(
            "Android key description is not a well-formed KeyDescription".into(),
        )),
    }
}

fn der_small_enum(contents: &[u8]) -> AttResult<u8> {
    match contents {
        [v] => Ok(*v),
        _ => Err(AttestationError::Malformed(
            "Android key description carries an out-of-range enumeration".into(),
        )),
    }
}

/// Decode an Android `KeyDescription` (the key attestation extension):
/// `attestationSecurityLevel`, `attestationChallenge`, and the hardware-
/// enforced `rootOfTrust`. Verified boot holds only when the TEE or
/// StrongBox reports the bootloader locked and the boot state `Verified`.
fn android_key_description(ext: &[u8]) -> AttResult<AndroidKeyDescription<'_>> {
    let (body, trailing) = der_expect(ext, DER_SEQUENCE)?;
    if !trailing.is_empty() {
        return Err(AttestationError::Malformed(
            "Android key description has trailing bytes".into(),
        ));
    }
    let (_, rest) = der_expect(body, DER_UNIVERSAL_INTEGER)?; // attestationVersion
    let (level, rest) = der_expect(rest, DER_UNIVERSAL_ENUMERATED)?;
    let level = der_small_enum(level)?;
    let (_, rest) = der_expect(rest, DER_UNIVERSAL_INTEGER)?; // keymasterVersion
    let (_, rest) = der_expect(rest, DER_UNIVERSAL_ENUMERATED)?; // keymasterSecurityLevel
    let (challenge, rest) = der_expect(rest, DER_UNIVERSAL_OCTET_STRING)?;
    let (_, rest) = der_expect(rest, DER_UNIVERSAL_OCTET_STRING)?; // uniqueId
    let (_, rest) = der_expect(rest, DER_SEQUENCE)?; // softwareEnforced
    let (mut hardware, _) = der_expect(rest, DER_SEQUENCE)?; // hardwareEnforced
    let protection = match level {
        2 => KeyProtection::SecureElement,
        1 => KeyProtection::TrustedEnvironment,
        _ => KeyProtection::Software,
    };
    let mut verified_boot = false;
    while !hardware.is_empty() {
        let (tag, contents, rest) = der_element(hardware).ok_or_else(|| {
            AttestationError::Malformed("Android hardware-enforced list is malformed".into())
        })?;
        hardware = rest;
        if tag != DER_ROOT_OF_TRUST {
            continue;
        }
        let (root, _) = der_expect(contents, DER_SEQUENCE)?;
        let (_, root) = der_expect(root, DER_UNIVERSAL_OCTET_STRING)?; // verifiedBootKey
        let (locked, root) = der_expect(root, DER_UNIVERSAL_BOOLEAN)?;
        let (state, _) = der_expect(root, DER_UNIVERSAL_ENUMERATED)?;
        verified_boot = level > 0 && locked == [0xff] && der_small_enum(state)? == 0;
    }
    Ok(AndroidKeyDescription {
        protection,
        challenge,
        verified_boot,
    })
}

/// AAGUID, credential id and credential public key from the attested
/// credential data. Every length is checked before use.
fn read_attested_credential_data(auth_data: &[u8]) -> AttResult<(Aaguid, Vec<u8>, CredentialKey)> {
    let start = ATTESTED_DATA_OFFSET;
    let id_len_at = start + 16;
    let id_at = id_len_at + 2;
    if auth_data.len() < id_at {
        return Err(AttestationError::TruncatedAuthData);
    }
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&auth_data[start..id_len_at]);
    let id_len = u16::from_be_bytes([auth_data[id_len_at], auth_data[id_len_at + 1]]) as usize;
    let id_end = id_at
        .checked_add(id_len)
        .ok_or(AttestationError::TruncatedAuthData)?;
    if auth_data.len() < id_end {
        return Err(AttestationError::TruncatedAuthData);
    }
    let key = read_cose_key(&auth_data[id_end..])?;
    Ok((Aaguid(aaguid), auth_data[id_at..id_end].to_vec(), key))
}

fn read_cose_key(bytes: &[u8]) -> AttResult<CredentialKey> {
    use ciborium::value::Value;
    let v: Value = ciborium::from_reader(bytes)
        .map_err(|e| AttestationError::Malformed(format!("COSE key: {e}")))?;
    let map = v
        .as_map()
        .ok_or_else(|| AttestationError::Malformed("COSE key is not a map".into()))?;
    let get = |label: i64| {
        map.iter()
            .find(|(k, _)| k.as_integer().and_then(|i| i64::try_from(i).ok()) == Some(label))
            .map(|(_, v)| v)
    };
    let kty = get(1)
        .and_then(|v| v.as_integer())
        .and_then(|i| i64::try_from(i).ok());
    match kty {
        Some(2) => {
            let x = get(-2).and_then(|v| v.as_bytes()).filter(|b| b.len() == 32);
            let y = get(-3).and_then(|v| v.as_bytes()).filter(|b| b.len() == 32);
            let crv = get(-1)
                .and_then(|v| v.as_integer())
                .and_then(|i| i64::try_from(i).ok());
            match (crv, x, y) {
                (Some(1), Some(x), Some(y)) => {
                    let mut pk = [0u8; 65];
                    pk[0] = 0x04;
                    pk[1..33].copy_from_slice(x);
                    pk[33..].copy_from_slice(y);
                    Ok(CredentialKey::P256(pk))
                }
                _ => Err(AttestationError::Malformed(
                    "only P-256 EC2 credential keys are supported".into(),
                )),
            }
        }
        Some(3) => {
            let n = get(-1).and_then(|v| v.as_bytes()).cloned();
            let e = get(-2).and_then(|v| v.as_bytes()).cloned();
            match (n, e) {
                (Some(n), Some(e)) => Ok(CredentialKey::Rsa { n, e }),
                _ => Err(AttestationError::Malformed(
                    "RSA COSE key without n or e".into(),
                )),
            }
        }
        _ => Err(AttestationError::Malformed(
            "unsupported COSE key type".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    //! Registrations are built to the WebAuthn wire format and signed with
    //! test keys; `packed` chains use a test CA.

    use super::*;
    use ciborium::value::Value;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;

    const NOW: u64 = 1_800_000_000;
    const CDH: [u8; 32] = [0x11; 32];

    fn cred_key() -> SigningKey {
        SigningKey::from_slice(&[0x21; 32]).unwrap()
    }

    fn cose(k: &SigningKey) -> Vec<u8> {
        let p = k.verifying_key().to_sec1_point(false);
        let b = p.as_bytes();
        let v = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-7).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (Value::Integer((-2).into()), Value::Bytes(b[1..33].to_vec())),
            (
                Value::Integer((-3).into()),
                Value::Bytes(b[33..65].to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&v, &mut out).unwrap();
        out
    }

    fn auth_data(flags: u8) -> Vec<u8> {
        let mut v = Sha256::digest(b"tenzro.com").to_vec();
        v.push(flags | flag::AT);
        v.extend_from_slice(&5u32.to_be_bytes());
        v.extend_from_slice(&[7u8; 16]);
        v.extend_from_slice(&(3u16).to_be_bytes());
        v.extend_from_slice(b"cid");
        v.extend_from_slice(&cose(&cred_key()));
        v
    }

    fn object(fmt: &str, auth: &[u8], stmt: Vec<(Value, Value)>) -> Vec<u8> {
        let v = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text(fmt.into())),
            (Value::Text("authData".into()), Value::Bytes(auth.to_vec())),
            (Value::Text("attStmt".into()), Value::Map(stmt)),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&v, &mut out).unwrap();
        out
    }

    fn sign(k: &SigningKey, auth: &[u8], cdh: &[u8; 32]) -> Vec<u8> {
        let mut m = auth.to_vec();
        m.extend_from_slice(cdh);
        let s: p256::ecdsa::Signature = k.sign(&m);
        s.to_der().as_bytes().to_vec()
    }

    fn packed(att_key: &SigningKey, x5c: Vec<Vec<u8>>, auth: &[u8]) -> Vec<u8> {
        let mut stmt = vec![
            (Value::Text("alg".into()), Value::Integer((-7).into())),
            (
                Value::Text("sig".into()),
                Value::Bytes(sign(att_key, auth, &CDH)),
            ),
        ];
        if !x5c.is_empty() {
            stmt.push((
                Value::Text("x5c".into()),
                Value::Array(x5c.into_iter().map(Value::Bytes).collect()),
            ));
        }
        object("packed", auth, stmt)
    }

    fn vendor_chain() -> (SigningKey, Vec<u8>, Vec<u8>) {
        use tenzro_tee::x509::testca;
        let root_k = testca::key(70);
        let att_k = testca::key(71);
        let root = testca::issue("FIDO Root", &root_k, "FIDO Root", &root_k, true, 1);
        let leaf = testca::issue("Attestation", &att_k, "FIDO Root", &root_k, false, 2);
        (att_k, leaf, root)
    }

    #[test]
    fn a_vendor_attested_packed_registration_is_hardware_bound() {
        let (att_k, leaf, root) = vendor_chain();
        let auth = auth_data(flag::UP | flag::UV);
        let f = parse_attestation(&packed(&att_k, vec![leaf], &auth), &CDH, &[root], NOW).unwrap();
        assert!(f.evidence.proves_hardware());
        assert_eq!(f.credential_id, b"cid");
        assert!(matches!(f.credential_key, CredentialKey::P256(_)));
    }

    #[test]
    fn a_signature_over_another_challenge_is_refused() {
        let (att_k, leaf, root) = vendor_chain();
        let auth = auth_data(flag::UP);
        let obj = packed(&att_k, vec![leaf], &auth);
        assert!(matches!(
            parse_attestation(&obj, &[0x22; 32], &[root], NOW),
            Err(AttestationError::BadSignature(_))
        ));
    }

    #[test]
    fn a_forged_chain_matching_by_name_only_does_not_grade_as_hardware() {
        use tenzro_tee::x509::testca;
        let (_, _, real_root) = vendor_chain();
        let fake_root_k = testca::key(80);
        let fake_att_k = testca::key(81);
        let fake_leaf = testca::issue(
            "Attestation",
            &fake_att_k,
            "FIDO Root",
            &fake_root_k,
            false,
            2,
        );
        let auth = auth_data(flag::UP);
        let f = parse_attestation(
            &packed(&fake_att_k, vec![fake_leaf], &auth),
            &CDH,
            &[real_root],
            NOW,
        )
        .unwrap();
        assert!(!f.evidence.proves_hardware());
    }

    #[test]
    fn an_attestation_signed_by_someone_else_is_refused() {
        let (_, leaf, root) = vendor_chain();
        let auth = auth_data(flag::UP);
        let other = SigningKey::from_slice(&[0x55; 32]).unwrap();
        assert!(parse_attestation(&packed(&other, vec![leaf], &auth), &CDH, &[root], NOW).is_err());
    }

    #[test]
    fn self_attestation_proves_possession_not_hardware() {
        let auth = auth_data(flag::UP);
        let f = parse_attestation(&packed(&cred_key(), vec![], &auth), &CDH, &[], NOW).unwrap();
        assert!(!f.evidence.proves_hardware());
        let other = SigningKey::from_slice(&[0x56; 32]).unwrap();
        assert!(parse_attestation(&packed(&other, vec![], &auth), &CDH, &[], NOW).is_err());
    }

    #[test]
    fn flags_come_from_the_signed_bytes() {
        let auth = auth_data(flag::UP | flag::UV | flag::BE | flag::BS);
        let f = parse_attestation(&packed(&cred_key(), vec![], &auth), &CDH, &[], NOW).unwrap();
        assert!(f.backup_eligible && f.backed_up && f.user_verified);
        assert_eq!(f.sign_count, 5);
    }

    #[test]
    fn contradictory_backup_flags_and_unknown_formats_are_refused() {
        let auth = auth_data(flag::UP | flag::BS);
        assert_eq!(
            parse_attestation(&packed(&cred_key(), vec![], &auth), &CDH, &[], NOW),
            Err(AttestationError::ContradictoryBackupFlags)
        );
        let auth = auth_data(flag::UP);
        assert!(matches!(
            parse_attestation(&object("android-safetynet", &auth, vec![]), &CDH, &[], NOW),
            Err(AttestationError::UnknownFormat(_))
        ));
    }

    #[test]
    fn apple_and_tpm_formats_do_not_grade_from_their_name() {
        let auth = auth_data(flag::UP);
        for fmt in ["apple", "tpm", "android-key"] {
            assert!(
                parse_attestation(&object(fmt, &auth, vec![]), &CDH, &[], NOW).is_err(),
                "{fmt} with no statement was accepted"
            );
        }
    }

    /// A KeyDescription with the given challenge and a hardware-enforced
    /// root of trust (`deviceLocked`, `verifiedBootState`).
    fn key_description(challenge: &[u8; 32], locked: bool, boot_state: u8) -> Vec<u8> {
        fn tlv(tag: &[u8], body: &[u8]) -> Vec<u8> {
            assert!(body.len() < 128);
            let mut v = tag.to_vec();
            v.push(body.len() as u8);
            v.extend_from_slice(body);
            v
        }
        let mut root = tlv(&[0x04], &[0x11; 32]);
        root.extend(tlv(&[0x01], &[if locked { 0xff } else { 0x00 }]));
        root.extend(tlv(&[0x0a], &[boot_state]));
        let root_of_trust = tlv(&[0xbf, 0x85, 0x40], &tlv(&[0x30], &root));
        let mut body = tlv(&[0x02], &[3]);
        body.extend(tlv(&[0x0a], &[1]));
        body.extend(tlv(&[0x02], &[4]));
        body.extend(tlv(&[0x0a], &[1]));
        body.extend(tlv(&[0x04], challenge));
        body.extend(tlv(&[0x04], &[]));
        body.extend(tlv(&[0x30], &[]));
        body.extend(tlv(&[0x30], &root_of_trust));
        tlv(&[0x30], &body)
    }

    #[test]
    fn android_verified_boot_is_read_from_the_hardware_root_of_trust() {
        // A challenge that happens to contain the bytes 0a 00, on a device
        // whose bootloader is unlocked and boot state Unverified (2).
        let mut challenge = [0x5au8; 32];
        challenge[7] = 0x0a;
        challenge[8] = 0x00;
        let unlocked = key_description(&challenge, false, 2);
        let d = android_key_description(&unlocked).unwrap();
        assert!(matches!(d.protection, KeyProtection::TrustedEnvironment));
        assert_eq!(d.challenge, challenge.as_slice());
        assert!(
            !d.verified_boot,
            "an unlocked, unverified device is not verified boot"
        );

        // A locked device in the Verified state (0) is.
        let locked = key_description(&[0x5a; 32], true, 0);
        assert!(android_key_description(&locked).unwrap().verified_boot);

        // Locked but self-signed (1) is not.
        let self_signed = key_description(&[0x5a; 32], true, 1);
        assert!(!android_key_description(&self_signed).unwrap().verified_boot);

        // The challenge is the field itself, not any window of the extension.
        let mut other = [0x5au8; 32];
        other[0] = 0x01;
        let other_description = key_description(&other, true, 0);
        let d = android_key_description(&other_description).unwrap();
        assert_ne!(d.challenge, challenge.as_slice());

        // Malformed input is refused rather than graded.
        assert!(android_key_description(&[0x30, 0x03, 0x0a, 0x01, 0x02]).is_err());
    }

    #[test]
    fn none_never_proves_hardware() {
        let auth = auth_data(flag::UP | flag::UV);
        let f = parse_attestation(&object("none", &auth, vec![]), &CDH, &[], NOW).unwrap();
        assert!(!f.evidence.proves_hardware());
    }

    /// With AT set, the AAGUID is the 16 bytes at offsets 37..53 and the
    /// credential id and key follow it.
    #[test]
    fn authenticator_data_with_at_yields_the_aaguid_and_credential() {
        let auth = auth_data(flag::UP | flag::UV | flag::BE | flag::BS);
        let d = read_authenticator_data(&auth).unwrap();
        assert_eq!(
            d.rp_id_hash,
            <[u8; 32]>::from(Sha256::digest(b"tenzro.com"))
        );
        assert!(d.user_present && d.user_verified && d.backup_eligible && d.backed_up);
        assert_eq!(d.sign_count, 5);
        let c = d.attested_credential.expect("AT is set");
        assert_eq!(c.aaguid, Aaguid([7u8; 16]));
        assert_eq!(&auth[37..53], &c.aaguid.0);
        assert_eq!(c.credential_id, b"cid".to_vec());
        let p = cred_key().verifying_key().to_sec1_point(false);
        assert_eq!(
            c.credential_key,
            CredentialKey::P256(p.as_bytes().try_into().unwrap())
        );
    }

    /// An assertion's authenticator data has no AT flag and no credential.
    #[test]
    fn authenticator_data_without_at_has_no_credential() {
        let mut auth = Sha256::digest(b"tenzro.com").to_vec();
        auth.push(flag::UP | flag::UV);
        auth.extend_from_slice(&9u32.to_be_bytes());
        let d = read_authenticator_data(&auth).unwrap();
        assert!(d.attested_credential.is_none());
        assert!(d.user_verified && !d.backup_eligible && !d.backed_up);
        assert_eq!(d.sign_count, 9);
    }

    #[test]
    fn short_authenticator_data_is_refused() {
        assert_eq!(
            read_authenticator_data(&[0u8; 36]),
            Err(AttestationError::TruncatedAuthData)
        );
        // AT promises attested credential data the bytes do not hold.
        let mut auth = vec![0u8; 37];
        auth[32] = flag::UP | flag::AT;
        auth.extend_from_slice(&[7u8; 10]);
        assert_eq!(
            read_authenticator_data(&auth),
            Err(AttestationError::TruncatedAuthData)
        );
        // A credential id length running past the end.
        let mut auth = auth_data(flag::UP)[..53].to_vec();
        auth.extend_from_slice(&200u16.to_be_bytes());
        auth.extend_from_slice(b"cid");
        assert_eq!(
            read_authenticator_data(&auth),
            Err(AttestationError::TruncatedAuthData)
        );
    }

    #[test]
    fn each_flag_is_read_from_its_own_bit() {
        for (bits, uv, be, bs) in [
            (flag::UP, false, false, false),
            (flag::UP | flag::UV, true, false, false),
            (flag::UP | flag::BE, false, true, false),
            (flag::UP | flag::BE | flag::BS, false, true, true),
        ] {
            let d = read_authenticator_data(&auth_data(bits)).unwrap();
            assert_eq!(
                (d.user_verified, d.backup_eligible, d.backed_up),
                (uv, be, bs),
                "{bits:#x}"
            );
        }
        assert_eq!(
            read_authenticator_data(&auth_data(flag::UP | flag::BS)),
            Err(AttestationError::ContradictoryBackupFlags)
        );
    }
}
