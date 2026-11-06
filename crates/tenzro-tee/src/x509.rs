//! X.509 certificate-chain validation by signature, for attestation evidence.
//!
//! Every hardware attestation format ends in a certificate chain back to a
//! vendor root: Intel's SGX root for TDX, AMD's ARK for SEV-SNP, AWS's Nitro
//! root, NVIDIA's device identity root, a TPM manufacturer's EK root. The
//! chain is only evidence if each link is checked by *signature*: the child's
//! to-be-signed bytes verified under the issuer's public key, all the way to a
//! root the verifier already holds. Matching names proves nothing, since
//! anyone can mint a certificate with any subject.
//!
//! [`verify_chain`] walks leaf to root and checks, for every link: the
//! signature, that the issuer's subject equals the child's issuer name, that
//! the issuer is a CA, and that both certificates are inside their validity
//! window at the verification time. The chain must end in a certificate
//! signed by (or byte-identical to) one of the trusted roots passed in.
//! [`check_not_revoked`] applies a CRL after checking the CRL's own signature
//! and freshness.

use der::{Decode, Encode};
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::BasicConstraints;

use crate::error::{Result, TeeError};

const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_RSA_SHA384: &str = "1.2.840.113549.1.1.12";
const OID_RSA_PSS: &str = "1.2.840.113549.1.1.10";
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_P521: &str = "1.3.132.0.35";

fn fail(msg: impl Into<String>) -> TeeError {
    TeeError::CertificateValidationFailed(msg.into())
}

/// A parsed certificate: the parts chain validation needs.
#[derive(Clone, Debug)]
pub struct Cert {
    pub der: Vec<u8>,
    pub tbs_der: Vec<u8>,
    pub signature_algorithm: String,
    /// DER of the signature algorithm's parameters, when present (RSA-PSS).
    pub signature_params: Option<Vec<u8>>,
    pub signature: Vec<u8>,
    pub spki_der: Vec<u8>,
    pub subject_der: Vec<u8>,
    pub issuer_der: Vec<u8>,
    pub serial: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
    pub is_ca: bool,
    /// `(oid, value)` of every extension, for vendor-specific fields such as
    /// AMD's chip id and TCB values.
    pub extensions: Vec<(String, Vec<u8>)>,
}

impl Cert {
    /// The raw subject public key bit string (for EC keys, the SEC1 point).
    pub fn public_key_bits(&self) -> Result<Vec<u8>> {
        let spki = spki::SubjectPublicKeyInfoRef::try_from(self.spki_der.as_slice())
            .map_err(|e| fail(format!("SPKI: {e}")))?;
        spki.subject_public_key
            .as_bytes()
            .map(|b| b.to_vec())
            .ok_or_else(|| fail("SPKI bit string has unused bits"))
    }

    /// The value of the extension with `oid`, if present.
    pub fn extension(&self, oid: &str) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(o, _)| o == oid)
            .map(|(_, v)| v.as_slice())
    }
}

/// Parse one DER certificate.
pub fn parse(der_bytes: &[u8]) -> Result<Cert> {
    let cert = Certificate::from_der(der_bytes).map_err(|e| fail(format!("certificate: {e}")))?;
    let tbs = &cert.tbs_certificate;
    let enc =
        |r: std::result::Result<Vec<u8>, der::Error>| r.map_err(|e| fail(format!("encode: {e}")));

    let mut is_ca = false;
    let mut extensions = Vec::new();
    for ext in tbs.extensions.iter().flatten() {
        let oid = ext.extn_id.to_string();
        let value = ext.extn_value.as_bytes().to_vec();
        if oid == OID_BASIC_CONSTRAINTS {
            let bc = BasicConstraints::from_der(&value)
                .map_err(|e| fail(format!("basicConstraints: {e}")))?;
            is_ca = bc.ca;
        }
        extensions.push((oid, value));
    }

    Ok(Cert {
        der: der_bytes.to_vec(),
        tbs_der: enc(tbs.to_der())?,
        signature_algorithm: cert.signature_algorithm.oid.to_string(),
        signature_params: cert
            .signature_algorithm
            .parameters
            .as_ref()
            .map(|p| p.to_der())
            .transpose()
            .map_err(|e| fail(format!("encode: {e}")))?,
        signature: cert
            .signature
            .as_bytes()
            .ok_or_else(|| fail("signature bit string has unused bits"))?
            .to_vec(),
        spki_der: enc(tbs.subject_public_key_info.to_der())?,
        subject_der: enc(tbs.subject.to_der())?,
        issuer_der: enc(tbs.issuer.to_der())?,
        serial: tbs.serial_number.as_bytes().to_vec(),
        not_before: tbs.validity.not_before.to_unix_duration().as_secs(),
        not_after: tbs.validity.not_after.to_unix_duration().as_secs(),
        is_ca,
        extensions,
    })
}

/// Parse PEM text holding one or more certificates, in order.
pub fn parse_pem_chain(pem: &str) -> Result<Vec<Cert>> {
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let body_start = start + "-----BEGIN CERTIFICATE-----".len();
        let end = rest[body_start..]
            .find("-----END CERTIFICATE-----")
            .ok_or_else(|| fail("unterminated PEM certificate"))?;
        let b64: String = rest[body_start..body_start + end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        use base64::Engine;
        let der_bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| fail(format!("PEM base64: {e}")))?;
        out.push(parse(&der_bytes)?);
        rest = &rest[body_start + end + "-----END CERTIFICATE-----".len()..];
    }
    if out.is_empty() {
        return Err(fail("no certificate in PEM input"));
    }
    Ok(out)
}

/// Named curve of an EC SPKI, or `None` for a non-EC key.
fn ec_curve(spki_der: &[u8]) -> Result<Option<&'static str>> {
    let spki = spki::SubjectPublicKeyInfoRef::try_from(spki_der)
        .map_err(|e| fail(format!("SPKI: {e}")))?;
    if spki.algorithm.oid.to_string() != OID_EC_PUBLIC_KEY {
        return Ok(None);
    }
    let params = spki
        .algorithm
        .parameters
        .ok_or_else(|| fail("EC key without curve parameters"))?;
    let curve: spki::ObjectIdentifier = params
        .decode_as()
        .map_err(|e| fail(format!("EC curve: {e}")))?;
    match curve.to_string().as_str() {
        OID_P256 => Ok(Some("P-256")),
        OID_P384 => Ok(Some("P-384")),
        OID_P521 => Ok(Some("P-521")),
        other => Err(fail(format!("unsupported EC curve {other}"))),
    }
}

/// Verify an ECDSA signature (DER or raw `r || s`) over `digest` with a key
/// given as SPKI DER. The digest may be longer than the curve order; it is
/// truncated as ECDSA specifies.
pub fn verify_ecdsa_prehash(spki_der: &[u8], digest: &[u8], signature: &[u8]) -> Result<()> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use spki::DecodePublicKey;
    match ec_curve(spki_der)? {
        Some("P-256") => {
            let vk = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
                .map_err(|e| fail(format!("P-256 key: {e}")))?;
            let sig = p256::ecdsa::Signature::from_der(signature)
                .or_else(|_| p256::ecdsa::Signature::from_slice(signature))
                .map_err(|e| fail(format!("P-256 signature: {e}")))?;
            vk.verify_prehash(digest, &sig)
                .map_err(|_| fail("P-256 signature does not verify"))
        }
        Some("P-384") => {
            let vk = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der)
                .map_err(|e| fail(format!("P-384 key: {e}")))?;
            let sig = p384::ecdsa::Signature::from_der(signature)
                .or_else(|_| p384::ecdsa::Signature::from_slice(signature))
                .map_err(|e| fail(format!("P-384 signature: {e}")))?;
            vk.verify_prehash(digest, &sig)
                .map_err(|_| fail("P-384 signature does not verify"))
        }
        // Some TPM vendors sign their EK intermediates with a P-521 root.
        Some("P-521") => {
            use p521::ecdsa::signature::hazmat::PrehashVerifier as _;
            let spki = spki::SubjectPublicKeyInfoRef::try_from(spki_der)
                .map_err(|e| fail(format!("SPKI: {e}")))?;
            let point = spki
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| fail("P-521 key bit string has unused bits"))?;
            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|e| fail(format!("P-521 key: {e}")))?;
            let sig = p521::ecdsa::Signature::from_der(signature)
                .or_else(|_| p521::ecdsa::Signature::from_slice(signature))
                .map_err(|e| fail(format!("P-521 signature: {e}")))?;
            vk.verify_prehash(digest, &sig)
                .map_err(|_| fail("P-521 signature does not verify"))
        }
        _ => Err(fail("not an EC key")),
    }
}

/// The URL a certificate's Authority Information Access extension gives
/// for its issuer's certificate (`caIssuers`), when it has one.
pub fn ca_issuers_url(cert: &Cert) -> Option<String> {
    use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;
    use x509_cert::ext::pkix::name::GeneralName;
    const OID_AIA: &str = "1.3.6.1.5.5.7.1.1";
    const OID_CA_ISSUERS: &str = "1.3.6.1.5.5.7.48.2";
    let aia = AuthorityInfoAccessSyntax::from_der(cert.extension(OID_AIA)?).ok()?;
    aia.0.iter().find_map(|d| match &d.access_location {
        GeneralName::UniformResourceIdentifier(uri)
            if d.access_method.to_string() == OID_CA_ISSUERS =>
        {
            Some(uri.to_string())
        }
        _ => None,
    })
}

/// The RSA public key in an SPKI.
pub fn rsa_public_key(spki_der: &[u8]) -> Result<rsa::RsaPublicKey> {
    rsa_key(spki_der)
}

fn rsa_key(spki_der: &[u8]) -> Result<rsa::RsaPublicKey> {
    use spki_v07::DecodePublicKey;
    rsa::RsaPublicKey::from_public_key_der(spki_der).map_err(|e| fail(format!("RSA key: {e}")))
}

/// Verify `signature` over `message` under the key in `spki_der`, with the
/// algorithm named by `alg_oid` (and `alg_params` for RSA-PSS).
pub fn verify_signature(
    alg_oid: &str,
    alg_params: Option<&[u8]>,
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    use signature_v2::Verifier;
    match alg_oid {
        OID_ECDSA_SHA256 => verify_ecdsa_prehash(spki_der, &Sha256::digest(message), signature),
        OID_ECDSA_SHA384 => verify_ecdsa_prehash(spki_der, &Sha384::digest(message), signature),
        OID_ECDSA_SHA512 => verify_ecdsa_prehash(spki_der, &Sha512::digest(message), signature),
        OID_RSA_SHA256 => {
            let vk = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa_key(spki_der)?);
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|e| fail(format!("RSA signature: {e}")))?;
            vk.verify(message, &sig)
                .map_err(|_| fail("RSA signature does not verify"))
        }
        OID_RSA_SHA384 => {
            let vk = rsa::pkcs1v15::VerifyingKey::<Sha384>::new(rsa_key(spki_der)?);
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|e| fail(format!("RSA signature: {e}")))?;
            vk.verify(message, &sig)
                .map_err(|_| fail("RSA signature does not verify"))
        }
        OID_RSA_PSS => {
            // Only the SHA-384 profile is accepted (the one AMD's chain uses);
            // the parameters must name SHA-384 or the signature is refused
            // rather than checked under a guessed hash.
            let params = alg_params.ok_or_else(|| fail("RSA-PSS without parameters"))?;
            if !contains_oid(params, OID_SHA384) {
                return Err(fail("RSA-PSS parameters do not name SHA-384"));
            }
            let vk = rsa::pss::VerifyingKey::<Sha384>::new(rsa_key(spki_der)?);
            let sig = rsa::pss::Signature::try_from(signature)
                .map_err(|e| fail(format!("RSA-PSS signature: {e}")))?;
            vk.verify(message, &sig)
                .map_err(|_| fail("RSA-PSS signature does not verify"))
        }
        other => Err(fail(format!("unsupported signature algorithm {other}"))),
    }
}

/// Whether DER `haystack` contains the encoded OID `oid`.
fn contains_oid(haystack: &[u8], oid: &str) -> bool {
    let Ok(o) = der::asn1::ObjectIdentifier::new(oid) else {
        return false;
    };
    let Ok(enc) = o.to_der() else {
        return false;
    };
    haystack.windows(enc.len()).any(|w| w == enc.as_slice())
}

/// Check that `child` was signed by the holder of `issuer`'s key and that
/// `issuer` is entitled to issue it.
pub fn verify_issued_by(child: &Cert, issuer: &Cert) -> Result<()> {
    if child.issuer_der != issuer.subject_der {
        return Err(fail(
            "issuer name does not match the next certificate's subject",
        ));
    }
    if !issuer.is_ca {
        return Err(fail("issuing certificate is not a CA"));
    }
    verify_signature(
        &child.signature_algorithm,
        child.signature_params.as_deref(),
        &issuer.spki_der,
        &child.tbs_der,
        &child.signature,
    )
}

fn check_validity(c: &Cert, now: u64) -> Result<()> {
    if now < c.not_before {
        return Err(fail("certificate is not yet valid"));
    }
    if now > c.not_after {
        return Err(fail("certificate has expired"));
    }
    Ok(())
}

/// Validate `chain` (leaf first, each element issued by the next) up to one
/// of `roots`, at unix time `now`.
///
/// The last element may itself be a trusted root (compared byte for byte, and
/// then checked as self-signed) or be issued by one. Returns the index into
/// `roots` of the anchor that closed the chain.
pub fn verify_chain(chain: &[Cert], roots: &[Cert], now: u64) -> Result<usize> {
    let last = chain
        .last()
        .ok_or_else(|| fail("empty certificate chain"))?;
    for c in chain {
        check_validity(c, now)?;
    }
    for pair in chain.windows(2) {
        verify_issued_by(&pair[0], &pair[1])?;
    }
    for (i, root) in roots.iter().enumerate() {
        if last.der == root.der {
            verify_issued_by(root, root)?;
            return Ok(i);
        }
    }
    for (i, root) in roots.iter().enumerate() {
        if last.issuer_der == root.subject_der {
            check_validity(root, now)?;
            verify_issued_by(last, root)?;
            return Ok(i);
        }
    }
    Err(fail("certificate chain does not end at a trusted root"))
}

/// Check that `cert` is not revoked by `crl_der`, after verifying the CRL was
/// signed by `issuer` and is current at `now`.
pub fn check_not_revoked(cert: &Cert, crl_der: &[u8], issuer: &Cert, now: u64) -> Result<()> {
    let crl = CertificateList::from_der(crl_der).map_err(|e| fail(format!("CRL: {e}")))?;
    let tbs_der = crl
        .tbs_cert_list
        .to_der()
        .map_err(|e| fail(format!("CRL encode: {e}")))?;
    let issuer_name = crl
        .tbs_cert_list
        .issuer
        .to_der()
        .map_err(|e| fail(format!("CRL encode: {e}")))?;
    if issuer_name != issuer.subject_der || cert.issuer_der != issuer.subject_der {
        return Err(fail("CRL is not from the certificate's issuer"));
    }
    let params = crl
        .signature_algorithm
        .parameters
        .as_ref()
        .map(|p| p.to_der())
        .transpose()
        .map_err(|e| fail(format!("CRL encode: {e}")))?;
    verify_signature(
        &crl.signature_algorithm.oid.to_string(),
        params.as_deref(),
        &issuer.spki_der,
        &tbs_der,
        crl.signature
            .as_bytes()
            .ok_or_else(|| fail("CRL signature bit string has unused bits"))?,
    )?;
    if let Some(next) = crl.tbs_cert_list.next_update
        && now > next.to_unix_duration().as_secs()
    {
        return Err(fail("CRL is past its next-update time"));
    }
    if crl
        .tbs_cert_list
        .revoked_certificates
        .iter()
        .flatten()
        .any(|r| r.serial_number.as_bytes() == cert.serial.as_slice())
    {
        return Err(fail("certificate is revoked"));
    }
    Ok(())
}

#[cfg(any(test, feature = "test-ca"))]
pub mod testca {
    //! A throwaway certificate authority for tests: real X.509 DER, real
    //! signatures, built from fixed seeds so tests are deterministic.

    use der::asn1::{BitString, GeneralizedTime};
    use der::{Decode, Encode};
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha256};
    use spki::EncodePublicKey;
    use x509_cert::name::Name;
    use x509_cert::time::{Time, Validity};

    pub struct Issued {
        pub der: Vec<u8>,
        pub key: p256::ecdsa::SigningKey,
    }

    pub fn key(seed: u8) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn name(cn: &str) -> Name {
        Name::from_der(&cn_der(cn)).unwrap()
    }

    fn cn_der(cn: &str) -> Vec<u8> {
        // SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String cn } } }
        let mut atv = vec![0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, cn.len() as u8];
        atv.extend_from_slice(cn.as_bytes());
        let mut seq = vec![0x30, atv.len() as u8];
        seq.extend(atv);
        let mut set = vec![0x31, seq.len() as u8];
        set.extend(seq);
        let mut outer = vec![0x30, set.len() as u8];
        outer.extend(set);
        outer
    }

    fn time(secs: u64) -> Time {
        Time::GeneralTime(
            GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(secs)).unwrap(),
        )
    }

    /// Issue a certificate for `subject_key` named `subject`, signed by
    /// `issuer_key` in the name of `issuer`. `ca` sets basicConstraints.
    pub fn issue(
        subject: &str,
        subject_key: &p256::ecdsa::SigningKey,
        issuer: &str,
        issuer_key: &p256::ecdsa::SigningKey,
        ca: bool,
        serial: u8,
    ) -> Vec<u8> {
        issue_with_spki(
            subject,
            subject_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
            issuer,
            issuer_key,
            ca,
            serial,
            (1_000_000_000, 4_000_000_000),
            &[],
        )
    }

    /// Like [`issue`], with an explicit SPKI, validity and extra extensions
    /// (`(oid, value)` pairs, value already DER).
    pub fn issue_with_spki(
        subject: &str,
        spki_der: &[u8],
        issuer: &str,
        issuer_key: &p256::ecdsa::SigningKey,
        ca: bool,
        serial: u8,
        validity: (u64, u64),
        extra: &[(&str, Vec<u8>)],
    ) -> Vec<u8> {
        use x509_cert::ext::Extension;
        use x509_cert::ext::pkix::BasicConstraints;
        let bc = BasicConstraints {
            ca,
            path_len_constraint: None,
        }
        .to_der()
        .unwrap();
        let mut exts = vec![Extension {
            extn_id: "2.5.29.19".parse().unwrap(),
            critical: true,
            extn_value: der::asn1::OctetString::new(bc).unwrap(),
        }];
        for (oid, v) in extra {
            exts.push(Extension {
                extn_id: oid.parse().unwrap(),
                critical: false,
                extn_value: der::asn1::OctetString::new(v.clone()).unwrap(),
            });
        }
        let alg = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: "1.2.840.10045.4.3.2".parse().unwrap(),
            parameters: None,
        };
        let tbs = x509_cert::TbsCertificate {
            version: x509_cert::Version::V3,
            serial_number: x509_cert::serial_number::SerialNumber::new(&[serial.max(1)]).unwrap(),
            signature: alg.clone(),
            issuer: name(issuer),
            validity: Validity {
                not_before: time(validity.0),
                not_after: time(validity.1),
            },
            subject: name(subject),
            subject_public_key_info: x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(spki_der)
                .unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(exts),
        };
        let tbs_der = tbs.to_der().unwrap();
        let digest: [u8; 32] = Sha256::digest(&tbs_der).into();
        let sig: p256::ecdsa::Signature = issuer_key.sign_prehash(&digest).unwrap();
        let cert = x509_cert::Certificate {
            tbs_certificate: tbs,
            signature_algorithm: alg,
            signature: BitString::from_bytes(sig.to_der().as_bytes()).unwrap(),
        };
        cert.to_der().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testca::*;
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn chain() -> (Cert, Cert, Cert) {
        let root_k = key(1);
        let int_k = key(2);
        let leaf_k = key(3);
        let root = parse(&issue("Root", &root_k, "Root", &root_k, true, 1)).unwrap();
        let int = parse(&issue("Intermediate", &int_k, "Root", &root_k, true, 2)).unwrap();
        let leaf = parse(&issue("Leaf", &leaf_k, "Intermediate", &int_k, false, 3)).unwrap();
        (root, int, leaf)
    }

    #[test]
    fn a_signed_chain_validates() {
        let (root, int, leaf) = chain();
        assert_eq!(
            verify_chain(
                &[leaf.clone(), int.clone()],
                std::slice::from_ref(&root),
                NOW
            )
            .unwrap(),
            0
        );
        assert_eq!(
            verify_chain(&[leaf, int, root.clone()], &[root], NOW).unwrap(),
            0
        );
    }

    #[test]
    fn a_name_match_without_the_signature_is_refused() {
        // An attacker mints its own "Intermediate" with the right names but its
        // own key; the name matches, the signature from Root does not.
        let (root, _int, _leaf) = chain();
        let fake_k = key(9);
        let fake_int = parse(&issue("Intermediate", &fake_k, "Root", &fake_k, true, 2)).unwrap();
        let leaf = parse(&issue("Leaf", &key(3), "Intermediate", &fake_k, false, 3)).unwrap();
        assert!(verify_chain(&[leaf, fake_int], &[root], NOW).is_err());
    }

    #[test]
    fn the_root_alone_cannot_vouch_for_itself_as_a_leaf_issuer_it_did_not_sign() {
        let (root, _int, _leaf) = chain();
        let self_leaf = parse(&issue("Leaf", &key(3), "Root", &key(3), false, 4)).unwrap();
        assert!(verify_chain(&[self_leaf, root.clone()], &[root], NOW).is_err());
    }

    #[test]
    fn a_non_ca_issuer_is_refused() {
        let root_k = key(1);
        let root = parse(&issue("Root", &root_k, "Root", &root_k, true, 1)).unwrap();
        let mid_k = key(5);
        let mid = parse(&issue("Mid", &mid_k, "Root", &root_k, false, 2)).unwrap();
        let leaf = parse(&issue("Leaf", &key(6), "Mid", &mid_k, false, 3)).unwrap();
        assert!(verify_chain(&[leaf, mid], &[root], NOW).is_err());
    }

    #[test]
    fn an_expired_certificate_is_refused() {
        let (root, int, leaf) = chain();
        assert!(verify_chain(&[leaf, int], &[root], 4_100_000_000).is_err());
    }

    #[test]
    fn an_unknown_root_is_refused() {
        let (_root, int, leaf) = chain();
        let other_k = key(7);
        let other = parse(&issue("Root", &other_k, "Root", &other_k, true, 1)).unwrap();
        assert!(verify_chain(&[leaf, int], &[other], NOW).is_err());
    }

    #[test]
    fn pem_round_trip() {
        let (root, _, _) = chain();
        use base64::Engine;
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(&root.der)
        );
        assert_eq!(parse_pem_chain(&pem).unwrap()[0].der, root.der);
    }
}
