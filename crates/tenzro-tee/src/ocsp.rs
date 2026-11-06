//! Certificate revocation asked of an OCSP responder (RFC 6960): the request
//! for one certificate, and the check of the responder's signed answer.
//!
//! Asking is an online question, so it is never part of what a chain
//! verifies on its own; a node that asks does so as a local choice. This
//! module does no I/O: the caller sends [`request`] and hands the body it gets
//! back to [`check_response`].

use der::asn1::{ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use sha2::{Digest, Sha384};
use spki_v07::AlgorithmIdentifierOwned;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::serial_number::SerialNumber;
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus, Request,
    TbsRequest, Version,
};

use crate::error::{Result, TeeError};
use crate::x509::{self, Cert};

fn fail(msg: impl Into<String>) -> TeeError {
    TeeError::AttestationVerificationFailed(msg.into())
}

const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OCSP_BASIC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
const OCSP_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
const KP_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");
const EXTENDED_KEY_USAGE: &str = "2.5.29.37";
/// How far a responder's clock may run ahead of this one, in seconds.
const CLOCK_SKEW: u64 = 300;

/// The SHA-384 identifier of `cert` under `issuer`, as a request names it.
pub fn cert_id(cert: &Cert, issuer: &Cert) -> Result<CertId> {
    if cert.issuer_der != issuer.subject_der {
        return Err(fail(
            "the issuer given is not the one that issued the certificate",
        ));
    }
    let octets = |bytes: Vec<u8>| OctetString::new(bytes).map_err(|e| fail(e.to_string()));
    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: SHA384,
            parameters: None,
        },
        issuer_name_hash: octets(Sha384::digest(&issuer.subject_der).to_vec())?,
        issuer_key_hash: octets(Sha384::digest(issuer.public_key_bits()?).to_vec())?,
        serial_number: SerialNumber::new(&cert.serial).map_err(|e| fail(e.to_string()))?,
    })
}

/// A DER `OCSPRequest` for `cert` under `issuer`, carrying `nonce`.
pub fn request(cert: &Cert, issuer: &Cert, nonce: &[u8]) -> Result<Vec<u8>> {
    let encode = |e: der::Error| fail(format!("OCSP request: {e}"));
    let nonce = OctetString::new(nonce.to_vec()).map_err(encode)?;
    let extension = Extension {
        extn_id: OCSP_NONCE,
        critical: false,
        extn_value: OctetString::new(nonce.to_der().map_err(encode)?).map_err(encode)?,
    };
    OcspRequest {
        tbs_request: TbsRequest {
            version: Version::V1,
            requestor_name: None,
            request_list: vec![Request {
                req_cert: cert_id(cert, issuer)?,
                single_request_extensions: None,
            }],
            request_extensions: Some(vec![extension]),
        },
        optional_signature: None,
    }
    .to_der()
    .map_err(encode)
}

/// Check a responder's DER `OCSPResponse` about `cert` under `issuer` at
/// unix time `now`: signed by the issuer or by a responder it delegated OCSP
/// signing to, current, answering `nonce` when it echoes one, and saying the
/// certificate is good. Revoked and unknown are both refusals.
pub fn check_response(
    response_der: &[u8],
    cert: &Cert,
    issuer: &Cert,
    nonce: &[u8],
    now: u64,
) -> Result<()> {
    let malformed = |e: der::Error| fail(format!("OCSP response: {e}"));
    let response = OcspResponse::from_der(response_der).map_err(malformed)?;
    if response.response_status != OcspResponseStatus::Successful {
        return Err(fail(format!(
            "the OCSP responder answered {:?}",
            response.response_status
        )));
    }
    let bytes = response
        .response_bytes
        .ok_or_else(|| fail("a successful OCSP response without its body"))?;
    if bytes.response_type != OCSP_BASIC {
        return Err(fail("the OCSP response is not a basic response"));
    }
    let basic = BasicOcspResponse::from_der(bytes.response.as_bytes()).map_err(malformed)?;
    let tbs = basic.tbs_response_data.to_der().map_err(malformed)?;
    let params = basic
        .signature_algorithm
        .parameters
        .as_ref()
        .map(|p| p.to_der())
        .transpose()
        .map_err(malformed)?;
    x509::verify_signature(
        &basic.signature_algorithm.oid.to_string(),
        params.as_deref(),
        &responder_key(&basic, issuer, now)?,
        &tbs,
        basic
            .signature
            .as_bytes()
            .ok_or_else(|| fail("the OCSP signature bit string has unused bits"))?,
    )
    .map_err(|e| fail(format!("the OCSP response signature: {e}")))?;

    let data = &basic.tbs_response_data;
    if let Some(echoed) = data
        .response_extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id == OCSP_NONCE)
    {
        let raw = echoed.extn_value.as_bytes();
        let inner = OctetString::from_der(raw).ok();
        if raw != nonce && inner.as_ref().map(|o| o.as_bytes()) != Some(nonce) {
            return Err(fail("the OCSP response answers another nonce"));
        }
    }
    let id = cert_id(cert, issuer)?;
    let single = data
        .responses
        .iter()
        .find(|r| {
            r.cert_id.serial_number == id.serial_number
                && r.cert_id.issuer_name_hash == id.issuer_name_hash
                && r.cert_id.issuer_key_hash == id.issuer_key_hash
        })
        .ok_or_else(|| fail("the OCSP response does not answer for the certificate"))?;
    if single.this_update.0.to_unix_duration().as_secs() > now + CLOCK_SKEW {
        return Err(fail("the OCSP response is dated in the future"));
    }
    if let Some(next) = &single.next_update
        && now > next.0.to_unix_duration().as_secs()
    {
        return Err(fail("the OCSP response is past its next update"));
    }
    match &single.cert_status {
        CertStatus::Good(_) => Ok(()),
        CertStatus::Revoked(info) => Err(fail(format!(
            "the certificate was revoked at unix time {}",
            info.revocation_time.0.to_unix_duration().as_secs()
        ))),
        CertStatus::Unknown(_) => Err(fail("the certificate is unknown to its OCSP responder")),
    }
}

/// The key the response must be signed with: a responder certificate it
/// carries that `issuer` issued for OCSP signing and that is valid at `now`,
/// or else the issuer's own.
fn responder_key(basic: &BasicOcspResponse, issuer: &Cert, now: u64) -> Result<Vec<u8>> {
    for carried in basic.certs.iter().flatten() {
        let responder = x509::parse(
            &carried
                .to_der()
                .map_err(|e| fail(format!("OCSP responder certificate: {e}")))?,
        )?;
        let delegated = responder
            .extension(EXTENDED_KEY_USAGE)
            .and_then(|v| ExtendedKeyUsage::from_der(v).ok())
            .is_some_and(|eku| eku.0.contains(&KP_OCSP_SIGNING));
        if responder.issuer_der != issuer.subject_der || !delegated {
            continue;
        }
        x509::verify_signature(
            &responder.signature_algorithm,
            responder.signature_params.as_deref(),
            &issuer.spki_der,
            &responder.tbs_der,
            &responder.signature,
        )
        .map_err(|e| fail(format!("the OCSP responder certificate: {e}")))?;
        if now < responder.not_before || now > responder.not_after {
            return Err(fail("the OCSP responder certificate is not valid now"));
        }
        return Ok(responder.spki_der);
    }
    Ok(issuer.spki_der.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::{BitString, GeneralizedTime, Null};
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::Sha256;
    use x509_cert::Certificate;
    use x509_ocsp::{
        OcspGeneralizedTime, ResponderId, ResponseBytes, ResponseData, RevokedInfo, SingleResponse,
    };

    use crate::x509::testca::{issue, issue_with_spki, key};

    const NOW: u64 = 1_792_886_400;
    const NONCE: [u8; 32] = [0x4e; 32];

    struct Pki {
        ca: Cert,
        ca_key: SigningKey,
        leaf: Cert,
        responder: Certificate,
        responder_key: SigningKey,
        plain: Certificate,
    }

    fn pki() -> Pki {
        let ca_key = key(0x51);
        let ca = issue("Test OCSP CA", &ca_key, "Test OCSP CA", &ca_key, true, 1);
        let leaf = issue("Test Device", &key(0x52), "Test OCSP CA", &ca_key, false, 7);
        let responder_key = key(0x53);
        let spki = |k: &SigningKey| {
            use spki::EncodePublicKey;
            k.verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes()
                .to_vec()
        };
        let eku = ExtendedKeyUsage(vec![KP_OCSP_SIGNING]).to_der().unwrap();
        let responder = issue_with_spki(
            "Test OCSP Responder",
            &spki(&responder_key),
            "Test OCSP CA",
            &ca_key,
            false,
            9,
            (1_000_000_000, 4_000_000_000),
            &[(EXTENDED_KEY_USAGE, eku)],
        );
        let plain = issue_with_spki(
            "Test Not A Responder",
            &spki(&responder_key),
            "Test OCSP CA",
            &ca_key,
            false,
            10,
            (1_000_000_000, 4_000_000_000),
            &[],
        );
        Pki {
            ca: x509::parse(&ca).unwrap(),
            ca_key,
            leaf: x509::parse(&leaf).unwrap(),
            responder: Certificate::from_der(&responder).unwrap(),
            responder_key,
            plain: Certificate::from_der(&plain).unwrap(),
        }
    }

    fn time(secs: u64) -> OcspGeneralizedTime {
        OcspGeneralizedTime(
            GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(secs)).unwrap(),
        )
    }

    struct Answer<'a> {
        signer: &'a SigningKey,
        certs: Option<Vec<Certificate>>,
        status: CertStatus,
        nonce: Option<Vec<u8>>,
        next_update: Option<u64>,
        id: CertId,
    }

    fn respond(a: Answer) -> Vec<u8> {
        let tbs_response_data = ResponseData {
            version: Version::V1,
            responder_id: ResponderId::ByKey(OctetString::new(vec![0; 20]).unwrap()),
            produced_at: time(NOW - 60),
            responses: vec![SingleResponse {
                cert_id: a.id,
                cert_status: a.status,
                this_update: time(NOW - 60),
                next_update: a.next_update.map(time),
                single_extensions: None,
            }],
            response_extensions: a.nonce.map(|n| {
                vec![Extension {
                    extn_id: OCSP_NONCE,
                    critical: false,
                    extn_value: OctetString::new(OctetString::new(n).unwrap().to_der().unwrap())
                        .unwrap(),
                }]
            }),
        };
        let digest = Sha256::digest(tbs_response_data.to_der().unwrap());
        let sig: p256::ecdsa::Signature = a.signer.sign_prehash(&digest).unwrap();
        let basic = BasicOcspResponse {
            tbs_response_data,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
                parameters: None,
            },
            signature: BitString::from_bytes(sig.to_der().as_bytes()).unwrap(),
            certs: a.certs,
        };
        OcspResponse {
            response_status: OcspResponseStatus::Successful,
            response_bytes: Some(ResponseBytes {
                response_type: OCSP_BASIC,
                response: OctetString::new(basic.to_der().unwrap()).unwrap(),
            }),
        }
        .to_der()
        .unwrap()
    }

    fn good<'a>(p: &'a Pki) -> Answer<'a> {
        Answer {
            signer: &p.ca_key,
            certs: None,
            status: CertStatus::Good(Null),
            nonce: Some(NONCE.to_vec()),
            next_update: Some(NOW + 3600),
            id: cert_id(&p.leaf, &p.ca).unwrap(),
        }
    }

    #[test]
    fn the_request_names_the_certificate_and_carries_the_nonce() {
        let p = pki();
        let der = request(&p.leaf, &p.ca, &NONCE).unwrap();
        let req = OcspRequest::from_der(&der).unwrap();
        assert_eq!(
            req.tbs_request.request_list[0].req_cert,
            cert_id(&p.leaf, &p.ca).unwrap()
        );
        let ext = &req.tbs_request.request_extensions.unwrap()[0];
        assert_eq!(ext.extn_id, OCSP_NONCE);
        assert_eq!(
            OctetString::from_der(ext.extn_value.as_bytes())
                .unwrap()
                .as_bytes(),
            NONCE
        );
        // A certificate under another issuer is not asked about.
        assert!(request(&p.ca, &p.leaf, &NONCE).is_err());
    }

    #[test]
    fn a_good_answer_by_the_issuer_or_its_delegated_responder_passes() {
        let p = pki();
        check_response(&respond(good(&p)), &p.leaf, &p.ca, &NONCE, NOW).unwrap();
        let delegated = Answer {
            signer: &p.responder_key,
            certs: Some(vec![p.responder.clone()]),
            ..good(&p)
        };
        check_response(&respond(delegated), &p.leaf, &p.ca, &NONCE, NOW).unwrap();
        // A responder that does not echo the nonce answers on its dates.
        let silent = Answer {
            nonce: None,
            ..good(&p)
        };
        check_response(&respond(silent), &p.leaf, &p.ca, &NONCE, NOW).unwrap();
    }

    #[test]
    fn revoked_unknown_stale_or_foreign_answers_are_refusals() {
        let p = pki();
        let revoked = Answer {
            status: CertStatus::Revoked(RevokedInfo {
                revocation_time: time(NOW - 600),
                revocation_reason: None,
            }),
            ..good(&p)
        };
        let err = check_response(&respond(revoked), &p.leaf, &p.ca, &NONCE, NOW).unwrap_err();
        assert!(err.to_string().contains("revoked"), "{err}");
        let unknown = Answer {
            status: CertStatus::Unknown(Null),
            ..good(&p)
        };
        assert!(check_response(&respond(unknown), &p.leaf, &p.ca, &NONCE, NOW).is_err());
        let stale = Answer {
            next_update: Some(NOW - 1),
            ..good(&p)
        };
        assert!(check_response(&respond(stale), &p.leaf, &p.ca, &NONCE, NOW).is_err());
        let replayed = Answer {
            nonce: Some(vec![0; 32]),
            ..good(&p)
        };
        let err = check_response(&respond(replayed), &p.leaf, &p.ca, &NONCE, NOW).unwrap_err();
        assert!(err.to_string().contains("another nonce"), "{err}");
        // Signed by a key the issuer never delegated OCSP signing to.
        let forged = Answer {
            signer: &p.responder_key,
            ..good(&p)
        };
        assert!(check_response(&respond(forged), &p.leaf, &p.ca, &NONCE, NOW).is_err());
        let undelegated = Answer {
            signer: &p.responder_key,
            certs: Some(vec![p.plain.clone()]),
            ..good(&p)
        };
        assert!(check_response(&respond(undelegated), &p.leaf, &p.ca, &NONCE, NOW).is_err());
        // An answer about another certificate.
        let other = Answer {
            id: cert_id(&x509::parse(&p.plain.to_der().unwrap()).unwrap(), &p.ca).unwrap(),
            ..good(&p)
        };
        assert!(check_response(&respond(other), &p.leaf, &p.ca, &NONCE, NOW).is_err());
        assert!(check_response(b"not der", &p.leaf, &p.ca, &NONCE, NOW).is_err());
    }
}
