//! AWS Nitro Enclaves attestation document verification.
//!
//! The document is a COSE_Sign1 (ES384) whose payload is a CBOR map carrying
//! the enclave's PCRs, a leaf certificate and a CA bundle. It is accepted only
//! when:
//!
//! - the CA bundle starts with the AWS Nitro root pinned in [`crate::certs`]
//!   (compared byte for byte) and the chain leaf -> bundle -> root verifies by
//!   signature at the verification time;
//! - the COSE signature verifies under the leaf certificate's P-384 key, over
//!   the exact `Sig_structure` COSE defines;
//! - the document is no older than the policy allows (its timestamp is signed
//!   by the NSM, so it is trustworthy once the signature is);
//! - PCR0 is not all zeros (an all-zero PCR0 is what a debug-mode enclave
//!   reports);
//! - `user_data` equals the verifier's challenge.

use std::collections::BTreeMap;

use ciborium::value::Value;
use sha2::{Digest, Sha384};
use tenzro_types::tee::{AttestationReport, Measurement, TeeVendor};

use super::{VerifiedAttestation, VerifyPolicy, ct_eq, fail};
use crate::error::Result;
use crate::x509::{self, Cert};

/// COSE algorithm identifier for ECDSA with SHA-384.
const COSE_ES384: i128 = -35;

fn aws_root() -> Result<Cert> {
    Ok(x509::parse_pem_chain(crate::certs::AWS_NITRO_ROOT_CA_PEM)?.remove(0))
}

pub fn verify(report: &AttestationReport, policy: &VerifyPolicy) -> Result<VerifiedAttestation> {
    verify_document(&report.attestation_data, &aws_root()?, policy)
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
        .map(|(_, v)| v)
}

fn bytes(v: Option<&Value>, what: &str) -> Result<Vec<u8>> {
    match v {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(fail(format!(
            "Nitro document field {what} is missing or not bytes"
        ))),
    }
}

/// Verify a COSE_Sign1 document against `root`.
pub fn verify_document(
    doc: &[u8],
    root: &Cert,
    policy: &VerifyPolicy,
) -> Result<VerifiedAttestation> {
    let value: Value =
        ciborium::de::from_reader(doc).map_err(|e| fail(format!("Nitro document CBOR: {e}")))?;
    let value = match value {
        Value::Tag(18, inner) => *inner,
        v => v,
    };
    let Value::Array(parts) = value else {
        return Err(fail("Nitro document is not a COSE_Sign1 array"));
    };
    let [
        Value::Bytes(protected),
        _unprotected,
        Value::Bytes(payload),
        Value::Bytes(signature),
    ] = parts.as_slice()
    else {
        return Err(fail("Nitro document is not a COSE_Sign1 structure"));
    };

    let header: Value = ciborium::de::from_reader(protected.as_slice())
        .map_err(|e| fail(format!("COSE protected header: {e}")))?;
    let alg = match &header {
        Value::Map(m) => m.iter().find_map(|(k, v)| match (k, v) {
            (Value::Integer(k), Value::Integer(a)) if i128::from(*k) == 1 => Some(i128::from(*a)),
            _ => None,
        }),
        _ => None,
    };
    if alg != Some(COSE_ES384) {
        return Err(fail("Nitro document is not signed with ES384"));
    }

    let body: Value = ciborium::de::from_reader(payload.as_slice())
        .map_err(|e| fail(format!("Nitro payload CBOR: {e}")))?;
    let Value::Map(fields) = body else {
        return Err(fail("Nitro payload is not a map"));
    };

    let leaf = x509::parse(&bytes(map_get(&fields, "certificate"), "certificate")?)?;
    let bundle: Vec<Vec<u8>> = match map_get(&fields, "cabundle") {
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| match v {
                Value::Bytes(b) => Ok(b.clone()),
                _ => Err(fail("cabundle entry is not bytes")),
            })
            .collect::<Result<_>>()?,
        _ => return Err(fail("Nitro document has no cabundle")),
    };
    if bundle.first().map(|b| b.as_slice()) != Some(root.der.as_slice()) {
        return Err(fail("Nitro cabundle does not start at the AWS Nitro root"));
    }
    let mut chain = vec![leaf];
    for der in bundle.iter().rev() {
        chain.push(x509::parse(der)?);
    }
    x509::verify_chain(&chain, std::slice::from_ref(root), policy.now)?;

    let mut sig_structure = Vec::new();
    ciborium::ser::into_writer(
        &Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(payload.clone()),
        ]),
        &mut sig_structure,
    )
    .map_err(|e| fail(format!("Sig_structure: {e}")))?;
    x509::verify_ecdsa_prehash(
        &chain[0].spki_der,
        &Sha384::digest(&sig_structure),
        signature,
    )
    .map_err(|_| fail("Nitro document signature does not verify under its leaf certificate"))?;

    let timestamp_ms = match map_get(&fields, "timestamp") {
        Some(Value::Integer(i)) => {
            u64::try_from(i128::from(*i)).map_err(|_| fail("bad timestamp"))?
        }
        _ => return Err(fail("Nitro document has no timestamp")),
    };
    let age = policy.now.saturating_sub(timestamp_ms / 1000);
    if age > policy.max_age_secs || timestamp_ms / 1000 > policy.now + 60 {
        return Err(fail("Nitro document is not fresh"));
    }

    let mut measurements = Vec::new();
    let mut pcr0 = Vec::new();
    if let Some(Value::Map(pcrs)) = map_get(&fields, "pcrs") {
        for (k, v) in pcrs {
            if let (Value::Integer(i), Value::Bytes(b)) = (k, v) {
                let idx = i128::from(*i) as u32;
                if idx == 0 {
                    pcr0 = b.clone();
                }
                measurements.push(Measurement {
                    index: idx,
                    algorithm: "SHA384".into(),
                    value: b.clone(),
                    register: format!("PCR{idx}"),
                    description: None,
                });
            }
        }
    }
    if pcr0.is_empty() || pcr0.iter().all(|b| *b == 0) {
        return Err(fail("Nitro enclave PCR0 is empty or zero (debug mode)"));
    }

    let user_data = bytes(map_get(&fields, "user_data"), "user_data")?;
    if !ct_eq(&user_data, &policy.expected_user_data) {
        return Err(fail("Nitro user data does not answer this challenge"));
    }
    let module_id = match map_get(&fields, "module_id") {
        Some(Value::Text(t)) => t.clone(),
        _ => return Err(fail("Nitro document has no module id")),
    };

    let mut details = BTreeMap::new();
    details.insert("timestamp_ms".into(), timestamp_ms.to_string());
    Ok(VerifiedAttestation {
        vendor: TeeVendor::AwsNitro,
        measurement: pcr0,
        user_data,
        tcb_status: "NsmSigned".into(),
        platform_id: module_id.into_bytes(),
        measurements,
        details,
    })
}

#[cfg(test)]
mod tests {
    //! Documents here are built to the Nitro NSM format and signed by a P-384
    //! leaf under a test root; the production path pins the AWS root.

    use super::*;
    use crate::x509::testca;
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use spki::EncodePublicKey;

    const NOW: u64 = 1_800_000_000;

    fn leaf_key() -> p384::ecdsa::SigningKey {
        p384::ecdsa::SigningKey::from_slice(&[0x21; 48]).unwrap()
    }

    fn cbor(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(v, &mut out).unwrap();
        out
    }

    struct Doc {
        root: Cert,
        bytes: Vec<u8>,
    }

    fn document(
        user_data: &[u8],
        pcr0: Vec<u8>,
        ts_ms: u64,
        signer: &p384::ecdsa::SigningKey,
    ) -> Doc {
        let root_k = testca::key(60);
        let root_der = testca::issue(
            "aws.nitro-enclaves",
            &root_k,
            "aws.nitro-enclaves",
            &root_k,
            true,
            1,
        );
        let spki = leaf_key().verifying_key().to_public_key_der().unwrap();
        let leaf = testca::issue_with_spki(
            "i-0abc.enclave",
            spki.as_bytes(),
            "aws.nitro-enclaves",
            &root_k,
            false,
            2,
            (1_000_000_000, 4_000_000_000),
            &[],
        );
        let payload = cbor(&Value::Map(vec![
            (
                Value::Text("module_id".into()),
                Value::Text("i-0abc-enc01".into()),
            ),
            (Value::Text("digest".into()), Value::Text("SHA384".into())),
            (
                Value::Text("timestamp".into()),
                Value::Integer(ts_ms.into()),
            ),
            (
                Value::Text("pcrs".into()),
                Value::Map(vec![(Value::Integer(0.into()), Value::Bytes(pcr0))]),
            ),
            (Value::Text("certificate".into()), Value::Bytes(leaf)),
            (
                Value::Text("cabundle".into()),
                Value::Array(vec![Value::Bytes(root_der.clone())]),
            ),
            (
                Value::Text("user_data".into()),
                Value::Bytes(user_data.to_vec()),
            ),
        ]));
        let protected = cbor(&Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Integer((-35).into()),
        )]));
        let sig_structure = cbor(&Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected.clone()),
            Value::Bytes(vec![]),
            Value::Bytes(payload.clone()),
        ]));
        let sig: p384::ecdsa::Signature = signer
            .sign_prehash(&Sha384::digest(&sig_structure))
            .unwrap();
        let bytes = cbor(&Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(vec![]),
                Value::Bytes(payload),
                Value::Bytes(sig.to_bytes().to_vec()),
            ])),
        ));
        Doc {
            root: x509::parse(&root_der).unwrap(),
            bytes,
        }
    }

    fn policy(user_data: &[u8]) -> VerifyPolicy {
        VerifyPolicy {
            now: NOW,
            expected_user_data: user_data.to_vec(),
            max_age_secs: 600,
            nvidia_jwks: None,
        }
    }

    #[test]
    fn a_genuine_document_verifies() {
        let d = document(b"challenge", vec![9; 48], NOW * 1000, &leaf_key());
        let v = verify_document(&d.bytes, &d.root, &policy(b"challenge")).unwrap();
        assert_eq!(v.measurement, vec![9; 48]);
        assert_eq!(v.platform_id, b"i-0abc-enc01".to_vec());
    }

    #[test]
    fn a_document_signed_by_another_key_is_refused() {
        let attacker = p384::ecdsa::SigningKey::from_slice(&[0x22; 48]).unwrap();
        let d = document(b"challenge", vec![9; 48], NOW * 1000, &attacker);
        assert!(verify_document(&d.bytes, &d.root, &policy(b"challenge")).is_err());
    }

    #[test]
    fn the_root_alone_as_the_bundle_does_not_make_a_self_signed_leaf_valid() {
        // The production path pins the real AWS root: a document whose bundle
        // is a look-alike root is refused.
        let d = document(b"challenge", vec![9; 48], NOW * 1000, &leaf_key());
        assert!(verify_document(&d.bytes, &aws_root().unwrap(), &policy(b"challenge")).is_err());
    }

    #[test]
    fn a_stale_document_is_refused() {
        let d = document(b"challenge", vec![9; 48], (NOW - 3600) * 1000, &leaf_key());
        assert!(verify_document(&d.bytes, &d.root, &policy(b"challenge")).is_err());
    }

    #[test]
    fn a_debug_mode_enclave_is_refused() {
        let d = document(b"challenge", vec![0; 48], NOW * 1000, &leaf_key());
        assert!(verify_document(&d.bytes, &d.root, &policy(b"challenge")).is_err());
    }

    #[test]
    fn a_document_answering_another_challenge_is_refused() {
        let d = document(b"other", vec![9; 48], NOW * 1000, &leaf_key());
        assert!(verify_document(&d.bytes, &d.root, &policy(b"challenge")).is_err());
    }

    #[test]
    fn json_is_not_a_document() {
        let json = br#"{"simulated":true,"pcrs":{"0":"00"}}"#;
        assert!(verify_document(json, &aws_root().unwrap(), &policy(b"x")).is_err());
    }
}
