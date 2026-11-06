//! The published vectors verify or are refused for the reason they name,
//! and every change to a signed field or a bound TEE report, a foreign key
//! or an expired certificate is refused.

use serde_json::Value;
use tenzro_receipt_verify::{Error, Expect, digest, preimage, verify, verify_signature};

fn vectors() -> Vec<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/standards/vectors/inference-receipt.json"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    v["vectors"].as_array().unwrap().clone()
}

#[test]
fn every_published_vector_verifies_and_rebuilds_its_preimage() {
    let all = vectors();
    assert!(
        all.iter()
            .any(|v| v["receipt"]["public_key"].get("pq").is_some())
    );
    assert!(
        all.iter()
            .any(|v| v["receipt"]["public_key"].get("pq").is_none())
    );
    for v in all {
        let r = &v["receipt"];
        assert_eq!(
            hex::encode(preimage(r).unwrap()),
            v["preimage_hex"],
            "{}",
            v["label"]
        );
        assert_eq!(digest(r).unwrap(), v["digest"], "{}", v["label"]);
        let expect = Expect {
            model_hash: v["catalog_model_hash"].as_str(),
            nonce: r["nonce"].as_str(),
            output_hash: Some(&tenzro_receipt_verify::output_hash("hello", "", "")),
        };
        match v["refused"].as_str() {
            None => verify(r, &expect).unwrap(),
            Some("certificate_expired") => assert!(
                matches!(verify(r, &expect), Err(Error::CertificateExpired { .. })),
                "{}",
                v["label"]
            ),
            Some(other) => panic!("unknown refusal {other}"),
        }
    }
}

/// A TEE-attested receipt binds its report into the signed preimage: the
/// receipt verifies, and any change to the report breaks the signature.
#[test]
fn a_tee_attested_receipt_binds_its_report() {
    let all = vectors();
    let v = all
        .iter()
        .find(|v| v["receipt"]["tee"].is_object())
        .expect("a TEE-attested vector");
    let r = &v["receipt"];
    verify_signature(r).unwrap();
    let mut changed = r.clone();
    let m = changed
        .pointer_mut("/tee/report/measurement/0")
        .expect("a measurement");
    *m = (m.as_u64().unwrap() ^ 1).into();
    assert_eq!(verify_signature(&changed), Err(Error::BadSignature));
    let mut dropped = r.clone();
    dropped["tee"] = Value::Null;
    assert_eq!(verify_signature(&dropped), Err(Error::BadSignature));
}

/// The expired-certificate vector carries a session key its hardware key
/// did certify, so expiry is the only reason it is refused, and it is
/// refused whatever else a holder checks.
#[test]
fn the_expired_certificate_vector_is_refused_for_expiry() {
    let all = vectors();
    let v = all
        .iter()
        .find(|v| v["refused"] == "certificate_expired")
        .expect("an expired-certificate vector");
    let r = &v["receipt"];
    let not_after_ms = r["signature"]["certificate"]["not_after_ms"]
        .as_u64()
        .unwrap();
    let signed_at_ms = r["signed_at_ms"].as_u64().unwrap();
    assert!(signed_at_ms > not_after_ms);
    assert_eq!(
        verify_signature(r),
        Err(Error::CertificateExpired {
            not_after_ms,
            signed_at_ms
        })
    );
    assert!(matches!(
        verify(r, &Expect::default()),
        Err(Error::CertificateExpired { .. })
    ));
}

#[test]
fn a_change_to_any_signed_field_is_refused() {
    for v in vectors().into_iter().filter(|v| v["refused"].is_null()) {
        let r = &v["receipt"];
        let edits: Vec<(&str, Value)> = vec![
            ("/model_id", "other".into()),
            ("/model_hash", "00".repeat(32).into()),
            ("/machine_did", "did:tenzro:machine:other".into()),
            ("/nonce", "nonce-2".into()),
            ("/output_hash", "00".repeat(32).into()),
            ("/units/output_tokens", 6.into()),
            ("/priced/charge", 1.into()),
            ("/provenance/0", "00".into()),
            ("/sampling/seed", 8.into()),
            ("/sampling/temperature", 0.8.into()),
            ("/decode/hardware_class", "cuda".into()),
            ("/commitment_hash", Value::Null),
            ("/activation_fingerprint", "ab".into()),
            (
                "/signed_at_ms",
                (r["signed_at_ms"].as_u64().unwrap() + 1).into(),
            ),
        ];
        for (at, value) in edits {
            let mut t = r.clone();
            *t.pointer_mut(at).unwrap_or_else(|| panic!("{at}")) = value;
            assert_eq!(
                verify_signature(&t),
                Err(Error::BadSignature),
                "{} {at}",
                v["label"]
            );
        }
    }
}

#[test]
fn a_foreign_identity_key_or_expired_certificate_is_refused() {
    let all = vectors();
    let (a, b) = (&all[0]["receipt"], &all[1]["receipt"]);
    let mut swapped = a.clone();
    swapped["public_key"] = b["public_key"].clone();
    assert!(matches!(
        verify_signature(&swapped),
        Err(Error::BadCertificate(_))
    ));

    let mut expired = a.clone();
    let not_after = a["signature"]["certificate"]["not_after_ms"]
        .as_u64()
        .unwrap();
    expired["signature"]["certificate"]["not_after_ms"] =
        (a["signed_at_ms"].as_u64().unwrap() - 1).into();
    assert!(
        matches!(verify_signature(&expired), Err(Error::BadCertificate(_))),
        "{not_after}"
    );

    assert_eq!(
        verify(
            a,
            &Expect {
                model_hash: Some("cd"),
                ..Default::default()
            }
        ),
        Err(Error::ModelHashMismatch)
    );
    assert_eq!(
        verify(
            a,
            &Expect {
                nonce: Some("other"),
                ..Default::default()
            }
        ),
        Err(Error::NonceMismatch)
    );
}

/// The verifier stands on the published format alone: nothing it builds
/// from is a Tenzro crate.
#[test]
fn no_tenzro_crate_is_linked() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock")).unwrap();
    let names: Vec<&str> = lock
        .lines()
        .filter_map(|l| l.strip_prefix("name = \""))
        .map(|n| n.trim_end_matches('"'))
        .collect();
    assert!(names.contains(&"tenzro-receipt-verify"));
    let foreign: Vec<_> = names
        .iter()
        .filter(|n| n.starts_with("tenzro") && **n != "tenzro-receipt-verify")
        .collect();
    assert!(foreign.is_empty(), "{foreign:?}");
}
