//! The vectors of docs/standards/machine-identity-onboarding.md hold for the
//! code admission runs: every identifier source is listed with the grade the
//! code gives it, and the DID derivation and the admission challenge give
//! the published values.

use serde_json::Value;
use tenzro_tee::tpm_attest::{admission_challenge, machine_did_for_attestation_key};
use tenzro_types::machine_id::{IdentifierGrade, IdentifierSource};

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/standards/vectors/machine-identity-onboarding.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn grade_name(grade: IdentifierGrade) -> &'static str {
    match grade {
        IdentifierGrade::Model => "model",
        IdentifierGrade::Fused => "fused",
        IdentifierGrade::Attestable => "attestable",
    }
}

#[test]
fn every_identifier_source_is_published_with_its_grade() {
    let all = vectors();
    let listed = all["identifier_sources"].as_array().unwrap();
    for v in listed {
        let label = v["label"].as_str().unwrap();
        let source = IdentifierSource::parse(label)
            .unwrap_or_else(|| panic!("{label} is not a source the code knows"));
        assert_eq!(grade_name(source.grade()), v["grade"], "{label}");
    }
    let every = IdentifierSource::ALL
        .into_iter()
        .chain(std::iter::once(IdentifierSource::SmbiosPlatform));
    for source in every {
        assert!(
            listed.iter().any(|v| v["label"] == source.as_str()),
            "{} is missing from the published table",
            source.as_str()
        );
    }
}

#[test]
fn the_did_derivation_gives_the_published_dids() {
    for v in vectors()["did_derivation"].as_array().unwrap() {
        let key: [u8; 65] = hex::decode(v["attestation_key_sec1"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            machine_did_for_attestation_key(&key),
            v["did"],
            "{}",
            v["label"]
        );
    }
}

#[test]
fn the_admission_challenge_gives_the_published_values() {
    for v in vectors()["admission_challenge"].as_array().unwrap() {
        let wallet = hex::decode(v["wallet_public_key"].as_str().unwrap()).unwrap();
        let nonce: [u8; 32] = hex::decode(v["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let did = v["did"].as_str().unwrap();
        assert_eq!(
            hex::encode(admission_challenge(did, &wallet, &nonce)),
            v["challenge"],
            "{}",
            v["label"]
        );
    }
}
