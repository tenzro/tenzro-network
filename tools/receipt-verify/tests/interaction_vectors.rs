//! The published interaction vectors rebuild their preimage and digest, the
//! refused ones are refused for the reason they name, and a change to any
//! covered field changes the digest.

use serde_json::Value;
use tenzro_receipt_verify::interaction::{
    InteractionError, interaction_digest, interaction_preimage,
};

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/standards/vectors/interaction-receipt.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn every_published_vector_rebuilds_its_preimage_and_digest() {
    let all = vectors();
    let accepted = all["vectors"].as_array().unwrap();
    assert!(accepted.len() >= 4);
    for v in accepted {
        let r = &v["record"];
        assert_eq!(
            hex::encode(interaction_preimage(r).unwrap()),
            v["preimage_hex"],
            "{}",
            v["label"]
        );
        assert_eq!(
            interaction_digest(r).unwrap(),
            v["digest"],
            "{}",
            v["label"]
        );
    }
}

#[test]
fn every_refused_vector_is_refused_for_its_reason() {
    for v in vectors()["refused"].as_array().unwrap() {
        let got = interaction_digest(&v["record"]).unwrap_err();
        let reason = match got {
            InteractionError::Malformed(_) => "malformed",
            InteractionError::NotAttestable(_) => "not_attestable",
        };
        assert_eq!(reason, v["reason"], "{}", v["label"]);
    }
}

#[test]
fn a_change_to_a_covered_field_changes_the_digest() {
    let all = vectors();
    let base = &all["vectors"][0]["record"];
    let digest = interaction_digest(base).unwrap();
    for (key, value) in [
        ("interaction_id", Value::from("int_x")),
        ("payer_did", Value::from("did:tenzro:machine:other")),
        ("on_behalf_of", Value::Null),
        ("attester_did", Value::from("did:tenzro:machine:other")),
        ("resource_id", Value::from("other-model")),
        ("amount_charged", Value::from(1001)),
        ("settled_asset", Value::from("other")),
        ("occurred_at", Value::from(1)),
    ] {
        let mut changed = base.clone();
        changed[key] = value;
        assert_ne!(interaction_digest(&changed).unwrap(), digest, "{key}");
    }
    let mut extra = base.clone();
    extra["payees"] = serde_json::json!([{ "amount": "1" }]);
    assert_eq!(
        interaction_digest(&extra).unwrap(),
        digest,
        "fields outside the preimage do not move the digest"
    );
}

#[test]
fn an_amount_past_64_bits_is_read_from_its_decimal_string() {
    let all = vectors();
    let big = all["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["record"]["amount_charged"].is_string())
        .expect("a vector with a string amount");
    let mut as_number = big["record"].clone();
    as_number["amount_charged"] = Value::from(u64::MAX);
    assert_ne!(
        interaction_digest(&as_number).unwrap(),
        big["digest"].as_str().unwrap()
    );
    let mut padded = big["record"].clone();
    padded["amount_charged"] = Value::from("+1");
    assert!(interaction_digest(&padded).is_err());
}

#[test]
fn a_digest_made_under_the_previous_version_no_longer_verifies() {
    use sha2::{Digest, Sha256};
    let all = vectors();
    let first = &all["vectors"][0];
    let preimage = interaction_preimage(&first["record"]).unwrap();
    let v2 = b"tenzro/interaction-attestation/v2";
    assert!(preimage.starts_with(v2));
    let mut old = b"tenzro/interaction-attestation/v1".to_vec();
    old.extend_from_slice(&preimage[v2.len()..]);
    let old_digest = hex::encode(Sha256::digest(&old));
    assert_ne!(old_digest, first["digest"].as_str().unwrap());
    assert_ne!(old_digest, interaction_digest(&first["record"]).unwrap());
}
