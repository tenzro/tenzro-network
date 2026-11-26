//! The published run manifest vectors have their digest, the refused ones
//! are refused for the reason they name, and a change to any covered member
//! changes the digest.

use serde_json::Value;
use tenzro_receipt_verify::run_manifest::{
    RUN_MANIFEST_DOMAIN, run_manifest_digest, run_manifest_preimage,
};

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/standards/vectors/run-manifest.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn every_published_manifest_has_its_digest() {
    let all = vectors();
    let accepted = all["vectors"].as_array().unwrap();
    assert!(accepted.len() >= 3);
    for v in accepted {
        let raw = v["manifest"].to_string();
        assert_eq!(
            run_manifest_digest(&raw).unwrap(),
            v["digest"].as_str().unwrap(),
            "{}",
            v["label"]
        );
        assert!(
            run_manifest_preimage(&raw)
                .unwrap()
                .starts_with(RUN_MANIFEST_DOMAIN)
        );
    }
}

#[test]
fn every_refused_manifest_is_refused_for_its_reason() {
    for v in vectors()["refused"].as_array().unwrap() {
        let got = run_manifest_digest(&v["manifest"].to_string()).unwrap_err();
        assert_eq!(got.reason(), v["reason"], "{}", v["label"]);
    }
}

#[test]
fn a_change_to_a_covered_member_changes_the_digest() {
    let base = vectors()["vectors"][0]["manifest"].clone();
    let digest = run_manifest_digest(&base.to_string()).unwrap();
    let mut changes: Vec<Value> = Vec::new();
    for (path, value) in [
        ("/run_id", Value::from("another-run")),
        ("/ended_at_ms", Value::from(1_763_370_600_001u64)),
        ("/outputs/0/bytes", Value::from(4_097u64)),
        ("/claims/0/value", Value::from("1201")),
        ("/claims/0/unit", Value::from("")),
    ] {
        let mut changed = base.clone();
        *changed.pointer_mut(path).unwrap() = value;
        changes.push(changed);
    }
    let mut without_claims = base.clone();
    without_claims["claims"] = serde_json::json!([]);
    changes.push(without_claims);
    for changed in changes {
        assert_ne!(run_manifest_digest(&changed.to_string()).unwrap(), digest);
    }
}

#[test]
fn a_string_with_a_lone_surrogate_is_refused() {
    let raw = vectors()["vectors"][0]["manifest"].to_string().replacen(
        "run-2026-11-17-001",
        "run-\\ud800",
        1,
    );
    assert_eq!(run_manifest_digest(&raw).unwrap_err().reason(), "malformed");
}
