//! Wycheproof vectors (C2SP/wycheproof, `testvectors_v1`) against the node's
//! ML-DSA-65 and P-256 verifiers.
//!
//! Each case is checked against its expected verdict. For ML-DSA-65 the
//! public verifier and both implementations behind it are checked one by
//! one, so a vector that one implementation gets wrong names that
//! implementation.

use serde_json::Value;
use tenzro_crypto::p256::{P256Signature, P256Verifier};
use tenzro_crypto::pq::{libcrux_ml_dsa_verify, ml_dsa_verify, rustcrypto_ml_dsa_verify};

fn load(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/wycheproof/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn hex_field(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap_or_default()).expect("vector field is hex")
}

/// Every test of every group, with its group.
fn cases(file: &Value) -> Vec<(&Value, &Value)> {
    file["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .flat_map(|g| {
            g["tests"]
                .as_array()
                .expect("tests")
                .iter()
                .map(move |t| (g, t))
        })
        .collect()
}

/// `valid` must verify and `invalid` must not. Wycheproof's `acceptable`
/// is either.
fn expected(t: &Value) -> Option<bool> {
    match t["result"].as_str() {
        Some("valid") => Some(true),
        Some("invalid") => Some(false),
        _ => None,
    }
}

fn report(what: &str, failures: &[String], total: usize) {
    assert!(total > 0, "{what}: no vectors were read");
    assert!(
        failures.is_empty(),
        "{what}: {} of {total} vectors give the wrong verdict:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn ml_dsa_65_verify_vectors() {
    let file = load("mldsa_65_verify_test.json");
    let mut failures = Vec::new();
    let all = cases(&file);
    for (g, t) in &all {
        let Some(want) = expected(t) else { continue };
        let pk = hex_field(g, "publicKey");
        let (msg, sig, ctx) = (
            hex_field(t, "msg"),
            hex_field(t, "sig"),
            hex_field(t, "ctx"),
        );
        for (name, got) in [
            (
                "ml_dsa_verify",
                ml_dsa_verify(&pk, &ctx, &msg, &sig).is_ok(),
            ),
            (
                "rustcrypto",
                rustcrypto_ml_dsa_verify(&pk, &ctx, &msg, &sig).is_ok(),
            ),
            (
                "libcrux",
                libcrux_ml_dsa_verify(&pk, &ctx, &msg, &sig).is_ok(),
            ),
        ] {
            if got != want {
                failures.push(format!(
                    "tc {} ({}): {name} says {got}, expected {want}",
                    t["tcId"], t["comment"]
                ));
            }
        }
    }
    report("ML-DSA-65", &failures, all.len());
}

#[test]
fn p256_sha256_p1363_vectors() {
    let file = load("ecdsa_secp256r1_sha256_p1363_test.json");
    let mut failures = Vec::new();
    let all = cases(&file);
    for (g, t) in &all {
        let Some(want) = expected(t) else { continue };
        let pk = hex::decode(g["publicKey"]["uncompressed"].as_str().unwrap()).unwrap();
        let (msg, sig) = (hex_field(t, "msg"), hex_field(t, "sig"));
        let got = P256Verifier::from_sec1_bytes(&pk)
            .and_then(|v| v.verify_sha256(&msg, &P256Signature::from_slice(&sig)?))
            .is_ok();
        if got != want {
            failures.push(format!(
                "tc {} ({}): says {got}, expected {want}",
                t["tcId"], t["comment"]
            ));
        }
    }
    report("P-256 SHA-256", &failures, all.len());
}
