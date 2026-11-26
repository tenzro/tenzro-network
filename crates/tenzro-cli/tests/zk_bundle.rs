//! `tenzro zk prove` writes the proof bundle, and only the bundle, to
//! standard output, so the redirected output is what `tenzro zk verify`
//! reads, in every output format.

use std::io::Write as _;
use std::process::{Command, Stdio};

const WITNESS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const BINDING: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn word(value: &serde_json::Value) -> Vec<u8> {
    let text = value.as_str().expect("hex string");
    hex::decode(text.strip_prefix("0x").expect("0x prefix")).expect("hex")
}

fn prove(extra: &[&str]) -> serde_json::Value {
    let home = tempfile::tempdir().expect("temp home");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tenzro"))
        .args(extra)
        .args([
            "zk",
            "prove",
            "--circuit-id",
            "settlement",
            "--binding",
            BINDING,
        ])
        .env("TENZRO_HOME", home.path())
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("TENZRO_NO_BANNER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run tenzro");
    writeln!(child.stdin.take().expect("stdin"), "{WITNESS}").expect("write witness");
    let out = child.wait_with_output().expect("wait for tenzro");
    assert!(
        out.status.success(),
        "zk prove failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "standard output is not one JSON document ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

fn assert_bundle_verifies(bundle: &serde_json::Value) {
    assert_eq!(bundle["circuit_id"], "settlement");
    let inputs: Vec<Vec<u8>> = bundle["public_inputs"]
        .as_array()
        .expect("public inputs")
        .iter()
        .map(word)
        .collect();
    assert_eq!(inputs.len(), 2);
    assert_eq!(inputs[1], hex::decode(BINDING).unwrap());
    let legs = bundle["proofs"].as_array().expect("proofs");
    assert_eq!(legs.len(), tenzro_zk::ProofSystem::ALL.len());
    for leg in legs {
        let name = leg["system"].as_str().expect("system name");
        let system = tenzro_zk::ProofSystem::parse(name).expect("known system");
        let proof = tenzro_zk::Proof::new_in(
            system,
            word(&leg["proof"]),
            inputs.clone(),
            "settlement".to_string(),
        );
        tenzro_zk::verify_proof_envelope(&proof)
            .unwrap_or_else(|e| panic!("the {name} leg does not verify: {e}"));
    }
}

#[test]
fn the_bundle_is_the_whole_of_standard_output() {
    assert_bundle_verifies(&prove(&[]));
}

#[test]
fn the_bundle_is_the_whole_of_standard_output_with_format_json() {
    assert_bundle_verifies(&prove(&["--format", "json"]));
}
