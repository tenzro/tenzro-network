//! The SDK's event-proof verifier against the shared fixture, which the
//! chain's own types pin (`tenzro-consensus/tests/event_proof_fixture.rs`):
//! what the node serves, the SDK accepts, and a tampered proof fails.

use serde_json::Value;
use tenzro_sdk::{
    checkpoint_digest, filter_index_keys, filter_selects, verify_completeness, verify_event_proof,
    verify_index_answer,
};

fn fixture() -> (Value, [u8; 32]) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/event-proof/fixture.json");
    let f: Value =
        serde_json::from_slice(&std::fs::read(path).expect("the shared fixture")).unwrap();
    let anchor: [u8; 32] = hex::decode(f["anchor_digest"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    (f, anchor)
}

#[test]
fn the_sdk_computes_the_chains_checkpoint_digest() {
    let (f, anchor) = fixture();
    let last = f["proof"]["checkpoints"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(checkpoint_digest(&last).unwrap(), anchor);
}

#[test]
fn blake3_matches_the_chains() {
    let (f, _) = fixture();
    let input: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        hex::encode(blake3::hash(&input).as_bytes()),
        f["blake3_3000"].as_str().unwrap()
    );
}

#[test]
fn a_served_proof_verifies_and_a_tampered_one_does_not() {
    let (f, anchor) = fixture();
    let proof = &f["proof"];
    verify_event_proof(proof, &anchor).unwrap();

    let mut tampered = proof.clone();
    tampered["event"]["data"][0] = Value::from(0);
    assert!(
        verify_event_proof(&tampered, &anchor).is_err(),
        "changed log data"
    );

    let mut tampered = proof.clone();
    tampered["header"]["metadata"]["gas_used"] = Value::from(1);
    assert!(
        verify_event_proof(&tampered, &anchor).is_err(),
        "changed header"
    );

    assert!(
        verify_event_proof(proof, &[0; 32]).is_err(),
        "not the certified checkpoint"
    );
}

#[test]
fn an_index_answer_verifies_only_as_its_projection() {
    let (f, anchor) = fixture();
    verify_index_answer(&f["answer"], &anchor).unwrap();
    let mut lie = f["answer"].clone();
    lie["result"] = Value::from(99);
    assert!(verify_index_answer(&lie, &anchor).is_err());
}

#[test]
fn a_complete_page_verifies_and_an_omission_does_not() {
    let (f, anchor) = fixture();
    let c = &f["completeness"];
    let filter = &c["filter"];
    let keys = filter_index_keys(filter).unwrap();
    let answer = c["answer"].as_array().unwrap().clone();
    let selects = |e: &Value| filter_selects(filter, e);
    verify_completeness(&c["proof"], &anchor, &keys, &answer, &selects).unwrap();
    for skip in 0..answer.len() {
        let mut short = answer.clone();
        short.remove(skip);
        assert!(
            verify_completeness(&c["proof"], &anchor, &keys, &short, &selects).is_err(),
            "omitted {skip}"
        );
    }
    let mut tampered = c["proof"].clone();
    tampered["blocks"][1]["entries"][0]["entry"]["cursors"] = serde_json::json!([]);
    assert!(
        verify_completeness(&tampered, &anchor, &keys, &answer, &selects).is_err(),
        "an entry emptied"
    );
}
