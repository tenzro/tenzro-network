//! The SDK's offline governance-receipt check against the shared fixtures:
//! a receipt certified from genesis (`tenzro-consensus` writes it, the CLI
//! checks it from the genesis anchor) verifies under its certified root, and
//! every tampering is refused.
use serde_json::Value;
use tenzro_sdk::verify_governance_receipt;

fn fixture(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/governance_receipt")
        .join(name);
    serde_json::from_slice(&std::fs::read(path).expect("the shared fixture")).unwrap()
}

fn root(f: &Value) -> [u8; 32] {
    hex::decode(f["certified_state_root"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn a_certified_receipt_verifies_offline() {
    let f = fixture("receipt_from_genesis.json");
    let report = verify_governance_receipt(&f["receipt"], &root(&f)).unwrap();
    assert_eq!(report.executed_height, f["executed_height"].as_u64());
    assert_eq!(report.proposal["status"], "executed");
    assert_eq!(report.tally.unwrap()["yes"], "3");
    assert_eq!(report.veto_locked, 0);
}

#[test]
fn every_tampering_is_refused() {
    let f = fixture("receipt_from_genesis.json");
    let (receipt, root) = (&f["receipt"], root(&f));
    assert!(
        verify_governance_receipt(receipt, &[9; 32]).is_err(),
        "another certified root"
    );

    let record = |r: &mut Value, kind: &str| -> usize {
        r["records"]
            .as_array()
            .unwrap()
            .iter()
            .position(|x| x["kind"] == kind)
            .unwrap()
    };
    let mut r = receipt.clone();
    let i = record(&mut r, "tally");
    r["records"][i]["value"] =
        Value::from(hex::encode(br#"{"yes":"4","no":"0","total_eligible":"4"}"#));
    assert!(
        verify_governance_receipt(&r, &root).is_err(),
        "a tally the root does not hold"
    );

    let mut r = receipt.clone();
    let i = record(&mut r, "veto_total");
    r["records"][i]["value"] = Value::from(hex::encode(1u128.to_le_bytes()));
    assert!(
        verify_governance_receipt(&r, &root).is_err(),
        "a veto escrow proven absent"
    );

    let mut r = receipt.clone();
    let i = record(&mut r, "decision");
    r["records"].as_array_mut().unwrap().remove(i);
    assert!(
        verify_governance_receipt(&r, &root).is_err(),
        "every record is proven, absent or not"
    );

    let mut r = receipt.clone();
    r["records"][0]["subject"] = Value::from("cd".repeat(32));
    assert!(
        verify_governance_receipt(&r, &root).is_err(),
        "a record about another proposal"
    );

    let mut r = receipt.clone();
    let i = record(&mut r, "proposal");
    r["records"][i]["proof"]["siblings"][0][0] = Value::from(0);
    assert!(
        verify_governance_receipt(&r, &root).is_err(),
        "a broken path"
    );
}

/// The binary proof form the finality verifier reads, as the JSON the node
/// serves.
fn proof_json(hexed: &str) -> Value {
    let b = hex::decode(hexed).unwrap();
    let depth = u16::from_be_bytes([b[0], b[1]]) as usize;
    let word = |at: usize| Value::from(hex::encode(&b[at..at + 32]));
    let siblings: Vec<Value> = (0..depth).map(|d| word(2 + 32 * d)).collect();
    let t = 2 + 32 * depth;
    let terminal = match b[t] {
        0 => Value::from("Empty"),
        1 => {
            serde_json::json!({ "OtherStem": { "stem": hex::encode(&b[t + 1..t + 32]), "slots_root": hex::encode(&b[t + 32..t + 64]) } })
        }
        _ => {
            serde_json::json!({ "Stem": { "slot_siblings": (0..8).map(|i| word(t + 1 + 32 * i)).collect::<Vec<_>>() } })
        }
    };
    serde_json::json!({ "siblings": siblings, "terminal": terminal })
}

/// The proposal and decision records of the finality verifier's vectors
/// (which the VM pins) verify here too: the receipt fails only for the
/// records the vectors do not carry.
#[test]
fn the_finality_verifier_vectors_verify_here() {
    let v = fixture("vectors.json");
    let id = v["proposal_id"].as_str().unwrap();
    let record = |kind: &str, prefix: &str, value: &Value, proof: &str| serde_json::json!({ "kind": kind, "subject": id, "slot": format!("{prefix}{id}"), "value": value, "proof": proof_json(v[proof].as_str().unwrap()) });
    let mut receipt = serde_json::json!({
        "state_root": v["state_root"],
        "proposal_id": id,
        "records": [
            record("proposal", "proposal:", &v["proposal_record"], "proposal_proof"),
            record("decision", "governance_decision:", &v["decision"], "decision_proof"),
        ],
    });
    let root: [u8; 32] = hex::decode(v["state_root"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let err = verify_governance_receipt(&receipt, &root)
        .unwrap_err()
        .to_string();
    assert!(err.contains("tally"), "{err}");
    receipt["records"][1]["value"] =
        Value::from(format!("{}00", &v["decision"].as_str().unwrap()[..78]));
    let err = verify_governance_receipt(&receipt, &root)
        .unwrap_err()
        .to_string();
    assert!(err.contains("not proven"), "{err}");
}
