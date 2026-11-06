//! The shared split vectors (sdk/fixtures/split): this SDK divides a gross
//! exactly as the chain does and hashes a rule to the same digest.

use serde_json::Value;
use tenzro_sdk::settle::{Allocation, FeeParams, SplitRule, preview_split};

#[test]
fn the_shared_split_vectors_hold() {
    let vectors: Vec<Value> =
        serde_json::from_str(include_str!("../../fixtures/split/vectors.json")).unwrap();
    assert!(!vectors.is_empty());
    let n = |v: &Value| -> u128 { v.as_str().unwrap().parse().unwrap() };
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let rule: SplitRule = serde_json::from_value(v["rule"].clone()).unwrap();
        let params: FeeParams = serde_json::from_value(v["params"].clone()).unwrap();
        let expect: Allocation = serde_json::from_value(v["expect"].clone()).unwrap();
        let got = preview_split(n(&v["gross"]), &rule, &params, n(&v["network_fees"])).unwrap();
        assert_eq!(got, expect, "{name}");
        assert_eq!(
            hex::encode(rule.hash().unwrap()),
            v["rule_hash"].as_str().unwrap(),
            "{name}"
        );
    }
}
