//! The bridge-send and payment operations the SDKs and MCP servers build
//! (sdk/fixtures/payment-ops/vectors.json) decode as the network's
//! operations, and those round-trip through the network's own encoding.

use std::path::Path;

use tenzro_types::bridge_transfer::BridgeOp;
use tenzro_types::settlement::PaymentOp;

fn vectors() -> serde_json::Value {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/fixtures/payment-ops/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vectors")).expect("json")
}

#[test]
fn bridge_outbound_vectors_are_network_ops() {
    for v in vectors()["bridge_outbound"].as_array().unwrap() {
        let json = v["fields"]["op"].clone();
        let op: BridgeOp = serde_json::from_value(json.clone()).expect("decodes");
        op.validate().expect("valid");
        let BridgeOp::Outbound {
            target_chain,
            recipient,
            amount,
            asset,
        } = &op
        else {
            panic!("not an outbound op: {op:?}");
        };
        let fields = &json["outbound"];
        assert_eq!(target_chain, fields["target_chain"].as_str().unwrap());
        assert_eq!(
            hex::encode(recipient),
            fields["recipient"].as_str().unwrap()
        );
        assert_eq!(amount.to_string(), fields["amount"].as_str().unwrap());
        assert_eq!(asset.as_deref(), fields["asset"].as_str());
        let back: BridgeOp = serde_json::from_value(serde_json::to_value(&op).unwrap()).unwrap();
        assert_eq!(back, op);
    }
}

#[test]
fn payment_op_vectors_are_network_ops() {
    let v = vectors();
    for key in ["payment_refund", "payment_set_split"] {
        for case in v[key].as_array().unwrap() {
            let json = case["op"].clone();
            let op: PaymentOp = serde_json::from_value(json.clone()).expect("decodes");
            if let PaymentOp::Refund { pay_ref, amount } = &op {
                assert_eq!(
                    hex::encode(pay_ref),
                    json["refund"]["pay_ref"].as_str().unwrap()
                );
                assert_eq!(
                    amount.to_string(),
                    json["refund"]["amount"].as_str().unwrap()
                );
            }
            let back: PaymentOp =
                serde_json::from_value(serde_json::to_value(&op).unwrap()).unwrap();
            assert_eq!(back, op, "{key}");
        }
    }
}
