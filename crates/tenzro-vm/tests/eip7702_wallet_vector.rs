//! The EIP-7702 set-code transaction vector the SDK builders are tested
//! against (`sdk/fixtures/eip7702/vectors.json`) was signed by an independent
//! wallet library. The node's decoder reads it back: the same sender, hash,
//! fields and authority, so a transaction an SDK builds to these bytes is one
//! the node admits.

use serde_json::Value;
use tenzro_vm::account_abstraction::recover_eoa_from_7702_signature;
use tenzro_vm::external_tx::{EvmTxKind, decode_evm_raw};

fn vector() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sdk/fixtures/eip7702/vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

#[test]
fn the_node_decodes_the_wallet_signed_set_code_transaction() {
    let v = vector();
    let t = &v["transaction"];
    let raw = bytes(&t["raw"]);
    let tx = decode_evm_raw(&raw, t["chain_id"].as_u64().unwrap()).unwrap();

    assert_eq!(tx.kind, EvmTxKind::SetCode);
    assert_eq!(tx.hash.to_vec(), bytes(&t["hash"]));
    assert_eq!(tx.from.to_vec(), bytes(&v["sender"]));
    assert_eq!(tx.nonce, t["nonce"].as_u64().unwrap());
    assert_eq!(tx.gas_limit, t["gas_limit"].as_u64().unwrap());
    assert_eq!(tx.to.map(|a| a.to_vec()), Some(bytes(&t["to"])));
    assert_eq!(tx.value.to_string(), t["value"].as_str().unwrap());
    assert_eq!(
        tx.max_fee_per_gas.to_string(),
        t["max_fee_per_gas"].as_str().unwrap()
    );
    assert_eq!(
        tx.max_priority_fee_per_gas.to_string(),
        t["max_priority_fee_per_gas"].as_str().unwrap()
    );
    assert_eq!(tx.data, bytes(&t["data"]));

    let a = &v["authorization"];
    assert_eq!(tx.authorizations.len(), 1);
    let auth = &tx.authorizations[0];
    assert_eq!(auth.chain_id, a["chain_id"].as_u64().unwrap());
    assert_eq!(auth.nonce, a["nonce"].as_u64().unwrap());
    assert_eq!(auth.delegate_address, bytes(&a["address"]));
    assert_eq!(auth.signing_hash().to_vec(), bytes(&a["signing_hash"]));
    assert_eq!(
        recover_eoa_from_7702_signature(auth).unwrap(),
        bytes(&v["authority"])
    );
}

#[test]
fn a_different_chain_refuses_the_vector() {
    let v = vector();
    let raw = bytes(&v["transaction"]["raw"]);
    assert!(decode_evm_raw(&raw, 1).is_err());
}
