//! The payment abstraction vectors in sdk/fixtures/payments: prices, the
//! idempotent payment id, the ledger authorization preimage and the record
//! a settlement leaves, as the chain computes them. Every SDK checks itself
//! against the same file.

use serde_json::Value;
use tenzro_types::payment_authorization::{
    PaymentBinding, idempotent_payment_id, payment_authorization_preimage,
};
use tenzro_types::primitives::Address;
use tenzro_types::settlement::PaymentRecord;
use tenzro_types::settlement_asset::parse_price_e6;

fn fixture() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdk/fixtures/payments/payment_abstraction.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn b32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn prices_parse_as_the_fixture_says() {
    let f = fixture();
    for p in f["prices"].as_array().unwrap() {
        assert_eq!(
            parse_price_e6(p[0].as_str().unwrap()),
            Ok(p[1].as_u64().unwrap())
        );
    }
    for p in f["bad_prices"].as_array().unwrap() {
        assert!(parse_price_e6(p.as_str().unwrap()).is_err(), "{p}");
    }
}

#[test]
fn the_payment_id_is_derived_from_the_idempotency_key() {
    let f = &fixture()["payment_id"];
    let id = idempotent_payment_id(
        f["idempotency_key"].as_str().unwrap(),
        &Address::new(b32(&f["payer"])),
        &Address::new(b32(&f["payee"])),
        &b32(&f["request_digest"]),
    );
    assert_eq!(id, f["payment_id"].as_str().unwrap());
}

#[test]
fn the_authorization_preimage_matches() {
    let f = &fixture()["authorization"];
    let binding = PaymentBinding {
        request_digest: b32(&f["request_digest"]),
        quote_digest: b32(&f["quote_digest"]),
        usd_e6: f["usd_e6"].as_u64().unwrap(),
        app_margin: None,
    };
    let preimage = payment_authorization_preimage(
        f["chain_id"].as_u64().unwrap(),
        f["payment_id"].as_str().unwrap(),
        &Address::new(b32(&f["payer"])),
        &Address::new(b32(&f["payee"])),
        f["max_amount"].as_str().unwrap().parse().unwrap(),
        f["asset"].as_str().unwrap(),
        &binding,
    );
    assert_eq!(hex::encode(preimage), f["preimage"].as_str().unwrap());
}

#[test]
fn the_receipt_record_is_the_chain_record_with_every_receipt_field() {
    let f = &fixture()["receipt"];
    let record: PaymentRecord = serde_json::from_value(f["record"].clone()).unwrap();
    assert_eq!(record.exact_json(), f["record"]);
    assert_eq!(record.nonce, f["expected"]["payment_id"].as_str().unwrap());
    assert!(!record.settled.fee_asset.is_empty() && !record.settled.payout_asset.is_empty());
    assert_eq!(record.settled.unit.basket, "USD");
}

#[test]
fn a_resold_authorization_and_its_receipt_match_the_chain() {
    let f = fixture();
    let a = &f["authorization_resold"];
    let binding = PaymentBinding {
        request_digest: b32(&a["request_digest"]),
        quote_digest: b32(&a["quote_digest"]),
        usd_e6: a["usd_e6"].as_u64().unwrap(),
        app_margin: None,
    };
    let resellers: Vec<tenzro_types::payment_authorization::ResellerLeg> = a["resellers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| tenzro_types::payment_authorization::ResellerLeg {
            reseller: Address::new(b32(&r["reseller"])),
            commission_bps: r["commission_bps"].as_u64().unwrap() as u32,
        })
        .collect();
    let preimage =
        tenzro_types::payment_authorization::payment_authorization_preimage_with_resellers(
            a["chain_id"].as_u64().unwrap(),
            a["payment_id"].as_str().unwrap(),
            &Address::new(b32(&a["payer"])),
            &Address::new(b32(&a["payee"])),
            a["max_amount"].as_str().unwrap().parse().unwrap(),
            a["asset"].as_str().unwrap(),
            &binding,
            &resellers,
        );
    assert_eq!(hex::encode(preimage), a["preimage"].as_str().unwrap());
    let r = &f["receipt_resold"]["record"];
    let record: PaymentRecord = serde_json::from_value(r.clone()).unwrap();
    assert_eq!(record.exact_json(), *r);
    assert_eq!(record.settled.legs[1].role, "reseller");
}
