//! The payment abstraction vectors in sdk/fixtures/payments, pinned by
//! tenzro-types: the Rust SDK prices, derives ids, signs and checks receipts
//! exactly as the chain does.
#![cfg(feature = "payments")]

use serde_json::Value;
use tenzro_sdk::ledger_pay::*;

fn fixture() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/payments/payment_abstraction.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn b32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn prices_parse_to_micro_units_exactly() {
    let f = fixture();
    for p in f["prices"].as_array().unwrap() {
        assert_eq!(
            parse_price_e6(p[0].as_str().unwrap()),
            Ok(p[1].as_u64().unwrap())
        );
    }
    for p in f["bad_prices"].as_array().unwrap() {
        assert_eq!(
            parse_price_e6(p.as_str().unwrap()).unwrap_err().code,
            "invalid_price"
        );
    }
}

#[test]
fn the_payment_id_and_request_digest_match() {
    let f = &fixture()["payment_id"];
    assert_eq!(
        hex::encode(request_digest("https://api.example/v1/infer")),
        f["request_digest"].as_str().unwrap()
    );
    let id = payment_id(
        f["idempotency_key"].as_str().unwrap(),
        &b32(&f["payer"]),
        &b32(&f["payee"]),
        &b32(&f["request_digest"]),
    );
    assert_eq!(id, f["payment_id"].as_str().unwrap());
}

#[test]
fn the_authorization_preimage_is_the_chains() {
    let f = &fixture()["authorization"];
    let m = ledger_authorization_message(&LedgerAuthorization {
        chain_id: f["chain_id"].as_u64().unwrap(),
        payment_id: f["payment_id"].as_str().unwrap(),
        payer: b32(&f["payer"]),
        payee: b32(&f["payee"]),
        max_amount: f["max_amount"].as_str().unwrap().parse().unwrap(),
        asset: f["asset"].as_str().unwrap(),
        request_digest: b32(&f["request_digest"]),
        quote_digest: b32(&f["quote_digest"]),
        usd_e6: f["usd_e6"].as_u64().unwrap(),
        resellers: &[],
    });
    assert_eq!(hex::encode(m), f["preimage"].as_str().unwrap());
}

#[test]
fn the_first_accepted_asset_that_can_settle_is_chosen() {
    let q = &fixture()["quote"];
    let assets = read_quote_assets(&q["response"]).unwrap();
    let accept: Vec<&str> = q["accept"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        choose_asset(&assets, &accept).unwrap().asset,
        q["chosen"].as_str().unwrap()
    );
    let none: Vec<&str> = q["accept_none"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        choose_asset(&assets, &none).unwrap_err().code,
        q["none_code"].as_str().unwrap()
    );
}

/// An asset its peg breaker suspended is passed over for the next accepted
/// asset that can settle; alone, it refuses with its own code.
#[test]
fn a_suspended_asset_is_passed_over_for_the_next_accepted_asset() {
    let q = &fixture()["quote_suspended"];
    let assets = read_quote_assets(&q["response"]).unwrap();
    let accept: Vec<&str> = q["accept"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        choose_asset(&assets, &accept).unwrap().asset,
        q["chosen"].as_str().unwrap()
    );
    let none: Vec<&str> = q["accept_none"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        choose_asset(&assets, &none).unwrap_err().code,
        "asset_suspended"
    );
}

/// An asset whose epoch inflow cap is full is passed over for the next
/// accepted asset; alone, it refuses with its own code.
#[test]
fn an_asset_with_a_full_inflow_cap_is_passed_over_for_the_next_accepted_asset() {
    let q = &fixture()["quote_inflow_full"];
    let assets = read_quote_assets(&q["response"]).unwrap();
    let accept: Vec<&str> = q["accept"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        choose_asset(&assets, &accept).unwrap().asset,
        q["chosen"].as_str().unwrap()
    );
    let none: Vec<&str> = q["accept_none"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        choose_asset(&assets, &none).unwrap_err().code,
        "asset_inflow_full"
    );
}

#[test]
fn a_receipt_checks_against_two_identical_records_with_every_field() {
    let r = &fixture()["receipt"];
    let e = &r["expected"];
    let expected = ExpectedPayment {
        payment_id: e["payment_id"].as_str().unwrap().into(),
        payee: e["payee"].as_str().unwrap().into(),
        asset: e["asset"].as_str().unwrap().into(),
        amount: e["amount"].as_str().unwrap().parse().unwrap(),
        request: e["request"].as_str().unwrap().into(),
        resellers: Vec::new(),
    };
    let record = &r["record"];
    assert!(check_receipt(&expected, record, &record.clone()).is_ok());
    // A receipt for one request never verifies for another.
    let elsewhere = ExpectedPayment {
        request: r["other_request"].as_str().unwrap().into(),
        ..expected.clone()
    };
    let e = check_receipt(&elsewhere, record, record).unwrap_err();
    assert_eq!(e.code, "receipt_mismatch");
    assert!(e.reason.contains("request"), "{e}");
    assert_eq!(
        check_receipt(&expected, &Value::Null, record)
            .unwrap_err()
            .code,
        "receipt_missing"
    );
    let mut other = record.clone();
    other["amount"] = "1".into();
    assert_eq!(
        check_receipt(&expected, record, &other).unwrap_err().code,
        "receipt_mismatch"
    );
    let mut blank = record.clone();
    blank["value_units"] = "".into();
    assert_eq!(
        check_receipt(&expected, &blank, &blank).unwrap_err().code,
        "receipt_mismatch"
    );
}

#[test]
fn a_payment_unlocks_one_request_once() {
    let store = MemoryChargeStore::default();
    assert!(store.claim("pid-1", "https://api.example/v1/infer"));
    assert!(
        !store.claim("pid-1", "https://api.example/v1/infer"),
        "presented again"
    );
    assert!(
        !store.claim("pid-1", "https://other.example/v1/infer"),
        "for another request"
    );
    assert!(store.claim("pid-2", "https://api.example/v1/infer"));
}

#[test]
fn a_resold_payment_signs_each_commission_and_its_receipt_shows_every_leg() {
    let f = fixture();
    let a = &f["authorization_resold"];
    let resellers: Vec<ResellerCommission> = a["resellers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| ResellerCommission {
            reseller: b32(&r["reseller"]),
            commission_bps: r["commission_bps"].as_u64().unwrap() as u32,
        })
        .collect();
    let m = ledger_authorization_message(&LedgerAuthorization {
        chain_id: a["chain_id"].as_u64().unwrap(),
        payment_id: a["payment_id"].as_str().unwrap(),
        payer: b32(&a["payer"]),
        payee: b32(&a["payee"]),
        max_amount: a["max_amount"].as_str().unwrap().parse().unwrap(),
        asset: a["asset"].as_str().unwrap(),
        request_digest: b32(&a["request_digest"]),
        quote_digest: b32(&a["quote_digest"]),
        usd_e6: a["usd_e6"].as_u64().unwrap(),
        resellers: &resellers,
    });
    assert_eq!(hex::encode(m), a["preimage"].as_str().unwrap());
    let q = &f["quote_resold"];
    let assets = read_quote_assets(&q["response"]).unwrap();
    let QuotedAsset::Priced(p) = &assets[0] else {
        panic!("priced")
    };
    assert_eq!(
        p.operator_amount.to_string(),
        q["operator_amount"].as_str().unwrap()
    );
    assert_eq!(
        p.legs[0].amount.to_string(),
        q["commission"].as_str().unwrap()
    );
    let r = &f["receipt_resold"];
    let e = &r["expected"];
    let expected = ExpectedPayment {
        payment_id: e["payment_id"].as_str().unwrap().into(),
        request: e["request"].as_str().unwrap().into(),
        payee: e["payee"].as_str().unwrap().into(),
        asset: e["asset"].as_str().unwrap().into(),
        amount: e["amount"].as_str().unwrap().parse().unwrap(),
        resellers: resellers.clone(),
    };
    assert!(check_receipt(&expected, &r["record"], &r["record"]).is_ok());
    let mut undisclosed = r["record"].clone();
    undisclosed["legs"].as_array_mut().unwrap().truncate(1);
    assert_eq!(
        check_receipt(&expected, &undisclosed, &undisclosed)
            .unwrap_err()
            .code,
        "receipt_mismatch"
    );
}
