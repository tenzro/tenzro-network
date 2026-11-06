//! Per-leg statements: an operator's and a reseller's statement each list
//! only their own legs, and verify against the records the chain holds.

use serde_json::{Value, json};
use tenzro_types::leg_statement::{Statement, verify};

fn record(pay_ref: &str, operator: &str, reseller: &str) -> Value {
    json!({
        "pay_ref": pay_ref,
        "class": "native",
        "asset": "TNZO",
        "recorded_at_ms": 1_700_000_000_000u64,
        "legs": [
            { "role": "operator", "account": operator, "amount": "1000", "fee": "1" },
            { "role": "reseller", "account": reseller, "amount": "100", "fee": "1", "commission_bps": 1000 },
        ],
    })
}

fn chain() -> Vec<Value> {
    vec![
        record(&"01".repeat(32), &"aa".repeat(32), &"bb".repeat(32)),
        record(&"02".repeat(32), &"aa".repeat(32), &"cc".repeat(32)),
    ]
}

#[test]
fn an_operator_statement_lists_only_its_own_legs() {
    let s = Statement::for_account(&"aa".repeat(32), &chain());
    assert_eq!(s.lines.len(), 2);
    assert!(s.lines.iter().all(|l| l.role == "operator"));
    assert_eq!(s.totals["TNZO"].gross, 2000);
    assert_eq!(s.totals["TNZO"].fees, 2);
    assert_eq!(s.totals["TNZO"].net, 1998);
}

#[test]
fn a_reseller_statement_lists_only_its_commission_legs() {
    let s = Statement::for_account(&"bb".repeat(32), &chain());
    assert_eq!(s.lines.len(), 1);
    assert_eq!(s.lines[0].role, "reseller");
    assert_eq!(s.lines[0].commission_bps, Some(1000));
    assert_eq!((s.lines[0].amount, s.lines[0].fee), (100, 1));
    // Another reseller's leg and the operator's never appear.
    assert!(
        Statement::for_account(&"dd".repeat(32), &chain())
            .lines
            .is_empty()
    );
}

#[test]
fn a_statement_verifies_against_the_chain_and_reports_every_difference() {
    let records = chain();
    let s = Statement::for_account(&"bb".repeat(32), &records);
    let fetch = |r: &str| records.iter().find(|x| x["pay_ref"] == r).cloned();
    assert!(verify(&s, fetch).is_empty());
    let mut tampered = s.clone();
    tampered.lines[0].amount = 200;
    let diffs = verify(&tampered, fetch);
    assert!(
        diffs.iter().any(|d| d.contains("amount is 200")),
        "{diffs:?}"
    );
    // A line changed without its total no longer adds up either.
    assert!(diffs.iter().any(|d| d.contains("totals")), "{diffs:?}");
    let missing = verify(&s, |_: &str| None);
    assert!(missing[0].contains("no record"), "{missing:?}");
}
