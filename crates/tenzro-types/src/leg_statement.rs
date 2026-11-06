//! Per-leg statements: what one account was paid, leg by leg.
//!
//! Every payment record lists its legs: the operator at its price, each
//! reseller at its commission, any platform fee. A statement for an
//! account takes from each record only the legs paid to that account, so an
//! operator's statement shows its operator legs and a reseller's its
//! commission legs, never another party's. Each line keeps the record's
//! reference, so [`verify`] recomputes the statement from what the chain
//! holds and reports every difference.
//!
//! Amounts are in the payment's asset, smallest unit, and totals are kept
//! per asset, never adding two assets together.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One leg paid to the statement's account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Line {
    /// The payment record's reference, hex.
    pub pay_ref: String,
    /// `operator`, `reseller` or `platform`.
    pub role: String,
    /// The payment's asset.
    pub asset: String,
    /// What the leg carried.
    #[serde(with = "crate::primitives::u128_serde")]
    pub amount: u128,
    /// The settlement fee the leg paid.
    #[serde(with = "crate::primitives::u128_serde")]
    pub fee: u128,
    /// A reseller's commission, bps of the operator's price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commission_bps: Option<u32>,
    /// When the payment was recorded, ms.
    pub recorded_at_ms: i64,
}

/// Totals of one asset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    /// What the legs carried.
    #[serde(with = "crate::primitives::u128_serde")]
    pub gross: u128,
    /// The settlement fees they paid.
    #[serde(with = "crate::primitives::u128_serde")]
    pub fees: u128,
    /// What reached the account.
    #[serde(with = "crate::primitives::u128_serde")]
    pub net: u128,
    /// Legs counted.
    pub legs: u64,
}

/// One account's statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    /// The account, hex.
    pub account: String,
    /// Its legs, in record order.
    pub lines: Vec<Line>,
    /// Per asset.
    pub totals: BTreeMap<String, Totals>,
}

fn norm(account: &str) -> String {
    account.trim_start_matches("0x").to_ascii_lowercase()
}

fn dec(v: &Value) -> Option<u128> {
    match v {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64().map(u128::from),
        _ => None,
    }
}

/// The legs of `record` paid to `account`.
pub fn lines_of(account: &str, record: &Value) -> Vec<Line> {
    let account = norm(account);
    record["legs"]
        .as_array()
        .map(|legs| {
            legs.iter()
                .filter(|l| l["account"].as_str().map(norm).as_deref() == Some(account.as_str()))
                .map(|l| Line {
                    pay_ref: record["pay_ref"].as_str().unwrap_or("").to_string(),
                    role: l["role"].as_str().unwrap_or("").to_string(),
                    asset: record["asset"].as_str().unwrap_or("").to_string(),
                    amount: dec(&l["amount"]).unwrap_or(0),
                    fee: dec(&l["fee"]).unwrap_or(0),
                    commission_bps: l["commission_bps"].as_u64().map(|b| b as u32),
                    recorded_at_ms: record["recorded_at_ms"].as_i64().unwrap_or(0),
                })
                .collect()
        })
        .unwrap_or_default()
}

impl Statement {
    /// The statement of `account` over `records` (payment records as
    /// `tenzro_getPayment` or `tenzro_listPayments` return them).
    pub fn for_account(account: &str, records: &[Value]) -> Self {
        let lines: Vec<Line> = records.iter().flat_map(|r| lines_of(account, r)).collect();
        let mut totals: BTreeMap<String, Totals> = BTreeMap::new();
        for l in &lines {
            let t = totals.entry(l.asset.clone()).or_default();
            t.gross = t.gross.saturating_add(l.amount);
            t.fees = t.fees.saturating_add(l.fee);
            t.net = t.net.saturating_add(l.amount.saturating_sub(l.fee));
            t.legs += 1;
        }
        Self {
            account: norm(account),
            lines,
            totals,
        }
    }
}

/// Recomputes every line of `statement` from the record `fetch` returns for
/// its reference, and every total from the lines, reporting each
/// difference. Empty when the statement is what the chain holds.
pub fn verify(statement: &Statement, fetch: impl Fn(&str) -> Option<Value>) -> Vec<String> {
    let mut diffs = Vec::new();
    let mut by_ref: BTreeMap<&str, Vec<&Line>> = BTreeMap::new();
    for l in &statement.lines {
        by_ref.entry(&l.pay_ref).or_default().push(l);
    }
    for (pay_ref, lines) in by_ref {
        let Some(record) = fetch(pay_ref) else {
            diffs.push(format!("{pay_ref}: no record on chain"));
            continue;
        };
        let chain = lines_of(&statement.account, &record);
        if chain.len() != lines.len() {
            diffs.push(format!(
                "{pay_ref}: {} legs on chain for this account, {} on the statement",
                chain.len(),
                lines.len()
            ));
            continue;
        }
        for (want, got) in chain.iter().zip(lines) {
            for (what, a, b) in [
                ("role", want.role.clone(), got.role.clone()),
                ("asset", want.asset.clone(), got.asset.clone()),
                ("amount", want.amount.to_string(), got.amount.to_string()),
                ("fee", want.fee.to_string(), got.fee.to_string()),
                (
                    "commission",
                    format!("{:?}", want.commission_bps),
                    format!("{:?}", got.commission_bps),
                ),
            ] {
                if a != b {
                    diffs.push(format!(
                        "{pay_ref}: {what} is {b} on the statement, {a} on chain"
                    ));
                }
            }
        }
    }
    let totals = {
        let mut t: BTreeMap<String, Totals> = BTreeMap::new();
        for l in &statement.lines {
            let e = t.entry(l.asset.clone()).or_default();
            e.gross = e.gross.saturating_add(l.amount);
            e.fees = e.fees.saturating_add(l.fee);
            e.net = e.net.saturating_add(l.amount.saturating_sub(l.fee));
            e.legs += 1;
        }
        t
    };
    if totals != statement.totals {
        diffs.push("the totals are not the sum of the lines".to_string());
    }
    diffs
}
