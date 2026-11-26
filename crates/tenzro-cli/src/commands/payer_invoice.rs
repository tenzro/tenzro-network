//! What one account paid, per payee: the paying side of a provider's
//! settlement statement, built from the same records.

use serde::Serialize;
use tenzro_types::statement::{Line, Period, Statement, build, lines_csv, summary_csv};

/// For each payee, the statement of the calls that payee served to `payer`
/// in the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Invoice {
    /// The paying account, hex.
    pub payer: String,
    pub from_ms: u64,
    pub to_ms: u64,
    pub period: Period,
    /// Whether every queried node still held every call of the window.
    pub complete: bool,
    /// One statement per payee, in the order the payees were given. Each
    /// statement's `provider` is the payee.
    pub payees: Vec<Statement>,
}

fn account_key(s: &str) -> String {
    s.trim_start_matches("0x").to_lowercase()
}

/// Build the invoice of `payer` over `[from_ms, to_ms)` from the lines each
/// payee's node lists. Lines another account paid are left out.
pub fn invoice(
    payer: &str,
    from_ms: u64,
    to_ms: u64,
    period: Period,
    complete: bool,
    per_payee: Vec<(String, Vec<Line>)>,
) -> Invoice {
    let key = account_key(payer);
    let payees = per_payee
        .into_iter()
        .map(|(payee, lines)| {
            let own = lines
                .into_iter()
                .filter(|l| l.payer.as_deref().map(account_key).as_deref() == Some(key.as_str()))
                .collect();
            build(&payee, from_ms, to_ms, period, complete, own)
        })
        .collect();
    Invoice {
        payer: payer.to_string(),
        from_ms,
        to_ms,
        period,
        complete,
        payees,
    }
}

/// The invoice as CSV: the statement CSV of each payee with the payee as the
/// first column, one row per call with `per_call`, else the summary rows.
pub fn invoice_csv(inv: &Invoice, per_call: bool) -> String {
    let render = |s: &Statement| {
        if per_call {
            lines_csv(s)
        } else {
            summary_csv(s)
        }
    };
    let empty = build(
        &inv.payer,
        inv.from_ms,
        inv.to_ms,
        inv.period,
        inv.complete,
        vec![],
    );
    let header = render(&empty);
    let mut out = format!("payee,{}\n", header.lines().next().unwrap_or_default());
    for s in &inv.payees {
        for row in render(s).lines().skip(1) {
            out.push_str(&format!("{},{row}\n", s.provider));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const JAN31: u64 = 1_769_817_600_000;

    fn entry(seq: u64, payer: &str, gross: u128) -> Line {
        Line::from_settlement(&json!({
            "cursor": seq.to_string(), "served_at_ms": JAN31 + seq, "settled_at_ms": JAN31 + seq + 500,
            "via": "ledger", "status": "settled", "work_class": "inference_served",
            "model_id": "gemma", "units": {"input_tokens": 10, "output_tokens": 20},
            "payer": payer, "asset": "TNZO", "amount": gross.to_string(),
            "fee": "10", "treasury_leg": "2", "burned": "4",
            "tx_hash": format!("{seq:064x}"), "pay_ref": format!("{:064x}", seq + 1000),
            "receipts": [format!("{:064x}", seq + 2000)],
        }))
        .unwrap()
    }

    /// The paying side reads the same records: what one payer paid a payee
    /// in a window equals that payee's own statement line for the payer, and
    /// a call another account paid is not on the invoice.
    #[test]
    fn a_payer_invoice_matches_the_payee_statement_for_the_same_window() {
        let first = vec![
            entry(0, "0xaa", 1_000_000),
            entry(1, "0xbb", 333_333),
            entry(2, "0xaa", 10_000_019),
        ];
        let second = vec![entry(10, "0xAA", 700_000), entry(11, "0xbb", 5)];
        let statement = build("0x7a7a", 0, u64::MAX, Period::Month, true, first.clone());
        let inv = invoice(
            "0xAA",
            0,
            u64::MAX,
            Period::Month,
            true,
            vec![("0x7a7a".to_string(), first), ("0xdd".to_string(), second)],
        );
        assert_eq!(inv.payees.len(), 2);
        let theirs: Vec<_> = statement
            .periods
            .iter()
            .flat_map(|p| p.counterparties.iter())
            .filter(|c| c.payer == "0xaa")
            .collect();
        let calls: u64 = theirs.iter().map(|c| c.calls).sum();
        let gross: u128 = theirs.iter().map(|c| c.gross).sum();
        let net: u128 = theirs.iter().map(|c| c.net).sum();
        let mine = &inv.payees[0].totals[0].sums;
        assert_eq!((mine.calls, mine.gross, mine.net), (calls, gross, net));
        assert!(
            inv.payees[0]
                .lines
                .iter()
                .all(|l| l.payer.as_deref() == Some("0xaa"))
        );
        assert_eq!(inv.payees[1].lines.len(), 1);
        assert_eq!(inv.payees[1].totals[0].sums.gross, 700_000);
        assert!(
            inv.payees
                .iter()
                .flat_map(|s| &s.lines)
                .all(|l| l.tx_hash.is_some())
        );
        let csv = invoice_csv(&inv, true);
        assert!(csv.starts_with("payee,period,"));
        assert_eq!(csv.lines().count(), 1 + 2 + 1);
        assert!(
            invoice_csv(&inv, false)
                .lines()
                .skip(1)
                .all(|r| r.starts_with("0x"))
        );
    }
}
