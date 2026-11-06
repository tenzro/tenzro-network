//! Settlement statements for a provider's finance team.
//!
//! A statement covers one provider account and one window, cut into UTC days
//! or months. It is built from the calls a node recorded as settled
//! (`tenzro_listSettlements`), one [`Line`] per call, and every line carries
//! the references that make it recomputable: the settlement transaction, the
//! payment record's reference and the delivery receipts the record lists.
//!
//! Amounts are in the payment's asset, in its smallest unit. The settlement
//! fee, its burn and the treasury leg are TNZO base units: TNZO is the fee
//! asset whatever the payment was made in. For a TNZO payment the payee is
//! credited the amount less the fee and the treasury leg; for any other asset
//! it receives the whole amount and pays the fee and leg in TNZO beside it.
//! Totals are therefore kept per asset and never add two assets together.
//!
//! Only lines settled on the ledger count toward the totals. A ledger call
//! whose payment the chain does not hold yet, and a call paid by voucher on a
//! payment channel (settled later, when the escrow is claimed, for every call
//! the claimed voucher covers), are listed with their status and counted
//! apart.
//!
//! [`verify`] recomputes a statement from what the chain holds for each line
//! (the payment record and the settlement transaction's receipt) and reports
//! every difference.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::BillableUnits;

/// The asset name a TNZO payment record carries.
pub const TNZO: &str = "TNZO";

/// The span a statement's periods cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Period {
    /// One UTC calendar day, `YYYY-MM-DD`.
    Day,
    /// One UTC calendar month, `YYYY-MM`.
    Month,
}

impl std::str::FromStr for Period {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "day" => Ok(Self::Day),
            "month" => Ok(Self::Month),
            other => Err(format!("unknown period '{other}': expected day or month")),
        }
    }
}

/// `(year, month, day)` of the UTC day `days` after 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

impl Period {
    /// The period a unix-millisecond instant falls in, as its UTC label.
    pub fn key(self, ms: u64) -> String {
        let (y, m, d) = civil_from_days((ms / 86_400_000) as i64);
        match self {
            Period::Day => format!("{y:04}-{m:02}-{d:02}"),
            Period::Month => format!("{y:04}-{m:02}"),
        }
    }
}

/// How a call was paid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    /// A payment the payer authorized, settled per call on the ledger.
    Ledger,
    /// A voucher on a payment channel, settled when the escrow is claimed.
    Channel,
}

/// One settled call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Line {
    /// The recording node's sequence number for the call.
    pub cursor: String,
    /// When the answer was ready and settlement began, unix ms. Selects the
    /// line's period.
    pub served_at_ms: u64,
    /// The block time the payment record was written at, for a settled
    /// ledger call.
    pub settled_at_ms: Option<i64>,
    pub via: Via,
    /// `settled` or `pending` for a ledger call; `claimed`, `in_channel` or
    /// `escrow_not_found` for a channel call.
    pub status: String,
    pub work_class: String,
    pub model_id: String,
    pub units: BillableUnits,
    /// The paying account, hex.
    pub payer: Option<String>,
    /// The payment record's asset, once the chain holds the record.
    pub asset: Option<String>,
    /// What the payer was charged, in the asset's smallest unit.
    #[serde(with = "crate::primitives::u128_serde")]
    pub gross: u128,
    /// The payment record's fee: the settlement fee and the treasury leg,
    /// TNZO base units.
    #[serde(with = "crate::primitives::u128_serde_opt")]
    pub deducted: Option<u128>,
    /// The treasury leg the settlement transaction declared, TNZO.
    #[serde(with = "crate::primitives::u128_serde_opt")]
    pub treasury_leg: Option<u128>,
    /// The TNZO the settlement transaction burned.
    #[serde(with = "crate::primitives::u128_serde_opt")]
    pub burned: Option<u128>,
    /// The settlement transaction, hex.
    pub tx_hash: Option<String>,
    /// The payment record's reference, hex.
    pub pay_ref: Option<String>,
    /// The delivery receipts the payment record lists, by digest; for a
    /// channel call, the head of the receipt chain its voucher pays for.
    pub receipts: Vec<String>,
    /// The escrow a channel call is paid from, hex.
    pub escrow_id: Option<String>,
    /// The node's debit reference on the channel.
    pub channel_reference: Option<String>,
}

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

fn amount(v: &Value, key: &str) -> Result<Option<u128>, String> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => s
            .parse::<u128>()
            .map(Some)
            .map_err(|_| format!("{key} is not a whole number: {s}")),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(|n| Some(u128::from(n)))
            .ok_or_else(|| format!("{key} is not a whole number: {n}")),
        Some(other) => Err(format!("{key} is not a whole number: {other}")),
    }
}

impl Line {
    /// Read one entry of a `tenzro_listSettlements` answer.
    pub fn from_settlement(v: &Value) -> Result<Self, String> {
        let via = match v.get("via").and_then(Value::as_str) {
            Some("ledger") => Via::Ledger,
            Some("channel") => Via::Channel,
            other => return Err(format!("unknown settlement path {other:?}")),
        };
        let units = match v.get("units") {
            None | Some(Value::Null) => BillableUnits::new(),
            Some(u) => serde_json::from_value(u.clone()).map_err(|e| format!("units: {e}"))?,
        };
        let burned = amount(v, "burned")?;
        // A successful settlement transaction whose type declares no
        // treasury leg paid none; without its receipt both are unknown.
        let treasury_leg = match (amount(v, "treasury_leg")?, burned) {
            (Some(l), _) => Some(l),
            (None, Some(_)) => Some(0),
            (None, None) => None,
        };
        Ok(Self {
            cursor: text(v, "cursor").ok_or("an entry without its cursor")?,
            served_at_ms: v
                .get("served_at_ms")
                .and_then(Value::as_u64)
                .ok_or("an entry without served_at_ms")?,
            settled_at_ms: v.get("settled_at_ms").and_then(Value::as_i64),
            via,
            status: text(v, "status").unwrap_or_default(),
            work_class: text(v, "work_class").unwrap_or_default(),
            model_id: text(v, "model_id").unwrap_or_default(),
            units,
            payer: text(v, "payer"),
            asset: text(v, "asset"),
            gross: amount(v, "amount")?.ok_or("an entry without its amount")?,
            deducted: if via == Via::Ledger {
                amount(v, "fee")?
            } else {
                None
            },
            treasury_leg,
            burned,
            tx_hash: text(v, "tx_hash"),
            pay_ref: text(v, "pay_ref"),
            receipts: v
                .get("receipts")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            escrow_id: text(v, "escrow_id"),
            channel_reference: text(v, "channel_reference"),
        })
    }

    /// Whether the line counts toward the totals: a ledger call whose
    /// payment record and settlement receipt the chain holds.
    pub fn settled(&self) -> bool {
        self.via == Via::Ledger
            && self.status == "settled"
            && self.asset.is_some()
            && self.deducted.is_some()
            && self.treasury_leg.is_some()
            && self.burned.is_some()
    }

    /// The settlement fee: the record's fee less the treasury leg.
    pub fn fee(&self) -> Option<u128> {
        self.deducted?.checked_sub(self.treasury_leg?)
    }

    /// What the payee keeps of the payment, in its asset: the amount less
    /// the fee and the leg for TNZO, the whole amount for any other asset
    /// (whose fee and leg the payee pays in TNZO beside it).
    pub fn net(&self) -> Option<u128> {
        if self.asset.as_deref()? == TNZO {
            self.gross.checked_sub(self.deducted?)
        } else {
            Some(self.gross)
        }
    }
}

/// Sums over a set of settled lines, all in one asset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sums {
    pub calls: u64,
    pub units: BillableUnits,
    #[serde(with = "crate::primitives::u128_serde")]
    pub gross: u128,
    /// Settlement fees, TNZO.
    #[serde(with = "crate::primitives::u128_serde")]
    pub fee: u128,
    /// Treasury legs, TNZO.
    #[serde(with = "crate::primitives::u128_serde")]
    pub treasury_leg: u128,
    /// TNZO burned out of the fees.
    #[serde(with = "crate::primitives::u128_serde")]
    pub burned: u128,
    /// Kept by the provider, in the asset.
    #[serde(with = "crate::primitives::u128_serde")]
    pub net: u128,
}

impl Sums {
    fn add(&mut self, l: &Line) {
        self.calls += 1;
        self.units.accumulate(&l.units);
        self.gross = self.gross.saturating_add(l.gross);
        self.fee = self.fee.saturating_add(l.fee().unwrap_or(0));
        self.treasury_leg = self
            .treasury_leg
            .saturating_add(l.treasury_leg.unwrap_or(0));
        self.burned = self.burned.saturating_add(l.burned.unwrap_or(0));
        self.net = self.net.saturating_add(l.net().unwrap_or(0));
    }
}

/// Calls of one model and work class, in one asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub model_id: String,
    pub work_class: String,
    pub asset: String,
    #[serde(flatten)]
    pub sums: Sums,
}

/// What one payer paid, in one asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counterparty {
    pub payer: String,
    pub asset: String,
    pub calls: u64,
    #[serde(with = "crate::primitives::u128_serde")]
    pub gross: u128,
    #[serde(with = "crate::primitives::u128_serde")]
    pub net: u128,
}

/// Totals in one asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetTotals {
    pub asset: String,
    #[serde(flatten)]
    pub sums: Sums,
}

/// One period of a statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeriodSummary {
    /// The UTC day or month, `YYYY-MM-DD` or `YYYY-MM`.
    pub period: String,
    pub groups: Vec<Group>,
    pub counterparties: Vec<Counterparty>,
    pub totals: Vec<AssetTotals>,
    /// Lines that do not count toward the totals, by status.
    pub unsettled: BTreeMap<String, u64>,
}

/// A provider's statement for one window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    /// The provider account, hex.
    pub provider: String,
    /// Start of the window, unix ms, inclusive.
    pub from_ms: u64,
    /// End of the window, unix ms, exclusive.
    pub to_ms: u64,
    pub period: Period,
    /// Whether the recording node still held every call of the window: it
    /// keeps a bounded number of entries and drops the oldest.
    pub complete: bool,
    /// Every call of the window, oldest first.
    pub lines: Vec<Line>,
    pub periods: Vec<PeriodSummary>,
    pub totals: Vec<AssetTotals>,
    pub unsettled: BTreeMap<String, u64>,
}

fn unsettled_key(l: &Line) -> String {
    match l.via {
        Via::Ledger => format!("ledger_{}", l.status),
        Via::Channel => format!("channel_{}", l.status),
    }
}

fn totals_of<'a>(lines: impl Iterator<Item = &'a Line>) -> Vec<AssetTotals> {
    let mut by: BTreeMap<String, Sums> = BTreeMap::new();
    for l in lines {
        by.entry(l.asset.clone().unwrap_or_default())
            .or_default()
            .add(l);
    }
    by.into_iter()
        .map(|(asset, sums)| AssetTotals { asset, sums })
        .collect()
}

fn summarize(period: String, lines: &[&Line]) -> PeriodSummary {
    let settled: Vec<&Line> = lines.iter().copied().filter(|l| l.settled()).collect();
    let mut groups: BTreeMap<(String, String, String), Sums> = BTreeMap::new();
    let mut parties: BTreeMap<(String, String), (u64, u128, u128)> = BTreeMap::new();
    for l in &settled {
        let asset = l.asset.clone().unwrap_or_default();
        groups
            .entry((l.model_id.clone(), l.work_class.clone(), asset.clone()))
            .or_default()
            .add(l);
        let p = parties
            .entry((l.payer.clone().unwrap_or_default(), asset))
            .or_default();
        p.0 += 1;
        p.1 = p.1.saturating_add(l.gross);
        p.2 = p.2.saturating_add(l.net().unwrap_or(0));
    }
    let mut unsettled = BTreeMap::new();
    for l in lines.iter().filter(|l| !l.settled()) {
        *unsettled.entry(unsettled_key(l)).or_insert(0) += 1;
    }
    PeriodSummary {
        period,
        groups: groups
            .into_iter()
            .map(|((model_id, work_class, asset), sums)| Group {
                model_id,
                work_class,
                asset,
                sums,
            })
            .collect(),
        counterparties: parties
            .into_iter()
            .map(|((payer, asset), (calls, gross, net))| Counterparty {
                payer,
                asset,
                calls,
                gross,
                net,
            })
            .collect(),
        totals: totals_of(settled.iter().copied()),
        unsettled,
    }
}

/// The lines of one provider as several nodes list them, as one ledger: an
/// operator that served through one platform node and then another keeps one
/// continuous statement. Each line's cursor is prefixed with the node it came
/// from, and a payment more than one node lists is counted once.
pub fn merge_sources(sources: Vec<(String, Vec<Line>)>) -> Vec<Line> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for (node, lines) in sources {
        for mut line in lines {
            // A payment two nodes both list is one line.
            if let Some(r) = &line.pay_ref
                && !seen.insert(r.clone())
            {
                continue;
            }
            line.cursor = format!("{node}:{}", line.cursor);
            out.push(line);
        }
    }
    out
}

/// Build the statement of `provider` over `[from_ms, to_ms)` from its lines.
/// Lines outside the window are left out.
pub fn build(
    provider: &str,
    from_ms: u64,
    to_ms: u64,
    period: Period,
    complete: bool,
    lines: Vec<Line>,
) -> Statement {
    let mut lines: Vec<Line> = lines
        .into_iter()
        .filter(|l| l.served_at_ms >= from_ms && l.served_at_ms < to_ms)
        .collect();
    lines.sort_by_key(|l| (l.served_at_ms, l.cursor.parse::<u64>().unwrap_or(u64::MAX)));
    let mut by_period: BTreeMap<String, Vec<&Line>> = BTreeMap::new();
    for l in &lines {
        by_period
            .entry(period.key(l.served_at_ms))
            .or_default()
            .push(l);
    }
    let periods = by_period
        .into_iter()
        .map(|(p, ls)| summarize(p, &ls))
        .collect();
    let mut unsettled = BTreeMap::new();
    for l in lines.iter().filter(|l| !l.settled()) {
        *unsettled.entry(unsettled_key(l)).or_insert(0) += 1;
    }
    let totals = totals_of(lines.iter().filter(|l| l.settled()));
    Statement {
        provider: provider.to_string(),
        from_ms,
        to_ms,
        period,
        complete,
        lines,
        periods,
        totals,
        unsettled,
    }
}

/// What the chain holds for one ledger line: its payment record and its
/// settlement transaction's receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainFacts {
    /// The record's payee, hex.
    pub payee: String,
    pub asset: String,
    pub amount: u128,
    /// The record's fee: settlement fee and treasury leg.
    pub fee: u128,
    pub recorded_at_ms: i64,
    pub receipts: Vec<String>,
    /// Whether the settlement transaction succeeded.
    pub tx_success: bool,
    /// TNZO the transaction burned.
    pub burned: u128,
    /// The treasury leg it declared.
    pub treasury_leg: u128,
}

/// An account as an RPC answer gives it (hex, or a byte array), as bare
/// lower-case hex.
pub fn account_hex(v: &Value) -> String {
    match v {
        Value::String(s) => s.trim_start_matches("0x").to_ascii_lowercase(),
        Value::Array(a) => a
            .iter()
            .filter_map(|b| b.as_u64().map(|b| format!("{:02x}", b as u8)))
            .collect(),
        _ => String::new(),
    }
}

fn whole(v: &Value, key: &str) -> Result<u128, String> {
    match v.get(key) {
        Some(Value::String(s)) => s
            .parse()
            .map_err(|_| format!("{key} is not a whole number")),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| format!("{key} is not a whole number")),
        _ => Err(format!("{key} is missing")),
    }
}

impl ChainFacts {
    /// What the chain holds for one line, from its payment record as
    /// `tenzro_getPayment` returns it and its settlement transaction's
    /// receipt as `eth_getTransactionReceipt` returns it.
    pub fn from_rpc(record: &Value, receipt: &Value) -> Result<Self, String> {
        let supply_change: i128 = receipt
            .get("supplyChange")
            .and_then(Value::as_str)
            .unwrap_or("0")
            .parse()
            .map_err(|_| "supplyChange is not a whole number".to_string())?;
        Ok(ChainFacts {
            payee: account_hex(&record["payee"]),
            asset: record["asset"].as_str().unwrap_or_default().to_string(),
            amount: whole(record, "amount")?,
            fee: whole(record, "fee")?,
            recorded_at_ms: record["recorded_at_ms"].as_i64().unwrap_or_default(),
            receipts: record["receipts"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|r| r.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            tx_success: receipt.get("status").and_then(Value::as_str) == Some("0x1"),
            burned: supply_change.min(0).unsigned_abs(),
            treasury_leg: match receipt.get("treasuryLeg").and_then(Value::as_str) {
                Some(l) => l
                    .parse()
                    .map_err(|_| "treasuryLeg is not a whole number".to_string())?,
                None => 0,
            },
        })
    }
}

fn same_account(a: &str, b: &str) -> bool {
    a.trim_start_matches("0x")
        .eq_ignore_ascii_case(b.trim_start_matches("0x"))
}

/// Recompute `statement` from the chain. `facts` holds, by payment
/// reference, what the chain holds for each ledger line. Returns every
/// difference found; an empty list means each settled line matches the chain
/// and every summary and total is the sum of its lines.
pub fn verify(statement: &Statement, facts: &BTreeMap<String, ChainFacts>) -> Vec<String> {
    let mut out = Vec::new();
    // The summaries are what the lines add up to.
    let rebuilt = build(
        &statement.provider,
        statement.from_ms,
        statement.to_ms,
        statement.period,
        statement.complete,
        statement.lines.clone(),
    );
    if rebuilt.periods != statement.periods {
        out.push("the period summaries are not the sums of the lines".to_string());
    }
    if rebuilt.totals != statement.totals || rebuilt.unsettled != statement.unsettled {
        out.push("the totals are not the sums of the lines".to_string());
    }

    // Each settled line is what the chain holds for it.
    let mut from_chain = Vec::with_capacity(statement.lines.len());
    for l in &statement.lines {
        let mut c = l.clone();
        if l.settled() {
            let at = format!("line {}", l.cursor);
            let Some(pay_ref) = &l.pay_ref else {
                out.push(format!("{at}: no payment reference"));
                continue;
            };
            let Some(f) = facts.get(pay_ref) else {
                out.push(format!("{at}: the chain holds no payment {pay_ref}"));
                continue;
            };
            if !same_account(&f.payee, &statement.provider) {
                out.push(format!(
                    "{at}: payment {pay_ref} pays {}, not the provider",
                    f.payee
                ));
            }
            if !f.tx_success {
                out.push(format!("{at}: the settlement transaction did not succeed"));
            }
            if f.treasury_leg > f.fee || f.burned > f.fee - f.treasury_leg {
                out.push(format!(
                    "{at}: the chain's burn {} and leg {} exceed the fee {}",
                    f.burned, f.treasury_leg, f.fee
                ));
            }
            for (field, stated, held) in [
                (
                    "asset",
                    l.asset.clone().unwrap_or_default(),
                    f.asset.clone(),
                ),
                ("gross", l.gross.to_string(), f.amount.to_string()),
                (
                    "fee",
                    l.deducted.unwrap_or_default().to_string(),
                    f.fee.to_string(),
                ),
                (
                    "treasury leg",
                    l.treasury_leg.unwrap_or_default().to_string(),
                    f.treasury_leg.to_string(),
                ),
                (
                    "burn",
                    l.burned.unwrap_or_default().to_string(),
                    f.burned.to_string(),
                ),
                (
                    "settled at",
                    l.settled_at_ms.unwrap_or_default().to_string(),
                    f.recorded_at_ms.to_string(),
                ),
                ("receipts", l.receipts.join(";"), f.receipts.join(";")),
            ] {
                if stated != held {
                    out.push(format!(
                        "{at}: {field} is {stated} on the statement, {held} on chain"
                    ));
                }
            }
            c.asset = Some(f.asset.clone());
            c.gross = f.amount;
            c.deducted = Some(f.fee);
            c.treasury_leg = Some(f.treasury_leg);
            c.burned = Some(f.burned);
            c.settled_at_ms = Some(f.recorded_at_ms);
            c.receipts = f.receipts.clone();
        }
        from_chain.push(c);
    }
    let recomputed = build(
        &statement.provider,
        statement.from_ms,
        statement.to_ms,
        statement.period,
        statement.complete,
        from_chain,
    );
    if recomputed.totals != statement.totals {
        out.push("the totals recomputed from the chain differ from the statement".to_string());
    }
    out
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn csv_row(fields: &[String]) -> String {
    let mut row = fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",");
    row.push('\n');
    row
}

fn units_text(u: &BillableUnits) -> String {
    u.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(";")
}

fn opt<T: ToString>(v: Option<T>) -> String {
    v.map(|v| v.to_string()).unwrap_or_default()
}

/// One CSV row per call, oldest first, with every reference the line
/// carries.
pub fn lines_csv(s: &Statement) -> String {
    let mut out = csv_row(
        &[
            "period",
            "served_at_ms",
            "settled_at_ms",
            "via",
            "status",
            "model_id",
            "work_class",
            "units",
            "payer",
            "asset",
            "gross",
            "fee",
            "treasury_leg",
            "burned",
            "net",
            "tx_hash",
            "pay_ref",
            "receipts",
            "escrow_id",
            "channel_reference",
            "cursor",
        ]
        .map(str::to_string),
    );
    for l in &s.lines {
        let settled = l.settled();
        out.push_str(&csv_row(&[
            s.period.key(l.served_at_ms),
            l.served_at_ms.to_string(),
            opt(l.settled_at_ms),
            match l.via {
                Via::Ledger => "ledger".into(),
                Via::Channel => "channel".into(),
            },
            l.status.clone(),
            l.model_id.clone(),
            l.work_class.clone(),
            units_text(&l.units),
            l.payer.clone().unwrap_or_default(),
            l.asset.clone().unwrap_or_default(),
            l.gross.to_string(),
            opt(l.fee().filter(|_| settled)),
            opt(l.treasury_leg.filter(|_| settled)),
            opt(l.burned.filter(|_| settled)),
            opt(l.net().filter(|_| settled)),
            l.tx_hash.clone().unwrap_or_default(),
            l.pay_ref.clone().unwrap_or_default(),
            l.receipts.join(";"),
            l.escrow_id.clone().unwrap_or_default(),
            l.channel_reference.clone().unwrap_or_default(),
            l.cursor.clone(),
        ]));
    }
    out
}

/// The summary as CSV: one `group` row per model, work class and asset in
/// each period, one `counterparty` row per payer and asset in each period,
/// one `period_total` row per asset in each period and one `total` row per
/// asset for the window.
pub fn summary_csv(s: &Statement) -> String {
    let mut out = csv_row(
        &[
            "row",
            "period",
            "model_id",
            "work_class",
            "payer",
            "asset",
            "calls",
            "units",
            "gross",
            "fee",
            "treasury_leg",
            "burned",
            "net",
        ]
        .map(str::to_string),
    );
    let sums_row = |row: &str, period: &str, model: &str, class: &str, asset: &str, m: &Sums| {
        csv_row(&[
            row.to_string(),
            period.to_string(),
            model.to_string(),
            class.to_string(),
            String::new(),
            asset.to_string(),
            m.calls.to_string(),
            units_text(&m.units),
            m.gross.to_string(),
            m.fee.to_string(),
            m.treasury_leg.to_string(),
            m.burned.to_string(),
            m.net.to_string(),
        ])
    };
    for p in &s.periods {
        for g in &p.groups {
            out.push_str(&sums_row(
                "group",
                &p.period,
                &g.model_id,
                &g.work_class,
                &g.asset,
                &g.sums,
            ));
        }
        for c in &p.counterparties {
            out.push_str(&csv_row(&[
                "counterparty".to_string(),
                p.period.clone(),
                String::new(),
                String::new(),
                c.payer.clone(),
                c.asset.clone(),
                c.calls.to_string(),
                String::new(),
                c.gross.to_string(),
                String::new(),
                String::new(),
                String::new(),
                c.net.to_string(),
            ]));
        }
        for t in &p.totals {
            out.push_str(&sums_row(
                "period_total",
                &p.period,
                "",
                "",
                &t.asset,
                &t.sums,
            ));
        }
    }
    for t in &s.totals {
        out.push_str(&sums_row("total", "", "", "", &t.asset, &t.sums));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split::{FeeParams, bps_of, fee_allocation};
    use serde_json::json;

    const PROVIDER: &str = "0x7a7a";
    const DAY: u64 = 86_400_000;
    /// 2026-01-31T00:00:00Z.
    const JAN31: u64 = 1_769_817_600_000;

    fn params() -> FeeParams {
        FeeParams {
            fee_bps: 250,
            min_fee: 7,
            burn_bps: 5_000,
            insurance_bps: 1_000,
        }
    }

    /// A settled ledger entry as `tenzro_listSettlements` answers it, with
    /// the fee, burn and leg the chain's split produces for `gross`.
    fn settled(seq: u64, at: u64, model: &str, payer: &str, gross: u128, leg_bps: u128) -> Value {
        let fee = fee_allocation(gross, &params());
        let leg = bps_of(gross - fee.fee, leg_bps);
        json!({
            "cursor": seq.to_string(), "served_at_ms": at, "settled_at_ms": at + 500,
            "via": "ledger", "status": "settled", "work_class": "inference_served",
            "model_id": model, "units": {"input_tokens": 10, "output_tokens": 20},
            "provider": PROVIDER, "payer": payer, "asset": "TNZO",
            "amount": gross.to_string(), "fee": (fee.fee + leg).to_string(),
            "treasury_leg": leg.to_string(), "burned": fee.burn.to_string(),
            "tx_hash": format!("{seq:064x}"), "pay_ref": format!("{:064x}", seq + 1000),
            "receipts": [format!("{:064x}", seq + 2000)],
        })
    }

    fn lines(entries: &[Value]) -> Vec<Line> {
        entries
            .iter()
            .map(|e| Line::from_settlement(e).unwrap())
            .collect()
    }

    /// Chain facts read the way the RPC answers carry them: the payment
    /// record's payee as hex or bytes, amounts as decimal text, the burn as a
    /// negative supply change and the treasury leg from the receipt.
    #[test]
    fn chain_facts_are_read_from_the_rpc_answers() {
        let record = json!({
            "payee": "0xABCD", "asset": "TNZO", "amount": "1000", "fee": 7,
            "recorded_at_ms": 5, "receipts": ["r1"],
        });
        let receipt = json!({"status": "0x1", "supplyChange": "-3", "treasuryLeg": "2"});
        let f = ChainFacts::from_rpc(&record, &receipt).unwrap();
        assert_eq!(f.payee, "abcd");
        assert_eq!((f.amount, f.fee, f.burned, f.treasury_leg), (1000, 7, 3, 2));
        assert!(f.tx_success);
        assert_eq!(f.receipts, vec!["r1".to_string()]);
        assert_eq!(account_hex(&json!([0xab, 0x01])), "ab01");
        let reverted = json!({"status": "0x0"});
        assert!(!ChainFacts::from_rpc(&record, &reverted).unwrap().tx_success);
        assert!(ChainFacts::from_rpc(&json!({"amount": "x", "fee": 1}), &receipt).is_err());
    }

    /// An operator that moves from one platform node to another keeps one
    /// statement: the lines both nodes list for its account build one
    /// continuous ledger whose totals are the sum of both, checked against
    /// the chain like any other, with a payment both list counted once.
    #[test]
    fn an_operator_moving_between_platform_nodes_keeps_one_statement() {
        let all = fixture();
        let settled: Vec<Value> = all
            .iter()
            .filter(|e| e["status"] == "settled")
            .cloned()
            .collect();
        assert!(settled.len() >= 4);
        // The first two calls were served through node A, the rest through
        // node B, which also lists the last call node A served.
        let on_a = lines(&settled[..2]);
        let on_b = lines(&settled[1..]);
        let merged = merge_sources(vec![("node-a".into(), on_a), ("node-b".into(), on_b)]);
        assert_eq!(merged.len(), settled.len(), "{merged:?}");
        assert!(merged.iter().any(|l| l.cursor.starts_with("node-a:")));
        assert!(merged.iter().any(|l| l.cursor.starts_with("node-b:")));

        let whole = build(PROVIDER, 0, u64::MAX, Period::Month, true, lines(&settled));
        let moved = build(PROVIDER, 0, u64::MAX, Period::Month, true, merged);
        assert_eq!(
            serde_json::to_value(&moved.totals).unwrap(),
            serde_json::to_value(&whole.totals).unwrap(),
            "one continuous ledger"
        );
        assert_eq!(moved.periods.len(), whole.periods.len());
        assert!(verify(&moved, &facts_of(&settled)).is_empty());
    }

    fn facts_of(entries: &[Value]) -> BTreeMap<String, ChainFacts> {
        entries
            .iter()
            .filter(|e| e["status"] == "settled")
            .map(|e| {
                let n = |k: &str| e[k].as_str().unwrap().parse::<u128>().unwrap();
                (
                    e["pay_ref"].as_str().unwrap().to_string(),
                    ChainFacts {
                        payee: PROVIDER.to_string(),
                        asset: e["asset"].as_str().unwrap().to_string(),
                        amount: n("amount"),
                        fee: n("fee"),
                        recorded_at_ms: e["settled_at_ms"].as_i64().unwrap(),
                        receipts: vec![e["receipts"][0].as_str().unwrap().to_string()],
                        tx_success: true,
                        burned: n("burned"),
                        treasury_leg: n("treasury_leg"),
                    },
                )
            })
            .collect()
    }

    fn fixture() -> Vec<Value> {
        vec![
            settled(0, JAN31 + 1_000, "gemma", "0xaa", 1_000_000, 1_000),
            settled(1, JAN31 + DAY - 1, "gemma", "0xbb", 333_333, 1_000),
            // 2026-02-01T00:00:00Z exactly: the next day and the next month.
            settled(2, JAN31 + DAY, "qwen", "0xaa", 10_000_019, 0),
            // Below the least fee's base: the fee is the least fee.
            settled(3, JAN31 + DAY + 5, "qwen", "0xaa", 100, 0),
            json!({
                "cursor": "4", "served_at_ms": JAN31 + DAY + 9, "via": "ledger", "status": "pending",
                "work_class": "inference_served", "model_id": "qwen", "units": {"output_tokens": 3},
                "payer": "0xcc", "amount": "999", "fee": null, "burned": null, "treasury_leg": null,
                "tx_hash": "ff", "pay_ref": "ee", "receipts": null,
            }),
            json!({
                "cursor": "5", "served_at_ms": JAN31 + DAY + 10, "via": "channel", "status": "in_channel",
                "work_class": "inference_served", "model_id": "qwen", "units": {"output_tokens": 3},
                "payer": "0xcc", "amount": "50", "fee": null, "burned": null, "treasury_leg": null,
                "settled_at_ms": JAN31 + DAY + 10, "escrow_id": "00", "channel_reference": "r",
                "receipts": ["11"],
            }),
        ]
    }

    #[test]
    fn utc_period_boundaries() {
        assert_eq!(Period::Day.key(JAN31), "2026-01-31");
        assert_eq!(Period::Day.key(JAN31 + DAY - 1), "2026-01-31");
        assert_eq!(Period::Day.key(JAN31 + DAY), "2026-02-01");
        assert_eq!(Period::Month.key(JAN31 + DAY - 1), "2026-01");
        assert_eq!(Period::Month.key(JAN31 + DAY), "2026-02");
        assert_eq!(Period::Day.key(0), "1970-01-01");
        // 2024-02-29 (leap day) and 2100-03-01 (no leap day in 2100).
        assert_eq!(Period::Day.key(1_709_164_800_000), "2024-02-29");
        assert_eq!(Period::Day.key(4_107_542_400_000), "2100-03-01");
    }

    #[test]
    fn totals_match_the_chain_split_line_by_line() {
        let entries = fixture();
        let s = build(
            PROVIDER,
            JAN31,
            JAN31 + 2 * DAY,
            Period::Day,
            true,
            lines(&entries),
        );
        assert_eq!(s.lines.len(), 6);
        assert_eq!(s.periods.len(), 2);
        let mut want = Sums::default();
        for e in entries.iter().filter(|e| e["status"] == "settled") {
            let gross: u128 = e["amount"].as_str().unwrap().parse().unwrap();
            let fee = fee_allocation(gross, &params());
            let leg: u128 = e["treasury_leg"].as_str().unwrap().parse().unwrap();
            want.calls += 1;
            want.gross += gross;
            want.fee += fee.fee;
            want.burned += fee.burn;
            want.treasury_leg += leg;
            want.net += gross - fee.fee - leg;
            want.units.accumulate(&BillableUnits::tokens(10, 20));
        }
        assert_eq!(s.totals.len(), 1);
        assert_eq!(s.totals[0].asset, "TNZO");
        assert_eq!(s.totals[0].sums, want);
        // Every unit of the gross is accounted for: fee, leg and net.
        let t = &s.totals[0].sums;
        assert_eq!(t.gross, t.fee + t.treasury_leg + t.net);
        // The least fee applies to the 100-unit payment.
        assert_eq!(s.lines[3].fee(), Some(7));
        // The period totals add up to the window's.
        let mut sum = Sums::default();
        for p in &s.periods {
            for t in &p.totals {
                sum.calls += t.sums.calls;
                sum.gross += t.sums.gross;
                sum.fee += t.sums.fee;
                sum.treasury_leg += t.sums.treasury_leg;
                sum.burned += t.sums.burned;
                sum.net += t.sums.net;
                sum.units.accumulate(&t.sums.units);
            }
        }
        assert_eq!(sum, *t);
        // Unsettled lines are listed and counted apart.
        assert_eq!(s.unsettled.get("ledger_pending"), Some(&1));
        assert_eq!(s.unsettled.get("channel_in_channel"), Some(&1));
        assert_eq!(s.periods[1].unsettled.len(), 2);
        // Groups and counterparties of the second day.
        let feb = &s.periods[1];
        assert_eq!(feb.period, "2026-02-01");
        assert_eq!(feb.groups.len(), 1);
        assert_eq!(feb.groups[0].model_id, "qwen");
        assert_eq!(feb.groups[0].sums.calls, 2);
        assert_eq!(feb.counterparties.len(), 1);
        assert_eq!(feb.counterparties[0].payer, "0xaa");
        assert_eq!(feb.counterparties[0].gross, 10_000_119);
    }

    #[test]
    fn months_cut_at_the_utc_month_boundary() {
        let s = build(
            PROVIDER,
            0,
            u64::MAX,
            Period::Month,
            true,
            lines(&fixture()),
        );
        let keys: Vec<&str> = s.periods.iter().map(|p| p.period.as_str()).collect();
        assert_eq!(keys, ["2026-01", "2026-02"]);
        assert_eq!(s.periods[0].totals[0].sums.calls, 2);
        assert_eq!(s.periods[1].totals[0].sums.calls, 2);
        // The window is half-open: a line at `to_ms` is left out.
        let s = build(
            PROVIDER,
            JAN31,
            JAN31 + DAY,
            Period::Day,
            true,
            lines(&fixture()),
        );
        assert_eq!(s.lines.len(), 2);
    }

    #[test]
    fn another_asset_is_totalled_apart_and_its_net_is_the_amount() {
        let mut e = settled(9, JAN31, "gemma", "0xaa", 5_000, 0);
        e["asset"] = json!("eip155:1/erc20:0xusdc");
        let mut entries = fixture();
        entries.push(e);
        let s = build(PROVIDER, 0, u64::MAX, Period::Day, true, lines(&entries));
        assert_eq!(s.totals.len(), 2);
        let other = s.totals.iter().find(|t| t.asset != "TNZO").unwrap();
        assert_eq!(other.sums.gross, 5_000);
        assert_eq!(other.sums.net, 5_000);
        assert!(other.sums.fee > 0);
    }

    #[test]
    fn csv_and_json_agree() {
        let s = build(PROVIDER, 0, u64::MAX, Period::Day, true, lines(&fixture()));
        let lines_csv = lines_csv(&s);
        let rows: Vec<&str> = lines_csv.lines().collect();
        assert_eq!(rows.len(), 1 + s.lines.len());
        let header: Vec<&str> = rows[0].split(',').collect();
        let col = |name: &str| header.iter().position(|h| *h == name).unwrap();
        let sum = |name: &str| -> u128 {
            rows[1..]
                .iter()
                .map(|r| {
                    r.split(',')
                        .nth(col(name))
                        .unwrap()
                        .parse::<u128>()
                        .unwrap_or(0)
                })
                .sum()
        };
        let t = &s.totals[0].sums;
        assert_eq!(sum("fee"), t.fee);
        assert_eq!(sum("treasury_leg"), t.treasury_leg);
        assert_eq!(sum("burned"), t.burned);
        assert_eq!(sum("net"), t.net);
        let summary = summary_csv(&s);
        let total = summary
            .lines()
            .find(|r| r.starts_with("total,"))
            .unwrap()
            .split(',')
            .collect::<Vec<_>>();
        assert_eq!(total[8], t.gross.to_string());
        assert_eq!(total[12], t.net.to_string());
        // The JSON form reads back to the same statement.
        let back: Statement = serde_json::from_value(serde_json::to_value(&s).unwrap()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn a_field_with_a_comma_is_quoted() {
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"x\""), "\"say \"\"x\"\"\"");
        assert_eq!(csv_field("plain"), "plain");
    }

    #[test]
    fn a_statement_matching_the_chain_verifies() {
        let entries = fixture();
        let s = build(PROVIDER, 0, u64::MAX, Period::Day, true, lines(&entries));
        assert_eq!(verify(&s, &facts_of(&entries)), Vec::<String>::new());
    }

    #[test]
    fn verify_reports_every_difference_from_the_chain() {
        let entries = fixture();
        let facts = facts_of(&entries);
        let s = build(PROVIDER, 0, u64::MAX, Period::Day, true, lines(&entries));

        // A total edited after the fact.
        let mut edited = s.clone();
        edited.totals[0].sums.net += 1;
        assert!(!verify(&edited, &facts).is_empty());

        // A line whose fee the chain does not hold, totals made consistent.
        let mut tampered = lines(&entries);
        tampered[0].deducted = tampered[0].deducted.map(|d| d - 1);
        let t = build(PROVIDER, 0, u64::MAX, Period::Day, true, tampered);
        let found = verify(&t, &facts);
        assert!(found.iter().any(|m| m.contains("fee is")), "{found:?}");
        assert!(
            found
                .iter()
                .any(|m| m.contains("recomputed from the chain"))
        );

        // A payment to someone else, and one the chain does not hold.
        let mut other = facts.clone();
        other.values_mut().next().unwrap().payee = "0xdead".into();
        assert!(
            verify(&s, &other)
                .iter()
                .any(|m| m.contains("not the provider"))
        );
        let mut missing = facts.clone();
        missing.pop_first();
        assert!(
            verify(&s, &missing)
                .iter()
                .any(|m| m.contains("holds no payment"))
        );

        // A burn larger than the fee can carry.
        let mut over = facts;
        let f = over.values_mut().next().unwrap();
        f.burned = f.fee + 1;
        assert!(
            verify(&s, &over)
                .iter()
                .any(|m| m.contains("exceed the fee"))
        );
    }
}
