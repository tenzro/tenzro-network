//! Paying on the Tenzro ledger in whatever asset the payer holds: a price in
//! the unit of account, a quote per accepted asset with its fee in kind, an
//! idempotent payment, and a receipt checked against the chain on two
//! endpoints.
//!
//! Nothing is rerouted silently: an asset that cannot settle now is reported
//! with its code, a quote none of whose accepted assets can settle is
//! refused, and a receipt the two endpoints disagree on is refused.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::rpc::RpcClient;
use crate::wallet::{
    HybridSigner, account_address, composite_message_representative, composite_signature_json,
};

/// Signature context of a payment authorization.
pub use crate::payment::PAYMENT_AUTHORIZATION_CONTEXT;

/// A payment step refused, with a stable code: `invalid_price`,
/// `asset_unpermitted`, `asset_disabled`, `rate_held`, `asset_suspended`,
/// `asset_off_peg`, `asset_inflow_full`, `invalid_asset`, `no_accepted_asset`,
/// `settlement_failed`, `receipt_missing`, `receipt_mismatch` or
/// `receipt_unverified`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentError {
    /// The code.
    pub code: String,
    /// What went wrong.
    pub reason: String,
}

impl PaymentError {
    fn new(code: &str, reason: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for PaymentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

impl std::error::Error for PaymentError {}

/// Micro-units of a decimal price: `"0.25"` is 250000. Refuses more than six
/// places, signs and exponents.
pub fn parse_price_e6(amount: &str) -> Result<u64, PaymentError> {
    let bad = || {
        PaymentError::new(
            "invalid_price",
            format!("price {amount:?} is not a decimal with at most six places"),
        )
    };
    let (whole, frac) = amount.split_once('.').unwrap_or((amount, ""));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || (amount.contains('.') && !digits(frac)) || frac.len() > 6 {
        return Err(bad());
    }
    let whole: u64 = whole.parse().map_err(|_| bad())?;
    let frac: u64 = format!("{frac:0<6}").parse().map_err(|_| bad())?;
    let e6 = whole
        .checked_mul(1_000_000)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(bad)?;
    if e6 == 0 {
        return Err(PaymentError::new(
            "invalid_price",
            "a price is greater than zero",
        ));
    }
    Ok(e6)
}

/// The digest of what a payment buys: SHA-256 of `tenzro/request` and the
/// request.
pub fn request_digest(request: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro/request");
    h.update(request.as_bytes());
    h.finalize().into()
}

/// The payment id every retry of one payment settles under: SHA-256 of
/// `tenzro/payment-id`, the idempotency key (u32 LE length prefixed), payer,
/// payee and request digest, as hex. The chain settles an id once.
pub fn payment_id(key: &str, payer: &[u8; 32], payee: &[u8; 32], digest: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"tenzro/payment-id");
    h.update((key.len() as u32).to_le_bytes());
    h.update(key.as_bytes());
    h.update(payer);
    h.update(payee);
    h.update(digest);
    hex::encode(h.finalize())
}

/// A reseller's commission on top of the operator's price: its own leg,
/// signed by the payer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResellerCommission {
    /// The reseller's account.
    pub reseller: [u8; 32],
    /// Basis points of the operator's price.
    pub commission_bps: u32,
}

fn reseller_json(resellers: &[ResellerCommission]) -> Value {
    Value::Array(
        resellers
            .iter()
            .map(|r| json!({ "reseller": r.reseller.to_vec(), "commission_bps": r.commission_bps }))
            .collect(),
    )
}

/// The fields a ledger payment authorization signs.
#[derive(Debug, Clone)]
pub struct LedgerAuthorization<'a> {
    pub chain_id: u64,
    pub payment_id: &'a str,
    pub payer: [u8; 32],
    pub payee: [u8; 32],
    pub max_amount: u128,
    pub asset: &'a str,
    pub request_digest: [u8; 32],
    pub quote_digest: [u8; 32],
    pub usd_e6: u64,
    /// Reseller commissions the payer agrees to.
    pub resellers: &'a [ResellerCommission],
}

/// The authorization preimage a `PayerSettle` checks, exactly as the chain
/// builds it (no developer margin): with resellers, a `0x02` tag, their
/// count and each reseller and commission follow, so none can change after
/// signing.
pub fn ledger_authorization_message(a: &LedgerAuthorization<'_>) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"tenzro/payment-authorization");
    m.extend_from_slice(&a.chain_id.to_le_bytes());
    m.extend_from_slice(&(a.payment_id.len() as u32).to_le_bytes());
    m.extend_from_slice(a.payment_id.as_bytes());
    m.extend_from_slice(&a.payer);
    m.extend_from_slice(&a.payee);
    m.extend_from_slice(&a.max_amount.to_le_bytes());
    m.extend_from_slice(&(a.asset.len() as u32).to_le_bytes());
    m.extend_from_slice(a.asset.as_bytes());
    m.extend_from_slice(&a.request_digest);
    m.extend_from_slice(&a.quote_digest);
    m.extend_from_slice(&a.usd_e6.to_le_bytes());
    m.push(0);
    if !a.resellers.is_empty() {
        m.push(2);
        m.extend_from_slice(&(a.resellers.len() as u32).to_le_bytes());
        for r in a.resellers {
            m.extend_from_slice(&r.reseller);
            m.extend_from_slice(&r.commission_bps.to_le_bytes());
        }
    }
    m
}

/// One commission a quote discloses, as the chain carves it from the signed
/// amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotedLeg {
    /// The reseller's account, hex.
    pub reseller: String,
    pub commission_bps: u32,
    pub amount: u128,
    pub fee: u128,
}

/// One accepted asset's price now, with the fee it pays in kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetQuote {
    pub asset: String,
    /// Smallest units to authorize: the operator's price and every
    /// commission.
    pub amount: u128,
    /// Settlement fee taken out of `amount`, every leg's together, in
    /// `fee_asset`.
    pub fee: u128,
    pub fee_asset: String,
    pub rate_epoch: Option<u64>,
    /// The operator's price inside `amount`.
    pub operator_amount: u128,
    /// Each commission inside `amount`; empty for a direct payment.
    pub legs: Vec<QuotedLeg>,
}

/// One accepted asset's answer: a price, or why it cannot settle now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotedAsset {
    Priced(AssetQuote),
    Refused { asset: String, error: PaymentError },
}

impl QuotedAsset {
    fn asset(&self) -> &str {
        match self {
            QuotedAsset::Priced(q) => &q.asset,
            QuotedAsset::Refused { asset, .. } => asset,
        }
    }
}

fn dec(v: &Value) -> Option<u128> {
    v.as_str()?.parse().ok()
}

/// Reads a `tenzro_quotePayment` answer.
pub fn read_quote_assets(response: &Value) -> Result<Vec<QuotedAsset>, PaymentError> {
    let bad = || PaymentError::new("invalid_asset", "the quote is not in the expected form");
    response["assets"]
        .as_array()
        .ok_or_else(bad)?
        .iter()
        .map(|a| {
            let asset = a["asset"].as_str().ok_or_else(bad)?.to_string();
            if let Some(e) = a.get("error") {
                return Ok(QuotedAsset::Refused {
                    asset,
                    error: PaymentError::new(
                        e["code"].as_str().unwrap_or("invalid_asset"),
                        e["reason"].as_str().unwrap_or(""),
                    ),
                });
            }
            let amount = dec(&a["amount"]).ok_or_else(bad)?;
            let legs = match a.get("legs").and_then(Value::as_array) {
                None => Vec::new(),
                Some(l) => l
                    .iter()
                    .map(|l| {
                        Ok(QuotedLeg {
                            reseller: l["reseller"].as_str().ok_or_else(bad)?.to_string(),
                            commission_bps: l["commission_bps"].as_u64().ok_or_else(bad)? as u32,
                            amount: dec(&l["amount"]).ok_or_else(bad)?,
                            fee: dec(&l["fee"]).ok_or_else(bad)?,
                        })
                    })
                    .collect::<Result<_, PaymentError>>()?,
            };
            Ok(QuotedAsset::Priced(AssetQuote {
                asset,
                amount,
                fee: dec(&a["fee"]).ok_or_else(bad)?,
                fee_asset: a["fee_asset"].as_str().ok_or_else(bad)?.to_string(),
                rate_epoch: a["rate_epoch"].as_u64(),
                operator_amount: a
                    .get("operator_amount")
                    .map_or(Some(amount), dec)
                    .ok_or_else(bad)?,
                legs,
            }))
        })
        .collect()
}

/// The first asset in `accept` order the payment can settle in; refused
/// with every reason when none can.
pub fn choose_asset(assets: &[QuotedAsset], accept: &[&str]) -> Result<AssetQuote, PaymentError> {
    let mut reasons = Vec::new();
    let mut only: Option<String> = None;
    for want in accept {
        match assets.iter().find(|a| a.asset().eq_ignore_ascii_case(want)) {
            None => reasons.push(format!("{want}: not quoted")),
            Some(QuotedAsset::Priced(q)) => return Ok(q.clone()),
            Some(QuotedAsset::Refused { error, .. }) => {
                reasons.push(format!("{want}: {} ({})", error.code, error.reason));
                only = Some(match only {
                    None => error.code.clone(),
                    Some(c) if c == error.code => c,
                    Some(_) => "no_accepted_asset".to_string(),
                });
            }
        }
    }
    Err(PaymentError::new(
        only.as_deref().unwrap_or("no_accepted_asset"),
        format!("no accepted asset can settle now: {}", reasons.join("; ")),
    ))
}

/// What a payment was made for, to check its record against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedPayment {
    pub payment_id: String,
    /// The one request the payment pays for.
    pub request: String,
    /// The payee, 32 bytes of hex.
    pub payee: String,
    pub asset: String,
    pub amount: u128,
    /// The commissions the payment carries; their legs must all be on the
    /// record.
    pub resellers: Vec<ResellerCommission>,
}

fn payee_hex(v: &Value) -> String {
    match v {
        Value::Array(a) => hex::encode(
            a.iter()
                .filter_map(|x| x.as_u64())
                .map(|x| x as u8)
                .collect::<Vec<_>>(),
        ),
        other => other
            .as_str()
            .unwrap_or("")
            .trim_start_matches("0x")
            .to_ascii_lowercase(),
    }
}

/// Checks the record two endpoints returned for a payment: both present and
/// identical, a native record under the payment id, to the payee, in the
/// asset and amount paid, for exactly `expected.request`, with every receipt
/// field filled. A receipt for one request never verifies for another.
pub fn check_receipt(
    expected: &ExpectedPayment,
    a: &Value,
    b: &Value,
) -> Result<Value, PaymentError> {
    if a.is_null() || b.is_null() {
        return Err(PaymentError::new(
            "receipt_missing",
            format!("no record settled under {}", expected.payment_id),
        ));
    }
    if a != b {
        return Err(PaymentError::new(
            "receipt_mismatch",
            "the two endpoints return different records",
        ));
    }
    let fail = |what: &str| {
        PaymentError::new(
            "receipt_mismatch",
            format!("the record's {what} is not what was paid"),
        )
    };
    if a["class"] != "native" {
        return Err(fail("class"));
    }
    if a["nonce"].as_str() != Some(expected.payment_id.as_str()) {
        return Err(fail("payment id"));
    }
    if payee_hex(&a["payee"]) != expected.payee.trim_start_matches("0x").to_ascii_lowercase() {
        return Err(fail("payee"));
    }
    if !a["asset"]
        .as_str()
        .unwrap_or("")
        .eq_ignore_ascii_case(&expected.asset)
    {
        return Err(fail("asset"));
    }
    if dec(&a["amount"]) != Some(expected.amount) {
        return Err(fail("amount"));
    }
    for f in ["fee_asset", "payout_asset", "value_units"] {
        if a[f].as_str().is_none_or(str::is_empty) {
            return Err(fail(f));
        }
    }
    if a["unit"]["basket"].as_str().is_none_or(str::is_empty) {
        return Err(fail("unit"));
    }
    if a["binding"]["request_digest"].as_str()
        != Some(hex::encode(request_digest(&expected.request)).as_str())
    {
        return Err(fail("request"));
    }
    // Every record names its legs: the operator first, then each commission.
    let legs = a["legs"].as_array().cloned().unwrap_or_default();
    let payee = expected.payee.trim_start_matches("0x").to_ascii_lowercase();
    if legs
        .first()
        .is_none_or(|l| l["role"] != "operator" || payee_hex(&l["account"]) != payee)
    {
        return Err(fail("operator leg"));
    }
    let resold: Vec<&Value> = legs.iter().filter(|l| l["role"] == "reseller").collect();
    let all_there = expected.resellers.iter().all(|w| {
        resold.iter().any(|l| {
            payee_hex(&l["account"]) == hex::encode(w.reseller)
                && l["commission_bps"].as_u64() == Some(u64::from(w.commission_bps))
        })
    });
    if resold.len() != expected.resellers.len() || !all_there {
        return Err(fail("reseller legs"));
    }
    Ok(a.clone())
}

/// Where a seller records the payments it has served, so each unlocks one
/// request once. A store shared by every server of a seller makes that hold
/// across them.
pub trait ChargeStore: Send + Sync {
    /// `true` the first time `payment_id` is claimed, `false` ever after.
    fn claim(&self, payment_id: &str, request: &str) -> bool;
}

/// A [`ChargeStore`] in this process's memory.
#[derive(Debug, Default)]
pub struct MemoryChargeStore {
    used: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

impl ChargeStore for MemoryChargeStore {
    fn claim(&self, payment_id: &str, request: &str) -> bool {
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        if used.contains_key(payment_id) {
            return false;
        }
        used.insert(payment_id.to_string(), request.to_string());
        true
    }
}

/// A quote with the asset chosen.
#[derive(Debug, Clone)]
pub struct LedgerQuote {
    pub payee: [u8; 32],
    /// What the payment buys.
    pub request: String,
    pub request_digest: [u8; 32],
    pub usd_e6: u64,
    pub assets: Vec<QuotedAsset>,
    pub chosen: AssetQuote,
    /// The commissions the payment carries, signed with it.
    pub resellers: Vec<ResellerCommission>,
}

/// A settled payment and the record the chain holds for it.
#[derive(Debug, Clone)]
pub struct PaidPayment {
    pub expected: ExpectedPayment,
    pub record: Value,
}

fn b32(value: &str, what: &str) -> Result<[u8; 32], PaymentError> {
    hex::decode(value.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| PaymentError::new("invalid_asset", format!("{what} is 32 bytes of hex")))
}

/// Quote, pay and verify ledger payments over one or more node endpoints.
pub struct LedgerPayments {
    rpcs: Vec<Arc<RpcClient>>,
    /// Pause between retries and record lookups.
    pub backoff: Duration,
}

impl LedgerPayments {
    /// Over `rpcs`; receipts are checked on the first two.
    pub fn new(rpcs: Vec<Arc<RpcClient>>) -> Self {
        assert!(!rpcs.is_empty(), "at least one endpoint");
        Self {
            rpcs,
            backoff: Duration::from_millis(250),
        }
    }

    async fn lookup(&self, i: usize, id: &str) -> Result<Value, PaymentError> {
        self.rpcs[i % self.rpcs.len()]
            .call(
                "tenzro_getPayment",
                json!({ "payment_id": id, "exact": true }),
            )
            .await
            .map_err(|e| PaymentError::new("receipt_missing", e.to_string()))
    }

    /// What `price` (a decimal in USD) costs in each of `accept` now, with
    /// the fee each pays in kind; chooses the first that can settle.
    pub async fn quote(
        &self,
        payee: &str,
        price: &str,
        request: &str,
        accept: &[&str],
        resellers: &[ResellerCommission],
    ) -> Result<LedgerQuote, PaymentError> {
        let usd_e6 = parse_price_e6(price)?;
        let mut params = json!({ "usd_e6": usd_e6, "accept": accept });
        if !resellers.is_empty() {
            params["resellers"] = reseller_json(resellers);
        }
        let response: Value = self.rpcs[0]
            .call("tenzro_quotePayment", params)
            .await
            .map_err(|e| PaymentError::new("rate_held", e.to_string()))?;
        let assets = read_quote_assets(&response)?;
        let chosen = choose_asset(&assets, accept)?;
        Ok(LedgerQuote {
            payee: b32(payee, "payee")?,
            request: request.to_string(),
            request_digest: request_digest(request),
            usd_e6,
            assets,
            chosen,
            resellers: resellers.to_vec(),
        })
    }

    /// Pays a quote: signs the authorization for the chosen asset and
    /// amount, has a node relay it, and waits for the record. A retry with
    /// the same idempotency key looks the payment up first and never pays
    /// twice.
    pub async fn pay(
        &self,
        q: &LedgerQuote,
        signer: &dyn HybridSigner,
        idempotency_key: &str,
        account: Option<[u8; 32]>,
    ) -> Result<PaidPayment, PaymentError> {
        let public_key = signer.p256_public_key();
        let payer = account.unwrap_or_else(|| account_address(&public_key));
        let id = payment_id(idempotency_key, &payer, &q.payee, &q.request_digest);
        let expected = ExpectedPayment {
            payment_id: id.clone(),
            request: q.request.clone(),
            payee: hex::encode(q.payee),
            asset: q.chosen.asset.clone(),
            amount: q.chosen.amount,
            resellers: q.resellers.clone(),
        };
        let existing = self.lookup(0, &id).await?;
        if !existing.is_null() {
            return Ok(PaidPayment {
                expected,
                record: existing,
            });
        }
        let chain: String = self.rpcs[0]
            .call("eth_chainId", json!([]))
            .await
            .map_err(|e| PaymentError::new("settlement_failed", e.to_string()))?;
        let chain_id = u64::from_str_radix(chain.trim_start_matches("0x"), 16).map_err(|_| {
            PaymentError::new("settlement_failed", "the node's chain id is not hex")
        })?;
        let message = ledger_authorization_message(&LedgerAuthorization {
            chain_id,
            payment_id: &id,
            payer,
            payee: q.payee,
            max_amount: q.chosen.amount,
            asset: &q.chosen.asset,
            request_digest: q.request_digest,
            quote_digest: [0; 32],
            usd_e6: q.usd_e6,
            resellers: &q.resellers,
        });
        let m_prime = composite_message_representative(PAYMENT_AUTHORIZATION_CONTEXT, &message);
        let (p256, ml_dsa) = signer
            .sign_composite(&m_prime)
            .await
            .map_err(|e| PaymentError::new("settlement_failed", e.to_string()))?;
        let params = json!({
            "payee": hex::encode(q.payee),
            "amount": q.chosen.amount.to_string(),
            "payment": {
                "payer": hex::encode(payer),
                "payment_id": id,
                "authorization": {
                    "public_key": hex::encode(public_key),
                    "signature": composite_signature_json(&p256, ml_dsa.as_deref()),
                    "max_amount": q.chosen.amount.to_string(),
                    "asset": q.chosen.asset,
                    "binding": {
                        "request_digest": hex::encode(q.request_digest),
                        "quote_digest": hex::encode([0u8; 32]),
                        "usd_e6": q.usd_e6,
                        "app_margin": null,
                    },
                    "resellers": reseller_json(&q.resellers),
                },
            },
        });
        let mut wait = self.backoff;
        let mut last = None;
        for i in 0..4 {
            match self.rpcs[i % self.rpcs.len()]
                .call::<Value>("tenzro_settle", params.clone())
                .await
            {
                Ok(_) => {
                    last = None;
                    break;
                }
                Err(e) => {
                    last = Some(e.to_string());
                    if let Ok(r) = self.lookup(i, &id).await
                        && !r.is_null()
                    {
                        return Ok(PaidPayment {
                            expected,
                            record: r,
                        });
                    }
                    tokio::time::sleep(wait).await;
                    wait *= 2;
                }
            }
        }
        if let Some(e) = last {
            return Err(PaymentError::new(
                "settlement_failed",
                format!("the payment was not settled: {e}"),
            ));
        }
        for i in 0..30 {
            if let Ok(r) = self.lookup(i, &id).await
                && !r.is_null()
            {
                return Ok(PaidPayment {
                    expected,
                    record: r,
                });
            }
            tokio::time::sleep(self.backoff).await;
        }
        Err(PaymentError::new(
            "receipt_missing",
            format!("payment {id} was submitted and is not yet recorded"),
        ))
    }

    /// Checks a payment's record on two endpoints.
    pub async fn verify_receipt(&self, expected: &ExpectedPayment) -> Result<Value, PaymentError> {
        if self.rpcs.len() < 2 {
            return Err(PaymentError::new(
                "receipt_unverified",
                "a receipt is checked on two endpoints",
            ));
        }
        let a = self.lookup(0, &expected.payment_id).await?;
        let b = self.lookup(1, &expected.payment_id).await?;
        check_receipt(expected, &a, &b)
    }

    /// Quote, pay and verify in one call.
    #[allow(clippy::too_many_arguments)]
    pub async fn pay_for(
        &self,
        request: &str,
        payee: &str,
        price: &str,
        accept: &[&str],
        signer: &dyn HybridSigner,
        idempotency_key: &str,
        account: Option<[u8; 32]>,
        resellers: &[ResellerCommission],
    ) -> Result<PaidPayment, PaymentError> {
        let q = self.quote(payee, price, request, accept, resellers).await?;
        let paid = self.pay(&q, signer, idempotency_key, account).await?;
        if self.rpcs.len() < 2 {
            return Ok(paid);
        }
        let record = self.verify_receipt(&paid.expected).await?;
        Ok(PaidPayment {
            expected: paid.expected,
            record,
        })
    }

    /// Seller side: whether the payment `payment_id` on chain, checked on two
    /// endpoints, pays `payee` at least `price` (a decimal in USD) for
    /// `request`, presented for the first time (`store`).
    /// `Ok(Some(record))` serves it; `Ok(None)` answers 402.
    pub async fn charge(
        &self,
        request: &str,
        payment_id: Option<&str>,
        payee: &str,
        price: &str,
        store: &dyn ChargeStore,
        reseller: Option<ResellerCommission>,
    ) -> Result<Option<Value>, PaymentError> {
        let owed = u128::from(parse_price_e6(price)?);
        let Some(id) = payment_id else {
            return Ok(None);
        };
        if self.rpcs.len() < 2 {
            return Err(PaymentError::new(
                "receipt_unverified",
                "a charge checks payments on two endpoints",
            ));
        }
        let a = self.lookup(0, id).await?;
        let b = self.lookup(1, id).await?;
        if a.is_null() || b.is_null() {
            return Ok(None);
        }
        if a != b {
            return Err(PaymentError::new(
                "receipt_mismatch",
                "the two endpoints return different records",
            ));
        }
        let paid_for = hex::encode(request_digest(request));
        let ok = payee_hex(&a["payee"]) == payee.trim_start_matches("0x").to_ascii_lowercase()
            && a["binding"]["request_digest"].as_str() == Some(paid_for.as_str())
            && dec(&a["value_units"]).unwrap_or(0) >= owed
            && reseller.is_none_or(|w| {
                a["legs"].as_array().is_some_and(|legs| {
                    legs.iter().any(|l| {
                        l["role"] == "reseller"
                            && payee_hex(&l["account"]) == hex::encode(w.reseller)
                            && l["commission_bps"].as_u64() == Some(u64::from(w.commission_bps))
                    })
                })
            });
        Ok((ok && store.claim(id, request)).then_some(a))
    }
}
