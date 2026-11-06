//! The provider legs this node owes for calls it forwarded.
//!
//! A gateway that forwards an OpenAI-shape call to another provider collects
//! from its own caller through the payment gate and owes the serving provider
//! for the work. Each such leg is a payment record bound to the call, paid
//! from this node's own ledger account with a `PayerSettle` it signs itself:
//!
//! - `request_digest` binds the model, the receipt nonce (unique per call and
//!   committed to by the provider's receipt), the provider, the served
//!   output's hash and the receipt's digest;
//! - `quote_digest` binds the offer the routing decision scored: the
//!   provider's rate card, the units it priced and the amount;
//! - the settlement carries the network fee leg to the treasury at the
//!   governed rate, the same split as a caller-signed payment.
//!
//! A leg is written before anything is paid, so it is never lost: it is
//! queued, then settled or pending under its transaction, or failed with
//! every attempt's reason. A refused attempt is retried with backoff under
//! the same `payment_id`, so a retry can never pay twice. Queued legs are
//! driven again when the RPC server starts, and a failed one can be driven
//! again by the operator (`tenzro_retryNetworkLeg`). `tenzro_listNetworkLegs`
//! lists them.
//!
//! Entries live in `CF_SETTLEMENTS` under `netleg:<payment_id>`.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_storage::{CF_SETTLEMENTS, KvStore};
use tenzro_types::model::BillableUnits;
use tenzro_types::payment_authorization::{PaymentAuthorization, PaymentBinding};
use tenzro_types::price_card::RateCard;
use tenzro_types::primitives::Address;
use tracing::{error, info, warn};

use crate::ledger_payment::{LedgerCharge, PayerPayment};
use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

const KEY_PREFIX: &str = "netleg:";

/// Attempts one drive makes before the leg is left failed for the operator.
pub(crate) const MAX_ATTEMPTS: u32 = 5;

/// Most legs one listing returns.
const MAX_LIST: usize = 500;

fn key(payment_id: &str) -> Vec<u8> {
    format!("{KEY_PREFIX}{payment_id}").into_bytes()
}

/// Where a leg stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LegStatus {
    /// Written, not yet paid; a drive is due or under way.
    Queued,
    /// Submitted and not yet executed when the wait ended.
    Pending,
    /// Executed on the ledger.
    Settled,
    /// Every attempt of the last drive was refused, or the leg could not be
    /// priced; the reasons are in `errors`.
    Failed,
    /// The provider's own offer prices this work at zero.
    Free,
}

/// One provider leg, as this node recorded it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct NetworkLeg {
    /// The idempotency key the payment is signed under: `request_digest`, hex.
    pub payment_id: String,
    pub model_id: String,
    /// The provider paid.
    pub provider: Address,
    /// What the leg pays, before the network fee.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub cost_wei: u128,
    /// The receipt nonce this node sent the provider.
    pub nonce: String,
    /// Hash of the output the provider served.
    pub output_hash: String,
    /// SHA-256 of the provider's receipt, hex, when it returned one.
    pub receipt_digest: Option<String>,
    /// What the payment names as the request it pays for, hex.
    pub request_digest: String,
    /// What the payment names as the offer it pays under, hex.
    pub quote_digest: String,
    pub units: BillableUnits,
    pub status: LegStatus,
    /// Attempts made over every drive.
    pub attempts: u32,
    /// Every refused attempt's reason, oldest first.
    pub errors: Vec<String>,
    /// The account paying: this node's ledger account, once signed.
    pub payer: Option<Address>,
    /// The signed payment, kept so every retry submits the same one.
    pub authorization: Option<PaymentAuthorization>,
    pub tx_hash: Option<String>,
    pub pay_ref: Option<String>,
    /// The network's fee leg out of `cost_wei`, to the treasury.
    #[serde(default, with = "opt_u128")]
    pub network_fee: Option<u128>,
    /// What the provider is credited.
    #[serde(default, with = "opt_u128")]
    pub payee_credit: Option<u128>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

mod opt_u128 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<u128>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(x) => s.serialize_some(&x.to_string()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u128>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| s.parse().map_err(serde::de::Error::custom))
            .transpose()
    }
}

impl NetworkLeg {
    /// The leg as RPC returns it: everything but the signed authorization.
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "payment_id": self.payment_id,
            "model_id": self.model_id,
            "provider": format!("0x{}", hex::encode(self.provider.as_bytes())),
            "cost_wei": self.cost_wei.to_string(),
            "nonce": self.nonce,
            "output_hash": self.output_hash,
            "receipt_digest": self.receipt_digest,
            "request_digest": self.request_digest,
            "quote_digest": self.quote_digest,
            "units": self.units,
            "status": self.status,
            "attempts": self.attempts,
            "errors": self.errors,
            "payer": self.payer.map(|p| format!("0x{}", hex::encode(p.as_bytes()))),
            "tx_hash": self.tx_hash,
            "pay_ref": self.pay_ref,
            "network_fee": self.network_fee.map(|v| v.to_string()),
            "payee_credit": self.payee_credit.map(|v| v.to_string()),
            "created_at_ms": self.created_at_ms,
            "updated_at_ms": self.updated_at_ms,
        })
    }

    /// The binding the payment for this leg is signed over.
    pub(crate) fn binding(&self) -> Result<PaymentBinding, String> {
        let decode = |h: &str| -> Result<[u8; 32], String> {
            hex::decode(h)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| format!("a stored digest is not 32 bytes of hex: {h}"))
        };
        Ok(PaymentBinding {
            request_digest: decode(&self.request_digest)?,
            quote_digest: decode(&self.quote_digest)?,
            usd_e6: 0,
            app_margin: None,
        })
    }
}

/// SHA-256 of a receipt's JSON, hex.
pub(crate) fn receipt_digest(receipt: &Value) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(receipt).unwrap_or_default(),
    ))
}

fn put_len_prefixed(h: &mut Sha256, part: &[u8]) {
    h.update((part.len() as u64).to_le_bytes());
    h.update(part);
}

/// What a leg's payment names as the request it pays for: the model, the
/// nonce, the provider, the served output and the provider's receipt. Any one
/// differing gives a different digest, and so a different `payment_id`.
pub(crate) fn request_digest(
    model_id: &str,
    nonce: &str,
    provider: &Address,
    output_hash: &str,
    receipt_digest: Option<&str>,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro/network-leg/request");
    put_len_prefixed(&mut h, model_id.as_bytes());
    put_len_prefixed(&mut h, nonce.as_bytes());
    put_len_prefixed(&mut h, provider.as_bytes());
    put_len_prefixed(&mut h, output_hash.as_bytes());
    put_len_prefixed(&mut h, receipt_digest.unwrap_or("").as_bytes());
    h.finalize().into()
}

/// What a leg's payment names as the offer it pays under: the provider's
/// card as the routing decision scored it, the units priced and the amount.
pub(crate) fn quote_digest(card: &RateCard, units: &BillableUnits, cost_wei: u128) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro/network-leg/offer");
    put_len_prefixed(&mut h, &serde_json::to_vec(card).unwrap_or_default());
    put_len_prefixed(&mut h, &serde_json::to_vec(units).unwrap_or_default());
    h.update(cost_wei.to_le_bytes());
    h.finalize().into()
}

/// The work one forwarded call owes a provider for.
pub(crate) struct LegWork<'a> {
    pub model_id: &'a str,
    pub provider: Address,
    pub card: &'a RateCard,
    pub units: &'a BillableUnits,
    pub nonce: &'a str,
    pub output_hash: &'a str,
    pub receipt: Option<&'a Value>,
}

/// Build the leg for `work` at `priced` (the card's charge, or why it could
/// not price the work).
pub(crate) fn new_leg(work: &LegWork<'_>, priced: Result<u128, String>, now_ms: u64) -> NetworkLeg {
    let receipt_digest = work.receipt.map(receipt_digest);
    let request = request_digest(
        work.model_id,
        work.nonce,
        &work.provider,
        work.output_hash,
        receipt_digest.as_deref(),
    );
    let (cost_wei, status, errors) = match priced {
        Ok(0) => (0, LegStatus::Free, Vec::new()),
        Ok(c) => (c, LegStatus::Queued, Vec::new()),
        Err(e) => (
            0,
            LegStatus::Failed,
            vec![format!(
                "the provider's announced card does not price this call: {e}"
            )],
        ),
    };
    NetworkLeg {
        payment_id: hex::encode(request),
        model_id: work.model_id.to_string(),
        provider: work.provider,
        cost_wei,
        nonce: work.nonce.to_string(),
        output_hash: work.output_hash.to_string(),
        receipt_digest,
        request_digest: hex::encode(request),
        quote_digest: hex::encode(quote_digest(work.card, work.units, cost_wei)),
        units: work.units.clone(),
        status,
        attempts: 0,
        errors,
        payer: None,
        authorization: None,
        tx_hash: None,
        pay_ref: None,
        network_fee: None,
        payee_credit: None,
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
    }
}

pub(crate) fn put(store: &dyn KvStore, leg: &NetworkLeg) -> Result<(), String> {
    let bytes = serde_json::to_vec(leg).map_err(|e| e.to_string())?;
    store
        .put(CF_SETTLEMENTS, &key(&leg.payment_id), &bytes)
        .map_err(|e| e.to_string())
}

pub(crate) fn get(store: &dyn KvStore, payment_id: &str) -> Result<Option<NetworkLeg>, String> {
    match store
        .get(CF_SETTLEMENTS, &key(payment_id))
        .map_err(|e| e.to_string())?
    {
        None => Ok(None),
        Some(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| e.to_string()),
    }
}

/// Every leg, newest first, optionally only those in `status`.
pub(crate) fn list(
    store: &dyn KvStore,
    status: Option<LegStatus>,
) -> Result<Vec<NetworkLeg>, String> {
    let mut legs: Vec<NetworkLeg> = store
        .scan_prefix(CF_SETTLEMENTS, KEY_PREFIX.as_bytes())
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<NetworkLeg>(&v).ok())
        .filter(|l| status.is_none_or(|s| l.status == s))
        .collect();
    legs.sort_by_key(|l| std::cmp::Reverse(l.created_at_ms));
    Ok(legs)
}

/// Pays a signed leg payment: the ledger in a node, a stand-in in tests.
pub(crate) type Settle = Arc<
    dyn Fn(PayerPayment, Address, u128) -> BoxFuture<'static, Result<LedgerCharge, String>>
        + Send
        + Sync,
>;

/// Signs a leg's payment from this node's own account.
pub(crate) type Sign = Arc<dyn Fn(&NetworkLeg) -> Result<PayerPayment, String> + Send + Sync>;

static IN_FLIGHT: parking_lot::Mutex<Option<HashSet<String>>> = parking_lot::Mutex::new(None);

struct Claim(String);

impl Claim {
    fn take(payment_id: &str) -> Option<Self> {
        let mut g = IN_FLIGHT.lock();
        g.get_or_insert_with(HashSet::new)
            .insert(payment_id.to_string())
            .then(|| Claim(payment_id.to_string()))
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        if let Some(set) = IN_FLIGHT.lock().as_mut() {
            set.remove(&self.0);
        }
    }
}

/// Drive the leg `payment_id` until it is paid or `delays.len() + 1`
/// attempts were refused. Each attempt's outcome is written before the next
/// begins. Returns the leg as it stands after the drive, and whether this
/// drive is the one that paid it. A leg already being driven, already paid,
/// free, or that cannot be priced is returned as it is.
pub(crate) async fn drive_with(
    store: Arc<dyn KvStore>,
    payment_id: &str,
    sign: Sign,
    settle: Settle,
    delays: &[Duration],
    now_ms: impl Fn() -> u64,
) -> Result<(NetworkLeg, bool), String> {
    let mut leg =
        get(store.as_ref(), payment_id)?.ok_or_else(|| format!("no network leg {payment_id}"))?;
    let drivable = matches!(leg.status, LegStatus::Queued | LegStatus::Failed) && leg.cost_wei > 0;
    if !drivable {
        return Ok((leg, false));
    }
    let Some(_claim) = Claim::take(payment_id) else {
        return Ok((leg, false));
    };
    leg.status = LegStatus::Queued;
    leg.updated_at_ms = now_ms();
    put(store.as_ref(), &leg)?;
    let mut i = 0usize;
    loop {
        leg.attempts += 1;
        let attempt = match (leg.authorization.clone(), leg.payer) {
            (Some(authorization), Some(payer)) => Ok(PayerPayment {
                payer,
                payment_id: leg.payment_id.clone(),
                authorization,
            }),
            _ => sign(&leg).inspect(|p| {
                leg.payer = Some(p.payer);
                leg.authorization = Some(p.authorization.clone());
            }),
        };
        let outcome = match attempt {
            Ok(payment) => settle(payment, leg.provider, leg.cost_wei).await,
            Err(e) => Err(format!("the payment could not be signed: {e}")),
        };
        leg.updated_at_ms = now_ms();
        match outcome {
            Ok(charge) => {
                leg.status = if charge.executed {
                    LegStatus::Settled
                } else {
                    LegStatus::Pending
                };
                leg.tx_hash = Some(charge.tx_hash);
                leg.pay_ref = Some(charge.pay_ref);
                leg.network_fee = Some(charge.network_fee);
                leg.payee_credit = Some(charge.payee_credit);
                put(store.as_ref(), &leg)?;
                return Ok((leg, true));
            }
            Err(e) => {
                leg.errors.push(format!("attempt {}: {e}", leg.attempts));
                match delays.get(i) {
                    Some(d) => {
                        put(store.as_ref(), &leg)?;
                        tokio::time::sleep(*d).await;
                        i += 1;
                    }
                    None => {
                        leg.status = LegStatus::Failed;
                        put(store.as_ref(), &leg)?;
                        return Ok((leg, false));
                    }
                }
            }
        }
    }
}

fn node_store(node: &TenzroNode) -> Result<Arc<dyn KvStore>, String> {
    node.storage()
        .cloned()
        .map(|s| s as Arc<dyn KvStore>)
        .ok_or_else(|| "storage not initialized".to_string())
}

fn backoff() -> Vec<Duration> {
    (1..MAX_ATTEMPTS)
        .map(|n| Duration::from_secs(2u64.pow(n)))
        .collect()
}

fn ledger_sign(node: &Arc<TenzroNode>) -> Sign {
    let node = node.clone();
    Arc::new(move |leg: &NetworkLeg| {
        let submitter = node.ledger_submitter().ok_or_else(|| {
            "this node submits no ledger transactions to pay the provider from".to_string()
        })?;
        if submitter.address() == leg.provider {
            return Err("this node is the provider; the leg has no counterparty".to_string());
        }
        submitter.sign_own_payment(leg.provider, &leg.payment_id, leg.cost_wei, leg.binding()?)
    })
}

fn ledger_settle(node: &Arc<TenzroNode>) -> Settle {
    let node = node.clone();
    Arc::new(move |payment, provider, cost| {
        let node = node.clone();
        Box::pin(async move {
            crate::ledger_payment::settle(&node, &payment, provider, cost, None)
                .await
                .map_err(|e| e.message)
        })
    })
}

/// Drive `payment_id` on the ledger, and record the call once it is paid.
pub(crate) async fn drive(node: Arc<TenzroNode>, payment_id: String) {
    let store = match node_store(&node) {
        Ok(s) => s,
        Err(e) => {
            error!(payment_id = %payment_id, error = %e, "Cannot drive a provider leg");
            return;
        }
    };
    let result = drive_with(
        store,
        &payment_id,
        ledger_sign(&node),
        ledger_settle(&node),
        &backoff(),
        crate::calendar::now_ms,
    )
    .await;
    match result {
        Ok((leg, true)) => {
            crate::work_settlements::record_call(
                &node,
                crate::work_settlements::Call {
                    model_id: &leg.model_id,
                    units: &leg.units,
                    provider: leg.provider,
                    routed: true,
                    payer: leg.payer,
                    call_attribution: None,
                    amount: leg.cost_wei,
                    served_at_ms: leg.created_at_ms,
                    paid: crate::work_settlements::Paid::Ledger {
                        tx_hash: leg.tx_hash.clone().unwrap_or_default(),
                        pay_ref: leg.pay_ref.clone().unwrap_or_default(),
                    },
                },
            )
            .await;
        }
        Ok((leg, false)) if leg.status == LegStatus::Failed => error!(
            model = %leg.model_id,
            provider = %leg.provider,
            cost_wei = %leg.cost_wei,
            attempts = leg.attempts,
            errors = ?leg.errors,
            "A provider leg of a forwarded call is unpaid; listed by tenzro_listNetworkLegs, retried by tenzro_retryNetworkLeg"
        ),
        Ok(_) => {}
        Err(e) => error!(payment_id = %payment_id, error = %e, "Driving a provider leg failed"),
    }
}

/// Record the leg `work` owes and start paying it. The record is written
/// before this returns; the payment proceeds in the background.
pub(crate) fn owe(node: &Arc<TenzroNode>, work: LegWork<'_>) -> Option<NetworkLeg> {
    let priced = crate::inference_pricing::charge_wei(node, work.card, work.units)
        .map_err(|e| e.to_string());
    let leg = new_leg(&work, priced, crate::calendar::now_ms());
    let store = match node_store(node) {
        Ok(s) => s,
        Err(e) => {
            error!(model = %work.model_id, error = %e, "Cannot record the provider leg of a forwarded call");
            return None;
        }
    };
    // The same call recorded twice keeps its first record.
    if let Ok(Some(existing)) = get(store.as_ref(), &leg.payment_id) {
        return Some(existing);
    }
    if let Err(e) = put(store.as_ref(), &leg) {
        error!(model = %work.model_id, error = %e, "Cannot record the provider leg of a forwarded call");
        return None;
    }
    match leg.status {
        LegStatus::Queued => {
            tokio::spawn(drive(node.clone(), leg.payment_id.clone()));
        }
        LegStatus::Failed => warn!(
            model = %leg.model_id,
            provider = %leg.provider,
            errors = ?leg.errors,
            "The provider leg of a forwarded call cannot be priced; listed by tenzro_listNetworkLegs"
        ),
        _ => {}
    }
    Some(leg)
}

/// Drive every queued leg again, as after a restart.
pub(crate) fn resume(node: &Arc<TenzroNode>) {
    let Ok(store) = node_store(node) else { return };
    let Ok(queued) = list(store.as_ref(), Some(LegStatus::Queued)) else {
        return;
    };
    if !queued.is_empty() {
        info!(
            count = queued.len(),
            "Resuming queued provider legs of forwarded calls"
        );
    }
    for leg in queued {
        tokio::spawn(drive(node.clone(), leg.payment_id));
    }
}

fn rpc_err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

fn param<'a>(params: &'a Option<Value>, name: &str) -> Option<&'a Value> {
    let p = params.as_ref()?;
    p.get(name).or_else(|| p.get(0).and_then(|o| o.get(name)))
}

/// `tenzro_listNetworkLegs { status?, provider?, limit?, cursor? }`: the
/// provider legs this node owes for calls it forwarded, newest first, one
/// page at a time. `cursor` is the `payment_id` of the last leg a prior page
/// ended on, echoed back as `next_cursor` here; omitted or exhausted, there
/// is no next page.
pub(crate) fn handle_list(node: &TenzroNode, params: Option<Value>) -> Result<Value, JsonRpcError> {
    let status = match param(&params, "status").and_then(|v| v.as_str()) {
        None => None,
        Some(s) => Some(
            serde_json::from_value::<LegStatus>(Value::String(s.to_string())).map_err(|_| {
                rpc_err(
                    -32602,
                    "status must be one of queued, pending, settled, failed, free",
                )
            })?,
        ),
    };
    let provider = match param(&params, "provider").and_then(|v| v.as_str()) {
        None => None,
        Some(p) => Some(
            tenzro_payments::payer_auth::parse_tenzro_address(p)
                .map_err(|e| rpc_err(-32602, format!("provider: {e}")))?,
        ),
    };
    let limit = param(&params, "limit")
        .and_then(|v| v.as_u64())
        .map_or(50, |l| (l as usize).clamp(1, MAX_LIST));
    let cursor = param(&params, "cursor")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let store = node_store(node).map_err(|e| rpc_err(-32603, e))?;
    let matching: Vec<NetworkLeg> = list(store.as_ref(), status)
        .map_err(|e| rpc_err(-32603, e))?
        .into_iter()
        .filter(|l| provider.is_none_or(|p| l.provider == p))
        .collect();
    let start = match &cursor {
        None => 0,
        Some(c) => match matching.iter().position(|l| &l.payment_id == c) {
            Some(i) => i + 1,
            // An unrecognized or already-exhausted cursor names no more
            // results, rather than silently restarting the page from zero.
            None => matching.len(),
        },
    };
    let page = &matching[start.min(matching.len())..];
    let next_cursor = page.get(limit).map(|_| page[limit - 1].payment_id.clone());
    let legs: Vec<Value> = page.iter().take(limit).map(|l| l.to_json()).collect();
    Ok(json!({ "legs": legs, "next_cursor": next_cursor }))
}

/// `tenzro_retryNetworkLeg { payment_id }`: drive a failed leg again, under
/// the same payment, and answer with how it stands after the drive.
pub(crate) async fn handle_retry(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let payment_id = param(&params, "payment_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| rpc_err(-32602, "payment_id is required"))?
        .to_string();
    let store = node_store(node).map_err(|e| rpc_err(-32603, e))?;
    let leg = get(store.as_ref(), &payment_id)
        .map_err(|e| rpc_err(-32603, e))?
        .ok_or_else(|| rpc_err(-32602, format!("no network leg {payment_id}")))?;
    if leg.status != LegStatus::Failed || leg.cost_wei == 0 {
        return Err(rpc_err(
            -32602,
            format!(
                "only a failed, priced leg is retried; this one is {:?}",
                leg.status
            )
            .to_lowercase(),
        ));
    }
    drive(node.clone(), payment_id.clone()).await;
    let leg = get(store.as_ref(), &payment_id)
        .map_err(|e| rpc_err(-32603, e))?
        .ok_or_else(|| rpc_err(-32603, "the leg disappeared"))?;
    Ok(leg.to_json())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn store() -> Arc<dyn KvStore> {
        Arc::new(tenzro_storage::MemoryStore::new())
    }

    fn work<'a>(
        card: &'a RateCard,
        units: &'a BillableUnits,
        receipt: Option<&'a Value>,
        nonce: &'a str,
    ) -> LegWork<'a> {
        LegWork {
            model_id: "qwen3-0.6b",
            provider: Address::new([7u8; 32]),
            card,
            units,
            nonce,
            output_hash: "output-a",
            receipt,
        }
    }

    fn charge(n: u32) -> LedgerCharge {
        LedgerCharge {
            tx_hash: format!("tx-{n}"),
            executed: true,
            amount: 1_000,
            leg: 0,
            network_fee: 10,
            payee_credit: 990,
            pay_ref: "ref".to_string(),
        }
    }

    fn signer(calls: Arc<AtomicU32>) -> Sign {
        Arc::new(move |leg: &NetworkLeg| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(PayerPayment {
                payer: Address::new([1u8; 32]),
                payment_id: leg.payment_id.clone(),
                authorization: PaymentAuthorization {
                    resellers: Vec::new(),
                    public_key: Vec::new(),
                    signature: tenzro_types::account_signature::CompositeSignature::classical(
                        tenzro_types::account_signature::ClassicalProof::Raw {
                            signature: Vec::new(),
                        },
                    ),
                    max_amount: leg.cost_wei,
                    asset: "TNZO".to_string(),
                    binding: leg.binding().unwrap(),
                },
            })
        })
    }

    /// Settles after `fail_first` refusals, recording every payment it saw.
    fn settler(
        fail_first: u32,
        seen: Arc<parking_lot::Mutex<Vec<(String, [u8; 32], u128)>>>,
    ) -> Settle {
        let n = Arc::new(AtomicU32::new(0));
        Arc::new(move |p: PayerPayment, _provider, cost| {
            let n = n.clone();
            let seen = seen.clone();
            Box::pin(async move {
                let i = n.fetch_add(1, Ordering::SeqCst);
                seen.lock().push((
                    p.payment_id.clone(),
                    p.authorization.binding.request_digest,
                    cost,
                ));
                if i < fail_first {
                    Err(format!("refused {i}"))
                } else {
                    Ok(charge(i))
                }
            })
        })
    }

    /// `nonce` must be unique per test: the payment id it determines doubles
    /// as the key into the module's process-wide in-flight guard, so two
    /// tests driving legs with the same nonce at once would contend for the
    /// same claim.
    fn priced_leg(store: &dyn KvStore, receipt: Option<&Value>, nonce: &str) -> NetworkLeg {
        let card = RateCard::default();
        let units = BillableUnits::tokens(5, 7);
        let leg = new_leg(&work(&card, &units, receipt, nonce), Ok(1_000), 1);
        put(store, &leg).unwrap();
        leg
    }

    /// The payment names exactly what it settles for: the request digest is
    /// the payment id and moves with the model, nonce, provider, output and
    /// receipt; the quote digest moves with the card, units and amount.
    #[test]
    fn a_leg_is_bound_to_the_request_the_receipt_and_the_offer() {
        let p = Address::new([7u8; 32]);
        let base = request_digest("m", "n", &p, "o", Some("r"));
        assert_eq!(base, request_digest("m", "n", &p, "o", Some("r")));
        for other in [
            request_digest("m2", "n", &p, "o", Some("r")),
            request_digest("m", "n2", &p, "o", Some("r")),
            request_digest("m", "n", &Address::new([8u8; 32]), "o", Some("r")),
            request_digest("m", "n", &p, "o2", Some("r")),
            request_digest("m", "n", &p, "o", Some("r2")),
            request_digest("m", "n", &p, "o", None),
        ] {
            assert_ne!(base, other);
        }
        let card = RateCard::default();
        let units = BillableUnits::tokens(5, 7);
        assert_ne!(
            quote_digest(&card, &units, 1),
            quote_digest(&card, &units, 2)
        );
        assert_ne!(
            quote_digest(&card, &units, 1),
            quote_digest(&card, &BillableUnits::tokens(5, 8), 1)
        );

        let receipt = json!({"nonce": "nonce-1", "output_hash": "output-a", "signature": "s"});
        let leg = new_leg(
            &work(&card, &units, Some(&receipt), "nonce-1"),
            Ok(1_000),
            1,
        );
        assert_eq!(
            leg.receipt_digest.as_deref(),
            Some(receipt_digest(&receipt).as_str())
        );
        assert_eq!(leg.payment_id, leg.request_digest);
        assert_eq!(
            leg.request_digest,
            hex::encode(request_digest(
                "qwen3-0.6b",
                "nonce-1",
                &Address::new([7u8; 32]),
                "output-a",
                Some(&receipt_digest(&receipt)),
            ))
        );
        assert_eq!(
            leg.quote_digest,
            hex::encode(quote_digest(&card, &units, 1_000))
        );
        assert_eq!(leg.status, LegStatus::Queued);
        let binding = leg.binding().unwrap();
        assert_eq!(hex::encode(binding.request_digest), leg.request_digest);
        assert_eq!(hex::encode(binding.quote_digest), leg.quote_digest);
    }

    /// A refused payment is retried under the same signed payment, every
    /// refusal is kept on the record, and the leg ends settled with the fee
    /// leg and the provider's credit.
    #[tokio::test]
    async fn a_refused_leg_is_retried_under_the_same_payment_and_settles() {
        let s = store();
        let leg = priced_leg(s.as_ref(), None, "nonce-retried-then-settles");
        let signs = Arc::new(AtomicU32::new(0));
        let seen = Arc::default();
        let (after, paid) = drive_with(
            s.clone(),
            &leg.payment_id,
            signer(signs.clone()),
            settler(2, Arc::clone(&seen)),
            &[Duration::ZERO; 4],
            || 2,
        )
        .await
        .unwrap();
        assert!(paid);
        assert_eq!(after.status, LegStatus::Settled);
        assert_eq!(after.attempts, 3);
        assert_eq!(after.errors.len(), 2);
        assert_eq!(after.network_fee, Some(10));
        assert_eq!(after.payee_credit, Some(990));
        assert_eq!(
            signs.load(Ordering::SeqCst),
            1,
            "signed once, retried under the same payment"
        );
        let seen = seen.lock();
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().all(|(id, d, c)| id == &leg.payment_id
            && hex::encode(d) == leg.request_digest
            && *c == 1_000));
        assert_eq!(get(s.as_ref(), &leg.payment_id).unwrap().unwrap(), after);
    }

    /// A leg refused on every attempt is left failed and listed with every
    /// reason; a later drive of the same leg pays it under the same id.
    #[tokio::test]
    async fn an_unpaid_leg_is_listed_failed_and_a_retry_pays_it_once() {
        let s = store();
        let leg = priced_leg(s.as_ref(), None, "nonce-unpaid-then-retried");
        let seen = Arc::default();
        let (after, paid) = drive_with(
            s.clone(),
            &leg.payment_id,
            signer(Arc::default()),
            settler(u32::MAX, Arc::clone(&seen)),
            &[Duration::ZERO; 2],
            || 2,
        )
        .await
        .unwrap();
        assert!(!paid);
        assert_eq!(after.status, LegStatus::Failed);
        assert_eq!(after.attempts, 3);
        let failed = list(s.as_ref(), Some(LegStatus::Failed)).unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].errors.len(), 3);

        let seen2 = Arc::default();
        let (after, paid) = drive_with(
            s.clone(),
            &leg.payment_id,
            signer(Arc::default()),
            settler(0, Arc::clone(&seen2)),
            &[],
            || 3,
        )
        .await
        .unwrap();
        assert!(paid);
        assert_eq!(after.status, LegStatus::Settled);
        assert_eq!(after.attempts, 4);
        assert_eq!(seen2.lock()[0].0, leg.payment_id);

        // A settled leg is never driven again.
        let seen3 = Arc::default();
        let (_, paid) = drive_with(
            s.clone(),
            &leg.payment_id,
            signer(Arc::default()),
            settler(0, Arc::clone(&seen3)),
            &[],
            || 4,
        )
        .await
        .unwrap();
        assert!(!paid);
        assert!(seen3.lock().is_empty());
    }

    /// A leg whose payment cannot be signed is a refused attempt like any
    /// other: recorded, and failed once the attempts run out.
    #[tokio::test]
    async fn a_leg_that_cannot_be_signed_is_recorded_failed() {
        let s = store();
        let leg = priced_leg(s.as_ref(), None, "nonce-cannot-be-signed");
        let no_signer: Sign = Arc::new(|_| Err("no ledger account".to_string()));
        let seen = Arc::default();
        let (after, paid) = drive_with(
            s.clone(),
            &leg.payment_id,
            no_signer,
            settler(0, Arc::clone(&seen)),
            &[Duration::ZERO],
            || 2,
        )
        .await
        .unwrap();
        assert!(!paid);
        assert_eq!(after.status, LegStatus::Failed);
        assert!(after.errors.iter().all(|e| e.contains("no ledger account")));
        assert!(seen.lock().is_empty());
    }

    /// A leg the card cannot price is recorded failed, with the reason, and
    /// is not driven; a leg the provider's own card prices at zero is
    /// recorded free.
    #[test]
    fn unpriced_and_free_legs_are_recorded_not_dropped() {
        let card = RateCard::default();
        let units = BillableUnits::tokens(1, 1);
        let unpriced = new_leg(
            &work(&card, &units, None, "nonce-unpriced"),
            Err("prices nothing".into()),
            1,
        );
        assert_eq!(unpriced.status, LegStatus::Failed);
        assert!(unpriced.errors[0].contains("prices nothing"));
        let free = new_leg(&work(&card, &units, None, "nonce-free"), Ok(0), 1);
        assert_eq!(free.status, LegStatus::Free);
    }
}
