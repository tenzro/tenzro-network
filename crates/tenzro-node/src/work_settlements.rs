//! The work this node settled: one entry per paid call it served or routed,
//! with what the work was, who served it, who paid and how it settled.
//!
//! An entry is this node's own account of a call: the model, the units, the
//! serving node and its hardware tier, the call chain a voucher named, and
//! when the request arrived. The settlement it names is on the chain, and
//! `tenzro_listSettlements` reads the chain for the parts the chain holds:
//! the fee, the burn and treasury leg, the block time and the delivery
//! receipts. Every entry in the answer says which of its fields came from
//! where.
//!
//! Entries live in `CF_SETTLEMENTS`:
//! - `work:n`: the next sequence number, u64 little endian;
//! - `work:<seq, 16 hex>`: one [`WorkSettlement`], JSON;
//! - `work:ref:<pay_ref hex>`: the sequence number of the entry a ledger
//!   payment settled, u64 little endian.
//!
//! The node keeps the latest [`MAX_ENTRIES`]; appending past that deletes
//! the oldest.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tenzro_storage::{CF_SETTLEMENTS, CF_TRANSACTIONS, KvStore, WriteOp};
use tenzro_types::model::BillableUnits;
use tenzro_types::primitives::Address;
use tenzro_types::settlement::CallAttribution;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Entries kept.
pub(crate) const MAX_ENTRIES: u64 = 100_000;
/// Most entries one page returns.
pub(crate) const MAX_PAGE: usize = 200;
const DEFAULT_PAGE: usize = 50;
/// Most entries one request reads while filtering; a page that reaches it
/// returns what it found and a cursor to continue from.
const MAX_SCAN: u64 = 5_000;

const COUNT_KEY: &[u8] = b"work:n";

fn entry_key(seq: u64) -> Vec<u8> {
    format!("work:{seq:016x}").into_bytes()
}

fn ref_key(pay_ref: &str) -> Vec<u8> {
    format!("work:ref:{pay_ref}").into_bytes()
}

/// How a settled call was paid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "via", rename_all = "snake_case")]
pub(crate) enum Paid {
    /// A `PayerSettle` the payer authorized, on the ledger.
    Ledger {
        /// The transaction, hex.
        tx_hash: String,
        /// The payment record's reference, hex.
        pay_ref: String,
    },
    /// A cumulative voucher on an escrow the payer funded, claimed on the
    /// ledger later.
    Channel {
        /// The escrow, hex.
        escrow_id: String,
        /// The node's debit reference on the channel.
        reference: String,
        /// The voucher's cumulative amount after this call.
        #[serde(with = "tenzro_types::primitives::u128_serde")]
        cumulative: u128,
        /// The head of the receipt chain the voucher pays for, hex.
        receipt_chain_head: String,
    },
}

/// One settled call, as this node recorded it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct WorkSettlement {
    /// Position in this node's record.
    pub seq: u64,
    /// The work class the settlement counts as.
    pub work_class: String,
    pub model_id: String,
    /// The units charged.
    pub units: BillableUnits,
    /// The account paid.
    pub provider: Address,
    /// The machine that served the call, `did:tenzro:machine:...`, when
    /// known.
    pub serving_node: Option<String>,
    /// The serving cluster's capability key, when it announced one.
    pub cap_key: Option<String>,
    /// The serving machine's hardware class, as it detected or announced it.
    pub hardware_tier: Option<String>,
    /// The paying account.
    pub payer: Option<Address>,
    /// The call chain the payer's voucher named.
    pub call_attribution: Option<CallAttribution>,
    /// When the request reached this node, unix ms, when it came over HTTP.
    pub requested_at_ms: Option<u64>,
    /// When the answer was ready and settlement began, unix ms.
    pub served_at_ms: u64,
    /// What the payer was charged.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub amount: u128,
    pub paid: Paid,
}

/// The hardware class name of `class`.
pub(crate) fn tier_name(class: tenzro_types::hardware::HardwareClass) -> &'static str {
    use tenzro_types::hardware::HardwareClass::*;
    match class {
        Unknown => "unknown",
        Cpu => "cpu",
        ConsumerGpu => "consumer_gpu",
        DatacenterGpu => "datacenter_gpu",
        MultiAccelerator => "multi_accelerator",
    }
}

static LOCAL_TIER: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

/// This machine's hardware class, detected on first use.
pub(crate) async fn local_tier() -> &'static str {
    if let Some(t) = LOCAL_TIER.get() {
        return t;
    }
    let hw = tokio::task::spawn_blocking(tenzro_types::HardwareCapabilities::detect)
        .await
        .unwrap_or_default();
    LOCAL_TIER.get_or_init(|| tier_name(hw.class()))
}

static APPEND: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

fn read_u64(store: &dyn KvStore, cf: &str, key: &[u8]) -> Result<Option<u64>, String> {
    match store.get(cf, key).map_err(|e| e.to_string())? {
        None => Ok(None),
        Some(b) => <[u8; 8]>::try_from(b.as_slice())
            .map(|a| Some(u64::from_le_bytes(a)))
            .map_err(|_| "a stored counter is not 8 bytes".to_string()),
    }
}

fn read_entry(store: &dyn KvStore, seq: u64) -> Result<Option<WorkSettlement>, String> {
    store
        .get(CF_SETTLEMENTS, &entry_key(seq))
        .map_err(|e| e.to_string())?
        .map(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
        .transpose()
}

/// Append `entry` under the next sequence number, which it returns; the
/// entry's own `seq` is overwritten.
pub(crate) fn append(store: &dyn KvStore, entry: WorkSettlement) -> Result<u64, String> {
    append_within(store, entry, MAX_ENTRIES)
}

fn append_within(store: &dyn KvStore, mut entry: WorkSettlement, kept: u64) -> Result<u64, String> {
    let _held = APPEND.lock();
    let seq = read_u64(store, CF_SETTLEMENTS, COUNT_KEY)?.unwrap_or(0);
    entry.seq = seq;
    let mut ops = vec![
        WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: entry_key(seq),
            value: serde_json::to_vec(&entry).map_err(|e| e.to_string())?,
        },
        WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: COUNT_KEY.to_vec(),
            value: (seq + 1).to_le_bytes().to_vec(),
        },
    ];
    if let Paid::Ledger { pay_ref, .. } = &entry.paid {
        ops.push(WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: ref_key(pay_ref),
            value: seq.to_le_bytes().to_vec(),
        });
    }
    if seq >= kept {
        let old = seq - kept;
        if let Some(Paid::Ledger { pay_ref, .. }) = read_entry(store, old)?.map(|e| e.paid) {
            ops.push(WriteOp::Delete {
                cf: CF_SETTLEMENTS.to_string(),
                key: ref_key(&pay_ref),
            });
        }
        ops.push(WriteOp::Delete {
            cf: CF_SETTLEMENTS.to_string(),
            key: entry_key(old),
        });
    }
    store.write_batch(ops).map_err(|e| e.to_string())?;
    Ok(seq)
}

/// The entry a ledger payment with reference `pay_ref` (hex) settled.
pub(crate) fn by_pay_ref(
    store: &dyn KvStore,
    pay_ref: &str,
) -> Result<Option<WorkSettlement>, String> {
    match read_u64(store, CF_SETTLEMENTS, &ref_key(pay_ref))? {
        Some(seq) => read_entry(store, seq),
        None => Ok(None),
    }
}

/// What a page of entries is narrowed to.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Filter {
    pub work_class: Option<String>,
    pub provider: Option<Address>,
    pub payer: Option<Address>,
    pub from_ms: Option<u64>,
    pub to_ms: Option<u64>,
}

impl Filter {
    fn admits(&self, e: &WorkSettlement) -> bool {
        self.work_class.as_ref().is_none_or(|w| &e.work_class == w)
            && self.provider.as_ref().is_none_or(|p| &e.provider == p)
            && self
                .payer
                .as_ref()
                .is_none_or(|p| e.payer.as_ref() == Some(p))
            && self.from_ms.is_none_or(|t| e.served_at_ms >= t)
            && self.to_ms.is_none_or(|t| e.served_at_ms < t)
    }
}

/// A page of entries, newest first.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Page {
    pub entries: Vec<WorkSettlement>,
    /// Pass back as `cursor` to continue; `None` once nothing older is kept.
    pub cursor: Option<u64>,
    /// Entries ever appended.
    pub total: u64,
}

/// Entries older than `before` (all when `None`) that `filter` admits,
/// newest first, at most `limit`, reading at most [`MAX_SCAN`] entries.
pub(crate) fn page(
    store: &dyn KvStore,
    before: Option<u64>,
    limit: usize,
    filter: &Filter,
) -> Result<Page, String> {
    page_within(store, before, limit, filter, MAX_ENTRIES)
}

fn page_within(
    store: &dyn KvStore,
    before: Option<u64>,
    limit: usize,
    filter: &Filter,
    kept: u64,
) -> Result<Page, String> {
    let total = read_u64(store, CF_SETTLEMENTS, COUNT_KEY)?.unwrap_or(0);
    let oldest = total.saturating_sub(kept);
    let mut next = before.unwrap_or(total).min(total);
    let mut entries = Vec::new();
    let mut scanned = 0;
    while next > oldest && entries.len() < limit && scanned < MAX_SCAN {
        next -= 1;
        scanned += 1;
        if let Some(e) = read_entry(store, next)?
            && filter.admits(&e)
        {
            entries.push(e);
        }
    }
    Ok(Page {
        entries,
        cursor: (next > oldest).then_some(next),
        total,
    })
}

/// Most entries a per-provider window reads back.
const MAX_WINDOW_SCAN: u64 = 20_000;

/// `provider`'s entries served at or after `since_ms`, newest first, and
/// whether the read reached back that far: it stops at the first entry
/// older than `since_ms` or after [`MAX_WINDOW_SCAN`] entries.
pub(crate) fn provider_since(
    store: &dyn KvStore,
    provider: &Address,
    since_ms: u64,
) -> Result<(Vec<WorkSettlement>, bool), String> {
    let total = read_u64(store, CF_SETTLEMENTS, COUNT_KEY)?.unwrap_or(0);
    let oldest = total.saturating_sub(MAX_ENTRIES);
    let mut next = total;
    let mut out = Vec::new();
    let mut scanned = 0;
    while next > oldest {
        if scanned == MAX_WINDOW_SCAN {
            return Ok((out, false));
        }
        next -= 1;
        scanned += 1;
        let Some(e) = read_entry(store, next)? else {
            continue;
        };
        if e.served_at_ms < since_ms {
            return Ok((out, true));
        }
        if &e.provider == provider {
            out.push(e);
        }
    }
    // The record ran out: complete only when nothing was ever dropped.
    Ok((out, oldest == 0))
}

/// Record a settled call; a failure to write it is logged, never fatal to
/// the call it describes.
pub(crate) fn record(node: &TenzroNode, entry: WorkSettlement) {
    let Some(store) = node.storage() else {
        return;
    };
    if let Err(e) = append(store.as_ref(), entry) {
        tracing::warn!(error = %e, "a settled call was not recorded");
    }
}

/// A call this node just settled, as its settlement path knows it.
pub(crate) struct Call<'a> {
    pub model_id: &'a str,
    pub units: &'a BillableUnits,
    /// The account paid.
    pub provider: Address,
    /// Whether another node served it, routed there by this one.
    pub routed: bool,
    pub payer: Option<Address>,
    pub call_attribution: Option<CallAttribution>,
    pub amount: u128,
    /// When the answer was ready and settlement began, unix ms.
    pub served_at_ms: u64,
    pub paid: Paid,
}

/// Record `call` with what this node knows of the machine that served it:
/// itself, or the announcement of the provider it was routed to.
pub(crate) async fn record_call(node: &TenzroNode, call: Call<'_>) {
    let (serving_node, cap_key, hardware_tier) = if call.routed {
        let payee = hex::encode(call.provider.as_bytes());
        node.network_providers_snapshot()
            .into_iter()
            .map(|e| e.announcement)
            .find(|a| {
                a.provider_address
                    .trim_start_matches("0x")
                    .eq_ignore_ascii_case(&payee)
                    && a.served_models.iter().any(|m| m == call.model_id)
            })
            .map_or((None, None, None), |a| {
                (
                    (!a.machine_did.is_empty()).then_some(a.machine_did.clone()),
                    a.cluster_profile
                        .as_ref()
                        .map(|c| c.cap_key.clone())
                        .filter(|k| !k.is_empty()),
                    a.hardware
                        .detected
                        .then(|| tier_name(a.hardware.class()).to_string()),
                )
            })
    } else {
        (
            crate::identity_bootstrap::machine_did(),
            None,
            Some(local_tier().await.to_string()),
        )
    };
    record(
        node,
        WorkSettlement {
            seq: 0,
            work_class: tenzro_token::rewards::WorkClass::InferenceServed
                .as_key()
                .to_string(),
            model_id: call.model_id.to_string(),
            units: call.units.clone(),
            provider: call.provider,
            serving_node,
            cap_key,
            hardware_tier,
            payer: call.payer,
            call_attribution: call.call_attribution,
            requested_at_ms: crate::ip_rate_limit::arrival().map(|a| a.at_ms),
            served_at_ms: call.served_at_ms,
            amount: call.amount,
            paid: call.paid,
        },
    );
}

/// What the chain holds for a ledger settlement: its payment record and its
/// transaction receipt, when they exist.
pub(crate) struct OnChain {
    pub record: Option<tenzro_types::settlement::PaymentRecord>,
    pub receipt: Option<crate::event_loop::TxReceiptRecord>,
    pub escrow: Option<tenzro_settlement::escrow::EscrowAccount>,
}

/// Read what the chain holds for `entry`.
pub(crate) fn on_chain(
    store: &dyn KvStore,
    chain: &dyn tenzro_vm::traits::VmState,
    entry: &WorkSettlement,
) -> OnChain {
    match &entry.paid {
        Paid::Ledger { tx_hash, pay_ref } => {
            let record = hex::decode(pay_ref)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .and_then(|r| tenzro_vm::native::read_payment(chain, &r));
            let receipt = store
                .get(
                    CF_TRANSACTIONS,
                    format!("receipt:{}", tx_hash.trim_start_matches("0x")).as_bytes(),
                )
                .ok()
                .flatten()
                .and_then(|b| serde_json::from_slice(&b).ok());
            OnChain {
                record,
                receipt,
                escrow: None,
            }
        }
        Paid::Channel { escrow_id, .. } => OnChain {
            record: None,
            receipt: None,
            escrow: hex::decode(escrow_id)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .and_then(|id| tenzro_vm::native::read_escrow(chain, &id)),
        },
    }
}

fn hex_addr(a: &Address) -> String {
    format!("0x{}", hex::encode(a.as_bytes()))
}

/// The answer's form of `entry`, with what `chain` holds for it.
pub(crate) fn entry_json(entry: &WorkSettlement, chain: &OnChain) -> Value {
    let attribution = entry
        .call_attribution
        .as_ref()
        .map(|a| json!({ "app_did": a.app_did, "agent_did": a.agent_did, "tool_did": a.tool_did }));
    let mut v = json!({
        "cursor": entry.seq.to_string(),
        "work_class": entry.work_class,
        "model_id": entry.model_id,
        "units": crate::rpc::units_to_json(&entry.units),
        "provider": hex_addr(&entry.provider),
        "serving_node": entry.serving_node,
        "cap_key": entry.cap_key,
        "hardware_tier": entry.hardware_tier,
        "payer": entry.payer.as_ref().map(hex_addr),
        "call_attribution": attribution,
        "requested_at_ms": entry.requested_at_ms,
        "served_at_ms": entry.served_at_ms,
        "latency_ms": entry.requested_at_ms.map(|r| entry.served_at_ms.saturating_sub(r)),
        "amount": entry.amount.to_string(),
    });
    let mut node_local = vec![
        "work_class",
        "model_id",
        "units",
        "serving_node",
        "cap_key",
        "hardware_tier",
        "call_attribution",
        "requested_at_ms",
        "served_at_ms",
        "latency_ms",
    ];
    let mut on_chain: Vec<&str> = Vec::new();
    match &entry.paid {
        Paid::Ledger { tx_hash, pay_ref } => {
            v["via"] = json!("ledger");
            v["tx_hash"] = json!(tx_hash);
            v["pay_ref"] = json!(pay_ref);
            match &chain.record {
                Some(r) => {
                    v["status"] = json!("settled");
                    v["settled_at_ms"] = json!(r.recorded_at_ms);
                    v["asset"] = json!(r.asset);
                    v["fee"] = json!(r.fee.to_string());
                    v["receipts"] = json!(r.receipts);
                    v["request_digest"] = json!(hex::encode(r.binding.request_digest));
                    v["agent_did"] = json!(r.agent_did);
                    on_chain.extend([
                        "status",
                        "settled_at_ms",
                        "asset",
                        "fee",
                        "receipts",
                        "request_digest",
                        "agent_did",
                    ]);
                }
                None => {
                    v["status"] = json!("pending");
                    v["settled_at_ms"] = Value::Null;
                    v["asset"] = Value::Null;
                    v["fee"] = Value::Null;
                    v["receipts"] = Value::Null;
                }
            }
            match chain.receipt.as_ref().filter(|r| r.success) {
                Some(r) => {
                    v["burned"] = json!(r.supply_change.min(0).unsigned_abs().to_string());
                    v["treasury_leg"] = json!(r.treasury_leg.map(|l| l.to_string()));
                    on_chain.extend(["burned", "treasury_leg"]);
                }
                None => {
                    v["burned"] = Value::Null;
                    v["treasury_leg"] = Value::Null;
                }
            }
        }
        Paid::Channel {
            escrow_id,
            reference,
            cumulative,
            receipt_chain_head,
        } => {
            v["via"] = json!("channel");
            v["escrow_id"] = json!(escrow_id);
            v["channel_reference"] = json!(reference);
            v["voucher_cumulative"] = json!(cumulative.to_string());
            v["receipt_chain_head"] = json!(receipt_chain_head);
            // A channel settles on the ledger when the escrow is claimed,
            // once for every call the claimed voucher covers; the claim's
            // fee is the claim's, not one call's.
            v["settled_at_ms"] = json!(entry.served_at_ms);
            v["fee"] = Value::Null;
            v["burned"] = Value::Null;
            v["treasury_leg"] = Value::Null;
            v["receipts"] = json!([receipt_chain_head]);
            node_local.extend([
                "settled_at_ms",
                "channel_reference",
                "voucher_cumulative",
                "receipt_chain_head",
            ]);
            match &chain.escrow {
                Some(e) => {
                    v["status"] = json!(if e.claimed >= *cumulative {
                        "claimed"
                    } else {
                        "in_channel"
                    });
                    v["escrow_claimed"] = json!(e.claimed.to_string());
                    on_chain.extend(["status", "escrow_claimed"]);
                }
                None => {
                    v["status"] = json!("escrow_not_found");
                }
            }
        }
    }
    v["sources"] = json!({ "node_local": node_local, "chain": on_chain });
    v
}

/// What `tenzro_listPayments` adds to a payment entry: the burn and the
/// treasury leg its transaction declared, from the transaction's receipt,
/// and the work this node recorded for the payment, when it settled one.
pub(crate) fn payment_extras(store: &dyn KvStore, tx_hash: &str, pay_ref: &str) -> (Value, Value) {
    let receipt: Option<crate::event_loop::TxReceiptRecord> = store
        .get(
            CF_TRANSACTIONS,
            format!("receipt:{}", tx_hash.trim_start_matches("0x")).as_bytes(),
        )
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let settlement = receipt.filter(|r| r.success).map_or(Value::Null, |r| {
        json!({
            "burned": r.supply_change.min(0).unsigned_abs().to_string(),
            "treasury_leg": r.treasury_leg.map(|l| l.to_string()),
        })
    });
    let work = by_pay_ref(store, pay_ref)
        .ok()
        .flatten()
        .map_or(Value::Null, |e| {
            json!({
                "work_class": e.work_class,
                "model_id": e.model_id,
                "units": crate::rpc::units_to_json(&e.units),
                "serving_node": e.serving_node,
                "cap_key": e.cap_key,
                "hardware_tier": e.hardware_tier,
                "requested_at_ms": e.requested_at_ms,
                "latency_ms": e.requested_at_ms.map(|r| e.served_at_ms.saturating_sub(r)),
                "cursor": e.seq.to_string(),
                "source": "node_local",
            })
        });
    (settlement, work)
}

fn bad(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: msg.into(),
        data: None,
    }
}

fn address_param(params: &Value, key: &str) -> Result<Option<Address>, JsonRpcError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(|s| Address::from_hex(s).map_err(|e| bad(format!("{key}: {e}"))))
        .transpose()
}

/// `tenzro_listSettlements { cursor?, limit?, work_class?, provider?,
/// payer?, from_ms?, to_ms? }`: the calls this node settled, newest first.
pub(crate) async fn handle_list(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let store = node.storage().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "storage not initialized".into(),
        data: None,
    })?;
    let before = match params.get("cursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(
            s.parse::<u64>()
                .map_err(|_| bad("cursor is a decimal sequence number"))?,
        ),
        Some(v) => Some(
            v.as_u64()
                .ok_or_else(|| bad("cursor is a decimal sequence number"))?,
        ),
    };
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(DEFAULT_PAGE, |l| (l as usize).clamp(1, MAX_PAGE));
    let filter = Filter {
        work_class: params
            .get("work_class")
            .and_then(Value::as_str)
            .map(str::to_string),
        provider: address_param(&params, "provider")?,
        payer: address_param(&params, "payer")?,
        from_ms: params.get("from_ms").and_then(Value::as_u64),
        to_ms: params.get("to_ms").and_then(Value::as_u64),
    };
    let page = page(store.as_ref(), before, limit, &filter).map_err(|e| JsonRpcError {
        code: -32603,
        message: e,
        data: None,
    })?;
    let chain = crate::rpc::chain_state_of(node);
    let settlements: Vec<Value> = page
        .entries
        .iter()
        .map(|e| {
            let held = match &chain {
                Some(c) => on_chain(store.as_ref(), c, e),
                None => OnChain {
                    record: None,
                    receipt: None,
                    escrow: None,
                },
            };
            entry_json(e, &held)
        })
        .collect();
    Ok(json!({
        "settlements": settlements,
        "cursor": page.cursor.map(|c| c.to_string()),
        "recorded": page.total,
        "kept": page.total.min(MAX_ENTRIES),
        "scope": "node_local",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::RocksDbStore;

    fn store() -> (Arc<RocksDbStore>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(RocksDbStore::open_default(dir.path()).unwrap());
        (store, dir)
    }

    fn entry(provider: u8, payer: u8, at: u64, ledger: bool) -> WorkSettlement {
        WorkSettlement {
            seq: 0,
            work_class: "inference_served".into(),
            model_id: "m".into(),
            units: BillableUnits::tokens(3, 4),
            provider: Address::new([provider; 32]),
            serving_node: Some("did:tenzro:machine:x".into()),
            cap_key: None,
            hardware_tier: Some("cpu".into()),
            payer: Some(Address::new([payer; 32])),
            call_attribution: None,
            requested_at_ms: Some(at - 5),
            served_at_ms: at,
            amount: 10,
            paid: if ledger {
                Paid::Ledger {
                    tx_hash: format!("{at:064x}"),
                    pay_ref: format!("{:064x}", at + 1),
                }
            } else {
                Paid::Channel {
                    escrow_id: "00".repeat(32),
                    reference: "r".into(),
                    cumulative: 10,
                    receipt_chain_head: "11".repeat(32),
                }
            },
        }
    }

    /// A served call settled by a real `PayerSettle`: the VM executes it
    /// against chain state, the receipt is kept as block commit keeps it,
    /// and the answer fills every field from that settlement and the work
    /// record.
    #[tokio::test]
    async fn a_settled_inference_answers_with_every_field_from_its_settlement() {
        use tenzro_crypto::composite::testing::TestHybridSigner;
        use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
        use tenzro_types::payment_authorization::{
            PaymentAuthorization, PaymentBinding, TNZO_ASSET, pay_ref,
            payment_authorization_preimage,
        };
        use tenzro_vm::traits::{VmExecutor as _, VmState as _};

        const CHAIN: u64 = 1337;
        let (s, _d) = store();
        let mut state = tenzro_vm::StateAdapter::with_storage(s.clone());
        let payer = TestHybridSigner::hybrid(41);
        let payer_addr = payer.address();
        let payee = Address::new([0x7a; 32]);
        let amount: u128 = 3_000_000_000_000_000_000;
        state.set_balance(payer_addr.as_bytes(), 2 * amount);
        tenzro_vm::account_keys::set_enrolled_pq_key(
            &mut state,
            &payer.public_key().p256,
            payer.public_key().pq.clone().unwrap(),
            &mut Vec::new(),
        );

        let binding = PaymentBinding {
            request_digest: [0x31; 32],
            quote_digest: [0u8; 32],
            usd_e6: 0,
            app_margin: None,
        };
        let id = "call-1";
        let preimage = payment_authorization_preimage(
            CHAIN,
            id,
            &payer_addr,
            &payee,
            amount,
            TNZO_ASSET,
            &binding,
        );
        let authorization = PaymentAuthorization {
            resellers: Vec::new(),
            public_key: payer.public_key().p256.clone(),
            signature: payer
                .sign(SignatureContext::PaymentAuthorization, &preimage)
                .unwrap(),
            max_amount: amount,
            asset: TNZO_ASSET.into(),
            binding,
        };
        let mut data = tenzro_vm::native::SELECTOR_PAYER_SETTLE.to_vec();
        data.extend_from_slice(
            &serde_json::to_vec(&json!({
                "payer": payer_addr, "payee": payee, "amount": amount,
                "payment_id": id, "authorization": authorization,
            }))
            .unwrap(),
        );
        let mut tx = tenzro_vm::VmTransaction::new(
            vec![0x5a; 32],
            None,
            0,
            data,
            1_000_000,
            0,
            0,
            tenzro_vm::VmType::Tenzro,
            CHAIN,
        );
        tx.block_timestamp_ms = Some(1_700_000_000_000);
        let executor =
            tenzro_vm::NativeExecutor::new(tenzro_vm::config::VmConfig::default()).unwrap();
        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();
        assert!(result.success, "{:?}", result.revert_reason);
        state.commit().unwrap();

        let tx_hash = "ab".repeat(32);
        let receipt = crate::event_loop::TxReceiptRecord {
            success: result.success,
            gas_used: result.gas_used,
            cumulative_gas_used: result.gas_used,
            effective_gas_price: 0,
            fee_paid: 0,
            revert_reason: None,
            contract_address: None,
            logs: Vec::new(),
            supply_change: result.supply_change,
            treasury_leg: result.treasury_leg,
        };
        s.put(
            CF_TRANSACTIONS,
            format!("receipt:{tx_hash}").as_bytes(),
            &serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();

        let reference = hex::encode(pay_ref(CHAIN, &payee, &binding, id));
        let seq = append(
            s.as_ref(),
            WorkSettlement {
                seq: 0,
                work_class: "inference_served".into(),
                model_id: "gemma".into(),
                units: BillableUnits::tokens(12, 30),
                provider: payee,
                serving_node: Some("did:tenzro:machine:serving".into()),
                cap_key: Some("cuda-sm90".into()),
                hardware_tier: Some("datacenter_gpu".into()),
                payer: Some(payer_addr),
                call_attribution: None,
                requested_at_ms: Some(1_699_999_999_000),
                served_at_ms: 1_699_999_999_420,
                amount,
                paid: Paid::Ledger {
                    tx_hash: tx_hash.clone(),
                    pay_ref: reference.clone(),
                },
            },
        )
        .unwrap();

        let entry = page(s.as_ref(), None, 1, &Filter::default())
            .unwrap()
            .entries
            .remove(0);
        assert_eq!(entry.seq, seq);
        let held = on_chain(s.as_ref(), &state, &entry);
        let v = entry_json(&entry, &held);
        for field in [
            "cursor",
            "work_class",
            "model_id",
            "units",
            "provider",
            "serving_node",
            "cap_key",
            "hardware_tier",
            "payer",
            "requested_at_ms",
            "latency_ms",
            "amount",
            "via",
            "tx_hash",
            "pay_ref",
            "status",
            "settled_at_ms",
            "fee",
            "burned",
            "treasury_leg",
            "receipts",
            "request_digest",
        ] {
            assert!(!v[field].is_null(), "{field} is not filled: {v}");
        }
        let record = tenzro_vm::native::read_payment(
            &state,
            &<[u8; 32]>::try_from(hex::decode(&reference).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(v["status"], "settled");
        assert_eq!(v["latency_ms"], 420);
        assert_eq!(v["fee"], record.fee.to_string());
        assert!(record.fee > 0);
        assert_eq!(v["settled_at_ms"], record.recorded_at_ms);
        assert_eq!(v["burned"], result.supply_change.unsigned_abs().to_string());
        assert!(result.supply_change < 0);
        assert_eq!(v["treasury_leg"], "0");
        assert_eq!(v["request_digest"], "31".repeat(32));
        assert_eq!(v["units"]["input_tokens"], 12);
        // A ledger settlement carries no payer-signed call chain on chain.
        assert!(v["call_attribution"].is_null());
        let chain: Vec<&str> = v["sources"]["chain"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f.as_str())
            .collect();
        for f in ["fee", "burned", "treasury_leg", "settled_at_ms", "status"] {
            assert!(chain.contains(&f), "{f} not labelled as chain: {chain:?}");
        }
        assert!(
            v["sources"]["node_local"]
                .as_array()
                .unwrap()
                .contains(&json!("latency_ms"))
        );

        let (settlement, work) = payment_extras(s.as_ref(), &tx_hash, &reference);
        assert_eq!(settlement["burned"], v["burned"]);
        assert_eq!(work["model_id"], "gemma");
        assert_eq!(work["source"], "node_local");

        // The provider's statement reads this answer and verifies against
        // what the chain holds: the payment record and the receipt.
        use tenzro_types::statement::{ChainFacts, Line, Period, build, verify};
        let provider = hex_addr(&payee);
        let line = Line::from_settlement(&v).unwrap();
        assert!(line.settled());
        let statement = build(
            &provider,
            1_699_920_000_000,
            1_700_006_400_000,
            Period::Day,
            true,
            vec![line],
        );
        let t = &statement.totals[0].sums;
        assert_eq!(statement.totals[0].asset, "TNZO");
        assert_eq!(t.gross, amount);
        assert_eq!(t.burned, result.supply_change.unsigned_abs());
        assert_eq!(t.treasury_leg, result.treasury_leg.unwrap());
        assert_eq!(t.fee + t.treasury_leg, record.fee);
        assert_eq!(t.net, amount - record.fee);
        assert_eq!(t.gross, t.fee + t.treasury_leg + t.net);
        assert_eq!(statement.periods[0].period, "2023-11-14");
        let facts = std::collections::BTreeMap::from([(
            reference.clone(),
            ChainFacts {
                payee: hex::encode(record.payee.as_bytes()),
                asset: record.asset.clone(),
                amount: record.amount,
                fee: record.fee,
                recorded_at_ms: record.recorded_at_ms,
                receipts: record.receipts.clone(),
                tx_success: receipt.success,
                burned: receipt.supply_change.min(0).unsigned_abs(),
                treasury_leg: receipt.treasury_leg.unwrap_or(0),
            },
        )]);
        assert_eq!(verify(&statement, &facts), Vec::<String>::new());
        let mut short = facts;
        short.get_mut(&reference).unwrap().fee -= 1;
        assert!(!verify(&statement, &short).is_empty());
    }

    /// A call paid on a channel answers with the call chain its voucher
    /// named, and no fee of its own: the escrow claim pays that.
    #[test]
    fn a_channel_call_names_its_call_chain_and_leaves_the_fee_to_the_claim() {
        let mut e = entry(1, 2, 100, false);
        e.call_attribution = Some(CallAttribution {
            app_did: Some("did:tenzro:human:app".into()),
            agent_did: Some("did:tenzro:agent:a".into()),
            tool_did: None,
        });
        let v = entry_json(
            &e,
            &OnChain {
                record: None,
                receipt: None,
                escrow: None,
            },
        );
        assert_eq!(v["via"], "channel");
        assert_eq!(v["call_attribution"]["app_did"], "did:tenzro:human:app");
        assert_eq!(v["call_attribution"]["agent_did"], "did:tenzro:agent:a");
        assert!(v["fee"].is_null() && v["burned"].is_null());
        assert_eq!(v["receipts"], json!(["11".repeat(32)]));
        assert_eq!(v["status"], "escrow_not_found");
    }

    #[test]
    fn an_empty_record_has_an_empty_page() {
        let (s, _d) = store();
        let p = page(s.as_ref(), None, 10, &Filter::default()).unwrap();
        assert_eq!(p, Page::default());
    }

    #[test]
    fn pages_run_newest_first_and_continue_without_a_gap() {
        let (s, _d) = store();
        for i in 0..7 {
            assert_eq!(append(s.as_ref(), entry(1, 2, 100 + i, true)).unwrap(), i);
        }
        let first = page(s.as_ref(), None, 3, &Filter::default()).unwrap();
        let seqs: Vec<u64> = first.entries.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![6, 5, 4]);
        assert_eq!(first.total, 7);
        let mut all = seqs;
        let mut cursor = first.cursor;
        while let Some(c) = cursor {
            let p = page(s.as_ref(), Some(c), 3, &Filter::default()).unwrap();
            all.extend(p.entries.iter().map(|e| e.seq));
            cursor = p.cursor;
        }
        assert_eq!(all, vec![6, 5, 4, 3, 2, 1, 0]);
    }

    #[test]
    fn filters_select_by_provider_payer_class_and_time() {
        let (s, _d) = store();
        append(s.as_ref(), entry(1, 2, 100, true)).unwrap();
        append(s.as_ref(), entry(3, 2, 200, false)).unwrap();
        append(s.as_ref(), entry(1, 4, 300, true)).unwrap();
        let sel = |f: Filter| -> Vec<u64> {
            page(s.as_ref(), None, 10, &f)
                .unwrap()
                .entries
                .iter()
                .map(|e| e.seq)
                .collect()
        };
        assert_eq!(
            sel(Filter {
                provider: Some(Address::new([1; 32])),
                ..Default::default()
            }),
            vec![2, 0]
        );
        assert_eq!(
            sel(Filter {
                payer: Some(Address::new([2; 32])),
                ..Default::default()
            }),
            vec![1, 0]
        );
        assert_eq!(
            sel(Filter {
                from_ms: Some(150),
                to_ms: Some(300),
                ..Default::default()
            }),
            vec![1]
        );
        assert!(
            sel(Filter {
                work_class: Some("tee_session".into()),
                ..Default::default()
            })
            .is_empty()
        );
    }

    #[test]
    fn the_record_keeps_only_the_latest_entries() {
        let (s, _d) = store();
        let mut refs = Vec::new();
        for i in 0..5 {
            let e = entry(1, 2, 100 + i, true);
            if let Paid::Ledger { pay_ref, .. } = &e.paid {
                refs.push(pay_ref.clone());
            }
            append_within(s.as_ref(), e, 3).unwrap();
        }
        let p = page_within(s.as_ref(), None, 10, &Filter::default(), 3).unwrap();
        let seqs: Vec<u64> = p.entries.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![4, 3, 2]);
        assert_eq!(p.cursor, None);
        assert!(read_entry(s.as_ref(), 1).unwrap().is_none());
        assert!(by_pay_ref(s.as_ref(), &refs[1]).unwrap().is_none());
        assert_eq!(by_pay_ref(s.as_ref(), &refs[4]).unwrap().unwrap().seq, 4);
    }

    #[test]
    fn a_provider_window_stops_at_its_start() {
        let (s, _d) = store();
        for (i, p) in [1u8, 3, 1, 1].iter().enumerate() {
            append(s.as_ref(), entry(*p, 2, 100 * (i as u64 + 1), true)).unwrap();
        }
        let (got, complete) = provider_since(s.as_ref(), &Address::new([1; 32]), 250).unwrap();
        assert_eq!(got.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![3, 2]);
        assert!(complete);
        let (all, complete) = provider_since(s.as_ref(), &Address::new([1; 32]), 0).unwrap();
        assert_eq!(all.len(), 3);
        assert!(complete);
    }

    #[test]
    fn a_ledger_entry_is_found_by_its_payment_reference() {
        let (s, _d) = store();
        let e = entry(1, 2, 100, true);
        let Paid::Ledger { pay_ref, .. } = e.paid.clone() else {
            unreachable!()
        };
        append(s.as_ref(), e).unwrap();
        assert_eq!(by_pay_ref(s.as_ref(), &pay_ref).unwrap().unwrap().seq, 0);
        assert!(by_pay_ref(s.as_ref(), "ab").unwrap().is_none());
    }
}
