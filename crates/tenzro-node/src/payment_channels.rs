//! Payment channels over on-chain escrows.
//!
//! A channel is an escrow the payer funded on the Tenzro Ledger with its own
//! signed `CreateEscrow` transaction, naming this node's payee. Payments on the
//! channel are cumulative vouchers the payer signs; this node accepts a
//! voucher only after checking it against the escrow on consensus state, and
//! claims the highest voucher on-chain when the channel closes (or before the
//! escrow expires). The payer can refund whatever was not claimed once the
//! escrow expires, so neither party depends on this node's memory for funds.
//!
//! The same sessions back MPP `session` payments and the x402
//! `batch-settlement` scheme.

use std::sync::Arc;

use serde_json::Value;
use tenzro_payments::gateway::RailOutcome;
use tenzro_types::payment_authorization::EscrowVoucher;
use tenzro_types::primitives::Address;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

fn sessions(
    node: &Arc<TenzroNode>,
) -> Result<&Arc<tenzro_payments::mpp::MppSessionManager>, JsonRpcError> {
    node.payment_sessions().ok_or_else(|| {
        err(
            -32000,
            "this node has no ledger rail, so it cannot hold payment channels",
        )
    })
}

fn payee(node: &Arc<TenzroNode>) -> Result<Address, JsonRpcError> {
    node.operator_payee()
        .ok_or_else(|| err(-32000, "this node has no payee address to be paid at"))
}

fn escrow_id_param(params: &Value) -> Result<[u8; 32], JsonRpcError> {
    let raw = params
        .get("channel_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err(-32602, "Missing channel_id (the escrow id, hex)"))?;
    hex::decode(raw.trim_start_matches("0x"))
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| err(-32602, "channel_id must be a 32-byte hex escrow id"))
}

/// Accept `voucher` as payment of `charge` to `payee`: its signature must
/// verify, and the escrow on the ledger must honour it.
pub(crate) fn pay_with_voucher(
    node: &Arc<TenzroNode>,
    voucher: &EscrowVoucher,
    payee: &Address,
    charge: u128,
) -> Result<String, JsonRpcError> {
    // The session's ledger reader checks the signer against chain state:
    // the payer's keys, or a serving node the agent's terms assign.
    match sessions(node)?
        .accept_voucher(voucher, payee, charge)
        .map_err(|e| err(-32000, e.to_string()))?
    {
        RailOutcome::Settled { reference } => Ok(reference),
        RailOutcome::Pending { reference } | RailOutcome::Failed { reason: reference } => {
            Err(err(-32023, format!("voucher not accepted: {reference}")))
        }
    }
}

/// Decode a voucher from its JSON form.
pub(crate) fn voucher_from(value: &Value) -> Result<EscrowVoucher, JsonRpcError> {
    serde_json::from_value(value.clone()).map_err(|e| err(-32602, format!("invalid voucher: {e}")))
}

/// `tenzro_openPaymentChannel { channel_id }`: open a channel over an escrow
/// the payer already funded on the ledger, paying this node.
pub(crate) async fn open(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| err(-32602, "Missing params"))?;
    let escrow_id = escrow_id_param(&params)?;
    let session = sessions(node)?
        .open_session(&escrow_id, &payee(node)?)
        .map_err(|e| err(-32000, e.to_string()))?;
    Ok(serde_json::to_value(&session).unwrap_or(Value::Null))
}

/// `tenzro_updatePaymentChannel { voucher, charge }`: pay `charge` on a
/// channel with the payer's next cumulative voucher.
pub(crate) async fn update(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| err(-32602, "Missing params"))?;
    let voucher = voucher_from(
        params
            .get("voucher")
            .ok_or_else(|| err(-32602, "Missing voucher"))?,
    )?;
    let charge: u128 = match params.get("charge") {
        Some(Value::String(s)) => s
            .parse()
            .map_err(|_| err(-32602, "charge must be a decimal u128"))?,
        Some(Value::Number(n)) => n
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| err(-32602, "charge must be a non-negative integer"))?,
        _ => return Err(err(-32602, "Missing charge")),
    };
    let reference = pay_with_voucher(node, &voucher, &payee(node)?, charge)?;
    let session = sessions(node)?.get_session(&hex::encode(voucher.escrow_id));
    Ok(serde_json::json!({
        "channel_id": hex::encode(voucher.escrow_id),
        "reference": reference,
        "session": session,
    }))
}

/// `tenzro_closePaymentChannel { channel_id }`, signed by the payer: stop
/// accepting vouchers on a channel. The highest voucher is claimed on-chain by the node's claimer;
/// the channel reports `closed` only once that claim has executed.
pub(crate) async fn close(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| err(-32602, "Missing params"))?;
    let escrow_id = escrow_id_param(&params)?;
    let id = hex::encode(escrow_id);
    let mgr = sessions(node)?;
    let session = mgr
        .get_session(&id)
        .ok_or_else(|| err(-32004, format!("no channel {id}")))?;
    // The payer ends its own channel; nobody else may cut it off.
    crate::payment_rpc::require_signed_owner_request(
        node,
        &params,
        &session.payer,
        "tenzro_closePaymentChannel",
        &escrow_id,
    )?;
    let due = mgr
        .close_session(&id)
        .map_err(|e| err(-32000, e.to_string()))?;
    let state = mgr
        .get_session(&id)
        .map(|s| s.state)
        .unwrap_or(session.state);
    Ok(serde_json::json!({
        "channel_id": id,
        "status": match state {
            tenzro_payments::mpp::MppSessionState::Open => "open",
            tenzro_payments::mpp::MppSessionState::Closing => "closing",
            tenzro_payments::mpp::MppSessionState::Closed => "closed",
        },
        "claim_due": due.map(|c| c.amount.to_string()),
    }))
}

/// `tenzro_agentVoucher { channel_id, cumulative_amount }`: a delegated
/// agent's next cumulative voucher on a channel its wallet funded, signed by
/// this serving node with its TPM key for the agent. The node signs only a
/// voucher the ledger would honour now: this machine assigned in the agent's
/// current terms, the agent neither revoked nor quarantined, the amount
/// within the lock the terms already counted when the channel opened.
pub(crate) async fn agent_voucher(
    node: &Arc<TenzroNode>,
    caller: Option<&str>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_types::payment_authorization::{AgentVoucherSigner, agent_voucher_digest};
    let agent_did = crate::agent_delegation::acting_agent(caller)?;
    let params = crate::rpc::unwrap_param_object(params);
    let escrow_id = escrow_id_param(&params)?;
    let cumulative: u128 = params
        .get("cumulative_amount")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| err(-32602, "cumulative_amount must be a decimal u128 string"))?;
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    let chain_id = node
        .payment_gateway()
        .map(|g| g.chain_id())
        .ok_or_else(|| err(-32603, "Payment gateway not initialized"))?;
    let (_, _, machine_did) =
        crate::agent_delegation::this_machine().map_err(|e| err(-32603, e))?;
    let now = crate::calendar::now_ms();
    let signer = AgentVoucherSigner {
        agent_did: agent_did.clone(),
        machine_did: machine_did.clone(),
        as_of_ms: now,
    };
    let digest = agent_voucher_digest(chain_id, &escrow_id, cumulative, &[0u8; 32], &signer);
    let label = crate::agent_delegation::key_label(&agent_did, &machine_did);
    let signature = tokio::task::spawn_blocking(move || {
        tenzro_device_key::signer::open_or_create(&label)
            .and_then(|k| k.sign_prehash(&digest))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| err(-32603, e.to_string()))?
    .map_err(|e| err(-32603, format!("agent key: {e}")))?;
    // The ML-DSA-65 signature rides beside the P-256 one when the agent's
    // wallet requires that leg.
    let pq = crate::agent_delegation::agent_pq_leg(&chain, &agent_did, &machine_did, digest)
        .await
        .map_err(|e| err(-32603, format!("agent ML-DSA key: {e}")))?;
    let mut voucher_signature = tenzro_crypto::composite::CompositeSignature::classical(
        tenzro_crypto::composite::ClassicalProof::Raw {
            signature: signature.to_vec(),
        },
    );
    voucher_signature.pq = pq;
    let voucher = EscrowVoucher {
        binding: [0u8; 32],
        escrow_id,
        cumulative_amount: cumulative,
        public_key: Vec::new(),
        signature: voucher_signature,
        agent: Some(signer),
        attribution: None,
    };
    let payout = tenzro_vm::native::check_escrow_voucher(&chain, chain_id, now as i64, &voucher)
        .map_err(|e| {
            err(
                -32001,
                format!("the ledger would not honour this voucher: {e}"),
            )
        })?;
    Ok(serde_json::json!({
        "voucher": voucher,
        "payout": payout.to_string(),
    }))
}

/// `tenzro_getPayeeSplit { payee }`: the standing split rule every payment
/// `payee` receives is divided by, from consensus state; null when it set
/// none.
pub(crate) async fn get_payee_split(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    let payee = params
        .get("payee")
        .and_then(Value::as_str)
        .and_then(|p| hex::decode(p.trim_start_matches("0x")).ok())
        .filter(|b| b.len() == 32)
        .ok_or_else(|| err(-32602, "payee must be a 32-byte hex address"))?;
    let rule = tenzro_vm::native::read_split(&chain, &payee);
    Ok(serde_json::json!({ "rule": rule }))
}

/// `tenzro_getPayment { pay_ref | payment_id, exact? }`: one payment's consensus
/// record (native, proven or attested), with the request, quote, USD price
/// and delivery receipts it binds.
pub(crate) async fn get_payment(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    let record = if let Some(r) = params.get("pay_ref").and_then(Value::as_str) {
        let pay_ref: [u8; 32] = hex::decode(r.trim_start_matches("0x"))
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| err(-32602, "pay_ref must be 32 bytes of hex"))?;
        tenzro_vm::native::read_payment(&chain, &pay_ref)
    } else if let Some(id) = params.get("payment_id").and_then(Value::as_str) {
        tenzro_vm::native::read_payment_by_id(&chain, id)
    } else {
        return Err(err(-32602, "pay_ref or payment_id is required"));
    };
    // With `exact`, every amount is a decimal string.
    let exact = params
        .get("exact")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(record
        .map(|r| {
            if exact {
                r.exact_json()
            } else {
                serde_json::to_value(r).unwrap_or(Value::Null)
            }
        })
        .unwrap_or(Value::Null))
}

/// `tenzro_listPayments { payee?, payer?, agent_did?, class?, asset?,
/// leg_account?, exact?, from_cursor?, from_height?, to_cursor?, limit?,
/// proofs?, anchor_index? }`: with `leg_account`, only payments one of whose
/// legs pays that account (an operator, reseller or platform); with
/// `exact`, every amount of each record as a decimal string.
/// consensus payment records in chain order, read from the event index
/// (each record's `PaymentRecorded` log). Every entry carries its event
/// cursor; with `proofs`, also the event's proof. Each entry also carries
/// `settlement`, the burn and treasury leg its transaction declared, and
/// `work`, the call this node recorded for the payment (node-local), each
/// null when unknown. Pass the returned `cursor` back as `from_cursor` to
/// continue with no gap.
pub(crate) async fn list_payments(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_types::chain_event::ChainEventKind;
    use tenzro_types::settlement::{PaymentRecord, RecordClass};

    let params = crate::rpc::unwrap_param_object(params);
    if params.get("filter").is_some_and(|f| !f.is_null()) {
        return Err(err(
            -32602,
            "listPayments selects payment events itself; filter with payee, payer, agent_did, class, asset or leg_account",
        ));
    }
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    let payee = match params.get("payee").and_then(Value::as_str) {
        Some(p) => Some(Address::from_hex(p).map_err(|e| err(-32602, format!("payee: {e}")))?),
        None => None,
    };
    let norm = |s: &str| s.trim_start_matches("0x").to_ascii_lowercase();
    let payer = params.get("payer").and_then(Value::as_str).map(norm);
    let agent_did = params
        .get("agent_did")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let asset = params
        .get("asset")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let leg_account = params.get("leg_account").and_then(Value::as_str).map(norm);
    let exact = params
        .get("exact")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let class: Option<RecordClass> = match params.get("class") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            serde_json::from_value(v.clone())
                .map_err(|_| err(-32602, "class is native, proven or attested"))?,
        ),
    };
    let proofs = params
        .get("proofs")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let anchor = crate::event_index::anchor_param(&params)?;
    let mut req = crate::event_index::ReadRequest::parse(&params, None)?;
    req.filter =
        tenzro_events::EventFilter::new().with_event_types(vec![tenzro_events::EventType::Log]);

    let record_of = |e: &tenzro_types::chain_event::ChainEvent| -> Option<PaymentRecord> {
        let ChainEventKind::Log {
            address,
            topics,
            data,
        } = &e.kind
        else {
            return None;
        };
        let emitter = if address.len() == 32 {
            &address[12..]
        } else {
            &address[..]
        };
        if emitter != tenzro_vm::native::SYSTEM_ADDRESS.as_slice()
            || topics.first().map(Vec::as_slice) != Some(tenzro_vm::native::PAYMENT_RECORDED_TOPIC)
            || data.len() != 33
        {
            return None;
        }
        let pay_ref: [u8; 32] = data[..32].try_into().ok()?;
        tenzro_vm::native::read_payment(&chain, &pay_ref)
    };
    let selected = |r: &PaymentRecord| {
        payee.as_ref().is_none_or(|p| &r.payee == p)
            && payer.as_ref().is_none_or(|p| &norm(&r.payer) == p)
            && agent_did
                .as_ref()
                .is_none_or(|d| r.agent_did.as_ref() == Some(d))
            && asset.as_ref().is_none_or(|a| &r.asset == a)
            && class.is_none_or(|c| r.class == c)
            && leg_account
                .as_ref()
                .is_none_or(|a| r.settled.legs.iter().any(|l| &norm(&l.account) == a))
    };
    let page =
        crate::event_index::read_where(node, &req, &|e| record_of(e).is_some_and(|r| selected(&r)))
            .await?;
    let proofs = if proofs {
        Some(crate::event_index::prove(node, &page.events, anchor).await?)
    } else {
        None
    };
    let payments: Vec<Value> = page
        .events
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            let record = record_of(e)?;
            let shown = if exact {
                record.exact_json()
            } else {
                serde_json::to_value(&record).unwrap_or(Value::Null)
            };
            let mut entry = serde_json::json!({ "cursor": e.cursor.to_string(), "tx_hash": e.tx_hash, "record": shown });
            if let Some(store) = node.storage() {
                let (settlement, work) = crate::work_settlements::payment_extras(
                    store.as_ref(),
                    &e.tx_hash.to_string(),
                    &record.pay_ref,
                );
                entry["settlement"] = settlement;
                entry["work"] = work;
            }
            if let Some(p) = proofs.as_ref().and_then(|p| p.get(i)) {
                entry["proof"] = serde_json::to_value(p).unwrap_or(Value::Null);
            }
            Some(entry)
        })
        .collect();
    Ok(serde_json::json!({ "payments": payments, "cursor": page.cursor.map(|c| c.to_string()) }))
}

/// `tenzro_quotePayment { usd_e6 | price: {amount, unit}, accept?,
/// resellers? }`: what a price costs in each accepted asset (TNZO when none
/// is named), with the settlement fee each pays in kind, or a coded reason
/// it cannot settle in it now. With resellers, each answer discloses the
/// operator's price and every commission on top of it separately.
pub(crate) async fn quote_payment(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    let usd_e6 = match (params.get("usd_e6"), params.get("price")) {
        (Some(u), None) => u
            .as_u64()
            .filter(|u| *u > 0)
            .ok_or_else(|| err(-32602, "usd_e6 must be a positive integer"))?,
        (None, Some(p)) => {
            let unit = p.get("unit").and_then(Value::as_str).unwrap_or("");
            let unit_of_account = tenzro_vm::native::settlement_asset::unit_of_account();
            if unit != unit_of_account.basket {
                return Err(err(
                    -32602,
                    format!("price.unit must be {}", unit_of_account.basket),
                ));
            }
            let amount = p
                .get("amount")
                .and_then(Value::as_str)
                .ok_or_else(|| err(-32602, "price.amount is a decimal string"))?;
            tenzro_types::settlement_asset::parse_price_e6(amount).map_err(|e| err(-32602, &e))?
        }
        _ => return Err(err(-32602, "give usd_e6 or price, not both")),
    };
    let accept: Vec<String> = match params.get("accept") {
        None | Some(Value::Null) => vec!["TNZO".to_string()],
        Some(Value::Array(a)) if !a.is_empty() && a.len() <= 16 => a
            .iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<_>>()
            .ok_or_else(|| err(-32602, "accept lists asset strings"))?,
        Some(_) => return Err(err(-32602, "accept lists 1 to 16 assets")),
    };
    let resellers: Vec<tenzro_types::payment_authorization::ResellerLeg> =
        match params.get("resellers") {
            None | Some(Value::Null) => Vec::new(),
            Some(v) => serde_json::from_value(v.clone())
                .map_err(|e| err(-32602, format!("resellers: {e}")))?,
        };
    let assets: Vec<Value> = accept
        .iter()
        .map(|asset| {
            match tenzro_vm::native::settlement_asset::quote_asset_resold(
                &chain, asset, usd_e6, &resellers,
            ) {
                Ok(q) => serde_json::to_value(q).unwrap_or(Value::Null),
                Err(r) => serde_json::json!({ "asset": asset, "error": r }),
            }
        })
        .collect();
    let rate = tenzro_vm::native::read_fee_rate(&chain);
    Ok(serde_json::json!({
        "usd_e6": usd_e6,
        "unit": tenzro_vm::native::settlement_asset::unit_of_account(),
        "rate_epoch": rate.epoch,
        "assets": assets,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_channel_id_is_a_32_byte_hex_escrow_id() {
        let id = hex::encode([7u8; 32]);
        assert_eq!(
            escrow_id_param(&json!({"channel_id": id})).unwrap(),
            [7u8; 32]
        );
        assert_eq!(
            escrow_id_param(&json!({"channel_id": format!("0x{id}")})).unwrap(),
            [7u8; 32]
        );
        for bad in [
            json!({}),
            json!({"channel_id": 5}),
            json!({"channel_id": "abcd"}),
            json!({"channel_id": hex::encode([7u8; 33])}),
            json!({"channel_id": "zz".repeat(32)}),
        ] {
            assert_eq!(escrow_id_param(&bad).unwrap_err().code, -32602, "{bad}");
        }
    }

    #[test]
    fn a_malformed_voucher_is_refused() {
        for bad in [
            json!(null),
            json!({}),
            json!({"escrow_id": "x"}),
            json!("v"),
        ] {
            let e = voucher_from(&bad).unwrap_err();
            assert_eq!(e.code, -32602);
            assert!(e.message.starts_with("invalid voucher"), "{}", e.message);
        }
    }

    #[tokio::test]
    async fn a_node_without_a_ledger_rail_holds_no_payment_channels() {
        let (node, _tmp) = crate::bare_node().await;
        let id = hex::encode([7u8; 32]);
        let e = open(&node, Some(json!({"channel_id": id})))
            .await
            .unwrap_err();
        assert_eq!(e.code, -32000);
        assert!(e.message.contains("no ledger rail"), "{}", e.message);
        let e = close(&node, Some(json!({"channel_id": id})))
            .await
            .unwrap_err();
        assert_eq!(e.code, -32000);
    }

    #[tokio::test]
    async fn opening_and_closing_need_params_and_a_valid_channel_id() {
        let (node, _tmp) = crate::bare_node().await;
        assert_eq!(open(&node, None).await.unwrap_err().code, -32602);
        assert_eq!(close(&node, None).await.unwrap_err().code, -32602);
        let bad = Some(json!({"channel_id": "abcd"}));
        assert_eq!(open(&node, bad.clone()).await.unwrap_err().code, -32602);
        assert_eq!(close(&node, bad).await.unwrap_err().code, -32602);
    }

    #[tokio::test]
    async fn an_update_needs_a_voucher_and_a_charge() {
        let (node, _tmp) = crate::bare_node().await;
        assert_eq!(update(&node, None).await.unwrap_err().code, -32602);
        let e = update(&node, Some(json!({"charge": "1"})))
            .await
            .unwrap_err();
        assert_eq!((e.code, e.message.as_str()), (-32602, "Missing voucher"));
        let e = update(
            &node,
            Some(json!({"voucher": {"bogus": true}, "charge": "1"})),
        )
        .await
        .unwrap_err();
        assert!(e.message.starts_with("invalid voucher"), "{}", e.message);
    }

    #[tokio::test]
    async fn an_agent_voucher_needs_the_agents_token_and_a_channel_and_an_amount() {
        let (node, _tmp) = crate::bare_node().await;
        let id = hex::encode([7u8; 32]);
        let e = agent_voucher(
            &node,
            None,
            Some(json!({"channel_id": id, "cumulative_amount": "5"})),
        )
        .await
        .unwrap_err();
        assert!(e.message.contains("access token"), "{}", e.message);
        let agent = Some("did:tenzro:agent:a");
        let e = agent_voucher(&node, agent, Some(json!({"cumulative_amount": "5"})))
            .await
            .unwrap_err();
        assert_eq!(e.code, -32602);
        for amount in [json!(null), json!("five"), json!(5)] {
            let e = agent_voucher(
                &node,
                agent,
                Some(json!({"channel_id": id, "cumulative_amount": amount})),
            )
            .await
            .unwrap_err();
            assert!(e.message.contains("cumulative_amount"), "{}", e.message);
        }
        let e = agent_voucher(
            &node,
            agent,
            Some(json!({"channel_id": id, "cumulative_amount": "5"})),
        )
        .await
        .unwrap_err();
        assert_eq!(
            e.code, -32603,
            "no chain state on a node that is not running"
        );
    }

    #[tokio::test]
    async fn the_payment_reads_refuse_malformed_input_and_a_node_with_no_chain_state() {
        let (node, _tmp) = crate::bare_node().await;
        let e = get_payee_split(&node, Some(json!({"payee": "ab"})))
            .await
            .unwrap_err();
        assert_eq!(e.code, -32603);
        let e = get_payment(&node, Some(json!({"pay_ref": "ab"})))
            .await
            .unwrap_err();
        assert_eq!(e.code, -32603);
        let e = list_payments(&node, None).await.unwrap_err();
        assert_eq!(e.code, -32603);
        let e = quote_payment(&node, Some(json!({"usd_e6": 5})))
            .await
            .unwrap_err();
        assert_eq!(e.code, -32603);
    }
}
