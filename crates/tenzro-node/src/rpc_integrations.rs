//! RPC handlers for ERC-8004 and other protocol integrations.
//!
//! This module centralizes JSON-RPC handlers for cross-cutting
//! integrations that layer on top of the core chain RPC surface:
//!
//! - **ERC-8004 (Trustless Agents Registry)** — build calldata for the
//!   IdentityRegistry, ReputationRegistry, and ValidationRegistry
//!   contracts, plus derive canonical `agentId` from a DID.
//! - **Bridge fees** — quote and sponsor bridge fees in TNZO.
//!
//! The handlers do not sign anything — clients are expected to
//! produce Ed25519 signatures locally using their wallet. This keeps
//! the node stateless with respect to user keys and matches the
//! TDIP "the principal signs" contract.
//!
//! Dispatched from `rpc.rs::handle_request` via explicit match arms.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

// ============================================================
// ERC-8004 — Trustless Agents Registry
// ============================================================

// ----- ERC-8004 (Jan 2026 revision) identity mutators -------------------------------

// ----- ERC-8004 (Jan 2026 revision) identity reads ----------------------------------

// ----- ERC-8004 (Jan 2026 revision) reputation mutators -----------------------------

// ----- ERC-8004 (Jan 2026 revision) reputation reads --------------------------------

// ----- ERC-8004 reads previously implemented but unexposed -----------

// ============================================================
// Prices
// ============================================================

// ============================================================
// EIP-7702 — EOA Code Delegation (stateless helpers)
// ============================================================

/// `tenzro_get7702Delegation` — the EIP-7702 delegation an EVM authority
/// has installed, read from the designator a type-4 transaction wrote into
/// its code. Returns `{ delegated: false }` when its code holds none.
/// Params: `{ "authority": "0x..." }`.
pub(crate) async fn handle_get_7702_delegation(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    use tenzro_vm::traits::VmState;

    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let authority_hex = params
        .get("authority")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing authority"))?;
    let authority = parse_eth_addr(authority_hex)?;
    if authority.len() != 20 {
        return Err(invalid_params("authority must be 20 bytes"));
    }
    let state = crate::rpc::chain_state(node)?;
    let code = state.get_code(&authority).unwrap_or_default();
    match tenzro_vm::eip7702::extract_delegation_target(&code) {
        Some(target) => Ok(json!({
            "delegated": true,
            "authority": format!("0x{}", hex::encode(authority)),
            "target": format!("0x{}", hex::encode(target)),
            "designator": format!("0x{}", hex::encode(&code)),
        })),
        None => Ok(json!({
            "delegated": false,
            "authority": format!("0x{}", hex::encode(authority)),
        })),
    }
}

fn parse_uint256_param(params: &Value, key: &str) -> std::result::Result<[u8; 32], JsonRpcError> {
    let raw = params
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing(&format!("Missing {key}")))?;
    let stripped = raw.trim_start_matches("0x");
    let decoded =
        hex::decode(stripped).map_err(|e| invalid_params(format!("{key}: invalid hex: {e}")))?;
    if decoded.len() != 32 {
        return Err(invalid_params(format!("{key} must be 32 bytes")));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn parse_eth_address_to_tenzro(
    params: &Value,
    key: &str,
) -> std::result::Result<tenzro_types::primitives::Address, JsonRpcError> {
    let raw = parse_eth_addr(
        params
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing(&format!("Missing {key}")))?,
    )?;
    if raw.len() != 20 {
        return Err(invalid_params(format!("{key} must be 20 bytes")));
    }
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(&raw);
    Ok(tenzro_types::primitives::Address::new(padded))
}

fn parse_permit_transfer(
    params: &Value,
) -> std::result::Result<tenzro_vm::permit2::PermitTransferFrom, JsonRpcError> {
    let token = parse_eth_address_to_tenzro(params, "token")?;
    let amount = parse_uint256_param(params, "amount")?;
    let spender = parse_eth_address_to_tenzro(params, "spender")?;
    let nonce = parse_uint256_param(params, "nonce")?;
    let deadline = params
        .get("deadline")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| missing("Missing deadline"))?;
    Ok(tenzro_vm::permit2::PermitTransferFrom {
        permitted: tenzro_vm::permit2::TokenPermissions { token, amount },
        spender,
        nonce,
        deadline,
    })
}

/// `tenzro_permit2VerifyAndConsume` — verify the signature, check
/// expiry, mark the nonce used, and return the recovered signer. This
/// is the trust-minimized read-side surface that relayers and settlers
/// call before pulling tokens on the EVM side.
///
/// Params: the permit (`token`, `amount`, `spender`, `nonce`, `deadline`,
/// optional `witness`, `witness_type_name` and `witness_type_string`) plus
/// `{ signature, owner, requested_amount? }`. `requested_amount`
/// defaults to the permitted amount.
pub(crate) async fn handle_permit2_verify_and_consume(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let chain_id = node.config().chain_id();
    let verifying = tenzro_types::primitives::Address::new({
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(&tenzro_vm::permit2::TENZRO_PERMIT2_ADDRESS);
        out
    });
    let ds = tenzro_vm::permit2::domain_separator(chain_id, &verifying);

    let base = parse_permit_transfer(&params)?;
    let owner_addr = parse_eth_addr(
        params
            .get("owner")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing owner"))?,
    )?;
    if owner_addr.len() != 20 {
        return Err(invalid_params("owner must be 20 bytes"));
    }
    let mut owner = [0u8; 20];
    owner.copy_from_slice(&owner_addr);

    let signature_hex = params
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing signature"))?;
    let signature = hex::decode(signature_hex.trim_start_matches("0x"))
        .map_err(|e| invalid_params(format!("signature hex: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if base.deadline < now {
        return Err(invalid_params(format!(
            "permit expired (deadline {}, now {})",
            base.deadline, now
        )));
    }

    let digest = if let (Some(witness_hex), Some(name), Some(typestr)) = (
        params.get("witness").and_then(|v| v.as_str()),
        params.get("witness_type_name").and_then(|v| v.as_str()),
        params.get("witness_type_string").and_then(|v| v.as_str()),
    ) {
        let witness_bytes = hex::decode(witness_hex.trim_start_matches("0x"))
            .map_err(|e| invalid_params(format!("witness hex: {e}")))?;
        if witness_bytes.len() != 32 {
            return Err(invalid_params("witness must be 32 bytes"));
        }
        let mut witness = [0u8; 32];
        witness.copy_from_slice(&witness_bytes);
        let permit = tenzro_vm::permit2::PermitTransferFromWitness {
            permitted: base.permitted.clone(),
            spender: base.spender,
            nonce: base.nonce,
            deadline: base.deadline,
            witness,
            witness_type_name: name.to_string(),
            witness_type_string: typestr.to_string(),
        };
        permit.digest(&ds)
    } else {
        base.digest(&ds)
    };

    let recovered = tenzro_vm::permit2::recover_signer(&digest, &signature)
        .map_err(|e| invalid_params(format!("recover: {e}")))?;
    if recovered != owner {
        return Err(invalid_params(format!(
            "signer {} does not match owner {}",
            hex::encode(recovered),
            hex::encode(owner)
        )));
    }

    let bitmap = node.permit2_nonce_bitmap();
    bitmap
        .check_and_use(&owner, &base.nonce)
        .map_err(|e| invalid_params(format!("nonce: {e}")))?;

    Ok(json!({
        "verified": true,
        "consumed": true,
        "owner": format!("0x{}", hex::encode(owner)),
        "spender": format!("0x{}", hex::encode(&base.spender.as_bytes()[12..])),
        "token": format!("0x{}", hex::encode(&base.permitted.token.as_bytes()[12..])),
        "amount": format!("0x{}", hex::encode(base.permitted.amount)),
        "nonce": format!("0x{}", hex::encode(base.nonce)),
        "deadline": base.deadline,
        "digest": format!("0x{}", hex::encode(digest)),
    }))
}

/// `tenzro_permit2NonceUsed` — query whether an `(owner, nonce)` pair
/// has been spent. Params: `{ owner, nonce }`.
pub(crate) async fn handle_permit2_nonce_used(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let owner_raw = parse_eth_addr(
        params
            .get("owner")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing owner"))?,
    )?;
    if owner_raw.len() != 20 {
        return Err(invalid_params("owner must be 20 bytes"));
    }
    let mut owner = [0u8; 20];
    owner.copy_from_slice(&owner_raw);
    let nonce = parse_uint256_param(&params, "nonce")?;
    let bitmap = node.permit2_nonce_bitmap();
    Ok(json!({
        "owner": format!("0x{}", hex::encode(owner)),
        "nonce": format!("0x{}", hex::encode(nonce)),
        "used": bitmap.is_used(&owner, &nonce),
    }))
}

// ============================================================
// Helpers
// ============================================================

fn missing(msg: &str) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: msg.to_string(),
        data: None,
    }
}

fn invalid_params(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: msg.into(),
        data: None,
    }
}

fn unwrap_arr(params: Value) -> Value {
    if let Some(arr) = params.as_array() {
        arr.first().cloned().unwrap_or(params)
    } else {
        params
    }
}

fn parse_eth_addr(s: &str) -> std::result::Result<[u8; 20], JsonRpcError> {
    let hex_str = s.trim_start_matches("0x");
    let bytes =
        hex::decode(hex_str).map_err(|e| invalid_params(format!("invalid address hex: {e}")))?;
    if bytes.len() != 20 {
        return Err(invalid_params(format!(
            "address must be 20 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// =============================================================================
// Wire protocol-primitive features as live RPC handlers
//
// Handlers over library modules (ERC-7943 uRWA, IVMS101 Travel Rule, A2A
// v1.0 SignedAgentCard) for the SDKs, CLI, MCP tools and external
// integrators.
// =============================================================================

/// A 32-byte token id from a hex parameter.
fn urwa_token(value: &str) -> std::result::Result<[u8; 32], JsonRpcError> {
    hex::decode(value.trim_start_matches("0x"))
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "token_id_hex must be 32 bytes of hex".to_string(),
            data: None,
        })
}

/// An account parameter as the ledger account token balances are keyed by.
fn urwa_account(field: &str, value: &str) -> std::result::Result<Vec<u8>, JsonRpcError> {
    hex::decode(value.trim_start_matches("0x"))
        .ok()
        .filter(|b| b.len() == 20 || b.len() == 32)
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: format!("{field} must be a 20- or 32-byte hex account"),
            data: None,
        })
}

fn urwa_state(node: &TenzroNode) -> std::result::Result<tenzro_vm::StateAdapter, JsonRpcError> {
    let storage: Arc<dyn tenzro_storage::KvStore> =
        node.storage().cloned().ok_or_else(|| JsonRpcError {
            code: -32603,
            message: "Storage not initialized".to_string(),
            data: None,
        })?;
    Ok(tenzro_vm::StateAdapter::with_storage(storage))
}

/// `tenzro_urwaIsKillSwitched { token_id_hex }` — whether the token's issuer
/// has halted holder transfers (ERC-7943), read from chain state. The issuer
/// halts and resumes them with a signed `Token` transaction.
pub(crate) async fn handle_urwa_is_kill_switched(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let p = params.unwrap_or(Value::Null);
    let p = p.as_array().and_then(|a| a.first()).cloned().unwrap_or(p);
    let token_id = urwa_token(
        p.get("token_id_hex")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let active = tenzro_vm::token_ledger::halted(&urwa_state(node)?, &token_id);
    Ok(json!({
        "token_id_hex": format!("0x{}", hex::encode(token_id)),
        "active": active,
    }))
}

/// `tenzro_urwaGetFrozenTokens { token_id_hex, account_hex }` — the part of
/// an account's balance the token's issuer froze (ERC-7943), read from chain
/// state. The issuer sets it with a signed `Token` transaction.
pub(crate) async fn handle_urwa_get_frozen_tokens(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let p = params.unwrap_or(Value::Null);
    let p = p.as_array().and_then(|a| a.first()).cloned().unwrap_or(p);
    let token_id = urwa_token(
        p.get("token_id_hex")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let account = urwa_account(
        "account_hex",
        p.get("account_hex")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let frozen = tenzro_vm::token_ledger::frozen(&urwa_state(node)?, &token_id, &account);
    Ok(json!({
        "frozen_amount": frozen.to_string(),
        "token_id_hex": format!("0x{}", hex::encode(token_id)),
        "account_hex": format!("0x{}", hex::encode(&account)),
    }))
}

/// `tenzro_quoteBridgeFeeInTnzo`: the TNZO that pays a destination-native
/// bridge fee at the USD rates validators committed on chain. Read-only;
/// refused while validators have not priced the destination's native asset.
pub(crate) async fn handle_quote_bridge_fee_in_tnzo(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    #[derive(serde::Deserialize)]
    struct Req {
        adapter: String,
        dest_chain: String,
        native_fee_smallest_unit: String,
    }
    let bad = |message: String| JsonRpcError {
        code: -32602,
        message,
        data: None,
    };
    let params = match params.unwrap_or(Value::Null) {
        Value::Array(mut a) if a.len() == 1 => a.remove(0),
        other => other,
    };
    let req: Req =
        serde_json::from_value(params).map_err(|e| bad(format!("invalid params: {e}")))?;
    let adapter =
        tenzro_bridge::route::BridgeRouteAdapter::parse(&req.adapter).ok_or_else(|| {
            bad(format!(
                "unknown route transport: {} ({})",
                req.adapter,
                tenzro_bridge::route::BridgeRouteAdapter::names()
            ))
        })?;
    let native_fee: u128 = req
        .native_fee_smallest_unit
        .parse()
        .map_err(|e| bad(format!("native_fee_smallest_unit not a valid u128: {e}")))?;
    let network =
        tenzro_types::settlement_network::network_by_caip2(&req.dest_chain, node.chain_id())
            .ok_or_else(|| bad(format!("unknown destination chain {}", req.dest_chain)))?;
    let state = crate::rpc::chain_state(node)?;
    let quote = bridge_fee_quote(
        &state,
        adapter,
        &req.dest_chain,
        &network,
        native_fee,
        now_ms_u64(),
    )
    .map_err(|message| JsonRpcError {
        code: -32004,
        message,
        data: None,
    })?;
    serde_json::to_value(&quote).map_err(|e| JsonRpcError {
        code: -32603,
        message: e.to_string(),
        data: None,
    })
}

fn now_ms_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The quote for `native_fee` on `network` at the rates committed in `state`.
pub(crate) fn bridge_fee_quote(
    state: &dyn tenzro_vm::VmState,
    adapter: tenzro_bridge::route::BridgeRouteAdapter,
    dest_chain: &str,
    network: &tenzro_types::settlement_network::SettlementNetwork,
    native_fee: u128,
    now_ms: u64,
) -> std::result::Result<tenzro_bridge::BridgeFeeQuote, String> {
    use tenzro_vm::native::economy;
    let symbol = network.native_asset;
    let (native_rate, rate_epoch) = economy::read_symbol_rate(state, symbol)
        .ok_or_else(|| format!("validators have not priced {symbol}"))?;
    let tnzo_rate = economy::read_fee_rate(state).rate_nano_usd;
    let tnzo = economy::amount_in_tnzo(state, symbol, network.native_decimals, native_fee)
        .ok_or_else(|| format!("{native_fee} {symbol} base units do not convert"))?;
    Ok(tenzro_bridge::BridgeFeeQuote::new(
        adapter,
        dest_chain,
        symbol,
        native_fee,
        tnzo,
        native_rate,
        tnzo_rate,
        rate_epoch,
        now_ms,
    ))
}

// ===========================================================================
// Decentralized MoE serving — shard view + dispatch planner over the
// existing ProviderManager. The compute providers serving expert shards are
// the same set the provider manager already tracks; MoE-specific
// state rides on ProviderCapacity.moe_holdings / moe_roles / iroh_endpoint_id.
// ===========================================================================

/// `tenzro_moeShardMap` — list every expert holder for `model_id` plus
/// replication factor + under-replicated experts + role counts.
pub(crate) async fn handle_moe_shard_map(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let model_id = params
        .as_ref()
        .and_then(|v| v.get("model_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing model_id".into(),
            data: None,
        })?;
    let manager = node.provider_manager().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "Provider manager not initialized".into(),
        data: None,
    })?;
    let providers = manager.list_providers();
    let view = tenzro_model::MoeShardView::build(model_id, providers.iter());
    let policy = tenzro_model::ReplicationPolicy::default();

    let mut holders_by_expert: Vec<Value> = view
        .covered_experts()
        .into_iter()
        .map(|eid| {
            let holders = view.holders(eid);
            json!({
                "layer": eid.layer,
                "expert": eid.expert,
                "replication": holders.len(),
                "holders": holders.iter().map(|h| json!({
                    "provider": hex::encode(h.provider.0),
                    "residency": format!("{:?}", h.residency),
                    "committed_tps": h.committed_tps,
                    "iroh_endpoint_id": h.iroh_endpoint_id,
                    "blob_uri": h.blob_uri,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    holders_by_expert.sort_by_key(|v| {
        (
            v["layer"].as_u64().unwrap_or(0),
            v["expert"].as_u64().unwrap_or(0),
        )
    });

    let under_replicated: Vec<Value> = view
        .under_replicated(policy)
        .into_iter()
        .map(|eid| json!({ "layer": eid.layer, "expert": eid.expert }))
        .collect();
    let hot_experts: Vec<Value> = view
        .hot_experts(policy)
        .into_iter()
        .map(|eid| json!({ "layer": eid.layer, "expert": eid.expert }))
        .collect();

    Ok(json!({
        "model_id": model_id,
        "covered_experts": holders_by_expert.len(),
        "distinct_providers": view.distinct_providers().len(),
        "expert_holders_role_count": view.providers_for_role(tenzro_types::model::MoeProviderRole::ExpertHolder),
        "router_role_count": view.providers_for_role(tenzro_types::model::MoeProviderRole::Router),
        "prefill_role_count": view.providers_for_role(tenzro_types::model::MoeProviderRole::Prefill),
        "decode_role_count": view.providers_for_role(tenzro_types::model::MoeProviderRole::Decode),
        "replica_role_count": view.providers_for_role(tenzro_types::model::MoeProviderRole::Replica),
        "policy": {
            "min_replication": policy.min_replication,
            "max_replication": policy.max_replication,
            "hot_threshold_tps": policy.hot_threshold_tps,
        },
        "under_replicated_experts": under_replicated,
        "hot_experts": hot_experts,
        "holders": holders_by_expert,
    }))
}

/// `tenzro_moePlanDispatch` — given a list of per-token top-k routing
/// decisions, return the per-holder batch plan. Used by router peers and
/// by clients that want to inspect the dispatch path before submitting.
pub(crate) async fn handle_moe_plan_dispatch(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let model_id = p
        .get("model_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing model_id".into(),
            data: None,
        })?;
    let allow_cold = p
        .get("allow_cold")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let routings_raw = p
        .get("routings")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing routings array".into(),
            data: None,
        })?;
    let mut routings: Vec<tenzro_model::TokenRouting> = Vec::with_capacity(routings_raw.len());
    for r in routings_raw {
        let token_index = r
            .get("token_index")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "routing missing token_index".into(),
                data: None,
            })? as u32;
        let experts_arr =
            r.get("experts")
                .and_then(|v| v.as_array())
                .ok_or_else(|| JsonRpcError {
                    code: -32602,
                    message: "routing missing experts array".into(),
                    data: None,
                })?;
        let mut experts: Vec<tenzro_model::ExpertId> = Vec::with_capacity(experts_arr.len());
        for e in experts_arr {
            let layer = e
                .get("layer")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| JsonRpcError {
                    code: -32602,
                    message: "expert missing layer".into(),
                    data: None,
                })? as u32;
            let expert = e
                .get("expert")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| JsonRpcError {
                    code: -32602,
                    message: "expert missing expert".into(),
                    data: None,
                })? as u32;
            experts.push(tenzro_model::ExpertId::new(layer, expert));
        }
        routings.push(tenzro_model::TokenRouting {
            token_index,
            experts,
        });
    }

    let manager = node.provider_manager().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "Provider manager not initialized".into(),
        data: None,
    })?;
    let providers = manager.list_providers();
    let view = tenzro_model::MoeShardView::build(model_id, providers.iter());
    let plan =
        tenzro_model::plan_dispatch(&view, &routings, allow_cold).map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("moe dispatch planner: {}", e),
            data: None,
        })?;
    Ok(json!({
        "model_id": plan.model_id,
        "batch_count": plan.batches.len(),
        "batches": plan.batches.iter().map(|b| json!({
            "layer": b.expert.layer,
            "expert": b.expert.expert,
            "provider": hex::encode(b.provider.0),
            "iroh_endpoint_id": b.iroh_endpoint_id,
            "token_indices": b.token_indices,
        })).collect::<Vec<_>>(),
        "token_assignments": plan.token_assignments.iter().map(|a| json!({
            "token_index": a.token_index,
            "slots": a.slots.iter().map(|s| json!({
                "layer": s.expert.layer,
                "expert": s.expert.expert,
                "provider": s.provider.map(|p| hex::encode(p.0)),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    }))
}

/// `tenzro_moeReplicationPolicy` — current governance-tuned replication
/// policy used by the network's shard-view consumers.
pub(crate) async fn handle_moe_replication_policy() -> std::result::Result<Value, JsonRpcError> {
    let p = tenzro_model::ReplicationPolicy::default();
    Ok(json!({
        "min_replication": p.min_replication,
        "max_replication": p.max_replication,
        "hot_threshold_tps": p.hot_threshold_tps,
    }))
}

/// `tenzro_moeCatalogShape` — return the catalog-side MoE topology for
/// `model_id` (num_experts, experts_per_token, shared_experts,
/// params_per_expert_x10). `null` for dense models.
pub(crate) async fn handle_moe_catalog_shape(
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let model_id = params
        .as_ref()
        .and_then(|v| v.get("model_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing model_id".into(),
            data: None,
        })?;
    let entry = tenzro_model::catalog::get_model_by_id(model_id).ok_or_else(|| JsonRpcError {
        code: -32602,
        message: format!("unknown model_id: {}", model_id),
        data: None,
    })?;
    let shape = entry.moe.map(|s| {
        json!({
            "num_experts": s.num_experts,
            "experts_per_token": s.experts_per_token,
            "shared_experts": s.shared_experts,
            "params_per_expert_x10": s.params_per_expert_x10,
        })
    });
    Ok(json!({
        "model_id": model_id,
        "is_moe": entry.moe.is_some(),
        "moe": shape,
        "architecture": entry.architecture.to_string(),
    }))
}

/// `tenzro_modelMetadata` — full catalog metadata for `model_id`: the
/// serving profile (sampler defaults, jinja, reasoning), multimodal
/// projector (mmproj) flags, speculative-decoding pairing (drafter_id /
/// mtp_kind / draft_n), MoE topology, and architecture. This is the
/// general per-model metadata surface that clients (SDKs, CLI) read to
/// render or apply the catalog's recommended serving config. The catalog
/// is the single source of truth; this RPC is its read API.
pub(crate) async fn handle_model_metadata(
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let model_id = params
        .as_ref()
        .and_then(|v| v.get("model_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing model_id".into(),
            data: None,
        })?;
    let entry = tenzro_model::catalog::get_model_by_id(model_id).ok_or_else(|| JsonRpcError {
        code: -32602,
        message: format!("unknown model_id: {}", model_id),
        data: None,
    })?;
    let moe = entry.moe.map(|s| {
        json!({
            "num_experts": s.num_experts,
            "experts_per_token": s.experts_per_token,
            "shared_experts": s.shared_experts,
            "params_per_expert_x10": s.params_per_expert_x10,
        })
    });
    Ok(json!({
        "model_id": model_id,
        "architecture": entry.architecture.to_string(),
        "is_moe": entry.moe.is_some(),
        "moe": moe,
        "drafter_id": entry.drafter_id,
        "mtp_kind": format!("{:?}", entry.mtp_kind),
        "mtp_default_draft_n": entry.mtp_default_draft_n,
        "multimodal": entry.mmproj.is_some(),
        "mmproj_filename": entry.mmproj.as_ref().map(|m| m.filename.clone()),
        "serving": {
            "temperature": entry.serving.temperature,
            "top_p": entry.serving.top_p,
            "top_k": entry.serving.top_k,
            "min_p": entry.serving.min_p,
            "presence_penalty": entry.serving.presence_penalty,
            "jinja_required": entry.serving.jinja_required,
            "reasoning_default": entry.serving.reasoning_default,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_eth_addr_rejects_wrong_length() {
        assert!(parse_eth_addr("0x1234").is_err());
        assert!(parse_eth_addr("not-hex").is_err());
        assert!(parse_eth_addr("0x0000000000000000000000000000000000000000").is_ok());
    }

    #[tokio::test]
    async fn unwrap_arr_extracts_first_element() {
        let v = json!([{ "a": 1 }]);
        let u = unwrap_arr(v);
        assert_eq!(u, json!({ "a": 1 }));
    }

    #[tokio::test]
    async fn unwrap_arr_passes_object_through() {
        let v = json!({ "a": 1 });
        let u = unwrap_arr(v.clone());
        assert_eq!(u, v);
    }
}
