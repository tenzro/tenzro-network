//! The Solana wallet RPC subset: the methods a Solana wallet calls to show a
//! balance, build, simulate, send and confirm a transaction. Accounts are the
//! one ledger's accounts named by their Ed25519 public key; amounts are in
//! units of 10^-9 TNZO, the precision Solana wallets display.

use std::sync::Arc;

use base64::Engine as _;
use serde_json::{Value, json};
use tenzro_storage::block_store::BlockStoreImpl;
use tenzro_storage::traits::BlockStore;
use tenzro_types::primitives::{Address, BlockHeight, Hash};
use tenzro_vm::external_tx::{ExternalSvmTx, SVM_GAS_LIMIT, decode_svm_wire};
use tenzro_vm::traits::VmState as _;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

type RpcResult = std::result::Result<Value, JsonRpcError>;

/// Blocks a recent blockhash stays valid for.
pub const BLOCKHASH_VALIDITY_BLOCKS: u64 = 150;

fn invalid(m: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: m.into(),
        data: None,
    }
}

fn internal(m: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32000,
        message: m.into(),
        data: None,
    }
}

fn arg(params: &Option<Value>, i: usize) -> Option<&Value> {
    params
        .as_ref()
        .and_then(|p| p.as_array())
        .and_then(|a| a.get(i))
}

fn pubkey_arg(params: &Option<Value>) -> std::result::Result<Address, JsonRpcError> {
    let s = arg(params, 0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid("expected a base58 public key"))?;
    Address::from_base58(s).map_err(|_| invalid("invalid base58 public key"))
}

fn context(node: &TenzroNode, value: Value) -> Value {
    json!({ "context": { "slot": node.chain_tip_height() }, "value": value })
}

fn lamports(balance: u128) -> u64 {
    tenzro_token::native_to_spl(balance).unwrap_or(u64::MAX)
}

fn state(node: &TenzroNode) -> std::result::Result<tenzro_vm::StateAdapter, JsonRpcError> {
    crate::rpc::chain_state_of(node).ok_or_else(|| internal("chain state unavailable"))
}

fn block_store(
    node: &TenzroNode,
) -> std::result::Result<BlockStoreImpl<tenzro_storage::RocksDbStore>, JsonRpcError> {
    let storage = node
        .storage()
        .ok_or_else(|| internal("storage not initialized"))?;
    BlockStoreImpl::new(storage.clone()).map_err(|e| internal(format!("block store: {e}")))
}

/// Hash of the block at `height`, if stored.
async fn block_hash_at(
    store: &BlockStoreImpl<tenzro_storage::RocksDbStore>,
    height: u64,
) -> Option<Hash> {
    store
        .get_block_by_height(BlockHeight(height))
        .await
        .ok()
        .flatten()
        .map(|b| b.hash())
}

/// Decodes the transaction argument (`base64`, or `base58` when the options
/// say so) and verifies its signatures.
fn decode_arg(
    params: &Option<Value>,
) -> std::result::Result<(Vec<u8>, ExternalSvmTx), JsonRpcError> {
    let encoded = arg(params, 0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid("expected an encoded transaction"))?;
    let encoding = arg(params, 1)
        .and_then(|o| o.get("encoding"))
        .and_then(|v| v.as_str())
        .unwrap_or("base58");
    let raw = match encoding {
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid("invalid base64"))?,
        "base58" => bs58::decode(encoded)
            .into_vec()
            .map_err(|_| invalid("invalid base58"))?,
        other => return Err(invalid(format!("unsupported encoding {other}"))),
    };
    let ext = decode_svm_wire(&raw).map_err(|e| invalid(format!("transaction refused: {e}")))?;
    Ok((raw, ext))
}

/// Refuses a transaction whose recent blockhash is not one of the last
/// [`BLOCKHASH_VALIDITY_BLOCKS`] blocks.
async fn check_recent_blockhash(
    node: &TenzroNode,
    ext: &ExternalSvmTx,
) -> std::result::Result<(), JsonRpcError> {
    let store = block_store(node)?;
    let tip = node.chain_tip_height();
    for h in (tip.saturating_sub(BLOCKHASH_VALIDITY_BLOCKS)..=tip).rev() {
        if block_hash_at(&store, h)
            .await
            .is_some_and(|b| b.0 == ext.recent_blockhash)
        {
            return Ok(());
        }
    }
    Err(JsonRpcError {
        code: -32002,
        message: "Blockhash not found".to_string(),
        data: None,
    })
}

/// `sendTransaction`: a Solana wire transaction signed by an external Ed25519
/// wallet. Returns its first signature, base58.
pub(crate) async fn handle_send_transaction(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> RpcResult {
    let (raw, ext) = decode_arg(&params)?;
    check_recent_blockhash(node, &ext).await?;
    let st = state(node)?;
    let payer = Address(ext.signers[0]);
    let executed = || st.get_nonce(payer.as_bytes());
    let nonce = match node.consensus() {
        Some(consensus) => consensus.mempool().next_nonce(&payer, executed),
        None => executed(),
    };
    let gas_price = u64::try_from(tenzro_vm::ledger::block_base_fee(&st)).unwrap_or(u64::MAX);
    let (signed_tx, _) = crate::event_loop::external_svm_envelope(
        raw,
        crate::rpc::node_chain_id(node),
        nonce,
        gas_price,
    )
    .map_err(|e| JsonRpcError {
        code: -32003,
        message: format!("Transaction refused: {e}"),
        data: None,
    })?;
    let tx_hash = signed_tx.transaction.hash();
    crate::rpc::admit_transaction(node, signed_tx, tx_hash).await?;
    Ok(json!(bs58::encode(ext.signature).into_string()))
}

/// `simulateTransaction`: executes the transaction against a scratch copy of
/// state and reports whether it would succeed and the gas it uses.
pub(crate) async fn handle_simulate_transaction(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> RpcResult {
    let (_, ext) = decode_arg(&params)?;
    let mut st = state(node)?;
    let base_fee = tenzro_vm::ledger::block_base_fee(&st);
    let nonce = st.get_nonce(&ext.signers[0]);
    let vm_tx = ext
        .to_vm_transaction(nonce, base_fee, crate::rpc::node_chain_id(node))
        .map_err(|e| invalid(e.to_string()))?;
    let (err, units) = crate::rpc::simulate_vm_transaction(node, &mut st, &vm_tx, base_fee).await?;
    Ok(context(
        node,
        json!({ "err": err, "logs": [], "accounts": null, "unitsConsumed": units }),
    ))
}

/// `getSignatureStatuses`: the status of each transaction, by first signature.
pub(crate) async fn handle_get_signature_statuses(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> RpcResult {
    let sigs = arg(&params, 0)
        .and_then(|v| v.as_array())
        .ok_or_else(|| invalid("expected an array of signatures"))?;
    let mut out = Vec::with_capacity(sigs.len());
    for s in sigs {
        let sig = s
            .as_str()
            .and_then(|s| bs58::decode(s).into_vec().ok())
            .filter(|b| b.len() == 64);
        let Some(sig) = sig else {
            out.push(Value::Null);
            continue;
        };
        let hash = tenzro_types::svm_signature_hash(&sig);
        let receipt =
            crate::rpc::handle_get_transaction_receipt_value(node, &hash.to_string()).await;
        out.push(match receipt {
            Some(r) => {
                let slot = r.get("blockNumber").and_then(|v| v.as_str())
                    .and_then(|h| u64::from_str_radix(h.trim_start_matches("0x"), 16).ok()).unwrap_or(0);
                let ok = r.get("status").and_then(|v| v.as_str()) == Some("0x1");
                let err = if ok { Value::Null } else { json!({ "InstructionError": [0, { "Custom": 1 }] }) };
                json!({ "slot": slot, "confirmations": null, "err": err, "status": if ok { json!({"Ok": null}) } else { json!({"Err": err}) }, "confirmationStatus": "finalized" })
            }
            None => Value::Null,
        });
    }
    Ok(context(node, Value::Array(out)))
}

/// `getLatestBlockhash`: the tip's hash and the last height it stays valid at.
pub(crate) async fn handle_get_latest_blockhash(node: &Arc<TenzroNode>) -> RpcResult {
    let tip = node.chain_tip_height();
    let hash = block_hash_at(&block_store(node)?, tip)
        .await
        .ok_or_else(|| internal("tip block unavailable"))?;
    Ok(context(
        node,
        json!({
            "blockhash": bs58::encode(hash.0).into_string(),
            "lastValidBlockHeight": tip + BLOCKHASH_VALIDITY_BLOCKS,
        }),
    ))
}

/// `isBlockhashValid`.
pub(crate) async fn handle_is_blockhash_valid(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> RpcResult {
    let wanted = arg(&params, 0)
        .and_then(|v| v.as_str())
        .and_then(|s| bs58::decode(s).into_vec().ok());
    let store = block_store(node)?;
    let tip = node.chain_tip_height();
    let mut valid = false;
    if let Some(w) = wanted {
        for h in (tip.saturating_sub(BLOCKHASH_VALIDITY_BLOCKS)..=tip).rev() {
            if block_hash_at(&store, h)
                .await
                .is_some_and(|b| b.0[..] == w[..])
            {
                valid = true;
                break;
            }
        }
    }
    Ok(context(node, json!(valid)))
}

/// `getBalance`, in units of 10^-9 TNZO.
pub(crate) async fn handle_get_balance(node: &Arc<TenzroNode>, params: Option<Value>) -> RpcResult {
    let address = pubkey_arg(&params)?;
    Ok(context(
        node,
        json!(lamports(state(node)?.get_balance(address.as_bytes()))),
    ))
}

/// `getAccountInfo`: a wallet account (no data, owned by the system
/// program), or null for an account the ledger has never seen.
pub(crate) async fn handle_get_account_info(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> RpcResult {
    let address = pubkey_arg(&params)?;
    let st = state(node)?;
    if !st.exists(address.as_bytes()) {
        return Ok(context(node, Value::Null));
    }
    Ok(context(
        node,
        json!({
            "lamports": lamports(st.get_balance(address.as_bytes())),
            "owner": "11111111111111111111111111111111",
            "data": ["", "base64"],
            "executable": false,
            "rentEpoch": u64::MAX,
            "space": 0,
        }),
    ))
}

/// `getFeeForMessage`: the fee at the current base fee for the standard
/// gas limit, in units of 10^-9 TNZO.
pub(crate) async fn handle_get_fee_for_message(node: &Arc<TenzroNode>) -> RpcResult {
    let base_fee = tenzro_vm::ledger::block_base_fee(&state(node)?);
    Ok(context(
        node,
        json!(lamports(base_fee.saturating_mul(u128::from(SVM_GAS_LIMIT)))),
    ))
}

/// The remaining read-only methods Solana wallets call.
pub(crate) async fn handle_simple(node: &Arc<TenzroNode>, method: &str) -> RpcResult {
    Ok(match method {
        "getSlot" | "getBlockHeight" => json!(node.chain_tip_height()),
        "getMinimumBalanceForRentExemption" => json!(0),
        "getVersion" => json!({ "solana-core": env!("CARGO_PKG_VERSION"), "feature-set": 0 }),
        "getHealth" => json!("ok"),
        _ => {
            return Err(JsonRpcError {
                code: -32601,
                message: format!("Method not found: {method}"),
                data: None,
            });
        }
    })
}
