//! ERC-7786 source gateway over the governed bridge routes.
//!
//! One address gives EVM contracts the standard cross-chain messaging
//! interface, whatever transport the route to the destination runs:
//!
//! ```text
//! supportsAttribute(bytes4) -> bool
//! sendMessage(bytes recipient, bytes payload, bytes[] attributes) -> bytes32
//! event MessageSent(bytes32 indexed sendId, bytes sender, bytes recipient,
//!                   bytes payload, uint256 value, bytes[] attributes)
//! ```
//!
//! `recipient` and the logged `sender` are ERC-7930 interoperable addresses.
//! The gateway serves the `eip155` chains a governed route reaches, supports
//! no attribute and carries no value; `sendId` is zero, and the message id
//! the route assigns is in the bridge log of the same transaction.
//!
//! A precompile writes only its own storage, and a route's sequence and
//! outbox live in system storage. So `sendMessage` records the message in
//! the gateway's storage, through the EVM journal (a reverted frame takes its
//! message with it), and once the transaction has succeeded
//! [`deliver_outbox`] hands each recorded message to the route framework's
//! `send_message`, the call the native `SendMessage` operation makes. A route
//! that refuses a message fails the whole transaction.
//!
//! The body a route carries for a gateway message is [`message_tag`] followed
//! by `abi.encode(bytes sender, bytes recipient, bytes payload)`. Only the
//! gateway produces a body that starts with the tag: the native `SendMessage`
//! refuses one, so the `sender` in a tagged body is the contract that called
//! the gateway.
//!
//! ## Receiving
//!
//! A tagged body the route's committee attests from an `eip155` chain is
//! handed to the contract it names by the gateway-delivery native call.
//! The bridge executor admits the delivery under the route's rules and checks
//! the body ([`inbound_message`]): its sender is on the route's chain and its
//! recipient on this one. Once the executor has returned, [`deliver_inbound`]
//! calls, from the gateway's address,
//!
//! ```text
//! receiveMessage(bytes32 receiveId, bytes sender, bytes payload) -> bytes4
//! ```
//!
//! on the recipient with [`DELIVERY_GAS_KEY`] gas. The recipient accepts by
//! returning the function's selector. Anything else (a revert, no code, out
//! of gas) fails the whole transaction: the delivery is not consumed and may
//! be submitted again, and its sender has paid for the bridge operation and
//! the whole of the delivery gas. The gateway sends nothing while the call
//! runs.
//!
//! The gateway runs from the epoch [`GATEWAY_KEY`] names. Until then its
//! address is an account with no code: the precompile host passes every call
//! to the EVM's own handler.

use sha3::{Digest, Keccak256};
use tenzro_bridge::route::attestation::Delivery;
use tenzro_native_ops::gateway_delivery::GatewayDeliveryOp;
use tenzro_types::bridge_route::{BridgeRouteAdapter, bridge_route_storage_key};

use crate::error::Result;
use crate::evm::EvmExecutor;
use crate::evm::precompile_host::{
    PrecompileCall, abi_error_string, slot_key, state_blob, state_word, state_write_blob,
    u128_to_word, word_to_u128,
};
use crate::evm::wtnzo::abi;
use crate::native::bridge::{BRIDGE_TOPIC, GAS_BRIDGE, GAS_BRIDGE_BYTE, VmRouteState};
use crate::precompiles::{PRECOMPILE_ERC7786_GATEWAY, PrecompileResult};
use crate::state_adapter::StateAdapter;
use crate::traits::{VmState, VmType};
use crate::types::{ExecutionResult, Log, StateChange, VmTransaction};

/// The gate of the gateway.
pub const GATEWAY_KEY: &str = "feature.erc7786_gateway.activation_epoch";

/// Gas the gateway gives a recipient's `receiveMessage`. The transaction
/// that delivers a message pays for all of it.
pub const DELIVERY_GAS_KEY: &str = "feature.erc7786_gateway.delivery_gas";

/// Gas of a call before what it reads and writes.
const GAS_BASE: u64 = 2_000;

/// ERC-7930 version 1.
const INTEROP_VERSION: [u8; 2] = [0x00, 0x01];
/// The ERC-7930 chain type of the `eip155` namespace.
const CHAIN_TYPE_EIP155: [u8; 2] = [0x00, 0x00];

fn selector(signature: &str) -> [u8; 4] {
    let d = Keccak256::digest(signature.as_bytes());
    [d[0], d[1], d[2], d[3]]
}

fn count_slot() -> [u8; 32] {
    slot_key(b"gateway/count", &[])
}

fn entry_slot(index: u128) -> [u8; 32] {
    slot_key(b"gateway/outbox", &[&index.to_be_bytes()])
}

fn revert(msg: &str) -> Result<PrecompileResult> {
    Ok(PrecompileResult::revert(abi_error_string(msg), 0))
}

/// The ERC-7930 address of the EVM account `address` on chain `chain_id`.
pub fn interoperable_address(chain_id: u64, address: &[u8; 20]) -> Vec<u8> {
    let reference = chain_id.to_be_bytes();
    let reference = &reference[reference.iter().position(|b| *b != 0).unwrap_or(7)..];
    let mut out = Vec::with_capacity(6 + reference.len() + 20);
    out.extend_from_slice(&INTEROP_VERSION);
    out.extend_from_slice(&CHAIN_TYPE_EIP155);
    out.push(reference.len() as u8);
    out.extend_from_slice(reference);
    out.push(20);
    out.extend_from_slice(address);
    out
}

/// The chain id and account of an ERC-7930 address in the `eip155`
/// namespace, or why it is not one.
fn eip155_address(address: &[u8]) -> std::result::Result<(u64, [u8; 20]), &'static str> {
    let malformed = "gateway: not an ERC-7930 address";
    if address.len() < 6 || address[..2] != INTEROP_VERSION {
        return Err(malformed);
    }
    let reference_len = address[4] as usize;
    let reference = address.get(5..5 + reference_len).ok_or(malformed)?;
    let account_len = *address.get(5 + reference_len).ok_or(malformed)? as usize;
    if address.len() != 6 + reference_len + account_len {
        return Err(malformed);
    }
    if address[2..4] != CHAIN_TYPE_EIP155 {
        return Err("gateway: only eip155 addresses are served");
    }
    if account_len != 20 || reference.is_empty() || reference.len() > 8 {
        return Err(malformed);
    }
    let chain_id = reference
        .iter()
        .fold(0u64, |id, b| (id << 8) | u64::from(*b));
    let mut account = [0u8; 20];
    account.copy_from_slice(&address[6 + reference_len..]);
    Ok((chain_id, account))
}

/// The route chain name an ERC-7930 address is on, or why the gateway does
/// not serve it.
fn route_chain(address: &[u8]) -> std::result::Result<&'static str, &'static str> {
    let (chain_id, _) = eip155_address(address)?;
    tenzro_bridge::route::evm::EVM_CHAINS
        .iter()
        .find(|c| c.chain_id == chain_id)
        .map(|c| c.name)
        .ok_or("gateway: no route serves the address's chain")
}

/// `abi.encode` of a tuple of `bytes` values, then `value_word` when given,
/// then one empty `bytes[]` when `with_empty_array` is set: the two
/// encodings the gateway produces.
fn encode(values: &[&[u8]], value_word: Option<[u8; 32]>, with_empty_array: bool) -> Vec<u8> {
    let heads = values.len() + usize::from(value_word.is_some()) + usize::from(with_empty_array);
    let mut head = Vec::with_capacity(heads * 32);
    let mut tail = Vec::new();
    for v in values {
        head.extend_from_slice(&u128_to_word((heads * 32 + tail.len()) as u128));
        tail.extend_from_slice(&u128_to_word(v.len() as u128));
        tail.extend_from_slice(v);
        tail.resize(tail.len() + (32 - v.len() % 32) % 32, 0);
    }
    if let Some(word) = value_word {
        head.extend_from_slice(&word);
    }
    if with_empty_array {
        head.extend_from_slice(&u128_to_word((heads * 32 + tail.len()) as u128));
        tail.extend_from_slice(&[0u8; 32]);
    }
    head.extend_from_slice(&tail);
    head
}

/// The 32 bytes that open the body of every gateway message and of no other
/// message a route carries from this chain.
pub fn message_tag() -> [u8; 32] {
    Keccak256::digest(b"ERC7786GatewayMessage(bytes sender,bytes recipient,bytes payload)").into()
}

/// The body a route carries for a gateway message.
pub fn message_body(sender: &[u8], recipient: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = message_tag().to_vec();
    body.extend(encode(&[sender, recipient, payload], None, false));
    body
}

/// Topic of `MessageSent`.
pub fn message_sent_topic() -> [u8; 32] {
    Keccak256::digest(b"MessageSent(bytes32,bytes,bytes,bytes,uint256,bytes[])").into()
}

/// The first attribute's key, when the call carries any attribute.
fn first_attribute(args: &[u8]) -> Option<Option<[u8; 4]>> {
    let array = abi::decode_usize_at(args, 64)?;
    if abi::decode_usize_at(args, array)? == 0 {
        return Some(None);
    }
    let elements = array.checked_add(32)?;
    let first = abi::decode_dynamic_bytes(args, elements, elements)?;
    let mut key = [0u8; 4];
    let n = first.len().min(4);
    key[..n].copy_from_slice(&first[..n]);
    Some(Some(key))
}

/// Entry point of the gateway precompile.
pub fn erc7786_gateway_precompile(call: &mut PrecompileCall<'_>) -> Result<PrecompileResult> {
    call.charge(GAS_BASE)?;
    if call.input.len() < 4 {
        return revert("gateway: missing selector");
    }
    let sel = [call.input[0], call.input[1], call.input[2], call.input[3]];
    let args = call.input[4..].to_vec();
    if sel == selector("supportsAttribute(bytes4)") {
        return Ok(PrecompileResult::success(abi::encode_bool(false), 0));
    }
    if sel != selector("sendMessage(bytes,bytes,bytes[])") {
        return revert("gateway: unknown selector");
    }
    call.require_write()?;
    if call.env.delivering {
        return revert("gateway: no message is sent while one is delivered");
    }
    if call.env.value != 0 {
        return revert("gateway: a message carries no value");
    }
    let (Some(recipient), Some(payload), Some(attribute)) = (
        abi::decode_dynamic_bytes(&args, 0, 0),
        abi::decode_dynamic_bytes(&args, 0, 32),
        first_attribute(&args),
    ) else {
        return revert("gateway: bad arguments");
    };
    if let Some(key) = attribute {
        // error UnsupportedAttribute(bytes4 selector)
        let mut out = selector("UnsupportedAttribute(bytes4)").to_vec();
        out.extend_from_slice(&key);
        out.resize(36, 0);
        return Ok(PrecompileResult::revert(out, 0));
    }
    let chain = match route_chain(recipient) {
        Ok(chain) => chain,
        Err(why) => return revert(why),
    };
    let mut served = false;
    for adapter in BridgeRouteAdapter::ALL {
        let key = bridge_route_storage_key(adapter, chain);
        if call
            .state
            .system_storage(key.as_bytes())?
            .is_some_and(|record| !record.is_empty())
        {
            served = true;
            break;
        }
    }
    if !served {
        return revert("gateway: no route serves the recipient's chain");
    }

    let sender = interoperable_address(call.env.chain_id, &call.env.caller);
    let body = message_body(&sender, recipient, payload);
    call.charge(GAS_BRIDGE.saturating_add(GAS_BRIDGE_BYTE.saturating_mul(body.len() as u64)))?;

    let mut entry = Vec::with_capacity(1 + chain.len() + body.len());
    entry.push(chain.len() as u8);
    entry.extend_from_slice(chain.as_bytes());
    entry.extend_from_slice(&body);
    let count = call.sload_u128(count_slot())?;
    call.write_blob(entry_slot(count), &entry)?;
    call.sstore_u128(count_slot(), count + 1)?;

    call.emit(
        vec![message_sent_topic(), [0u8; 32]],
        encode(&[&sender, recipient, payload], Some([0u8; 32]), true),
    )?;
    Ok(PrecompileResult::success(vec![0u8; 32], 0))
}

/// A gateway message a route delivered to this chain.
pub struct InboundMessage {
    /// ERC-7930 address of the contract that sent it.
    pub sender: Vec<u8>,
    /// The contract it is for.
    pub recipient: [u8; 20],
    /// What the sender handed its gateway.
    pub payload: Vec<u8>,
}

/// Reads the gateway message in `body`, a delivery on the route from
/// `source_chain` to the chain `chain_id`, or says why it is not one this
/// chain delivers.
pub fn inbound_message(
    chain_id: u64,
    source_chain: &str,
    body: &[u8],
) -> std::result::Result<InboundMessage, &'static str> {
    let Some(tuple) = body.strip_prefix(&message_tag()) else {
        return Err("gateway: the delivery is not a gateway message");
    };
    let (Some(sender), Some(recipient), Some(payload)) = (
        abi::decode_dynamic_bytes(tuple, 0, 0),
        abi::decode_dynamic_bytes(tuple, 0, 32),
        abi::decode_dynamic_bytes(tuple, 0, 64),
    ) else {
        return Err("gateway: the delivery is not a gateway message");
    };
    if route_chain(sender)? != source_chain {
        return Err("gateway: the sender is not on the route's chain");
    }
    let (to_chain, recipient) = eip155_address(recipient)?;
    if to_chain != chain_id {
        return Err("gateway: the recipient is not on this chain");
    }
    Ok(InboundMessage {
        sender: sender.to_vec(),
        recipient,
        payload: payload.to_vec(),
    })
}

/// The id a recipient is given for the delivery with `nonce` on the route
/// stored under `route_key`.
pub fn receive_id(route_key: &str, nonce: u64) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(route_key.as_bytes());
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

/// Selector of the recipient's `receiveMessage`, which is also what it
/// returns to accept a message.
pub fn receive_message_selector() -> [u8; 4] {
    selector("receiveMessage(bytes32,bytes,bytes)")
}

/// The delivery a gateway-delivery native call carries.
fn delivery_of(tx: &VmTransaction) -> Option<(BridgeRouteAdapter, String, Delivery)> {
    let body = tx
        .data
        .strip_prefix(crate::native::native_call::SELECTOR_NATIVE_CALL.as_slice())?
        .strip_prefix(tenzro_native_ops::SELECTOR_GATEWAY_DELIVERY.as_slice())?;
    let op: GatewayDeliveryOp = serde_json::from_slice(body).ok()?;
    let delivery = Delivery::decode(&op.delivery).ok()?;
    Some((op.adapter, op.source_chain.to_ascii_lowercase(), delivery))
}

/// Calls the recipient of the message a successful gateway delivery
/// admitted. A recipient that does not accept it turns `result` into a
/// failure, which block execution reverts and charges in full.
pub(crate) fn deliver_inbound(
    evm: &EvmExecutor,
    tx: &VmTransaction,
    state: &mut dyn VmState,
    result: &mut ExecutionResult,
) {
    if !result.success || tx.vm_type != VmType::Tenzro {
        return;
    }
    let Some((adapter, chain, delivery)) = delivery_of(tx) else {
        return;
    };
    let refuse = |result: &mut ExecutionResult, why: String| {
        *result = ExecutionResult::failed(result.gas_used, format!("ERC-7786 gateway: {why}"));
    };
    let message = match inbound_message(tx.chain_id, &chain, &delivery.body) {
        Ok(message) => message,
        Err(why) => return refuse(result, why.to_string()),
    };
    let id = receive_id(&bridge_route_storage_key(adapter, &chain), delivery.nonce);
    let padded = |v: &[u8]| {
        let mut out = u128_to_word(v.len() as u128).to_vec();
        out.extend_from_slice(v);
        out.resize(out.len() + (32 - v.len() % 32) % 32, 0);
        out
    };
    let (sender, payload) = (padded(&message.sender), padded(&message.payload));
    let mut data = receive_message_selector().to_vec();
    data.extend_from_slice(&id);
    data.extend_from_slice(&u128_to_word(96));
    data.extend_from_slice(&u128_to_word(96 + sender.len() as u128));
    data.extend(sender);
    data.extend(payload);

    let gateway = PRECOMPILE_ERC7786_GATEWAY.to_vec();
    let mut call = VmTransaction::new(
        gateway.clone(),
        Some(message.recipient.to_vec()),
        0,
        data,
        crate::native::network_param(state, DELIVERY_GAS_KEY),
        0,
        state.get_nonce(&gateway),
        VmType::Evm,
        tx.chain_id,
    );
    call.block_timestamp_ms = tx.block_timestamp_ms;
    call.block_height = tx.block_height;
    call.block_base_fee = tx.block_base_fee;

    let Some(adapter_state) = state.as_any_mut().downcast_mut::<StateAdapter>() else {
        return refuse(result, "delivery requires the node state".to_string());
    };
    let called = match evm.deliver(&call, adapter_state) {
        Ok(called) => called,
        Err(e) => return refuse(result, e.to_string()),
    };
    if !called.success {
        let why = called.revert_reason.unwrap_or_default();
        return refuse(result, format!("the recipient refused the message: {why}"));
    }
    let mut accepted = [0u8; 32];
    accepted[..4].copy_from_slice(&receive_message_selector());
    if called.output != accepted {
        return refuse(
            result,
            "the recipient did not accept the message".to_string(),
        );
    }
    result.logs.extend(called.logs);
    result.state_changes.extend(called.state_changes);
}

/// Hands the messages a successful EVM transaction recorded in the gateway
/// to their routes and empties the gateway's storage. A route that refuses
/// one turns `result` into a failure, which block execution reverts.
pub(crate) fn deliver_outbox(
    tx: &VmTransaction,
    state: &mut dyn VmState,
    result: &mut ExecutionResult,
) {
    if !result.success
        || tx.vm_type != VmType::Evm
        || !crate::feature_gate::is_live_now(state, GATEWAY_KEY)
    {
        return;
    }
    let gateway = PRECOMPILE_ERC7786_GATEWAY;
    let count = word_to_u128(&state_word(state, &gateway, &count_slot()));
    if count == 0 {
        return;
    }
    let refuse = |result: &mut ExecutionResult, why: String| {
        *result = ExecutionResult::failed(result.gas_used, format!("ERC-7786 gateway: {why}"));
    };
    let now = match crate::native::deterministic_now_ms(tx) {
        Ok(now) => now,
        Err(e) => return refuse(result, e.to_string()),
    };
    let epoch = match crate::native::rewards::read_reward_state(state) {
        Ok(rewards) => rewards.current_epoch,
        Err(e) => return refuse(result, e.to_string()),
    };
    let write =
        |state: &mut dyn VmState, key: [u8; 32], value: [u8; 32], result: &mut ExecutionResult| {
            let old = state.get_storage(&gateway, &key);
            state.set_storage(&gateway, &key, value.to_vec());
            result.state_changes.push(StateChange::new(
                gateway.to_vec(),
                key.to_vec(),
                old,
                Some(value.to_vec()),
            ));
        };
    for index in 0..count {
        let slot = entry_slot(index);
        let entry = state_blob(state, &gateway, slot).unwrap_or_default();
        let name_len = entry.first().copied().unwrap_or(0) as usize;
        let (Some(name), Some(body)) = (
            entry
                .get(1..1 + name_len)
                .and_then(|n| std::str::from_utf8(n).ok()),
            entry.get(1 + name_len..),
        ) else {
            return refuse(result, "a recorded message is malformed".to_string());
        };
        let mut view = VmRouteState::new(state, tx.chain_id, now, epoch);
        let sent =
            match crate::native::bridge::route_framework().send_message(&mut view, name, body) {
                Ok(sent) => sent,
                Err(e) => return refuse(result, e.to_string()),
            };
        result.state_changes.extend(view.into_changes());
        let out = serde_json::json!({
            "route": sent.route.storage_key(),
            "sequence": sent.sequence,
            "message_id": hex::encode(sent.message_id),
            "message": hex::encode(&sent.bytes),
            "from": hex::encode(&tx.from),
        });
        result.logs.push(Log::new(
            crate::native::SYSTEM_ADDRESS.to_vec(),
            vec![BRIDGE_TOPIC.to_vec(), b"message_out".to_vec()],
            serde_json::to_vec(&out).unwrap_or_default(),
        ));
        state_write_blob(state, &gateway, slot, &[]);
        write(state, slot, [0u8; 32], result);
    }
    write(state, count_slot(), [0u8; 32], result);
}
