//! The Solana adapter.
//!
//! It speaks the CCIP message envelope in the Borsh layout the SVM CCIP
//! programs use:
//!
//! - **Inbound** (Solana to Tenzro): `SVM2AnyRampMessage`. Its message id
//!   must equal the hash in [`svm2any_message_id`], recomputed from the
//!   route's on-ramp program and chain selectors.
//! - **Outbound** (Tenzro to Solana): `Any2SVMRampMessage`, a token-only
//!   transfer with no data and default execution arguments.
//!
//! Amounts are 256-bit little-endian on the wire and must fit in u128.
//!
//! # What a Solana delivery proves
//!
//! Solana commits no per-slot receipt or per-account state root a light
//! client could check: a transaction's inclusion does not prove it succeeded.
//! A Solana route therefore admits on attestations alone. Each verifier reads
//! the transaction that emitted the message from its own RPC provider and
//! signs, together with the message, a [`SolanaExecution`] stating that the
//! transaction is finalized and succeeded; the delivery carries that record
//! as its proof, so every signature covers it. The route's verifiers run on
//! different hosts under different operators and read from different RPC
//! providers, and a delivery is admitted only with the route's threshold of
//! signatures from verifiers that are pairwise independent in both
//! ([`check_execution`]). Such routes mint under the network's attested-route
//! limits, which governance keeps below those of routes with a light client.
//!
//! When Solana commits transaction results under a root its validators vote
//! on, a Solana light client takes the place of the execution record: the
//! route's anchor then names it, as the Ethereum route's names the sync
//! committee, and the route moves to the proven-route limits.

use std::collections::HashMap;

use sha3::{Digest, Keccak256};

use super::attestation::Delivery;
use super::canonical::{Reader, Writer};
use super::{
    BridgeRoute, BridgeRouteAdapter, ChainFamily, RouteAdapter, RouteMessage, VerifierQuorum,
};
use crate::error::{BridgeError, Result};

/// Solana's CCIP chain selector.
pub const SOLANA_SELECTOR: u64 = 124_615_329_519_749_607;

/// Compute units requested for an outbound token transfer.
pub const OUTBOUND_COMPUTE_UNITS: u32 = 0;

/// Gas (compute) the destination pool may use to mint.
pub const DEST_POOL_GAS: u32 = 90_000;

const MAX_FIELD_LEN: usize = 16 * 1024;
const MAX_TOKEN_TRANSFERS: usize = 1;

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("CCIP Solana message: {}", what.into()))
}

/// `SVM2AnyTokenTransfer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Svm2AnyTokenTransfer {
    /// The source pool program.
    pub source_pool: [u8; 32],
    /// The destination token, as the destination encodes it.
    pub dest_token: Vec<u8>,
    /// Pool data.
    pub extra_data: Vec<u8>,
    /// Amount.
    pub amount: u128,
    /// Destination execution data.
    pub dest_exec_data: Vec<u8>,
}

/// `SVM2AnyRampMessage`, the message the Solana router emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Svm2AnyMessage {
    /// Message id.
    pub message_id: [u8; 32],
    /// Sending chain selector.
    pub source_selector: u64,
    /// Receiving chain selector.
    pub dest_selector: u64,
    /// Per-lane sequence number.
    pub sequence: u64,
    /// Per-sender nonce.
    pub nonce: u64,
    /// The account that called the router.
    pub sender: [u8; 32],
    /// Arbitrary data.
    pub data: Vec<u8>,
    /// The receiver, as the destination encodes it.
    pub receiver: Vec<u8>,
    /// Extra arguments.
    pub extra_args: Vec<u8>,
    /// Fee token mint.
    pub fee_token: [u8; 32],
    /// Token transfers.
    pub token_amounts: Vec<Svm2AnyTokenTransfer>,
    /// Fee paid, in the fee token.
    pub fee_token_amount: u128,
    /// Fee value in juels.
    pub fee_value_juels: u128,
}

impl Svm2AnyMessage {
    /// Borsh encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w, &self.message_id);
        w.into_bytes()
    }

    fn write(&self, w: &mut Writer, message_id: &[u8; 32]) {
        w.raw(message_id)
            .u64_le(self.source_selector)
            .u64_le(self.dest_selector)
            .u64_le(self.sequence)
            .u64_le(self.nonce)
            .raw(&self.sender)
            .borsh_bytes(&self.data)
            .borsh_bytes(&self.receiver)
            .borsh_bytes(&self.extra_args)
            .raw(&self.fee_token)
            .u32_le(self.token_amounts.len() as u32);
        for t in &self.token_amounts {
            w.raw(&t.source_pool)
                .borsh_bytes(&t.dest_token)
                .borsh_bytes(&t.extra_data)
                .u256_le(t.amount)
                .borsh_bytes(&t.dest_exec_data);
        }
        w.u256_le(self.fee_token_amount)
            .u256_le(self.fee_value_juels);
    }

    /// Read a Borsh-encoded message through `r`.
    pub fn read(r: &mut Reader<'_>) -> Result<Self> {
        let message_id = r.array()?;
        let source_selector = r.u64_le()?;
        let dest_selector = r.u64_le()?;
        let sequence = r.u64_le()?;
        let nonce = r.u64_le()?;
        let sender = r.array()?;
        let data = r.borsh_bytes(MAX_FIELD_LEN)?;
        let receiver = r.borsh_bytes(64)?;
        let extra_args = r.borsh_bytes(MAX_FIELD_LEN)?;
        let fee_token = r.array()?;
        let n = r.borsh_len(MAX_TOKEN_TRANSFERS)?;
        let token_amounts = (0..n)
            .map(|_| {
                Ok(Svm2AnyTokenTransfer {
                    source_pool: r.array()?,
                    dest_token: r.borsh_bytes(64)?,
                    extra_data: r.borsh_bytes(MAX_FIELD_LEN)?,
                    amount: r.u256_le_as_u128()?,
                    dest_exec_data: r.borsh_bytes(MAX_FIELD_LEN)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let fee_token_amount = r.u256_le_as_u128()?;
        let fee_value_juels = r.u256_le_as_u128()?;
        Ok(Self {
            message_id,
            source_selector,
            dest_selector,
            sequence,
            nonce,
            sender,
            data,
            receiver,
            extra_args,
            fee_token,
            token_amounts,
            fee_token_amount,
            fee_value_juels,
        })
    }
}

/// The id of an SVM-to-any message, as the router computes it: Keccak-256
/// over a zero leaf domain, a domain tag, the lane (selectors and router
/// program), the header fields, the fees, the length-prefixed receiver and
/// data, and the Borsh encodings of the token transfers and extra arguments.
pub fn svm2any_message_id(m: &Svm2AnyMessage, on_ramp: &[u8; 32]) -> [u8; 32] {
    let mut tokens = Writer::new();
    tokens.u32_le(m.token_amounts.len() as u32);
    for t in &m.token_amounts {
        tokens
            .raw(&t.source_pool)
            .borsh_bytes(&t.dest_token)
            .borsh_bytes(&t.extra_data)
            .u256_le(t.amount)
            .borsh_bytes(&t.dest_exec_data);
    }
    let mut fees = Writer::new();
    fees.u256_le(m.fee_token_amount).u256_le(m.fee_value_juels);
    let mut extra = Writer::new();
    extra.borsh_bytes(&m.extra_args);
    let mut h = Keccak256::new();
    h.update([0u8; 32]);
    h.update(b"SVM2AnyMessageHashV1");
    h.update(m.source_selector.to_be_bytes());
    h.update(m.dest_selector.to_be_bytes());
    h.update(on_ramp);
    h.update(m.sender);
    h.update(m.sequence.to_be_bytes());
    h.update(m.nonce.to_be_bytes());
    h.update(m.fee_token);
    h.update(fees.into_bytes());
    h.update([m.receiver.len() as u8]);
    h.update(&m.receiver);
    h.update((m.data.len() as u16).to_be_bytes());
    h.update(&m.data);
    h.update(tokens.into_bytes());
    h.update(extra.into_bytes());
    h.finalize().into()
}

/// The Solana adapter. See the module docs.
pub struct SolanaCcipAdapter;

impl SolanaCcipAdapter {
    fn check_route(route: &BridgeRoute) -> Result<()> {
        if route.source_chain_id != SOLANA_SELECTOR {
            return Err(bad(format!(
                "route selector {} is not Solana's {SOLANA_SELECTOR}",
                route.source_chain_id
            )));
        }
        Ok(())
    }
}

impl RouteAdapter for SolanaCcipAdapter {
    fn transport(&self) -> BridgeRouteAdapter {
        BridgeRouteAdapter::Ccip
    }

    fn family(&self) -> ChainFamily {
        ChainFamily::Solana
    }

    fn decode_inbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        Self::check_route(route)?;
        let m = Svm2AnyMessage::read(r)?;
        if m.message_id != svm2any_message_id(&m, &route.ramp) {
            return Err(bad("message id is not the hash of the message"));
        }
        let [t] = m.token_amounts.as_slice() else {
            return Err(bad("a route transfer carries exactly one token transfer"));
        };
        let token: [u8; 32] = t
            .dest_token
            .as_slice()
            .try_into()
            .map_err(|_| bad("destination token must be a 32-byte Tenzro address"))?;
        Ok(RouteMessage {
            message_id: m.message_id,
            source_selector: m.source_selector,
            dest_selector: m.dest_selector,
            sequence: m.sequence,
            sender: m.sender.to_vec(),
            receiver: m.receiver.clone(),
            token_pool: t.source_pool,
            token,
            amount: t.amount,
        })
    }

    fn encode_outbound(&self, route: &BridgeRoute, msg: &RouteMessage) -> Result<Vec<u8>> {
        Self::check_route(route)?;
        let receiver: [u8; 32] = msg
            .receiver
            .as_slice()
            .try_into()
            .map_err(|_| bad("a Solana recipient is a 32-byte public key"))?;
        let mut w = Writer::new();
        w.raw(&msg.message_id)
            .u64_le(msg.source_selector)
            .u64_le(msg.dest_selector)
            .u64_le(msg.sequence)
            .u64_le(0)
            .borsh_bytes(&msg.sender)
            .borsh_bytes(&[])
            .raw(&receiver)
            .u32_le(1)
            .borsh_bytes(&msg.token_pool)
            .raw(&msg.token)
            .u32_le(DEST_POOL_GAS)
            .borsh_bytes(&[])
            .u256_le(msg.amount)
            .u32_le(OUTBOUND_COMPUTE_UNITS)
            .u64_le(0);
        Ok(w.into_bytes())
    }

    fn decode_outbound(&self, _route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        let message_id = r.array()?;
        let source_selector = r.u64_le()?;
        let dest_selector = r.u64_le()?;
        let sequence = r.u64_le()?;
        let nonce = r.u64_le()?;
        let sender = r.borsh_bytes(64)?;
        let data = r.borsh_bytes(MAX_FIELD_LEN)?;
        let receiver: [u8; 32] = r.array()?;
        if r.borsh_len(MAX_TOKEN_TRANSFERS)? != 1 {
            return Err(bad(
                "an outbound transfer carries exactly one token transfer",
            ));
        }
        let pool = r.borsh_bytes(32)?;
        let token: [u8; 32] = r.array()?;
        let gas = r.u32_le()?;
        let extra = r.borsh_bytes(MAX_FIELD_LEN)?;
        let amount = r.u256_le_as_u128()?;
        let compute_units = r.u32_le()?;
        let writable = r.u64_le()?;
        if nonce != 0
            || !data.is_empty()
            || !extra.is_empty()
            || gas != DEST_POOL_GAS
            || compute_units != OUTBOUND_COMPUTE_UNITS
            || writable != 0
        {
            return Err(bad(
                "an outbound transfer carries no nonce, data or custom execution",
            ));
        }
        let token_pool: [u8; 32] = pool
            .as_slice()
            .try_into()
            .map_err(|_| bad("source pool must be 32 bytes"))?;
        Ok(RouteMessage {
            message_id,
            source_selector,
            dest_selector,
            sequence,
            sender,
            receiver: receiver.to_vec(),
            token_pool,
            token,
            amount,
        })
    }

    /// Tenzro, as the sending chain, assigns the id over the lane, the
    /// sequence number, the parties, the token and the amount.
    /// Slots until the `finalized` commitment covers the message's slot.
    fn finality_depth(&self, route: &BridgeRoute) -> Result<u64> {
        Self::check_route(route)?;
        Ok(32)
    }

    fn outbound_message_id(&self, route: &BridgeRoute, msg: &RouteMessage) -> Result<[u8; 32]> {
        let mut h = Keccak256::new();
        h.update(b"Any2SVMMessageHashV1");
        h.update(msg.source_selector.to_be_bytes());
        h.update(msg.dest_selector.to_be_bytes());
        h.update(route.local_endpoint);
        h.update(msg.sequence.to_be_bytes());
        h.update((msg.sender.len() as u32).to_be_bytes());
        h.update(&msg.sender);
        h.update((msg.receiver.len() as u32).to_be_bytes());
        h.update(&msg.receiver);
        h.update(msg.token);
        h.update(msg.amount.to_be_bytes());
        Ok(h.finalize().into())
    }
}

/// Bytes of an encoded [`SolanaExecution`].
pub const EXECUTION_LEN: usize = 64 + 8 + 1;

/// The status byte of a transaction that succeeded.
const SUCCEEDED: u8 = 1;

/// What each verifier of a Solana route attests about the transaction that
/// emitted a message, read from its own RPC provider at finalized
/// commitment: the transaction succeeded.
///
/// ```text
/// signature 64 | slot u64 big-endian | status u8 (1: succeeded)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolanaExecution {
    /// The transaction's signature, which names it.
    pub signature: [u8; 64],
    /// The slot it executed in.
    pub slot: u64,
}

impl SolanaExecution {
    /// The record in the one layout [`SolanaExecution::decode`] accepts.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(&self.signature).u64_be(self.slot).u8(SUCCEEDED);
        w.into_bytes()
    }

    /// Decode a record, refusing any other layout and any transaction that
    /// did not succeed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let signature = r.array::<64>()?;
        let slot = r.u64_be()?;
        let status = r.u8()?;
        r.finish()?;
        if status != SUCCEEDED {
            return Err(bad("the attested transaction did not succeed"));
        }
        Ok(Self { signature, slot })
    }
}

/// The discriminator of the router's `CCIPMessageSent` event: the first
/// eight bytes of SHA-256 over `event:CCIPMessageSent`.
fn ccip_message_sent_discriminator() -> [u8; 8] {
    let d = sha2::Sha256::digest(b"event:CCIPMessageSent");
    d[..8].try_into().expect("eight bytes")
}

fn field<'a>(v: &'a serde_json::Value, path: &[&str]) -> Result<&'a serde_json::Value> {
    path.iter()
        .try_fold(v, |v, k| v.get(*k))
        .ok_or_else(|| bad(format!("the transaction has no {}", path.join("."))))
}

/// What a verifier attests for one Solana transaction: every CCIP message
/// it sent to Tenzro over `route`, and its execution record.
///
/// `tx` is the transaction as the `getTransaction` RPC returns it in the
/// `json` encoding, read at finalized commitment from the verifier's own
/// provider. The transaction must have succeeded; a message counts only if
/// the route's router program itself logged it (as the `CCIPMessageSent`
/// event, while it was the executing program), for the route's lane, with
/// the id its content hashes to. Truncated logs are refused, since a message
/// could be missing from them.
pub fn attest_transaction(
    route: &BridgeRoute,
    tx: &serde_json::Value,
) -> Result<(Vec<Svm2AnyMessage>, SolanaExecution)> {
    use base64::Engine as _;

    SolanaCcipAdapter::check_route(route)?;
    let meta = field(tx, &["meta"])?;
    if !field(meta, &["err"])?.is_null() {
        return Err(bad("the transaction failed"));
    }
    let slot = field(tx, &["slot"])?
        .as_u64()
        .ok_or_else(|| bad("slot is not a number"))?;
    let signature: [u8; 64] = field(tx, &["transaction", "signatures"])?
        .get(0)
        .and_then(|s| s.as_str())
        .and_then(|s| bs58::decode(s).into_vec().ok())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad("the transaction's first signature is not 64 base58 bytes"))?;
    let logs = field(meta, &["logMessages"])?
        .as_array()
        .ok_or_else(|| bad("logMessages is not a list"))?;

    let router = bs58::encode(route.ramp).into_string();
    let discriminator = ccip_message_sent_discriminator();
    let mut stack: Vec<&str> = Vec::new();
    let mut messages = Vec::new();
    for line in logs {
        let line = line.as_str().ok_or_else(|| bad("a log line is not text"))?;
        if line.starts_with("Log truncated") {
            return Err(bad("the transaction's logs are truncated"));
        }
        let words: Vec<&str> = line.split(' ').collect();
        match words.as_slice() {
            ["Program", id, "invoke", _] => stack.push(id),
            ["Program", id, "success"] | ["Program", id, "failed:", ..] => {
                if stack.pop() != Some(*id) {
                    return Err(bad("the program log is not well nested"));
                }
            }
            ["Program", "data:", chunks @ ..] if stack.last() == Some(&router.as_str()) => {
                let [chunk] = chunks else { continue };
                let data = base64::engine::general_purpose::STANDARD
                    .decode(chunk)
                    .map_err(|_| bad("event data is not base64"))?;
                if data.len() < 24 || data[..8] != discriminator {
                    continue;
                }
                let dest_selector =
                    u64::from_le_bytes(data[8..16].try_into().expect("eight bytes"));
                if dest_selector != route.local_selector {
                    continue;
                }
                let mut r = Reader::new(&data[24..]);
                let m = Svm2AnyMessage::read(&mut r)?;
                r.finish()?;
                let sequence = u64::from_le_bytes(data[16..24].try_into().expect("eight bytes"));
                if m.sequence != sequence
                    || m.dest_selector != dest_selector
                    || m.source_selector != SOLANA_SELECTOR
                {
                    return Err(bad("the event's lane does not match its message"));
                }
                if m.message_id != svm2any_message_id(&m, &route.ramp) {
                    return Err(bad("message id is not the hash of the message"));
                }
                messages.push(m);
            }
            _ => {}
        }
    }
    if messages.is_empty() {
        return Err(bad(
            "the route's router sent no message to Tenzro in this transaction",
        ));
    }
    Ok((messages, SolanaExecution { signature, slot }))
}

/// The most of `signers` that are pairwise independent: no two share an
/// operator or an RPC provider. A maximum bipartite matching of operators to
/// providers, each matched pair one signer.
fn independent_signers(quorum: &VerifierQuorum, signers: &[[u8; 20]]) -> usize {
    let mut edges: HashMap<&str, Vec<&str>> = HashMap::new();
    for m in quorum
        .members
        .iter()
        .filter(|m| signers.contains(&m.address))
    {
        edges
            .entry(m.operator.trim())
            .or_default()
            .push(m.rpc_provider.trim());
    }
    fn augment<'a>(
        op: &'a str,
        edges: &HashMap<&'a str, Vec<&'a str>>,
        seen: &mut Vec<&'a str>,
        owner: &mut HashMap<&'a str, &'a str>,
    ) -> bool {
        for &rpc in &edges[op] {
            if seen.contains(&rpc) {
                continue;
            }
            seen.push(rpc);
            let free = match owner.get(rpc).copied() {
                None => true,
                Some(other) => augment(other, edges, seen, owner),
            };
            if free {
                owner.insert(rpc, op);
                return true;
            }
        }
        false
    }
    let mut owner: HashMap<&str, &str> = HashMap::new();
    let ops: Vec<&str> = edges.keys().copied().collect();
    ops.into_iter()
        .filter(|op| augment(op, &edges, &mut Vec::new(), &mut owner))
        .count()
}

/// Check what a Solana delivery must carry beyond the committee quorum: an
/// execution record of a successful transaction as its proof, and the
/// route's threshold of signatures over `digest` from verifiers independent
/// in operator and RPC provider.
pub fn check_execution(
    route: &BridgeRoute,
    digest: &[u8; 32],
    delivery: &Delivery,
) -> Result<SolanaExecution> {
    let execution = SolanaExecution::decode(&delivery.proof)?;
    let signers = super::attestation::dual_signers(
        &route.verifiers,
        digest,
        &delivery.committee,
        &delivery.committee_pq,
    );
    let independent = independent_signers(&route.verifiers, &signers);
    if independent < route.verifiers.threshold as usize {
        return Err(BridgeError::AdapterError(format!(
            "verifiers: {independent} independent attestations of the Solana transaction < threshold {}",
            route.verifiers.threshold
        )));
    }
    Ok(execution)
}
