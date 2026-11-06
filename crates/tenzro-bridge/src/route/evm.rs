//! The EVM-family adapter: Ethereum, its rollups and the other EVM chains
//! (BNB Chain, Avalanche C-Chain, Polygon PoS) share it, with one entry per
//! chain in [`EVM_CHAINS`].
//!
//! It speaks the CCIP message envelope as the published CCIP contracts
//! define it:
//!
//! - **Inbound** (EVM to Tenzro): the data of the on-ramp's message event,
//!   in the layout of the on-ramp version the route's lane declares
//!   ([`CcipLaneVersion`]); [`read_onramp_message`] reads all three in one
//!   place and refuses any other layout:
//!   - `2.0.0`: `CCIPMessageSent(destChainSelector, sender, messageId,
//!     feeToken, amount, encodedMessage, receipts, verifierBlobs)`. The
//!     message id is the keccak-256 of `encodedMessage`, the chain-agnostic
//!     message (version byte 1), which names the on-ramp itself.
//!   - `1.6.0`: `CCIPMessageSent(destChainSelector, sequenceNumber,
//!     EVM2AnyRampMessage)`. The message id is the on-ramp's hash of the
//!     message under the lane's metadata (selectors and on-ramp).
//!   - `1.5.0`: `CCIPSendRequested(EVM2EVMMessage)`, from an on-ramp that
//!     serves this lane alone. The message id is the on-ramp's hash of the
//!     message under the lane's metadata. The receiver is a 20-byte address,
//!     the Tenzro account it names with twelve zero bytes appended.
//!
//!   In every version the message id is recomputed here from the route's
//!   on-ramp (`ramp`) and chain selectors and must match.
//! - **Outbound** (Tenzro to EVM): the message the lane's off-ramp executes,
//!   in the lane's version: for `2.0.0` the chain-agnostic [`MessageV1`]
//!   naming the off-ramp from the lane's route config, whose keccak-256 is
//!   the message id; for `1.6.0` the ABI encoding of `Any2EVMRampMessage`.
//!   A `1.5.0` lane runs between EVM chains only and carries nothing out.
//!   Outbound transfers carry no data and no receiver callback.

use sha3::{Digest, Keccak256};

use super::canonical::{Reader, Writer};
use super::{
    BridgeRoute, BridgeRouteAdapter, CcipLaneVersion, ChainFamily, RouteAdapter, RouteMessage,
};
use crate::error::{BridgeError, Result};

/// One EVM chain the adapter serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvmChain {
    /// Route chain name.
    pub name: &'static str,
    /// EIP-155 chain id.
    pub chain_id: u64,
    /// The chain's CCIP chain selector.
    pub selector: u64,
    /// Blocks a message's block is buried under before the chain's own
    /// rule makes it final; committee members attest only final blocks.
    pub finality_depth: u64,
}

/// The EVM chains the adapter serves. A route for any other chain name, or
/// with a selector that does not match the chain, carries nothing.
pub const EVM_CHAINS: &[EvmChain] = &[
    EvmChain {
        name: "ethereum",
        chain_id: 1,
        selector: 5_009_297_550_715_157_269,
        // Two epochs: the Casper FFG finalized checkpoint.
        finality_depth: 64,
    },
    EvmChain {
        name: "base",
        chain_id: 8_453,
        selector: 15_971_525_489_660_198_786,
        // The OP Stack finalized head: the batch is in a finalized Ethereum block.
        finality_depth: 1_800,
    },
    EvmChain {
        name: "arbitrum",
        chain_id: 42_161,
        selector: 4_949_039_107_694_359_620,
        // The batch is in a finalized Ethereum block.
        finality_depth: 4_800,
    },
    EvmChain {
        name: "optimism",
        chain_id: 10,
        selector: 3_734_403_246_176_062_136,
        // The OP Stack finalized head: the batch is in a finalized Ethereum block.
        finality_depth: 1_800,
    },
    EvmChain {
        name: "bnb",
        chain_id: 56,
        selector: 11_344_663_589_394_136_015,
        // Fast finality: two thirds of validators voted for the block.
        finality_depth: 3,
    },
    EvmChain {
        name: "avalanche",
        chain_id: 43_114,
        selector: 6_433_500_567_565_415_381,
        // Snowman: a block is final once accepted.
        finality_depth: 1,
    },
    EvmChain {
        name: "polygon",
        chain_id: 137,
        selector: 4_051_577_828_743_386_545,
        // A Heimdall milestone covers the block.
        finality_depth: 16,
    },
];

/// Gas the destination token pool may use to mint, per outbound transfer.
pub const DEST_POOL_GAS: u32 = 90_000;

/// Most token transfers one message may carry. A route transfer carries one.
const MAX_TOKEN_TRANSFERS: usize = 1;

/// Largest variable-length field accepted in a message.
const MAX_FIELD_LEN: usize = 16 * 1024;

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("CCIP EVM message: {}", what.into()))
}

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_u128(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_addr(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn pad32(b: &[u8]) -> Result<[u8; 32]> {
    if b.len() > 32 {
        return Err(bad("address longer than 32 bytes"));
    }
    let mut w = [0u8; 32];
    w[32 - b.len()..].copy_from_slice(b);
    Ok(w)
}

/// The 20-byte address in a left-padded 32-byte field.
pub fn evm_address(w: &[u8; 32]) -> Result<[u8; 20]> {
    if w[..12].iter().any(|b| *b != 0) {
        return Err(bad("field is not a 20-byte address"));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&w[12..]);
    Ok(a)
}

/// One field of an ABI tuple being written.
pub enum Field {
    /// A static word.
    Word([u8; 32]),
    /// A dynamic value's encoding, placed in the tail.
    Tail(Vec<u8>),
}

/// The ABI encoding of a tuple (or, behind a length word, an array).
pub fn abi_tuple(fields: &[Field]) -> Vec<u8> {
    let head_len = fields.len() * 32;
    let mut head = Writer::new();
    let mut tail = Writer::new();
    for f in fields {
        match f {
            Field::Word(w) => {
                head.raw(w);
            }
            Field::Tail(t) => {
                head.abi_uint((head_len + tail.len()) as u128);
                tail.raw(t);
            }
        }
    }
    let mut out = head.into_bytes();
    out.extend_from_slice(&tail.into_bytes());
    out
}

/// The ABI encoding of a `bytes` value.
pub fn abi_bytes(b: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.abi_bytes(b);
    w.into_bytes()
}

/// The ABI encoding of an array of dynamic tuples.
pub fn abi_array(items: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = word_u64(items.len() as u64).to_vec();
    let fields: Vec<Field> = items.into_iter().map(Field::Tail).collect();
    out.extend_from_slice(&abi_tuple(&fields));
    out
}

/// The CCIP message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RampHeader {
    /// Message id.
    pub message_id: [u8; 32],
    /// Sending chain selector.
    pub source_selector: u64,
    /// Receiving chain selector.
    pub dest_selector: u64,
    /// Per-lane sequence number.
    pub sequence: u64,
    /// Per-sender nonce; zero for out-of-order messages.
    pub nonce: u64,
}

impl RampHeader {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            message_id: r.word()?,
            source_selector: r.abi_u64()?,
            dest_selector: r.abi_u64()?,
            sequence: r.abi_u64()?,
            nonce: r.abi_u64()?,
        })
    }

    fn fields(&self) -> [Field; 5] {
        [
            Field::Word(self.message_id),
            Field::Word(word_u64(self.source_selector)),
            Field::Word(word_u64(self.dest_selector)),
            Field::Word(word_u64(self.sequence)),
            Field::Word(word_u64(self.nonce)),
        ]
    }
}

/// `EVM2AnyTokenTransfer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evm2AnyTokenTransfer {
    /// The source pool.
    pub source_pool: [u8; 20],
    /// The destination token, as the destination encodes it.
    pub dest_token: Vec<u8>,
    /// Pool data.
    pub extra_data: Vec<u8>,
    /// Amount.
    pub amount: u128,
    /// Destination execution data.
    pub dest_exec_data: Vec<u8>,
}

impl Evm2AnyTokenTransfer {
    /// ABI encoding of the tuple.
    pub fn encode(&self) -> Vec<u8> {
        abi_tuple(&[
            Field::Word(word_addr(&self.source_pool)),
            Field::Tail(abi_bytes(&self.dest_token)),
            Field::Tail(abi_bytes(&self.extra_data)),
            Field::Word(word_u128(self.amount)),
            Field::Tail(abi_bytes(&self.dest_exec_data)),
        ])
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let base = r.position();
        let source_pool = r.abi_address()?;
        let o_token = r.abi_offset()?;
        let o_extra = r.abi_offset()?;
        let amount = r.abi_u256_as_u128()?;
        let o_exec = r.abi_offset()?;
        r.abi_expect_tail(base, o_token)?;
        let dest_token = r.abi_bytes(MAX_FIELD_LEN)?;
        r.abi_expect_tail(base, o_extra)?;
        let extra_data = r.abi_bytes(MAX_FIELD_LEN)?;
        r.abi_expect_tail(base, o_exec)?;
        let dest_exec_data = r.abi_bytes(MAX_FIELD_LEN)?;
        Ok(Self {
            source_pool,
            dest_token,
            extra_data,
            amount,
            dest_exec_data,
        })
    }
}

/// `EVM2AnyRampMessage`, the message an EVM on-ramp emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evm2AnyMessage {
    /// Header.
    pub header: RampHeader,
    /// The account that called the router.
    pub sender: [u8; 20],
    /// Arbitrary data.
    pub data: Vec<u8>,
    /// The receiver, as the destination encodes it.
    pub receiver: Vec<u8>,
    /// Extra arguments.
    pub extra_args: Vec<u8>,
    /// Fee token.
    pub fee_token: [u8; 20],
    /// Fee paid, in the fee token.
    pub fee_token_amount: u128,
    /// Fee value in juels.
    pub fee_value_juels: u128,
    /// Token transfers.
    pub token_amounts: Vec<Evm2AnyTokenTransfer>,
}

fn read_array<T>(
    r: &mut Reader<'_>,
    max: usize,
    item: impl Fn(&mut Reader<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    let n = r.abi_offset()?;
    if n > max {
        return Err(bad(format!("an array of {n} items; at most {max}")));
    }
    let base = r.position();
    let offsets = (0..n).map(|_| r.abi_offset()).collect::<Result<Vec<_>>>()?;
    offsets
        .into_iter()
        .map(|o| {
            r.abi_expect_tail(base, o)?;
            item(r)
        })
        .collect()
}

impl Evm2AnyMessage {
    /// `abi.encode(message)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut fields: Vec<Field> = self.header.fields().into_iter().collect();
        fields.extend([
            Field::Word(word_addr(&self.sender)),
            Field::Tail(abi_bytes(&self.data)),
            Field::Tail(abi_bytes(&self.receiver)),
            Field::Tail(abi_bytes(&self.extra_args)),
            Field::Word(word_addr(&self.fee_token)),
            Field::Word(word_u128(self.fee_token_amount)),
            Field::Word(word_u128(self.fee_value_juels)),
            Field::Tail(self.tokens_encoding()),
        ]);
        abi_tuple(&[Field::Tail(abi_tuple(&fields))])
    }

    fn tokens_encoding(&self) -> Vec<u8> {
        abi_array(self.token_amounts.iter().map(|t| t.encode()).collect())
    }

    /// Read `abi.encode(message)` through `r`.
    pub fn read(r: &mut Reader<'_>) -> Result<Self> {
        let outer = r.abi_offset()?;
        r.abi_expect_tail(0, outer)?;
        let base = r.position();
        let header = RampHeader::read(r)?;
        let sender = r.abi_address()?;
        let o_data = r.abi_offset()?;
        let o_receiver = r.abi_offset()?;
        let o_extra = r.abi_offset()?;
        let fee_token = r.abi_address()?;
        let fee_token_amount = r.abi_u256_as_u128()?;
        let fee_value_juels = r.abi_u256_as_u128()?;
        let o_tokens = r.abi_offset()?;
        r.abi_expect_tail(base, o_data)?;
        let data = r.abi_bytes(MAX_FIELD_LEN)?;
        r.abi_expect_tail(base, o_receiver)?;
        let receiver = r.abi_bytes(64)?;
        r.abi_expect_tail(base, o_extra)?;
        let extra_args = r.abi_bytes(MAX_FIELD_LEN)?;
        r.abi_expect_tail(base, o_tokens)?;
        let token_amounts = read_array(r, MAX_TOKEN_TRANSFERS, Evm2AnyTokenTransfer::read)?;
        Ok(Self {
            header,
            sender,
            data,
            receiver,
            extra_args,
            fee_token,
            fee_token_amount,
            fee_value_juels,
            token_amounts,
        })
    }

    /// The on-ramp's hash of this message, which is its message id.
    pub fn hash(&self, on_ramp: &[u8; 20]) -> [u8; 32] {
        let tag = keccak(&[b"EVM2AnyMessageHashV1"]);
        let metadata = keccak(&[
            &tag,
            &word_u64(self.header.source_selector),
            &word_u64(self.header.dest_selector),
            &word_addr(on_ramp),
        ]);
        let fixed = keccak(&[
            &word_addr(&self.sender),
            &word_u64(self.header.sequence),
            &word_u64(self.header.nonce),
            &word_addr(&self.fee_token),
            &word_u128(self.fee_token_amount),
        ]);
        let tokens = abi_tuple(&[Field::Tail(self.tokens_encoding())]);
        keccak(&[
            &[0u8; 32],
            &metadata,
            &fixed,
            &keccak(&[&self.receiver]),
            &keccak(&[&self.data]),
            &keccak(&[&tokens]),
            &keccak(&[&self.extra_args]),
        ])
    }
}

/// Most receipts and verifier blobs a `2.0.0` message event may carry.
const MAX_RECEIPTS: usize = 32;

/// The token a message moves, in any lane version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnRampToken {
    /// The source token pool.
    pub source_pool: [u8; 20],
    /// The destination token, as the destination encodes it.
    pub dest_token: Vec<u8>,
    /// Amount in the smallest unit.
    pub amount: u128,
}

/// One message an on-ramp emitted towards Tenzro, read in its lane's
/// version and with its message id checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnRampMessage {
    /// Message id.
    pub message_id: [u8; 32],
    /// Sending chain selector.
    pub source_selector: u64,
    /// Receiving chain selector.
    pub dest_selector: u64,
    /// Per-lane sequence (message) number.
    pub sequence: u64,
    /// The account that called the router.
    pub sender: [u8; 20],
    /// The Tenzro account the message (or its tokens) is delivered to.
    pub receiver: Vec<u8>,
    /// Arbitrary data.
    pub data: Vec<u8>,
    /// The token moved, if any.
    pub token: Option<OnRampToken>,
}

/// The lane version a CCIP route declares.
pub fn lane_version(route: &BridgeRoute) -> Result<CcipLaneVersion> {
    route
        .lane_limits
        .map(|l| l.version)
        .ok_or_else(|| bad("the route declares no CCIP lane"))
}

/// The topic of the event the lane's on-ramp emits for each message.
pub fn onramp_event_topic(version: CcipLaneVersion) -> [u8; 32] {
    let signature: &[u8] = match version {
        CcipLaneVersion::V2_0 => {
            b"CCIPMessageSent(uint64,address,bytes32,address,uint256,bytes,(address,uint32,uint32,uint256,bytes)[],bytes[])"
        }
        CcipLaneVersion::V1_6 => {
            b"CCIPMessageSent(uint64,uint64,((bytes32,uint64,uint64,uint64,uint64),address,bytes,bytes,bytes,address,\
uint256,uint256,(address,bytes,bytes,uint256,bytes)[]))"
        }
        CcipLaneVersion::V1_5 => {
            b"CCIPSendRequested((uint64,address,address,uint64,uint256,bool,uint64,address,uint256,bytes,(address,uint256)[],\
bytes[],bytes32))"
        }
    };
    keccak(&[signature])
}

/// Whether a log with `topics` and `data` is the message event of the
/// route's lane, of version `version`, towards Tenzro: its event topic, the
/// destination it indexes, and data that reads as the lane's message. A
/// `2.0.0` or `1.6.0` event names the destination in its first indexed topic
/// (and a `2.0.0` event the message id, which must be the hash of the
/// message it carries); a `1.5.0` on-ramp serves one destination and indexes
/// nothing, so its message id, which commits to the destination, binds it.
pub fn onramp_log_matches(
    version: CcipLaneVersion,
    topics: &[[u8; 32]],
    data: &[u8],
    route: &BridgeRoute,
) -> bool {
    let count = match version {
        CcipLaneVersion::V2_0 => 4,
        CcipLaneVersion::V1_6 => 3,
        CcipLaneVersion::V1_5 => 1,
    };
    if topics.len() != count
        || topics[0] != onramp_event_topic(version)
        || (count > 1 && topics[1] != word_u64(route.local_selector))
        || lane_version(route).ok() != Some(version)
    {
        return false;
    }
    let mut r = Reader::new(data);
    let Ok(m) = read_onramp_message(route, &mut r) else {
        return false;
    };
    r.finish().is_ok() && (version != CcipLaneVersion::V2_0 || topics[3] == m.message_id)
}

/// Read one on-ramp message from `r`, in the layout of the lane version
/// `route` declares, and check its message id against the route's on-ramp
/// and selectors. A message in any other version's layout is refused.
pub fn read_onramp_message(route: &BridgeRoute, r: &mut Reader<'_>) -> Result<OnRampMessage> {
    let on_ramp = evm_address(&route.ramp)?;
    match lane_version(route)? {
        CcipLaneVersion::V2_0 => read_v2_0(route, r),
        CcipLaneVersion::V1_6 => {
            let m = Evm2AnyMessage::read(r)?;
            if m.header.message_id != m.hash(&on_ramp) {
                return Err(bad("message id is not the on-ramp's hash of the message"));
            }
            let token = match m.token_amounts.as_slice() {
                [] => None,
                [t] => Some(OnRampToken {
                    source_pool: t.source_pool,
                    dest_token: t.dest_token.clone(),
                    amount: t.amount,
                }),
                _ => return Err(bad("a message carries at most one token transfer")),
            };
            Ok(OnRampMessage {
                message_id: m.header.message_id,
                source_selector: m.header.source_selector,
                dest_selector: m.header.dest_selector,
                sequence: m.header.sequence,
                sender: m.sender,
                receiver: m.receiver,
                data: m.data,
                token,
            })
        }
        CcipLaneVersion::V1_5 => read_v1_5(route, &on_ramp, r),
    }
}

/// `2.0.0`: the event data, then the chain-agnostic message inside it.
fn read_v2_0(route: &BridgeRoute, r: &mut Reader<'_>) -> Result<OnRampMessage> {
    let _fee_token = r.abi_address()?;
    let _amount_before_fees = r.abi_u256_as_u128()?;
    let o_message = r.abi_offset()?;
    let o_receipts = r.abi_offset()?;
    let o_blobs = r.abi_offset()?;
    r.abi_expect_tail(0, o_message)?;
    let encoded = r.abi_bytes(MAX_FIELD_LEN)?;
    r.abi_expect_tail(0, o_receipts)?;
    read_array(r, MAX_RECEIPTS, |r| {
        let base = r.position();
        let _issuer = r.abi_address()?;
        let _dest_gas_limit = r.abi_u32()?;
        let _dest_bytes_overhead = r.abi_u32()?;
        let _fee_token_amount = r.abi_u256_as_u128()?;
        let o_extra = r.abi_offset()?;
        r.abi_expect_tail(base, o_extra)?;
        r.abi_bytes(MAX_FIELD_LEN)
    })?;
    r.abi_expect_tail(0, o_blobs)?;
    read_array(r, MAX_RECEIPTS, |r| r.abi_bytes(MAX_FIELD_LEN))?;

    let m = MessageV1::read(&encoded)?;
    if m.on_ramp.as_slice() != route.ramp {
        return Err(bad("the message does not name the route's on-ramp"));
    }
    let sender: [u8; 32] = m
        .sender
        .as_slice()
        .try_into()
        .map_err(|_| bad("the sender is not an encoded EVM address"))?;
    let (receiver, token) = match m.token_transfer {
        None => (m.receiver, None),
        Some(t) => {
            let source_pool: [u8; 32] = t
                .source_pool
                .as_slice()
                .try_into()
                .map_err(|_| bad("the source pool is not an encoded EVM address"))?;
            (
                t.token_receiver,
                Some(OnRampToken {
                    source_pool: evm_address(&source_pool)?,
                    dest_token: t.dest_token,
                    amount: t.amount,
                }),
            )
        }
    };
    Ok(OnRampMessage {
        message_id: keccak(&[&encoded]),
        source_selector: m.source_selector,
        dest_selector: m.dest_selector,
        sequence: m.sequence,
        sender: evm_address(&sender)?,
        receiver,
        data: m.data,
        token,
    })
}

/// The token transfer inside a [`MessageV1`] (token transfer version 1).
/// Every address is in the encoding of the chain it lives on: the source
/// pool and token in the sending chain's, the destination token and the
/// token receiver in the receiving chain's (20 bytes on an EVM chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenTransferV1 {
    /// Amount in the smallest unit of the source token.
    pub amount: u128,
    /// The token pool on the sending chain.
    pub source_pool: Vec<u8>,
    /// The token on the sending chain.
    pub source_token: Vec<u8>,
    /// The token on the receiving chain.
    pub dest_token: Vec<u8>,
    /// Who receives the tokens on the receiving chain.
    pub token_receiver: Vec<u8>,
    /// The source pool's data for the destination pool.
    pub extra_data: Vec<u8>,
}

/// The chain-agnostic CCIP message of a `2.0.0` lane (message version 1):
/// big-endian integers, then length-prefixed byte strings (one length byte
/// for addresses, two for the blobs). Its keccak-256 is the message id. An
/// on-ramp emits it inside `CCIPMessageSent`; an off-ramp executes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageV1 {
    /// Sending chain selector.
    pub source_selector: u64,
    /// Receiving chain selector.
    pub dest_selector: u64,
    /// Per-lane sequence number.
    pub sequence: u64,
    /// Gas the receiving chain spends executing the message.
    pub execution_gas_limit: u32,
    /// Gas for the receiver's callback; zero when no callback runs.
    pub receive_gas_limit: u32,
    /// The finality the sender asked for; zero is the chain's default.
    pub finality: [u8; 4],
    /// The hash over the verifiers and executor the message requires.
    pub ccv_and_executor_hash: [u8; 32],
    /// The sending chain's on-ramp.
    pub on_ramp: Vec<u8>,
    /// The receiving chain's off-ramp.
    pub off_ramp: Vec<u8>,
    /// The sender on the sending chain.
    pub sender: Vec<u8>,
    /// The receiver on the receiving chain.
    pub receiver: Vec<u8>,
    /// Data for the receiving chain's executor.
    pub dest_blob: Vec<u8>,
    /// At most one token transfer.
    pub token_transfer: Option<TokenTransferV1>,
    /// Data for the receiver.
    pub data: Vec<u8>,
}

fn write_short(w: &mut Writer, b: &[u8]) -> Result<()> {
    let len = u8::try_from(b.len()).map_err(|_| bad("an address field exceeds 255 bytes"))?;
    w.u8(len).raw(b);
    Ok(())
}

fn write_long(w: &mut Writer, b: &[u8]) -> Result<()> {
    let len = u16::try_from(b.len()).map_err(|_| bad("a blob field exceeds 65535 bytes"))?;
    w.u16_be(len).raw(b);
    Ok(())
}

fn read_short(r: &mut Reader<'_>) -> Result<Vec<u8>> {
    let len = r.u8()? as usize;
    Ok(r.take(len)?.to_vec())
}

fn read_long(r: &mut Reader<'_>) -> Result<Vec<u8>> {
    let len = r.u16_be()? as usize;
    Ok(r.take(len)?.to_vec())
}

impl TokenTransferV1 {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(1).raw(&word_u128(self.amount));
        write_short(&mut w, &self.source_pool)?;
        write_short(&mut w, &self.source_token)?;
        write_short(&mut w, &self.dest_token)?;
        write_short(&mut w, &self.token_receiver)?;
        write_long(&mut w, &self.extra_data)?;
        Ok(w.into_bytes())
    }

    fn read(b: &[u8]) -> Result<Self> {
        let mut t = Reader::new(b);
        if t.u8()? != 1 {
            return Err(bad("the token transfer is not token transfer version 1"));
        }
        let amount = t.abi_u256_as_u128()?;
        let out = Self {
            amount,
            source_pool: read_short(&mut t)?,
            source_token: read_short(&mut t)?,
            dest_token: read_short(&mut t)?,
            token_receiver: read_short(&mut t)?,
            extra_data: read_long(&mut t)?,
        };
        t.finish()?;
        Ok(out)
    }
}

impl MessageV1 {
    /// The message's bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(1)
            .u64_be(self.source_selector)
            .u64_be(self.dest_selector)
            .u64_be(self.sequence)
            .u32_be(self.execution_gas_limit)
            .u32_be(self.receive_gas_limit)
            .raw(&self.finality)
            .raw(&self.ccv_and_executor_hash);
        write_short(&mut w, &self.on_ramp)?;
        write_short(&mut w, &self.off_ramp)?;
        write_short(&mut w, &self.sender)?;
        write_short(&mut w, &self.receiver)?;
        write_long(&mut w, &self.dest_blob)?;
        let token = match &self.token_transfer {
            Some(t) => t.encode()?,
            None => Vec::new(),
        };
        write_long(&mut w, &token)?;
        write_long(&mut w, &self.data)?;
        Ok(w.into_bytes())
    }

    /// Read exactly one message from `b`.
    pub fn read(b: &[u8]) -> Result<Self> {
        let mut m = Reader::new(b);
        if m.u8()? != 1 {
            return Err(bad("the encoded message is not message version 1"));
        }
        let source_selector = m.u64_be()?;
        let dest_selector = m.u64_be()?;
        let sequence = m.u64_be()?;
        let execution_gas_limit = m.u32_be()?;
        let receive_gas_limit = m.u32_be()?;
        let finality = m.array::<4>()?;
        let ccv_and_executor_hash = m.array::<32>()?;
        let on_ramp = read_short(&mut m)?;
        let off_ramp = read_short(&mut m)?;
        let sender = read_short(&mut m)?;
        let receiver = read_short(&mut m)?;
        let dest_blob = read_long(&mut m)?;
        let token = read_long(&mut m)?;
        let data = read_long(&mut m)?;
        m.finish()?;
        let token_transfer = if token.is_empty() {
            None
        } else {
            Some(TokenTransferV1::read(&token)?)
        };
        Ok(Self {
            source_selector,
            dest_selector,
            sequence,
            execution_gas_limit,
            receive_gas_limit,
            finality,
            ccv_and_executor_hash,
            on_ramp,
            off_ramp,
            sender,
            receiver,
            dest_blob,
            token_transfer,
            data,
        })
    }
}

/// `1.5.0`: `abi.encode(EVM2EVMMessage)`.
fn read_v1_5(route: &BridgeRoute, on_ramp: &[u8; 20], r: &mut Reader<'_>) -> Result<OnRampMessage> {
    let outer = r.abi_offset()?;
    r.abi_expect_tail(0, outer)?;
    let base = r.position();
    let source_selector = r.abi_u64()?;
    let sender = r.abi_address()?;
    let receiver = r.abi_address()?;
    let sequence = r.abi_u64()?;
    let gas_limit = r.abi_u256_as_u128()?;
    let strict = r.abi_u64()?;
    if strict > 1 {
        return Err(bad("strict is not a boolean"));
    }
    let nonce = r.abi_u64()?;
    let fee_token = r.abi_address()?;
    let fee_token_amount = r.abi_u256_as_u128()?;
    let o_data = r.abi_offset()?;
    let o_tokens = r.abi_offset()?;
    let o_token_data = r.abi_offset()?;
    let message_id = r.word()?;
    r.abi_expect_tail(base, o_data)?;
    let data = r.abi_bytes(MAX_FIELD_LEN)?;
    r.abi_expect_tail(base, o_tokens)?;
    let n = r.abi_offset()?;
    if n > MAX_TOKEN_TRANSFERS {
        return Err(bad("a message carries at most one token transfer"));
    }
    let tokens = (0..n)
        .map(|_| Ok((r.abi_address()?, r.abi_u256_as_u128()?)))
        .collect::<Result<Vec<_>>>()?;
    r.abi_expect_tail(base, o_token_data)?;
    let token_data = read_array(r, MAX_TOKEN_TRANSFERS, |r| r.abi_bytes(MAX_FIELD_LEN))?;
    if token_data.len() != tokens.len() {
        return Err(bad("every token transfer carries its source token data"));
    }

    let metadata = keccak(&[
        &keccak(&[b"EVM2EVMMessageHashV2"]),
        &word_u64(source_selector),
        &word_u64(route.local_selector),
        &word_addr(on_ramp),
    ]);
    let fixed = keccak(&[
        &word_addr(&sender),
        &word_addr(&receiver),
        &word_u64(sequence),
        &word_u128(gas_limit),
        &word_u64(strict),
        &word_u64(nonce),
        &word_addr(&fee_token),
        &word_u128(fee_token_amount),
    ]);
    let mut token_words = word_u64(tokens.len() as u64).to_vec();
    for (token, amount) in &tokens {
        token_words.extend_from_slice(&word_addr(token));
        token_words.extend_from_slice(&word_u128(*amount));
    }
    let token_data_encoding = abi_array(token_data.iter().map(|d| abi_bytes(d)).collect());
    let hash = keccak(&[
        &[0u8; 32],
        &metadata,
        &fixed,
        &keccak(&[&data]),
        &keccak(&[&abi_tuple(&[Field::Tail(token_words)])]),
        &keccak(&[&abi_tuple(&[Field::Tail(token_data_encoding)])]),
    ]);
    if message_id != hash {
        return Err(bad("message id is not the on-ramp's hash of the message"));
    }

    let token = match (tokens.as_slice(), token_data.as_slice()) {
        ([], []) => None,
        ([(_, amount)], [pool_data]) => {
            // `abi.encode(SourceTokenData(sourcePoolAddress, destTokenAddress,
            // extraData, destGasAmount))`.
            let mut t = Reader::new(pool_data);
            let outer = t.abi_offset()?;
            t.abi_expect_tail(0, outer)?;
            let base = t.position();
            let o_pool = t.abi_offset()?;
            let o_dest = t.abi_offset()?;
            let o_extra = t.abi_offset()?;
            let _dest_gas = t.abi_u32()?;
            t.abi_expect_tail(base, o_pool)?;
            let pool = t.abi_bytes(32)?;
            t.abi_expect_tail(base, o_dest)?;
            let dest_token = t.abi_bytes(64)?;
            t.abi_expect_tail(base, o_extra)?;
            let _extra = t.abi_bytes(MAX_FIELD_LEN)?;
            t.finish()?;
            let pool: [u8; 32] = pool
                .as_slice()
                .try_into()
                .map_err(|_| bad("the source pool is not an encoded EVM address"))?;
            Some(OnRampToken {
                source_pool: evm_address(&pool)?,
                dest_token,
                amount: *amount,
            })
        }
        _ => return Err(bad("a message carries at most one token transfer")),
    };
    let mut tenzro_receiver = receiver.to_vec();
    tenzro_receiver.extend_from_slice(&[0u8; 12]);
    Ok(OnRampMessage {
        message_id,
        source_selector,
        dest_selector: route.local_selector,
        sequence,
        sender,
        receiver: tenzro_receiver,
        data,
        token,
    })
}

/// A data message the on-ramp of `route` emitted towards Tenzro: read
/// `body` strictly in the lane's version, check its message id, that it
/// travels the route's lane to the route's Tenzro endpoint and that it moves
/// no tokens. Returns its sender and its data.
pub fn data_message(route: &BridgeRoute, body: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    let mut r = Reader::new(body);
    let m = read_onramp_message(route, &mut r)?;
    r.finish()?;
    if m.source_selector != route.source_chain_id || m.dest_selector != route.local_selector {
        return Err(bad("the message does not travel the route's lane"));
    }
    if m.receiver.as_slice() != route.local_endpoint {
        return Err(bad(
            "the message is not addressed to the route's Tenzro endpoint",
        ));
    }
    if m.token.is_some() {
        return Err(bad("a data message moves no tokens"));
    }
    Ok((word_addr(&m.sender), m.data))
}

/// `Any2EVMTokenTransfer`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Any2EvmTokenTransfer {
    source_pool: Vec<u8>,
    dest_token: [u8; 20],
    dest_gas_amount: u32,
    extra_data: Vec<u8>,
    amount: u128,
}

impl Any2EvmTokenTransfer {
    fn encode(&self) -> Vec<u8> {
        abi_tuple(&[
            Field::Tail(abi_bytes(&self.source_pool)),
            Field::Word(word_addr(&self.dest_token)),
            Field::Word(word_u64(self.dest_gas_amount as u64)),
            Field::Tail(abi_bytes(&self.extra_data)),
            Field::Word(word_u128(self.amount)),
        ])
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let base = r.position();
        let o_pool = r.abi_offset()?;
        let dest_token = r.abi_address()?;
        let dest_gas_amount = r.abi_u32()?;
        let o_extra = r.abi_offset()?;
        let amount = r.abi_u256_as_u128()?;
        r.abi_expect_tail(base, o_pool)?;
        let source_pool = r.abi_bytes(64)?;
        r.abi_expect_tail(base, o_extra)?;
        let extra_data = r.abi_bytes(MAX_FIELD_LEN)?;
        Ok(Self {
            source_pool,
            dest_token,
            dest_gas_amount,
            extra_data,
            amount,
        })
    }
}

/// The EVM-family adapter. See the module docs.
pub struct EvmCcipAdapter {
    chains: &'static [EvmChain],
}

impl EvmCcipAdapter {
    /// The adapter over [`EVM_CHAINS`].
    pub fn new() -> Self {
        Self { chains: EVM_CHAINS }
    }

    /// The chain entry for `route`; its selector must be the route's.
    fn chain(&self, route: &BridgeRoute) -> Result<&EvmChain> {
        let chain = self
            .chains
            .iter()
            .find(|c| c.name == route.source_chain)
            .ok_or_else(|| {
                bad(format!(
                    "'{}' is not a served EVM chain",
                    route.source_chain
                ))
            })?;
        if chain.selector != route.source_chain_id {
            return Err(bad(format!(
                "route selector {} is not {}'s selector {}",
                route.source_chain_id, chain.name, chain.selector
            )));
        }
        Ok(chain)
    }
}

impl Default for EvmCcipAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteAdapter for EvmCcipAdapter {
    fn transport(&self) -> BridgeRouteAdapter {
        BridgeRouteAdapter::Ccip
    }

    fn family(&self) -> ChainFamily {
        ChainFamily::Evm
    }

    fn decode_inbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        self.chain(route)?;
        let m = read_onramp_message(route, r)?;
        let Some(t) = m.token else {
            return Err(bad("a route transfer carries exactly one token transfer"));
        };
        if t.dest_token.len() != 32 {
            return Err(bad("destination token must be a 32-byte Tenzro address"));
        }
        Ok(RouteMessage {
            message_id: m.message_id,
            source_selector: m.source_selector,
            dest_selector: m.dest_selector,
            sequence: m.sequence,
            sender: m.sender.to_vec(),
            receiver: m.receiver,
            token_pool: word_addr(&t.source_pool),
            token: pad32(&t.dest_token)?,
            amount: t.amount,
        })
    }

    fn encode_outbound(&self, route: &BridgeRoute, msg: &RouteMessage) -> Result<Vec<u8>> {
        self.chain(route)?;
        match lane_version(route)? {
            CcipLaneVersion::V2_0 => outbound_v2_0(route, msg)?.encode(),
            CcipLaneVersion::V1_6 => encode_outbound_v1_6(msg),
            CcipLaneVersion::V1_5 => Err(refuse_v1_5()),
        }
    }

    fn decode_outbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        match lane_version(route)? {
            CcipLaneVersion::V2_0 => decode_outbound_v2_0(route, r),
            CcipLaneVersion::V1_6 => decode_outbound_v1_6(r),
            CcipLaneVersion::V1_5 => Err(refuse_v1_5()),
        }
    }

    fn finality_depth(&self, route: &BridgeRoute) -> Result<u64> {
        Ok(self.chain(route)?.finality_depth)
    }

    fn outbound_message_id(&self, route: &BridgeRoute, msg: &RouteMessage) -> Result<[u8; 32]> {
        match lane_version(route)? {
            CcipLaneVersion::V2_0 => Ok(keccak(&[&outbound_v2_0(route, msg)?.encode()?])),
            CcipLaneVersion::V1_6 => Ok(message_id_v1_6(route, msg)),
            CcipLaneVersion::V1_5 => Err(refuse_v1_5()),
        }
    }
}

/// A `1.5.0` lane carries nothing out of Tenzro: `EVM2EVMMessage` names its
/// sender as a 20-byte EVM address, which a Tenzro account is not.
fn refuse_v1_5() -> BridgeError {
    bad("a 1.5.0 lane runs between EVM chains only; Tenzro sends over 2.0.0 or 1.6.0 lanes")
}

/// The `2.0.0` message the lane's off-ramp executes for `msg`. Tenzro's
/// endpoint is its on-ramp, its token pool and its token; the sender keeps
/// its 32-byte Tenzro encoding; the off-ramp, receiver and token are 20-byte
/// EVM addresses. The transfer asks for the pool's gas only and runs no
/// receiver callback.
fn outbound_v2_0(route: &BridgeRoute, msg: &RouteMessage) -> Result<MessageV1> {
    let lane = route
        .lane_limits
        .ok_or_else(|| bad("a CCIP route needs its lane"))?;
    let receiver: [u8; 20] = msg
        .receiver
        .as_slice()
        .try_into()
        .map_err(|_| bad("an EVM recipient is a 20-byte address"))?;
    Ok(MessageV1 {
        source_selector: msg.source_selector,
        dest_selector: msg.dest_selector,
        sequence: msg.sequence,
        execution_gas_limit: DEST_POOL_GAS,
        receive_gas_limit: 0,
        finality: [0u8; 4],
        ccv_and_executor_hash: lane.ccv_and_executor_hash,
        on_ramp: route.local_endpoint.to_vec(),
        off_ramp: lane.off_ramp.to_vec(),
        sender: msg.sender.clone(),
        receiver: receiver.to_vec(),
        dest_blob: Vec::new(),
        token_transfer: Some(TokenTransferV1 {
            amount: msg.amount,
            source_pool: msg.token_pool.to_vec(),
            source_token: msg.token_pool.to_vec(),
            dest_token: evm_address(&msg.token)?.to_vec(),
            token_receiver: receiver.to_vec(),
            extra_data: Vec::new(),
        }),
        data: Vec::new(),
    })
}

/// Read back a `2.0.0` outbound message: it must be exactly the message
/// [`outbound_v2_0`] builds for its own fields on this route's lane.
fn decode_outbound_v2_0(route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
    let bytes = r.take(r.remaining())?;
    let m = MessageV1::read(bytes)?;
    let Some(t) = &m.token_transfer else {
        return Err(bad(
            "an outbound transfer carries exactly one token transfer",
        ));
    };
    let msg = RouteMessage {
        message_id: keccak(&[bytes]),
        source_selector: m.source_selector,
        dest_selector: m.dest_selector,
        sequence: m.sequence,
        sender: m.sender.clone(),
        receiver: m.receiver.clone(),
        token_pool: pad32(&t.source_pool)?,
        token: pad32(&t.dest_token)?,
        amount: t.amount,
    };
    if outbound_v2_0(route, &msg)? != m {
        return Err(bad(
            "an outbound transfer names the lane's off-ramp and carries no data or callback",
        ));
    }
    Ok(msg)
}

/// `1.6.0`: the ABI encoding of `Any2EVMRampMessage`.
fn encode_outbound_v1_6(msg: &RouteMessage) -> Result<Vec<u8>> {
    let receiver: [u8; 20] = msg
        .receiver
        .as_slice()
        .try_into()
        .map_err(|_| bad("an EVM recipient is a 20-byte address"))?;
    let token = Any2EvmTokenTransfer {
        source_pool: msg.token_pool.to_vec(),
        dest_token: evm_address(&msg.token)?,
        dest_gas_amount: DEST_POOL_GAS,
        extra_data: Vec::new(),
        amount: msg.amount,
    };
    let header = RampHeader {
        message_id: msg.message_id,
        source_selector: msg.source_selector,
        dest_selector: msg.dest_selector,
        sequence: msg.sequence,
        nonce: 0,
    };
    let mut fields: Vec<Field> = header.fields().into_iter().collect();
    fields.extend([
        Field::Tail(abi_bytes(&msg.sender)),
        Field::Tail(abi_bytes(&[])),
        Field::Word(word_addr(&receiver)),
        Field::Word([0u8; 32]),
        Field::Tail(abi_array(vec![token.encode()])),
    ]);
    Ok(abi_tuple(&[Field::Tail(abi_tuple(&fields))]))
}

fn decode_outbound_v1_6(r: &mut Reader<'_>) -> Result<RouteMessage> {
    let outer = r.abi_offset()?;
    r.abi_expect_tail(0, outer)?;
    let base = r.position();
    let header = RampHeader::read(r)?;
    let o_sender = r.abi_offset()?;
    let o_data = r.abi_offset()?;
    let receiver = r.abi_address()?;
    let gas_limit = r.abi_u256_as_u128()?;
    let o_tokens = r.abi_offset()?;
    r.abi_expect_tail(base, o_sender)?;
    let sender = r.abi_bytes(64)?;
    r.abi_expect_tail(base, o_data)?;
    let data = r.abi_bytes(MAX_FIELD_LEN)?;
    r.abi_expect_tail(base, o_tokens)?;
    let tokens = read_array(r, MAX_TOKEN_TRANSFERS, Any2EvmTokenTransfer::read)?;
    let [t] = tokens.as_slice() else {
        return Err(bad(
            "an outbound transfer carries exactly one token transfer",
        ));
    };
    if header.nonce != 0 || gas_limit != 0 || !data.is_empty() || !t.extra_data.is_empty() {
        return Err(bad(
            "an outbound transfer carries no nonce, gas limit or data",
        ));
    }
    if t.dest_gas_amount != DEST_POOL_GAS {
        return Err(bad("unexpected destination pool gas"));
    }
    Ok(RouteMessage {
        message_id: header.message_id,
        source_selector: header.source_selector,
        dest_selector: header.dest_selector,
        sequence: header.sequence,
        sender,
        receiver: receiver.to_vec(),
        token_pool: pad32(&t.source_pool)?,
        token: word_addr(&t.dest_token),
        amount: t.amount,
    })
}

/// `1.6.0`: Tenzro, as the sending chain, assigns the id: a hash over the
/// lane metadata (selectors and Tenzro's endpoint), the sequence number, the
/// parties, the token and the amount.
fn message_id_v1_6(route: &BridgeRoute, msg: &RouteMessage) -> [u8; 32] {
    let tag = keccak(&[b"Any2EVMMessageHashV1"]);
    let metadata = keccak(&[
        &tag,
        &word_u64(msg.source_selector),
        &word_u64(msg.dest_selector),
        &keccak(&[&route.local_endpoint]),
    ]);
    keccak(&[
        &metadata,
        &word_u64(msg.sequence),
        &keccak(&[&msg.sender]),
        &keccak(&[&msg.receiver]),
        &msg.token,
        &word_u128(msg.amount),
    ])
}
