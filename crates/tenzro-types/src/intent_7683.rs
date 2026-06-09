//! ERC-7683 Cross-Chain Intents — protocol primitives (Agent-Swarm Spec 4).
//!
//! Tenzro speaks both halves of ERC-7683:
//!
//! - As **origin settler**: Tenzro is the chain where a `CrossChainOrder` is
//!   opened. Solvers watch Tenzro for new orders, fill them on the destination,
//!   and come back to claim repayment.
//! - As **destination settler**: Tenzro is the chain where a 7683 order is
//!   filled. After proving fill, the solver claims the user's locked input on
//!   the origin chain via that chain's settler.
//!
//! This module defines the wire types — `CrossChainOrder`, `ResolvedCrossChainOrder`,
//! `Output`, `FillInstruction`, the Tenzro-specific `TenzroOrderData` payload,
//! the `ProofRoute` enum (which underlying bridge ferries the fill proof), and
//! the on-chain `Tenzro7683Order` envelope. Settler precompile bytecode, EIP-712
//! verification, escrow integration, gossipsub indexing, and bridge-adapter
//! glue land alongside their respective subsystems and consume these types
//! verbatim.
//!
//! ### CAIP-2 chain-id mapping
//!
//! 7683 carries a `uint32` chain ID. Tenzro chains use the constants
//! [`TENZRO_MAINNET_CHAIN_ID`] / [`TENZRO_TESTNET_CHAIN_ID`] — chosen to not
//! collide with EVM EIP-155 IDs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::primitives::{Address, Hash, Timestamp};

/// 7683 chain ID for Tenzro mainnet (`uint32`, encoded "TENZRO" lower bits).
pub const TENZRO_MAINNET_CHAIN_ID: u32 = 0x10ED20;

/// 7683 chain ID for Tenzro testnet.
pub const TENZRO_TESTNET_CHAIN_ID: u32 = 0x10ED21;

/// Bridge route a 7683 order designates for ferrying the fill proof from the
/// destination chain back to the origin settler. Encoded into the order at
/// open time so solvers see (and can refuse) the route up front.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofRoute {
    LayerZero,
    Wormhole,
    DeBridge,
    Hyperlane,
}

impl ProofRoute {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProofRoute::LayerZero => "layerzero",
            ProofRoute::Wormhole => "wormhole",
            ProofRoute::DeBridge => "debridge",
            ProofRoute::Hyperlane => "hyperlane",
        }
    }
}

/// A token + amount pair, encoded with chain-agnostic recipient bytes
/// (12-byte zero-pad + 20-byte EVM addr, 32-byte SVM pubkey, or party ID for
/// Canton — discriminated by `chain_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenAmount {
    /// Token contract address on the chain where this token lives. For
    /// Tenzro-native TNZO, use the wTNZO EVM pointer (`0x7a4bcb13...`); for
    /// SPL adapter, the SPL mint; for foreign tokens, their native contract.
    pub token: Vec<u8>,
    /// uint256 amount as 32-byte big-endian bytes — preserves precision
    /// across the 7683 wire format.
    pub amount: [u8; 32],
}

/// What the user wants on the destination chain. Mirrors 7683's `Output`
/// struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    pub token: Vec<u8>,
    pub amount: [u8; 32],
    /// Chain-discriminated recipient — see `TokenAmount::token` doc.
    pub recipient: [u8; 32],
    /// 7683 chain ID of the destination chain (uint32).
    pub chain_id: u32,
}

/// What the user wants on the destination chain — the user-side declarative
/// half of an order.
pub type TargetOutput = Output;

/// 7683 fill instruction — pairs a destination chain with the calldata the
/// solver will execute there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FillInstruction {
    /// 7683 destination chain ID.
    pub destination_chain_id: u32,
    /// Settler contract on the destination chain (chain-discriminated bytes).
    pub destination_settler: [u8; 32],
    /// Calldata the solver passes to `IDestinationSettler.fill`.
    pub origin_data: Vec<u8>,
}

/// Tenzro-specific payload carried in `CrossChainOrder.orderData` when Tenzro
/// is the origin chain. Solvers decode this to know what to fill and which
/// bridge route to use for the proof return.
///
/// Optional [`BridgeFeeHint`] lets the swapper bake a destination-native-fee-
/// in-TNZO quote into the open order. When set, any bridge in the registered
/// adapter set can pick up the order: the solver references `bridge_fee_hint.
/// tnzo_amount_wei` to know what TNZO it's reimbursed in TNZO terms, the
/// origin settler enforces the quote's `valid_until_ms`, and the destination
/// settler routes the proof through whichever adapter the solver chose. This
/// is the SOTA across-protocol pattern (Across V3 hub-and-spoke + Cosmos
/// ICS-29 escrow fee abstraction): user signs once with one TNZO-denominated
/// price, the solver picks the bridge based on liquidity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenzroOrderData {
    pub inputs: Vec<TokenAmount>,
    pub outputs: Vec<TargetOutput>,
    pub dest_chain_id: u32,
    pub dest_recipient: [u8; 32],
    pub fill_deadline: u32,
    pub proof_route: ProofRoute,
    /// Optional destination-bridge-fee hint denominated in TNZO. When `Some`,
    /// the order is fungible across the 6 supported bridges — any solver can
    /// pick up the order and quote whichever adapter has cheapest destination
    /// liquidity, as long as their destination-native-fee is <= the hinted
    /// TNZO amount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_fee_hint: Option<BridgeFeeHint>,
}

/// Hint embedded in [`TenzroOrderData`] to make a 7683 order fungible across
/// every registered bridge adapter. The swapper obtains this by calling
/// `tenzro_quoteBridgeFeeInTnzo` against any of the 6 adapters before
/// opening the order; the value bounds the solver's destination-native fee
/// commitment in TNZO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeFeeHint {
    /// Reference quote id from the BridgeFeeOracle. Solvers can re-fetch
    /// the canonical quote via `tenzro_getBridgeFeeQuote` for audit.
    pub quote_id_hex: String,
    /// TNZO ceiling the swapper authorized for the destination-native fee.
    /// Encoded as decimal string to round-trip through JSON without
    /// precision loss for u128 values.
    pub tnzo_amount_wei: String,
    /// Wall-clock expiry — solvers MUST NOT execute fills referencing this
    /// hint after expiry. Mirrors the underlying quote's `valid_until_ms`.
    pub valid_until_ms: u64,
    /// Suggested adapter the swapper had in mind at quote time. Advisory
    /// only; the solver may choose a different adapter as long as the
    /// destination-native fee in TNZO terms stays <= `tnzo_amount_wei`.
    pub preferred_adapter: String,
}

/// 7683 `CrossChainOrder` — what the user signs to open an order. Written
/// here in protocol-native types; EIP-712 encoding happens in the settler
/// precompile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossChainOrder {
    pub settlement_contract: Address,
    pub swapper: Address,
    pub nonce: u64,
    pub origin_chain_id: u32,
    pub fill_deadline: u32,
    /// EIP-712 typehash for `order_data` decoding — for Tenzro orders this
    /// is `keccak256("TenzroOrderData(...)")`.
    pub order_data_type: Hash,
    /// Bincode-encoded `TenzroOrderData` (or foreign payload for non-Tenzro
    /// origins). Opaque at the protocol layer.
    pub order_data: Vec<u8>,
}

/// 7683 `GaslessCrossChainOrder` — same shape as `CrossChainOrder`, signed
/// for relayer submission so the swapper does not pay origin-chain gas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GaslessCrossChainOrder {
    pub settlement_contract: Address,
    pub swapper: Address,
    pub nonce: u64,
    pub origin_chain_id: u32,
    pub fill_deadline: u32,
    pub order_data_type: Hash,
    pub order_data: Vec<u8>,
}

/// 7683 `ResolvedCrossChainOrder` — what `IOriginSettler.resolve` returns.
/// Solvers use this to decide whether to take an order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedCrossChainOrder {
    pub settlement_contract: Address,
    pub swapper: Address,
    pub nonce: u64,
    pub origin_chain_id: u32,
    pub fill_deadline: u32,
    /// What the solver spent on the destination chain.
    pub max_spent: Vec<Output>,
    /// What the user receives on the origin chain (typically the locked
    /// inputs released to the solver after fill).
    pub min_received: Vec<Output>,
    pub fill_instructions: Vec<FillInstruction>,
}

/// Lifecycle of a 7683 order tracked on Tenzro.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderState {
    /// Open, escrow locked, awaiting fill.
    Open,
    /// Solver filled on destination; settler awaiting bridge proof.
    AwaitingProof,
    /// Bridge proof verified, escrow released to solver.
    Settled,
    /// Deadline passed without fill, swapper refunded.
    Refunded,
    /// Swapper Quarantined/Terminated post-open — anyone can force refund.
    ForceRefundEligible,
}

impl OrderState {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrderState::Open => "open",
            OrderState::AwaitingProof => "awaiting_proof",
            OrderState::Settled => "settled",
            OrderState::Refunded => "refunded",
            OrderState::ForceRefundEligible => "force_refund_eligible",
        }
    }
}

/// On-chain envelope tracking a Tenzro-origin 7683 order from open through
/// settlement or refund. Persisted in `CF_SETTLEMENTS` under the
/// [`ORDER_KEY_PREFIX`] keyspace, keyed by `order_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenzro7683Order {
    pub order_id: Hash,
    pub state: OrderState,
    pub resolved: ResolvedCrossChainOrder,
    /// Escrow id from `tenzro-settlement::EscrowManager` holding the locked
    /// inputs. Used to release/refund.
    pub escrow_id: Hash,
    pub opened_at: Timestamp,
    pub fill_deadline: u32,
    /// Filler that submitted the destination-side fill, if any. Settled once
    /// the bridge proof verifies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filler: Option<Address>,
    /// Hash of the bridge proof that ferried the fill back from destination.
    /// Set when state transitions to `Settled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill_proof_hash: Option<Hash>,
    pub proof_route: ProofRoute,
}

/// Destination-side fill record for an ERC-7683 order. Persisted in
/// `CF_SETTLEMENTS` under the [`FILL_KEY_PREFIX`] keyspace, keyed by
/// `order_id`. Existence of this record is the idempotency guard — the
/// destination settler refuses to process a second `fill(originData)` whose
/// decoded `orderId` already maps to a `FillRecord`.
///
/// The record captures everything a downstream observer (origin-chain
/// settler, indexer, dispute resolver) needs to verify that the fill
/// happened on this Tenzro replica:
///
/// - `order_id` — the canonical 7683 order id this fill discharges.
/// - `origin_chain_id` / `origin_settler` — where the order was opened (for
///   reverse-route addressing when the bridge ferries fill proof back).
/// - `filler` — Tenzro address of the solver who filled.
/// - `recipient` — chain-discriminated recipient bytes32 the solver paid
///   (mirrors the `Output.recipient` of the resolved order).
/// - `outputs` — exact `Output` set the solver delivered (must equal the
///   resolved order's `min_received` per spec).
/// - `fill_tx_hash` — hash of the Tenzro transaction in which the fill
///   transfers happened, so the bridge can attest to a specific block.
/// - `filled_at` — wall-clock timestamp when the registry recorded the fill.
/// - `proof_route` — bridge route the order designated for ferrying proof
///   back to origin (snapshot at fill-time so an audit doesn't have to
///   re-read the open envelope).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FillRecord {
    pub order_id: Hash,
    pub origin_chain_id: u32,
    pub origin_settler: Address,
    pub filler: Address,
    pub recipient: [u8; 32],
    pub outputs: Vec<Output>,
    pub fill_tx_hash: Hash,
    pub filled_at: Timestamp,
    pub proof_route: ProofRoute,
}

/// `CF_SETTLEMENTS` key prefix for Tenzro-origin 7683 orders.
pub const ORDER_KEY_PREFIX: &[u8] = b"7683_origin:";

/// `CF_SETTLEMENTS` key prefix for destination-side fill records (the
/// idempotency guard — same `order_id` cannot be filled twice).
pub const FILL_KEY_PREFIX: &[u8] = b"7683_dest:";

/// Build the `CF_SETTLEMENTS` storage key for a destination-side fill
/// record. The key is `7683_dest:` followed by the raw 32-byte order id —
/// keeps key size constant and lookup an O(1) point read.
pub fn fill_storage_key(order_id: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(FILL_KEY_PREFIX.len() + 32);
    key.extend_from_slice(FILL_KEY_PREFIX);
    key.extend_from_slice(order_id.as_bytes());
    key
}

/// Build the `CF_SETTLEMENTS` storage key for a Tenzro-origin 7683 order
/// envelope. Mirrors [`fill_storage_key`] for the open side. Defined here
/// so callers don't have to reconstruct the layout in two crates.
pub fn order_storage_key(order_id: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(ORDER_KEY_PREFIX.len() + 32);
    key.extend_from_slice(ORDER_KEY_PREFIX);
    key.extend_from_slice(order_id.as_bytes());
    key
}

/// Compute the canonical `order_id` for a `CrossChainOrder`.
///
/// `order_id = SHA-256("tenzro/7683/order" || swapper || nonce_le ||
/// origin_chain_id_le || fill_deadline_le || order_data_type || order_data)`.
///
/// Deterministic — same order produces the same id regardless of who computes
/// it (settler, solver, indexer).
pub fn compute_order_id(order: &CrossChainOrder) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(b"tenzro/7683/order");
    hasher.update(order.swapper.as_bytes());
    hasher.update(order.nonce.to_le_bytes());
    hasher.update(order.origin_chain_id.to_le_bytes());
    hasher.update(order.fill_deadline.to_le_bytes());
    hasher.update(order.order_data_type.as_bytes());
    hasher.update(&order.order_data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash::new(bytes)
}

/// Wrap a u128 into the 32-byte big-endian uint256 layout expected by 7683
/// `Output.amount` / `TokenAmount.amount`.
pub fn u128_to_uint256_be(value: u128) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&value.to_be_bytes());
    bytes
}

/// Read the low 128 bits out of a 32-byte big-endian uint256. Returns `None`
/// if the high 128 bits are non-zero — guards against silent truncation when
/// downstream code (e.g. settlement) only handles u128.
pub fn uint256_be_to_u128(bytes: &[u8; 32]) -> Option<u128> {
    if bytes[..16].iter().any(|&b| b != 0) {
        return None;
    }
    let mut low = [0u8; 16];
    low.copy_from_slice(&bytes[16..]);
    Some(u128::from_be_bytes(low))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_order() -> CrossChainOrder {
        CrossChainOrder {
            settlement_contract: Address::new([1u8; 32]),
            swapper: Address::new([2u8; 32]),
            nonce: 42,
            origin_chain_id: TENZRO_TESTNET_CHAIN_ID,
            fill_deadline: 1_700_001_000,
            order_data_type: Hash::new([3u8; 32]),
            order_data: b"opaque-payload".to_vec(),
        }
    }

    #[test]
    fn chain_ids_match_spec() {
        assert_eq!(TENZRO_MAINNET_CHAIN_ID, 0x10ED20);
        assert_eq!(TENZRO_TESTNET_CHAIN_ID, 0x10ED21);
    }

    #[test]
    fn compute_order_id_is_deterministic() {
        let order = sample_order();
        assert_eq!(compute_order_id(&order), compute_order_id(&order));
    }

    #[test]
    fn compute_order_id_changes_on_field_change() {
        let order = sample_order();
        let baseline = compute_order_id(&order);

        let mut nonce_changed = order.clone();
        nonce_changed.nonce = 43;
        assert_ne!(compute_order_id(&nonce_changed), baseline);

        let mut deadline_changed = order.clone();
        deadline_changed.fill_deadline = 1_700_001_001;
        assert_ne!(compute_order_id(&deadline_changed), baseline);

        let mut data_changed = order.clone();
        data_changed.order_data = b"different-payload".to_vec();
        assert_ne!(compute_order_id(&data_changed), baseline);
    }

    #[test]
    fn proof_route_str() {
        assert_eq!(ProofRoute::LayerZero.as_str(), "layerzero");
        assert_eq!(ProofRoute::Wormhole.as_str(), "wormhole");
        assert_eq!(ProofRoute::DeBridge.as_str(), "debridge");
        assert_eq!(ProofRoute::Hyperlane.as_str(), "hyperlane");
    }

    #[test]
    fn order_state_str() {
        assert_eq!(OrderState::Open.as_str(), "open");
        assert_eq!(OrderState::AwaitingProof.as_str(), "awaiting_proof");
        assert_eq!(OrderState::Settled.as_str(), "settled");
        assert_eq!(OrderState::Refunded.as_str(), "refunded");
        assert_eq!(
            OrderState::ForceRefundEligible.as_str(),
            "force_refund_eligible"
        );
    }

    #[test]
    fn uint256_round_trip() {
        for v in [0u128, 1, 12345, u128::MAX] {
            let bytes = u128_to_uint256_be(v);
            assert_eq!(uint256_be_to_u128(&bytes), Some(v));
        }
    }

    #[test]
    fn uint256_high_bits_rejected() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        assert_eq!(uint256_be_to_u128(&bytes), None);
    }

    #[test]
    fn key_prefixes_are_distinct() {
        assert_ne!(ORDER_KEY_PREFIX, FILL_KEY_PREFIX);
    }

    #[test]
    fn order_envelope_round_trips_through_serde() {
        let resolved = ResolvedCrossChainOrder {
            settlement_contract: Address::new([1u8; 32]),
            swapper: Address::new([2u8; 32]),
            nonce: 7,
            origin_chain_id: TENZRO_MAINNET_CHAIN_ID,
            fill_deadline: 1_700_002_000,
            max_spent: vec![Output {
                token: vec![0xaa; 20],
                amount: u128_to_uint256_be(1_000_000),
                recipient: [0xbb; 32],
                chain_id: 8453, // base
            }],
            min_received: vec![],
            fill_instructions: vec![FillInstruction {
                destination_chain_id: 8453,
                destination_settler: [0xcc; 32],
                origin_data: vec![0xdd, 0xee],
            }],
        };
        let envelope = Tenzro7683Order {
            order_id: Hash::new([9u8; 32]),
            state: OrderState::Open,
            resolved,
            escrow_id: Hash::new([0xee; 32]),
            opened_at: Timestamp::new(1_700_000_000),
            fill_deadline: 1_700_002_000,
            filler: None,
            fill_proof_hash: None,
            proof_route: ProofRoute::LayerZero,
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let decoded: Tenzro7683Order = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn order_data_bridge_fee_hint_round_trips() {
        let order = TenzroOrderData {
            inputs: vec![],
            outputs: vec![],
            dest_chain_id: 8453,
            dest_recipient: [0u8; 32],
            fill_deadline: 1_700_002_000,
            proof_route: ProofRoute::LayerZero,
            bridge_fee_hint: Some(BridgeFeeHint {
                quote_id_hex: "0xabcd".to_string(),
                tnzo_amount_wei: "5100000".to_string(),
                valid_until_ms: 1_700_001_000,
                preferred_adapter: "layerzero".to_string(),
            }),
        };
        let bytes = serde_json::to_vec(&order).unwrap();
        let decoded: TenzroOrderData = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, order);
        assert!(decoded.bridge_fee_hint.is_some());
    }

    #[test]
    fn order_data_without_fee_hint_is_backward_compat() {
        // Simulate an "old" payload that doesn't include `bridge_fee_hint`.
        let bytes = br#"{
            "inputs": [],
            "outputs": [],
            "dest_chain_id": 8453,
            "dest_recipient": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "fill_deadline": 1700002000,
            "proof_route": "LayerZero"
        }"#;
        let decoded: TenzroOrderData = serde_json::from_slice(bytes).unwrap();
        assert!(decoded.bridge_fee_hint.is_none());
    }
}
