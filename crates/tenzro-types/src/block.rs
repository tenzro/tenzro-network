//! Block types for Tenzro Network
//!
//! This module defines the block structure used to organize transactions
//! and maintain the blockchain state.

use crate::primitives::{Address, BlockHeight, Hash, Timestamp};
use sha2::{Digest, Sha256};
use crate::transaction::SignedTransaction;
use serde::{Deserialize, Serialize};

/// Maximum number of transactions allowed per block
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 10_000;

/// A block header containing metadata about a block
///
/// The header includes cryptographic commitments to the block's contents
/// and links to the previous block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// The height of this block
    pub height: BlockHeight,
    /// The HotStuff-2 view at which this block was proposed.
    ///
    /// Required for view-sync on inbound proposals: receivers must advance
    /// their local view to match `view` before voting, so that the resulting
    /// vote is bucketed at the same view as the proposer's self-vote and a
    /// quorum can form. See `tenzro-consensus::HotStuff2Engine::on_proposal`.
    ///
    /// Mirrors HotStuff-2 (Malkhi & Nayak, eprint 2023/397) Figure 1: the
    /// proposal message `⟨propose, B_k, v, C_{v'}(B_{k-1})⟩_{L_v}` carries
    /// `v` as its own field: the consensus round number for this block.
    #[serde(default)]
    pub view: u64,
    /// Hash of the previous block
    pub prev_hash: Hash,
    /// Merkle root of all transactions in the block
    pub tx_root: Hash,
    /// Merkle root of the state after executing this block
    pub state_root: Hash,
    /// Block timestamp
    pub timestamp: Timestamp,
    /// Address of the block proposer
    pub proposer: Address,
    /// Consensus proof for this block
    pub consensus_proof: ConsensusProof,
    /// Additional metadata
    pub metadata: BlockMetadata,
}

impl BlockHeader {
    /// Creates a new block header at view 0.
    ///
    /// For consensus-driven proposals use [`BlockHeader::new_at_view`] to
    /// stamp the proposer's current view. Genesis uses view 0.
    pub fn new(
        height: BlockHeight,
        prev_hash: Hash,
        tx_root: Hash,
        state_root: Hash,
        proposer: Address,
        consensus_proof: ConsensusProof,
    ) -> Self {
        Self::new_at_view(height, 0, prev_hash, tx_root, state_root, proposer, consensus_proof)
    }

    /// Creates a new block header stamped with the proposer's view.
    pub fn new_at_view(
        height: BlockHeight,
        view: u64,
        prev_hash: Hash,
        tx_root: Hash,
        state_root: Hash,
        proposer: Address,
        consensus_proof: ConsensusProof,
    ) -> Self {
        Self {
            height,
            view,
            prev_hash,
            tx_root,
            state_root,
            timestamp: Timestamp::now(),
            proposer,
            consensus_proof,
            metadata: BlockMetadata::default(),
        }
    }

    /// Computes the hash of the block header using canonical binary encoding.
    ///
    /// Fields are hashed in order: height, view, prev_hash, tx_root,
    /// state_root, timestamp, proposer, gas_used, gas_limit, tx_count,
    /// protocol_version, base_fee_per_gas. Using LE bytes for integer
    /// fields ensures deterministic output regardless of platform or
    /// serialization format.
    ///
    /// `base_fee_per_gas` is encoded as a presence-tagged u128:
    /// `[0u8]` for `None`, `[1u8] || u128_le` for `Some(_)`. This
    /// distinguishes a zero base fee from an unset base fee while
    /// keeping the canonical encoding deterministic. Per EIP-1559 +
    /// go-ethereum `VerifyEIP1559Header`, the base fee is part of the
    /// signed block hash so validators reach byzantine agreement on it.
    pub fn hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(self.height.0.to_le_bytes());
        hasher.update(self.view.to_le_bytes());
        hasher.update(self.prev_hash.0);
        hasher.update(self.tx_root.0);
        hasher.update(self.state_root.0);
        hasher.update(self.timestamp.0.to_le_bytes());
        hasher.update(self.proposer.0);
        hasher.update(self.metadata.gas_used.to_le_bytes());
        hasher.update(self.metadata.gas_limit.to_le_bytes());
        hasher.update(self.metadata.tx_count.to_le_bytes());
        hasher.update((self.metadata.protocol_version as u64).to_le_bytes());
        match self.metadata.base_fee_per_gas {
            None => hasher.update([0u8]),
            Some(bf) => {
                hasher.update([1u8]);
                hasher.update(bf.to_le_bytes());
            }
        }
        Hash::new(hasher.finalize().into())
    }
}

/// EIP-1559 fee-market parameters used for base-fee calculation.
///
/// Mirrors `tenzro_vm::eip1559::Eip1559Config` but lives in `tenzro-types`
/// so the pure [`calculate_next_base_fee`] function can be invoked from
/// the consensus layer without taking a dependency on `tenzro-vm`.
///
/// Defaults match `Eip1559Config::default()` in `tenzro-vm` (initial
/// 1 Gwei, 15M target / 30M max, 12.5% max change per block, 0.1 Gwei
/// floor, 1000 Gwei ceiling).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeMarketParams {
    pub initial_base_fee: u128,
    pub target_gas_per_block: u64,
    pub base_fee_change_denominator: u64,
    pub min_base_fee: u128,
    pub max_base_fee: u128,
}

impl Default for FeeMarketParams {
    fn default() -> Self {
        Self {
            initial_base_fee: 1_000_000_000,
            target_gas_per_block: 15_000_000,
            base_fee_change_denominator: 8,
            min_base_fee: 100_000_000,
            max_base_fee: 1_000_000_000_000,
        }
    }
}

/// Pure EIP-1559 base-fee derivation for the next block.
///
/// Given the parent block's base fee and gas usage, returns what the
/// child block's base fee MUST be. Both proposers (when stamping
/// `BlockMetadata::base_fee_per_gas`) and validators (when verifying
/// an inbound proposal) call this and reject any block that diverges.
///
/// Genesis-edge case: if `parent_base_fee` is `None` (parent predates
/// EIP-1559) or the parent's `gas_limit` is 0 (genesis itself),
/// returns `params.initial_base_fee`. Mirrors go-ethereum's behavior
/// at the London-fork boundary.
///
/// The formula matches `FeeMarket::calculate_next_base_fee` byte-for-byte:
/// - `parent_gas_used == target`: no change
/// - `parent_gas_used > target`: increase by `current * delta / target / denom`, min 1 wei
/// - `parent_gas_used < target`: decrease by `current * delta / target / denom` (saturating)
/// - Result clamped to `[min_base_fee, max_base_fee]`.
pub fn calculate_next_base_fee(
    parent_base_fee: Option<u128>,
    parent_gas_used: u64,
    parent_gas_limit: u64,
    params: &FeeMarketParams,
) -> u128 {
    // Genesis-edge: parent has no base fee, OR parent has zero gas_limit
    // (genesis block) — child uses the initial fee.
    let current = match parent_base_fee {
        Some(bf) if parent_gas_limit > 0 => bf,
        _ => return params.initial_base_fee,
    };

    let target = params.target_gas_per_block;
    let denom = params.base_fee_change_denominator as u128;

    let next_fee = if parent_gas_used == target {
        current
    } else if parent_gas_used > target {
        let gas_delta = (parent_gas_used - target) as u128;
        let fee_delta = (current * gas_delta) / (target as u128) / denom;
        current + fee_delta.max(1)
    } else {
        let gas_delta = (target - parent_gas_used) as u128;
        let fee_delta = (current * gas_delta) / (target as u128) / denom;
        current.saturating_sub(fee_delta)
    };

    next_fee.clamp(params.min_base_fee, params.max_base_fee)
}

/// Additional metadata included in a block header
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BlockMetadata {
    /// Total gas used in this block
    pub gas_used: u64,
    /// Gas limit for this block
    pub gas_limit: u64,
    /// Number of transactions in this block
    pub tx_count: u64,
    /// Protocol version
    pub protocol_version: u32,
    /// EIP-1559 base fee per gas for this block, in wei-equivalent (TNZO base units / 10^18).
    ///
    /// Stamped at block-finalize time from the live `FeeMarket`. This is the
    /// minimum gas price that any transaction in this block had to bid; the
    /// portion of effective gas price equal to this is burned. `eth_feeHistory`
    /// reads this field directly per block, so it must be persisted with the
    /// block header rather than reconstructed from the runtime fee market
    /// (which only retains a bounded recent window).
    ///
    /// `None` for genesis and any block produced before EIP-1559 wiring; new
    /// blocks always carry `Some(_)`.
    pub base_fee_per_gas: Option<u128>,
}

/// Proof of consensus for a block
///
/// Contains the cryptographic evidence that the block was produced
/// according to the consensus rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusProof {
    /// The consensus algorithm used
    pub algorithm: ConsensusAlgorithm,
    /// Proof data specific to the consensus algorithm
    pub proof_data: Vec<u8>,
    /// Signatures from validators
    pub signatures: Vec<ValidatorSignature>,
}

impl ConsensusProof {
    /// Creates a new consensus proof
    pub fn new(algorithm: ConsensusAlgorithm, proof_data: Vec<u8>) -> Self {
        Self {
            algorithm,
            proof_data,
            signatures: Vec::new(),
        }
    }

    /// Adds a validator signature to the proof
    pub fn add_signature(&mut self, signature: ValidatorSignature) {
        self.signatures.push(signature);
    }
}

/// The consensus algorithm used to produce a block
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusAlgorithm {
    /// Proof of Stake
    PoS,
    /// Practical Byzantine Fault Tolerance
    PBFT,
    /// Tendermint-style consensus
    Tendermint,
}

/// A signature from a validator in the consensus process
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// The validator's address
    pub validator: Address,
    /// The signature bytes
    pub signature: Vec<u8>,
    /// The voting power of the validator
    pub voting_power: u128,
}

/// A complete block on Tenzro Network
///
/// Contains the header and all transactions included in the block.
///
/// The `transactions` vector is bounded by `MAX_DESERIALIZED_TX_COUNT`
/// at deserialization time to protect against OOM via untrusted payloads
/// (HIGH #69 in the production audit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// The block header
    pub header: BlockHeader,
    /// All transactions in this block
    #[serde(deserialize_with = "crate::validation::bounded_tx_vec")]
    pub transactions: Vec<SignedTransaction>,
}

impl Block {
    /// Creates a new block
    pub fn new(header: BlockHeader, transactions: Vec<SignedTransaction>) -> Self {
        Self {
            header,
            transactions,
        }
    }

    /// Creates a new block with validation
    ///
    /// Returns an error if the number of transactions exceeds MAX_TRANSACTIONS_PER_BLOCK
    pub fn new_validated(header: BlockHeader, transactions: Vec<SignedTransaction>) -> Result<Self, crate::error::TenzroError> {
        if transactions.len() > MAX_TRANSACTIONS_PER_BLOCK {
            return Err(crate::error::TenzroError::InvalidBlock(format!(
                "Too many transactions: {} exceeds maximum of {}",
                transactions.len(),
                MAX_TRANSACTIONS_PER_BLOCK
            )));
        }
        Ok(Self {
            header,
            transactions,
        })
    }

    /// Returns the hash of the block
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Returns the height of the block
    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    /// Returns the timestamp of the block
    pub fn timestamp(&self) -> Timestamp {
        self.header.timestamp
    }

    /// Returns the number of transactions in the block
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }

    /// Returns the block proposer
    pub fn proposer(&self) -> Address {
        self.header.proposer
    }

    /// Validates the block structure
    ///
    /// Checks basic invariants like transaction count matching metadata.
    pub fn validate_structure(&self) -> bool {
        self.transactions.len() as u64 == self.header.metadata.tx_count
    }
}
