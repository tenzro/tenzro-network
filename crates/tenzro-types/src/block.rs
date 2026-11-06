//! Block types for Tenzro Network
//!
//! This module defines the block structure used to organize transactions
//! and maintain the blockchain state.

use crate::primitives::{Address, BlockHeight, Hash, Timestamp};
use crate::transaction::SignedTransaction;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum number of transactions allowed per block: the one limit blocks
/// are built, ordered and decoded under.
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = crate::constants::MAX_TRANSACTIONS_PER_BLOCK as usize;

/// A block header containing metadata about a block
///
/// Every validator builds the same header for a height from the segment
/// consensus ordered: the committed leader vertex (`round`, `anchor`) fixes
/// the transactions and the timestamp, and execution fixes the rest. There
/// is no per-block signature; blocks are certified in ranges by checkpoint
/// certificates, whose blocks root commits these header hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// The height of this block
    pub height: BlockHeight,
    /// Consensus epoch that ordered this block.
    pub epoch: u64,
    /// Round of the committed leader vertex that ordered this block.
    pub round: u64,
    /// Digest of that leader vertex.
    pub anchor: Hash,
    /// Hash of the previous block
    pub prev_hash: Hash,
    /// Merkle root of all transactions in the block
    pub tx_root: Hash,
    /// Post-state root of the block `STATE_ROOT_LAG` heights below this one
    /// (the genesis state root for the first blocks).
    pub state_root: Hash,
    /// Merkle root of the events this block's execution emitted, in cursor
    /// order (see [`crate::chain_event`]).
    pub event_root: Hash,
    /// Root of the trie of this block's Ethereum receipts, keyed by
    /// transaction index (Ethereum `receiptsRoot`, see [`crate::eth_receipt`]).
    pub receipts_root: Hash,
    /// Bloom filter over the addresses and topics of every EVM log this
    /// block's execution emitted (Ethereum `logsBloom`).
    pub logs_bloom: LogsBloom,
    /// Block timestamp: the median timestamp of the leader vertex's parents.
    pub timestamp: Timestamp,
    /// Author of the leader vertex.
    pub proposer: Address,
    /// Additional metadata
    pub metadata: BlockMetadata,
}

impl BlockHeader {
    /// A header outside any consensus round (epoch 0, round 0, no anchor),
    /// stamped now: the genesis block's.
    pub fn new(
        height: BlockHeight,
        prev_hash: Hash,
        tx_root: Hash,
        state_root: Hash,
        proposer: Address,
    ) -> Self {
        Self {
            height,
            epoch: 0,
            round: 0,
            anchor: Hash::zero(),
            prev_hash,
            tx_root,
            state_root,
            event_root: crate::chain_event::event_root(&[]),
            receipts_root: Hash::new(crate::eth_receipt::EMPTY_TRIE_ROOT),
            logs_bloom: LogsBloom::default(),
            timestamp: Timestamp::now(),
            proposer,
            metadata: BlockMetadata::default(),
        }
    }

    /// Computes the hash of the block header using canonical binary encoding.
    ///
    /// Fields are hashed in order: height, epoch, round, anchor, prev_hash,
    /// tx_root, state_root, event_root, receipts_root, logs_bloom, timestamp, proposer, gas_used, gas_limit,
    /// tx_count, protocol_version, base_fee_per_gas. Integers are LE bytes,
    /// so the output does not depend on platform or serialization format.
    ///
    /// `base_fee_per_gas` is encoded as a presence-tagged u128:
    /// `[0u8]` for `None`, `[1u8] || u128_le` for `Some(_)`. This
    /// distinguishes a zero base fee from an unset base fee while
    /// keeping the canonical encoding deterministic, so validators agree on
    /// the base fee through the block hash.
    ///
    /// The hash function is the one [`crate::hash_scheme::BLOCK_HASH_SCHEMES`]
    /// gives the header's own `protocol_version`.
    pub fn hash(&self) -> Hash {
        self.hash_under(crate::hash_scheme::BLOCK_HASH_SCHEMES)
    }

    /// [`Self::hash`] with the version-to-scheme table `schemes`.
    pub fn hash_under(&self, schemes: &[(u32, crate::hash_scheme::HashScheme)]) -> Hash {
        let scheme = crate::hash_scheme::block_hash_scheme(self.metadata.protocol_version, schemes);
        Hash::new(scheme.digest(&self.canonical_bytes()))
    }

    /// The bytes [`Self::hash`] digests, in the order the documentation of
    /// [`Self::hash`] gives.
    fn canonical_bytes(&self) -> Vec<u8> {
        trait Update {
            fn update(&mut self, bytes: impl AsRef<[u8]>);
        }
        impl Update for Vec<u8> {
            fn update(&mut self, bytes: impl AsRef<[u8]>) {
                self.extend_from_slice(bytes.as_ref());
            }
        }
        let mut hasher: Vec<u8> = Vec::with_capacity(512);
        hasher.update(self.height.0.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.anchor.0);
        hasher.update(self.prev_hash.0);
        hasher.update(self.tx_root.0);
        hasher.update(self.state_root.0);
        hasher.update(self.event_root.0);
        hasher.update(self.receipts_root.0);
        hasher.update(self.logs_bloom.0);
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
        hasher
    }
}

/// The 2048-bit Ethereum log bloom (Yellow Paper section 4.3.1): for each
/// log, its address and every topic set three bits, each chosen by the low
/// 11 bits of one of the first three byte pairs of the item's Keccak-256
/// hash. A receipt's bloom covers its logs; a block's is the union of its
/// receipts'.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LogsBloom(#[serde(with = "hex::serde")] pub [u8; 256]);

impl Default for LogsBloom {
    fn default() -> Self {
        Self([0u8; 256])
    }
}

impl std::fmt::Debug for LogsBloom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LogsBloom(0x{})", hex::encode(self.0))
    }
}

impl LogsBloom {
    /// Sets the three bits of `item` (a log address or topic).
    pub fn accrue(&mut self, item: &[u8]) {
        use sha3::{Digest, Keccak256};
        let h = Keccak256::digest(item);
        for i in [0usize, 2, 4] {
            let bit = (usize::from(h[i]) << 8 | usize::from(h[i + 1])) & 2047;
            self.0[255 - bit / 8] |= 1 << (bit % 8);
        }
    }

    /// Adds one log: its address and each of its topics.
    pub fn accrue_log<T: AsRef<[u8]>>(&mut self, address: &[u8], topics: &[T]) {
        self.accrue(address);
        for t in topics {
            self.accrue(t.as_ref());
        }
    }

    /// The bloom of `logs`, each an address and its topics.
    pub fn of_logs<'a, T: AsRef<[u8]> + 'a>(
        logs: impl IntoIterator<Item = (&'a [u8], &'a [T])>,
    ) -> Self {
        let mut b = Self::default();
        for (address, topics) in logs {
            b.accrue_log(address, topics);
        }
        b
    }

    /// Adds every bit of `other`.
    pub fn union(&mut self, other: &LogsBloom) {
        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a |= b;
        }
    }

    /// Whether every bit `item` sets is set: `false` means `item` is
    /// certainly absent, `true` that it may be present.
    pub fn may_contain(&self, item: &[u8]) -> bool {
        let mut probe = Self::default();
        probe.accrue(item);
        probe.0.iter().zip(self.0.iter()).all(|(p, s)| p & s == *p)
    }
}

/// EIP-1559 fee-market parameters used for base-fee calculation.
///
/// Mirrors `tenzro_vm::eip1559::Eip1559Config` but lives in `tenzro-types`
/// so the genesis block can stamp the initial base fee without a dependency
/// on `tenzro-vm`.
///
/// Defaults match `Eip1559Config::default()` in `tenzro-vm` (initial
/// 1 Gwei, 15M target / 30M max, 12.5% max change per block, 0.1 Gwei
/// floor, 1000 Gwei ceiling).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeMarketParams {
    #[serde(with = "crate::primitives::u128_serde")]
    pub initial_base_fee: u128,
    pub target_gas_per_block: u64,
    pub base_fee_change_denominator: u64,
    #[serde(with = "crate::primitives::u128_serde")]
    pub min_base_fee: u128,
    #[serde(with = "crate::primitives::u128_serde")]
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
    pub fn new_validated(
        header: BlockHeader,
        transactions: Vec<SignedTransaction>,
    ) -> Result<Self, crate::error::TenzroError> {
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

    /// Merkle root over the block body, as committed by `header.tx_root`.
    ///
    /// Each leaf commits to a whole signed transaction: the transaction hash
    /// and both signature legs. Committing only the transaction hash would let
    /// a relay swap a signature for garbage, and execution skips a transaction
    /// whose signature does not verify, so two nodes holding the same header
    /// would execute different bodies.
    ///
    /// Leaves and interior nodes carry distinct prefixes, and an odd node at
    /// any level is carried up unchanged rather than paired with a copy of
    /// itself, so no two different bodies share a root. The empty body's root
    /// is the zero hash.
    pub fn compute_tx_root(transactions: &[SignedTransaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::zero();
        }
        let mut level: Vec<[u8; 32]> = transactions.iter().map(tx_root_leaf).collect();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                match pair {
                    [left, right] => {
                        let mut h = Sha256::new();
                        h.update(TX_ROOT_NODE_PREFIX);
                        h.update(left);
                        h.update(right);
                        next.push(h.finalize().into());
                    }
                    [single] => next.push(*single),
                    _ => unreachable!("chunks(2) yields one or two items"),
                }
            }
            level = next;
        }
        Hash::new(level[0])
    }

    /// Checks that the body is the one the header commits to: the recomputed
    /// transaction root equals `header.tx_root` and the transaction count
    /// equals `header.metadata.tx_count`. Both are covered by the block hash,
    /// so a certificate over the hash is a certificate over this body.
    pub fn verify_body(&self) -> Result<(), String> {
        if !self.validate_structure() {
            return Err(format!(
                "block {} carries {} transactions but its header declares {}",
                self.header.height,
                self.transactions.len(),
                self.header.metadata.tx_count
            ));
        }
        let computed = Self::compute_tx_root(&self.transactions);
        if computed != self.header.tx_root {
            return Err(format!(
                "block {} body does not match its header: tx_root {} recomputes to {}",
                self.header.height, self.header.tx_root, computed
            ));
        }
        Ok(())
    }
}

/// Prefix for a transaction-root leaf.
const TX_ROOT_LEAF_PREFIX: &[u8] = b"tenzro.tx-root.leaf";
/// Prefix for a transaction-root interior node.
const TX_ROOT_NODE_PREFIX: &[u8] = b"tenzro.tx-root.node";

fn tx_root_leaf(tx: &SignedTransaction) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TX_ROOT_LEAF_PREFIX);
    h.update(tx.transaction.hash().as_bytes());
    let signature = serde_json::to_vec(&tx.signature).expect("a signature is JSON-safe");
    for part in [tx.public_key.as_slice(), signature.as_slice()] {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tx_root_tests {
    use super::*;
    use crate::primitives::{ChainId, Nonce};
    use crate::transaction::{Transaction, TransactionType};

    fn tx(nonce: u64, sig_byte: u8) -> SignedTransaction {
        let t = Transaction::new(
            ChainId::from(1u64),
            Address::new([1u8; 32]),
            Address::new([2u8; 32]),
            Nonce::from(nonce),
            TransactionType::Transfer { amount: 5 },
            21_000,
            1,
        );
        SignedTransaction::new(
            t,
            vec![3u8; 32],
            crate::account_signature::CompositeSignature::hybrid(
                crate::account_signature::ClassicalProof::Raw {
                    signature: vec![sig_byte; 64],
                },
                vec![sig_byte; 3309],
            ),
        )
    }

    fn block_with(txs: Vec<SignedTransaction>) -> Block {
        let mut header = BlockHeader {
            height: BlockHeight::from(9u64),
            epoch: 0,
            round: 3,
            anchor: Hash::zero(),
            prev_hash: Hash::zero(),
            tx_root: Block::compute_tx_root(&txs),
            state_root: Hash::zero(),
            event_root: Hash::zero(),
            receipts_root: Hash::zero(),
            logs_bloom: LogsBloom::default(),
            timestamp: Timestamp(0),
            proposer: Address::new([4u8; 32]),
            metadata: BlockMetadata::default(),
        };
        header.metadata.tx_count = txs.len() as u64;
        Block::new(header, txs)
    }

    #[test]
    fn an_honest_body_verifies() {
        for n in 0..6u64 {
            let txs = (0..n).map(|i| tx(i, 1)).collect();
            block_with(txs).verify_body().expect("honest body verifies");
        }
    }

    #[test]
    fn a_stripped_body_is_rejected() {
        let mut block = block_with(vec![tx(0, 1), tx(1, 1)]);
        block.transactions.clear();
        block.header.metadata.tx_count = 0;
        // The header hash still names the original body, so the stripped
        // block fails even when the count is patched to match.
        assert!(block.verify_body().is_err());
    }

    #[test]
    fn a_swapped_body_is_rejected() {
        let mut block = block_with(vec![tx(0, 1), tx(1, 1)]);
        block.transactions[1] = tx(2, 1);
        assert!(block.verify_body().is_err());
    }

    #[test]
    fn a_reordered_body_is_rejected() {
        let mut block = block_with(vec![tx(0, 1), tx(1, 1), tx(2, 1)]);
        block.transactions.swap(0, 2);
        assert!(block.verify_body().is_err());
    }

    #[test]
    fn a_replaced_signature_is_rejected() {
        let mut block = block_with(vec![tx(0, 1)]);
        block.transactions[0].signature.pq = Some(vec![9u8; 3309]);
        assert!(block.verify_body().is_err());
        let mut block = block_with(vec![tx(0, 1)]);
        block.transactions[0].signature.classical = crate::account_signature::ClassicalProof::Raw {
            signature: vec![9u8; 64],
        };
        assert!(block.verify_body().is_err());
    }

    #[test]
    fn an_odd_leaf_is_not_duplicated() {
        // With leaf duplication, [a, b, c] and [a, b, c, c] would share a root.
        let three = Block::compute_tx_root(&[tx(0, 1), tx(1, 1), tx(2, 1)]);
        let four = Block::compute_tx_root(&[tx(0, 1), tx(1, 1), tx(2, 1), tx(2, 1)]);
        assert_ne!(three, four);
    }
}

#[cfg(test)]
mod hash_scheme_tests {
    use super::*;
    use crate::hash_scheme::HashScheme;

    fn header(height: u64, version: u32, prev: Hash, base_fee: Option<u128>) -> BlockHeader {
        BlockHeader {
            height: BlockHeight::from(height),
            epoch: 2,
            round: height * 3,
            anchor: Hash::new([4; 32]),
            prev_hash: prev,
            tx_root: Hash::new([5; 32]),
            state_root: Hash::new([6; 32]),
            event_root: Hash::new([7; 32]),
            receipts_root: Hash::new([8; 32]),
            logs_bloom: crate::LogsBloom::default(),
            timestamp: Timestamp::new(1_800_000_000_000 + height as i64),
            proposer: Address::new([9; 32]),
            metadata: BlockMetadata {
                gas_used: 21_000,
                gas_limit: 30_000_000,
                tx_count: 1,
                protocol_version: version,
                base_fee_per_gas: base_fee,
            },
        }
    }

    /// The header hash as it was computed before hash schemes were named:
    /// SHA-256 over the canonical fields.
    fn sha256_as_before(h: &BlockHeader) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(h.height.0.to_le_bytes());
        hasher.update(h.epoch.to_le_bytes());
        hasher.update(h.round.to_le_bytes());
        hasher.update(h.anchor.0);
        hasher.update(h.prev_hash.0);
        hasher.update(h.tx_root.0);
        hasher.update(h.state_root.0);
        hasher.update(h.event_root.0);
        hasher.update(h.receipts_root.0);
        hasher.update(h.logs_bloom.0);
        hasher.update(h.timestamp.0.to_le_bytes());
        hasher.update(h.proposer.0);
        hasher.update(h.metadata.gas_used.to_le_bytes());
        hasher.update(h.metadata.gas_limit.to_le_bytes());
        hasher.update(h.metadata.tx_count.to_le_bytes());
        hasher.update((h.metadata.protocol_version as u64).to_le_bytes());
        match h.metadata.base_fee_per_gas {
            None => hasher.update([0u8]),
            Some(bf) => {
                hasher.update([1u8]);
                hasher.update(bf.to_le_bytes());
            }
        }
        Hash::new(hasher.finalize().into())
    }

    /// Every header keeps the hash it had before schemes were named.
    #[test]
    fn existing_headers_keep_their_hashes() {
        for fee in [None, Some(0), Some(7_000_000_000)] {
            for version in [0, 1, 2, u32::MAX] {
                let h = header(5, version, Hash::new([1; 32]), fee);
                assert_eq!(h.hash(), sha256_as_before(&h));
            }
        }
    }

    /// A protocol upgrade moves the header hash to SHA3-256 from version 7:
    /// headers before it keep their SHA-256 hashes, those from it on are
    /// SHA3-256, and every parent link across the switch still verifies.
    #[test]
    fn the_header_hash_changes_at_the_version_an_upgrade_names_and_old_blocks_keep_theirs() {
        let schemes = [(0u32, HashScheme::Sha256), (7, HashScheme::Sha3_256)];
        let mut chain: Vec<BlockHeader> = Vec::new();
        let mut prev = Hash::zero();
        for (height, version) in [(1u64, 6u32), (2, 6), (3, 7), (4, 7)] {
            let h = header(height, version, prev, Some(1_000));
            prev = h.hash_under(&schemes);
            chain.push(h);
        }
        for h in &chain[..2] {
            assert_eq!(h.hash_under(&schemes), sha256_as_before(h));
            assert_eq!(h.hash_under(&schemes), h.hash());
        }
        for h in &chain[2..] {
            assert_ne!(h.hash_under(&schemes), sha256_as_before(h));
            assert_ne!(h.hash_under(&schemes), h.hash());
        }
        for w in chain.windows(2) {
            assert_eq!(w[1].prev_hash, w[0].hash_under(&schemes));
        }
        assert_eq!(
            crate::hash_scheme::block_hash_scheme(6, &schemes),
            HashScheme::Sha256
        );
        assert_eq!(
            crate::hash_scheme::block_hash_scheme(9, &schemes),
            HashScheme::Sha3_256
        );
    }
}
