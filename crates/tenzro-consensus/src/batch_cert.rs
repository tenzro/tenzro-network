//! Batch certificates: decoupling ordering bandwidth from data bandwidth.
//!
//! HotStuff-2 as originally wired carries full transaction bodies inside the
//! proposal. That makes the leader's egress bandwidth the throughput ceiling:
//! every block the leader mints has to be pushed, in full, to `2f+1` voters
//! before a quorum certificate can form. When a validator serves a large open
//! set, the leader is the bottleneck.
//!
//! This module implements the data-dissemination decoupling that the mempool's
//! own rustdoc points at ("certify data availability before consensus orders
//! it"):
//!
//! 1. A **batch producer** drains pending transactions into a [`Batch`] and
//!    disseminates the batch over a dedicated gossip topic.
//! 2. Validators that persist the batch return a signed acknowledgment. The
//!    producer aggregates `2f+1`-stake-weight of these into a
//!    [`BatchAvailabilityCertificate`] — a single BLS12-381 aggregate signature
//!    plus a signer bitmap over the [`ValidatorSet`], the identical shape used
//!    by [`crate::voter::QuorumCertificate`].
//! 3. The proposer then orders only certificate **hashes**. A proposal that
//!    references certified batches is a constant-size object regardless of how
//!    many transactions those batches hold, so ordering bandwidth is decoupled
//!    from data bandwidth.
//! 4. At execution/DECIDE the node **fetches the bodies** for each referenced
//!    certificate before applying, using the local [`BatchCertStore`] (or a
//!    pull over the same gossip mesh when the body is not local).
//!
//! # Large-set fan-out
//!
//! Direct gossip of a full batch to every peer costs `O(n · |batch|)` egress at
//! the producer. Above an adaptive validator-count threshold the producer
//! switches to **erasure-coded broadcast**: the batch is Reed-Solomon encoded
//! into per-validator slivers via [`tenzro_storage::redstuff`] and each
//! validator receives only its sliver. Any `2f+1` correct slivers reconstruct
//! the batch, so availability survives `f` faults while the producer pushes only
//! `O(|batch|)` total bytes instead of `O(n · |batch|)`.
//!
//! The switch threshold and the code's fault bound are **pure functions of the
//! validator-set size** — there is no hardcoded region count or fixed topology
//! (see [`erasure_activation_threshold`] and [`ErasurePlan::for_set_size`]).

use crate::error::{ConsensusError, Result};
use crate::validator::ValidatorSet;
use crate::voter::VOTE_FORMAT_VERSION;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_crypto::bls::{BlsKeyPair, BlsPublicKey, BlsSignature};
use tenzro_storage::{CF_AUDIT, CommitteeShape, KvStore};
use tenzro_types::primitives::{Address, Hash};
use tenzro_types::transaction::SignedTransaction;

/// Length-checked serde for a 96-byte BLS aggregate (G2 compressed point).
/// Mirrors `voter::bls_aggregate_serde` — `serde` won't auto-derive for arrays
/// wider than 32 bytes, and the 96-byte invariant is required by
/// `BlsSignature::from_bytes`, so widening to `Vec<u8>` would lose it.
mod bls_aggregate_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 96], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 96], D::Error> {
        let v: Vec<u8> = Vec::<u8>::deserialize(de)?;
        if v.len() != 96 {
            return Err(serde::de::Error::custom(format!(
                "batch-cert bls_aggregate must be exactly 96 bytes, got {}",
                v.len()
            )));
        }
        let mut out = [0u8; 96];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

/// The validator-set size at or above which the producer erasure-codes a batch
/// for fan-out instead of gossiping the full body to every peer.
///
/// Adaptive by construction: this is the crossover point where the extra
/// coding/reconstruction cost is paid back by the `O(n·|batch|) → O(|batch|)`
/// egress reduction. Below it, direct gossip wins on latency; above it,
/// per-validator slivers win on the producer's bandwidth. There is no fixed
/// region count and no assumption about topology — the only input is `n`.
pub const ERASURE_ACTIVATION_N: usize = 100;

/// Whether a validator set of `n` members warrants erasure-coded fan-out.
///
/// A pure function of the set size, evaluated fresh on every batch so a set
/// that grows or shrinks across epochs crosses the threshold automatically.
pub fn erasure_activation_threshold(n: usize) -> bool {
    n >= ERASURE_ACTIVATION_N
}

/// Domain tag for a batch content hash.
const BATCH_ID_TAG: &[u8] = b"TENZRO_BATCH_ID:";
/// Domain tag for the availability-acknowledgment BLS payload. Distinct from
/// the QC DST (`TENZRO_QC_BLS:`) so a batch-availability signature can never be
/// replayed as a consensus vote or vice-versa.
const BATCH_ACK_TAG: &[u8] = b"TENZRO_BATCH_ACK:";

/// A set of transactions grouped for dissemination and certification.
///
/// The batch id is a content hash over the ordered transaction hashes plus the
/// producer address and a producer-local sequence number, so two producers (or
/// one producer across rounds) never collide, and the id is verifiable from the
/// bodies alone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Batch {
    /// Content-derived identifier — see [`Batch::compute_id`].
    pub id: Hash,
    /// Producer that assembled the batch.
    pub producer: Address,
    /// Producer-local monotonic sequence number (uniqueness across rounds).
    pub sequence: u64,
    /// The transaction bodies. Present on the producer and on any validator
    /// that stored the full batch; a validator holding only an erasure sliver
    /// reconstructs this on demand.
    pub transactions: Vec<SignedTransaction>,
}

impl Batch {
    /// Assemble a batch from selected transactions, computing its content id.
    pub fn new(producer: Address, sequence: u64, transactions: Vec<SignedTransaction>) -> Self {
        let id = Self::compute_id(&producer, sequence, &transactions);
        Self {
            id,
            producer,
            sequence,
            transactions,
        }
    }

    /// `SHA-256(BATCH_ID_TAG || producer(32) || sequence(u64 LE) || n(u64 LE) ||
    /// Σ tx_hash(32))`. Order-sensitive: the batch commits to the exact ordering
    /// of its bodies.
    pub fn compute_id(
        producer: &Address,
        sequence: u64,
        transactions: &[SignedTransaction],
    ) -> Hash {
        let mut h = Sha256::new();
        h.update(BATCH_ID_TAG);
        h.update(producer.as_bytes());
        h.update(sequence.to_le_bytes());
        h.update((transactions.len() as u64).to_le_bytes());
        for tx in transactions {
            h.update(tx.transaction.hash().as_bytes());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        Hash::new(out)
    }

    /// Re-derive the id from the bodies and confirm it matches the stored id.
    /// A batch whose bodies were tampered fails this check.
    pub fn verify_id(&self) -> bool {
        Self::compute_id(&self.producer, self.sequence, &self.transactions) == self.id
    }

    /// Canonical bytes an availability acknowledgment signs over. Identical for
    /// every acknowledging validator (the precondition for sound BLS
    /// aggregation under one DST): `BATCH_ACK_TAG || VOTE_FORMAT_VERSION(1) ||
    /// batch_id(32)`.
    pub fn ack_payload(id: &Hash) -> Vec<u8> {
        let mut payload = Vec::with_capacity(BATCH_ACK_TAG.len() + 1 + 32);
        payload.extend_from_slice(BATCH_ACK_TAG);
        payload.push(VOTE_FORMAT_VERSION);
        payload.extend_from_slice(id.as_bytes());
        payload
    }

    /// Serialize the full batch (id + bodies) for gossip or persistence.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| ConsensusError::Internal(format!("batch serialize failed: {e}")))
    }

    /// Deserialize a batch from wire bytes, checking the content id.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let batch: Batch = serde_json::from_slice(bytes)
            .map_err(|e| ConsensusError::Internal(format!("batch deserialize failed: {e}")))?;
        if !batch.verify_id() {
            return Err(ConsensusError::Internal(
                "batch content id does not match bodies".to_string(),
            ));
        }
        Ok(batch)
    }
}

/// One validator's signed acknowledgment that it has stored a batch.
///
/// The producer collects these off the availability gossip topic and folds them
/// into a [`BatchAvailabilityCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAck {
    /// The batch being acknowledged.
    pub batch_id: Hash,
    /// The acknowledging validator.
    pub validator: Address,
    /// BLS12-381 (`min_pk`) signature over [`Batch::ack_payload`].
    pub bls_signature: Vec<u8>,
}

/// A `2f+1`-stake-weight availability certificate over a batch.
///
/// Wire-identical in shape to [`crate::voter::QuorumCertificate`]: a single
/// 96-byte BLS aggregate signature plus a signer bitmap indexed against the
/// active [`ValidatorSet`] (LSB-first, `n.div_ceil(8)` bytes). This is the
/// object a proposal references instead of the batch body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchAvailabilityCertificate {
    /// The certified batch.
    pub batch_id: Hash,
    /// Total voting power of the signer set, tallied at formation from the same
    /// active set the bitmap indexes. Re-derived and cross-checked on verify.
    pub voting_power: u128,
    /// Aggregate BLS signature over [`Batch::ack_payload`].
    #[serde(with = "bls_aggregate_serde")]
    pub bls_aggregate: [u8; 96],
    /// Signer bitmap over the active validator set (LSB-first). Bit `i` set iff
    /// `active[i]` contributed a signature to `bls_aggregate`.
    pub signer_bitmap: Vec<u8>,
}

impl BatchAvailabilityCertificate {
    /// Form a certificate from a batch id and a set of acknowledgments, given
    /// the active validator set the bitmap is indexed against.
    ///
    /// Reuses the exact BLS-aggregation path used for quorum certificates:
    /// per-ack `BlsSignature`s are combined via
    /// `tenzro_crypto::bls::aggregate_signatures`, and each signer's bit is set
    /// at `validator_set.index_of(&ack.validator)`. Fails if the collected
    /// signers do not reach `2f+1` stake-weight.
    pub fn form(batch_id: Hash, acks: &[BatchAck], validator_set: &ValidatorSet) -> Result<Self> {
        let active = validator_set.active_validators();
        let n = active.len();
        let bitmap_bytes = n.div_ceil(8);
        let mut signer_bitmap = vec![0u8; bitmap_bytes];
        let mut bls_sigs: Vec<BlsSignature> = Vec::new();
        let mut voting_power: u128 = 0;
        let normalized = validator_set.normalized_weights();
        let mut signed_power: u128 = 0;
        let mut seen = vec![false; n];

        for ack in acks {
            if ack.batch_id != batch_id {
                continue;
            }
            let Some(idx) = validator_set.index_of(&ack.validator) else {
                continue;
            };
            if seen[idx] {
                continue;
            }
            let sig = BlsSignature::from_bytes(&ack.bls_signature).map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "batch ack from {} carries malformed BLS signature: {e}",
                    ack.validator
                ))
            })?;
            // Verify the leg against the acknowledging validator's registered
            // BLS key before admitting it into the aggregate, so a forged ack
            // can never poison the certificate.
            let pk = BlsPublicKey::from_bytes(&active[idx].bls_public_key).map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "validator {} has malformed BLS key: {e}",
                    ack.validator
                ))
            })?;
            let payload = Batch::ack_payload(&batch_id);
            let ok = sig.verify(&pk, &payload).map_err(|e| {
                ConsensusError::InvalidSignature(format!("batch ack verify raised: {e}"))
            })?;
            if !ok {
                continue;
            }
            seen[idx] = true;
            signer_bitmap[idx / 8] |= 1 << (idx % 8);
            bls_sigs.push(sig);
            voting_power = voting_power.saturating_add(active[idx].voting_power());
            if let Some(w) = normalized.get(idx) {
                signed_power = signed_power.saturating_add(*w);
            }
        }

        let quorum_power = validator_set.quorum_voting_power();
        if signed_power < quorum_power {
            return Err(ConsensusError::InsufficientVotes {
                got: signed_power.min(u64::MAX as u128) as u64,
                need: quorum_power.min(u64::MAX as u128) as u64,
            });
        }

        let agg = tenzro_crypto::bls::aggregate_signatures(&bls_sigs).map_err(|e| {
            ConsensusError::InvalidSignature(format!("batch BLS aggregation failed: {e}"))
        })?;

        Ok(Self {
            batch_id,
            voting_power,
            bls_aggregate: agg.to_bytes(),
            signer_bitmap,
        })
    }

    /// Verify the aggregate signature carries `2f+1` stake-weight over the
    /// canonical ack payload. Mirrors `QuorumCertificate::verify_bls_aggregate`.
    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<()> {
        let active = validator_set.active_validators();
        let n = active.len();
        let expected_bitmap_bytes = n.div_ceil(8);
        if self.signer_bitmap.len() != expected_bitmap_bytes {
            return Err(ConsensusError::InvalidSignature(format!(
                "batch-cert signer_bitmap length {} does not match expected {} for {} validators",
                self.signer_bitmap.len(),
                expected_bitmap_bytes,
                n
            )));
        }

        let normalized = validator_set.normalized_weights();
        let mut signer_pks: Vec<BlsPublicKey> = Vec::new();
        let mut total_voting_power: u128 = 0;
        let mut signed_power: u128 = 0;
        // bit_index drives both the bitmap byte/bit math and the active-set index
        #[allow(clippy::needless_range_loop)]
        for bit_index in 0..(expected_bitmap_bytes * 8) {
            let byte = self.signer_bitmap[bit_index / 8];
            if (byte >> (bit_index % 8)) & 1 == 0 {
                continue;
            }
            if bit_index >= n {
                return Err(ConsensusError::InvalidSignature(format!(
                    "batch-cert bitmap bit {bit_index} set but active set has {n} validators"
                )));
            }
            let validator = &active[bit_index];
            let pk = BlsPublicKey::from_bytes(&validator.bls_public_key).map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "batch-cert signer {} has malformed BLS key: {e}",
                    validator.address
                ))
            })?;
            signer_pks.push(pk);
            total_voting_power = total_voting_power.saturating_add(validator.voting_power());
            if let Some(w) = normalized.get(bit_index) {
                signed_power = signed_power.saturating_add(*w);
            }
        }

        if signer_pks.is_empty() {
            return Err(ConsensusError::InvalidSignature(
                "batch-cert bitmap empty — no signers".to_string(),
            ));
        }

        let quorum_power = validator_set.quorum_voting_power();
        if signed_power < quorum_power {
            return Err(ConsensusError::InvalidSignature(format!(
                "batch-cert carries {signed_power} stake-weight from {} signers, below quorum {quorum_power}",
                signer_pks.len()
            )));
        }

        if self.voting_power != total_voting_power {
            return Err(ConsensusError::InvalidSignature(format!(
                "batch-cert claims voting_power={} but bitmap-tallied power is {total_voting_power}",
                self.voting_power
            )));
        }

        let agg_pk = tenzro_crypto::bls::aggregate_public_keys(&signer_pks).map_err(|e| {
            ConsensusError::InvalidSignature(format!(
                "batch-cert aggregate public-key reconstruction failed: {e}"
            ))
        })?;
        let agg_pk_single = BlsPublicKey::from_bytes(&agg_pk.to_bytes()).map_err(|e| {
            ConsensusError::InvalidSignature(format!(
                "batch-cert aggregate public-key round-trip failed: {e}"
            ))
        })?;
        let agg_sig = BlsSignature::from_bytes(&self.bls_aggregate).map_err(|e| {
            ConsensusError::InvalidSignature(format!(
                "batch-cert bls_aggregate is not a valid signature: {e}"
            ))
        })?;
        let payload = Batch::ack_payload(&self.batch_id);
        let ok = agg_sig.verify(&agg_pk_single, &payload).map_err(|e| {
            ConsensusError::InvalidSignature(format!("batch-cert aggregate verify raised: {e}"))
        })?;
        if !ok {
            return Err(ConsensusError::InvalidSignature(
                "batch-cert aggregate verification rejected the signature".to_string(),
            ));
        }
        Ok(())
    }
}

/// The erasure-coding plan for a batch, derived purely from the validator-set
/// size. Wraps [`tenzro_storage::CommitteeShape`] with the activation decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErasurePlan {
    /// The Reed-Solomon committee shape (`n = 3f+1`, quorum `2f+1`) the batch is
    /// coded for, or `None` when the set is below the activation threshold and
    /// direct gossip is used instead.
    pub shape: Option<CommitteeShape>,
}

impl ErasurePlan {
    /// Build the plan for a validator set of `n` members.
    ///
    /// - Below [`ERASURE_ACTIVATION_N`]: direct gossip (`shape = None`).
    /// - At or above it: Reed-Solomon over the largest fault bound the set
    ///   supports (`f = (n-1)/3`), so any `2f+1` slivers reconstruct.
    ///
    /// The activation point and the fault bound are both functions of `n`
    /// alone — no fixed region count, no topology assumption.
    pub fn for_set_size(n: usize) -> Self {
        if !erasure_activation_threshold(n) {
            return Self { shape: None };
        }
        // `from_committee_size` picks the largest f with 3f+1 <= n. For n >= 100
        // this always succeeds (needs n >= 4).
        let shape = CommitteeShape::from_committee_size(n).ok();
        Self { shape }
    }

    /// True when this plan erasure-codes rather than direct-gossips.
    pub fn is_coded(&self) -> bool {
        self.shape.is_some()
    }
}

/// Producer + tracker for batch certificates.
///
/// Owns the local producer sequence counter, the pool of certificates the node
/// has observed (its own and peers'), and the batch bodies keyed by id so the
/// execution path can fetch bodies for a referenced certificate. Persists both
/// certificates and bodies write-through to `CF_AUDIT` and hydrates them on
/// construction, so a restart does not lose certified-but-unexecuted batches.
/// Largest batch body this node will produce, in bytes.
///
/// A batch must fit inside a single block, because a block that can only carry
/// part of one forces the proposal path to slice it — and a sliced batch is
/// never fully finalized, so it is retained and re-proposed indefinitely. The
/// bound is well under `ConsensusConfig::max_block_size` (2 MiB) so several
/// whole batches still fit per block, and it matches the order of magnitude
/// Narwhal uses for worker batches (its worked example is 1,000 transactions of
/// 512 B each, i.e. 512 KB).
pub const MAX_BATCH_BYTES: usize = 512 * 1024;

pub struct BatchCertStore {
    /// This node's BLS key, used to sign availability acknowledgments and to
    /// sign the acks for batches it stores.
    bls_key: Arc<BlsKeyPair>,
    /// This node's address (producer identity).
    address: Address,
    /// Monotonic producer sequence.
    sequence: parking_lot::Mutex<u64>,
    /// Certificates observed, keyed by batch id.
    certs: DashMap<Hash, BatchAvailabilityCertificate>,
    /// Batch bodies held locally, keyed by batch id. Populated when this node
    /// produces or stores a batch; consulted by the execution fetch path.
    bodies: DashMap<Hash, Batch>,
    /// Pending availability acks for batches this node produced, keyed by batch
    /// id. Acks accumulate here until they reach `2f+1` stake-weight, at which
    /// point [`Self::record_ack`] forms the certificate and clears the buffer.
    /// Deduplicated by validator address within a batch. In-memory only — an
    /// uncertified batch that loses its acks across a restart is re-produced.
    pending_acks: DashMap<Hash, Vec<BatchAck>>,
    /// Transaction hashes already finalized on-chain, for batches still held.
    ///
    /// A batch is only evicted once *every* transaction in it is finalized, so
    /// a batch straddling a block boundary is retained — correctly, it still
    /// backs transactions that have not landed. But the ordering path
    /// concatenates whole bodies, so re-proposing that batch dragged its
    /// already-finalized transactions back in, every block, forever:
    ///
    ///   height=1936 tx_count=78
    ///   height=1937 tx_count=78   <- the same 78
    ///   height=1938 tx_count=78
    ///
    /// which produced ~3 blocks/second of duplicates and 33,864 execution
    /// failures in two minutes, all `Invalid nonce` — the transactions had
    /// already executed.
    ///
    /// The bodies cannot simply be pruned: a batch id commits to its contents,
    /// so editing a body would break [`Batch::verify_id`] and invalidate the
    /// certificate over it. Instead the store remembers what has landed and
    /// filters it out when a retained batch is reused.
    finalized_txs: DashMap<Hash, ()>,
    /// Optional durable store.
    storage: Option<Arc<dyn KvStore>>,
}

impl BatchCertStore {
    /// Key prefix under `CF_AUDIT` for a persisted certificate.
    fn cert_key(id: &Hash) -> Vec<u8> {
        let mut k = b"batch_cert/".to_vec();
        k.extend_from_slice(id.as_bytes());
        k
    }

    /// Key prefix under `CF_AUDIT` for a persisted batch body.
    fn body_key(id: &Hash) -> Vec<u8> {
        let mut k = b"batch_body/".to_vec();
        k.extend_from_slice(id.as_bytes());
        k
    }

    /// Build an in-memory store.
    pub fn new(bls_key: Arc<BlsKeyPair>, address: Address) -> Self {
        Self {
            bls_key,
            address,
            sequence: parking_lot::Mutex::new(0),
            certs: DashMap::new(),
            bodies: DashMap::new(),
            pending_acks: DashMap::new(),
            finalized_txs: DashMap::new(),
            storage: None,
        }
    }

    /// Build a durable store, hydrating any persisted certificates and bodies.
    pub fn with_storage(
        bls_key: Arc<BlsKeyPair>,
        address: Address,
        storage: Arc<dyn KvStore>,
    ) -> Self {
        let store = Self {
            bls_key,
            address,
            sequence: parking_lot::Mutex::new(0),
            certs: DashMap::new(),
            bodies: DashMap::new(),
            pending_acks: DashMap::new(),
            finalized_txs: DashMap::new(),
            storage: Some(storage),
        };
        store.hydrate();
        store
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        if let Ok(keys) = storage.get_keys_with_prefix(CF_AUDIT, b"batch_cert/") {
            for k in keys {
                if let Ok(Some(v)) = storage.get(CF_AUDIT, &k)
                    && let Ok(cert) = serde_json::from_slice::<BatchAvailabilityCertificate>(&v)
                {
                    self.certs.insert(cert.batch_id, cert);
                }
            }
        }
        if let Ok(keys) = storage.get_keys_with_prefix(CF_AUDIT, b"batch_body/") {
            for k in keys {
                if let Ok(Some(v)) = storage.get(CF_AUDIT, &k)
                    && let Ok(batch) = Batch::from_bytes(&v)
                {
                    self.bodies.insert(batch.id, batch);
                }
            }
        }
    }

    /// Assemble the next batch from selected transactions. Increments the local
    /// producer sequence and stores the body so this node can later serve it and
    /// sign its own availability ack.
    /// The prefix of `transactions` that fits within [`MAX_BATCH_BYTES`], and
    /// the remainder, which the caller should leave in the mempool for a later
    /// batch.
    ///
    /// Splitting here rather than at proposal time is the point: once a batch
    /// is certified, its contents are fixed — the id commits to them — so a
    /// batch too large for a block can only ever be used by slicing it, which
    /// is exactly what must not happen.
    pub fn split_to_fit(
        transactions: Vec<SignedTransaction>,
    ) -> (Vec<SignedTransaction>, Vec<SignedTransaction>) {
        let mut used = 0usize;
        let mut fitted = Vec::new();
        let mut deferred = Vec::new();
        for tx in transactions {
            let size = serde_json::to_string(&tx).map(|s| s.len()).unwrap_or(0);
            // Always take at least one, or a single transaction larger than the
            // bound would never batch at all and would wedge the mempool.
            if fitted.is_empty() || used.saturating_add(size) <= MAX_BATCH_BYTES {
                used = used.saturating_add(size);
                fitted.push(tx);
            } else {
                deferred.push(tx);
            }
        }
        (fitted, deferred)
    }

    pub fn produce(&self, transactions: Vec<SignedTransaction>) -> Batch {
        let seq = {
            let mut s = self.sequence.lock();
            let cur = *s;
            *s += 1;
            cur
        };
        let batch = Batch::new(self.address, seq, transactions);
        self.store_body(batch.clone());
        batch
    }

    /// Compute the erasure-coding plan for a batch given the current
    /// validator-set size and, when the set is at or above the activation
    /// threshold, Reed-Solomon-encode the batch bytes into per-node slivers.
    ///
    /// Below [`ERASURE_ACTIVATION_N`] this returns `Ok(None)`: the batch is
    /// disseminated as a full body over direct gossip, which is bandwidth-cheap
    /// at small `n`. At or above the threshold it returns the [`EncodedBlob`]
    /// (`n = 3f+1` sliver pairs, any `2f+1` of which reconstruct) so no single
    /// node has to upload the full body to every peer — each committee node
    /// holds one sliver and the body is reconstructable from a quorum. The
    /// activation point and the fault bound are pure functions of `n`; there is
    /// no fixed region count or topology assumption.
    pub fn encode_for_broadcast(
        &self,
        batch: &Batch,
        validator_count: usize,
    ) -> Result<Option<tenzro_storage::da::redstuff::EncodedBlob>> {
        let plan = ErasurePlan::for_set_size(validator_count);
        let Some(shape) = plan.shape else {
            return Ok(None);
        };
        let bytes = batch
            .to_bytes()
            .map_err(|e| ConsensusError::Internal(format!("batch encode: {e}")))?;
        let encoded = tenzro_storage::da::redstuff::encode(&bytes, shape).map_err(|e| {
            ConsensusError::Internal(format!("erasure encode (n={validator_count}): {e}"))
        })?;
        Ok(Some(encoded))
    }

    /// Sign an availability acknowledgment for a batch id with this node's BLS
    /// key. Called after the node has durably stored the batch (or its sliver).
    pub fn sign_ack(&self, batch_id: &Hash) -> BatchAck {
        let payload = Batch::ack_payload(batch_id);
        let sig = self.bls_key.sign(&payload);
        BatchAck {
            batch_id: *batch_id,
            validator: self.address,
            bls_signature: sig.to_bytes().to_vec(),
        }
    }

    /// Accumulate an availability ack toward a certificate for a batch this node
    /// produced.
    ///
    /// Buffers the ack (deduplicated by validator address) and attempts to form
    /// a [`BatchAvailabilityCertificate`] from the acks gathered so far. Returns:
    /// - `Ok(Some(cert))` once the buffered acks reach `2f+1` stake-weight — the
    ///   certificate is installed (write-through) and the buffer cleared;
    /// - `Ok(None)` while still below quorum;
    /// - `Err(..)` only on a malformed ack that `form` surfaces (a below-quorum
    ///   tally is *not* an error here — it is the normal `Ok(None)` case).
    ///
    /// If a certificate already exists for `batch_id` (a peer's cert arrived
    /// first, or acks re-arrive after formation) this returns `Ok(None)` without
    /// re-forming.
    pub fn record_ack(
        &self,
        batch_id: Hash,
        ack: BatchAck,
        validator_set: &ValidatorSet,
    ) -> Result<Option<BatchAvailabilityCertificate>> {
        if ack.batch_id != batch_id {
            return Ok(None);
        }
        if self.certs.contains_key(&batch_id) {
            return Ok(None);
        }
        {
            let mut entry = self.pending_acks.entry(batch_id).or_default();
            if entry.iter().any(|a| a.validator == ack.validator) {
                return Ok(None);
            }
            entry.push(ack);
        }
        let acks: Vec<BatchAck> = match self.pending_acks.get(&batch_id) {
            Some(v) => v.clone(),
            None => return Ok(None),
        };
        // `form` returns InsufficientVotes below quorum; treat that as "not yet".
        match BatchAvailabilityCertificate::form(batch_id, &acks, validator_set) {
            Ok(cert) => {
                self.install_cert(cert.clone(), validator_set)?;
                self.pending_acks.remove(&batch_id);
                Ok(Some(cert))
            }
            Err(ConsensusError::InsufficientVotes { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Record a batch body locally (write-through). Idempotent.
    pub fn store_body(&self, batch: Batch) {
        if let Some(ref storage) = self.storage
            && let Ok(bytes) = batch.to_bytes()
        {
            let _ = storage.put(CF_AUDIT, &Self::body_key(&batch.id), &bytes);
        }
        self.bodies.insert(batch.id, batch);
    }

    /// Record an observed certificate (write-through), verifying it against the
    /// current validator set first. Rejects a certificate that does not carry a
    /// valid `2f+1` aggregate.
    pub fn install_cert(
        &self,
        cert: BatchAvailabilityCertificate,
        validator_set: &ValidatorSet,
    ) -> Result<()> {
        cert.verify(validator_set)?;
        if let Some(ref storage) = self.storage
            && let Ok(bytes) = serde_json::to_vec(&cert)
        {
            let _ = storage.put(CF_AUDIT, &Self::cert_key(&cert.batch_id), &bytes);
        }
        self.certs.insert(cert.batch_id, cert);
        Ok(())
    }

    /// Look up a certificate by batch id.
    pub fn get_cert(&self, id: &Hash) -> Option<BatchAvailabilityCertificate> {
        self.certs.get(id).map(|c| c.clone())
    }

    /// Fetch a batch body by id for the execution/DECIDE path. Returns `None`
    /// when the body is not held locally — the caller then pulls it over the
    /// availability gossip mesh (or reconstructs it from slivers).
    pub fn get_body(&self, id: &Hash) -> Option<Batch> {
        self.bodies.get(id).map(|b| b.clone())
    }

    /// True when this node holds the body for `id`.
    pub fn has_body(&self, id: &Hash) -> bool {
        self.bodies.contains_key(id)
    }

    /// Drop a certificate and its body once the referencing block has been
    /// finalized and its transactions applied. Write-through removal.
    pub fn evict(&self, id: &Hash) {
        self.certs.remove(id);
        self.bodies.remove(id);
        self.pending_acks.remove(id);
        if let Some(ref storage) = self.storage {
            let _ = storage.delete(CF_AUDIT, &Self::cert_key(id));
            let _ = storage.delete(CF_AUDIT, &Self::body_key(id));
        }
    }

    /// Number of certificates currently tracked.
    pub fn cert_count(&self) -> usize {
        self.certs.len()
    }

    /// Evict every certified batch whose transactions have all been finalized
    /// by a committed block. Called from the DECIDE path with the finalized
    /// block's transaction-hash set: a batch whose bodies are now on-chain is
    /// no longer needed for availability and its cert/body/pending-acks are
    /// dropped (write-through removal). A batch not yet fully finalized (e.g.
    /// only partially included) is retained so it can still back a later block.
    /// Returns the number of batches evicted.
    pub fn evict_finalized(&self, finalized_tx_hashes: &std::collections::HashSet<Hash>) -> usize {
        // Remember every hash that landed, so a batch retained for its
        // still-pending transactions does not re-offer the ones that did.
        for h in finalized_tx_hashes {
            self.finalized_txs.insert(*h, ());
        }

        // Iterate bodies rather than certs. A batch this node produced holds a
        // body from the moment it is created but has no certificate until acks
        // reach quorum, so scanning certs left every uncertified body in place
        // forever — a leak, and one that hid this eviction path from any batch
        // that never certified.
        let to_evict: Vec<Hash> = self
            .bodies
            .iter()
            .filter_map(|entry| {
                let id = *entry.key();
                let body = entry.value();
                // Against the accumulated set, not just this block: a batch
                // whose transactions landed across several blocks is fully
                // finalized even though no single block contained all of them,
                // and checking one block at a time never evicted it.
                let all_finalized = body
                    .transactions
                    .iter()
                    .all(|tx| self.finalized_txs.contains_key(&tx.transaction.hash()));
                if all_finalized { Some(id) } else { None }
            })
            .collect();

        for id in &to_evict {
            // Drop this batch's hashes from the set as it goes — they are only
            // needed while some retained batch could still offer them, so the
            // set stays bounded by the unfinalized frontier rather than growing
            // with chain history.
            if let Some(body) = self.bodies.get(id) {
                for tx in &body.transactions {
                    self.finalized_txs.remove(&tx.transaction.hash());
                }
            }
            self.evict(id);
        }
        to_evict.len()
    }

    /// Whether this transaction has already been finalized on-chain.
    ///
    /// Consulted by the ordering path so a retained batch contributes only its
    /// still-pending transactions to a proposal.
    pub fn is_finalized(&self, tx_hash: &Hash) -> bool {
        self.finalized_txs.contains_key(tx_hash)
    }

    /// Record a transaction that can never execute, so it is never proposed
    /// again.
    ///
    /// Removing it from the mempool is not enough. A certified batch holds its
    /// own copy, and the ordering path sources proposals from the certified
    /// prefix — so a permanently-invalid transaction was evicted from the
    /// mempool, re-offered by its batch, evicted again, forever. It was
    /// observed retrying 78 times in five minutes while eviction fired 180
    /// times against the wrong store.
    ///
    /// Shares the `finalized_txs` set: both answer the same question the
    /// ordering path asks — will this transaction ever need to be in a block
    /// again — and the set is bounded the same way, dropped when its batch is
    /// evicted rather than growing with history.
    pub fn mark_terminal(&self, tx_hash: Hash) {
        self.finalized_txs.insert(tx_hash, ());
    }

    /// The ordered prefix of certified batch ids this node can reference in a
    /// proposal (G6 prefix consensus).
    ///
    /// A batch id is eligible only when this node holds BOTH a valid
    /// availability certificate AND the body (the body carries the
    /// `(producer, sequence)` key the ordering is deterministic on). The
    /// eligible set is sorted by `(producer, sequence)` — the same total order
    /// every honest node derives from the same certified history — then run
    /// through [`agree_prefix`] against the certified id-set so a candidate
    /// missing its certificate truncates the prefix. Two honest proposers with
    /// the same certified history therefore emit the same ordered id list, and
    /// the ordering path references only these hashes rather than full bodies.
    pub fn certified_prefix(&self) -> Vec<Hash> {
        let mut ordered: Vec<(Address, u64, Hash)> = self
            .certs
            .iter()
            .filter_map(|entry| {
                let id = *entry.key();
                self.bodies.get(&id).map(|b| (b.producer, b.sequence, id))
            })
            .collect();
        ordered.sort_by(|a, b| a.0.0.cmp(&b.0.0).then(a.1.cmp(&b.1)));
        let certified: std::collections::HashSet<Hash> =
            self.certs.iter().map(|e| *e.key()).collect();
        let local: Vec<Hash> = ordered.into_iter().map(|(_, _, id)| id).collect();
        agree_prefix(&local, &certified)
    }
}

/// Agree on a prefix of certified batches.
///
/// The ordering path does not need to agree on an arbitrary set of certificate
/// hashes — it agrees on a **prefix** of the producers' certified sequences.
/// Given each node's locally-observed certificate ids (already `2f+1`-certified)
/// this returns the longest prefix, ordered by `(producer, sequence)`, such that
/// every id in the prefix is present in the reference set. A proposal carries
/// exactly this prefix, so two honest nodes building on the same certified
/// history produce the same ordered reference list deterministically.
///
/// `local` is this node's ordered candidate list; `certified` is the id-set the
/// node has valid certificates for. Any candidate lacking a certificate breaks
/// the prefix (everything after it is deferred to a later block).
pub fn agree_prefix(local: &[Hash], certified: &std::collections::HashSet<Hash>) -> Vec<Hash> {
    let mut prefix = Vec::new();
    for id in local {
        if certified.contains(id) {
            prefix.push(*id);
        } else {
            break;
        }
    }
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::{ValidatorInfo, ValidatorSet};
    use std::collections::HashSet;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::{KeyPair, KeyType};

    fn addr(byte: u8) -> Address {
        Address::new([byte; 32])
    }

    fn make_validator(byte: u8, stake: u128) -> (ValidatorInfo, Arc<BlsKeyPair>) {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pq = MlDsaSigningKey::generate();
        let bls = BlsKeyPair::generate().unwrap();
        let info = ValidatorInfo::new(
            addr(byte),
            kp.public_key().clone(),
            pq.verifying_key_bytes().to_vec(),
            bls.public_key().to_bytes().to_vec(),
            stake,
        );
        (info, Arc::new(bls))
    }

    #[test]
    fn batch_id_is_content_bound() {
        let b1 = Batch::new(addr(1), 0, vec![]);
        let b2 = Batch::new(addr(1), 1, vec![]);
        assert_ne!(b1.id, b2.id, "sequence must disambiguate empty batches");
        assert!(b1.verify_id());
        assert!(b2.verify_id());
    }

    #[test]
    fn erasure_plan_is_pure_function_of_n() {
        assert!(!ErasurePlan::for_set_size(4).is_coded());
        assert!(!ErasurePlan::for_set_size(50).is_coded());
        assert!(!ErasurePlan::for_set_size(99).is_coded());
        assert!(ErasurePlan::for_set_size(100).is_coded());
        assert!(ErasurePlan::for_set_size(1000).is_coded());
        // At n=1000 the fault bound is floor((1000-1)/3)=333, quorum 2f+1=667.
        let plan = ErasurePlan::for_set_size(1000);
        let shape = plan.shape.unwrap();
        assert_eq!(shape.f, 333);
        assert_eq!(shape.quorum(), 667);
    }

    #[test]
    fn availability_cert_forms_and_verifies_at_quorum() {
        // 4 validators, equal stake → quorum_voting_power needs 3 signers.
        let mut infos = Vec::new();
        let mut keys = Vec::new();
        for i in 0..4u8 {
            let (info, bls) = make_validator(i + 1, 1000);
            infos.push(info);
            keys.push(bls);
        }
        let vset = ValidatorSet::new(0, infos.clone()).unwrap();
        let batch = Batch::new(addr(1), 0, vec![]);

        // 3 of 4 acknowledge.
        let mut acks = Vec::new();
        for i in 0..3usize {
            let payload = Batch::ack_payload(&batch.id);
            let sig = keys[i].sign(&payload);
            acks.push(BatchAck {
                batch_id: batch.id,
                validator: infos[i].address,
                bls_signature: sig.to_bytes().to_vec(),
            });
        }
        let cert = BatchAvailabilityCertificate::form(batch.id, &acks, &vset).unwrap();
        assert!(cert.verify(&vset).is_ok());
    }

    #[test]
    fn availability_cert_rejects_below_quorum() {
        let mut infos = Vec::new();
        let mut keys = Vec::new();
        for i in 0..4u8 {
            let (info, bls) = make_validator(i + 1, 1000);
            infos.push(info);
            keys.push(bls);
        }
        let vset = ValidatorSet::new(0, infos.clone()).unwrap();
        let batch = Batch::new(addr(1), 0, vec![]);
        // Only 2 of 4 acknowledge — below 2f+1 = 3.
        let mut acks = Vec::new();
        for i in 0..2usize {
            let payload = Batch::ack_payload(&batch.id);
            let sig = keys[i].sign(&payload);
            acks.push(BatchAck {
                batch_id: batch.id,
                validator: infos[i].address,
                bls_signature: sig.to_bytes().to_vec(),
            });
        }
        assert!(BatchAvailabilityCertificate::form(batch.id, &acks, &vset).is_err());
    }

    #[test]
    fn prefix_stops_at_first_uncertified() {
        let ids: Vec<Hash> = (0..5u8).map(|i| Hash::new([i; 32])).collect();
        let mut certified = HashSet::new();
        certified.insert(ids[0]);
        certified.insert(ids[1]);
        certified.insert(ids[3]); // gap at index 2
        let prefix = agree_prefix(&ids, &certified);
        assert_eq!(prefix, vec![ids[0], ids[1]]);
    }

    #[test]
    fn record_ack_forms_cert_at_quorum() {
        // 4 validators, equal stake → 3 acks reach 2f+1.
        let mut infos = Vec::new();
        let mut keys = Vec::new();
        for i in 0..4u8 {
            let (info, bls) = make_validator(i + 1, 1000);
            infos.push(info);
            keys.push(bls);
        }
        let vset = ValidatorSet::new(0, infos.clone()).unwrap();
        // Producer is validator 0.
        let store = BatchCertStore::new(keys[0].clone(), infos[0].address);
        let batch = store.produce(vec![]);

        // Producer's own ack: below quorum, no cert yet.
        let ack0 = store.sign_ack(&batch.id);
        assert!(store.record_ack(batch.id, ack0, &vset).unwrap().is_none());

        // Second ack: still below quorum (2 of 4).
        let ack1 = BatchAck {
            batch_id: batch.id,
            validator: infos[1].address,
            bls_signature: keys[1]
                .sign(&Batch::ack_payload(&batch.id))
                .to_bytes()
                .to_vec(),
        };
        assert!(store.record_ack(batch.id, ack1, &vset).unwrap().is_none());

        // Third ack: reaches 2f+1 → cert formed and installed.
        let ack2 = BatchAck {
            batch_id: batch.id,
            validator: infos[2].address,
            bls_signature: keys[2]
                .sign(&Batch::ack_payload(&batch.id))
                .to_bytes()
                .to_vec(),
        };
        let cert = store.record_ack(batch.id, ack2, &vset).unwrap();
        assert!(cert.is_some(), "third ack should reach quorum");
        assert!(store.get_cert(&batch.id).is_some());
        assert!(cert.unwrap().verify(&vset).is_ok());
    }

    #[test]
    fn record_ack_dedups_by_validator() {
        let mut infos = Vec::new();
        let mut keys = Vec::new();
        for i in 0..4u8 {
            let (info, bls) = make_validator(i + 1, 1000);
            infos.push(info);
            keys.push(bls);
        }
        let vset = ValidatorSet::new(0, infos.clone()).unwrap();
        let store = BatchCertStore::new(keys[0].clone(), infos[0].address);
        let batch = store.produce(vec![]);
        let ack = store.sign_ack(&batch.id);
        assert!(
            store
                .record_ack(batch.id, ack.clone(), &vset)
                .unwrap()
                .is_none()
        );
        // Same validator's ack again must not double-count.
        assert!(store.record_ack(batch.id, ack, &vset).unwrap().is_none());
        assert!(store.get_cert(&batch.id).is_none());
    }

    fn tx_with_nonce(n: u64) -> SignedTransaction {
        use tenzro_crypto::pq::MlDsaSigningKey;
        use tenzro_types::primitives::{ChainId, Nonce};
        use tenzro_types::transaction::{Transaction, TransactionType};
        use tenzro_types::Signature;

        let pq_key = MlDsaSigningKey::generate();
        let tx = Transaction::new(
            ChainId::from(1),
            Address::default(),
            Address::default(),
            Nonce::from(n),
            TransactionType::Transfer { amount: 1 },
            21000,
            100,
            pq_key.verifying_key_bytes().to_vec(),
        );
        let sig = pq_key.sign(tx.hash().as_bytes()).to_vec();
        SignedTransaction::new(tx, Signature::default(), sig)
    }

    /// A batch must never be larger than a block.
    ///
    /// `select_transactions` caps count and gas but not bytes, so a batch could
    /// hold thousands of transactions and dwarf the 2 MiB block limit. A batch
    /// bigger than a block can only be used by slicing it, and a sliced batch is
    /// only partially finalized — retained, then re-offered forever. Bounding at
    /// creation is what lets whole-batch inclusion always make progress.
    #[test]
    fn a_batch_is_bounded_to_fit_inside_a_block() {
        let many: Vec<_> = (1..=400).map(tx_with_nonce).collect();
        let offered = many.len();
        let (fitted, deferred) = BatchCertStore::split_to_fit(many);

        assert!(!fitted.is_empty(), "a batch must make progress");
        assert_eq!(fitted.len() + deferred.len(), offered, "nothing may be dropped");

        let size: usize = fitted
            .iter()
            .map(|t| serde_json::to_string(t).map(|s| s.len()).unwrap_or(0))
            .sum();
        assert!(size <= MAX_BATCH_BYTES, "batch is {size} bytes, over the bound");
        // Compared against the live config rather than a literal, so this
        // tracks the real limit instead of a constant clippy can fold away.
        assert!(
            MAX_BATCH_BYTES < crate::config::ConsensusConfig::default().max_block_size,
            "the bound must leave room for a whole batch inside a block"
        );
    }

    /// A single transaction larger than the bound must still batch.
    ///
    /// Otherwise it can never be included and blocks the mempool behind it,
    /// trading one liveness bug for another.
    #[test]
    fn an_oversized_single_transaction_still_makes_progress() {
        let (fitted, deferred) = BatchCertStore::split_to_fit(vec![tx_with_nonce(1)]);
        assert_eq!(fitted.len(), 1);
        assert!(deferred.is_empty());
    }

    /// A transaction marked terminal is never offered again.
    ///
    /// Evicting from the mempool alone did not stop it: a certified batch holds
    /// its own copy and the ordering path sources proposals from the certified
    /// prefix, so the eviction was undone by the very next proposal. Two stale
    /// grants were seen retrying 78 and 72 times in five minutes while eviction
    /// fired 180 times against the wrong store.
    #[test]
    fn a_terminal_transaction_is_not_offered_again() {
        let (_info, bls) = make_validator(9, 1000);
        let store = BatchCertStore::new(bls, addr(9));

        let doomed = tx_with_nonce(1);
        let good = tx_with_nonce(2);
        let batch = store.produce(vec![doomed.clone(), good.clone()]);

        store.mark_terminal(doomed.transaction.hash());

        // The batch survives — `good` still needs a block — but the doomed
        // transaction is filtered out of any proposal built from it.
        assert!(store.has_body(&batch.id));
        assert!(store.is_finalized(&doomed.transaction.hash()));
        assert!(!store.is_finalized(&good.transaction.hash()));
    }

    /// A partially-finalized batch must not re-offer what already landed.
    ///
    /// This is what drove the chain to ~3 blocks/second of duplicates. A batch
    /// is retained until *all* of its transactions finalize, which is correct —
    /// it still backs the ones that have not. But the ordering path
    /// concatenated whole bodies, so the landed transactions came back on every
    /// proposal and failed execution with `Invalid nonce`, forever.
    #[test]
    fn a_partially_finalized_batch_stops_offering_what_landed() {
        let (_info, bls) = make_validator(9, 1000);
        let store = BatchCertStore::new(bls, addr(9));

        let landed = tx_with_nonce(1);
        let pending = tx_with_nonce(2);
        let batch = store.produce(vec![landed.clone(), pending.clone()]);

        // One of the two makes it into a block.
        let mut finalized = std::collections::HashSet::new();
        finalized.insert(landed.transaction.hash());
        store.evict_finalized(&finalized);

        // The batch is correctly retained — `pending` still needs a block.
        assert!(
            store.has_body(&batch.id),
            "a batch with unfinalized transactions must be kept"
        );
        // But the landed one must never be offered again.
        assert!(store.is_finalized(&landed.transaction.hash()));
        assert!(!store.is_finalized(&pending.transaction.hash()));
    }

    /// A batch finalized across several blocks is eventually evicted.
    ///
    /// Eviction compared against one block at a time, so a batch whose
    /// transactions were split across blocks was never fully covered by any
    /// single comparison and was retained forever.
    #[test]
    fn a_batch_finalized_across_blocks_is_evicted() {
        let (_info, bls) = make_validator(9, 1000);
        let store = BatchCertStore::new(bls, addr(9));

        let first = tx_with_nonce(1);
        let second = tx_with_nonce(2);
        let batch = store.produce(vec![first.clone(), second.clone()]);

        let mut block_a = std::collections::HashSet::new();
        block_a.insert(first.transaction.hash());
        assert_eq!(store.evict_finalized(&block_a), 0, "still one to go");
        assert!(store.has_body(&batch.id));

        let mut block_b = std::collections::HashSet::new();
        block_b.insert(second.transaction.hash());
        assert_eq!(
            store.evict_finalized(&block_b),
            1,
            "the batch is fully finalized now, across two blocks"
        );
        assert!(!store.has_body(&batch.id));

        // Its hashes are dropped with it, so the set tracks the unfinalized
        // frontier rather than growing with chain history.
        assert!(!store.is_finalized(&first.transaction.hash()));
        assert!(!store.is_finalized(&second.transaction.hash()));
    }

    #[test]
    fn store_produce_and_fetch_body() {
        let (_info, bls) = make_validator(9, 1000);
        let store = BatchCertStore::new(bls, addr(9));
        let batch = store.produce(vec![]);
        assert!(store.has_body(&batch.id));
        let fetched = store.get_body(&batch.id).unwrap();
        assert_eq!(fetched.id, batch.id);
        store.evict(&batch.id);
        assert!(!store.has_body(&batch.id));
    }
}
