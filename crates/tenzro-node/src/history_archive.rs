//! Bounded local history, with older blocks held by the committee's
//! data-availability layer.
//!
//! Validators and RPC nodes keep the live state and the most recent
//! [`HISTORY_RETENTION_PARAM`](tenzro_vm::governance::HISTORY_RETENTION_PARAM)
//! blocks. Older blocks leave the local store in segments: a run of
//! certified checkpoints, closed at an epoch's last checkpoint or once it
//! covers [`SEGMENT_MAX_BLOCKS`]. A segment is first written to the DA layer,
//! where bonded storage providers hold the erasure-coded slivers and answer
//! possession challenges, and its pointer is recorded durably; only then are
//! its blocks deleted locally.
//!
//! A committee member writes each segment into the DA layer itself. A node
//! outside the committee (an RPC node) writes nothing: it asks committee
//! members where the DA layer holds the segment, fetches it, and deletes its
//! own copy only once the fetched segment verifies. Until a member names a
//! segment that verifies, the node keeps those blocks.
//!
//! A node with no DA layer to hand history to keeps the same window and
//! deletes what falls below it: history past the window is kept whole only
//! by a node run as an archive (`storage.archival`).
//!
//! A pruned block's transactions, their locations and their receipts go
//! with it. The block, transactions included, can still be fetched back from
//! the DA layer by height; a transaction or receipt looked up by hash below
//! the window is not found here.
//!
//! A pruned block is fetched back from the DA layer and trusted only after
//! the segment's blocks rebuild the blocks root of every checkpoint the
//! segment covers, each checkpoint body being one this node authenticated
//! through a certificate. Where the bytes came from does not matter.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tenzro_consensus::Checkpoint;
use tenzro_events::EventLog;
use tenzro_storage::da::{DaBackend, DaPointer};
use tenzro_storage::traits::BlockStore;
use tenzro_storage::{
    BlockStoreImpl, CF_METADATA, CF_TRANSACTIONS, KvStore, RocksDbStore, WriteOp,
};
use tenzro_types::block::Block;
use tenzro_types::chain_event::{ChainEvent, event_root};
use tenzro_types::primitives::BlockHeight;
use tracing::warn;

use crate::certified_import::check_range;
use crate::error::{NodeError, Result};

/// DA namespace history segments are written under.
pub const HISTORY_NAMESPACE: &[u8] = b"tenzro/history";

/// Most blocks one segment covers.
pub const SEGMENT_MAX_BLOCKS: u64 = 4_096;

/// Next checkpoint index not yet handed to the DA layer.
const NEXT_CHECKPOINT_KEY: &[u8] = b"history/next_checkpoint";
/// Number of segments recorded.
const SEGMENT_COUNT_KEY: &[u8] = b"history/segments";

fn segment_key(ordinal: u64) -> Vec<u8> {
    [b"history/segment/".as_slice(), &ordinal.to_be_bytes()].concat()
}

/// Digest of the last checkpoint body a recorded segment covers, kept when
/// the segment is recorded from a body this node authenticated.
fn segment_digest_key(ordinal: u64) -> Vec<u8> {
    [
        b"history/segment_digest/".as_slice(),
        &ordinal.to_be_bytes(),
    ]
    .concat()
}

/// Checkpoint bodies this node has authenticated.
pub trait CertifiedCheckpoints: Send + Sync {
    /// The authenticated checkpoint body with `index`.
    fn checkpoint(&self, index: u64) -> Option<Checkpoint>;
    /// Index of the latest certified checkpoint.
    fn latest_index(&self) -> Option<u64>;
}

impl CertifiedCheckpoints for crate::consensus_driver::ConsensusHandle {
    fn checkpoint(&self, index: u64) -> Option<Checkpoint> {
        crate::consensus_driver::ConsensusHandle::checkpoint(self, index)
    }

    fn latest_index(&self) -> Option<u64> {
        self.latest_certificate().map(|c| c.checkpoint.index)
    }
}

/// Names where the DA layer holds a history segment. Answers are untrusted:
/// a segment is used only once its bytes verify against the checkpoints.
#[async_trait::async_trait]
pub trait SegmentLocator: Send + Sync {
    /// Segment records starting at checkpoint `first_index`, as reported.
    async fn locate(&self, first_index: u64) -> Vec<ArchivedSegment>;
}

/// How a closed segment reaches the DA layer before its blocks are deleted.
pub enum Handoff {
    /// This node is a committee member and writes the segment itself.
    Submit,
    /// This node is outside the committee: it deletes a segment only once a
    /// located copy of it verifies.
    Locate(Arc<dyn SegmentLocator>),
}

/// Where a pruned segment lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedSegment {
    /// First checkpoint index covered.
    pub first_index: u64,
    /// Last checkpoint index covered.
    pub last_index: u64,
    /// First block height covered.
    pub first_height: u64,
    /// Last block height covered.
    pub last_height: u64,
    /// The segment in the DA layer.
    pub pointer: DaPointer,
}

/// What one segment carries in the DA layer. JSON, like the block store,
/// because blocks carry internally tagged enums.
#[derive(Serialize, Deserialize)]
struct SegmentPayload {
    first_index: u64,
    blocks: Vec<Block>,
    /// Each block's events, in block order.
    events: Vec<Vec<ChainEvent>>,
    /// The bodies of the checkpoints the segment covers, so it verifies
    /// after a node has dropped its own copies of them.
    #[serde(default)]
    checkpoints: Vec<Checkpoint>,
}

/// A segment fetched back from the DA layer and verified: its blocks, and
/// each block's events.
#[derive(Debug, Clone)]
pub struct VerifiedSegment {
    /// The blocks, in height order.
    pub blocks: Vec<Block>,
    /// Each block's events, in block order.
    pub events: Vec<Vec<ChainEvent>>,
}

/// What one pruning pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Segments written to the DA layer and deleted locally.
    pub segments: u64,
    /// Blocks deleted locally.
    pub blocks: u64,
    /// Events deleted locally.
    pub events: u64,
    /// Transactions deleted locally, with their locations and receipts.
    pub transactions: u64,
}

/// Retention and retrieval of block history.
pub struct HistoryArchive {
    storage: Arc<RocksDbStore>,
    /// `None` on a node with no DA layer: history below the floor is
    /// deleted and kept nowhere.
    da: Option<Arc<dyn DaBackend>>,
    checkpoints: Arc<dyn CertifiedCheckpoints>,
    handoff: Handoff,
    events: EventLog,
    /// Delete the height and hash indexes of pruned blocks too, as an edge
    /// node does: a pruned block is then found only by height, from the DA
    /// layer.
    drop_indexes: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for HistoryArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryArchive").finish_non_exhaustive()
    }
}

fn read_u64<S: KvStore + ?Sized>(storage: &S, key: &[u8]) -> Result<u64> {
    Ok(storage
        .get(CF_METADATA, key)?
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0))
}

fn read_segment<S: KvStore + ?Sized>(storage: &S, ordinal: u64) -> Result<ArchivedSegment> {
    let bytes = storage
        .get(CF_METADATA, &segment_key(ordinal))?
        .ok_or_else(|| NodeError::Other(format!("history segment record {ordinal} is missing")))?;
    bincode::deserialize(&bytes)
        .map_err(|e| NodeError::Other(format!("segment record {ordinal}: {e}")))
}

/// The segment this node recorded as starting at checkpoint `first_index`,
/// answered to nodes outside the committee that locate history.
pub fn recorded_segment<S: KvStore + ?Sized>(
    storage: &S,
    first_index: u64,
) -> Result<Option<ArchivedSegment>> {
    let (mut lo, mut hi) = (0u64, read_u64(storage, SEGMENT_COUNT_KEY)?);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let seg = read_segment(storage, mid)?;
        match first_index.cmp(&seg.first_index) {
            std::cmp::Ordering::Less => hi = mid,
            std::cmp::Ordering::Greater => lo = mid + 1,
            std::cmp::Ordering::Equal => return Ok(Some(seg)),
        }
    }
    Ok(None)
}

impl HistoryArchive {
    /// History over `storage`, pruned into `da` as `handoff` says, verified
    /// against `checkpoints`.
    pub fn new(
        storage: Arc<RocksDbStore>,
        da: Arc<dyn DaBackend>,
        checkpoints: Arc<dyn CertifiedCheckpoints>,
        handoff: Handoff,
    ) -> Result<Self> {
        let events = EventLog::open(storage.clone() as Arc<dyn KvStore>)?;
        Ok(Self {
            storage,
            da: Some(da),
            checkpoints,
            handoff,
            events,
            drop_indexes: Default::default(),
        })
    }

    /// History over `storage` on a node with no DA layer to hand it to: the
    /// same window is kept and what falls below it is deleted.
    pub fn local(
        storage: Arc<RocksDbStore>,
        checkpoints: Arc<dyn CertifiedCheckpoints>,
    ) -> Result<Self> {
        let events = EventLog::open(storage.clone() as Arc<dyn KvStore>)?;
        Ok(Self {
            storage,
            da: None,
            checkpoints,
            handoff: Handoff::Submit,
            events,
            drop_indexes: Default::default(),
        })
    }

    /// Whether pruning also deletes the height and hash indexes of the
    /// blocks it deletes.
    pub fn set_drop_indexes(&self, drop: bool) {
        self.drop_indexes
            .store(drop, std::sync::atomic::Ordering::Relaxed);
    }

    /// The first checkpoint whose blocks this node still holds: every one
    /// before it was handed over (or, with no DA layer, dropped) and its
    /// blocks deleted.
    pub fn next_checkpoint(&self) -> Result<u64> {
        read_u64(&*self.storage, NEXT_CHECKPOINT_KEY)
    }

    /// Hands every closed segment wholly below `floor` to the DA layer and
    /// deletes its blocks locally, with their events and transactions. A
    /// segment is deleted only after the DA layer returned its pointer and
    /// the pointer is recorded. With no DA layer it is deleted outright.
    pub async fn prune_below(&self, floor: u64) -> Result<PruneReport> {
        self.prune_below_limited(floor, usize::MAX).await
    }

    /// As [`Self::prune_below`], handing over at most `max_segments` closed
    /// segments (a segment covers at most [`SEGMENT_MAX_BLOCKS`] blocks). The
    /// node calls it every pass with a small bound while the volume has room,
    /// so history leaves in steady small steps and never in one large burst;
    /// under disk pressure it calls it unbounded.
    pub async fn prune_below_limited(
        &self,
        floor: u64,
        max_segments: usize,
    ) -> Result<PruneReport> {
        let mut report = PruneReport::default();
        let mut steps = 0usize;
        let Some(latest) = self.checkpoints.latest_index() else {
            return Ok(report);
        };
        let blocks = BlockStoreImpl::new(self.storage.clone())?;
        let mut next = read_u64(&*self.storage, NEXT_CHECKPOINT_KEY)?;
        loop {
            if steps >= max_segments {
                return Ok(report);
            }
            steps += 1;
            let mut cps: Vec<Checkpoint> = Vec::new();
            let mut covered = 0u64;
            let mut closed = false;
            let mut index = next;
            while index <= latest {
                let Some(cp) = self.checkpoints.checkpoint(index) else {
                    return Err(NodeError::Other(format!(
                        "checkpoint {index} has no authenticated body"
                    )));
                };
                if cp.last_height >= floor && cp.first_height <= cp.last_height {
                    break;
                }
                covered += (cp.last_height + 1).saturating_sub(cp.first_height);
                closed = cp.next_committee_root.is_some() || covered >= SEGMENT_MAX_BLOCKS;
                cps.push(cp);
                index += 1;
                if closed {
                    break;
                }
            }
            if !closed {
                return Ok(report);
            }
            let first_height = cps[0].first_height;
            let last_height = cps
                .last()
                .expect("a closed segment holds a checkpoint")
                .last_height;

            let mut held = Vec::with_capacity(covered as usize);
            for h in first_height..=last_height {
                if let Some(b) = blocks.get_block_by_height(BlockHeight(h)).await? {
                    held.push(b);
                }
            }
            if held.is_empty() {
                // Nothing of this segment is held here (the node started from
                // a snapshot above it): nothing to hand over or delete.
                next = index;
                self.storage
                    .put(CF_METADATA, NEXT_CHECKPOINT_KEY, &next.to_be_bytes())?;
                continue;
            }
            if held.len() as u64 != covered {
                return Err(NodeError::Other(format!(
                    "heights {first_height}..={last_height} are only partly held ({} of {covered} blocks)",
                    held.len()
                )));
            }
            check_segment(&cps, &held)?;
            let events = held
                .iter()
                .map(|b| self.events.block(b.height().0))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            check_events(&held, &events)?;
            let transactions: Vec<String> = held
                .iter()
                .flat_map(|b| b.transactions.iter())
                .map(|t| t.transaction.hash().to_string())
                .collect();

            let segment = match (&self.da, &self.handoff) {
                (None, _) => None,
                (Some(da), Handoff::Submit) => {
                    let payload = serde_json::to_vec(&SegmentPayload {
                        first_index: cps[0].index,
                        blocks: held,
                        events,
                        checkpoints: cps.clone(),
                    })
                    .map_err(|e| NodeError::Other(format!("encode history segment: {e}")))?;
                    let pointer = da.submit(HISTORY_NAMESPACE, &payload).await?;
                    Some(ArchivedSegment {
                        first_index: cps[0].index,
                        last_index: index - 1,
                        first_height,
                        last_height,
                        pointer,
                    })
                }
                (Some(_), Handoff::Locate(locator)) => {
                    let mut verified = None;
                    for candidate in locator.locate(cps[0].index).await {
                        if candidate.last_index != index - 1
                            || candidate.first_height != first_height
                            || candidate.last_height != last_height
                        {
                            continue;
                        }
                        match self.fetch_verified(&candidate, &cps).await {
                            Ok(_) => {
                                verified = Some(candidate);
                                break;
                            }
                            Err(e) => {
                                warn!(first_index = cps[0].index, error = %e, "a located history segment does not verify")
                            }
                        }
                    }
                    // No verified copy in the DA layer yet: keep these blocks.
                    let Some(segment) = verified else {
                        return Ok(report);
                    };
                    Some(segment)
                }
            };
            let mut ops = vec![WriteOp::Put {
                cf: CF_METADATA.to_string(),
                key: NEXT_CHECKPOINT_KEY.to_vec(),
                value: index.to_be_bytes().to_vec(),
            }];
            if let Some(segment) = &segment {
                let ordinal = read_u64(&*self.storage, SEGMENT_COUNT_KEY)?;
                let encoded = bincode::serialize(segment)
                    .map_err(|e| NodeError::Other(format!("encode segment record: {e}")))?;
                ops.push(WriteOp::Put {
                    cf: CF_METADATA.to_string(),
                    key: segment_key(ordinal),
                    value: encoded,
                });
                ops.push(WriteOp::Put {
                    cf: CF_METADATA.to_string(),
                    key: segment_digest_key(ordinal),
                    value: cps
                        .last()
                        .expect("a closed segment holds a checkpoint")
                        .digest()
                        .to_vec(),
                });
                ops.push(WriteOp::Put {
                    cf: CF_METADATA.to_string(),
                    key: SEGMENT_COUNT_KEY.to_vec(),
                    value: (ordinal + 1).to_be_bytes().to_vec(),
                });
                report.segments += 1;
            }
            self.storage.write_batch_sync(ops)?;
            report.blocks += if self.drop_indexes.load(std::sync::atomic::Ordering::Relaxed) {
                blocks
                    .prune_range_with_indexes(BlockHeight(first_height), BlockHeight(last_height))?
            } else {
                blocks.prune_range(BlockHeight(first_height), BlockHeight(last_height))?
            };
            report.events += self.events.prune_range(first_height, last_height)? as u64;
            report.transactions += prune_transactions(&*self.storage, &transactions, last_height)?;
            next = index;
        }
    }

    /// The block at `height`: from the local store, else from the DA layer,
    /// verified against the certified checkpoints its segment covers. `None`
    /// when no segment covers `height`.
    pub async fn block(&self, height: u64) -> Result<Option<Block>> {
        let blocks = BlockStoreImpl::new(self.storage.clone())?;
        if let Some(b) = blocks.get_block_by_height(BlockHeight(height)).await? {
            return Ok(Some(b));
        }
        let Some(segment) = self.archived(height).await? else {
            return Ok(None);
        };
        Ok(segment.blocks.into_iter().find(|b| b.height().0 == height))
    }

    /// The archived segment covering `height`, fetched from the DA layer and
    /// verified: its blocks against the certified checkpoints, its events
    /// against the blocks' event roots. `None` when no segment covers it.
    pub async fn archived(&self, height: u64) -> Result<Option<VerifiedSegment>> {
        let Some((ordinal, segment)) = self.segment_covering_at(height)? else {
            return Ok(None);
        };
        let held: Option<Vec<Checkpoint>> = (segment.first_index..=segment.last_index)
            .map(|index| self.checkpoints.checkpoint(index))
            .collect();
        if let Some(cps) = held {
            return self.fetch_verified(&segment, &cps).await.map(Some);
        }
        // Bodies below the history floor are dropped: the segment's own
        // bodies verify by their links back from the digest recorded here.
        let digest: [u8; 32] = self
            .storage
            .get(CF_METADATA, &segment_digest_key(ordinal))?
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .ok_or_else(|| {
                NodeError::Other(format!(
                    "checkpoint {} has no authenticated body to verify history against",
                    segment.first_index
                ))
            })?;
        let da = self.da.as_ref().ok_or_else(|| {
            NodeError::Other("this node has no DA layer to fetch history from".into())
        })?;
        let bytes = da.fetch(&segment.pointer).await?;
        let payload: SegmentPayload = serde_json::from_slice(&bytes).map_err(|e| {
            NodeError::Other(format!(
                "history segment from the DA layer does not decode: {e}"
            ))
        })?;
        let cps = &payload.checkpoints;
        let linked = cps.first().is_some_and(|c| c.index == segment.first_index)
            && cps
                .last()
                .is_some_and(|c| c.index == segment.last_index && c.digest() == digest)
            && cps
                .windows(2)
                .all(|w| w[1].index == w[0].index + 1 && w[1].prev == w[0].digest());
        if !linked || payload.first_index != segment.first_index {
            return Err(NodeError::Other(
                "the history segment's checkpoint bodies do not link to the recorded digest".into(),
            ));
        }
        check_segment(cps, &payload.blocks)?;
        check_events(&payload.blocks, &payload.events)?;
        Ok(Some(VerifiedSegment {
            blocks: payload.blocks,
            events: payload.events,
        }))
    }

    /// Lowest height whose events this node still holds locally.
    pub fn event_floor(&self) -> Result<u64> {
        Ok(self.events.floor()?)
    }

    /// The blocks of `segment`, fetched from the DA layer and checked to be
    /// exactly the blocks the certified checkpoints `cps` cover, with the
    /// events those blocks' headers commit.
    async fn fetch_verified(
        &self,
        segment: &ArchivedSegment,
        cps: &[Checkpoint],
    ) -> Result<VerifiedSegment> {
        let da = self.da.as_ref().ok_or_else(|| {
            NodeError::Other("this node has no DA layer to fetch history from".into())
        })?;
        let bytes = da.fetch(&segment.pointer).await?;
        let payload: SegmentPayload = serde_json::from_slice(&bytes).map_err(|e| {
            NodeError::Other(format!(
                "history segment from the DA layer does not decode: {e}"
            ))
        })?;
        if payload.first_index != segment.first_index {
            return Err(NodeError::Other(format!(
                "history segment starts at checkpoint {}, its record says {}",
                payload.first_index, segment.first_index
            )));
        }
        check_segment(cps, &payload.blocks)?;
        check_events(&payload.blocks, &payload.events)?;
        Ok(VerifiedSegment {
            blocks: payload.blocks,
            events: payload.events,
        })
    }

    /// The recorded segment covering `height`, with its ordinal. Segments are
    /// recorded in height order, so this is a binary search over their
    /// ordinals.
    fn segment_covering_at(&self, height: u64) -> Result<Option<(u64, ArchivedSegment)>> {
        let (mut lo, mut hi) = (0u64, read_u64(&*self.storage, SEGMENT_COUNT_KEY)?);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let seg = read_segment(&*self.storage, mid)?;
            if height < seg.first_height {
                hi = mid;
            } else if height > seg.last_height {
                lo = mid + 1;
            } else {
                return Ok(Some((mid, seg)));
            }
        }
        Ok(None)
    }
}

/// Checks that `events` are, block by block, exactly the events each block's
/// header commits.
/// Deletes each of `hashes` (hex transaction hashes of pruned blocks) from
/// the transaction records: the transaction, its location and its receipt.
/// A transaction whose location names a block above `last` was indexed
/// under that later block and stays. Returns the number deleted.
fn prune_transactions<S: KvStore + ?Sized>(
    storage: &S,
    hashes: &[String],
    last: u64,
) -> Result<u64> {
    let mut ops = Vec::new();
    let mut pruned = 0u64;
    for hash in hashes {
        let location = format!("idx:{hash}");
        let height = storage
            .get(CF_TRANSACTIONS, location.as_bytes())?
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.get("block_height")?.as_u64());
        if height.is_some_and(|h| h > last) {
            continue;
        }
        for key in [hash.clone(), location, format!("receipt:{hash}")] {
            ops.push(WriteOp::Delete {
                cf: CF_TRANSACTIONS.to_string(),
                key: key.into_bytes(),
            });
        }
        pruned += 1;
    }
    if !ops.is_empty() {
        storage.write_batch(ops)?;
    }
    Ok(pruned)
}

fn check_events(blocks: &[Block], events: &[Vec<ChainEvent>]) -> Result<()> {
    if blocks.len() != events.len() {
        return Err(NodeError::Other(format!(
            "history segment holds {} blocks but events for {}",
            blocks.len(),
            events.len()
        )));
    }
    for (block, evs) in blocks.iter().zip(events) {
        let height = block.height().0;
        if evs.iter().any(|e| e.cursor.height != height)
            || event_root(evs) != block.header.event_root
        {
            return Err(NodeError::Other(format!(
                "the events of block {height} do not match its header"
            )));
        }
    }
    Ok(())
}

/// Checks that `blocks` are exactly the blocks `cps` cover, in order.
fn check_segment(cps: &[Checkpoint], blocks: &[Block]) -> Result<()> {
    let mut at = 0usize;
    for cp in cps {
        let n = (cp.last_height + 1).saturating_sub(cp.first_height) as usize;
        let Some(slice) = blocks.get(at..at + n) else {
            return Err(NodeError::Other(format!(
                "history segment ends inside checkpoint {}",
                cp.index
            )));
        };
        check_range(cp, slice).map_err(NodeError::Other)?;
        at += n;
    }
    if at != blocks.len() {
        return Err(NodeError::Other(format!(
            "history segment holds {} blocks beyond its checkpoints",
            blocks.len() - at
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use tenzro_consensus::checkpoint::{merkle_root, state_root_height};
    use tenzro_storage::da::{DaBackendId, DaBackendStatus};
    use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
    use tenzro_types::block::{BlockHeader, BlockMetadata};
    use tenzro_types::primitives::{Address, ChainId, Hash, Nonce, Timestamp};
    use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};

    /// A DA layer in memory, which can be told to return altered bytes.
    #[derive(Default)]
    struct MemDa {
        blobs: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
        tamper: Mutex<bool>,
        tamper_checkpoint: Mutex<bool>,
    }

    #[async_trait]
    impl DaBackend for MemDa {
        fn id(&self) -> DaBackendId {
            DaBackendId::TenzroCommittee
        }
        fn status(&self) -> DaBackendStatus {
            DaBackendStatus {
                backend: DaBackendId::TenzroCommittee,
                healthy: true,
                last_submission_ms: None,
                last_fetch_ms: None,
                error_rate_bps: 0,
            }
        }
        async fn submit(
            &self,
            namespace: &[u8],
            payload: &[u8],
        ) -> tenzro_storage::Result<DaPointer> {
            let locator = tenzro_storage::compute_commitment(payload)
                .as_bytes()
                .to_vec();
            self.blobs.lock().insert(locator.clone(), payload.to_vec());
            Ok(DaPointer {
                backend: DaBackendId::TenzroCommittee,
                namespace: namespace.to_vec(),
                locator,
                commitment_kzg: None,
                attestation_root: None,
            })
        }
        async fn fetch(&self, pointer: &DaPointer) -> tenzro_storage::Result<Vec<u8>> {
            let bytes = self
                .blobs
                .lock()
                .get(&pointer.locator)
                .cloned()
                .expect("submitted");
            if *self.tamper_checkpoint.lock() {
                let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                if let Some(root) = v.pointer_mut("/checkpoints/0/state_root/0") {
                    *root = serde_json::json!((root.as_u64().unwrap() + 1) % 256);
                }
                return Ok(serde_json::to_vec(&v).unwrap());
            }
            if !*self.tamper.lock() {
                return Ok(bytes);
            }
            let mut payload: SegmentPayload = serde_json::from_slice(&bytes).unwrap();
            payload.blocks[0].header.timestamp = Timestamp::new(1);
            Ok(serde_json::to_vec(&payload).unwrap())
        }
        async fn verify_availability(&self, _pointer: &DaPointer) -> tenzro_storage::Result<()> {
            Ok(())
        }
    }

    struct Cps(Vec<Checkpoint>);

    impl CertifiedCheckpoints for Cps {
        fn checkpoint(&self, index: u64) -> Option<Checkpoint> {
            self.0.get(index as usize).cloned()
        }
        fn latest_index(&self) -> Option<u64> {
            self.0.len().checked_sub(1).map(|i| i as u64)
        }
    }

    fn transfer(nonce: u64) -> SignedTransaction {
        SignedTransaction::new(
            Transaction::new(
                ChainId::from(1),
                Address::zero(),
                Address::default(),
                Nonce::from(nonce),
                TransactionType::Transfer { amount: 1 },
                21_000,
                100,
            ),
            Vec::new(),
            CompositeSignature::classical(ClassicalProof::Raw {
                signature: Vec::new(),
            }),
        )
    }

    /// The transaction records block finalization writes for `block`.
    fn index_transactions(storage: &RocksDbStore, block: &Block) {
        for (i, t) in block.transactions.iter().enumerate() {
            let hash = t.transaction.hash().to_string();
            let location = serde_json::json!({
                "block_height": block.height().0,
                "block_hash": block.hash().to_string(),
                "tx_index": i,
            });
            for (key, value) in [
                (hash.clone(), serde_json::to_vec(t).unwrap()),
                (
                    format!("idx:{hash}"),
                    serde_json::to_vec(&location).unwrap(),
                ),
                (format!("receipt:{hash}"), b"{}".to_vec()),
            ] {
                storage
                    .put(CF_TRANSACTIONS, key.as_bytes(), &value)
                    .unwrap();
            }
        }
    }

    fn holds_transaction(storage: &RocksDbStore, block: &Block) -> [bool; 3] {
        let hash = block.transactions[0].transaction.hash().to_string();
        [
            hash.clone(),
            format!("idx:{hash}"),
            format!("receipt:{hash}"),
        ]
        .map(|k| {
            storage
                .get(CF_TRANSACTIONS, k.as_bytes())
                .unwrap()
                .is_some()
        })
    }

    fn chain(n: u64) -> Vec<Block> {
        let mut prev = Hash::new([7; 32]);
        (1..=n)
            .map(|h| {
                let header = BlockHeader {
                    height: BlockHeight(h),
                    epoch: 0,
                    round: h,
                    anchor: Hash::new([9; 32]),
                    prev_hash: prev,
                    tx_root: Hash::zero(),
                    state_root: Hash::zero(),
                    event_root: tenzro_types::chain_event::event_root(&[]),
                    receipts_root: Hash::zero(),
                    logs_bloom: tenzro_types::LogsBloom::default(),
                    timestamp: Timestamp::new(1_000 + h as i64 * 10),
                    proposer: Address::zero(),
                    metadata: BlockMetadata::default(),
                };
                let b = Block::new(header, vec![transfer(h)]);
                prev = b.hash();
                b
            })
            .collect()
    }

    /// Checkpoints of `per` blocks each over `blocks`; every `epoch_every`-th
    /// ends an epoch.
    fn checkpoints(blocks: &[Block], per: usize, epoch_every: usize) -> Vec<Checkpoint> {
        blocks
            .chunks(per)
            .enumerate()
            .map(|(i, c)| {
                let hashes: Vec<[u8; 32]> = c.iter().map(|b| b.hash().0).collect();
                Checkpoint {
                    chain_id: 1,
                    genesis_hash: [0; 32],
                    epoch: (i / epoch_every) as u64,
                    index: i as u64,
                    prev: [0; 32],
                    first_height: c[0].height().0,
                    last_height: c.last().unwrap().height().0,
                    blocks_root: merkle_root(&hashes),
                    state_height: state_root_height(c.last().unwrap().height().0),
                    state_root: [5; 32],
                    statement_root: [0; 32],
                    next_committee_root: ((i + 1) % epoch_every == 0).then_some([1; 32]),
                    anchor_round: 1,
                    timestamp_ms: 0,
                    ordering_root: [0; 32],
                }
            })
            .collect()
    }

    async fn setup(tmp: &std::path::Path) -> (HistoryArchive, Arc<MemDa>, Vec<Block>) {
        let (storage, blocks, cps) = stored_chain(tmp).await;
        let da = Arc::new(MemDa::default());
        (
            HistoryArchive::new(storage, da.clone(), Arc::new(Cps(cps)), Handoff::Submit).unwrap(),
            da,
            blocks,
        )
    }

    async fn stored_chain(
        tmp: &std::path::Path,
    ) -> (Arc<RocksDbStore>, Vec<Block>, Vec<Checkpoint>) {
        std::fs::create_dir_all(tmp).unwrap();
        let storage = Arc::new(
            RocksDbStore::open(
                &tenzro_storage::StorageConfig::new(tmp.join("db")).with_memory_bytes(8 << 20),
            )
            .unwrap(),
        );
        let blocks = chain(40);
        let mut store = BlockStoreImpl::new(storage.clone()).unwrap();
        for b in &blocks {
            store.put_block(b).await.unwrap();
            index_transactions(&storage, b);
        }
        // 10 checkpoints of 4 blocks, an epoch every 2 checkpoints.
        let cps = checkpoints(&blocks, 4, 2);
        (storage, blocks, cps)
    }

    /// `cps` with each body's `prev` the digest of the one before, as the
    /// chain links them.
    fn chained(mut cps: Vec<Checkpoint>) -> Vec<Checkpoint> {
        let mut prev = [0u8; 32];
        for cp in &mut cps {
            cp.prev = prev;
            prev = cp.digest();
        }
        cps
    }

    /// Checkpoint bodies of a node that has dropped those below `floor`.
    struct Below(Vec<Checkpoint>, u64);

    impl CertifiedCheckpoints for Below {
        fn checkpoint(&self, index: u64) -> Option<Checkpoint> {
            (index >= self.1)
                .then(|| self.0.get(index as usize).cloned())
                .flatten()
        }
        fn latest_index(&self) -> Option<u64> {
            self.0.len().checked_sub(1).map(|i| i as u64)
        }
    }

    /// Bodies of checkpoints below the history floor may be dropped: an
    /// archived segment carries its own checkpoint bodies, which verify by
    /// their links back from the digest recorded when the segment was handed
    /// over, so its blocks are still served and checked. Bodies altered in
    /// the DA layer are refused.
    #[tokio::test]
    async fn archived_history_verifies_after_its_checkpoint_bodies_are_pruned() {
        let tmp = tempfile::tempdir().unwrap();
        let (storage, blocks, cps) = stored_chain(tmp.path()).await;
        let cps = chained(cps);
        let da = Arc::new(MemDa::default());
        let archive = HistoryArchive::new(
            storage.clone(),
            da.clone(),
            Arc::new(Cps(cps.clone())),
            Handoff::Submit,
        )
        .unwrap();
        assert_eq!(archive.prune_below(22).await.unwrap().segments, 2);
        // Checkpoints 0..=3 cover heights 1..=16; their bodies are gone.
        let pruned = HistoryArchive::new(
            storage.clone(),
            da.clone(),
            Arc::new(Below(cps.clone(), 4)),
            Handoff::Submit,
        )
        .unwrap();
        for h in [1u64, 8, 9, 16] {
            let got = pruned.block(h).await.unwrap().expect("served from DA");
            assert_eq!(got.hash(), blocks[h as usize - 1].hash());
        }
        *da.tamper_checkpoint.lock() = true;
        assert!(pruned.block(3).await.is_err());
    }

    /// An edge node drops the indexes of the blocks it prunes: below the
    /// window neither a height nor a hash index entry is left, the window
    /// keeps both, and pruned blocks are still served by height from the DA
    /// layer.
    #[tokio::test]
    async fn an_edge_node_leaves_no_index_entries_below_the_window() {
        let tmp = tempfile::tempdir().unwrap();
        let (archive, _da, blocks) = setup(tmp.path()).await;
        archive.set_drop_indexes(true);
        archive.prune_below(22).await.unwrap();
        let s = &archive.storage;
        let indexed = |b: &Block| {
            let mut h = b"height_hash:".to_vec();
            h.extend_from_slice(&b.height().0.to_be_bytes());
            let mut k = b"block_hash:".to_vec();
            k.extend_from_slice(b.hash().as_bytes());
            [
                s.get(tenzro_storage::CF_BLOCKS, &h).unwrap().is_some(),
                s.get(CF_METADATA, &k).unwrap().is_some(),
            ]
        };
        for b in &blocks[..16] {
            assert_eq!(indexed(b), [false, false], "height {}", b.height().0);
        }
        for b in &blocks[16..] {
            assert_eq!(indexed(b), [true, true], "height {}", b.height().0);
        }
        assert_eq!(
            archive.block(3).await.unwrap().unwrap().hash(),
            blocks[2].hash()
        );
    }

    /// Locates segments from a committee member's own records.
    struct MemberRecords(Arc<RocksDbStore>);

    #[async_trait]
    impl SegmentLocator for MemberRecords {
        async fn locate(&self, first_index: u64) -> Vec<ArchivedSegment> {
            recorded_segment(&*self.0, first_index)
                .unwrap()
                .into_iter()
                .collect()
        }
    }

    #[tokio::test]
    async fn an_rpc_node_prunes_only_what_the_committee_archived_and_serves_it_from_da() {
        let tmp = tempfile::tempdir().unwrap();
        let (member, da, blocks) = setup(&tmp.path().join("member")).await;
        let (storage, _, cps) = stored_chain(&tmp.path().join("rpc")).await;
        let rpc = HistoryArchive::new(
            storage.clone(),
            da.clone(),
            Arc::new(Cps(cps)),
            Handoff::Locate(Arc::new(MemberRecords(member.storage.clone()))),
        )
        .unwrap();
        let local = BlockStoreImpl::new(storage.clone()).unwrap();

        // The committee has archived nothing yet: the RPC node keeps it all.
        assert_eq!(rpc.prune_below(22).await.unwrap(), PruneReport::default());
        assert!(
            local
                .get_block_by_height(BlockHeight(1))
                .await
                .unwrap()
                .is_some()
        );

        // Once the committee archived the first epoch only, only that goes.
        member.prune_below(10).await.unwrap();
        assert_eq!(
            rpc.prune_below(22).await.unwrap(),
            PruneReport {
                segments: 1,
                blocks: 8,
                events: 0,
                transactions: 8,
            }
        );
        assert!(
            local
                .get_block_by_height(BlockHeight(9))
                .await
                .unwrap()
                .is_some()
        );

        member.prune_below(22).await.unwrap();
        assert_eq!(
            rpc.prune_below(22).await.unwrap(),
            PruneReport {
                segments: 1,
                blocks: 8,
                events: 0,
                transactions: 8,
            }
        );
        for h in [1u64, 8, 9, 16] {
            assert!(
                local
                    .get_block_by_height(BlockHeight(h))
                    .await
                    .unwrap()
                    .is_none(),
                "height {h} pruned"
            );
            let got = rpc.block(h).await.unwrap().expect("served from DA");
            assert_eq!(got.hash(), blocks[h as usize - 1].hash());
        }
        assert!(
            local
                .get_block_by_height(BlockHeight(17))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn an_rpc_node_keeps_blocks_whose_located_copy_does_not_verify() {
        let tmp = tempfile::tempdir().unwrap();
        let (member, da, _) = setup(&tmp.path().join("member")).await;
        member.prune_below(22).await.unwrap();
        let (storage, _, cps) = stored_chain(&tmp.path().join("rpc")).await;
        let rpc = HistoryArchive::new(
            storage.clone(),
            da.clone(),
            Arc::new(Cps(cps)),
            Handoff::Locate(Arc::new(MemberRecords(member.storage.clone()))),
        )
        .unwrap();
        *da.tamper.lock() = true;
        assert_eq!(rpc.prune_below(22).await.unwrap(), PruneReport::default());
        let local = BlockStoreImpl::new(storage).unwrap();
        for h in 1..=40 {
            assert!(
                local
                    .get_block_by_height(BlockHeight(h))
                    .await
                    .unwrap()
                    .is_some(),
                "height {h} kept"
            );
        }
    }

    #[tokio::test]
    async fn pruning_keeps_the_window_and_fetches_older_history_from_da() {
        let tmp = tempfile::tempdir().unwrap();
        let (archive, _da, blocks) = setup(tmp.path()).await;
        let local = BlockStoreImpl::new(archive.storage.clone()).unwrap();

        // Keep heights 22 and above: the epochs ending at 8 and 16 are
        // closed segments wholly below; the epoch 17..=24 straddles the floor.
        let report = archive.prune_below(22).await.unwrap();
        assert_eq!(
            report,
            PruneReport {
                segments: 2,
                blocks: 16,
                events: 0,
                transactions: 16,
            }
        );
        for b in &blocks[..16] {
            assert_eq!(holds_transaction(&archive.storage, b), [false; 3]);
        }
        for b in &blocks[16..] {
            assert_eq!(holds_transaction(&archive.storage, b), [true; 3]);
        }
        // The block fetched back from the DA layer still carries its
        // transactions.
        assert_eq!(
            archive.block(3).await.unwrap().unwrap().transactions,
            blocks[2].transactions
        );
        for h in 1..=16 {
            assert!(
                local
                    .get_block_by_height(BlockHeight(h))
                    .await
                    .unwrap()
                    .is_none(),
                "height {h} pruned"
            );
        }
        for h in 17..=40 {
            assert!(
                local
                    .get_block_by_height(BlockHeight(h))
                    .await
                    .unwrap()
                    .is_some(),
                "height {h} kept"
            );
        }
        for h in [1u64, 8, 9, 16] {
            let got = archive.block(h).await.unwrap().expect("served from DA");
            assert_eq!(got.hash(), blocks[h as usize - 1].hash());
        }
        assert_eq!(archive.block(41).await.unwrap(), None);

        // A second pass with the same floor has nothing more to hand over.
        assert_eq!(
            archive.prune_below(22).await.unwrap(),
            PruneReport::default()
        );
    }

    /// A node with no DA layer keeps the same window and deletes the blocks,
    /// events and transactions below it rather than keeping them for ever.
    #[tokio::test]
    async fn a_node_without_a_da_layer_deletes_history_below_the_window() {
        let tmp = tempfile::tempdir().unwrap();
        let (storage, blocks, cps) = stored_chain(tmp.path()).await;
        let archive = HistoryArchive::local(storage.clone(), Arc::new(Cps(cps))).unwrap();
        let report = archive.prune_below(22).await.unwrap();
        assert_eq!(
            report,
            PruneReport {
                segments: 0,
                blocks: 16,
                events: 0,
                transactions: 16,
            }
        );
        let local = BlockStoreImpl::new(storage.clone()).unwrap();
        for b in &blocks[..16] {
            assert!(
                local
                    .get_block_by_height(b.height())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(holds_transaction(&storage, b), [false; 3]);
        }
        for b in &blocks[16..] {
            assert!(
                local
                    .get_block_by_height(b.height())
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(holds_transaction(&storage, b), [true; 3]);
        }
        assert_eq!(archive.next_checkpoint().unwrap(), 4);
        assert_eq!(archive.block(3).await.unwrap(), None);
        assert_eq!(
            archive.block(17).await.unwrap().unwrap().hash(),
            blocks[16].hash()
        );
    }

    #[tokio::test]
    async fn history_altered_in_the_da_layer_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (archive, da, _) = setup(tmp.path()).await;
        archive.prune_below(22).await.unwrap();
        *da.tamper.lock() = true;
        let err = archive.block(3).await.unwrap_err().to_string();
        assert!(err.contains("blocks root"), "{err}");
    }
}
