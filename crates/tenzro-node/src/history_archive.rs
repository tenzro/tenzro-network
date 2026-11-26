//! Bounded local history, with older blocks held by the committee's
//! data-availability layer.
//!
//! Validators and RPC nodes keep the live state and the most recent
//! [`HISTORY_RETENTION_PARAM`](tenzro_vm::governance::HISTORY_RETENTION_PARAM)
//! blocks. Older blocks leave the local store in segments: a run of
//! certified checkpoints, closed at an epoch's last checkpoint, once it
//! covers [`SEGMENT_MAX_BLOCKS`], or once its encoded payload reaches
//! [`SEGMENT_MAX_BYTES`]. A segment is first written to the DA layer,
//! where bonded storage providers hold the erasure-coded slivers and answer
//! possession challenges, and its pointer is recorded durably; only then are
//! its blocks deleted locally.
//!
//! A segment's payload is written in parts of at most [`SEGMENT_MAX_BYTES`]
//! each, one DA blob and one availability certificate per part, so a
//! checkpoint whose blocks alone encode larger than one blob is still
//! archived. The segment's record names its parts in order; it is recorded,
//! and the blocks deleted, only once every part is certified.
//!
//! One committee member writes each segment: the member whose committee
//! index is the segment's first checkpoint index modulo the committee size.
//! Every node, members included, first asks committee members where the DA
//! layer holds the segment, fetches it, and takes that record once the
//! fetched segment verifies against its own certified checkpoints. A member
//! other than the writer writes the segment itself only when no verified
//! copy turned up within [`WRITER_WAIT_PER_PLACE`] times its place after the
//! writer in committee order, so a failed or slow writer delays archiving
//! but never stops it. A node outside the committee (an RPC node) writes
//! nothing: until a member names a segment that verifies, it keeps those
//! blocks.
//!
//! A node restored from a state snapshot holds no block below the restored
//! height, and holds the restored block without its events or transaction
//! records; the snapshot vouches for them. A segment reaching down to that
//! height counts as held when every block above the restored height is
//! held. Such a node takes a verified copy of the segment from the committee
//! and never writes it.
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
use std::time::{Duration, Instant};

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

/// Encoded size at which a segment closes, and the largest part its payload
/// is written to the DA layer in. A segment takes whole checkpoints, so it
/// stays at or under this size unless one checkpoint's blocks alone encode
/// larger; such a segment is written in several parts. The committee DA
/// layer takes a blob only when every member's sliver of it fits one store
/// request ([`max_blob_len`](crate::da_committee::max_blob_len)), and every
/// committee shape takes a blob of this size.
pub const SEGMENT_MAX_BYTES: usize = 8 * 1024 * 1024;

/// How long a committee member waits for a segment's writer, per place it
/// stands after the writer in committee order, before writing the segment
/// itself. Storage maintenance runs once a minute, so the next member in
/// order writes after about two passes without a verified copy.
pub const WRITER_WAIT_PER_PLACE: Duration = Duration::from_secs(120);

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

/// This node's place in the committee that writes history segments.
pub trait CommitteeSeat: Send + Sync {
    /// This node's index in the current committee order and the committee
    /// size; `None` while this node is not a member.
    fn seat(&self) -> Option<(usize, usize)>;
}

impl CommitteeSeat for crate::da_committee::DaCommitteeBackend {
    fn seat(&self) -> Option<(usize, usize)> {
        let members = self.committee_members();
        let local = self.local_address()?;
        members
            .iter()
            .find(|m| m.address == local)
            .map(|m| (m.index, members.len()))
    }
}

/// How a closed segment reaches the DA layer before its blocks are deleted.
/// Either way a verified copy located through `locator` is taken first.
pub enum Handoff {
    /// This node is a committee member: it writes a segment when the segment
    /// is its turn, or when the member whose turn it is has not delivered a
    /// verified copy in time.
    Committee {
        seat: Arc<dyn CommitteeSeat>,
        locator: Arc<dyn SegmentLocator>,
    },
    /// This node is outside the committee: it deletes a segment only once a
    /// located copy of it verifies.
    Locate(Arc<dyn SegmentLocator>),
}

impl Handoff {
    fn locator(&self) -> &Arc<dyn SegmentLocator> {
        match self {
            Handoff::Committee { locator, .. } | Handoff::Locate(locator) => locator,
        }
    }
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
    /// The segment's payload in the DA layer: its parts in order, each a
    /// certified blob of at most [`SEGMENT_MAX_BYTES`].
    pub parts: Vec<DaPointer>,
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
    da: Option<(Arc<dyn DaBackend>, Handoff)>,
    checkpoints: Arc<dyn CertifiedCheckpoints>,
    events: EventLog,
    /// Delete the height and hash indexes of pruned blocks too, as an edge
    /// node does: a pruned block is then found only by height, from the DA
    /// layer.
    drop_indexes: std::sync::atomic::AtomicBool,
    /// Encoded size at which a segment closes, [`SEGMENT_MAX_BYTES`].
    segment_max_bytes: usize,
    /// Largest part of a segment's payload, [`SEGMENT_MAX_BYTES`].
    part_max_bytes: usize,
    /// [`WRITER_WAIT_PER_PLACE`].
    writer_wait_per_place: Duration,
    /// The segment this member waits on another member to write: its first
    /// checkpoint index and when the wait began.
    waiting: parking_lot::Mutex<Option<(u64, Instant)>>,
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
            da: Some((da, handoff)),
            checkpoints,
            events,
            drop_indexes: Default::default(),
            segment_max_bytes: SEGMENT_MAX_BYTES,
            part_max_bytes: SEGMENT_MAX_BYTES,
            writer_wait_per_place: WRITER_WAIT_PER_PLACE,
            waiting: Default::default(),
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
            events,
            drop_indexes: Default::default(),
            segment_max_bytes: SEGMENT_MAX_BYTES,
            part_max_bytes: SEGMENT_MAX_BYTES,
            writer_wait_per_place: WRITER_WAIT_PER_PLACE,
            waiting: Default::default(),
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

    /// The first checkpoint from `from` on whose body is held, when the
    /// bodies of the checkpoints below some index are absent and every one
    /// from it to `latest` is held: found by halving, none when even
    /// `latest` has no body.
    fn first_held_checkpoint(&self, from: u64, latest: u64) -> Option<u64> {
        self.checkpoints.checkpoint(latest)?;
        let (mut low, mut high) = (from, latest);
        while low < high {
            let mid = low + (high - low) / 2;
            if self.checkpoints.checkpoint(mid).is_some() {
                high = mid;
            } else {
                low = mid + 1;
            }
        }
        Some(high)
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
        // A node restored from a snapshot holds history from the block after
        // the restored height: blocks below it were never stored here, and
        // the restored block itself was stored without its events or
        // transaction records. The snapshot vouches for all of them.
        let base = match read_u64(&*self.storage, crate::snapshot::RESTORED_HEIGHT_KEY)? {
            0 => 0,
            restored => restored + 1,
        };
        let mut next = read_u64(&*self.storage, NEXT_CHECKPOINT_KEY)?;
        // The checkpoints below the snapshot's own were never stored here
        // either: a restored node starts at the first checkpoint it holds.
        // So does a node that ran before bodies were kept: bodies missing
        // at the start are no fault, and nothing below the first one held
        // can be handed over verified.
        if self.checkpoints.checkpoint(next).is_none() {
            let Some(first) = self.first_held_checkpoint(next, latest) else {
                return Ok(report);
            };
            next = first;
            self.storage
                .put(CF_METADATA, NEXT_CHECKPOINT_KEY, &next.to_be_bytes())?;
        }
        loop {
            if steps >= max_segments {
                return Ok(report);
            }
            steps += 1;
            let mut cps: Vec<Checkpoint> = Vec::new();
            let mut held: Vec<Block> = Vec::new();
            let mut events: Vec<Vec<ChainEvent>> = Vec::new();
            let mut covered = 0u64;
            // Blocks of the segment from `base` on: those this node holds.
            let mut expected = 0u64;
            let mut bytes = 0usize;
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
                let mut cp_blocks = Vec::new();
                for h in cp.first_height.max(base)..=cp.last_height {
                    if let Some(b) = blocks.get_block_by_height(BlockHeight(h)).await? {
                        cp_blocks.push(b);
                    }
                }
                let cp_events = cp_blocks
                    .iter()
                    .map(|b| self.events.block(b.height().0))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let cp_bytes = encoded_len(&cp)?
                    + cp_blocks.iter().map(encoded_len).sum::<Result<usize>>()?
                    + cp_events.iter().map(encoded_len).sum::<Result<usize>>()?;
                if !cps.is_empty() && bytes + cp_bytes > self.segment_max_bytes {
                    // This checkpoint would take the segment past its byte
                    // bound: the segment ends before it.
                    closed = true;
                    break;
                }
                covered += (cp.last_height + 1).saturating_sub(cp.first_height);
                expected += (cp.last_height + 1).saturating_sub(cp.first_height.max(base));
                bytes += cp_bytes;
                closed = cp.next_committee_root.is_some()
                    || covered >= SEGMENT_MAX_BLOCKS
                    || bytes >= self.segment_max_bytes;
                cps.push(cp);
                held.extend(cp_blocks);
                events.extend(cp_events);
                index += 1;
                if closed {
                    break;
                }
            }
            if cps.is_empty() || (!closed && self.da.is_none()) {
                return Ok(report);
            }
            let first_height = cps[0].first_height;
            let last_height = cps
                .last()
                .expect("a segment holds a checkpoint")
                .last_height;

            if closed && expected == 0 {
                // Nothing of this segment is held here (the node started from
                // a snapshot above it): nothing to hand over or delete.
                next = index;
                self.storage
                    .put(CF_METADATA, NEXT_CHECKPOINT_KEY, &next.to_be_bytes())?;
                continue;
            }
            if held.len() as u64 != expected {
                return Err(NodeError::Other(format!(
                    "heights {}..={last_height} are only partly held ({} of {expected} blocks)",
                    first_height.max(base),
                    held.len()
                )));
            }
            // A segment reaching below `base` holds only its upper blocks:
            // this node cannot write it, only take a verified copy.
            let whole = expected == covered;
            if whole {
                check_segment(&cps, &held)?;
            }
            check_events(&held, &events)?;

            // What leaves: the record, the checkpoints and heights it covers,
            // and the transactions of its blocks.
            let (segment, last_index, range, transactions) = match &self.da {
                None => (
                    None,
                    index - 1,
                    (first_height, last_height),
                    transaction_hashes(&held),
                ),
                Some((da, handoff)) => {
                    if let Some(found) = self.locate_verified(handoff.locator(), &cps).await {
                        let (last_index, range) =
                            (found.last_index, (found.first_height, found.last_height));
                        let ending = held.partition_point(|b| b.height().0 <= range.1);
                        (
                            Some(found),
                            last_index,
                            range,
                            transaction_hashes(&held[..ending]),
                        )
                    } else if closed && whole && self.writes(handoff, cps[0].index) {
                        let transactions = transaction_hashes(&held);
                        let payload = serde_json::to_vec(&SegmentPayload {
                            first_index: cps[0].index,
                            blocks: held,
                            events,
                            checkpoints: cps.clone(),
                        })
                        .map_err(|e| NodeError::Other(format!("encode history segment: {e}")))?;
                        // Each part is certified before the next is written;
                        // the segment is recorded only once all are.
                        let mut parts =
                            Vec::with_capacity(payload.len().div_ceil(self.part_max_bytes));
                        for part in payload.chunks(self.part_max_bytes) {
                            parts.push(da.submit(HISTORY_NAMESPACE, part).await?);
                        }
                        (
                            Some(ArchivedSegment {
                                first_index: cps[0].index,
                                last_index: index - 1,
                                first_height,
                                last_height,
                                parts,
                            }),
                            index - 1,
                            (first_height, last_height),
                            transactions,
                        )
                    } else {
                        // No verified copy in the DA layer yet, and not this
                        // node's to write: keep these blocks.
                        return Ok(report);
                    }
                }
            };
            let digest = self
                .checkpoints
                .checkpoint(last_index)
                .map(|cp| cp.digest())
                .ok_or_else(|| {
                    NodeError::Other(format!("checkpoint {last_index} has no authenticated body"))
                })?;
            next = last_index + 1;
            let mut ops = vec![WriteOp::Put {
                cf: CF_METADATA.to_string(),
                key: NEXT_CHECKPOINT_KEY.to_vec(),
                value: next.to_be_bytes().to_vec(),
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
                    value: digest.to_vec(),
                });
                ops.push(WriteOp::Put {
                    cf: CF_METADATA.to_string(),
                    key: SEGMENT_COUNT_KEY.to_vec(),
                    value: (ordinal + 1).to_be_bytes().to_vec(),
                });
                report.segments += 1;
            }
            self.storage.write_batch_sync(ops)?;
            {
                let mut waiting = self.waiting.lock();
                if waiting.is_some_and(|(first, _)| first < next) {
                    *waiting = None;
                }
            }
            let (first_height, last_height) = range;
            report.blocks += if self.drop_indexes.load(std::sync::atomic::Ordering::Relaxed) {
                blocks
                    .prune_range_with_indexes(BlockHeight(first_height), BlockHeight(last_height))?
            } else {
                blocks.prune_range(BlockHeight(first_height), BlockHeight(last_height))?
            };
            report.events += self.events.prune_range(first_height, last_height)? as u64;
            report.transactions += prune_transactions(&*self.storage, &transactions, last_height)?;
        }
    }

    /// A segment record a committee member names for the segment starting at
    /// `cps[0]`, ending at one of `cps`, whose payload fetched from the DA
    /// layer verifies against those checkpoints.
    async fn locate_verified(
        &self,
        locator: &Arc<dyn SegmentLocator>,
        cps: &[Checkpoint],
    ) -> Option<ArchivedSegment> {
        let first = &cps[0];
        for candidate in locator.locate(first.index).await {
            let Some(span) = candidate
                .last_index
                .checked_sub(first.index)
                .and_then(|d| usize::try_from(d).ok())
                .filter(|d| *d < cps.len())
            else {
                continue;
            };
            if candidate.first_index != first.index
                || candidate.first_height != first.first_height
                || candidate.last_height != cps[span].last_height
            {
                continue;
            }
            match self.fetch_verified(&candidate, &cps[..=span]).await {
                Ok(_) => return Some(candidate),
                Err(e) => {
                    warn!(first_index = first.index, error = %e, "a located history segment does not verify")
                }
            }
        }
        None
    }

    /// Whether this node writes the segment starting at checkpoint
    /// `first_index` now: a committee member writes it when it is the member
    /// at `first_index` modulo the committee size, or once it has waited
    /// [`Self::writer_wait_per_place`] for every place it stands after that
    /// member in committee order.
    fn writes(&self, handoff: &Handoff, first_index: u64) -> bool {
        let Handoff::Committee { seat, .. } = handoff else {
            return false;
        };
        let Some((own, size)) = seat.seat().filter(|(own, size)| own < size) else {
            return false;
        };
        let turn = (first_index % size as u64) as usize;
        let place = (own + size - turn) % size;
        if place == 0 {
            return true;
        }
        let mut waiting = self.waiting.lock();
        let since = match *waiting {
            Some((first, since)) if first == first_index => since,
            _ => {
                let now = Instant::now();
                *waiting = Some((first_index, now));
                now
            }
        };
        since.elapsed() >= self.writer_wait_per_place.saturating_mul(place as u32)
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
        let payload = self.fetch_payload(&segment).await?;
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
        let payload = self.fetch_payload(segment).await?;
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

    /// The payload of `segment`: its parts fetched from the DA layer in
    /// order, each checked by the DA layer against its own commitment, and
    /// decoded together.
    async fn fetch_payload(&self, segment: &ArchivedSegment) -> Result<SegmentPayload> {
        let (da, _) = self.da.as_ref().ok_or_else(|| {
            NodeError::Other("this node has no DA layer to fetch history from".into())
        })?;
        if segment.parts.is_empty() {
            return Err(NodeError::Other(format!(
                "history segment at checkpoint {} names no parts",
                segment.first_index
            )));
        }
        let mut bytes = Vec::new();
        for part in &segment.parts {
            bytes.extend_from_slice(&da.fetch(part).await?);
        }
        serde_json::from_slice(&bytes).map_err(|e| {
            NodeError::Other(format!(
                "history segment from the DA layer does not decode: {e}"
            ))
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

/// Hex hashes of the transactions of `blocks`.
fn transaction_hashes(blocks: &[Block]) -> Vec<String> {
    blocks
        .iter()
        .flat_map(|b| b.transactions.iter())
        .map(|t| t.transaction.hash().to_string())
        .collect()
}

/// Bytes of `value`'s JSON encoding, counted without building it. The
/// length does not depend on the order of map entries, so every node holding
/// the same blocks measures the same size and closes the same segments.
fn encoded_len<T: Serialize + ?Sized>(value: &T) -> Result<usize> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value)
        .map_err(|e| NodeError::Other(format!("measure history segment: {e}")))?;
    Ok(count.0)
}

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

/// Checks that `events` are, block by block, exactly the events each block's
/// header commits.
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
        /// Number of blobs submitted, counting repeats.
        submits: Mutex<usize>,
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
            *self.submits.lock() += 1;
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

    /// A transfer whose bytes depend only on `nonce`, so two nodes building
    /// the test chain hold the same blocks.
    fn transfer(nonce: u64) -> SignedTransaction {
        let mut tx = Transaction::new(
            ChainId::from(1),
            Address::zero(),
            Address::default(),
            Nonce::from(nonce),
            TransactionType::Transfer { amount: 1 },
            21_000,
            100,
        );
        tx.timestamp = Timestamp::new(1_000);
        tx.valid_until = Timestamp::new(301_000);
        SignedTransaction::new(
            tx,
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

    /// The events block `h` commits: the outcome of its one transaction.
    fn tx_events(h: u64) -> Vec<ChainEvent> {
        vec![ChainEvent {
            cursor: tenzro_types::chain_event::EventCursor {
                height: h,
                tx_index: 0,
                event_index: 0,
            },
            tx_hash: transfer(h).transaction.hash(),
            kind: tenzro_types::chain_event::ChainEventKind::TxOutcome {
                success: true,
                gas_used: 21_000,
                contract_address: None,
            },
        }]
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
                    event_root: event_root(&tx_events(h)),
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

    /// A fixed place in the committee: index and committee size.
    struct Seat(usize, usize);

    impl CommitteeSeat for Seat {
        fn seat(&self) -> Option<(usize, usize)> {
            Some((self.0, self.1))
        }
    }

    /// The only member of a committee: every segment is its turn.
    fn sole_writer() -> Handoff {
        Handoff::Committee {
            seat: Arc::new(Seat(0, 1)),
            locator: Arc::new(MemberRecords(Vec::new())),
        }
    }

    async fn setup(tmp: &std::path::Path) -> (HistoryArchive, Arc<MemDa>, Vec<Block>) {
        let (storage, blocks, cps) = stored_chain(tmp).await;
        let da = Arc::new(MemDa::default());
        (
            HistoryArchive::new(storage, da.clone(), Arc::new(Cps(cps)), sole_writer()).unwrap(),
            da,
            blocks,
        )
    }

    async fn stored_chain(
        tmp: &std::path::Path,
    ) -> (Arc<RocksDbStore>, Vec<Block>, Vec<Checkpoint>) {
        stored_chain_from(tmp, 1).await
    }

    /// The chain of 40 blocks as a node holds it that restored its state at
    /// height `base`: blocks below `base` were never stored, and block
    /// `base` was stored without its events or transaction records, as a
    /// snapshot restore leaves it.
    async fn stored_chain_from(
        tmp: &std::path::Path,
        base: u64,
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
        for b in blocks.iter().filter(|b| b.height().0 >= base) {
            store.put_block(b).await.unwrap();
            if base == 1 || b.height().0 > base {
                index_transactions(&storage, b);
                storage
                    .write_batch_sync(EventLog::block_writes(
                        b.height().0,
                        &tx_events(b.height().0),
                    ))
                    .unwrap();
            }
        }
        if base > 1 {
            storage
                .put(
                    CF_METADATA,
                    crate::snapshot::RESTORED_HEIGHT_KEY,
                    &base.to_be_bytes(),
                )
                .unwrap();
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
            sole_writer(),
        )
        .unwrap();
        assert_eq!(archive.prune_below(22).await.unwrap().segments, 2);
        // Checkpoints 0..=3 cover heights 1..=16; their bodies are gone.
        let pruned = HistoryArchive::new(
            storage.clone(),
            da.clone(),
            Arc::new(Below(cps.clone(), 4)),
            sole_writer(),
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

    /// Locates segments from committee members' own records.
    struct MemberRecords(Vec<Arc<RocksDbStore>>);

    #[async_trait]
    impl SegmentLocator for MemberRecords {
        async fn locate(&self, first_index: u64) -> Vec<ArchivedSegment> {
            self.0
                .iter()
                .filter_map(|s| recorded_segment(&**s, first_index).unwrap())
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
            Handoff::Locate(Arc::new(MemberRecords(vec![member.storage.clone()]))),
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
                events: 8,
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
                events: 8,
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
            Handoff::Locate(Arc::new(MemberRecords(vec![member.storage.clone()]))),
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
                events: 16,
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

    /// A segment closes before the checkpoint that would take its encoded
    /// size past the byte bound. With a bound under two checkpoints' worth,
    /// every segment holds one checkpoint even inside an epoch, each payload
    /// handed to the DA layer stays within the bound (plus the payload's own
    /// field names), and every pruned block is still served.
    #[tokio::test]
    async fn a_segment_closes_at_its_byte_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut archive, da, blocks) = setup(tmp.path()).await;
        let cps = checkpoints(&blocks, 4, 2);
        let one = encoded_len(&cps[0]).unwrap()
            + blocks[..4]
                .iter()
                .map(|b| encoded_len(b).unwrap())
                .sum::<usize>()
            + 4 * encoded_len(&Vec::<ChainEvent>::new()).unwrap();
        archive.segment_max_bytes = one + one / 2;

        let report = archive.prune_below(22).await.unwrap();
        assert_eq!(report.segments, 4);
        assert_eq!(report.blocks, 16);
        let payloads = da.blobs.lock().values().cloned().collect::<Vec<_>>();
        assert_eq!(payloads.len(), 4);
        for payload in &payloads {
            assert!(payload.len() <= archive.segment_max_bytes + 256);
            let segment: SegmentPayload = serde_json::from_slice(payload).unwrap();
            assert_eq!(segment.checkpoints.len(), 1);
        }
        for h in 1..=16u64 {
            let got = archive.block(h).await.unwrap().expect("served from DA");
            assert_eq!(got.hash(), blocks[h as usize - 1].hash());
        }
    }

    /// The byte bound leaves every committee shape room to store a full
    /// segment: each member's sliver of it fits one store request.
    #[test]
    fn a_full_segment_fits_every_committee() {
        for f in 1..=100 {
            let shape = tenzro_storage::redstuff::CommitteeShape::from_fault_bound(f).unwrap();
            assert!(
                SEGMENT_MAX_BYTES <= crate::da_committee::max_blob_len(shape),
                "f = {f}"
            );
        }
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
                events: 16,
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

    /// Blocks of `storage` at heights `range`, as held locally.
    async fn held(storage: &Arc<RocksDbStore>, range: std::ops::RangeInclusive<u64>) -> Vec<u64> {
        let local = BlockStoreImpl::new(storage.clone()).unwrap();
        let mut out = Vec::new();
        for h in range {
            if local
                .get_block_by_height(BlockHeight(h))
                .await
                .unwrap()
                .is_some()
            {
                out.push(h);
            }
        }
        out
    }

    /// A checkpoint whose blocks encode larger than one DA blob is written
    /// in several parts, each certified by a quorum of the committee; the
    /// segment is recorded with its parts in order, its blocks are pruned,
    /// and every block comes back intact from the reassembled parts.
    #[tokio::test]
    async fn a_checkpoint_larger_than_one_blob_is_archived_in_certified_parts() {
        use crate::da_committee::tests::{MeshSurface, StaticCommittee, backend_for};
        let tmp = tempfile::tempdir().unwrap();
        let (storage, blocks, cps) = stored_chain(tmp.path()).await;
        let committee = StaticCommittee::new(4);
        let backend = Arc::new(backend_for(
            &committee,
            Arc::new(MeshSurface::new(&committee, &[])),
        ));
        assert_eq!(backend.seat(), Some((0, 4)));
        let mut archive = HistoryArchive::new(
            storage.clone(),
            backend.clone(),
            Arc::new(Cps(cps.clone())),
            Handoff::Committee {
                seat: backend.clone(),
                locator: Arc::new(MemberRecords(Vec::new())),
            },
        )
        .unwrap();
        let checkpoint_bytes = encoded_len(&cps[0]).unwrap()
            + blocks[..4]
                .iter()
                .map(|b| encoded_len(b).unwrap())
                .sum::<usize>();
        archive.part_max_bytes = checkpoint_bytes / 3;

        // Checkpoints 0 and 1 (heights 1..=8) close the first epoch.
        let report = archive.prune_below(10).await.unwrap();
        assert_eq!(report.segments, 1);
        assert_eq!(report.blocks, 8);
        assert!(held(&storage, 1..=8).await.is_empty());

        let segment = recorded_segment(&*storage, 0).unwrap().expect("recorded");
        assert_eq!((segment.first_index, segment.last_index), (0, 1));
        assert!(segment.parts.len() >= 6, "{} parts", segment.parts.len());
        let members = backend.committee_members();
        for part in &segment.parts {
            let commitment = Hash::new(part.locator.as_slice().try_into().unwrap());
            let cert = backend
                .custody_store()
                .get_cert(&commitment)
                .expect("every part is certified");
            assert!(cert.verify(&members));
            assert_eq!(Some(cert.root()), part.attestation_root);
            assert!(cert.blob_len as usize <= archive.part_max_bytes);
        }
        for h in 1..=8u64 {
            let got = archive.block(h).await.unwrap().expect("served from DA");
            assert_eq!(got, blocks[h as usize - 1]);
        }
    }

    /// A node restored from a snapshot at height 7, inside the segment of
    /// heights 1..=8, holds that segment only from its base. With no DA
    /// layer it deletes what it holds below the window; as a committee
    /// member it takes the copy another member wrote for that segment
    /// (it cannot write a segment it holds only part of), and writes the
    /// next whole segment itself when it is its turn.
    #[tokio::test]
    async fn a_node_restored_inside_a_segment_prunes_from_its_base() {
        let tmp = tempfile::tempdir().unwrap();

        let (storage, blocks, cps) = stored_chain_from(&tmp.path().join("local"), 7).await;
        let local = HistoryArchive::local(storage.clone(), Arc::new(Cps(cps))).unwrap();
        let report = local.prune_below(22).await.unwrap();
        assert_eq!((report.blocks, report.transactions), (10, 9));
        assert_eq!(local.next_checkpoint().unwrap(), 4);
        assert_eq!(held(&storage, 1..=40).await, (17..=40).collect::<Vec<_>>());
        assert_eq!(local.prune_below(22).await.unwrap(), PruneReport::default());

        let (member, da, _) = setup(&tmp.path().join("member")).await;
        member.prune_below(10).await.unwrap();
        assert_eq!(*da.submits.lock(), 1);
        let (storage, _, cps) = stored_chain_from(&tmp.path().join("restored"), 7).await;
        let restored = HistoryArchive::new(
            storage.clone(),
            da.clone(),
            Arc::new(Cps(cps)),
            Handoff::Committee {
                seat: Arc::new(Seat(0, 1)),
                locator: Arc::new(MemberRecords(vec![member.storage.clone()])),
            },
        )
        .unwrap();
        let report = restored.prune_below(22).await.unwrap();
        assert_eq!((report.segments, report.blocks), (2, 10));
        // The first segment came from the member; only the second was
        // written here.
        assert_eq!(*da.submits.lock(), 2);
        assert_eq!(restored.next_checkpoint().unwrap(), 4);
        assert_eq!(held(&storage, 1..=40).await, (17..=40).collect::<Vec<_>>());
        for h in [1u64, 7, 8, 9, 16] {
            let got = restored.block(h).await.unwrap().expect("served from DA");
            assert_eq!(got, blocks[h as usize - 1]);
        }
    }

    /// A node restored from a snapshot holds the checkpoint bodies from the
    /// snapshot's own checkpoint on, none below: pruning starts at the first
    /// it holds instead of stopping at checkpoint 0 for want of its body.
    #[tokio::test]
    async fn a_restored_node_without_the_bodies_below_its_snapshot_prunes_what_it_holds() {
        let tmp = tempfile::tempdir().unwrap();
        let (storage, _, cps) = stored_chain_from(tmp.path(), 22).await;
        let archive = HistoryArchive::local(storage.clone(), Arc::new(Below(cps, 5))).unwrap();
        let report = archive.prune_below(34).await.unwrap();
        assert!(report.blocks > 0, "nothing pruned");
        assert!(archive.next_checkpoint().unwrap() >= 5);
        let held = held(&storage, 1..=40).await;
        assert_eq!(held.last(), Some(&40));
        assert!(held.first().is_some_and(|h| *h > 22), "{held:?}");
    }

    #[tokio::test]
    async fn a_node_without_the_first_bodies_prunes_what_it_holds_though_it_was_not_restored() {
        let tmp = tempfile::tempdir().unwrap();
        let (storage, _, cps) = stored_chain(tmp.path()).await;
        let archive = HistoryArchive::local(storage.clone(), Arc::new(Below(cps, 3))).unwrap();
        archive.prune_below(22).await.unwrap();
        assert!(archive.next_checkpoint().unwrap() >= 3);
    }

    /// Three members over one DA layer, each holding the whole chain.
    async fn committee_of_three(
        tmp: &std::path::Path,
        step: Duration,
    ) -> (Vec<HistoryArchive>, Arc<MemDa>) {
        let da = Arc::new(MemDa::default());
        let mut stores = Vec::new();
        let mut cps = Vec::new();
        for i in 0..3 {
            let (storage, _, c) = stored_chain(&tmp.join(format!("m{i}"))).await;
            stores.push(storage);
            cps = c;
        }
        let members = (0..3)
            .map(|i| {
                let others = (0..3)
                    .filter(|j| *j != i)
                    .map(|j| stores[j].clone())
                    .collect();
                let mut archive = HistoryArchive::new(
                    stores[i].clone(),
                    da.clone(),
                    Arc::new(Cps(cps.clone())),
                    Handoff::Committee {
                        seat: Arc::new(Seat(i, 3)),
                        locator: Arc::new(MemberRecords(others)),
                    },
                )
                .unwrap();
                archive.writer_wait_per_place = step;
                archive
            })
            .collect();
        (members, da)
    }

    fn segments_recorded(archive: &HistoryArchive) -> u64 {
        read_u64(&*archive.storage, SEGMENT_COUNT_KEY).unwrap()
    }

    /// Each segment is written by one member, the one at its first
    /// checkpoint index modulo the committee size; the others take its
    /// verified copy, whatever order they run in.
    #[tokio::test]
    async fn one_member_writes_each_segment() {
        let tmp = tempfile::tempdir().unwrap();
        let (members, da) = committee_of_three(tmp.path(), WRITER_WAIT_PER_PLACE).await;
        // Segments start at checkpoints 0 and 2: members 0 and 2 write them.
        for _ in 0..2 {
            for m in members.iter().rev() {
                m.prune_below(22).await.unwrap();
            }
        }
        assert_eq!(*da.submits.lock(), 2);
        assert_eq!(da.blobs.lock().len(), 2);
        for m in &members {
            assert_eq!(m.next_checkpoint().unwrap(), 4);
            assert_eq!(segments_recorded(m), 2);
            assert!(held(&m.storage, 1..=16).await.is_empty());
            assert!(m.block(5).await.unwrap().is_some());
        }
    }

    /// When the member whose turn a segment is does not deliver, the next
    /// member in committee order writes it after one wait per place, and the
    /// member after that never does. A late writer takes the copy already
    /// there rather than writing a second one, and no member records a
    /// segment twice.
    #[tokio::test]
    async fn another_member_writes_a_segment_its_writer_does_not_deliver() {
        let tmp = tempfile::tempdir().unwrap();
        let step = Duration::from_millis(200);
        let (members, da) = committee_of_three(tmp.path(), step).await;

        // Member 0, the writer of the segment at checkpoint 0, is silent.
        assert_eq!(
            members[1].prune_below(22).await.unwrap(),
            PruneReport::default()
        );
        assert_eq!(
            members[2].prune_below(22).await.unwrap(),
            PruneReport::default()
        );
        assert_eq!(*da.submits.lock(), 0);

        tokio::time::sleep(step).await;
        // Member 1 stands one place after member 0 and writes; member 2,
        // two places after, still waits.
        let report = members[1].prune_below(22).await.unwrap();
        assert_eq!(report.segments, 1);
        assert_eq!(*da.submits.lock(), 1);
        // Member 2 takes that copy and writes the segment at checkpoint 2,
        // its own turn.
        assert_eq!(members[2].prune_below(22).await.unwrap().segments, 2);
        assert_eq!(*da.submits.lock(), 2);
        assert_eq!(members[1].prune_below(22).await.unwrap().segments, 1);

        // Member 0 comes back and takes both copies.
        assert_eq!(members[0].prune_below(22).await.unwrap().segments, 2);
        assert_eq!(*da.submits.lock(), 2);
        for m in &members {
            assert_eq!(m.next_checkpoint().unwrap(), 4);
            assert_eq!(segments_recorded(m), 2);
            assert_eq!(m.prune_below(22).await.unwrap(), PruneReport::default());
        }
    }

    /// A node that holds a committee seat no longer, or a node outside the
    /// committee, never writes.
    #[test]
    fn only_a_seated_member_writes() {
        struct Unseated;
        impl CommitteeSeat for Unseated {
            fn seat(&self) -> Option<(usize, usize)> {
                None
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            RocksDbStore::open(&tenzro_storage::StorageConfig::new(tmp.path().join("db"))).unwrap(),
        );
        let mut archive = HistoryArchive::local(storage, Arc::new(Cps(Vec::new()))).unwrap();
        archive.writer_wait_per_place = Duration::ZERO;
        let locator: Arc<dyn SegmentLocator> = Arc::new(MemberRecords(Vec::new()));
        let unseated = Handoff::Committee {
            seat: Arc::new(Unseated),
            locator: locator.clone(),
        };
        assert!(!archive.writes(&unseated, 0));
        assert!(!archive.writes(&Handoff::Locate(locator.clone()), 0));
        let seated = Handoff::Committee {
            seat: Arc::new(Seat(1, 3)),
            locator,
        };
        assert!(archive.writes(&seated, 1));
        assert!(archive.writes(&seated, 2));
    }
}
