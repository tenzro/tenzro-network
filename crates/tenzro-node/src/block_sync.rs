//! Block sync: catches a node up when it falls behind, over the node's iroh
//! endpoint (ALPN `tenzro/block-sync`).
//!
//! The peers asked are the committee members of the current and previous
//! epoch whose endpoints were disclosed to this node (a validator seals its
//! endpoint to committee members only, under a commitment its consensus key
//! signs; see [`tenzro_consensus::announce`]) and the best-scored peers this
//! node is connected to over gossip, up to a configured number. A node
//! outside the committee, an RPC node, has only the latter. Anyone may serve:
//! nothing a peer serves is trusted for being served: a range comes with the checkpoint
//! bodies covering it and a certificate they chain to by predecessor digests,
//! and [`crate::event_loop::EventLoop::handle_block_imported_from_sync`]
//! executes a block only once an authenticated checkpoint commits it.
//!
//! - Every probe interval, or at once when consensus reports a certificate
//!   past the local tip or stands down, the engine asks each candidate for
//!   its tip. A round that moved the node on is followed by another at once,
//!   since the network moved on while it imported.
//! - If one is more than the tolerance ahead (or any amount while hinted, or
//!   for longer than the behind deadline), it fetches ranges from the
//!   best-scored of them until it reaches that tip, scoring a peer down for
//!   anything that fails and moving on. Scores below zero recover a little
//!   every round, so a peer that was down is asked again later.
//! - The intervals, timeouts and scores are node configuration
//!   ([`crate::config::BlockSyncConfig`]).
//!
//! This module also serves: [`BlockSyncService`] answers the same requests
//! from the local block store.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use tenzro_consensus::{Checkpoint, PublishedCertificate};
use tenzro_storage::traits::BlockStore;
use tenzro_storage::{BlockStoreImpl, RocksDbStore};
use tenzro_types::block::Block;
use tenzro_types::primitives::{BlockHeight, Hash};

use crate::config::BlockSyncConfig;
use crate::consensus_driver::ConsensusHandle;
use crate::error::{NodeError, Result};

/// Largest number of blocks one range request asks for.
pub const MAX_BLOCKS_PER_RANGE: u32 = 128;

/// Largest block payload a server puts in one range response. A server
/// returning fewer blocks than asked for is normal: the requester asks again
/// from its new height.
pub const MAX_BLOCK_RANGE_BYTES: usize = 6 * 1024 * 1024;

/// A block-sync request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockSyncRequest {
    /// The peer's tip.
    GetTipInfo,
    /// Up to `count` consecutive blocks from `start`, with the checkpoint
    /// evidence covering them.
    GetBlockRange {
        /// First height.
        start: BlockHeight,
        /// Blocks asked for, `1..=MAX_BLOCKS_PER_RANGE`.
        count: u32,
        /// The latest epoch whose committee the requester knows: evidence
        /// past that epoch's end cannot verify for it yet.
        known_epoch: u64,
        /// The latest checkpoint the requester holds a certificate for:
        /// when there are no blocks past its tip (checkpoints that ordered
        /// none), the evidence carries it on from there.
        known_checkpoint: Option<u64>,
    },
}

/// A block-sync response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockSyncResponse {
    /// Answer to `GetTipInfo`.
    TipInfo {
        /// Highest block the peer can serve.
        tip_height: BlockHeight,
        /// Its hash.
        tip_hash: Hash,
        /// The latest checkpoint the peer holds a certificate for, as
        /// (epoch, index). Checkpoints go on while no blocks are ordered.
        certified: Option<(u64, u64)>,
    },
    /// Answer to `GetBlockRange`: ascending blocks, possibly fewer than
    /// asked for, the checkpoint bodies covering them and the certificate
    /// they chain to.
    BlockRange {
        /// The blocks.
        blocks: Vec<Block>,
        /// Checkpoint bodies from the one covering the first block.
        checkpoints: Vec<Checkpoint>,
        /// The certificate the bodies chain to, with every session
        /// certificate it names.
        certificate: Option<PublishedCertificate>,
    },
    /// The request could not be answered.
    Error(String),
}

fn wire() -> impl bincode::Options {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(tenzro_iroh::block_sync::MAX_RESPONSE_BYTES as u64)
        .reject_trailing_bytes()
}

fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    use bincode::Options;
    wire().serialize(value).expect("block-sync messages encode")
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> std::result::Result<T, String> {
    use bincode::Options;
    wire().deserialize(bytes).map_err(|e| e.to_string())
}

/// Checks that a range response is exactly what was requested: it starts at
/// `start`, holds at most `count` blocks, carries consecutive heights, and
/// each block links to its predecessor by `prev_hash`.
fn check_range_response(
    start: u64,
    count: u32,
    blocks: &[Block],
) -> std::result::Result<(), String> {
    if blocks.len() > count as usize {
        return Err(format!(
            "range response holds {} blocks, {} were requested",
            blocks.len(),
            count
        ));
    }
    let mut prev: Option<&Block> = None;
    for (i, block) in blocks.iter().enumerate() {
        let expected = start + i as u64;
        if block.height().0 != expected {
            return Err(format!(
                "range response block {} has height {}, expected {}",
                i,
                block.height(),
                expected
            ));
        }
        if let Some(p) = prev
            && block.header.prev_hash != p.hash()
        {
            return Err(format!(
                "range response block at height {} does not link to its predecessor",
                block.height()
            ));
        }
        prev = Some(block);
    }
    Ok(())
}

/// Whether a peer with `score` and `advertised_tip` is a sync target: its
/// score is at or above `exclusion_threshold` and its tip more than
/// `tolerance` above `our_height`.
fn peer_is_sync_eligible(
    score: i32,
    advertised_tip: Option<(BlockHeight, Hash)>,
    our_height: BlockHeight,
    tolerance: u64,
    exclusion_threshold: i32,
) -> Option<(BlockHeight, Hash)> {
    if score < exclusion_threshold {
        return None;
    }
    let (tip_h, tip_hash) = advertised_tip?;
    (tip_h.0 > our_height.0 + tolerance).then_some((tip_h, tip_hash))
}

/// A peer's score after one round of recovery: a score below zero regains
/// `step`, up to zero; others are kept.
/// The peers a round asks: every `disclosed` committee endpoint and the
/// first `max_connected` of `connected` (best scored first), without
/// `own` or repeats.
fn sync_candidates(
    own: [u8; 32],
    disclosed: Vec<[u8; 32]>,
    connected: Vec<[u8; 32]>,
    max_connected: usize,
) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = disclosed
        .into_iter()
        .chain(
            connected
                .into_iter()
                .filter(|p| *p != own)
                .take(max_connected),
        )
        .filter(|p| *p != own)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn recovered(score: i32, step: i32) -> i32 {
    if score < 0 {
        score.saturating_add(step.max(0)).min(0)
    } else {
        score
    }
}

/// Sent from the engine to the event loop to import a range. The engine
/// learns the outcome through `result`.
#[derive(Debug)]
pub struct BlockImport {
    /// The served blocks, ascending.
    pub blocks: Vec<Block>,
    /// Checkpoint bodies covering them.
    pub checkpoints: Vec<Checkpoint>,
    /// The certificate the bodies chain to, with every session certificate
    /// it names.
    pub certificate: Option<PublishedCertificate>,
    /// The import outcome.
    pub result: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
}

/// Answers block-sync requests from the local block store.
pub struct BlockSyncService {
    storage: Arc<RocksDbStore>,
    consensus: Arc<ConsensusHandle>,
}

impl std::fmt::Debug for BlockSyncService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockSyncService").finish_non_exhaustive()
    }
}

impl BlockSyncService {
    /// A server over `storage`, with evidence from `consensus`.
    pub fn new(storage: Arc<RocksDbStore>, consensus: Arc<ConsensusHandle>) -> Self {
        Self { storage, consensus }
    }

    async fn answer(&self, request: &BlockSyncRequest) -> BlockSyncResponse {
        let store = match BlockStoreImpl::new(self.storage.clone()) {
            Ok(s) => s,
            Err(e) => return BlockSyncResponse::Error(format!("open block store: {e}")),
        };
        match request {
            BlockSyncRequest::GetTipInfo => {
                let certified = self
                    .consensus
                    .latest_certificate()
                    .map(|c| (c.checkpoint.epoch, c.checkpoint.index));
                match store.latest_block().await {
                    Ok(Some(b)) => BlockSyncResponse::TipInfo {
                        tip_height: b.height(),
                        tip_hash: b.hash(),
                        certified,
                    },
                    Ok(None) => BlockSyncResponse::TipInfo {
                        tip_height: BlockHeight(0),
                        tip_hash: Hash::default(),
                        certified,
                    },
                    Err(e) => BlockSyncResponse::Error(format!("latest block: {e}")),
                }
            }
            BlockSyncRequest::GetBlockRange {
                start,
                count,
                known_epoch,
                known_checkpoint,
            } => {
                if *count == 0 || *count > MAX_BLOCKS_PER_RANGE {
                    return BlockSyncResponse::Error(format!(
                        "range of {count} blocks; 1 to {MAX_BLOCKS_PER_RANGE} allowed"
                    ));
                }
                let end = BlockHeight(start.0.saturating_add(*count as u64).saturating_sub(1));
                let blocks = match store.blocks_by_height_range(*start, end).await {
                    Ok(b) => b,
                    Err(e) => return BlockSyncResponse::Error(format!("blocks by height: {e}")),
                };
                // Truncated to the byte budget, never below one block.
                let mut used = 0usize;
                let mut fitted = Vec::with_capacity(blocks.len());
                for block in blocks {
                    let size = bincode::serialized_size(&block).unwrap_or(u64::MAX) as usize;
                    if !fitted.is_empty() && used.saturating_add(size) > MAX_BLOCK_RANGE_BYTES {
                        break;
                    }
                    used = used.saturating_add(size);
                    fitted.push(block);
                }
                let (checkpoints, certificate) = match (fitted.first(), fitted.last()) {
                    (Some(first), Some(last)) => self.consensus.evidence_for(
                        first.height().0,
                        last.height().0,
                        *known_epoch,
                        *known_checkpoint,
                    ),
                    _ => self
                        .consensus
                        .evidence_past_blocks(*known_epoch, *known_checkpoint),
                };
                let certificate = certificate.map(|c| PublishedCertificate {
                    sessions: self.consensus.session_bundle(&c),
                    certificate: c,
                });
                BlockSyncResponse::BlockRange {
                    blocks: fitted,
                    checkpoints,
                    certificate,
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl tenzro_iroh::BlockSyncServer for BlockSyncService {
    async fn serve(&self, request: Vec<u8>) -> Vec<u8> {
        let response = match decode::<BlockSyncRequest>(&request) {
            Ok(r) => self.answer(&r).await,
            Err(e) => BlockSyncResponse::Error(format!("malformed request: {e}")),
        };
        encode(&response)
    }
}

/// The endpoints of the peers a node is connected to, best scored first.
pub type ConnectedPeers = Arc<dyn Fn() -> Vec<[u8; 32]> + Send + Sync>;

/// The client side: finds a peer ahead of the local tip and imports ranges
/// from it.
pub struct BlockSyncEngine {
    endpoint: tenzro_iroh::Endpoint,
    storage: Arc<RocksDbStore>,
    consensus: Arc<ConsensusHandle>,
    block_importer: mpsc::Sender<BlockImport>,
    config: BlockSyncConfig,
    /// The peers this node is connected to, best scored first.
    connected: ConnectedPeers,
    scores: HashMap<[u8; 32], i32>,
    /// While in the future, any positive gap is closed.
    hinted_until: Option<std::time::Instant>,
    /// When the node was first seen behind, for the staleness deadline.
    behind_since: Option<std::time::Instant>,
}

impl BlockSyncEngine {
    /// An engine requesting over `endpoint` and importing through
    /// `block_importer`, asking the committee and `connected`, paced and
    /// scoring peers as `config` says.
    pub fn new(
        endpoint: tenzro_iroh::Endpoint,
        storage: Arc<RocksDbStore>,
        consensus: Arc<ConsensusHandle>,
        block_importer: mpsc::Sender<BlockImport>,
        config: BlockSyncConfig,
        connected: ConnectedPeers,
    ) -> Self {
        Self {
            endpoint,
            storage,
            consensus,
            block_importer,
            config,
            connected,
            scores: HashMap::new(),
            hinted_until: None,
            behind_since: None,
        }
    }

    fn hinted(&self) -> bool {
        matches!(self.hinted_until, Some(t) if std::time::Instant::now() < t)
    }

    fn tolerance(&self) -> u64 {
        if self.hinted() {
            0
        } else {
            self.config.tolerance_blocks
        }
    }

    fn exclusion_threshold(&self) -> i32 {
        if self.hinted() {
            self.config.score_hard_ban_threshold
        } else {
            self.config.score_drop_threshold
        }
    }

    fn score(&mut self, peer: [u8; 32], delta: i32) {
        let (floor, ceiling) = (
            self.config.score_hard_ban_threshold,
            self.config.score_ceiling,
        );
        let s = self.scores.entry(peer).or_default();
        *s = s.saturating_add(delta).clamp(floor, ceiling);
    }

    /// Every peer below zero regains `score_recovery_per_round`, up to zero.
    fn recover_scores(&mut self) {
        let step = self.config.score_recovery_per_round;
        for s in self.scores.values_mut() {
            *s = recovered(*s, step);
        }
    }

    /// The endpoints the current and previous epoch's committee members
    /// disclosed to this node, and the connected peers, but this node's own.
    fn candidates(&self) -> Vec<[u8; 32]> {
        let current = self.consensus.epoch_manager().current_epoch().number;
        let disclosed: Vec<[u8; 32]> = (current.saturating_sub(1)..=current)
            .filter_map(|e| self.consensus.committee(e))
            .flat_map(|c| {
                c.members()
                    .iter()
                    .filter_map(|m| self.consensus.announced_endpoint(&m.public_key))
                    .collect::<Vec<_>>()
            })
            .collect();
        sync_candidates(
            *self.endpoint.id().as_bytes(),
            disclosed,
            (self.connected)(),
            self.config.max_connected_peers,
        )
    }

    /// Runs until `shutdown` fires.
    pub async fn run(mut self, mut shutdown: tokio::sync::broadcast::Receiver<()>) {
        info!("Block-sync engine started");
        let mut behind = self.consensus.subscribe_behind_hint();
        let mut tick = tokio::time::interval(Duration::from_millis(
            self.config.tip_probe_interval_ms.max(1),
        ));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.recv() => return,
                changed = behind.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    self.hinted_until = Some(
                        std::time::Instant::now()
                            + Duration::from_millis(self.config.behind_hint_ms),
                    );
                    debug!(height = *behind.borrow(), "Block-sync: a certificate is past the local tip");
                }
                _ = tick.tick() => {}
            }
            run_rounds(&mut self, MAX_ROUNDS_PER_WAKE).await;
        }
    }

    async fn request(
        &self,
        peer: [u8; 32],
        request: &BlockSyncRequest,
        timeout: Duration,
    ) -> std::result::Result<BlockSyncResponse, String> {
        let id = tenzro_iroh::EndpointId::from_bytes(&peer)
            .map_err(|e| format!("peer endpoint key: {e}"))?;
        let bytes = tokio::time::timeout(
            timeout,
            tenzro_iroh::block_sync_request(&self.endpoint, id, &encode(request)),
        )
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| e.to_string())?;
        decode(&bytes)
    }

    /// One round: probe tips, and if a peer is ahead, import from it until
    /// the local tip reaches its tip or it fails.
    async fn sync_once(&mut self) -> Result<()> {
        self.recover_scores();
        let our = self.local_tip().await?;
        let threshold = self.exclusion_threshold();
        let candidates: Vec<[u8; 32]> = self
            .candidates()
            .into_iter()
            .filter(|p| self.scores.get(p).copied().unwrap_or(0) >= threshold)
            .collect();
        let probe_timeout = Duration::from_millis(self.config.tip_request_timeout_ms);
        let probes = futures::future::join_all(
            candidates
                .iter()
                .map(|p| self.request(*p, &BlockSyncRequest::GetTipInfo, probe_timeout)),
        )
        .await;
        let mut tips = Vec::new();
        for (peer, probe) in candidates.into_iter().zip(probes) {
            match probe {
                Ok(BlockSyncResponse::TipInfo {
                    tip_height,
                    tip_hash,
                    certified,
                }) => tips.push((peer, tip_height, tip_hash, certified.map_or(0, |(_, i)| i))),
                Ok(other) => {
                    debug!(peer = %hex::encode(&peer[..8]), response = ?std::mem::discriminant(&other), "Block-sync: tip probe answered with something else");
                    self.score(peer, self.config.score_penalty);
                }
                Err(e) => {
                    debug!(peer = %hex::encode(&peer[..8]), error = %e, "Block-sync: tip probe failed");
                    self.score(peer, self.config.score_penalty);
                }
            }
        }
        if let Some(c) = tips.iter().map(|(_, _, _, c)| *c).max() {
            self.consensus.note_network_checkpoint(c);
        }
        let our_checkpoint = self.local_checkpoint();
        let behind = tips
            .iter()
            .any(|(_, h, _, c)| h.0 > our.0 || our_checkpoint.is_none_or(|o| *c > o));
        match (behind, self.behind_since) {
            (true, None) => self.behind_since = Some(std::time::Instant::now()),
            (false, _) => self.behind_since = None,
            _ => {}
        }
        let stale = self
            .behind_since
            .is_some_and(|t| t.elapsed() >= Duration::from_millis(self.config.max_behind_ms));
        let tolerance = if stale { 0 } else { self.tolerance() };
        // A node that does not validate follows certified checkpoints
        // closely: one that stood down rejoins at the next handover only if
        // it learns of it while it is current.
        let checkpoint_tolerance = if stale || self.hinted() || !self.consensus.is_validator() {
            0
        } else {
            self.config.tolerance_checkpoints
        };
        let mut eligible: Vec<([u8; 32], BlockHeight, u64)> = tips
            .iter()
            .filter_map(|(p, h, hash, c)| {
                let score = self.scores.get(p).copied().unwrap_or(0);
                let by_blocks =
                    peer_is_sync_eligible(score, Some((*h, *hash)), our, tolerance, threshold)
                        .is_some();
                // Checkpoints that order no block move the epoch on too: a
                // node that missed them cannot verify what comes after.
                let by_checkpoints = score >= threshold
                    && our_checkpoint.is_none_or(|o| *c > o.saturating_add(checkpoint_tolerance));
                (by_blocks || by_checkpoints).then_some((*p, *h, *c))
            })
            .collect();
        // Best-scored first, then the highest tip.
        eligible.sort_by_key(|(p, h, c)| {
            (
                std::cmp::Reverse(self.scores.get(p).copied().unwrap_or(0)),
                std::cmp::Reverse(h.0),
                std::cmp::Reverse(*c),
            )
        });
        for (peer, target, checkpoint) in eligible {
            if self.sync_from(peer, target, checkpoint).await? {
                self.hinted_until = None;
                return Ok(());
            }
        }
        Ok(())
    }

    /// Imports ranges from `peer` up to block `target` and checkpoint
    /// `checkpoint`. True once the local node is there; false if the peer
    /// stopped being useful first.
    async fn sync_from(
        &mut self,
        peer: [u8; 32],
        target: BlockHeight,
        checkpoint: u64,
    ) -> Result<bool> {
        info!(peer = %hex::encode(&peer[..8]), target = %target, checkpoint, "Block-sync: catching up");
        loop {
            let our = self.local_tip().await?;
            let our_checkpoint = self.local_checkpoint();
            if our.0 >= target.0 && our_checkpoint.is_some_and(|c| c >= checkpoint) {
                info!(height = %our, checkpoint = ?our_checkpoint, "Block-sync: caught up");
                return Ok(true);
            }
            let start = our.0 + 1;
            let count = target
                .0
                .saturating_sub(our.0)
                .clamp(1, MAX_BLOCKS_PER_RANGE as u64) as u32;
            let known_epoch = self.consensus.known_epoch();
            let request = BlockSyncRequest::GetBlockRange {
                start: BlockHeight(start),
                count,
                known_epoch,
                known_checkpoint: our_checkpoint,
            };
            let (blocks, checkpoints, certificate) = match self
                .request(
                    peer,
                    &request,
                    Duration::from_millis(self.config.range_request_timeout_ms),
                )
                .await
            {
                Ok(BlockSyncResponse::BlockRange {
                    blocks,
                    checkpoints,
                    certificate,
                }) => (blocks, checkpoints, certificate),
                Ok(other) => {
                    warn!(peer = %hex::encode(&peer[..8]), response = ?std::mem::discriminant(&other), "Block-sync: the range request was not answered with a range");
                    self.score(peer, self.config.score_penalty);
                    return Ok(false);
                }
                Err(e) => {
                    warn!(peer = %hex::encode(&peer[..8]), error = %e, "Block-sync: range request failed");
                    self.score(peer, self.config.score_penalty);
                    return Ok(false);
                }
            };
            if blocks.is_empty() && certificate.is_none() {
                info!(peer = %hex::encode(&peer[..8]), start, known_epoch, "Block-sync: the peer sent nothing from here");
                return Ok(false);
            }
            if let Err(e) = check_range_response(start, count, &blocks) {
                warn!(peer = %hex::encode(&peer[..8]), error = %e, "Block-sync: refusing a range");
                self.score(peer, self.config.score_penalty);
                return Ok(false);
            }
            let served = certificate.as_ref().map(|c| c.certificate.checkpoint.index);
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.block_importer
                .send(BlockImport {
                    blocks,
                    checkpoints,
                    certificate,
                    result: tx,
                })
                .await
                .map_err(|_| NodeError::Other("block importer channel closed".into()))?;
            match rx
                .await
                .map_err(|_| NodeError::Other("block importer reply channel closed".into()))?
            {
                Ok(()) => {}
                Err(e) => {
                    warn!(peer = %hex::encode(&peer[..8]), error = %e, "Block-sync: import refused");
                    self.score(peer, self.config.score_penalty);
                    return Ok(false);
                }
            }
            // A served certificate is taken by the consensus core after the
            // import call returns, so the epoch it ends shows a moment later:
            // wait for it before calling the range fruitless, or a node many
            // epochs behind takes one epoch per retry interval and never
            // catches a network whose epochs are shorter than that.
            let progressed = settle(
                || async {
                    Ok::<bool, NodeError>(range_progressed(
                        (our.0, known_epoch, our_checkpoint),
                        (
                            self.local_tip().await?.0,
                            self.consensus.known_epoch(),
                            self.local_checkpoint(),
                        ),
                        served,
                    ))
                },
                PROGRESS_STEP,
                PROGRESS_WAIT,
            )
            .await?;
            if !progressed {
                // The peer holds blocks past its latest certificate; not a
                // fault, and nothing more to gain from it now. An import
                // that only ended an epoch made progress: its next committee
                // verifies the next range.
                info!(
                    peer = %hex::encode(&peer[..8]), height = %our, known_epoch, target = %target,
                    "Block-sync: the range imported nothing new"
                );
                return Ok(false);
            }
            self.score(peer, self.config.score_success);
        }
    }

    /// The latest checkpoint this node holds a certificate for.
    fn local_checkpoint(&self) -> Option<u64> {
        self.consensus
            .latest_certificate()
            .map(|c| c.checkpoint.index)
    }

    async fn local_tip(&self) -> Result<BlockHeight> {
        let store = BlockStoreImpl::new(self.storage.clone()).map_err(NodeError::Storage)?;
        Ok(store
            .latest_height()
            .await
            .map_err(NodeError::Storage)?
            .unwrap_or(BlockHeight(0)))
    }
}

/// Whether a range import moved the node on, from `before` to `after`, each
/// (tip, known epoch, latest checkpoint): its tip or its epoch moved, or its
/// checkpoint reached the certificate `served` with the range, past the one
/// it held. A checkpoint the node learns meanwhile from gossip or its own
/// core is not the range's doing: counted as progress, it had the node ask
/// again and again for the same few blocks, which complete no checkpoint,
/// while its tip stood still for as long as the network went on certifying.
fn range_progressed(
    before: (u64, u64, Option<u64>),
    after: (u64, u64, Option<u64>),
    served: Option<u64>,
) -> bool {
    let (tip, epoch, checkpoint) = before;
    let (tip_now, epoch_now, checkpoint_now) = after;
    let certified = served.is_some_and(|s| {
        checkpoint.is_none_or(|c| s > c) && checkpoint_now.is_some_and(|c| c >= s)
    });
    tip_now != tip || epoch_now != epoch || certified
}

/// The most rounds one wake runs back to back. Each round asks every
/// candidate once and is bounded by the request timeouts; the next wake or
/// probe carries on after these.
const MAX_ROUNDS_PER_WAKE: u32 = 16;

/// A sync round and where it leaves the node.
trait SyncRounds {
    type Position: PartialEq;
    /// The local tip and checkpoint, if they can be read.
    async fn position(&self) -> Option<Self::Position>;
    /// One round; false if it failed.
    async fn round(&mut self) -> bool;
}

impl SyncRounds for BlockSyncEngine {
    type Position = (BlockHeight, Option<u64>);

    async fn position(&self) -> Option<Self::Position> {
        Some((self.local_tip().await.ok()?, self.local_checkpoint()))
    }

    async fn round(&mut self) -> bool {
        match self.sync_once().await {
            Ok(()) => true,
            Err(e) => {
                warn!(error = %e, "Block-sync round failed");
                false
            }
        }
    }
}

/// Runs rounds while each moves the node on, up to `limit`; how many ran.
/// A round's target is the tip peers advertised when it began; a node that
/// reached it asks again at once instead of waiting for the next probe,
/// and stops once a round leaves it where it was, so a node at the
/// network's tip runs one round per wake.
async fn run_rounds<S: SyncRounds>(s: &mut S, limit: u32) -> u32 {
    let mut ran = 0;
    while ran < limit {
        let before = s.position().await;
        ran += 1;
        if !s.round().await {
            break;
        }
        let after = s.position().await;
        if before.is_none() || after.is_none() || before == after {
            break;
        }
    }
    ran
}

/// How often an import's effect is looked for, and for how long.
const PROGRESS_STEP: Duration = Duration::from_millis(25);
const PROGRESS_WAIT: Duration = Duration::from_millis(1_000);

/// Polls `changed` every `step` until it reports true or `limit` has passed;
/// whether it did.
async fn settle<F, Fut, E>(
    mut changed: F,
    step: Duration,
    limit: Duration,
) -> std::result::Result<bool, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<bool, E>>,
{
    let mut waited = Duration::ZERO;
    loop {
        if changed().await? {
            return Ok(true);
        }
        if waited >= limit {
            return Ok(false);
        }
        tokio::time::sleep(step).await;
        waited += step;
    }
}

#[cfg(test)]
mod round_tests {
    use super::*;

    /// A restarted validator asked for the three blocks up to a tip a peer
    /// had probed, inside a checkpoint not yet certified there: the range
    /// imported nothing, and the certificates the network formed meanwhile
    /// moved its checkpoint on every half second. Counted as progress, that
    /// had it ask for the same three blocks for two minutes, its tip still.
    #[test]
    fn a_checkpoint_learned_elsewhere_is_not_a_ranges_progress() {
        // The served certificate is older than the one the node holds.
        assert!(!range_progressed(
            (435, 0, Some(270)),
            (435, 0, Some(271)),
            Some(80)
        ));
        // No certificate served at all.
        assert!(!range_progressed(
            (435, 0, Some(270)),
            (435, 0, Some(271)),
            None
        ));
        // A newer one served, but the checkpoint did not reach it.
        assert!(!range_progressed(
            (435, 0, Some(77)),
            (435, 0, Some(77)),
            Some(78)
        ));
    }

    #[test]
    fn a_range_that_moves_the_tip_the_epoch_or_to_its_certificate_progressed() {
        assert!(range_progressed(
            (435, 0, Some(77)),
            (442, 0, Some(77)),
            Some(78)
        ));
        assert!(range_progressed(
            (435, 0, Some(77)),
            (435, 1, Some(77)),
            None
        ));
        // Checkpoints that order no block: the served certificate is taken.
        assert!(range_progressed(
            (435, 0, Some(77)),
            (435, 0, Some(78)),
            Some(78)
        ));
        assert!(range_progressed((435, 0, None), (435, 0, Some(3)), Some(3)));
    }

    /// A network whose tip moves on while the node imports: each round
    /// reaches the tip probed when it began, and the network is `ahead`
    /// rounds further on by then.
    struct Moving {
        tip: u64,
        ahead: u64,
        fail_at: Option<u32>,
        rounds: u32,
    }

    impl SyncRounds for Moving {
        type Position = u64;
        async fn position(&self) -> Option<u64> {
            Some(self.tip)
        }
        async fn round(&mut self) -> bool {
            self.rounds += 1;
            if self.fail_at == Some(self.rounds) {
                return false;
            }
            if self.ahead > 0 {
                self.ahead -= 1;
                self.tip += 10;
            }
            true
        }
    }

    #[tokio::test]
    async fn a_node_that_caught_up_asks_again_at_once_while_the_network_moved_on() {
        let mut m = Moving {
            tip: 0,
            ahead: 3,
            fail_at: None,
            rounds: 0,
        };
        // Three rounds that each moved the node on, then one that found it
        // at the tip.
        assert_eq!(run_rounds(&mut m, MAX_ROUNDS_PER_WAKE).await, 4);
        assert_eq!(m.tip, 30);
    }

    #[tokio::test]
    async fn a_node_at_the_tip_runs_one_round() {
        let mut m = Moving {
            tip: 5,
            ahead: 0,
            fail_at: None,
            rounds: 0,
        };
        assert_eq!(run_rounds(&mut m, MAX_ROUNDS_PER_WAKE).await, 1);
    }

    #[tokio::test]
    async fn rounds_stop_at_the_limit_and_on_a_failure() {
        let mut m = Moving {
            tip: 0,
            ahead: 100,
            fail_at: None,
            rounds: 0,
        };
        assert_eq!(run_rounds(&mut m, 5).await, 5);
        let mut m = Moving {
            tip: 0,
            ahead: 100,
            fail_at: Some(2),
            rounds: 0,
        };
        assert_eq!(run_rounds(&mut m, MAX_ROUNDS_PER_WAKE).await, 2);
    }
}

#[cfg(test)]
mod settle_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn a_change_that_shows_a_moment_later_is_seen() {
        let polls = AtomicU32::new(0);
        let seen = settle(
            || async { Ok::<bool, ()>(polls.fetch_add(1, Ordering::SeqCst) >= 3) },
            Duration::from_millis(5),
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(seen, Ok(true));
    }

    #[tokio::test]
    async fn no_change_is_given_up_on_after_the_limit() {
        let started = std::time::Instant::now();
        let seen = settle(
            || async { Ok::<bool, ()>(false) },
            Duration::from_millis(5),
            Duration::from_millis(60),
        )
        .await;
        assert_eq!(seen, Ok(false));
        assert!(started.elapsed() >= Duration::from_millis(60));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BlockSyncConfig {
        BlockSyncConfig::default()
    }

    /// A node outside the committee has no disclosed endpoints; it asks the
    /// peers it is connected to, the best-scored up to the configured
    /// number, never itself.
    #[test]
    fn a_node_outside_the_committee_asks_its_connected_peers() {
        let own = [9; 32];
        let connected = vec![[1; 32], own, [2; 32], [3; 32]];
        assert_eq!(
            sync_candidates(own, Vec::new(), connected.clone(), 2),
            vec![[1; 32], [2; 32]]
        );
        assert!(sync_candidates(own, Vec::new(), connected, 0).is_empty());
    }

    /// A committee member asks the disclosed endpoints and its connected
    /// peers, each once.
    #[test]
    fn a_member_asks_the_disclosed_endpoints_and_its_connected_peers_once() {
        let own = [9; 32];
        assert_eq!(
            sync_candidates(own, vec![[4; 32], own, [1; 32]], vec![[1; 32], [5; 32]], 8),
            vec![[1; 32], [4; 32], [5; 32]]
        );
    }

    /// A peer that failed for a while, down to the hard-ban line, is asked
    /// again once enough rounds pass; it never banks credit by waiting.
    #[test]
    fn a_failed_peer_recovers_to_neutral_over_rounds() {
        let c = cfg();
        let mut s = c.score_hard_ban_threshold;
        let mut rounds = 0;
        while s < c.score_drop_threshold {
            s = recovered(s, c.score_recovery_per_round);
            rounds += 1;
        }
        assert!(rounds > 0 && rounds < 1_000);
        for _ in 0..1_000 {
            s = recovered(s, c.score_recovery_per_round);
        }
        assert_eq!(s, 0);
        assert_eq!(
            recovered(c.score_ceiling, c.score_recovery_per_round),
            c.score_ceiling
        );
    }

    fn tip(h: u64) -> Option<(BlockHeight, Hash)> {
        Some((BlockHeight(h), Hash::default()))
    }

    /// A peer one block ahead is eligible while hinted (tolerance 0) even
    /// with a score below the steady-state drop line.
    #[test]
    fn behind_hinted_peer_below_drop_line_is_eligible() {
        let r = peer_is_sync_eligible(
            -60,
            tip(192_745),
            BlockHeight(192_744),
            0,
            cfg().score_hard_ban_threshold,
        );
        assert_eq!(r, Some((BlockHeight(192_745), Hash::default())));
    }

    #[test]
    fn same_peer_excluded_at_steady_state_drop_line() {
        let r = peer_is_sync_eligible(
            -60,
            tip(192_745),
            BlockHeight(192_744),
            cfg().tolerance_blocks,
            cfg().score_drop_threshold,
        );
        assert_eq!(r, None);
    }

    #[test]
    fn hard_banned_peer_excluded_even_when_behind() {
        let r = peer_is_sync_eligible(
            -600,
            tip(192_745),
            BlockHeight(192_744),
            0,
            cfg().score_hard_ban_threshold,
        );
        assert_eq!(r, None);
    }

    #[test]
    fn peer_at_our_head_is_not_a_sync_target() {
        let r = peer_is_sync_eligible(
            0,
            tip(192_744),
            BlockHeight(192_744),
            0,
            cfg().score_hard_ban_threshold,
        );
        assert_eq!(r, None);
    }

    #[test]
    fn peer_without_advertised_tip_is_not_eligible() {
        let r = peer_is_sync_eligible(
            100,
            None,
            BlockHeight(192_744),
            0,
            cfg().score_hard_ban_threshold,
        );
        assert_eq!(r, None);
    }

    #[test]
    fn single_block_gap_within_steady_tolerance_is_ignored() {
        assert!(cfg().tolerance_blocks >= 1);
        let r = peer_is_sync_eligible(
            0,
            tip(192_745),
            BlockHeight(192_744),
            cfg().tolerance_blocks,
            cfg().score_drop_threshold,
        );
        assert_eq!(r, None);
    }

    fn linked_chain(start: u64, len: u64) -> Vec<Block> {
        use tenzro_types::block::BlockHeader;
        use tenzro_types::primitives::Address;
        let mut prev = Hash::new([7u8; 32]);
        (start..start + len)
            .map(|h| {
                let header = BlockHeader::new(
                    BlockHeight(h),
                    prev,
                    Hash::zero(),
                    Hash::zero(),
                    Address::zero(),
                );
                let block = Block::new(header, Vec::new());
                prev = block.hash();
                block
            })
            .collect()
    }

    #[test]
    fn a_complete_linked_range_is_accepted() {
        let blocks = linked_chain(10, 5);
        assert!(check_range_response(10, 5, &blocks).is_ok());
        assert!(check_range_response(10, 8, &blocks).is_ok());
    }

    #[test]
    fn a_range_with_a_block_removed_is_refused() {
        let mut blocks = linked_chain(10, 5);
        blocks.remove(2);
        assert!(check_range_response(10, 5, &blocks).is_err());
    }

    #[test]
    fn a_range_starting_elsewhere_is_refused() {
        let blocks = linked_chain(11, 3);
        assert!(check_range_response(10, 5, &blocks).is_err());
    }

    #[test]
    fn a_range_longer_than_requested_is_refused() {
        let blocks = linked_chain(10, 6);
        assert!(check_range_response(10, 5, &blocks).is_err());
    }

    #[test]
    fn a_range_that_does_not_link_is_refused() {
        let mut blocks = linked_chain(10, 3);
        blocks[1].header.prev_hash = Hash::new([9u8; 32]);
        assert!(check_range_response(10, 3, &blocks).is_err());
    }

    /// A full range and its evidence fit a response frame: the block budget
    /// leaves room for a certificate of the largest committee (one member
    /// per seat), each signer with its session signature, session digest and
    /// session certificate.
    #[test]
    fn a_full_range_fits_a_response_frame() {
        let signature = 3_309 + 64 + 2 * 8;
        let session_certificate = 8 + 32 + 8 + 32 + (1_952 + 65 + 3 * 8) + (3_309 + 64 + 2 * 8);
        let per_signer = 2 + 32 + signature + session_certificate;
        let certificate_budget =
            tenzro_consensus::committee::DEFAULT_SEAT_BUDGET as usize * per_signer + 4_096;
        assert!(
            MAX_BLOCK_RANGE_BYTES + certificate_budget
                < tenzro_iroh::block_sync::MAX_RESPONSE_BYTES
        );
    }

    #[test]
    fn a_trailing_byte_or_an_oversized_length_is_refused() {
        let mut bytes = encode(&BlockSyncRequest::GetTipInfo);
        assert_eq!(
            decode::<BlockSyncRequest>(&bytes),
            Ok(BlockSyncRequest::GetTipInfo)
        );
        bytes.push(0);
        assert!(decode::<BlockSyncRequest>(&bytes).is_err());
        // A vector length claiming more than the frame limit.
        let mut huge = encode(&BlockSyncResponse::Error(String::new()));
        let n = huge.len();
        huge[n - 8..].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode::<BlockSyncResponse>(&huge).is_err());
    }
}
