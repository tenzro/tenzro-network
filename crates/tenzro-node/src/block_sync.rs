//! Block-sync engine: catches a node up to the network's chain tip when the
//! node falls behind by more than `SLOT_IMPORT_TOLERANCE` blocks.
//!
//! Architecture follows Lighthouse's `SyncManager`:
//!
//! - **Idle**: periodically probe peers via `GetTipInfo`. If any peer's tip is
//!   `> our_height + SLOT_IMPORT_TOLERANCE`, transition into syncing.
//! - **Syncing**: send `GetBlockRange { start = our_height + 1, count }` to
//!   the chosen peer, validate each returned block (per-block QC verification
//!   via [`crate::event_loop::EventLoop::handle_block_imported_from_sync`]),
//!   import via `handle_block_imported_from_sync`, and repeat until our tip
//!   reaches the target. On peer failure (transport error, invalid response,
//!   QC rejection), score the peer down, drop it, and re-probe.
//! - **Done**: call [`tenzro_consensus::HotStuff2Engine::resume_from_synced_height`]
//!   so the consensus engine advances past the obsolete view it was stuck at,
//!   then return to Idle.
//!
//! This module also runs the **server side**: it owns the
//! `subscribe_block_sync_requests` consumer and answers inbound
//! `GetTipInfo` / `GetBlockRange` / `GetBlockByHash` requests by reading
//! from the local block store.
//!
//! # Concurrency model
//!
//! The engine is a single async task driven by a Tokio loop. Inbound requests,
//! outbound responses, and the periodic tip probe are all selected on the same
//! `tokio::select!`. There is no shared state across tasks — the engine owns
//! its peer table, in-flight request map, and target.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{Interval, interval};
use tracing::{debug, info, warn};

use libp2p::PeerId;
use tenzro_consensus::HotStuff2Engine;
use tenzro_consensus::QuorumCertificate;
use tenzro_network::{
    BlockSyncError, BlockSyncRequest, BlockSyncResponse, InboundBlockSync, InboundRequestId,
    MAX_BLOCKS_PER_RANGE, MAX_INFLIGHT_REQUESTS_PER_PEER, NetworkService, OutboundBlockSyncResult,
    OutboundRequestId, PeerEvent, TenzroNetworkService,
};
use tenzro_storage::traits::BlockStore;
use tenzro_storage::{BlockStoreImpl, RocksDbStore};
use tenzro_types::block::Block;
use tenzro_types::primitives::{BlockHeight, Hash};

use crate::error::{NodeError, Result};

/// Lighthouse `SyncManager` constant: if our local head is within this many
/// blocks of a peer's advertised tip, we consider ourselves synced and skip
/// the catch-up state. Set to 8 (Lighthouse default).
pub const SLOT_IMPORT_TOLERANCE: u64 = 8;

/// How often the idle state probes peers for tip info.
pub const TIP_PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// How long to wait between successive `GetBlockRange` calls inside a sync run
/// before flagging the peer as stalled.
pub const RANGE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum simultaneous block-sync requests outstanding against a single peer.
///
/// Re-exports the wire-protocol-level constant so caller-side and server-side
/// limits stay in sync. Lighthouse's `SyncManager` uses 10; we follow that.
/// Overflow is rejected with `NodeError::Other("peer saturated")` rather than
/// queued — queueing turns one slow peer into a memory-amplification vector.
pub const MAX_INFLIGHT_PER_PEER: usize = MAX_INFLIGHT_REQUESTS_PER_PEER;

/// Score adjustment applied to a peer when it serves invalid data
/// (bad QC, malformed range, transport error).
pub const PEER_SCORE_PENALTY: i32 = -10;

/// Score adjustment applied to a peer when it serves a valid response.
/// Without a recovery path a peer that flaps a few times during a transient
/// network blip (or while a neighbour is mid-restart) is driven below the drop
/// line and never re-probed — its score can only ever fall. Rewarding success
/// lets a recovered peer climb back into the candidate set. Smaller in
/// magnitude than the penalty so misbehaviour still dominates.
pub const PEER_SCORE_SUCCESS: i32 = 5;

/// Upper bound on a peer's reputation score. Caps how much credit a peer can
/// bank so a long-good peer can't absorb an unbounded run of later failures
/// before being evicted.
pub const PEER_SCORE_CEILING: i32 = 50;

/// Score below which a peer is dropped from the steady-state candidate set.
/// This is a DoS dampener for *normal* operation — it stops the engine from
/// repeatedly probing a flaky peer while the local head is already current.
pub const PEER_SCORE_DROP_THRESHOLD: i32 = -50;

/// Score below which a peer is excluded even while we are actively behind
/// (a consensus behind-hint is engaged). Catchup peer-eligibility must be
/// SEPARATE from steady-state reputation: the node that is behind is exactly
/// the one whose sync requests have been failing (its only candidates are
/// OOM-flapping peers serving the missing block), so its peer scores are
/// degraded *by being behind*. Gating catchup on the same threshold starves
/// the requester and deadlocks sync — the chain can then lose quorum and
/// halt (cf. the known catchup-starvation-on-degraded-score class of bug).
/// While behind we
/// only exclude peers that are hard-banned (egregious, sustained
/// misbehavior), never peers merely below the steady-state drop line.
pub const PEER_SCORE_HARD_BAN_THRESHOLD: i32 = -500;

/// Block-sync engine state machine.
#[derive(Debug, Clone)]
pub enum SyncState {
    /// Local head is within `SLOT_IMPORT_TOLERANCE` of every known peer's tip.
    /// The engine periodically re-probes peers via `GetTipInfo`.
    Synced,

    /// Catching up to `target`. Active outbound `GetBlockRange` is tracked by
    /// `in_flight`; on response, more requests are issued until the target is
    /// reached. `deadline` is the watchdog: libp2p does not always deliver an
    /// `OutboundFailure` for a request lost to a connection-drop race (cf. the
    /// `handle_peer_event` doc comment), so a sync run can hang in `Syncing`
    /// forever with no response and no failure event — every probe tick and
    /// behind-hint then early-returns and the engine deadlocks. Once `deadline`
    /// passes the next probe tick force-drops to `Stalled` and re-elects a peer.
    Syncing {
        target_height: BlockHeight,
        target_hash: Hash,
        peer: PeerId,
        in_flight: Option<OutboundRequestId>,
        deadline: std::time::Instant,
    },

    /// Last sync attempt failed (peer disconnected, invalid data, timeout).
    /// The engine will re-enter Idle on the next probe tick.
    Stalled,
}

/// Per-peer reputation + concurrency tracking. Lighthouse maintains a rolling
/// integer score; peers below `PEER_SCORE_DROP_THRESHOLD` are evicted from the
/// candidate set. We additionally cap the number of outstanding outbound
/// requests at `MAX_INFLIGHT_PER_PEER` to prevent one slow peer from
/// monopolising the engine's request capacity.
#[derive(Debug, Clone, Default)]
struct PeerScore {
    /// Rolling reputation score; mutated by `score_peer`. Negative on
    /// transport errors, malformed responses, or QC verification failures.
    score: i32,
    /// Last `tip_height` / `tip_hash` reported by this peer via `GetTipInfo`.
    advertised_tip: Option<(BlockHeight, Hash)>,
    /// Outbound `OutboundRequestId`s we've issued to this peer that have not
    /// yet resolved. Bounded above by `MAX_INFLIGHT_PER_PEER`. Decremented in
    /// `handle_outbound` regardless of success/failure.
    in_flight: HashSet<OutboundRequestId>,
}

impl PeerScore {
    /// True iff this peer has spare capacity for another outbound request.
    fn has_capacity(&self) -> bool {
        self.in_flight.len() < MAX_INFLIGHT_PER_PEER
    }
}

/// Pure sync-eligibility predicate, extracted from `best_peer_tip` so it can
/// be unit-tested without standing up a live engine (the constructor needs a
/// network service, store, and consensus handle). A peer is an eligible sync
/// target iff its score is at or above `exclusion_threshold` AND it has
/// advertised a tip more than `tolerance` blocks above our local head.
///
/// `exclusion_threshold` is supplied by the caller's `peer_exclusion_threshold()`
/// — the steady-state drop line when current, the hard-ban floor while behind —
/// so catchup is never starved by scores that degraded *because* we fell behind
/// (cf. the known catchup-starvation-on-degraded-score class of bug).
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
    if tip_h.0 > our_height.0 + tolerance {
        Some((tip_h, tip_hash))
    } else {
        None
    }
}

/// Block-sync engine. Owns the network service handle, storage handle, and
/// optional consensus handle.
pub struct BlockSyncEngine {
    network: Arc<TenzroNetworkService>,
    storage: Arc<RocksDbStore>,
    consensus: Option<Arc<HotStuff2Engine>>,

    /// Receives inbound block-sync requests from peers (server role).
    inbound_rx: mpsc::UnboundedReceiver<InboundBlockSync>,

    /// Receives outbound block-sync results matching our requests (client role).
    outbound_rx: mpsc::UnboundedReceiver<OutboundBlockSyncResult>,

    /// Receives peer connection lifecycle events from the network event
    /// loop. `Connected` populates `peers` with a default `PeerScore` so
    /// the next probe tick can include this peer; `Disconnected` evicts
    /// the entry so we stop probing peers we can no longer reach. Without
    /// this stream, `peers` stays empty forever and the engine never
    /// sends any outbound requests.
    peer_events_rx: mpsc::UnboundedReceiver<PeerEvent>,

    /// Imports a synced block into the node — calls
    /// `handle_block_imported_from_sync` which runs the per-block QC check.
    block_importer: mpsc::Sender<BlockImport>,

    state: SyncState,
    peers: HashMap<PeerId, PeerScore>,

    /// Interval ticker for the idle tip-probe loop.
    probe_tick: Interval,

    /// While set and in the future, the engine syncs on ANY positive gap
    /// (tolerance 0) instead of requiring `> SLOT_IMPORT_TOLERANCE`.
    /// Armed by consensus rejecting an ahead-of-us proposal (the
    /// behind-hint watch channel) — that rejection is proof a quorum is
    /// building blocks past our tip, so even a gap of 1..=8 must be
    /// closed or this replica is stranded forever.
    hinted_until: Option<std::time::Instant>,
}

/// Sent from the engine to the event loop to import a block. The event loop
/// performs the actual `handle_block_imported_from_sync` call (which holds
/// `&mut self`); the engine cannot do that directly because it does not own
/// the EventLoop.
///
/// The engine also receives the import outcome via `result` so it can score
/// the serving peer and decide whether to continue syncing or stall.
#[derive(Debug)]
pub struct BlockImport {
    pub block: Block,
    pub serving_peer: PeerId,
    pub result: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
}

impl BlockSyncEngine {
    /// Constructs a new engine. The caller must already have:
    ///   1. Subscribed to inbound block-sync requests via
    ///      `network.subscribe_block_sync_requests()`,
    ///   2. Subscribed to outbound results via
    ///      `network.subscribe_block_sync_results()`,
    ///   3. Subscribed to peer lifecycle events via
    ///      `network.subscribe_peer_events()`,
    ///   4. Set up an mpsc channel for importing blocks into the EventLoop.
    pub fn new(
        network: Arc<TenzroNetworkService>,
        storage: Arc<RocksDbStore>,
        consensus: Option<Arc<HotStuff2Engine>>,
        inbound_rx: mpsc::UnboundedReceiver<InboundBlockSync>,
        outbound_rx: mpsc::UnboundedReceiver<OutboundBlockSyncResult>,
        peer_events_rx: mpsc::UnboundedReceiver<PeerEvent>,
        block_importer: mpsc::Sender<BlockImport>,
    ) -> Self {
        Self {
            network,
            storage,
            consensus,
            inbound_rx,
            outbound_rx,
            peer_events_rx,
            block_importer,
            state: SyncState::Synced,
            peers: HashMap::new(),
            probe_tick: interval(TIP_PROBE_INTERVAL),
            hinted_until: None,
        }
    }

    /// Effective gap tolerance for engaging sync: zero while a behind-hint
    /// is active (consensus saw a proposal ahead of our tip), otherwise the
    /// steady-state `SLOT_IMPORT_TOLERANCE` that absorbs ordinary
    /// propagation jitter without flapping into sync mode.
    fn sync_tolerance(&self) -> u64 {
        match self.hinted_until {
            Some(t) if std::time::Instant::now() < t => 0,
            _ => SLOT_IMPORT_TOLERANCE,
        }
    }

    /// True iff a consensus behind-hint is currently engaged (we observed a
    /// quorum-advertised finalized height above our own). While behind, the
    /// peer-eligibility gate relaxes from the steady-state drop threshold to
    /// the hard-ban floor so catchup cannot be starved by degraded scores.
    fn is_behind_hinted(&self) -> bool {
        matches!(self.hinted_until, Some(t) if std::time::Instant::now() < t)
    }

    /// Effective score below which a peer is excluded from the sync candidate
    /// set. Steady state uses the drop threshold; while behind-hinted it
    /// relaxes to the hard-ban floor (see `PEER_SCORE_HARD_BAN_THRESHOLD`).
    fn peer_exclusion_threshold(&self) -> i32 {
        if self.is_behind_hinted() {
            PEER_SCORE_HARD_BAN_THRESHOLD
        } else {
            PEER_SCORE_DROP_THRESHOLD
        }
    }

    /// Drives the engine forever. Returns only on shutdown signal.
    pub async fn run(mut self, mut shutdown: tokio::sync::broadcast::Receiver<()>) {
        info!("Block-sync engine started");
        let mut behind_rx = self.consensus.as_ref().map(|c| c.subscribe_behind_hint());
        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    info!("Block-sync engine shutting down");
                    return;
                }
                changed = async { behind_rx.as_mut().unwrap().changed().await }, if behind_rx.is_some() => {
                    match changed {
                        Ok(()) => {
                            let hinted_height = *behind_rx.as_ref().unwrap().borrow();
                            self.hinted_until = Some(
                                std::time::Instant::now() + Duration::from_secs(60),
                            );
                            info!(
                                hinted_height,
                                "Behind-hint from consensus — engaging sync at zero tolerance"
                            );
                            if let Err(e) = self.on_probe_tick().await {
                                warn!(error = %e, "Block-sync hinted probe failed");
                            }
                        }
                        Err(_) => {
                            // Sender dropped (consensus gone) — stop polling.
                            behind_rx = None;
                        }
                    }
                }
                _ = self.probe_tick.tick() => {
                    if let Err(e) = self.on_probe_tick().await {
                        warn!(error = %e, "Block-sync probe tick failed");
                    }
                }
                Some(inbound) = self.inbound_rx.recv() => {
                    // Serve inbound requests on a detached task. Serving is a
                    // pure read (`Arc<RocksDbStore>` + `Arc<TenzroNetworkService>`,
                    // both clonable, `send_block_sync_response` takes `&self`),
                    // so it must NOT run inline: `handle_outbound` →
                    // `import_one` awaits a oneshot reply from the EventLoop,
                    // which holds `&mut self` and is busy applying consensus
                    // blocks. Inline, a single slow import head-of-line-blocks
                    // every parked inbound serve until libp2p's inbound
                    // substream times out (`InboundFailure: Timeout`), which
                    // drops the parked response channel — the requester then
                    // sees an EOF mid-decode and scores us down. Detaching the
                    // serve keeps the read path independent of import latency.
                    let network = self.network.clone();
                    let storage = self.storage.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::serve_inbound(network, storage, inbound).await {
                            warn!(error = %e, "Block-sync inbound handler failed");
                        }
                    });
                }
                Some(outbound) = self.outbound_rx.recv() => {
                    if let Err(e) = self.handle_outbound(outbound).await {
                        warn!(error = %e, "Block-sync outbound handler failed");
                    }
                }
                Some(peer_event) = self.peer_events_rx.recv() => {
                    self.handle_peer_event(peer_event);
                }
            }
        }
    }

    /// Apply a connection lifecycle delta to the candidate peer set.
    ///
    /// `Connected` inserts a default `PeerScore` (zero score, full
    /// in-flight capacity, no advertised tip) — the next probe tick will
    /// send this peer a `GetTipInfo`.
    ///
    /// `Disconnected` evicts the entry entirely. We do NOT attempt to
    /// preserve score across reconnects: the swarm-level `auto_unban`
    /// path already grants reconnecting peers a clean slate, and
    /// keeping stale `in_flight` `OutboundRequestId`s pinned to a peer
    /// that just dropped would leak request slots forever (the matching
    /// `OutboundFailure` is delivered by libp2p, but only if the request
    /// was outstanding at the moment of disconnect; race-condition
    /// requests submitted after the drop are silently lost).
    ///
    /// If the disconnected peer is the one we're actively syncing
    /// against, transition to `Stalled` so the next probe tick re-elects
    /// a fresh peer instead of waiting for a `GetBlockRange` response
    /// that will never arrive.
    fn handle_peer_event(&mut self, event: PeerEvent) {
        match event {
            PeerEvent::Connected(peer) => {
                self.note_peer(peer);
                debug!(
                    ?peer,
                    total = self.peers.len(),
                    "Block-sync: peer connected"
                );
            }
            PeerEvent::Disconnected(peer) => {
                self.peers.remove(&peer);
                if let SyncState::Syncing { peer: active, .. } = &self.state
                    && *active == peer
                {
                    warn!(
                        ?peer,
                        "Block-sync: active sync peer disconnected — stalling"
                    );
                    self.state = SyncState::Stalled;
                }
                debug!(
                    ?peer,
                    remaining = self.peers.len(),
                    "Block-sync: peer disconnected"
                );
            }
        }
    }

    /// Idle/Synced behavior: probe a sample of peers for their tip.
    ///
    /// This is also the recovery point from `Stalled` — if we previously
    /// failed a sync run, the next probe tick re-checks peers and may
    /// re-enter `Syncing`.
    async fn on_probe_tick(&mut self) -> Result<()> {
        // If actively syncing, don't probe — the active peer is already
        // streaming us blocks. But a sync run can hang past its deadline when
        // libp2p silently loses the request to a connection-drop race and never
        // delivers an `OutboundFailure` — without this watchdog the engine
        // early-returns here forever and deadlocks (the June 2026 192745 stall:
        // v0 latched `Syncing` against a peer on the old broken-serve image and
        // never re-probed, even after a fixed-serve peer rejoined). Force-drop
        // to `Stalled` so the rest of this tick re-elects a peer.
        if let SyncState::Syncing { peer, deadline, .. } = self.state {
            if std::time::Instant::now() < deadline {
                return Ok(());
            }
            warn!(
                ?peer,
                "Block-sync: sync run exceeded watchdog deadline with no response — stalling to re-elect"
            );
            self.state = SyncState::Stalled;
        }

        let our_height = self.local_tip().await?;

        // Heal an engine that has fallen behind local storage. Gossip imports
        // (`handle_network_block`) advance storage without touching the
        // engine, and `local_tip()` reads storage — so neither the behind-hint
        // nor tip probing ever sees a gap, while the engine keeps rejecting
        // every live proposal ("expected N, got N+700"). The June 2026 v1
        // stall. On a healthy validator the engine advances its height at
        // finalization *before* the event loop persists the block, so
        // `engine_next` is at least `tip + 1` and this is a no-op; height
        // only ever moves forward inside `resume_from_synced_height`.
        if let Some(consensus) = &self.consensus {
            let engine_next = consensus.current_height();
            if engine_next <= our_height && our_height.0 > 0 {
                let commit_qc_view = self.commit_qc_view_at(our_height).await.unwrap_or(0);
                consensus.resume_from_synced_height(our_height, commit_qc_view);
                info!(
                    engine_next = %engine_next,
                    our_height = %our_height,
                    commit_qc_view,
                    "Block-sync: engine behind local storage — resumed from stored tip"
                );
            }
        }

        // Heal the subscription race: connections established before this
        // engine spawned never produced a `PeerEvent::Connected`, so the
        // candidate set can be empty even though the swarm is fully
        // connected. Seed from the network's live connection snapshot —
        // subsequent lifecycle events keep it current.
        if self.peers.is_empty() {
            match self.network.connected_peers().await {
                Ok(connected) => {
                    for peer in connected {
                        self.note_peer(peer);
                    }
                    if !self.peers.is_empty() {
                        info!(
                            count = self.peers.len(),
                            "Block-sync: seeded peer set from live connections"
                        );
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Block-sync: connected-peers snapshot failed");
                }
            }
        }

        // Snapshot peer ids before issuing requests (we mutate self in the loop).
        let exclusion_threshold = self.peer_exclusion_threshold();
        let peer_ids: Vec<PeerId> = self.peers.keys().copied().collect();
        for peer in peer_ids {
            // Score-gate: don't probe peers we've already evicted. While
            // behind-hinted this relaxes to the hard-ban floor so catchup
            // is never starved by degraded steady-state scores.
            if self
                .peers
                .get(&peer)
                .map(|p| p.score < exclusion_threshold)
                .unwrap_or(false)
            {
                continue;
            }
            // Capacity-gate: skip probes against peers already at the
            // in-flight cap. They'll be re-probed on a future tick once
            // their outstanding requests have resolved. Lighthouse drops
            // probes the same way rather than queueing them.
            if !self.peer_has_capacity(&peer) {
                debug!(
                    ?peer,
                    "Block-sync: skipping tip probe, peer at in-flight cap"
                );
                continue;
            }
            match self.network.request_tip_info(peer).await {
                Ok(req_id) => {
                    self.reserve_inflight(peer, req_id);
                }
                Err(e) => {
                    warn!(?peer, error = %e, "Failed to send tip-info probe");
                }
            }
        }

        // If we have a peer whose tip is well ahead of us already known,
        // transition to syncing immediately rather than waiting for new probes.
        if let Some((peer, tip_height, tip_hash)) = self.best_peer_tip(our_height) {
            self.start_sync_against(peer, tip_height, tip_hash).await?;
        }

        Ok(())
    }

    /// Returns the best peer (highest tip) whose tip exceeds our local head
    /// by more than the effective tolerance (`sync_tolerance()` — zero
    /// while a behind-hint is active). Eligibility uses
    /// `peer_exclusion_threshold()`, which relaxes from the steady-state
    /// drop line to the hard-ban floor while behind so catchup is never
    /// starved by degraded scores. Returns `None` if we're synced.
    fn best_peer_tip(&self, our_height: BlockHeight) -> Option<(PeerId, BlockHeight, Hash)> {
        let tolerance = self.sync_tolerance();
        let exclusion_threshold = self.peer_exclusion_threshold();
        self.peers
            .iter()
            .filter_map(|(peer, score)| {
                peer_is_sync_eligible(
                    score.score,
                    score.advertised_tip,
                    our_height,
                    tolerance,
                    exclusion_threshold,
                )
                .map(|(tip_h, tip_hash)| (*peer, tip_h, tip_hash))
            })
            .max_by_key(|(_, h, _)| h.0)
    }

    /// Transitions to `Syncing` against `peer` with the given target.
    async fn start_sync_against(
        &mut self,
        peer: PeerId,
        target_height: BlockHeight,
        target_hash: Hash,
    ) -> Result<()> {
        let our_height = self.local_tip().await?;
        let next_start = BlockHeight(our_height.0 + 1);
        let count =
            (target_height.0.saturating_sub(our_height.0)).min(MAX_BLOCKS_PER_RANGE as u64) as u32;
        if count == 0 {
            self.state = SyncState::Synced;
            return Ok(());
        }

        // Cap-check the per-peer in-flight set BEFORE issuing the request.
        // We never queue: a saturated peer causes the engine to defer to
        // the next probe tick rather than holding state for it.
        if !self.peer_has_capacity(&peer) {
            warn!(
                ?peer,
                in_flight = self
                    .peers
                    .get(&peer)
                    .map(|p| p.in_flight.len())
                    .unwrap_or(0),
                cap = MAX_INFLIGHT_PER_PEER,
                "Block-sync: peer saturated, deferring sync start"
            );
            return Ok(());
        }

        info!(
            ?peer,
            our_height = %our_height,
            target_height = %target_height,
            count,
            "Block-sync: starting catch-up"
        );

        let req_id = self
            .network
            .request_blocks(peer, next_start, count)
            .await
            .map_err(|e| NodeError::Other(format!("request_blocks failed: {}", e)))?;
        self.reserve_inflight(peer, req_id);

        self.state = SyncState::Syncing {
            target_height,
            target_hash,
            peer,
            in_flight: Some(req_id),
            deadline: std::time::Instant::now() + RANGE_REQUEST_TIMEOUT,
        };
        Ok(())
    }

    /// Inbound (server role): peer asked us for blocks.
    ///
    /// Associated function (not `&self`) so it can run on a detached task,
    /// keeping serve latency independent of the outbound import path. Takes
    /// clones of the two `Arc`s it needs.
    async fn serve_inbound(
        network: Arc<TenzroNetworkService>,
        storage: Arc<RocksDbStore>,
        inbound: InboundBlockSync,
    ) -> Result<()> {
        let response = Self::serve_request(&storage, &inbound.request).await;
        // Always answer — silent drops cause the requester to time out and
        // score us down (Lighthouse SyncManager contract).
        if let Err(e) = network
            .send_block_sync_response(inbound.request_id, response)
            .await
        {
            warn!(
                peer = ?inbound.peer,
                request_id = ?inbound.request_id,
                error = %e,
                "Failed to send block-sync response (peer may have disconnected)"
            );
        }
        Ok(())
    }

    async fn serve_request(
        storage: &Arc<RocksDbStore>,
        req: &BlockSyncRequest,
    ) -> BlockSyncResponse {
        let block_store = match BlockStoreImpl::new(storage.clone()) {
            Ok(s) => s,
            Err(e) => {
                return BlockSyncResponse::Error(BlockSyncError::Storage(format!(
                    "open block store: {}",
                    e
                )));
            }
        };

        match req {
            BlockSyncRequest::GetTipInfo => {
                let latest = match block_store.latest_block().await {
                    Ok(Some(b)) => b,
                    Ok(None) => {
                        // Genesis only — report height 0 with the zero hash
                        // (peer should treat us as a non-useful sync source).
                        return BlockSyncResponse::TipInfo {
                            tip_height: BlockHeight(0),
                            tip_hash: Hash::default(),
                            lowest_available: BlockHeight(0),
                        };
                    }
                    Err(e) => {
                        return BlockSyncResponse::Error(BlockSyncError::Storage(format!(
                            "latest_block: {}",
                            e
                        )));
                    }
                };
                BlockSyncResponse::TipInfo {
                    tip_height: latest.height(),
                    tip_hash: latest.hash(),
                    // We are an archive node — every height since genesis is
                    // available. Pruning nodes will report a non-zero value
                    // when pruning is implemented.
                    lowest_available: BlockHeight(0),
                }
            }
            BlockSyncRequest::GetBlockRange { start, count } => {
                if *count == 0 || *count > MAX_BLOCKS_PER_RANGE {
                    return BlockSyncResponse::Error(BlockSyncError::RangeTooLarge {
                        got: *count,
                        max: MAX_BLOCKS_PER_RANGE,
                    });
                }
                let end = BlockHeight(start.0.saturating_add(*count as u64).saturating_sub(1));
                match block_store.blocks_by_height_range(*start, end).await {
                    Ok(blocks) => BlockSyncResponse::BlockRange { blocks },
                    Err(e) => BlockSyncResponse::Error(BlockSyncError::Storage(format!(
                        "blocks_by_height_range: {}",
                        e
                    ))),
                }
            }
            BlockSyncRequest::GetBlockByHash { hash } => match block_store.get_block(hash).await {
                Ok(block) => BlockSyncResponse::BlockByHash { block },
                Err(e) => {
                    BlockSyncResponse::Error(BlockSyncError::Storage(format!("get_block: {}", e)))
                }
            },
        }
    }

    /// Outbound (client role): a previous request we issued has resolved.
    async fn handle_outbound(&mut self, result: OutboundBlockSyncResult) -> Result<()> {
        let OutboundBlockSyncResult {
            peer,
            request_id,
            result,
        } = result;

        // Always release the in-flight slot first — whether the result was
        // a transport error, a remote-side error, or a success, the request
        // is no longer outstanding.
        self.release_inflight(&peer, &request_id);

        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                self.score_peer(&peer, PEER_SCORE_PENALTY);
                warn!(?peer, ?request_id, error = %e, "Block-sync transport error");
                self.handle_outbound_failure(peer, request_id);
                return Ok(());
            }
        };

        // A transport-level success heals the peer's reputation (a remote-side
        // `Error` payload is penalised below, not here). This is the only path
        // by which a score climbs back up after transient failures.
        if !matches!(response, BlockSyncResponse::Error(_)) {
            self.score_peer(&peer, PEER_SCORE_SUCCESS);
        }

        match response {
            BlockSyncResponse::TipInfo {
                tip_height,
                tip_hash,
                ..
            } => {
                self.peers.entry(peer).or_default().advertised_tip = Some((tip_height, tip_hash));

                let our_height = self.local_tip().await?;
                if matches!(self.state, SyncState::Synced | SyncState::Stalled)
                    && tip_height.0 > our_height.0 + self.sync_tolerance()
                {
                    self.start_sync_against(peer, tip_height, tip_hash).await?;
                }
            }
            BlockSyncResponse::BlockRange { blocks } => {
                self.handle_block_range(peer, request_id, blocks).await?;
            }
            BlockSyncResponse::BlockByHash { block } => {
                if let Some(b) = block {
                    self.import_one(b, peer).await?;
                }
            }
            BlockSyncResponse::Error(err) => {
                self.score_peer(&peer, PEER_SCORE_PENALTY);
                warn!(?peer, ?request_id, ?err, "Block-sync remote error");
                self.handle_outbound_failure(peer, request_id);
            }
        }
        Ok(())
    }

    /// Track a peer's PeerId. Called from `handle_peer_event` when the
    /// network surfaces `PeerEvent::Connected`.
    fn note_peer(&mut self, peer: PeerId) {
        self.peers.entry(peer).or_default();
    }

    fn score_peer(&mut self, peer: &PeerId, delta: i32) {
        let entry = self.peers.entry(*peer).or_default();
        // Clamp into [PEER_SCORE_HARD_BAN_THRESHOLD, PEER_SCORE_CEILING]. The
        // floor is what makes recovery possible: without it, a peer that merely
        // times out repeatedly (e.g. the only node serving the one block we
        // need, while it is itself slow under load) sinks arbitrarily far
        // below the hard-ban floor. The behind-hint eligibility gate
        // (`peer_exclusion_threshold`) relaxes to exactly this floor, so a
        // peer parked *below* it is excluded even while we are stranded —
        // catch-up then latches off permanently and the chain halts. Flooring
        // at the hard-ban line keeps transport-timeout peers eligible during
        // behind-hinted catch-up indefinitely, which is the intended
        // behavior: keep retrying the only candidate until it serves the block.
        entry.score = entry
            .score
            .saturating_add(delta)
            .clamp(PEER_SCORE_HARD_BAN_THRESHOLD, PEER_SCORE_CEILING);
        if entry.score < PEER_SCORE_DROP_THRESHOLD {
            warn!(
                ?peer,
                score = entry.score,
                "Block-sync: dropping peer below threshold"
            );
        }
    }

    /// True iff this peer currently has spare in-flight capacity. Unknown
    /// peers (never previously contacted) implicitly have full capacity.
    fn peer_has_capacity(&self, peer: &PeerId) -> bool {
        self.peers
            .get(peer)
            .map(|p| p.has_capacity())
            .unwrap_or(true)
    }

    /// Records a newly-issued outbound request against a peer. Inserts a
    /// default `PeerScore` entry if this peer was previously unknown.
    fn reserve_inflight(&mut self, peer: PeerId, request_id: OutboundRequestId) {
        self.peers
            .entry(peer)
            .or_default()
            .in_flight
            .insert(request_id);
    }

    /// Removes a previously-reserved in-flight request. Idempotent — if the
    /// entry is missing (e.g. duplicate result delivery), the call is a noop.
    fn release_inflight(&mut self, peer: &PeerId, request_id: &OutboundRequestId) {
        if let Some(entry) = self.peers.get_mut(peer) {
            entry.in_flight.remove(request_id);
        }
    }

    fn handle_outbound_failure(&mut self, peer: PeerId, _request_id: OutboundRequestId) {
        // If the failed request was the active sync request, mark stalled so
        // the next probe tick can pick a different peer.
        if let SyncState::Syncing {
            peer: active_peer, ..
        } = &self.state
            && *active_peer == peer
        {
            self.state = SyncState::Stalled;
        }
    }

    async fn handle_block_range(
        &mut self,
        peer: PeerId,
        request_id: OutboundRequestId,
        blocks: Vec<Block>,
    ) -> Result<()> {
        // Empty range is treated as the peer running out of blocks at our tip
        // — return to Synced. Not necessarily a fault.
        if blocks.is_empty() {
            debug!(
                ?peer,
                ?request_id,
                "Block-sync: empty range, ending sync run"
            );
            self.finish_sync().await?;
            return Ok(());
        }

        for block in blocks {
            if let Err(e) = self.import_one(block, peer).await {
                warn!(?peer, error = %e, "Block-sync import failed; scoring peer down");
                self.score_peer(&peer, PEER_SCORE_PENALTY);
                self.state = SyncState::Stalled;
                return Ok(());
            }
        }

        // After import, decide whether to continue.
        let our_height = self.local_tip().await?;
        let SyncState::Syncing {
            target_height,
            target_hash,
            ..
        } = self.state.clone()
        else {
            return Ok(());
        };

        if our_height.0 >= target_height.0 {
            self.finish_sync().await?;
        } else {
            // Issue the next range request against the same peer. The
            // previous request_id was already cleared from the in-flight
            // set in `handle_outbound` (success path); we re-check
            // capacity here in case a parallel probe is using the slot.
            if !self.peer_has_capacity(&peer) {
                debug!(
                    ?peer,
                    "Block-sync: peer at cap, deferring continuation \
                     to next probe tick"
                );
                self.state = SyncState::Stalled;
                return Ok(());
            }
            let next_start = BlockHeight(our_height.0 + 1);
            let count = (target_height.0.saturating_sub(our_height.0))
                .min(MAX_BLOCKS_PER_RANGE as u64) as u32;
            let req_id = self
                .network
                .request_blocks(peer, next_start, count)
                .await
                .map_err(|e| NodeError::Other(format!("request_blocks failed: {}", e)))?;
            self.reserve_inflight(peer, req_id);
            self.state = SyncState::Syncing {
                target_height,
                target_hash,
                peer,
                in_flight: Some(req_id),
                deadline: std::time::Instant::now() + RANGE_REQUEST_TIMEOUT,
            };
        }
        Ok(())
    }

    /// Import a single block via the EventLoop's `handle_block_imported_from_sync`.
    /// Returns `Err` if the import fails (QC verification failure, storage
    /// error, etc.) so the caller can score the peer.
    async fn import_one(&mut self, block: Block, serving_peer: PeerId) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.block_importer
            .send(BlockImport {
                block,
                serving_peer,
                result: tx,
            })
            .await
            .map_err(|_| NodeError::Other("block importer channel closed".to_string()))?;
        rx.await
            .map_err(|_| NodeError::Other("block importer reply channel closed".to_string()))?
            .map_err(NodeError::Other)
    }

    /// Sync run completed. Tell consensus to advance past whatever stale view
    /// it was sitting at, then return to `Synced`.
    async fn finish_sync(&mut self) -> Result<()> {
        let our_height = self.local_tip().await?;
        if let Some(consensus) = &self.consensus {
            // Pull the commit-QC view from the block we just finalized to
            // pass into resume_from_synced_height. If we cannot extract a QC
            // (genesis, missing proof_data), pass 0 — the engine treats that
            // as a no-op for view advancement and only updates height.
            let commit_qc_view = self.commit_qc_view_at(our_height).await.unwrap_or(0);
            consensus.resume_from_synced_height(our_height, commit_qc_view);
            info!(
                our_height = %our_height,
                commit_qc_view,
                "Block-sync: caught up, resuming consensus"
            );
        }
        self.state = SyncState::Synced;
        self.hinted_until = None;
        Ok(())
    }

    /// Read the embedded commit-QC view from the block at `height`. Returns
    /// `None` for genesis or pre-QC-embed blocks.
    async fn commit_qc_view_at(&self, height: BlockHeight) -> Option<u64> {
        let block_store = BlockStoreImpl::new(self.storage.clone()).ok()?;
        let block = block_store.get_block_by_height(height).await.ok()??;
        QuorumCertificate::extract_from_block(&block).map(|qc| qc.view)
    }

    /// Local chain tip from storage. `BlockHeight(0)` if the store is empty
    /// (pre-genesis).
    async fn local_tip(&self) -> Result<BlockHeight> {
        let block_store = BlockStoreImpl::new(self.storage.clone())
            .map_err(|e| NodeError::Other(format!("open block store: {}", e)))?;
        Ok(block_store
            .latest_height()
            .await
            .map_err(|e| NodeError::Other(format!("latest_height: {}", e)))?
            .unwrap_or(BlockHeight(0)))
    }
}

/// Map an [`InboundRequestId`] for trait-object-style consumers — kept here
/// rather than in `tenzro-network` because the engine's own consumers know
/// what kind of request id type to expect.
pub type ServerRequestId = InboundRequestId;

#[cfg(test)]
mod tests {
    use super::*;

    fn tip(h: u64) -> Option<(BlockHeight, Hash)> {
        Some((BlockHeight(h), Hash::default()))
    }

    /// A peer one block ahead is eligible when behind-hinted (tolerance 0)
    /// even with a score below the steady-state drop line, because the
    /// exclusion threshold relaxes to the hard-ban floor.
    #[test]
    fn behind_hinted_peer_below_drop_line_is_eligible() {
        // score -60: below the -50 drop line, above the -500 hard-ban floor.
        let r = peer_is_sync_eligible(
            -60,
            tip(192_745),
            BlockHeight(192_744),
            0, // behind-hinted tolerance
            PEER_SCORE_HARD_BAN_THRESHOLD,
        );
        assert_eq!(r, Some((BlockHeight(192_745), Hash::default())));
    }

    /// The same peer is NOT eligible in steady state: the drop-line threshold
    /// excludes it. This is the deadlock the relaxed threshold breaks — under
    /// the old single-threshold gate, a node one block behind could never
    /// catch up because the only peers serving the missing block had degraded
    /// scores.
    #[test]
    fn same_peer_excluded_at_steady_state_drop_line() {
        let r = peer_is_sync_eligible(
            -60,
            tip(192_745),
            BlockHeight(192_744),
            SLOT_IMPORT_TOLERANCE, // steady-state tolerance
            PEER_SCORE_DROP_THRESHOLD,
        );
        assert_eq!(r, None);
    }

    /// A hard-banned peer (below the floor) is excluded even while behind.
    #[test]
    fn hard_banned_peer_excluded_even_when_behind() {
        let r = peer_is_sync_eligible(
            -600,
            tip(192_745),
            BlockHeight(192_744),
            0,
            PEER_SCORE_HARD_BAN_THRESHOLD,
        );
        assert_eq!(r, None);
    }

    /// A peer at or above our head (no gap beyond tolerance) is not a sync
    /// target regardless of score.
    #[test]
    fn peer_at_our_head_is_not_a_sync_target() {
        let r = peer_is_sync_eligible(
            0,
            tip(192_744),
            BlockHeight(192_744),
            0,
            PEER_SCORE_HARD_BAN_THRESHOLD,
        );
        assert_eq!(r, None);
    }

    /// A peer that has never advertised a tip is not eligible.
    #[test]
    fn peer_without_advertised_tip_is_not_eligible() {
        let r = peer_is_sync_eligible(
            100,
            None,
            BlockHeight(192_744),
            0,
            PEER_SCORE_HARD_BAN_THRESHOLD,
        );
        assert_eq!(r, None);
    }

    /// Steady-state tolerance suppresses single-block flapping: a peer one
    /// block ahead is not a sync target until the gap exceeds the tolerance.
    #[test]
    fn single_block_gap_within_steady_tolerance_is_ignored() {
        const { assert!(SLOT_IMPORT_TOLERANCE >= 1) };
        let r = peer_is_sync_eligible(
            0,
            tip(192_745),
            BlockHeight(192_744),
            SLOT_IMPORT_TOLERANCE,
            PEER_SCORE_DROP_THRESHOLD,
        );
        assert_eq!(r, None);
    }
}
