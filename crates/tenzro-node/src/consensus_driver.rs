//! The node's consensus.
//!
//! [`ConsensusHandle`] is what the rest of the node talks to: it owns the
//! mempool, reports ordered and certified finality, and verifies the
//! checkpoint certificates a follower imports blocks under.
//!
//! On a validator it also runs the protocol core ([`tenzro_consensus::Core`]):
//!
//! - it keeps one authenticated channel to every other committee member over
//!   the node's iroh endpoint (`tenzro/consensus`), the lower index dialling
//!   (the higher one too when no channel comes up, so a validator behind NAT
//!   with outbound connections only reaches every peer) the endpoint the peer
//!   sealed to it under the commitment its consensus key signed; a
//!   validator's endpoint is told only to committee members;
//! - every batch interval it cuts the transactions assigned to it from the
//!   mempool into a batch;
//! - it hands every ordered segment to the event loop, which builds and
//!   executes the block and reports the block hash and state root back;
//! - it signs every checkpoint with the validator's hardware key, after
//!   persisting that it is about to;
//! - it stores and publishes certificates, and starts the next epoch's core
//!   when the handover certificate forms.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tenzro_consensus::announce::{
    DisclosureSecret, EndpointAnnouncement, EndpointBook, EndpointOpening, PublishedAnnouncement,
    SealedEndpoint,
};
use tenzro_consensus::batch::{BatchPart, BatchPayload, MAX_PART_BYTES, assigned_validator};
use tenzro_consensus::channel::{
    AwaitingAccept, Challenge, ChannelContext, Hello, Initiator, Opener, Responder, Sealer,
    StreamKind, TranscriptSignature,
};
use tenzro_consensus::checkpoint::{
    Certificate, CertificateContext, Checkpoint, CheckpointEquivocation, CheckpointVote,
    FULL_BUNDLE_EVERY, PublishedCertificate,
};
use tenzro_consensus::compact::{CompactCertificate, ProofSetups, is_compacted, prove_after_ms};
use tenzro_consensus::compact_work::CompactWork;
use tenzro_consensus::mempool::Pick;
use tenzro_consensus::session::{SessionBook, SessionCertificate, SessionKey};
use tenzro_consensus::{
    Committee, ConsensusConfig, Core, EpochManager, EpochStart, Event, Frame, Mempool, Message,
    Record, Segment, Target, TimeRules, ValidatorIndex, ValidatorSet, ValidatorSigner,
    VoteHighWater, sign_checkpoint,
};
use tenzro_storage::KvStore;
use tenzro_types::primitives::{Address, Hash};
use tenzro_types::transaction::SignedTransaction;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::error::{NodeError, Result};

/// Largest encoded consensus frame accepted from a peer.
const MAX_WIRE_FRAME: usize = tenzro_consensus::wire::MAX_FRAME_BYTES + 64;
/// Frames queued to one peer before new ones are dropped; the core recovers
/// anything dropped by fetching it or through the peer's frontier.
const PEER_QUEUE: usize = 8_192;
/// Bytes queued to one peer before new frames are dropped, whatever their
/// number: a peer that stops reading holds at most this much here.
const PEER_QUEUE_BYTES: usize = 64 << 20;
/// Bytes received from one peer and not yet handled by the core. The channel
/// stops reading at this point, so a peer sending faster than the core
/// handles is held back by the transport's flow control instead of growing
/// this node's memory.
const PEER_INBOUND_BYTES: u32 = 64 << 20;
/// Channels one peer may hold open at once in an epoch, both directions
/// together: a dialled one and an answered one, and a reconnect while an old
/// one is still timing out. All of them share the peer's inbound budget.
const MAX_CHANNELS_PER_PEER: usize = 4;
/// How long the answering side of a handshake waits for the dialler to
/// finish it before it drops the stream.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Multiple of a connection's measured rtt the application handshake is
/// given, once the QUIC connection is up: generous enough that one lost
/// packet's PTO backoff does not throw the whole attempt away.
const HANDSHAKE_RTT_FACTOR: u32 = 16;
/// Longest a handshake retry's rtt-scaled budget is allowed to grow to,
/// across repeated timeouts on the same peer.
const HANDSHAKE_RETRY_CAP: Duration = Duration::from_secs(60);
/// How long a dial waits for the connection and its stream to open, before
/// the application handshake even starts. Separate from HANDSHAKE_TIMEOUT:
/// under loss on a relayed path, opening the connection is the slow part --
/// a lost Initial or Handshake datagram backs off exponentially from noq's
/// 333ms initial_rtt, and the ClientHello's post-quantum key share spans
/// two datagrams, doubling the chance one is lost -- while the application
/// handshake itself, once connected, is a fixed 3-message exchange that
/// stays fast. One combined 10s budget for both made the connect step the
/// one likely to run out, which left the lower-index validator's own dial
/// still in flight past ANSWER_GRACE and the higher-index side dialling
/// too, creating the duplicate channels `OpenPeer`'s doc comment describes
///.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// The frames queued to one peer's channel, bounded in number and in bytes.
#[derive(Clone)]
struct PeerQueue {
    tx: mpsc::Sender<Vec<u8>>,
    queued: Arc<AtomicUsize>,
}

impl PeerQueue {
    fn new() -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(PEER_QUEUE);
        (
            Self {
                tx,
                queued: Arc::new(AtomicUsize::new(0)),
            },
            rx,
        )
    }

    /// Queues `frame`; false when the queue is full and it was dropped.
    fn try_send(&self, frame: Vec<u8>) -> bool {
        let len = frame.len();
        if self.queued.fetch_add(len, Ordering::AcqRel) + len > PEER_QUEUE_BYTES
            || self.tx.try_send(frame).is_err()
        {
            self.queued.fetch_sub(len, Ordering::AcqRel);
            return false;
        }
        true
    }

    /// Bytes the queue can still take.
    fn room(&self) -> usize {
        PEER_QUEUE_BYTES.saturating_sub(self.queued.load(Ordering::Acquire))
    }

    /// Records that a queued frame of `len` bytes left the queue.
    fn sent(&self, len: usize) {
        self.queued.fetch_sub(len, Ordering::AcqRel);
    }

    fn same_channel(&self, other: &Self) -> bool {
        self.tx.same_channel(&other.tx)
    }
}
/// The least time a transaction waits for its assigned validator before any
/// validator batches it; the wait grows with the measured ordering latency.
const ASSIGNMENT_GRACE: Duration = Duration::from_secs(3);
/// Consensus timer resolution.
const TICK: Duration = Duration::from_millis(10);

static DIAG_BEAT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static DIAG_PHASE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static DIAG_WATCH: std::sync::Once = std::sync::Once::new();

fn diag_phase(p: u64) {
    DIAG_PHASE.store(p, Ordering::Release);
    DIAG_BEAT.store(unix_ms(), Ordering::Release);
}

/// One engine's loop position and when it last moved, so a stalled engine
/// is named even while other engines in the same process keep looping.
#[derive(Default)]
struct EngineBeat {
    phase: AtomicU64,
    at_ms: AtomicU64,
}

impl EngineBeat {
    fn mark(&self, p: u64) {
        diag_phase(p);
        self.phase.store(p, Ordering::Release);
        self.at_ms.store(unix_ms(), Ordering::Release);
    }
}

/// Most heights a validator's ordering runs ahead of its own execution
/// before its core holds its frontier (see `Core::hold_frontier`). A commit
/// that releases more blocks at once holds the frontier only until they
/// execute.
const MAX_UNEXECUTED_HEIGHTS: u64 = 32;

/// How long a core waits for the ordering state of the checkpoint it
/// fast-forwards to before it moves on to a later certified checkpoint.
const FAST_FORWARD_RETRY: Duration = Duration::from_secs(2);

/// How often a validator republishes its endpoint announcement, so a peer
/// that joined or restarted since learns it. Republishing reuses the signed
/// announcement until it is due for renewal.
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);

/// Executed blocks the handle keeps: as many as an epoch start's base.
const EXECUTED_TAIL: usize = tenzro_consensus::STATE_ROOT_LAG as usize + 1;

/// Every this many announcements the sealed endpoints are republished even
/// when no member's disclosure key changed; otherwise they go out only when
/// one did.
const RESEAL_EVERY: u32 = 4;

/// Periodic announcements after a change that carry the sealed set again.
/// The set goes out at once when it changes, but that publication can reach
/// a peer before its gossip mesh to this validator has formed (a peer that
/// just restarted); without a repeat that peer would wait for the next
/// [`RESEAL_EVERY`] announcement to learn the endpoint sealed to it.
const RESEAL_REPEATS: u32 = 3;

/// First wait before the sealed set is published again after it changed;
/// doubled for each later repeat. A peer whose gossip mesh to this validator
/// forms moments after the first publication gets the set within seconds,
/// not at the next [`ANNOUNCE_INTERVAL`].
const RESEAL_RETRY: Duration = Duration::from_secs(3);

/// Quick repeats after a change: 3 s, 6 s, 12 s, 24 s.
const RESEAL_QUICK_REPEATS: u32 = 4;

/// What woke the announcer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wake {
    Tick,
    Kick,
    Retry,
}

/// Whether an announcement carries the sealed endpoints. `repeats` counts the
/// periodic announcements still owed after the last change; a wake-up
/// (`kicked`) neither spends nor sets one beyond what its change sets.
fn sealed_due(changed: bool, kicked: bool, since_sealed: u32, repeats: &mut u32) -> bool {
    if changed {
        *repeats = RESEAL_REPEATS;
        return true;
    }
    if !kicked && *repeats > 0 {
        *repeats -= 1;
        return true;
    }
    since_sealed >= RESEAL_EVERY
}

/// How long the higher index of a pair waits for the lower one to dial
/// before dialling itself.
const ANSWER_GRACE: Duration = Duration::from_secs(3);

/// Longest wait between two dials of a peer whose channel is down. At a
/// handover each validator enters the new epoch when it sees the handover
/// certificate, so a dial often reaches a peer still in the old epoch and is
/// refused; the channel must come up soon after the peer enters, because
/// the new committee's rounds need channels between every pair of a quorum
/// to deliver their broadcasts.
const DIAL_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// How long a channel of an epoch this node has left keeps writing before it
/// closes.
const EPOCH_CHANNEL_DRAIN: Duration = Duration::from_secs(2);

/// Longest a channel may carry nothing from its peer before it is closed and
/// dialled again. Each side writes at least every [`CHANNEL_KEEPALIVE`],
/// whatever its core sends, so a channel this quiet has failed in at least
/// one direction: the peer's frames no longer arrive though this side's
/// still leave, or the reverse. Every round the core cannot run while it
/// lasts is lost, so it is found within a few rounds, not an idle round's
/// multiple.
const CHANNEL_SILENCE: Duration = Duration::from_secs(10);
/// Multiple of a connection's measured rtt a channel's read side is given
/// before it is called silent: smaller than [`HANDSHAKE_RTT_FACTOR`] since
/// an established channel's reads are not also paying for a fresh QUIC
/// connect.
const SILENCE_RTT_FACTOR: u32 = 12;

/// How long a channel's send side stays idle before it writes an empty
/// frame, so its peer can tell a quiet channel from a broken one.
const CHANNEL_KEEPALIVE: Duration = Duration::from_secs(1);

/// Longest one write may wait for the peer to take it. A large frame on a
/// slow link takes time; a peer that takes nothing for this long has stopped
/// reading.
const CHANNEL_WRITE_STALL: Duration = Duration::from_secs(30);

/// Longest a channel's reader waits for the core to free its share of the
/// peer's inbound budget before this frame's turn, once the frame itself
/// has already arrived off the wire. Every other wait in this channel's
/// loop is bounded -- [`CHANNEL_SILENCE`] on a read, [`CHANNEL_WRITE_STALL`]
/// on a write, `HANDSHAKE_TIMEOUT` on the handshake -- so a core that falls
/// behind and never frees this peer's share must not be allowed to hang
/// this reader, and the channel it holds, forever: tearing the channel
/// down here frees its (epoch, peer) budget entry for the next one, and
/// gets it dialled again rather than left stuck (seen holding the whole
/// committee at `round-weight-below-quorum` for minutes, well after a
/// chaos run's last induced packet loss had ended: chaos seed
/// 3054677367, runs 20261020T1503Z and 20261020T1947Z).
const INBOUND_BUDGET_STALL: Duration = Duration::from_secs(30);

/// Longest the engine trusts a peer the dialler reports as connected
/// (`EpochChannels::is_open`) while it has no sender for that peer in
/// `Engine.peers` to route through. The duplicate-channel fix
/// (`ChannelLease::retire`, `run_channel`'s teardown) closes this gap at
/// its source, but this is the backstop for any similar disagreement
/// between the dialler's and the engine's own view that nothing else
/// catches: past this long, the route is force-closed and left to redial
/// fresh rather than trusted a moment longer (Mysticeti's subscriber uses the same
/// progress-based pattern, reconnecting when no block arrives within its
/// own 30s SUBSCRIPTION_TIMEOUT).
const PEER_ROUTE_STALL: Duration = Duration::from_secs(30);

/// Why a channel's send side stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendEnd {
    /// The queue closed: the channel is shutting down.
    Closed,
    /// A frame could not be sealed.
    SealFailed,
    /// A write failed.
    Failed,
    /// A write was not taken by the peer within [`CHANNEL_WRITE_STALL`]: the
    /// channel failed in this direction while frames may still arrive in
    /// the other, which the receive side alone would never notice.
    Stalled,
}

impl std::fmt::Display for SendEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => f.write_str("closed"),
            Self::SealFailed => f.write_str("could not seal a frame"),
            Self::Failed => f.write_str("failed"),
            Self::Stalled => write!(
                f,
                "stalled: the peer took nothing for {}s",
                CHANNEL_WRITE_STALL.as_secs()
            ),
        }
    }
}

/// Where a channel's sealed frames go.
trait FrameSink: Send {
    /// Writes one frame; false when the write failed.
    fn write(&mut self, frame: Vec<u8>) -> impl Future<Output = bool> + Send;
}

impl FrameSink for tenzro_iroh::SendStream {
    async fn write(&mut self, frame: Vec<u8>) -> bool {
        tenzro_iroh::write_frame(self, &frame).await.is_ok()
    }
}

/// Writes the frames queued for one peer until the queue closes or the send
/// side fails. Each write must complete within [`CHANNEL_WRITE_STALL`]. With
/// `keepalive`, that frame is written whenever nothing was queued for
/// [`CHANNEL_KEEPALIVE`].
async fn write_queued(
    rx: &mut mpsc::Receiver<Vec<u8>>,
    queue: &PeerQueue,
    mut seal: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    sink: &mut impl FrameSink,
    keepalive: Option<&[u8]>,
) -> SendEnd {
    loop {
        let (frame, queued) = match keepalive {
            Some(k) => match tokio::time::timeout(CHANNEL_KEEPALIVE, rx.recv()).await {
                Ok(Some(f)) => (f, true),
                Ok(None) => return SendEnd::Closed,
                Err(_) => (k.to_vec(), false),
            },
            None => match rx.recv().await {
                Some(f) => (f, true),
                None => return SendEnd::Closed,
            },
        };
        if queued {
            queue.sent(frame.len());
        }
        let Some(sealed) = seal(&frame) else {
            return SendEnd::SealFailed;
        };
        match tokio::time::timeout(CHANNEL_WRITE_STALL, sink.write(sealed)).await {
            Ok(true) => {}
            Ok(false) => return SendEnd::Failed,
            Err(_) => return SendEnd::Stalled,
        }
    }
}

/// The session key and the hardware key that certifies it, per epoch.
struct Certifier {
    hardware: Arc<dyn ValidatorSigner>,
    session: Arc<SessionKey>,
    cache: Arc<parking_lot::Mutex<Option<SessionCertificate>>>,
    chain_id: u64,
    genesis_hash: [u8; 32],
}

impl Certifier {
    /// The session key's certificate for `epoch`, signing it with the
    /// hardware key the first time. Blocks for that signature; callers run
    /// on a blocking thread. Concurrent callers wait for one signature.
    fn certificate(&self, epoch: u64) -> tenzro_consensus::Result<SessionCertificate> {
        let mut held = self.cache.lock();
        if let Some(c) = held.as_ref()
            && c.epoch == epoch
        {
            return Ok(c.clone());
        }
        let c = tenzro_consensus::session::sign_certificate(
            &*self.hardware,
            self.chain_id,
            self.genesis_hash,
            epoch,
            ValidatorSigner::public_key(&*self.session).clone(),
        )?;
        *held = Some(c.clone());
        Ok(c)
    }
}

/// Wall-clock Unix milliseconds.
fn unix_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}
/// Every how many checkpoints a full certificate is kept on disk (checkpoint
/// bodies are kept for all).
const CERTIFICATE_RETENTION_STRIDE: u64 = 20;
/// Rounds ahead [`ConsensusHandle::leads_soon`] looks.
pub const LEADERSHIP_HORIZON: u64 = 32;

const CF: &str = tenzro_storage::CF_BLOCKS;
const LATEST_CERTIFICATE_KEY: &[u8] = b"consensus/certificate/latest";
const LATEST_COMPACT_KEY: &[u8] = b"consensus/compact/latest";
/// Bytes of a bincode `Vec` length prefix.
const VEC_PREFIX_BYTES: usize = 8;

/// The transactions of a batch, part by part. A malformed body contributes
/// nothing, and a malformed part is skipped; every node decodes the same
/// bytes the same way, so every node skips the same.
fn batch_transactions(p: &BatchPayload) -> Vec<SignedTransaction> {
    p.parts()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|part| bincode::deserialize::<Vec<SignedTransaction>>(part).ok())
        .flatten()
        .collect()
}

fn body_key(index: u64) -> Vec<u8> {
    let mut k = b"consensus/checkpoint/".to_vec();
    k.extend_from_slice(&index.to_be_bytes());
    k
}

fn boundary_key(epoch: u64) -> Vec<u8> {
    let mut k = b"consensus/boundary/".to_vec();
    k.extend_from_slice(&epoch.to_be_bytes());
    k
}

/// The epoch this validator's core runs in and where it started.
const ACTIVE_KEY: &[u8] = b"consensus/active";

fn journal_prefix(epoch: u64) -> Vec<u8> {
    let mut k = b"consensus/journal/".to_vec();
    k.extend_from_slice(&epoch.to_be_bytes());
    k
}

fn journal_key(epoch: u64, seq: u64) -> Vec<u8> {
    let mut k = journal_prefix(epoch);
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

fn session_prefix(epoch: u64) -> Vec<u8> {
    let mut k = b"consensus/session/".to_vec();
    k.extend_from_slice(&epoch.to_be_bytes());
    k
}

fn session_key(epoch: u64, digest: &[u8; 32]) -> Vec<u8> {
    let mut k = session_prefix(epoch);
    k.extend_from_slice(digest);
    k
}

fn compact_key(index: u64) -> Vec<u8> {
    let mut k = b"consensus/compact/".to_vec();
    k.extend_from_slice(&index.to_be_bytes());
    k
}

fn certificate_key(index: u64) -> Vec<u8> {
    let mut k = b"consensus/certificate/".to_vec();
    k.extend_from_slice(&index.to_be_bytes());
    k
}

/// One ordered segment, ready to be built into a block.
#[derive(Debug, Clone)]
pub struct OrderedSegment {
    /// Block height.
    pub height: u64,
    /// Consensus epoch.
    pub epoch: u64,
    /// Round of the committed leader vertex.
    pub round: u64,
    /// Digest of the committed leader vertex.
    pub anchor: Hash,
    /// Address of the leader vertex's author.
    pub proposer: Address,
    /// Block timestamp, milliseconds.
    pub timestamp_ms: u64,
    /// Transactions in execution order, each once.
    pub transactions: Vec<SignedTransaction>,
}

/// Stages the validator registry's changes into the epoch manager, right
/// before the next committee is derived.
pub trait EpochPlanner: Send + Sync {
    /// Queues the next epoch's entrants and exits, and returns the token that
    /// names what it changed. Staging starts from the registry as it stood
    /// before the boundary, so staging again gives the same result as staging
    /// once. An error means the registry was left unchanged and no committee
    /// is derived.
    fn stage_next_epoch(&self) -> std::result::Result<String, String>;

    /// Undoes what the staging named by `token` changed, after a derivation
    /// that failed, so the next try starts from the registry as it was.
    fn unstage_next_epoch(&self, _token: &str) {}
}

/// Backoff of the retries of a failed epoch-end derivation.
#[derive(Debug)]
struct CloseRetry {
    next: Instant,
    step: Duration,
}

impl Default for CloseRetry {
    fn default() -> Self {
        Self {
            next: Instant::now(),
            step: Duration::ZERO,
        }
    }
}

const CLOSE_RETRY_FIRST: Duration = Duration::from_secs(1);
const CLOSE_RETRY_MAX: Duration = Duration::from_secs(30);

/// What a node with a hardware validator key needs to run consensus, kept so
/// it can start whenever it is seated: at genesis, or at the first epoch
/// boundary after it registers or restarts.
#[derive(Clone)]
pub struct Launcher {
    /// The hardware validator key.
    pub signer: Arc<dyn ValidatorSigner>,
    /// Where the last signed checkpoint is persisted.
    pub high_water: Arc<dyn VoteHighWater>,
    /// The node's iroh endpoint.
    pub endpoint: tenzro_iroh::Endpoint,
    /// The machine's identity transport: its endpoint record and the
    /// discovery store peers' records resolve through.
    pub identity: Option<Arc<tenzro_iroh::IdentityTransport>>,
    /// The machine identity whose record resolves `endpoint`.
    pub machine: Option<String>,
    /// The endpoint's `tenzro/consensus` handler slot.
    pub handler: tenzro_iroh::DeferredConsensusHandler,
    /// Receives every ordered segment, in height order.
    pub segments: mpsc::Sender<OrderedSegment>,
    /// Receives every certificate this validator forms.
    pub certificates: mpsc::UnboundedSender<Certificate>,
    /// Receives every compact certificate this validator proves.
    pub compact: mpsc::UnboundedSender<CompactCertificate>,
    /// Receives every proof of checkpoint equivocation.
    pub evidence: mpsc::UnboundedSender<CheckpointEquivocation>,
    /// Receives this validator's endpoint announcement to publish, every
    /// [`ANNOUNCE_INTERVAL`], with its endpoint sealed to committee members.
    pub announcements: mpsc::UnboundedSender<PublishedAnnouncement>,
}

enum Input {
    // `_held` is the frame's share of its channel's inbound budget, returned
    // once the core has handled it. `epoch` is the epoch of the channel it
    // came over: one that closed at a handover may still deliver a frame.
    Inbound {
        epoch: u64,
        from: ValidatorIndex,
        messages: Vec<Message>,
        _held: tokio::sync::OwnedSemaphorePermit,
    },
    Executed {
        height: u64,
        block_hash: Hash,
        state_root: Hash,
    },
    Vote(Box<CheckpointVote>),
    NextCommittee(Committee),
    PeerUp {
        epoch: u64,
        peer: ValidatorIndex,
        sender: PeerQueue,
    },
    PeerDown {
        peer: ValidatorIndex,
        sender: PeerQueue,
    },
    /// A peer's bulk (payload/batch) stream came up. Carries no consensus
    /// reachability signal of its own -- `Engine::on_peer_up` fires only
    /// from `PeerUp` -- it only gives the outbox a faster queue to use for
    /// that peer's bulk traffic.
    BulkPeerUp {
        epoch: u64,
        peer: ValidatorIndex,
        sender: PeerQueue,
    },
    /// The counterpart to `BulkPeerUp`: outbound bulk traffic to this peer
    /// falls back onto its control stream until a fresh one comes up.
    BulkPeerDown {
        peer: ValidatorIndex,
        sender: PeerQueue,
    },
    StandDown,
    /// The node is stopping: the core ends where it is, its journal kept for
    /// the next start to recover from.
    Stop,
    /// A certificate of the running epoch from the network, with the session
    /// certificates it names.
    Certificate {
        cert: Box<Certificate>,
        sessions: Vec<SessionCertificate>,
    },
    /// The network certified this epoch past what the core can still order:
    /// the core takes the checkpoint's ordering state from a peer and orders
    /// on from there.
    FastForward {
        cert: Box<Certificate>,
        sessions: Vec<SessionCertificate>,
    },
    /// The handover of the running epoch, which this node knows by the
    /// closing checkpoint's body it holds: the closing checkpoint's own
    /// certificate may never have formed.
    Handover {
        cert: Box<Certificate>,
        sessions: Vec<SessionCertificate>,
    },
}

/// What the running core measures, for tuning a live network. Read by the
/// metrics endpoint and a read-only RPC; nothing acts on it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct ConsensusMetrics {
    /// Epoch of the running core.
    pub epoch: u64,
    /// Current round.
    pub round: u64,
    /// Median and 99th percentile of recent round durations, ms.
    pub round_p50_ms: u64,
    /// See `round_p50_ms`.
    pub round_p99_ms: u64,
    /// Median and 99th percentile, over recent transactions this validator
    /// batched, of the time from first seeing one to ordering it, ms.
    pub ordered_p50_ms: u64,
    /// See `ordered_p50_ms`.
    pub ordered_p99_ms: u64,
    /// Reliable-broadcast deliveries on the two-step path.
    pub rbc_fast: u64,
    /// Reliable-broadcast deliveries on the slower path.
    pub rbc_slow: u64,
    /// Leader slots committed since the core started.
    pub leaders_committed: u64,
    /// Leader slots skipped since the core started.
    pub leaders_skipped: u64,
    /// Batches introduced and not yet available.
    pub batches_pending: u64,
    /// Encoded size of the last certificate this validator formed, bytes.
    pub certificate_bytes: u64,
    /// Consensus bytes this validator sent since the core started.
    pub egress_bytes: u64,
    /// Consensus bytes sent per round, over the last metrics interval.
    pub egress_bytes_per_round: u64,
    /// Bytes the core holds in batches and vertices.
    pub buffered_bytes: u64,
}

/// Core buffers above this size are reported: a validator whose buffers
/// grow this far is holding a stalled committee's traffic.
const BUFFER_WARN_BYTES: usize = 1 << 30;

/// How often the engine publishes its metrics.
const METRICS_INTERVAL: Duration = Duration::from_secs(1);

/// How long a running core's reach round may stand still before a verified
/// certificate showing the network ahead of it fast-forwards the core.
const STUCK_BEHIND_MS: u64 = 60_000;

/// How many rounds past its reach such a certificate's anchor must lie.
const STUCK_MIN_LAG_ROUNDS: u64 = 4;

/// How long this node's committed tip may stand still while block sync is
/// served a verified certificate of the running epoch covering blocks past
/// it before the core stands down and the node imports them as a follower.
/// Unlike [`STUCK_BEHIND_MS`] it looks at the tip, which only moves with
/// real progress, not at the core's reach round.
const TIP_STALL_MS: u64 = 20_000;

/// Latency samples kept for the ordered percentiles.
const LATENCY_WINDOW: usize = 4_096;

/// First-seen-to-ordered latencies of the transactions assigned to this
/// validator, each kept for [`LATENCY_HORIZON`]. A transaction batched after
/// stepping in for another validator has already waited out the grace, so
/// timing it would let the grace grow on its own samples.
struct OrderedLatencies {
    samples: std::collections::VecDeque<(Instant, u64)>,
}

impl OrderedLatencies {
    fn new() -> Self {
        Self {
            samples: std::collections::VecDeque::with_capacity(LATENCY_WINDOW),
        }
    }

    fn expire(&mut self, now: Instant) {
        while self
            .samples
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) > LATENCY_HORIZON)
        {
            self.samples.pop_front();
        }
    }

    fn record(&mut self, at: Instant, ms: u64) {
        self.expire(at);
        if self.samples.len() == LATENCY_WINDOW {
            self.samples.pop_front();
        }
        self.samples.push_back((at, ms));
    }

    /// The `q` quantile of the samples still within the horizon, 0 if none.
    fn quantile(&mut self, now: Instant, q: f64) -> u64 {
        self.expire(now);
        let mut v: Vec<u64> = self.samples.iter().map(|(_, ms)| *ms).collect();
        if v.is_empty() {
            return 0;
        }
        v.sort_unstable();
        v[((v.len() - 1) as f64 * q).round() as usize]
    }

    /// How long each validator in turn waits for the one before it to batch
    /// a sender's transactions: twice the typical time to order, never past
    /// `bound`, so a sender whose validator does not batch it is taken up by
    /// the next within `bound` however slow ordering has become.
    fn grace(&mut self, now: Instant, bound: Duration) -> Duration {
        let median = self.quantile(now, 0.5);
        ASSIGNMENT_GRACE
            .max(Duration::from_millis(median.saturating_mul(2)))
            .min(bound)
    }
}

/// Committees kept in memory: the newest known and the three before it,
/// which covers the previous, running and next epochs around a handover.
/// An older one is rebuilt from the epoch manager when asked for.
const COMMITTEES_KEPT: u64 = 4;

/// A batched transaction not ordered within this long is no longer timed.
const LATENCY_HORIZON: Duration = Duration::from_secs(60);

/// How long a batched transaction is held out of later batches waiting to be
/// ordered or handed back: as long as a batch is timed at all.
const IN_FLIGHT_LEASE: Duration = LATENCY_HORIZON;

/// What a cut makes of a pooled transaction this validator batched before,
/// `None` when it did not.
///
/// One already ordered lets the sender's next transaction follow it: any
/// part cut now is ordered after it. One in a part not yet ordered holds the
/// sender's later transactions back, since that part can still be handed
/// back or lost with its core, and a later part ordered ahead of it would
/// execute ahead of its nonce and fail.
fn already_batched(
    h: &Hash,
    in_flight: &HashMap<Hash, Instant>,
    ordered: &HashMap<Hash, u64>,
) -> Option<Pick> {
    if ordered.contains_key(h) {
        Some(Pick::Taken)
    } else if in_flight.contains_key(h) {
        Some(Pick::Wait)
    } else {
        None
    }
}

/// How many of its own batches a validator holds unordered before it stops
/// cutting more: well above what ordering at full load leaves outstanding,
/// far below what a network stalled for minutes would pile up.
const MAX_UNORDERED_OWN_BATCHES: usize = 128;

/// A part holding fewer transactions than this waits, up to `PART_HOLD`,
/// for more.
const MIN_PART_TRANSACTIONS: usize = 64;

/// How long a small part waits to fill.
const PART_HOLD: Duration = Duration::from_millis(250);

/// Finality as the RPC reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct FinalityStatus {
    /// Highest height ordered: final for every honest validator.
    pub ordered: u64,
    /// Highest height covered by a checkpoint certificate: transferable
    /// and accountable. Bridges act on this one.
    pub certified: u64,
}

/// The node's consensus.
pub struct ConsensusHandle {
    this: std::sync::Weak<ConsensusHandle>,
    config: ConsensusConfig,
    /// The genesis time rules.
    time: TimeRules,
    chain_id: u64,
    genesis_hash: [u8; 32],
    mempool: Arc<Mempool>,
    epoch_manager: Arc<EpochManager>,
    /// The node's store: governed parameters, blocks and state.
    storage: Option<Arc<dyn KvStore>>,
    /// Where this validator's consensus records live: the journal, its vote
    /// boundaries, certificates and session certificates. A store of their
    /// own, so a write to the node's store never holds a consensus write.
    records: Option<Arc<dyn KvStore>>,
    /// The thread the journal is written on, over `records`.
    journal: Option<Arc<crate::journal_writer::JournalWriter>>,
    ordered: AtomicU64,
    /// The highest height this node executed, from its own ordering or
    /// imported. `ordered` also counts the heights a certificate covers,
    /// which a node catching up may not have executed yet.
    executed: AtomicU64,
    certified: AtomicU64,
    latest: RwLock<Option<Certificate>>,
    committees: RwLock<HashMap<u64, Committee>>,
    /// Each epoch's session certificates this node has checked against the
    /// epoch's committee: the bundle its certificates are verified with.
    sessions: RwLock<HashMap<u64, SessionBook>>,
    /// The epoch this node last published certificates in, and the session
    /// certificates it published with them.
    published_sessions: parking_lot::Mutex<(u64, HashSet<[u8; 32]>)>,
    /// Compact-certificate proof set-ups, shared by proving and verifying.
    setups: Arc<ProofSetups>,
    /// Where compact certificates are proven and checked, one at a time.
    compact_work: Arc<CompactWork>,
    /// The latest compact certificate this node accepted.
    compact: RwLock<Option<CompactCertificate>>,
    /// Whether this node is proving a compact certificate: one at a time.
    proving: AtomicBool,
    draining: AtomicBool,
    inputs: RwLock<Option<mpsc::UnboundedSender<Input>>>,
    me: RwLock<Option<ValidatorIndex>>,
    behind: tokio::sync::watch::Sender<u64>,
    /// The last epoch-ending checkpoint certified, as it is recorded.
    epoch_certified: tokio::sync::watch::Sender<Option<Checkpoint>>,
    leads_soon: AtomicBool,
    planner: RwLock<Option<Arc<dyn EpochPlanner>>>,
    launcher: RwLock<Option<Launcher>>,
    /// Epoch of the running core, while one runs.
    running_epoch: AtomicU64,
    /// When the running core's epoch ends, in block time (milliseconds).
    epoch_ends_ms: AtomicU64,
    round: AtomicU64,
    /// The running core's reach round (see `Core::reach_round`): what it
    /// still needs from its peers starts above it.
    committed_round: AtomicU64,
    /// Wall-clock milliseconds when the reach round last moved, or when the
    /// running core started: how long this validator's core has made no
    /// progress, for [`Self::on_certificate_while_validating`].
    last_reach_change_ms: AtomicU64,
    /// The node tip block sync last saw served against, and the wall-clock
    /// milliseconds it was first seen at that height: how long the tip has
    /// stood still, for [`Self::on_served_certificate`].
    tip_seen: AtomicU64,
    tip_seen_ms: AtomicU64,
    last_certified: RwLock<Option<Instant>>,
    equivocations: AtomicU64,
    /// Consensus frames dropped because the queue to their peer was full.
    dropped_frames: AtomicU64,
    /// Index of each epoch's last checkpoint, once known.
    boundaries: RwLock<HashMap<u64, u64>>,
    /// Where each validator announced it can be reached.
    endpoints: Arc<RwLock<EndpointBook>>,
    /// Wakes the announcer loop at once when a fresh or changed committee
    /// member announcement is recorded, instead of leaving it to find out
    /// at its next `ANNOUNCE_INTERVAL` tick. A validator that just
    /// restarted holds an empty endpoint book and admits no one until it
    /// has resealed its own endpoint to every member and been resealed to
    /// in return; gating that exchange on unsynchronised 30s ticks alone
    /// let one restart, under packet loss thinning the gossip that carries
    /// it, stall liveness for minutes (chaos seed 3054677367).
    reseal_kick: Arc<tokio::sync::Notify>,
    /// This validator's own current announcement, once signed, and the
    /// endpoint and salt it commits to.
    announcement: Arc<RwLock<Option<(EndpointAnnouncement, EndpointOpening)>>>,
    /// This boot's session key, certified by the announcement.
    session: Arc<SessionKey>,
    /// This boot's disclosure key, named by the announcement: members seal
    /// their endpoints to it.
    disclosure: Arc<DisclosureSecret>,
    /// Fingerprint of this node's validator key, once it has one.
    own_key: RwLock<Option<[u8; 32]>>,
    /// The key a pending rotation of this validator's key seats, held until
    /// the first committee that seats it.
    incoming_key: RwLock<Option<Arc<dyn ValidatorSigner>>>,
    /// The hardware key's certificate of the session key for the epoch it
    /// last voted in.
    session_cert: Arc<parking_lot::Mutex<Option<SessionCertificate>>>,
    /// The running core's latest metrics.
    metrics: RwLock<Option<ConsensusMetrics>>,
    /// The last height of an epoch whose next committee is derived once that
    /// height is executed. Checked under one lock by the engine and by
    /// execution, so the epoch's end is acted on exactly once, right after
    /// its last block and before any later one.
    closing: parking_lot::Mutex<Option<u64>>,
    /// Held while a committee is derived, from staging to the transition, so
    /// two callers at one boundary derive it one after the other.
    derivation: parking_lot::Mutex<()>,
    /// When a pending epoch end is tried again after a failure, and how long
    /// the wait grows to: from a second, doubling, to half a minute.
    close_retry: parking_lot::Mutex<CloseRetry>,
    /// A timer-started retry is under way.
    close_retry_in_flight: std::sync::atomic::AtomicBool,
    /// The last executed blocks, (height, hash, post-state root), oldest
    /// first: what a core entering an epoch late starts from.
    executed_tail: parking_lot::Mutex<std::collections::VecDeque<(u64, [u8; 32], [u8; 32])>>,
    /// Whether the running core took its epoch's handover before this node
    /// executed the blocks it covers, and waits for them to be imported.
    awaiting_handover: AtomicBool,
    /// The last height of the certified checkpoint the running core
    /// fast-forwarded to (0 when none): until the node's tip reaches it, the
    /// node imports blocks like a follower.
    fast_forward_to: AtomicU64,
    /// The latest checkpoint index peers report certified.
    network_checkpoint: AtomicU64,
}

impl ConsensusHandle {
    /// Consensus for a chain, with the genesis committee.
    pub fn new(
        config: ConsensusConfig,
        time: TimeRules,
        chain_id: u64,
        genesis_hash: [u8; 32],
        epoch_manager: Arc<EpochManager>,
        storage: Option<Arc<dyn KvStore>>,
        records: Option<Arc<dyn KvStore>>,
    ) -> Result<Arc<Self>> {
        let mempool = Arc::new(Mempool::new(Arc::new(config.clone())));
        // The current epoch's committee, and the previous one's: after a
        // restart between an epoch's last checkpoint and its handover the
        // epoch manager is already on the next epoch while the handover
        // certificates are still signed by the previous committee.
        let current = epoch_manager.current_epoch().number;
        let mut committees = HashMap::new();
        for number in current.saturating_sub(1)..=current {
            if let Some(set) = epoch_manager.get_validator_set(number) {
                committees.insert(
                    number,
                    tenzro_consensus::committee::from_validator_set(&set, config.seat_budget)?,
                );
            }
        }
        if let std::collections::hash_map::Entry::Vacant(e) = committees.entry(current) {
            let set = epoch_manager.current_validator_set();
            e.insert(tenzro_consensus::committee::from_validator_set(
                &set,
                config.seat_budget,
            )?);
        }
        let latest: Option<Certificate> = records
            .as_ref()
            .and_then(|s| s.get(CF, LATEST_CERTIFICATE_KEY).ok().flatten())
            .and_then(|b| bincode::deserialize(&b).ok());
        let certified = latest.as_ref().map_or(0, |c| c.checkpoint.last_height);
        let compact: Option<CompactCertificate> = records
            .as_ref()
            .and_then(|s| s.get(CF, LATEST_COMPACT_KEY).ok().flatten())
            .and_then(|b| bincode::deserialize(&b).ok());
        let mut boundaries = HashMap::new();
        if let Some(s) = records.as_ref() {
            for number in current.saturating_sub(1)..=current {
                if let Some(b) = s.get(CF, &boundary_key(number)).ok().flatten()
                    && let Ok(bytes) = <[u8; 8]>::try_from(b.as_slice())
                {
                    boundaries.insert(number, u64::from_be_bytes(bytes));
                }
            }
        }
        let mut sessions = HashMap::new();
        if let Some(s) = records.as_ref() {
            for (number, committee) in &committees {
                let mut book = SessionBook::new(chain_id, genesis_hash, *number);
                for (_, value) in s.scan_prefix(CF, &session_prefix(*number))? {
                    if let Ok(c) = bincode::deserialize::<SessionCertificate>(&value) {
                        let _ = book.admit(committee, c);
                    }
                }
                sessions.insert(*number, book);
            }
        }
        let session = Arc::new(SessionKey::generate_with_scheme(config.session_key_scheme)?);
        let compact_threads = config.compact_pool_threads;
        Ok(Arc::new_cyclic(|this| Self {
            this: this.clone(),
            config,
            time,
            chain_id,
            genesis_hash,
            mempool,
            epoch_manager,
            storage,
            journal: records
                .clone()
                .map(|r| Arc::new(crate::journal_writer::JournalWriter::spawn(r))),
            records,
            ordered: AtomicU64::new(certified),
            executed: AtomicU64::new(0),
            certified: AtomicU64::new(certified),
            latest: RwLock::new(latest),
            committees: RwLock::new(committees),
            sessions: RwLock::new(sessions),
            published_sessions: parking_lot::Mutex::new((0, HashSet::new())),
            setups: shared_setups(),
            compact_work: shared_compact_work(compact_threads),
            compact: RwLock::new(compact),
            proving: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            inputs: RwLock::new(None),
            me: RwLock::new(None),
            behind: tokio::sync::watch::channel(0).0,
            epoch_certified: tokio::sync::watch::channel(None).0,
            leads_soon: AtomicBool::new(false),
            planner: RwLock::new(None),
            launcher: RwLock::new(None),
            running_epoch: AtomicU64::new(0),
            epoch_ends_ms: AtomicU64::new(0),
            round: AtomicU64::new(0),
            committed_round: AtomicU64::new(0),
            last_reach_change_ms: AtomicU64::new(unix_ms()),
            tip_seen: AtomicU64::new(u64::MAX),
            tip_seen_ms: AtomicU64::new(unix_ms()),
            last_certified: RwLock::new(None),
            equivocations: AtomicU64::new(0),
            dropped_frames: AtomicU64::new(0),
            boundaries: RwLock::new(boundaries),
            endpoints: Arc::new(RwLock::new(EndpointBook::new())),
            reseal_kick: Arc::new(tokio::sync::Notify::new()),
            announcement: Arc::new(RwLock::new(None)),
            session,
            disclosure: Arc::new(DisclosureSecret::generate()),
            own_key: RwLock::new(None),
            incoming_key: RwLock::new(None),
            session_cert: Arc::new(parking_lot::Mutex::new(None)),
            metrics: RwLock::new(None),
            closing: parking_lot::Mutex::new(None),
            derivation: parking_lot::Mutex::new(()),
            close_retry: parking_lot::Mutex::new(CloseRetry::default()),
            close_retry_in_flight: std::sync::atomic::AtomicBool::new(false),
            executed_tail: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            awaiting_handover: AtomicBool::new(false),
            fast_forward_to: AtomicU64::new(0),
            network_checkpoint: AtomicU64::new(0),
        }))
    }

    /// What signs this validator's votes: the session key, and the hardware
    /// key that certifies it.
    fn certifier(&self, hardware: Arc<dyn ValidatorSigner>) -> Certifier {
        Certifier {
            hardware,
            session: self.session.clone(),
            cache: self.session_cert.clone(),
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
        }
    }

    /// The running core's latest metrics; `None` on a follower.
    pub fn metrics(&self) -> Option<ConsensusMetrics> {
        if self.is_validator() {
            *self.metrics.read()
        } else {
            None
        }
    }

    /// Whether `bytes` are a published endpoint announcement that verifies
    /// under the key of a member of a committee this node holds and is
    /// current. Records nothing: it is how gossip decides to hear an
    /// announcement from a neighbour no endpoint record names yet.
    pub fn vouches_for_announcement(&self, bytes: &[u8]) -> bool {
        let Ok(published) = bincode::deserialize::<PublishedAnnouncement>(bytes) else {
            return false;
        };
        let announcement = published.announcement;
        let key = self
            .committees
            .read()
            .values()
            .flat_map(|c| c.members().iter())
            .find(|m| m.public_key.fingerprint() == announcement.validator)
            .map(|m| m.public_key.clone());
        key.is_some_and(|key| {
            announcement
                .verify(&key, self.chain_id, &self.genesis_hash, unix_ms())
                .is_ok()
        })
    }

    /// Records an endpoint announcement seen on the network, when it
    /// verifies under the key of a member of a committee this node holds,
    /// and the endpoint it carries sealed to this node, if any. Returns the
    /// endpoint it disclosed to this node, if a sealed copy opened.
    pub fn offer_announcement(&self, published: PublishedAnnouncement) -> Option<[u8; 32]> {
        let PublishedAnnouncement {
            announcement,
            sealed,
        } = published;
        let sender = announcement.validator;
        let key = self
            .committees
            .read()
            .values()
            .flat_map(|c| c.members().iter())
            .find(|m| m.public_key.fingerprint() == announcement.validator)
            .map(|m| m.public_key.clone());
        let key = key?;
        let now = unix_ms();
        let mut book = self.endpoints.write();
        book.expire(now);
        let recorded = match book.offer(announcement, &key, self.chain_id, &self.genesis_hash, now)
        {
            Ok(recorded) => recorded,
            Err(e) => {
                debug!(error = %e, "endpoint announcement refused");
                return None;
            }
        };
        // A new or renewed announcement may need a fresh seal of our own
        // endpoint to it (a new disclosure key) or be the one this node
        // itself was waiting on to admit that member at all: react now
        // rather than at the announcer's next periodic tick. A repeat of the
        // announcement already held changes nothing, and waking on it would
        // answer every peer's periodic republish with one of our own.
        if recorded {
            self.reseal_kick.notify_one();
        }
        let opened = match *self.own_key.read() {
            Some(me) if !sealed.is_empty() => book.open(&sender, &me, &sealed, &self.disclosure),
            _ => false,
        };
        let disclosed = if opened {
            book.endpoint(&key, now)
        } else {
            None
        };
        drop(book);
        if disclosed.is_some() {
            self.share_record_with_committee();
        }
        disclosed
    }

    /// Shares this machine's endpoint record only with the machines of the
    /// committee members that disclosed their endpoints to this node and with
    /// the machines on its own boot list, so the validator's endpoint
    /// resolves for the committee and its entry points and no one else.
    fn share_record_with_committee(&self) {
        let Some(launcher) = self.launcher.read().clone() else {
            return;
        };
        let Some(identity) = launcher.identity.as_ref() else {
            return;
        };
        let mut machines: std::collections::HashSet<String> = self
            .endpoints
            .read()
            .disclosed_machines(unix_ms())
            .map(str::to_string)
            .collect();
        machines.extend(launcher.machine.clone());
        identity.share_within_epoch_set(machines);
    }

    /// The endpoint the validator holding `key` disclosed to this node,
    /// while its announcement is current.
    pub fn announced_endpoint(
        &self,
        key: &tenzro_consensus::ValidatorPublicKey,
    ) -> Option<[u8; 32]> {
        self.endpoints.read().endpoint(key, unix_ms())
    }

    /// Signs this validator's endpoint announcement on first use and at
    /// half its lifetime, and hands it to the launcher's publisher every
    /// [`ANNOUNCE_INTERVAL`]. The hardware key signs a few times a day.
    fn spawn_announcer(&self, launcher: &Launcher) {
        *self.own_key.write() = Some(launcher.signer.public_key().fingerprint());
        let Some(machine) = launcher.machine.clone() else {
            warn!(
                "this machine has no hardware identity, so no endpoint record resolves its endpoint: \
                 it announces nothing and the committee cannot reach it"
            );
            return;
        };
        let opening = match EndpointOpening::new(*launcher.endpoint.id().as_bytes(), machine) {
            Ok(o) => o,
            Err(e) => {
                warn!(error = %e, "endpoint announcement not made");
                return;
            }
        };
        self.share_record_with_committee();
        let session_key = tenzro_consensus::ValidatorSigner::public_key(&*self.session).clone();
        let disclosure_key = self.disclosure.public().clone();
        let publish = launcher.announcements.clone();
        let own = self.announcement.clone();
        let handle = self.this.clone();
        let kick = self.reseal_kick.clone();
        let (chain_id, genesis_hash) = (self.chain_id, self.genesis_hash);
        let lifetime_ms = self.time.announcement_lifetime_ms;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(ANNOUNCE_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The endpoint sealed to each member's current disclosure key,
            // and how many announcements ago the sealed set last went out.
            let mut sealed: HashMap<[u8; 32], ([u8; 32], SealedEndpoint)> = HashMap::new();
            let mut since_sealed = RESEAL_EVERY;
            let mut repeats: u32 = 0;
            let mut retry_at: Option<tokio::time::Instant> = None;
            let mut quick: u32 = 0;
            loop {
                let wake = tokio::select! {
                    _ = tick.tick() => Wake::Tick,
                    _ = kick.notified() => Wake::Kick,
                    _ = async {
                        match retry_at {
                            Some(at) => tokio::time::sleep_until(at).await,
                            None => std::future::pending().await,
                        }
                    } => Wake::Retry,
                };
                let kicked = wake == Wake::Kick;
                let Some(handle) = handle.upgrade() else {
                    return;
                };
                // The launcher's key, which a seated key rotation replaces.
                let Some(signer) = handle.launcher.read().as_ref().map(|l| l.signer.clone()) else {
                    return;
                };
                let me = signer.public_key().fingerprint();
                let now = unix_ms();
                let held = own
                    .read()
                    .as_ref()
                    .map(|(a, _)| a.clone())
                    .filter(|a| a.validator == me);
                let renewed = !matches!(&held, Some(a) if !a.due_for_renewal(now));
                let announcement = match held {
                    Some(a) if !a.due_for_renewal(now) => a,
                    _ => {
                        let s = signer.clone();
                        let session_key = session_key.clone();
                        let disclosure_key = disclosure_key.clone();
                        let o = opening.clone();
                        let signed = tokio::task::spawn_blocking(move || {
                            EndpointAnnouncement::sign(
                                &*s,
                                chain_id,
                                genesis_hash,
                                &o,
                                session_key,
                                disclosure_key,
                                now,
                                lifetime_ms,
                            )
                        })
                        .await;
                        match signed {
                            Ok(Ok(a)) => {
                                *own.write() = Some((a.clone(), opening.clone()));
                                a
                            }
                            Ok(Err(e)) => {
                                warn!(error = %e, "could not sign the endpoint announcement");
                                continue;
                            }
                            Err(e) => {
                                warn!(error = %e, "endpoint announcement signing task failed");
                                continue;
                            }
                        }
                    }
                };
                let changed = handle.reseal(&opening, me, now, &mut sealed);
                // A wake-up publishes only what it changed; the periodic tick
                // republishes for peers that joined or restarted since.
                if kicked && !changed && !renewed {
                    continue;
                }
                if changed {
                    quick = 0;
                    retry_at = Some(tokio::time::Instant::now() + RESEAL_RETRY);
                } else if wake == Wake::Retry {
                    quick += 1;
                    retry_at = (quick < RESEAL_QUICK_REPEATS)
                        .then(|| tokio::time::Instant::now() + RESEAL_RETRY * (1 << quick));
                }
                since_sealed += 1;
                let sealed_out = if sealed_due(changed, kicked, since_sealed, &mut repeats)
                    || wake == Wake::Retry
                {
                    since_sealed = 0;
                    sealed.values().map(|(_, s)| s.clone()).collect()
                } else {
                    Vec::new()
                };
                if publish
                    .send(PublishedAnnouncement {
                        announcement,
                        sealed: sealed_out,
                    })
                    .is_err()
                {
                    return;
                }
            }
        });
    }

    /// Seals this validator's endpoint to every member of a committee this
    /// node holds that has a current announcement, reusing the sealed copy
    /// for a member whose disclosure key has not changed and dropping those
    /// of validators no longer in any held committee. Returns whether the
    /// set changed.
    fn reseal(
        &self,
        opening: &EndpointOpening,
        me: [u8; 32],
        now: u64,
        sealed: &mut HashMap<[u8; 32], ([u8; 32], SealedEndpoint)>,
    ) -> bool {
        let members: HashSet<[u8; 32]> = self
            .committees
            .read()
            .values()
            .flat_map(|c| c.members().iter().map(|m| m.public_key.fingerprint()))
            .filter(|f| *f != me)
            .collect();
        let before = sealed.len();
        sealed.retain(|recipient, _| members.contains(recipient));
        let mut changed = sealed.len() != before;
        let book = self.endpoints.read();
        for a in book
            .announcements(now)
            .filter(|a| members.contains(&a.validator))
        {
            let key = a.disclosure_key.fingerprint();
            if sealed.get(&a.validator).is_some_and(|(k, _)| *k == key) {
                continue;
            }
            match opening.seal(&me, a.validator, &a.disclosure_key) {
                Ok(s) => {
                    sealed.insert(a.validator, (key, s));
                    changed = true;
                }
                Err(e) => debug!(error = %e, "could not seal the endpoint to a member"),
            }
        }
        changed
    }

    /// Installs the registry seam run before every next-committee derivation.
    pub fn set_epoch_planner(&self, planner: Arc<dyn EpochPlanner>) {
        *self.planner.write() = Some(planner);
    }

    /// Called for every certificate seen on the network while this node
    /// validates.
    ///
    /// The certificates closing the running epoch and handing it over reach
    /// a validator that missed the votes on them (its channels were down at
    /// the handover, and its peers, already in the next epoch, refuse a hello
    /// for this one): the running core adopts both, with the session
    /// certificates they name, and hands over as the others did.
    ///
    /// A certificate of a later epoch means the network moved on without
    /// this validator: the core stands down and the node follows, importing
    /// under certificates, until its key is seated again at a handover. A
    /// certificate of the running epoch whose anchor is more than the DAG's
    /// garbage-collection depth past the core's last committed round means
    /// its peers no longer hold the rounds the core would have to order to
    /// get there: the core fast-forwards to that checkpoint, taking the
    /// ordering state it commits from a peer, while the node imports the
    /// blocks up to it. Returns whether the node imports the certified
    /// blocks itself (it stood down or fast-forwards).
    ///
    /// Only a certificate that verifies against its epoch's committee moves
    /// the core. One of an epoch whose committee this node has not derived
    /// yet cannot be checked and is ignored: block sync, whose evidence stops
    /// at the epochs this node can verify, brings it there.
    pub fn on_network_certificate(&self, cert: &Certificate) -> bool {
        if !self.is_validator() || self.awaiting_handover() {
            return false;
        }
        self.on_certificate_while_validating(cert)
    }

    /// As [`Self::on_network_certificate`], for a certificate block sync
    /// served while this node's tip is at `tip`. The end of the running
    /// epoch, or a checkpoint after it, covering blocks past the tip shows
    /// the network closed the epoch without this validator: its core can no
    /// longer order those blocks, nor enter the next epoch without having
    /// executed them. The node stands down, imports them like a follower and
    /// starts again at the handover.
    pub fn on_served_certificate(&self, cert: &Certificate, tip: u64) -> bool {
        if !self.is_validator() || self.awaiting_handover() {
            return false;
        }
        let epoch = cert.checkpoint.epoch;
        let closed = cert.checkpoint.next_committee_root.is_some()
            || self
                .boundary(epoch)
                .is_some_and(|b| cert.checkpoint.index > b);
        if epoch == self.running_epoch.load(Ordering::Acquire)
            && closed
            && cert.checkpoint.last_height > tip
            && self.verify_certificate(cert).is_ok()
        {
            info!(
                epoch,
                index = cert.checkpoint.index,
                last_height = cert.checkpoint.last_height,
                tip,
                "the network closed this validator's epoch past its tip; following to catch up"
            );
            self.stand_down();
            return true;
        }
        // A stalled tip: the tip has not moved for [`TIP_STALL_MS`] while a
        // verified certificate of the running epoch covers blocks past it.
        // The core runs but does not order them (it cannot reach a quorum),
        // and no other trigger fires for a certificate within its reach.
        let now = unix_ms();
        if self.tip_seen.swap(tip, Ordering::AcqRel) != tip {
            self.tip_seen_ms.store(now, Ordering::Release);
        }
        let stalled_ms = now.saturating_sub(self.tip_seen_ms.load(Ordering::Acquire));
        if stalled_ms >= TIP_STALL_MS
            && epoch == self.running_epoch.load(Ordering::Acquire)
            && cert.checkpoint.last_height > tip
            && self.verify_certificate(cert).is_ok()
        {
            info!(
                epoch,
                index = cert.checkpoint.index,
                last_height = cert.checkpoint.last_height,
                tip,
                stalled_ms,
                "this validator's tip stalled while the network certified past it; following to catch up"
            );
            self.tip_seen_ms.store(now, Ordering::Release);
            self.stand_down();
            return true;
        }
        self.on_certificate_while_validating(cert)
    }

    /// Records that the running core moved on, or has just started.
    fn note_reach_progress(&self) {
        self.last_reach_change_ms
            .store(unix_ms(), Ordering::Release);
    }

    fn on_certificate_while_validating(&self, cert: &Certificate) -> bool {
        let running = self.running_epoch.load(Ordering::Acquire);
        let epoch = cert.checkpoint.epoch;
        let committed = self.committed_round.load(Ordering::Acquire);
        // Past what the DAG still keeps, or past what this core reached
        // while its reach has not moved for [`STUCK_BEHIND_MS`]: a core that
        // makes no progress while a certificate it verifies shows the network
        // ahead of it is brought to that checkpoint the same way.
        let stuck = unix_ms().saturating_sub(self.last_reach_change_ms.load(Ordering::Acquire))
            >= STUCK_BEHIND_MS;
        let past_reach = epoch == running
            && (cert.checkpoint.anchor_round > committed.saturating_add(self.config.gc_depth)
                || (stuck
                    && cert.checkpoint.anchor_round
                        > committed.saturating_add(STUCK_MIN_LAG_ROUNDS)));
        let closing = epoch == running && cert.checkpoint.next_committee_root.is_some();
        // The running epoch's last checkpoint: recorded when this node saw
        // it close, or read from the closing body it holds when it accepted
        // that certificate as a follower (it took the previous handover
        // before executing that epoch's last blocks), before this core ran.
        let recorded = self.boundaries.read().get(&running).copied();
        let boundary = recorded.or_else(|| {
            if epoch != running {
                return None;
            }
            let b = cert
                .checkpoint
                .index
                .checked_sub(self.time.handover_confirmations)?;
            self.checkpoint(b)
                .filter(|c| c.epoch == running && c.next_committee_root.is_some())
                .map(|_| b)
        });
        let handover = epoch == running
            && boundary
                .is_some_and(|b| cert.checkpoint.index == b + self.time.handover_confirmations);
        let later = epoch > running;
        if !(past_reach || closing || handover || later) {
            return false;
        }
        if let Err(e) = self.verify_certificate(cert) {
            debug!(epoch, index = cert.checkpoint.index, error = %e, "certificate not verified; ignored");
            return false;
        }
        if later {
            info!(
                epoch = running,
                certificate_epoch = epoch,
                "the network is past this validator's epoch; following to catch up"
            );
            self.stand_down();
            return true;
        }
        if past_reach {
            info!(
                epoch = running,
                index = cert.checkpoint.index,
                anchor_round = cert.checkpoint.anchor_round,
                committed_round = committed,
                "the network certified past what this validator can still order; fast-forwarding"
            );
            if let Some(tx) = self.inputs.read().as_ref() {
                self.fast_forward_to
                    .store(cert.checkpoint.last_height.max(1), Ordering::Release);
                let sessions = self.session_bundle(cert);
                let _ = tx.send(Input::FastForward {
                    cert: Box::new(cert.clone()),
                    sessions,
                });
            }
            return true;
        }
        if closing {
            self.record_boundary(running, cert.checkpoint.index);
        }
        // A core started after its epoch closed and handed over learns of
        // the certificates only from what this node holds: it adopts the
        // closing one before the handover, whichever of them arrives here.
        // Block sync serves the closing one again and again otherwise, and
        // the core waits for a handover the node already holds.
        let mut adopt = Vec::new();
        let mut closing_held = false;
        if handover && let Some(b) = boundary {
            if recorded.is_none() {
                self.record_boundary(running, b);
            }
            if b != cert.checkpoint.index
                && let Some(c) = self.certificate(b)
            {
                adopt.push(c);
                closing_held = true;
            }
        }
        // The handover without its closing certificate: the core cannot
        // tell it from any later certificate, so it is named as one.
        let handover_alone = handover && !closing_held;
        adopt.push(cert.clone());
        if closing
            && self.time.handover_confirmations > 0
            && let Some(h) = self
                .certificate(cert.checkpoint.index + self.time.handover_confirmations)
                .filter(|h| h.checkpoint.epoch == running)
        {
            adopt.push(h);
        }
        if let Some(tx) = self.inputs.read().as_ref() {
            for c in adopt {
                let sessions = self.session_bundle(&c);
                let named = handover_alone && c.checkpoint.index == cert.checkpoint.index;
                let cert = Box::new(c);
                let _ = tx.send(if named {
                    Input::Handover { cert, sessions }
                } else {
                    Input::Certificate { cert, sessions }
                });
            }
        }
        false
    }

    /// Whether the running core took its epoch's handover before this node
    /// executed the blocks the handover covers: block sync then imports them
    /// for it, and the core enters the next epoch once they are executed.
    pub fn awaiting_handover(&self) -> bool {
        self.awaiting_handover.load(Ordering::Acquire)
    }

    /// The last height of the certified checkpoint the running core
    /// fast-forwarded to: while the node's tip is below it, the node imports
    /// the blocks up to it.
    pub fn fast_forward_target(&self) -> Option<u64> {
        Some(self.fast_forward_to.load(Ordering::Acquire)).filter(|h| *h > 0)
    }

    /// The executed blocks through `height` an epoch starting after it is
    /// based on, if `height` is the last block this node executed.
    fn base_through(&self, height: u64) -> Option<Vec<(u64, [u8; 32], [u8; 32])>> {
        let tail = self.executed_tail.lock();
        (tail.back()?.0 == height).then(|| tail.iter().copied().collect())
    }

    /// Stops the running core as the node shuts down. Its journal stays, so
    /// the next start recovers the epoch it was running.
    pub fn stop(&self) {
        self.awaiting_handover.store(false, Ordering::Release);
        self.fast_forward_to.store(0, Ordering::Release);
        let tx = self.inputs.write().take();
        *self.me.write() = None;
        if let Some(tx) = tx {
            let _ = tx.send(Input::Stop);
        }
    }

    /// Stops the running core: the node follows from here, and block sync
    /// catches it up at once.
    fn stand_down(&self) {
        self.awaiting_handover.store(false, Ordering::Release);
        self.fast_forward_to.store(0, Ordering::Release);
        let tx = self.inputs.write().take();
        *self.me.write() = None;
        if let Some(tx) = tx {
            let _ = tx.send(Input::StandDown);
        }
        self.wake_block_sync();
    }

    /// Makes this node able to validate: it starts whenever its key is
    /// seated. A node without a hardware validator key never calls this and
    /// follows.
    pub fn set_launcher(&self, launcher: Launcher) {
        *self.launcher.write() = Some(launcher.clone());
        self.spawn_announcer(&launcher);
    }

    /// Hands this validator the key a pending rotation of its key seats. It
    /// keeps signing with the launcher's key while a committee seats that
    /// key, and moves to this one at the first committee that seats it
    /// instead, without a restart.
    pub fn set_incoming_key(&self, key: Arc<dyn ValidatorSigner>) {
        *self.incoming_key.write() = Some(key);
    }

    /// Whether `key` is the incoming key a pending rotation seats.
    fn is_incoming(&self, key: &tenzro_consensus::ValidatorPublicKey) -> bool {
        self.incoming_key
            .read()
            .as_ref()
            .is_some_and(|k| k.public_key() == key)
    }

    /// This validator's key seated in `committee`, and its index there:
    /// `current` while the committee seats it; otherwise the incoming key,
    /// once a committee seats it. From then on the incoming key is the
    /// launcher's key, and the announcements this validator publishes are
    /// signed by it and name it.
    fn key_for(
        &self,
        committee: &Committee,
        current: &Arc<dyn ValidatorSigner>,
    ) -> Option<(Arc<dyn ValidatorSigner>, ValidatorIndex)> {
        let index = |k: &Arc<dyn ValidatorSigner>| {
            committee
                .members()
                .iter()
                .position(|m| &m.public_key == k.public_key())
                .map(|i| i as ValidatorIndex)
        };
        if let Some(i) = index(current) {
            return Some((current.clone(), i));
        }
        let incoming = self.incoming_key.read().clone()?;
        let i = index(&incoming)?;
        *self.incoming_key.write() = None;
        if let Some(launcher) = self.launcher.write().as_mut() {
            launcher.signer = incoming.clone();
        }
        *self.own_key.write() = Some(incoming.public_key().fingerprint());
        // The announcement held names the old key; the announcer signs a new
        // one with this key at once.
        *self.announcement.write() = None;
        self.reseal_kick.notify_one();
        info!(
            epoch = committee.epoch,
            "this validator's rotated key is seated; it signs with that key from this epoch"
        );
        Some((incoming, i))
    }

    /// Derives the next epoch's committee from the state executed through
    /// `last_height`, and moves the epoch manager to it. Every node runs this
    /// at the same height over the same state, so every node derives the
    /// same committee.
    ///
    /// Deriving it moves the epoch manager on, so it happens once per epoch:
    /// a validator that derived it when its epoch closed, then fell behind
    /// and follows, takes the set it derived then.
    ///
    /// With `expected_root`, the set the transition derives is checked
    /// against it before the epoch manager moves; a set that does not match
    /// leaves the manager where it was.
    fn derive_next_committee(
        &self,
        closing: u64,
        last_height: u64,
        expected_root: Option<[u8; 32]>,
    ) -> Result<Committee> {
        let _derivation = self.derivation.lock();
        let em = &self.epoch_manager;
        if em.current_epoch().number > closing {
            let set = em.get_validator_set(closing + 1).ok_or_else(|| {
                NodeError::Other(format!(
                    "the validator set of epoch {} is not kept",
                    closing + 1
                ))
            })?;
            return Ok(tenzro_consensus::committee::from_validator_set(
                &set,
                self.config.seat_budget,
            )?);
        }
        // The committee is derived from the state at `last_height`, the epoch's
        // last block. A node that has executed further, or not as far, would
        // read other state and derive another committee: it refuses.
        let executed = self.executed_height();
        if executed != last_height {
            return Err(NodeError::Other(format!(
                "the next committee is derived from the state at height {last_height}, but this node has executed through height {executed}"
            )));
        }
        let planner = self.planner.read().clone();
        let token = match &planner {
            Some(p) => Some(p.stage_next_epoch().map_err(|e| {
                NodeError::Other(format!("the next epoch could not be staged: {e}"))
            })?),
            None => None,
        };
        let seat_budget = self.config.seat_budget;
        let matches = |set: &tenzro_consensus::ValidatorSet| match expected_root {
            None => true,
            Some(root) => tenzro_consensus::committee::from_validator_set(set, seat_budget)
                .is_ok_and(|c| c.root() == root),
        };
        // Staging changed the registry; a derivation that fails or does not
        // happen puts it back, so a retry does not apply the boundary twice.
        let set = match em.transition_epoch_checked(
            tenzro_types::primitives::BlockHeight::from(last_height),
            Some(closing),
            Some(&matches),
        ) {
            Ok(Some(set)) => set,
            Ok(None) => {
                if let (Some(p), Some(t)) = (&planner, &token) {
                    p.unstage_next_epoch(t);
                }
                em.current_validator_set()
            }
            Err(e) => {
                if let (Some(p), Some(t)) = (&planner, &token) {
                    p.unstage_next_epoch(t);
                }
                return Err(e.into());
            }
        };
        Ok(tenzro_consensus::committee::from_validator_set(
            &set,
            self.config.seat_budget,
        )?)
    }

    /// On a validator, called once the block closing the epoch is executed:
    /// derives the next committee and hands it to the running core, whose
    /// last checkpoint of the epoch commits its root.
    pub fn close_epoch(&self, last_height: u64) -> Result<()> {
        let committee = self.derive_next_committee(
            self.running_epoch.load(Ordering::Acquire),
            last_height,
            None,
        )?;
        if let Some(tx) = self.inputs.read().as_ref() {
            let _ = tx.send(Input::NextCommittee(committee));
        }
        Ok(())
    }

    /// On a follower, called once the blocks of an epoch's last checkpoint
    /// are imported: derives the next committee the same way the validators
    /// did and refuses the epoch change if its root is not the one the
    /// certified checkpoint commits.
    pub fn adopt_next_committee(&self, last: &Checkpoint) -> Result<()> {
        let Some(root) = last.next_committee_root else {
            return Ok(());
        };
        if self.committee(last.epoch + 1).is_some() {
            // Derived already (this node validated to the epoch's end, then
            // fell behind): the boundary the handover is counted from is
            // still this checkpoint.
            if self.boundary(last.epoch).is_none() {
                self.record_boundary(last.epoch, last.index);
            }
            return Ok(());
        }
        let committee = self.derive_next_committee(last.epoch, last.last_height, Some(root))?;
        if committee.root() != root {
            return Err(NodeError::Other(format!(
                "checkpoint {} commits a next committee this node does not derive from its state",
                last.index
            )));
        }
        self.record_boundary(last.epoch, last.index);
        self.add_committee(committee);
        Ok(())
    }

    /// Records the index of `epoch`'s last checkpoint, durably: the handover
    /// a follower joins at is counted from it.
    fn record_boundary(&self, epoch: u64, index: u64) {
        if let Some(s) = &self.records
            && let Err(e) = s.put(CF, &boundary_key(epoch), &index.to_be_bytes())
        {
            warn!(epoch, error = %e, "failed to persist the epoch boundary");
        }
        self.boundaries.write().insert(epoch, index);
    }

    /// On a follower, called once the blocks a certified checkpoint covers
    /// are imported. If the checkpoint is its epoch's handover and this
    /// node's key is seated in the next committee, consensus starts here.
    /// `base_blocks` are the last executed blocks as (height, hash, post-state
    /// root), oldest first.
    pub fn on_imported(
        &self,
        cp: &Checkpoint,
        base_blocks: Vec<(u64, [u8; 32], [u8; 32])>,
    ) -> Result<()> {
        if self.is_validator() || !self.joins_at(cp) {
            return Ok(());
        }
        let start = EpochStart {
            first_height: cp.last_height + 1,
            first_checkpoint: cp.index + 1,
            prev_checkpoint: cp.digest(),
            timestamp_ms: cp.timestamp_ms,
            base_blocks,
            leader_lookahead_rounds: governed_lookahead(self.storage.as_ref()),
        };
        self.launch(cp.epoch + 1, start)
    }

    /// Whether a follower that imported the blocks `cp` covers starts
    /// consensus there: `cp` is its epoch's handover, and a current one.
    fn joins_at(&self, cp: &Checkpoint) -> bool {
        let Some(boundary) = self.boundary(cp.epoch) else {
            return false;
        };
        if cp.index != boundary + self.time.handover_confirmations {
            return false;
        }
        // A handover certified longer ago than an epoch lasts is history this
        // node is catching up through when its peers certified past it: the
        // network has left that epoch, and a core started in it would only
        // hold up the import of the blocks after it. The node joins at a
        // current handover. One its peers certified nothing past is where
        // the network stands, however long ago: a network short of a quorum
        // without this validator certifies no later handover to join at.
        let epoch_ms = self
            .time
            .epoch_checkpoints
            .saturating_mul(self.time.checkpoint_interval_ms);
        if unix_ms().saturating_sub(cp.timestamp_ms) > epoch_ms
            && self.network_checkpoint.load(Ordering::Acquire) > cp.index
        {
            debug!(
                epoch = cp.epoch + 1,
                "not starting consensus at a past handover"
            );
            return false;
        }
        true
    }

    /// Whether this validator leads one of the next [`LEADERSHIP_HORIZON`]
    /// rounds. Periodic duties that one node should run for the network
    /// (sweeps, keepers) gate on it, so they rotate with leadership instead
    /// of every validator running them at once.
    pub fn leads_soon(&self) -> bool {
        self.leads_soon.load(Ordering::Acquire)
    }

    /// Round this validator last proposed in (0 on a follower).
    pub fn round(&self) -> u64 {
        self.round.load(Ordering::Acquire)
    }

    /// Seconds since this node last recorded a certificate, if it has.
    pub fn seconds_since_last_certificate(&self) -> Option<u64> {
        self.last_certified.read().map(|t| t.elapsed().as_secs())
    }

    /// Checkpoint equivocations this validator's core has proof of.
    pub fn equivocations_seen(&self) -> u64 {
        self.equivocations.load(Ordering::Acquire)
    }

    /// Consensus frames dropped because the queue to their peer was full: a
    /// slow or stalled peer costs this node at most its queue, never more.
    pub fn dropped_frames(&self) -> u64 {
        self.dropped_frames.load(Ordering::Acquire)
    }

    /// Seats apportioned across a committee.
    pub fn seat_budget(&self) -> u64 {
        self.config.seat_budget
    }

    /// Records that a certificate starting at `height`, past the local tip,
    /// arrived: block-sync closes the gap at once instead of waiting for its
    /// next probe.
    pub fn note_behind_hint(&self, height: u64) {
        self.behind.send_if_modified(|h| {
            if height > *h {
                *h = height;
                true
            } else {
                false
            }
        });
    }

    /// Tells block sync this node is behind without naming a height: a
    /// validator that stood down knows the network is past it before it knows
    /// by how much. The hint channel keeps the wake until the engine reads
    /// it, so one sent while a round runs starts the next round at once.
    pub fn wake_block_sync(&self) {
        self.behind.send_modify(|_| {});
    }

    /// Records the latest checkpoint index a peer reports certified.
    pub fn note_network_checkpoint(&self, index: u64) {
        self.network_checkpoint.fetch_max(index, Ordering::AcqRel);
    }

    /// Heights block-sync is told this node is behind.
    pub fn subscribe_behind_hint(&self) -> tokio::sync::watch::Receiver<u64> {
        self.behind.subscribe()
    }

    /// Epoch-ending checkpoints, each delivered when its certificate is
    /// recorded.
    pub fn subscribe_epoch_certified(&self) -> tokio::sync::watch::Receiver<Option<Checkpoint>> {
        self.epoch_certified.subscribe()
    }

    /// The mempool.
    pub fn mempool(&self) -> &Arc<Mempool> {
        &self.mempool
    }

    /// The gas price a transaction this node signs itself (validator,
    /// settlement, attestation, registration) carries: the fee market's
    /// current minimum, read at signing time from the same calculation the
    /// mempool admits by.
    pub fn node_tx_gas_price(&self) -> u64 {
        self.mempool
            .current_min_gas_price(tenzro_consensus::admission::Lane::Open)
    }

    /// Wires the per-DID admission controller into the mempool. Fails if
    /// one is already set.
    pub fn set_admission(
        &self,
        admission: Arc<tenzro_consensus::AdmissionController>,
    ) -> Result<()> {
        self.mempool
            .set_admission(admission)
            .map_err(NodeError::from)
    }

    /// Wires the account state reader the mempool admits against (nonce
    /// ordering and balance coverage). Fails if one is already set.
    pub fn set_state_reader(
        &self,
        reader: Arc<dyn tenzro_consensus::mempool::AccountStateReader>,
    ) -> Result<()> {
        self.mempool
            .set_state_reader(reader)
            .map_err(NodeError::from)
    }

    /// The epoch manager.
    pub fn epoch_manager(&self) -> &Arc<EpochManager> {
        &self.epoch_manager
    }

    /// The current validator set.
    pub fn validator_set(&self) -> ValidatorSet {
        self.epoch_manager.current_validator_set()
    }

    /// Admits a transaction to the mempool.
    ///
    /// A beacon contribution for a round the beacon has left behind is
    /// refused here: it could only revert, and a reverted transaction still
    /// takes a place in a block and spends its sender's nonce.
    pub fn submit_transaction(&self, tx: SignedTransaction) -> Result<()> {
        if let Some(storage) = self.storage.as_ref() {
            let chain = tenzro_vm::StateAdapter::with_storage(storage.clone());
            if crate::beacon::is_stale_contribution(&chain, &tx.transaction.tx_type) {
                return Err(NodeError::from(tenzro_consensus::ConsensusError::Mempool(
                    "the beacon has moved past the round this contribution is for".to_string(),
                )));
            }
        }
        self.mempool.add_transaction(tx).map_err(NodeError::from)
    }

    /// Ordered and certified heights.
    pub fn finality(&self) -> FinalityStatus {
        FinalityStatus {
            ordered: self.ordered.load(Ordering::Acquire),
            certified: self.certified.load(Ordering::Acquire),
        }
    }

    /// Highest height covered by a checkpoint certificate.
    pub fn certified_height(&self) -> u64 {
        self.certified.load(Ordering::Acquire)
    }

    /// Highest ordered height.
    pub fn ordered_height(&self) -> u64 {
        self.ordered.load(Ordering::Acquire)
    }

    /// Highest height this node executed, from its own ordering or
    /// imported.
    pub fn executed_height(&self) -> u64 {
        self.executed.load(Ordering::Acquire)
    }

    /// The latest certificate.
    pub fn latest_certificate(&self) -> Option<Certificate> {
        self.latest.read().clone()
    }

    /// The certificate kept for checkpoint `index`, if any.
    pub fn certificate(&self, index: u64) -> Option<Certificate> {
        if let Some(c) = self
            .latest
            .read()
            .as_ref()
            .filter(|c| c.checkpoint.index == index)
        {
            return Some(c.clone());
        }
        self.records
            .as_ref()?
            .get(CF, &certificate_key(index))
            .ok()
            .flatten()
            .and_then(|b| bincode::deserialize(&b).ok())
    }

    /// The checkpoint body with `index`, if known.
    pub fn checkpoint(&self, index: u64) -> Option<Checkpoint> {
        self.records
            .as_ref()?
            .get(CF, &body_key(index))
            .ok()
            .flatten()
            .and_then(|b| bincode::deserialize(&b).ok())
    }

    /// Drops the bodies of checkpoints below `index`, keeping those that
    /// close or hand over an epoch. Archived history carries its own bodies.
    /// Returns how many were deleted.
    pub fn prune_bodies_below(&self, index: u64) -> usize {
        let Some(s) = &self.records else { return 0 };
        let prefix = b"consensus/checkpoint/";
        let mut ops = Vec::new();
        for key in s.get_keys_with_prefix(CF, prefix).unwrap_or_default() {
            let Some(i) = key
                .strip_prefix(prefix.as_slice())
                .and_then(|r| <[u8; 8]>::try_from(r).ok())
                .map(u64::from_be_bytes)
                .filter(|i| *i < index)
            else {
                continue;
            };
            let Some(cp) = self.checkpoint(i) else {
                continue;
            };
            let closes = cp.next_committee_root.is_some();
            let hands_over = self
                .boundary(cp.epoch)
                .is_some_and(|b| i == b + self.time.handover_confirmations);
            if !closes && !hands_over {
                ops.push(tenzro_storage::WriteOp::Delete {
                    cf: CF.to_string(),
                    key,
                });
            }
        }
        let n = ops.len();
        if n > 0
            && let Err(e) = s.write_batch(ops)
        {
            warn!(index, error = %e, "failed to prune checkpoint bodies below the history floor");
            return 0;
        }
        n
    }

    /// Drops every record of the epochs below `epoch`: their session
    /// certificates, the bodies and certificates of the checkpoints that
    /// close and hand them over, and their boundaries. Called once a proof
    /// of the handover chain covers those epochs and their history is
    /// archived: neither a proof of a checkpoint nor archived history needs
    /// them then, and these records stop growing with the chain's age.
    /// Returns how many records were deleted.
    pub fn prune_epoch_records_below(&self, epoch: u64) -> usize {
        let Some(s) = &self.records else { return 0 };
        let epoch_of = |key: &[u8], prefix: &[u8]| -> Option<u64> {
            let rest = key.strip_prefix(prefix)?;
            Some(u64::from_be_bytes(
                <[u8; 8]>::try_from(rest.get(..8)?).ok()?,
            ))
        };
        let delete = |key: Vec<u8>| tenzro_storage::WriteOp::Delete {
            cf: CF.to_string(),
            key,
        };
        let mut ops = Vec::new();
        let sessions = b"consensus/session/";
        for key in s.get_keys_with_prefix(CF, sessions).unwrap_or_default() {
            if epoch_of(&key, sessions).is_some_and(|e| e < epoch) {
                ops.push(delete(key));
            }
        }
        let boundaries = boundary_key(0);
        let boundaries = &boundaries[..boundaries.len() - 8];
        for key in s.get_keys_with_prefix(CF, boundaries).unwrap_or_default() {
            let Some(e) = epoch_of(&key, boundaries).filter(|e| *e < epoch) else {
                continue;
            };
            if let Some(index) = self.boundary(e) {
                for i in [index, index + self.time.handover_confirmations] {
                    for k in [body_key(i), certificate_key(i)] {
                        if s.get(CF, &k).ok().flatten().is_some() {
                            ops.push(delete(k));
                        }
                    }
                }
            }
            ops.push(delete(key));
        }
        let n = ops.len();
        if n > 0
            && let Err(e) = s.write_batch(ops)
        {
            warn!(epoch, error = %e, "failed to prune the records of epochs a chain proof covers");
            return 0;
        }
        n
    }

    /// Drops the compact certificates of checkpoints below `index`, and the
    /// full certificates kept there on the stride. Every checkpoint body,
    /// session certificate and epoch boundary stays, with the certificates
    /// that close and hand over each epoch: a proof from genesis and the
    /// verification of archived history need those. Returns how many
    /// certificates were deleted.
    pub fn prune_certificates_below(&self, index: u64) -> usize {
        let Some(s) = &self.records else { return 0 };
        let indexed = |key: &[u8], prefix: &[u8]| -> Option<u64> {
            let rest = key.strip_prefix(prefix)?;
            Some(u64::from_be_bytes(<[u8; 8]>::try_from(rest).ok()?))
        };
        let mut ops = Vec::new();
        for key in s
            .get_keys_with_prefix(CF, b"consensus/compact/")
            .unwrap_or_default()
        {
            if indexed(&key, b"consensus/compact/").is_some_and(|i| i < index) {
                ops.push(tenzro_storage::WriteOp::Delete {
                    cf: CF.to_string(),
                    key,
                });
            }
        }
        for key in s
            .get_keys_with_prefix(CF, b"consensus/certificate/")
            .unwrap_or_default()
        {
            let Some(i) = indexed(&key, b"consensus/certificate/").filter(|i| *i < index) else {
                continue;
            };
            let Some(cp) = self.checkpoint(i) else {
                continue;
            };
            let closes = cp.next_committee_root.is_some();
            let hands_over = self
                .boundary(cp.epoch)
                .is_some_and(|b| i == b + self.time.handover_confirmations);
            if !closes && !hands_over {
                ops.push(tenzro_storage::WriteOp::Delete {
                    cf: CF.to_string(),
                    key,
                });
            }
        }
        let n = ops.len();
        if n > 0
            && let Err(e) = s.write_batch(ops)
        {
            warn!(index, error = %e, "failed to prune certificates below the history floor");
            return 0;
        }
        n
    }

    /// Stores an authenticated checkpoint body.
    pub fn record_body(&self, cp: &Checkpoint) {
        if let Some(s) = &self.records
            && let Err(e) = s.put(
                CF,
                &body_key(cp.index),
                &bincode::serialize(cp).expect("checkpoint encodes"),
            )
        {
            warn!(index = cp.index, error = %e, "failed to persist checkpoint body");
        }
    }

    /// The stored checkpoint covering `height`, if any.
    pub fn checkpoint_covering(&self, height: u64) -> Option<Checkpoint> {
        self.checkpoint(self.covering_index(height)?)
    }

    /// Index of the stored checkpoint covering `height`, if any.
    fn covering_index(&self, height: u64) -> Option<u64> {
        let latest = self.latest.read().as_ref()?.checkpoint.index;
        let (mut lo, mut hi) = (0u64, latest);
        while lo <= hi {
            let mid = lo + (hi - lo) / 2;
            let cp = self.checkpoint(mid)?;
            if height < cp.first_height {
                hi = mid.checked_sub(1)?;
            } else if height > cp.last_height {
                lo = mid + 1;
            } else {
                return Some(mid);
            }
        }
        None
    }

    /// The stored checkpoint whose state root is the post-state of `height`,
    /// if one commits it: what a state proof at `height` verifies against.
    /// A checkpoint decided while no block was ordered commits the state
    /// after the last block, so the last transaction before an idle spell
    /// is provable without a later block.
    pub fn checkpoint_certifying_state(&self, height: u64) -> Option<Checkpoint> {
        let latest = self.latest.read().as_ref()?.checkpoint.index;
        let (mut lo, mut hi) = (0u64, latest);
        while lo <= hi {
            let mid = lo + (hi - lo) / 2;
            let cp = self.checkpoint(mid)?;
            match cp.state_height.cmp(&height) {
                std::cmp::Ordering::Equal => return Some(cp),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid.checked_sub(1)?,
            }
        }
        None
    }

    /// The certificate that ends the epoch whose last checkpoint is
    /// `boundary`: that checkpoint's own, or, when this node holds none (the
    /// quorum went on to the next index before signing it), the handover
    /// certificate after it, of the same epoch, which chains to it.
    fn epoch_end_certificate(&self, boundary: u64) -> Option<Certificate> {
        self.certificate(boundary)
            .or_else(|| self.certificate(boundary + self.time.handover_confirmations))
    }

    /// What moves a peer past the end of the epoch whose last checkpoint is
    /// `boundary`. A peer that already holds that end (its latest certified
    /// checkpoint is `known_checkpoint`) needs the handover certificate
    /// after it: its core enters the next epoch only on that one, and a
    /// validator cut off while its epoch ended may never receive it by
    /// gossip. Any other peer gets the end (see
    /// [`Self::epoch_end_certificate`]). The handover is served only with
    /// every body between it and the end: a peer short of the epoch's last
    /// blocks authenticates them only through that chain.
    fn epoch_end_for(&self, boundary: u64, known_checkpoint: Option<u64>) -> Option<Certificate> {
        let handover = boundary + self.time.handover_confirmations;
        if known_checkpoint.is_some_and(|k| k >= boundary)
            && (boundary..handover).all(|i| self.checkpoint(i).is_some())
            && let Some(c) = self.certificate(handover)
        {
            return Some(c);
        }
        self.epoch_end_certificate(boundary)
    }

    /// Evidence for a peer with every block this node holds: checkpoints
    /// that ordered no block still move the chain on, through epoch ends
    /// and handovers. From after `known_checkpoint`, the peer's latest
    /// certified checkpoint, it is the first epoch end (or the handover
    /// after it) the peer lacks, from the epoch of that checkpoint up to
    /// `known_epoch`, when this node recorded it, and otherwise this node's latest certificate when the
    /// peer can verify it (its epoch is at most `known_epoch`: right after an
    /// epoch ends, the latest are the old committee's handover
    /// confirmations), with the bodies before it: at most an epoch's worth,
    /// each authenticated through the certificate's predecessor digests.
    pub fn evidence_past_blocks(
        &self,
        known_epoch: u64,
        known_checkpoint: Option<u64>,
    ) -> (Vec<Checkpoint>, Option<Certificate>) {
        let from = known_checkpoint.map_or(0, |i| i + 1);
        // The first epoch end the peer has not moved past, from the epoch of
        // its latest certificate on: a validator whose core is still in that
        // epoch enters the next one only on its end and the handover after
        // it, whatever later committees it derived from executed blocks.
        let first_epoch = known_checkpoint
            .and_then(|k| self.checkpoint(k))
            .map_or(known_epoch, |c| c.epoch.min(known_epoch));
        let pending = (first_epoch..=known_epoch).find_map(|e| {
            self.boundary(e)
                .filter(|b| b + self.time.handover_confirmations >= from)
        });
        let cert = match pending {
            Some(b) if b >= from => self.epoch_end_certificate(b),
            b => {
                b.and_then(|b| self.epoch_end_for(b, known_checkpoint))
                    .filter(|c| c.checkpoint.index >= from)
                    .or_else(|| {
                        self.latest.read().clone().filter(|c| {
                            c.checkpoint.epoch <= known_epoch && c.checkpoint.index >= from
                        })
                    })
            }
        };
        let Some(cert) = cert else {
            debug!(
                known_epoch,
                ?known_checkpoint,
                boundary = ?self.boundary(known_epoch),
                boundary_body = ?self
                    .boundary(known_epoch)
                    .and_then(|b| self.checkpoint(b))
                    .map(|c| (c.epoch, c.index, c.next_committee_root.is_some())),
                latest = ?self.latest.read().as_ref().map(|c| (c.checkpoint.epoch, c.checkpoint.index)),
                "no evidence past the blocks for a peer"
            );
            return (Vec::new(), None);
        };
        let span = self
            .time
            .epoch_checkpoints
            .saturating_add(self.time.handover_confirmations);
        let lowest = from.max(cert.checkpoint.index.saturating_sub(span));
        let mut bodies = Vec::new();
        let mut i = cert.checkpoint.index;
        while i > lowest {
            i -= 1;
            match self.checkpoint(i) {
                Some(cp) => bodies.push(cp),
                None => break,
            }
        }
        bodies.reverse();
        (bodies, Some(cert))
    }

    /// Evidence for the blocks `first..=last`: the checkpoint bodies from the
    /// one covering `first` up to the nearest kept certificate, and that
    /// certificate. A peer holding the blocks authenticates every body
    /// through the certificate and its predecessor digests.
    ///
    /// The evidence never crosses an epoch boundary: an epoch's last
    /// checkpoint always has its certificate kept, and the evidence stops
    /// there, because the peer can verify a later epoch's certificate only
    /// after it has executed up to the boundary and derived that epoch's
    /// committee.
    ///
    /// `known_epoch` is the latest epoch whose committee the peer knows. If
    /// the peer already holds every block of that epoch but not its last
    /// checkpoint's certificate (the epoch ended on checkpoints ordering no
    /// block, or the peer missed the certificate), no later evidence can
    /// verify for it, so the evidence is that epoch's last checkpoint and
    /// its certificate, with the bodies from after the peer's tip.
    pub fn evidence_for(
        &self,
        first: u64,
        last: u64,
        known_epoch: u64,
        known_checkpoint: Option<u64>,
    ) -> (Vec<Checkpoint>, Option<Certificate>) {
        if let Some(boundary) = self.boundary(known_epoch)
            && let Some(end) = self.checkpoint(boundary)
            && end.last_height < first
            && let Some(cert) = self.epoch_end_for(boundary, known_checkpoint)
        {
            let from = first
                .checked_sub(1)
                .and_then(|tip| self.covering_index(tip))
                .map_or(0, |i| i + 1);
            let bodies = (from..cert.checkpoint.index)
                .map_while(|i| self.checkpoint(i))
                .collect();
            return (bodies, Some(cert));
        }
        let Some(from) = self.covering_index(first) else {
            return (Vec::new(), None);
        };
        let to = self.covering_index(last).unwrap_or(from);
        let latest = self
            .latest
            .read()
            .as_ref()
            .map_or(to, |c| c.checkpoint.index);
        let mut bodies = Vec::new();
        for index in from..=latest {
            let Some(cp) = self.checkpoint(index) else {
                break;
            };
            // A certificate past the epochs the peer knows cannot verify for
            // it: the evidence ends at its epoch's end or not at all.
            if cp.epoch > known_epoch {
                debug!(
                    known_epoch,
                    index, "no kept certificate for the end of the peer's epoch"
                );
                break;
            }
            // The epoch's end, or the handover after it, which chains to it.
            if cp.next_committee_root.is_some()
                && let Some(cert) = self.epoch_end_for(index, known_checkpoint)
            {
                bodies.extend((index..cert.checkpoint.index).map_while(|i| self.checkpoint(i)));
                return (bodies, Some(cert));
            }
            if index >= to
                && let Some(cert) = self.certificate(index)
            {
                return (bodies, Some(cert));
            }
            bodies.push(cp);
        }
        (bodies, None)
    }

    /// Whether this node runs as a validator of the current committee.
    pub fn is_validator(&self) -> bool {
        self.me.read().is_some()
    }

    /// This validator's turn to record the signers of `cert`'s epoch on
    /// chain: 0 for the committee member whose position is the epoch number
    /// modulo the committee size, 1 for the member after it, and so on round
    /// the committee. `None` when this node is no member of the
    /// checkpoint's epoch. Every member computes the same ranking, so
    /// exactly one holds rank 0 for all of an epoch's checkpoints; the
    /// others are the fallbacks, each waiting for its turn.
    ///
    /// The turn belongs to the epoch and not to the checkpoint. With one
    /// member per checkpoint, consecutive checkpoints fell to different
    /// members, whose records were ordered in any order: a later checkpoint's
    /// record that landed first made the earlier one's refused as "at or
    /// below one already recorded". One member sends an epoch's records in
    /// index order from one account, so they cannot overtake each other.
    pub fn record_rank(&self, cert: &Certificate) -> Option<u64> {
        let me = (*self.me.read())?;
        let committee = self
            .committees
            .read()
            .get(&cert.checkpoint.epoch)
            .cloned()?;
        let size = committee.members().len() as u64;
        if size == 0 || committee.member(me).is_none() {
            return None;
        }
        Some((u64::from(me) + size - cert.checkpoint.epoch % size) % size)
    }

    /// Whether this validator is the one that records the signers of
    /// `cert`'s epoch on chain first (see [`Self::record_rank`]).
    pub fn records_signers_of(&self, cert: &Certificate) -> bool {
        self.record_rank(cert) == Some(0)
    }

    /// The epoch of the running core and when it ends, in block time
    /// (milliseconds). `None` while this node runs no core, so it is no
    /// validator at the moment.
    pub fn epoch_window(&self) -> Option<(u64, u64)> {
        if !self.is_validator() {
            return None;
        }
        let ends = self.epoch_ends_ms.load(Ordering::Acquire);
        (ends > 0).then(|| (self.running_epoch.load(Ordering::Acquire), ends))
    }

    /// The genesis time rules.
    pub fn time_rules(&self) -> &TimeRules {
        &self.time
    }

    /// `cert` with the session certificate of every signer, as a
    /// transaction recording its signers carries it.
    pub fn signers_record(&self, cert: Certificate) -> PublishedCertificate {
        let sessions = self.session_bundle(&cert);
        PublishedCertificate {
            certificate: cert,
            sessions,
        }
    }

    /// The signers' accounts of the certificate a transaction carries, in a
    /// block of `block_epoch`. `Ok(Err(reason))` when it does not verify
    /// against the committee of its epoch with the session certificates it
    /// carries, or its epoch is neither the block's nor the one before: the
    /// transaction is left out of the block on every node alike. An error
    /// when this node does not hold that committee, so it cannot decide.
    pub fn certified_signers(
        &self,
        encoded: &[u8],
        block_epoch: u64,
    ) -> Result<std::result::Result<tenzro_vm::native::CheckpointSigners, String>> {
        let published = match bincode::deserialize::<PublishedCertificate>(encoded) {
            Ok(p) => p,
            Err(e) => return Ok(Err(format!("the certificate does not decode: {e}"))),
        };
        let cert = &published.certificate;
        let epoch = cert.checkpoint.epoch;
        if epoch != block_epoch && epoch.saturating_add(1) != block_epoch {
            return Ok(Err(format!(
                "checkpoint {} of epoch {epoch} reached a block of epoch {block_epoch}",
                cert.checkpoint.index
            )));
        }
        let committee = self
            .committee(epoch)
            .ok_or_else(|| NodeError::Other(format!("no committee known for epoch {epoch}")))?;
        let mut sessions = SessionBook::new(self.chain_id, self.genesis_hash, epoch);
        for s in published.sessions.iter().cloned() {
            let _ = sessions.admit(&committee, s);
        }
        let ctx = CertificateContext {
            chain_id: self.chain_id,
            genesis_hash: &self.genesis_hash,
            committee: &committee,
            sessions: &sessions,
        };
        if let Err(e) = cert.verify(&ctx) {
            return Ok(Err(format!(
                "checkpoint {} of epoch {epoch} does not verify with the {} session certificates it carries: {e}",
                cert.checkpoint.index,
                published.sessions.len()
            )));
        }
        let signers = cert
            .signers
            .iter()
            .filter_map(|s| committee.member(*s).map(|m| m.address))
            .collect();
        Ok(Ok(tenzro_vm::native::CheckpointSigners {
            epoch,
            index: cert.checkpoint.index,
            anchor_round: cert.checkpoint.anchor_round,
            signers,
        }))
    }

    /// Stops cutting new batches (the node is leaving); ordering continues.
    pub fn set_draining(&self, draining: bool) {
        self.draining.store(draining, Ordering::Release);
    }

    /// Whether the node is draining.
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Records, at start, the last block this node executed before it
    /// stopped. The executed blocks an epoch start is based on are otherwise
    /// known only from blocks executed since the process started: after a
    /// restart on a network that orders no new block for a while, an epoch
    /// end at the local tip would wait for an execution that never comes,
    /// and the validator could not follow the handover past it.
    pub fn seed_executed(&self, height: u64, block_hash: Hash, state_root: Hash) {
        self.executed.fetch_max(height, Ordering::AcqRel);
        let mut tail = self.executed_tail.lock();
        if tail.is_empty() {
            tail.push_back((height, block_hash.0, state_root.0));
        }
    }

    /// Whether the epoch ends at `height` and the next committee waits for
    /// that block's execution to be reported.
    pub fn closes_epoch_at(&self, height: u64) -> bool {
        *self.closing.lock() == Some(height)
    }

    /// Reports that the block at `height` was built and executed.
    /// When `height` ends the epoch, the next committee is derived now, from
    /// the state it produced.
    pub fn on_executed(&self, height: u64, block_hash: Hash, state_root: Hash) {
        self.ordered.fetch_max(height, Ordering::AcqRel);
        self.executed.fetch_max(height, Ordering::AcqRel);
        {
            let mut tail = self.executed_tail.lock();
            if tail.back().is_some_and(|(h, ..)| *h >= height) {
                tail.clear();
            }
            tail.push_back((height, block_hash.0, state_root.0));
            while tail.len() > EXECUTED_TAIL {
                tail.pop_front();
            }
        }
        if let Some(tx) = self.inputs.read().as_ref() {
            let _ = tx.send(Input::Executed {
                height,
                block_hash,
                state_root,
            });
        }
        let mut closing = self.closing.lock();
        if *closing == Some(height) {
            *closing = None;
            self.try_close(height, &mut closing);
        }
    }

    /// The epoch ends at `last_height`: derives the next committee now if
    /// that height is executed, or right after it is.
    fn epoch_ends(&self, last_height: u64) {
        let mut closing = self.closing.lock();
        // Only the executed height decides: a state root already in the trie
        // is written before the height is raised, and deriving in between
        // would be refused with nothing left to derive it later.
        if self.executed_height() >= last_height {
            *closing = None;
            self.try_close(last_height, &mut closing);
        } else {
            *closing = Some(last_height);
        }
    }

    /// Derives the next committee at `last_height`. When that fails the end
    /// stays pending and is tried again by [`Self::retry_close`], which the
    /// event loop calls each time it is still waiting to execute the next epoch's
    /// first block. A node that has executed past `last_height` without having
    /// derived the committee cannot derive it from the state it holds: that is
    /// reported loudly and the node has to be resynchronised.
    fn try_close(&self, last_height: u64, closing: &mut Option<u64>) {
        let result = self.close_epoch(last_height);
        if result.is_ok() {
            *self.close_retry.lock() = CloseRetry::default();
        }
        if let Err(e) = result {
            let executed = self.executed_height();
            if executed > last_height {
                tracing::error!(
                    height = last_height,
                    executed,
                    error = %e,
                    "this node executed past the end of an epoch without deriving the next committee; it must be resynchronised"
                );
            } else {
                let mut retry = self.close_retry.lock();
                retry.step = if retry.step.is_zero() {
                    CLOSE_RETRY_FIRST
                } else {
                    (retry.step * 2).min(CLOSE_RETRY_MAX)
                };
                retry.next = Instant::now() + retry.step;
                warn!(
                    height = last_height,
                    error = %e,
                    retry_in_s = retry.step.as_secs(),
                    "the next committee could not be derived; trying again"
                );
                *closing = Some(last_height);
            }
        }
    }

    /// Tries again to derive the next committee of an epoch whose end is
    /// pending because an earlier try failed, once the wait after the last
    /// failure is over. Storage work: call it off the async workers.
    pub fn retry_close(&self) {
        let mut closing = self.closing.lock();
        if let Some(last_height) = *closing
            && self.executed_height() == last_height
            && Instant::now() >= self.close_retry.lock().next
        {
            *closing = None;
            self.try_close(last_height, &mut closing);
        }
    }

    /// Whether a pending epoch end is due for another try. The engine asks on
    /// every tick, so a derivation that failed on a third of the validators
    /// is tried again without waiting for a block that cannot come.
    pub fn close_retry_due(&self) -> bool {
        let Some(closing) = self.closing.try_lock() else {
            return false;
        };
        closing.is_some_and(|l| self.executed_height() == l)
            && Instant::now() >= self.close_retry.lock().next
    }

    /// Verifies `cert` against the committee of its epoch and, if it is new,
    /// records it. Used by followers importing certified blocks.
    pub fn accept_certificate(&self, cert: &Certificate) -> Result<bool> {
        self.verify_certificate(cert)?;
        if self
            .latest
            .read()
            .as_ref()
            .is_some_and(|l| l.checkpoint.index >= cert.checkpoint.index)
        {
            return Ok(false);
        }
        self.record_certificate(cert);
        Ok(true)
    }

    /// Verifies `cert` against the committee of its epoch and the session
    /// certificates this node holds for it.
    pub fn verify_certificate(&self, cert: &Certificate) -> Result<()> {
        let (committee, sessions) = self.epoch_context(cert.checkpoint.epoch)?;
        let ctx = CertificateContext {
            chain_id: self.chain_id,
            genesis_hash: &self.genesis_hash,
            committee: &committee,
            sessions: &sessions,
        };
        cert.verify(&ctx)
            .map_err(|e| NodeError::from(tenzro_consensus::ConsensusError::from(e)))
    }

    /// Keeps `cert` as its epoch's handover when the closing body this node
    /// holds names it, whichever came first, the body or the certificate: a
    /// follower that took the handover before the bodies it authenticates
    /// it through must still serve it to a peer left in that epoch.
    pub fn keep_handover(&self, cert: &Certificate) {
        let confirmations = self.time.handover_confirmations;
        let epoch = cert.checkpoint.epoch;
        let index = cert.checkpoint.index;
        let Some(b) = index
            .checked_sub(confirmations)
            .filter(|_| confirmations > 0)
        else {
            return;
        };
        if !self
            .checkpoint(b)
            .is_some_and(|c| c.epoch == epoch && c.next_committee_root.is_some())
        {
            return;
        }
        if self.boundary(epoch).is_none() {
            self.record_boundary(epoch, b);
        }
        if let Some(s) = &self.records
            && let Err(e) = s.put(
                CF,
                &certificate_key(index),
                &bincode::serialize(cert).expect("certificate encodes"),
            )
        {
            warn!(index, error = %e, "failed to keep the handover certificate");
        }
    }

    fn record_certificate(&self, cert: &Certificate) {
        let index = cert.checkpoint.index;
        if let Some(s) = &self.records {
            let mut ops = vec![
                tenzro_storage::WriteOp::Put {
                    cf: CF.to_string(),
                    key: body_key(index),
                    value: bincode::serialize(&cert.checkpoint).expect("checkpoint encodes"),
                },
                tenzro_storage::WriteOp::Put {
                    cf: CF.to_string(),
                    key: LATEST_CERTIFICATE_KEY.to_vec(),
                    value: bincode::serialize(cert).expect("certificate encodes"),
                },
            ];
            // An epoch whose closing checkpoint never certified here has no
            // recorded boundary; its handover certificate names it through
            // the closing body this node holds.
            let epoch = cert.checkpoint.epoch;
            if self.time.handover_confirmations > 0
                && self.boundary(epoch).is_none()
                && let Some(b) = index.checked_sub(self.time.handover_confirmations)
                && self
                    .checkpoint(b)
                    .is_some_and(|c| c.epoch == epoch && c.next_committee_root.is_some())
            {
                self.record_boundary(epoch, b);
            }
            let handover = self
                .boundary(epoch)
                .is_some_and(|b| index == b + self.time.handover_confirmations);
            if index.is_multiple_of(CERTIFICATE_RETENTION_STRIDE)
                || cert.checkpoint.next_committee_root.is_some()
                || handover
            {
                debug!(
                    index,
                    epoch = cert.checkpoint.epoch,
                    closing = cert.checkpoint.next_committee_root.is_some(),
                    "certificate kept"
                );
                ops.push(tenzro_storage::WriteOp::Put {
                    cf: CF.to_string(),
                    key: certificate_key(index),
                    value: bincode::serialize(cert).expect("certificate encodes"),
                });
            }
            if let Err(e) = s.write_batch_sync(ops) {
                warn!(index, error = %e, "failed to persist checkpoint certificate");
            }
        }
        self.certified
            .fetch_max(cert.checkpoint.last_height, Ordering::AcqRel);
        self.ordered
            .fetch_max(cert.checkpoint.last_height, Ordering::AcqRel);
        *self.latest.write() = Some(cert.clone());
        *self.last_certified.write() = Some(Instant::now());
        if cert.checkpoint.next_committee_root.is_some() {
            // The handover is counted from here, whether the running core
            // certified the epoch's end itself or the node accepted it: a
            // validator cut off right after recognises the handover a peer
            // serves it only against this boundary.
            self.record_boundary(cert.checkpoint.epoch, index);
            self.epoch_certified
                .send_replace(Some(cert.checkpoint.clone()));
        }
    }

    /// Checks session certificates of `epoch` against the epoch's committee
    /// and keeps those that pass, in memory and on disk. Certificates of an
    /// epoch whose committee this node does not hold are ignored.
    pub fn admit_sessions(&self, epoch: u64, certs: Vec<SessionCertificate>) {
        let Some(committee) = self.committee(epoch) else {
            return;
        };
        let mut books = self.sessions.write();
        let book = books
            .entry(epoch)
            .or_insert_with(|| SessionBook::new(self.chain_id, self.genesis_hash, epoch));
        let mut ops = Vec::new();
        for c in certs {
            let digest = c.digest();
            if book.get(&digest).is_some() {
                continue;
            }
            match book.admit(&committee, c.clone()) {
                Ok(_) => ops.push(tenzro_storage::WriteOp::Put {
                    cf: CF.to_string(),
                    key: session_key(epoch, &digest),
                    value: bincode::serialize(&c).expect("session certificate encodes"),
                }),
                Err(e) => debug!(epoch, error = %e, "session certificate refused"),
            }
        }
        // Books of epochs two or more behind are only needed on disk.
        books.retain(|e, _| *e + 2 > epoch);
        drop(books);
        if !ops.is_empty()
            && let Some(s) = &self.records
            && let Err(e) = s.write_batch_sync(ops)
        {
            warn!(epoch, error = %e, "failed to persist session certificates");
        }
    }

    /// The session certificates `cert` names, as this node holds them: with
    /// the committee, all anyone needs to verify it.
    pub fn session_bundle(&self, cert: &Certificate) -> Vec<SessionCertificate> {
        let epoch = cert.checkpoint.epoch;
        if let Some(book) = self.sessions.read().get(&epoch) {
            return book.bundle(&cert.sessions);
        }
        let Some(s) = self.records.as_ref() else {
            return Vec::new();
        };
        cert.sessions
            .iter()
            .filter_map(|d| s.get(CF, &session_key(epoch, d)).ok().flatten())
            .filter_map(|b| bincode::deserialize(&b).ok())
            .collect()
    }

    /// `cert` as this node publishes it: with the session certificates it
    /// names that this node has not published in the epoch yet, and with all
    /// of them every [`FULL_BUNDLE_EVERY`]th checkpoint.
    pub fn publication(&self, cert: Certificate) -> PublishedCertificate {
        let bundle = self.session_bundle(&cert);
        let mut published = self.published_sessions.lock();
        if published.0 != cert.checkpoint.epoch {
            *published = (cert.checkpoint.epoch, HashSet::new());
        }
        let full = cert.checkpoint.index.is_multiple_of(FULL_BUNDLE_EVERY);
        let sessions: Vec<SessionCertificate> = bundle
            .into_iter()
            .filter(|s| full || !published.1.contains(&s.digest()))
            .collect();
        published.1.extend(sessions.iter().map(|s| s.digest()));
        PublishedCertificate {
            certificate: cert,
            sessions,
        }
    }

    /// The verification context of `epoch`: its committee and a copy of its
    /// session-certificate bundle, taken so that proving and verifying hold
    /// no lock.
    /// `epoch`'s committee and the session certificates this node holds for
    /// it: from memory for the last two epochs, from disk for older ones (a
    /// compact certificate proven after its fallback wait, or a certificate
    /// verified while catching up, may be of an epoch already left).
    fn epoch_context(&self, epoch: u64) -> Result<(Committee, SessionBook)> {
        let committee = self
            .committee(epoch)
            .ok_or_else(|| NodeError::Other(format!("no committee known for epoch {epoch}")))?;
        if let Some(book) = self.sessions.read().get(&epoch) {
            return Ok((committee, book.clone()));
        }
        let mut book = SessionBook::new(self.chain_id, self.genesis_hash, epoch);
        if let Some(s) = self.records.as_ref() {
            for (_, value) in s.scan_prefix(CF, &session_prefix(epoch))? {
                if let Ok(c) = bincode::deserialize::<SessionCertificate>(&value) {
                    let _ = book.admit(&committee, c);
                }
            }
        }
        Ok((committee, book))
    }

    /// The compact form of `cert`. Seconds of work on the compact pool, after
    /// any check running there; run it off the async runtime.
    pub fn prove_compact(&self, cert: &Certificate) -> Result<CompactCertificate> {
        let (committee, sessions) = self.epoch_context(cert.checkpoint.epoch)?;
        let ctx = CertificateContext {
            chain_id: self.chain_id,
            genesis_hash: &self.genesis_hash,
            committee: &committee,
            sessions: &sessions,
        };
        self.compact_work
            .run(|| tenzro_consensus::compact::prove(cert, &ctx, &self.setups))
            .map_err(NodeError::from)
    }

    /// Whether this node holds a compact certificate for checkpoint `index`
    /// or a later one.
    pub fn compact_covers(&self, index: u64) -> bool {
        self.compact
            .read()
            .as_ref()
            .is_some_and(|c| c.checkpoint.index >= index)
    }

    /// Verifies a compact certificate against the committee and bundle of
    /// its epoch and, if it is newer than the one held, records it. Returns
    /// whether it was recorded: one no newer than the one held is not
    /// checked at all, and one arriving while the compact pool is busy is
    /// passed over, since a later one supersedes it. Run it off the async
    /// runtime.
    pub fn accept_compact_certificate(&self, cc: &CompactCertificate) -> Result<bool> {
        if self.compact_covers(cc.checkpoint.index) {
            return Ok(false);
        }
        let (committee, sessions) = self.epoch_context(cc.checkpoint.epoch)?;
        let ctx = CertificateContext {
            chain_id: self.chain_id,
            genesis_hash: &self.genesis_hash,
            committee: &committee,
            sessions: &sessions,
        };
        let Some(checked) = self.compact_work.try_run(|| cc.verify(&ctx, &self.setups)) else {
            debug!(
                index = cc.checkpoint.index,
                "compact certificate passed over while another is proven or checked"
            );
            return Ok(false);
        };
        checked.map_err(|e| NodeError::from(tenzro_consensus::ConsensusError::from(e)))?;
        if self.compact_covers(cc.checkpoint.index) {
            return Ok(false);
        }
        self.record_compact(cc);
        Ok(true)
    }

    fn record_compact(&self, cc: &CompactCertificate) {
        if let Some(s) = &self.records {
            let bytes = bincode::serialize(cc).expect("compact certificate encodes");
            let ops = vec![
                tenzro_storage::WriteOp::Put {
                    cf: CF.to_string(),
                    key: LATEST_COMPACT_KEY.to_vec(),
                    value: bytes.clone(),
                },
                tenzro_storage::WriteOp::Put {
                    cf: CF.to_string(),
                    key: compact_key(cc.checkpoint.index),
                    value: bytes,
                },
            ];
            if let Err(e) = s.write_batch_sync(ops) {
                warn!(index = cc.checkpoint.index, error = %e, "failed to persist compact certificate");
            }
        }
        let mut latest = self.compact.write();
        if latest
            .as_ref()
            .is_none_or(|l| l.checkpoint.index < cc.checkpoint.index)
        {
            *latest = Some(cc.clone());
        }
    }

    /// The latest compact certificate, or the one kept for checkpoint
    /// `index`, with the session certificates its slots name.
    pub fn compact_certificate(
        &self,
        index: Option<u64>,
    ) -> Option<(CompactCertificate, Vec<SessionCertificate>)> {
        let cc = match index {
            None => self.compact.read().clone()?,
            Some(i) => {
                if let Some(c) = self
                    .compact
                    .read()
                    .as_ref()
                    .filter(|c| c.checkpoint.index == i)
                {
                    c.clone()
                } else {
                    bincode::deserialize(&self.records.as_ref()?.get(CF, &compact_key(i)).ok()??)
                        .ok()?
                }
            }
        };
        let digests: Vec<[u8; 32]> = cc.slots.iter().flatten().copied().collect();
        let epoch = cc.checkpoint.epoch;
        let sessions = match self.sessions.read().get(&epoch) {
            Some(book) => book.bundle(&digests),
            None => {
                let s = self.records.as_ref()?;
                digests
                    .iter()
                    .filter_map(|d| s.get(CF, &session_key(epoch, d)).ok().flatten())
                    .filter_map(|b| bincode::deserialize(&b).ok())
                    .collect()
            }
        };
        Some((cc, sessions))
    }

    /// The committee of `epoch`, from memory or rebuilt from the epoch
    /// manager's validator set of that epoch.
    pub fn committee_of(&self, epoch: u64) -> Option<Committee> {
        self.committee(epoch).or_else(|| {
            let set = self.epoch_manager.get_validator_set(epoch)?;
            tenzro_consensus::committee::from_validator_set(&set, self.config.seat_budget).ok()
        })
    }

    /// What a light client needs to move past `epoch`: the certificate of the
    /// checkpoint that ends it, the session certificates that certificate
    /// names, and the members of the committee it commits.
    pub fn handover(
        &self,
        epoch: u64,
    ) -> Option<(Certificate, Vec<SessionCertificate>, Committee)> {
        let index = self.boundary(epoch)?;
        let cert = self.certificate(index)?;
        let next = self.committee_of(epoch + 1)?;
        let sessions = self.session_bundle(&cert);
        Some((cert, sessions, next))
    }

    /// Proof from genesis that checkpoint `index` is certified: the genesis
    /// committee, every epoch handover before its epoch, and its certificate.
    /// `None` when any of them is not kept here.
    pub fn checkpoint_proof(
        &self,
        index: u64,
    ) -> Option<tenzro_consensus::light_client::CheckpointProof> {
        let certificate = self.certificate(index)?;
        let handovers = (0..certificate.checkpoint.epoch)
            .map(|epoch| {
                let (certificate, sessions, next) = self.handover(epoch)?;
                Some(tenzro_consensus::light_client::EpochHandover {
                    certificate,
                    sessions,
                    next_members: next.members().to_vec(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(tenzro_consensus::light_client::CheckpointProof {
            genesis_members: self.committee_of(0)?.members().to_vec(),
            handovers,
            sessions: self.session_bundle(&certificate),
            certificate,
        })
    }

    /// Adds the committee of a later epoch, once the certificate that
    /// commits it has been accepted.
    pub fn add_committee(&self, committee: Committee) {
        let mut committees = self.committees.write();
        committees.insert(committee.epoch, committee);
        let newest = committees.keys().copied().max().unwrap_or(0);
        committees.retain(|epoch, _| epoch + COMMITTEES_KEPT > newest);
    }

    /// Prepares this node for the recovery epoch `to_epoch` its epoch manager
    /// now holds (see [`tenzro_consensus::EpochManager::install_recovery_epoch`]):
    /// builds and keeps that epoch's committee, replacing one the halted chain
    /// had derived, and ends the recovery journal of the epoch this node was
    /// running, which no committee will ever continue. A journal of
    /// `to_epoch` itself is left alone, so a restart after the recovery epoch
    /// started recovers its core instead of starting a second one.
    pub fn begin_recovery_epoch(&self, to_epoch: u64) -> Result<()> {
        let set = self
            .epoch_manager
            .get_validator_set(to_epoch)
            .ok_or_else(|| {
                NodeError::Other(format!("the validator set of epoch {to_epoch} is not kept"))
            })?;
        let committee =
            tenzro_consensus::committee::from_validator_set(&set, self.config.seat_budget)?;
        if let Some(s) = &self.records
            && let Some(active) = s.get(CF, ACTIVE_KEY)?
        {
            let (running, _): (u64, EpochStart) = bincode::deserialize(&active)
                .map_err(|e| NodeError::Other(format!("active consensus epoch: {e}")))?;
            if running != to_epoch {
                self.end_epoch_journal(running, None);
            }
        }
        self.add_committee(committee);
        Ok(())
    }

    /// The latest epoch whose committee this node knows: the epoch it can
    /// verify certificates of, and past whose end it cannot yet follow.
    pub fn known_epoch(&self) -> u64 {
        self.committees.read().keys().copied().max().unwrap_or(0)
    }

    /// The index of `epoch`'s last checkpoint, if this node recorded it.
    fn boundary(&self, epoch: u64) -> Option<u64> {
        if let Some(i) = self.boundaries.read().get(&epoch).copied() {
            return Some(i);
        }
        let b = self
            .records
            .as_ref()?
            .get(CF, &boundary_key(epoch))
            .ok()??;
        Some(u64::from_be_bytes(<[u8; 8]>::try_from(b.as_slice()).ok()?))
    }

    /// The committee of `epoch`, if known.
    /// The committee of `epoch`, if known: one derived or adopted since the
    /// node started, or, for an epoch no later than the epoch manager's
    /// current one, the validator set it keeps for that epoch. A restarted
    /// node resumes where blocks may still carry certificates of epochs
    /// before the latest two.
    pub fn committee(&self, epoch: u64) -> Option<Committee> {
        if let Some(c) = self.committees.read().get(&epoch) {
            return Some(c.clone());
        }
        if epoch > self.epoch_manager.current_epoch().number {
            return None;
        }
        let set = self.epoch_manager.get_validator_set(epoch)?;
        let committee =
            tenzro_consensus::committee::from_validator_set(&set, self.config.seat_budget).ok()?;
        let mut committees = self.committees.write();
        let newest = committees.keys().copied().max().unwrap_or(epoch).max(epoch);
        // An older epoch's committee is rebuilt when asked for, not kept.
        if epoch + COMMITTEES_KEPT <= newest {
            return Some(committee);
        }
        committees.entry(epoch).or_insert(committee).clone().into()
    }

    /// Starts consensus for `epoch` from `start`, if a launcher is installed
    /// and its key is seated in that epoch's committee. Otherwise the node
    /// keeps following.
    pub fn launch(&self, epoch: u64, start: EpochStart) -> Result<()> {
        let Some((launcher, committee, me)) = self.seat(epoch)? else {
            return Ok(());
        };
        self.persist_active(epoch, &start)?;
        let core = Core::new(
            governed_timing(&self.config, self.storage.as_ref()).core(
                self.chain_id,
                self.genesis_hash,
                &self.time,
            ),
            committee.clone(),
            me,
            start,
        );
        self.spawn_engine(launcher, committee, me, core, 0, 0);
        info!(epoch, validator = me, "consensus started");
        Ok(())
    }

    /// After a restart: rebuilds this validator's core for the epoch it was
    /// running from its recovery journal, and carries on in that epoch.
    /// `executed_through` is the local tip. Returns whether consensus runs.
    pub fn resume(&self, executed_through: u64) -> Result<bool> {
        self.executed.fetch_max(executed_through, Ordering::AcqRel);
        let Some(storage) = self.records.as_ref() else {
            return Ok(false);
        };
        let Some(active) = storage.get(CF, ACTIVE_KEY)? else {
            return Ok(false);
        };
        let (epoch, start): (u64, EpochStart) = bincode::deserialize(&active)
            .map_err(|e| NodeError::Other(format!("active consensus epoch: {e}")))?;
        let Some((launcher, committee, me)) = self.seat(epoch)? else {
            return Ok(false);
        };
        let mut records = Vec::new();
        let mut next_seq = 0;
        for (key, value) in storage.scan_prefix(CF, &journal_prefix(epoch))? {
            let seq = key
                .get(key.len().saturating_sub(8)..)
                .and_then(|b| <[u8; 8]>::try_from(b).ok());
            next_seq = next_seq.max(seq.map_or(0, u64::from_be_bytes) + 1);
            let batch: Vec<Record> = bincode::deserialize(&value)
                .map_err(|e| NodeError::Other(format!("consensus journal: {e}")))?;
            records.extend(batch);
        }
        let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
        let mut core = Core::recover(
            governed_timing(&self.config, self.storage.as_ref()).core(
                self.chain_id,
                self.genesis_hash,
                &self.time,
            ),
            committee.clone(),
            me,
            start,
            records,
            executed_through,
            now,
        );
        if let Some(c) = self
            .latest_certificate()
            .filter(|c| c.checkpoint.epoch == epoch)
        {
            let sessions = self.session_bundle(&c);
            let confirmations = self.time.handover_confirmations;
            let closed_by_held_body = c
                .checkpoint
                .index
                .checked_sub(confirmations)
                .filter(|b| *b != c.checkpoint.index)
                .and_then(|b| self.checkpoint(b))
                .is_some_and(|k| k.epoch == epoch && k.next_committee_root.is_some());
            if closed_by_held_body {
                core.adopt_handover(c, sessions);
            } else {
                core.adopt_certificate(c, sessions);
            }
        }
        self.spawn_engine(launcher, committee, me, core, next_seq, executed_through);
        info!(
            epoch,
            validator = me,
            executed_through,
            "consensus recovered"
        );
        Ok(true)
    }

    /// The launcher, `epoch`'s committee and this node's index in it, if a
    /// launcher is installed and its key is seated.
    fn seat(&self, epoch: u64) -> Result<Option<(Launcher, Committee, ValidatorIndex)>> {
        let Some(launcher) = self.launcher.read().clone() else {
            return Ok(None);
        };
        let committee = self
            .committee(epoch)
            .ok_or_else(|| NodeError::Other(format!("no committee known for epoch {epoch}")))?;
        let Some((signer, me)) = self.key_for(&committee, &launcher.signer) else {
            debug!(epoch, "this node's validator key is not seated; following");
            return Ok(None);
        };
        Ok(Some((Launcher { signer, ..launcher }, committee, me)))
    }

    /// Records durably which epoch this validator's core runs and where it
    /// started, so a restart can recover it.
    fn persist_active(&self, epoch: u64, start: &EpochStart) -> Result<()> {
        if let Some(s) = &self.records {
            s.write_batch_sync(vec![tenzro_storage::WriteOp::Put {
                cf: CF.to_string(),
                key: ACTIVE_KEY.to_vec(),
                value: bincode::serialize(&(epoch, start)).expect("epoch start encodes"),
            }])?;
        }
        Ok(())
    }

    /// Drops the recovery journal of `epoch` and nothing else.
    fn drop_epoch_journal(&self, epoch: u64) {
        let Some(s) = &self.records else { return };
        let ops: Vec<tenzro_storage::WriteOp> = s
            .get_keys_with_prefix(CF, &journal_prefix(epoch))
            .unwrap_or_default()
            .into_iter()
            .map(|key| tenzro_storage::WriteOp::Delete {
                cf: CF.to_string(),
                key,
            })
            .collect();
        if !ops.is_empty()
            && let Err(e) = s.write_batch_sync(ops)
        {
            warn!(epoch, error = %e, "failed to drop the consensus journal");
        }
    }

    /// Drops the recovery journal of `epoch` and, when `next` is given,
    /// records the epoch the core moves to; otherwise that no core runs.
    fn end_epoch_journal(&self, epoch: u64, next: Option<(u64, &EpochStart)>) {
        let Some(s) = &self.records else { return };
        let mut ops: Vec<tenzro_storage::WriteOp> = s
            .get_keys_with_prefix(CF, &journal_prefix(epoch))
            .unwrap_or_default()
            .into_iter()
            .map(|key| tenzro_storage::WriteOp::Delete {
                cf: CF.to_string(),
                key,
            })
            .collect();
        ops.push(match next {
            Some((e, start)) => tenzro_storage::WriteOp::Put {
                cf: CF.to_string(),
                key: ACTIVE_KEY.to_vec(),
                value: bincode::serialize(&(e, start)).expect("epoch start encodes"),
            },
            None => tenzro_storage::WriteOp::Delete {
                cf: CF.to_string(),
                key: ACTIVE_KEY.to_vec(),
            },
        });
        if let Err(e) = s.write_batch_sync(ops) {
            warn!(epoch, error = %e, "failed to rotate the consensus journal");
        }
    }

    fn spawn_engine(
        &self,
        launcher: Launcher,
        committee: Committee,
        me: ValidatorIndex,
        core: Core,
        journal_seq: u64,
        executed_through: u64,
    ) {
        let committee_epoch = committee.epoch;
        // Certify the session key for this epoch now, off the engine, so the
        // epoch's first vote does not wait for the hardware.
        let certifier = self.certifier(launcher.signer.clone());
        tokio::task::spawn_blocking(move || {
            if let Err(e) = certifier.certificate(committee_epoch) {
                warn!(epoch = committee_epoch, error = %e, "the session key could not be certified");
            }
        });
        let (tx, rx) = mpsc::unbounded_channel();
        // A new core has taken no handover and fast-forwards to nothing yet,
        // whatever the core before it left here.
        self.awaiting_handover.store(false, Ordering::Release);
        self.fast_forward_to.store(0, Ordering::Release);
        *self.inputs.write() = Some(tx.clone());
        *self.me.write() = Some(me);
        let links = Arc::new(Links {
            endpoint: launcher.endpoint.clone(),
            identity: launcher.identity.clone(),
            session: self.session.clone(),
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            committee: RwLock::new(committee),
            me: RwLock::new(me),
            inputs: tx,
            endpoints: self.endpoints.clone(),
            announcement: self.announcement.clone(),
            channels: EpochChannels::new(committee_epoch),
            dial_diag: parking_lot::Mutex::new(HashMap::new()),
            dial_stage: parking_lot::Mutex::new(HashMap::new()),
        });
        launcher.handler.set(links.clone());
        links.dial_all();
        let beat = Arc::new(EngineBeat::default());
        {
            let beat = beat.clone();
            let handle = self.self_arc();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if Arc::strong_count(&beat) == 1 {
                        return;
                    }
                    let at = beat.at_ms.load(Ordering::Acquire);
                    let stale = unix_ms().saturating_sub(at);
                    if at != 0 && stale > 5_000 {
                        warn!(
                            validator = ?*handle.me.read(),
                            epoch = committee_epoch,
                            phase = beat.phase.load(Ordering::Acquire),
                            stale_ms = stale,
                            "diag: this validator's consensus engine has not looped"
                        );
                    }
                }
            });
        }
        let engine = Engine {
            beat,
            handle: self.self_arc(),
            core,
            links,
            signer: launcher.signer,
            high_water: launcher.high_water,
            inputs: rx,
            peers: HashMap::new(),
            bulk_peers: HashMap::new(),
            segments: launcher.segments,
            certificates: launcher.certificates,
            compact: launcher.compact,
            evidence: launcher.evidence,
            in_flight: HashMap::new(),
            failover: governed_failover(self.storage.as_ref()),
            ordered: HashMap::new(),
            first_seen: HashMap::new(),
            stepped_in: HashMap::new(),
            batch_seq: 0,
            last_batch: Instant::now(),
            next_committee: None,
            pending_handover: None,
            batched_at: HashMap::new(),
            ordered_latencies: OrderedLatencies::new(),
            egress_bytes: 0,
            certificate_bytes: 0,
            last_metrics: (Instant::now(), 0, 0),
            buffers_over: false,
            journal_seq,
            slow_journal: Default::default(),
            executed_through,
            sent_through: executed_through,
            catching_up: None,
            fast_forward_since: None,
            standing_down: false,
            stopping: false,
            peer_route_missing_since: HashMap::new(),
        };
        self.committed_round
            .store(engine.core.reach_round().unwrap_or(0), Ordering::Release);
        self.epoch_ends_ms
            .store(engine.core.epoch_ends_ms(), Ordering::Release);
        self.running_epoch.store(committee_epoch, Ordering::Release);
        DIAG_WATCH.call_once(|| {
            tokio::spawn(async {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let beat = DIAG_BEAT.load(Ordering::Acquire);
                    let stale = unix_ms().saturating_sub(beat);
                    if beat != 0 && stale > 5_000 {
                        warn!(
                            phase = DIAG_PHASE.load(Ordering::Acquire),
                            stale_ms = stale,
                            "diag: consensus engine has not looped"
                        );
                    }
                }
            });
        });
        tokio::spawn(engine.run());
    }

    fn self_arc(&self) -> Arc<Self> {
        self.this
            .upgrade()
            .expect("the handle is alive while it is used")
    }
}

/// Connections to the other committee members.
struct Links {
    endpoint: tenzro_iroh::Endpoint,
    /// Where members' endpoint records resolve.
    identity: Option<Arc<tenzro_iroh::IdentityTransport>>,
    /// This boot's session key, which signs the handshakes.
    session: Arc<SessionKey>,
    chain_id: u64,
    genesis_hash: [u8; 32],
    committee: RwLock<Committee>,
    me: RwLock<ValidatorIndex>,
    inputs: mpsc::UnboundedSender<Input>,
    endpoints: Arc<RwLock<EndpointBook>>,
    announcement: Arc<RwLock<Option<(EndpointAnnouncement, EndpointOpening)>>>,
    /// Open channels per epoch and peer, either direction.
    channels: EpochChannels,
    /// diag: per-peer keep_dialled() activity, added to chase chaos seed
    /// 3054677367's peer set collapsing to one or two live channels and
    /// never recovering. (attempts,
    /// is_open skips, last activity ms, last dial result).
    dial_diag: parking_lot::Mutex<HashMap<ValidatorIndex, (u64, u64, u64, String)>>,
    /// diag: the stage name and start time (ms) of each peer's currently
    /// in-flight dial() call, if any -- cleared when dial() returns. An
    /// entry surviving many ticks in a row for a peer not in `peers`
    /// localises exactly which await inside dial() that call is stuck on.
    dial_stage: parking_lot::Mutex<HashMap<ValidatorIndex, (&'static str, u64)>>,
}

/// The consensus channels open per epoch and peer, with the inbound byte
/// budget the peer's channels share. A channel belongs to the epoch whose
/// committee its handshake bound, and closes once the node enters the next
/// epoch; only a channel of the running epoch counts as up.
///
/// Holds every live channel's own outbound sender, not just a count: under
/// loss both sides can dial at once, so two channels to the same peer can both be up while the engine
/// (`Engine.peers`) keeps only the sender of whichever one's `PeerUp`
/// arrived last. If that one later dies, its `PeerDown` used to remove the
/// engine's only route to the peer even though an older channel was still
/// healthy -- the dialler saw `is_open` stay true on the survivor and never
/// redialled, so the peer was never heard from again until the survivor
/// itself eventually died. A dying channel now looks up whether a sibling
/// survives and, if so, hands its sender back to be promoted with a fresh
/// `PeerUp` (see `run_channel`'s teardown), so the engine's route and the
/// dialler's "is this peer open" view can never disagree about which
/// channel, if any, is still alive.
struct EpochChannels {
    open: parking_lot::Mutex<HashMap<(u64, ValidatorIndex, StreamKind), OpenPeer>>,
    epoch: tokio::sync::watch::Sender<u64>,
    next_lease_id: std::sync::atomic::AtomicU64,
}

/// One peer's live channels in one epoch.
struct OpenPeer {
    /// Bytes received from the peer and not yet handled by the core, shared
    /// by every channel the peer holds.
    inbound: Arc<tokio::sync::Semaphore>,
    /// Each live channel's outbound sender, by the lease that holds it.
    live: HashMap<u64, PeerQueue>,
    /// Bumped to force every live channel of this peer to end at once: the
    /// progress-based backstop for a route the engine cannot explain any
    /// other way (see `Engine`'s per-tick peer-route check).
    closing: tokio::sync::watch::Sender<u64>,
}

/// One open channel's place in [`EpochChannels`], released when dropped.
struct ChannelLease<'a> {
    channels: &'a EpochChannels,
    epoch: u64,
    peer: ValidatorIndex,
    kind: StreamKind,
    id: u64,
    current: tokio::sync::watch::Receiver<u64>,
    closing: tokio::sync::watch::Receiver<u64>,
    closing_seen: u64,
    /// Bytes received from the peer and not yet handled by the core, shared
    /// by every channel the peer holds.
    inbound: Arc<tokio::sync::Semaphore>,
}

impl EpochChannels {
    fn new(epoch: u64) -> Self {
        Self {
            open: parking_lot::Mutex::new(HashMap::new()),
            epoch: tokio::sync::watch::Sender::new(epoch),
            next_lease_id: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Whether a channel of `epoch` and `kind` to `peer` is open.
    fn is_open(&self, epoch: u64, peer: ValidatorIndex, kind: StreamKind) -> bool {
        self.open
            .lock()
            .get(&(epoch, peer, kind))
            .is_some_and(|p| !p.live.is_empty())
    }

    /// Records a channel of `epoch` and `kind` to `peer`, with the sender
    /// that routes outbound traffic through it; None once the node has left
    /// that epoch, or while the peer holds [`MAX_CHANNELS_PER_PEER`]
    /// channels of this kind, when the channel must not come up. Control
    /// and bulk channels to the same peer are tracked separately: a flood
    /// on one cannot exhaust the other's lease slots or inbound budget.
    fn open(
        &self,
        epoch: u64,
        peer: ValidatorIndex,
        kind: StreamKind,
        sender: PeerQueue,
    ) -> Option<ChannelLease<'_>> {
        let current = self.epoch.subscribe();
        let mut open = self.open.lock();
        // The current epoch, or exactly the one after it: a channel for the
        // next epoch may be dialled ahead of its own handover
        // (`Links::pre_dial_next_epoch`), while this node's own epoch is
        // still the one running now, so this must not refuse it the way it
        // refuses anything older or further ahead.
        if epoch != *current.borrow() && epoch != *current.borrow() + 1 {
            return None;
        }
        let entry = open.entry((epoch, peer, kind)).or_insert_with(|| OpenPeer {
            inbound: Arc::new(tokio::sync::Semaphore::new(PEER_INBOUND_BYTES as usize)),
            live: HashMap::new(),
            closing: tokio::sync::watch::Sender::new(0),
        });
        if entry.live.len() >= MAX_CHANNELS_PER_PEER {
            return None;
        }
        let id = self
            .next_lease_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        entry.live.insert(id, sender);
        Some(ChannelLease {
            channels: self,
            epoch,
            peer,
            kind,
            id,
            current,
            closing: entry.closing.subscribe(),
            closing_seen: *entry.closing.borrow(),
            inbound: entry.inbound.clone(),
        })
    }

    /// Moves to `epoch`: every channel of an earlier one ends.
    fn enter(&self, epoch: u64) {
        let _open = self.open.lock();
        self.epoch.send_replace(epoch);
    }

    /// Every channel already open for `epoch`, one sender per (peer, kind):
    /// what `Links::pre_dial_next_epoch` may have already established by the
    /// time this node actually enters that epoch.
    fn open_now(&self, epoch: u64) -> Vec<(ValidatorIndex, StreamKind, PeerQueue)> {
        self.open
            .lock()
            .iter()
            .filter(|((e, ..), _)| *e == epoch)
            .filter_map(|((_, peer, kind), entry)| {
                entry
                    .live
                    .values()
                    .next()
                    .cloned()
                    .map(|s| (*peer, *kind, s))
            })
            .collect()
    }

    /// Forces every live control channel of `epoch` to `peer` to end,
    /// whether or not any of them look unhealthy on their own: the backstop
    /// for a route the engine cannot otherwise explain (`is_open` true, no
    /// sender in `Engine.peers`, for longer than `PEER_ROUTE_STALL`). Bulk
    /// channels carry nothing the engine's routing table depends on, so
    /// they are not part of this backstop.
    fn force_close(&self, epoch: u64, peer: ValidatorIndex) {
        if let Some(entry) = self.open.lock().get(&(epoch, peer, StreamKind::Control)) {
            entry.closing.send_modify(|g| *g += 1);
        }
    }
}

/// Why a [`ChannelLease`] ended, from [`ChannelLease::ended_or_closed`].
enum LeaseEnd {
    /// The node moved to the next epoch; this one's channels wind down.
    Ended,
    /// The engine force-closed this peer's channels (the progress-based
    /// backstop, `Engine::check_peer_routes`), unrelated to the epoch.
    Closed,
}

impl ChannelLease<'_> {
    /// Resolves once the node has left this channel's epoch, or once this
    /// channel's peer has been force-closed -- whichever comes first. Both
    /// wait on their own field's `watch::Receiver`, so this races them in
    /// one `&mut self` call instead of two, which a `tokio::select!` with
    /// one bound per field cannot otherwise express.
    async fn ended_or_closed(&mut self) -> LeaseEnd {
        let epoch = self.epoch;
        let closing_seen = self.closing_seen;
        tokio::select! {
            _ = self.current.wait_for(|e| *e > epoch) => LeaseEnd::Ended,
            _ = self.closing.wait_for(|g| *g != closing_seen) => LeaseEnd::Closed,
        }
    }

    /// Removes this lease's own channel from the registry and, if another
    /// live channel to the same peer survives, returns its sender so the
    /// caller can promote it with a fresh `PeerUp` -- the engine's only
    /// route to the peer must never go missing while a channel the dialler
    /// still considers open is in fact still alive.
    fn retire(&self) -> Option<PeerQueue> {
        let mut open = self.channels.open.lock();
        let entry = open.get_mut(&(self.epoch, self.peer, self.kind))?;
        entry.live.remove(&self.id);
        let survivor = entry.live.values().next().cloned();
        if entry.live.is_empty() {
            open.remove(&(self.epoch, self.peer, self.kind));
        }
        survivor
    }
}

impl Drop for ChannelLease<'_> {
    fn drop(&mut self) {
        // Idempotent with `retire`: a lease retired explicitly before
        // dropping leaves nothing here to remove.
        let mut open = self.channels.open.lock();
        if let Some(entry) = open.get_mut(&(self.epoch, self.peer, self.kind)) {
            entry.live.remove(&self.id);
            if entry.live.is_empty() {
                open.remove(&(self.epoch, self.peer, self.kind));
            }
        }
    }
}

impl std::fmt::Debug for Links {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Links")
            .field("me", &*self.me.read())
            .finish()
    }
}

async fn read_msg<T: serde::de::DeserializeOwned>(recv: &mut tenzro_iroh::RecvStream) -> Result<T> {
    let bytes = tenzro_iroh::read_frame(recv, 64 * 1024)
        .await
        .map_err(|e| NodeError::Other(e.to_string()))?;
    bincode::deserialize(&bytes).map_err(|e| NodeError::Other(format!("handshake message: {e}")))
}

async fn write_msg<T: serde::Serialize>(send: &mut tenzro_iroh::SendStream, m: &T) -> Result<()> {
    let bytes = bincode::serialize(m).expect("handshake message encodes");
    tenzro_iroh::write_frame(send, &bytes)
        .await
        .map_err(|e| NodeError::Other(e.to_string()))
}

/// Acquires `cost` of `budget`'s permits: the frame's share of the peer's
/// shared inbound byte budget, released once the core has handled it.
async fn acquire_inbound_budget(
    budget: &Arc<tokio::sync::Semaphore>,
    cost: u32,
) -> Result<tokio::sync::OwnedSemaphorePermit> {
    match tokio::time::timeout(
        INBOUND_BUDGET_STALL,
        budget.clone().acquire_many_owned(cost),
    )
    .await
    {
        Ok(Ok(held)) => Ok(held),
        Ok(Err(_)) => Err(NodeError::Other("inbound budget closed".into())),
        Err(_) => Err(NodeError::Other(format!(
            "the core did not free this peer's inbound budget within {}s",
            INBOUND_BUDGET_STALL.as_secs()
        ))),
    }
}

/// The connection's rtt estimate on its currently selected path, or a
/// generous guess before one has settled: treating an unmeasured path as 0
/// would floor every rtt-scaled budget at its minimum right when a slow
/// path most needs the room.
fn path_rtt(conn: &tenzro_iroh::Connection) -> Duration {
    conn.paths()
        .iter()
        .find(|p| p.is_selected())
        .map(|p| p.rtt())
        .unwrap_or(Duration::from_millis(100))
}

/// `max(HANDSHAKE_TIMEOUT, HANDSHAKE_RTT_FACTOR * rtt)`: the application
/// handshake's budget once the QUIC connection is up, scaled to the path
/// rather than a fixed LAN-sized constant. `scale` grows this further on a
/// retry after a handshake specifically timed out (see `keep_dialled`), not
/// on any other kind of dial failure.
fn handshake_budget(rtt: Duration, scale: u32) -> Duration {
    (rtt * HANDSHAKE_RTT_FACTOR)
        .max(HANDSHAKE_TIMEOUT)
        .saturating_mul(scale)
        .min(HANDSHAKE_RETRY_CAP)
}

/// `max(CHANNEL_SILENCE, SILENCE_RTT_FACTOR * rtt)`: how long an established
/// channel's read side may go quiet before it is called silent, scaled to
/// the path it actually runs over.
fn silence_budget(rtt: Duration) -> Duration {
    (rtt * SILENCE_RTT_FACTOR).max(CHANNEL_SILENCE)
}

impl Links {
    fn context_parts(&self) -> (Committee, ValidatorIndex) {
        (self.committee.read().clone(), *self.me.read())
    }

    /// Moves the links to `next`'s epoch, closing every channel of the old
    /// one.
    fn enter_epoch(&self, next: Committee) {
        let epoch = next.epoch;
        *self.committee.write() = next;
        self.channels.enter(epoch);
    }

    /// Forces every live channel this node holds to `peer` in its current
    /// epoch to end, for the progress-based backstop (see `Engine`'s
    /// per-tick peer-route check): a route the engine cannot otherwise
    /// explain is closed outright and left to redial fresh, rather than
    /// trusted a moment longer.
    fn force_close_peer(&self, peer: ValidatorIndex) {
        let epoch = self.committee.read().epoch;
        self.channels.force_close(epoch, peer);
    }

    fn dial_all(self: &Arc<Self>) {
        let (committee, me) = self.context_parts();
        for peer in (0..committee.size() as ValidatorIndex).filter(|p| *p != me) {
            let links = self.clone();
            tokio::spawn(async move {
                links
                    .keep_dialled(peer, peer < me, StreamKind::Control)
                    .await
            });
            let links = self.clone();
            tokio::spawn(
                async move { links.keep_dialled(peer, peer < me, StreamKind::Bulk).await },
            );
        }
    }

    /// Keeps a channel to `peer` open for as long as this epoch's core runs.
    ///
    /// The lower index of a pair dials. The higher one dials only when no
    /// channel has come up for [`ANSWER_GRACE`], so a validator that takes
    /// no inbound connections (behind NAT, outbound only) still reaches
    /// every peer that does.
    async fn keep_dialled(self: Arc<Self>, peer: ValidatorIndex, answers: bool, kind: StreamKind) {
        let epoch = self.committee.read().epoch;
        let mut backoff = Duration::from_millis(200);
        // Doubled only when the attempt this peer just made timed out
        // specifically on the handshake: a path whose rtt alone is not
        // enough margin (a lost packet's PTO backoff pushed it over) gets a
        // bigger budget next time instead of failing at the same one
        // forever. Any other kind of dial
        // failure (connect, endpoint lookup, ...) leaves it as is; a success
        // resets it.
        let mut hs_scale: u32 = 1;
        while self.committee.read().epoch == epoch && !self.inputs.is_closed() {
            if answers {
                tokio::time::sleep(ANSWER_GRACE).await;
            }
            if self.channels.is_open(epoch, peer, kind) {
                {
                    let mut d = self.dial_diag.lock();
                    let e = d.entry(peer).or_insert((0, 0, 0, String::new()));
                    e.1 += 1;
                    e.2 = unix_ms();
                }
                backoff = Duration::from_millis(200);
                tokio::time::sleep(backoff).await;
                continue;
            }
            let outcome = self.dial(peer, kind, hs_scale).await;
            {
                let mut d = self.dial_diag.lock();
                let e = d.entry(peer).or_insert((0, 0, 0, String::new()));
                e.0 += 1;
                e.2 = unix_ms();
                e.3 = match &outcome {
                    Ok(()) => "ok".to_string(),
                    Err(err) => err.to_string(),
                };
            }
            match outcome {
                Ok(()) => {
                    hs_scale = 1;
                    backoff = Duration::from_millis(200);
                    tokio::time::sleep(backoff).await;
                }
                Err(e) => {
                    debug!(peer, error = %e, "consensus channel to peer is down");
                    if e.to_string()
                        .contains("the handshake did not finish within")
                    {
                        hs_scale = hs_scale.saturating_mul(2).min(8);
                    }
                    backoff = (backoff * 2).min(DIAL_BACKOFF_MAX);
                    // A little jitter so a loss burst that knocks out several
                    // peers at once does not have them all redial in lockstep
                    // (CometBFT's switch adds the same kind of randomSleep to
                    // its own reconnect backoff).
                    let jitter = Duration::from_millis(rand::random::<u64>() % 250);
                    tokio::time::sleep(backoff + jitter).await;
                }
            }
        }
    }

    /// diag: records that `peer`'s in-flight dial() call has reached
    /// `stage`.
    fn mark_dial_stage(&self, peer: ValidatorIndex, stage: &'static str) {
        self.dial_stage.lock().insert(peer, (stage, unix_ms()));
    }

    /// diag: a snapshot of each peer's currently in-flight dial() stage, if
    /// any, with ms spent there so far.
    fn dial_stage_snapshot(&self) -> Vec<(ValidatorIndex, &'static str, u64)> {
        let now = unix_ms();
        let mut out: Vec<_> = self
            .dial_stage
            .lock()
            .iter()
            .map(|(p, (stage, since))| (*p, *stage, now.saturating_sub(*since)))
            .collect();
        out.sort_by_key(|(p, ..)| *p);
        out
    }

    /// diag: a snapshot of keep_dialled()'s per-peer activity, sorted by
    /// peer: (peer, dial attempts, is_open skips, ms since the last of
    /// either, last dial outcome).
    fn dial_diag_snapshot(&self) -> Vec<(ValidatorIndex, u64, u64, u64, String)> {
        let now = unix_ms();
        let mut out: Vec<_> = self
            .dial_diag
            .lock()
            .iter()
            .map(|(p, (attempts, skips, last_ms, result))| {
                (
                    *p,
                    *attempts,
                    *skips,
                    now.saturating_sub(*last_ms),
                    result.clone(),
                )
            })
            .collect();
        out.sort_by_key(|(p, ..)| *p);
        out
    }

    async fn dial(&self, peer: ValidatorIndex, kind: StreamKind, scale: u32) -> Result<()> {
        self.mark_dial_stage(peer, "start");
        let result = self.dial_inner(peer, kind, scale).await;
        self.dial_stage.lock().remove(&peer);
        result
    }

    async fn dial_inner(&self, peer: ValidatorIndex, kind: StreamKind, scale: u32) -> Result<()> {
        let (committee, me) = self.context_parts();
        self.dial_for(&committee, me, peer, kind, scale).await
    }

    /// The dial mechanics shared by this node's own dialler (`dial_inner`,
    /// against its own current committee) and pre-dialling the next epoch's
    /// channels ahead of its handover (`pre_dial_next_epoch`, against the
    /// already-derived next committee directly, before this node's own
    /// epoch has moved there). `scale` widens the handshake budget on a
    /// retry after a prior handshake specifically timed out; pre-dialling,
    /// a one-shot attempt, always passes 1.
    async fn dial_for(
        &self,
        committee: &Committee,
        me: ValidatorIndex,
        peer: ValidatorIndex,
        kind: StreamKind,
        scale: u32,
    ) -> Result<()> {
        let member = committee
            .member(peer)
            .ok_or_else(|| NodeError::Other("peer left the committee".into()))?;
        let (peer_announcement, (endpoint, machine)) = {
            let book = self.endpoints.read();
            let now = unix_ms();
            let a = book
                .current(&member.public_key, now)
                .cloned()
                .ok_or_else(|| NodeError::Other("the peer has not announced itself".into()))?;
            let e = book
                .disclosed(&member.public_key, now)
                .cloned()
                .ok_or_else(|| {
                    NodeError::Other(
                        "the peer has not disclosed its endpoint to this validator".into(),
                    )
                })?;
            (a, e)
        };
        // The disclosed endpoint is reached only through the signed record
        // of the machine the peer named, and only when that record names it.
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| NodeError::Other("this node resolves no endpoint records".into()))?;
        if let Ok(peer_id) = tenzro_iroh::EndpointId::from_bytes(&endpoint) {
            self.mark_dial_stage(peer, "fetching the peer's disclosed record");
            identity
                .fetch_disclosed_record(&self.endpoint, peer_id, &machine)
                .await;
        }
        self.mark_dial_stage(peer, "looking up the resolved record");
        let record = identity.store().lookup(&machine).ok_or_else(|| {
            NodeError::Other("the peer's endpoint record has not reached this validator".into())
        })?;
        let addr = tenzro_iroh::identity_transport::endpoint_addr(&record)
            .map_err(|e| NodeError::Other(e.to_string()))?;
        if addr.id.as_bytes() != &endpoint {
            return Err(NodeError::Other(
                "the peer's endpoint record names another endpoint".into(),
            ));
        }
        let (own, opening) = self.announcement.read().clone().ok_or_else(|| {
            NodeError::Other("this validator has not announced its endpoint yet".into())
        })?;
        self.mark_dial_stage(peer, "connecting");
        let (conn, send, recv) = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tenzro_iroh::open_consensus_connection(&self.endpoint, addr),
        )
        .await
        .map_err(|_| {
            NodeError::Other(format!(
                "the connection did not open within {}s",
                CONNECT_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| NodeError::Other(e.to_string()))?;
        let rtt = path_rtt(&conn);
        let budget = handshake_budget(rtt, scale);
        // A dial that stalls mid-handshake holds nothing past the limit,
        // same as a stalled inbound handshake in `answer`.
        self.mark_dial_stage(peer, "handshake");
        let (sealer, opener, send, recv) = tokio::time::timeout(
            budget,
            self.dial_handshake(
                send,
                recv,
                committee,
                me,
                peer,
                &own,
                &opening,
                &peer_announcement,
                kind,
            ),
        )
        .await
        .map_err(|_| {
            NodeError::Other(format!(
                "the handshake did not finish within {}s",
                budget.as_secs()
            ))
        })??;
        self.mark_dial_stage(peer, "running the channel");
        self.run_channel(
            committee.epoch,
            peer,
            kind,
            silence_budget(rtt),
            sealer,
            opener,
            send,
            recv,
        )
        .await
    }

    /// Best-effort: dials `next`'s channels to every peer ahead of the
    /// actual handover, while this node's own committee is still the one
    /// running, so a slow handshake under loss has the rest of the epoch to
    /// finish in rather than the few seconds between the handover
    /// certificate and round 0. `me` is this
    /// node's own index in `next`, already resolved by the caller. Nothing
    /// here retries: a peer this reaches is simply already open by the time
    /// `enter_epoch`'s own `dial_all` looks for it (`EpochChannels::open_now`
    /// tells the engine about it then); anything this does not reach falls
    /// to that dialler's normal retry loop, same as always.
    fn pre_dial_next_epoch(self: &Arc<Self>, next: Committee, me: ValidatorIndex) {
        for peer in (0..next.size() as ValidatorIndex).filter(|p| *p != me) {
            for kind in [StreamKind::Control, StreamKind::Bulk] {
                if self.channels.is_open(next.epoch, peer, kind) {
                    continue;
                }
                let links = self.clone();
                let next = next.clone();
                tokio::spawn(async move {
                    if let Err(e) = links.dial_for(&next, me, peer, kind, 1).await {
                        debug!(
                            peer,
                            epoch = next.epoch,
                            error = %e,
                            "pre-dialling the next epoch's channel failed; the regular dialler retries it after the handover"
                        );
                    }
                });
            }
        }
    }

    /// The dialling side of a handshake, run over an already-open stream:
    /// the channel's two halves.
    async fn dial_handshake(
        &self,
        mut send: tenzro_iroh::SendStream,
        mut recv: tenzro_iroh::RecvStream,
        committee: &Committee,
        me: ValidatorIndex,
        peer: ValidatorIndex,
        own: &EndpointAnnouncement,
        opening: &EndpointOpening,
        peer_announcement: &EndpointAnnouncement,
        kind: StreamKind,
    ) -> Result<(
        Sealer,
        Opener,
        tenzro_iroh::SendStream,
        tenzro_iroh::RecvStream,
    )> {
        let ctx = ChannelContext {
            chain_id: self.chain_id,
            genesis_hash: &self.genesis_hash,
            committee,
        };
        let (initiator, hello) = Initiator::start(&ctx, me, peer, kind)?;
        // The responder admits this stream only from the endpoint this
        // validator's announcement commits to, so the announcement and the
        // commitment's salt open the stream.
        write_msg(&mut send, own).await?;
        write_msg(&mut send, &opening.salt).await?;
        write_msg(&mut send, &hello).await?;
        let challenge: Challenge = read_msg(&mut recv).await?;
        // Signed by this boot's session key: a handshake costs no hardware
        // signature.
        let (awaiting, proof) = initiator.on_challenge(&challenge, &*self.session)?;
        write_msg(&mut send, &proof).await?;
        let accept: TranscriptSignature = read_msg(&mut recv).await?;
        let channel = AwaitingAccept::on_accept(awaiting, &ctx, &accept, peer_announcement)?;
        let (sealer, opener) = channel.split();
        Ok((sealer, opener, send, recv))
    }

    async fn answer(
        &self,
        remote: [u8; 32],
        rtt: Duration,
        mut send: tenzro_iroh::SendStream,
        mut recv: tenzro_iroh::RecvStream,
    ) -> Result<()> {
        // A dialler that stalls mid-handshake holds nothing past the limit.
        let budget = handshake_budget(rtt, 1);
        let (epoch, peer, kind, sealer, opener) =
            tokio::time::timeout(budget, self.answer_handshake(remote, &mut send, &mut recv))
                .await
                .map_err(|_| {
                    NodeError::Other(format!(
                        "the handshake did not finish within {}s",
                        budget.as_secs()
                    ))
                })??;
        self.run_channel(
            epoch,
            peer,
            kind,
            silence_budget(rtt),
            sealer,
            opener,
            send,
            recv,
        )
        .await
    }

    /// The answering side of a handshake: the epoch, peer and stream kind
    /// (named by the initiator's `hello`) it bound, and the channel's two
    /// halves.
    async fn answer_handshake(
        &self,
        remote: [u8; 32],
        send: &mut tenzro_iroh::SendStream,
        recv: &mut tenzro_iroh::RecvStream,
    ) -> Result<(u64, ValidatorIndex, StreamKind, Sealer, Opener)> {
        let (committee, me) = self.context_parts();
        let ctx = ChannelContext {
            chain_id: self.chain_id,
            genesis_hash: &self.genesis_hash,
            committee: &committee,
        };
        let announced: EndpointAnnouncement = read_msg(recv).await?;
        let salt: [u8; 32] = read_msg(recv).await?;
        let hello: Hello = read_msg(recv).await?;
        let peer = hello.initiator;
        // The handshake authenticates the peer's validator key; the stream
        // must also come from the endpoint that validator's newest signed
        // announcement commits to.
        let member = committee.member(peer).ok_or_else(|| {
            NodeError::Other("consensus stream from outside the committee".into())
        })?;
        let now = unix_ms();
        let current = {
            let mut book = self.endpoints.write();
            book.offer(
                announced,
                &member.public_key,
                self.chain_id,
                &self.genesis_hash,
                now,
            )?;
            match book.current(&member.public_key, now) {
                Some(a) if a.commits_to(&remote, &salt) => a.clone(),
                _ => {
                    return Err(NodeError::Other(
                        "consensus stream from an endpoint the validator has not announced".into(),
                    ));
                }
            }
        };
        let (responder, challenge) = Responder::on_hello(&ctx, me, &hello)?;
        write_msg(send, &challenge).await?;
        let proof: TranscriptSignature = read_msg(recv).await?;
        // The initiator must have signed with the session key its newest
        // announcement certifies; this side answers with its own.
        let (channel, accept) = responder.on_proof(&ctx, &proof, &current, &*self.session)?;
        write_msg(send, &accept).await?;
        let kind = hello.kind;
        let (sealer, opener) = channel.split();
        Ok((committee.epoch, peer, kind, sealer, opener))
    }

    /// Runs a channel whose handshake bound `epoch`'s committee until it
    /// fails or the node leaves that epoch.
    /// What a decoded, already-authenticated frame routes to: its
    /// messages tagged with the frame's own epoch, or nothing for an empty
    /// keepalive. The frame's MAC already verified before this is called,
    /// so its epoch is as trustworthy as anything else in it; the engine
    /// is what decides whether an epoch it names is still worth acting on.
    fn route_frame(frame: Frame) -> Option<(u64, Vec<Message>)> {
        if frame.items.is_empty() {
            None
        } else {
            Some((frame.epoch, frame.items))
        }
    }

    async fn run_channel(
        &self,
        epoch: u64,
        peer: ValidatorIndex,
        kind: StreamKind,
        silence: Duration,
        mut sealer: Sealer,
        mut opener: Opener,
        mut send: tenzro_iroh::SendStream,
        mut recv: tenzro_iroh::RecvStream,
    ) -> Result<()> {
        // Bulk never outranks control for this endpoint's own outgoing
        // bytes: the two now ride separate QUIC streams, so a payload
        // already in flight cannot hold up a vote or certificate behind it
        // either way, but a lower priority also keeps bulk from winning a
        // local scheduling tie under contention.
        if kind == StreamKind::Bulk {
            let _ = send.set_priority(-1);
        }
        let (tx, mut rx) = PeerQueue::new();
        let Some(mut lease) = self.channels.open(epoch, peer, kind, tx.clone()) else {
            return Err(NodeError::Other(
                "the channel's epoch ended during its handshake, or the peer holds its most channels"
                    .into(),
            ));
        };
        let down = tx.clone();
        let queue = tx.clone();
        match kind {
            StreamKind::Control => {
                let _ = self.inputs.send(Input::PeerUp {
                    epoch,
                    peer,
                    sender: tx,
                });
            }
            StreamKind::Bulk => {
                let _ = self.inputs.send(Input::BulkPeerUp {
                    epoch,
                    peer,
                    sender: tx,
                });
            }
        }
        // An empty frame of the channel's epoch: the peer takes it as a sign
        // of life and hands nothing to its core.
        let keepalive = Frame {
            epoch,
            items: Vec::new(),
        }
        .encode();
        let mut writer = tokio::spawn(async move {
            write_queued(
                &mut rx,
                &queue,
                |frame| sealer.seal(frame).ok(),
                &mut send,
                Some(&keepalive),
            )
            .await
        });
        let budget = lease.inbound.clone();
        let result = loop {
            // A channel fails in one direction as often as in both: a send
            // side that broke ends the channel, and so does a receive side
            // that went silent, so the peer is dialled again either way.
            let read = tokio::select! {
                // Bounded by idle time, not total transfer time: a large
                // frame under loss can take several multiples of one round
                // trip to arrive in full once retransmission is counted,
                // while still arriving steadily the whole time. Wrapping
                // the whole read in one outer CHANNEL_SILENCE, as this used
                // to, tore the channel down mid-transfer under exactly that
                // condition.
                read = tenzro_iroh::read_frame_idle(&mut recv, MAX_WIRE_FRAME, silence) => read,
                end = &mut writer => break Err(NodeError::Other(match end {
                    Ok(end) => format!("the channel's send side {end}"),
                    Err(e) => format!("the channel's send side ended: {e}"),
                })),
                end = lease.ended_or_closed() => match end {
                    LeaseEnd::Ended => {
                        // What the old core sent last (its vote on the
                        // handover, the certificate) is still being
                        // written: a peer that has not certified the
                        // handover yet needs it.
                        tokio::time::sleep(EPOCH_CHANNEL_DRAIN).await;
                        break Ok(());
                    }
                    LeaseEnd::Closed => break Err(NodeError::Other(
                        "closed: the engine had no route to this peer through this channel for too long"
                            .into(),
                    )),
                },
            };
            let bytes = match read {
                Ok(b) => b,
                Err(e) => break Err(NodeError::Other(e.to_string())),
            };
            // Wait for the core to catch up before reading more from this
            // peer.
            let cost = (bytes.len() as u32).clamp(1, PEER_INBOUND_BYTES);
            let held = match acquire_inbound_budget(&budget, cost).await {
                Ok(held) => held,
                Err(e) => break Err(e),
            };
            let payload = match opener.open(&bytes) {
                Ok(p) => p,
                Err(e) => break Err(e.into()),
            };
            match Frame::decode(&payload) {
                Ok(frame) => {
                    if let Some((epoch, messages)) = Self::route_frame(frame) {
                        let _ = self.inputs.send(Input::Inbound {
                            epoch,
                            from: peer,
                            messages,
                            _held: held,
                        });
                    }
                }
                Err(e) => break Err(e.into()),
            }
        };
        writer.abort();
        match kind {
            StreamKind::Control => {
                // A sibling channel to the same peer, if one is still live,
                // must be handed back to the engine before this one's
                // PeerDown can remove the engine's only route to the peer:
                // both sides can dial at once under loss, and the engine
                // keeps just one sender per peer, so a dying channel whose
                // own PeerUp happened to be the one the engine is still
                // using must not leave the peer unreachable while a healthy
                // sibling sits there unused (`OpenPeer`'s doc comment above).
                let survivor = lease.retire();
                drop(lease);
                let _ = self.inputs.send(Input::PeerDown { peer, sender: down });
                if let Some(sender) = survivor {
                    let _ = self.inputs.send(Input::PeerUp {
                        epoch,
                        peer,
                        sender,
                    });
                }
            }
            StreamKind::Bulk => {
                // Best-effort: losing it only means this peer's bulk
                // traffic falls back onto its control stream until a fresh
                // bulk channel comes up, never a lost route.
                lease.retire();
                drop(lease);
                let _ = self.inputs.send(Input::BulkPeerDown { peer, sender: down });
            }
        }
        result
    }
}

#[async_trait::async_trait]
impl tenzro_iroh::ConsensusStreamHandler for Links {
    /// Only an endpoint a member of this epoch's committee disclosed to this
    /// validator is admitted; anyone else is refused before a stream opens.
    fn admits(&self, remote: &[u8; 32]) -> bool {
        let committee = self.committee.read();
        let book = self.endpoints.read();
        let now = unix_ms();
        committee
            .members()
            .iter()
            .any(|m| book.endpoint(&m.public_key, now).as_ref() == Some(remote))
    }

    async fn accept_stream(
        &self,
        remote: [u8; 32],
        rtt: Duration,
        send: tenzro_iroh::SendStream,
        recv: tenzro_iroh::RecvStream,
    ) {
        if let Err(e) = self.answer(remote, rtt, send, recv).await {
            debug!(error = %e, "inbound consensus channel closed");
        }
    }
}

/// Inputs the engine handles in one pass before it ticks, flushes its
/// journal and outbox, and handles events again.
const INPUTS_PER_PASS: usize = 256;

/// `first`, then the inputs already queued behind it, at most `limit` in
/// all: inputs that keep arriving cannot hold the engine away from its timer
/// and its flushes.
/// Whether `m` carries transaction bytes (a batch push or a fetch reply)
/// rather than small consensus control data: the split the outbox drain
/// uses to route a peer's traffic onto its bulk stream instead of its
/// control one, so a payload already queued cannot make a vote or
/// certificate wait behind it.
fn is_bulk_message(m: &Message) -> bool {
    matches!(m, Message::Batch(_) | Message::Batches(_))
}

/// A message's kind, for counting.
fn message_kind(m: &Message) -> &'static str {
    match m {
        Message::Propose(_) => "propose",
        Message::Signals(_) => "signals",
        Message::Batch(_) => "batch",
        Message::FetchVertices(_) => "fetch_vertices",
        Message::Vertices(_) => "vertices",
        Message::FetchBatches(_) => "fetch_batches",
        Message::Batches(_) => "batches",
        Message::Vote(_) => "vote",
        Message::Certificate(_) => "certificate",
        Message::Frontier(_) => "frontier",
        Message::FetchOrdering(_) => "fetch_ordering",
        Message::Ordering(_) => "ordering",
    }
}

/// What a set of outgoing messages holds, for a log line about losing them:
/// proposals and signals by (round, author[, kind]), the rest by count.
fn describe_messages(items: &[Message]) -> String {
    let mut proposals = Vec::new();
    let mut signals = Vec::new();
    let mut other = 0usize;
    for m in items {
        match m {
            Message::Propose(v) => proposals.push((v.round, v.source)),
            Message::Signals(ss) => {
                signals.extend(ss.iter().map(|s| (s.round, s.source, s.kind as u8)))
            }
            _ => other += 1,
        }
    }
    format!("proposals={proposals:?} signals={signals:?} other={other}")
}

fn take_ready<T>(first: T, inputs: &mut mpsc::UnboundedReceiver<T>, limit: usize) -> Vec<T> {
    let mut ready = vec![first];
    while ready.len() < limit {
        let Ok(more) = inputs.try_recv() else { break };
        ready.push(more);
    }
    ready
}

struct Engine {
    beat: Arc<EngineBeat>,
    handle: Arc<ConsensusHandle>,
    core: Core,
    links: Arc<Links>,
    signer: Arc<dyn ValidatorSigner>,
    high_water: Arc<dyn VoteHighWater>,
    inputs: mpsc::UnboundedReceiver<Input>,
    peers: HashMap<ValidatorIndex, PeerQueue>,
    /// Peers with a bulk stream currently up, used only to route payload
    /// and batch-fetch replies off the control stream; a peer missing here
    /// still gets that traffic, merged onto its control frame as before.
    bulk_peers: HashMap<ValidatorIndex, PeerQueue>,
    segments: mpsc::Sender<OrderedSegment>,
    certificates: mpsc::UnboundedSender<Certificate>,
    compact: mpsc::UnboundedSender<CompactCertificate>,
    evidence: mpsc::UnboundedSender<CheckpointEquivocation>,
    /// Transactions this validator batched and has not seen ordered or
    /// handed back, with when it batched them. Each is held out of later
    /// batches for at most [`IN_FLIGHT_LEASE`].
    in_flight: HashMap<Hash, Instant>,
    /// The most each validator in turn waits for the one before it to batch
    /// a sender's transactions; governed, read when an epoch begins.
    failover: Duration,
    /// Transactions ordered in a segment not yet executed, with its height.
    /// They stay in the mempool until their block executes, and must not be
    /// batched again meanwhile.
    ordered: HashMap<Hash, u64>,
    first_seen: HashMap<Hash, Instant>,
    /// Senders this validator stepped in for, when their assigned validator
    /// did not batch them, and when it last did: their later transactions
    /// are batched here without waiting again, since one grace per
    /// transaction would hold a sender back for as many graces as it has
    /// transactions queued. A sender is dropped once a batch of its assigned
    /// validator orders one of its transactions.
    stepped_in: HashMap<Address, Instant>,
    batch_seq: u64,
    last_batch: Instant,
    next_committee: Option<Committee>,
    /// A handover this core took before the node executed the blocks it
    /// covers; the next epoch starts once they are.
    pending_handover: Option<tenzro_consensus::Certificate>,
    /// When each transaction this validator batched was first seen, until
    /// it is ordered, and whether it was assigned to this validator.
    batched_at: HashMap<Hash, (Instant, bool)>,
    /// Recent first-seen-to-ordered latencies of assigned transactions.
    ordered_latencies: OrderedLatencies,
    /// Consensus bytes sent since the core started.
    egress_bytes: u64,
    /// Encoded size of the last certificate formed.
    certificate_bytes: u64,
    /// When metrics were last published, with the round and egress then.
    last_metrics: (Instant, u64, u64),
    /// Whether the core's buffers were above BUFFER_WARN_BYTES when last
    /// measured.
    buffers_over: bool,
    /// Sequence number of the next recovery journal entry.
    journal_seq: u64,
    /// Spaces out the warnings about slow journal writes.
    slow_journal: crate::journal_writer::SlowWriteLog,
    /// Heights executed before a recovery: segments up to here are not
    /// executed again; their hashes and roots come from storage.
    executed_through: u64,
    /// The highest height whose segment went to execution.
    sent_through: u64,
    /// While the core fast-forwards: the last height the node imports
    /// before it orders its own blocks again. The core's segments past it
    /// wait in the event loop until the imports reach them.
    catching_up: Option<u64>,
    /// When the core started waiting for a checkpoint's ordering state.
    fast_forward_since: Option<Instant>,
    /// Set when the network is known to be past this core's epoch.
    standing_down: bool,
    stopping: bool,
    /// ms since each peer this node has no route to (`peers` holds no
    /// sender for it) was first seen missing while the dialler still
    /// considers a channel to it open. Past `PEER_ROUTE_STALL`, the route is
    /// force-closed and left to redial fresh rather than trusted a moment
    /// longer: the backstop for a disagreement between the dialler and the
    /// engine's own routing table that nothing else caught in time
    ///.
    peer_route_missing_since: HashMap<ValidatorIndex, u64>,
}

impl Engine {
    /// Closes any channel the dialler still considers open to a peer this
    /// node has had no route to (no sender in `peers`) for longer than
    /// `PEER_ROUTE_STALL`: the progress-based backstop for a disagreement
    /// between the dialler's and the engine's own view of which channels
    /// are actually serving traffic that the duplicate-channel fix did not
    /// anticipate.
    fn check_peer_routes(&mut self, now: u64) {
        let me = self.core.me();
        let epoch = self.core.committee().epoch;
        let n = self.core.committee().size() as ValidatorIndex;
        self.peer_route_missing_since
            .retain(|p, _| *p < n && *p != me);
        for peer in (0..n).filter(|p| *p != me) {
            let routed = self.peers.contains_key(&peer);
            let open = self
                .links
                .channels
                .is_open(epoch, peer, StreamKind::Control);
            if routed || !open {
                self.peer_route_missing_since.remove(&peer);
                continue;
            }
            let since = *self.peer_route_missing_since.entry(peer).or_insert(now);
            if now.saturating_sub(since) >= PEER_ROUTE_STALL.as_millis() as u64 {
                self.links.force_close_peer(peer);
                self.peer_route_missing_since.remove(&peer);
            }
        }
    }

    /// Whether the handle still feeds this core: false once it stood the
    /// core down or stopped it, or started another.
    fn is_current(&self) -> bool {
        self.handle
            .inputs
            .read()
            .as_ref()
            .is_some_and(|tx| tx.same_channel(&self.links.inputs))
    }

    fn now_ms(&self) -> u64 {
        // Wall-clock milliseconds: vertex timestamps are the inputs the
        // block timestamp is the median of.
        chrono::Utc::now().timestamp_millis().max(0) as u64
    }

    async fn run(mut self) {
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let now = self.now_ms();
        self.core.start(now);
        let mut diag_round = (0u64, Instant::now(), Instant::now());
        loop {
            self.beat.mark(1);
            // The timer first whenever it is due, so a steady stream of
            // input never delays a tick.
            tokio::select! {
                biased;
                _ = tick.tick() => {
                    self.beat.mark(2);
                    let now = self.now_ms();
                    {
                        let r = self.core.round().unwrap_or(0);
                        if r != diag_round.0 {
                            diag_round = (r, Instant::now(), Instant::now());
                        } else if diag_round.1.elapsed() > Duration::from_secs(15)
                            && diag_round.2.elapsed() > Duration::from_secs(10)
                        {
                            diag_round.2 = Instant::now();
                            let st = self.core.stats();
                            debug!(
                                epoch = self.core.committee().epoch,
                                round = r,
                                stalled_s = diag_round.1.elapsed().as_secs(),
                                peers = ?self.peers.keys().collect::<Vec<_>>(),
                                inputs_queued = self.inputs.len(),
                                sizes = ?self.core.sizes(),
                                rbc = ?st.rbc,
                                batches_pending = st.batches_pending,
                                last_committed = ?st.last_committed,
                                frontier_held = self.core.frontier_held(),
                                advance_refusal = st.diag_advance_refusal,
                                round_weight = st.diag_round_weight.0,
                                quorum = st.diag_round_weight.1,
                                empty_batch_replies = st.diag_empty_batch_replies,
                                frontier_sent = st.diag_frontier_sent,
                                frontier_received = st.diag_frontier_received,
                                frontier_answered = st.diag_frontier_answered,
                                frontier_reply_vertices = st.diag_last_frontier_reply.0,
                                frontier_reply_signals = st.diag_last_frontier_reply.1,
                                dial_diag = ?self.links.dial_diag_snapshot(),
                                dial_stage = ?self.links.dial_stage_snapshot(),
                                view = %self.core.diag_view(),
                                "diag: round stalled"
                            );
                        }
                    }
                    self.check_peer_routes(now);
                    if self.handle.close_retry_due()
                        && !self
                            .handle
                            .close_retry_in_flight
                            .swap(true, Ordering::AcqRel)
                    {
                        let handle = self.handle.clone();
                        tokio::task::spawn_blocking(move || {
                            handle.retry_close();
                            handle.close_retry_in_flight.store(false, Ordering::Release);
                        });
                    }
                    self.retry_fast_forward();
                    self.pace_to_execution();
                    self.core.on_tick(now);
                    let from = self.core.round().unwrap_or(0);
                    let me = self.core.me();
                    let leads = (from..from + LEADERSHIP_HORIZON).any(|r| self.core.leads(r, me));
                    self.handle.leads_soon.store(leads, Ordering::Release);
                    self.handle.round.store(from, Ordering::Release);
                    let reach = self.core.reach_round().unwrap_or(0);
                    if self.handle.committed_round.swap(reach, Ordering::AcqRel) != reach {
                        self.handle.note_reach_progress();
                    }
                    if self.last_batch.elapsed() >= Duration::from_millis(self.handle.config.batch_interval_ms) {
                        self.cut_batch();
                    }
                    if self.last_metrics.0.elapsed() >= METRICS_INTERVAL {
                        self.publish_metrics();
                    }
                }
                input = self.inputs.recv() => {
                    self.beat.mark(3);
                    let Some(input) = input else {
                        info!(
                            epoch = self.core.committee().epoch,
                            "consensus engine stopped: its inputs closed"
                        );
                        return;
                    };
                    self.pace_to_execution();
                    for input in take_ready(input, &mut self.inputs, INPUTS_PER_PASS) {
                        self.on_input(input);
                    }
                }
            }
            if self.stopping {
                self.flush().await;
                info!(epoch = self.core.committee().epoch, "consensus stopped");
                return;
            }
            if self.standing_down {
                let epoch = self.core.committee().epoch;
                // Once the handle feeds another core, started since this
                // one was stood down, that core owns the handle and the
                // record of the running epoch: this one drops only its own
                // journal.
                let replaced = !self.is_current() && self.handle.inputs.read().is_some();
                if replaced {
                    if self.handle.running_epoch.load(Ordering::Acquire) != epoch {
                        self.handle.drop_epoch_journal(epoch);
                    }
                } else {
                    self.handle.end_epoch_journal(epoch, None);
                    self.handle.fast_forward_to.store(0, Ordering::Release);
                    self.handle
                        .awaiting_handover
                        .store(false, Ordering::Release);
                    *self.handle.me.write() = None;
                    *self.handle.inputs.write() = None;
                }
                info!(
                    epoch,
                    "the network is past this validator's epoch; following to catch up"
                );
                self.handle.wake_block_sync();
                return;
            }
            self.beat.mark(4);
            if !self.flush().await {
                return;
            }
            self.beat.mark(5);
            let seated = self.handle_events().await;
            self.beat.mark(9);
            if !self.flush().await || !seated {
                return;
            }
        }
    }

    fn on_input(&mut self, input: Input) {
        let now = self.now_ms();
        match input {
            Input::Inbound {
                epoch,
                from,
                messages,
                ..
            } => {
                if epoch == self.core.committee().epoch {
                    self.core.on_messages(from, messages, now);
                } else {
                    debug!(
                        me = self.core.me(),
                        from,
                        epoch,
                        running = self.core.committee().epoch,
                        messages = %describe_messages(&messages),
                        "consensus messages for another epoch dropped"
                    );
                }
            }
            Input::Executed {
                height,
                block_hash,
                state_root,
            } => self.executed(height, block_hash.0, state_root.0),
            Input::Vote(v) => self.core.on_own_vote(*v),
            Input::NextCommittee(c) => {
                // Derived for the epoch after the one the core runs, or
                // stale: a core that entered the next epoch before this
                // arrived must not take its own committee as the next one.
                if c.epoch != self.core.committee().epoch + 1 {
                    return;
                }
                let already_predialed = self
                    .next_committee
                    .as_ref()
                    .is_some_and(|nc| nc.epoch == c.epoch);
                self.core.set_next_committee_root(c.root());
                if !already_predialed
                    && let Some(me) = c.members().iter().position(|m| {
                        &m.public_key == self.signer.public_key()
                            || self.handle.is_incoming(&m.public_key)
                    })
                {
                    self.links
                        .pre_dial_next_epoch(c.clone(), me as ValidatorIndex);
                }
                self.next_committee = Some(c);
            }
            Input::PeerUp {
                epoch,
                peer,
                sender,
            } => {
                if epoch != self.core.committee().epoch {
                    return;
                }
                self.peers.insert(peer, sender);
                self.core.on_peer_up(peer, now);
            }
            Input::PeerDown { peer, sender } => {
                // Only the channel that went down: a newer one to the same
                // peer may already have replaced it.
                if self
                    .peers
                    .get(&peer)
                    .is_some_and(|s| s.same_channel(&sender))
                {
                    self.peers.remove(&peer);
                }
            }
            Input::BulkPeerUp {
                epoch,
                peer,
                sender,
            } => {
                if epoch != self.core.committee().epoch {
                    return;
                }
                self.bulk_peers.insert(peer, sender);
            }
            Input::BulkPeerDown { peer, sender } => {
                if self
                    .bulk_peers
                    .get(&peer)
                    .is_some_and(|s| s.same_channel(&sender))
                {
                    self.bulk_peers.remove(&peer);
                }
            }
            Input::StandDown => self.standing_down = true,
            Input::Stop => self.stopping = true,
            Input::Certificate { cert, sessions } => {
                if cert.checkpoint.epoch == self.core.committee().epoch {
                    self.core.adopt_certificate(*cert, sessions);
                }
            }
            Input::FastForward { cert, sessions } => self.fast_forward(*cert, sessions),
            Input::Handover { cert, sessions } => {
                if cert.checkpoint.epoch == self.core.committee().epoch {
                    self.core.adopt_handover(*cert, sessions);
                }
            }
        }
    }

    /// Replaces the core with one that orders on from `cert`, a certified
    /// checkpoint of its epoch, once a peer sends the ordering state the
    /// checkpoint commits. The node imports the blocks up to the checkpoint
    /// meanwhile; the new core's segments wait until it has.
    fn fast_forward(&mut self, cert: Certificate, sessions: Vec<SessionCertificate>) {
        let cp = cert.checkpoint.clone();
        let epoch = self.core.committee().epoch;
        if cp.epoch != epoch
            || cp.next_committee_root.is_some()
            || self
                .core
                .resuming_from()
                .is_some_and(|c| c.checkpoint.index >= cp.index)
        {
            return;
        }
        // What this node executed, not what it holds certificates for: the
        // core skips the batches of the segments it counts as executed, and
        // the node would never build those blocks.
        let tip = self.handle.executed_height();
        let mut core = Core::resume(
            self.handle.config.core(
                self.handle.chain_id,
                self.handle.genesis_hash,
                &self.handle.time,
            ),
            self.core.committee().clone(),
            self.core.me(),
            cert,
            sessions,
            self.core.round(),
            self.core.next_batch_sequence(),
            tip.max(self.executed_through),
            self.core.leader_lookahead(),
        );
        let now = self.now_ms();
        core.start(now);
        let tail: Vec<(u64, [u8; 32], [u8; 32])> =
            self.handle.executed_tail.lock().iter().copied().collect();
        for (h, block, root) in tail {
            core.on_executed(h, block, root, Vec::new());
        }
        let peers: Vec<ValidatorIndex> = self.peers.keys().copied().collect();
        for p in peers {
            core.on_peer_up(p, now);
        }
        self.core = core;
        self.executed_through = self.executed_through.max(tip);
        self.sent_through = self.sent_through.max(tip);
        self.catching_up = Some(cp.last_height);
        self.fast_forward_since = Some(Instant::now());
        self.handle
            .fast_forward_to
            .store(cp.last_height.max(1), Ordering::Release);
        self.handle.note_behind_hint(cp.last_height);
        info!(
            epoch,
            index = cp.index,
            anchor_round = cp.anchor_round,
            through = cp.last_height,
            "fast-forwarding to a certified checkpoint"
        );
    }

    /// A core still waiting for a checkpoint's ordering state moves on to the
    /// latest certified checkpoint of its epoch, whose state peers still
    /// keep, or stands down if the network left the epoch.
    fn retry_fast_forward(&mut self) {
        if !self.core.is_resuming()
            || self
                .fast_forward_since
                .is_none_or(|t| t.elapsed() < FAST_FORWARD_RETRY)
        {
            return;
        }
        self.fast_forward_since = Some(Instant::now());
        let Some(c) = self.handle.latest_certificate() else {
            return;
        };
        let epoch = self.core.committee().epoch;
        if c.checkpoint.epoch > epoch {
            self.standing_down = true;
            return;
        }
        let sessions = self.handle.session_bundle(&c);
        self.fast_forward(c, sessions);
    }

    /// Once the node has executed through the checkpoint the core
    /// fast-forwarded to, the catch-up is over: the node orders its own
    /// blocks again (the event loop sees its tip reach the target).
    fn finish_catch_up(&mut self) {
        let Some(through) = self.catching_up else {
            return;
        };
        let tip = self.handle.executed_height();
        if self.core.is_resuming() || tip < through {
            return;
        }
        self.catching_up = None;
        self.fast_forward_since = None;
        self.executed_through = self.executed_through.max(tip);
        self.sent_through = self.sent_through.max(tip);
        info!(
            epoch = self.core.committee().epoch,
            through = tip,
            "caught up with the network; ordering again"
        );
    }

    fn executed(&mut self, height: u64, block_hash: [u8; 32], state_root: [u8; 32]) {
        self.ordered.retain(|_, h| *h > height);
        self.core
            .on_executed(height, block_hash, state_root, Vec::new());
        self.pace_to_execution();
    }

    /// Holds the core's frontier while the blocks this validator sent to
    /// execution run more than [`MAX_UNEXECUTED_HEIGHTS`] past the blocks it
    /// executed, and releases it once they no longer do.
    fn pace_to_execution(&mut self) {
        let executed = self.handle.executed_height().max(self.executed_through);
        let behind = self.sent_through.saturating_sub(executed);
        let held = behind > MAX_UNEXECUTED_HEIGHTS;
        if held != self.core.frontier_held() {
            debug!(
                behind,
                held,
                sent_through = self.sent_through,
                executed,
                "frontier paced to execution"
            );
            self.core.hold_frontier(held);
        }
    }

    /// A segment a recovered core ordered again at a height this node had
    /// already executed: its block hash and post-state root come from
    /// storage.
    async fn replayed(&mut self, seg: &Segment) {
        use tenzro_storage::BlockStore;
        let Some(storage) = self.handle.storage.clone() else {
            return;
        };
        let block = match tenzro_storage::block_store::BlockStoreImpl::new(storage.clone()) {
            Ok(store) => {
                store
                    .get_block_by_height(tenzro_types::primitives::BlockHeight::from(seg.height))
                    .await
            }
            Err(e) => Err(e),
        };
        let root = tenzro_storage::StateTrie::new(storage).root_at(seg.height);
        match (block, root) {
            (Ok(Some(block)), Ok(Some(root))) => {
                if block.header.anchor.0 != seg.anchor.digest {
                    tracing::error!(
                        height = seg.height,
                        "the recovered order differs from the executed chain"
                    );
                    return;
                }
                self.executed(seg.height, block.hash().0, root.0);
            }
            _ => warn!(
                height = seg.height,
                "an executed block or its state root is missing from storage"
            ),
        }
    }

    /// The epoch ends at `last_height`: its next committee, when this node
    /// already derived it (a recovered core ordering the end again), or
    /// derived once that height is executed.
    fn epoch_ends(&mut self, last_height: u64) {
        match self.handle.committee(self.core.committee().epoch + 1) {
            Some(next) => {
                self.core.set_next_committee_root(next.root());
                self.next_committee = Some(next);
            }
            None => self.handle.epoch_ends(last_height),
        }
    }

    /// Cuts this validator's share of the mempool into a part; the core seals
    /// the parts pending at its next proposal into that vertex's batch.
    fn cut_batch(&mut self) {
        self.last_batch = Instant::now();
        if self.handle.is_draining() || self.core.is_halted() {
            return;
        }
        // While this validator's batches are not being ordered (the network
        // below quorum, say), cutting on would pile up batches every peer
        // must fetch once ordering resumes, many holding the same
        // transactions again once the in-flight lease runs out. It cuts
        // again as its batches are ordered; the transactions wait in the
        // mempool meanwhile.
        if self.core.unordered_own_batches() >= MAX_UNORDERED_OWN_BATCHES {
            return;
        }
        let n = self.core.committee().size() as u64;
        let me = self.core.me() as u64;
        let now = Instant::now();
        let mut chosen: Vec<(Hash, SignedTransaction)> = Vec::new();
        // The part is a bincode `Vec`, whose length prefix counts too.
        let budget = self
            .handle
            .config
            .batch_max_bytes
            .min(MAX_PART_BYTES)
            .saturating_sub(VEC_PREFIX_BYTES);
        let mut bytes = 0usize;
        // The assigned validator gets twice the typical time to order before
        // the next in turn steps in, and each further one as long again:
        // stepping in any sooner orders the transaction twice.
        let grace = self.ordered_latencies.grace(now, self.failover);
        // A part the core neither ordered nor handed back (taken into a
        // round that was never committed while the network was below
        // quorum) would hold its transactions out of every later batch, and
        // with them every later transaction of their senders. Past the lease
        // they are batched again; one ordered twice executes once.
        self.in_flight
            .retain(|_, at| now.duration_since(*at) < IN_FLIGHT_LEASE);
        // The mempool shows each sender's transactions in nonce order from
        // its executed nonce, and a later one only once the one before it is
        // batched in this part or already ordered: once one waits, every later one of
        // that sender waits with it, since batched without it they would
        // execute ahead of their nonce and fail. The walk ends when the part
        // is full, so a cut costs what it takes, not the size of the pool.
        self.stepped_in
            .retain(|_, at| now.duration_since(*at) < LATENCY_HORIZON);
        let (in_flight, ordered, first_seen, stepped_in) = (
            &self.in_flight,
            &self.ordered,
            &mut self.first_seen,
            &self.stepped_in,
        );
        let mut stepping_in: Vec<Address> = Vec::new();
        // A beacon contribution whose round the beacon has passed would only
        // revert, taking a place in the block. It is dropped, unless the
        // sender has a later transaction pooled: that one needs the nonce
        // this one spends, even by reverting.
        let chain = self
            .handle
            .storage
            .as_ref()
            .map(|s| tenzro_vm::StateAdapter::with_storage(s.clone()));
        let mempool_ref = &self.handle.mempool;
        let mut stale: Vec<Hash> = Vec::new();
        self.handle.mempool.select_with(|h, tx| {
            if let Some(pick) = already_batched(h, in_flight, ordered) {
                return pick;
            }
            // A signers record for a checkpoint another validator's copy has
            // already put on the chain is dropped the same way.
            if let Some(chain) = chain.as_ref()
                && (crate::beacon::is_stale_contribution(chain, &tx.transaction.tx_type)
                    || crate::checkpoint_recorder::is_recorded_checkpoint(
                        chain,
                        &tx.transaction.tx_type,
                    ))
                && !mempool_ref.has_pending_from(&tx.transaction.from, |o| {
                    o.transaction.nonce.0 > tx.transaction.nonce.0
                })
            {
                stale.push(*h);
                return Pick::Taken;
            }
            let from = tx.transaction.from;
            let seen = *first_seen.entry(*h).or_insert(now);
            let turn = (me + n - assigned_validator(&from, n)) % n;
            if turn > 0
                && !stepped_in.contains_key(&from)
                && now.duration_since(seen) < grace.saturating_mul(turn as u32)
            {
                return Pick::Wait;
            }
            let size = bincode::serialized_size(tx).unwrap_or(0) as usize;
            if bytes + size > budget
                || chosen.len() >= tenzro_types::block::MAX_TRANSACTIONS_PER_BLOCK
            {
                return Pick::Stop;
            }
            bytes += size;
            if turn > 0 {
                stepping_in.push(from);
            }
            chosen.push((*h, tx.clone()));
            Pick::Take
        });
        for from in stepping_in {
            self.stepped_in.insert(from, now);
        }
        if !stale.is_empty() {
            debug!(
                dropped = stale.len(),
                "stale beacon contributions left the mempool"
            );
            self.handle.mempool.remove_transactions(&stale);
        }
        let mempool = &self.handle.mempool;
        self.first_seen.retain(|h, _| mempool.contains(h));
        if chosen.is_empty() {
            return;
        }
        // A part of a few transactions every batch interval costs every peer
        // a batch to receive, hold and order for little: a small part is
        // held back until it fills or its oldest transaction has waited
        // `PART_HOLD`.
        let oldest = chosen
            .iter()
            .filter_map(|(h, _)| self.first_seen.get(h))
            .min()
            .copied()
            .unwrap_or(now);
        if chosen.len() < MIN_PART_TRANSACTIONS && now.duration_since(oldest) < PART_HOLD {
            return;
        }
        self.batched_at
            .retain(|_, (t, _)| now.duration_since(*t) < LATENCY_HORIZON);
        for (h, tx) in &chosen {
            let h = *h;
            self.in_flight.insert(h, now);
            let assigned = assigned_validator(&tx.transaction.from, n) == me;
            self.batched_at.insert(
                h,
                (self.first_seen.get(&h).copied().unwrap_or(now), assigned),
            );
        }
        let chosen: Vec<SignedTransaction> = chosen.into_iter().map(|(_, tx)| tx).collect();
        let part = BatchPart {
            transactions: chosen.len() as u32,
            bytes: bincode::serialize(&chosen).expect("transactions encode"),
        };
        self.batch_seq += 1;
        self.core.submit_part(part);
    }

    /// Persists the journal, then sends. False if the journal could not be
    /// written: the core then holds state that is not on disk, and a
    /// validator that carried on from it could contradict itself after a
    /// restart, so it stops instead.
    ///
    /// The synced write runs on the journal's own thread, which joins it
    /// with any other write waiting; this waits for it without holding an
    /// executor thread, and sends only once it is durable.
    async fn flush(&mut self) -> bool {
        let epoch = self.core.committee().epoch;
        let records = self.core.take_journal();
        if !records.is_empty()
            && let Some(writer) = self.handle.journal.clone()
        {
            let started = Instant::now();
            let value = bincode::serialize(&records).expect("records encode");
            let encoded_ms = started.elapsed().as_millis() as u64;
            let bytes = value.len();
            let op = tenzro_storage::WriteOp::Put {
                cf: CF.to_string(),
                key: journal_key(epoch, self.journal_seq),
                value,
            };
            let written = writer.write(vec![op]).await;
            let took_ms = started.elapsed().as_millis() as u64;
            let threshold_ms =
                crate::journal_writer::slow_threshold_ms(self.handle.config.leader_timeout_ms);
            if let Some(held_back) = self
                .slow_journal
                .warn(took_ms, threshold_ms, Instant::now())
            {
                warn!(
                    validator = self.core.me(),
                    records = records.len(),
                    bytes,
                    encoded_ms,
                    took_ms,
                    threshold_ms,
                    held_back,
                    "diag: consensus journal write was slow"
                );
            }
            if let Err(e) = written {
                tracing::error!(error = %e, "consensus journal write failed; this validator stops");
                *self.handle.me.write() = None;
                *self.handle.inputs.write() = None;
                return false;
            }
            self.journal_seq += 1;
        }
        let send_started = Instant::now();
        let n = self.core.committee().size() as ValidatorIndex;
        let me = self.core.me();
        let mut per_peer: HashMap<ValidatorIndex, Vec<Message>> = HashMap::new();
        let outbox = self.core.take_outbox();
        let outbox_kinds = {
            let mut counts: std::collections::BTreeMap<&'static str, usize> = Default::default();
            for (_, m) in &outbox {
                *counts.entry(message_kind(m)).or_default() += 1;
            }
            format!("{counts:?}")
        };
        let (mut queued_bytes, mut bulk_frames, mut bulk_dropped) = (0usize, 0usize, 0usize);
        for (t, m) in outbox {
            match t {
                Target::All => {
                    for p in (0..n).filter(|p| *p != me) {
                        per_peer.entry(p).or_default().push(m.clone());
                    }
                }
                Target::One(p) => per_peer.entry(p).or_default().push(m),
            }
        }
        for (p, items) in per_peer {
            let Some(sender) = self.peers.get(&p).cloned() else {
                continue;
            };
            // Batch pushes and fetch replies carry transaction bytes. They
            // travel in frames of their own, after the peer's control
            // messages, on the peer's bulk stream once one is up and on
            // control otherwise: a frame dropped at a full queue then never
            // takes a vote, signal or proposal down with megabytes of
            // batches.
            let (bulk_items, items): (Vec<Message>, Vec<Message>) =
                items.into_iter().partition(is_bulk_message);
            if !items.is_empty() {
                let described =
                    tracing::enabled!(tracing::Level::DEBUG).then(|| describe_messages(&items));
                let (frames, left_out) = Frame::encode_bounded(epoch, items);
                if left_out > 0 {
                    warn!(
                        peer = p,
                        left_out, "messages larger than a frame were not sent"
                    );
                }
                let count = frames.len();
                for (i, bytes) in frames.into_iter().enumerate() {
                    self.egress_bytes += bytes.len() as u64;
                    queued_bytes += bytes.len();
                    if !sender.try_send(bytes) {
                        self.handle.dropped_frames.fetch_add(1, Ordering::AcqRel);
                        debug!(
                            me,
                            peer = p,
                            epoch,
                            frame = i,
                            frames = count,
                            messages = described.as_deref().unwrap_or(""),
                            "consensus queue to peer is full; the peer will fetch what it misses"
                        );
                    }
                }
            }
            if bulk_items.is_empty() {
                continue;
            }
            let bulk_sender = self.bulk_peers.get(&p).cloned().unwrap_or(sender);
            // A queue without room for a whole frame would drop what is
            // encoded for it: nothing is encoded, and the peer asks again.
            if bulk_sender.room() < MAX_WIRE_FRAME {
                bulk_dropped += bulk_items.len();
                self.handle.dropped_frames.fetch_add(1, Ordering::AcqRel);
                debug!(
                    me,
                    peer = p,
                    messages = bulk_items.len(),
                    "consensus bulk queue to peer is full; the peer will fetch what it misses"
                );
                continue;
            }
            // Fetch replies after a stall can far exceed one frame: they
            // travel in as many frames as they need, since a frame over the
            // bound is refused with the channel, and the same reply sent
            // again would be refused again.
            let (frames, left_out) = Frame::encode_bounded(epoch, bulk_items);
            if left_out > 0 {
                warn!(
                    peer = p,
                    left_out, "messages larger than a frame were not sent"
                );
            }
            for bulk_bytes in frames {
                self.egress_bytes += bulk_bytes.len() as u64;
                queued_bytes += bulk_bytes.len();
                bulk_frames += 1;
                if !bulk_sender.try_send(bulk_bytes) {
                    bulk_dropped += 1;
                    self.handle.dropped_frames.fetch_add(1, Ordering::AcqRel);
                    debug!(
                        me,
                        peer = p,
                        "consensus bulk queue to peer is full; the peer will fetch what it misses"
                    );
                }
            }
        }
        let send_ms = send_started.elapsed().as_millis() as u64;
        if send_ms >= 1_000 {
            warn!(
                validator = me,
                send_ms,
                queued_bytes,
                bulk_frames,
                bulk_dropped,
                outbox = %outbox_kinds,
                "diag: consensus frames took long to queue"
            );
        }
        true
    }

    /// Acts on the core's events; false once this node has left the
    /// committee.
    async fn handle_events(&mut self) -> bool {
        // The handle stood this core down or stopped it, and the input that
        // says so is still queued: the core acts on nothing more. Taking a
        // handover now would mark the node as awaiting one after the stand
        // down cleared that, and the core the node starts next at the
        // handover would inherit the mark: certificates of later epochs
        // would no longer stand it down, nor its node order its own blocks.
        if !self.is_current() {
            return true;
        }
        if let Some(handover) = self.pending_handover.take()
            && !self.next_epoch(handover)
        {
            return false;
        }
        self.finish_catch_up();
        for e in self.core.take_events() {
            match e {
                Event::Ordered(seg) => {
                    // A segment past the blocks executed so far (the core
                    // resumed from a checkpoint the node has not imported up
                    // to): the node imports them first.
                    if self.catching_up.is_none() && seg.height > self.sent_through + 1 {
                        self.catching_up = Some(seg.height - 1);
                        self.handle
                            .fast_forward_to
                            .store(seg.height - 1, Ordering::Release);
                        self.handle.note_behind_hint(seg.height - 1);
                    }
                    self.on_ordered(seg).await;
                }
                Event::EpochEnds { last_height } => self.epoch_ends(last_height),
                Event::Sign(cp) => {
                    // Every checkpoint this core decides is kept, certified
                    // here or not: a peer catching up authenticates it
                    // through a later certificate's predecessor digests.
                    self.handle.record_body(&cp);
                    let certifier = self.handle.certifier(self.signer.clone());
                    let hw = self.high_water.clone();
                    let me = self.core.me();
                    let inputs = self.links.inputs.clone();
                    tokio::task::spawn_blocking(move || {
                        // The session key signs; its certificate for this
                        // epoch is signed by the hardware key once per epoch.
                        let signed = certifier.certificate(cp.epoch).and_then(|cert| {
                            sign_checkpoint(&*certifier.session, &cert, &*hw, me, &cp)
                        });
                        match signed {
                            Ok(v) => {
                                let _ = inputs.send(Input::Vote(Box::new(v)));
                            }
                            Err(e) => warn!(index = cp.index, error = %e, "not signing checkpoint"),
                        }
                    });
                }
                Event::Certified(c) => self.on_certified(*c),
                Event::EpochComplete(c) => {
                    self.handle.record_boundary(
                        c.checkpoint.epoch,
                        c.checkpoint.index - self.handle.time.handover_confirmations,
                    );
                    self.on_certified((*c).clone());
                    if !self.next_epoch(*c) {
                        return false;
                    }
                }
                Event::Equivocation(e) => {
                    warn!(
                        epoch = e.first.epoch,
                        index = e.first.index,
                        "a validator signed two checkpoints"
                    );
                    self.handle.equivocations.fetch_add(1, Ordering::AcqRel);
                    let _ = self.evidence.send(*e);
                }
                Event::Unordered(p) => {
                    for tx in batch_transactions(&p) {
                        self.in_flight.remove(&tx.transaction.hash());
                    }
                }
                Event::VerifierDisagreement { index } => {
                    tracing::error!(
                        index,
                        "consensus halted: the two ML-DSA-65 implementations disagree on a \
                         signature; restart on a build whose implementations agree"
                    );
                }
            }
        }
        true
    }

    async fn on_ordered(&mut self, seg: Segment) {
        self.sent_through = self.sent_through.max(seg.height);
        if seg.height <= self.executed_through {
            self.replayed(&seg).await;
            return;
        }
        let committee = self.core.committee().clone();
        let mut seen: HashSet<Hash> = HashSet::new();
        let mut transactions = Vec::new();
        let ordered_at = Instant::now();
        for (b, payload) in &seg.batches {
            // A batch counts only if its payload names the author it was
            // ordered as; the digest binds the author field.
            if payload.author != b.author || payload.epoch != committee.epoch {
                continue;
            }
            for tx in batch_transactions(payload) {
                let h = tx.transaction.hash();
                self.in_flight.remove(&h);
                // The sender's own validator batches it again: this one
                // stops stepping in for it.
                let from = tx.transaction.from;
                if self.stepped_in.contains_key(&from)
                    && assigned_validator(&from, committee.size() as u64) == u64::from(b.author)
                {
                    self.stepped_in.remove(&from);
                }
                // One that executes ahead of its nonce stays in the mempool
                // and is seen again, and waited for afresh, once its block
                // has executed.
                self.first_seen.remove(&h);
                self.ordered.insert(h, seg.height);
                if let Some((t, assigned)) = self.batched_at.remove(&h)
                    && assigned
                {
                    self.ordered_latencies
                        .record(ordered_at, ordered_at.duration_since(t).as_millis() as u64);
                }
                if seen.insert(h) {
                    transactions.push(tx);
                }
            }
        }
        let proposer = committee
            .member(seg.anchor.source)
            .map_or(Address::zero(), |m| m.address);
        let out = OrderedSegment {
            height: seg.height,
            epoch: seg.epoch,
            round: seg.anchor.round,
            anchor: Hash::new(seg.anchor.digest),
            proposer,
            timestamp_ms: seg.timestamp_ms,
            transactions,
        };
        self.beat.mark(6);
        let sent = self.segments.send(out).await;
        self.beat.mark(5);
        if sent.is_err() {
            warn!("the event loop stopped taking ordered segments");
        }
    }

    fn on_certified(&mut self, c: tenzro_consensus::Certificate) {
        debug!(
            index = c.checkpoint.index,
            last_height = c.checkpoint.last_height,
            "checkpoint certified"
        );
        self.handle
            .admit_sessions(c.checkpoint.epoch, self.core.sessions().bundle(&c.sessions));
        self.handle.record_certificate(&c);
        self.certificate_bytes = bincode::serialized_size(&c).unwrap_or(0);
        self.prove_compact(&c);
        let _ = self.certificates.send(c);
    }

    /// Proves the compact form of `c` off the engine, when `c` is one that
    /// gets a compact form (every compact interval, and every checkpoint
    /// that ends an epoch, which light clients follow): at once on the
    /// epoch's designated prover, and on every other member only once its
    /// fallback time passes with no verified compact certificate received.
    fn prove_compact(&self, c: &Certificate) {
        let time = self.handle.time.clone();
        if !is_compacted(c.checkpoint.index, &time) && c.checkpoint.next_committee_root.is_none() {
            return;
        }
        let wait = prove_after_ms(
            c.checkpoint.epoch,
            self.core.committee().size(),
            self.core.me(),
            &time,
        );
        let (handle, cert, tx) = (self.handle.clone(), c.clone(), self.compact.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(wait)).await;
            if handle.compact_covers(cert.checkpoint.index)
                || handle.proving.swap(true, Ordering::AcqRel)
            {
                return;
            }
            let index = cert.checkpoint.index;
            let started = Instant::now();
            let prover = handle.clone();
            let outcome = tokio::task::spawn_blocking(move || prover.prove_compact(&cert)).await;
            handle.proving.store(false, Ordering::Release);
            match outcome.map(|r| r.map(|cc| (handle, cc))) {
                Ok(Ok((handle, cc))) => {
                    debug!(
                        index,
                        ms = started.elapsed().as_millis() as u64,
                        "compact certificate proven"
                    );
                    handle.record_compact(&cc);
                    let _ = tx.send(cc);
                }
                Ok(Err(e)) => warn!(index, error = %e, "compact certificate not proven"),
                Err(e) => warn!(index, error = %e, "compact certificate prover failed"),
            }
        });
    }

    /// Publishes the core's metrics to the handle.
    fn publish_metrics(&mut self) {
        let stats = self.core.stats();
        let round = stats.round.unwrap_or(0);
        let (_, last_round, last_egress) = self.last_metrics;
        let rounds = round.saturating_sub(last_round);
        let egress_bytes_per_round = (self.egress_bytes - last_egress)
            .checked_div(rounds)
            .unwrap_or(0);
        let buffered = self.core.buffered_bytes();
        let over = buffered > BUFFER_WARN_BYTES;
        if over && !self.buffers_over {
            warn!(buffered_bytes = buffered, round, last_committed = ?stats.last_committed, "consensus buffers are large; the committee may be stalled");
        }
        self.buffers_over = over;
        let now = Instant::now();
        let ordered_p50_ms = self.ordered_latencies.quantile(now, 0.5);
        let ordered_p99_ms = self.ordered_latencies.quantile(now, 0.99);
        *self.handle.metrics.write() = Some(ConsensusMetrics {
            epoch: self.core.committee().epoch,
            round,
            round_p50_ms: stats.round_p50_ms,
            round_p99_ms: stats.round_p99_ms,
            ordered_p50_ms,
            ordered_p99_ms,
            rbc_fast: stats.rbc.fast,
            rbc_slow: stats.rbc.slow,
            leaders_committed: stats.leaders_committed,
            leaders_skipped: stats.leaders_skipped,
            batches_pending: stats.batches_pending as u64,
            certificate_bytes: self.certificate_bytes,
            egress_bytes: self.egress_bytes,
            egress_bytes_per_round,
            buffered_bytes: buffered as u64,
        });
        self.last_metrics = (Instant::now(), round, self.egress_bytes);
    }

    /// Starts the next epoch's core; false if this node is not seated in it.
    fn next_epoch(&mut self, handover: tenzro_consensus::Certificate) -> bool {
        let mut start = self.core.next_epoch_start(&handover);
        // Read once the epoch's last blocks are executed (the start is
        // based on them below), so every validator reads the same state.
        start.leader_lookahead_rounds = governed_lookahead(self.handle.storage.as_ref());
        self.failover = governed_failover(self.handle.storage.as_ref());
        let last = start.first_height.saturating_sub(1);
        // A core that took the handover from a certificate, without having
        // ordered the epoch's last blocks, has neither their state nor the
        // next committee derived from it. The node imports and executes them
        // (block sync, under the certificates covering them); the epoch
        // starts once it has, based on what it executed.
        if start.base_blocks.last().is_none_or(|(h, ..)| *h != last)
            && let Some(base) = self.handle.base_through(last)
        {
            start.base_blocks = base;
        }
        let next_epoch = handover.checkpoint.epoch + 1;
        let next = self
            .next_committee
            .take()
            .filter(|c| c.epoch == next_epoch)
            .or_else(|| self.handle.committee(next_epoch));
        let based = start.base_blocks.last().is_some_and(|(h, ..)| *h == last);
        let (Some(next), true) = (next.clone(), based) else {
            if !self.handle.awaiting_handover.swap(true, Ordering::AcqRel) {
                info!(
                    epoch = next_epoch,
                    through = last,
                    "took the handover before executing the epoch's last blocks; importing them"
                );
                if self.handle.committee(next_epoch).is_none() {
                    self.handle.epoch_ends(last);
                }
                self.handle.note_behind_hint(last);
            }
            self.next_committee = next;
            self.pending_handover = Some(handover);
            return true;
        };
        self.handle
            .awaiting_handover
            .store(false, Ordering::Release);
        self.handle.record_boundary(
            handover.checkpoint.epoch,
            handover.checkpoint.index - self.handle.time.handover_confirmations,
        );
        self.handle.add_committee(next.clone());
        // A rotation seated by this committee moves the engine to the new
        // key here, without a restart.
        let me = self
            .handle
            .key_for(&next, &self.signer)
            .map(|(signer, me)| {
                self.signer = signer;
                me
            });
        // The old epoch's channels close; the new committee's come up as
        // each peer enters the epoch.
        self.links.enter_epoch(next.clone());
        self.peers.clear();
        self.bulk_peers.clear();
        let old_epoch = handover.checkpoint.epoch;
        match me {
            Some(me) => {
                self.handle
                    .end_epoch_journal(old_epoch, Some((next.epoch, &start)));
                self.handle
                    .running_epoch
                    .store(next.epoch, Ordering::Release);
                self.journal_seq = 0;
                *self.links.me.write() = me;
                *self.handle.me.write() = Some(me);
                self.handle.note_reach_progress();
                self.core = Core::new(
                    governed_timing(&self.handle.config, self.handle.storage.as_ref()).core(
                        self.handle.chain_id,
                        self.handle.genesis_hash,
                        &self.handle.time,
                    ),
                    next,
                    me,
                    start,
                );
                self.handle
                    .epoch_ends_ms
                    .store(self.core.epoch_ends_ms(), Ordering::Release);
                // Parts the last core took but neither ordered nor handed
                // back are gone with it: their transactions are batched
                // again. Kept in flight, the sender would wait on them for
                // good while its later transactions failed ahead of them.
                self.in_flight.clear();
                for (peer, kind, sender) in self.links.channels.open_now(next_epoch) {
                    match kind {
                        StreamKind::Control => self.on_input(Input::PeerUp {
                            epoch: next_epoch,
                            peer,
                            sender,
                        }),
                        StreamKind::Bulk => self.on_input(Input::BulkPeerUp {
                            epoch: next_epoch,
                            peer,
                            sender,
                        }),
                    }
                }
                self.links.dial_all();
                let now = self.now_ms();
                self.core.start(now);
                info!(
                    epoch = self.core.committee().epoch,
                    validator = me,
                    "entered the next epoch"
                );
                true
            }
            None => {
                self.handle.end_epoch_journal(old_epoch, None);
                *self.handle.me.write() = None;
                *self.handle.inputs.write() = None;
                info!("this node is not in the next committee; following as a full node");
                false
            }
        }
    }
}

/// The governed leader lookahead in this node's chain state, or its genesis
/// value without one.
pub(crate) fn governed_lookahead(storage: Option<&Arc<dyn KvStore>>) -> u64 {
    use tenzro_vm::governance as g;
    match storage {
        Some(s) => tenzro_vm::native::network_param(
            &tenzro_vm::StateAdapter::with_storage(s.clone()),
            g::CONSENSUS_LEADER_LOOKAHEAD_PARAM,
        ),
        None => g::governed_param(g::CONSENSUS_LEADER_LOOKAHEAD_PARAM).map_or(4, |p| p.genesis),
    }
}

/// The compact-certificate proof set-ups of this process. A set-up depends
/// only on the committee's slot keys, so every handle in one process shares
/// a single cache rather than building and holding its own copy.
fn shared_setups() -> Arc<ProofSetups> {
    static SETUPS: std::sync::OnceLock<Arc<ProofSetups>> = std::sync::OnceLock::new();
    SETUPS.get_or_init(|| Arc::new(ProofSetups::new())).clone()
}

/// The compact-certificate pool of this process. Its budget, one job at a
/// time on `threads` threads (half the machine's cores when 0), is the
/// machine's: handles sharing a process share it rather than each taking
/// half the cores and a proof's peak memory of their own. The first handle
/// sizes it.
fn shared_compact_work(threads: usize) -> Arc<CompactWork> {
    static WORK: std::sync::OnceLock<Arc<CompactWork>> = std::sync::OnceLock::new();
    WORK.get_or_init(|| Arc::new(CompactWork::with_threads(threads)))
        .clone()
}

/// This validator's round timing held inside the governed bounds in
/// `storage` (their genesis values without storage), read when an epoch
/// begins: a validator configures its own leader timeout and round interval
/// for its network, and governance bounds both.
pub(crate) fn governed_timing(
    config: &ConsensusConfig,
    storage: Option<&Arc<dyn KvStore>>,
) -> ConsensusConfig {
    use tenzro_vm::governance as g;
    let state = storage.map(|s| tenzro_vm::StateAdapter::with_storage(s.clone()));
    let read = |key: &str| match &state {
        Some(st) => tenzro_vm::native::network_param(st, key),
        None => g::genesis_param(key),
    };
    let mut out = config.clone();
    out.leader_timeout_ms = g::within_bounds(
        config.leader_timeout_ms,
        read(g::CONSENSUS_LEADER_TIMEOUT_MIN_PARAM),
        read(g::CONSENSUS_LEADER_TIMEOUT_MAX_PARAM),
    );
    out.min_round_interval_ms = g::within_bounds(
        config.min_round_interval_ms,
        read(g::CONSENSUS_ROUND_INTERVAL_MIN_PARAM),
        read(g::CONSENSUS_ROUND_INTERVAL_MAX_PARAM),
    );
    out
}

/// `consensus.sender_failover_ms` as governed in `storage`, or its genesis
/// value without storage.
pub(crate) fn governed_failover(storage: Option<&Arc<dyn KvStore>>) -> Duration {
    use tenzro_vm::governance as g;
    let ms = match storage {
        Some(s) => tenzro_vm::native::network_param(
            &tenzro_vm::StateAdapter::with_storage(s.clone()),
            g::CONSENSUS_SENDER_FAILOVER_PARAM,
        ),
        None => g::governed_param(g::CONSENSUS_SENDER_FAILOVER_PARAM).map_or(10_000, |p| p.genesis),
    };
    Duration::from_millis(ms)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A change goes out at once and is repeated on the next periodic
    /// announcements, so a peer whose mesh to this validator formed after the
    /// first publication still receives the sealed endpoints soon; then the
    /// set rides only every RESEAL_EVERY announcement.
    #[test]
    fn a_changed_sealed_set_is_repeated_on_the_periodic_announcements() {
        let mut repeats = 0;
        assert!(sealed_due(true, true, 0, &mut repeats));
        for _ in 0..RESEAL_REPEATS {
            assert!(sealed_due(false, false, 0, &mut repeats));
        }
        assert!(!sealed_due(false, false, 0, &mut repeats));
        assert!(!sealed_due(false, false, RESEAL_EVERY - 1, &mut repeats));
        assert!(sealed_due(false, false, RESEAL_EVERY, &mut repeats));
    }

    /// A wake-up that changed nothing neither carries the set nor uses up
    /// the repeats owed to the periodic announcements.
    #[test]
    fn a_wake_up_does_not_spend_the_repeats() {
        let mut repeats = RESEAL_REPEATS;
        assert!(!sealed_due(false, true, 0, &mut repeats));
        assert_eq!(repeats, RESEAL_REPEATS);
    }

    /// A frame for an epoch other than the channel's own is still an
    /// authenticated frame -- its MAC already verified before `route_frame`
    /// sees it -- so it routes by the epoch it actually names instead of
    /// being refused outright.
    #[test]
    fn a_frame_for_another_epoch_is_routed_not_refused() {
        let frame = Frame {
            epoch: 7,
            items: vec![Message::FetchVertices(vec![])],
        };
        let (epoch, messages) = Links::route_frame(frame).expect("a non-empty frame routes");
        assert_eq!(epoch, 7);
        assert_eq!(messages.len(), 1);
    }

    /// The empty frame a channel sends as a keepalive routes nothing,
    /// whatever epoch it names.
    #[test]
    fn an_empty_keepalive_frame_routes_nothing() {
        let frame = Frame {
            epoch: 3,
            items: Vec::new(),
        };
        assert!(Links::route_frame(frame).is_none());
    }

    /// Batch pushes and fetch replies are the only bulk-classified
    /// messages; everything else, including a `Vertices` answer or an
    /// `Ordering` state reply, stays on the control stream.
    #[test]
    fn only_batch_and_batches_are_classified_as_bulk() {
        assert!(is_bulk_message(&Message::Batch(BatchPayload {
            epoch: 0,
            author: 0,
            sequence: 0,
            transactions: 0,
            body: Vec::new(),
        })));
        assert!(is_bulk_message(&Message::Batches(Vec::new())));
        assert!(!is_bulk_message(&Message::FetchBatches(Vec::new())));
        assert!(!is_bulk_message(&Message::FetchVertices(Vec::new())));
        assert!(!is_bulk_message(&Message::Vertices(Vec::new())));
        assert!(!is_bulk_message(&Message::Signals(Vec::new())));
    }

    /// A validator's own leader timeout and round interval run inside the
    /// governed bounds; inside them, its configuration stands.
    #[test]
    fn round_timing_is_held_inside_the_governed_bounds() {
        let mut cfg = ConsensusConfig::default();
        let same = governed_timing(&cfg, None);
        assert_eq!(same.leader_timeout_ms, cfg.leader_timeout_ms);
        assert_eq!(same.min_round_interval_ms, cfg.min_round_interval_ms);
        cfg.leader_timeout_ms = 1;
        cfg.min_round_interval_ms = 1_000_000;
        let held = governed_timing(&cfg, None);
        assert_eq!(held.leader_timeout_ms, 100);
        assert_eq!(held.min_round_interval_ms, 2_000);
    }

    /// Transactions ordered late after stepping in are not timed, so they
    /// cannot raise the grace; and a slow start ages out of the percentiles.
    #[test]
    fn the_assignment_grace_does_not_feed_on_itself() {
        let t0 = Instant::now();
        let mut l = OrderedLatencies::new();
        for i in 0..100 {
            l.record(t0 + Duration::from_millis(i), 1_000);
        }
        let bound = Duration::from_secs(60);
        assert_eq!(
            l.grace(t0 + Duration::from_secs(1), bound),
            ASSIGNMENT_GRACE
        );
        let start = t0 + Duration::from_secs(1);
        l.record(start, 39_000);
        assert_eq!(l.quantile(start, 1.0), 39_000);
        let later = start + LATENCY_HORIZON + Duration::from_secs(1);
        assert_eq!(l.quantile(later, 0.99), 0);
        for i in 0..10 {
            l.record(later + Duration::from_millis(i), 2_000);
        }
        assert_eq!(l.quantile(later + Duration::from_secs(1), 0.99), 2_000);
        assert_eq!(
            l.grace(later + Duration::from_secs(1), bound),
            Duration::from_secs(4)
        );
        // However slow ordering becomes, the next validator steps in within
        // the governed bound.
        for _ in 0..20 {
            l.record(later + Duration::from_secs(2), 900_000);
        }
        assert_eq!(l.grace(later + Duration::from_secs(3), bound), bound);
    }

    /// A test sink: each write takes `delay` (forever when `None`) and the
    /// first `fail_at` writes succeed.
    struct TestSink {
        delay: Option<Duration>,
        fail_at: usize,
        written: usize,
    }

    impl FrameSink for TestSink {
        async fn write(&mut self, _frame: Vec<u8>) -> bool {
            match self.delay {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending::<()>().await,
            }
            self.written += 1;
            self.written <= self.fail_at
        }
    }

    /// A channel with nothing queued still writes, once each keepalive
    /// interval, so its peer can tell it from one that broke; the keepalive
    /// is not counted against the queue.
    #[tokio::test(start_paused = true)]
    async fn an_idle_send_side_writes_a_keepalive_each_interval() {
        let (queue, mut rx) = PeerQueue::new();
        let start = tokio::time::Instant::now();
        let mut sink = TestSink {
            delay: Some(Duration::ZERO),
            fail_at: 3,
            written: 0,
        };
        let end = write_queued(
            &mut rx,
            &queue,
            |f| Some(f.to_vec()),
            &mut sink,
            Some(&[0u8]),
        )
        .await;
        assert_eq!(end, SendEnd::Failed);
        assert_eq!(sink.written, 4);
        assert_eq!(start.elapsed(), CHANNEL_KEEPALIVE * 4);
        assert_eq!(queue.queued.load(Ordering::Acquire), 0);
        assert!(CHANNEL_SILENCE >= CHANNEL_KEEPALIVE * 5);
    }

    /// The leader lookahead starts at the consensus core's genesis value.
    #[test]
    fn the_governed_lookahead_starts_at_the_core_value() {
        assert_eq!(
            governed_lookahead(None),
            tenzro_consensus::schedule::LOOKAHEAD_ROUNDS
        );
    }

    /// A peer that takes nothing at all, slow or malicious, holds this node
    /// to at most its queue: frames past the byte budget are refused, not
    /// buffered, however many are offered.
    #[test]
    fn a_peer_that_takes_nothing_costs_at_most_its_queue() {
        let (queue, _rx) = PeerQueue::new();
        let frame = 1 << 20;
        let mut refused = 0;
        for _ in 0..(4 * PEER_QUEUE_BYTES / frame) {
            if !queue.try_send(vec![0; frame]) {
                refused += 1;
            }
        }
        assert!(queue.queued.load(Ordering::Acquire) <= PEER_QUEUE_BYTES);
        assert!(refused >= 3 * PEER_QUEUE_BYTES / frame);
    }

    /// A peer that stops taking frames while its own still arrive: the send
    /// side ends as stalled after exactly `CHANNEL_WRITE_STALL`, so the channel
    /// closes and is dialled again.
    #[tokio::test(start_paused = true)]
    async fn a_send_side_the_peer_stops_taking_ends_the_channel_after_the_silence_limit() {
        let (queue, mut rx) = PeerQueue::new();
        assert!(queue.try_send(vec![1; 10]));
        let start = tokio::time::Instant::now();
        let mut sink = TestSink {
            delay: None,
            fail_at: usize::MAX,
            written: 0,
        };
        let end = write_queued(&mut rx, &queue, |f| Some(f.to_vec()), &mut sink, None).await;
        assert_eq!(end, SendEnd::Stalled);
        assert_eq!(start.elapsed(), CHANNEL_WRITE_STALL);
        assert_eq!(queue.queued.load(Ordering::Acquire), 0);
    }

    /// A slow peer that keeps taking frames is not a failure; a write that
    /// errors, or a frame that cannot be sealed, ends the channel at once.
    #[tokio::test(start_paused = true)]
    async fn a_send_side_ends_on_a_failed_write_but_not_on_a_slow_peer() {
        let (queue, mut rx) = PeerQueue::new();
        for _ in 0..3 {
            assert!(queue.try_send(vec![0; 4]));
        }
        let mut sink = TestSink {
            delay: Some(CHANNEL_WRITE_STALL - Duration::from_secs(1)),
            fail_at: 2,
            written: 0,
        };
        assert_eq!(
            write_queued(&mut rx, &queue, |f| Some(f.to_vec()), &mut sink, None).await,
            SendEnd::Failed
        );
        assert_eq!(sink.written, 3);

        let (queue, mut rx) = PeerQueue::new();
        assert!(queue.try_send(vec![0; 4]));
        let mut sink = TestSink {
            delay: Some(Duration::ZERO),
            fail_at: usize::MAX,
            written: 0,
        };
        assert_eq!(
            write_queued(&mut rx, &queue, |_| None, &mut sink, None).await,
            SendEnd::SealFailed
        );
        assert_eq!(sink.written, 0);
    }

    #[tokio::test]
    async fn entering_the_next_epoch_closes_the_previous_epochs_channels_and_counts_none_of_them() {
        let channels = EpochChannels::new(0);
        let mut old = channels
            .open(0, 1, StreamKind::Control, PeerQueue::new().0)
            .expect("a channel of the running epoch");
        assert!(channels.is_open(0, 1, StreamKind::Control));
        channels.enter(1);
        // The old channel ends by itself: nothing need be sent on it.
        let end = tokio::time::timeout(Duration::from_secs(1), old.ended_or_closed())
            .await
            .expect("the old epoch's channel ended");
        assert!(matches!(end, LeaseEnd::Ended));
        // And it never counts for the new epoch, so the peer is dialled again.
        assert!(!channels.is_open(1, 1, StreamKind::Control));
        drop(old);
        assert!(!channels.is_open(0, 1, StreamKind::Control));
        // A handshake that bound the old committee does not come up.
        assert!(
            channels
                .open(0, 2, StreamKind::Control, PeerQueue::new().0)
                .is_none()
        );
        let mut new = channels
            .open(1, 1, StreamKind::Control, PeerQueue::new().0)
            .expect("a channel of the new epoch");
        assert!(channels.is_open(1, 1, StreamKind::Control));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), new.ended_or_closed())
                .await
                .is_err(),
            "a live channel ended"
        );
    }

    /// A peer's control and bulk channels are leased independently: one
    /// kind opening, failing or closing never touches the other's lease, so
    /// a bulk stream that cannot be established leaves control unaffected
    /// (and vice versa).
    #[tokio::test]
    async fn control_and_bulk_channels_to_the_same_peer_are_independent() {
        let channels = EpochChannels::new(0);
        let control = channels
            .open(0, 1, StreamKind::Control, PeerQueue::new().0)
            .expect("a control channel");
        let bulk = channels
            .open(0, 1, StreamKind::Bulk, PeerQueue::new().0)
            .expect("a bulk channel to the same peer");
        assert!(channels.is_open(0, 1, StreamKind::Control));
        assert!(channels.is_open(0, 1, StreamKind::Bulk));
        drop(bulk);
        assert!(
            channels.is_open(0, 1, StreamKind::Control),
            "the control channel survives its bulk sibling closing"
        );
        assert!(!channels.is_open(0, 1, StreamKind::Bulk));
        drop(control);
        assert!(!channels.is_open(0, 1, StreamKind::Control));
    }

    /// `handshake_budget` and `silence_budget` never fall below their fixed
    /// floors on a fast path, scale up with rtt past them, and
    /// `handshake_budget`'s retry scale is capped so a run of timeouts does
    /// not grow the budget without bound.
    #[test]
    fn rtt_budgets_floor_scale_and_cap() {
        assert_eq!(
            handshake_budget(Duration::from_millis(1), 1),
            HANDSHAKE_TIMEOUT
        );
        assert_eq!(silence_budget(Duration::from_millis(1)), CHANNEL_SILENCE);
        let slow = Duration::from_secs(1);
        assert_eq!(handshake_budget(slow, 1), slow * HANDSHAKE_RTT_FACTOR);
        assert_eq!(silence_budget(slow), slow * SILENCE_RTT_FACTOR);
        assert_eq!(
            handshake_budget(slow, 1_000),
            HANDSHAKE_RETRY_CAP,
            "a growing retry scale must not push the handshake budget past its cap"
        );
    }

    /// A channel may be opened one epoch ahead of the current one -- what
    /// `Links::pre_dial_next_epoch` does, before this node's own epoch has
    /// moved there -- but no further ahead, and never behind it.
    #[test]
    fn a_channel_may_be_opened_one_epoch_ahead_of_the_current_one() {
        let channels = EpochChannels::new(5);
        let _held = channels
            .open(6, 1, StreamKind::Control, PeerQueue::new().0)
            .expect("the next epoch may be pre-dialled");
        assert!(
            channels
                .open(7, 1, StreamKind::Control, PeerQueue::new().0)
                .is_none(),
            "two epochs ahead is refused"
        );
        assert!(
            channels
                .open(4, 1, StreamKind::Control, PeerQueue::new().0)
                .is_none(),
            "an earlier epoch is refused"
        );
        assert!(channels.is_open(6, 1, StreamKind::Control));
    }

    /// A lease opened for the next epoch (pre-dialled ahead of the
    /// handover) is not reported ended while this node's own epoch is still
    /// the one before it, nor the moment that epoch arrives -- only once the
    /// epoch moves past the lease's own, same as any other lease.
    #[tokio::test]
    async fn a_pre_dialled_lease_survives_into_its_own_epoch() {
        let channels = EpochChannels::new(5);
        let mut lease = channels
            .open(6, 1, StreamKind::Control, PeerQueue::new().0)
            .expect("the next epoch may be pre-dialled");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), lease.ended_or_closed())
                .await
                .is_err(),
            "still ahead of the current epoch: not ended yet"
        );
        channels.enter(6);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), lease.ended_or_closed())
                .await
                .is_err(),
            "the lease's epoch just became current: still not ended"
        );
        channels.enter(7);
        assert!(
            matches!(
                tokio::time::timeout(Duration::from_millis(50), lease.ended_or_closed()).await,
                Ok(LeaseEnd::Ended)
            ),
            "the epoch moved past the lease's own: now ended"
        );
    }

    /// `EpochChannels::open_now` is what lets a pre-dialled channel reach
    /// the engine once this node actually enters that epoch: `keep_dialled`
    /// never resends `PeerUp` for a channel its own `is_open` check finds
    /// already up.
    #[test]
    fn open_now_lists_only_the_given_epochs_channels() {
        let channels = EpochChannels::new(5);
        let _current = channels
            .open(5, 1, StreamKind::Control, PeerQueue::new().0)
            .expect("the current epoch");
        let _next_control = channels
            .open(6, 2, StreamKind::Control, PeerQueue::new().0)
            .expect("pre-dialled control");
        let _next_bulk = channels
            .open(6, 2, StreamKind::Bulk, PeerQueue::new().0)
            .expect("pre-dialled bulk");
        let mut now: Vec<_> = channels
            .open_now(6)
            .into_iter()
            .map(|(peer, kind, _)| (peer, kind))
            .collect();
        now.sort_by_key(|(p, k)| (*p, *k == StreamKind::Bulk));
        assert_eq!(now, vec![(2, StreamKind::Control), (2, StreamKind::Bulk)]);
    }

    /// Under loss both sides can dial a peer at once, so two channels to it
    /// can both be live while the engine keeps only the newer one's sender.
    /// If the newer one dies, the older one -- still live -- must be handed
    /// back to the engine rather than left orphaned: this seed stalled
    /// chaos runs for 840-966s with exactly this signature (dial_stage
    /// "running the channel" for peers missing from `peers`).
    #[tokio::test]
    async fn a_peers_older_channel_survives_its_newer_sibling_dying() {
        let channels = EpochChannels::new(0);
        let (older_tx, _older_rx) = PeerQueue::new();
        let older = channels
            .open(0, 1, StreamKind::Control, older_tx)
            .expect("a channel");
        let (newer_tx, _newer_rx) = PeerQueue::new();
        let newer = channels
            .open(0, 1, StreamKind::Control, newer_tx)
            .expect("a second channel");
        let survivor = newer.retire();
        assert!(
            survivor.is_some(),
            "the older, still-live channel should be promoted once the newer one dies"
        );
        drop(newer);
        assert!(
            channels.is_open(0, 1, StreamKind::Control),
            "the older channel is still live"
        );
        drop(older);
        assert!(!channels.is_open(0, 1, StreamKind::Control));
    }

    /// The backstop for any route the engine cannot otherwise explain: a
    /// force-closed peer's live channels end even though nothing about them
    /// looks unhealthy on their own.
    #[tokio::test]
    async fn force_closing_a_peer_ends_every_live_channel_to_it() {
        let channels = EpochChannels::new(0);
        let (tx, _rx) = PeerQueue::new();
        let mut lease = channels
            .open(0, 1, StreamKind::Control, tx)
            .expect("a channel");
        channels.force_close(0, 1);
        let end = tokio::time::timeout(Duration::from_secs(1), lease.ended_or_closed())
            .await
            .expect("ended_or_closed should resolve once force_close is called");
        assert!(matches!(end, LeaseEnd::Closed));
    }

    /// One peer cannot open channels without bound: past a few at once the
    /// next is refused until one closes.
    #[tokio::test]
    async fn one_peer_holds_a_bounded_number_of_channels() {
        let channels = EpochChannels::new(0);
        let held: Vec<_> = (0..4)
            .map(|_| {
                channels
                    .open(0, 1, StreamKind::Control, PeerQueue::new().0)
                    .expect("a channel")
            })
            .collect();
        assert!(
            channels
                .open(0, 1, StreamKind::Control, PeerQueue::new().0)
                .is_none(),
            "a fifth channel came up"
        );
        assert!(
            channels
                .open(0, 2, StreamKind::Control, PeerQueue::new().0)
                .is_some(),
            "another peer is not limited"
        );
        drop(held);
        assert!(
            channels
                .open(0, 1, StreamKind::Control, PeerQueue::new().0)
                .is_some()
        );
    }

    /// A stream that opens and then stalls mid-handshake is dropped once the
    /// handshake time runs out, rather than held for as long as the dialler
    /// likes.
    #[tokio::test]
    async fn a_handshake_that_stalls_is_dropped() {
        type Stream = ([u8; 32], tenzro_iroh::SendStream, tenzro_iroh::RecvStream);
        #[derive(Debug)]
        struct Hand(mpsc::UnboundedSender<Stream>);
        #[async_trait::async_trait]
        impl tenzro_iroh::ConsensusStreamHandler for Hand {
            fn admits(&self, _remote: &[u8; 32]) -> bool {
                true
            }
            async fn accept_stream(
                &self,
                remote: [u8; 32],
                _rtt: Duration,
                send: tenzro_iroh::SendStream,
                recv: tenzro_iroh::RecvStream,
            ) {
                let _ = self.0.send((remote, send, recv));
            }
        }

        let c = Committee4::new();
        let server = tenzro_iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let (inputs, _rx) = mpsc::unbounded_channel();
        let links = Links {
            endpoint: server.clone(),
            identity: None,
            session: Arc::new(SessionKey::generate().expect("key")),
            chain_id: 7,
            genesis_hash: [1; 32],
            committee: RwLock::new(c.handle.committee(0).expect("committee")),
            me: RwLock::new(3),
            inputs,
            endpoints: Arc::new(RwLock::new(EndpointBook::new())),
            announcement: Arc::new(RwLock::new(None)),
            channels: EpochChannels::new(0),
            dial_diag: parking_lot::Mutex::new(HashMap::new()),
            dial_stage: parking_lot::Mutex::new(HashMap::new()),
        };
        let (streams, mut accepted) = mpsc::unbounded_channel();
        let _router = iroh::protocol::Router::builder(server.clone())
            .accept(
                tenzro_iroh::ALPN_CONSENSUS,
                tenzro_iroh::consensus::ConsensusProtocol::new(Arc::new(Hand(streams))),
            )
            .spawn();
        let client = tenzro_iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let (mut send, _recv) = tenzro_iroh::open_consensus_stream(&client, server.addr())
            .await
            .unwrap();
        // Half of a frame's length prefix, and then nothing.
        send.write_all(&[0, 0]).await.unwrap();
        let (remote, s, r) = accepted.recv().await.expect("the stream reached the node");
        let answered = tokio::time::timeout(
            Duration::from_secs(30),
            links.answer(remote, Duration::ZERO, s, r),
        )
        .await;
        assert!(
            matches!(answered, Ok(Err(_))),
            "the stalled handshake was still held after 30s"
        );
    }

    /// Recording a committee member's freshly signed endpoint announcement
    /// wakes the announcer loop at once, rather than leaving it to notice
    /// only at its next `ANNOUNCE_INTERVAL` tick (up to 30s away).
    ///
    /// A validator that just restarted holds an empty endpoint book: it
    /// admits no one (see `admits`, above) until it has resealed its own
    /// endpoint to every member and been resealed to in return, and each
    /// leg of that exchange used to wait for the announcer's own 30s tick
    /// to notice anything had changed. With several unsynchronised legs
    /// needed and gossip itself thinner under the same packet loss, this
    /// stalled liveness for minutes after a single restart (chaos seed
    /// 3054677367: 268-928s gaps despite a quorum up) rather than the few
    /// seconds a dial retry should cost once the exchange is immediate.
    #[tokio::test(flavor = "multi_thread")]
    async fn offering_a_changed_announcement_wakes_the_announcer_at_once() {
        fn toy_published(signer: &SessionKey, seed: u8) -> PublishedAnnouncement {
            let opening =
                EndpointOpening::new([seed; 32], format!("did:tenzro:machine:test{seed}"))
                    .expect("opening");
            let disclosure = DisclosureSecret::generate();
            let announcement = EndpointAnnouncement::sign(
                signer,
                7,
                [1; 32],
                &opening,
                signer.public_key().clone(),
                disclosure.public().clone(),
                unix_ms(),
                6 * 3_600 * 1_000,
            )
            .expect("announcement");
            PublishedAnnouncement {
                announcement,
                sealed: Vec::new(),
            }
        }

        let c = Committee4::new();
        *c.handle.own_key.write() = Some(c.keys[3].public_key().fingerprint());

        let published = toy_published(&c.keys[0], 40);
        let published_again = published.clone();
        c.handle.offer_announcement(published);

        tokio::time::timeout(Duration::from_millis(200), c.handle.reseal_kick.notified())
            .await
            .expect(
                "recording committee member 0's announcement should wake the announcer at \
                 once; it did not within 200ms, so it is still waiting for its own \
                 ANNOUNCE_INTERVAL tick (up to 30s away) as it did before this fix",
            );

        // The same announcement again, as every member's periodic republish
        // delivers it: nothing changed, so the announcer stays asleep.
        c.handle.offer_announcement(published_again);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), c.handle.reseal_kick.notified())
                .await
                .is_err(),
            "a repeat of the announcement already held woke the announcer, which then \
             publishes its own, so every republish anywhere is answered by every member"
        );
    }

    /// A validator key known by its public half only: seating looks at
    /// nothing else.
    struct PublicOnly(tenzro_consensus::ValidatorPublicKey);

    impl ValidatorSigner for PublicOnly {
        fn public_key(&self) -> &tenzro_consensus::ValidatorPublicKey {
            &self.0
        }
        fn sign(
            &self,
            _domain: &[u8],
            _message: &[u8],
        ) -> tenzro_consensus::Result<tenzro_consensus::CompositeSignature> {
            Err(tenzro_consensus::ConsensusError::HardwareKeyUnavailable(
                "a public key only".into(),
            ))
        }
    }

    /// A validator whose key is being rotated holds the key in force and the
    /// key the rotation seats. The key in force seats it for the epoch it
    /// runs; at the epoch whose committee seats the new key in its place,
    /// the same node, launcher and engine path take the new key, which then
    /// names it in its announcements, with no restart.
    #[tokio::test]
    async fn a_rotating_validator_signs_with_its_new_key_from_the_epoch_that_seats_it() {
        let c = Committee4::new();
        let old = c.keys[3].public_key().clone();
        let new = tenzro_consensus::session::SessionKey::generate()
            .expect("key")
            .public_key()
            .clone();
        let old_signer: Arc<dyn ValidatorSigner> = Arc::new(PublicOnly(old.clone()));
        let endpoint = tenzro_iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let (segments, _) = mpsc::channel(1);
        let (certificates, _) = mpsc::unbounded_channel();
        let (compact, _) = mpsc::unbounded_channel();
        let (evidence, _) = mpsc::unbounded_channel();
        let (announcements, _) = mpsc::unbounded_channel();
        c.handle.set_launcher(Launcher {
            signer: old_signer.clone(),
            high_water: Arc::new(NoVotes),
            endpoint,
            identity: None,
            machine: None,
            handler: tenzro_iroh::DeferredConsensusHandler::new(),
            segments,
            certificates,
            compact,
            evidence,
            announcements,
        });
        c.handle.set_incoming_key(Arc::new(PublicOnly(new.clone())));

        let (launcher, _, _) = c.handle.seat(0).unwrap().expect("seated in epoch 0");
        assert_eq!(
            launcher.signer.public_key(),
            &old,
            "the key in force signs while its committee seats it"
        );

        // Epoch 1 seats the new key in the place of the old one.
        let members = c.keys[..3]
            .iter()
            .map(|k| k.public_key().clone())
            .chain(std::iter::once(new.clone()))
            .enumerate()
            .map(|(i, key)| {
                tenzro_consensus::validator::ValidatorInfo::new(
                    Address::new([i as u8 + 1; 32]),
                    key,
                    [i as u8 + 1; 32],
                    1 << 80,
                )
            })
            .collect();
        let set = tenzro_consensus::validator::ValidatorSet::new(1, members).expect("set");
        let next =
            tenzro_consensus::committee::from_validator_set(&set, c.handle.config.seat_budget)
                .expect("committee");
        assert!(next.members().iter().all(|m| m.public_key != old));

        // The running engine's handover asks with the key it signs with.
        let (signer, me) = c
            .handle
            .key_for(&next, &old_signer)
            .expect("the new key seats this validator at the epoch that seats it");
        assert_eq!(signer.public_key(), &new);
        assert_eq!(
            next.members()[me as usize].public_key,
            new,
            "its index is the new key's seat"
        );
        assert_eq!(*c.handle.own_key.read(), Some(new.fingerprint()));

        // A later start, recovery or launch from the launcher takes the new
        // key as well.
        c.handle.add_committee(next);
        let (launcher, _, _) = c.handle.seat(1).unwrap().expect("seated in epoch 1");
        assert_eq!(launcher.signer.public_key(), &new);
    }

    /// A peer's inbound budget the core never frees -- stuck, like every
    /// validator's own round advance was for minutes on end in chaos seed
    /// 3054677367, well after the chaos run's last induced packet loss --
    /// must not hang this reader forever: every other wait on this
    /// channel's loop is bounded, and this one needs to be too.
    #[tokio::test(start_paused = true)]
    async fn an_inbound_budget_the_core_never_frees_does_not_hang_forever() {
        let budget = Arc::new(tokio::sync::Semaphore::new(PEER_INBOUND_BYTES as usize));
        let _held = budget
            .clone()
            .try_acquire_many_owned(PEER_INBOUND_BYTES)
            .unwrap();
        let waited =
            tokio::time::timeout(Duration::from_secs(600), acquire_inbound_budget(&budget, 1))
                .await;
        assert!(
            waited.is_ok(),
            "acquire_inbound_budget should give up once the core has had long enough to free \
             this peer's budget, rather than wait on it for over 600s (10 minutes) as it did \
             before this fix"
        );
        assert!(
            waited.unwrap().is_err(),
            "an exhausted, never-freed budget should be reported as a failure, not silently granted"
        );
    }

    /// A dial whose peer accepts the stream and then stalls mid-handshake is
    /// dropped once the handshake time runs out, rather than held forever.
    ///
    /// The dialling side used to carry no timeout at all (only the
    /// answering side did, see the test above) - so a peer that went
    /// silent right after accepting a connection, exactly what
    /// packet loss can cause mid-epoch, could wedge that
    /// peer's `keep_dialled` task permanently: no error, no backoff, no
    /// further redial ever attempted, for the rest of the run.
    #[tokio::test]
    async fn a_dial_that_stalls_mid_handshake_is_dropped() {
        type Stream = ([u8; 32], tenzro_iroh::SendStream, tenzro_iroh::RecvStream);
        #[derive(Debug)]
        struct Hand(mpsc::UnboundedSender<Stream>);
        #[async_trait::async_trait]
        impl tenzro_iroh::ConsensusStreamHandler for Hand {
            fn admits(&self, _remote: &[u8; 32]) -> bool {
                true
            }
            async fn accept_stream(
                &self,
                remote: [u8; 32],
                _rtt: Duration,
                send: tenzro_iroh::SendStream,
                recv: tenzro_iroh::RecvStream,
            ) {
                let _ = self.0.send((remote, send, recv));
            }
        }

        fn toy_announcement(seed: u8) -> (EndpointAnnouncement, EndpointOpening) {
            let signer = SessionKey::generate().expect("key");
            let opening =
                EndpointOpening::new([seed; 32], format!("did:tenzro:machine:test{seed}"))
                    .expect("opening");
            let disclosure = DisclosureSecret::generate();
            let announcement = EndpointAnnouncement::sign(
                &signer,
                7,
                [1; 32],
                &opening,
                signer.public_key().clone(),
                disclosure.public().clone(),
                1_800_000_000_000,
                6 * 3_600 * 1_000,
            )
            .expect("announcement");
            (announcement, opening)
        }

        let c = Committee4::new();
        let committee = c.handle.committee(0).expect("committee");
        let (own, opening) = toy_announcement(10);
        let (peer_announcement, _) = toy_announcement(20);

        // A server that accepts every stream and then never says another
        // word on any of them: held alive, never read, never written to.
        let server = tenzro_iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let (streams, mut accepted) = mpsc::unbounded_channel();
        let _router = iroh::protocol::Router::builder(server.clone())
            .accept(
                tenzro_iroh::ALPN_CONSENSUS,
                tenzro_iroh::consensus::ConsensusProtocol::new(Arc::new(Hand(streams))),
            )
            .spawn();
        let held: Arc<RwLock<Vec<Stream>>> = Arc::new(RwLock::new(Vec::new()));
        let held2 = held.clone();
        tokio::spawn(async move {
            while let Some(stream) = accepted.recv().await {
                held2.write().push(stream);
            }
        });

        let (inputs, _rx) = mpsc::unbounded_channel();
        let client = tenzro_iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let links = Links {
            endpoint: client,
            identity: None,
            session: Arc::new(SessionKey::generate().expect("key")),
            chain_id: 7,
            genesis_hash: [1; 32],
            committee: RwLock::new(committee.clone()),
            me: RwLock::new(0),
            inputs,
            endpoints: Arc::new(RwLock::new(EndpointBook::new())),
            announcement: Arc::new(RwLock::new(None)),
            channels: EpochChannels::new(committee.epoch),
            dial_diag: parking_lot::Mutex::new(HashMap::new()),
            dial_stage: parking_lot::Mutex::new(HashMap::new()),
        };

        // Raw: the handshake itself carries no bound at all - that is the
        // bug. It is still pending once a generous bound runs out. The
        // connect step is out of dial_handshake's own scope now (split from
        // it so a slow connect and a slow handshake get separate budgets), so the test opens the stream
        // itself, the same way dial_inner does just before calling it.
        let (send, recv) = tenzro_iroh::open_consensus_stream(&links.endpoint, server.addr())
            .await
            .expect("the stream opens; only the handshake past it stalls");
        let raw = tokio::time::timeout(
            Duration::from_millis(300),
            links.dial_handshake(
                send,
                recv,
                &committee,
                0,
                1,
                &own,
                &opening,
                &peer_announcement,
                StreamKind::Control,
            ),
        )
        .await;
        assert!(
            raw.is_err(),
            "the stalled dial finished on its own, with no caller timeout"
        );

        // Wrapped exactly as `dial` wraps it: the fix bounds it to
        // HANDSHAKE_TIMEOUT, so it is dropped instead of held forever.
        let (send, recv) = tenzro_iroh::open_consensus_stream(&links.endpoint, server.addr())
            .await
            .expect("the stream opens; only the handshake past it stalls");
        let wrapped = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                links.dial_handshake(
                    send,
                    recv,
                    &committee,
                    0,
                    1,
                    &own,
                    &opening,
                    &peer_announcement,
                    StreamKind::Control,
                ),
            ),
        )
        .await;
        assert!(
            matches!(wrapped, Ok(Err(_))),
            "the stalled dial was still held after HANDSHAKE_TIMEOUT"
        );
    }

    /// Peers sending without pause cannot keep the engine handling their
    /// input: one pass takes a bounded number, and the rest wait in the
    /// queue while the engine ticks and flushes.
    #[test]
    fn one_pass_takes_a_bounded_number_of_inputs() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        for i in 1..10_000u32 {
            tx.send(i).unwrap();
        }
        let pass = take_ready(0u32, &mut rx, INPUTS_PER_PASS);
        assert!(
            pass.len() <= INPUTS_PER_PASS,
            "{} inputs in one pass",
            pass.len()
        );
        assert_eq!(pass[..3], [0, 1, 2]);
        assert_eq!(rx.try_recv().unwrap() as usize, pass.len());
    }

    /// Every channel a peer holds draws on one inbound budget, so more
    /// channels never buy it more of this node's memory; a fresh budget
    /// comes only once all of them closed.
    #[tokio::test]
    async fn a_peer_s_channels_share_one_inbound_budget() {
        let channels = EpochChannels::new(0);
        let first = channels
            .open(0, 1, StreamKind::Control, PeerQueue::new().0)
            .expect("a channel");
        let second = channels
            .open(0, 1, StreamKind::Control, PeerQueue::new().0)
            .expect("a second channel");
        assert!(Arc::ptr_eq(&first.inbound, &second.inbound));
        let held = first
            .inbound
            .clone()
            .try_acquire_many_owned(PEER_INBOUND_BYTES)
            .expect("the whole budget");
        assert_eq!(second.inbound.available_permits(), 0);
        let other = channels
            .open(0, 2, StreamKind::Control, PeerQueue::new().0)
            .expect("another peer's channel");
        assert_eq!(
            other.inbound.available_permits(),
            PEER_INBOUND_BYTES as usize
        );
        drop(held);
        drop((first, second));
        let fresh = channels
            .open(0, 1, StreamKind::Control, PeerQueue::new().0)
            .expect("a channel again");
        assert_eq!(
            fresh.inbound.available_permits(),
            PEER_INBOUND_BYTES as usize
        );
    }

    /// The validator account's allocator numbers from what the chain and the
    /// mempool leave free: an admission that fails leaves no gap behind it.
    #[test]
    fn a_failed_admission_leaves_its_nonce_free() {
        let consensus = handle_with_one_validator();
        let storage: Arc<dyn tenzro_storage::KvStore> =
            Arc::new(tenzro_storage::MemoryStore::new());
        let nonces = crate::payment_rails::NonceReservation::default();
        let account = Address::new([4; 32]);
        let refused: std::result::Result<u64, &str> =
            nonces.admit_next(&consensus, storage.clone(), &account, |_| {
                Err("rejected by the mempool")
            });
        assert!(refused.is_err());
        let next = nonces
            .admit_next(&consensus, storage.clone(), &account, Ok::<u64, ()>)
            .unwrap();
        assert_eq!(next, 0, "the refused nonce is handed out again");
        // Nothing reached the mempool, so the account's next nonce is still free.
        let again = nonces
            .admit_next(&consensus, storage, &account, Ok::<u64, ()>)
            .unwrap();
        assert_eq!(again, 0);
    }

    pub(crate) fn handle_with_one_validator() -> Arc<ConsensusHandle> {
        handle_with_stores(
            Arc::new(tenzro_storage::MemoryStore::new()),
            Arc::new(tenzro_storage::MemoryStore::new()),
        )
    }

    fn handle_with_stores(
        node: Arc<dyn KvStore>,
        records: Arc<dyn KvStore>,
    ) -> Arc<ConsensusHandle> {
        let key = tenzro_consensus::ValidatorPublicKey::new(
            tenzro_crypto::pq::MlDsaSigningKey::generate()
                .verifying_key_bytes()
                .to_vec(),
            tenzro_crypto::P256KeyPair::generate()
                .public_key_sec1()
                .to_vec(),
        )
        .expect("well-formed key");
        let v = tenzro_consensus::validator::ValidatorInfo::new(
            Address::new([1; 32]),
            key,
            [1; 32],
            1 << 80,
        );
        let em = Arc::new(EpochManager::new(vec![v], 100).expect("epoch manager"));
        ConsensusHandle::new(
            tenzro_consensus::ConsensusConfig::default(),
            TimeRules::default(),
            7,
            [1; 32],
            em,
            Some(node),
            Some(records),
        )
        .expect("consensus handle")
    }

    /// A handle seated as validator 0 of its one-member committee, as a
    /// running core leaves it.
    pub(crate) fn seated_validator() -> Arc<ConsensusHandle> {
        let handle = handle_with_one_validator();
        *handle.me.write() = Some(0);
        handle
    }

    struct AtNonce(u64);

    impl tenzro_consensus::mempool::AccountStateReader for AtNonce {
        fn account_nonce(&self, _: &Address) -> u64 {
            self.0
        }
        fn account_balance(&self, _: &Address) -> u128 {
            u128::MAX / 4
        }
        fn block_base_fee(&self) -> u128 {
            0
        }
    }

    /// A sender's later transaction is not cut into a new part while the
    /// part holding the one before it is not yet ordered: that part can be
    /// handed back or lost with its core, and the later part ordered ahead
    /// of it would execute ahead of its nonce and fail. Once the earlier
    /// part is ordered the later one follows it; once it is handed back the
    /// whole run is cut again in nonce order.
    #[test]
    fn a_later_nonce_is_not_cut_while_the_one_before_it_is_unordered() {
        use tenzro_crypto::composite::HybridSigner as _;
        use tenzro_types::transaction::{Transaction, TransactionType};
        let mempool = tenzro_consensus::mempool::Mempool::new(Arc::new(
            tenzro_consensus::ConsensusConfig::default(),
        ));
        mempool.set_state_reader(Arc::new(AtNonce(0))).unwrap();
        let signer = tenzro_crypto::composite::testing::TestHybridSigner::p256_only(1);
        let tx = |nonce: u64| {
            let tx = Transaction::new(
                tenzro_types::primitives::ChainId::from(1),
                Address::default(),
                Address::default(),
                tenzro_types::primitives::Nonce::from(nonce),
                TransactionType::Transfer { amount: 1 },
                21_000,
                1_000_000_000,
            );
            let sig = signer
                .sign(
                    tenzro_crypto::composite::SignatureContext::Transaction,
                    tx.hash().as_bytes(),
                )
                .unwrap();
            SignedTransaction::new(tx, signer.public_key().p256.clone(), sig)
        };
        let cut = |in_flight: &HashMap<Hash, Instant>, ordered: &HashMap<Hash, u64>| {
            let mut out = Vec::new();
            mempool.select_with(|h, t| {
                if let Some(pick) = already_batched(h, in_flight, ordered) {
                    return pick;
                }
                out.push((*h, t.transaction.nonce.0));
                Pick::Take
            });
            out
        };
        let nonces = |cut: &[(Hash, u64)]| cut.iter().map(|(_, n)| *n).collect::<Vec<_>>();
        let mut in_flight = HashMap::new();
        let mut ordered = HashMap::new();

        for n in 0..2 {
            mempool.add_transaction(tx(n)).unwrap();
        }
        let first = cut(&in_flight, &ordered);
        assert_eq!(nonces(&first), vec![0, 1], "in order, in one part");
        for (h, _) in &first {
            in_flight.insert(*h, Instant::now());
        }
        mempool.add_transaction(tx(2)).unwrap();
        assert_eq!(
            nonces(&cut(&in_flight, &ordered)),
            Vec::<u64>::new(),
            "nonce 2 waits while the part holding 0 and 1 is unordered"
        );

        for (h, _) in &first {
            in_flight.remove(h);
            ordered.insert(*h, 1);
        }
        assert_eq!(nonces(&cut(&in_flight, &ordered)), vec![2]);

        // Handed back unordered instead: everything is cut again, in order.
        ordered.clear();
        assert_eq!(nonces(&cut(&in_flight, &ordered)), vec![0, 1, 2]);
    }

    /// A consensus record goes to the records store and never to the node's
    /// store, so no write to the node's store can hold one up.
    #[test]
    fn consensus_records_are_kept_apart_from_the_node_store() {
        let node: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let records: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let handle = handle_with_stores(node.clone(), records.clone());
        handle.record_boundary(3, 42);
        assert_eq!(
            records.get(CF, &boundary_key(3)).unwrap(),
            Some(42u64.to_be_bytes().to_vec())
        );
        assert_eq!(node.get(CF, &boundary_key(3)).unwrap(), None);
    }

    fn body(
        epoch: u64,
        index: u64,
        first_height: u64,
        last_height: u64,
        ends_epoch: bool,
    ) -> Checkpoint {
        Checkpoint {
            chain_id: 7,
            genesis_hash: [1; 32],
            epoch,
            index,
            prev: [0; 32],
            first_height,
            last_height,
            blocks_root: [0; 32],
            state_height: last_height,
            state_root: [0; 32],
            statement_root: [0; 32],
            next_committee_root: ends_epoch.then_some([9; 32]),
            anchor_round: index,
            timestamp_ms: 0,
            ordering_root: [0; 32],
        }
    }

    fn certified(cp: Checkpoint) -> Certificate {
        Certificate {
            checkpoint: cp,
            signers: Vec::new(),
            sessions: Vec::new(),
            signatures: Vec::new(),
        }
    }

    /// Below the history floor a node keeps only the bodies of checkpoints
    /// that close or hand over an epoch.
    #[test]
    fn checkpoint_bodies_below_the_history_floor_are_pruned_and_epoch_handovers_kept() {
        let records: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let handle = handle_with_stores(
            Arc::new(tenzro_storage::MemoryStore::new()),
            records.clone(),
        );
        let h = handle.time.handover_confirmations;
        handle.record_boundary(0, 39);
        for i in 0..70u64 {
            handle.record_body(&body(u64::from(i > 39 + h), i, i, i, i == 39));
        }
        handle.prune_bodies_below(50);
        let held: Vec<u64> = (0..70)
            .filter(|i| records.get(CF, &body_key(*i)).unwrap().is_some())
            .collect();
        let mut expected = vec![39, 39 + h];
        expected.extend(50..70);
        assert_eq!(held, expected);
    }

    /// Below the history floor a node keeps what a proof from genesis and
    /// archived history need: every checkpoint body and the certificates that
    /// close and hand over each epoch. The compact certificates and the
    /// stride certificates there go, so these records stop growing with the
    /// chain's age; those at and above the floor stay.
    #[test]
    fn certificates_below_the_history_floor_are_pruned_and_epoch_handovers_kept() {
        let records: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let handle = handle_with_stores(
            Arc::new(tenzro_storage::MemoryStore::new()),
            records.clone(),
        );
        let h = handle.time.handover_confirmations;
        // Epoch 0 closes at checkpoint 39 and is handed over at 39 + h.
        handle.record_boundary(0, 39);
        for i in 0..70u64 {
            let epoch = u64::from(i > 39 + h);
            let cp = body(epoch, i, i, i, i == 39);
            handle.record_body(&cp);
            handle.record_certificate(&certified(cp.clone()));
            handle.record_compact(&CompactCertificate {
                checkpoint: cp,
                slots: Vec::new(),
                p256: Vec::new(),
                proof: Vec::new(),
            });
        }
        let held = |prefix: fn(u64) -> Vec<u8>| -> Vec<u64> {
            (0..70)
                .filter(|i| records.get(CF, &prefix(*i)).unwrap().is_some())
                .collect()
        };
        assert_eq!(held(certificate_key), vec![0, 20, 39, 40, 39 + h, 60]);
        assert_eq!(held(compact_key).len(), 70);

        handle.prune_certificates_below(50);

        assert_eq!(held(certificate_key), vec![39, 39 + h, 60]);
        assert_eq!(held(compact_key), (50..70).collect::<Vec<_>>());
        assert_eq!(held(body_key).len(), 70, "every checkpoint body stays");
        assert!(records.get(CF, LATEST_CERTIFICATE_KEY).unwrap().is_some());
        assert!(records.get(CF, LATEST_COMPACT_KEY).unwrap().is_some());
        assert_eq!(handle.boundary(0), Some(39));
    }

    /// Three years of epochs on a non-archival node, with the records of a
    /// 4-member committee at their real sizes: each epoch's session
    /// certificates and validator record, the certificates that close and
    /// hand it over, and its handover in the proof log. A prover delivers a
    /// handover chain proof every ten epochs, and every checkpoint is
    /// archived as it is certified. Once the chain proof covers an epoch,
    /// nothing of it stays, so the consensus records a node keeps are the
    /// same size after the third year as after the first.
    /// Once the records a chain proof covers are pruned, consensus no longer
    /// proves a checkpoint from genesis, and its certification comes from the
    /// proof log: the chain proof, the handovers since and the checkpoint's
    /// own certificate. Event proofs and evidence packs are built from it.
    #[test]
    fn a_checkpoint_past_pruned_records_is_certified_from_the_proof_log() {
        use crate::proof_log::{ChainProof, ProofLog, certification};
        use tenzro_consensus::light_client::{Certification, EpochHandover, HandoverChainJournal};

        let node: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let records: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let handle = handle_with_stores(node, records);
        let h = handle.time.handover_confirmations;
        let dir = tempfile::tempdir().unwrap();
        let log = parking_lot::Mutex::new(ProofLog::open(dir.path()).unwrap());
        let mut boundaries = Vec::new();
        let mut index = 0u64;
        for epoch in 0..30u64 {
            handle.record_boundary(epoch, index);
            boundaries.push(index);
            for i in index..=index + h {
                let cert = certified(body(epoch, i, i, i, i == index));
                handle.record_body(&cert.checkpoint);
                handle.record_certificate(&cert);
                if i == index {
                    log.lock()
                        .append(&EpochHandover {
                            certificate: cert,
                            sessions: Vec::new(),
                            next_members: Vec::new(),
                        })
                        .unwrap();
                }
            }
            index += h + 1;
        }
        let last = index - 1;
        log.lock()
            .install(ChainProof {
                journal: HandoverChainJournal {
                    program: [3; 32],
                    chain_id: 7,
                    genesis_hash: [1; 32],
                    genesis_root: [2; 32],
                    epoch: 20,
                    committee_root: [4; 32],
                },
                members: Vec::new(),
                receipt: vec![9; 64],
            })
            .unwrap();
        handle.prune_certificates_below(boundaries[20]);
        handle.prune_bodies_below(boundaries[20]);
        handle.prune_epoch_records_below(20);

        assert!(
            handle.checkpoint_proof(last).is_none(),
            "the handovers before epoch 20 are gone"
        );
        match certification(&handle, Some(&log), last) {
            Some(Certification::Chained(p)) => {
                assert_eq!(p.chain, vec![9; 64]);
                let epochs: Vec<u64> = p
                    .handovers
                    .iter()
                    .map(|h| h.certificate.checkpoint.epoch)
                    .collect();
                assert_eq!(epochs, (20..29).collect::<Vec<_>>());
                assert_eq!(p.certificate.checkpoint.index, last);
            }
            other => panic!("expected a chained certification, got {other:?}"),
        }
        assert!(
            certification(&handle, None, last).is_none(),
            "no proof log, no certification"
        );
        assert!(
            certification(&handle, Some(&log), boundaries[3]).is_none(),
            "a checkpoint whose certificate is pruned"
        );
    }

    #[test]
    fn consensus_records_stay_flat_over_years_once_a_chain_proof_covers_them() {
        use crate::proof_log::{ChainProof, ProofLog};
        use tenzro_consensus::light_client::{EpochHandover, HandoverChainJournal};
        use tenzro_consensus::{
            CompositeSignature, Member, SessionCertificate, ValidatorPublicKey,
        };

        // Scaled down from 8,760 hour-long epochs a year; the bound does not
        // depend on the count.
        const EPOCHS_PER_YEAR: u64 = 120;
        const PROOF_EVERY: u64 = 10;
        let node: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let records: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let handle = handle_with_stores(node.clone(), records.clone());
        let h = handle.time.handover_confirmations;
        let dir = tempfile::tempdir().unwrap();
        let mut log = ProofLog::open(dir.path()).unwrap();

        let key = ValidatorPublicKey {
            ml_dsa: vec![5; 1952],
            p256: vec![5; 65],
        };
        let signature = CompositeSignature {
            ml_dsa: vec![7; 3309],
            p256: vec![7; 64],
        };
        let members: Vec<Member> = (0..4u8)
            .map(|m| Member {
                address: tenzro_types::primitives::Address([m; 32]),
                public_key: key.clone(),
                stake: 1,
                seats: 1,
            })
            .collect();
        let held = |log: &ProofLog| -> u64 {
            let records: u64 = records
                .scan_prefix(CF, b"consensus/")
                .unwrap()
                .iter()
                .map(|(k, v)| (k.len() + v.len()) as u64)
                .sum();
            let epochs: u64 = node
                .scan_prefix(tenzro_storage::CF_METADATA, b"epoch_validators:")
                .unwrap()
                .iter()
                .map(|(k, v)| (k.len() + v.len()) as u64)
                .sum();
            records + epochs + log.disk_bytes()
        };

        let mut index = 0u64;
        let mut yearly = Vec::new();
        for epoch in 0..3 * EPOCHS_PER_YEAR {
            let sessions: Vec<SessionCertificate> = members
                .iter()
                .map(|m| SessionCertificate {
                    chain_id: 7,
                    genesis_hash: [1; 32],
                    epoch,
                    validator: m.address.0,
                    session_key: key.clone(),
                    signature: signature.clone(),
                })
                .collect();
            for (m, c) in sessions.iter().enumerate() {
                records
                    .put(
                        CF,
                        &session_key(epoch, &[m as u8; 32]),
                        &bincode::serialize(c).unwrap(),
                    )
                    .unwrap();
            }
            node.put(
                tenzro_storage::CF_METADATA,
                &crate::epoch_state_store::epoch_key(epoch),
                &vec![0; 4 * 2100],
            )
            .unwrap();
            handle.record_boundary(epoch, index);
            let mut closing = None;
            for i in index..=index + h {
                let cert = Certificate {
                    checkpoint: body(epoch, i, i, i, i == index),
                    signers: vec![0, 1, 2],
                    sessions: vec![[0; 32], [1; 32], [2; 32]],
                    signatures: vec![signature.clone(); 3],
                };
                handle.record_body(&cert.checkpoint);
                handle.record_certificate(&cert);
                closing.get_or_insert(cert);
            }
            index += h + 1;
            log.append(&EpochHandover {
                certificate: closing.unwrap(),
                sessions,
                next_members: members.clone(),
            })
            .unwrap();
            if (epoch + 1) % PROOF_EVERY == 0 {
                log.install(ChainProof {
                    journal: HandoverChainJournal {
                        program: [3; 32],
                        chain_id: 7,
                        genesis_hash: [1; 32],
                        genesis_root: [2; 32],
                        epoch: epoch + 1,
                        committee_root: [4; 32],
                    },
                    members: members.clone(),
                    receipt: vec![0; 250_000],
                })
                .unwrap();
            }
            // What the maintenance pass prunes, with all history archived.
            handle.prune_certificates_below(index);
            handle.prune_bodies_below(index);
            let floor = log
                .chain_epoch()
                .min(log.count())
                .min((epoch + 1).saturating_sub(crate::storage_maintenance::EPOCH_RECORDS_KEPT));
            handle.prune_epoch_records_below(floor);
            crate::epoch_state_store::prune_epochs_below(&*node, floor);
            if (epoch + 1) % EPOCHS_PER_YEAR == 0 {
                yearly.push(held(&log));
            }
        }
        let (first, third) = (yearly[0], yearly[2]);
        assert!(
            third <= first + first / 100,
            "consensus records grew from {first} bytes after the first year to {third} after the third"
        );
    }

    /// Epoch 0 ends at checkpoint 2 and epoch 1 at the one after epoch 0's
    /// handover, each followed by its handover confirmations; none orders a
    /// block past height 5. A validator whose core is still in epoch 1 holds
    /// epoch 0's handover as its latest certificate, while executing the
    /// blocks derived epoch 2's committee. Its core enters epoch 2 only on
    /// epoch 1's end and the handover after it, so a peer serves it those in
    /// turn rather than its own latest certificate, which the core ignores.
    #[test]
    fn a_peer_whose_core_trails_its_committees_is_served_its_epoch_end() {
        let handle = handle_with_one_validator();
        let h = handle.time.handover_confirmations;
        let mut bodies = vec![
            body(0, 0, 1, 3, false),
            body(0, 1, 4, 5, false),
            body(0, 2, 6, 5, true),
        ];
        for i in 0..h {
            bodies.push(body(0, 3 + i, 6, 5, false));
        }
        let end = 3 + h;
        bodies.push(body(1, end, 6, 5, true));
        for i in 0..h {
            bodies.push(body(1, end + 1 + i, 6, 5, false));
        }
        let handover = end + h;
        for cp in &bodies {
            handle.record_body(cp);
        }
        for i in [0, 2, 2 + h, end, handover] {
            handle.record_certificate(&certified(bodies[i as usize].clone()));
        }

        let (_, cert) = handle.evidence_past_blocks(2, Some(2 + h));
        assert_eq!(
            cert.map(|c| c.checkpoint.index),
            Some(end),
            "the end of the epoch its core is in"
        );
        let (_, cert) = handle.evidence_past_blocks(2, Some(end));
        assert_eq!(
            cert.map(|c| c.checkpoint.index),
            Some(handover),
            "then the handover"
        );
    }

    /// A validator that stood down follows; it starts consensus again at a
    /// handover it imports. One certified longer ago than an epoch lasts is
    /// passed over while its peers report later certificates, but joined
    /// when they report none: a network short of a quorum without this
    /// validator certifies no later handover.
    #[test]
    fn a_follower_joins_at_a_past_handover_its_peers_certified_nothing_past() {
        let handle = handle_with_one_validator();
        let h = handle.time.handover_confirmations;
        handle.record_certificate(&certified(body(0, 2, 6, 5, true)));
        let handover = body(0, 2 + h, 6, 5, false);
        assert_eq!(handover.timestamp_ms, 0, "certified long ago");
        assert!(
            !handle.joins_at(&body(0, 1 + h, 6, 5, false)),
            "not the handover"
        );

        handle.note_network_checkpoint(3 + h);
        assert!(!handle.joins_at(&handover), "the network is past it");

        let stalled = handle_with_one_validator();
        stalled.record_certificate(&certified(body(0, 2, 6, 5, true)));
        stalled.note_network_checkpoint(2 + h);
        assert!(stalled.joins_at(&handover), "the network stands there");

        let recent = Checkpoint {
            timestamp_ms: unix_ms(),
            ..handover.clone()
        };
        assert!(handle.joins_at(&recent), "a current handover");
    }

    /// Epoch 0 orders blocks 1-3 and ends on checkpoints that order none;
    /// epoch 1 orders blocks 4-6. A peer at height 3 that knows only epoch
    /// 0's committee cannot verify epoch 1's certificate, so it is served
    /// epoch 0's end first, and epoch 1's range once it knows epoch 1.
    #[test]
    fn a_peer_at_an_epoch_end_it_has_not_certified_is_served_that_end_first() {
        let handle = handle_with_one_validator();
        let bodies = [
            body(0, 0, 1, 3, false),
            body(0, 1, 4, 3, false),
            body(0, 2, 4, 3, true),
            body(1, 3, 4, 6, false),
        ];
        for cp in &bodies {
            handle.record_body(cp);
        }
        handle.record_certificate(&certified(bodies[2].clone()));
        handle.record_boundary(0, 2);
        handle.record_certificate(&certified(bodies[3].clone()));

        let (served, cert) = handle.evidence_for(4, 6, 0, None);
        assert_eq!(
            cert.map(|c| c.checkpoint.index),
            Some(2),
            "the end of the peer's epoch"
        );
        assert_eq!(
            served.iter().map(|c| c.index).collect::<Vec<_>>(),
            vec![1],
            "the bodies after the peer's tip"
        );

        let (served, cert) = handle.evidence_for(4, 6, 1, None);
        assert_eq!(
            cert.map(|c| c.checkpoint.index),
            Some(3),
            "the range itself, once the peer knows its epoch"
        );
        assert!(served.is_empty());

        // A peer still short of the epoch's last block gets the range up to
        // the epoch's end, as before.
        let (served, cert) = handle.evidence_for(2, 3, 0, None);
        assert_eq!(cert.map(|c| c.checkpoint.index), Some(2));
        assert_eq!(
            served.iter().map(|c| c.index).collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    /// Epoch 0's closing checkpoint (index 2) never certified: this node
    /// holds its body and the handover certificate after it, and no boundary
    /// was ever recorded. A peer that knows only epoch 0 must still be served
    /// that handover, or it can never leave the epoch.
    #[test]
    fn a_peer_is_served_the_handover_of_an_epoch_whose_end_never_certified() {
        let handle = handle_with_one_validator();
        let h = handle.time.handover_confirmations;
        assert!(h > 0);
        let mut bodies = vec![
            body(0, 0, 1, 3, false),
            body(0, 1, 4, 5, false),
            body(0, 2, 6, 5, true),
        ];
        for i in 0..h {
            bodies.push(body(0, 3 + i, 6, 5, false));
        }
        let handover = 2 + h;
        bodies.push(body(1, handover + 1, 6, 8, false));
        for cp in &bodies {
            handle.record_body(cp);
        }
        handle.record_certificate(&certified(bodies[0].clone()));
        handle.record_certificate(&certified(bodies[handover as usize].clone()));
        handle.record_certificate(&certified(bodies[handover as usize + 1].clone()));

        let (_, cert) = handle.evidence_for(6, 8, 0, Some(0));
        assert_eq!(
            cert.map(|c| c.checkpoint.index),
            Some(handover),
            "the handover that moves the peer out of epoch 0"
        );
    }

    /// As above, on a follower: the handover certificate was accepted before
    /// the closing body that authenticates it was recorded.
    #[test]
    fn a_handover_taken_before_its_closing_body_is_still_served() {
        let handle = handle_with_one_validator();
        let h = handle.time.handover_confirmations;
        assert!(h > 0);
        let mut bodies = vec![
            body(0, 0, 1, 3, false),
            body(0, 1, 4, 5, false),
            body(0, 2, 6, 5, true),
        ];
        for i in 0..h {
            bodies.push(body(0, 3 + i, 6, 5, false));
        }
        let handover = 2 + h;
        bodies.push(body(1, handover + 1, 6, 8, false));
        handle.record_body(&bodies[0]);
        handle.record_certificate(&certified(bodies[0].clone()));
        let cert = certified(bodies[handover as usize].clone());
        handle.record_certificate(&cert);
        handle.record_certificate(&certified(bodies[handover as usize + 1].clone()));
        for cp in &bodies {
            handle.record_body(cp);
        }
        handle.keep_handover(&cert);

        let (_, served) = handle.evidence_for(6, 8, 0, Some(0));
        assert_eq!(served.map(|c| c.checkpoint.index), Some(handover));
    }

    /// Epoch 0 orders blocks 1-5; checkpoint 2 ends it and the handover
    /// confirmations after it order no block; epoch 1 orders blocks 6-8.
    /// A validator cut off while the epoch ended learned of its last
    /// checkpoint's certificate but not of the handover certificate, and its
    /// peers have gone on to epoch 1. Its core enters the next epoch only on
    /// that handover certificate, so a peer serves it the handover rather
    /// than the end it already holds; a peer that has not got the end yet is
    /// served the end first, as before.
    #[test]
    fn a_peer_holding_its_epoch_end_is_served_the_handover() {
        let handle = handle_with_one_validator();
        let h = handle.time.handover_confirmations;
        assert!(h > 0);
        let mut bodies = vec![
            body(0, 0, 1, 3, false),
            body(0, 1, 4, 5, false),
            body(0, 2, 6, 5, true),
        ];
        for i in 0..h {
            bodies.push(body(0, 3 + i, 6, 5, false));
        }
        let handover = 2 + h;
        bodies.push(body(1, handover + 1, 6, 8, false));
        for cp in &bodies {
            handle.record_body(cp);
        }
        handle.record_certificate(&certified(bodies[0].clone()));
        handle.record_certificate(&certified(bodies[2].clone()));
        handle.record_boundary(0, 2);
        handle.record_certificate(&certified(bodies[handover as usize].clone()));
        handle.record_certificate(&certified(bodies[handover as usize + 1].clone()));
        let indices = |served: &[Checkpoint]| served.iter().map(|c| c.index).collect::<Vec<_>>();

        // Short of the epoch's last blocks, holding its end.
        let (served, cert) = handle.evidence_for(4, 8, 0, Some(2));
        assert_eq!(
            cert.map(|c| c.checkpoint.index),
            Some(handover),
            "the handover"
        );
        assert_eq!(indices(&served), (1..handover).collect::<Vec<_>>());

        // With every block of the epoch, holding its end.
        let (served, cert) = handle.evidence_for(6, 8, 0, Some(2));
        assert_eq!(cert.map(|c| c.checkpoint.index), Some(handover));
        assert_eq!(indices(&served), (2..handover).collect::<Vec<_>>());

        // No block past the peer's, holding its end.
        let (_, cert) = handle.evidence_past_blocks(0, Some(2));
        assert_eq!(cert.map(|c| c.checkpoint.index), Some(handover));

        // Not holding the end yet: the end first.
        let (served, cert) = handle.evidence_for(4, 8, 0, Some(0));
        assert_eq!(cert.map(|c| c.checkpoint.index), Some(2));
        assert_eq!(indices(&served), vec![1]);
        let (_, cert) = handle.evidence_past_blocks(0, Some(1));
        assert_eq!(cert.map(|c| c.checkpoint.index), Some(2));
    }

    /// A validator that derived the next committee when its epoch closed and
    /// then fell behind derives the same committee again as a follower,
    /// without moving the epoch manager a second time.
    #[test]
    fn the_next_committee_is_derived_once_per_epoch() {
        let handle = handle_with_one_validator();
        handle.executed.store(3, Ordering::Release);
        let first = handle.derive_next_committee(0, 3, None).expect("derives");
        assert_eq!(handle.epoch_manager.current_epoch().number, 1);
        let again = handle
            .derive_next_committee(0, 3, None)
            .expect("derives again");
        assert_eq!(
            handle.epoch_manager.current_epoch().number,
            1,
            "the epoch manager moved once"
        );
        assert_eq!(first.root(), again.root());
        assert_eq!(first.epoch, 1);
    }

    /// A committee is derived only from the state at the epoch's last block:
    /// a node that executed past it, or not up to it, refuses and the epoch
    /// manager stays where it was.
    #[test]
    fn the_next_committee_is_not_derived_from_other_state_than_the_closing_block() {
        let handle = handle_with_one_validator();
        handle.executed.store(5, Ordering::Release);
        assert!(
            handle.derive_next_committee(0, 3, None).is_err(),
            "ahead of the closing block"
        );
        handle.executed.store(2, Ordering::Release);
        assert!(
            handle.derive_next_committee(0, 3, None).is_err(),
            "behind it"
        );
        assert_eq!(
            handle.epoch_manager.current_epoch().number,
            0,
            "nothing moved"
        );
        handle.executed.store(3, Ordering::Release);
        assert!(handle.derive_next_committee(0, 3, None).is_ok());
        assert_eq!(handle.epoch_manager.current_epoch().number, 1);
    }

    /// The high-water mark of a validator that never signed before.
    struct NoVotes;

    impl tenzro_consensus::VoteHighWater for NoVotes {
        fn record(
            &self,
            _epoch: u64,
            _index: u64,
            _digest: &[u8; 32],
            _prev: &[u8; 32],
        ) -> tenzro_consensus::Result<()> {
            Ok(())
        }
    }

    /// Four validators, and the handle of the fourth while its core runs
    /// epoch 0, last committed at round 10. The receiver sees what the
    /// handle tells the core.
    struct Committee4 {
        keys: Vec<tenzro_consensus::session::SessionKey>,
        handle: Arc<ConsensusHandle>,
        inputs: mpsc::UnboundedReceiver<Input>,
    }

    impl Committee4 {
        fn new() -> Self {
            let keys: Vec<_> = (0..4)
                .map(|_| tenzro_consensus::session::SessionKey::generate().expect("key"))
                .collect();
            let validators = keys
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    tenzro_consensus::validator::ValidatorInfo::new(
                        Address::new([i as u8 + 1; 32]),
                        k.public_key().clone(),
                        [i as u8 + 1; 32],
                        1 << 80,
                    )
                })
                .collect();
            let em = Arc::new(EpochManager::new(validators, 100).expect("epoch manager"));
            let handle = ConsensusHandle::new(
                tenzro_consensus::ConsensusConfig::default(),
                TimeRules::default(),
                7,
                [1; 32],
                em,
                Some(Arc::new(tenzro_storage::MemoryStore::new())),
                Some(Arc::new(tenzro_storage::MemoryStore::new())),
            )
            .expect("consensus handle");
            let me = handle
                .committee(0)
                .expect("the genesis committee")
                .members()
                .iter()
                .position(|m| &m.public_key == keys[3].public_key())
                .expect("seated");
            let (tx, inputs) = mpsc::unbounded_channel();
            *handle.inputs.write() = Some(tx);
            *handle.me.write() = Some(me as ValidatorIndex);
            handle.running_epoch.store(0, Ordering::Release);
            handle.committed_round.store(10, Ordering::Release);
            Self {
                keys,
                handle,
                inputs,
            }
        }

        /// A certificate of `epoch` checkpoint `index` anchored at `round`,
        /// signed by the first three validators (a quorum of four), with
        /// their session certificates admitted.
        fn certify(&self, epoch: u64, index: u64, round: u64) -> Certificate {
            self.certify_body(epoch, index, round, false)
        }

        /// As `certify`, for the checkpoint ending `epoch`.
        fn certify_closing(&self, epoch: u64, index: u64, round: u64) -> Certificate {
            self.certify_body(epoch, index, round, true)
        }

        fn certify_body(&self, epoch: u64, index: u64, round: u64, closing: bool) -> Certificate {
            use tenzro_consensus::checkpoint::{VoteCollector, VoteOutcome};
            let committee = self.handle.committee(epoch).expect("the epoch's committee");
            // A checkpoint ordering no block: its state height is its last height.
            let mut cp = body(epoch, index, index + 1, index, closing);
            cp.anchor_round = round;
            let mut votes = VoteCollector::new();
            let mut sessions = Vec::new();
            for hardware in &self.keys[..3] {
                let me = committee
                    .members()
                    .iter()
                    .position(|m| &m.public_key == hardware.public_key())
                    .expect("seated") as ValidatorIndex;
                let session = tenzro_consensus::session::SessionKey::generate().expect("key");
                let sc = tenzro_consensus::session::sign_certificate(
                    hardware,
                    7,
                    [1; 32],
                    epoch,
                    session.public_key().clone(),
                )
                .expect("session certificate");
                let vote = tenzro_consensus::sign_checkpoint(&session, &sc, &NoVotes, me, &cp)
                    .expect("vote");
                sessions.push(sc);
                if let VoteOutcome::Certified(c) = votes.add(&committee, vote) {
                    self.handle.admit_sessions(epoch, sessions);
                    self.handle
                        .verify_certificate(&c)
                        .expect("the quorum's certificate verifies");
                    return *c;
                }
            }
            panic!("three of four votes are a quorum");
        }

        fn stood_down(&mut self) -> bool {
            let mut down = false;
            while let Ok(i) = self.inputs.try_recv() {
                down |= matches!(i, Input::StandDown);
            }
            down && !self.handle.is_validator()
        }

        /// The indices of the certificates the core was told to adopt, in
        /// order.
        fn adopted(&mut self) -> Vec<u64> {
            let mut told = Vec::new();
            while let Ok(i) = self.inputs.try_recv() {
                if let Input::Certificate { cert, .. } = i {
                    told.push(cert.checkpoint.index);
                }
            }
            told
        }

        /// The index of the last certificate handed to the core, if any.
        fn handed_to_core(&mut self) -> Option<u64> {
            let mut to = None;
            while let Ok(i) = self.inputs.try_recv() {
                if let Input::Certificate { cert, .. } = i {
                    to = Some(cert.checkpoint.index);
                }
            }
            to
        }

        /// The index of the checkpoint the core was told to fast-forward
        /// to, if any.
        fn fast_forwarded(&mut self) -> Option<u64> {
            let mut to = None;
            while let Ok(i) = self.inputs.try_recv() {
                if let Input::FastForward { cert, .. } = i {
                    to = Some(cert.checkpoint.index);
                }
            }
            to
        }
    }

    /// A validator that was stopped while the network went on: a
    /// certificate of its own epoch anchored further past its reach than
    /// the DAG keeps means its peers no longer hold the rounds it would have
    /// to order, so its core fast-forwards to that checkpoint and the node
    /// imports the blocks up to it, still a validator of the epoch. One
    /// within reach leaves it validating as it was.
    #[test]
    fn a_validator_left_past_the_dag_it_can_still_order_fast_forwards() {
        let mut net = Committee4::new();
        let gc = tenzro_consensus::ConsensusConfig::default().gc_depth;
        let near = net.certify(0, 1, 10 + gc);
        assert!(!net.handle.on_network_certificate(&near));
        assert_eq!(
            net.fast_forwarded(),
            None,
            "a certificate within reach keeps it validating"
        );
        assert_eq!(net.handle.fast_forward_target(), None);

        let far = net.certify(0, 2, 11 + gc);
        assert!(net.handle.on_network_certificate(&far));
        assert_eq!(net.fast_forwarded(), Some(2));
        assert_eq!(
            net.handle.fast_forward_target(),
            Some(far.checkpoint.last_height.max(1)),
            "the node imports the blocks up to it"
        );
        assert!(
            net.handle.is_validator(),
            "it stays a validator of its epoch"
        );
    }

    /// A core whose reach has stood still for a minute while a certificate it
    /// verifies shows the network a few rounds ahead is fast-forwarded, even
    /// though the certificate is within the DAG's reach; before the minute is
    /// up, or with the network only just ahead, it keeps validating.
    #[test]
    fn a_core_that_stands_still_while_the_network_moves_on_fast_forwards() {
        let mut net = Committee4::new();
        let ahead = net.certify(0, 1, 10 + STUCK_MIN_LAG_ROUNDS + 2);
        assert!(!net.handle.on_network_certificate(&ahead));
        assert_eq!(net.fast_forwarded(), None, "not stuck yet");

        net.handle
            .last_reach_change_ms
            .store(unix_ms() - STUCK_BEHIND_MS - 1_000, Ordering::Release);
        let just = net.certify(0, 2, 10 + STUCK_MIN_LAG_ROUNDS);
        assert!(!net.handle.on_network_certificate(&just));
        assert_eq!(net.fast_forwarded(), None, "the network is only just ahead");

        let past = net.certify(0, 3, 10 + STUCK_MIN_LAG_ROUNDS + 2);
        assert!(net.handle.on_network_certificate(&past));
        assert_eq!(net.fast_forwarded(), Some(3));
        assert!(
            net.handle.is_validator(),
            "it stays a validator of its epoch"
        );
    }

    /// A certificate shows what the network executed, not what this node
    /// did: the node's executed height moves only with the blocks it builds
    /// or imports, so a core fast-forwarded on it never counts a block the
    /// node has yet to build as executed.
    #[test]
    fn a_certificate_does_not_count_as_executed() {
        let net = Committee4::new();
        net.handle
            .on_executed(3, Hash::new([3; 32]), Hash::new([4; 32]));
        let cert = net.certify(0, 40, 10);
        net.handle.record_certificate(&cert);
        assert_eq!(net.handle.ordered_height(), 40);
        assert_eq!(net.handle.executed_height(), 3);
        net.handle
            .on_executed(4, Hash::new([5; 32]), Hash::new([6; 32]));
        assert_eq!(net.handle.executed_height(), 4);
    }

    /// A validator that took its previous epoch's handover before executing
    /// that epoch's last blocks follows meanwhile: the certificates closing
    /// and handing over the epoch it then enters reach it as a follower,
    /// before its core for that epoch runs. Block sync serves it the closing
    /// certificate; its core takes the handover the node holds with it,
    /// rather than wait for it while the network has moved on.
    #[test]
    fn a_core_behind_its_epochs_handover_takes_the_one_the_node_holds() {
        let mut net = Committee4::new();
        let conf = TimeRules::default().handover_confirmations;
        let closing = net.certify_closing(0, 5, 11);
        let handover = net.certify(0, 5 + conf, 12);
        // Accepted while following: the core is not told.
        assert!(net.handle.accept_certificate(&closing).expect("verifies"));
        assert!(net.handle.accept_certificate(&handover).expect("verifies"));

        assert!(!net.handle.on_network_certificate(&closing));
        assert_eq!(
            net.adopted(),
            vec![5, 5 + conf],
            "the closing certificate block sync served, then the handover held"
        );
    }

    /// The same validator served the handover, with the closing certificate
    /// accepted while it followed and the epoch's end never recorded: the
    /// closing body it holds marks the handover, and its core adopts the
    /// closing certificate before it.
    #[test]
    fn a_served_handover_counts_from_the_closing_certificate_held() {
        let mut net = Committee4::new();
        let conf = TimeRules::default().handover_confirmations;
        let closing = net.certify_closing(0, 5, 11);
        let handover = net.certify(0, 5 + conf, 12);
        assert!(net.handle.accept_certificate(&closing).expect("verifies"));

        assert!(!net.handle.on_network_certificate(&handover));
        assert_eq!(net.adopted(), vec![5, 5 + conf]);
        assert_eq!(
            net.handle.boundary(0),
            Some(5),
            "the epoch's end is recorded"
        );
    }

    /// A certificate that does not verify moves nothing, however far ahead
    /// it claims the network is.
    #[test]
    fn an_unverified_certificate_never_stands_a_validator_down() {
        let mut net = Committee4::new();
        let mut forged = net.certify(0, 1, 5);
        forged.checkpoint.anchor_round = 10_000;
        assert!(!net.handle.on_network_certificate(&forged));
        forged.checkpoint.epoch = 3;
        assert!(!net.handle.on_network_certificate(&forged));
        assert!(!net.stood_down());
        assert!(net.handle.is_validator());
    }

    /// A certificate of an epoch the node has left still verifies, and its
    /// compact form can still be proven: the session certificates it names
    /// are read back from disk once the in-memory books moved on.
    #[test]
    fn a_certificate_of_an_epoch_left_behind_still_verifies() {
        let net = Committee4::new();
        let old = net.certify(0, 1, 5);
        let members = net
            .handle
            .committee(0)
            .expect("committee")
            .members()
            .to_vec();
        for e in 1..=3 {
            net.handle
                .add_committee(Committee::from_members(e, members.clone()).expect("committee"));
            net.handle.admit_sessions(e, Vec::new());
        }
        assert!(
            !net.handle.sessions.read().contains_key(&0),
            "epoch 0's book left memory"
        );
        net.handle
            .verify_certificate(&old)
            .expect("verifies from the session certificates on disk");
    }

    /// A verified certificate of a later epoch stands the validator down; one
    /// of an epoch whose committee it has not derived cannot be verified and
    /// is ignored (block sync brings the node there).
    #[test]
    fn a_verified_later_epoch_stands_a_validator_down() {
        let mut net = Committee4::new();
        let members = net
            .handle
            .committee(0)
            .expect("committee")
            .members()
            .to_vec();
        net.handle
            .add_committee(Committee::from_members(1, members).expect("committee"));
        let later = net.certify(1, 30, 3);
        assert!(net.handle.on_network_certificate(&later));
        assert!(net.stood_down());
    }

    /// Standing down wakes block sync at once: the node is behind, and a
    /// sync that waited for its next probe would let a network with short
    /// epochs close the next one before the node reached it.
    #[test]
    fn standing_down_wakes_block_sync_at_once() {
        let mut net = Committee4::new();
        let members = net
            .handle
            .committee(0)
            .expect("committee")
            .members()
            .to_vec();
        net.handle
            .add_committee(Committee::from_members(1, members).expect("committee"));
        let mut behind = net.handle.subscribe_behind_hint();
        behind.borrow_and_update();
        let later = net.certify(1, 30, 3);
        assert!(net.handle.on_network_certificate(&later));
        assert!(net.stood_down());
        assert!(
            behind.has_changed().expect("the hint channel is open"),
            "block sync was not woken by the stand-down"
        );
    }

    /// A validator whose own core certified its epoch's last checkpoint, and
    /// which was then cut off before the handover certificate reached it by
    /// gossip. Block sync serves it the handover; its core enters the next
    /// epoch only on that certificate, so the node hands it to the core.
    #[test]
    fn a_handover_served_after_the_core_certified_the_epoch_end_reaches_the_core() {
        let mut net = Committee4::new();
        let h = net.handle.time.handover_confirmations;
        let end = net.certify_body(0, 2, 5, true);
        // What the engine does with a certificate its own core formed.
        net.handle.record_certificate(&end);
        assert_eq!(net.handed_to_core(), None);

        let handover = net.certify(0, 2 + h, 6);
        assert!(
            !net.handle.on_network_certificate(&handover),
            "the validator keeps validating"
        );
        assert_eq!(
            net.handed_to_core(),
            Some(2 + h),
            "the core is handed the handover"
        );
        assert!(net.handle.is_validator());
    }

    /// A validator whose core is still in its epoch while block sync serves
    /// that epoch's end, or a checkpoint after it, covering blocks past its
    /// tip: the network closed the epoch without it, so it stands down and
    /// imports them. Holding those blocks, it keeps validating and its core
    /// is handed the certificate.
    #[test]
    fn a_validator_served_its_closed_epoch_past_its_tip_follows() {
        let mut net = Committee4::new();
        let end = net.certify_body(0, 2, 5, true);
        assert!(!net.handle.on_served_certificate(&end, 2));
        assert!(net.handle.is_validator(), "it holds the blocks");
        assert_eq!(net.handed_to_core(), Some(2));
        assert!(net.handle.on_served_certificate(&end, 1));
        assert!(!net.handle.is_validator(), "it follows");

        let net = Committee4::new();
        let h = net.handle.time.handover_confirmations;
        net.handle.record_boundary(0, 2);
        let handover = net.certify(0, 2 + h, 6);
        assert!(net.handle.on_served_certificate(&handover, 2));
        assert!(!net.handle.is_validator());

        let mut net = Committee4::new();
        let open = net.certify(0, 1, 30);
        assert!(!net.handle.on_served_certificate(&open, 0));
        assert!(net.handle.is_validator(), "its epoch is open");
        assert_eq!(net.handed_to_core(), None);
    }

    /// A validator whose core runs but cannot reach a quorum, served a
    /// verified certificate of its running epoch for blocks past its tip,
    /// within the DAG's reach and not closing the epoch: no other trigger
    /// fires. Once its tip has stood still for [`TIP_STALL_MS`] it stands
    /// down and imports them; before that, or with its tip moving, it
    /// leaves its core alone.
    #[test]
    fn a_validator_whose_tip_stalls_while_certificates_run_ahead_follows() {
        let mut net = Committee4::new();
        let ahead = net.certify(0, 10, 12);
        // First sighting of the tip: the clock starts, the core is left alone.
        assert!(!net.handle.on_served_certificate(&ahead, 3));
        assert!(net.handle.is_validator());
        assert!(!net.stood_down());

        // A tip that moves restarts the clock, however old it was.
        net.handle
            .tip_seen_ms
            .store(unix_ms() - TIP_STALL_MS - 1_000, Ordering::Release);
        assert!(!net.handle.on_served_certificate(&ahead, 4));
        assert!(net.handle.is_validator(), "the tip moved");

        // A certificate covering nothing past the tip changes nothing.
        net.handle
            .tip_seen_ms
            .store(unix_ms() - TIP_STALL_MS - 1_000, Ordering::Release);
        let behind = net.certify(0, 2, 12);
        assert!(!net.handle.on_served_certificate(&behind, 4));
        assert!(net.handle.is_validator(), "nothing past the tip");

        // The tip stood still past the window while the network is ahead.
        assert!(net.handle.on_served_certificate(&ahead, 4));
        assert!(!net.handle.is_validator(), "it follows");
        assert!(net.stood_down());
    }

    /// The handover is served to a peer short of its epoch's last blocks
    /// only with every body between the end and it: without one, the peer
    /// could not authenticate the end's blocks, and is served the end.
    #[test]
    fn a_handover_whose_bodies_this_node_lacks_is_not_served() {
        let handle = handle_with_one_validator();
        let h = handle.time.handover_confirmations;
        assert!(h > 0);
        let mut bodies = vec![
            body(0, 0, 1, 3, false),
            body(0, 1, 4, 5, false),
            body(0, 2, 6, 5, true),
        ];
        for i in 0..h {
            bodies.push(body(0, 3 + i, 6, 5, false));
        }
        let handover = 2 + h;
        bodies.push(body(1, handover + 1, 6, 8, false));
        for cp in bodies.iter().filter(|c| c.index != 3) {
            handle.record_body(cp);
        }
        handle.record_certificate(&certified(bodies[0].clone()));
        handle.record_certificate(&certified(bodies[2].clone()));
        handle.record_boundary(0, 2);
        handle.record_certificate(&certified(bodies[handover as usize].clone()));
        handle.record_certificate(&certified(bodies[handover as usize + 1].clone()));

        let (served, cert) = handle.evidence_for(4, 8, 0, Some(2));
        assert_eq!(cert.map(|c| c.checkpoint.index), Some(2), "the end");
        assert_eq!(served.iter().map(|c| c.index).collect::<Vec<_>>(), vec![1]);
    }

    /// A full node stopped and started again verifies what it verified
    /// before: a block it resumes at may carry a certificate of an epoch
    /// further back than the one before its latest (epochs that ordered no
    /// block end without one), and the node holds that epoch's committee
    /// from the epochs its epoch manager kept, not only the latest two.
    /// However many epochs have passed and however many old committees are
    /// asked for (light-client proofs walk every epoch), the node keeps a
    /// bounded number in memory, and every one asked for is still right.
    #[test]
    fn the_committees_kept_in_memory_stay_bounded() {
        let dir = tempfile::tempdir().expect("temp dir");
        let key = tenzro_consensus::ValidatorPublicKey::new(
            tenzro_crypto::pq::MlDsaSigningKey::generate()
                .verifying_key_bytes()
                .to_vec(),
            tenzro_crypto::P256KeyPair::generate()
                .public_key_sec1()
                .to_vec(),
        )
        .expect("well-formed key");
        let validators = vec![tenzro_consensus::validator::ValidatorInfo::new(
            Address::new([1; 32]),
            key,
            [1; 32],
            1 << 80,
        )];
        let db = Arc::new(
            tenzro_storage::RocksDbStore::open(&tenzro_storage::StorageConfig::new(
                dir.path().to_path_buf(),
            ))
            .expect("store"),
        );
        let em = Arc::new(
            EpochManager::with_store(
                validators,
                100,
                Arc::new(crate::epoch_state_store::RocksDbEpochStateStore::new(
                    db.clone(),
                )),
            )
            .expect("epoch manager"),
        );
        let kv: Arc<dyn KvStore> = db;
        let handle = ConsensusHandle::new(
            tenzro_consensus::ConsensusConfig::default(),
            TimeRules::default(),
            7,
            [1; 32],
            em,
            Some(kv.clone()),
            Some(kv),
        )
        .expect("consensus handle");
        let mut derived = Vec::new();
        for closing in 0..40u64 {
            handle.executed.store(10 * (closing + 1), Ordering::Release);
            let next = handle
                .derive_next_committee(closing, 10 * (closing + 1), None)
                .expect("the next committee");
            handle.add_committee(next.clone());
            derived.push(next);
        }
        for next in &derived {
            assert_eq!(
                handle.committee(next.epoch).map(|c| c.root()),
                Some(next.root()),
                "the committee of epoch {}",
                next.epoch
            );
        }
        assert_eq!(handle.known_epoch(), 40);
        assert!(
            handle.committees.read().len() as u64 <= COMMITTEES_KEPT,
            "{} committees kept",
            handle.committees.read().len()
        );
    }

    #[test]
    fn a_restarted_node_knows_the_committees_of_the_epochs_it_kept() {
        let dir = tempfile::tempdir().expect("temp dir");
        let key = tenzro_consensus::ValidatorPublicKey::new(
            tenzro_crypto::pq::MlDsaSigningKey::generate()
                .verifying_key_bytes()
                .to_vec(),
            tenzro_crypto::P256KeyPair::generate()
                .public_key_sec1()
                .to_vec(),
        )
        .expect("well-formed key");
        let validators = vec![tenzro_consensus::validator::ValidatorInfo::new(
            Address::new([1; 32]),
            key,
            [1; 32],
            1 << 80,
        )];
        let open = || {
            let config = tenzro_storage::StorageConfig::new(dir.path().to_path_buf());
            let db = Arc::new(tenzro_storage::RocksDbStore::open(&config).expect("store"));
            let em = Arc::new(
                EpochManager::with_store(
                    validators.clone(),
                    100,
                    Arc::new(crate::epoch_state_store::RocksDbEpochStateStore::new(
                        db.clone(),
                    )),
                )
                .expect("epoch manager"),
            );
            let kv: Arc<dyn KvStore> = db;
            ConsensusHandle::new(
                tenzro_consensus::ConsensusConfig::default(),
                TimeRules::default(),
                7,
                [1; 32],
                em,
                Some(kv.clone()),
                Some(kv),
            )
            .expect("consensus handle")
        };

        let handle = open();
        // Three epochs end, the last two having ordered no block.
        let mut derived = Vec::new();
        for closing in 0..3u64 {
            handle.executed.store(10 * (closing + 1), Ordering::Release);
            let next = handle
                .derive_next_committee(closing, 10 * (closing + 1), None)
                .expect("the next committee");
            handle.add_committee(next.clone());
            derived.push(next);
        }
        assert_eq!(handle.known_epoch(), 3);
        drop(handle);

        let restarted = open();
        assert_eq!(restarted.known_epoch(), 3);
        for next in &derived {
            assert_eq!(
                restarted.committee(next.epoch).map(|c| c.root()),
                Some(next.root()),
                "the committee of epoch {} after a restart",
                next.epoch
            );
        }
    }

    /// The epoch's end reaches the driver while the closing block is being
    /// executed: the state root is in the trie but the executed height is still
    /// to be raised. The committee is derived when the height is raised, not
    /// lost.
    #[test]
    fn a_committee_is_derived_when_the_closing_block_is_reported_after_the_epoch_end() {
        let handle = handle_with_one_validator();
        handle.executed.store(4, Ordering::Release);
        handle.epoch_ends(5);
        assert_eq!(
            handle.epoch_manager.current_epoch().number,
            0,
            "waits for the block"
        );
        assert_eq!(*handle.closing.lock(), Some(5));
        handle.on_executed(5, Hash::zero(), Hash::zero());
        assert_eq!(
            handle.epoch_manager.current_epoch().number,
            1,
            "derived once it is executed"
        );
    }

    #[derive(Default)]
    struct CountingPlanner {
        staged: std::sync::atomic::AtomicUsize,
        unstaged: std::sync::atomic::AtomicUsize,
        fail_first: std::sync::atomic::AtomicBool,
        /// Fails this many stagings from the first.
        fail_times: std::sync::atomic::AtomicUsize,
    }

    impl EpochPlanner for CountingPlanner {
        fn stage_next_epoch(&self) -> std::result::Result<String, String> {
            let n = self.staged.fetch_add(1, Ordering::SeqCst);
            if (self.fail_first.load(Ordering::SeqCst) && n == 0)
                || n < self.fail_times.load(Ordering::SeqCst)
            {
                return Err("the staging failed".to_string());
            }
            Ok(format!("boundary:{n}"))
        }
        fn unstage_next_epoch(&self, _token: &str) {
            self.unstaged.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A derivation that fails after staging undoes the staging, and the retry
    /// stages from the start again.
    #[test]
    fn a_failed_derivation_undoes_its_staging_and_the_retry_stages_again() {
        let handle = handle_with_one_validator();
        let planner = Arc::new(CountingPlanner::default());
        handle.set_epoch_planner(planner.clone());
        handle.executed.store(3, Ordering::Release);
        assert!(handle.derive_next_committee(0, 3, Some([9; 32])).is_err());
        assert_eq!(planner.staged.load(Ordering::SeqCst), 1);
        assert_eq!(planner.unstaged.load(Ordering::SeqCst), 1);
        assert_eq!(handle.epoch_manager.current_epoch().number, 0);
        assert!(handle.derive_next_committee(0, 3, None).is_ok());
        assert_eq!(planner.staged.load(Ordering::SeqCst), 2);
        assert_eq!(
            planner.unstaged.load(Ordering::SeqCst),
            1,
            "a derivation that held is kept"
        );
    }

    /// Two callers at one boundary derive the committee one after the other:
    /// the registry is staged once and both get the same committee.
    #[test]
    fn two_concurrent_derivations_at_one_boundary_stage_once() {
        let handle = handle_with_one_validator();
        let planner = Arc::new(CountingPlanner::default());
        handle.set_epoch_planner(planner.clone());
        handle.executed.store(3, Ordering::Release);
        let roots: Vec<[u8; 32]> = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..4)
                .map(|_| scope.spawn(|| handle.derive_next_committee(0, 3, None).unwrap().root()))
                .collect();
            threads.into_iter().map(|t| t.join().unwrap()).collect()
        });
        assert!(roots.windows(2).all(|w| w[0] == w[1]));
        assert_eq!(planner.staged.load(Ordering::SeqCst), 1, "staged once");
        assert_eq!(handle.epoch_manager.current_epoch().number, 1);
    }

    /// A derivation that fails at the closing height is tried again, and
    /// succeeds, without waiting for a restart.
    #[test]
    fn a_derivation_that_fails_once_is_retried() {
        let handle = handle_with_one_validator();
        let planner = Arc::new(CountingPlanner::default());
        planner.fail_first.store(true, Ordering::SeqCst);
        handle.set_epoch_planner(planner.clone());
        handle.executed.store(3, Ordering::Release);
        handle.epoch_ends(3);
        assert_eq!(
            handle.epoch_manager.current_epoch().number,
            0,
            "the first try failed"
        );
        assert_eq!(*handle.closing.lock(), Some(3), "the end is still pending");
        // The wait after the failure is not over: nothing is tried.
        assert!(!handle.close_retry_due());
        handle.retry_close();
        assert_eq!(handle.epoch_manager.current_epoch().number, 0, "backed off");
        handle.close_retry.lock().next = Instant::now();
        assert!(handle.close_retry_due());
        handle.retry_close();
        assert_eq!(
            handle.epoch_manager.current_epoch().number,
            1,
            "the retry derived it"
        );
        assert_eq!(*handle.closing.lock(), None);
    }

    /// A node that executed past the end of an epoch without deriving the next
    /// committee cannot derive it from the state it holds: it is refused and
    /// the end is not tried again.
    #[test]
    fn a_node_that_executed_past_an_epoch_end_without_deriving_it_is_refused() {
        let handle = handle_with_one_validator();
        handle.executed.store(7, Ordering::Release);
        assert!(handle.derive_next_committee(0, 3, None).is_err());
        handle.epoch_ends(3);
        assert_eq!(handle.epoch_manager.current_epoch().number, 0);
        assert_eq!(
            *handle.closing.lock(),
            None,
            "no retry that could never succeed"
        );
    }

    /// With no block coming, a derivation that fails twice is tried again by
    /// the timer, after a wait that doubles, and succeeds.
    #[test]
    fn a_derivation_that_fails_twice_is_retried_by_the_timer_with_backoff() {
        let handle = handle_with_one_validator();
        let planner = Arc::new(CountingPlanner::default());
        planner.fail_times.store(2, Ordering::SeqCst);
        handle.set_epoch_planner(planner.clone());
        handle.executed.store(3, Ordering::Release);
        handle.epoch_ends(3);
        assert_eq!(handle.close_retry.lock().step, CLOSE_RETRY_FIRST);
        // What the engine does on a tick, once the wait is over.
        handle.close_retry.lock().next = Instant::now();
        assert!(handle.close_retry_due());
        handle.retry_close();
        assert_eq!(
            handle.close_retry.lock().step,
            CLOSE_RETRY_FIRST * 2,
            "the wait doubled"
        );
        assert_eq!(handle.epoch_manager.current_epoch().number, 0);
        handle.close_retry.lock().next = Instant::now();
        handle.retry_close();
        assert_eq!(
            handle.epoch_manager.current_epoch().number,
            1,
            "the third try held"
        );
        assert!(
            handle.close_retry.lock().step.is_zero(),
            "the wait is reset"
        );
        assert!(!handle.close_retry_due());
    }
}
