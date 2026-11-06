//! The consensus state machine of one validator in one epoch.
//!
//! [`Core`] performs no I/O and reads no clock: every input carries the
//! current time, and every output is returned to the caller, which sends
//! frames, signs checkpoints with the hardware key, executes ordered
//! segments and reports the results back. The same code therefore runs in
//! the node and in the network emulator its latency is measured with.
//!
//! # Rounds
//!
//! A validator in round `r` has broadcast its round-`r` vertex. Every round
//! has [`CoreConfig::leader_slots`] leader slots, each held by a distinct
//! member. A validator enters `r + 1` as soon as its DAG holds round-`r`
//! vertices carrying a quorum of seats and every round-`r` leader vertex;
//! while a leader vertex is missing it waits for it at most
//! [`CoreConfig::leader_timeout_ms`] from entering `r`, then enters on the
//! quorum alone. Its round-`(r+1)` vertex references every round-`r` vertex
//! it holds.
//!
//! # Commit rule
//!
//! Slots are decided in order, by round then slot, each committed or
//! skipped. A slot of round `r` is decided directly from round `r + 1`:
//!
//! - committed once round-`(r+1)` vertices from a quorum of seats strongly
//!   reference its vertex, counting each author's delivered vertex or,
//!   before that, its first proposal. Of that quorum at least `f + 1` seats
//!   are honest and their vertices are delivered as proposed, so every
//!   vertex of round `r + 2` or later, which reaches a quorum of round
//!   `r + 1` through strong references, reaches the slot's vertex;
//! - skipped once the delivered round-`(r+1)` vertices of every seat do not
//!   reference it, so no vertex ever reaches it.
//!
//! Otherwise the slot is decided by its anchor, the first slot of round
//! `r + 2` or later that is not skipped: a committed anchor commits the slot
//! exactly when the anchor's vertex reaches the slot's through strong
//! references, and an undecided anchor leaves the slot undecided. By the two
//! reachability facts above, an indirect decision never contradicts a direct
//! one, and validators that decide the same later slots pick the same
//! anchor, so every validator decides every slot alike. Each committed slot
//! orders its vertex's causal history not yet ordered, by round then author,
//! into one segment.
//!
//! The leader schedule changes only at checkpoints and only as a function of
//! the committed prefix, so after a commit that takes a checkpoint the
//! remaining slots are decided again under the schedule that prefix defines.
//!
//! # Checkpoints and epochs
//!
//! At the first committed leader whose segment timestamp is at least the
//! checkpoint interval after the previous checkpoint, a checkpoint over the
//! segments since is decided. Its body is built once the caller has executed
//! its blocks; the caller then has it signed and hands the vote back. The
//! checkpoint that ends an epoch commits the next committee. The committee
//! keeps ordering for [`CoreConfig::handover_confirmations`] more
//! checkpoints, then stops; once the last of those is certified the caller
//! starts the next epoch's core.
//!
//! # Recovery
//!
//! Before the caller sends a frame it persists the [`Record`]s the core
//! produced with it ([`Core::take_journal`]): every vertex this validator
//! proposed, every reliable-broadcast signal it sent, every vertex it
//! delivered and every batch it authored. A validator that restarts rebuilds
//! its core from them with [`Core::recover`]: it re-derives the committed
//! sequence from the delivered vertices (every honest view commits the same
//! sequence, so it is the one ordered before the crash), never signals a
//! different digest in an instance it already signalled in, and never
//! proposes again in a round it already proposed in.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::batch::{Availability, BatchPart, BatchPayload, MAX_BATCH_BYTES, OrderedBatch};
use crate::checkpoint::{
    Certificate, CertificateContext, Checkpoint, CheckpointEquivocation, CheckpointVote,
    VoteCollector, VoteOutcome, checkpoint_state_height, merkle_root, state_root_height,
};
use crate::committee::{Committee, SeatSet, ValidatorIndex};
use crate::dag::Dag;
use crate::ordering::{OrderingState, Resumed};
use crate::rbc::{RbcAction, RbcStats, ReliableBroadcast, Signal};
use crate::schedule::Schedule;

/// `batches` in order, cut into runs of at most `max` transactions each
/// (a batch holds at most `max`, so none is split), the last holding any
/// batches without transactions that follow.
fn block_chunks(batches: Vec<OrderedBatch>, max: usize) -> Vec<Vec<OrderedBatch>> {
    let mut out: Vec<Vec<OrderedBatch>> = vec![Vec::new()];
    let mut in_chunk = 0usize;
    for b in batches {
        let n = b.batch.transactions as usize;
        if in_chunk > 0 && in_chunk + n > max {
            out.push(Vec::new());
            in_chunk = 0;
        }
        in_chunk += n;
        out.last_mut().expect("one chunk at least").push(b);
    }
    out
}

/// Whether round `r`'s leaders are final for a validator whose first
/// undecided slot is in round `next_undecided`: a commit at an anchor of
/// round `a` redraws the leaders from `a + lookahead + 1` on, and every slot
/// still to be decided is in round `next_undecided` or later.
fn leaders_settled(r: Round, next_undecided: Round, lookahead: Round) -> bool {
    r <= next_undecided.saturating_add(lookahead)
}
use crate::session::{SessionBook, SessionCertificate};
use crate::vertex::{BatchRef, CarriedBatch, Digest, MAX_CARRIED, Round, Vertex, VertexRef};
use crate::wire::{Frontier, MAX_FETCH, Message};

/// Parameters of the protocol core.
#[derive(Debug, Clone)]
pub struct CoreConfig {
    /// Chain id bound into checkpoints.
    pub chain_id: u64,
    /// Genesis block hash bound into checkpoints.
    pub genesis_hash: Digest,
    /// How long a validator holding a quorum of its current round waits for
    /// the round's missing leader vertices before proposing the next round,
    /// counted from when it entered the round.
    pub leader_timeout_ms: u64,
    /// Least time between two rounds this validator proposes.
    pub min_round_interval_ms: u64,
    /// Leader slots per round.
    pub leader_slots: usize,
    /// Minimum spacing of checkpoints, in segment time.
    pub checkpoint_interval_ms: u64,
    /// Rounds kept below the last committed leader.
    pub gc_depth: Round,
    /// Largest number of weak references a vertex carries.
    pub max_weak_refs: usize,
    /// Proposals more than this many rounds ahead are not accepted yet.
    pub max_rounds_ahead: Round,
    /// Checkpoints per epoch.
    pub epoch_checkpoints: u64,
    /// Checkpoints the old committee keeps ordering after the one ending
    /// its epoch.
    pub handover_confirmations: u64,
    /// How long before a fetch is retried from another peer.
    pub fetch_retry_ms: u64,
    /// Least time between two rounds this validator proposes while no
    /// transaction waits to be ordered.
    pub idle_round_interval_ms: u64,
}

/// What a validator must persist before sending what came with it, to be
/// able to recover its core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Record {
    /// A vertex this validator proposed.
    Own(Vertex),
    /// A reliable-broadcast signal this validator sent.
    Signal(Signal),
    /// A vertex this validator delivered into its DAG.
    Delivered(Vertex),
    /// A batch this validator authored.
    Batch(BatchPayload),
    /// The core took a certified checkpoint's ordering state from a peer
    /// and ordered on from there: records before it, other than its own
    /// vertices and batches, are history it no longer needs.
    Resumed(Box<Resumed>),
}

/// Where an epoch starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochStart {
    /// Height of the first block this epoch orders.
    pub first_height: u64,
    /// Index of this epoch's first checkpoint.
    pub first_checkpoint: u64,
    /// Digest of the checkpoint the epoch starts after (zero at genesis).
    pub prev_checkpoint: Digest,
    /// Segment timestamp the epoch starts at.
    pub timestamp_ms: u64,
    /// Height, block hash and post-state root of the last blocks before the
    /// epoch: at least the last [`crate::checkpoint::STATE_ROOT_LAG`] + 1 of
    /// them (only the genesis block at genesis), so the epoch's first
    /// checkpoint can commit its lagged state root.
    pub base_blocks: Vec<(u64, Digest, Digest)>,
    /// Rounds between a checkpoint's anchor and the first round its seed
    /// draws, for the whole epoch: the governed value when the epoch began.
    pub leader_lookahead_rounds: Round,
}

/// Who a message is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Every other committee member.
    All,
    /// One member.
    One(ValidatorIndex),
}

/// An ordered segment: one block's worth of batches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Epoch.
    pub epoch: u64,
    /// Block height.
    pub height: u64,
    /// The committed leader vertex.
    pub anchor: VertexRef,
    /// Block timestamp: the median of the leader's parents' timestamps,
    /// never below the previous segment's.
    pub timestamp_ms: u64,
    /// Batches, in execution order, with their payloads.
    pub batches: Vec<(OrderedBatch, BatchPayload)>,
    /// Vertices this segment ordered.
    pub vertices: usize,
}

/// Something the caller must act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A segment to build a block from and execute, in height order. Only a
    /// committed leader that orders transactions makes one: an idle
    /// committee's leaders order none, and no block.
    Ordered(Segment),
    /// The epoch's last checkpoint ends at `last_height`, after every
    /// segment released before this event. Once that height is executed,
    /// the caller derives the next committee from the state it produced and
    /// supplies its root with [`Core::set_next_committee_root`]; the
    /// checkpoint is not signed before that.
    EpochEnds {
        /// The last block of the epoch.
        last_height: u64,
    },
    /// A checkpoint body to sign; hand the vote back with
    /// [`Core::on_own_vote`].
    Sign(Checkpoint),
    /// A certificate.
    Certified(Box<Certificate>),
    /// A validator signed two checkpoints with one index.
    Equivocation(Box<CheckpointEquivocation>),
    /// This validator's batch was never ordered; its transactions go back
    /// to the mempool.
    Unordered(BatchPayload),
    /// The epoch is over: the last handover checkpoint is certified.
    EpochComplete(Box<Certificate>),
    /// The two ML-DSA-65 implementations disagreed on a signature in a vote
    /// or certificate for checkpoint `index`. The object was refused and
    /// this core has halted: it orders and certifies nothing more until it
    /// is restarted on a build whose implementations agree.
    VerifierDisagreement {
        /// The checkpoint the refused vote or certificate was for.
        index: u64,
    },
}

#[derive(Debug, Clone)]
struct PendingCheckpoint {
    index: u64,
    first_height: u64,
    last_height: u64,
    anchor_round: Round,
    timestamp_ms: u64,
    ends_epoch: bool,
    // The digest of the ordering state right after the checkpoint was
    // decided, set once the commit that decided it is done.
    ordering_root: Option<Digest>,
}

/// A core waiting for the ordering state of a certified checkpoint.
#[derive(Debug)]
struct Resuming {
    certificate: Certificate,
    // The last round this validator proposed in before, if any: it never
    // proposes in it or below it again.
    own_round: Option<Round>,
    asked_ms: u64,
}

/// What is released to the caller in order: a block's segment, or the end
/// of the epoch.
#[derive(Debug)]
enum Waiting {
    Segment(WaitingSegment),
    EpochEnds { last_height: u64 },
}

#[derive(Debug)]
struct WaitingSegment {
    height: u64,
    anchor: VertexRef,
    timestamp_ms: u64,
    batches: Vec<OrderedBatch>,
    vertices: usize,
}

/// Fetch requests one frame is answered for.
const MAX_FETCHES_PER_FRAME: usize = 4;

/// Most batch bytes one peer's fetches are answered with between two takes
/// of the outbox. A peer asking for more asks again; what it asks for and
/// is not sent now is sent on a later pass.
const MAX_BATCH_REPLY_BYTES: usize = 8 << 20;

/// Fetch retry intervals a batch sent to a peer in answer to a fetch is not
/// sent to it again. A peer retries a missing batch every interval; were
/// every retry answered, a validator slow to drain its outbox would copy
/// the same batches into it again and again, and the copies it can never
/// send crowd out the messages its peers wait on.
const BATCH_REPLY_COOLDOWN_RETRIES: u64 = 8;

#[derive(Debug, Default)]
struct Wanted {
    asked_ms: u64,
    attempts: u32,
    /// The validator that surely holds it, when known: a batch's author.
    /// Every other attempt goes to it.
    holder: Option<ValidatorIndex>,
    /// For a batch, the highest round of a vertex naming it: once that
    /// round is below the garbage-collection floor, nothing waits for it.
    round: Round,
}

/// Most reliable-broadcast signals a recovering validator re-sends in one
/// message.
const MAX_SIGNALS_PER_FRAME: usize = 4_096;

/// Released segments whose batches are kept for peers until a certificate
/// covers them, at most.
const UNCERTIFIED_SEGMENTS_KEPT: usize = 4_096;

/// Ordering states of the latest decided checkpoints kept to serve a peer
/// that resumes from one.
const ORDERING_STATES_KEPT: usize = 32;

/// Rounds below the DAG's floor whose vertices are kept to serve a peer
/// that resumes from a checkpoint: it needs the rounds from that
/// checkpoint's floor up, which this validator may already have pruned.
fn history_depth(gc_depth: Round) -> Round {
    gc_depth.saturating_mul(4)
}

/// A leader slot: a round and the slot's index within it.
type Slot = (Round, usize);

/// What a leader slot is decided as.
#[derive(Debug, Clone, Copy)]
enum Decision {
    Commit(VertexRef),
    Skip,
    Undecided,
}

/// Round durations kept for [`CoreStats`].
const ROUND_WINDOW: usize = 256;

/// Skipped leader slots kept for [`Core::take_skipped`]; older ones are
/// dropped when nobody takes them.
pub const SKIPPED_SLOTS_KEPT: usize = 256;

/// Container sizes of one core, from [`Core::sizes`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoreSizes {
    /// Rounds the DAG spans, floor to top.
    pub dag_rounds: u64,
    /// Vertices the DAG holds.
    pub dag_vertices: usize,
    /// Vertices waiting for parents.
    pub dag_pending: usize,
    /// Delivered vertices not yet echoed.
    pub unechoed: usize,
    /// Vertex bodies held.
    pub bodies: usize,
    /// Rounds with first proposals recorded.
    pub first_proposals: usize,
    /// Vertices ordered and remembered.
    pub ordered: usize,
    /// Batch payloads held.
    pub payloads: usize,
    /// Rounds with payload records.
    pub payload_rounds: usize,
    /// Vertices requested from peers.
    pub wanted_vertices: usize,
    /// Batches requested from peers.
    pub wanted_batches: usize,
    /// Segments waiting for their payloads.
    pub waiting: usize,
    /// Slots decided and remembered.
    pub decided: usize,
    /// Executed heights remembered.
    pub executed: usize,
    /// Reliable-broadcast instances open.
    pub rbc_instances: usize,
    /// Batches waiting for availability.
    pub availability_pending: usize,
    /// Events not yet taken.
    pub events: usize,
    /// Frames not yet taken.
    pub outbox: usize,
    /// Journal records not yet taken.
    pub journal: usize,
    /// Vertices kept below the DAG's floor to serve a resuming peer.
    pub history: usize,
    /// Ordering states kept to serve a resuming peer.
    pub ordering_states: usize,
    /// Released segments whose batches are kept until a certificate covers
    /// them.
    pub uncertified_segments: usize,
    /// [`Core::buffered_bytes`].
    pub buffered_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreStats {
    /// Current round, if started.
    pub round: Option<Round>,
    /// Last committed leader round.
    pub last_committed: Option<Round>,
    /// Next block height to order.
    pub next_height: u64,
    /// Median and 99th percentile of the last rounds' durations, ms.
    pub round_p50_ms: u64,
    /// See `round_p50_ms`.
    pub round_p99_ms: u64,
    /// Rounds the percentiles are over.
    pub rounds_measured: usize,
    /// Reliable-broadcast deliveries by path.
    pub rbc: RbcStats,
    /// Leader slots committed and skipped since start.
    pub leaders_committed: u64,
    /// See `leaders_committed`.
    pub leaders_skipped: u64,
    /// Batches introduced but not yet available.
    pub batches_pending: usize,
    /// diag: why enter_after most recently refused to advance the round.
    pub diag_advance_refusal: &'static str,
    /// diag: this round's weight vs the quorum it needs.
    pub diag_round_weight: (u64, u64),
    /// diag: FetchBatches requests answered with nothing held, since start.
    pub diag_empty_batch_replies: u64,
    /// diag: Frontier repair requests sent (to all peers), since start.
    pub diag_frontier_sent: u64,
    /// diag: Frontier repair requests received from a peer, since start --
    /// counted whether or not this core went on to answer (the once-per
    /// fetch_retry_ms throttle in `on_frontier` may have skipped it).
    pub diag_frontier_received: u64,
    /// diag: Frontier repair requests this core actually answered, since
    /// start (a subset of `diag_frontier_received`).
    pub diag_frontier_answered: u64,
    /// diag: on the most recent answer, how many of this core's own
    /// authored vertices and how many RBC signals it resent. Both at 0 on
    /// an answered request means this core itself has nothing yet to
    /// offer the asker for the round it asked about.
    pub diag_last_frontier_reply: (usize, usize),
}

/// Most unreleased batches of another author kept beyond its released
/// point.
const MAX_AHEAD_PER_AUTHOR: usize = 1_024;

/// Rounds below the current one whose missing vertices are pulled as live
/// traffic rather than as history.
const LIVE_ROUNDS: Round = 2;

/// Most history vertices asked for in one retry pass.
const MAX_BULK_FETCH: usize = 256;

/// The least `gc_depth` the bound on uncommitted rounds is taken from.
const MIN_UNCOMMITTED_ROUNDS: Round = 16;

/// Rough in-memory size of a vertex with its references.
const VERTEX_BYTES_ESTIMATE: usize = 2_048;

/// The consensus state machine of one validator in one epoch.
pub struct Core {
    cfg: CoreConfig,
    committee: Committee,
    me: ValidatorIndex,
    start: EpochStart,
    rbc: ReliableBroadcast,
    dag: Dag,
    schedule: Schedule,
    availability: Availability,
    bodies: HashMap<Digest, Vertex>,
    first_proposals: BTreeMap<Round, HashMap<ValidatorIndex, Vec<VertexRef>>>,
    round: Option<Round>,
    round_entered_ms: u64,
    // Instrumentation.
    round_durations_ms: VecDeque<u64>,
    // diag: why enter_after most recently refused to advance the round,
    // cleared on an accepted advance. Local-only diagnostic, this session.
    diag_advance_refusal: &'static str,
    // diag: FetchBatches requests this core answered with nothing held.
    diag_empty_batch_replies: u64,
    // diag: Frontier repair requests sent, received, and answered; and the
    // (vertices, signals) counts of the most recent answer. Local-only
    // diagnostic, added to chase chaos seed 3054677367's round-1 RBC
    // delivery stall (TENZRO-INFLIGHT.md, 2026-10-21).
    diag_frontier_sent: u64,
    diag_frontier_received: u64,
    diag_frontier_answered: u64,
    diag_last_frontier_reply: (usize, usize),
    leaders_committed: u64,
    leaders_skipped: u64,
    // The latest skipped slots with their leaders, bounded.
    skipped_slots: VecDeque<(Round, ValidatorIndex)>,
    // The first leader slot not yet decided.
    next_slot: Slot,
    last_committed: Option<Round>,
    ordered: HashMap<Digest, Round>,
    next_height: u64,
    last_timestamp_ms: u64,
    // Batches.
    payloads: HashMap<Digest, BatchPayload>,
    payload_round: HashMap<Digest, Round>,
    next_batch_sequence: u64,
    own_unintroduced: Vec<BatchRef>,
    own_introduced: HashMap<Digest, Round>,
    // Other authors' batches this validator holds that no vertex in its DAG
    // introduced and that are not released yet: what it carries when it
    // leads a round.
    carry_pool: BTreeMap<(ValidatorIndex, u64), BatchRef>,
    // Proposals this validator has not echoed yet because it does not hold
    // every batch they introduce, by (round, author): the first proposal of
    // each slot only.
    unechoed: HashMap<(Round, ValidatorIndex), Vertex>,
    // The time of the latest input.
    now_ms: u64,
    // Segments waiting for batch payloads, in height order, with the end of
    // the epoch in its place among them.
    waiting: VecDeque<Waiting>,
    // The highest round whose vertices introduced or carried a batch: the
    // committee stays at full pace until a leader after it commits.
    last_payload_round: Option<Round>,
    // The height whose post-state the last checkpoint decided commits.
    last_state_height: u64,
    // When the epoch's last checkpoint is due, in segment time.
    epoch_ends_ms: u64,
    // Whether this validator's ordering decided the epoch's last checkpoint.
    // Only ordering sets it: every validator decides the epoch's checkpoints
    // from the same ordered history, whatever certificates it holds.
    epoch_closed: bool,
    // Fetches.
    wanted_vertices: HashMap<Digest, Wanted>,
    wanted_batches: HashMap<Digest, Wanted>,
    // Requests answered from the frame being handled; see on_messages.
    frame_fetches: usize,
    // Batch bytes each peer's fetches were answered with since the outbox
    // was last taken.
    batch_reply_bytes: HashMap<ValidatorIndex, usize>,
    // When each batch was last sent to each peer in answer to a fetch.
    batch_replied: HashMap<(ValidatorIndex, Digest), u64>,
    frame_answered_frontier: bool,
    frame_answered_ordering: bool,
    // When each peer's frontier was last answered.
    frontier_answered_ms: HashMap<ValidatorIndex, u64>,
    // Checkpoints.
    last_checkpoint_height: u64,
    last_checkpoint_ts: u64,
    next_checkpoint_index: u64,
    decided: VecDeque<PendingCheckpoint>,
    seed_chain: Vec<Digest>,
    executed: BTreeMap<u64, (Digest, Digest, Vec<Digest>)>,
    prev_checkpoint: Digest,
    next_committee_root: Option<Digest>,
    votes: VoteCollector,
    // The epoch's session certificates, admitted from votes, that this
    // validator's certificates name by digest.
    sessions: SessionBook,
    certificates: BTreeMap<u64, Certificate>,
    halted: bool,
    // The two ML-DSA-65 implementations every vote and certificate is
    // checked with before it counts.
    ml_dsa: crate::nversion::Verifiers,
    // Set by the caller while its execution trails this validator's
    // ordering too far: see `hold_frontier`.
    frontier_held: bool,
    // The handover's index, from this validator's ordering.
    handover_index: u64,
    // The handover's index, from a certified closing checkpoint this
    // validator has not ordered to yet.
    certified_handover_index: u64,
    events: Vec<Event>,
    outbox: Vec<(Target, Message)>,
    journal: Vec<Record>,
    // Heights already executed before a recovery: their segments are
    // released without payloads, which the caller does not need again.
    executed_through: u64,
    // Validators this one has a channel to, itself included: the epoch's
    // first round is proposed once they hold a quorum.
    connected: SeatSet,
    started: bool,
    // This validator's votes for checkpoints not yet certified, re-sent to a
    // peer that missed them.
    own_votes: BTreeMap<u64, CheckpointVote>,
    // When this validator last asked its peers for what its round lacks.
    last_repair_ms: u64,
    // The ordering state right after each of the latest decided checkpoints.
    ordering_states: BTreeMap<u64, OrderingState>,
    // Vertices pruned from the DAG, kept for `history_depth` rounds to serve
    // a resuming peer, by digest and by round.
    history: HashMap<Digest, Vertex>,
    history_rounds: BTreeMap<Round, Vec<Digest>>,
    // Set while this core waits for a checkpoint's ordering state.
    resuming: Option<Resuming>,
    // The batches of each released segment no certificate covers yet.
    uncertified_payloads: BTreeMap<u64, Vec<Digest>>,
    // Every slot decision and every released vertex, in order, for the
    // specification replay.
    #[cfg(test)]
    decided_slots: Vec<(Slot, Option<VertexRef>)>,
    #[cfg(test)]
    released: Vec<VertexRef>,
}

impl Core {
    /// The core of validator `me` in `committee`'s epoch.
    pub fn new(
        cfg: CoreConfig,
        committee: Committee,
        me: ValidatorIndex,
        start: EpochStart,
    ) -> Self {
        let seed = Schedule::epoch_seed(committee.epoch, &start.prev_checkpoint);
        let schedule = Schedule::new(
            &committee,
            seed,
            cfg.leader_slots,
            start.leader_lookahead_rounds,
        );
        let mut executed = BTreeMap::new();
        for (h, block, state) in &start.base_blocks {
            executed.insert(*h, (*block, *state, Vec::new()));
        }
        // Fixed once the epoch's last checkpoint is decided.
        let handover_index = u64::MAX;
        Self {
            rbc: ReliableBroadcast::new(me),
            dag: Dag::with_vouching(
                committee.members().iter().map(|m| m.seats).collect(),
                committee.validity(),
            ),
            schedule,
            availability: Availability::new(),
            bodies: HashMap::new(),
            first_proposals: BTreeMap::new(),
            round: None,
            round_entered_ms: 0,
            round_durations_ms: VecDeque::with_capacity(ROUND_WINDOW),
            diag_advance_refusal: "none",
            diag_empty_batch_replies: 0,
            diag_frontier_sent: 0,
            diag_frontier_received: 0,
            diag_frontier_answered: 0,
            diag_last_frontier_reply: (0, 0),
            leaders_committed: 0,
            leaders_skipped: 0,
            skipped_slots: VecDeque::new(),
            next_slot: (0, 0),
            last_committed: None,
            ordered: HashMap::new(),
            next_height: start.first_height,
            last_timestamp_ms: start.timestamp_ms,
            payloads: HashMap::new(),
            payload_round: HashMap::new(),
            next_batch_sequence: 0,
            own_unintroduced: Vec::new(),
            own_introduced: HashMap::new(),
            carry_pool: BTreeMap::new(),
            unechoed: HashMap::new(),
            now_ms: 0,
            waiting: VecDeque::new(),
            last_payload_round: None,
            last_state_height: start.first_height.saturating_sub(1),
            epoch_ends_ms: start.timestamp_ms.saturating_add(
                cfg.checkpoint_interval_ms
                    .saturating_mul(cfg.epoch_checkpoints),
            ),
            epoch_closed: false,
            wanted_vertices: HashMap::new(),
            wanted_batches: HashMap::new(),
            frame_fetches: 0,
            batch_reply_bytes: HashMap::new(),
            batch_replied: HashMap::new(),
            frame_answered_frontier: false,
            frame_answered_ordering: false,
            frontier_answered_ms: HashMap::new(),
            last_checkpoint_height: start.first_height.saturating_sub(1),
            last_checkpoint_ts: start.timestamp_ms,
            next_checkpoint_index: start.first_checkpoint,
            decided: VecDeque::new(),
            seed_chain: vec![start.prev_checkpoint],
            executed,
            prev_checkpoint: start.prev_checkpoint,
            next_committee_root: None,
            votes: VoteCollector::new(),
            sessions: SessionBook::new(cfg.chain_id, cfg.genesis_hash, committee.epoch),
            certificates: BTreeMap::new(),
            halted: false,
            ml_dsa: crate::nversion::Verifiers::default(),
            frontier_held: false,
            handover_index,
            certified_handover_index: u64::MAX,
            events: Vec::new(),
            outbox: Vec::new(),
            journal: Vec::new(),
            executed_through: 0,
            connected: SeatSet::new(),
            started: false,
            own_votes: BTreeMap::new(),
            last_repair_ms: 0,
            ordering_states: BTreeMap::new(),
            history: HashMap::new(),
            history_rounds: BTreeMap::new(),
            resuming: None,
            uncertified_payloads: BTreeMap::new(),
            #[cfg(test)]
            decided_slots: Vec::new(),
            #[cfg(test)]
            released: Vec::new(),
            cfg,
            committee,
            me,
            start,
        }
    }

    /// Rebuilds the core of a validator that restarted mid-epoch from the
    /// records it persisted since `start`. `executed_through` is the highest
    /// height it had executed: segments up to it are re-emitted without
    /// batches, so the caller can hand back their block hashes and state
    /// roots from storage instead of executing them again.
    pub fn recover(
        cfg: CoreConfig,
        committee: Committee,
        me: ValidatorIndex,
        start: EpochStart,
        records: Vec<Record>,
        executed_through: u64,
        now_ms: u64,
    ) -> Self {
        let mut core = Self::new(cfg, committee, me, start);
        core.executed_through = executed_through;
        // A core that resumed from a certified checkpoint starts again from
        // there: before it, only its own rounds and batches still count.
        let mut records = records;
        if let Some(at) = records
            .iter()
            .rposition(|r| matches!(r, Record::Resumed(_)))
        {
            let after = records.split_off(at + 1);
            let Some(Record::Resumed(resumed)) = records.pop() else {
                unreachable!("the record at `at` resumes")
            };
            let mut own_round = None;
            for r in records {
                match r {
                    Record::Own(v) => own_round = own_round.max(Some(v.round)),
                    Record::Batch(p) => {
                        let d = p.digest();
                        core.payload_round.insert(d, 0);
                        core.payloads.insert(d, p);
                    }
                    _ => {}
                }
            }
            let Resumed { certificate, state } = *resumed;
            core.install(certificate, state, own_round, now_ms);
            records = after;
        }
        let mut own = Vec::new();
        let mut delivered = Vec::new();
        let mut signals = Vec::new();
        for r in records {
            match r {
                Record::Own(v) => own.push(v),
                Record::Delivered(v) => delivered.push(v),
                Record::Signal(s) => signals.push(s),
                Record::Batch(p) => {
                    let d = p.digest();
                    core.payload_round.insert(d, 0);
                    core.payloads.insert(d, p);
                }
                Record::Resumed(_) => {}
            }
        }
        // Batch sequence numbers continue past every batch already sealed.
        core.next_batch_sequence = core.next_batch_sequence.max(
            core.payloads
                .values()
                .filter(|p| p.author == me)
                .map(|p| p.sequence + 1)
                .max()
                .unwrap_or(0),
        );
        // This validator's own vertices: it never proposes in their rounds
        // again, and the batches they introduced are accounted for.
        own.sort_by_key(|v| v.round);
        for v in &own {
            for b in &v.batches {
                core.own_introduced.insert(b.digest, v.round);
            }
            core.first_proposals
                .entry(v.round)
                .or_default()
                .insert(me, v.strong.clone());
            core.bodies.insert(v.digest(), v.clone());
            core.round = Some(v.round);
        }
        let introduced: HashSet<Digest> = own
            .iter()
            .flat_map(|v| v.batches.iter().map(|b| b.digest))
            .collect();
        let mut unintroduced: Vec<BatchRef> = core
            .payloads
            .iter()
            .filter(|(d, p)| p.author == me && !introduced.contains(*d))
            .map(|(_, p)| p.reference())
            .collect();
        // A vertex introduces consecutive sequences.
        unintroduced.sort_by_key(|b| b.sequence);
        core.own_unintroduced = unintroduced;

        // The DAG and the signals, a round at a time, committing as soon as
        // it can so that garbage collection keeps memory bounded.
        delivered.sort_by_key(|v| (v.round, v.source));
        signals.sort_by_key(|s| s.round);
        let sent_before = signals.clone();
        let mut signals = signals.into_iter().peekable();
        let mut i = 0;
        while i < delivered.len() {
            let round = delivered[i].round;
            while let Some(s) = signals.next_if(|s| s.round <= round) {
                core.rbc.restore_sent(&core.committee, s);
            }
            while i < delivered.len() && delivered[i].round == round {
                let v = delivered[i].clone();
                let d = v.digest();
                core.rbc.restore_delivered(v.round, v.source, d);
                core.first_proposals
                    .entry(v.round)
                    .or_default()
                    .entry(v.source)
                    .or_insert_with(|| v.strong.clone());
                core.dag.expect(d, v.round);
                let _ = core.dag.offer(v);
                i += 1;
            }
            core.try_commit();
        }
        for s in signals {
            core.rbc.restore_sent(&core.committee, s);
        }
        core.release_segments();
        core.wanted_vertices.clear();
        core.journal.clear();
        core.round_entered_ms = now_ms;
        // Peers may not hold this validator's latest vertices yet.
        let floor = core.dag.floor();
        for v in own.into_iter().filter(|v| v.round >= floor) {
            if core.dag.get(&v.digest()).is_none() {
                core.send(Target::All, Message::Propose(v));
            }
        }
        // Nor the signals it sent: a peer that restarted too lost its tally
        // of them, and an instance whose echoes and readies no one tallies
        // any more would never deliver. The same signals again, never a
        // different digest, so nothing it said changes.
        let resend: Vec<Signal> = sent_before
            .into_iter()
            .filter(|s| s.round >= floor)
            .collect();
        for chunk in resend.chunks(MAX_SIGNALS_PER_FRAME) {
            core.send(Target::All, Message::Signals(chunk.to_vec()));
        }
        core
    }

    /// The core of validator `me` in `committee`'s epoch, for a validator
    /// that fell further behind than its peers keep the DAG: it orders on
    /// from `certificate`, a certified checkpoint of the epoch, once a peer
    /// sends the ordering state the checkpoint commits. Until then it
    /// proposes and orders nothing. `own_round` is the last round it
    /// proposed in, `next_batch_sequence` the sequence its next batch takes,
    /// `executed_through` the highest height the caller already executed,
    /// and `leader_lookahead_rounds` the lookahead the epoch runs with.
    #[allow(clippy::too_many_arguments)]
    pub fn resume(
        cfg: CoreConfig,
        committee: Committee,
        me: ValidatorIndex,
        certificate: Certificate,
        sessions: Vec<SessionCertificate>,
        own_round: Option<Round>,
        next_batch_sequence: u64,
        executed_through: u64,
        leader_lookahead_rounds: Round,
    ) -> Self {
        let cp = &certificate.checkpoint;
        let start = EpochStart {
            first_height: cp.last_height + 1,
            first_checkpoint: cp.index + 1,
            prev_checkpoint: cp.digest(),
            timestamp_ms: cp.timestamp_ms,
            base_blocks: Vec::new(),
            leader_lookahead_rounds,
        };
        let mut core = Self::new(cfg, committee, me, start);
        for s in sessions {
            let _ = core.sessions.admit(&core.committee, s);
        }
        core.last_committed = Some(cp.anchor_round);
        core.next_batch_sequence = next_batch_sequence;
        core.executed_through = executed_through;
        core.resuming = Some(Resuming {
            certificate,
            own_round,
            asked_ms: 0,
        });
        core
    }

    /// The round from which this core still needs what its peers hold:
    /// the last committed leader's, or the anchor round of the oldest
    /// ordered segment still waiting for its batches if that is lower.
    /// Peers keep the DAG and the batches it introduces for the
    /// garbage-collection depth above their own last committed round; a
    /// certified checkpoint whose anchor is further past this round than
    /// that is out of this core's reach.
    pub fn reach_round(&self) -> Option<Round> {
        let waiting = self.waiting.iter().find_map(|w| match w {
            Waiting::Segment(s) => Some(s.anchor.round),
            Waiting::EpochEnds { .. } => None,
        });
        match (self.last_committed, waiting) {
            (Some(c), Some(w)) => Some(c.min(w)),
            (c, w) => c.or(w),
        }
    }

    /// Whether this core still waits for the ordering state it resumes
    /// from.
    pub fn is_resuming(&self) -> bool {
        self.resuming.is_some()
    }

    /// The checkpoint this core resumes from, while it waits for its state.
    pub fn resuming_from(&self) -> Option<&Certificate> {
        self.resuming.as_ref().map(|r| &r.certificate)
    }

    /// Rounds between a checkpoint's anchor and the first round its seed
    /// draws, fixed for the epoch.
    pub fn leader_lookahead(&self) -> Round {
        self.schedule.lookahead()
    }

    /// The sequence this validator's next batch takes.
    pub fn next_batch_sequence(&self) -> u64 {
        self.next_batch_sequence
    }

    /// Asks every connected peer for the ordering state this core resumes
    /// from, at most once per retry interval.
    fn ask_ordering(&mut self, now_ms: u64) {
        let retry = self.cfg.fetch_retry_ms.max(1).saturating_mul(4);
        let Some(r) = self.resuming.as_mut() else {
            return;
        };
        if r.asked_ms != 0 && now_ms < r.asked_ms.saturating_add(retry) {
            return;
        }
        r.asked_ms = now_ms.max(1);
        let index = r.certificate.checkpoint.index;
        self.send(Target::All, Message::FetchOrdering(index));
    }

    /// A peer's answer: installed if it is the state the certificate this
    /// core resumes from commits.
    fn on_ordering(&mut self, state: OrderingState) {
        let Some(r) = self.resuming.as_ref() else {
            return;
        };
        let cp = &r.certificate.checkpoint;
        if state.index != cp.index || state.epoch != cp.epoch || state.digest() != cp.ordering_root
        {
            return;
        }
        let r = self.resuming.take().expect("checked above");
        let now = self.now_ms;
        self.install(r.certificate, state, r.own_round, now);
        // Ask every peer for the rounds in play.
        self.last_repair_ms = now;
        let f = self.frontier();
        self.send(Target::All, Message::Frontier(f));
        self.progress(now);
    }

    /// Takes on `state`, the ordering state `certificate`'s checkpoint
    /// commits, as this core's own.
    fn install(
        &mut self,
        certificate: Certificate,
        state: OrderingState,
        own_round: Option<Round>,
        now_ms: u64,
    ) {
        self.resuming = None;
        self.journal.push(Record::Resumed(Box::new(Resumed {
            certificate: certificate.clone(),
            state: state.clone(),
        })));
        let index = certificate.checkpoint.index;
        self.dag = Dag::with_vouching(
            self.committee.members().iter().map(|m| m.seats).collect(),
            self.committee.validity(),
        );
        self.dag.prune_below(state.floor);
        self.ordered = state.ordered.iter().copied().collect();
        self.next_slot = (state.next_slot.0, state.next_slot.1 as usize);
        self.last_committed = Some(state.anchor_round);
        self.next_height = state.next_height;
        self.last_timestamp_ms = state.last_timestamp_ms;
        self.last_state_height = state.last_state_height;
        self.last_checkpoint_height = state.last_checkpoint_height;
        self.last_checkpoint_ts = state.last_checkpoint_ts;
        self.next_checkpoint_index = index + 1;
        self.epoch_ends_ms = state.epoch_ends_ms;
        self.epoch_closed = state.epoch_closed;
        self.handover_index = state.handover_index;
        self.seed_chain = state.seed_tail.clone();
        if self.seed_chain.is_empty() {
            self.seed_chain.push(certificate.checkpoint.prev);
        }
        self.schedule = Schedule::import(&state.schedule);
        self.availability = Availability::import(&state.availability);
        let own_next = state
            .availability
            .early
            .iter()
            .filter(|(a, _)| *a == self.me)
            .flat_map(|(_, v)| v.iter().map(|(s, ..)| s + 1))
            .max()
            .unwrap_or(0)
            .max(self.availability.released_through(self.me));
        self.next_batch_sequence = self.next_batch_sequence.max(own_next);
        self.prev_checkpoint = certificate.checkpoint.digest();
        self.decided.clear();
        self.waiting.clear();
        self.uncertified_payloads.clear();
        self.round = own_round.max(Some(state.anchor_round));
        self.round_entered_ms = now_ms;
        self.certificates.insert(index, certificate);
        self.ordering_states.insert(index, state);
        self.wanted_vertices.clear();
    }

    /// The ordering state right after the commit that decided checkpoint
    /// `index`.
    fn ordering_state(&self, index: u64) -> OrderingState {
        let mut ordered: Vec<(Digest, Round)> =
            self.ordered.iter().map(|(d, r)| (*d, *r)).collect();
        ordered.sort_unstable();
        let tail = self.seed_chain.len().saturating_sub(3);
        OrderingState {
            epoch: self.committee.epoch,
            index,
            anchor_round: self.last_committed.unwrap_or(0),
            next_slot: (self.next_slot.0, self.next_slot.1 as u64),
            floor: self.dag.floor(),
            ordered,
            next_height: self.next_height,
            last_timestamp_ms: self.last_timestamp_ms,
            last_state_height: self.last_state_height,
            last_checkpoint_height: self.last_checkpoint_height,
            last_checkpoint_ts: self.last_checkpoint_ts,
            epoch_ends_ms: self.epoch_ends_ms,
            epoch_closed: self.epoch_closed,
            handover_index: self.handover_index,
            seed_tail: self.seed_chain[tail..].to_vec(),
            schedule: self.schedule.export(),
            availability: self.availability.export(),
        }
    }

    /// Fixes the ordering root of the checkpoint the last commit decided,
    /// keeping its state to serve resuming peers, and builds what is ready.
    fn seal_decided(&mut self) {
        if let Some(index) = self
            .decided
            .back()
            .filter(|pc| pc.ordering_root.is_none())
            .map(|pc| pc.index)
        {
            let state = self.ordering_state(index);
            let root = state.digest();
            if let Some(pc) = self.decided.back_mut() {
                pc.ordering_root = Some(root);
            }
            self.ordering_states.insert(index, state);
            while self.ordering_states.len() > ORDERING_STATES_KEPT {
                self.ordering_states.pop_first();
            }
        }
        self.build_checkpoints();
    }

    /// Entries held in each of the core's growing containers, for memory
    /// accounting: every one of them must stay bounded however long the
    /// validator runs.
    pub fn diag_view(&self) -> String {
        let cur = self.round.unwrap_or(0);
        let mut rounds = Vec::new();
        for r in cur.saturating_sub(2)..=cur + 1 {
            let have: Vec<ValidatorIndex> = (0..self.committee.size() as ValidatorIndex)
                .filter(|s| self.dag.at(r, *s).is_some())
                .collect();
            rounds.push((r, have));
        }
        let mut wb: Vec<(u32, Option<ValidatorIndex>, Round)> = self
            .wanted_batches
            .values()
            .map(|w| (w.attempts, w.holder, w.round))
            .collect();
        wb.sort();
        wb.truncate(12);
        let un: Vec<(Round, ValidatorIndex)> = self.unechoed.keys().copied().collect();
        format!(
            "delivered={:?} holes={:?} wanted_batches={} {:?} wanted_vertices={} unechoed={:?} connected={} floor={} leaders_wait={}",
            rounds,
            self.rbc.undelivered_from(),
            self.wanted_batches.len(),
            wb,
            self.wanted_vertices.len(),
            un,
            self.connected.weight(),
            self.dag.floor(),
            self.waiting.len(),
        )
    }

    pub fn sizes(&self) -> CoreSizes {
        let top = self.dag.highest_round().unwrap_or(0);
        CoreSizes {
            dag_rounds: top.saturating_sub(self.dag.floor()) + 1,
            dag_vertices: (self.dag.floor()..=top)
                .map(|r| self.dag.round(r).count())
                .sum(),
            dag_pending: {
                let (a, b) = self.dag.pending_len();
                a + b
            },
            unechoed: self.unechoed.len(),
            bodies: self.bodies.len(),
            first_proposals: self.first_proposals.len(),
            ordered: self.ordered.len(),
            payloads: self.payloads.len(),
            payload_rounds: self.payload_round.len(),
            wanted_vertices: self.wanted_vertices.len(),
            wanted_batches: self.wanted_batches.len(),
            waiting: self.waiting.len(),
            decided: self.decided.len(),
            executed: self.executed.len(),
            rbc_instances: self.rbc.instances_len(),
            availability_pending: self.availability.pending_len(),
            events: self.events.len(),
            outbox: self.outbox.len(),
            journal: self.journal.len(),
            history: self.history.len(),
            ordering_states: self.ordering_states.len(),
            uncertified_segments: self.uncertified_payloads.len(),
            buffered_bytes: self.buffered_bytes(),
        }
    }

    #[cfg(test)]
    pub(crate) fn mem_probe(&self) -> String {
        let fp: usize = self
            .first_proposals
            .values()
            .map(|m| m.values().map(|v| v.len()).sum::<usize>())
            .sum();
        let top = self.dag.highest_round().unwrap_or(0);
        let dag_rounds = top.saturating_sub(self.dag.floor()) + 1;
        let dag_v: usize = (self.dag.floor()..=top)
            .map(|r| self.dag.round(r).count())
            .sum();
        format!(
            "round={:?} committed={:?} dag_floor={} dag_rounds={dag_rounds} dag_vertices={dag_v} unechoed={} dag_pending_expected={:?} bodies={} first_prop_rounds={} first_prop_refs={fp} ordered={} payloads={} payload_round={} own_intro={} wanted_v={} wanted_b={} waiting={} decided={} executed={} rbc={} avail_pending={} events={} outbox={} journal={}",
            self.round,
            self.last_committed,
            self.dag.floor(),
            self.unechoed.len(),
            self.dag.pending_len(),
            self.bodies.len(),
            self.first_proposals.len(),
            self.ordered.len(),
            self.payloads.len(),
            self.payload_round.len(),
            self.own_introduced.len(),
            self.wanted_vertices.len(),
            self.wanted_batches.len(),
            self.waiting.len(),
            self.decided.len(),
            self.executed.len(),
            self.rbc.instances_len(),
            self.availability.pending_len(),
            self.events.len(),
            self.outbox.len(),
            self.journal.len(),
        )
    }

    /// Takes the records produced since the last call. The caller persists
    /// them before it sends the frames [`Core::take_outbox`] returns.
    pub fn take_journal(&mut self) -> Vec<Record> {
        std::mem::take(&mut self.journal)
    }

    /// Adopts a certificate this validator already holds, after a recovery,
    /// with the session certificates it names.
    /// Adopts `c` as the handover of the running epoch. The caller holds
    /// the epoch's closing checkpoint, so it knows `c` is the one
    /// confirming it; the closing checkpoint itself may never have been
    /// certified (a quorum did not sign it before the epoch moved on), and
    /// a validator that was not there when the epoch closed cannot tell
    /// the handover from any other later certificate without it.
    pub fn adopt_handover(&mut self, c: Certificate, sessions: Vec<SessionCertificate>) {
        if !self.admit_sessions(c.checkpoint.index, sessions) {
            return;
        }
        if !self.ml_dsa.certificate_agrees(&c, &self.sessions) {
            self.on_disagreement(c.checkpoint.index);
            return;
        }
        let ctx = CertificateContext {
            chain_id: self.cfg.chain_id,
            genesis_hash: &self.cfg.genesis_hash,
            committee: &self.committee,
            sessions: &self.sessions,
        };
        if c.verify(&ctx).is_err() {
            return;
        }
        if c.checkpoint.epoch == self.committee.epoch
            && !self.epoch_closed
            && self.certified_handover_index == u64::MAX
        {
            self.certified_handover_index = c.checkpoint.index;
            if let Some(held) = self.certificates.get(&c.checkpoint.index).cloned() {
                self.complete_epoch(held);
                return;
            }
        }
        self.on_certificate(c);
    }

    pub fn adopt_certificate(&mut self, c: Certificate, sessions: Vec<SessionCertificate>) {
        if !self.admit_sessions(c.checkpoint.index, sessions) {
            return;
        }
        self.on_certificate(c);
    }

    /// Admits the session certificates that come with a certificate. False,
    /// with the core halted, when the two ML-DSA-65 implementations disagree
    /// on one of them.
    fn admit_sessions(&mut self, index: u64, sessions: Vec<SessionCertificate>) -> bool {
        for s in sessions {
            if !self.ml_dsa.session_agrees(&self.committee, &s) {
                self.on_disagreement(index);
                return false;
            }
            let _ = self.sessions.admit(&self.committee, s);
        }
        true
    }

    /// Refuses an object the two ML-DSA-65 implementations disagree on and
    /// halts: this validator neither orders nor certifies anything more, so
    /// it cannot certify a history validators on another build refuse.
    fn on_disagreement(&mut self, index: u64) {
        tracing::error!(
            index,
            "ML-DSA-65 implementations disagree on a consensus signature; halting"
        );
        self.halted = true;
        self.events.push(Event::VerifierDisagreement { index });
    }

    /// The epoch's session certificates this validator holds: what anyone
    /// needs, besides the committee, to verify its certificates.
    pub fn sessions(&self) -> &SessionBook {
        &self.sessions
    }

    /// The committee.
    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    /// This validator's index.
    pub fn me(&self) -> ValidatorIndex {
        self.me
    }

    /// The round this validator last proposed in.
    pub fn round(&self) -> Option<Round> {
        self.round
    }

    /// Round of the last committed leader.
    pub fn last_committed_round(&self) -> Option<Round> {
        self.last_committed
    }

    /// Height the next ordered segment gets.
    pub fn next_height(&self) -> u64 {
        self.next_height
    }

    /// Where the next epoch starts once `handover`, this epoch's handover
    /// certificate, is formed. Its base blocks are the last executed blocks
    /// this core holds, which include the ones it started from: an epoch that
    /// ordered no block hands its own base on, so the next epoch's first
    /// checkpoint can still commit a state root.
    pub fn next_epoch_start(&self, handover: &Certificate) -> EpochStart {
        let keep = crate::checkpoint::STATE_ROOT_LAG as usize + 1;
        let executed: Vec<(u64, Digest, Digest)> = self
            .executed
            .range(..self.next_height)
            .rev()
            .take(keep)
            .map(|(h, (block, state, _))| (*h, *block, *state))
            .collect();
        EpochStart {
            // A validator that adopted the handover without ordering the
            // epoch's last blocks starts after them all the same.
            first_height: self.next_height.max(handover.checkpoint.last_height + 1),
            first_checkpoint: handover.checkpoint.index + 1,
            prev_checkpoint: handover.checkpoint.digest(),
            timestamp_ms: handover.checkpoint.timestamp_ms,
            base_blocks: executed.into_iter().rev().collect(),
            // The node replaces it with the governed value at the handover.
            leader_lookahead_rounds: self.schedule.lookahead(),
        }
    }

    /// The latest certificate.
    pub fn latest_certificate(&self) -> Option<&Certificate> {
        self.certificates.values().next_back()
    }

    /// A snapshot for monitoring.
    pub fn stats(&self) -> CoreStats {
        let mut d: Vec<u64> = self.round_durations_ms.iter().copied().collect();
        d.sort_unstable();
        let at = |q: f64| {
            if d.is_empty() {
                0
            } else {
                d[((d.len() - 1) as f64 * q).round() as usize]
            }
        };
        CoreStats {
            round: self.round,
            last_committed: self.last_committed,
            next_height: self.next_height,
            round_p50_ms: at(0.5),
            round_p99_ms: at(0.99),
            rounds_measured: d.len(),
            rbc: self.rbc.stats(),
            leaders_committed: self.leaders_committed,
            leaders_skipped: self.leaders_skipped,
            batches_pending: self.availability.pending_len(),
            diag_advance_refusal: self.diag_advance_refusal,
            diag_round_weight: (
                self.round.map_or(0, |r| self.round_weight(r)),
                self.committee.quorum(),
            ),
            diag_empty_batch_replies: self.diag_empty_batch_replies,
            diag_frontier_sent: self.diag_frontier_sent,
            diag_frontier_received: self.diag_frontier_received,
            diag_frontier_answered: self.diag_frontier_answered,
            diag_last_frontier_reply: self.diag_last_frontier_reply,
        }
    }

    /// Whether this committee has stopped ordering.
    pub fn is_halted(&self) -> bool {
        self.halted
    }

    /// How many of this validator's batches are not ordered yet: those no
    /// vertex of its introduced, and those introduced and not yet ordered.
    pub fn unordered_own_batches(&self) -> usize {
        self.own_unintroduced.len() + self.own_introduced.len()
    }

    /// Holds or releases this validator's frontier. While held it does not
    /// open a round of its own accord: it proposes only in rounds its peers
    /// already hold a quorum of, as a validator catching up does. One
    /// validator holding follows the others' pace and slows no one; once a
    /// quorum holds, rounds wait, so ordering cannot run ahead of the
    /// execution of a quorum. Liveness does not depend on it: execution goes
    /// on while the frontier is held, and the caller releases it as the
    /// executed height catches up.
    pub fn hold_frontier(&mut self, held: bool) {
        self.frontier_held = held;
    }

    /// Whether this validator's frontier is held.
    pub fn frontier_held(&self) -> bool {
        self.frontier_held
    }

    /// Whether `v` leads a slot of `round`.
    pub fn leads(&self, round: Round, v: ValidatorIndex) -> bool {
        self.schedule.leads(round, v)
    }

    /// The leader slots skipped since the last call, oldest first, as
    /// (round, leader); at most the latest [`SKIPPED_SLOTS_KEPT`].
    pub fn take_skipped(&mut self) -> Vec<(Round, ValidatorIndex)> {
        self.skipped_slots.drain(..).collect()
    }

    /// Takes the events produced since the last call.
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// Takes the messages produced since the last call.
    pub fn take_outbox(&mut self) -> Vec<(Target, Message)> {
        self.batch_reply_bytes.clear();
        let (now, cooldown) = (self.now_ms, self.batch_reply_cooldown_ms());
        self.batch_replied
            .retain(|_, at| now.saturating_sub(*at) < cooldown);
        std::mem::take(&mut self.outbox)
    }

    fn batch_reply_cooldown_ms(&self) -> u64 {
        self.cfg
            .fetch_retry_ms
            .saturating_mul(BATCH_REPLY_COOLDOWN_RETRIES)
    }

    fn send(&mut self, to: Target, m: Message) {
        self.outbox.push((to, m));
    }

    // ------------------------------------------------------------------
    // Inputs.
    // ------------------------------------------------------------------

    /// Starts the epoch. This validator's round-0 vertex goes out once it
    /// has a channel to a quorum of the committee, itself included (see
    /// [`Core::on_peer_up`]): a vertex sent to peers that are not connected
    /// yet would reach too few of them for any round to complete.
    pub fn start(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        self.started = true;
        self.connected
            .insert(self.me, self.committee.seats(self.me));
        if self.resuming.is_some() {
            self.ask_ordering(now_ms);
            return;
        }
        self.try_start(now_ms);
    }

    fn try_start(&mut self, now_ms: u64) {
        if self.started
            && self.resuming.is_none()
            && self.round.is_none()
            && self.connected.weight() >= self.committee.quorum()
        {
            self.propose(0, now_ms);
        }
    }

    /// A channel to `peer` came up. The peer is told where this validator
    /// stands, and answers with whatever of the rounds still in play this
    /// validator has not seen (see [`Message::Frontier`]); this validator
    /// does the same for the peer when the peer's frontier arrives. Nothing
    /// sent before the channel existed is waited on.
    pub fn on_peer_up(&mut self, peer: ValidatorIndex, now_ms: u64) {
        if peer == self.me || self.committee.member(peer).is_none() {
            return;
        }
        self.now_ms = now_ms;
        self.connected.insert(peer, self.committee.seats(peer));
        if let Some(r) = &self.resuming {
            let index = r.certificate.checkpoint.index;
            self.send(Target::One(peer), Message::FetchOrdering(index));
            return;
        }
        let f = self.frontier();
        self.send(Target::One(peer), Message::Frontier(f));
        self.try_start(now_ms);
    }

    /// Where this validator stands.
    ///
    /// Each author's entry is its highest vertex below the first of its
    /// instances this validator has heard of but not delivered. Instances
    /// deliver independently of each other, so an author's vertex can be
    /// held while one of its earlier ones is not; reporting the higher one
    /// would tell peers nothing below it is missing, and the signals that
    /// instance lacks would never be sent again.
    fn frontier(&self) -> Frontier {
        let top = self.dag.highest_round().unwrap_or(0);
        let floor = self.dag.floor();
        let holes = self.rbc.undelivered_from();
        let mut highest: Vec<VertexRef> = Vec::new();
        for source in 0..self.committee.size() as ValidatorIndex {
            let below = match holes.get(&source) {
                Some(&hole) if hole <= floor => continue,
                Some(&hole) => (hole - 1).min(top),
                None => top,
            };
            let found = (floor..=below).rev().find_map(|r| {
                self.dag.at(r, source).map(|(d, _)| VertexRef {
                    round: r,
                    source,
                    digest: *d,
                })
            });
            highest.extend(found);
        }
        Frontier {
            round: self.round,
            highest,
            next_checkpoint: self
                .certificates
                .keys()
                .next_back()
                .map_or(self.start.first_checkpoint, |i| i + 1),
        }
    }

    /// Re-sends `peer` what its frontier shows it lacks of the rounds still
    /// in play: this validator's own vertices it has not delivered, every
    /// reliable-broadcast signal this validator sent from the lowest round
    /// the peer is missing, this validator's votes for checkpoints the peer
    /// holds no certificate for, and the latest certificate if the peer is
    /// behind it. The same messages again, never different ones, so nothing
    /// this validator said changes.
    fn on_frontier(&mut self, peer: ValidatorIndex, f: Frontier) {
        let Some(current) = self.round else { return };
        self.diag_frontier_received += 1;
        // One answer per peer per fetch retry interval: an answer can be
        // far larger than the frontier that asks for it.
        let now = self.now_ms;
        if self
            .frontier_answered_ms
            .get(&peer)
            .is_some_and(|at| now.saturating_sub(*at) < self.cfg.fetch_retry_ms)
        {
            tracing::trace!(me = self.me, peer, "frontier: answered recently, skipped");
            return;
        }
        self.frontier_answered_ms.insert(peer, now);
        self.diag_frontier_answered += 1;
        let floor = self.dag.floor();
        let delivered_of = |source: ValidatorIndex| {
            f.highest
                .iter()
                .filter(|r| r.source == source)
                .map(|r| r.round)
                .max()
        };
        // The lowest round in which the peer may lack a vertex of some
        // author: one past the highest it delivered, or the round it is in.
        let mut low = f.round.unwrap_or(0);
        for source in 0..self.committee.size() as ValidatorIndex {
            low = low.min(delivered_of(source).map_or(0, |r| r.saturating_add(1)));
        }
        let low = low.max(floor);
        if low > current {
            return;
        }
        let mine_from = delivered_of(self.me)
            .map_or(0, |r| r.saturating_add(1))
            .max(floor);
        let mut vertices_sent = 0usize;
        for r in mine_from..=current {
            let own = self.dag.at(r, self.me).map(|(_, v)| v.clone()).or_else(|| {
                self.bodies
                    .values()
                    .find(|v| v.source == self.me && v.round == r)
                    .cloned()
            });
            if let Some(v) = own {
                vertices_sent += 1;
                self.send(Target::One(peer), Message::Propose(v));
            }
        }
        let signals = self.rbc.sent_signals(low);
        self.diag_last_frontier_reply = (vertices_sent, signals.len());
        tracing::debug!(
            me = self.me,
            peer,
            peer_round = ?f.round,
            low,
            mine_from,
            vertices_sent,
            signals = ?signals
                .iter()
                .map(|s| (s.round, s.source, s.kind as u8))
                .collect::<Vec<_>>(),
            "frontier: answered"
        );
        for chunk in signals.chunks(MAX_SIGNALS_PER_FRAME) {
            self.send(Target::One(peer), Message::Signals(chunk.to_vec()));
        }
        let votes: Vec<CheckpointVote> = self
            .own_votes
            .range(f.next_checkpoint..)
            .map(|(_, v)| v.clone())
            .collect();
        for v in votes {
            self.send(Target::One(peer), Message::Vote(v));
        }
        if let Some((&index, c)) = self.certificates.iter().next_back()
            && index >= f.next_checkpoint
        {
            let c = Box::new(c.clone());
            self.send(Target::One(peer), Message::Certificate(c));
        }
    }

    /// Asks every peer for what this validator's round lacks once the round
    /// has not advanced for a while: a message lost while a channel was
    /// being replaced is repaired rather than waited on.
    fn repair_stall(&mut self, now_ms: u64) {
        if self.halted || self.round.is_none() {
            return;
        }
        let after = self.stall_after_ms();
        if now_ms < self.round_entered_ms.saturating_add(after)
            || now_ms < self.last_repair_ms.saturating_add(after)
        {
            return;
        }
        self.last_repair_ms = now_ms;
        self.diag_frontier_sent += 1;
        let f = self.frontier();
        tracing::debug!(
            me = self.me,
            round = ?self.round,
            highest = ?f
                .highest
                .iter()
                .map(|r| (r.round, r.source))
                .collect::<Vec<_>>(),
            "stall: frontier sent to every peer"
        );
        self.send(Target::All, Message::Frontier(f));
    }

    /// Whether nothing waits to be ordered: no batch of this validator's or
    /// another's is unreleased, no ordered segment waits, and a leader has
    /// committed since the last round that introduced or carried a batch.
    pub fn is_idle(&self) -> bool {
        self.own_unintroduced.is_empty()
            && self.own_introduced.is_empty()
            && self.carry_pool.is_empty()
            && self.waiting.is_empty()
            && self
                .last_payload_round
                .is_none_or(|r| self.last_committed.is_some_and(|c| c > r + 1))
    }

    /// How far this validator's frontier may run ahead of its last commit.
    fn max_uncommitted_rounds(&self) -> Round {
        self.cfg
            .gc_depth
            .max(MIN_UNCOMMITTED_ROUNDS)
            .saturating_mul(2)
    }

    /// Bytes this core holds in batches and vertices, roughly: what its
    /// caller counts against the node's memory.
    pub fn buffered_bytes(&self) -> usize {
        let payloads: usize = self.payloads.values().map(|p| p.body.len() + 64).sum();
        let top = self.dag.highest_round().unwrap_or(0);
        let vertices: usize = (self.dag.floor()..=top)
            .map(|r| self.dag.round(r).count())
            .sum::<usize>()
            + self.bodies.len()
            + self.unechoed.len();
        payloads + vertices * VERTEX_BYTES_ESTIMATE
    }

    /// How long a round may stand still before this validator asks its
    /// peers to repair it.
    fn stall_after_ms(&self) -> u64 {
        let pace = if self.is_idle() {
            self.cfg.idle_round_interval_ms
        } else {
            self.cfg.min_round_interval_ms
        };
        self.cfg
            .leader_timeout_ms
            .max(self.cfg.fetch_retry_ms)
            .max(pace)
            .saturating_mul(2)
    }

    /// Hands over a part of this validator's mempool. It is sealed into the
    /// next batch of this validator's chain at once, pushed to every
    /// validator and introduced in this validator's next vertex. A part that
    /// cannot be sealed (too large, or this core has halted) comes straight
    /// back as [`Event::Unordered`].
    pub fn submit_part(&mut self, part: BatchPart) {
        let transactions = part.transactions as usize;
        let payload = BatchPayload::seal(
            self.committee.epoch,
            self.me,
            self.next_batch_sequence,
            &[part],
        );
        if self.halted
            || payload.body.len() > MAX_BATCH_BYTES
            || transactions > tenzro_types::block::MAX_TRANSACTIONS_PER_BLOCK
        {
            self.events.push(Event::Unordered(payload));
            return;
        }
        self.next_batch_sequence += 1;
        let r = payload.reference();
        self.payload_round.insert(r.digest, self.round.unwrap_or(0));
        self.payloads.insert(r.digest, payload.clone());
        self.journal.push(Record::Batch(payload.clone()));
        self.own_unintroduced.push(r);
        self.send(Target::All, Message::Batch(payload));
    }

    /// Echoes every held-back proposal whose batches this validator now
    /// holds.
    fn echo_held(&mut self) {
        let ready: Vec<((Round, ValidatorIndex), bool)> = self
            .unechoed
            .iter()
            .filter_map(|(k, v)| self.holds_batches_of(v).map(|ok| (*k, ok)))
            .collect();
        for (k, ok) in ready {
            let v = self.unechoed.remove(&k).expect("listed");
            if ok {
                self.echo(v);
            }
        }
    }

    /// Whether this validator holds every batch `v` introduces or carries:
    /// None while one is missing, otherwise whether each held payload is
    /// the batch it is named as (author, sequence, size and count). A
    /// vertex naming a batch as something it is not is never echoed.
    fn holds_batches_of(&self, v: &Vertex) -> Option<bool> {
        let named = v
            .batches
            .iter()
            .map(|b| (v.source, b))
            .chain(v.carried.iter().map(|c| (c.author, &c.batch)));
        let mut ok = true;
        for (author, b) in named {
            let p = self.payloads.get(&b.digest)?;
            ok &= p.author == author
                && p.sequence == b.sequence
                && p.transactions == b.transactions
                && p.body.len() == b.bytes as usize;
        }
        Some(ok)
    }

    /// Echoes `v`, a proposal whose batches this validator holds.
    fn echo(&mut self, v: Vertex) {
        let d = v.digest();
        let acts = self
            .rbc
            .on_propose(&self.committee, v.source, v.round, v.source, d);
        if !acts.is_empty() && !self.dag.contains(&d) {
            self.bodies.insert(d, v);
        }
        self.apply_rbc(acts);
    }

    /// Handles every message of one frame from `from`.
    pub fn on_messages(&mut self, from: ValidatorIndex, messages: Vec<Message>, now_ms: u64) {
        if from == self.me || self.committee.member(from).is_none() {
            return;
        }
        self.now_ms = now_ms;
        if self.resuming.is_some() {
            // Nothing of the epoch's traffic counts until the state arrives;
            // what this core then lacks it asks for.
            for m in messages {
                if let Message::Ordering(state) = m {
                    self.on_ordering(*state);
                }
            }
            return;
        }
        // Requests answer in proportion to the frame they came in, not to
        // how often it repeats them: a few fetches, one frontier and one
        // ordering state per frame. A peer that needs more asks again.
        self.frame_fetches = 0;
        self.frame_answered_frontier = false;
        self.frame_answered_ordering = false;
        for m in messages {
            self.on_message(from, m);
        }
        self.echo_held();
        self.progress(now_ms);
    }

    fn on_message(&mut self, from: ValidatorIndex, m: Message) {
        match m {
            Message::Propose(v) => self.on_propose(from, v),
            Message::Signals(signals) => {
                // The same horizon as proposals: an instance is opened only
                // for a round this validator would accept a proposal for.
                let horizon = self.round.unwrap_or(0) + self.cfg.max_rounds_ahead;
                for s in signals {
                    if s.round > horizon {
                        tracing::debug!(
                            me = self.me,
                            from,
                            round = s.round,
                            source = s.source,
                            horizon,
                            "rbc: signal beyond the horizon ignored"
                        );
                        continue;
                    }
                    let acts = self.rbc.on_signal(&self.committee, from, s);
                    self.apply_rbc(acts);
                }
            }
            Message::Batch(p) => self.on_batch(from, p),
            Message::FetchVertices(ds) => {
                if self.frame_fetches >= MAX_FETCHES_PER_FRAME {
                    return;
                }
                self.frame_fetches += 1;
                let found: Vec<Vertex> = ds
                    .iter()
                    .take(MAX_FETCH)
                    .filter_map(|d| {
                        self.dag
                            .get(d)
                            .or_else(|| self.bodies.get(d))
                            .or_else(|| self.history.get(d))
                            .cloned()
                    })
                    .collect();
                if !found.is_empty() {
                    self.send(Target::One(from), Message::Vertices(found));
                }
            }
            Message::Vertices(vs) => {
                for v in vs {
                    let d = v.digest();
                    if v.check_structure(&self.committee).is_err() {
                        continue;
                    }
                    if self.dag.is_expected(&d) {
                        self.wanted_vertices.remove(&d);
                        self.offer(v);
                    } else if self.wanted_vertices.remove(&d).is_some() && !self.dag.contains(&d) {
                        // A parent this validator has not delivered yet: the
                        // DAG holds it until it is delivered or accepted
                        // vertices of authors holding f + 1 seats reach it.
                        let (inserted, missing) = self.dag.hold(v);
                        self.after_offer(inserted, missing);
                    }
                }
            }
            Message::FetchBatches(ds) => {
                if self.frame_fetches >= MAX_FETCHES_PER_FRAME {
                    return;
                }
                self.frame_fetches += 1;
                self.answer_batch_fetch(from, &ds);
            }
            Message::Batches(ps) => {
                for p in ps {
                    let d = p.digest();
                    if p.epoch == self.committee.epoch
                        && self.wanted_batches.remove(&d).is_some()
                        && p.body.len() <= MAX_BATCH_BYTES
                    {
                        self.payload_round.insert(d, self.round.unwrap_or(0));
                        self.payloads.insert(d, p);
                    }
                }
            }
            Message::Vote(v) => self.on_vote(v),
            Message::Certificate(c) => self.on_certificate(*c),
            Message::Frontier(f) => {
                if !std::mem::replace(&mut self.frame_answered_frontier, true) {
                    self.on_frontier(from, f);
                }
            }
            Message::FetchOrdering(index) => {
                if std::mem::replace(&mut self.frame_answered_ordering, true) {
                    return;
                }
                if let Some(state) = self.ordering_states.get(&index) {
                    let state = Box::new(state.clone());
                    self.send(Target::One(from), Message::Ordering(state));
                }
            }
            Message::Ordering(_) => {}
        }
    }

    /// Advances timers: the wait for a round's missing leader vertices and
    /// fetch retries.
    pub fn on_tick(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        if self.resuming.is_some() {
            self.ask_ordering(now_ms);
            return;
        }
        self.retry_fetches(now_ms);
        self.progress(now_ms);
        self.repair_stall(now_ms);
    }

    /// Reports that the block at `height` was built and executed:
    /// its hash, its post-state root, and the statements its execution
    /// attested.
    pub fn on_executed(
        &mut self,
        height: u64,
        block_hash: Digest,
        post_state_root: Digest,
        statements: Vec<Digest>,
    ) {
        self.executed
            .insert(height, (block_hash, post_state_root, statements));
        self.build_checkpoints();
    }

    /// Supplies the next committee's root for the checkpoint ending the
    /// epoch.
    pub fn set_next_committee_root(&mut self, root: Digest) {
        self.next_committee_root = Some(root);
        self.build_checkpoints();
    }

    /// Hands back this validator's signed vote for a checkpoint.
    pub fn on_own_vote(&mut self, vote: CheckpointVote) {
        // A signature that finished after the epoch handed over is for a
        // committee that no longer runs.
        if vote.checkpoint.epoch != self.committee.epoch {
            return;
        }
        if !self.certificates.contains_key(&vote.checkpoint.index) {
            self.own_votes.insert(vote.checkpoint.index, vote.clone());
        }
        self.send(Target::All, Message::Vote(vote.clone()));
        self.count_vote(vote);
    }

    // ------------------------------------------------------------------
    // Reliable broadcast and the DAG.
    // ------------------------------------------------------------------

    /// Sends `from` the batches it asked for that this validator holds,
    /// each at most once per cooldown and within the peer's byte budget for
    /// this pass. A batch held back is sent when the peer asks again.
    fn answer_batch_fetch(&mut self, from: ValidatorIndex, ds: &[Digest]) {
        let now = self.now_ms;
        let cooldown = self.batch_reply_cooldown_ms();
        let used = self.batch_reply_bytes.get(&from).copied().unwrap_or(0);
        let mut budget = MAX_BATCH_REPLY_BYTES.saturating_sub(used);
        let (mut held, mut recent, mut over) = (0usize, 0usize, 0usize);
        let mut found: Vec<BatchPayload> = Vec::new();
        for d in ds.iter().take(MAX_FETCH) {
            let Some(p) = self.payloads.get(d) else {
                continue;
            };
            held += 1;
            if self
                .batch_replied
                .get(&(from, *d))
                .is_some_and(|at| now.saturating_sub(*at) < cooldown)
            {
                recent += 1;
                continue;
            }
            let len = p.body.len().max(1);
            if len > budget {
                over += 1;
                continue;
            }
            budget -= len;
            found.push(p.clone());
            self.batch_replied.insert((from, *d), now);
        }
        let bytes = MAX_BATCH_REPLY_BYTES.saturating_sub(used) - budget;
        tracing::debug!(
            me = self.me,
            from,
            asked = ds.len(),
            held,
            sent = found.len(),
            recent,
            over,
            bytes,
            "fetch: batches asked"
        );
        if held == 0 {
            self.diag_empty_batch_replies += 1;
        }
        if found.is_empty() {
            return;
        }
        *self.batch_reply_bytes.entry(from).or_default() += bytes;
        self.send(Target::One(from), Message::Batches(found));
    }

    fn on_propose(&mut self, from: ValidatorIndex, v: Vertex) {
        if from != v.source || v.check_structure(&self.committee).is_err() {
            return;
        }
        let horizon = self.round.unwrap_or(0) + self.cfg.max_rounds_ahead;
        if v.round < self.dag.floor() || v.round > horizon {
            tracing::debug!(
                me = self.me,
                round = v.round,
                source = v.source,
                horizon,
                "rbc: proposal outside the rounds in play ignored"
            );
            return;
        }
        // Only the author's first proposal for a slot counts.
        let slot = (v.round, v.source);
        if self.rbc.proposed(v.round, v.source).is_some() || self.unechoed.contains_key(&slot) {
            tracing::trace!(
                me = self.me,
                round = v.round,
                source = v.source,
                "rbc: proposal already taken"
            );
            return;
        }
        self.first_proposals
            .entry(v.round)
            .or_default()
            .insert(v.source, v.strong.clone());
        // Echoing a vertex vouches for its batches: a validator echoes only
        // once it holds every batch the vertex introduces. The author pushed
        // them before the vertex, so they are normally here already; any
        // missing is asked of the author at once, and of others after. A
        // leader's carried batches are asked of the leader, which holds
        // them.
        let missing: Vec<Digest> = v
            .batches
            .iter()
            .chain(v.carried.iter().map(|c| &c.batch))
            .map(|b| b.digest)
            .filter(|d| !self.payloads.contains_key(d))
            .collect();
        if missing.is_empty() {
            if self.holds_batches_of(&v) == Some(true) {
                self.echo(v);
            } else {
                tracing::debug!(
                    me = self.me,
                    round = v.round,
                    source = v.source,
                    "rbc: proposal names batches as what they are not; not echoed"
                );
            }
            return;
        }
        tracing::debug!(
            me = self.me,
            round = v.round,
            source = v.source,
            missing = missing.len(),
            "rbc: proposal held until its batches arrive"
        );
        for d in &missing {
            let w = self.wanted_batches.entry(*d).or_insert(Wanted {
                asked_ms: self.now_ms,
                attempts: 1,
                holder: Some(v.source),
                round: v.round,
            });
            w.round = w.round.max(v.round);
        }
        for chunk in missing.chunks(MAX_FETCH) {
            self.send(Target::One(v.source), Message::FetchBatches(chunk.to_vec()));
        }
        self.unechoed.insert(slot, v);
    }

    fn apply_rbc(&mut self, acts: Vec<RbcAction>) {
        let mut signals: Vec<Signal> = Vec::new();
        for a in acts {
            match a {
                RbcAction::Broadcast(s) => {
                    self.journal.push(Record::Signal(s));
                    signals.push(s);
                }
                RbcAction::Deliver {
                    digest,
                    round,
                    source,
                } => {
                    self.dag.expect(digest, round);
                    // Delivered on others' echoes before this validator held
                    // the batches: the body is the held-back proposal.
                    if let Some(v) = self
                        .unechoed
                        .get(&(round, source))
                        .filter(|v| v.digest() == digest)
                        .cloned()
                    {
                        self.bodies.insert(digest, v);
                    }
                    match self.bodies.get(&digest).cloned() {
                        Some(v) => self.offer(v),
                        None => {
                            self.wanted_vertices.entry(digest).or_default();
                        }
                    }
                }
            }
        }
        if !signals.is_empty() {
            self.send(Target::All, Message::Signals(signals));
        }
    }

    fn offer(&mut self, v: Vertex) {
        let (inserted, missing) = self.dag.offer(v);
        self.after_offer(inserted, missing);
    }

    /// Records the vertices that entered the DAG and fetches the missing
    /// digests.
    fn after_offer(&mut self, inserted: Vec<VertexRef>, missing: Vec<Digest>) {
        for r in &inserted {
            self.wanted_vertices.remove(&r.digest);
            self.bodies.remove(&r.digest);
            if let Some(v) = self.dag.get(&r.digest) {
                if !v.batches.is_empty() || !v.carried.is_empty() {
                    self.last_payload_round = self.last_payload_round.max(Some(v.round));
                }
                self.journal.push(Record::Delivered(v.clone()));
                for b in &v.batches {
                    self.carry_pool.remove(&(v.source, b.sequence));
                }
                for b in v.batches.iter().chain(v.carried.iter().map(|c| &c.batch)) {
                    if !self.payloads.contains_key(&b.digest) && v.source != self.me {
                        let w = self.wanted_batches.entry(b.digest).or_insert(Wanted {
                            holder: Some(v.source),
                            round: v.round,
                            ..Wanted::default()
                        });
                        w.round = w.round.max(v.round);
                    }
                }
            }
        }
        for d in missing {
            self.wanted_vertices.entry(d).or_default();
        }
    }

    fn on_batch(&mut self, from: ValidatorIndex, p: BatchPayload) {
        if p.author != from
            || p.epoch != self.committee.epoch
            || p.body.len() > MAX_BATCH_BYTES
            || self.halted
        {
            return;
        }
        let d = p.digest();
        if self.payloads.contains_key(&d) {
            return;
        }
        // An author's batches are held from its released point up to
        // MAX_AHEAD_PER_AUTHOR beyond it, whether or not anything commits:
        // an author pushing batches while the committee is stalled cannot
        // grow this validator's memory. A batch outside that window that a
        // vertex later names is fetched then.
        // Nor can it by sending a second batch under a sequence it already
        // used.
        let base = self.availability.released_through(p.author);
        let wanted = self.wanted_batches.contains_key(&d);
        if p.sequence >= base + MAX_AHEAD_PER_AUTHOR as u64
            || (!wanted
                && (p.sequence < base || self.carry_pool.contains_key(&(p.author, p.sequence))))
        {
            return;
        }
        self.wanted_batches.remove(&d);
        self.payload_round.insert(d, self.round.unwrap_or(0));
        if p.sequence >= base {
            self.carry_pool
                .insert((p.author, p.sequence), p.reference());
        }
        self.payloads.insert(d, p);
    }

    fn retry_fetches(&mut self, now_ms: u64) {
        let n = self.committee.size() as u32;
        if n < 2 {
            return;
        }
        let retry = self.cfg.fetch_retry_ms;
        let me = self.me as u32;
        let pick = |attempts: u32, d: &Digest| -> ValidatorIndex {
            let base = u32::from(d[0]) + u32::from(d[1]) * 256 + attempts;
            let mut i = base % (n - 1);
            if i >= me {
                i += 1;
            }
            i as ValidatorIndex
        };
        let mut by_peer: HashMap<ValidatorIndex, (Vec<Digest>, Vec<Digest>)> = HashMap::new();
        // Vertices of the rounds being decided are pulled at once and on
        // every retry; older history a validator catching up needs is pulled
        // at most MAX_BULK_FETCH at a time, so catching up never crowds out
        // the traffic the current round waits on.
        let live_from = self.round.unwrap_or(0).saturating_sub(LIVE_ROUNDS);
        let dag = &self.dag;
        let mut bulk = 0usize;
        for (d, w) in self.wanted_vertices.iter_mut() {
            if w.attempts == 0 || now_ms.saturating_sub(w.asked_ms) >= retry {
                if dag.expected_round(d).is_some_and(|r| r < live_from) {
                    if bulk == MAX_BULK_FETCH {
                        continue;
                    }
                    bulk += 1;
                }
                let p = pick(w.attempts, d);
                w.attempts += 1;
                w.asked_ms = now_ms;
                by_peer.entry(p).or_default().0.push(*d);
            }
        }
        for (d, w) in self.wanted_batches.iter_mut() {
            if w.attempts == 0 || now_ms.saturating_sub(w.asked_ms) >= retry {
                // The author serves its own batches, including after a
                // restart (they are in its journal); others are tried in
                // between in case it is down. Those in-between attempts walk
                // the other peers on their own count: drawn from the odd
                // attempt numbers alone, a committee with an even number of
                // other peers would only ever be asked half of them, and a
                // batch held only by the other half would never arrive while
                // its author stays down.
                let p = match w.holder {
                    Some(h) if u32::from(h) != me => {
                        if w.attempts % 2 == 0 {
                            h
                        } else {
                            pick(w.attempts / 2, d)
                        }
                    }
                    _ => pick(w.attempts, d),
                };
                w.attempts += 1;
                w.asked_ms = now_ms;
                by_peer.entry(p).or_default().1.push(*d);
            }
        }
        for (p, (vs, bs)) in by_peer {
            for chunk in vs.chunks(MAX_FETCH) {
                self.send(Target::One(p), Message::FetchVertices(chunk.to_vec()));
            }
            for chunk in bs.chunks(MAX_FETCH) {
                self.send(Target::One(p), Message::FetchBatches(chunk.to_vec()));
            }
        }
    }

    // ------------------------------------------------------------------
    // Rounds.
    // ------------------------------------------------------------------

    fn progress(&mut self, now_ms: u64) {
        self.try_commit();
        self.try_advance(now_ms);
        self.release_segments();
    }

    fn round_weight(&self, r: Round) -> u64 {
        self.dag
            .round(r)
            .map(|(s, ..)| self.committee.seats(s))
            .sum()
    }

    /// Proposes the rounds the DAG allows. A core whose ordering closed the
    /// epoch keeps proposing empty vertices until the handover is certified:
    /// a peer that has not ordered as far yet may still need its next-round
    /// vertex to reach the same decisions, and a core that stopped at the
    /// close would leave that peer short of a quorum for good.
    fn try_advance(&mut self, now_ms: u64) {
        loop {
            let Some(current) = self.round else { return };
            // A validator that fell behind jumps to the highest round the
            // DAG already holds a quorum of, rather than proposing every
            // round it missed; failing that it advances from its own round.
            // `top` never drops below the current round: the DAG's highest
            // round lags this validator's own proposal until that proposal
            // is delivered, and entering after a round below `current` would
            // propose a round this validator already proposed, a second
            // vertex for one (round, author) slot.
            let mut top = self.dag.highest_round().map_or(current, |h| h.max(current));
            while top > current && self.round_weight(top) < self.committee.quorum() {
                top -= 1;
            }
            // Jumping ahead to the DAG's top is catch-up and is not paced;
            // entering the round after this validator's own is frontier
            // work and is. A validator that leads a slot of the top round
            // proposes in it first: its peers have not left it yet, and
            // jumping past it would leave its own leader vertex out, its slot
            // skipped though it is up and honest.
            let entered = if top > current {
                (self.schedule.leads(top, self.me) && self.enter_after(top - 1, now_ms, false))
                    || self.enter_after(top, now_ms, false)
                    || self.enter_after(current, now_ms, true)
            } else {
                self.enter_after(current, now_ms, true)
            };
            if !entered {
                return;
            }
        }
    }

    /// Proposes the round after `r` if the DAG allows it now.
    ///
    /// `paced` throttles the frontier: a validator at the head of the DAG
    /// waits out the minimum round interval, so a committee whose members
    /// deliver each other's vertices instantly (a single validator, or a
    /// LAN) does not spin through rounds. Catching up is never paced, or a
    /// validator that fell behind would advance one round per interval
    /// while its peers ran ahead and would never rejoin them.
    fn enter_after(&mut self, r: Round, now_ms: u64, paced: bool) -> bool {
        // An honest validator proposes each round at most once.
        if self.round.is_some_and(|current| r < current) {
            self.diag_advance_refusal = "already-past";
            return false;
        }
        // With nothing to order the frontier moves at the idle heartbeat;
        // a batch reaching this validator, or a vertex introducing one,
        // returns it to full pace at once.
        let interval = if self.halted || self.is_idle() {
            self.cfg.idle_round_interval_ms
        } else {
            self.cfg.min_round_interval_ms
        };
        if paced && (self.frontier_held || now_ms < self.round_entered_ms.saturating_add(interval))
        {
            self.diag_advance_refusal = if self.frontier_held {
                "frontier-held"
            } else {
                "paced-interval"
            };
            return false;
        }
        // Nothing is collected above the last committed round, so a
        // committee that keeps proposing while nothing commits would hold
        // every round it adds. Its frontier stops this far ahead instead,
        // and moves on with the next commit.
        let committed = self.last_committed.unwrap_or(0);
        if paced && r + 1 > committed.saturating_add(self.max_uncommitted_rounds()) {
            self.diag_advance_refusal = "uncommitted-rounds-cap";
            return false;
        }
        if self.round_weight(r) < self.committee.quorum() {
            self.diag_advance_refusal = "round-weight-below-quorum";
            return false;
        }
        // With every leader vertex of the round held, the next round starts
        // at once; a missing one is waited for until the leader timeout. The
        // leaders are this validator's to judge only once no undecided slot
        // can still redraw them: otherwise its schedule may be stale, and
        // leaving early on it can strand the vertex of a leader it does not
        // know of yet. Holding every vertex of the round needs no schedule.
        let leaders_held = if leaders_settled(r, self.next_slot.0, self.schedule.lookahead()) {
            (0..self.schedule.slots()).all(|k| self.dag.at(r, self.schedule.leader(r, k)).is_some())
        } else {
            self.dag.round(r).count() == self.committee.size()
        };
        // A jump over a round this validator leads never leaves on the
        // timeout: the missing leader vertex is its own, which it cannot
        // hold before proposing it, so it would skip its own slot. It
        // proposes the rounds it is behind on instead, as the
        // specification's catch-up, which jumps only with the leaders held.
        let own_slot_missing = !paced
            && self.dag.at(r, self.me).is_none()
            && (0..self.schedule.slots()).any(|k| self.schedule.leader(r, k) == self.me);
        let waited = !own_slot_missing
            && now_ms
                >= self
                    .round_entered_ms
                    .saturating_add(self.cfg.leader_timeout_ms);
        if !leaders_held && !waited {
            self.diag_advance_refusal = if own_slot_missing {
                "own-slot-missing"
            } else {
                "leaders-not-held"
            };
            return false;
        }
        self.diag_advance_refusal = "none";
        self.propose(r + 1, now_ms);
        true
    }

    fn propose(&mut self, round: Round, now_ms: u64) {
        let strong: Vec<VertexRef> = if round == 0 {
            Vec::new()
        } else {
            let mut s: Vec<VertexRef> = self
                .dag
                .round(round - 1)
                .map(|(src, d, _)| VertexRef {
                    round: round - 1,
                    source: src,
                    digest: *d,
                })
                .collect();
            s.sort();
            s
        };
        let weak = if round >= 2 {
            let roots: Vec<Digest> = strong.iter().map(|r| r.digest).collect();
            let ordered = &self.ordered;
            self.dag.orphans_below(
                round - 1,
                &roots,
                |d| ordered.contains_key(d),
                self.cfg.max_weak_refs,
            )
        } else {
            Vec::new()
        };
        // After the close nothing more is ordered in this epoch: a vertex
        // introduces and carries no batch, and the batches still held go
        // back to the mempool with the handover.
        let batches: Vec<BatchRef> = if self.halted {
            Vec::new()
        } else {
            std::mem::take(&mut self.own_unintroduced)
        };
        for b in &batches {
            self.own_introduced.insert(b.digest, round);
        }
        // A leader of the round carries what it holds of other authors'
        // batches that its references do not introduce: ordered with this
        // vertex when its slot commits, a round before their authors'
        // vertices would be.
        let mut carried = Vec::new();
        if !self.halted && self.schedule.leads(round, self.me) {
            while carried.len() < MAX_CARRIED {
                let Some(((author, _), batch)) = self.carry_pool.pop_first() else {
                    break;
                };
                carried.push(CarriedBatch { author, batch });
            }
        }
        let v = Vertex {
            epoch: self.committee.epoch,
            round,
            source: self.me,
            strong,
            weak,
            batches,
            carried,
            timestamp_ms: now_ms.max(self.last_timestamp_ms),
        };
        if self.round.is_some() {
            if self.round_durations_ms.len() == ROUND_WINDOW {
                self.round_durations_ms.pop_front();
            }
            self.round_durations_ms
                .push_back(now_ms.saturating_sub(self.round_entered_ms));
        }
        self.round = Some(round);
        self.round_entered_ms = now_ms;
        let d = v.digest();
        self.first_proposals
            .entry(round)
            .or_default()
            .insert(self.me, v.strong.clone());
        self.bodies.insert(d, v.clone());
        self.journal.push(Record::Own(v.clone()));
        self.send(Target::All, Message::Propose(v));
        let acts = self
            .rbc
            .on_propose(&self.committee, self.me, round, self.me, d);
        self.apply_rbc(acts);
    }

    // ------------------------------------------------------------------
    // Commit rule and ordering.
    // ------------------------------------------------------------------

    /// The vertex of leader slot `(round, k)`, if delivered.
    fn slot_vertex(&self, (round, k): Slot) -> Option<VertexRef> {
        let leader = self.schedule.leader(round, k);
        self.dag.at(round, leader).map(|(d, _)| VertexRef {
            round,
            source: leader,
            digest: *d,
        })
    }

    /// The direct decision of a slot, from the next round's vertices.
    ///
    /// Support counts each author's delivered next-round vertex or, before it
    /// is delivered, its first proposal: a quorum of it holds at least
    /// `f + 1` honest supporters, whose vertices every vertex two or more
    /// rounds later reaches through strong references. Blame counts
    /// delivered vertices only and skips the slot once it covers every seat,
    /// when no vertex can reach the slot's vertex.
    fn direct(&self, slot: Slot) -> Decision {
        let (round, k) = slot;
        let leader = self.schedule.leader(round, k);
        let (mut support, mut blame) = (0u64, 0u64);
        let mut delivered: HashSet<ValidatorIndex> = HashSet::new();
        for (s, _, v) in self.dag.round(round + 1) {
            delivered.insert(s);
            if v.references_author(leader) {
                support += self.committee.seats(s);
            } else {
                blame += self.committee.seats(s);
            }
        }
        if let Some(props) = self.first_proposals.get(&(round + 1)) {
            for (s, refs) in props {
                if !delivered.contains(s)
                    && refs.iter().any(|r| r.round == round && r.source == leader)
                {
                    support += self.committee.seats(*s);
                }
            }
        }
        if support >= self.committee.quorum() {
            // Honest supporters reference a delivered vertex, which reaches
            // this validator too; until it does the slot waits.
            return self
                .slot_vertex(slot)
                .map_or(Decision::Undecided, Decision::Commit);
        }
        if blame >= self.committee.total_seats() {
            return Decision::Skip;
        }
        Decision::Undecided
    }

    /// The indirect decision of a slot: the first slot at least two rounds
    /// later that is not skipped anchors it. A committed anchor commits the
    /// slot exactly when its vertex reaches the slot's through strong
    /// references; an undecided one leaves the slot undecided.
    fn indirect(&self, slot: Slot, later: &BTreeMap<Slot, Decision>) -> Decision {
        for d in later.range((slot.0 + 2, 0)..).map(|(_, d)| d) {
            match d {
                Decision::Skip => continue,
                Decision::Undecided => return Decision::Undecided,
                Decision::Commit(anchor) => {
                    return match self.slot_vertex(slot) {
                        Some(l) if self.dag.strong_path(&anchor.digest, &l) => Decision::Commit(l),
                        _ => Decision::Skip,
                    };
                }
            }
        }
        Decision::Undecided
    }

    /// Decisions of the slots from the first undecided one up to the last
    /// round with a next round to decide by, in slot order. Slots are decided
    /// from the highest down, so a slot's anchor may itself be decided
    /// indirectly.
    fn decide_slots(&self) -> BTreeMap<Slot, Decision> {
        let mut out = BTreeMap::new();
        let top = self
            .dag
            .highest_round()
            .max(self.first_proposals.keys().next_back().copied());
        let Some(hi) = top.and_then(|t| t.checked_sub(1)) else {
            return out;
        };
        let lo = self.next_slot.0;
        if hi < lo {
            return out;
        }
        for r in (lo..=hi).rev() {
            for k in (0..self.schedule.slots()).rev() {
                let slot = (r, k);
                if slot < self.next_slot {
                    continue;
                }
                let d = match self.direct(slot) {
                    Decision::Undecided => self.indirect(slot, &out),
                    d => d,
                };
                out.insert(slot, d);
            }
        }
        out
    }

    /// Commits or skips the decided slots in order, up to the first
    /// undecided one.
    fn try_commit(&mut self) {
        'decide: while !self.halted {
            for (slot, d) in self.decide_slots() {
                let anchor = match d {
                    Decision::Undecided => return,
                    Decision::Skip => None,
                    Decision::Commit(a) => Some(a),
                };
                #[cfg(test)]
                self.decided_slots.push((slot, anchor));
                let slots = self.schedule.slots();
                self.next_slot = if slot.1 + 1 == slots {
                    (slot.0 + 1, 0)
                } else {
                    (slot.0, slot.1 + 1)
                };
                let Some(anchor) = anchor else {
                    let leader = self.schedule.leader(slot.0, slot.1);
                    self.schedule.record_outcome(leader, false);
                    self.leaders_skipped += 1;
                    if self.skipped_slots.len() == SKIPPED_SLOTS_KEPT {
                        self.skipped_slots.pop_front();
                    }
                    self.skipped_slots.push_back((slot.0, leader));
                    continue;
                };
                let checkpoint = self.next_checkpoint_index;
                self.commit(anchor);
                // A checkpoint may redraw later rounds' leaders: the
                // remaining slots are decided again under the new schedule.
                if self.next_checkpoint_index != checkpoint || self.halted {
                    continue 'decide;
                }
            }
            return;
        }
    }

    fn commit(&mut self, anchor: VertexRef) {
        self.schedule.record_outcome(anchor.source, true);
        self.leaders_committed += 1;
        self.last_committed = Some(anchor.round);

        let ordered = &self.ordered;
        let history = self
            .dag
            .causal_history(&anchor.digest, |d| ordered.contains_key(d));
        #[cfg(test)]
        self.released.extend(history.iter().copied());
        for r in &history {
            self.ordered.insert(r.digest, r.round);
            let v = self.dag.get(&r.digest).expect("in the DAG").clone();
            self.availability.on_ordered(&v);
        }
        self.availability
            .on_carried(self.dag.get(&anchor.digest).expect("in the DAG"));
        self.availability.expire_gaps(self.dag.floor());
        let released = self.availability.release();
        let availability = &self.availability;
        self.carry_pool
            .retain(|(a, s), _| *s >= availability.released_through(*a));
        // This validator's batches a leader carried are not introduced again.
        let own_through = self.availability.released_through(self.me);
        self.own_unintroduced.retain(|b| b.sequence >= own_through);
        let already_executed = self.next_height <= self.executed_through;
        for b in &released {
            if b.author == self.me {
                self.own_introduced.remove(&b.batch.digest);
            }
            if !already_executed && !self.payloads.contains_key(&b.batch.digest) {
                let w = self.wanted_batches.entry(b.batch.digest).or_insert(Wanted {
                    holder: Some(b.author),
                    round: anchor.round,
                    ..Wanted::default()
                });
                w.round = w.round.max(anchor.round);
            }
        }
        // This validator's batches in a gap that was skipped will never be
        // ordered: their transactions go back to the mempool.
        let next_own = self.availability.released_through(self.me);
        let mut skipped: Vec<(u64, Digest)> = self
            .own_introduced
            .keys()
            .filter_map(|d| {
                self.payloads
                    .get(d)
                    .filter(|p| p.sequence < next_own)
                    .map(|p| (p.sequence, *d))
            })
            .collect();
        skipped.sort_unstable();
        for (_, d) in skipped {
            self.own_introduced.remove(&d);
            if let Some(p) = self.payloads.get(&d).cloned() {
                self.events.push(Event::Unordered(p));
            }
        }
        let anchor_vertex = self.dag.get(&anchor.digest).expect("in the DAG");
        let mut stamps: Vec<u64> = anchor_vertex
            .strong
            .iter()
            .filter_map(|p| self.dag.get(&p.digest).map(|v| v.timestamp_ms))
            .collect();
        stamps.sort_unstable();
        // A round-0 leader has no parents to take a median of; its own stamp
        // is its author's to choose, so the chain keeps the time it has.
        let median = if stamps.is_empty() {
            self.last_timestamp_ms
        } else {
            stamps[stamps.len() / 2]
        };
        let timestamp_ms = median.max(self.last_timestamp_ms);
        self.last_timestamp_ms = timestamp_ms;

        // A block is made only when the leader orders transactions: an idle
        // committee's commits advance no height and store nothing.
        // A commit releasing more transactions than a block holds makes as
        // many consecutive blocks as it needs, each batch whole and in order.
        if released.iter().any(|b| b.batch.transactions > 0) {
            for batches in block_chunks(released, tenzro_types::block::MAX_TRANSACTIONS_PER_BLOCK) {
                let height = self.next_height;
                self.next_height += 1;
                self.waiting.push_back(Waiting::Segment(WaitingSegment {
                    height,
                    anchor,
                    timestamp_ms,
                    batches,
                    vertices: history.len(),
                }));
            }
        }
        let last_height = self.next_height.saturating_sub(1);

        // Checkpoints: one at most every interval while blocks are ordered;
        // then one more covering no block, which certifies the state after
        // the last block without waiting for a later one; the epoch's last
        // when its time is up, blocks or none; and the handover
        // confirmations after it. An idle epoch is one checkpoint.
        let due = timestamp_ms
            >= self
                .last_checkpoint_ts
                .saturating_add(self.cfg.checkpoint_interval_ms);
        if !self.epoch_closed && timestamp_ms >= self.epoch_ends_ms {
            self.epoch_closed = true;
            self.handover_index = self.next_checkpoint_index + self.cfg.handover_confirmations;
            self.waiting.push_back(Waiting::EpochEnds { last_height });
            self.decide_checkpoint(anchor, last_height, timestamp_ms, true);
        } else if due
            && (self.epoch_closed
                || last_height > self.last_checkpoint_height
                || self.last_state_height < self.last_checkpoint_height)
        {
            self.decide_checkpoint(anchor, last_height, timestamp_ms, false);
        }
        self.collect_garbage(anchor.round);
        self.seal_decided();
    }

    fn decide_checkpoint(
        &mut self,
        anchor: VertexRef,
        last_height: u64,
        timestamp_ms: u64,
        ends_epoch: bool,
    ) {
        let anchor_round = anchor.round;
        let index = self.next_checkpoint_index;
        self.next_checkpoint_index += 1;
        let pc = PendingCheckpoint {
            index,
            first_height: self.last_checkpoint_height + 1,
            last_height,
            anchor_round,
            timestamp_ms,
            ends_epoch,
            ordering_root: None,
        };
        self.last_state_height = checkpoint_state_height(pc.first_height, last_height);
        self.last_checkpoint_height = last_height;
        self.last_checkpoint_ts = timestamp_ms;
        let prev_seed = *self.seed_chain.last().expect("seed chain starts non-empty");
        let mut h = blake3::Hasher::new();
        h.update(b"tenzro/consensus/checkpoint/ordering");
        h.update(&prev_seed);
        h.update(&index.to_be_bytes());
        h.update(&last_height.to_be_bytes());
        h.update(&anchor.digest);
        self.seed_chain.push(h.finalize().into());
        // The schedule the checkpoint releases draws from the ordering
        // digest two checkpoints back, fixed about a second before use.
        let seed_from = self.seed_chain[self.seed_chain.len().saturating_sub(3)];
        self.schedule
            .advance(&self.committee, anchor_round, &seed_from);
        if index == self.handover_index {
            self.halted = true;
        }
        self.decided.push_back(pc);
    }

    fn release_segments(&mut self) {
        while let Some(front) = self.waiting.front() {
            let seg = match front {
                Waiting::EpochEnds { last_height } => {
                    let last_height = *last_height;
                    self.waiting.pop_front();
                    self.events.push(Event::EpochEnds { last_height });
                    continue;
                }
                Waiting::Segment(seg) => seg,
            };
            let already_executed = seg.height <= self.executed_through;
            if !already_executed
                && seg
                    .batches
                    .iter()
                    .any(|b| !self.payloads.contains_key(&b.batch.digest))
            {
                return;
            }
            let Some(Waiting::Segment(seg)) = self.waiting.pop_front() else {
                unreachable!("front is a segment")
            };
            if !already_executed && !seg.batches.is_empty() {
                self.uncertified_payloads.insert(
                    seg.height,
                    seg.batches.iter().map(|b| b.batch.digest).collect(),
                );
                while self.uncertified_payloads.len() > UNCERTIFIED_SEGMENTS_KEPT {
                    self.uncertified_payloads.pop_first();
                }
            }
            let batches = if already_executed {
                Vec::new()
            } else {
                seg.batches
                    .into_iter()
                    .map(|b| {
                        let p = self
                            .payloads
                            .get(&b.batch.digest)
                            .cloned()
                            .expect("present");
                        (b, p)
                    })
                    .collect()
            };
            self.events.push(Event::Ordered(Segment {
                epoch: self.committee.epoch,
                height: seg.height,
                anchor: seg.anchor,
                timestamp_ms: seg.timestamp_ms,
                batches,
                vertices: seg.vertices,
            }));
        }
    }

    fn collect_garbage(&mut self, committed_round: Round) {
        let Some(floor) = committed_round.checked_sub(self.cfg.gc_depth) else {
            return;
        };
        if floor <= self.dag.floor() {
            return;
        }
        let pruned = self.dag.prune_below(floor);
        let mut by_round: BTreeMap<Round, Vec<Digest>> = BTreeMap::new();
        for (d, v) in pruned {
            by_round.entry(v.round).or_default().push(d);
            self.history.insert(d, v);
        }
        for (r, ds) in by_round {
            self.history_rounds.entry(r).or_default().extend(ds);
        }
        let history_from = floor.saturating_sub(history_depth(self.cfg.gc_depth));
        let kept = self.history_rounds.split_off(&history_from);
        for ds in std::mem::replace(&mut self.history_rounds, kept).into_values() {
            for d in ds {
                self.history.remove(&d);
            }
        }
        self.rbc.prune_below(floor);
        self.first_proposals = self.first_proposals.split_off(&floor);
        self.ordered.retain(|_, r| *r >= floor);
        self.bodies.retain(|_, v| v.round >= floor);
        self.unechoed.retain(|(r, _), _| *r >= floor);
        // A payload is kept while an ordered segment waits for it, for the
        // GC depth after it arrived, and while its batch is unreleased: all
        // of this validator's own (it serves them), and another author's
        // within MAX_AHEAD_PER_AUTHOR of that author's released point, so
        // an author whose batches never become available cannot grow this
        // map without bound. Anything dropped is fetched again once needed.
        let in_segments: HashSet<Digest> = self
            .waiting
            .iter()
            .filter_map(|w| match w {
                Waiting::Segment(s) => Some(s),
                Waiting::EpochEnds { .. } => None,
            })
            .flat_map(|s| s.batches.iter().map(|b| b.batch.digest))
            .collect();
        let keep_from = floor;
        // A peer that ordered these blocks but has not executed them yet
        // fetches their batches; they are kept until a certificate covers
        // them, after which such a peer imports the blocks instead.
        let uncertified: HashSet<Digest> = self
            .uncertified_payloads
            .values()
            .flatten()
            .copied()
            .collect();
        let payload_round = &mut self.payload_round;
        let availability = &self.availability;
        let me = self.me;
        self.payloads.retain(|d, p| {
            let base = availability.released_through(p.author);
            let unreleased = p.sequence >= base
                && (p.author == me || p.sequence < base + MAX_AHEAD_PER_AUTHOR as u64);
            let keep = payload_round.get(d).is_some_and(|r| *r >= keep_from)
                || in_segments.contains(d)
                || uncertified.contains(d)
                || unreleased;
            if !keep {
                payload_round.remove(d);
            }
            keep
        });
        let payloads = &self.payloads;
        self.carry_pool
            .retain(|_, b| payloads.contains_key(&b.digest));
        self.wanted_vertices.retain(|d, _| self.dag.is_expected(d));
        // A batch is wanted while a vertex above the floor names it or an
        // ordered segment waits for it; one named only by vertices that
        // were collected is never asked for again.
        self.wanted_batches
            .retain(|d, w| w.round >= floor || in_segments.contains(d));
    }

    // ------------------------------------------------------------------
    // Checkpoints.
    // ------------------------------------------------------------------

    fn build_checkpoints(&mut self) {
        while let Some(pc) = self.decided.front().cloned() {
            let Some(ordering_root) = pc.ordering_root else {
                return;
            };
            let state_height = checkpoint_state_height(pc.first_height, pc.last_height);
            let ready = (pc.first_height..=pc.last_height).all(|h| self.executed.contains_key(&h))
                && self.executed.contains_key(&state_height);
            if !ready {
                return;
            }
            let ends_epoch = pc.ends_epoch;
            if ends_epoch && self.next_committee_root.is_none() {
                return;
            }
            self.decided.pop_front();
            let hashes: Vec<Digest> = (pc.first_height..=pc.last_height)
                .map(|h| self.executed[&h].0)
                .collect();
            let statements: Vec<Digest> = (pc.first_height..=pc.last_height)
                .flat_map(|h| self.executed[&h].2.iter().copied())
                .collect();
            let cp = Checkpoint {
                chain_id: self.cfg.chain_id,
                genesis_hash: self.cfg.genesis_hash,
                epoch: self.committee.epoch,
                index: pc.index,
                prev: self.prev_checkpoint,
                first_height: pc.first_height,
                last_height: pc.last_height,
                blocks_root: merkle_root(&hashes),
                state_height,
                state_root: self.executed[&state_height].1,
                statement_root: merkle_root(&statements),
                next_committee_root: if ends_epoch {
                    self.next_committee_root
                } else {
                    None
                },
                anchor_round: pc.anchor_round,
                timestamp_ms: pc.timestamp_ms,
                ordering_root,
            };
            self.prev_checkpoint = cp.digest();
            let keep_from = state_root_height(pc.last_height);
            self.executed = self.executed.split_off(&keep_from);
            self.events.push(Event::Sign(cp));
        }
    }

    fn on_vote(&mut self, vote: CheckpointVote) {
        let Some(member) = self.committee.member(vote.signer) else {
            return;
        };
        let cp = &vote.checkpoint;
        if cp.epoch != self.committee.epoch
            || cp.chain_id != self.cfg.chain_id
            || cp.genesis_hash != self.cfg.genesis_hash
        {
            return;
        }
        // Votes are held only for checkpoints within the signing window of
        // the next one this validator builds or the latest it holds a
        // certificate for, so a faulty member cannot have it hold votes for
        // any number of future indices. One further behind catches up from
        // certificates.
        let reach = self
            .certificates
            .keys()
            .next_back()
            .map_or(self.next_checkpoint_index, |i| {
                self.next_checkpoint_index.max(i + 1)
            });
        if cp.index > reach.saturating_add(crate::checkpoint::SIGNED_VOTE_WINDOW) {
            return;
        }
        let verified = vote.verify(&member.public_key);
        if !self.ml_dsa.vote_agrees(&self.committee, &vote) {
            self.on_disagreement(vote.checkpoint.index);
            return;
        }
        if !verified {
            return;
        }
        self.count_vote(vote);
    }

    fn count_vote(&mut self, vote: CheckpointVote) {
        // The certificate a quorum forms names each vote's session
        // certificate, so each is kept before its vote counts.
        if self
            .sessions
            .admit(&self.committee, vote.signature.session.clone())
            .is_err()
        {
            return;
        }
        match self.votes.add(&self.committee, vote) {
            VoteOutcome::Certified(c) => self.on_certified(*c),
            VoteOutcome::Equivocation(pair) => {
                let (a, b) = *pair;
                let key = self
                    .committee
                    .member(a.signer)
                    .expect("member")
                    .public_key
                    .clone();
                self.events
                    .push(Event::Equivocation(Box::new(CheckpointEquivocation {
                        public_key: key,
                        first: a.checkpoint,
                        first_signature: a.signature,
                        second: b.checkpoint,
                        second_signature: b.signature,
                    })));
            }
            VoteOutcome::Counted | VoteOutcome::Duplicate => {}
        }
    }

    fn on_certificate(&mut self, c: Certificate) {
        if !self.ml_dsa.certificate_agrees(&c, &self.sessions) {
            self.on_disagreement(c.checkpoint.index);
            return;
        }
        let ctx = CertificateContext {
            chain_id: self.cfg.chain_id,
            genesis_hash: &self.cfg.genesis_hash,
            committee: &self.committee,
            sessions: &self.sessions,
        };
        if c.verify(&ctx).is_err() {
            return;
        }
        if let Some(mine) = self.certificates.get(&c.checkpoint.index) {
            if mine.checkpoint.digest() != c.checkpoint.digest() {
                for (_, e) in CheckpointEquivocation::from_conflicting_certificates(mine, &c, &ctx)
                {
                    self.events.push(Event::Equivocation(Box::new(e)));
                }
            }
            return;
        }
        self.on_certified(c);
    }

    fn on_certified(&mut self, c: Certificate) {
        let index = c.checkpoint.index;
        if self.certificates.contains_key(&index) {
            return;
        }
        self.uncertified_payloads = self
            .uncertified_payloads
            .split_off(&(c.checkpoint.last_height + 1));
        // The epoch's last checkpoint, certified without this validator (it
        // was cut off when the epoch ended, or entered the epoch after): the
        // handover is the certificate the confirmations after it, which it
        // adopts the same way. Its ordering is left alone: closing it here
        // would have it decide the epoch's checkpoints apart from the
        // others, and draw its leaders from another seed.
        if c.checkpoint.next_committee_root.is_some() && !self.epoch_closed {
            self.certified_handover_index = index + self.cfg.handover_confirmations;
        }
        self.certificates.insert(index, c.clone());
        while self.certificates.len() > 8 {
            let first = *self.certificates.keys().next().expect("non-empty");
            self.certificates.remove(&first);
        }
        self.votes.prune_below(index.saturating_sub(16));
        self.own_votes = self.own_votes.split_off(&(index + 1));
        if index == self.handover_index || index == self.certified_handover_index {
            self.complete_epoch(c);
        } else {
            self.events.push(Event::Certified(Box::new(c)));
        }
    }

    fn complete_epoch(&mut self, handover: Certificate) {
        // Batches this committee will never order go back to the
        // mempool for the next epoch.
        let mut stranded: Vec<Digest> = self.own_introduced.keys().copied().collect();
        stranded.extend(self.own_unintroduced.drain(..).map(|b| b.digest));
        self.own_introduced.clear();
        stranded.sort();
        for d in stranded {
            if let Some(p) = self.payloads.get(&d).cloned() {
                self.events.push(Event::Unordered(p));
            }
        }
        self.events.push(Event::EpochComplete(Box::new(handover)));
    }
}

#[cfg(test)]
mod conformance;
#[cfg(test)]
mod conformance_votes;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConsensusConfig;
    use crate::harness::tdc::{committee, genesis_start};
    use crate::rbc::SignalKind;

    /// The skipped honest leader slot of the specification trace (n = 4,
    /// lookahead 1): validators that had decided slot (1,0) but not (1,1)
    /// left round 3 on leaders a later redraw replaced. Under the rule they
    /// may not judge round 3's leaders until round 1 is decided, and at the
    /// core's lookahead a commit lag above it is held to the same rule.
    /// A commit releasing more transactions than a block holds makes
    /// consecutive blocks within the limit, every batch whole and in order.
    #[test]
    fn a_commit_larger_than_a_block_makes_several_blocks() {
        let batch = |author: ValidatorIndex, transactions: u32| OrderedBatch {
            batch: crate::vertex::BatchRef {
                transactions,
                ..BatchPayload::seal(
                    0,
                    author,
                    0,
                    &[BatchPart {
                        transactions,
                        bytes: vec![author as u8],
                    }],
                )
                .reference()
            },
            author,
            round: 1,
        };
        let released = vec![
            batch(0, 600),
            batch(1, 300),
            batch(2, 400),
            batch(3, 0),
            batch(0, 1000),
            batch(1, 5),
        ];
        let chunks = block_chunks(released.clone(), 1000);
        let sizes: Vec<u32> = chunks
            .iter()
            .map(|c| c.iter().map(|b| b.batch.transactions).sum())
            .collect();
        assert_eq!(sizes, vec![900, 400, 1000, 5]);
        assert!(sizes.iter().all(|s| *s as usize <= 1000));
        let flat: Vec<ValidatorIndex> = chunks.iter().flatten().map(|b| b.author).collect();
        assert_eq!(flat, released.iter().map(|b| b.author).collect::<Vec<_>>());
        // Below the limit, one block as before.
        assert_eq!(block_chunks(released[..2].to_vec(), 1000).len(), 1);
    }

    #[test]
    fn a_validator_behind_on_commits_does_not_leave_a_round_on_stale_leaders() {
        // Trace: first undecided slot (1,1), round 3, lookahead 1.
        assert!(!leaders_settled(3, 1, 1));
        // Once (1,1) is decided the next undecided slot is in round 2.
        assert!(leaders_settled(3, 2, 1));
        // The core's lookahead: settled up to four rounds past the first
        // undecided slot, not beyond.
        let l = crate::schedule::LOOKAHEAD_ROUNDS;
        assert!(leaders_settled(10, 6, l));
        assert!(!leaders_settled(11, 6, l));
        // An epoch run with a governed lookahead of 7 judges by 7.
        assert!(leaders_settled(13, 6, 7));
        assert!(!leaders_settled(14, 6, 7));
    }

    /// An epoch runs with the lookahead its start carries, and hands it on
    /// to the next epoch's start for the node to replace with the governed
    /// value.
    #[test]
    fn an_epoch_runs_with_the_lookahead_its_start_carries() {
        let (c, _) = committee(4, 4);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let start = EpochStart {
            leader_lookahead_rounds: 9,
            ..genesis_start()
        };
        let core = Core::new(cfg, c, 0, start);
        assert_eq!(core.schedule.lookahead(), 9);
    }

    fn echoes(out: &[(Target, Message)]) -> usize {
        out.iter()
            .filter_map(|(_, m)| {
                if let Message::Signals(s) = m {
                    Some(s)
                } else {
                    None
                }
            })
            .flatten()
            .filter(|s| s.kind == SignalKind::Echo && s.source == 0)
            .count()
    }

    #[test]
    fn a_proposal_is_echoed_only_once_its_batches_are_held() {
        let (c, _) = committee(4, 4);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let mut author = Core::new(cfg.clone(), c.clone(), 0, genesis_start());
        let mut me = Core::new(cfg, c, 1, genesis_start());
        author.start(0);
        me.start(0);
        let _ = me.take_outbox();
        // The author seals a batch; its round-1 vertex will introduce it.
        author.submit_part(BatchPart {
            transactions: 1,
            bytes: vec![7; 16],
        });
        let out = author.take_outbox();
        let batch = out
            .iter()
            .find_map(|(_, m)| {
                if let Message::Batch(p) = m {
                    Some(p.clone())
                } else {
                    None
                }
            })
            .expect("pushed");
        let v = Vertex {
            epoch: 0,
            round: 0,
            source: 0,
            strong: vec![],
            weak: vec![],
            batches: vec![batch.reference()],
            carried: vec![],
            timestamp_ms: 1,
        };

        // The vertex arrives before its batch: no echo, and the batch is
        // asked of the author at once.
        me.on_messages(0, vec![Message::Propose(v.clone())], 10);
        let out = me.take_outbox();
        assert_eq!(
            echoes(&out),
            0,
            "echoed a vertex whose batch it does not hold"
        );
        assert!(out.iter().any(|(t, m)| *t == Target::One(0)
            && matches!(m, Message::FetchBatches(d) if d == &vec![batch.digest()])));
        // A second, different proposal for the slot is ignored meanwhile.
        let mut twin = v.clone();
        twin.timestamp_ms = 2;
        me.on_messages(0, vec![Message::Propose(twin)], 11);
        assert_eq!(echoes(&me.take_outbox()), 0);

        // The batch arrives: the held-back proposal is echoed, once.
        me.on_messages(0, vec![Message::Batches(vec![batch.clone()])], 12);
        let out = me.take_outbox();
        assert_eq!(echoes(&out), 1);
        let echoed = out
            .iter()
            .filter_map(|(_, m)| {
                if let Message::Signals(s) = m {
                    Some(s)
                } else {
                    None
                }
            })
            .flatten()
            .find(|s| s.kind == SignalKind::Echo && s.source == 0)
            .expect("echo");
        assert_eq!(
            echoed.digest,
            v.digest(),
            "the first proposal, not the twin"
        );
        me.on_messages(0, vec![Message::Batch(batch)], 13);
        assert_eq!(echoes(&me.take_outbox()), 0, "echoed once only");
    }

    #[test]
    fn a_vertex_carrying_a_batch_as_something_it_is_not_is_never_echoed() {
        use crate::vertex::CarriedBatch;
        let (c, _) = committee(4, 4);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let mut author = Core::new(cfg.clone(), c.clone(), 2, genesis_start());
        let mut me = Core::new(cfg, c, 1, genesis_start());
        author.start(0);
        me.start(0);
        let _ = me.take_outbox();
        author.submit_part(BatchPart {
            transactions: 1,
            bytes: vec![9; 16],
        });
        let batch = author
            .take_outbox()
            .iter()
            .find_map(|(_, m)| {
                if let Message::Batch(p) = m {
                    Some(p.clone())
                } else {
                    None
                }
            })
            .expect("pushed");
        me.on_messages(2, vec![Message::Batch(batch.clone())], 5);
        let _ = me.take_outbox();
        let vertex = |source, carried: Vec<CarriedBatch>, ts| Vertex {
            epoch: 0,
            round: 0,
            source,
            strong: vec![],
            weak: vec![],
            batches: vec![],
            carried,
            timestamp_ms: ts,
        };
        // Validator 0 carries validator 2's batch as validator 3's, and
        // validator 3 carries it under another sequence: neither is echoed.
        let as_other_author = vertex(
            0,
            vec![CarriedBatch {
                author: 3,
                batch: batch.reference(),
            }],
            1,
        );
        let mut wrong_sequence = batch.reference();
        wrong_sequence.sequence += 1;
        let as_other_sequence = vertex(
            3,
            vec![CarriedBatch {
                author: 2,
                batch: wrong_sequence,
            }],
            1,
        );
        me.on_messages(0, vec![Message::Propose(as_other_author)], 10);
        me.on_messages(3, vec![Message::Propose(as_other_sequence)], 10);
        let any_echo = me
            .take_outbox()
            .iter()
            .filter_map(|(_, m)| {
                if let Message::Signals(s) = m {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .flatten()
            .filter(|s| s.kind == SignalKind::Echo)
            .count();
        assert_eq!(any_echo, 0, "echoed a vertex that misnames a carried batch");
        // Carried as what it is, it is echoed.
        let honest = vertex(
            0,
            vec![CarriedBatch {
                author: 2,
                batch: batch.reference(),
            }],
            2,
        );
        let mut fresh = Core::new(
            ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default()),
            committee(4, 4).0,
            1,
            genesis_start(),
        );
        fresh.start(0);
        let _ = fresh.take_outbox();
        fresh.on_messages(2, vec![Message::Batch(batch)], 5);
        fresh.on_messages(0, vec![Message::Propose(honest)], 10);
        assert_eq!(echoes(&fresh.take_outbox()), 1);
    }

    /// Four validators whose channels come up one pair at a time, in an
    /// order where each proposes its first vertex to only some of the
    /// others: a message to a peer without a channel is lost. Once every
    /// channel is up, every validator must commit, and in the same order.
    fn run_staggered(connect_at: &[((usize, usize), u64)], until_ms: u64) -> Vec<Vec<VertexRef>> {
        let n = 4;
        let (c, _) = committee(n, n as u64);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let mut cores: Vec<Core> = (0..n)
            .map(|i| Core::new(cfg.clone(), c.clone(), i as ValidatorIndex, genesis_start()))
            .collect();
        let mut up = vec![vec![false; n]; n];
        let mut anchors: Vec<Vec<VertexRef>> = vec![Vec::new(); n];
        for core in cores.iter_mut() {
            core.start(0);
        }
        let mut now = 0u64;
        while now <= until_ms {
            // Every validator's clients keep submitting, so commits make blocks.
            if now.is_multiple_of(500) {
                for (i, core) in cores.iter_mut().enumerate() {
                    core.submit_part(BatchPart {
                        transactions: 1,
                        bytes: vec![i as u8, (now / 500) as u8],
                    });
                }
            }
            for &((a, b), at) in connect_at {
                if at == now {
                    up[a][b] = true;
                    up[b][a] = true;
                    cores[a].on_peer_up(b as ValidatorIndex, now);
                    cores[b].on_peer_up(a as ValidatorIndex, now);
                }
            }
            // Deliver until quiet: each hop takes no time.
            loop {
                let mut frames: Vec<(usize, usize, Vec<Message>)> = Vec::new();
                for i in 0..n {
                    for (t, m) in cores[i].take_outbox() {
                        let to: Vec<usize> = match t {
                            Target::All => (0..n).filter(|p| *p != i).collect(),
                            Target::One(p) => vec![p as usize],
                        };
                        for p in to.into_iter().filter(|p| up[i][*p]) {
                            frames.push((i, p, vec![m.clone()]));
                        }
                    }
                }
                if frames.is_empty() {
                    break;
                }
                for (from, to, ms) in frames {
                    cores[to].on_messages(from as ValidatorIndex, ms, now);
                }
            }
            for (i, core) in cores.iter_mut().enumerate() {
                core.on_tick(now);
                for e in core.take_events() {
                    if let Event::Ordered(seg) = e {
                        anchors[i].push(seg.anchor);
                    }
                }
            }
            now += 10;
        }
        anchors
    }

    /// Four connected validators whose clients keep submitting, each
    /// holding its frontier whenever `held(validator, now)`. Returns each
    /// validator's round at every time in `samples`.
    #[allow(clippy::needless_range_loop)] // the loop index is also the sender's validator index
    fn run_held(samples: &[u64], held: impl Fn(usize, u64) -> bool) -> Vec<Vec<Round>> {
        let n = 4;
        let (c, _) = committee(n, n as u64);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let mut cores: Vec<Core> = (0..n)
            .map(|i| Core::new(cfg.clone(), c.clone(), i as ValidatorIndex, genesis_start()))
            .collect();
        for (i, core) in cores.iter_mut().enumerate() {
            core.start(0);
            for p in (0..n).filter(|p| *p != i) {
                core.on_peer_up(p as ValidatorIndex, 0);
            }
        }
        let mut out = Vec::new();
        let until = *samples.iter().max().expect("a sample");
        let mut now = 0u64;
        while now <= until {
            for (i, core) in cores.iter_mut().enumerate() {
                core.hold_frontier(held(i, now));
                if now.is_multiple_of(100) {
                    core.submit_part(BatchPart {
                        transactions: 1,
                        bytes: vec![i as u8, (now / 100) as u8, (now / 25_600) as u8],
                    });
                }
            }
            loop {
                let mut frames: Vec<(usize, usize, Message)> = Vec::new();
                for i in 0..n {
                    for (t, m) in cores[i].take_outbox() {
                        let to: Vec<usize> = match t {
                            Target::All => (0..n).filter(|p| *p != i).collect(),
                            Target::One(p) => vec![p as usize],
                        };
                        for p in to {
                            frames.push((i, p, m.clone()));
                        }
                    }
                }
                if frames.is_empty() {
                    break;
                }
                for (from, to, m) in frames {
                    cores[to].on_messages(from as ValidatorIndex, vec![m], now);
                }
            }
            for core in cores.iter_mut() {
                core.on_tick(now);
                let _ = core.take_events();
            }
            if samples.contains(&now) {
                out.push(cores.iter().map(|c| c.round().unwrap_or(0)).collect());
            }
            now += 10;
        }
        out
    }

    #[test]
    fn one_held_frontier_follows_its_peers_without_slowing_them() {
        let free = run_held(&[3_000], |_, _| false);
        let one = run_held(&[3_000], |i, _| i == 3);
        let free_top = *free[0].iter().max().unwrap();
        let rounds = &one[0];
        assert!(
            free_top > 50,
            "the reference committee advanced {free_top} rounds"
        );
        // The held validator proposes in the rounds its peers open.
        assert!(
            rounds[3] + 2 >= *rounds.iter().max().unwrap(),
            "the held validator fell behind: {rounds:?}"
        );
        // And the others keep their pace.
        assert!(
            rounds[0] * 10 >= free_top * 9,
            "one held frontier slowed the committee: {rounds:?} against {free_top}"
        );
    }

    #[test]
    fn rounds_wait_while_a_quorum_holds_and_resume_on_release() {
        // Three of four hold from 1 s to 2 s.
        let samples = run_held(&[1_000, 1_500, 2_000, 3_000], |i, now| {
            i != 0 && (1_000..2_000).contains(&now)
        });
        let top = |s: &Vec<Round>| *s.iter().max().unwrap();
        // Held, the committee opens at most the rounds already under way
        // when the hold began.
        assert!(
            top(&samples[1]) <= top(&samples[0]) + 2 && top(&samples[2]) <= top(&samples[0]) + 2,
            "rounds went on under a held quorum: {samples:?}"
        );
        // Released, the committee goes on at its usual pace.
        assert!(
            top(&samples[3]) > top(&samples[2]) + 25,
            "rounds did not resume after release: {samples:?}"
        );
    }

    #[test]
    fn validators_whose_channels_come_up_in_staggered_order_commit() {
        // 0-1 and 2-3 first; then 0-2 and 1-3, which give every validator a
        // quorum of channels, so each proposes round 0 to only two others;
        // 0-3 and 1-2 come up seconds later.
        let order = [
            ((0, 1), 100),
            ((2, 3), 300),
            ((0, 2), 700),
            ((1, 3), 1_100),
            ((0, 3), 4_000),
            ((1, 2), 6_000),
        ];
        let anchors = run_staggered(&order, 20_000);
        for (i, a) in anchors.iter().enumerate() {
            assert!(a.len() >= 3, "validator {i} committed {} leaders", a.len());
        }
        let shortest = anchors.iter().map(Vec::len).min().expect("four");
        for a in &anchors[1..] {
            assert_eq!(
                a[..shortest],
                anchors[0][..shortest],
                "validators committed different sequences"
            );
        }
    }

    /// Four validators on links that are all up, each submitting a part
    /// every 500 ms, until `until_ms`; every proposal is passed through
    /// `mutate` as the other validators receive it. Returns the validators
    /// and the timestamps of the segments they ordered.
    fn run_mutated(
        cfg: CoreConfig,
        until_ms: u64,
        mutate: impl Fn(&mut Vertex),
    ) -> (Vec<Core>, Vec<u64>) {
        let n = 4;
        let (c, _) = committee(n, n as u64);
        let mut cores: Vec<Core> = (0..n)
            .map(|i| Core::new(cfg.clone(), c.clone(), i as ValidatorIndex, genesis_start()))
            .collect();
        for core in cores.iter_mut() {
            core.start(0);
        }
        for (a, core) in cores.iter_mut().enumerate() {
            for b in 0..n {
                if a != b {
                    core.on_peer_up(b as ValidatorIndex, 0);
                }
            }
        }
        let mut stamps = Vec::new();
        let mut now = 0u64;
        while now <= until_ms {
            if now.is_multiple_of(500) {
                for (i, core) in cores.iter_mut().enumerate() {
                    core.submit_part(BatchPart {
                        transactions: 1,
                        bytes: vec![i as u8, (now / 500) as u8],
                    });
                }
            }
            loop {
                let mut frames: Vec<(usize, usize, Message)> = Vec::new();
                for (i, core) in cores.iter_mut().enumerate() {
                    for (t, m) in core.take_outbox() {
                        let to: Vec<usize> = match t {
                            Target::All => (0..n).filter(|p| *p != i).collect(),
                            Target::One(p) => vec![p as usize],
                        };
                        for p in to {
                            let mut m = m.clone();
                            if let Message::Propose(v) = &mut m {
                                mutate(v);
                            }
                            frames.push((i, p, m));
                        }
                    }
                }
                if frames.is_empty() {
                    break;
                }
                for (from, to, m) in frames {
                    cores[to].on_messages(from as ValidatorIndex, vec![m], now);
                }
            }
            for core in cores.iter_mut() {
                core.on_tick(now);
                for e in core.take_events() {
                    if let Event::Ordered(seg) = e {
                        stamps.push(seg.timestamp_ms);
                    }
                }
            }
            now += 10;
        }
        (cores, stamps)
    }

    /// A round-0 leader cannot set chain time: its round-0 vertex stamped far
    /// in the future, as every other validator receives it, moves no
    /// segment's timestamp past the clocks of the validators that commit it.
    #[test]
    fn a_round_zero_leader_cannot_move_chain_time() {
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let until = 20_000u64;
        let (c, _) = committee(4, 4);
        let leader = Core::new(cfg.clone(), c, 0, genesis_start())
            .schedule
            .leader(0, 0);
        let (_, stamps) = run_mutated(cfg, until, |v| {
            if v.round == 0 && v.source == leader {
                v.timestamp_ms = u64::MAX - 1;
            }
        });
        assert!(!stamps.is_empty(), "nothing was committed");
        assert!(
            stamps.iter().all(|t| *t <= until),
            "a segment carries a timestamp past every clock: {:?}",
            stamps.iter().max()
        );
    }

    /// Batches a Byzantine author names but never serves are wanted only
    /// while a vertex that names them is above the garbage-collection floor:
    /// the wanted set stays bounded however many rounds pass.
    #[test]
    fn batches_that_never_arrive_are_not_wanted_forever() {
        let mut cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        cfg.gc_depth = 5;
        cfg.max_rounds_ahead = 10;
        const FAKE: u64 = 64;
        let (cores, _) = run_mutated(cfg.clone(), 30_000, |v| {
            if v.source == 0 {
                v.batches = (0..FAKE)
                    .map(|i| {
                        let mut digest = [0u8; 32];
                        digest[..8].copy_from_slice(&v.round.to_be_bytes());
                        digest[8..16].copy_from_slice(&i.to_be_bytes());
                        digest[31] = 0xBA;
                        BatchRef {
                            sequence: 1_000_000 + v.round * FAKE + i,
                            digest,
                            bytes: 1,
                            transactions: 1,
                        }
                    })
                    .collect();
            }
        });
        let rounds = cores[1].round.unwrap_or(0);
        assert!(
            rounds > 4 * (cfg.gc_depth + cfg.max_rounds_ahead),
            "only {rounds} rounds ran"
        );
        let bound = FAKE as usize * (cfg.gc_depth + cfg.max_rounds_ahead + 4) as usize;
        for core in &cores[1..] {
            assert!(
                core.sizes().wanted_batches <= bound,
                "{} batches wanted after {rounds} rounds, bound {bound}",
                core.sizes().wanted_batches
            );
        }
    }

    /// One validator delivers an author's vertex while the others' signals
    /// for it are lost, and a validator whose echo that delivery counted
    /// goes down for good. The others deliver the author's next vertex, so
    /// the lost instance sits below the highest vertex they hold of that
    /// author. Their stall repair must still bring its signals back: the
    /// delivering validator's next vertex references it, and without it
    /// they never hold a quorum of that round.
    #[test]
    #[allow(clippy::needless_range_loop)] // the loop indices are also the validator indices
    fn signals_lost_below_an_authors_highest_vertex_are_repaired() {
        const N: usize = 5;
        const R: Round = 5;
        const AUTHOR: usize = 2;
        const DELIVERS: usize = 0;
        const CRASHES: usize = 3;
        let (c, _) = committee(N, N as u64);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let mut cores: Vec<Core> = (0..N)
            .map(|i| Core::new(cfg.clone(), c.clone(), i as ValidatorIndex, genesis_start()))
            .collect();
        for core in cores.iter_mut() {
            core.start(0);
        }
        for a in 0..N {
            for b in 0..N {
                if a != b {
                    cores[a].on_peer_up(b as ValidatorIndex, 0);
                }
            }
        }
        // Signals of instance (R, AUTHOR) are lost on their way to every
        // validator but DELIVERS and CRASHES, until CRASHES is down.
        let lost = |s: &Signal, to: usize| {
            s.round == R && s.source as usize == AUTHOR && to != DELIVERS && to != CRASHES
        };
        let mut down_at: Option<u64> = None;
        let mut now = 0u64;
        while now <= 120_000 {
            if now.is_multiple_of(500) {
                for (i, core) in cores.iter_mut().enumerate() {
                    if Some(i) == down_at.map(|_| CRASHES) {
                        continue;
                    }
                    core.submit_part(BatchPart {
                        transactions: 1,
                        bytes: vec![i as u8, (now / 500) as u8],
                    });
                }
            }
            loop {
                let mut frames: Vec<(usize, usize, Message)> = Vec::new();
                for i in 0..N {
                    for (t, m) in cores[i].take_outbox() {
                        if down_at.is_none()
                            && i == DELIVERS
                            && matches!(&m, Message::Propose(v) if v.round == R + 1)
                        {
                            down_at = Some(now);
                        }
                        let to: Vec<usize> = match t {
                            Target::All => (0..N).filter(|p| *p != i).collect(),
                            Target::One(p) => vec![p as usize],
                        };
                        for p in to {
                            frames.push((i, p, m.clone()));
                        }
                    }
                }
                if frames.is_empty() {
                    break;
                }
                for (from, to, m) in frames {
                    if down_at.is_some() && (from == CRASHES || to == CRASHES) {
                        continue;
                    }
                    let m = match m {
                        Message::Signals(ss) if down_at.is_none() => {
                            let kept: Vec<Signal> =
                                ss.into_iter().filter(|s| !lost(s, to)).collect();
                            if kept.is_empty() {
                                continue;
                            }
                            Message::Signals(kept)
                        }
                        m => m,
                    };
                    cores[to].on_messages(from as ValidatorIndex, vec![m], now);
                }
            }
            for (i, core) in cores.iter_mut().enumerate() {
                if down_at.is_some() && i == CRASHES {
                    continue;
                }
                core.on_tick(now);
                core.take_events();
            }
            now += 10;
        }
        assert!(
            down_at.is_some(),
            "validator {DELIVERS} never left round {R}"
        );
        for (i, core) in cores.iter().enumerate().filter(|(i, _)| *i != CRASHES) {
            let committed = core.last_committed_round().unwrap_or(0);
            assert!(
                committed > R + 10,
                "validator {i} committed through round {committed} only, stalled at round {:?}",
                core.round()
            );
        }
    }

    /// A batch whose author is down is asked of every other peer in turn,
    /// whichever validator wants it and whatever its digest. With five
    /// validators the attempts that skip the author once reached only half
    /// of the others, and a batch held only by the other half stayed
    /// missing until its author came back.
    #[test]
    fn a_batch_whose_author_is_down_is_asked_of_every_other_peer() {
        let n = 5;
        let (c, _) = committee(n, n as u64);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let retry = cfg.fetch_retry_ms;
        for me in 0..n as ValidatorIndex {
            let others: HashSet<ValidatorIndex> =
                (0..n as ValidatorIndex).filter(|p| *p != me).collect();
            for &author in &others {
                for first in 0u8..4 {
                    let mut core = Core::new(cfg.clone(), c.clone(), me, genesis_start());
                    let mut digest = [0u8; 32];
                    digest[0] = first;
                    core.wanted_batches.insert(
                        digest,
                        Wanted {
                            holder: Some(author),
                            round: 1,
                            ..Wanted::default()
                        },
                    );
                    let mut asked = HashSet::new();
                    let mut now = 0;
                    for _ in 0..2 * (n - 1) {
                        core.retry_fetches(now);
                        for (to, m) in core.take_outbox() {
                            if let (Target::One(p), Message::FetchBatches(ds)) = (to, m)
                                && ds.contains(&digest)
                            {
                                asked.insert(p);
                            }
                        }
                        now += retry;
                    }
                    assert_eq!(
                        asked, others,
                        "validator {me} wanting a batch of {author} (digest {first}) asked only {asked:?}"
                    );
                }
            }
        }
    }

    /// A frame of repeated requests is answered a bounded number of times:
    /// one small frame cannot make a validator copy its payloads, vertices
    /// or broadcast state into its outbox without limit.
    #[test]
    fn a_frame_of_repeated_requests_is_answered_a_bounded_number_of_times() {
        let (c, _) = committee(4, 4);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let mut author = Core::new(cfg.clone(), c.clone(), 2, genesis_start());
        let mut me = Core::new(cfg, c, 1, genesis_start());
        author.start(0);
        me.start(0);
        for p in [0, 2, 3] {
            me.on_peer_up(p, 0);
        }
        let _ = me.take_outbox();
        author.submit_part(BatchPart {
            transactions: 1,
            bytes: vec![9; 1024],
        });
        let batch = author
            .take_outbox()
            .iter()
            .find_map(|(_, m)| match m {
                Message::Batch(p) => Some(p.clone()),
                _ => None,
            })
            .expect("pushed");
        me.on_messages(2, vec![Message::Batch(batch.clone())], 5);
        let _ = me.take_outbox();
        let d = batch.digest();
        me.on_messages(3, vec![Message::FetchBatches(vec![d]); 1_000], 10);
        let replies = me
            .take_outbox()
            .iter()
            .filter(|(_, m)| matches!(m, Message::Batches(_)))
            .count();
        assert!(replies <= 4, "{replies} replies to one frame");
        let frontier = Frontier {
            round: None,
            highest: vec![],
            next_checkpoint: 0,
        };
        me.on_messages(3, vec![Message::Frontier(frontier); 1_000], 20);
        let out = me.take_outbox().len();
        assert!(out <= 64, "{out} messages for one frame of frontiers");
    }

    /// A peer retrying a fetch every interval, faster than this validator
    /// drains its outbox, gets each batch once per cooldown, and one pass
    /// answers a peer with a bounded number of batch bytes. Every retry used
    /// to be answered with the whole batch again: a validator starved of CPU
    /// spent its time copying and encoding the same megabytes, its channels
    /// stalled, and the signals queued behind them were lost.
    #[test]
    fn repeated_batch_fetches_are_answered_once_per_cooldown_within_a_budget() {
        let (c, _) = committee(4, 4);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let cooldown = cfg.fetch_retry_ms * BATCH_REPLY_COOLDOWN_RETRIES;
        let mut me = Core::new(cfg, c, 1, genesis_start());
        me.start(0);
        let mut digests = Vec::new();
        for sequence in 0..24u64 {
            let p = BatchPayload::seal(
                me.committee.epoch,
                2,
                sequence,
                &[BatchPart {
                    transactions: 1,
                    bytes: vec![sequence as u8; 900_000],
                }],
            );
            digests.push(p.digest());
            me.payloads.insert(p.digest(), p);
        }
        let _ = me.take_outbox();
        let sent = |out: &[(Target, Message)], d: &Digest| -> usize {
            out.iter()
                .filter_map(|(_, m)| match m {
                    Message::Batches(ps) => Some(ps.iter().filter(|p| p.digest() == *d).count()),
                    _ => None,
                })
                .sum()
        };
        // Two hundred retries of one batch within one pass: answered once.
        let one = digests[0];
        for i in 0..200u64 {
            me.on_messages(3, vec![Message::FetchBatches(vec![one])], 10 + i);
        }
        let out = me.take_outbox();
        assert_eq!(sent(&out, &one), 1, "one batch asked 200 times in one pass");
        // Asked again within the cooldown: not sent again.
        me.on_messages(3, vec![Message::FetchBatches(vec![one])], 10 + cooldown / 2);
        assert_eq!(
            sent(&me.take_outbox(), &one),
            0,
            "sent again within the cooldown"
        );
        // Once the cooldown has passed, a peer whose copy was lost gets it.
        me.on_messages(3, vec![Message::FetchBatches(vec![one])], 20 + cooldown);
        assert_eq!(
            sent(&me.take_outbox(), &one),
            1,
            "not sent again after the cooldown"
        );
        // Every batch asked at once: one pass answers within the budget,
        // and the rest follow on later passes as the peer asks again.
        let mut now = 100 + 2 * cooldown;
        let mut got: HashSet<Digest> = HashSet::new();
        for _ in 0..8 {
            me.on_messages(3, vec![Message::FetchBatches(digests.clone())], now);
            let out = me.take_outbox();
            let bytes: usize = out
                .iter()
                .filter_map(|(_, m)| match m {
                    Message::Batches(ps) => Some(ps.iter().map(|p| p.body.len()).sum::<usize>()),
                    _ => None,
                })
                .sum();
            assert!(
                bytes <= MAX_BATCH_REPLY_BYTES,
                "{bytes} batch bytes answered to one peer in one pass"
            );
            for (_, m) in out {
                if let Message::Batches(ps) = m {
                    got.extend(ps.iter().map(|p| p.digest()));
                }
            }
            now += cooldown / 4;
        }
        assert_eq!(got.len(), digests.len(), "every batch asked for arrives");
    }

    /// Echoes and readies of one instance lost on their way to a validator,
    /// and the votes and acknowledgements of another lost too, are sent again
    /// by the repair until the instance delivers there: no lost message is
    /// relied on, and every validator keeps committing.
    #[test]
    fn lost_echoes_and_readies_are_sent_again_until_delivery() {
        const N: usize = 4;
        const R: Round = 3;
        const AUTHOR: usize = 1;
        const STARVED: usize = 3;
        let (c, _) = committee(N, N as u64);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let mut cores: Vec<Core> = (0..N)
            .map(|i| Core::new(cfg.clone(), c.clone(), i as ValidatorIndex, genesis_start()))
            .collect();
        for core in cores.iter_mut() {
            core.start(0);
        }
        for a in 0..N {
            for b in 0..N {
                if a != b {
                    cores[a].on_peer_up(b as ValidatorIndex, 0);
                }
            }
        }
        // The first copy of every echo and ready of instances (R, AUTHOR)
        // and (R + 1, AUTHOR) sent to STARVED is lost, and so is every
        // vote and acknowledgement of (R, AUTHOR) sent to it, the way a
        // full queue drops them.
        let mut first_copy: HashSet<(usize, Round, u8)> = HashSet::new();
        let mut lost = 0usize;
        let mut now = 0u64;
        while now <= 60_000 {
            if now % 500 == 0 {
                for (i, core) in cores.iter_mut().enumerate() {
                    core.submit_part(BatchPart {
                        transactions: 1,
                        bytes: vec![i as u8, (now / 500) as u8],
                    });
                }
            }
            loop {
                let mut frames: Vec<(usize, usize, Message)> = Vec::new();
                for i in 0..N {
                    for (t, m) in cores[i].take_outbox() {
                        let to: Vec<usize> = match t {
                            Target::All => (0..N).filter(|p| *p != i).collect(),
                            Target::One(p) => vec![p as usize],
                        };
                        for p in to {
                            frames.push((i, p, m.clone()));
                        }
                    }
                }
                if frames.is_empty() {
                    break;
                }
                for (from, to, m) in frames {
                    let m = match m {
                        Message::Signals(ss) if to == STARVED => {
                            let kept: Vec<Signal> = ss
                                .into_iter()
                                .filter(|s| {
                                    let ours = s.source as usize == AUTHOR
                                        && (s.round == R || s.round == R + 1);
                                    let drop = ours
                                        && match s.kind {
                                            SignalKind::Echo | SignalKind::Ready => {
                                                first_copy.insert((from, s.round, s.kind as u8))
                                            }
                                            _ => s.round == R,
                                        };
                                    lost += usize::from(drop);
                                    !drop
                                })
                                .collect();
                            if kept.is_empty() {
                                continue;
                            }
                            Message::Signals(kept)
                        }
                        m => m,
                    };
                    cores[to].on_messages(from as ValidatorIndex, vec![m], now);
                }
            }
            for core in cores.iter_mut() {
                core.on_tick(now);
                core.take_events();
            }
            now += 10;
        }
        assert!(lost > 0, "no message of the instance was lost");
        for r in [R, R + 1] {
            assert!(
                cores[STARVED]
                    .rbc
                    .delivered(r, AUTHOR as ValidatorIndex)
                    .is_some()
                    || cores[STARVED].dag.floor() > r,
                "validator {STARVED} never delivered ({r}, {AUTHOR})"
            );
        }
        for (i, core) in cores.iter().enumerate() {
            let committed = core.last_committed_round().unwrap_or(0);
            assert!(
                committed > R + 10,
                "validator {i} committed through round {committed} only, stalled at round {:?}",
                core.round()
            );
        }
    }

    /// A frontier claiming a vertex at the last round neither overflows nor
    /// makes the validator resend everything it holds, and frontiers from
    /// one peer are answered at most once per fetch retry interval.
    #[test]
    fn a_frontier_at_the_last_round_is_answered_without_overflow() {
        let (c, _) = committee(4, 4);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let retry = cfg.fetch_retry_ms;
        let mut me = Core::new(cfg, c, 1, genesis_start());
        me.start(0);
        for p in [0, 2, 3] {
            me.on_peer_up(p, 0);
        }
        let _ = me.take_outbox();
        let frontier = Frontier {
            round: Some(0),
            highest: (0..4)
                .map(|source| VertexRef {
                    round: Round::MAX,
                    source,
                    digest: [7; 32],
                })
                .collect(),
            next_checkpoint: 0,
        };
        me.on_messages(3, vec![Message::Frontier(frontier.clone())], 10);
        let _ = me.take_outbox();
        let empty = Frontier {
            round: Some(0),
            highest: vec![],
            next_checkpoint: 0,
        };
        me.on_messages(3, vec![Message::Frontier(empty.clone())], 11);
        assert!(
            me.take_outbox().is_empty(),
            "answered twice within the interval"
        );
        me.on_messages(3, vec![Message::Frontier(empty)], 11 + retry);
        assert!(!me.take_outbox().is_empty(), "never answered again");
    }

    #[test]
    fn a_stalled_committee_holds_a_bounded_number_of_batches() {
        let (c, _) = committee(4, 4);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let mut me = Core::new(cfg.clone(), c.clone(), 1, genesis_start());
        me.start(0);
        // An author pushes batches far past anything that commits.
        for sequence in 0..(3 * MAX_AHEAD_PER_AUTHOR as u64) {
            let p = BatchPayload::seal(
                0,
                2,
                sequence,
                &[BatchPart {
                    transactions: 1,
                    bytes: vec![1; 32],
                }],
            );
            me.on_messages(2, vec![Message::Batch(p)], 1);
        }
        assert_eq!(
            me.payloads.len(),
            MAX_AHEAD_PER_AUTHOR,
            "held batches past the per-author window"
        );
        let before = me.buffered_bytes();
        for sequence in 0..(3 * MAX_AHEAD_PER_AUTHOR as u64) {
            let p = BatchPayload::seal(
                0,
                2,
                sequence,
                &[BatchPart {
                    transactions: 1,
                    bytes: vec![2; 32],
                }],
            );
            me.on_messages(2, vec![Message::Batch(p)], 2);
        }
        assert_eq!(me.buffered_bytes(), before, "a second flood grew the core");
    }

    /// A frame whose proposal names a parent in the last representable
    /// round is refused like any other malformed vertex.
    #[test]
    fn a_proposal_naming_a_parent_in_the_last_round_is_refused_without_panicking() {
        let bytes = include_bytes!(
            "../../../fuzz/regressions/consensus_frame/strong-reference-at-the-last-round"
        );
        let (c, _) = committee(4, 4);
        let frame = crate::wire::Frame::decode(&bytes[1..]).expect("decodes");
        let from = ValidatorIndex::from(bytes[0] % 4);
        assert!(frame.items.iter().any(|m| matches!(
            m,
            Message::Propose(v) if v.source == from
                && v.epoch == c.epoch
                && v.strong.iter().any(|s| s.round == Round::MAX)
        )));
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let mut me = Core::new(cfg, c, (from + 1) % 4, genesis_start());
        me.start(0);
        let _ = me.take_outbox();
        me.on_messages(from, frame.items, 1_000);
        me.on_tick(1_000);
        assert!(me.first_proposals.values().all(|p| !p.contains_key(&from)));
    }

    /// A frontier claiming a peer delivered vertices of the last
    /// representable round asks for nothing to be sent again.
    #[test]
    fn a_frontier_at_the_last_round_resends_nothing() {
        let (c, _) = committee(4, 4);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let mut me = Core::new(cfg, c, 1, genesis_start());
        me.start(0);
        let _ = me.take_outbox();
        let highest = (0..4)
            .map(|source| VertexRef {
                round: Round::MAX,
                source,
                digest: [9; 32],
            })
            .collect();
        let f = Frontier {
            round: Some(Round::MAX),
            highest,
            next_checkpoint: u64::MAX,
        };
        me.on_messages(2, vec![Message::Frontier(f)], 10);
        assert!(
            me.take_outbox()
                .iter()
                .all(|(_, m)| !matches!(m, Message::Propose(_))),
            "a frontier past every round had vertices sent again"
        );
    }

    #[test]
    fn no_round_starts_before_a_quorum_of_channels_is_up() {
        // Only 0-1 ever comes up: two of four is not a quorum.
        let anchors = run_staggered(&[((0, 1), 100)], 5_000);
        assert!(anchors.iter().all(Vec::is_empty));
        let (c, _) = committee(4, 4);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let mut core = Core::new(cfg, c, 0, genesis_start());
        core.start(0);
        core.on_peer_up(1, 1);
        assert_eq!(core.round(), None, "proposed with two of four connected");
        core.on_peer_up(2, 2);
        assert_eq!(core.round(), Some(0));
    }

    #[test]
    fn one_validator_cannot_make_others_hold_votes_for_any_number_of_future_checkpoints() {
        use crate::checkpoint::test_support::{MemoryHighWater, checkpoint};
        use crate::validator_key::ValidatorSigner;
        let (c, signers) = committee(4, 4);
        let signer = &signers[3];
        let who = (0..4)
            .find(|i| {
                c.member(*i)
                    .is_some_and(|m| &m.public_key == signer.public_key())
            })
            .expect("seated");
        let me_index = if who == 1 { 2 } else { 1 };
        let cfg = ConsensusConfig::default().core(7, [1; 32], &crate::TimeRules::default());
        let mut me = Core::new(cfg, c, me_index, genesis_start());
        me.start(0);
        let _ = me.take_outbox();
        // One session key, certified once, signs every vote.
        let session = crate::session::SessionKey::generate().unwrap();
        let cert = crate::session::sign_certificate(
            &**signer,
            7,
            [1; 32],
            0,
            session.public_key().clone(),
        )
        .unwrap();
        let marks = MemoryHighWater::default();
        let vote = |index: u64| {
            crate::checkpoint::sign_checkpoint(&session, &cert, &marks, who, &checkpoint(index, 3))
                .unwrap()
        };
        // A vote for a checkpoint the committee is about to build is held.
        me.on_messages(who, vec![Message::Vote(vote(1))], 10);
        assert_eq!(
            me.votes.held_indices(),
            1,
            "a vote for the next checkpoint is not held"
        );
        // Votes for many checkpoints far beyond anything built are not.
        let far = crate::checkpoint::SIGNED_VOTE_WINDOW * 4;
        for i in 0..300u64 {
            me.on_messages(who, vec![Message::Vote(vote(far + i * 1_000))], 10);
        }
        assert_eq!(
            me.votes.held_indices(),
            1,
            "votes for checkpoints far beyond this validator's are held"
        );
    }

    #[test]
    fn a_vote_the_two_ml_dsa_implementations_disagree_on_is_refused_and_halts() {
        use crate::checkpoint::test_support::{MemoryHighWater, checkpoint};
        use crate::validator_key::ValidatorSigner;
        fn accept_all(_: &[u8], _: &[u8], _: &[u8]) -> bool {
            true
        }
        let (c, signers) = committee(4, 4);
        let signer = &signers[3];
        let who = (0..4)
            .find(|i| {
                c.member(*i)
                    .is_some_and(|m| &m.public_key == signer.public_key())
            })
            .expect("seated");
        let me_index = if who == 1 { 2 } else { 1 };
        let cfg = ConsensusConfig::default().core(7, [1; 32], &crate::TimeRules::default());
        let session = crate::session::SessionKey::generate().unwrap();
        let cert = crate::session::sign_certificate(
            &**signer,
            7,
            [1; 32],
            0,
            session.public_key().clone(),
        )
        .unwrap();
        let marks = MemoryHighWater::default();
        let vote =
            crate::checkpoint::sign_checkpoint(&session, &cert, &marks, who, &checkpoint(1, 3))
                .unwrap();
        let mut mutated = vote.clone();
        mutated.signature.signature.ml_dsa[100] ^= 0x01;

        // Both real implementations: the valid vote is held, the mutated one
        // refused by both without a halt.
        let mut honest = Core::new(cfg.clone(), c.clone(), me_index, genesis_start());
        honest.start(0);
        let _ = honest.take_outbox();
        honest.on_messages(who, vec![Message::Vote(mutated.clone())], 10);
        assert_eq!(honest.votes.held_indices(), 0);
        assert!(
            !honest.is_halted(),
            "a vote both implementations refuse halted the core"
        );
        honest.on_messages(who, vec![Message::Vote(vote)], 10);
        assert_eq!(honest.votes.held_indices(), 1);

        // One implementation patched to accept anything: the mutated vote it
        // accepts and the other refuses is refused, and the core halts.
        for patched in [
            crate::nversion::Verifiers {
                primary: accept_all,
                ..Default::default()
            },
            crate::nversion::Verifiers {
                second: accept_all,
                ..Default::default()
            },
        ] {
            let mut me = Core::new(cfg.clone(), c.clone(), me_index, genesis_start());
            me.ml_dsa = patched;
            me.start(0);
            let _ = me.take_outbox();
            me.on_messages(who, vec![Message::Vote(mutated.clone())], 10);
            assert_eq!(me.votes.held_indices(), 0, "the disputed vote was held");
            assert!(me.is_halted(), "the core went on after a disagreement");
            assert!(
                me.events
                    .iter()
                    .any(|e| matches!(e, Event::VerifierDisagreement { index: 1 })),
                "the disagreement was not reported"
            );
        }
    }

    #[test]
    fn one_validator_cannot_make_others_hold_broadcast_state_for_any_number_of_future_rounds() {
        let (c, _) = committee(4, 4);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let mut me = Core::new(cfg, c, 1, genesis_start());
        me.start(0);
        let _ = me.take_outbox();
        let before = me.rbc.instances_len();
        let far = me.round.unwrap_or(0) + me.cfg.max_rounds_ahead + 1;
        let signals: Vec<Signal> = (0..2_000u64)
            .map(|i| Signal {
                kind: SignalKind::Echo,
                round: far + i,
                source: 0,
                digest: [7; 32],
            })
            .collect();
        for chunk in signals.chunks(MAX_SIGNALS_PER_FRAME) {
            me.on_messages(3, vec![Message::Signals(chunk.to_vec())], 10);
        }
        assert_eq!(
            me.rbc.instances_len(),
            before,
            "signals for rounds beyond the proposal horizon are held"
        );
    }

    /// A slot holds only the vertex reliable broadcast delivered for it. A
    /// faulty author's vertex naming another author's undelivered twin as a
    /// parent does not let a fetch of that twin take the slot, so the
    /// delivered vertex still enters the DAG and every validator orders the
    /// same vertex for the slot.
    #[test]
    fn a_fetched_vertex_never_takes_a_slot_reliable_broadcast_did_not_deliver_to_it() {
        let (c, _) = committee(4, 4);
        let cfg = ConsensusConfig::default().core(7, [0x11; 32], &crate::TimeRules::default());
        let mut me = Core::new(cfg, c, 1, genesis_start());
        me.start(0);
        let _ = me.take_outbox();
        let vertex =
            |round: Round, source: ValidatorIndex, strong: Vec<VertexRef>, ts: u64| Vertex {
                epoch: 0,
                round,
                source,
                strong,
                weak: vec![],
                batches: vec![],
                carried: vec![],
                timestamp_ms: ts,
            };
        let ready_from = |me: &mut Core, v: &Vertex| {
            for from in [0, 2, 3] {
                let s = Signal {
                    kind: SignalKind::Ready,
                    round: v.round,
                    source: v.source,
                    digest: v.digest(),
                };
                me.on_messages(from, vec![Message::Signals(vec![s])], 20);
            }
        };
        let v2 = vertex(0, 2, vec![], 1);
        let v3 = vertex(0, 3, vec![], 1);
        for v in [&v2, &v3] {
            me.on_messages(v.source, vec![Message::Propose(v.clone())], 10);
            ready_from(&mut me, v);
        }
        assert!(me.dag.contains(&v2.digest()) && me.dag.contains(&v3.digest()));

        // Author 0's vertex, the one the others deliver, and a twin no
        // reliable broadcast delivered.
        let v0 = vertex(0, 0, vec![], 1);
        let twin = vertex(0, 0, vec![], 2);
        // Faulty author 3 names the twin as its round-1 parent; nothing in
        // its proposal is wrong on its own, so it is echoed and delivered.
        let b1 = vertex(
            1,
            3,
            vec![twin.reference(), v2.reference(), v3.reference()],
            3,
        );
        me.on_messages(3, vec![Message::Propose(b1.clone())], 30);
        ready_from(&mut me, &b1);
        // It answers the fetch of its missing parent with the twin.
        me.on_messages(3, vec![Message::Vertices(vec![twin.clone()])], 40);
        // Author 0's vertex is delivered.
        me.on_messages(0, vec![Message::Propose(v0.clone())], 50);
        ready_from(&mut me, &v0);

        assert!(
            !me.dag.contains(&twin.digest()),
            "an undelivered twin entered the DAG"
        );
        assert_eq!(
            me.dag.at(0, 0).map(|(d, _)| *d),
            Some(v0.digest()),
            "the slot holds the vertex reliable broadcast delivered"
        );
        assert!(
            !me.dag.contains(&b1.digest()),
            "a vertex with an undelivered parent entered the DAG"
        );
    }
}
