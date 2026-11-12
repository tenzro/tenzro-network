//! Records the signers of certified checkpoints on chain, once each, only
//! for checkpoints that certify real work, and only alongside other traffic.
//!
//! A `RecordCheckpointSigners` transaction is itself an ordered transaction,
//! so it makes a block, and the block makes a checkpoint. If every checkpoint
//! were recorded, the record of one would produce the next forever and an
//! idle chain would never go quiet. The rules that stop that:
//!
//! 1. **Real work only.** A checkpoint is recorded only when a block it
//!    covers holds a transaction that is neither a signers record nor a
//!    beacon contribution. A checkpoint covering no block (the one that
//!    certifies the state after the last block), or only records and beacon
//!    contributions, is left unrecorded; the next recorded
//!    checkpoint's rounds start where the last recorded one ended (see
//!    `record_checkpoint_signers`), so no round is skipped, they are
//!    credited with the next recorded checkpoint.
//! 2. **One submitter.** The committee ranks itself per epoch ([`rank`]):
//!    rank 0 sends every record of the epoch, in checkpoint order, from one
//!    account, so they cannot overtake each other on the way to a block.
//!    Rank `k` waits `k` fallback intervals after the records are due and
//!    sends only those neither the chain has taken nor its pool holds from
//!    another member.
//! 3. **Held, then sent with other traffic.** A record that is due is not
//!    sent at once, for it would make a block of its own. It waits in a
//!    bounded queue ([`Queue`]) until the pool holds a transaction that is
//!    not a record (a block is made anyway), or until the epoch is close to
//!    its end ([`flush_lead`]), and then goes in one batch. The flush is
//!    early enough that a record of work certified before it reaches a
//!    block of its own epoch, where the epoch's participation count sees
//!    it.
//! 4. **No stale submissions.** A block admits a record of its own epoch or
//!    of the one before. Work certified so late that its epoch ends before
//!    the record can be sent is recorded at once in the next epoch, where
//!    it still earns its signers' credit; a record of any older epoch is
//!    dropped, never sent. A member never sends at or below the highest
//!    index it already sent in the epoch, nor a record the chain's tally
//!    or its own pool already covers, so it sends none it can know will be
//!    refused. Two members can still send the same record at the same
//!    moment, each before the other's has reached it: a member kept from
//!    its turn because its own key enrolment had not executed sends as soon
//!    as it has, whatever turn it is by then. The chain takes the first and
//!    refuses the second, so the checkpoint is counted once either way. The
//!    queue lives in memory: a restarted node starts with none, which costs
//!    credit for the certificates it held and nothing else.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tenzro_consensus::{Certificate, TimeRules};
use tenzro_storage::BlockStore;
use tenzro_storage::RocksDbStore;
use tenzro_types::transaction::TransactionType;
use tracing::{debug, info, warn};

use crate::consensus_driver::ConsensusHandle;

/// How long each rank behind the first waits before it sends a record the
/// chain has still not taken.
pub const RANK_STEP: Duration = Duration::from_secs(30);

/// How long to wait for the blocks of a checkpoint to reach the local store
/// (a checkpoint is certified while its blocks may still be executing).
const BLOCKS_WAIT: Duration = Duration::from_secs(60);

/// How long to wait for the index entry of a transaction in a stored block.
const INDEX_WAIT: Duration = Duration::from_secs(2);

/// How often the queue is looked at.
const TICK: Duration = Duration::from_millis(250);

/// The most records held at once. Past it the oldest are dropped, and a
/// queue half this full is flushed whatever else is going on.
pub const HELD_CAP: usize = 256;

/// The least time between two summary lines in the log.
const SUMMARY_EVERY: Duration = Duration::from_secs(60);

/// A member's turn to record the checkpoints of an epoch in a committee of
/// `size`, for the member at position `me`: 0 is the first. `epoch` is the
/// epoch the checkpoint belongs to.
pub fn rank(epoch: u64, size: u64, me: u64) -> u64 {
    (me % size + size - epoch % size) % size
}

/// How long before the end of an epoch a held record is sent whatever else
/// is going on: a fifth of the epoch, and at least eight checkpoint
/// intervals (long enough for a record to be gossiped, ordered and
/// executed), but no more than half the epoch.
pub fn flush_lead(time: &TimeRules) -> Duration {
    let epoch_ms = time
        .epoch_checkpoints
        .saturating_mul(time.checkpoint_interval_ms);
    let lead = (epoch_ms / 5)
        .max(time.checkpoint_interval_ms.saturating_mul(8))
        .min(epoch_ms / 2);
    Duration::from_millis(lead)
}

/// The rank step for a chain with `time`: [`RANK_STEP`],
/// or less on a short epoch so that every rank of a committee of eight
/// still gets its turn before the flush point of the epoch has passed.
pub fn rank_step_for(time: &TimeRules) -> Duration {
    RANK_STEP.min(flush_lead(time) / 8)
}

/// Whether `tx` is a signers record, the only kind of transaction that does
/// not count as work worth recording.
pub fn is_signers_record(tx: &TransactionType) -> bool {
    matches!(tx, TransactionType::RecordCheckpointSigners { .. })
}

/// Whether `tx` is upkeep the validators send on their own whether or not
/// anyone uses the chain: a signers record or a beacon contribution. Upkeep
/// alone is not work worth recording; otherwise every beacon round would
/// make an idle checkpoint one to record.
pub fn is_upkeep(tx: &TransactionType) -> bool {
    is_signers_record(tx) || matches!(tx, TransactionType::BeaconContribute { .. })
}

/// The (epoch, index) of the checkpoint a signers record carries, or `None`
/// for any other transaction or one that does not decode.
pub fn pooled_record_of(tx: &TransactionType) -> Option<(u64, u64)> {
    let TransactionType::RecordCheckpointSigners { certificate } = tx else {
        return None;
    };
    let p: tenzro_consensus::PublishedCertificate = bincode::deserialize(certificate).ok()?;
    Some((
        p.certificate.checkpoint.epoch,
        p.certificate.checkpoint.index,
    ))
}

/// Whether `tx` is a signers record for a checkpoint the chain has already
/// recorded: its epoch's tally holds an index at or above it. Executing it
/// would be refused, and a refused record still takes a place in a block.
pub fn is_recorded_checkpoint(chain: &dyn tenzro_vm::VmState, tx: &TransactionType) -> bool {
    let Some((epoch, index)) = pooled_record_of(tx) else {
        return false;
    };
    tenzro_vm::native::rewards::read_epoch_votes(chain, epoch)
        .is_ok_and(|votes| tally_holds(&votes, index))
}

/// Whether an epoch's tally already holds a checkpoint at or above `index`.
fn tally_holds(votes: &tenzro_vm::native::rewards::EpochVotes, index: u64) -> bool {
    votes.last_index.is_some_and(|last| index <= last)
}

/// Whether a block holding transactions of these types certifies real work:
/// at least one is not upkeep ([`is_upkeep`]). A block with none, or only
/// records and beacon contributions, does not, and a checkpoint covering
/// only such blocks is not recorded, which is what lets an idle chain go
/// quiet. Its rounds are credited with the next recorded checkpoint of the
/// epoch.
pub fn covers_real_work<'a>(types: impl IntoIterator<Item = &'a TransactionType>) -> bool {
    types.into_iter().any(|t| !is_upkeep(t))
}

/// Why a record is not sent.
#[derive(Debug, PartialEq, Eq)]
pub enum Skip {
    /// The certificate's epoch is neither the block's epoch nor the one
    /// before it, so the node would turn it into a refused record.
    Stale,
    /// This node has already sent a record at or above this index.
    AlreadySent,
}

/// The local rule deciding whether a record may be sent: nothing stale, and
/// never twice for an index at or below the highest already sent in its epoch.
#[derive(Default)]
pub struct SendGate {
    sent_through: Mutex<HashMap<u64, u64>>,
}

impl SendGate {
    /// Whether a record for `index` of `epoch` may go into a block of
    /// `block_epoch`; if so it is marked sent.
    pub fn admit(&self, epoch: u64, index: u64, block_epoch: u64) -> Result<(), Skip> {
        if epoch != block_epoch && epoch.saturating_add(1) != block_epoch {
            return Err(Skip::Stale);
        }
        let mut sent = self.sent_through.lock();
        if sent.get(&epoch).is_some_and(|h| index <= *h) {
            return Err(Skip::AlreadySent);
        }
        sent.insert(epoch, index);
        Ok(())
    }

    /// Takes back the mark of a send that did not happen.
    pub fn forget(&self, epoch: u64, index: u64) {
        let mut sent = self.sent_through.lock();
        if sent.get(&epoch) == Some(&index) {
            sent.remove(&epoch);
        }
    }
}

/// What the queue is told about the moment it is looked at.
#[derive(Clone, Copy, Debug)]
pub struct View {
    /// The time now, in milliseconds on the clock `ends_ms` is on.
    pub now_ms: u64,
    /// The epoch the node's core is running.
    pub running: u64,
    /// When that epoch ends.
    pub ends_ms: u64,
    /// Whether the pool holds a transaction that is not a signers record.
    pub traffic: bool,
}

/// How the queue decides.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// How long before the end of the epoch a held record is sent whatever
    /// else is going on.
    pub lead_ms: u64,
    /// How long each rank behind the first waits.
    pub step_ms: u64,
    /// The most records held.
    pub cap: usize,
}

/// Why held records are sent now.
#[derive(Debug, PartialEq, Eq)]
pub enum Trigger {
    /// The pool holds other transactions, so a block is made anyway.
    Traffic,
    /// The epoch is close to its end.
    EpochEnd,
    /// The queue is half full.
    Full,
}

/// Whether `unsent` held records are to go now, and why.
pub fn trigger(unsent: usize, view: &View, policy: &Policy) -> Option<Trigger> {
    if unsent == 0 {
        None
    } else if unsent >= (policy.cap / 2).max(1) {
        Some(Trigger::Full)
    } else if view.now_ms.saturating_add(policy.lead_ms) >= view.ends_ms {
        Some(Trigger::EpochEnd)
    } else if view.traffic {
        Some(Trigger::Traffic)
    } else {
        None
    }
}

/// One held record.
struct Entry<T> {
    item: T,
    rank: u64,
    /// Sent by this node; kept until the chain takes it, so it is not sent
    /// again.
    sent: bool,
    /// When the record became due to go, from which its rank's wait runs.
    due_since_ms: Option<u64>,
}

/// What a look at the queue found.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome<T> {
    /// Held records dropped because their epoch is no longer the running one.
    pub dropped_stale: usize,
    /// Held records dropped unsent because the chain's tally covers them.
    pub suppressed: usize,
    /// The records to send now, in checkpoint order, by (epoch, index).
    pub send: Vec<((u64, u64), T)>,
}

/// The bounded queue of records waiting to be sent, by (epoch, index).
pub struct Queue<T> {
    cap: usize,
    entries: BTreeMap<(u64, u64), Entry<T>>,
}

impl<T: Clone> Queue<T> {
    /// An empty queue holding at most `cap` records.
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            entries: BTreeMap::new(),
        }
    }

    /// How many records are held, sent or not.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many records wait to be sent.
    pub fn unsent(&self) -> usize {
        self.entries.values().filter(|e| !e.sent).count()
    }

    /// Holds the record of checkpoint `index` of `epoch`, to be sent in turn
    /// `rank`. `None` when it is held already, otherwise how many older
    /// records were dropped to make room.
    pub fn insert(&mut self, epoch: u64, index: u64, rank: u64, item: T) -> Option<usize> {
        if self.entries.contains_key(&(epoch, index)) {
            return None;
        }
        let mut evicted = 0;
        while self.entries.len() >= self.cap {
            self.entries.pop_first();
            evicted += 1;
        }
        self.entries.insert(
            (epoch, index),
            Entry {
                item,
                rank,
                sent: false,
                due_since_ms: None,
            },
        );
        Some(evicted)
    }

    /// Marks a record as sent.
    pub fn mark_sent(&mut self, key: (u64, u64)) {
        if let Some(e) = self.entries.get_mut(&key) {
            e.sent = true;
        }
    }

    /// Takes a record out.
    pub fn remove(&mut self, key: (u64, u64)) {
        self.entries.remove(&key);
    }

    /// Looks at the queue: drops what is already on chain or on its way
    /// there, and what is stale, decides whether the rest is to go now, and
    /// returns what to send. `covered` says whether the chain's tally or the
    /// pool already holds a record that takes this one's place.
    pub fn step(
        &mut self,
        view: &View,
        policy: &Policy,
        covered: impl Fn(&T) -> bool,
    ) -> Outcome<T> {
        let mut out = Outcome {
            dropped_stale: 0,
            suppressed: 0,
            send: Vec::new(),
        };
        self.entries.retain(|(epoch, _), e| {
            if covered(&e.item) {
                // One this node sent that has landed or is pooled is the
                // expected end; one it never sent is a duplicate it did not
                // make.
                if !e.sent {
                    out.suppressed += 1;
                }
                false
            } else if *epoch != view.running && epoch.saturating_add(1) != view.running {
                // A record this node sent is on its way, not lost; only one
                // never sent is dropped.
                if !e.sent {
                    out.dropped_stale += 1;
                }
                false
            } else {
                true
            }
        });
        // A record of the epoch just ended is overdue: it goes now.
        let overdue = self
            .entries
            .iter()
            .any(|((epoch, _), e)| !e.sent && *epoch < view.running);
        if !overdue && trigger(self.unsent(), view, policy).is_none() {
            for e in self.entries.values_mut() {
                e.due_since_ms = None;
            }
            return out;
        }
        for (key, e) in self.entries.iter_mut() {
            if e.sent {
                continue;
            }
            let since = *e.due_since_ms.get_or_insert(view.now_ms);
            if view.now_ms.saturating_sub(since) >= policy.step_ms.saturating_mul(e.rank) {
                out.send.push((*key, e.item.clone()));
            }
        }
        out
    }
}

/// A log line at most once in an interval.
struct Limiter {
    every: Duration,
    last: Mutex<Option<Instant>>,
}

impl Limiter {
    fn new(every: Duration) -> Self {
        Self {
            every,
            last: Mutex::new(None),
        }
    }

    fn allow(&self) -> bool {
        let mut last = self.last.lock();
        if last.is_some_and(|t| t.elapsed() < self.every) {
            return false;
        }
        *last = Some(Instant::now());
        true
    }
}

/// Counters a caller can watch.
#[derive(Default)]
pub struct RecorderStats {
    /// Records submitted and admitted to the mempool.
    pub submitted: AtomicU64,
    /// Checkpoints left unrecorded because they certify no real work.
    pub skipped_idle: AtomicU64,
    /// Records put in the queue to wait for traffic or the end of the epoch.
    pub held: AtomicU64,
    /// Times the queue was flushed: a batch of records sent together.
    pub flushed: AtomicU64,
    /// Records not sent because the chain's tally covered them already, or
    /// this node had sent that index.
    pub suppressed_duplicate: AtomicU64,
    /// Records of real work dropped because their epoch is no longer the
    /// running one, or would be refused where they would land. A checkpoint
    /// of a past epoch that certifies no work counts as idle, not here.
    pub dropped_stale: AtomicU64,
    /// Records dropped because the queue was full.
    pub dropped_overflow: AtomicU64,
    /// Why a submission was not admitted.
    pub refusals: Mutex<Vec<String>>,
}

impl RecorderStats {
    fn snapshot(&self) -> [u64; 7] {
        [
            self.submitted.load(Ordering::Relaxed),
            self.skipped_idle.load(Ordering::Relaxed),
            self.held.load(Ordering::Relaxed),
            self.flushed.load(Ordering::Relaxed),
            self.suppressed_duplicate.load(Ordering::Relaxed),
            self.dropped_stale.load(Ordering::Relaxed),
            self.dropped_overflow.load(Ordering::Relaxed),
        ]
    }
}

/// What came of an attempt to send a held record.
enum Sent {
    /// In the mempool.
    Yes,
    /// Nothing to send for it, and nothing to try again.
    Done,
    /// Not now; try again at the next look.
    Later,
}

/// The recorder of one validator.
pub struct CheckpointRecorder {
    consensus: Arc<ConsensusHandle>,
    signer: Arc<dyn tenzro_crypto::composite::HybridSigner>,
    storage: Arc<RocksDbStore>,
    chain_id: u64,
    nonces: Arc<crate::payment_rails::NonceReservation>,
    gossip: crate::payment_rails::GossipSlot,
    rank_step: Duration,
    gate: SendGate,
    /// Records of checkpoints that certify real work, waiting to be sent.
    queue: Mutex<Queue<Certificate>>,
    /// Whether the task that looks at the queue runs.
    started: AtomicBool,
    warnings: Limiter,
    /// Observable outcomes.
    pub stats: Arc<RecorderStats>,
}

impl CheckpointRecorder {
    /// A recorder for the validator `signer` is the account of. `rank_step`
    /// is how long each rank behind the first waits (see [`rank_step_for`]).
    pub fn new(
        consensus: Arc<ConsensusHandle>,
        signer: Arc<dyn tenzro_crypto::composite::HybridSigner>,
        storage: Arc<RocksDbStore>,
        chain_id: u64,
        nonces: Arc<crate::payment_rails::NonceReservation>,
        gossip: crate::payment_rails::GossipSlot,
        rank_step: Duration,
        stats: Arc<RecorderStats>,
    ) -> Arc<Self> {
        Arc::new(Self {
            consensus,
            signer,
            storage,
            chain_id,
            nonces,
            gossip,
            rank_step,
            gate: SendGate::default(),
            queue: Mutex::new(Queue::new(HELD_CAP)),
            started: AtomicBool::new(false),
            warnings: Limiter::new(SUMMARY_EVERY),
            stats,
        })
    }

    /// Handles a certificate this validator formed. Returns at once; the
    /// work (waiting for blocks, then for the record's time) runs in tasks.
    pub fn on_certificate(self: &Arc<Self>, cert: &Certificate) {
        let Some(rank) = self.consensus.record_rank(cert) else {
            return;
        };
        if !self.started.swap(true, Ordering::AcqRel) {
            let weak = Arc::downgrade(self);
            tokio::spawn(Self::run(weak));
        }
        let this = self.clone();
        let cert = cert.clone();
        tokio::spawn(async move { this.handle(cert, rank).await });
    }

    /// The votes of `epoch` as the chain's state holds them.
    fn votes(&self, epoch: u64) -> Option<tenzro_vm::native::rewards::EpochVotes> {
        let state = tenzro_vm::StateAdapter::with_storage(
            self.storage.clone() as Arc<dyn tenzro_storage::KvStore>
        );
        tenzro_vm::native::rewards::read_epoch_votes(&state, epoch).ok()
    }

    async fn handle(self: Arc<Self>, cert: Certificate, rank: u64) {
        let cp = &cert.checkpoint;
        // A validator's first transaction is the enrolment of its ML-DSA-65
        // key, and nothing else is admitted from its account before that has
        // executed. It is sent here, ahead of the work check, so a chain
        // that is idle from genesis still seats its validators' keys (once;
        // a retry interval inside spaces any repeat) instead of waiting for
        // the first real transaction.
        {
            let this = self.clone();
            let enrolled = tokio::task::spawn_blocking(move || {
                let kv: Arc<dyn tenzro_storage::KvStore> = this.storage.clone();
                crate::node::ensure_pq_key_enrolled(
                    &this.consensus,
                    &this.signer,
                    &kv,
                    this.chain_id,
                    &this.nonces,
                    &this.gossip,
                )
            })
            .await;
            match enrolled {
                // Enrolled, or the enrolment is on its way: the record is
                // held all the same and sent once the enrolment has executed
                // (see `send`), so a checkpoint certified meanwhile is not
                // lost to this member's turn.
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    warn!(error = %e, "validator key enrolment not submitted");
                    return;
                }
                Err(e) => {
                    warn!(error = %e, "enrolment task failed");
                    return;
                }
            }
        }
        // Whether the checkpoint certifies work comes first: the last
        // checkpoints of an epoch are often certified after the core has
        // moved to the next one, and one of them that certifies no work is
        // idle, not a record lost.
        match self.certifies_work(&cert).await {
            Some(true) => {}
            Some(false) => {
                self.stats.skipped_idle.fetch_add(1, Ordering::Relaxed);
                debug!(
                    index = cp.index,
                    "checkpoint certifies no real work; not recorded"
                );
                return;
            }
            None => {
                warn!(
                    index = cp.index,
                    "blocks of the checkpoint not in the store; not recorded"
                );
                return;
            }
        }
        // A certificate of real work of the epoch just ended is held and
        // sent at once into the next epoch, which a block admits; one of an
        // older epoch could land nowhere and is never held.
        if self.consensus.epoch_window().is_some_and(|(running, _)| {
            running != cp.epoch && running != cp.epoch.saturating_add(1)
        }) {
            self.stats.dropped_stale.fetch_add(1, Ordering::Relaxed);
            debug!(
                index = cp.index,
                epoch = cp.epoch,
                "certificate of a past epoch; not held"
            );
            return;
        }
        let evicted = self
            .queue
            .lock()
            .insert(cp.epoch, cp.index, rank, cert.clone());
        if let Some(evicted) = evicted {
            self.stats.held.fetch_add(1, Ordering::Relaxed);
            if evicted > 0 {
                self.stats
                    .dropped_overflow
                    .fetch_add(evicted as u64, Ordering::Relaxed);
            }
            debug!(index = cp.index, rank, "checkpoint record held");
        }
    }

    /// Looks at the queue every [`TICK`] until the recorder is gone.
    async fn run(this: std::sync::Weak<Self>) {
        let mut logged = (Instant::now(), [0u64; 7]);
        loop {
            tokio::time::sleep(TICK).await;
            let Some(this) = this.upgrade() else {
                return;
            };
            this.tick().await;
            if logged.0.elapsed() >= SUMMARY_EVERY {
                let now = this.stats.snapshot();
                if now != logged.1 {
                    info!(
                        submitted = now[0],
                        idle = now[1],
                        held = now[2],
                        flushed = now[3],
                        suppressed_duplicate = now[4],
                        dropped_stale = now[5],
                        dropped_overflow = now[6],
                        queued = this.queue.lock().len(),
                        "checkpoint recorder"
                    );
                }
                logged = (Instant::now(), now);
            }
        }
    }

    /// One look at the queue: drops what cannot or need not be sent, and
    /// sends what is due.
    async fn tick(self: &Arc<Self>) {
        let Some((running, ends_ms)) = self.consensus.epoch_window() else {
            return;
        };
        if self.queue.lock().is_empty() {
            return;
        }
        let traffic = self.queue.lock().unsent() > 0
            && self
                .consensus
                .mempool()
                .any_transaction(|t| !is_signers_record(&t.transaction.tx_type));
        let view = View {
            now_ms: chrono::Utc::now().timestamp_millis().max(0) as u64,
            running,
            ends_ms,
            traffic,
        };
        let policy = Policy {
            lead_ms: flush_lead(self.consensus.time_rules()).as_millis() as u64,
            step_ms: self.rank_step.as_millis() as u64,
            cap: HELD_CAP,
        };
        let votes = self.votes(running);
        let before = running.checked_sub(1).and_then(|e| self.votes(e));
        let mempool = self.consensus.mempool();
        // Taken by the chain's tally of the running epoch, or a record of
        // the same epoch at or above this index is in the pool already, on
        // its way to a block: another member's record, gossiped here, that
        // a fallback must not send again while it is being ordered.
        let covered = |c: &Certificate| {
            let cp = &c.checkpoint;
            let tally = if cp.epoch == running {
                votes.as_ref()
            } else if cp.epoch.saturating_add(1) == running {
                before.as_ref()
            } else {
                None
            };
            let tallied = tally.is_some_and(|v| {
                v.last_index.is_some_and(|l| cp.index <= l) || cp.anchor_round < v.next_round
            });
            tallied
                || mempool.any_transaction(|t| {
                    pooled_record_of(&t.transaction.tx_type)
                        .is_some_and(|(e, i)| e == cp.epoch && i >= cp.index)
                })
        };
        let outcome = self.queue.lock().step(&view, &policy, covered);
        if outcome.dropped_stale > 0 {
            self.stats
                .dropped_stale
                .fetch_add(outcome.dropped_stale as u64, Ordering::Relaxed);
            if self.warnings.allow() {
                info!(
                    dropped = outcome.dropped_stale,
                    running, "held checkpoint records of a past epoch dropped"
                );
            }
        }
        if outcome.suppressed > 0 {
            self.stats
                .suppressed_duplicate
                .fetch_add(outcome.suppressed as u64, Ordering::Relaxed);
        }
        if outcome.send.is_empty() {
            return;
        }
        self.stats.flushed.fetch_add(1, Ordering::Relaxed);
        for (key, cert) in outcome.send {
            match self.send(&cert, running).await {
                Sent::Yes => self.queue.lock().mark_sent(key),
                Sent::Done => self.queue.lock().remove(key),
                Sent::Later => break,
            }
        }
    }

    /// Sends the record of `cert` into the pool, for a block of
    /// `block_epoch`.
    async fn send(self: &Arc<Self>, cert: &Certificate, block_epoch: u64) -> Sent {
        let cp = &cert.checkpoint;
        if self.consensus.record_rank(cert).unwrap_or(0) > 0 {
            debug!(
                index = cp.index,
                "recording a checkpoint's signers as the fallback"
            );
        }
        let record = self.consensus.signers_record(cert.clone());
        let encoded = bincode::serialize(&record).expect("certificate encodes");
        // The node turns a record whose certificate does not verify for the
        // epoch of the block it lands in into a transaction with an empty
        // payload, which the VM refuses ("checkpoint signers: EOF while
        // parsing"). Check it the way the block will, and send nothing that
        // is already bound to be refused.
        match self.consensus.certified_signers(&encoded, block_epoch) {
            Ok(Ok(_)) => {}
            Ok(Err(reason)) => {
                self.stats.dropped_stale.fetch_add(1, Ordering::Relaxed);
                if self.warnings.allow() {
                    warn!(index = cp.index, %reason, "checkpoint record would be refused; not sent");
                }
                return Sent::Done;
            }
            Err(e) => {
                if self.warnings.allow() {
                    warn!(index = cp.index, error = %e, "checkpoint record not checked; not sent");
                }
                return Sent::Later;
            }
        }
        match self.gate.admit(cp.epoch, cp.index, block_epoch) {
            Ok(()) => {}
            Err(Skip::Stale) => {
                self.stats.dropped_stale.fetch_add(1, Ordering::Relaxed);
                return Sent::Done;
            }
            Err(Skip::AlreadySent) => {
                self.stats
                    .suppressed_duplicate
                    .fetch_add(1, Ordering::Relaxed);
                debug!(index = cp.index, "checkpoint record already sent");
                return Sent::Yes;
            }
        }
        let tx_type = TransactionType::RecordCheckpointSigners {
            certificate: encoded,
        };
        let this = self.clone();
        let submitted = tokio::task::spawn_blocking(move || {
            crate::node::submit_validator_transaction(
                &this.consensus,
                &this.signer,
                &this.storage,
                this.chain_id,
                &this.nonces,
                &this.gossip,
                tx_type,
                100_000,
            )
        })
        .await;
        match submitted {
            Ok(Ok(Some(_))) => {
                self.stats.submitted.fetch_add(1, Ordering::AcqRel);
                Sent::Yes
            }
            // The key enrolment of the account is on its way: nothing was
            // submitted, so a later attempt is still allowed.
            Ok(Ok(None)) => {
                self.gate.forget(cp.epoch, cp.index);
                Sent::Later
            }
            Ok(Err(e)) => {
                self.gate.forget(cp.epoch, cp.index);
                if self.warnings.allow() {
                    warn!(error = %e, index = cp.index, "checkpoint signers not recorded on chain");
                }
                let mut refusals = self.stats.refusals.lock();
                if refusals.len() < 64 {
                    refusals.push(e.to_string());
                }
                Sent::Later
            }
            Err(e) => {
                self.gate.forget(cp.epoch, cp.index);
                warn!(error = %e, "recording task failed");
                Sent::Later
            }
        }
    }

    /// Whether a block the checkpoint covers holds a transaction that is not
    /// upkeep and executed there. `None` when its blocks do not reach the
    /// store.
    ///
    /// Validators batch what their pools hold, so one transaction can be
    /// ordered in more than one block; only its first inclusion executes and
    /// a later copy is skipped. A copy is not work: counted as work, a
    /// transaction gossiped to every pool would make the later checkpoints
    /// that carry its copies ones to record, often after their epoch has
    /// ended.
    async fn certifies_work(&self, cert: &Certificate) -> Option<bool> {
        let cp = &cert.checkpoint;
        if cp.first_height > cp.last_height {
            return Some(false);
        }
        let store = tenzro_storage::block_store::BlockStoreImpl::new(self.storage.clone()).ok()?;
        let deadline = tokio::time::Instant::now() + BLOCKS_WAIT;
        for height in cp.first_height..=cp.last_height {
            let block = loop {
                match store
                    .get_block_by_height(tenzro_types::BlockHeight(height))
                    .await
                {
                    Ok(Some(b)) => break b,
                    _ if tokio::time::Instant::now() < deadline => {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                    _ => return None,
                }
            };
            for t in &block.transactions {
                if is_upkeep(&t.transaction.tx_type) {
                    continue;
                }
                if self.first_included_at(&t.transaction.hash(), height).await {
                    return Some(true);
                }
            }
        }
        Some(false)
    }

    /// Whether the transaction `hash` was first included, and so executed,
    /// at `height`. The index entry is written just after the block is
    /// stored, so a missing one is waited for a moment; one still missing
    /// then was not executed at that height (it was ordered ahead of its
    /// nonce, or did not verify).
    async fn first_included_at(&self, hash: &tenzro_types::Hash, height: u64) -> bool {
        use tenzro_storage::KvStore as _;
        let key = format!("idx:{hash}");
        let deadline = tokio::time::Instant::now() + INDEX_WAIT;
        loop {
            match self
                .storage
                .get(tenzro_storage::CF_TRANSACTIONS, key.as_bytes())
            {
                Ok(Some(bytes)) => {
                    return serde_json::from_slice::<serde_json::Value>(&bytes)
                        .ok()
                        .and_then(|v| v.get("block_height").and_then(|h| h.as_u64()))
                        == Some(height);
                }
                _ if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                _ => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> TransactionType {
        TransactionType::RecordCheckpointSigners {
            certificate: Vec::new(),
        }
    }

    fn transfer() -> TransactionType {
        TransactionType::Transfer { amount: 1 }
    }

    fn policy() -> Policy {
        Policy {
            lead_ms: 4_000,
            step_ms: 500,
            cap: 8,
        }
    }

    fn view(now_ms: u64, traffic: bool) -> View {
        View {
            now_ms,
            running: 7,
            ends_ms: 100_000,
            traffic,
        }
    }

    #[test]
    fn exactly_one_member_holds_each_epochs_first_turn() {
        for size in 1..=9u64 {
            for epoch in 0..40u64 {
                let firsts = (0..size).filter(|me| rank(epoch, size, *me) == 0).count();
                assert_eq!(firsts, 1, "size {size} epoch {epoch}");
                let mut ranks: Vec<u64> = (0..size).map(|me| rank(epoch, size, me)).collect();
                ranks.sort_unstable();
                assert_eq!(ranks, (0..size).collect::<Vec<_>>());
            }
        }
    }

    #[test]
    fn the_first_turn_rotates_with_the_epoch() {
        assert_eq!(rank(7, 5, 2), 0);
        assert_eq!(rank(8, 5, 2), 4);
        assert_eq!(rank(9, 5, 2), 3);
    }

    /// The live pattern: with the turn per checkpoint, five consecutive
    /// checkpoints had five different submitters at once. With it per epoch
    /// every checkpoint of an epoch has the same one.
    #[test]
    fn all_checkpoints_of_an_epoch_have_one_submitter() {
        let size = 5;
        for epoch in 0..10u64 {
            let submitters: std::collections::HashSet<u64> = (0..30u64)
                .map(|_index| (0..size).find(|me| rank(epoch, size, *me) == 0).unwrap())
                .collect();
            assert_eq!(submitters.len(), 1);
        }
    }

    /// The loop-break rule: a checkpoint of blocks holding no transaction, or
    /// only signers records, is not recorded; one with any other is.
    #[test]
    fn only_checkpoints_of_real_transactions_are_recorded() {
        assert!(!covers_real_work(std::iter::empty()));
        assert!(!covers_real_work([&record()]));
        assert!(!covers_real_work([&record(), &record(), &record()]));
        assert!(covers_real_work([&transfer()]));
        assert!(covers_real_work([&record(), &transfer(), &record()]));
        let beacon = TransactionType::BeaconContribute {
            round: 3,
            proof: vec![1; 8],
        };
        assert!(!covers_real_work([&beacon]));
        assert!(!covers_real_work([&beacon, &record(), &beacon]));
        assert!(covers_real_work([&beacon, &transfer()]));
    }

    #[test]
    fn the_flush_lead_and_fallback_follow_the_epoch() {
        let public = TimeRules::default();
        assert_eq!(flush_lead(&public), Duration::from_secs(720));
        assert_eq!(rank_step_for(&public), RANK_STEP);
        let test = TimeRules {
            checkpoint_interval_ms: 500,
            epoch_checkpoints: 20,
            ..TimeRules::default()
        };
        // Ten-second epochs: eight intervals, at most half the epoch.
        assert_eq!(flush_lead(&test), Duration::from_secs(4));
        assert_eq!(rank_step_for(&test), Duration::from_millis(500));
        let tiny = TimeRules {
            checkpoint_interval_ms: 500,
            epoch_checkpoints: 4,
            ..TimeRules::default()
        };
        assert_eq!(flush_lead(&tiny), Duration::from_secs(1));
    }

    #[test]
    fn a_record_waits_for_traffic_or_the_end_of_the_epoch() {
        let p = policy();
        assert_eq!(trigger(0, &view(0, true), &p), None, "nothing held");
        assert_eq!(trigger(1, &view(0, false), &p), None, "idle, epoch far off");
        assert_eq!(trigger(1, &view(0, true), &p), Some(Trigger::Traffic));
        // The epoch ends at 100 000 and the lead is 4 000.
        assert_eq!(trigger(1, &view(95_999, false), &p), None);
        assert_eq!(
            trigger(1, &view(96_000, false), &p),
            Some(Trigger::EpochEnd)
        );
        assert_eq!(trigger(4, &view(0, false), &p), Some(Trigger::Full));
    }

    /// A tally holding index 5 covers every index at or below it, and no
    /// index above it; an epoch with nothing recorded covers none.
    #[test]
    fn a_tally_holds_the_indices_at_or_below_its_last() {
        use tenzro_vm::native::rewards::EpochVotes;
        let votes = EpochVotes {
            last_index: Some(5),
            ..EpochVotes::default()
        };
        assert!(tally_holds(&votes, 4));
        assert!(tally_holds(&votes, 5));
        assert!(!tally_holds(&votes, 6));
        assert!(!tally_holds(&EpochVotes::default(), 0));
    }

    /// Only a signers record can be a copy of one the chain holds.
    #[test]
    fn a_transaction_that_is_no_record_is_never_a_recorded_checkpoint() {
        let state = tenzro_vm::StateAdapter::new();
        assert!(!is_recorded_checkpoint(
            &state,
            &TransactionType::Transfer { amount: 1 }
        ));
    }

    /// An idle chain: records are held until the flush point, then go in one
    /// batch, in checkpoint order, once.
    #[test]
    fn an_idle_chain_flushes_once_before_the_epoch_ends() {
        let mut q = Queue::new(8);
        for index in [10, 11, 12] {
            assert_eq!(q.insert(7, index, 0, index), Some(0));
        }
        let covered = |_: &u64| false;
        for now in (0..96_000).step_by(250) {
            let out = q.step(&view(now, false), &policy(), covered);
            assert!(
                out.send.is_empty(),
                "sent at {now} with nothing else going on"
            );
        }
        let out = q.step(&view(96_000, false), &policy(), covered);
        assert_eq!(
            out.send.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            vec![(7, 10), (7, 11), (7, 12)]
        );
        for (key, _) in &out.send {
            q.mark_sent(*key);
        }
        // Sent ones are not sent again at the next looks.
        for now in [96_250, 96_500, 99_000] {
            assert!(
                q.step(&view(now, false), &policy(), covered)
                    .send
                    .is_empty()
            );
        }
        // A record that lands leaves the queue without counting as a duplicate.
        let out = q.step(&view(99_250, false), &policy(), |i| *i <= 12);
        assert_eq!((out.suppressed, out.dropped_stale), (0, 0));
        assert!(q.is_empty());
    }

    /// Every record leaves in time to land in its own epoch: whatever the
    /// instant a record becomes due, it is sent before the epoch ends minus
    /// the lead, so anything that lands within the lead lands inside it.
    #[test]
    fn a_flush_leaves_the_lead_before_the_epoch_ends() {
        let p = policy();
        for held_at in (0..100_000).step_by(997) {
            let mut q = Queue::new(8);
            q.insert(7, 1, 0, 1u64);
            let mut sent_at = None;
            for now in (held_at..100_000).step_by(250) {
                if !q.step(&view(now, false), &p, |_| false).send.is_empty() {
                    sent_at = Some(now);
                    break;
                }
            }
            let sent_at = sent_at.expect("sent before the end");
            // Held before the flush point: sent at it. Held after it: at once.
            assert!(sent_at >= 96_000, "sent at {sent_at}, held at {held_at}");
            assert!(sent_at < 96_000.max(held_at) + 250);
        }
    }

    /// Traffic carries the held records with it, at once for the first turn.
    #[test]
    fn records_go_with_the_next_transactions() {
        let mut q = Queue::new(8);
        q.insert(7, 5, 0, 5u64);
        assert!(
            q.step(&view(1_000, false), &policy(), |_| false)
                .send
                .is_empty()
        );
        let out = q.step(&view(1_250, true), &policy(), |_| false);
        assert_eq!(out.send.len(), 1);
    }

    /// A fallback member sends only after its turns have passed, and not at
    /// all if the first member's record landed meanwhile.
    #[test]
    fn a_fallback_sends_after_its_turn_and_only_if_not_landed() {
        let p = policy();
        // Rank 2 waits two steps of 500 ms from the moment the record is due.
        let mut q = Queue::new(8);
        q.insert(7, 5, 2, 5u64);
        assert!(q.step(&view(1_000, true), &p, |_| false).send.is_empty());
        assert!(q.step(&view(1_999, true), &p, |_| false).send.is_empty());
        assert_eq!(q.step(&view(2_000, true), &p, |_| false).send.len(), 1);
        // The first member's record landed first: nothing is sent, and it is
        // counted as a duplicate that was suppressed.
        let mut q = Queue::new(8);
        q.insert(7, 5, 2, 5u64);
        assert!(q.step(&view(1_000, true), &p, |_| false).send.is_empty());
        let out = q.step(&view(2_000, true), &p, |i| *i <= 5);
        assert!(out.send.is_empty());
        assert_eq!(out.suppressed, 1);
        assert!(q.is_empty());
    }

    /// The restart case and the live storm: records of an epoch the chain has
    /// left are dropped, sent or not, and never sent.
    #[test]
    fn records_of_a_past_epoch_are_dropped_never_sent() {
        let mut q = Queue::new(8);
        q.insert(5, 100, 0, 100u64);
        q.insert(6, 200, 0, 200u64);
        q.insert(7, 300, 0, 300u64);
        q.mark_sent((6, 200));
        let out = q.step(&view(96_000, false), &policy(), |_| false);
        // Running epoch 7: (5, 100) is two epochs back, never sent, and
        // lost; (6, 200) of the epoch just ended was sent and stays until
        // the chain takes it.
        assert_eq!(out.dropped_stale, 1);
        assert_eq!(q.len(), 2);
        assert_eq!(
            out.send.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            vec![(7, 300)]
        );
        // And a node that was down long: all its held certificates are of
        // epochs the chain has left.
        let mut q = Queue::new(8);
        for index in 0..5 {
            q.insert(3, index, 0, index);
        }
        let out = q.step(&view(96_000, true), &policy(), |_| false);
        assert_eq!((out.dropped_stale, out.send.len()), (5, 0));
        assert!(q.is_empty());
    }

    #[test]
    fn a_record_of_the_epoch_just_ended_goes_at_once() {
        let mut q = Queue::new(8);
        q.insert(6, 40, 0, 40u64);
        q.insert(6, 41, 1, 41u64);
        // Running epoch 7, nothing else going on, its end far off: the
        // first turn sends the record of epoch 6 now, the fallback waits.
        let out = q.step(&view(1_000, false), &policy(), |_| false);
        assert_eq!(out.dropped_stale, 0);
        assert_eq!(
            out.send.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            vec![(6, 40)]
        );
    }

    #[test]
    fn the_queue_is_bounded_and_drops_the_oldest() {
        let mut q = Queue::new(4);
        for index in 0..4 {
            assert_eq!(q.insert(7, index, 0, index), Some(0));
        }
        assert_eq!(q.insert(7, 4, 0, 4), Some(1));
        assert_eq!(q.len(), 4);
        assert_eq!(q.insert(7, 4, 0, 4), None, "held already");
        let out = q.step(&view(0, false), &policy(), |_| false);
        assert_eq!(
            out.send.iter().map(|(k, _)| k.1).collect::<Vec<_>>(),
            vec![1, 2, 3, 4],
            "the oldest went, and a queue this full flushes"
        );
    }

    /// A node never sends at or below the highest index it already sent in
    /// the epoch, and a stale epoch never at all.
    #[test]
    fn a_stale_epoch_certificate_is_never_sent_and_a_current_one_only_once() {
        let gate = SendGate::default();
        for _ in 0..1000 {
            assert_eq!(gate.admit(10, 34197, 13), Err(Skip::Stale));
        }
        assert_eq!(gate.admit(13, 40000, 13), Ok(()));
        for _ in 0..1000 {
            assert_eq!(gate.admit(13, 40000, 13), Err(Skip::AlreadySent));
            assert_eq!(gate.admit(13, 39999, 13), Err(Skip::AlreadySent));
        }
        // The epoch before the block's is still accepted by the node.
        assert_eq!(gate.admit(12, 1, 13), Ok(()));
        // A send that did not happen can be tried again.
        gate.forget(13, 40000);
        assert_eq!(gate.admit(13, 40000, 13), Ok(()));
    }
}
