//! The ordering state a validator's core holds right after it decides a
//! checkpoint.
//!
//! Every honest validator that orders up to a checkpoint holds the same
//! ordering state there: which leader slot comes next, which vertices in the
//! DAG window are already ordered, the leader schedule's credit and recent
//! outcomes, the batch release frontier and the checkpoint bookkeeping. Each
//! checkpoint commits the digest of this state ([`OrderingState::digest`] as
//! `ordering_root`), so a validator that fell further behind than peers keep
//! the DAG can take the state of a certified checkpoint from any one peer,
//! check it against the certificate, and carry on ordering from there in the
//! same epoch.

use serde::{Deserialize, Serialize};

use crate::checkpoint::Certificate;
use crate::committee::ValidatorIndex;
use crate::vertex::{BatchRef, Digest, Round};

/// The leader schedule, reduced to what determines every later draw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleState {
    /// Draw entries: first round, seed, per-member weights.
    pub entries: Vec<(Round, Digest, Vec<u64>)>,
    /// Recent leader-slot outcomes: leader and whether it committed.
    pub outcomes: Vec<(ValidatorIndex, bool)>,
    /// Leader slots per round.
    pub slots: u64,
    /// Rounds between a checkpoint anchor and the first round its seed draws.
    pub lookahead: Round,
    /// First round the retained draws start at.
    pub base: Round,
    /// Per-member credit before `base`.
    pub credit: Vec<i64>,
}

/// The batch release frontier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityState {
    /// Per author, the sequence of its first unreleased batch (non-zero
    /// ones), by author.
    pub next: Vec<(ValidatorIndex, u64)>,
    /// Per author, introductions ordered ahead of `next`: sequence, round,
    /// position and batch, by author then sequence.
    pub early: Vec<(ValidatorIndex, Vec<(u64, Round, u64, BatchRef)>)>,
}

/// A core's ordering state right after it decided checkpoint `index`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderingState {
    /// The epoch.
    pub epoch: u64,
    /// The checkpoint this state was taken at.
    pub index: u64,
    /// Round of the leader whose commit decided the checkpoint.
    pub anchor_round: Round,
    /// The first leader slot not yet decided: round and slot.
    pub next_slot: (Round, u64),
    /// Lowest round the DAG keeps.
    pub floor: Round,
    /// Vertices at or above `floor` already ordered, by digest.
    pub ordered: Vec<(Digest, Round)>,
    /// Height the next ordered segment gets.
    pub next_height: u64,
    /// Timestamp of the last ordered segment.
    pub last_timestamp_ms: u64,
    /// The height whose post-state the checkpoint commits.
    pub last_state_height: u64,
    /// Last height the checkpoint covers.
    pub last_checkpoint_height: u64,
    /// Segment time of the checkpoint.
    pub last_checkpoint_ts: u64,
    /// When the epoch's last checkpoint is due, in segment time.
    pub epoch_ends_ms: u64,
    /// Whether ordering already decided the epoch's last checkpoint.
    pub epoch_closed: bool,
    /// The handover's index, once the epoch's last checkpoint is decided.
    pub handover_index: u64,
    /// The last ordering digests of the checkpoint seed chain, oldest first.
    pub seed_tail: Vec<Digest>,
    /// The leader schedule.
    pub schedule: ScheduleState,
    /// The batch release frontier.
    pub availability: AvailabilityState,
}

impl OrderingState {
    /// The digest a checkpoint commits as its `ordering_root`.
    pub fn digest(&self) -> Digest {
        let mut h = blake3::Hasher::new();
        h.update(b"tenzro/consensus/ordering-state");
        h.update(&bincode::serialize(self).expect("ordering state encodes"));
        h.finalize().into()
    }
}

/// A recovery-journal record: the core took `state` from a peer for the
/// certified checkpoint `certificate` and orders on from there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resumed {
    /// The certificate the state was checked against.
    pub certificate: Certificate,
    /// The ordering state.
    pub state: OrderingState,
}
