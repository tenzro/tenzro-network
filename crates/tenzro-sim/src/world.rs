//! The simulated network: validators, links, clients and faults on one
//! simulated clock, with the invariants checked as the run goes.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, OnceLock};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tenzro_consensus::batch::BatchPart;
use tenzro_consensus::checkpoint::test_support::MemoryHighWater;
use tenzro_consensus::checkpoint::{
    CHECKPOINT_VOTE_DOMAIN, Certificate, Checkpoint, CheckpointVote, VoteSignature, sign_checkpoint,
};
use tenzro_consensus::config::{ConsensusConfig, TimeRules};
use tenzro_consensus::validator_key::test_signer::SoftwareTestSigner;
use tenzro_consensus::{
    Committee, Core, CoreConfig, EpochStart, Event, Message, Record, SessionCertificate, Target,
    ValidatorIndex, ValidatorInfo, ValidatorPublicKey, ValidatorSet, ValidatorSigner,
};

use crate::config::{Behaviour, SimConfig};
use crate::ledger::{self, Envelope, Genesis, Ledger, SimTx, TNZO, USER_BASE};
use crate::node::{NodeBlocks, SegmentBlock, batching_index};
use crate::report::{Report, Violation};

type Digest = [u8; 32];

/// Hardware key of validator `v`, cached: key generation is slow.
pub fn validator_key(v: u32) -> ValidatorPublicKey {
    signer(v).public_key().clone()
}

fn signer(v: u32) -> Arc<SoftwareTestSigner> {
    static KEYS: OnceLock<parking_lot_free::Cache> = OnceLock::new();
    KEYS.get_or_init(parking_lot_free::Cache::default)
        .get(v as u64)
}

fn session_signer(v: u32) -> Arc<SoftwareTestSigner> {
    static KEYS: OnceLock<parking_lot_free::Cache> = OnceLock::new();
    KEYS.get_or_init(parking_lot_free::Cache::default)
        .get(1_000_000 + v as u64)
}

mod parking_lot_free {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct Cache(Mutex<HashMap<u64, Arc<SoftwareTestSigner>>>);

    impl Cache {
        pub fn get(&self, seed: u64) -> Arc<SoftwareTestSigner> {
            let mut g = self.0.lock().expect("key cache");
            g.entry(seed)
                .or_insert_with(|| Arc::new(SoftwareTestSigner::from_seed(seed)))
                .clone()
        }
    }
}

/// The committee seated by `bonds` for `epoch`, and the validator id of each
/// seat index.
pub fn committee_of(epoch: u64, bonds: &[u128], seat_budget: u64) -> Option<(Committee, Vec<u32>)> {
    let infos: Vec<ValidatorInfo> = bonds
        .iter()
        .enumerate()
        .filter(|(_, b)| **b >= TNZO)
        .map(|(v, b)| {
            ValidatorInfo::new(
                tenzro_types::primitives::Address::new(ledger::account(v as u32)),
                validator_key(v as u32),
                ledger::node_key(v as u32),
                *b / TNZO,
            )
        })
        .collect();
    if infos.is_empty() {
        return None;
    }
    let set = ValidatorSet::new(epoch, infos).ok()?;
    let c = tenzro_consensus::committee::from_validator_set(&set, seat_budget).ok()?;
    let ids = c
        .members()
        .iter()
        .map(|m| {
            (0..bonds.len() as u32)
                .find(|v| ledger::account(*v) == m.address.0)
                .expect("member is a validator")
        })
        .collect();
    Some((c, ids))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Up,
    Down {
        until_us: u64,
        long: bool,
    },
    /// Not seated in the running epoch.
    Retired,
}

struct Rejoin {
    since_us: u64,
    epoch: u64,
    height: u64,
    live_ms: u64,
    reason: &'static str,
}

struct Node {
    id: u32,
    behaviour: Behaviour,
    status: Status,
    skew_ms: i64,
    core: Option<Core>,
    epoch: u64,
    committee: Committee,
    members: Arc<Vec<u32>>,
    me: ValidatorIndex,
    start: EpochStart,
    // Persisted: survives a crash.
    journal: Vec<Record>,
    journal_bytes: u64,
    executed_through: u64,
    high_water: Arc<MemoryHighWater>,
    // Lost on a crash.
    session_cert: Option<SessionCertificate>,
    to_sign: VecDeque<(u64, Checkpoint)>,
    extra: Vec<(Target, Message)>,
    proposed: BTreeMap<u64, Digest>,
    clients: Vec<Envelope>,
    // Progress and accounting.
    last_height: u64,
    batch_count: u64,
    cpu_free_us: u64,
    egress_free_us: u64,
    bytes_out: u64,
    bytes_in: u64,
    cpu_busy_us: u64,
    rejoin: Option<Rejoin>,
    max_entries: usize,
    max_bytes: usize,
    last_reset: String,
    commit_mark: (u64, u64),
    // Node layer. Persisted: the block store and the checkpoints signed.
    blocks: Option<NodeBlocks>,
    signed: BTreeMap<(u64, u64), Digest>,
    // Execution stopped on a block the node could not read back.
    exec_halted: bool,
    // The event loop is blocked on storage until then.
    stall_until_us: u64,
    // Processing cost multiplier (1: normal).
    slow: u64,
    up_since_us: u64,
    epoch_since_us: u64,
    // When its core started waiting for a checkpoint's ordering state.
    fast_forward_since_us: Option<u64>,
}

/// A sender's transactions in flight.
struct Sending {
    count: u32,
    /// The epoch whose committee it was routed by.
    epoch: u64,
    since_us: u64,
    node: u32,
    /// Something outside the sender's order touched its transactions in
    /// flight (a crash, a lost batch, a reroute, a timeout): a nonce failure
    /// then proves nothing.
    disturbed: bool,
    /// Where and when each nonce in flight was sent.
    sent: BTreeMap<u64, (u32, u64)>,
    /// Runs ahead of its nonce sent back to the mempool.
    retries: u32,
}

/// How long after a member enters an epoch a skipped slot of that epoch
/// says nothing: the member may have missed vertices sent before it did.
const EPOCH_ENTRY_US: u64 = 3_000_000;

/// Times a sender's transactions are run again after running ahead of their
/// nonce before the sender is treated as having lost one.
const MAX_REQUEUES: u32 = 64;

struct Delivery {
    to: u32,
    from: ValidatorIndex,
    from_id: u32,
    epoch: u64,
    msgs: Arc<Vec<Message>>,
    cost_us: u64,
    queued: bool,
}

#[derive(Default)]
struct Links {
    up: HashMap<(u32, u32), u64>,
    pending: Vec<(u64, u32, u32, u64)>,
}

fn pair(a: u32, b: u32) -> (u32, u32) {
    (a.min(b), a.max(b))
}

struct Partition {
    until_us: u64,
    side_a: HashSet<u32>,
    quorum_loss: bool,
}

#[derive(Default)]
struct Gov {
    active: Option<Proposal>,
    next_cal_ms: i64,
    proposals: u64,
    kinds_done: BTreeMap<&'static str, u64>,
    failures: Vec<String>,
    turn: u64,
    /// Next entry of the workload parameter schedule to drive.
    sched_idx: usize,
}

struct Proposal {
    kind: &'static str,
    id: Option<Vec<u8>>,
    proposed_cal: i64,
    stage: GovStage,
    retry_at_cal: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GovStage {
    Proposing,
    Voting,
    Closing,
    Timelock { enact_after: i64 },
    Enacting,
}

#[derive(Default)]
struct Stake {
    next_cal_ms: i64,
    unbonding: BTreeMap<u32, i64>,
    joins: u64,
    exits: u64,
    withdrawals: u64,
    top_ups: u64,
}

/// Called once each time the network enters a new epoch, with the ledger as
/// of that moment.
pub trait EpochObserver {
    /// The network entered `epoch`.
    fn on_epoch(&mut self, epoch: u64, ledger: &Ledger);
    /// The run ended; anything the observer wants in the report goes into
    /// `extra`.
    fn finish(
        &mut self,
        _ledger: &Ledger,
        _extra: &mut serde_json::Map<String, serde_json::Value>,
    ) {
    }
}

/// Extra clients: asked once a simulated second for transactions to send.
/// Each is sent through a validator like any client's, one in flight per
/// sender; the nonce the driver puts in is replaced with the sender's next.
pub trait ClientDriver {
    /// Transactions to send now.
    fn step(&mut self, now_us: u64, ledger: &Ledger, rng: &mut StdRng) -> Vec<SimTx>;
    /// Outcomes of transactions it sent, as the chain executed them.
    fn results(&mut self, _results: &[ledger::TxResult]) {}
}

/// The simulated network.
pub struct World {
    observers: Vec<Box<dyn EpochObserver>>,
    drivers: Vec<Box<dyn ClientDriver>>,
    cfg: SimConfig,
    rng: StdRng,
    now_us: u64,
    seq: u64,
    heap: BinaryHeap<Reverse<(u64, u64)>>,
    deliveries: HashMap<u64, Delivery>,
    nodes: Vec<Node>,
    ledger: Ledger,
    core_cfg: CoreConfig,
    seat_budget: u64,
    /// Committee and start of every epoch the network entered.
    epochs: BTreeMap<u64, (Committee, Arc<Vec<u32>>, EpochStart)>,
    /// The next committee each closing epoch named, as first derived.
    next_roots: BTreeMap<u64, Digest>,
    /// Committees derived at epoch ends, not yet entered.
    pending_committees: BTreeMap<u64, (Committee, Arc<Vec<u32>>)>,
    /// Closing and handover certificates per epoch, for peers that missed
    /// them, with the validators that hold them.
    handovers: BTreeMap<u64, BTreeMap<u64, (Certificate, Vec<SessionCertificate>, Vec<u32>)>>,
    /// The index of each epoch's handover certificate, as its holders know it.
    handover_of: BTreeMap<u64, u64>,
    cert_digests: HashMap<u64, Digest>,
    links: Links,
    partition: Option<Partition>,
    spike: Option<(u64, u64)>,
    senders: BTreeMap<u32, Sending>,
    gov: Gov,
    stake: Stake,
    evidence_seen: HashSet<Digest>,
    // Invariant tracking.
    last_progress_us: u64,
    network_height: u64,
    last_cert_us: u64,
    last_submit_us: u64,
    cert_index: u64,
    live_since_us: Option<u64>,
    stall_flagged: bool,
    final_flagged: bool,
    pub(crate) report: Report,
    certify_wait: BTreeMap<u64, Vec<u64>>,
    epoch_mem: BTreeMap<u64, (usize, usize)>,
    epoch_journal: BTreeMap<u64, u64>,
    started: std::time::Instant,
    ended_early: Option<String>,
    // Node layer.
    faults_until_us: u64,
    calm_since_us: u64,
    ahead_flagged: bool,
    skips_judged: BTreeSet<(u64, u64, ValidatorIndex)>,
    /// The next boundary-aligned crash: when, and which validator.
    boundary_due: Option<(u64, u32)>,
    /// The next boundary-aligned partition: install time, heal time, and the cut-off side.
    boundary_partition_due: Option<(u64, u64, Vec<u32>)>,
}

const TICK: u64 = 0;
const CUT: u64 = 1;
const SECOND: u64 = 2;
const GOSSIP: u64 = 3;

impl World {
    /// Builds the network at genesis.
    pub fn new(cfg: SimConfig) -> Self {
        let mut rng = StdRng::seed_from_u64(cfg.seed);
        let validators = cfg.validators + cfg.standby;
        let ledger = Ledger::genesis(&Genesis {
            active: cfg.validators,
            standby: cfg.standby,
            users: cfg.workload.users,
            bond_tnzo: 100_000,
            balance_tnzo: 10_000_000,
            network_params: cfg.network_params.clone(),
            accounts: Vec::new(),
            strict_supply: false,
            calendar_scale: cfg.calendar_scale(),
            epoch_ms: cfg.epoch_ms(),
        });
        let time = TimeRules {
            checkpoint_interval_ms: cfg.checkpoint_interval_ms,
            epoch_checkpoints: cfg.epoch_checkpoints,
            idle_round_interval_ms: cfg.idle_round_interval_ms,
            calendar_scale: cfg.calendar_scale(),
            ..TimeRules::default()
        };
        let consensus = ConsensusConfig {
            batch_interval_ms: cfg.batch_interval_ms,
            ..ConsensusConfig::default()
        };
        let seat_budget = consensus.seat_budget.max(validators as u64);
        let core_cfg = consensus.core(ledger::CHAIN_ID, [0x11; 32], &time);
        let (committee, members) =
            committee_of(0, ledger.bonds_now(), seat_budget).expect("genesis committee");
        let members = Arc::new(members);
        let start = EpochStart {
            first_height: 1,
            first_checkpoint: 0,
            prev_checkpoint: [0; 32],
            timestamp_ms: 0,
            base_blocks: vec![(0, [0xAA; 32], [0; 32])],
            // The governed lookahead, as a node reads it at epoch begin.
            leader_lookahead_rounds: match ledger
                .param(tenzro_vm::governance::CONSENSUS_LEADER_LOOKAHEAD_PARAM)
            {
                0 => tenzro_consensus::schedule::LOOKAHEAD_ROUNDS,
                v => v,
            },
        };
        let byz: HashMap<u32, Behaviour> = cfg.faults.byzantine.iter().copied().collect();
        let mut nodes = Vec::new();
        for v in 0..validators {
            let seated = members.iter().position(|m| *m == v);
            let skew = if cfg.faults.max_skew_ms > 0 {
                rng.gen_range(-(cfg.faults.max_skew_ms as i64)..=cfg.faults.max_skew_ms as i64)
            } else {
                0
            };
            let core = seated.map(|i| {
                Core::new(
                    core_cfg.clone(),
                    committee.clone(),
                    i as ValidatorIndex,
                    start.clone(),
                )
            });
            nodes.push(Node {
                id: v,
                behaviour: byz.get(&v).copied().unwrap_or(Behaviour::Honest),
                status: if seated.is_some() {
                    Status::Up
                } else {
                    Status::Retired
                },
                skew_ms: skew,
                core,
                epoch: 0,
                committee: committee.clone(),
                members: members.clone(),
                me: seated.unwrap_or(0) as ValidatorIndex,
                start: start.clone(),
                journal: Vec::new(),
                journal_bytes: 0,
                executed_through: 0,
                high_water: Arc::new(MemoryHighWater::default()),
                session_cert: None,
                to_sign: VecDeque::new(),
                extra: Vec::new(),
                proposed: BTreeMap::new(),
                clients: Vec::new(),
                last_height: 0,
                batch_count: 0,
                cpu_free_us: 0,
                egress_free_us: 0,
                bytes_out: 0,
                bytes_in: 0,
                cpu_busy_us: 0,
                rejoin: None,
                max_entries: 0,
                max_bytes: 0,
                last_reset: "genesis".into(),
                commit_mark: (0, 0),
                blocks: (cfg.node_blocks_kept > 0).then(|| NodeBlocks::new(cfg.node_blocks_kept)),
                signed: BTreeMap::new(),
                exec_halted: false,
                stall_until_us: 0,
                slow: 1,
                up_since_us: 0,
                epoch_since_us: 0,
                fast_forward_since_us: None,
            });
        }
        let mut epochs = BTreeMap::new();
        epochs.insert(0, (committee, members.clone(), start));
        let report = Report::new(&cfg);
        let mut w = Self {
            observers: Vec::new(),
            drivers: Vec::new(),
            cfg,
            rng,
            now_us: 0,
            seq: 0,
            heap: BinaryHeap::new(),
            deliveries: HashMap::new(),
            nodes,
            ledger,
            core_cfg,
            seat_budget,
            epochs,
            next_roots: BTreeMap::new(),
            pending_committees: BTreeMap::new(),
            handovers: BTreeMap::new(),
            handover_of: BTreeMap::new(),
            cert_digests: HashMap::new(),
            links: Links::default(),
            partition: None,
            spike: None,
            senders: BTreeMap::new(),
            gov: Gov::default(),
            stake: Stake::default(),
            evidence_seen: HashSet::new(),
            last_progress_us: 0,
            network_height: 0,
            last_cert_us: 0,
            last_submit_us: 0,
            cert_index: 0,
            live_since_us: Some(0),
            stall_flagged: false,
            final_flagged: false,
            report,
            certify_wait: BTreeMap::new(),
            epoch_mem: BTreeMap::new(),
            epoch_journal: BTreeMap::new(),
            started: std::time::Instant::now(),
            ended_early: None,
            faults_until_us: 0,
            boundary_due: None,
            boundary_partition_due: None,
            calm_since_us: 0,
            ahead_flagged: false,
            skips_judged: BTreeSet::new(),
        };
        w.faults_until_us = (w.cfg.duration_ms() as f64
            * w.cfg.faults.faults_until_share.clamp(0.0, 1.0)) as u64
            * 1_000;
        if w.cfg.faults.slow_validators > 0 {
            let mut pool: Vec<usize> = (0..w.cfg.validators as usize)
                .filter(|i| w.nodes[*i].behaviour == Behaviour::Honest)
                .collect();
            for _ in 0..w.cfg.faults.slow_validators {
                if pool.is_empty() {
                    break;
                }
                let k = w.rng.gen_range(0..pool.len());
                let i = pool.swap_remove(k);
                w.nodes[i].slow = w.cfg.faults.slow_factor.max(1);
            }
        }
        w.gov.next_cal_ms = (w.cfg.workload.governance_every_days * 86_400_000.0) as i64;
        w.stake.next_cal_ms = (w.cfg.workload.stake_every_days * 86_400_000.0) as i64;
        for i in 0..w.nodes.len() {
            if let Some(c) = w.nodes[i].core.as_mut() {
                c.start(0);
            }
        }
        for a in 0..validators {
            for b in a + 1..validators {
                if w.nodes[a as usize].core.is_some() && w.nodes[b as usize].core.is_some() {
                    let d = w.connect_delay_us(a, b);
                    w.links.pending.push((d, a, b, 0));
                }
            }
        }
        w
    }

    /// Adds an epoch observer.
    pub fn with_observer(mut self, o: Box<dyn EpochObserver>) -> Self {
        self.observers.push(o);
        self
    }

    /// Adds a client driver.
    pub fn with_driver(mut self, d: Box<dyn ClientDriver>) -> Self {
        self.drivers.push(d);
        self
    }

    /// The chain's ledger.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    fn connect_delay_us(&mut self, _a: u32, _b: u32) -> u64 {
        let (lo, hi) = self.cfg.latency_ms;
        (3 * self.rng.gen_range(lo..=hi) + 50) * 1_000
    }

    fn push(&mut self, at_us: u64, kind: u64) {
        self.seq += 1;
        // Timers and deliveries share one queue: kinds below 16 are timers,
        // anything above is a delivery id.
        self.heap.push(Reverse((at_us, (self.seq << 8) | kind)));
    }

    fn push_delivery(&mut self, at_us: u64, d: Delivery) {
        self.seq += 1;
        let key = (self.seq << 8) | 0xFF;
        self.deliveries.insert(key, d);
        self.heap.push(Reverse((at_us, key)));
    }

    fn node_ms(&self, i: usize) -> u64 {
        ((self.now_us / 1_000) as i64 + self.nodes[i].skew_ms).max(0) as u64
    }

    /// Runs to the end and returns the report.
    pub fn run(mut self, mut progress: impl FnMut(&Report)) -> Report {
        let end_us = self.cfg.duration_ms() * 1_000;
        self.push(0, TICK);
        self.push(0, CUT);
        self.push(0, SECOND);
        self.push(0, GOSSIP);
        let mut next_progress_us = 600_000_000;
        while let Some(Reverse((t, key))) = self.heap.pop() {
            if t > end_us || self.ended_early.is_some() {
                break;
            }
            self.now_us = t;
            match key & 0xFF {
                0xFF => {
                    let d = self.deliveries.remove(&key).expect("delivery");
                    self.deliver(d);
                }
                TICK => {
                    self.tick();
                    self.push(t + self.cfg.tick_ms * 1_000, TICK);
                }
                CUT => {
                    self.cut();
                    self.push(t + self.cfg.batch_interval_ms * 1_000, CUT);
                }
                GOSSIP => {
                    self.gossip();
                    self.push(t + 500_000, GOSSIP);
                }
                SECOND => {
                    self.second();
                    self.push(t + 1_000_000, SECOND);
                    if t >= next_progress_us {
                        next_progress_us += 600_000_000;
                        self.fill_report();
                        progress(&self.report);
                    }
                }
                _ => unreachable!(),
            }
        }
        self.finish()
    }

    // ---- validators ----------------------------------------------------

    fn session_certificate(&mut self, i: usize, cp: &Checkpoint) -> SessionCertificate {
        let n = &mut self.nodes[i];
        match &n.session_cert {
            Some(c) if c.epoch == cp.epoch => c.clone(),
            _ => {
                let c = tenzro_consensus::session::sign_certificate(
                    &*signer(n.id),
                    cp.chain_id,
                    cp.genesis_hash,
                    cp.epoch,
                    session_signer(n.id).public_key().clone(),
                )
                .expect("test signer");
                n.session_cert = Some(c.clone());
                c
            }
        }
    }

    fn sign_due(&mut self, i: usize) {
        let now = self.node_ms(i);
        loop {
            let Some((ready, _)) = self.nodes[i].to_sign.front() else {
                return;
            };
            if *ready > now {
                return;
            }
            let (_, cp) = self.nodes[i].to_sign.pop_front().expect("front");
            let cert = self.session_certificate(i, &cp);
            let n = &mut self.nodes[i];
            let session = session_signer(n.id);
            let Some(core) = n.core.as_mut() else { return };
            if cp.epoch != n.epoch {
                continue;
            }
            let mut twice = None;
            if let Ok(v) = sign_checkpoint(&*session, &cert, &*n.high_water, n.me, &cp) {
                core.on_own_vote(v);
                let d = cp.digest();
                let first = *n.signed.entry((cp.epoch, cp.index)).or_insert(d);
                if first != d && n.behaviour == Behaviour::Honest {
                    twice = Some(cp.index);
                }
                while n.signed.len() > 4_096 {
                    n.signed.pop_first();
                }
            }
            if let Some(index) = twice {
                let id = n.id;
                self.violation(
                    "safety",
                    Some(id),
                    format!("signed two different checkpoints at index {index}"),
                );
                continue;
            }
            let n = &mut self.nodes[i];
            if n.behaviour == Behaviour::DoubleSign {
                let mut other = cp.clone();
                other.state_root[0] ^= 0xFF;
                let digest = other.digest();
                let signature = session
                    .sign(CHECKPOINT_VOTE_DOMAIN, &digest)
                    .expect("test signer");
                let vote = CheckpointVote {
                    checkpoint: other,
                    signer: n.me,
                    signature: VoteSignature {
                        session: cert,
                        signature,
                    },
                };
                let size = n.committee.size() as ValidatorIndex;
                for p in (0..size).filter(|p| p % 2 == 1 && *p != n.me) {
                    n.extra.push((Target::One(p), Message::Vote(vote.clone())));
                }
            }
        }
    }

    fn stalled(&self, i: usize) -> bool {
        self.nodes[i].stall_until_us > self.now_us
    }

    fn tick(&mut self) {
        for i in 0..self.nodes.len() {
            if self.nodes[i].status != Status::Up || self.stalled(i) {
                continue;
            }
            self.sign_due(i);
            let now = self.node_ms(i);
            if let Some(c) = self.nodes[i].core.as_mut() {
                c.on_tick(now);
            }
            self.process(i);
        }
    }

    fn cut(&mut self) {
        for i in 0..self.nodes.len() {
            if self.nodes[i].status != Status::Up
                || self.nodes[i].clients.is_empty()
                || self.stalled(i)
            {
                continue;
            }
            let n = &mut self.nodes[i];
            let Some(core) = n.core.as_mut() else {
                continue;
            };
            let txs = std::mem::take(&mut n.clients);
            let count = txs.len() as u32;
            core.submit_part(BatchPart {
                transactions: count,
                bytes: bincode::serialize(&txs).expect("envelopes encode"),
            });
            self.process(i);
        }
    }

    /// Takes a validator's events and frames and acts on them.
    fn process(&mut self, i: usize) {
        for _ in 0..8 {
            let events = match self.nodes[i].core.as_mut() {
                Some(c) => c.take_events(),
                None => return,
            };
            if events.is_empty() {
                break;
            }
            for e in events {
                self.on_event(i, e);
                if self.nodes[i].core.is_none() {
                    return;
                }
            }
        }
        self.judge_skips(i);
        self.drain(i);
    }

    /// A leader slot skipped while the network was calm, with the leader
    /// honest, up, connected to every member up and not slow or stalled, is
    /// a liveness violation: every honest validator holds its vertex well
    /// within the leader timeout.
    fn judge_skips(&mut self, i: usize) {
        let skipped = match self.nodes[i].core.as_mut() {
            Some(c) => c.take_skipped(),
            None => return,
        };
        if skipped.is_empty() || self.nodes[i].behaviour != Behaviour::Honest {
            return;
        }
        let epoch = self.nodes[i].epoch;
        let members = self.nodes[i].members.clone();
        let calm = self.cfg.limits.calm_ms * 1_000;
        let lossy = self.cfg.faults.frame_loss > 0.0 && self.now_us < self.faults_until_us;
        for (round, leader) in skipped {
            if !self.skips_judged.insert((epoch, round, leader)) {
                continue;
            }
            if lossy || self.now_us < self.calm_since_us + calm {
                continue;
            }
            let Some(&id) = members.get(leader as usize) else {
                continue;
            };
            let l = &self.nodes[id as usize];
            if l.behaviour != Behaviour::Honest
                || l.status != Status::Up
                || l.epoch != epoch
                || l.slow > 1
                || self.now_us < l.up_since_us + calm
                || self.now_us < l.stall_until_us + calm
            {
                continue;
            }
            // A validator recovering replays what it built before it
            // stopped; the network is judged once no member has restarted
            // within the calm window.
            let recovering = members
                .iter()
                .any(|m| self.now_us < self.nodes[*m as usize].up_since_us + calm);
            // A member that entered the epoch only lately may have missed
            // the leader's vertex sent before it did.
            let entering = members.iter().any(|m| {
                let n = &self.nodes[*m as usize];
                n.status == Status::Up && self.now_us < n.epoch_since_us + EPOCH_ENTRY_US
            });
            if recovering || entering {
                continue;
            }
            let disconnected = members.iter().any(|m| {
                *m != id
                    && self.nodes[*m as usize].status == Status::Up
                    && self.nodes[*m as usize].epoch == epoch
                    && !self.carries(id, *m, epoch)
            });
            if disconnected {
                continue;
            }
            let up = members
                .iter()
                .filter(|m| self.nodes[**m as usize].status == Status::Up)
                .count();
            let restarted_ms = members
                .iter()
                .map(|m| {
                    self.now_us
                        .saturating_sub(self.nodes[*m as usize].up_since_us)
                        / 1_000
                })
                .min()
                .unwrap_or(0);
            let judge_round = self.nodes[i]
                .core
                .as_ref()
                .and_then(|c| c.round())
                .unwrap_or(0);
            self.violation(
                "liveness",
                Some(self.nodes[i].id),
                format!(
                    "skipped the slot of honest leader {id} in round {round} of epoch {epoch} (judged in round {judge_round}), network calm for {} ms, {up} of {} members up, latest restart {restarted_ms} ms ago",
                    (self.now_us - self.calm_since_us) / 1_000,
                    members.len()
                ),
            );
        }
        if self.skips_judged.len() > 65_536 {
            let floor = epoch.saturating_sub(2);
            self.skips_judged.retain(|(e, _, _)| *e >= floor);
        }
    }

    fn on_event(&mut self, i: usize, e: Event) {
        let now = self.node_ms(i);
        match e {
            Event::Ordered(seg) => {
                let mut h = blake3::Hasher::new();
                h.update(&seg.anchor.digest);
                let mut txs: Vec<Envelope> = Vec::new();
                for (_, p) in &seg.batches {
                    for part in p.parts().unwrap_or_default() {
                        h.update(part);
                        if let Ok(mut v) = bincode::deserialize::<Vec<Envelope>>(part) {
                            txs.append(&mut v);
                        }
                    }
                }
                let content = *h.finalize().as_bytes();
                let height = seg.height;
                if self.nodes[i].exec_halted {
                    return;
                }
                let proposer = self.nodes[i]
                    .members
                    .get(seg.anchor.source as usize)
                    .copied()
                    .unwrap_or(0);
                if height > self.nodes[i].executed_through
                    && let Some(blocks) = self.nodes[i].blocks.as_mut()
                {
                    let stored = blocks.store_and_read(&SegmentBlock {
                        height,
                        epoch: seg.epoch,
                        round: seg.anchor.round,
                        anchor: seg.anchor.digest,
                        proposer,
                        timestamp_ms: seg.timestamp_ms,
                        txs: &txs,
                    });
                    if let Err(e) = stored {
                        self.nodes[i].exec_halted = true;
                        self.violation(
                            "execution",
                            Some(self.nodes[i].id),
                            format!(
                                "stopped at height {height} ({} transactions): {e}",
                                txs.len()
                            ),
                        );
                        return;
                    }
                }
                let batch_ids: Vec<(u16, u64)> = seg
                    .batches
                    .iter()
                    .map(|(_, p)| (p.author, p.sequence))
                    .collect();
                let batches_digest = {
                    let mut h = 0u64;
                    for (a, q) in &batch_ids {
                        h = h
                            .wrapping_mul(1_000_003)
                            .wrapping_add(((*a as u64) << 40) ^ q);
                    }
                    h
                };
                let executed = match self.ledger.at(height) {
                    Some(e) => {
                        // A validator recovering from its journal re-derives the
                        // heights it already executed with their anchors only; the
                        // node keeps those blocks, so only the anchor must match.
                        let replayed = height <= self.nodes[i].executed_through;
                        let differs = if replayed {
                            e.anchor != seg.anchor.digest
                        } else {
                            e.content != content
                        };
                        if differs {
                            let n = &self.nodes[i];
                            let detail = format!(
                                "validator ordered different content at height {height} (anchor {}, batches {}: {:?}; its epoch {} from height {}, segment epoch {}, last reset: {})",
                                if e.anchor == seg.anchor.digest {
                                    "same"
                                } else {
                                    "differs"
                                },
                                if e.batches == batches_digest {
                                    "same"
                                } else {
                                    "differ"
                                },
                                batch_ids,
                                n.epoch,
                                n.start.first_height,
                                seg.epoch,
                                n.last_reset
                            ) + &format!(
                                "; first executed by validator {} (its epoch {} from height {}; network's epoch {} start {}; last reset: {}, behaviour {:?})",
                                e.first_by,
                                self.nodes[e.first_by as usize].epoch,
                                self.nodes[e.first_by as usize].start.first_height,
                                seg.epoch,
                                self.epochs
                                    .get(&seg.epoch)
                                    .map(|x| x.2.first_height)
                                    .unwrap_or(0),
                                self.nodes[e.first_by as usize].last_reset,
                                self.nodes[e.first_by as usize].behaviour
                            );
                            self.violation("safety", Some(n.id), detail);
                        }
                        e
                    }
                    None if height == self.ledger.height() + 1 => {
                        let proposer = self.nodes[i]
                            .members
                            .get(seg.anchor.source as usize)
                            .copied()
                            .unwrap_or(0);
                        let e = self.ledger.execute(
                            height,
                            content,
                            seg.anchor.digest,
                            batches_digest,
                            self.nodes[i].id,
                            seg.epoch,
                            seg.timestamp_ms,
                            proposer,
                            txs,
                        );
                        self.after_block(height);
                        e
                    }
                    None => {
                        self.violation(
                            "safety",
                            Some(self.nodes[i].id),
                            format!(
                                "validator ordered height {height} past the chain's {}",
                                self.ledger.height()
                            ),
                        );
                        return;
                    }
                };
                let n = &mut self.nodes[i];
                n.last_height = n.last_height.max(height);
                n.executed_through = n.executed_through.max(height);
                if let Some(c) = n.core.as_mut() {
                    c.on_executed(height, executed.block, executed.root, Vec::new());
                }
                if height > self.network_height && self.nodes[i].behaviour == Behaviour::Honest {
                    self.network_height = height;
                }
            }
            Event::EpochEnds { last_height } => {
                let epoch = self.nodes[i].epoch + 1;
                let bonds = self.ledger.bonds_at(last_height).to_vec();
                let Some((c, _)) = committee_of(epoch, &bonds, self.seat_budget) else {
                    self.violation(
                        "liveness",
                        None,
                        format!("no validator is bonded for epoch {epoch}"),
                    );
                    return;
                };
                let root = c.root();
                match self.next_roots.get(&epoch) {
                    Some(r) if *r != root => self.violation(
                        "safety",
                        Some(self.nodes[i].id),
                        format!("validator derived a different committee for epoch {epoch}"),
                    ),
                    Some(_) => {}
                    None => {
                        self.next_roots.insert(epoch, root);
                        let members = committee_of(epoch, &bonds, self.seat_budget)
                            .expect("same committee")
                            .1;
                        self.pending_committees
                            .insert(epoch, (c, Arc::new(members)));
                    }
                }
                if let Some(core) = self.nodes[i].core.as_mut() {
                    core.set_next_committee_root(root);
                }
            }
            Event::Sign(cp) => {
                // A signer's latency varies, so a validator may sign a
                // checkpoint after the one that follows it.
                let jitter = self.cfg.faults.sign_jitter_ms;
                let extra = if jitter > 0 && self.now_us < self.faults_until_us {
                    self.rng.gen_range(0..=jitter)
                } else {
                    0
                };
                let burst = self.sign_burst_ms(i, &cp);
                let ready = now + self.cfg.sign_latency_ms + extra + burst;
                let q = &mut self.nodes[i].to_sign;
                let at = q.iter().position(|(r, _)| *r > ready).unwrap_or(q.len());
                q.insert(at, (ready, cp));
            }
            Event::Certified(c) => {
                self.on_certificate(i, &c);
                if c.checkpoint.next_committee_root.is_some() {
                    self.keep_handover(i, &c);
                }
            }
            Event::EpochComplete(c) => {
                self.on_certificate(i, &c);
                self.keep_handover(i, &c);
                self.handover_of
                    .insert(c.checkpoint.epoch, c.checkpoint.index);
                self.enter_next_epoch(i, &c);
            }
            Event::Equivocation(e) => {
                let Ok(bytes) = bincode::serialize(&*e) else {
                    return;
                };
                let key = *blake3::hash(&bytes).as_bytes();
                if self.nodes[i].behaviour == Behaviour::Honest && self.evidence_seen.insert(key) {
                    self.report.equivocations_detected += 1;
                    let from = self.nodes[i].id;
                    self.send_tx(from, |nonce| SimTx::Evidence {
                        from,
                        evidence: bytes,
                        nonce,
                    });
                }
            }
            Event::VerifierDisagreement { .. } => {
                self.report.verifier_disagreements += 1;
            }
            Event::Unordered(p) => {
                // The node puts these back in its mempool; here the sender
                // times out and sends again, so its order is not its own.
                for part in p.parts().unwrap_or_default() {
                    if let Ok(v) = bincode::deserialize::<Vec<Envelope>>(part) {
                        for e in v {
                            if let Some(s) = self.senders.get_mut(&e.tx.sender()) {
                                s.disturbed = true;
                            }
                        }
                    }
                }
            }
        }
    }

    fn on_certificate(&mut self, i: usize, c: &Certificate) {
        let cp = &c.checkpoint;
        let d = cp.digest();
        match self.cert_digests.get(&cp.index) {
            Some(prev) if *prev != d => self.violation(
                "safety",
                Some(self.nodes[i].id),
                format!("two certificates at checkpoint {}", cp.index),
            ),
            Some(_) => {}
            None => {
                self.cert_digests.insert(cp.index, d);
                if cp.index > self.cert_index {
                    self.cert_index = cp.index;
                    self.last_cert_us = self.now_us;
                    self.report.checkpoints_certified += 1;
                    let done: Vec<u64> = self
                        .certify_wait
                        .range(..=cp.last_height)
                        .map(|(h, _)| *h)
                        .collect();
                    for h in done {
                        for s in self.certify_wait.remove(&h).unwrap_or_default() {
                            if s >= self.cfg.warmup_ms * 1_000 {
                                self.report
                                    .finality_ms
                                    .push((self.now_us.saturating_sub(s)) as f64 / 1_000.0);
                            }
                        }
                    }
                }
            }
        }
    }

    fn keep_handover(&mut self, i: usize, c: &Certificate) {
        let id = self.nodes[i].id;
        let sessions = match self.nodes[i].core.as_ref() {
            Some(core) => core.sessions().bundle(&c.sessions),
            None => return,
        };
        let e = self
            .handovers
            .entry(c.checkpoint.epoch)
            .or_default()
            .entry(c.checkpoint.index)
            .or_insert_with(|| (c.clone(), sessions, Vec::new()));
        if !e.2.contains(&id) {
            e.2.push(id);
        }
    }

    fn enter_next_epoch(&mut self, i: usize, c: &Certificate) {
        let next = self.nodes[i].epoch + 1;
        // Epoch-end journal size, for the storage bound.
        let jb = self.nodes[i].journal_bytes;
        let e = self.epoch_journal.entry(next - 1).or_default();
        *e = (*e).max(jb);
        if jb > self.cfg.limits.max_journal_epoch_bytes {
            self.violation(
                "storage",
                Some(self.nodes[i].id),
                format!("recovery journal reached {jb} bytes in epoch {}", next - 1),
            );
        }
        let mut start = match self.nodes[i].core.as_ref() {
            Some(core) => core.next_epoch_start(c),
            None => return,
        };
        // A validator that took the handover from a certificate without
        // having ordered the epoch's last blocks enters, as the node does,
        // once it has imported and executed them under the certificates
        // covering them: its base is those blocks.
        let last = start.first_height.saturating_sub(1);
        let mut imported = false;
        if start.base_blocks.last().is_none_or(|(h, ..)| *h != last) {
            let keep = tenzro_consensus::STATE_ROOT_LAG + 1;
            let base: Vec<(u64, [u8; 32], [u8; 32])> = (last.saturating_sub(keep - 1)..=last)
                .filter_map(|h| self.ledger.at(h).map(|e| (h, e.block, e.root)))
                .collect();
            if base.last().is_some_and(|(h, ..)| *h == last) {
                start.base_blocks = base;
                imported = true;
                self.report.faults.late_handovers += 1;
            }
        }
        if !self.epochs.contains_key(&next) {
            let Some((committee, members)) = self.pending_committees.remove(&next) else {
                self.violation(
                    "liveness",
                    Some(self.nodes[i].id),
                    format!("epoch {next} handed over with no committee derived"),
                );
                return;
            };
            self.epochs
                .insert(next, (committee, members, start.clone()));
            self.report.epochs = next;
            self.plan_boundary_crash(next);
            self.plan_boundary_partition(next);
            for o in self.observers.iter_mut() {
                o.on_epoch(next, &self.ledger);
            }
            let floor = next.saturating_sub(self.cfg.certificate_retention_epochs);
            self.handovers = self.handovers.split_off(&floor);
            self.handover_of = self.handover_of.split_off(&floor);
            self.epoch_journal = self.epoch_journal.split_off(&next.saturating_sub(4096));
        }
        let (committee, members, _) = self.epochs[&next].clone();
        self.seat(i, next, committee, members, start, imported);
    }

    /// Seats validator `i` in `epoch` (a fresh core from the epoch start), or
    /// retires it if the epoch's committee does not hold it.
    fn seat(
        &mut self,
        i: usize,
        epoch: u64,
        committee: Committee,
        members: Arc<Vec<u32>>,
        start: EpochStart,
        jumped: bool,
    ) {
        let now = self.node_ms(i);
        let id = self.nodes[i].id;
        let at = self.now_us / 1_000;
        let n = &mut self.nodes[i];
        n.last_reset = format!("seated in epoch {epoch} at {at} ms (jumped {jumped})");
        n.epoch = epoch;
        n.epoch_since_us = at * 1_000;
        n.journal.clear();
        n.journal_bytes = 0;
        n.to_sign.clear();
        n.proposed.clear();
        n.extra.clear();
        if jumped {
            n.last_height = n.last_height.max(start.first_height.saturating_sub(1));
            n.executed_through = n.executed_through.max(start.first_height.saturating_sub(1));
        }
        match members.iter().position(|m| *m == id) {
            Some(me) => {
                let mut core = Core::new(
                    self.core_cfg.clone(),
                    committee.clone(),
                    me as ValidatorIndex,
                    start.clone(),
                );
                core.start(now);
                n.core = Some(core);
                n.me = me as ValidatorIndex;
                if n.status == Status::Retired {
                    n.status = Status::Up;
                    n.up_since_us = at * 1_000;
                }
            }
            None => {
                n.core = None;
                if matches!(n.status, Status::Up) {
                    n.status = Status::Retired;
                }
            }
        }
        n.committee = committee;
        n.members = members;
        n.start = start;
        self.reconnect(id);
    }

    fn drain(&mut self, i: usize) {
        let now_us = self.now_us;
        let n = &mut self.nodes[i];
        let Some(core) = n.core.as_mut() else { return };
        let records = core.take_journal();
        if !records.is_empty() {
            n.journal_bytes += records
                .iter()
                .map(|r| bincode::serialized_size(r).unwrap_or(0))
                .sum::<u64>();
            n.journal.extend(records);
        }
        let me = n.me;
        let behaviour = n.behaviour;
        let size = n.committee.size() as ValidatorIndex;
        let mut sends: Vec<(Target, Message)> = Vec::new();
        let outbox = core.take_outbox();
        let mut twice = None;
        for (t, m) in outbox {
            if let Message::Propose(v) = &m
                && v.source == me
            {
                let d = v.digest();
                let first = *n.proposed.entry(v.round).or_insert(d);
                if first != d && behaviour != Behaviour::Equivocate {
                    twice = Some(v.round);
                }
                while n.proposed.len() > 4_096 {
                    n.proposed.pop_first();
                }
            }
            match (&m, behaviour) {
                (_, Behaviour::Mute) => {}
                (Message::Propose(v), Behaviour::Equivocate) => {
                    let mut twin = v.clone();
                    twin.timestamp_ms += 1;
                    for p in (0..size).filter(|p| *p != me) {
                        let msg = if p < size / 2 {
                            m.clone()
                        } else {
                            Message::Propose(twin.clone())
                        };
                        sends.push((Target::One(p), msg));
                    }
                }
                (Message::Propose(v), Behaviour::WithholdLeaderVertex)
                    if core.leads(v.round, me) => {}
                (Message::Propose(_), Behaviour::Withhold) => {
                    for p in (0..size).filter(|p| p % 2 == 0 && *p != me) {
                        sends.push((Target::One(p), m.clone()));
                    }
                }
                (Message::Batch(_), Behaviour::Withhold) => {
                    n.batch_count += 1;
                    if n.batch_count % 2 == 1 {
                        sends.push((t, m));
                    }
                }
                _ => sends.push((t, m)),
            }
        }
        if behaviour != Behaviour::Mute {
            sends.append(&mut n.extra);
        } else {
            n.extra.clear();
        }
        let id = n.id;
        let epoch = n.epoch;
        let members = n.members.clone();
        if let Some(r) = twice {
            self.violation(
                "safety",
                Some(id),
                format!("validator proposed two vertices for round {r} of epoch {epoch} (after a restart)"),
            );
        }
        if sends.is_empty() {
            return;
        }
        // One frame per destination.
        let mut frames: BTreeMap<u32, Vec<Message>> = BTreeMap::new();
        for (t, m) in sends {
            match t {
                Target::All => {
                    for (p, dest) in members.iter().enumerate() {
                        if p as ValidatorIndex != me {
                            frames.entry(*dest).or_default().push(m.clone());
                        }
                    }
                }
                Target::One(p) => {
                    if let Some(dest) = members.get(p as usize) {
                        frames.entry(*dest).or_default().push(m);
                    }
                }
            }
        }
        for (dest, msgs) in frames {
            if !self.carries(id, dest, epoch) {
                continue;
            }
            let bytes: usize = msgs.iter().map(msg_size).sum();
            let cost: u64 = msgs.iter().map(|m| msg_cost(m, self.cfg.verify_us)).sum();
            let n = &mut self.nodes[i];
            n.bytes_out += bytes as u64;
            let ser = (bytes as u64 * 8 * 1_000_000) / self.cfg.uplink_bps.max(1);
            n.egress_free_us = n.egress_free_us.max(now_us) + ser;
            let sent = n.egress_free_us;
            if self.cfg.faults.frame_loss > 0.0
                && self.now_us < self.faults_until_us
                && self.rng.r#gen::<f64>() < self.cfg.faults.frame_loss
            {
                continue;
            }
            let lat = self.latency_us(id, dest);
            self.push_delivery(
                sent + lat,
                Delivery {
                    to: dest,
                    from: me,
                    from_id: id,
                    epoch,
                    msgs: Arc::new(msgs),
                    cost_us: cost,
                    queued: false,
                },
            );
        }
    }

    fn latency_us(&mut self, a: u32, b: u32) -> u64 {
        let (lo, hi) = self.cfg.latency_ms;
        // A fixed base per link plus jitter.
        let base = lo + (((a as u64 * 7_919) ^ (b as u64 * 104_729)) % (hi - lo + 1).max(1));
        let jitter = self.rng.gen_range(0..=base / 5 + 1);
        let mut l = (base + jitter) * 1_000;
        if let Some((until, f)) = self.spike
            && self.now_us < until
        {
            l *= f;
        }
        l
    }

    fn carries(&self, from: u32, to: u32, epoch: u64) -> bool {
        self.links.up.get(&pair(from, to)) == Some(&epoch)
            && self.nodes[to as usize].epoch == epoch
            && self.nodes[to as usize].status == Status::Up
            && !self.cut_off(from, to)
    }

    fn cut_off(&self, a: u32, b: u32) -> bool {
        match &self.partition {
            Some(p) => p.side_a.contains(&a) != p.side_a.contains(&b),
            None => false,
        }
    }

    fn deliver(&mut self, mut d: Delivery) {
        let to = d.to as usize;
        if !self.carries(d.from_id, d.to, d.epoch) {
            return;
        }
        if !d.queued {
            let n = &mut self.nodes[to];
            let cost = d.cost_us * n.slow;
            let done = n.cpu_free_us.max(self.now_us).max(n.stall_until_us) + cost;
            n.cpu_free_us = done;
            n.cpu_busy_us += cost;
            if done > self.now_us + 1_000 {
                d.queued = true;
                self.push_delivery(done, d);
                return;
            }
        }
        let now = self.node_ms(to);
        let bytes: usize = d.msgs.iter().map(msg_size).sum();
        let n = &mut self.nodes[to];
        n.bytes_in += bytes as u64;
        let Some(core) = n.core.as_mut() else { return };
        core.on_messages(d.from, (*d.msgs).clone(), now);
        self.process(to);
    }

    // ---- links ---------------------------------------------------------

    fn reconnect(&mut self, id: u32) {
        self.links.up.retain(|(a, b), _| *a != id && *b != id);
        let epoch = self.nodes[id as usize].epoch;
        if self.nodes[id as usize].status != Status::Up {
            return;
        }
        let peers: Vec<u32> = self.nodes[id as usize]
            .members
            .iter()
            .copied()
            .filter(|p| *p != id)
            .collect();
        for p in peers {
            let d = self.connect_delay_us(id, p);
            let (a, b) = pair(id, p);
            self.links.pending.push((self.now_us + d, a, b, epoch));
        }
    }

    fn connect_due(&mut self) {
        let now = self.now_us;
        let (due, later): (Vec<_>, Vec<_>) = self
            .links
            .pending
            .drain(..)
            .partition(|(at, ..)| *at <= now);
        self.links.pending = later;
        for (_, a, b, e) in due {
            let (na, nb) = (&self.nodes[a as usize], &self.nodes[b as usize]);
            if na.status != Status::Up || nb.status != Status::Up || self.cut_off(a, b) {
                continue;
            }
            if na.epoch != e || nb.epoch != e || self.links.up.contains_key(&(a, b)) {
                continue;
            }
            let (Some(ia), Some(ib)) = (
                na.members.iter().position(|m| *m == a),
                na.members.iter().position(|m| *m == b),
            ) else {
                continue;
            };
            self.links.up.insert((a, b), e);
            let (ma, mb) = (self.node_ms(a as usize), self.node_ms(b as usize));
            if let Some(c) = self.nodes[a as usize].core.as_mut() {
                c.on_peer_up(ib as ValidatorIndex, ma);
            }
            if let Some(c) = self.nodes[b as usize].core.as_mut() {
                c.on_peer_up(ia as ValidatorIndex, mb);
            }
            self.process(a as usize);
            self.process(b as usize);
        }
    }

    /// Certificates travel to every validator a peer still reaches, its
    /// consensus channels up or not.
    fn gossip(&mut self) {
        self.connect_due();
        for i in 0..self.nodes.len() {
            for _ in 0..64 {
                let n = &self.nodes[i];
                if n.status != Status::Up || n.core.is_none() {
                    break;
                }
                let epoch = n.epoch;
                let id = n.id;
                let have = n
                    .core
                    .as_ref()
                    .and_then(|c| c.latest_certificate())
                    .map(|c| c.checkpoint.index);
                let carried: Vec<(Certificate, Vec<SessionCertificate>)> = self
                    .handovers
                    .get(&epoch)
                    .map(|m| {
                        m.values()
                            .filter(|(c, _, holders)| {
                                have.is_none_or(|h| c.checkpoint.index > h)
                                    && holders.iter().any(|h| {
                                        // A holder the next epoch did not
                                        // seat still runs and serves it, as
                                        // block sync asks every member of
                                        // the epoch it ended.
                                        *h != id
                                            && !matches!(
                                                self.nodes[*h as usize].status,
                                                Status::Down { .. }
                                            )
                                            && !self.cut_off(*h, id)
                                    })
                            })
                            .map(|(c, s, _)| (c.clone(), s.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                if carried.is_empty() {
                    break;
                }
                let handover = self.handover_of.get(&epoch).copied();
                for (c, s) in carried {
                    if let Some(core) = self.nodes[i].core.as_mut() {
                        if handover == Some(c.checkpoint.index) {
                            core.adopt_handover(c, s);
                        } else {
                            core.adopt_certificate(c, s);
                        }
                    }
                }
                let now = self.node_ms(i);
                if let Some(core) = self.nodes[i].core.as_mut() {
                    core.on_tick(now);
                }
                self.process(i);
                if self.nodes[i].epoch == epoch {
                    break;
                }
            }
        }
    }

    // ---- once a second: faults, clients, invariants ----------------------

    fn second(&mut self) {
        self.faults();
        self.fast_forward();
        self.join_seated();
        self.clients();
        self.check();
    }

    /// As the node does: a validator whose epoch a reachable peer certified
    /// more than the DAG's garbage-collection depth past its reach round
    /// takes that checkpoint's ordering state from a peer and orders
    /// on from there; the blocks up to it it imports. One still waiting for
    /// the state after two seconds moves on to the latest checkpoint.
    fn fast_forward(&mut self) {
        let gc = self.core_cfg.gc_depth;
        for i in 0..self.nodes.len() {
            let n = &self.nodes[i];
            if n.status != Status::Up {
                continue;
            }
            let Some(core) = n.core.as_ref() else {
                continue;
            };
            let (id, epoch) = (n.id, n.epoch);
            let committed = core.reach_round().unwrap_or(0);
            let resuming = core.resuming_from().map(|c| c.checkpoint.index);
            let waited = n
                .fast_forward_since_us
                .is_some_and(|t| self.now_us.saturating_sub(t) >= 2_000_000);
            let mut best: Option<(Certificate, Vec<SessionCertificate>)> = None;
            for p in &self.nodes {
                if p.id == id
                    || p.status != Status::Up
                    || p.epoch != epoch
                    || self.cut_off(p.id, id)
                {
                    continue;
                }
                let Some(pc) = p.core.as_ref() else { continue };
                let Some(c) = pc.latest_certificate() else {
                    continue;
                };
                if c.checkpoint.epoch != epoch
                    || c.checkpoint.next_committee_root.is_some()
                    || best
                        .as_ref()
                        .is_some_and(|(b, _)| b.checkpoint.index >= c.checkpoint.index)
                {
                    continue;
                }
                best = Some((c.clone(), pc.sessions().bundle(&c.sessions)));
            }
            let Some((c, sessions)) = best else { continue };
            let due = match resuming {
                Some(r) => waited && c.checkpoint.index > r,
                None => c.checkpoint.anchor_round > committed + gc,
            };
            if !due {
                continue;
            }
            let now = self.node_ms(i);
            let at = self.now_us / 1_000;
            let last = c.checkpoint.last_height;
            let base: Vec<(u64, [u8; 32], [u8; 32])> =
                (last.saturating_sub(tenzro_consensus::STATE_ROOT_LAG)..=last)
                    .filter_map(|h| self.ledger.at(h).map(|e| (h, e.block, e.root)))
                    .collect();
            let n = &mut self.nodes[i];
            let old = n.core.as_ref().expect("checked above");
            let mut core = Core::resume(
                self.core_cfg.clone(),
                n.committee.clone(),
                n.me,
                c.clone(),
                sessions,
                old.round(),
                old.next_batch_sequence(),
                n.executed_through.max(last),
                old.leader_lookahead(),
            );
            for (h, block, root) in base {
                core.on_executed(h, block, root, Vec::new());
            }
            core.start(now);
            n.core = Some(core);
            n.last_height = n.last_height.max(last);
            n.executed_through = n.executed_through.max(last);
            n.to_sign.clear();
            n.fast_forward_since_us = Some(self.now_us);
            n.last_reset = format!(
                "fast-forwarded in epoch {epoch} to checkpoint {} at {at} ms",
                c.checkpoint.index
            );
            if resuming.is_none() {
                self.report.faults.fast_forwards += 1;
            }
            self.process(i);
        }
    }

    fn quorum_ok(&self, excluding: &[u32]) -> bool {
        let Some((_, (committee, members, _))) = self.epochs.last_key_value() else {
            return false;
        };
        let bad: u64 = members
            .iter()
            .enumerate()
            .filter(|(_, id)| {
                let n = &self.nodes[**id as usize];
                n.status != Status::Up || n.behaviour != Behaviour::Honest || excluding.contains(id)
            })
            .map(|(i, _)| committee.seats(i as ValidatorIndex))
            .sum();
        let f = (committee.total_seats().saturating_sub(1)) / 3;
        bad <= f
    }

    /// Places the crash of the epoch the network just entered: a
    /// non-negative offset counts from this entry, a negative one back from
    /// the next boundary, predicted one epoch length after it.
    fn plan_boundary_crash(&mut self, epoch: u64) {
        let Some(b) = self.cfg.faults.boundary_crashes.clone() else {
            return;
        };
        if b.offsets_ms.is_empty() {
            return;
        }
        let len = b.offsets_ms.len() as u64;
        let offset = b.offsets_ms[(epoch % len) as usize];
        let members = self.epochs[&epoch].1.clone();
        if members.is_empty() {
            return;
        }
        let target = members[((epoch / len) % members.len() as u64) as usize];
        let entry_ms = self.now_us / 1_000;
        let at_ms = if offset >= 0 {
            entry_ms + offset as u64
        } else {
            (entry_ms + self.cfg.epoch_ms()).saturating_sub(offset.unsigned_abs())
        };
        self.boundary_due = Some((at_ms * 1_000, target));
    }

    /// Extra signing latency the boundary burst gives validator `i` for
    /// checkpoint `cp`.
    fn sign_burst_ms(&self, i: usize, cp: &Checkpoint) -> u64 {
        let Some(b) = self.cfg.faults.boundary_sign_burst.as_ref() else {
            return 0;
        };
        if self.now_us >= self.faults_until_us {
            return 0;
        }
        let Some((_, members, start)) = self.epochs.get(&cp.epoch) else {
            return 0;
        };
        let pos = cp.index.saturating_sub(start.first_checkpoint);
        if pos < b.index_from || pos > b.index_to || members.is_empty() {
            return 0;
        }
        let id = self.nodes[i].id;
        let n = members.len() as u64;
        let slowed = (0..u64::from(b.validators).min(n))
            .any(|j| members[((cp.epoch + j) % n) as usize] == id);
        if slowed { b.extra_ms } else { 0 }
    }

    /// Places the boundary partition of the epoch just entered: a side of
    /// the committee cut off from an offset around the next boundary
    /// (predicted one epoch length after this entry) for a window, healed by
    /// the usual partition expiry. Honest-only and slow-excluded sides keep
    /// the quorum under test; the side size is capped so the honest set
    /// stays a quorum.
    fn plan_boundary_partition(&mut self, epoch: u64) {
        let Some(b) = self.cfg.faults.boundary_partitions.clone() else {
            return;
        };
        let cal_day = self.ledger.calendar_ms as f64 / 86_400_000.0;
        if cal_day < b.from_day || cal_day > b.to_day {
            self.boundary_partition_due = None;
            return;
        }
        let members = self.epochs[&epoch].1.clone();
        if members.is_empty() {
            return;
        }
        let byz: std::collections::HashSet<u32> =
            self.cfg.faults.byzantine.iter().map(|(v, _)| *v).collect();
        let eligible: Vec<u32> = members
            .iter()
            .copied()
            .filter(|v| !(b.honest_only && byz.contains(v)))
            .filter(|v| !(b.exclude_slow && self.nodes[*v as usize].slow > 1))
            .collect();
        if eligible.is_empty() {
            return;
        }
        let f = (members.len().saturating_sub(1)) / 3;
        let cap = f.saturating_sub(byz.len());
        let size = (b.side_size as usize).min(cap).min(eligible.len());
        if size == 0 {
            return;
        }
        let shift = if b.rotate {
            (epoch as usize) % eligible.len()
        } else {
            0
        };
        let side: Vec<u32> = (0..size)
            .map(|j| eligible[(shift + j) % eligible.len()])
            .collect();
        let entry_ms = self.now_us / 1_000;
        let boundary_ms = entry_ms + self.cfg.epoch_ms();
        let at_ms = if b.start_offset_ms >= 0 {
            boundary_ms + b.start_offset_ms as u64
        } else {
            boundary_ms.saturating_sub(b.start_offset_ms.unsigned_abs())
        };
        self.boundary_partition_due = Some((at_ms * 1_000, (at_ms + b.duration_ms) * 1_000, side));
    }

    /// Installs a due boundary partition once no other partition is active;
    /// the usual partition-expiry path heals it.
    fn boundary_partition(&mut self, now: u64) {
        let Some((at, until, side)) = self.boundary_partition_due.clone() else {
            return;
        };
        if now < at || until <= now || self.partition.is_some() {
            return;
        }
        self.boundary_partition_due = None;
        let side_a: HashSet<u32> = side.into_iter().collect();
        self.partition = Some(Partition {
            until_us: until,
            side_a,
            quorum_loss: false,
        });
        self.report.faults.partitions += 1;
        let cut: Vec<(u32, u32)> = self
            .links
            .up
            .keys()
            .copied()
            .filter(|(a, b)| self.cut_off(*a, *b))
            .collect();
        for k in cut {
            self.links.up.remove(&k);
        }
    }

    fn boundary_crash(&mut self) {
        let now = self.now_us;
        let Some((at, id)) = self.boundary_due else {
            return;
        };
        if now < at {
            return;
        }
        self.boundary_due = None;
        let Some(b) = self.cfg.faults.boundary_crashes.clone() else {
            return;
        };
        let i = id as usize;
        if i >= self.nodes.len()
            || self.nodes[i].status != Status::Up
            || self.nodes[i].behaviour != Behaviour::Honest
            || !self.quorum_ok(&[id])
        {
            return;
        }
        self.crash(i, now + b.down_ms * 1_000, false);
    }

    fn faults(&mut self) {
        let now = self.now_us;
        // Recoveries.
        for i in 0..self.nodes.len() {
            if let Status::Down { until_us, long } = self.nodes[i].status
                && until_us <= now
            {
                self.restart(i, long);
            }
        }
        if let Some(p) = &self.partition
            && p.until_us <= now
        {
            self.partition = None;
            self.report.faults.partitions_healed += 1;
            let ids: Vec<u32> = (0..self.nodes.len() as u32).collect();
            for id in ids {
                self.reconnect_cross(id);
            }
        }
        if self.spike.is_some_and(|(u, _)| u <= now) {
            self.spike = None;
        }
        if self.partition.is_some() || self.spike.is_some() {
            self.calm_since_us = now;
        }
        for n in &self.nodes {
            if n.status == Status::Up && n.stall_until_us > 0 && n.stall_until_us + 1_000_000 > now
            {
                self.calm_since_us = now;
            }
        }
        if now < self.cfg.warmup_ms * 1_000 || now >= self.faults_until_us {
            return;
        }
        self.boundary_crash();
        self.boundary_partition(now);
        let f = self.cfg.faults.clone();
        let per_s = |per_hour: f64| per_hour / 3_600.0;
        // Disk stalls: the event loop blocks on storage.
        if f.disk_stalls_per_node_hour > 0.0 {
            for i in 0..self.nodes.len() {
                if self.nodes[i].status != Status::Up || self.stalled(i) {
                    continue;
                }
                if self.rng.r#gen::<f64>() >= per_s(f.disk_stalls_per_node_hour) {
                    continue;
                }
                let ms = self.rng.gen_range(f.disk_stall_ms.0..=f.disk_stall_ms.1);
                self.nodes[i].stall_until_us = now + ms * 1_000;
                self.calm_since_us = now;
                self.report.faults.disk_stalls += 1;
            }
        }
        // Crashes, within f together with the byzantine ones.
        for i in 0..self.nodes.len() {
            if self.nodes[i].status != Status::Up || self.nodes[i].behaviour != Behaviour::Honest {
                continue;
            }
            if self.rng.r#gen::<f64>() >= per_s(f.crashes_per_node_hour) {
                continue;
            }
            let id = self.nodes[i].id;
            if !self.quorum_ok(&[id]) {
                continue;
            }
            let long = self.rng.r#gen::<f64>() < f.long_down_share;
            let down_ms = if long {
                self.rng
                    .gen_range(f.long_down_epochs.0..=f.long_down_epochs.1)
                    * self.cfg.epoch_ms()
            } else {
                self.rng.gen_range(f.short_down_ms.0..=f.short_down_ms.1)
            };
            self.crash(i, now + down_ms * 1_000, long);
        }
        if self.partition.is_none() && self.rng.r#gen::<f64>() < per_s(f.partitions_per_hour) {
            let ids: Vec<u32> = self
                .epochs
                .last_key_value()
                .map(|(_, e)| (*e.1).clone())
                .unwrap_or_default();
            let quorum_loss = self.rng.r#gen::<f64>() < f.quorum_loss_share;
            let mut side_a = HashSet::new();
            let take = if quorum_loss {
                ids.len().div_ceil(2)
            } else {
                (ids.len().saturating_sub(1)) / 3
            };
            let mut pool = ids.clone();
            for _ in 0..take.max(1) {
                if pool.is_empty() {
                    break;
                }
                let k = self.rng.gen_range(0..pool.len());
                side_a.insert(pool.swap_remove(k));
            }
            let dur = self.rng.gen_range(f.partition_ms.0..=f.partition_ms.1);
            self.partition = Some(Partition {
                until_us: now + dur * 1_000,
                side_a,
                quorum_loss,
            });
            self.report.faults.partitions += 1;
            if quorum_loss {
                self.report.faults.quorum_losses += 1;
            }
            let cut: Vec<(u32, u32)> = self
                .links
                .up
                .keys()
                .copied()
                .filter(|(a, b)| self.cut_off(*a, *b))
                .collect();
            for k in cut {
                self.links.up.remove(&k);
            }
        }
        if self.spike.is_none() && self.rng.r#gen::<f64>() < per_s(f.spikes_per_hour) {
            let dur = self.rng.gen_range(f.spike_ms.0..=f.spike_ms.1);
            let factor = self.rng.gen_range(f.spike_factor.0..=f.spike_factor.1);
            self.spike = Some((now + dur * 1_000, factor));
            self.report.faults.delay_spikes += 1;
        }
    }

    fn reconnect_cross(&mut self, id: u32) {
        if self.nodes[id as usize].status != Status::Up {
            return;
        }
        let epoch = self.nodes[id as usize].epoch;
        let peers: Vec<u32> = self.nodes[id as usize]
            .members
            .iter()
            .copied()
            .filter(|p| *p > id)
            .collect();
        for p in peers {
            if !self.links.up.contains_key(&(id, p)) {
                let d = self.connect_delay_us(id, p);
                self.links.pending.push((self.now_us + d, id, p, epoch));
            }
        }
    }

    fn crash(&mut self, i: usize, until_us: u64, long: bool) {
        let id = self.nodes[i].id;
        let n = &mut self.nodes[i];
        // Everything in memory is lost; the journal, the vote high-water
        // mark, the executed height and the epoch's start are on disk.
        n.core = None;
        n.status = Status::Down { until_us, long };
        n.session_cert = None;
        n.to_sign.clear();
        n.extra.clear();
        n.clients.clear();
        n.rejoin = None;
        n.stall_until_us = 0;
        self.links.up.retain(|(a, b), _| *a != id && *b != id);
        for s in self.senders.values_mut() {
            if s.node == id {
                s.disturbed = true;
            }
        }
        self.report.faults.crashes += 1;
        if long {
            self.report.faults.long_downtimes += 1;
        }
    }

    fn restart(&mut self, i: usize, long: bool) {
        let f = self.cfg.faults.max_skew_ms as i64;
        if f > 0 {
            self.nodes[i].skew_ms = self.rng.gen_range(-f..=f);
        }
        self.nodes[i].status = Status::Up;
        self.nodes[i].up_since_us = self.now_us;
        if let Some(Err(e)) = self.nodes[i].blocks.as_mut().map(|b| b.reopen()) {
            self.nodes[i].exec_halted = true;
            let id = self.nodes[i].id;
            self.violation("execution", Some(id), format!("on restart: {e}"));
        }
        let now = self.node_ms(i);
        let id = self.nodes[i].id;
        let latest = *self.epochs.last_key_value().map(|(e, _)| e).unwrap_or(&0);
        let floor = latest.saturating_sub(self.cfg.certificate_retention_epochs);
        let n = &self.nodes[i];
        if n.epoch < floor || !n.members.contains(&id) {
            // Too far behind for the certificates peers keep: it syncs the
            // certified chain to the running epoch.
            let (c, m, s) = self.epochs[&latest].clone();
            self.seat(i, latest, c, m, s, true);
            self.report.faults.synced_restarts += 1;
        } else {
            let at = self.now_us / 1_000;
            let n = &mut self.nodes[i];
            n.last_reset = format!(
                "recovered in epoch {} at {at} ms, executed through {}",
                n.epoch, n.executed_through
            );
            let mut core = Core::recover(
                self.core_cfg.clone(),
                n.committee.clone(),
                n.me,
                n.start.clone(),
                n.journal.clone(),
                n.executed_through,
                now,
            );
            core.start(now);
            n.core = Some(core);
            self.reconnect(id);
            self.process(i);
        }
        self.track_rejoin(
            i,
            if long {
                "restart after a long downtime"
            } else {
                "restart"
            },
        );
    }

    fn track_rejoin(&mut self, i: usize, reason: &'static str) {
        // A mute node sends nothing, not even a sync request, so it is never
        // expected to catch up after a restart.
        if self.nodes[i].behaviour == Behaviour::Mute {
            return;
        }
        let latest = *self.epochs.last_key_value().map(|(e, _)| e).unwrap_or(&0);
        self.nodes[i].rejoin = Some(Rejoin {
            since_us: self.now_us,
            epoch: latest,
            height: self.network_height,
            live_ms: 0,
            reason,
        });
    }

    /// A registered validator the running epoch seats, but that holds no
    /// core, starts one from the epoch's certified start.
    fn join_seated(&mut self) {
        let Some((&latest, (c, m, s))) = self.epochs.last_key_value() else {
            return;
        };
        let (c, m, s) = (c.clone(), m.clone(), s.clone());
        for i in 0..self.nodes.len() {
            let n = &self.nodes[i];
            if n.status == Status::Retired && m.contains(&n.id) {
                self.seat(i, latest, c.clone(), m.clone(), s.clone(), true);
                self.report.joins += 1;
                self.track_rejoin(i, "newly seated");
            } else if n.status == Status::Up && n.core.is_none() {
                self.nodes[i].status = Status::Retired;
            }
        }
    }

    // ---- clients -------------------------------------------------------

    fn entry_node(&mut self) -> Option<usize> {
        let up: Vec<usize> = (0..self.nodes.len())
            .filter(|i| self.nodes[*i].status == Status::Up && self.nodes[*i].core.is_some())
            .collect();
        if up.is_empty() {
            return None;
        }
        Some(up[self.rng.gen_range(0..up.len())])
    }

    /// The validator that batches `tx` first, as the node routes it, or
    /// another one up when that one is not (true).
    fn route(&mut self, tx: &SimTx) -> Option<(usize, bool)> {
        if let Some((_, (committee, members, _))) = self.epochs.last_key_value() {
            let k = batching_index(tx, committee.size() as u64) as usize;
            if let Some(&id) = members.get(k) {
                let n = &self.nodes[id as usize];
                if n.status == Status::Up && n.core.is_some() && !n.exec_halted {
                    return Some((id as usize, false));
                }
            }
        }
        self.entry_node().map(|i| (i, true))
    }

    fn send_tx(&mut self, from: u32, make: impl FnOnce(u64) -> SimTx) -> bool {
        let pipeline = self.cfg.workload.pipeline.max(1);
        let ahead = self.senders.get(&from).map_or(0, |s| s.count);
        if ahead >= pipeline {
            return false;
        }
        let tx = make(self.ledger.nonce(from) + ahead as u64);
        let Some((i, rerouted)) = self.route(&tx) else {
            return false;
        };
        let now = self.now_us;
        let id = self.nodes[i].id;
        let epoch = self.epochs.last_key_value().map_or(0, |(e, _)| *e);
        let s = self.senders.entry(from).or_insert(Sending {
            epoch,
            count: 0,
            since_us: now,
            node: id,
            disturbed: false,
            sent: BTreeMap::new(),
            retries: 0,
        });
        // Rerouted by failover, or by a committee change while some were in
        // flight: its order is no longer one validator's.
        if s.count > 0 && s.epoch != epoch {
            s.disturbed = true;
        }
        s.disturbed |= rerouted;
        s.epoch = epoch;
        s.count += 1;
        s.since_us = now;
        s.node = id;
        s.sent.insert(tx.nonce(), (id, now / 1_000));
        while s.sent.len() > 64 {
            s.sent.pop_first();
        }
        self.nodes[i].clients.push(Envelope {
            submitted_ms: now / 1_000,
            tx,
        });
        self.report.txs_submitted += 1;
        self.last_submit_us = now;
        true
    }

    fn clients(&mut self) {
        // In-flight transactions a crash or a lost batch dropped.
        let now = self.now_us;
        // A sender that heard nothing for a minute starts again from the
        // chain's nonce; what it had in flight may still land, out of its
        // order.
        for s in self.senders.values_mut() {
            if s.count > 0 && now - s.since_us >= 60_000_000 {
                s.count = 0;
                s.disturbed = true;
            }
        }
        let w = self.cfg.workload.clone();
        if w.users > 1 && w.transfers_per_s > 0.0 {
            let mut k = w.transfers_per_s.floor() as u64;
            if self.rng.r#gen::<f64>() < w.transfers_per_s.fract() {
                k += 1;
            }
            for _ in 0..k {
                let from = USER_BASE + self.rng.gen_range(0..w.users);
                let to = USER_BASE + self.rng.gen_range(0..w.users);
                if from == to {
                    continue;
                }
                let amount = self.rng.gen_range(1..1_000u128) * TNZO / 1_000;
                self.send_tx(from, |nonce| SimTx::Transfer {
                    from,
                    to,
                    amount,
                    nonce,
                });
            }
        }
        self.governance();
        self.staking();
        let mut drivers = std::mem::take(&mut self.drivers);
        for d in drivers.iter_mut() {
            for tx in d.step(self.now_us, &self.ledger, &mut self.rng) {
                let from = tx.sender();
                self.send_tx(from, |nonce| with_nonce(tx, nonce));
            }
        }
        self.drivers = drivers;
    }

    fn after_block(&mut self, height: u64) {
        let results = std::mem::take(&mut self.ledger.results);
        for d in self.drivers.iter_mut() {
            d.results(&results);
        }
        for r in results {
            let from = r.tx.sender();
            if let Some(s) = self.senders.get_mut(&from) {
                // Ahead of its nonce with its predecessor still in flight:
                // the node keeps it in its mempool and runs it when it is
                // ordered again.
                let ahead = !r.applied
                    && !s.disturbed
                    && r.error.contains("Invalid nonce")
                    && s.sent.contains_key(&r.tx.nonce().saturating_sub(1));
                if ahead && s.retries < MAX_REQUEUES {
                    s.retries += 1;
                    let node = s.node as usize;
                    self.report.ahead_of_nonce += 1;
                    if self.nodes[node].status == Status::Up {
                        self.nodes[node].clients.push(Envelope {
                            submitted_ms: r.submitted_ms,
                            tx: r.tx.clone(),
                        });
                        continue;
                    }
                }
                let s = self.senders.get_mut(&from).expect("sender");
                // A transaction refused for any other reason may leave its
                // nonce unused, and the sender's next ones fail behind it.
                s.disturbed |= !r.applied;
                s.count = s.count.saturating_sub(1);
                s.since_us = self.now_us;
                if s.count == 0 {
                    self.senders.remove(&from);
                }
            }
            if r.submitted_ms * 1_000 >= self.cfg.warmup_ms * 1_000 {
                self.report
                    .ordered_ms
                    .push(self.now_us.saturating_sub(r.submitted_ms * 1_000) as f64 / 1_000.0);
                self.certify_wait
                    .entry(height)
                    .or_default()
                    .push(r.submitted_ms * 1_000);
            }
            if r.applied && r.submitted_ms * 1_000 >= self.cfg.warmup_ms * 1_000 {
                self.report.txs_in_window += 1;
            }
            self.on_result(&r);
        }
    }

    fn on_result(&mut self, r: &ledger::TxResult) {
        let cal = self.ledger.calendar_ms;
        match &r.tx {
            SimTx::Propose { .. } => {
                if let Some(p) = self.gov.active.as_mut() {
                    if r.applied {
                        p.id = Some(r.output.clone());
                        p.stage = GovStage::Voting;
                        p.proposed_cal = cal;
                        self.report.governance.proposed += 1;
                        let voters: Vec<u32> = self.active_honest();
                        let id = r.output.clone();
                        for v in voters {
                            let id = id.clone();
                            self.send_tx(v, |nonce| SimTx::Vote {
                                from: v,
                                proposal: id,
                                nonce,
                            });
                        }
                    } else {
                        let e = format!("{} proposal refused: {}", p.kind, r.error);
                        self.gov.failures.push(e);
                        self.gov.active = None;
                    }
                }
            }
            SimTx::Vote { .. } => {
                if r.applied {
                    self.report.governance.votes += 1;
                }
            }
            SimTx::Execute { .. } => {
                if let Some(p) = self.gov.active.as_mut() {
                    match (p.stage, r.applied) {
                        (GovStage::Closing, true) => {
                            let timelock =
                                tenzro_vm::governance::GovernanceRules::GENESIS.timelock_ms;
                            p.stage = GovStage::Timelock {
                                enact_after: cal + timelock + timelock / 10,
                            };
                        }
                        (GovStage::Enacting, true) => {
                            *self.gov.kinds_done.entry(p.kind).or_default() += 1;
                            self.report.governance.enacted += 1;
                            self.gov.active = None;
                        }
                        (stage, false) => {
                            // Too early or refused: try again an hour later, a few times.
                            p.retry_at_cal = cal + 3_600_000;
                            p.stage = match stage {
                                GovStage::Enacting => GovStage::Timelock {
                                    enact_after: cal + 3_600_000,
                                },
                                _ => GovStage::Voting,
                            };
                            self.gov
                                .failures
                                .push(format!("{} execute refused: {}", p.kind, r.error));
                            if self.gov.failures.len() > 200 {
                                self.gov.failures.remove(0);
                            }
                        }
                        _ => {}
                    }
                }
            }
            SimTx::IncreaseStake { from, .. } => {
                if !r.applied {
                    self.report
                        .workload_errors
                        .push(format!("stake increase by {from} refused: {}", r.error));
                }
            }
            SimTx::Exit { from, .. } => {
                if r.applied {
                    if self.stake.unbonding.contains_key(from) && r.output.is_empty() {
                        // Output carries no step; the bond tells which it was.
                    }
                    if self.cfg.faults.exit_goes_mute
                        && (*from as usize) < self.nodes.len()
                        && self.nodes[*from as usize].behaviour == Behaviour::Honest
                    {
                        self.nodes[*from as usize].behaviour = Behaviour::Mute;
                        self.nodes[*from as usize].rejoin = None;
                    }
                } else {
                    self.report
                        .workload_errors
                        .push(format!("exit by {from} refused: {}", r.error));
                }
            }
            SimTx::Evidence { .. } => {
                if r.applied {
                    self.report.slashes += 1;
                } else {
                    self.report
                        .workload_errors
                        .push(format!("evidence refused: {}", r.error));
                }
            }
            SimTx::Transfer { .. } | SimTx::Call { .. } => {}
        }
        self.report.workload_errors.truncate(200);
    }

    fn active_honest(&self) -> Vec<u32> {
        self.ledger
            .bonds_now()
            .iter()
            .enumerate()
            .filter(|(v, b)| **b >= TNZO && self.nodes[*v].behaviour == Behaviour::Honest)
            .map(|(v, _)| v as u32)
            .collect()
    }

    fn governance(&mut self) {
        if self.cfg.workload.governance_every_days <= 0.0
            && self.cfg.workload.param_schedule.is_empty()
        {
            return;
        }
        let cal = self.ledger.calendar_ms;
        let rules = tenzro_vm::governance::GovernanceRules::GENESIS;
        match self
            .gov
            .active
            .as_ref()
            .map(|p| (p.stage, p.proposed_cal, p.retry_at_cal, p.id.clone()))
        {
            None => {
                // A workload parameter schedule takes priority: open the next
                // entry whose day has arrived, one at a time, regardless of
                // the periodic cadence.
                if let Some(entry) = self
                    .cfg
                    .workload
                    .param_schedule
                    .get(self.gov.sched_idx)
                    .cloned()
                {
                    if cal < (entry.day * 86_400_000.0) as i64 {
                        return;
                    }
                    let Some(&proposer) = self.active_honest().first() else {
                        return;
                    };
                    let action = ledger::parameter_change(&entry.name, entry.value);
                    if self.send_tx(proposer, |nonce| SimTx::Propose {
                        from: proposer,
                        action,
                        nonce,
                    }) {
                        self.gov.sched_idx += 1;
                        self.gov.proposals += 1;
                        self.gov.active = Some(Proposal {
                            kind: "scheduled parameter",
                            id: None,
                            proposed_cal: cal,
                            stage: GovStage::Proposing,
                            retry_at_cal: 0,
                        });
                    }
                    return;
                }
                if self.cfg.workload.governance_every_days <= 0.0 {
                    return;
                }
                if cal < self.gov.next_cal_ms {
                    return;
                }
                let Some(&proposer) = self.active_honest().first() else {
                    return;
                };
                let turn = self.gov.turn;
                let (kind, action) = if turn.is_multiple_of(2) {
                    let key = "agent.remote_grant_budget_divisor";
                    let v = self.ledger.param(key);
                    (
                        "parameter change",
                        ledger::parameter_change(
                            key,
                            if turn.is_multiple_of(4) {
                                v + 1
                            } else {
                                v.saturating_sub(1).max(1)
                            },
                        ),
                    )
                } else {
                    (
                        "treasury grant",
                        ledger::treasury_grant(USER_BASE, TNZO / 100),
                    )
                };
                if self.send_tx(proposer, |nonce| SimTx::Propose {
                    from: proposer,
                    action,
                    nonce,
                }) {
                    self.gov.turn += 1;
                    self.gov.proposals += 1;
                    self.gov.next_cal_ms =
                        cal + (self.cfg.workload.governance_every_days * 86_400_000.0) as i64;
                    self.gov.active = Some(Proposal {
                        kind,
                        id: None,
                        proposed_cal: cal,
                        stage: GovStage::Proposing,
                        retry_at_cal: 0,
                    });
                }
            }
            Some((GovStage::Proposing, proposed, ..)) => {
                if cal > proposed + 86_400_000 {
                    self.gov.failures.push("proposal never executed".into());
                    self.gov.active = None;
                }
            }
            Some((GovStage::Voting, proposed, retry, Some(id))) => {
                let close = proposed + rules.voting_period_ms + rules.voting_period_ms / 10;
                if cal >= close.max(retry) {
                    let Some(&from) = self.active_honest().first() else {
                        return;
                    };
                    if self.send_tx(from, |nonce| SimTx::Execute {
                        from,
                        proposal: id,
                        nonce,
                    }) && let Some(p) = self.gov.active.as_mut()
                    {
                        p.stage = GovStage::Closing;
                    }
                }
                if cal > proposed + 60 * 86_400_000 {
                    self.gov.failures.push("proposal stuck for 60 days".into());
                    self.gov.active = None;
                }
            }
            Some((GovStage::Timelock { enact_after }, proposed, _, Some(id))) => {
                if cal >= enact_after {
                    let Some(&from) = self.active_honest().first() else {
                        return;
                    };
                    if self.send_tx(from, |nonce| SimTx::Execute {
                        from,
                        proposal: id,
                        nonce,
                    }) && let Some(p) = self.gov.active.as_mut()
                    {
                        p.stage = GovStage::Enacting;
                    }
                }
                if cal > proposed + 60 * 86_400_000 {
                    self.gov.failures.push("proposal stuck for 60 days".into());
                    self.gov.active = None;
                }
            }
            Some((_, proposed, ..)) => {
                if cal > proposed + 60 * 86_400_000 {
                    self.gov.failures.push("proposal stuck for 60 days".into());
                    self.gov.active = None;
                }
            }
        }
    }

    fn staking(&mut self) {
        if self.cfg.workload.stake_every_days <= 0.0 {
            return;
        }
        let cal = self.ledger.calendar_ms;
        // Withdraw what finished unbonding.
        let unbonding = self.ledger.param("staking.validator_unbonding_ms") as i64;
        let due: Vec<u32> = self
            .stake
            .unbonding
            .iter()
            .filter(|(_, since)| cal > **since + unbonding + unbonding / 10)
            .map(|(v, _)| *v)
            .collect();
        for v in due {
            if self.send_tx(v, |nonce| SimTx::Exit { from: v, nonce }) {
                self.stake.unbonding.remove(&v);
                self.stake.withdrawals += 1;
            }
        }
        if cal < self.stake.next_cal_ms {
            return;
        }
        self.stake.next_cal_ms = cal + (self.cfg.workload.stake_every_days * 86_400_000.0) as i64;
        let bonds = self.ledger.bonds_now().to_vec();
        let active: Vec<u32> = self.active_honest();
        let all_active = bonds.iter().filter(|b| **b >= TNZO).count();
        // One registered validator without a bond joins.
        let idle: Vec<u32> = (0..bonds.len() as u32)
            .filter(|v| bonds[*v as usize] < TNZO && !self.stake.unbonding.contains_key(v))
            .collect();
        if let Some(&v) = idle.get(
            self.rng
                .gen_range(0..idle.len().max(1))
                .min(idle.len().saturating_sub(1)),
        ) && !idle.is_empty()
            && self.send_tx(v, |nonce| SimTx::IncreaseStake {
                from: v,
                amount: 100_000 * TNZO,
                nonce,
            })
        {
            self.stake.joins += 1;
        }
        // One validator leaves, keeping at least the genesis count seated.
        if all_active > self.cfg.validators as usize && active.len() > 1 {
            let v = active[self.rng.gen_range(0..active.len())];
            if self.send_tx(v, |nonce| SimTx::Exit { from: v, nonce }) {
                self.stake.unbonding.insert(v, cal);
                self.stake.exits += 1;
            }
        }
        // One tops up, which moves seats.
        if let Some(&v) = active.get(self.rng.gen_range(0..active.len().max(1))) {
            let amount = self.rng.gen_range(1..20_000u128) * TNZO;
            if self.send_tx(v, |nonce| SimTx::IncreaseStake {
                from: v,
                amount,
                nonce,
            }) {
                self.stake.top_ups += 1;
            }
        }
    }

    // ---- invariants ------------------------------------------------------

    /// Every validator's state, for a liveness report: what each one runs
    /// and how far its core got.
    fn node_states(&self) -> String {
        let mut out = String::from("; validators:");
        for n in &self.nodes {
            let status = match n.status {
                Status::Up => "up",
                Status::Down { .. } => "down",
                Status::Retired => "retired",
            };
            out.push_str(&format!(
                " [{} {status} epoch {} height {}",
                n.id, n.epoch, n.last_height
            ));
            if let Some(core) = n.core.as_ref() {
                let s = core.stats();
                out.push_str(&format!(
                    " round {:?} committed {:?} next height {} certified {:?}",
                    s.round,
                    s.last_committed,
                    s.next_height,
                    core.latest_certificate().map(|c| c.checkpoint.index)
                ));
            }
            out.push_str(&format!("; {}]", n.last_reset));
        }
        out
    }

    fn violation(&mut self, kind: &'static str, node: Option<u32>, detail: String) {
        self.report.violations.push(Violation {
            kind,
            at_ms: self.now_us / 1_000,
            epoch: *self.epochs.last_key_value().map(|(e, _)| e).unwrap_or(&0),
            node,
            detail,
        });
        if self.report.violations.len() > 500 {
            self.ended_early = Some("more than 500 violations".into());
        }
    }

    fn check(&mut self) {
        let now = self.now_us;
        // Senders routed to one validator rarely run ahead of their nonce.
        let submitted = self.report.txs_submitted;
        if !self.ahead_flagged
            && submitted >= 2_000
            && self.report.ahead_of_nonce * 10_000
                > self.cfg.limits.max_ahead_of_nonce_bps * submitted
        {
            self.ahead_flagged = true;
            let detail = format!(
                "{} of {submitted} transactions ran ahead of their nonce with their predecessor in flight, over {} basis points",
                self.report.ahead_of_nonce, self.cfg.limits.max_ahead_of_nonce_bps
            );
            self.violation("ordering", None, detail);
        }
        // The node layer's block store stays within its bound.
        let limit = self.cfg.limits.max_node_store_bytes;
        for i in 0..self.nodes.len() {
            let bytes = self.nodes[i].blocks.as_ref().map_or(0, |b| b.bytes());
            self.report.node_store_peak_bytes = self.report.node_store_peak_bytes.max(bytes);
            if bytes > limit {
                let id = self.nodes[i].id;
                self.violation(
                    "memory",
                    Some(id),
                    format!("block store holds {bytes} bytes, over {limit}"),
                );
            }
        }
        // Value conservation, from the ledger's own block rule.
        for (h, e) in std::mem::take(&mut self.ledger.conservation_failures) {
            self.violation("value", None, format!("height {h}: {e}"));
        }
        // Liveness: while a quorum of honest validators is up and
        // connected, commits and certificates keep advancing.
        let partitioned_minority: Vec<u32> = match &self.partition {
            Some(p) if p.quorum_loss => Vec::new(),
            Some(p) => p.side_a.iter().copied().collect(),
            None => Vec::new(),
        };
        // Progress: some honest validator's leaders keep committing (an idle
        // committee commits leaders too, ordering no block).
        for i in 0..self.nodes.len() {
            let n = &self.nodes[i];
            if n.status != Status::Up || n.behaviour != Behaviour::Honest {
                continue;
            }
            let Some(core) = n.core.as_ref() else {
                continue;
            };
            let mark = (n.epoch, core.stats().leaders_committed);
            if mark != n.commit_mark {
                self.nodes[i].commit_mark = mark;
                self.last_progress_us = now;
            }
        }
        let quorum_loss = self.partition.as_ref().is_some_and(|p| p.quorum_loss);
        let live = !quorum_loss && self.quorum_ok(&partitioned_minority);
        if live {
            let since = *self.live_since_us.get_or_insert(now);
            let from = self.last_progress_us.max(since);
            let gap = now.saturating_sub(from) / 1_000;
            if now >= self.cfg.warmup_ms * 1_000 {
                self.report.max_commit_gap_ms = self.report.max_commit_gap_ms.max(gap);
            }
            if gap > self.cfg.limits.commit_gap_ms && !self.stall_flagged {
                self.stall_flagged = true;
                self.violation(
                    "liveness",
                    None,
                    format!(
                        "no leader committed for {gap} ms with a quorum up (height {}){}",
                        self.network_height,
                        self.node_states()
                    ),
                );
            }
            let fgap = now.saturating_sub(self.last_cert_us.max(since)) / 1_000;
            // An idle committee certifies once an epoch.
            let idle =
                now.saturating_sub(self.last_submit_us) > self.cfg.limits.finality_gap_ms * 1_000;
            let fbound = if idle {
                self.cfg.limits.finality_gap_ms + self.cfg.epoch_ms()
            } else {
                self.cfg.limits.finality_gap_ms
            };
            if now >= self.cfg.warmup_ms * 1_000 {
                self.report.max_finality_gap_ms = self.report.max_finality_gap_ms.max(fgap);
            }
            if fgap > fbound && !self.final_flagged {
                self.final_flagged = true;
                self.violation(
                    "liveness",
                    None,
                    format!(
                        "no certificate for {fgap} ms with a quorum up (checkpoint {}){}",
                        self.cert_index,
                        self.node_states()
                    ),
                );
            }
            if gap > self.cfg.limits.dead_after_ms {
                self.ended_early = Some(format!(
                    "network stalled for {gap} ms at height {}",
                    self.network_height
                ));
            }
        } else {
            self.live_since_us = None;
        }
        if self.last_progress_us == now || now.saturating_sub(self.last_progress_us) < 1_000_000 {
            self.stall_flagged = false;
        }
        if now.saturating_sub(self.last_cert_us) < 1_000_000 {
            self.final_flagged = false;
        }
        // Rejoin.
        let latest = *self.epochs.last_key_value().map(|(e, _)| e).unwrap_or(&0);
        for i in 0..self.nodes.len() {
            let n = &self.nodes[i];
            let Some(r) = &n.rejoin else { continue };
            if n.status != Status::Up || n.core.is_none() {
                self.nodes[i].rejoin = None;
                continue;
            }
            if n.epoch >= r.epoch && n.last_height >= r.height {
                let took = (now - r.since_us) / 1_000;
                self.report.rejoin_ms.push(took as f64);
                self.nodes[i].rejoin = None;
                continue;
            }
            let id = n.id;
            let reason = r.reason;
            let behind = (
                latest.saturating_sub(n.epoch),
                self.network_height.saturating_sub(n.last_height),
            );
            let mut flag = false;
            if let Some(r) = self.nodes[i].rejoin.as_mut() {
                if live && !partitioned_minority.contains(&id) {
                    r.live_ms += 1_000;
                }
                if r.live_ms > self.cfg.limits.rejoin_ms {
                    flag = true;
                }
            }
            if flag {
                self.violation("rejoin", Some(id), format!("{reason}: still {} epochs and {} heights behind after {} s of live network", behind.0, behind.1, self.cfg.limits.rejoin_ms / 1_000));
                self.nodes[i].rejoin = None;
            }
        }
        // Memory, every ten seconds.
        if (now / 1_000_000).is_multiple_of(10) {
            for i in 0..self.nodes.len() {
                let Some(core) = self.nodes[i].core.as_ref() else {
                    continue;
                };
                let s = core.sizes();
                let entries = s.dag_vertices
                    + s.dag_pending
                    + s.unechoed
                    + s.bodies
                    + s.first_proposals
                    + s.ordered
                    + s.payloads
                    + s.payload_rounds
                    + s.wanted_vertices
                    + s.wanted_batches
                    + s.waiting
                    + s.decided
                    + s.executed
                    + s.rbc_instances
                    + s.availability_pending
                    + s.events
                    + s.outbox
                    + self.nodes[i].journal.len()
                    + self.nodes[i].to_sign.len();
                let bytes = s.buffered_bytes;
                let epoch = self.nodes[i].epoch;
                let id = self.nodes[i].id;
                let n = &mut self.nodes[i];
                let first_over = (entries > self.cfg.limits.max_core_entries
                    && n.max_entries <= self.cfg.limits.max_core_entries)
                    || (bytes > self.cfg.limits.max_core_bytes
                        && n.max_bytes <= self.cfg.limits.max_core_bytes);
                n.max_entries = n.max_entries.max(entries);
                n.max_bytes = n.max_bytes.max(bytes);
                let e = self.epoch_mem.entry(epoch).or_default();
                e.0 = e.0.max(entries);
                e.1 = e.1.max(bytes);
                if first_over {
                    self.violation("memory", Some(id), format!("consensus state holds {entries} entries, {bytes} bytes (limits {} / {})", self.cfg.limits.max_core_entries, self.cfg.limits.max_core_bytes));
                }
            }
            if self.epoch_mem.len() > 8_192 {
                // Keep a thinned history: every other early epoch.
                let keys: Vec<u64> = self.epoch_mem.keys().copied().take(4_096).collect();
                for k in keys.iter().skip(1).step_by(2) {
                    self.epoch_mem.remove(k);
                }
            }
        }
    }

    fn fill_report(&mut self) {
        let r = &mut self.report;
        r.sim_ms = self.now_us / 1_000;
        r.calendar_days = self.ledger.calendar_ms as f64 / 86_400_000.0;
        r.height = self.network_height;
        r.wall_s = self.started.elapsed().as_secs_f64();
        r.ledger = self.ledger.stats.clone();
        r.governance.by_kind = self
            .gov
            .kinds_done
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
        r.governance.failures = self.gov.failures.iter().rev().take(20).cloned().collect();
        r.stake_joins = self.stake.joins;
        r.stake_exits = self.stake.exits;
        r.stake_withdrawals = self.stake.withdrawals;
        r.stake_top_ups = self.stake.top_ups;
        r.total_supply = self.ledger.total_supply().to_string();
        r.genesis_supply = self.ledger.genesis_supply.to_string();
        r.ledger_index_bytes = self.ledger.index_bytes() as u64;
        let span = (self.now_us.saturating_sub(self.cfg.warmup_ms * 1_000)).max(1) as f64 / 1e6;
        let seated: Vec<&Node> = self.nodes.iter().filter(|n| n.core.is_some()).collect();
        let k = seated.len().max(1) as f64;
        r.bandwidth_out_mbps = seated
            .iter()
            .map(|n| n.bytes_out as f64 * 8.0 / 1e6)
            .sum::<f64>()
            / k
            / (self.now_us as f64 / 1e6).max(1.0);
        r.cpu_busy_pct = seated.iter().map(|n| n.cpu_busy_us as f64).sum::<f64>()
            / k
            / (self.now_us as f64).max(1.0)
            * 100.0;
        r.tps = r.txs_in_window as f64 / span;
        r.max_core_entries = self.nodes.iter().map(|n| n.max_entries).max().unwrap_or(0) as u64;
        r.max_core_bytes = self.nodes.iter().map(|n| n.max_bytes).max().unwrap_or(0) as u64;
        r.mem_by_epoch = self
            .epoch_mem
            .iter()
            .map(|(e, (a, b))| (*e, *a as u64, *b as u64))
            .collect();
        r.journal_by_epoch = self.epoch_journal.iter().map(|(e, b)| (*e, *b)).collect();
        r.ended_early = self.ended_early.clone();
    }

    fn finish(mut self) -> Report {
        self.fill_report();
        let mut extra = serde_json::Map::new();
        for o in self.observers.iter_mut() {
            o.finish(&self.ledger, &mut extra);
        }
        self.report.extra = extra;
        // Growth: the late run against the early run, per epoch maxima.
        let growth = |series: Vec<u64>| -> Option<(f64, u64, u64)> {
            if series.len() < 16 {
                return None;
            }
            let q = series.len() / 4;
            let early = *series[q..2 * q].iter().max()?;
            let late = *series[3 * q..].iter().max()?;
            Some((late as f64 / early.max(1) as f64, early, late))
        };
        let lim = self.cfg.limits.growth_ratio;
        if let Some((ratio, early, late)) =
            growth(self.report.mem_by_epoch.iter().map(|m| m.1).collect())
            && ratio > lim
            && late > early + 10_000
        {
            self.violation(
                "memory",
                None,
                format!(
                    "consensus state grew from {early} to {late} entries over the run (x{ratio:.2})"
                ),
            );
        }
        if let Some((ratio, early, late)) =
            growth(self.report.journal_by_epoch.iter().map(|m| m.1).collect())
            && ratio > lim
            && late > early + 1_000_000
        {
            self.violation(
                "storage",
                None,
                format!("journal per epoch grew from {early} to {late} bytes (x{ratio:.2})"),
            );
        }
        // Every restarted validator rejoined by the end, unless the network
        // was not live.
        if let Some(why) = self.ended_early.clone() {
            self.violation("liveness", None, format!("run ended early: {why}"));
        }
        self.report.passed = self.report.violations.is_empty();
        self.report.wall_s = self.started.elapsed().as_secs_f64();
        self.report
    }
}

fn with_nonce(tx: SimTx, n: u64) -> SimTx {
    match tx {
        SimTx::Transfer {
            from, to, amount, ..
        } => SimTx::Transfer {
            from,
            to,
            amount,
            nonce: n,
        },
        SimTx::Propose { from, action, .. } => SimTx::Propose {
            from,
            action,
            nonce: n,
        },
        SimTx::Vote { from, proposal, .. } => SimTx::Vote {
            from,
            proposal,
            nonce: n,
        },
        SimTx::Execute { from, proposal, .. } => SimTx::Execute {
            from,
            proposal,
            nonce: n,
        },
        SimTx::IncreaseStake { from, amount, .. } => SimTx::IncreaseStake {
            from,
            amount,
            nonce: n,
        },
        SimTx::Exit { from, .. } => SimTx::Exit { from, nonce: n },
        SimTx::Evidence { from, evidence, .. } => SimTx::Evidence {
            from,
            evidence,
            nonce: n,
        },
        SimTx::Call {
            from,
            to,
            value,
            data,
            gas,
            max_fee,
            ..
        } => SimTx::Call {
            from,
            to,
            value,
            data,
            gas,
            max_fee,
            nonce: n,
        },
    }
}

fn msg_size(m: &Message) -> usize {
    let vertex = |v: &tenzro_consensus::vertex::Vertex| {
        48 + 42 * (v.strong.len() + v.weak.len()) + 40 * v.batches.len() + 44 * v.carried.len()
    };
    match m {
        Message::Propose(v) => vertex(v),
        Message::Signals(s) => 8 + 44 * s.len(),
        Message::Batch(p) => 40 + p.body.len(),
        Message::FetchVertices(d) | Message::FetchBatches(d) => 8 + 32 * d.len(),
        Message::Vertices(vs) => vs.iter().map(vertex).sum::<usize>() + 8,
        Message::Batches(ps) => ps.iter().map(|p| 40 + p.body.len()).sum(),
        Message::Vote(_) => 3_309 + 64 + 320,
        Message::Certificate(c) => 320 + c.signers.len() * (2 + 32 + 3_309 + 64 + 16),
        Message::Frontier(f) => 24 + 42 * f.highest.len(),
        Message::FetchOrdering(_) => 16,
        Message::Ordering(s) => {
            256 + 40 * s.ordered.len()
                + 16 * s
                    .availability
                    .early
                    .iter()
                    .map(|(_, e)| e.len())
                    .sum::<usize>()
        }
    }
}

fn msg_cost(m: &Message, verify_us: u64) -> u64 {
    match m {
        Message::Propose(v) => {
            5 + (v.strong.len() + v.weak.len() + v.batches.len() + v.carried.len()) as u64 / 4
        }
        Message::Signals(s) => 1 + s.len() as u64 / 2,
        Message::Batch(p) => 2 + p.body.len() as u64 / 1_000,
        Message::FetchVertices(d) | Message::FetchBatches(d) => 2 + d.len() as u64,
        Message::Vertices(vs) => 5 * vs.len() as u64,
        Message::Batches(ps) => ps.iter().map(|p| 2 + p.body.len() as u64 / 1_000).sum(),
        Message::Vote(_) => verify_us,
        Message::Certificate(c) => verify_us * c.signers.len() as u64,
        Message::Frontier(f) => 1 + f.highest.len() as u64 / 4,
        Message::FetchOrdering(_) => 1,
        Message::Ordering(s) => 5 + s.ordered.len() as u64 / 16,
    }
}
