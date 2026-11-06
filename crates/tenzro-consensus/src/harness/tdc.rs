//! The consensus core as an emulated node.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use super::driver::{Output, SimBatch, SimNode};
use crate::batch::{BatchPart, BatchPayload};
use crate::checkpoint::test_support::MemoryHighWater;
use crate::checkpoint::{Checkpoint, sign_checkpoint};
use crate::committee::{Committee, ValidatorIndex};
use crate::config::{ConsensusConfig, TimeRules};
use crate::core::{Core, CoreConfig, EpochStart, Event, Record, Target};
use crate::session::SessionCertificate;
use crate::validator::{ValidatorInfo, ValidatorSet};
use crate::validator_key::ValidatorSigner;
use crate::validator_key::test_signer::SoftwareTestSigner;
use crate::vertex::Digest;
use crate::wire::Message;

/// How an emulated validator behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    /// Follows the protocol.
    Honest,
    /// Sends two different vertices every round, one to each half.
    Equivocate,
    /// Never sends its vertex in rounds it leads.
    WithholdLeaderVertex,
    /// Sends half of its batches to nobody and its vertices to only half of
    /// the committee.
    Withhold,
    /// Signs a second, conflicting checkpoint for every index and sends it
    /// to half of the committee.
    DoubleSign,
}

/// Parameters of the emulated validators.
#[derive(Debug, Clone)]
pub struct TdcParams {
    /// Consensus configuration.
    pub config: ConsensusConfig,
    /// The genesis time rules.
    pub time: TimeRules,
    /// Modeled hardware signing latency, milliseconds.
    pub sign_latency_ms: u64,
    /// Behaviour per validator (missing = honest).
    pub behaviour: Vec<Behaviour>,
    /// Validators that lose all in-memory state at the given time and come
    /// back from their recovery journal.
    pub restart: Option<(u64, Vec<u16>)>,
    /// Whether validators start the next epoch's core once an epoch hands
    /// over, as a node does; otherwise the committee stops at its first
    /// handover.
    pub handover: bool,
}

impl TdcParams {
    /// Honest validators with the default configuration.
    pub fn honest() -> Self {
        Self {
            config: ConsensusConfig::default(),
            time: TimeRules::default(),
            sign_latency_ms: 50,
            behaviour: Vec::new(),
            restart: None,
            handover: false,
        }
    }
}

/// An emulated validator.
pub struct TdcNode {
    core: Core,
    signer: Arc<SoftwareTestSigner>,
    // The session key votes are signed with, and its certificate for the
    // epoch it last voted in.
    session: SoftwareTestSigner,
    session_cert: Option<SessionCertificate>,
    high_water: MemoryHighWater,
    to_sign: VecDeque<(u64, Checkpoint)>,
    sign_latency_ms: u64,
    behaviour: Behaviour,
    n: u16,
    ordered: Vec<(u64, Digest, Vec<Digest>)>,
    certified: Vec<(u64, u64, Digest)>,
    convicted: Vec<u16>,
    batch_count: u64,
    extra: Vec<(Target, Message)>,
    // Set for a validator that restarts: when, what it persisted, and the
    // anchor it ordered at every height, to check the recovered order.
    restart_at: Option<u64>,
    journal: Vec<Record>,
    anchors: BTreeMap<u64, Digest>,
    // Every vertex the core proposed, by round.
    proposed: BTreeMap<u64, Digest>,
    // For this validator's own batches: rounds from the vertex that
    // introduced or carried a batch to the anchor that ordered it, and how
    // many.
    anchor_lag: BTreeMap<u64, u64>,
    core_cfg: CoreConfig,
    committee: Committee,
    // Where the running epoch started, which a restart recovers from.
    start: EpochStart,
    handover: bool,
    // Every epoch's closing and handover certificates this validator formed
    // or adopted, with the session certificates they name: what the network
    // carries to a validator that missed them.
    handovers: Vec<(crate::checkpoint::Certificate, Vec<SessionCertificate>)>,
}

/// Committee and signers for `n` equal-stake validators.
pub fn committee(n: usize, seat_budget: u64) -> (Committee, Vec<Arc<SoftwareTestSigner>>) {
    committee_of_epoch(0, n, seat_budget)
}

/// The same `n` validators seated in `epoch`'s committee.
pub fn committee_of_epoch(
    epoch: u64,
    n: usize,
    seat_budget: u64,
) -> (Committee, Vec<Arc<SoftwareTestSigner>>) {
    let signers: Vec<Arc<SoftwareTestSigner>> = (0..n as u64)
        .map(|i| Arc::new(SoftwareTestSigner::from_seed(i)))
        .collect();
    let infos: Vec<ValidatorInfo> = signers
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mut a = [0u8; 32];
            a[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            ValidatorInfo::new(
                tenzro_types::primitives::Address::new(a),
                s.public_key().clone(),
                a,
                100,
            )
        })
        .collect();
    let set = ValidatorSet::new(epoch, infos).expect("valid set");
    (
        crate::committee::from_validator_set(&set, seat_budget).expect("valid committee"),
        signers,
    )
}

/// The genesis epoch start used by emulated runs.
pub fn genesis_start() -> EpochStart {
    EpochStart {
        first_height: 1,
        first_checkpoint: 0,
        prev_checkpoint: [0; 32],
        timestamp_ms: 0,
        base_blocks: vec![(0, [0xAA; 32], state_root(0))],
        leader_lookahead_rounds: crate::schedule::LOOKAHEAD_ROUNDS,
    }
}

fn state_root(height: u64) -> Digest {
    *blake3::hash(&height.to_be_bytes()).as_bytes()
}

/// `n` emulated validators.
pub fn nodes(n: usize, p: &TdcParams) -> Vec<TdcNode> {
    let (c, signers) = committee(n, n as u64);
    let core_cfg = p.config.core(7, [0x11; 32], &p.time);
    (0..n)
        .map(|i| TdcNode {
            core: Core::new(
                core_cfg.clone(),
                c.clone(),
                i as ValidatorIndex,
                genesis_start(),
            ),
            signer: signers[i].clone(),
            session: SoftwareTestSigner::from_seed(1_000_000 + i as u64),
            session_cert: None,
            high_water: MemoryHighWater::default(),
            to_sign: VecDeque::new(),
            sign_latency_ms: p.sign_latency_ms,
            behaviour: p.behaviour.get(i).copied().unwrap_or(Behaviour::Honest),
            n: n as u16,
            ordered: Vec::new(),
            certified: Vec::new(),
            convicted: Vec::new(),
            batch_count: 0,
            extra: Vec::new(),
            restart_at: p
                .restart
                .as_ref()
                .filter(|(_, who)| who.contains(&(i as u16)))
                .map(|(at, _)| *at),
            journal: Vec::new(),
            anchors: BTreeMap::new(),
            proposed: BTreeMap::new(),
            anchor_lag: BTreeMap::new(),
            core_cfg: core_cfg.clone(),
            committee: c.clone(),
            start: genesis_start(),
            handover: p.handover,
            handovers: Vec::new(),
        })
        .collect()
}

impl TdcNode {
    /// The session key's certificate for `cp`'s epoch, which the hardware
    /// key signs once per epoch.
    fn session_certificate(&mut self, cp: &Checkpoint) -> SessionCertificate {
        match &self.session_cert {
            Some(c) if c.epoch == cp.epoch => c.clone(),
            _ => {
                let c = crate::session::sign_certificate(
                    &*self.signer,
                    cp.chain_id,
                    cp.genesis_hash,
                    cp.epoch,
                    self.session.public_key().clone(),
                )
                .expect("test signer");
                self.session_cert = Some(c.clone());
                c
            }
        }
    }

    fn handle_events(&mut self, now_ms: u64) {
        for e in self.core.take_events() {
            match e {
                Event::Ordered(seg) => {
                    let block = {
                        let mut h = blake3::Hasher::new();
                        h.update(&seg.height.to_be_bytes());
                        h.update(&seg.anchor.digest);
                        *h.finalize().as_bytes()
                    };
                    if self.restart_at.is_some() || !self.anchors.is_empty() {
                        match self.anchors.get(&seg.height) {
                            Some(before) => {
                                // Re-derived after a restart: it must be what
                                // this validator ordered before.
                                assert_eq!(
                                    *before, seg.anchor.digest,
                                    "recovered order diverged at {}",
                                    seg.height
                                );
                                self.core.on_executed(
                                    seg.height,
                                    block,
                                    state_root(seg.height),
                                    Vec::new(),
                                );
                                continue;
                            }
                            None => {
                                self.anchors.insert(seg.height, seg.anchor.digest);
                            }
                        }
                    }
                    let me = self.core.me();
                    for (b, _) in seg.batches.iter().filter(|(b, _)| b.author == me) {
                        *self
                            .anchor_lag
                            .entry(seg.anchor.round.saturating_sub(b.round))
                            .or_default() += 1;
                    }
                    self.ordered.push((
                        seg.height,
                        seg.anchor.digest,
                        seg.batches
                            .iter()
                            .flat_map(|(_, p)| sim_digests(p))
                            .collect(),
                    ));
                    self.core
                        .on_executed(seg.height, block, state_root(seg.height), Vec::new());
                }
                // Execution here is immediate, so the epoch's last block is
                // executed by the time its end is released.
                Event::EpochEnds { .. } => {
                    let root = self.next_committee().root();
                    self.core.set_next_committee_root(root);
                }
                Event::Sign(cp) => self.to_sign.push_back((now_ms + self.sign_latency_ms, cp)),
                Event::Certified(c) => {
                    self.certified.push((
                        c.checkpoint.index,
                        c.checkpoint.last_height,
                        c.checkpoint.digest(),
                    ));
                    if c.checkpoint.next_committee_root.is_some() {
                        let sessions = self.core.sessions().bundle(&c.sessions);
                        self.handovers.push(((*c).clone(), sessions));
                    }
                }
                Event::EpochComplete(c) => {
                    self.certified.push((
                        c.checkpoint.index,
                        c.checkpoint.last_height,
                        c.checkpoint.digest(),
                    ));
                    let sessions = self.core.sessions().bundle(&c.sessions);
                    self.handovers.push(((*c).clone(), sessions));
                    if self.handover {
                        self.enter_next_epoch(&c);
                    }
                }
                Event::Equivocation(e) => {
                    if let Some(i) = self
                        .core
                        .committee()
                        .members()
                        .iter()
                        .position(|m| m.public_key == e.public_key)
                    {
                        self.convicted.push(i as u16);
                    }
                }
                Event::Unordered(_) | Event::VerifierDisagreement { .. } => {}
            }
        }
    }

    /// The same validators seated for the epoch after the running one.
    fn next_committee(&self) -> Committee {
        let size = self.committee.size();
        committee_of_epoch(self.committee.epoch + 1, size, size as u64).0
    }

    /// Starts the next epoch's core from the handover certificate, as a node
    /// does: the old epoch's journal and pending signatures are dropped.
    fn enter_next_epoch(&mut self, handover: &crate::checkpoint::Certificate) {
        let next = self.next_committee();
        let start = self.core.next_epoch_start(handover);
        let me = self.core.me();
        self.core = Core::new(self.core_cfg.clone(), next.clone(), me, start.clone());
        self.committee = next;
        self.start = start;
        self.journal.clear();
        self.to_sign.clear();
        // Rounds count from zero again in each epoch.
        self.proposed.clear();
    }

    /// Loses every piece of in-memory state, including frames not yet sent,
    /// and rebuilds the core from what was persisted.
    fn restart(&mut self, now_ms: u64) {
        let executed_through = self.anchors.keys().next_back().copied().unwrap_or(0);
        let me = self.core.me();
        self.core = Core::recover(
            self.core_cfg.clone(),
            self.committee.clone(),
            me,
            self.start.clone(),
            std::mem::take(&mut self.journal),
            executed_through,
            now_ms,
        );
        self.to_sign.clear();
        self.extra.clear();
        self.handle_events(now_ms);
    }

    fn sign_due(&mut self, now_ms: u64) {
        while let Some((ready, _)) = self.to_sign.front() {
            if *ready > now_ms {
                return;
            }
            let (_, cp) = self.to_sign.pop_front().expect("front");
            let me = self.core.me();
            let cert = self.session_certificate(&cp);
            if let Ok(v) = sign_checkpoint(&self.session, &cert, &self.high_water, me, &cp) {
                self.core.on_own_vote(v);
            }
            if self.behaviour == Behaviour::DoubleSign {
                let mut other = cp.clone();
                other.state_root[0] ^= 0xFF;
                let digest = other.digest();
                let signature = self
                    .session
                    .sign(crate::checkpoint::CHECKPOINT_VOTE_DOMAIN, &digest)
                    .expect("test signer");
                let signature = crate::checkpoint::VoteSignature {
                    session: cert,
                    signature,
                };
                let vote = crate::checkpoint::CheckpointVote {
                    checkpoint: other,
                    signer: me,
                    signature,
                };
                for p in (0..self.n).filter(|p| p % 2 == 1 && *p != me) {
                    self.extra
                        .push((Target::One(p), Message::Vote(vote.clone())));
                }
            }
        }
    }
}

/// Digest the load generator gave a batch, recovered from its payload body.
/// The load generator's batches a sealed batch holds: each part is one of
/// their 32-byte digests.
fn sim_digests(p: &BatchPayload) -> Vec<Digest> {
    p.parts()
        .expect("the harness seals well-formed parts")
        .into_iter()
        .map(|part| part.try_into().expect("each part is a 32-byte digest"))
        .collect()
}

impl SimNode for TdcNode {
    type Msg = Message;

    fn start(&mut self, now_ms: u64) {
        self.core.start(now_ms);
        // Every link of the simulated network is up from the start.
        let me = self.core.me();
        for peer in 0..self.core.committee().size() as ValidatorIndex {
            if peer != me {
                self.core.on_peer_up(peer, now_ms);
            }
        }
    }

    fn deliver(&mut self, from: u16, msgs: Vec<Message>, now_ms: u64) {
        self.core.on_messages(from, msgs, now_ms);
        self.handle_events(now_ms);
    }

    fn tick(&mut self, now_ms: u64) {
        if self.restart_at.is_some_and(|at| now_ms >= at) {
            self.restart_at = None;
            self.restart(now_ms);
        }
        self.sign_due(now_ms);
        self.core.on_tick(now_ms);
        self.handle_events(now_ms);
    }

    fn submit(&mut self, batch: SimBatch, _tx_bytes: usize) {
        self.core.submit_part(BatchPart {
            transactions: batch.transactions,
            bytes: batch.digest.to_vec(),
        });
    }

    fn drain(&mut self, now_ms: u64) -> Output<Message> {
        self.handle_events(now_ms);
        // What the node persists before it sends.
        let records = self.core.take_journal();
        let journal_bytes: u64 = records
            .iter()
            .map(|r| bincode::serialized_size(r).expect("record encodes"))
            .sum();
        if self.restart_at.is_some() {
            self.journal.extend(records);
        }
        let me = self.core.me();
        let mut sends = Vec::new();
        for (t, m) in self.core.take_outbox() {
            // The core itself never equivocates: it may re-send its vertex
            // for a round (after a restart), never send a different one.
            if let Message::Propose(v) = &m
                && v.source == me
            {
                let d = v.digest();
                let first = *self.proposed.entry(v.round).or_insert(d);
                assert_eq!(
                    first, d,
                    "validator {me} proposed two vertices for round {}",
                    v.round
                );
            }
            match (&m, self.behaviour) {
                (Message::Propose(v), Behaviour::Equivocate) => {
                    let mut twin = v.clone();
                    twin.timestamp_ms += 1;
                    for p in 0..self.n {
                        if p == me {
                            continue;
                        }
                        let msg = if p < self.n / 2 {
                            m.clone()
                        } else {
                            Message::Propose(twin.clone())
                        };
                        sends.push((Target::One(p), msg));
                    }
                }
                (Message::Propose(v), Behaviour::WithholdLeaderVertex)
                    if self.core.leads(v.round, me) => {}
                (Message::Propose(_), Behaviour::Withhold) => {
                    for p in (0..self.n).filter(|p| p % 2 == 0 && *p != me) {
                        sends.push((Target::One(p), m.clone()));
                    }
                }
                // Every second batch it seals stays out of every peer's hands.
                (Message::Batch(_), Behaviour::Withhold) => {
                    self.batch_count += 1;
                    if self.batch_count % 2 == 1 {
                        sends.push((t, m));
                    }
                }
                _ => sends.push((t, m)),
            }
        }
        sends.append(&mut self.extra);
        Output {
            sends,
            ordered: std::mem::take(&mut self.ordered),
            certified: std::mem::take(&mut self.certified),
            convicted: std::mem::take(&mut self.convicted),
            journal_bytes,
        }
    }

    fn size(m: &Message, tx_bytes: usize) -> usize {
        let vertex = |v: &crate::vertex::Vertex| {
            48 + 42 * (v.strong.len() + v.weak.len()) + 40 * v.batches.len() + 44 * v.carried.len()
        };
        match m {
            Message::Propose(v) => vertex(v),
            Message::Signals(s) => 8 + 44 * s.len(),
            Message::Batch(p) => 40 + p.transactions as usize * tx_bytes,
            Message::FetchVertices(d) | Message::FetchBatches(d) => 8 + 32 * d.len(),
            Message::Vertices(vs) => vs.iter().map(vertex).sum::<usize>() + 8,
            Message::Batches(ps) => ps
                .iter()
                .map(|p| 40 + p.transactions as usize * tx_bytes)
                .sum(),
            Message::Vote(_) => 3_309 + 64 + 320,
            Message::Certificate(c) => 320 + c.signers.len() * (2 + 32 + 3_309 + 64 + 16),
            Message::Frontier(f) => 24 + 42 * f.highest.len(),
            Message::FetchOrdering(_) => 16,
            Message::Ordering(s) => 256 + 40 * s.ordered.len(),
        }
    }

    fn cost_us(m: &Message, tx_bytes: usize) -> u64 {
        match m {
            Message::Propose(v) => {
                5 + (v.strong.len() + v.weak.len() + v.batches.len() + v.carried.len()) as u64 / 4
            }
            Message::Signals(s) => 1 + s.len() as u64 / 2,
            Message::Batch(p) => 2 + (p.transactions as u64 * tx_bytes as u64) / 1_000,
            Message::FetchVertices(d) | Message::FetchBatches(d) => 2 + d.len() as u64,
            Message::Vertices(vs) => 5 * vs.len() as u64,
            Message::Batches(ps) => ps
                .iter()
                .map(|p| 2 + p.transactions as u64 * tx_bytes as u64 / 1_000)
                .sum(),
            Message::Vote(_) => 150,
            Message::Certificate(c) => 150 * c.signers.len() as u64,
            Message::Frontier(f) => 1 + f.highest.len() as u64 / 4,
            Message::FetchOrdering(_) => 1,
            Message::Ordering(s) => 5 + s.ordered.len() as u64 / 16,
        }
    }

    fn class(m: &Message) -> &'static str {
        match m {
            Message::Batch(_) | Message::Batches(_) => "payload",
            _ => "consensus",
        }
    }

    fn mem_probe(&self) -> String {
        let s = self.core.stats();
        format!(
            "proposed={} anchor_lag={:?} round_p50={} round_p99={} rbc_fast={} rbc_slow={} leaders_committed={} leaders_skipped={} {}",
            self.proposed.len(),
            self.anchor_lag,
            s.round_p50_ms,
            s.round_p99_ms,
            s.rbc.fast,
            s.rbc.slow,
            s.leaders_committed,
            s.leaders_skipped,
            self.core.mem_probe()
        )
    }
}

#[cfg(test)]
mod idle_tests {
    use super::*;
    use crate::harness::driver::{SimBatch, SimNode};

    /// Four validators on 500 ms checkpoints, a `epoch_ms` epoch with no
    /// handover confirmations, and a one-second idle heartbeat.
    fn validators(epoch_ms: u64, behaviour: Vec<Behaviour>) -> Vec<TdcNode> {
        let mut p = TdcParams::honest();
        p.time = TimeRules {
            checkpoint_interval_ms: 500,
            epoch_checkpoints: epoch_ms / 500,
            handover_confirmations: 0,
            idle_round_interval_ms: 1_000,
            ..TimeRules::default()
        };
        p.sign_latency_ms = 5;
        p.behaviour = behaviour;
        let mut nodes = nodes(4, &p);
        for n in nodes.iter_mut() {
            n.start(0);
        }
        nodes
    }

    #[derive(Default)]
    struct Seen {
        blocks: Vec<(u64, u64)>,
        certified: Vec<(u64, u64)>,
    }

    /// Runs every link with no delay, in 10 ms steps, from `from` to
    /// `until`, calling `at` before each step.
    #[allow(clippy::needless_range_loop)] // the loop index is also the node's validator index
    fn run(
        nodes: &mut [TdcNode],
        seen: &mut Seen,
        from: u64,
        until: u64,
        mut at: impl FnMut(u64, &mut [TdcNode]),
    ) {
        let n = nodes.len();
        let mut now = from;
        while now < until {
            at(now, nodes);
            loop {
                let mut frames = Vec::new();
                for i in 0..n {
                    let out = nodes[i].drain(now);
                    if i == 0 {
                        seen.blocks
                            .extend(out.ordered.iter().map(|(h, ..)| (*h, now)));
                        seen.certified
                            .extend(out.certified.iter().map(|(index, last, _)| (*index, *last)));
                    }
                    for (t, m) in out.sends {
                        for p in (0..n).filter(|p| {
                            *p != i && (t == Target::All || t == Target::One(*p as ValidatorIndex))
                        }) {
                            frames.push((i, p, m.clone()));
                        }
                    }
                }
                if frames.is_empty() {
                    break;
                }
                for (from, to, m) in frames {
                    nodes[to].deliver(from as u16, vec![m], now);
                }
            }
            for node in nodes.iter_mut() {
                node.tick(now);
            }
            now += 10;
        }
    }

    #[test]
    fn an_idle_epoch_orders_no_block_and_one_checkpoint() {
        let mut nodes = validators(10_000, Vec::new());
        let mut seen = Seen::default();
        // The epoch's time is up at 10 s; the leader committed after it,
        // whose block time is its parents', a heartbeat or two later.
        run(&mut nodes, &mut seen, 0, 16_000, |_, _| {});
        assert!(
            seen.blocks.is_empty(),
            "an idle committee ordered blocks {:?}",
            seen.blocks
        );
        assert_eq!(
            seen.certified,
            vec![(0, 0)],
            "one checkpoint for the idle epoch, covering no block"
        );
        let cert = nodes[0]
            .core
            .latest_certificate()
            .expect("certified")
            .clone();
        assert!(cert.checkpoint.first_height > cert.checkpoint.last_height);
        assert!(
            cert.checkpoint.next_committee_root.is_some(),
            "the epoch's last checkpoint"
        );
        // At the heartbeat, not at full pace: about one round a second.
        let committed = nodes[0].core.stats().leaders_committed;
        assert!(
            committed > 0 && committed < 60,
            "{committed} leaders committed while idle"
        );
    }

    #[test]
    fn a_transaction_wakes_an_idle_committee_and_its_state_is_certified_without_a_later_block() {
        let mut nodes = validators(30_000, Vec::new());
        let mut seen = Seen::default();
        run(&mut nodes, &mut seen, 0, 5_000, |_, _| {});
        assert!(seen.blocks.is_empty());
        let rounds_idle = nodes[0].core.round().expect("started");
        run(&mut nodes, &mut seen, 5_000, 12_000, |now, nodes| {
            if now == 5_000 {
                nodes[2].submit(
                    SimBatch {
                        digest: [7; 32],
                        transactions: 1,
                    },
                    100,
                );
            }
        });
        assert_eq!(
            seen.blocks.len(),
            1,
            "one block for one transaction, none around it"
        );
        let (height, ordered_at) = seen.blocks[0];
        assert!(
            ordered_at - 5_000 <= 500,
            "ordered {} ms after it was submitted",
            ordered_at - 5_000
        );
        assert!(
            rounds_idle < 15,
            "{rounds_idle} rounds in five idle seconds"
        );
        // The checkpoint over the block commits a lagged state root; the one
        // after it covers no block and commits the block's own post-state.
        assert_eq!(seen.certified, vec![(0, height), (1, height)]);
        let cert = nodes[0]
            .core
            .latest_certificate()
            .expect("certified")
            .clone();
        assert_eq!(cert.checkpoint.state_height, height);
        assert_eq!(cert.checkpoint.state_root, state_root(height));
        assert!(cert.checkpoint.well_formed());
    }

    #[test]
    fn an_idle_committee_still_skips_a_silent_leader() {
        let mut nodes = validators(
            30_000,
            vec![
                Behaviour::Honest,
                Behaviour::Honest,
                Behaviour::Honest,
                Behaviour::WithholdLeaderVertex,
            ],
        );
        let mut seen = Seen::default();
        run(&mut nodes, &mut seen, 0, 15_000, |_, _| {});
        let s = nodes[0].core.stats();
        assert!(s.leaders_skipped > 0, "the silent leader was never skipped");
        assert!(s.leaders_committed > 0, "nothing committed");
        assert!(seen.blocks.is_empty());
    }
}

#[cfg(test)]
mod epoch_tests {
    use std::collections::HashMap;

    use super::*;
    use crate::harness::driver::{SimBatch, SimNode};

    const N: usize = 4;

    /// How long the channel between `a` and `b` takes to come up in
    /// `epoch` once both are in it: every pair differently, and one pair
    /// seconds late, so each validator starts its epoch with only some of
    /// its peers.
    fn connect_delay(a: usize, b: usize, epoch: u64, n: usize) -> u64 {
        let (a, b) = (a.min(b), a.max(b));
        if (a + b + epoch as usize) % n == 1 {
            return 3_000;
        }
        50 + 250 * ((a * 3 + b * 5 + epoch as usize) % 4) as u64
    }

    /// The channels as a node keeps them: each belongs to the epoch both
    /// ends were in when it came up, closes when either end leaves that
    /// epoch or restarts, and carries only frames of its epoch. A validator
    /// cut off at some time loses every channel then and never gets one
    /// back.
    struct Net {
        n: usize,
        epoch: Vec<u64>,
        up: HashMap<(usize, usize), u64>,
        pending: Vec<(u64, usize, usize, u64)>,
        cut: Vec<(usize, u64)>,
    }

    impl Net {
        fn new(n: usize) -> Self {
            let mut net = Net {
                n,
                epoch: vec![0; n],
                up: HashMap::new(),
                pending: Vec::new(),
                cut: Vec::new(),
            };
            for a in 0..n {
                for b in a + 1..n {
                    net.pending.push((connect_delay(a, b, 0, n), a, b, 0));
                }
            }
            net
        }

        fn is_cut(&self, i: usize, now: u64) -> bool {
            self.cut.iter().any(|(v, at)| *v == i && *at <= now)
        }

        /// Closes the channels of every validator cut off by `now`.
        fn cut_due(&mut self, now: u64) {
            let cut: Vec<usize> = (0..self.n).filter(|i| self.is_cut(*i, now)).collect();
            self.up
                .retain(|(a, b), _| !cut.contains(a) && !cut.contains(b));
        }

        /// Drops `i`'s channels and dials every peer in its epoch again.
        fn reconnect(&mut self, i: usize, now: u64) {
            self.up.retain(|(a, b), _| *a != i && *b != i);
            let e = self.epoch[i];
            for j in (0..self.n).filter(|j| *j != i && self.epoch[*j] == e) {
                let (a, b) = (i.min(j), i.max(j));
                self.pending
                    .push((now + connect_delay(a, b, e, self.n), a, b, e));
            }
        }

        /// Notices validators that entered a new epoch: their old channels
        /// close and the new core starts.
        #[allow(clippy::needless_range_loop)] // the loop index also indexes the per-node epochs
        fn follow_epochs(&mut self, nodes: &mut [TdcNode], now: u64) {
            for i in 0..self.n {
                let e = nodes[i].core.committee().epoch;
                if e != self.epoch[i] {
                    self.epoch[i] = e;
                    nodes[i].core.start(now);
                    self.reconnect(i, now);
                }
            }
        }

        fn connect_due(&mut self, nodes: &mut [TdcNode], now: u64) {
            let (due, later): (Vec<_>, Vec<_>) =
                self.pending.drain(..).partition(|(at, ..)| *at <= now);
            self.pending = later;
            for (_, a, b, e) in due {
                if self.is_cut(a, now) || self.is_cut(b, now) {
                    continue;
                }
                if self.epoch[a] == e && self.epoch[b] == e && !self.up.contains_key(&(a, b)) {
                    self.up.insert((a, b), e);
                    nodes[a].core.on_peer_up(b as ValidatorIndex, now);
                    nodes[b].core.on_peer_up(a as ValidatorIndex, now);
                }
            }
        }

        fn carries(&self, from: usize, to: usize, epoch: u64) -> bool {
            self.up.get(&(from.min(to), from.max(to))) == Some(&epoch) && self.epoch[to] == epoch
        }
    }

    #[test]
    #[allow(clippy::needless_range_loop)] // the loop index is also the node's validator index
    fn a_committee_keeps_committing_across_epoch_handovers_with_staggered_channels_and_a_restart() {
        let mut p = TdcParams::honest();
        p.time = TimeRules {
            checkpoint_interval_ms: 500,
            epoch_checkpoints: 20,
            handover_confirmations: 2,
            idle_round_interval_ms: 1_000,
            ..TimeRules::default()
        };
        p.sign_latency_ms = 5;
        p.handover = true;
        // Validator 2 loses its memory in the middle of the run and comes
        // back from its journal.
        p.restart = Some((27_000, vec![2]));
        let mut nodes = nodes(N, &p);
        for n in nodes.iter_mut() {
            n.core.start(0);
        }
        let mut net = Net::new(N);
        // Per validator, the certificates it formed or adopted: index to
        // digest, and the epoch of each.
        let mut certified: Vec<BTreeMap<u64, Digest>> = vec![BTreeMap::new(); N];
        // Blocks validator 0 ordered: height and when.
        let mut blocks: Vec<(u64, u64)> = Vec::new();
        let mut submitted = None;
        let mut now = 0u64;
        while now < 80_000 {
            net.follow_epochs(&mut nodes, now);
            net.connect_due(&mut nodes, now);
            // A transaction once the committee is past its second handover.
            if submitted.is_none() && net.epoch.iter().all(|e| *e >= 2) {
                nodes[1].submit(
                    SimBatch {
                        digest: [9; 32],
                        transactions: 1,
                    },
                    100,
                );
                submitted = Some(now);
            }
            loop {
                net.follow_epochs(&mut nodes, now);
                let mut frames = Vec::new();
                for i in 0..N {
                    let epoch = nodes[i].core.committee().epoch;
                    let out = nodes[i].drain(now);
                    for (index, _, digest) in out.certified {
                        certified[i].insert(index, digest);
                    }
                    if i == 0 {
                        blocks.extend(out.ordered.iter().map(|(h, ..)| (*h, now)));
                    }
                    for (t, m) in out.sends {
                        for to in (0..N).filter(|p| {
                            *p != i && (t == Target::All || t == Target::One(*p as ValidatorIndex))
                        }) {
                            frames.push((i, to, epoch, m.clone()));
                        }
                    }
                }
                if frames.is_empty() {
                    break;
                }
                for (from, to, epoch, m) in frames {
                    if net.carries(from, to, epoch) {
                        nodes[to].deliver(from as u16, vec![m], now);
                    }
                }
            }
            for i in 0..N {
                let restarts = nodes[i].restart_at.is_some_and(|at| now >= at);
                nodes[i].tick(now);
                if restarts {
                    nodes[i].core.start(now);
                    net.reconnect(i, now);
                }
            }
            now += 10;
        }
        for (i, node) in nodes.iter().enumerate() {
            let epoch = node.core.committee().epoch;
            assert!(epoch >= 4, "validator {i} is stuck in epoch {epoch}");
            assert!(
                node.core.stats().leaders_committed > 0,
                "validator {i} commits nothing in epoch {epoch}"
            );
            assert!(
                !node.core.is_halted(),
                "validator {i} halted in epoch {epoch}"
            );
        }
        // Every epoch certified checkpoints, and every validator the same ones.
        let last_epoch = nodes[0].core.committee().epoch;
        let certs = &certified[0];
        assert!(
            certs.len() as u64 >= 3 * last_epoch,
            "only {} checkpoints over {last_epoch} epochs",
            certs.len()
        );
        for (i, c) in certified.iter().enumerate().skip(1) {
            for (index, digest) in c {
                if let Some(d) = certs.get(index) {
                    assert_eq!(
                        d, digest,
                        "validators {i} and 0 certified different checkpoints at {index}"
                    );
                }
            }
        }
        // The transaction submitted in a later epoch was ordered into a block.
        let submitted = submitted.expect("the committee never reached its second handover");
        assert_eq!(blocks.len(), 1, "one block for the one transaction");
        // Within a few rounds of the idle heartbeat while the epoch's last
        // channels come up, not whenever the epoch next turns over.
        let waited = blocks[0].1 - submitted;
        assert!(
            waited <= 5_000,
            "the transaction was ordered {waited} ms after it was submitted"
        );
    }

    /// Seven validators (`f = 2`) on 500 ms checkpoints and 10 s epochs,
    /// with the validators in `cut` losing every channel at the given time
    /// and never getting one back, and every frame `lost(from, to, now)`
    /// names dropped in that direction only. Certificates gossip over every
    /// link that still carries frames, as the node's certificate gossip
    /// does. Returns, per validator, the epoch of every block it ordered and
    /// when, and the certificates it formed.
    fn run_with_cuts(
        cut: &[(usize, u64)],
        lost: &dyn Fn(usize, usize, u64) -> bool,
        until: u64,
    ) -> (
        Vec<TdcNode>,
        Vec<Vec<(u64, u64)>>,
        Vec<BTreeMap<u64, Digest>>,
    ) {
        const SEVEN: usize = 7;
        let mut p = TdcParams::honest();
        p.time = TimeRules {
            checkpoint_interval_ms: 500,
            epoch_checkpoints: 20,
            handover_confirmations: 2,
            idle_round_interval_ms: 1_000,
            ..TimeRules::default()
        };
        p.sign_latency_ms = 5;
        p.handover = true;
        let mut nodes = nodes(SEVEN, &p);
        for n in nodes.iter_mut() {
            n.core.start(0);
        }
        let mut net = Net::new(SEVEN);
        net.cut = cut.to_vec();
        let mut blocks: Vec<Vec<(u64, u64)>> = vec![Vec::new(); SEVEN];
        let mut certified: Vec<BTreeMap<u64, Digest>> = vec![BTreeMap::new(); SEVEN];
        let mut now = 0u64;
        let mut seq = 0u64;
        while now < until {
            net.cut_due(now);
            // Certificate gossip, as the node runs it: a validator adopts
            // the closing and handover certificates of its running epoch
            // from any peer it still hears, its consensus channel to that
            // peer up or not.
            if now.is_multiple_of(500) {
                for i in (0..SEVEN).filter(|i| !net.is_cut(*i, now)) {
                    let epoch = nodes[i].core.committee().epoch;
                    let mut carried: BTreeMap<u64, _> = BTreeMap::new();
                    for j in
                        (0..SEVEN).filter(|j| *j != i && !net.is_cut(*j, now) && !lost(*j, i, now))
                    {
                        for (c, sessions) in nodes[j]
                            .handovers
                            .iter()
                            .filter(|(c, _)| c.checkpoint.epoch == epoch)
                        {
                            carried
                                .entry(c.checkpoint.index)
                                .or_insert_with(|| (c.clone(), sessions.clone()));
                        }
                    }
                    for (cert, sessions) in carried.into_values() {
                        nodes[i].core.adopt_certificate(cert, sessions);
                        nodes[i].tick(now);
                    }
                }
            }
            net.follow_epochs(&mut nodes, now);
            net.connect_due(&mut nodes, now);
            if now.is_multiple_of(200) {
                seq += 1;
                let mut digest = [0u8; 32];
                digest[..8].copy_from_slice(&seq.to_be_bytes());
                let to = (seq as usize) % SEVEN;
                nodes[to].submit(
                    SimBatch {
                        digest,
                        transactions: 1,
                    },
                    100,
                );
            }
            loop {
                net.follow_epochs(&mut nodes, now);
                let mut frames = Vec::new();
                for i in 0..SEVEN {
                    let epoch = nodes[i].core.committee().epoch;
                    let out = nodes[i].drain(now);
                    for (index, _, digest) in out.certified {
                        certified[i].insert(index, digest);
                    }
                    blocks[i].extend(out.ordered.iter().map(|_| (epoch, now)));
                    for (t, m) in out.sends {
                        for to in (0..SEVEN).filter(|q| {
                            *q != i && (t == Target::All || t == Target::One(*q as ValidatorIndex))
                        }) {
                            frames.push((i, to, epoch, m.clone()));
                        }
                    }
                }
                if frames.is_empty() {
                    break;
                }
                for (from, to, epoch, m) in frames {
                    if net.carries(from, to, epoch) && !lost(from, to, now) {
                        nodes[to].deliver(from as u16, vec![m], now);
                    }
                }
            }
            for n in nodes.iter_mut() {
                n.tick(now);
            }
            now += 10;
        }
        (nodes, blocks, certified)
    }

    /// Channels that fail in one direction only: validator 5's frames stop
    /// reaching anyone mid-epoch while it still hears them, and validator
    /// 2 stops hearing anyone while its own frames still arrive. The others
    /// keep ordering blocks and certifying checkpoints through at least
    /// three epochs, and every validator certifies the same checkpoints.
    #[test]
    fn a_committee_keeps_committing_when_channels_fail_in_one_direction() {
        let lost = |from: usize, to: usize, now: u64| {
            (from == 5 && now >= 6_000) || (to == 2 && now >= 13_000)
        };
        let (nodes, blocks, certified) = run_with_cuts(&[], &lost, 70_000);
        let live = [0usize, 1, 3, 4, 6];
        for &i in &live {
            let epoch = nodes[i].core.committee().epoch;
            assert!(
                !nodes[i].core.is_halted(),
                "validator {i} halted in epoch {epoch}"
            );
            let epochs: std::collections::BTreeSet<u64> = blocks[i]
                .iter()
                .filter(|(_, at)| *at > 13_000)
                .map(|(e, _)| *e)
                .collect();
            assert!(
                epochs.len() >= 3,
                "validator {i} ordered blocks in epochs {epochs:?}, now in epoch {epoch}"
            );
        }
        for i in 0..nodes.len() {
            for (index, digest) in &certified[i] {
                if let Some(d) = certified[0].get(index) {
                    assert_eq!(
                        d, digest,
                        "validators {i} and 0 certified different checkpoints at {index}"
                    );
                }
            }
        }
    }

    /// Up to `f` validators unreachable, from the start or from the middle
    /// of an epoch: the others keep ordering blocks and certifying
    /// checkpoints through at least three epochs after the last one is cut
    /// off, and agree on every checkpoint.
    #[test]
    fn a_committee_with_up_to_f_validators_unreachable_keeps_committing_across_epochs() {
        let cases: [(&str, Vec<(usize, u64)>); 4] = [
            ("one down from the start", vec![(6, 0)]),
            ("two down from the start", vec![(2, 0), (5, 0)]),
            ("one down mid-epoch", vec![(3, 14_000)]),
            ("two down mid-epoch", vec![(1, 4_000), (4, 15_000)]),
        ];
        for (name, cut) in cases {
            let (nodes, blocks, certified) = run_with_cuts(&cut, &|_, _, _| false, 70_000);
            let last_cut = cut.iter().map(|(_, at)| *at).max().expect("a cut");
            let live: Vec<usize> = (0..nodes.len())
                .filter(|i| !cut.iter().any(|(v, _)| v == i))
                .collect();
            for &i in &live {
                let epoch = nodes[i].core.committee().epoch;
                assert!(
                    !nodes[i].core.is_halted(),
                    "{name}: validator {i} halted in epoch {epoch}"
                );
                let epochs: std::collections::BTreeSet<u64> = blocks[i]
                    .iter()
                    .filter(|(_, at)| *at > last_cut)
                    .map(|(e, _)| *e)
                    .collect();
                assert!(
                    epochs.len() >= 3,
                    "{name}: validator {i} ordered blocks in epochs {epochs:?} after the last cut, now in epoch {epoch}"
                );
                for (index, digest) in &certified[i] {
                    if let Some(d) = certified[live[0]].get(index) {
                        assert_eq!(
                            d, digest,
                            "{name}: validators {i} and {} certified different checkpoints at {index}",
                            live[0]
                        );
                    }
                }
            }
        }
    }

    /// Asserts that every validator in `live` is running and ordered blocks
    /// in at least `min_epochs` epochs after `after`, and that no two
    /// validators certified different checkpoints at the same index.
    fn assert_live_and_agreed(
        name: &str,
        nodes: &[TdcNode],
        blocks: &[Vec<(u64, u64)>],
        certified: &[BTreeMap<u64, Digest>],
        live: &[usize],
        after: u64,
        min_epochs: usize,
    ) {
        for &i in live {
            let epoch = nodes[i].core.committee().epoch;
            assert!(
                !nodes[i].core.is_halted(),
                "{name}: validator {i} halted in epoch {epoch}"
            );
            let epochs: std::collections::BTreeSet<u64> = blocks[i]
                .iter()
                .filter(|(_, at)| *at > after)
                .map(|(e, _)| *e)
                .collect();
            assert!(
                epochs.len() >= min_epochs,
                "{name}: validator {i} ordered blocks in epochs {epochs:?} after {after} ms, now in epoch {epoch}"
            );
        }
        for i in 0..certified.len() {
            for j in i + 1..certified.len() {
                for (index, digest) in &certified[i] {
                    if let Some(d) = certified[j].get(index) {
                        assert_eq!(
                            d, digest,
                            "{name}: validators {i} and {j} certified different checkpoints at {index}"
                        );
                    }
                }
            }
        }
    }

    /// Partial channel failure: single links between pairs fail in both
    /// directions while each end still reaches the rest of the committee,
    /// so connectivity is no longer transitive. Validator 6 keeps channels
    /// to exactly a quorum (itself and four peers). Every validator keeps
    /// ordering blocks through at least three epochs after the links fail,
    /// relaying what it misses through the peers it still reaches, and all
    /// agree on every checkpoint.
    #[test]
    fn a_committee_keeps_committing_when_single_links_fail_in_both_directions() {
        const FAILED: [(usize, usize); 4] = [(0, 1), (2, 5), (3, 6), (4, 6)];
        let lost = |from: usize, to: usize, now: u64| {
            now >= 5_000
                && FAILED
                    .iter()
                    .any(|&(a, b)| (a, b) == (from, to) || (b, a) == (from, to))
        };
        let (nodes, blocks, certified) = run_with_cuts(&[], &lost, 70_000);
        let all: Vec<usize> = (0..nodes.len()).collect();
        assert_live_and_agreed(
            "single links down",
            &nodes,
            &blocks,
            &certified,
            &all,
            5_000,
            3,
        );
    }

    /// Partial one-way failure: single links fail in one direction only, at
    /// different times, so a validator hears a peer it cannot reach and the
    /// reverse. No validator is cut off as a whole; every one keeps ordering
    /// blocks through at least three epochs, and all agree.
    #[test]
    fn a_committee_keeps_committing_when_single_links_fail_in_one_direction() {
        const FAILED: [(usize, usize, u64); 5] = [
            (1, 3, 4_000),
            (3, 5, 9_000),
            (6, 0, 12_000),
            (0, 6, 21_000),
            (4, 2, 15_000),
        ];
        let lost = |from: usize, to: usize, now: u64| {
            FAILED
                .iter()
                .any(|&(f, t, at)| f == from && t == to && now >= at)
        };
        let (nodes, blocks, certified) = run_with_cuts(&[], &lost, 70_000);
        let all: Vec<usize> = (0..nodes.len()).collect();
        assert_live_and_agreed(
            "single links one way",
            &nodes,
            &blocks,
            &certified,
            &all,
            21_000,
            3,
        );
    }

    /// A split that leaves no side with a quorum: three validators against
    /// four, from mid-epoch for 20 s. Neither side orders a block while
    /// split, nobody certifies a conflicting checkpoint, and once the split
    /// heals every validator orders blocks again through at least two more
    /// epochs.
    #[test]
    fn a_split_without_a_quorum_halts_ordering_safely_and_recovers_when_it_heals() {
        const SPLIT: u64 = 13_000;
        const HEAL: u64 = 33_000;
        let side = |v: usize| v < 3;
        let lost = |from: usize, to: usize, now: u64| {
            (SPLIT..HEAL).contains(&now) && side(from) != side(to)
        };
        let (nodes, blocks, certified) = run_with_cuts(&[], &lost, 80_000);
        // Blocks already in flight when the split started are ordered in
        // its first moments; none after that until it heals.
        for (i, b) in blocks.iter().enumerate() {
            let during: Vec<u64> = b
                .iter()
                .map(|(_, at)| *at)
                .filter(|at| (SPLIT + 2_000..HEAL).contains(at))
                .collect();
            assert!(
                during.is_empty(),
                "validator {i} ordered blocks while no side had a quorum: {during:?}"
            );
        }
        let all: Vec<usize> = (0..nodes.len()).collect();
        assert_live_and_agreed("split healed", &nodes, &blocks, &certified, &all, HEAL, 2);
    }

    /// Seven validators; validator 6 loses every channel from just before
    /// the first handover until the others are in epoch 1, then is
    /// reachable again. Its peers refuse a hello for epoch 0, so without the
    /// handover certificate it never leaves epoch 0. With `gossip`, the
    /// certificate reaches it as the network carries certificates, it adopts
    /// it and enters epoch 1 like the others. Returns the nodes and the
    /// certificates each formed or adopted.
    fn run_with_a_missed_handover(gossip: bool) -> (Vec<TdcNode>, Vec<BTreeMap<u64, Digest>>) {
        // Cut off from 8s; healed only once the others are an epoch ahead,
        // so it has missed at least one handover.
        let (nodes, certified, _) = run_with_a_lagging_validator(
            Lag {
                cut_at: 8_000,
                earliest_heal: 14_000,
                after_a_handover: true,
                after_the_close: false,
                starts_late: false,
                load: false,
            },
            gossip,
        );
        (nodes, certified)
    }

    /// When validator 6 of seven is out of reach. `starts_late`: it is not
    /// started until it is healed (a node booted after the others), so it
    /// proposed nothing and holds no channel before then. `after_the_close`:
    /// healed once the others certified its epoch's closing checkpoint, which
    /// reaches it before the epoch's vertices do. `load`: the others are
    /// handed a batch every 50 ms, so the epoch orders blocks.
    struct Lag {
        cut_at: u64,
        earliest_heal: u64,
        after_a_handover: bool,
        after_the_close: bool,
        starts_late: bool,
        load: bool,
    }

    fn run_with_a_lagging_validator(
        lag: Lag,
        gossip: bool,
    ) -> (
        Vec<TdcNode>,
        Vec<BTreeMap<u64, Digest>>,
        Vec<BTreeMap<u64, Digest>>,
    ) {
        const SEVEN: usize = 7;
        const LAGGING: usize = 6;
        let Lag {
            cut_at,
            earliest_heal,
            after_a_handover,
            after_the_close,
            starts_late,
            load,
        } = lag;
        let mut healed = false;
        let mut p = TdcParams::honest();
        p.time = TimeRules {
            checkpoint_interval_ms: 500,
            epoch_checkpoints: 20,
            handover_confirmations: 2,
            idle_round_interval_ms: 1_000,
            ..TimeRules::default()
        };
        p.sign_latency_ms = 5;
        p.handover = true;
        if after_the_close {
            // The others keep the epoch's whole DAG, as a committee does
            // whose epoch runs fewer rounds than the GC depth, so the
            // validator can order the epoch from its first round.
            p.config.gc_depth = 1_000;
        }
        let mut nodes = nodes(SEVEN, &p);
        for (i, n) in nodes.iter_mut().enumerate() {
            if !(starts_late && i == LAGGING) {
                n.core.start(0);
            }
        }
        let mut net = Net::new(SEVEN);
        net.cut = vec![(LAGGING, cut_at)];
        let mut certified: Vec<BTreeMap<u64, Digest>> = vec![BTreeMap::new(); SEVEN];
        let mut anchors: Vec<BTreeMap<u64, Digest>> = vec![BTreeMap::new(); SEVEN];
        let mut now = 0u64;
        while now < 60_000 {
            let lagging_epoch = nodes[LAGGING].core.committee().epoch;
            let ahead = nodes[0].core.committee().epoch > lagging_epoch;
            let closed = nodes[0]
                .handovers
                .iter()
                .any(|(c, _)| c.checkpoint.epoch == lagging_epoch);
            let mut healing = false;
            if !healed
                && now >= earliest_heal
                && (ahead || !after_a_handover)
                && (closed || !after_the_close)
            {
                healed = true;
                healing = true;
                net.cut.clear();
                if starts_late {
                    nodes[LAGGING].core.start(now);
                }
                net.reconnect(LAGGING, now);
            }
            net.cut_due(now);
            if load && now.is_multiple_of(50) {
                let seq = now / 50;
                let mut digest = [0u8; 32];
                digest[..8].copy_from_slice(&seq.to_be_bytes());
                nodes[(seq as usize) % LAGGING].submit(
                    SimBatch {
                        digest,
                        transactions: 1,
                    },
                    100,
                );
            }
            // The network carries certificates to every node, a validator's
            // own channels or not.
            if gossip && healed && (healing || now.is_multiple_of(500)) {
                let epoch = nodes[LAGGING].core.committee().epoch;
                // The epoch's closing certificate, then its handover.
                let mut carried: BTreeMap<u64, _> = BTreeMap::new();
                for (c, sessions) in nodes[..LAGGING].iter().flat_map(|n| n.handovers.iter()) {
                    if c.checkpoint.epoch == epoch {
                        carried
                            .entry(c.checkpoint.index)
                            .or_insert_with(|| (c.clone(), sessions.clone()));
                    }
                }
                for (cert, sessions) in carried.into_values() {
                    nodes[LAGGING].core.adopt_certificate(cert, sessions);
                    nodes[LAGGING].tick(now);
                }
            }
            net.follow_epochs(&mut nodes, now);
            net.connect_due(&mut nodes, now);
            loop {
                net.follow_epochs(&mut nodes, now);
                let mut frames = Vec::new();
                for i in 0..SEVEN {
                    let epoch = nodes[i].core.committee().epoch;
                    let out = nodes[i].drain(now);
                    for (index, _, digest) in out.certified {
                        certified[i].insert(index, digest);
                    }
                    for (height, anchor, _) in out.ordered {
                        anchors[i].insert(height, anchor);
                    }
                    for (t, m) in out.sends {
                        for to in (0..SEVEN).filter(|q| {
                            *q != i && (t == Target::All || t == Target::One(*q as ValidatorIndex))
                        }) {
                            frames.push((i, to, epoch, m.clone()));
                        }
                    }
                }
                if frames.is_empty() {
                    break;
                }
                for (from, to, epoch, m) in frames {
                    if net.carries(from, to, epoch) {
                        nodes[to].deliver(from as u16, vec![m], now);
                    }
                }
            }
            for n in nodes.iter_mut() {
                n.tick(now);
            }
            now += 10;
        }
        (nodes, certified, anchors)
    }

    #[test]
    fn a_validator_that_missed_the_handover_enters_the_next_epoch_from_its_certificate() {
        let (stuck, _) = run_with_a_missed_handover(false);
        let (behind, ahead) = (
            stuck[6].core.committee().epoch,
            stuck[0].core.committee().epoch,
        );
        assert!(
            behind < ahead,
            "without the certificate the lagging validator stays behind ({behind} vs {ahead})"
        );
        assert!(stuck[0].core.committee().epoch >= 3);

        let (nodes, certified) = run_with_a_missed_handover(true);
        let lagging = &nodes[6];
        let epoch = lagging.core.committee().epoch;
        assert!(epoch >= 3, "the lagging validator is in epoch {epoch}");
        assert!(!lagging.core.is_halted());
        assert!(
            lagging.core.stats().leaders_committed > 0,
            "it commits again"
        );
        for (index, digest) in &certified[6] {
            if let Some(d) = certified[0].get(index) {
                assert_eq!(
                    d, digest,
                    "validators 6 and 0 certified different checkpoints at {index}"
                );
            }
        }
    }

    #[test]
    fn a_validator_started_after_the_others_joins_and_commits() {
        // Booted 5 s after the others, inside their first epoch.
        let lag = Lag {
            cut_at: 0,
            earliest_heal: 5_000,
            after_a_handover: false,
            after_the_close: false,
            starts_late: true,
            load: false,
        };
        let (nodes, certified, _) = run_with_a_lagging_validator(lag, false);
        assert_late_validator_caught_up(&nodes, &certified);
    }

    #[test]
    fn a_validator_started_after_a_handover_joins_from_the_certificates() {
        // Booted once the others are an epoch ahead: only the carried
        // certificates bring it to their committee.
        let lag = Lag {
            cut_at: 0,
            earliest_heal: 12_000,
            after_a_handover: true,
            after_the_close: false,
            starts_late: true,
            load: false,
        };
        let (stuck, ..) = run_with_a_lagging_validator(lag, false);
        assert!(stuck[6].core.committee().epoch < stuck[0].core.committee().epoch);
        let lag = Lag {
            cut_at: 0,
            earliest_heal: 12_000,
            after_a_handover: true,
            after_the_close: false,
            starts_late: true,
            load: false,
        };
        let (nodes, certified, _) = run_with_a_lagging_validator(lag, true);
        assert_late_validator_caught_up(&nodes, &certified);
    }

    #[test]
    fn a_validator_that_learns_the_close_first_orders_the_epoch_as_the_others_did() {
        // Booted once the others certified its epoch's closing checkpoint,
        // which reaches it before it orders a vertex of the epoch: it still
        // orders the epoch from its vertices, as the others did.
        let lag = Lag {
            cut_at: 0,
            earliest_heal: 5_000,
            after_a_handover: false,
            after_the_close: true,
            starts_late: true,
            load: true,
        };
        let (nodes, certified, anchors) = run_with_a_lagging_validator(lag, true);
        assert_late_validator_caught_up(&nodes, &certified);
        let common: Vec<u64> = anchors[6]
            .keys()
            .filter(|h| anchors[0].contains_key(h))
            .copied()
            .collect();
        assert!(!common.is_empty(), "it orders blocks the others ordered");
        for h in common {
            assert_eq!(
                anchors[6][&h], anchors[0][&h],
                "validators 6 and 0 ordered different anchors at height {h}"
            );
        }
    }

    fn assert_late_validator_caught_up(nodes: &[TdcNode], certified: &[BTreeMap<u64, Digest>]) {
        let (late, first) = (&nodes[6], &nodes[0]);
        assert!(first.core.committee().epoch >= 3);
        assert!(
            late.core.committee().epoch + 1 >= first.core.committee().epoch,
            "the late validator is in epoch {} of {}",
            late.core.committee().epoch,
            first.core.committee().epoch
        );
        assert!(!late.core.is_halted());
        assert!(late.core.stats().leaders_committed > 0, "it commits");
        assert!(!certified[6].is_empty(), "it certifies checkpoints");
        for (index, digest) in &certified[6] {
            if let Some(d) = certified[0].get(index) {
                assert_eq!(
                    d, digest,
                    "validators 6 and 0 certified different checkpoints at {index}"
                );
            }
        }
    }

    /// Epoch length and the stall at each handover under the local test
    /// genesis (500 ms checkpoints, 20 per epoch) with channels coming up
    /// staggered at every epoch, as a node's do, a batch submitted every
    /// 50 ms, and no CPU limit: the protocol's own timing. Prints one
    /// `GATE {json}` line. Run with `--ignored --nocapture`.
    #[test]
    #[ignore]
    #[allow(clippy::needless_range_loop)] // the loop index is also the node's validator index
    fn gate_epoch_handover_timing() {
        let mut p = TdcParams::honest();
        p.time = TimeRules {
            checkpoint_interval_ms: 500,
            epoch_checkpoints: 20,
            handover_confirmations: 2,
            idle_round_interval_ms: 1_000,
            ..TimeRules::default()
        };
        p.sign_latency_ms = 5;
        p.handover = true;
        let mut nodes = nodes(N, &p);
        for n in nodes.iter_mut() {
            n.core.start(0);
        }
        let mut net = Net::new(N);
        let mut entered: Vec<u64> = vec![0];
        let mut blocks: Vec<u64> = Vec::new();
        let mut now = 0u64;
        let mut seq = 0u64;
        while now < 180_000 {
            net.follow_epochs(&mut nodes, now);
            net.connect_due(&mut nodes, now);
            if now.is_multiple_of(50) {
                seq += 1;
                let mut digest = [0u8; 32];
                digest[..8].copy_from_slice(&seq.to_be_bytes());
                nodes[(seq as usize) % N].submit(
                    SimBatch {
                        digest,
                        transactions: 1,
                    },
                    100,
                );
            }
            loop {
                net.follow_epochs(&mut nodes, now);
                let mut frames = Vec::new();
                for i in 0..N {
                    let epoch = nodes[i].core.committee().epoch;
                    let out = nodes[i].drain(now);
                    if i == 0 {
                        blocks.extend(out.ordered.iter().map(|_| now));
                    }
                    for (t, m) in out.sends {
                        for to in (0..N).filter(|q| {
                            *q != i && (t == Target::All || t == Target::One(*q as ValidatorIndex))
                        }) {
                            frames.push((i, to, epoch, m.clone()));
                        }
                    }
                }
                if frames.is_empty() {
                    break;
                }
                for (from, to, epoch, m) in frames {
                    if net.carries(from, to, epoch) {
                        nodes[to].deliver(from as u16, vec![m], now);
                    }
                }
            }
            for n in nodes.iter_mut() {
                n.tick(now);
            }
            if nodes[0].core.committee().epoch as usize >= entered.len() {
                entered.push(now);
            }
            now += 10;
        }
        let lengths: Vec<u64> = entered.windows(2).map(|w| w[1] - w[0]).collect();
        let mut gaps: Vec<u64> = blocks.windows(2).map(|w| w[1] - w[0]).collect();
        gaps.sort_unstable();
        let at = |q: f64| {
            gaps.get(((gaps.len() as f64 - 1.0) * q) as usize)
                .copied()
                .unwrap_or(0)
        };
        // The longest wait for a block around each handover.
        let stalls: Vec<u64> = entered[1..]
            .iter()
            .map(|e| {
                blocks
                    .windows(2)
                    .filter(|w| w[0] <= *e + 5_000 && w[1] + 5_000 >= *e)
                    .map(|w| w[1] - w[0])
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        println!(
            "GATE {{\"validators\":{N},\"epochs\":{},\"epoch_ms\":{lengths:?},\"handover_stall_ms\":{stalls:?},\"blocks\":{},\"block_gap_p50_ms\":{},\"block_gap_p99_ms\":{},\"block_gap_max_ms\":{}}}",
            lengths.len(),
            blocks.len(),
            at(0.5),
            at(0.99),
            gaps.last().copied().unwrap_or(0)
        );
        assert!(lengths.len() >= 5, "only {} epochs in 180 s", lengths.len());
    }
}

/// Validators whose clocks disagree, on lossy links.
#[cfg(test)]
#[path = "tdc_skew.rs"]
mod skew_tests;
