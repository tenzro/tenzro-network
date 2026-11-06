//! Reference protocols run in the same emulator, for comparison.
//!
//! - [`SailfishNode`]: the signature-free DAG with the core's reliable
//!   broadcast, one leader per round, leader timeouts, a no-vote rule and a
//!   commit rule on a quorum of next-round first proposals, with batch
//!   payloads carried inside vertices and ordered as soon as their vertex is
//!   ordered, and no checkpoints.
//! - [`MysticetiNode`]: an uncertified DAG. Each validator signs one block
//!   per round and sends it once (no reliable broadcast). The round-`r`
//!   leader commits when a quorum of round-`r+2` blocks each reference a
//!   quorum of round-`r+1` blocks that reference the leader, and is skipped
//!   when a quorum of round-`r+1` blocks do not reference it; undecided
//!   leaders are decided by the next committed leader's history.
//!
//! Both use a fixed seeded leader schedule and one leader per round.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::driver::{Output, SimBatch, SimNode};
use crate::committee::{Committee, SeatSet, ValidatorIndex};
use crate::core::Target;
use crate::dag::Dag;
use crate::rbc::{RbcAction, ReliableBroadcast, Signal};
use crate::schedule::Schedule;
use crate::vertex::{BatchRef, Digest, Round, Vertex, VertexRef};

/// Weak edges a Sailfish vertex carries at most: the same bound TDC's core
/// uses, so the two differ only in protocol.
const SAILFISH_MAX_WEAK_REFS: usize = 64;

// ---------------------------------------------------------------------------
// Signature-free DAG, payload in the vertex.
// ---------------------------------------------------------------------------

/// Messages of the signature-free baseline.
#[derive(Debug, Clone)]
pub enum SfMsg {
    /// A vertex and its no-votes; its batches' payloads travel with it.
    Propose(Vertex, Vec<VertexRef>),
    /// Reliable-broadcast signals.
    Signals(Vec<Signal>),
    /// Leader timeout.
    Timeout(Round),
    /// Fetch vertices by digest.
    Fetch(Vec<Digest>),
    /// Fetched vertices, each with its no-votes.
    Vertices(Vec<(Vertex, Vec<VertexRef>)>),
}

/// A signature-free DAG validator.
pub struct SailfishNode {
    committee: Committee,
    me: ValidatorIndex,
    schedule: Schedule,
    rbc: ReliableBroadcast,
    dag: Dag,
    bodies: HashMap<Digest, Vertex>,
    // A leader vertex's no-votes: round `round` vertices of others that do
    // not reference the previous leader. They travel beside the vertex.
    no_votes: HashMap<Digest, (Round, Vec<VertexRef>)>,
    first: BTreeMap<Round, HashMap<ValidatorIndex, Vec<VertexRef>>>,
    timeouts: BTreeMap<Round, SeatSet>,
    timed_out: HashSet<Round>,
    round: Option<Round>,
    entered_ms: u64,
    leader_timeout_ms: u64,
    last_committed: Option<Round>,
    ordered: HashSet<Digest>,
    height: u64,
    pending: Vec<BatchRef>,
    next_sequence: u64,
    wanted: HashMap<Digest, u64>,
    out: Vec<(Target, SfMsg)>,
    blocks: Vec<(u64, Digest, Vec<Digest>)>,
}

/// `n` signature-free baseline validators.
pub fn sailfish_nodes(n: usize, leader_timeout_ms: u64) -> Vec<SailfishNode> {
    let (c, _) = super::tdc::committee(n, n as u64);
    (0..n)
        .map(|i| SailfishNode {
            schedule: Schedule::new(&c, [5; 32], 1, crate::schedule::LOOKAHEAD_ROUNDS),
            committee: c.clone(),
            me: i as ValidatorIndex,
            rbc: ReliableBroadcast::new(i as ValidatorIndex),
            dag: Dag::new(),
            bodies: HashMap::new(),
            no_votes: HashMap::new(),
            first: BTreeMap::new(),
            timeouts: BTreeMap::new(),
            timed_out: HashSet::new(),
            round: None,
            entered_ms: 0,
            leader_timeout_ms,
            last_committed: None,
            ordered: HashSet::new(),
            height: 1,
            pending: Vec::new(),
            next_sequence: 0,
            wanted: HashMap::new(),
            out: Vec::new(),
            blocks: Vec::new(),
        })
        .collect()
}

impl SailfishNode {
    fn weight(&self, r: Round) -> u64 {
        self.dag
            .round(r)
            .map(|(s, ..)| self.committee.seats(s))
            .sum()
    }

    fn apply(&mut self, acts: Vec<RbcAction>) {
        let mut sig = Vec::new();
        for a in acts {
            match a {
                RbcAction::Broadcast(s) => sig.push(s),
                RbcAction::Deliver { round, digest, .. } => {
                    self.dag.expect(digest, round);
                    match self.bodies.get(&digest).cloned() {
                        Some(v) => self.offer(v),
                        None => {
                            self.wanted.entry(digest).or_insert(0);
                        }
                    }
                }
            }
        }
        if !sig.is_empty() {
            self.out.push((Target::All, SfMsg::Signals(sig)));
        }
    }

    fn offer(&mut self, v: Vertex) {
        let (ins, missing) = self.dag.offer(v);
        for r in ins {
            self.wanted.remove(&r.digest);
        }
        for d in missing {
            self.wanted.entry(d).or_insert(0);
        }
    }

    fn propose(&mut self, round: Round, no_votes: Vec<VertexRef>, now_ms: u64) {
        let mut strong: Vec<VertexRef> = if round == 0 {
            Vec::new()
        } else {
            self.dag
                .round(round - 1)
                .map(|(s, d, _)| VertexRef {
                    round: round - 1,
                    source: s,
                    digest: *d,
                })
                .collect()
        };
        strong.sort();
        // Weak edges to vertices no strong path reaches, as the DAG
        // protocols Sailfish builds on use, so a slow author's vertex (and
        // the batches it carries) is still ordered.
        let weak = if round >= 2 {
            let roots: Vec<Digest> = strong.iter().map(|r| r.digest).collect();
            let ordered = &self.ordered;
            self.dag.orphans_below(
                round - 1,
                &roots,
                |d| ordered.contains(d),
                SAILFISH_MAX_WEAK_REFS,
            )
        } else {
            Vec::new()
        };
        let v = Vertex {
            epoch: 0,
            round,
            source: self.me,
            strong,
            weak,
            batches: std::mem::take(&mut self.pending),
            carried: Vec::new(),
            timestamp_ms: now_ms,
        };
        let d = v.digest();
        self.round = Some(round);
        self.entered_ms = now_ms;
        self.first
            .entry(round)
            .or_default()
            .insert(self.me, v.strong.clone());
        self.bodies.insert(d, v.clone());
        if !no_votes.is_empty() {
            self.no_votes.insert(d, (round, no_votes.clone()));
        }
        self.out.push((Target::All, SfMsg::Propose(v, no_votes)));
        let acts = self
            .rbc
            .on_propose(&self.committee, self.me, round, self.me, d);
        self.apply(acts);
    }

    fn advance(&mut self, now_ms: u64) {
        loop {
            let Some(r) = self.round else { return };
            let top = self.dag.highest_round().unwrap_or(r).max(r);
            let mut t = top;
            while t > r && self.weight(t) < self.committee.quorum() {
                t -= 1;
            }
            if self.weight(t) < self.committee.quorum() {
                return;
            }
            let leader = self.schedule.leader(t, 0);
            let have = self.dag.at(t, leader).is_some();
            let to = self.timeouts.get(&t).map_or(0, |s| s.weight()) >= self.committee.quorum();
            if !have && !to {
                return;
            }
            let next = t + 1;
            let mut nv = Vec::new();
            if self.schedule.leader(next, 0) == self.me && !have {
                let mut w = SeatSet::new();
                w.insert(self.me, self.committee.seats(self.me));
                for (s, d, v) in self.dag.round(next) {
                    if s != self.me && !v.references_author(leader) {
                        w.insert(s, self.committee.seats(s));
                        nv.push(VertexRef {
                            round: next,
                            source: s,
                            digest: *d,
                        });
                    }
                }
                if w.weight() < self.committee.quorum() {
                    return;
                }
                nv.sort();
            }
            self.propose(next, nv, now_ms);
        }
    }

    fn leader_vertex(&self, round: Round) -> Option<VertexRef> {
        let l = self.schedule.leader(round, 0);
        let (d, v) = self.dag.at(round, l)?;
        if round > 0 && !v.references_author(self.schedule.leader(round - 1, 0)) {
            let prev = self.schedule.leader(round - 1, 0);
            let mut w = SeatSet::new();
            w.insert(l, self.committee.seats(l));
            for n in self
                .no_votes
                .get(d)
                .map(|(_, n)| n.as_slice())
                .unwrap_or_default()
            {
                if let Some(x) = self.dag.get(&n.digest)
                    && !x.references_author(prev)
                {
                    w.insert(x.source, self.committee.seats(x.source));
                }
            }
            if w.weight() < self.committee.quorum() {
                return None;
            }
        }
        Some(VertexRef {
            round,
            source: l,
            digest: *d,
        })
    }

    fn commit(&mut self) {
        loop {
            let lo = self.last_committed.map_or(0, |r| r + 1);
            let Some(hi) = self.first.keys().next_back().and_then(|r| r.checked_sub(1)) else {
                return;
            };
            let mut found = None;
            for r in (lo..=hi).rev() {
                let Some(l) = self.leader_vertex(r) else {
                    continue;
                };
                let mut w = SeatSet::new();
                if let Some(p) = self.first.get(&(r + 1)) {
                    for (s, refs) in p {
                        if refs.contains(&l) {
                            w.insert(*s, self.committee.seats(*s));
                        }
                    }
                }
                if w.weight() >= self.committee.quorum() {
                    let mut a = l;
                    for e in (lo..r).rev() {
                        if let Some(x) = self.leader_vertex(e)
                            && self.dag.strong_path(&a.digest, &x)
                        {
                            a = x;
                        }
                    }
                    found = Some(a);
                    break;
                }
            }
            let Some(a) = found else { return };
            self.last_committed = Some(a.round);
            let ordered = &self.ordered;
            let hist = self.dag.causal_history(&a.digest, |d| ordered.contains(d));
            let mut batches = Vec::new();
            for r in &hist {
                self.ordered.insert(r.digest);
                if let Some(v) = self.dag.get(&r.digest) {
                    batches.extend(v.batches.iter().map(|b| b.digest));
                }
            }
            self.blocks.push((self.height, a.digest, batches));
            self.height += 1;
            if let Some(floor) = a.round.checked_sub(50) {
                self.dag.prune_below(floor);
                self.rbc.prune_below(floor);
                self.first = self.first.split_off(&floor);
                self.timeouts = self.timeouts.split_off(&floor);
                self.bodies.retain(|_, v| v.round >= floor);
                self.no_votes.retain(|_, (r, _)| *r >= floor);
            }
        }
    }
}

impl SimNode for SailfishNode {
    type Msg = SfMsg;

    fn start(&mut self, now_ms: u64) {
        self.propose(0, Vec::new(), now_ms);
    }

    fn deliver(&mut self, from: u16, msgs: Vec<SfMsg>, now_ms: u64) {
        for m in msgs {
            match m {
                SfMsg::Propose(v, nv) => {
                    if v.source != from || v.check_structure(&self.committee).is_err() {
                        continue;
                    }
                    let d = v.digest();
                    if !nv.is_empty() {
                        self.no_votes.entry(d).or_insert((v.round, nv));
                    }
                    if self.rbc.proposed(v.round, v.source).is_none() {
                        self.first
                            .entry(v.round)
                            .or_default()
                            .insert(v.source, v.strong.clone());
                    }
                    let acts = self
                        .rbc
                        .on_propose(&self.committee, from, v.round, v.source, d);
                    if !acts.is_empty() {
                        self.bodies.insert(d, v);
                    }
                    self.apply(acts);
                }
                SfMsg::Signals(s) => {
                    for x in s {
                        let acts = self.rbc.on_signal(&self.committee, from, x);
                        self.apply(acts);
                    }
                }
                SfMsg::Timeout(r) => {
                    self.timeouts
                        .entry(r)
                        .or_default()
                        .insert(from, self.committee.seats(from));
                    if self.timeouts[&r].weight() >= self.committee.validity()
                        && self.timed_out.insert(r)
                    {
                        self.out.push((Target::All, SfMsg::Timeout(r)));
                        let me = self.me;
                        self.timeouts
                            .entry(r)
                            .or_default()
                            .insert(me, self.committee.seats(me));
                    }
                }
                SfMsg::Fetch(ds) => {
                    let vs: Vec<(Vertex, Vec<VertexRef>)> = ds
                        .iter()
                        .filter_map(|d| {
                            let v = self.dag.get(d).or_else(|| self.bodies.get(d)).cloned()?;
                            Some((
                                v,
                                self.no_votes
                                    .get(d)
                                    .map(|(_, n)| n.clone())
                                    .unwrap_or_default(),
                            ))
                        })
                        .collect();
                    if !vs.is_empty() {
                        self.out.push((Target::One(from), SfMsg::Vertices(vs)));
                    }
                }
                SfMsg::Vertices(vs) => {
                    for (v, nv) in vs {
                        if !nv.is_empty() {
                            self.no_votes.entry(v.digest()).or_insert((v.round, nv));
                        }
                        self.offer(v);
                    }
                }
            }
        }
        self.commit();
        self.advance(now_ms);
    }

    fn tick(&mut self, now_ms: u64) {
        if let Some(r) = self.round
            && now_ms.saturating_sub(self.entered_ms) >= self.leader_timeout_ms
            && self.dag.at(r, self.schedule.leader(r, 0)).is_none()
            && self.timed_out.insert(r)
        {
            self.out.push((Target::All, SfMsg::Timeout(r)));
            let me = self.me;
            self.timeouts
                .entry(r)
                .or_default()
                .insert(me, self.committee.seats(me));
        }
        let n = self.committee.size() as u64;
        let mut ask: HashMap<u16, Vec<Digest>> = HashMap::new();
        for (d, last) in self.wanted.iter_mut() {
            if *last == 0 || now_ms.saturating_sub(*last) >= 250 {
                *last = now_ms.max(1);
                let p = (u64::from(d[0]) + now_ms / 250) % n;
                let p = if p as u16 == self.me { (p + 1) % n } else { p } as u16;
                ask.entry(p).or_default().push(*d);
            }
        }
        for (p, ds) in ask {
            self.out.push((Target::One(p), SfMsg::Fetch(ds)));
        }
        self.commit();
        self.advance(now_ms);
    }

    fn submit(&mut self, b: SimBatch, _tx_bytes: usize) {
        self.pending.push(BatchRef {
            sequence: self.next_sequence,
            digest: b.digest,
            bytes: 0,
            transactions: b.transactions,
        });
        self.next_sequence += 1;
    }

    fn drain(&mut self, _now_ms: u64) -> Output<SfMsg> {
        Output {
            sends: std::mem::take(&mut self.out),
            ordered: std::mem::take(&mut self.blocks),
            ..Default::default()
        }
    }

    fn size(m: &SfMsg, tx_bytes: usize) -> usize {
        let vertex = |v: &Vertex, nv: &[VertexRef]| {
            48 + 42 * (v.strong.len() + nv.len())
                + v.batches
                    .iter()
                    .map(|b| 40 + b.transactions as usize * tx_bytes)
                    .sum::<usize>()
        };
        match m {
            SfMsg::Propose(v, nv) => vertex(v, nv),
            SfMsg::Signals(s) => 8 + 44 * s.len(),
            SfMsg::Timeout(_) => 12,
            SfMsg::Fetch(d) => 8 + 32 * d.len(),
            SfMsg::Vertices(vs) => vs.iter().map(|(v, nv)| vertex(v, nv)).sum(),
        }
    }

    fn cost_us(m: &SfMsg, tx_bytes: usize) -> u64 {
        match m {
            SfMsg::Propose(v, _) => {
                5 + v.strong.len() as u64 / 4
                    + v.batches
                        .iter()
                        .map(|b| b.transactions as u64 * tx_bytes as u64 / 1_000)
                        .sum::<u64>()
            }
            SfMsg::Signals(s) => 1 + s.len() as u64 / 2,
            SfMsg::Timeout(_) => 1,
            SfMsg::Fetch(d) => 2 + d.len() as u64,
            SfMsg::Vertices(vs) => 5 * vs.len() as u64,
        }
    }

    fn class(m: &SfMsg) -> &'static str {
        match m {
            SfMsg::Propose(v, _) if !v.batches.is_empty() => "payload",
            _ => "consensus",
        }
    }
}

// ---------------------------------------------------------------------------
// Uncertified DAG with signed blocks.
// ---------------------------------------------------------------------------

/// A signed block of the uncertified DAG.
#[derive(Debug, Clone)]
pub struct Block {
    /// Round.
    pub round: Round,
    /// Author.
    pub author: ValidatorIndex,
    /// Parents: round-1 blocks (a quorum of them).
    pub parents: Vec<Digest>,
    /// Batches.
    pub batches: Vec<BatchRef>,
    /// Digest (the signature binds it; its cost is modeled).
    pub digest: Digest,
}

/// Messages of the uncertified baseline.
#[derive(Debug, Clone)]
pub enum MyMsg {
    /// A block.
    Block(Box<Block>),
    /// Fetch blocks by digest.
    Fetch(Vec<Digest>),
}

/// An uncertified-DAG validator.
pub struct MysticetiNode {
    committee: Committee,
    me: ValidatorIndex,
    schedule: Schedule,
    blocks: HashMap<Digest, Block>,
    by_round: BTreeMap<Round, HashMap<ValidatorIndex, Digest>>,
    pending: HashMap<Digest, Block>,
    wanted: HashMap<Digest, u64>,
    round: Round,
    entered_ms: u64,
    leader_wait_ms: u64,
    leaders: usize,
    next_decide: Slot,
    decided: HashMap<Slot, bool>,
    ordered: HashSet<Digest>,
    height: u64,
    batches: Vec<BatchRef>,
    next_sequence: u64,
    out: Vec<(Target, MyMsg)>,
    blocks_out: Vec<(u64, Digest, Vec<Digest>)>,
}

/// A leader slot of the uncertified baseline: round and leader number.
type Slot = (Round, usize);

/// `n` uncertified-DAG baseline validators with `leaders` leader slots per
/// round. `leader_wait_ms` is how long a validator holding a quorum of a
/// round waits for that round's leaders.
pub fn mysticeti_nodes(n: usize, leader_wait_ms: u64, leaders: usize) -> Vec<MysticetiNode> {
    let (c, _) = super::tdc::committee(n, n as u64);
    (0..n)
        .map(|i| MysticetiNode {
            schedule: Schedule::new(&c, [6; 32], 1, crate::schedule::LOOKAHEAD_ROUNDS),
            committee: c.clone(),
            me: i as ValidatorIndex,
            blocks: HashMap::new(),
            by_round: BTreeMap::new(),
            pending: HashMap::new(),
            wanted: HashMap::new(),
            round: 0,
            entered_ms: 0,
            leader_wait_ms,
            leaders: leaders.clamp(1, n),
            next_decide: (1, 0),
            decided: HashMap::new(),
            ordered: HashSet::new(),
            height: 1,
            batches: Vec::new(),
            next_sequence: 0,
            out: Vec::new(),
            blocks_out: Vec::new(),
        })
        .collect()
}

fn block_digest(
    round: Round,
    author: ValidatorIndex,
    parents: &[Digest],
    batches: &[BatchRef],
) -> Digest {
    let mut h = blake3::Hasher::new();
    h.update(&round.to_be_bytes());
    h.update(&author.to_be_bytes());
    for p in parents {
        h.update(p);
    }
    for b in batches {
        h.update(&b.digest);
    }
    h.finalize().into()
}

impl MysticetiNode {
    fn insert(&mut self, b: Block) {
        if self.blocks.contains_key(&b.digest) {
            return;
        }
        self.pending.insert(b.digest, b);
        loop {
            let ready: Vec<Digest> = self
                .pending
                .values()
                .filter(|b| b.parents.iter().all(|p| self.blocks.contains_key(p)))
                .map(|b| b.digest)
                .collect();
            if ready.is_empty() {
                break;
            }
            for d in ready {
                let b = self.pending.remove(&d).expect("pending");
                self.wanted.remove(&d);
                let slot = self.by_round.entry(b.round).or_default();
                if slot.contains_key(&b.author) {
                    continue;
                }
                slot.insert(b.author, d);
                self.blocks.insert(d, b);
            }
        }
        let missing: Vec<Digest> = self
            .pending
            .values()
            .flat_map(|b| b.parents.iter().copied())
            .filter(|p| !self.blocks.contains_key(p) && !self.pending.contains_key(p))
            .collect();
        for d in missing {
            self.wanted.entry(d).or_insert(0);
        }
    }

    fn weight(&self, r: Round) -> u64 {
        self.by_round
            .get(&r)
            .map_or(0, |m| m.keys().map(|a| self.committee.seats(*a)).sum())
    }

    /// The author of leader slot `k` of round `r`: the scheduled leader, and
    /// for further slots the members spread evenly after it.
    fn slot_author(&self, r: Round, k: usize) -> ValidatorIndex {
        let n = self.committee.size();
        ((self.schedule.leader(r, 0) as usize + k * n / self.leaders) % n) as ValidatorIndex
    }

    fn leader_block(&self, (r, k): Slot) -> Option<Digest> {
        self.by_round
            .get(&r)
            .and_then(|m| m.get(&self.slot_author(r, k)))
            .copied()
    }

    fn votes(&self, r: Round, leader: &Digest) -> HashSet<Digest> {
        self.by_round
            .get(&(r + 1))
            .map(|m| {
                m.values()
                    .filter(|d| self.blocks[*d].parents.contains(leader))
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn certifies(&self, c: &Block, votes: &HashSet<Digest>) -> bool {
        let w: u64 = c
            .parents
            .iter()
            .filter(|p| votes.contains(*p))
            .map(|p| self.committee.seats(self.blocks[p].author))
            .sum();
        w >= self.committee.quorum()
    }

    /// Commit (Some(true)), skip (Some(false)) or undecided (None) by the
    /// direct rule.
    fn direct(&self, (r, k): Slot) -> Option<bool> {
        let Some(l) = self.leader_block((r, k)) else {
            let blame = self.weight(r + 1);
            return (blame >= self.committee.quorum()).then_some(false);
        };
        let votes = self.votes(r, &l);
        let non_votes: u64 = self.by_round.get(&(r + 1)).map_or(0, |m| {
            m.iter()
                .filter(|(_, d)| !votes.contains(*d))
                .map(|(a, _)| self.committee.seats(*a))
                .sum()
        });
        if non_votes >= self.committee.quorum() {
            return Some(false);
        }
        let certs: u64 = self.by_round.get(&(r + 2)).map_or(0, |m| {
            m.iter()
                .filter(|(_, d)| self.certifies(&self.blocks[*d], &votes))
                .map(|(a, _)| self.committee.seats(*a))
                .sum()
        });
        (certs >= self.committee.quorum()).then_some(true)
    }

    fn history(&self, root: &Digest) -> Vec<Digest> {
        let mut seen = HashSet::new();
        let mut stack = vec![*root];
        let mut out = Vec::new();
        while let Some(d) = stack.pop() {
            if self.ordered.contains(&d) || !seen.insert(d) {
                continue;
            }
            if let Some(b) = self.blocks.get(&d) {
                out.push((b.round, b.author, d));
                stack.extend(b.parents.iter().copied());
            }
        }
        out.sort();
        out.into_iter().map(|x| x.2).collect()
    }

    /// Indirect decision of slot `s`: the first later slot at least a wave
    /// ahead that is decided as committed (directly or indirectly, from
    /// `later`) is its anchor, and `s` commits iff the anchor's history holds
    /// a certificate for `s`'s leader. Skipped slots in between are passed
    /// over; an undecided one leaves `s` undecided.
    fn indirect(&self, (r, k): Slot, later: &BTreeMap<Slot, Option<bool>>) -> Option<bool> {
        for (a, d) in later.range((r + 3, 0)..) {
            match d {
                Some(true) => {
                    let anchor = self.leader_block(*a).expect("committed leader exists");
                    let hist: HashSet<Digest> = self.history_all(&anchor);
                    return Some(match self.leader_block((r, k)) {
                        Some(l) => {
                            let votes = self.votes(r, &l);
                            self.by_round.get(&(r + 2)).is_some_and(|m| {
                                m.values().any(|d| {
                                    hist.contains(d) && self.certifies(&self.blocks[d], &votes)
                                })
                            })
                        }
                        None => false,
                    });
                }
                Some(false) => continue,
                None => return None,
            }
        }
        None
    }

    fn decide(&mut self) {
        let top = self.by_round.keys().next_back().copied().unwrap_or(0);
        let hi = top.saturating_sub(2);
        if hi < self.next_decide.0 {
            return;
        }
        // Slots are decided from the highest down, so an undecided slot's
        // anchor may itself be decided indirectly.
        let mut decisions: BTreeMap<Slot, Option<bool>> = BTreeMap::new();
        for r in (self.next_decide.0..=hi).rev() {
            for k in (0..self.leaders).rev() {
                let s = (r, k);
                if s < self.next_decide {
                    continue;
                }
                let d = self
                    .decided
                    .get(&s)
                    .copied()
                    .or_else(|| self.direct(s))
                    .or_else(|| self.indirect(s, &decisions));
                decisions.insert(s, d);
            }
        }
        // The decided prefix commits in order.
        for (s, d) in decisions {
            let Some(commit) = d else { return };
            self.decided.insert(s, commit);
            self.next_decide = if s.1 + 1 == self.leaders {
                (s.0 + 1, 0)
            } else {
                (s.0, s.1 + 1)
            };
            if commit {
                let l = self.leader_block(s).expect("committed leader exists");
                let hist = self.history(&l);
                let mut batches = Vec::new();
                for d in &hist {
                    self.ordered.insert(*d);
                    batches.extend(self.blocks[d].batches.iter().map(|b| b.digest));
                }
                self.blocks_out.push((self.height, l, batches));
                self.height += 1;
            }
        }
    }

    fn history_all(&self, root: &Digest) -> HashSet<Digest> {
        let mut seen = HashSet::new();
        let mut stack = vec![*root];
        while let Some(d) = stack.pop() {
            if !seen.insert(d) {
                continue;
            }
            if let Some(b) = self.blocks.get(&d)
                && b.round + 8 > self.next_decide.0
            {
                stack.extend(b.parents.iter().copied());
            }
        }
        seen
    }

    fn advance(&mut self, now_ms: u64) {
        loop {
            let r = self.round;
            if self.weight(r) < self.committee.quorum() {
                return;
            }
            let have_leader = (0..self.leaders).all(|k| self.leader_block((r, k)).is_some());
            if !have_leader && now_ms.saturating_sub(self.entered_ms) < self.leader_wait_ms {
                return;
            }
            let parents: Vec<Digest> = {
                let mut v: Vec<(ValidatorIndex, Digest)> =
                    self.by_round[&r].iter().map(|(a, d)| (*a, *d)).collect();
                v.sort();
                v.into_iter().map(|x| x.1).collect()
            };
            let batches = std::mem::take(&mut self.batches);
            let round = r + 1;
            let digest = block_digest(round, self.me, &parents, &batches);
            let b = Block {
                round,
                author: self.me,
                parents,
                batches,
                digest,
            };
            self.round = round;
            self.entered_ms = now_ms;
            self.out
                .push((Target::All, MyMsg::Block(Box::new(b.clone()))));
            self.insert(b);
        }
    }
}

impl SimNode for MysticetiNode {
    type Msg = MyMsg;

    fn start(&mut self, now_ms: u64) {
        let digest = block_digest(0, self.me, &[], &[]);
        let b = Block {
            round: 0,
            author: self.me,
            parents: Vec::new(),
            batches: Vec::new(),
            digest,
        };
        self.entered_ms = now_ms;
        self.out
            .push((Target::All, MyMsg::Block(Box::new(b.clone()))));
        self.insert(b);
    }

    fn deliver(&mut self, from: u16, msgs: Vec<MyMsg>, now_ms: u64) {
        for m in msgs {
            match m {
                MyMsg::Block(b) => {
                    let ok = b.parents.is_empty() == (b.round == 0)
                        && block_digest(b.round, b.author, &b.parents, &b.batches) == b.digest;
                    if ok {
                        self.insert(*b);
                    }
                }
                MyMsg::Fetch(ds) => {
                    for d in ds {
                        if let Some(b) = self.blocks.get(&d) {
                            self.out
                                .push((Target::One(from), MyMsg::Block(Box::new(b.clone()))));
                        }
                    }
                }
            }
        }
        self.decide();
        self.advance(now_ms);
    }

    fn tick(&mut self, now_ms: u64) {
        let n = self.committee.size() as u64;
        let mut ask: HashMap<u16, Vec<Digest>> = HashMap::new();
        for (d, last) in self.wanted.iter_mut() {
            if *last == 0 || now_ms.saturating_sub(*last) >= 250 {
                *last = now_ms.max(1);
                let p = (u64::from(d[0]) + now_ms / 250) % n;
                let p = if p as u16 == self.me { (p + 1) % n } else { p } as u16;
                ask.entry(p).or_default().push(*d);
            }
        }
        for (p, ds) in ask {
            self.out.push((Target::One(p), MyMsg::Fetch(ds)));
        }
        self.decide();
        self.advance(now_ms);
        if let Some(floor) = self.next_decide.0.checked_sub(60) {
            let old: Vec<Round> = self.by_round.range(..floor).map(|(r, _)| *r).collect();
            for r in old {
                if let Some(m) = self.by_round.remove(&r) {
                    for d in m.values() {
                        self.blocks.remove(d);
                        self.ordered.remove(d);
                    }
                }
            }
            self.decided.retain(|s, _| s.0 >= floor);
        }
    }

    fn submit(&mut self, b: SimBatch, _tx_bytes: usize) {
        self.batches.push(BatchRef {
            sequence: self.next_sequence,
            digest: b.digest,
            bytes: 0,
            transactions: b.transactions,
        });
        self.next_sequence += 1;
    }

    fn drain(&mut self, _now_ms: u64) -> Output<MyMsg> {
        Output {
            sends: std::mem::take(&mut self.out),
            ordered: std::mem::take(&mut self.blocks_out),
            ..Default::default()
        }
    }

    fn size(m: &MyMsg, tx_bytes: usize) -> usize {
        match m {
            MyMsg::Block(b) => {
                48 + 64
                    + 32 * b.parents.len()
                    + b.batches
                        .iter()
                        .map(|x| 40 + x.transactions as usize * tx_bytes)
                        .sum::<usize>()
            }
            MyMsg::Fetch(d) => 8 + 32 * d.len(),
        }
    }

    fn cost_us(m: &MyMsg, tx_bytes: usize) -> u64 {
        match m {
            // Ed25519 verification of the block signature plus hashing.
            MyMsg::Block(b) => {
                50 + b.parents.len() as u64 / 4
                    + b.batches
                        .iter()
                        .map(|x| x.transactions as u64 * tx_bytes as u64 / 1_000)
                        .sum::<u64>()
            }
            MyMsg::Fetch(d) => 2 + d.len() as u64,
        }
    }

    fn class(m: &MyMsg) -> &'static str {
        match m {
            MyMsg::Block(b) if !b.batches.is_empty() => "payload",
            _ => "consensus",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::driver::{Scenario, run};
    use super::*;

    #[test]
    fn both_baselines_order_on_a_wan() {
        let sc = Scenario::wan(10, 2_000.0, 15_000);
        let a = run(&sc, sailfish_nodes(10, 1_000));
        assert_eq!(a.safety_violations, 0);
        assert!(a.ordered.count > 1_000.0, "{a:?}");
        let b = run(&sc, mysticeti_nodes(10, 100, 1));
        assert_eq!(b.safety_violations, 0);
        assert!(b.ordered.count > 1_000.0, "{b:?}");
    }
}
