//! Signature-free reliable broadcast of vertices.
//!
//! Every vertex reaches the other validators through one reliable-broadcast
//! instance, keyed by (round, author). The instance guarantees that honest
//! validators deliver the same digest or none, and that if one honest
//! validator delivers, all do. No message is signed: each travels over an
//! authenticated channel, so its sender is known, and only the author may
//! propose in its own instance.
//!
//! Messages and thresholds (weights in seats; `t` is the most seats faulty
//! validators can hold, see [`crate::committee::BroadcastThresholds`]):
//!
//! | on | condition | action |
//! |---|---|---|
//! | PROPOSE from the author | first one | send ECHO(d) |
//! | ECHO(d) | non-author weight >= ceil(n/2) | send VOTE(d) once |
//! | ECHO(d) or VOTE(d) | non-author weight >= ceil((n+t-1)/2) | send ACK(d) once |
//! | ACK(d) | non-author weight >= ceil((n+t-1)/2) | send READY(d) once |
//! | READY(d) | weight >= t+1 | send READY(d) once |
//! | ECHO(d) | non-author weight >= ceil((n+2t-2)/2) | deliver d (two steps) |
//! | READY(d) | weight >= 2t+1 | deliver d |
//!
//! Each sender is counted once per message kind in an instance, whatever
//! digest it names, so a validator cannot be counted for two digests.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::committee::{BroadcastThresholds, Committee, FaultBound, SeatSet, ValidatorIndex};
use crate::vertex::{Digest, Round};

/// The first bytes of a digest, enough to tell instances apart in a log.
fn short(d: &Digest) -> String {
    d[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// The digest-only messages of an instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignalKind {
    /// Echo of the author's proposal.
    Echo = 0,
    /// Vote after a majority of echoes.
    Vote = 1,
    /// Acknowledgement after enough echoes or votes.
    Ack = 2,
    /// Ready to deliver.
    Ready = 3,
}

/// One digest-only message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Signal {
    /// Message kind.
    pub kind: SignalKind,
    /// Instance round.
    pub round: Round,
    /// Instance author.
    pub source: ValidatorIndex,
    /// The digest the message is about.
    pub digest: Digest,
}

/// What an instance asks its caller to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RbcAction {
    /// Send this signal to every committee member.
    Broadcast(Signal),
    /// The instance delivered this digest.
    Deliver {
        /// Instance round.
        round: Round,
        /// Instance author.
        source: ValidatorIndex,
        /// Delivered digest.
        digest: Digest,
    },
}

#[derive(Default)]
struct Tally {
    by_kind: [SeatSet; 4],
    non_author: [u64; 4],
}

#[derive(Default)]
struct Instance {
    proposed: Option<Digest>,
    counted: [SeatSet; 4],
    tallies: Vec<(Digest, Tally)>,
    // The digest this validator sent each kind of signal for.
    sent: [Option<Digest>; 4],
    delivered: Option<Digest>,
}

impl Instance {
    fn tally(&mut self, digest: Digest) -> &mut Tally {
        if let Some(pos) = self.tallies.iter().position(|(d, _)| *d == digest) {
            return &mut self.tallies[pos].1;
        }
        self.tallies.push((digest, Tally::default()));
        &mut self.tallies.last_mut().expect("just pushed").1
    }
}

/// All reliable-broadcast instances of one epoch at one validator.
pub struct ReliableBroadcast {
    me: ValidatorIndex,
    instances: HashMap<(Round, ValidatorIndex), Instance>,
    floor: Round,
    stats: RbcStats,
    bound: FaultBound,
    // The thresholds of the committee last seen, by its epoch.
    thresholds: Option<(u64, BroadcastThresholds)>,
}

/// How this validator's instances delivered, since it started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RbcStats {
    /// Delivered in two steps, on enough ECHOs (or on the author's own
    /// proposal in a one-member committee).
    pub fast: u64,
    /// Delivered on READYs, the slower path.
    pub slow: u64,
}

impl ReliableBroadcast {
    /// Delivery counts by path.
    pub fn stats(&self) -> RbcStats {
        self.stats
    }

    pub(crate) fn instances_len(&self) -> usize {
        self.instances.len()
    }

    /// Instances for validator `me`, with thresholds from `bound`.
    pub fn new(me: ValidatorIndex, bound: FaultBound) -> Self {
        Self {
            me,
            bound,
            instances: HashMap::new(),
            floor: 0,
            stats: RbcStats::default(),
            thresholds: None,
        }
    }

    /// The fault bound the thresholds are computed from.
    pub fn bound(&self) -> FaultBound {
        self.bound
    }

    /// The thresholds of `committee`, computed once per epoch.
    fn thresholds(&mut self, committee: &Committee) -> BroadcastThresholds {
        match self.thresholds {
            Some((epoch, t)) if epoch == committee.epoch => t,
            _ => {
                let t = BroadcastThresholds::of(committee, self.bound);
                self.thresholds = Some((committee.epoch, t));
                t
            }
        }
    }

    /// Records the author's proposal of `digest` for (`round`, `source`),
    /// received from `from`. Only the author's first proposal counts; the
    /// caller has already checked the vertex's structure.
    pub fn on_propose(
        &mut self,
        committee: &Committee,
        from: ValidatorIndex,
        round: Round,
        source: ValidatorIndex,
        digest: Digest,
    ) -> Vec<RbcAction> {
        if from != source || round < self.floor {
            return Vec::new();
        }
        let inst = self.instances.entry((round, source)).or_default();
        if inst.proposed.is_some() {
            return Vec::new();
        }
        inst.proposed = Some(digest);
        if committee.size() == 1 {
            // The author is the whole committee: there is nobody to agree
            // with, and its own proposal is what it delivers.
            inst.delivered = Some(digest);
            self.stats.fast += 1;
            return vec![RbcAction::Deliver {
                round,
                source,
                digest,
            }];
        }
        let mut out = Vec::new();
        let echo = Signal {
            kind: SignalKind::Echo,
            round,
            source,
            digest,
        };
        out.push(RbcAction::Broadcast(echo));
        inst.sent[SignalKind::Echo as usize] = Some(digest);
        tracing::debug!(
            me = self.me,
            round,
            source,
            digest = %short(&digest),
            "rbc: proposal taken, echo sent"
        );
        out.extend(self.on_signal(committee, self.me, echo));
        out
    }

    /// The author's first proposal digest for (`round`, `source`), if seen.
    pub fn proposed(&self, round: Round, source: ValidatorIndex) -> Option<Digest> {
        self.instances
            .get(&(round, source))
            .and_then(|i| i.proposed)
    }

    /// The delivered digest for (`round`, `source`), if delivered.
    pub fn delivered(&self, round: Round, source: ValidatorIndex) -> Option<Digest> {
        self.instances
            .get(&(round, source))
            .and_then(|i| i.delivered)
    }

    /// Records `signal` from `from` and returns what follows from it.
    pub fn on_signal(
        &mut self,
        committee: &Committee,
        from: ValidatorIndex,
        signal: Signal,
    ) -> Vec<RbcAction> {
        let Signal {
            kind,
            round,
            source,
            digest,
        } = signal;
        if round < self.floor
            || committee.member(source).is_none()
            || committee.member(from).is_none()
        {
            return Vec::new();
        }
        let need = self.thresholds(committee);
        let inst = self.instances.entry((round, source)).or_default();
        let k = kind as usize;
        if !inst.counted[k].insert(from, committee.seats(from)) {
            tracing::trace!(
                me = self.me,
                from,
                ?kind,
                round,
                source,
                "rbc: signal already counted"
            );
            return Vec::new();
        }
        let non_author = committee.non_broadcaster_weight(from, source);
        {
            let t = inst.tally(digest);
            t.by_kind[k].insert(from, committee.seats(from));
            t.non_author[k] += non_author;
        }
        let mut out = Vec::new();
        let t = inst
            .tallies
            .iter()
            .find(|(d, _)| *d == digest)
            .map(|(_, t)| {
                (
                    t.non_author,
                    [
                        t.by_kind[0].weight(),
                        t.by_kind[1].weight(),
                        t.by_kind[2].weight(),
                        t.by_kind[3].weight(),
                    ],
                )
            })
            .expect("tally exists");
        let (na, full) = t;
        let echo = na[SignalKind::Echo as usize];
        let vote = na[SignalKind::Vote as usize];
        let ack = na[SignalKind::Ack as usize];
        let ready = full[SignalKind::Ready as usize];
        tracing::debug!(
            me = self.me,
            from,
            ?kind,
            round,
            source,
            digest = %short(&digest),
            echo,
            vote,
            ack,
            ready,
            delivered = inst.delivered.is_some(),
            "rbc: signal counted"
        );

        let me = self.me;
        let send = |inst: &mut Instance, kind: SignalKind, out: &mut Vec<RbcAction>| {
            if inst.sent[kind as usize].is_none() {
                inst.sent[kind as usize] = Some(digest);
                tracing::debug!(me, ?kind, round, source, "rbc: signal sent");
                out.push(RbcAction::Broadcast(Signal {
                    kind,
                    round,
                    source,
                    digest,
                }));
                true
            } else {
                false
            }
        };
        let mut loopback = Vec::new();
        if echo >= need.vote && send(inst, SignalKind::Vote, &mut out) {
            loopback.push(SignalKind::Vote);
        }
        if (echo >= need.ack || vote >= need.ack) && send(inst, SignalKind::Ack, &mut out) {
            loopback.push(SignalKind::Ack);
        }
        if (ack >= need.ack || ready >= need.ready) && send(inst, SignalKind::Ready, &mut out) {
            loopback.push(SignalKind::Ready);
        }
        if inst.delivered.is_none() && (echo >= need.fast || ready >= need.deliver) {
            inst.delivered = Some(digest);
            let fast = echo >= need.fast;
            if fast {
                self.stats.fast += 1;
            } else {
                self.stats.slow += 1;
            }
            tracing::debug!(
                me,
                round,
                source,
                digest = %short(&digest),
                fast,
                echo,
                ready,
                "rbc: delivered"
            );
            out.push(RbcAction::Deliver {
                round,
                source,
                digest,
            });
        }
        for kind in loopback {
            out.extend(self.on_signal(
                committee,
                me,
                Signal {
                    kind,
                    round,
                    source,
                    digest,
                },
            ));
        }
        out
    }

    /// Restores, after a restart, that this validator sent `signal`: it is
    /// counted, and this validator never sends that kind again in the
    /// instance, for any digest.
    pub fn restore_sent(&mut self, committee: &Committee, signal: Signal) {
        let Signal {
            kind,
            round,
            source,
            digest,
        } = signal;
        if round < self.floor || committee.member(source).is_none() {
            return;
        }
        let me = self.me;
        let inst = self.instances.entry((round, source)).or_default();
        inst.sent[kind as usize] = Some(digest);
        if kind == SignalKind::Echo && inst.proposed.is_none() {
            inst.proposed = Some(digest);
        }
        if inst.counted[kind as usize].insert(me, committee.seats(me)) {
            let non_author = committee.non_broadcaster_weight(me, source);
            let t = inst.tally(digest);
            t.by_kind[kind as usize].insert(me, committee.seats(me));
            t.non_author[kind as usize] += non_author;
        }
    }

    /// Every signal this validator has sent in instances of `from_round` and
    /// later, in round order: what a peer that missed them needs to count
    /// this validator's part in those instances.
    pub fn sent_signals(&self, from_round: Round) -> Vec<Signal> {
        let mut out: Vec<Signal> = self
            .instances
            .iter()
            .filter(|((r, _), _)| *r >= from_round)
            .flat_map(|(&(round, source), inst)| {
                [
                    SignalKind::Echo,
                    SignalKind::Vote,
                    SignalKind::Ack,
                    SignalKind::Ready,
                ]
                .into_iter()
                .filter_map(move |kind| {
                    inst.sent[kind as usize].map(|digest| Signal {
                        kind,
                        round,
                        source,
                        digest,
                    })
                })
            })
            .collect();
        out.sort_by_key(|s| (s.round, s.source, s.kind as u8));
        out
    }

    /// For each author, the lowest round at or above the floor in which an
    /// instance this validator has heard of has not delivered.
    pub fn undelivered_from(&self) -> HashMap<ValidatorIndex, Round> {
        let mut out: HashMap<ValidatorIndex, Round> = HashMap::new();
        for (&(round, source), inst) in &self.instances {
            if round >= self.floor && inst.delivered.is_none() {
                out.entry(source)
                    .and_modify(|r| *r = (*r).min(round))
                    .or_insert(round);
            }
        }
        out
    }

    /// Restores, after a restart, that the instance delivered `digest`.
    pub fn restore_delivered(&mut self, round: Round, source: ValidatorIndex, digest: Digest) {
        if round < self.floor {
            return;
        }
        let inst = self.instances.entry((round, source)).or_default();
        inst.delivered.get_or_insert(digest);
    }

    /// Drops every instance below `round`.
    pub fn prune_below(&mut self, round: Round) {
        if round <= self.floor {
            return;
        }
        self.floor = round;
        self.instances.retain(|(r, _), _| *r >= round);
    }

    /// Number of live instances.
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    /// Whether no instance is live.
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::test_support::committee;
    use std::collections::VecDeque;

    /// Runs one instance among `n` parties where `byzantine` parties stay
    /// silent and the author proposes `digests[i]` to party i. Returns each
    /// honest party's delivered digest.
    fn run(
        n: usize,
        silent: &[ValidatorIndex],
        proposals: &[Option<Digest>],
    ) -> Vec<Option<Digest>> {
        let (c, _) = committee(n);
        run_in(&c, FaultBound::Seats, silent, proposals).0
    }

    /// The same in the committee `c` under `bound`, with each party's
    /// delivery counts.
    fn run_in(
        c: &Committee,
        bound: FaultBound,
        silent: &[ValidatorIndex],
        proposals: &[Option<Digest>],
    ) -> (Vec<Option<Digest>>, Vec<RbcStats>) {
        let n = c.size();
        let author = 0u16;
        let mut parties: Vec<ReliableBroadcast> = (0..n as u16)
            .map(|me| ReliableBroadcast::new(me, bound))
            .collect();
        let mut queue: VecDeque<(ValidatorIndex, ValidatorIndex, Signal)> = VecDeque::new();
        let mut delivered = vec![None; n];
        let apply =
            |i: usize, acts: Vec<RbcAction>, q: &mut VecDeque<_>, d: &mut Vec<Option<Digest>>| {
                for a in acts {
                    match a {
                        RbcAction::Broadcast(s) => {
                            for to in 0..n as u16 {
                                if to as usize != i {
                                    q.push_back((i as u16, to, s));
                                }
                            }
                        }
                        RbcAction::Deliver { digest, .. } => d[i] = Some(digest),
                    }
                }
            };
        for i in 0..n {
            if silent.contains(&(i as u16)) {
                continue;
            }
            if let Some(d) = proposals[i] {
                let acts = parties[i].on_propose(c, author, 1, author, d);
                apply(i, acts, &mut queue, &mut delivered);
            }
        }
        while let Some((from, to, s)) = queue.pop_front() {
            if silent.contains(&to) {
                continue;
            }
            let acts = parties[to as usize].on_signal(c, from, s);
            apply(to as usize, acts, &mut queue, &mut delivered);
        }
        let out = (0..n)
            .map(|i| {
                if silent.contains(&(i as u16)) {
                    None
                } else {
                    delivered[i]
                }
            })
            .collect();
        (out, parties.iter().map(|p| p.stats()).collect())
    }

    #[test]
    fn four_equal_weighted_validators_deliver_in_two_steps_with_one_silent() {
        let c = crate::committee::test_support::seated(&[200, 200, 200, 200]);
        let d = [7u8; 32];
        let (out, stats) = run_in(&c, FaultBound::WholeMembers, &[3], &[Some(d); 4]);
        assert_eq!(out, [Some(d), Some(d), Some(d), None]);
        for (i, s) in stats.iter().enumerate().take(3) {
            assert_eq!((s.fast, s.slow), (1, 0), "party {i}");
        }
    }

    #[test]
    fn under_the_seat_bound_one_silent_validator_of_four_sends_delivery_the_slower_way() {
        let c = crate::committee::test_support::seated(&[200, 200, 200, 200]);
        let d = [7u8; 32];
        let (out, stats) = run_in(&c, FaultBound::Seats, &[3], &[Some(d); 4]);
        assert_eq!(out, [Some(d), Some(d), Some(d), None]);
        for (i, s) in stats.iter().enumerate().take(3) {
            assert_eq!((s.fast, s.slow), (0, 1), "party {i}");
        }
    }

    #[test]
    fn a_weighted_equivocating_author_cannot_make_two_digests_deliver() {
        // The author holds 200 of 800 seats and tells two parties one digest
        // and the third another, in every split.
        let c = crate::committee::test_support::seated(&[200, 200, 200, 200]);
        let (a, b) = ([1u8; 32], [2u8; 32]);
        for other in 1..4usize {
            let mut proposals = [Some(a); 4];
            proposals[0] = None;
            proposals[other] = Some(b);
            for bound in [FaultBound::Seats, FaultBound::WholeMembers] {
                let (out, _) = run_in(&c, bound, &[0], &proposals);
                let delivered: Vec<Digest> = out.into_iter().flatten().collect();
                assert!(
                    delivered.windows(2).all(|w| w[0] == w[1]),
                    "split at {other} under {bound:?}: {delivered:?}"
                );
            }
        }
    }

    /// Runs one instance in `c` under `bound` where every party in `faulty`
    /// (the author, party 0, among them) sends every signal for two digests
    /// to every honest party, before or after the honest parties' own
    /// messages, and the author proposes the second digest to the honest
    /// parties in `split` and the first to the rest. Returns what each party
    /// delivered.
    fn equivocation(
        c: &Committee,
        bound: FaultBound,
        faulty: &[ValidatorIndex],
        split: &[ValidatorIndex],
        forged_first: bool,
        order: [Digest; 2],
    ) -> Vec<Vec<Digest>> {
        type Queue = VecDeque<(ValidatorIndex, ValidatorIndex, Signal)>;
        let n = c.size() as u16;
        let honest: Vec<ValidatorIndex> = (0..n).filter(|i| !faulty.contains(i)).collect();
        let mut parties: Vec<ReliableBroadcast> =
            (0..n).map(|me| ReliableBroadcast::new(me, bound)).collect();
        let mut delivered = vec![Vec::new(); n as usize];
        let take = |i: ValidatorIndex,
                    acts: Vec<RbcAction>,
                    queue: &mut Queue,
                    delivered: &mut [Vec<Digest>]| {
            for act in acts {
                match act {
                    RbcAction::Broadcast(s) => {
                        for to in honest.iter().filter(|to| **to != i) {
                            queue.push_back((i, *to, s));
                        }
                    }
                    RbcAction::Deliver { digest, .. } => delivered[i as usize].push(digest),
                }
            }
        };
        let mut own = Queue::new();
        for i in &honest {
            let digest = if split.contains(i) {
                order[1]
            } else {
                order[0]
            };
            let acts = parties[*i as usize].on_propose(c, 0, 1, 0, digest);
            take(*i, acts, &mut own, &mut delivered);
        }
        let mut forged = Queue::new();
        for from in faulty {
            for digest in order {
                for kind in [
                    SignalKind::Echo,
                    SignalKind::Vote,
                    SignalKind::Ack,
                    SignalKind::Ready,
                ] {
                    for to in &honest {
                        let signal = Signal {
                            kind,
                            round: 1,
                            source: 0,
                            digest,
                        };
                        forged.push_back((*from, *to, signal));
                    }
                }
            }
        }
        let mut queue = if forged_first {
            forged.append(&mut own);
            forged
        } else {
            own.append(&mut forged);
            own
        };
        while let Some((from, to, s)) = queue.pop_front() {
            let acts = parties[to as usize].on_signal(c, from, s);
            take(to, acts, &mut queue, &mut delivered);
        }
        delivered
    }

    /// No honest party of `c` delivers a digest another delivers not, under
    /// either bound, for every split of the honest parties and every order.
    fn assert_no_split(c: &Committee, faulty: &[ValidatorIndex]) {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let honest: Vec<ValidatorIndex> = (0..c.size() as u16)
            .filter(|i| !faulty.contains(i))
            .collect();
        for bound in [FaultBound::Seats, FaultBound::WholeMembers] {
            for mask in 0..1u32 << honest.len() {
                let split: Vec<ValidatorIndex> = honest
                    .iter()
                    .enumerate()
                    .filter(|(k, _)| mask >> k & 1 == 1)
                    .map(|(_, i)| *i)
                    .collect();
                for forged_first in [true, false] {
                    for order in [[a, b], [b, a]] {
                        let delivered = equivocation(c, bound, faulty, &split, forged_first, order);
                        let all: Vec<Digest> = delivered.iter().flatten().copied().collect();
                        assert!(
                            all.windows(2).all(|w| w[0] == w[1]),
                            "{bound:?}, faulty {faulty:?}, split {split:?}, forged first \
                             {forged_first}: {delivered:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn an_author_that_signals_both_digests_cannot_split_weighted_validators() {
        // The author holds 200 of 800 seats.
        assert_no_split(&crate::committee::test_support::seated(&[200; 4]), &[0]);
    }

    #[test]
    fn faulty_whole_members_holding_the_bound_cannot_split_uneven_committees() {
        // The author alone holds the bound t; then two members together hold
        // it, 100 and 100 seats (t = 200) or 150 and 100 (t = 250), and both
        // signal both digests.
        for (seats, faulty) in [
            (&[200, 400, 100, 100][..], &[0u16][..]),
            (&[100, 400, 200, 100], &[0, 3]),
            (&[250, 300, 150, 100], &[0]),
            (&[150, 300, 250, 100], &[0, 3]),
        ] {
            let c = crate::committee::test_support::seated(seats);
            let held: u64 = faulty.iter().map(|i| seats[*i as usize]).sum();
            assert_eq!(
                held,
                crate::committee::largest_faulty_weight(&c),
                "{seats:?}"
            );
            assert_no_split(&c, faulty);
        }
    }

    #[test]
    fn uneven_committees_deliver_with_members_holding_the_bound_silent() {
        let d = [7u8; 32];
        for (seats, silent) in [
            (&[400, 200, 100, 100][..], &[1u16][..]),
            (&[400, 200, 100, 100], &[2, 3]),
            (&[300, 250, 150, 100], &[1]),
            (&[300, 250, 150, 100], &[2, 3]),
        ] {
            let c = crate::committee::test_support::seated(seats);
            for bound in [FaultBound::Seats, FaultBound::WholeMembers] {
                let (out, _) = run_in(&c, bound, silent, &[Some(d); 4]);
                for (i, got) in out.iter().enumerate() {
                    let want = (!silent.contains(&(i as u16))).then_some(d);
                    assert_eq!(
                        *got, want,
                        "{seats:?}, silent {silent:?}, {bound:?}, party {i}"
                    );
                }
            }
        }
    }

    #[test]
    fn deliveries_are_counted_by_the_path_that_made_them() {
        let (c, _) = committee(4);
        let d = [5u8; 32];
        let signal = |kind| Signal {
            kind,
            round: 1,
            source: 0,
            digest: d,
        };
        // Enough non-author ECHOs: the two-step path.
        let mut fast = ReliableBroadcast::new(1, FaultBound::Seats);
        for from in [2, 3] {
            fast.on_signal(&c, from, signal(SignalKind::Echo));
        }
        assert_eq!(fast.delivered(1, 0), Some(d));
        assert_eq!(fast.stats(), RbcStats { fast: 1, slow: 0 });
        // No ECHOs at all, a quorum of READYs: the slow path.
        let mut slow = ReliableBroadcast::new(1, FaultBound::Seats);
        for from in [0, 2, 3] {
            slow.on_signal(&c, from, signal(SignalKind::Ready));
        }
        assert_eq!(slow.delivered(1, 0), Some(d));
        assert_eq!(slow.stats(), RbcStats { fast: 0, slow: 1 });
    }

    #[test]
    fn every_party_delivers_an_honest_proposal_even_with_f_silent() {
        let d = [7u8; 32];
        let out = run(4, &[3], &[Some(d); 4]);
        assert_eq!(&out[..3], &[Some(d), Some(d), Some(d)]);
        let out = run(10, &[7, 8, 9], &[Some(d); 10]);
        assert!(out[..7].iter().all(|x| *x == Some(d)));
    }

    #[test]
    fn an_equivocating_author_cannot_make_two_digests_deliver() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        for split in 1..9 {
            let proposals: Vec<Option<Digest>> = (0..10)
                .map(|i| Some(if i < split { a } else { b }))
                .collect();
            let out = run(10, &[], &proposals);
            let got: std::collections::HashSet<_> = out.iter().flatten().collect();
            assert!(got.len() <= 1, "split {split}: {out:?}");
            if !got.is_empty() {
                assert!(
                    out.iter().all(|x| x.is_some()),
                    "split {split}: totality {out:?}"
                );
            }
        }
    }

    #[test]
    fn a_proposal_not_from_its_author_is_ignored() {
        let (c, _) = committee(4);
        let mut p = ReliableBroadcast::new(1, FaultBound::Seats);
        assert!(p.on_propose(&c, 2, 1, 0, [1; 32]).is_empty());
        assert!(p.proposed(1, 0).is_none());
    }

    #[test]
    fn a_sender_counts_once_per_kind_whatever_digest_it_names() {
        let (c, _) = committee(4);
        let mut p = ReliableBroadcast::new(1, FaultBound::Seats);
        let echo = |d| Signal {
            kind: SignalKind::Echo,
            round: 1,
            source: 0,
            digest: d,
        };
        p.on_signal(&c, 2, echo([1; 32]));
        assert!(p.on_signal(&c, 2, echo([2; 32])).is_empty());
    }
}
