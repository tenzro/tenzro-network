//! Signature-free reliable broadcast of vertices.
//!
//! Every vertex reaches the other validators through one reliable-broadcast
//! instance, keyed by (round, author). The instance guarantees that honest
//! validators deliver the same digest or none, and that if one honest
//! validator delivers, all do. No message is signed: each travels over an
//! authenticated channel, so its sender is known, and only the author may
//! propose in its own instance.
//!
//! Messages and thresholds (weights in seats, see [`crate::committee`]):
//!
//! | on | condition | action |
//! |---|---|---|
//! | PROPOSE from the author | first one | send ECHO(d) |
//! | ECHO(d) | non-author weight >= ceil(n/2) | send VOTE(d) once |
//! | ECHO(d) or VOTE(d) | non-author weight >= ceil((n+f-1)/2) | send ACK(d) once |
//! | ACK(d) | non-author weight >= ceil((n+f-1)/2) | send READY(d) once |
//! | READY(d) | weight >= f+1 | send READY(d) once |
//! | ECHO(d) | non-author weight >= ceil((n+2f-2)/2) | deliver d (two steps) |
//! | READY(d) | weight >= 2f+1 | deliver d |
//!
//! Each sender is counted once per message kind in an instance, whatever
//! digest it names, so a validator cannot be counted for two digests.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::committee::{Committee, SeatSet, ValidatorIndex};
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

    /// Instances for validator `me`.
    pub fn new(me: ValidatorIndex) -> Self {
        Self {
            me,
            instances: HashMap::new(),
            floor: 0,
            stats: RbcStats::default(),
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
        if echo >= committee.rbc_vote_threshold() && send(inst, SignalKind::Vote, &mut out) {
            loopback.push(SignalKind::Vote);
        }
        if (echo >= committee.rbc_ack_threshold() || vote >= committee.rbc_ack_threshold())
            && send(inst, SignalKind::Ack, &mut out)
        {
            loopback.push(SignalKind::Ack);
        }
        if (ack >= committee.rbc_ack_threshold() || ready >= committee.validity())
            && send(inst, SignalKind::Ready, &mut out)
        {
            loopback.push(SignalKind::Ready);
        }
        if inst.delivered.is_none()
            && (echo >= committee.rbc_fast_threshold() || ready >= committee.ready_delivery())
        {
            inst.delivered = Some(digest);
            let fast = echo >= committee.rbc_fast_threshold();
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
        let author = 0u16;
        let mut parties: Vec<ReliableBroadcast> =
            (0..n as u16).map(ReliableBroadcast::new).collect();
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
                let acts = parties[i].on_propose(&c, author, 1, author, d);
                apply(i, acts, &mut queue, &mut delivered);
            }
        }
        while let Some((from, to, s)) = queue.pop_front() {
            if silent.contains(&to) {
                continue;
            }
            let acts = parties[to as usize].on_signal(&c, from, s);
            apply(to as usize, acts, &mut queue, &mut delivered);
        }
        (0..n)
            .map(|i| {
                if silent.contains(&(i as u16)) {
                    None
                } else {
                    delivered[i]
                }
            })
            .collect()
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
        let mut fast = ReliableBroadcast::new(1);
        for from in [2, 3] {
            fast.on_signal(&c, from, signal(SignalKind::Echo));
        }
        assert_eq!(fast.delivered(1, 0), Some(d));
        assert_eq!(fast.stats(), RbcStats { fast: 1, slow: 0 });
        // No ECHOs at all, a quorum of READYs: the slow path.
        let mut slow = ReliableBroadcast::new(1);
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
        let mut p = ReliableBroadcast::new(1);
        assert!(p.on_propose(&c, 2, 1, 0, [1; 32]).is_empty());
        assert!(p.proposed(1, 0).is_none());
    }

    #[test]
    fn a_sender_counts_once_per_kind_whatever_digest_it_names() {
        let (c, _) = committee(4);
        let mut p = ReliableBroadcast::new(1);
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
