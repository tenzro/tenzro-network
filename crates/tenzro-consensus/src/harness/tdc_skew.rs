//! Validators whose wall clocks disagree, on links that delay and lose
//! packets as a lossy network does.
//!
//! Each validator reads its own clock: the run's time plus that validator's
//! offset, which a restart may change, as a machine whose clock is set wrong
//! and is then restarted with another setting. Links deliver in order, as a
//! stream does; while a delay phase lasts every frame takes a one-way delay
//! with jitter, a lost packet costs one more round trip before the frame
//! arrives, and a frame the link tears down with it is lost outright.

use std::collections::{BTreeMap, HashMap, VecDeque};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::*;
use crate::harness::driver::{SimBatch, SimNode};

/// A delay phase: from, until, one-way delay, jitter, packet loss in
/// percent, and frames lost outright in percent.
#[derive(Clone, Copy)]
struct Netem {
    from: u64,
    until: u64,
    delay_ms: u64,
    jitter_ms: u64,
    loss_pct: f64,
    drop_pct: f64,
}

/// A validator taken down and brought back with a different clock offset.
#[derive(Clone, Copy)]
struct SkewRestart {
    who: usize,
    down_at: u64,
    up_at: u64,
    offset_after: i64,
}

#[derive(Clone)]
struct Plan {
    n: usize,
    offset: Vec<i64>,
    restarts: Vec<SkewRestart>,
    netem: Vec<Netem>,
    /// Validators whose checkpoint votes are lost on every link, and when.
    vote_loss: Vec<(usize, u64, u64)>,
    until: u64,
    seed: u64,
}

/// Where the run starts, so a clock set back by the largest offset still
/// reads a positive time.
const T0: u64 = 60_000;
const CONNECT_MS: u64 = 200;

struct Outcome {
    nodes: Vec<TdcNode>,
    /// Per validator, index to (digest, run time first certified).
    certified: Vec<BTreeMap<u64, (Digest, u64)>>,
    /// Per validator, (epoch, run time) of every block it ordered.
    blocks: Vec<Vec<(u64, u64)>>,
}

impl Plan {
    fn offset_at(&self, i: usize, t: u64) -> i64 {
        let mut off = self.offset[i];
        for r in self.restarts.iter().filter(|r| r.who == i && t >= r.up_at) {
            off = r.offset_after;
        }
        off
    }

    fn local(&self, i: usize, t: u64) -> u64 {
        (t as i64 + self.offset_at(i, t)).max(0) as u64
    }

    fn down(&self, i: usize, t: u64) -> bool {
        self.restarts
            .iter()
            .any(|r| r.who == i && t >= r.down_at && t < r.up_at)
    }

    fn netem_at(&self, t: u64) -> Option<Netem> {
        self.netem
            .iter()
            .copied()
            .find(|e| t >= e.from && t < e.until)
    }
}

fn run(plan: &Plan) -> Outcome {
    let n = plan.n;
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
    // Journal from the start for every validator that restarts; the restart
    // itself is made here, at the run time the plan names.
    let restarting: Vec<u16> = plan.restarts.iter().map(|r| r.who as u16).collect();
    p.restart = Some((u64::MAX, restarting));
    let mut nodes = nodes(n, &p);
    for (i, node) in nodes.iter_mut().enumerate() {
        node.core.start(plan.local(i, T0));
    }
    let mut rng = StdRng::seed_from_u64(plan.seed);
    let mut epoch = vec![0u64; n];
    let mut up: HashMap<(usize, usize), u64> = HashMap::new();
    let mut pending: Vec<(u64, usize, usize, u64)> = Vec::new();
    for a in 0..n {
        for b in a + 1..n {
            pending.push((T0 + CONNECT_MS, a, b, 0));
        }
    }
    // In flight per directed link: arrival, epoch, frame.
    let mut links: HashMap<(usize, usize), VecDeque<(u64, u64, Vec<Message>)>> = HashMap::new();
    let mut certified: Vec<BTreeMap<u64, (Digest, u64)>> = vec![BTreeMap::new(); n];
    let mut blocks: Vec<Vec<(u64, u64)>> = vec![Vec::new(); n];
    let mut was_down = vec![false; n];
    let mut seq = 0u64;
    let mut t = T0;
    while t < plan.until {
        // Validators going down lose their channels and what is in flight to
        // them; validators coming back recover from their journal.
        for i in 0..n {
            let down = plan.down(i, t);
            if down && !was_down[i] {
                up.retain(|(a, b), _| *a != i && *b != i);
                links.retain(|(a, b), _| *a != i && *b != i);
            }
            if !down && was_down[i] {
                let now = plan.local(i, t);
                // The journal stays on disk across the restart, for the next.
                let kept = nodes[i].journal.clone();
                nodes[i].restart(now);
                nodes[i].journal = kept;
                nodes[i].core.start(now);
                epoch[i] = nodes[i].core.committee().epoch;
                for j in (0..n).filter(|j| *j != i && epoch[*j] == epoch[i]) {
                    pending.push((t + CONNECT_MS, i.min(j), i.max(j), epoch[i]));
                }
            }
            was_down[i] = down;
        }
        // Certificate gossip: a validator adopts its running epoch's closing
        // and handover certificates from any peer it hears.
        if t.is_multiple_of(500) {
            for i in (0..n).filter(|i| !plan.down(*i, t)) {
                let e = nodes[i].core.committee().epoch;
                let mut carried: BTreeMap<u64, _> = BTreeMap::new();
                for j in (0..n).filter(|j| *j != i && !plan.down(*j, t)) {
                    for (c, sessions) in nodes[j]
                        .handovers
                        .iter()
                        .filter(|(c, _)| c.checkpoint.epoch == e)
                    {
                        carried
                            .entry(c.checkpoint.index)
                            .or_insert_with(|| (c.clone(), sessions.clone()));
                    }
                }
                let now = plan.local(i, t);
                for (cert, sessions) in carried.into_values() {
                    nodes[i].core.adopt_certificate(cert, sessions);
                    nodes[i].tick(now);
                }
            }
        }
        let follow = |nodes: &mut [TdcNode],
                      epoch: &mut [u64],
                      up: &mut HashMap<(usize, usize), u64>,
                      pending: &mut Vec<(u64, usize, usize, u64)>| {
            for i in (0..n).filter(|i| !plan.down(*i, t)) {
                let e = nodes[i].core.committee().epoch;
                if e != epoch[i] {
                    epoch[i] = e;
                    nodes[i].core.start(plan.local(i, t));
                    up.retain(|(a, b), _| *a != i && *b != i);
                    for j in (0..n).filter(|j| *j != i && epoch[*j] == e) {
                        pending.push((t + CONNECT_MS, i.min(j), i.max(j), e));
                    }
                }
            }
        };
        follow(&mut nodes, &mut epoch, &mut up, &mut pending);
        let (due, later): (Vec<_>, Vec<_>) = pending.drain(..).partition(|(at, ..)| *at <= t);
        pending = later;
        for (_, a, b, e) in due {
            if plan.down(a, t) || plan.down(b, t) {
                continue;
            }
            if epoch[a] == e && epoch[b] == e && !up.contains_key(&(a, b)) {
                up.insert((a, b), e);
                nodes[a]
                    .core
                    .on_peer_up(b as ValidatorIndex, plan.local(a, t));
                nodes[b]
                    .core
                    .on_peer_up(a as ValidatorIndex, plan.local(b, t));
            }
        }
        if t.is_multiple_of(200) {
            seq += 1;
            let to = (seq as usize) % n;
            if !plan.down(to, t) {
                let mut digest = [0u8; 32];
                digest[..8].copy_from_slice(&seq.to_be_bytes());
                nodes[to].submit(
                    SimBatch {
                        digest,
                        transactions: 1,
                    },
                    100,
                );
            }
        }
        loop {
            follow(&mut nodes, &mut epoch, &mut up, &mut pending);
            let netem = plan.netem_at(t);
            let mut sent = false;
            for i in (0..n).filter(|i| !plan.down(*i, t)) {
                let e = nodes[i].core.committee().epoch;
                let out = nodes[i].drain(plan.local(i, t));
                for (index, _, digest) in out.certified {
                    certified[i].entry(index).or_insert((digest, t));
                }
                blocks[i].extend(out.ordered.iter().map(|_| (e, t)));
                let mut frames: BTreeMap<usize, Vec<Message>> = BTreeMap::new();
                for (target, m) in out.sends {
                    for to in (0..n).filter(|q| {
                        *q != i
                            && (target == Target::All
                                || target == Target::One(*q as ValidatorIndex))
                    }) {
                        frames.entry(to).or_default().push(m.clone());
                    }
                }
                let votes_lost = plan
                    .vote_loss
                    .iter()
                    .any(|(v, from, until)| *v == i && t >= *from && t < *until);
                for (to, mut msgs) in frames {
                    if votes_lost {
                        msgs.retain(|m| !matches!(m, Message::Vote(_)));
                        if msgs.is_empty() {
                            continue;
                        }
                    }
                    let mut arrive = t;
                    if let Some(ne) = netem {
                        if rng.gen_bool((ne.drop_pct / 100.0).clamp(0.0, 1.0)) {
                            continue;
                        }
                        let j = if ne.jitter_ms > 0 {
                            rng.gen_range(0..=2 * ne.jitter_ms) as i64 - ne.jitter_ms as i64
                        } else {
                            0
                        };
                        let one_way = (ne.delay_ms as i64 + j).max(0) as u64;
                        arrive += one_way;
                        if rng.gen_bool((ne.loss_pct / 100.0).clamp(0.0, 1.0)) {
                            arrive += 2 * ne.delay_ms;
                        }
                    }
                    let q = links.entry((i, to)).or_default();
                    // A stream delivers in order.
                    if let Some((last, ..)) = q.back() {
                        arrive = arrive.max(*last);
                    }
                    q.push_back((arrive, e, msgs));
                    sent = true;
                }
            }
            let mut delivered = false;
            for i in 0..n {
                for to in 0..n {
                    let Some(q) = links.get_mut(&(i, to)) else {
                        continue;
                    };
                    while q.front().is_some_and(|(at, ..)| *at <= t) {
                        let (_, e, msgs) = q.pop_front().expect("front");
                        let carries = up.get(&(i.min(to), i.max(to))) == Some(&e)
                            && epoch[to] == e
                            && !plan.down(to, t);
                        if carries {
                            nodes[to].deliver(i as u16, msgs, plan.local(to, t));
                            delivered = true;
                        }
                    }
                }
            }
            if !sent && !delivered {
                break;
            }
        }
        for i in (0..n).filter(|i| !plan.down(*i, t)) {
            nodes[i].tick(plan.local(i, t));
        }
        t += 10;
    }
    Outcome {
        nodes,
        certified,
        blocks,
    }
}

/// Longest run time any validator up at the time went without a new
/// certificate between `from` and the end of the run, and when it began.
fn longest_certification_gap(plan: &Plan, o: &Outcome, from: u64) -> (u64, usize, u64) {
    let mut worst = (0, 0, 0);
    for i in 0..plan.n {
        let mut times: Vec<u64> = o.certified[i].values().map(|(_, at)| *at).collect();
        times.sort_unstable();
        let mut last = from;
        for at in times
            .into_iter()
            .filter(|at| *at >= from)
            .chain([plan.until])
        {
            // Time a validator was down is not held against it.
            let downtime: u64 = plan
                .restarts
                .iter()
                .filter(|r| r.who == i)
                .map(|r| r.up_at.min(at).saturating_sub(r.down_at.max(last)))
                .sum();
            let gap = at.saturating_sub(last).saturating_sub(downtime);
            if gap > worst.0 {
                worst = (gap, i, last);
            }
            last = at;
        }
    }
    worst
}

/// Every validator stays live, certifies with no gap longer than
/// `max_gap_ms` after `from`, and all certify the same checkpoints.
fn assert_live(name: &str, plan: &Plan, o: &Outcome, from: u64, max_gap_ms: u64) {
    for i in 0..plan.n {
        assert!(
            !o.nodes[i].core.is_halted(),
            "{name}: validator {i} halted in epoch {}",
            o.nodes[i].core.committee().epoch
        );
        let late = o.blocks[i]
            .iter()
            .filter(|(_, at)| *at >= plan.until - 10_000)
            .count();
        assert!(
            late > 0,
            "{name}: validator {i} ordered no block in the last 10 s (epoch {})",
            o.nodes[i].core.committee().epoch
        );
    }
    let (gap, who, since) = longest_certification_gap(plan, o, from);
    assert!(
        gap <= max_gap_ms,
        "{name}: validator {who} certified nothing for {gap} ms from run time {since}"
    );
    for i in 0..plan.n {
        for j in i + 1..plan.n {
            for (index, (digest, _)) in &o.certified[i] {
                if let Some((d, _)) = o.certified[j].get(index) {
                    assert_eq!(
                        d, digest,
                        "{name}: validators {i} and {j} certified different checkpoints at {index}"
                    );
                }
            }
        }
    }
}

fn plan(n: usize, offset: Vec<i64>) -> Plan {
    Plan {
        n,
        offset,
        restarts: Vec::new(),
        netem: Vec::new(),
        vote_loss: Vec::new(),
        until: T0 + 70_000,
        seed: 11,
    }
}

/// One validator's clock runs behind or ahead of the others' by a few
/// seconds and by half a minute, from the start: the committee certifies
/// as it does with the clocks agreeing. Vertex timestamps only feed the
/// block time, so no validator refuses another's messages over its clock.
#[test]
fn one_validator_with_a_skewed_clock_does_not_slow_certification() {
    for n in [4usize, 7] {
        for skew in [-30_000i64, -5_000, -1_500, 1_500, 5_000, 30_000] {
            let mut offset = vec![0; n];
            offset[n - 1] = skew;
            let p = plan(n, offset);
            let o = run(&p);
            assert_live(&format!("n={n} skew={skew}"), &p, &o, T0 + 5_000, 2_000);
        }
    }
}

/// Every validator's clock differs from every other's, by up to a minute.
#[test]
fn clocks_spread_over_a_minute_do_not_slow_certification() {
    let p = plan(7, vec![-30_000, -5_000, -1_500, 0, 1_500, 5_000, 30_000]);
    let o = run(&p);
    assert_live("spread", &p, &o, T0 + 5_000, 2_000);
}

/// The chaos run's clock step: a validator is taken down for 20 s and comes
/// back with its clock set back 5 s or 1.5 s (or forward), so time as it
/// reads it runs backwards across the restart, while every link delays
/// 150 ms with 10-50 ms of jitter and loses 2-10% of its packets. Every
/// validator certifies again within a few seconds of the restart.
#[test]
fn a_validator_restarted_with_its_clock_stepped_recovers_under_delay_and_loss() {
    for n in [4usize, 7] {
        for (step, jitter, loss) in [
            (-5_000i64, 10u64, 2.0f64),
            (-5_000, 50, 10.0),
            (-1_500, 50, 10.0),
            (5_000, 50, 10.0),
            (-30_000, 50, 10.0),
            (30_000, 50, 10.0),
        ] {
            let mut p = plan(n, vec![0; n]);
            p.until = T0 + 90_000;
            p.restarts.push(SkewRestart {
                who: n - 1,
                down_at: T0 + 20_000,
                up_at: T0 + 40_000,
                offset_after: step,
            });
            p.netem.push(Netem {
                from: T0 + 10_000,
                until: T0 + 70_000,
                delay_ms: 150,
                jitter_ms: jitter,
                loss_pct: loss,
                drop_pct: 0.0,
            });
            let o = run(&p);
            let name = format!("n={n} step={step} jitter={jitter} loss={loss}");
            assert_live(&name, &p, &o, T0 + 5_000, 6_000);
            // The restarted validator certifies again soon after it is back.
            let back = o.certified[n - 1]
                .values()
                .map(|(_, at)| *at)
                .filter(|at| *at >= T0 + 40_000)
                .min();
            assert!(
                back.is_some_and(|at| at <= T0 + 40_000 + 15_000),
                "{name}: the restarted validator first certified again at {back:?}"
            );
        }
    }
}

/// As above with the skewed validator restarted twice, its clock moving the
/// other way the second time (a skewed clock corrected), and frames lost
/// outright while the delay lasts, as channels torn down and dialled again
/// lose what they held. While it is down the other three are exactly a
/// quorum, so every lost frame they needed delays certification until the
/// core asks again: this run has gaps of up to 15.5 s, against 3.5 to 7.3 s
/// with no frame lost, and certification always resumes.
#[test]
fn a_validator_whose_clock_is_stepped_twice_recovers_while_frames_are_lost() {
    for n in [4usize, 7] {
        let mut p = plan(n, vec![0; n]);
        p.until = T0 + 120_000;
        p.restarts.push(SkewRestart {
            who: n - 1,
            down_at: T0 + 15_000,
            up_at: T0 + 35_000,
            offset_after: -5_000,
        });
        p.restarts.push(SkewRestart {
            who: n - 1,
            down_at: T0 + 60_000,
            up_at: T0 + 80_000,
            offset_after: 5_000,
        });
        p.netem.push(Netem {
            from: T0 + 10_000,
            until: T0 + 100_000,
            delay_ms: 150,
            jitter_ms: 50,
            loss_pct: 10.0,
            drop_pct: 2.0,
        });
        let o = run(&p);
        assert_live(&format!("n={n} two steps"), &p, &o, T0 + 5_000, 20_000);
    }
}

/// Four validators, one of them down for good, so every certificate needs
/// the votes of all three others. One of them has its checkpoint votes lost
/// on every link for 12 s, across an epoch handover; every other message
/// arrives and every channel stays up. Once its votes arrive again the
/// committee certifies again.
#[test]
fn certification_resumes_after_one_validators_votes_are_lost_across_a_handover() {
    let n = 4;
    let mut p = plan(n, vec![0; n]);
    p.until = T0 + 60_000;
    p.restarts.push(SkewRestart {
        who: 3,
        down_at: T0 + 5_000,
        up_at: u64::MAX,
        offset_after: 0,
    });
    p.vote_loss.push((1, T0 + 15_000, T0 + 27_000));
    let o = run(&p);
    for i in 0..3 {
        let after: Vec<u64> = o.certified[i]
            .iter()
            .filter(|(_, (_, at))| *at >= T0 + 27_000)
            .map(|(index, _)| *index)
            .collect();
        assert!(
            !after.is_empty(),
            "validator {i} certified nothing in the 33 s after the votes arrive again (epoch {}, halted {}, last certified {:?})",
            o.nodes[i].core.committee().epoch,
            o.nodes[i].core.is_halted(),
            o.certified[i]
                .iter()
                .next_back()
                .map(|(k, (_, at))| (*k, at - T0))
        );
    }
}
