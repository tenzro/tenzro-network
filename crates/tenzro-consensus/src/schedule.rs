//! Leader schedule.
//!
//! Every round has a fixed number of leader slots, each held by a distinct
//! member. Leaders are drawn slot by slot by seats x behaviour, and the draw
//! is credit-bounded: for each slot every member earns its weight in
//! credit, the slot's leader is drawn (in proportion to weight) only from
//! members holding positive credit that lead no earlier slot of the round,
//! and the leader pays the total weight. Credit sums to zero, and no member
//! is drawn while its credit is not positive (unless every member with
//! positive credit already leads a slot of the round), so over any `T` slots
//! a member leads at most `T x weight / total + 1` of them whatever the seeds
//! are. Whoever influences a seed can reorder leaders among the members that
//! are due, never raise a coalition's share above its weight.
//!
//! The seed that picks among the due members depends only on the committed
//! prefix:
//!
//! - an epoch starts with a seed derived from the checkpoint the epoch was
//!   handed over at;
//! - when checkpoint `j` is taken, a new seed `H(domain || digest of
//!   checkpoint j-2)` takes effect [`LOOKAHEAD_ROUNDS`] rounds after the
//!   anchor that closed checkpoint `j`, together with behaviour weights
//!   computed from the leader outcomes committed so far.
//!
//! The schedule for a round is therefore a function of the agreed commit
//! sequence, so every validator evaluates the commit rule for a round against
//! the same leader. A validator that has not yet committed far enough may
//! wait on the wrong leader for a round, which costs it time, never safety.
//! No VRF and no signature enters the draw.

use std::collections::VecDeque;

use parking_lot::Mutex;

use crate::committee::{Committee, ValidatorIndex};
use crate::vertex::{Digest, Round};

/// Rounds between the anchor that closes a checkpoint and the first round
/// drawn from the seed that checkpoint releases, at genesis: the governed
/// `consensus.leader_lookahead_rounds` starts here, and each epoch runs with
/// the value its start carries ([`crate::core::EpochStart`]).
pub const LOOKAHEAD_ROUNDS: Round = 4;

/// Number of most recent leader outcomes behaviour weights are computed over.
pub const BEHAVIOUR_WINDOW: usize = 200;

/// Behaviour factor of a leader with no recent failures.
pub const ACTIVE_FACTOR: u64 = 1_000;
/// Behaviour factor of a leader whose recent slots failed too often.
pub const FAILED_FACTOR: u64 = 1;
/// A leader fails when more than this percentage of its recent slots in the
/// window were skipped.
pub const FAILURE_THRESHOLD_PERCENT: u64 = 10;

/// Rounds between stored credit snapshots.
const SNAPSHOT_EVERY: Round = 64;

#[derive(Clone, Debug)]
struct Entry {
    from: Round,
    seed: Digest,
    weights: Vec<u64>,
    total: u64,
}

impl Entry {
    fn new(from: Round, seed: Digest, weights: Vec<u64>) -> Self {
        let total = weights.iter().sum();
        Self {
            from,
            seed,
            weights,
            total,
        }
    }
}

/// Leaders drawn so far and the credit state after them.
#[derive(Clone, Debug)]
struct Drawn {
    /// Leader slots per round.
    slots: usize,
    /// Round of the first `slots` entries of `leaders`.
    base: Round,
    /// Leaders of the drawn rounds, `slots` per round in slot order.
    leaders: Vec<ValidatorIndex>,
    /// Credit before round `base + leaders.len()`.
    credit: Vec<i64>,
    /// Credit before each listed round, ascending; the first is at `base`.
    snapshots: Vec<(Round, Vec<i64>)>,
}

impl Drawn {
    fn new(n: usize, slots: usize) -> Self {
        Self {
            slots,
            base: 0,
            leaders: Vec::new(),
            credit: vec![0; n],
            snapshots: vec![(0, vec![0; n])],
        }
    }

    fn next_round(&self) -> Round {
        self.base + (self.leaders.len() / self.slots) as Round
    }

    fn index(&self, round: Round, slot: usize) -> usize {
        (round - self.base) as usize * self.slots + slot
    }

    /// Draws the leaders of the next round under `entry`.
    fn draw(&mut self, entry: &Entry) {
        let round = self.next_round();
        if round.is_multiple_of(SNAPSHOT_EVERY)
            && self.snapshots.last().is_none_or(|(r, _)| *r < round)
        {
            self.snapshots.push((round, self.credit.clone()));
        }
        let mut picked: Vec<usize> = Vec::with_capacity(self.slots);
        for slot in 0..self.slots {
            for (c, w) in self.credit.iter_mut().zip(&entry.weights) {
                *c += *w as i64;
            }
            let open = |i: usize| !picked.contains(&i);
            let due: u64 = self
                .credit
                .iter()
                .zip(&entry.weights)
                .enumerate()
                .filter(|(i, (c, _))| **c > 0 && open(*i))
                .map(|(_, (_, w))| *w)
                .sum();
            let leader = if due == 0 {
                // Every member due already leads a slot of this round: the
                // slot goes to the open member holding the most credit.
                (0..self.credit.len())
                    .filter(|i| open(*i))
                    .max_by_key(|i| (self.credit[*i], std::cmp::Reverse(*i)))
                    .expect("a round has no more slots than members")
            } else {
                let mut h = blake3::Hasher::new();
                h.update(b"tenzro/consensus/leader/draw");
                h.update(&entry.seed);
                h.update(&round.to_be_bytes());
                h.update(&(slot as u64).to_be_bytes());
                let out: [u8; 32] = h.finalize().into();
                let mut draw = u64::from_be_bytes(out[..8].try_into().expect("8 bytes")) % due;
                let mut leader = 0;
                for (i, (c, w)) in self.credit.iter().zip(&entry.weights).enumerate() {
                    if *c > 0 && open(i) {
                        if draw < *w {
                            leader = i;
                            break;
                        }
                        draw -= *w;
                    }
                }
                leader
            };
            self.credit[leader] -= entry.total as i64;
            picked.push(leader);
            self.leaders.push(leader as ValidatorIndex);
        }
    }

    /// Forgets the leaders of `round` and later, restoring the credit
    /// before `round` from the nearest snapshot.
    fn truncate(&mut self, round: Round, entries: &[Entry]) {
        if round >= self.next_round() {
            return;
        }
        let round = round.max(self.base);
        self.snapshots.retain(|(r, _)| *r <= round);
        let (from, credit) = self
            .snapshots
            .last()
            .expect("the base snapshot is kept")
            .clone();
        self.credit = credit;
        for r in from..round {
            let e = entry_for(entries, r);
            for slot in 0..self.slots {
                for (c, w) in self.credit.iter_mut().zip(&e.weights) {
                    *c += *w as i64;
                }
                let leader = self.leaders[self.index(r, slot)] as usize;
                self.credit[leader] -= e.total as i64;
            }
        }
        let keep = self.index(round, 0);
        self.leaders.truncate(keep);
    }

    /// Drops leaders and snapshots below the newest snapshot at or below
    /// `round`.
    fn prune_below(&mut self, round: Round) {
        let keep = self
            .snapshots
            .iter()
            .rposition(|(r, _)| *r <= round)
            .unwrap_or(0);
        self.snapshots.drain(..keep);
        let new_base = self.snapshots[0].0;
        self.leaders
            .drain(..(new_base - self.base) as usize * self.slots);
        self.base = new_base;
    }
}

fn entry_for(entries: &[Entry], round: Round) -> &Entry {
    entries
        .iter()
        .rev()
        .find(|e| e.from <= round)
        .unwrap_or(&entries[0])
}

/// The leader schedule of one epoch.
#[derive(Debug)]
pub struct Schedule {
    lookahead: Round,
    entries: Vec<Entry>,
    outcomes: VecDeque<(ValidatorIndex, bool)>,
    drawn: Mutex<Drawn>,
}

impl Clone for Schedule {
    fn clone(&self) -> Self {
        Self {
            lookahead: self.lookahead,
            entries: self.entries.clone(),
            outcomes: self.outcomes.clone(),
            drawn: Mutex::new(self.drawn.lock().clone()),
        }
    }
}

impl Schedule {
    /// The schedule of `committee`'s epoch, starting from `epoch_seed`, with
    /// `slots` leader slots per round (at least one, at most the committee
    /// size), redrawing leaders `lookahead` rounds after each checkpoint's
    /// anchor (at least one).
    pub fn new(committee: &Committee, epoch_seed: Digest, slots: usize, lookahead: Round) -> Self {
        let weights: Vec<u64> = committee
            .members()
            .iter()
            .map(|m| m.seats * ACTIVE_FACTOR)
            .collect();
        let slots = slots.clamp(1, committee.size().max(1));
        Self {
            lookahead: lookahead.max(1),
            entries: vec![Entry::new(0, epoch_seed, weights)],
            outcomes: VecDeque::new(),
            drawn: Mutex::new(Drawn::new(committee.size(), slots)),
        }
    }

    /// Rounds between a checkpoint's anchor and the first round its seed
    /// draws.
    pub fn lookahead(&self) -> Round {
        self.lookahead
    }

    /// What determines every later draw: the entries, the recent outcomes,
    /// and the credit at the first retained draw.
    pub fn export(&self) -> crate::ordering::ScheduleState {
        let d = self.drawn.lock();
        let (base, credit) = d.snapshots[0].clone();
        crate::ordering::ScheduleState {
            entries: self
                .entries
                .iter()
                .map(|e| (e.from, e.seed, e.weights.clone()))
                .collect(),
            outcomes: self.outcomes.iter().copied().collect(),
            slots: d.slots as u64,
            lookahead: self.lookahead,
            base,
            credit,
        }
    }

    /// A schedule that draws exactly as the one `state` was exported from.
    pub fn import(state: &crate::ordering::ScheduleState) -> Self {
        let slots = (state.slots as usize).max(1);
        Self {
            lookahead: state.lookahead.max(1),
            entries: state
                .entries
                .iter()
                .map(|(from, seed, weights)| Entry::new(*from, *seed, weights.clone()))
                .collect(),
            outcomes: state.outcomes.iter().copied().collect(),
            drawn: Mutex::new(Drawn {
                slots,
                base: state.base,
                leaders: Vec::new(),
                credit: state.credit.clone(),
                snapshots: vec![(state.base, state.credit.clone())],
            }),
        }
    }

    /// Leader slots per round.
    pub fn slots(&self) -> usize {
        self.drawn.lock().slots
    }

    /// The seed an epoch starts from, given the digest of the checkpoint it
    /// was handed over at.
    pub fn epoch_seed(epoch: u64, handover_checkpoint: &Digest) -> Digest {
        let mut h = blake3::Hasher::new();
        h.update(b"tenzro/consensus/leader/epoch");
        h.update(&epoch.to_be_bytes());
        h.update(handover_checkpoint);
        h.finalize().into()
    }

    /// The leader of slot `slot` of `round`.
    pub fn leader(&self, round: Round, slot: usize) -> ValidatorIndex {
        let mut d = self.drawn.lock();
        let slot = slot.min(d.slots - 1);
        // Rounds below the retained draws are already decided and are never
        // asked for; they read the oldest retained draw.
        if round < d.base {
            if d.leaders.is_empty() {
                let base = d.base;
                d.draw(entry_for(&self.entries, base));
            }
            return d.leaders[slot];
        }
        while d.next_round() <= round {
            let r = d.next_round();
            d.draw(entry_for(&self.entries, r));
        }
        d.leaders[d.index(round, slot)]
    }

    /// Whether `v` leads a slot of `round`.
    pub fn leads(&self, round: Round, v: ValidatorIndex) -> bool {
        (0..self.slots()).any(|s| self.leader(round, s) == v)
    }

    /// Records a committed leader slot (`committed`) or a skipped one.
    pub fn record_outcome(&mut self, leader: ValidatorIndex, committed: bool) {
        self.outcomes.push_back((leader, committed));
        while self.outcomes.len() > BEHAVIOUR_WINDOW {
            self.outcomes.pop_front();
        }
    }

    /// Adds the schedule released by a checkpoint taken at anchor round
    /// `anchor_round`, seeded from `seed_checkpoint` (the digest of the
    /// checkpoint two before it).
    pub fn advance(
        &mut self,
        committee: &Committee,
        anchor_round: Round,
        seed_checkpoint: &Digest,
    ) {
        let mut h = blake3::Hasher::new();
        h.update(b"tenzro/consensus/leader");
        h.update(seed_checkpoint);
        let seed: Digest = h.finalize().into();
        let mut slots = vec![(0u64, 0u64); committee.size()];
        for (l, ok) in &self.outcomes {
            let s = &mut slots[*l as usize];
            s.0 += 1;
            if !ok {
                s.1 += 1;
            }
        }
        let weights: Vec<u64> = committee
            .members()
            .iter()
            .zip(slots)
            .map(|(m, (total, skipped))| {
                let failed = total > 0 && skipped * 100 > total * FAILURE_THRESHOLD_PERCENT;
                m.seats * if failed { FAILED_FACTOR } else { ACTIVE_FACTOR }
            })
            .collect();
        let from = anchor_round + self.lookahead + 1;
        let drawn = self.drawn.get_mut();
        drawn.truncate(from, &self.entries);
        self.entries.retain(|e| e.from < from);
        self.entries.push(Entry::new(from, seed, weights));
        // Draws below the anchor are committed; entries that no longer
        // govern any retained draw are dropped.
        drawn.prune_below(anchor_round);
        let base = drawn.base;
        let keep_from = self
            .entries
            .iter()
            .rposition(|e| e.from <= base)
            .unwrap_or(0);
        self.entries.drain(..keep_from);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::test_support::committee;
    use rand::{Rng, SeedableRng};

    #[test]
    fn an_imported_schedule_draws_the_same_leaders() {
        let (c, _) = committee(7);
        let mut s = Schedule::new(&c, [5; 32], 2, 7);
        for r in 0..300u64 {
            let l = s.leader(r, 0);
            s.record_outcome(l, r % 5 != 0);
            if r % 37 == 0 {
                s.advance(&c, r, &[r as u8; 32]);
            }
        }
        let copy = Schedule::import(&s.export());
        assert_eq!(copy.export(), s.export());
        assert_eq!(copy.lookahead(), 7);
        for r in 280..1_000u64 {
            for k in 0..2 {
                assert_eq!(copy.leader(r, k), s.leader(r, k), "round {r} slot {k}");
            }
        }
    }

    #[test]
    fn leaders_are_drawn_in_proportion_to_seats() {
        let (c, _) = committee(10);
        let s = Schedule::new(&c, [3; 32], 1, LOOKAHEAD_ROUNDS);
        let mut counts = [0u32; 10];
        for r in 0..20_000 {
            counts[s.leader(r, 0) as usize] += 1;
        }
        for n in counts {
            assert!((1_980..=2_020).contains(&n), "{counts:?}");
        }
    }

    #[test]
    fn a_round_has_distinct_slot_leaders_drawn_in_proportion_to_seats() {
        let (c, _) = committee(10);
        let mut s = Schedule::new(&c, [3; 32], 3, LOOKAHEAD_ROUNDS);
        let mut counts = [0u32; 10];
        for r in 0..10_000 {
            let l: Vec<_> = (0..3).map(|k| s.leader(r, k)).collect();
            assert!(
                l[0] != l[1] && l[1] != l[2] && l[0] != l[2],
                "round {r}: {l:?}"
            );
            for v in l {
                counts[v as usize] += 1;
            }
        }
        for n in counts {
            assert!((2_970..=3_030).contains(&n), "{counts:?}");
        }
        // A new seed leaves every slot up to its lookahead as it was.
        let slots = |s: &Schedule| -> Vec<ValidatorIndex> {
            (9_100..9_300)
                .flat_map(|r| (0..3).map(move |k| (r, k)))
                .map(|(r, k)| s.leader(r, k))
                .collect()
        };
        let before = slots(&s);
        s.advance(&c, 9_100, &[8; 32]);
        let after = slots(&s);
        let fixed = (LOOKAHEAD_ROUNDS as usize + 1) * 3;
        assert_eq!(before[..fixed], after[..fixed]);
        assert_ne!(before[fixed..], after[fixed..]);
    }

    #[test]
    fn a_new_seed_governs_only_rounds_after_the_lookahead() {
        let (c, _) = committee(10);
        let mut s = Schedule::new(&c, [3; 32], 1, LOOKAHEAD_ROUNDS);
        let before: Vec<_> = (0..40).map(|r| s.leader(r, 0)).collect();
        s.advance(&c, 20, &[9; 32]);
        let after: Vec<_> = (0..40).map(|r| s.leader(r, 0)).collect();
        assert_eq!(
            before[..=20 + LOOKAHEAD_ROUNDS as usize],
            after[..=20 + LOOKAHEAD_ROUNDS as usize]
        );
        assert_ne!(before[25..], after[25..]);
    }

    #[test]
    fn the_same_commits_give_the_same_schedule_whatever_was_asked_before() {
        let (c, _) = committee(10);
        let mut a = Schedule::new(&c, [3; 32], 1, LOOKAHEAD_ROUNDS);
        let mut b = Schedule::new(&c, [3; 32], 1, LOOKAHEAD_ROUNDS);
        for r in 0..300 {
            a.leader(r, 0);
        }
        for k in 0..10u64 {
            a.advance(&c, 20 * k + 7, &[k as u8; 32]);
            b.advance(&c, 20 * k + 7, &[k as u8; 32]);
            for r in 20 * k..20 * k + 90 {
                a.leader(r, 0);
            }
        }
        for r in 187..400 {
            assert_eq!(a.leader(r, 0), b.leader(r, 0), "round {r}");
        }
    }

    #[test]
    fn a_leader_that_keeps_failing_is_rarely_drawn() {
        let (c, _) = committee(10);
        let mut s = Schedule::new(&c, [3; 32], 1, LOOKAHEAD_ROUNDS);
        for _ in 0..20 {
            s.record_outcome(4, false);
            s.record_outcome(5, true);
        }
        s.advance(&c, 0, &[1; 32]);
        let drawn = (10..10_010).filter(|r| s.leader(*r, 0) == 4).count();
        assert!(drawn < 20, "{drawn}");
    }

    /// A coalition holding `members` of `n` equal seats grinds: whenever it
    /// closed the checkpoint a seed comes from, it picks the best of `tries`
    /// digests for that seed, knowing every other seed in force, to maximise
    /// its leaders over the next two checkpoints. Returns its leader share
    /// over all rounds, with each checkpoint `per_checkpoint` rounds.
    fn grind(n: usize, members: usize, tries: usize, checkpoints: u64, per_checkpoint: u64) -> f64 {
        let (c, _) = committee(n);
        let ours = |v: ValidatorIndex| (v as usize) < members;
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let mut s = Schedule::new(&c, [0; 32], 1, LOOKAHEAD_ROUNDS);
        let mut closers: Vec<ValidatorIndex> = Vec::new();
        let mut won = 0u64;
        for j in 0..checkpoints {
            let anchor = j * per_checkpoint;
            closers.push(s.leader(anchor, 0));
            let controlled = j >= 2 && ours(closers[(j - 2) as usize]);
            let window =
                anchor + LOOKAHEAD_ROUNDS + 1..anchor + LOOKAHEAD_ROUNDS + 1 + 2 * per_checkpoint;
            let mut best = rng.r#gen::<[u8; 32]>();
            if controlled {
                let mut best_score = 0;
                for _ in 0..tries {
                    let digest = rng.r#gen::<[u8; 32]>();
                    let mut trial = s.clone();
                    trial.advance(&c, anchor, &digest);
                    let score = window.clone().filter(|r| ours(trial.leader(*r, 0))).count();
                    if score > best_score {
                        best_score = score;
                        best = digest;
                    }
                }
            }
            s.advance(&c, anchor, &best);
            for r in anchor..anchor + per_checkpoint {
                won += ours(s.leader(r, 0)) as u64;
            }
        }
        won as f64 / (checkpoints * per_checkpoint) as f64
    }

    #[test]
    fn grinding_seeds_does_not_raise_a_coalition_share() {
        let share = grind(10, 3, 64, 400, 4);
        assert!((share - 0.3).abs() <= 0.02, "{share}");
    }

    /// The leader-seed grinding criterion at `TDC_N` (default 100) with an
    /// `f` coalition, `TDC_GRIND_TRIES` digests per controlled seed (default
    /// 4096) and `TDC_GRIND_CHECKPOINTS` checkpoints of four rounds (default
    /// 5000). Prints one `GATE {json}` line. Run with `--release --ignored
    /// --nocapture`.
    #[test]
    #[ignore]
    fn gate_leader_seed_grinding() {
        let env = |k: &str, d: u64| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        let n = env("TDC_N", 100) as usize;
        let f = (n - 1) / 3;
        let tries = env("TDC_GRIND_TRIES", 4096) as usize;
        let checkpoints = env("TDC_GRIND_CHECKPOINTS", 5000);
        let share = grind(n, f, tries, checkpoints, 4);
        let stake = f as f64 / n as f64;
        let gain_pts = (share - stake) * 100.0;
        println!(
            "GATE {{\"gate\":\"leader_seed_grinding\",\"n\":{n},\"coalition\":{f},\"tries\":{tries},\
             \"checkpoints\":{checkpoints},\"stake_share\":{stake:.4},\"leader_share\":{share:.4},\"gain_pts\":{gain_pts:.2}}}"
        );
        assert!(gain_pts <= 2.0);
    }
}
