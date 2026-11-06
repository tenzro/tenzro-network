//! The local DAG of delivered vertices.
//!
//! A vertex enters the DAG only once every vertex it references is already
//! in it, so the DAG is always causally closed. A delivered vertex whose
//! references are missing waits in a pending set while the missing ones are
//! fetched by digest from peers. A fetched vertex is accepted only when its
//! digest is one this validator delivered through reliable broadcast, or one
//! in the causal history of accepted vertices from authors holding at least
//! `f + 1` seats: at least one of those authors is honest, and an honest
//! author's history holds only the vertices reliable broadcast delivered for
//! their slots. The digest then authenticates the content without a
//! signature. A fetched vertex not yet accepted is held, and its references
//! carry the authors whose history reaches it.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use crate::committee::ValidatorIndex;
use crate::vertex::{Digest, Round, Vertex, VertexRef};

/// The delivered, causally closed vertices of one epoch.
pub struct Dag {
    rounds: BTreeMap<Round, HashMap<ValidatorIndex, (Digest, Vertex)>>,
    by_digest: HashMap<Digest, (Round, ValidatorIndex)>,
    pending: HashMap<Digest, Vertex>,
    expected: HashMap<Digest, Round>,
    floor: Round,
    /// Seats of each committee member, by index.
    seats: Vec<u64>,
    /// Seats of authors whose accepted vertices reach an undelivered digest
    /// that make it acceptable; `u64::MAX` (the default) accepts delivered
    /// digests only.
    vouch_seats: u64,
    /// Fetched vertices not yet acceptable, by digest.
    held: HashMap<Digest, Vertex>,
    /// For each digest not in the DAG, the round and the authors whose
    /// accepted vertices reach it through references.
    reached_by: HashMap<Digest, (Round, HashSet<ValidatorIndex>)>,
}

impl Default for Dag {
    fn default() -> Self {
        Self {
            rounds: BTreeMap::new(),
            by_digest: HashMap::new(),
            pending: HashMap::new(),
            expected: HashMap::new(),
            floor: 0,
            seats: Vec::new(),
            vouch_seats: u64::MAX,
            held: HashMap::new(),
            reached_by: HashMap::new(),
        }
    }
}

impl Dag {
    /// An empty DAG.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty DAG for a committee whose members hold `seats`, accepting a
    /// fetched digest once accepted vertices of authors holding
    /// `vouch_seats` reach it.
    pub fn with_vouching(seats: Vec<u64>, vouch_seats: u64) -> Self {
        Self {
            seats,
            vouch_seats,
            ..Self::default()
        }
    }

    pub(crate) fn pending_len(&self) -> (usize, usize) {
        (self.pending.len(), self.expected.len())
    }

    /// Lowest round still held.
    pub fn floor(&self) -> Round {
        self.floor
    }

    /// Whether the vertex `digest` is in the DAG.
    pub fn contains(&self, digest: &Digest) -> bool {
        self.by_digest.contains_key(digest)
    }

    /// The vertex `digest`, if in the DAG.
    pub fn get(&self, digest: &Digest) -> Option<&Vertex> {
        let (r, s) = self.by_digest.get(digest)?;
        self.rounds.get(r).and_then(|m| m.get(s)).map(|(_, v)| v)
    }

    /// The vertex of `source` in `round`, if in the DAG.
    pub fn at(&self, round: Round, source: ValidatorIndex) -> Option<(&Digest, &Vertex)> {
        self.rounds
            .get(&round)
            .and_then(|m| m.get(&source))
            .map(|(d, v)| (d, v))
    }

    /// Vertices of `round`, by author.
    pub fn round(&self, round: Round) -> impl Iterator<Item = (ValidatorIndex, &Digest, &Vertex)> {
        self.rounds
            .get(&round)
            .into_iter()
            .flat_map(|m| m.iter().map(|(s, (d, v))| (*s, d, v)))
    }

    /// Highest round with at least one vertex.
    pub fn highest_round(&self) -> Option<Round> {
        self.rounds.keys().next_back().copied()
    }

    /// Marks `digest`, a vertex of `round`, as one this validator may
    /// accept from a fetch: one it delivered through reliable broadcast.
    pub fn expect(&mut self, digest: Digest, round: Round) {
        if round >= self.floor && !self.by_digest.contains_key(&digest) {
            self.expected.insert(digest, round);
        }
    }

    /// The round of `digest`, a vertex this validator may accept from a
    /// fetch.
    pub fn expected_round(&self, digest: &Digest) -> Option<Round> {
        self.expected.get(digest).copied()
    }

    /// Whether a fetched vertex with this digest would be accepted.
    pub fn is_expected(&self, digest: &Digest) -> bool {
        self.expected.contains_key(digest)
    }

    /// Offers a vertex whose digest reliable broadcast delivered. Returns
    /// every vertex that entered the DAG as a result, in insertion order,
    /// and the referenced digests still missing, which the caller fetches
    /// and offers once they are delivered too.
    pub fn offer(&mut self, vertex: Vertex) -> (Vec<VertexRef>, Vec<Digest>) {
        let digest = vertex.digest();
        if self.by_digest.contains_key(&digest) || vertex.round < self.floor {
            return (Vec::new(), Vec::new());
        }
        if self.expected.remove(&digest).is_none() {
            return (Vec::new(), Vec::new());
        }
        self.held.remove(&digest);
        let work = self.accept(digest, vertex);
        self.reach(work);
        self.drain_pending()
    }

    /// Holds a fetched vertex that is not yet acceptable. It enters the DAG
    /// once it is delivered or accepted vertices of authors holding
    /// `vouch_seats` reach it; meanwhile its references carry the authors
    /// that reach it. Returns what [`Dag::offer`] returns.
    pub fn hold(&mut self, vertex: Vertex) -> (Vec<VertexRef>, Vec<Digest>) {
        let digest = vertex.digest();
        if self.by_digest.contains_key(&digest)
            || self.pending.contains_key(&digest)
            || vertex.round < self.floor
        {
            return (Vec::new(), Vec::new());
        }
        if self.expected.contains_key(&digest) {
            return self.offer(vertex);
        }
        let carried: Vec<ValidatorIndex> = self
            .reached_by
            .get(&digest)
            .map(|(_, s)| s.iter().copied().collect())
            .unwrap_or_default();
        let refs = self.missing_refs(&vertex);
        self.held.insert(digest, vertex);
        let mut work: Vec<(VertexRef, Vec<ValidatorIndex>)> = Vec::new();
        if !carried.is_empty() {
            for r in refs {
                work.push((r, carried.clone()));
            }
        }
        self.reach(work);
        self.drain_pending()
    }

    /// Puts an acceptable vertex in the pending set; returns its references
    /// with its author and the authors that reach it, to carry on.
    fn accept(&mut self, digest: Digest, vertex: Vertex) -> Vec<(VertexRef, Vec<ValidatorIndex>)> {
        let mut authors: Vec<ValidatorIndex> = self
            .reached_by
            .remove(&digest)
            .map(|(_, s)| s.into_iter().collect())
            .unwrap_or_default();
        if !authors.contains(&vertex.source) {
            authors.push(vertex.source);
        }
        let work: Vec<(VertexRef, Vec<ValidatorIndex>)> = self
            .missing_refs(&vertex)
            .into_iter()
            .map(|r| (r, authors.clone()))
            .collect();
        self.pending.insert(digest, vertex);
        work
    }

    /// Adds authors to the digests in `work`, through held vertices to the
    /// digests those reference, and accepts each held digest whose authors
    /// reach `vouch_seats`.
    fn reach(&mut self, mut work: Vec<(VertexRef, Vec<ValidatorIndex>)>) {
        if self.vouch_seats == u64::MAX {
            return;
        }
        while let Some((r, authors)) = work.pop() {
            if r.round < self.floor
                || self.by_digest.contains_key(&r.digest)
                || self.pending.contains_key(&r.digest)
            {
                continue;
            }
            let entry = self
                .reached_by
                .entry(r.digest)
                .or_insert_with(|| (r.round, HashSet::new()));
            let added: Vec<ValidatorIndex> =
                authors.into_iter().filter(|a| entry.1.insert(*a)).collect();
            if added.is_empty() {
                continue;
            }
            let weight: u64 = entry
                .1
                .iter()
                .map(|a| self.seats.get(*a as usize).copied().unwrap_or(0))
                .sum();
            if weight >= self.vouch_seats {
                if let Some(v) = self.held.remove(&r.digest) {
                    self.expected.remove(&r.digest);
                    work.extend(self.accept(r.digest, v));
                } else {
                    self.expected.insert(r.digest, r.round);
                }
                continue;
            }
            if let Some(v) = self.held.get(&r.digest) {
                for p in self.missing_refs(v) {
                    work.push((p, added.clone()));
                }
            }
        }
    }

    fn missing_refs(&self, v: &Vertex) -> Vec<VertexRef> {
        v.strong
            .iter()
            .chain(v.weak.iter())
            .filter(|r| r.round >= self.floor && !self.by_digest.contains_key(&r.digest))
            .copied()
            .collect()
    }

    fn drain_pending(&mut self) -> (Vec<VertexRef>, Vec<Digest>) {
        let mut inserted = Vec::new();
        loop {
            let ready: Vec<Digest> = self
                .pending
                .iter()
                .filter(|(_, v)| self.missing_refs(v).is_empty())
                .map(|(d, _)| *d)
                .collect();
            if ready.is_empty() {
                break;
            }
            let mut ready: Vec<(Round, ValidatorIndex, Digest)> = ready
                .into_iter()
                .map(|d| {
                    let v = &self.pending[&d];
                    (v.round, v.source, d)
                })
                .collect();
            ready.sort();
            for (_, _, d) in ready {
                let v = self.pending.remove(&d).expect("pending vertex");
                let slot = self.rounds.entry(v.round).or_default();
                if slot.contains_key(&v.source) {
                    // Reliable broadcast delivers one vertex per author and
                    // round; a second can only arrive by fetch and is dropped.
                    continue;
                }
                inserted.push(VertexRef {
                    round: v.round,
                    source: v.source,
                    digest: d,
                });
                self.by_digest.insert(d, (v.round, v.source));
                slot.insert(v.source, (d, v));
            }
        }
        let mut missing = Vec::new();
        let refs: Vec<VertexRef> = self
            .pending
            .values()
            .flat_map(|v| self.missing_refs(v))
            .collect();
        for r in refs {
            if !self.pending.contains_key(&r.digest) && !self.held.contains_key(&r.digest) {
                missing.push(r.digest);
            }
        }
        // Missing digests reached only through held vertices are fetched too.
        let held_refs: Vec<Digest> = self
            .held
            .values()
            .flat_map(|v| self.missing_refs(v))
            .map(|r| r.digest)
            .filter(|d| !self.pending.contains_key(d) && !self.held.contains_key(d))
            .collect();
        missing.extend(held_refs);
        missing.sort();
        missing.dedup();
        (inserted, missing)
    }

    /// Whether `from` reaches `to` through strong references only.
    pub fn strong_path(&self, from: &Digest, to: &VertexRef) -> bool {
        let Some(start) = self.get(from) else {
            return false;
        };
        if start.round < to.round {
            return false;
        }
        if *from == to.digest {
            return true;
        }
        let mut frontier: HashSet<Digest> = HashSet::from([*from]);
        let mut round = start.round;
        while round > to.round && !frontier.is_empty() {
            let mut next = HashSet::new();
            for d in &frontier {
                if let Some(v) = self.get(d) {
                    for s in &v.strong {
                        if s.round == to.round {
                            if s.digest == to.digest {
                                return true;
                            }
                        } else {
                            next.insert(s.digest);
                        }
                    }
                }
            }
            frontier = next;
            round -= 1;
        }
        false
    }

    /// Every DAG vertex reachable from `root` through any reference, root
    /// included, for which `skip` is false, in deterministic order (round,
    /// then author). The walk does not continue past a skipped vertex.
    pub fn causal_history(&self, root: &Digest, skip: impl Fn(&Digest) -> bool) -> Vec<VertexRef> {
        let mut seen: HashSet<Digest> = HashSet::new();
        let mut out = Vec::new();
        let mut queue = VecDeque::from([*root]);
        while let Some(d) = queue.pop_front() {
            if skip(&d) || !seen.insert(d) {
                continue;
            }
            let Some(v) = self.get(&d) else { continue };
            out.push(VertexRef {
                round: v.round,
                source: v.source,
                digest: d,
            });
            for r in v.strong.iter().chain(v.weak.iter()) {
                if r.round >= self.floor {
                    queue.push_back(r.digest);
                }
            }
        }
        out.sort();
        out
    }

    /// Vertices in rounds below `round`, not yet ordered, and not reachable
    /// through any reference from `roots`: the orphans a new vertex should
    /// reference weakly so they are eventually ordered.
    pub fn orphans_below(
        &self,
        round: Round,
        roots: &[Digest],
        ordered: impl Fn(&Digest) -> bool,
        limit: usize,
    ) -> Vec<VertexRef> {
        let mut reachable: HashSet<Digest> = HashSet::new();
        let mut queue: VecDeque<Digest> = roots.iter().copied().collect();
        while let Some(d) = queue.pop_front() {
            if !reachable.insert(d) {
                continue;
            }
            if let Some(v) = self.get(&d) {
                for r in v.strong.iter().chain(v.weak.iter()) {
                    if r.round >= self.floor && !ordered(&r.digest) {
                        queue.push_back(r.digest);
                    }
                }
            }
        }
        let mut out = Vec::new();
        for (r, m) in self.rounds.range(self.floor..round) {
            let mut authors: Vec<_> = m.iter().collect();
            authors.sort_by_key(|(s, _)| **s);
            for (s, (d, _)) in authors {
                if !reachable.contains(d) && !ordered(d) {
                    out.push(VertexRef {
                        round: *r,
                        source: *s,
                        digest: *d,
                    });
                    if out.len() == limit {
                        return out;
                    }
                }
            }
        }
        out
    }

    /// Drops every vertex below `round` and returns the ones it held.
    pub fn prune_below(&mut self, round: Round) -> Vec<(Digest, Vertex)> {
        if round <= self.floor {
            return Vec::new();
        }
        self.floor = round;
        let keep = self.rounds.split_off(&round);
        let mut pruned = Vec::new();
        for m in std::mem::replace(&mut self.rounds, keep).into_values() {
            for (_, (d, v)) in m {
                self.by_digest.remove(&d);
                pruned.push((d, v));
            }
        }
        self.pending.retain(|_, v| v.round >= round);
        self.expected.retain(|_, r| *r >= round);
        self.held.retain(|_, v| v.round >= round);
        self.reached_by.retain(|_, (r, _)| *r >= round);
        pruned
    }

    /// Number of vertices held.
    pub fn len(&self) -> usize {
        self.by_digest.len()
    }

    /// Whether the DAG holds no vertex.
    pub fn is_empty(&self) -> bool {
        self.by_digest.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(round: Round, source: ValidatorIndex, parents: &[VertexRef]) -> Vertex {
        Vertex {
            epoch: 0,
            round,
            source,
            strong: parents.to_vec(),
            weak: vec![],
            batches: vec![],
            carried: vec![],
            timestamp_ms: round * 100,
        }
    }

    #[test]
    fn a_vertex_waits_for_its_parents_and_unknown_digests_are_refused() {
        let mut dag = Dag::new();
        let g: Vec<Vertex> = (0..4).map(|s| v(0, s, &[])).collect();
        let refs: Vec<VertexRef> = g.iter().map(|x| x.reference()).collect();
        let child = v(1, 0, &refs[..3]);
        assert!(
            dag.offer(child.clone()).0.is_empty(),
            "not expected: refused"
        );
        dag.expect(child.digest(), 1);
        let (inserted, missing) = dag.offer(child.clone());
        assert!(inserted.is_empty());
        assert_eq!(missing.len(), 3);
        for p in &g[..3] {
            dag.offer(p.clone());
        }
        assert!(
            !dag.contains(&child.digest()) && !dag.contains(&g[0].digest()),
            "a parent named only by a reference was accepted"
        );
        for p in &g[..3] {
            dag.expect(p.digest(), 0);
            dag.offer(p.clone());
        }
        assert!(dag.contains(&child.digest()));
        assert!(
            !dag.contains(&g[3].digest()),
            "an unreferenced vertex was never expected"
        );
    }

    #[test]
    fn a_reference_from_f_plus_one_seats_makes_an_undelivered_parent_acceptable() {
        // Four members of one seat each: f = 1, so two authors' references
        // vouch for a digest and one author's reference does not.
        let mut dag = Dag::with_vouching(vec![1; 4], 2);
        let g: Vec<Vertex> = (0..4).map(|s| v(0, s, &[])).collect();
        let refs: Vec<VertexRef> = g.iter().map(|x| x.reference()).collect();
        let twin = Vertex {
            timestamp_ms: 7,
            ..g[1].clone()
        };
        let faulty = v(1, 3, &[refs[0], twin.reference(), refs[2]]);
        dag.expect(faulty.digest(), 1);
        dag.offer(faulty.clone());
        assert!(
            !dag.is_expected(&twin.digest()) && !dag.is_expected(&g[0].digest()),
            "one author's reference made a digest acceptable"
        );
        let honest = v(1, 0, &refs[..3]);
        dag.expect(honest.digest(), 1);
        dag.offer(honest.clone());
        assert!(
            dag.is_expected(&g[0].digest()) && dag.is_expected(&g[2].digest()),
            "references from f + 1 seats did not make the parent acceptable"
        );
        assert!(
            !dag.is_expected(&twin.digest()) && !dag.is_expected(&g[1].digest()),
            "a digest referenced by one author only became acceptable"
        );
        for p in [&g[0], &g[2], &twin] {
            dag.offer(p.clone());
        }
        assert!(dag.contains(&g[0].digest()) && dag.contains(&g[2].digest()));
        assert!(!dag.contains(&twin.digest()), "the twin took a slot");
        assert!(!dag.contains(&honest.digest()), "honest waits for g[1]");
    }

    #[test]
    fn a_held_vertex_carries_the_authors_that_reach_it_to_its_parents() {
        let mut dag = Dag::with_vouching(vec![1; 4], 2);
        let p = v(0, 1, &[]);
        let q = v(1, 1, &[p.reference()]);
        let r0 = v(2, 0, &[q.reference()]);
        let r2 = v(2, 2, &[q.reference()]);
        dag.expect(r0.digest(), 2);
        let (_, missing) = dag.offer(r0.clone());
        assert_eq!(missing, vec![q.digest()]);
        let (inserted, missing) = dag.hold(q.clone());
        assert!(inserted.is_empty());
        assert_eq!(
            missing,
            vec![p.digest()],
            "a held vertex's parent is fetched"
        );
        assert!(
            !dag.is_expected(&p.digest()) && !dag.contains(&q.digest()),
            "one author's history made a digest acceptable"
        );
        dag.expect(r2.digest(), 2);
        dag.offer(r2.clone());
        assert!(
            dag.is_expected(&p.digest()),
            "the histories of f + 1 seats did not reach the parent of a held vertex"
        );
        let (inserted, _) = dag.offer(p.clone());
        assert_eq!(inserted.len(), 4);
        for x in [&p, &q, &r0, &r2] {
            assert!(dag.contains(&x.digest()));
        }
    }

    #[test]
    fn strong_paths_follow_only_strong_references() {
        let mut dag = Dag::new();
        let g: Vec<Vertex> = (0..4).map(|s| v(0, s, &[])).collect();
        for x in &g {
            dag.expect(x.digest(), 0);
            dag.offer(x.clone());
        }
        let refs: Vec<VertexRef> = g.iter().map(|x| x.reference()).collect();
        let mut a = v(1, 0, &refs[..3]);
        a.weak.push(refs[3]);
        dag.expect(a.digest(), 1);
        dag.offer(a.clone());
        assert!(dag.strong_path(&a.digest(), &refs[0]));
        assert!(!dag.strong_path(&a.digest(), &refs[3]));
        let hist = dag.causal_history(&a.digest(), |_| false);
        assert_eq!(hist.len(), 5);
    }
}
