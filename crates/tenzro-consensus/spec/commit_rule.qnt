// -*- mode: Bluespec; -*-
//
// The commit rule of Tenzro consensus: leader slots, the direct and indirect
// commit or skip of each slot, and the order committed vertices are released
// in. It follows `Core::direct`, `Core::indirect`, `Core::decide_slots`,
// `Core::try_commit` and `Dag::causal_history` (crates/tenzro-consensus/src).
//
// Reliable broadcast is modeled by the guarantees it gives: each
// (round, author) delivers at most one vertex, the same one at every honest
// validator, and an honest author's vertex is the one it proposed.
// Byzantine validators (the last F) may build several vertices for a round,
// send different first proposals to different validators, reference any
// vertices they like, and withhold. Honest validators learn delivered
// vertices in any order, always causally closed.
//
// Vertices carry strong references only. Each validator's first-proposal
// record, which the direct rule counts as support before a vertex is
// delivered, is modeled per validator.
//
// Invariants:
//   agreement     two honest validators' decided slots, and their released
//                 vertex sequences, are prefixes of one another;
//   noReorder     a validator releases no vertex twice;
//   liveCommit    with SYNC, once nothing more can happen every honest
//                 validator has decided every slot up to MAX_ROUND - 1 and
//                 committed every honest leader's slot.
//
// With REDRAW, every commit takes a checkpoint, and the checkpoint redraws the
// leaders of the rounds from its anchor's round + LOOKAHEAD + 1 on, seeded by
// the anchors committed two checkpoints before (`Core::decide_checkpoint`,
// `Schedule::advance`). Leaders are then a function of each validator's own
// decided prefix, and a validator decides again under the new schedule after
// every commit (`Core::try_commit`).
//
// With RESTARTS, an honest validator may restart (`Core::recover`): it keeps
// its delivered vertices and its own proposals (the journal), loses the first
// proposals of vertices not yet delivered, and decides again from the start
// of the epoch. What it handed to execution before the restart is kept in
// `executed`, and is not executed again.
//
//   rejoinConsistent  a validator's released sequence after a restart is a
//                     prefix of, or extends, what it executed before;
//   executedAgreement the executed sequences of two honest validators are
//                     prefixes of one another;
//   liveCommitEarly   as liveCommit, for the slots up to MAX_ROUND - 4 (a
//                     redrawn schedule may give Byzantine validators the last
//                     rounds, which then never decide).
module commit_rule {
  // Committee size.
  const N: int
  // Byzantine validators: N - F .. N - 1. At most (N - 1) / 3.
  const F: int
  // Last round explored.
  const MAX_ROUND: int
  // Leader slots per round.
  const SLOTS: int
  // Leaders of each round, one per slot, distinct.
  const LEADERS: int -> List[int]
  // Vertices a Byzantine validator may build per round.
  const VERSIONS: int
  // After the network stabilises an honest validator holds every honest
  // leader's vertex of a round before it leaves the round. Without SYNC it
  // may leave on a quorum alone, as after a leader timeout.
  const SYNC: bool
  // Leaders are redrawn at every commit.
  const REDRAW: bool
  // Rounds between a checkpoint's anchor and the first round it redraws.
  const LOOKAHEAD: int
  // Restarts of honest validators allowed in an execution.
  const RESTARTS: int
  // An honest validator decides as soon as anything it holds changes, and
  // then catches up to the highest round it holds a quorum of, as the core
  // does after every input (`Core::progress`). Without it decisions are
  // taken at any later step, which covers every schedule of them.
  const EAGER: bool
  // Byzantine validators build vertices. Without it they are silent, so
  // the honest validators are exactly a quorum.
  const BYZ_BUILD: bool
  // An honest vertex also references weakly the vertices below its previous
  // round that its strong references do not reach and its author has not
  // released, so every delivered vertex is eventually released
  // (`Dag::orphans_below`). Release follows strong and weak references.
  const WEAK: bool
  // A validator that restarts remembers the proposals it echoed (its
  // journal holds the echo), and does not take one of those as a first
  // proposal again (`ReliableBroadcast::restore_sent`). Without it a
  // restarted validator takes any proposal it has no first proposal for.
  const RESTORE_ECHO: bool
  // A validator behind a checkpoint another honest validator decided may
  // resume from it (`Core::resume`): it takes the ordering state the
  // checkpoint's certificate commits to (the decided slots, the released
  // vertices, the leader schedule) and orders on from there, and the blocks
  // up to it count as executed. Every commit takes a checkpoint here.
  const FAST_FORWARD: bool

  type VId = { round: int, author: int, ver: int }
  type Slot = (int, int)
  type Decision = Commit(VId) | Skip | Undecided
  type Step =
    | Init
    | Propose(VId)
    | Build(VId)
    | First((int, VId))
    | Deliver((int, VId))
    | Decide(int)
    | Restart(int)
    | FastForward((int, int))

  pure val Validators: Set[int] = 0.to(N - 1)
  pure val Byz: Set[int] = (N - F).to(N - 1)
  pure val Honest: Set[int] = Validators.exclude(Byz)
  pure val Q: int = N - (N - 1) / 3
  pure val Rounds: List[int] = range(0, MAX_ROUND + 1)
  pure val Authors: List[int] = range(0, N)
  pure val SlotIdx: List[int] = range(0, SLOTS)

  // Every slot, ascending.
  pure val AllSlots: List[Slot] =
    Rounds.foldl([], (acc, r) => SlotIdx.foldl(acc, (acc2, k) => acc2.append((r, k))))

  // Anchors committed in a decided prefix, in order.
  pure def anchorsOf(lg: List[(Slot, Decision)]): List[VId] =
    lg.foldl([], (acc, e) => match e._2 {
      | Commit(x) => acc.append(x)
      | Skip => acc
      | Undecided => acc
    })
  // The seed checkpoint j releases: the ordering digest two checkpoints back.
  pure def seedOf(anc: List[VId], j: int): int =
    if (j < 2) 0
    else range(0, j - 1).foldl(0, (h, k) => (h * 7 + anc[k].author + N * anc[k].ver + 1) % N)
  // The rotation in force at round `rho`: that of the last checkpoint whose
  // redraw starts at or before `rho`.
  pure def offsetAt(anc: List[VId], rho: int): int =
    if (not(REDRAW)) 0
    else range(0, anc.length()).foldl(0, (off, j) =>
      if (anc[j].round + LOOKAHEAD + 1 <= rho) seedOf(anc, j) else off)
  // Leaders of every round under a validator's decided prefix.
  pure def schedule(lg: List[(Slot, Decision)]): int -> List[int] = {
    val anc = anchorsOf(lg)
    Rounds.foldl(Map(), (m, r) =>
      m.put(r, LEADERS.get(r).foldl([], (l, x) => l.append((x + offsetAt(anc, r)) % N))))
  }
  pure def ldr(sch: int -> List[int], s: Slot): int = sch.get(s._1)[s._2]
  pure def slotLt(a: Slot, b: Slot): bool = a._1 < b._1 or (a._1 == b._1 and a._2 < b._2)
  pure def succ(s: Slot): Slot = if (s._2 + 1 == SLOTS) (s._1 + 1, 0) else (s._1, s._2 + 1)
  pure def imax(a: int, b: int): int = if (a > b) a else b
  pure def toSet(l: List[VId]): Set[VId] = l.foldl(Set(), (s, x) => s.union(Set(x)))

  // ---------------------------------------------------------------------
  // State.
  // ---------------------------------------------------------------------

  // Every vertex built, with its strong references.
  var created: VId -> Set[VId]
  // Each vertex's weak references (WEAK).
  var weak: VId -> Set[VId]
  // The slots whose proposal each honest validator echoed, kept across
  // restarts.
  var echoed: int -> Set[(int, int)]
  // Which version of (round, author) reliable broadcast delivers.
  var canon: (int, int) -> int
  // Delivered vertices, per honest validator.
  var view: int -> Set[VId]
  // First proposal's references, per honest validator and (round, author).
  var fp: int -> ((int, int) -> Set[VId])
  // Last round each honest validator proposed in (-1: none).
  var proposed: int -> int
  // Decided slots, in order, per honest validator.
  var log: int -> List[(Slot, Decision)]
  // Released vertices, in order, per honest validator.
  var ordered: int -> List[VId]
  // First slot not yet decided, per honest validator.
  var nextSlot: int -> Slot
  // What the last step did.
  var lastStep: Step
  // The leader table, for trace readers.
  var leaders: int -> List[int]
  // The longest released sequence handed to execution, per honest validator;
  // kept across restarts.
  var executed: int -> List[VId]
  // Restarts so far.
  var restarts: int

  // ---------------------------------------------------------------------
  // The commit rule, as a function of one validator's state.
  // ---------------------------------------------------------------------

  pure def vertexAt(view: Set[VId], r: int, a: int): Set[VId] =
    view.filter(v => v.round == r and v.author == a)

  // Whether `from` reaches `to` through strong references.
  pure def reach(created: VId -> Set[VId], src: VId, dst: VId): bool =
    if (src.round < dst.round) false
    else {
      val frontier = Rounds.foldl(Set(src), (fr, j) =>
        if (j < src.round - dst.round) fr.map(x => created.get(x)).flatten() else fr)
      frontier.contains(dst)
    }

  // Every vertex `v` reaches through references, `v` included.
  pure def ancestors(created: VId -> Set[VId], v: VId): Set[VId] =
    Rounds.foldl((Set(v), Set(v)), (st, j) => {
      val nxt = st._2.map(x => created.get(x)).flatten()
      (st._1.union(nxt), nxt)
    })._1

  // A set holding at most one vertex per (round, author), by round then author.
  pure def sorted(s: Set[VId]): List[VId] =
    Rounds.foldl([], (acc, r) => Authors.foldl(acc, (acc2, a) =>
      s.filter(x => x.round == r and x.author == a).fold(acc2, (l, x) => l.append(x))))

  pure def direct(created: VId -> Set[VId], view: Set[VId], fpi: (int, int) -> Set[VId], sch: int -> List[int], s: Slot): Decision = {
    val r = s._1
    val l = ldr(sch, s)
    val nextRound = view.filter(v => v.round == r + 1)
    val deliveredAuthors = nextRound.map(v => v.author)
    val supportDelivered = nextRound.filter(v => created.get(v).exists(x => x.author == l)).size()
    val supportProposed = fpi.keys().filter(k =>
      k._1 == r + 1 and not(deliveredAuthors.contains(k._2))
        and fpi.get(k).exists(x => x.round == r and x.author == l)).size()
    val blame = nextRound.filter(v => not(created.get(v).exists(x => x.author == l))).size()
    val lv = vertexAt(view, r, l)
    if (supportDelivered + supportProposed >= Q)
      lv.fold(Undecided, (d, x) => Commit(x))
    else if (blame >= N) Skip
    else Undecided
  }

  pure def indirect(created: VId -> Set[VId], view: Set[VId], sch: int -> List[int], s: Slot, later: Slot -> Decision): Decision = {
    val lv = vertexAt(view, s._1, ldr(sch, s))
    val res = AllSlots.foldl((false, Undecided), (st, t) =>
      if (st._1 or t._1 < s._1 + 2 or not(later.keys().contains(t))) st
      else match later.get(t) {
        | Skip => st
        | Undecided => (true, Undecided)
        | Commit(anchor) =>
          (true, lv.fold(Skip, (d, x) => if (reach(created, anchor, x)) Commit(x) else Skip))
      })
    res._2
  }

  // Decisions of the slots from `next` up to the last round with a next
  // round, decided from the highest down.
  pure def decisions(created: VId -> Set[VId], view: Set[VId], fpi: (int, int) -> Set[VId], sch: int -> List[int], from: Slot): Slot -> Decision = {
    val top = fpi.keys().map(k => k._1).union(view.map(v => v.round)).fold(-1, (m, r) => imax(m, r))
    val hi = top - 1
    val desc = AllSlots.foldl([], (acc, t) => [t].concat(acc))
    desc.foldl(Map(), (m, t) =>
      if (t._1 > hi or slotLt(t, from)) m
      else {
        val d = match direct(created, view, fpi, sch, t) {
          | Undecided => indirect(created, view, sch, t, m)
          | Commit(x) => Commit(x)
          | Skip => Skip
        }
        m.put(t, d)
      })
  }

  // The decided slots from `next` up to the first undecided one.
  pure def decidedPrefix(created: VId -> Set[VId], view: Set[VId], fpi: (int, int) -> Set[VId], sch: int -> List[int], from: Slot): List[(Slot, Decision)] = {
    val ds = decisions(created, view, fpi, sch, from)
    AllSlots.foldl((false, []), (st, t) =>
      if (st._1 or not(ds.keys().contains(t))) st
      else match ds.get(t) {
        | Undecided => (true, st._2)
        | Commit(x) => (false, st._2.append((t, Commit(x))))
        | Skip => (false, st._2.append((t, Skip)))
      })._2
  }

  // With REDRAW, the decided slots up to and including the first commit: the
  // checkpoint it takes may redraw the leaders of the slots after it.
  pure def untilCheckpoint(prefix: List[(Slot, Decision)]): List[(Slot, Decision)] =
    if (not(REDRAW)) prefix
    else prefix.foldl((false, []), (st, e) =>
      if (st._1) st
      else match e._2 {
        | Commit(x) => (true, st._2.append(e))
        | Skip => (false, st._2.append(e))
        | Undecided => st
      })._2

  // Vertices released by committing `prefix` after `done`.
  pure def release(created: VId -> Set[VId], done: List[VId], prefix: List[(Slot, Decision)]): List[VId] =
    prefix.foldl(done, (ord, sd) => match sd._2 {
      | Commit(a) => ord.concat(sorted(ancestors(created, a).exclude(toSet(ord))))
      | Skip => ord
      | Undecided => ord
    })

  // Strong and weak references of every vertex.
  pure def linked(created: VId -> Set[VId], weak: VId -> Set[VId]): VId -> Set[VId] =
    created.keys().mapBy(k => if (weak.keys().contains(k)) created.get(k).union(weak.get(k)) else created.get(k))

  // The weak references of a round-`r` vertex with strong references
  // `prev`, by a validator holding `vi` that released `ord`: the vertices
  // below round r - 1 it holds that are neither reached from `prev` through
  // vertices it has not released, nor released.
  pure def orphans(lk: VId -> Set[VId], vi: Set[VId], ord: Set[VId], prev: Set[VId], r: int): Set[VId] =
    if (not(WEAK) or r < 2) Set()
    else {
      val reachable = Rounds.foldl((prev, prev), (st, j) => {
        val nxt = st._2.map(x => lk.get(x)).flatten().filter(y => not(ord.contains(y)))
        (st._1.union(nxt), nxt)
      })._1
      vi.filter(v => v.round < r - 1 and not(reachable.contains(v)) and not(ord.contains(v)))
    }

  // What a validator decides and releases when it decides as soon as it
  // can (`Core::try_commit`): its decided prefix, again after every
  // checkpoint, until nothing more is decided.
  pure def settle(created: VId -> Set[VId], lk: VId -> Set[VId], vi: Set[VId], fpi: (int, int) -> Set[VId],
                  lg: List[(Slot, Decision)], ord: List[VId], nxt: Slot): (List[(Slot, Decision)], List[VId], Slot) = {
    val res = AllSlots.foldl((lg, ord, nxt, false), (st, t) =>
      if (st._4) st
      else {
        val prefix = untilCheckpoint(decidedPrefix(created, vi, fpi, schedule(st._1), st._3))
        if (prefix.length() == 0) (st._1, st._2, st._3, true)
        else (st._1.concat(prefix), release(lk, st._2, prefix), succ(prefix[prefix.length() - 1]._1), false)
      })
    (res._1, res._2, res._3)
  }

  // Whether a validator holding `vi` holds what leaving round `r` needs:
  // the round's leaders, or every vertex of the round while those leaders
  // may still be redrawn (Core::enter_after).
  pure def leftHeld(vi: Set[VId], sch: int -> List[int], nxt: Slot, r: int): bool = {
    val at = vi.filter(v => v.round == r).map(v => v.author)
    if (r <= nxt._1 + LOOKAHEAD) SlotIdx.foldl(true, (ok, k) => ok and at.contains(ldr(sch, (r, k))))
    else at.size() == N
  }

  // The round validator `i`, which last proposed round `cur`, jumps to
  // (`Core::try_advance`), with `top` the highest round above `cur` it holds
  // a quorum of: `top` itself when `i` leads a slot of it and holds what
  // leaving the round before needs, so its own leader vertex is not left
  // out; otherwise the round after `top`, once it holds what leaving `top`
  // needs. -1 when it does not jump.
  pure def catchUpRound(i: int, vi: Set[VId], lg: List[(Slot, Decision)], nxt: Slot, cur: int): int = {
    val sch = schedule(lg)
    val top = vi.map(v => v.round).filter(t =>
      t > cur and t <= MAX_ROUND and vi.filter(v => v.round == t).size() >= Q).fold(-1, (m, t) => imax(m, t))
    if (cur < 0 or top < 0) -1
    else if (SlotIdx.foldl(false, (l, k) => l or ldr(sch, (top, k)) == i) and leftHeld(vi, sch, nxt, top - 1)) top
    else if (leftHeld(vi, sch, nxt, top)) top + 1
    else -1
  }

  // ---------------------------------------------------------------------
  // Steps.
  // ---------------------------------------------------------------------

  action init = all {
    created' = Map(),
    weak' = Map(),
    echoed' = Honest.mapBy(i => Set()),
    canon' = Map(),
    view' = Honest.mapBy(i => Set()),
    fp' = Honest.mapBy(i => Map()),
    proposed' = Honest.mapBy(i => -1),
    log' = Honest.mapBy(i => []),
    ordered' = Honest.mapBy(i => []),
    nextSlot' = Honest.mapBy(i => (0, 0)),
    lastStep' = Init,
    leaders' = LEADERS,
    executed' = Honest.mapBy(i => []),
    restarts' = 0,
  }

  // An honest validator leaves its round and proposes the next, referencing
  // every vertex of its round it holds. It judges the round's leaders by its
  // own schedule only once no slot it has still to decide can redraw them
  // (round <= its first undecided round + LOOKAHEAD, Core::enter_after);
  // otherwise it waits, as for a missing leader, until every honest vertex
  // of the round has arrived, which synchrony bounds.
  action propose(a: int): bool = {
    val r = proposed.get(a) + 1
    val prev = view.get(a).filter(v => v.round == r - 1)
    val id = { round: r, author: a, ver: 0 }
    val sch = schedule(log.get(a))
    val leadersHeld = SlotIdx.foldl(true, (ok, k) =>
      ok and (Byz.contains(ldr(sch, (r - 1, k))) or prev.exists(v => v.author == ldr(sch, (r - 1, k)))))
    val settled = r - 1 <= nextSlot.get(a)._1 + LOOKAHEAD
    val honestHeld = Honest.forall(h => prev.exists(v => v.author == h))
    all {
      r <= MAX_ROUND,
      r == 0 or prev.size() >= Q,
      not(SYNC) or r == 0 or (if (settled) leadersHeld else honestHeld),
      // With EAGER the core progresses on its next input, before anything
      // else reaches it.
      val l = fixpoint(a, view.get(a), localOf(a, created.put(id, prev),
        weak.put(id, orphans(linked(created, weak), view.get(a), toSet(ordered.get(a)), prev, r)),
        fp.get(a).put((r, a), prev), log.get(a), ordered.get(a), nextSlot.get(a), r))
      all {
        created' = l.created, weak' = l.weak, fp' = fp.set(a, l.fp), proposed' = proposed.set(a, l.proposed),
        log' = log.set(a, l.log), ordered' = ordered.set(a, l.ordered), nextSlot' = nextSlot.set(a, l.next),
        executed' = executed.set(a, if (l.ordered.length() > executed.get(a).length()) l.ordered else executed.get(a)),
      },
      echoed' = echoed,
      canon' = canon, view' = view,
      lastStep' = Propose(id),
      leaders' = leaders,
      restarts' = restarts,
    }
  }

  // A Byzantine validator builds a vertex for a round: any references to
  // distinct authors of the round before carrying a quorum.
  action build(a: int, r: int, ver: int, refs: Set[VId]): bool = {
    val id = { round: r, author: a, ver: ver }
    all {
      not(created.keys().contains(id)),
      refs.forall(x => x.round == r - 1 and created.keys().contains(x)),
      refs.map(x => x.author).size() == refs.size(),
      r == 0 or refs.size() >= Q,
      r > 0 or refs == Set(),
      created' = created.put(id, refs),
      weak' = weak.put(id, Set()),
      echoed' = echoed,
      canon' = canon, view' = view, fp' = fp, proposed' = proposed, log' = log,
      ordered' = ordered, nextSlot' = nextSlot,
      lastStep' = Build(id),
      leaders' = leaders,
      executed' = executed, restarts' = restarts,
    }
  }

  type Local = {
    created: VId -> Set[VId], weak: VId -> Set[VId], fp: (int, int) -> Set[VId],
    log: List[(Slot, Decision)], ordered: List[VId], next: Slot, proposed: int
  }

  // One `Core::progress` of validator `i` holding `vi`: it decides what it
  // can, then catches up, proposing the round it jumps to, if any.
  pure def progress(i: int, vi: Set[VId], l: Local): Local = {
    val s = settle(l.created, linked(l.created, l.weak), vi, l.fp, l.log, l.ordered, l.next)
    val up = catchUpRound(i, vi, s._1, s._3, l.proposed)
    val id = { round: up, author: i, ver: 0 }
    val prev = vi.filter(x => x.round == up - 1)
    if (up < 0) { ...l, log: s._1, ordered: s._2, next: s._3 }
    else {
      created: l.created.put(id, prev),
      weak: l.weak.put(id, orphans(linked(l.created, l.weak), vi, toSet(s._2), prev, up)),
      fp: l.fp.put((up, i), prev),
      log: s._1, ordered: s._2, next: s._3, proposed: up,
    }
  }

  // `Core::progress` until nothing changes: deciding can follow a catch-up
  // proposal (its first proposal counts), and a catch-up can follow a
  // decision; three rounds reach the fixed point.
  pure def fixpoint(i: int, vi: Set[VId], l: Local): Local =
    if (EAGER) progress(i, vi, progress(i, vi, progress(i, vi, l))) else l

  pure def localOf(i: int, created: VId -> Set[VId], weak: VId -> Set[VId], fpi: (int, int) -> Set[VId],
                   lg: List[(Slot, Decision)], ord: List[VId], nxt: Slot, prop: int): Local =
    { created: created, weak: weak, fp: fpi, log: lg, ordered: ord, next: nxt, proposed: prop }

  // Validator `i` now holds the delivered vertices `vi` and first proposals
  // `fpi`, and has echoed `ech`. With EAGER it progresses (decides and
  // catches up) until nothing changes, as the core does on every input.
  action react(i: int, vi: Set[VId], fpi: (int, int) -> Set[VId], ech: Set[(int, int)]): bool = {
    val l = fixpoint(i, vi, localOf(i, created, weak, fpi, log.get(i), ordered.get(i), nextSlot.get(i), proposed.get(i)))
    all {
      view' = view.set(i, vi),
      created' = l.created,
      weak' = l.weak,
      fp' = fp.set(i, l.fp),
      log' = log.set(i, l.log),
      ordered' = ordered.set(i, l.ordered),
      nextSlot' = nextSlot.set(i, l.next),
      proposed' = proposed.set(i, l.proposed),
      executed' = executed.set(i, if (l.ordered.length() > executed.get(i).length()) l.ordered else executed.get(i)),
      echoed' = echoed.set(i, ech),
    }
  }

  // Honest validator `i` receives `v` as the first proposal of its slot.
  action first(i: int, v: VId): bool = {
    val key = (v.round, v.author)
    val ignored = RESTORE_ECHO and echoed.get(i).contains(key)
    all {
    v.author != i,
    not(fp.get(i).keys().contains(key)),
    if (ignored) react(i, view.get(i), fp.get(i), echoed.get(i))
    else react(i, view.get(i), fp.get(i).put(key, created.get(v)), echoed.get(i).union(Set(key))),
    canon' = canon,
    lastStep' = First((i, v)),
    leaders' = leaders,
    restarts' = restarts,
    }
  }

  // Honest validator `i` delivers `v` once it holds everything `v`
  // references. Reliable broadcast delivers one version of a slot only.
  action deliver(i: int, v: VId): bool = {
    val key = (v.round, v.author)
    all {
      not(view.get(i).contains(v)),
      not(canon.keys().contains(key)) or canon.get(key) == v.ver,
      linked(created, weak).get(v).subseteq(view.get(i)),
      canon' = canon.put(key, v.ver),
      react(i, view.get(i).union(Set(v)), fp.get(i), echoed.get(i)),
      lastStep' = Deliver((i, v)),
      leaders' = leaders,
      restarts' = restarts,
    }
  }

  // Honest validator `i` commits or skips its decided slots in order.
  action decide(i: int): bool = {
    val prefix = untilCheckpoint(
      decidedPrefix(created, view.get(i), fp.get(i), schedule(log.get(i)), nextSlot.get(i)))
    val now = release(linked(created, weak), ordered.get(i), prefix)
    all {
      not(EAGER),
      prefix.length() > 0,
      log' = log.set(i, log.get(i).concat(prefix)),
      ordered' = ordered.set(i, now),
      nextSlot' = nextSlot.set(i, succ(prefix[prefix.length() - 1]._1)),
      executed' = executed.set(i, if (now.length() > executed.get(i).length()) now else executed.get(i)),
      created' = created, canon' = canon, view' = view, fp' = fp, proposed' = proposed,
      weak' = weak, echoed' = echoed,
      lastStep' = Decide(i),
      leaders' = leaders,
      restarts' = restarts,
    }
  }

  // Honest validator `i` restarts from its journal: its delivered vertices
  // and its own proposals. First proposals of vertices it had not delivered
  // are lost; it decides again from the first slot. Only a validator that has
  // released something restarts: an earlier restart changes nothing.
  action restart(i: int): bool = {
    val own = fp.get(i).keys().filter(k => k._2 == i)
    val kept = view.get(i).filter(v => v.author != i).fold(
      own.mapBy(k => fp.get(i).get(k)),
      (m, v) => if (m.keys().contains((v.round, v.author))) m else m.put((v.round, v.author), created.get(v)))
    // With EAGER it decides again while it rebuilds (`Core::recover`), then
    // progresses on its next input.
    val s = if (EAGER) settle(created, linked(created, weak), view.get(i), kept, [], [], (0, 0)) else ([], [], (0, 0))
    val l = fixpoint(i, view.get(i), localOf(i, created, weak, kept, s._1, s._2, s._3, proposed.get(i)))
    all {
      restarts < RESTARTS,
      ordered.get(i).length() > 0,
      fp' = fp.set(i, l.fp),
      log' = log.set(i, l.log),
      ordered' = ordered.set(i, l.ordered),
      nextSlot' = nextSlot.set(i, l.next),
      restarts' = restarts + 1,
      created' = l.created, weak' = l.weak, proposed' = proposed.set(i, l.proposed),
      canon' = canon, view' = view, echoed' = echoed,
      executed' = executed.set(i, if (l.ordered.length() > executed.get(i).length()) l.ordered else executed.get(i)),
      lastStep' = Restart(i),
      leaders' = leaders,
    }
  }

  // Honest validator `i` resumes from the checkpoint taken at the `k`-th
  // decided slot of honest validator `j`, a commit `i` has not decided yet.
  action fastForward(i: int, j: int, k: int): bool = {
    val prefix = log.get(j).slice(0, k + 1)
    val slot = log.get(j)[k]._1
    val ord = release(linked(created, weak), [], prefix)
    val l = fixpoint(i, view.get(i), localOf(i, created, weak, fp.get(i), prefix, ord, succ(slot), proposed.get(i)))
    all {
      i != j,
      match log.get(j)[k]._2 { | Commit(_) => true | Skip => false | Undecided => false },
      not(slotLt(slot, nextSlot.get(i))),
      log' = log.set(i, l.log),
      ordered' = ordered.set(i, l.ordered),
      nextSlot' = nextSlot.set(i, l.next),
      fp' = fp.set(i, l.fp),
      created' = l.created, weak' = l.weak, proposed' = proposed.set(i, l.proposed),
      executed' = executed.set(i, if (l.ordered.length() > executed.get(i).length()) l.ordered else executed.get(i)),
      canon' = canon, view' = view, echoed' = echoed, restarts' = restarts,
      lastStep' = FastForward((i, j)),
      leaders' = leaders,
    }
  }

  action step = any {
    nondet a = Honest.oneOf()
    propose(a),
    nondet i = Honest.oneOf()
    decide(i),
    all {
      RESTARTS > 0,
      nondet i = Honest.oneOf()
      restart(i),
    },
    all {
      FAST_FORWARD,
      nondet i = Honest.oneOf()
      nondet j = Honest.oneOf()
      nondet k = 0.to(AllSlots.length() - 1).oneOf()
      all { k < log.get(j).length(), fastForward(i, j, k) },
    },
    all {
      created.keys().size() > 0,
      nondet i = Honest.oneOf()
      nondet v = created.keys().oneOf()
      any { first(i, v), deliver(i, v) },
    },
    all {
      F > 0,
      BYZ_BUILD,
      nondet a = Byz.oneOf()
      nondet r = 0.to(MAX_ROUND).oneOf()
      nondet ver = 0.to(VERSIONS - 1).oneOf()
      nondet refs = created.keys().filter(x => x.round == r - 1).powerset().oneOf()
      build(a, r, ver, refs),
    },
  }

  // A first proposal reaching an honest validator, as in `step`.
  action firstProposal = all {
    created.keys().size() > 0,
    nondet i = Honest.oneOf()
    nondet v = created.keys().oneOf()
    first(i, v),
  }

  // The actions of `step`, with first proposals weighted ahead of delivery,
  // for reaching the rejoin witness (`noRejoin`): a restart then more often
  // finds a decision that counted first proposals of vertices not yet
  // delivered, which the restart loses. Every execution is one of `step`.
  action stepFirstProposals = any { step, firstProposal, firstProposal, firstProposal }

  // The actions of `step` other than restarting.
  action stepWithoutRestart = any {
    nondet a = Honest.oneOf()
    propose(a),
    nondet i = Honest.oneOf()
    decide(i),
    all {
      FAST_FORWARD,
      nondet i = Honest.oneOf()
      nondet j = Honest.oneOf()
      nondet k = 0.to(AllSlots.length() - 1).oneOf()
      all { k < log.get(j).length(), fastForward(i, j, k) },
    },
    all {
      created.keys().size() > 0,
      nondet i = Honest.oneOf()
      nondet v = created.keys().oneOf()
      any { first(i, v), deliver(i, v) },
    },
    all {
      F > 0,
      BYZ_BUILD,
      nondet a = Byz.oneOf()
      nondet r = 0.to(MAX_ROUND).oneOf()
      nondet ver = 0.to(VERSIONS - 1).oneOf()
      nondet refs = created.keys().filter(x => x.round == r - 1).powerset().oneOf()
      build(a, r, ver, refs),
    },
  }

  // A restart of an honest validator that has proposed the last round and
  // holds a first proposal of another validator it has not delivered.
  action lateRestart = all {
    RESTARTS > 0,
    nondet i = Honest.oneOf()
    all {
      proposed.get(i) == MAX_ROUND,
      fp.get(i).keys().exists(k => k._2 != i and vertexAt(view.get(i), k._1, k._2) == Set()),
      restart(i),
    },
  }

  // The actions of `step`, for reaching the rejoin witness (`noRejoin`) in
  // c7quorum: there a restart releases less than it executed only when it
  // loses first proposals of the last round that a release counted, so a
  // validator restarts only once it has proposed the last round and holds a
  // first proposal it has not delivered, and first proposals are weighted
  // ahead of delivery. Every execution is one of `step`.
  action stepLateRestart = any { stepWithoutRestart, firstProposal, firstProposal, lateRestart }

  // ---------------------------------------------------------------------
  // Properties.
  // ---------------------------------------------------------------------

  pure def isPrefix(a: List[t], b: List[t]): bool =
    a.length() <= b.length() and a.indices().forall(j => a[j] == b[j])

  val agreement: bool = Honest.forall(i => Honest.forall(j =>
    (isPrefix(log.get(i), log.get(j)) or isPrefix(log.get(j), log.get(i)))
    and (isPrefix(ordered.get(i), ordered.get(j)) or isPrefix(ordered.get(j), ordered.get(i)))))

  val noReorder: bool = Honest.forall(i =>
    toSet(ordered.get(i)).size() == ordered.get(i).length())

  // Nothing more can happen for the honest validators: each proposed its
  // last round, holds every vertex reliable broadcast delivered and every
  // honest vertex, and has nothing left to decide.
  val quiescent: bool = Honest.forall(i => and {
    // A validator that caught up may have proposed the round after.
    proposed.get(i) >= MAX_ROUND,
    created.keys().forall(v =>
      (Honest.contains(v.author) or (canon.keys().contains((v.round, v.author))
        and canon.get((v.round, v.author)) == v.ver)) implies view.get(i).contains(v)),
    decidedPrefix(created, view.get(i), fp.get(i), schedule(log.get(i)), nextSlot.get(i)).length() == 0,
  })

  pure def liveUpTo(lg: List[(Slot, Decision)], top: int): bool = {
    val sch = schedule(lg)
    AllSlots.select(s => s._1 <= top).foldl(true, (ok, s) =>
      ok and lg.foldl(false, (found, e) =>
        found or (e._1 == s and (Byz.contains(ldr(sch, s)) or e._2 != Skip))))
  }

  val liveCommit: bool = (SYNC and quiescent) implies Honest.forall(i =>
    liveUpTo(log.get(i), MAX_ROUND - 1))

  val liveCommitEarly: bool = (SYNC and quiescent) implies Honest.forall(i =>
    liveUpTo(log.get(i), MAX_ROUND - 4))

  val rejoinConsistent: bool = Honest.forall(i =>
    isPrefix(ordered.get(i), executed.get(i)) or isPrefix(executed.get(i), ordered.get(i)))

  val executedAgreement: bool = Honest.forall(i => Honest.forall(j =>
    isPrefix(executed.get(i), executed.get(j)) or isPrefix(executed.get(j), executed.get(i))))

  val safety: bool = agreement and noReorder and rejoinConsistent and executedAgreement

  // With SYNC no honest validator skips the slot of an honest leader, at
  // any point of an execution (not only once it is quiescent).
  val noHonestSkip: bool = SYNC implies Honest.forall(i => log.get(i).foldl(true, (ok, e) =>
    ok and (e._2 != Skip or Byz.contains(ldr(schedule(log.get(i)), e._1)))))

  // Witnesses: violated when the state is reachable.
  val noQuiescence: bool = not(quiescent)
  val noSkip: bool = Honest.forall(i => log.get(i).foldl(true, (ok, e) => ok and e._2 != Skip))
  val noRedraw: bool = Honest.forall(i => schedule(log.get(i)) == LEADERS)
  val noFastForward: bool = match lastStep { | FastForward(_) => false | _ => true }
  val noRejoin: bool = not(restarts > 0 and Honest.exists(i =>
    ordered.get(i).length() > 0 and ordered.get(i).length() < executed.get(i).length()))
}

// n = 4, f = 1. Byzantine validators lead only second slots and only up to
// round MAX_ROUND - 3, so with SYNC every slot has a decision by the end.
module n4 {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 5, SLOTS = 2, VERSIONS = 2, SYNC = false, REDRAW = false, LOOKAHEAD = 0, RESTARTS = 0, EAGER = false, BYZ_BUILD = true, WEAK = false, RESTORE_ECHO = false, FAST_FORWARD = false,
    LEADERS = Map(0 -> [0, 3], 1 -> [1, 2], 2 -> [2, 3], 3 -> [0, 1], 4 -> [1, 0], 5 -> [2, 1])
  ).*
}

module n4sync {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 5, SLOTS = 2, VERSIONS = 2, SYNC = true, REDRAW = false, LOOKAHEAD = 0, RESTARTS = 0, EAGER = false, BYZ_BUILD = true, WEAK = false, RESTORE_ECHO = false, FAST_FORWARD = false,
    LEADERS = Map(0 -> [0, 3], 1 -> [1, 2], 2 -> [2, 3], 3 -> [0, 1], 4 -> [1, 0], 5 -> [2, 1])
  ).*
}

// n = 4, f = 1 with a Byzantine first slot, for safety only.
module n4byzfirst {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 5, SLOTS = 2, VERSIONS = 2, SYNC = false, REDRAW = false, LOOKAHEAD = 0, RESTARTS = 0, EAGER = false, BYZ_BUILD = true, WEAK = false, RESTORE_ECHO = false, FAST_FORWARD = false,
    LEADERS = Map(0 -> [3, 0], 1 -> [3, 1], 2 -> [3, 2], 3 -> [0, 3], 4 -> [3, 1], 5 -> [2, 3])
  ).*
}

// n = 7, f = 2.
module n7 {
  import commit_rule(
    N = 7, F = 2, MAX_ROUND = 5, SLOTS = 2, VERSIONS = 2, SYNC = false, REDRAW = false, LOOKAHEAD = 0, RESTARTS = 0, EAGER = false, BYZ_BUILD = true, WEAK = false, RESTORE_ECHO = false, FAST_FORWARD = false,
    LEADERS = Map(0 -> [0, 5], 1 -> [1, 6], 2 -> [2, 5], 3 -> [3, 4], 4 -> [4, 0], 5 -> [1, 2])
  ).*
}

module n7sync {
  import commit_rule(
    N = 7, F = 2, MAX_ROUND = 5, SLOTS = 2, VERSIONS = 2, SYNC = true, REDRAW = false, LOOKAHEAD = 0, RESTARTS = 0, EAGER = false, BYZ_BUILD = true, WEAK = false, RESTORE_ECHO = false, FAST_FORWARD = false,
    LEADERS = Map(0 -> [0, 5], 1 -> [1, 6], 2 -> [2, 5], 3 -> [3, 4], 4 -> [4, 0], 5 -> [1, 2])
  ).*
}

// n = 4, f = 1 over four rounds, for the symbolic model checker.
module n4small {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 3, SLOTS = 2, VERSIONS = 2, SYNC = false, REDRAW = false, LOOKAHEAD = 0, RESTARTS = 0, EAGER = false, BYZ_BUILD = true, WEAK = false, RESTORE_ECHO = false, FAST_FORWARD = false,
    LEADERS = Map(0 -> [3, 0], 1 -> [1, 3], 2 -> [2, 0], 3 -> [0, 1])
  ).*
}

// The core's leader schedule for its test committees (seed 0x5e..5e, two
// slots), so executions of these instances replay through the core.
module replay4 {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 5, SLOTS = 2, VERSIONS = 2, SYNC = false, REDRAW = false, LOOKAHEAD = 0, RESTARTS = 0, EAGER = false, BYZ_BUILD = true, WEAK = false, RESTORE_ECHO = false, FAST_FORWARD = false,
    LEADERS = Map(0 -> [3, 2], 1 -> [0, 1], 2 -> [2, 0], 3 -> [1, 3], 4 -> [3, 1], 5 -> [2, 0])
  ).*
}

module replay7 {
  import commit_rule(
    N = 7, F = 2, MAX_ROUND = 5, SLOTS = 2, VERSIONS = 2, SYNC = false, REDRAW = false, LOOKAHEAD = 0, RESTARTS = 0, EAGER = false, BYZ_BUILD = true, WEAK = false, RESTORE_ECHO = false, FAST_FORWARD = false,
    LEADERS = Map(0 -> [6, 2], 1 -> [1, 0], 2 -> [3, 4], 3 -> [5, 6], 4 -> [1, 5], 5 -> [4, 3])
  ).*
}

// Leaders redrawn at every commit, restarts of honest validators. n = 4,
// f = 1 over seven rounds; LOOKAHEAD 0 and 1 (the core uses 4; the property
// does not depend on it, and a short one lets redraws matter within seven
// rounds).
module n4rejoin {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 6, SLOTS = 2, VERSIONS = 2, SYNC = false,
    REDRAW = true, LOOKAHEAD = 1, RESTARTS = 2, EAGER = false, BYZ_BUILD = true, WEAK = false, RESTORE_ECHO = false, FAST_FORWARD = false,
    LEADERS = Map(0 -> [0, 3], 1 -> [1, 2], 2 -> [2, 3], 3 -> [0, 1], 4 -> [1, 0], 5 -> [2, 1], 6 -> [3, 0])
  ).*
}

module n4rejoin0 {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 6, SLOTS = 2, VERSIONS = 2, SYNC = false,
    REDRAW = true, LOOKAHEAD = 0, RESTARTS = 2, EAGER = false, BYZ_BUILD = true, WEAK = false, RESTORE_ECHO = false, FAST_FORWARD = false,
    LEADERS = Map(0 -> [3, 0], 1 -> [3, 1], 2 -> [3, 2], 3 -> [0, 3], 4 -> [3, 1], 5 -> [2, 3], 6 -> [1, 3])
  ).*
}

// With SYNC and the core's lookahead of 4 rounds.
module n4rejoinsync4 {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 9, SLOTS = 2, VERSIONS = 2, SYNC = true,
    REDRAW = true, LOOKAHEAD = 4, RESTARTS = 1, EAGER = false, BYZ_BUILD = true, WEAK = false, RESTORE_ECHO = false, FAST_FORWARD = false,
    LEADERS = Map(0 -> [0, 3], 1 -> [1, 2], 2 -> [2, 3], 3 -> [0, 1], 4 -> [1, 0], 5 -> [2, 1], 6 -> [3, 0], 7 -> [0, 2],
      8 -> [1, 3], 9 -> [2, 0])
  ).*
}

// With SYNC and a lookahead of 1 round: shorter than the commit depth. A
// validator behind on its decisions does not judge leaders it may yet see
// redrawn, so no honest leader's slot is skipped.
module n4rejoinsync {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 7, SLOTS = 2, VERSIONS = 2, SYNC = true,
    REDRAW = true, LOOKAHEAD = 1, RESTARTS = 1, EAGER = false, BYZ_BUILD = true, WEAK = false, RESTORE_ECHO = false, FAST_FORWARD = false,
    LEADERS = Map(0 -> [0, 3], 1 -> [1, 2], 2 -> [2, 3], 3 -> [0, 1], 4 -> [1, 0], 5 -> [2, 1], 6 -> [3, 0], 7 -> [0, 2])
  ).*
}

// n = 7, f = 2.
module n7rejoin {
  import commit_rule(
    N = 7, F = 2, MAX_ROUND = 6, SLOTS = 2, VERSIONS = 2, SYNC = false,
    REDRAW = true, LOOKAHEAD = 1, RESTARTS = 2, EAGER = false, BYZ_BUILD = true, WEAK = false, RESTORE_ECHO = false, FAST_FORWARD = false,
    LEADERS = Map(0 -> [0, 5], 1 -> [1, 6], 2 -> [2, 5], 3 -> [3, 4], 4 -> [4, 0], 5 -> [1, 2], 6 -> [6, 3])
  ).*
}

// Conformance instances: executions of these replay step by step through the
// core (src/core/conformance.rs). They decide eagerly and catch up as the
// core does, use the core's leader table for the replay committee (epoch 0,
// genesis start, two slots) and its lookahead of 4 rounds, and draw no new
// leaders (the replay takes no checkpoint).
module c4 {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 7, SLOTS = 2, VERSIONS = 2, SYNC = false, REDRAW = false, LOOKAHEAD = 4, RESTARTS = 0,
    EAGER = true, BYZ_BUILD = true, WEAK = true, RESTORE_ECHO = true, FAST_FORWARD = false,
    LEADERS = Map(0 -> [3, 2], 1 -> [0, 1], 2 -> [2, 0], 3 -> [1, 3], 4 -> [3, 1], 5 -> [2, 0], 6 -> [2, 3], 7 -> [1, 0])
  ).*
}

module c4sync {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 7, SLOTS = 2, VERSIONS = 2, SYNC = true, REDRAW = false, LOOKAHEAD = 4, RESTARTS = 0,
    EAGER = true, BYZ_BUILD = true, WEAK = true, RESTORE_ECHO = true, FAST_FORWARD = false,
    LEADERS = Map(0 -> [3, 2], 1 -> [0, 1], 2 -> [2, 0], 3 -> [1, 3], 4 -> [3, 1], 5 -> [2, 0], 6 -> [2, 3], 7 -> [1, 0])
  ).*
}

// Restarts of honest validators (`Core::recover`).
module c4rejoin {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 7, SLOTS = 2, VERSIONS = 2, SYNC = false, REDRAW = false, LOOKAHEAD = 4, RESTARTS = 2,
    EAGER = true, BYZ_BUILD = true, WEAK = true, RESTORE_ECHO = true, FAST_FORWARD = false,
    LEADERS = Map(0 -> [3, 2], 1 -> [0, 1], 2 -> [2, 0], 3 -> [1, 3], 4 -> [3, 1], 5 -> [2, 0], 6 -> [2, 3], 7 -> [1, 0])
  ).*
}

// Exactly a quorum: the Byzantine validator is silent; honest validators
// restart and rejoin.
module c4quorum {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 7, SLOTS = 2, VERSIONS = 2, SYNC = false, REDRAW = false, LOOKAHEAD = 4, RESTARTS = 2,
    EAGER = true, BYZ_BUILD = false, WEAK = true, RESTORE_ECHO = true, FAST_FORWARD = false,
    LEADERS = Map(0 -> [3, 2], 1 -> [0, 1], 2 -> [2, 0], 3 -> [1, 3], 4 -> [3, 1], 5 -> [2, 0], 6 -> [2, 3], 7 -> [1, 0])
  ).*
}

module c4quorumsync {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 7, SLOTS = 2, VERSIONS = 2, SYNC = true, REDRAW = false, LOOKAHEAD = 4, RESTARTS = 1,
    EAGER = true, BYZ_BUILD = false, WEAK = true, RESTORE_ECHO = true, FAST_FORWARD = false,
    LEADERS = Map(0 -> [3, 2], 1 -> [0, 1], 2 -> [2, 0], 3 -> [1, 3], 4 -> [3, 1], 5 -> [2, 0], 6 -> [2, 3], 7 -> [1, 0])
  ).*
}

module c7 {
  import commit_rule(
    N = 7, F = 2, MAX_ROUND = 6, SLOTS = 2, VERSIONS = 2, SYNC = false, REDRAW = false, LOOKAHEAD = 4, RESTARTS = 1,
    EAGER = true, BYZ_BUILD = true, WEAK = true, RESTORE_ECHO = true, FAST_FORWARD = false,
    LEADERS = Map(0 -> [6, 2], 1 -> [1, 0], 2 -> [3, 4], 3 -> [5, 6], 4 -> [1, 5], 5 -> [4, 3], 6 -> [0, 2])
  ).*
}

// n = 7 with the two Byzantine validators silent: five up, exactly a quorum,
// as in the simulator's exact-quorum profile.
module c7quorum {
  import commit_rule(
    N = 7, F = 2, MAX_ROUND = 6, SLOTS = 2, VERSIONS = 2, SYNC = false, REDRAW = false, LOOKAHEAD = 4, RESTARTS = 2,
    EAGER = true, BYZ_BUILD = false, WEAK = true, RESTORE_ECHO = true, FAST_FORWARD = false,
    LEADERS = Map(0 -> [6, 2], 1 -> [1, 0], 2 -> [3, 4], 3 -> [5, 6], 4 -> [1, 5], 5 -> [4, 3], 6 -> [0, 2])
  ).*
}

// Validators resume from a checkpoint another decided, with leader redraws,
// restarts and weak references, deciding at any time (n = 4) or as soon as
// they can (n = 4 and n = 7): safety only.
module n4ff {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 6, SLOTS = 2, VERSIONS = 2, SYNC = false,
    REDRAW = true, LOOKAHEAD = 1, RESTARTS = 1, EAGER = false, BYZ_BUILD = true, WEAK = true, RESTORE_ECHO = true,
    FAST_FORWARD = true,
    LEADERS = Map(0 -> [0, 3], 1 -> [1, 2], 2 -> [2, 3], 3 -> [0, 1], 4 -> [1, 0], 5 -> [2, 1], 6 -> [3, 0])
  ).*
}

module c4ff {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 7, SLOTS = 2, VERSIONS = 2, SYNC = false, REDRAW = false, LOOKAHEAD = 4, RESTARTS = 1,
    EAGER = true, BYZ_BUILD = true, WEAK = true, RESTORE_ECHO = true, FAST_FORWARD = true,
    LEADERS = Map(0 -> [3, 2], 1 -> [0, 1], 2 -> [2, 0], 3 -> [1, 3], 4 -> [3, 1], 5 -> [2, 0], 6 -> [2, 3], 7 -> [1, 0])
  ).*
}

module c4ffsync {
  import commit_rule(
    N = 4, F = 1, MAX_ROUND = 7, SLOTS = 2, VERSIONS = 2, SYNC = true, REDRAW = false, LOOKAHEAD = 4, RESTARTS = 1,
    EAGER = true, BYZ_BUILD = false, WEAK = true, RESTORE_ECHO = true, FAST_FORWARD = true,
    LEADERS = Map(0 -> [3, 2], 1 -> [0, 1], 2 -> [2, 0], 3 -> [1, 3], 4 -> [3, 1], 5 -> [2, 0], 6 -> [2, 3], 7 -> [1, 0])
  ).*
}

