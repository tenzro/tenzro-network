// -*- mode: Bluespec; -*-
//
// Checkpoint votes of Tenzro consensus: what a validator signs
// (`sign_checkpoint` with its vote high-water mark), and how a validator
// collects votes into certificates and catches equivocation
// (`Core::on_vote`, `Core::count_vote`, `VoteCollector::add`,
// `Core::on_certified`), in one epoch.
//
// A checkpoint is named by its index and a body. Body 0 of each index is the
// one the honest validators' agreed ordering decides; other bodies exist only
// if someone signs them. Body `b` of index `k` follows body `prevBody(b)` of
// index `k - 1`, so a body determines its whole chain.
//
// Honest validators sign through the high-water mark, which refuses a
// second body for an index and, behind the latest signature, any body not
// consistent with what was signed after it. With HONEST_ANY an honest
// validator may be asked to sign any body (a restart that lost its ordering,
// or a faulty caller); the mark alone must then keep it from equivocating.
// Byzantine validators (the last F) sign anything.
//
// Every signed vote may reach any honest collector, any number of times, in
// any order. A collector:
//   - with VOTE_BOUND, holds no other validator's vote for an index beyond
//     the signing window of the next checkpoint it builds or the latest it
//     holds a certificate for (a faulty member could otherwise make it hold
//     votes for any number of future indices);
//   - holds no vote below its floor;
//   - reports a signer whose vote differs from the one it holds for that
//     index (equivocation evidence), and keeps the first;
//   - certifies an index once a quorum signed one body, keeps the latest
//     KEEP_CERTS certificates, and drops votes PRUNE_LAG indices behind a new
//     certificate.
//
// Invariants:
//   certificateAgreement  two honest collectors never certify different
//                         bodies for one index (without HONEST_ANY);
//   honestNeverEquivocates no honest validator signs two bodies for one
//                         index (with HONEST_ANY too: the mark alone);
//   evidenceIsByzantine   equivocation evidence names Byzantine signers only.
module checkpoint_votes {
  const N: int
  const F: int
  // The checkpoint indices votes are for.
  const INDICES: Set[int]
  // Bodies per index.
  const BODIES: int
  // `SIGNED_VOTE_WINDOW`.
  const WINDOW: int
  // Certificates a collector keeps.
  const KEEP_CERTS: int
  // Votes are dropped this many indices behind a new certificate.
  const PRUNE_LAG: int
  const HONEST_ANY: bool
  const VOTE_BOUND: bool

  type Outcome =
    | None
    | Refused
    | Signed
    | Ignored
    | Held
    | Certified(int)
    | Evidence(int)
  type Step =
    | Init
    | Sign((int, int, int))
    | Receive((int, int, int, int))

  pure val Validators: Set[int] = 0.to(N - 1)
  pure val Byz: Set[int] = (N - F).to(N - 1)
  pure val Honest: Set[int] = Validators.exclude(Byz)
  pure val Q: int = N - (N - 1) / 3
  pure val Bodies: Set[int] = 0.to(BODIES - 1)

  pure def prevBody(b: int): int = b / 2
  pure def imax(a: int, b: int): int = if (a > b) a else b

  // Every signed vote: (signer, index, body).
  var sigs: Set[(int, int, int)]
  // Each honest signer's mark (index, body), (-1, -1) before any, and the
  // bodies it signed within the window of its mark.
  var mark: int -> (int, int)
  var signedAt: int -> (int -> int)
  // Each honest collector's held votes, (index, signer) -> body.
  var held: int -> ((int, int) -> int)
  // Indices a collector certified while their votes are held.
  var certified: int -> Set[int]
  // The certificates a collector keeps, index -> body.
  var certs: int -> (int -> int)
  // The lowest index a collector holds votes for.
  var floor: int -> int
  // Equivocation evidence a collector reported: (signer, index).
  var evidence: int -> Set[(int, int)]
  var lastStep: Step
  var outcome: Outcome

  // What the mark does with a request to sign body `b` of index `k`:
  // 0 refuse, 1 sign as the new mark, 2 sign behind the mark, 3 signed
  // before.
  pure def highWater(m: (int, int), at: int -> int, k: int, b: int): int =
    if (m._1 < 0) 1
    else if (m._1 == k) (if (m._2 == b) 3 else 0)
    else if (m._1 > k) {
      if (m._1 - k >= WINDOW) 0
      else if (at.keys().contains(k)) (if (at.get(k) == b) 3 else 0)
      else if (at.keys().contains(k + 1) and prevBody(at.get(k + 1)) == b) 2
      else 0
    } else 1

  action init = all {
    sigs' = Set(),
    mark' = Honest.mapBy(s => (-1, -1)),
    signedAt' = Honest.mapBy(s => Map()),
    held' = Honest.mapBy(i => Map()),
    certified' = Honest.mapBy(i => Set()),
    certs' = Honest.mapBy(i => Map()),
    floor' = Honest.mapBy(i => 0),
    evidence' = Honest.mapBy(i => Set()),
    lastStep' = Init,
    outcome' = None,
  }

  action signed(s: int, k: int, b: int): bool = all {
    held' = held, certified' = certified, certs' = certs, floor' = floor, evidence' = evidence,
    lastStep' = Sign((s, k, b)),
  }

  // Validator `s` is asked to sign body `b` of index `k`.
  action sign(s: int, k: int, b: int): bool = {
    if (Byz.contains(s)) all {
      sigs' = sigs.union(Set((s, k, b))),
      mark' = mark, signedAt' = signedAt,
      outcome' = Signed,
      signed(s, k, b),
    } else {
      val r = highWater(mark.get(s), signedAt.get(s), k, b)
      all {
        HONEST_ANY or b == 0,
        if (r == 0) all {
          sigs' = sigs, mark' = mark, signedAt' = signedAt, outcome' = Refused,
        } else if (r == 1) all {
          sigs' = sigs.union(Set((s, k, b))),
          mark' = mark.set(s, (k, b)),
          signedAt' = signedAt.set(s, signedAt.get(s).put(k, b).keys()
            .filter(j => j > k - WINDOW).mapBy(j => signedAt.get(s).put(k, b).get(j))),
          outcome' = Signed,
        } else if (r == 2) all {
          sigs' = sigs.union(Set((s, k, b))),
          mark' = mark,
          signedAt' = signedAt.set(s, signedAt.get(s).put(k, b)),
          outcome' = Signed,
        } else all {
          sigs' = sigs, mark' = mark, signedAt' = signedAt, outcome' = Signed,
        },
        signed(s, k, b),
      }
    }
  }

  // The latest certificate kept, or -1.
  pure def topCert(c: int -> int): int = c.keys().fold(-1, (m, j) => imax(m, j))

  action received(i: int, s: int, k: int, b: int): bool = all {
    sigs.contains((s, k, b)),
    lastStep' = Receive((i, s, k, b)),
    sigs' = sigs, mark' = mark, signedAt' = signedAt,
  }

  // Collector `i` receives signer `s`'s vote for body `b` of index `k`.
  action receive(i: int, s: int, k: int, b: int): bool = {
    val h = held.get(i)
    // The next checkpoint this collector builds is index 0: it orders
    // nothing here.
    val reach = imax(0, topCert(certs.get(i)) + 1)
    val tally = h.keys().filter(x => x._1 == k and h.get(x) == b).size() + 1
    // A collector's own vote is counted directly (`Core::on_own_vote`).
    if (VOTE_BOUND and s != i and k > reach + WINDOW) all {
      received(i, s, k, b), outcome' = Ignored,
      held' = held, certified' = certified, certs' = certs, floor' = floor, evidence' = evidence,
    }
    else if (k < floor.get(i)) all {
      received(i, s, k, b), outcome' = Ignored,
      held' = held, certified' = certified, certs' = certs, floor' = floor, evidence' = evidence,
    }
    else if (h.keys().contains((k, s))) all {
      received(i, s, k, b),
      if (h.get((k, s)) == b) all { outcome' = Ignored, evidence' = evidence }
      else all { outcome' = Evidence(s), evidence' = evidence.setBy(i, e => e.union(Set((s, k)))) },
      held' = held, certified' = certified, certs' = certs, floor' = floor,
    }
    else if (certified.get(i).contains(k) or tally < Q) all {
      received(i, s, k, b), outcome' = Held,
      held' = held.set(i, h.put((k, s), b)),
      certified' = certified, certs' = certs, floor' = floor, evidence' = evidence,
    }
    else {
      // A new certificate: kept unless one for the index is (it was then
      // dropped from the held votes' bookkeeping), the oldest beyond
      // KEEP_CERTS dropped, votes PRUNE_LAG behind it dropped.
      val c0 = certs.get(i)
      val c1 = if (c0.keys().contains(k)) c0 else c0.put(k, b)
      val keep = c1.keys().filter(j => c1.keys().filter(x => x > j).size() < KEEP_CERTS)
      val c2 = keep.mapBy(j => c1.get(j))
      val fl = if (c0.keys().contains(k)) floor.get(i) else imax(floor.get(i), k - PRUNE_LAG)
      val h1 = h.put((k, s), b)
      all {
        received(i, s, k, b),
        outcome' = Certified(k),
        held' = held.set(i, h1.keys().filter(x => x._1 >= fl).mapBy(x => h1.get(x))),
        certified' = certified.set(i, certified.get(i).union(Set(k)).filter(j => j >= fl)),
        certs' = certs.set(i, c2),
        floor' = floor.set(i, fl),
        evidence' = evidence,
      }
    }
  }

  action step = any {
    nondet s = Validators.oneOf()
    nondet k = INDICES.oneOf()
    nondet b = Bodies.oneOf()
    sign(s, k, b),
    all {
      sigs.size() > 0,
      nondet i = Honest.oneOf()
      nondet v = sigs.oneOf()
      receive(i, v._1, v._2, v._3),
    },
  }

  val certificateAgreement: bool = Honest.forall(i => Honest.forall(j =>
    certs.get(i).keys().forall(k => certs.get(j).keys().contains(k) implies certs.get(i).get(k) == certs.get(j).get(k))))
  val honestNeverEquivocates: bool = Honest.forall(s =>
    INDICES.forall(k => sigs.filter(v => v._1 == s and v._2 == k).size() <= 1))
  val evidenceIsByzantine: bool = Honest.forall(i => evidence.get(i).forall(e => Byz.contains(e._1)))
  val safety: bool = certificateAgreement and honestNeverEquivocates and evidenceIsByzantine

  // Witnesses: violated when the state is reachable.
  val noCertificate: bool = Honest.forall(i => certs.get(i).keys().size() == 0)
  val noEvidence: bool = Honest.forall(i => evidence.get(i).size() == 0)
  val noRefusal: bool = outcome != Refused
  val noIgnoredFar: bool = not(VOTE_BOUND and outcome == Ignored and match lastStep {
    | Receive(r) => r._3 > WINDOW
    | Sign(_) => false
    | Init => false
  })
}

// n = 4, f = 1. Indices that cross the certificates kept, the vote prune
// lag and the signing window. The core's window is 1024 checkpoints.
module v4 {
  import checkpoint_votes(
    N = 4, F = 1, INDICES = Set(0, 1, 2, 3, 17, 18, 1023, 1024, 1025, 1030), BODIES = 3, WINDOW = 1024,
    KEEP_CERTS = 8, PRUNE_LAG = 16, HONEST_ANY = false, VOTE_BOUND = true
  ).*
}

// Honest validators asked to sign any body: the mark alone.
module v4any {
  import checkpoint_votes(
    N = 4, F = 1, INDICES = Set(0, 1, 2, 3, 17, 18, 1023, 1024, 1025, 1030), BODIES = 3, WINDOW = 1024,
    KEEP_CERTS = 8, PRUNE_LAG = 16, HONEST_ANY = true, VOTE_BOUND = true
  ).*
}

// Many certified indices, to cross the certificates kept.
module v4many {
  import checkpoint_votes(
    N = 4, F = 1, INDICES = 0.to(11), BODIES = 2, WINDOW = 1024,
    KEEP_CERTS = 8, PRUNE_LAG = 16, HONEST_ANY = false, VOTE_BOUND = true
  ).*
}

module v7 {
  import checkpoint_votes(
    N = 7, F = 2, INDICES = Set(0, 1, 2, 17, 1024, 1025), BODIES = 3, WINDOW = 1024,
    KEEP_CERTS = 8, PRUNE_LAG = 16, HONEST_ANY = false, VOTE_BOUND = true
  ).*
}
