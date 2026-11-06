// -*- mode: Bluespec; -*-
//
// Validator set membership and availability of Tenzro consensus: who is in the
// set, who is up, when the set can certify, and what the rules around the set
// do to that.
//
// Rules modelled (all from the repository):
//   - certification needs live stake above two thirds of the counted stake
//     (`launch_check::above_two_thirds`); counted = Active or PendingExit;
//   - a halted chain cannot repair itself: ejection, replacement bonding and
//     slashing are transactions, so they need a block, and the missed-epoch
//     counter is derived from certified data and does not move while the
//     chain is halted;
//   - `ValidatorRegistry::eject_inactive`: at an epoch boundary, validators
//     whose committed missed-epoch count reached LIMIT leave, longest-absent
//     first and ties by id, never leaving fewer than FLOOR counted
//     validators (`staking.active_set_floor`, a count, not stake);
//   - `launch_check::check_launch_set` (n >= 4, live stake above two thirds,
//     still above after the largest live validator is lost) and
//     `check_stop` (the same check on the set with the validator stopped).
//
// Faults: a stop is a process that can restart; a loss (`die`) is a machine
// that never comes back. A stopped validator misses epochs when the chain
// still certifies. Several validators may stop in the same step.
//
// Stop modes: MODE 0 stops are unguarded; MODE 1 one validator at a time,
// each stop passing `check_stop` against the current state; MODE 2 any set
// of validators that each passed `check_stop` against the same state (stage
// scripts that run side by side, none seeing the others' stop).
//
// Invariants (named per run in check.sh):
//   noHalt         the set can certify
//   survivesOneDown with at most one counted validator down the set certifies
//   recoverable    restarting every validator that has not been lost
//                  restores certification
//   liveSetOk      the live validators pass the launch check
//   spareKept      the counted set, all up, passes the launch check
module membership {
  const N: int
  const STAKES: List[int]
  const LIMIT: int
  const FLOOR: int
  const LAUNCH_RULE: bool
  const GENESIS_DEAD: int
  const MAX_GONE: int
  const MODE: int
  const SLASH: bool
  // Ejection also requires the remaining set to pass the launch check by
  // stake (the proposed replacement for a count-only floor).
  const GUARD_EJECT: bool

  var member: int -> bool
  var up: int -> bool
  var gone: int -> bool
  var missed: int -> int

  pure val VALS = 0.to(N - 1)
  pure def stakeOf(i: int): int = STAKES.nth(i)
  pure def cert(l: int, t: int): bool = 3 * l > 2 * t

  def stakeIn(s: Set[int]): int = s.fold(0, (a, i) => a + stakeOf(i))
  def members: Set[int] = VALS.filter(i => member.get(i))
  def liveSet: Set[int] = members.filter(i => up.get(i))
  def total: int = stakeIn(members)
  def canCertify: bool = total > 0 and cert(stakeIn(liveSet), total)
  def recoverable: bool = total > 0 and cert(stakeIn(members.filter(i => not(gone.get(i)))), total)
  def downCount: int = members.filter(i => not(up.get(i))).size()
  def goneCount: int = VALS.filter(i => gone.get(i)).size()

  // check_launch_set on the validators `mem` with liveness `upm`.
  def launchOkFor(mem: Set[int], upm: int -> bool): bool = {
    val t = stakeIn(mem)
    val lv = mem.filter(i => upm.get(i))
    val l = stakeIn(lv)
    val big = lv.fold(0, (a, i) => if (stakeOf(i) > a) stakeOf(i) else a)
    mem.size() >= 4 and t > 0 and cert(l, t) and cert(l - big, t)
  }
  // check_stop(set, i)
  def stopAllowed(i: int): bool = launchOkFor(members, up.set(i, false))

  action init = {
    nondet dead = VALS.powerset().filter(s => s.size() == (if (LAUNCH_RULE) 0 else GENESIS_DEAD)).oneOf()
    val upm = VALS.mapBy(i => not(dead.contains(i)))
    all {
      if (LAUNCH_RULE) launchOkFor(VALS, upm) else cert(stakeIn(VALS.filter(i => upm.get(i))), stakeIn(VALS)),
      member' = VALS.mapBy(i => true),
      up' = upm,
      gone' = VALS.mapBy(i => dead.contains(i)),
      missed' = VALS.mapBy(i => 0),
    }
  }

  action stopSet = {
    nondet s = VALS.powerset().filter(s =>
      s.size() > 0 and s.forall(i => member.get(i) and up.get(i)) and
      (MODE == 0 or
       (MODE == 1 and s.size() == 1 and s.forall(i => stopAllowed(i))) or
       (MODE == 2 and s.forall(i => stopAllowed(i))))).oneOf()
    all {
      up' = VALS.mapBy(i => if (s.contains(i)) false else up.get(i)),
      member' = member, gone' = gone, missed' = missed,
    }
  }

  action die = {
    nondet i = members.filter(i => not(gone.get(i)) and goneCount < MAX_GONE).oneOf()
    all {
      gone' = gone.set(i, true), up' = up.set(i, false),
      member' = member, missed' = missed,
    }
  }

  action restart = {
    nondet i = members.filter(i => not(up.get(i)) and not(gone.get(i))).oneOf()
    all { up' = up.set(i, true), member' = member, gone' = gone, missed' = missed }
  }

  // One epoch boundary: the chain certified the epoch, so the missed-epoch
  // counters advance, and eject_inactive runs.
  action epoch = {
    val m2 = VALS.mapBy(i =>
      if (not(member.get(i))) missed.get(i)
      else if (up.get(i)) 0
      else if (missed.get(i) + 1 > LIMIT) LIMIT else missed.get(i) + 1)
    val cands = members.filter(i => m2.get(i) >= LIMIT)
    def rank(i: int): int = cands.filter(j => m2.get(j) > m2.get(i) or (m2.get(j) == m2.get(i) and j < i)).size()
    val room = if (members.size() > FLOOR) members.size() - FLOOR else 0
    def prefix(p: int): Set[int] = cands.filter(i => rank(i) < p)
    val okP = 0.to(room).filter(p => p == 0 or not(GUARD_EJECT) or
      launchOkFor(members.exclude(prefix(p)), VALS.mapBy(i => true)))
    val ejected = prefix(okP.fold(0, (a, p) => if (p > a) p else a))
    all {
      canCertify,
      member' = VALS.mapBy(i => member.get(i) and not(ejected.contains(i))),
      missed' = m2,
      up' = up, gone' = gone,
    }
  }

  // A replacement is bonded: a transaction, so the set must certify.
  action join = {
    nondet i = VALS.filter(i => not(member.get(i))).oneOf()
    all {
      canCertify,
      member' = member.set(i, true), up' = up.set(i, true),
      gone' = gone.set(i, false), missed' = missed.set(i, 0),
    }
  }

  // A member is jailed or slashed out of the counted set: a transaction.
  action slash = {
    nondet i = members.oneOf()
    all {
      SLASH, canCertify,
      member' = member.set(i, false),
      up' = up, gone' = gone, missed' = missed,
    }
  }

  action step = any { stopSet, die, restart, epoch, join, slash }

  val noHalt = canCertify
  val survivesOneDown = downCount <= 1 implies canCertify
  val recoverableInv = recoverable
  val liveSetOk = launchOkFor(members, up)
  val spareKept = launchOkFor(members, VALS.mapBy(i => true))
  // reachability witnesses: each is violated when the event happens
  val neverEjects = members.size() == N
  val neverHalts = canCertify
}

// the 2026 launch: one of four gone at genesis, then one more stop
module old4 { import membership(N = 4, STAKES = [1, 1, 1, 1], LIMIT = 2, FLOOR = 3, LAUNCH_RULE = false, GENESIS_DEAD = 1, MAX_GONE = 2, MODE = 0, SLASH = false, GUARD_EJECT = false).* }
// launch rule holds, floor as shipped (3), losses and stops free
module ship4 { import membership(N = 4, STAKES = [1, 1, 1, 1], LIMIT = 2, FLOOR = 3, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 1, MODE = 0, SLASH = false, GUARD_EJECT = false).* }
module floor4 { import membership(N = 4, STAKES = [1, 1, 1, 1], LIMIT = 2, FLOOR = 4, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 1, MODE = 0, SLASH = false, GUARD_EJECT = false).* }
module ship5 { import membership(N = 5, STAKES = [1, 1, 1, 1, 1], LIMIT = 2, FLOOR = 3, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 1, MODE = 0, SLASH = false, GUARD_EJECT = false).* }
module floor5 { import membership(N = 5, STAKES = [1, 1, 1, 1, 1], LIMIT = 2, FLOOR = 4, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 1, MODE = 0, SLASH = false, GUARD_EJECT = false).* }
module ship7 { import membership(N = 7, STAKES = [1, 1, 1, 1, 1, 1, 1], LIMIT = 2, FLOOR = 3, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 1, MODE = 0, SLASH = false, GUARD_EJECT = false).* }
module floor7 { import membership(N = 7, STAKES = [1, 1, 1, 1, 1, 1, 1], LIMIT = 2, FLOOR = 4, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 1, MODE = 0, SLASH = false, GUARD_EJECT = false).* }
// weighted: one validator holds twice the others
module weighted7 { import membership(N = 7, STAKES = [2, 1, 1, 1, 1, 1, 1], LIMIT = 2, FLOOR = 4, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 1, MODE = 0, SLASH = false, GUARD_EJECT = false).* }
// guarded stops: no losses, no slashing
module seq7 { import membership(N = 7, STAKES = [1, 1, 1, 1, 1, 1, 1], LIMIT = 2, FLOOR = 4, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 0, MODE = 1, SLASH = false, GUARD_EJECT = false).* }
module par7 { import membership(N = 7, STAKES = [1, 1, 1, 1, 1, 1, 1], LIMIT = 2, FLOOR = 4, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 0, MODE = 2, SLASH = false, GUARD_EJECT = false).* }
module seq9 { import membership(N = 9, STAKES = [1, 1, 1, 1, 1, 1, 1, 1, 1], LIMIT = 2, FLOOR = 4, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 0, MODE = 1, SLASH = false, GUARD_EJECT = false).* }
// slashing while another validator is down
module slash5 { import membership(N = 5, STAKES = [1, 1, 1, 1, 1], LIMIT = 2, FLOOR = 4, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 1, MODE = 0, SLASH = true, GUARD_EJECT = false).* }
// ejection guarded by the launch check on the remaining set, floor left at 3
module guard5 { import membership(N = 5, STAKES = [1, 1, 1, 1, 1], LIMIT = 2, FLOOR = 3, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 1, MODE = 0, SLASH = false, GUARD_EJECT = true).* }
module guardw7 { import membership(N = 7, STAKES = [2, 1, 1, 1, 1, 1, 1], LIMIT = 2, FLOOR = 3, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 1, MODE = 0, SLASH = false, GUARD_EJECT = true).* }
module guard4 { import membership(N = 4, STAKES = [1, 1, 1, 1], LIMIT = 2, FLOOR = 3, LAUNCH_RULE = true, GENESIS_DEAD = 0, MAX_GONE = 1, MODE = 0, SLASH = false, GUARD_EJECT = true).* }
