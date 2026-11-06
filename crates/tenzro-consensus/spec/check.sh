#!/usr/bin/env bash
# Checks the commit-rule specification and replays its executions through the
# consensus core.
#
# Usage: spec/check.sh <out-dir>
#
#   QUINT          the quint command (default: quint)
#   SAMPLES        random executions per check (default: 300)
#   SEED           simulator seed (default: 1)
#   TRACES         executions replayed through the core per committee size
#                  (default: 20)
#   CARGO_WRAP     command the cargo test runs under (default: none)
#   VERIFY_STEPS   when set, also checks agreement with the symbolic model
#                  checker up to this many steps (needs Java 21)
#   REPLAY         when set to 1, also replays generated executions through
#                  the core (needs the commit replay test in the crate)
#
# Steps, each reported on one line of <out-dir>/summary.txt:
#   1. typecheck;
#   2. safety (agreement, noReorder) by random simulation at n = 4, f = 1 with
#      two leader tables and at n = 7, f = 2;
#   3. liveness at n = 4 and n = 7 with SYNC: liveCommit;
#   4. leaders redrawn at every checkpoint and restarts from the journal:
#      safety (agreement, noReorder, rejoinConsistent, executedAgreement) at
#      n = 4 with lookahead 1 and 0 and at n = 7, and liveCommitEarly at n = 4
#      with SYNC and the core's lookahead of 4;
#   5. reachability witnesses: a skipped slot, a quiescent end state, a
#      redrawn schedule, a restarted validator deciding again below what it
#      executed, a quiescent end state with redraws and restarts, and a
#      skipped honest slot under a lookahead of 1 are reached (the check fails if the simulator cannot find
#      them);
#   6. optional bounded symbolic check of agreement;
#   7. optional replay of generated executions, and of executions ending on a
#      skipped slot, through the core (cargo test).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=${1:?usage: check.sh <out-dir>}
quint=${QUINT:-quint}
export NODE_OPTIONS=${NODE_OPTIONS:---max-old-space-size=4096}
samples=${SAMPLES:-300}
seed=${SEED:-1}
traces=${TRACES:-20}
spec=$here/commit_rule.qnt
mkdir -p "$out/traces"
: > "$out/summary.txt"
failed=0

report() { echo "$1" | tee -a "$out/summary.txt"; }

holds() {  # holds <name> <main> <invariant> <steps>
  if $quint run "$spec" --main "$2" --invariant "$3" --max-samples "$samples" --max-steps "$4" \
      --seed "$seed" > "$out/$1.log" 2>&1; then
    report "PASS $1"
  else
    report "FAIL $1: see $out/$1.log"
    failed=1
  fi
}

reached() {  # reached <name> <main> <invariant> <steps>: the invariant must be violated
  if $quint run "$spec" --main "$2" --invariant "$3" --max-samples "$samples" --max-steps "$4" \
      --seed "$seed" > "$out/$1.log" 2>&1; then
    report "FAIL $1: not reached in $samples executions"
    failed=1
  else
    report "PASS $1"
  fi
}

if $quint typecheck "$spec" > "$out/typecheck.log" 2>&1; then report "PASS typecheck"; else
  report "FAIL typecheck: see $out/typecheck.log"; exit 1
fi

holds safety-n4 n4 "agreement and noReorder" 200
holds safety-n4-byzantine-first n4byzfirst "agreement and noReorder" 200
holds safety-n7 n7 "agreement and noReorder" 400
holds liveness-n4 n4sync "liveCommit and agreement" 400
holds liveness-n7 n7sync "liveCommit and agreement" 800
holds rejoin-n4 n4rejoin safety 300
holds rejoin-n4-lookahead0 n4rejoin0 safety 300
holds rejoin-n7 n7rejoin safety 500
holds rejoin-liveness-n4 n4rejoinsync4 "liveCommitEarly and safety" 1200
reached witness-skip n4 noSkip 200
reached witness-quiescent n4sync noQuiescence 400
reached witness-redraw n4rejoin noRedraw 300
reached witness-rejoin n4rejoin noRejoin 300
reached witness-rejoin-quiescent n4rejoinsync4 noQuiescence 1200
# A lookahead shorter than the commit depth: the execution that skipped an
# honest leader's slot before validators held off judging unsettled leaders
# (seed 0xfc364) must now keep liveness, and so must random executions.
if $quint run "$spec" --main n4rejoinsync --invariant "liveCommitEarly and safety" --max-samples 1 --max-steps 600 \
    --seed 0xfc364 > "$out/short-lookahead-replay.log" 2>&1; then
  report "PASS short-lookahead-replay"
else
  report "FAIL short-lookahead-replay: see $out/short-lookahead-replay.log"
  failed=1
fi
holds short-lookahead-liveness-n4 n4rejoinsync "liveCommitEarly and safety" 1200

if [[ -n ${VERIFY_STEPS:-} ]]; then
  if $quint verify "$spec" --main n4small --invariant agreement --max-steps "$VERIFY_STEPS" \
      > "$out/verify-n4.log" 2>&1; then
    report "PASS verify-n4 ($VERIFY_STEPS steps)"
  else
    report "FAIL verify-n4: see $out/verify-n4.log"
    failed=1
  fi
fi

gen() {  # gen <main> <prefix> <steps> <count>: one execution per seed
  local k
  for k in $(seq 1 "$4"); do
    $quint run "$spec" --main "$1" --mbt --max-samples 1 --n-traces 1 --max-steps "$3" \
      --seed "$((seed + k))" --out-itf "$out/traces/$2_$k.itf.json" >> "$out/gen-$2.log" 2>&1 || return 1
  done
}
# Executions that end on a skipped slot, which random executions rarely reach.
skips() {  # skips <main> <prefix> <steps>
  local k
  for k in $(seq 1 "$((traces / 4 + 1))"); do
    $quint run "$spec" --main "$1" --invariant noSkip --mbt --max-samples "$samples" --max-steps "$3" \
      --seed "$((seed + k))" --out-itf "$out/traces/$2_skip_$k.itf.json" >> "$out/gen-$2.log" 2>&1
  done
  ls "$out/traces/$2_skip_"*.itf.json > /dev/null 2>&1
}
[[ ${REPLAY:-0} == 1 ]] || exit $failed

if gen replay4 n4 200 "$traces" && gen replay7 n7 400 "$((traces / 2))" && skips replay4 n4 200 && skips replay7 n7 400; then
  if (cd "$root" && COMMIT_RULE_TRACES="$out/traces" ${CARGO_WRAP:-} cargo test -p tenzro-consensus --lib \
      core::conformance::conformance_replay -- --nocapture) > "$out/replay.log" 2>&1; then
    report "PASS replay ($(ls "$out/traces" | wc -l) executions)"
  else
    report "FAIL replay: see $out/replay.log"
    failed=1
  fi
else
  report "FAIL trace generation: see $out/gen-*.log"
  failed=1
fi

exit $failed
