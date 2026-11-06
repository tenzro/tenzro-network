#!/usr/bin/env bash
# Spec-to-code conformance of consensus: the commit rule (commit_rule.qnt) and checkpoint votes
# (checkpoint_votes.qnt).
#
#   conformance.sh check <out-dir>    the conformance instances' own properties (safety, liveness): <out>/check.txt
#   conformance.sh gen <out-dir>      executions of the conformance instances, seeded and gzipped: commit rule
#                                     in <out>/traces, checkpoint votes in <out>/vote-traces
#   conformance.sh run <out-dir>      check, then gen, on one set of workers
#   conformance.sh build <out-dir>    builds the replay's tests ahead of the replay
#   conformance.sh replay <out-dir>   the executions replayed through the code (cargo test, the core's
#                                     conformance tests)
#   conformance.sh report <out-dir>   per instance, the executions generated and replayed and each witness
#                                     reached; one FAIL line per failure (<out>/report.txt); exits 1 on any
#   conformance.sh jobs <out-dir>     the jobs `run` starts, in order, without running them
#
# The commit-rule conformance instances (c4*, c7*) decide eagerly and catch up as the core does, with the core's
# own leader table for the replay committee, so each execution replays step by step. Executions are random runs
# of every instance, plus runs that end where a witness is reached (a skipped slot, a restarted validator
# releasing less than it executed, a certificate, equivocation evidence, a refused signature, a vote held off
# beyond the window). Each job takes one seed, so a run is reproduced from its file name:
# n<N>f<F>_<instance>[-<witness>[-<step>]]_<seed>_<k>.itf.json.gz.
#
# Simulations run on workers (quint_jobs.js) that each compile a specification once and run Quint's own
# simulator for many jobs. The checks start first; then jobs start in an order that keeps every instance and
# witness at the same share of its runs, so a deadline cuts all of them alike, and the search for a witness not
# reached in WITNESS_TARGET jobs comes last. With DEADLINE set no job starts after it; the report counts
# what was made and replayed, and fails an instance with fewer than MIN_PER_INSTANCE executions replayed, a
# check with fewer runs than it asks for, and a witness no replayed execution reaches.
#
# Environment: QUINT (quint binary), SEED (base seed, default 1), PER_INSTANCE (executions per instance, default
# 600), BATCH (executions per job, default 25), JOBS (most workers, default 16: worker k takes a job only while k
# is below the processors free, so a loaded host runs fewer; the first MIN_JOBS, default 2, always run), STEPS
# (default 400), CHECK_PERCENT (share of each check's runs, default 100), CHECK_CHUNK (runs per check job, default
# 50), DEADLINE and HARD_DEADLINE (Unix seconds: no job starts after the first; running jobs are stopped at the
# second), WITNESS_TARGET (runs that should reach each witness, default PER_INSTANCE / 20 + 1), WITNESS_SAMPLES
# (executions searched per witness, default 2,000 per target run), WITNESS_CHUNK (executions per witness job,
# default 100), WITNESS_MIN (replayed executions that must reach each witness, default 1), MIN_PER_INSTANCE
# (default 40), CARGO_WRAP (prefix for the cargo command), REPLAY_THREADS (default the processors free, at most
# REPLAY_MAX_THREADS, default 8, and at least MIN_JOBS), REPLAY_DEADLINE (Unix seconds: no replay starts after
# it), VOTE_COST (a vote execution's replay time over a commit-rule one's, default 1.5, for sharing the replay's
# time). Identical executions are kept once.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
cmd=${1:?usage: conformance.sh check|gen|run|build|replay|report|jobs <out-dir>}
out=${2:?usage: conformance.sh check|gen|run|build|replay|report|jobs <out-dir>}
out=$(mkdir -p "$out" && cd "$out" && pwd)
quint=${QUINT:-quint}
spec=$here/commit_rule.qnt
vspec=$here/checkpoint_votes.qnt
seed=${SEED:-1}
per=${PER_INSTANCE:-600}
batch=${BATCH:-25}
steps=${STEPS:-400}
cchunk=${CHECK_CHUNK:-50}
wtarget=${WITNESS_TARGET:-$(( per / 20 + 1 ))}
wsamples=${WITNESS_SAMPLES:-$(( wtarget * 2000 ))}
wchunk=${WITNESS_CHUNK:-100}
mkdir -p "$out/traces" "$out/vote-traces" "$out/logs"
export NODE_OPTIONS=${NODE_OPTIONS:---max-old-space-size=3072}

# instance:committee (each list may be overridden from the environment; empty or none skips it)
INSTANCES=${INSTANCES-"c4:n4f1 c4sync:n4f1 c4rejoin:n4f1 c4quorum:n4f1 c4quorumsync:n4f1 c7:n7f2 c7quorum:n7f2"}
VOTE_INSTANCES=${VOTE_INSTANCES-"v4:n4f1 v4any:n4f1 v4many:n4f1 v7:n7f2"}
# instance:invariant[:step]: the invariant's first violation ends the run where the witness is reached. A step
# other than `step` takes the specification's own actions with the ones leading to the witness made likelier.
WITNESSES=${WITNESSES-"c4:noSkip c4rejoin:noRejoin c4quorum:noSkip c4quorum:noRejoin:stepFirstProposals c7quorum:noRejoin:stepLateRestart c7:noSkip"}
VOTE_WITNESSES=${VOTE_WITNESSES-"v4:noCertificate v4:noEvidence v4any:noRefusal v4:noIgnoredFar v4many:noCertificate"}
# "none" empties a list (an empty variable cannot be passed from every shell).
for v in INSTANCES VOTE_INSTANCES WITNESSES VOTE_WITNESSES; do [[ ${!v} == none ]] && printf -v "$v" ''; done
export INSTANCES VOTE_INSTANCES WITNESSES VOTE_WITNESSES

cpus() { node "$here/quint_jobs.js" cpus; }

prefix_of() {  # prefix_of <instance> <list>
  local x
  for x in $2; do [[ ${x%%:*} == "$1" ]] && echo "${x##*:}"; done
}

# The simulator's first execution barely depends on nearby seeds, so seeds are spread over 40 bits. The shell
# multiplies modulo 2^64 with a sign, so a large base seed wraps negative and % would keep the sign (Quint refuses a
# negative seed); masking keeps the low 40 bits of the true product, which are never negative.
spread() { echo $(( (($1 * 1000003 + $2) * 2654435761) & 1099511627775 )); }

# Each job line starts with its order: the share of its group's runs made before it, in millionths (checks
# first, below zero), then its group, numbered so that the two specifications' groups alternate. The pool starts
# jobs in that order, so a deadline cuts every group alike.
gen_jobs() {  # gen_jobs <spec> <dir> <instances> <witnesses> <first group number>
  local e main pre b k n s inv st g=$(( $5 - 2 ))
  for e in $3; do
    g=$(( g + 2 ))
    main=${e%%:*} pre=${e##*:}
    # Larger committees and restarts make larger executions: fewer per job keeps the simulator's heap bounded.
    b=$batch
    [[ $pre == n4* && $main != *rejoin* && $main != *quorum* ]] || b=$(( batch < 5 ? batch : 5 ))
    n=$(( (per + b - 1) / b ))
    for (( k = 0; k < n; k++ )); do
      s=$(spread "$seed" "$k")
      echo "$(( k * 1000000 / n )) $g gen $1 $2 $main ${pre}_${main}_$s $s $b"
    done
  done
  for e in $4; do
    g=$(( g + 2 ))
    IFS=: read -r main inv st <<< "$e"
    pre=$(prefix_of "$main" "$3")
    n=$(( (wsamples + wchunk - 1) / wchunk ))
    for (( k = 0; k < n; k++ )); do
      s=$(spread "$seed" $(( 50000 + k )))
      # The first WITNESS_TARGET jobs keep pace with the instances' executions; the search beyond them, for a
      # witness still not reached, comes after every instance's executions.
      echo "$(( k * 1000000 / wtarget )) $g wit $1 $2 $main ${pre}_$main-$inv${st:+-$st}_$s $s $wchunk $inv ${st:-step} $main-$inv $wtarget"
    done
  done
}

check_jobs() {
  : > "$out/checks.txt"
  chk() {  # chk <spec> <name> <main> <invariant> <runs>
    local total=$(( $5 * ${CHECK_PERCENT:-100} / 100 )) k n m s
    n=$(( (total + cchunk - 1) / cchunk ))
    for (( k = 0; k < n; k++ )); do
      m=$(( total - k * cchunk < cchunk ? total - k * cchunk : cchunk ))
      s=$(spread "$seed" $(( 90000 + k )))
      echo "$(( k * 1000000 / n - 2000000 )) 0 chk $1 $2 $3 check-$2_$s $s $m $4"
    done
    echo "$2 $total" >> "$out/checks.txt"
  }
  chk "$spec" eager-safety-n4 c4 safety 2000
  chk "$spec" eager-safety-n4-rejoin c4rejoin safety 2000
  # With the core's own leader table a Byzantine validator may lead a slot of the last rounds, which no later
  # anchor decides: liveness is checked up to MAX_ROUND - 4, and no honest leader's slot is ever skipped.
  chk "$spec" eager-liveness-n4 c4sync "liveCommitEarly and noHonestSkip and safety" 2000
  chk "$spec" eager-safety-n7 c7 safety 1000
  chk "$spec" exact-quorum-safety-n4 c4quorum safety 2000
  chk "$spec" exact-quorum-liveness-n4 c4quorumsync "liveCommitEarly and noHonestSkip and safety" 2000
  chk "$spec" exact-quorum-safety-n7 c7quorum safety 1000
  chk "$vspec" votes-safety-n4 v4 safety 4000
  chk "$vspec" votes-safety-n4-any-request v4any safety 4000
  chk "$vspec" votes-safety-n4-many v4many safety 4000
  chk "$vspec" votes-safety-n7 v7 safety 2000
}

pool() {  # pool <jobs-file>: runs the jobs on the workers, one line per job to <out>/jobs.log
  local q w n hard_s=""
  q=$(command -v "$quint") || { echo "no quint at $quint" >&2; return 1; }
  n=${JOBS:-16}
  rm -rf "$out/claims" "$out/staging"
  # A worker stops itself at HARD_DEADLINE; the timeout is a backstop.
  [[ -n ${HARD_DEADLINE:-} ]] && hard_s=$(( HARD_DEADLINE - $(date +%s) + 120 ))
  echo "$(date -u +%FT%TZ) $(wc -l < "$1") jobs on up to $n workers (deadline ${DEADLINE:-none})" >> "$out/pool.txt"
  for (( w = 0; w < n; w++ )); do
    if [[ -n $hard_s ]]; then
      DEADLINE=${DEADLINE:-} HARD_DEADLINE=$HARD_DEADLINE JOBS=$n STEPS=$steps \
        timeout --kill-after=30 "$(( hard_s > 1 ? hard_s : 1 ))" node "$here/quint_jobs.js" work "$q" "$1" "$out" "$w" \
        >> "$out/jobs.log" 2>> "$out/logs/worker-$w.err" &
    else
      DEADLINE=${DEADLINE:-} JOBS=$n STEPS=$steps node "$here/quint_jobs.js" work "$q" "$1" "$out" "$w" \
        >> "$out/jobs.log" 2>> "$out/logs/worker-$w.err" &
    fi
  done
  wait
  echo "$(date -u +%FT%TZ) done" >> "$out/pool.txt"
}

# The check verdicts: a check passes when all its runs were made and none violated its invariant.
check_verdicts() {
  local name total ok bad
  : > "$out/check.txt"
  while read -r name total; do
    ok=$(awk -v c="$name" '$1 == "CHECK-OK" && $2 == c { sub("samples=", "", $4); n += $4 } END { print n + 0 }' "$out/jobs.log")
    bad=$(awk -v c="$name" '($1 == "CHECK-VIOLATED" && $2 == c) || ($1 == "FAILED" && $2 == "chk" && $3 == c) { print; exit }' "$out/jobs.log")
    if [[ -n $bad ]]; then
      echo "FAIL $name: $bad"
    elif (( ok < total )); then
      echo "FAIL $name: $ok of $total runs made before the deadline"
    else
      echo "PASS $name ($ok runs)"
    fi
  done < "$out/checks.txt" | tee -a "$out/check.txt"
  ! grep -q '^FAIL' "$out/check.txt"
}

gen_summary() {
  echo "$(ls "$out/traces" | wc -l) commit-rule and $(ls "$out/vote-traces" | wc -l) vote executions" \
    "($(grep -o 'duplicates=[0-9]*' "$out/gen.txt" | awk -F= '{ n += $2 } END { print n + 0 }') duplicates dropped);" \
    "$(grep -c '^FAILED' "$out/gen.txt") generation failures;" \
    "$(grep -c '^NOT-STARTED' "$out/gen.txt") jobs not started before the deadline;" \
    "$(grep -c '^WITNESS ' "$out/gen.txt") witness runs reached, $(grep -c '^WITNESS-MISS' "$out/gen.txt") not" |
    tee "$out/gen-summary.txt"
}

jobs_file() {  # jobs_file check|gen|run: the jobs, in the order they start, to <out>/jobs.txt
  {
    [[ $1 == gen ]] || check_jobs
    [[ $1 == check ]] || { gen_jobs "$spec" traces "$INSTANCES" "$WITNESSES" 0
                           gen_jobs "$vspec" vote-traces "$VOTE_INSTANCES" "$VOTE_WITNESSES" 1; }
  } | sort -s -n -k1,1 -k2,2 | cut -d' ' -f3- > "$out/jobs.txt"
}

case $cmd in
jobs)
  # The jobs `run` would start, in order, without running them.
  jobs_file run
  cat "$out/jobs.txt"
  ;;
check|gen|run)
  : > "$out/jobs.log"
  jobs_file "$cmd"
  pool "$out/jobs.txt"
  rc=0
  if [[ $cmd != gen ]]; then check_verdicts || rc=1; fi
  if [[ $cmd != check ]]; then
    grep -v '^CHECK-\|^NOT-STARTED chk\|^FAILED chk' "$out/jobs.log" > "$out/gen.txt"
    gen_summary
    grep -q '^FAILED' "$out/gen.txt" && rc=1
  fi
  exit $rc
  ;;
build)
  # The replay's test binary, built ahead so the replay's time goes to replaying.
  (cd "$root" && ${CARGO_WRAP:-} cargo test -p tenzro-consensus --lib --no-run) > "$out/build.log" 2>&1
  ;;
replay)
  # Each replay thread holds a committee of cores (about 300 MB at four validators, more at seven), and the
  # replay runs under the build slot's memory cap, so the processors free are capped at REPLAY_MAX_THREADS.
  threads=${REPLAY_THREADS:-$(cpus)}
  [[ -n ${REPLAY_THREADS:-} ]] || (( threads <= ${REPLAY_MAX_THREADS:-8} )) || threads=${REPLAY_MAX_THREADS:-8}
  (( threads >= ${MIN_JOBS:-2} )) || threads=${MIN_JOBS:-2}
  # The vote executions replay first, until their share of the time: the share of the work they are, a vote
  # execution taking about VOTE_COST (default 1.5) times a commit-rule one. The commit rule then has the rest.
  nc=$(find "$out/traces" -maxdepth 1 -name '*.itf.json*' 2> /dev/null | wc -l)
  nv=$(find "$out/vote-traces" -maxdepth 1 -name '*.itf.json*' 2> /dev/null | wc -l)
  vote_deadline=${REPLAY_DEADLINE:-}
  if [[ -n ${REPLAY_DEADLINE:-} ]] && (( nc + nv > 0 )); then
    now=$(date +%s)
    span=$(( REPLAY_DEADLINE > now ? REPLAY_DEADLINE - now : 0 ))
    vc=$(awk -v c="${VOTE_COST:-1.5}" 'BEGIN { printf "%d", c * 100 }')
    vote_deadline=$(( now + span * nv * vc / (nc * 100 + nv * vc) ))
  fi
  replay_tests() {  # replay_tests <filter> <deadline>
    (cd "$root" && COMMIT_RULE_TRACES="$out/traces" CHECKPOINT_VOTE_TRACES="$out/vote-traces" \
      CONFORMANCE_REPORT="$out/replay-report.txt" CONFORMANCE_VOTE_REPORT="$out/vote-replay-report.txt" \
      CONFORMANCE_THREADS=$threads CONFORMANCE_DEADLINE=$2 ${CARGO_WRAP:-} \
      cargo test -p tenzro-consensus --lib "$1" -- --nocapture --test-threads 1) >> "$out/replay.log" 2>&1
  }
  : > "$out/replay.log"
  rc=0
  replay_tests core::conformance_votes:: "$vote_deadline" || rc=1
  replay_tests core::conformance:: "${REPLAY_DEADLINE:-}" || rc=1
  grep -h '^SUMMARY' "$out/replay.log"
  exit $rc
  ;;
report)
  "${PYTHON:-python3}" - "$out" "${MIN_PER_INSTANCE:-40}" "${WITNESS_MIN:-1}" <<'PY' | tee "$out/report.txt"
import os, re, sys
from collections import Counter, defaultdict
out, need, wneed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
env = lambda k: [e.split(":") for e in os.environ.get(k, "").split()]
read = lambda f: open(os.path.join(out, f)).read().splitlines() if os.path.exists(os.path.join(out, f)) else []
key = lambda f: f.split("_")[1] if f.count("_") >= 3 else f  # n4f1_<key>_<seed>_<k>.itf.json.gz
gen, rep, notrep, div = Counter(), Counter(), Counter(), Counter()
for d in ("traces", "vote-traces"):
    for f in os.listdir(os.path.join(out, d)) if os.path.isdir(os.path.join(out, d)) else []:
        gen[key(f)] += 1
fails = []
summaries = 0
for f in ("replay-report.txt", "vote-replay-report.txt"):
    lines = read(f)
    for i, line in enumerate(lines):
        m = re.match(r"INSTANCE (\S+) replayed=(\d+) diverged=(\d+) not-replayed=(\d+)", line)
        if m:
            rep[m[1]] += int(m[2]); div[m[1]] += int(m[3]); notrep[m[1]] += int(m[4])
        summaries += line.startswith("SUMMARY")
        if line.startswith("DIVERGE"):
            fails.append(" |".join([line] + [l for l in lines[i + 1:i + 3] if l.startswith("  ")]))
if summaries < 2:
    fails.append("the replay did not finish (see replay.log): no executions counted as replayed")
base = lambda k: k.split("-")[0]
for inst, _ in env("INSTANCES") + env("VOTE_INSTANCES"):
    g = sum(v for k, v in gen.items() if base(k) == inst)
    r = sum(v for k, v in rep.items() if base(k) == inst)
    n = sum(v for k, v in notrep.items() if base(k) == inst)
    dv = sum(v for k, v in div.items() if base(k) == inst)
    print(f"INSTANCE {inst} generated={g} replayed={r} diverged={dv} not-replayed={n}")
    if r < need:
        fails.append(f"{inst}: {r} executions replayed, fewer than the {need} required ({g} generated, {n} not replayed)")
jobs = read("gen.txt")
for w in env("WITNESSES") + env("VOTE_WITNESSES"):
    wk = f"{w[0]}-{w[1]}"
    runs = [l.split() for l in jobs if l.split()[:2] in (["WITNESS", wk], ["WITNESS-MISS", wk])]
    hit = sum(1 for l in runs if l[0] == "WITNESS")
    searched = sum(int(l[3].split("=")[1]) for l in runs)
    r = sum(v for k, v in rep.items() if k == wk or k.startswith(wk + "-"))
    step = w[2] if len(w) > 2 else "step"
    print(f"WITNESS {wk} reached={hit} replayed={r} runs={len(runs)} executions-searched={searched} step={step}")
    if r < wneed:
        what = "not reached" if hit == 0 else "reached but not replayed"
        fails.append(f"WITNESS-NOT-REACHED {wk}: {what}: {hit} of {len(runs)} runs reached it in {searched} executions of {step}, {r} replayed")
for l in read("check.txt"):
    if l.startswith("FAIL"):
        fails.append(l[5:])
# A job stopped at the hard deadline kept nothing; it is counted below, not a failure.
for l in jobs:
    if l.startswith("FAILED"):
        fails.append(l)
started = Counter(l.split()[0] for l in jobs)
print(f"JOBS gen-and-witness: {started['GEN'] + started['WITNESS'] + started['WITNESS-MISS']} run, "
      f"{started['WITNESS-DONE']} not needed, {started['NOT-STARTED']} not started before the deadline, {started['CUT']} cut")
for f in fails:
    print("FAIL " + f)
sys.exit(1 if fails else 0)
PY
  ;;
*) echo "unknown command $cmd" >&2; exit 2 ;;
esac
