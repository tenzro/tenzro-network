#!/usr/bin/env bash
# stale-sweep.sh names merged and idle branches, never main or fresh work, and deletes nothing.
#
#   bash scripts/release/test_stale_sweep.sh
set -uo pipefail
sweep=$(cd "$(dirname "$0")" && pwd)/stale-sweep.sh
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "FAIL: $*"; fail=1; }
g() { git -C "$tmp/r" -c user.name=t -c user.email=t@t "$@" >/dev/null; }
commit() { GIT_COMMITTER_DATE=$1 GIT_AUTHOR_DATE=$1 g commit --allow-empty -m "$2"; }

git init -q -b main "$tmp/r"
commit "$(date -d '-40 days' -R)" base
g switch -q -c merged-work; commit "$(date -d '-30 days' -R)" merged
g switch -q main; g merge -q --ff-only merged-work
g switch -q -c idle-work; commit "$(date -d '-20 days' -R)" idle
g switch -q main; g switch -q -c fresh-work; commit "$(date -R)" fresh
g switch -q main

out=$("$sweep" --repo "$tmp/r"); rc=$?
[[ $rc == 0 ]] || bad "a report-only sweep exited $rc"
grep -q '^merged merged-work ' <<<"$out" || bad "a branch already in main is not named merged: $out"
grep -q '^idle idle-work .* 20$' <<<"$out" || bad "a branch left 20 days is not named idle: $out"
grep -q 'fresh-work' <<<"$out" && bad "fresh work was named stale: $out"
grep -qE '^(merged|idle) main ' <<<"$out" && bad "main was named stale: $out"
grep -q 'stale sweep: 2 stale branch(es)' <<<"$out" || bad "the count is wrong: $out"

out=$("$sweep" --repo "$tmp/r" --days 25)
grep -q 'idle-work' <<<"$out" && bad "--days 25 still names a 20-day-old branch: $out"

"$sweep" --repo "$tmp/r" --strict >/dev/null; [[ $? == 1 ]] || bad "--strict does not fail on stale branches"
"$sweep" --repo "$tmp/r" --days x >/dev/null 2>&1; [[ $? == 2 ]] || bad "a bad --days was accepted"
"$sweep" --repo "$tmp/r" --main nope >/dev/null 2>&1; [[ $? == 2 ]] || bad "a missing main branch was accepted"

[[ $(git -C "$tmp/r" for-each-ref refs/heads | wc -l) == 4 ]] || bad "the sweep deleted a branch"

# Branches of a remote are swept the same way.
git clone -q "$tmp/r" "$tmp/c"
out=$("$sweep" --repo "$tmp/c" --remote origin)
grep -q '^merged merged-work ' <<<"$out" && grep -q '^idle idle-work ' <<<"$out" || bad "a remote's branches are not swept: $out"

[ $fail = 0 ] && echo "ok: the stale sweep names merged and idle branches only, and deletes nothing"
exit $fail
