#!/usr/bin/env bash
# Stale sweep: which branches of a repository are stale. It reports and deletes nothing.
#
#   stale-sweep.sh [--repo DIR] [--remote NAME] [--main REF] [--days N] [--strict]
#
# A branch is stale when either holds:
#   merged   everything on it is already in the main branch (its tip is an ancestor of main), but
#            the branch still exists: code nobody needs any more, waiting to be built on by mistake.
#   idle     it is not merged and its newest commit is older than N days (default 14): work that
#            stopped, and drifts further from main each day it is left.
# The main branch itself is never listed. Branches are read from the remote named by --remote
# (default: local branches when no remote is given).
#
# Output: one line per stale branch, "<merged|idle> <branch> <tip> <age in days>", then a count.
# Exit 0, or with --strict 1 when any branch is stale. Choosing what to delete is left to people.
set -euo pipefail
repo=. remote= main= days=14 strict=0
while [[ $# -gt 0 ]]; do case $1 in
  --repo) repo=$2; shift 2 ;;
  --remote) remote=$2; shift 2 ;;
  --main) main=$2; shift 2 ;;
  --days) days=$2; shift 2 ;;
  --strict) strict=1; shift ;;
  *) echo "usage: stale-sweep.sh [--repo DIR] [--remote NAME] [--main REF] [--days N] [--strict]" >&2; exit 2 ;;
esac; done
[[ $days =~ ^[0-9]+$ ]] || { echo "REFUSING: --days takes a whole number of days" >&2; exit 2; }
G=(git -C "$repo")
if [[ -n $remote ]]; then prefix=refs/remotes/$remote/; else prefix=refs/heads/; fi
main=${main:-${prefix#refs/}main}
"${G[@]}" rev-parse -q --verify "$main^{commit}" >/dev/null || { echo "REFUSING: no main branch $main" >&2; exit 2; }
main_tip=$("${G[@]}" rev-parse "$main^{commit}")
main_ref=$("${G[@]}" rev-parse --symbolic-full-name "$main")
now=$(date +%s)
n=0
while IFS=$'\t' read -r ref tip when; do
  name=${ref#"$prefix"}
  [[ $name == HEAD || $ref == "$main_ref" ]] && continue
  age=$(( (now - when) / 86400 ))
  if "${G[@]}" merge-base --is-ancestor "$tip" "$main_tip"; then
    printf 'merged %s %s %d\n' "$name" "${tip:0:12}" "$age"; n=$((n + 1))
  elif (( age > days )); then
    printf 'idle %s %s %d\n' "$name" "${tip:0:12}" "$age"; n=$((n + 1))
  fi
done < <("${G[@]}" for-each-ref --format='%(refname)%09%(objectname)%09%(committerdate:unix)' "$prefix" | sort)
echo "stale sweep: $n stale branch(es) against $main (idle after $days days); nothing deleted"
(( strict && n > 0 )) && exit 1
exit 0
