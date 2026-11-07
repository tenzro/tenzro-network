#!/usr/bin/env bash
# Compares every git+rev dependency pin in Cargo.toml against its upstream
# repository's current default-branch head, and reports what sits between
# the pin and that head.
#
# This never changes a pin and never decides to upgrade anything: the launch
# binaries (and every release) stay on their recorded rev until a human bumps
# it in a reviewed PR (docs/SUPPLY-CHAIN.md). A release never depends on this
# script's exit code; the weekly supply-chain workflow uses it only to open
# an issue when something changed upstream.
#
# Usage: scripts/supply-chain/git-pin-drift.sh [Cargo.toml]
#   GITHUB_TOKEN   optional; raises the GitHub API rate limit if set
# Exit 0   every pin matches its upstream head (no drift)
# Exit 1   at least one pin has drifted (commits exist between the pin and head)
# Exit 2   the check could not run (network, parse or API failure) -- a refusal,
#          not a drift report; CI should not open an issue on exit 2
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
toml=${1:-$root/Cargo.toml}
[ -f "$toml" ] || { echo "REFUSING: no Cargo.toml at $toml"; exit 2; }

auth=()
[ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")

api() { # path -> json on stdout; returns the curl exit code
    curl -fsS "${auth[@]}" -H "Accept: application/vnd.github+json" "https://api.github.com/$1"
}

# One line per distinct (git url, rev): "<url> <rev> <crate1,crate2,...>"
pins=$(python3 -c "
import re, sys
text = open('$toml').read()
# A dependency table entry on one line: name = { ... git = \"URL\" ... rev = \"SHA\" ... }
pat = re.compile(r'^([A-Za-z0-9_-]+)\s*=\s*\{[^}]*\bgit\s*=\s*\"([^\"]+)\"[^}]*\brev\s*=\s*\"([^\"]+)\"', re.M)
seen = {}
for name, url, rev in pat.findall(text):
    seen.setdefault((url, rev), []).append(name)
for (url, rev), names in seen.items():
    print(f'{url} {rev} {\",\".join(names)}')
")

if [ -z "$pins" ]; then
    echo "No git+rev dependency pins found in $toml."
    exit 0
fi

drift=0
while IFS=' ' read -r url rev names; do
    repo=${url#https://github.com/}; repo=${repo%.git}
    echo "--- $repo (crates: $names) ---"
    echo "pinned: $rev"

    default_branch=$(api "repos/$repo" | python3 -c "import json,sys; print(json.load(sys.stdin).get('default_branch',''))" 2>/dev/null)
    if [ -z "$default_branch" ]; then
        echo "REFUSING: could not read $repo's default branch (API or network failure)"
        exit 2
    fi

    head=$(api "repos/$repo/commits/$default_branch" | python3 -c "import json,sys; print(json.load(sys.stdin).get('sha',''))" 2>/dev/null)
    if [ -z "$head" ]; then
        echo "REFUSING: could not read $repo's $default_branch head"
        exit 2
    fi
    echo "upstream $default_branch head: $head"

    if [ "$head" = "$rev" ]; then
        echo "no drift"
        echo
        continue
    fi

    drift=1
    compare=$(api "repos/$repo/compare/$rev...$head")
    count=$(printf '%s' "$compare" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('commits', [])))" 2>/dev/null || echo "?")
    echo "DRIFT: $count commit(s) between the pin and $default_branch"
    printf '%s' "$compare" | python3 -c "
import json, sys
d = json.load(sys.stdin)
sensitive_paths = ('llama-cpp-sys-2', 'llama-cpp-2', 'bindings', 'ffi', 'src/runtime', 'runtime/src')
sensitive_words = ('cve', 'security', 'vulnerab', 'advisory', 'unsafe', 'overflow', 'use-after-free', 'uaf')
for c in d.get('commits', []):
    sha = c['sha'][:12]
    msg = c['commit']['message'].splitlines()[0]
    files = [f['filename'] for f in c.get('files', [])] if 'files' in c else []
    flags = []
    low = msg.lower()
    if any(w in low for w in sensitive_words):
        flags.append('message mentions a security/safety word')
    if any(any(p in f for p in sensitive_paths) for f in files):
        flags.append('touches llama-cpp-sys-2/bindings/runtime paths')
    flag_str = f\"  [{'; '.join(flags)}]\" if flags else ''
    print(f'  {sha}  {msg}{flag_str}')
"
    echo
done <<< "$pins"

if [ "$drift" -eq 1 ]; then
    echo "RESULT: drift found. Review the diff, run the Tenzro test suite against the new rev on a"
    echo "branch (cargo check -p tenzro-model, the inference tests, the model smoke test), then bump"
    echo "the pin in a reviewed PR for the next release. The current release's pin is unaffected."
    exit 1
fi
echo "RESULT: no drift on any pin."
exit 0
