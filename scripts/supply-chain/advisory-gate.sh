#!/usr/bin/env bash
# Release advisory gate: refuses a lockfile that pulls in a RustSec
# vulnerability, or an advisory that marks a crate unsound, unless
# .cargo/audit.toml accepts it with a recorded decision. release.sh stops on
# it; the scheduled sec-supply-chain stage only files what it finds.
#
# Usage: scripts/supply-chain/advisory-gate.sh [--no-fetch] [lockfile]
#   lockfile   default Cargo.lock; read with this repository's .cargo/audit.toml
#   --no-fetch use the advisory database already on this host
# Needs cargo-audit (pinned in scripts/testnet/security/tools.env).
# Exit 0 clean, 1 blocked, 2 the check could not run (also a refusal).
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fetch=()
if [ "${1:-}" = "--no-fetch" ]; then fetch=(--no-fetch); shift; fi
lock=${1:-$root/Cargo.lock}
[ -f "$lock" ] || { echo "REFUSING: no lockfile at $lock"; exit 2; }
lock=$(realpath "$lock")
cd "$root"
command -v cargo-audit >/dev/null || { echo "REFUSING: cargo-audit not found"; exit 2; }
json=$(cargo audit --json "${fetch[@]}" --file "$lock" 2>/dev/null)
read -r -d '' check <<'PY'
import json, sys
try:
    report = json.load(sys.stdin)
except ValueError:
    print("REFUSING: cargo-audit produced no report")
    sys.exit(2)
found = []
for v in report.get("vulnerabilities", {}).get("list", []):
    found.append((v["advisory"], v["package"], "vulnerability", v.get("versions", {}).get("patched", [])))
for w in report.get("warnings", {}).get("unsound", []):
    if w.get("advisory"):
        found.append((w["advisory"], w["package"], "unsound", w.get("versions", {}).get("patched", [])))
for adv, pkg, kind, patched in sorted(found, key=lambda f: f[0]["id"]):
    print(f"BLOCKED: {adv['id']} ({kind}) in {pkg['name']}@{pkg['version']}: {adv.get('title', '')}; "
          f"patched: {', '.join(patched) or 'none'}")
if found:
    print(f"advisory gate FAILED for {sys.argv[1]}: {len(found)} advisory(ies) not accepted in .cargo/audit.toml")
    sys.exit(1)
print(f"advisory gate passed for {sys.argv[1]}")
PY
python3 -c "$check" "$lock" <<<"$json"
