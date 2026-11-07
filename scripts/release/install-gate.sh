#!/usr/bin/env bash
# The install gate for one Linux release archive, run on a machine of the
# class the archive is for: the archive's digest is taken, it goes through
# tenzro-node-install --dry-run for its role (cpu and edge builds for the CPU
# and edge roles, cuda and vulkan builds for the GPU role), and only an
# accepted archive gets a record beside it:
#
#   <artifact>.install.json  {artifact, file, sha256, role, host, verdict: "pass", checked, report}
#
# manifest.sh --complete refuses a matrix in which any archive lacks a passing
# record whose sha256 is the archive's own.
#
# Usage: scripts/release/install-gate.sh <dist-dir> <artifact.tar.gz>
set -euo pipefail

DIST=${1:?usage: install-gate.sh <dist-dir> <artifact.tar.gz>}
FILE=${2:?usage: install-gate.sh <dist-dir> <artifact.tar.gz>}
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"
cd "$DIST"
[ -f "$FILE" ] || { echo "REFUSING: no $FILE in $DIST"; exit 1; }

name=${FILE%.tar.gz}
case "$name" in
    tenzro-node-linux-*-cpu|tenzro-node-linux-*-cpu-bookworm) role=cpu ;;
    tenzro-node-linux-*-edge) role=edge ;;
    tenzro-node-linux-*-cuda|tenzro-node-linux-*-cuda-orin|tenzro-node-linux-*-vulkan) role=gpu ;;
    *) echo "REFUSING: $FILE is not a Linux release archive"; exit 1 ;;
esac
arch=${name#tenzro-node-linux-}; arch=${arch%%-*}
[ "$(uname -s)-$(uname -m)" = "Linux-$arch" ] || { echo "REFUSING: $FILE is for Linux $arch; this host is $(uname -s) $(uname -m)"; exit 1; }

sha=$(release_sha256 < "$FILE")
report=$(mktemp)
trap 'rm -f "$report"' EXIT
if ! bash "$here/tenzro-node-install" --dry-run --role "$role" "$FILE" > "$report" 2>&1; then
    cat "$report"
    echo "INSTALL GATE FAIL: $FILE ($role role)"
    rm -f "$name.install.json"
    exit 1
fi
cat "$report"
jq -n --arg artifact "$name" --arg file "$FILE" --arg sha "$sha" --arg role "$role" \
    --arg host "$(uname -s)-$(uname -m)" --arg checked "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --rawfile report "$report" \
    '{artifact: $artifact, file: $file, sha256: $sha, role: $role, host: $host, verdict: "pass", checked: $checked,
      report: ($report | split("\n") | map(select(length > 0)))}' > "$name.install.json"
echo "INSTALL GATE PASS: $FILE ($role role) sha256 $sha"
