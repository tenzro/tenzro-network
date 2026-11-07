#!/bin/bash
# Write the release manifest over a dist directory the build scripts filled:
#
#   SHA256SUMS     one line per archive, `sha256sum -c` format
#   matrix.json    every artifact's build record (.buildenv.json), digest and
#                  install gate record (.install.json, install-gate.sh),
#                  and every container image saved beside the archives
#                  (tenzro-node-image-*.tar, built by build-image.sh from them)
#
# Every artifact must come from the same commit. The full matrix is
# MATRIX below; a missing entry is listed, and refused with --complete, as is
# an archive without a passing install gate record for its own sha256.
# Signing is a separate, later step over these files
# (scripts/supply-chain/release.sh, with the release hardware token).
#
# Usage: scripts/release/manifest.sh <dist-dir> [--complete]
set -euo pipefail

DIST=${1:?usage: manifest.sh <dist-dir> [--complete]}
COMPLETE=${2:-}
MATRIX="tenzro-node-linux-x86_64-cpu.tar.gz tenzro-node-linux-x86_64-cuda.tar.gz
tenzro-node-linux-x86_64-vulkan.tar.gz
tenzro-node-linux-aarch64-cpu.tar.gz tenzro-node-linux-aarch64-cuda.tar.gz
tenzro-node-linux-aarch64-vulkan.tar.gz tenzro-node-linux-aarch64-edge.tar.gz
tenzro-node-windows-x86_64-cpu.zip tenzro-node-windows-x86_64-cuda.zip
tenzro-node-windows-x86_64-vulkan.zip
tenzro-node-macos-aarch64-metal.tar.gz tenzro-node-macos-x86_64-cpu.tar.gz"

here=$(cd "$(dirname "$0")" && pwd)
cd "$DIST"
. "$here/lib.sh"
present=() missing=()
for a in $MATRIX; do
    if [ -f "$a" ]; then present+=("$a"); else missing+=("$a"); fi
done
[ ${#present[@]} -gt 0 ] || { echo "REFUSING: no artifacts in $DIST"; exit 1; }
if [ ${#missing[@]} -gt 0 ]; then
    echo "missing from the matrix: ${missing[*]}"
    [ "$COMPLETE" = --complete ] && { echo "REFUSING: incomplete matrix"; exit 1; }
fi

records='[]' ungated=()
: > SHA256SUMS.tmp
for a in "${present[@]}"; do
    env="${a%.tar.gz}"; env="${env%.zip}.buildenv.json"
    [ -f "$env" ] || { echo "REFUSING: $a has no $env"; exit 1; }
    sha=$(release_sha256 < "$a")
    printf '%s  %s\n' "$sha" "$a" >> SHA256SUMS.tmp
    gate="${env%.buildenv.json}.install.json" install=null
    if [ -f "$gate" ] && [ "$(jq -r .verdict "$gate")" = pass ] && [ "$(jq -r .sha256 "$gate")" = "$sha" ]; then
        install=$(jq -c '{role, host, checked}' "$gate")
    else
        ungated+=("$a")
    fi
    records=$(jq -c --arg f "$a" --arg s "$sha" --slurpfile e "$env" --argjson g "$install" \
        '. + [($e[0] + {file: $f, sha256: $s, install_gate: $g})]' <<<"$records")
done
if [ ${#ungated[@]} -gt 0 ]; then
    echo "no passing install gate for its sha256: ${ungated[*]}"
    [ "$COMPLETE" = --complete ] && { echo "REFUSING: archives without a passing install gate"; rm -f SHA256SUMS.tmp; exit 1; }
fi
images='[]'
for img in tenzro-node-image-*.tar; do
    [ -f "$img" ] || continue
    rec="${img%.tar}.image.json"
    [ -f "$rec" ] || { echo "REFUSING: $img has no $rec"; exit 1; }
    sha=$(release_sha256 < "$img")
    [ "$sha" = "$(jq -r .sha256 "$rec")" ] || { echo "REFUSING: $img does not match its record"; exit 1; }
    printf '%s  %s\n' "$sha" "$img" >> SHA256SUMS.tmp
    images=$(jq -c --slurpfile e "$rec" '. + [$e[0]]' <<<"$images")
done
packages='[]'
if [ -f packages.json ]; then
    n=$(jq length packages.json)
    for ((k = 0; k < n; k++)); do
        rec=$(jq -c ".[$k]" packages.json)
        pf=$(jq -r .file <<<"$rec")
        [ -f "$pf" ] || { echo "REFUSING: packages.json lists $pf, which is not here"; exit 1; }
        sha=$(release_sha256 < "$pf")
        [ "$sha" = "$(jq -r .sha256 <<<"$rec")" ] || { echo "REFUSING: $pf does not match packages.json"; exit 1; }
        while read -r sf ss; do
            [ "$(release_sha256 < "$sf" 2>/dev/null)" = "$ss" ] || { echo "REFUSING: $pf was built from $sf with digest $ss, which is not the archive here"; exit 1; }
        done < <(jq -r '.sources[] | "\(.file) \(.sha256)"' <<<"$rec")
        printf '%s  %s\n' "$sha" "$pf" >> SHA256SUMS.tmp
        packages=$(jq -c --argjson r "$rec" '. + [$r]' <<<"$packages")
    done
fi
commits=$(jq -nr --argjson a "$records" --argjson i "$images" '[$a[].commit, $i[].commit] | unique | length')
[ "$commits" = 1 ] || { echo "REFUSING: artifacts from $commits different commits"; exit 1; }
mv SHA256SUMS.tmp SHA256SUMS
jq --argjson i "$images" --argjson p "$packages" '{commit: .[0].commit, rust: .[0].rust, artifacts: ., images: $i, packages: $p}' <<<"$records" > matrix.json
echo "manifest: ${#present[@]} artifact(s), $(jq '.images | length' matrix.json) image(s), $(jq '.packages | length' matrix.json) package(s) at $(jq -r .commit matrix.json)"
cat SHA256SUMS
