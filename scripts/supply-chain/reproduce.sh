#!/usr/bin/env bash
# Two-host reproducibility check for a release: builds tenzro-node at one
# commit on two independent hosts of the same target architecture and
# compares the binaries' SHA-256.
#
# Each host gets the same source (git archive of the commit) at the same
# absolute path, builds with --locked, the pinned toolchain, no incremental
# state, SOURCE_DATE_EPOCH set to the commit time and the source and cargo
# home paths remapped, so nothing about the host leaks into the binary.
# Writes <dist>/reproducible-<commit>.txt with one line per host and a final
# MATCH or MISMATCH line; release.sh refuses a commit without a MATCH.
#
# Usage: scripts/supply-chain/reproduce.sh <ref> <host-a> <host-b> <dist-dir>
#   BUILD_WRAPPER   command prefix the remote build runs under (e.g. a
#                   capped builder); it is followed by `env ... cargo build`
#   CARGO_FEATURES  features of the release build, default the crate's
set -euo pipefail

REF=${1:?usage: reproduce.sh <ref> <host-a> <host-b> <dist-dir>}
HOST_A=${2:?host-a}
HOST_B=${3:?host-b}
DIST=${4:?dist-dir}

repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
commit=$(git rev-parse --verify "$REF^{commit}")
epoch=$(git log -1 --format=%ct "$commit")
dir=/tmp/tenzro-repro-$commit
features=${CARGO_FEATURES:+--features $CARGO_FEATURES}
mkdir -p "$DIST"
record="$DIST/reproducible-$commit.txt"

build_on() {  # build_on <host>: prints the sha256 of the binary built there
    local host=$1
    ssh "$host" "rm -rf '$dir' && mkdir -p '$dir'"
    git archive --format=tar "$commit" | ssh "$host" "tar -x -C '$dir'"
    ssh "$host" "cd '$dir' && ${BUILD_WRAPPER:-} env SOURCE_DATE_EPOCH=$epoch CARGO_INCREMENTAL=0 \
        CARGO_TARGET_DIR='$dir/target' \
        RUSTFLAGS=\"--remap-path-prefix=$dir=/build --remap-path-prefix=\$HOME/.cargo=/cargo -C link-arg=-Wl,--build-id=none\" \
        cargo build --release --locked -p tenzro-node $features >&2 \
        && sha256sum '$dir/target/release/tenzro-node' | cut -d' ' -f1"
}

a=$(build_on "$HOST_A")
b=$(build_on "$HOST_B")
{
    echo "commit $commit"
    echo "$HOST_A $a"
    echo "$HOST_B $b"
    if [ -n "$a" ] && [ "$a" = "$b" ]; then echo "MATCH $a"; else echo "MISMATCH"; fi
} > "$record"
cat "$record"
grep -q '^MATCH ' "$record"
