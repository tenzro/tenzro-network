#!/bin/bash
# Build the confidential VM image of the node from a released Linux x86_64
# node archive: one UEFI disk that boots under Intel TDX and AMD SEV-SNP, with
# a dm-verity root file system and a unified kernel image (kernel, initrd and a
# command line carrying the verity root hash) as its only EFI binary. Nothing
# is compiled: the node and CLI binaries are taken from the archive as they
# are.
#
#   node    the node, its CLI and the first-boot units (scripts/release/cvm/)
#   prover  the node image plus the finality prover and the Groth16 prover
#           container it wraps proofs in, so proofs made on the machine can
#           be bound to its attestation
#
# The build runs in a pinned Debian image with every package (the build tools
# and the image's own) from one snapshot.debian.org timestamp, and every file
# time clamped to the commit time of REF, so a second host building the same
# inputs gets the same bytes. Outputs, in DIST:
#
#   tenzro-node-cvm-x86_64[-prover].raw            the disk
#   tenzro-node-cvm-x86_64[-prover].efi            the unified kernel image on it
#   tenzro-node-cvm-x86_64[-prover].roothash       the verity root hash
#   tenzro-node-cvm-x86_64[-prover].gce.tar.gz     the disk as a cloud image archive
#   tenzro-node-cvm-x86_64[-prover].measurements.json  (scripts/release/cvm-measure.py)
#
# Usage: scripts/release/build-cvm-image.sh <node|prover> <node-archive.tar.gz> [dist-dir]
#   prover also needs PROVER_BIN: tenzro-finality-prover built for x86_64 without cuda.
#   SNAPSHOT (default below) picks the package snapshot; REF (default HEAD) the commit time.
#   CVM_CACHE, a directory, keeps downloaded packages between builds.
# SOURCE_DATE_EPOCH, when set, replaces the commit time (to rebuild on a host
# without the repository history).
set -euo pipefail

VARIANT=${1:?usage: build-cvm-image.sh <node|prover> <node-archive.tar.gz> [dist-dir]}
ARCHIVE=${2:?usage: build-cvm-image.sh <node|prover> <node-archive.tar.gz> [dist-dir]}
DIST=${3:-$HOME/dist}
REF=${REF:-HEAD}
SNAPSHOT=${SNAPSHOT:-20261005T000000Z}
# Debian 13 (trixie), by digest.
BASE_IMAGE=docker.io/library/debian@sha256:bcf83fd8af414eda0c0a99d25a4e61dedd88e7aac7f7bc519d04555ff0c40ec5

case "$VARIANT" in
    node) name=tenzro-node-cvm-x86_64; profile="" ;;
    prover) name=tenzro-node-cvm-x86_64-prover; profile=prover
        [ -x "${PROVER_BIN:-}" ] || { echo "REFUSING: the prover image needs PROVER_BIN (tenzro-finality-prover, x86_64, without cuda)"; exit 1; } ;;
    *) echo "REFUSING: unknown variant $VARIANT (node or prover)"; exit 1 ;;
esac
[ -f "$ARCHIVE" ] || { echo "REFUSING: no archive $ARCHIVE"; exit 1; }
case "$(basename "$ARCHIVE")" in
    tenzro-node-linux-x86_64-cpu.tar.gz) ;;
    *) echo "REFUSING: the image carries the x86_64 CPU node (tenzro-node-linux-x86_64-cpu.tar.gz)"; exit 1 ;;
esac

repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
. scripts/release/lib.sh
CT=$(release_container)
epoch=${SOURCE_DATE_EPOCH:-$(release_epoch "$REF")}
mkdir -p "$DIST"
DIST=$(cd "$DIST" && pwd)

# The work tree holds the image being built (several GB for the prover image):
# on the dist disk, not in a memory-backed /tmp.
work=$(mktemp -d -p "$DIST" .cvm-build.XXXXXX)
trap 'rm -rf "${work:?}"' EXIT
mkdir -p "$work/stage/usr/bin" "$work/sandbox/etc/apt/sources.list.d" "$work/sandbox/etc/apt/apt.conf.d" "$work/out" "$work/ws"

# The node and CLI, exactly as released.
tar -xzf "$ARCHIVE" -C "$work"
install -m 0755 "$work/tenzro-node-linux-x86_64-cpu/bin/tenzro-node" "$work/stage/usr/bin/tenzro-node"
install -m 0755 "$work/tenzro-node-linux-x86_64-cpu/bin/tenzro" "$work/stage/usr/bin/tenzro"
rm -rf "${work:?}/tenzro-node-linux-x86_64-cpu"
if [ "$VARIANT" = prover ]; then
    install -m 0755 "$PROVER_BIN" "$work/stage/usr/bin/tenzro-finality-prover"
    # The container reference the prover was built with.
    ref=$(strings "$PROVER_BIN" | grep -o 'risczero/risc0-groth16-prover@sha256:[0-9a-f]\{64\}' | sort -u)
    [ "$(printf '%s\n' "$ref" | wc -l)" = 1 ] && [ -n "$ref" ] || { echo "REFUSING: PROVER_BIN names no single Groth16 prover image"; exit 1; }
    mkdir -p "$work/stage/usr/share/tenzro"
    printf 'docker.io/%s\n' "$ref" > "$work/stage/usr/share/tenzro/groth16-prover.ref"
fi

# Every package from one snapshot: the image's and the build tools'. Plain
# HTTP, as apt checks every index against the Debian archive keys.
for suite in "debian trixie" "debian trixie-updates" "debian-security trixie-security"; do
    set -- $suite
    printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/%s/%s/\nSuites: %s\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\n' "$1" "$SNAPSHOT" "$2"
done > "$work/sandbox/etc/apt/sources.list.d/mkosi.sources"
printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "5";\n' > "$work/sandbox/etc/apt/apt.conf.d/50-snapshot"

cat > "$work/build.sh" <<'IN'
set -euo pipefail
rm -f /etc/apt/sources.list.d/*
cp /work/sandbox/etc/apt/sources.list.d/mkosi.sources /etc/apt/sources.list.d/debian.sources
cp /work/sandbox/etc/apt/apt.conf.d/50-snapshot /etc/apt/apt.conf.d/
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    mkosi systemd-ukify systemd-repart systemd-boot-efi erofs-utils dosfstools mtools e2fsprogs \
    cryptsetup-bin libcryptsetup12 apt debian-archive-keyring ca-certificates zstd cpio kmod \
    python3-pefile skopeo binutils >/dev/null
if [ -s /work/stage/usr/share/tenzro/groth16-prover.ref ]; then
    skopeo copy --quiet --preserve-digests "docker://$(cat /work/stage/usr/share/tenzro/groth16-prover.ref)" \
        dir:/work/stage/usr/share/tenzro/groth16-prover
fi
find /work/stage -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
cp -a /src/scripts/release/cvm /work/cvm
cd /work/cvm
mkosi --source-date-epoch "$SOURCE_DATE_EPOCH" ${PROFILE:+--profile "$PROFILE"} \
    --sandbox-tree /work/sandbox --extra-tree /work/stage \
    --workspace-directory /work/ws ${CACHE:+--cache-directory /cache} --output-dir /work/out --force build
# A rootful runtime leaves root-owned files; hand the work tree back.
[ -z "${HOST_UID:-}" ] || chown -R "$HOST_UID:$HOST_GID" /work
IN

owner=()
[ "$(basename "$CT")" = docker ] && owner=(-e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)")
"$CT" run --rm --privileged --network=host "${owner[@]}" \
    -e SOURCE_DATE_EPOCH="$epoch" -e PROFILE="$profile" \
    ${CVM_CACHE:+-e CACHE=1 -v "$CVM_CACHE:/cache"} \
    -v "$repo:/src:ro" -v "$work:/work" \
    "$BASE_IMAGE" bash /work/build.sh

out=$work/out
image=$(basename "$(ls "$out"/*.raw)" .raw)
cp "$out/$image.raw" "$DIST/$name.raw"
cp "$out/$image.efi" "$DIST/$name.efi"

# The cloud image archive: the disk as disk.raw in a sparse oldgnu tar.
cp --sparse=always "$DIST/$name.raw" "$work/disk.raw"
touch -d "@$epoch" "$work/disk.raw"
tar --format=oldgnu -S --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
    -C "$work" -cf - disk.raw | gzip -9n > "$DIST/$name.gce.tar.gz"

python3 scripts/release/cvm-measure.py image --disk "$DIST/$name.raw" --uki "$DIST/$name.efi" \
    > "$DIST/$name.measurements.json"
python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["uki"]["roothash"])' \
    "$DIST/$name.measurements.json" > "$DIST/$name.roothash"
( cd "$DIST" && sha256sum "$name.raw" "$name.efi" "$name.roothash" "$name.gce.tar.gz" "$name.measurements.json" )
echo "BUILD OK: $DIST/$name.raw"
