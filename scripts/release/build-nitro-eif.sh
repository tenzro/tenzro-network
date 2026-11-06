#!/bin/bash
# Build the AWS Nitro Enclaves image (EIF) of the node from the released Linux
# x86_64 CPU node archive, and publish its PCR0, PCR1 and PCR2. Nothing of the
# node is compiled: the binary is taken from the archive as it is.
#
# The enclave boots the Nitro kernel, init and NSM driver that AWS publishes
# with the Nitro Enclaves CLI (pinned below by tag and sha256). The bootstrap
# ramdisk holds init and the NSM driver; the application ramdisk holds
# rootfs/ (the node, the shared libraries it links, CA certificates) and the
# cmd and env files init starts it with. Both ramdisks are written here as
# uncompressed newc archives with sorted names, owner 0 and the commit time of
# REF on every entry, so the PCRs are a function of the inputs alone.
#
#   PCR0  the whole image (kernel, command line, both ramdisks)
#   PCR1  the kernel, command line and bootstrap ramdisk
#   PCR2  the application ramdisk
#
# Outputs, in DIST: tenzro-node-nitro-x86_64.eif and
# tenzro-node-nitro-x86_64.pcrs.json.
#
# Usage: scripts/release/build-nitro-eif.sh <node-archive.tar.gz> [dist-dir]
# SOURCE_DATE_EPOCH, when set, replaces the commit time (to rebuild on a host
# without the repository history).
set -euo pipefail

ARCHIVE=${1:?usage: build-nitro-eif.sh <tenzro-node-linux-x86_64-cpu.tar.gz> [dist-dir]}
DIST=${2:-$HOME/dist}
REF=${REF:-HEAD}
SNAPSHOT=${SNAPSHOT:-20261005T000000Z}
BASE_IMAGE=docker.io/library/debian@sha256:bcf83fd8af414eda0c0a99d25a4e61dedd88e7aac7f7bc519d04555ff0c40ec5
RUST_IMAGE=docker.io/library/rust:1.99.1-slim-bookworm@sha256:ed2c95ca377d6571b124b05e75e01207973ded639dce7d5542eb7bcd797e32aa
EIF_BUILD_VERSION=0.2.1
NITRO_CLI_TAG=v1.5.0
NITRO_BLOBS="
210eda749c1308eb60671a579d24db5e8a3477cb7a247cf313c286b09fe2d857 bzImage
9378dea490ed6c698c3d23b346ed08e49dae52d74a59cee2673b8a7b1951fc5b bzImage.config
10d7d9dd205d4596d45997d17434f26207525f129d171a51f9859b1af9f4a07a cmdline
755e650b732777b798cb9ec243ee402bef4826f789cf01a1e453bb724207c005 init
48904e520db2541ca4378da29d85791749408febc81987ade56cc5c556bd90df nsm.ko
"

case "$(basename "$ARCHIVE")" in
    tenzro-node-linux-x86_64-cpu.tar.gz) ;;
    *) echo "REFUSING: the enclave carries the x86_64 CPU node (tenzro-node-linux-x86_64-cpu.tar.gz)"; exit 1 ;;
esac
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
. scripts/release/lib.sh
CT=$(release_container)
epoch=${SOURCE_DATE_EPOCH:-$(release_epoch "$REF")}
mkdir -p "$DIST"
DIST=$(cd "$DIST" && pwd)
name=tenzro-node-nitro-x86_64

work=$(mktemp -d -p "$DIST" .eif-build.XXXXXX)
trap 'rm -rf "${work:?}"' EXIT
mkdir -p "$work/blobs" "$work/tools"

echo "$NITRO_BLOBS" | while read -r sum file; do
    [ -n "$file" ] || continue
    curl -sfL -o "$work/blobs/$file" "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/$NITRO_CLI_TAG/blobs/x86_64/$file"
    echo "$sum  $work/blobs/$file" | sha256sum -c --quiet
done
tar -xzf "$ARCHIVE" -C "$work"

# The EIF assembler, from crates.io at a pinned version with its lock file.
"$CT" run --rm --network=host -v "$work:/work" "$RUST_IMAGE" bash -c "
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends pkg-config libssl-dev >/dev/null
    cargo install --quiet --locked --root /work/tools eif_build@$EIF_BUILD_VERSION"

printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s/\nSuites: trixie\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' \
    "$SNAPSHOT" > "$work/debian.sources"

cat > "$work/build.sh" <<'IN'
set -euo pipefail
rm -f /etc/apt/sources.list.d/*
cp /work/debian.sources /etc/apt/sources.list.d/debian.sources
echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/50-snapshot
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    libssl3t64 libstdc++6 ca-certificates python3 >/dev/null

# Application root: the node, the libraries it links, CA certificates.
r=/work/app/rootfs
mkdir -p $r/usr/bin $r/usr/lib/x86_64-linux-gnu $r/usr/lib64 $r/etc/ssl/certs \
    $r/dev $r/run $r/sys $r/var/lib/tenzro $r/proc $r/tmp
install -m 0755 /work/tenzro-node-linux-x86_64-cpu/bin/tenzro-node $r/usr/bin/tenzro-node
for lib in libc.so.6 libm.so.6 libgcc_s.so.1 libstdc++.so.6 libssl.so.3 libcrypto.so.3; do
    cp -L /usr/lib/x86_64-linux-gnu/$lib $r/usr/lib/x86_64-linux-gnu/$lib
done
cp -L /usr/lib64/ld-linux-x86-64.so.2 $r/usr/lib64/ld-linux-x86-64.so.2
cp -L /etc/ssl/certs/ca-certificates.crt $r/etc/ssl/certs/ca-certificates.crt
ln -s usr/bin $r/bin
ln -s usr/lib $r/lib
ln -s usr/lib64 $r/lib64
printf '/usr/bin/tenzro-node\n--data-dir\n/var/lib/tenzro/data\n--log-level\ninfo\n' > /work/app/cmd
printf 'PATH=/usr/bin\nSSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n' > /work/app/env

mkdir -p /work/boot/dev
install -m 0755 /work/blobs/init /work/boot/init
install -m 0755 /work/blobs/nsm.ko /work/boot/nsm.ko

python3 /src/scripts/release/newc.py /work/boot "$SOURCE_DATE_EPOCH" > /work/bootstrap.cpio
python3 /src/scripts/release/newc.py /work/app "$SOURCE_DATE_EPOCH" > /work/app.cpio
/work/tools/bin/eif_build \
    --kernel /work/blobs/bzImage --kernel_config /work/blobs/bzImage.config \
    --cmdline "$(cat /work/blobs/cmdline)" \
    --ramdisk /work/bootstrap.cpio --ramdisk /work/app.cpio \
    --name tenzro-node --version "$IMAGE_VERSION" \
    --build-time "$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%S+00:00)" \
    --output /work/out.eif > /work/eif_build.json
# A rootful runtime leaves root-owned files; hand the work tree back.
[ -z "${HOST_UID:-}" ] || chown -R "$HOST_UID:$HOST_GID" /work
IN

owner=()
[ "$(basename "$CT")" = docker ] && owner=(-e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)")
"$CT" run --rm --network=host -e SOURCE_DATE_EPOCH="$epoch" "${owner[@]}" \
    -e IMAGE_VERSION="${IMAGE_VERSION:-$(git rev-parse --short "$REF")}" \
    -v "$repo:/src:ro" -v "$work:/work" "$BASE_IMAGE" bash /work/build.sh

cp "$work/out.eif" "$DIST/$name.eif"
# eif_build prints a status line, then the measurements as JSON.
python3 - "$work/eif_build.json" > "$DIST/$name.pcrs.json" <<'PY'
import json, sys
text = open(sys.argv[1]).read()
m = json.loads(text[text.index("{"):])
out = {"HashAlgorithm": "SHA384", "PCR0": m["PCR0"], "PCR1": m["PCR1"], "PCR2": m["PCR2"]}
print(json.dumps(out, indent=2))
PY
cat "$DIST/$name.pcrs.json"
( cd "$DIST" && sha256sum "$name.eif" "$name.pcrs.json" )
echo "BUILD OK: $DIST/$name.eif"
