#!/usr/bin/env bash
# Build the container image that has rpmbuild (Fedora). Usage: build-rpm-image.sh [image-name]
set -euo pipefail
image=${1:-tenzro-rpmbuild}
ctr=${CONTAINER:-$(command -v podman || command -v docker)}
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
printf 'FROM registry.fedoraproject.org/fedora:latest\nRUN dnf -y install rpm-build zstd binutils && dnf clean all\n' > "$d/Containerfile"
"$ctr" build -t "$image" "$d"
