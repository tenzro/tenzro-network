#!/usr/bin/env bash
# Build + publish the Tenzro machine-class base images, and/or export a base to a
# pre-unpacked directory for the node's dir-base path.
#
# Two consumption modes on the node (see crates/tenzro-node/src/machine_build.rs):
#   1. OCI (feature machine-builder-oci): the node pulls a base by pinned digest
#      from the registry at build time. Use `publish` here to get the digests.
#   2. Dir (feature machine-builder): the operator pre-unpacks a base into
#      $TENZRO_MACHINE_BASES_DIR/<name>. Use `export` here. No registry needed.
#
# Usage:
#   REGISTRY=registry.tenzro.network ./build-and-publish.sh publish
#   ./build-and-publish.sh export ./bases        # -> ./bases/base-node20, ...
#
# Requires: docker (or podman via DOCKER=podman) for build; skopeo OR docker for
# export. Nothing here runs as part of the Rust build — bases need a registry /
# a host with a container tool, which is out of the node's critical path.
set -euo pipefail

DOCKER="${DOCKER:-docker}"
REGISTRY="${REGISTRY:-registry.tenzro.network}"
NAMESPACE="${NAMESPACE:-tenzro}"
TAG="${TAG:-v1}"
HERE="$(cd "$(dirname "$0")" && pwd)"

BASES=(base-node20 base-python312 base-static)

build_one() {
  local name="$1"
  local ref="${REGISTRY}/${NAMESPACE}/${name}:${TAG}"
  echo ">> building ${ref}" >&2
  "$DOCKER" build -f "${HERE}/${name}.Dockerfile" -t "${ref}" "${HERE}"
  echo "${ref}"
}

cmd_publish() {
  for name in "${BASES[@]}"; do
    ref="$(build_one "$name")"
    echo ">> pushing ${ref}" >&2
    "$DOCKER" push "${ref}"
    # Print the pinned digest a machine deploy should reference.
    digest="$("$DOCKER" inspect --format='{{index .RepoDigests 0}}' "${ref}" 2>/dev/null || true)"
    echo "PINNED ${name}: ${digest:-<run: docker inspect --format '{{index .RepoDigests 0}}' ${ref}>}"
  done
}

# Flatten an image's filesystem into a directory (rootless-friendly via a stopped
# container export). This is what TENZRO_MACHINE_BASES_DIR/<name> should hold.
cmd_export() {
  local out="${1:?usage: export <dir>}"
  mkdir -p "$out"
  for name in "${BASES[@]}"; do
    ref="$(build_one "$name")"
    dest="${out}/${name}"
    echo ">> exporting ${ref} -> ${dest}" >&2
    rm -rf "$dest"; mkdir -p "$dest"
    cid="$("$DOCKER" create "${ref}")"
    "$DOCKER" export "$cid" | tar -x -C "$dest"
    "$DOCKER" rm "$cid" >/dev/null
    echo "EXPORTED ${name}: ${dest}"
  done
  echo ">> set on the node: export TENZRO_MACHINE_BASES_DIR=$(cd "$out" && pwd)" >&2
}

case "${1:-}" in
  publish) cmd_publish ;;
  export)  cmd_export "${2:-./bases}" ;;
  *) echo "usage: $0 {publish|export <dir>}" >&2; exit 2 ;;
esac
