# Shared by the release build scripts. Sourced, not run.
#
# Every artifact is an archive named tenzro-node-<os>-<arch>-<flavour>, holding
# bin/tenzro-node, bin/tenzro (the CLI) and, when the node links shared
# libraries that are not part of the operating system, lib/ (the node's rpath
# includes $ORIGIN/../lib). Beside it the build writes
# <artifact>.buildenv.json: the source commit, toolchain, container image,
# features and builder, so a second build of the same commit can be compared
# byte for byte.

# Commit time, used as the timestamp of every file in an archive so the same
# commit packs to the same bytes.
release_epoch() { # ref
    git log -1 --format=%ct "$1"
}

# The toolchain pinned in rust-toolchain.toml. A build host with another
# version is refused rather than recorded.
release_rust() {
    sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml
}

# Deterministic tar.gz of a staging directory: sorted names, fixed owner, the
# commit time on every entry, no gzip timestamp.
release_pack() { # staging-dir out.tar.gz epoch
    local dir=$1 out=$2 epoch=$3
    # Fixed modes too: the builder's umask must not reach the archive.
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" --mode='u=rwX,go=rX' \
        --format=gnu -C "$(dirname "$dir")" -cf - "$(basename "$dir")" | gzip -9n > "$out"
}

release_buildenv() { # out.json artifact commit flavour target features image
    jq -n \
        --arg artifact "$2" --arg commit "$3" --arg flavour "$4" --arg target "$5" \
        --arg features "$6" --arg image "$7" --arg rust "$(release_rust)" \
        --arg builder "$(uname -s)-$(uname -m)" --arg built "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg lock "$(git show "$3:Cargo.lock" | release_sha256)" \
        '{artifact: $artifact, commit: $commit, flavour: $flavour, target: $target,
          features: $features, rust: $rust, cargo_lock_sha256: $lock,
          container_image: $image, builder: $builder, built: $built, locked: true}' > "$1"
}

release_sha256() { # stdin -> hex digest
    if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

# Picks the container runtime: podman or docker, whichever is installed.
release_container() {
    if [ -n "${CONTAINER:-}" ]; then echo "$CONTAINER"; return; fi
    for c in podman docker; do command -v "$c" >/dev/null && { echo "$c"; return; }; done
    echo "REFUSING: neither podman nor docker found" >&2; return 1
}
