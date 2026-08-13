# Tenzro machine-class base images

Base filesystems for the `machine`-class deploy pipeline. The node's
`tenzro-machine-builder` overlays a built app onto one of these, installs the
static `tenzro-initagent` at `/sbin/tenzro-initagent`, writes
`/etc/tenzro/run.json`, and bakes the result into a rootless `rootfs.ext4` that
boots on the operator's `vmlinux` with `init=/sbin/tenzro-initagent`.

## The base contract

A base must provide, and nothing more:

- an unprivileged `app` user (uid/gid **10001**) in `/etc/passwd` (for the
  run-spec `user`);
- empty mountpoint dirs the init mounts pseudo-filesystems onto: `/proc`,
  `/sys`, `/dev`, `/tmp`, `/run`;
- an `/app` working directory and a `/sbin` (the init is installed there);
- the language runtime (`node`, `python`, or none for static).

The base carries **no app, no run.json, and no entrypoint** — the microVM boots
the init directly and the init execs the app per `run.json`.

## The three bases

| name              | runtime            | use                                   |
|-------------------|--------------------|---------------------------------------|
| `base-node20`     | Node.js 20         | Node / Next server apps               |
| `base-python312`  | Python 3.12        | FastAPI / Flask / Django etc.         |
| `base-static`     | BusyBox only       | static Go / Rust-musl / Zig binaries  |

A fully self-contained static binary can also deploy with `base = none` and skip
a base entirely.

## Building the static init

The init must be a fully-static musl binary so it runs as PID 1 in a bare
rootfs:

```sh
rustup target add x86_64-unknown-linux-musl   # (or aarch64-unknown-linux-musl)
cargo build -p tenzro-initagent --release --target x86_64-unknown-linux-musl
# -> target/x86_64-unknown-linux-musl/release/tenzro-initagent
```

Point the node at it: `export TENZRO_INITAGENT_BIN=/path/to/tenzro-initagent`.

## Two ways the node consumes a base

1. **OCI pull by digest** (node feature `machine-builder-oci`): publish the bases
   to the Tenzro registry and reference them by pinned `sha256` digest.

   ```sh
   REGISTRY=registry.tenzro.network ./build-and-publish.sh publish
   # prints PINNED base-node20: registry.tenzro.network/tenzro/base-node20@sha256:...
   ```

2. **Pre-unpacked directory** (node feature `machine-builder`, no registry):
   export each base to a directory and point the node at it.

   ```sh
   ./build-and-publish.sh export ./bases
   export TENZRO_MACHINE_BASES_DIR=$(pwd)/bases
   ```

   A `build.base = {type:"dir", name:"base-node20"}` then resolves to
   `$TENZRO_MACHINE_BASES_DIR/base-node20`.

## Note

Building/hosting the images needs a container tool + a registry, so it is
scripted here and kept out of the Rust build. The node code degrades honestly if
neither a base dir nor the OCI feature is available.
