#!/usr/bin/env bash
# Build tenzro-node for a node tier (docs/NODE.md, "Node tiers").
#
#   scripts/build-tier.sh edge [--cpu <name>] [--size] [--target <triple>]
#   scripts/build-tier.sh validator [--target <triple>]
#   scripts/build-tier.sh provider [<gpu backend>] [--target <triple>]
#
# edge       the light build (no inference) under the `edge` profile. --cpu
#            tunes it for one processor and the binary then runs on that
#            processor family only: cortex-a76 for a Raspberry Pi 5,
#            cortex-a72 for a Pi 4. Without --cpu it runs on any aarch64 or
#            x86_64 machine. --size optimises for size (opt-level "s"):
#            28% smaller, with no loss measured in sync or RPC load on the test host
#            (docs/NODE.md).
# validator  the light build under the release profile: consensus, storage,
#            networking, RPC; no inference.
# provider   the full build under the release profile, with a GPU backend
#            feature (cuda, rocm, vulkan, metal, ...) when one is named.
#
# The binary is copied to dist/tenzro-node-<tier>[-<cpu>][-size][-<gpu>]-<arch>.
# Build on the target architecture, or pass --target with a toolchain for it.
set -euo pipefail
cd "$(dirname "$0")/.."

tier=${1:-}; shift || true
cpu="" target="" gpu="" size=""
while [ $# -gt 0 ]; do
  case $1 in
    --cpu) cpu=$2; shift 2 ;;
    --target) target=$2; shift 2 ;;
    --size) size=1; shift ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) gpu=$1; shift ;;
  esac
done

args=(build -p tenzro-node --bin tenzro-node)
case $tier in
  edge) args+=(--profile edge --no-default-features); profile_dir=edge ;;
  validator) args+=(--release --no-default-features --features mcp-output-schemas); profile_dir=release ;;
  provider) args+=(--release); profile_dir=release
            [ -n "$gpu" ] && args+=(--features "$gpu") ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
[ -n "$gpu" ] && [ "$tier" != provider ] && { echo "a GPU backend is for the provider tier only" >&2; exit 2; }
[ -n "$cpu" ] && [ "$tier" != edge ] && { echo "--cpu is for the edge tier only" >&2; exit 2; }
[ -n "$target" ] && args+=(--target "$target")
[ -n "$size" ] && [ "$tier" != edge ] && { echo "--size is for the edge tier only" >&2; exit 2; }
[ -n "$size" ] && export CARGO_PROFILE_EDGE_OPT_LEVEL=s

if [ -n "$cpu" ]; then
  # RUSTFLAGS replaces the target's rustflags in .cargo/config.toml, so the
  # path remapping there is repeated here.
  export RUSTFLAGS="--remap-path-prefix=/build=/tenzro --remap-path-prefix=/usr/local/cargo=/cargo --remap-path-prefix=/root/.cargo=/cargo -C target-cpu=$cpu"
fi

cargo "${args[@]}"

arch=${target%%-*}; [ -n "$arch" ] || arch=$(uname -m)
out_dir=target; [ -n "${CARGO_TARGET_DIR:-}" ] && out_dir=$CARGO_TARGET_DIR
[ -n "$target" ] && out_dir=$out_dir/$target
name=tenzro-node-$tier${cpu:+-$cpu}${size:+-size}${gpu:+-$gpu}-$arch
mkdir -p dist
cp "$out_dir/$profile_dir/tenzro-node" "dist/$name"
echo "dist/$name $(stat -c %s "dist/$name" 2>/dev/null || stat -f %z "dist/$name") bytes"
