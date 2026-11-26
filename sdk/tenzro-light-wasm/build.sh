#!/bin/sh
# Builds the WebAssembly light client and its JavaScript glue into pkg/
# (CommonJS for Node; `--target web` for a browser bundle). Needs the
# wasm32-unknown-unknown target and wasm-bindgen-cli at the version pinned
# in Cargo.toml.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
target=${1:-nodejs}
cd "$root"
# wasm-bindgen reads the target_features section, which the release profile's strip removes
CARGO_PROFILE_RELEASE_STRIP=none cargo build --locked --release -p tenzro-light-wasm --target wasm32-unknown-unknown
wasm-bindgen --target "$target" --out-dir "$here/pkg" \
    target/wasm32-unknown-unknown/release/tenzro_light_wasm.wasm
