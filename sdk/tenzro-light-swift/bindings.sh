#!/bin/sh
# Builds sdk/tenzro-ffi for this host and writes its Swift bindings into the
# package: the Swift source into Sources/TenzroLight, the C header and module
# map into Sources/TenzroLightFFI/include.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
case "$(uname -s)" in
    Darwin) lib=libtenzro_ffi.dylib ;;
    *) lib=libtenzro_ffi.so ;;
esac
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
cd "$root"
cargo build --locked --release -p tenzro-ffi
cargo run --locked --release -p tenzro-ffi --features bindgen --bin uniffi-bindgen -- \
    generate --library "target/release/$lib" --language swift --no-format --out-dir "$out"
mkdir -p "$here/Sources/TenzroLight" "$here/Sources/TenzroLightFFI/include"
cp "$out/TenzroLight.swift" "$here/Sources/TenzroLight/"
cp "$out/TenzroLightFFI.h" "$here/Sources/TenzroLightFFI/include/"
cp "$out/TenzroLightFFI.modulemap" "$here/Sources/TenzroLightFFI/include/module.modulemap"
