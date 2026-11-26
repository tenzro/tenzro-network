#!/bin/bash
# Tests of scripts/release/update-channel.py against `tenzro update` itself: a release of stand-in archives is
# written to a channel, signed with keys made for the run (openssl signs the .tosign files the way cosign
# sign-blob does: ECDSA P-256 over SHA-256 of the file, DER, base64), sealed, and read by the tenzro binaries
# given. Every binary must accept the channel; the first is the tree's own and is also tested on the build
# kinds; any further one (a released tenzro) must still find its CPU update in it.
#   scripts/release/tests/update-channel.sh <tenzro> [<released tenzro> ...]
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
PUB="$HERE/../update-channel.py"
[ $# -ge 1 ] || { echo "usage: update-channel.sh <tenzro> [<released tenzro> ...]"; exit 2; }
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
pass=0 failn=0
ok() { pass=$((pass+1)); echo "PASS  $1"; }
no() { failn=$((failn+1)); echo "FAIL  $1"; [ -n "${2:-}" ] && echo "$2" | sed 's/^/        /' | head -20; }
case "$(uname -m)" in x86_64) A=x86_64 ;; aarch64) A=aarch64 ;; *) echo "SKIP: $(uname -m)"; exit 0 ;; esac
NATIVE="$A-linux"

# keys of the run: one for targets, one for timestamp, and the trusted keys file of the clients
for k in targets timestamp; do
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$W/$k.key" 2>/dev/null
    openssl pkey -in "$W/$k.key" -pubout -out "$W/$k.pub" 2>/dev/null
done
sec1() { openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | tail -c 65 | od -An -tx1 | tr -d ' \n'; }
printf '{"targets":["%s"],"timestamp":["%s"]}\n' "$(sec1 "$W/targets.pub")" "$(sec1 "$W/timestamp.pub")" > "$W/trusted.json"
sign() { # sign DOC KEY: the cosign-style signature of CHANNEL/DOC.tosign, then seal
    openssl dgst -sha256 -sign "$W/$2.key" "$W/channel/$1.tosign" | openssl base64 -A > "$W/$1.sig"
    python3 -I "$PUB" seal --channel "$W/channel" --doc "$1" --public-key "$W/$2.pub" --signature "$W/$1.sig" >/dev/null
}

# the release: stand-in binaries that answer like tenzro and tenzro-node, packed as the release builds pack them
stand_in() { # stand_in FILE LABEL
    printf '#!/bin/sh\ncase "$1" in\n  --version) echo "tenzro 0.2.2" ;;\n  hardware) echo "build: %s"; echo "gpus: 0"; echo "startup: ok" ;;\nesac\n' "$2" > "$1"
    chmod +x "$1"
}
mkdir -p "$W/dist"
pack() { # pack OS KIND
    n="tenzro-node-$1-$A-$2"; d="$W/stage/$n"; rm -rf "$W/stage"; mkdir -p "$d/bin"
    sfx=""; [ "$1" = windows ] && sfx=.exe
    stand_in "$d/bin/tenzro$sfx" "$2"; stand_in "$d/bin/tenzro-node$sfx" "$2"
    [ "$2" = cuda ] && { mkdir -p "$d/lib"; echo "new onnx" > "$d/lib/libonnxruntime.so.1.22.0"
        ln -s libonnxruntime.so.1.22.0 "$d/lib/libonnxruntime.so.1"; }
    [ "$1" = windows ] && echo "a dll" > "$d/bin/onnxruntime.dll"
    mkdir -p "$d/share/console/src"; echo "new console" > "$d/share/console/index.html"; echo "app" > "$d/share/console/src/app.js"
    if [ "$1" = windows ]; then
        python3 -I -c 'import sys, zipfile, os
z = zipfile.ZipFile(sys.argv[1], "w")
for root, _, files in os.walk(sys.argv[2]):
    for f in files:
        p = os.path.join(root, f); z.write(p, os.path.relpath(p, sys.argv[3]))' "$W/dist/$n.zip" "$d" "$W/stage"
    else
        tar -czf "$W/dist/$n.tar.gz" -C "$W/stage" "$n"
    fi
}
pack linux cpu; pack linux cuda; pack linux vulkan; pack windows cpu; pack macos metal
cp "$W/dist/tenzro-node-linux-$A-cpu.tar.gz" "$W/dist/tenzro-node-linux-$A-cpu-debug.tar.gz"
(cd "$W/dist" && sha256sum ./*.tar.gz ./*.zip | sed 's# \./# #' > SHA256SUMS)

# publish
out=$(python3 -I "$PUB" targets --dist "$W/dist" --channel "$W/channel" --release 0.2.2 --version 4 --class C0 \
    --description "Stand-in release" 2>&1) && rc=0 || rc=$?
listed=$(echo "$out" | grep -c -E '^[a-z0-9_-]+ +tenzro(-node)? +[0-9a-f]{64}$')
[ "$rc" = 0 ] && [ "$listed" = 10 ] && ok "five archives give ten files (the debug archive is left out)" || no "targets: rc=$rc, $listed files" "$out"
for p in "$NATIVE" "$NATIVE-cuda" "$NATIVE-vulkan" "$A-windows" "$A-macos"; do
    [ -d "$W/channel/0.2.2/$p" ] || no "no folder for platform $p"
done
[ -f "$W/channel/0.2.2/$A-windows/tenzro-node.exe" ] && ok "a Windows binary keeps its .exe name in the channel" || no "Windows binary path"
sign targets targets
[ -f "$W/channel/libraries.tosign" ] && sign libraries targets
[ -f "$W/channel/libraries.json" ] && ok "the CUDA and Windows libraries are in a libraries document" || no "no libraries document"
python3 -I "$PUB" timestamp --channel "$W/channel" --version 11 >/dev/null
sign timestamp timestamp
[ -f "$W/channel/targets.json" ] && [ -f "$W/channel/timestamp.json" ] && [ ! -e "$W/channel/targets.tosign" ] \
    && ok "sealed: targets.json and timestamp.json, no bytes to sign left behind" || no "sealing"

# a signature by another key is refused before anything is published
python3 -I "$PUB" targets --dist "$W/dist" --channel "$W/channel2" --release 0.2.2 --version 4 --class C0 --description x >/dev/null
openssl dgst -sha256 -sign "$W/timestamp.key" "$W/channel2/targets.tosign" | openssl base64 -A > "$W/wrong.sig"
if python3 -I "$PUB" seal --channel "$W/channel2" --doc targets --public-key "$W/targets.pub" --signature "$W/wrong.sig" >/dev/null 2>&1 \
    || [ -e "$W/channel2/targets.json" ]; then no "a signature by another key was sealed"; else ok "a signature by another key is refused"; fi
# a release is written once
if python3 -I "$PUB" targets --dist "$W/dist" --channel "$W/channel" --release 0.2.2 --version 5 --class C0 --description x >/dev/null 2>&1; then
    no "a release folder was written twice"; else ok "a release folder is written once"; fi
# an archive that does not match SHA256SUMS is refused
cp -r "$W/dist" "$W/dist3"; printf x >> "$W/dist3/tenzro-node-linux-$A-vulkan.tar.gz"
if python3 -I "$PUB" targets --dist "$W/dist3" --channel "$W/channel3" --release 0.2.2 --version 4 --class C0 --description x >/dev/null 2>&1; then
    no "an archive that does not match SHA256SUMS was published"; else ok "an archive that does not match SHA256SUMS is refused"; fi

# an archive whose lib/ holds what an update cannot carry is refused, not trimmed
bad_lib() { # bad_lib LABEL: the CUDA archive rebuilt with one more entry made by the commands that follow on stdin
    rm -rf "$W/badstage"; mkdir -p "$W/badstage" "$W/bad-$1"; tar -xzf "$W/dist/tenzro-node-linux-$A-cuda.tar.gz" -C "$W/badstage"
    (cd "$W/badstage/tenzro-node-linux-$A-cuda" && sh)
    cp "$W/dist/"*.tar.gz "$W/dist/"*.zip "$W/bad-$1/"
    tar -czf "$W/bad-$1/tenzro-node-linux-$A-cuda.tar.gz" -C "$W/badstage" "tenzro-node-linux-$A-cuda"
    (cd "$W/bad-$1" && sha256sum ./*.tar.gz ./*.zip | sed 's# \./# #' > SHA256SUMS)
    if python3 -I "$PUB" targets --dist "$W/bad-$1" --channel "$W/channel-$1" --release 0.2.2 --version 4 --class C0 --description x >"$W/bad-$1.out" 2>&1; then
        no "an archive with $1 in lib/ was published"
    else grep -q "REFUSING" "$W/bad-$1.out" && ok "an archive with $1 in lib/ is refused" || no "$1: no refusal" "$(cat "$W/bad-$1.out")"; fi
}
echo 'ln lib/libonnxruntime.so.1.22.0 lib/libonnxruntime-copy.so' | bad_lib "a hard link"
echo 'mkdir lib/sub && echo x > lib/sub/libx.so' | bad_lib "a subfolder"

# the clients: an install at 0.2.1 of each kind, updated from the channel
install_at() { # install_at DIR FOLDER: a versioned install whose current release folder is FOLDER
    mkdir -p "$1/versions/$2/bin"
    printf '#!/bin/sh\necho "tenzro 0.2.1"\n' > "$1/versions/$2/bin/tenzro"
    printf '#!/bin/sh\necho old\n' > "$1/versions/$2/bin/tenzro-node"
    chmod +x "$1/versions/$2/bin/"*
    echo 0.2.1 > "$1/versions/$2/RELEASE"
    case "$2" in *-cuda-*) mkdir -p "$1/versions/$2/lib"; echo "old onnx" > "$1/versions/$2/lib/libonnxruntime.so.1.20.0" ;; esac
    mkdir -p "$1/versions/$2/share/console/src"; echo "old console" > "$1/versions/$2/share/console/index.html"
    echo "old" > "$1/versions/$2/share/console/src/old.js"
    ln -s "versions/$2" "$1/current"
}
client() { # client TENZRO LABEL FOLDER [platform]: check then apply; output in OUT, status RC
    d="$W/c-$2"; install_at "$d/inst" "$3"
    args=(--channel "$W/channel" --trusted-keys "$W/trusted.json" --data-dir "$d/data" --install-dir "$d/inst")
    [ -n "${4:-}" ] && args+=(--platform "$4")
    OUT=$("$1" update check "${args[@]}" 2>&1; echo "---"; "$1" update apply "${args[@]}" 2>&1); RC=$?
    NODE=$(cat "$d/inst/current/bin/tenzro-node" 2>/dev/null | sed -n 's/.*echo "build: \([a-z]*\)".*/\1/p')
    BUILD=$(cat "$d/inst/current/BUILD" 2>/dev/null)
}
NEW=$1; shift
client "$NEW" new-cpu "tenzro-node-linux-$A-cpu-0123456789ab"
echo "$OUT" | grep -q "C0 update available: 0.2.2" && [ "$NODE" = cpu ] && [ "$BUILD" = cpu ] \
    && ok "this tree's tenzro takes the CPU build into a CPU install" || no "new client, cpu (node=$NODE build=$BUILD)" "$OUT"
CON="$W/c-new-cpu/inst/current/share/console"
[ "$(cat "$CON/index.html" 2>/dev/null)" = "new console" ] && [ "$(ls "$CON/src" 2>/dev/null | tr '\n' ' ')" = "app.js " ] \
    && ok "the update replaces the console whole: the new release's files, none of the old" \
    || no "console after the update: $(ls -R "$CON" 2>&1 | tr '\n' ' ')"
client "$NEW" new-cuda "tenzro-node-linux-$A-cuda-0123456789ab"
LIBS=$(ls "$W/c-new-cuda/inst/current/lib" 2>/dev/null | tr '\n' ' ')
[ "$NODE" = cuda ] && [ "$BUILD" = cuda ] && [ "$LIBS" = "libonnxruntime.so.1 libonnxruntime.so.1.22.0 " ] \
    && [ "$(cat "$W/c-new-cuda/inst/current/lib/libonnxruntime.so.1")" = "new onnx" ] \
    && ok "this tree's tenzro takes the CUDA build and its new libraries into a CUDA install" \
    || no "new client, cuda (node=$NODE build=$BUILD lib=$LIBS)" "$OUT"
client "$NEW" new-vulkan "tenzro-node-linux-$A-vulkan-0123456789ab"
[ "$NODE" = vulkan ] && ok "this tree's tenzro takes the Vulkan build into a Vulkan install" || no "new client, vulkan (node=$NODE)" "$OUT"
client "$NEW" new-edge "tenzro-node-linux-$A-edge-0123456789ab"
echo "$OUT" | grep -q "no edge build" && [ "$(cat "$W/c-new-edge/inst/current/bin/tenzro-node")" = "$(printf '#!/bin/sh\necho old')" ] \
    && ok "an edge install is refused, unchanged, by a release without an edge build" || no "new client, edge" "$OUT"
for old in "$@"; do
    # What a released tenzro does to a CUDA install: it knows no build kinds, so it takes the CPU build and
    # keeps the old lib/. Stated here as it is, for the release note (docs/UPDATE-MANIFEST.md).
    client "$old" "old-cuda-$pass" "tenzro-node-linux-$A-cuda-0123456789ab" "$NATIVE"
    OLDLIB=$(cat "$W/c-old-cuda-$((pass))/inst/current/lib/libonnxruntime.so.1.20.0" 2>/dev/null)
    [ "$NODE" = cpu ] && [ "$OLDLIB" = "old onnx" ] \
        && ok "a released tenzro ($old) puts the CPU build into a CUDA install and keeps its old lib/" \
        || no "released client on a CUDA install (node=$NODE lib=$OLDLIB)" "$OUT"
    client "$old" "old-$pass" "0.2.1" "$NATIVE"
    echo "$OUT" | grep -q "C0 update available: 0.2.2" && [ "$NODE" = cpu ] \
        && ok "a released tenzro ($old) still takes its update from the channel" || no "released client $old (node=$NODE)" "$OUT"
done
echo "$pass passed, $failn failed"
exit "$failn"
