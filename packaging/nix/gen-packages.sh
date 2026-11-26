#!/usr/bin/env bash
# The Nix packages for a release, for a pull request to nixpkgs: tenzro (the node and the terminal
# app) and tenzro-control (Tenzro Control, the desktop app), both from the release's Linux cpu
# archives, checked against the release's SHA256SUMS. The binaries are the release's own, patched
# by autoPatchelfHook to find their libraries in the Nix store.
#
#   gen-packages.sh <dist-dir> <version> <download-url-of-the-release> <out-dir>
#
# Writes <out-dir>/tenzro/package.nix and <out-dir>/tenzro-control/package.nix. Nix checks each
# archive against the digest written here.
set -euo pipefail
dist=$(cd "${1:?usage: gen-packages.sh <dist-dir> <version> <download-url> <out-dir>}" && pwd)
ver=${2:?}; base=${3:?}; out=${4:?}
base=${base%/}
digest() {
    local s; s=$(awk -v f="$1" '$2==f {print $1}' "$dist/SHA256SUMS")
    [ -n "$s" ] || { echo "REFUSING: $dist/SHA256SUMS does not list $1" >&2; exit 1; }
    echo "$s"
}
x86_sha=$(digest tenzro-node-linux-x86_64-cpu.tar.gz); arm_sha=$(digest tenzro-node-linux-aarch64-cpu.tar.gz)
sources="  sources = {
    x86_64-linux = {
      url = \"$base/tenzro-node-linux-x86_64-cpu.tar.gz\";
      sha256 = \"$x86_sha\";
    };
    aarch64-linux = {
      url = \"$base/tenzro-node-linux-aarch64-cpu.tar.gz\";
      sha256 = \"$arm_sha\";
    };
  };"

mkdir -p "$out/tenzro" "$out/tenzro-control"
cat > "$out/tenzro/package.nix" <<EOF
{
  lib,
  stdenv,
  fetchurl,
  autoPatchelfHook,
}:

let
$sources
in
stdenv.mkDerivation {
  pname = "tenzro";
  version = "$ver";

  src = fetchurl sources.\${stdenv.hostPlatform.system};

  nativeBuildInputs = [ autoPatchelfHook ];
  buildInputs = [ stdenv.cc.cc.lib ];

  # The binaries find their network profile at <bin dir>/../share/network.
  installPhase = ''
    runHook preInstall
    mkdir -p \$out/lib/tenzro \$out/bin
    cp -a bin share \$out/lib/tenzro/
    ln -s \$out/lib/tenzro/bin/tenzro \$out/bin/tenzro
    ln -s \$out/lib/tenzro/bin/tenzro-node \$out/bin/tenzro-node
    runHook postInstall
  '';

  meta = {
    description = "Run a Tenzro node, with the tenzro terminal app";
    homepage = "https://tenzro.com";
    license = lib.licenses.asl20;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    platforms = builtins.attrNames sources;
    mainProgram = "tenzro";
  };
}
EOF
cat > "$out/tenzro-control/package.nix" <<EOF
{
  lib,
  stdenv,
  fetchurl,
  autoPatchelfHook,
  wrapGAppsHook4,
  gtk4,
  libadwaita,
}:

let
$sources
in
stdenv.mkDerivation {
  pname = "tenzro-control";
  version = "$ver";

  src = fetchurl sources.\${stdenv.hostPlatform.system};

  nativeBuildInputs = [
    autoPatchelfHook
    wrapGAppsHook4
  ];
  buildInputs = [
    gtk4
    libadwaita
  ];

  installPhase = ''
    runHook preInstall
    install -Dm755 control/tenzro-control \$out/bin/tenzro-control
    install -Dm644 control/com.tenzro.Control.desktop \$out/share/applications/com.tenzro.Control.desktop
    install -Dm644 control/com.tenzro.Control.metainfo.xml \$out/share/metainfo/com.tenzro.Control.metainfo.xml
    install -Dm644 control/com.tenzro.Control.svg \$out/share/icons/hicolor/scalable/apps/com.tenzro.Control.svg
    runHook postInstall
  '';

  meta = {
    description = "Set up and run a Tenzro node from the desktop";
    homepage = "https://tenzro.com";
    license = lib.licenses.asl20;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    platforms = builtins.attrNames sources;
    mainProgram = "tenzro-control";
  };
}
EOF
echo "$out/tenzro/package.nix"
echo "$out/tenzro-control/package.nix"
