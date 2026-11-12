#!/usr/bin/env bash
# Builds the Tenzro Windows MSI from a signed release archive.
#
# usage: build-msi.sh <dist-dir> <out-dir>
#
#   <dist-dir>  directory holding tenzro-node-windows-x86_64-*.zip (read only)
#   <out-dir>   where the MSI is written (not the dist directory)
#
# The archive is copied to a Windows build machine, repackaged there with
# WiX v4 (build-msi.ps1) and the MSI is copied back. Nothing in <dist-dir> is
# modified.
#
# environment:
#   TZ_WIN_HOST      ssh target of the Windows machine, for example user@host (required)
#   TZ_WIN_JUMP      optional ssh jump host (ProxyJump) used to reach it
#   TZ_WIN_SCRATCH   scratch directory on the Windows machine (default C:/tmp/tz-pkg-msi)
#   TZ_ZIP           archive file name inside <dist-dir> (default
#                    tenzro-node-windows-x86_64-cuda.zip)
#   TZ_VERSION       MSI version (default: the version of the node in this repository)
#   TZ_SOURCE_COMMIT, TZ_PUBLIC_COMMIT   recorded in the MSI and PROVENANCE.txt (defaults: the
#                    commit in the archive's buildenv.json, and the commit named by
#                    provenance-*.intoto.json beside the archive)
#   TZ_COMPRESSION   low | medium | high (default high)
set -euo pipefail

dist=${1:?usage: build-msi.sh <dist-dir> <out-dir>}
out=${2:?usage: build-msi.sh <dist-dir> <out-dir>}
host=${TZ_WIN_HOST:?set TZ_WIN_HOST to the ssh target of the Windows build machine}
scratch=${TZ_WIN_SCRATCH:-C:/tmp/tz-pkg-msi}
compression=${TZ_COMPRESSION:-high}

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
for f in LICENSE NOTICE; do [ -f "$root/$f" ] || { echo "missing $root/$f" >&2; exit 1; }; done

zip=${TZ_ZIP:-tenzro-node-windows-x86_64-cuda.zip}
[ -f "$dist/$zip" ] || { echo "no such archive: $dist/$zip" >&2; exit 1; }
version=${TZ_VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/crates/tenzro-node/Cargo.toml" | head -1)}
[ -n "$version" ] || { echo "no version: set TZ_VERSION" >&2; exit 1; }
src_commit=${TZ_SOURCE_COMMIT:-$(jq -r '.commit // empty' "$dist/${zip%.zip}.buildenv.json" 2>/dev/null || true)}
src_commit=${src_commit:-unknown}
pub_commit=${TZ_PUBLIC_COMMIT:-$(jq -r '.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit // empty' "$dist"/provenance-*.intoto.json 2>/dev/null | head -1 || true)}
pub_commit=${pub_commit:-unknown}
mkdir -p "$out"

ssh_opts=(-o BatchMode=yes -o ServerAliveInterval=30)
[ -n "${TZ_WIN_JUMP:-}" ] && ssh_opts+=(-o "ProxyJump=$TZ_WIN_JUMP")
winsh() { ssh "${ssh_opts[@]}" "$host" "$@"; }
winpath() { printf '%s' "$1" | sed 's|/|\\|g'; }

zip_sha=$(sha256sum "$dist/$zip" | cut -d' ' -f1)
echo "archive: $zip  sha256 $zip_sha"

# scratch is removed on exit, success or not
cleanup() { winsh "powershell -NoProfile -Command \"Remove-Item -LiteralPath '$(winpath "$scratch")' -Recurse -Force -ErrorAction SilentlyContinue\"" >/dev/null 2>&1 || true; }
trap cleanup EXIT

winsh "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$(winpath "$scratch")\\pkg','$(winpath "$scratch")\\out' | Out-Null\""
scp "${ssh_opts[@]}" -q "$here"/Tenzro.wxs "$here"/build-msi.ps1 "$here"/tenzro-check.ps1 "$here"/tenzro-check.cmd \
    "$here"/tenzro-terminal.cmd "$root"/LICENSE "$root"/NOTICE "$host:$scratch/pkg/"
scp "${ssh_opts[@]}" -q "$dist/$zip" "$host:$scratch/$zip"

msi="tenzro-$version-windows-x86_64-cuda.msi"
w=$(winpath "$scratch")
winsh "powershell -NoProfile -ExecutionPolicy Bypass -File $w\\pkg\\build-msi.ps1 -ZipPath $w\\$zip -ExpectedZipSha256 $zip_sha -OutMsi $w\\out\\$msi -WorkDir $w\\work -Version $version -SourceCommit $src_commit -PublicCommit $pub_commit -Compression $compression"

scp "${ssh_opts[@]}" -q "$host:$scratch/out/$msi" "$out/$msi"
echo "wrote $out/$msi"
sha256sum "$out/$msi"
