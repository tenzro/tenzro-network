#!/usr/bin/env bash
# Write packages.json for the installer packages in a directory.
#
#   gen-packages-json.sh <dist-dir> <packages-dir>
#
# One record per package: file, sha256, size, kind, platform, arch, flavour, version,
# the archive(s) it repackages with their digests from <dist-dir>/SHA256SUMS, and the
# release and public source commits. Deb packages are also checked against the
# PACKAGE-INFO they carry (the archive digest inside must equal the one listed).
set -euo pipefail
dist=$(cd "${1:?usage: gen-packages-json.sh <dist-dir> <packages-dir>}" && pwd)
pkgs=$(cd "${2:?}" && pwd)
command -v jq >/dev/null || { echo "REFUSING: jq not found" >&2; exit 1; }
sums() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
fsize() { wc -c < "$1" | tr -d ' '; }
listed() { awk -v f="$1" '$2==f {print $1}' "$dist/SHA256SUMS"; }
src() { # archive-name -> {file, sha256}; refuses an archive that SHA256SUMS does not list
    local s; s=$(listed "$1"); [ -n "$s" ] || { echo "REFUSING: $dist/SHA256SUMS does not list $1" >&2; exit 1; }
    jq -nc --arg f "$1" --arg s "$s" '{file: $f, sha256: $s}'
}
release_commit=$(jq -r .commit "$dist/matrix.json")
public_commit=${PUBLIC_COMMIT:-$(jq -r '.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit // empty' "$dist"/provenance-*.intoto.json 2>/dev/null | head -1)}
records='[]'
shopt -s nullglob
for f in "$pkgs"/tenzro-*.deb "$pkgs"/tenzro-*.rpm "$pkgs"/tenzro-*.msi "$pkgs"/tenzro-*.pkg; do
    b=$(basename "$f"); kind=${b##*.}
    case "$kind" in
        deb) flavour=$(echo "$b" | sed 's/^tenzro-\([a-z]*\)_.*/\1/'); version=$(echo "$b" | sed 's/^tenzro-[a-z]*_\(.*\)_[a-z0-9]*\.deb/\1/')
             a=$(echo "$b" | sed 's/.*_\([a-z0-9]*\)\.deb/\1/'); arch=$([ "$a" = amd64 ] && echo x86_64 || echo aarch64)
             platform=linux; sources=$(src "tenzro-node-linux-$arch-$flavour.tar.gz" | jq -s .)
             inner=$(dpkg-deb --fsys-tarfile "$f" | tar -xO ./usr/lib/tenzro/PACKAGE-INFO | sed -n 's/^source_archive_sha256=//p')
             [ "$inner" = "$(jq -r '.[0].sha256' <<<"$sources")" ] || { echo "REFUSING: $b carries archive digest $inner, SHA256SUMS lists another" >&2; exit 1; } ;;
        rpm) flavour=$(echo "$b" | sed 's/^tenzro-\([a-z]*\)-.*/\1/'); version=$(echo "$b" | sed 's/^tenzro-[a-z]*-\([0-9.]*-[0-9]*\)\..*/\1/')
             arch=$(echo "$b" | sed 's/.*\.\([a-z0-9_]*\)\.rpm/\1/'); platform=linux
             sources=$(src "tenzro-node-linux-$arch-$flavour.tar.gz" | jq -s .) ;;
        msi) version=$(echo "$b" | sed 's/^tenzro-\([0-9.]*\)-windows.*/\1/'); platform=windows; arch=x86_64; flavour=cuda
             sources=$(src tenzro-node-windows-x86_64-cuda.zip | jq -s .) ;;
        pkg) version=$(echo "$b" | sed 's/^tenzro-\([0-9.]*\)-macos\.pkg/\1/'); platform=macos; arch=universal; flavour="metal+cpu"
             sources=$( { src tenzro-node-macos-aarch64-metal.tar.gz; src tenzro-node-macos-x86_64-cpu.tar.gz; } | jq -s .) ;;
    esac
    records=$(jq -c --arg f "$b" --arg s "$(sums "$f" | cut -d' ' -f1)" --arg z "$(fsize "$f")" --arg k "$kind" --arg p "$platform" \
        --arg a "$arch" --arg fl "$flavour" --arg v "$version" --argjson src "$sources" --arg rc "$release_commit" --arg pc "$public_commit" \
        '. + [{file: $f, sha256: $s, size: ($z|tonumber), kind: $k, platform: $p, arch: $a, flavour: $fl, version: $v, sources: $src, release_commit: $rc, public_source_commit: $pc}]' <<<"$records")
done
jq 'sort_by(.platform, .arch, .kind, .file)' <<<"$records" > "$pkgs/packages.json"
echo "packages.json: $(jq length "$pkgs/packages.json") package(s)"
