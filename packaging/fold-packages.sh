#!/usr/bin/env bash
# Put the installer packages beside the archives and rebuild the manifest, so the
# next signed SHA256SUMS lists archives AND packages. Run by the release assembler on
# the host that holds the dist directory, before the key holder signs.
#
#   fold-packages.sh <dist-dir> <packages-dir>
#
# It never touches an archive. It does change SHA256SUMS, matrix.json and the
# provenance statement (through make-manifest.sh), which is the point: the previous
# signature (SHA256SUMS.sig) no longer matches and is moved aside to SHA256SUMS.sig.prev.
#
# Environment for make-manifest.sh as for the archives:
#   ORIGIN=<public source URL> PUBLIC_COMMIT=<40-hex> PUBLIC_TREE=<40-hex>
set -euo pipefail
dist=$(cd "${1:?usage: fold-packages.sh <dist-dir> <packages-dir>}" && pwd)
pk=$(cd "${2:?}" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
[ -f "$pk/packages.json" ] || { echo "REFUSING: $pk/packages.json missing (run make-packages.sh)" >&2; exit 1; }
( cd "$pk" && sha256sum -c --quiet SHA256SUMS.packages )
# The manifest tool that knows packages.json.
[ -f "$here/../scripts/release/manifest.sh" ] && cp "$here/../scripts/release/manifest.sh" "$dist/tools/manifest.sh"
# Hard links, not copies: no extra disk, same bytes. Falls back to copying across filesystems.
for f in "$pk"/tenzro-*.deb "$pk"/tenzro-*.rpm "$pk"/tenzro-*.msi "$pk"/tenzro-*.pkg "$pk/packages.json"; do
    [ -f "$f" ] || continue
    ln -f "$f" "$dist/$(basename "$f")" 2>/dev/null || cp "$f" "$dist/$(basename "$f")"
done
[ -f "$dist/SHA256SUMS.sig" ] && mv "$dist/SHA256SUMS.sig" "$dist/SHA256SUMS.sig.prev"
( cd "$dist" && PATH="$HOME/.local/bin:$PATH" ./make-manifest.sh )
( cd "$dist" && sha256sum -c SHA256SUMS )
echo "folded: $(wc -l < "$dist/SHA256SUMS") lines in SHA256SUMS; now sign it (the release signer's step)"
