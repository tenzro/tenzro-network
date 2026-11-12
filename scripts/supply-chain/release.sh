#!/usr/bin/env bash
# Release signing: the supply-chain evidence and signatures over a release
# matrix that scripts/release/ built and scripts/release/manifest.sh recorded.
# This is the step that needs the key holder's release hardware token; the builds
# themselves never touch a key.
#
#   1. Refuse to start from unpinned inputs (check-pins.sh --release): one Rust
#      version, --locked everywhere, base images by digest, actions by commit.
#   2. Dependency policy: cargo-deny advisories, licences, bans, sources;
#      the advisory gate (advisory-gate.sh: no RustSec vulnerability or
#      unsound advisory that .cargo/audit.toml does not accept); every
#      dependency audited or exempted in supply-chain/ (cargo vet, with the
#      Mozilla, Google and Bytecode Alliance audits imported); and a
#      two-host reproducibility record for the commit (reproduce.sh).
#   3. Check the dist directory: SHA256SUMS must verify and matrix.json must
#      name one commit, the one given.
#   4. For each artifact, and for SHA256SUMS itself: SHA-256 and BLAKE3 digests, an SPDX SBOM of the
#      source tree and lockfile it was built from, an in-toto SLSA v1
#      provenance statement naming the artifact by both digests and the source
#      commit, and signatures over the artifact and the statement.
#
# Signing uses cosign with a hardware-held key only: RELEASE_SIGNING_KEY must be
# a PKCS#11 URI (`pkcs11:...`, e.g. a YubiKey PIV slot or a TPM-backed token).
# A key file is refused. The provenance is a DSSE envelope over the in-toto
# statement; machine images released this way carry the BLAKE3 subject that
# tenzro_machineDeploy's `provenance` check expects.
#
# The signatures are made with cosign 3.x and are NOT uploaded to a transparency
# log: a hardware-key signature is checked offline against the published public
# key (`verify-blob --key ... --insecure-ignore-tlog=true`, see
# docs/VERIFY-DOWNLOAD.md). cosign 3 needs all three flags below to write a plain
# signature file with no log entry.
#
# Usage: scripts/supply-chain/release.sh <ref> <dist-dir>
set -euo pipefail

REF=${1:?usage: release.sh <ref> <dist-dir>}
DIST=${2:?usage: release.sh <ref> <dist-dir>}

repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"

for tool in cargo-deny cargo-audit cargo-vet syft cosign b3sum sha256sum git jq; do
    command -v "$tool" >/dev/null || { echo "REFUSING: $tool not found"; exit 1; }
done
case "${RELEASE_SIGNING_KEY:-}" in
    pkcs11:*) ;;
    *) echo "REFUSING: RELEASE_SIGNING_KEY must be a pkcs11: URI for a hardware-held key"; exit 1 ;;
esac

commit=$(git rev-parse --verify "$REF^{commit}")
origin=$(git config --get remote.origin.url || echo "unknown")
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "=== pins ==="
bash scripts/supply-chain/check-pins.sh --release

echo "=== dependency policy ==="
cargo deny --locked check advisories licenses bans sources
bash scripts/supply-chain/advisory-gate.sh
cargo vet --locked

echo "=== reproducibility ==="
grep -q "^MATCH " "$DIST/reproducible-$commit.txt" 2>/dev/null ||
    { echo "REFUSING: no two-host reproducibility match for $commit (run scripts/supply-chain/reproduce.sh)"; exit 1; }

echo "=== manifest $commit ==="
(cd "$DIST" && sha256sum -c --quiet SHA256SUMS) || { echo "REFUSING: SHA256SUMS does not verify"; exit 1; }
[ "$(jq -r .commit "$DIST/matrix.json")" = "$commit" ] || { echo "REFUSING: matrix.json is not $commit"; exit 1; }
artifacts=$(awk '{print $2}' "$DIST/SHA256SUMS")
finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sign_flags=(--yes --key "$RELEASE_SIGNING_KEY" --tlog-upload=false --use-signing-config=false --new-bundle-format=false)
cosign sign-blob "${sign_flags[@]}" \
    --output-signature "$DIST/SHA256SUMS.sig" "$DIST/SHA256SUMS"

echo "=== SBOM ==="
src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT
git archive --format=tar "$commit" | tar -x -C "$src"
sbom="$DIST/sbom-$commit.spdx.json"
syft "dir:$src" -o "spdx-json=$sbom"

echo "=== provenance and signatures ==="
subjects='[]'
for a in $artifacts; do
    path="$DIST/$a"
    sha=$(sha256sum "$path" | cut -d' ' -f1)
    b3=$(b3sum --no-names "$path")
    subjects=$(jq -c --arg n "$a" --arg s "$sha" --arg b "$b3" \
        '. + [{name: $n, digest: {sha256: $s, blake3: $b}}]' <<<"$subjects")
    cosign sign-blob "${sign_flags[@]}" \
        --output-signature "$path.sig" "$path"
done

statement="$DIST/provenance-$commit.intoto.json"
jq -n \
    --argjson subjects "$subjects" \
    --arg commit "$commit" \
    --arg origin "$origin" \
    --arg ref "$REF" \
    --arg builder "tenzro-build-host:$(hostname)" \
    --arg started "$started" \
    --arg finished "$finished" \
    --arg sbom_sha "$(sha256sum "$sbom" | cut -d' ' -f1)" \
    '{
      "_type": "https://in-toto.io/Statement/v1",
      subject: $subjects,
      predicateType: "https://slsa.dev/provenance/v1",
      predicate: {
        buildDefinition: {
          buildType: "https://tenzro.com/build/release-matrix",
          externalParameters: { ref: $ref, source: ("git+" + $origin + "@" + $commit) },
          resolvedDependencies: [
            { uri: ("git+" + $origin + "@" + $commit), digest: { gitCommit: $commit } },
            { uri: "sbom", digest: { sha256: $sbom_sha } }
          ]
        },
        runDetails: {
          builder: { id: $builder },
          metadata: { startedOn: $started, finishedOn: $finished }
        }
      }
    }' > "$statement"

# DSSE envelope over the statement, signed by the same hardware key.
cosign attest-blob "${sign_flags[@]}" \
    --type slsaprovenance1 --predicate <(jq '.predicate' "$statement") \
    --output-attestation "$DIST/provenance-$commit.dsse.json" \
    $(for a in $artifacts; do printf '%s ' "$DIST/$a"; done)

echo "RELEASE OK: $commit"
ls -1 "$DIST" | grep -E "$commit|\.sig$" || true
