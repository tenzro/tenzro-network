#!/usr/bin/env bash
# Supply-chain pin checks for the build configuration.
#
# Always enforced:
#   - one Rust version: the `rust:` images in the Dockerfiles and the rustup
#     toolchain the GPU Dockerfiles install all equal the channel in
#     rust-toolchain.toml;
#   - every cargo build/test/check/bench/install in a Dockerfile or a build
#     script under scripts/ passes --locked, so the committed Cargo.lock is
#     what is built.
#
# Enforced with --release (scripts/supply-chain/release.sh), reported otherwise:
#   - every Dockerfile FROM names its base image by digest (@sha256:...);
#   - every GitHub Actions `uses:` names its action by commit SHA.
#
# Usage: scripts/supply-chain/check-pins.sh [--release]
set -euo pipefail

cd "$(dirname "$0")/../.."
release=0
[ "${1:-}" = "--release" ] && release=1
fail=0

channel=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' rust-toolchain.toml)
if [ -z "$channel" ]; then
  echo "rust-toolchain.toml has no channel"; exit 1
fi

# Regular files only: a pattern that matches nothing stays literal and fails the
# test, so a missing kind of file never aborts the check under `set -e`.
configs=$(for f in Dockerfile Dockerfile.* scripts/*.sh scripts/*.ps1 scripts/release/*; do
  if [ -f "$f" ]; then printf '%s\n' "$f"; fi
done)

# One Rust version.
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  version=$(printf '%s' "$hit" | sed -n 's/.*rust:\([0-9][0-9.]*\)-.*/\1/p')
  if [ "$version" != "$channel" ]; then
    echo "Rust version mismatch (toolchain $channel): $hit"; fail=1
  fi
done < <(grep -Hn 'rust:[0-9]' $configs | grep -v '^[^:]*:[0-9]*:[[:space:]]*#' || true)
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  if ! printf '%s' "$hit" | grep -q -- "--default-toolchain $channel"; then
    echo "rustup toolchain mismatch (toolchain $channel): $hit"; fail=1
  fi
done < <(grep -Hn -- '--default-toolchain' $configs || true)

# --locked on every cargo invocation that resolves dependencies.
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  echo "cargo without --locked: $hit"; fail=1
done < <(grep -Hn -E '(^|[[:space:]])cargo (build|test|check|bench|install|run)([[:space:]]|$)' $configs \
          | grep -v -- '--locked' \
          | grep -v -E '^[^:]*:[0-9]*:[[:space:]]*#' \
          | grep -v -E 'echo |printf ' || true)

# Every `--features <crate>/<feature>` that a workflow or build file passes names a
# feature the crate declares: cargo refuses an unknown feature before it compiles
# anything, so a stale name turns the whole job red.
feature_files=$(ls .github/workflows/*.yml $configs 2>/dev/null)
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  file=${hit%%:*}
  spec=$(printf '%s' "${hit#*:}" | sed -E 's/^--features[ =]//; s/["();]//g')
  for item in $(printf '%s' "$spec" | tr ',' ' '); do
    case "$item" in *'$'*|*/*/*) continue ;; */*) ;; *) continue ;; esac
    crate=${item%%/*}; feat=${item#*/}
    manifest=$(grep -l -E "^name = \"$crate\"" $(find crates apps sdk vendor tools programs \
      -name Cargo.toml -not -path '*/node_modules/*' -not -path '*/target/*' 2>/dev/null) 2>/dev/null | head -1)
    if [ -z "$manifest" ]; then
      echo "--features $item names no crate in this repository ($file)"; fail=1; continue
    fi
    if ! sed -n '/^\[features\]/,/^\[/p' "$manifest" | grep -q -E "^$feat *="; then
      echo "--features $item: $crate declares no feature $feat ($file)"; fail=1
    fi
  done
done < <(grep -oH -E -- '--features[ =][^ ]+' $feature_files || true)

# Base images by digest.
unpinned_from=$(grep -Hn -E '^FROM ' Dockerfile Dockerfile.* scripts/release/Containerfile.* | grep -v '@sha256:' || true)
if [ -n "$unpinned_from" ]; then
  echo "Base images not pinned by digest:"; echo "$unpinned_from"
  [ $release -eq 1 ] && fail=1
fi

# GitHub Actions by commit SHA.
unpinned_uses=$(grep -Hn -E '^[[:space:]]*-?[[:space:]]*uses:' .github/workflows/*.yml 2>/dev/null \
  | grep -v -E '@[0-9a-f]{40}' || true)
if [ -n "$unpinned_uses" ]; then
  echo "GitHub Actions not pinned by commit SHA:"; echo "$unpinned_uses"
  [ $release -eq 1 ] && fail=1
fi

# No new private key created or stored in software.
"$(dirname "$0")/check-keys.sh" || fail=1

# No unsafe in the crates that have none; consensus keeps its two libc calls and no more.
"$(dirname "$0")/check-unsafe.sh" || fail=1

# Every npm project turns dependency install scripts off (.npmrc ignore-scripts=true), at its
# own directory or at the repository root.
while IFS= read -r pj; do
  [ -z "$pj" ] && continue
  d=$(dirname "$pj")
  if ! grep -qs '^ignore-scripts=true' "$d/.npmrc" && ! grep -qs '^ignore-scripts=true' .npmrc; then
    echo "npm project without ignore-scripts=true: $d"; fail=1
  fi
done < <(find apps sdk contracts crates -name package.json -not -path '*/node_modules/*' -not -path '*/native/npm/*' -not -path '*/packages/*' 2>/dev/null || true)

# Dependency policy (advisories, licences, bans, sources) on every check.
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny --locked check advisories licenses bans sources || fail=1
  # The control app ships its own lockfile; its advisories are held to the same policy.
  cargo deny --manifest-path apps/tenzro-control/src-tauri/Cargo.toml --locked check advisories || fail=1
else
  echo "cargo-deny is not installed; the dependency policy was not checked"
  fail=1
fi

if [ $fail -ne 0 ]; then
  echo "supply-chain pin check FAILED"; exit 1
fi
echo "supply-chain pin check passed (toolchain $channel)"
