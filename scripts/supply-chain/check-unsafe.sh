#!/bin/bash
# Keeps `unsafe` out of the crates that have none and bounds it in consensus.
#   - tenzro-crypto, tenzro-identity, tenzro-iroh and tenzro-zk carry `#![forbid(unsafe_code)]` in
#     src/lib.rs and contain no `unsafe` token in any source file.
#   - tenzro-consensus contains exactly two `unsafe` blocks, both libc calls in src/compact_work.rs.
# UNSAFE_ROOT overrides the repository root (used by test_check_unsafe.sh).
set -u
root=${UNSAFE_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
cd "$root"
fail=0
# `unsafe` as a word, outside whole-line comments. `unsafe_code` in an attribute is a different word.
hits() { grep -rnw --include='*.rs' unsafe "$@" 2>/dev/null | grep -v -E '^[^:]+:[0-9]+:[[:space:]]*//'; }

for c in tenzro-crypto tenzro-identity tenzro-iroh tenzro-zk; do
  lib=crates/$c/src/lib.rs
  if ! grep -q -E '^#!\[forbid\(unsafe_code\)\]' "$lib" 2>/dev/null; then
    echo "$lib lacks #![forbid(unsafe_code)]"; fail=1
  fi
  found=$(hits "crates/$c")
  if [ -n "$found" ]; then echo "unsafe in $c:"; echo "$found"; fail=1; fi
done

found=$(hits crates/tenzro-consensus)
total=$(printf '%s' "$found" | grep -c .)
known=$(printf '%s' "$found" | grep -c '^crates/tenzro-consensus/src/compact_work\.rs:')
if [ "$total" -ne 2 ] || [ "$known" -ne 2 ]; then
  echo "tenzro-consensus must have exactly the 2 libc unsafe blocks in src/compact_work.rs; found $total ($known there):"
  echo "$found"; fail=1
fi

if [ $fail -ne 0 ]; then echo "unsafe check FAILED"; exit 1; fi
echo "unsafe check passed"
