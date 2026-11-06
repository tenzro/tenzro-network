#!/bin/bash
# Refuse a new place in non-test Rust code that creates, derives or stores a
# private key in software. Private keys belong in a TPM, the Secure Enclave or
# a passkey. The sites that still do it are listed, with a count per file, in
# software-key-sites.txt; a new file, or more sites in a listed file, fails the
# check. Removing a site means lowering or deleting its line.
set -u
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
pat='KeyPair::generate|MlDsaSigningKey::generate|MlDsaSigningKey::from_seed|BlsKeyPair::generate|SigningKey::generate|SigningKey::from_bytes|SigningKey::from_slice|Ed25519SignerImpl::generate|X25519KeyPair::from_secret_bytes|write_secret[(]|with_secret_key_seed'
current=$(for f in $(git ls-files 'crates/*.rs' | grep -v -E '/(tests|benches|examples)/|test_support|tests\.rs$'); do
  # Everything after a file's first `#[cfg(test)]` is test code, and so is any item carrying
  # `#[cfg(any(test, feature = "test-keys"))]` or the `test-support` equivalent: those features are
  # only ever enabled from dev-dependencies (checked below). The skip covers exactly the braces of
  # the one gated item.
  awk -v pat="$pat" '
    !skip && /#\[cfg\(test\)\]/ {exit}
    !skip && /^[[:space:]]*#\[cfg\(any\(test, feature = "(test-keys|test-support)"\)\)\]/ {pend=1; next}
    pend && /^[[:space:]]*(#\[|\/\/)/ {next}
    pend {pend=0; skip=1; depth=0; seen=0}
    skip {
      line=$0; o=gsub(/\{/,"",line); c=gsub(/\}/,"",line); depth+=o-c; if (o>0) seen=1
      if ((seen && depth<=0) || (!seen && $0 ~ /;[[:space:]]*$/)) skip=0
      next
    }
    $0 ~ pat && $0 !~ /^[[:space:]]*\/\// {n++}
    END {if (n) print FILENAME, n}' "$f"
done | sort)
# The two test features may be enabled only from a dev-dependencies table (or defined in [features]).
# fuzz/ (standalone harness) and crates/tenzro-sim (publish = false simulator, used only by tenzro-econsim) never ship in a release build.
fail=0
for t in $(git ls-files '*Cargo.toml' | grep -v -E "^(fuzz/|crates/tenzro-sim/Cargo.toml)"); do
  bad=$(awk '/^\[/ {sec=$0} /features *= *\[.*"test-(keys|support)"/ && sec !~ /^\[(features|dev-dependencies|target\..*\.dev-dependencies)\]/ {print FILENAME ":" FNR ": " $0}' "$t")
  if [ -n "$bad" ]; then echo "test feature enabled outside dev-dependencies: $bad"; fail=1; fi
done
allowed=$(grep -v -E '^[[:space:]]*(#|$)' scripts/supply-chain/software-key-sites.txt | sort)
while read -r file count; do
  [ -z "$file" ] && continue
  limit=$(printf '%s\n' "$allowed" | awk -v f="$file" '$1 == f {print $2}')
  if [ -z "$limit" ]; then
    echo "new software key site in $file ($count)"; fail=1
  elif [ "$count" -gt "$limit" ]; then
    echo "more software key sites in $file: $count, listed $limit"; fail=1
  fi
done <<< "$current"
if [ $fail -ne 0 ]; then
  echo "software key check FAILED"; exit 1
fi
echo "software key check passed"
