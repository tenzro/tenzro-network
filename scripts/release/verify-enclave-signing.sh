#!/bin/bash
# Real-Mac check of the promise operators rely on: the node's Secure Enclave key works unsigned and works signed,
# and signing it (or changing how it is signed) never silently changes the machine identity.
#
#   scripts/release/verify-enclave-signing.sh            # unsigned, and signed with the Praecise Developer ID if this Mac holds it
#   scripts/release/verify-enclave-signing.sh "Developer ID Application: Example (TEAMID)"   # a named identity instead
#
# Needs a Mac with a Secure Enclave (not a VM), logged in at the desktop. The unsigned build is the ad-hoc signature
# the linker gives every arm64 binary ("-"). With a Developer ID identity the signed build uses the hardened runtime and
# no entitlements, as the release does. Each step runs test_enclave_resign.sh: make the key under A, open and sign under A,
# re-sign as B, open and sign under B. The keys live in a throw-away directory.
#
# Last line: ENCLAVE SIGNING PASS or ENCLAVE SIGNING FAIL. Paste the whole output into the release record.
set -uo pipefail
[ "$(uname -s)" = Darwin ] || { echo "REFUSING: this runs on a Mac" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
# Build the test program once and reuse it for every pair (a fresh build takes many minutes).
export ENCLAVE_PROBE_TARGET=${ENCLAVE_PROBE_TARGET:-$HOME/.cache/tenzro-enclave-probe-target}
# Signing needs the desktop session: from ssh the login keychain is locked and codesign fails with errSecInternalComponent.
[ -n "${SSH_CONNECTION:-}" ] && echo "NOTE: this is an ssh session; run it in Terminal on the Mac itself, or the signed pairs cannot sign."
dev=${1:-}
if [ -z "$dev" ]; then
    # No identity given: use the Developer ID Application identity of Praecise that this Mac holds, if there is one.
    dev=$(security find-identity -v -p codesigning 2>/dev/null | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | grep -i praecise | head -n 1 || true)
fi
echo "== signing identity for the signed pairs: ${dev:-none found (unsigned pair only)}"
echo "== machine"
sw_vers | sed 's/^/  /'
system_profiler SPHardwareDataType 2>/dev/null | grep -E "Model Name|Model Identifier|Chip" | sed 's/^ */  /'
echo "  arch: $(uname -m)"
echo "== pairs (A -> B)"
pairs=("-|-")
if [ -n "$dev" ]; then pairs+=("-|$dev" "$dev|-" "$dev|$dev"); fi
fail=0; n=0
for p in "${pairs[@]}"; do
    a=${p%%|*}; b=${p#*|}; n=$((n+1))
    echo "-- pair $n: A=[$a] B=[$b]"
    out=$(bash "$here/test_enclave_resign.sh" "$a" "$b" 2>&1); rc=$?
    echo "$out" | grep -E "^(RESIGN|step:)" | sed 's/^/   /'
    if [ $rc -ne 0 ] || ! grep -q "^RESIGN PASS" <<<"$out"; then
        fail=$((fail+1)); echo "$out" | tail -n 6 | sed 's/^/   | /'
    fi
done
echo "== result: $((n-fail)) of $n pairs passed"
if [ $fail -eq 0 ]; then echo "ENCLAVE SIGNING PASS"; else echo "ENCLAVE SIGNING FAIL"; exit 1; fi
