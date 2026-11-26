#!/bin/bash
# Real-Mac test: a Secure Enclave key made by a binary signed with identity A opens, and signs, after the
# binary is re-signed with identity B (hardened runtime, no entitlements). This shows the key is not bound
# to the signer. Needs a Mac with a Secure Enclave, logged in, and two codesign identities (or "-" for ad-hoc):
#   scripts/release/test_enclave_resign.sh "<identity A>" "<identity B>"
#   e.g. test_enclave_resign.sh - "Developer ID Application: Example (TEAMID)"
# Result lines: RESIGN PASS / RESIGN FAIL <step>. The key lives in a throw-away directory that is removed.
set -euo pipefail
[ "$(uname -s)" = Darwin ] || { echo "REFUSING: this runs on a Mac" >&2; exit 1; }
a=${1:?identity A (or -)}; b=${2:?identity B (or -)}
repo=$(cd "$(dirname "$0")/../.." && pwd)
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
export TENZRO_DEVICE_KEY_DIR=$t/keys
(cd "$repo" && cargo build --locked -p tenzro-device-key --example enclave_probe --target-dir "$t/target")
probe=$t/enclave_probe
cp "$t/target/debug/examples/enclave_probe" "$probe"
label=resign-test-$$
step() { echo "step: $*"; }
step "sign with A"; codesign --force --options runtime --sign "$a" "$probe"
step "create"; "$probe" create "$label" || { echo "RESIGN FAIL create (the Enclave did not make the key)"; exit 1; }
step "sign with A opens"; "$probe" sign "$label" || { echo "RESIGN FAIL open-under-A"; exit 1; }
step "re-sign with B"; codesign --force --options runtime --sign "$b" "$probe"
codesign -dv "$probe" 2>&1 | grep -E 'Identifier|Authority|TeamIdentifier|flags' || true
step "open under B"; "$probe" sign "$label" || { echo "RESIGN FAIL open-under-B (the key is bound to the signer)"; exit 1; }
echo "RESIGN PASS: the key made under A signs under B, hardened runtime, no entitlements"
