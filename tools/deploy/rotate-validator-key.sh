#!/bin/bash
# Validator key rotation fan-out — broadcasts the rotation RPC to every
# active validator so each node's local registry + EpochManager converges
# on the new key tuple at the same epoch boundary.
#
# Until the cross-node consensus-mediated path lands (see
# `handle_rotate_validator_key` rustdoc), this script is the operational
# answer to "I want to rotate keys without splitting consensus." The
# pattern is identical to what other modern L1s do during the bootstrap
# phase before consensus-level key rotation lands (Cosmos uses
# `MsgEditValidator`, Aptos uses `rotate_consensus_key` — both
# eventually land in a block but are also fan-out-driven during the
# preview).
#
# Inputs (env or args):
#   VALIDATOR_RPCS — comma-separated list of validator RPC URLs (https://...).
#                    Caller MUST include every active-set validator. Any node
#                    that doesn't see this rotation will reject the rotating
#                    validator's votes after the next epoch boundary.
#   ROTATION_JSON  — path to a JSON file with the rotation payload
#                    (address, new_consensus_pubkey, new_pq_pubkey,
#                    new_bls_pubkey, nonce, signature). The signature
#                    must be produced offline with the *current* consensus
#                    key over the canonical preimage; this script does
#                    not sign anything.
#
# Exit codes:
#   0  all validators accepted the rotation
#   1  one or more validators rejected; script prints the per-validator outcome
#   2  bad inputs

set -euo pipefail

VALIDATOR_RPCS="${VALIDATOR_RPCS:-${1:-}}"
ROTATION_JSON="${ROTATION_JSON:-${2:-}}"

if [[ -z "$VALIDATOR_RPCS" || -z "$ROTATION_JSON" ]]; then
  echo "Usage: VALIDATOR_RPCS=https://v0.rpc,https://v1.rpc ROTATION_JSON=/tmp/rotation.json $0"
  echo "       OR: $0 <comma-separated-rpcs> <rotation-json-path>"
  exit 2
fi
if [[ ! -s "$ROTATION_JSON" ]]; then
  echo "ERROR: rotation JSON not found at $ROTATION_JSON"
  exit 2
fi

PAYLOAD=$(jq -c '.' "$ROTATION_JSON")
if [[ -z "$PAYLOAD" || "$PAYLOAD" == "null" ]]; then
  echo "ERROR: rotation JSON is empty or invalid"
  exit 2
fi

FAILURES=0
TOTAL=0
IFS=',' read -ra RPCS <<< "$VALIDATOR_RPCS"
for RPC in "${RPCS[@]}"; do
  RPC=$(echo "$RPC" | xargs) # trim
  [[ -z "$RPC" ]] && continue
  TOTAL=$((TOTAL + 1))
  echo "=== $RPC ==="
  RESPONSE=$(curl -fsS -X POST "$RPC" \
    -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tenzro_rotateValidatorKey\",\"params\":$PAYLOAD}" \
    2>&1 || true)
  if echo "$RESPONSE" | jq -e '.result.status == "pending_epoch_activation"' >/dev/null 2>&1; then
    echo "  OK — rotation pending epoch activation"
  elif echo "$RESPONSE" | jq -e '.error' >/dev/null 2>&1; then
    ERR_MSG=$(echo "$RESPONSE" | jq -r '.error.message')
    echo "  FAIL — $ERR_MSG"
    FAILURES=$((FAILURES + 1))
  else
    echo "  FAIL — unexpected response: $RESPONSE"
    FAILURES=$((FAILURES + 1))
  fi
done

echo ""
echo "Summary: $((TOTAL - FAILURES))/$TOTAL accepted."
if [[ $FAILURES -gt 0 ]]; then
  echo "WARNING: $FAILURES validator(s) did not accept the rotation. They will"
  echo "         reject the rotating validator's votes after the next epoch"
  echo "         boundary, causing consensus to fork until those nodes either"
  echo "         see the rotation or the rotating validator is jailed."
  echo "         Re-run after fixing the failed RPCs, or manually call"
  echo "         tenzro_rotateValidatorKey on each before the epoch boundary."
  exit 1
fi
echo "All validators accepted. Rotation takes effect at the next epoch boundary."
