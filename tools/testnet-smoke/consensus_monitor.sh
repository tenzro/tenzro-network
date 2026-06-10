#!/usr/bin/env bash
# Continuous consensus health monitor for the Tenzro testnet fleet.
#
# Polls every validator's local RPC every 10s, recording:
#   - block height advancement
#   - peer count
#   - last TC / NEC formation from logs
#   - max_high_qc_view gap (the tail-fork signature)
#
# Outputs to a timestamped TSV. On stall detection (no height advance in 60s
# AND a TC was formed in the same window), emits a diagnostic line on stdout
# that the harness picks up as a monitor event.
#
# Usage:
#   ./consensus_monitor.sh [output.tsv]
#
# Stop with Ctrl+C or send SIGTERM.

set -uo pipefail

OUT_TSV=${1:-/tmp/tenzro-consensus-monitor.tsv}
POLL_INTERVAL=${POLL_INTERVAL:-10}
STALL_THRESHOLD_SECS=${STALL_THRESHOLD_SECS:-60}

PROJECT=tenzro-operator-project
declare -A ZONE_OF=(
  [tenzro-validator-0]=us-central1-a
  [tenzro-validator-1]=us-central1-b
  [tenzro-validator-2]=us-central1-c
  [tenzro-validator-3]=us-central1-f
  [tenzro-validator-4]=europe-west1-b
  [tenzro-validator-5]=europe-west1-c
  [tenzro-validator-6]=europe-west1-d
  [tenzro-validator-7]=asia-southeast1-a
  [tenzro-validator-8]=asia-southeast1-b
  [tenzro-validator-9]=asia-southeast1-c
)
VALIDATORS=(tenzro-validator-0 tenzro-validator-1 tenzro-validator-2 tenzro-validator-3 tenzro-validator-4 tenzro-validator-5 tenzro-validator-6 tenzro-validator-7 tenzro-validator-8 tenzro-validator-9)

# Header (overwrite if missing or stall-detect previously cleared).
if [ ! -f "$OUT_TSV" ]; then
  printf "ts\tvalidator\tblock_hex\tblock_dec\tpeers_hex\tlast_tc_view\ttc_max_high_qc\ttc_gap\tnec_view\tnec_signers\n" > "$OUT_TSV"
fi

# Public RPC (validator-0 routes through Caddy) — cheaper than per-VM SSH for the global tip.
public_tip() {
  curl -s --max-time 5 https://rpc.tenzro.network -X POST \
    -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
    2>/dev/null | grep -o '"result":"0x[0-9a-f]*"' | sed 's/"result":"//;s/"//' || echo ""
}

# Per-validator local poll via IAP tunnel. Returns a TSV row.
poll_validator() {
  local vm=$1
  local zone=${ZONE_OF[$vm]}
  local ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local out
  out=$(gcloud compute ssh "$vm" --zone="$zone" --project="$PROJECT" --tunnel-through-iap --command='
    block=$(curl -s --max-time 3 -X POST http://127.0.0.1:8545 -H "content-type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_blockNumber\",\"params\":[]}" 2>/dev/null | grep -o "\"result\":\"0x[0-9a-f]*\"" | sed "s/\"result\":\"//;s/\"//")
    peers=$(curl -s --max-time 3 -X POST http://127.0.0.1:8545 -H "content-type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"net_peerCount\",\"params\":[]}" 2>/dev/null | grep -o "\"result\":\"0x[0-9a-f]*\"" | sed "s/\"result\":\"//;s/\"//")
    # Pull the most recent TC and NEC formations from the last 2 minutes of logs.
    tc=$(sudo docker logs --since=2m tenzro-node 2>&1 | grep "TimeoutCertificate formed" | tail -1 || true)
    nec=$(sudo docker logs --since=2m tenzro-node 2>&1 | grep "NoEndorsementCertificate formed" | tail -1 || true)
    echo "BLOCK=$block"
    echo "PEERS=$peers"
    echo "TC=$tc"
    echo "NEC=$nec"
  ' 2>/dev/null)

  local block_hex peers_hex tc_view tc_max_high_qc nec_view nec_signers tc_gap
  block_hex=$(echo "$out" | sed -n 's/^BLOCK=//p' | head -1)
  peers_hex=$(echo "$out" | sed -n 's/^PEERS=//p' | head -1)
  tc_view=$(echo "$out" | sed -n 's/.*TimeoutCertificate formed for view //p' | head -1 | grep -oE "^[0-9]+" || echo "")
  tc_max_high_qc=$(echo "$out" | grep -oE "max_high_qc_view=[0-9]+" | head -1 | sed 's/max_high_qc_view=//' || echo "")
  nec_view=$(echo "$out" | sed -n 's/.*NoEndorsementCertificate formed for view //p' | head -1 | grep -oE "^[0-9]+" || echo "")
  nec_signers=$(echo "$out" | grep -oE "signers=[0-9]+" | head -1 | sed 's/signers=//' || echo "")

  local block_dec=""
  if [ -n "${block_hex:-}" ]; then
    block_dec=$(printf "%d" "$block_hex" 2>/dev/null || echo "")
  fi

  if [ -n "${tc_view:-}" ] && [ -n "${tc_max_high_qc:-}" ]; then
    tc_gap=$(( tc_view - tc_max_high_qc ))
  else
    tc_gap=""
  fi

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$ts" "$vm" "$block_hex" "$block_dec" "$peers_hex" "$tc_view" "$tc_max_high_qc" "$tc_gap" "$nec_view" "$nec_signers" \
    >> "$OUT_TSV"
}

# Track public tip for stall detection.
prev_tip=""
prev_tip_ts=$(date +%s)
stall_alerted=0

trap 'echo "monitor stopped at $(date -u +%Y-%m-%dT%H:%M:%SZ)"; exit 0' INT TERM

while true; do
  tip=$(public_tip)
  now=$(date +%s)

  if [ -n "$tip" ]; then
    if [ "$tip" != "$prev_tip" ]; then
      prev_tip=$tip
      prev_tip_ts=$now
      stall_alerted=0
    else
      stall_secs=$(( now - prev_tip_ts ))
      if [ "$stall_secs" -ge "$STALL_THRESHOLD_SECS" ] && [ "$stall_alerted" -eq 0 ]; then
        # Decode hex tip to decimal.
        tip_dec=$(printf "%d" "$tip" 2>/dev/null || echo "$tip")
        echo "STALL_DETECTED tip=$tip ($tip_dec) stuck for ${stall_secs}s"
        stall_alerted=1
      fi
    fi
  fi

  for vm in "${VALIDATORS[@]}"; do
    poll_validator "$vm" &
  done
  wait

  sleep "$POLL_INTERVAL"
done
