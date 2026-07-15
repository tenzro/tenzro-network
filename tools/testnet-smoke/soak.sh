#!/usr/bin/env bash
# Sustained load soak test for the Tenzro testnet.
#
# Drives concurrent traffic across:
#   - eth_blockNumber, net_peerCount (cheap polls)
#   - tenzro_listTokens, tenzro_listBridgeAdapters (catalog reads)
#   - tenzro_listForecastCatalog and other multi-modal reads
#   - Web API /status, /health probes
#   - MCP initialize handshakes
#
# Writes per-second throughput + latency to /tmp/tenzro-soak-stats.tsv.
# Captures any non-success responses to /tmp/tenzro-soak-errors.log.
#
# Runs for DURATION_SECS (default 28800 = 8h overnight). Adjust via env.
# Stop early with SIGTERM.

set -uo pipefail

RPC=${RPC:-https://rpc.tenzro.xyz}
API=${API:-https://api.tenzro.xyz}
MCP=${MCP:-https://mcp.tenzro.xyz/mcp}
DURATION_SECS=${DURATION_SECS:-28800}    # 8h
CONCURRENCY=${CONCURRENCY:-4}              # 4 workers; each fires N ops/sec
OPS_PER_SEC_PER_WORKER=${OPS_PER_SEC_PER_WORKER:-2}
STATS_TSV=${STATS_TSV:-/tmp/tenzro-soak-stats.tsv}
ERR_LOG=${ERR_LOG:-/tmp/tenzro-soak-errors.log}

# Workload mix (probability weights summing roughly to 100).
read -r -a WORKLOAD <<< "rpc:50 catalog:30 web:15 mcp:5"

if [ ! -f "$STATS_TSV" ]; then
  printf "ts\tworker_id\top\tlatency_ms\tstatus\tbytes\n" > "$STATS_TSV"
fi
: > "$ERR_LOG"

START_TS=$(date +%s)
END_TS=$(( START_TS + DURATION_SECS ))

call_rpc() {
  local method=$1
  local t0 t1 latency
  t0=$(python3 -c "import time; print(int(time.time()*1000))")
  local r
  r=$(curl -s --max-time 10 "$RPC" -X POST \
    -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":[]}" 2>/dev/null)
  t1=$(python3 -c "import time; print(int(time.time()*1000))")
  latency=$(( t1 - t0 ))
  local bytes status
  bytes=${#r}
  if echo "$r" | grep -q '"result"'; then status=ok; else status=err; echo "[rpc:$method] $r" >> "$ERR_LOG"; fi
  echo -e "$(date -u +%Y-%m-%dT%H:%M:%SZ)\t$WORKER_ID\t$method\t$latency\t$status\t$bytes" >> "$STATS_TSV"
}

call_web() {
  local path=$1
  local t0 t1 latency
  t0=$(python3 -c "import time; print(int(time.time()*1000))")
  local r
  r=$(curl -s --max-time 10 "$API$path" 2>/dev/null)
  t1=$(python3 -c "import time; print(int(time.time()*1000))")
  latency=$(( t1 - t0 ))
  local bytes status
  bytes=${#r}
  if [ -n "$r" ]; then status=ok; else status=err; echo "[web:$path] empty response" >> "$ERR_LOG"; fi
  echo -e "$(date -u +%Y-%m-%dT%H:%M:%SZ)\t$WORKER_ID\t$path\t$latency\t$status\t$bytes" >> "$STATS_TSV"
}

call_mcp() {
  local t0 t1 latency
  t0=$(python3 -c "import time; print(int(time.time()*1000))")
  local r
  r=$(curl -s --max-time 10 -X POST "$MCP" \
    -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"soak","version":"0"}}}' \
    2>/dev/null)
  t1=$(python3 -c "import time; print(int(time.time()*1000))")
  latency=$(( t1 - t0 ))
  local bytes status
  bytes=${#r}
  if echo "$r" | grep -qE '"protocolVersion"|"serverInfo"'; then status=ok; else status=err; echo "[mcp:initialize] $r" >> "$ERR_LOG"; fi
  echo -e "$(date -u +%Y-%m-%dT%H:%M:%SZ)\t$WORKER_ID\tmcp_initialize\t$latency\t$status\t$bytes" >> "$STATS_TSV"
}

worker() {
  export WORKER_ID=$1
  local interval=$(awk -v ops="$OPS_PER_SEC_PER_WORKER" 'BEGIN{printf "%.3f", 1.0/ops}')
  local pick op
  while [ "$(date +%s)" -lt "$END_TS" ]; do
    pick=$((RANDOM % 100))
    if [ "$pick" -lt 50 ]; then
      # 50% RPC
      case $((RANDOM % 4)) in
        0) op=eth_blockNumber ;;
        1) op=net_peerCount ;;
        2) op=tenzro_listTokens ;;
        3) op=tenzro_listBridgeAdapters ;;
      esac
      call_rpc "$op"
    elif [ "$pick" -lt 80 ]; then
      # 30% catalog
      case $((RANDOM % 6)) in
        0) op=tenzro_listForecastCatalog ;;
        1) op=tenzro_listVisionCatalog ;;
        2) op=tenzro_listTextEmbeddingCatalog ;;
        3) op=tenzro_listSegmentationCatalog ;;
        4) op=tenzro_listDetectionCatalog ;;
        5) op=tenzro_listAudioCatalog ;;
      esac
      call_rpc "$op"
    elif [ "$pick" -lt 95 ]; then
      # 15% web
      case $((RANDOM % 3)) in
        0) call_web /health ;;
        1) call_web /ready ;;
        2) call_web /status ;;
      esac
    else
      # 5% MCP
      call_mcp
    fi
    sleep "$interval"
  done
}

trap 'echo "soak stopped at $(date -u +%Y-%m-%dT%H:%M:%SZ)"; pkill -P $$; wait; exit 0' INT TERM

echo "=========================================="
echo "Soak load test"
echo "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Duration: ${DURATION_SECS}s (~$((DURATION_SECS/3600))h)"
echo "Concurrency: $CONCURRENCY workers @ $OPS_PER_SEC_PER_WORKER ops/sec each"
echo "Stats TSV: $STATS_TSV"
echo "Errors:   $ERR_LOG"
echo "=========================================="

for i in $(seq 1 "$CONCURRENCY"); do
  worker "w$i" &
done
wait
echo "soak complete"
