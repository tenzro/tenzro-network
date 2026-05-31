#!/usr/bin/env bash
#
# regenerate.sh
#
# Deterministically regenerates the ERC-8004 predeploy genesis bundle at
# crates/tenzro-node/res/genesis/erc8004-predeploys.json by:
#
#   1. Spinning up a local Anvil node (foundry) — chosen over `npx hardhat
#      node` because Hardhat 3 dropped `hardhat_dumpState` (returns -32004
#      "Method not supported"), while `anvil_dumpState` is alive and
#      well-supported.
#   2. Running the vendored canonical CREATE2 deploy + UUPS upgrade flow
#      against it (factory → MinimalUUPS → 3 proxies → 3 impls →
#      presigned upgrades → verify). The vendor scripts use viem against
#      `http://127.0.0.1:8545` so they are transport-agnostic.
#   3. Snapshotting the resulting full state via `anvil_dumpState`. The
#      response is a hex-encoded gzip-compressed JSON blob (Anvil 1.x
#      wire format), which we gunzip + JSON-parse before extraction.
#   4. Piping the structured dump to tools/predeploys/extract-erc8004.mjs
#      which filters down to the 8 ERC-8004 addresses and emits Tenzro's
#      genesis predeploy schema.
#
# Output: crates/tenzro-node/res/genesis/erc8004-predeploys.json
#
# This script is idempotent. Re-run after bumping the canonical pin to
# regenerate the bundle.
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENDOR_DIR="$REPO_ROOT/vendor/erc8004-evm"
EXTRACTOR="$SCRIPT_DIR/extract-erc8004.mjs"
OUTPUT_DIR="$REPO_ROOT/crates/tenzro-node/res/genesis"
OUTPUT_FILE="$OUTPUT_DIR/erc8004-predeploys.json"
RPC_URL="http://127.0.0.1:8545"

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
if [[ ! -d "$VENDOR_DIR" ]]; then
  echo "error: vendored canonical repo missing at $VENDOR_DIR" >&2
  echo "       run: git clone https://github.com/erc-8004/erc-8004-contracts $VENDOR_DIR" >&2
  exit 1
fi

if [[ ! -d "$VENDOR_DIR/node_modules" ]]; then
  echo "error: $VENDOR_DIR/node_modules missing — run \`npm install --legacy-peer-deps\` first" >&2
  exit 1
fi

if [[ ! -f "$EXTRACTOR" ]]; then
  echo "error: extractor missing at $EXTRACTOR" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "error: node is required" >&2
  exit 1
fi

if ! command -v anvil >/dev/null 2>&1; then
  echo "error: anvil (foundry) is required — install via https://getfoundry.sh" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

# ---------------------------------------------------------------------------
# Background anvil node lifecycle
# ---------------------------------------------------------------------------
ANVIL_LOG="$(mktemp -t tenzro-anvil-node.XXXXXX.log)"
ANVIL_PID=""

cleanup() {
  if [[ -n "$ANVIL_PID" ]] && kill -0 "$ANVIL_PID" 2>/dev/null; then
    echo "==> stopping anvil (pid $ANVIL_PID)"
    kill "$ANVIL_PID" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      if ! kill -0 "$ANVIL_PID" 2>/dev/null; then break; fi
      sleep 0.5
    done
    if kill -0 "$ANVIL_PID" 2>/dev/null; then
      kill -9 "$ANVIL_PID" 2>/dev/null || true
    fi
  fi
  if [[ -f "$ANVIL_LOG" ]]; then
    if [[ "${KEEP_ANVIL_LOG:-0}" == "1" ]]; then
      echo "==> anvil log preserved at $ANVIL_LOG"
    else
      rm -f "$ANVIL_LOG"
    fi
  fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Step 1 — start anvil node
# ---------------------------------------------------------------------------
echo "==> starting anvil (chainId 31337, hardfork shanghai)"
# --chain-id 31337 matches what the vendored canonical scripts expect
#   (their `validateChainId()` and presigned-upgrade bundle are pinned to it).
# --hardfork shanghai matches solc 0.8.24 evmVersion in vendor/erc8004-evm
#   so deployed bytecode is byte-identical to the canonical artifacts.
# --silent suppresses startup banner; we still capture stderr for diagnostics.
(
  exec anvil \
    --host 127.0.0.1 \
    --port 8545 \
    --chain-id 31337 \
    --hardfork shanghai \
    --silent \
    >"$ANVIL_LOG" 2>&1
) &
ANVIL_PID=$!
echo "   pid=$ANVIL_PID, log=$ANVIL_LOG"

# ---------------------------------------------------------------------------
# Step 2 — wait for RPC readiness (eth_chainId)
# ---------------------------------------------------------------------------
echo "==> waiting for RPC at $RPC_URL"
READY=0
for _ in $(seq 1 60); do
  if curl -fsS -X POST "$RPC_URL" \
       -H 'Content-Type: application/json' \
       --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
       >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 0.5
done

if [[ "$READY" -ne 1 ]]; then
  echo "error: anvil did not become ready within 30s" >&2
  echo "--- anvil log (last 40 lines) ---" >&2
  tail -n 40 "$ANVIL_LOG" >&2 || true
  exit 1
fi
echo "   RPC ready"

# ---------------------------------------------------------------------------
# Step 3 — canonical CREATE2 deploy + UUPS upgrade flow
# ---------------------------------------------------------------------------
echo "==> deploying SAFE Singleton Factory"
(cd "$VENDOR_DIR" && npm run --silent local:factory)

echo "==> funding canonical owner address"
(cd "$VENDOR_DIR" && npm run --silent local:fund-owner)

echo "==> deploying ERC-8004 vanity proxies + impls + presigned upgrade + verify"
# `local:vanity` chains: deploy-vanity → upgrade-vanity-presigned → verify-vanity.
(cd "$VENDOR_DIR" && npm run --silent local:vanity)

# ---------------------------------------------------------------------------
# Step 4 — snapshot full state via anvil_dumpState
# ---------------------------------------------------------------------------
echo "==> dumping chain state via anvil_dumpState"
DUMP_TMP="$(mktemp -t tenzro-erc8004-dump.XXXXXX.json)"
trap 'rm -f "$DUMP_TMP"; cleanup' EXIT INT TERM

curl -fsS -X POST "$RPC_URL" \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"anvil_dumpState","params":[]}' \
  > "$DUMP_TMP"

# `anvil_dumpState` (Anvil 1.x) returns
#   { "jsonrpc": "2.0", "id": 1, "result": "0x<gzip(JSON)>" }
# The result is a hex-encoded gzip-compressed JSON blob — this is the wire
# format `anvil_loadState` consumes. Gunzip + JSON-parse it to recover the
# structured `{ accounts: { addr: { nonce, balance, code, storage } }, ... }`
# shape that extract-erc8004.mjs expects.
RESULT_TMP="$(mktemp -t tenzro-erc8004-result.XXXXXX.json)"
node -e '
const fs = require("node:fs");
const zlib = require("node:zlib");
const raw = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (raw.error) {
  console.error("anvil_dumpState RPC error:", JSON.stringify(raw.error));
  process.exit(1);
}
if (typeof raw.result !== "string" || !raw.result.startsWith("0x")) {
  console.error("anvil_dumpState returned unexpected result type:", typeof raw.result);
  process.exit(1);
}
const compressed = Buffer.from(raw.result.slice(2), "hex");
let decompressed;
try {
  decompressed = zlib.gunzipSync(compressed);
} catch (e) {
  console.error("failed to gunzip anvil_dumpState payload:", e.message);
  process.exit(1);
}
let parsed;
try {
  parsed = JSON.parse(decompressed.toString("utf8"));
} catch (e) {
  console.error("decompressed anvil_dumpState payload is not JSON:", e.message);
  console.error("first 80 bytes hex:", decompressed.slice(0, 80).toString("hex"));
  process.exit(1);
}
fs.writeFileSync(process.argv[2], JSON.stringify(parsed));
' "$DUMP_TMP" "$RESULT_TMP"

# ---------------------------------------------------------------------------
# Step 5 — filter dump to the 8 ERC-8004 addresses + write predeploys.json
# ---------------------------------------------------------------------------
echo "==> extracting ERC-8004 predeploys → $OUTPUT_FILE"
node "$EXTRACTOR" "$OUTPUT_FILE" < "$RESULT_TMP"

rm -f "$DUMP_TMP" "$RESULT_TMP"

# ---------------------------------------------------------------------------
# Step 6 — verify output sanity
# ---------------------------------------------------------------------------
EXPECTED_ACCOUNTS=8
ACTUAL_ACCOUNTS=$(node -e '
const fs = require("node:fs");
const j = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
console.log(Object.keys(j.accounts || {}).length);
' "$OUTPUT_FILE")

if [[ "$ACTUAL_ACCOUNTS" -ne "$EXPECTED_ACCOUNTS" ]]; then
  echo "error: expected $EXPECTED_ACCOUNTS accounts in predeploy bundle, got $ACTUAL_ACCOUNTS" >&2
  exit 1
fi

echo
echo "==> SUCCESS"
echo "    bundle: $OUTPUT_FILE"
echo "    accounts: $ACTUAL_ACCOUNTS"
echo "    source_commit: $(node -e '
const fs = require("node:fs");
const j = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
console.log(j.source_commit || "unknown");
' "$OUTPUT_FILE")"
