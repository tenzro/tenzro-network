#!/usr/bin/env bash
# Coordinated stop-the-world cutover for the tenzronet validator fleet.
#
# # Why this exists (not just rollout-validators.sh)
#
# The rolling-restart script bounces VMs one at a time; that is the right tool
# when the new image is *protocol-compatible* with the old one. When the new
# image carries a hard consensus rule change (e.g. headcount quorum →
# stake-weighted quorum), rolling restart will FORK the network: the first
# restarted node refuses quorums formed under the old rule, and the un-restarted
# nodes refuse quorums formed under the new rule.
#
# The safe path for a hard rule change is a brief, coordinated halt:
#
#   1. SSH into every validator and stop the systemd unit. Network stalls.
#   2. Update the IMAGE= pin in every VM's wrapper.
#   3. Start every validator simultaneously. They come up on the new rule,
#      reach quorum, and resume block production.
#
# This script does that in three phases. Each phase is parallel-fanned across
# the fleet and waits for every VM to acknowledge before moving on, so we
# never half-cut the world.
#
# # Usage
#
#   ./scripts/stop-the-world-cutover.sh <full-image-digest> [--dry-run]
#
# The digest must be the full `host/path/name@sha256:...` form produced by
# `cloudbuild-image.yaml`. Pass --dry-run to print the plan without touching
# the fleet.

set -euo pipefail

PROJECT_ID="tenzro-infra"
REGISTRY="us-central1-docker.pkg.dev/${PROJECT_ID}/tenzro"
IMAGE_NAME="tenzro-node"
UNIT="tenzro-node.service"
WRAPPER="/var/lib/tenzro-bin/tenzro-run"

# All validators — order does not matter for a stop-the-world cutover (we
# halt all of them before starting any). The bootstrap (validator-0) gets
# started a beat earlier than the others so peers re-handshake against a
# known anchor; see PHASE 3 below.
VALIDATORS=(
  "tenzro-validator-1:us-central1-b"
  "tenzro-validator-4:europe-west1-b"
  "tenzro-validator-7:asia-southeast1-a"
)
BOOTSTRAP_VALIDATOR="tenzro-validator-0:us-central1-a"

# After starting, how long to give the network to converge on a new tip
# before declaring success. Same generous budget as the rolling script.
CONVERGE_TIMEOUT_S=240
CONVERGE_POLL_S=5

IMAGE_DIGEST="${1:-}"
DRY_RUN="${2:-}"

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }

if [[ -z "$IMAGE_DIGEST" ]]; then
    red "usage: $0 <full-image-digest> [--dry-run]"
    red "example: $0 ${REGISTRY}/${IMAGE_NAME}@sha256:abc...123"
    exit 1
fi

if [[ "$IMAGE_DIGEST" != *"@sha256:"* ]]; then
    if [[ "$IMAGE_DIGEST" == sha256:* ]]; then
        IMAGE_DIGEST="${REGISTRY}/${IMAGE_NAME}@${IMAGE_DIGEST}"
    else
        red "Digest must be a sha256: pin (got: $IMAGE_DIGEST)"
        exit 1
    fi
fi

green "Verifying image exists in Artifact Registry..."
if ! gcloud artifacts docker images describe "$IMAGE_DIGEST" \
        --project="$PROJECT_ID" --format='value(name)' >/dev/null 2>&1; then
    red "Image not found in Artifact Registry: $IMAGE_DIGEST"
    exit 1
fi
green "Image confirmed."

ALL=("${BOOTSTRAP_VALIDATOR}" "${VALIDATORS[@]}")

if [[ "$DRY_RUN" == "--dry-run" ]]; then
    yellow "DRY RUN — would cut over the following fleet simultaneously:"
    for entry in "${ALL[@]}"; do printf '  %s\n' "$entry"; done
    yellow "Each VM's $WRAPPER IMAGE= line would be repointed to:"
    yellow "  $IMAGE_DIGEST"
    yellow "Then all units would stop, restart, and the script would wait up"
    yellow "to ${CONVERGE_TIMEOUT_S}s for the chain to advance under the new rule."
    exit 0
fi

# Confirmation gate — stop-the-world halts consensus on the live testnet.
# If the operator invoked us in an unattended context (no TTY), we still
# require an explicit env flag so this can never run accidentally.
if [[ -t 0 ]]; then
    yellow "About to halt the live testnet (${#ALL[@]} validators) and cut over to:"
    yellow "  $IMAGE_DIGEST"
    yellow "Estimated consensus halt: 2-5 minutes."
    read -r -p "Type 'CUTOVER' to proceed: " confirm
    if [[ "$confirm" != "CUTOVER" ]]; then
        red "aborted by operator"
        exit 1
    fi
elif [[ "${UNATTENDED_CUTOVER:-}" != "yes" ]]; then
    red "non-interactive context; set UNATTENDED_CUTOVER=yes to proceed"
    exit 1
fi

# Run a remote shell command in parallel across every VM, waiting for all
# children before returning. Any non-zero child causes us to exit immediately
# — the only safe behavior when half the fleet did the thing and half didn't.
run_parallel() {
    local desc="$1"
    shift
    local cmd="$*"

    yellow "[parallel] ${desc}"
    local pids=() names=()
    for entry in "${ALL[@]}"; do
        local name="${entry%%:*}"
        local zone="${entry##*:}"
        gcloud compute ssh "$name" \
            --zone="$zone" --project="$PROJECT_ID" --tunnel-through-iap --quiet \
            --command="$cmd" >/tmp/cutover_${name}.log 2>&1 &
        pids+=($!)
        names+=("$name")
    done

    local failed=0
    for i in "${!pids[@]}"; do
        if ! wait "${pids[$i]}"; then
            red "  FAILED on ${names[$i]} — see /tmp/cutover_${names[$i]}.log"
            failed=1
        else
            green "  ok: ${names[$i]}"
        fi
    done

    if [[ "$failed" -ne 0 ]]; then
        red "[parallel] ${desc} did not complete on all VMs"
        return 1
    fi
}

# Read the local-RPC chain height on one VM (via IAP). Returns the integer or 0.
height_on() {
    local entry="$1"
    local name="${entry%%:*}"
    local zone="${entry##*:}"
    gcloud compute ssh "$name" \
        --zone="$zone" --project="$PROJECT_ID" --tunnel-through-iap --quiet \
        --command='curl -fsS -X POST -H "content-type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"tenzro_blockNumber\",\"params\":[],\"id\":1}" \
            http://127.0.0.1:8545 | python3 -c "import sys,json; r=json.load(sys.stdin).get(\"result\",\"0x0\"); print(int(r,16) if isinstance(r,str) and r.startswith(\"0x\") else int(r or 0))" 2>/dev/null || echo 0' \
        2>/dev/null || echo 0
}

# Capture pre-cutover heights so we can verify post-cutover advance.
green "==== capturing pre-cutover heights ===="
declare -A BEFORE
for entry in "${ALL[@]}"; do
    name="${entry%%:*}"
    BEFORE["$name"]=$(height_on "$entry")
    yellow "  $name: ${BEFORE[$name]}"
done

# PHASE 1: rewrite the IMAGE= pin on every VM (in parallel). This is
# idempotent — re-running with the same digest is a no-op. Stopping the unit
# does NOT happen here; we want to wait until every wrapper is updated before
# starting the halt, otherwise a VM whose wrapper update fails would come
# back up on the OLD digest mid-cutover.
green "==== PHASE 1: updating wrapper digest pin on every VM ===="
run_parallel "sed wrapper" \
    "sudo sed -i.bak -E 's|^IMAGE=\".*\"|IMAGE=\"$IMAGE_DIGEST\"|' '$WRAPPER' \
     && sudo grep -E '^IMAGE=' '$WRAPPER'"

# PHASE 2: stop every validator. The testnet is now halted.
green "==== PHASE 2: stopping every validator (network halts) ===="
run_parallel "systemctl stop" "sudo systemctl stop '$UNIT' || true"

# PHASE 3: start the bootstrap first, then the rest immediately. Peers expect
# a stable bootstrap endpoint when re-handshaking; bringing it up a hair
# earlier reduces the time spent in 'no peers' state on the other nodes.
green "==== PHASE 3: starting validators (bootstrap first) ===="
bs_name="${BOOTSTRAP_VALIDATOR%%:*}"
bs_zone="${BOOTSTRAP_VALIDATOR##*:}"
yellow "  starting $bs_name (bootstrap)..."
gcloud compute ssh "$bs_name" \
    --zone="$bs_zone" --project="$PROJECT_ID" --tunnel-through-iap --quiet \
    --command="sudo systemctl start '$UNIT'"
green "  bootstrap started"

# A short pause so the bootstrap's libp2p listener is up before peers dial it.
sleep 5

yellow "  starting remaining ${#VALIDATORS[@]} validators in parallel..."
pids=()
for entry in "${VALIDATORS[@]}"; do
    name="${entry%%:*}"
    zone="${entry##*:}"
    gcloud compute ssh "$name" \
        --zone="$zone" --project="$PROJECT_ID" --tunnel-through-iap --quiet \
        --command="sudo systemctl start '$UNIT'" >/tmp/cutover_start_${name}.log 2>&1 &
    pids+=($!)
done
for pid in "${pids[@]}"; do wait "$pid"; done
green "  all validators started"

# PHASE 4: wait for the new chain to advance. Success = at least one validator
# reports a finalized height GREATER than its pre-cutover height. If the
# stake-weighted rule change is wrong, no quorum forms and no height advance
# will happen — that's the failure signal.
green "==== PHASE 4: waiting up to ${CONVERGE_TIMEOUT_S}s for chain advance ===="
deadline=$(( $(date +%s) + CONVERGE_TIMEOUT_S ))
converged=0
while [[ $(date +%s) -lt $deadline ]]; do
    sleep "$CONVERGE_POLL_S"
    advanced=0
    for entry in "${ALL[@]}"; do
        name="${entry%%:*}"
        h=$(height_on "$entry")
        if [[ "$h" -gt "${BEFORE[$name]}" ]]; then
            advanced=$(( advanced + 1 ))
        fi
        yellow "  $name: $h (pre=${BEFORE[$name]})"
    done
    if [[ "$advanced" -ge 3 ]]; then
        green "  ${advanced}/${#ALL[@]} validators have advanced past their pre-cutover height"
        converged=1
        break
    fi
done

if [[ "$converged" -ne 1 ]]; then
    red "==== CUTOVER FAILED: chain did not advance within ${CONVERGE_TIMEOUT_S}s ===="
    red "  investigate per-VM logs:"
    for entry in "${ALL[@]}"; do
        name="${entry%%:*}"
        zone="${entry##*:}"
        red "    gcloud compute ssh $name --zone=$zone --tunnel-through-iap --command='sudo journalctl -u $UNIT -n 100 --no-pager'"
    done
    exit 1
fi

green "==== CUTOVER COMPLETE ===="
