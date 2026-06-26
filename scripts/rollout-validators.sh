#!/usr/bin/env bash
# Rolling restart of the per-VM tenzronet validator fleet onto a new image.
#
# # Why this script
#
# The testnet runs on GCE VMs (`tenzro-validator-*`) under per-VM systemd, NOT
# on GKE. The legacy `scripts/deploy-testnet.sh` targets a GKE cluster that the
# production system does not use; running it would create a redundant cluster.
# This script is the correct rollout path: bump the digest pin in each VM's
# wrapper script and bounce the systemd unit, one VM at a time.
#
# # Flow
#
# 1. Verify the requested `IMAGE_DIGEST` exists in Artifact Registry.
# 2. For each validator in restart order (non-bootstrap first, bootstrap last):
#    - SSH in via IAP tunnel.
#    - Rewrite the `IMAGE=...` line in `/var/lib/tenzro-bin/tenzro-run` so the
#      next start pulls the requested digest.
#    - `systemctl restart tenzro-node.service`.
#    - Wait for the node's local JSON-RPC to report a finalized block height
#      higher than the height it reported pre-restart (proves it joined back).
# 3. Abort on the first VM that fails verification — never proceed past a
#    broken validator into the bootstrap restart.
#
# # Usage
#
#   ./scripts/rollout-validators.sh <image-digest>
#
# where <image-digest> is the full `us-central1-docker.pkg.dev/.../tenzro-node@sha256:...`
# pin produced by `cloudbuild-image.yaml`. Pass `--dry-run` as the second arg
# to print the plan without touching VMs.

set -euo pipefail

PROJECT_ID="tenzro-operator-project"
REGISTRY="us-central1-docker.pkg.dev/${PROJECT_ID}/tenzro"
IMAGE_NAME="tenzro-node"
UNIT="tenzro-node.service"
WRAPPER="/var/lib/tenzro-bin/tenzro-run"

# Restart order: non-bootstrap first (so the bootstrap anchor stays up while
# the rest re-handshake against it), bootstrap last. Adjust here if the fleet
# changes; the live list can be confirmed with:
#   gcloud compute instances list --project=tenzro-operator-project --filter="name~'^tenzro-validator-'"
VALIDATORS=(
  "tenzro-validator-1:us-central1-b"
  "tenzro-validator-4:europe-west1-b"
  "tenzro-validator-7:asia-southeast1-a"
  "tenzro-validator-0:us-central1-a"
)

# How long to wait for a restarted node to advance one block before declaring
# the rollout step healthy. 90s covers BFT round latency + image pull.
HEALTH_TIMEOUT_S=180

# How long to wait between probes while polling for block-height advance.
HEALTH_POLL_S=5

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

# Accept either a full `host/path/name@sha256:...` or a bare `sha256:...`.
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
    red "Build it first via cloudbuild-image.yaml."
    exit 1
fi
green "Image confirmed."

if [[ "$DRY_RUN" == "--dry-run" ]]; then
    yellow "DRY RUN — would roll the following validators in order:"
    for entry in "${VALIDATORS[@]}"; do
        printf '  %s\n' "$entry"
    done
    yellow "Each would have its $WRAPPER IMAGE= line repointed to:"
    yellow "  $IMAGE_DIGEST"
    yellow "and $UNIT restarted, then health-checked for ${HEALTH_TIMEOUT_S}s."
    exit 0
fi

# Per-VM rollout. Each step must succeed before we move on.
for entry in "${VALIDATORS[@]}"; do
    name="${entry%%:*}"
    zone="${entry##*:}"

    green "==== rolling $name ($zone) ===="

    # Capture the validator's pre-restart finalized height. The probe runs
    # via IAP-tunneled SSH and reads localhost:8545 inside the VM so we are
    # not exposed to firewall variance between zones. A node that is already
    # wedged before the restart gets a zero baseline; the success criterion
    # still requires advance after the restart.
    before=$(gcloud compute ssh "$name" \
        --zone="$zone" --project="$PROJECT_ID" --tunnel-through-iap --quiet \
        --command='curl -fsS -X POST -H "content-type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"tenzro_blockNumber\",\"params\":[],\"id\":1}" \
            http://127.0.0.1:8545 | python3 -c "import sys,json; r=json.load(sys.stdin).get(\"result\",\"0x0\"); print(int(r,16) if isinstance(r,str) and r.startswith(\"0x\") else int(r or 0))" 2>/dev/null || echo 0' \
        2>/dev/null || echo 0)
    yellow "  pre-restart height: $before"

    # Bump the wrapper's pinned digest and bounce the systemd unit. The sed
    # replaces any current `IMAGE="..."` assignment with the new digest. The
    # wrapper itself does `docker pull "$IMAGE"` on every restart, so the
    # next `systemctl restart` picks up the new pin automatically.
    gcloud compute ssh "$name" \
        --zone="$zone" --project="$PROJECT_ID" --tunnel-through-iap --quiet \
        --command="sudo sed -i.bak -E 's|^IMAGE=\".*\"|IMAGE=\"$IMAGE_DIGEST\"|' '$WRAPPER' \
                   && sudo grep -E '^IMAGE=' '$WRAPPER' \
                   && sudo systemctl restart '$UNIT'"

    # Poll for finalized-height advance. The node must publish a block whose
    # height is strictly greater than `before` within HEALTH_TIMEOUT_S to be
    # considered healthy. We re-SSH each probe instead of holding a session
    # open so transient IAP timeouts don't poison the check.
    deadline=$(( $(date +%s) + HEALTH_TIMEOUT_S ))
    healthy=0
    while [[ $(date +%s) -lt $deadline ]]; do
        sleep "$HEALTH_POLL_S"
        after=$(gcloud compute ssh "$name" \
            --zone="$zone" --project="$PROJECT_ID" --tunnel-through-iap --quiet \
            --command='curl -fsS -X POST -H "content-type: application/json" \
                -d "{\"jsonrpc\":\"2.0\",\"method\":\"tenzro_chainHeight\",\"params\":[],\"id\":1}" \
                http://127.0.0.1:8545 | python3 -c "import sys,json; print(int(json.load(sys.stdin).get(\"result\",0)))" 2>/dev/null || echo 0' \
            2>/dev/null || echo 0)
        if [[ "$after" -gt "$before" ]]; then
            green "  post-restart height: $after (advanced $((after - before)) blocks) — healthy"
            healthy=1
            break
        fi
        yellow "  post-restart height: $after (not yet advanced)"
    done

    if [[ "$healthy" -ne 1 ]]; then
        red "  $name did NOT advance within ${HEALTH_TIMEOUT_S}s; aborting rollout"
        red "  to investigate: gcloud compute ssh $name --zone=$zone --tunnel-through-iap --command='sudo journalctl -u $UNIT -n 100 --no-pager'"
        exit 1
    fi
done

green "==== rollout complete on all ${#VALIDATORS[@]} validators ===="
