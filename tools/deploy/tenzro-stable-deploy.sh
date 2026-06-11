#!/bin/bash
# Stable validator deploy: in-place image rotation that preserves chain DB.
#
# Per CLAUDE.md: validators must survive image upgrades without losing chain
# state. The earlier deploy script wiped /var/lib/tenzro/db on every roll,
# which made every binary upgrade a chain-reset event for the validator.
# That's not how decentralized networks upgrade.
#
# This script:
#   1. Stops the container.
#   2. Updates the pinned image digest in the wrapper.
#   3. Restarts the container against the SAME data directory.
#
# The Rust-side `verify_chain_compat` check (genesis.rs) refuses to start if
# the configured genesis no longer matches the on-disk chain — so this is
# safe: same genesis = preserve DB; different genesis = fail loud, operator
# decides whether to wipe.
#
# Args: $1 = DIGEST (sha256:...)
set -euo pipefail
DIGEST="$1"

if ! [[ "$DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]]; then
  echo "ERROR: DIGEST must be a sha256:<64-hex> manifest digest"
  exit 1
fi

WRAPPER=/var/lib/tenzro-bin/tenzro-run
if [[ ! -s "$WRAPPER" ]]; then
  echo "ERROR: wrapper not found at $WRAPPER"
  exit 1
fi

echo "=== Stable upgrade to $DIGEST ==="
sudo systemctl status tenzro-node --no-pager 2>&1 | head -3 || true

# 1. Stop the container. systemd KillSignal=SIGTERM aligns with the node's
# graceful_exit() handler; the node should drain in <60s.
sudo systemctl stop tenzro-node.service 2>/dev/null || true
sudo docker stop tenzro-node 2>/dev/null || true

# 2. Update the pinned image digest in the wrapper. The previous digest is
# replaced in-place — no other state mutations.
OLD_DIGEST=$(sudo grep -oE 'sha256:[a-f0-9]+' "$WRAPPER" | head -1)
if [[ "$OLD_DIGEST" == "$DIGEST" ]]; then
  echo "Image digest unchanged ($DIGEST) — no work to do"
else
  sudo sed -i "s|$OLD_DIGEST|$DIGEST|" "$WRAPPER"
  echo "Image digest: $OLD_DIGEST → $DIGEST"
fi

# 3. Start the container. The node will hit verify_chain_compat on boot;
# if the genesis is unchanged it will load the existing DB and re-join
# consensus at its prior height. If the genesis has drifted (different
# chain_id or different state_root) the node will refuse to start and
# the operator must decide.
sudo systemctl start tenzro-node.service
echo "=== container starting ==="

# Wait briefly + report status. Real readiness verification (peer count,
# height advance) is the caller's responsibility — this script is the
# minimal stable rotation primitive.
sleep 5
sudo docker ps --format "{{.Names}} {{.Status}}" | grep tenzro-node || \
  { echo "WARN: container not up yet — check journalctl -u tenzro-node.service"; exit 0; }

echo "=== done ==="
