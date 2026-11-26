#!/bin/sh
# Looks for a node running as a service on the machine about to build or test.
# A release build or a test run takes the processors and memory a node needs
# to keep up with consensus, and a validator that falls behind stops signing.
#
#   check-build-host.sh [--quiet]
#
# A machine that runs a node and builds too gets one warning line (none with
# --quiet) and exit 0. A machine whose operator forbids builds refuses with
# exit 1: the operator creates the marker file /etc/tenzro/no-builds, or sets
# TENZRO_BUILD_GUARD=enforce. A machine without systemd has no node service to
# find and passes.
quiet=0; [ "${1:-}" = --quiet ] && quiet=1
command -v systemctl >/dev/null 2>&1 || exit 0
marker=/etc/tenzro/no-builds
for unit in tenzro-node.service tenzro-testnet-node.service; do
    for scope in --system --user; do
        systemctl "$scope" is-active --quiet "$unit" 2>/dev/null || continue
        if [ -e "$marker" ] || [ "${TENZRO_BUILD_GUARD:-}" = enforce ]; then
            echo "REFUSING: $unit is active on this machine ($scope) and its operator forbids builds here ($marker or TENZRO_BUILD_GUARD=enforce). Build and test on another machine." >&2
            exit 1
        fi
        [ $quiet = 1 ] || echo "warning: $unit is active on this machine ($scope); a build or test run here competes with the node" >&2
        exit 0
    done
done
exit 0
