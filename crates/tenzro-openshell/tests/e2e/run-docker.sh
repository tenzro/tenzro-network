#!/usr/bin/env bash
# Run the OpenShell end-to-end test on a Docker host with a TPM.
#
#   run-docker.sh <openshell checkout at the pinned release> <test binary>
#
# Needs OPENSHELL_BIN (the openshell CLI) and OPENSHELL_GATEWAY_BIN (the
# openshell-gateway binary) of the same release, TENZRO_NODE_LAUNCH (the
# program that runs a Tenzro developer chain of this tree on a TPM of its
# own, such as devnode-swtpm.sh beside this script),
# a Docker daemon the user can reach and a /dev/tpmrm0 the user can open. OpenShell's own e2e support
# scripts issue the gateway PKI and JWT keys and register the gateway with the
# CLI; the test starts the gateway itself, after the Tenzro extensions it
# calls at startup.
set -euo pipefail

OS_SRC=$(cd "$1" && pwd)
TEST_BIN=$2
: "${OPENSHELL_BIN:?set OPENSHELL_BIN to the openshell CLI}"
: "${OPENSHELL_GATEWAY_BIN:?set OPENSHELL_GATEWAY_BIN to openshell-gateway}"
: "${TENZRO_NODE_LAUNCH:?set TENZRO_NODE_LAUNCH to a developer-chain launcher such as devnode-swtpm.sh}"

# shellcheck source=/dev/null
source "${OS_SRC}/e2e/support/gateway-common.sh"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/tenzro-openshell-e2e.XXXXXX")
export XDG_CONFIG_HOME="${WORK}/config"
export XDG_STATE_HOME="${WORK}/state"
export TENZRO_DEVICE_KEY_DIR="${WORK}/device-keys"
mkdir -p "${XDG_CONFIG_HOME}" "${XDG_STATE_HOME}" "${TENZRO_DEVICE_KEY_DIR}"

PORT=$(e2e_pick_port)
HEALTH_PORT=$(e2e_pick_port)
NAME="tenzro-openshell-e2e-${PORT}"

e2e_generate_pki "${OPENSHELL_GATEWAY_BIN}" "${WORK}/pki"
e2e_generate_gateway_jwt "${WORK}/jwt"
e2e_register_mtls_gateway "${XDG_CONFIG_HOME}" "${NAME}" \
  "https://127.0.0.1:${PORT}" "${PORT}" "${WORK}/pki"

export OPENSHELL_GATEWAY="${NAME}"
export OPENSHELL_PROVISION_TIMEOUT="${OPENSHELL_PROVISION_TIMEOUT:-180}"
export TENZRO_E2E_WORK="${WORK}"
export TENZRO_E2E_PORT="${PORT}"
export TENZRO_E2E_HEALTH_PORT="${HEALTH_PORT}"

echo "work dir: ${WORK}"
status=0
"${TEST_BIN}" --nocapture --test-threads 1 || status=$?
if [ "${status}" -ne 0 ] && [ -f "${WORK}/gateway.log" ]; then
  echo "--- gateway log (last 80 lines)"
  tail -80 "${WORK}/gateway.log"
fi
exit "${status}"
