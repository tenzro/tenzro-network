#!/usr/bin/env bash
set -euo pipefail

# Start a local Tenzro testnet with Docker Compose
#
# Usage: ./scripts/local-testnet.sh [start|stop|status|logs]

COMMAND=${1:-start}
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "${COMMAND}" in
    start)
        echo "Starting local Tenzro testnet..."
        echo ""

        # Validators hold their consensus keys in hardware, so no key can be
        # generated for them here: the genesis must already name them.
        if ! grep -q '^\[\[validators\]\]' "${PROJECT_DIR}/config/genesis-local.toml"; then
            echo "config/genesis-local.toml names no validators. Add one entry per" >&2
            echo "validator, printed on each validator machine by:" >&2
            echo "  tenzro-node validator-entry --stake <whole TNZO>" >&2
            exit 1
        fi

        # Build and start
        cd "${PROJECT_DIR}"
        docker compose up -d --build

        echo ""
        echo "Local testnet started!"
        echo "  RPC endpoint:  http://localhost:8545"
        echo "  Web API:       http://localhost:8080"
        echo ""
        echo "  View logs:     ./scripts/local-testnet.sh logs"
        echo "  Stop:          ./scripts/local-testnet.sh stop"
        ;;

    stop)
        echo "Stopping local Tenzro testnet..."
        cd "${PROJECT_DIR}"
        docker compose down
        echo "Testnet stopped."
        ;;

    status)
        cd "${PROJECT_DIR}"
        docker compose ps
        ;;

    logs)
        cd "${PROJECT_DIR}"
        docker compose logs -f --tail=100 "${@:2}"
        ;;

    clean)
        echo "Stopping and removing all data..."
        cd "${PROJECT_DIR}"
        docker compose down -v
        echo "All data removed."
        ;;

    *)
        echo "Usage: $0 {start|stop|status|logs|clean}"
        exit 1
        ;;
esac
