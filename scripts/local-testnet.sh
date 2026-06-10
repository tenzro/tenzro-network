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

        # Generate genesis if not exists. Uses tools/genkeys to produce
        # a full v3-schema genesis (Ed25519 + ML-DSA-65 + BLS12-381 per
        # validator) so the binary can boot.
        if [ ! -f "${PROJECT_DIR}/config/genesis-local.toml" ]; then
            echo "Generating local genesis via tools/genkeys (v3 schema)..."
            (cd "${PROJECT_DIR}" && cargo build --release -p tenzro-genkeys >/dev/null 2>&1)
            tmpdir=$(mktemp -d -t tenzro-local-genesis-XXXXXX)
            "${PROJECT_DIR}/target/release/tenzro-genkeys" \
                --out "${tmpdir}" \
                --count 3 \
                --chain-id 1337 \
                --stake-per-validator 1000
            cp "${tmpdir}/genesis-prod.toml" "${PROJECT_DIR}/config/genesis-local.toml"
            echo "Wrote ${PROJECT_DIR}/config/genesis-local.toml"
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
