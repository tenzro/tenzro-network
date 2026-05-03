#!/usr/bin/env bash
set -euo pipefail

# Generate genesis configuration for Tenzro Network testnet
#
# Usage: ./scripts/generate-genesis.sh [NUM_VALIDATORS] [OUTPUT_FILE]
#
# Generates:
# - Ed25519 keypairs for each validator
# - Genesis TOML config with validator public keys and pre-funded accounts
# - Outputs private keys to separate files

NUM_VALIDATORS=${1:-7}
OUTPUT_DIR=${2:-"config/testnet"}
GENESIS_FILE="${OUTPUT_DIR}/genesis.toml"

echo "============================================"
echo "  Tenzro Network Genesis Generator"
echo "============================================"
echo "Validators: ${NUM_VALIDATORS}"
echo "Output dir: ${OUTPUT_DIR}"
echo ""

# Create output directory
mkdir -p "${OUTPUT_DIR}/keys"

# Generate validator keys using openssl
echo "Generating validator keypairs..."

VALIDATORS_TOML=""
for i in $(seq 1 ${NUM_VALIDATORS}); do
    # Generate 32 random bytes as a hex-encoded public key placeholder
    # In production, these would be actual Ed25519 public keys from tenzro-cli
    PUB_KEY=$(openssl rand -hex 32)
    PRIV_KEY=$(openssl rand -hex 64)

    # Save keys
    echo "${PRIV_KEY}" > "${OUTPUT_DIR}/keys/validator-${i}.key"
    echo "${PUB_KEY}" > "${OUTPUT_DIR}/keys/validator-${i}.pub"
    chmod 600 "${OUTPUT_DIR}/keys/validator-${i}.key"

    VALIDATORS_TOML="${VALIDATORS_TOML}
[[validators]]
public_key = \"${PUB_KEY}\"
stake = 10000
"
    echo "  Validator ${i}: ${PUB_KEY:0:16}..."
done

# Generate faucet account
FAUCET_KEY=$(openssl rand -hex 32)
echo "${FAUCET_KEY}" > "${OUTPUT_DIR}/keys/faucet.key"
chmod 600 "${OUTPUT_DIR}/keys/faucet.key"
echo "  Faucet:      ${FAUCET_KEY:0:16}..."

# Generate pre-funded test accounts
TEST_ACCOUNT_1=$(openssl rand -hex 32)
TEST_ACCOUNT_2=$(openssl rand -hex 32)
echo "${TEST_ACCOUNT_1}" > "${OUTPUT_DIR}/keys/test-account-1.key"
echo "${TEST_ACCOUNT_2}" > "${OUTPUT_DIR}/keys/test-account-2.key"

# Write genesis TOML
cat > "${GENESIS_FILE}" << EOF
# Tenzro Network Testnet Genesis Configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Validators: ${NUM_VALIDATORS}

chain_id = 1337
timestamp = 0
${VALIDATORS_TOML}
[[accounts]]
address = "${TEST_ACCOUNT_1}"
balance = 10000000

[[accounts]]
address = "${TEST_ACCOUNT_2}"
balance = 10000000

[faucet]
address = "${FAUCET_KEY}"
amount_per_request = 100
cooldown_seconds = 86400
enabled = true
EOF

echo ""
echo "============================================"
echo "  Genesis configuration generated!"
echo "============================================"
echo "  Config: ${GENESIS_FILE}"
echo "  Keys:   ${OUTPUT_DIR}/keys/"
echo ""
echo "  IMPORTANT: Back up validator keys securely!"
echo "  Never commit private keys to version control."
echo ""
echo "  To start a validator:"
echo "    tenzro-node --role validator --genesis ${GENESIS_FILE}"
echo "============================================"
