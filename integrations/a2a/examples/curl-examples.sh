#!/usr/bin/env bash
# Tenzro A2A Protocol -- cURL Examples
#
# Usage:
#   chmod +x curl-examples.sh
#   ./curl-examples.sh
#
# Set TENZRO_A2A_URL to override the endpoint:
#   TENZRO_A2A_URL=http://localhost:3002 ./curl-examples.sh

set -euo pipefail

A2A="${TENZRO_A2A_URL:-https://a2a.tenzro.network}"

echo "=== Tenzro A2A cURL Examples ==="
echo "Endpoint: $A2A"
echo ""

# --- 1. Agent Card Discovery ---
echo "1. Fetching Agent Card..."
curl -s "$A2A/.well-known/agent.json" | python3 -m json.tool 2>/dev/null || \
  curl -s "$A2A/.well-known/agent.json"
echo ""

# --- 2. Send a Task ---
echo "2. Sending task: node status query..."
curl -s -X POST "$A2A/a2a" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"type": "text", "text": "What is the node status?"}]
      }
    },
    "id": 1
  }' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

# --- 3. Query Balance ---
echo "3. Querying balance..."
curl -s -X POST "$A2A/a2a" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"type": "text", "text": "What is the balance of 0x0000000000000000000000000000000000000000?"}]
      }
    },
    "id": 2
  }' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

# --- 4. Get Block Height ---
echo "4. Getting block height..."
curl -s -X POST "$A2A/a2a" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"type": "text", "text": "What is the current block height?"}]
      }
    },
    "id": 3
  }' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

# --- 5. Identity Operations ---
echo "5. Registering identity..."
curl -s -X POST "$A2A/a2a" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"type": "text", "text": "Register a new human identity with name TestUser"}]
      }
    },
    "id": 4
  }' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

# --- 6. List Tasks ---
echo "6. Listing all tasks..."
curl -s -X POST "$A2A/a2a" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tasks/list",
    "params": {},
    "id": 5
  }' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

# --- 7. Get Task by ID ---
echo "7. Getting task by ID (replace TASK_ID)..."
echo "   curl -s -X POST $A2A/a2a \\"
echo '     -H "Content-Type: application/json" \'
echo '     -d '"'"'{"jsonrpc":"2.0","method":"tasks/get","params":{"id":"TASK_ID"},"id":6}'"'"
echo ""

# --- 8. Cancel Task ---
echo "8. Canceling task (replace TASK_ID)..."
echo "   curl -s -X POST $A2A/a2a \\"
echo '     -H "Content-Type: application/json" \'
echo '     -d '"'"'{"jsonrpc":"2.0","method":"tasks/cancel","params":{"id":"TASK_ID"},"id":7}'"'"
echo ""

# --- 9. Streaming (SSE) ---
echo "9. Streaming task response..."
echo "   curl -N -X POST $A2A/a2a/stream \\"
echo '     -H "Content-Type: application/json" \'
echo '     -H "Accept: text/event-stream" \'
echo '     -d '"'"'{"jsonrpc":"2.0","method":"tasks/send","params":{"message":{"role":"user","parts":[{"type":"text","text":"Get network status"}]}},"id":1}'"'"
echo ""

# --- 10. Faucet via A2A ---
echo "10. Requesting faucet tokens..."
curl -s -X POST "$A2A/a2a" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"type": "text", "text": "Request faucet tokens for 0x0000000000000000000000000000000000000001"}]
      }
    },
    "id": 8
  }' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

# --- 11. List Tokens ---
echo "11. Listing tokens..."
curl -s -X POST "$A2A/a2a" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"type": "text", "text": "List all registered tokens"}]
      }
    },
    "id": 9
  }' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

# --- 12. Task Marketplace ---
echo "12. Task marketplace..."
curl -s -X POST "$A2A/a2a" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"type": "text", "text": "List open tasks in the marketplace"}]
      }
    },
    "id": 10
  }' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

# --- 13. Agent Templates ---
echo "13. Agent marketplace..."
curl -s -X POST "$A2A/a2a" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"type": "text", "text": "List available agent templates"}]
      }
    },
    "id": 11
  }' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

# --- 14. Join as MicroNode ---
echo "14. Join as MicroNode..."
curl -s -X POST "$A2A/a2a" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"type": "text", "text": "Join the Tenzro Network as CurlTestNode"}]
      }
    },
    "id": 12
  }' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

echo "=== Done ==="
