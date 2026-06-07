# Tenzro Node Quick Start Guide

Get a Tenzro Network node up and running in minutes.

## Prerequisites

- Rust 1.70+ (install from https://rustup.rs)
- 8GB+ RAM recommended
- 100GB+ free disk space
- Linux, macOS, or Windows (WSL2)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/tenzro/tenzro-network.git
cd tenzro-network

# Build the node
cargo build --release -p tenzro-node

# The binary is now at: target/release/tenzro-node
```

### Verify Installation

```bash
./target/release/tenzro-node --version
```

You should see:
```
tenzro-node 0.1.0
```

## Running Your First Node

### 1. LightClient (Simplest)

Perfect for interacting with the network:

```bash
./target/release/tenzro-node \
  --role light-client \
  --data-dir ./data/light \
  --log-level info
```

### 2. Validator Node

Participate in consensus:

```bash
./target/release/tenzro-node \
  --role validator \
  --data-dir ./data/validator \
  --log-level info
```

### 3. Model Provider

Serve AI models:

```bash
./target/release/tenzro-node \
  --role model-provider \
  --data-dir ./data/provider \
  --log-level info
```

## Using Configuration Files

Create `my-config.json`:

```json
{
  "role": "Validator",
  "data_dir": "./data/my-node",
  "log_level": "info",
  "rpc_addr": "0.0.0.0:8545",
  "web_addr": "0.0.0.0:8080",
  "mcp_addr": "0.0.0.0:3001",
  "a2a_addr": "0.0.0.0:3002",
  "tee_enabled": false,
  "metrics_enabled": true,
  "health_enabled": true,
  "network": {
    "listen_addresses": [
      "/ip4/0.0.0.0/tcp/9000",
      "/ip4/0.0.0.0/udp/9000/quic-v1"
    ],
    "boot_nodes": [],
    "max_peers": 50,
    "chain": "Testnet"
  }
}
```

Run with:

```bash
./target/release/tenzro-node --config my-config.json
```

## Interacting with Your Node

### Using curl (JSON-RPC)

```bash
# Get node info
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_nodeInfo",
    "params": [],
    "id": 1
  }'

# Get block number
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_blockNumber",
    "params": [],
    "id": 1
  }'

# Get peer count
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_peerCount",
    "params": [],
    "id": 1
  }'
```

### Using the Tenzro CLI

```bash
# Install the CLI
cargo install --path crates/tenzro-cli

# Check node status
tenzro node status

# Query balance
tenzro wallet balance <address>

# List models
tenzro model list
```

## Connecting to Testnet

To connect to the Tenzro testnet:

```bash
./target/release/tenzro-node \
  --role light-client \
  --data-dir ./data/testnet \
  --log-level info
```

The binary's default `--boot-nodes` list points at the live tri-continental testnet seeds; override it only for a private deployment.

## Monitoring Your Node

### View Logs

Logs are output to stdout. To save them:

```bash
./target/release/tenzro-node \
  --role validator \
  --data-dir ./data/validator 2>&1 | tee node.log
```

### Health Check

```bash
curl http://localhost:8545 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_nodeInfo",
    "params": [],
    "id": 1
  }' | jq .
```

### Metrics

Check metrics with:

```bash
curl http://localhost:8545 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_nodeInfo",
    "params": [],
    "id": 1
  }' | jq '.result.metrics'
```

## Stopping Your Node

Press `Ctrl+C` in the terminal where the node is running. The node will:
1. Stop accepting new requests
2. Flush pending data
3. Cleanly shut down all subsystems
4. Exit

## Troubleshooting

### "Failed to bind RPC server"

Another process is using port 8545. Use a different port:

```bash
./target/release/tenzro-node \
  --rpc-addr 127.0.0.1:8546 \
  ...other args...
```

### "Failed to create data directory"

Ensure you have write permissions:

```bash
mkdir -p ./data/validator
chmod 755 ./data/validator
```

### Low Peer Count

1. Check your firewall allows TCP and UDP on port 9000 (libp2p TCP + QUIC)
2. Add boot nodes with `--boot-nodes`
3. Wait a few minutes for peer discovery

### High Memory Usage

Limit memory with:

```bash
# On Linux with systemd
systemctl set-property tenzro-node.service MemoryMax=4G

# Or run with ulimit
ulimit -v 4194304  # 4GB in KB
./target/release/tenzro-node ...
```

## Next Steps

- Read the [full README](README.md)
- Explore the [Architecture documentation](ARCHITECTURE.md)
- Join the community
- Deploy a TEE Provider (see the main [README](../../README.md))
- Set up a Model Provider (see the main [README](../../README.md))

## Production Deployment

For production, use:
- systemd service (see `tenzro-node.service`)
- Dedicated user account
- Firewall configuration
- Monitoring (Prometheus/Grafana)
- Backup strategy for data directory
- Log rotation

See [`deploy/README.md`](../../deploy/README.md) for production deployment details.
