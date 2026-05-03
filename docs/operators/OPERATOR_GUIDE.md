# Tenzro Node Operator Guide

Complete reference for running a Tenzro Network node in production. For a
faster onboarding walkthrough, see `crates/tenzro-node/QUICKSTART.md`.

---

## 1. Node Roles

Every node runs the same `tenzro-node` binary but can be configured for one or
more of the following roles via `--role` or `config.toml`:

| Role            | Purpose                                                   | Stake required |
|-----------------|-----------------------------------------------------------|----------------|
| `validator`     | Participate in HotStuff-2 consensus, finalize blocks      | Yes            |
| `model-provider`| Serve AI inference via RPC/MCP                            | Optional       |
| `tee-provider`  | Attest confidential compute (TDX / SEV-SNP / Nitro / NVIDIA) | Optional     |
| `light-client`  | Query RPC, gossip only (no consensus participation)       | No             |

A single node may combine roles (e.g. `validator,model-provider`). Each role
contributes different gossipsub topic subscriptions and RPC handlers.

---

## 2. System Requirements

### Minimum (testnet / light-client)

- 4 vCPU, 8 GB RAM, 100 GB SSD
- Ubuntu 22.04 LTS or macOS 14+
- Static public IPv4 address (validators only)
- TCP ports open: 9000 (libp2p), 8545 (JSON-RPC), 8080 (Web API), 3001 (MCP), 3002 (A2A)

### Recommended (mainnet validator)

- 8 vCPU, 32 GB RAM, 1 TB NVMe SSD (enough for RocksDB + snapshots)
- Dual-attached NIC with 1 Gbps minimum
- Hardware security module or KMS for validator key (`TENZRO_VALIDATOR_KEY`)
- Separate disk for WAL (`--wal-dir`) and state (`--data-dir`)
- Dedicated host (avoid containerized consensus in production — disk fsync
  semantics matter)

### Optional — for TEE providers

- Intel SGX/TDX-capable CPU with BIOS TDX enabled, or
- AMD EPYC with SEV-SNP firmware, or
- AWS Nitro instance (any `*.metal` or `*n.xlarge`+), or
- NVIDIA H100/H200/B200 with Confidential Computing enabled

Set `TENZRO_SIMULATE_TDX=1` / `TENZRO_SIMULATE_SEV_SNP=1` for CI only — never
in production.

---

## 3. Installation

### From source

```bash
git clone https://github.com/tenzro/tenzro-network.git
cd tenzro-network
cargo build --release -p tenzro-node
sudo install -m0755 target/release/tenzro-node /usr/local/bin/
```

### Deterministic image

```bash
docker pull ghcr.io/tenzro/tenzro-node:<version>
```

### systemd (Linux)

The binary ships with `crates/tenzro-node/tenzro-node.service`. Install:

```bash
sudo cp crates/tenzro-node/tenzro-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tenzro-node
```

---

## 4. Configuration

Precedence: CLI args > environment variables > TOML file > defaults.

### Minimal `config.toml`

```toml
role = "validator"
data_dir = "/var/lib/tenzro"

[network]
listen_addr = "/ip4/0.0.0.0/tcp/9000"
boot_nodes = [
  "/dns4/boot0.tenzro.network/tcp/9000/p2p/12D3KooW...",
]

[rpc]
addr = "0.0.0.0:8545"
max_connections = 512

[web]
addr = "0.0.0.0:8080"

[mcp]
addr = "0.0.0.0:3001"

[a2a]
addr = "0.0.0.0:3002"

[consensus]
block_time_ms = 2000
view_timeout_ms = 10000

[storage]
cache_size_mb = 1024
snapshot_retention = 100

[bridge]
enabled = false

# Enable per-protocol bridge signers. Private keys MUST come from environment
# variables in production — never inline in config.
#
# [bridge.layerzero]
# enabled = true
# chain_id = 30101
# rpc_url  = "https://mainnet.infura.io/v3/YOUR_KEY"
# private_key_env = "TENZRO_LZ_SIGNER_KEY"
#
# [bridge.ccip]
# enabled = true
# chain_id = 1
# rpc_url  = "https://mainnet.infura.io/v3/YOUR_KEY"
# private_key_env = "TENZRO_CCIP_SIGNER_KEY"
#
# [bridge.debridge]
# enabled = true
# chain_id = 1
# rpc_url  = "https://mainnet.infura.io/v3/YOUR_KEY"
# private_key_env = "TENZRO_DEBRIDGE_SIGNER_KEY"
```

### Environment variables

| Variable                        | Description                             |
|---------------------------------|-----------------------------------------|
| `RUST_LOG`                      | tracing filter (e.g. `info,tenzro_consensus=debug`) |
| `TENZRO_VALIDATOR_KEY`          | Hex-encoded Ed25519 validator key       |
| `TENZRO_LZ_SIGNER_KEY`          | EVM private key for LayerZero sends     |
| `TENZRO_CCIP_SIGNER_KEY`        | EVM private key for CCIP sends          |
| `TENZRO_DEBRIDGE_SIGNER_KEY`    | EVM private key for deBridge orders     |
| `TENZRO_SIMULATE_TDX`           | Simulate TDX attestation (dev only)     |
| `TENZRO_SIMULATE_SEV_SNP`       | Simulate SEV-SNP attestation (dev only) |

**Secret hygiene**: private keys should live in systemd credentials, AWS
Secrets Manager, GCP Secret Manager, or Vault — not in `.env` files on disk.

---

## 5. Startup

```bash
tenzro-node \
  --config /etc/tenzro/config.toml \
  --data-dir /var/lib/tenzro \
  --role validator \
  --listen-addr /ip4/0.0.0.0/tcp/9000
```

On startup the node will:

1. Load (or create) the keystore at `$data_dir/keystore`.
2. Open RocksDB at `$data_dir/db` and auto-repair corrupted WALs.
3. Hydrate AI infrastructure: model catalog, agent runtime, swarm manager,
   identity registry.
4. Bind RPC (8545), Web API (8080), MCP (3001), A2A (3002).
5. Connect to boot nodes and begin gossiping.
6. Start consensus loop (validators only).

Look for `"AI infrastructure hydrated: <N> models, <N> agents, <N> swarms"` in
the logs to confirm durable state restored correctly.

---

## 6. Observability

### Metrics

Prometheus metrics are exposed at `http://<web-addr>/metrics`. Key series:

- `tenzro_consensus_view` — current view number
- `tenzro_consensus_finalized_height` — last finalized block
- `tenzro_consensus_votes_total{phase}` — votes by phase
- `tenzro_consensus_equivocations_total` — detected equivocations (should be 0)
- `tenzro_network_peers` — connected peer count
- `tenzro_rpc_requests_total{method}` — RPC call counts
- `tenzro_bridge_circuit_breaker_state{endpoint}` — 0=closed, 1=open
- `tenzro_storage_write_latency_seconds{cf}` — RocksDB write histogram

Grafana dashboard JSON: `deploy/monitoring/grafana-dashboard.json`.
Alert rules: `deploy/monitoring/alerts.yml`.

### Logs

Structured JSON output (for `fluentd`/`loki`):

```bash
RUST_LOG=info tenzro-node --log-format json
```

Recommended minimum log levels for production:

```
tenzro_consensus=info
tenzro_node=info
tenzro_bridge=warn
tenzro_network=warn
libp2p=warn
```

### Health checks

- `GET /health` — returns 200 if RPC thread is alive.
- `GET /status` — returns node role, block height, peer count, uptime.

Kubernetes liveness probe example:
```yaml
livenessProbe:
  httpGet: { path: /health, port: 8080 }
  periodSeconds: 10
  failureThreshold: 3
```

---

## 7. Operations

### Backups

Snapshots are created automatically every 100 blocks (configurable via
`storage.snapshot_retention`). To take a manual snapshot:

```bash
tenzro --rpc-url http://localhost:8545 node snapshot \
  --out /backups/tenzro-$(date +%Y%m%d).tar.zst
```

Restore:
```bash
systemctl stop tenzro-node
tar -I zstd -xf /backups/tenzro-20260101.tar.zst -C /var/lib/tenzro
systemctl start tenzro-node
```

### Upgrades

Rolling upgrade procedure for validators:

1. Announce upgrade via governance (if consensus-breaking).
2. Drain one validator at a time:
   ```bash
   tenzro node drain  # stops producing proposals but keeps voting
   ```
3. `systemctl stop tenzro-node`
4. Replace binary.
5. `systemctl start tenzro-node` — watch logs for `consensus ready`.
6. Wait until the node is fully synced (height matches peers) before draining
   the next.

Never restart >1 validator at a time when cluster size is 4–7. With ≥10
validators, 2 parallel restarts are safe given BFT quorum (⌊(n-1)/3⌋).

### Adding a new validator

1. Generate keypair: `tenzro wallet create --type ed25519`
2. Acquire stake: `tenzro stake deposit --amount 100000`
3. Register: `tenzro provider register --role validator`
4. Wait for the next epoch boundary (see `/status.epoch.next_at`).
5. New validator starts receiving proposals automatically.

### Removing a validator

1. `tenzro stake unstake --amount <full-amount>` — initiates 7-day
   unbonding.
2. Wait for unbonding period; node continues validating until epoch boundary.
3. Shut down node after the epoch in which unbonding completes.

### Slashing

Automatic slashing triggers on equivocation (double-voting in the same view).
Penalty: 10% of stake. The offending validator is ejected from the active set
and their remaining stake enters a 7-day unbonding period.

To recover from unjust slashing: submit a governance proposal with evidence;
if passed, the slashed amount is restored from the treasury.

---

## 8. Bridge Operation

Bridges are **opt-in** — disabled by default. Enabling a bridge requires:

1. An EVM RPC endpoint (Infura / Alchemy / self-hosted).
2. A funded EVM wallet on the source chain (pays gas for `send` / `ccipSend`
   / `createOrder` transactions).
3. The private key provisioned via an environment variable.

When the bridge is enabled but no signer is configured, the adapter runs in
**quote-only mode**: it can return fee estimates but cannot submit transactions.

Circuit breakers protect all external HTTP calls. If an endpoint (LayerZero
Scan API, CCIP router RPC, deBridge API) records 5 consecutive failures, the
breaker trips for 30 seconds. Metrics:

```
tenzro_bridge_circuit_breaker_state{endpoint="dln-api"} 1
tenzro_bridge_circuit_breaker_failures{endpoint="dln-api"} 5
```

Manual recovery: restart the node (state is in-memory) or hit the admin RPC
`tenzro_resetCircuitBreaker` (requires admin token).

---

## 9. Troubleshooting

### `Storage error: IO error: Corruption`

RocksDB auto-repair runs on every open. If it fails:
```bash
systemctl stop tenzro-node
/usr/local/bin/ldb --db=/var/lib/tenzro/db repair
systemctl start tenzro-node
```
If still corrupt, restore from the most recent snapshot.

### `Insufficient votes for quorum`

- Check peer count: `curl -s localhost:8080/status | jq .peer_count`
- Ensure `listen_addr` is reachable externally (`nc -v <peer-ip> 9000`).
- Verify system clock drift ≤ 500ms (`chronyc tracking` / `timedatectl`).
- Check `tenzro_consensus_view` — if view keeps incrementing with no commits,
  consensus is stuck; investigate network partition.

### `View … timed out`

Normal during transient network issues. If it happens every view, either:
- Leader is offline — wait for the epoch to rotate leader.
- Network partition — check peer connectivity.
- Clock skew — verify NTP is working.

### `Circuit breaker TRIPPED for …`

The upstream HTTP service is down or rate-limiting. Check:
- Upstream status page.
- Outbound connectivity: `curl -v https://lz-scan.layerzero.network`.
- Rate limits: rotate API keys or add a proxy.

### High disk I/O from RocksDB

- Increase `storage.cache_size_mb` (reduces compaction read amplification).
- Move `data_dir` to NVMe.
- Reduce `snapshot_retention` if disk pressure is from old snapshots.

### Node won't sync

- Check `tenzro_consensus_finalized_height` against a trusted peer.
- Verify boot nodes are reachable.
- Inspect gossip topics: `tenzro node gossip-stats`.
- Last resort: wipe `data_dir` and sync from genesis (or restore a snapshot).

---

## 10. Security Checklist

Before going live on mainnet:

- [ ] Validator key stored in HSM / KMS, never on disk plaintext.
- [ ] `config.toml` has mode 0600 and is owned by the `tenzro` user.
- [ ] RPC (8545) is firewalled — only reachable via authenticated proxy.
- [ ] Web API (8080) exposed behind TLS (Caddy / nginx).
- [ ] MCP (3001) and A2A (3002) authenticated via OAuth or API keys.
- [ ] `data_dir` on an encrypted filesystem (LUKS / GCP CMEK / AWS EBS KMS).
- [ ] System packages patched weekly.
- [ ] Prometheus / Grafana in a separate security zone.
- [ ] Bridge signer keys scoped to bridge-only addresses (not shared with
      validator or treasury wallets).
- [ ] Slashing alerting configured (`tenzro_consensus_equivocations_total > 0`).
- [ ] Runbook for key rotation, backup restore, and incident response.

---

## 11. Reference

- **QuickStart**: `crates/tenzro-node/QUICKSTART.md`
- **Architecture**: `crates/tenzro-node/ARCHITECTURE.md`
- **Kubernetes manifests**: `deploy/kubernetes/`
- **Terraform (GKE)**: `deploy/terraform/`
- **Monitoring**: `deploy/monitoring/`
- **Tokenomics**: `../TOKENOMICS.md`
- **Specification**: `../SPECIFICATION.md`
- **GitHub**: https://github.com/tenzro/tenzro-network
