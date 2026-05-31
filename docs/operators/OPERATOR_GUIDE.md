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
| `TENZRO_ADMIN_TOKEN`            | Operator admin secret. Gates `tenzro_createApiKey` / `tenzro_revokeApiKey` / `tenzro_listApiKeys` / `tenzro_resetCircuitBreaker` (and other admin RPCs) via `X-Tenzro-Admin-Token` header. **Unset = admin gate is fail-closed.** Required only on the public RPC node. |
| `CANTON_DEVNET`                 | Set to `true` on the public RPC node to enable the Canton devnet profile in `CantonConfig::from_env()`. Other validators leave unset. |
| `CANTON_DEVNET_CLIENT_SECRET`   | Auth0 client_secret used by `CantonTokenProvider` to mint `daml_ledger_api` JWTs against `https://canton.network.global`. Required when `CANTON_DEVNET=true`. |
| `TENZRO_LZ_SIGNER_KEY`          | EVM private key for LayerZero sends     |
| `TENZRO_CCIP_SIGNER_KEY`        | EVM private key for CCIP sends          |
| `TENZRO_DEBRIDGE_SIGNER_KEY`    | EVM private key for deBridge orders     |
| `TENZRO_SIMULATE_TDX`           | Simulate TDX attestation (dev only)     |
| `TENZRO_SIMULATE_SEV_SNP`       | Simulate SEV-SNP attestation (dev only) |

**Secret hygiene**: private keys, admin tokens, and Auth0 client secrets
should live in systemd credentials, AWS Secrets Manager, GCP Secret Manager,
or Vault — not in `.env` files on disk. The recommended pattern is a
boot-time fetcher (oneshot systemd unit) that pulls each secret into a
root-only `EnvironmentFile` consumed by `tenzro-node.service`. See
`deploy/terraform/gce_validators/cloud-init.yaml` for a Canton-on-GCE
worked example (`tenzro-fetch-canton-config.service` → `/etc/tenzro/tenzro-node.env`).

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
- `tenzro_peer_address_migrations_total` — count of peers whose remote multiaddr changed on a new `ConnectionEstablished` event. Rises on QUIC path migration, NAT rebinding, and any wifi→cellular interface switch. Note: rust-libp2p 0.56 does not surface a structured QUIC migration event, so this counter cannot distinguish path migration (same connection, new path) from reconnection (new connection on new address). The acceptance test for migration-without-redial is a hands-on procedure, not CI-automated — see §9 *QUIC migration acceptance test (hands-on)*.
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

### Canton bridge

The Canton bridge follows the same opt-in pattern but with one extra layer:
the Canton ledger API requires an Auth0-issued JWT bearer, and external
callers should not need Auth0 credentials. Tenzro fronts Canton with an
operator-issued API-key gate (`X-Tenzro-Api-Key` with the `canton` scope) so
the Auth0 client_secret stays server-side. To enable on your public RPC node:

1. Provision an Auth0 application with the `daml_ledger_api` scope on your
   ledger's audience (e.g. `https://canton.network.global` for the public
   devnet, or your own audience for self-hosted Canton).
2. Set `CANTON_DEVNET=true` + `CANTON_DEVNET_CLIENT_SECRET=<auth0-secret>`
   on the RPC node (`CantonConfig::from_env()` picks this profile up). For
   operator-run Canton, see `CantonConfig::from_env()` in
   `crates/tenzro-node/src/config.rs` for the OAuth2 and static-JWT profiles.
3. Set `TENZRO_ADMIN_TOKEN=<random-32-byte-secret>` on the RPC node. Without
   this, all admin RPCs (including API-key issuance) are fail-closed.
4. Restart the node so the new env is picked up.

Other validators in your fleet should **not** set any of these — they will
return `-32004` on `tenzro_*Canton*` calls (scope gate, no API key) and
`-32001` on admin RPCs (admin-token unset), which is the intended fail-closed
posture.

### API key issuance (admin)

Once `TENZRO_ADMIN_TOKEN` is set on the RPC node, you can issue scoped API
keys to external callers via three admin RPCs. All three require the
`X-Tenzro-Admin-Token` header on the request.

```bash
# Mint a Canton-scoped key for a developer
curl -s https://rpc.your-network -X POST \
  -H 'content-type: application/json' \
  -H "X-Tenzro-Admin-Token: $TENZRO_ADMIN_TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_createApiKey","params":{
        "label": "alice@example.com",
        "subject": "did:tenzro:human:alice",
        "scopes": ["canton"]
      }}'
# → { "key": "tnz_...",  ← shown once; hand to dev securely
#     "key_id": "30891a07da6f9f98", ← retain for audit/revoke
#     ... }

# List all issued keys (revoked + active)
curl -s https://rpc.your-network -X POST \
  -H 'content-type: application/json' \
  -H "X-Tenzro-Admin-Token: $TENZRO_ADMIN_TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_listApiKeys","params":[]}'

# Revoke a key by id
curl -s https://rpc.your-network -X POST \
  -H 'content-type: application/json' \
  -H "X-Tenzro-Admin-Token: $TENZRO_ADMIN_TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_revokeApiKey","params":{
        "key_id": "30891a07da6f9f98"
      }}'
```

The key (`tnz_...`) is shown only once at issuance — the node persists only
its SHA-256 hash in `CF_API_KEYS`. Callers send it on every Canton RPC call:

```bash
curl -s https://rpc.your-network -X POST \
  -H 'content-type: application/json' \
  -H 'X-Tenzro-Api-Key: tnz_...' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_listCantonDomains","params":[]}'
```

Available scopes: `canton`. Additional scopes (`inference`, `bridge`, etc.)
are enum extensions in `tenzro_node::api_key::ApiKeyScope` and will land as
those surfaces are gated.

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

## 11. Iroh data plane

Iroh is the QUIC-native content-addressed transport that serves bulk payloads
(model weights, outer gradients, sealed dataset shards, agent-memory archives).
It complements the libp2p control plane — small reliable broadcasts continue
to flow over gossipsub/Kademlia.

### Config

```toml
[iroh]
enable = true
# Optional: pin Pkarr relay for TDIP-anchored discovery.
# Default is the n0 relay, which is fine for local dev.
pkarr_relay_url = "https://relay.pkarr.org"
# Optional: 32-byte hex seed. Default derives EndpointId from the TDIP key,
# so the iroh EndpointId is byte-identical to your validator's Ed25519 key.
secret_key_seed = "<32-byte-hex>"
```

Or the CLI shorthand:

```bash
tenzro-node --role validator --iroh.enable
```

### What you get

- `IrohBlobsDaBackend` becomes the `DaBackend` for offloaded receipts
  (SettlementChannel, Inference, AgentMessage). InlineFallback remains the
  safe default for receipts with `default_mode() = Inline`.
- `IrohGradientStore` handles `OuterGradient` distribution for trainers.
- `IrohSealedShardStore` distributes Confidential-tier dataset shards.
- `IrohBlobFetcher` makes `HfArtifactDownloader` peer-first — HuggingFace Hub
  is the fallback, not the default.
- `MemoryManager::archive()` writes to iroh-blobs instead of inline storage.
- A2A traffic over the `tenzro/a2a` ALPN on the shared router.

### Operational notes

- One `IrohBackedResolver` per node — never instantiate two. The same endpoint
  is shared by every consumer above.
- The transport is hidden behind the `tenzro://` scheme. The string `iroh://`
  must not appear in operator runbooks, dashboards, or log queries.
- iroh-blobs verifies BLAKE3 end-to-end on every transfer — there is no extra
  hash-check work required at the application layer.

---

## 12. NAT traversal

Tenzro nodes form a mesh across home wifi, mobile tethers, residential ISPs,
and corporate NATs without any per-node external-address configuration. The
stack is Identify observed-address tally + AutoNAT v2 + Circuit-Relay v2 +
DCUtR.

### Listen addresses

By default `tenzro-node` binds **both** of:

- `/ip4/0.0.0.0/tcp/9000`
- `/ip4/0.0.0.0/udp/9000/quic-v1`

This is the universal transport set. QUIC's structural port-reuse gives
Identify `observed_addr` a stable listening UDP port for AutoNAT v2 dial-back
probes, which is what makes hole punching reliable.

To override:

```bash
tenzro-node --listen-addr /ip4/0.0.0.0/tcp/9000,/ip4/0.0.0.0/udp/9000/quic-v1
```

`--listen-addr` accepts a comma-separated list of full libp2p multiaddrs.

### Behaviour role split

- **Validators** with a confirmed public address run the *server* halves
  (`relay::Behaviour`, `autonat::v2::server::Behaviour`). They serve as relay
  hops and dial-back probes for the rest of the network.
- **Joiner-class roles** (LightClient, ModelProvider, TeeProvider) run the
  *client* halves (`relay::client::Behaviour`, `autonat::v2::client::Behaviour`,
  `dcutr::Behaviour`).

The defaults are role-aware: `enable_relay = true` for validators,
`enable_hole_punching = true` for every role.

### Cloud firewalls

This part is an operator runbook, not a protocol design issue. Open both ports
on every provider you use:

- **GCE**: VPC firewall rule allowing TCP/9000 and UDP/9000 from `0.0.0.0/0`.
- **EC2**: Security group with the same rules.
- **Azure**: NSG rules.
- **GKE**: NetworkPolicy if you use one; otherwise nothing extra.
- **COS (Container-Optimized OS, used on GCE and GKE)**: COS defaults to `DROP`
  for everything except `lo`, `icmp`, `tcp:22`, and ESTABLISHED. Append an
  `ACCEPT` rule for TCP/9000 and UDP/9000 via cloud-init `runcmd:` — see
  `deploy/terraform/gce_validators/cloud-init.yaml` for the canonical example
  used by the Tenzro testnet fleet.

### Bootstrap addresses

Advertise bootstrap peers in **both** forms so dialers can pick whichever
their NAT permits:

```
/ip4/<ip>/tcp/9000/p2p/<peer-id>
/ip4/<ip>/udp/9000/quic-v1/p2p/<peer-id>
```

Pass to joiners via `--boot-nodes a,b,c,d`.

---

## 13. Intel Tiber Trust Authority

Tiber is the hosted attestation alternative to native Intel PCS verification.
The node fetches a nonce, posts a TDX quote, and receives a signed EAT (Entity
Attestation Token) as a JWT. Use this when you do not want to ship the PCS
certificate chain yourself or when you want a vendor-attested appraisal
alongside your own.

### Enabling

Build with the `intel-tiber` feature (implies `intel-tdx`):

```bash
cargo build --release --bin tenzro-node --features intel-tiber
```

### Round trip

```
GET  https://api.trustauthority.intel.com/appraisal/v2/nonce
POST https://api.trustauthority.intel.com/appraisal/v2/attest  { quote, nonce }
→ JWT (PS384 or RS256)
```

The node verifies the JWT against Tiber's JWKS. To defend against
open-redirect attacks on a passive verifier, `TiberJwksPin::AllowedHosts`
locks the `jku` header to a configurable allow-list. The default allow-list
contains only Intel-published hosts.

### Regional endpoints

Two regions are wired today via the `TIBER_API_URL_US` and `TIBER_API_URL_EU`
constants — pick the one that matches your data-residency posture.

### Claims surfaced

The verified `TiberClaims` projected into `AttestationResult` include
`tdx_mrtd`, `tdx_rtmr0..3`, `tdx_mrsignerseam`, `tdx_seamsvn`,
`attester_tcb_status`, `dbgstat`, and `attester_advisory_ids`. The result is
marked `valid = true` only when `attester_tcb_status == "OK"` and
`dbgstat == "disabled"`. `details["verification_method"] = "intel_tiber"`
lets downstream consumers distinguish a Tiber appraisal from native PCS.

---

## 14. Streaming inference (resume, backpressure, HTTP/3 ingress)

Token-streamed inference responses (SSE) survive transport drops via cursor-based resume on the gateway. Clients reconnect using the standard HTML5 EventSource `Last-Event-ID` header; the node replays any chunks that were emitted but not yet acknowledged, then continues live emission.

### Resume

The OpenAI-compatible `POST /v1/chat/completions` and `POST /api/paid/chat/completions` handlers tag every emitted SSE event with an `id:` line of the form `<completion_id>:<seq>`:

- `completion_id` is the same `chatcmpl-<uuid>` value returned in the first chunk. For network-model proxy paths it is locally generated as `chatcmpl-proxy-<uuid>` (the upstream provider's id is opaque on the wire, so we synthesize our own).
- `seq` is a monotonically-increasing `u64` starting at `0`.

On reconnect, the client sends `Last-Event-ID: <completion_id>:<last_seen_seq>`. The gateway replays every chunk with `seq > last_seen_seq` and then either continues live emission (if the producer is still active) or closes with `data: [DONE]\n\n` (if the original stream already finished).

If the cursor has been garbage-collected (see TTL below) the gateway responds as if no resume were requested — the client must reissue the prompt.

### Cursor lifecycle

Cursors live in process memory under `TenzroNode::stream_cursors` (`crate::streaming::StreamCursorStore`, a clone-cheap `Arc<DashMap>`):

- Per-stream ring cap: `MAX_BUFFERED_CHUNKS = 4096`. Beyond this, the oldest chunks are evicted from the head of the ring — a late reconnect receives a partial replay. Sized to cover a 4 KB completion at ~4-chars/token.
- TTL after `finish()`: `DEFAULT_TTL = 5min`. Covers mobile flap + retry-with-backoff.
- In-flight idle timeout: `IN_FLIGHT_IDLE_TIMEOUT = 10min`. Protects against stuck generators when the client never reconnects.
- A background GC task ticks every 30s (spawned during `start()` step 16) and evicts past-deadline entries.

State is in-memory and not persisted across node restarts — this is intentional: clients should always be prepared to fall back to a full reissue.

### Backpressure observability

The cursor module exposes `streaming::observe_and_send` for SSE producers that want to log when the consumer channel is the bottleneck. It uses `tokio::sync::mpsc::Sender::reserve()` so the value is never consumed by a timed-out future; if the soft deadline elapses before a permit is available the send still completes but a `BackpressureSignal::Slow { elapsed_ms }` is returned. Wire this into per-request logs to distinguish "model is slow" from "client TCP receive window is closed".

### HTTP/3 ingress

The fleet's edge already advertises HTTP/3 via the `alt-svc: h3=":443"; ma=2592000` header through the validator-0 Caddy reverse proxy (PQ-hybrid X25519MLKEM768 TLS). Clients that prefer h3 will use it transparently; clients that don't will fall back to h2 over TLS 1.3. No node-side configuration is required for the testnet edge.

In-process HTTP/3 binding on the node itself is not enabled — the axum/hyper stack speaks HTTP/1.1 and h2 only. Operators running a node directly exposed to the internet (rare; usually behind Caddy or another proxy) can add h3 at the proxy. A standalone h3 listener inside `tenzro-node` is deferred — there is no production demand path that bypasses the Caddy edge.

### Verifying resume end-to-end

```bash
# Open a stream, capture id and seq from the first chunk(s).
curl -N -sS https://rpc.tenzro.network/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"<model_id>","stream":true,"messages":[{"role":"user","content":"hi"}]}' \
  | head -20

# Kill the connection. Reissue with Last-Event-ID, observe replay+resume.
curl -N -sS https://rpc.tenzro.network/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'Last-Event-ID: chatcmpl-<uuid>:3' \
  -d '{"model":"<model_id>","stream":true,"messages":[{"role":"user","content":"hi"}]}'
```

### QUIC migration acceptance test (hands-on)

**Known limitation.** rust-libp2p 0.56 does not surface a structured per-connection QUIC migration event. The `tenzro_peer_address_migrations_total` counter (see §6) is the only available signal, and it cannot distinguish path migration (same QUIC connection, new remote address) from reconnection (new connection on new address). The acceptance test below is a manual interface-switch procedure rather than a CI check — re-evaluate once rust-libp2p ships a structured event upstream.

**Procedure.** Two hosts: A = the node under test (any role, public reachable), B = a mobile/laptop validator on wifi.

1. From host B, run a tenzro-node configured to dial A and confirm `peer_count >= 1` and gossipsub mesh participation.
2. On host A, capture baseline:
   ```bash
   curl -s http://127.0.0.1:8080/metrics | grep -E 'tenzro_peer_address_migrations_total|tenzro_network_peers'
   ```
3. On host B, switch network interface (wifi → cellular tether, or wifi → different SSID with a different external IP). Do **not** restart the node.
4. Wait ~30s (libp2p ping cadence is 15s — give two cycles for the new path to be observed).
5. On host A, re-capture metrics. **Pass conditions:**
   - `tenzro_peer_address_migrations_total` incremented by 1 for the B peer.
   - `tenzro_network_peers` unchanged (B was not disconnected).
   - No `SwarmEvent::ConnectionClosed{peer=<B>}` in A's logs between baseline and re-capture.
   - B's gossipsub mesh score for A (visible via the node's debug RPC) did not reset to zero.
6. From host B, immediately publish a transaction or send a gossipsub message and confirm A receives it without a re-dial round-trip.

**If the test fails** (counter incremented but peer count dropped, or `ConnectionClosed` observed), QUIC migration is not transparently transferring on this network path — the connection re-established rather than migrated. This is acceptable for current production but defeats the purpose of QUIC vs TCP for mobile clients. File the incident with packet captures from both ends.

---

## 15. Reference

- **QuickStart**: `crates/tenzro-node/QUICKSTART.md`
- **Architecture**: `crates/tenzro-node/ARCHITECTURE.md`
- **Reference builds**: `docs/operators/REFERENCE_BUILDS.md`
- **Terraform (GCE — canonical testnet fleet)**: `deploy/terraform/gce_validators/`
- **Kubernetes manifests (legacy, not used by current testnet)**: `deploy/kubernetes/`
- **Monitoring**: `deploy/monitoring/`
- **GitHub**: https://github.com/tenzro/tenzro-network
