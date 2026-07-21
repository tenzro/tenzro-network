# Running a Tenzro Validator Fleet

This is the IaC-agnostic operator guide for running a Tenzro Network validator
fleet on any cloud (GCE, EC2, Azure, Hetzner, bare metal, mixed). The
canonical per-VM software install is captured here; the infrastructure layer
(Terraform / Pulumi / Ansible / hand-rolled) is yours to write.

For the per-node config reference, observability, upgrade procedures, and
incident response, see [`crates/tenzro-node/QUICKSTART.md`](../crates/tenzro-node/QUICKSTART.md)
and the node's `--help` output.

## What you're deploying

A Tenzro validator is a single `tenzro-node` binary running with
`--role validator`, pulled as a container image, persisting state to a local
disk, and exposing one network port to peers.

A **fleet** is N validators (typically 4 or more, often 10+) running this
binary, sharing a genesis file, and bootstrapping off one well-known peer.

## Sizing & topology

| Dimension | Recommendation | Notes |
|---|---|---|
| **Number of validators** | 4 minimum for BFT (tolerates 1 fault); 10+ for production | HotStuff-2 needs `3f+1` honest |
| **Zones** | Spread across ≥3 zones | Avoid single-zone correlated failure |
| **Regions** | Multi-region recommended for public testnets | Plan ~$0.05–0.12/GB cross-region egress |
| **VM size** | 4 vCPU / 16 GB RAM / 100 GB SSD per validator | e.g. GCE `n2-standard-4`, EC2 `m5.xlarge` |
| **OS** | Container-Optimized OS (GCE), Bottlerocket (AWS), or any modern Linux with systemd + docker | The container is the abstraction; host OS choice is yours |

A 10-VM fleet across 3 continents (4 NA + 3 EU + 3 APAC) gives real
geographic diversity while keeping a 7-of-10 quorum reachable from any
continent.

## Network requirements

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 9000 | TCP | ingress + egress | libp2p P2P (gossipsub + HotStuff-2) |
| 9000 | UDP | ingress + egress | libp2p QUIC (same port, structural reuse) |
| 8545 | TCP | egress only, or ingress on the public RPC node | JSON-RPC |
| 8080 | TCP | egress only, or ingress on the public RPC node | Web verification API |
| 3001 | TCP | egress only, or ingress on the public RPC node | MCP server |
| 3002 | TCP | egress only, or ingress on the public RPC node | A2A protocol server |

**Typically one validator** in the fleet exposes the public RPC/MCP/A2A
surfaces (behind a TLS-terminating reverse proxy like Caddy). The other N-1
validators only need port 9000 open.

**libp2p needs both TCP and UDP/QUIC on 9000.** Validators dial whichever
their environment permits. Some NATs/firewalls allow one but not the other —
opening both gives the highest reachability.

**Cross-region note:** the libp2p `connection_idle_timeout` is set to 600s
to survive cloud NAT conntrack eviction (commonly 5–10 min). On GCE COS,
also set host sysctl TCP keepalives:
```
net.ipv4.tcp_keepalive_time=120
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=5
```

## Container image

Build the `tenzro-node` image from the repo `Dockerfile`:

```bash
# From repo root
TAG=$(date +%Y%m%d-%H%M%S)
docker build -t <your-registry>/tenzro-node:$TAG .
docker push <your-registry>/tenzro-node:$TAG
```

The image is multi-stage (Rust 1.85 builder → debian-slim runtime), produces
a single `tenzro-node` binary, and runs as non-root. Build time on a fast
build host is ~15–25 min.

### GPU / accelerator variants

The base `Dockerfile` is CPU-only. To serve inference on an accelerator,
build the matching backend variant instead. Each variant compiles
`tenzro-node` with the corresponding llama.cpp/ggml backend feature.

| Backend | Dockerfile | `docker run` flags |
|---|---|---|
| NVIDIA CUDA | `Dockerfile.cuda` | `--gpus all` |
| AMD ROCm / HIP | `Dockerfile.rocm` | `--device /dev/kfd --device /dev/dri --group-add video` |
| Vulkan (NVIDIA / AMD / Intel Arc / Mali) | `Dockerfile.vulkan` | `--device /dev/dri -v /usr/share/vulkan/icd.d:/usr/share/vulkan/icd.d:ro` |

```bash
TAG=$(date +%Y%m%d-%H%M%S)
docker build -f Dockerfile.rocm -t <your-registry>/tenzro-node:$TAG-rocm .
docker push <your-registry>/tenzro-node:$TAG-rocm
```

Backends without a prebuilt image (Intel SYCL / OpenVINO, OpenCL, Moore
Threads MUSA, Huawei CANN, WebGPU, IBM zDNN, BLAS) build from the base
`Dockerfile` template with the vendor toolchain layered into the builder
stage and `--features tenzro-node/<backend>` added to the `cargo build`
line. See `docs/AI.md` §2.7 for the full backend/feature matrix and the
per-backend build recipes.

**Pin by digest in production.** Tags can be moved; digests can't:
```bash
docker inspect <your-registry>/tenzro-node:$TAG --format '{{.RepoDigests}}'
# Use the @sha256:... form in your per-VM run script.
```

## Per-VM software layout

On each validator VM:

```
/var/lib/tenzro-bin/tenzro-run        # operator-owned wrapper script
/var/lib/tenzro/                      # persistent state (chain DB, keys)
  ├── keys/
  │   ├── consensus.seed              # mode 0600, tenzro:tenzro
  │   ├── pq.seed                     # mode 0600, tenzro:tenzro
  │   └── p2p.seed                    # mode 0600, tenzro:tenzro
  ├── data/                           # chain DB (RocksDB)
  └── config.toml                     # node config (optional, CLI flags suffice)
/etc/systemd/system/
  ├── tenzro-fetch-keys.service       # pulls keys from your KMS on boot
  └── tenzro-node.service             # runs tenzro-run via docker
```

### `tenzro-run` wrapper

A shell script that pulls the pinned image and runs the container. Sketch:

```bash
#!/bin/bash
set -euo pipefail

IMAGE="<your-registry>/tenzro-node@sha256:<pinned-digest>"
NODE_INDEX="<0..N-1>"
BOOT_PEER_ID="<peer id of validator-0>"
BOOT_PEER_IP="<public IP or DNS of validator-0>"

docker pull "$IMAGE"

# Always remove any prior container so --rm + restart cycles cleanly
docker rm -f tenzro-node 2>/dev/null || true

exec docker run --rm \
  --name tenzro-node \
  --network host \
  -v /var/lib/tenzro:/var/lib/tenzro \
  -e RUST_LOG=info \
  -e TENZRO_SIMULATE_TDX=0 \
  -e TENZRO_SIMULATE_SEV=0 \
  -e TENZRO_SIMULATE_NSM=0 \
  "$IMAGE" \
  tenzro-node \
    --role validator \
    --data-dir /var/lib/tenzro/data \
    --config /var/lib/tenzro/config.toml \
    --boot-nodes "/ip4/$BOOT_PEER_IP/tcp/9000/p2p/$BOOT_PEER_ID,/ip4/$BOOT_PEER_IP/udp/9000/quic-v1/p2p/$BOOT_PEER_ID"
```

Validator-0 (the bootstrap) runs the same script but with no
`--boot-nodes` flag.

### systemd units

`tenzro-fetch-keys.service` — runs once on boot, pulls the three per-VM
secrets from your KMS into `/var/lib/tenzro/keys/`. Sketch (GCE Secret
Manager example shown; adapt to AWS Secrets Manager, Vault, etc.):

```ini
[Unit]
Description=Fetch tenzro validator keys
Before=tenzro-node.service
RequiresMountsFor=/var/lib/tenzro

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tenzro-fetch-keys
RemainAfterExit=yes
```

`tenzro-node.service`:

```ini
[Unit]
Description=Tenzro validator node
After=network-online.target tenzro-fetch-keys.service
Requires=tenzro-fetch-keys.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/var/lib/tenzro-bin/tenzro-run
Restart=always
RestartSec=10s
TimeoutStopSec=60
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
```

`TimeoutStopSec=60` + `KillSignal=SIGTERM` align with the node's
`graceful_exit()` handler — it needs ~30s to flush state and unstake leader
roles before being killed.

## Key generation

Run [`tools/genkeys/`](../tools/genkeys/README.md) once, on a trusted offline
laptop, before any infrastructure is provisioned:

```bash
cargo run --release -p tenzro-genkeys -- \
    --out ~/tenzro-keys \
    --count <N> \
    --chain-id <YOUR_CHAIN_ID> \
    --stake-per-validator <STAKE>
```

This produces:
- `validator-{0..N-1}/{consensus,pq,p2p,bls}.seed` — deliver to each
  validator's secret storage, one per VM
- `genesis.toml` — commit to your repo, embed in all N VMs
- `PEER_IDS.txt` — copy validator-0's peer ID for the boot-nodes flag

**Never let `*.seed` files touch CI, shared disks, or any unencrypted
backup.** See the genkeys README for the secure-wipe procedure after upload.

## Genesis file

Every validator must load the **same** `genesis.toml` (schema v3 —
three pubkeys per validator: Ed25519 + ML-DSA-65 + BLS12-381). Mount it at
the path your config or CLI expects, typically `/var/lib/tenzro/genesis.toml`.

## Rolling out a new image

Canary-then-fleet, one VM at a time:

1. Build the new image, get its `@sha256:...` digest.
2. **Canary on one non-RPC validator.** SSH in, update the pinned digest
   in `/var/lib/tenzro-bin/tenzro-run`, then `docker stop tenzro-node`
   (systemd will respawn it with the new digest).
3. **Verify on a neighbor**: peer count should remain at N-1, block height
   should advance. Container `healthy` alone is not enough — consensus
   liveness is the real signal.
4. Sweep the remaining validators one at a time. Wait ~30s between rolls
   so the cluster recovers between each.

**Do not** use `systemctl restart tenzro-node` for the rollout — for
`docker run --rm` units, systemd's Main PID is the docker CLI, not the
container, so `restart` is a no-op for the container itself. `docker stop`
exits the docker CLI → systemd respawns it → wrapper pulls the new digest.

## Observability

The node exposes:

| Endpoint | Purpose |
|---|---|
| `http://127.0.0.1:8080/verify/health` | liveness probe (200 = process alive) |
| `http://127.0.0.1:8080/verify/ready` | readiness probe (200 = caught up to head, in consensus) |
| `http://127.0.0.1:8080/status` | block height, peer count, role, uptime |
| `http://127.0.0.1:9090/metrics` | Prometheus metrics |

Sanity-check the consensus mesh from any neighbor:

```bash
curl -s -X POST http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"net_peerCount","params":[]}'
# expect "0x<N-1>"

curl -s -X POST http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'
# expect a hex height that increases over time
```

## Public-facing reverse proxy (one node)

The validator that exposes the public RPC surface typically fronts it with
a TLS-terminating reverse proxy (Caddy, nginx, traefik). Subdomains map to
local ports:

| Hostname | → | Local port |
|---|---|---|
| `rpc.your-network` | → | 8545 (JSON-RPC) |
| `api.your-network` | → | 8080 (Web verification API) |
| `mcp.your-network` | → | 3001 (MCP server) |
| `a2a.your-network` | → | 3002 (A2A protocol) |

A Caddyfile for this is ~10 lines per subdomain (reverse_proxy + automatic
Let's Encrypt). The Caddy container runs alongside the validator container.

## Optional: Canton bridge + admin gate on the RPC node

The Canton bridge is opt-in and lives on the public RPC node only. Two extra
env vars enable it:

| Variable | Purpose |
|---|---|
| `CANTON_DEVNET=true` + `CANTON_DEVNET_CLIENT_SECRET=<auth0-secret>` | Enables `CantonConfig::from_env()` devnet profile. Tenzro's `CantonTokenProvider` mints `daml_ledger_api` JWTs against `https://canton.network.global` using this secret. For self-hosted Canton, see the OAuth2 / static-JWT profiles in `crates/tenzro-node/src/config.rs`. |
| `TENZRO_ADMIN_TOKEN=<random-32-byte-secret>` | Gates admin RPCs (`tenzro_createApiKey`, `tenzro_revokeApiKey`, `tenzro_listApiKeys`, `tenzro_resetCircuitBreaker`). Unset = fail-closed. |

External callers reach Canton through Tenzro's API-key gate
(`X-Tenzro-Api-Key` header with the `canton` scope). The operator mints
keys via `tenzro_createApiKey` (admin-token-gated) and hands them to devs
out-of-band — no self-service portal.

**Validators 1..N-1 must NOT carry any of these env vars** — they should
return `-32004` on `tenzro_*Canton*` calls (scope gate) and `-32001` on
admin RPCs (admin-token unset), which is the intended fail-closed posture
for non-RPC nodes.

The recommended secret-fetch pattern is a boot-time oneshot systemd unit
that writes a root-only `EnvironmentFile` consumed by `tenzro-node.service`.
Operators provision this through their own infrastructure tooling; the unit
only needs read access to wherever the operator stores its secrets.

## Next steps

- Read [`tools/genkeys/README.md`](../tools/genkeys/README.md) for the
  offline key generation + secrets-upload procedure.
- Read [`crates/tenzro-node/QUICKSTART.md`](../crates/tenzro-node/QUICKSTART.md)
  if you want to run a single node locally first before standing up a fleet.
