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
`--roles validator`, pulled as a container image, persisting state to a local
disk, and exposing one network port to peers.

A **fleet** is N validators (typically 4 or more, often 10+) running this
binary, sharing a genesis file, and bootstrapping off one well-known peer.

## Sizing & topology

| Dimension | Recommendation | Notes |
|---|---|---|
| **Number of validators** | 4 minimum for BFT (tolerates 1 fault); 10+ for production | Quorum is `n - f` of `n` seats, `f = (n - 1) / 3` |
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
| iroh | UDP | ingress + egress | iroh endpoint: gossip topics (`tenzro/gossip`: blocks, certificates, transactions, ...), consensus channels (`tenzro/consensus`), block sync (`tenzro/block-sync`), state sync |
| 8545 | TCP | egress only, or ingress on the public RPC node | JSON-RPC |
| 8080 | TCP | egress only, or ingress on the public RPC node | Web verification API |
| 3001 | TCP | egress only, or ingress on the public RPC node | MCP server |
| 3002 | TCP | egress only, or ingress on the public RPC node | A2A protocol server |

**Typically one validator** in the fleet exposes the public RPC/MCP/A2A
surfaces (behind a TLS-terminating reverse proxy like Caddy). The other N-1
validators only need the iroh endpoint's UDP port reachable.

A node that cannot be reached directly is still reachable through the relays
named in its signed endpoint record.

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
run the matching release image (`cpu`, `cuda` and `vulkan` are published)
or build a backend variant yourself. Each variant compiles `tenzro-node`
with the corresponding llama.cpp/ggml backend feature. There is no
published ROCm image: `Dockerfile.rocm` is built from source, as below.

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

Backends without a Dockerfile variant (Intel SYCL / OpenVINO, OpenCL, Moore
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
/var/lib/tenzro/                      # persistent state (chain DB); no key files
  ├── data/                           # chain DB (RocksDB)
  └── config.toml                     # node config (optional, CLI flags suffice)
/etc/systemd/system/
  └── tenzro-node.service             # runs tenzro-run via docker
```

The validator's keys are not files. They are created inside the machine's TPM 2.0
(or, on macOS, the Secure Enclave) by `tenzro-node init` and never leave it; the
node signs through the chip. There is nothing to copy, back up or fetch at boot.

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
  --device /dev/tpmrm0 \
  -e RUST_LOG=info \
  "$IMAGE" \
  tenzro-node \
    --roles validator,rpc \
    --external-rpc-addr "$SEED_URL" \
    --data-dir /var/lib/tenzro/data \
    --config /var/lib/tenzro/config.toml \
    --boot-nodes "$BOOT_IDENTITY"
```

A founding validator is also an SDK seed: it bonds `rpc` in the genesis
`[[role_stakes]]` and publishes `$SEED_URL`, its own `https://rpcN.tenzro.com`
reverse proxy in front of the loopback RPC listener (`--external-rpc-addr`
refuses anything that is not public https). A validator that is not a seed
runs `--roles validator` without `--external-rpc-addr`.

`$BOOT_IDENTITY` is the bootstrap validator's machine identity with its relay,
`did:tenzro:machine:<id>@<relay url>`. Validator-0 (the bootstrap) runs the
same script with `--relay-listen <addr> --relay-url <url>` in place of
`--boot-nodes`.

### systemd units

`tenzro-node.service`:

```ini
[Unit]
Description=Tenzro validator node
After=network-online.target
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

## Keys and genesis

A validator's consensus key is a composite ML-DSA-65 + P-256 key. The P-256
leg is a key in the machine's TPM 2.0 or Secure Enclave; the ML-DSA-65 leg is
derived from that hardware on demand, for each use, and wiped afterwards.
Neither is ever generated in software, written to disk, placed in a secret
store, or passed through an environment variable, and a machine without such
hardware runs as a follower.

Each founding validator prints its genesis entry on its own machine:

```bash
tenzro-node init --data-dir /var/lib/tenzro
tenzro-node validator-entry --data-dir /var/lib/tenzro --stake <STAKE>
```

The entry holds `address`, `ml_dsa_public_key`, `p256_public_key`,
`node_key`, `proof_of_possession`, `node_key_proof`, `vrf_key`,
`vrf_key_proof` and `stake`; the first proof is signed by the hardware
consensus key, the second by the node key derived from the same hardware, and
the third is a VRF proof by the VRF key, which the same hardware derives
apart from the node key. No network address is in the entry: each
boot, a validator announces its endpoint signed by its consensus key.
Collect every entry into one `genesis.toml` (schema version 1).

A founding node that serves as an SDK seed also bonds the `rpc` role, so it
appears in the on-chain operator list like any other operator. Add one
`[[role_stakes]]` per bonded role, from the node account its entry names;
leave `stake` out to bond the amount the governed `stake.*` parameters
require at genesis:

```toml
[[role_stakes]]
address = "<the node account from the entry>"
role = "rpc"
endpoint = "https://<this node's public RPC host>"
```

## Genesis file

Every validator must load the **same** `genesis.toml`. Mount it at the path
your config or CLI expects, typically `/var/lib/tenzro/genesis.toml`. A node
refuses to start on a genesis whose entries' proofs do not verify, or that
names no validators.

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

## Optional: admin gate on the RPC node

Who may use the node at all is its access
policy (`access.toml`, see [`docs/ACCESS.md`](../docs/ACCESS.md)); set it with
`tenzro-node access`. It does not gate the marketplace registry: publishing an agent, skill, workflow, or MCP server is
permissionless, priced by the provider in TNZO or offered free, and needs no
operator approval.

**Validators 1..N-1 must NOT carry an admin token** — they should
return `-32001` on admin RPCs (admin-token unset), which is the intended
fail-closed posture for non-RPC nodes.

The recommended secret-fetch pattern is a boot-time oneshot systemd unit
that writes a root-only `EnvironmentFile` consumed by `tenzro-node.service`.
Operators provision this through their own infrastructure tooling; the unit
only needs read access to wherever the operator stores its secrets.

## Next steps

- Read [`crates/tenzro-node/QUICKSTART.md`](../crates/tenzro-node/QUICKSTART.md)
  if you want to run a single node locally first before standing up a fleet.
