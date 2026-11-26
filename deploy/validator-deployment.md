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
binary, sharing a genesis file, and each naming the other validators as its
boot identities.

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
BOOT_IDENTITIES="<every other validator: did:tenzro:machine:<id>@<relay url>, comma separated>"

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
    --boot-nodes "$BOOT_IDENTITIES"
```

A founding validator is also an SDK seed: it bonds `rpc` in the genesis
`[[role_stakes]]` and publishes `$SEED_URL`, its own `https://rpcN.tenzro.com`
reverse proxy in front of the loopback RPC listener (`--external-rpc-addr`
refuses anything that is not public https). A validator that is not a seed
runs `--roles validator` without `--external-rpc-addr`.

`$BOOT_IDENTITIES` names every other validator of the fleet by its machine
identity with its relay, `did:tenzro:machine:<id>@<relay url>`. On a new chain
no identity is registered yet, so a validator started without the others on
its list stays at round 0 with no peers; the genesis validator entries alone
do not bring the fleet up.

With the `[onboarding]` mode `enforce` (the shipped default) a validator is
isolated: the connections it makes (its dials) go only to the machines on its
boot list, the validators' machines and any peer named with
`--state-sync-from`, and other nodes it learns of through
discovery are never dialled. Inbound connections from other peers are still
admitted when they pass the identity gate, so nodes can sync blocks and state
from the validator. Gossip is the exception: the validator keeps gossip
neighbours only among its boot list and the validators, whichever side dialled.

Every validator's `--boot-nodes` list therefore names the other validators and
the network's relay and RPC entry points, plus any other machine it must reach outside the validator
set (a sentry, an RPC node of the same operator). A machine missing from the
list is neither dialled nor kept as a gossip neighbour.

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

### A validator-only machine forbids builds

A release build or a test run takes the processors and memory the node needs
to keep up with consensus. On a machine that only validates, create the marker
file:

```bash
sudo install -D /dev/null /etc/tenzro/no-builds
```

`scripts/supply-chain/check-build-host.sh` then refuses the release build and
every test binary while the node service is active. Without the marker the
same check prints one warning line and lets the build run.

## Keys and genesis

A validator's consensus key is a composite ML-DSA-65 + P-256 key. The P-256
leg is a key in the machine's TPM 2.0 or Secure Enclave; the ML-DSA-65 leg is
derived from that hardware on demand, for each use, and wiped afterwards.
Neither is ever generated in software, written to disk, placed in a secret
store, or passed through an environment variable. A Linux or macOS machine
without such hardware can hold the consensus key in another machine's TPM
through a key holder (`tenzro-node tpm key-holder`, `--tpm-key-holder`), with
the limits in
[docs/NODE.md](../docs/NODE.md#raspberry-pi-and-other-edge-devices) (every
signature is a round trip to the provider, a grant lasts at most the
provider's `max_grant_hours`, and the ML-DSA-87 / P-384 scheme is not available
this way); otherwise it runs as a follower.
Such a machine cannot be a founding validator: `validator-entry` reads only
the machine's own TPM or Secure Enclave. It joins after genesis with
`tenzro validator register --tpm-key-holder`.

A node that joins after genesis, validator or not, replays the chain from block
0 with the same `genesis.toml` before it takes part
([docs/operations/node-joining.md](../docs/operations/node-joining.md)); a
validator never joins by snapshot.

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

## After genesis

A new chain has no model catalog, no identity for any account genesis funds,
and no operator on a node that does not name one. Do these before the network
is called launched:

1. **Operators.** Each validator's node configuration names its operator,
   `operator_did = "did:tenzro:..."` at the top level. Unset, the machine's
   own DID administers the node and the node reports no operator.
2. **Identities for funded accounts.** An account with no registered identity
   cannot send: its first transaction is refused with "Sender ... is not
   admitted: no registered identity". On the machine that holds each funded
   account's key (the founders operations account, the catalog publisher and
   every other allocation account), run
   `tenzro identity register-account --key-namespace <namespace>`.
3. **Catalog publisher.** From the publisher's machine, bond the catalog role
   (`stake.catalog_tnzo`, 1,000 TNZO at genesis) and publish the seed
   entries:

   ```bash
   tenzro stake bond --role catalog --amount 1000 --key-namespace <publisher>
   tenzro catalog publish crates/tenzro-catalog/seed --key-label client/<publisher>
   ```

   Until a bonded publisher's entries arrive, every node's catalog is empty.
4. **Check.** `scripts/launch/after_start.py --hosts <hosts file>
   --funded-account <address> ...`, one `--funded-account` per account
   genesis funds. It fails on an empty catalog, a node that names no
   operator, and a funded account with no registered identity.

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

## Access to the RPC node

Who may use the node at all is its access
policy (`access.toml`, see [`docs/ACCESS.md`](../docs/ACCESS.md)); set it with
`tenzro-node access`. Admin-class methods admit only the operator DID and the
policy's `admins`, who sign in with a passkey or hardware key for a DPoP-bound
access token. There is no admin token, API key or shared secret to provision
on any node.

## Engine-error pool guard

A transaction that makes the EVM engine fail after it has run is charged as
one that never ran. Until the chain rule that prices it is live
(`feature.evm_conformance.activation_epoch`), each node keeps such
transactions out of its own pool from what executed blocks show it. This is
the node's own admission, for transactions from peers and from its RPC
alike; it changes nothing about which blocks are valid. The values are in
the node's configuration file and are read at start:

```toml
[evm_pool_guard]
enabled = true            # false turns the guard off
hold_secs = 3600          # a sender is held this long after its transaction ended in an engine error
watch_secs = 600          # engine errors are counted over this window
watch_faults = 3          # this many in the window start the gas limit ceiling
watch_gas_limit = 1000000 # no EVM transaction above this gas limit is admitted while the window runs
held_senders_max = 10000  # most senders held at once
```

A value of zero for any of the counts or durations, or a ceiling below the
gas of a plain transfer, is refused at start: the guard is turned off only
with `enabled = false`. Each hold and each start of the ceiling is logged
at `warn` with the transaction.

Under attack, tighten `watch_faults` and `watch_gas_limit`. Know the two
ways the guard can be used against honest users before you do: `watch_faults`
cheap engine-error transactions every `watch_secs` keep every EVM
transaction above `watch_gas_limit`, large deployments among them, out of
your node; and a contract that calls the failing address gets each of its
callers held for `hold_secs`. Holds are kept in memory only and run from the
time of the block that showed the error, so a restart forgets them and
blocks imported from the past set none that is still in force.

## Next steps

- Read [`crates/tenzro-node/QUICKSTART.md`](../crates/tenzro-node/QUICKSTART.md)
  if you want to run a single node locally first before standing up a fleet.
