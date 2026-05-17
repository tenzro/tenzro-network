# gce_validators — Phase A: 10 GCE validators across 5 zones

Replaces the 3-pod GKE `StatefulSet` + 1 RPC `Deployment` shape with 10 individual
GCE instances spread across 5 GCP zones (2 per zone). The existing GKE cluster
(`tenzro-testnet`) is **not** torn down by this module — operators cut over by
seeding a fresh genesis on the new VMs, then drain the GKE cluster manually.

## Topology

| Index | Hostname            | Zone            | Role
|------:|---------------------|-----------------|------------------------------
| 0     | tenzro-validator-0  | us-central1-a   | validator + bootstrap peer + RPC
| 1     | tenzro-validator-1  | us-central1-a   | validator
| 2     | tenzro-validator-2  | us-central1-b   | validator
| 3     | tenzro-validator-3  | us-central1-b   | validator
| 4     | tenzro-validator-4  | us-central1-c   | validator
| 5     | tenzro-validator-5  | us-central1-c   | validator
| 6     | tenzro-validator-6  | us-east1-b      | validator
| 7     | tenzro-validator-7  | us-east1-b      | validator
| 8     | tenzro-validator-8  | us-west1-a      | validator
| 9     | tenzro-validator-9  | us-west1-a      | validator

Validator 0 doubles as the RPC node (publicly serves `:8545`, `:8080`, MCP
`:3001`, A2A `:3002`, Solana/Ethereum/Canton/LayerZero/Chainlink/Li.Fi MCP
`:3003`–`:3008`). Validators 1–9 expose only `:9000` (libp2p) externally; their
RPC port is bound to `127.0.0.1`.

## Consensus quorum

With 10 validators the HotStuff-2 quorum is **7-of-10** (`f = 3`, `2f+1 = 7`).
Losing any single zone (max 2 validators) leaves 8 honest validators — still
above the quorum threshold.

## Key material

Each validator carries three keys:

1. **Ed25519 consensus key** (32-byte secret) — votes & block signatures.
2. **ML-DSA-65 PQ key** (4032-byte secret) — hybrid signature, post-quantum leg.
3. **libp2p p2p key** (Ed25519, 32-byte secret) — stable peer ID for gossipsub.

All three are generated offline (see `tools/genkeys/`), stored in GCP Secret
Manager under `projects/${project_id}/secrets/tenzro-validator-${i}-{consensus,pq,p2p}`,
and pulled by cloud-init into `/var/lib/tenzro/keys/` (mode `0600`,
`tenzro:tenzro`) on first boot.

The genesis file (`config/genesis-prod.toml`) is committed to the repo and
embeds only **public** Ed25519 + ML-DSA-65 keys and stakes.

## CLAUDE.md boundary

This module is **dev-tree-only**. Running `terraform apply` against
`tenzro-operator-project` would:

  - create 10 GCE instances (~$650/mo on `n2-standard-4` + `pd-balanced 100GB`)
  - create 30 Secret Manager entries (key material)
  - create 2 new VPC subnetworks (`us-east1`, `us-west1`)
  - create a regional internal LB and public IPs for validator-0

All of which cross the boundary. The user must explicitly authorize:

```
cd deploy/terraform/gce_validators
terraform init
terraform plan -var-file=../terraform.tfvars
terraform apply -var-file=../terraform.tfvars
```

before each invocation. There is no per-`terraform apply` standing approval.

## Migration sequence (post-`terraform apply`)

1. **Build a new image with #129 code landed** (snapshot ABCI + state-sync).
   Existing image `:20260513-192247` predates #129 — re-running `gcloud builds
   submit` produces a new tag with the new code.
2. **Seed validator-0 first** with the new genesis. It starts an empty chain
   at height 0.
3. **Bring up validators 1–9** with `--boot-nodes` pointing at validator-0's
   external IP + peer ID. Each joins consensus once it has caught up.
4. **Repoint DNS** — `rpc.tenzro.network`, `api.tenzro.network`,
   `mcp.tenzro.network`, `a2a.tenzro.network`, `solana-mcp.tenzro.network`,
   `ethereum-mcp.tenzro.network`, `canton-mcp.tenzro.network`,
   `layerzero-mcp.tenzro.network`, `chainlink-mcp.tenzro.network`,
   `lifi-mcp.tenzro.network` from the GKE Caddy LB to validator-0's IP.
5. **Drain GKE** — `kubectl scale statefulset/tenzro-validator --replicas=0`
   and `kubectl scale deployment/tenzro-rpc --replicas=0`, leave the cluster
   running for snapshot-restore safety for 7 days, then `terraform destroy`
   the GKE module.

## File layout

```
gce_validators/
  README.md         — this file
  main.tf           — provider + terraform block
  variables.tf      — all module inputs
  network.tf        — VPC subnets in 3 regions + firewall rules
  secrets.tf        — 30 Secret Manager entries (3 per validator)
  validators.tf     — 10 google_compute_instance resources
  cloud-init.yaml   — systemd unit + key fetch + binary install
  outputs.tf        — validator IPs, peer multiaddrs, RPC endpoint
```

The `tools/genkeys/` companion (offline key generator) lives outside this
module — see `tools/genkeys/README.md`.
