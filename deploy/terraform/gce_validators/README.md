# gce_validators — 10 GCE validators across 3 continents

Tenzro testnet runs as 10 individual GCE instances on Container-Optimized OS,
spread across 10 zones in 3 GCP regions (4 NA + 3 EU + 3 APAC). This module is
the IaC source-of-truth for the live fleet — `terraform apply` from a clean
state reproduces the current testnet topology exactly.

## Topology

| Index | Hostname             | Zone               | Role
|------:|----------------------|--------------------|------------------------------
| 0     | tenzro-validator-0   | us-central1-a      | validator + bootstrap peer + RPC public + Caddy + pkarr-relay + Canton
| 1     | tenzro-validator-1   | us-central1-b      | validator
| 2     | tenzro-validator-2   | us-central1-c      | validator
| 3     | tenzro-validator-3   | us-central1-f      | validator
| 4     | tenzro-validator-4   | europe-west1-b     | validator
| 5     | tenzro-validator-5   | europe-west1-c     | validator
| 6     | tenzro-validator-6   | europe-west1-d     | validator
| 7     | tenzro-validator-7   | asia-southeast1-a  | validator
| 8     | tenzro-validator-8   | asia-southeast1-b  | validator
| 9     | tenzro-validator-9   | asia-southeast1-c  | validator

Validator 0 doubles as the RPC node (publicly serves `:8545`, `:8080`, MCP
`:3001`, A2A `:3002`, Solana/Ethereum/Canton/LayerZero/Chainlink/Li.Fi MCP
`:3003`–`:3008`). Validators 1–9 expose only `:9000` (libp2p TCP+QUIC)
externally; their RPC port is bound to `127.0.0.1`.

### Validator 0's extra services

The RPC-public node carries four roles beyond plain validation, all gated on
`rpc_public == "true"` in `cloud-init.yaml`:

1. **Caddy reverse proxy** — terminates TLS (PQ-hybrid X25519MLKEM768) for
   `*.tenzro.network` and reverse-proxies to local ports.
2. **pkarr-relay** — Tenzro-operated Pkarr relay for TDIP-anchored iroh
   `EndpointId` discovery (Phase C2). Published at `https://pkarr.tenzro.network/`.
3. **Canton bridge** — Auth0-mediated access to the Canton devnet ledger,
   fronted by Tenzro's API-key gate (`X-Tenzro-Api-Key` with `canton` scope).
   See [Canton config (RPC node only)](#canton-config-rpc-node-only).
4. **Admin API gate** — admin-token-protected RPCs for API key issuance
   (`tenzro_createApiKey` / `tenzro_revokeApiKey` / `tenzro_listApiKeys`) and
   circuit-breaker reset.

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

## Canton config (RPC node only)

Validator-0's RPC surface fronts the Canton devnet ledger. The devnet
endpoint (`https://json.devnet.tenzro.network/`) lives in a separate GCP
project (`canton-network`), and Canton mandates a JWT bearer issued by
Auth0. Tenzro holds the Auth0 client credentials server-side and exposes
the Canton API through a `tnz_...` API-key gate so external callers never
touch Auth0 directly.

Two secrets are sourced at boot from the `canton-network` project's Secret
Manager (cross-project IAM grants `roles/secretmanager.secretAccessor`
per-secret to `tenzro-validator-0@tenzro-operator-project.iam.gserviceaccount.com`, granted
out-of-band in the `canton-network` project — those grants are NOT in this
terraform module because this module's provider is scoped to `tenzro-operator-project`):

| Secret (in `canton-network`)              | Env var on validator-0          | Purpose
|-------------------------------------------|---------------------------------|---------
| `tenzro-rpc-admin-token`                  | `TENZRO_ADMIN_TOKEN`            | Gates admin RPCs (`tenzro_createApiKey`, etc.) via `X-Tenzro-Admin-Token` header
| `damlstudio-canton-auth0-client-secret`   | `CANTON_DEVNET_CLIENT_SECRET`   | Auth0 client_secret for the devnet profile (`CantonConfig::from_env()` when `CANTON_DEVNET=true`)

The fetcher, the systemd unit (`tenzro-fetch-canton-config.service`), the
`EnvironmentFile=/etc/tenzro/tenzro-node.env` line on `tenzro-node.service`,
and the `-e CANTON_DEVNET=true -e CANTON_DEVNET_CLIENT_SECRET -e TENZRO_ADMIN_TOKEN`
additions on the docker wrapper are all written by `cloud-init.yaml` and gated
on `rpc_public == "true"`. Validators 1–9 don't carry any of this — they
return `-32004` on `tenzro_*Canton*` calls (scope gate) and `-32001` on admin
RPCs (admin-token unset → fail-closed).

Secret rotation: update the secret in the `canton-network` project's Secret
Manager, then on validator-0:

```
sudo systemctl restart tenzro-fetch-canton-config.service
sudo docker stop tenzro-node    # systemd respawns the node with new env
```

## CLAUDE.md boundary

Running `terraform apply` against `tenzro-operator-project` would:

  - create 10 GCE instances (~$650/mo on `n2-standard-4` + `pd-balanced 100GB`)
  - create 30 Secret Manager entries (validator key material) in `tenzro-operator-project`
  - create 2 new VPC subnetworks (`europe-west1`, `asia-southeast1`; `us-central1`
    is data-sourced from an existing subnet)
  - create public IPs for validator-0 (RPC) and validators 1–9 (libp2p)

All of which cross the boundary. The user must explicitly authorize:

```
cd deploy/terraform/gce_validators
terraform init
terraform plan -var-file=../terraform.tfvars
terraform apply -var-file=../terraform.tfvars
```

before each invocation. There is no per-`terraform apply` standing approval.

The Canton-related secrets (`tenzro-rpc-admin-token`,
`damlstudio-canton-auth0-client-secret`) and the cross-project IAM grants
that let validator-0 read them are managed out-of-band in the
`canton-network` project. This module does not touch them.

## File layout

```
gce_validators/
  README.md         — this file
  main.tf           — provider + terraform block
  variables.tf      — all module inputs
  network.tf        — VPC subnets in 3 regions + firewall rules
  secrets.tf        — 30 Secret Manager entries (3 per validator)
  validators.tf     — 10 google_compute_instance resources
  cloud-init.yaml   — systemd units + key fetch + Canton fetch (RPC node) + wrapper
  outputs.tf        — validator IPs, peer multiaddrs, RPC endpoint
```

The `tools/genkeys/` companion (offline key generator) lives outside this
module — see `tools/genkeys/README.md`. The standalone bootstrap copies of
the Canton fetcher under `deploy/rpc-node/` are kept for manual
re-bootstrap; `cloud-init.yaml` is the canonical source.
