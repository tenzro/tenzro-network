# tenzro-genkeys — offline validator key generator

Generates the cryptographic material for the 10-validator Phase A GCE
deploy: per-validator Ed25519 consensus seed, ML-DSA-65 post-quantum seed,
and libp2p Ed25519 P2P keypair, plus a ready-to-commit `genesis-prod.toml`.

This tool runs **once**, on a **trusted laptop** that is air-gapped or at
least off corporate WiFi. The seeds it produces are the long-term identity
of the production testnet validators — they must not touch CI, shared
disks, or any service that backs up to the cloud unencrypted.

## Prerequisites

- Rust toolchain (`rustup`, matching `rust-toolchain.toml`)
- `gcloud` CLI authenticated as a principal with
  `roles/secretmanager.admin` on project `tenzro-infra`
- `shred` (GNU coreutils) or equivalent secure-erase tool

## Run

From the workspace root:

```bash
cargo run --release -p tenzro-genkeys -- \
    --out ~/tenzro-phaseA-keys \
    --count 10 \
    --chain-id 1338 \
    --stake-per-validator 1000
```

This creates `~/tenzro-phaseA-keys/` with:

```
validator-0/
    consensus.seed   # 32-byte raw Ed25519 seed (mode 0600)
    pq.seed          # 32-byte raw ML-DSA-65 seed (mode 0600)
    p2p.seed         # libp2p protobuf-encoded Ed25519 keypair (mode 0600)
    consensus.pub    # hex of 32-byte Ed25519 public key
    pq.pub           # hex of 1952-byte ML-DSA-65 verifying key
    peer_id.txt      # base58 multihash libp2p peer ID
validator-1/  ...  validator-9/
genesis-prod.toml    # version=2, all 10 validators, faucet + seed accounts
PEER_IDS.txt         # summary list — copy validator-0 into Terraform
```

All directories are mode `0700`, all `*.seed` files are mode `0600`.

The tool **refuses to overwrite an existing `--out` directory**. Pick a
fresh path each invocation; if you need to regenerate, move the old
directory aside first (after wiping its contents — see "Secure wipe"
below).

## Verify

Before uploading, eyeball one validator to sanity-check the byte counts:

```bash
wc -c ~/tenzro-phaseA-keys/validator-0/{consensus,pq,p2p}.seed
# consensus.seed: 32
# pq.seed:        32
# p2p.seed:       ~40-80 (libp2p protobuf, variable but stable across runs)
```

And confirm the hex public keys in `genesis-prod.toml` match what the
per-validator `*.pub` files contain:

```bash
grep -A2 'validator-0' ~/tenzro-phaseA-keys/genesis-prod.toml
diff <(cat ~/tenzro-phaseA-keys/validator-0/consensus.pub) \
     <(grep -m1 'public_key' ~/tenzro-phaseA-keys/genesis-prod.toml | \
       sed -E 's/.*"([0-9a-f]+)".*/\1/')
```

## Commit the genesis (no seeds)

```bash
cp ~/tenzro-phaseA-keys/genesis-prod.toml \
   ~/AI/tenzronetwork/config/genesis-prod.toml
```

Review the file diff before committing.

## Upload secrets to GCP Secret Manager

The tool prints the exact `gcloud` commands at the end of its run. They
look like:

```bash
gcloud secrets versions add tenzro-validator-0-consensus \
    --data-file=~/tenzro-phaseA-keys/validator-0/consensus.seed \
    --project=tenzro-infra
gcloud secrets versions add tenzro-validator-0-pq \
    --data-file=~/tenzro-phaseA-keys/validator-0/pq.seed \
    --project=tenzro-infra
gcloud secrets versions add tenzro-validator-0-p2p \
    --data-file=~/tenzro-phaseA-keys/validator-0/p2p.seed \
    --project=tenzro-infra
# ... repeated for validator-1 through validator-9
```

The Secret Manager **containers** are created by
`deploy/terraform/gce_validators/` — `terraform apply` must run **before**
you upload payloads. After `apply`, the containers exist with zero
versions; `gcloud secrets versions add` populates them.

Each `gcloud secrets versions add` invocation writes a new secret
version. Run them one at a time and verify the per-VM payload is
correct before proceeding to the next.

## Set the Terraform bootstrap peer ID

Open `PEER_IDS.txt`, copy the `validator-0:` line, and set it in
`deploy/terraform/gce_validators/terraform.tfvars`:

```hcl
bootstrap_peer_id = "12D3KooW..."
```

This is the libp2p peer ID validators 1–9 dial as their `--boot-nodes`.

## Secure wipe

Once the seeds are confirmed uploaded to Secret Manager and the genesis
file is committed, **delete every `*.seed` file**:

```bash
shred -uvz ~/tenzro-phaseA-keys/validator-*/*.seed
rm -rf ~/tenzro-phaseA-keys
```

`shred -u` overwrites then unlinks; `-v` is verbose; `-z` zeros the final
pass to hide that shredding occurred. On encrypted-volume filesystems
(APFS with FileVault, LUKS) `shred` is overkill but harmless.

If your laptop has a backup running (Time Machine, Arq, restic) make sure
the backup either excludes `~/tenzro-phaseA-keys` or that you suspend it
for the duration. **A backup of `*.seed` defeats the entire offline-key
model.**

## What this tool does NOT do

- No HSM integration — seeds are written to disk in cleartext. The 0600
  permissions + filesystem encryption + immediate-wipe-after-upload model
  is what protects them.
- No threshold/MPC split — each validator's seed is a single ed25519 /
  ML-DSA-65 keypair. Phase B may move to threshold consensus signatures;
  the on-disk format stays the same so existing seeds carry forward.
- No automatic upload — uploading to Secret Manager is a separate
  deliberate step the operator runs, so the boundary is auditable.
- No re-randomization on partial failure — if `gcloud secrets versions
  add` fails mid-way, fix the auth/network issue and resume from the
  failed validator. There is no harm in re-uploading the same seed (it
  just creates a new version; the loader always reads `latest`).
