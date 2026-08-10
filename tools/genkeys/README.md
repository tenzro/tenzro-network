# tenzro-genkeys — offline validator key generator

Generates the cryptographic material for a validator set: per-validator
Ed25519 consensus seed, ML-DSA-65 post-quantum seed, and libp2p Ed25519
P2P keypair, plus a ready-to-commit `genesis.toml`.

This tool runs **once**, on a **trusted machine** that is air-gapped or at
least off shared networks. The seeds it produces are the long-term identity
of your validators — they must not touch CI, shared disks, or any service
that backs up to the cloud unencrypted.

## Prerequisites

- Rust toolchain (`rustup`, matching `rust-toolchain.toml`)
- `shred` (GNU coreutils) or equivalent secure-erase tool

## Run

From the workspace root:

```bash
cargo run --release -p tenzro-genkeys -- \
    --out ~/validator-keys \
    --count 4 \
    --chain-id 1337 \
    --stake-per-validator 1000
```

This creates `~/validator-keys/` with:

```
validator-0/
    consensus.seed   # 32-byte raw Ed25519 seed (mode 0600)
    pq.seed          # 32-byte raw ML-DSA-65 seed (mode 0600)
    p2p.seed         # libp2p protobuf-encoded Ed25519 keypair (mode 0600)
    consensus.pub    # hex of 32-byte Ed25519 public key
    pq.pub           # hex of 1952-byte ML-DSA-65 verifying key
    peer_id.txt      # base58 multihash libp2p peer ID
validator-1/  ...  validator-N/
genesis.toml         # all N validators, faucet + seed accounts
PEER_IDS.txt         # summary list — copy validator-0 into your boot config
```

All directories are mode `0700`, all `*.seed` files are mode `0600`.

The tool **refuses to overwrite an existing `--out` directory**. Pick a
fresh path each invocation; if you need to regenerate, move the old
directory aside first (after wiping its contents — see "Secure wipe"
below).

## Verify

Before uploading, eyeball one validator to sanity-check the byte counts:

```bash
wc -c ~/validator-keys/validator-0/{consensus,pq,p2p}.seed
# consensus.seed: 32
# pq.seed:        32
# p2p.seed:       ~40-80 (libp2p protobuf, variable but stable across runs)
```

And confirm the hex public keys in `genesis.toml` match what the
per-validator `*.pub` files contain:

```bash
grep -A2 'validator-0' ~/validator-keys/genesis.toml
diff <(cat ~/validator-keys/validator-0/consensus.pub) \
     <(grep -m1 'public_key' ~/validator-keys/genesis.toml | \
       sed -E 's/.*"([0-9a-f]+)".*/\1/')
```

## Commit the genesis (no seeds)

```bash
cp ~/validator-keys/genesis.toml config/genesis.toml
```

Review the file diff before committing. Only the genesis (public keys)
goes into the repo — never the seeds.

## Distribute the seeds to your validators

Each validator needs its own three seeds (`consensus.seed`, `pq.seed`,
`p2p.seed`) delivered to a root-only path (e.g. `/var/lib/tenzro/`) before
`tenzro-node` starts. How you deliver them — a secrets manager, an
encrypted transfer, a hardware token — is up to your infrastructure. The
boot-time fetch pattern (a oneshot unit that writes the seeds, required-by
`tenzro-node.service`) is described in
[`deploy/validator-deployment.md`](../../deploy/validator-deployment.md).

Set the bootstrap peer ID your other validators dial: copy the
`validator-0:` line from `PEER_IDS.txt` into their `--boot-nodes`.

## Secure wipe

Once the seeds are confirmed delivered and the genesis file is committed,
**delete every `*.seed` file**:

```bash
shred -uvz ~/validator-keys/validator-*/*.seed
rm -rf ~/validator-keys
```

`shred -u` overwrites then unlinks; `-v` is verbose; `-z` zeros the final
pass to hide that shredding occurred. On encrypted-volume filesystems
(APFS with FileVault, LUKS) `shred` is overkill but harmless.

If your machine has a backup running (Time Machine, Arq, restic) make sure
the backup either excludes `~/validator-keys` or that you suspend it for
the duration. **A backup of `*.seed` defeats the entire offline-key
model.**

## What this tool does NOT do

- No HSM integration — seeds are written to disk in cleartext. The 0600
  permissions + filesystem encryption + immediate-wipe-after-delivery
  model is what protects them.
- No threshold/MPC split — each validator's seed is a single Ed25519 /
  ML-DSA-65 keypair.
- No automatic upload — delivering the seeds is a separate deliberate step
  the operator runs, so the boundary is auditable.
