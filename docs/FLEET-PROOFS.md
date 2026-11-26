# Fleet and rack proofs

An operator with many machines proves their hardware in one transaction from the operator's wallet instead of one transaction per machine. This page describes what a fleet proof carries, how the chain judges it and what it records. The hardware levels themselves, and the roots and reference values governance sets for them, are described in [GOVERNANCE_PARAMS.md](GOVERNANCE_PARAMS.md).

## What a single machine does without a fleet proof

A hardware level is never declared. The chain derives it from evidence in consensus state, and a machine must show every reward epoch that it still holds the TPM its level rests on. Once the randomness beacon has taken its first value of the epoch, the epoch's possession challenge is known. A node quotes it with its TPM's admitted attestation key and sends the quote as a `HardwareProof` transaction from its own account. A node with an NVIDIA GPU also sends the GPU's signed SPDM measurement report over the epoch's GPU challenge, with the GPU's certificate chain. A node does this by itself; its operator runs nothing.

A machine that sends no quote for an epoch, or whose quote is refused, is level 0 at that epoch's close. A level adds a small, capped reward bonus. It never admits or excludes anyone.

## What a fleet proof is

A fleet proof is the `Fleet` form of the `HardwareProof` transaction. The operator's wallet sends it, and it carries the evidence of many hosts for one reward epoch:

- `issuers`: the DER certificates every GPU chain in the proof shares above its device certificate (NVIDIA's device identity CA and root). They are appended to each GPU's chain, so they travel once. Empty when each chain is whole.
- `units`: the hosts and racks.

A unit is one of two things.

| Unit | What it is | How it is judged |
|------|------------|------------------|
| `host` | One machine identity admitted with its own TPM, with up to 8 GPUs | On its own |
| `rack` | A rack-scale system attested as one unit (an NVL72 rack: 18 compute trays of 4 GPUs), under a label the operator chooses | Every host and GPU in it verifies, or none of it counts |

Each host in a unit carries:

- `did`: the host's machine identity. Each host is registered and admitted with its own TPM before it can appear in a fleet proof.
- `binding`: a quote by the host's TPM over the fleet binding, which is a hash of the operator's identity and the host's. A host sends it the first time it joins the operator's fleet and leaves it out afterwards. A quote made for one operator or host binds no other.
- `epoch` and `possession`: the reward epoch and the host's quote over that epoch's possession challenge.
- `gpus`: each GPU's SPDM measurement report over the GPU challenge drawn from that host's possession challenge, with the device's own certificates.

## What a GPU proof publishes

A GPU report is published with the certificates NVIDIA signed for that device: the device certificate's serial number, the alias certificate's serial and the NVIDIA device identifier in its subject alternative name. The signatures the chain checks cover them, so they cannot be removed or replaced by a hash, and they stay in the chain's history for good. Anyone can then tell when the same GPU appears again, under any operator.

So GPU evidence is sent only when its operator asks for it: a fleet proof carries GPUs only when built with `--gpu`, and a single machine sends its own GPU proof each reward epoch only with

```toml
[gpu_proof]
enabled = true
```

in its node configuration. Without GPU evidence the GPU does not count toward the machine's hardware level; the TPM possession proof is sent either way.

## How the chain judges it

Each host stands alone and each rack stands as one. A host or rack whose evidence fails is refused and named in the transaction's log with the reason, and the rest are written. The proof is refused whole only when nothing in it is accepted, when the operator's identity is revoked, or when it breaks a size limit. A rack label that appears twice in one proof is refused the second time.

A GPU is checked as it is for a single machine: its device chain must end at a GPU root governance recognizes, and its measurements must match the GPU reference values governance sets. Both records are empty until governance sets them, so no GPU counts before that. One GPU counts for one live identity.

## Limits and gas

| Limit | Value |
|-------|-------|
| Hosts in one proof, a rack's hosts included | 64 |
| GPUs in one proof | 128 |
| GPUs on one host | 8 |
| Hosts in one rack | 18 |
| GPUs in one rack | 72 |
| Rack label | 64 bytes |
| One GPU report, and one GPU certificate chain | 8,192 bytes each |
| Evidence in one proof | 480 KiB |

The evidence limit keeps the transaction inside one gossip message. One NVL72 rack fits in one proof: its 72 GPU reports and device certificates with its 18 hosts' quotes. A larger fleet sends several proofs.

A fleet proof costs the gas of a hardware proof (150,000) plus 40,000 for each TPM quote and 60,000 for each GPU report it carries.

## What the chain records

- For each accepted host: its possession for the epoch, the GPUs it proved together, and its fleet membership (the operator, the epoch it joined in, and the rack it was last proven in, when it is part of one).
- For each accepted rack: a record under an identifier derived from the operator's identity and the label, with the epoch it was last proven in, its hosts and its GPUs.
- One log under the hardware proof topic with the operator, the accepted hosts with their GPUs and rack, and the refused hosts and racks with their reasons.

`tenzro_getHardwareLevel` reads the level the chain derives for an account.

## Building a fleet proof

A fleet proof is built in two steps, because only a host's own TPM can quote with its admitted attestation key.

1. On each host, once the epoch's possession challenge is known, ask the host's node for its evidence:

   ```
   tenzro fleet evidence --operator <operator's identity> --out host-07.json
   ```

   Add `--bind` the first time the host joins the operator's fleet, and `--gpu` on a host whose GPU should be counted (one GPU per host through this command). A GPU's evidence is its SPDM report and its certificate chain, both signed, so they go on chain whole. The device and alias certificates carry per-device serial numbers and an NVIDIA device identifier, so a GPU proof publishes the GPU's identity permanently, as the single-machine GPU proof already does. `--gpu` is off unless given. The node answers through `tenzro_fleetHostEvidence`, an operator-only method; it quotes with the host's TPM and submits nothing.

2. As the operator, send the files together from the operator's wallet:

   ```
   tenzro fleet prove --host host-07.json --host host-08.json \
     --rack hall-a/row-3/nvl72-07=tray-01.json,tray-02.json \
     --issuers nvidia-issuers.der
   ```

   Each `--host` is judged on its own and each `--rack` as one unit. `--issuers` carries the certificates every GPU chain shares, once. The command refuses a proof the chain would refuse at admission (a size limit passed, a host named twice) before it is sent. Its gas limit is twice what the chain charges for the proof's quotes and reports, as a node sets for its own proof.

The evidence answers one reward epoch's challenge, so the operator sends it within that epoch. A host or rack the chain refuses is named in the transaction's log with the reason.
