# tenzro-storage-provider

Paid, fault-tolerant object storage over the content-addressed iroh transport.

## Overview

A node that accepts the `StorageProvider` role takes bytes from a renter, cuts
them into erasure shards, publishes the shards over iroh, and gets paid one
epoch at a time — but only for the epochs in which it can prove it still holds
them.

That last clause is the whole design. A per-shard SHA-256 commitment proves
*what* the bytes should be, but a provider can discard the bytes and still know
the commitment. So payment is gated on a fresh challenge each epoch rather than
on a stored digest.

## Layers

| Module | Role |
|---|---|
| `provider` | The daemon. `StorageProvider::store` erasure-encodes an object, publishes each shard through the `IrohResolver` (one `tenzro://blob/<blake3>` URI per shard), and records an `ObjectDescriptor` binding object id → shard URIs, per-shard commitments, byte length, and scheme. `serve` fetches the shards back, verifies each against its commitment, and reconstructs — tolerating up to `parity_shards` missing or corrupt shards. |
| `redundancy` | Systematic Reed-Solomon over GF(2^8): `k` data shards plus `m` parity, any `k` of `n` reconstruct. Surviving `m` failures costs `n/k` overhead rather than the `m+1` full copies replication would need. Plain replication remains available as the `k = 1` case, so `RedundancyScheme::replicated(copies)` is sugar over the same encoder. The object is zero-padded to a multiple of `k` and the original length is kept in the descriptor so padding is stripped on reconstruction. |
| `por` | Proof of retrievability. The verifier draws a fresh random nonce, names a random subset of shard indices, and demands `SHA-256(nonce ‖ shard_bytes)` for each. The nonce makes precomputation useless. Two verification models: independent recompute, where the verifier fetches the challenged shards itself and compares — this proves the bytes are retrievable from the network, not merely that the provider answered — and a commitment-witness pre-filter that can reject structurally impossible responses without transport access. |
| `metering` | `StoragePricing` and `StorageMeter`. One epoch costs `size_bytes × rate_per_byte_epoch`, drawn from the renter's pre-funded deposit and streamed to the provider only when that epoch's challenge passes. A failed challenge is a miss: the renter is not charged. Repeated misses terminate the deal and return unearned funds. |
| `placement` | Rendezvous (HRW) shard placement over the network tier, pinned to the storage domain tag so shards and database partitions never co-place by accident over the same endpoint ids. `select_tiered_holders` / `should_replicate_tiered` wrap the local-first `tenzro_cluster::tiered` primitive, so a deal served entirely inside one segment keeps every replica on that segment and spills onto the wider network only when the segment is too small. |

## Economic model

Storage is billed like rental. The renter pre-funds; value streams per epoch;
provider stake collateralizes the obligation. This crate moves deposit value
and signals misses. It does not own slashing policy — that stays with the
staking subsystem, which consumes the miss signal.

## Placement without a coordinator

Every node computes the same HRW ranking of storage-capable endpoints for a
given shard commitment from its own membership view, and pins the shard if it
ranks in the top `replicas`. There is no placement table and no election.
Membership-view skew produces mild over- or under-replication that heals as
views converge and blob heartbeats re-announce holders.

## Used By

- **`tenzro-node`** — `storage_provider_runtime` owns the daemon, the meter,
  and a per-resource pricing policy (fixed, network-dynamic, or order book),
  and runs the charge tick: draw a challenge over a random shard subset, answer
  it from local bytes, verify the answer over the transport, then charge the
  epoch. Cross-service stake coverage across storage and compute rentals runs
  through the shared obligations tracker. Surfaced as `tenzro_storageStoreObject`,
  `tenzro_storageOpenDeal`, `tenzro_storageChargeEpoch`, `tenzro_storageGetDeal`,
  `tenzro_storageDeal`, `tenzro_storageSetPricing`, and `tenzro_storageStatus`.

## Tests

```bash
cargo test -p tenzro-storage-provider
```

## License

Apache-2.0.
