# tenzro-cluster

Engine-agnostic local-network cluster substrate.

## Overview

A Tenzro node can serve a workload three ways: on the single local machine,
across a **local-network cluster** of nearby machines it discovered on the same
segment, or sharded across the **wider network**. This crate holds the parts of
the middle and outer tiers that do not depend on *what* is being served — model
layers, storage shards, and database partitions all reuse the same reachability
tiers, the same probed link-cost graph, the same nearest-neighbour ordering, and
the same rendezvous placement.

Each serving domain keeps its own workload-specific planner — model-layer
bin-packing, erasure-coded shard redundancy, database partition maps — and
consumes these primitives underneath it. Nothing here runs a workload or makes a
generative decision. Every function is a deterministic function of measured
inputs, so two members fed identical inputs compute the identical plan with no
coordinator round.

The crate depends on `serde` and `sha2` and nothing else, including no other
Tenzro crate. That is what lets the model, storage, and database layers all sit
on top of it without a cycle.

## Layers

| Module | Role |
|---|---|
| `reachability` | `MemberReachability` — the data-plane admission tier: `LocalDirect`, `Direct`, `RelayOnly`, `SymmetricNat`. Only directly reachable members may carry per-request cluster traffic; a relayed or symmetric-NAT member can be a catalog participant but not a hop in a latency-bound path. |
| `topology` | `MemberId`, `LinkProbe`, `link_key`, `CostMember`, `OrderedMembers`, `order_members` — a probed pairwise cost graph plus the greedy nearest-neighbour chain that orders members to minimize total transfer cost across a small cluster. `link_key` canonicalizes an unordered member pair so both ends index the same probe. |
| `placement` | `hrw_score`, `select_holders`, `should_replicate` — domain-tagged highest-random-weight (rendezvous) hashing for the network tier, so shards or partitions self-select onto independent members with no placement table and no coordinator. The domain tag keeps two subsystems placing over the same member ids from colliding. |
| `tiered` | `select_tiered_holders`, `should_replicate_tiered`, `TieredCandidate`, `TieredHolders` — local-first placement over the same rendezvous ranking. Fills replicas from the caller's own segment first and spills onto the network tier only when the segment is too small, which is the local-machine → cluster → wider-network progression applied to placement. |

## Why rendezvous hashing

Placement has to be recomputed independently by every member, from membership
alone, without an election or a shared table. Rendezvous hashing gives that: a
member scores each candidate for a key and takes the top `n`, and adding or
removing one member moves only the keys that member held. `should_replicate` is
the inverse question a candidate asks about itself — "am I one of the holders
for this key?" — answered locally with no lookup.

## Used By

- **`tenzro-model`** — LAN pipeline serving. `order_members` fixes the stage
  order for layer-wise pipeline parallelism so consecutive transformer stages
  sit on the cheapest link, and `MemberReachability` keeps a relay-only machine
  out of the per-token path.
- **`tenzro-storage-provider`** — erasure-coded shard placement across
  independent providers.
- **`tenzro-database`** — partition placement, pinned to its own domain tag so
  database partitions and storage shards never co-place by accident over the
  same member set.

## Tests

```bash
cargo test -p tenzro-cluster
```

## License

Apache-2.0.
