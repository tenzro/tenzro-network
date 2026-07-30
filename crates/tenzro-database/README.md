# tenzro-database

Engine-agnostic distributed database layer.

## Overview

A node can serve a queryable database three ways: on its own machine, across
its own local-network segment, or sharded across the wider network — the same
local-machine → cluster → network progression the model-serving and storage
tiers use.

This crate is the protocol and registry layer for that. It records what
databases exist, which engine each one wants, where its partitions sit, who
may read them, and what a query costs. It links no engine driver. A node layer
constructs the concrete backend — the thing that actually starts Postgres or
opens a Lance dataset — registers it against an engine id, and receives
partition handles to operate on.

That split is what lets the registry stay small and dependency-free while the
engine set stays open. The registry depends on `tenzro-types`,
`tenzro-cluster`, and `tenzro-storage`, and nothing else.

## Layers

| Module | Role |
|---|---|
| `catalog` | The engines a node can run — Postgres, Qdrant, Milvus, Dgraph, Valkey, embedded Lance, embedded Tantivy — each with its `DataModel`s, license, external dependencies, and `ShardingModel`. Every entry is checked to be outside the SSPL / RSALv2 source-available family. |
| `engine_config` | Typed builders (`PostgresConfig`, `MilvusConfig`, `QdrantConfig`, `ValkeyConfig`, `DgraphConfig`, `EmbeddedConfig`) for the opaque `engine_config` JSON a descriptor carries. The registry stores the blob verbatim; only the backend interprets it, so a backend can read fields this module does not model. |
| `database` | `DatabaseDescriptor`, `PlacementMode`, `ReplicationPolicy`, and the write-through `DatabaseRegistry`. Persists descriptors and partition placements to `CF_DATABASES`, hydrates on boot, and reports health through `under_replicated` / `plan_repair` / `record_repair`. |
| `placement` | Rendezvous (HRW) partition placement over the network tier, pinned to the database domain tag so database partitions and storage shards never co-place by accident over the same member ids. Wraps the local-first `tenzro_cluster::tiered` primitive. |
| `access_control` | The `AccessPolicy` every descriptor carries — who may read, who may administer — enforced identically across all three tiers, plus an opt-in `ConfidentialSeal` that encrypts network-tier data with a data key wrapped once per authorized DID. This crate records policy and wrapped-key envelopes; the node layer adjudicates capabilities and unwraps keys. |
| `pricing` | `DatabasePricing` per descriptor and the write-through `DatabaseUsageMeter` a holder uses to count served queries and settled payments. The node gates the query path on price through the payment gateway. The owner always queries free. |
| `runtime` | The `DatabaseEngine` trait — the seam to node-layer backends — plus `QueryRouter`, which routes reads to one holder with deterministic failover and fans writes out under a `WriteConsistency` level, and `HolderDispatch` / `PartitionHandle` / `WriteReceipt`. |
| `gossip` | One topic, `tenzro/databases`. When a node creates or rescales a network-tier database it broadcasts the descriptor so other nodes hydrate the same placement without polling. Local- and cluster-tier databases stay off the topic — they have no network holders to announce. |

## How an engine gets distributed

`ShardingModel` decides. Engines that carry their own cluster fabric — Milvus,
Postgres with Citus, Valkey Cluster, Dgraph — are placed as native cluster
members, and the `NativeClusterSpec` in the catalog entry says which roles need
filling. Single-node engines are sharded by Tenzro instead: the partition map
is computed here and each holder runs an independent instance.

Either way, `ReplicationPolicy` sets a floor and ceiling on distinct holders
per partition, and placement fails closed below the floor rather than silently
under-replicating.

## Used By

- **`tenzro-node`** — `db_engine_registry`, `db_engines`, and
  `db_holder_dispatch` are the node-side surface: they own the concrete
  backends, serve the database RPC namespace, and consume the
  `tenzro/databases` topic.

## Tests

```bash
cargo test -p tenzro-database
```

## License

Apache-2.0.
