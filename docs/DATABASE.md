# Tenzro Databases

**Managed databases on Tenzro Network — engine-agnostic, capability-gated, elastic from a single machine to a sharded network deployment.**

---

## Abstract

A node with spare capacity can hold data for a developer the same way a managed database service does: the developer names an engine, picks how far the data should spread, and gets back a connection they authorize with a capability token. Behind that connection the node connects to a real database engine the operator runs — PostgreSQL, Qdrant, or Valkey — or serves an embedded Lance / Tantivy index in-process, and Tenzro places its partitions and replicas across the reach the developer asked for.

The database surface is a protocol layer, not a database. `tenzro-database` owns the descriptor, the placement math, access control, and gossip; it never links a tensor library or an engine driver. The node layer holds the engine drivers and dispatches queries to whichever process actually serves a partition. A developer talks to it over JSON-RPC, the CLI, or an SDK, exactly as they would a hosted database — with authentication and per-database credentials on the front.

This document describes the descriptor, the three placement tiers, the engine catalog and per-engine configuration, access control and the confidential seal, the managed-connection credential model, elastic rescale, and the RPC / CLI surfaces.

---

## 1. Design

Four properties shape the surface:

1. **Engine-agnostic protocol layer.** `tenzro-database` models a database as a `DatabaseDescriptor` — an engine id, a placement, a partition/replica count, an opaque per-engine config, an access policy, and an optional confidential seal. It computes placement and gates access; it does not run queries. The node layer holds the `EngineRegistry` that maps an engine id to a driver and dispatches `tenzro_databaseQuery` to it.

2. **Elastic from local to global.** The same descriptor scales along one continuum — `Local` (this machine), `LanCluster` (a discovered local segment), `Network` (holders across the network). A developer starts a database on their own machine and rescales it outward in place without recreating it.

3. **Native distribution, honored.** For engines that carry their own cluster fabric — Postgres/Citus, Valkey Cluster (and cataloged Milvus, Dgraph) — Tenzro places the engine's own roles (coordinator, worker, query node, primary, replica) rather than sharding rows itself. For engines that are single-node in a segment — Qdrant in the local/LAN tier — Tenzro orchestrates the sharding by placing one standalone instance per partition. Each engine's descriptor declares which model it uses so placement never fights the engine's own design.

4. **Capability-gated, like a managed service.** Every database is owned. Reads and writes pass an access policy; a developer gets a per-database connection credential (an AAP capability scoped to that one database) and dials queries with it. Sensitive network-tier data can additionally carry a confidential seal — encryption-at-rest with per-DID wrapped keys.

The crate that implements the protocol layer:

- `tenzro-database` — `DatabaseDescriptor`, `PlacementMode`, `engine_catalog`, `DatabaseRegistry`, placement, `AccessPolicy` / `ConfidentialSeal` (re-exported from `tenzro-types`), the `tenzro/databases` gossip topic.

The node layer holds the engine drivers, the `EngineRegistry`, query dispatch, connection-credential issuance, and the RPC handlers.

---

## 2. Placement tiers

`PlacementMode` is the one dial that moves a database along the local → global continuum.

| Mode | Reach | Sharding basis |
|------|-------|----------------|
| `local` | This machine only | One in-process or single-container partition |
| `lan_cluster` | A discovered local segment (mDNS + reachability) | Partitions/replicas placed across reachable local members |
| `network` | Holders across the network | Partitions/replicas placed across network candidates; descriptor gossiped on `tenzro/databases` |

Local and LAN databases have no network holders to announce and are not gossiped. A network database's descriptor is broadcast so peers converge on the same shape without polling; the consumer applies it idempotently as metadata (no placement recompute on the receiving side).

---

## 3. Engine catalog

`tenzro_listDatabaseEngines` returns the catalog. Every entry carries its data models, pinned version, container image (for external-process engines), license, and cluster model. Engines under a source-available license that restricts hosting (SSPL and equivalents) are excluded.

| Engine | Data models | Kind | Sharding | Native cluster roles | Driver |
|--------|-------------|------|----------|----------------------|--------|
| PostgreSQL | Relational, Vector (pgvector), Graph (Apache AGE) | External process | Engine-native (Citus) | Coordinator ×1, Worker ×2, Replica ×1 | Yes |
| Qdrant | Vector | External process | Tenzro-orchestrated | — (one standalone instance per partition) | Yes |
| Valkey | Key-value | External process | Engine-native (Cluster) | Primary ×3, Replica ×3 | Yes |
| Lance | Vector | Embedded | Single-node | — | Yes |
| Tantivy | Full-text | Embedded | Single-node | — | Yes |
| Milvus | Vector | External process | Engine-native | Coordinator ×1, Router ×2, StreamNode ×2, QueryNode ×2, DataNode ×2 | Catalog-only |
| Dgraph | Graph | External process | Engine-native (Raft) | Zero ×3, Alpha ×3 | Catalog-only |

The catalog is the protocol-level list of engines a database descriptor may name. A node serves an engine only when it has a linked driver *and* the operator configured its endpoint; five engines have a driver (PostgreSQL, Qdrant, Valkey, Lance, Tantivy). Milvus and Dgraph are cataloged so a descriptor can already target them, but no node driver is linked yet — a `create` or `query` against an engine no node serves returns a routing error, never a partial deployment. `tenzro_listDatabaseEngines` returns the full catalog; a node's own served set is the subset of catalog ids for which a driver is linked and an endpoint configured.

**Sharding models.**

- **Engine-native** — the engine owns partition/replica assignment and failover through its own cluster fabric. Tenzro places the engine's typed roles onto members; it does not assign rows to shards. Native-cluster engines declare their minimum role counts and any external dependencies (a leader-election store, metadata store, object store, or write-ahead-log backend) so a placement request that cannot satisfy them is rejected rather than half-formed.
- **Tenzro-orchestrated** — the engine is single-node within a segment; Tenzro shards for it by placing one standalone instance per partition and routing to the right one.
- **Single-node** — an embedded engine (Lance, Tantivy) that runs in-process and is not network-shardable.

---

## 4. Per-engine configuration

`engine_config` on the descriptor is an opaque per-engine JSON object, so a developer can drive the engine's full native configuration rather than a lowest-common-denominator subset. The node validates it against the engine before placement — an unknown key or a value the engine cannot honor fails the create, it is not silently dropped. What lives in `engine_config` is engine-specific (Citus shard count and colocation for Postgres, collection and index parameters for a vector engine, cluster slot and replica policy for Valkey), and is documented per engine in the catalog entry.

**Connect-to-existing.** A node does not spawn an external engine — it connects to one the operator runs. For each external-process engine the operator supplies a connection endpoint in node config; the node holds a stateless client to it. An embedded engine (Lance, Tantivy) needs no endpoint — it serves in-process under the node's `data_dir`. Absent an endpoint for an external engine, the node serves no backend of that kind. The `[databases]` config block carries the endpoints:

| Field | Engine served when set |
|-------|------------------------|
| `postgres_url` | `postgres` against the operator's libpq URL (Citus-clustered if the server is) |
| `qdrant_url` (+ optional `qdrant_api_key`) | `qdrant` against the operator's Qdrant endpoint |
| `valkey_url` | `valkey` against the operator's Valkey/Redis-protocol endpoint |
| `lance_embedded = true` | `lance` in-process under `{data_dir}/databases/lance/` |
| `tantivy_embedded = true` | `tantivy` in-process under `{data_dir}/databases/tantivy/` |

The operator owns the engine's lifecycle, pooling, backups, and — for the engine-native cluster engines — the cluster fabric itself; Tenzro places the descriptor's partitions onto nodes that serve the engine and routes queries to a holder.

---

## 5. Access control

Access control is shared with file storage — the same `AccessPolicy` and `ConfidentialSeal` types (in `tenzro-types`) gate a database and a stored object identically. Every database is owned; an unowned database has no admin authority and cannot be created.

`AccessPolicy` is one of:

- **`public`** — any caller may read; only the owner administers.
- **`owner_only`** — only the owner DID may read or administer. The default when a create request supplies just `owner_did`.
- **`did_allowlist`** — a named set of reader DIDs may read; the owner administers.
- **`capability_required`** — reads and writes require an AAP capability naming the policy's read/write action; the owner always administers.

A read is gated by `permits_read(caller, has_cap)`; an administrative operation (rescale, drop, issuing a connection) by `permits_admin(caller, has_cap)`. The node adjudicates every query and every admin op fail-closed before any engine work runs.

**Confidential seal.** A network-tier database holding sensitive data can carry a `ConfidentialSeal`: an encryption-at-rest envelope with one wrapped data key per authorized DID (`hpke-x25519-hkdf-sha256-aes-256-gcm`). The crate records the wrapped-key envelopes; the node/client layer does the crypto. This is opt-in on top of the always-on access policy, not a replacement for it — the layered model is: capability gate for every tier, encryption-at-rest for sensitive network data.

---

## 6. Managed connections

A developer uses a Tenzro database the way they use a hosted one — they get a credential scoped to that database and dial queries with it.

`tenzro_issueDatabaseConnection` mints the credential. The caller must be the owner (or hold the write-action capability). Params: `{database_id, caller_did, bearer_did?, write?, ttl_secs?, capability?}`. It returns an AAP capability token pinned to that single database (`allowed_resources: [database_id]`), a `mode` of `read_only` or `read_write`, the read/write actions, a TTL, and the `query_method` to call. `bearer_did` defaults to the caller — an owner can issue a read-only connection to another DID.

`tenzro_databaseQuery` runs an engine-dialect query. Params: `{database_id, caller_did, body, partition_index?, write?, capability?}`. `body` is the engine's own query payload — `{sql, params}` for Postgres, a `{op, ...}` vector search for Qdrant or Lance, a `{op, ...}` full-text search for Tantivy, a `{command: [...]}` for Valkey. The node gates the call, then:

- If this node holds the target partition, it dispatches `body` to the engine driver and returns the result.
- If it does not, it returns the holder endpoints for that partition so the caller reaches one that does. There is no silent local execution against a partition this node does not hold.

---

## 7. Elastic rescale

`tenzro_rescaleDatabase` grows or shrinks a database along the continuum in place. It is administrative — the caller passes the owner DID (or a write-action capability). Params: `{database_id, caller_did, placement, partitions?, replicas?, capability?}`. It recomputes placement over the current cluster candidates and rewrites the partition rows; a network-tier result is re-gossiped so peers converge on the new shape.

A database created `local` with one partition can be rescaled to `lan_cluster` and then `network` with more partitions and replicas as demand grows — without recreating it or moving the developer's connection.

---

## 8. Two-sided model

Databases mirror the two-sided model of the rest of the network. A developer can run engines on their own machine or LAN cluster and serve data from there, or place a database across network holders and query it over the network — the same descriptor, the same connection credential, the same query method for both. One node's stake and one set of obligations back everything it holds across compute, file storage, and databases at once.

---

## 9. RPC surface

| RPC | Purpose |
|-----|---------|
| `tenzro_listDatabaseEngines` | Return the engine catalog (data models, versions, images, licenses, cluster roles) |
| `tenzro_createDatabase` | Create a database from a descriptor; returns the normalized descriptor and its partition placements |
| `tenzro_getDatabase` | Read a database descriptor |
| `tenzro_listDatabases` | List databases |
| `tenzro_listDatabasePartitions` | List a database's partition placements |
| `tenzro_getDatabasePartition` | Read one partition placement (holders) |
| `tenzro_authorizeDatabaseRead` | Adjudicate whether a caller may read (gate check without a query) |
| `tenzro_issueDatabaseConnection` | Mint a per-database connection credential (managed-DB auth) |
| `tenzro_databaseQuery` | Run an engine-dialect query against a partition |
| `tenzro_rescaleDatabase` | Grow/shrink placement along local → LAN → network in place |
| `tenzro_dropDatabase` | Drop a database |

## 10. CLI

```
tenzro database engines
tenzro database create --id <id> --engine <engine> --placement <local|lan_cluster|network> \
  --partitions <n> --replicas <n> --owner-did <did> [--config <json>]
tenzro database get --id <id>
tenzro database list
tenzro database partitions --id <id>
tenzro database connect --id <id> --caller-did <did> [--write] [--ttl <secs>]
tenzro database query --id <id> --caller-did <did> --body <json> [--capability <token>] [--write]
tenzro database rescale --id <id> --caller-did <did> --placement <mode> [--partitions <n>] [--replicas <n>]
tenzro database drop --id <id> --caller-did <did>
```
