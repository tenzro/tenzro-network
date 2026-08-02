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

1. **Engine-agnostic protocol layer.** `tenzro-database` models a database as a `DatabaseDescriptor` — an engine id, a placement, a partition count, a replication policy, an opaque per-engine config, an access policy, and an optional confidential seal. It computes placement and gates access; it does not run queries. The node layer holds the `EngineRegistry` that maps an engine id to a driver and dispatches `tenzro_databaseQuery` to it.

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

**Replication policy.** Each partition is placed onto between `min_replication` and `max_replication` holders (default 2–4). The bounds are a policy, not a fixed count: placement targets `max_replication` when enough candidates exist, a write that cannot reach `min_replication` acknowledgements fails, and repair never grows a partition past `max_replication`. The create and rescale requests carry the policy as a `replication: {min_replication, max_replication}` object; omitted on create, the default applies — omitted on rescale, the database's current policy is kept.

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

**DID proof.** A `caller_did` on its own is an assertion, not a proof. Every gated call accepts an optional `envelope` parameter — a hex-encoded signed DID envelope binding the caller's DID, the RPC method name, and a SHA-256 hash of the call's resolved parameters, with a nonce checked for replay. Identity-based access passes (the owner, an allowlisted DID) **require** the envelope: without it the gate denies with `caller DID not authenticated: signed envelope required`. Capability-based passes are their own proof — the AAP token is signed — so a capability caller needs no envelope. Public-policy reads are exempt. The envelope's parameter hash binds the *resolved* values (for rescale, the effective partition count and min/max replication bounds after defaulting), so a replayed envelope cannot authorize a different operation.

**Confidential seal.** A network-tier database holding sensitive data can carry a `ConfidentialSeal`: an encryption-at-rest envelope with one wrapped data key per authorized DID (`hpke-x25519-hkdf-sha256-aes-256-gcm`). The crate records the wrapped-key envelopes; the node/client layer does the crypto. This is opt-in on top of the always-on access policy, not a replacement for it — the layered model is: capability gate for every tier, encryption-at-rest for sensitive network data.

---

## 6. Managed connections

A developer uses a Tenzro database the way they use a hosted one — they get a credential scoped to that database and dial queries with it.

`tenzro_issueDatabaseConnection` mints the credential. The caller must be the owner (or hold the write-action capability). Params: `{database_id, caller_did, bearer_did?, write?, ttl_secs?, capability?, envelope?}`. It returns an AAP capability token pinned to that single database (`allowed_resources: [database_id]`), a `mode` of `read_only` or `read_write`, the read/write actions, a TTL, and the `query_method` to call. `bearer_did` defaults to the caller — an owner can issue a read-only connection to another DID.

`tenzro_databaseQuery` runs an engine-dialect query. Params: `{database_id, caller_did, body, partition_index?, write?, consistency?, capability?, envelope?, payment_credential?}`. `consistency` is the write acknowledgement level — `quorum` (default: a majority of the partition's holders acknowledge) or `all` (every holder acknowledges); it is ignored on the read path. `body` is the engine's own query payload — `{sql, params}` for Postgres, a `{op, ...}` vector search for Qdrant or Lance, a `{op, ...}` full-text search for Tantivy, a `{command: [...]}` for Valkey. The node gates the call, then:

- If this node holds the target partition, it dispatches `body` to the engine driver and returns the result.
- If it does not, it returns the holder endpoints for that partition so the caller reaches one that does. There is no silent local execution against a partition this node does not hold.

---

## 7. Per-query pricing and usage metering

A database owner can charge non-owner callers per query. The descriptor carries a `pricing` object — `{asset_id, price_per_query}` where `price_per_query` is in the asset's base units (a decimal string in JSON, since u128 exceeds JSON's safe-integer range). The default is free (`price_per_query: 0`); the owner always queries free regardless of price.

**402 flow.** A priced query from a non-owner without a `payment_credential` is rejected with JSON-RPC error `-32402` whose `data` carries an x402 payment challenge for the resource `tenzro://db/<database_id>/query`, priced at `price_per_query` and payable to the owner's wallet. The caller settles the challenge and retries the same query with `payment_credential` set; the serving node verifies the credential against the challenge (resource, amount, recipient) and settles it before the engine runs. Only the node that actually serves the partition bills — a routing response (holder endpoints) is never charged.

**Metering.** Every served query is recorded in a per-database usage meter: query count, write count, request/response bytes, cumulative billed amount, and last-query timestamp. Counters persist in RocksDB (`CF_DATABASES / usage/<database_id>`) and survive restarts; dropping a database removes its counters. `tenzro_databaseUsage` reads them — administrative, gated on the admin action like rescale and drop. Params: `{database_id, caller_did, capability?, envelope?}`; returns `{database_id, pricing, usage}` where `usage` is null until the first query is served.

---

## 8. Elastic rescale

`tenzro_rescaleDatabase` grows or shrinks a database along the continuum in place. It is administrative — the caller passes the owner DID (or a write-action capability). Params: `{database_id, caller_did, placement, partitions?, replication?, capability?, envelope?}` — `replication` is the `{min_replication, max_replication}` policy object, kept at the database's current policy when omitted. It recomputes placement over the current cluster candidates and rewrites the partition rows; a network-tier result is re-gossiped so peers converge on the new shape.

A database created `local` with one partition can be rescaled to `lan_cluster` and then `network` with more partitions and a wider replication policy as demand grows — without recreating it or moving the developer's connection.

---

## 9. Two-sided model

Databases mirror the two-sided model of the rest of the network. A developer can run engines on their own machine or LAN cluster and serve data from there, or place a database across network holders and query it over the network — the same descriptor, the same connection credential, the same query method for both. One node's stake and one set of obligations back everything it holds across compute, file storage, and databases at once.

---

## 10. Reaching a database

Three surfaces, one gate. REST, JSON-RPC and the MCP tools all end up in the same handler, so the access-policy adjudication, the capability check and the engine routing are the same code on every path — a REST route cannot become a way around a check the RPC path enforces.

### Authentication: two ways to prove a caller DID

Every operation is adjudicated against a `caller_did`, and the node will not take that field on trust. There are exactly two ways to establish it:

1. **A signed DID envelope** (`envelope`), binding the DID, the method, and a hash of these specific parameters. This is the node-to-node path: a caller legitimately speaking for someone else proves it.
2. **A `database`-scoped API key whose `subject` is the claimed caller.** The node minted that key, recorded the subject on it, and compares the presented value constant-time against its own store — so it is not the weaker assertion. It exists because requiring an envelope would mean the only callers able to use a managed database are those already carrying Tenzro identity keys, which excludes every application developer holding a `tnz_...` key.

The scope check is what keeps the second path honest: a key issued for inference names a subject too, and that subject must not thereby become an authenticated database caller.

A caller with neither gets a pass only from a `public` policy's read path, which grants nothing identity-based.

### `/v1/databases` (REST)

| Route | Does |
|---|---|
| `GET /v1/databases/engines` | the engine catalog |
| `POST /v1/databases` | create |
| `GET /v1/databases` | list |
| `GET /v1/databases/{id}` | read a descriptor |
| `DELETE /v1/databases/{id}` | drop |
| `GET /v1/databases/{id}/partitions` | partition placements |
| `POST /v1/databases/{id}/query` | engine-dialect query |
| `POST /v1/databases/{id}/rescale` | rescale in place |
| `POST /v1/databases/{id}/connections` | mint a connection credential |
| `GET /v1/databases/{id}/usage` | pricing and usage counters |

On this surface `caller_did` is **derived** from the presented key's subject, and any value in the request body is overwritten. So is `owner_did` on create — and so, on create, is a supplied `access_policy` checked to be owned by the caller, because `tenzro_createDatabase` reads a full policy's own owner and never looks at the top-level `owner_did`. A body carrying `{"access_policy": {"kind": "owner_only", "owner_did": "<someone else>"}}` is refused rather than silently corrected: it is not a shape question, it is an attempt, and rewriting it would hide that from whoever reads the logs.

`GET /v1/databases/engines` is the one route that needs no key. It reports which engines this operator wired up — node capability advertisement, the same class of fact as `/v1/models` — and gating it would mean a caller cannot discover what a node offers without first being issued a key by its operator, which defeats network-level resource discovery.

### MCP

All twelve operations are exposed as MCP tools, dispatching through the same JSON-RPC layer with the caller's `X-Tenzro-Api-Key` forwarded, so an agent with a tool list and no HTTP client reaches the same surface under the same gate.

## 10.1. RPC surface

| RPC | Purpose |
|-----|---------|
| `tenzro_listDatabaseEngines` | Return the engine catalog (data models, versions, images, licenses, cluster roles) |
| `tenzro_createDatabase` | Create a database from a descriptor (optional `pricing`); returns the normalized descriptor and its partition placements |
| `tenzro_getDatabase` | Read a database descriptor |
| `tenzro_listDatabases` | List databases |
| `tenzro_listDatabasePartitions` | List a database's partition placements |
| `tenzro_getDatabasePartition` | Read one partition placement (holders) |
| `tenzro_authorizeDatabaseRead` | Adjudicate whether a caller may read (gate check without a query; accepts `envelope`) |
| `tenzro_issueDatabaseConnection` | Mint a per-database connection credential (managed-DB auth; accepts `envelope`) |
| `tenzro_databaseQuery` | Run an engine-dialect query against a partition (accepts `envelope`, `payment_credential`) |
| `tenzro_rescaleDatabase` | Grow/shrink placement along local → LAN → network in place (accepts `envelope`) |
| `tenzro_dropDatabase` | Drop a database (admin-gated on `caller_did`; removes its usage counters) |
| `tenzro_databaseUsage` | Read per-query pricing and cumulative usage counters (admin-gated on `caller_did`) |

## 11. CLI

```
tenzro database engines
tenzro database create <id> --engine <engine> --owner-did <did> \
  [--placement <local|lan_cluster|network>] [--partitions <n>] \
  [--min-replication <n>] [--max-replication <n>] \
  [--engine-config <file.json>] [--access-policy <file.json>] [--confidential <file.json>] \
  [--price-per-query <amount>] [--asset <asset>]
tenzro database get <id>
tenzro database list
tenzro database partitions <id>
tenzro database connect <id> --caller-did <did> [--bearer-did <did>] [--write] \
  [--ttl-secs <secs>] [--capability <jwt>] [--envelope <hex>]
tenzro database query <id> --caller-did <did> --body <file.json> [--partition <n>] [--write] \
  [--consistency <quorum|all>] [--capability <jwt>] [--envelope <hex>] \
  [--payment-credential <file.json>]
tenzro database authorize <id> --caller-did <did> [--capability <jwt>] [--envelope <hex>]
tenzro database rescale <id> --caller-did <did> --placement <mode> [--partitions <n>] \
  [--min-replication <n> --max-replication <n>] [--capability <jwt>] [--envelope <hex>]
tenzro database usage <id> --caller-did <did> [--capability <jwt>] [--envelope <hex>]
tenzro database drop <id> --caller-did <did> [--capability <jwt>] [--envelope <hex>]
```

Every subcommand takes `--api-key` (falling back to `TENZRO_API_KEY`). It is surfaced per subcommand rather than left to the environment because the key's subject *is* the caller DID: a command run with the wrong key does not fail closed with a clear error, it succeeds as somebody else.
