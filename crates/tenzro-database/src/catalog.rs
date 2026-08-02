//! Engine catalog: the database engines a Tenzro node can spin up.
//!
//! Every engine here is verified free of the SSPL / RSALv2 family of
//! source-available-but-not-open licenses. Two shapes exist:
//!
//! - **External-process engines** ([`EngineKind::ExternalProcess`]) — a
//!   separate server binary the node orchestrates (Postgres, Qdrant, Valkey).
//!   These support both local single-node serving and network sharding.
//! - **Embedded engines** ([`EngineKind::Embedded`]) — linked into the node
//!   process (Lance vector store, Tantivy BM25 index). Local-only: an embedded
//!   engine holds one partition, so a "sharded" embedded database is expressed
//!   as many single-partition embedded databases placed across members.
//!
//! The version/image pins are the canonical facts to render into operator docs
//! and to hand a runtime that shells out to the engine. The protocol layer
//! never links the engine itself — it records *which* engine a database uses
//! and leaves the spin-up to a [`crate::runtime`] backend.

use serde::{Deserialize, Serialize};

/// A queryable data model an engine exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataModel {
    /// Relational (SQL) tables.
    Relational,
    /// Approximate-nearest-neighbour vector search.
    Vector,
    /// Full-text (BM25 / inverted-index) search.
    FullText,
    /// Key-value / cache.
    KeyValue,
    /// Property graph (openCypher).
    Graph,
}

/// How the engine runs relative to the node process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    /// A separate server process the node orchestrates.
    ExternalProcess,
    /// Linked into the node process; holds a single partition.
    Embedded,
}

/// How a single logical database is distributed across members. This is the
/// difference between Tenzro sharding *for* an engine and an engine that
/// shards *itself*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardingModel {
    /// Single node only — one instance holds the whole database (embedded
    /// engines, or an external engine run standalone). To spread data, Tenzro
    /// places many single-partition databases, each an independent instance.
    SingleNode,
    /// Tenzro orchestrates the sharding: it computes partition → member
    /// placement via tiered HRW and runs one independent single-node engine
    /// instance per member, each holding one Tenzro-assigned partition. The
    /// engine has no cross-instance awareness.
    TenzroOrchestrated,
    /// The engine clusters itself: it has its own coordinator/consensus and
    /// does its own sharding, replication, and rebalancing internally (Milvus
    /// compute/storage separation, Postgres/Citus, Valkey Cluster hash slots,
    /// Dgraph predicate groups). Tenzro places the engine's *own* cluster
    /// roles onto members and lets the engine cluster; it does not compute
    /// per-row partition placement.
    EngineNative,
}

/// A distinct process role in an engine's own distributed deployment. For an
/// [`ShardingModel::EngineNative`] engine, Tenzro places these roles onto
/// members and lets the engine self-shard; the role names are the engine's
/// own, so a runtime backend can select the role via the engine's per-role
/// launch flag/arg/subcommand.
///
/// This is the difference between Tenzro sharding *for* an engine (one
/// [`StandaloneShard`](ClusterRole::StandaloneShard) role, Tenzro-assigned
/// partitions) and placing the engine's *own* cluster roles and letting it
/// shard itself.
///
/// [`ClusterRole`]: crate::database::ClusterRole
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRole {
    /// Control-plane coordinator that holds cluster metadata and plans/routes
    /// queries but stores no shard data itself. Postgres/Citus coordinator,
    /// Dgraph Zero, Milvus MixCoord, a MongoDB-shape config/metadata role.
    Coordinator,
    /// Stateless request-entry / routing tier that fronts the data plane and
    /// holds no durable state. Milvus Proxy, a MongoDB-shape `mongos` router.
    Router,
    /// Data-plane worker that stores shard data and executes query fragments.
    /// Postgres/Citus worker, Dgraph Alpha, a shard replica-set member.
    Worker,
    /// Primary of a data shard: owns writes for its slot/key range and
    /// replicates to its replicas. Valkey Cluster primary.
    Primary,
    /// Read replica / hot standby of a primary, promotable on primary failure.
    /// Valkey Cluster replica, a Postgres streaming standby.
    Replica,
    /// Ingest/streaming node that consumes the write-ahead log and owns
    /// growing (real-time) segments. Milvus streaming node.
    StreamNode,
    /// Query-serving node that loads sealed/historical segments and answers
    /// batch search. Milvus query node.
    QueryNode,
    /// Offline data node: compaction, index building, flush to object storage.
    /// Milvus data node.
    DataNode,
}

impl NativeRole {
    /// Whether this role is control-plane (coordination/routing, no durable
    /// shard data) rather than data-plane.
    pub fn is_control_plane(&self) -> bool {
        matches!(self, NativeRole::Coordinator | NativeRole::Router)
    }
}

/// One role slot in an engine's native cluster: the role and how many members
/// carry it for a minimum highly-available deployment. A runtime backend scales
/// each slot up from `min_count` as the placed member set grows, but never
/// below it — below the minimum the engine's own cluster refuses to form
/// (Valkey's 3-primary floor, Dgraph's Raft quorum, an odd Zero count).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeRoleSlot {
    /// The engine's own role for this slot.
    pub role: NativeRole,
    /// Members that must carry this role for a real HA cluster.
    pub min_count: usize,
}

/// A backing service an [`ShardingModel::EngineNative`] cluster needs alongside
/// its own roles — durable state the engine does not hold in its role processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalDependency {
    /// A metadata/coordination store (etcd) for service discovery + config.
    MetadataStore,
    /// Object storage (S3 / MinIO) for durable segment + index persistence.
    ObjectStore,
    /// A write-ahead-log / message backend (Milvus Woodpecker default, or
    /// Pulsar/Kafka) carrying the streaming log.
    WriteAheadLog,
    /// A distributed configuration store for HA leader election (etcd/Consul/
    /// ZooKeeper) used by a Patroni-style supervisor, distinct from the
    /// engine's own metadata.
    LeaderElection,
}

/// The native-cluster topology of an [`ShardingModel::EngineNative`] engine:
/// the typed roles Tenzro places onto members and the backing services the
/// cluster needs. `None` on the [`EngineEntry`] for engines that are not
/// engine-native (Tenzro-orchestrated or single-node).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeClusterSpec {
    /// The role slots this engine's cluster runs, each with its HA minimum.
    pub roles: Vec<NativeRoleSlot>,
    /// Backing services the cluster needs beyond its own role processes.
    pub external_dependencies: Vec<ExternalDependency>,
}

impl NativeClusterSpec {
    /// The smallest member count a real HA cluster of this engine needs — the
    /// sum of every role slot's `min_count`. A member may co-locate multiple
    /// roles, so this is a data-plane sizing hint, not a hard host floor.
    pub fn min_members(&self) -> usize {
        self.roles.iter().map(|s| s.min_count).sum()
    }

    /// Whether this engine's cluster carries a stateless routing tier
    /// ([`NativeRole::Router`]) in front of its data plane.
    pub fn has_router_tier(&self) -> bool {
        self.roles.iter().any(|s| s.role == NativeRole::Router)
    }
}

/// A catalog entry: an engine plus the facts needed to spin it up and to
/// render it into operator documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineEntry {
    /// Stable catalog id (kebab-case, Tenzro-owned, no version segment).
    pub id: String,
    /// Human-facing engine name.
    pub name: String,
    /// How the engine runs relative to the node.
    pub kind: EngineKind,
    /// Data models this engine can serve.
    pub data_models: Vec<DataModel>,
    /// Pinned upstream version (web-verified, SSPL-free).
    pub version: String,
    /// Container image reference for external-process engines; `None` for
    /// embedded engines (they ship in the node binary).
    pub image: Option<String>,
    /// Upstream license identifier (SPDX where one exists).
    pub license: String,
    /// Whether the engine can shard a single logical database across multiple
    /// network members. Embedded engines are false — each embedded instance is
    /// one partition.
    pub network_shardable: bool,
    /// How a single logical database on this engine is distributed. Decides
    /// whether Tenzro computes per-partition placement itself
    /// ([`ShardingModel::TenzroOrchestrated`]) or places the engine's own
    /// cluster roles and lets the engine self-shard
    /// ([`ShardingModel::EngineNative`]).
    pub sharding: ShardingModel,
    /// The engine's native cluster topology when it self-clusters
    /// ([`ShardingModel::EngineNative`]) — the typed roles Tenzro places onto
    /// members and the backing services the cluster needs. `None` for
    /// Tenzro-orchestrated and single-node engines, which carry no engine-owned
    /// cluster roles.
    pub native_cluster: Option<NativeClusterSpec>,
}

impl EngineEntry {
    /// Whether this engine clusters itself (has its own coordinator, sharding,
    /// and replication). When true, Tenzro places the engine's cluster roles
    /// onto members rather than computing per-partition HRW placement.
    pub fn is_engine_native_cluster(&self) -> bool {
        self.sharding == ShardingModel::EngineNative
    }
}

/// Catalog id constants — the single source of truth for engine ids across the
/// registry, RPC, and CLI.
pub mod engine_ids {
    /// Postgres 18 + pgvector / pgvectorscale + Apache AGE.
    pub const POSTGRES: &str = "postgres";
    /// Qdrant dedicated vector database (stateful, local/LAN tier).
    pub const QDRANT: &str = "qdrant";
    /// Milvus distributed vector database (compute/storage separation, network tier).
    pub const MILVUS: &str = "milvus";
    /// Valkey key-value / cache.
    pub const VALKEY: &str = "valkey";
    /// Dgraph natively-distributed graph database (network-shardable graph tier).
    pub const DGRAPH: &str = "dgraph";
    /// Embedded Lance vector store.
    pub const LANCE: &str = "lance";
    /// Embedded Tantivy BM25 full-text index.
    pub const TANTIVY: &str = "tantivy";
}

/// The full engine catalog. Version/image/license pins are web-verified as of
/// the last catalog review — update them from canonical sources, never from
/// training-data recall.
pub fn engine_catalog() -> Vec<EngineEntry> {
    use engine_ids::*;
    vec![
        EngineEntry {
            id: POSTGRES.to_string(),
            name: "PostgreSQL".to_string(),
            kind: EngineKind::ExternalProcess,
            // Postgres carries relational natively, vector via pgvector, graph
            // via Apache AGE (openCypher-on-Postgres) — all riding one engine.
            data_models: vec![DataModel::Relational, DataModel::Vector, DataModel::Graph],
            version: "18.4".to_string(),
            image: Some("postgres:18-alpine".to_string()),
            license: "PostgreSQL".to_string(),
            network_shardable: true,
            // Citus distributed sharding + streaming/logical replication are
            // Postgres's own cluster fabric; Tenzro places coordinator +
            // worker roles, not per-row partitions.
            sharding: ShardingModel::EngineNative,
            // Citus: one coordinator (holds metadata, routes) + hash-sharded
            // workers. HA doubles each role via streaming standbys, with a
            // Patroni-style supervisor needing a leader-election DCS.
            native_cluster: Some(NativeClusterSpec {
                roles: vec![
                    NativeRoleSlot {
                        role: NativeRole::Coordinator,
                        min_count: 1,
                    },
                    NativeRoleSlot {
                        role: NativeRole::Worker,
                        min_count: 2,
                    },
                    NativeRoleSlot {
                        role: NativeRole::Replica,
                        min_count: 1,
                    },
                ],
                external_dependencies: vec![ExternalDependency::LeaderElection],
            }),
        },
        EngineEntry {
            id: QDRANT.to_string(),
            name: "Qdrant".to_string(),
            kind: EngineKind::ExternalProcess,
            data_models: vec![DataModel::Vector],
            version: "1.18.2".to_string(),
            image: Some("qdrant/qdrant:v1.18.2".to_string()),
            license: "Apache-2.0".to_string(),
            network_shardable: true,
            // Qdrant is stateful single-node in the local/LAN tier: Tenzro
            // shards for it by placing independent instances per partition.
            // (Qdrant's own distributed mode exists but the network vector
            // tier routes to Milvus, which separates compute from storage.)
            sharding: ShardingModel::TenzroOrchestrated,
            // Tenzro-orchestrated: no engine-owned cluster roles — each member
            // runs a standalone instance holding one Tenzro-assigned partition.
            native_cluster: None,
        },
        EngineEntry {
            id: MILVUS.to_string(),
            name: "Milvus".to_string(),
            kind: EngineKind::ExternalProcess,
            data_models: vec![DataModel::Vector],
            version: "2.6.19".to_string(),
            image: Some("milvusdb/milvus:v2.6.19".to_string()),
            license: "Apache-2.0".to_string(),
            network_shardable: true,
            // Milvus separates compute from storage and does its own
            // sharding/replication over object storage; Tenzro places its
            // coordinator + query/data/index node roles onto members.
            sharding: ShardingModel::EngineNative,
            // Milvus 2.6: MixCoord (merged root/query/data coord) + stateless
            // Proxy + StreamNode (WAL/growing segments) + QueryNode (sealed
            // segments) + DataNode (compaction/index/flush). Durability lives
            // in etcd + object storage + the WAL backend, not the role procs.
            native_cluster: Some(NativeClusterSpec {
                roles: vec![
                    NativeRoleSlot {
                        role: NativeRole::Coordinator,
                        min_count: 1,
                    },
                    NativeRoleSlot {
                        role: NativeRole::Router,
                        min_count: 2,
                    },
                    NativeRoleSlot {
                        role: NativeRole::StreamNode,
                        min_count: 2,
                    },
                    NativeRoleSlot {
                        role: NativeRole::QueryNode,
                        min_count: 2,
                    },
                    NativeRoleSlot {
                        role: NativeRole::DataNode,
                        min_count: 2,
                    },
                ],
                external_dependencies: vec![
                    ExternalDependency::MetadataStore,
                    ExternalDependency::ObjectStore,
                    ExternalDependency::WriteAheadLog,
                ],
            }),
        },
        EngineEntry {
            id: VALKEY.to_string(),
            name: "Valkey".to_string(),
            kind: EngineKind::ExternalProcess,
            data_models: vec![DataModel::KeyValue],
            version: "9.1.0".to_string(),
            image: Some("valkey/valkey:9.1-alpine".to_string()),
            license: "BSD-3-Clause".to_string(),
            network_shardable: true,
            // Valkey Cluster distributes keys over 16,384 hash slots with its
            // own gossip + replica failover; Tenzro places primary + replica
            // roles onto members and lets the cluster own slot assignment.
            sharding: ShardingModel::EngineNative,
            // Valkey Cluster: 3-primary floor (below which the slot space
            // cannot form) + one replica each for failover. No external
            // coordinator — slot ownership + failover are gossip-emergent.
            native_cluster: Some(NativeClusterSpec {
                roles: vec![
                    NativeRoleSlot {
                        role: NativeRole::Primary,
                        min_count: 3,
                    },
                    NativeRoleSlot {
                        role: NativeRole::Replica,
                        min_count: 3,
                    },
                ],
                external_dependencies: vec![],
            }),
        },
        EngineEntry {
            id: DGRAPH.to_string(),
            name: "Dgraph".to_string(),
            kind: EngineKind::ExternalProcess,
            data_models: vec![DataModel::Graph],
            version: "25.3.8".to_string(),
            image: Some("dgraph/dgraph:v25.3.8".to_string()),
            license: "Apache-2.0".to_string(),
            network_shardable: true,
            // Dgraph shards predicates across Raft groups internally; Tenzro
            // places zero + alpha-group roles onto members.
            sharding: ShardingModel::EngineNative,
            // Dgraph: Zero (control plane — membership, predicate assignment,
            // txn oracle, rebalancing) forms a Raft group; Alpha (data)
            // predicate-shards into Raft groups. 3 Zeros + 3 Alphas
            // (--replicas=3) is the smallest quorum-safe HA cluster. Zero
            // replaces any external coordinator, so no backing services.
            native_cluster: Some(NativeClusterSpec {
                roles: vec![
                    NativeRoleSlot {
                        role: NativeRole::Coordinator,
                        min_count: 3,
                    },
                    NativeRoleSlot {
                        role: NativeRole::Worker,
                        min_count: 3,
                    },
                ],
                external_dependencies: vec![],
            }),
        },
        EngineEntry {
            id: LANCE.to_string(),
            name: "Lance".to_string(),
            kind: EngineKind::Embedded,
            data_models: vec![DataModel::Vector],
            version: "8.0.0".to_string(),
            image: None,
            license: "Apache-2.0".to_string(),
            network_shardable: false,
            sharding: ShardingModel::SingleNode,
            // Embedded: one in-process partition, no cluster roles.
            native_cluster: None,
        },
        EngineEntry {
            id: TANTIVY.to_string(),
            name: "Tantivy".to_string(),
            kind: EngineKind::Embedded,
            data_models: vec![DataModel::FullText],
            version: "0.26.1".to_string(),
            image: None,
            license: "MIT".to_string(),
            network_shardable: false,
            sharding: ShardingModel::SingleNode,
            // Embedded: one in-process partition, no cluster roles.
            native_cluster: None,
        },
    ]
}

/// Look up a single engine entry by catalog id.
pub fn engine_by_id(id: &str) -> Option<EngineEntry> {
    engine_catalog().into_iter().find(|e| e.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_are_unique() {
        let cat = engine_catalog();
        let mut ids: Vec<&str> = cat.iter().map(|e| e.id.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n, "duplicate engine id in catalog");
    }

    #[test]
    fn embedded_engines_are_not_network_shardable() {
        for e in engine_catalog() {
            if e.kind == EngineKind::Embedded {
                assert!(!e.network_shardable, "{} embedded but shardable", e.id);
                assert!(e.image.is_none(), "{} embedded but has image", e.id);
            }
        }
    }

    #[test]
    fn external_engines_have_images() {
        for e in engine_catalog() {
            if e.kind == EngineKind::ExternalProcess {
                assert!(e.image.is_some(), "{} external but no image", e.id);
                assert!(e.network_shardable, "{} external but not shardable", e.id);
            }
        }
    }

    #[test]
    fn no_sspl_family_licenses() {
        // Guardrail: the SSPL / RSALv2 / non-OSI-commercial family is banned.
        for e in engine_catalog() {
            let l = e.license.to_ascii_lowercase();
            assert!(!l.contains("sspl"), "{} has SSPL license", e.id);
            assert!(!l.contains("rsal"), "{} has RSALv2 license", e.id);
        }
    }

    #[test]
    fn lookup_hits_and_misses() {
        assert!(engine_by_id(engine_ids::POSTGRES).is_some());
        assert!(engine_by_id("mongodb").is_none());
    }

    #[test]
    fn embedded_engines_are_single_node() {
        for e in engine_catalog() {
            if e.kind == EngineKind::Embedded {
                assert_eq!(
                    e.sharding,
                    ShardingModel::SingleNode,
                    "{} embedded but not single-node",
                    e.id
                );
            }
        }
    }

    #[test]
    fn single_node_engines_are_not_network_shardable() {
        // A single-node engine cannot host one logical database across members;
        // spreading it is many independent single-partition databases.
        for e in engine_catalog() {
            if e.sharding == ShardingModel::SingleNode {
                assert!(!e.network_shardable, "{} single-node but shardable", e.id);
            }
        }
    }

    #[test]
    fn engine_native_clusters_are_network_shardable() {
        for e in engine_catalog() {
            if e.is_engine_native_cluster() {
                assert!(
                    e.network_shardable,
                    "{} native cluster but not shardable",
                    e.id
                );
            }
        }
    }

    #[test]
    fn native_cluster_spec_matches_sharding_model() {
        // Exactly the engine-native engines carry a native cluster spec; the
        // others carry none.
        for e in engine_catalog() {
            if e.sharding == ShardingModel::EngineNative {
                assert!(e.native_cluster.is_some(), "{} native but no spec", e.id);
            } else {
                assert!(
                    e.native_cluster.is_none(),
                    "{} non-native but has spec",
                    e.id
                );
            }
        }
    }

    #[test]
    fn every_native_cluster_has_a_data_owning_control_or_primary() {
        // A native cluster must place at least one role that owns writes — a
        // coordinator (Citus/Dgraph/Milvus) or a primary (Valkey). A router-only
        // or worker-only spec would be a mis-modelled topology.
        for e in engine_catalog() {
            let Some(spec) = e.native_cluster.as_ref() else {
                continue;
            };
            assert!(
                !spec.roles.is_empty(),
                "{} native cluster with no roles",
                e.id
            );
            let has_anchor = spec
                .roles
                .iter()
                .any(|s| matches!(s.role, NativeRole::Coordinator | NativeRole::Primary));
            assert!(
                has_anchor,
                "{} native cluster with no coordinator/primary",
                e.id
            );
            // Every role slot needs a positive HA minimum.
            for s in &spec.roles {
                assert!(s.min_count >= 1, "{} role {:?} min_count 0", e.id, s.role);
            }
        }
    }

    #[test]
    fn milvus_declares_its_three_backing_services() {
        let m = engine_by_id(engine_ids::MILVUS).unwrap();
        let spec = m.native_cluster.unwrap();
        assert!(
            spec.external_dependencies
                .contains(&ExternalDependency::MetadataStore)
        );
        assert!(
            spec.external_dependencies
                .contains(&ExternalDependency::ObjectStore)
        );
        assert!(
            spec.external_dependencies
                .contains(&ExternalDependency::WriteAheadLog)
        );
        assert!(spec.has_router_tier(), "milvus proxy is a router tier");
    }

    #[test]
    fn valkey_and_dgraph_need_no_backing_services() {
        for id in [engine_ids::VALKEY, engine_ids::DGRAPH] {
            let spec = engine_by_id(id).unwrap().native_cluster.unwrap();
            assert!(
                spec.external_dependencies.is_empty(),
                "{id} should self-coordinate with no backing services"
            );
        }
    }
}
