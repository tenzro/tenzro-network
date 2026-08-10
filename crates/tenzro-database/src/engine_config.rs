//! Customizable per-engine configuration.
//!
//! [`DatabaseDescriptor::engine_config`] is an opaque `serde_json::Value` the
//! registry never inspects — the seam that keeps the protocol layer
//! engine-agnostic. This module gives callers *typed* builders for that blob so
//! each engine's full native architecture is expressible: a Citus coordinator
//! host + shard-replication factor, Milvus's etcd / object-store / WAL
//! endpoints + per-collection replica count, Valkey's replicas-per-primary,
//! Dgraph's `--replicas` group size, a Qdrant collection's vector dimension, an
//! embedded engine's on-disk path.
//!
//! Each [`EngineConfig`] variant serializes to the JSON the node-layer
//! [`crate::runtime::DatabaseEngine`] backend reads when it spins the engine
//! up. The registry stores it verbatim; only the backend interprets it. That
//! keeps the customization surface open — a backend can read fields this module
//! does not model by round-tripping through `serde_json::Value` — while giving
//! the common knobs a checked, discoverable shape.
//!
//! [`DatabaseDescriptor::engine_config`]: crate::database::DatabaseDescriptor::engine_config

use serde::{Deserialize, Serialize};

use crate::catalog::engine_ids;

/// A typed, per-engine configuration that serializes into a descriptor's
/// opaque `engine_config`. Tagged by engine so a backend can dispatch on the
/// variant; extra engine-specific fields a caller needs beyond these live in
/// `extra` and pass through untouched.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "engine", rename_all = "snake_case")]
pub enum EngineConfig {
    /// PostgreSQL + Citus. `database`/`schema` name the logical database;
    /// `shard_replication_factor` sets Citus shard copies; `coordinator_host`
    /// pins the coordinator when a caller wants a specific member to hold it.
    Postgres(PostgresConfig),
    /// Qdrant collection: vector `dimension` + `distance` metric. Tenzro shards
    /// by placing one standalone instance per partition, so this is the
    /// per-instance collection shape.
    Qdrant(QdrantConfig),
    /// Milvus collection over its own cluster: vector `dimension` + `metric` +
    /// per-collection `replicas`, plus the three backing-service endpoints its
    /// cluster needs (etcd / object store / WAL).
    Milvus(MilvusConfig),
    /// Valkey Cluster: `replicas_per_primary` sets the failover fan-out; the
    /// 16384-slot map is the engine's own, so no per-key config here.
    Valkey(ValkeyConfig),
    /// Dgraph: `replicas` is the Alpha Raft-group size (odd: 1/3/5); `schema`
    /// is the optional DQL schema to install at create.
    Dgraph(DgraphConfig),
    /// An embedded engine (Lance / Tantivy): the on-disk `path` under the
    /// node's data dir and, for a vector store, the `dimension`.
    Embedded(EmbeddedConfig),
}

impl EngineConfig {
    /// The catalog engine id this config targets.
    pub fn engine_id(&self) -> &'static str {
        match self {
            EngineConfig::Postgres(_) => engine_ids::POSTGRES,
            EngineConfig::Qdrant(_) => engine_ids::QDRANT,
            EngineConfig::Milvus(_) => engine_ids::MILVUS,
            EngineConfig::Valkey(_) => engine_ids::VALKEY,
            EngineConfig::Dgraph(_) => engine_ids::DGRAPH,
            EngineConfig::Embedded(c) => c.engine_id(),
        }
    }

    /// Serializes to the opaque JSON a descriptor carries. Infallible for the
    /// modelled shapes (plain structs of scalars + a JSON `extra`).
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Backing-service endpoints an [`crate::catalog::ShardingModel::EngineNative`]
/// cluster with external dependencies needs. Empty when the deployment supplies
/// them out of band; a backend fails closed if a required endpoint is absent.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BackingServices {
    /// etcd endpoint(s) for the metadata / coordination store.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metadata_store: Vec<String>,
    /// Object-storage endpoint (S3 / MinIO) for durable segment persistence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_store: Option<String>,
    /// Object-storage bucket / namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_store_bucket: Option<String>,
    /// Write-ahead-log / message backend endpoint (Woodpecker / Pulsar / Kafka).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_ahead_log: Option<String>,
}

/// PostgreSQL + Citus config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostgresConfig {
    /// Logical database name.
    pub database: String,
    /// Schema to place tables in.
    #[serde(default = "default_public_schema")]
    pub schema: String,
    /// Citus shard copies per shard. 1 = no shard replication (rely on physical
    /// streaming standbys for HA); >1 = Citus keeps N shard placements.
    #[serde(default = "one")]
    pub shard_replication_factor: usize,
    /// Pin the coordinator to a specific member endpoint. `None` lets placement
    /// choose (the first coordinator-role holder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_host: Option<String>,
    /// Endpoint(s) of the leader-election DCS a Patroni-style supervisor uses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leader_election: Vec<String>,
    /// Passthrough for engine fields this struct does not model.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

/// Qdrant per-instance collection config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QdrantConfig {
    /// Collection name.
    pub collection: String,
    /// Vector dimension.
    pub dimension: usize,
    /// Distance metric (`cosine` / `dot` / `euclid`).
    #[serde(default = "default_cosine")]
    pub distance: String,
    /// Passthrough for engine fields this struct does not model.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

/// Milvus collection-over-cluster config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MilvusConfig {
    /// Collection name.
    pub collection: String,
    /// Vector dimension.
    pub dimension: usize,
    /// Similarity metric (`COSINE` / `IP` / `L2`).
    #[serde(default = "default_cosine_upper")]
    pub metric: String,
    /// Per-collection replica count the coordinator balances across query nodes.
    #[serde(default = "one")]
    pub replicas: usize,
    /// The three backing-service endpoints Milvus's cluster needs.
    #[serde(default)]
    pub backing: BackingServices,
    /// Passthrough for engine fields this struct does not model.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

/// Valkey Cluster config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValkeyConfig {
    /// Replicas per primary for failover. 1 = one replica each (the HA default).
    #[serde(default = "one")]
    pub replicas_per_primary: usize,
    /// Passthrough for engine fields this struct does not model.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

/// Dgraph config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DgraphConfig {
    /// Alpha Raft-group size (odd: 1/3/5). 3 is the smallest quorum-safe group.
    #[serde(default = "three")]
    pub replicas: usize,
    /// Optional DQL schema to install at create.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// Passthrough for engine fields this struct does not model.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

/// Embedded engine (Lance / Tantivy) config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbeddedConfig {
    /// Which embedded engine (`lance` or `tantivy`).
    pub embedded: EmbeddedEngine,
    /// On-disk path under the node's data dir.
    pub path: String,
    /// Vector dimension for a Lance store; ignored for Tantivy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimension: Option<usize>,
    /// Passthrough for engine fields this struct does not model.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

impl EmbeddedConfig {
    fn engine_id(&self) -> &'static str {
        match self.embedded {
            EmbeddedEngine::Lance => engine_ids::LANCE,
            EmbeddedEngine::Tantivy => engine_ids::TANTIVY,
        }
    }
}

/// Which embedded engine an [`EmbeddedConfig`] targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddedEngine {
    /// Lance embedded vector store.
    Lance,
    /// Tantivy embedded BM25 index.
    Tantivy,
}

fn default_public_schema() -> String {
    "public".to_string()
}
fn default_cosine() -> String {
    "cosine".to_string()
}
fn default_cosine_upper() -> String {
    "COSINE".to_string()
}
fn one() -> usize {
    1
}
fn three() -> usize {
    3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_variant_reports_its_engine_id() {
        let cfgs = [
            EngineConfig::Postgres(PostgresConfig {
                database: "app".into(),
                schema: "public".into(),
                shard_replication_factor: 1,
                coordinator_host: None,
                leader_election: vec![],
                extra: serde_json::Value::Null,
            }),
            EngineConfig::Qdrant(QdrantConfig {
                collection: "docs".into(),
                dimension: 768,
                distance: "cosine".into(),
                extra: serde_json::Value::Null,
            }),
            EngineConfig::Milvus(MilvusConfig {
                collection: "docs".into(),
                dimension: 1024,
                metric: "COSINE".into(),
                replicas: 2,
                backing: BackingServices::default(),
                extra: serde_json::Value::Null,
            }),
            EngineConfig::Valkey(ValkeyConfig {
                replicas_per_primary: 1,
                extra: serde_json::Value::Null,
            }),
            EngineConfig::Dgraph(DgraphConfig {
                replicas: 3,
                schema: None,
                extra: serde_json::Value::Null,
            }),
            EngineConfig::Embedded(EmbeddedConfig {
                embedded: EmbeddedEngine::Lance,
                path: "vec.lance".into(),
                dimension: Some(384),
                extra: serde_json::Value::Null,
            }),
        ];
        let ids: Vec<&str> = cfgs.iter().map(|c| c.engine_id()).collect();
        assert_eq!(
            ids,
            vec![
                engine_ids::POSTGRES,
                engine_ids::QDRANT,
                engine_ids::MILVUS,
                engine_ids::VALKEY,
                engine_ids::DGRAPH,
                engine_ids::LANCE,
            ]
        );
    }

    #[test]
    fn tantivy_embedded_reports_tantivy_id() {
        let c = EngineConfig::Embedded(EmbeddedConfig {
            embedded: EmbeddedEngine::Tantivy,
            path: "idx".into(),
            dimension: None,
            extra: serde_json::Value::Null,
        });
        assert_eq!(c.engine_id(), engine_ids::TANTIVY);
    }

    #[test]
    fn milvus_backing_services_round_trip() {
        let c = EngineConfig::Milvus(MilvusConfig {
            collection: "docs".into(),
            dimension: 1024,
            metric: "COSINE".into(),
            replicas: 2,
            backing: BackingServices {
                metadata_store: vec!["etcd:2379".into()],
                object_store: Some("minio:9000".into()),
                object_store_bucket: Some("milvus".into()),
                write_ahead_log: Some("woodpecker".into()),
            },
            extra: serde_json::json!({ "index_type": "HNSW" }),
        });
        let v = c.to_value();
        let back = serde_json::from_value::<EngineConfig>(v).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn config_serializes_with_engine_tag() {
        let c = EngineConfig::Dgraph(DgraphConfig {
            replicas: 3,
            schema: Some("name: string @index(exact) .".into()),
            extra: serde_json::Value::Null,
        });
        let v = c.to_value();
        assert_eq!(v["engine"], "dgraph");
        assert_eq!(v["replicas"], 3);
    }

    #[test]
    fn defaults_fill_when_absent() {
        // A Postgres config with only the required database name deserializes
        // with public schema + replication factor 1.
        let v = serde_json::json!({ "engine": "postgres", "database": "app" });
        let c: EngineConfig = serde_json::from_value(v).unwrap();
        match c {
            EngineConfig::Postgres(p) => {
                assert_eq!(p.schema, "public");
                assert_eq!(p.shard_replication_factor, 1);
            }
            _ => panic!("wrong variant"),
        }
    }
}
