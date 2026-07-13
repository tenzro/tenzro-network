//! Distributed database layer for Tenzro Network.
//!
//! A node can serve a queryable database on its own machine, across its own
//! local-network segment, or sharded across the wider network — the same
//! local-machine → LAN-cluster → network progression the model-serving and
//! storage tiers use. This crate owns the protocol/registry layer only; it is
//! engine-agnostic and links no engine driver.
//!
//! # Layers
//!
//! - [`catalog`] — the engines a node can spin up (Postgres, Qdrant, Milvus,
//!   Dgraph, Valkey, embedded Lance and Tantivy), each with its data models,
//!   license, whether it can shard across the network, and how it distributes
//!   ([`catalog::ShardingModel`]): engines with their own cluster fabric
//!   (Milvus, Postgres/Citus, Valkey Cluster, Dgraph) are placed as native
//!   cluster members; single-node engines are sharded by Tenzro. Every entry
//!   is verified free of the SSPL / RSALv2 source-available family.
//! - [`placement`] — rendezvous (HRW) partition placement over the network
//!   tier, pinned to the database domain so it never collides with storage-shard
//!   placement over the same member ids. Wraps the local-first
//!   [`tenzro_cluster::tiered`] primitive.
//! - [`database`] — [`DatabaseDescriptor`], [`PlacementMode`], the per-partition
//!   [`ReplicationPolicy`] (floor/ceiling on distinct holders, placement fails
//!   closed below the floor), and the write-through [`DatabaseRegistry`] that
//!   persists descriptors and their partition placements to `CF_DATABASES`,
//!   hydrates them on boot, and reports replication health via
//!   `under_replicated` / `plan_repair` / `record_repair`.
//! - [`access_control`] — the [`AccessPolicy`] every descriptor carries (who may
//!   read and administer it, enforced identically across all three tiers) and an
//!   opt-in [`ConfidentialSeal`] that encrypts network-tier data with a data key
//!   wrapped once per authorized DID. This crate records the policy and the
//!   wrapped-key envelopes; a node layer that links `tenzro-auth` and the crypto
//!   adjudicates capabilities and unwraps keys.
//! - [`pricing`] — the per-query [`DatabasePricing`] every descriptor carries
//!   and the write-through [`DatabaseUsageMeter`] a holder uses to count served
//!   queries and settled payments. The node layer gates the query path on the
//!   price via the payment gateway; the owner always queries free.
//! - [`runtime`] — the [`DatabaseEngine`] trait (the seam to node-layer backends
//!   that actually spin an engine up and run queries) and the [`QueryRouter`]
//!   that routes reads to one holder with deterministic failover and fans
//!   writes out under a [`WriteConsistency`] level. The registry tracks *what*
//!   exists and *where* its partitions land; the runtime backend does the rest.
//!
//! # Engine-agnostic split
//!
//! The registry never links Postgres/Qdrant/Valkey/Lance/Tantivy — mirroring the
//! tenzro-training Rust-protocol / external-engine split. A node constructs the
//! concrete [`DatabaseEngine`] backend (which links the driver), registers it
//! against an engine id, and dispatches [`runtime::PartitionHandle`]s to it.

#![deny(missing_docs)]

pub mod access_control;
pub mod catalog;
pub mod database;
pub mod engine_config;
pub mod error;
pub mod gossip;
pub mod placement;
pub mod pricing;
pub mod runtime;

pub use access_control::{
    AccessPolicy, ConfidentialSeal, WrappedDataKey, DEFAULT_READ_ACTION, DEFAULT_WRITE_ACTION,
    WRAP_ALG,
};
pub use catalog::{
    engine_by_id, engine_catalog, engine_ids, DataModel, EngineEntry, EngineKind,
    ExternalDependency, NativeClusterSpec, NativeRole, NativeRoleSlot, ShardingModel,
};
pub use database::{
    ClusterRole, DatabaseDescriptor, DatabaseRegistry, PartitionPlacement,
    PartitionReplicationStatus, PlacementMode, RepairAssignment, ReplicationPolicy,
};
pub use engine_config::{
    BackingServices, DgraphConfig, EmbeddedConfig, EmbeddedEngine, EngineConfig, MilvusConfig,
    PostgresConfig, QdrantConfig, ValkeyConfig,
};
pub use error::{DatabaseError, Result};
pub use gossip::{
    decode_for_topic, encode_registered, encode_rescaled, DatabaseGossipMessage, DATABASES_TOPIC,
};
pub use placement::{
    partition_key, select_holders, select_tiered_holders, should_replicate,
    should_replicate_tiered, MemberReachability, TieredCandidate, TieredHolders,
};
pub use pricing::{DatabasePricing, DatabaseUsageMeter, DatabaseUsageStats};
pub use runtime::{
    DatabaseEngine, HolderDispatch, PartitionHandle, PartitionHealth, QueryRequest,
    QueryResponse, QueryRouter, WriteConsistency, WriteReceipt,
};
