//! Database descriptors, placement modes, and the write-through registry.
//!
//! A [`DatabaseDescriptor`] is the protocol-level record of one logical
//! database: which engine serves it, how it is placed relative to the node,
//! and — for network mode — how many partitions it carries and the
//! [`ReplicationPolicy`] every partition must satisfy. The
//! [`DatabaseRegistry`] persists descriptors and their computed partition
//! placements to `CF_DATABASES` and hydrates them on boot, so a node restores
//! every database it serves without a coordinator round.
//!
//! This layer is engine-agnostic: it never links Postgres/Qdrant/Valkey/Lance/
//! Tantivy. Spinning an engine up and routing queries to it is a
//! [`crate::runtime::DatabaseEngine`] backend concern. The registry only tracks
//! *what* exists and *where* its partitions land.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_storage::{KvStore, WriteOp, CF_DATABASES};

use crate::access_control::{AccessPolicy, ConfidentialSeal};
use crate::catalog::{engine_by_id, EngineKind, ShardingModel};
use crate::error::{DatabaseError, Result};
use crate::placement::{partition_key, select_tiered_holders, TieredCandidate};
use crate::pricing::DatabasePricing;

const DB_PREFIX: &[u8] = b"db/";
const PARTITION_PREFIX: &[u8] = b"partition/";

/// How a database is placed relative to the serving node — the same
/// local-machine → LAN-cluster → network progression the model and storage
/// tiers use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementMode {
    /// Served on this single machine. One partition, one holder (self). No
    /// network egress.
    Local,
    /// Served across the node's own local-network segment first, spilling onto
    /// the wider network only if the segment cannot meet the replica count.
    LanCluster,
    /// Sharded across the wider network by rendezvous placement.
    Network,
}

impl PlacementMode {
    /// The lower-case wire form, for error messages and RPC.
    pub fn as_str(&self) -> &'static str {
        match self {
            PlacementMode::Local => "local",
            PlacementMode::LanCluster => "lan_cluster",
            PlacementMode::Network => "network",
        }
    }
}

/// Replication floor and ceiling per partition — the same policy shape the
/// MoE expert-shard map uses. Placement fails closed when the membership view
/// cannot supply `min_replication` distinct holders; repair never grows a
/// holder set past `max_replication`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationPolicy {
    /// Every partition must be held by at least this many distinct providers.
    pub min_replication: u8,
    /// Hard ceiling on holders per partition.
    pub max_replication: u8,
}

impl Default for ReplicationPolicy {
    fn default() -> Self {
        Self { min_replication: 2, max_replication: 4 }
    }
}

/// The protocol-level record of one logical database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseDescriptor {
    /// Stable database id (caller-supplied or derived; unique in the registry).
    pub database_id: String,
    /// Catalog id of the engine that serves it (see [`crate::catalog`]).
    pub engine_id: String,
    /// Placement relative to the serving node.
    pub placement: PlacementMode,
    /// Number of partitions. Always 1 for `Local`; 1 for an embedded engine
    /// regardless of mode; `>= 1` for a network-sharded external engine.
    pub partitions: usize,
    /// Replication floor/ceiling per partition. Normalized to `{1, 1}` for
    /// `Local`.
    pub replication: ReplicationPolicy,
    /// Free-form engine-specific config the runtime backend interprets (schema
    /// name, vector dimension, collection name, …). Opaque to the registry.
    pub engine_config: serde_json::Value,
    /// Who may read and administer this database. Enforced identically across
    /// the local, LAN-cluster, and network tiers — a node layer adjudicates the
    /// caller's capability against it before touching the engine.
    pub access_policy: AccessPolicy,
    /// What non-owner callers pay per query. The node layer gates
    /// `tenzro_databaseQuery` on it via the payment gateway; the owner always
    /// queries free.
    pub pricing: DatabasePricing,
    /// Opt-in encryption-at-rest for the network tier: when set, holders store
    /// ciphertext and the data key is wrapped once per authorized DID. `None`
    /// for plaintext databases (all local/LAN databases and network databases
    /// that rely on the access policy alone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidential: Option<ConfidentialSeal>,
}

/// What a placed member runs for a partition — the difference between a member
/// holding a Tenzro-assigned shard standalone and a member joining the engine's
/// own cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterRole {
    /// The member runs a standalone engine instance holding exactly this
    /// Tenzro-assigned partition. Used for [`ShardingModel::TenzroOrchestrated`]
    /// and [`ShardingModel::SingleNode`].
    StandaloneShard,
    /// The member is one node of the engine's own cluster; the engine does its
    /// internal sharding/replication and Tenzro does not own per-row placement.
    /// Used for [`ShardingModel::EngineNative`]. `partition_index` names the
    /// engine's internal shard/group index Tenzro sized, not a Tenzro shard.
    NativeClusterMember,
}

/// The HRW-selected holders for one partition, split by tier so a caller can
/// see whether the partition stayed on-LAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionPlacement {
    /// Database this partition belongs to.
    pub database_id: String,
    /// Zero-based partition index.
    pub partition_index: usize,
    /// What placed members run for this partition — a standalone Tenzro shard
    /// or a node of the engine's own cluster.
    pub role: ClusterRole,
    /// Holders on the caller's local segment, HRW-ranked.
    pub local_holders: Vec<String>,
    /// Holders drawn from the wider network to top up the replica count.
    pub network_holders: Vec<String>,
}

impl PartitionPlacement {
    /// All holders, local tier first then network tier.
    pub fn all_holders(&self) -> Vec<String> {
        self.local_holders.iter().chain(self.network_holders.iter()).cloned().collect()
    }

    /// Distinct holders currently recorded for this partition.
    pub fn holder_count(&self) -> usize {
        self.local_holders.len() + self.network_holders.len()
    }
}

/// Replication health of one partition, as reported by
/// [`DatabaseRegistry::under_replicated`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionReplicationStatus {
    /// Zero-based partition index.
    pub partition_index: usize,
    /// Holders currently recorded.
    pub current: usize,
    /// Holders the database's [`ReplicationPolicy`] floor demands.
    pub required: usize,
    /// `required - current`.
    pub missing: usize,
}

/// One planned repair: copy the partition onto `new_holder`. Planning only —
/// executing the copy is a node-layer concern; the node records the outcome
/// via [`DatabaseRegistry::record_repair`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairAssignment {
    /// Zero-based partition index.
    pub partition_index: usize,
    /// Endpoint id of the provider to copy the partition onto.
    pub new_holder: String,
    /// Whether the new holder was drawn from the caller's local segment.
    pub local: bool,
}

/// Validates a descriptor against its engine's catalog constraints, normalizing
/// partition/replica counts for the placement mode.
fn validate_descriptor(mut desc: DatabaseDescriptor) -> Result<DatabaseDescriptor> {
    let engine = engine_by_id(&desc.engine_id)
        .ok_or_else(|| DatabaseError::UnknownEngine(desc.engine_id.clone()))?;

    // Every database has an owner; an unowned database has no admin authority
    // and could never be dropped or re-policied.
    if desc.access_policy.owner_did().is_empty() {
        return Err(DatabaseError::InvalidRequest(
            "access_policy owner_did must not be empty".to_string(),
        ));
    }

    // A priced database must name the asset the price settles in.
    if desc.pricing.asset_id.is_empty() {
        return Err(DatabaseError::InvalidRequest(
            "pricing asset_id must not be empty".to_string(),
        ));
    }

    match desc.placement {
        PlacementMode::Local => {
            // A local database is one partition, one holder (self).
            desc.partitions = 1;
            desc.replication = ReplicationPolicy { min_replication: 1, max_replication: 1 };
        }
        PlacementMode::LanCluster | PlacementMode::Network => {
            if engine.kind == EngineKind::Embedded && desc.partitions > 1 {
                // An embedded engine holds exactly one partition. Sharding an
                // embedded database is expressed as many single-partition
                // embedded databases, not one multi-partition one.
                return Err(DatabaseError::UnsupportedPlacement {
                    engine: desc.engine_id.clone(),
                    mode: desc.placement.as_str().to_string(),
                });
            }
            if desc.placement == PlacementMode::Network && !engine.network_shardable {
                return Err(DatabaseError::UnsupportedPlacement {
                    engine: desc.engine_id.clone(),
                    mode: desc.placement.as_str().to_string(),
                });
            }
            desc.partitions = desc.partitions.max(1);
            if desc.replication.min_replication == 0 {
                return Err(DatabaseError::InvalidRequest(
                    "min_replication must be >= 1".to_string(),
                ));
            }
            if desc.replication.max_replication < desc.replication.min_replication {
                return Err(DatabaseError::InvalidRequest(
                    "max_replication must be >= min_replication".to_string(),
                ));
            }
        }
    }
    Ok(desc)
}

/// Write-through registry of the databases a node serves.
///
/// Descriptors and their partition placements persist to `CF_DATABASES` and
/// hydrate on boot. In-memory reads are served from `DashMap`s; every mutation
/// writes through synchronously.
pub struct DatabaseRegistry {
    databases: DashMap<String, DatabaseDescriptor>,
    placements: DashMap<String, PartitionPlacement>,
    storage: Option<Arc<dyn KvStore>>,
}

impl DatabaseRegistry {
    /// An in-memory registry with no persistence. Use [`Self::with_storage`]
    /// for a durable one.
    pub fn new() -> Self {
        Self { databases: DashMap::new(), placements: DashMap::new(), storage: None }
    }

    /// A registry backed by `storage`, hydrating any previously-persisted
    /// descriptors and placements from `CF_DATABASES`.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let reg = Self {
            databases: DashMap::new(),
            placements: DashMap::new(),
            storage: Some(storage.clone()),
        };
        reg.hydrate()?;
        Ok(reg)
    }

    fn hydrate(&self) -> Result<()> {
        let Some(ref storage) = self.storage else { return Ok(()) };

        for (_, value) in storage
            .scan_prefix(CF_DATABASES, DB_PREFIX)
            .map_err(|e| DatabaseError::Persistence(e.to_string()))?
        {
            if let Ok(desc) = serde_json::from_slice::<DatabaseDescriptor>(&value) {
                self.databases.insert(desc.database_id.clone(), desc);
            }
        }
        for (_, value) in storage
            .scan_prefix(CF_DATABASES, PARTITION_PREFIX)
            .map_err(|e| DatabaseError::Persistence(e.to_string()))?
        {
            if let Ok(p) = serde_json::from_slice::<PartitionPlacement>(&value) {
                self.placements.insert(placement_map_key(&p.database_id, p.partition_index), p);
            }
        }
        Ok(())
    }

    fn db_storage_key(database_id: &str) -> Vec<u8> {
        let mut k = DB_PREFIX.to_vec();
        k.extend_from_slice(database_id.as_bytes());
        k
    }

    fn partition_storage_key(database_id: &str, partition_index: usize) -> Vec<u8> {
        let mut k = PARTITION_PREFIX.to_vec();
        k.extend_from_slice(format!("{database_id}/{partition_index}").as_bytes());
        k
    }

    /// Registers a new database, computing and persisting its partition
    /// placements. `candidates` is the caller's membership view (self plus every
    /// data-plane-eligible member it can see, each tagged with reachability);
    /// it is ignored for `Local` mode. Returns the normalized descriptor.
    pub fn create_database(
        &self,
        desc: DatabaseDescriptor,
        candidates: &[TieredCandidate],
    ) -> Result<DatabaseDescriptor> {
        let desc = validate_descriptor(desc)?;
        if self.databases.contains_key(&desc.database_id) {
            return Err(DatabaseError::DatabaseExists(desc.database_id.clone()));
        }

        let placements = self.compute_placements(&desc, candidates)?;

        let mut ops: Vec<WriteOp> = Vec::with_capacity(1 + placements.len());
        ops.push(WriteOp::Put {
            cf: CF_DATABASES.to_string(),
            key: Self::db_storage_key(&desc.database_id),
            value: serde_json::to_vec(&desc)
                .map_err(|e| DatabaseError::Persistence(e.to_string()))?,
        });
        for p in &placements {
            ops.push(WriteOp::Put {
                cf: CF_DATABASES.to_string(),
                key: Self::partition_storage_key(&p.database_id, p.partition_index),
                value: serde_json::to_vec(p)
                    .map_err(|e| DatabaseError::Persistence(e.to_string()))?,
            });
        }
        if let Some(ref storage) = self.storage {
            storage.write_batch_sync(ops).map_err(|e| DatabaseError::Persistence(e.to_string()))?;
        }

        self.databases.insert(desc.database_id.clone(), desc.clone());
        for p in placements {
            self.placements.insert(placement_map_key(&p.database_id, p.partition_index), p);
        }
        Ok(desc)
    }

    /// Computes the holder set for each partition of `desc`. `Local` mode places
    /// the single partition on self only; the tiered modes rank `candidates` by
    /// the database-domain HRW, local segment first.
    fn compute_placements(
        &self,
        desc: &DatabaseDescriptor,
        candidates: &[TieredCandidate],
    ) -> Result<Vec<PartitionPlacement>> {
        let role = match engine_by_id(&desc.engine_id) {
            Some(e) if e.sharding == ShardingModel::EngineNative => {
                ClusterRole::NativeClusterMember
            }
            _ => ClusterRole::StandaloneShard,
        };

        let mut out = Vec::with_capacity(desc.partitions);
        for idx in 0..desc.partitions {
            let placement = match desc.placement {
                PlacementMode::Local => PartitionPlacement {
                    database_id: desc.database_id.clone(),
                    partition_index: idx,
                    role: ClusterRole::StandaloneShard,
                    local_holders: vec![self_endpoint(candidates)],
                    network_holders: Vec::new(),
                },
                PlacementMode::LanCluster | PlacementMode::Network => {
                    let required = desc.replication.min_replication as usize;
                    let key = partition_key(&desc.database_id, idx);
                    let holders = select_tiered_holders(&key, candidates, required);
                    // Fail closed: an under-placed partition would silently
                    // carry less redundancy than the policy floor.
                    if holders.len() < required {
                        return Err(DatabaseError::InsufficientProviders {
                            database_id: desc.database_id.clone(),
                            partition_index: idx,
                            required,
                            available: holders.len(),
                        });
                    }
                    PartitionPlacement {
                        database_id: desc.database_id.clone(),
                        partition_index: idx,
                        role,
                        local_holders: holders.local,
                        network_holders: holders.network,
                    }
                }
            };
            out.push(placement);
        }
        Ok(out)
    }

    /// Looks up a database descriptor by id.
    pub fn get_database(&self, database_id: &str) -> Result<DatabaseDescriptor> {
        self.databases
            .get(database_id)
            .map(|r| r.value().clone())
            .ok_or_else(|| DatabaseError::DatabaseNotFound(database_id.to_string()))
    }

    /// Every registered database descriptor.
    pub fn list_databases(&self) -> Vec<DatabaseDescriptor> {
        self.databases.iter().map(|r| r.value().clone()).collect()
    }

    /// Idempotently records a descriptor learned from another node over the
    /// `tenzro/databases` gossip topic. Unlike [`create_database`], this does
    /// **not** recompute partition placement — the receiver is not a holder and
    /// the origin's descriptor is authoritative for the database's shape. It
    /// only persists and indexes the descriptor so passive observers can answer
    /// `tenzro_getDatabase` / `tenzro_listDatabases` without polling the origin.
    /// Re-receiving a descriptor already held with the same contents is a no-op.
    ///
    /// [`create_database`]: Self::create_database
    pub fn upsert_descriptor(&self, desc: DatabaseDescriptor) -> Result<()> {
        let desc = validate_descriptor(desc)?;
        if self.databases.get(&desc.database_id).is_some_and(|r| *r.value() == desc) {
            return Ok(());
        }
        if let Some(ref storage) = self.storage {
            storage
                .write_batch_sync(vec![WriteOp::Put {
                    cf: CF_DATABASES.to_string(),
                    key: Self::db_storage_key(&desc.database_id),
                    value: serde_json::to_vec(&desc)
                        .map_err(|e| DatabaseError::Persistence(e.to_string()))?,
                }])
                .map_err(|e| DatabaseError::Persistence(e.to_string()))?;
        }
        self.databases.insert(desc.database_id.clone(), desc);
        Ok(())
    }

    /// The placement of one partition of a database.
    pub fn get_partition(&self, database_id: &str, partition_index: usize) -> Result<PartitionPlacement> {
        self.placements
            .get(&placement_map_key(database_id, partition_index))
            .map(|r| r.value().clone())
            .ok_or_else(|| DatabaseError::PartitionNotFound {
                database_id: database_id.to_string(),
                partition_index,
            })
    }

    /// Every partition placement of a database, ordered by index.
    pub fn list_partitions(&self, database_id: &str) -> Vec<PartitionPlacement> {
        let mut out: Vec<PartitionPlacement> = self
            .placements
            .iter()
            .filter(|r| r.value().database_id == database_id)
            .map(|r| r.value().clone())
            .collect();
        out.sort_by_key(|p| p.partition_index);
        out
    }

    /// Removes a database and all its partition placements.
    pub fn drop_database(&self, database_id: &str) -> Result<()> {
        if !self.databases.contains_key(database_id) {
            return Err(DatabaseError::DatabaseNotFound(database_id.to_string()));
        }
        let partitions = self.list_partitions(database_id);

        let mut ops: Vec<WriteOp> = Vec::with_capacity(1 + partitions.len());
        ops.push(WriteOp::Delete {
            cf: CF_DATABASES.to_string(),
            key: Self::db_storage_key(database_id),
        });
        for p in &partitions {
            ops.push(WriteOp::Delete {
                cf: CF_DATABASES.to_string(),
                key: Self::partition_storage_key(database_id, p.partition_index),
            });
        }
        if let Some(ref storage) = self.storage {
            storage.write_batch_sync(ops).map_err(|e| DatabaseError::Persistence(e.to_string()))?;
        }

        self.databases.remove(database_id);
        for p in partitions {
            self.placements.remove(&placement_map_key(database_id, p.partition_index));
        }
        Ok(())
    }

    /// Rescales an existing database along the local → LAN-cluster → network
    /// continuum without minting a new descriptor. `new_placement` may promote a
    /// `Local` database to `LanCluster` or `Network` (or demote it); `partitions`
    /// and `replication` set the new shard count and replication policy.
    /// Placement is recomputed over the current `candidates` and every partition
    /// row is rewritten; partitions beyond the new count are dropped when
    /// shrinking. The database's engine, access policy, and confidential seal
    /// are preserved.
    ///
    /// The same descriptor-shape invariants apply as at creation (`Local`
    /// forces a single partition and a `{1, 1}` policy), so a caller may pass
    /// any counts and let normalization settle them.
    pub fn rescale_database(
        &self,
        database_id: &str,
        new_placement: PlacementMode,
        partitions: usize,
        replication: ReplicationPolicy,
        candidates: &[TieredCandidate],
    ) -> Result<DatabaseDescriptor> {
        let mut desc = self.get_database(database_id)?;
        desc.placement = new_placement;
        desc.partitions = partitions;
        desc.replication = replication;
        let desc = validate_descriptor(desc)?;

        let new_placements = self.compute_placements(&desc, candidates)?;
        let old_partitions = self.list_partitions(database_id);

        let mut ops: Vec<WriteOp> =
            Vec::with_capacity(1 + new_placements.len() + old_partitions.len());
        ops.push(WriteOp::Put {
            cf: CF_DATABASES.to_string(),
            key: Self::db_storage_key(&desc.database_id),
            value: serde_json::to_vec(&desc)
                .map_err(|e| DatabaseError::Persistence(e.to_string()))?,
        });
        // Delete every stale partition row the new placement does not cover.
        for old in &old_partitions {
            if old.partition_index >= desc.partitions {
                ops.push(WriteOp::Delete {
                    cf: CF_DATABASES.to_string(),
                    key: Self::partition_storage_key(database_id, old.partition_index),
                });
            }
        }
        for p in &new_placements {
            ops.push(WriteOp::Put {
                cf: CF_DATABASES.to_string(),
                key: Self::partition_storage_key(&p.database_id, p.partition_index),
                value: serde_json::to_vec(p)
                    .map_err(|e| DatabaseError::Persistence(e.to_string()))?,
            });
        }
        if let Some(ref storage) = self.storage {
            storage.write_batch_sync(ops).map_err(|e| DatabaseError::Persistence(e.to_string()))?;
        }

        for old in &old_partitions {
            if old.partition_index >= desc.partitions {
                self.placements.remove(&placement_map_key(database_id, old.partition_index));
            }
        }
        self.databases.insert(desc.database_id.clone(), desc.clone());
        for p in new_placements {
            self.placements.insert(placement_map_key(&p.database_id, p.partition_index), p);
        }
        Ok(desc)
    }

    fn persist_partition(&self, p: &PartitionPlacement) -> Result<()> {
        if let Some(ref storage) = self.storage {
            storage
                .write_batch_sync(vec![WriteOp::Put {
                    cf: CF_DATABASES.to_string(),
                    key: Self::partition_storage_key(&p.database_id, p.partition_index),
                    value: serde_json::to_vec(p)
                        .map_err(|e| DatabaseError::Persistence(e.to_string()))?,
                }])
                .map_err(|e| DatabaseError::Persistence(e.to_string()))?;
        }
        Ok(())
    }

    /// Records the loss of a holder (provider outage, departure) for one
    /// partition, shrinking its holder set. Idempotent: removing a holder that
    /// is not recorded returns the unchanged placement. The shrunk set is what
    /// [`Self::under_replicated`] measures against the policy floor.
    pub fn mark_holder_lost(
        &self,
        database_id: &str,
        partition_index: usize,
        endpoint_id: &str,
    ) -> Result<PartitionPlacement> {
        let mut p = self.get_partition(database_id, partition_index)?;
        let before = p.holder_count();
        p.local_holders.retain(|h| h != endpoint_id);
        p.network_holders.retain(|h| h != endpoint_id);
        if p.holder_count() == before {
            tracing::warn!(
                database_id,
                partition_index,
                endpoint_id,
                "holder not recorded for partition; nothing to remove"
            );
            return Ok(p);
        }
        self.persist_partition(&p)?;
        self.placements.insert(placement_map_key(database_id, partition_index), p.clone());
        tracing::info!(
            database_id,
            partition_index,
            endpoint_id,
            remaining = p.holder_count(),
            "holder marked lost"
        );
        Ok(p)
    }

    /// Partitions of `database_id` whose recorded holder count falls below the
    /// database's `min_replication` floor, ordered by partition index.
    pub fn under_replicated(&self, database_id: &str) -> Result<Vec<PartitionReplicationStatus>> {
        let desc = self.get_database(database_id)?;
        let required = desc.replication.min_replication as usize;
        Ok(self
            .list_partitions(database_id)
            .into_iter()
            .filter_map(|p| {
                let current = p.holder_count();
                (current < required).then(|| PartitionReplicationStatus {
                    partition_index: p.partition_index,
                    current,
                    required,
                    missing: required - current,
                })
            })
            .collect())
    }

    /// Plans repairs for every under-replicated partition of `database_id`:
    /// for each, HRW-selects `missing` new holders from `available_providers`
    /// minus the partition's existing holders, local segment first. Pure
    /// planning — executing the copy is a node-layer concern; the node records
    /// each completed copy via [`Self::record_repair`]. When fewer candidates
    /// remain than `missing`, the plan covers what it can and the shortfall
    /// stays visible in [`Self::under_replicated`].
    pub fn plan_repair(
        &self,
        database_id: &str,
        available_providers: &[TieredCandidate],
    ) -> Result<Vec<RepairAssignment>> {
        let mut out = Vec::new();
        for status in self.under_replicated(database_id)? {
            let p = self.get_partition(database_id, status.partition_index)?;
            let existing = p.all_holders();
            let remaining: Vec<TieredCandidate> = available_providers
                .iter()
                .filter(|c| !existing.contains(&c.endpoint_id))
                .cloned()
                .collect();
            let key = partition_key(database_id, status.partition_index);
            let picked = select_tiered_holders(&key, &remaining, status.missing);
            out.extend(picked.local.into_iter().map(|h| RepairAssignment {
                partition_index: status.partition_index,
                new_holder: h,
                local: true,
            }));
            out.extend(picked.network.into_iter().map(|h| RepairAssignment {
                partition_index: status.partition_index,
                new_holder: h,
                local: false,
            }));
        }
        Ok(out)
    }

    /// Records a completed repair copy, appending `assignment.new_holder` to
    /// the partition's holder set. Idempotent: a holder already recorded
    /// returns the unchanged placement. Refuses to grow the set past the
    /// database's `max_replication` ceiling.
    pub fn record_repair(
        &self,
        database_id: &str,
        assignment: &RepairAssignment,
    ) -> Result<PartitionPlacement> {
        let desc = self.get_database(database_id)?;
        let mut p = self.get_partition(database_id, assignment.partition_index)?;
        if p.all_holders().iter().any(|h| h == &assignment.new_holder) {
            return Ok(p);
        }
        let ceiling = desc.replication.max_replication as usize;
        if p.holder_count() >= ceiling {
            return Err(DatabaseError::InvalidRequest(format!(
                "partition {} of database {} already at max_replication {}",
                assignment.partition_index, database_id, ceiling
            )));
        }
        if assignment.local {
            p.local_holders.push(assignment.new_holder.clone());
        } else {
            p.network_holders.push(assignment.new_holder.clone());
        }
        self.persist_partition(&p)?;
        self.placements
            .insert(placement_map_key(database_id, assignment.partition_index), p.clone());
        tracing::info!(
            database_id,
            partition_index = assignment.partition_index,
            new_holder = %assignment.new_holder,
            holders = p.holder_count(),
            "repair recorded"
        );
        Ok(p)
    }
}

impl Default for DatabaseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// The self endpoint for a `Local` placement: the first local candidate, else
/// the first candidate of any tier, else the empty string (no membership view —
/// a single-machine node with no announced endpoint still serves itself).
fn self_endpoint(candidates: &[TieredCandidate]) -> String {
    candidates
        .iter()
        .find(|c| c.reachability.is_local())
        .or_else(|| candidates.first())
        .map(|c| c.endpoint_id.clone())
        .unwrap_or_default()
}

fn placement_map_key(database_id: &str, partition_index: usize) -> String {
    format!("{database_id}/{partition_index}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::engine_ids;

    fn locals(n: usize) -> Vec<TieredCandidate> {
        (0..n).map(|i| TieredCandidate::local(format!("local-{i}"))).collect()
    }

    fn directs(n: usize) -> Vec<TieredCandidate> {
        (0..n).map(|i| TieredCandidate::direct(format!("net-{i}"))).collect()
    }

    fn policy(min: u8) -> ReplicationPolicy {
        ReplicationPolicy { min_replication: min, max_replication: min + 2 }
    }

    fn desc(id: &str, engine: &str, mode: PlacementMode, partitions: usize, min_replication: u8) -> DatabaseDescriptor {
        DatabaseDescriptor {
            database_id: id.to_string(),
            engine_id: engine.to_string(),
            placement: mode,
            partitions,
            replication: policy(min_replication),
            engine_config: serde_json::json!({}),
            access_policy: AccessPolicy::owner_only("did:tenzro:human:test-owner"),
            pricing: DatabasePricing::free(),
            confidential: None,
        }
    }

    #[test]
    fn local_database_is_single_partition_on_self() {
        let reg = DatabaseRegistry::new();
        let cands = locals(1);
        let out = reg
            .create_database(desc("db-l", engine_ids::POSTGRES, PlacementMode::Local, 8, 5), &cands)
            .unwrap();
        assert_eq!(out.partitions, 1);
        assert_eq!(out.replication, ReplicationPolicy { min_replication: 1, max_replication: 1 });
        let p = reg.get_partition("db-l", 0).unwrap();
        assert_eq!(p.all_holders(), vec!["local-0".to_string()]);
    }

    #[test]
    fn lan_cluster_keeps_partitions_local_when_segment_large() {
        let reg = DatabaseRegistry::new();
        let mut cands = locals(5);
        cands.extend(directs(5));
        reg.create_database(desc("db-c", engine_ids::POSTGRES, PlacementMode::LanCluster, 3, 2), &cands)
            .unwrap();
        for idx in 0..3 {
            let p = reg.get_partition("db-c", idx).unwrap();
            assert_eq!(p.local_holders.len(), 2);
            assert!(p.network_holders.is_empty());
        }
    }

    #[test]
    fn network_spills_when_local_segment_small() {
        let reg = DatabaseRegistry::new();
        let mut cands = locals(1);
        cands.extend(directs(5));
        reg.create_database(desc("db-n", engine_ids::POSTGRES, PlacementMode::Network, 2, 3), &cands)
            .unwrap();
        let p = reg.get_partition("db-n", 0).unwrap();
        assert_eq!(p.all_holders().len(), 3);
        assert!(!p.network_holders.is_empty());
    }

    #[test]
    fn engine_native_cluster_tags_native_member_role() {
        // Milvus clusters itself: placed members are cluster nodes, not
        // standalone Tenzro shards.
        let reg = DatabaseRegistry::new();
        let mut cands = locals(2);
        cands.extend(directs(4));
        reg.create_database(desc("db-m", engine_ids::MILVUS, PlacementMode::Network, 3, 2), &cands)
            .unwrap();
        for idx in 0..3 {
            let p = reg.get_partition("db-m", idx).unwrap();
            assert_eq!(p.role, ClusterRole::NativeClusterMember);
        }
    }

    #[test]
    fn tenzro_orchestrated_tags_standalone_shard_role() {
        // Qdrant in the local/LAN tier is sharded by Tenzro: each member runs
        // a standalone instance holding one Tenzro-assigned partition.
        let reg = DatabaseRegistry::new();
        let cands = locals(4);
        reg.create_database(desc("db-q", engine_ids::QDRANT, PlacementMode::LanCluster, 3, 2), &cands)
            .unwrap();
        for idx in 0..3 {
            let p = reg.get_partition("db-q", idx).unwrap();
            assert_eq!(p.role, ClusterRole::StandaloneShard);
        }
    }

    #[test]
    fn embedded_engine_rejects_multi_partition_shard() {
        let reg = DatabaseRegistry::new();
        let cands = locals(4);
        let err = reg
            .create_database(desc("db-e", engine_ids::LANCE, PlacementMode::Network, 4, 2), &cands)
            .unwrap_err();
        assert!(matches!(err, DatabaseError::UnsupportedPlacement { .. }));
    }

    #[test]
    fn embedded_engine_rejects_network_mode() {
        let reg = DatabaseRegistry::new();
        let cands = locals(4);
        // Single partition, but Network mode on a non-shardable engine.
        let err = reg
            .create_database(desc("db-e2", engine_ids::TANTIVY, PlacementMode::Network, 1, 2), &cands)
            .unwrap_err();
        assert!(matches!(err, DatabaseError::UnsupportedPlacement { .. }));
    }

    #[test]
    fn embedded_engine_local_is_allowed() {
        let reg = DatabaseRegistry::new();
        let cands = locals(1);
        let out = reg
            .create_database(desc("db-e3", engine_ids::LANCE, PlacementMode::Local, 1, 1), &cands)
            .unwrap();
        assert_eq!(out.partitions, 1);
    }

    #[test]
    fn unknown_engine_rejected() {
        let reg = DatabaseRegistry::new();
        let err = reg
            .create_database(desc("db-u", "mongodb", PlacementMode::Local, 1, 1), &locals(1))
            .unwrap_err();
        assert!(matches!(err, DatabaseError::UnknownEngine(_)));
    }

    #[test]
    fn duplicate_database_rejected() {
        let reg = DatabaseRegistry::new();
        let cands = locals(1);
        reg.create_database(desc("dup", engine_ids::POSTGRES, PlacementMode::Local, 1, 1), &cands)
            .unwrap();
        let err = reg
            .create_database(desc("dup", engine_ids::POSTGRES, PlacementMode::Local, 1, 1), &cands)
            .unwrap_err();
        assert!(matches!(err, DatabaseError::DatabaseExists(_)));
    }

    #[test]
    fn drop_removes_database_and_partitions() {
        let reg = DatabaseRegistry::new();
        let mut cands = locals(3);
        cands.extend(directs(3));
        reg.create_database(desc("db-d", engine_ids::QDRANT, PlacementMode::Network, 3, 2), &cands)
            .unwrap();
        reg.drop_database("db-d").unwrap();
        assert!(reg.get_database("db-d").is_err());
        assert!(reg.list_partitions("db-d").is_empty());
    }

    #[test]
    fn persistence_hydrates_on_reopen() {
        let storage: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        {
            let reg = DatabaseRegistry::with_storage(storage.clone()).unwrap();
            let mut cands = locals(3);
            cands.extend(directs(3));
            reg.create_database(desc("db-p", engine_ids::POSTGRES, PlacementMode::Network, 2, 2), &cands)
                .unwrap();
        }
        // Reopen against the same store: descriptors + placements must return.
        let reg2 = DatabaseRegistry::with_storage(storage).unwrap();
        let d = reg2.get_database("db-p").unwrap();
        assert_eq!(d.partitions, 2);
        assert_eq!(reg2.list_partitions("db-p").len(), 2);
    }

    #[test]
    fn empty_pricing_asset_rejected() {
        let reg = DatabaseRegistry::new();
        let mut d = desc("db-price", engine_ids::POSTGRES, PlacementMode::Local, 1, 1);
        d.pricing = DatabasePricing { asset_id: String::new(), price_per_query: 5 };
        let err = reg.create_database(d, &locals(1)).unwrap_err();
        assert!(matches!(err, DatabaseError::InvalidRequest(_)));
    }

    #[test]
    fn pricing_persists_and_hydrates() {
        let storage: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        {
            let reg = DatabaseRegistry::with_storage(storage.clone()).unwrap();
            let mut d = desc("db-priced", engine_ids::POSTGRES, PlacementMode::Local, 1, 1);
            d.pricing = DatabasePricing { asset_id: "TNZO".to_string(), price_per_query: 250 };
            reg.create_database(d, &locals(1)).unwrap();
        }
        let reg2 = DatabaseRegistry::with_storage(storage).unwrap();
        let got = reg2.get_database("db-priced").unwrap();
        assert_eq!(got.pricing.price_per_query, 250);
        assert!(!got.pricing.is_free());
    }

    #[test]
    fn empty_owner_rejected() {
        let reg = DatabaseRegistry::new();
        let mut d = desc("db-o", engine_ids::POSTGRES, PlacementMode::Local, 1, 1);
        d.access_policy = AccessPolicy::owner_only("");
        let err = reg.create_database(d, &locals(1)).unwrap_err();
        assert!(matches!(err, DatabaseError::InvalidRequest(_)));
    }

    #[test]
    fn access_policy_persists_and_hydrates() {
        let storage: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        {
            let reg = DatabaseRegistry::with_storage(storage.clone()).unwrap();
            let mut d = desc("db-ap", engine_ids::POSTGRES, PlacementMode::Local, 1, 1);
            d.access_policy = AccessPolicy::capability_required("did:tenzro:human:alice");
            reg.create_database(d, &locals(1)).unwrap();
        }
        let reg2 = DatabaseRegistry::with_storage(storage).unwrap();
        let got = reg2.get_database("db-ap").unwrap();
        assert!(matches!(got.access_policy, AccessPolicy::CapabilityRequired { .. }));
        assert_eq!(got.access_policy.owner_did(), "did:tenzro:human:alice");
    }

    #[test]
    fn list_databases_returns_all() {
        let reg = DatabaseRegistry::new();
        let cands = locals(1);
        reg.create_database(desc("a", engine_ids::VALKEY, PlacementMode::Local, 1, 1), &cands).unwrap();
        reg.create_database(desc("b", engine_ids::POSTGRES, PlacementMode::Local, 1, 1), &cands).unwrap();
        assert_eq!(reg.list_databases().len(), 2);
    }

    #[test]
    fn rescale_local_to_network_reshards() {
        let reg = DatabaseRegistry::new();
        reg.create_database(desc("db-r", engine_ids::POSTGRES, PlacementMode::Local, 4, 3), &locals(1))
            .unwrap();
        // Local forces a single partition on self.
        assert_eq!(reg.get_database("db-r").unwrap().partitions, 1);
        assert_eq!(reg.list_partitions("db-r").len(), 1);

        let mut cands = locals(1);
        cands.extend(directs(5));
        let out = reg
            .rescale_database("db-r", PlacementMode::Network, 3, policy(2), &cands)
            .unwrap();
        assert_eq!(out.placement, PlacementMode::Network);
        assert_eq!(out.partitions, 3);
        assert_eq!(reg.list_partitions("db-r").len(), 3);
        // Engine and policy survive the rescale.
        assert_eq!(out.engine_id, engine_ids::POSTGRES);
        assert_eq!(out.access_policy.owner_did(), "did:tenzro:human:test-owner");
    }

    #[test]
    fn rescale_shrink_drops_stale_partition_rows() {
        let reg = DatabaseRegistry::new();
        let mut cands = locals(3);
        cands.extend(directs(3));
        reg.create_database(desc("db-s", engine_ids::QDRANT, PlacementMode::Network, 4, 2), &cands)
            .unwrap();
        assert_eq!(reg.list_partitions("db-s").len(), 4);

        reg.rescale_database("db-s", PlacementMode::Network, 2, policy(2), &cands).unwrap();
        assert_eq!(reg.list_partitions("db-s").len(), 2);
        // Rows 2 and 3 are gone, not merely orphaned in the map.
        assert!(reg.get_partition("db-s", 2).is_err());
        assert!(reg.get_partition("db-s", 3).is_err());
    }

    #[test]
    fn rescale_persists_across_reopen() {
        let storage: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        {
            let reg = DatabaseRegistry::with_storage(storage.clone()).unwrap();
            reg.create_database(desc("db-rp", engine_ids::POSTGRES, PlacementMode::Local, 1, 1), &locals(1))
                .unwrap();
            let mut cands = locals(2);
            cands.extend(directs(4));
            reg.rescale_database("db-rp", PlacementMode::Network, 3, policy(2), &cands).unwrap();
        }
        let reg2 = DatabaseRegistry::with_storage(storage).unwrap();
        let d = reg2.get_database("db-rp").unwrap();
        assert_eq!(d.placement, PlacementMode::Network);
        assert_eq!(d.partitions, 3);
        assert_eq!(reg2.list_partitions("db-rp").len(), 3);
    }

    #[test]
    fn rescale_unknown_database_rejected() {
        let reg = DatabaseRegistry::new();
        let err = reg
            .rescale_database("nope", PlacementMode::Network, 2, policy(2), &directs(3))
            .unwrap_err();
        assert!(matches!(err, DatabaseError::DatabaseNotFound(_)));
    }

    #[test]
    fn top_n_selection_is_deterministic_and_distinct() {
        let mut cands = locals(3);
        cands.extend(directs(7));

        let reg_a = DatabaseRegistry::new();
        let reg_b = DatabaseRegistry::new();
        reg_a
            .create_database(desc("db-det", engine_ids::POSTGRES, PlacementMode::Network, 4, 3), &cands)
            .unwrap();
        // Same descriptor, same view, reversed candidate order: HRW must
        // produce the identical holder sets.
        let mut reversed = cands.clone();
        reversed.reverse();
        reg_b
            .create_database(desc("db-det", engine_ids::POSTGRES, PlacementMode::Network, 4, 3), &reversed)
            .unwrap();

        for idx in 0..4 {
            let a = reg_a.get_partition("db-det", idx).unwrap();
            let b = reg_b.get_partition("db-det", idx).unwrap();
            assert_eq!(a, b);
            let holders = a.all_holders();
            assert_eq!(holders.len(), 3);
            let distinct: std::collections::HashSet<_> = holders.iter().collect();
            assert_eq!(distinct.len(), 3);
        }
    }

    #[test]
    fn placement_fails_closed_below_replication_floor() {
        let reg = DatabaseRegistry::new();
        let err = reg
            .create_database(desc("db-f", engine_ids::POSTGRES, PlacementMode::Network, 2, 3), &directs(2))
            .unwrap_err();
        match err {
            DatabaseError::InsufficientProviders { required, available, .. } => {
                assert_eq!(required, 3);
                assert_eq!(available, 2);
            }
            other => panic!("wrong error: {:?}", other),
        }
        // Fail-closed: nothing registered, nothing placed.
        assert!(reg.get_database("db-f").is_err());
        assert!(reg.list_partitions("db-f").is_empty());
    }

    #[test]
    fn holder_loss_surfaces_under_replication() {
        let reg = DatabaseRegistry::new();
        let cands = directs(4);
        reg.create_database(desc("db-h", engine_ids::POSTGRES, PlacementMode::Network, 2, 2), &cands)
            .unwrap();
        assert!(reg.under_replicated("db-h").unwrap().is_empty());

        let lost = reg.get_partition("db-h", 1).unwrap().all_holders()[0].clone();
        reg.mark_holder_lost("db-h", 1, &lost).unwrap();

        let statuses = reg.under_replicated("db-h").unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(
            statuses[0],
            PartitionReplicationStatus { partition_index: 1, current: 1, required: 2, missing: 1 }
        );
    }

    #[test]
    fn repair_plan_excludes_existing_holders() {
        let reg = DatabaseRegistry::new();
        let cands = directs(5);
        reg.create_database(desc("db-rep", engine_ids::POSTGRES, PlacementMode::Network, 1, 2), &cands)
            .unwrap();
        let lost = reg.get_partition("db-rep", 0).unwrap().all_holders()[0].clone();
        reg.mark_holder_lost("db-rep", 0, &lost).unwrap();

        let survivors = reg.get_partition("db-rep", 0).unwrap().all_holders();
        let plan = reg.plan_repair("db-rep", &cands).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].partition_index, 0);
        assert!(!survivors.contains(&plan[0].new_holder));

        reg.record_repair("db-rep", &plan[0]).unwrap();
        assert!(reg.under_replicated("db-rep").unwrap().is_empty());
    }

    #[test]
    fn record_repair_refuses_past_max_replication() {
        let reg = DatabaseRegistry::new();
        let cands = directs(6);
        let mut d = desc("db-max", engine_ids::POSTGRES, PlacementMode::Network, 1, 2);
        d.replication = ReplicationPolicy { min_replication: 2, max_replication: 2 };
        reg.create_database(d, &cands).unwrap();

        let extra = RepairAssignment {
            partition_index: 0,
            new_holder: "net-extra".to_string(),
            local: false,
        };
        let err = reg.record_repair("db-max", &extra).unwrap_err();
        assert!(matches!(err, DatabaseError::InvalidRequest(_)));
    }

    #[test]
    fn holder_loss_and_repair_persist_across_reopen() {
        let storage: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let lost;
        {
            let reg = DatabaseRegistry::with_storage(storage.clone()).unwrap();
            let cands = directs(5);
            reg.create_database(desc("db-dur", engine_ids::POSTGRES, PlacementMode::Network, 1, 3), &cands)
                .unwrap();
            lost = reg.get_partition("db-dur", 0).unwrap().all_holders()[0].clone();
            reg.mark_holder_lost("db-dur", 0, &lost).unwrap();
        }
        let reg2 = DatabaseRegistry::with_storage(storage.clone()).unwrap();
        let holders = reg2.get_partition("db-dur", 0).unwrap().all_holders();
        assert_eq!(holders.len(), 2);
        assert!(!holders.contains(&lost));

        let plan = reg2.plan_repair("db-dur", &directs(5)).unwrap();
        assert_eq!(plan.len(), 1);
        reg2.record_repair("db-dur", &plan[0]).unwrap();

        let reg3 = DatabaseRegistry::with_storage(storage).unwrap();
        assert_eq!(reg3.get_partition("db-dur", 0).unwrap().holder_count(), 3);
        assert!(reg3.under_replicated("db-dur").unwrap().is_empty());
    }
}
