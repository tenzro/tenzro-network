//! Rendezvous (HRW) partition placement over the network tier.
//!
//! A network-mode database is split into partitions; each partition is placed
//! on `replicas` independent members by highest-random-weight hashing over the
//! members a node can see. Every node computes the same ranking from its own
//! membership view and pins the partition if it lands in the top set — no
//! coordinator, no placement table, the same self-selection storage shards use.
//!
//! The ranking primitive is the engine-agnostic [`tenzro_cluster::placement`];
//! this module pins the **database** domain tag so partition placement never
//! collides with storage-shard placement over the same member ids.
//!
//! [`select_tiered_holders`] / [`should_replicate_tiered`] wrap the local-first
//! [`tenzro_cluster::tiered`] primitive: a database served entirely within a
//! home/office LAN keeps every partition replica on that segment, spilling onto
//! the wider network only when the segment is too small to meet the redundancy
//! count — the same local-machine → LAN-cluster → network progression the
//! model-serving and storage tiers use.

pub use tenzro_cluster::{MemberReachability, TieredCandidate, TieredHolders};

/// Domain-separation tag for database-partition placement scores. Distinct from
/// the storage-shard tag so the two placement domains never collide over the
/// same member id space.
const PLACEMENT_DOMAIN: &[u8] = b"tenzro/database/placement";

/// The partition-placement key for `(database_id, partition_index)`.
///
/// Every node derives the identical key so the HRW ranking — and therefore the
/// holder set — is identical across the network with no coordination.
pub fn partition_key(database_id: &str, partition_index: usize) -> String {
    format!("{database_id}/{partition_index}")
}

/// Deterministic HRW score of one member for one partition key.
pub fn hrw_score(key: &str, endpoint_id: &str) -> [u8; 32] {
    tenzro_cluster::hrw_score(PLACEMENT_DOMAIN, key, endpoint_id)
}

/// Ranks `candidates` for a partition key and returns the top `replicas`
/// endpoint ids. Duplicate candidate ids are collapsed before ranking; when
/// fewer distinct candidates than `replicas` exist, every candidate is
/// returned.
pub fn select_holders(key: &str, candidates: &[String], replicas: usize) -> Vec<String> {
    tenzro_cluster::select_holders(PLACEMENT_DOMAIN, key, candidates, replicas)
}

/// Whether `own_endpoint_id` should hold the partition under HRW
/// self-selection. The caller's own id is added if absent so a node never
/// excludes itself from its own view.
pub fn should_replicate(
    key: &str,
    own_endpoint_id: &str,
    candidates: &[String],
    replicas: usize,
) -> bool {
    tenzro_cluster::should_replicate(PLACEMENT_DOMAIN, key, own_endpoint_id, candidates, replicas)
}

/// Selects partition holders local segment first, spilling onto the network
/// tier only when the segment is too small to meet `replicas`. Same domain tag
/// as [`select_holders`], so the flat and tiered paths never collide with
/// storage-shard placement.
pub fn select_tiered_holders(
    key: &str,
    candidates: &[TieredCandidate],
    replicas: usize,
) -> TieredHolders {
    tenzro_cluster::select_tiered_holders(PLACEMENT_DOMAIN, key, candidates, replicas)
}

/// Whether `own_endpoint_id` should hold the partition under local-first tiered
/// self-selection. `own_is_local` places the caller in the local segment or the
/// network tier when it is not already present in `candidates`.
pub fn should_replicate_tiered(
    key: &str,
    own_endpoint_id: &str,
    own_is_local: bool,
    candidates: &[TieredCandidate],
    replicas: usize,
) -> bool {
    tenzro_cluster::should_replicate_tiered(
        PLACEMENT_DOMAIN,
        key,
        own_endpoint_id,
        own_is_local,
        candidates,
        replicas,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_domain_differs_from_storage_domain() {
        // The database tag must produce a different score than the storage tag
        // for the same key/endpoint, so the two placement domains are
        // independent over one member id space.
        let db = hrw_score("k", "endpoint-a");
        let storage = tenzro_cluster::hrw_score(b"tenzro/storage/placement", "k", "endpoint-a");
        assert_ne!(db, storage);
    }

    #[test]
    fn partition_key_is_stable() {
        assert_eq!(partition_key("db-1", 3), "db-1/3");
    }

    #[test]
    fn tiered_prefers_local_segment() {
        let mut cands: Vec<TieredCandidate> = (0..4)
            .map(|i| TieredCandidate::local(format!("local-{i}")))
            .collect();
        cands.extend((0..4).map(|i| TieredCandidate::direct(format!("net-{i}"))));
        let out = select_tiered_holders(&partition_key("db", 0), &cands, 2);
        assert_eq!(out.local.len(), 2);
        assert!(out.network.is_empty());
    }
}
