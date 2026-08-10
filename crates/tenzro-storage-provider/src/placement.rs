//! Rendezvous (HRW) shard placement over the network tier.
//!
//! Given a shard commitment and the set of storage-capable endpoints known to
//! a node, highest-random-weight hashing deterministically ranks every
//! endpoint for that shard. The top `replicas` endpoints self-select as
//! holders: each node computes the same ranking from its own membership view
//! and pins the shard if it appears in the top set. No coordinator, no
//! placement table — membership-view skew produces mild over- or
//! under-replication that heals as views converge and blob heartbeats
//! re-announce holders.
//!
//! The ranking itself is the engine-agnostic [`tenzro_cluster::placement`]
//! primitive; this module pins the storage domain tag so shard placement never
//! collides with database-partition placement over the same endpoint ids.
//!
//! [`select_tiered_holders`] / [`should_replicate_tiered`] wrap the same tag
//! over the local-first [`tenzro_cluster::tiered`] primitive: a shard whose
//! deal is served entirely within a home/office LAN keeps every replica on that
//! segment, spilling onto the wider network only when the segment is too small
//! to meet the redundancy count.

pub use tenzro_cluster::{MemberReachability, TieredCandidate, TieredHolders};

/// Domain-separation tag for storage-shard placement scores.
const PLACEMENT_DOMAIN: &[u8] = b"tenzro/storage/placement";

/// Deterministic HRW score of one endpoint for one shard commitment.
///
/// `commitment` is the shard's SHA-256 commitment (hex, as recorded in
/// [`crate::ShardRef`]); `endpoint_id` is the candidate's iroh endpoint id
/// (z-base-32 string). Higher scores rank earlier.
pub fn hrw_score(commitment: &str, endpoint_id: &str) -> [u8; 32] {
    tenzro_cluster::hrw_score(PLACEMENT_DOMAIN, commitment, endpoint_id)
}

/// Ranks `candidates` for a shard and returns the top `replicas` endpoint ids.
///
/// Duplicate candidate ids are collapsed before ranking. When fewer distinct
/// candidates than `replicas` exist, every candidate is returned.
pub fn select_holders(commitment: &str, candidates: &[String], replicas: usize) -> Vec<String> {
    tenzro_cluster::select_holders(PLACEMENT_DOMAIN, commitment, candidates, replicas)
}

/// Whether `own_endpoint_id` should hold the shard under HRW self-selection.
///
/// The candidate set should include the caller's own endpoint id; it is added
/// if absent so a node never excludes itself from its own view.
pub fn should_replicate(
    commitment: &str,
    own_endpoint_id: &str,
    candidates: &[String],
    replicas: usize,
) -> bool {
    tenzro_cluster::should_replicate(
        PLACEMENT_DOMAIN,
        commitment,
        own_endpoint_id,
        candidates,
        replicas,
    )
}

/// Selects shard holders local segment first, spilling onto the network tier
/// only when the segment is too small to meet `replicas`.
///
/// `candidates` carry each endpoint's data-plane reachability; local-segment
/// members fill the replica count before any wider-network member is chosen.
/// The returned [`TieredHolders`] keeps the two tiers distinct so a caller can
/// see whether a shard stayed on-LAN. Same domain tag as [`select_holders`], so
/// the flat and tiered paths never collide with database placement.
pub fn select_tiered_holders(
    commitment: &str,
    candidates: &[TieredCandidate],
    replicas: usize,
) -> TieredHolders {
    tenzro_cluster::select_tiered_holders(PLACEMENT_DOMAIN, commitment, candidates, replicas)
}

/// Whether `own_endpoint_id` should hold the shard under local-first tiered
/// self-selection.
///
/// `own_is_local` places the caller in the local segment or the network tier
/// when it is not already present in `candidates`. Returns true when the caller
/// lands in either tier of the selected holder set.
pub fn should_replicate_tiered(
    commitment: &str,
    own_endpoint_id: &str,
    own_is_local: bool,
    candidates: &[TieredCandidate],
    replicas: usize,
) -> bool {
    tenzro_cluster::should_replicate_tiered(
        PLACEMENT_DOMAIN,
        commitment,
        own_endpoint_id,
        own_is_local,
        candidates,
        replicas,
    )
}
