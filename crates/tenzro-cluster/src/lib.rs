//! Engine-agnostic local-network cluster substrate.
//!
//! A Tenzro node can serve a workload three ways: on the single local machine,
//! across a **local-network cluster** of nearby machines it discovered on the
//! same segment, or sharded across the **wider network**. This crate holds the
//! parts of the middle and outer tiers that do not depend on *what* is being
//! served — model layers, storage shards, or database partitions all reuse the
//! same reachability tiers, the same probed link-cost graph, the same
//! nearest-neighbour ordering, and the same rendezvous placement.
//!
//! Each serving domain keeps its own workload-specific planner (model-layer
//! bin-packing, erasure-coded shard redundancy, database partition maps) and
//! consumes these primitives underneath it. Nothing here runs a workload or
//! makes a generative decision: every function is a deterministic function of
//! measured inputs, so two members fed identical inputs compute the identical
//! plan with no coordinator round.
//!
//! ## Layers
//!
//! - [`reachability`] — [`MemberReachability`]: the data-plane admission tier
//!   (`LocalDirect` / `Direct` / `RelayOnly` / `SymmetricNat`). Only directly
//!   reachable members may carry per-request cluster traffic.
//! - [`topology`] — [`MemberId`], [`LinkProbe`], [`link_key`], and
//!   [`order_members`]: a probed pairwise cost graph plus the greedy
//!   nearest-neighbour chain that orders members to minimise total transfer
//!   cost across a small LAN cluster.
//! - [`placement`] — [`hrw_score`] / [`select_holders`] / [`should_replicate`]:
//!   domain-tagged highest-random-weight (rendezvous) hashing for the network
//!   tier, so shards or partitions self-select onto independent members with
//!   no placement table.
//! - [`tiered`] — [`select_tiered_holders`] / [`should_replicate_tiered`]:
//!   local-first placement over the same HRW ranking. Fills replicas from the
//!   caller's local segment first, spilling onto the network tier only when the
//!   segment is too small — the local-machine → LAN-cluster → wider-network
//!   progression applied to shard and partition placement.

#![deny(missing_docs)]

pub mod placement;
pub mod reachability;
pub mod tiered;
pub mod topology;

pub use placement::{hrw_score, select_holders, should_replicate};
pub use reachability::MemberReachability;
pub use tiered::{select_tiered_holders, should_replicate_tiered, TieredCandidate, TieredHolders};
pub use topology::{link_key, order_members, CostMember, LinkProbe, MemberId, OrderedMembers};
