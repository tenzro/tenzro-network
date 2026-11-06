//! Local-first tiered placement over the same domain-tagged HRW ranking.
//!
//! The engine-agnostic placement question a node asks is: given a content key
//! (a storage-shard commitment, a database-partition id) and the members it can
//! see, which members should hold it? [`placement`] answers that over one flat
//! endpoint set. This module answers the *tiered* form the local/network model
//! demands: prefer members on the caller's own local segment, and only reach
//! out to the wider network once the local segment cannot meet the replica
//! count.
//!
//! A member is a [`TieredCandidate`]: an endpoint id plus its
//! [`MemberReachability`]. Selection fills `replicas` local-segment
//! ([`is_local`]) holders first — deterministically ranked by the same HRW
//! score so every node computes the same local set — then tops up the shortfall
//! from the network tier (all remaining [`data_plane_eligible`] members) by HRW
//! over the endpoints not already chosen. Relayed and symmetric-NAT members are
//! never selected: a relay hop cannot carry sustained holder traffic.
//!
//! The result: a workload served entirely within a home/office LAN keeps every
//! replica on that LAN (no egress, lowest latency), and only spills onto the
//! network when the local segment is too small — the same local-machine →
//! LAN-cluster → wider-network progression the model-serving tier uses, applied
//! to shard and partition placement.
//!
//! [`placement`]: crate::placement
//! [`is_local`]: crate::reachability::MemberReachability::is_local
//! [`data_plane_eligible`]: crate::reachability::MemberReachability::data_plane_eligible

use crate::placement::select_holders;
use crate::reachability::MemberReachability;

/// One placement candidate: its endpoint id and its data-plane reachability
/// tier from the caller's vantage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TieredCandidate {
    /// Endpoint id (iroh endpoint id, node address hex, …) — the same id space
    /// [`crate::placement`] ranks over.
    pub endpoint_id: String,
    /// Data-plane reachability from the caller. Only [`data_plane_eligible`]
    /// candidates are ever selected; [`is_local`] candidates form the local
    /// tier.
    ///
    /// [`data_plane_eligible`]: MemberReachability::data_plane_eligible
    /// [`is_local`]: MemberReachability::is_local
    pub reachability: MemberReachability,
}

impl TieredCandidate {
    /// A local-segment candidate ([`MemberReachability::LocalDirect`]).
    pub fn local(endpoint_id: impl Into<String>) -> Self {
        Self {
            endpoint_id: endpoint_id.into(),
            reachability: MemberReachability::LocalDirect,
        }
    }

    /// A directly-dialable network-tier candidate ([`MemberReachability::Direct`]).
    pub fn direct(endpoint_id: impl Into<String>) -> Self {
        Self {
            endpoint_id: endpoint_id.into(),
            reachability: MemberReachability::Direct,
        }
    }
}

/// The holder set for a key, split by the tier each holder was drawn from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TieredHolders {
    /// Holders on the caller's local segment, HRW-ranked. Filled first.
    pub local: Vec<String>,
    /// Holders drawn from the wider network to top up the replica count when
    /// the local segment could not supply enough. Empty when the local tier
    /// met `replicas`.
    pub network: Vec<String>,
}

impl TieredHolders {
    /// All selected holders, local tier first then network tier.
    pub fn all(&self) -> Vec<String> {
        self.local
            .iter()
            .chain(self.network.iter())
            .cloned()
            .collect()
    }

    /// Total number of selected holders across both tiers.
    pub fn len(&self) -> usize {
        self.local.len() + self.network.len()
    }

    /// Whether no holder was selected (no data-plane-eligible candidate).
    pub fn is_empty(&self) -> bool {
        self.local.is_empty() && self.network.is_empty()
    }
}

/// Select up to `replicas` holders for `key` under `domain`, local segment
/// first.
///
/// Local-segment ([`is_local`]) candidates are ranked by the domain-tagged HRW
/// score and fill the replica count first; any shortfall is topped up by HRW
/// over the remaining [`data_plane_eligible`] network-tier candidates. Members
/// that are not data-plane eligible (relayed, symmetric-NAT) are never
/// selected. Every node computing this over the same membership view reaches
/// the same holder set with no coordinator round.
///
/// [`is_local`]: MemberReachability::is_local
/// [`data_plane_eligible`]: MemberReachability::data_plane_eligible
pub fn select_tiered_holders(
    domain: &[u8],
    key: &str,
    candidates: &[TieredCandidate],
    replicas: usize,
) -> TieredHolders {
    if replicas == 0 {
        return TieredHolders {
            local: Vec::new(),
            network: Vec::new(),
        };
    }

    let local_ids: Vec<String> = candidates
        .iter()
        .filter(|c| c.reachability.is_local())
        .map(|c| c.endpoint_id.clone())
        .collect();
    let local = select_holders(domain, key, &local_ids, replicas);

    let remaining = replicas - local.len();
    let network = if remaining == 0 {
        Vec::new()
    } else {
        // Network tier: every data-plane-eligible candidate not already chosen
        // in the local tier. Local-only members are excluded here so a member
        // is never counted twice.
        let network_ids: Vec<String> = candidates
            .iter()
            .filter(|c| c.reachability.data_plane_eligible() && !c.reachability.is_local())
            .map(|c| c.endpoint_id.clone())
            .filter(|id| !local.contains(id))
            .collect();
        select_holders(domain, key, &network_ids, remaining)
    };

    TieredHolders { local, network }
}

/// Whether `own_endpoint_id` should hold `key` under local-first tiered
/// self-selection.
///
/// The caller's own candidate should appear in `candidates`; if absent it is
/// added with the reachability given by `own_is_local` (local segment vs
/// network tier) so a node never excludes itself from its own view. Returns
/// true when the caller lands in either tier of the selected holder set.
pub fn should_replicate_tiered(
    domain: &[u8],
    key: &str,
    own_endpoint_id: &str,
    own_is_local: bool,
    candidates: &[TieredCandidate],
    replicas: usize,
) -> bool {
    let mut all = candidates.to_vec();
    if !all.iter().any(|c| c.endpoint_id == own_endpoint_id) {
        all.push(TieredCandidate {
            endpoint_id: own_endpoint_id.to_string(),
            reachability: if own_is_local {
                MemberReachability::LocalDirect
            } else {
                MemberReachability::Direct
            },
        });
    }
    select_tiered_holders(domain, key, &all, replicas)
        .all()
        .iter()
        .any(|c| c == own_endpoint_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &[u8] = b"tenzro/test/tiered";

    fn locals(n: usize) -> Vec<TieredCandidate> {
        (0..n)
            .map(|i| TieredCandidate::local(format!("local-{i}")))
            .collect()
    }

    fn directs(n: usize) -> Vec<TieredCandidate> {
        (0..n)
            .map(|i| TieredCandidate::direct(format!("net-{i}")))
            .collect()
    }

    #[test]
    fn all_replicas_stay_local_when_segment_is_large_enough() {
        let mut cands = locals(6);
        cands.extend(directs(6));
        let out = select_tiered_holders(D, "shard-a", &cands, 3);
        assert_eq!(out.local.len(), 3);
        assert!(out.network.is_empty());
        assert!(out.local.iter().all(|h| h.starts_with("local-")));
    }

    #[test]
    fn spills_to_network_when_local_segment_too_small() {
        let mut cands = locals(2);
        cands.extend(directs(6));
        let out = select_tiered_holders(D, "shard-b", &cands, 4);
        assert_eq!(out.local.len(), 2);
        assert_eq!(out.network.len(), 2);
        assert!(out.local.iter().all(|h| h.starts_with("local-")));
        assert!(out.network.iter().all(|h| h.starts_with("net-")));
    }

    #[test]
    fn purely_network_when_no_local_segment() {
        let cands = directs(5);
        let out = select_tiered_holders(D, "shard-c", &cands, 3);
        assert!(out.local.is_empty());
        assert_eq!(out.network.len(), 3);
    }

    #[test]
    fn relay_and_symmetric_nat_never_selected() {
        let cands = vec![
            TieredCandidate {
                endpoint_id: "relay".into(),
                reachability: MemberReachability::RelayOnly,
            },
            TieredCandidate {
                endpoint_id: "nat".into(),
                reachability: MemberReachability::SymmetricNat,
            },
            TieredCandidate::direct("ok"),
        ];
        let out = select_tiered_holders(D, "shard-d", &cands, 3);
        assert_eq!(out.all(), vec!["ok".to_string()]);
    }

    #[test]
    fn no_holder_counted_twice_across_tiers() {
        let mut cands = locals(3);
        cands.extend(directs(3));
        let out = select_tiered_holders(D, "shard-e", &cands, 6);
        let all = out.all();
        let distinct: std::collections::HashSet<_> = all.iter().collect();
        assert_eq!(all.len(), distinct.len());
    }

    #[test]
    fn selection_is_deterministic() {
        let mut cands = locals(4);
        cands.extend(directs(4));
        let a = select_tiered_holders(D, "shard-f", &cands, 5);
        let b = select_tiered_holders(D, "shard-f", &cands, 5);
        assert_eq!(a, b);
    }

    #[test]
    fn zero_replicas_selects_nothing() {
        let cands = locals(4);
        let out = select_tiered_holders(D, "shard-g", &cands, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn local_tier_ranking_matches_flat_hrw() {
        // The local tier must rank identically to a flat HRW over just the
        // local endpoints, so tiered and untiered nodes agree on the local set.
        let cands = locals(8);
        let local_ids: Vec<String> = cands.iter().map(|c| c.endpoint_id.clone()).collect();
        let flat = select_holders(D, "shard-h", &local_ids, 3);
        let tiered = select_tiered_holders(D, "shard-h", &cands, 3);
        assert_eq!(tiered.local, flat);
    }

    #[test]
    fn self_selection_consistent_with_holder_set() {
        let mut cands = locals(5);
        cands.extend(directs(5));
        cands.push(TieredCandidate::local("me"));
        for i in 0..30 {
            let key = format!("k-{i}");
            let expected = select_tiered_holders(D, &key, &cands, 3)
                .all()
                .iter()
                .any(|h| h == "me");
            assert_eq!(
                should_replicate_tiered(D, &key, "me", true, &cands, 3),
                expected
            );
        }
    }

    #[test]
    fn self_added_when_absent() {
        let cands = directs(2);
        // With replicas >= candidates+self, self must be selected.
        assert!(should_replicate_tiered(D, "k", "me", false, &cands, 5));
    }
}
