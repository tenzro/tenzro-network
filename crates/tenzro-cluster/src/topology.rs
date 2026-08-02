//! Probed link-cost graph and deterministic member ordering for a cluster.
//!
//! A cluster's members sit on one local segment. To order them into a
//! transfer-cost-minimising chain (a model pipeline, a shard-fetch order, a
//! partition-scan order) the head probes pairwise round-trip latency and usable
//! bandwidth, then walks a greedy nearest-neighbour chain over that cost graph.
//! For the small member counts a single LAN cluster holds, greedy ordering is
//! correct and far simpler than shortest-path ordering.
//!
//! Members are identified by an opaque [`MemberId`] (a string) so the substrate
//! is engine-agnostic: the model tier keys members by node address, the storage
//! and database tiers by iroh endpoint id. Only [`data_plane_eligible`] members
//! are admitted to the ordering; the rest are returned as excluded.
//!
//! [`data_plane_eligible`]: crate::reachability::MemberReachability::data_plane_eligible

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::reachability::MemberReachability;

/// Opaque identifier for a cluster member. Wraps whatever key a serving domain
/// already uses (node address hex, iroh endpoint id, …). Ordering compares the
/// inner string, so tie-breaks are stable across members.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MemberId(pub String);

impl MemberId {
    /// Borrow the inner id string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for MemberId {
    fn from(s: String) -> Self {
        MemberId(s)
    }
}

impl From<&str> for MemberId {
    fn from(s: &str) -> Self {
        MemberId(s.to_string())
    }
}

/// One member of the cost graph: its id, its reachability tier, and the number
/// of bytes it transfers per request unit (the per-request data-plane weight).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CostMember {
    /// The member's opaque id.
    pub id: MemberId,
    /// Data-plane reachability tier. Only eligible members enter the ordering.
    pub reachability: MemberReachability,
}

/// A probed pairwise link between two members: round-trip latency and usable
/// bandwidth. Populated by an active probe burst at cluster-form time.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LinkProbe {
    /// Round-trip time, milliseconds.
    pub rtt_ms: f32,
    /// Usable bandwidth, gigabits per second.
    pub bandwidth_gbps: f32,
}

impl LinkProbe {
    /// Estimated transfer cost (ms) to move `transfer_bytes` over this link:
    /// RTT plus serialization time. A non-positive bandwidth is infinite cost.
    pub fn transfer_ms(&self, transfer_bytes: u32) -> f32 {
        if self.bandwidth_gbps <= 0.0 {
            return f32::INFINITY;
        }
        let bits = transfer_bytes as f32 * 8.0;
        let serialize_ms = bits / (self.bandwidth_gbps * 1e9) * 1e3;
        self.rtt_ms + serialize_ms
    }
}

/// Canonical (order-independent) key for a member-pair probe.
pub fn link_key(a: &MemberId, b: &MemberId) -> (MemberId, MemberId) {
    if a.0 <= b.0 {
        (a.clone(), b.clone())
    } else {
        (b.clone(), a.clone())
    }
}

/// Result of ordering a cluster's members: the data-plane-eligible members in
/// nearest-neighbour chain order, plus the ids excluded for not being
/// data-plane reachable (each with its reachability tier).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrderedMembers {
    /// Members in chain order (first hop first). The head connects to the first.
    pub ordered: Vec<MemberId>,
    /// Members excluded from the data plane, each with the reachability tier
    /// that disqualified it.
    pub excluded: Vec<(MemberId, MemberReachability)>,
}

/// Admit only data-plane-reachable members and order them to minimise total
/// transfer cost, as a greedy nearest-neighbour chain from `head` over the
/// probed cost graph. `probes` is keyed by [`link_key`]; `transfer_bytes` sets
/// the per-hop transfer weight. Ties break on member-id order, so the ordering
/// is deterministic and coordinator-free.
pub fn order_members(
    head: &MemberId,
    members: &[CostMember],
    probes: &HashMap<(MemberId, MemberId), LinkProbe>,
    transfer_bytes: u32,
) -> OrderedMembers {
    let mut excluded = Vec::new();
    let mut remaining: Vec<MemberId> = Vec::new();
    for m in members {
        if m.reachability.data_plane_eligible() {
            remaining.push(m.id.clone());
        } else {
            excluded.push((m.id.clone(), m.reachability));
        }
    }
    // Stable tie-break: id order.
    remaining.sort();

    let mut ordered: Vec<MemberId> = Vec::new();
    let mut current = head.clone();
    while !remaining.is_empty() {
        let mut best_idx = 0usize;
        let mut best_cost = f32::INFINITY;
        for (i, cand) in remaining.iter().enumerate() {
            let cost = probe_cost(probes, &current, cand, transfer_bytes);
            if cost < best_cost {
                best_cost = cost;
                best_idx = i;
            }
        }
        let next = remaining.remove(best_idx);
        current = next.clone();
        ordered.push(next);
    }

    OrderedMembers { ordered, excluded }
}

fn probe_cost(
    probes: &HashMap<(MemberId, MemberId), LinkProbe>,
    a: &MemberId,
    b: &MemberId,
    transfer_bytes: u32,
) -> f32 {
    probes
        .get(&link_key(a, b))
        .map(|p| p.transfer_ms(transfer_bytes))
        // No probe for this pair: worst-case so probed links win.
        .unwrap_or(f32::INFINITY)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(id: &str, r: MemberReachability) -> CostMember {
        CostMember {
            id: id.into(),
            reachability: r,
        }
    }

    #[test]
    fn excludes_relay_and_symmetric_nat() {
        let head: MemberId = "head".into();
        let members = vec![
            m("direct", MemberReachability::Direct),
            m("relay", MemberReachability::RelayOnly),
            m("nat", MemberReachability::SymmetricNat),
        ];
        let probes = HashMap::new();
        let out = order_members(&head, &members, &probes, 16384);
        assert_eq!(out.ordered, vec![MemberId::from("direct")]);
        assert_eq!(out.excluded.len(), 2);
    }

    #[test]
    fn prefers_cheaper_links() {
        let head: MemberId = "head".into();
        let near: MemberId = "near".into();
        let far: MemberId = "far".into();
        let mut probes = HashMap::new();
        probes.insert(
            link_key(&head, &near),
            LinkProbe {
                rtt_ms: 1.0,
                bandwidth_gbps: 10.0,
            },
        );
        probes.insert(
            link_key(&head, &far),
            LinkProbe {
                rtt_ms: 50.0,
                bandwidth_gbps: 1.0,
            },
        );
        probes.insert(
            link_key(&near, &far),
            LinkProbe {
                rtt_ms: 2.0,
                bandwidth_gbps: 10.0,
            },
        );
        let members = vec![
            m("far", MemberReachability::LocalDirect),
            m("near", MemberReachability::LocalDirect),
        ];
        let out = order_members(&head, &members, &probes, 16384);
        assert_eq!(out.ordered, vec![near, far]);
    }

    #[test]
    fn transfer_cost_accounts_for_bandwidth() {
        let fast = LinkProbe {
            rtt_ms: 1.0,
            bandwidth_gbps: 100.0,
        };
        let slow = LinkProbe {
            rtt_ms: 1.0,
            bandwidth_gbps: 1.0,
        };
        assert!(fast.transfer_ms(16384) < slow.transfer_ms(16384));
    }

    #[test]
    fn zero_bandwidth_is_infinite() {
        let dead = LinkProbe {
            rtt_ms: 1.0,
            bandwidth_gbps: 0.0,
        };
        assert!(dead.transfer_ms(1024).is_infinite());
    }

    #[test]
    fn link_key_is_order_independent() {
        let a: MemberId = "a".into();
        let b: MemberId = "b".into();
        assert_eq!(link_key(&a, &b), link_key(&b, &a));
    }
}
