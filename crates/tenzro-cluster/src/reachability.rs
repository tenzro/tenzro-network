//! Data-plane reachability tier of a cluster member.

use serde::{Deserialize, Serialize};

/// Data-plane reachability of a candidate cluster member from the head's
/// vantage. Only members the head can reach directly may carry per-request
/// cluster traffic (pipeline activations, shard transfers, partition reads);
/// relayed or symmetric-NAT members can still take part in control-plane
/// coordination but never on the data plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberReachability {
    /// Reachable on the same local segment (mDNS / private range). Ideal — the
    /// local-network cluster tier is built from these.
    LocalDirect,
    /// Directly dialable (public or hole-punched) without a relay.
    Direct,
    /// Reachable only through a circuit relay. The relay budget carries a
    /// handful of requests at most — never admit on the data plane.
    RelayOnly,
    /// Behind symmetric NAT with no working hole-punch. Excluded.
    SymmetricNat,
}

impl MemberReachability {
    /// Whether a member with this reachability may carry data-plane traffic.
    /// Relayed and symmetric-NAT members are excluded — a relay hop is useless
    /// for sustained per-request traffic.
    pub fn data_plane_eligible(self) -> bool {
        matches!(self, Self::LocalDirect | Self::Direct)
    }

    /// Whether the member is on the local segment. The local-network cluster
    /// tier admits only [`Self::LocalDirect`] members; the wider-network tier
    /// additionally accepts [`Self::Direct`].
    pub fn is_local(self) -> bool {
        matches!(self, Self::LocalDirect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_plane_eligibility() {
        assert!(MemberReachability::LocalDirect.data_plane_eligible());
        assert!(MemberReachability::Direct.data_plane_eligible());
        assert!(!MemberReachability::RelayOnly.data_plane_eligible());
        assert!(!MemberReachability::SymmetricNat.data_plane_eligible());
    }

    #[test]
    fn locality() {
        assert!(MemberReachability::LocalDirect.is_local());
        assert!(!MemberReachability::Direct.is_local());
        assert!(!MemberReachability::RelayOnly.is_local());
    }
}
