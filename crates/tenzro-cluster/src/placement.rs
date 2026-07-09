//! Domain-tagged rendezvous (HRW) placement for the network tier.
//!
//! Given a content key and the set of endpoints known to a node,
//! highest-random-weight hashing deterministically ranks every endpoint for
//! that key. The top `replicas` endpoints self-select as holders: each node
//! computes the same ranking from its own membership view and pins the item if
//! it appears in the top set. No coordinator, no placement table —
//! membership-view skew produces mild over- or under-replication that heals as
//! views converge and heartbeats re-announce holders.
//!
//! Every score is domain-separated so independent serving domains (storage
//! shards, database partitions) that share the same endpoint id space and the
//! same content key never rank endpoints identically. Callers pass their own
//! `domain` tag; adding a node to one domain never reshuffles another.

use sha2::{Digest, Sha256};

/// Deterministic HRW score of one endpoint for one content key under `domain`.
///
/// `domain` separates independent placement problems that reuse the same
/// endpoint ids and keys (e.g. `b"tenzro/storage/placement"` vs
/// `b"tenzro/database/placement"`). `key` is the content key being placed (a
/// shard commitment, a partition id, …); `endpoint_id` is the candidate's
/// endpoint id string. Higher scores rank earlier.
pub fn hrw_score(domain: &[u8], key: &str, endpoint_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(key.as_bytes());
    hasher.update(endpoint_id.as_bytes());
    hasher.finalize().into()
}

/// Ranks `candidates` for a key under `domain` and returns the top `replicas`
/// endpoint ids.
///
/// Duplicate candidate ids are collapsed before ranking. When fewer distinct
/// candidates than `replicas` exist, every candidate is returned — the network
/// cannot do better than full membership.
pub fn select_holders(
    domain: &[u8],
    key: &str,
    candidates: &[String],
    replicas: usize,
) -> Vec<String> {
    let mut ranked: Vec<(String, [u8; 32])> = {
        let mut seen = std::collections::HashSet::new();
        candidates
            .iter()
            .filter(|c| seen.insert(c.as_str()))
            .map(|c| (c.clone(), hrw_score(domain, key, c)))
            .collect()
    };
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked.truncate(replicas);
    ranked.into_iter().map(|(id, _)| id).collect()
}

/// Whether `own_endpoint_id` should hold the key under HRW self-selection.
///
/// The candidate set should include the caller's own endpoint id; it is added
/// if absent so a node never excludes itself from its own view.
pub fn should_replicate(
    domain: &[u8],
    key: &str,
    own_endpoint_id: &str,
    candidates: &[String],
    replicas: usize,
) -> bool {
    let mut all = candidates.to_vec();
    if !all.iter().any(|c| c == own_endpoint_id) {
        all.push(own_endpoint_id.to_string());
    }
    select_holders(domain, key, &all, replicas)
        .iter()
        .any(|c| c == own_endpoint_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &[u8] = b"tenzro/test/placement";

    fn endpoints(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("endpoint-{i}")).collect()
    }

    #[test]
    fn selection_is_deterministic() {
        let cands = endpoints(10);
        let a = select_holders(D, "abc123", &cands, 3);
        let b = select_holders(D, "abc123", &cands, 3);
        assert_eq!(a, b);
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn distinct_keys_spread_across_endpoints() {
        let cands = endpoints(20);
        let mut chosen = std::collections::HashSet::new();
        for i in 0..50 {
            for holder in select_holders(D, &format!("key-{i}"), &cands, 3) {
                chosen.insert(holder);
            }
        }
        assert!(chosen.len() > 10, "only {} endpoints chosen", chosen.len());
    }

    #[test]
    fn membership_change_causes_minimal_reshuffle() {
        let cands = endpoints(10);
        let mut grown = cands.clone();
        grown.push("endpoint-new".to_string());

        let mut moved = 0usize;
        let total = 100usize;
        for i in 0..total {
            let key = format!("shard-{i}");
            let before: std::collections::HashSet<_> =
                select_holders(D, &key, &cands, 3).into_iter().collect();
            let after: std::collections::HashSet<_> =
                select_holders(D, &key, &grown, 3).into_iter().collect();
            moved += before.difference(&after).count();
        }
        assert!(moved < 100, "{moved} of 300 slots moved");
    }

    #[test]
    fn fewer_candidates_than_replicas_returns_all() {
        let cands = endpoints(2);
        let holders = select_holders(D, "abc", &cands, 5);
        assert_eq!(holders.len(), 2);
    }

    #[test]
    fn duplicates_collapsed() {
        let cands = vec!["a".to_string(), "a".to_string(), "b".to_string()];
        let holders = select_holders(D, "abc", &cands, 3);
        assert_eq!(holders.len(), 2);
    }

    #[test]
    fn should_replicate_includes_self_in_view() {
        let cands = endpoints(3);
        let selected_somewhere = (0..20)
            .any(|i| should_replicate(D, &format!("c-{i}"), "endpoint-self", &cands, 2));
        assert!(selected_somewhere);
    }

    #[test]
    fn should_replicate_consistent_with_select_holders() {
        let mut cands = endpoints(8);
        cands.push("me".to_string());
        for i in 0..30 {
            let key = format!("x-{i}");
            let holders = select_holders(D, &key, &cands, 3);
            let expected = holders.iter().any(|h| h == "me");
            assert_eq!(should_replicate(D, &key, "me", &cands, 3), expected);
        }
    }

    #[test]
    fn distinct_domains_rank_independently() {
        // Same key + endpoints, different domain tags → generally different
        // holder sets. Verify at least one key diverges across 30 trials.
        let cands = endpoints(12);
        let diverged = (0..30).any(|i| {
            let k = format!("k-{i}");
            select_holders(b"domain/a", &k, &cands, 3)
                != select_holders(b"domain/b", &k, &cands, 3)
        });
        assert!(diverged, "domain tag had no effect on ranking");
    }
}
