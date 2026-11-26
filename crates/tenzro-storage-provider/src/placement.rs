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
//! The score is the engine-agnostic [`tenzro_cluster::hrw_score`] primitive;
//! this module pins the storage domain tag so shard placement never collides
//! with database-partition placement over the same endpoint ids.
//!
//! [`select_ranked_holders`] / [`should_replicate_ranked`] rank by what the
//! chain records about each candidate: a share of the replicas goes to
//! candidates with no record yet, so a new provider can earn one, and the rest
//! favour candidates by their standing. Every node reads the same standings
//! from the same chain state, so self-selection still agrees across nodes.

/// Most entries in each list of a [`PlacementConstraint`].
pub const MAX_CONSTRAINT_ENTRIES: usize = 16;

/// A buyer's rule for where an object's shards may be held: in one of the
/// listed countries, by one of the listed operators, or both. An empty list
/// does not constrain. Holders are judged by what they declare: the coarse
/// region of their provider announcement and the account it names. A region
/// is a claim the operator makes, not a geolocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlacementConstraint {
    /// Upper-case ISO 3166-1 alpha-2 country codes, any of which a holder's
    /// declared region must be.
    pub jurisdiction: Vec<String>,
    /// Lower-case hex provider accounts, without `0x`, one of which must
    /// run the holder.
    pub operators: Vec<String>,
}

impl PlacementConstraint {
    /// A constraint from caller input: country codes upper-cased, accounts
    /// lower-cased without `0x`, each list sorted without duplicates. Refuses
    /// an empty constraint, a token that is not a country code or an
    /// account, and more than [`MAX_CONSTRAINT_ENTRIES`] in a list.
    pub fn new(jurisdiction: &[String], operators: &[String]) -> Result<Self, String> {
        let mut jurisdiction: Vec<String> = jurisdiction
            .iter()
            .map(|c| c.trim().to_ascii_uppercase())
            .collect();
        let mut operators: Vec<String> = operators
            .iter()
            .map(|o| o.trim().trim_start_matches("0x").to_ascii_lowercase())
            .collect();
        jurisdiction.sort();
        jurisdiction.dedup();
        operators.sort();
        operators.dedup();
        if jurisdiction.is_empty() && operators.is_empty() {
            return Err("a placement constraint names countries, operators or both".into());
        }
        if jurisdiction.len() > MAX_CONSTRAINT_ENTRIES || operators.len() > MAX_CONSTRAINT_ENTRIES {
            return Err(format!(
                "a placement constraint lists at most {MAX_CONSTRAINT_ENTRIES} countries and \
                 {MAX_CONSTRAINT_ENTRIES} operators"
            ));
        }
        if let Some(bad) = jurisdiction
            .iter()
            .find(|c| c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase()))
        {
            return Err(format!("'{bad}' is not a two-letter country code"));
        }
        if let Some(bad) = operators
            .iter()
            .find(|o| o.len() != 64 || !o.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(format!("'{bad}' is not a 32-byte account in hex"));
        }
        Ok(Self {
            jurisdiction,
            operators,
        })
    }

    /// Whether a holder that declares `region` and is run by the account
    /// `operator` (hex, with or without `0x`) may hold a shard. A holder
    /// that declares no region never meets a country rule.
    pub fn admits(&self, region: Option<&str>, operator: &str) -> bool {
        let operator = operator.trim_start_matches("0x").to_ascii_lowercase();
        (self.jurisdiction.is_empty()
            || region.is_some_and(|r| self.jurisdiction.iter().any(|c| c.eq_ignore_ascii_case(r))))
            && (self.operators.is_empty() || self.operators.contains(&operator))
    }

    /// SHA-256 over a domain tag and the length-prefixed entries: what a
    /// holding receipt names the constraint by.
    pub fn digest(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(CONSTRAINT_DOMAIN);
        for list in [&self.jurisdiction, &self.operators] {
            h.update((list.len() as u32).to_le_bytes());
            for entry in list {
                h.update((entry.len() as u32).to_le_bytes());
                h.update(entry.as_bytes());
            }
        }
        h.finalize().into()
    }
}

/// Domain tag of [`PlacementConstraint::digest`].
const CONSTRAINT_DOMAIN: &[u8] = b"tenzro/storage/placement-constraint/v1";

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

/// One candidate holder and what the chain records about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedCandidate {
    /// The candidate's iroh endpoint id.
    pub endpoint_id: String,
    /// Its standing, `0..=10_000`, read from consensus state.
    pub standing: u64,
    /// Whether any of its hours in the standing window were judged: false
    /// for a provider with no record yet.
    pub judged: bool,
}

fn hrw_u64(commitment: &str, endpoint_id: &str) -> u64 {
    u64::from_be_bytes(
        hrw_score(commitment, endpoint_id)[..8]
            .try_into()
            .expect("8 bytes"),
    )
}

/// `list` ranked by plain HRW for `commitment`, best first.
fn by_hrw<'a>(commitment: &str, mut list: Vec<&'a RankedCandidate>) -> Vec<&'a RankedCandidate> {
    list.sort_by_key(|c| std::cmp::Reverse(hrw_score(commitment, &c.endpoint_id)));
    list
}

/// The holders of a shard: up to `new_share_bps` of `replicas` (rounded up)
/// from candidates with no record, ranked by HRW; then candidates with a
/// record and a standing above zero, ranked by HRW scaled by standing, so a
/// better record wins more shards; then anyone left, by HRW, when there are
/// too few. Duplicate endpoint ids count once.
pub fn select_ranked_holders(
    commitment: &str,
    candidates: &[RankedCandidate],
    replicas: usize,
    new_share_bps: u64,
) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let unique: Vec<&RankedCandidate> = candidates
        .iter()
        .filter(|c| seen.insert(c.endpoint_id.as_str()))
        .collect();
    let reserved = (replicas as u64 * new_share_bps.min(10_000)).div_ceil(10_000) as usize;
    let mut chosen: Vec<String> = by_hrw(
        commitment,
        unique.iter().copied().filter(|c| !c.judged).collect(),
    )
    .into_iter()
    .take(reserved.min(replicas))
    .map(|c| c.endpoint_id.clone())
    .collect();
    let mut recorded: Vec<&RankedCandidate> = unique
        .iter()
        .copied()
        .filter(|c| c.judged && c.standing > 0)
        .collect();
    recorded.sort_by_key(|c| {
        std::cmp::Reverse((
            u128::from(c.standing) * u128::from(hrw_u64(commitment, &c.endpoint_id)),
            hrw_score(commitment, &c.endpoint_id),
        ))
    });
    for c in recorded {
        if chosen.len() == replicas {
            break;
        }
        chosen.push(c.endpoint_id.clone());
    }
    let rest: Vec<&RankedCandidate> = unique
        .iter()
        .copied()
        .filter(|c| !chosen.contains(&c.endpoint_id))
        .collect();
    for c in by_hrw(commitment, rest) {
        if chosen.len() == replicas {
            break;
        }
        chosen.push(c.endpoint_id.clone());
    }
    chosen
}

/// Whether `own_endpoint_id`, one of `candidates`, holds the shard under
/// [`select_ranked_holders`].
pub fn should_replicate_ranked(
    commitment: &str,
    own_endpoint_id: &str,
    candidates: &[RankedCandidate],
    replicas: usize,
    new_share_bps: u64,
) -> bool {
    select_ranked_holders(commitment, candidates, replicas, new_share_bps)
        .iter()
        .any(|c| c == own_endpoint_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OP: &str = "ab0000000000000000000000000000000000000000000000000000000000000c";

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_constraint_is_normalised_and_refuses_what_it_cannot_judge() {
        let c = PlacementConstraint::new(&strings(&["de", "FR", "DE"]), &[]).unwrap();
        assert_eq!(c.jurisdiction, strings(&["DE", "FR"]));
        let upper = format!("0x{}", OP.to_uppercase());
        let c = PlacementConstraint::new(&[], &[upper]).unwrap();
        assert_eq!(c.operators, strings(&[OP]));
        assert!(PlacementConstraint::new(&[], &[]).is_err(), "empty");
        assert!(
            PlacementConstraint::new(&strings(&["EU"]), &[]).is_ok(),
            "two letters"
        );
        assert!(PlacementConstraint::new(&strings(&["europe"]), &[]).is_err());
        assert!(PlacementConstraint::new(&strings(&["D1"]), &[]).is_err());
        assert!(PlacementConstraint::new(&[], &strings(&["abc"])).is_err());
        let many: Vec<String> = (0..=MAX_CONSTRAINT_ENTRIES)
            .map(|i| {
                format!(
                    "{}{}",
                    (b'A' + (i / 26) as u8) as char,
                    (b'A' + (i % 26) as u8) as char
                )
            })
            .collect();
        assert!(PlacementConstraint::new(&many, &[]).is_err());
    }

    #[test]
    fn a_holder_is_admitted_only_inside_every_rule() {
        let c = PlacementConstraint::new(&strings(&["DE", "FR"]), &strings(&[OP])).unwrap();
        assert!(c.admits(Some("DE"), OP));
        assert!(c.admits(Some("fr"), &format!("0x{OP}")));
        assert!(!c.admits(Some("US"), OP), "outside the countries");
        assert!(!c.admits(Some("europe"), OP), "a wide region is no country");
        assert!(!c.admits(None, OP), "no declared region");
        assert!(!c.admits(Some("DE"), &"00".repeat(32)), "another operator");
        let anywhere_by_op = PlacementConstraint::new(&[], &strings(&[OP])).unwrap();
        assert!(anywhere_by_op.admits(None, OP));
    }

    #[test]
    fn the_digest_names_the_normalised_constraint() {
        let a = PlacementConstraint::new(&strings(&["fr", "DE"]), &[]).unwrap();
        let b = PlacementConstraint::new(&strings(&["DE", "FR", "DE"]), &[]).unwrap();
        assert_eq!(a.digest(), b.digest());
        let c = PlacementConstraint::new(&strings(&["DE"]), &[]).unwrap();
        assert_ne!(a.digest(), c.digest());
        // Lists are length-prefixed: one country cannot pass for an operator.
        let d = PlacementConstraint::new(&[], &strings(&[OP])).unwrap();
        assert_ne!(c.digest(), d.digest());
    }

    fn ranked(id: &str, standing: u64, judged: bool) -> RankedCandidate {
        RankedCandidate {
            endpoint_id: id.into(),
            standing,
            judged,
        }
    }

    #[test]
    fn every_candidate_agrees_on_exactly_the_holders() {
        let candidates: Vec<RankedCandidate> = (0..8)
            .map(|i| ranked(&format!("node-{i}"), 1_000 * (i + 1), i % 3 != 0))
            .collect();
        for shard in ["c0", "c1", "c2", "c3"] {
            let holders = select_ranked_holders(shard, &candidates, 3, 2_000);
            assert_eq!(holders.len(), 3);
            let selecting: Vec<&str> = candidates
                .iter()
                .filter(|c| should_replicate_ranked(shard, &c.endpoint_id, &candidates, 3, 2_000))
                .map(|c| c.endpoint_id.as_str())
                .collect();
            assert_eq!(
                selecting.len(),
                3,
                "{shard}: every node must reach the same holders"
            );
            assert!(selecting.iter().all(|c| holders.iter().any(|h| h == c)));
        }
    }

    #[test]
    fn a_provider_with_no_record_takes_the_reserved_share() {
        let mut candidates: Vec<RankedCandidate> = (0..5)
            .map(|i| ranked(&format!("old-{i}"), 10_000, true))
            .collect();
        candidates.push(ranked("new", 0, false));
        for shard in ["a", "b", "c"] {
            assert!(
                select_ranked_holders(shard, &candidates, 3, 2_000).contains(&"new".to_string())
            );
            assert!(!select_ranked_holders(shard, &candidates, 3, 0).contains(&"new".to_string()));
        }
        // Too few recorded candidates: the new one fills even without a share.
        let few = vec![ranked("old", 10_000, true), ranked("new", 0, false)];
        assert_eq!(select_ranked_holders("a", &few, 2, 0).len(), 2);
    }

    #[test]
    fn a_better_record_wins_more_shards() {
        let candidates = vec![ranked("good", 10_000, true), ranked("poor", 1_000, true)];
        let good = (0..500)
            .filter(|i| {
                select_ranked_holders(&format!("shard-{i}"), &candidates, 1, 0)[0] == "good"
            })
            .count();
        assert!(
            good > 400,
            "the better record should win most shards, won {good}/500"
        );
    }

    #[test]
    fn a_judged_provider_with_no_standing_only_fills() {
        let candidates = vec![
            ranked("zero", 0, true),
            ranked("a", 5_000, true),
            ranked("b", 5_000, true),
        ];
        for shard in ["x", "y", "z"] {
            assert!(!select_ranked_holders(shard, &candidates, 2, 0).contains(&"zero".to_string()));
        }
        assert_eq!(select_ranked_holders("x", &candidates, 3, 0).len(), 3);
        assert!(select_ranked_holders("x", &candidates, 0, 2_000).is_empty());
    }
}
