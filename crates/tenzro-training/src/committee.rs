//! Witness-committee selection for Tenzro Train multi-syncer coordination.
//!
//! Per `(task_id, round)`, k validators are deterministically drawn from the
//! run's enrolled syncer-eligible validator set to act as witnesses. All k
//! witnesses train normally; the first 2f+1-attested aggregate to land
//! on-chain wins via [`crate::runtime::SyncerState::finalize_round`], which is
//! idempotent under conflicting submissions.
//!
//! # Pattern (matches Nous Psyche on Solana, 2025 and Prime Intellect
//! INTELLECT-2, May 2025)
//!
//! ```text
//! seed = sha256(
//!     "tenzro/training/leader"
//!     || task_id_bytes
//!     || round_le_u32
//!     || chain_entropy_bytes      // finalized block hash at round start
//! )
//! score(v) = sha256(seed || validator_did)
//! committee = top-k validators by ascending score
//! k = min(5, max(3, n / 5))
//! ```
//!
//! The `chain_entropy` argument makes the seed **grinding-resistant**: a
//! sponsor cannot pick a `task_id` that pre-elects a friendly validator,
//! because the block hash at round start is determined after the task is
//! posted. This crate stays chain-agnostic — the node layer plumbs the
//! actual finalized block hash in via `TrainingRuntime`.
//!
//! # Rejected alternatives (zero 2026 production users)
//!
//! - **Hash-mod-N single leader**: predictable DoS target; one bad pod stalls
//!   the round until grace window expires.
//! - **VRF-lowest-output single leader**: extra round-trip + synchrony
//!   assumption; production projects prefer "smart-contract draws from chain
//!   entropy beacon" which is what Psyche does.
//! - **Everyone-writes + Yuma-style on-chain aggregator** (Bittensor): would
//!   require a wholly different consensus path we don't have.

use sha2::{Digest, Sha256};
use tenzro_types::primitives::Hash;

/// Domain tag for committee-selection seed derivation. No version prefix per
/// the `feedback_no_version_prefix_in_identifiers` rule — change the tag
/// itself if the scheme changes incompatibly.
pub const COMMITTEE_SEED_DOMAIN_TAG: &[u8] = b"tenzro/training/leader";

/// Domain tag for per-validator scoring under the committee seed.
pub const COMMITTEE_SCORE_DOMAIN_TAG: &[u8] = b"tenzro/training/leader/score";

/// Compute the committee seed for `(task_id, round)`.
///
/// `chain_entropy` is the **finalized block hash at round start** as observed
/// by the consensus layer. The node-layer caller is responsible for passing
/// the correct value; this function does not reach into consensus state.
pub fn committee_seed(task_id: &str, round: u32, chain_entropy: Hash) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMMITTEE_SEED_DOMAIN_TAG);
    hasher.update(task_id.as_bytes());
    hasher.update(round.to_le_bytes());
    hasher.update(chain_entropy.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Recommended committee size given `n` syncer-eligible validators enrolled
/// for the run: `min(5, max(3, n/5))`, clamped to at most `n`.
///
/// The lower bound 3 lets us tolerate 1 failure; 5 lets us tolerate 1
/// Byzantine + 1 crash. The upper bound 5 keeps coordination overhead bounded
/// — at large fleets (n ≫ 25) we accept that the committee is a small
/// fraction of validators rather than scaling linearly. Revisit only when run
/// sizes routinely exceed 100 syncers.
pub fn recommended_committee_size(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let target = (n / 5).clamp(3, 5);
    target.min(n)
}

/// Select the witness committee deterministically.
///
/// Inputs:
/// - `task_id`: the training task identifier
/// - `round`: round index within the run
/// - `chain_entropy`: finalized block hash at round start (plumbed by node)
/// - `validators`: the run's enrolled syncer-eligible validator DIDs. Order of
///   the input does not matter — output is determined by score ranking.
/// - `k`: committee size (typically [`recommended_committee_size`])
///
/// Returns the chosen DIDs in ascending-score order (canonical). Empty if
/// `validators` is empty or `k == 0`.
pub fn select_witness_committee(
    task_id: &str,
    round: u32,
    chain_entropy: Hash,
    validators: &[String],
    k: usize,
) -> Vec<String> {
    if validators.is_empty() || k == 0 {
        return Vec::new();
    }
    let seed = committee_seed(task_id, round, chain_entropy);
    let mut scored: Vec<(Hash, &String)> = validators
        .iter()
        .map(|did| {
            let mut hasher = Sha256::new();
            hasher.update(COMMITTEE_SCORE_DOMAIN_TAG);
            hasher.update(seed);
            hasher.update(did.as_bytes());
            let digest = hasher.finalize();
            let hash = Hash::from_bytes(&digest).expect("sha256 digest is 32 bytes");
            (hash, did)
        })
        .collect();
    // Stable sort by (score, did) so ties (cryptographically negligible) are
    // broken deterministically. `Hash` orders lexicographically by bytes.
    scored.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()).then_with(|| a.1.cmp(b.1)));
    scored
        .into_iter()
        .take(k.min(validators.len()))
        .map(|(_, did)| did.clone())
        .collect()
}

/// Check whether `local_did` is in the committee for `(task_id, round)`.
/// Convenience for gossip listeners deciding between active-coordinate
/// (witness) vs. passive-observe (non-witness) behavior.
pub fn is_in_committee(
    local_did: &str,
    task_id: &str,
    round: u32,
    chain_entropy: Hash,
    validators: &[String],
    k: usize,
) -> bool {
    select_witness_committee(task_id, round, chain_entropy, validators, k)
        .iter()
        .any(|d| d == local_did)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entropy(byte: u8) -> Hash {
        Hash::from_bytes(&[byte; 32]).unwrap()
    }

    fn validators(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| format!("did:tenzro:machine:validator-{:03}", i))
            .collect()
    }

    #[test]
    fn committee_size_formula() {
        assert_eq!(recommended_committee_size(0), 0);
        assert_eq!(recommended_committee_size(1), 1);
        assert_eq!(recommended_committee_size(2), 2);
        assert_eq!(recommended_committee_size(3), 3);
        assert_eq!(recommended_committee_size(10), 3); // 10/5=2, clamped up to 3
        assert_eq!(recommended_committee_size(15), 3); // 15/5=3
        assert_eq!(recommended_committee_size(20), 4); // 20/5=4
        assert_eq!(recommended_committee_size(25), 5); // 25/5=5
        assert_eq!(recommended_committee_size(100), 5); // capped at 5
    }

    #[test]
    fn empty_inputs_yield_empty_committee() {
        assert!(select_witness_committee("t1", 0, entropy(1), &[], 3).is_empty());
        let vs = validators(5);
        assert!(select_witness_committee("t1", 0, entropy(1), &vs, 0).is_empty());
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let vs = validators(10);
        let a = select_witness_committee("t1", 0, entropy(1), &vs, 3);
        let b = select_witness_committee("t1", 0, entropy(1), &vs, 3);
        assert_eq!(a, b);
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn committee_changes_when_round_advances() {
        let vs = validators(10);
        let a = select_witness_committee("t1", 0, entropy(1), &vs, 3);
        let b = select_witness_committee("t1", 1, entropy(1), &vs, 3);
        // High-probability of difference; if equal, the test is still valid
        // because round advancement should yield independent selection.
        assert_ne!(a, b);
    }

    #[test]
    fn committee_changes_when_entropy_changes() {
        let vs = validators(10);
        let a = select_witness_committee("t1", 0, entropy(1), &vs, 3);
        let b = select_witness_committee("t1", 0, entropy(2), &vs, 3);
        assert_ne!(a, b);
    }

    #[test]
    fn committee_invariant_under_input_permutation() {
        let mut vs = validators(8);
        let a = select_witness_committee("t1", 0, entropy(1), &vs, 3);
        // Reverse the input order — committee must still be the same set.
        vs.reverse();
        let b = select_witness_committee("t1", 0, entropy(1), &vs, 3);
        let mut a_sorted = a.clone();
        let mut b_sorted = b.clone();
        a_sorted.sort();
        b_sorted.sort();
        assert_eq!(a_sorted, b_sorted);
    }

    #[test]
    fn k_capped_at_validator_count() {
        let vs = validators(3);
        let c = select_witness_committee("t1", 0, entropy(1), &vs, 10);
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn is_in_committee_matches_select() {
        let vs = validators(10);
        let committee = select_witness_committee("t1", 0, entropy(1), &vs, 5);
        for did in &committee {
            assert!(is_in_committee(did, "t1", 0, entropy(1), &vs, 5));
        }
        let outside: Vec<&String> = vs.iter().filter(|d| !committee.contains(d)).collect();
        for did in outside {
            assert!(!is_in_committee(did, "t1", 0, entropy(1), &vs, 5));
        }
    }
}
