//! MPC signing-committee selection.
//!
//! Adapted from `tenzro_training::committee::select_witness_committee` —
//! same chain-anchored deterministic-draw pattern, distinct domain tags so
//! a single chain entropy hash can never produce the same committee for
//! both training and MPC.
//!
//! Per `(group_id, epoch, message_hash)`, `t` parties are deterministically
//! drawn from the `n` group members to form the active signing quorum.
//! Validators outside the quorum hold their shares but do not participate in
//! this signature; on quorum failure (timeout or abort), the next attempt
//! redraws with a fresh `chain_entropy`.
//!
//! ```text
//! seed = sha256(
//!     "tenzro/mpc/committee"
//!  || group_id_bytes
//!  || epoch_le_u64
//!  || message_hash
//!  || chain_entropy_bytes      // finalized block hash at session start
//! )
//! score(party_did) = sha256(seed || party_did)
//! quorum = top-threshold parties by ascending score
//! ```
//!
//! The `chain_entropy` argument makes the seed grinding-resistant: a payer
//! cannot pick a `message_hash` that pre-elects a friendly subset of
//! signers, because the finalized block hash at session start is determined
//! after the message is queued. The bridge crate stays chain-agnostic — the
//! node layer plumbs the actual finalized block hash in via the session
//! driver.

use sha2::{Digest, Sha256};
use tenzro_types::Hash;

use crate::mpc::setup::{InstanceId, MpcParameters};
use crate::mpc::sign::{SignConfig, SignError};
use crate::mpc::store::GroupId;

/// Domain tag for committee-selection seed derivation. Distinct from the
/// training-side `tenzro/training/leader` tag so the same chain hash never
/// produces the same committee for both subsystems.
pub const COMMITTEE_SEED_DOMAIN_TAG: &[u8] = b"tenzro/mpc/committee";

/// Domain tag for per-party scoring under the committee seed.
pub const COMMITTEE_SCORE_DOMAIN_TAG: &[u8] = b"tenzro/mpc/committee/score";

/// Compute the committee seed for `(group_id, epoch, message_hash)`.
///
/// `chain_entropy` is the **finalized block hash at session start** as
/// observed by the consensus layer. The node-layer caller is responsible
/// for passing the correct value; this function does not reach into
/// consensus state.
pub fn committee_seed(
    group_id: &GroupId,
    epoch: u64,
    message_hash: &[u8; 32],
    chain_entropy: Hash,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMMITTEE_SEED_DOMAIN_TAG);
    hasher.update(group_id.as_bytes());
    hasher.update(epoch.to_le_bytes());
    hasher.update(message_hash);
    hasher.update(chain_entropy.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Select the signing quorum deterministically. Returns the chosen DIDs in
/// ascending-score order (canonical). Empty if `members` is empty or
/// `threshold == 0`. If `threshold > members.len()`, returns all members.
pub fn select_signing_quorum(
    group_id: &GroupId,
    epoch: u64,
    message_hash: &[u8; 32],
    chain_entropy: Hash,
    members: &[String],
    threshold: usize,
) -> Vec<String> {
    if members.is_empty() || threshold == 0 {
        return Vec::new();
    }
    let seed = committee_seed(group_id, epoch, message_hash, chain_entropy);
    let mut scored: Vec<(Hash, &String)> = members
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
    // Stable sort by (score, did) so cryptographically-negligible ties
    // resolve deterministically across nodes.
    scored.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()).then_with(|| a.1.cmp(b.1)));
    scored
        .into_iter()
        .take(threshold.min(members.len()))
        .map(|(_, did)| did.clone())
        .collect()
}

/// Outcome of a committee-bound `SignConfig` resolution. Either the local
/// party is in the drawn quorum (and a ready-to-use [`SignConfig`] is
/// returned), or the local party is not in the quorum for this session — in
/// which case the bridge adapter should hold its share and wait without
/// dispatching a `SignSession`. The third variant covers under-stake (the
/// group does not have enough live members to form a threshold quorum).
#[derive(Clone, Debug)]
pub enum CommitteeRole {
    /// Local party is in the drawn quorum. The carried [`SignConfig`] passes
    /// `SignConfig::validate()` and is ready to feed into `SignSession::new`.
    Participant(SignConfig),
    /// Local party holds a share but was not drawn for this session.
    Observer { quorum: Vec<String> },
    /// `members.len() < threshold` — the group cannot form a signing quorum.
    /// The bridge router should reject the transaction with a clear error
    /// rather than silently waiting.
    UnderQuorum { available: usize, threshold: u8 },
}

/// Build a committee-bound [`SignConfig`] for the local party.
///
/// Combines [`select_signing_quorum`] with the `SignConfig` shape so the
/// node-layer bridge adapter has a single entry point that handles draw,
/// admission, and config assembly atomically. Returns [`CommitteeRole`] so
/// the caller can distinguish the three outcomes without exception flow.
///
/// `group_members` is the full set of DKG participants for `(group_id, epoch)`
/// — typically read from the [`crate::mpc::store::KeyshareStore`] or a
/// node-layer group registry. `chain_entropy` is the finalized block hash at
/// session start (plumbed from consensus by the caller).
pub fn build_committee_bound_sign_config(
    instance_id: InstanceId,
    group_id: GroupId,
    epoch: u64,
    parameters: MpcParameters,
    group_public_key_compressed: Vec<u8>,
    message_hash: [u8; 32],
    chain_entropy: Hash,
    group_members: &[String],
    local_did: &str,
) -> Result<CommitteeRole, SignError> {
    let threshold = parameters.threshold;
    if group_members.len() < threshold as usize {
        return Ok(CommitteeRole::UnderQuorum {
            available: group_members.len(),
            threshold,
        });
    }
    let quorum = select_signing_quorum(
        &group_id,
        epoch,
        &message_hash,
        chain_entropy,
        group_members,
        threshold as usize,
    );
    // `select_signing_quorum` returns ascending-score order; `SignConfig`
    // expects DID-ascending order so all parties derive the same DKLS23
    // `PartyIndex` mapping. Re-sort here so the score-order is opaque to the
    // session driver.
    let mut quorum_sorted = quorum.clone();
    quorum_sorted.sort();
    if !quorum_sorted.iter().any(|d| d == local_did) {
        return Ok(CommitteeRole::Observer {
            quorum: quorum_sorted,
        });
    }
    let cfg = SignConfig {
        instance_id,
        group_id,
        epoch,
        parameters,
        group_public_key_compressed,
        message_hash,
        quorum_dids: quorum_sorted,
        local_did: local_did.to_string(),
    };
    cfg.validate()?;
    Ok(CommitteeRole::Participant(cfg))
}

/// Check whether `local_did` is in the signing quorum for the given session.
pub fn is_in_quorum(
    local_did: &str,
    group_id: &GroupId,
    epoch: u64,
    message_hash: &[u8; 32],
    chain_entropy: Hash,
    members: &[String],
    threshold: usize,
) -> bool {
    select_signing_quorum(group_id, epoch, message_hash, chain_entropy, members, threshold)
        .iter()
        .any(|d| d == local_did)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_group() -> GroupId {
        GroupId([7u8; 32])
    }

    fn entropy(byte: u8) -> Hash {
        Hash::from_bytes(&[byte; 32]).unwrap()
    }

    fn members(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| format!("did:tenzro:machine:signer-{:03}", i))
            .collect()
    }

    #[test]
    fn empty_inputs_yield_empty_quorum() {
        let g = sample_group();
        assert!(select_signing_quorum(&g, 0, &[1u8; 32], entropy(1), &[], 2).is_empty());
        let m = members(5);
        assert!(select_signing_quorum(&g, 0, &[1u8; 32], entropy(1), &m, 0).is_empty());
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let g = sample_group();
        let m = members(7);
        let a = select_signing_quorum(&g, 1, &[9u8; 32], entropy(1), &m, 3);
        let b = select_signing_quorum(&g, 1, &[9u8; 32], entropy(1), &m, 3);
        assert_eq!(a, b);
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn quorum_changes_when_message_changes() {
        let g = sample_group();
        let m = members(7);
        let a = select_signing_quorum(&g, 0, &[1u8; 32], entropy(1), &m, 3);
        let b = select_signing_quorum(&g, 0, &[2u8; 32], entropy(1), &m, 3);
        assert_ne!(a, b);
    }

    #[test]
    fn quorum_changes_when_entropy_changes() {
        let g = sample_group();
        let m = members(7);
        let a = select_signing_quorum(&g, 0, &[1u8; 32], entropy(1), &m, 3);
        let b = select_signing_quorum(&g, 0, &[1u8; 32], entropy(2), &m, 3);
        assert_ne!(a, b);
    }

    #[test]
    fn quorum_invariant_under_member_permutation() {
        let g = sample_group();
        let mut m = members(8);
        let a = select_signing_quorum(&g, 0, &[1u8; 32], entropy(1), &m, 3);
        m.reverse();
        let b = select_signing_quorum(&g, 0, &[1u8; 32], entropy(1), &m, 3);
        let mut a_sorted = a.clone();
        let mut b_sorted = b.clone();
        a_sorted.sort();
        b_sorted.sort();
        assert_eq!(a_sorted, b_sorted);
    }

    #[test]
    fn threshold_capped_at_member_count() {
        let g = sample_group();
        let m = members(3);
        let q = select_signing_quorum(&g, 0, &[1u8; 32], entropy(1), &m, 10);
        assert_eq!(q.len(), 3);
    }

    fn sample_parameters() -> MpcParameters {
        MpcParameters {
            curve: crate::mpc::setup::MpcCurve::Secp256k1,
            threshold: 3,
            total_parties: 5,
        }
    }

    fn sample_instance_id() -> InstanceId {
        use crate::mpc::setup::SESSION_NONCE_LEN;
        let block = Hash::from_bytes(&[2u8; 32]).unwrap();
        InstanceId::derive(&block, &[0u8; 32], &[7u8; SESSION_NONCE_LEN])
    }

    fn sample_group_pk() -> Vec<u8> {
        // A valid SEC1-compressed point is not required for the committee
        // helper itself — it only stamps the bytes into the returned config.
        // `SignSession::new` (downstream) is where the point is decoded.
        let mut v = vec![0x02];
        v.extend_from_slice(&[0u8; 32]);
        v
    }

    #[test]
    fn committee_bound_participant_when_local_drawn() {
        let g = sample_group();
        let members = members(5);
        let params = sample_parameters();
        // Find a member that will be drawn by trying each as local_did. At
        // least one of the five members must end up in any 3-of-5 draw.
        let drawn = select_signing_quorum(&g, 0, &[1u8; 32], entropy(1), &members, 3);
        let local = &drawn[0];
        let role = build_committee_bound_sign_config(
            sample_instance_id(),
            g,
            0,
            params,
            sample_group_pk(),
            [1u8; 32],
            entropy(1),
            &members,
            local,
        )
        .expect("valid inputs must not error");
        match role {
            CommitteeRole::Participant(cfg) => {
                assert_eq!(cfg.quorum_dids.len(), 3);
                assert!(cfg.quorum_dids.iter().any(|d| d == local));
                // Quorum must be DID-ascending (canonical).
                let mut sorted = cfg.quorum_dids.clone();
                sorted.sort();
                assert_eq!(cfg.quorum_dids, sorted);
            }
            other => panic!("expected Participant, got {:?}", other),
        }
    }

    #[test]
    fn committee_bound_observer_when_local_not_drawn() {
        let g = sample_group();
        let members = members(5);
        let params = sample_parameters();
        let drawn = select_signing_quorum(&g, 0, &[1u8; 32], entropy(1), &members, 3);
        // Find a member NOT in the drawn quorum.
        let outsider = members
            .iter()
            .find(|d| !drawn.contains(d))
            .expect("3-of-5 leaves 2 outsiders");
        let role = build_committee_bound_sign_config(
            sample_instance_id(),
            g,
            0,
            params,
            sample_group_pk(),
            [1u8; 32],
            entropy(1),
            &members,
            outsider,
        )
        .expect("valid inputs must not error");
        match role {
            CommitteeRole::Observer { quorum } => {
                assert_eq!(quorum.len(), 3);
                assert!(!quorum.iter().any(|d| d == outsider));
            }
            other => panic!("expected Observer, got {:?}", other),
        }
    }

    #[test]
    fn committee_bound_under_quorum_when_too_few_members() {
        let g = sample_group();
        let members = members(2); // less than threshold=3
        let params = sample_parameters();
        let role = build_committee_bound_sign_config(
            sample_instance_id(),
            g,
            0,
            params,
            sample_group_pk(),
            [1u8; 32],
            entropy(1),
            &members,
            &members[0],
        )
        .expect("under-quorum is a CommitteeRole variant, not an error");
        match role {
            CommitteeRole::UnderQuorum { available, threshold } => {
                assert_eq!(available, 2);
                assert_eq!(threshold, 3);
            }
            other => panic!("expected UnderQuorum, got {:?}", other),
        }
    }

    #[test]
    fn is_in_quorum_matches_select() {
        let g = sample_group();
        let m = members(10);
        let q = select_signing_quorum(&g, 0, &[1u8; 32], entropy(1), &m, 5);
        for did in &q {
            assert!(is_in_quorum(did, &g, 0, &[1u8; 32], entropy(1), &m, 5));
        }
        let outside: Vec<&String> = m.iter().filter(|d| !q.contains(d)).collect();
        for did in outside {
            assert!(!is_in_quorum(did, &g, 0, &[1u8; 32], entropy(1), &m, 5));
        }
    }

    #[test]
    fn committee_bound_participant_emits_valid_sign_config() {
        // Belt-and-braces: the SignConfig returned by Participant must pass
        // SignConfig::validate() on the consumer side. Catches any drift
        // between the sort-and-stamp logic in build_committee_bound_sign_config
        // and SignConfig's invariants.
        let g = sample_group();
        let members = members(7);
        let params = sample_parameters();
        let drawn = select_signing_quorum(&g, 0, &[1u8; 32], entropy(1), &members, 3);
        let local = &drawn[0];
        let role = build_committee_bound_sign_config(
            sample_instance_id(),
            g,
            0,
            params,
            sample_group_pk(),
            [1u8; 32],
            entropy(1),
            &members,
            local,
        )
        .expect("valid inputs must not error");
        match role {
            CommitteeRole::Participant(cfg) => {
                // The validate() pass inside build_committee_bound_sign_config
                // must not silently lose any of its checks; rerun here to
                // assert downstream consumers can trust the config.
                cfg.validate()
                    .expect("Participant SignConfig must satisfy SignConfig::validate()");
                // local_party_index must round-trip.
                let idx = cfg.local_party_index().unwrap();
                assert!(idx >= 1 && idx <= cfg.parameters.threshold);
            }
            other => panic!("expected Participant, got {:?}", other),
        }
    }

    #[test]
    fn committee_bound_redraws_when_chain_entropy_changes() {
        // Grinding resistance: changing only chain_entropy (with everything
        // else fixed) must redraw a different quorum, so a payer cannot
        // pre-elect signers by choosing the message hash. This complements
        // the unit-level `quorum_changes_when_entropy_changes` test by
        // verifying the property end-to-end through the higher-level
        // build_committee_bound_sign_config entry point.
        let g = sample_group();
        let members = members(7);
        let params = sample_parameters();
        let message_hash = [0xAB; 32];

        let extract_quorum = |chain_entropy: Hash| -> Vec<String> {
            // Use the first member as `local`; we only care about the quorum
            // contents, not which role we land in.
            let role = build_committee_bound_sign_config(
                sample_instance_id(),
                g,
                0,
                params,
                sample_group_pk(),
                message_hash,
                chain_entropy,
                &members,
                &members[0],
            )
            .expect("valid inputs must not error");
            match role {
                CommitteeRole::Participant(cfg) => cfg.quorum_dids.clone(),
                CommitteeRole::Observer { quorum } => quorum.clone(),
                CommitteeRole::UnderQuorum { .. } => {
                    panic!("members(7) ≥ threshold(3) must not yield UnderQuorum")
                }
            }
        };

        let q_a = extract_quorum(entropy(1));
        let q_b = extract_quorum(entropy(2));
        assert_ne!(
            q_a, q_b,
            "chain_entropy must seed the draw — identical entropies would let a payer grind message_hash"
        );
    }
}
