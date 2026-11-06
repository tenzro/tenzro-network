// SPDX-License-Identifier: Apache-2.0
//! Tenzro governance decisions on other chains.
//!
//! When governance enacts a proposal, consensus state records
//! `governance_decision:<proposal_id>` as the SHA-256 of the executed
//! proposal record (32) followed by the enacting height (8, big-endian). A
//! contract accepts the decision by checking that record with a state proof
//! under a final checkpoint's state root.

/// Length of a decision record.
pub const DECISION_LEN: usize = 40;

/// The state tree key of proposal `proposal_id`'s decision record.
pub fn decision_tree_key(proposal_id: &[u8; 32]) -> [u8; 32] {
    crate::state_proof::system_slot_tree_key(b"governance_decision:", proposal_id)
}

/// The decision record of a proposal whose executed record hashes to
/// `record_hash`, enacted at `height`.
pub fn decision(record_hash: &[u8; 32], height: u64) -> [u8; DECISION_LEN] {
    let mut out = [0u8; DECISION_LEN];
    out[..32].copy_from_slice(record_hash);
    out[32..].copy_from_slice(&height.to_be_bytes());
    out
}

/// Whether, under `root`, proposal `proposal_id` was enacted at `height`
/// with its executed record hashing to `record_hash`, by `proof`.
pub fn proven_decision(root: &[u8; 32], proposal_id: &[u8; 32], record_hash: &[u8; 32], height: u64, proof: &[u8]) -> bool {
    crate::state_proof::verify_at(root, &decision_tree_key(proposal_id), Some(&decision(record_hash, height)), proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        let text = include_str!("../../../sdk/fixtures/governance_receipt/vectors.json");
        serde_json::from_str(text).unwrap()
    }

    fn b32(v: &serde_json::Value, k: &str) -> [u8; 32] {
        hex::decode(v[k].as_str().unwrap()).unwrap().try_into().unwrap()
    }

    #[test]
    fn a_real_decision_verifies_and_nothing_else_does() {
        let v = vectors();
        let (root, id, hash) = (b32(&v, "state_root"), b32(&v, "proposal_id"), b32(&v, "proposal_record_hash"));
        let height = v["executed_height"].as_u64().unwrap();
        let proof = hex::decode(v["decision_proof"].as_str().unwrap()).unwrap();
        assert_eq!(decision_tree_key(&id), b32(&v, "decision_tree_key"));
        assert!(proven_decision(&root, &id, &hash, height, &proof));
        assert!(!proven_decision(&root, &id, &hash, height + 1, &proof));
        assert!(!proven_decision(&root, &b32(&v, "absent_proposal_id"), &hash, height, &proof));
        let absent = hex::decode(v["absent_decision_proof"].as_str().unwrap()).unwrap();
        assert!(crate::state_proof::verify_at(&root, &b32(&v, "absent_decision_tree_key"), None, &absent));
    }
}
