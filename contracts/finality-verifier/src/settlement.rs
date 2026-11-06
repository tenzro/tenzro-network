//! Settlement-plan legs on other chains: the ids Tenzro gives them, the
//! decision commitment a lock proves before it releases or refunds, and the
//! receipt of each leg's outcome.
//!
//! The commitment at `decision:<plan_id>` is
//! `version (1) || outcome (1: 1 commit, 2 abort) || decided_at_ms (8, big
//! endian) || plan_id (32)`.

use sha2::{Digest, Sha256};

/// Length of a decision commitment.
pub const DECISION_LEN: usize = 42;

/// A plan's proven outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Pay the leg's recipient.
    Commit,
    /// Refund the leg's payer.
    Abort,
}

/// The id of leg `index` of plan `plan_id`.
pub fn leg_id(plan_id: &[u8; 32], index: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro/plan/leg/v1");
    h.update(plan_id);
    h.update([index]);
    h.finalize().into()
}

/// Domain of a settlement lock's running reconciliation hash.
pub const RECON_DOMAIN: &[u8] = b"tenzro/settlement/recon/v1";
/// Reconciliation entry kinds: a leg locked, released, refunded.
pub const RECON_LOCKED: u8 = 1;
pub const RECON_RELEASED: u8 = 2;
pub const RECON_REFUNDED: u8 = 3;

/// Fold one lock entry into a running reconciliation hash:
/// `sha256(RECON_DOMAIN || acc || plan_id || leg_id || kind || amount)`,
/// the amount as a 32-byte big-endian word, from zero in recording order.
pub fn recon_step(acc: &[u8; 32], plan_id: &[u8; 32], leg_id: &[u8; 32], kind: u8, amount: u128) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RECON_DOMAIN);
    h.update(acc);
    h.update(plan_id);
    h.update(leg_id);
    h.update([kind]);
    h.update([0u8; 16]);
    h.update(amount.to_be_bytes());
    h.finalize().into()
}

/// A lock's reconciliation checkpoint as Tenzro reads it: `count (8, big
/// endian) || acc`.
pub fn recon_checkpoint(count: u64, acc: &[u8; 32]) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..8].copy_from_slice(&count.to_be_bytes());
    out[8..].copy_from_slice(acc);
    out
}

/// The state tree key of `decision:<plan_id>` (VM system storage, keyed by
/// the hex of the record key).
pub fn decision_tree_key(plan_id: &[u8; 32]) -> [u8; 32] {
    crate::state_proof::system_slot_tree_key(b"decision:", plan_id)
}

/// The outcome a decision commitment for `plan_id` records, if it is one.
pub fn decode_decision(plan_id: &[u8; 32], decision: &[u8]) -> Option<Outcome> {
    if decision.len() != DECISION_LEN || decision[0] != 1 || &decision[10..] != plan_id.as_slice() {
        return None;
    }
    match decision[1] {
        1 => Some(Outcome::Commit),
        2 => Some(Outcome::Abort),
        _ => None,
    }
}

/// The outcome of plan `plan_id`, if `decision` is its commitment and
/// `proof` proves it under `root`.
pub fn proven_outcome(root: &[u8; 32], plan_id: &[u8; 32], decision: &[u8], proof: &[u8]) -> Option<Outcome> {
    let outcome = decode_decision(plan_id, decision)?;
    crate::state_proof::verify_at(root, &decision_tree_key(plan_id), Some(decision), proof).then_some(outcome)
}

/// Length of a leg receipt at `plr:<leg_id>`.
pub const LEG_RECEIPT_LEN: usize = 189;

/// One leg's outcome as Tenzro recorded it at `plr:<leg_id>`:
/// `version (1) || outcome (1: 1 commit, 2 abort) || index (1) || class (1:
/// 0 none, 1 native, 2 proven, 3 attested) || flags (1: bit 0 proof digest,
/// bit 1 compensation, bit 2 relayer) || decided_at_ms (8) || plan_id (32) ||
/// leg_id (32) || amount (16) || network_fee (16) || compensation (16) ||
/// proof_digest (32) || relayer (32)`, integers big endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegReceipt {
    /// The plan.
    pub plan_id: [u8; 32],
    /// Index of the leg in the plan.
    pub index: u8,
    /// The plan committed (or aborted).
    pub committed: bool,
    /// The evidence class the leg reached: 0 none, 1 native, 2 proven, 3
    /// attested.
    pub class: u8,
    /// Block time of the decision, ms.
    pub decided_at_ms: u64,
    /// The leg's value, wei.
    pub amount: u128,
    /// The network fee the commit repaid the leg's relayer, wei.
    pub network_fee: u128,
    /// A rail leg's compensation, wei, if one was paid.
    pub compensation: Option<u128>,
    /// Digest of the evidence that proved the leg, if any.
    pub proof_digest: Option<[u8; 32]>,
    /// The Tenzro account of the relayer that carried the leg's proof, if one did.
    pub relayer: Option<[u8; 32]>,
}

/// The state tree key of `plr:<leg_id>`.
pub fn leg_receipt_tree_key(leg_id: &[u8; 32]) -> [u8; 32] {
    crate::state_proof::system_slot_tree_key(b"plr:", leg_id)
}

/// The receipt `bytes` records for leg `leg_id`, if it is one.
pub fn decode_leg_receipt(leg_id: &[u8; 32], bytes: &[u8]) -> Option<LegReceipt> {
    if bytes.len() != LEG_RECEIPT_LEN || bytes[0] != 1 || bytes[3] > 3 || bytes[4] & !0b111 != 0 {
        return None;
    }
    if &bytes[45..77] != leg_id.as_slice() {
        return None;
    }
    let b32 = |at: usize| -> [u8; 32] { bytes[at..at + 32].try_into().expect("32 bytes") };
    let u128_at = |at: usize| u128::from_be_bytes(bytes[at..at + 16].try_into().expect("16 bytes"));
    let flag = |bit: u8| bytes[4] & (1 << bit) != 0;
    let plan_id = b32(13);
    if crate::settlement::leg_id(&plan_id, bytes[2]) != *leg_id {
        return None;
    }
    Some(LegReceipt {
        plan_id,
        index: bytes[2],
        committed: match bytes[1] {
            1 => true,
            2 => false,
            _ => return None,
        },
        class: bytes[3],
        decided_at_ms: u64::from_be_bytes(bytes[5..13].try_into().expect("8 bytes")),
        amount: u128_at(77),
        network_fee: u128_at(93),
        compensation: flag(1).then(|| u128_at(109)),
        proof_digest: flag(0).then(|| b32(125)),
        relayer: flag(2).then(|| b32(157)),
    })
}

/// Leg `leg_id`'s receipt, if `bytes` is it and `proof` proves it under `root`.
pub fn proven_leg_receipt(root: &[u8; 32], leg_id: &[u8; 32], bytes: &[u8], proof: &[u8]) -> Option<LegReceipt> {
    let receipt = decode_leg_receipt(leg_id, bytes)?;
    crate::state_proof::verify_at(root, &leg_receipt_tree_key(leg_id), Some(bytes), proof).then_some(receipt)
}

/// Where a locked leg stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegState {
    /// Funds held, no decision applied.
    Locked,
    /// Paid to the recipient on a proven commit.
    Released,
    /// Returned to the payer, on a proven abort or after the escape horizon.
    Refunded,
}

/// Why a lock refuses to settle or release a leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegError {
    /// The leg is not locked, or was already settled.
    NotLocked,
    /// The decision is not a commitment for this plan, or its proof does not
    /// verify under the checkpoint's root.
    Unproven,
    /// The escape horizon has not passed.
    TooEarly,
}

/// Apply the decision of plan `plan_id` to a leg in `state`: the leg's next
/// state when `decision` is the plan's commitment proven by `proof` under
/// `root`. Every lock settles through this, so a leg moves once and only on
/// a proven outcome.
pub fn settle_leg(state: LegState, root: &[u8; 32], plan_id: &[u8; 32], decision: &[u8], proof: &[u8]) -> Result<LegState, LegError> {
    if state != LegState::Locked {
        return Err(LegError::NotLocked);
    }
    match proven_outcome(root, plan_id, decision, proof).ok_or(LegError::Unproven)? {
        Outcome::Commit => Ok(LegState::Released),
        Outcome::Abort => Ok(LegState::Refunded),
    }
}

/// Refund an undecided leg in `state` once `now` reaches its `escape_at`.
pub fn escape_leg(state: LegState, now: u64, escape_at: u64) -> Result<LegState, LegError> {
    if state != LegState::Locked {
        return Err(LegError::NotLocked);
    }
    if now < escape_at {
        return Err(LegError::TooEarly);
    }
    Ok(LegState::Refunded)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn hex32(v: &serde_json::Value) -> [u8; 32] {
        hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap().try_into().unwrap()
    }

    fn bytes(v: &serde_json::Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
    }

    #[test]
    fn the_shared_vectors_prove_each_outcome_and_nothing_else() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../sdk/fixtures/settlement_lock/vectors.json")).unwrap();
        let root = hex32(&v["root"]);
        let committed = hex32(&v["committed"]["plan_id"]);
        let aborted = hex32(&v["aborted"]["plan_id"]);
        let undecided = hex32(&v["undecided"]["plan_id"]);
        assert_eq!(decision_tree_key(&committed), hex32(&v["committed"]["tree_key"]));
        assert_eq!(leg_id(&committed, 2), hex32(&v["committed"]["leg_ids"][2]));
        let (cd, cp) = (bytes(&v["committed"]["decision"]), bytes(&v["committed"]["proof"]));
        let (ad, ap) = (bytes(&v["aborted"]["decision"]), bytes(&v["aborted"]["proof"]));
        assert_eq!(proven_outcome(&root, &committed, &cd, &cp), Some(Outcome::Commit));
        assert_eq!(proven_outcome(&root, &aborted, &ad, &ap), Some(Outcome::Abort));
        // Another plan's decision, or a forged one, proves nothing.
        assert_eq!(proven_outcome(&root, &undecided, &cd, &cp), None);
        let mut forged = cd.clone();
        forged[10..].copy_from_slice(&undecided);
        assert_eq!(proven_outcome(&root, &undecided, &forged, &cp), None);
        forged[1] = 2;
        assert_eq!(proven_outcome(&root, &committed, &forged, &cp), None);
    }

    #[test]
    fn a_leg_receipt_proves_its_outcome_and_repaid_network_fee() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../sdk/fixtures/settlement_lock/leg_receipts.json")).unwrap();
        let root = hex32(&v["root"]);
        let plan = hex32(&v["plan_id"]);
        let c = &v["committed"];
        let leg = hex32(&c["leg_id"]);
        assert_eq!(leg_receipt_tree_key(&leg), hex32(&c["tree_key"]));
        let (r, p) = (bytes(&c["receipt"]), bytes(&c["proof"]));
        let got = proven_leg_receipt(&root, &leg, &r, &p).unwrap();
        assert_eq!((got.plan_id, got.index, got.committed, got.class), (plan, 1, true, 2));
        assert_eq!(got.network_fee, c["network_fee"].as_str().unwrap().parse::<u128>().unwrap());
        assert_eq!(got.relayer, Some(hex32(&c["relayer"])));
        let a = &v["aborted"];
        let aborted = proven_leg_receipt(&root, &hex32(&a["leg_id"]), &bytes(&a["receipt"]), &bytes(&a["proof"])).unwrap();
        assert_eq!((aborted.committed, aborted.compensation, aborted.relayer), (false, Some(3), None));
        // Another leg's receipt, an altered one, or one under another root proves nothing.
        assert_eq!(proven_leg_receipt(&root, &hex32(&v["absent"]["leg_id"]), &r, &p), None);
        let mut forged = r.clone();
        forged[93 + 15] ^= 1;
        assert_eq!(proven_leg_receipt(&root, &leg, &forged, &p), None);
        assert_eq!(proven_leg_receipt(&[0u8; 32], &leg, &r, &p), None);
    }

    #[test]
    fn a_leg_moves_once_and_only_on_a_proven_outcome() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../sdk/fixtures/settlement_lock/vectors.json")).unwrap();
        let root = hex32(&v["root"]);
        let committed = hex32(&v["committed"]["plan_id"]);
        let aborted = hex32(&v["aborted"]["plan_id"]);
        let (cd, cp) = (bytes(&v["committed"]["decision"]), bytes(&v["committed"]["proof"]));
        let (ad, ap) = (bytes(&v["aborted"]["decision"]), bytes(&v["aborted"]["proof"]));
        assert_eq!(settle_leg(LegState::Locked, &root, &committed, &cd, &cp), Ok(LegState::Released));
        assert_eq!(settle_leg(LegState::Locked, &root, &aborted, &ad, &ap), Ok(LegState::Refunded));
        assert_eq!(settle_leg(LegState::Released, &root, &committed, &cd, &cp), Err(LegError::NotLocked));
        assert_eq!(settle_leg(LegState::Refunded, &root, &aborted, &ad, &ap), Err(LegError::NotLocked));
        assert_eq!(settle_leg(LegState::Locked, &root, &aborted, &cd, &cp), Err(LegError::Unproven));
        assert_eq!(settle_leg(LegState::Locked, &[0u8; 32], &committed, &cd, &cp), Err(LegError::Unproven));
        assert_eq!(escape_leg(LegState::Locked, 99, 100), Err(LegError::TooEarly));
        assert_eq!(escape_leg(LegState::Locked, 100, 100), Ok(LegState::Refunded));
        assert_eq!(escape_leg(LegState::Released, 200, 100), Err(LegError::NotLocked));
    }
}
