//! Reward issuance to accountable roots.
//!
//! A coupon pays for verified work, but a party can still make work cheaply
//! from many identities. Once this rule is live, an epoch's work earns a
//! coupon only when the root behind the earning account (the account's
//! identity, followed to the root a delegated identity answers to) is a
//! human root, held by a passkey, or an autonomous machine whose TPM
//! endorsement certificate chains to a root governance recognises
//! ([`super::funding::machine_endorsed`]). Work by an account with no
//! identity, under a revoked identity or root, or under a machine root
//! without a manufacturer-endorsed TPM is left unmatched, and its share of
//! the bucket stays in the pool.
//!
//! It changes which coupons an epoch issues, so it ships dormant behind
//! [`KEY`] ([`crate::feature_gate`]) and a vote switches it on for every node
//! at one epoch.

use tenzro_token::rewards::WorkRecord;
use tenzro_types::agent_terms::RootKind;

use super::*;
use crate::feature_gate;

/// The gate of the rule.
pub const KEY: &str = "feature.reward_root.activation_epoch";

/// Whether work by `address` may earn a coupon at `now_ms`, or why not.
pub fn may_earn(
    state: &dyn VmState,
    address: &[u8],
    now_ms: i64,
) -> std::result::Result<(), String> {
    let did = identity_of_wallet(state, address)
        .ok_or_else(|| format!("{} has no registered identity", hex::encode(address)))?;
    let root = super::operator::operator_did(state, &did);
    for d in [did.as_str(), root.as_str()] {
        if is_identity_revoked(state, d) {
            return Err(format!("{d} is revoked"));
        }
    }
    if super::funding::identity_record(state, &root).is_none() {
        return Err(format!("{root} is not registered"));
    }
    match RootKind::of(&root) {
        Some(RootKind::Passkey) => Ok(()),
        Some(RootKind::Machine) => super::funding::machine_endorsed(state, &root, now_ms)
            .map_err(|e| format!("{root} has no manufacturer-endorsed TPM: {e}")),
        None => Err(format!("{root} is neither a human nor a machine root")),
    }
}

/// For each account with work in the open epoch, in any bucket, the bucket
/// and whether that work would earn a coupon at `now_ms` (and why not).
/// What the rule would leave unmatched when the epoch closes, for the vote
/// that switches it on to read.
pub fn pending_verdicts(
    state: &dyn VmState,
    now_ms: i64,
) -> Result<Vec<(Address, &'static str, std::result::Result<(), String>)>> {
    use tenzro_token::rewards::RoleBucket;
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    let epoch = super::rewards::read_reward_state(state)?.current_epoch;
    for w in super::rewards::pending_records(state, epoch)? {
        let bucket = match w.class.bucket() {
            RoleBucket::Validator => "validator",
            RoleBucket::Provider => "provider",
            RoleBucket::Ecosystem => "ecosystem",
        };
        if seen.insert((w.address.0, bucket)) {
            out.push((w.address, bucket, may_earn(state, &w.address.0, now_ms)));
        }
    }
    Ok(out)
}

/// The part of an epoch's `work` that may earn coupons at `now_ms`: all of it
/// while the rule is dormant.
pub fn issuable(state: &dyn VmState, mut work: Vec<WorkRecord>, now_ms: i64) -> Vec<WorkRecord> {
    if feature_gate::is_live_now(state, KEY) {
        work.retain(|w| may_earn(state, &w.address.0, now_ms).is_ok());
    }
    work
}
