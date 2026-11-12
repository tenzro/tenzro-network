//! This validator's contributions to the chain's randomness beacon, and the
//! beacon's read surface.
//!
//! A bonded validator proves, with the VRF over its hardware-derived node
//! key, the output on the beacon's current round and mix, and submits it as
//! a `BeaconContribute` transaction (see `tenzro_vm::native::beacon`). The
//! key is derived per proof and never leaves the derivation.
//!
//! Once governance enables commit-reveal, each contribution also commits to
//! the validator's next beacon secret and reveals the last one. The secrets
//! derive from the hardware root under [`BEACON_SECRET_LABEL`] and the
//! commitment's index on chain, so nothing is stored and a restart reveals
//! the same secret it committed to.
//!
//! - `tenzro_getBeacon { round?, at_ms? }`: the head (round and mix), or the
//!   value taken at `round`, or the first value taken at or after `at_ms`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tenzro_crypto::vrf::VrfProver;
use tenzro_vm::native::beacon::{
    BACKUP_STEP_MS, BeaconEntry, MIN_CONTRIBUTION_INTERVAL_MS, alpha, first_at_or_after,
    read_entry, read_head, submission_delay_ms,
};
use tracing::{debug, info};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// How often a validator considers contributing.
const TICK: Duration = Duration::from_secs(30);

/// Derivation label of the beacon secrets.
pub const BEACON_SECRET_LABEL: &str = "tenzro/beacon/secret";

const SECRET_DOMAIN: &[u8] = b"tenzro/beacon/secret/v1";

/// The beacon secret of commitment `index`, from the root's secret `base`.
pub fn beacon_secret(base: &[u8; 32], index: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update(SECRET_DOMAIN)
        .chain_update(base)
        .chain_update(index.to_be_bytes())
        .finalize()
        .into()
}

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

fn entry_json(e: &BeaconEntry) -> Value {
    json!({ "round": e.round, "mix": e.mix, "at_ms": e.at_ms, "contributor": e.contributor })
}

/// `tenzro_getBeacon`.
pub(crate) async fn handle_get_beacon(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let chain = crate::rpc::chain_state(node)?;
    if let Some(round) = params.get("round").and_then(Value::as_u64) {
        let e = read_entry(&chain, round)
            .ok_or_else(|| err(-32004, format!("the beacon has not taken round {round}")))?;
        return Ok(entry_json(&e));
    }
    if let Some(at) = params.get("at_ms").and_then(Value::as_i64) {
        let e = first_at_or_after(&chain, at)
            .ok_or_else(|| err(-32004, format!("the beacon has taken no value since {at}")))?;
        return Ok(entry_json(&e));
    }
    let head = read_head(&chain);
    let latest = head
        .round
        .checked_sub(1)
        .and_then(|r| read_entry(&chain, r));
    Ok(json!({ "round": head.round, "mix": head.mix, "latest": latest.as_ref().map(entry_json) }))
}

/// Whether `tx` is a beacon contribution for a round the beacon has already
/// left behind: one that can only revert when it executes.
pub(crate) fn is_stale_contribution(
    chain: &dyn tenzro_vm::VmState,
    tx: &tenzro_types::TransactionType,
) -> bool {
    match tx {
        tenzro_types::TransactionType::BeaconContribute { round, .. } => {
            tenzro_vm::native::beacon::is_stale_at(chain, *round)
        }
        _ => false,
    }
}

/// The accounts that may contribute now: active validators with a validator's
/// bond, a registered VRF key and no contribution in the last two intervals.
fn eligible_contributors(
    node: &Arc<TenzroNode>,
    chain: &tenzro_vm::StateAdapter,
    now: i64,
) -> Vec<Vec<u8>> {
    let Some(consensus) = node.consensus() else {
        return Vec::new();
    };
    let floor = tenzro_vm::native::stake_ladder(chain).validator.max(1);
    consensus
        .validator_set()
        .active_validators()
        .iter()
        .map(|v| v.address.as_bytes().to_vec())
        .filter(|a| {
            tenzro_vm::native::bonded_stake_of(chain, a) >= floor
                && tenzro_vm::native::vrf_key_of(chain, a).is_some()
                && tenzro_vm::native::beacon::last_contribution(chain, a)
                    .is_none_or(|last| now >= last.saturating_add(MIN_CONTRIBUTION_INTERVAL_MS * 2))
        })
        .collect()
}

/// Submit one contribution when this node is a bonded validator, its
/// last one is old enough, and it is this node's turn in the round.
///
/// One validator is first in line for each round and the others back it up
/// in turn, each [`BACKUP_STEP_MS`] later than the one before. A node does
/// not send for a round it already sent for, nor when the head moved on
/// while its proof was being made. `sent` holds the round it last sent for.
async fn contribute_once(node: &Arc<TenzroNode>, sent: &mut Option<u64>) -> Result<bool, String> {
    let Some(submitter) = node.ledger_submitter() else {
        return Ok(false);
    };
    let account = submitter.address();
    let chain = crate::rpc::chain_state_of(node).ok_or("no chain state")?;
    if tenzro_vm::native::bonded_stake_of(&chain, account.as_bytes())
        < tenzro_vm::native::stake_ladder(&chain).validator.max(1)
    {
        return Ok(false);
    }
    if tenzro_vm::native::vrf_key_of(&chain, account.as_bytes()).is_none() {
        return Ok(false);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    if let Some(last) = tenzro_vm::native::beacon::last_contribution(&chain, account.as_bytes())
        && now < last.saturating_add(MIN_CONTRIBUTION_INTERVAL_MS * 2)
    {
        return Ok(false);
    }
    let head = read_head(&chain);
    if *sent == Some(head.round) {
        return Ok(false);
    }
    let mix: [u8; 32] = hex::decode(&head.mix)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("the beacon mix is malformed")?;
    let eligible = eligible_contributors(node, &chain, now);
    let delay = submission_delay_ms(head.round, &mix, account.as_bytes(), &eligible)
        .unwrap_or(eligible.len() as i64 * BACKUP_STEP_MS);
    let round_began = head
        .round
        .checked_sub(1)
        .and_then(|r| read_entry(&chain, r))
        .map_or(0, |e| e.at_ms);
    if now < round_began.saturating_add(delay) {
        return Ok(false);
    }
    let data_dir = node.config().data_dir.clone();
    let round = head.round;
    let commit = tenzro_vm::native::beacon::commit_reveal_enabled(&chain)
        .then(|| tenzro_vm::native::beacon::commitment_of(&chain, account.as_bytes()));
    let who = account.as_bytes().to_vec();
    let proof = tokio::task::spawn_blocking(move || {
        let prover = crate::keygen::NodeKeys::open(&data_dir)
            .map_err(|e| e.to_string())?
            .vrf_prover()
            .map_err(|e| e.to_string())?;
        let vrf = prover
            .prove(&alpha(round, &mix))
            .map_err(|e| e.to_string())?;
        let Some(held) = commit else {
            return Ok::<_, String>(vrf.as_bytes().to_vec());
        };
        let base = tenzro_device_key::DerivationRoot::open_or_create()
            .and_then(|root| root.endpoint_secret(BEACON_SECRET_LABEL))
            .map_err(|e| format!("beacon secret: {e}"))?;
        let next = held.as_ref().map_or(0, |h| h.index + 1);
        let reveal = held.map(|h| beacon_secret(&base, h.index));
        let commitment =
            tenzro_vm::native::beacon::commitment_to(&who, &beacon_secret(&base, next));
        Ok(tenzro_vm::native::beacon::contribution_proof(
            vrf.as_bytes(),
            Some(&commitment),
            reveal.as_ref(),
        ))
    })
    .await
    .map_err(|e| e.to_string())??;
    // Proving takes a moment; a block may have taken the round meanwhile.
    let chain = crate::rpc::chain_state_of(node).ok_or("no chain state")?;
    if tenzro_vm::native::beacon::is_stale_at(&chain, round) {
        return Ok(false);
    }
    let tx = tenzro_types::TransactionType::BeaconContribute { round, proof };
    crate::rpc::submit_as_validator(node, tx, tenzro_vm::native::beacon::GAS_BEACON_CONTRIBUTE)
        .await
        .map_err(|e| e.message)?;
    *sent = Some(round);
    Ok(true)
}

/// Contribute to the beacon while this node is a bonded validator.
pub fn spawn_contributor(node: Arc<TenzroNode>) {
    tokio::spawn(async move {
        let mut sent = None;
        loop {
            match contribute_once(&node, &mut sent).await {
                Ok(true) => info!(target: "beacon", "contributed to the randomness beacon"),
                Ok(false) => {}
                Err(e) => debug!(target: "beacon", error = %e, "no beacon contribution this round"),
            }
            tokio::time::sleep(TICK).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::TransactionType;

    #[test]
    fn other_transactions_are_never_stale() {
        let state = tenzro_vm::StateAdapter::new();
        assert!(!is_stale_contribution(
            &state,
            &TransactionType::Transfer { amount: 1 }
        ));
    }

    #[test]
    fn a_contribution_for_the_head_round_is_not_stale() {
        let state = tenzro_vm::StateAdapter::new();
        let tx = TransactionType::BeaconContribute {
            round: 0,
            proof: Vec::new(),
        };
        assert!(!is_stale_contribution(&state, &tx));
    }
}
