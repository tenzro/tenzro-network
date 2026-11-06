//! The treasury's accounts on other chains.
//!
//! The treasury holds, on every chain agents hold accounts on, the account
//! the same account code places for [`TREASURY_DID`]: computed from the
//! chain's governed [`AgentAccountChain`] deployment, never stored, and with
//! no key behind it. Its funds move only by an exact remote grant that an
//! enacted `TreasuryRemoteAction` proposal writes at
//! `agent_grant:{TREASURY_DID}:{caip2}`: the account proves the grant under a
//! final checkpoint's state root and runs the one action it pins. The
//! proposal reaches enactment only after its vote, its timelock and any
//! Foundation steward veto or hold, so the grant cannot exist before then.
//!
//! Bitcoin has no account code: treasury BTC moves through the deposit route
//! only, and a `TreasuryRemoteAction` for a `bip122` chain is
//! refused.

use tenzro_types::omni_account::{AgentAccountChain, OmniAddress, omni_address};
use tenzro_types::remote_grant::{
    RemoteAction, RemoteGrant, agent_hash, asset_hash, chain_hash, index_key, leaf_key,
    payload_hash,
};

use super::funding::{read_json, write_json};
use super::*;

/// The identity the treasury's accounts on other chains are derived from.
/// No key exists for it.
pub const TREASURY_DID: &str = "did:tenzro:treasury:network";

/// Storage key of the list of chains with an account-code record.
pub const CHAIN_INDEX_KEY: &str = "agent_account_chain_index";

/// Topic of the log a treasury remote grant emits.
pub const TREASURY_REMOTE_TOPIC: &[u8] = b"TreasuryRemoteGrant";

/// Longest a treasury remote grant may wait to be installed and run.
pub const MAX_TREASURY_GRANT_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// The chains with an account-code record.
pub fn account_chains(state: &dyn VmState) -> Vec<String> {
    read_json(state, CHAIN_INDEX_KEY).unwrap_or_default()
}

/// Add `caip2` to the chain index.
pub(crate) fn index_chain(
    state: &mut dyn VmState,
    caip2: &str,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let mut chains = account_chains(state);
    if !chains.iter().any(|c| c == caip2) {
        chains.push(caip2.to_string());
        chains.sort();
        write_json(state, CHAIN_INDEX_KEY, &chains, changes)?;
    }
    Ok(())
}

/// The treasury's account on `caip2`, from the chain's governed deployment.
pub fn treasury_account(
    state: &dyn VmState,
    caip2: &str,
) -> std::result::Result<OmniAddress, String> {
    if caip2.starts_with("bip122:") {
        return Err("treasury BTC moves through the deposit route, not an account".into());
    }
    let chain: AgentAccountChain = read_json(state, &AgentAccountChain::storage_key(caip2))
        .ok_or_else(|| format!("no account code is configured for {caip2}"))?;
    omni_address(TREASURY_DID, caip2, &chain.deployment).map_err(|e| e.to_string())
}

/// The treasury's accounts on every configured chain.
pub fn treasury_accounts(state: &dyn VmState) -> Vec<OmniAddress> {
    account_chains(state)
        .iter()
        .filter_map(|c| treasury_account(state, c).ok())
        .collect()
}

/// Refuse a treasury remote action that could not be enacted on `caip2`:
/// the chain must be configured and open.
pub(crate) fn check_chain(state: &dyn VmState, caip2: &str) -> std::result::Result<(), String> {
    let chain: AgentAccountChain = read_json(state, &AgentAccountChain::storage_key(caip2))
        .ok_or_else(|| format!("no account code is configured for {caip2}"))?;
    if !chain.open {
        return Err(format!("{caip2} is not open"));
    }
    treasury_account(state, caip2).map(|_| ())
}

/// The exact grant an enacted treasury remote action writes, at block time
/// `now_ms`.
pub fn grant_for(
    state: &dyn VmState,
    caip2: &str,
    caip19: &str,
    action: &RemoteAction,
    ttl_ms: u64,
    now_ms: u64,
) -> std::result::Result<RemoteGrant, String> {
    let account = treasury_account(state, caip2)?;
    let seq = super::remote_grant::read_grant(state, TREASURY_DID, caip2)
        .map(|g| g.seq + 1)
        .unwrap_or(1);
    Ok(RemoteGrant {
        chain: chain_hash(caip2),
        account: account.account_word(),
        agent: agent_hash(TREASURY_DID),
        terms_version: 0,
        seq,
        not_before_ms: now_ms,
        not_after_ms: now_ms.saturating_add(ttl_ms),
        asset: asset_hash(caip19),
        budget: action.amount,
        per_action_max: action.amount,
        cosign_above: u128::MAX,
        keys_root: [0u8; 32],
        targets_root: [0u8; 32],
        payload_hash: payload_hash(action),
        relay_fee_max: action.relay_refund,
        void: false,
    })
}

/// Write the exact grant for an enacted treasury remote action.
pub(crate) fn enact(
    state: &mut dyn VmState,
    caip2: &str,
    caip19: &str,
    action: &RemoteAction,
    ttl_ms: u64,
    now_ms: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    check_chain(state, caip2)
        .map_err(|e| VmError::InvalidTransaction(format!("treasury remote action refused: {e}")))?;
    let grant = grant_for(state, caip2, caip19, action, ttl_ms, now_ms)
        .map_err(|e| VmError::InvalidTransaction(format!("treasury remote action refused: {e}")))?;
    let key = leaf_key(TREASURY_DID, caip2);
    let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), grant.encode());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        prior,
        Some(grant.encode()),
    ));
    let mut chains: Vec<String> = read_json(state, &index_key(TREASURY_DID)).unwrap_or_default();
    if !chains.iter().any(|c| c == caip2) {
        chains.push(caip2.to_string());
        write_json(state, &index_key(TREASURY_DID), &chains, changes)?;
    }
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![TREASURY_REMOTE_TOPIC.to_vec(), chain_hash(caip2).to_vec()],
        grant.encode(),
    ));
    Ok(())
}
