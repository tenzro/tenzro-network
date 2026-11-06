//! Admission rules, a change ceiling and an alert for the EIP-7702
//! authorization list of a set-code transaction.
//!
//! The EVM applies an authorization list on its own terms: every entry whose
//! signature recovers sets that signer's code to a delegation, whatever the
//! chain id says (zero means every chain), and nothing bounds how many
//! entries one transaction carries or how many of them name one signer. A
//! thief holding one key can therefore sign a run of authorizations over
//! consecutive nonces, once for every chain, and land them in one
//! transaction. These rules close that shape at admission, before any
//! entry is applied:
//!
//! - the list holds at most `evm.max_authorizations_per_tx` entries;
//! - no signer appears twice (consecutive nonces for one account), unless
//!   `evm.multiple_authorizations_per_signer_allowed` is set;
//! - an entry for chain id zero (valid on every chain) is refused unless
//!   `evm.universal_authorization_allowed` is set;
//! - an entry signed for another chain is refused unless
//!   `evm.foreign_chain_authorization_allowed` is set;
//! - one account changes its delegation at most
//!   `evm.delegation_changes_per_window` times in a rolling
//!   `evm.delegation_window_ms`, however many transactions carry the
//!   changes, so a thief who lands one entry per transaction is slowed to
//!   the same ceiling and the owner has the window to react;
//! - while `evm.delegate_allowlist_enforced` is set, an entry may only name
//!   a delegate whose code hash governance listed (`SetDelegateCode`), or
//!   the zero address, which clears a delegation.
//!
//! Every change that lands is logged (`DelegationChanged`, topic and the
//! account) for wallets and monitors. Every limit is a governed parameter.

use std::collections::BTreeSet;

use revm::primitives::U256;
use sha3::{Digest, Keccak256};

use crate::error::{Result, VmError};
use crate::native::{SYSTEM_ADDRESS, network_param};
use crate::traits::VmState;
use crate::types::{ExecutionResult, Log, StateChange, VmTransaction};

/// Governed: the most authorizations one transaction may carry.
pub const MAX_AUTHORIZATIONS_PARAM: &str = "evm.max_authorizations_per_tx";

/// Genesis value of [`MAX_AUTHORIZATIONS_PARAM`]. A wallet upgrade needs one.
pub const DEFAULT_MAX_AUTHORIZATIONS: u64 = 2;

/// Governed: whether an authorization signed for every chain (chain id zero)
/// is admitted.
pub const UNIVERSAL_ALLOWED_PARAM: &str = "evm.universal_authorization_allowed";

/// Genesis value of [`UNIVERSAL_ALLOWED_PARAM`]: not admitted.
pub const DEFAULT_UNIVERSAL_ALLOWED: u64 = 0;

/// Governed: whether one signer may appear in a transaction's list more than
/// once (1 admits it). Several entries over consecutive nonces for one
/// account is the shape of a sweep.
pub const MULTI_SIGNER_ENTRIES_PARAM: &str = "evm.multiple_authorizations_per_signer_allowed";

/// Genesis value of [`MULTI_SIGNER_ENTRIES_PARAM`]: not admitted.
pub const DEFAULT_MULTI_SIGNER_ENTRIES: u64 = 0;

/// Governed: whether an entry signed for another chain's id is admitted (1
/// admits it; the EVM skips it).
pub const FOREIGN_CHAIN_PARAM: &str = "evm.foreign_chain_authorization_allowed";

/// Genesis value of [`FOREIGN_CHAIN_PARAM`]: not admitted.
pub const DEFAULT_FOREIGN_CHAIN: u64 = 0;

/// Governed: the most delegation changes one account may make in a window.
pub const CHANGES_PER_WINDOW_PARAM: &str = "evm.delegation_changes_per_window";

/// Genesis value of [`CHANGES_PER_WINDOW_PARAM`].
pub const DEFAULT_CHANGES_PER_WINDOW: u64 = 4;

/// Governed: the rolling window of [`CHANGES_PER_WINDOW_PARAM`], ms.
pub const WINDOW_MS_PARAM: &str = "evm.delegation_window_ms";

/// Genesis value of [`WINDOW_MS_PARAM`]: one day.
pub const DEFAULT_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

/// Governed: whether an entry may only name a delegate whose code hash is
/// on the governed list (1 enforces it).
pub const ALLOWLIST_ENFORCED_PARAM: &str = "evm.delegate_allowlist_enforced";

/// Genesis value of [`ALLOWLIST_ENFORCED_PARAM`]: not enforced; the list is
/// empty until governance lists code hashes.
pub const DEFAULT_ALLOWLIST_ENFORCED: u64 = 0;

/// Topic of the log every landed delegation change emits.
pub const DELEGATION_CHANGED_TOPIC: &[u8] = b"DelegationChanged";

/// Hex of the Keccak-256 hash of `code`, the form the list is keyed by.
pub fn code_hash_hex(code: &[u8]) -> String {
    hex::encode(Keccak256::digest(code))
}

/// System-storage key under which governance lists a delegate code hash.
pub fn delegate_code_key(code_hash_hex: &str) -> String {
    format!("evm_delegate_code:{}", code_hash_hex.to_ascii_lowercase())
}

/// Whether the code at `delegate` is on the governed list.
pub fn delegate_listed(state: &dyn VmState, delegate: &[u8]) -> bool {
    let Some(code) = state.get_code(delegate).filter(|c| !c.is_empty()) else {
        return false;
    };
    state
        .get_storage(
            &SYSTEM_ADDRESS,
            delegate_code_key(&code_hash_hex(&code)).as_bytes(),
        )
        .is_some_and(|v| !v.is_empty())
}

fn counter_key(authority: &[u8]) -> String {
    format!("evm_delegation_changes:{}", hex::encode(authority))
}

/// Changes `authority` has landed in the window that contains `now_ms`.
pub fn changes_in_window(state: &dyn VmState, authority: &[u8], now_ms: i64) -> u64 {
    let window = network_param(state, WINDOW_MS_PARAM) as i64;
    let Some(raw) = state.get_storage(&SYSTEM_ADDRESS, counter_key(authority).as_bytes()) else {
        return 0;
    };
    if raw.len() != 12 {
        return 0;
    }
    let start = i64::from_le_bytes(raw[..8].try_into().unwrap());
    let count = u32::from_le_bytes(raw[8..].try_into().unwrap()) as u64;
    if now_ms >= start && now_ms - start < window {
        count
    } else {
        0
    }
}

fn authority_of(a: &crate::account_abstraction::Eip7702Authorization) -> Option<[u8; 20]> {
    a.recovered().authority().map(|x| x.0.0)
}

/// Refuses a transaction whose authorization list breaks the rules above.
pub fn check(tx: &VmTransaction, state: &dyn VmState) -> Result<()> {
    if tx.authorization_list.is_empty() {
        return Ok(());
    }
    let max = network_param(state, MAX_AUTHORIZATIONS_PARAM) as usize;
    if tx.authorization_list.len() > max {
        return Err(VmError::InvalidTransaction(format!(
            "authorization list holds {} entries; the limit is {max}",
            tx.authorization_list.len()
        )));
    }
    let universal = network_param(state, UNIVERSAL_ALLOWED_PARAM) != 0;
    let foreign = network_param(state, FOREIGN_CHAIN_PARAM) != 0;
    let multi = network_param(state, MULTI_SIGNER_ENTRIES_PARAM) != 0;
    let enforced = network_param(state, ALLOWLIST_ENFORCED_PARAM) != 0;
    let ceiling = network_param(state, CHANGES_PER_WINDOW_PARAM);
    let now = crate::native::deterministic_now_ms(tx);
    let mut seen = BTreeSet::new();
    let mut entries: std::collections::BTreeMap<[u8; 20], u64> = Default::default();
    for a in &tx.authorization_list {
        if a.chain_id == U256::ZERO {
            if !universal {
                return Err(VmError::InvalidTransaction(
                    "authorization for every chain (chain id 0) is not admitted".to_string(),
                ));
            }
        } else if a.chain_id != U256::from(tx.chain_id) && !foreign {
            return Err(VmError::InvalidTransaction(
                "authorization is signed for another chain".to_string(),
            ));
        }
        if enforced
            && a.delegate_address.iter().any(|b| *b != 0)
            && !delegate_listed(state, &a.delegate_address)
        {
            return Err(VmError::InvalidTransaction(
                "authorization names a delegate whose code is not on the governed list".to_string(),
            ));
        }
        if let Some(signer) = authority_of(a) {
            if a.delegate_address.iter().any(|b| *b != 0)
                && crate::account_outflow::policy_in_force(state, &signer, now).is_some()
            {
                return Err(VmError::InvalidTransaction(
                    "an account with an outflow policy takes no delegation".to_string(),
                ));
            }
            if !seen.insert(signer) && !multi {
                return Err(VmError::InvalidTransaction(
                    "two authorizations from one signer in one transaction".to_string(),
                ));
            }
            *entries.entry(signer).or_default() += 1;
        }
    }
    for (signer, n) in entries {
        let used = changes_in_window(state, &signer, now);
        if used + n > ceiling {
            return Err(VmError::InvalidTransaction(format!(
                "account {} would make {} delegation changes in the window; the ceiling is {ceiling}",
                hex::encode(signer),
                used + n
            )));
        }
    }
    Ok(())
}

/// The code of every account the transaction's authorization list names,
/// taken before the transaction runs.
pub fn snapshot(tx: &VmTransaction, state: &dyn VmState) -> Vec<([u8; 20], Vec<u8>, u64)> {
    let mut out: Vec<([u8; 20], Vec<u8>, u64)> = Vec::new();
    for a in &tx.authorization_list {
        if let Some(signer) = authority_of(a)
            && !out.iter().any(|(s, _, _)| *s == signer)
        {
            out.push((
                signer,
                state.get_code(&signer).unwrap_or_default(),
                state.get_nonce(&signer),
            ));
        }
    }
    out
}

/// Counts one more delegation change for `signer` in the window that holds
/// `now_ms`. A transaction that reverts keeps its delegations, so the block
/// executor calls this too for the delegations it re-applies.
pub fn bump(state: &mut dyn VmState, signer: &[u8], now_ms: i64) -> StateChange {
    let key = counter_key(signer);
    let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let used = changes_in_window(state, signer, now_ms);
    let start = if used == 0 {
        now_ms
    } else {
        previous
            .as_ref()
            .filter(|p| p.len() == 12)
            .map(|p| i64::from_le_bytes(p[..8].try_into().unwrap()))
            .unwrap_or(now_ms)
    };
    let mut blob = start.to_le_bytes().to_vec();
    blob.extend_from_slice(&((used + 1) as u32).to_le_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        previous,
        Some(blob),
    )
}

/// After the transaction ran: counts and logs every account whose code
/// changed.
pub fn record(
    tx: &VmTransaction,
    state: &mut dyn VmState,
    before: &[([u8; 20], Vec<u8>, u64)],
    result: &mut ExecutionResult,
) {
    let now = crate::native::deterministic_now_ms(tx);
    for (signer, old_code, old_nonce) in before {
        let new_code = state.get_code(signer).unwrap_or_default();
        // An applied entry spends its signer's nonce, so a repeat of the same
        // delegation counts although the code is unchanged. (A signer that
        // is also the sender has its nonce spent by the transaction itself.)
        let applied =
            signer.as_slice() != tx.from.as_slice() && state.get_nonce(signer) != *old_nonce;
        if &new_code == old_code && !applied {
            continue;
        }
        result.state_changes.push(bump(state, signer, now));
        let mut data = Vec::with_capacity(2 + old_code.len() + new_code.len());
        data.extend_from_slice(&(old_code.len() as u16).to_be_bytes());
        data.extend_from_slice(old_code);
        data.extend_from_slice(&new_code);
        result.logs.push(Log::new(
            signer.to_vec(),
            vec![DELEGATION_CHANGED_TOPIC.to_vec(), signer.to_vec()],
            data,
        ));
    }
}
