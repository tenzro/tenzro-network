//! Validator admission at the node: the seams where a node could let a
//! validator join consensus while the network is closed to new validators
//! ([`tenzro_vm::validator_admission`]).
//!
//! Three places read the rule through this module:
//!
//! - the committee: [`enforce_committee`] runs after the registry's epoch
//!   plan is staged and, in closed mode, drops every staged entrant that is
//!   not admitted and queues the removal of every seated member that is not,
//!   so a bonded account that is not admitted never reaches a committee;
//! - the raw RPC: [`rpc_refusal`] is the error a `RegisterValidator` from a
//!   non-admitted account gets, with its own error code;
//! - gossip: [`PeerGate`] is the cheap early refusal of a validator endpoint
//!   announcement whose consensus key does not belong to an admitted
//!   account, with a rate limited log line.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tenzro_consensus::EpochManager;
use tenzro_types::primitives::Address;
use tenzro_vm::traits::VmState;
use tenzro_vm::validator_admission as rule;

use crate::rpc::JsonRpcError;

/// The mode name a status reply carries.
pub fn mode_name(open: bool) -> &'static str {
    if open { "open" } else { "closed" }
}

/// Closed mode: removes from the next committee every staged entrant that is
/// not admitted and queues the removal of every seated member that is not.
/// Open mode changes nothing. Returns the accounts it acted on.
pub fn enforce_committee(em: &Arc<EpochManager>, chain: &dyn VmState) -> Vec<Address> {
    if !rule::is_closed(chain) {
        return Vec::new();
    }
    let mut refused = Vec::new();
    let staged = em.pending_validators().into_iter().map(|v| v.address);
    let seated = em
        .current_validator_set()
        .active_validators()
        .iter()
        .map(|v| v.address)
        .collect::<Vec<_>>();
    for address in staged.chain(seated) {
        if !rule::is_on_admitted_set(chain, address.as_bytes()) && !refused.contains(&address) {
            em.remove_pending_validator(&address);
            refused.push(address);
        }
    }
    refused
}

/// The JSON-RPC error for a validator registration from `account` while
/// admission is closed and it is not admitted.
pub(crate) fn rpc_refusal(account: &[u8]) -> JsonRpcError {
    JsonRpcError {
        code: rule::REFUSAL_RPC_CODE,
        message: rule::refusal_message(account),
        data: Some(json!({
            "reason": rule::REFUSAL_CODE,
            "mode": "closed",
            "contact": rule::CONTACT,
            "alternatives": ["operator", "participant"],
        })),
    }
}

/// The reply of `tenzro_getNetworkParams { "validator_admission": true,
/// "address"? }`: the mode, and for an `address` whether it is admitted now
/// and whether it is on the admitted set.
pub fn status_json(chain: &dyn VmState, address: Option<&[u8]>) -> Value {
    let open = !rule::is_closed(chain);
    json!({
        "mode": mode_name(open),
        "address": address.map(hex::encode),
        "admitted": address.map(|a| rule::is_admitted(chain, a)),
        "on_admitted_set": address.map(|a| rule::is_on_admitted_set(chain, a)),
        "contact": rule::CONTACT,
        "mode_key": rule::MODE_KEY,
    })
}

/// Whether a consensus key fingerprint belongs to an admitted account.
fn key_admitted(chain: &dyn VmState, fingerprint: &[u8; 32]) -> bool {
    rule::account_of_key(chain, fingerprint)
        .is_some_and(|account| rule::is_admitted(chain, &account))
}

/// Refuses validator announcements from keys that are not admitted while the
/// network is closed. It logs at most once per [`PeerGate::LOG_EVERY_SECS`].
#[derive(Default)]
pub struct PeerGate {
    last_log: AtomicU64,
    refused: AtomicU64,
}

impl PeerGate {
    /// Seconds between two log lines about refused announcements.
    pub const LOG_EVERY_SECS: u64 = 60;

    /// Whether an announcement from the validator key `fingerprint` may go on
    /// to consensus handling. `chain` is `None` on a node with no state, which
    /// admits everything.
    pub fn allows(&self, chain: Option<&dyn VmState>, fingerprint: &[u8; 32]) -> bool {
        let Some(chain) = chain else { return true };
        if !rule::is_closed(chain) || key_admitted(chain, fingerprint) {
            return true;
        }
        let total = self.refused.fetch_add(1, Ordering::Relaxed) + 1;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let last = self.last_log.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= Self::LOG_EVERY_SECS
            && self
                .last_log
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!(
                refused_total = total,
                key = %hex::encode(fingerprint),
                "validator admission is closed: ignoring a peer announcing as a validator that is not admitted"
            );
        }
        false
    }

    /// How many announcements were refused.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }
}
