//! A root delegates a bounded number of agents.
//!
//! Every agent answers to one root (a human or an autonomous machine), and
//! the root is the party accountable for it. Without a bound, one root can
//! stand behind any number of agents, each with its own spending limits, so
//! what the root can put at work grows with nothing but the fees of creating
//! them. With the rule live, a root that already has [`LIMIT_KEY`] live
//! agents is refused another. An agent stops counting once it is revoked, by
//! its root, by governance or by its controller's revocation; a quarantined
//! agent still counts, since its quarantine can be lifted, and so does a
//! terminated one until its root revokes it. Changing an existing agent's
//! terms is never refused.
//!
//! The count is a counter per root in consensus state, so creating or
//! revoking an agent costs the same however many agents the root ever had.
//! The counter is written only while the rule is live. A root's first new
//! agent under the live rule seeds it with one scan of the root's agent
//! index, which the transaction pays for at [`GAS_SEED_PER_AGENT`] an entry,
//! so agents delegated before activation are counted.
//!
//! The rule changes which delegations a block admits, so it ships dormant
//! behind [`KEY`] ([`crate::feature_gate`]) and a vote switches it on for
//! every node at one epoch.

use super::agent_audit::read_agent_quarantine;
use super::agent_terms::read_agent_terms;
use super::funding::{read_json, write_json};
use super::identity_revocation::read_delegated_agents;
use super::*;
use crate::feature_gate;

/// The gate of the rule.
pub const KEY: &str = "feature.agent_cap.activation_epoch";

/// Most agents one root may have delegated and not revoked.
pub const LIMIT_KEY: &str = "feature.agent_cap.max_agents_per_root";

/// Gas for each entry of a root's agent index the seeding scan reads.
pub const GAS_SEED_PER_AGENT: u64 = 5_000;

fn count_key(controller_did: &str) -> String {
    format!("agent_cap_live:{controller_did}")
}

/// Whether `agent_did` no longer counts: chain state records it revoked, by
/// its root or governance, or revoked by its controller.
fn retired(state: &dyn VmState, agent_did: &str) -> bool {
    is_identity_revoked(state, agent_did)
        || read_agent_quarantine(state, agent_did).is_some_and(|q| q.revoked)
}

fn scan(state: &dyn VmState, controller_did: &str) -> u64 {
    read_delegated_agents(state, controller_did)
        .iter()
        .filter(|agent| !retired(state, agent))
        .count() as u64
}

/// The live agents of `controller_did`: its counter once seeded, else a
/// scan of its agent index.
pub fn live_agents(state: &dyn VmState, controller_did: &str) -> u64 {
    read_json(state, &count_key(controller_did)).unwrap_or_else(|| scan(state, controller_did))
}

/// Gas the seeding scan adds to a new delegation by `controller_did`: one
/// [`GAS_SEED_PER_AGENT`] per indexed agent when the rule is live and the
/// root's counter is not yet seeded, else nothing.
pub fn seed_gas(state: &dyn VmState, controller_did: &str) -> u64 {
    let unseeded = feature_gate::is_live_now(state, KEY)
        && read_json::<u64>(state, &count_key(controller_did)).is_none();
    if !unseeded {
        return 0;
    }
    GAS_SEED_PER_AGENT.saturating_mul(read_delegated_agents(state, controller_did).len() as u64)
}

/// Refuse `controller_did` one more agent when the rule is live and the
/// root already has as many as the limit allows. Returns the live count the
/// new agent joins, `None` while the rule is dormant.
pub fn check_new_agent(
    state: &dyn VmState,
    controller_did: &str,
) -> std::result::Result<Option<u64>, String> {
    if !feature_gate::is_live_now(state, KEY) {
        return Ok(None);
    }
    let limit = network_param(state, LIMIT_KEY);
    let live = live_agents(state, controller_did);
    if live >= limit {
        return Err(format!(
            "{controller_did} has {live} agents and may have at most {limit}; revoke one first"
        ));
    }
    Ok(Some(live))
}

/// Count the new agent of `controller_did` that joined `live` others.
pub(super) fn note_new_agent(
    state: &mut dyn VmState,
    controller_did: &str,
    live: u64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    write_json(state, &count_key(controller_did), &(live + 1), changes).map(|_| ())
}

/// Uncount `agent_did` before a revocation of it is written, when the rule
/// is live, the agent still counts and its root's counter is seeded. Called
/// on every path that revokes an agent; one already revoked is not
/// uncounted twice.
pub(super) fn note_retiring(
    state: &mut dyn VmState,
    agent_did: &str,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if !feature_gate::is_live_now(state, KEY) || retired(state, agent_did) {
        return Ok(());
    }
    let Some(terms) = read_agent_terms(state, agent_did) else {
        return Ok(());
    };
    let key = count_key(&terms.terms.controller_did);
    let Some(live) = read_json::<u64>(state, &key) else {
        return Ok(());
    };
    write_json(state, &key, &live.saturating_sub(1), changes).map(|_| ())
}
