//! Bridge from `tenzro_payments::LifecycleStateResolver` to the
//! [`AgentLifecycle`] FSM held by [`AgentRuntime`].
//!
//! `tenzro-payments` defines the trait so that the [`IdentityPaymentBinder`]
//! can refuse outbound payments from agents in a non-operational kill-switch
//! state (`Paused` / `Quarantined` / `Terminated`) without depending on the
//! agent crate. The runtime registry that knows each agent's posture lives in
//! `tenzro-agent`. This adapter, owned by `tenzro-node`, glues the two
//! together — same shape as
//! [`crate::spending_policy_bridge::AgentRuntimeSpendingPolicyResolver`].
//!
//! Lookup is by DID. The trait surface uses `payer_did` because that is what
//! a payment carries; the lifecycle FSM is keyed by `agent_id`. We resolve
//! `did → agent_id` by scanning the identity manager's registered agents
//! (typically a small set; agents that have not registered a DID with TDIP
//! are skipped). When the DID does not match any registered agent we return
//! `Ok(None)` — the binder falls back to `DelegationScope` + `SpendingPolicy`
//! only.

use std::sync::Arc;

use tenzro_agent::{AgentRuntime, AgentState};
use tenzro_payments::{LifecyclePosture, LifecycleStateResolver, Result};

/// `LifecycleStateResolver` impl backed by [`AgentRuntime`]'s lifecycle FSM.
/// See module docs.
pub struct AgentRuntimeLifecycleResolver {
    runtime: Arc<AgentRuntime>,
}

impl AgentRuntimeLifecycleResolver {
    /// Wraps an existing [`AgentRuntime`] handle.
    pub fn new(runtime: Arc<AgentRuntime>) -> Self {
        Self { runtime }
    }
}

impl LifecycleStateResolver for AgentRuntimeLifecycleResolver {
    fn resolve(&self, payer_did: &str) -> Result<Option<LifecyclePosture>> {
        // Resolve DID → agent_id by scanning the identity manager.
        let agents = self.runtime.identity_manager().list_agents(None);
        let agent_id = match agents
            .iter()
            .find(|a| a.tenzro_did.as_deref() == Some(payer_did))
        {
            Some(agent) => agent.identity.agent_id.clone(),
            None => return Ok(None),
        };

        // Read the lifecycle FSM. Missing entries mean the agent has been
        // removed but the registered identity record lingers — treat as no
        // posture (caller falls back to DelegationScope/SpendingPolicy).
        let state = match self.runtime.lifecycle_manager().get_state(&agent_id) {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };

        Ok(Some(map_state(state)))
    }
}

/// Project the agent-side `AgentState` enum onto the payment-side
/// `LifecyclePosture` enum. All operational states (`Created`, `Initializing`,
/// `Active`, `Suspended`) collapse to `Operational` per the trait contract —
/// `Suspended` is the heartbeat-monitor liveness axis, not the kill-switch
/// axis.
fn map_state(state: AgentState) -> LifecyclePosture {
    match state {
        AgentState::Created
        | AgentState::Initializing
        | AgentState::Active
        | AgentState::Suspended => LifecyclePosture::Operational,
        AgentState::Paused => LifecyclePosture::Paused,
        AgentState::Quarantined => LifecyclePosture::Quarantined,
        AgentState::Terminated => LifecyclePosture::Terminated,
    }
}
