//! Kill-switch primitive types (Agent-Swarm Spec 1).
//!
//! `KillSwitchReceipt` is the canonical on-chain artifact written when a
//! `PauseAgent` / `QuarantineAgent` / `TerminateAgent` precompile fires.
//! It is consumed by:
//!
//! - The node's `KillSwitchStore` (RocksDB CF_SETTLEMENTS write-through).
//! - The `tenzro_listKillSwitchByAgent` / `tenzro_listKillSwitchByController`
//!   RPC handlers.
//! - The `AgentRuntime` lifecycle dispatcher, which mirrors the action onto
//!   the in-memory `AgentLifecycle` state machine after the VM commits.
//!
//! The receipt is structurally simple: it commits the action, the actor,
//! the target, the reason, and (for terminate) the slash + cascade flags,
//! plus a `frozen_at_block` so auditors can correlate against block state.
//! Receipt id derivation is deterministic for replay-resistance:
//! `id = SHA-256("tenzro/killswitch/receipt" || action || agent_did ||
//!  controller_did || block_height_le)`.

use serde::{Deserialize, Serialize};

use crate::primitives::{BlockHeight, Timestamp};

/// Tier of intervention performed by the kill-switch.
///
/// Distinct from `tenzro_agent::lifecycle::AgentState` — that is the
/// runtime FSM, this is the on-chain action label that produced the
/// transition. The two are not 1:1: an `Active → Quarantined` transition
/// can come from either a controller `Quarantine` or an escalated
/// `Pause → Quarantine`. This field records *what was issued*, not *what
/// the agent's resulting state is* (the receipt does not duplicate the
/// FSM — readers join on `agent_did`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KillSwitchAction {
    /// Reversible pause (tier 1).
    Pause,
    /// Reversible quarantine (tier 2).
    Quarantine,
    /// Irreversible termination (tier 3).
    Terminate,
}

impl KillSwitchAction {
    /// Human-readable label used in log topics, RPC envelopes, and CF
    /// receipt-id derivation.
    pub fn as_str(&self) -> &'static str {
        match self {
            KillSwitchAction::Pause => "pause",
            KillSwitchAction::Quarantine => "quarantine",
            KillSwitchAction::Terminate => "terminate",
        }
    }
}

/// Receipt written to CF_SETTLEMENTS for every successful kill-switch
/// precompile execution. Indexed by both `agent_did` and `controller_did`
/// for the listing RPCs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KillSwitchReceipt {
    /// Deterministic 32-byte receipt id (hex-encoded). See module docs.
    pub receipt_id: String,
    /// What was issued.
    pub action: KillSwitchAction,
    /// DID of the agent the action targeted (`did:tenzro:machine:...`).
    pub agent_did: String,
    /// DID of the controller / committee / governance proposer that
    /// authorised the action. For cascaded terminations this is the
    /// upstream parent's controller — the cascaded children inherit the
    /// authority of the root termination.
    pub controller_did: String,
    /// Canonical reason code (see kill-switch spec §"Reason codes").
    pub reason_code: u16,
    /// Optional human-readable reason text, capped at 256 bytes by the
    /// transaction validator.
    pub reason_text: Option<String>,
    /// Optional commitment hash to off-chain evidence (32-byte SHA-256
    /// hex). Only meaningful for `Quarantine` and `Terminate`.
    pub evidence_hash: Option<String>,
    /// For `Terminate` only: basis points of stake to slash, capped per
    /// governance `slash_bps_cap`. `None` for Pause / Quarantine.
    pub slash_bps: Option<u16>,
    /// For `Terminate` only: whether the action recursively terminates
    /// descendants under the agent's `children:` index.
    pub cascade: Option<bool>,
    /// For `Pause` only: optional auto-resume deadline (Unix seconds).
    /// `None` means an indefinite pause that requires an explicit resume
    /// action. Always `None` for `Quarantine` / `Terminate`.
    pub pause_until: Option<u64>,
    /// Block height at which the action was finalized.
    pub frozen_at_block: BlockHeight,
    /// Wall-clock timestamp of finalization (informational; the
    /// authoritative ordering is the block height).
    pub timestamp: Timestamp,
}

impl KillSwitchReceipt {
    /// Returns true if the receipt represents a reversible action.
    pub fn is_reversible(&self) -> bool {
        matches!(
            self.action,
            KillSwitchAction::Pause | KillSwitchAction::Quarantine
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_roundtrip_strings() {
        assert_eq!(KillSwitchAction::Pause.as_str(), "pause");
        assert_eq!(KillSwitchAction::Quarantine.as_str(), "quarantine");
        assert_eq!(KillSwitchAction::Terminate.as_str(), "terminate");
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let r = KillSwitchReceipt {
            receipt_id: "deadbeef".to_string(),
            action: KillSwitchAction::Quarantine,
            agent_did: "did:tenzro:machine:alice".to_string(),
            controller_did: "did:tenzro:human:bob".to_string(),
            reason_code: 100,
            reason_text: Some("safety".into()),
            evidence_hash: None,
            slash_bps: None,
            cascade: None,
            pause_until: None,
            frozen_at_block: BlockHeight::new(42),
            timestamp: Timestamp::new(1_700_000_000_000),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: KillSwitchReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
        assert!(r.is_reversible());
    }

    #[test]
    fn terminate_is_irreversible() {
        let r = KillSwitchReceipt {
            receipt_id: "abc".to_string(),
            action: KillSwitchAction::Terminate,
            agent_did: "did:tenzro:machine:alice".to_string(),
            controller_did: "did:tenzro:human:bob".to_string(),
            reason_code: 200,
            reason_text: None,
            evidence_hash: None,
            slash_bps: Some(10_000),
            cascade: Some(true),
            pause_until: None,
            frozen_at_block: BlockHeight::new(0),
            timestamp: Timestamp::new(0),
        };
        assert!(!r.is_reversible());
    }
}
