//! Who joins by snapshot and who replays the chain.
//!
//! Replaying every block from genesis is what a validator does: it holds the
//! complete history for its own consensus duties. Everyone else (an operator
//! running RPC or storage, a light node) has no use for the history, and
//! replaying it costs hours and gigabytes (the Raspberry Pi light node spent
//! 2.5 hours and 9.3 GB on 32,000 blocks). Such a node restores the committed
//! state from a peer's snapshot instead, checked against a block hash it
//! trusts (see [`crate::snapshot`]), and block-syncs only what follows.
//!
//! This is node-local policy: it decides what this node downloads and never
//! what a block or a snapshot contains, so a node on either side of the
//! decision follows the same chain.

use serde::{Deserialize, Serialize};

/// The `state_sync` setting of the node configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateSyncMode {
    /// A node without the validator role joins by snapshot when it can;
    /// a validator replays.
    #[default]
    Auto,
    /// Replay the chain from the local tip, whatever the role. Explicit
    /// `state_sync_from` peers still restore.
    Off,
}

/// Where the snapshot peers come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSource {
    /// The operator named them (`--state-sync-from`).
    Named,
    /// The boot identities the node resolved.
    Boot,
}

/// Why a node replays instead of joining by snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayReason {
    /// `state_sync = "off"` or `--no-state-sync`.
    Disabled,
    /// A validator keeps the complete history.
    Validator,
    /// The node already holds chain state: a snapshot restores a fresh node.
    HasChain,
    /// No trusted checkpoint to verify a snapshot against was configured.
    NoCheckpoint,
}

/// How a node catches up with the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinPlan {
    /// Restore the state from a snapshot, then block-sync the rest.
    Snapshot(PeerSource),
    /// Replay the blocks.
    Replay(ReplayReason),
}

/// The facts the plan rests on.
#[derive(Debug, Clone, Copy)]
pub struct JoinFacts {
    /// The configured `state_sync` mode.
    pub mode: StateSyncMode,
    /// Whether the node holds the validator role.
    pub is_validator: bool,
    /// Whether the operator named state-sync peers.
    pub named_peers: bool,
    /// Whether a weak-subjectivity checkpoint is configured (flags, genesis
    /// `[weak_subjectivity]`).
    pub has_checkpoint: bool,
    /// Whether the node already holds blocks beyond genesis.
    pub has_chain: bool,
}

/// Decides how the node catches up. Named peers always mean a snapshot
/// join: the operator asked for it (the recovery after a corrupt store uses
/// it on a validator).
pub fn plan(f: JoinFacts) -> JoinPlan {
    if f.named_peers {
        return JoinPlan::Snapshot(PeerSource::Named);
    }
    if f.mode == StateSyncMode::Off {
        return JoinPlan::Replay(ReplayReason::Disabled);
    }
    if f.is_validator {
        return JoinPlan::Replay(ReplayReason::Validator);
    }
    if f.has_chain {
        return JoinPlan::Replay(ReplayReason::HasChain);
    }
    if !f.has_checkpoint {
        return JoinPlan::Replay(ReplayReason::NoCheckpoint);
    }
    JoinPlan::Snapshot(PeerSource::Boot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> JoinFacts {
        JoinFacts {
            mode: StateSyncMode::Auto,
            is_validator: false,
            named_peers: false,
            has_checkpoint: true,
            has_chain: false,
        }
    }

    #[test]
    fn a_fresh_non_validator_with_a_checkpoint_joins_by_snapshot() {
        assert_eq!(plan(facts()), JoinPlan::Snapshot(PeerSource::Boot));
    }

    #[test]
    fn a_validator_replays_the_chain() {
        let f = JoinFacts {
            is_validator: true,
            ..facts()
        };
        assert_eq!(plan(f), JoinPlan::Replay(ReplayReason::Validator));
    }

    #[test]
    fn without_a_checkpoint_the_node_replays_rather_than_trusting_a_peer() {
        let f = JoinFacts {
            has_checkpoint: false,
            ..facts()
        };
        assert_eq!(plan(f), JoinPlan::Replay(ReplayReason::NoCheckpoint));
    }

    #[test]
    fn a_node_with_chain_state_does_not_restore() {
        let f = JoinFacts {
            has_chain: true,
            ..facts()
        };
        assert_eq!(plan(f), JoinPlan::Replay(ReplayReason::HasChain));
    }

    #[test]
    fn off_replays_unless_peers_are_named() {
        let off = JoinFacts {
            mode: StateSyncMode::Off,
            ..facts()
        };
        assert_eq!(plan(off), JoinPlan::Replay(ReplayReason::Disabled));
        let named = JoinFacts {
            named_peers: true,
            ..off
        };
        assert_eq!(plan(named), JoinPlan::Snapshot(PeerSource::Named));
    }

    #[test]
    fn a_validator_recovering_with_named_peers_still_restores() {
        let f = JoinFacts {
            is_validator: true,
            named_peers: true,
            ..facts()
        };
        assert_eq!(plan(f), JoinPlan::Snapshot(PeerSource::Named));
    }

    #[test]
    fn the_snapshot_producer_defaults_follow_the_role() {
        let unset = crate::snapshot::SnapshotConfig::default();
        assert!(unset.produces(true), "a validator produces snapshots");
        assert!(!unset.produces(false), "another role does not");
        let off = crate::snapshot::SnapshotConfig {
            enabled: Some(false),
            ..unset.clone()
        };
        assert!(!off.produces(true), "a validator can turn it off");
        let on = crate::snapshot::SnapshotConfig {
            enabled: Some(true),
            ..unset
        };
        assert!(on.produces(false), "another role can turn it on");
    }
}
