//! Gossip wire format for cross-node SeedAgent (Spec 10) propagation.
//!
//! Topic: [`SEED_AGENTS_TOPIC`] (`tenzro/seed-agents`). Every node that holds
//! a [`SeedAgentEarmarkManager`] subscribes; the four mutation paths
//! (governance executor for earmark/charter/status changes + the per-agent
//! `refill_agent_monthly` RPC) broadcast on a successful local mutation, and
//! receivers apply the inbound event idempotently against their own
//! manager so every replica converges to the same state.
//!
//! Idempotency:
//! - [`CharterUpserted`](SeedAgentGossipMessage::CharterUpserted) is a full
//!   replace keyed by `charter_id`. Re-applying the same charter is a no-op
//!   (the `charter_ids` sync skip-path handles re-insert).
//! - [`AgentRegistered`](SeedAgentGossipMessage::AgentRegistered) re-uses
//!   the same agent record; the manager's `register_agent` keeps the count
//!   from double-bumping if the DID is already known.
//! - [`AgentStatusChanged`](SeedAgentGossipMessage::AgentStatusChanged) is a
//!   simple set-state operation; re-applying the same status is a no-op
//!   (the underlying field is overwritten with the same value).
//! - [`EarmarkUpdated`](SeedAgentGossipMessage::EarmarkUpdated) carries the
//!   full snapshot; receivers replace their singleton.
//! - [`MonthlyRefillCompleted`](SeedAgentGossipMessage::MonthlyRefillCompleted)
//!   is **informational** only — receivers do NOT replay the refill (that
//!   would double-spend). It carries the originator's post-refill earmark
//!   snapshot so passive observers can track aggregate draw without polling
//!   `tenzro_getTreasuryEarmark`.
//!
//! Topic discipline is enforced by [`decode_for_topic`], which rejects any
//! payload arriving on a topic other than [`SEED_AGENTS_TOPIC`].
//!
//! Per the project convention against version segments in tenzro-owned
//! identifiers, the topic name is `tenzro/seed-agents`, not
//! `tenzro_seed_agents/1.0.0` as the early spec draft suggested.

use serde::{Deserialize, Serialize};

use crate::error::{Result, TokenError};
use crate::seed_agent::{Charter, SeedAgentRecord, SeedAgentStatus, TreasuryEarmark};

/// Gossipsub topic carrying [`SeedAgentGossipMessage`] envelopes.
pub const SEED_AGENTS_TOPIC: &str = "tenzro/seed-agents";

/// Bincode-serialised envelope for cross-node SeedAgent state propagation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SeedAgentGossipMessage {
    /// Full charter replace — governance executor or initial seed.
    CharterUpserted(Charter),
    /// Full singleton replace — governance executor or initial seed.
    EarmarkUpdated(TreasuryEarmark),
    /// New SeedAgent provisioned under an existing charter.
    AgentRegistered(SeedAgentRecord),
    /// Agent status transition (Paused / Quarantined / Terminated / Active).
    AgentStatusChanged {
        agent_did: String,
        status: SeedAgentStatus,
    },
    /// Informational broadcast after a successful monthly refill on the
    /// originating node. Receivers DO NOT replay the refill — they
    /// optionally use the carried `earmark_snapshot` to keep their local
    /// singleton up to date for read-only RPCs without polling.
    MonthlyRefillCompleted {
        agent_did: String,
        granted_wei: u128,
        month: u8,
        earmark_snapshot: TreasuryEarmark,
    },
}

/// Bincode-encode a [`SeedAgentGossipMessage::CharterUpserted`] payload.
pub fn encode_charter_upserted(charter: &Charter) -> Result<Vec<u8>> {
    let msg = SeedAgentGossipMessage::CharterUpserted(charter.clone());
    bincode::serialize(&msg).map_err(|e| {
        TokenError::InvalidParameter(format!("encode CharterUpserted: {}", e))
    })
}

/// Bincode-encode a [`SeedAgentGossipMessage::EarmarkUpdated`] payload.
pub fn encode_earmark_updated(earmark: &TreasuryEarmark) -> Result<Vec<u8>> {
    let msg = SeedAgentGossipMessage::EarmarkUpdated(earmark.clone());
    bincode::serialize(&msg).map_err(|e| {
        TokenError::InvalidParameter(format!("encode EarmarkUpdated: {}", e))
    })
}

/// Bincode-encode a [`SeedAgentGossipMessage::AgentRegistered`] payload.
pub fn encode_agent_registered(record: &SeedAgentRecord) -> Result<Vec<u8>> {
    let msg = SeedAgentGossipMessage::AgentRegistered(record.clone());
    bincode::serialize(&msg).map_err(|e| {
        TokenError::InvalidParameter(format!("encode AgentRegistered: {}", e))
    })
}

/// Bincode-encode a [`SeedAgentGossipMessage::AgentStatusChanged`] payload.
pub fn encode_agent_status_changed(
    agent_did: &str,
    status: SeedAgentStatus,
) -> Result<Vec<u8>> {
    let msg = SeedAgentGossipMessage::AgentStatusChanged {
        agent_did: agent_did.to_string(),
        status,
    };
    bincode::serialize(&msg).map_err(|e| {
        TokenError::InvalidParameter(format!("encode AgentStatusChanged: {}", e))
    })
}

/// Bincode-encode a [`SeedAgentGossipMessage::MonthlyRefillCompleted`] payload.
pub fn encode_monthly_refill_completed(
    agent_did: &str,
    granted_wei: u128,
    month: u8,
    earmark_snapshot: &TreasuryEarmark,
) -> Result<Vec<u8>> {
    let msg = SeedAgentGossipMessage::MonthlyRefillCompleted {
        agent_did: agent_did.to_string(),
        granted_wei,
        month,
        earmark_snapshot: earmark_snapshot.clone(),
    };
    bincode::serialize(&msg).map_err(|e| {
        TokenError::InvalidParameter(format!(
            "encode MonthlyRefillCompleted: {}",
            e
        ))
    })
}

/// Decode an inbound gossip payload and reject any message that does not
/// match the topic it arrived on. Returns the typed variant on success.
pub fn decode_for_topic(topic: &str, bytes: &[u8]) -> Result<SeedAgentGossipMessage> {
    let msg: SeedAgentGossipMessage = bincode::deserialize(bytes).map_err(|e| {
        TokenError::InvalidParameter(format!("decode SeedAgent gossip: {}", e))
    })?;
    if topic != SEED_AGENTS_TOPIC {
        return Err(TokenError::InvalidParameter(format!(
            "unexpected SeedAgent gossip topic '{}'",
            topic
        )));
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed_agent::{
        CounterpartyFilter, DecaySchedule, OperationKind, SpendCaps, TreasuryEarmark,
        DEFAULT_SURPLUS_BURN_BPS,
    };
    use tenzro_types::primitives::{Hash, Timestamp};

    fn h(byte: u8) -> Hash {
        Hash::new([byte; 32])
    }

    fn sample_charter() -> Charter {
        Charter {
            charter_id: h(0xC1),
            name: "InferenceLoad".to_string(),
            purpose: "test".to_string(),
            operations: vec![OperationKind::InferenceConsumer],
            spend_caps: SpendCaps::default_inference_caps(),
            target_throughput: None,
            counterparty_filter: CounterpartyFilter::default(),
            sunset: Timestamp::new(1_000_000),
            enabled: true,
        }
    }

    fn sample_record() -> SeedAgentRecord {
        SeedAgentRecord::new(
            "did:tenzro:machine:seed:001".to_string(),
            "did:tenzro:org:treasury:seedagents".to_string(),
            h(0xC1),
            Timestamp::new(0),
        )
    }

    fn sample_earmark() -> TreasuryEarmark {
        TreasuryEarmark {
            name: "SeedAgent".into(),
            initial_allocation_wei: 1_000,
            allocation_remaining_wei: 1_000,
            total_drawn_wei: 0,
            bootstrap_start: Timestamp::new(0),
            bootstrap_end: Timestamp::new(1_000_000),
            decay_schedule: DecaySchedule::default_with_base(100),
            seed_agent_count: 1,
            charter_ids: vec![h(0xC1)],
            enabled: true,
            surplus_burn_bps: DEFAULT_SURPLUS_BURN_BPS,
            current_month: 0,
            month_drawn_wei: 0,
        }
    }

    #[test]
    fn roundtrip_charter_upserted() {
        let c = sample_charter();
        let bytes = encode_charter_upserted(&c).unwrap();
        let decoded = decode_for_topic(SEED_AGENTS_TOPIC, &bytes).unwrap();
        match decoded {
            SeedAgentGossipMessage::CharterUpserted(d) => {
                assert_eq!(d.charter_id, c.charter_id);
                assert_eq!(d.name, c.name);
            }
            other => panic!("expected CharterUpserted, got {:?}", other),
        }
    }

    #[test]
    fn roundtrip_earmark_updated() {
        let e = sample_earmark();
        let bytes = encode_earmark_updated(&e).unwrap();
        let decoded = decode_for_topic(SEED_AGENTS_TOPIC, &bytes).unwrap();
        match decoded {
            SeedAgentGossipMessage::EarmarkUpdated(d) => {
                assert_eq!(d.initial_allocation_wei, e.initial_allocation_wei);
                assert_eq!(d.charter_ids, e.charter_ids);
            }
            other => panic!("expected EarmarkUpdated, got {:?}", other),
        }
    }

    #[test]
    fn roundtrip_agent_registered() {
        let r = sample_record();
        let bytes = encode_agent_registered(&r).unwrap();
        let decoded = decode_for_topic(SEED_AGENTS_TOPIC, &bytes).unwrap();
        match decoded {
            SeedAgentGossipMessage::AgentRegistered(d) => {
                assert_eq!(d.agent_did, r.agent_did);
                assert_eq!(d.charter_id, r.charter_id);
            }
            other => panic!("expected AgentRegistered, got {:?}", other),
        }
    }

    #[test]
    fn roundtrip_agent_status_changed() {
        let bytes = encode_agent_status_changed(
            "did:tenzro:machine:seed:001",
            SeedAgentStatus::Quarantined,
        )
        .unwrap();
        let decoded = decode_for_topic(SEED_AGENTS_TOPIC, &bytes).unwrap();
        match decoded {
            SeedAgentGossipMessage::AgentStatusChanged { agent_did, status } => {
                assert_eq!(agent_did, "did:tenzro:machine:seed:001");
                assert!(matches!(status, SeedAgentStatus::Quarantined));
            }
            other => panic!("expected AgentStatusChanged, got {:?}", other),
        }
    }

    #[test]
    fn roundtrip_monthly_refill_completed() {
        let e = sample_earmark();
        let bytes = encode_monthly_refill_completed(
            "did:tenzro:machine:seed:001",
            123,
            0,
            &e,
        )
        .unwrap();
        let decoded = decode_for_topic(SEED_AGENTS_TOPIC, &bytes).unwrap();
        match decoded {
            SeedAgentGossipMessage::MonthlyRefillCompleted {
                agent_did,
                granted_wei,
                month,
                earmark_snapshot,
            } => {
                assert_eq!(agent_did, "did:tenzro:machine:seed:001");
                assert_eq!(granted_wei, 123);
                assert_eq!(month, 0);
                assert_eq!(
                    earmark_snapshot.initial_allocation_wei,
                    e.initial_allocation_wei
                );
            }
            other => panic!("expected MonthlyRefillCompleted, got {:?}", other),
        }
    }

    #[test]
    fn rejects_payload_on_wrong_topic() {
        let c = sample_charter();
        let bytes = encode_charter_upserted(&c).unwrap();
        let err = decode_for_topic("tenzro/blocks", &bytes).unwrap_err();
        match err {
            TokenError::InvalidParameter(msg) => {
                assert!(msg.contains("unexpected SeedAgent gossip topic"), "{}", msg);
            }
            other => panic!("expected InvalidParameter, got {:?}", other),
        }
    }
}
