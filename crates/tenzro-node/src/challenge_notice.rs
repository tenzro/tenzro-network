//! Inference challenges reach every node that may hold a seat.
//!
//! A challenge is filed on one node, but its committee is drawn from every
//! validator. The filing node publishes the challenge, with the commitment
//! its provider's receipt binds, on its own gossip topic; each seat's signed
//! commit and reveal travel the same way. A receiving node takes in a filing
//! only when the receipt verifies, the entropy block is the one its own chain
//! holds at that height and the entropy draws exactly the named committee, so
//! the filing node cannot pick the seats. Votes carry the seat's signature, so
//! every node applies them with the same checks and finalizes the same record.
//!
//! The challenged inputs never travel here: the filing node serves them only
//! to a drawn seat that signs for them (`tenzro_getChallengeInputs`).
//!
//! Only validators and model providers join the topic; a light node pays
//! nothing for it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tenzro_model::toploc::InferenceCommitment;
use tenzro_network::{MessagePayload, NetworkMessage, NetworkService};
use tracing::{debug, warn};

use crate::inference_challenge::{
    ChallengeManager, ChallengeWindows, InferenceChallenge, now_secs,
};
use crate::node::TenzroNode;

/// The gossip topic challenges and their votes travel on.
pub const INFERENCE_CHALLENGES_TOPIC: &str = "tenzro/inference-challenges";

/// Messages one neighbour may deliver on the topic per minute; the rest are
/// dropped unjudged.
const MAX_PER_NEIGHBOUR_PER_MINUTE: u32 = 120;

/// How often open challenges past their reveal window are closed.
const EXPIRY_INTERVAL: Duration = Duration::from_secs(60);

/// What travels on [`INFERENCE_CHALLENGES_TOPIC`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChallengeGossip {
    /// A challenge as filed, with the commitment its receipt names.
    Filed {
        challenge: Box<InferenceChallenge>,
        commitment: InferenceCommitment,
    },
    /// A seat's signed vote commit.
    Commit {
        challenge_id: String,
        voter: String,
        commit_hash: String,
        signature: String,
    },
    /// A seat's signed vote reveal.
    Reveal {
        challenge_id: String,
        voter: String,
        verdict: bool,
        salt: String,
        signature: String,
    },
}

impl ChallengeGossip {
    fn challenge_id(&self) -> &str {
        match self {
            Self::Filed { challenge, .. } => &challenge.challenge_id,
            Self::Commit { challenge_id, .. } | Self::Reveal { challenge_id, .. } => challenge_id,
        }
    }

    /// Whether `manager` already has what this message carries, answered
    /// before any signature is checked.
    pub(crate) fn already_held(&self, manager: &ChallengeManager) -> bool {
        let Some(held) = manager.get(self.challenge_id()) else {
            return false;
        };
        let voter = |v: &str| crate::inference_challenge::canonical_voter(v);
        match self {
            Self::Filed { .. } => true,
            Self::Commit { voter: v, .. } => {
                let v = voter(v);
                held.votes.iter().any(|vote| vote.voter == v)
            }
            Self::Reveal { voter: v, .. } => {
                let v = voter(v);
                held.votes
                    .iter()
                    .any(|vote| vote.voter == v && vote.is_revealed())
            }
        }
    }
}

/// Whether this node carries the topic.
pub fn joins_topic(node: &TenzroNode) -> bool {
    let roles = &node.config().roles;
    roles.is_validator() || roles.is_provider()
}

/// Publishes `message` on the topic. A node that does not carry the topic
/// publishes nothing.
pub async fn publish(node: &TenzroNode, message: &ChallengeGossip) {
    let Some(network) = node.network() else {
        return;
    };
    if !joins_topic(node) {
        return;
    }
    let data = match serde_json::to_vec(message) {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "inference challenge gossip encode failed");
            return;
        }
    };
    let msg = NetworkMessage::new(MessagePayload::Custom {
        topic: INFERENCE_CHALLENGES_TOPIC.to_string(),
        data,
    });
    if let Err(e) = network.broadcast(INFERENCE_CHALLENGES_TOPIC, msg).await {
        debug!(error = %e, "inference challenge broadcast failed");
    }
}

/// Per-neighbour message counts over one-minute windows.
#[derive(Default)]
struct NeighbourRate {
    windows: HashMap<tenzro_iroh::EndpointId, (Instant, u32)>,
}

impl NeighbourRate {
    fn admit(&mut self, from: tenzro_iroh::EndpointId, now: Instant) -> bool {
        self.windows
            .retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(60));
        let (_, count) = self.windows.entry(from).or_insert((now, 0));
        *count += 1;
        *count <= MAX_PER_NEIGHBOUR_PER_MINUTE
    }
}

/// How a received message was judged.
#[derive(Debug, PartialEq, Eq)]
enum Judgement {
    /// Taken in: pass it on.
    Taken,
    /// Malformed or forged: blame the neighbour.
    Invalid,
    /// Nothing to do here (already held, unknown challenge, out of window,
    /// or this node cannot check it yet): drop without blame.
    Skipped,
}

/// Joins the topic (validators and model providers) and starts closing
/// expired challenges (every node holding a challenge manager).
pub fn spawn(node: Arc<TenzroNode>) {
    let Some(manager) = node.challenge_manager().cloned() else {
        return;
    };
    let expiring = manager.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(EXPIRY_INTERVAL);
        loop {
            tick.tick().await;
            expiring.expire(now_secs());
        }
    });
    if !joins_topic(&node) {
        return;
    }
    let Some(network) = node.network().cloned() else {
        return;
    };
    tokio::spawn(async move {
        let mut sub = match network
            .subscribe_validated(INFERENCE_CHALLENGES_TOPIC)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "could not subscribe to {}", INFERENCE_CHALLENGES_TOPIC);
                return;
            }
        };
        let mut rate = NeighbourRate::default();
        while let Some(validated) = sub.recv().await {
            let ticket = validated.ticket;
            if !rate.admit(ticket.from(), Instant::now()) {
                ticket.ignore();
                continue;
            }
            let MessagePayload::Custom { data, .. } = validated.message.payload else {
                ticket.reject();
                continue;
            };
            let Ok(message) = serde_json::from_slice::<ChallengeGossip>(&data) else {
                ticket.reject();
                continue;
            };
            if message.already_held(&manager) {
                ticket.ignore();
                continue;
            }
            match judge(&node, &manager, message).await {
                Judgement::Taken => ticket.accept(),
                Judgement::Invalid => ticket.reject(),
                Judgement::Skipped => ticket.ignore(),
            }
        }
    });
}

async fn judge(
    node: &Arc<TenzroNode>,
    manager: &ChallengeManager,
    message: ChallengeGossip,
) -> Judgement {
    let now = now_secs();
    match message {
        ChallengeGossip::Filed {
            challenge,
            commitment,
        } => adopt_filing(node, manager, *challenge, commitment, now).await,
        ChallengeGossip::Commit {
            challenge_id,
            voter,
            commit_hash,
            signature,
        } => match manager.commit_vote(&challenge_id, &voter, &commit_hash, &signature, now) {
            Ok(_) => Judgement::Taken,
            Err(e) => {
                debug!(challenge = %challenge_id, error = %e, "gossiped vote commit not applied");
                Judgement::Skipped
            }
        },
        ChallengeGossip::Reveal {
            challenge_id,
            voter,
            verdict,
            salt,
            signature,
        } => {
            let Ok(salt) = hex::decode(salt.trim_start_matches("0x")) else {
                return Judgement::Invalid;
            };
            match manager.reveal_vote(&challenge_id, &voter, verdict, &salt, &signature, now) {
                Ok(_) => Judgement::Taken,
                Err(e) => {
                    debug!(challenge = %challenge_id, error = %e, "gossiped vote reveal not applied");
                    Judgement::Skipped
                }
            }
        }
    }
}

async fn adopt_filing(
    node: &Arc<TenzroNode>,
    manager: &ChallengeManager,
    challenge: InferenceChallenge,
    commitment: InferenceCommitment,
    now: u64,
) -> Judgement {
    if crate::exposure::check_public_https(&challenge.holder_rpc).is_err() {
        return Judgement::Invalid;
    }
    let Some(key) = crate::identity_bootstrap::registered_identity_key(
        &node.identity_registry_slot(),
        &challenge.receipt.machine_did,
    ) else {
        // This node does not know the provider yet.
        return Judgement::Skipped;
    };
    let stored = match crate::inference_challenge::supplied_commitment(
        &challenge.commitment_hash,
        commitment,
        &challenge.receipt,
        &key,
    ) {
        Ok(stored) => stored,
        Err(_) => return Judgement::Invalid,
    };
    match crate::rpc::certified_block_hash(node, challenge.entropy_height).await {
        Some(hash) if hex::encode(hash.as_bytes()) == challenge.chain_entropy => {}
        Some(_) => return Judgement::Invalid,
        // Not yet certified here.
        None => return Judgement::Skipped,
    }
    let Ok(candidates) = crate::rpc::challenge_committee_candidates(node) else {
        return Judgement::Skipped;
    };
    let windows = ChallengeWindows::governed(crate::rpc::chain_state_of(node).as_ref());
    match manager.adopt(challenge, stored, &candidates, windows, now) {
        Ok(_) => Judgement::Taken,
        Err(e) => {
            debug!(error = %e, "gossiped inference challenge not adopted");
            Judgement::Invalid
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_neighbour_past_its_rate_is_dropped_until_its_window_turns() {
        let mut rate = NeighbourRate::default();
        let from = iroh::SecretKey::from_bytes(&[7u8; 32]).public();
        let other = iroh::SecretKey::from_bytes(&[9u8; 32]).public();
        let t0 = Instant::now();
        for _ in 0..MAX_PER_NEIGHBOUR_PER_MINUTE {
            assert!(rate.admit(from, t0));
        }
        assert!(!rate.admit(from, t0));
        // Another neighbour has its own allowance.
        assert!(rate.admit(other, t0));
        assert!(rate.admit(from, t0 + Duration::from_secs(61)));
    }
}
