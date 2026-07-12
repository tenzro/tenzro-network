//! Gossip wire format for cross-syncer Tenzro Train messages.
//!
//! Two topics:
//!
//! - [`TRAINING_TOPIC`] (`tenzro/training`) — trainers publish their per-round
//!   per-fragment [`OuterGradient`]s here. A remote syncer for the same
//!   `task_id` ingests the gradient via
//!   [`SyncerState::accept_outer_gradient`](crate::SyncerState::accept_outer_gradient)
//!   exactly as if it had arrived via the local
//!   `tenzro_training_submitOuterGradient` RPC. Idempotency is provided by the
//!   accept-path's `trainer_did` dedup, so re-receiving a self-published
//!   gradient is a no-op.
//!
//! - [`TRAINING_SYNCER_TOPIC`] (`tenzro/training/syncer`) — the elected syncer
//!   for a run publishes a signed [`SyncRound`] after every successful
//!   `finalize_round`. Other syncers (failover candidates) and any local
//!   trainer-side daemons can use this to track the canonical `state_root`
//!   chain without polling `tenzro_training_getRun`.
//!
//! Both topics carry a single bincode-encoded [`TrainingGossipMessage`]. The
//! enum is externally-tagged (serde default), the same encoding the rest of
//! `tenzro-network` uses for `MessagePayload` and `ConsensusMessage` — see
//! the rationale comment in `tenzro_network::message`. The topic the message
//! arrived on is used as a filter: an `OuterGradient` on the syncer topic is
//! malformed and dropped, and vice versa.

use serde::{Deserialize, Serialize};
use tenzro_types::training::{OuterGradient, SealedDatasetManifest, SyncRound};

use crate::error::{Result, TrainingError};

/// Outer-gradient + sealed-manifest broadcast topic.
///
/// Two payload kinds ride this topic: high-frequency [`OuterGradient`]
/// envelopes (one per trainer × round × fragment) and low-frequency
/// [`SealedDatasetManifest`] install events (one per Confidential-tier task
/// over its lifetime). Both are sponsor- or trainer-authored content
/// addressed to all syncers tracking the run; reusing the same topic keeps
/// the subscription set identical and avoids a second mesh.
pub const TRAINING_TOPIC: &str = "tenzro/training";

/// Per-round syncer state-root broadcast topic.
pub const TRAINING_SYNCER_TOPIC: &str = "tenzro/training/syncer";

/// Bincode-serialised envelope for the two Tenzro Train gossip topics.
///
/// Topic discipline:
/// - [`OuterGradient`] and [`InstallSealedManifest`](Self::InstallSealedManifest)
///   are valid only on [`TRAINING_TOPIC`].
/// - [`SyncRound`] is valid only on [`TRAINING_SYNCER_TOPIC`].
///
/// The consumer-side helper [`decode_for_topic`] enforces this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrainingGossipMessage {
    OuterGradient(OuterGradient),
    SyncRound(SyncRound),
    /// A sponsor's signed sealed-shard manifest install announcement
    /// (Phase B2, #217). Receivers attempt `install_sealed_manifest`
    /// idempotently — the existing hash-binding check rejects a manifest
    /// that does not match the task spec's `tee://<hex>` `dataset_ref`,
    /// and the canonical-hash stamp inside `install_sealed_manifest`
    /// makes redundant installs a no-op.
    ///
    /// The manifest is content-addressed by its `manifest_hash` (which is
    /// recomputed deterministically inside the install path). The shard
    /// ciphertexts referenced from inside the envelopes are fetched
    /// separately via a [`crate::SealedShardStore`] adapter (typically
    /// `IrohSealedShardStore`) keyed on `shard_ciphertext_hash`.
    InstallSealedManifest(SealedDatasetManifest),
}

/// Bincode-encode an [`OuterGradient`] for publication on [`TRAINING_TOPIC`].
pub fn encode_outer_gradient(gradient: &OuterGradient) -> Result<Vec<u8>> {
    let msg = TrainingGossipMessage::OuterGradient(gradient.clone());
    bincode::serialize(&msg)
        .map_err(|e| TrainingError::Serialization(format!("encode OuterGradient: {}", e)))
}

/// Bincode-encode a [`SyncRound`] for publication on [`TRAINING_SYNCER_TOPIC`].
pub fn encode_sync_round(round: &SyncRound) -> Result<Vec<u8>> {
    let msg = TrainingGossipMessage::SyncRound(round.clone());
    bincode::serialize(&msg)
        .map_err(|e| TrainingError::Serialization(format!("encode SyncRound: {}", e)))
}

/// Bincode-encode a [`SealedDatasetManifest`] install event for publication
/// on [`TRAINING_TOPIC`] (Phase B2, #217).
pub fn encode_install_sealed_manifest(manifest: &SealedDatasetManifest) -> Result<Vec<u8>> {
    let msg = TrainingGossipMessage::InstallSealedManifest(manifest.clone());
    bincode::serialize(&msg).map_err(|e| {
        TrainingError::Serialization(format!("encode InstallSealedManifest: {}", e))
    })
}

/// Decode an inbound gossip payload and reject any message that does not
/// match the topic it arrived on.
///
/// Returns the typed variant on success. Topic discipline is enforced here
/// so the event loop never has to know about the wire format.
pub fn decode_for_topic(topic: &str, bytes: &[u8]) -> Result<TrainingGossipMessage> {
    let msg: TrainingGossipMessage = bincode::deserialize(bytes)
        .map_err(|e| TrainingError::Serialization(format!("decode gossip message: {}", e)))?;
    match (topic, &msg) {
        (TRAINING_TOPIC, TrainingGossipMessage::OuterGradient(_))
        | (TRAINING_TOPIC, TrainingGossipMessage::InstallSealedManifest(_))
        | (TRAINING_SYNCER_TOPIC, TrainingGossipMessage::SyncRound(_)) => Ok(msg),
        (TRAINING_TOPIC, TrainingGossipMessage::SyncRound(_)) => Err(TrainingError::Serialization(
            format!("SyncRound payload on outer-gradient topic '{}'", topic),
        )),
        (TRAINING_SYNCER_TOPIC, TrainingGossipMessage::OuterGradient(_)) => {
            Err(TrainingError::Serialization(format!(
                "OuterGradient payload on syncer topic '{}'",
                topic
            )))
        }
        (TRAINING_SYNCER_TOPIC, TrainingGossipMessage::InstallSealedManifest(_)) => {
            Err(TrainingError::Serialization(format!(
                "InstallSealedManifest payload on syncer topic '{}'",
                topic
            )))
        }
        (other, _) => Err(TrainingError::Serialization(format!(
            "unexpected training gossip topic '{}'",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tenzro_types::primitives::{Address, Hash, Signature, Timestamp};
    use tenzro_types::training::{FragmentQuorumStatus, OuterGradient, SyncRound};

    fn h(n: u8) -> Hash {
        Hash::new([n; 32])
    }

    fn sample_gradient() -> OuterGradient {
        OuterGradient {
            task_id: "task-1".to_string(),
            round: 0,
            fragment: 0,
            trainer_did: "did:tenzro:machine:bob".to_string(),
            trainer_address: Address::new([0u8; 32]),
            safetensors_hash: h(1),
            payload_bytes: 1024,
            quantization: tenzro_types::training::GradientQuantization::None,
            inner_step_count: 32,
            submitted_at: Timestamp::now(),
            signature: Signature::default(),
            attestation: None,
            commitment: None,
        }
    }

    fn sample_sync_round() -> SyncRound {
        let mut fragment_quorums = HashMap::new();
        fragment_quorums.insert(
            0,
            FragmentQuorumStatus {
                fragment: 0,
                accepted: 3,
                accepted_hashes: vec![h(1), h(2), h(3)],
                quorum_met: true,
                post_step_hash: h(2),
            },
        );
        SyncRound {
            task_id: "task-1".to_string(),
            round: 0,
            fragment_quorums,
            state_root: h(3),
            syncer_signature: Signature::default(),
            published_at: Timestamp::now(),
            no_quorum_witnesses: None,
        }
    }

    #[test]
    fn roundtrip_outer_gradient_on_correct_topic() {
        let g = sample_gradient();
        let bytes = encode_outer_gradient(&g).unwrap();
        let decoded = decode_for_topic(TRAINING_TOPIC, &bytes).unwrap();
        match decoded {
            TrainingGossipMessage::OuterGradient(d) => {
                assert_eq!(d.task_id, g.task_id);
                assert_eq!(d.round, g.round);
                assert_eq!(d.fragment, g.fragment);
            }
            _ => panic!("expected OuterGradient variant"),
        }
    }

    #[test]
    fn roundtrip_sync_round_on_correct_topic() {
        let r = sample_sync_round();
        let bytes = encode_sync_round(&r).unwrap();
        let decoded = decode_for_topic(TRAINING_SYNCER_TOPIC, &bytes).unwrap();
        match decoded {
            TrainingGossipMessage::SyncRound(d) => {
                assert_eq!(d.task_id, r.task_id);
                assert_eq!(d.state_root, r.state_root);
            }
            _ => panic!("expected SyncRound variant"),
        }
    }

    #[test]
    fn rejects_outer_gradient_on_syncer_topic() {
        let g = sample_gradient();
        let bytes = encode_outer_gradient(&g).unwrap();
        let err = decode_for_topic(TRAINING_SYNCER_TOPIC, &bytes).unwrap_err();
        match err {
            TrainingError::Serialization(s) => assert!(s.contains("OuterGradient")),
            _ => panic!("expected Serialization error, got {:?}", err),
        }
    }

    #[test]
    fn rejects_sync_round_on_gradient_topic() {
        let r = sample_sync_round();
        let bytes = encode_sync_round(&r).unwrap();
        let err = decode_for_topic(TRAINING_TOPIC, &bytes).unwrap_err();
        match err {
            TrainingError::Serialization(s) => assert!(s.contains("SyncRound")),
            _ => panic!("expected Serialization error, got {:?}", err),
        }
    }

    #[test]
    fn rejects_unknown_topic() {
        let g = sample_gradient();
        let bytes = encode_outer_gradient(&g).unwrap();
        let err = decode_for_topic("tenzro/blocks", &bytes).unwrap_err();
        match err {
            TrainingError::Serialization(s) => assert!(s.contains("unexpected training gossip topic")),
            _ => panic!("expected Serialization error, got {:?}", err),
        }
    }

    fn sample_manifest() -> tenzro_types::training::SealedDatasetManifest {
        use tenzro_types::training::{SealedDatasetManifest, SealedShardEnvelope};
        let env = SealedShardEnvelope {
            trainer_did: "did:tenzro:machine:alice".to_string(),
            shard_index: 0,
            shard_ciphertext_hash: h(7),
            shard_ciphertext_bytes: 1024,
            wrapped_data_key: vec![0xbb; 96],
            wrap_alg: "hpke-x25519-hkdf-sha256-aes-256-gcm".to_string(),
            enclave_pubkey: vec![0xcc; 32],
            enclave_measurements_hex: "deadbeef".to_string(),
            created_at: Timestamp::now(),
        };
        SealedDatasetManifest {
            task_id: "task-c1".to_string(),
            sponsor_did: "did:tenzro:human:sponsor".to_string(),
            manifest_hash: h(9),
            envelopes: vec![env],
            sponsor_signature: Signature::default(),
            created_at: Timestamp::now(),
        }
    }

    #[test]
    fn roundtrip_install_sealed_manifest_on_training_topic() {
        let m = sample_manifest();
        let bytes = encode_install_sealed_manifest(&m).unwrap();
        let decoded = decode_for_topic(TRAINING_TOPIC, &bytes).unwrap();
        match decoded {
            TrainingGossipMessage::InstallSealedManifest(d) => {
                assert_eq!(d.task_id, m.task_id);
                assert_eq!(d.sponsor_did, m.sponsor_did);
                assert_eq!(d.envelopes.len(), 1);
            }
            _ => panic!("expected InstallSealedManifest variant"),
        }
    }

    #[test]
    fn rejects_install_sealed_manifest_on_syncer_topic() {
        let m = sample_manifest();
        let bytes = encode_install_sealed_manifest(&m).unwrap();
        let err = decode_for_topic(TRAINING_SYNCER_TOPIC, &bytes).unwrap_err();
        match err {
            TrainingError::Serialization(s) => assert!(s.contains("InstallSealedManifest")),
            _ => panic!("expected Serialization error, got {:?}", err),
        }
    }
}
