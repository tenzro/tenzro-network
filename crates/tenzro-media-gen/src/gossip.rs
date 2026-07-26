//! Gossip wire format for generative-media job coordination.
//!
//! One topic, [`MEDIA_GEN_TOPIC`] (`tenzro/media-gen`), carries every
//! media-gen envelope. A job's whole life is a small number of low-frequency
//! events — posted, claimed, completed — so a second mesh would only split the
//! subscription set without reducing traffic.
//!
//! Five payload kinds ride the topic:
//!
//! - [`WorkerEnrolled`](MediaGenGossipMessage::WorkerEnrolled) — a node with a
//!   GPU announces which models it can serve and at what resolution. Receivers
//!   record the capability so a locally-posted job can be matched against the
//!   network's capacity instead of only the local worker set.
//! - [`JobPosted`](MediaGenGossipMessage::JobPosted) — a requester's signed
//!   spec. Enrolled workers decide for themselves whether to claim it;
//!   [`MediaGenWorkerCapability::can_serve`] is the filter.
//! - [`JobClaimed`](MediaGenGossipMessage::JobClaimed) — the claiming worker
//!   tells everyone else to stop considering the job, so two GPUs do not burn
//!   the same denoising loop. A claim on a job whose schedule splits names the
//!   half taken, leaving the other half open.
//! - [`HandoffPublished`](MediaGenGossipMessage::HandoffPublished) — the
//!   high-noise expert of a split job commits to the intermediate latent. This
//!   is what tells the low-noise holder its half can start; the latent bytes
//!   themselves come from the media store, keyed by the `latent_hash` inside.
//! - [`ReceiptSubmitted`](MediaGenGossipMessage::ReceiptSubmitted) — the signed
//!   result. The `output_hash` inside is the only thing needed to fetch the
//!   rendered bytes from a [`MediaGenOutputStore`](crate::MediaGenOutputStore).
//!
//! Payloads are bincode-encoded, externally-tagged (serde default) — the same
//! encoding the rest of the network uses for its gossip envelopes.
//!
//! # Why the two bulk-carrying variants have a locator beside the payload
//!
//! A signed payload commits to its bytes with a SHA-256 hash, which is what a
//! verifier checks. It is not what a transport indexes by: iroh-blobs uses
//! BLAKE3. A node that did not render the bytes therefore knows *what* to
//! verify but not *where* to pull from.
//!
//! The locator closes that gap without touching the signed struct. It sits on
//! the envelope, outside the signing preimage, because it is a routing hint
//! rather than a claim: a wrong locator can only cause a fetch to fail or to
//! return bytes that fail the SHA-256 check the store already performs. Putting
//! it inside the payload would mean re-signing a receipt whenever it is
//! re-announced over a different transport.

use serde::{Deserialize, Serialize};

use tenzro_types::media_gen::{
    MediaGenExpertRole, MediaGenHandoff, MediaGenReceipt, MediaGenTaskSpec,
    MediaGenWorkerCapability,
};
use tenzro_types::primitives::{Address, Timestamp};

use crate::error::{MediaGenError, Result};

/// Generative-media job coordination topic.
pub const MEDIA_GEN_TOPIC: &str = "tenzro/media-gen";

/// A worker's claim announcement.
///
/// Carries only what a receiver needs to mark its local copy of the job as
/// taken. Re-broadcasting the spec would double the wire cost of every claim
/// for no gain — the receiver already has it from
/// [`JobPosted`](MediaGenGossipMessage::JobPosted).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaGenClaim {
    pub job_id: String,
    pub worker_did: String,
    pub worker_address: Address,
    /// Which half of a split schedule was taken. `None` for a job served whole
    /// — a receiver reading `None` marks the job taken outright.
    pub role: Option<MediaGenExpertRole>,
    pub claimed_at: Timestamp,
}

/// Bincode-serialised envelope for [`MEDIA_GEN_TOPIC`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MediaGenGossipMessage {
    WorkerEnrolled(MediaGenWorkerCapability),
    JobPosted(MediaGenTaskSpec),
    JobClaimed(MediaGenClaim),
    HandoffPublished {
        handoff: MediaGenHandoff,
        /// Transport locator for the latent the handoff commits to. `None`
        /// when the publisher has no transport that can name it, in which
        /// case only a node that already holds the bytes can continue the job.
        latent_locator: Option<String>,
    },
    ReceiptSubmitted {
        receipt: MediaGenReceipt,
        /// Transport locator for the rendered output. `None` leaves the
        /// receipt verifiable but the bytes unreachable from a node that did
        /// not render them.
        output_locator: Option<String>,
    },
}

/// Bincode-encode a worker capability announcement.
pub fn encode_worker_enrolled(capability: &MediaGenWorkerCapability) -> Result<Vec<u8>> {
    encode(MediaGenGossipMessage::WorkerEnrolled(capability.clone()))
}

/// Bincode-encode a posted job spec.
pub fn encode_job_posted(spec: &MediaGenTaskSpec) -> Result<Vec<u8>> {
    encode(MediaGenGossipMessage::JobPosted(spec.clone()))
}

/// Bincode-encode a claim announcement.
pub fn encode_job_claimed(claim: &MediaGenClaim) -> Result<Vec<u8>> {
    encode(MediaGenGossipMessage::JobClaimed(claim.clone()))
}

/// Bincode-encode a split job's intermediate-latent commitment, plus the
/// transport locator the low-noise holder needs to pull the latent.
pub fn encode_handoff_published(
    handoff: &MediaGenHandoff,
    latent_locator: Option<String>,
) -> Result<Vec<u8>> {
    encode(MediaGenGossipMessage::HandoffPublished {
        handoff: handoff.clone(),
        latent_locator,
    })
}

/// Bincode-encode a completed job's signed receipt, plus the transport
/// locator the requester needs to pull the rendered output.
pub fn encode_receipt_submitted(
    receipt: &MediaGenReceipt,
    output_locator: Option<String>,
) -> Result<Vec<u8>> {
    encode(MediaGenGossipMessage::ReceiptSubmitted {
        receipt: receipt.clone(),
        output_locator,
    })
}

fn encode(msg: MediaGenGossipMessage) -> Result<Vec<u8>> {
    bincode::serialize(&msg)
        .map_err(|e| MediaGenError::Serialization(format!("encode media-gen gossip: {}", e)))
}

/// Decode an inbound payload, rejecting anything that did not arrive on
/// [`MEDIA_GEN_TOPIC`].
///
/// Topic discipline lives here so the event loop never has to know the wire
/// format.
pub fn decode_for_topic(topic: &str, bytes: &[u8]) -> Result<MediaGenGossipMessage> {
    if topic != MEDIA_GEN_TOPIC {
        return Err(MediaGenError::Serialization(format!(
            "unexpected media-gen gossip topic '{}'",
            topic
        )));
    }
    bincode::deserialize(bytes)
        .map_err(|e| MediaGenError::Serialization(format!("decode media-gen gossip: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use tenzro_types::media_gen::{MediaGenExpertHolding, MediaGenKind, MediaGenParams};
    use tenzro_types::primitives::{Hash, Signature};

    fn params() -> MediaGenParams {
        MediaGenParams {
            prompt: "a plaster model of a lighthouse".to_string(),
            negative_prompt: None,
            width: 1024,
            height: 1024,
            num_frames: None,
            fps: None,
            steps: 30,
            guidance_scale: 4.5,
            seed: Some(11),
            input_image_hash: None,
            metadata: HashMap::new(),
        }
    }

    fn spec() -> MediaGenTaskSpec {
        MediaGenTaskSpec {
            job_id: "job-1".to_string(),
            requester_did: "did:tenzro:human:requester".to_string(),
            requester_address: Address::zero(),
            model_id: "qwen-image".to_string(),
            kind: MediaGenKind::Text2Image,
            params: params(),
            max_price: 10_000,
            created_at: Timestamp::new(0),
            metadata: HashMap::new(),
        }
    }

    fn capability() -> MediaGenWorkerCapability {
        MediaGenWorkerCapability {
            worker_did: "did:tenzro:machine:worker".to_string(),
            worker_address: Address::new([3u8; 32]),
            supported_models: vec!["qwen-image".to_string()],
            expert_holdings: vec![MediaGenExpertHolding {
                model_id: "wan2.2-t2v-a14b".to_string(),
                role: MediaGenExpertRole::HighNoise,
            }],
            max_resolution: 2048,
            max_frames: None,
            gpu_vram_gb: 80.0,
            registered_at: Timestamp::new(0),
        }
    }

    fn claim() -> MediaGenClaim {
        MediaGenClaim {
            job_id: "job-1".to_string(),
            worker_did: "did:tenzro:machine:worker".to_string(),
            worker_address: Address::new([3u8; 32]),
            role: Some(MediaGenExpertRole::HighNoise),
            claimed_at: Timestamp::new(5),
        }
    }

    fn handoff() -> MediaGenHandoff {
        MediaGenHandoff {
            job_id: "job-1".to_string(),
            from_worker_did: "did:tenzro:machine:worker".to_string(),
            from_worker_address: Address::new([3u8; 32]),
            latent_hash: Hash::new([4u8; 32]),
            latent_bytes: 8_388_608,
            steps_completed: 26,
            handed_off_at: Timestamp::new(7),
            worker_signature: Signature::default(),
        }
    }

    fn receipt() -> MediaGenReceipt {
        MediaGenReceipt {
            job_id: "job-1".to_string(),
            task_spec: spec(),
            worker_did: "did:tenzro:machine:worker".to_string(),
            worker_address: Address::new([3u8; 32]),
            output_hash: Hash::new([9u8; 32]),
            output_mime: "image/png".to_string(),
            output_bytes: 2048,
            seed_used: 11,
            generation_time_ms: 3_100,
            price_paid: 9_000,
            completed_at: Timestamp::new(9),
            worker_signature: Signature::default(),
        }
    }

    #[test]
    fn worker_enrolled_round_trips() {
        let c = capability();
        let bytes = encode_worker_enrolled(&c).unwrap();
        match decode_for_topic(MEDIA_GEN_TOPIC, &bytes).unwrap() {
            MediaGenGossipMessage::WorkerEnrolled(d) => {
                assert_eq!(d.worker_did, c.worker_did);
                assert_eq!(d.supported_models, c.supported_models);
                assert_eq!(d.expert_holdings, c.expert_holdings);
            }
            other => panic!("expected WorkerEnrolled, got {:?}", other),
        }
    }

    #[test]
    fn handoff_published_round_trips_with_its_locator() {
        let h = handoff();
        let bytes = encode_handoff_published(&h, Some("bafkr-latent".to_string())).unwrap();
        match decode_for_topic(MEDIA_GEN_TOPIC, &bytes).unwrap() {
            MediaGenGossipMessage::HandoffPublished {
                handoff: d,
                latent_locator,
            } => {
                assert_eq!(d, h);
                assert_eq!(latent_locator.as_deref(), Some("bafkr-latent"));
            }
            other => panic!("expected HandoffPublished, got {:?}", other),
        }
    }

    #[test]
    fn a_locator_is_optional_on_the_wire() {
        // A publisher with no addressable transport still announces the
        // commitment — receivers just cannot fetch the bytes from it.
        let bytes = encode_handoff_published(&handoff(), None).unwrap();
        match decode_for_topic(MEDIA_GEN_TOPIC, &bytes).unwrap() {
            MediaGenGossipMessage::HandoffPublished { latent_locator, .. } => {
                assert!(latent_locator.is_none())
            }
            other => panic!("expected HandoffPublished, got {:?}", other),
        }
    }

    #[test]
    fn job_posted_round_trips() {
        let s = spec();
        let bytes = encode_job_posted(&s).unwrap();
        match decode_for_topic(MEDIA_GEN_TOPIC, &bytes).unwrap() {
            MediaGenGossipMessage::JobPosted(d) => {
                assert_eq!(d.job_id, s.job_id);
                assert_eq!(d.kind, s.kind);
                assert_eq!(d.params.prompt, s.params.prompt);
            }
            other => panic!("expected JobPosted, got {:?}", other),
        }
    }

    #[test]
    fn job_claimed_round_trips() {
        let c = claim();
        let bytes = encode_job_claimed(&c).unwrap();
        match decode_for_topic(MEDIA_GEN_TOPIC, &bytes).unwrap() {
            MediaGenGossipMessage::JobClaimed(d) => assert_eq!(d, c),
            other => panic!("expected JobClaimed, got {:?}", other),
        }
    }

    #[test]
    fn receipt_submitted_round_trips_with_its_locator() {
        let r = receipt();
        let bytes = encode_receipt_submitted(&r, Some("bafkr-output".to_string())).unwrap();
        match decode_for_topic(MEDIA_GEN_TOPIC, &bytes).unwrap() {
            MediaGenGossipMessage::ReceiptSubmitted {
                receipt: d,
                output_locator,
            } => {
                assert_eq!(d.job_id, r.job_id);
                assert_eq!(d.output_hash, r.output_hash);
                assert_eq!(d.price_paid, r.price_paid);
                assert_eq!(output_locator.as_deref(), Some("bafkr-output"));
            }
            other => panic!("expected ReceiptSubmitted, got {:?}", other),
        }
    }

    #[test]
    fn rejects_another_topic() {
        let bytes = encode_job_posted(&spec()).unwrap();
        let err = decode_for_topic("tenzro/training", &bytes).unwrap_err();
        match err {
            MediaGenError::Serialization(s) => {
                assert!(s.contains("unexpected media-gen gossip topic"))
            }
            other => panic!("expected Serialization error, got {:?}", other),
        }
    }

    #[test]
    fn rejects_garbage_bytes() {
        let err = decode_for_topic(MEDIA_GEN_TOPIC, &[0xff, 0xff, 0xff, 0xff]).unwrap_err();
        assert!(matches!(err, MediaGenError::Serialization(_)));
    }
}
