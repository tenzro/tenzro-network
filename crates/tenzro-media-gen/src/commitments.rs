//! Deterministic job identity and receipt signing preimages.
//!
//! Three independent digests:
//!
//! - [`compute_job_id`] derives a job's identity from the posted request, so a
//!   requester and a node compute the same id without a round-trip and a
//!   duplicate post is detected as such rather than queued twice.
//! - [`handoff_signing_bytes`] is the preimage the high-noise expert of a split
//!   job signs over the intermediate latent. It binds the latent's content hash
//!   and the step count, so the low-noise holder knows exactly which bytes it is
//!   picking up and how much of the schedule is left to run.
//! - [`receipt_signing_bytes`] is the canonical preimage a worker signs to
//!   attest a completed job. It binds the job id, the spec the worker actually
//!   executed, and the content hash of the output — so a worker cannot swap
//!   the artifact or the parameters after signing.
//!
//! Both must stay byte-identical to the Python reference worker's
//! implementation (`integrations/media_gen/tenzro_media_gen/commitments.py`).
//! Encoding rules, applied uniformly:
//!
//! - Integers are big-endian, at their declared width.
//! - `Timestamp` is two's-complement i64 milliseconds (Python:
//!   `to_bytes(8, "big", signed=True)`).
//! - `f32` is its IEEE-754 big-endian bit pattern. `MediaGenParams::validate_for`
//!   rejects non-finite values, so the pattern is always canonical.
//! - Variable-length fields are length-prefixed with a big-endian `u32` byte
//!   count, so no field boundary is ambiguous.
//! - `Option` is a presence byte (`0x01` / `0x00`) followed, when present, by
//!   the value's encoding.

use sha2::{Digest, Sha256};

use tenzro_types::media_gen::{
    MediaGenHandoff, MediaGenKind, MediaGenParams, MediaGenReceipt, MediaGenTaskSpec,
};
use tenzro_types::primitives::{Address, Hash, Timestamp};

/// Domain tag for job-identity derivation.
const JOB_ID_TAG: &[u8] = b"tenzro/media-gen/job-id";

/// Domain tag for the high-noise expert's intermediate-latent commitment.
const HANDOFF_TAG: &[u8] = b"tenzro/media-gen/handoff";

/// Domain tag for the worker's receipt attestation.
const RECEIPT_TAG: &[u8] = b"tenzro/media-gen/receipt";

/// Derive the deterministic job id for a posted request.
///
/// The id is the lowercase hex SHA-256 over the requester, the model, the
/// kind, the sampling parameters, the price ceiling, and the posting
/// timestamp. The timestamp is what separates two otherwise-identical
/// requests from the same requester — reposting the same prompt yields a new
/// job, but a retried post carrying the original timestamp is recognised as
/// the same job.
pub fn compute_job_id(
    requester_did: &str,
    requester_address: &Address,
    model_id: &str,
    kind: MediaGenKind,
    params: &MediaGenParams,
    max_price: u128,
    created_at: Timestamp,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(JOB_ID_TAG);
    hasher.update(len_prefixed(requester_did.as_bytes()));
    hasher.update(len_prefixed(requester_address.as_bytes()));
    hasher.update(len_prefixed(model_id.as_bytes()));
    hasher.update(len_prefixed(kind.to_string().as_bytes()));
    hasher.update(encode_params(params));
    hasher.update(max_price.to_be_bytes());
    hasher.update(created_at.as_millis().to_be_bytes());
    hex::encode(hasher.finalize())
}

/// Derive the job id a [`MediaGenTaskSpec`] should carry, ignoring whatever
/// `spec.job_id` currently holds. Used at admission to normalise a
/// caller-supplied spec and to reject a spec whose id does not bind its own
/// contents.
pub fn expected_job_id(spec: &MediaGenTaskSpec) -> String {
    compute_job_id(
        &spec.requester_did,
        &spec.requester_address,
        &spec.model_id,
        spec.kind,
        &spec.params,
        spec.max_price,
        spec.created_at,
    )
}

/// Canonical preimage the high-noise expert signs over a [`MediaGenHandoff`].
///
/// Binds every handoff field except the signature itself. `steps_completed` is
/// in here because it is what the payment split is computed from — a worker
/// that overstates its half of the schedule would have to forge the signature
/// to do so.
pub fn handoff_signing_bytes(handoff: &MediaGenHandoff) -> Vec<u8> {
    let mut buf = Vec::with_capacity(192);
    buf.extend_from_slice(HANDOFF_TAG);
    buf.extend_from_slice(&len_prefixed(handoff.job_id.as_bytes()));
    buf.extend_from_slice(&len_prefixed(handoff.from_worker_did.as_bytes()));
    buf.extend_from_slice(&len_prefixed(handoff.from_worker_address.as_bytes()));
    buf.extend_from_slice(handoff.latent_hash.as_bytes());
    buf.extend_from_slice(&handoff.latent_bytes.to_be_bytes());
    buf.extend_from_slice(&handoff.steps_completed.to_be_bytes());
    buf.extend_from_slice(&handoff.handed_off_at.as_millis().to_be_bytes());
    buf
}

/// SHA-256 over [`handoff_signing_bytes`] — the digest a verifier checks the
/// high-noise expert's signature against.
pub fn handoff_commitment(handoff: &MediaGenHandoff) -> Hash {
    let digest = Sha256::digest(handoff_signing_bytes(handoff));
    Hash::from_bytes(&digest).expect("sha256 digest is 32 bytes")
}

/// Canonical preimage the worker signs over a completed [`MediaGenReceipt`].
///
/// Binds every receipt field except the signature itself, with the full task
/// spec folded in so the parameters the worker executed are covered.
pub fn receipt_signing_bytes(receipt: &MediaGenReceipt) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(RECEIPT_TAG);
    buf.extend_from_slice(&len_prefixed(receipt.job_id.as_bytes()));
    buf.extend_from_slice(&encode_task_spec(&receipt.task_spec));
    buf.extend_from_slice(&len_prefixed(receipt.worker_did.as_bytes()));
    buf.extend_from_slice(&len_prefixed(receipt.worker_address.as_bytes()));
    buf.extend_from_slice(receipt.output_hash.as_bytes());
    buf.extend_from_slice(&len_prefixed(receipt.output_mime.as_bytes()));
    buf.extend_from_slice(&receipt.output_bytes.to_be_bytes());
    buf.extend_from_slice(&receipt.seed_used.to_be_bytes());
    buf.extend_from_slice(&receipt.generation_time_ms.to_be_bytes());
    buf.extend_from_slice(&receipt.price_paid.to_be_bytes());
    buf.extend_from_slice(&receipt.completed_at.as_millis().to_be_bytes());
    buf
}

/// SHA-256 over [`receipt_signing_bytes`] — the digest a verifier checks the
/// worker signature against, and the value a settlement record references.
pub fn receipt_commitment(receipt: &MediaGenReceipt) -> Hash {
    let digest = Sha256::digest(receipt_signing_bytes(receipt));
    Hash::from_bytes(&digest).expect("sha256 digest is 32 bytes")
}

fn encode_task_spec(spec: &MediaGenTaskSpec) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&len_prefixed(spec.job_id.as_bytes()));
    buf.extend_from_slice(&len_prefixed(spec.requester_did.as_bytes()));
    buf.extend_from_slice(&len_prefixed(spec.requester_address.as_bytes()));
    buf.extend_from_slice(&len_prefixed(spec.model_id.as_bytes()));
    buf.extend_from_slice(&len_prefixed(spec.kind.to_string().as_bytes()));
    buf.extend_from_slice(&encode_params(&spec.params));
    buf.extend_from_slice(&spec.max_price.to_be_bytes());
    buf.extend_from_slice(&spec.created_at.as_millis().to_be_bytes());
    buf
}

/// Encode the sampling parameters. `metadata` is deliberately excluded: it is
/// opaque pipeline-tuning input with no canonical ordering guarantee across
/// the Rust and Python JSON encoders, and binding it would make the preimage
/// depend on map iteration order.
fn encode_params(params: &MediaGenParams) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&len_prefixed(params.prompt.as_bytes()));
    match &params.negative_prompt {
        Some(np) => {
            buf.push(0x01);
            buf.extend_from_slice(&len_prefixed(np.as_bytes()));
        }
        None => buf.push(0x00),
    }
    buf.extend_from_slice(&params.width.to_be_bytes());
    buf.extend_from_slice(&params.height.to_be_bytes());
    buf.extend_from_slice(&encode_opt_u32(params.num_frames));
    buf.extend_from_slice(&encode_opt_u32(params.fps));
    buf.extend_from_slice(&params.steps.to_be_bytes());
    buf.extend_from_slice(&params.guidance_scale.to_be_bytes());
    match params.seed {
        Some(s) => {
            buf.push(0x01);
            buf.extend_from_slice(&s.to_be_bytes());
        }
        None => buf.push(0x00),
    }
    match &params.input_image_hash {
        Some(h) => {
            buf.push(0x01);
            buf.extend_from_slice(h.as_bytes());
        }
        None => buf.push(0x00),
    }
    buf
}

fn encode_opt_u32(v: Option<u32>) -> Vec<u8> {
    match v {
        Some(n) => {
            let mut buf = Vec::with_capacity(5);
            buf.push(0x01);
            buf.extend_from_slice(&n.to_be_bytes());
            buf
        }
        None => vec![0x00],
    }
}

fn len_prefixed(bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + bytes.len());
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tenzro_types::media_gen::{MediaGenHandoff, MediaGenReceipt};
    use tenzro_types::primitives::Signature;

    fn params() -> MediaGenParams {
        MediaGenParams {
            prompt: "a fox in a plaster diorama".to_string(),
            negative_prompt: Some("blurry".to_string()),
            width: 1024,
            height: 1024,
            num_frames: None,
            fps: None,
            steps: 30,
            guidance_scale: 4.5,
            voxel_resolution: None,
            audio_duration_secs: None,
            seed: Some(42),
            input_image_hash: None,
            metadata: HashMap::new(),
        }
    }

    fn spec() -> MediaGenTaskSpec {
        let p = params();
        let created_at = Timestamp::new(1_700_000_000_000);
        let job_id = compute_job_id(
            "did:tenzro:human:req",
            &Address::zero(),
            "qwen-image",
            MediaGenKind::Text2Image,
            &p,
            1_000_000_000_000_000_000,
            created_at,
        );
        MediaGenTaskSpec {
            job_id,
            requester_did: "did:tenzro:human:req".to_string(),
            requester_address: Address::zero(),
            model_id: "qwen-image".to_string(),
            kind: MediaGenKind::Text2Image,
            params: p,
            max_price: 1_000_000_000_000_000_000,
            created_at,
            metadata: HashMap::new(),
        }
    }

    fn receipt() -> MediaGenReceipt {
        MediaGenReceipt {
            job_id: spec().job_id,
            task_spec: spec(),
            worker_did: "did:tenzro:machine:worker".to_string(),
            worker_address: Address::zero(),
            output_hash: Hash::new([9u8; 32]),
            output_mime: "image/png".to_string(),
            output_bytes: 2048,
            seed_used: 42,
            generation_time_ms: 8_500,
            price_paid: 500_000_000_000_000_000,
            completed_at: Timestamp::new(1_700_000_030_000),
            worker_signature: Signature::default(),
        }
    }

    fn handoff() -> MediaGenHandoff {
        MediaGenHandoff {
            job_id: spec().job_id,
            from_worker_did: "did:tenzro:machine:high".to_string(),
            from_worker_address: Address::new([3u8; 32]),
            latent_hash: Hash::new([5u8; 32]),
            latent_bytes: 8_388_608,
            steps_completed: 26,
            handed_off_at: Timestamp::new(1_700_000_020_000),
            worker_signature: Signature::default(),
        }
    }

    #[test]
    fn job_id_is_deterministic() {
        assert_eq!(expected_job_id(&spec()), expected_job_id(&spec()));
        assert_eq!(expected_job_id(&spec()).len(), 64);
    }

    #[test]
    fn job_id_binds_spec_contents() {
        let base = expected_job_id(&spec());

        let mut other_prompt = spec();
        other_prompt.params.prompt = "a different fox".to_string();
        assert_ne!(expected_job_id(&other_prompt), base);

        let mut other_model = spec();
        other_model.model_id = "flux2-klein".to_string();
        assert_ne!(expected_job_id(&other_model), base);

        let mut other_time = spec();
        other_time.created_at = Timestamp::new(1_700_000_000_001);
        assert_ne!(expected_job_id(&other_time), base);

        let mut other_price = spec();
        other_price.max_price += 1;
        assert_ne!(expected_job_id(&other_price), base);
    }

    #[test]
    fn job_id_ignores_the_carried_id() {
        let mut lying = spec();
        lying.job_id = "not-the-real-id".to_string();
        assert_eq!(expected_job_id(&lying), expected_job_id(&spec()));
    }

    #[test]
    fn job_id_ignores_opaque_metadata() {
        let mut with_meta = spec();
        with_meta
            .params
            .metadata
            .insert("scheduler".to_string(), serde_json::json!("euler"));
        assert_eq!(expected_job_id(&with_meta), expected_job_id(&spec()));
    }

    #[test]
    fn length_prefix_removes_field_boundary_ambiguity() {
        let mut a = spec();
        a.requester_did = "ab".to_string();
        a.model_id = "cd".to_string();
        let mut b = spec();
        b.requester_did = "a".to_string();
        b.model_id = "bcd".to_string();
        assert_ne!(expected_job_id(&a), expected_job_id(&b));
    }

    #[test]
    fn receipt_commitment_binds_output_and_spec() {
        let base = receipt_commitment(&receipt());

        let mut other_output = receipt();
        other_output.output_hash = Hash::new([8u8; 32]);
        assert_ne!(receipt_commitment(&other_output), base);

        let mut other_mime = receipt();
        other_mime.output_mime = "image/webp".to_string();
        assert_ne!(receipt_commitment(&other_mime), base);

        let mut other_spec = receipt();
        other_spec.task_spec.params.steps = 31;
        assert_ne!(receipt_commitment(&other_spec), base);

        let mut other_price = receipt();
        other_price.price_paid += 1;
        assert_ne!(receipt_commitment(&other_price), base);
    }

    #[test]
    fn receipt_commitment_ignores_the_signature() {
        let mut resigned = receipt();
        resigned.worker_signature = Signature::new(vec![7u8; 64], vec![3u8; 32]);
        assert_eq!(
            receipt_commitment(&resigned),
            receipt_commitment(&receipt())
        );
    }

    #[test]
    fn receipt_preimage_carries_the_domain_tag() {
        let bytes = receipt_signing_bytes(&receipt());
        assert!(bytes.starts_with(RECEIPT_TAG));
    }

    #[test]
    fn handoff_commitment_binds_the_latent_and_the_step_count() {
        let base = handoff_commitment(&handoff());

        let mut other_latent = handoff();
        other_latent.latent_hash = Hash::new([6u8; 32]);
        assert_ne!(handoff_commitment(&other_latent), base);

        let mut other_size = handoff();
        other_size.latent_bytes += 1;
        assert_ne!(handoff_commitment(&other_size), base);

        let mut other_steps = handoff();
        other_steps.steps_completed = 27;
        assert_ne!(handoff_commitment(&other_steps), base);

        let mut other_worker = handoff();
        other_worker.from_worker_did = "did:tenzro:machine:low".to_string();
        assert_ne!(handoff_commitment(&other_worker), base);
    }

    #[test]
    fn handoff_commitment_ignores_the_signature() {
        let mut resigned = handoff();
        resigned.worker_signature = Signature::new(vec![7u8; 64], vec![3u8; 32]);
        assert_eq!(
            handoff_commitment(&resigned),
            handoff_commitment(&handoff())
        );
    }

    #[test]
    fn handoff_preimage_carries_the_domain_tag() {
        let bytes = handoff_signing_bytes(&handoff());
        assert!(bytes.starts_with(HANDOFF_TAG));
    }

    #[test]
    fn handoff_and_receipt_digests_do_not_collide() {
        // Distinct domain tags, so the two preimages cannot be confused even
        // when they carry the same job id.
        assert_ne!(
            handoff_commitment(&handoff()).as_bytes(),
            receipt_commitment(&receipt()).as_bytes()
        );
    }
}
