//! Tenzro Media Gen — protocol-only Rust crate for generative-media inference
//! (images and video) on the network.
//!
//! # Architecture
//!
//! This crate is **protocol only**. It owns:
//! - The job queue, worker registry, and status machine ([`runtime`]).
//! - Deterministic price quoting and ceiling enforcement ([`pricing`]).
//! - Canonical signing preimages for job ids, handoffs, and receipts
//!   ([`commitments`]).
//! - The content-addressed store trait for rendered output ([`output_store`]).
//! - The gossip wire format for job coordination ([`gossip`]).
//!
//! It deliberately does **not** depend on a tensor library or a diffusion
//! runtime. The denoising loop is dispatched to the Python reference worker at
//! `integrations/media_gen/`, which wraps HuggingFace `diffusers`. The same
//! split as Tenzro Train: the protocol layer decides who does the work, what it
//! costs, and what was actually produced; the Python layer does the arithmetic.
//!
//! # Scope
//!
//! Jobs are scoped by output modality and shape, not by model architecture —
//! [`MediaGenKind`] covers text-to-image, image-to-image, text-to-video, and
//! image-to-video. A diffusion model that emits *text* is served by the chat
//! path instead; nothing about it is generative-media shaped.
//!
//! A job is inference-shaped, not training-shaped: one requester posts it,
//! enrolled workers claim it, and the last one to run returns a signed
//! [`MediaGenReceipt`] committing to the output's SHA-256 hash. There is no
//! multi-party aggregation and no round structure.
//!
//! # Jobs that split across two experts
//!
//! Some video models pair two transformers of identical shape and switch
//! between them partway through the denoising schedule — one trained on the
//! high-noise steps, one on the low-noise steps. Only one is resident per step,
//! so the pair can sit on two machines instead of one, halving the VRAM a
//! worker needs to participate.
//!
//! [`MediaGenRuntime::post_split_job`] posts such a job. Each half is claimed
//! separately ([`MediaGenExpertRole`]); the job only starts once both are
//! taken. The high-noise holder runs its steps and publishes a
//! [`MediaGenHandoff`] committing to the intermediate latent, the low-noise
//! holder picks that latent up and finishes, and the price is split between
//! them in proportion to the steps each actually ran.
//!
//! # Hashes
//!
//! [`MediaGenReceipt::output_hash`] is the canonical Tenzro content hash —
//! SHA-256 over the rendered bytes. A transport that indexes by some other
//! digest (iroh-blobs uses BLAKE3) owns the mapping inside its
//! [`MediaGenOutputStore`] adapter and re-verifies SHA-256 at the protocol
//! boundary; see the integrity contract on that trait.

pub mod commitments;
pub mod error;
pub mod gossip;
pub mod output_store;
pub mod pricing;
pub mod runtime;

pub use commitments::{
    compute_job_id, expected_job_id, handoff_commitment, handoff_signing_bytes, receipt_commitment,
    receipt_signing_bytes,
};
pub use error::{MediaGenError, Result};
pub use gossip::{
    MEDIA_GEN_TOPIC, MediaGenClaim, MediaGenGossipMessage, decode_for_topic,
    encode_handoff_published, encode_job_claimed, encode_job_posted, encode_receipt_submitted,
    encode_worker_enrolled,
};
pub use output_store::{
    InMemoryOutputStore, MediaGenOutputStore, compute_output_hash, verify_input, verify_latent,
    verify_output,
};
pub use pricing::{
    DEFAULT_BASE_FEE, DEFAULT_PER_PIXEL_STEP, MediaGenPricing, enforce_ceiling, pixel_steps,
    split_payout,
};
pub use runtime::{HydratedCounts, MediaGenRuntime};

// Re-export the protocol-level types from `tenzro-types` for convenience —
// downstream crates can `use tenzro_media_gen::MediaGenTaskSpec` instead of
// `use tenzro_types::media_gen::MediaGenTaskSpec`.
pub use tenzro_types::media_gen::{
    MAX_MEDIA_GEN_DIMENSION, MAX_MEDIA_GEN_FRAMES, MAX_MEDIA_GEN_PROMPT_BYTES, MAX_MEDIA_GEN_STEPS,
    MediaGenAssignment, MediaGenExpertHolding, MediaGenExpertRole, MediaGenHandoff, MediaGenJob,
    MediaGenKind, MediaGenParams, MediaGenReceipt, MediaGenStatus, MediaGenTaskSpec,
    MediaGenWorkerCapability,
};
