//! Deterministic price quoting for generative-media jobs.
//!
//! A requester needs to know what a job will cost before posting it, and a node
//! needs to reject a receipt that charges more than the posted ceiling. Both
//! read from the same function, so a quote and the settled price are derived
//! identically.
//!
//! The work unit is the **pixel-step**: one denoising step over one pixel of
//! one frame. It is the quantity diffusion inference actually scales with —
//! doubling the resolution or the step count doubles the compute, and a video
//! pays per frame. Prices are in attoTNZO (1 TNZO = 10^18 attoTNZO).

use serde::{Deserialize, Serialize};

use tenzro_types::media_gen::{MediaGenKind, MediaGenParams};

use crate::error::{MediaGenError, Result};

/// attoTNZO charged per pixel-step by default (1 Gwei-equivalent).
pub const DEFAULT_PER_PIXEL_STEP: u128 = 1_000_000_000;

/// attoTNZO charged per job regardless of size, by default 0.001 TNZO. Covers
/// the fixed cost of a job — model load, scheduler setup, output encoding —
/// which does not scale with resolution.
pub const DEFAULT_BASE_FEE: u128 = 1_000_000_000_000_000;

/// Rate card a node applies when quoting generative-media jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaGenPricing {
    /// attoTNZO per pixel-step.
    pub per_pixel_step: u128,
    /// Flat attoTNZO added to every job.
    pub base_fee: u128,
}

impl Default for MediaGenPricing {
    fn default() -> Self {
        Self {
            per_pixel_step: DEFAULT_PER_PIXEL_STEP,
            base_fee: DEFAULT_BASE_FEE,
        }
    }
}

impl MediaGenPricing {
    pub fn new(per_pixel_step: u128, base_fee: u128) -> Self {
        Self {
            per_pixel_step,
            base_fee,
        }
    }

    /// Price in attoTNZO for the given job shape.
    pub fn quote(&self, kind: MediaGenKind, params: &MediaGenParams) -> u128 {
        self.base_fee
            .saturating_add(self.per_pixel_step.saturating_mul(pixel_steps(kind, params)))
    }
}

/// Work units for a job: `width × height × steps × frames`.
///
/// `num_frames` is only counted for video kinds — an image job that carries a
/// stray frame count is still one frame of work, and must not be priced as if
/// it were a clip.
pub fn pixel_steps(kind: MediaGenKind, params: &MediaGenParams) -> u128 {
    let frames = if kind.is_video() {
        u128::from(params.num_frames.unwrap_or(1).max(1))
    } else {
        1
    };
    u128::from(params.width)
        .saturating_mul(u128::from(params.height))
        .saturating_mul(u128::from(params.steps))
        .saturating_mul(frames)
}

/// Reject a charge above the ceiling the requester posted.
pub fn enforce_ceiling(job_id: &str, charged: u128, max: u128) -> Result<()> {
    if charged > max {
        return Err(MediaGenError::PriceCeilingExceeded {
            job_id: job_id.to_string(),
            charged,
            max,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn image_params() -> MediaGenParams {
        MediaGenParams {
            prompt: "a plaster diorama".to_string(),
            negative_prompt: None,
            width: 1024,
            height: 1024,
            num_frames: None,
            fps: None,
            steps: 30,
            guidance_scale: 4.5,
            seed: None,
            input_image_hash: None,
            metadata: HashMap::new(),
        }
    }

    fn video_params() -> MediaGenParams {
        MediaGenParams {
            num_frames: Some(81),
            fps: Some(16),
            width: 832,
            height: 480,
            ..image_params()
        }
    }

    #[test]
    fn pixel_steps_scale_with_resolution_and_steps() {
        let p = image_params();
        assert_eq!(pixel_steps(MediaGenKind::Text2Image, &p), 1024 * 1024 * 30);

        let mut double_steps = p.clone();
        double_steps.steps = 60;
        assert_eq!(
            pixel_steps(MediaGenKind::Text2Image, &double_steps),
            2 * pixel_steps(MediaGenKind::Text2Image, &p)
        );
    }

    #[test]
    fn frames_only_count_for_video_kinds() {
        let v = video_params();
        assert_eq!(
            pixel_steps(MediaGenKind::Text2Video, &v),
            832 * 480 * 30 * 81
        );
        // The same params posted as an image job are one frame of work.
        assert_eq!(pixel_steps(MediaGenKind::Text2Image, &v), 832 * 480 * 30);
    }

    #[test]
    fn quote_includes_the_base_fee() {
        let pricing = MediaGenPricing::default();
        let p = image_params();
        let expected = DEFAULT_BASE_FEE
            + DEFAULT_PER_PIXEL_STEP * pixel_steps(MediaGenKind::Text2Image, &p);
        assert_eq!(pricing.quote(MediaGenKind::Text2Image, &p), expected);
    }

    #[test]
    fn video_quotes_above_the_equivalent_image() {
        let pricing = MediaGenPricing::default();
        assert!(
            pricing.quote(MediaGenKind::Text2Video, &video_params())
                > pricing.quote(MediaGenKind::Text2Image, &image_params())
        );
    }

    #[test]
    fn ceiling_admits_an_exact_match_and_rejects_an_overcharge() {
        assert!(enforce_ceiling("job", 100, 100).is_ok());
        let err = enforce_ceiling("job", 101, 100).unwrap_err();
        assert!(matches!(
            err,
            MediaGenError::PriceCeilingExceeded {
                charged: 101,
                max: 100,
                ..
            }
        ));
    }
}
