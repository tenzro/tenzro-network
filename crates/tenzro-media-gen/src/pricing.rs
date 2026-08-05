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

use tenzro_types::media_gen::{MediaGenAssignment, MediaGenKind, MediaGenParams};

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
        self.base_fee.saturating_add(
            self.per_pixel_step
                .saturating_mul(pixel_steps(kind, params)),
        )
    }
}

/// Work units for a job: `width × height × steps × frames`.
///
/// `num_frames` is only counted for video kinds — an image job that carries a
/// stray frame count is still one frame of work, and must not be priced as if
/// it were a clip.
pub fn pixel_steps(kind: MediaGenKind, params: &MediaGenParams) -> u128 {
    // A 3D job has no pixels to charge for. `width`/`height` describe the
    // *conditioning image*, so pricing on them would charge for the input and
    // ignore the thing actually produced — two jobs from the same photo at
    // 512³ and 1536³ would cost the same while differing 27× in work.
    if kind.is_3d() {
        return voxel_steps(params);
    }

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

/// Work units for a 3D job, in the same unit as [`pixel_steps`].
///
/// One occupied voxel of one step, so a 3D job and a pixel job are quoted
/// against the same `per_pixel_step` rate and settle through the same path —
/// a second rate would be a second thing to govern and to keep in step.
///
/// Charged on the **grid face** (`r²`) rather than the full cube. Generation
/// cost tracks the sparse occupied surface, not the empty interior; `r³` at
/// 1536 would be 3.6 billion units against a 1024×1024 image's 1.0 million and
/// price a mesh out of existence.
pub fn voxel_steps(params: &MediaGenParams) -> u128 {
    let r = u128::from(params.voxel_resolution.unwrap_or(512).max(1));
    r.saturating_mul(r)
        .saturating_mul(u128::from(params.steps.max(1)))
}

/// Divide a job's worker payout across its assignments by the `share_bps` the
/// runtime fixed at completion.
///
/// Returns one amount per assignment, in the order given. Integer division
/// leaves up to `assignments.len() - 1` attoTNZO unallocated; that dust goes to
/// the last assignment, so the amounts always sum to `total` exactly. On a job
/// served whole that is the single worker taking all of it; on a split job it is
/// the two experts in proportion to the steps each ran, with the low-noise
/// worker — which the runtime already rounds toward — absorbing the remainder.
pub fn split_payout(total: u128, assignments: &[MediaGenAssignment]) -> Vec<u128> {
    if assignments.is_empty() {
        return Vec::new();
    }
    let last = assignments.len() - 1;
    let mut allocated: u128 = 0;
    let mut amounts = Vec::with_capacity(assignments.len());
    for (i, a) in assignments.iter().enumerate() {
        let amount = if i == last {
            total.saturating_sub(allocated)
        } else {
            total.saturating_mul(u128::from(a.share_bps)) / 10_000
        };
        allocated = allocated.saturating_add(amount);
        amounts.push(amount);
    }
    amounts
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

    use tenzro_types::media_gen::MediaGenExpertRole;
    use tenzro_types::primitives::{Address, Timestamp};

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
            voxel_resolution: None,
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
        let expected =
            DEFAULT_BASE_FEE + DEFAULT_PER_PIXEL_STEP * pixel_steps(MediaGenKind::Text2Image, &p);
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

    fn assignment(role: Option<MediaGenExpertRole>, share_bps: u32) -> MediaGenAssignment {
        MediaGenAssignment {
            worker_did: format!(
                "did:tenzro:machine:{}",
                role.map(|r| r.to_string())
                    .unwrap_or_else(|| "whole".into())
            ),
            worker_address: Address::new([share_bps as u8; 32]),
            role,
            claimed_at: Timestamp::now(),
            share_bps,
        }
    }

    #[test]
    fn a_whole_job_pays_its_single_worker_everything() {
        let a = vec![assignment(None, 10_000)];
        assert_eq!(split_payout(1_000_000, &a), vec![1_000_000]);
    }

    #[test]
    fn a_split_job_pays_each_expert_its_share() {
        let a = vec![
            assignment(Some(MediaGenExpertRole::HighNoise), 8_666),
            assignment(Some(MediaGenExpertRole::LowNoise), 1_334),
        ];
        let paid = split_payout(10_000, &a);
        assert_eq!(paid, vec![8_666, 1_334]);
    }

    #[test]
    fn the_dust_of_an_uneven_split_lands_on_the_last_assignment() {
        let a = vec![
            assignment(Some(MediaGenExpertRole::HighNoise), 3_333),
            assignment(Some(MediaGenExpertRole::LowNoise), 6_667),
        ];
        // 7 * 3333 / 10000 truncates to 2; the remainder must not vanish.
        let paid = split_payout(7, &a);
        assert_eq!(paid, vec![2, 5]);
        assert_eq!(paid.iter().sum::<u128>(), 7);
    }

    #[test]
    fn every_split_sums_to_the_total_it_was_given() {
        for high in [0u32, 1, 4_999, 5_000, 8_666, 9_999, 10_000] {
            let a = vec![
                assignment(Some(MediaGenExpertRole::HighNoise), high),
                assignment(Some(MediaGenExpertRole::LowNoise), 10_000 - high),
            ];
            for total in [0u128, 1, 7, 999_999_999_999_999_999] {
                let paid = split_payout(total, &a);
                assert_eq!(
                    paid.iter().sum::<u128>(),
                    total,
                    "high={high} total={total}"
                );
            }
        }
    }

    #[test]
    fn nothing_is_paid_when_there_is_nobody_to_pay() {
        assert!(split_payout(1_000, &[]).is_empty());
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

#[cfg(test)]
mod three_d_pricing_tests {
    use super::*;
    use tenzro_types::{MediaGenKind, MediaGenParams};

    fn params(width: u32, height: u32, steps: u32, voxels: Option<u32>) -> MediaGenParams {
        MediaGenParams {
            prompt: "a bronze teapot".to_string(),
            negative_prompt: None,
            width,
            height,
            num_frames: None,
            fps: None,
            steps,
            guidance_scale: 7.5,
            voxel_resolution: voxels,
            seed: None,
            input_image_hash: None,
            metadata: Default::default(),
        }
    }

    /// A 3D job is priced on the asset it produces, not the photo it was
    /// conditioned on. Two jobs from the same image at different grids must
    /// not cost the same.
    #[test]
    fn a_3d_job_is_priced_on_the_grid_not_the_conditioning_image() {
        let small = pixel_steps(MediaGenKind::Image23d, &params(1024, 1024, 25, Some(512)));
        let large = pixel_steps(MediaGenKind::Image23d, &params(1024, 1024, 25, Some(1536)));
        assert!(
            large > small,
            "a finer grid must cost more: {small} vs {large}"
        );
        assert_eq!(large / small, 9, "cost scales on the grid face, r²");
    }

    /// Changing the conditioning image's size must not move a 3D price.
    #[test]
    fn conditioning_image_size_does_not_move_a_3d_price() {
        let a = pixel_steps(MediaGenKind::Image23d, &params(512, 512, 25, Some(1024)));
        let b = pixel_steps(MediaGenKind::Image23d, &params(2048, 2048, 25, Some(1024)));
        assert_eq!(a, b);
    }

    /// The pixel path must be untouched by the existence of 3D — an image job
    /// prices exactly as it did before.
    #[test]
    fn the_pixel_path_is_unchanged() {
        let p = params(1024, 1024, 30, None);
        assert_eq!(
            pixel_steps(MediaGenKind::Text2Image, &p),
            1024u128 * 1024 * 30
        );
        let mut v = params(1280, 720, 40, None);
        v.num_frames = Some(81);
        assert_eq!(
            pixel_steps(MediaGenKind::Text2Video, &v),
            1280u128 * 720 * 40 * 81
        );
    }

    /// A 3D job with no grid stated still prices, on a documented default,
    /// rather than collapsing to zero and being served for free.
    #[test]
    fn a_3d_job_without_a_grid_is_not_free() {
        let n = pixel_steps(MediaGenKind::Image23d, &params(1024, 1024, 25, None));
        assert_eq!(n, 512u128 * 512 * 25);
    }
}
