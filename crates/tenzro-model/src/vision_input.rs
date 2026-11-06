//! Image and video preprocessing for vision-language rerankers and embedders.
//!
//! Reproduces the checkpoint pipeline's own preprocessing exactly, because a
//! vision tower given differently resized or normalised pixels returns a
//! different embedding without any error:
//!
//! - decoding to RGB (an RGBA picture is composited onto white),
//! - the size rule (each side a multiple of the merged patch size, the area
//!   within the pipeline's pixel budget, the aspect ratio kept),
//! - bicubic resampling with the reference's fixed-point arithmetic for
//!   pictures, and the floating-point antialiased bicubic used for the second
//!   resize of video frames,
//! - frame sampling and the per-slice timestamps of a video.
//!
//! The projector then cuts the pictures into patches and lays out the
//! decoder's positions.

use crate::catalog::VisionPreprocess;
use crate::error::{ModelError, Result};

/// An RGB picture, row-major, three bytes per pixel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RgbImage {
    pub width: usize,
    pub height: usize,
    pub data: Vec<u8>,
}

/// Pictures whose sides differ by more than this ratio are refused, as in the
/// reference pipeline.
const MAX_ASPECT_RATIO: f64 = 200.0;

fn bad_input(msg: impl Into<String>) -> ModelError {
    ModelError::InvalidInput(msg.into())
}

/// Decode PNG, JPEG or WebP bytes to RGB. A picture with an alpha channel is
/// composited onto white; grey-scale is replicated over the three channels.
pub fn decode_rgb(bytes: &[u8]) -> Result<RgbImage> {
    if bytes.starts_with(&[0xFF, 0xD8]) {
        // JPEG: the reference pipeline's decoder, so pixels match exactly
        let img = turbojpeg::decompress(bytes, turbojpeg::PixelFormat::RGB)
            .map_err(|e| bad_input(format!("could not decode the JPEG picture: {e}")))?;
        if img.width == 0 || img.height == 0 {
            return Err(bad_input("the image is empty"));
        }
        let mut data = Vec::with_capacity(img.width * img.height * 3);
        for row in img.pixels.chunks(img.pitch).take(img.height) {
            data.extend_from_slice(&row[..img.width * 3]);
        }
        return Ok(RgbImage {
            width: img.width,
            height: img.height,
            data,
        });
    }
    let img = image::load_from_memory(bytes)
        .map_err(|e| bad_input(format!("could not decode the image: {e}")))?;
    let (width, height) = (img.width() as usize, img.height() as usize);
    if width == 0 || height == 0 {
        return Err(bad_input("the image is empty"));
    }
    let data = match img.color() {
        image::ColorType::Rgba8 | image::ColorType::Rgba16 | image::ColorType::Rgba32F => {
            let rgba = img.to_rgba8();
            let mut out = Vec::with_capacity(width * height * 3);
            for px in rgba.pixels() {
                let a = px.0[3] as u32;
                for c in 0..3 {
                    out.push(div255(255 * (255 - a) + px.0[c] as u32 * a));
                }
            }
            out
        }
        _ => img.to_rgb8().into_raw(),
    };
    Ok(RgbImage {
        width,
        height,
        data,
    })
}

fn div255(a: u32) -> u8 {
    let t = a + 128;
    (((t >> 8) + t) >> 8) as u8
}

fn round_by_factor(x: f64, factor: u64) -> u64 {
    ((x / factor as f64).round_ties_even() as u64) * factor
}

fn ceil_by_factor(x: f64, factor: u64) -> u64 {
    ((x / factor as f64).ceil() as u64) * factor
}

fn floor_by_factor(x: f64, factor: u64) -> u64 {
    ((x / factor as f64).floor() as u64) * factor
}

/// The reference size rule: `(height, width)`, each a multiple of `factor`,
/// with the area in `[min_pixels, max_pixels]` and the aspect ratio kept.
pub fn smart_resize(
    height: usize,
    width: usize,
    factor: u64,
    min_pixels: f64,
    max_pixels: f64,
) -> Result<(usize, usize)> {
    let (h, w) = (height as f64, width as f64);
    if h.max(w) / h.min(w) > MAX_ASPECT_RATIO {
        return Err(bad_input(format!(
            "the aspect ratio of a {width}x{height} picture exceeds {MAX_ASPECT_RATIO}"
        )));
    }
    let mut h_bar = factor.max(round_by_factor(h, factor));
    let mut w_bar = factor.max(round_by_factor(w, factor));
    if (h_bar * w_bar) as f64 > max_pixels {
        let beta = ((h * w) / max_pixels).sqrt();
        h_bar = floor_by_factor(h / beta, factor);
        w_bar = floor_by_factor(w / beta, factor);
    } else if ((h_bar * w_bar) as f64) < min_pixels {
        let beta = (min_pixels / (h * w)).sqrt();
        h_bar = ceil_by_factor(h * beta, factor);
        w_bar = ceil_by_factor(w * beta, factor);
    }
    if h_bar == 0 || w_bar == 0 {
        return Err(bad_input(format!(
            "a {width}x{height} picture is too small to resize"
        )));
    }
    Ok((h_bar as usize, w_bar as usize))
}

fn bicubic(x: f64) -> f64 {
    const A: f64 = -0.5;
    let x = x.abs();
    if x < 1.0 {
        ((A + 2.0) * x - (A + 3.0)) * x * x + 1.0
    } else if x < 2.0 {
        (((x - 5.0) * x + 8.0) * x - 4.0) * A
    } else {
        0.0
    }
}

/// Per output index: first source index and normalised weights.
fn coefficients(in_size: usize, out_size: usize) -> (usize, Vec<(usize, Vec<f64>)>) {
    let scale = in_size as f64 / out_size as f64;
    let filterscale = scale.max(1.0);
    let support = 2.0 * filterscale;
    let ksize = support.ceil() as usize * 2 + 1;
    let mut out = Vec::with_capacity(out_size);
    for xx in 0..out_size {
        let center = (xx as f64 + 0.5) * scale;
        let ss = 1.0 / filterscale;
        let xmin = ((center - support + 0.5) as i64).max(0) as usize;
        let xmax = (((center + support + 0.5) as i64).min(in_size as i64) as usize) - xmin;
        let mut k: Vec<f64> = (0..xmax)
            .map(|x| bicubic((x as f64 + xmin as f64 - center + 0.5) * ss))
            .collect();
        let ww: f64 = k.iter().sum();
        if ww != 0.0 {
            for w in &mut k {
                *w /= ww;
            }
        }
        out.push((xmin, k));
    }
    (ksize, out)
}

const PRECISION_BITS: u32 = 32 - 8 - 2;

fn fixed(k: &[f64]) -> Vec<i32> {
    k.iter()
        .map(|&w| {
            if w < 0.0 {
                (-0.5 + w * (1i64 << PRECISION_BITS) as f64) as i32
            } else {
                (0.5 + w * (1i64 << PRECISION_BITS) as f64) as i32
            }
        })
        .collect()
}

fn clip8(v: i32) -> u8 {
    (v >> PRECISION_BITS).clamp(0, 255) as u8
}

/// Bicubic resize with 8-bit fixed-point arithmetic, horizontal pass first,
/// matching the reference picture library bit for bit.
pub fn resize_bicubic_u8(src: &RgbImage, width: usize, height: usize) -> RgbImage {
    if src.width == width && src.height == height {
        return src.clone();
    }
    let (_, vert) = coefficients(src.height, height);
    let first = vert[0].0;
    let last = vert[height - 1].0 + vert[height - 1].1.len();
    let mut cur = src.clone();
    let mut row_offset = 0usize;
    if src.width != width {
        let (_, horiz) = coefficients(src.width, width);
        let horiz: Vec<(usize, Vec<i32>)> =
            horiz.into_iter().map(|(x0, k)| (x0, fixed(&k))).collect();
        let rows = last - first;
        let mut data = vec![0u8; width * rows * 3];
        for y in 0..rows {
            let src_row = &src.data[(y + first) * src.width * 3..(y + first + 1) * src.width * 3];
            for (xx, (x0, k)) in horiz.iter().enumerate() {
                for c in 0..3 {
                    let mut ss: i32 = 1 << (PRECISION_BITS - 1);
                    for (i, w) in k.iter().enumerate() {
                        ss = ss.wrapping_add(src_row[(x0 + i) * 3 + c] as i32 * w);
                    }
                    data[(y * width + xx) * 3 + c] = clip8(ss);
                }
            }
        }
        cur = RgbImage {
            width,
            height: rows,
            data,
        };
        row_offset = first;
    }
    if src.height != height {
        let mut data = vec![0u8; width * height * 3];
        for (yy, (y0, k)) in vert.iter().enumerate() {
            let k = fixed(k);
            let y0 = y0 - row_offset;
            for x in 0..width {
                for c in 0..3 {
                    let mut ss: i32 = 1 << (PRECISION_BITS - 1);
                    for (i, w) in k.iter().enumerate() {
                        ss = ss.wrapping_add(cur.data[((y0 + i) * width + x) * 3 + c] as i32 * w);
                    }
                    data[(yy * width + x) * 3 + c] = clip8(ss);
                }
            }
        }
        cur = RgbImage {
            width,
            height,
            data,
        };
    }
    cur
}

/// Antialiased bicubic weights in single precision, as the tensor library
/// computes them for its floating-point resize.
fn coefficients_f32(in_size: usize, out_size: usize) -> Vec<(usize, Vec<f32>)> {
    let scale = in_size as f32 / out_size as f32;
    let support = if scale >= 1.0 { 2.0 * scale } else { 2.0f32 };
    let invscale = if scale >= 1.0 {
        (1.0 / scale as f64) as f32
    } else {
        1.0f32
    };
    let filter = |x: f32| -> f32 {
        const A: f32 = -0.5;
        let x = x.abs();
        if x < 1.0 {
            ((A + 2.0) * x - (A + 3.0)) * x * x + 1.0
        } else if x < 2.0 {
            ((A * x - 5.0 * A) * x + 8.0 * A) * x - 4.0 * A
        } else {
            0.0
        }
    };
    (0..out_size)
        .map(|i| {
            // mixed single/double precision exactly as the reference computes it
            let center = (scale as f64 * (i as f64 + 0.5)) as f32;
            let xmin = (((center - support) as f64 + 0.5) as i64).max(0) as usize;
            let xsize =
                (((center + support) as f64 + 0.5) as i64).min(in_size as i64) as usize - xmin;
            let mut w: Vec<f32> = (0..xsize)
                .map(|j| {
                    let d = ((j + xmin) as f32 - center) as f64 + 0.5;
                    filter((d * invscale as f64) as f32)
                })
                .collect();
            let total: f32 = w.iter().fold(0.0, |a, b| a + b);
            if total != 0.0 {
                for v in &mut w {
                    *v /= total;
                }
            }
            (xmin, w)
        })
        .collect()
}

/// Antialiased bicubic resize in single precision (width first, then
/// height), clamped to `[0, 255]` and rounded half to even, as the video
/// path of the reference pipeline resizes frames.
pub fn resize_bicubic_f32(src: &RgbImage, width: usize, height: usize) -> RgbImage {
    if src.width == width && src.height == height {
        return src.clone();
    }
    let mut cur: Vec<f32> = src.data.iter().map(|&v| v as f32).collect();
    let mut cur_w = src.width;
    if src.width != width {
        let k = coefficients_f32(src.width, width);
        let mut out = vec![0f32; width * src.height * 3];
        for y in 0..src.height {
            for (xx, (x0, w)) in k.iter().enumerate() {
                for c in 0..3 {
                    let mut t = cur[(y * cur_w + x0) * 3 + c] * w[0];
                    for (j, wj) in w.iter().enumerate().skip(1) {
                        t += cur[(y * cur_w + x0 + j) * 3 + c] * wj;
                    }
                    out[(y * width + xx) * 3 + c] = t;
                }
            }
        }
        cur = out;
        cur_w = width;
    }
    if src.height != height {
        let k = coefficients_f32(src.height, height);
        let mut out = vec![0f32; width * height * 3];
        for (yy, (y0, w)) in k.iter().enumerate() {
            for x in 0..width {
                for c in 0..3 {
                    let mut t = cur[(y0 * cur_w + x) * 3 + c] * w[0];
                    for (j, wj) in w.iter().enumerate().skip(1) {
                        t += cur[((y0 + j) * cur_w + x) * 3 + c] * wj;
                    }
                    out[(yy * width + x) * 3 + c] = t;
                }
            }
        }
        cur = out;
    }
    RgbImage {
        width,
        height,
        data: cur
            .into_iter()
            .map(|v| v.clamp(0.0, 255.0).round_ties_even() as u8)
            .collect(),
    }
}

/// One picture or video ready for the projector: `frames` share one
/// size, their count is a multiple of the temporal patch size.
#[derive(Debug, Clone)]
pub struct VisualInput {
    pub frames: Vec<RgbImage>,
    /// Per temporal slice, the timestamp text the prompt carries (videos
    /// only).
    pub timestamps: Vec<String>,
    pub is_video: bool,
}

/// The vision markers the checkpoints write around a block of visual tokens.
pub const VISION_START: &str = "<|vision_start|>";
pub const VISION_END: &str = "<|vision_end|>";

/// A picture, resized for the vision tower and repeated over the temporal
/// patch.
pub fn prepare_image(bytes: &[u8], spec: &VisionPreprocess) -> Result<VisualInput> {
    let img = decode_rgb(bytes)?;
    let factor = (spec.patch_size * spec.merge_size) as u64;
    let (h, w) = smart_resize(
        img.height,
        img.width,
        factor,
        spec.image_min_pixels as f64,
        spec.image_max_pixels as f64,
    )?;
    let img = resize_bicubic_u8(&img, w, h);
    Ok(VisualInput {
        frames: vec![img; spec.temporal_patch_size as usize],
        timestamps: Vec::new(),
        is_video: false,
    })
}

/// Indices of `count` evenly spaced frames out of `available`, the first and
/// the last included (frames repeat when fewer are available).
pub fn sample_frame_indices(available: usize, count: usize) -> Vec<usize> {
    if count == 1 {
        return vec![0];
    }
    let step = (available - 1) as f64 / (count - 1) as f64;
    (0..count)
        .map(|i| {
            if i == count - 1 {
                available - 1
            } else {
                (i as f64 * step) as usize
            }
        })
        .collect()
}

/// `x` to one decimal, rounding the exact binary value half to even.
pub fn one_decimal(x: f64) -> String {
    let s = x * 10.0;
    let residual = x.mul_add(10.0, -s);
    let floor = s.floor();
    let r = if s - floor == 0.5 {
        if residual > 0.0 {
            floor + 1.0
        } else if residual < 0.0 || floor % 2.0 == 0.0 {
            floor
        } else {
            floor + 1.0
        }
    } else {
        s.round()
    };
    let r = r as i64;
    format!("{}.{}", r / 10, r % 10)
}

/// A video given as frames: sampled to the pipeline's frame count, each frame
/// rounded, then all resized together for the vision tower.
pub fn prepare_video(frames: &[Vec<u8>], spec: &VisionPreprocess) -> Result<VisualInput> {
    if frames.is_empty() {
        return Err(bad_input("a video needs at least one frame"));
    }
    let count = spec.video_frames as usize;
    let indices = sample_frame_indices(frames.len(), count);
    let mut rounded: Vec<Option<RgbImage>> = vec![None; frames.len()];
    let mut picked = Vec::with_capacity(count);
    for &i in &indices {
        if rounded[i].is_none() {
            let img = decode_rgb(&frames[i])?;
            let (h, w) = smart_resize(
                img.height,
                img.width,
                spec.video_frame_round_factor as u64,
                spec.video_frame_round_min_pixels as f64,
                f64::INFINITY,
            )?;
            rounded[i] = Some(resize_bicubic_u8(&img, w, h));
        }
        picked.push(rounded[i].clone().expect("set above"));
    }
    let tp = spec.temporal_patch_size as usize;
    while picked.len() % tp != 0 {
        let last = picked.last().expect("non-empty").clone();
        picked.push(last);
    }
    let (height, width) = (picked[0].height, picked[0].width);
    if picked
        .iter()
        .any(|f| f.height != height || f.width != width)
    {
        return Err(bad_input("every frame of a video must have the same size"));
    }
    let n = picked.len();
    let min_pixels = spec.video_frame_min_pixels as f64;
    let max_pixels = (spec.video_frame_max_pixels as f64)
        .min(spec.video_total_pixels as f64 / n as f64 * tp as f64)
        .max((min_pixels * 1.05).floor());
    let factor = (spec.patch_size * spec.merge_size) as u64;
    let (h, w) = smart_resize(height, width, factor, min_pixels, max_pixels)?;
    let frames: Vec<RgbImage> = picked.iter().map(|f| resize_bicubic_f32(f, w, h)).collect();
    let fps = spec.video_sample_fps;
    let timestamps = (0..n / tp)
        .map(|s| {
            let first = (s * tp) as f64 / fps;
            let last = (s * tp + tp - 1) as f64 / fps;
            one_decimal((first + last) / 2.0)
        })
        .collect();
    Ok(VisualInput {
        frames,
        timestamps,
        is_video: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_rule_matches_the_reference() {
        // within budget: rounded to the factor, half to even
        assert_eq!(
            smart_resize(480, 640, 32, 4096.0, 1_843_200.0).unwrap(),
            (480, 640)
        );
        assert_eq!(
            smart_resize(120, 160, 64, 16384.0, f64::INFINITY).unwrap(),
            (128, 128)
        );
        // too small: scaled up
        assert_eq!(
            smart_resize(50, 50, 32, 4096.0, 1_843_200.0).unwrap(),
            (64, 64)
        );
        assert_eq!(
            smart_resize(256, 320, 32, 131_072.0, 245_760.0).unwrap(),
            (352, 416)
        );
        // too large: scaled down
        let (h, w) = smart_resize(1600, 2400, 32, 4096.0, 1_843_200.0).unwrap();
        assert!(h * w <= 1_843_200 && h % 32 == 0 && w % 32 == 0);
        assert!(smart_resize(1, 500, 32, 4096.0, 1_843_200.0).is_err());
    }

    #[test]
    fn frames_are_sampled_evenly_with_repeats() {
        assert_eq!(sample_frame_indices(6, 4), vec![0, 1, 3, 5]);
        let idx = sample_frame_indices(6, 64);
        assert_eq!((idx[0], idx[63], idx.len()), (0, 5, 64));
        assert!(idx.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn timestamps_round_half_to_even_on_the_exact_value() {
        assert_eq!(one_decimal(0.25), "0.2");
        assert_eq!(one_decimal(1.25), "1.2");
        assert_eq!(one_decimal(0.75), "0.8");
        assert_eq!(one_decimal(0.35), "0.3");
        assert_eq!(one_decimal(31.25), "31.2");
        assert_eq!(one_decimal(2.0), "2.0");
    }

    #[test]
    fn same_size_resize_is_identity_and_constant_stays_constant() {
        let img = RgbImage {
            width: 5,
            height: 3,
            data: vec![77; 45],
        };
        assert_eq!(resize_bicubic_u8(&img, 5, 3), img);
        let up = resize_bicubic_u8(&img, 11, 7);
        assert!(up.data.iter().all(|v| *v == 77));
        let down = resize_bicubic_f32(&up, 4, 2);
        assert!(down.data.iter().all(|v| *v == 77));
    }

    #[test]
    fn alpha_is_composited_onto_white() {
        // A colour of 10 over white at alpha 0 (white shows) and 255 (the colour).
        let over_white = |alpha: u32| div255(255 * (255 - alpha) + 10 * alpha);
        assert_eq!(over_white(0), 255);
        assert_eq!(over_white(255), 10);
    }
}
