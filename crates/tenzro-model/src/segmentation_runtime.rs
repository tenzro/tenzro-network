//! Segmentation runtime backed by ONNX Runtime.
//!
//! Supports two SAM dialects that share the same point/box prompt API:
//!
//! - **SAM 1 family** (EdgeSAM, MobileSAM): 6-input decoder, longest-side
//!   resize-to-1024 with zero-padding, SAM normalization (mean
//!   `[123.675, 116.28, 103.53]`, std `[58.395, 57.12, 57.375]` over raw
//!   0–255 pixel values), decoder consumes `image_embeddings` +
//!   `point_coords` + `point_labels` + `mask_input` + `has_mask_input` +
//!   `orig_im_size`. The decoder graph rescales output masks to the
//!   original image size internally.
//!
//! - **SAM 2 family** (Hiera base+, Hiera large): 7-input decoder, plain
//!   bilinear resize to `(input_size, input_size)` (no padding), ImageNet
//!   normalization on `[0, 1]` pixels. Encoder produces three outputs:
//!   `high_res_feats_0` `[1, 32, 256, 256]`, `high_res_feats_1`
//!   `[1, 64, 128, 128]`, and `image_embed` `[1, 256, 64, 64]`. The
//!   decoder consumes all three plus the same prompt tensors as SAM 1,
//!   but **without** `orig_im_size` — output masks come back at
//!   `[1, 3, H/4, W/4]` resolution and the runtime rescales them to the
//!   original image.
//!
//! In both families, prompt labels follow SAM convention:
//!   - `1.0` = foreground point
//!   - `0.0` = background point
//!   - `2.0` = top-left box corner
//!   - `3.0` = bottom-right box corner
//!   - `-1.0` = padding (used when no prompt is supplied for a slot)
//!
//! Point coordinates are passed in the encoder's resized pixel space, *not*
//! normalized `[0, 1]`. The runtime converts user-supplied prompts (in
//! original image pixels) into encoder space before invoking the decoder.
//!
//! The decoder returns 3 mask candidates per request along with an IoU
//! prediction per mask; this runtime returns the argmax-IoU mask resampled
//! to the original image size as a `[H * W]` u8 buffer.
//!
//! SAM 3 / SAM 3.1 are text-promptable and use a different decoder
//! topology (image encoder + language encoder + detection-shaped box
//! decoder). They live in [`crate::text_segmentation_runtime`] with
//! their own [`TextPromptableSegmenter`](crate::text_segmentation_runtime::TextPromptableSegmenter)
//! trait — same crate, separate type, different I/O contract.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// A point prompt for segmentation. Points anchor the mask to a target
/// pixel; the `is_foreground` flag distinguishes "this is the object"
/// (true) from "this is background" (false).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointPrompt {
    pub x: f32,
    pub y: f32,
    pub is_foreground: bool,
}

/// A bounding-box prompt for segmentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxPrompt {
    pub x0: f32,
    pub y0: f32,
    pub x1: f32,
    pub y1: f32,
}

/// A unified segmentation prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SegmentPrompt {
    Point(PointPrompt),
    Box(BoxPrompt),
    Points(Vec<PointPrompt>),
}

/// A single output mask from a segmentation call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentMask {
    /// Width of the mask in pixels.
    pub width: u32,
    /// Height of the mask in pixels.
    pub height: u32,
    /// Flat `[H * W]` u8 buffer (0 = background, 1 = foreground).
    pub mask: Vec<u8>,
    /// Predicted IoU / confidence score for this mask, in `[0, 1]`.
    pub score: f32,
}

/// Result of a segmentation call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentResult {
    pub masks: Vec<SegmentMask>,
    pub generation_time_ms: u64,
}

/// Trait for segmentation models.
pub trait Segmenter: Send + Sync {
    fn segment(&self, image_bytes: &[u8], prompts: &[SegmentPrompt]) -> Result<SegmentResult>;
    fn input_size(&self) -> u32;
}

/// Which SAM ONNX dialect the loaded encoder/decoder pair implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamFamily {
    /// SAM 1 family — EdgeSAM, MobileSAM. 6-input decoder with
    /// `orig_im_size`. Longest-side resize-to-1024 + zero pad.
    /// Normalization: `(pixel - mean) / std` where pixel is 0–255 and mean
    /// = `[123.675, 116.28, 103.53]`, std = `[58.395, 57.12, 57.375]`.
    Sam1,
    /// SAM 2 family — Hiera base+, Hiera large. 7-input decoder with two
    /// extra `high_res_feats_*` tensors and no `orig_im_size`. Plain
    /// bilinear resize to `(input_size, input_size)`. Normalization:
    /// ImageNet mean/std on `[0, 1]` pixels.
    Sam2,
}

/// Stub segmenter for builds without the `onnx` feature.
#[derive(Debug)]
pub struct StubSegmenter;

impl StubSegmenter {
    pub fn from_onnx(_encoder: impl AsRef<Path>, _decoder: impl AsRef<Path>) -> Result<Self> {
        Err(ModelError::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
}

impl Segmenter for StubSegmenter {
    fn segment(&self, _image_bytes: &[u8], _prompts: &[SegmentPrompt]) -> Result<SegmentResult> {
        Err(ModelError::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
    fn input_size(&self) -> u32 {
        0
    }
}

mod onnx_backend {
    use super::*;
    use image::imageops::FilterType;
    use ndarray::{Array2, Array3, Array4};
    use ort::session::{Session, SessionInputValue};
    use ort::value::Tensor;
    use std::time::Instant;

    /// SAM-1 pixel-space normalization. Raw 0–255 input.
    const SAM1_MEAN: [f32; 3] = [123.675, 116.28, 103.53];
    const SAM1_STD: [f32; 3] = [58.395, 57.12, 57.375];

    /// ImageNet normalization on `[0, 1]` input — used by SAM 2.
    const IMAGENET_MEAN: [f32; 3] = [0.485, 0.456, 0.406];
    const IMAGENET_STD: [f32; 3] = [0.229, 0.224, 0.225];

    /// Generic ONNX segmenter spanning SAM 1 (EdgeSAM, MobileSAM) and SAM 2
    /// (Hiera base+, large).
    ///
    /// Encoder and decoder sessions are stored in two `parking_lot::Mutex`
    /// guards. They are taken sequentially per request; in steady-state
    /// usage there is only ever one outstanding `segment` call per loaded
    /// model (the `DashMap` clones an `Arc<dyn Segmenter>` per dispatch),
    /// so there is no contention.
    pub struct GenericSamSegmenter {
        encoder: parking_lot::Mutex<Session>,
        decoder: parking_lot::Mutex<Session>,
        family: SamFamily,
        input_size: u32,
        encoder_input_name: String,
    }

    impl GenericSamSegmenter {
        pub fn from_onnx(
            encoder_path: impl AsRef<Path>,
            decoder_path: impl AsRef<Path>,
            family: SamFamily,
            input_size: u32,
        ) -> Result<Self> {
            let encoder =
                crate::onnx_session::build_onnx_session(encoder_path.as_ref(), "encoder")?;

            let decoder =
                crate::onnx_session::build_onnx_session(decoder_path.as_ref(), "decoder")?;

            let encoder_input_name = encoder
                .inputs
                .first()
                .map(|i| i.name.clone())
                .ok_or_else(|| ModelError::InvalidModel("encoder has no inputs".to_string()))?;

            Ok(Self {
                encoder: parking_lot::Mutex::new(encoder),
                decoder: parking_lot::Mutex::new(decoder),
                family,
                input_size,
                encoder_input_name,
            })
        }

        /// Decode + preprocess the source image. Returns `(arr, scale_x, scale_y,
        /// pad_w, pad_h, orig_w, orig_h)` where `scale_x`/`scale_y` map original
        /// pixels into the encoder's pixel grid (used to remap prompts), and
        /// `pad_w`/`pad_h` are 0 for SAM 2 (no padding) and non-zero for SAM 1
        /// (longest-side fit + zero pad to square).
        fn preprocess(&self, image_bytes: &[u8]) -> Result<PreprocessOutput> {
            let img = image::load_from_memory(image_bytes)
                .map_err(|e| ModelError::InvalidModel(format!("image decode: {}", e)))?
                .to_rgb8();
            let orig_w = img.width();
            let orig_h = img.height();

            let target = self.input_size;
            let target_usize = target as usize;
            let mut arr = Array4::<f32>::zeros((1, 3, target_usize, target_usize));

            match self.family {
                SamFamily::Sam1 => {
                    // Longest-side resize to `target`, zero-pad to (target, target).
                    let scale = (target as f32) / (orig_w.max(orig_h) as f32);
                    let new_w = ((orig_w as f32) * scale).round() as u32;
                    let new_h = ((orig_h as f32) * scale).round() as u32;
                    let resized = image::imageops::resize(
                        &img,
                        new_w.max(1),
                        new_h.max(1),
                        FilterType::Lanczos3,
                    );

                    for y in 0..new_h as usize {
                        for x in 0..new_w as usize {
                            let px = resized.get_pixel(x as u32, y as u32);
                            for c in 0..3 {
                                let v = (px[c] as f32 - SAM1_MEAN[c]) / SAM1_STD[c];
                                arr[[0, c, y, x]] = v;
                            }
                        }
                    }

                    Ok(PreprocessOutput {
                        tensor: arr,
                        orig_w,
                        orig_h,
                        // Same scale on both axes for SAM 1.
                        scale_x: scale,
                        scale_y: scale,
                    })
                }
                SamFamily::Sam2 => {
                    // Plain bilinear resize to (target, target). No padding.
                    let resized =
                        image::imageops::resize(&img, target, target, FilterType::Triangle);
                    for y in 0..target_usize {
                        for x in 0..target_usize {
                            let px = resized.get_pixel(x as u32, y as u32);
                            for c in 0..3 {
                                let scaled = px[c] as f32 / 255.0;
                                let v = (scaled - IMAGENET_MEAN[c]) / IMAGENET_STD[c];
                                arr[[0, c, y, x]] = v;
                            }
                        }
                    }

                    Ok(PreprocessOutput {
                        tensor: arr,
                        orig_w,
                        orig_h,
                        scale_x: (target as f32) / (orig_w as f32),
                        scale_y: (target as f32) / (orig_h as f32),
                    })
                }
            }
        }

        fn collect_prompt_tensors(
            &self,
            prompts: &[SegmentPrompt],
            scale_x: f32,
            scale_y: f32,
        ) -> Result<(Array3<f32>, Array2<f32>)> {
            // Flatten user prompts into (coords, labels) pairs in encoder
            // pixel space. SAM expects shape `[1, N, 2]` for coords and
            // `[1, N]` for labels.
            let mut pts: Vec<[f32; 2]> = Vec::new();
            let mut labels: Vec<f32> = Vec::new();

            for p in prompts {
                match p {
                    SegmentPrompt::Point(pt) => {
                        pts.push([pt.x * scale_x, pt.y * scale_y]);
                        labels.push(if pt.is_foreground { 1.0 } else { 0.0 });
                    }
                    SegmentPrompt::Points(list) => {
                        for pt in list {
                            pts.push([pt.x * scale_x, pt.y * scale_y]);
                            labels.push(if pt.is_foreground { 1.0 } else { 0.0 });
                        }
                    }
                    SegmentPrompt::Box(b) => {
                        pts.push([b.x0 * scale_x, b.y0 * scale_y]);
                        labels.push(2.0);
                        pts.push([b.x1 * scale_x, b.y1 * scale_y]);
                        labels.push(3.0);
                    }
                }
            }

            if pts.is_empty() {
                return Err(ModelError::InvalidModel(
                    "segmentation requires at least one prompt".to_string(),
                ));
            }

            // SAM convention: when prompts contain only points (no box),
            // append a single padding point `(0, 0)` with label -1 so the
            // decoder treats the prompt as point-only. We skip this when
            // a box is present.
            let has_box = prompts.iter().any(|p| matches!(p, SegmentPrompt::Box(_)));
            if !has_box {
                pts.push([0.0, 0.0]);
                labels.push(-1.0);
            }

            let n = pts.len();
            let mut coords = Array3::<f32>::zeros((1, n, 2));
            for (i, p) in pts.iter().enumerate() {
                coords[[0, i, 0]] = p[0];
                coords[[0, i, 1]] = p[1];
            }
            let mut labels_arr = Array2::<f32>::zeros((1, n));
            for (i, l) in labels.iter().enumerate() {
                labels_arr[[0, i]] = *l;
            }
            Ok((coords, labels_arr))
        }
    }

    struct PreprocessOutput {
        tensor: Array4<f32>,
        orig_w: u32,
        orig_h: u32,
        scale_x: f32,
        scale_y: f32,
    }

    /// Convert mask logits to a `[height * width]` u8 buffer of `0`/`1`
    /// after threshold-at-zero (SAM convention).
    fn logits_to_binary_mask(
        logits: &[f32],
        src_h: usize,
        src_w: usize,
        dst_h: usize,
        dst_w: usize,
    ) -> Vec<u8> {
        // Nearest-neighbor upsample from (src_h, src_w) to (dst_h, dst_w),
        // then threshold at 0. SAM's output mask is signed-distance-like
        // logits; positive values are foreground.
        let mut out = vec![0u8; dst_h * dst_w];
        if src_h == 0 || src_w == 0 {
            return out;
        }
        for y in 0..dst_h {
            let sy = (y * src_h) / dst_h;
            for x in 0..dst_w {
                let sx = (x * src_w) / dst_w;
                let v = logits[sy * src_w + sx];
                if v > 0.0 {
                    out[y * dst_w + x] = 1;
                }
            }
        }
        out
    }

    /// Pick the mask with the highest predicted IoU.
    fn argmax(values: &[f32]) -> usize {
        let mut best_i = 0;
        let mut best_v = f32::NEG_INFINITY;
        for (i, v) in values.iter().enumerate() {
            if *v > best_v {
                best_v = *v;
                best_i = i;
            }
        }
        best_i
    }

    impl Segmenter for GenericSamSegmenter {
        fn segment(
            &self,
            image_bytes: &[u8],
            prompts: &[SegmentPrompt],
        ) -> Result<SegmentResult> {
            if image_bytes.is_empty() {
                return Err(ModelError::InvalidModel("image bytes are empty".to_string()));
            }

            let start = Instant::now();
            let prep = self.preprocess(image_bytes)?;
            let (coords, labels) = self.collect_prompt_tensors(prompts, prep.scale_x, prep.scale_y)?;

            // ── Encoder pass ────────────────────────────────────────
            let image_tensor = Tensor::from_array(prep.tensor)
                .map_err(|e| ModelError::InferenceError(format!("ORT image tensor: {}", e)))?;

            // Collect encoder outputs into owned buffers so we can release
            // the encoder lock before taking the decoder lock.
            let enc_outputs: Vec<(String, Vec<i64>, Vec<f32>)> = {
                let mut session = self.encoder.lock();
                // Snapshot output names before run() takes a mutable borrow on
                // session — session.outputs is borrowed immutably, and the
                // SessionOutputs returned by run() holds the &mut for the rest
                // of this scope.
                let output_names: Vec<String> = session
                    .outputs
                    .iter()
                    .map(|o| o.name.clone())
                    .collect();
                let outputs = session
                    .run(ort::inputs![self.encoder_input_name.as_str() => image_tensor])
                    .map_err(|e| ModelError::InferenceError(format!("encoder run: {}", e)))?;

                let mut collected = Vec::with_capacity(output_names.len());
                for name in output_names {
                    let v = outputs.get(name.as_str()).ok_or_else(|| {
                        ModelError::InferenceError(format!(
                            "encoder missing output '{}'",
                            name
                        ))
                    })?;
                    let (shape, data) = v.try_extract_tensor::<f32>().map_err(|e| {
                        ModelError::InferenceError(format!(
                            "encoder extract '{}': {}",
                            name, e
                        ))
                    })?;
                    collected.push((name, shape.iter().copied().collect(), data.to_vec()));
                }
                collected
            };

            // ── Decoder feed assembly ──────────────────────────────
            let coords_tensor = Tensor::from_array(coords)
                .map_err(|e| ModelError::InferenceError(format!("coords tensor: {}", e)))?;
            let labels_tensor = Tensor::from_array(labels)
                .map_err(|e| ModelError::InferenceError(format!("labels tensor: {}", e)))?;

            // SAM mask_input is always `[1, 1, H/4, W/4]` (256x256 for the
            // 1024-input variants). `has_mask_input = 0` tells the decoder
            // to ignore mask_input contents, so we pass a zero tensor.
            let mask_input = Array4::<f32>::zeros((1, 1, 256, 256));
            let mask_input_tensor = Tensor::from_array(mask_input)
                .map_err(|e| ModelError::InferenceError(format!("mask_input tensor: {}", e)))?;
            let has_mask = ndarray::Array1::<f32>::zeros(1);
            let has_mask_tensor = Tensor::from_array(has_mask)
                .map_err(|e| ModelError::InferenceError(format!("has_mask tensor: {}", e)))?;

            // Build the feed depending on family. We assemble
            // `Vec<(String, SessionInputValue<'_>)>` so we can mix tensor
            // types and variable input counts.
            let mut feed: Vec<(String, SessionInputValue<'_>)> = Vec::new();

            match self.family {
                SamFamily::Sam1 => {
                    // SAM 1 decoder inputs (canonical names per samexporter
                    // and chongzhou/EdgeSAM exports):
                    //   image_embeddings, point_coords, point_labels,
                    //   mask_input, has_mask_input, orig_im_size
                    let (_name, _shape, embed) = enc_outputs
                        .into_iter()
                        .next()
                        .ok_or_else(|| {
                            ModelError::InferenceError("SAM 1 encoder produced no outputs".into())
                        })?;
                    // image_embeddings is [1, 256, 64, 64]
                    let embed_arr = ndarray::Array4::<f32>::from_shape_vec(
                        (1, 256, 64, 64),
                        embed,
                    )
                    .map_err(|e| {
                        ModelError::InferenceError(format!("SAM 1 embed reshape: {}", e))
                    })?;
                    let embed_tensor = Tensor::from_array(embed_arr).map_err(|e| {
                        ModelError::InferenceError(format!("SAM 1 embed tensor: {}", e))
                    })?;

                    let orig_im = ndarray::Array1::<f32>::from_vec(vec![
                        prep.orig_h as f32,
                        prep.orig_w as f32,
                    ]);
                    let orig_im_tensor = Tensor::from_array(orig_im).map_err(|e| {
                        ModelError::InferenceError(format!("orig_im_size tensor: {}", e))
                    })?;

                    feed.push(("image_embeddings".into(), embed_tensor.into()));
                    feed.push(("point_coords".into(), coords_tensor.into()));
                    feed.push(("point_labels".into(), labels_tensor.into()));
                    feed.push(("mask_input".into(), mask_input_tensor.into()));
                    feed.push(("has_mask_input".into(), has_mask_tensor.into()));
                    feed.push(("orig_im_size".into(), orig_im_tensor.into()));
                }
                SamFamily::Sam2 => {
                    // SAM 2 decoder inputs (positional order — samexporter
                    // sam2_onnx.py):
                    //   image_embed, high_res_feats_0, high_res_feats_1,
                    //   point_coords, point_labels, mask_input, has_mask_input
                    //
                    // The encoder emits the three feature tensors in a
                    // deterministic order; we sort by output name to map
                    // each name to its decoder input regardless of how the
                    // ORT runtime orders them.
                    let mut high_res_0: Option<Vec<f32>> = None;
                    let mut high_res_1: Option<Vec<f32>> = None;
                    let mut embed: Option<Vec<f32>> = None;

                    for (name, _shape, data) in enc_outputs {
                        match name.as_str() {
                            "high_res_feats_0" => high_res_0 = Some(data),
                            "high_res_feats_1" => high_res_1 = Some(data),
                            "image_embed" => embed = Some(data),
                            _ => {}
                        }
                    }

                    let high_res_0 = high_res_0.ok_or_else(|| {
                        ModelError::InferenceError(
                            "SAM 2 encoder missing 'high_res_feats_0'".into(),
                        )
                    })?;
                    let high_res_1 = high_res_1.ok_or_else(|| {
                        ModelError::InferenceError(
                            "SAM 2 encoder missing 'high_res_feats_1'".into(),
                        )
                    })?;
                    let embed = embed.ok_or_else(|| {
                        ModelError::InferenceError("SAM 2 encoder missing 'image_embed'".into())
                    })?;

                    let hr0_arr = ndarray::Array4::<f32>::from_shape_vec(
                        (1, 32, 256, 256),
                        high_res_0,
                    )
                    .map_err(|e| {
                        ModelError::InferenceError(format!("high_res_0 reshape: {}", e))
                    })?;
                    let hr1_arr = ndarray::Array4::<f32>::from_shape_vec(
                        (1, 64, 128, 128),
                        high_res_1,
                    )
                    .map_err(|e| {
                        ModelError::InferenceError(format!("high_res_1 reshape: {}", e))
                    })?;
                    let embed_arr = ndarray::Array4::<f32>::from_shape_vec(
                        (1, 256, 64, 64),
                        embed,
                    )
                    .map_err(|e| ModelError::InferenceError(format!("embed reshape: {}", e)))?;

                    let hr0_tensor = Tensor::from_array(hr0_arr).map_err(|e| {
                        ModelError::InferenceError(format!("hr0 tensor: {}", e))
                    })?;
                    let hr1_tensor = Tensor::from_array(hr1_arr).map_err(|e| {
                        ModelError::InferenceError(format!("hr1 tensor: {}", e))
                    })?;
                    let embed_tensor = Tensor::from_array(embed_arr).map_err(|e| {
                        ModelError::InferenceError(format!("embed tensor: {}", e))
                    })?;

                    feed.push(("image_embed".into(), embed_tensor.into()));
                    feed.push(("high_res_feats_0".into(), hr0_tensor.into()));
                    feed.push(("high_res_feats_1".into(), hr1_tensor.into()));
                    feed.push(("point_coords".into(), coords_tensor.into()));
                    feed.push(("point_labels".into(), labels_tensor.into()));
                    feed.push(("mask_input".into(), mask_input_tensor.into()));
                    feed.push(("has_mask_input".into(), has_mask_tensor.into()));
                }
            }

            // ── Decoder pass ────────────────────────────────────────
            let (masks_shape, masks_data, iou_data) = {
                let mut session = self.decoder.lock();
                let outputs = session
                    .run(feed)
                    .map_err(|e| ModelError::InferenceError(format!("decoder run: {}", e)))?;

                let masks_v = outputs.get("masks").ok_or_else(|| {
                    ModelError::InferenceError("decoder missing 'masks' output".into())
                })?;
                let (ms, md) = masks_v
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("masks extract: {}", e)))?;
                let masks_shape: Vec<i64> = ms.iter().copied().collect();
                let masks_data: Vec<f32> = md.to_vec();

                // The IoU output is called `iou_predictions` in both
                // dialects.
                let iou_v = outputs.get("iou_predictions").ok_or_else(|| {
                    ModelError::InferenceError(
                        "decoder missing 'iou_predictions' output".into(),
                    )
                })?;
                let (_is, id) = iou_v
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("iou extract: {}", e)))?;
                let iou_data: Vec<f32> = id.to_vec();

                (masks_shape, masks_data, iou_data)
            };

            // ── Postprocess: pick best mask + upsample to original size ─
            let (m_h, m_w, n_masks) = match masks_shape.as_slice() {
                // SAM 2: [1, N, H, W] in low-res; SAM 1 decoder rescales
                // to orig size and may emit [1, N, orig_h, orig_w].
                [1, n, h, w] => (*h as usize, *w as usize, *n as usize),
                other => {
                    return Err(ModelError::InferenceError(format!(
                        "decoder unexpected masks shape {:?}, expected [1, N, H, W]",
                        other
                    )));
                }
            };
            if iou_data.len() < n_masks {
                return Err(ModelError::InferenceError(format!(
                    "iou_predictions length {} < n_masks {}",
                    iou_data.len(),
                    n_masks
                )));
            }

            let best = argmax(&iou_data[..n_masks]);
            let mask_offset = best * m_h * m_w;
            let mask_slice = &masks_data[mask_offset..mask_offset + m_h * m_w];

            let dst_h = prep.orig_h as usize;
            let dst_w = prep.orig_w as usize;
            let binary = logits_to_binary_mask(mask_slice, m_h, m_w, dst_h, dst_w);
            // SAM IoU predictions are already in [0, 1].
            let score = iou_data[best].clamp(0.0, 1.0);

            Ok(SegmentResult {
                masks: vec![SegmentMask {
                    width: prep.orig_w,
                    height: prep.orig_h,
                    mask: binary,
                    score,
                }],
                generation_time_ms: start.elapsed().as_millis() as u64,
            })
        }

        fn input_size(&self) -> u32 {
            self.input_size
        }
    }
}

pub use onnx_backend::GenericSamSegmenter;

/// Runtime that owns multiple loaded segmentation models.
pub struct SegmentationRuntime {
    models: dashmap::DashMap<String, Arc<dyn Segmenter>>,
}

impl Default for SegmentationRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl SegmentationRuntime {
    pub fn new() -> Self {
        Self {
            models: dashmap::DashMap::new(),
        }
    }

    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn Segmenter>) {
        self.models.insert(model_id.into(), model);
    }

    /// Load an encoder/decoder pair from disk and register them under
    /// `model_id`. The caller picks the correct `SamFamily` based on the
    /// catalog entry's `family` field (`sam2` → `Sam2`, otherwise `Sam1`).
    pub fn load_onnx(
        &self,
        model_id: impl Into<String>,
        encoder_path: impl AsRef<Path>,
        decoder_path: impl AsRef<Path>,
        family: SamFamily,
        input_size: u32,
    ) -> Result<()> {
        let model =
            GenericSamSegmenter::from_onnx(encoder_path, decoder_path, family, input_size)?;
        self.models
            .insert(model_id.into(), Arc::new(model) as Arc<dyn Segmenter>);
        Ok(())
    }

    pub fn unregister(&self, model_id: &str) -> bool {
        self.models.remove(model_id).is_some()
    }

    pub fn is_loaded(&self, model_id: &str) -> bool {
        self.models.contains_key(model_id)
    }

    pub fn loaded_models(&self) -> Vec<String> {
        self.models.iter().map(|kv| kv.key().clone()).collect()
    }

    pub async fn segment(
        &self,
        model_id: &str,
        image_bytes: Vec<u8>,
        prompts: Vec<SegmentPrompt>,
    ) -> Result<SegmentResult> {
        let model = self
            .models
            .get(model_id)
            .map(|kv| kv.value().clone())
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))?;
        tokio::task::spawn_blocking(move || model.segment(&image_bytes, &prompts))
            .await
            .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {}", e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock segmenter that returns a fixed 10x10 mask. Exercises runtime
    /// dispatch and dashmap bookkeeping without loading an ONNX file.
    struct ConstantSegmenter {
        input_size: u32,
    }
    impl Segmenter for ConstantSegmenter {
        fn segment(
            &self,
            _image_bytes: &[u8],
            _prompts: &[SegmentPrompt],
        ) -> Result<SegmentResult> {
            Ok(SegmentResult {
                masks: vec![SegmentMask {
                    width: 10,
                    height: 10,
                    mask: vec![1u8; 100],
                    score: 0.88,
                }],
                generation_time_ms: 0,
            })
        }
        fn input_size(&self) -> u32 {
            self.input_size
        }
    }

    #[test]
    fn runtime_starts_empty() {
        let rt = SegmentationRuntime::new();
        assert!(rt.loaded_models().is_empty());
        assert!(!rt.is_loaded("anything"));
    }

    #[test]
    fn unregister_returns_false_when_absent() {
        let rt = SegmentationRuntime::new();
        assert!(!rt.unregister("missing"));
    }

    #[test]
    fn stub_segmenter_returns_provider_not_available() {
        let stub = StubSegmenter;
        let res = stub.segment(&[], &[]);
        assert!(matches!(res, Err(ModelError::ProviderNotAvailable(_))));
    }

    #[tokio::test]
    async fn segment_on_unknown_model_returns_not_found() {
        let rt = SegmentationRuntime::new();
        let res = rt.segment("missing", vec![], vec![]).await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
    }

    #[tokio::test]
    async fn runtime_dispatches_to_registered_segmenter() {
        let rt = SegmentationRuntime::new();
        rt.register("mock", Arc::new(ConstantSegmenter { input_size: 1024 }));
        let r = rt
            .segment(
                "mock",
                vec![1],
                vec![SegmentPrompt::Point(PointPrompt {
                    x: 0.0,
                    y: 0.0,
                    is_foreground: true,
                })],
            )
            .await
            .unwrap();
        assert_eq!(r.masks.len(), 1);
        assert_eq!(r.masks[0].width, 10);
        assert_eq!(r.masks[0].height, 10);
        assert_eq!(r.masks[0].mask.len(), 100);
    }

    #[test]
    fn prompt_serializes_round_trip() {
        let p = SegmentPrompt::Point(PointPrompt {
            x: 1.0,
            y: 2.0,
            is_foreground: true,
        });
        let s = serde_json::to_string(&p).unwrap();
        let _: SegmentPrompt = serde_json::from_str(&s).unwrap();
    }
}
