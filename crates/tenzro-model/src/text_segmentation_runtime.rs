//! Text-promptable segmentation runtime — SAM 3 / SAM 3.1 family.
//!
//! SAM 3 is Meta's text-and-box-promptable open-vocabulary segmenter. It
//! is architecturally distinct from SAM 1 (`EdgeSAM`, `MobileSAM`) and
//! SAM 2 (Hiera): instead of one point/box prompt → 3 mask candidates,
//! SAM 3 runs three separate ONNX graphs in sequence and emits a
//! *detection*-shaped result — N (bbox, score, mask) triples per call,
//! gated by a free-text label.
//!
//! ```text
//!                 ┌─────────────────────────────┐
//!   image bytes ─▶│ sam3_image_encoder.onnx     │── backbone_fpn[3]
//!                 │ uint8 (3, 1008, 1008)       │── vision_pos_enc[3]
//!                 └─────────────────────────────┘
//!                                                       │
//!                 ┌─────────────────────────────┐       │
//!   text prompt ─▶│ sam3_language_encoder.onnx  │── language_mask
//!                 │ int64 (1, 32) CLIP BPE      │── language_features
//!                 └─────────────────────────────┘  (── language_embeds, unused)
//!                                                       │
//!                                                       ▼
//!                 ┌─────────────────────────────────────────────┐
//!   box prompt ──▶│ sam3_decoder.onnx                           │── boxes  (N, 4) cxcywh normalized
//!   (optional)    │  in: backbone_fpn_{0,1,2}, vision_pos_enc_2,│── scores (N,)
//!                 │      language_mask, language_features,      │── masks  (N, 1, H, W) bool-like
//!                 │      box_coords (1,1,4), box_labels (1,1),  │
//!                 │      box_masks (1,1) bool                   │
//!                 └─────────────────────────────────────────────┘
//! ```
//!
//! # Why a separate runtime from [`crate::segmentation_runtime`]
//!
//! SAM 1/2 expose a stable `(image_bytes, [point|box]+) → 1 SegmentMask`
//! API that the existing [`crate::segmentation_runtime::Segmenter`] trait
//! captures. SAM 3 is structurally different:
//!
//! - **Three ONNX graphs**, not two. Adds a tokenized text encoder.
//! - **Detection-style output**: variable number of (bbox, score, mask)
//!   triples per query, not a single argmax-IoU mask. Closer to the
//!   shape served by [`crate::detection_runtime::Detector`].
//! - **Open vocabulary**: prompt is a free-text label (e.g.
//!   `"person"`), not a point/box.
//! - **uint8 image input** with no normalization (just HWC→CHW
//!   transpose at 1008×1008). SAM 1 uses 0–255 + SAM mean/std and SAM
//!   2 uses ImageNet norm on `[0,1]`.
//!
//! Adding a `SamFamily::Sam3` variant to the existing runtime would
//! require widening the `Segmenter` trait's return type and shimming
//! the missing text-encoder path through the same trait — which would
//! break the SAM 1/2 callers without buying anything. A sibling module
//! with its own trait is the right factoring.
//!
//! # Threading
//!
//! `TextSegmentationRuntime` is `Send + Sync` and stores models in a
//! `DashMap<String, Arc<dyn TextPromptableSegmenter>>` keyed by model_id.
//! ORT sessions are not concurrent-safe — each of the three sessions
//! lives behind a `parking_lot::Mutex`. Inference is dispatched through
//! `tokio::task::spawn_blocking`.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// A single text-promptable segmentation result. The decoder emits
/// variable-N detections per query; this struct represents one of them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSegmentation {
    /// Bounding box in input-image pixel coordinates: (x0, y0, x1, y1).
    pub bbox: [f32; 4],
    /// Confidence score in `[0, 1]`.
    pub score: f32,
    /// Width of the mask in pixels (= original image width).
    pub width: u32,
    /// Height of the mask in pixels (= original image height).
    pub height: u32,
    /// Flat `[H * W]` u8 buffer (0 = background, 1 = foreground).
    pub mask: Vec<u8>,
}

/// Result of a text-promptable segmentation call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSegmentResult {
    /// One entry per detection above `score_threshold`.
    pub segmentations: Vec<TextSegmentation>,
    /// Total inference wall time in milliseconds.
    pub generation_time_ms: u64,
}

/// Optional box prompt for text-promptable segmentation. When `None`,
/// the decoder uses the text prompt alone; when `Some`, the decoder
/// restricts attention to the given box. Coordinates are
/// **normalized** `cxcywh` in `[0, 1]` (centre-x, centre-y, width,
/// height), matching the SAM 3 reference inference script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSegmentBoxPrompt {
    pub cx: f32,
    pub cy: f32,
    pub w: f32,
    pub h: f32,
}

/// Configuration for a text-promptable segmentation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSegmentConfig {
    /// Free-text label to segment (e.g. `"person"`, `"sofa"`, `"dog"`).
    /// When empty and `box_prompt` is `Some`, the decoder runs in
    /// box-only mode (`box_labels = [[1]]`, `box_masks = [[false]]`).
    pub text_prompt: String,
    /// Optional normalized cxcywh box prompt.
    #[serde(default)]
    pub box_prompt: Option<TextSegmentBoxPrompt>,
    /// Score threshold for retained detections, in `[0, 1]`. Detections
    /// with `score < threshold` are dropped.
    #[serde(default = "default_score_threshold")]
    pub score_threshold: f32,
}

fn default_score_threshold() -> f32 {
    0.5
}

impl Default for TextSegmentConfig {
    fn default() -> Self {
        Self {
            text_prompt: String::new(),
            box_prompt: None,
            score_threshold: default_score_threshold(),
        }
    }
}

/// Trait for text-promptable segmentation models. Implementations
/// adapt model-specific tokenization, preprocessing, and decoder I/O
/// to a common signature.
pub trait TextPromptableSegmenter: Send + Sync {
    fn segment_with_text(
        &self,
        image_bytes: &[u8],
        config: &TextSegmentConfig,
    ) -> Result<TextSegmentResult>;
    /// Native encoder input resolution (square). SAM 3 uses 1008.
    fn input_size(&self) -> u32;
    /// Tokenizer context length. SAM 3 uses 32.
    fn context_length(&self) -> u32;
}

/// Placeholder segmenter for tests and dependency-injection points that
/// need a `TextPromptableSegmenter` without loading a real SAM 3 bundle.
/// Always returns [`ModelError::ProviderNotAvailable`] from
/// `segment_with_text` so call sites can exercise their error paths.
#[derive(Debug)]
pub struct StubTextSegmenter;

impl TextPromptableSegmenter for StubTextSegmenter {
    fn segment_with_text(
        &self,
        _image_bytes: &[u8],
        _config: &TextSegmentConfig,
    ) -> Result<TextSegmentResult> {
        Err(ModelError::ProviderNotAvailable(
            "StubTextSegmenter cannot perform inference — load a real SAM 3 bundle".to_string(),
        ))
    }
    fn input_size(&self) -> u32 {
        0
    }
    fn context_length(&self) -> u32 {
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
    use tokenizers::Tokenizer;

    /// SAM 3 image encoder input resolution.
    const SAM3_INPUT_SIZE: u32 = 1008;
    /// SAM 3 CLIP tokenizer context length.
    const SAM3_CONTEXT_LENGTH: usize = 32;

    /// SAM 3 segmenter — three ORT sessions (image encoder + language
    /// encoder + decoder) plus a CLIP BPE tokenizer.
    pub struct Sam3Segmenter {
        image_encoder: parking_lot::Mutex<Session>,
        language_encoder: parking_lot::Mutex<Session>,
        decoder: parking_lot::Mutex<Session>,
        tokenizer: Tokenizer,
        /// CLIP `<|endoftext|>` token id, used to pad short prompts and
        /// as the EOS marker. Resolved at load time from the tokenizer.
        eot_id: u32,
    }

    impl Sam3Segmenter {
        /// Load the three ONNX models and the CLIP tokenizer from disk.
        ///
        /// External-data files (`*.onnx.data`) must be co-located next
        /// to their `.onnx` counterparts — ORT resolves them
        /// automatically via the relative path embedded in the
        /// `external_data` proto field.
        pub fn from_onnx(
            image_encoder_path: impl AsRef<Path>,
            language_encoder_path: impl AsRef<Path>,
            decoder_path: impl AsRef<Path>,
            tokenizer_path: impl AsRef<Path>,
        ) -> Result<Self> {
            let image_encoder = crate::onnx_session::build_onnx_session(
                image_encoder_path.as_ref(),
                "image encoder",
            )?;

            let language_encoder = crate::onnx_session::build_onnx_session(
                language_encoder_path.as_ref(),
                "language encoder",
            )?;

            let decoder =
                crate::onnx_session::build_onnx_session(decoder_path.as_ref(), "decoder")?;

            let tokenizer = Tokenizer::from_file(tokenizer_path.as_ref())
                .map_err(|e| ModelError::InvalidModel(format!("tokenizer load: {}", e)))?;

            // CLIP's `<|endoftext|>` token serves as both BOS, EOS, and
            // pad. Resolve it once at load time and reuse for padding
            // shorter sequences out to `SAM3_CONTEXT_LENGTH`.
            let eot_id = tokenizer.token_to_id("<|endoftext|>").ok_or_else(|| {
                ModelError::InvalidModel("CLIP tokenizer missing '<|endoftext|>' token".to_string())
            })?;

            Ok(Self {
                image_encoder: parking_lot::Mutex::new(image_encoder),
                language_encoder: parking_lot::Mutex::new(language_encoder),
                decoder: parking_lot::Mutex::new(decoder),
                tokenizer,
                eot_id,
            })
        }

        /// Decode the image and produce the uint8 `(3, 1008, 1008)`
        /// tensor SAM 3 expects. CHW layout, no normalization — the
        /// graph absorbs the 0–255 → float conversion internally.
        fn preprocess_image(&self, image_bytes: &[u8]) -> Result<(Array3<u8>, u32, u32)> {
            let img = image::load_from_memory(image_bytes)
                .map_err(|e| ModelError::InvalidModel(format!("image decode: {}", e)))?
                .to_rgb8();
            let orig_w = img.width();
            let orig_h = img.height();

            let resized = image::imageops::resize(
                &img,
                SAM3_INPUT_SIZE,
                SAM3_INPUT_SIZE,
                FilterType::Triangle,
            );

            // Build a (3, H, W) array in CHW order. The reference
            // Python script does `np.asarray(image).transpose(2, 0, 1)`
            // which lays out channels-first; we replicate exactly so
            // the encoder reads pixels in the order it was trained
            // with.
            let size = SAM3_INPUT_SIZE as usize;
            let mut arr = Array3::<u8>::zeros((3, size, size));
            for y in 0..size {
                for x in 0..size {
                    let px = resized.get_pixel(x as u32, y as u32);
                    for c in 0..3 {
                        arr[[c, y, x]] = px[c];
                    }
                }
            }
            Ok((arr, orig_w, orig_h))
        }

        /// Tokenize a text prompt to a `(1, 32)` int64 tensor using
        /// CLIP's BPE tokenizer. Replicates the OpenAI CLIP
        /// `tokenize(texts, context_length=32)` contract: BOS/EOS via
        /// `<|endoftext|>`, right-padded to context length, truncated
        /// to context length with EOT preserved at the final slot.
        fn tokenize_prompt(&self, text: &str) -> Result<Array2<i64>> {
            let encoded = self
                .tokenizer
                .encode(text, true)
                .map_err(|e| ModelError::InvalidModel(format!("tokenize: {}", e)))?;
            let ids = encoded.get_ids();
            let mut out = vec![self.eot_id as i64; SAM3_CONTEXT_LENGTH];

            let n = ids.len().min(SAM3_CONTEXT_LENGTH);
            for (i, id) in ids.iter().take(n).enumerate() {
                out[i] = *id as i64;
            }
            // Force the last slot to EOT when the input was truncated.
            // OpenAI's CLIP tokenize() asserts this — the decoder
            // attends to the EOT position for the pooled text feature.
            if ids.len() >= SAM3_CONTEXT_LENGTH {
                out[SAM3_CONTEXT_LENGTH - 1] = self.eot_id as i64;
            }

            let arr = Array2::<i64>::from_shape_vec((1, SAM3_CONTEXT_LENGTH), out)
                .map_err(|e| ModelError::InferenceError(format!("token tensor reshape: {}", e)))?;
            Ok(arr)
        }
    }

    impl TextPromptableSegmenter for Sam3Segmenter {
        fn segment_with_text(
            &self,
            image_bytes: &[u8],
            config: &TextSegmentConfig,
        ) -> Result<TextSegmentResult> {
            if image_bytes.is_empty() {
                return Err(ModelError::InvalidModel(
                    "image bytes are empty".to_string(),
                ));
            }
            if config.text_prompt.is_empty() && config.box_prompt.is_none() {
                return Err(ModelError::InvalidModel(
                    "either text_prompt or box_prompt must be supplied".to_string(),
                ));
            }

            let start = Instant::now();

            // ── Image encoder ────────────────────────────────────────
            let (image_arr, orig_w, orig_h) = self.preprocess_image(image_bytes)?;
            let image_tensor = Tensor::from_array(image_arr)
                .map_err(|e| ModelError::InferenceError(format!("image tensor: {}", e)))?;

            // Encoder emits six tensors in a deterministic order per
            // the wkentaro/sam3-onnx export contract:
            //   vision_pos_enc[0], vision_pos_enc[1], vision_pos_enc[2],
            //   backbone_fpn[0], backbone_fpn[1], backbone_fpn[2].
            // We snapshot the output names from the session metadata
            // before run() so we can release the encoder lock before
            // taking the decoder lock.
            let enc_outputs: Vec<(String, Vec<i64>, Vec<f32>)> = {
                let mut session = self.image_encoder.lock();
                let output_names: Vec<String> =
                    session.outputs.iter().map(|o| o.name.clone()).collect();
                let outputs = session
                    .run(ort::inputs!["image" => image_tensor])
                    .map_err(|e| ModelError::InferenceError(format!("image encoder run: {}", e)))?;

                let mut collected = Vec::with_capacity(output_names.len());
                for name in output_names {
                    let v = outputs.get(name.as_str()).ok_or_else(|| {
                        ModelError::InferenceError(format!(
                            "image encoder missing output '{}'",
                            name
                        ))
                    })?;
                    let (shape, data) = v.try_extract_tensor::<f32>().map_err(|e| {
                        ModelError::InferenceError(format!(
                            "image encoder extract '{}': {}",
                            name, e
                        ))
                    })?;
                    collected.push((name, shape.iter().copied().collect(), data.to_vec()));
                }
                collected
            };

            if enc_outputs.len() != 6 {
                return Err(ModelError::InferenceError(format!(
                    "SAM 3 image encoder expected 6 outputs, got {}",
                    enc_outputs.len()
                )));
            }

            // Split into the two triples per the reference contract.
            // Output 0..3 = vision_pos_enc, 3..6 = backbone_fpn.
            let vision_pos_enc_2 = enc_outputs[2].clone();
            let backbone_fpn_0 = enc_outputs[3].clone();
            let backbone_fpn_1 = enc_outputs[4].clone();
            let backbone_fpn_2 = enc_outputs[5].clone();

            // ── Language encoder ─────────────────────────────────────
            // Empty text + box-only mode: still tokenize an empty
            // string so the decoder receives shape-correct inputs;
            // box_labels=[[1]] / box_masks=[[true]] downstream tells
            // the decoder to ignore the language features.
            let tokens = self.tokenize_prompt(&config.text_prompt)?;
            let tokens_tensor = Tensor::from_array(tokens)
                .map_err(|e| ModelError::InferenceError(format!("tokens tensor: {}", e)))?;

            let (language_mask, language_features) = {
                let mut session = self.language_encoder.lock();
                let outputs = session
                    .run(ort::inputs!["tokens" => tokens_tensor])
                    .map_err(|e| {
                        ModelError::InferenceError(format!("language encoder run: {}", e))
                    })?;

                let mask_v = outputs.get("language_mask").ok_or_else(|| {
                    ModelError::InferenceError("language encoder missing 'language_mask'".into())
                })?;
                let (mask_shape, mask_data) = mask_v.try_extract_tensor::<f32>().map_err(|e| {
                    ModelError::InferenceError(format!("language_mask extract: {}", e))
                })?;

                let feats_v = outputs.get("language_features").ok_or_else(|| {
                    ModelError::InferenceError(
                        "language encoder missing 'language_features'".into(),
                    )
                })?;
                let (feats_shape, feats_data) =
                    feats_v.try_extract_tensor::<f32>().map_err(|e| {
                        ModelError::InferenceError(format!("language_features extract: {}", e))
                    })?;

                (
                    (
                        "language_mask".to_string(),
                        mask_shape.iter().copied().collect::<Vec<i64>>(),
                        mask_data.to_vec(),
                    ),
                    (
                        "language_features".to_string(),
                        feats_shape.iter().copied().collect::<Vec<i64>>(),
                        feats_data.to_vec(),
                    ),
                )
            };

            // ── Decoder feed assembly ────────────────────────────────
            let fpn0 = reshape_4d(&backbone_fpn_0)?;
            let fpn1 = reshape_4d(&backbone_fpn_1)?;
            let fpn2 = reshape_4d(&backbone_fpn_2)?;
            let vpe2 = reshape_4d(&vision_pos_enc_2)?;
            let lang_mask = reshape_nd(&language_mask)?;
            let lang_feats = reshape_nd(&language_features)?;

            let fpn0_tensor = Tensor::from_array(fpn0)
                .map_err(|e| ModelError::InferenceError(format!("fpn0 tensor: {}", e)))?;
            let fpn1_tensor = Tensor::from_array(fpn1)
                .map_err(|e| ModelError::InferenceError(format!("fpn1 tensor: {}", e)))?;
            let fpn2_tensor = Tensor::from_array(fpn2)
                .map_err(|e| ModelError::InferenceError(format!("fpn2 tensor: {}", e)))?;
            let vpe2_tensor = Tensor::from_array(vpe2)
                .map_err(|e| ModelError::InferenceError(format!("vpe2 tensor: {}", e)))?;
            let lang_mask_tensor = Tensor::from_array(lang_mask)
                .map_err(|e| ModelError::InferenceError(format!("lang_mask tensor: {}", e)))?;
            let lang_feats_tensor = Tensor::from_array(lang_feats)
                .map_err(|e| ModelError::InferenceError(format!("lang_feats tensor: {}", e)))?;

            // Box prompt handling. The reference inference script
            // encodes the dual mode as:
            //   - text-only:  box_coords=zeros, labels=[[1]], masks=[[true]]
            //   - box+text:   box_coords=[cx,cy,w,h], labels=[[1]], masks=[[false]]
            // The `masks` flag tells the decoder whether the box
            // tensor is real (`false` → real, `true` → masked-out
            // placeholder, semantics inverted from intuition).
            let (box_coords_vals, box_masks_val): ([f32; 4], bool) = match &config.box_prompt {
                Some(b) => ([b.cx, b.cy, b.w, b.h], false),
                None => ([0.0, 0.0, 0.0, 0.0], true),
            };
            let box_coords_arr = Array3::<f32>::from_shape_vec((1, 1, 4), box_coords_vals.to_vec())
                .map_err(|e| ModelError::InferenceError(format!("box_coords reshape: {}", e)))?;
            let box_labels_arr = Array2::<i64>::from_shape_vec((1, 1), vec![1])
                .map_err(|e| ModelError::InferenceError(format!("box_labels reshape: {}", e)))?;
            let box_masks_arr = Array2::<bool>::from_shape_vec((1, 1), vec![box_masks_val])
                .map_err(|e| ModelError::InferenceError(format!("box_masks reshape: {}", e)))?;

            let box_coords_tensor = Tensor::from_array(box_coords_arr)
                .map_err(|e| ModelError::InferenceError(format!("box_coords tensor: {}", e)))?;
            let box_labels_tensor = Tensor::from_array(box_labels_arr)
                .map_err(|e| ModelError::InferenceError(format!("box_labels tensor: {}", e)))?;
            let box_masks_tensor = Tensor::from_array(box_masks_arr)
                .map_err(|e| ModelError::InferenceError(format!("box_masks tensor: {}", e)))?;

            let feed: Vec<(String, SessionInputValue<'_>)> = vec![
                ("backbone_fpn_0".into(), fpn0_tensor.into()),
                ("backbone_fpn_1".into(), fpn1_tensor.into()),
                ("backbone_fpn_2".into(), fpn2_tensor.into()),
                ("vision_pos_enc_2".into(), vpe2_tensor.into()),
                ("language_mask".into(), lang_mask_tensor.into()),
                ("language_features".into(), lang_feats_tensor.into()),
                ("box_coords".into(), box_coords_tensor.into()),
                ("box_labels".into(), box_labels_tensor.into()),
                ("box_masks".into(), box_masks_tensor.into()),
            ];

            // ── Decoder pass ─────────────────────────────────────────
            let (boxes_shape, boxes_data, scores_data, masks_shape, masks_data) = {
                let mut session = self.decoder.lock();
                let outputs = session
                    .run(feed)
                    .map_err(|e| ModelError::InferenceError(format!("decoder run: {}", e)))?;

                let boxes_v = outputs.get("boxes").ok_or_else(|| {
                    ModelError::InferenceError("decoder missing 'boxes' output".into())
                })?;
                let (bs, bd) = boxes_v
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("boxes extract: {}", e)))?;

                let scores_v = outputs.get("scores").ok_or_else(|| {
                    ModelError::InferenceError("decoder missing 'scores' output".into())
                })?;
                let (_ss, sd) = scores_v
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("scores extract: {}", e)))?;

                let masks_v = outputs.get("masks").ok_or_else(|| {
                    ModelError::InferenceError("decoder missing 'masks' output".into())
                })?;
                let (ms, md) = masks_v
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("masks extract: {}", e)))?;

                (
                    bs.iter().copied().collect::<Vec<i64>>(),
                    bd.to_vec(),
                    sd.to_vec(),
                    ms.iter().copied().collect::<Vec<i64>>(),
                    md.to_vec(),
                )
            };

            // ── Postprocess ──────────────────────────────────────────
            // boxes: [N, 4] cxcywh normalized — convert to xyxy pixel
            // coords. masks: [N, 1, H, W] post-sigmoid logits;
            // threshold at 0.5 and bilinear-resample to (orig_h, orig_w).
            let n = match boxes_shape.as_slice() {
                [n, 4] => *n as usize,
                other => {
                    return Err(ModelError::InferenceError(format!(
                        "decoder unexpected boxes shape {:?}, expected [N, 4]",
                        other
                    )));
                }
            };

            let (m_n, m_h, m_w) = match masks_shape.as_slice() {
                [n, 1, h, w] => (*n as usize, *h as usize, *w as usize),
                [n, h, w] => (*n as usize, *h as usize, *w as usize),
                other => {
                    return Err(ModelError::InferenceError(format!(
                        "decoder unexpected masks shape {:?}, expected [N, 1, H, W]",
                        other
                    )));
                }
            };
            if m_n != n {
                return Err(ModelError::InferenceError(format!(
                    "boxes/masks N mismatch: {} vs {}",
                    n, m_n
                )));
            }
            if scores_data.len() < n {
                return Err(ModelError::InferenceError(format!(
                    "scores length {} < N {}",
                    scores_data.len(),
                    n
                )));
            }

            let mut segmentations = Vec::new();
            for i in 0..n {
                let score = scores_data[i];
                if score < config.score_threshold {
                    continue;
                }

                let cx = boxes_data[i * 4] * orig_w as f32;
                let cy = boxes_data[i * 4 + 1] * orig_h as f32;
                let w = boxes_data[i * 4 + 2] * orig_w as f32;
                let h = boxes_data[i * 4 + 3] * orig_h as f32;
                let x0 = cx - w / 2.0;
                let y0 = cy - h / 2.0;
                let x1 = cx + w / 2.0;
                let y1 = cy + h / 2.0;

                let mask_offset = i * m_h * m_w;
                let mask_slice = &masks_data[mask_offset..mask_offset + m_h * m_w];
                let binary =
                    bilinear_threshold(mask_slice, m_h, m_w, orig_h as usize, orig_w as usize, 0.5);

                segmentations.push(TextSegmentation {
                    bbox: [x0, y0, x1, y1],
                    score: score.clamp(0.0, 1.0),
                    width: orig_w,
                    height: orig_h,
                    mask: binary,
                });
            }

            Ok(TextSegmentResult {
                segmentations,
                generation_time_ms: start.elapsed().as_millis() as u64,
            })
        }

        fn input_size(&self) -> u32 {
            SAM3_INPUT_SIZE
        }

        fn context_length(&self) -> u32 {
            SAM3_CONTEXT_LENGTH as u32
        }
    }

    /// Reshape a `(name, shape, data)` triple into a 4-D `f32` array,
    /// returning a clear error when the shape doesn't fit the data.
    fn reshape_4d(t: &(String, Vec<i64>, Vec<f32>)) -> Result<Array4<f32>> {
        if t.1.len() != 4 {
            return Err(ModelError::InferenceError(format!(
                "expected 4-D tensor for '{}', got rank {}",
                t.0,
                t.1.len()
            )));
        }
        let dims = (
            t.1[0] as usize,
            t.1[1] as usize,
            t.1[2] as usize,
            t.1[3] as usize,
        );
        Array4::<f32>::from_shape_vec(dims, t.2.clone())
            .map_err(|e| ModelError::InferenceError(format!("reshape '{}' to 4-D: {}", t.0, e)))
    }

    /// Reshape an arbitrary-rank `(name, shape, data)` triple back into
    /// a dynamic `ndarray::ArrayD<f32>`. The decoder accepts the
    /// language tensors at whatever rank/shape the encoder emitted —
    /// we just preserve it round-trip.
    fn reshape_nd(t: &(String, Vec<i64>, Vec<f32>)) -> Result<ndarray::ArrayD<f32>> {
        let dims: Vec<usize> = t.1.iter().map(|d| *d as usize).collect();
        ndarray::ArrayD::<f32>::from_shape_vec(ndarray::IxDyn(&dims), t.2.clone())
            .map_err(|e| ModelError::InferenceError(format!("reshape '{}' to ND: {}", t.0, e)))
    }

    /// Bilinear-resample logits from `(src_h, src_w)` to
    /// `(dst_h, dst_w)` and threshold at `threshold` to a binary `u8`
    /// mask. SAM 3's decoder emits post-sigmoid mask logits in `[0, 1]`
    /// at a low resolution — the reference script does bilinear
    /// resize + threshold at 0.5.
    fn bilinear_threshold(
        src: &[f32],
        src_h: usize,
        src_w: usize,
        dst_h: usize,
        dst_w: usize,
        threshold: f32,
    ) -> Vec<u8> {
        let mut out = vec![0u8; dst_h * dst_w];
        if src_h == 0 || src_w == 0 || dst_h == 0 || dst_w == 0 {
            return out;
        }
        let scale_y = (src_h as f32 - 1.0).max(0.0) / (dst_h as f32 - 1.0).max(1.0);
        let scale_x = (src_w as f32 - 1.0).max(0.0) / (dst_w as f32 - 1.0).max(1.0);

        for y in 0..dst_h {
            let sy = y as f32 * scale_y;
            let y0 = sy.floor() as usize;
            let y1 = (y0 + 1).min(src_h - 1);
            let wy = sy - y0 as f32;
            for x in 0..dst_w {
                let sx = x as f32 * scale_x;
                let x0 = sx.floor() as usize;
                let x1 = (x0 + 1).min(src_w - 1);
                let wx = sx - x0 as f32;

                let v00 = src[y0 * src_w + x0];
                let v01 = src[y0 * src_w + x1];
                let v10 = src[y1 * src_w + x0];
                let v11 = src[y1 * src_w + x1];

                let v0 = v00 * (1.0 - wx) + v01 * wx;
                let v1 = v10 * (1.0 - wx) + v11 * wx;
                let v = v0 * (1.0 - wy) + v1 * wy;

                if v > threshold {
                    out[y * dst_w + x] = 1;
                }
            }
        }
        out
    }
}

pub use onnx_backend::Sam3Segmenter;

/// Runtime owning one or more loaded text-promptable segmenters.
pub struct TextSegmentationRuntime {
    models: dashmap::DashMap<String, Arc<dyn TextPromptableSegmenter>>,
}

impl Default for TextSegmentationRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl TextSegmentationRuntime {
    pub fn new() -> Self {
        Self {
            models: dashmap::DashMap::new(),
        }
    }

    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn TextPromptableSegmenter>) {
        self.models.insert(model_id.into(), model);
    }

    /// Load a SAM-3-family bundle from disk (image encoder + language
    /// encoder + decoder + tokenizer.json) and register it under
    /// `model_id`.
    pub fn load_sam3(
        &self,
        model_id: impl Into<String>,
        image_encoder_path: impl AsRef<Path>,
        language_encoder_path: impl AsRef<Path>,
        decoder_path: impl AsRef<Path>,
        tokenizer_path: impl AsRef<Path>,
    ) -> Result<()> {
        let model = Sam3Segmenter::from_onnx(
            image_encoder_path,
            language_encoder_path,
            decoder_path,
            tokenizer_path,
        )?;
        self.models.insert(
            model_id.into(),
            Arc::new(model) as Arc<dyn TextPromptableSegmenter>,
        );
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

    pub async fn segment_with_text(
        &self,
        model_id: &str,
        image_bytes: Vec<u8>,
        config: TextSegmentConfig,
    ) -> Result<TextSegmentResult> {
        let model = self
            .models
            .get(model_id)
            .map(|kv| kv.value().clone())
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))?;
        tokio::task::spawn_blocking(move || model.segment_with_text(&image_bytes, &config))
            .await
            .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {}", e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock segmenter that returns one fixed detection. Exercises
    /// runtime dispatch and DashMap bookkeeping without loading ONNX.
    struct ConstantTextSegmenter;
    impl TextPromptableSegmenter for ConstantTextSegmenter {
        fn segment_with_text(
            &self,
            _image_bytes: &[u8],
            _config: &TextSegmentConfig,
        ) -> Result<TextSegmentResult> {
            Ok(TextSegmentResult {
                segmentations: vec![TextSegmentation {
                    bbox: [0.0, 0.0, 10.0, 10.0],
                    score: 0.9,
                    width: 10,
                    height: 10,
                    mask: vec![1u8; 100],
                }],
                generation_time_ms: 0,
            })
        }
        fn input_size(&self) -> u32 {
            1008
        }
        fn context_length(&self) -> u32 {
            32
        }
    }

    #[test]
    fn runtime_starts_empty() {
        let rt = TextSegmentationRuntime::new();
        assert!(rt.loaded_models().is_empty());
        assert!(!rt.is_loaded("anything"));
    }

    #[test]
    fn unregister_returns_false_when_absent() {
        let rt = TextSegmentationRuntime::new();
        assert!(!rt.unregister("missing"));
    }

    #[test]
    fn stub_returns_provider_not_available() {
        let stub = StubTextSegmenter;
        let res = stub.segment_with_text(&[], &TextSegmentConfig::default());
        assert!(matches!(res, Err(ModelError::ProviderNotAvailable(_))));
    }

    #[tokio::test]
    async fn segment_on_unknown_model_returns_not_found() {
        let rt = TextSegmentationRuntime::new();
        let res = rt
            .segment_with_text("missing", vec![], TextSegmentConfig::default())
            .await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
    }

    #[tokio::test]
    async fn runtime_dispatches_to_registered_segmenter() {
        let rt = TextSegmentationRuntime::new();
        rt.register("mock", Arc::new(ConstantTextSegmenter));
        let cfg = TextSegmentConfig {
            text_prompt: "person".to_string(),
            box_prompt: None,
            score_threshold: 0.5,
        };
        let r = rt.segment_with_text("mock", vec![1], cfg).await.unwrap();
        assert_eq!(r.segmentations.len(), 1);
        assert_eq!(r.segmentations[0].width, 10);
        assert_eq!(r.segmentations[0].mask.len(), 100);
    }

    #[test]
    fn box_prompt_round_trip() {
        let b = TextSegmentBoxPrompt {
            cx: 0.5,
            cy: 0.5,
            w: 0.2,
            h: 0.3,
        };
        let s = serde_json::to_string(&b).unwrap();
        let _: TextSegmentBoxPrompt = serde_json::from_str(&s).unwrap();
    }

    #[test]
    fn config_default_threshold_is_half() {
        let cfg = TextSegmentConfig::default();
        assert!((cfg.score_threshold - 0.5).abs() < f32::EPSILON);
    }
}
