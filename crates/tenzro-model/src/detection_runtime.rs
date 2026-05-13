//! Object detection runtime backed by ONNX Runtime.
//!
//! Supports the two open-license, NMS-free DETR families that ship in the
//! Tenzro detection catalog:
//!
//! - **RF-DETR** (Roboflow, Apache 2.0, ICLR 2026 — the first real-time
//!   detector to break >60 AP on COCO). Single input `"input"` of shape
//!   `[1, 3, H, W]` with ImageNet normalization. Two outputs: `"dets"` —
//!   cxcywh boxes in `[0, 1]` normalized image coordinates of shape
//!   `[1, num_queries, 4]`, and `"labels"` — raw class logits of shape
//!   `[1, num_queries, num_classes]` that the client must sigmoid.
//!   RF-DETR was trained with **90-class COCO indexing** (the original
//!   Detectron2 layout that includes 11 deprecated "background" slots), so
//!   the catalog records `num_classes: 90`.
//!
//! - **D-FINE** (Peterande/D-FINE, Apache 2.0). Two inputs `"images"` of
//!   shape `[1, 3, 640, 640]` and `"orig_target_sizes"` of dtype int64,
//!   shape `[1, 2]` carrying the unresized `(H, W)` of the source image.
//!   Pixel values are scaled to `[0, 1]` *only* — no ImageNet normalization.
//!   Three outputs already in fully postprocessed form: `"labels"` (int64),
//!   `"boxes"` (xyxy pixel coordinates relative to the original image),
//!   and `"scores"` (post-sigmoid, sorted descending). D-FINE uses standard
//!   80-class COCO indexing.
//!
//! # Pre/post-processing
//!
//! - **Decode** PNG/JPEG/WebP via the `image` crate.
//! - **Resize** to `(input_size, input_size)` with Lanczos3.
//! - **NHWC → NCHW** float layout.
//! - **RF-DETR:** normalize with ImageNet mean/std. Postprocess by
//!   sigmoiding the class logits, taking the per-query top-1 class, filtering
//!   by `score_threshold`, converting cxcywh → xyxy, and scaling to the
//!   *original* image pixel coordinates.
//! - **D-FINE:** scale to `[0, 1]` only and pass `orig_target_sizes`
//!   directly; the graph emits final xyxy pixel boxes already in the
//!   original image's coordinate frame.
//!
//! # Threading
//!
//! `DetectionRuntime` is `Send + Sync` and holds loaded ONNX sessions in a
//! `DashMap` keyed by model_id. ORT sessions are not concurrent-safe, so
//! sessions are wrapped in `parking_lot::Mutex`. Inference is dispatched
//! through `tokio::task::spawn_blocking`.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// A single detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Bounding box in input-image pixel coordinates: (x0, y0, x1, y1).
    pub bbox: [f32; 4],
    /// Class index (catalog-dependent — RF-DETR uses 0..90, D-FINE uses 0..80).
    pub label_id: u32,
    /// Optional class label string when the registry was loaded with
    /// a labels file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Confidence in [0, 1].
    pub score: f32,
}

/// Result of a detection call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectResult {
    pub detections: Vec<Detection>,
    pub generation_time_ms: u64,
}

/// Trait for object detectors.
pub trait Detector: Send + Sync {
    fn detect(&self, image_bytes: &[u8], score_threshold: f32) -> Result<DetectResult>;
    fn input_size(&self) -> u32;
    fn num_classes(&self) -> u32;
}

/// Which DETR family the loaded ONNX graph implements. Drives both
/// preprocessing (normalization vs. scale-only) and postprocessing
/// (raw logits vs. baked-in NMS-free output).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetrFamily {
    /// RF-DETR — single `"input"` tensor, ImageNet norm, raw logit outputs.
    RfDetr,
    /// D-FINE — `"images"` + `"orig_target_sizes"` int64 input, no norm,
    /// postprocessed output (labels int64, xyxy pixel boxes, sigmoid scores).
    DFine,
}

/// Stub detector for builds without the `onnx` feature.
#[derive(Debug)]
pub struct StubDetector;

impl StubDetector {
    pub fn from_onnx(_path: impl AsRef<Path>) -> Result<Self> {
        Err(ModelError::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
}

impl Detector for StubDetector {
    fn detect(&self, _image_bytes: &[u8], _score_threshold: f32) -> Result<DetectResult> {
        Err(ModelError::ProviderNotAvailable(
            "ONNX backend not enabled — rebuild tenzro-model with --features onnx".to_string(),
        ))
    }
    fn input_size(&self) -> u32 {
        0
    }
    fn num_classes(&self) -> u32 {
        0
    }
}

mod onnx_backend {
    use super::*;
    use image::imageops::FilterType;
    use ndarray::{Array2, Array4};
    use ort::session::{Session, builder::GraphOptimizationLevel};
    use ort::value::Tensor;
    use std::time::Instant;

    /// ImageNet normalization constants — RF-DETR was trained with these.
    const IMAGENET_MEAN: [f32; 3] = [0.485, 0.456, 0.406];
    const IMAGENET_STD: [f32; 3] = [0.229, 0.224, 0.225];

    /// Generic ONNX detector covering both RF-DETR and D-FINE.
    ///
    /// `Session::run` requires `&mut self` in ort 2.x, so the session is
    /// wrapped in a `Mutex` to expose a `&self` API. ONNX Runtime sessions
    /// are not safe to call concurrently from multiple threads regardless,
    /// so the mutex matches the underlying contract.
    pub struct GenericDetrDetector {
        session: parking_lot::Mutex<Session>,
        family: DetrFamily,
        input_size: u32,
        num_classes: u32,
        /// Tensor name for the image input (RF-DETR: "input", D-FINE: "images").
        image_input_name: String,
        /// Tensor name for the original-size int64 input. Only used by D-FINE.
        orig_size_input_name: Option<String>,
    }

    impl GenericDetrDetector {
        /// Load an ONNX file and inspect its inputs to pick names. Falls back
        /// to family-canonical names ("input" / "images" / "orig_target_sizes")
        /// when introspection is ambiguous.
        pub fn from_onnx(
            path: impl AsRef<Path>,
            family: DetrFamily,
            input_size: u32,
            num_classes: u32,
        ) -> Result<Self> {
            let session = Session::builder()
                .map_err(|e| ModelError::InvalidModel(format!("ORT session builder: {}", e)))?
                .with_optimization_level(GraphOptimizationLevel::Level3)
                .map_err(|e| ModelError::InvalidModel(format!("ORT optimization level: {}", e)))?
                .commit_from_file(path.as_ref())
                .map_err(|e| ModelError::ProviderNotAvailable(format!("ORT load failed: {}", e)))?;

            let mut image_input_name = None;
            let mut orig_size_input_name = None;

            for inp in &session.inputs {
                let n = inp.name.as_str();
                if n == "orig_target_sizes" {
                    orig_size_input_name = Some(inp.name.clone());
                } else if image_input_name.is_none() {
                    image_input_name = Some(inp.name.clone());
                }
            }

            let image_input_name = image_input_name.unwrap_or_else(|| match family {
                DetrFamily::RfDetr => "input".to_string(),
                DetrFamily::DFine => "images".to_string(),
            });

            if family == DetrFamily::DFine && orig_size_input_name.is_none() {
                orig_size_input_name = Some("orig_target_sizes".to_string());
            }

            Ok(Self {
                session: parking_lot::Mutex::new(session),
                family,
                input_size,
                num_classes,
                image_input_name,
                orig_size_input_name,
            })
        }

        /// Decode → resize → NCHW float. Returns the `[1, 3, H, W]` tensor and
        /// the original `(width, height)` pair for downstream coordinate
        /// scaling.
        fn preprocess(&self, image_bytes: &[u8]) -> Result<(Array4<f32>, u32, u32)> {
            let img = image::load_from_memory(image_bytes)
                .map_err(|e| ModelError::InvalidModel(format!("image decode: {}", e)))?
                .to_rgb8();
            let orig_w = img.width();
            let orig_h = img.height();

            let size = self.input_size;
            let resized = image::imageops::resize(&img, size, size, FilterType::Lanczos3);

            let h = size as usize;
            let w = size as usize;
            let mut arr = Array4::<f32>::zeros((1, 3, h, w));

            let (apply_norm, mean, std) = match self.family {
                DetrFamily::RfDetr => (true, IMAGENET_MEAN, IMAGENET_STD),
                // D-FINE: scale to [0, 1] only; no per-channel norm.
                DetrFamily::DFine => (false, [0.0; 3], [1.0; 3]),
            };

            for y in 0..h {
                for x in 0..w {
                    let px = resized.get_pixel(x as u32, y as u32);
                    for c in 0..3 {
                        let scaled = px[c] as f32 / 255.0;
                        let v = if apply_norm {
                            (scaled - mean[c]) / std[c]
                        } else {
                            scaled
                        };
                        arr[[0, c, y, x]] = v;
                    }
                }
            }

            Ok((arr, orig_w, orig_h))
        }
    }

    /// Numerically stable sigmoid.
    #[inline]
    fn sigmoid(x: f32) -> f32 {
        if x >= 0.0 {
            1.0 / (1.0 + (-x).exp())
        } else {
            let e = x.exp();
            e / (1.0 + e)
        }
    }

    /// Convert a single cxcywh-normalized box to xyxy pixel coordinates.
    #[inline]
    fn cxcywh_norm_to_xyxy_pixels(
        cx: f32,
        cy: f32,
        w: f32,
        h: f32,
        img_w: f32,
        img_h: f32,
    ) -> [f32; 4] {
        let x0 = (cx - w * 0.5) * img_w;
        let y0 = (cy - h * 0.5) * img_h;
        let x1 = (cx + w * 0.5) * img_w;
        let y1 = (cy + h * 0.5) * img_h;
        [
            x0.clamp(0.0, img_w),
            y0.clamp(0.0, img_h),
            x1.clamp(0.0, img_w),
            y1.clamp(0.0, img_h),
        ]
    }

    impl Detector for GenericDetrDetector {
        fn detect(&self, image_bytes: &[u8], score_threshold: f32) -> Result<DetectResult> {
            if image_bytes.is_empty() {
                return Err(ModelError::InvalidModel("image bytes are empty".to_string()));
            }

            let start = Instant::now();
            let (arr, orig_w, orig_h) = self.preprocess(image_bytes)?;

            let image_tensor = Tensor::from_array(arr)
                .map_err(|e| ModelError::InferenceError(format!("ORT tensor: {}", e)))?;

            let detections = match self.family {
                DetrFamily::RfDetr => {
                    self.run_rfdetr(image_tensor, orig_w, orig_h, score_threshold)?
                }
                DetrFamily::DFine => {
                    self.run_dfine(image_tensor, orig_w, orig_h, score_threshold)?
                }
            };

            Ok(DetectResult {
                detections,
                generation_time_ms: start.elapsed().as_millis() as u64,
            })
        }

        fn input_size(&self) -> u32 {
            self.input_size
        }

        fn num_classes(&self) -> u32 {
            self.num_classes
        }
    }

    impl GenericDetrDetector {
        fn run_rfdetr(
            &self,
            image_tensor: Tensor<f32>,
            orig_w: u32,
            orig_h: u32,
            score_threshold: f32,
        ) -> Result<Vec<Detection>> {
            let (dets_shape, dets, labels_shape, labels) = {
                let mut session = self.session.lock();
                let outputs = session
                    .run(ort::inputs![self.image_input_name.as_str() => image_tensor])
                    .map_err(|e| ModelError::InferenceError(format!("ORT run: {}", e)))?;

                let dets_value = outputs.get("dets").ok_or_else(|| {
                    ModelError::InferenceError("RF-DETR missing 'dets' output".to_string())
                })?;
                let (ds, dd) = dets_value
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("ORT extract dets: {}", e)))?;
                let dets_shape: Vec<i64> = ds.iter().copied().collect();
                let dets: Vec<f32> = dd.to_vec();

                let labels_value = outputs.get("labels").ok_or_else(|| {
                    ModelError::InferenceError("RF-DETR missing 'labels' output".to_string())
                })?;
                let (ls, ld) = labels_value.try_extract_tensor::<f32>().map_err(|e| {
                    ModelError::InferenceError(format!("ORT extract labels: {}", e))
                })?;
                let labels_shape: Vec<i64> = ls.iter().copied().collect();
                let labels: Vec<f32> = ld.to_vec();

                (dets_shape, dets, labels_shape, labels)
            };

            // dets: [1, Q, 4], labels: [1, Q, C]
            let (q_d, four) = match dets_shape.as_slice() {
                [1, q, 4] => (*q as usize, 4_usize),
                other => {
                    return Err(ModelError::InferenceError(format!(
                        "RF-DETR unexpected dets shape {:?}, expected [1, Q, 4]",
                        other
                    )));
                }
            };
            let (q_l, c) = match labels_shape.as_slice() {
                [1, q, c] => (*q as usize, *c as usize),
                other => {
                    return Err(ModelError::InferenceError(format!(
                        "RF-DETR unexpected labels shape {:?}, expected [1, Q, C]",
                        other
                    )));
                }
            };
            if q_d != q_l {
                return Err(ModelError::InferenceError(format!(
                    "RF-DETR query count mismatch: dets={} labels={}",
                    q_d, q_l
                )));
            }
            let _ = four;

            let img_w = orig_w as f32;
            let img_h = orig_h as f32;

            let mut out = Vec::new();
            for q in 0..q_d {
                // Per-query top-1 class via sigmoid (DETR's NMS-free scoring).
                let logit_base = q * c;
                let mut best_score = 0.0_f32;
                let mut best_class = 0_usize;
                for k in 0..c {
                    let s = sigmoid(labels[logit_base + k]);
                    if s > best_score {
                        best_score = s;
                        best_class = k;
                    }
                }
                if best_score < score_threshold {
                    continue;
                }

                let box_base = q * 4;
                let cx = dets[box_base];
                let cy = dets[box_base + 1];
                let bw = dets[box_base + 2];
                let bh = dets[box_base + 3];
                let bbox = cxcywh_norm_to_xyxy_pixels(cx, cy, bw, bh, img_w, img_h);

                out.push(Detection {
                    bbox,
                    label_id: best_class as u32,
                    label: None,
                    score: best_score,
                });
            }

            // Sort descending by score so callers can take top-K cheaply.
            out.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
            Ok(out)
        }

        fn run_dfine(
            &self,
            image_tensor: Tensor<f32>,
            orig_w: u32,
            orig_h: u32,
            score_threshold: f32,
        ) -> Result<Vec<Detection>> {
            // D-FINE expects orig_target_sizes as int64 [1, 2] in (H, W) order
            // — matches Peterande/D-FINE export.
            let orig_arr =
                Array2::<i64>::from_shape_vec((1, 2), vec![orig_h as i64, orig_w as i64])
                    .map_err(|e| ModelError::InferenceError(format!("orig_sizes shape: {}", e)))?;
            let orig_tensor = Tensor::from_array(orig_arr)
                .map_err(|e| ModelError::InferenceError(format!("ORT orig_sizes tensor: {}", e)))?;

            let orig_name = self
                .orig_size_input_name
                .clone()
                .unwrap_or_else(|| "orig_target_sizes".to_string());

            // Build the feed manually because the two inputs have different
            // element types (f32 image, i64 orig sizes).
            let feed: Vec<(String, ort::session::SessionInputValue<'_>)> = vec![
                (self.image_input_name.clone(), image_tensor.into()),
                (orig_name, orig_tensor.into()),
            ];

            let (labels_shape, labels, boxes_shape, boxes, scores_shape, scores) = {
                let mut session = self.session.lock();
                let outputs = session
                    .run(feed)
                    .map_err(|e| ModelError::InferenceError(format!("ORT run: {}", e)))?;

                let labels_v = outputs.get("labels").ok_or_else(|| {
                    ModelError::InferenceError("D-FINE missing 'labels' output".to_string())
                })?;
                let (ls, ld) = labels_v.try_extract_tensor::<i64>().map_err(|e| {
                    ModelError::InferenceError(format!("ORT extract labels: {}", e))
                })?;
                let labels_shape: Vec<i64> = ls.iter().copied().collect();
                let labels: Vec<i64> = ld.to_vec();

                let boxes_v = outputs.get("boxes").ok_or_else(|| {
                    ModelError::InferenceError("D-FINE missing 'boxes' output".to_string())
                })?;
                let (bs, bd) = boxes_v
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("ORT extract boxes: {}", e)))?;
                let boxes_shape: Vec<i64> = bs.iter().copied().collect();
                let boxes: Vec<f32> = bd.to_vec();

                let scores_v = outputs.get("scores").ok_or_else(|| {
                    ModelError::InferenceError("D-FINE missing 'scores' output".to_string())
                })?;
                let (ss, sd) = scores_v.try_extract_tensor::<f32>().map_err(|e| {
                    ModelError::InferenceError(format!("ORT extract scores: {}", e))
                })?;
                let scores_shape: Vec<i64> = ss.iter().copied().collect();
                let scores: Vec<f32> = sd.to_vec();

                (
                    labels_shape,
                    labels,
                    boxes_shape,
                    boxes,
                    scores_shape,
                    scores,
                )
            };

            let n_labels = match labels_shape.as_slice() {
                [1, n] => *n as usize,
                [n] => *n as usize,
                other => {
                    return Err(ModelError::InferenceError(format!(
                        "D-FINE unexpected labels shape {:?}",
                        other
                    )));
                }
            };
            let n_scores = match scores_shape.as_slice() {
                [1, n] => *n as usize,
                [n] => *n as usize,
                other => {
                    return Err(ModelError::InferenceError(format!(
                        "D-FINE unexpected scores shape {:?}",
                        other
                    )));
                }
            };
            let n_boxes = match boxes_shape.as_slice() {
                [1, n, 4] => *n as usize,
                [n, 4] => *n as usize,
                other => {
                    return Err(ModelError::InferenceError(format!(
                        "D-FINE unexpected boxes shape {:?}, expected [.., N, 4]",
                        other
                    )));
                }
            };
            if n_labels != n_scores || n_labels != n_boxes {
                return Err(ModelError::InferenceError(format!(
                    "D-FINE shape mismatch: labels={} scores={} boxes={}",
                    n_labels, n_scores, n_boxes
                )));
            }

            let mut out = Vec::with_capacity(n_labels);
            for i in 0..n_labels {
                let score = scores[i];
                // D-FINE emits scores sorted desc — early-exit once we drop below threshold.
                if score < score_threshold {
                    break;
                }
                let bb_base = i * 4;
                let bbox = [
                    boxes[bb_base],
                    boxes[bb_base + 1],
                    boxes[bb_base + 2],
                    boxes[bb_base + 3],
                ];
                let label_id = labels[i].max(0) as u32;
                out.push(Detection {
                    bbox,
                    label_id,
                    label: None,
                    score,
                });
            }

            Ok(out)
        }
    }
}

pub use onnx_backend::GenericDetrDetector;

/// Runtime that owns multiple loaded detection models.
pub struct DetectionRuntime {
    models: dashmap::DashMap<String, Arc<dyn Detector>>,
}

impl Default for DetectionRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionRuntime {
    pub fn new() -> Self {
        Self {
            models: dashmap::DashMap::new(),
        }
    }

    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn Detector>) {
        self.models.insert(model_id.into(), model);
    }

    /// Load an ONNX detector from disk and register it under `model_id`.
    /// The caller is responsible for picking the correct `DetrFamily` based
    /// on the catalog entry's `family` field.
    pub fn load_onnx(
        &self,
        model_id: impl Into<String>,
        path: impl AsRef<Path>,
        family: DetrFamily,
        input_size: u32,
        num_classes: u32,
    ) -> Result<()> {
        let model = GenericDetrDetector::from_onnx(path, family, input_size, num_classes)?;
        self.models
            .insert(model_id.into(), Arc::new(model) as Arc<dyn Detector>);
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

    pub async fn detect(
        &self,
        model_id: &str,
        image_bytes: Vec<u8>,
        score_threshold: f32,
    ) -> Result<DetectResult> {
        let model = self
            .models
            .get(model_id)
            .map(|kv| kv.value().clone())
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))?;
        tokio::task::spawn_blocking(move || model.detect(&image_bytes, score_threshold))
            .await
            .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {}", e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock detector that returns a deterministic synthetic result. Used to
    /// exercise the runtime's dispatch and dashmap bookkeeping without
    /// loading an ONNX file.
    struct ConstantDetector {
        input_size: u32,
        num_classes: u32,
    }
    impl Detector for ConstantDetector {
        fn detect(&self, _image_bytes: &[u8], _threshold: f32) -> Result<DetectResult> {
            Ok(DetectResult {
                detections: vec![Detection {
                    bbox: [0.0, 0.0, 10.0, 10.0],
                    label_id: 1,
                    label: Some("person".into()),
                    score: 0.99,
                }],
                generation_time_ms: 0,
            })
        }
        fn input_size(&self) -> u32 {
            self.input_size
        }
        fn num_classes(&self) -> u32 {
            self.num_classes
        }
    }

    #[test]
    fn runtime_starts_empty() {
        let rt = DetectionRuntime::new();
        assert!(rt.loaded_models().is_empty());
    }

    #[test]
    fn unregister_returns_false_when_absent() {
        let rt = DetectionRuntime::new();
        assert!(!rt.unregister("missing"));
    }

    #[test]
    fn stub_detector_returns_provider_not_available() {
        let stub = StubDetector;
        let res = stub.detect(&[], 0.5);
        assert!(matches!(res, Err(ModelError::ProviderNotAvailable(_))));
    }

    #[tokio::test]
    async fn detect_on_unknown_model_returns_not_found() {
        let rt = DetectionRuntime::new();
        let res = rt.detect("missing", vec![], 0.5).await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
    }

    #[tokio::test]
    async fn runtime_dispatches_to_registered_detector() {
        let rt = DetectionRuntime::new();
        rt.register(
            "test-model",
            Arc::new(ConstantDetector {
                input_size: 640,
                num_classes: 80,
            }),
        );
        let r = rt.detect("test-model", vec![1, 2, 3], 0.0).await.unwrap();
        assert_eq!(r.detections.len(), 1);
        assert_eq!(r.detections[0].label_id, 1);
        assert!((r.detections[0].score - 0.99).abs() < 1e-6);
    }

    #[test]
    fn detection_serializes_round_trip() {
        let d = Detection {
            bbox: [1.0, 2.0, 3.0, 4.0],
            label_id: 0,
            label: Some("person".into()),
            score: 0.95,
        };
        let s = serde_json::to_string(&d).unwrap();
        let back: Detection = serde_json::from_str(&s).unwrap();
        assert_eq!(back.bbox, d.bbox);
        assert_eq!(back.label_id, d.label_id);
    }
}
