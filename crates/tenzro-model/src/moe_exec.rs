//! MoE expert-host execution runtime.
//!
//! Completes the decentralized MoE serving path that [`crate::moe_shard`]
//! (holder view) and [`crate::moe_router`] (dispatch planner) set up:
//!
//! - **Expert weights** — a holder loads one expert's FFN as a standalone
//!   safetensors blob (`gate_proj.weight` / `up_proj.weight` /
//!   `down_proj.weight`, HF row-major `[out_features, in_features]`) and
//!   executes the SwiGLU forward over a batched hidden-state matrix.
//! - **Gating network** — the router peer loads the per-layer router
//!   weight (`router.weight`, `[num_experts, d_model]`) as its own blob
//!   and computes top-k routing with renormalized softmax weights over
//!   the selected experts (Mixtral convention).
//! - **Combine** — after fan-out responses return, the router reassembles
//!   per-token outputs as the gate-weighted sum of expert outputs.
//!
//! Everything here is pure compute over `ndarray` `f32` — no I/O, no
//! signing, no settlement. The `tenzro-node` layer wires the wire types
//! ([`ExpertExecuteRequest`] / [`ExpertExecuteResponse`]) over the iroh
//! QUIC channel and applies payment/verification policy.
//!
//! Per-expert blobs are the unit of distribution: they are published to
//! the iroh blob store and fetched by holders on `load_expert`. The blob
//! format is fixed to the three-tensor safetensors layout above so any
//! extraction tool that walks a HF MoE checkpoint
//! (`model.layers.{L}.mlp.experts.{E}.{gate,up,down}_proj.weight`) can
//! emit holder-loadable blobs.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use ndarray::{Array1, Array2, ArrayView1, ArrayView2, Axis};
use parking_lot::Mutex;
use safetensors::tensor::TensorView;
use safetensors::{Dtype, SafeTensors};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::moe_compute::{BackendKind, ComputeBackend, ExpertCompute, Weight};
use crate::moe_quant::{QuantKind, QuantMatrix};
use crate::moe_receipt::ExpertExecutionReceipt;
use crate::moe_router::TokenRouting;
use crate::moe_shard::ExpertId;

/// Canonical tensor name for the gate projection in an expert blob.
pub const TENSOR_GATE_PROJ: &str = "gate_proj.weight";
/// Canonical tensor name for the up projection in an expert blob.
pub const TENSOR_UP_PROJ: &str = "up_proj.weight";
/// Canonical tensor name for the down projection in an expert blob.
pub const TENSOR_DOWN_PROJ: &str = "down_proj.weight";
/// Canonical tensor name for the gating network in a router blob.
pub const TENSOR_ROUTER: &str = "router.weight";
/// Canonical tensor name for the router's expert-selection bias in a router
/// blob. Present only for sigmoid-scored checkpoints (DeepSeek layout); its
/// presence switches [`GatingNetwork`] from softmax to sigmoid routing.
pub const TENSOR_ROUTER_BIAS: &str = "router.bias";

/// `__metadata__` key on a router blob: scaling factor multiplied into the
/// renormalized routed-expert weights (DeepSeek layout; defaults to 1.0).
pub const META_ROUTED_SCALING_FACTOR: &str = "routed_scaling_factor";
/// `__metadata__` key on a router blob: the checkpoint's shared-expert count.
/// Non-zero means one fused shared-expert FFN rides at expert index
/// `num_experts` and every token receives it with weight 1.0.
pub const META_SHARED_EXPERTS: &str = "shared_experts";

/// `__metadata__` key prefix for a quantized projection's kind tag. A blob
/// carries `"<tensor>.quant" = "q4_k" | "q6_k" | "q8_0"` when the tensor's
/// bytes are GGUF-block-quantized (stored as a flat `U8` tensor) rather than
/// a dense float matrix.
const META_QUANT_SUFFIX: &str = ".quant";
/// `__metadata__` key suffix for a quantized projection's logical shape,
/// `"<rows>,<cols>"` — the block bytes alone do not carry `[out, in]`.
const META_SHAPE_SUFFIX: &str = ".shape";

/// Errors from expert loading, routing, execution, and combining.
#[derive(Debug, Clone, Error, PartialEq)]
pub enum MoeExecError {
    /// The safetensors blob failed to parse.
    #[error("safetensors parse error: {0}")]
    Parse(String),

    /// A required tensor is absent from the blob.
    #[error("tensor '{name}' missing from blob")]
    TensorMissing {
        /// Canonical tensor name that was expected.
        name: String,
    },

    /// A tensor's dtype is not one of F32 / F16 / BF16.
    #[error("tensor '{name}' has unsupported dtype {dtype:?} (want F32, F16, or BF16)")]
    UnsupportedDtype {
        /// Tensor name.
        name: String,
        /// The offending dtype.
        dtype: Dtype,
    },

    /// A tensor's shape does not match the expected projection shape.
    #[error("tensor '{name}' has shape {got:?}, expected {expected}")]
    BadShape {
        /// Tensor name.
        name: String,
        /// Shape found in the blob.
        got: Vec<usize>,
        /// Human-readable expected shape.
        expected: String,
    },

    /// Execution was requested for an expert this host has not loaded.
    #[error("expert {model_id} l{layer}/e{expert} is not loaded on this host")]
    ExpertNotLoaded {
        /// Model the request targeted.
        model_id: String,
        /// Layer index.
        layer: u32,
        /// Expert index.
        expert: u32,
    },

    /// Routing was requested for a layer whose gating network is not loaded.
    #[error("gating network for {model_id} layer {layer} is not loaded on this host")]
    GateNotLoaded {
        /// Model the request targeted.
        model_id: String,
        /// Layer index.
        layer: u32,
    },

    /// The flattened hidden-state buffer does not factor into
    /// `token_count * d_model`.
    #[error("hidden-state length {len} does not match {tokens} tokens x d_model {d_model}")]
    DimensionMismatch {
        /// Flat buffer length.
        len: usize,
        /// Token count declared by the request.
        tokens: usize,
        /// Model dimension declared by the request.
        d_model: usize,
    },

    /// The request carried zero tokens.
    #[error("expert execution batch is empty")]
    EmptyBatch,

    /// The disk tier failed to read or write an expert blob.
    #[error("expert disk tier I/O error: {0}")]
    DiskTier(String),

    /// A quantized projection's `__metadata__` tag is malformed or its
    /// block bytes do not decode against the declared shape.
    #[error("quantized tensor '{name}' is malformed: {reason}")]
    BadQuant {
        /// Tensor name.
        name: String,
        /// Why the quantized tensor was rejected.
        reason: String,
    },

    /// A combine step referenced a token/expert output that no response
    /// supplied.
    #[error("no expert output for token {token_index} from expert l{layer}/e{expert}")]
    MissingContribution {
        /// Token index that lacked an output row.
        token_index: u32,
        /// Layer of the expert.
        layer: u32,
        /// Expert index.
        expert: u32,
    },
}

/// Result alias for this module.
pub type MoeExecResult<T> = std::result::Result<T, MoeExecError>;

// ---------------------------------------------------------------------------
// dtype decode
// ---------------------------------------------------------------------------

/// Decode a safetensors tensor view into a row-major `f32` matrix.
/// Accepts F32 (little-endian per the safetensors spec), F16, and BF16.
fn tensor_to_f32_matrix(name: &str, view: &TensorView<'_>) -> MoeExecResult<Array2<f32>> {
    let shape = view.shape();
    if shape.len() != 2 {
        return Err(MoeExecError::BadShape {
            name: name.to_string(),
            got: shape.to_vec(),
            expected: "a 2-D matrix".to_string(),
        });
    }
    let (rows, cols) = (shape[0], shape[1]);
    let data = view.data();
    let values: Vec<f32> = match view.dtype() {
        Dtype::F32 => data
            .chunks_exact(4)
            .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect(),
        Dtype::F16 => data
            .chunks_exact(2)
            .map(|b| half::f16::from_le_bytes([b[0], b[1]]).to_f32())
            .collect(),
        Dtype::BF16 => data
            .chunks_exact(2)
            .map(|b| half::bf16::from_le_bytes([b[0], b[1]]).to_f32())
            .collect(),
        other => {
            return Err(MoeExecError::UnsupportedDtype {
                name: name.to_string(),
                dtype: other,
            })
        }
    };
    Array2::from_shape_vec((rows, cols), values).map_err(|e| MoeExecError::Parse(e.to_string()))
}

/// Decode a safetensors tensor view into an `f32` vector.
/// Accepts F32 (little-endian per the safetensors spec), F16, and BF16.
fn tensor_to_f32_vector(name: &str, view: &TensorView<'_>) -> MoeExecResult<Array1<f32>> {
    let shape = view.shape();
    if shape.len() != 1 {
        return Err(MoeExecError::BadShape {
            name: name.to_string(),
            got: shape.to_vec(),
            expected: "a 1-D vector".to_string(),
        });
    }
    let data = view.data();
    let values: Vec<f32> = match view.dtype() {
        Dtype::F32 => data
            .chunks_exact(4)
            .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect(),
        Dtype::F16 => data
            .chunks_exact(2)
            .map(|b| half::f16::from_le_bytes([b[0], b[1]]).to_f32())
            .collect(),
        Dtype::BF16 => data
            .chunks_exact(2)
            .map(|b| half::bf16::from_le_bytes([b[0], b[1]]).to_f32())
            .collect(),
        other => {
            return Err(MoeExecError::UnsupportedDtype {
                name: name.to_string(),
                dtype: other,
            })
        }
    };
    Ok(Array1::from_vec(values))
}

fn required_tensor<'a>(
    st: &'a SafeTensors<'a>,
    name: &str,
) -> MoeExecResult<TensorView<'a>> {
    st.tensor(name).map_err(|_| MoeExecError::TensorMissing {
        name: name.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Expert FFN
// ---------------------------------------------------------------------------

/// One expert projection weight, row-major `[out_features, in_features]`.
///
/// Either a dense `f32` matrix (decoded from F32/F16/BF16) or a GGUF
/// block-quantized matrix (Q4_K/Q6_K/Q8_0) held in its compact block form.
/// The quantized variant is decoded one weight row at a time inside the
/// matmul, so only a single `f32` row is ever materialized — the resident
/// footprint stays at the quantized size and the byte-bounded LRU keeps
/// proportionally more experts warm.
#[derive(Debug, Clone)]
enum Projection {
    Dense(Array2<f32>),
    Quant(QuantMatrix),
}

impl Projection {
    fn rows(&self) -> usize {
        match self {
            Projection::Dense(w) => w.nrows(),
            Projection::Quant(q) => q.nrows(),
        }
    }

    fn cols(&self) -> usize {
        match self {
            Projection::Dense(w) => w.ncols(),
            Projection::Quant(q) => q.ncols(),
        }
    }

    fn dim(&self) -> (usize, usize) {
        (self.rows(), self.cols())
    }

    /// Resident bytes: dense = `elems * 4`, quant = the block payload.
    fn approx_bytes(&self) -> u64 {
        match self {
            Projection::Dense(w) => (w.len() * 4) as u64,
            Projection::Quant(q) => q.approx_bytes(),
        }
    }

    /// Quant tag for status, or `None` when dense.
    fn quant_tag(&self) -> Option<&'static str> {
        match self {
            Projection::Dense(_) => None,
            Projection::Quant(q) => Some(q.kind().tag()),
        }
    }

    /// Borrow this projection as a backend-consumable [`Weight`].
    fn as_weight(&self) -> Weight<'_> {
        match self {
            Projection::Dense(w) => Weight::Dense(w.view()),
            Projection::Quant(q) => Weight::Quant(q),
        }
    }
}

/// One expert's FFN weights.
///
/// Projections follow the HF `Linear.weight` convention — row-major
/// `[out_features, in_features]`, so the forward computes `x @ W^T`. Each
/// projection is independently dense or block-quantized (mixed is allowed;
/// GGUF conventionally leaves `down_proj` at higher precision than
/// `gate`/`up`).
#[derive(Debug, Clone)]
pub struct ExpertFfn {
    gate: Projection,
    up: Projection,
    down: Projection,
    d_model: usize,
    d_ff: usize,
}

impl ExpertFfn {
    /// Parse an expert blob (three-tensor safetensors layout) and
    /// validate the projection shapes against each other. Each projection
    /// is dense (F32/F16/BF16) or, when tagged in `__metadata__`, GGUF
    /// block-quantized (a flat `U8` tensor + `"<name>.quant"` /
    /// `"<name>.shape"` metadata).
    pub fn from_safetensors(bytes: &[u8]) -> MoeExecResult<Self> {
        let st = SafeTensors::deserialize(bytes).map_err(|e| MoeExecError::Parse(e.to_string()))?;
        let meta = safetensors_metadata(bytes);
        let gate = load_projection(&st, &meta, TENSOR_GATE_PROJ)?;
        let up = load_projection(&st, &meta, TENSOR_UP_PROJ)?;
        let down = load_projection(&st, &meta, TENSOR_DOWN_PROJ)?;

        let (d_ff, d_model) = gate.dim();
        if up.dim() != (d_ff, d_model) {
            let (r, c) = up.dim();
            return Err(MoeExecError::BadShape {
                name: TENSOR_UP_PROJ.to_string(),
                got: vec![r, c],
                expected: format!("[{d_ff}, {d_model}] to match {TENSOR_GATE_PROJ}"),
            });
        }
        if down.dim() != (d_model, d_ff) {
            let (r, c) = down.dim();
            return Err(MoeExecError::BadShape {
                name: TENSOR_DOWN_PROJ.to_string(),
                got: vec![r, c],
                expected: format!("[{d_model}, {d_ff}] (transpose of {TENSOR_GATE_PROJ})"),
            });
        }

        Ok(Self {
            gate,
            up,
            down,
            d_model,
            d_ff,
        })
    }

    /// Model (hidden) dimension.
    pub fn d_model(&self) -> usize {
        self.d_model
    }

    /// Intermediate FFN dimension.
    pub fn d_ff(&self) -> usize {
        self.d_ff
    }

    /// Approximate resident bytes for the weights as held — dense
    /// projections count `f32` bytes, quantized ones count block bytes.
    pub fn approx_bytes(&self) -> u64 {
        self.gate.approx_bytes() + self.up.approx_bytes() + self.down.approx_bytes()
    }

    /// The highest-compression quant kind present across the three
    /// projections (for status), or `None` when the expert is fully dense.
    /// Ordering by descending bytes-per-weight: `q8_0` > `q6_k` > `q4_k`.
    pub fn quant_tag(&self) -> Option<&'static str> {
        // Report the coarsest (smallest) quant present, since that bounds
        // the expert's fidelity; fall back to any tag when only one differs.
        let tags = [
            self.gate.quant_tag(),
            self.up.quant_tag(),
            self.down.quant_tag(),
        ];
        let rank = |t: &&'static str| match *t {
            "q4_k" => 0,
            "q6_k" => 1,
            "q8_0" => 2,
            _ => 3,
        };
        tags.into_iter().flatten().min_by_key(|t| rank(t))
    }

    /// Batched SwiGLU forward:
    /// `Y = (silu(X W_g^T) * (X W_u^T)) W_d^T` for `X: [n_tokens, d_model]`.
    ///
    /// The three matmuls route through the supplied [`ExpertCompute`] backend
    /// (CPU floor, or GPU when the runtime resolved one). Grouped-GEMM
    /// batching is inherent: the whole token batch shares each projection's
    /// weight, so `W` is dequantized/uploaded once per projection, not once
    /// per token.
    pub fn forward(&self, x: ArrayView2<'_, f32>, be: &dyn ExpertCompute) -> Array2<f32> {
        debug_assert_eq!(x.ncols(), self.d_model);
        let mut h = be.matmul_xt(x, &self.gate.as_weight());
        h.mapv_inplace(silu);
        let u = be.matmul_xt(x, &self.up.as_weight());
        h *= &u;
        be.matmul_xt(h.view(), &self.down.as_weight())
    }
}

/// Decode the top-level `__metadata__` map from a safetensors blob. Returns
/// an empty map when absent or unparseable (a dense blob simply has none).
fn safetensors_metadata(bytes: &[u8]) -> HashMap<String, String> {
    if bytes.len() < 8 {
        return HashMap::new();
    }
    let header_len = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
    let Some(header) = bytes.get(8..8 + header_len) else {
        return HashMap::new();
    };
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(header) else {
        return HashMap::new();
    };
    val.get("__metadata__")
        .and_then(|m| m.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// Load one projection, choosing the dense or quantized decode by whether a
/// `"<name>.quant"` metadata tag is present.
fn load_projection(
    st: &SafeTensors<'_>,
    meta: &HashMap<String, String>,
    name: &str,
) -> MoeExecResult<Projection> {
    let view = required_tensor(st, name)?;
    let quant_key = format!("{name}{META_QUANT_SUFFIX}");
    match meta.get(&quant_key) {
        None => Ok(Projection::Dense(tensor_to_f32_matrix(name, &view)?)),
        Some(tag) => {
            let kind = QuantKind::from_tag(tag).ok_or_else(|| MoeExecError::BadQuant {
                name: name.to_string(),
                reason: format!("unknown quant tag '{tag}'"),
            })?;
            let (rows, cols) = parse_shape(meta, name)?;
            let q = QuantMatrix::from_blocks(kind, rows, cols, view.data().to_vec()).map_err(
                |e| MoeExecError::BadQuant {
                    name: name.to_string(),
                    reason: e.to_string(),
                },
            )?;
            Ok(Projection::Quant(q))
        }
    }
}

/// Parse the `"<name>.shape" = "rows,cols"` metadata for a quantized tensor.
fn parse_shape(meta: &HashMap<String, String>, name: &str) -> MoeExecResult<(usize, usize)> {
    let key = format!("{name}{META_SHAPE_SUFFIX}");
    let raw = meta.get(&key).ok_or_else(|| MoeExecError::BadQuant {
        name: name.to_string(),
        reason: format!("missing '{key}' shape metadata"),
    })?;
    let mut it = raw.split(',');
    let parse = |s: Option<&str>| s.and_then(|s| s.trim().parse::<usize>().ok());
    match (parse(it.next()), parse(it.next()), it.next()) {
        (Some(r), Some(c), None) => Ok((r, c)),
        _ => Err(MoeExecError::BadQuant {
            name: name.to_string(),
            reason: format!("shape '{raw}' is not 'rows,cols'"),
        }),
    }
}

#[inline]
fn silu(x: f32) -> f32 {
    x / (1.0 + (-x).exp())
}

// ---------------------------------------------------------------------------
// Gating network
// ---------------------------------------------------------------------------

/// Per-layer gating (router) network, decoded to `f32`.
///
/// Two scoring modes, selected by the blob's contents:
///
/// - **Softmax** (Qwen layout): `router.weight` only. Top-k by logit,
///   softmax-renormalized over the selection.
/// - **Sigmoid** (DeepSeek layout): `router.bias` present. Scores are
///   `sigmoid(W h)`; the bias steers *selection only* (top-k by
///   `score + bias`); combine weights are the selected raw scores
///   renormalized to sum 1 and multiplied by `routed_scaling_factor`.
///   When `shared_experts > 0`, every token additionally receives the
///   fused shared-expert FFN at expert index `num_experts` with weight
///   1.0, so the combiner's `Σ wᵢ·expertᵢ(h)` reproduces
///   `shared(h) + scale·Σ wᵢ·expertᵢ(h)`.
#[derive(Debug, Clone)]
pub struct GatingNetwork {
    weight: Array2<f32>,
    bias: Option<Array1<f32>>,
    routed_scaling_factor: f32,
    shared_experts: u32,
}

impl GatingNetwork {
    /// Parse a router blob: `router.weight` `[num_experts, d_model]`,
    /// optionally `router.bias` `[num_experts]` plus the
    /// [`META_ROUTED_SCALING_FACTOR`] / [`META_SHARED_EXPERTS`]
    /// `__metadata__` keys (DeepSeek layout).
    pub fn from_safetensors(bytes: &[u8]) -> MoeExecResult<Self> {
        let meta = safetensors_metadata(bytes);
        let st = SafeTensors::deserialize(bytes).map_err(|e| MoeExecError::Parse(e.to_string()))?;
        let weight = tensor_to_f32_matrix(TENSOR_ROUTER, &required_tensor(&st, TENSOR_ROUTER)?)?;
        let bias = match st.tensor(TENSOR_ROUTER_BIAS) {
            Ok(view) => Some(tensor_to_f32_vector(TENSOR_ROUTER_BIAS, &view)?),
            Err(_) => None,
        };
        if let Some(b) = &bias
            && b.len() != weight.nrows()
        {
            return Err(MoeExecError::BadShape {
                name: TENSOR_ROUTER_BIAS.to_string(),
                got: vec![b.len()],
                expected: format!("[{}] (one entry per routed expert)", weight.nrows()),
            });
        }
        let routed_scaling_factor = meta
            .get(META_ROUTED_SCALING_FACTOR)
            .and_then(|s| s.parse::<f32>().ok())
            .unwrap_or(1.0);
        let shared_experts = meta
            .get(META_SHARED_EXPERTS)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        Ok(Self {
            weight,
            bias,
            routed_scaling_factor,
            shared_experts,
        })
    }

    /// Number of routed experts this gate selects over.
    pub fn num_experts(&self) -> usize {
        self.weight.nrows()
    }

    /// Model (hidden) dimension.
    pub fn d_model(&self) -> usize {
        self.weight.ncols()
    }

    /// Approximate resident bytes for the decoded `f32` weight and bias.
    pub fn approx_bytes(&self) -> u64 {
        let bias_len = self.bias.as_ref().map_or(0, |b| b.len());
        ((self.weight.len() + bias_len) * 4) as u64
    }

    /// Top-k routing for one token. Softmax mode: select the k highest
    /// logits, renormalize with softmax over the selection. Sigmoid mode
    /// (bias present): select the k highest `sigmoid(logit) + bias`,
    /// weight by the selected sigmoid scores renormalized to sum 1 and
    /// scaled by `routed_scaling_factor`.
    /// Returns `(expert_index, weight)` pairs sorted by descending weight.
    pub fn route(&self, hidden: ArrayView1<'_, f32>, top_k: usize) -> Vec<(u32, f32)> {
        debug_assert_eq!(hidden.len(), self.d_model());
        let logits: Array1<f32> = self.weight.dot(&hidden);
        let k = top_k.clamp(1, logits.len());

        match &self.bias {
            Some(bias) => {
                // Sigmoid scoring: the bias steers selection only; combine
                // weights come from the raw sigmoid scores.
                let mut indexed: Vec<(u32, f32)> = logits
                    .iter()
                    .enumerate()
                    .map(|(i, &l)| (i as u32, 1.0 / (1.0 + (-l).exp())))
                    .collect();
                indexed.sort_by(|a, b| {
                    let ka = a.1 + bias[a.0 as usize];
                    let kb = b.1 + bias[b.0 as usize];
                    kb.total_cmp(&ka).then(a.0.cmp(&b.0))
                });
                indexed.truncate(k);
                let sum = indexed
                    .iter()
                    .map(|(_, s)| *s)
                    .sum::<f32>()
                    .max(f32::EPSILON);
                for (_, s) in indexed.iter_mut() {
                    *s = *s / sum * self.routed_scaling_factor;
                }
                indexed.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
                indexed
            }
            None => {
                let mut indexed: Vec<(u32, f32)> = logits
                    .iter()
                    .enumerate()
                    .map(|(i, &l)| (i as u32, l))
                    .collect();
                indexed.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
                indexed.truncate(k);

                // Softmax over the selected logits (max-subtracted for
                // stability).
                let max = indexed
                    .iter()
                    .map(|(_, l)| *l)
                    .fold(f32::NEG_INFINITY, f32::max);
                let mut sum = 0.0f32;
                for (_, l) in indexed.iter_mut() {
                    *l = (*l - max).exp();
                    sum += *l;
                }
                for (_, l) in indexed.iter_mut() {
                    *l /= sum;
                }
                indexed
            }
        }
    }

    /// Batched routing: one [`RoutedToken`] per row of `hidden`
    /// (`[n_tokens, d_model]`), with token indices `0..n`. When the blob
    /// declares shared experts, every token gets one extra slot for the
    /// fused shared-expert FFN at expert index `num_experts`, weight 1.0.
    pub fn route_batch(&self, layer: u32, hidden: ArrayView2<'_, f32>, top_k: usize) -> Vec<RoutedToken> {
        let shared_slot = (self.shared_experts > 0).then(|| RoutedSlot {
            expert: ExpertId::new(layer, self.num_experts() as u32),
            weight: 1.0,
        });
        hidden
            .axis_iter(Axis(0))
            .enumerate()
            .map(|(i, row)| {
                let mut slots: Vec<RoutedSlot> = self
                    .route(row, top_k)
                    .into_iter()
                    .map(|(expert, weight)| RoutedSlot {
                        expert: ExpertId::new(layer, expert),
                        weight,
                    })
                    .collect();
                if let Some(s) = shared_slot {
                    slots.push(s);
                }
                RoutedToken {
                    token_index: i as u32,
                    slots,
                }
            })
            .collect()
    }
}

/// One token's gate decision: its top-k experts with renormalized weights.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutedToken {
    /// Token index inside the request.
    pub token_index: u32,
    /// Selected `(expert, weight)` slots, descending by weight; when the
    /// checkpoint has a fused shared expert, its weight-1.0 slot rides last.
    pub slots: Vec<RoutedSlot>,
}

/// One top-k slot of a routed token.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RoutedSlot {
    /// Expert selected by the gate.
    pub expert: ExpertId,
    /// Renormalized gate weight for this slot.
    pub weight: f32,
}

/// Project routed tokens into the weight-free [`TokenRouting`] shape the
/// dispatch planner ([`crate::moe_router::plan_dispatch`]) consumes.
pub fn to_token_routing(routed: &[RoutedToken]) -> Vec<TokenRouting> {
    routed
        .iter()
        .map(|r| TokenRouting {
            token_index: r.token_index,
            experts: r.slots.iter().map(|s| s.expert).collect(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Serde adapter: `Vec<f32>` ⇔ base64 of the little-endian f32 bytes.
///
/// JSON number arrays cost ~10 bytes per element; base64-of-LE-bytes
/// costs ~5.4. Dense hidden-state batches (`tokens × d_model` floats)
/// stay comfortably inside the 4 MiB per-frame cap on the `tenzro/moe`
/// iroh ALPN.
pub mod f32_base64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Encode as base64(LE bytes).
    pub fn serialize<S: Serializer>(v: &[f32], s: S) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::with_capacity(v.len() * 4);
        for x in v {
            bytes.extend_from_slice(&x.to_le_bytes());
        }
        base64::engine::general_purpose::STANDARD
            .encode(bytes)
            .serialize(s)
    }

    /// Decode from base64(LE bytes).
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<f32>, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        if bytes.len() % 4 != 0 {
            return Err(serde::de::Error::custom(
                "f32 payload length is not a multiple of 4 bytes",
            ));
        }
        Ok(bytes
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect())
    }
}

/// Batched expert-execution request — the payload a router peer sends to
/// an expert holder for one [`crate::moe_router::ExpertBatch`].
///
/// The hidden-state rows travel one of two ways. Dense `f32` in
/// [`hidden_states`](Self::hidden_states) is the default. When `d_model`
/// is a multiple of 32 the router may instead send Q8_0-compressed blocks
/// in [`hidden_q8`](Self::hidden_q8) — quartering the on-wire activation
/// bytes at ~0.4% relative error, well below the noise floor of the
/// gate-weighted combine. Exactly one carrier is populated per request;
/// [`materialize_hidden`](Self::materialize_hidden) yields the `f32` rows
/// regardless of which was used, so the holder [`execute`] path is
/// carrier-agnostic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpertExecuteRequest {
    /// Model the expert belongs to.
    pub model_id: String,
    /// Layer index of the expert.
    pub layer: u32,
    /// Expert index inside the layer.
    pub expert: u32,
    /// Token indices this batch carries (for reassembly at the router).
    pub token_indices: Vec<u32>,
    /// Model (hidden) dimension of each row.
    pub d_model: u32,
    /// Row-major `[token_indices.len(), d_model]` hidden states,
    /// serialized as base64 f32 LE bytes (see [`f32_base64`]). Empty when
    /// [`hidden_q8`](Self::hidden_q8) carries the batch instead.
    #[serde(with = "f32_base64", default, skip_serializing_if = "Vec::is_empty")]
    pub hidden_states: Vec<f32>,
    /// Row-major `[token_indices.len(), d_model]` hidden states as
    /// concatenated Q8_0 blocks (base64), one row after another. `None`
    /// when the batch travels dense in [`hidden_states`](Self::hidden_states).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden_q8: Option<String>,
}

impl ExpertExecuteRequest {
    /// Build a request, compressing the hidden rows to Q8_0 on the wire
    /// when `d_model` is a multiple of 32. Falls back to dense `f32`
    /// otherwise (Q8_0 blocks are 32 elements wide).
    pub fn compressed(
        model_id: String,
        layer: u32,
        expert: u32,
        token_indices: Vec<u32>,
        d_model: u32,
        rows: Vec<f32>,
    ) -> Self {
        if d_model.is_multiple_of(32) && !rows.is_empty() {
            use base64::Engine;
            let blocks = crate::moe_quant::quantize_row_q8_0(&rows);
            let hidden_q8 =
                base64::engine::general_purpose::STANDARD.encode(&blocks);
            Self {
                model_id,
                layer,
                expert,
                token_indices,
                d_model,
                hidden_states: Vec::new(),
                hidden_q8: Some(hidden_q8),
            }
        } else {
            Self {
                model_id,
                layer,
                expert,
                token_indices,
                d_model,
                hidden_states: rows,
                hidden_q8: None,
            }
        }
    }

    /// Yield the `[token_indices.len(), d_model]` hidden rows, decoding the
    /// Q8_0 carrier when present. The returned length is always
    /// `token_indices.len() * d_model`; a carrier/length mismatch surfaces
    /// as [`MoeExecError::DimensionMismatch`].
    pub fn materialize_hidden(&self) -> MoeExecResult<Vec<f32>> {
        let d_model = self.d_model as usize;
        let expected = self.token_indices.len() * d_model;
        match &self.hidden_q8 {
            Some(b64) => {
                use base64::Engine;
                let blocks = base64::engine::general_purpose::STANDARD
                    .decode(b64.as_bytes())
                    .map_err(|_| MoeExecError::DimensionMismatch {
                        len: 0,
                        tokens: self.token_indices.len(),
                        d_model,
                    })?;
                if !d_model.is_multiple_of(32) {
                    return Err(MoeExecError::DimensionMismatch {
                        len: blocks.len(),
                        tokens: self.token_indices.len(),
                        d_model,
                    });
                }
                let mut out = vec![0.0f32; expected];
                if !out.is_empty() {
                    crate::moe_quant::dequantize_row_q8_0(&blocks, &mut out);
                }
                Ok(out)
            }
            None => Ok(self.hidden_states.clone()),
        }
    }

    /// SHA-256 over the wire carrier bytes of the hidden states — the Q8_0
    /// block bytes when [`hidden_q8`](Self::hidden_q8) carries the batch, the
    /// raw f32 LE bytes otherwise. Router and holder hash the identical bytes
    /// they exchanged, so the hash is stable across the lossy Q8_0 leg. A
    /// leading tag byte separates the two carrier encodings.
    pub fn carrier_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"tenzro/moe/carrier");
        match &self.hidden_q8 {
            Some(b64) => {
                use base64::Engine;
                hasher.update([1u8]);
                let blocks = base64::engine::general_purpose::STANDARD
                    .decode(b64.as_bytes())
                    .unwrap_or_default();
                hasher.update(&blocks);
            }
            None => {
                hasher.update([0u8]);
                for v in &self.hidden_states {
                    hasher.update(v.to_le_bytes());
                }
            }
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }
}

/// Response to an [`ExpertExecuteRequest`] — expert-FFN outputs for the
/// same token set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpertExecuteResponse {
    /// Model the expert belongs to.
    pub model_id: String,
    /// Layer index of the expert.
    pub layer: u32,
    /// Expert index inside the layer.
    pub expert: u32,
    /// Token indices, mirroring the request order.
    pub token_indices: Vec<u32>,
    /// Model (hidden) dimension of each row.
    pub d_model: u32,
    /// Row-major `[token_indices.len(), d_model]` expert outputs,
    /// serialized as base64 f32 LE bytes (see [`f32_base64`]).
    #[serde(with = "f32_base64")]
    pub outputs: Vec<f32>,
    /// Signed execution receipt binding the input carrier hash and the
    /// activation commitment of these outputs to the holder's provider
    /// identity. `None` only for local self-execution, where no receipt is
    /// needed — remote holders always attach one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ExpertExecutionReceipt>,
}

// ---------------------------------------------------------------------------
// Host runtime
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExpertKey {
    model_id: String,
    layer: u32,
    expert: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GateKey {
    model_id: String,
    layer: u32,
}

/// Where an expert's weights currently live on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpertTier {
    /// Decoded `f32` weights resident in the in-memory LRU, ready to
    /// dispatch without a decode step.
    Memory,
    /// Raw safetensors blob retained on the disk tier only; a decode is
    /// required before the next execute.
    Disk,
}

/// Status row for one loaded expert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoeLoadedExpert {
    /// Model the expert belongs to.
    pub model_id: String,
    /// Layer index.
    pub layer: u32,
    /// Expert index.
    pub expert: u32,
    /// Model (hidden) dimension.
    pub d_model: u32,
    /// Intermediate FFN dimension.
    pub d_ff: u32,
    /// Approximate resident bytes — dense `f32` size, or the block payload
    /// size when quantized.
    pub approx_bytes: u64,
    /// Whether the decoded weights are in memory or only on the disk tier.
    pub tier: ExpertTier,
    /// GGUF quant kind of the most-compressed projection (`q4_k` / `q6_k` /
    /// `q8_0`), or `None` when the expert is fully dense `f32`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub quant: Option<String>,
    /// Content-addressed `tenzro://blob/<hash>` URI these weights came from.
    /// `None` for experts admitted from an inline payload. Carried into the
    /// provider declaration so peers can fetch the same bytes when they
    /// self-select to repair an under-replicated expert.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source_uri: Option<String>,
}

/// Status row for one loaded gating network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoeLoadedGate {
    /// Model the gate belongs to.
    pub model_id: String,
    /// Layer index.
    pub layer: u32,
    /// Routed expert count.
    pub num_experts: u32,
    /// Model (hidden) dimension.
    pub d_model: u32,
    /// Approximate resident bytes (decoded `f32`).
    pub approx_bytes: u64,
}

/// Snapshot of everything resident on this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoeExpertRuntimeStatus {
    /// Loaded experts, sorted by `(model_id, layer, expert)`.
    pub experts: Vec<MoeLoadedExpert>,
    /// Loaded gating networks, sorted by `(model_id, layer)`.
    pub gates: Vec<MoeLoadedGate>,
    /// Sum of all approximate resident bytes (memory tier + gates).
    pub total_bytes: u64,
    /// Approximate bytes held by memory-tier experts.
    pub memory_bytes: u64,
    /// Memory-tier budget ceiling in bytes; experts beyond it spill to the
    /// disk tier.
    pub memory_budget_bytes: u64,
    /// Count of experts whose weights are decoded in memory.
    pub memory_experts: u32,
    /// Count of experts held on the disk tier only.
    pub disk_experts: u32,
    /// The compute backend this host resolved for expert forwards
    /// (`"cpu"`, `"cpu-avx512-vnni"`, `"cuda"`, `"wgpu"`). Advertised so the
    /// router can prefer GPU holders for large batches.
    pub compute_backend: String,
    /// True when the resolved backend runs on a GPU device.
    pub gpu: bool,
    /// Cumulative count of experts evicted from the memory tier to the disk
    /// tier under LRU pressure (blob retained on disk, decodable on demand).
    pub evicted_to_disk: u64,
    /// Cumulative count of experts dropped from the memory tier entirely (no
    /// disk tier configured) under LRU pressure. Dropped experts must be
    /// re-fetched from a peer holder before they can serve again.
    pub evicted_dropped: u64,
    /// Cumulative count of expert admissions that could not be satisfied within
    /// the memory budget without evicting the expert being admitted — i.e. a
    /// single expert larger than the whole budget was admitted anyway (it is
    /// still servable, but on-tier accounting exceeds the ceiling while it is
    /// resident).
    pub admissions_over_budget: u64,
    /// Measured expert-forward throughput in tokens per second: the larger of
    /// the current and previous one-minute buckets, divided by 60. Host-level
    /// aggregate across every resident expert; the declaration layer stamps it
    /// onto each advertised holding as `committed_tps`.
    pub measured_tps: u32,
}

/// Bytes reserved on the memory tier when no explicit budget and no
/// `MemAvailable` reading is obtainable: 4 GiB.
const DEFAULT_MEMORY_BUDGET_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Fraction of `MemAvailable` an auto-sized memory budget will claim.
const AUTO_BUDGET_NUM: u64 = 6;
const AUTO_BUDGET_DEN: u64 = 10;

/// Configuration for the holder-local expert residency layer.
#[derive(Debug, Clone)]
pub struct ResidencyConfig {
    /// Memory-tier byte ceiling. Experts beyond it are evicted (LRU) to the
    /// disk tier when a disk directory is set, or dropped otherwise.
    pub memory_budget_bytes: u64,
    /// Optional on-disk directory for the cold tier. When set, evicted
    /// experts keep their raw safetensors blob on disk and are decoded back
    /// into memory on demand.
    pub disk_dir: Option<PathBuf>,
}

impl Default for ResidencyConfig {
    fn default() -> Self {
        Self {
            memory_budget_bytes: auto_memory_budget_bytes(),
            disk_dir: None,
        }
    }
}

impl ResidencyConfig {
    /// Budget auto-sized from `MemAvailable`, no disk tier.
    pub fn auto() -> Self {
        Self::default()
    }

    /// Fixed memory budget, no disk tier.
    pub fn with_memory_budget(mut self, bytes: u64) -> Self {
        self.memory_budget_bytes = bytes.max(1);
        self
    }

    /// Enable the disk tier at `dir`. Evicted experts spill there instead of
    /// being dropped.
    pub fn with_disk_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.disk_dir = Some(dir.into());
        self
    }
}

/// Auto budget in bytes: `AUTO_BUDGET_NUM/AUTO_BUDGET_DEN` of the memory the
/// host reports as available. Falls back to [`DEFAULT_MEMORY_BUDGET_BYTES`]
/// when the reading is unavailable or rounds to zero.
fn auto_memory_budget_bytes() -> u64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    let budget = sys.available_memory() / AUTO_BUDGET_DEN * AUTO_BUDGET_NUM;
    if budget > 0 {
        budget
    } else {
        DEFAULT_MEMORY_BUDGET_BYTES
    }
}

/// LRU bookkeeping for one memory-resident expert.
struct MemEntry {
    ffn: Arc<ExpertFfn>,
    bytes: u64,
    /// Monotonic tick of the last access; the smallest is the LRU victim.
    last_tick: u64,
}

/// Disk-tier record: the raw blob path plus decoded-shape metadata so the
/// status view stays truthful without touching the file.
#[derive(Clone)]
struct DiskEntry {
    path: PathBuf,
    d_model: u32,
    d_ff: u32,
    approx_bytes: u64,
    quant: Option<String>,
}

/// Expert-holder / router-peer execution runtime. Holds decoded expert
/// FFNs and gating networks keyed by `(model_id, layer, expert)` /
/// `(model_id, layer)` and executes batches against them.
///
/// The expert side is residency-managed: a byte-bounded LRU keeps hot
/// experts decoded in memory, colder ones spill to an optional disk tier
/// (raw safetensors, decoded back on demand), and a readahead hook warms
/// experts the gate is about to select. Gating networks are small and stay
/// fully resident.
pub struct MoeExpertRuntime {
    /// Memory-tier experts under LRU eviction.
    mem: DashMap<ExpertKey, MemEntry>,
    /// Disk-tier experts (evicted from memory, blob retained on disk).
    disk: DashMap<ExpertKey, DiskEntry>,
    /// Content-addressed URI each expert's blob was fetched from. Keyed
    /// independently of the residency tiers so an eviction or promotion
    /// never loses the provenance the repair path needs.
    sources: DashMap<ExpertKey, String>,
    gates: DashMap<GateKey, Arc<GatingNetwork>>,
    /// Sum of `MemEntry::bytes` over `mem`.
    mem_bytes: AtomicU64,
    /// Monotonic access counter driving LRU ordering.
    tick: AtomicU64,
    /// Cumulative experts spilled to the disk tier under LRU pressure.
    evicted_to_disk: AtomicU64,
    /// Cumulative experts dropped (no disk tier) under LRU pressure.
    evicted_dropped: AtomicU64,
    /// Cumulative admissions where a single expert exceeded the whole budget
    /// and was admitted over-budget rather than refused.
    admissions_over_budget: AtomicU64,
    /// Wall-clock minute (`now_ms / 60_000`) the current throughput bucket
    /// covers.
    served_bucket_minute: AtomicU64,
    /// Tokens served by [`Self::execute`] during the current minute bucket.
    served_bucket_tokens: AtomicU64,
    /// Tokens served during the immediately preceding minute bucket. Zeroed
    /// when a minute is skipped entirely (idle host).
    served_prev_tokens: AtomicU64,
    memory_budget_bytes: u64,
    disk_dir: Option<PathBuf>,
    /// Serializes eviction so concurrent loads can't over-evict.
    evict_guard: Mutex<()>,
    /// Compute backend resolved once at construction (CPU floor, or GPU when
    /// `moe-gpu` is compiled and a device is present).
    compute: Box<dyn ExpertCompute>,
    /// Which backend `compute` resolved to (for status/telemetry).
    backend_kind: BackendKind,
}

impl std::fmt::Debug for MoeExpertRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MoeExpertRuntime")
            .field("mem_experts", &self.mem.len())
            .field("disk_experts", &self.disk.len())
            .field("gates", &self.gates.len())
            .field("mem_bytes", &self.mem_bytes.load(Ordering::Relaxed))
            .field("memory_budget_bytes", &self.memory_budget_bytes)
            .field("disk_dir", &self.disk_dir)
            .finish()
    }
}

impl Default for MoeExpertRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl MoeExpertRuntime {
    /// Construct an empty runtime with an auto-sized memory budget and no
    /// disk tier.
    pub fn new() -> Self {
        Self::with_config(ResidencyConfig::default())
    }

    /// Construct an empty runtime with an explicit residency configuration.
    /// The compute backend is resolved here via [`ComputeBackend::select`] —
    /// GPU when compiled and present, CPU otherwise.
    pub fn with_config(config: ResidencyConfig) -> Self {
        let (backend_kind, compute) = ComputeBackend::select();
        Self {
            mem: DashMap::new(),
            disk: DashMap::new(),
            sources: DashMap::new(),
            gates: DashMap::new(),
            mem_bytes: AtomicU64::new(0),
            tick: AtomicU64::new(0),
            evicted_to_disk: AtomicU64::new(0),
            evicted_dropped: AtomicU64::new(0),
            admissions_over_budget: AtomicU64::new(0),
            served_bucket_minute: AtomicU64::new(0),
            served_bucket_tokens: AtomicU64::new(0),
            served_prev_tokens: AtomicU64::new(0),
            memory_budget_bytes: config.memory_budget_bytes.max(1),
            disk_dir: config.disk_dir,
            evict_guard: Mutex::new(()),
            compute,
            backend_kind,
        }
    }

    /// The compute backend this runtime resolved (`"cpu"`,
    /// `"cpu-avx512-vnni"`, `"cuda"`, `"wgpu"`).
    pub fn compute_backend(&self) -> &'static str {
        self.compute.tag()
    }

    /// The resolved backend kind.
    pub fn backend_kind(&self) -> BackendKind {
        self.backend_kind
    }

    /// Memory-tier budget ceiling in bytes.
    pub fn memory_budget_bytes(&self) -> u64 {
        self.memory_budget_bytes
    }

    fn next_tick(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::Relaxed)
    }

    fn disk_path(&self, key: &ExpertKey) -> Option<PathBuf> {
        self.disk_dir.as_ref().map(|dir| {
            // Filenames are content-free of path separators: model ids can
            // contain '/', so hash-free but slash-escaped.
            let safe_model = key.model_id.replace(['/', '\\', ':'], "_");
            dir.join(format!("{safe_model}.l{}.e{}.safetensors", key.layer, key.expert))
        })
    }

    /// Decode and admit one expert blob. Replaces any previously loaded
    /// weights for the same `(model_id, layer, expert)`. Admits into the
    /// memory tier, evicting the coldest experts to the disk tier (or
    /// dropping them when no disk tier is set) to stay within budget.
    /// Returns the status row for the freshly loaded expert.
    ///
    /// `source_uri` is the content-addressed `tenzro://blob/<hash>` the
    /// bytes were fetched from, or `None` when they arrived inline. It is
    /// recorded verbatim and re-advertised so peers repairing this expert
    /// can fetch the identical blob.
    pub fn load_expert(
        &self,
        model_id: impl Into<String>,
        layer: u32,
        expert: u32,
        blob: &[u8],
        source_uri: Option<String>,
    ) -> MoeExecResult<MoeLoadedExpert> {
        let model_id = model_id.into();
        let ffn = ExpertFfn::from_safetensors(blob)?;
        let key = ExpertKey {
            model_id: model_id.clone(),
            layer,
            expert,
        };
        // Persist the raw blob to the disk tier up front when configured, so
        // a later eviction is a metadata move rather than a re-serialize.
        if let Some(path) = self.disk_path(&key) {
            write_blob_atomic(&path, blob)?;
        }
        match &source_uri {
            Some(uri) => {
                self.sources.insert(key.clone(), uri.clone());
            }
            None => {
                self.sources.remove(&key);
            }
        }
        let bytes = ffn.approx_bytes();
        let row = MoeLoadedExpert {
            model_id,
            layer,
            expert,
            d_model: ffn.d_model() as u32,
            d_ff: ffn.d_ff() as u32,
            approx_bytes: bytes,
            tier: ExpertTier::Memory,
            quant: ffn.quant_tag().map(str::to_string),
            source_uri,
        };
        self.admit_memory(key, Arc::new(ffn), bytes);
        Ok(row)
    }

    /// Insert (or replace) `key` in the memory tier, updating the byte
    /// accounting and evicting LRU victims until the budget holds.
    fn admit_memory(&self, key: ExpertKey, ffn: Arc<ExpertFfn>, bytes: u64) {
        // Replace any existing memory entry (subtract its bytes first).
        if let Some(prev) = self.mem.remove(&key) {
            self.mem_bytes.fetch_sub(prev.1.bytes, Ordering::Relaxed);
        }
        // A disk copy is now stale relative to this in-memory version only
        // if the blob changed; the on-disk blob was just (re)written by the
        // caller, so drop the disk-tier index entry — memory supersedes it.
        self.disk.remove(&key);
        let tick = self.next_tick();
        self.mem.insert(
            key,
            MemEntry {
                ffn,
                bytes,
                last_tick: tick,
            },
        );
        self.mem_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.evict_to_budget();
        // A single expert larger than the whole budget survives eviction (the
        // last resident entry is never evicted to nothing) but leaves resident
        // bytes above the ceiling. Record it so operators can see when the
        // budget is too small for the model being served.
        if bytes > self.memory_budget_bytes {
            self.admissions_over_budget
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Evict coldest memory-tier experts until resident bytes fit the
    /// budget. Evicted experts move to the disk tier when one is configured
    /// (blob already on disk from `load_expert`), else are dropped.
    fn evict_to_budget(&self) {
        let _guard = self.evict_guard.lock();
        while self.mem_bytes.load(Ordering::Relaxed) > self.memory_budget_bytes {
            // Never evict the last entry down to nothing if it alone exceeds
            // the budget — a single oversized expert must still be servable.
            if self.mem.len() <= 1 {
                break;
            }
            let victim = self
                .mem
                .iter()
                .min_by_key(|e| e.value().last_tick)
                .map(|e| e.key().clone());
            let Some(vkey) = victim else { break };
            if let Some((k, entry)) = self.mem.remove(&vkey) {
                self.mem_bytes.fetch_sub(entry.bytes, Ordering::Relaxed);
                if let Some(path) = self.disk_path(&k) {
                    self.disk.insert(
                        k,
                        DiskEntry {
                            path,
                            d_model: entry.ffn.d_model() as u32,
                            d_ff: entry.ffn.d_ff() as u32,
                            approx_bytes: entry.bytes,
                            quant: entry.ffn.quant_tag().map(str::to_string),
                        },
                    );
                    self.evicted_to_disk.fetch_add(1, Ordering::Relaxed);
                } else {
                    // No disk tier: expert is dropped (must be re-fetched).
                    self.evicted_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Resolve an expert to a decoded FFN, promoting it from the disk tier
    /// into memory (and touching its LRU tick) on a hit. Returns `None` when
    /// the expert is resident on neither tier.
    fn resolve(&self, key: &ExpertKey) -> MoeExecResult<Option<Arc<ExpertFfn>>> {
        if let Some(entry) = self.mem.get(key) {
            let ffn = Arc::clone(&entry.ffn);
            drop(entry);
            // Touch LRU without holding the map ref across another lock.
            if let Some(mut e) = self.mem.get_mut(key) {
                e.last_tick = self.next_tick();
            }
            return Ok(Some(ffn));
        }
        // Disk-tier promotion.
        let disk = self.disk.get(key).map(|e| e.value().clone());
        if let Some(disk) = disk {
            let blob = std::fs::read(&disk.path)
                .map_err(|e| MoeExecError::DiskTier(format!("{}: {e}", disk.path.display())))?;
            let ffn = Arc::new(ExpertFfn::from_safetensors(&blob)?);
            let bytes = ffn.approx_bytes();
            let tick = self.next_tick();
            self.mem.insert(
                key.clone(),
                MemEntry {
                    ffn: Arc::clone(&ffn),
                    bytes,
                    last_tick: tick,
                },
            );
            self.mem_bytes.fetch_add(bytes, Ordering::Relaxed);
            self.disk.remove(key);
            self.evict_to_budget();
            return Ok(Some(ffn));
        }
        Ok(None)
    }

    /// Warm experts the gate is about to select into the memory tier ahead
    /// of dispatch. Decodes any disk-tier members of `experts`; memory-tier
    /// and absent experts are no-ops. Returns the count promoted from disk.
    pub fn readahead(&self, model_id: &str, experts: &[ExpertId]) -> u32 {
        let mut promoted = 0u32;
        for id in experts {
            let key = ExpertKey {
                model_id: model_id.to_string(),
                layer: id.layer,
                expert: id.expert,
            };
            if self.mem.contains_key(&key) {
                continue;
            }
            if self.disk.contains_key(&key)
                && let Ok(Some(_)) = self.resolve(&key)
            {
                promoted += 1;
            }
        }
        promoted
    }

    /// Drop one expert from both tiers (and its disk blob). Returns `true`
    /// when it was resident on either tier.
    pub fn unload_expert(&self, model_id: &str, layer: u32, expert: u32) -> bool {
        let key = ExpertKey {
            model_id: model_id.to_string(),
            layer,
            expert,
        };
        let mut hit = false;
        if let Some((_, entry)) = self.mem.remove(&key) {
            self.mem_bytes.fetch_sub(entry.bytes, Ordering::Relaxed);
            hit = true;
        }
        if let Some((_, disk)) = self.disk.remove(&key) {
            let _ = std::fs::remove_file(&disk.path);
            hit = true;
        } else if let Some(path) = self.disk_path(&key) {
            // Blob may exist on disk even if it was never evicted (written at
            // load time); clean it up.
            let _ = std::fs::remove_file(&path);
        }
        self.sources.remove(&key);
        hit
    }

    /// Decode and admit one gating-network blob for `(model_id, layer)`.
    pub fn load_gate(
        &self,
        model_id: impl Into<String>,
        layer: u32,
        blob: &[u8],
    ) -> MoeExecResult<MoeLoadedGate> {
        let model_id = model_id.into();
        let gate = GatingNetwork::from_safetensors(blob)?;
        let row = MoeLoadedGate {
            model_id: model_id.clone(),
            layer,
            num_experts: gate.num_experts() as u32,
            d_model: gate.d_model() as u32,
            approx_bytes: gate.approx_bytes(),
        };
        self.gates
            .insert(GateKey { model_id, layer }, Arc::new(gate));
        Ok(row)
    }

    /// Drop one gating network. Returns `true` when it was resident.
    pub fn unload_gate(&self, model_id: &str, layer: u32) -> bool {
        self.gates
            .remove(&GateKey {
                model_id: model_id.to_string(),
                layer,
            })
            .is_some()
    }

    /// Whether the expert is resident on either tier (memory or disk).
    pub fn has_expert(&self, model_id: &str, layer: u32, expert: u32) -> bool {
        let key = ExpertKey {
            model_id: model_id.to_string(),
            layer,
            expert,
        };
        self.mem.contains_key(&key) || self.disk.contains_key(&key)
    }

    /// Run the gating network for `(model_id, layer)` over a flattened
    /// row-major `[n_tokens, d_model]` hidden-state buffer.
    pub fn route(
        &self,
        model_id: &str,
        layer: u32,
        d_model: usize,
        hidden_states: &[f32],
        top_k: usize,
    ) -> MoeExecResult<Vec<RoutedToken>> {
        let gate = self
            .gates
            .get(&GateKey {
                model_id: model_id.to_string(),
                layer,
            })
            .map(|g| Arc::clone(g.value()))
            .ok_or_else(|| MoeExecError::GateNotLoaded {
                model_id: model_id.to_string(),
                layer,
            })?;
        let x = view_hidden(hidden_states, d_model)?;
        Ok(gate.route_batch(layer, x, top_k))
    }

    /// Execute one batched expert-FFN request against a resident expert.
    /// A disk-tier expert is promoted into memory on demand.
    pub fn execute(&self, req: &ExpertExecuteRequest) -> MoeExecResult<ExpertExecuteResponse> {
        let key = ExpertKey {
            model_id: req.model_id.clone(),
            layer: req.layer,
            expert: req.expert,
        };
        let ffn = self.resolve(&key)?.ok_or_else(|| MoeExecError::ExpertNotLoaded {
            model_id: req.model_id.clone(),
            layer: req.layer,
            expert: req.expert,
        })?;

        let d_model = req.d_model as usize;
        if d_model != ffn.d_model() {
            return Err(MoeExecError::DimensionMismatch {
                len: req.hidden_states.len(),
                tokens: req.token_indices.len(),
                d_model,
            });
        }
        let rows = req.materialize_hidden()?;
        let x = view_hidden(&rows, d_model)?;
        if x.nrows() != req.token_indices.len() {
            return Err(MoeExecError::DimensionMismatch {
                len: rows.len(),
                tokens: req.token_indices.len(),
                d_model,
            });
        }

        let y = ffn.forward(x, self.compute.as_ref());
        self.record_served(req.token_indices.len() as u64);
        Ok(ExpertExecuteResponse {
            model_id: req.model_id.clone(),
            layer: req.layer,
            expert: req.expert,
            token_indices: req.token_indices.clone(),
            d_model: req.d_model,
            outputs: y.into_raw_vec_and_offset().0,
            receipt: None,
        })
    }

    /// Fold `tokens` served into the per-minute throughput buckets. On a
    /// minute boundary the current bucket rotates into the previous slot;
    /// skipping a minute (idle host) zeroes the previous slot so stale
    /// throughput never inflates the advertised rate.
    fn record_served(&self, tokens: u64) {
        let minute = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64 / 60_000)
            .unwrap_or(0);
        let mut cur = self.served_bucket_minute.load(Ordering::Acquire);
        while minute > cur {
            match self.served_bucket_minute.compare_exchange(
                cur,
                minute,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let finished = self.served_bucket_tokens.swap(0, Ordering::AcqRel);
                    let prev = if minute == cur + 1 { finished } else { 0 };
                    self.served_prev_tokens.store(prev, Ordering::Release);
                    cur = minute;
                }
                Err(actual) => cur = actual,
            }
        }
        self.served_bucket_tokens.fetch_add(tokens, Ordering::AcqRel);
    }

    /// Measured expert-forward throughput in tokens per second: the larger
    /// of the current and previous minute buckets divided by 60.
    pub fn measured_tps(&self) -> u32 {
        let cur = self.served_bucket_tokens.load(Ordering::Acquire);
        let prev = self.served_prev_tokens.load(Ordering::Acquire);
        (cur.max(prev) / 60).min(u32::MAX as u64) as u32
    }

    /// Snapshot of resident experts and gates across both tiers.
    pub fn status(&self) -> MoeExpertRuntimeStatus {
        let mut experts: Vec<MoeLoadedExpert> = self
            .mem
            .iter()
            .map(|e| MoeLoadedExpert {
                model_id: e.key().model_id.clone(),
                layer: e.key().layer,
                expert: e.key().expert,
                d_model: e.value().ffn.d_model() as u32,
                d_ff: e.value().ffn.d_ff() as u32,
                approx_bytes: e.value().bytes,
                tier: ExpertTier::Memory,
                quant: e.value().ffn.quant_tag().map(str::to_string),
                source_uri: self.sources.get(e.key()).map(|u| u.clone()),
            })
            .collect();
        experts.extend(self.disk.iter().map(|e| MoeLoadedExpert {
            model_id: e.key().model_id.clone(),
            layer: e.key().layer,
            expert: e.key().expert,
            d_model: e.value().d_model,
            d_ff: e.value().d_ff,
            approx_bytes: e.value().approx_bytes,
            tier: ExpertTier::Disk,
            quant: e.value().quant.clone(),
            source_uri: self.sources.get(e.key()).map(|u| u.clone()),
        }));
        experts.sort_by(|a, b| {
            (a.model_id.as_str(), a.layer, a.expert).cmp(&(b.model_id.as_str(), b.layer, b.expert))
        });

        let mut gates: Vec<MoeLoadedGate> = self
            .gates
            .iter()
            .map(|g| MoeLoadedGate {
                model_id: g.key().model_id.clone(),
                layer: g.key().layer,
                num_experts: g.value().num_experts() as u32,
                d_model: g.value().d_model() as u32,
                approx_bytes: g.value().approx_bytes(),
            })
            .collect();
        gates.sort_by(|a, b| (a.model_id.as_str(), a.layer).cmp(&(b.model_id.as_str(), b.layer)));

        let memory_bytes = self.mem_bytes.load(Ordering::Relaxed);
        let gate_bytes = gates.iter().map(|g| g.approx_bytes).sum::<u64>();
        let memory_experts = self.mem.len() as u32;
        let disk_experts = self.disk.len() as u32;

        MoeExpertRuntimeStatus {
            experts,
            gates,
            total_bytes: memory_bytes + gate_bytes,
            memory_bytes,
            memory_budget_bytes: self.memory_budget_bytes,
            memory_experts,
            disk_experts,
            compute_backend: self.compute.tag().to_string(),
            gpu: matches!(self.backend_kind, BackendKind::Cuda | BackendKind::Wgpu),
            evicted_to_disk: self.evicted_to_disk.load(Ordering::Relaxed),
            evicted_dropped: self.evicted_dropped.load(Ordering::Relaxed),
            admissions_over_budget: self.admissions_over_budget.load(Ordering::Relaxed),
            measured_tps: self.measured_tps(),
        }
    }
}

/// Write a blob to `path` atomically (temp file + rename), creating parent
/// directories as needed.
fn write_blob_atomic(path: &Path, blob: &[u8]) -> MoeExecResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| MoeExecError::DiskTier(format!("{}: {e}", parent.display())))?;
    }
    let tmp = path.with_extension("safetensors.tmp");
    let mut f = std::fs::File::create(&tmp)
        .map_err(|e| MoeExecError::DiskTier(format!("{}: {e}", tmp.display())))?;
    f.write_all(blob)
        .map_err(|e| MoeExecError::DiskTier(format!("{}: {e}", tmp.display())))?;
    f.sync_all()
        .map_err(|e| MoeExecError::DiskTier(format!("{}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| MoeExecError::DiskTier(format!("{}: {e}", path.display())))?;
    Ok(())
}

/// Per-projection quant selection for [`quantize_expert_blob`]. A `None`
/// leaves that projection dense `f32`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExpertQuantPlan {
    /// Quant kind for `gate_proj`, or dense when `None`.
    pub gate: Option<QuantKind>,
    /// Quant kind for `up_proj`, or dense when `None`.
    pub up: Option<QuantKind>,
    /// Quant kind for `down_proj`, or dense when `None`.
    pub down: Option<QuantKind>,
}

impl ExpertQuantPlan {
    /// Quantize all three projections to the same kind.
    pub fn uniform(kind: QuantKind) -> Self {
        Self {
            gate: Some(kind),
            up: Some(kind),
            down: Some(kind),
        }
    }

    /// The GGUF Q4_K_M convention: `gate`/`up` at Q4_K, `down` at Q6_K
    /// (down-projection error dominates output quality, so it is kept
    /// higher-precision).
    pub fn q4_k_m() -> Self {
        Self {
            gate: Some(QuantKind::Q4K),
            up: Some(QuantKind::Q4K),
            down: Some(QuantKind::Q6K),
        }
    }

    /// Coarsest (lowest bytes-per-weight) quant tag across the three
    /// projections, matching [`ExpertFfn::quant_tag`]'s ordering
    /// (`q4_k` < `q6_k` < `q8_0`). `None` when every projection is dense.
    pub fn coarsest_tag(&self) -> Option<&'static str> {
        let rank = |k: QuantKind| match k {
            QuantKind::Q4K => 0,
            QuantKind::Q6K => 1,
            QuantKind::Q8_0 => 2,
        };
        [self.gate, self.up, self.down]
            .into_iter()
            .flatten()
            .min_by_key(|k| rank(*k))
            .map(|k| k.tag())
    }
}

/// Re-encode a dense expert blob (three F32/F16/BF16 projections) into a
/// GGUF block-quantized blob per `plan`. Quantized projections become flat
/// `U8` tensors carrying `"<name>.quant"` / `"<name>.shape"` metadata that
/// [`ExpertFfn::from_safetensors`] reads back. Projections whose column
/// width is not a multiple of the kind's block width are left dense.
///
/// This is the holder-side prepare step: a holder can shrink its resident
/// footprint before admitting an expert, or a prepare job can publish
/// quantized blobs directly.
pub fn quantize_expert_blob(dense_blob: &[u8], plan: ExpertQuantPlan) -> MoeExecResult<Vec<u8>> {
    let st = SafeTensors::deserialize(dense_blob)
        .map_err(|e| MoeExecError::Parse(e.to_string()))?;
    let gate = tensor_to_f32_matrix(TENSOR_GATE_PROJ, &required_tensor(&st, TENSOR_GATE_PROJ)?)?;
    let up = tensor_to_f32_matrix(TENSOR_UP_PROJ, &required_tensor(&st, TENSOR_UP_PROJ)?)?;
    let down = tensor_to_f32_matrix(TENSOR_DOWN_PROJ, &required_tensor(&st, TENSOR_DOWN_PROJ)?)?;

    // Encode each projection to either a dense F32 byte blob or quantized
    // block bytes, recording metadata for the quantized ones. Byte buffers
    // must outlive the TensorView borrows, so collect them first.
    struct Encoded {
        name: &'static str,
        dtype: Dtype,
        shape: Vec<usize>,
        bytes: Vec<u8>,
        quant: Option<QuantKind>,
    }
    fn encode(name: &'static str, w: &Array2<f32>, kind: Option<QuantKind>) -> Encoded {
        let (rows, cols) = (w.nrows(), w.ncols());
        let flat: Vec<f32> = w.iter().copied().collect();
        match kind.filter(|k| cols % k.block_width() == 0) {
            Some(k) => {
                let q = QuantMatrix::quantize(k, rows, cols, &flat)
                    .expect("block-aligned quantize cannot fail");
                Encoded {
                    name,
                    dtype: Dtype::U8,
                    // A quantized tensor is a flat 1-D byte payload; the
                    // logical [rows, cols] rides in metadata.
                    shape: vec![q.approx_bytes() as usize],
                    bytes: q.into_block_bytes(),
                    quant: Some(k),
                }
            }
            None => {
                let mut bytes = Vec::with_capacity(flat.len() * 4);
                for x in &flat {
                    bytes.extend_from_slice(&x.to_le_bytes());
                }
                Encoded {
                    name,
                    dtype: Dtype::F32,
                    shape: vec![rows, cols],
                    bytes,
                    quant: None,
                }
            }
        }
    }

    let encoded = [
        encode(TENSOR_GATE_PROJ, &gate, plan.gate),
        encode(TENSOR_UP_PROJ, &up, plan.up),
        encode(TENSOR_DOWN_PROJ, &down, plan.down),
    ];

    let mut metadata: HashMap<String, String> = HashMap::new();
    let logical = [
        (TENSOR_GATE_PROJ, gate.nrows(), gate.ncols()),
        (TENSOR_UP_PROJ, up.nrows(), up.ncols()),
        (TENSOR_DOWN_PROJ, down.nrows(), down.ncols()),
    ];
    for (e, (_, r, c)) in encoded.iter().zip(logical.iter()) {
        if let Some(k) = e.quant {
            metadata.insert(format!("{}{META_QUANT_SUFFIX}", e.name), k.tag().to_string());
            metadata.insert(format!("{}{META_SHAPE_SUFFIX}", e.name), format!("{r},{c}"));
        }
    }

    let views: Vec<(&str, TensorView<'_>)> = encoded
        .iter()
        .map(|e| {
            let v = TensorView::new(e.dtype, e.shape.clone(), &e.bytes)
                .map_err(|err| MoeExecError::Parse(format!("{}: {err:?}", e.name)))?;
            Ok((e.name, v))
        })
        .collect::<MoeExecResult<_>>()?;

    let meta_opt = if metadata.is_empty() { None } else { Some(metadata) };
    safetensors::serialize(views, meta_opt)
        .map_err(|e| MoeExecError::Parse(format!("serialize quantized expert blob: {e:?}")))
}

fn view_hidden(hidden: &[f32], d_model: usize) -> MoeExecResult<ArrayView2<'_, f32>> {
    if hidden.is_empty() {
        return Err(MoeExecError::EmptyBatch);
    }
    if d_model == 0 || !hidden.len().is_multiple_of(d_model) {
        return Err(MoeExecError::DimensionMismatch {
            len: hidden.len(),
            tokens: hidden.len().checked_div(d_model).unwrap_or(0),
            d_model,
        });
    }
    let n = hidden.len() / d_model;
    ArrayView2::from_shape((n, d_model), hidden).map_err(|e| MoeExecError::Parse(e.to_string()))
}

// ---------------------------------------------------------------------------
// Gather-side combine
// ---------------------------------------------------------------------------

/// Reassemble per-token outputs from holder responses: for every routed
/// token, the combined output is the gate-weighted sum of its experts'
/// FFN outputs. Returns a row-major `[routed.len(), d_model]` buffer in
/// `routed` order.
///
/// Errors with [`MoeExecError::MissingContribution`] when any
/// `(expert, token)` pair selected by the gate has no output row in
/// `responses` — the caller decides whether to replan or fail the
/// request.
pub fn combine_expert_outputs(
    d_model: usize,
    routed: &[RoutedToken],
    responses: &[ExpertExecuteResponse],
) -> MoeExecResult<Vec<f32>> {
    if routed.is_empty() {
        return Err(MoeExecError::EmptyBatch);
    }

    // (expert, token_index) -> output row.
    let mut rows: HashMap<(ExpertId, u32), &[f32]> = HashMap::new();
    for resp in responses {
        let dm = resp.d_model as usize;
        if dm != d_model || resp.outputs.len() != resp.token_indices.len() * dm {
            return Err(MoeExecError::DimensionMismatch {
                len: resp.outputs.len(),
                tokens: resp.token_indices.len(),
                d_model,
            });
        }
        let expert = ExpertId::new(resp.layer, resp.expert);
        for (i, &tok) in resp.token_indices.iter().enumerate() {
            rows.insert((expert, tok), &resp.outputs[i * dm..(i + 1) * dm]);
        }
    }

    let mut combined = vec![0.0f32; routed.len() * d_model];
    for (row_idx, token) in routed.iter().enumerate() {
        let out = &mut combined[row_idx * d_model..(row_idx + 1) * d_model];
        for slot in &token.slots {
            let contribution = rows.get(&(slot.expert, token.token_index)).ok_or(
                MoeExecError::MissingContribution {
                    token_index: token.token_index,
                    layer: slot.expert.layer,
                    expert: slot.expert.expert,
                },
            )?;
            for (o, c) in out.iter_mut().zip(contribution.iter()) {
                *o += slot.weight * c;
            }
        }
    }
    Ok(combined)
}

/// Incremental gate-weighted combiner for pipelined dispatch.
///
/// [`combine_expert_outputs`] gathers all holder responses in one pass —
/// it must wait for every batch to return before any accumulation runs.
/// On a permissionless WAN batch RTTs are 30–150 ms and vary widely
/// between holders, so a router that blocks on the slowest batch leaves
/// the CPU idle while faster batches sit in a buffer.
///
/// `MoeCombiner` lets the router accumulate each holder response the
/// moment it arrives (fed from a `FuturesUnordered` stream), overlapping
/// the gate-weighted gather with still-in-flight batches. Each expected
/// `(expert, token)` contribution is counted at construction from the
/// routing decision; [`MoeCombiner::finish`] fails with
/// [`MoeExecError::MissingContribution`] when any expected contribution
/// never arrived.
pub struct MoeCombiner {
    d_model: usize,
    combined: Vec<f32>,
    /// token_index -> row index in `combined` (routed order).
    row_of_token: HashMap<u32, usize>,
    /// (expert, token) -> gate weight for that slot.
    weight_of: HashMap<(ExpertId, u32), f32>,
    /// (expert, token) pairs still awaited. Drained as responses arrive.
    outstanding: std::collections::HashSet<(ExpertId, u32)>,
}

impl MoeCombiner {
    /// Prepare a combiner for a routed batch. Precomputes the token
    /// layout and the set of `(expert, token)` contributions the gate
    /// expects, so [`accumulate`](Self::accumulate) is O(response rows)
    /// and [`finish`](Self::finish) is O(1) in the common (complete) case.
    pub fn new(d_model: usize, routed: &[RoutedToken]) -> MoeExecResult<Self> {
        if routed.is_empty() {
            return Err(MoeExecError::EmptyBatch);
        }
        let mut row_of_token = HashMap::with_capacity(routed.len());
        let mut weight_of = HashMap::new();
        let mut outstanding = std::collections::HashSet::new();
        for (row_idx, token) in routed.iter().enumerate() {
            row_of_token.insert(token.token_index, row_idx);
            for slot in &token.slots {
                weight_of.insert((slot.expert, token.token_index), slot.weight);
                outstanding.insert((slot.expert, token.token_index));
            }
        }
        Ok(Self {
            d_model,
            combined: vec![0.0f32; routed.len() * d_model],
            row_of_token,
            weight_of,
            outstanding,
        })
    }

    /// Fold one holder response into the running combined buffer. Only
    /// `(expert, token)` pairs the gate actually selected are applied;
    /// rows for tokens or experts not in the routing are ignored (a
    /// holder cannot corrupt tokens it was not routed). Returns a
    /// dimension error when the response shape is inconsistent.
    pub fn accumulate(&mut self, resp: &ExpertExecuteResponse) -> MoeExecResult<()> {
        let dm = resp.d_model as usize;
        if dm != self.d_model || resp.outputs.len() != resp.token_indices.len() * dm {
            return Err(MoeExecError::DimensionMismatch {
                len: resp.outputs.len(),
                tokens: resp.token_indices.len(),
                d_model: self.d_model,
            });
        }
        let expert = ExpertId::new(resp.layer, resp.expert);
        for (i, &tok) in resp.token_indices.iter().enumerate() {
            let key = (expert, tok);
            let Some(&weight) = self.weight_of.get(&key) else {
                continue;
            };
            let Some(&row_idx) = self.row_of_token.get(&tok) else {
                continue;
            };
            let contribution = &resp.outputs[i * dm..(i + 1) * dm];
            let out = &mut self.combined[row_idx * dm..(row_idx + 1) * dm];
            for (o, c) in out.iter_mut().zip(contribution.iter()) {
                *o += weight * c;
            }
            self.outstanding.remove(&key);
        }
        Ok(())
    }

    /// Finalize: consumes the combiner and returns the row-major
    /// `[routed.len(), d_model]` buffer. Fails with
    /// [`MoeExecError::MissingContribution`] when any gate-selected
    /// `(expert, token)` contribution never arrived.
    pub fn finish(self) -> MoeExecResult<Vec<f32>> {
        if let Some((expert, token_index)) = self.outstanding.into_iter().next() {
            return Err(MoeExecError::MissingContribution {
                token_index,
                layer: expert.layer,
                expert: expert.expert,
            });
        }
        Ok(self.combined)
    }

    /// Finalize tolerating missing contributions. Each token whose slots
    /// only partially arrived is renormalized: the accumulated row is
    /// scaled by `total_selected_weight / arrived_weight`, so the combined
    /// output keeps the gate's magnitude despite the absent experts. Fails
    /// with [`MoeExecError::MissingContribution`] only when a token
    /// received no contribution at all — there is nothing to renormalize.
    pub fn finish_partial(mut self) -> MoeExecResult<PartialCombine> {
        if self.outstanding.is_empty() {
            return Ok(PartialCombine {
                outputs: self.combined,
                missing: Vec::new(),
            });
        }

        let mut total_weight: HashMap<u32, f32> = HashMap::new();
        for (&(_, tok), &w) in &self.weight_of {
            *total_weight.entry(tok).or_insert(0.0) += w;
        }
        let mut missing_weight: HashMap<u32, f32> = HashMap::new();
        for key in &self.outstanding {
            let w = self.weight_of.get(key).copied().unwrap_or(0.0);
            *missing_weight.entry(key.1).or_insert(0.0) += w;
        }

        for (&tok, &miss) in &missing_weight {
            let total = total_weight.get(&tok).copied().unwrap_or(0.0);
            let arrived = total - miss;
            if arrived <= 0.0 {
                let (expert, token_index) = self
                    .outstanding
                    .iter()
                    .find(|(_, t)| *t == tok)
                    .copied()
                    .expect("token with missing weight has an outstanding slot");
                return Err(MoeExecError::MissingContribution {
                    token_index,
                    layer: expert.layer,
                    expert: expert.expert,
                });
            }
            let scale = total / arrived;
            if let Some(&row_idx) = self.row_of_token.get(&tok) {
                let out =
                    &mut self.combined[row_idx * self.d_model..(row_idx + 1) * self.d_model];
                for o in out.iter_mut() {
                    *o *= scale;
                }
            }
        }

        let mut missing: Vec<(ExpertId, u32)> = self.outstanding.into_iter().collect();
        missing.sort_by_key(|&(e, t)| (e.layer, e.expert, t));
        Ok(PartialCombine {
            outputs: self.combined,
            missing,
        })
    }
}

/// Result of [`MoeCombiner::finish_partial`]: the combined buffer plus the
/// `(expert, token)` contributions that never arrived and were renormalized
/// around.
#[derive(Debug, Clone, PartialEq)]
pub struct PartialCombine {
    /// Row-major `[routed.len(), d_model]` combined hidden states.
    pub outputs: Vec<f32>,
    /// Gate-selected `(expert, token)` pairs with no contribution, sorted by
    /// `(layer, expert, token)`.
    pub missing: Vec<(ExpertId, u32)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use safetensors::serialize;

    fn f32_bytes(values: &[f32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn expert_blob(d_model: usize, d_ff: usize, gate: &[f32], up: &[f32], down: &[f32]) -> Vec<u8> {
        let gate_b = f32_bytes(gate);
        let up_b = f32_bytes(up);
        let down_b = f32_bytes(down);
        let tensors = vec![
            (
                TENSOR_GATE_PROJ,
                TensorView::new(Dtype::F32, vec![d_ff, d_model], &gate_b).unwrap(),
            ),
            (
                TENSOR_UP_PROJ,
                TensorView::new(Dtype::F32, vec![d_ff, d_model], &up_b).unwrap(),
            ),
            (
                TENSOR_DOWN_PROJ,
                TensorView::new(Dtype::F32, vec![d_model, d_ff], &down_b).unwrap(),
            ),
        ];
        serialize(tensors, None).unwrap()
    }

    fn router_blob(num_experts: usize, d_model: usize, weight: &[f32]) -> Vec<u8> {
        let w = f32_bytes(weight);
        let tensors = vec![(
            TENSOR_ROUTER,
            TensorView::new(Dtype::F32, vec![num_experts, d_model], &w).unwrap(),
        )];
        serialize(tensors, None).unwrap()
    }

    // ---- expert FFN ----

    #[test]
    fn swiglu_forward_matches_hand_computation() {
        // d_model = 2, d_ff = 2. Identity-ish weights so the math stays
        // hand-checkable.
        //   W_g = [[1, 0], [0, 1]], W_u = [[2, 0], [0, 2]],
        //   W_d = [[1, 0], [0, 1]]
        // x = [1, -1]:
        //   g = silu([1, -1]) = [0.7310586, -0.2689414]
        //   u = [2, -2]
        //   h = g * u = [1.4621172, 0.5378828]
        //   y = h (W_d = I)
        let blob = expert_blob(
            2,
            2,
            &[1.0, 0.0, 0.0, 1.0],
            &[2.0, 0.0, 0.0, 2.0],
            &[1.0, 0.0, 0.0, 1.0],
        );
        let ffn = ExpertFfn::from_safetensors(&blob).unwrap();
        assert_eq!(ffn.d_model(), 2);
        assert_eq!(ffn.d_ff(), 2);
        let x = Array2::from_shape_vec((1, 2), vec![1.0, -1.0]).unwrap();
        let cpu = crate::moe_compute::CpuCompute::detect();
        let y = ffn.forward(x.view(), &cpu);
        assert!((y[[0, 0]] - 1.4621172).abs() < 1e-5, "{}", y[[0, 0]]);
        assert!((y[[0, 1]] - 0.5378828).abs() < 1e-5, "{}", y[[0, 1]]);
    }

    #[test]
    fn forward_batches_rows_independently() {
        let blob = expert_blob(
            2,
            2,
            &[1.0, 0.0, 0.0, 1.0],
            &[1.0, 0.0, 0.0, 1.0],
            &[1.0, 0.0, 0.0, 1.0],
        );
        let ffn = ExpertFfn::from_safetensors(&blob).unwrap();
        let cpu = crate::moe_compute::CpuCompute::detect();
        let single = ffn.forward(
            Array2::from_shape_vec((1, 2), vec![0.5, 2.0])
                .unwrap()
                .view(),
            &cpu,
        );
        let batch = ffn.forward(
            Array2::from_shape_vec((2, 2), vec![0.5, 2.0, 0.5, 2.0])
                .unwrap()
                .view(),
            &cpu,
        );
        for c in 0..2 {
            assert_eq!(single[[0, c]], batch[[0, c]]);
            assert_eq!(single[[0, c]], batch[[1, c]]);
        }
    }

    #[test]
    fn quantized_blob_round_trips_and_reports_tag() {
        // d_model = d_ff = 32 so every projection is a whole Q8_0 block
        // (block width 32). Deterministic small weights keep the quant
        // error bounded and the forward output close to the dense pass.
        let dm = 32usize;
        let df = 32usize;
        let mk = |seed: f32| -> Vec<f32> {
            (0..dm * df)
                .map(|i| ((i as f32 * 0.013 + seed).sin()) * 0.2)
                .collect()
        };
        let gate = mk(0.1);
        let up = mk(0.7);
        let down = mk(1.3);
        let dense_blob = expert_blob(dm, df, &gate, &up, &down);

        let dense_ffn = ExpertFfn::from_safetensors(&dense_blob).unwrap();
        assert_eq!(dense_ffn.quant_tag(), None);

        // Uniform Q8_0 across all three projections.
        let q_blob = quantize_expert_blob(&dense_blob, ExpertQuantPlan::uniform(QuantKind::Q8_0))
            .expect("quantize");
        let q_ffn = ExpertFfn::from_safetensors(&q_blob).unwrap();
        assert_eq!(q_ffn.quant_tag(), Some("q8_0"));
        assert_eq!(q_ffn.d_model(), dm);
        assert_eq!(q_ffn.d_ff(), df);
        // Quantized blob is materially smaller than the dense one.
        assert!(
            q_blob.len() < dense_blob.len(),
            "quantized {} !< dense {}",
            q_blob.len(),
            dense_blob.len()
        );

        // Forward outputs agree to within Q8_0 error tolerance.
        let x = Array2::from_shape_fn((2, dm), |(r, c)| ((r * dm + c) as f32 * 0.01).cos() * 0.5);
        let cpu = crate::moe_compute::CpuCompute::detect();
        let y_dense = dense_ffn.forward(x.view(), &cpu);
        let y_quant = q_ffn.forward(x.view(), &cpu);
        assert_eq!(y_dense.dim(), y_quant.dim());
        for (d, q) in y_dense.iter().zip(y_quant.iter()) {
            assert!(
                (d - q).abs() < 5e-2,
                "dense {d} vs quant {q} exceeds tolerance"
            );
        }
    }

    #[test]
    fn mixed_dense_quant_plan_tags_coarsest() {
        // gate/up quantized, down left dense: coarsest tag is q4_k... but
        // 32-wide rows are not Q4_K-block-aligned (block width 256), so the
        // plan falls back to dense for those and yields a fully dense blob.
        // Use Q8_0 (block width 32) for the quantized legs instead.
        let dm = 32usize;
        let df = 32usize;
        let flat: Vec<f32> = (0..dm * df).map(|i| (i as f32 * 0.001).sin()).collect();
        let dense_blob = expert_blob(dm, df, &flat, &flat, &flat);
        let plan = ExpertQuantPlan {
            gate: Some(QuantKind::Q8_0),
            up: Some(QuantKind::Q8_0),
            down: None,
        };
        assert_eq!(plan.coarsest_tag(), Some("q8_0"));
        let q_blob = quantize_expert_blob(&dense_blob, plan).expect("quantize");
        let q_ffn = ExpertFfn::from_safetensors(&q_blob).unwrap();
        // At least one projection is quantized, so the expert reports a tag.
        assert_eq!(q_ffn.quant_tag(), Some("q8_0"));
    }

    #[test]
    fn blob_with_missing_tensor_is_rejected() {
        let w = f32_bytes(&[1.0, 0.0, 0.0, 1.0]);
        let tensors = vec![(
            TENSOR_GATE_PROJ,
            TensorView::new(Dtype::F32, vec![2, 2], &w).unwrap(),
        )];
        let blob = serialize(tensors, None).unwrap();
        let err = ExpertFfn::from_safetensors(&blob).unwrap_err();
        assert!(matches!(err, MoeExecError::TensorMissing { name } if name == TENSOR_UP_PROJ));
    }

    #[test]
    fn blob_with_mismatched_shapes_is_rejected() {
        // down_proj is [d_ff, d_model] instead of the required transpose.
        let gate = f32_bytes(&[1.0; 6]);
        let up = f32_bytes(&[1.0; 6]);
        let down = f32_bytes(&[1.0; 6]);
        let tensors = vec![
            (
                TENSOR_GATE_PROJ,
                TensorView::new(Dtype::F32, vec![3, 2], &gate).unwrap(),
            ),
            (
                TENSOR_UP_PROJ,
                TensorView::new(Dtype::F32, vec![3, 2], &up).unwrap(),
            ),
            (
                TENSOR_DOWN_PROJ,
                TensorView::new(Dtype::F32, vec![3, 2], &down).unwrap(),
            ),
        ];
        let blob = serialize(tensors, None).unwrap();
        let err = ExpertFfn::from_safetensors(&blob).unwrap_err();
        assert!(matches!(err, MoeExecError::BadShape { name, .. } if name == TENSOR_DOWN_PROJ));
    }

    #[test]
    fn f16_and_bf16_tensors_decode() {
        let vals = [1.0f32, -0.5, 0.25, 2.0];
        let f16_b: Vec<u8> = vals
            .iter()
            .flat_map(|v| half::f16::from_f32(*v).to_le_bytes())
            .collect();
        let bf16_b: Vec<u8> = vals
            .iter()
            .flat_map(|v| half::bf16::from_f32(*v).to_le_bytes())
            .collect();

        let f16_view = TensorView::new(Dtype::F16, vec![2, 2], &f16_b).unwrap();
        let bf16_view = TensorView::new(Dtype::BF16, vec![2, 2], &bf16_b).unwrap();

        let m16 = tensor_to_f32_matrix("t", &f16_view).unwrap();
        let mb16 = tensor_to_f32_matrix("t", &bf16_view).unwrap();
        for (i, v) in vals.iter().enumerate() {
            assert!((m16[[i / 2, i % 2]] - v).abs() < 1e-2);
            assert!((mb16[[i / 2, i % 2]] - v).abs() < 1e-1);
        }
    }

    // ---- gating ----

    #[test]
    fn gate_top_k_selects_and_renormalizes() {
        // 3 experts, d_model = 2. Rows crafted so h = [1, 0] gives
        // logits [2, 1, -1] → top-2 = experts 0, 1 with softmax(2, 1).
        let blob = router_blob(3, 2, &[2.0, 0.0, 1.0, 0.0, -1.0, 0.0]);
        let gate = GatingNetwork::from_safetensors(&blob).unwrap();
        assert_eq!(gate.num_experts(), 3);
        let h = Array1::from_vec(vec![1.0f32, 0.0]);
        let routed = gate.route(h.view(), 2);
        assert_eq!(routed.len(), 2);
        assert_eq!(routed[0].0, 0);
        assert_eq!(routed[1].0, 1);
        let e = std::f32::consts::E;
        let expect0 = e / (e + 1.0); // softmax(2,1)[0] = e^1/(e^1+e^0) after max-subtract
        assert!((routed[0].1 - expect0).abs() < 1e-5, "{}", routed[0].1);
        assert!((routed[0].1 + routed[1].1 - 1.0).abs() < 1e-6);
    }

    #[test]
    fn route_batch_indexes_tokens_and_projects_to_token_routing() {
        let blob = router_blob(2, 2, &[1.0, 0.0, 0.0, 1.0]);
        let gate = GatingNetwork::from_safetensors(&blob).unwrap();
        // Token 0 favors expert 0; token 1 favors expert 1.
        let hidden =
            Array2::from_shape_vec((2, 2), vec![1.0f32, 0.0, 0.0, 1.0]).unwrap();
        let routed = gate.route_batch(5, hidden.view(), 1);
        assert_eq!(routed.len(), 2);
        assert_eq!(routed[0].slots[0].expert, ExpertId::new(5, 0));
        assert_eq!(routed[1].slots[0].expert, ExpertId::new(5, 1));

        let plans = to_token_routing(&routed);
        assert_eq!(plans[0].token_index, 0);
        assert_eq!(plans[0].experts, vec![ExpertId::new(5, 0)]);
        assert_eq!(plans[1].experts, vec![ExpertId::new(5, 1)]);
    }

    fn sigmoid_router_blob(
        num_experts: usize,
        d_model: usize,
        weight: &[f32],
        bias: &[f32],
        scale: f32,
        shared: u32,
    ) -> Vec<u8> {
        let w = f32_bytes(weight);
        let b = f32_bytes(bias);
        let tensors = vec![
            (
                TENSOR_ROUTER,
                TensorView::new(Dtype::F32, vec![num_experts, d_model], &w).unwrap(),
            ),
            (
                TENSOR_ROUTER_BIAS,
                TensorView::new(Dtype::F32, vec![num_experts], &b).unwrap(),
            ),
        ];
        let meta = HashMap::from([
            (META_ROUTED_SCALING_FACTOR.to_string(), scale.to_string()),
            (META_SHARED_EXPERTS.to_string(), shared.to_string()),
        ]);
        serialize(tensors, Some(meta)).unwrap()
    }

    #[test]
    fn sigmoid_gate_bias_steers_selection_not_weights() {
        // 3 experts, d_model = 1, h = [1] → logits [2, 1, 0] →
        // sigmoid scores [0.8808, 0.7311, 0.5]. Bias [0, 0, 1] pushes
        // expert 2's selection key to 1.5, above expert 1's 0.7311 —
        // top-2 selection = experts 0 and 2. Combine weights renormalize
        // the raw scores 0.8808 / 0.5 (bias excluded) and scale by 2.5.
        let blob = sigmoid_router_blob(3, 1, &[2.0, 1.0, 0.0], &[0.0, 0.0, 1.0], 2.5, 0);
        let gate = GatingNetwork::from_safetensors(&blob).unwrap();
        assert_eq!(gate.num_experts(), 3);
        let h = Array1::from_vec(vec![1.0f32]);
        let routed = gate.route(h.view(), 2);
        assert_eq!(routed.len(), 2);
        assert_eq!(routed[0].0, 0);
        assert_eq!(routed[1].0, 2);
        let s0 = 1.0 / (1.0 + (-2.0f32).exp());
        let s2 = 0.5f32;
        let sum = s0 + s2;
        assert!((routed[0].1 - s0 / sum * 2.5).abs() < 1e-5, "{}", routed[0].1);
        assert!((routed[1].1 - s2 / sum * 2.5).abs() < 1e-5, "{}", routed[1].1);
    }

    #[test]
    fn route_batch_appends_shared_expert_slot() {
        let blob = sigmoid_router_blob(2, 1, &[1.0, -1.0], &[0.0, 0.0], 1.0, 1);
        let gate = GatingNetwork::from_safetensors(&blob).unwrap();
        let hidden = Array2::from_shape_vec((1, 1), vec![1.0f32]).unwrap();
        let routed = gate.route_batch(3, hidden.view(), 1);
        assert_eq!(routed[0].slots.len(), 2);
        assert_eq!(routed[0].slots[0].expert, ExpertId::new(3, 0));
        // Fused shared expert rides at index num_experts with weight 1.0.
        assert_eq!(routed[0].slots[1].expert, ExpertId::new(3, 2));
        assert_eq!(routed[0].slots[1].weight, 1.0);
    }

    #[test]
    fn softmax_gate_ignores_deepseek_metadata_defaults() {
        // A plain Qwen-layout blob parses with the sigmoid machinery off.
        let blob = router_blob(2, 2, &[1.0, 0.0, 0.0, 1.0]);
        let gate = GatingNetwork::from_safetensors(&blob).unwrap();
        let hidden = Array2::from_shape_vec((1, 2), vec![1.0f32, 0.0]).unwrap();
        let routed = gate.route_batch(0, hidden.view(), 1);
        assert_eq!(routed[0].slots.len(), 1);
        assert_eq!(routed[0].slots[0].expert, ExpertId::new(0, 0));
    }

    #[test]
    fn router_bias_length_mismatch_rejected() {
        let w = f32_bytes(&[1.0, 0.0, 0.0, 1.0]);
        let b = f32_bytes(&[0.5]);
        let tensors = vec![
            (
                TENSOR_ROUTER,
                TensorView::new(Dtype::F32, vec![2, 2], &w).unwrap(),
            ),
            (
                TENSOR_ROUTER_BIAS,
                TensorView::new(Dtype::F32, vec![1], &b).unwrap(),
            ),
        ];
        let blob = serialize(tensors, None).unwrap();
        let err = GatingNetwork::from_safetensors(&blob).unwrap_err();
        assert!(matches!(err, MoeExecError::BadShape { .. }));
    }

    // ---- runtime ----

    fn identity_expert_blob(scale: f32) -> Vec<u8> {
        // gate = I so silu applies; up = scale·I; down = I.
        expert_blob(
            2,
            2,
            &[1.0, 0.0, 0.0, 1.0],
            &[scale, 0.0, 0.0, scale],
            &[1.0, 0.0, 0.0, 1.0],
        )
    }

    #[test]
    fn runtime_load_execute_unload_cycle() {
        let rt = MoeExpertRuntime::new();
        let row = rt.load_expert("qwen", 0, 1, &identity_expert_blob(1.0), None).unwrap();
        assert_eq!(row.d_model, 2);
        assert!(rt.has_expert("qwen", 0, 1));

        let req = ExpertExecuteRequest {
            model_id: "qwen".into(),
            layer: 0,
            expert: 1,
            token_indices: vec![7, 9],
            d_model: 2,
            hidden_states: vec![1.0, -1.0, 0.0, 2.0],
            hidden_q8: None,
        };
        let resp = rt.execute(&req).unwrap();
        assert_eq!(resp.token_indices, vec![7, 9]);
        assert_eq!(resp.outputs.len(), 4);

        assert!(rt.unload_expert("qwen", 0, 1));
        assert!(!rt.has_expert("qwen", 0, 1));
        let err = rt.execute(&req).unwrap_err();
        assert!(matches!(err, MoeExecError::ExpertNotLoaded { .. }));
    }

    #[test]
    fn execute_rejects_bad_dimensions() {
        let rt = MoeExpertRuntime::new();
        rt.load_expert("qwen", 0, 1, &identity_expert_blob(1.0), None).unwrap();

        // d_model mismatch vs loaded expert.
        let err = rt
            .execute(&ExpertExecuteRequest {
                model_id: "qwen".into(),
                layer: 0,
                expert: 1,
                token_indices: vec![0],
                d_model: 4,
                hidden_states: vec![0.0; 4],
                hidden_q8: None,
            })
            .unwrap_err();
        assert!(matches!(err, MoeExecError::DimensionMismatch { .. }));

        // token count doesn't match row count.
        let err = rt
            .execute(&ExpertExecuteRequest {
                model_id: "qwen".into(),
                layer: 0,
                expert: 1,
                token_indices: vec![0, 1, 2],
                d_model: 2,
                hidden_states: vec![0.5; 4],
                hidden_q8: None,
            })
            .unwrap_err();
        assert!(matches!(err, MoeExecError::DimensionMismatch { .. }));

        // empty batch.
        let err = rt
            .execute(&ExpertExecuteRequest {
                model_id: "qwen".into(),
                layer: 0,
                expert: 1,
                token_indices: vec![],
                d_model: 2,
                hidden_states: vec![],
                hidden_q8: None,
            })
            .unwrap_err();
        assert!(matches!(err, MoeExecError::EmptyBatch));
    }

    #[test]
    fn runtime_routes_via_loaded_gate() {
        let rt = MoeExpertRuntime::new();
        let err = rt.route("qwen", 0, 2, &[1.0, 0.0], 1).unwrap_err();
        assert!(matches!(err, MoeExecError::GateNotLoaded { .. }));

        rt.load_gate("qwen", 0, &router_blob(2, 2, &[1.0, 0.0, 0.0, 1.0]))
            .unwrap();
        let routed = rt.route("qwen", 0, 2, &[1.0, 0.0], 1).unwrap();
        assert_eq!(routed.len(), 1);
        assert_eq!(routed[0].slots[0].expert, ExpertId::new(0, 0));

        assert!(rt.unload_gate("qwen", 0));
        assert!(!rt.unload_gate("qwen", 0));
    }

    #[test]
    fn status_reports_resident_state() {
        let rt = MoeExpertRuntime::new();
        rt.load_expert("qwen", 0, 1, &identity_expert_blob(1.0), None).unwrap();
        rt.load_expert("qwen", 0, 2, &identity_expert_blob(2.0), None).unwrap();
        rt.load_gate("qwen", 0, &router_blob(2, 2, &[1.0, 0.0, 0.0, 1.0]))
            .unwrap();

        let status = rt.status();
        assert_eq!(status.experts.len(), 2);
        assert_eq!(status.gates.len(), 1);
        assert_eq!(status.experts[0].expert, 1);
        assert_eq!(status.experts[1].expert, 2);
        // 3 matrices x 4 values x 4 bytes per expert + 4 values x 4 bytes gate.
        assert_eq!(status.total_bytes, 2 * 48 + 16);
    }

    // ---- combine ----

    #[test]
    fn combine_weights_expert_outputs_per_token() {
        let routed = vec![RoutedToken {
            token_index: 0,
            slots: vec![
                RoutedSlot {
                    expert: ExpertId::new(0, 1),
                    weight: 0.75,
                },
                RoutedSlot {
                    expert: ExpertId::new(0, 2),
                    weight: 0.25,
                },
            ],
        }];
        let responses = vec![
            ExpertExecuteResponse {
                model_id: "qwen".into(),
                layer: 0,
                expert: 1,
                token_indices: vec![0],
                d_model: 2,
                outputs: vec![4.0, 8.0],
                receipt: None,
            },
            ExpertExecuteResponse {
                model_id: "qwen".into(),
                layer: 0,
                expert: 2,
                token_indices: vec![0],
                d_model: 2,
                outputs: vec![-4.0, 0.0],
                receipt: None,
            },
        ];
        let combined = combine_expert_outputs(2, &routed, &responses).unwrap();
        // 0.75*4 + 0.25*(-4) = 2.0 ; 0.75*8 + 0.25*0 = 6.0
        assert_eq!(combined, vec![2.0, 6.0]);
    }

    #[test]
    fn combine_errors_on_missing_contribution() {
        let routed = vec![RoutedToken {
            token_index: 3,
            slots: vec![RoutedSlot {
                expert: ExpertId::new(1, 7),
                weight: 1.0,
            }],
        }];
        let err = combine_expert_outputs(2, &routed, &[]).unwrap_err();
        assert_eq!(
            err,
            MoeExecError::MissingContribution {
                token_index: 3,
                layer: 1,
                expert: 7,
            }
        );
    }

    #[test]
    fn incremental_combiner_matches_batch_combine() {
        let routed = vec![RoutedToken {
            token_index: 0,
            slots: vec![
                RoutedSlot {
                    expert: ExpertId::new(0, 1),
                    weight: 0.75,
                },
                RoutedSlot {
                    expert: ExpertId::new(0, 2),
                    weight: 0.25,
                },
            ],
        }];
        let responses = vec![
            ExpertExecuteResponse {
                model_id: "qwen".into(),
                layer: 0,
                expert: 1,
                token_indices: vec![0],
                d_model: 2,
                outputs: vec![4.0, 8.0],
                receipt: None,
            },
            ExpertExecuteResponse {
                model_id: "qwen".into(),
                layer: 0,
                expert: 2,
                token_indices: vec![0],
                d_model: 2,
                outputs: vec![-4.0, 0.0],
                receipt: None,
            },
        ];
        // Feed responses out of routed order — order must not matter.
        let mut combiner = MoeCombiner::new(2, &routed).unwrap();
        combiner.accumulate(&responses[1]).unwrap();
        combiner.accumulate(&responses[0]).unwrap();
        let combined = combiner.finish().unwrap();
        assert_eq!(combined, vec![2.0, 6.0]);
        assert_eq!(combined, combine_expert_outputs(2, &routed, &responses).unwrap());
    }

    #[test]
    fn incremental_combiner_finish_errors_on_missing_contribution() {
        let routed = vec![RoutedToken {
            token_index: 3,
            slots: vec![RoutedSlot {
                expert: ExpertId::new(1, 7),
                weight: 1.0,
            }],
        }];
        // Nothing accumulated → finish must report the awaited slot.
        let err = MoeCombiner::new(2, &routed).unwrap().finish().unwrap_err();
        assert_eq!(
            err,
            MoeExecError::MissingContribution {
                token_index: 3,
                layer: 1,
                expert: 7,
            }
        );
    }

    #[test]
    fn finish_partial_renormalizes_missing_slot() {
        // Token 0 selected experts (0,1) w=0.75 and (0,2) w=0.25; only
        // expert 1 responds. The arrived accumulation is 0.75*[4,8] =
        // [3,6]; renormalization scales by 1.0/0.75 → [4,8].
        let routed = vec![RoutedToken {
            token_index: 0,
            slots: vec![
                RoutedSlot {
                    expert: ExpertId::new(0, 1),
                    weight: 0.75,
                },
                RoutedSlot {
                    expert: ExpertId::new(0, 2),
                    weight: 0.25,
                },
            ],
        }];
        let resp = ExpertExecuteResponse {
            model_id: "qwen".into(),
            layer: 0,
            expert: 1,
            token_indices: vec![0],
            d_model: 2,
            outputs: vec![4.0, 8.0],
            receipt: None,
        };
        let mut combiner = MoeCombiner::new(2, &routed).unwrap();
        combiner.accumulate(&resp).unwrap();
        let partial = combiner.finish_partial().unwrap();
        assert_eq!(partial.outputs, vec![4.0, 8.0]);
        assert_eq!(partial.missing, vec![(ExpertId::new(0, 2), 0)]);
    }

    #[test]
    fn finish_partial_complete_batch_has_no_missing() {
        let routed = vec![RoutedToken {
            token_index: 0,
            slots: vec![RoutedSlot {
                expert: ExpertId::new(0, 1),
                weight: 1.0,
            }],
        }];
        let resp = ExpertExecuteResponse {
            model_id: "qwen".into(),
            layer: 0,
            expert: 1,
            token_indices: vec![0],
            d_model: 2,
            outputs: vec![1.0, 2.0],
            receipt: None,
        };
        let mut combiner = MoeCombiner::new(2, &routed).unwrap();
        combiner.accumulate(&resp).unwrap();
        let partial = combiner.finish_partial().unwrap();
        assert_eq!(partial.outputs, vec![1.0, 2.0]);
        assert!(partial.missing.is_empty());
    }

    #[test]
    fn finish_partial_errors_when_token_has_no_contribution() {
        // Both selected slots missing → nothing to renormalize.
        let routed = vec![RoutedToken {
            token_index: 5,
            slots: vec![
                RoutedSlot {
                    expert: ExpertId::new(2, 3),
                    weight: 0.5,
                },
                RoutedSlot {
                    expert: ExpertId::new(2, 4),
                    weight: 0.5,
                },
            ],
        }];
        let err = MoeCombiner::new(2, &routed)
            .unwrap()
            .finish_partial()
            .unwrap_err();
        assert!(matches!(
            err,
            MoeExecError::MissingContribution { token_index: 5, layer: 2, .. }
        ));
    }

    #[test]
    fn finish_partial_only_scales_affected_tokens() {
        // Token 0 complete, token 1 partial — token 0's row must be
        // untouched by token 1's renormalization.
        let routed = vec![
            RoutedToken {
                token_index: 0,
                slots: vec![RoutedSlot {
                    expert: ExpertId::new(0, 1),
                    weight: 1.0,
                }],
            },
            RoutedToken {
                token_index: 1,
                slots: vec![
                    RoutedSlot {
                        expert: ExpertId::new(0, 1),
                        weight: 0.5,
                    },
                    RoutedSlot {
                        expert: ExpertId::new(0, 2),
                        weight: 0.5,
                    },
                ],
            },
        ];
        let resp = ExpertExecuteResponse {
            model_id: "qwen".into(),
            layer: 0,
            expert: 1,
            token_indices: vec![0, 1],
            d_model: 2,
            outputs: vec![1.0, 2.0, 6.0, 10.0],
            receipt: None,
        };
        let mut combiner = MoeCombiner::new(2, &routed).unwrap();
        combiner.accumulate(&resp).unwrap();
        let partial = combiner.finish_partial().unwrap();
        // Token 0: 1.0*[1,2] unscaled. Token 1: 0.5*[6,10]=[3,5], scaled
        // by 1.0/0.5 → [6,10].
        assert_eq!(partial.outputs, vec![1.0, 2.0, 6.0, 10.0]);
        assert_eq!(partial.missing, vec![(ExpertId::new(0, 2), 1)]);
    }

    #[test]
    fn throughput_meter_counts_served_tokens() {
        let rt = MoeExpertRuntime::new();
        rt.load_expert("qwen", 0, 0, &identity_expert_blob(1.0), None).unwrap();
        let req = ExpertExecuteRequest {
            model_id: "qwen".into(),
            layer: 0,
            expert: 0,
            token_indices: vec![0, 1, 2],
            d_model: 2,
            hidden_states: vec![1.0, 0.0, 0.0, 1.0, 1.0, 1.0],
            hidden_q8: None,
        };
        rt.execute(&req).unwrap();
        // Current-minute bucket holds 3 tokens; tps floors to 0 (<60/min)
        // but the raw bucket must have registered the tokens.
        assert_eq!(rt.served_bucket_tokens.load(Ordering::Relaxed), 3);
        assert_eq!(rt.status().measured_tps, rt.measured_tps());
    }

    #[test]
    fn incremental_combiner_ignores_unrouted_rows() {
        // Gate selected only (0,1) for token 0. A holder response that
        // also carries an unrouted (expert,token) must not corrupt output
        // nor leave the routed slot outstanding.
        let routed = vec![RoutedToken {
            token_index: 0,
            slots: vec![RoutedSlot {
                expert: ExpertId::new(0, 1),
                weight: 1.0,
            }],
        }];
        let resp = ExpertExecuteResponse {
            model_id: "qwen".into(),
            layer: 0,
            expert: 1,
            token_indices: vec![0, 9], // token 9 was never routed
            d_model: 2,
            outputs: vec![1.0, 2.0, 5.0, 5.0],
            receipt: None,
        };
        let mut combiner = MoeCombiner::new(2, &routed).unwrap();
        combiner.accumulate(&resp).unwrap();
        assert_eq!(combiner.finish().unwrap(), vec![1.0, 2.0]);
    }

    #[test]
    fn end_to_end_route_dispatch_execute_combine() {
        // Two experts on layer 0; gate picks both (top-2) for one token.
        let rt = MoeExpertRuntime::new();
        rt.load_expert("qwen", 0, 0, &identity_expert_blob(1.0), None).unwrap();
        rt.load_expert("qwen", 0, 1, &identity_expert_blob(2.0), None).unwrap();
        rt.load_gate("qwen", 0, &router_blob(2, 2, &[1.0, 0.0, 0.5, 0.0]))
            .unwrap();

        let hidden = vec![1.0f32, 0.0];
        let routed = rt.route("qwen", 0, 2, &hidden, 2).unwrap();
        assert_eq!(routed[0].slots.len(), 2);

        // Execute each selected expert on the token's hidden state.
        let mut responses = Vec::new();
        for slot in &routed[0].slots {
            let resp = rt
                .execute(&ExpertExecuteRequest {
                    model_id: "qwen".into(),
                    layer: slot.expert.layer,
                    expert: slot.expert.expert,
                    token_indices: vec![0],
                    d_model: 2,
                    hidden_states: hidden.clone(),
                    hidden_q8: None,
                })
                .unwrap();
            responses.push(resp);
        }

        let combined = combine_expert_outputs(2, &routed, &responses).unwrap();
        assert_eq!(combined.len(), 2);
        // Expert outputs: e0 = silu(1)*1 = 0.7310586 ; e1 = silu(1)*2 = 1.4621172.
        // Combined = w0*out(e0) + w1*out(e1) with w0+w1 = 1 → strictly
        // between the two expert outputs.
        assert!(combined[0] > 0.7310586 && combined[0] < 1.4621172, "{}", combined[0]);
    }

    #[test]
    fn wire_types_roundtrip_base64_f32() {
        let req = ExpertExecuteRequest {
            model_id: "qwen".into(),
            layer: 3,
            expert: 7,
            token_indices: vec![0, 5, 9],
            d_model: 2,
            hidden_states: vec![1.0, -2.5, 0.0, f32::MIN_POSITIVE, 3.25, -0.125],
            hidden_q8: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        // Hidden states travel as a base64 string, not a JSON number array.
        assert!(json.contains("\"hidden_states\":\""), "{json}");
        let back: ExpertExecuteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);

        let resp = ExpertExecuteResponse {
            model_id: "qwen".into(),
            layer: 3,
            expert: 7,
            token_indices: vec![0, 5, 9],
            d_model: 2,
            outputs: vec![0.5; 6],
            receipt: None,
        };
        let back: ExpertExecuteResponse =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(back, resp);

        // Truncated payloads (not a multiple of 4 bytes) are rejected.
        let bad = json.replace(
            serde_json::to_string(&req)
                .unwrap()
                .split("\"hidden_states\":\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap(),
            "AAA",
        );
        assert!(serde_json::from_str::<ExpertExecuteRequest>(&bad).is_err());
    }

    #[test]
    fn q8_activation_carrier_matches_dense_within_tolerance() {
        // 32-wide expert so the Q8_0 block width (32) divides d_model.
        let d = 32usize;
        let mut gate = vec![0.0f32; d * d];
        let mut up = vec![0.0f32; d * d];
        let mut down = vec![0.0f32; d * d];
        for i in 0..d {
            gate[i * d + i] = 1.0;
            up[i * d + i] = 1.0;
            down[i * d + i] = 1.0;
        }
        let blob = expert_blob(d, d, &gate, &up, &down);
        let rt = MoeExpertRuntime::new();
        rt.load_expert("qwen", 0, 1, &blob, None).unwrap();

        // Two token rows of arbitrary magnitude.
        let mut rows = vec![0.0f32; 2 * d];
        for (i, v) in rows.iter_mut().enumerate() {
            *v = ((i as f32) * 0.37).sin() * 3.0;
        }

        let dense = ExpertExecuteRequest {
            model_id: "qwen".into(),
            layer: 0,
            expert: 1,
            token_indices: vec![0, 1],
            d_model: d as u32,
            hidden_states: rows.clone(),
            hidden_q8: None,
        };
        // compressed() must pick the Q8_0 carrier for a 32-wide row.
        let q8 = ExpertExecuteRequest::compressed(
            "qwen".into(),
            0,
            1,
            vec![0, 1],
            d as u32,
            rows.clone(),
        );
        assert!(q8.hidden_q8.is_some(), "d_model % 32 == 0 must compress");
        assert!(q8.hidden_states.is_empty());

        let y_dense = rt.execute(&dense).unwrap().outputs;
        let y_q8 = rt.execute(&q8).unwrap().outputs;
        assert_eq!(y_dense.len(), y_q8.len());
        for (a, b) in y_dense.iter().zip(y_q8.iter()) {
            assert!(
                (a - b).abs() < 5e-2,
                "dense {a} vs q8 {b} diverged beyond Q8_0 noise floor"
            );
        }

        // A non-multiple-of-32 width falls back to the dense carrier.
        let small = ExpertExecuteRequest::compressed(
            "qwen".into(),
            0,
            1,
            vec![0],
            2,
            vec![1.0, -1.0],
        );
        assert!(small.hidden_q8.is_none());
        assert_eq!(small.hidden_states, vec![1.0, -1.0]);
    }

    // ---- residency: budget, eviction, disk tier, readahead ----

    /// Each 2x2 identity expert is 3 matrices x 4 values x 4 bytes = 48 bytes.
    const EXPERT_BYTES: u64 = 48;

    #[test]
    fn budget_evicts_lru_expert_when_no_disk_tier() {
        // Budget holds exactly two experts; loading a third evicts the LRU.
        let rt = MoeExpertRuntime::with_config(
            ResidencyConfig::auto().with_memory_budget(EXPERT_BYTES * 2),
        );
        rt.load_expert("m", 0, 0, &identity_expert_blob(1.0), None).unwrap();
        rt.load_expert("m", 0, 1, &identity_expert_blob(1.0), None).unwrap();
        // Touch expert 0 so expert 1 becomes the LRU victim.
        rt.execute(&exec_req("m", 0, 0)).unwrap();
        rt.load_expert("m", 0, 2, &identity_expert_blob(1.0), None).unwrap();

        let status = rt.status();
        assert_eq!(status.memory_experts, 2);
        assert_eq!(status.disk_experts, 0, "no disk tier => victim dropped");
        assert!(rt.has_expert("m", 0, 0));
        assert!(!rt.has_expert("m", 0, 1), "LRU victim was dropped");
        assert!(rt.has_expert("m", 0, 2));
        assert_eq!(status.memory_bytes, EXPERT_BYTES * 2);
        assert!(status.memory_bytes <= status.memory_budget_bytes);
        assert_eq!(status.evicted_dropped, 1, "one LRU victim was dropped");
        assert_eq!(status.evicted_to_disk, 0, "no disk tier to spill to");
        assert_eq!(status.admissions_over_budget, 0);
    }

    #[test]
    fn eviction_spills_to_disk_tier_and_promotes_on_execute() {
        let dir = std::env::temp_dir().join(format!("tenzro_moe_disk_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let rt = MoeExpertRuntime::with_config(
            ResidencyConfig::auto()
                .with_memory_budget(EXPERT_BYTES)
                .with_disk_dir(&dir),
        );
        rt.load_expert("m", 0, 0, &identity_expert_blob(1.0), None).unwrap();
        // Second load evicts expert 0 to disk (budget holds one).
        rt.load_expert("m", 0, 1, &identity_expert_blob(1.0), None).unwrap();

        let status = rt.status();
        assert_eq!(status.memory_experts, 1);
        assert_eq!(status.disk_experts, 1);
        assert_eq!(status.evicted_to_disk, 1, "one expert spilled to disk");
        assert_eq!(status.evicted_dropped, 0, "disk tier => nothing dropped");
        let evicted = status.experts.iter().find(|e| e.expert == 0).unwrap();
        assert_eq!(evicted.tier, ExpertTier::Disk);

        // Executing the disk-tier expert promotes it back into memory
        // (evicting expert 1 in turn).
        let resp = rt.execute(&exec_req("m", 0, 0)).unwrap();
        assert_eq!(resp.expert, 0);
        assert!(rt.has_expert("m", 0, 0));
        let after = rt.status();
        assert_eq!(after.memory_experts, 1);
        let promoted = after.experts.iter().find(|e| e.expert == 0).unwrap();
        assert_eq!(promoted.tier, ExpertTier::Memory);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn readahead_promotes_disk_experts() {
        let dir = std::env::temp_dir().join(format!("tenzro_moe_ra_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let rt = MoeExpertRuntime::with_config(
            ResidencyConfig::auto()
                .with_memory_budget(EXPERT_BYTES)
                .with_disk_dir(&dir),
        );
        rt.load_expert("m", 0, 0, &identity_expert_blob(1.0), None).unwrap();
        rt.load_expert("m", 0, 1, &identity_expert_blob(1.0), None).unwrap();
        // Expert 0 is now on disk. Readahead of [0] promotes exactly one.
        let promoted = rt.readahead("m", &[ExpertId::new(0, 0), ExpertId::new(0, 1)]);
        assert_eq!(promoted, 1, "only the disk-tier member is promoted");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unload_clears_both_tiers() {
        let dir = std::env::temp_dir().join(format!("tenzro_moe_ul_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let rt = MoeExpertRuntime::with_config(
            ResidencyConfig::auto()
                .with_memory_budget(EXPERT_BYTES)
                .with_disk_dir(&dir),
        );
        rt.load_expert("m", 0, 0, &identity_expert_blob(1.0), None).unwrap();
        rt.load_expert("m", 0, 1, &identity_expert_blob(1.0), None).unwrap();
        assert!(rt.unload_expert("m", 0, 0), "disk-tier expert unloads");
        assert!(!rt.has_expert("m", 0, 0));
        assert!(rt.unload_expert("m", 0, 1), "memory-tier expert unloads");
        assert!(!rt.has_expert("m", 0, 1));
        assert_eq!(rt.status().memory_bytes, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_single_expert_stays_servable() {
        // Budget below a single expert: it must still load and execute.
        let rt = MoeExpertRuntime::with_config(ResidencyConfig::auto().with_memory_budget(1));
        rt.load_expert("m", 0, 0, &identity_expert_blob(1.0), None).unwrap();
        assert!(rt.has_expert("m", 0, 0));
        assert!(rt.execute(&exec_req("m", 0, 0)).is_ok());
        let status = rt.status();
        assert_eq!(status.memory_experts, 1);
        assert_eq!(
            status.admissions_over_budget, 1,
            "the oversized expert was admitted over budget"
        );
    }

    fn exec_req(model: &str, layer: u32, expert: u32) -> ExpertExecuteRequest {
        ExpertExecuteRequest {
            model_id: model.into(),
            layer,
            expert,
            token_indices: vec![0],
            d_model: 2,
            hidden_states: vec![1.0, -1.0],
            hidden_q8: None,
        }
    }
}
