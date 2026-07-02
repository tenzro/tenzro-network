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
use std::sync::Arc;

use dashmap::DashMap;
use ndarray::{Array1, Array2, ArrayView1, ArrayView2, Axis};
use safetensors::tensor::TensorView;
use safetensors::{Dtype, SafeTensors};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

/// One expert's FFN weights, decoded to `f32`.
///
/// Projections follow the HF `Linear.weight` convention — row-major
/// `[out_features, in_features]`, so the forward computes `x @ W^T`.
#[derive(Debug, Clone)]
pub struct ExpertFfn {
    gate: Array2<f32>,
    up: Array2<f32>,
    down: Array2<f32>,
    d_model: usize,
    d_ff: usize,
}

impl ExpertFfn {
    /// Parse an expert blob (three-tensor safetensors layout) and
    /// validate the projection shapes against each other.
    pub fn from_safetensors(bytes: &[u8]) -> MoeExecResult<Self> {
        let st = SafeTensors::deserialize(bytes).map_err(|e| MoeExecError::Parse(e.to_string()))?;
        let gate = tensor_to_f32_matrix(TENSOR_GATE_PROJ, &required_tensor(&st, TENSOR_GATE_PROJ)?)?;
        let up = tensor_to_f32_matrix(TENSOR_UP_PROJ, &required_tensor(&st, TENSOR_UP_PROJ)?)?;
        let down = tensor_to_f32_matrix(TENSOR_DOWN_PROJ, &required_tensor(&st, TENSOR_DOWN_PROJ)?)?;

        let (d_ff, d_model) = (gate.nrows(), gate.ncols());
        if up.dim() != (d_ff, d_model) {
            return Err(MoeExecError::BadShape {
                name: TENSOR_UP_PROJ.to_string(),
                got: vec![up.nrows(), up.ncols()],
                expected: format!("[{d_ff}, {d_model}] to match {TENSOR_GATE_PROJ}"),
            });
        }
        if down.dim() != (d_model, d_ff) {
            return Err(MoeExecError::BadShape {
                name: TENSOR_DOWN_PROJ.to_string(),
                got: vec![down.nrows(), down.ncols()],
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

    /// Approximate resident bytes for the decoded `f32` weights.
    pub fn approx_bytes(&self) -> u64 {
        ((self.gate.len() + self.up.len() + self.down.len()) * 4) as u64
    }

    /// Batched SwiGLU forward:
    /// `Y = (silu(X W_g^T) * (X W_u^T)) W_d^T` for `X: [n_tokens, d_model]`.
    pub fn forward(&self, x: ArrayView2<'_, f32>) -> Array2<f32> {
        debug_assert_eq!(x.ncols(), self.d_model);
        let mut h = x.dot(&self.gate.t());
        h.mapv_inplace(silu);
        let u = x.dot(&self.up.t());
        h *= &u;
        h.dot(&self.down.t())
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
#[derive(Debug, Clone)]
pub struct GatingNetwork {
    weight: Array2<f32>,
}

impl GatingNetwork {
    /// Parse a router blob (single-tensor safetensors layout,
    /// `router.weight` `[num_experts, d_model]`).
    pub fn from_safetensors(bytes: &[u8]) -> MoeExecResult<Self> {
        let st = SafeTensors::deserialize(bytes).map_err(|e| MoeExecError::Parse(e.to_string()))?;
        let weight = tensor_to_f32_matrix(TENSOR_ROUTER, &required_tensor(&st, TENSOR_ROUTER)?)?;
        Ok(Self { weight })
    }

    /// Number of routed experts this gate selects over.
    pub fn num_experts(&self) -> usize {
        self.weight.nrows()
    }

    /// Model (hidden) dimension.
    pub fn d_model(&self) -> usize {
        self.weight.ncols()
    }

    /// Approximate resident bytes for the decoded `f32` weight.
    pub fn approx_bytes(&self) -> u64 {
        (self.weight.len() * 4) as u64
    }

    /// Top-k routing for one token: expert logits `W h`, select the k
    /// highest, renormalize with softmax over the selected logits.
    /// Returns `(expert_index, weight)` pairs sorted by descending weight.
    pub fn route(&self, hidden: ArrayView1<'_, f32>, top_k: usize) -> Vec<(u32, f32)> {
        debug_assert_eq!(hidden.len(), self.d_model());
        let logits: Array1<f32> = self.weight.dot(&hidden);
        let k = top_k.clamp(1, logits.len());

        let mut indexed: Vec<(u32, f32)> = logits
            .iter()
            .enumerate()
            .map(|(i, &l)| (i as u32, l))
            .collect();
        indexed.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        indexed.truncate(k);

        // Softmax over the selected logits (max-subtracted for stability).
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

    /// Batched routing: one [`RoutedToken`] per row of `hidden`
    /// (`[n_tokens, d_model]`), with token indices `0..n`.
    pub fn route_batch(&self, layer: u32, hidden: ArrayView2<'_, f32>, top_k: usize) -> Vec<RoutedToken> {
        hidden
            .axis_iter(Axis(0))
            .enumerate()
            .map(|(i, row)| RoutedToken {
                token_index: i as u32,
                slots: self
                    .route(row, top_k)
                    .into_iter()
                    .map(|(expert, weight)| RoutedSlot {
                        expert: ExpertId::new(layer, expert),
                        weight,
                    })
                    .collect(),
            })
            .collect()
    }
}

/// One token's gate decision: its top-k experts with renormalized weights.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutedToken {
    /// Token index inside the request.
    pub token_index: u32,
    /// Selected `(expert, weight)` slots, descending by weight.
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
    /// serialized as base64 f32 LE bytes (see [`f32_base64`]).
    #[serde(with = "f32_base64")]
    pub hidden_states: Vec<f32>,
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
    /// Approximate resident bytes (decoded `f32`).
    pub approx_bytes: u64,
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
    /// Sum of all approximate resident bytes.
    pub total_bytes: u64,
}

/// Expert-holder / router-peer execution runtime. Holds decoded expert
/// FFNs and gating networks keyed by `(model_id, layer, expert)` /
/// `(model_id, layer)` and executes batches against them.
#[derive(Debug, Default)]
pub struct MoeExpertRuntime {
    experts: DashMap<ExpertKey, Arc<ExpertFfn>>,
    gates: DashMap<GateKey, Arc<GatingNetwork>>,
}

impl MoeExpertRuntime {
    /// Construct an empty runtime.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode and admit one expert blob. Replaces any previously loaded
    /// weights for the same `(model_id, layer, expert)`. Returns the
    /// status row for the freshly loaded expert.
    pub fn load_expert(
        &self,
        model_id: impl Into<String>,
        layer: u32,
        expert: u32,
        blob: &[u8],
    ) -> MoeExecResult<MoeLoadedExpert> {
        let model_id = model_id.into();
        let ffn = ExpertFfn::from_safetensors(blob)?;
        let row = MoeLoadedExpert {
            model_id: model_id.clone(),
            layer,
            expert,
            d_model: ffn.d_model() as u32,
            d_ff: ffn.d_ff() as u32,
            approx_bytes: ffn.approx_bytes(),
        };
        self.experts.insert(
            ExpertKey {
                model_id,
                layer,
                expert,
            },
            Arc::new(ffn),
        );
        Ok(row)
    }

    /// Drop one expert. Returns `true` when it was resident.
    pub fn unload_expert(&self, model_id: &str, layer: u32, expert: u32) -> bool {
        self.experts
            .remove(&ExpertKey {
                model_id: model_id.to_string(),
                layer,
                expert,
            })
            .is_some()
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

    /// Whether the expert is resident.
    pub fn has_expert(&self, model_id: &str, layer: u32, expert: u32) -> bool {
        self.experts.contains_key(&ExpertKey {
            model_id: model_id.to_string(),
            layer,
            expert,
        })
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
    pub fn execute(&self, req: &ExpertExecuteRequest) -> MoeExecResult<ExpertExecuteResponse> {
        let ffn = self
            .experts
            .get(&ExpertKey {
                model_id: req.model_id.clone(),
                layer: req.layer,
                expert: req.expert,
            })
            .map(|e| Arc::clone(e.value()))
            .ok_or_else(|| MoeExecError::ExpertNotLoaded {
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
        let x = view_hidden(&req.hidden_states, d_model)?;
        if x.nrows() != req.token_indices.len() {
            return Err(MoeExecError::DimensionMismatch {
                len: req.hidden_states.len(),
                tokens: req.token_indices.len(),
                d_model,
            });
        }

        let y = ffn.forward(x);
        Ok(ExpertExecuteResponse {
            model_id: req.model_id.clone(),
            layer: req.layer,
            expert: req.expert,
            token_indices: req.token_indices.clone(),
            d_model: req.d_model,
            outputs: y.into_raw_vec_and_offset().0,
        })
    }

    /// Snapshot of resident experts and gates.
    pub fn status(&self) -> MoeExpertRuntimeStatus {
        let mut experts: Vec<MoeLoadedExpert> = self
            .experts
            .iter()
            .map(|e| MoeLoadedExpert {
                model_id: e.key().model_id.clone(),
                layer: e.key().layer,
                expert: e.key().expert,
                d_model: e.value().d_model() as u32,
                d_ff: e.value().d_ff() as u32,
                approx_bytes: e.value().approx_bytes(),
            })
            .collect();
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

        let total_bytes = experts.iter().map(|e| e.approx_bytes).sum::<u64>()
            + gates.iter().map(|g| g.approx_bytes).sum::<u64>();

        MoeExpertRuntimeStatus {
            experts,
            gates,
            total_bytes,
        }
    }
}

fn view_hidden(hidden: &[f32], d_model: usize) -> MoeExecResult<ArrayView2<'_, f32>> {
    if hidden.is_empty() {
        return Err(MoeExecError::EmptyBatch);
    }
    if d_model == 0 || hidden.len() % d_model != 0 {
        return Err(MoeExecError::DimensionMismatch {
            len: hidden.len(),
            tokens: if d_model == 0 { 0 } else { hidden.len() / d_model },
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
        let y = ffn.forward(x.view());
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
        let single = ffn.forward(
            Array2::from_shape_vec((1, 2), vec![0.5, 2.0])
                .unwrap()
                .view(),
        );
        let batch = ffn.forward(
            Array2::from_shape_vec((2, 2), vec![0.5, 2.0, 0.5, 2.0])
                .unwrap()
                .view(),
        );
        for c in 0..2 {
            assert_eq!(single[[0, c]], batch[[0, c]]);
            assert_eq!(single[[0, c]], batch[[1, c]]);
        }
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
        let row = rt.load_expert("qwen", 0, 1, &identity_expert_blob(1.0)).unwrap();
        assert_eq!(row.d_model, 2);
        assert!(rt.has_expert("qwen", 0, 1));

        let req = ExpertExecuteRequest {
            model_id: "qwen".into(),
            layer: 0,
            expert: 1,
            token_indices: vec![7, 9],
            d_model: 2,
            hidden_states: vec![1.0, -1.0, 0.0, 2.0],
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
        rt.load_expert("qwen", 0, 1, &identity_expert_blob(1.0)).unwrap();

        // d_model mismatch vs loaded expert.
        let err = rt
            .execute(&ExpertExecuteRequest {
                model_id: "qwen".into(),
                layer: 0,
                expert: 1,
                token_indices: vec![0],
                d_model: 4,
                hidden_states: vec![0.0; 4],
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
        rt.load_expert("qwen", 0, 1, &identity_expert_blob(1.0)).unwrap();
        rt.load_expert("qwen", 0, 2, &identity_expert_blob(2.0)).unwrap();
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
            },
            ExpertExecuteResponse {
                model_id: "qwen".into(),
                layer: 0,
                expert: 2,
                token_indices: vec![0],
                d_model: 2,
                outputs: vec![-4.0, 0.0],
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
    fn end_to_end_route_dispatch_execute_combine() {
        // Two experts on layer 0; gate picks both (top-2) for one token.
        let rt = MoeExpertRuntime::new();
        rt.load_expert("qwen", 0, 0, &identity_expert_blob(1.0)).unwrap();
        rt.load_expert("qwen", 0, 1, &identity_expert_blob(2.0)).unwrap();
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
}
