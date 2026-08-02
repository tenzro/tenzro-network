//! Registry-native MoE expert extraction from upstream safetensors
//! checkpoints.
//!
//! Slices per-expert FFN weights and per-layer router weights directly
//! out of a HuggingFace safetensors checkpoint using HTTP Range
//! requests — only the requested tensors' bytes cross the wire, never
//! whole multi-GB shards. Each slice is re-serialized as the canonical
//! blob shape that [`crate::moe_exec::MoeExpertRuntime`] accepts:
//!
//! - expert blob: `gate_proj.weight` / `up_proj.weight` /
//!   `down_proj.weight` (shapes `[d_ff, d_model]` × 2 + `[d_model, d_ff]`)
//! - gate blob: `router.weight` (shape `[num_experts, d_model]`), plus —
//!   for DeepSeek-layout checkpoints — `router.bias` and the
//!   `routed_scaling_factor` / `shared_experts` `__metadata__` keys that
//!   switch [`crate::moe_exec::GatingNetwork`] into sigmoid routing
//!
//! DeepSeek-layout checkpoints additionally expose one fused
//! shared-expert FFN per MoE layer via [`MoeExtractor::shared_expert_blob`],
//! serialized as a normal expert blob and addressed at expert index
//! `num_experts`.
//!
//! Source dtype bytes (BF16 / F16 / F32) are preserved verbatim; the
//! expert runtime decodes them to f32 at load time.
//!
//! Wire mechanics: a sharded checkpoint publishes
//! `model.safetensors.index.json` mapping every tensor name to its
//! shard file. Each shard is a safetensors file — 8-byte little-endian
//! header length, JSON header with per-tensor
//! `{dtype, shape, data_offsets}` (offsets relative to the data
//! section), then the data section. Three ranged GETs per shard give
//! the header; one ranged GET per tensor gives its bytes.

use std::collections::HashMap;

use bytes::Bytes;
use reqwest::Client;
use safetensors::Dtype;
use safetensors::tensor::TensorView;
use serde::Deserialize;
use tracing::debug;

use crate::catalog::ModelArchitecture;
use crate::error::{ModelError, Result};
use crate::moe_exec::{
    ExpertQuantPlan, META_ROUTED_SCALING_FACTOR, META_SHARED_EXPERTS, TENSOR_DOWN_PROJ,
    TENSOR_GATE_PROJ, TENSOR_ROUTER, TENSOR_ROUTER_BIAS, TENSOR_UP_PROJ, quantize_expert_blob,
};

/// Upper bound on a shard's safetensors JSON header. Real headers for
/// multi-GB shards are well under 1 MB; anything larger is corrupt.
const MAX_HEADER_BYTES: u64 = 32 * 1024 * 1024;

/// Upstream tensor-naming convention for a MoE checkpoint family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoeTensorNaming {
    /// transformers `Qwen3MoeForCausalLM` layout, used by every
    /// Qwen-family MoE checkpoint:
    /// `model.layers.{L}.mlp.experts.{E}.{gate,up,down}_proj.weight`
    /// with the router at `model.layers.{L}.mlp.gate.weight`.
    QwenMoe,
    /// transformers `DeepseekV3ForCausalLM` layout, used by the DeepSeek
    /// and Kimi MoE checkpoints. Routed-expert and router tensors match
    /// the Qwen pattern; the layout adds a router selection bias
    /// (`model.layers.{L}.mlp.gate.e_score_correction_bias`), one fused
    /// shared-expert FFN per MoE layer
    /// (`model.layers.{L}.mlp.shared_experts.{gate,up,down}_proj.weight`),
    /// sigmoid expert scoring, and dense (non-MoE) MLPs on the first
    /// `first_k_dense_replace` layers per the checkpoint's `config.json`.
    DeepSeekMoe,
}

impl MoeTensorNaming {
    /// Resolve the naming convention for a catalog architecture.
    /// `None` means the family's checkpoint layout is not yet mapped
    /// for extraction.
    pub fn for_architecture(arch: ModelArchitecture) -> Option<Self> {
        match arch {
            ModelArchitecture::Qwen3Moe
            | ModelArchitecture::Qwen35Moe
            | ModelArchitecture::Qwen36Moe
            // Qwen3-Next replaces half the attention layers with gated
            // delta-net but leaves the MoE MLP block — and so its tensor
            // names — identical to the rest of the Qwen MoE line.
            | ModelArchitecture::Qwen3Next => Some(Self::QwenMoe),
            ModelArchitecture::DeepSeekV3 | ModelArchitecture::Kimi => Some(Self::DeepSeekMoe),
            _ => None,
        }
    }

    fn expert_tensor(self, layer: u32, expert: u32, proj: &str) -> String {
        match self {
            Self::QwenMoe | Self::DeepSeekMoe => {
                format!("model.layers.{layer}.mlp.experts.{expert}.{proj}.weight")
            }
        }
    }

    fn router_tensor(self, layer: u32) -> String {
        match self {
            Self::QwenMoe | Self::DeepSeekMoe => format!("model.layers.{layer}.mlp.gate.weight"),
        }
    }

    fn router_bias_tensor(self, layer: u32) -> Option<String> {
        match self {
            Self::QwenMoe => None,
            Self::DeepSeekMoe => Some(format!(
                "model.layers.{layer}.mlp.gate.e_score_correction_bias"
            )),
        }
    }

    fn shared_expert_tensor(self, layer: u32, proj: &str) -> Option<String> {
        match self {
            Self::QwenMoe => None,
            Self::DeepSeekMoe => Some(format!(
                "model.layers.{layer}.mlp.shared_experts.{proj}.weight"
            )),
        }
    }
}

/// Router-topology facts a DeepSeek-layout checkpoint publishes in its
/// `config.json`. All three fields are present in every known
/// `DeepseekV3ForCausalLM` config; a checkpoint missing them is refused
/// rather than silently mis-scaled.
#[derive(Debug, Clone, Copy, Deserialize)]
struct DeepSeekMoeConfig {
    /// Layers `0..first_k_dense_replace` carry a plain dense MLP — no
    /// experts, no router.
    first_k_dense_replace: u32,
    /// Multiplier applied to the renormalized routed-expert weights.
    routed_scaling_factor: f32,
    /// Shared-expert count fused into the single
    /// `mlp.shared_experts.*` FFN.
    n_shared_experts: u32,
}

#[derive(Debug, Deserialize)]
struct RawIndex {
    weight_map: HashMap<String, String>,
}

/// Tensor-name → shard-file mapping. Empty for single-file checkpoints,
/// where every tensor lives in `model.safetensors`.
pub struct WeightIndex {
    weight_map: HashMap<String, String>,
}

impl WeightIndex {
    fn shard_for(&self, tensor: &str) -> &str {
        self.weight_map
            .get(tensor)
            .map(String::as_str)
            .unwrap_or("model.safetensors")
    }
}

#[derive(Debug, Clone, Deserialize)]
struct TensorMeta {
    dtype: String,
    shape: Vec<usize>,
    data_offsets: (u64, u64),
}

/// Parsed safetensors header for one shard: absolute data-section
/// offset plus per-tensor metadata.
pub struct ShardHeader {
    data_start: u64,
    tensors: HashMap<String, TensorMeta>,
}

fn parse_dtype(s: &str) -> Result<Dtype> {
    match s {
        "F32" => Ok(Dtype::F32),
        "F16" => Ok(Dtype::F16),
        "BF16" => Ok(Dtype::BF16),
        other => Err(ModelError::InvalidModel(format!(
            "unsupported tensor dtype {other} for MoE extraction (want F32/F16/BF16)"
        ))),
    }
}

/// Ranged-GET client for one HuggingFace checkpoint repository.
pub struct HfShardClient {
    http: Client,
    repo: String,
}

impl HfShardClient {
    /// Create a client for `repo` (e.g. `"Qwen/Qwen3-30B-A3B"`),
    /// resolving files at the `main` revision.
    pub fn new(repo: impl Into<String>) -> Self {
        Self {
            http: Client::new(),
            repo: repo.into(),
        }
    }

    fn url(&self, file: &str) -> String {
        format!("https://huggingface.co/{}/resolve/main/{}", self.repo, file)
    }

    async fn ranged(&self, file: &str, start: u64, end_inclusive: u64) -> Result<Bytes> {
        let resp = self
            .http
            .get(self.url(file))
            .header(
                reqwest::header::RANGE,
                format!("bytes={start}-{end_inclusive}"),
            )
            .send()
            .await
            .map_err(|e| ModelError::DownloadError(format!("range fetch {file}: {e}")))?;
        if resp.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(ModelError::DownloadError(format!(
                "range fetch {file}: expected 206 Partial Content, got {}",
                resp.status()
            )));
        }
        resp.bytes()
            .await
            .map_err(|e| ModelError::DownloadError(format!("range body {file}: {e}")))
    }

    /// Fetch the checkpoint's tensor→shard index. A 404 means a
    /// single-file checkpoint; every tensor then resolves to
    /// `model.safetensors`.
    pub async fn weight_index(&self) -> Result<WeightIndex> {
        let file = "model.safetensors.index.json";
        let resp = self
            .http
            .get(self.url(file))
            .send()
            .await
            .map_err(|e| ModelError::DownloadError(format!("fetch {file}: {e}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            debug!(repo = %self.repo, "no shard index — single-file checkpoint");
            return Ok(WeightIndex {
                weight_map: HashMap::new(),
            });
        }
        if !resp.status().is_success() {
            return Err(ModelError::DownloadError(format!(
                "fetch {file}: HTTP {}",
                resp.status()
            )));
        }
        let raw: RawIndex = resp
            .json()
            .await
            .map_err(|e| ModelError::DownloadError(format!("parse {file}: {e}")))?;
        Ok(WeightIndex {
            weight_map: raw.weight_map,
        })
    }

    /// Fetch and parse the repo's `config.json` into the DeepSeek MoE
    /// topology facts the extractor needs.
    async fn deepseek_config(&self) -> Result<DeepSeekMoeConfig> {
        let file = "config.json";
        let resp = self
            .http
            .get(self.url(file))
            .send()
            .await
            .map_err(|e| ModelError::DownloadError(format!("fetch {file}: {e}")))?;
        if !resp.status().is_success() {
            return Err(ModelError::DownloadError(format!(
                "fetch {file}: HTTP {}",
                resp.status()
            )));
        }
        resp.json::<DeepSeekMoeConfig>().await.map_err(|e| {
            ModelError::InvalidModel(format!(
                "{}: config.json is missing DeepSeek MoE fields \
                 (first_k_dense_replace / routed_scaling_factor / n_shared_experts): {e}",
                self.repo
            ))
        })
    }

    /// Fetch and parse one shard's safetensors header via two ranged
    /// GETs (8-byte length prefix, then the JSON header).
    pub async fn shard_header(&self, file: &str) -> Result<ShardHeader> {
        let len_bytes = self.ranged(file, 0, 7).await?;
        if len_bytes.len() != 8 {
            return Err(ModelError::DownloadError(format!(
                "shard {file}: short header-length read ({} bytes)",
                len_bytes.len()
            )));
        }
        let header_len = u64::from_le_bytes(len_bytes[..8].try_into().expect("8-byte slice"));
        if header_len == 0 || header_len > MAX_HEADER_BYTES {
            return Err(ModelError::InvalidModel(format!(
                "shard {file}: implausible safetensors header length {header_len}"
            )));
        }
        let hdr = self.ranged(file, 8, 8 + header_len - 1).await?;
        let raw: HashMap<String, serde_json::Value> = serde_json::from_slice(&hdr)
            .map_err(|e| ModelError::InvalidModel(format!("shard {file}: header parse: {e}")))?;
        let mut tensors = HashMap::new();
        for (name, value) in raw {
            if name == "__metadata__" {
                continue;
            }
            let meta: TensorMeta = serde_json::from_value(value).map_err(|e| {
                ModelError::InvalidModel(format!("shard {file}: tensor {name}: {e}"))
            })?;
            tensors.insert(name, meta);
        }
        Ok(ShardHeader {
            data_start: 8 + header_len,
            tensors,
        })
    }

    /// Fetch one tensor's raw bytes via a ranged GET against its shard.
    pub async fn tensor(
        &self,
        file: &str,
        header: &ShardHeader,
        name: &str,
    ) -> Result<(Dtype, Vec<usize>, Bytes)> {
        let meta = header.tensors.get(name).ok_or_else(|| {
            ModelError::InvalidModel(format!("tensor {name} not present in shard {file}"))
        })?;
        let dtype = parse_dtype(&meta.dtype)?;
        let (begin, end) = meta.data_offsets;
        if end <= begin {
            return Err(ModelError::InvalidModel(format!(
                "tensor {name}: empty data range {begin}..{end}"
            )));
        }
        let bytes = self
            .ranged(file, header.data_start + begin, header.data_start + end - 1)
            .await?;
        if bytes.len() as u64 != end - begin {
            return Err(ModelError::DownloadError(format!(
                "tensor {name}: short read ({} of {} bytes)",
                bytes.len(),
                end - begin
            )));
        }
        Ok((dtype, meta.shape.clone(), bytes))
    }
}

/// High-level extractor: caches shard headers across tensor fetches so
/// a full layer's 128 experts cost one header parse per shard plus one
/// ranged GET per tensor.
pub struct MoeExtractor {
    client: HfShardClient,
    index: WeightIndex,
    naming: MoeTensorNaming,
    headers: HashMap<String, ShardHeader>,
    deepseek: Option<DeepSeekMoeConfig>,
}

impl MoeExtractor {
    /// Open an extractor against `repo`, fetching the shard index. For
    /// DeepSeek-layout checkpoints the repo's `config.json` is also
    /// fetched — it carries the dense-layer prefix, routed scaling
    /// factor, and shared-expert count.
    pub async fn open(repo: impl Into<String>, naming: MoeTensorNaming) -> Result<Self> {
        let client = HfShardClient::new(repo);
        let index = client.weight_index().await?;
        let deepseek = match naming {
            MoeTensorNaming::QwenMoe => None,
            MoeTensorNaming::DeepSeekMoe => Some(client.deepseek_config().await?),
        };
        Ok(Self {
            client,
            index,
            naming,
            headers: HashMap::new(),
            deepseek,
        })
    }

    /// Refuse extraction against a dense (non-MoE) layer. DeepSeek-layout
    /// checkpoints carry a plain MLP on the first `first_k_dense_replace`
    /// layers — the expert/router tensors simply don't exist there, and a
    /// clear error beats a tensor-404.
    fn check_moe_layer(&self, layer: u32) -> Result<()> {
        if let Some(cfg) = &self.deepseek
            && layer < cfg.first_k_dense_replace
        {
            return Err(ModelError::InvalidModel(format!(
                "layer {layer} is a dense layer (first {} layers of this \
                 checkpoint have no experts)",
                cfg.first_k_dense_replace
            )));
        }
        Ok(())
    }

    async fn fetch_named(&mut self, name: &str) -> Result<(Dtype, Vec<usize>, Bytes)> {
        let shard = self.index.shard_for(name).to_string();
        if !self.headers.contains_key(&shard) {
            let header = self.client.shard_header(&shard).await?;
            self.headers.insert(shard.clone(), header);
        }
        let header = self.headers.get(&shard).expect("just inserted");
        self.client.tensor(&shard, header, name).await
    }

    /// Extract one expert's FFN as a canonical expert blob, preserving
    /// the source dtype bytes verbatim.
    pub async fn expert_blob(&mut self, layer: u32, expert: u32) -> Result<Vec<u8>> {
        self.check_moe_layer(layer)?;
        let gate_name = self.naming.expert_tensor(layer, expert, "gate_proj");
        let up_name = self.naming.expert_tensor(layer, expert, "up_proj");
        let down_name = self.naming.expert_tensor(layer, expert, "down_proj");
        let gate = self.fetch_named(&gate_name).await?;
        let up = self.fetch_named(&up_name).await?;
        let down = self.fetch_named(&down_name).await?;
        fn view<'a>(
            t: &'a (Dtype, Vec<usize>, Bytes),
            layer: u32,
            expert: u32,
        ) -> Result<TensorView<'a>> {
            TensorView::new(t.0, t.1.clone(), &t.2).map_err(|e| {
                ModelError::InvalidModel(format!("expert L{layer}/E{expert}: tensor view: {e:?}"))
            })
        }
        let tensors = vec![
            (TENSOR_GATE_PROJ, view(&gate, layer, expert)?),
            (TENSOR_UP_PROJ, view(&up, layer, expert)?),
            (TENSOR_DOWN_PROJ, view(&down, layer, expert)?),
        ];
        safetensors::serialize(tensors, None).map_err(|e| {
            ModelError::SerializationError(format!("expert blob L{layer}/E{expert}: {e:?}"))
        })
    }

    /// Extract one expert's FFN and re-encode it as a GGUF block-quantized
    /// blob per `plan`. Equivalent to [`Self::expert_blob`] followed by
    /// [`quantize_expert_blob`], but avoids exposing the intermediate dense
    /// blob to callers that only want the smaller quantized payload.
    pub async fn quantized_expert_blob(
        &mut self,
        layer: u32,
        expert: u32,
        plan: ExpertQuantPlan,
    ) -> Result<Vec<u8>> {
        let dense = self.expert_blob(layer, expert).await?;
        quantize_expert_blob(&dense, plan).map_err(|e| {
            ModelError::SerializationError(format!("quantize expert blob L{layer}/E{expert}: {e}"))
        })
    }

    /// Extract one layer's router as a canonical gate blob. For
    /// DeepSeek-layout checkpoints the blob also carries the selection
    /// bias under [`TENSOR_ROUTER_BIAS`] plus the
    /// [`META_ROUTED_SCALING_FACTOR`] / [`META_SHARED_EXPERTS`]
    /// `__metadata__` keys, switching the loaded
    /// [`crate::moe_exec::GatingNetwork`] into sigmoid routing.
    pub async fn gate_blob(&mut self, layer: u32) -> Result<Vec<u8>> {
        self.check_moe_layer(layer)?;
        let name = self.naming.router_tensor(layer);
        let router = self.fetch_named(&name).await?;
        let bias = match self.naming.router_bias_tensor(layer) {
            Some(bias_name) => Some(self.fetch_named(&bias_name).await?),
            None => None,
        };
        let view = TensorView::new(router.0, router.1.clone(), &router.2).map_err(|e| {
            ModelError::InvalidModel(format!("router L{layer}: tensor view: {e:?}"))
        })?;
        let mut tensors = vec![(TENSOR_ROUTER, view)];
        if let Some(b) = &bias {
            let bias_view = TensorView::new(b.0, b.1.clone(), &b.2).map_err(|e| {
                ModelError::InvalidModel(format!("router bias L{layer}: tensor view: {e:?}"))
            })?;
            tensors.push((TENSOR_ROUTER_BIAS, bias_view));
        }
        let meta = self.deepseek.map(|cfg| {
            HashMap::from([
                (
                    META_ROUTED_SCALING_FACTOR.to_string(),
                    cfg.routed_scaling_factor.to_string(),
                ),
                (
                    META_SHARED_EXPERTS.to_string(),
                    cfg.n_shared_experts.to_string(),
                ),
            ])
        });
        safetensors::serialize(tensors, meta)
            .map_err(|e| ModelError::SerializationError(format!("gate blob L{layer}: {e:?}")))
    }

    /// Extract one layer's fused shared-expert FFN as a canonical expert
    /// blob (DeepSeek layout only). The runtime addresses it at expert
    /// index `num_experts`; its `d_ff` is `n_shared × moe_intermediate`,
    /// which the expert runtime reads from the blob shapes.
    pub async fn shared_expert_blob(&mut self, layer: u32) -> Result<Vec<u8>> {
        self.check_moe_layer(layer)?;
        let names = ["gate_proj", "up_proj", "down_proj"]
            .map(|proj| self.naming.shared_expert_tensor(layer, proj));
        let [Some(gate_name), Some(up_name), Some(down_name)] = names else {
            return Err(ModelError::InvalidModel(
                "this checkpoint layout has no shared experts".to_string(),
            ));
        };
        if self.deepseek.is_some_and(|cfg| cfg.n_shared_experts == 0) {
            return Err(ModelError::InvalidModel(
                "config.json declares n_shared_experts = 0".to_string(),
            ));
        }
        let gate = self.fetch_named(&gate_name).await?;
        let up = self.fetch_named(&up_name).await?;
        let down = self.fetch_named(&down_name).await?;
        fn view<'a>(t: &'a (Dtype, Vec<usize>, Bytes), layer: u32) -> Result<TensorView<'a>> {
            TensorView::new(t.0, t.1.clone(), &t.2).map_err(|e| {
                ModelError::InvalidModel(format!("shared expert L{layer}: tensor view: {e:?}"))
            })
        }
        let tensors = vec![
            (TENSOR_GATE_PROJ, view(&gate, layer)?),
            (TENSOR_UP_PROJ, view(&up, layer)?),
            (TENSOR_DOWN_PROJ, view(&down, layer)?),
        ];
        safetensors::serialize(tensors, None).map_err(|e| {
            ModelError::SerializationError(format!("shared expert blob L{layer}: {e:?}"))
        })
    }
}
