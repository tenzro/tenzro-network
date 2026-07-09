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
//! - gate blob: `router.weight` (shape `[num_experts, d_model]`)
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
use safetensors::tensor::TensorView;
use safetensors::Dtype;
use serde::Deserialize;
use tracing::debug;

use crate::catalog::ModelArchitecture;
use crate::error::{ModelError, Result};
use crate::moe_exec::{TENSOR_DOWN_PROJ, TENSOR_GATE_PROJ, TENSOR_ROUTER, TENSOR_UP_PROJ};

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
}

impl MoeTensorNaming {
    /// Resolve the naming convention for a catalog architecture.
    /// `None` means the family's checkpoint layout is not yet mapped
    /// for extraction.
    pub fn for_architecture(arch: ModelArchitecture) -> Option<Self> {
        match arch {
            ModelArchitecture::Qwen3Moe
            | ModelArchitecture::Qwen35Moe
            | ModelArchitecture::Qwen36Moe => Some(Self::QwenMoe),
            _ => None,
        }
    }

    fn expert_tensor(self, layer: u32, expert: u32, proj: &str) -> String {
        match self {
            Self::QwenMoe => {
                format!("model.layers.{layer}.mlp.experts.{expert}.{proj}.weight")
            }
        }
    }

    fn router_tensor(self, layer: u32) -> String {
        match self {
            Self::QwenMoe => format!("model.layers.{layer}.mlp.gate.weight"),
        }
    }
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
}

impl MoeExtractor {
    /// Open an extractor against `repo`, fetching the shard index.
    pub async fn open(repo: impl Into<String>, naming: MoeTensorNaming) -> Result<Self> {
        let client = HfShardClient::new(repo);
        let index = client.weight_index().await?;
        Ok(Self {
            client,
            index,
            naming,
            headers: HashMap::new(),
        })
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
                ModelError::InvalidModel(format!(
                    "expert L{layer}/E{expert}: tensor view: {e:?}"
                ))
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

    /// Extract one layer's router as a canonical gate blob.
    pub async fn gate_blob(&mut self, layer: u32) -> Result<Vec<u8>> {
        let name = self.naming.router_tensor(layer);
        let router = self.fetch_named(&name).await?;
        let view = TensorView::new(router.0, router.1.clone(), &router.2).map_err(|e| {
            ModelError::InvalidModel(format!("router L{layer}: tensor view: {e:?}"))
        })?;
        safetensors::serialize(vec![(TENSOR_ROUTER, view)], None)
            .map_err(|e| ModelError::SerializationError(format!("gate blob L{layer}: {e:?}")))
    }
}
