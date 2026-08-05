//! Curated model catalog with HuggingFace GGUF repository metadata.
//!
//! All models listed here are **ungated** — no HF login required for download.
//! Models use GGUF quantization format for efficient loading via llama.cpp.
//! llama.cpp auto-detects the model architecture from GGUF metadata — the
//! `ModelArchitecture` enum is informational only (for UI display and filtering).

use serde::{Deserialize, Serialize};

/// License tier for catalog entries. Defined in `tenzro-types` so it can be
/// carried on `ModelInfo` and enforced in `ModelRegistry::register_model()`.
pub use tenzro_types::LicenseTier;

/// A model entry in the curated catalog with HuggingFace metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HfModelEntry {
    /// Internal model ID (e.g. "qwen3.5-4b-q4km")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Model family (e.g. "qwen3.5", "gemma3", "mistral")
    pub family: String,
    /// HuggingFace repository ID (e.g. "unsloth/Qwen3.5-4B-GGUF")
    pub hf_repo: String,
    /// GGUF filename to download (e.g. "Qwen3.5-4B-Q4_K_M.gguf")
    pub hf_filename: String,
    /// Parameter count
    pub parameters: String,
    /// Model architecture (informational — llama.cpp auto-detects from GGUF)
    pub architecture: ModelArchitecture,
    /// Context window length
    pub context_length: u32,
    /// Quantization method (e.g. "Q4_K_M", "Q8_0")
    pub quantization: String,
    /// Approximate file size in bytes
    pub size_bytes: u64,
    /// Minimum RAM in GB to load
    pub min_ram_gb: u32,
    /// License
    pub license: String,
    /// Short description
    pub description: String,
    /// Optional speculative-decoding drafter — the catalog ID of a smaller,
    /// vocab-matched GGUF to load alongside this model as the speculative
    /// drafter (llama.cpp `--spec-draft-model` / `-md`). The referenced ID
    /// must resolve via `get_model_by_id`; the drafter entry itself is a
    /// normal `HfModelEntry` and so is independently downloadable. `None`
    /// means no drafter is recommended for this target — either because
    /// none exists with a matching tokenizer, or because community
    /// benchmarks show speculative decoding is net-negative for this
    /// architecture (e.g. small-active-path MoE on consumer GPUs).
    pub drafter_id: Option<String>,
    /// Speculative-decoding flavour this target uses when paired with its
    /// `drafter_id`. Drives the `--spec-type` argument on the llama.cpp
    /// invocation. Defaults to `MtpKind::None` when no drafter is wired.
    /// See [`MtpKind`] for the semantic difference between `Generic` and
    /// `DraftMtp`.
    #[serde(default)]
    pub mtp_kind: MtpKind,
    /// Recommended starting `--spec-draft-n-max` (1..=6) for this target
    /// when speculative decoding is enabled. `None` means use the
    /// runtime's global default (Unsloth recommends 2 as a starting
    /// point; optimal value is hardware-dependent — try 1..=6).
    #[serde(default)]
    pub mtp_default_draft_n: Option<u8>,
    /// MoE expert topology when the model is a Mixture-of-Experts
    /// architecture. `None` for dense models. Drives the
    /// [`tenzro_types::model::MoeMetadata`] block attached to
    /// [`ModelInfo`] at registration time so routing, capacity
    /// estimation, and the distributed expert-shard view all see the
    /// correct expert count, active-experts-per-token, and shared
    /// experts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moe: Option<MoeShape>,
    /// Whether this entry is currently promotable to users — i.e. its GGUF
    /// is actually downloadable from `hf_repo`/`hf_filename` right now.
    /// `false` gates the entry OUT of the user-facing catalog
    /// (`tenzro_listModels` / `GET /v1/models`) while keeping it in source
    /// so it can be re-enabled the moment the upstream GGUF is published (gated
    /// repos, unreleased quants, etc.). Defaults to `true`; the committed
    /// HF-verification test asserts every `promotable` entry resolves.
    #[serde(default = "default_true")]
    pub promotable: bool,
    /// Per-model serving configuration (sampler defaults, `--jinja`,
    /// reasoning default). Stamped by the catalog build pass from
    /// [`ServingProfile::for_family`] so every entry carries the
    /// model-author-recommended serving config. Required — the catalog is
    /// the single source of truth for serving behaviour across all clients.
    pub serving: ServingProfile,
    /// Multimodal projector (mmproj) for vision-capable GGUFs. `Some` when
    /// the model accepts image input and needs a separate projector file
    /// loaded via llama.cpp `--mmproj`. The projector ships in the same
    /// `hf_repo` as the model GGUF, so only the filename is carried here.
    /// `None` for text-only models. When set, the downloader fetches the
    /// projector alongside the model and the sidecar emits `mmproj = <path>`
    /// so image input actually works instead of being silently dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmproj: Option<MmprojSpec>,
    /// Reasoning / thinking-mode policy. Universal policy the serving
    /// runtime resolves per-request. Stamped by the catalog build pass
    /// from [`ReasoningPolicy::for_family`] so every entry carries the
    /// correct policy without per-id app code.
    #[serde(default)]
    pub reasoning: ReasoningPolicy,
    /// Chat-template fix policy. `TemplateFix::None` for entries whose
    /// embedded GGUF jinja is correct as-is; `TemplateFix::Vendored {
    /// filename }` when the inference client should load a vendored
    /// fix from its bundled templates dir. Stamped by the catalog
    /// build pass from [`TemplateFix::for_family`].
    #[serde(default)]
    pub template_fix: TemplateFix,
    /// Flat filename the network's HF downloader writes to
    /// `~/.tenzro/models/`. Always `<id>.gguf` for unshared models.
    /// Distinct from `hf_filename` (which is the canonical Unsloth
    /// name and may include a sharded subdir prefix). The serving
    /// runtime's filename matcher should key off THIS field — eliminating
    /// the dual-stem lookup the inference client used to do.
    /// Stamped by the catalog build pass from `id` + `hf_filename`.
    #[serde(default)]
    pub download_filename: String,
}

/// Multimodal projector descriptor for a vision-capable GGUF.
///
/// llama.cpp loads the language GGUF and the projector (mmproj) as two
/// files; the projector encodes images into the embedding space the model
/// expects. Unsloth publishes the projector in the same repo as the model
/// (e.g. `mmproj-F16.gguf`), so we only need its filename.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmprojSpec {
    /// Projector filename within the model's `hf_repo`
    /// (e.g. `"mmproj-F16.gguf"`).
    pub filename: String,
}

/// Serde default for [`HfModelEntry::promotable`] — entries are promotable
/// unless explicitly gated out.
fn default_true() -> bool {
    true
}

/// MoE expert topology declared by a catalog entry. Mirrors the public
/// fields of [`tenzro_types::model::MoeMetadata`] in the smallest
/// possible form so catalog entries stay terse — the registry expands
/// this into the full metadata block at registration time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoeShape {
    /// Total routed experts in the model (e.g. 64 for Qwen 3.5 35B-A3B,
    /// 256 for DeepSeek V3).
    pub num_experts: u32,
    /// Experts activated per token (top-k routing).
    pub experts_per_token: u8,
    /// Shared ("always-on") experts that process every token alongside
    /// the routed experts. Zero for Mixtral / Qwen-style, 1 for
    /// DeepSeek-V3.
    pub shared_experts: u32,
    /// Parameters per routed expert, in billions scaled x10 (e.g. 5 =
    /// 0.5B, 37 = 3.7B). Optional when the upstream model card doesn't
    /// publish a clean value.
    pub params_per_expert_x10: Option<u32>,
}

/// Flavour of speculative decoding declared by a catalog entry's
/// drafter pairing.
///
/// llama.cpp distinguishes two speculative-decoding regimes via the
/// `--spec-type` flag:
///
/// - `Generic` (`--spec-type draft`): classical two-model speculative
///   decoding where the drafter is an independent smaller LLM with the
///   same tokenizer (e.g. Qwen 3 32B target + Qwen 3 0.6B drafter).
///   Draft tokens are sampled freely; the target verifies them in a
///   single batch and accepts the longest matching prefix.
///
/// - `DraftMtp` (`--spec-type draft-mtp`): Multi-Token Prediction —
///   the drafter is an auxiliary head jointly trained with the target
///   (Gemma 4, DeepSeek V3, others). The MTP head shares hidden state
///   with the target and produces tokens consistent with the target's
///   distribution, which means higher accept rates and a real net
///   throughput gain (Unsloth measured 1.5–2.2× on Gemma 4). The
///   drafter GGUF is shipped as a sibling file in the target's repo
///   (e.g. `mtp-gemma-4-12B-it.gguf`).
///
/// `None` means no drafter is paired and the target runs single-token
/// autoregressive sampling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MtpKind {
    /// No drafter paired; standard autoregressive decoding only.
    #[default]
    None,
    /// Classical two-model speculative decoding (`--spec-type draft`).
    Generic,
    /// Jointly-trained Multi-Token-Prediction head (`--spec-type draft-mtp`).
    DraftMtp,
}

/// Per-model serving configuration — the sampler defaults, chat-template
/// handling, and reasoning behaviour a runtime should apply when it loads
/// this model. This is an **intrinsic property of the model** (sourced from
/// the model author's recommendations, primarily Unsloth's per-family
/// guidance), not of any one client. The catalog is the single source of
/// truth: every consumer (Ipnops Edge's llama-server sidecar, any future
/// client) reads the same profile so serving behaviour never drifts between
/// products.
///
/// Sampler fields map directly onto llama.cpp / OpenAI-compatible request
/// parameters (`temperature`, `top_p`, `top_k`, `min_p`). `jinja_required`
/// drives the `--jinja` flag (mandatory for tool calling and for the models
/// — Phi-4, DeepSeek — that emit no tokens without their embedded template).
/// `reasoning_default` is the out-of-the-box thinking mode for hybrid
/// reasoning models.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ServingProfile {
    /// Sampling temperature. Unsloth per-family defaults, e.g. Gemma 1.0,
    /// Qwen3.5 non-thinking 0.7, Mistral/Ministral instruct 0.1.
    pub temperature: f32,
    /// Nucleus sampling top-p.
    pub top_p: f32,
    /// Top-k cutoff. `0` disables top-k (e.g. gpt-oss Harmony).
    pub top_k: u32,
    /// Min-p sampling floor. `0.0` disables it. GLM/Kimi/DeepSeek use 0.01.
    pub min_p: f32,
    /// Presence penalty. `0.0` disables it, which is right for almost every
    /// family. Qwen3-VL is the exception: its instruct card publishes 1.5,
    /// because the vision path otherwise loops on repeated image captions.
    pub presence_penalty: f32,
    /// Whether `--jinja` must be passed (apply the GGUF's embedded chat
    /// template). Required for tool calling and for templates that otherwise
    /// emit empty/garbage output. Effectively always `true` for chat models;
    /// kept explicit so non-chat entries can opt out.
    pub jinja_required: bool,
    /// Default reasoning/thinking mode when the model supports a hybrid
    /// think/no-think toggle. `false` = reasoning off by default (Unsloth's
    /// recommendation for small models and latency-sensitive chat).
    pub reasoning_default: bool,
}

impl Default for ServingProfile {
    /// Neutral, broadly-safe chat defaults (temp 0.7 / top_p 0.8 / top_k 20,
    /// jinja on). Used as a placeholder before [`ServingProfile::for_family`]
    /// fills in the model-author-recommended values, and for any family
    /// without a specific profile.
    fn default() -> Self {
        Self {
            temperature: 0.7,
            top_p: 0.8,
            top_k: 20,
            min_p: 0.0,
            presence_penalty: 0.0,
            jinja_required: true,
            reasoning_default: false,
        }
    }
}

impl ServingProfile {
    /// Recommended serving profile for a catalog `family` (+ architecture for
    /// the diffusion special-case). Encodes the model author's published
    /// sampler guidance — primarily Unsloth's per-family recommendations.
    /// This is the single place per-family serving knowledge lives; the
    /// catalog build pass stamps every entry with the result.
    pub fn for_family(family: &str, architecture: ModelArchitecture) -> Self {
        // DiffusionGemma is a parallel-denoising model — autoregressive
        // samplers don't apply; keep jinja on for its template but use
        // neutral values.
        if matches!(architecture, ModelArchitecture::Gemma4Diffusion) {
            return Self {
                temperature: 0.9,
                top_p: 0.95,
                top_k: 0,
                min_p: 0.0,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: false,
            };
        }
        match family {
            // Gemma 3 / Gemma 4: temp 1.0, top_p 0.95, top_k 64.
            "gemma3" | "gemma4" => Self {
                temperature: 1.0,
                top_p: 0.95,
                top_k: 64,
                min_p: 0.0,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: false,
            },
            // Qwen 3 (original): Unsloth thinking-mode defaults — temp 0.6 /
            // top_p 0.95 / top_k 20 / min_p 0.0. Qwen 3 ships thinking-ON
            // by default; the non-thinking row (0.7 / 0.8 / 20) is for the
            // explicit instruct mode. See https://unsloth.ai/docs/models/tutorials/qwen3-how-to-run-and-fine-tune
            // and the upstream Qwen3 model card. Thinking is on by default
            // so the chat template emits a `<think>` prefix.
            "qwen3" => Self {
                temperature: 0.6,
                top_p: 0.95,
                top_k: 20,
                min_p: 0.0,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: true,
            },
            // Qwen3-VL instruct: temp 0.7 / top_p 0.8 / top_k 20, and the one
            // family with a non-zero presence penalty — 1.5, per Unsloth's
            // published row. The thinking variants use 1.0 / 0.95 / 20 with
            // no penalty; the catalog carries the instruct model.
            // See https://unsloth.ai/docs/models/tutorials/qwen3-how-to-run-and-fine-tune/qwen3-vl-how-to-run-and-fine-tune
            "qwen3-vl" => Self {
                temperature: 0.7,
                top_p: 0.8,
                top_k: 20,
                min_p: 0.0,
                presence_penalty: 1.5,
                jinja_required: true,
                reasoning_default: false,
            },
            // Qwen3-Next: temp 1.0 / top_p 0.95 / top_k 40 / min_p 0.01, and
            // repeat penalty off. Non-thinking — the line emits no `<think>`
            // block at all, so there is no mode to default on.
            // See https://unsloth.ai/docs/models/qwen3-coder-next
            "qwen3-next" => Self {
                temperature: 1.0,
                top_p: 0.95,
                top_k: 40,
                min_p: 0.01,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: false,
            },
            // Qwen-AgentWorld: temp 0.6 / top_p 0.95 / top_k 20 — the Qwen
            // team's own world-model-inference row, lower than the Qwen 3.5
            // family it shares an architecture with. Thinking is on: the
            // model reasons about environment state transitions before
            // predicting the next observation.
            // See https://huggingface.co/Qwen/Qwen-AgentWorld-35B-A3B
            "qwen-agentworld" => Self {
                temperature: 0.6,
                top_p: 0.95,
                top_k: 20,
                min_p: 0.0,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: true,
            },
            // Qwen 3.5 / 3.6: Unsloth thinking-general defaults — temp 1.0 /
            // top_p 0.95 / top_k 20 / min_p 0.0. Both families ship
            // thinking-ON by default and use a vendored chat-template
            // override (froggeric v20) because the upstream embedded
            // jinja has the prompt-drop bug (minja `replace()` swallows
            // user prompt at idx 0). Override is wired in
            // tenzro-inference sidecar.rs TEMPLATE_OVERRIDES — the
            // catalog only carries the sampler profile.
            "qwen3.5" | "qwen3.6" => Self {
                temperature: 1.0,
                top_p: 0.95,
                top_k: 20,
                min_p: 0.0,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: true,
            },
            // Ornith 1.0: post-trained on Qwen 3.5 / Gemma 4, so the Qwen
            // chat template applies, but Deep Reinforce publishes its own
            // sampler row — temp 0.6 / top_p 0.95 / top_k 20 — in the
            // model-card usage example, distinct from the Qwen 3.5 temp 1.0.
            // See https://huggingface.co/deepreinforce-ai/Ornith-1.0-35B
            "ornith" => Self {
                temperature: 0.6,
                top_p: 0.95,
                top_k: 20,
                min_p: 0.0,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: true,
            },
            // gpt-oss Harmony: temp 1.0, top_p 1.0, top_k disabled.
            "gpt-oss" => Self {
                temperature: 1.0,
                top_p: 1.0,
                top_k: 0,
                min_p: 0.0,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: false,
            },
            // Phi-4: temp 0.8 / top_p 0.95; needs --jinja to emit tokens.
            "phi" | "phi3" | "phi4" => Self {
                temperature: 0.8,
                top_p: 0.95,
                top_k: 0,
                min_p: 0.0,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: false,
            },
            // Mistral / Ministral / Nemo: low-temp instruct (0.15).
            "mistral" | "ministral" | "mistral-nemo" => Self {
                temperature: 0.15,
                top_p: 1.0,
                top_k: 0,
                min_p: 0.0,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: false,
            },
            // GLM 5.x: temp 1.0 / top_p 0.95 / min_p 0.01.
            "glm" => Self {
                temperature: 1.0,
                top_p: 0.95,
                top_k: 0,
                min_p: 0.01,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: false,
            },
            // Kimi: temp 0.6 / top_p 0.95 / min_p 0.01.
            "kimi" => Self {
                temperature: 0.6,
                top_p: 0.95,
                top_k: 0,
                min_p: 0.01,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: false,
            },
            // Kimi K3: temp 1.0 / top_p 0.95 per Unsloth's K3 guidance, and
            // reasoning is not optional — the model always emits a thinking
            // block, gated only by `reasoning_effort`.
            "kimi-k3" => Self {
                temperature: 1.0,
                top_p: 0.95,
                top_k: 0,
                min_p: 0.01,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: true,
            },
            // DeepSeek V3/V4: temp 0.6 / top_p 0.95 / min_p 0.01; needs --jinja.
            "deepseek" | "deepseek-v3" | "deepseek-v4" => Self {
                temperature: 0.6,
                top_p: 0.95,
                top_k: 0,
                min_p: 0.01,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: false,
            },
            // MiniMax: same low-temp reasoning family profile.
            "minimax" => Self {
                temperature: 0.6,
                top_p: 0.95,
                top_k: 0,
                min_p: 0.01,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: false,
            },
            // Granite 4: greedy instruct (temp 0.0).
            "granite" | "granite4" => Self {
                temperature: 0.0,
                top_p: 1.0,
                top_k: 0,
                min_p: 0.0,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: false,
            },
            // Nemotron: temp 1.0 / top_p 1.0 chat.
            "nemotron" => Self {
                temperature: 1.0,
                top_p: 1.0,
                top_k: 0,
                min_p: 0.0,
                presence_penalty: 0.0,
                jinja_required: true,
                reasoning_default: false,
            },
            // SmolLM and anything unlisted: neutral chat defaults.
            _ => Self::default(),
        }
    }
}

/// Universal reasoning/thinking-mode policy for a catalog entry.
///
/// Replaces the older `ServingProfile::reasoning_default` bool with a
/// policy that the serving runtime can resolve per-request based on
/// (a) whether the family supports thinking mode at all, (b) the model
/// size, and (c) the caller's `max_tokens` budget. See
/// `docs/serving-policy.md` in tenzro-inference for the design rationale
/// and the per-family threshold table.
///
/// The runtime contract: when `supports_thinking == false`, never inject
/// `chat_template_kwargs.enable_thinking`. When true and `default_mode ==
/// Auto`, resolve to thinking-ON iff the model size is at least
/// `thinking_safe_min_b` AND the caller's budget (or default budget) is
/// at least `thinking_min_budget_tokens`. Below either threshold,
/// thinking-OFF — small models / small budgets in thinking mode are the
/// documented Qwen3.5-0.8B/2B failure mode (model spends the entire
/// budget in `<think>`, emits empty content).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ReasoningPolicy {
    /// Whether the family supports hybrid thinking/non-thinking mode.
    /// False for instruct-only families (mistral, ministral,
    /// mistral-nemo, phi without -reasoning, gemma3-it, gemma4-it,
    /// granite4 instruct). True for qwen3 / qwen3.5 / qwen3.6, gpt-oss,
    /// glm5+, deepseek-v3+, kimi-k2+, minimax-m1/m3, nemotron reasoning,
    /// phi-N-reasoning.
    pub supports_thinking: bool,
    /// Default mode for fresh requests. `Auto` resolves per the size +
    /// budget thresholds below. `Always` / `Never` are escape hatches
    /// for entries where the family-default doesn't apply (e.g. a
    /// distilled instruct of a thinking model).
    pub default_mode: ReasoningMode,
    /// Below this parameter count (in billions; for MoE entries, use
    /// active-parameter count) thinking is OFF even when the family
    /// supports it. Qwen team's own model cards explicitly warn about
    /// qwen3.5-0.8B/2B entering thinking loops; this threshold codifies
    /// the warning across the family.
    pub thinking_safe_min_b: f32,
    /// Minimum total max_tokens budget when thinking is ON. Below this
    /// the runtime forces non-thinking. Qwen's reference code uses
    /// 32_768 as the published min for thinking-mode generation; we
    /// default to family-tuned values (16K for qwen3.5/qwen3.6, 32K
    /// for deepseek/kimi, 8K for gpt-oss/qwen3-original).
    pub thinking_min_budget_tokens: u32,
}

/// Default mode for [`ReasoningPolicy`]. `Auto` is the common case;
/// `Always` / `Never` are explicit overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningMode {
    #[default]
    Auto,
    Always,
    Never,
}

impl Default for ReasoningPolicy {
    /// Safe non-thinking default. Used as the placeholder before
    /// [`ReasoningPolicy::for_family`] fills in the family-correct
    /// values, and for any family without a published policy.
    fn default() -> Self {
        Self {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        }
    }
}

impl ReasoningPolicy {
    /// Recommended reasoning policy for a catalog `family`. Encodes the
    /// per-family published guidance (Qwen team model-card warnings,
    /// Unsloth docs, llama.cpp issue tracker for known thinking-mode
    /// bugs).
    pub fn for_family(family: &str) -> Self {
        match family {
            // Qwen 3 (original): every published size operates in
            // thinking mode by default per the Qwen team's model cards
            // and Unsloth's docs. Smallest is 0.6B — no documented
            // failure mode at that size. Use a low safe-min so all
            // sizes get thinking-on; budget min matches the original
            // Qwen3 reference of 8K.
            "qwen3" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 0.0,
                thinking_min_budget_tokens: 8_192,
            },
            // Qwen 3.5 / 3.6: thinking-on by default but small sizes
            // (0.8B, 2B) carry an explicit thinking-loop warning on
            // their own model cards — reproduced locally on 0.8B with
            // a 200-token budget producing empty content. Safe-min 4B
            // matches Unsloth's published "Small series" carve-out;
            // budget min 16K is the empirically-safe floor for
            // thinking-mode multi-turn at these sizes (Qwen's reference
            // uses 32K for hard problems, 8K is too tight for chat).
            "qwen3.5" | "qwen3.6" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 4.0,
                thinking_min_budget_tokens: 16_384,
            },
            // Qwen-AgentWorld: thinking on by default — the card states the
            // model reasons about environment state transitions inside
            // `<think>` before emitting the predicted observation, so it is
            // not an optional mode. Safe-min 0.0 rather than the Qwen 3.5
            // family's 4.0: that carve-out guards small models that loop,
            // and this one is published as thinking-first at 3B active.
            "qwen-agentworld" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 0.0,
                thinking_min_budget_tokens: 16_384,
            },
            // Ornith 1.0: agentic-coding family whose RL objective is the
            // reasoning trajectory itself; vLLM serving uses the
            // `reasoning_content` key. Smallest member is 9B dense, so the
            // Qwen 3.5 Small-series carve-out doesn't bite; budget min
            // matches the family it was post-trained from.
            "ornith" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 4.0,
                thinking_min_budget_tokens: 16_384,
            },
            // Laguna S 2.1: native interleaved thinking between tool calls,
            // per-request `enable_thinking`. Poolside's card recommends
            // thinking-on with preserved reasoning blocks for agentic
            // coding — the model may stop reasoning in follow-up steps if
            // prior thinking blocks are dropped. 8B active, single size.
            "laguna" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 0.0,
                thinking_min_budget_tokens: 16_384,
            },
            // Inkling: thinking is exposed as an explicit toggle by every
            // published serving path. 41B active, single size — no small
            // variant to guard against.
            "inkling" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 0.0,
                thinking_min_budget_tokens: 32_768,
            },
            // gpt-oss Harmony: defaults thinking-on; smallest published
            // sizes are well above any concerning threshold.
            "gpt-oss" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 0.0,
                thinking_min_budget_tokens: 8_192,
            },
            // GLM 5 / 6: thinking-on for the 9B+ chat variants per the
            // model cards.
            "glm" | "glm5" | "glm6" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 9.0,
                thinking_min_budget_tokens: 16_384,
            },
            // DeepSeek V3 / V4: pure-reasoning, dense or MoE. Largest
            // sizes only — set the safe-min conservatively at 13B
            // (smallest published distill) and require the larger 32K
            // budget the model card recommends.
            "deepseek" | "deepseek-v3" | "deepseek-v4" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 13.0,
                thinking_min_budget_tokens: 32_768,
            },
            // Kimi K2 family: all MoE, all thinking. K2.6 is the hybrid
            // variant. 32K budget matches the published guidance.
            "kimi" | "kimi-k2" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 0.0,
                thinking_min_budget_tokens: 32_768,
            },
            // Kimi K3: thinking is unconditional — the template emits a
            // reasoning block on every turn and `reasoning_effort` sets its
            // depth rather than switching it off.
            "kimi-k3" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Always,
                thinking_safe_min_b: 0.0,
                thinking_min_budget_tokens: 32_768,
            },
            // MiniMax M1 / M3: reasoning MoE. M1 is dense-equivalent
            // 40B, M3 is MoE — both safe with thinking on.
            "minimax" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 0.0,
                thinking_min_budget_tokens: 16_384,
            },
            // Nemotron Nano: reasoning is the explicit purpose of the
            // -Nano series. Match Unsloth's guidance.
            "nemotron" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 4.0,
                thinking_min_budget_tokens: 16_384,
            },
            // Phi-N-reasoning variants: thinking-mode only when the id
            // carries a -reasoning suffix; the catalog's family for
            // those is "phi-reasoning". Plain "phi" is instruct.
            "phi-reasoning" => Self {
                supports_thinking: true,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 4.0,
                thinking_min_budget_tokens: 16_384,
            },
            // Everything else: instruct-only families. Don't touch
            // enable_thinking at all (the GGUF template handles it).
            _ => Self::default(),
        }
    }
}

/// Per-entry chat-template fix policy. Replaces the inference-client's
/// hand-maintained `TEMPLATE_OVERRIDES` map. The catalog publishes
/// which fix (if any) each family needs; the client maps logical
/// filenames to its bundled `templates/` directory.
///
/// Adding a new known-broken family: add the row in
/// [`TemplateFix::for_family`] and drop the vendored jinja in the
/// inference client's `templates/` dir.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "kind", content = "spec")]
pub enum TemplateFix {
    /// Use the GGUF's embedded jinja as-is. The common case.
    #[default]
    None,
    /// Use a vendored fix shipped in the inference client. The string
    /// is the bundled jinja filename (e.g.
    /// `"qwen3.5-3.6-froggeric-v20.jinja"`). The catalog declares
    /// WHICH fix; the client supplies the file.
    Vendored { filename: String },
}

impl TemplateFix {
    /// Recommended chat-template fix for a catalog `family`. Currently
    /// only Qwen 3.5 / 3.6 ship a known-bad embedded template; froggeric
    /// v20 patches the prompt-drop + empty-think bugs that otherwise
    /// produce empty-content multi-turn output. See
    /// <https://huggingface.co/froggeric/Qwen-Fixed-Chat-Templates> and
    /// <https://github.com/ggml-org/llama.cpp/issues/13178>.
    pub fn for_family(family: &str) -> Self {
        match family {
            "qwen3.5" | "qwen3.6" => Self::Vendored {
                filename: "qwen3.5-3.6-froggeric-v20.jinja".to_string(),
            },
            _ => Self::None,
        }
    }
}

/// Parse a catalog `parameters` string (e.g. "0.8B", "27B",
/// "30B-A3B", "1T (MoE, 32B active)") into a billions-of-active-params
/// float that the [`ReasoningPolicy`] threshold check can compare
/// against. For MoE entries we use the **active** parameter count, not
/// the total — thinking-mode coherence correlates with active path
/// width, not total parameters.
pub fn parse_params_active_b(parameters: &str) -> f32 {
    // Look for "(... XB active)" first — MoE form.
    if let Some(idx) = parameters.find("active") {
        let digits = parameters[..idx].trim_end().trim_end_matches(['B', 'b']);
        let num_start = digits
            .rfind(|c: char| !c.is_ascii_digit() && c != '.')
            .map_or(0, |i| i + 1);
        if let Ok(v) = digits[num_start..].parse::<f32>() {
            return v;
        }
    }
    // Look for "<N>B-A<M>B" (e.g. "30B-A3B") — take the A part.
    if let Some(a_idx) = parameters.find("-A") {
        let after = &parameters[a_idx + 2..];
        let num_end = after
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(after.len());
        if let Ok(v) = after[..num_end].parse::<f32>() {
            return v;
        }
    }
    // Plain "<N>B" — dense.
    let trimmed = parameters.trim().trim_end_matches(['B', 'b']);
    let num_end = trimmed
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(trimmed.len());
    trimmed[..num_end].parse::<f32>().unwrap_or(0.0)
}

/// Model architecture — informational only.
///
/// llama.cpp auto-detects the architecture from GGUF metadata, so this enum
/// is used for UI display, catalog filtering, and documentation purposes.
/// All listed architectures are fully supported by llama.cpp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelArchitecture {
    #[default]
    Llama,
    Qwen2,
    Qwen3,
    Qwen3Moe,
    Qwen35,
    Qwen35Moe,
    Qwen36,
    Qwen36Moe,
    /// Qwen3-VL: the Qwen 3 decoder plus a vision tower, served through
    /// llama.cpp's mmproj path rather than one of the ONNX vision
    /// runtimes.
    Qwen3Vl,
    /// Qwen3-Next: the hybrid gated-delta-net attention line. No `Moe`
    /// suffix because — unlike Qwen3 / Qwen3.5 / Qwen3.6, which each ship
    /// a dense and an MoE sibling — every released Qwen3-Next checkpoint
    /// is MoE, so there is no dense variant to distinguish it from.
    Qwen3Next,
    Gemma3,
    Gemma4,
    Gemma4Moe,
    /// Gemma 4-family diffusion variant (DiffusionGemma) — generates
    /// blocks of tokens via parallel denoising over a fixed canvas
    /// rather than autoregressive next-token sampling. Speculative
    /// decoding / MTP do not apply. Serving requires a diffusion-
    /// aware runtime (Unsloth Studio or llama.cpp PR #24423+).
    Gemma4Diffusion,
    Mistral,
    MistralMoe,
    Phi3,
    Glm,
    Kimi,
    MiniMax,
    DeepSeekV3,
    GptOss,
    Granite,
    GraniteH,
    Laguna,
    Inkling,
}

impl std::fmt::Display for ModelArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Llama => write!(f, "llama"),
            Self::Qwen2 => write!(f, "qwen2"),
            Self::Qwen3 => write!(f, "qwen3"),
            Self::Qwen3Moe => write!(f, "qwen3moe"),
            Self::Qwen35 => write!(f, "qwen35"),
            Self::Qwen35Moe => write!(f, "qwen35moe"),
            Self::Qwen36 => write!(f, "qwen36"),
            Self::Qwen36Moe => write!(f, "qwen36moe"),
            Self::Qwen3Vl => write!(f, "qwen3vl"),
            Self::Qwen3Next => write!(f, "qwen3next"),
            Self::Gemma3 => write!(f, "gemma3"),
            Self::Gemma4 => write!(f, "gemma4"),
            Self::Gemma4Moe => write!(f, "gemma4moe"),
            Self::Gemma4Diffusion => write!(f, "gemma4diffusion"),
            Self::Mistral => write!(f, "mistral"),
            Self::MistralMoe => write!(f, "mistralmoe"),
            Self::Phi3 => write!(f, "phi3"),
            Self::Glm => write!(f, "glm"),
            Self::Kimi => write!(f, "kimi"),
            Self::MiniMax => write!(f, "minimax"),
            Self::DeepSeekV3 => write!(f, "deepseekv3"),
            Self::GptOss => write!(f, "gpt-oss"),
            Self::Granite => write!(f, "granite"),
            Self::GraniteH => write!(f, "granite-h"),
            Self::Laguna => write!(f, "laguna"),
            Self::Inkling => write!(f, "inkling"),
        }
    }
}

/// A curated ONNX vision encoder entry.
///
/// Vision encoders run on the `VisionRuntime` (ORT-backed) rather than
/// llama.cpp, so they have a separate metadata shape — no GGUF
/// quantization, no llama.cpp architecture enum, but they do carry the
/// preprocessing parameters the runtime needs (input size, normalization,
/// embedding dim).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxVisionEntry {
    /// Internal model ID (e.g. "clip-vit-b32").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family (e.g. "clip", "siglip2", "dinov3").
    pub family: String,
    /// HuggingFace repository ID (e.g. "Xenova/clip-vit-base-patch32").
    pub hf_repo: String,
    /// ONNX filename within the repo (e.g. "onnx/vision_model.onnx").
    pub hf_filename: String,
    /// Native input resolution in pixels (square — H == W).
    pub input_size: u32,
    /// Output embedding dimension.
    pub embedding_dim: usize,
    /// Recommended preprocessing normalization key — one of
    /// `"clip"`, `"imagenet"`, `"siglip"`. Maps directly to
    /// `ImageNormalization::{CLIP, IMAGENET, SIGLIP}` at load time.
    pub normalization: String,
    /// Approximate file size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB to load.
    pub min_ram_gb: u32,
    /// License (inherited from upstream base model where applicable).
    pub license: String,
    /// License tier — drives the gating logic in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX vision encoder catalog.
///
/// All entries verified to have **ungated, single-file ONNX exports** on
/// HuggingFace as of 2026-04. Files come from `Xenova/*` and
/// `onnx-community/*` mirrors of upstream base models.
pub fn get_vision_catalog() -> Vec<OnnxVisionEntry> {
    vec![
        // ── CLIP family (MIT, OpenAI) ──────────────────────────────
        OnnxVisionEntry {
            id: "clip-vit-b32".into(),
            name: "CLIP ViT-B/32".into(),
            family: "clip".into(),
            hf_repo: "Xenova/clip-vit-base-patch32".into(),
            hf_filename: "onnx/vision_model.onnx".into(),
            input_size: 224,
            embedding_dim: 512,
            normalization: "clip".into(),
            size_bytes: 352_000_000,
            min_ram_gb: 2,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "OpenAI CLIP ViT-B/32 — compact image encoder, 512-dim embeddings".into(),
        },
        OnnxVisionEntry {
            id: "clip-vit-l14".into(),
            name: "CLIP ViT-L/14".into(),
            family: "clip".into(),
            hf_repo: "Xenova/clip-vit-large-patch14".into(),
            hf_filename: "onnx/vision_model.onnx".into(),
            input_size: 224,
            embedding_dim: 768,
            normalization: "clip".into(),
            size_bytes: 1_220_000_000,
            min_ram_gb: 4,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "OpenAI CLIP ViT-L/14 — large image encoder, 768-dim embeddings".into(),
        },
        // ── SigLIP / SigLIP2 (Apache 2.0, Google) ─────────────────
        OnnxVisionEntry {
            id: "siglip-base-224".into(),
            name: "SigLIP base patch16-224".into(),
            family: "siglip".into(),
            hf_repo: "Xenova/siglip-base-patch16-224".into(),
            hf_filename: "onnx/vision_model.onnx".into(),
            input_size: 224,
            embedding_dim: 768,
            normalization: "siglip".into(),
            size_bytes: 372_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Google SigLIP base — sigmoid-loss image-text encoder".into(),
        },
        OnnxVisionEntry {
            id: "siglip2-base-224".into(),
            name: "SigLIP2 base patch16-224".into(),
            family: "siglip2".into(),
            hf_repo: "onnx-community/siglip2-base-patch16-224-ONNX".into(),
            hf_filename: "onnx/vision_model.onnx".into(),
            input_size: 224,
            embedding_dim: 768,
            normalization: "siglip".into(),
            size_bytes: 372_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Google SigLIP2 base — improved multilingual image-text encoder".into(),
        },
        OnnxVisionEntry {
            id: "siglip2-large-256".into(),
            name: "SigLIP2 large patch16-256".into(),
            family: "siglip2".into(),
            hf_repo: "onnx-community/siglip2-large-patch16-256-ONNX".into(),
            hf_filename: "onnx/vision_model.onnx".into(),
            input_size: 256,
            embedding_dim: 1024,
            normalization: "siglip".into(),
            size_bytes: 1_300_000_000,
            min_ram_gb: 4,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Google SigLIP2 large — high-fidelity multilingual image-text encoder"
                .into(),
        },
        OnnxVisionEntry {
            id: "siglip2-so400m-384".into(),
            name: "SigLIP2 SO400M patch14-384".into(),
            family: "siglip2".into(),
            hf_repo: "onnx-community/siglip2-so400m-patch14-384-ONNX".into(),
            hf_filename: "onnx/vision_model.onnx".into(),
            input_size: 384,
            embedding_dim: 1152,
            normalization: "siglip".into(),
            size_bytes: 1_700_000_000,
            min_ram_gb: 6,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Google SigLIP2 SO400M-384 — flagship encoder, top zero-shot accuracy"
                .into(),
        },
        // ── DINOv3 family (DINOv3 License — commercial-OK custom) ─
        // Released Sep 2025; ONNX exports at onnx-community mirrors.
        // License is bespoke (not Apache); commercial use permitted with
        // restrictions on derivative-model redistribution. See:
        // https://huggingface.co/facebook/dinov3-vits16-pretrain-lvd1689m
        OnnxVisionEntry {
            id: "dinov3-vits16".into(),
            name: "DINOv3 ViT-S/16".into(),
            family: "dinov3".into(),
            hf_repo: "onnx-community/dinov3-vits16-pretrain-lvd1689m-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            input_size: 224,
            embedding_dim: 384,
            normalization: "imagenet".into(),
            size_bytes: 92_000_000,
            min_ram_gb: 1,
            license: "DINOv3 License".into(),
            license_tier: LicenseTier::CommercialCustom,
            description: "Meta DINOv3 ViT-S/16 — next-gen self-supervised features, edge-tier"
                .into(),
        },
        OnnxVisionEntry {
            id: "dinov3-vitb16".into(),
            name: "DINOv3 ViT-B/16".into(),
            family: "dinov3".into(),
            hf_repo: "onnx-community/dinov3-vitb16-pretrain-lvd1689m-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            input_size: 224,
            embedding_dim: 768,
            normalization: "imagenet".into(),
            size_bytes: 350_000_000,
            min_ram_gb: 2,
            license: "DINOv3 License".into(),
            license_tier: LicenseTier::CommercialCustom,
            description: "Meta DINOv3 ViT-B/16 — flagship self-supervised features, base-tier"
                .into(),
        },
        OnnxVisionEntry {
            id: "dinov3-vitl16".into(),
            name: "DINOv3 ViT-L/16".into(),
            family: "dinov3".into(),
            hf_repo: "onnx-community/dinov3-vitl16-pretrain-lvd1689m-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            input_size: 224,
            embedding_dim: 1024,
            normalization: "imagenet".into(),
            size_bytes: 1_240_000_000,
            min_ram_gb: 4,
            license: "DINOv3 License".into(),
            license_tier: LicenseTier::CommercialCustom,
            description: "Meta DINOv3 ViT-L/16 — large self-supervised features".into(),
        },
    ]
}

/// Look up an ONNX vision encoder by its internal ID.
pub fn get_vision_model_by_id(id: &str) -> Option<OnnxVisionEntry> {
    get_vision_catalog().into_iter().find(|m| m.id == id)
}

/// A curated ONNX timeseries-forecaster entry.
///
/// Forecasters run on the `TimeseriesRuntime` (ORT-backed) and have a
/// distinct shape from the LLM and vision catalogs: no token vocabulary
/// or pixel preprocessing, just the I/O contract the runtime needs to
/// dispatch a forecast — `context_length` (input window), `max_horizon`
/// (output prediction length), and `n_quantiles` (0 for point forecasts,
/// >0 for quantile heads where the output tensor has shape
/// > `[1, max_horizon, n_quantiles]`).
///
/// Source of truth for buildable models: `tools/ts-export/targets.toml`
/// (the export harness that produces the artifacts referenced here).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxForecastEntry {
    /// Internal model ID (e.g. "timesfm-2.5-200m").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Architecture family (e.g. "timesfm").
    pub family: String,
    /// Upstream HuggingFace repository ID (PyTorch source weights).
    pub hf_repo: String,
    /// ONNX filename produced by the export harness (relative to
    /// the artifact dir — typically `model.onnx`).
    pub hf_filename: String,
    /// Maximum input context length in timesteps.
    pub context_length: usize,
    /// Maximum forecast horizon in timesteps.
    pub max_horizon: usize,
    /// Number of quantiles in the output head. `0` means a point
    /// forecast (shape `[1, max_horizon]`); `>0` means a quantile
    /// forecast (shape `[1, max_horizon, n_quantiles]`).
    pub n_quantiles: usize,
    /// Name of the ONNX output tensor holding the forecast. `None` means
    /// the graph's first output is the forecast. Multi-output graphs need
    /// this set, otherwise the runtime reads a hidden-state tensor.
    pub output_name: Option<String>,
    /// Fixed leading batch dimension the graph requires. Almost always
    /// `1`; TimesFM 2.5 needs `2` because its decoder averages across the
    /// batch axis for flip invariance. The runtime tiles the input to
    /// this width and reads row 0.
    pub batch_size: usize,
    /// Approximate parameter count label (e.g. "200M").
    pub parameters: String,
    /// Approximate ONNX file size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB to load.
    pub min_ram_gb: u32,
    /// License (inherited from upstream model).
    pub license: String,
    /// License tier — drives gating in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX timeseries-forecaster catalog.
///
/// Every entry resolves to a single-file ONNX artifact compatible with
/// `GenericForecast`. Entries whose weights are Apache-2.0 or MIT also
/// carry a re-export path in `tools/ts-export/targets.toml` so we can
/// rebuild the artifact if the hosted one goes stale; entries under
/// attribution or revenue-threshold terms are served only from the
/// upstream ONNX and are gated by `license_tier`.
pub fn get_forecast_catalog() -> Vec<OnnxForecastEntry> {
    vec![
        // ── TimesFM 2.5 (Apache 2.0, Google) ───────────────────────
        // Decoder-only transformer with patch tokenizer. 10 quantiles.
        // Community ONNX export (pdufour) is the only live-loadable form;
        // upstream google/timesfm-2.5-200m-transformers ships PyTorch
        // weights. Requires batch_size=2 (force_flip_invariance: true in
        // config) and an explicit output_name, because the graph's first
        // output is last_hidden_state rather than the forecast.
        OnnxForecastEntry {
            id: "timesfm-2.5-200m".into(),
            name: "TimesFM 2.5 200M".into(),
            family: "timesfm".into(),
            hf_repo: "pdufour/timesfm-2.5-200m-transformers-onnx".into(),
            hf_filename: "onnx/model.onnx".into(),
            context_length: 2048,
            max_horizon: 128,
            n_quantiles: 10,
            output_name: Some("full_predictions".into()),
            batch_size: 2,
            parameters: "200M".into(),
            size_bytes: 1_001_713_626,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description:
                "Google TimesFM 2.5 — foundation timeseries forecaster, patch-tokenized decoder"
                    .into(),
        },
        // ── Chronos-2 Small (Apache 2.0, Amazon) ────────────────────
        // A five-input encoder, not a single-tensor forecaster: it takes
        // `context`, `group_ids`, `attention_mask` (float, not int64), and a
        // pair of covariate tensors, and returns `quantile_preds` shaped
        // [batch, 13, 672] — quantiles *before* time. `GenericForecast`
        // would read a quantile index as a timestep, so this entry is served
        // by the `chronos2` adapter, selected on `family`.
        //
        // The covariate tensors cannot be omitted or sent empty even with no
        // covariates: the graph reshapes them to [batch, 42, 16], so a
        // zero-length tensor fails inside the model. The adapter sends them
        // full-width with an all-zero mask.
        //
        // Horizon is fixed at 672 (42 patches × 16) by the export; shorter
        // requests are truncations of that single pass.
        OnnxForecastEntry {
            id: "chronos-2-small".into(),
            name: "Chronos-2 Small".into(),
            family: "chronos2".into(),
            hf_repo: "OpenSTEF/chronos-2-small-onnx".into(),
            hf_filename: "chronos-2-small.onnx".into(),
            context_length: 5760,
            max_horizon: 672,
            n_quantiles: 13,
            output_name: Some("quantile_preds".into()),
            batch_size: 1,
            parameters: "120M".into(),
            size_bytes: 112_083_145,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description:
                "Amazon Chronos-2 — multivariate-capable foundation forecaster, 13-quantile head"
                    .into(),
        },
        // ── TiRex 35M (NXAI Community License, NXAI) ────────────────
        // sLSTM recurrent forecaster, not a transformer. Upstream ships
        // tirex.onnx in the model repo, so no re-export is involved.
        // One forward pass emits exactly 32 steps with 9 quantiles;
        // longer horizons would need an autoregressive roll-forward that
        // GenericForecast does not do, so max_horizon is the single-pass
        // figure. Median sits at quantile index 4, which is what
        // GenericForecast reads (q / 2).
        OnnxForecastEntry {
            id: "tirex-35m".into(),
            name: "TiRex 35M".into(),
            family: "tirex".into(),
            hf_repo: "NX-AI/TiRex".into(),
            hf_filename: "tirex.onnx".into(),
            context_length: 2048,
            max_horizon: 32,
            n_quantiles: 9,
            output_name: None,
            batch_size: 1,
            parameters: "35M".into(),
            size_bytes: 142_243_285,
            min_ram_gb: 1,
            license: "NXAI Community License".into(),
            license_tier: LicenseTier::CommercialCustom,
            description: "NXAI TiRex 35M — sLSTM zero-shot forecaster with a 9-quantile head"
                .into(),
        },
    ]
}

/// Look up an ONNX timeseries forecaster by its internal ID.
pub fn get_forecast_model_by_id(id: &str) -> Option<OnnxForecastEntry> {
    get_forecast_catalog().into_iter().find(|m| m.id == id)
}

// ─────────────────────────────────────────────────────────────────────
// Text embedding catalog.
// ─────────────────────────────────────────────────────────────────────

/// A curated ONNX text-embedding entry.
///
/// Text encoders that map `[B, L]` token sequences to `[B, D]` dense
/// vectors. Served via the same ORT runtime path as vision encoders,
/// not via llama.cpp — even Gemma-derived encoders behave better as
/// bidirectional ONNX exports than as decoder-only GGUF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxTextEmbeddingEntry {
    /// Internal model ID (e.g. "qwen3-embedding-0.6b").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family (e.g. "qwen3-embedding", "embeddinggemma", "bge-m3").
    pub family: String,
    /// HuggingFace repository ID.
    pub hf_repo: String,
    /// ONNX filename within the repo.
    pub hf_filename: String,
    /// Optional external-data sidecar (ONNX `model.onnx_data`) that large
    /// exports ship alongside `model.onnx`. When set, the model is fetched
    /// as a bundle so the sidecar lands next to the graph file and ORT
    /// resolves it via the relative path in the `external_data` proto
    /// field. Empty when the export is self-contained (single-file).
    #[serde(default)]
    pub external_data_filename: String,
    /// Tokenizer filename (typically "tokenizer.json"). Loaded by the runtime.
    pub tokenizer_filename: String,
    /// Maximum sequence length the tokenizer/model accepts.
    pub max_sequence_length: u32,
    /// Native output embedding dimension (full vector, before any
    /// Matryoshka truncation).
    pub embedding_dim: u32,
    /// Optional Matryoshka dims allowed (e.g. `vec![512, 256, 128]` for
    /// EmbeddingGemma-300M). Empty means no MRL — only `embedding_dim`.
    pub matryoshka_dims: Vec<u32>,
    /// Whether the model supports fp16 activations. Some ONNX exports
    /// (e.g. EmbeddingGemma) require fp32 due to numerical sensitivity.
    pub supports_fp16: bool,
    /// Approximate file size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB to load.
    pub min_ram_gb: u32,
    /// License (inherited from upstream).
    pub license: String,
    /// License tier — drives gating in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX text-embedding catalog.
///
/// Verified 2026 additions: Qwen3-Embedding family (#1 on MTEB
/// multilingual June 2025), EmbeddingGemma 300M (Matryoshka edge-tier),
/// and BGE-M3 (multilingual retrieval classic).
pub fn get_text_embedding_catalog() -> Vec<OnnxTextEmbeddingEntry> {
    vec![
        // ── Qwen3-Embedding (Apache 2.0, Alibaba) ──────────────────
        // #1 on MTEB multilingual (June 2025). Hidden dim varies by tier.
        OnnxTextEmbeddingEntry {
            id: "qwen3-embedding-0.6b".into(),
            name: "Qwen3-Embedding 0.6B".into(),
            family: "qwen3-embedding".into(),
            hf_repo: "onnx-community/Qwen3-Embedding-0.6B-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            external_data_filename: "onnx/model.onnx_data".into(),
            tokenizer_filename: "tokenizer.json".into(),
            max_sequence_length: 32768,
            embedding_dim: 1024,
            matryoshka_dims: vec![],
            supports_fp16: true,
            size_bytes: 2_400_000_000,
            min_ram_gb: 3,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Qwen3-Embedding 0.6B — multilingual text embeddings, edge-tier".into(),
        },
        OnnxTextEmbeddingEntry {
            id: "qwen3-embedding-4b".into(),
            name: "Qwen3-Embedding 4B".into(),
            family: "qwen3-embedding".into(),
            hf_repo: "onnx-community/Qwen3-Embedding-4B-ONNX".into(),
            hf_filename: "model.onnx".into(),
            external_data_filename: "model.onnx_data".into(),
            tokenizer_filename: "tokenizer.json".into(),
            max_sequence_length: 32768,
            embedding_dim: 2560,
            matryoshka_dims: vec![],
            supports_fp16: true,
            size_bytes: 16_100_000_000,
            min_ram_gb: 20,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Qwen3-Embedding 4B — mid-tier multilingual text embeddings".into(),
        },
        OnnxTextEmbeddingEntry {
            id: "qwen3-embedding-8b".into(),
            name: "Qwen3-Embedding 8B".into(),
            family: "qwen3-embedding".into(),
            hf_repo: "onnx-community/Qwen3-Embedding-8B-ONNX".into(),
            hf_filename: "model.onnx".into(),
            external_data_filename: "model.onnx_data".into(),
            tokenizer_filename: "tokenizer.json".into(),
            max_sequence_length: 32768,
            embedding_dim: 4096,
            matryoshka_dims: vec![],
            supports_fp16: true,
            size_bytes: 30_300_000_000,
            min_ram_gb: 36,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Qwen3-Embedding 8B — flagship multilingual text embeddings".into(),
        },
        // ── EmbeddingGemma 300M (Gemma terms, Google) ──────────────
        // Matryoshka 768→512→256→128. fp32 only.
        OnnxTextEmbeddingEntry {
            id: "embeddinggemma-300m".into(),
            name: "EmbeddingGemma 300M".into(),
            family: "embeddinggemma".into(),
            hf_repo: "onnx-community/embeddinggemma-300m-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            external_data_filename: "onnx/model.onnx_data".into(),
            tokenizer_filename: "tokenizer.json".into(),
            max_sequence_length: 2048,
            embedding_dim: 768,
            matryoshka_dims: vec![512, 256, 128],
            supports_fp16: false,
            size_bytes: 1_235_000_000,
            min_ram_gb: 3,
            license: "Gemma Terms of Use".into(),
            license_tier: LicenseTier::CommercialCustom,
            description: "Google EmbeddingGemma 300M — Matryoshka edge embeddings, fp32-only"
                .into(),
        },
        // ── BGE-M3 (MIT, BAAI) ─────────────────────────────────────
        // Multilingual + multi-functional (dense, sparse, ColBERT) — dense only here.
        OnnxTextEmbeddingEntry {
            id: "bge-m3".into(),
            name: "BGE-M3".into(),
            family: "bge".into(),
            hf_repo: "BAAI/bge-m3".into(),
            hf_filename: "onnx/model.onnx".into(),
            external_data_filename: "onnx/model.onnx_data".into(),
            tokenizer_filename: "tokenizer.json".into(),
            max_sequence_length: 8192,
            embedding_dim: 1024,
            matryoshka_dims: vec![],
            supports_fp16: true,
            size_bytes: 2_270_000_000,
            min_ram_gb: 4,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "BAAI BGE-M3 — multilingual multi-granularity retrieval encoder".into(),
        },
        // ── ModernBERT embedding variants (Apache 2.0) ─────────────
        // Bidirectional RoPE encoder, 8192 context, mean pooling.
        // The base masked-LM checkpoint is not retrieval-tuned; these
        // are the embedding-finetuned variants (mean-pool at inference).
        OnnxTextEmbeddingEntry {
            id: "modernbert-embed-base".into(),
            name: "ModernBERT-embed base".into(),
            family: "modernbert".into(),
            hf_repo: "nomic-ai/modernbert-embed-base".into(),
            hf_filename: "onnx/model.onnx".into(),
            external_data_filename: String::new(),
            tokenizer_filename: "tokenizer.json".into(),
            max_sequence_length: 8192,
            embedding_dim: 768,
            matryoshka_dims: vec![256],
            supports_fp16: true,
            size_bytes: 596_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description:
                "ModernBERT-embed base — 8192-context mean-pooled retrieval encoder, Matryoshka 256"
                    .into(),
        },
        OnnxTextEmbeddingEntry {
            id: "modernbert-embed-large".into(),
            name: "ModernBERT-embed large".into(),
            family: "modernbert".into(),
            hf_repo: "lightonai/modernbert-embed-large".into(),
            hf_filename: "onnx/model.onnx".into(),
            external_data_filename: String::new(),
            tokenizer_filename: "tokenizer.json".into(),
            max_sequence_length: 8192,
            embedding_dim: 1024,
            matryoshka_dims: vec![],
            supports_fp16: true,
            size_bytes: 1_580_000_000,
            min_ram_gb: 3,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "ModernBERT-embed large — 8192-context mean-pooled retrieval encoder"
                .into(),
        },
    ]
}

/// Look up an ONNX text-embedding model by its internal ID.
pub fn get_text_embedding_model_by_id(id: &str) -> Option<OnnxTextEmbeddingEntry> {
    get_text_embedding_catalog()
        .into_iter()
        .find(|m| m.id == id)
}

// ─────────────────────────────────────────────────────────────────────
// Segmentation catalog.
// ─────────────────────────────────────────────────────────────────────

/// A curated ONNX segmentation model entry.
///
/// SAM-family models split into an image encoder (cached per image) and
/// a prompt decoder (mask predictor). Both are required at inference
/// time, so the artifact is a multi-file `Bundle`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxSegmentationEntry {
    /// Internal model ID (e.g. "sam2-base", "edgesam").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family (e.g. "sam3", "sam2", "edgesam", "mobilesam").
    pub family: String,
    /// HuggingFace repository ID.
    pub hf_repo: String,
    /// Encoder ONNX filename within the bundle.
    pub encoder_filename: String,
    /// Decoder ONNX filename within the bundle.
    pub decoder_filename: String,
    /// Native input resolution.
    pub input_size: u32,
    /// Approximate total bundle size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB.
    pub min_ram_gb: u32,
    /// License (inherited from upstream).
    pub license: String,
    /// License tier — drives gating in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX segmentation catalog.
pub fn get_segmentation_catalog() -> Vec<OnnxSegmentationEntry> {
    // SAM 3 / SAM 3.1 live in [`get_text_segmentation_catalog`] — they
    // ship a 3-graph bundle (image encoder + CLIP language encoder +
    // detection-shaped decoder) and need an open-vocabulary text prompt.
    // Their I/O contract doesn't fit the SAM-1/SAM-2 single-mask
    // `Segmenter` trait, so they're routed through
    // `text_segmentation_runtime` instead.
    vec![
        // ── SAM 2 (community ONNX export — vietanhdev / samexporter) ─
        // Meta source is Apache 2.0; ONNX exports inherit that tier.
        OnnxSegmentationEntry {
            id: "sam2-base".into(),
            name: "SAM 2 base".into(),
            family: "sam2".into(),
            hf_repo: "vietanhdev/segment-anything-2-onnx-models".into(),
            encoder_filename: "sam2_hiera_base_plus.encoder.onnx".into(),
            decoder_filename: "sam2_hiera_base_plus.decoder.onnx".into(),
            input_size: 1024,
            size_bytes: 320_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Meta SAM 2 base (community ONNX export) — previous-gen flagship".into(),
        },
        OnnxSegmentationEntry {
            id: "sam2-large".into(),
            name: "SAM 2 large".into(),
            family: "sam2".into(),
            hf_repo: "vietanhdev/segment-anything-2-onnx-models".into(),
            encoder_filename: "sam2_hiera_large.encoder.onnx".into(),
            decoder_filename: "sam2_hiera_large.decoder.onnx".into(),
            input_size: 1024,
            size_bytes: 900_000_000,
            min_ram_gb: 4,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "Meta SAM 2 large (community ONNX export) — high-fidelity".into(),
        },
        // ── EdgeSAM (NTU S-Lab 1.0 — non-commercial) ────────────────
        OnnxSegmentationEntry {
            id: "edgesam".into(),
            name: "EdgeSAM".into(),
            family: "edgesam".into(),
            hf_repo: "chongzhou/EdgeSAM".into(),
            encoder_filename: "edge_sam_3x_encoder.onnx".into(),
            decoder_filename: "edge_sam_3x_decoder.onnx".into(),
            input_size: 1024,
            size_bytes: 38_000_000,
            min_ram_gb: 1,
            license: "NTU S-Lab License 1.0".into(),
            license_tier: LicenseTier::NonCommercial,
            description: "EdgeSAM — ultra-compact 9.6M-param segmentation (research-only)".into(),
        },
        // ── MobileSAM (Apache 2.0) — edge tier ─────────────────────
        OnnxSegmentationEntry {
            id: "mobilesam".into(),
            name: "MobileSAM".into(),
            family: "mobilesam".into(),
            hf_repo: "Acly/MobileSAM".into(),
            encoder_filename: "mobile_sam_image_encoder.onnx".into(),
            // `_single` rather than `_multi`: this runtime's decoder ABI
            // returns one mask per prompt.
            decoder_filename: "sam_mask_decoder_single.onnx".into(),
            input_size: 1024,
            size_bytes: 40_000_000,
            min_ram_gb: 1,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "MobileSAM (community ONNX export) — compact mobile-optimized".into(),
        },
    ]
}

/// Look up an ONNX segmentation model by its internal ID.
pub fn get_segmentation_model_by_id(id: &str) -> Option<OnnxSegmentationEntry> {
    get_segmentation_catalog().into_iter().find(|m| m.id == id)
}

// ─────────────────────────────────────────────────────────────────────
// Text-promptable segmentation catalog — SAM 3 family.
// ─────────────────────────────────────────────────────────────────────

/// A curated ONNX text-promptable segmentation entry.
///
/// SAM 3 ships a three-graph bundle: an image encoder, a CLIP-style
/// language encoder, and a detection-shaped decoder. All three plus a
/// CLIP BPE `tokenizer.json` are required at inference time, so the
/// artifact is a multi-file `Bundle`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxTextSegmentationEntry {
    /// Internal model ID (e.g. "sam3-vit-h").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family (e.g. "sam3").
    pub family: String,
    /// HuggingFace repository ID for the ONNX bundle.
    pub hf_repo: String,
    /// Image encoder ONNX filename within the bundle.
    pub image_encoder_filename: String,
    /// Language encoder ONNX filename within the bundle.
    pub language_encoder_filename: String,
    /// Decoder ONNX filename within the bundle.
    pub decoder_filename: String,
    /// Tokenizer JSON filename within the bundle (CLIP BPE).
    pub tokenizer_filename: String,
    /// Native encoder input resolution (square). SAM 3 = 1008.
    pub input_size: u32,
    /// CLIP context length used by the language encoder. SAM 3 = 32.
    pub context_length: u32,
    /// Approximate total bundle size in bytes (all 3 graphs + tokenizer).
    pub size_bytes: u64,
    /// Minimum RAM in GB.
    pub min_ram_gb: u32,
    /// License (inherited from upstream).
    pub license: String,
    /// License tier — drives gating in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX text-promptable segmentation catalog.
///
/// SAM 3 weights are released under the Meta SAM License (custom
/// commercial-allowed terms with use restrictions) — the runtime gates
/// these as `LicenseTier::CommercialCustom`, requiring explicit
/// `--accept-license meta-sam` at registration time.
pub fn get_text_segmentation_catalog() -> Vec<OnnxTextSegmentationEntry> {
    vec![
        // ── SAM 3 ViT-H (community ONNX export by wkentaro) ─────────
        // Source weights: Meta `facebook/sam3-vit-h-2024-10`.
        // ONNX bundle: `wkentaro/sam3-onnx-models` (export script MIT,
        // weights inherit Meta SAM License).
        // Tokenizer: openai/clip-vit-base-patch16 tokenizer.json (CLIP
        // BPE with `<|endoftext|>` BOS/EOS/pad, context_length=32).
        OnnxTextSegmentationEntry {
            id: "sam3-vit-h".into(),
            name: "SAM 3 ViT-H".into(),
            family: "sam3".into(),
            hf_repo: "wkentaro/sam3-onnx-models".into(),
            image_encoder_filename: "sam3_image_encoder.onnx".into(),
            language_encoder_filename: "sam3_language_encoder.onnx".into(),
            decoder_filename: "sam3_decoder.onnx".into(),
            tokenizer_filename: "tokenizer.json".into(),
            input_size: 1008,
            context_length: 32,
            size_bytes: 2_500_000_000,
            min_ram_gb: 6,
            license: "Meta SAM License".into(),
            license_tier: LicenseTier::CommercialCustom,
            description:
                "Meta SAM 3 ViT-H — text-promptable open-vocabulary segmenter (community ONNX)"
                    .into(),
        },
    ]
}

/// Look up an ONNX text-promptable segmentation model by its internal ID.
pub fn get_text_segmentation_model_by_id(id: &str) -> Option<OnnxTextSegmentationEntry> {
    get_text_segmentation_catalog()
        .into_iter()
        .find(|m| m.id == id)
}

// ─────────────────────────────────────────────────────────────────────
// Detection catalog.
// ─────────────────────────────────────────────────────────────────────

/// A curated ONNX object-detection entry.
///
/// Real-time DETR-family detectors (single-file ONNX, NMS-free output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxDetectionEntry {
    /// Internal model ID (e.g. "rf-detr-base").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family (e.g. "rf-detr", "d-fine").
    pub family: String,
    /// HuggingFace repository ID.
    pub hf_repo: String,
    /// ONNX filename.
    pub hf_filename: String,
    /// Native input resolution.
    pub input_size: u32,
    /// Number of class labels (COCO=80 by default; some checkpoints differ).
    pub num_classes: u32,
    /// Approximate file size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB.
    pub min_ram_gb: u32,
    /// License (inherited from upstream).
    pub license: String,
    /// License tier — drives gating in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX detection catalog.
///
/// RF-DETR is a 2026 real-time detector achieving >60 AP on COCO
/// (ICLR 2026). D-FINE retained as a secondary baseline. Avoids
/// AGPL-licensed Ultralytics YOLO and demoted RT-DETRv2.
pub fn get_detection_catalog() -> Vec<OnnxDetectionEntry> {
    vec![
        // ── RF-DETR (Apache 2.0, Roboflow) ─────────────────────────
        // 6 size tiers from nano to 2x-large.
        // RF-DETR has tier-specific input resolutions (384–880). The
        // detector reads the actual shape from the loaded ONNX session
        // at load time; these catalog values are advisory.
        OnnxDetectionEntry {
            id: "rf-detr-nano".into(),
            name: "RF-DETR nano".into(),
            family: "rf-detr".into(),
            hf_repo: "PierreMarieCurie/rf-detr-onnx".into(),
            hf_filename: "rf-detr-nano.onnx".into(),
            input_size: 384,
            num_classes: 90,
            size_bytes: 30_000_000,
            min_ram_gb: 1,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "RF-DETR nano — fastest real-time DETR, edge-tier".into(),
        },
        OnnxDetectionEntry {
            id: "rf-detr-small".into(),
            name: "RF-DETR small".into(),
            family: "rf-detr".into(),
            hf_repo: "PierreMarieCurie/rf-detr-onnx".into(),
            hf_filename: "rf-detr-small.onnx".into(),
            input_size: 512,
            num_classes: 90,
            size_bytes: 60_000_000,
            min_ram_gb: 1,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "RF-DETR small — balanced speed/accuracy".into(),
        },
        OnnxDetectionEntry {
            id: "rf-detr-medium".into(),
            name: "RF-DETR medium".into(),
            family: "rf-detr".into(),
            hf_repo: "PierreMarieCurie/rf-detr-onnx".into(),
            hf_filename: "rf-detr-medium.onnx".into(),
            input_size: 576,
            num_classes: 90,
            size_bytes: 110_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "RF-DETR medium — mid-tier real-time DETR".into(),
        },
        OnnxDetectionEntry {
            id: "rf-detr-base".into(),
            name: "RF-DETR base".into(),
            family: "rf-detr".into(),
            hf_repo: "PierreMarieCurie/rf-detr-onnx".into(),
            hf_filename: "rf-detr-base-coco.onnx".into(),
            input_size: 560,
            num_classes: 90,
            size_bytes: 180_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "RF-DETR base — real-time DETR baseline (COCO)".into(),
        },
        OnnxDetectionEntry {
            id: "rf-detr-large".into(),
            name: "RF-DETR large".into(),
            family: "rf-detr".into(),
            hf_repo: "PierreMarieCurie/rf-detr-onnx".into(),
            hf_filename: "rf-detr-large-2026.onnx".into(),
            input_size: 704,
            num_classes: 90,
            size_bytes: 350_000_000,
            min_ram_gb: 3,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "RF-DETR large — high-accuracy real-time DETR (2026 refresh)".into(),
        },
        OnnxDetectionEntry {
            id: "rf-detr-2xl".into(),
            name: "RF-DETR 2x-large".into(),
            family: "rf-detr".into(),
            hf_repo: "PierreMarieCurie/rf-detr-onnx".into(),
            hf_filename: "rf-detr-xxlarge.onnx".into(),
            input_size: 768,
            num_classes: 90,
            size_bytes: 700_000_000,
            min_ram_gb: 4,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "RF-DETR 2x-large — flagship >60 AP on COCO (ICLR 2026)".into(),
        },
        // ── D-FINE (Apache 2.0) — secondary baseline ──────────────
        // Weights come from the per-variant `onnx-community/dfine_*_coco-ONNX`
        // exports, not from `Peterande/D-FINE`: the upstream author's repo
        // publishes PyTorch `.pth` checkpoints only, and this runtime is ORT.
        // Every file in those repos is named `onnx/model.onnx`, so the repo
        // id is what selects the variant.
        OnnxDetectionEntry {
            id: "d-fine-s".into(),
            name: "D-FINE small".into(),
            family: "d-fine".into(),
            hf_repo: "onnx-community/dfine_s_coco-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            input_size: 640,
            num_classes: 80,
            size_bytes: 40_000_000,
            min_ram_gb: 1,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "D-FINE small — efficient DETR variant".into(),
        },
        OnnxDetectionEntry {
            id: "d-fine-m".into(),
            name: "D-FINE medium".into(),
            family: "d-fine".into(),
            hf_repo: "onnx-community/dfine_m_coco-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            input_size: 640,
            num_classes: 80,
            size_bytes: 80_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "D-FINE medium — mid-tier DETR baseline".into(),
        },
        OnnxDetectionEntry {
            id: "d-fine-l".into(),
            name: "D-FINE large".into(),
            family: "d-fine".into(),
            hf_repo: "onnx-community/dfine_l_coco-ONNX".into(),
            hf_filename: "onnx/model.onnx".into(),
            input_size: 640,
            num_classes: 80,
            size_bytes: 130_000_000,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            license_tier: LicenseTier::Permissive,
            description: "D-FINE large — high-accuracy DETR baseline".into(),
        },
    ]
}

/// Look up an ONNX detection model by its internal ID.
pub fn get_detection_model_by_id(id: &str) -> Option<OnnxDetectionEntry> {
    get_detection_catalog().into_iter().find(|m| m.id == id)
}

// ─────────────────────────────────────────────────────────────────────
// Audio (ASR) catalog.
// ─────────────────────────────────────────────────────────────────────

/// A curated ONNX audio-ASR entry.
///
/// Whisper-family models split into encoder + decoder (+ optional joiner
/// for transducer-style architectures). Distil-Whisper / Whisper-v3-turbo
/// follow the encoder-decoder split. Moonshine v2 is a single-file
/// encoder-only architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxAudioEntry {
    /// Internal model ID (e.g. "whisper-large-v3-turbo").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family (e.g. "whisper", "moonshine", "parakeet", "canary").
    pub family: String,
    /// HuggingFace repository ID.
    pub hf_repo: String,
    /// Encoder ONNX filename (always present).
    pub encoder_filename: String,
    /// Optional decoder filename (None for single-file encoders like Moonshine).
    pub decoder_filename: Option<String>,
    /// Optional joiner filename (transducer-style models like Parakeet).
    pub joiner_filename: Option<String>,
    /// Audio sample rate the model expects (typically 16000 Hz).
    pub sample_rate: u32,
    /// Maximum audio segment length in seconds.
    pub max_audio_seconds: u32,
    /// Languages supported (ISO codes, e.g. ["en", "es", "fr", ...]).
    pub languages: Vec<String>,
    /// Approximate total file size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB.
    pub min_ram_gb: u32,
    /// License (inherited from upstream).
    pub license: String,
    /// License tier — drives gating in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX audio-ASR catalog.
/// A speech-synthesis model this node can serve.
///
/// Named for what it is rather than mirroring the ONNX entry types: the
/// Qwen3-TTS family ships `safetensors` with a `config.json` and loads
/// through `transformers`, not ORT. A field called `onnx_filename` holding
/// something that is not ONNX is exactly the drift this avoids.
///
/// Synthesis itself runs in the Python worker at `integrations/tts/`, the same
/// split as Tenzro Train and Media Gen. The node owns admission, billing and
/// the API surface; the worker owns the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtsModelEntry {
    /// Internal model ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family.
    pub family: String,
    /// HuggingFace repository.
    pub hf_repo: String,
    /// Approximate on-disk size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB to load.
    pub min_ram_gb: u32,
    /// Output sample rate in Hz.
    pub sample_rate: u32,
    /// Languages, as the model card names them.
    pub languages: Vec<String>,
    /// Licence exactly as the repo declares it.
    pub license: String,
    /// Licence tier, enforced in `ModelRegistry::register_model`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Whether this checkpoint can clone a voice from reference audio.
    ///
    /// Recorded per checkpoint so an operator can see which models carry the
    /// capability before enabling it, rather than discovering it from a
    /// request. Cloning stays behind a separate operator opt-in regardless —
    /// choosing a model family that supports it is not the same act as
    /// offering it to callers.
    pub supports_voice_cloning: bool,
    /// Preset voice ids the checkpoint ships.
    pub preset_voices: Vec<String>,
    /// Short description.
    pub description: String,
}

/// Get the curated speech-synthesis catalog.
///
/// Qwen3-TTS only, deliberately. It is Apache-2.0, ungated, and — the property
/// that made this modality buildable at all — it takes **raw text** with no
/// grapheme-to-phoneme step. The obvious alternative, Kokoro, needs a
/// phonemizer, and the standard engine for that (espeak-ng) is GPL, which
/// cannot be linked from an Apache-2.0 codebase. The permissive G2P
/// alternatives are Python-only and would have made the phonemizer the hardest
/// part of the modality rather than an implementation detail.
///
/// Sizes are the summed blob sizes reported by the hub, not estimates.
pub fn get_tts_catalog() -> Vec<TtsModelEntry> {
    let langs: Vec<String> = [
        "Chinese",
        "English",
        "Japanese",
        "Korean",
        "German",
        "French",
        "Russian",
        "Portuguese",
        "Spanish",
        "Italian",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    vec![
        // ── Qwen3-TTS 1.7B CustomVoice (Apache-2.0, Alibaba Qwen) ──
        // The default. Preset voices only, so it carries none of the consent
        // questions the cloning checkpoint does.
        TtsModelEntry {
            id: "qwen3-tts-1.7b".to_string(),
            name: "Qwen3-TTS 12Hz 1.7B CustomVoice".to_string(),
            family: "qwen3-tts".to_string(),
            hf_repo: "Qwen/Qwen3-TTS-12Hz-1.7B-CustomVoice".to_string(),
            size_bytes: 4_520_218_951,
            min_ram_gb: 7,
            sample_rate: 24_000,
            languages: langs.clone(),
            license: "Apache-2.0".to_string(),
            license_tier: LicenseTier::Permissive,
            supports_voice_cloning: false,
            preset_voices: vec!["Vivian".to_string()],
            description: "Ten-language speech synthesis from raw text; no phonemizer required"
                .to_string(),
        },
        // ── Qwen3-TTS 0.6B CustomVoice (Apache-2.0) ──
        // Same shape at a little over half the size. What to reach for when
        // speech shares a machine with a language model rather than owning it.
        TtsModelEntry {
            id: "qwen3-tts-0.6b".to_string(),
            name: "Qwen3-TTS 12Hz 0.6B CustomVoice".to_string(),
            family: "qwen3-tts".to_string(),
            hf_repo: "Qwen/Qwen3-TTS-12Hz-0.6B-CustomVoice".to_string(),
            size_bytes: 2_498_388_392,
            min_ram_gb: 4,
            sample_rate: 24_000,
            languages: langs.clone(),
            license: "Apache-2.0".to_string(),
            license_tier: LicenseTier::Permissive,
            supports_voice_cloning: false,
            preset_voices: vec!["Vivian".to_string()],
            description: "Smaller Qwen3-TTS for nodes where speech shares the machine".to_string(),
        },
        // ── Qwen3-TTS 1.7B Base (Apache-2.0) ──
        // The cloning checkpoint: ~3s of reference audio plus its transcript.
        // Listed so an operator who wants it can have it, flagged so nobody
        // enables it without meaning to.
        TtsModelEntry {
            id: "qwen3-tts-1.7b-clone".to_string(),
            name: "Qwen3-TTS 12Hz 1.7B Base".to_string(),
            family: "qwen3-tts".to_string(),
            hf_repo: "Qwen/Qwen3-TTS-12Hz-1.7B-Base".to_string(),
            size_bytes: 4_544_229_700,
            min_ram_gb: 7,
            sample_rate: 24_000,
            languages: langs,
            license: "Apache-2.0".to_string(),
            license_tier: LicenseTier::Permissive,
            supports_voice_cloning: true,
            preset_voices: Vec::new(),
            description: "Voice cloning from ~3s of reference audio and its transcript; \
                          requires an explicit operator opt-in"
                .to_string(),
        },
    ]
}

/// Look up a speech model by its internal ID.
pub fn get_tts_model_by_id(model_id: &str) -> Option<TtsModelEntry> {
    get_tts_catalog().into_iter().find(|e| e.id == model_id)
}

pub fn get_audio_catalog() -> Vec<OnnxAudioEntry> {
    vec![
        // ── Moonshine (MIT, Useful Sensors) ────────────────────────
        // Community ONNX export at onnx-community/moonshine-{tiny,base}-ONNX.
        // Standard transformers.js layout: onnx/encoder_model.onnx +
        // onnx/decoder_model_merged.onnx (single graph keyed by
        // `use_cache_branch` bool input).
        OnnxAudioEntry {
            id: "moonshine-tiny".into(),
            name: "Moonshine Tiny".into(),
            family: "moonshine".into(),
            hf_repo: "onnx-community/moonshine-tiny-ONNX".into(),
            encoder_filename: "onnx/encoder_model.onnx".into(),
            decoder_filename: Some("onnx/decoder_model_merged.onnx".into()),
            joiner_filename: None,
            sample_rate: 16000,
            max_audio_seconds: 30,
            languages: vec!["en".into()],
            size_bytes: 100_000_000,
            min_ram_gb: 1,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "Moonshine Tiny — on-device English ASR, edge-tier (raw waveform input)".into(),
        },
        OnnxAudioEntry {
            id: "moonshine-base".into(),
            name: "Moonshine Base".into(),
            family: "moonshine".into(),
            hf_repo: "onnx-community/moonshine-base-ONNX".into(),
            encoder_filename: "onnx/encoder_model.onnx".into(),
            decoder_filename: Some("onnx/decoder_model_merged.onnx".into()),
            joiner_filename: None,
            sample_rate: 16000,
            max_audio_seconds: 30,
            languages: vec!["en".into()],
            size_bytes: 240_000_000,
            min_ram_gb: 1,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "Moonshine Base — on-device English ASR, balanced (raw waveform input)".into(),
        },
        // ── Distil-Whisper (MIT, HuggingFace) ──────────────────────
        // Merged decoder with `use_cache_branch` input — single graph
        // handles both prefill and incremental decode.
        OnnxAudioEntry {
            id: "distil-whisper-small-en".into(),
            name: "Distil-Whisper small.en".into(),
            family: "whisper".into(),
            hf_repo: "distil-whisper/distil-small.en".into(),
            encoder_filename: "onnx/encoder_model.onnx".into(),
            decoder_filename: Some("onnx/decoder_model_merged.onnx".into()),
            joiner_filename: None,
            sample_rate: 16000,
            max_audio_seconds: 30,
            languages: vec!["en".into()],
            size_bytes: 330_000_000,
            min_ram_gb: 2,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "Distil-Whisper small.en — distilled English ASR (80-mel)".into(),
        },
        OnnxAudioEntry {
            id: "distil-whisper-medium-en".into(),
            name: "Distil-Whisper medium.en".into(),
            family: "whisper".into(),
            hf_repo: "distil-whisper/distil-medium.en".into(),
            encoder_filename: "onnx/encoder_model.onnx".into(),
            decoder_filename: Some("onnx/decoder_model_merged.onnx".into()),
            joiner_filename: None,
            sample_rate: 16000,
            max_audio_seconds: 30,
            languages: vec!["en".into()],
            size_bytes: 760_000_000,
            min_ram_gb: 3,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "Distil-Whisper medium.en — higher-accuracy distilled English ASR (80-mel)".into(),
        },
        OnnxAudioEntry {
            id: "distil-whisper-large-v3".into(),
            name: "Distil-Whisper large-v3".into(),
            family: "whisper".into(),
            hf_repo: "distil-whisper/distil-large-v3".into(),
            encoder_filename: "onnx/encoder_model.onnx".into(),
            decoder_filename: Some("onnx/decoder_model_merged.onnx".into()),
            joiner_filename: None,
            sample_rate: 16000,
            max_audio_seconds: 30,
            languages: vec!["multilingual".into()],
            size_bytes: 1_500_000_000,
            min_ram_gb: 4,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "Distil-Whisper large-v3 — multilingual distilled ASR (128-mel)".into(),
        },
        // ── Whisper Large-v3-turbo (MIT, OpenAI) ───────────────────
        // Community ONNX export at onnx-community/whisper-large-v3-turbo;
        // OpenAI's own repo ships PyTorch only.
        OnnxAudioEntry {
            id: "whisper-large-v3-turbo".into(),
            name: "Whisper Large-v3-turbo".into(),
            family: "whisper".into(),
            hf_repo: "onnx-community/whisper-large-v3-turbo".into(),
            encoder_filename: "onnx/encoder_model.onnx".into(),
            decoder_filename: Some("onnx/decoder_model_merged.onnx".into()),
            joiner_filename: None,
            sample_rate: 16000,
            max_audio_seconds: 30,
            languages: vec!["multilingual".into()],
            size_bytes: 1_600_000_000,
            min_ram_gb: 5,
            license: "MIT".into(),
            license_tier: LicenseTier::Permissive,
            description: "OpenAI Whisper Large-v3-turbo — flagship multilingual ASR (128-mel)".into(),
        },
        // ── Parakeet TDT 0.6B v3 (NVIDIA, CC-BY-4.0) ───────────────
        // Community ONNX export at istupakov/parakeet-tdt-0.6b-v3-onnx.
        // Three-file bundle: encoder + fused decoder_joint + 128-mel
        // preprocessor. Token-and-Duration Transducer — joint emits
        // vocab logits plus per-step duration logits that drive how
        // many encoder frames to advance per emission.
        // `joiner_filename` carries the preprocessor here because the
        // catalog struct doesn't have a dedicated preprocessor slot;
        // `decoder_filename` carries the fused decoder_joint network.
        // Loader resolves `vocab.txt` separately by convention.
        OnnxAudioEntry {
            id: "parakeet-tdt-0.6b-v3".into(),
            name: "NeMo Parakeet TDT 0.6B v3".into(),
            family: "parakeet".into(),
            hf_repo: "istupakov/parakeet-tdt-0.6b-v3-onnx".into(),
            encoder_filename: "encoder-model.onnx".into(),
            decoder_filename: Some("decoder_joint-model.onnx".into()),
            joiner_filename: Some("nemo128.onnx".into()),
            sample_rate: 16000,
            max_audio_seconds: 60,
            languages: vec![
                "en".into(), "es".into(), "fr".into(), "de".into(),
                "bg".into(), "hr".into(), "cs".into(), "da".into(),
                "nl".into(), "et".into(), "fi".into(), "el".into(),
                "hu".into(), "it".into(), "lv".into(), "lt".into(),
                "mt".into(), "pl".into(), "pt".into(), "ro".into(),
                "sk".into(), "sl".into(), "sv".into(), "ru".into(),
                "uk".into(),
            ],
            size_bytes: 2_500_000_000,
            min_ram_gb: 4,
            license: "CC-BY-4.0".into(),
            license_tier: LicenseTier::Attribution,
            description: "NVIDIA Parakeet TDT 0.6B v3 — multilingual TDT transducer (25 langs, 128-mel)".into(),
        },
        // ── Canary 1B Flash ────────────────────────────────────────
        // NeMo Conformer AED ASR (attention encoder-decoder, no blank).
        // 5249-entry SentencePiece vocab, 10-token decoder prefix
        // selecting source/target language + PNC + timestamp + diarize
        // modes. CC-BY-4.0 / Attribution. Reuses Parakeet's nemo128
        // preprocessor — `joiner_filename` slot carries `nemo128.onnx`.
        OnnxAudioEntry {
            id: "canary-1b-flash".into(),
            name: "NVIDIA Canary 1B Flash".into(),
            family: "canary".into(),
            hf_repo: "istupakov/canary-1b-flash-onnx".into(),
            encoder_filename: "encoder-model.onnx".into(),
            decoder_filename: Some("decoder-model.onnx".into()),
            joiner_filename: Some("nemo128.onnx".into()),
            sample_rate: 16000,
            max_audio_seconds: 40,
            languages: vec![
                "en".into(),
                "de".into(),
                "es".into(),
                "fr".into(),
            ],
            size_bytes: 4_000_000_000,
            min_ram_gb: 6,
            license: "CC-BY-4.0".into(),
            license_tier: LicenseTier::Attribution,
            description: "NVIDIA Canary 1B Flash — Conformer AED with translation across 4 languages (en/de/es/fr)".into(),
        },
    ]
}

/// Look up an ONNX audio model by its internal ID.
pub fn get_audio_model_by_id(id: &str) -> Option<OnnxAudioEntry> {
    get_audio_catalog().into_iter().find(|m| m.id == id)
}

// ─────────────────────────────────────────────────────────────────────
// Video catalog — V-JEPA 2 family advertised; loader pending ONNX export.
// ─────────────────────────────────────────────────────────────────────

/// A curated ONNX video-encoder entry.
///
/// The catalog advertises the V-JEPA 2 family (ViT-L/H MIT, ViT-g
/// Apache-2.0) so license_tier-gated discovery, CLI listing, and RPC
/// surfaces show the correct options. The `load_video_model` RPC
/// rejects until per-model ONNX exports are published — facebook/vjepa2-*
/// carries safetensors only, no native ONNX. VideoMAE v1/v2 stay off the
/// catalog (CC-BY-NC), V-JEPA 2.1 stays off (CC-BY-NC-ND).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxVideoEntry {
    /// Internal model ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family.
    pub family: String,
    /// HuggingFace repository ID.
    pub hf_repo: String,
    /// ONNX filename.
    pub hf_filename: String,
    /// Frame side length (typically 224).
    pub frame_size: u32,
    /// Number of frames consumed per clip.
    pub num_frames: u32,
    /// Sampling FPS.
    pub fps: u32,
    /// Output embedding dimension.
    pub embedding_dim: u32,
    /// Approximate file size in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB.
    pub min_ram_gb: u32,
    /// License.
    pub license: String,
    /// License tier — drives gating in `ModelRegistry::register_model()`.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Short description.
    pub description: String,
}

/// Get the curated ONNX video catalog.
///
/// **Empty, and deliberately so.** No permissive, ONNX-shippable,
/// encoder-only video model exists to put in it.
///
/// The V-JEPA 2 family (Meta, MIT/Apache-2.0) is the obvious candidate and
/// was listed here for a while, but the upstream `facebook/vjepa2-*` repos
/// ship `safetensors` only — verified against the HF API, no `.onnx` sibling
/// on any of the three sizes. The community exports that do exist are not
/// substitutes: `onnx-community/vjepa2-vitl-fpc32-256-diving48-ONNX` is
/// fine-tuned for Diving48 video *classification*, and the `abdelstark`
/// exports are `fpc2` / `img16` — two frames per clip, not the 64-frame
/// configuration the encoder is trained for.
///
/// Listing them anyway would have been worse than an empty catalog: nothing
/// in the node can load a V-JEPA 2 checkpoint, so `tenzro_listVideoCatalog`
/// would advertise three models that every caller discovers are unreachable
/// only after trying.
///
/// Video embedding is served instead by
/// [`VisionFallbackVideoEncoder`](crate::video_runtime::VisionFallbackVideoEncoder),
/// which extracts evenly-spaced frames with `ffmpeg`, embeds each through a
/// registered image encoder, and mean-pools — the CLIP4Clip pattern.
/// `tenzro_loadVideoModel` wires it by naming an already-loaded vision model,
/// which is why that handler takes a `vision_model_id` rather than trying to
/// load anything from this catalog.
///
/// Populate this when an encoder-only video model ships a real ONNX export
/// under a permissive licence.
pub fn get_video_catalog() -> Vec<OnnxVideoEntry> {
    Vec::new()
}

pub fn get_video_model_by_id(id: &str) -> Option<OnnxVideoEntry> {
    get_video_catalog().into_iter().find(|m| m.id == id)
}

/// Two denoising experts split across the noise schedule.
///
/// Wan 2.2 A14B ships two full transformers of identical shape rather than a
/// single one: the high-noise expert denoises the early, coarse part of the
/// schedule and the low-noise expert finishes it. The pipeline switches once,
/// at [`boundary_ratio`](Self::boundary_ratio) of the schedule.
///
/// This is a different shape from the token-routed FFN experts that
/// [`MoeShape`] describes, and the difference is what makes it worth
/// distributing. A routed model hands off per token; this hands off once per
/// job, as a single latent tensor of a few megabytes. Two workers can hold one
/// expert each and split a job across a wide-area link without the per-token
/// round trips that make routed MoE impractical off a datacenter fabric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaGenExpertPair {
    /// Repository subfolder holding the high-noise expert.
    pub high_noise_component: String,
    /// Repository subfolder holding the low-noise expert.
    pub low_noise_component: String,
    /// Fraction of the noise schedule above which the high-noise expert runs.
    /// The low-noise expert takes the remainder.
    pub boundary_ratio: f32,
    /// GPU VRAM in GB to hold one expert plus the shared text-encoder and VAE
    /// stack — what a worker needs to serve half a job, against
    /// [`min_vram_gb`](MediaGenModelEntry::min_vram_gb) for the whole of one.
    pub min_vram_gb_per_expert: u32,
}

/// Which inference library a media-gen entry is loaded and run through.
///
/// # Why this is per-entry rather than one house style
///
/// The worker began as a `diffusers` host because every model it served was a
/// `diffusers` pipeline. That stopped being true: `Trellis2ImageTo3DPipeline`
/// comes from Microsoft's own `trellis2` package, and Cosmos3 ships a
/// `Cosmos3OmniPipeline` whose omni surface is not a `diffusers` pipeline in
/// the usual sense either.
///
/// Forcing those through a `diffusers` shim, or forcing `diffusers` models
/// through a new abstraction, both trade a working path for a uniform one. So
/// the backend is a property of the entry, defaulted to
/// [`Diffusers`](Self::Diffusers) — every existing entry keeps its exact
/// behaviour without being touched, and a new family declares what it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MediaGenBackend {
    /// HuggingFace `diffusers`. The default and the common case.
    #[default]
    Diffusers,
    /// Microsoft's `trellis2` package (`Trellis2ImageTo3DPipeline`).
    Trellis2,
    /// Tencent's `hy3dgen` stack for the Hunyuan3D family.
    Hunyuan3d,
    /// NVIDIA Cosmos omni pipeline (`Cosmos3OmniPipeline`).
    Cosmos3Omni,
}

impl MediaGenBackend {
    /// Stable wire/label form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Diffusers => "diffusers",
            Self::Trellis2 => "trellis2",
            Self::Hunyuan3d => "hunyuan3d",
            Self::Cosmos3Omni => "cosmos3_omni",
        }
    }

    /// The Python distribution a worker must have installed to serve it.
    ///
    /// Reported so a worker can refuse enrolment for a backend it cannot load,
    /// rather than accepting the job and failing at claim time.
    pub fn required_package(&self) -> &'static str {
        match self {
            Self::Diffusers => "diffusers",
            Self::Trellis2 => "trellis2",
            Self::Hunyuan3d => "hy3dgen",
            Self::Cosmos3Omni => "cosmos3",
        }
    }
}

/// A generative-media pipeline in the curated media-gen catalog.
///
/// Unlike the ONNX entries above, a media-gen pipeline is a multi-folder
/// HuggingFace repository (transformer + text encoder + VAE + scheduler)
/// loaded whole by `diffusers`, so there is no single `hf_filename`. The
/// worker in `integrations/media_gen/` resolves the repo through the
/// [`pipeline_class`](MediaGenModelEntry::pipeline_class) declared in its
/// `model_index.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct MediaGenModelEntry {
    /// Internal model ID, used as `model_id` on a `MediaGenTaskSpec`.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family.
    pub family: String,
    /// HuggingFace repository ID. Loaded as a whole pipeline directory.
    pub hf_repo: String,
    /// Which inference library loads and runs this entry.
    ///
    /// Defaulted, so every pipeline that predates 3D support keeps working
    /// unchanged and a worker that only has `diffusers` installed is unaffected
    /// by the existence of entries it cannot serve.
    #[serde(default)]
    pub backend: MediaGenBackend,
    /// Voxel grid resolution the vendor's reference invocation uses, for 3D
    /// entries. `None` for pixel pipelines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_voxel_resolution: Option<u32>,
    /// Diffusers pipeline class named by the repo's `model_index.json`.
    ///
    /// A repo that serves more than one [`MediaGenKind`] may need a sibling
    /// class for the secondary kind — Wan TI2V-5B declares `WanPipeline` but
    /// takes `WanImageToVideoPipeline` over the same weights for
    /// image-to-video. The worker resolves that from the job's kind.
    pub pipeline_class: String,
    /// Job kinds this pipeline serves.
    pub kinds: Vec<tenzro_types::MediaGenKind>,
    /// Output width the vendor's reference invocation uses.
    pub default_width: u32,
    /// Output height the vendor's reference invocation uses.
    pub default_height: u32,
    /// Largest side length the pipeline is trained for.
    pub max_resolution: u32,
    /// Denoising steps the vendor's reference invocation uses.
    pub default_steps: u32,
    /// Classifier-free guidance scale the vendor's reference invocation uses.
    pub default_guidance_scale: f32,
    /// Frame count for video kinds; `None` for image-only pipelines.
    pub default_num_frames: Option<u32>,
    /// Frames per second for video kinds; `None` for image-only pipelines.
    pub default_fps: Option<u32>,
    /// Parameter count across the repo's safetensors.
    pub parameters: String,
    /// Total download footprint of the repository in bytes.
    pub size_bytes: u64,
    /// Minimum GPU VRAM in GB. Vendor-stated where the model card gives a
    /// figure, otherwise the bf16 weight footprint rounded up to the next
    /// common card size. Actual use varies with resolution and offload.
    pub min_vram_gb: u32,
    /// License.
    pub license: String,
    /// License tier. Gated at worker enrollment rather than at load: these
    /// weights are loaded by the Python worker, so the node's only chance to
    /// hold the operator to the terms is when a capability naming the model is
    /// admitted.
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Set when the pipeline splits denoising across two experts, so a job can
    /// be served by two workers holding one expert each. `None` for a single
    /// dense transformer.
    #[serde(default)]
    pub expert_pair: Option<MediaGenExpertPair>,
    /// Repo publishing a GGUF-quantized transformer for this model, and the
    /// file within it. A GGUF release carries the transformer alone, so
    /// `hf_repo` still supplies the text encoder, VAE, tokenizer and
    /// scheduler; the worker builds the transformer with
    /// `from_single_file` and swaps it into the upstream pipeline.
    ///
    /// This is what lets a 20B-parameter image model fit where its bf16
    /// release would not: `qwen-image` is 57.7 GB at bf16 against 15.0 GB at
    /// Q5_K_M. Both fields are set together or the entry is not a GGUF entry.
    #[serde(default)]
    pub gguf_repo: Option<String>,
    /// File path within [`Self::gguf_repo`].
    #[serde(default)]
    pub gguf_file: Option<String>,
    /// diffusers model class the GGUF weights build into (e.g.
    /// `QwenImageTransformer2DModel`). Required alongside the GGUF fields
    /// because a GGUF carries weights and no diffusers config, so the loader
    /// has to be told which architecture to construct.
    #[serde(default)]
    pub transformer_class: Option<String>,
    /// Repo to read the transformer's diffusers *config* from, when that is
    /// not `hf_repo`.
    ///
    /// Weights and geometry usually travel together, so the default — read the
    /// config from the same repo the components come from — is right for every
    /// entry here today. It stops being right whenever a release publishes
    /// weights whose geometry no repo in the entry describes: diffusers'
    /// single-file loader resolves an unknown checkpoint to the nearest
    /// fingerprint it knows and applies *that* generation's config, which is a
    /// silent shape mismatch rather than a clean failure. `Lightricks/LTX-2.3`
    /// is the live example — recognised as `ltx2`, configured from the 19B
    /// `Lightricks/LTX-2`, actually 22B.
    ///
    /// Setting this pins the config explicitly instead of inheriting whatever
    /// the loader guessed. `None` keeps the existing behaviour exactly.
    #[serde(default)]
    pub config_repo: Option<String>,
    /// Whether this is a step-distilled release, whose sampler must follow the
    /// sigma trajectory the distillation was trained against.
    ///
    /// A distilled checkpoint is not simply "the same model at fewer steps".
    /// It is trained to jump along one specific path through noise, and
    /// `FlowMatchEulerDiscreteScheduler` left to derive its own dynamically
    /// shifted sigmas takes a different path — composition still lands,
    /// because that is decided early, but fine structure never resolves. The
    /// symptom is a render that is recognisably the prompt and yet visibly
    /// unfinished, which reads as a weak model rather than a wrong schedule.
    ///
    /// diffusers publishes the trained trajectories as `DISTILLED_SIGMA_VALUES`
    /// and `STAGE_2_DISTILLED_SIGMA_VALUES`, so the entry records only *that*
    /// the checkpoint is distilled and the worker passes the matching values.
    #[serde(default)]
    pub distilled: bool,
    /// Subfolder of [`Self::config_repo`]'s converted snapshot holding the
    /// latent upsampler that stage 2 refines through. `None` renders in one
    /// stage.
    ///
    /// LTX-2 is designed as a two-stage model: stage 1 lays down composition
    /// and motion at the base resolution, then the latents are upsampled 2×
    /// and a short second pass synthesizes the detail. Decoding stage 1
    /// directly — which is what a single-stage render does — skips the pass
    /// that produces fine structure, and no amount of stage-1 tuning
    /// substitutes for it.
    #[serde(default)]
    pub latent_upsampler: Option<String>,
    /// Short description.
    pub description: String,
    /// Whether the Hub requires per-account approval before this can be
    /// fetched.
    ///
    /// Recorded because it decides whether an operator can serve the model at
    /// all, and they should learn that from the catalog rather than from a 403
    /// halfway through a 50 GB download. A gated entry needs `HF_TOKEN` (or
    /// `huggingface-cli login`) from an account that has accepted the model's
    /// terms.
    #[serde(default)]
    pub gated: bool,
}

/// Get the curated generative-media catalog.
///
/// Membership rules, applied against the HuggingFace API at the time each
/// entry was added:
///
/// - **Ungated.** `gated == false`, matching the catalog-wide invariant that
///   no entry needs an HF login to download.
/// - **Loadable by `diffusers`.** The repo ships a `model_index.json` whose
///   `_class_name` is a real diffusers pipeline, so `from_pretrained` resolves
///   the whole repo. This excludes repos that tag `library_name: diffusers`
///   but ship their own loader (Microsoft Mage-Flow needs the `mage_flow`
///   package) and repos that ship bare root-level checkpoints with no pipeline
///   manifest. `Lightricks/LTX-2.3` is the latter case: root-level
///   `.safetensors` and nothing else, so `from_pretrained` has no pipeline to
///   resolve.
///
///   **Re-checked 2026-08-03; most of that reasoning was wrong, and the real
///   blocker is narrower.** Each correction verified rather than inferred:
///
///   - diffusers 0.39 ships the whole LTX2 family — `LTX2Pipeline`,
///     `LTX2ImageToVideoPipeline`, `LTX2VideoTransformer3DModel`,
///     `AutoencoderKLLTX2Video`, `AutoencoderKLLTX2Audio` — so the
///     architecture is supported.
///   - A first-party diffusers-format repo **does** exist. `Lightricks/LTX-2`
///     carries `model_index.json` and all nine components (`scheduler`, `vae`,
///     `audio_vae`, `text_encoder`, `tokenizer`, `connectors`, `transformer`,
///     `vocoder`, `latent_upsampler`); its text encoder is
///     `Gemma3ForConditionalGeneration`.
///   - The bare checkpoints in `Lightricks/LTX-2.3` are meant for
///     `from_single_file`, not `from_pretrained`: diffusers carries an `ltx2`
///     fingerprint in `CHECKPOINT_KEY_NAMES` and maps it to `ltx2-dev` →
///     `Lightricks/LTX-2` for component configs. The `from_pretrained`
///     snippet on that model card **404s on `model_index.json`**, confirmed
///     against the live Hub.
///
///   What blocked an LTX-2.3 entry was therefore a config mismatch, not
///   missing components: that single-file path resolves configs to
///   `Lightricks/LTX-2`, the **19B** generation (`num_layers: 48`,
///   `caption_channels: 3840`), while 2.3 is 22B.
///   `convert_ltx2_transformer_to_diffusers` is a pure key-rename that derives
///   no geometry from the checkpoint, so it applied 19B config to 22B weights
///   and failed on shapes.
///
///   **Resolved 2026-08-04, and `ltx-2.3-22b-distilled-gguf` is now an
///   entry.** The geometry was recovered by fitting each component against its
///   published weights until the parameter count matched exactly, and the
///   result is three authored configs plus three rename tables:
///
///   - **transformer** — `use_prompt_embeddings: false`; leaving it `true`
///     builds LTX-2.0's `caption_projection` and strands 8 tensors. 4186/4186
///     parameters, none left on meta. 12 `prompt_adaln_single.*` keys need
///     renaming to `prompt_adaln.*`, which the shipped converter misses
///     because its handler matches the `adaln_single` substring but only
///     rewrites two other prefixes.
///   - **connectors** — `per_modality_projections: true` is the literal
///     2.0-vs-2.3 switch; head counts must make `inner_dim` match the
///     projected widths (video 32×128, audio 16×128) or the zero-layer
///     `norm_out` fails.
///   - **video VAE** — 170/170. The decoder carries one more upsample stage
///     than the shipped rename table covers, so flat `up_blocks.7`/`.8` map to
///     `up_blocks.3.upsamplers.0`/`up_blocks.3`.
///   - **audio VAE** — geometry is *identical* to 2.0; only the latent
///     statistics keys moved, which the shipped converter already handles.
///   - **vocoder** — 2.3 is BigVGAN-shaped with a bandwidth-extension
///     generator, so the class is `LTX2VocoderWithBWE` rather than 2.0's
///     `LTX2Vocoder`. Its default config is already correct; 1227/1227
///     parameters fit under a six-entry rename.
///
///   Weights come from `unsloth/LTX-2.3-GGUF` (transformer, both VAEs,
///   connectors, vocoder) and `Lightricks/LTX-2` (tokenizer, scheduler); the
///   text encoder is the ungated `unsloth/gemma-3-12b-it-qat-bnb-4bit`, whose
///   3840-wide hidden states across 49 layers are what the connectors project.
///   Because those pieces span two repos in a pre-0.39 key layout, the worker
///   applies the renames once offline into a local snapshot and points
///   [`Self::config_repo`] at it — a conversion the operator performs and can
///   re-derive, rather than a third-party conversion pulled from the Hub.
///
///   It is not [`LicenseTier::Permissive`] — the LTX Open Weights terms put it
///   in [`LicenseTier::CommercialCustom`], so it needs an explicit
///   `--accept-license ltx-open-weights`. Only `Text2Video` is declared:
///   the image-conditioned sibling is unverified here, and the joint
///   audio+video output shape still has no [`MediaGenKind`], so the audio
///   branch renders but is not offered as a product.
/// - **Serves a [`MediaGenKind`].** Image and video output only; a diffusion
///   model that emits text is served by the chat path.
///
/// Entries are [`LicenseTier::Permissive`] except `qwen-image-flash`, which
/// carries the NVIDIA Open Model License and so is [`LicenseTier::CommercialCustom`]
/// — a worker must enroll with `--accept-license nvidia-open-model` to hold it.
/// Two different reasons keep other frontier checkpoints out, and they are
/// worth separating because only one of them is about licensing:
///
/// - **Gated on the Hub** — Krea 2, `FLUX.2-dev`, `FLUX.2-klein-9B` and the
///   `klein-base-9B` / `klein-9b-kv` line all report `gated: auto`. A worker
///   cannot fetch them without per-account approval, so listing them would
///   advertise something most operators cannot actually serve.
/// - **Not a loadable pipeline** — the `fp8` and `nvfp4` FLUX.2 repos
///   (`klein-4b-fp8`, `klein-4b-nvfp4`, `dev-NVFP4`, `klein-9b-kv-fp8`) are
///   ungated, and two of them are Apache-2.0, but each ships only a quantized
///   transformer with no `model_index.json`. `from_pretrained` cannot build a
///   pipeline from them; they are a component to swap into a base pipeline,
///   which is a loading path `MediaGenModelEntry` does not yet express. Their
///   appeal is real — `klein-4b-nvfp4` is 2.5 GB against the base model's
///   23.7 GB — so this is a gap to close, not a decision to exclude them.
///
/// Checked against the Hub API rather than inferred: `gated` and `license` were
/// read per repo, and the earlier note in this position claimed the whole
/// non-Apache FLUX.2 line was gated, which was wrong for `dev-NVFP4` and
/// `klein-9b-kv-fp8`.
pub fn get_media_gen_catalog() -> Vec<MediaGenModelEntry> {
    use tenzro_types::MediaGenKind::{Image2Image, Image2Video, Image23d, Text2Image, Text2Video};

    vec![
        // ── Qwen-Image (Apache-2.0, Alibaba Qwen) ──
        // 20B MMDiT. The reference invocation samples 50 steps at
        // true-CFG 4.0; 1328² is the 1:1 entry in the card's aspect-ratio
        // table and 1664 the longest side it lists (16:9).
        //
        // `default_guidance_scale` is true-CFG for this family, not the
        // embedded-guidance scale of the same name: these checkpoints report
        // no guidance embedding, so the worker sends the figure as
        // `true_cfg_scale`, which is the knob that reaches the sampler.
        MediaGenModelEntry {
            id: "qwen-image".to_string(),
            name: "Qwen-Image".to_string(),
            family: "qwen-image".to_string(),
            // The 2512 release supersedes the original Qwen/Qwen-Image.
            // Same architecture and near-identical size, newer weights — a
            // version bump, so the repo moves and the id stays stable rather
            // than the catalog carrying both.
            hf_repo: "Qwen/Qwen-Image-2512".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "QwenImagePipeline".to_string(),
            kinds: vec![Text2Image],
            default_width: 1328,
            default_height: 1328,
            max_resolution: 1664,
            default_steps: 50,
            default_guidance_scale: 4.0,
            default_num_frames: None,
            default_fps: None,
            parameters: "20.4B".to_string(),
            size_bytes: 57_704_595_735,
            min_vram_gb: 48,
            distilled: false,
            latent_upsampler: None,
            license: "Apache-2.0".to_string(),
            license_tier: LicenseTier::Permissive,
            expert_pair: None,
            gated: false,
            description: "Qwen-Image 2512 text-to-image MMDiT with strong text rendering"
                .to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── Qwen-Image 2512, GGUF transformer (Apache-2.0) ──
        // Same pipeline as the entry above with the transformer read from
        // Unsloth's GGUF quantization instead of the bf16 release: 15.0 GB
        // against 57.7 GB, which is the difference between a node that can
        // hold this alongside its language and embedding models and one that
        // cannot. The `min_vram_gb` floor drops with it.
        //
        // Only the transformer is quantized. `Qwen/Qwen-Image-2512` still
        // supplies the Qwen2.5-VL text encoder, the VAE, the tokenizer and the
        // scheduler, so sampling behaviour is the upstream one — same 50 steps
        // at true-CFG 4.0, same aspect-ratio table.
        MediaGenModelEntry {
            id: "qwen-image-gguf".to_string(),
            name: "Qwen-Image 2512 (GGUF Q5_K_M)".to_string(),
            family: "qwen-image".to_string(),
            hf_repo: "Qwen/Qwen-Image-2512".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "QwenImagePipeline".to_string(),
            kinds: vec![Text2Image],
            default_width: 1328,
            default_height: 1328,
            max_resolution: 1664,
            default_steps: 50,
            default_guidance_scale: 4.0,
            default_num_frames: None,
            default_fps: None,
            parameters: "20.4B".to_string(),
            size_bytes: 15_004_000_000,
            min_vram_gb: 18,
            distilled: false,
            latent_upsampler: None,
            license: "Apache-2.0".to_string(),
            license_tier: LicenseTier::Permissive,
            expert_pair: None,
            gated: false,
            description: "Qwen-Image 2512 text-to-image, Q5_K_M GGUF transformer".to_string(),
            gguf_repo: Some("unsloth/Qwen-Image-2512-GGUF".to_string()),
            gguf_file: Some("qwen-image-2512-Q5_K_M.gguf".to_string()),
            transformer_class: Some("QwenImageTransformer2DModel".to_string()),
            config_repo: None,
        },
        // ── Qwen-Image-Flash (NVIDIA Open Model License, NVIDIA) ──
        // A distillation of Qwen/Qwen-Image down to a four-step trajectory,
        // keeping the 20.4B transformer architecture and replacing its weights
        // with the student's. The packaged scheduler is configured for that
        // four-step trajectory, so the reference call is 4 steps at
        // true-CFG 1.0 — guidance off — against 50 steps at 4.0 for the base
        // model. Same footprint, same VRAM floor, one twelfth of the
        // pixel-steps.
        //
        // The card states one tested output setting, 1024², and gives no
        // larger figure, so `max_resolution` does not inherit the base model's
        // 1664 even though the architecture is unchanged. Editing is named as
        // out of scope, so this entry serves `text2image` only.
        MediaGenModelEntry {
            id: "qwen-image-flash".to_string(),
            name: "Qwen-Image-Flash".to_string(),
            family: "qwen-image".to_string(),
            hf_repo: "nvidia/Qwen-Image-Flash".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "QwenImagePipeline".to_string(),
            kinds: vec![Text2Image],
            default_width: 1024,
            default_height: 1024,
            max_resolution: 1024,
            default_steps: 4,
            default_guidance_scale: 1.0,
            default_num_frames: None,
            default_fps: None,
            parameters: "20.4B".to_string(),
            size_bytes: 57_708_362_811,
            min_vram_gb: 48,
            distilled: false,
            latent_upsampler: None,
            license: "NVIDIA Open Model License".to_string(),
            license_tier: LicenseTier::CommercialCustom,
            expert_pair: None,
            gated: false,
            description: "Qwen-Image distilled to four steps, guidance disabled".to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── Qwen-Image-Edit (Apache-2.0, Alibaba Qwen) ──
        // Same 20B backbone specialised for instruction editing. 40 steps
        // at true-CFG 4.0 per the card's parameter block.
        MediaGenModelEntry {
            id: "qwen-image-edit".to_string(),
            name: "Qwen-Image-Edit 2511".to_string(),
            family: "qwen-image".to_string(),
            hf_repo: "Qwen/Qwen-Image-Edit-2511".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "QwenImageEditPlusPipeline".to_string(),
            kinds: vec![Image2Image],
            default_width: 1328,
            default_height: 1328,
            max_resolution: 1664,
            default_steps: 40,
            default_guidance_scale: 4.0,
            default_num_frames: None,
            default_fps: None,
            parameters: "20.4B".to_string(),
            size_bytes: 57_720_463_453,
            min_vram_gb: 48,
            distilled: false,
            latent_upsampler: None,
            license: "Apache-2.0".to_string(),
            license_tier: LicenseTier::Permissive,
            expert_pair: None,
            gated: false,
            description: "Qwen-Image-Edit instruction-driven image editing, multi-reference"
                .to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── Z-Image Turbo (Apache-2.0, Tongyi MAI) ──
        // 6B few-step distillation: 9 steps, guidance disabled.
        MediaGenModelEntry {
            id: "z-image-turbo".to_string(),
            name: "Z-Image Turbo".to_string(),
            family: "z-image".to_string(),
            hf_repo: "Tongyi-MAI/Z-Image-Turbo".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "ZImagePipeline".to_string(),
            kinds: vec![Text2Image],
            default_width: 1024,
            default_height: 1024,
            max_resolution: 2048,
            default_steps: 9,
            default_guidance_scale: 0.0,
            default_num_frames: None,
            default_fps: None,
            parameters: "6.2B".to_string(),
            size_bytes: 32_899_667_397,
            min_vram_gb: 16,
            distilled: false,
            latent_upsampler: None,
            license: "Apache-2.0".to_string(),
            license_tier: LicenseTier::Permissive,
            expert_pair: None,
            gated: false,
            description: "Z-Image Turbo few-step text-to-image, 9 steps without guidance"
                .to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── FLUX.2 klein 4B (Apache-2.0, Black Forest Labs) ──
        // The one FLUX.2 checkpoint released under Apache-2.0 and ungated.
        // One class covers generation, editing, and multi-reference. 4 steps
        // at guidance 1.0; the card targets consumer cards from 12 GB up.
        MediaGenModelEntry {
            id: "flux2-klein-4b".to_string(),
            name: "FLUX.2 klein 4B".to_string(),
            family: "flux2".to_string(),
            hf_repo: "black-forest-labs/FLUX.2-klein-4B".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "Flux2KleinPipeline".to_string(),
            kinds: vec![Text2Image, Image2Image],
            default_width: 1024,
            default_height: 1024,
            max_resolution: 2048,
            default_steps: 4,
            default_guidance_scale: 1.0,
            default_num_frames: None,
            default_fps: None,
            parameters: "3.9B".to_string(),
            size_bytes: 23_740_007_447,
            min_vram_gb: 12,
            distilled: false,
            latent_upsampler: None,
            license: "Apache-2.0".to_string(),
            license_tier: LicenseTier::Permissive,
            expert_pair: None,
            gated: false,
            description: "FLUX.2 klein 4B text-to-image and editing, runs on consumer GPUs"
                .to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── FLUX.2 klein base 4B (Apache-2.0, Black Forest Labs) ──
        // The un-distilled sibling of klein-4B: same architecture and licence,
        // but trained without the few-step distillation, so it wants a normal
        // step count and real guidance. Kept alongside rather than instead —
        // the distilled one is four steps and much cheaper, this one is what
        // you reach for when the distilled output is not good enough.
        //
        // Verified ungated with `license: apache-2.0` on the Hub, and it ships
        // a `model_index.json`, so `from_pretrained` loads it whole.
        MediaGenModelEntry {
            id: "flux2-klein-base-4b".to_string(),
            name: "FLUX.2 klein base 4B".to_string(),
            family: "flux2".to_string(),
            hf_repo: "black-forest-labs/FLUX.2-klein-base-4B".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "Flux2KleinPipeline".to_string(),
            kinds: vec![Text2Image, Image2Image],
            default_width: 1024,
            default_height: 1024,
            max_resolution: 2048,
            // Undistilled: the four-step schedule of the distilled sibling
            // does not apply, and guidance is doing real work again.
            default_steps: 28,
            default_guidance_scale: 4.0,
            default_num_frames: None,
            default_fps: None,
            parameters: "3.9B".to_string(),
            size_bytes: 23_740_007_506,
            min_vram_gb: 12,
            distilled: false,
            latent_upsampler: None,
            license: "Apache-2.0".to_string(),
            license_tier: LicenseTier::Permissive,
            expert_pair: None,
            gated: false,
            description: "FLUX.2 klein base 4B — undistilled text-to-image and editing".to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── FLUX.2 dev (custom BFL licence, gated, Black Forest Labs) ──
        // The full 32B flagship. Gated on the Hub, so an operator needs a
        // token from an account that has accepted its terms — the downloader
        // sends one when configured.
        //
        // 177 GB of weights: it does not fit a single 121 GB box even at
        // bf16, so this entry is for machines that have the memory or that
        // shard it. The serve planner refuses rather than thrashes.
        MediaGenModelEntry {
            id: "flux2-dev".to_string(),
            name: "FLUX.2 dev".to_string(),
            family: "flux2".to_string(),
            hf_repo: "black-forest-labs/FLUX.2-dev".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "Flux2Pipeline".to_string(),
            kinds: vec![Text2Image, Image2Image],
            default_width: 1024,
            default_height: 1024,
            max_resolution: 4096,
            default_steps: 28,
            default_guidance_scale: 4.0,
            default_num_frames: None,
            default_fps: None,
            parameters: "32B".to_string(),
            size_bytes: 177_640_374_395,
            min_vram_gb: 80,
            distilled: false,
            latent_upsampler: None,
            license: "FLUX.2 Non-Commercial / BFL custom".to_string(),
            license_tier: LicenseTier::CommercialCustom,
            expert_pair: None,
            gated: true,
            description: "FLUX.2 dev — 32B flagship text-to-image and editing".to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── FLUX.2 klein 9B (custom BFL licence, gated) ──
        // The distilled 9B: the size most single-accelerator operators will
        // actually run, and it fits a 121 GB box with room for the rest of
        // the node.
        MediaGenModelEntry {
            id: "flux2-klein-9b".to_string(),
            name: "FLUX.2 klein 9B".to_string(),
            family: "flux2".to_string(),
            hf_repo: "black-forest-labs/FLUX.2-klein-9B".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "Flux2KleinPipeline".to_string(),
            kinds: vec![Text2Image, Image2Image],
            default_width: 1024,
            default_height: 1024,
            max_resolution: 2048,
            default_steps: 4,
            default_guidance_scale: 1.0,
            default_num_frames: None,
            default_fps: None,
            parameters: "9B".to_string(),
            size_bytes: 52_888_736_795,
            min_vram_gb: 24,
            distilled: false,
            latent_upsampler: None,
            license: "FLUX.2 Non-Commercial / BFL custom".to_string(),
            license_tier: LicenseTier::CommercialCustom,
            expert_pair: None,
            gated: true,
            description: "FLUX.2 klein 9B — distilled few-step generation and editing".to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── FLUX.2 klein base 9B (custom BFL licence, gated) ──
        // Undistilled 9B: normal step count and real guidance, for when the
        // four-step output is not good enough.
        MediaGenModelEntry {
            id: "flux2-klein-base-9b".to_string(),
            name: "FLUX.2 klein base 9B".to_string(),
            family: "flux2".to_string(),
            hf_repo: "black-forest-labs/FLUX.2-klein-base-9B".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "Flux2KleinPipeline".to_string(),
            kinds: vec![Text2Image, Image2Image],
            default_width: 1024,
            default_height: 1024,
            max_resolution: 2048,
            default_steps: 28,
            default_guidance_scale: 4.0,
            default_num_frames: None,
            default_fps: None,
            parameters: "9B".to_string(),
            size_bytes: 52_888_736_752,
            min_vram_gb: 24,
            distilled: false,
            latent_upsampler: None,
            license: "FLUX.2 Non-Commercial / BFL custom".to_string(),
            license_tier: LicenseTier::CommercialCustom,
            expert_pair: None,
            gated: true,
            description: "FLUX.2 klein base 9B — undistilled generation and editing".to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── FLUX.2 klein 9B KV (custom BFL licence, gated) ──
        // The KV variant of klein-9B. Same weights budget; the difference is
        // in how attention state is carried, which is what its card is about.
        MediaGenModelEntry {
            id: "flux2-klein-9b-kv".to_string(),
            name: "FLUX.2 klein 9B KV".to_string(),
            family: "flux2".to_string(),
            hf_repo: "black-forest-labs/FLUX.2-klein-9b-kv".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "Flux2KleinPipeline".to_string(),
            kinds: vec![Text2Image, Image2Image],
            default_width: 1024,
            default_height: 1024,
            max_resolution: 2048,
            default_steps: 4,
            default_guidance_scale: 1.0,
            default_num_frames: None,
            default_fps: None,
            parameters: "9B".to_string(),
            size_bytes: 52_886_252_700,
            min_vram_gb: 24,
            distilled: false,
            latent_upsampler: None,
            license: "FLUX.2 Non-Commercial / BFL custom".to_string(),
            license_tier: LicenseTier::CommercialCustom,
            expert_pair: None,
            gated: true,
            description: "FLUX.2 klein 9B KV — few-step generation and editing".to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── Wan 2.2 T2V A14B (Apache-2.0, Alibaba Wan) ──
        // Two-expert MoE over the denoising schedule: 27B total, ~14B active
        // per step. The card's reference call is 1280×720, 81 frames at
        // 16 fps, 40 steps, and asks for 80 GB single-GPU without offload.
        MediaGenModelEntry {
            id: "wan2.2-t2v-a14b".to_string(),
            name: "Wan 2.2 T2V A14B".to_string(),
            family: "wan2.2".to_string(),
            hf_repo: "Wan-AI/Wan2.2-T2V-A14B-Diffusers".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "WanPipeline".to_string(),
            kinds: vec![Text2Video],
            default_width: 1280,
            default_height: 720,
            max_resolution: 1280,
            default_steps: 40,
            default_guidance_scale: 4.0,
            default_num_frames: Some(81),
            default_fps: Some(16),
            parameters: "14.3B".to_string(),
            size_bytes: 126_200_628_126,
            min_vram_gb: 80,
            distilled: false,
            latent_upsampler: None,
            license: "Apache-2.0".to_string(),
            license_tier: LicenseTier::Permissive,
            expert_pair: Some(MediaGenExpertPair {
                high_noise_component: "transformer".to_string(),
                low_noise_component: "transformer_2".to_string(),
                boundary_ratio: 0.875,
                min_vram_gb_per_expert: 48,
            }),
            gated: false,
            description: "Wan 2.2 text-to-video mixture-of-experts, 480P and 720P".to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── Wan 2.2 I2V A14B (Apache-2.0, Alibaba Wan) ──
        // Same MoE shape, conditioned on a reference frame. Guidance 3.5.
        MediaGenModelEntry {
            id: "wan2.2-i2v-a14b".to_string(),
            name: "Wan 2.2 I2V A14B".to_string(),
            family: "wan2.2".to_string(),
            hf_repo: "Wan-AI/Wan2.2-I2V-A14B-Diffusers".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "WanImageToVideoPipeline".to_string(),
            kinds: vec![Image2Video],
            default_width: 1280,
            default_height: 720,
            max_resolution: 1280,
            default_steps: 40,
            default_guidance_scale: 3.5,
            default_num_frames: Some(81),
            default_fps: Some(16),
            parameters: "14.3B".to_string(),
            size_bytes: 126_204_155_463,
            min_vram_gb: 80,
            distilled: false,
            latent_upsampler: None,
            license: "Apache-2.0".to_string(),
            license_tier: LicenseTier::Permissive,
            expert_pair: Some(MediaGenExpertPair {
                high_noise_component: "transformer".to_string(),
                low_noise_component: "transformer_2".to_string(),
                boundary_ratio: 0.875,
                min_vram_gb_per_expert: 48,
            }),
            gated: false,
            description: "Wan 2.2 image-to-video mixture-of-experts, 480P and 720P".to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── Wan 2.1 FLF2V 14B 720P (Apache-2.0, Alibaba Wan) ──
        // First-last-frame interpolation: given two stills it generates the
        // motion between them, which is the stills-to-video bridge rather
        // than a plain animation of one frame.
        //
        // Declared `Image2Video` because that is the closest kind the
        // protocol carries, but the shape is not quite the same — this takes
        // TWO conditioning images where ordinary I2V takes one. A caller
        // passing a single image gets an interpolation to nowhere, so the
        // worker has to validate the pair rather than assume it.
        MediaGenModelEntry {
            id: "wan2.1-flf2v-14b".to_string(),
            name: "Wan 2.1 FLF2V 14B 720P".to_string(),
            family: "wan2.1".to_string(),
            hf_repo: "Wan-AI/Wan2.1-FLF2V-14B-720P-diffusers".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "WanImageToVideoPipeline".to_string(),
            kinds: vec![Image2Video],
            default_width: 1280,
            default_height: 720,
            max_resolution: 1280,
            default_steps: 40,
            default_guidance_scale: 5.0,
            default_num_frames: Some(81),
            default_fps: Some(16),
            parameters: "14B".to_string(),
            size_bytes: 90_110_903_694,
            min_vram_gb: 60,
            distilled: false,
            latent_upsampler: None,
            license: "Apache-2.0".to_string(),
            license_tier: LicenseTier::Permissive,
            expert_pair: None,
            gated: false,
            description: "Wan 2.1 first-last-frame interpolation; bridges two stills into motion"
                .to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── Wan 2.2 TI2V 5B (Apache-2.0, Alibaba Wan) ──
        // The affordable video option: a 16×16×4 VAE lets 5B cover both video
        // kinds at 720P/24fps on a 24 GB card. 1280×704 because the TI2V
        // 720P shape is 1280*704, not 1280*720.
        MediaGenModelEntry {
            id: "wan2.2-ti2v-5b".to_string(),
            name: "Wan 2.2 TI2V 5B".to_string(),
            family: "wan2.2".to_string(),
            hf_repo: "Wan-AI/Wan2.2-TI2V-5B-Diffusers".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "WanPipeline".to_string(),
            kinds: vec![Text2Video, Image2Video],
            default_width: 1280,
            default_height: 704,
            max_resolution: 1280,
            default_steps: 50,
            default_guidance_scale: 5.0,
            default_num_frames: Some(121),
            default_fps: Some(24),
            parameters: "5.0B".to_string(),
            size_bytes: 34_203_021_834,
            min_vram_gb: 24,
            distilled: false,
            latent_upsampler: None,
            license: "Apache-2.0".to_string(),
            license_tier: LicenseTier::Permissive,
            expert_pair: None,
            gated: false,
            description: "Wan 2.2 hybrid text/image-to-video at 720P 24fps on a single 24 GB GPU"
                .to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ── LTX-2.3 (LTX Open Weights, Lightricks) ──
        // 22B audio-video DiT, distilled to an 8-sigma schedule, served from
        // Unsloth's Q5_K_M GGUF. `config_repo` names a locally converted
        // snapshot rather than a Hub repo: 2.3's components are split across
        // `Lightricks/LTX-2` (tokenizer, scheduler) and `unsloth/LTX-2.3-GGUF`
        // (transformer, VAEs, connectors, vocoder), and three sets of keys sit
        // in a layout the installed diffusers converters predate. The worker
        // builds that snapshot once, offline, then loads it with plain
        // `from_pretrained`.
        //
        // Text-to-video only for now. `LTX2ImageToVideoPipeline` exists in
        // diffusers 0.39 and the components are the same, but the
        // image-conditioned path is unverified here, and declaring a kind the
        // worker has never run is how a job gets accepted and then fails.
        MediaGenModelEntry {
            id: "ltx-2.3-22b-distilled-gguf".to_string(),
            name: "LTX-2.3 22B Distilled (GGUF Q5_K_M)".to_string(),
            family: "ltx2".to_string(),
            hf_repo: "Lightricks/LTX-2.3".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "LTX2Pipeline".to_string(),
            kinds: vec![Text2Video],
            default_width: 768,
            default_height: 512,
            max_resolution: 1280,
            default_steps: 8,
            // The distilled schedule is not classifier-free-guided; the
            // reference sigmas were tuned against an unguided sampler and a
            // scale above 1.0 fights the distillation.
            default_guidance_scale: 1.0,
            default_num_frames: Some(121),
            default_fps: Some(24),
            parameters: "22B".to_string(),
            size_bytes: 30_215_060_095,
            min_vram_gb: 36,
            distilled: true,
            latent_upsampler: Some("latent_upsampler".to_string()),
            license: "LTX Open Weights".to_string(),
            license_tier: LicenseTier::CommercialCustom,
            expert_pair: None,
            gated: false,
            description: "LTX-2.3 22B distilled text-to-video, 8-step schedule, \
                          synchronized audio branch"
                .to_string(),
            gguf_repo: Some("unsloth/LTX-2.3-GGUF".to_string()),
            gguf_file: Some("ltx-2.3-22b-distilled-1.1-UD-Q5_K_M.gguf".to_string()),
            transformer_class: Some("LTX2VideoTransformer3DModel".to_string()),
            config_repo: Some("~/.tenzro/models/ltx-2.3/diffusers".to_string()),
        },
        // MiniMax H3 (Hailuo 3.0), the open-weight H3-Base module.
        //
        // Registered so the catalog records that it exists and on what terms;
        // **no run has been verified**, and three facts decide whether any
        // given operator can serve it at all.
        //
        // *Not yet constructible.* `MiniMaxH3ModularPipeline` is a Modular
        // Diffusers class and is absent from diffusers 0.39, which is what this
        // worker pins; Modular Diffusers still announces itself as
        // experimental and subject to breaking changes. Until the class ships
        // in a pinned release the worker cannot build this entry at all, and
        // because modular pipelines are invoked through blocks rather than a
        // single `pipe(**kwargs)` call, it will also need a `FamilyAdapter`
        // — see `docs/MEDIA_GEN_FAMILIES.md`. The entry is therefore
        // discoverable, priced and licence-gated, but not servable.
        //
        // *Territory.* The H3 Community License grants rights "worldwide,
        // excluding the European Union, the United Kingdom, the Republic of
        // Korea and the United States of America", and §IV.4 extends that to
        // the model's *Outputs*, not just its weights. That makes it unlike
        // every other [`LicenseTier::CommercialCustom`] entry here, whose terms
        // turn on revenue or attribution: acknowledging this one is a claim
        // about **where the operator is**. For a node serving a decentralized
        // network it is sharper still, because §III permits distribution to
        // third parties only within the Applicable Territory, and a node
        // cannot in general establish where its consumers are. Registering the
        // entry does not resolve that; `--accept-license minimax-h3-community`
        // is where the operator takes the position.
        //
        // *Footprint.* 144 GB at bf16 for the text-to-video path — transformer
        // 66.3, Qwen3-VL-32B text encoder 66.7, video VAE 10.4, audio VAE 0.6 —
        // so `min_vram_gb` refuses on anything smaller, including a 121 GB
        // GB10. Third-party GGUFs exist but quantize the FL2VA
        // (first-and-last-frame) task bundle rather than the base
        // text-to-video transformer, so they do not serve this entry's kind.
        //
        // Only `Text2Video` is declared. The repo advertises image-, video-,
        // audio- and reference-conditioned variants, but those live in the
        // separate `FL2VA/` and `Ref2VA/` task partitions, and the discipline
        // that applies to every entry here applies doubly to an unrun one: a
        // worker advertising a kind it has never served gets jobs accepted and
        // then fails them.
        //
        // 2K output is **not** reachable from these weights. H3-Base renders at
        // a 768-pixel short edge; the 2K path runs through H3-Regenerate-2K,
        // which MiniMax kept proprietary. `max_resolution` therefore describes
        // the open module, not the hosted product.
        MediaGenModelEntry {
            id: "minimax-h3".to_string(),
            name: "MiniMax H3 (Hailuo 3.0) H3-Base".to_string(),
            family: "minimax-h3".to_string(),
            hf_repo: "MiniMaxAI/MiniMax-H3".to_string(),
            backend: MediaGenBackend::Diffusers,
            default_voxel_resolution: None,
            pipeline_class: "MiniMaxH3ModularPipeline".to_string(),
            kinds: vec![Text2Video],
            // The reference request takes `short_edge` + `aspect_ratio` rather
            // than a pixel pair; 768 short edge at 16:9 is this, rounded to a
            // multiple of 16.
            default_width: 1360,
            default_height: 768,
            max_resolution: 1360,
            // Provisional: the reference deployment is an SGLang service that
            // owns its own schedule and exposes neither a step count nor a
            // guidance scale, so these are placeholders and must be verified
            // against a real run before this entry is served or priced.
            default_steps: 50,
            default_guidance_scale: 1.0,
            // 10s at 24fps, the duration the official t2va script requests.
            // The model card states a 4-15s range.
            default_num_frames: Some(240),
            default_fps: Some(24),
            parameters: "H3-Base + Qwen3-VL-32B text encoder".to_string(),
            size_bytes: 144_000_000_000,
            min_vram_gb: 144,
            distilled: false,
            latent_upsampler: None,
            license: "MiniMax H3 Community License".to_string(),
            license_tier: LicenseTier::CommercialCustom,
            expert_pair: None,
            gated: false,
            description: "MiniMax H3 omni-modal text-to-video with native \
                          stereo audio, 768p short edge, 4-15s. Licence \
                          excludes the EU, UK, South Korea and the USA, \
                          including outputs"
                .to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
        // ---- 3D asset generation -------------------------------------------
        //
        // These produce a GLB mesh, not frames, and neither loads through
        // `diffusers`. They sit in the same catalog and the same job queue as
        // the pixel pipelines because the surrounding machinery — posting,
        // claiming, content-addressed output, signed receipts, settlement — is
        // identical; only the loader and the artifact differ, which is exactly
        // what `backend` and `kinds` exist to carry.
        MediaGenModelEntry {
            id: "trellis2-4b".to_string(),
            name: "TRELLIS.2 4B".to_string(),
            family: "trellis2".to_string(),
            hf_repo: "microsoft/TRELLIS.2-4B".to_string(),
            backend: MediaGenBackend::Trellis2,
            default_voxel_resolution: Some(1024),
            // Not a `diffusers` class. Named for the worker's dispatch and to
            // keep the field's meaning uniform: the entry-point class its own
            // library exposes.
            pipeline_class: "Trellis2ImageTo3DPipeline".to_string(),
            kinds: vec![Image23d],
            // The conditioning image, not the asset. A 3D job's size is
            // `default_voxel_resolution`.
            default_width: 1024,
            default_height: 1024,
            max_resolution: 1536,
            default_steps: 25,
            default_guidance_scale: 7.5,
            default_num_frames: None,
            default_fps: None,
            parameters: "4B".to_string(),
            size_bytes: 16_800_000_000,
            min_vram_gb: 24,
            distilled: false,
            latent_upsampler: None,
            license: "MIT".to_string(),
            license_tier: LicenseTier::Permissive,
            expert_pair: None,
            gated: false,
            description: "Microsoft TRELLIS.2 image-to-3D. Produces a GLB mesh \
                          with PBR materials including transparency, at up to \
                          1536³. Loads through the `trellis2` package, not \
                          diffusers"
                .to_string(),
            gguf_repo: None,
            gguf_file: None,
            transformer_class: None,
            config_repo: None,
        },
    ]
}

impl MediaGenModelEntry {
    /// Frame counts this pipeline can actually produce, as the stride of the
    /// `stride·k + 1` grid its video VAE decodes onto.
    ///
    /// A latent video frame covers `stride` pixel frames plus a single
    /// unpaired first frame, so a request off the grid is silently rounded
    /// *down* by the pipeline: asking LTX-2.3 for 48 frames (2s at 24fps)
    /// yields `(48-1)/8 + 1 = 6` latents, which decode back to 41. Billing is
    /// quoted from the requested count, so leaving the request off-grid
    /// charges for 48 frames and delivers 41. [`Self::snap_num_frames`] is
    /// applied at admission so the quote and the output agree.
    ///
    /// Image-only entries return 1: every count is representable.
    pub fn temporal_stride(&self) -> u32 {
        match self.family.as_str() {
            "ltx2" => 8,
            // Wan 2.1 and 2.2 share a 4× temporal VAE.
            "wan2.1" | "wan2.2" => 4,
            _ => 1,
        }
    }

    /// The requested frame count rounded up onto [`Self::temporal_stride`].
    ///
    /// Rounds up rather than down so a caller never silently receives less
    /// footage than they asked for and were quoted.
    pub fn snap_num_frames(&self, requested: u32) -> u32 {
        let stride = self.temporal_stride();
        if stride <= 1 || requested <= 1 {
            return requested.max(1);
        }
        // Smallest `stride·k + 1` that is >= requested.
        let k = (requested - 1).div_ceil(stride);
        k * stride + 1
    }
}

/// Look up a generative-media pipeline by its internal ID.
pub fn get_media_gen_model_by_id(id: &str) -> Option<MediaGenModelEntry> {
    get_media_gen_catalog().into_iter().find(|m| m.id == id)
}

/// Whether jobs for this model split their denoising schedule across two
/// experts, and so must be posted as a split job.
///
/// Splitting is a property of the model, not of the request: a spec carries no
/// role list, so the node admitting a job and every node mirroring it off the
/// gossip topic have to reach the same answer from the model id alone or they
/// end up holding different jobs under the same id. An unknown model is treated
/// as whole — nothing can be split into halves that are not described anywhere.
pub fn media_gen_model_splits(model_id: &str) -> bool {
    get_media_gen_model_by_id(model_id)
        .map(|m| m.expert_pair.is_some())
        .unwrap_or(false)
}

/// Generative-media pipelines serving a given job kind.
pub fn get_media_gen_models_for_kind(kind: tenzro_types::MediaGenKind) -> Vec<MediaGenModelEntry> {
    get_media_gen_catalog()
        .into_iter()
        .filter(|m| m.kinds.contains(&kind))
        .collect()
}

/// Get the full curated model catalog.
pub fn get_model_catalog() -> Vec<HfModelEntry> {
    let mut catalog = vec![
        // ── Qwen 3 (Apache 2.0, via unsloth GGUF — official Qwen repos lack Q4_K_M) ──
        HfModelEntry {
            id: "qwen3-0.6b".into(),
            name: "Qwen 3 0.6B".into(),
            family: "qwen3".into(),
            hf_repo: "unsloth/Qwen3-0.6B-GGUF".into(),
            hf_filename: "Qwen3-0.6B-Q4_K_M.gguf".into(),
            parameters: "0.6B".into(),
            architecture: ModelArchitecture::Qwen3,
            context_length: 32768,
            quantization: "Q4_K_M".into(),
            size_bytes: 396_705_472,
            min_ram_gb: 2,
            license: "Apache 2.0".into(),
            description: "Compact model optimized for edge deployment".into(),
            drafter_id: None,
            mtp_kind: MtpKind::None,
            mtp_default_draft_n: None,
            moe: None,
            promotable: true,
            serving: ServingProfile::default(),
            mmproj: None,
            reasoning: ReasoningPolicy {
                supports_thinking: false,
                default_mode: ReasoningMode::Auto,
                thinking_safe_min_b: 0.0,
                thinking_min_budget_tokens: 0,
            },
            template_fix: TemplateFix::None,
            download_filename: String::new(),
        },
    ];
    catalog.push(HfModelEntry {
        id: "qwen3-1.7b".into(),
        name: "Qwen 3 1.7B".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-1.7B-GGUF".into(),
        hf_filename: "Qwen3-1.7B-Q4_K_M.gguf".into(),
        parameters: "1.7B".into(),
        architecture: ModelArchitecture::Qwen3,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 1_107_409_472,
        min_ram_gb: 3,
        license: "Apache 2.0".into(),
        description: "Versatile model for various language tasks".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3-4b".into(),
        name: "Qwen 3 4B".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-4B-GGUF".into(),
        hf_filename: "Qwen3-4B-Q4_K_M.gguf".into(),
        parameters: "4B".into(),
        architecture: ModelArchitecture::Qwen3,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_497_281_312,
        min_ram_gb: 4,
        license: "Apache 2.0".into(),
        description: "Well-balanced model for production use".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3-8b".into(),
        name: "Qwen 3 8B".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-8B-GGUF".into(),
        hf_filename: "Qwen3-8B-Q4_K_M.gguf".into(),
        parameters: "8B".into(),
        architecture: ModelArchitecture::Qwen3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 5_027_784_512,
        min_ram_gb: 8,
        license: "Apache 2.0".into(),
        description: "Extended context model for long-form tasks".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3-14b".into(),
        name: "Qwen 3 14B".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-14B-GGUF".into(),
        hf_filename: "Qwen3-14B-Q4_K_M.gguf".into(),
        parameters: "14B".into(),
        architecture: ModelArchitecture::Qwen3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 9_001_753_984,
        min_ram_gb: 12,
        license: "Apache 2.0".into(),
        description: "Premium model with extended context support".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3-32b".into(),
        name: "Qwen 3 32B".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-32B-GGUF".into(),
        hf_filename: "Qwen3-32B-Q4_K_M.gguf".into(),
        parameters: "32B".into(),
        architecture: ModelArchitecture::Qwen3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 19_762_150_048,
        min_ram_gb: 24,
        license: "Apache 2.0".into(),
        description: "Top-tier model with 128K context window".into(),
        drafter_id: Some("qwen3-0.6b".into()),
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3-30b-a3b".into(),
        name: "Qwen 3 30B-A3B (MoE)".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-30B-A3B-GGUF".into(),
        hf_filename: "Qwen3-30B-A3B-Q4_K_M.gguf".into(),
        parameters: "30B (MoE, 3B active)".into(),
        architecture: ModelArchitecture::Qwen3Moe,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 18_556_686_912,
        min_ram_gb: 12,
        license: "Apache 2.0".into(),
        description: "Mixture-of-Experts with 3B active params for efficient scaling".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 128,
            experts_per_token: 8,
            shared_experts: 0,
            params_per_expert_x10: Some(2),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Qwen 3.5 (Apache 2.0, ungated, unsloth GGUF) ──────────────────
    catalog.push(HfModelEntry {
        id: "qwen3.5-0.8b".into(),
        name: "Qwen 3.5 0.8B".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-0.8B-GGUF".into(),
        hf_filename: "Qwen3.5-0.8B-Q4_K_M.gguf".into(),
        parameters: "0.8B".into(),
        architecture: ModelArchitecture::Qwen35,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 532_517_120,
        min_ram_gb: 2,
        license: "Apache 2.0".into(),
        description: "Compact multilingual model for efficient on-device inference".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3.5-2b".into(),
        name: "Qwen 3.5 2B".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-2B-GGUF".into(),
        hf_filename: "Qwen3.5-2B-Q4_K_M.gguf".into(),
        parameters: "2B".into(),
        architecture: ModelArchitecture::Qwen35,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 1_280_835_840,
        min_ram_gb: 3,
        license: "Apache 2.0".into(),
        description: "Efficient small model for chat and text generation".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3.5-4b".into(),
        name: "Qwen 3.5 4B".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-4B-GGUF".into(),
        hf_filename: "Qwen3.5-4B-Q4_K_M.gguf".into(),
        parameters: "4B".into(),
        architecture: ModelArchitecture::Qwen35,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_740_937_888,
        min_ram_gb: 4,
        license: "Apache 2.0".into(),
        description: "Mid-size model with strong reasoning and coding performance".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3.5-9b".into(),
        name: "Qwen 3.5 9B".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-9B-GGUF".into(),
        hf_filename: "Qwen3.5-9B-Q4_K_M.gguf".into(),
        parameters: "9B".into(),
        architecture: ModelArchitecture::Qwen35,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 5_680_522_464,
        min_ram_gb: 8,
        license: "Apache 2.0".into(),
        description: "High-performance model for complex language understanding".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3.5-27b".into(),
        name: "Qwen 3.5 27B".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-27B-GGUF".into(),
        hf_filename: "Qwen3.5-27B-Q4_K_M.gguf".into(),
        parameters: "27B".into(),
        architecture: ModelArchitecture::Qwen35,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 16_740_812_704,
        min_ram_gb: 20,
        license: "Apache 2.0".into(),
        description: "Flagship Qwen 3.5 model".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3.5-35b-a3b".into(),
        name: "Qwen 3.5 35B-A3B (MoE)".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-35B-A3B-GGUF".into(),
        hf_filename: "Qwen3.5-35B-A3B-Q4_K_M.gguf".into(),
        parameters: "35B (MoE, 3B active)".into(),
        architecture: ModelArchitecture::Qwen35Moe,
        context_length: 262144,
        quantization: "Q4_K_M".into(),
        size_bytes: 22_016_023_168,
        min_ram_gb: 14,
        license: "Apache 2.0".into(),
        description:
            "Mixture-of-Experts with only 3B active params — fast inference at 35B quality".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(1),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3.5-122b-a10b".into(),
        name: "Qwen 3.5 122B-A10B (MoE)".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-122B-A10B-GGUF".into(),
        hf_filename: "Q4_K_M/Qwen3.5-122B-A10B-Q4_K_M-00001-of-00003.gguf".into(),
        parameters: "122B (MoE, 10B active)".into(),
        architecture: ModelArchitecture::Qwen35Moe,
        context_length: 262144,
        quantization: "Q4_K_M".into(),
        size_bytes: 75_000_000_000,
        min_ram_gb: 80,
        license: "Apache 2.0".into(),
        description: "Qwen 3.5 large MoE — 122B total, 10B active per token. Replica-routed on high-VRAM provider tiers only; Unsloth ships an MTP variant in `unsloth/Qwen3.5-122B-A10B-MTP-GGUF` for compatible runtimes.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(5),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3.5-397b-a17b".into(),
        name: "Qwen 3.5 397B-A17B (MoE)".into(),
        family: "qwen3.5".into(),
        hf_repo: "unsloth/Qwen3.5-397B-A17B-GGUF".into(),
        hf_filename: "Q4_K_M/Qwen3.5-397B-A17B-Q4_K_M-00001-of-00006.gguf".into(),
        parameters: "397B (MoE, 17B active)".into(),
        architecture: ModelArchitecture::Qwen35Moe,
        context_length: 262144,
        quantization: "Q4_K_M".into(),
        size_bytes: 240_000_000_000,
        min_ram_gb: 256,
        license: "Apache 2.0".into(),
        description: "Qwen 3.5 frontier MoE — 397B total, 17B active per token. Multi-GPU replicas only; Unsloth ships an MTP variant in `unsloth/Qwen3.5-397B-A17B-MTP-GGUF` for compatible runtimes.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 512,
            experts_per_token: 10,
            shared_experts: 1,
            params_per_expert_x10: Some(8),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Gemma 3 (Google, ungated via unsloth GGUF) ─────────────────────
    catalog.push(HfModelEntry {
        id: "gemma3-270m".into(),
        name: "Gemma 3 270M".into(),
        family: "gemma3".into(),
        hf_repo: "unsloth/gemma-3-270m-it-GGUF".into(),
        hf_filename: "gemma-3-270m-it-Q4_K_M.gguf".into(),
        parameters: "270M".into(),
        architecture: ModelArchitecture::Gemma3,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 253_115_424,
        min_ram_gb: 1,
        license: "Gemma License".into(),
        description: "Tiny Gemma model for ultra-lightweight on-device inference".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma3-1b".into(),
        name: "Gemma 3 1B".into(),
        family: "gemma3".into(),
        hf_repo: "unsloth/gemma-3-1b-it-GGUF".into(),
        hf_filename: "gemma-3-1b-it-Q4_K_M.gguf".into(),
        parameters: "1B".into(),
        architecture: ModelArchitecture::Gemma3,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 806_058_272,
        min_ram_gb: 2,
        license: "Gemma License".into(),
        description: "Google's compact instruction-tuned model".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma3-4b".into(),
        name: "Gemma 3 4B".into(),
        family: "gemma3".into(),
        hf_repo: "unsloth/gemma-3-4b-it-GGUF".into(),
        hf_filename: "gemma-3-4b-it-Q4_K_M.gguf".into(),
        parameters: "4B".into(),
        architecture: ModelArchitecture::Gemma3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_489_894_016,
        min_ram_gb: 4,
        license: "Gemma License".into(),
        description: "Extended context Gemma model for chat applications".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma3-12b".into(),
        name: "Gemma 3 12B".into(),
        family: "gemma3".into(),
        hf_repo: "unsloth/gemma-3-12b-it-GGUF".into(),
        hf_filename: "gemma-3-12b-it-Q4_K_M.gguf".into(),
        parameters: "12B".into(),
        architecture: ModelArchitecture::Gemma3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 7_300_778_336,
        min_ram_gb: 10,
        license: "Gemma License".into(),
        description: "High-performance instruction-tuned model from Google".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma3-27b".into(),
        name: "Gemma 3 27B".into(),
        family: "gemma3".into(),
        hf_repo: "unsloth/gemma-3-27b-it-GGUF".into(),
        hf_filename: "gemma-3-27b-it-Q4_K_M.gguf".into(),
        parameters: "27B".into(),
        architecture: ModelArchitecture::Gemma3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 16_546_688_736,
        min_ram_gb: 20,
        license: "Gemma License".into(),
        description: "Google's largest Gemma model with exceptional capabilities".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Gemma 4 (Gemma License, via unsloth GGUF) ──────────────────────
    // MTP drafters: Unsloth ships Google's jointly-trained Multi-Token-
    // Prediction head as a sibling GGUF inside each target repo under the
    // `MTP/` subdirectory (e.g. `unsloth/gemma-4-12B-it-GGUF` carries
    // `MTP/mtp-gemma-4-12B-it.gguf` alongside the main GGUF files). The
    // drafter file is ~1–2 GB depending on target size and ~2 GB extra
    // VRAM at load. Pair with the target via `--spec-type draft-mtp` +
    // `--spec-draft-n-max 2..6` (Unsloth recommends 2 as a default).
    catalog.push(HfModelEntry {
        id: "gemma4-e2b-mtp-draft".into(),
        name: "Gemma 4 E2B MTP Drafter".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-E2B-it-GGUF".into(),
        hf_filename: "mtp-gemma-4-E2B-it.gguf".into(),
        parameters: "MTP head".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "BF16".into(),
        size_bytes: 200_000_000,
        min_ram_gb: 1,
        license: "Gemma License".into(),
        description: "Google's jointly-trained Multi-Token Prediction head for Gemma 4 E2B. Pair with the E2B target via `--spec-type draft-mtp`.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-12b-mtp-draft".into(),
        name: "Gemma 4 12B MTP Drafter".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-12b-it-GGUF".into(),
        hf_filename: "mtp-gemma-4-12b-it.gguf".into(),
        parameters: "MTP head".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "BF16".into(),
        size_bytes: 600_000_000,
        min_ram_gb: 2,
        license: "Gemma License".into(),
        description: "Google's jointly-trained Multi-Token Prediction head for Gemma 4 12B. Pair with the 12B target via `--spec-type draft-mtp`.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-e4b-mtp-draft".into(),
        name: "Gemma 4 E4B MTP Drafter".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-E4B-it-GGUF".into(),
        hf_filename: "mtp-gemma-4-E4B-it.gguf".into(),
        parameters: "MTP head".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "BF16".into(),
        size_bytes: 300_000_000,
        min_ram_gb: 1,
        license: "Gemma License".into(),
        description: "Google's jointly-trained Multi-Token Prediction head for Gemma 4 E4B. Pair with the E4B target via `--spec-type draft-mtp`.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-26b-a4b-mtp-draft".into(),
        name: "Gemma 4 26B-A4B MTP Drafter (MoE)".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-26B-A4B-it-GGUF".into(),
        hf_filename: "mtp-gemma-4-26B-A4B-it.gguf".into(),
        parameters: "MTP head".into(),
        architecture: ModelArchitecture::Gemma4Moe,
        context_length: 131072,
        quantization: "BF16".into(),
        size_bytes: 1_200_000_000,
        min_ram_gb: 2,
        license: "Gemma License".into(),
        description: "Google's jointly-trained Multi-Token Prediction head for the Gemma 4 26B-A4B Mixture-of-Experts target. Pair via `--spec-type draft-mtp`; Unsloth measures ~1.15–1.2× speedup on MoE targets vs ~1.4–2.2× on dense.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 128,
            experts_per_token: 4,
            shared_experts: 1,
            params_per_expert_x10: Some(2),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-31b-mtp-draft".into(),
        name: "Gemma 4 31B MTP Drafter".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-31B-it-GGUF".into(),
        hf_filename: "mtp-gemma-4-31B-it.gguf".into(),
        parameters: "MTP head".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "BF16".into(),
        size_bytes: 1_500_000_000,
        min_ram_gb: 2,
        license: "Gemma License".into(),
        description: "Google's jointly-trained Multi-Token Prediction head for Gemma 4 31B. Pair with the 31B target via `--spec-type draft-mtp`.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-e2b".into(),
        name: "Gemma 4 E2B".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-E2B-it-GGUF".into(),
        hf_filename: "gemma-4-E2B-it-Q4_K_M.gguf".into(),
        parameters: "E2B".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 3_339_569_152,
        min_ram_gb: 4,
        license: "Gemma License".into(),
        description: "Google's compact Gemma 4 multimodal model (text + image, 128K context). MTP-enabled — pairs with `gemma4-e2b-mtp-draft` for 1.5–2.2× throughput.".into(),
        drafter_id: Some("gemma4-e2b-mtp-draft".into()),
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-e4b".into(),
        name: "Gemma 4 E4B".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-E4B-it-GGUF".into(),
        hf_filename: "gemma-4-E4B-it-Q4_K_M.gguf".into(),
        parameters: "E4B".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 5_347_737_600,
        min_ram_gb: 8,
        license: "Gemma License".into(),
        description: "Google's efficient Gemma 4 multimodal model (text + image, 128K context). MTP-enabled — pairs with `gemma4-e4b-mtp-draft` for 1.5–2.2× throughput.".into(),
        drafter_id: Some("gemma4-e4b-mtp-draft".into()),
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-26b-a4b".into(),
        name: "Gemma 4 26B-A4B (MoE)".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-26B-A4B-it-GGUF".into(),
        hf_filename: "gemma-4-26B-A4B-it-UD-Q4_K_M.gguf".into(),
        parameters: "26B (4B active)".into(),
        architecture: ModelArchitecture::Gemma4Moe,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 18_146_000_000,
        min_ram_gb: 20,
        license: "Gemma License".into(),
        description: "Gemma 4 Mixture-of-Experts: 26B total params, 4B active per token (128K context). MTP-enabled — pairs with `gemma4-26b-a4b-mtp-draft`; expect ~1.15–1.2× speedup on MoE targets per Unsloth.".into(),
        drafter_id: Some("gemma4-26b-a4b-mtp-draft".into()),
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: Some(MoeShape {
            num_experts: 128,
            experts_per_token: 4,
            shared_experts: 1,
            params_per_expert_x10: Some(2),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-12b".into(),
        name: "Gemma 4 12B".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-12b-it-GGUF".into(),
        hf_filename: "gemma-4-12b-it-Q4_K_M.gguf".into(),
        parameters: "12B".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 7_637_385_216,
        min_ram_gb: 10,
        license: "Gemma License".into(),
        description: "Google's mid-tier dense Gemma 4 model (128K context). MTP-enabled — pairs with `gemma4-12b-mtp-draft` for 1.5–2.2× throughput on the same hardware (Unsloth: 52 → 162 t/s at Q4 on a 4090).".into(),
        drafter_id: Some("gemma4-12b-mtp-draft".into()),
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-31b".into(),
        name: "Gemma 4 31B".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-31B-it-GGUF".into(),
        hf_filename: "gemma-4-31B-it-Q4_K_M.gguf".into(),
        parameters: "31B".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 19_650_142_208,
        min_ram_gb: 24,
        license: "Gemma License".into(),
        description: "Google's largest dense Gemma 4 model (128K context). MTP-enabled — pairs with `gemma4-31b-mtp-draft` for ~2× throughput at 101 t/s on consumer GPUs (Unsloth benchmark).".into(),
        drafter_id: Some("gemma4-31b-mtp-draft".into()),
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Gemma 4 QAT (Quantization-Aware Training) ──────────────────────
    // Parallel-listed alongside the standard Q4_K_M targets. QAT
    // recovers ~15 MMLU points over naive 4-bit quantization on the
    // 26B-A4B target per Unsloth's measurements (85.6% vs 70.2% top-1).
    // Same drafter pairings as the non-QAT entries — MTP works
    // identically on QAT GGUFs since the MTP head ships in a
    // separate file regardless of the target's quantization regime.
    catalog.push(HfModelEntry {
        id: "gemma4-e2b-qat".into(),
        name: "Gemma 4 E2B (QAT)".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-E2B-it-qat-GGUF".into(),
        hf_filename: "gemma-4-E2B-it-qat-UD-Q4_K_XL.gguf".into(),
        parameters: "E2B".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "UD-Q4_K_XL (QAT)".into(),
        size_bytes: 3_500_000_000,
        min_ram_gb: 4,
        license: "Gemma License".into(),
        description: "Quantization-Aware-Trained Gemma 4 E2B. Higher quality than naive Q4 at the same size. MTP-enabled via `gemma4-e2b-mtp-draft`.".into(),
        drafter_id: Some("gemma4-e2b-mtp-draft".into()),
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-e4b-qat".into(),
        name: "Gemma 4 E4B (QAT)".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-E4B-it-qat-GGUF".into(),
        hf_filename: "gemma-4-E4B-it-qat-UD-Q4_K_XL.gguf".into(),
        parameters: "E4B".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "UD-Q4_K_XL (QAT)".into(),
        size_bytes: 5_500_000_000,
        min_ram_gb: 8,
        license: "Gemma License".into(),
        description: "Quantization-Aware-Trained Gemma 4 E4B. Higher quality than naive Q4 at the same size. MTP-enabled via `gemma4-e4b-mtp-draft`.".into(),
        drafter_id: Some("gemma4-e4b-mtp-draft".into()),
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-12b-qat".into(),
        name: "Gemma 4 12B (QAT)".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-12B-it-qat-GGUF".into(),
        hf_filename: "gemma-4-12B-it-qat-UD-Q4_K_XL.gguf".into(),
        parameters: "12B".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "UD-Q4_K_XL (QAT)".into(),
        size_bytes: 7_900_000_000,
        min_ram_gb: 10,
        license: "Gemma License".into(),
        description: "Quantization-Aware-Trained Gemma 4 12B. Higher quality than naive Q4 at the same size. MTP-enabled via `gemma4-12b-mtp-draft`.".into(),
        drafter_id: Some("gemma4-12b-mtp-draft".into()),
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-26b-a4b-qat".into(),
        name: "Gemma 4 26B-A4B (QAT, MoE)".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-26B-A4B-it-qat-GGUF".into(),
        hf_filename: "gemma-4-26B-A4B-it-qat-UD-Q4_K_XL.gguf".into(),
        parameters: "26B (4B active)".into(),
        architecture: ModelArchitecture::Gemma4Moe,
        context_length: 131072,
        quantization: "UD-Q4_K_XL (QAT)".into(),
        size_bytes: 18_300_000_000,
        min_ram_gb: 20,
        license: "Gemma License".into(),
        description: "Quantization-Aware-Trained Gemma 4 26B-A4B MoE. Unsloth measures 85.6% MMLU top-1 vs 70.2% on naive Q4 (+15.4 points). MTP-enabled via `gemma4-26b-a4b-mtp-draft`.".into(),
        drafter_id: Some("gemma4-26b-a4b-mtp-draft".into()),
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: Some(MoeShape {
            num_experts: 128,
            experts_per_token: 4,
            shared_experts: 1,
            params_per_expert_x10: Some(2),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gemma4-31b-qat".into(),
        name: "Gemma 4 31B (QAT)".into(),
        family: "gemma4".into(),
        hf_repo: "unsloth/gemma-4-31B-it-qat-GGUF".into(),
        hf_filename: "gemma-4-31B-it-qat-UD-Q4_K_XL.gguf".into(),
        parameters: "31B".into(),
        architecture: ModelArchitecture::Gemma4,
        context_length: 131072,
        quantization: "UD-Q4_K_XL (QAT)".into(),
        size_bytes: 19_800_000_000,
        min_ram_gb: 24,
        license: "Gemma License".into(),
        description: "Quantization-Aware-Trained Gemma 4 31B. Higher quality than naive Q4 at the same size. MTP-enabled via `gemma4-31b-mtp-draft`.".into(),
        drafter_id: Some("gemma4-31b-mtp-draft".into()),
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── DiffusionGemma (Gemma License, via unsloth GGUF) ───────────────
    // Block-parallel diffusion generation over a 256-token canvas
    // rather than autoregressive sampling. Speculative decoding does
    // not apply (MtpKind::None). Serving requires a diffusion-aware
    // runtime: the in-process `llama-cpp-2` binding does not yet
    // accept these GGUFs — operators run Unsloth Studio or build
    // llama.cpp from PR #24423 to serve them. Catalog entry exists so
    // model discovery / pricing / provider registration work; the
    // runtime returns a structured error if the in-process path is
    // attempted on this architecture.
    catalog.push(HfModelEntry {
        id: "diffusiongemma-26b-a4b".into(),
        name: "DiffusionGemma 26B-A4B".into(),
        family: "diffusiongemma".into(),
        hf_repo: "unsloth/diffusiongemma-26B-A4B-it-GGUF".into(),
        hf_filename: "diffusiongemma-26B-A4B-it-Q4_K_M.gguf".into(),
        parameters: "26B (4B active)".into(),
        architecture: ModelArchitecture::Gemma4Diffusion,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 18_000_000_000,
        min_ram_gb: 20,
        license: "Gemma License".into(),
        description: "Diffusion-generation Gemma 4 26B-A4B. Generates 256-token canvases by parallel denoising rather than autoregressive sampling. Unsloth: 2000+ t/s on RTX 6000. Requires Unsloth Studio or llama.cpp PR #24423+.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 128,
            experts_per_token: 4,
            shared_experts: 1,
            params_per_expert_x10: Some(2),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Mistral (Apache 2.0, ungated) ──────────────────────────────────
    catalog.push(HfModelEntry {
        id: "mistral-7b".into(),
        name: "Mistral 7B Instruct v0.3".into(),
        family: "mistral".into(),
        hf_repo: "bartowski/Mistral-7B-Instruct-v0.3-GGUF".into(),
        hf_filename: "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf".into(),
        parameters: "7B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 4_372_812_000,
        min_ram_gb: 6,
        license: "Apache 2.0".into(),
        description: "Mistral AI's classic 7B instruction model".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "mistral-nemo-12b".into(),
        name: "Mistral Nemo 12B".into(),
        family: "mistral".into(),
        hf_repo: "unsloth/Mistral-Nemo-Instruct-2407-GGUF".into(),
        hf_filename: "Mistral-Nemo-Instruct-2407.Q4_K_M.gguf".into(),
        parameters: "12B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 7_477_204_512,
        min_ram_gb: 10,
        license: "Apache 2.0".into(),
        description: "Extended-context Mistral model built with NVIDIA".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "mistral-small-24b".into(),
        name: "Mistral Small 3.2 24B".into(),
        family: "mistral".into(),
        hf_repo: "unsloth/Mistral-Small-3.2-24B-Instruct-2506-GGUF".into(),
        hf_filename: "Mistral-Small-3.2-24B-Instruct-2506-Q4_K_M.gguf".into(),
        parameters: "24B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 14_333_922_848,
        min_ram_gb: 18,
        license: "Apache 2.0".into(),
        description: "Mistral's latest Small 3.2 model for demanding workloads".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Ministral 3 (Mistral AI, Apache 2.0, ungated) ──────────────────
    catalog.push(HfModelEntry {
        id: "ministral3-3b".into(),
        name: "Ministral 3 3B".into(),
        family: "mistral".into(),
        hf_repo: "unsloth/Ministral-3-3B-Instruct-2512-GGUF".into(),
        hf_filename: "Ministral-3-3B-Instruct-2512-Q4_K_M.gguf".into(),
        parameters: "3B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_146_497_824,
        min_ram_gb: 3,
        license: "Apache 2.0".into(),
        description: "Compact Ministral 3 for lightweight tasks".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "ministral3-8b".into(),
        name: "Ministral 3 8B".into(),
        family: "mistral".into(),
        hf_repo: "bartowski/Ministral-8B-Instruct-2410-GGUF".into(),
        hf_filename: "Ministral-8B-Instruct-2410-Q4_K_M.gguf".into(),
        parameters: "8B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 4_911_500_096,
        min_ram_gb: 8,
        license: "Apache 2.0".into(),
        description: "Versatile Ministral 3 for general-purpose tasks".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "ministral3-14b".into(),
        name: "Ministral 3 14B".into(),
        family: "mistral".into(),
        hf_repo: "unsloth/Ministral-3-14B-Instruct-2512-GGUF".into(),
        hf_filename: "Ministral-3-14B-Instruct-2512-Q4_K_M.gguf".into(),
        parameters: "14B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 8_239_067_840,
        min_ram_gb: 12,
        license: "Apache 2.0".into(),
        description: "High-performance Ministral 3 for complex reasoning".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Phi 4 (Microsoft, MIT, ungated) ─────────────────────────────
    catalog.push(HfModelEntry {
        id: "phi4-mini".into(),
        name: "Phi-4 Mini 3.8B".into(),
        family: "phi".into(),
        hf_repo: "unsloth/Phi-4-mini-instruct-GGUF".into(),
        hf_filename: "Phi-4-mini-instruct-Q4_K_M.gguf".into(),
        parameters: "3.8B".into(),
        architecture: ModelArchitecture::Phi3,
        context_length: 128000,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_491_874_272,
        min_ram_gb: 3,
        license: "MIT".into(),
        description: "Compact Phi-4 Mini with 128K context".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "phi4".into(),
        name: "Phi-4 14B".into(),
        family: "phi".into(),
        hf_repo: "unsloth/phi-4-GGUF".into(),
        hf_filename: "phi-4-Q4_K_M.gguf".into(),
        parameters: "14B".into(),
        architecture: ModelArchitecture::Phi3,
        context_length: 16000,
        quantization: "Q4_K_M".into(),
        size_bytes: 8_890_306_112,
        min_ram_gb: 10,
        license: "MIT".into(),
        description: "Microsoft Phi-4 — strong reasoning at 14B".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "phi4-reasoning".into(),
        name: "Phi-4 Reasoning 14B".into(),
        family: "phi".into(),
        hf_repo: "unsloth/Phi-4-reasoning-GGUF".into(),
        hf_filename: "phi-4-reasoning-Q4_K_M.gguf".into(),
        parameters: "14B".into(),
        architecture: ModelArchitecture::Phi3,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 9_053_117_728,
        min_ram_gb: 10,
        license: "MIT".into(),
        description: "Phi-4 fine-tuned for chain-of-thought reasoning".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "phi4-mini-reasoning".into(),
        name: "Phi-4 Mini Reasoning 3.8B".into(),
        family: "phi".into(),
        hf_repo: "unsloth/Phi-4-mini-reasoning-GGUF".into(),
        hf_filename: "Phi-4-mini-reasoning-Q4_K_M.gguf".into(),
        parameters: "3.8B".into(),
        architecture: ModelArchitecture::Phi3,
        context_length: 128000,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_491_875_232,
        min_ram_gb: 3,
        license: "MIT".into(),
        description: "Compact Phi-4 Mini fine-tuned for reasoning tasks".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── SmolLM (HuggingFace, Apache 2.0, ungated) ───────────────────
    catalog.push(HfModelEntry {
        id: "smollm2-1.7b".into(),
        name: "SmolLM2 1.7B".into(),
        family: "smollm".into(),
        hf_repo: "unsloth/SmolLM2-1.7B-Instruct-GGUF".into(),
        hf_filename: "SmolLM2-1.7B-Instruct-Q4_K_M.gguf".into(),
        parameters: "1.7B".into(),
        architecture: ModelArchitecture::Llama,
        context_length: 8192,
        quantization: "Q4_K_M".into(),
        size_bytes: 1_055_609_504,
        min_ram_gb: 2,
        license: "Apache-2.0".into(),
        description: "Compact SmolLM2 for on-device AI".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "smollm3-3b".into(),
        name: "SmolLM3 3B".into(),
        family: "smollm".into(),
        hf_repo: "unsloth/SmolLM3-3B-GGUF".into(),
        hf_filename: "SmolLM3-3B-Q4_K_M.gguf".into(),
        parameters: "3B".into(),
        architecture: ModelArchitecture::Llama,
        context_length: 65536,
        quantization: "Q4_K_M".into(),
        size_bytes: 1_915_306_528,
        min_ram_gb: 3,
        license: "Apache-2.0".into(),
        description: "SmolLM3 — 11T tokens, dual-mode reasoning".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Qwen 3 Coder (Apache 2.0, ungated, unsloth GGUF) ───────────────
    catalog.push(HfModelEntry {
        id: "qwen3-coder-30b-a3b".into(),
        name: "Qwen 3 Coder 30B-A3B (MoE)".into(),
        family: "qwen3".into(),
        hf_repo: "unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF".into(),
        hf_filename: "Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf".into(),
        parameters: "30B (MoE, 3B active)".into(),
        architecture: ModelArchitecture::Qwen3Moe,
        context_length: 262144,
        quantization: "Q4_K_M".into(),
        size_bytes: 18_556_689_568,
        min_ram_gb: 12,
        license: "Apache 2.0".into(),
        description: "Code-focused MoE — 30B total, 3B active, 256K context".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 128,
            experts_per_token: 8,
            shared_experts: 0,
            params_per_expert_x10: Some(2),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Nemotron (NVIDIA Open, ungated, unsloth GGUF) ────────────────
    catalog.push(HfModelEntry {
        id: "nemotron-nano-4b".into(),
        name: "Nemotron 3 Nano 4B".into(),
        family: "nemotron".into(),
        hf_repo: "unsloth/NVIDIA-Nemotron-3-Nano-4B-GGUF".into(),
        hf_filename: "NVIDIA-Nemotron-3-Nano-4B-Q4_K_M.gguf".into(),
        parameters: "4B".into(),
        architecture: ModelArchitecture::Llama,
        context_length: 262144,
        quantization: "Q4_K_M".into(),
        size_bytes: 2_900_295_712,
        min_ram_gb: 4,
        license: "NVIDIA Open".into(),
        description: "Hybrid Mamba-2 + Attention edge model, 256K context".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "nemotron-nano-30b-a3b".into(),
        name: "Nemotron 3 Nano 30B-A3B (MoE)".into(),
        family: "nemotron".into(),
        hf_repo: "unsloth/Nemotron-3-Nano-30B-A3B-GGUF".into(),
        hf_filename: "Nemotron-3-Nano-30B-A3B-Q4_K_M.gguf".into(),
        parameters: "30B (MoE, 3B active)".into(),
        architecture: ModelArchitecture::Llama,
        context_length: 128000,
        quantization: "Q4_K_M".into(),
        size_bytes: 24_574_373_664,
        min_ram_gb: 16,
        license: "NVIDIA Open".into(),
        description: "Hybrid Mamba-2 MoE — 30B total, 3.5B active, 128K context".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 128,
            experts_per_token: 6,
            shared_experts: 1,
            params_per_expert_x10: Some(2),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Nemotron 3 Ultra + Nano Omni (verified 2026-07-31) ───────────
    // Ultra is a hybrid Transformer-Mamba MoE with Latent MoE and a
    // built-in Multi-Token-Prediction head, so it drafts against itself
    // rather than needing a paired drafter GGUF.
    catalog.push(HfModelEntry {
        id: "nemotron-3-ultra-550b-a55b".into(),
        name: "Nemotron 3 Ultra 550B-A55B (MoE)".into(),
        family: "nemotron".into(),
        hf_repo: "unsloth/NVIDIA-Nemotron-3-Ultra-550B-A55B-GGUF".into(),
        hf_filename: "UD-Q4_K_XL/NVIDIA-Nemotron-3-Ultra-550B-A55B-UD-Q4_K_XL-00001-of-00009.gguf".into(),
        parameters: "550B (MoE, 55B active)".into(),
        architecture: ModelArchitecture::Llama,
        context_length: 1048576,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 330_000_000_000,
        min_ram_gb: 360,
        license: "NVIDIA Open Model, Weights & Data".into(),
        description: "NVIDIA Nemotron 3 Ultra — 550B total / 55B active hybrid Transformer-Mamba MoE with Latent MoE and a built-in Multi-Token-Prediction head; up to 1M context.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    // Omni takes audio, video, text, images and documents in and emits
    // text. The vision path needs the separate `mmproj` sibling, which is
    // why it is declared here rather than left for the loader to guess.
    catalog.push(HfModelEntry {
        id: "nemotron-3-nano-omni-30b-a3b".into(),
        name: "Nemotron 3 Nano Omni 30B-A3B (MoE, multimodal)".into(),
        family: "nemotron".into(),
        hf_repo: "unsloth/NVIDIA-Nemotron-3-Nano-Omni-30B-A3B-Reasoning-GGUF".into(),
        hf_filename: "NVIDIA-Nemotron-3-Nano-Omni-30B-A3B-Reasoning-UD-Q4_K_XL.gguf".into(),
        parameters: "30B (MoE, 3B active)".into(),
        architecture: ModelArchitecture::Llama,
        context_length: 262144,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 18_500_000_000,
        min_ram_gb: 25,
        license: "NVIDIA Open".into(),
        description: "NVIDIA Nemotron 3 Nano Omni — 30B total / 3B active hybrid reasoning MoE, 256K context. Accepts audio, video, text, images and documents; output is text. Needs a llama.cpp-compatible backend: the vision path uses a separate mmproj file that Ollama does not load.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 128,
            experts_per_token: 6,
            shared_experts: 1,
            params_per_expert_x10: Some(2),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: Some(MmprojSpec { filename: "mmproj-F16.gguf".into() }),
        reasoning: ReasoningPolicy { supports_thinking: true, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── GLM-4 (Apache 2.0, via bartowski GGUF) ─────────────────────────
    catalog.push(HfModelEntry {
        id: "glm4-9b".into(),
        name: "GLM-4 9B Chat".into(),
        family: "glm".into(),
        hf_repo: "bartowski/glm-4-9b-chat-GGUF".into(),
        hf_filename: "glm-4-9b-chat-Q4_K_M.gguf".into(),
        parameters: "9B".into(),
        architecture: ModelArchitecture::Glm,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 5_758_885_888,
        min_ram_gb: 8,
        license: "Apache 2.0".into(),
        description: "Zhipu AI GLM-4 9B instruction-tuned, 128K context".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Kimi K2 (MIT, via unsloth GGUF) ──────────────────────────────
    catalog.push(HfModelEntry {
        id: "kimi-k2-instruct".into(),
        name: "Kimi K2 Instruct (MoE)".into(),
        family: "kimi".into(),
        hf_repo: "unsloth/Kimi-K2-Instruct-GGUF".into(),
        hf_filename: "Q4_K_M/Kimi-K2-Instruct-Q4_K_M-00001-of-00013.gguf".into(),
        parameters: "1T (MoE, 32B active)".into(),
        architecture: ModelArchitecture::Kimi,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 20_203_667_456,
        min_ram_gb: 24,
        license: "MIT".into(),
        description: "Moonshot AI Kimi K2 MoE — 1T total, 32B active, 128K context".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 384,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(26),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "kimi-k2.6".into(),
        name: "Kimi K2.6 (Hybrid Thinking, MoE)".into(),
        family: "kimi".into(),
        hf_repo: "unsloth/Kimi-K2.6-GGUF".into(),
        hf_filename: "UD-Q4_K_XL/Kimi-K2.6-UD-Q4_K_XL-00001-of-00014.gguf".into(),
        parameters: "1T (MoE, 32B active)".into(),
        architecture: ModelArchitecture::Kimi,
        context_length: 262144,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 600_000_000_000,
        min_ram_gb: 400,
        license: "MIT".into(),
        description: "Moonshot AI Kimi K2.6 hybrid-thinking MoE — 1T total params, 256K context. Replica-routed on B200-class infrastructure; Unsloth measures >40 t/s on B200. Recommended `UD-Q2_K_XL` (350GB) for size/quality balance.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 384,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(26),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    // Kimi K3 — `hf_repo` points at the Unsloth GGUF mirror for whole-model
    // serving; distributed expert extraction reads the safetensors checkpoint
    // through `moe_safetensors_repo("kimi-k3")` instead, so the two paths are
    // independent. `UD-IQ1_S` is the smallest published quant and therefore
    // the widest-reach declaration; the six folders run from it up to
    // `UD-Q8_K_XL` at 1.56 TB. `mmproj-BF16.gguf` carries the MoonViT-3d
    // projector, loaded through the mtmd path.
    catalog.push(HfModelEntry {
        id: "kimi-k3".into(),
        name: "Kimi K3 (MoE, multimodal)".into(),
        family: "kimi-k3".into(),
        hf_repo: "unsloth/Kimi-K3-GGUF".into(),
        hf_filename: "UD-IQ1_S/Kimi-K3-UD-IQ1_S-00001-of-00014.gguf".into(),
        parameters: "2.8T total / 104B active (MoE)".into(),
        architecture: ModelArchitecture::Kimi,
        context_length: 1048576,
        quantization: "UD-IQ1_S".into(),
        size_bytes: 593_997_933_024,
        min_ram_gb: 610,
        // Custom terms, not MIT: a Model-as-a-Service operator past 20M USD of
        // revenue over any 12 consecutive months needs a separate agreement
        // with Moonshot AI, and a product past 100M monthly active users or
        // 20M USD monthly revenue must display "Kimi K3" in its interface.
        // Internal use carries neither obligation.
        license: "Kimi K3 License".into(),
        description: "Moonshot AI Kimi K3 — 2.8T total parameters, 104B active, 896 routed experts with 16 selected per token and 2 shared. Kimi Delta Attention plus gated MLA across 93 layers, 1M context, 160K vocabulary, MXFP4 weights and MXFP8 activations from quantization-aware training. Text, image, and video via the MoonViT-V2 encoder. `UD-IQ1_S` (594GB) is the smallest quant; `UD-Q2_K_XL` (861GB) is the size/quality balance point. Both exceed any single machine, so whole-model serving means a pipeline cluster; a lone host runs it as distributed expert extraction instead.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 896,
            experts_per_token: 16,
            shared_experts: 2,
            params_per_expert_x10: Some(31),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: Some(MmprojSpec { filename: "mmproj-BF16.gguf".into() }),
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Ornith 1.0 (Deep Reinforce, MIT) ─────────────────────────────
    // Agentic-coding family post-trained on Gemma 4 and Qwen 3.5. Four
    // published members; Unsloth quantizes 9B (dense), 35B (MoE) and
    // 397B (MoE). The 31B dense member has no GGUF upstream.
    catalog.push(HfModelEntry {
        id: "ornith-1.0-9b".into(),
        name: "Ornith 1.0 9B".into(),
        family: "ornith".into(),
        hf_repo: "unsloth/Ornith-1.0-9B-GGUF".into(),
        hf_filename: "Ornith-1.0-9B-UD-Q4_K_XL.gguf".into(),
        parameters: "9B".into(),
        architecture: ModelArchitecture::Qwen35,
        context_length: 262144,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 5_980_000_000,
        min_ram_gb: 10,
        license: "MIT".into(),
        description: "Deep Reinforce Ornith 1.0 9B — dense agentic-coding model post-trained on Qwen 3.5, 256K context, vision input via the bundled projector. Smallest member of the Ornith family.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: Some(MmprojSpec { filename: "mmproj-F16.gguf".into() }),
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "ornith-1.0-35b".into(),
        name: "Ornith 1.0 35B (MoE)".into(),
        family: "ornith".into(),
        hf_repo: "unsloth/Ornith-1.0-35B-GGUF".into(),
        hf_filename: "Ornith-1.0-35B-UD-Q4_K_XL.gguf".into(),
        parameters: "35B (MoE, 3B active)".into(),
        architecture: ModelArchitecture::Qwen35Moe,
        context_length: 262144,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 22_320_000_000,
        min_ram_gb: 26,
        license: "MIT".into(),
        description: "Deep Reinforce Ornith 1.0 35B — agentic-coding MoE with 256 routed experts, 8 selected per token and 1 shared, over 40 layers. 256K context, vision input via the bundled projector. Designed for single-GPU deployment.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(1),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: Some(MmprojSpec { filename: "mmproj-F16.gguf".into() }),
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    // 397B ships no projector upstream even though its config declares a
    // vision tower, so `mmproj` stays None — the downloader would 404.
    catalog.push(HfModelEntry {
        id: "ornith-1.0-397b".into(),
        name: "Ornith 1.0 397B (MoE)".into(),
        family: "ornith".into(),
        hf_repo: "unsloth/Ornith-1.0-397B-GGUF".into(),
        hf_filename: "UD-Q4_K_XL/Ornith-1.0-397B-UD-Q4_K_XL-00001-of-00006.gguf".into(),
        parameters: "397B (MoE, 17B active)".into(),
        architecture: ModelArchitecture::Qwen35Moe,
        context_length: 262144,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 245_800_000_000,
        min_ram_gb: 260,
        license: "MIT".into(),
        description: "Deep Reinforce Ornith 1.0 397B — flagship agentic-coding MoE with 512 routed experts, 10 selected per token and 1 shared, over 60 layers. 256K context. Leads open-weight coding benchmarks at its size; MIT licensed with no regional limitation.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 512,
            experts_per_token: 10,
            shared_experts: 1,
            params_per_expert_x10: Some(8),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Laguna S 2.1 (Poolside, OpenMDW-1.1) ─────────────────────────
    catalog.push(HfModelEntry {
        id: "laguna-s-2.1".into(),
        name: "Laguna S 2.1 (MoE)".into(),
        family: "laguna".into(),
        hf_repo: "unsloth/Laguna-S-2.1-GGUF".into(),
        hf_filename: "UD-Q4_K_XL/Laguna-S-2.1-UD-Q4_K_XL-00001-of-00003.gguf".into(),
        parameters: "118B (MoE, 8B active)".into(),
        architecture: ModelArchitecture::Laguna,
        context_length: 1048576,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 73_400_000_000,
        min_ram_gb: 80,
        license: "OpenMDW-1.1".into(),
        description: "Poolside Laguna S 2.1 — 118B-total agentic-coding MoE, 8B active, with a token-choice router using softplus gating over 256 routed experts plus 1 shared. Grouped-query attention with interleaved full and sliding-window layers, 1M context. Native interleaved thinking between tool calls; preserve reasoning blocks across turns. Requires llama.cpp b10087 or newer.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 10,
            shared_experts: 1,
            params_per_expert_x10: Some(5),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Inkling (Thinking Machines, Apache-2.0) ──────────────────────
    // Only a BF16 projector is published upstream; there is no F16 sibling.
    catalog.push(HfModelEntry {
        id: "inkling".into(),
        name: "Inkling (MoE, multimodal)".into(),
        family: "inkling".into(),
        hf_repo: "unsloth/Inkling-GGUF".into(),
        hf_filename: "UD-Q4_K_XL/inkling-UD-Q4_K_XL-00001-of-00014.gguf".into(),
        parameters: "975B (MoE, 41B active)".into(),
        architecture: ModelArchitecture::Inkling,
        context_length: 1048576,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 587_040_000_000,
        min_ram_gb: 620,
        license: "Apache 2.0".into(),
        description: "Thinking Machines Inkling — 975B-total multimodal MoE, 41B active, routing each token to 6 of 256 experts plus 2 shared across 66 layers. Hybrid local/global attention, 1M context. Accepts text, images and 16kHz WAV audio via a hierarchical patch encoder and discrete audio tokens, all projected into one hidden space; output is text. Apache-2.0.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 6,
            shared_experts: 2,
            params_per_expert_x10: Some(36),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: Some(MmprojSpec { filename: "mmproj-BF16.gguf".into() }),
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // Inkling Small: same architecture and modalities, a fifth the size, so
    // it fits hardware the 975B never will.
    catalog.push(HfModelEntry {
        id: "inkling-small".into(),
        name: "Inkling Small (MoE, multimodal)".into(),
        family: "inkling".into(),
        hf_repo: "unsloth/Inkling-Small-GGUF".into(),
        hf_filename: "UD-Q4_K_XL/Inkling-Small-UD-Q4_K_XL-00001-of-00005.gguf".into(),
        parameters: "276B (MoE, 12B active)".into(),
        architecture: ModelArchitecture::Inkling,
        context_length: 1048576,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 170_000_000_000,
        min_ram_gb: 180,
        license: "Apache 2.0".into(),
        description: "Thinking Machines Inkling Small — 276B-total multimodal MoE, 12B active, 1M context. Accepts text, images and 16kHz WAV audio; output is text. Apache-2.0.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 6,
            shared_experts: 2,
            params_per_expert_x10: Some(10),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: Some(MmprojSpec { filename: "mmproj-BF16.gguf".into() }),
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Qwen 3.6 27B Fable-Fusion (community fine-tune, verified 2026-07-31)
    // A DavidAU merge of Qwen3.6-27B. Listed because its MTP GGUFs carry the
    // multi-token-prediction tensors in-file at Q8_0, so it drafts against
    // itself with no paired drafter — the same shape as the Unsloth MTP
    // variants but on a fine-tune an operator may prefer for long-form work.
    //
    // Uncensored: the tune deliberately removes the base model's refusal
    // behaviour. Stated plainly here rather than left in the repo name so an
    // operator choosing what their node serves is making an informed choice.
    catalog.push(HfModelEntry {
        id: "qwen3.6-27b-fable-fusion-mtp".into(),
        name: "Qwen 3.6 27B Fable-Fusion (MTP, uncensored)".into(),
        family: "qwen3.6".into(),
        hf_repo: "DavidAU/Qwen3.6-27B-Fable-Fusion-711-Uncensored-Heretic-NM-DAU-NEO-MAX-MTP-GGUF".into(),
        hf_filename: "Qwen3.6-27B-Fable-Fus-711-UnHeretic-NM-DAU-NEO-MAX-NEO-MTP-Q4_K_M.gguf".into(),
        parameters: "27B".into(),
        architecture: ModelArchitecture::Qwen36,
        // 256K native; the card documents YaRN extension to ~1.01M, which is
        // an operator decision rather than a default.
        context_length: 262144,
        quantization: "Q4_K_M".into(),
        size_bytes: 16_800_000_000,
        min_ram_gb: 24,
        license: "Apache 2.0".into(),
        description: "Qwen 3.6 27B Fable-Fusion — community fine-tune of Qwen3.6-27B tuned for long-form fiction and creative writing, with multi-token-prediction tensors carried in-file at Q8_0 so it drafts against itself. 256K native context, YaRN-extensible. Uncensored: the base model's refusal behaviour is deliberately removed.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── MiniMax M2.7 (current frontier MiniMax, via unsloth GGUF) ────
    catalog.push(HfModelEntry {
        id: "minimax-m2.7".into(),
        name: "MiniMax M2.7 (MoE)".into(),
        family: "minimax".into(),
        hf_repo: "unsloth/MiniMax-M2.7-GGUF".into(),
        hf_filename: "UD-Q4_K_XL/MiniMax-M2.7-UD-Q4_K_XL-00001-of-00004.gguf".into(),
        parameters: "230B (MoE, 10B active)".into(),
        architecture: ModelArchitecture::MiniMax,
        context_length: 1048576,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 140_000_000_000,
        min_ram_gb: 128,
        license: "MiniMax Open".into(),
        description: "MiniMax M2.7 — current frontier MiniMax MoE; Lightning Attention with 1M context. Unsloth dynamic UD-Q4_K_XL GGUF (sharded).".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 8,
            shared_experts: 0,
            params_per_expert_x10: Some(9),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── DeepSeek V3 (MIT, via unsloth GGUF) ──────────────────────────
    catalog.push(HfModelEntry {
        id: "deepseek-v3-0324".into(),
        name: "DeepSeek V3 0324 (MoE)".into(),
        family: "deepseek".into(),
        hf_repo: "unsloth/DeepSeek-V3-0324-GGUF".into(),
        hf_filename: "Q4_K_M/DeepSeek-V3-0324-Q4_K_M-00001-of-00009.gguf".into(),
        parameters: "685B (MoE, 37B active)".into(),
        architecture: ModelArchitecture::DeepSeekV3,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 377_801_089_024,
        min_ram_gb: 256,
        license: "MIT".into(),
        description: "DeepSeek V3 MoE — 685B total, 37B active, 128K context. Native Multi-Token-Prediction head (n=4, ~80% accept rate, ~1.8× decode speedup per DeepSeek tech report). Retired by upstream after 2026-07-24 in favor of DeepSeek V4.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(4),
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(27),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // NOTE: Llama models removed — not supported on Tenzro Network.
    // Mistral Small 4 (119B MoE) excluded — Q4_K_M split across multiple GGUF files.
    // Mistral Large 3 (675B MoE) excluded — Q4_K_M split across multiple GGUF files.
    // DeepSeek V4 (Pro/Flash) excluded — no community GGUF available as of 2026-04.

    // ── Qwen 3.6 (Apache 2.0, via unsloth GGUF) ──────────────────────
    catalog.push(HfModelEntry {
        id: "qwen3.6-27b".into(),
        name: "Qwen 3.6 27B".into(),
        family: "qwen3.6".into(),
        hf_repo: "unsloth/Qwen3.6-27B-GGUF".into(),
        hf_filename: "Qwen3.6-27B-Q4_K_M.gguf".into(),
        parameters: "27B".into(),
        architecture: ModelArchitecture::Qwen36,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 16_800_000_000,
        min_ram_gb: 24,
        license: "Apache 2.0".into(),
        description: "Qwen 3.6 27B — flagship dense model with 128K context".into(),
        // Vocab-matched (248320) per llama.cpp PR #19493; community-validated pairing.
        drafter_id: Some("qwen3.5-0.8b".into()),
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3.6-35b-a3b".into(),
        name: "Qwen 3.6 35B-A3B (MoE)".into(),
        family: "qwen3.6".into(),
        hf_repo: "unsloth/Qwen3.6-35B-A3B-GGUF".into(),
        hf_filename: "Qwen3.6-35B-A3B-UD-Q4_K_M.gguf".into(),
        parameters: "35B (MoE, 3B active)".into(),
        architecture: ModelArchitecture::Qwen36Moe,
        context_length: 262144,
        quantization: "Q4_K_M".into(),
        size_bytes: 21_400_000_000,
        min_ram_gb: 24,
        license: "Apache 2.0".into(),
        description: "Qwen 3.6 MoE — 35B total, ~3B active per token".into(),
        // Intentionally no drafter: `qwen3.5-0.8b` would be vocab-matched, but the
        // 3B-active-path MoE makes the speculative verify cost outweigh the draft
        // savings on consumer GPUs (RTX 3090: net-negative throughput). Re-evaluate
        // when a smaller MoE-aware drafter exists or llama.cpp PR #22673 (native MTP) merges.
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(1),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    // ── Qwen3-VL 8B Instruct (Apache-2.0, Alibaba Qwen) ───────────────
    // Vision-language: the same llama.cpp path as the text models plus an
    // mmproj tower, so images arrive on the chat surface rather than needing
    // one of the ONNX vision runtimes. 5M downloads makes it the most-used
    // model in this group by an order of magnitude.
    catalog.push(HfModelEntry {
        id: "qwen3-vl-8b".into(),
        name: "Qwen3-VL 8B Instruct".into(),
        family: "qwen3-vl".into(),
        hf_repo: "unsloth/Qwen3-VL-8B-Instruct-GGUF".into(),
        hf_filename: "Qwen3-VL-8B-Instruct-UD-Q4_K_XL.gguf".into(),
        parameters: "8B".into(),
        architecture: ModelArchitecture::Qwen3Vl,
        context_length: 262144,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 5_148_699_488,
        min_ram_gb: 8,
        license: "Apache 2.0".into(),
        description: "Qwen3-VL 8B — vision-language instruct, images on the chat surface".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: Some(MmprojSpec {
            filename: "mmproj-F16.gguf".into(),
        }),
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    // ── Qwen3-Coder-Next (Apache-2.0, Alibaba Qwen) ───────────────────
    // The coding model of the Next line. 49.6 GB at UD-Q4_K_XL — it fits a
    // 121 GB box comfortably, and does not fit a 48 GB one, which is the
    // decision the serve planner exists to make before the download starts.
    catalog.push(HfModelEntry {
        id: "qwen3-coder-next".into(),
        name: "Qwen3-Coder-Next".into(),
        family: "qwen3-next".into(),
        hf_repo: "unsloth/Qwen3-Coder-Next-GGUF".into(),
        hf_filename: "Qwen3-Coder-Next-UD-Q4_K_XL.gguf".into(),
        parameters: "80B (MoE, 3B active)".into(),
        architecture: ModelArchitecture::Qwen3Next,
        context_length: 262144,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 49_608_478_720,
        min_ram_gb: 56,
        license: "Apache 2.0".into(),
        description: "Qwen3-Coder-Next — agentic coding, long-context repository work".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        // 512 routed experts, top-10, one shared. 3 x 2048 x 512 per
        // expert per layer over 48 layers is 0.15B, so 2 at the x10 scale.
        moe: Some(MoeShape {
            num_experts: 512,
            experts_per_token: 10,
            shared_experts: 1,
            params_per_expert_x10: Some(2),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    // ── Qwen-AgentWorld 35B-A3B (Apache-2.0, Alibaba Qwen) ────────────
    // Agentic MoE: 35B total with ~3B active, so it serves at roughly the
    // cost of a 3B while holding a 35B's knowledge. 22.3 GB quantized.
    catalog.push(HfModelEntry {
        id: "qwen-agentworld-35b-a3b".into(),
        name: "Qwen-AgentWorld 35B-A3B (MoE)".into(),
        family: "qwen-agentworld".into(),
        hf_repo: "unsloth/Qwen-AgentWorld-35B-A3B-GGUF".into(),
        hf_filename: "Qwen-AgentWorld-35B-A3B-UD-Q4_K_XL.gguf".into(),
        parameters: "35B (MoE, 3B active)".into(),
        architecture: ModelArchitecture::Qwen35Moe,
        context_length: 262144,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 22_324_804_864,
        min_ram_gb: 26,
        license: "Apache 2.0".into(),
        description: "Qwen-AgentWorld 35B-A3B — agentic MoE, 3B active per token".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(1),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    // ── Qwen 3.6 MTP variants ─────────────────────────────────────────
    // Unsloth ships dedicated `-MTP-GGUF` repos for Qwen 3.6 where the
    // MTP head is built into the model file rather than shipped as a
    // sibling drafter — `drafter_id` stays None and the runtime drives
    // MTP off the `mtp_kind` field alone. Unsloth measures 160 t/s on
    // a 27B + RTX 6000 and 240 t/s on the 35B-A3B MoE with MTP enabled.
    catalog.push(HfModelEntry {
        id: "qwen3.6-27b-mtp".into(),
        name: "Qwen 3.6 27B (MTP)".into(),
        family: "qwen3.6".into(),
        hf_repo: "unsloth/Qwen3.6-27B-MTP-GGUF".into(),
        hf_filename: "Qwen3.6-27B-UD-Q4_K_XL.gguf".into(),
        parameters: "27B".into(),
        architecture: ModelArchitecture::Qwen36,
        context_length: 131072,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 17_900_000_000,
        min_ram_gb: 22,
        license: "Apache 2.0".into(),
        description: "Qwen 3.6 27B with built-in Multi-Token-Prediction head. Single-file MTP GGUF — no separate drafter needed. Unsloth: 160 t/s on RTX 6000.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "qwen3.6-35b-a3b-mtp".into(),
        name: "Qwen 3.6 35B-A3B MTP (MoE)".into(),
        family: "qwen3.6".into(),
        hf_repo: "unsloth/Qwen3.6-35B-A3B-MTP-GGUF".into(),
        hf_filename: "Qwen3.6-35B-A3B-UD-Q4_K_XL.gguf".into(),
        parameters: "35B (MoE, 3B active)".into(),
        architecture: ModelArchitecture::Qwen36Moe,
        context_length: 262144,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 22_000_000_000,
        min_ram_gb: 28,
        license: "Apache 2.0".into(),
        description: "Qwen 3.6 35B-A3B MoE with built-in Multi-Token-Prediction head. Single-file MTP GGUF — no separate drafter needed. Unsloth: 240 t/s on RTX 6000.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(1),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Mistral Small 3.1 / 3.2 (Apache 2.0, via unsloth GGUF) ───────
    // Drafter: alamios/Mistral-Small-3.1-DRAFT-0.5B-GGUF — Qwen2.5-0.5B base
    // fine-tuned on Mistral-Small-3.1 outputs across 6 languages. Tokenizer
    // is vocab-compatible with Mistral-Small-3.1/3.2 by construction.
    catalog.push(HfModelEntry {
        id: "mistral-small-3.1-draft-0.5b".into(),
        name: "Mistral Small 3.1 DRAFT 0.5B".into(),
        family: "mistral".into(),
        hf_repo: "alamios/Mistral-Small-3.1-DRAFT-0.5B-GGUF".into(),
        hf_filename: "Mistral-Small-3.1-DRAFT-0.5B-Q4_K_M.gguf".into(),
        parameters: "0.5B".into(),
        // GGUF is a Qwen2.5-0.5B fine-tune — llama.cpp loads it as Qwen2.
        architecture: ModelArchitecture::Qwen2,
        context_length: 32768,
        quantization: "Q4_K_M".into(),
        size_bytes: 397_000_000,
        min_ram_gb: 1,
        license: "Apache 2.0".into(),
        description:
            "Speculative drafter for Mistral Small 3.1/3.2 — vocab-matched, 6-language fine-tune."
                .into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "mistral-small-3.1-24b".into(),
        name: "Mistral Small 3.1 24B".into(),
        family: "mistral".into(),
        hf_repo: "unsloth/Mistral-Small-3.1-24B-Instruct-2503-GGUF".into(),
        hf_filename: "Mistral-Small-3.1-24B-Instruct-2503-Q4_K_M.gguf".into(),
        parameters: "24B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 14_300_000_000,
        min_ram_gb: 16,
        license: "Apache 2.0".into(),
        description: "Mistral Small 3.1 — improved reasoning over 3.0 baseline".into(),
        drafter_id: Some("mistral-small-3.1-draft-0.5b".into()),
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "mistral-small-3.2-24b".into(),
        name: "Mistral Small 3.2 24B".into(),
        family: "mistral".into(),
        hf_repo: "unsloth/Mistral-Small-3.2-24B-Instruct-2506-GGUF".into(),
        hf_filename: "Mistral-Small-3.2-24B-Instruct-2506-Q4_K_M.gguf".into(),
        parameters: "24B".into(),
        architecture: ModelArchitecture::Mistral,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 14_300_000_000,
        min_ram_gb: 16,
        license: "Apache 2.0".into(),
        description: "Mistral Small 3.2 — latest 3-series point release".into(),
        drafter_id: Some("mistral-small-3.1-draft-0.5b".into()),
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── GPT-OSS (Apache 2.0, OpenAI's open-weights release) ──────────
    catalog.push(HfModelEntry {
        id: "gpt-oss-20b".into(),
        name: "GPT-OSS 20B".into(),
        family: "gpt-oss".into(),
        hf_repo: "unsloth/gpt-oss-20b-GGUF".into(),
        hf_filename: "gpt-oss-20b-Q4_K_M.gguf".into(),
        parameters: "20B".into(),
        architecture: ModelArchitecture::GptOss,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 12_400_000_000,
        min_ram_gb: 16,
        license: "Apache 2.0".into(),
        description: "OpenAI GPT-OSS 20B — open-weights release, native MXFP4".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "gpt-oss-120b".into(),
        name: "GPT-OSS 120B".into(),
        family: "gpt-oss".into(),
        hf_repo: "unsloth/gpt-oss-120b-GGUF".into(),
        hf_filename: "Q4_K_M/gpt-oss-120b-Q4_K_M-00001-of-00002.gguf".into(),
        parameters: "120B".into(),
        architecture: ModelArchitecture::GptOss,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 73_500_000_000,
        min_ram_gb: 80,
        license: "Apache 2.0".into(),
        description: "OpenAI GPT-OSS 120B — open-weights release, native MXFP4".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 128,
            experts_per_token: 4,
            shared_experts: 0,
            params_per_expert_x10: Some(9),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── IBM Granite 4.0 (Apache 2.0) ─────────────────────────────────
    catalog.push(HfModelEntry {
        id: "granite4-350m".into(),
        name: "Granite 4.0 350M".into(),
        family: "granite".into(),
        hf_repo: "ibm-granite/granite-4.0-350m-GGUF".into(),
        hf_filename: "granite-4.0-350m-Q4_K_M.gguf".into(),
        parameters: "350M".into(),
        architecture: ModelArchitecture::Granite,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 220_000_000,
        min_ram_gb: 1,
        license: "Apache 2.0".into(),
        description: "IBM Granite 4.0 350M — ultra-compact for edge deployment".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "granite4-1b".into(),
        name: "Granite 4.0 1B".into(),
        family: "granite".into(),
        hf_repo: "ibm-granite/granite-4.0-1b-GGUF".into(),
        hf_filename: "granite-4.0-1b-Q4_K_M.gguf".into(),
        parameters: "1B".into(),
        architecture: ModelArchitecture::Granite,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 700_000_000,
        min_ram_gb: 2,
        license: "Apache 2.0".into(),
        description: "IBM Granite 4.0 1B — compact enterprise model".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "granite4-h-tiny".into(),
        name: "Granite 4.0 H-Tiny".into(),
        family: "granite".into(),
        hf_repo: "ibm-granite/granite-4.0-h-tiny-GGUF".into(),
        hf_filename: "granite-4.0-h-tiny-Q4_K_M.gguf".into(),
        parameters: "7B (hybrid)".into(),
        architecture: ModelArchitecture::GraniteH,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 4_300_000_000,
        min_ram_gb: 8,
        license: "Apache 2.0".into(),
        description: "IBM Granite 4.0 H-Tiny — hybrid Mamba/Transformer architecture".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "granite4-h-small".into(),
        name: "Granite 4.0 H-Small (32B)".into(),
        family: "granite".into(),
        hf_repo: "unsloth/granite-4.0-h-small-GGUF".into(),
        hf_filename: "granite-4.0-h-small-Q4_K_M.gguf".into(),
        parameters: "32B (hybrid)".into(),
        architecture: ModelArchitecture::GraniteH,
        context_length: 131072,
        quantization: "Q4_K_M".into(),
        size_bytes: 19_400_000_000,
        min_ram_gb: 24,
        license: "Apache 2.0".into(),
        description: "IBM Granite 4.0 H-Small — 32B hybrid for long-context enterprise".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: None,
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── GLM 5 / 5.1 / 5.2 (MIT, via unsloth + zai-org GGUF) ──────────
    catalog.push(HfModelEntry {
        id: "glm-5".into(),
        name: "GLM-5 (MoE)".into(),
        family: "glm".into(),
        hf_repo: "unsloth/GLM-5-GGUF".into(),
        hf_filename: "UD-Q4_K_XL/GLM-5-UD-Q4_K_XL-00001-of-00010.gguf".into(),
        parameters: "744B (MoE, 40B active)".into(),
        architecture: ModelArchitecture::Glm,
        context_length: 202752,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 400_000_000_000,
        min_ram_gb: 256,
        license: "MIT".into(),
        description: "Z.ai GLM-5 — 744B total parameter MoE, 40B active, trained on 28.5T tokens. Routes each token to 8 of 256 experts plus 1 shared across 75 MoE layers, with DeepSeek Sparse Attention over a 198K context. Unsloth dynamic UD-Q4_K_XL GGUF (sharded).".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(28),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "glm-5.1".into(),
        name: "GLM-5.1 (MoE)".into(),
        family: "glm".into(),
        hf_repo: "unsloth/GLM-5.1-GGUF".into(),
        hf_filename: "UD-Q4_K_M/GLM-5.1-UD-Q4_K_M-00001-of-00011.gguf".into(),
        parameters: "744B (MoE, 40B active)".into(),
        architecture: ModelArchitecture::Glm,
        context_length: 202752,
        quantization: "UD-Q4_K_M".into(),
        size_bytes: 400_000_000_000,
        min_ram_gb: 256,
        license: "MIT".into(),
        description: "Z.ai GLM-5.1 — next-generation flagship for agentic engineering, class-leading on SWE-Bench Pro; 744B total / 40B active, 8 of 256 experts plus 1 shared across 75 MoE layers; 198K context. `glm_moe_dsa` architecture with Dynamic Sparse Attention.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(28),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "glm-5.2".into(),
        name: "GLM-5.2 (MoE, MTP)".into(),
        family: "glm".into(),
        hf_repo: "unsloth/GLM-5.2-GGUF".into(),
        hf_filename: "UD-Q4_K_XL/GLM-5.2-UD-Q4_K_XL-00001-of-00011.gguf".into(),
        parameters: "753B (MoE, 40B active)".into(),
        architecture: ModelArchitecture::Glm,
        context_length: 1048576,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 410_000_000_000,
        min_ram_gb: 256,
        license: "MIT".into(),
        description: "Z.ai GLM-5.2 — 753B total parameter MoE flagship, 40B active, routing each token to 8 of 256 experts plus 1 shared across 75 MoE layers. Solid 1M-token context with IndexShare sparse-attention (2.9× per-token FLOP reduction at 1M). Improved Multi-Token-Prediction layer increases speculative-decoding accept rate by ~20% over GLM-5.1.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(2),
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(28),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── MiniMax M3 (MIT, via unsloth GGUF) ───────────────────────────
    catalog.push(HfModelEntry {
        id: "minimax-m3".into(),
        name: "MiniMax M3 (MoE, native multimodal)".into(),
        family: "minimax".into(),
        hf_repo: "unsloth/MiniMax-M3-GGUF".into(),
        hf_filename: "MXFP4_MOE/MiniMax-M3-MXFP4_MOE-00001-of-00007.gguf".into(),
        parameters: "428B (MoE, 23B active)".into(),
        architecture: ModelArchitecture::MiniMax,
        context_length: 1048576,
        quantization: "Q4_K_M".into(),
        size_bytes: 230_000_000_000,
        min_ram_gb: 192,
        license: "MIT".into(),
        description: "MiniMax M3 — ~428B total / ~23B active MoE with native multimodal training. MiniMax Sparse Attention (MSA) delivers 9× prefill and 15× decode speedups vs M2 at 1M context. Note: GGUF builds currently fall back to dense attention; sparse attention not yet supported in llama.cpp.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 128,
            experts_per_token: 4,
            shared_experts: 1,
            params_per_expert_x10: Some(34),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── DeepSeek V4 (MIT, via unsloth — safetensors mirrors; GGUF community ports) ──
    // V4 supersedes V3 from 2026-07-24. Two variants: Pro (1.6T / 49B
    // active) and Flash (284B / 13B active). Both 1M context.
    // Note: Instruct variants are QAT-trained at FP4 for experts — GGUF
    // conversion is non-trivial. Flash now pins the official
    // `unsloth/DeepSeek-V4-Flash-0731-GGUF` (verified 2026-07-31); Pro still
    // has no official sharded GGUF and stays on the community build.
    catalog.push(HfModelEntry {
        id: "deepseek-v4-flash".into(),
        name: "DeepSeek V4 Flash (MoE)".into(),
        family: "deepseek".into(),
        hf_repo: "unsloth/DeepSeek-V4-Flash-0731-GGUF".into(),
        hf_filename: "UD-Q4_K_XL/DeepSeek-V4-Flash-0731-UD-Q4_K_XL-00001-of-00005.gguf".into(),
        parameters: "284B (MoE, 13B active)".into(),
        architecture: ModelArchitecture::DeepSeekV3,
        context_length: 1048576,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 155_000_000_000,
        min_ram_gb: 128,
        license: "MIT".into(),
        description: "DeepSeek V4 Flash 0731 — 284B total / 13B active MoE; 1M context. Hybrid Compressed Sparse Attention (CSA) + Heavily Compressed Attention (HCA). Quantization-aware-trained: routed experts (96% of the model) natively MXFP4, the rest FP8/BF16. Outperforms V4-Pro Preview. MTP head built into the model file.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(4),
        moe: Some(MoeShape {
            num_experts: 256,
            experts_per_token: 6,
            shared_experts: 1,
            params_per_expert_x10: Some(11),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "deepseek-v4-pro".into(),
        name: "DeepSeek V4 Pro (MoE)".into(),
        family: "deepseek".into(),
        hf_repo: "antirez/deepseek-v4-gguf".into(),
        hf_filename: "DeepSeek-V4-Pro-IQ2XXS-w2Q2K-AProjQ8-SExpQ8-OutQ8-Instruct.gguf".into(),
        parameters: "1.6T (MoE, 49B active)".into(),
        architecture: ModelArchitecture::DeepSeekV3,
        context_length: 1048576,
        quantization: "IQ2XXS".into(),
        size_bytes: 440_000_000_000,
        min_ram_gb: 470,
        license: "MIT".into(),
        description: "DeepSeek V4 Pro — 1.6T total / 49B active MoE; 1M context. CSA+HCA hybrid attention reduces single-token inference to 27% of V3.2 FLOPs and 10% of KV cache at 1M. Frontier intelligence variant. MTP head built into the model file.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::DraftMtp,
        mtp_default_draft_n: Some(4),
        moe: Some(MoeShape {
            num_experts: 384,
            experts_per_token: 6,
            shared_experts: 1,
            params_per_expert_x10: Some(40),
        }),
        // The community repo's Q4K build is a non-standard manual 2-file
        // layer split (`...Layers00-30.gguf` + `...Layers-31-output.gguf`),
        // NOT gguf-split numbering, so llama.cpp will not auto-continue it.
        // This entry pins the single-file IQ2XXS instead, which loads
        // normally. Still gated out: at 2 bits over a 1.6T MoE the quality
        // is not something to serve to the network by default, and there is
        // no official Unsloth Pro GGUF yet to promote to.
        promotable: false,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Kimi K2.5 + K2.7-Code (MIT, via moonshotai/unsloth) ──────────
    catalog.push(HfModelEntry {
        id: "kimi-k2.5".into(),
        name: "Kimi K2.5 (MoE)".into(),
        family: "kimi".into(),
        hf_repo: "unsloth/Kimi-K2.5-GGUF".into(),
        hf_filename: "UD-Q4_K_XL/Kimi-K2.5-UD-Q4_K_XL-00001-of-00013.gguf".into(),
        parameters: "1T (MoE, 32B active)".into(),
        architecture: ModelArchitecture::Kimi,
        context_length: 262144,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 580_000_000_000,
        min_ram_gb: 384,
        license: "MIT".into(),
        description: "Moonshot AI Kimi K2.5 — 1T total / 32B active MoE; image input support; 256K context. Predecessor to K2.6's hybrid-thinking variant.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 384,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(26),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });
    catalog.push(HfModelEntry {
        id: "kimi-k2.7-code".into(),
        name: "Kimi K2.7 Code (MoE)".into(),
        family: "kimi".into(),
        hf_repo: "unsloth/Kimi-K2.7-Code-GGUF".into(),
        hf_filename: "UD-Q4_K_XL/Kimi-K2.7-Code-UD-Q4_K_XL-00001-of-00014.gguf".into(),
        parameters: "1T (MoE, 32B active, code-focused)".into(),
        architecture: ModelArchitecture::Kimi,
        context_length: 262144,
        quantization: "UD-Q4_K_XL".into(),
        size_bytes: 580_000_000_000,
        min_ram_gb: 384,
        license: "MIT".into(),
        description: "Moonshot AI Kimi K2.7 Code — code-focused refresh of the K2 series. 1T total / 32B active; 256K context; recent updates target tool-call accuracy on long-horizon coding tasks.".into(),
        drafter_id: None,
        mtp_kind: MtpKind::None,
        mtp_default_draft_n: None,
        moe: Some(MoeShape {
            num_experts: 384,
            experts_per_token: 8,
            shared_experts: 1,
            params_per_expert_x10: Some(26),
        }),
        promotable: true,
        serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
    });

    // ── Qwen 3.5 MTP variants (Apache 2.0, via unsloth GGUF) ──────────
    // Unsloth published MTP-paired GGUFs for every Qwen 3.5 size in the
    // dedicated `Qwen3.5-<size>-MTP-GGUF` repos (the MTP head is baked
    // into the GGUF — the *repo* carries the MTP designation, the
    // filename does NOT). Smaller sizes are single-file UD-Q4_K_XL;
    // 122B/397B are gguf-split sharded (point at the first shard, the
    // rest auto-load). No separate drafter target needed at runtime
    // (`--spec-type draft-mtp`).
    for &(id, name_size, hf_size, gguf_size, params, ctx, sz, ram, is_moe, shards, moe_shape) in &[
        (
            "qwen3.5-0.8b-mtp",
            "0.8B",
            "0.8B",
            "0.8B",
            "0.8B",
            131072_u32,
            540_000_000_u64,
            2_u32,
            false,
            0_u32,
            None::<(u32, u8, u32, Option<u32>)>,
        ),
        (
            "qwen3.5-2b-mtp",
            "2B",
            "2B",
            "2B",
            "2B",
            131072,
            1_300_000_000,
            4,
            false,
            0,
            None,
        ),
        (
            "qwen3.5-4b-mtp",
            "4B",
            "4B",
            "4B",
            "4B",
            131072,
            2_500_000_000,
            6,
            false,
            0,
            None,
        ),
        (
            "qwen3.5-9b-mtp",
            "9B",
            "9B",
            "9B",
            "9B",
            131072,
            5_500_000_000,
            12,
            false,
            0,
            None,
        ),
        (
            "qwen3.5-27b-mtp",
            "27B",
            "27B",
            "27B",
            "27B",
            131072,
            17_000_000_000,
            24,
            false,
            0,
            None,
        ),
        (
            "qwen3.5-35b-a3b-mtp",
            "35B-A3B (MoE)",
            "35B-A3B",
            "35B-A3B",
            "35B (MoE, 3B active)",
            131072,
            22_500_000_000,
            28,
            true,
            0,
            Some((128, 8, 0, Some(2))),
        ),
        (
            "qwen3.5-122b-a10b-mtp",
            "122B-A10B (MoE)",
            "122B-A10B",
            "122B-A10B",
            "122B (MoE, 10B active)",
            131072,
            75_000_000_000,
            96,
            true,
            3,
            Some((128, 8, 0, Some(8))),
        ),
        (
            "qwen3.5-397b-a17b-mtp",
            "397B-A17B (MoE)",
            "397B-A17B",
            "397B-A17B",
            "397B (MoE, 17B active)",
            131072,
            240_000_000_000,
            256,
            true,
            7,
            Some((128, 8, 0, Some(13))),
        ),
    ] {
        let hf_filename = if shards > 0 {
            format!(
                "UD-Q4_K_XL/Qwen3.5-{}-UD-Q4_K_XL-00001-of-{:05}.gguf",
                gguf_size, shards
            )
        } else {
            format!("Qwen3.5-{}-UD-Q4_K_XL.gguf", gguf_size)
        };
        catalog.push(HfModelEntry {
            id: id.into(),
            name: format!("Qwen 3.5 {} (MTP)", name_size),
            family: "qwen3.5".into(),
            hf_repo: format!("unsloth/Qwen3.5-{}-MTP-GGUF", hf_size),
            hf_filename,
            parameters: params.into(),
            architecture: if is_moe {
                ModelArchitecture::Qwen35Moe
            } else {
                ModelArchitecture::Qwen35
            },
            context_length: ctx,
            quantization: "UD-Q4_K_XL".into(),
            size_bytes: sz,
            min_ram_gb: ram,
            license: "Apache 2.0".into(),
            description: format!("Qwen 3.5 {} with built-in Multi-Token-Prediction head. Single-file MTP GGUF — no separate drafter needed. Unsloth measures ~1.5-2× speedup over the non-MTP baseline.", name_size),
            drafter_id: None,
            mtp_kind: MtpKind::DraftMtp,
            mtp_default_draft_n: Some(2),
            moe: moe_shape.map(|(num_experts, experts_per_token, shared_experts, params_per_expert_x10)| MoeShape {
                num_experts,
                experts_per_token,
                shared_experts,
                params_per_expert_x10,
            }),
            promotable: true,
            serving: ServingProfile::default(),
        mmproj: None,
        reasoning: ReasoningPolicy { supports_thinking: false, default_mode: ReasoningMode::Auto, thinking_safe_min_b: 0.0, thinking_min_budget_tokens: 0 },
        template_fix: TemplateFix::None,
        download_filename: String::new(),
        });
    }

    // Stamp every entry with its model-author-recommended serving profile.
    // The literals above carry a placeholder `ServingProfile::default()`;
    // this single pass is the source of truth for per-family sampler /
    // template / reasoning defaults, so the knowledge lives in exactly one
    // place rather than being duplicated across ~80 struct literals.
    //
    // The same pass stamps the multimodal projector (mmproj) so vision-
    // capable families carry their projector filename in one place. Gemma 4
    // is natively multimodal and every Unsloth Gemma-4 GGUF repo ships
    // `mmproj-F16.gguf` alongside the language model; the tiny speculative
    // `-mtp-draft` entries are text-only draft models and must NOT carry a
    // projector (they're never served to the user as the vision model).
    // Catalog build pass — derive every serving-runtime field from the
    // entry's published facts. The runtime contract: clients READ this
    // catalog and configure llama.cpp accordingly; they NEVER decide.
    // Adding a new model = adding an HfModelEntry literal + (if needed)
    // adding a row in ServingProfile::for_family / ReasoningPolicy::
    // for_family / TemplateFix::for_family. Never per-id conditionals.
    // See docs/serving-policy.md in tenzro-inference for the rationale.
    for entry in &mut catalog {
        // 1. Sampler defaults — model-author-recommended (Unsloth /
        //    upstream model card guidance), family-keyed.
        entry.serving = ServingProfile::for_family(&entry.family, entry.architecture);

        // 2. Reasoning policy — universal across all clients. The
        //    runtime resolves Auto -> thinking-ON iff size >= threshold
        //    AND budget >= threshold, otherwise thinking-OFF. Replaces
        //    the per-id `if matches!("qwen3.5-0.8b" | "qwen3.5-2b")`
        //    override the catalog used to carry — the threshold-based
        //    policy now covers the Qwen 3.5 Small-series carve-out
        //    universally (and for any future model with the same
        //    size-vs-thinking-coherence shape).
        entry.reasoning = ReasoningPolicy::for_family(&entry.family);

        // 3. Chat-template fix — declares which (if any) vendored jinja
        //    the inference client should load for this entry. Replaces
        //    the client's hand-maintained TEMPLATE_OVERRIDES map.
        entry.template_fix = TemplateFix::for_family(&entry.family);

        // 4. Download filename — flat name the HF downloader writes to
        //    `~/.tenzro/models/`. Eliminates the client's dual-stem
        //    catalog index (which existed to handle the case where the
        //    downloader wrote `<id>.gguf` while hf_filename was the
        //    canonical Unsloth mixed-case name). With this field
        //    published, the matcher reads exactly one filename.
        entry.download_filename = format!("{}.gguf", entry.id);

        // Vision: every Gemma 4 GGUF ships a mmproj-F16.gguf alongside
        // the language model. Speculative draft entries (-mtp-draft)
        // are text-only and must NOT carry a projector.
        if entry.architecture == ModelArchitecture::Gemma4 && !entry.id.ends_with("-mtp-draft") {
            entry.mmproj = Some(MmprojSpec {
                filename: "mmproj-F16.gguf".into(),
            });
        }
    }

    catalog
}

impl MoeShape {
    /// Expand the catalog-side shape into the full
    /// [`tenzro_types::model::MoeMetadata`] block used by `ModelInfo`,
    /// the inference router, and the [`crate::moe_shard::MoeShardView`].
    pub fn to_metadata(self) -> tenzro_types::model::MoeMetadata {
        let mut m = tenzro_types::model::MoeMetadata::new(
            self.num_experts,
            self.experts_per_token,
            tenzro_types::model::MoeRoutingStrategy::TopK,
        )
        .with_shared_experts(self.shared_experts);
        if let Some(p) = self.params_per_expert_x10 {
            m = m.with_params_per_expert_x10(p);
        }
        m
    }
}

impl HfModelEntry {
    /// Convert this catalog entry into a [`tenzro_types::model::ModelInfo`]
    /// bound to `provider`. Populates the MoE metadata block from the
    /// catalog's `moe` shape, the architecture string from the enum
    /// variant, and a description/parameters annotation.
    pub fn to_model_info(&self, provider: tenzro_types::Address) -> tenzro_types::ModelInfo {
        let mut info = tenzro_types::ModelInfo::new(
            self.id.clone(),
            self.name.clone(),
            self.quantization.clone(),
            tenzro_types::model::ModelModality::Text,
            provider,
        );
        info.architecture = self.architecture.to_string();
        info.description = self.description.clone();
        info.size_bytes = self.size_bytes;
        info.parameters.context_window = self.context_length;
        if let Some(shape) = self.moe {
            info = info.with_moe(shape.to_metadata());
        }
        let (tier, license_id) = license_tier_for(&self.license, &self.family);
        info = info.with_license(tier, self.license.clone(), license_id);
        info
    }
}

/// Classifies an `HfModelEntry` license string into a [`LicenseTier`] plus an
/// optional stable license id used by the operator acceptance policy. The LM
/// catalog carries only a free-text license string, so custom-license families
/// (Gemma terms) are recognised by name; everything else is treated as a
/// permissive/attribution open-weight license that any operator admits.
fn license_tier_for(license: &str, family: &str) -> (LicenseTier, Option<String>) {
    let l = license.to_ascii_lowercase();
    if l.contains("gemma") || family.starts_with("gemma") {
        (LicenseTier::CommercialCustom, Some("gemma".to_string()))
    } else if l.contains("cc-by") {
        (LicenseTier::Attribution, None)
    } else {
        (LicenseTier::Permissive, None)
    }
}

/// Stable license id for a custom-license (`CommercialCustom`) model, derived
/// from its free-text license string. The multi-modal ONNX catalogs carry a
/// `license_tier` but no explicit id, so the acceptance-policy check needs a
/// canonical id to match against `--accept-license <id>`. Returns `None` for
/// permissive/attribution licenses (no id is required to admit those).
pub fn custom_license_id(license: &str) -> Option<String> {
    let l = license.to_ascii_lowercase();
    if l.contains("flux") || l.contains("bfl") {
        // The FLUX.2 non-commercial / BFL custom terms. Gated on the Hub *and*
        // custom-licensed, which are two separate gates: the token gets the
        // bytes, this gets the operator's acknowledgement of the terms.
        Some("bfl-flux2".to_string())
    } else if l.contains("dinov3") {
        Some("dinov3".to_string())
    } else if l.contains("gemma") {
        Some("gemma".to_string())
    } else if l.contains("ltx") {
        // Lightricks' LTX Open Weights terms: freely redistributable, with
        // revenue-scale conditions on commercial use that the operator has to
        // acknowledge rather than the loader infer.
        Some("ltx-open-weights".to_string())
    } else if l.contains("minimax") {
        // MiniMax's H3 Community License. Unlike every other custom licence in
        // this table, its restriction is **territorial**: the grant covers
        // "worldwide, excluding the European Union, the United Kingdom, the
        // Republic of Korea and the United States of America", and §IV.4
        // extends that exclusion to the model's *outputs*, not only its
        // weights. Acknowledging it is therefore a statement about where the
        // operator is, which no loader can infer.
        Some("minimax-h3-community".to_string())
    } else if l.contains("nvidia open model") {
        Some("nvidia-open-model".to_string())
    } else if l.contains("nxai") {
        Some("nxai-community".to_string())
    } else if l.contains("sam") {
        Some("meta-sam".to_string())
    } else {
        None
    }
}

/// Look up a model by its internal ID.
pub fn get_model_by_id(id: &str) -> Option<HfModelEntry> {
    get_model_catalog().into_iter().find(|m| m.id == id)
}

/// HuggingFace repository holding the original (unquantized)
/// safetensors checkpoint for a MoE catalog entry. The serving
/// artifact (`hf_repo`/`hf_filename`) is a quantized GGUF for
/// whole-model llama.cpp serving; distributed expert extraction
/// (`crate::moe_extract`) instead slices per-expert weights out of the
/// safetensors layout, so MoE entries carry this second source.
/// `None` means expert extraction is not yet available for the entry.
pub fn moe_safetensors_repo(model_id: &str) -> Option<&'static str> {
    match model_id {
        "qwen3-30b-a3b" => Some("Qwen/Qwen3-30B-A3B"),
        "deepseek-v3-0324" => Some("deepseek-ai/DeepSeek-V3-0324"),
        "deepseek-v4-flash" => Some("deepseek-ai/DeepSeek-V4-Flash"),
        "deepseek-v4-pro" => Some("deepseek-ai/DeepSeek-V4-Pro"),
        "kimi-k2-instruct" => Some("moonshotai/Kimi-K2-Instruct"),
        "kimi-k2.6" => Some("moonshotai/Kimi-K2.6"),
        "kimi-k3" => Some("moonshotai/Kimi-K3"),
        _ => None,
    }
}

/// Get all model families.
pub fn get_model_families() -> Vec<String> {
    let catalog = get_model_catalog();
    let mut families: Vec<String> = catalog.iter().map(|m| m.family.clone()).collect();
    families.sort();
    families.dedup();
    families
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catalog_not_empty() {
        let catalog = get_model_catalog();
        assert!(!catalog.is_empty());
        assert!(
            catalog.len() >= 20,
            "Expected at least 20 models in catalog"
        );
    }

    #[test]
    fn test_all_entries_have_required_fields() {
        for entry in get_model_catalog() {
            assert!(!entry.id.is_empty(), "Model ID empty");
            assert!(!entry.name.is_empty(), "Model name empty for {}", entry.id);
            assert!(!entry.hf_repo.is_empty(), "HF repo empty for {}", entry.id);
            // Extraction-only MoE entries carry no whole-model GGUF
            // serving artifact yet: hf_filename is empty, size/RAM are
            // unset, and the entry is not promotable. They must instead
            // map to a safetensors checkpoint source for per-expert
            // extraction.
            let extraction_only = entry.hf_filename.is_empty();
            if extraction_only {
                assert!(
                    !entry.promotable,
                    "{} has no serving artifact but is promotable",
                    entry.id
                );
                assert!(
                    entry.moe.is_some(),
                    "{} has no serving artifact and no MoE shape",
                    entry.id
                );
                assert!(
                    moe_safetensors_repo(&entry.id).is_some(),
                    "{} has no serving artifact and no safetensors source",
                    entry.id
                );
            } else {
                assert!(entry.size_bytes > 0, "Size is 0 for {}", entry.id);
                assert!(entry.min_ram_gb > 0, "Min RAM is 0 for {}", entry.id);
            }
            assert!(
                entry.context_length > 0,
                "Context length is 0 for {}",
                entry.id
            );
            // Serving profile must be stamped (the build pass overwrites the
            // literal placeholder). Sampler values must be plausible.
            assert!(
                entry.serving.temperature >= 0.0 && entry.serving.temperature <= 2.0,
                "implausible temperature {} for {}",
                entry.serving.temperature,
                entry.id
            );
            assert!(
                entry.serving.top_p > 0.0 && entry.serving.top_p <= 1.0,
                "implausible top_p {} for {}",
                entry.serving.top_p,
                entry.id
            );
        }
    }

    /// The build pass must stamp each entry's serving profile from its
    /// family — not leave the literal `ServingProfile::default()` placeholder.
    /// Spot-check a few families whose profiles differ from the default.
    #[test]
    fn test_serving_profiles_stamped_by_family() {
        let by = |id: &str| get_model_by_id(id).expect(id).serving;
        // Gemma uses temp 1.0 / top_k 64 — distinct from the 0.7/20 default.
        let g = by("gemma3-4b");
        assert_eq!(g.temperature, 1.0, "gemma3 temperature");
        assert_eq!(g.top_k, 64, "gemma3 top_k");
        // Mistral uses low-temp instruct 0.15.
        if let Some(m) = get_model_by_id("mistral-nemo-12b") {
            assert_eq!(m.serving.temperature, 0.15, "mistral temperature");
        }
        // Every entry must have jinja required (all are chat models).
        for entry in get_model_catalog() {
            assert!(
                entry.serving.jinja_required,
                "{} should require jinja",
                entry.id
            );
        }
    }

    #[test]
    fn test_mmproj_stamped_on_gemma4_multimodal() {
        // Every Gemma 4 language model carries the projector; the tiny
        // speculative drafters do not.
        for entry in get_model_catalog() {
            if entry.architecture == ModelArchitecture::Gemma4 {
                if entry.id.ends_with("-mtp-draft") {
                    assert!(
                        entry.mmproj.is_none(),
                        "{} is a draft model and must not carry mmproj",
                        entry.id
                    );
                } else {
                    let mm = entry
                        .mmproj
                        .as_ref()
                        .unwrap_or_else(|| panic!("{} should carry mmproj", entry.id));
                    assert_eq!(mm.filename, "mmproj-F16.gguf", "{}", entry.id);
                }
            }
        }
        // Text-only families never carry a projector.
        let q = get_model_by_id("qwen3-4b").expect("qwen3-4b");
        assert!(q.mmproj.is_none(), "text-only model should have no mmproj");
    }

    #[test]
    fn test_get_model_by_id() {
        assert!(get_model_by_id("qwen3-0.6b").is_some());
        assert!(get_model_by_id("gemma3-4b").is_some());
        assert!(get_model_by_id("nonexistent").is_none());
    }

    /// Every `drafter_id` in the catalog must resolve to another catalog
    /// entry. A dangling reference would break speculative-decoding load.
    #[test]
    fn test_drafter_ids_resolve() {
        let catalog = get_model_catalog();
        for entry in &catalog {
            if let Some(drafter) = entry.drafter_id.as_ref() {
                assert!(
                    get_model_by_id(drafter).is_some(),
                    "model `{}` references unknown drafter `{}`",
                    entry.id,
                    drafter,
                );
                // A drafter must not itself nest a drafter.
                let drafter_entry = get_model_by_id(drafter).unwrap();
                assert!(
                    drafter_entry.drafter_id.is_none(),
                    "drafter `{}` itself has a drafter_id — nesting not supported",
                    drafter,
                );
                // Drafter must be smaller than target — sanity check, not a hard
                // requirement of llama.cpp but a precondition for net-positive
                // speculative decoding throughput.
                assert!(
                    drafter_entry.size_bytes < entry.size_bytes,
                    "drafter `{}` ({} bytes) is not smaller than target `{}` ({} bytes)",
                    drafter,
                    drafter_entry.size_bytes,
                    entry.id,
                    entry.size_bytes,
                );
            }
        }
    }

    /// The four target/drafter pairings we explicitly ship as of 2026-05-06.
    /// If any of these stop being wired, speculative decoding regresses for
    /// the corresponding family.
    #[test]
    fn test_known_drafter_pairings() {
        let pairs = [
            ("qwen3-32b", "qwen3-0.6b"),
            ("qwen3.6-27b", "qwen3.5-0.8b"),
            ("mistral-small-3.1-24b", "mistral-small-3.1-draft-0.5b"),
            ("mistral-small-3.2-24b", "mistral-small-3.1-draft-0.5b"),
            // Gemma 4 drafter pairings switched to Unsloth's MTP heads
            // (`mtp-gemma-4-*-it.gguf` shipped as siblings of the
            // target GGUFs). MtpKind::DraftMtp + draft_n=2 are the
            // production defaults; older `*-it-assistant` references
            // were community-converted safetensors and are no longer
            // in the catalog.
            ("gemma4-e2b", "gemma4-e2b-mtp-draft"),
            ("gemma4-e4b", "gemma4-e4b-mtp-draft"),
            ("gemma4-12b", "gemma4-12b-mtp-draft"),
            ("gemma4-26b-a4b", "gemma4-26b-a4b-mtp-draft"),
            ("gemma4-31b", "gemma4-31b-mtp-draft"),
        ];
        for (target, expected_drafter) in pairs {
            let entry =
                get_model_by_id(target).unwrap_or_else(|| panic!("missing target `{}`", target));
            assert_eq!(
                entry.drafter_id.as_deref(),
                Some(expected_drafter),
                "target `{}` should pair with drafter `{}`",
                target,
                expected_drafter,
            );
        }
    }

    #[test]
    fn test_model_families() {
        let families = get_model_families();
        assert!(families.contains(&"qwen3".to_string()));
        assert!(families.contains(&"qwen3.6".to_string()));
        assert!(families.contains(&"gemma3".to_string()));
        assert!(families.contains(&"gemma4".to_string()));
        assert!(families.contains(&"mistral".to_string()));
        assert!(families.contains(&"nemotron".to_string()));
        assert!(families.contains(&"glm".to_string()));
        assert!(families.contains(&"kimi".to_string()));
        assert!(families.contains(&"minimax".to_string()));
        assert!(families.contains(&"deepseek".to_string()));
        assert!(families.contains(&"gpt-oss".to_string()));
        assert!(families.contains(&"granite".to_string()));
    }

    #[test]
    fn test_2026_additions_present() {
        assert!(get_model_by_id("qwen3.6-27b").is_some());
        assert!(get_model_by_id("qwen3.6-35b-a3b").is_some());
        assert!(get_model_by_id("mistral-small-3.1-24b").is_some());
        assert!(get_model_by_id("mistral-small-3.2-24b").is_some());
        assert!(get_model_by_id("gpt-oss-20b").is_some());
        assert!(get_model_by_id("gpt-oss-120b").is_some());
        assert!(get_model_by_id("granite4-350m").is_some());
        assert!(get_model_by_id("granite4-1b").is_some());
        assert!(get_model_by_id("granite4-h-tiny").is_some());
        assert!(get_model_by_id("granite4-h-small").is_some());
    }

    #[test]
    fn test_unique_ids() {
        let catalog = get_model_catalog();
        let mut ids: Vec<&str> = catalog.iter().map(|m| m.id.as_str()).collect();
        ids.sort();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "Duplicate model IDs found");
    }

    #[test]
    fn test_vision_catalog_not_empty() {
        let catalog = get_vision_catalog();
        assert!(!catalog.is_empty());
        assert!(catalog.len() >= 7, "Expected at least 7 vision encoders");
    }

    #[test]
    fn test_vision_entries_have_required_fields() {
        for e in get_vision_catalog() {
            assert!(!e.id.is_empty(), "vision id empty");
            assert!(!e.name.is_empty(), "vision name empty for {}", e.id);
            assert!(!e.hf_repo.is_empty(), "vision repo empty for {}", e.id);
            assert!(
                e.hf_filename.ends_with(".onnx"),
                "vision filename not .onnx for {}: {}",
                e.id,
                e.hf_filename
            );
            assert!(e.input_size > 0, "input_size 0 for {}", e.id);
            assert!(e.embedding_dim > 0, "embedding_dim 0 for {}", e.id);
            assert!(e.size_bytes > 0, "size 0 for {}", e.id);
            assert!(e.min_ram_gb > 0, "min ram 0 for {}", e.id);
            assert!(
                matches!(e.normalization.as_str(), "clip" | "imagenet" | "siglip"),
                "unknown normalization '{}' for {}",
                e.normalization,
                e.id
            );
        }
    }

    #[test]
    fn test_vision_get_by_id() {
        assert!(get_vision_model_by_id("clip-vit-b32").is_some());
        assert!(get_vision_model_by_id("siglip2-base-224").is_some());
        assert!(get_vision_model_by_id("dinov3-vitl16").is_some());
        assert!(get_vision_model_by_id("nonexistent").is_none());
    }

    #[test]
    fn test_vision_unique_ids() {
        let catalog = get_vision_catalog();
        let mut ids: Vec<&str> = catalog.iter().map(|m| m.id.as_str()).collect();
        ids.sort();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "Duplicate vision model IDs");
    }

    #[test]
    fn test_vision_families_present() {
        let catalog = get_vision_catalog();
        let families: std::collections::HashSet<&str> =
            catalog.iter().map(|m| m.family.as_str()).collect();
        assert!(families.contains("clip"));
        assert!(families.contains("siglip"));
        assert!(families.contains("siglip2"));
        assert!(families.contains("dinov3"));
    }

    #[test]
    fn test_forecast_catalog_not_empty() {
        let catalog = get_forecast_catalog();
        assert!(!catalog.is_empty());
    }

    #[test]
    fn test_forecast_entries_have_required_fields() {
        for e in get_forecast_catalog() {
            assert!(!e.id.is_empty(), "forecast id empty");
            assert!(!e.name.is_empty(), "forecast name empty for {}", e.id);
            assert!(!e.hf_repo.is_empty(), "forecast repo empty for {}", e.id);
            assert!(
                e.hf_filename.ends_with(".onnx"),
                "forecast filename not .onnx for {}: {}",
                e.id,
                e.hf_filename
            );
            assert!(e.context_length > 0, "context_length 0 for {}", e.id);
            assert!(e.max_horizon > 0, "max_horizon 0 for {}", e.id);
            assert!(e.size_bytes > 0, "size 0 for {}", e.id);
            assert!(e.min_ram_gb > 0, "min ram 0 for {}", e.id);
            assert!(!e.parameters.is_empty(), "parameters empty for {}", e.id);
            assert!(!e.license.is_empty(), "license empty for {}", e.id);
            assert!(
                e.batch_size > 0,
                "batch_size 0 for {} — the runtime tiles input to this width",
                e.id
            );
            if let Some(name) = &e.output_name {
                assert!(!name.is_empty(), "empty output_name for {}", e.id);
            }
        }
    }

    #[test]
    fn test_forecast_custom_licenses_are_acceptable() {
        // A forecaster under a custom commercial license is admissible only
        // if its license string maps to an acceptance id, because
        // `check_model_license` refuses the load until the operator accepted
        // that id via `--accept-license`.
        for e in get_forecast_catalog() {
            if matches!(e.license_tier, LicenseTier::CommercialCustom) {
                assert!(
                    custom_license_id(&e.license).is_some(),
                    "{} is CommercialCustom but its license '{}' maps to no \
                     acceptance id, so --accept-license could never admit it",
                    e.id,
                    e.license
                );
            }
        }
    }

    #[test]
    fn test_tirex_single_pass_quantile_shape() {
        // TiRex emits exactly 32 steps × 9 quantiles per forward pass, and
        // GenericForecast reads the median at index q / 2 = 4, which is where
        // TiRex puts it. Raising max_horizon past 32 would need an
        // autoregressive roll-forward the runtime does not implement.
        let tirex = get_forecast_model_by_id("tirex-35m").unwrap();
        assert_eq!(tirex.max_horizon, 32);
        assert_eq!(tirex.n_quantiles, 9);
        assert_eq!(tirex.n_quantiles / 2, 4);
        assert_eq!(tirex.batch_size, 1);
        assert!(tirex.output_name.is_none());
        assert!(matches!(tirex.license_tier, LicenseTier::CommercialCustom));
    }

    #[test]
    fn test_timesfm_graph_quirks_are_recorded() {
        // Both quirks are properties of the published graph, not caller
        // choices: the decoder averages across the batch axis for flip
        // invariance, and the first output is a hidden state.
        let t = get_forecast_model_by_id("timesfm-2.5-200m").unwrap();
        assert_eq!(t.batch_size, 2);
        assert_eq!(t.output_name.as_deref(), Some("full_predictions"));
    }

    #[test]
    fn test_forecast_get_by_id() {
        assert!(get_forecast_model_by_id("timesfm-2.5-200m").is_some());
        assert!(get_forecast_model_by_id("nonexistent").is_none());
    }

    #[test]
    fn test_forecast_unique_ids() {
        let catalog = get_forecast_catalog();
        let mut ids: Vec<&str> = catalog.iter().map(|m| m.id.as_str()).collect();
        ids.sort();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "Duplicate forecast model IDs");
    }

    #[test]
    fn test_forecast_families_present() {
        let catalog = get_forecast_catalog();
        let families: std::collections::HashSet<&str> =
            catalog.iter().map(|m| m.family.as_str()).collect();
        assert!(families.contains("timesfm"));
    }

    #[test]
    fn test_forecast_quantile_shape_invariant() {
        // n_quantiles > 0 → quantile head; TimesFM 2.5 ships 10 bands.
        let timesfm = get_forecast_model_by_id("timesfm-2.5-200m").unwrap();
        assert_eq!(timesfm.n_quantiles, 10);
    }

    // ── Vision catalog (DINOv3 + SigLIP2 large/so400m) ──────────────

    #[test]
    fn test_vision_dinov3_entries_present() {
        for id in &["dinov3-vits16", "dinov3-vitb16", "dinov3-vitl16"] {
            let e =
                get_vision_model_by_id(id).unwrap_or_else(|| panic!("missing dinov3 entry {}", id));
            assert_eq!(e.family, "dinov3");
            assert_eq!(e.license_tier, LicenseTier::CommercialCustom);
        }
    }

    #[test]
    fn test_vision_siglip2_large_so400m_present() {
        for id in &["siglip2-large-256", "siglip2-so400m-384"] {
            let e = get_vision_model_by_id(id)
                .unwrap_or_else(|| panic!("missing siglip2 entry {}", id));
            assert_eq!(e.family, "siglip2");
            assert_eq!(e.license_tier, LicenseTier::Permissive);
        }
    }

    // ── Text embedding catalog ─────────────────────────────────────

    #[test]
    fn test_text_embedding_catalog_not_empty() {
        let catalog = get_text_embedding_catalog();
        assert!(
            catalog.len() >= 5,
            "expected at least 5 text-embedding models"
        );
    }

    #[test]
    fn test_text_embedding_required_fields() {
        for e in get_text_embedding_catalog() {
            assert!(!e.id.is_empty());
            assert!(!e.hf_repo.is_empty());
            assert!(e.hf_filename.ends_with(".onnx"), "{} not .onnx", e.id);
            assert!(e.tokenizer_filename.ends_with(".json"));
            assert!(e.max_sequence_length > 0);
            assert!(e.embedding_dim > 0);
            assert!(e.size_bytes > 0);
            assert!(e.min_ram_gb > 0);
        }
    }

    #[test]
    fn test_text_embedding_qwen3_family() {
        for id in &[
            "qwen3-embedding-0.6b",
            "qwen3-embedding-4b",
            "qwen3-embedding-8b",
        ] {
            let e = get_text_embedding_model_by_id(id)
                .unwrap_or_else(|| panic!("missing qwen3-embedding {}", id));
            assert_eq!(e.family, "qwen3-embedding");
            assert_eq!(e.license_tier, LicenseTier::Permissive);
        }
    }

    #[test]
    fn test_embeddinggemma_matryoshka() {
        let e = get_text_embedding_model_by_id("embeddinggemma-300m").unwrap();
        assert_eq!(e.embedding_dim, 768);
        assert_eq!(e.matryoshka_dims, vec![512, 256, 128]);
        assert!(!e.supports_fp16, "EmbeddingGemma is fp32-only");
        assert_eq!(e.license_tier, LicenseTier::CommercialCustom);
    }

    #[test]
    fn test_modernbert_embed_variants() {
        let base = get_text_embedding_model_by_id("modernbert-embed-base").unwrap();
        assert_eq!(base.family, "modernbert");
        assert_eq!(base.embedding_dim, 768);
        assert_eq!(base.max_sequence_length, 8192);
        assert_eq!(base.matryoshka_dims, vec![256]);
        assert_eq!(base.license_tier, LicenseTier::Permissive);

        let large = get_text_embedding_model_by_id("modernbert-embed-large").unwrap();
        assert_eq!(large.family, "modernbert");
        assert_eq!(large.embedding_dim, 1024);
        assert_eq!(large.max_sequence_length, 8192);
        assert_eq!(large.license_tier, LicenseTier::Permissive);
    }

    #[test]
    fn test_text_embedding_unique_ids() {
        let ids: Vec<_> = get_text_embedding_catalog()
            .into_iter()
            .map(|m| m.id)
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        let len_before = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), len_before, "duplicate text-embedding IDs");
    }

    // ── Segmentation catalog ───────────────────────────────────────

    #[test]
    fn test_segmentation_catalog_not_empty() {
        let catalog = get_segmentation_catalog();
        // SAM 2 base + large, EdgeSAM, MobileSAM. SAM 3 is deferred to a
        // future text-promptable runtime — see comment in
        // `get_segmentation_catalog`.
        assert_eq!(catalog.len(), 4, "expected 4 segmentation models");
    }

    #[test]
    fn test_segmentation_sam2_permissive() {
        for id in &["sam2-base", "sam2-large"] {
            let e = get_segmentation_model_by_id(id).unwrap_or_else(|| panic!("missing {}", id));
            assert_eq!(e.license_tier, LicenseTier::Permissive);
        }
    }

    #[test]
    fn test_segmentation_edge_tier() {
        // EdgeSAM is research-only (NTU S-Lab 1.0 = NonCommercial); MobileSAM
        // is Apache 2.0. Both are <50 MB.
        let edgesam = get_segmentation_model_by_id("edgesam").expect("missing edgesam");
        assert_eq!(edgesam.license_tier, LicenseTier::NonCommercial);
        assert!(edgesam.size_bytes < 50_000_000);

        let mobilesam = get_segmentation_model_by_id("mobilesam").expect("missing mobilesam");
        assert_eq!(mobilesam.license_tier, LicenseTier::Permissive);
        assert!(mobilesam.size_bytes < 50_000_000);
    }

    #[test]
    fn test_segmentation_required_fields() {
        for e in get_segmentation_catalog() {
            assert!(!e.id.is_empty());
            assert!(e.encoder_filename.ends_with(".onnx"));
            assert!(e.decoder_filename.ends_with(".onnx"));
            assert!(e.input_size > 0);
            assert!(e.size_bytes > 0);
        }
    }

    // ── Detection catalog ──────────────────────────────────────────

    #[test]
    fn test_detection_catalog_not_empty() {
        let catalog = get_detection_catalog();
        assert!(catalog.len() >= 9, "expected ≥9 detection models");
    }

    #[test]
    fn test_detection_rf_detr_six_tiers() {
        for id in &[
            "rf-detr-nano",
            "rf-detr-small",
            "rf-detr-medium",
            "rf-detr-base",
            "rf-detr-large",
            "rf-detr-2xl",
        ] {
            let e = get_detection_model_by_id(id)
                .unwrap_or_else(|| panic!("missing rf-detr tier {}", id));
            assert_eq!(e.family, "rf-detr");
            assert_eq!(e.license_tier, LicenseTier::Permissive);
        }
    }

    #[test]
    fn test_detection_required_fields() {
        for e in get_detection_catalog() {
            assert!(!e.id.is_empty());
            assert!(e.hf_filename.ends_with(".onnx"));
            assert!(e.input_size > 0);
            assert!(e.num_classes > 0);
            assert!(e.size_bytes > 0);
        }
    }

    // ── Audio catalog ──────────────────────────────────────────────

    #[test]
    fn test_audio_catalog_not_empty() {
        let catalog = get_audio_catalog();
        assert!(catalog.len() >= 5, "expected ≥5 audio models");
    }

    #[test]
    fn test_audio_required_fields() {
        for e in get_audio_catalog() {
            assert!(!e.id.is_empty());
            assert!(e.encoder_filename.ends_with(".onnx"));
            assert_eq!(e.sample_rate, 16000);
            assert!(e.max_audio_seconds > 0);
            assert!(!e.languages.is_empty(), "{} has no languages", e.id);
        }
    }

    // ── Video catalog ──────────────────────────────────────────────

    #[test]
    fn the_video_catalog_is_empty_until_a_real_onnx_export_exists() {
        // Guards against re-adding entries the node cannot load. V-JEPA 2 sat
        // here for a while, but `facebook/vjepa2-*` ships safetensors only and
        // `handle_load_video_model` never consults this catalog — it wires the
        // frame-wise vision fallback from a `vision_model_id` instead. An entry
        // here is therefore unreachable by construction, and advertising an
        // unreachable model is worse than advertising none: callers only find
        // out after trying.
        //
        // When a permissive encoder-only video model ships a genuine ONNX
        // export, add it here AND give it a loader path in the same change.
        assert!(
            get_video_catalog().is_empty(),
            "video entries need a loader path before they are listed"
        );
        assert!(get_video_model_by_id("vjepa2-vitl-256").is_none());
    }

    // ── Speech synthesis catalog ─────────────────────────────────────

    #[test]
    fn every_tts_entry_is_permissive_and_complete() {
        let catalog = get_tts_catalog();
        assert!(!catalog.is_empty());
        for e in &catalog {
            assert_eq!(e.license, "Apache-2.0", "{} is {}", e.id, e.license);
            assert!(matches!(e.license_tier, LicenseTier::Permissive));
            assert!(e.hf_repo.starts_with("Qwen/"), "{}", e.hf_repo);
            assert!(e.size_bytes > 0 && e.min_ram_gb > 0 && e.sample_rate > 0);
            assert!(e.languages.iter().any(|l| l == "English"));
            assert_eq!(
                get_tts_model_by_id(&e.id).as_ref().map(|x| &x.id),
                Some(&e.id),
                "{} must round-trip through lookup",
                e.id
            );
        }
    }

    #[test]
    fn voice_cloning_capability_is_recorded_per_checkpoint() {
        // An operator has to be able to see which checkpoints carry cloning
        // before turning it on, rather than finding out from a request.
        let by_id: std::collections::HashMap<String, TtsModelEntry> = get_tts_catalog()
            .into_iter()
            .map(|e| (e.id.clone(), e))
            .collect();
        assert!(!by_id["qwen3-tts-1.7b"].supports_voice_cloning);
        assert!(!by_id["qwen3-tts-0.6b"].supports_voice_cloning);
        assert!(by_id["qwen3-tts-1.7b-clone"].supports_voice_cloning);
    }

    #[test]
    fn a_preset_voice_model_ships_a_voice_to_speak_with() {
        for e in get_tts_catalog() {
            if !e.supports_voice_cloning {
                assert!(!e.preset_voices.is_empty(), "{} has no voice", e.id);
            }
        }
    }

    #[test]
    fn an_unknown_tts_model_resolves_to_none() {
        assert!(get_tts_model_by_id("kokoro-82m").is_none());
    }

    // ── Generative-media catalog ─────────────────────────────────────

    /// Every media-gen entry must still satisfy the catalog's own admission
    /// rules on the real hub.
    ///
    /// The rules are documented on [`get_media_gen_catalog`]: ungated, and
    /// loadable by `diffusers` (a `model_index.json` naming a real pipeline).
    /// Both are properties of the upstream repo, not of this file, so they
    /// can stop being true without anything here changing — a repo gets
    /// gated, renamed, or re-uploaded at a different size, and the first
    /// anyone knows is a worker failing mid-job.
    ///
    /// `size_bytes` is checked to within 10%: it feeds the memory budget and
    /// the on-demand tier ceiling, so a stale figure means the node admits a
    /// pipeline against the wrong footprint.
    ///
    /// Ignored by default — it hits the network, and CI stays hermetic.
    #[tokio::test]
    #[ignore = "hits the HuggingFace API; run with --run-ignored"]
    async fn media_gen_entries_still_satisfy_their_admission_rules() {
        #[derive(serde::Deserialize)]
        struct Sibling {
            rfilename: String,
            #[serde(default)]
            size: Option<u64>,
        }
        #[derive(serde::Deserialize)]
        struct RepoInfo {
            #[serde(default)]
            gated: serde_json::Value,
            #[serde(default)]
            siblings: Vec<Sibling>,
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("client");

        let mut problems = Vec::new();
        for entry in get_media_gen_catalog() {
            let url = format!(
                "https://huggingface.co/api/models/{}?blobs=true",
                entry.hf_repo
            );
            let response = client.get(&url).send().await.expect("HF reachable");
            if !response.status().is_success() {
                problems.push(format!(
                    "{}: HF returned {} for {}",
                    entry.id,
                    response.status(),
                    entry.hf_repo
                ));
                continue;
            }
            let info: RepoInfo = response.json().await.expect("HF response parses");

            // `gated` is `false` when open, or a string like "auto"/"manual".
            if info.gated != serde_json::Value::Bool(false) {
                problems.push(format!("{}: gated ({})", entry.id, info.gated));
            }
            if !info
                .siblings
                .iter()
                .any(|s| s.rfilename == "model_index.json")
            {
                problems.push(format!(
                    "{}: no model_index.json — not loadable by diffusers::from_pretrained",
                    entry.id
                ));
            }

            let actual: u64 = info.siblings.iter().filter_map(|s| s.size).sum();
            if actual > 0 && entry.size_bytes > 0 {
                let drift = (actual as f64 - entry.size_bytes as f64).abs()
                    / entry.size_bytes as f64
                    * 100.0;
                if drift > 10.0 {
                    problems.push(format!(
                        "{}: size drifted {drift:.0}% (catalog {:.1} GB, actual {:.1} GB) — the \
                         memory budget would admit it against the wrong footprint",
                        entry.id,
                        entry.size_bytes as f64 / 1e9,
                        actual as f64 / 1e9
                    ));
                }
            }
        }

        assert!(
            problems.is_empty(),
            "catalog drift:\n  {}",
            problems.join("\n  ")
        );
    }

    #[test]
    fn test_media_gen_catalog_membership() {
        let catalog = get_media_gen_catalog();
        let mut ids: Vec<&str> = catalog.iter().map(|e| e.id.as_str()).collect();
        ids.sort();
        assert_eq!(
            ids,
            vec![
                "flux2-dev",
                "flux2-klein-4b",
                "flux2-klein-9b",
                "flux2-klein-9b-kv",
                "flux2-klein-base-4b",
                "flux2-klein-base-9b",
                // Ungated on the Hub. Not loadable by `from_pretrained`
                // straight from either publishing repo — its components are
                // split across two and keyed for a diffusers older than the
                // installed one — so the worker converts them once into a
                // local snapshot named by `config_repo`.
                "ltx-2.3-22b-distilled-gguf",
                // The one entry here that is listed *without* being servable.
                // `MiniMaxH3ModularPipeline` is absent from the pinned
                // diffusers 0.39, so the worker cannot build it at all; it is
                // carried so the catalog records that the model exists and on
                // what terms, which for this one is a claim about where the
                // operator is — the H3 Community License excludes the EU, UK,
                // Korea and the US, and extends that to Outputs. Two guards
                // keep it from being enrolled by accident: a 144 GB
                // `min_vram_gb` floor and `--accept-license
                // minimax-h3-community`. See the entry's own comment.
                "minimax-h3",
                "qwen-image",
                "qwen-image-edit",
                "qwen-image-flash",
                // Same pipeline and components as `qwen-image`, transformer
                // read from Unsloth's GGUF instead of the bf16 release: still
                // ungated, still a diffusers-loadable pipeline, 15.0 GB
                // against 57.7 GB.
                "qwen-image-gguf",
                "trellis2-4b",
                "wan2.1-flf2v-14b",
                "wan2.2-i2v-a14b",
                "wan2.2-t2v-a14b",
                "wan2.2-ti2v-5b",
                "z-image-turbo",
            ],
            "media-gen membership changed — every entry must be ungated on \
             HuggingFace, and loadable by diffusers unless it is listed here \
             as a documented not-yet-constructible exception"
        );
        for e in &catalog {
            // Nothing gated survives membership, so no entry is
            // NonCommercial. A custom commercial license is admissible —
            // enrollment refuses the model unless the operator accepted it by
            // id — so every such entry must yield an id to accept.
            match e.license_tier {
                LicenseTier::Permissive | LicenseTier::Attribution => {}
                LicenseTier::CommercialCustom => assert!(
                    custom_license_id(&e.license).is_some(),
                    "{} is CommercialCustom but its license '{}' maps to no \
                     acceptance id, so --accept-license could never admit it",
                    e.id,
                    e.license
                ),
                LicenseTier::NonCommercial => panic!(
                    "{} is NonCommercial (license={}); such a model is gated \
                     on HuggingFace and fails membership",
                    e.id, e.license
                ),
            }
            assert!(!e.kinds.is_empty(), "{} serves no MediaGenKind", e.id);
            assert!(e.pipeline_class.ends_with("Pipeline"), "{}", e.id);
            assert!(e.max_resolution >= e.default_width.max(e.default_height));
            let looked_up = get_media_gen_model_by_id(&e.id)
                .unwrap_or_else(|| panic!("{} missing from catalog lookup", e.id));
            assert_eq!(looked_up.hf_repo, e.hf_repo);
        }
        assert!(get_media_gen_model_by_id("not-a-real-id").is_none());
    }

    #[test]
    fn test_media_gen_expert_pairs_are_the_two_a14b_entries() {
        let catalog = get_media_gen_catalog();
        let mut split: Vec<&str> = catalog
            .iter()
            .filter(|e| e.expert_pair.is_some())
            .map(|e| e.id.as_str())
            .collect();
        split.sort();
        assert_eq!(
            split,
            vec!["wan2.2-i2v-a14b", "wan2.2-t2v-a14b"],
            "only the Wan 2.2 A14B checkpoints ship two denoising experts"
        );
        for e in &catalog {
            let Some(ref pair) = e.expert_pair else {
                continue;
            };
            assert_ne!(pair.high_noise_component, pair.low_noise_component);
            assert!(
                pair.boundary_ratio > 0.0 && pair.boundary_ratio < 1.0,
                "{}: boundary must split the schedule",
                e.id
            );
            assert!(
                pair.min_vram_gb_per_expert < e.min_vram_gb,
                "{}: holding one expert must cost less than holding both",
                e.id
            );
        }
    }

    #[test]
    fn test_media_gen_frame_grid_snaps_up_and_defaults_are_on_grid() {
        let ltx = get_media_gen_model_by_id("ltx-2.3-22b-distilled-gguf").expect("ltx entry");
        assert_eq!(ltx.temporal_stride(), 8);
        // 2s at 24fps is the case that shipped 41 frames against a 48-frame
        // bill before this snapped.
        assert_eq!(ltx.snap_num_frames(48), 49);
        assert_eq!(ltx.snap_num_frames(49), 49, "already on grid, unchanged");
        assert_eq!(ltx.snap_num_frames(50), 57);
        assert_eq!(ltx.snap_num_frames(1), 1);

        // An image entry has no temporal grid, so every count passes through.
        let img = get_media_gen_model_by_id("qwen-image-gguf").expect("image entry");
        assert_eq!(img.temporal_stride(), 1);
        assert_eq!(img.snap_num_frames(48), 48);

        // A default the catalog hands out must itself be representable, or the
        // no-`seconds` path reintroduces exactly the mismatch snapping fixes.
        for e in get_media_gen_catalog() {
            if let Some(frames) = e.default_num_frames {
                assert_eq!(
                    e.snap_num_frames(frames),
                    frames,
                    "{}: default_num_frames {} is off its {}-frame grid",
                    e.id,
                    frames,
                    e.temporal_stride()
                );
            }
        }
    }

    #[test]
    fn test_media_gen_video_entries_carry_frame_defaults() {
        for e in get_media_gen_catalog() {
            let serves_video = e.kinds.iter().any(|k| k.is_video());
            assert_eq!(
                serves_video,
                e.default_num_frames.is_some() && e.default_fps.is_some(),
                "{}: frame/fps defaults must be present iff it serves a \
                 video kind",
                e.id
            );
        }
    }

    #[test]
    fn test_media_gen_kind_filter() {
        use tenzro_types::MediaGenKind;
        let t2v = get_media_gen_models_for_kind(MediaGenKind::Text2Video);
        assert!(
            t2v.iter()
                .all(|e| e.kinds.contains(&MediaGenKind::Text2Video))
        );
        assert!(t2v.iter().any(|e| e.id == "wan2.2-t2v-a14b"));
        // TI2V-5B is the one entry serving both video kinds.
        assert!(t2v.iter().any(|e| e.id == "wan2.2-ti2v-5b"));
        let i2v = get_media_gen_models_for_kind(MediaGenKind::Image2Video);
        assert!(i2v.iter().any(|e| e.id == "wan2.2-ti2v-5b"));
        let t2i = get_media_gen_models_for_kind(MediaGenKind::Text2Image);
        assert!(t2i.iter().any(|e| e.id == "qwen-image"));
        assert!(t2i.iter().all(|e| !e.kinds.iter().any(|k| k.is_video())));
    }

    // ── GGUF promotability / HF-resolvability verification ───────────
    //
    // The catalog is the single source of truth for which models we
    // promote to users. Two failure modes have historically slipped in:
    //   1. an entry points at a `hf_repo`/`hf_filename` that doesn't
    //      exist on HuggingFace (sharded-path typos, dot-vs-dash quant
    //      suffixes, renamed MTP drafts) — the user clicks download and
    //      gets a 404.
    //   2. an entry is left `promotable` even though its GGUF is gated
    //      (HTTP 401) or simply not published yet.
    //
    // `test_promotable_entries_have_plausible_gguf_paths` runs offline
    // on every `cargo test` and catches structural mistakes. The
    // network-gated `verify_promotable_entries_resolve_on_hf` (marked
    // `#[ignore]`) hits the HF API for every promotable entry and is the
    // CI-able regression guard — run with
    // `cargo test -p tenzro-model -- --ignored verify_promotable`.

    /// Returns true if `name` looks like the first shard of a
    /// gguf-split set (`...-00001-of-000NN.gguf`).
    fn is_first_shard(name: &str) -> bool {
        name.contains("-00001-of-")
    }

    #[test]
    fn test_promotable_entries_have_plausible_gguf_paths() {
        for entry in get_model_catalog() {
            // GGUF entries only (skip ONNX vision/audio/embedding).
            if !entry.hf_filename.ends_with(".gguf") {
                continue;
            }
            assert!(
                !entry.hf_repo.is_empty() && !entry.hf_filename.is_empty(),
                "{}: empty repo/filename",
                entry.id
            );
            // A filename that mentions a multi-part split MUST be the
            // first shard — llama.cpp only auto-continues from -00001-.
            if entry.hf_filename.contains("-of-") {
                assert!(
                    is_first_shard(&entry.hf_filename),
                    "{}: sharded filename must point at the first shard \
                     (-00001-of-...), got `{}`",
                    entry.id,
                    entry.hf_filename
                );
            }
            // No accidental leading slash / windows separators.
            assert!(
                !entry.hf_filename.starts_with('/') && !entry.hf_filename.contains('\\'),
                "{}: malformed hf_filename `{}`",
                entry.id,
                entry.hf_filename
            );
        }
    }

    #[test]
    fn test_parse_params_active_b_prefers_active_over_total() {
        // MoE forms must yield the active path width, not the total.
        assert_eq!(parse_params_active_b("1T (MoE, 32B active)"), 32.0);
        assert_eq!(
            parse_params_active_b("2.8T total / 104B active (MoE)"),
            104.0
        );
        assert_eq!(parse_params_active_b("35B (MoE, 3B active)"), 3.0);
        assert_eq!(parse_params_active_b("397B (MoE, 17B active)"), 17.0);
        assert_eq!(parse_params_active_b("975B (MoE, 41B active)"), 41.0);
        assert_eq!(parse_params_active_b("118B (MoE, 8B active)"), 8.0);
        // Hyphenated MoE form.
        assert_eq!(parse_params_active_b("30B-A3B"), 3.0);
        // Dense.
        assert_eq!(parse_params_active_b("27B"), 27.0);
        assert_eq!(parse_params_active_b("0.8B"), 0.8);
    }

    #[test]
    fn test_moe_entries_report_active_not_total_params() {
        for entry in get_model_catalog() {
            let Some(moe) = entry.moe.as_ref() else {
                continue;
            };
            let Some(per_expert_x10) = moe.params_per_expert_x10 else {
                continue;
            };
            let parsed = parse_params_active_b(&entry.parameters);
            if parsed == 0.0 {
                continue;
            }
            // Routed + shared experts alone are a lower bound on the
            // active path; attention and embeddings add to it. A parsed
            // figure below that bound means we read the total by mistake
            // or the shape is wrong.
            let expert_active_b = (per_expert_x10 as f32 / 10.0)
                * (moe.experts_per_token as f32 + moe.shared_experts as f32);
            assert!(
                parsed >= expert_active_b * 0.9,
                "{}: parsed active {}B is below the expert-only floor {}B \
                 derived from its MoE shape",
                entry.id,
                parsed,
                expert_active_b
            );
        }
    }

    #[test]
    fn test_gated_entries_are_explicitly_known() {
        // Keep the set of gated-out entries visible and intentional. If
        // a new entry is gated, add it here on purpose; if a gated entry
        // becomes downloadable, flip `promotable` and drop it here.
        let gated: Vec<String> = get_model_catalog()
            .into_iter()
            .filter(|e| !e.promotable)
            .map(|e| e.id)
            .collect();
        let mut gated_sorted = gated.clone();
        gated_sorted.sort();
        let expected = vec!["deepseek-v4-pro".to_string()];
        assert_eq!(
            gated_sorted, expected,
            "Gated-out set changed unexpectedly. Current gated: {:?}. \
             If intentional, update this test.",
            gated
        );
    }

    /// Network-gated: verifies every promotable GGUF entry resolves on
    /// HuggingFace (repo exists AND the exact `hf_filename` is present).
    /// Ignored by default so offline/`cargo test` stays hermetic; run in
    /// CI with `--ignored`.
    #[tokio::test]
    #[ignore = "network: hits huggingface.co — run with --ignored in CI"]
    async fn verify_promotable_entries_resolve_on_hf() {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("tenzro-model-catalog-verify")
            .build()
            .expect("build http client");

        // Cache repo file-listings so we hit each repo once.
        let mut repo_files: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        let mut failures: Vec<String> = Vec::new();

        for entry in get_model_catalog() {
            if !entry.promotable || !entry.hf_filename.ends_with(".gguf") {
                continue;
            }
            let files = if let Some(f) = repo_files.get(&entry.hf_repo) {
                f.clone()
            } else {
                let url = format!(
                    "https://huggingface.co/api/models/{}?blobs=true",
                    entry.hf_repo
                );
                let resp = client.get(&url).send().await;
                let files = match resp {
                    Ok(r) if r.status().is_success() => {
                        let v: serde_json::Value =
                            r.json().await.unwrap_or(serde_json::Value::Null);
                        v.get("siblings")
                            .and_then(|s| s.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|s| {
                                        s.get("rfilename")
                                            .and_then(|n| n.as_str())
                                            .map(String::from)
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default()
                    }
                    Ok(r) => {
                        failures.push(format!(
                            "{}: repo `{}` returned HTTP {}",
                            entry.id,
                            entry.hf_repo,
                            r.status()
                        ));
                        Vec::new()
                    }
                    Err(e) => {
                        failures.push(format!(
                            "{}: repo `{}` request error: {}",
                            entry.id, entry.hf_repo, e
                        ));
                        Vec::new()
                    }
                };
                repo_files.insert(entry.hf_repo.clone(), files.clone());
                files
            };

            if !files.is_empty() && !files.iter().any(|f| f == &entry.hf_filename) {
                failures.push(format!(
                    "{}: file `{}` not found in repo `{}`",
                    entry.id, entry.hf_filename, entry.hf_repo
                ));
            }

            // Vision-capable entries must have their projector present too,
            // or image input silently degrades to text-only.
            if let Some(mmproj) = entry.mmproj.as_ref()
                && !files.is_empty()
                && !files.iter().any(|f| f == &mmproj.filename)
            {
                failures.push(format!(
                    "{}: mmproj `{}` not found in repo `{}`",
                    entry.id, mmproj.filename, entry.hf_repo
                ));
            }
        }

        assert!(
            failures.is_empty(),
            "{} promotable catalog entries failed HF verification:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// The GGUF verifier above covered only `get_model_catalog`, which is why
    /// three D-FINE detection entries sat pointing at `.onnx` files that never
    /// existed in `Peterande/D-FINE` (that repo publishes PyTorch `.pth`
    /// only). The ONNX catalogs need the same check or the same drift recurs.
    ///
    /// Network-gated for the same reason as its GGUF sibling.
    #[tokio::test]
    #[ignore = "network: hits huggingface.co — run with --ignored in CI"]
    async fn verify_onnx_catalog_entries_resolve_on_hf() {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("tenzro-model-catalog-verify")
            .build()
            .expect("build http client");

        // (catalog label, id, repo, filename) flattened across every ONNX
        // catalog, so adding a modality without adding it here is visible as
        // a missing label rather than as silent non-coverage.
        let mut entries: Vec<(&str, String, String, String)> = Vec::new();
        for e in get_detection_catalog() {
            entries.push(("detection", e.id, e.hf_repo, e.hf_filename));
        }
        for e in get_segmentation_catalog() {
            // Both halves: a missing decoder breaks segmentation exactly as
            // thoroughly as a missing encoder.
            entries.push((
                "segmentation-encoder",
                e.id.clone(),
                e.hf_repo.clone(),
                e.encoder_filename,
            ));
            entries.push(("segmentation-decoder", e.id, e.hf_repo, e.decoder_filename));
        }
        for e in get_vision_catalog() {
            entries.push(("vision", e.id, e.hf_repo, e.hf_filename));
        }
        for e in get_text_embedding_catalog() {
            entries.push(("text-embedding", e.id, e.hf_repo, e.hf_filename));
        }
        for e in get_forecast_catalog() {
            entries.push(("forecast", e.id, e.hf_repo, e.hf_filename));
        }

        let mut repo_files: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        let mut failures: Vec<String> = Vec::new();

        for (kind, id, repo, filename) in entries {
            if filename.is_empty() {
                continue;
            }
            let files = if let Some(f) = repo_files.get(&repo) {
                f.clone()
            } else {
                let url = format!("https://huggingface.co/api/models/{repo}");
                let files = match client.get(&url).send().await {
                    Ok(r) if r.status().is_success() => {
                        let v: serde_json::Value =
                            r.json().await.unwrap_or(serde_json::Value::Null);
                        v.get("siblings")
                            .and_then(|s| s.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|s| {
                                        s.get("rfilename")
                                            .and_then(|n| n.as_str())
                                            .map(String::from)
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default()
                    }
                    Ok(r) => {
                        failures.push(format!(
                            "{kind}/{id}: repo `{repo}` returned HTTP {}",
                            r.status()
                        ));
                        Vec::new()
                    }
                    Err(e) => {
                        failures.push(format!("{kind}/{id}: repo `{repo}` request error: {e}"));
                        Vec::new()
                    }
                };
                repo_files.insert(repo.clone(), files.clone());
                files
            };

            if !files.is_empty() && !files.iter().any(|f| f == &filename) {
                failures.push(format!(
                    "{kind}/{id}: file `{filename}` not found in repo `{repo}`"
                ));
            }
        }

        assert!(
            failures.is_empty(),
            "ONNX catalog entries that do not resolve on HuggingFace:\n  {}",
            failures.join("\n  ")
        );
    }
}
