//! The Tenzro model catalog.
//!
//! See the crate README for why this is not inside `tenzro-model`. In short:
//! naming a model and running one are different jobs, and only the second
//! needs llama.cpp.
//!
//! The catalog is data, not code. Each model is a [`CatalogEntry`] that a
//! publisher signs and publishes on the network; a node serves the entries
//! its operator's trusted publishers have published and installs them in the
//! process-wide [`store`]. The accessors below read that store, so a newly
//! published model is served without a rebuild or a restart. Every file an
//! entry downloads carries the SHA-256 its bytes must have.

use serde::{Deserialize, Serialize};

pub mod entry;
pub mod store;

pub use entry::{
    CatalogEntry, Component, ComponentLicence, EntryDependency, EntryError, Licence, LicencePart,
    Loader, ModelSpec, Source, SourceCheckpoint, ViewFile,
};
pub use store::Catalog;

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
    /// `false` keeps the entry OUT of the user-facing catalog
    /// (`tenzro_listModels` / `GET /v1/models`) while it stays published, so
    /// it can be re-enabled the moment the upstream GGUF is released.
    #[serde(default = "default_true")]
    pub promotable: bool,
    /// Per-model serving configuration (sampler defaults, `--jinja`,
    /// reasoning default), as the model's author recommends it. Required:
    /// the catalog is the single source of truth for serving behaviour
    /// across all clients.
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
    /// How the checkpoint's own pipeline sizes pictures and video frames
    /// before its projector, for models whose input preprocessing the
    /// serving runtime reproduces (vision-language rerankers). `None`
    /// where the projector sizes its input itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision_input: Option<VisionPreprocess>,
    /// Reasoning / thinking-mode policy. Universal policy the serving
    /// runtime resolves per-request, carried on every entry so no client
    /// needs per-id code.
    #[serde(default)]
    pub reasoning: ReasoningPolicy,
    /// Chat-template fix policy. `TemplateFix::None` for entries whose
    /// embedded GGUF jinja is correct as-is; `TemplateFix::Vendored {
    /// filename }` when the inference client should load a vendored
    /// fix from its bundled templates dir.
    #[serde(default)]
    pub template_fix: TemplateFix,
    /// Placement tiers the weights fit on: one node with this much memory,
    /// or a cluster of this many nodes of this size. Metadata for operators
    /// and the cluster planner's first guess only; it never gates an entry,
    /// because a model larger than any one machine loads across nodes by
    /// layer range and expert shard. Empty when the entry carries none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hardware_tiers: Vec<HardwareTier>,
    /// Flat filename the network's HF downloader writes to
    /// `~/.tenzro/models/`. Always `<id>.gguf` for unshared models.
    /// Distinct from `hf_filename` (which is the canonical Unsloth
    /// name and may include a sharded subdir prefix). The serving
    /// runtime's filename matcher should key off THIS field — eliminating
    /// the dual-stem lookup the inference client used to do.
    #[serde(default)]
    pub download_filename: String,
}

/// One placement option for an entry's weights. Descriptive only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareTier {
    /// Short name, for example `single-node` or `cluster-2x128`.
    pub label: String,
    /// Nodes the weights are split over (1 for a single machine).
    pub nodes: u32,
    /// Memory each node offers the model, in GB (unified or VRAM plus RAM).
    pub memory_gb_per_node: u32,
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
    /// Block-diffusion DFlash drafter (`--spec-type draft-dflash`), e.g.
    /// Muse-Glimmer's companion `dflash-*.gguf`. Self-speculative ~2x decode.
    DraftDflash,
}

/// Per-model serving configuration — the sampler defaults, chat-template
/// handling, and reasoning behaviour a runtime should apply when it loads
/// this model. This is an **intrinsic property of the model** (sourced from
/// the model author's recommendations, primarily Unsloth's per-family
/// guidance), not of any one client. The catalog is the single source of
/// truth: every consumer (an edge
/// runtime, any other client) reads the same profile so serving behaviour never drifts between
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
    /// jinja on), for a model whose author recommends nothing specific.
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
    /// Safe non-thinking default, for a model without a published policy.
    fn default() -> Self {
        Self {
            supports_thinking: false,
            default_mode: ReasoningMode::Auto,
            thinking_safe_min_b: 0.0,
            thinking_min_budget_tokens: 0,
        }
    }
}

/// Per-entry chat-template fix policy. Replaces the inference-client's
/// hand-maintained `TEMPLATE_OVERRIDES` map. The catalog publishes
/// which fix (if any) each family needs; the client maps logical
/// filenames to its bundled `templates/` directory.
///
/// A newly known-broken family: publish its entries with the fix and drop
/// the vendored jinja in the inference client's `templates/` dir.
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
    /// Render the embedded jinja directly and take everything after the
    /// generation prompt as plain content — no tool-call/reasoning parsing,
    /// no grammar, no format auto-detection. For a family whose template
    /// `common_chat`'s auto-detector misidentifies as a *different* known
    /// format (observed: gemma4-12b-qat detected as gpt-oss/Harmony-shaped,
    /// which corrupted both the render and the reply parsing — see
    /// `llama_rs_chat_template_oaicompat_params::force_pure_content` in the
    /// vendored `llama-cpp-sys-2` wrapper). The template itself is fine;
    /// only the auto-detection is wrong, so this asks llama.cpp to skip
    /// detection rather than trying to out-guess it. Trade: no native
    /// tool-calling for this family — falls back to the preamble/XML path,
    /// same as any template without a tool branch. Remove for a family once
    /// `common_chat`'s detector is confirmed fixed for it upstream.
    ForcePureContent,
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

/// Total (not active) parameter count in billions, parsed from the catalog
/// `parameters` display string. The reasoning size-gate keys on TOTAL params:
/// an MoE such as `qwen3.6-35b-a3b` is a capable reasoner at 35B total even
/// though only 3B are active per token, so gating on the active width (3B <
/// the 4B safe-min) would wrongly disable its thinking. Reuses
/// [`parse_parameter_count`], which reads the leading magnitude
/// ("35B (MoE, 3B active)" -> 35e9, "0.8B" -> 8e8).
pub fn parse_params_total_b(parameters: &str) -> f32 {
    parse_parameter_count(parameters).map_or(0.0, |c| c as f32 / 1e9)
}

/// Resolve whether the served chat template for `model_id` should render with
/// thinking enabled, from the entry's [`ReasoningPolicy`].
///
/// * A family without the hybrid toggle (instruct-only, and channel-format
///   reasoners like muse-glimmer whose thinking is intrinsic to the output
///   format rather than a template variable) -> `true`, preserving the
///   pre-policy default; `enable_thinking` is a no-op for those templates.
/// * `Never` -> `false`; `Always` -> `true`.
/// * `Auto` -> thinking-ON iff TOTAL params >= `thinking_safe_min_b` AND the
///   caller's `budget_tokens` (when supplied) >= `thinking_min_budget_tokens`.
///   This is the Qwen 3.5/3.6 Small-series carve-out: `qwen3.5-0.8b` (0.8B <
///   4B) renders thinking-OFF and answers directly, while `qwen3.6-35b-a3b`
///   (35B >= 4B) keeps thinking. The budget half of the gate guards a capable
///   reasoner given too small a `max_tokens` to both think and answer (the
///   documented failure mode: the whole budget is spent inside `<think>` and
///   the model emits empty content).
///
/// `budget_tokens` is the caller's max output-token budget. `None` means
/// "unbounded / unknown" and passes the budget half of the gate, so an
/// engine-level resolve with no per-request budget behaves exactly as before.
///
/// Operators can force a served model onto the non-thinking path without a
/// rebuild via the `TENZRO_NOTHINK_MODELS` env var (comma-separated model ids):
/// a match returns `false` before any policy lookup.
///
/// An unknown `model_id` returns `true` (the unchanged default).
/// How a family's chat template exposes a reasoning-budget control.
///
/// This is per-family configuration rather than a constant because the two
/// families served today disagree on every axis. Qwen 3.8 reads a
/// `reasoning_effort` kwarg accepting `xhigh | medium | low`, aliases `high`
/// onto `xhigh`, and **raises** on anything else. Muse-Glimmer reads
/// `reasoning_strength`, accepts `low | medium | high | xhigh`, defaults to
/// `high`, and performs **no validation at all** — it interpolates whatever
/// string it is handed straight into its system prompt. A single hardcoded
/// kwarg name would simply be ignored by one of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EffortPolicy {
    /// Chat-template variable to set. Empty means the family exposes no
    /// reasoning-budget control, and any caller-supplied value is dropped.
    pub kwarg: String,
    /// Levels the template accepts, lowercase.
    pub levels: Vec<String>,
    /// Accepted spellings that are not themselves levels, mapped onto one that
    /// is (e.g. Qwen 3.8's `high` -> `xhigh`). Resolving aliases here keeps the
    /// rendered prompt identical however the caller spelled it.
    pub aliases: Vec<(String, String)>,
}

impl EffortPolicy {
    fn of(kwarg: &str, levels: &[&str], aliases: &[(&str, &str)]) -> Self {
        Self {
            kwarg: kwarg.to_string(),
            levels: levels.iter().map(|s| s.to_string()).collect(),
            aliases: aliases
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
        }
    }

    /// Per-family reasoning-budget control.
    ///
    /// A family absent from this table returns the empty policy, which drops
    /// any caller-supplied value rather than guessing — the safe direction,
    /// since a template that validates will raise mid-request on a wrong one.
    pub fn for_family(family: &str) -> Self {
        match family {
            // Qwen 3.8 / Flash-Next: `xhigh` (the template's own default),
            // `medium` and `low`, plus a `high` alias the template folds into
            // `xhigh`. `medium` is the *neutral* setting rather than a midpoint
            // — an instruction is injected only for `xhigh` and `low`.
            "qwen3.8" | "qwen3.8-flash-next" => Self::of(
                "reasoning_effort",
                &["xhigh", "medium", "low"],
                &[("high", "xhigh")],
            ),
            // Muse-Glimmer: a differently-named variable over the full
            // four-level ladder, per its model card. Its template does no
            // validation — it interpolates whatever string it is handed
            // straight into the system prompt — so screening here is what keeps
            // a typo out of the model's context. No aliases: the card defines
            // exactly these four spellings.
            "muse-glimmer" => Self::of(
                "reasoning_strength",
                &["low", "medium", "high", "xhigh"],
                &[],
            ),
            // Mistral Large 4: `reasoning_effort` low / medium / high, high by
            // default, per the model card.
            "mistral-large" => Self::of("reasoning_effort", &["low", "medium", "high"], &[]),
            // Nemotron 3 Ultra and 3.5 Bolt: the template has a boolean
            // `medium_effort` switch beside `enable_thinking`. The engine
            // hands the variable over as the text of the level, which the
            // template's truthiness test accepts; `high` is the template's
            // own default and so is left unset.
            "nemotron" | "nemotron-bolt" => Self::of("medium_effort", &["medium"], &[]),
            _ => Self::default(),
        }
    }

    /// Normalise one caller-supplied value against this policy.
    fn normalize(&self, raw: &str) -> Option<String> {
        let raw = raw.trim().to_ascii_lowercase();
        if raw.is_empty() {
            return None;
        }
        if self.levels.contains(&raw) {
            return Some(raw);
        }
        self.aliases
            .iter()
            .find(|(from, _)| *from == raw)
            .map(|(_, to)| to.clone())
    }
}

/// Resolve a caller-supplied reasoning budget for `model_id` into the
/// template variable and value to render with, or `None` to leave the
/// template's own default in place.
///
/// Validation happens here because a template that checks its input *raises*
/// on an unrecognised value, which would turn a bad client string into a hard
/// generation failure; and a template that does not check will happily
/// interpolate a typo into the model's system prompt. Either way the caller's
/// value must be screened before it reaches the prompt. Anything unrecognised
/// falls back to the template default rather than failing the request.
///
/// Operators can pin a default without a rebuild via `TENZRO_REASONING_EFFORT`,
/// validated against the same policy — an unsupported pin is ignored rather
/// than breaking every request.
pub fn resolve_reasoning_effort(model_id: &str, effort: Option<&str>) -> Option<(String, String)> {
    let family = get_model_by_id(model_id).map(|e| e.family.clone())?;
    let policy = EffortPolicy::for_family(&family);
    if policy.kwarg.is_empty() {
        return None;
    }
    let requested = match effort {
        Some(e) => e.to_string(),
        None => std::env::var("TENZRO_REASONING_EFFORT").ok()?,
    };
    policy
        .normalize(&requested)
        .map(|v| (policy.kwarg.clone(), v))
}

pub fn resolve_enable_thinking(model_id: &str, budget_tokens: Option<u32>) -> bool {
    // Operator escape hatch first: a comma-separated id list forces those
    // models onto the non-thinking path with no rebuild. Empty/whitespace
    // entries are ignored so a trailing comma is harmless.
    if let Ok(list) = std::env::var("TENZRO_NOTHINK_MODELS")
        && list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .any(|id| id == model_id)
    {
        return false;
    }
    let Some(entry) = get_model_by_id(model_id) else {
        return true;
    };
    let p = entry.reasoning;
    if !p.supports_thinking {
        return true;
    }
    match p.default_mode {
        ReasoningMode::Never => false,
        ReasoningMode::Always => true,
        ReasoningMode::Auto => {
            let big_enough = parse_params_total_b(&entry.parameters) >= p.thinking_safe_min_b;
            let budget_ok = budget_tokens.is_none_or(|b| b >= p.thinking_min_budget_tokens);
            big_enough && budget_ok
        }
    }
}

/// Model architecture, as the catalog labels it.
///
/// The engine reads the architecture from the GGUF's own metadata; this label
/// groups entries for display and filtering, and
/// [`ModelArchitecture::engine_architectures`] names the GGUF architectures
/// an entry with the label may carry, or why the engine cannot load it.
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
    /// Qwen4-Exp (`qwen4_exp`): the experimental architecture behind
    /// Qwen3.8-Flash-Next and, per Qwen, the basis of Qwen4. Gated delta net
    /// on 3 of every 4 layers, Qwen Sparse Attention (QSA) on the rest,
    /// hyper-connections, and a per-layer-embedding n-gram table. Support is
    /// vendored into our llama.cpp — no released build can load it.
    Qwen4Exp,
    Gemma3,
    Gemma4,
    Gemma4Moe,
    /// Gemma 4-family diffusion variant (DiffusionGemma) — generates
    /// fixed-length canvases by parallel denoising rather than
    /// autoregressive next-token sampling (GGUF architecture
    /// `diffusion-gemma`). Speculative decoding / MTP do not apply; the
    /// batch engine serves it through its denoising scheduler.
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
    /// Mamba: a selective state-space model with no attention and no KV
    /// cache; its per-sequence state is a fixed-size recurrence.
    Mamba,
    /// NVIDIA Nemotron-H (`nemotron_h`, `nemotron_h_moe`): the hybrid line.
    /// Each layer is one of Mamba-2 (a fixed-size recurrent state), a
    /// feed-forward or Mixture-of-Experts block, or attention, in a
    /// per-layer pattern; only the attention layers hold a KV cache. The
    /// MoE form (Nano, Super, Ultra, Bolt) routes in a latent space smaller
    /// than the hidden size (Latent MoE) with a shared expert.
    NemotronH,
    /// Mistral Large 4 (`mistral-large4`): multi-head latent attention with a
    /// sparse-attention indexer and key/value sharing across layers, 128
    /// routed experts with 4 active, final-logit soft-capping. Distinct from
    /// `mistral4`, which has neither the indexer nor the sharing.
    MistralLarge4,
    Beam,
    Hy4,
    Flint,
    Spark25,
    /// ModernBERT (`modern-bert`): the bidirectional encoder with alternating
    /// local and global attention, here with a decision head (Laya).
    ModernBert,
    /// EmbeddingGemma 2: the second-generation bidirectional Gemma encoder
    /// (`gemma-embedding2`), with audio and vision encoders beside the text
    /// encoder. The text encoder alone serves text embeddings.
    GemmaEmbedding2,
    /// RWKV-7: a linear-attention recurrent model with fixed-size state.
    Rwkv7,
    /// T5: an encoder-decoder transformer. The encoder runs once per
    /// prompt and the decoder attends to its output.
    T5,
    /// Idefics3 (SmolVLM): a Llama-family decoder with a SigLIP vision
    /// tower, served through the mmproj path.
    Idefics3,
    /// EmbeddingGemma: a bidirectional Gemma 3 encoder with mean pooling.
    /// It produces embeddings, not text, so the chat engine refuses it.
    GemmaEmbedding,
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
            Self::Qwen4Exp => write!(f, "qwen4exp"),
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
            Self::Mamba => write!(f, "mamba"),
            Self::NemotronH => write!(f, "nemotron-h"),
            Self::MistralLarge4 => write!(f, "mistral-large4"),
            Self::Beam => write!(f, "beam"),
            Self::Hy4 => write!(f, "hy4"),
            Self::Flint => write!(f, "flint"),
            Self::Spark25 => write!(f, "spark25"),
            Self::GemmaEmbedding2 => write!(f, "gemma-embedding2"),
            Self::ModernBert => write!(f, "modern-bert"),
            Self::Rwkv7 => write!(f, "rwkv7"),
            Self::T5 => write!(f, "t5"),
            Self::Idefics3 => write!(f, "idefics3"),
            Self::GemmaEmbedding => write!(f, "gemma-embedding"),
        }
    }
}

impl ModelArchitecture {
    /// The GGUF `general.architecture` values an entry with this label may
    /// carry, each one the Praecise engine has a loader for; `Err` says why
    /// the engine has no loader for the label. The scheduled loader stage
    /// checks every entry's file header against this list, the list against
    /// the pinned engine, and loads a small model of each architecture.
    pub fn engine_architectures(&self) -> Result<&'static [&'static str], &'static str> {
        Ok(match self {
            Self::Llama => &["llama", "dflash", "muse-glimmer", "smollm3"],
            Self::Qwen2 => &["qwen2"],
            Self::Qwen3 => &["qwen3"],
            Self::Qwen3Moe => &["qwen3moe"],
            Self::Qwen35 | Self::Qwen36 => &["qwen35"],
            Self::Qwen35Moe | Self::Qwen36Moe => &["qwen35moe"],
            Self::Qwen3Vl => &["qwen3vl", "qwen3vlmoe"],
            Self::Qwen3Next => &["qwen3next"],
            Self::Qwen4Exp => &["qwen4exp"],
            Self::Gemma3 => &["gemma3"],
            Self::Gemma4 | Self::Gemma4Moe => &["gemma4", "gemma4-assistant"],
            Self::Gemma4Diffusion => &["diffusion-gemma"],
            Self::Mistral => &["llama", "mistral3", "mistral4"],
            Self::MistralMoe => &["mistral4"],
            Self::Phi3 => &["phi3", "llama"],
            Self::Glm => &["chatglm", "glm4", "glm4moe", "glm-dsa", "glm5-next"],
            Self::Kimi => &["deepseek2", "kimi-k3", "kimi-linear"],
            Self::MiniMax => &["minimax-m2", "minimax-m3"],
            Self::DeepSeekV3 => &["deepseek2", "deepseek32", "deepseek4", "deepseek41"],
            Self::GptOss => &["gpt-oss"],
            Self::Granite => &["granite", "granitemoe"],
            Self::GraniteH => &["granite", "granitehybrid"],
            Self::Laguna => &["laguna"],
            Self::Inkling => &["inkling"],
            Self::Mamba => &["mamba", "mamba2"],
            Self::NemotronH => &["nemotron_h", "nemotron_h_moe"],
            Self::MistralLarge4 => &["mistral-large4"],
            Self::Beam => &["beam"],
            Self::Hy4 => &["hy_v4"],
            Self::Flint => &["flint"],
            Self::Spark25 => &["spark2_5"],
            Self::GemmaEmbedding2 => &["gemma-embedding2"],
            Self::ModernBert => &["modern-bert"],
            Self::Rwkv7 => &["rwkv7"],
            Self::T5 => &["t5"],
            Self::Idefics3 => &["llama"],
            Self::GemmaEmbedding => &["gemma-embedding"],
        })
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
    /// Short description.
    pub description: String,
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
    /// Short description.
    pub description: String,
}

// ─────────────────────────────────────────────────────────────────────
// Text embedding catalog.
// ─────────────────────────────────────────────────────────────────────

/// How a text-embedding family expects queries and documents to be
/// prefixed before tokenization.
///
/// This is the embedding-side counterpart to [`TemplateFix`]: embedding
/// families disagree on instruction formatting exactly the way chat
/// families disagree on chat templates, and the fix is the same — data on
/// the catalog entry, read generically by the runtime, never a per-model
/// branch in the encoder itself. Every variant below is verified against
/// the family's own HF model card / README (2026-08-27), not guessed:
///
/// - Qwen3-Embedding: an unprefixed query embeds noticeably worse on
///   retrieval (its own docs give the `Instruct: …\nQuery:…` template as
///   required for queries; documents take no prefix at all).
/// - EmbeddingGemma: queries AND documents both take a prefix, but two
///   different ones — mixing them up silently degrades retrieval rather
///   than erroring.
/// - BGE-M3: explicitly dropped the instruction requirement earlier BGE
///   versions had ("no longer requires adding instruction to the
///   queries") — `None` is the correct, verified answer here, not an
///   oversight.
/// - ModernBERT-embed / other Nomic-lineage encoders: the `search_query:`
///   / `search_document:` prefix pair from Nomic's own convention.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EmbeddingTemplate {
    /// No prefix for either role. BGE-M3.
    None,
    /// Qwen3-Embedding: query → `"Instruct: {task}\nQuery:{text}"` (no
    /// space after the colon — verified byte-for-byte against the model's
    /// own `get_detailed_instruct` example); document → no prefix.
    /// `default_task` is used when a caller's request doesn't supply one.
    InstructQuery { default_task: String },
    /// EmbeddingGemma: query → `"task: {task} | query: {text}"`;
    /// document → `"title: {title|none} | text: {text}"`. `default_task`
    /// is used when a caller's request doesn't supply one.
    GemmaTask { default_task: String },
    /// Nomic-lineage (ModernBERT-embed, nomic-embed-*): query →
    /// `"search_query: {text}"`; document → `"search_document: {text}"`.
    NomicPrefix,
    /// Query/passage prefixes (Nemotron embed): query → `"query: {text}"`;
    /// document → `"passage: {text}"`.
    QueryPassagePrefix,
    /// Chat-formatted instruction (decoder embedders on the Praecise
    /// engine): the instruction is the system turn and the input the user
    /// turn of the checkpoint's own chat template, which the engine applies.
    /// Query → the caller's task or `default_task`; document →
    /// `document_task`. An instruction that does not end in punctuation
    /// gets a full stop, as the checkpoint's own pipeline does.
    ChatInstruct {
        default_task: String,
        document_task: String,
    },
}

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
    /// field. Large exports split the weights over several sidecars
    /// (`model.onnx_data`, `model.onnx_data_1`, ...); every one is listed.
    /// Empty when the export is self-contained (single-file).
    #[serde(default)]
    pub external_data_filenames: Vec<String>,
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
    /// Short description.
    pub description: String,
    /// Per-family query/document instruction template — see
    /// [`EmbeddingTemplate`]. `#[serde(default)]` so an older recorded
    /// catalog snapshot (attestation, cached listing) without this field
    /// deserializes as `None` rather than failing to load.
    #[serde(default = "EmbeddingTemplate::default_none")]
    pub embedding_template: EmbeddingTemplate,
}

/// How a vision-language model's own pipeline sizes pictures and video
/// frames, read from the checkpoint.
///
/// Images are resized (bicubic) so each side is a multiple of
/// `patch_size * merge_size` and the area lies within
/// `[image_min_pixels, image_max_pixels]`, rescaled to `[0, 1]`, normalised
/// with `image_mean`/`image_std`, and cut into
/// `temporal_patch_size x patch_size x patch_size` patches (a picture is
/// repeated over the temporal patch). A video is a list of frames sampled
/// to exactly `video_frames` evenly spaced frames, at `video_sample_fps`
/// for the timestamps; each frame is first rounded to a multiple of
/// `video_frame_round_factor` (area at least
/// `video_frame_round_min_pixels`), then all frames are resized together
/// to a multiple of `patch_size * merge_size` with an area within
/// `[video_frame_min_pixels, min(video_frame_max_pixels,
/// video_total_pixels / frames * temporal_patch_size)]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VisionPreprocess {
    pub patch_size: u32,
    pub merge_size: u32,
    pub temporal_patch_size: u32,
    pub image_mean: [f32; 3],
    pub image_std: [f32; 3],
    pub image_min_pixels: u64,
    pub image_max_pixels: u64,
    pub video_frames: u32,
    pub video_sample_fps: f64,
    pub video_frame_round_factor: u32,
    pub video_frame_round_min_pixels: u64,
    pub video_frame_min_pixels: u64,
    pub video_frame_max_pixels: u64,
    pub video_total_pixels: u64,
}

impl EmbeddingTemplate {
    fn default_none() -> Self {
        Self::None
    }
}

/// A pooled embedder in GGUF form, served by the Praecise engine in the node
/// process: each input (text, and with a projector pictures and video
/// frames) becomes one vector, the hidden state of the last position,
/// L2-normalised.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedModelEntry {
    /// Internal model ID (e.g. "qwen3-vl-embedding-2b").
    pub id: String,
    /// Display name.
    pub name: String,
    /// Model family.
    pub family: String,
    /// Short description.
    pub description: String,
    /// Repository the files are published in.
    pub hf_repo: String,
    /// The GGUF model file within the repo.
    pub hf_filename: String,
    /// The vision projector of a vision-language embedder; `None` for one
    /// that reads text only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmproj: Option<MmprojSpec>,
    /// How the checkpoint's own pipeline sizes pictures and video frames;
    /// present exactly when `mmproj` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision_input: Option<VisionPreprocess>,
    /// Weight format of the GGUF file (e.g. "F16").
    pub quantization: String,
    /// Longest input in tokens, template and pictures included.
    pub max_sequence_length: u32,
    /// Native output embedding dimension.
    pub embedding_dim: u32,
    /// Nested dimensions the checkpoint was trained with; empty when only
    /// `embedding_dim` is served.
    #[serde(default)]
    pub matryoshka_dims: Vec<u32>,
    /// Instruction for queries and documents.
    pub embedding_template: EmbeddingTemplate,
    /// Size of the files in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB to load.
    pub min_ram_gb: u32,
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
    /// Short description.
    pub description: String,
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
    /// Short description.
    pub description: String,
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
    /// Short description.
    pub description: String,
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
    /// Optional feature-extractor graph (NeMo models like Parakeet and Canary,
    /// which take mel features rather than raw audio).
    pub preprocessor_filename: Option<String>,
    /// The tokenizer: `tokenizer.json` for Moonshine and Whisper, the
    /// `vocab.txt` token table for Parakeet and Canary.
    pub tokenizer_filename: String,
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
    /// Short description.
    pub description: String,
}

/// A speech-synthesis model this node can serve.
///
/// Named for what it is rather than mirroring the ONNX entry types: the
/// Qwen3-TTS family ships `safetensors` with a `config.json` and loads
/// through `transformers`, not ORT. A field called `onnx_filename` holding
/// something that is not ONNX is exactly the drift this avoids.
///
/// Synthesis runs on the Praecise speech engine in the node process, over the
/// entry's components for `hf_repo`. The node owns admission,
/// billing and the API surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtsModelEntry {
    /// Internal model ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family.
    pub family: String,
    /// Origin repository of the GGUF files.
    pub hf_repo: String,
    /// The backbone GGUF: reads the text and drives each audio frame.
    pub hf_filename: String,
    /// The audio projector GGUF: turns the backbone's states into a
    /// waveform.
    pub mmproj_filename: String,
    /// On-disk size of both files in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB to load.
    pub min_ram_gb: u32,
    /// Output sample rate in Hz.
    pub sample_rate: u32,
    /// Language codes the model takes (`en`, `zh`, ...).
    pub languages: Vec<String>,
    /// Whether this checkpoint speaks in a voice taken from reference audio.
    ///
    /// Recorded per checkpoint so an operator can see which models carry the
    /// capability before enabling it, rather than discovering it from a
    /// request. Cloning stays behind a separate operator opt-in regardless —
    /// choosing a model family that supports it is not the same act as
    /// offering it to callers.
    pub supports_voice_cloning: bool,
    /// Short description.
    pub description: String,
}

/// A catalog omni model: a reading model (thinker) that takes text and audio
/// and writes the reply, and a talker that speaks the reply while it is
/// written, both GGUF pairs, served in the node process by an inference
/// engine that loads them. A turn is billed on prompt and reply tokens,
/// audio heard and audio spoken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmniModelEntry {
    /// Internal model ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family.
    pub family: String,
    /// Origin repository of the four GGUF files, converted together from one
    /// checkpoint revision so the talker matches the thinker it reads.
    pub hf_repo: String,
    /// The thinker GGUF.
    pub hf_filename: String,
    /// The thinker's input projector (audio and pictures).
    pub mmproj_filename: String,
    /// The talker backbone GGUF.
    pub talker_filename: String,
    /// The talker's speech projector GGUF.
    pub talker_mmproj_filename: String,
    /// On-disk size of all four files in bytes.
    pub size_bytes: u64,
    /// Minimum RAM in GB to load.
    pub min_ram_gb: u32,
    /// Output sample rate in Hz.
    pub sample_rate: u32,
    /// Voices the talker speaks in.
    pub voices: Vec<String>,
    /// Language codes the model speaks.
    pub languages: Vec<String>,
    /// Short description.
    pub description: String,
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
    /// Short description.
    pub description: String,
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

/// Whether a media-gen entry runs on this release.
///
/// Media models run in process on the node's native engine, one dispatch slot
/// every ported pipeline plugs into. An entry whose port has not shipped stays
/// listed so clients can see it is coming, and every use of it is refused with
/// [`MEDIA_PLANNED_REFUSAL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaGenStatus {
    /// Runs on the node's native engine.
    Native,
    /// Listed; its native port is planned and it cannot be used yet.
    Planned,
}

impl MediaGenStatus {
    /// Stable wire/label form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Planned => "planned",
        }
    }
}

/// The refusal for any use of a planned media model.
pub const MEDIA_PLANNED_REFUSAL: &str =
    "this media model is planned: its native engine port has not shipped, so it cannot be used yet";

/// The embodiment an action-policy entry is trained for: what one
/// observation holds and what one action chunk contains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionPolicySpec {
    /// Embodiment label, e.g. `droid` or `so101`; `generic` for a base model
    /// that needs a per-embodiment head before it acts.
    pub embodiment: String,
    /// Camera views per observation.
    pub cameras: u32,
    /// Proprioceptive state dimension.
    pub state_dim: u32,
    /// Action dimension per control step.
    pub action_dim: u32,
    /// Control steps per action chunk.
    pub chunk_len: u32,
    /// Control rate the chunk is executed at.
    pub control_hz: u32,
}

/// A generative-media pipeline in the curated media-gen catalog.
///
/// Unlike the ONNX entries above, a media-gen pipeline is a multi-folder
/// HuggingFace repository (transformer + text encoder + VAE + scheduler)
/// loaded whole, so there is no single `hf_filename`: a node fetches the
/// entry's components for `hf_repo` as one directory. A runtime host resolves
/// it through the [`pipeline_class`](MediaGenModelEntry::pipeline_class)
/// declared in its `model_index.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct MediaGenModelEntry {
    /// Internal model ID, the `model_id` a render names.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Model family.
    pub family: String,
    /// HuggingFace repository ID. Loaded as a whole pipeline directory.
    pub hf_repo: String,
    /// Whether the entry runs on this release or is planned.
    pub status: MediaGenStatus,
    /// The native engine revision a `native` entry's port is pinned at, so a
    /// catalog row names the exact engine build that runs it. `None` while
    /// planned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_rev: Option<String>,
    /// Voxel grid resolution the vendor's reference invocation uses, for 3D
    /// entries. `None` for pixel pipelines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_voxel_resolution: Option<u32>,
    /// The embodiment an action-policy entry drives. `None` for every
    /// pixel, audio and 3D pipeline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionPolicySpec>,
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
    /// Load the transformer and prompt encoder as 8-bit blocks quantised
    /// from the bfloat16 weights at load time. Such an entry ships no
    /// weights of its own and requires the bfloat16 entry's.
    #[serde(default)]
    pub load_int8: bool,
    /// Short description.
    pub description: String,
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
            // Wan 2.1 and 2.2 share a 4× temporal VAE, and Matrix-Game
            // decodes through the Wan 2.2 one.
            "wan2.1" | "wan2.2" | "matrix-game" => 4,
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

impl MoeShape {
    /// Expand the catalog-side shape into the full
    /// [`tenzro_types::model::MoeMetadata`] block used by `ModelInfo`,
    /// the inference router, and `tenzro_model::moe_shard::MoeShardView`.
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

/// Reads a parameter count out of a catalog entry's display string.
///
/// The catalog writes these for humans — `"0.8B"`, `"35B (MoE, 3B active)"`,
/// `"270M"` — so only the leading magnitude is authoritative and the rest is
/// prose. For a MoE entry that leading figure is the **total**, not the active,
/// count, which is the one worth tiering on: a 35B-A3B reasons like a large
/// model even though it runs at the cost of a small one, and reading `3B active`
/// here would file it next to a 3B dense model.
///
/// Returns `None` when there is no leading number, which keeps an
/// undeclared-size entry out of the strong tier rather than guessing it in.
pub(crate) fn parse_parameter_count(declared: &str) -> Option<u64> {
    // Gemma 4 states an *effective* count as `E2B` / `E4B` — the size the
    // model behaves as, which is the figure to tier on, with more raw weights
    // behind it. Drop the marker and read the magnitude that follows.
    let s = declared.trim();
    let s = s.strip_prefix(['E', 'e']).unwrap_or(s);
    let digits: String = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if digits.is_empty() {
        return None;
    }
    let magnitude: f64 = digits.parse().ok()?;
    let unit = s[digits.len()..].trim_start().chars().next()?;
    let scale = match unit.to_ascii_uppercase() {
        'T' => 1e12,
        'B' => 1e9,
        'M' => 1e6,
        'K' => 1e3,
        _ => return None,
    };
    Some((magnitude * scale) as u64)
}

/// The territorial grant attached to a custom licence id, if it has one.
///
/// Keyed on the **licence**, not the model: every model under a licence
/// inherits the same territory, and a newly-restricted licence is a row here
/// rather than a code change. A licence absent from this table is unrestricted,
/// which is the correct default — most are.
///
/// Adding a row is a compliance decision. Two questions decide it, and both
/// are answered from the licence text rather than inferred:
///
/// 1. **Does the restriction reach outputs?** If it covers only the weights, a
///    registration-time refusal discharges it and
///    [`TerritorialScope::Weights`] is right. Only a grant that also limits
///    outputs forces a per-request check.
/// 2. **Is there an end-user carve-out?** Llama's EU restriction withholds
///    rights from EU-*domiciled* companies but explicitly exempts "end users of
///    a product or service that incorporates" the model — a test on who the
///    operator is, so per-request blocking would solve a problem that does not
///    exist. MiniMax H3 has no such carve-out.
pub fn license_territory(license_id: &str) -> Option<tenzro_types::model::TerritorialGrant> {
    use tenzro_types::model::{TerritorialGrant, TerritorialScope};
    match license_id {
        // MiniMax H3 Community License, verified against the LICENSE file.
        //
        // "Applicable Territory" is "worldwide, excluding the European Union,
        // the United Kingdom, the Republic of Korea and the United States of
        // America", and **§V.4** reads: "You may not use, reproduce, modify,
        // distribute, or display the MiniMax H3 Works **or any of their Outputs
        // or results** outside the Applicable Territory."
        //
        // Outputs are in scope and there is **no end-user carve-out**, so this
        // is `WeightsAndOutputs` and every request has to be checked.
        //
        // The UK is listed separately from the EU in the licence itself — the
        // drafters were alive to Brexit — so it is listed separately here
        // rather than folded into the `EU` token.
        "minimax-h3-community" => Some(TerritorialGrant {
            excluded: vec!["EU".into(), "GB".into(), "KR".into(), "US".into()],
            scope: TerritorialScope::WeightsAndOutputs,
        }),
        // Tencent Hunyuan 3D 2.1 Community License, verified against the
        // LICENSE file in `tencent/Hunyuan3D-2.1`.
        //
        // **§1.l** defines "Territory" as "the worldwide territory, excluding
        // the territory of the European Union, United Kingdom and South Korea",
        // **§2** grants rights "for the Territory only", and **§5.c** reads:
        // "You must not use, reproduce, modify, distribute, or display the
        // Tencent Hunyuan 3D 2.1 Works, **Output or results** of the Tencent
        // Hunyuan 3D 2.1 Works outside the Territory."
        //
        // Outputs are in scope, so this is `WeightsAndOutputs`. There is **no
        // end-user carve-out**: the end of §3 releases a recipient of an
        // integrated end-user product from §3's distribution conditions only,
        // not from §5.c. The United States is not excluded, unlike MiniMax H3.
        "tencent-hunyuan3d-2.1-community" => Some(TerritorialGrant {
            excluded: vec!["EU".into(), "GB".into(), "KR".into()],
            scope: TerritorialScope::WeightsAndOutputs,
        }),
        // Tencent Hunyuan Community License, verified against the LICENSE
        // file of HunyuanImage 3.0. "Territory" is "the worldwide territory,
        // excluding the territory of the European Union, United Kingdom and
        // South Korea", and §5(c) reads: "You must not use, reproduce, modify,
        // distribute, or display the Tencent Hunyuan Works, **Output or
        // results** of the Tencent Hunyuan Works outside the Territory."
        "tencent-hunyuan-community" => Some(TerritorialGrant {
            excluded: vec!["EU".into(), "GB".into(), "KR".into()],
            scope: TerritorialScope::WeightsAndOutputs,
        }),
        _ => None,
    }
}
/// Parse a gguf-split first-shard filename into its `(prefix, total, ext)`
/// parts. Accepts the bare name or a subdir-prefixed remote path; the
/// returned `prefix` is the model stem WITHOUT the `-00001-of-000NN`
/// segment and WITHOUT any leading directory, and `ext` is everything
/// after the shard segment (normally `.gguf`).
///
/// Returns `None` for non-sharded names or any shard other than the
/// first — only the first shard is a valid catalog entry point.
///
/// `Q4_K_M/Kimi-K2-Instruct-Q4_K_M-00001-of-00013.gguf`
///   → `("Kimi-K2-Instruct-Q4_K_M", 13, ".gguf")`
pub fn shard_spec(hf_filename: &str) -> Option<(String, u32, String)> {
    let bare = hf_filename.rsplit('/').next().unwrap_or(hf_filename);
    let marker = bare.find("-00001-of-")?;
    let prefix = bare[..marker].to_string();
    // After the marker: "-00001-of-" then NNNNN then the extension.
    let rest = &bare[marker + "-00001-of-".len()..];
    let digits_end = rest.find(|c: char| !c.is_ascii_digit())?;
    let total: u32 = rest[..digits_end].parse().ok()?;
    if total == 0 {
        return None;
    }
    let ext_suffix = rest[digits_end..].to_string();
    Some((prefix, total, ext_suffix))
}

impl HfModelEntry {
    /// Every GGUF file of the model in its repository: each shard of a split
    /// set, or the one file. Empty for an extraction-only MoE entry, which
    /// has no whole-model file.
    pub fn download_files(&self) -> Vec<String> {
        if self.hf_filename.is_empty() {
            return Vec::new();
        }
        let Some((prefix, total, ext)) = shard_spec(&self.hf_filename) else {
            return vec![self.hf_filename.clone()];
        };
        let dir = self
            .hf_filename
            .rsplit_once('/')
            .map(|(d, _)| format!("{d}/"))
            .unwrap_or_default();
        (1..=total)
            .map(|i| format!("{dir}{prefix}-{i:05}-of-{total:05}{ext}"))
            .collect()
    }
}

/// The entries of one engine family, in id order.
fn of_engine<T: Clone>(pick: impl Fn(&ModelSpec) -> Option<&T>) -> Vec<T> {
    store::current()
        .entries()
        .iter()
        .filter_map(|e| pick(&e.model).cloned())
        .collect()
}

/// One entry of one engine family, by id.
fn one_of_engine<T: Clone>(id: &str, pick: impl Fn(&ModelSpec) -> Option<&T>) -> Option<T> {
    store::current()
        .entry(id)
        .and_then(|e| pick(&e.model).cloned())
}

macro_rules! engine_accessors {
    ($variant:ident, $ty:ty, $all:ident, $by_id:ident, $what:literal) => {
        #[doc = concat!("Every ", $what, " in the catalog.")]
        pub fn $all() -> Vec<$ty> {
            of_engine(|m| match m {
                ModelSpec::$variant(e) => Some(e),
                _ => None,
            })
        }

        #[doc = concat!("A ", $what, " in the catalog, by id.")]
        pub fn $by_id(id: &str) -> Option<$ty> {
            one_of_engine(id, |m| match m {
                ModelSpec::$variant(e) => Some(e),
                _ => None,
            })
        }
    };
}

engine_accessors!(
    Gguf,
    HfModelEntry,
    get_model_catalog,
    get_model_by_id,
    "GGUF language model"
);
engine_accessors!(
    Rerank,
    HfModelEntry,
    get_rerank_catalog,
    get_rerank_model_by_id,
    "GGUF reranker"
);
engine_accessors!(
    Decision,
    HfModelEntry,
    get_decision_catalog,
    get_decision_model_by_id,
    "GGUF decision model"
);
engine_accessors!(
    OnnxVision,
    OnnxVisionEntry,
    get_vision_catalog,
    get_vision_model_by_id,
    "ONNX vision encoder"
);
engine_accessors!(
    OnnxForecast,
    OnnxForecastEntry,
    get_forecast_catalog,
    get_forecast_model_by_id,
    "ONNX timeseries forecaster"
);
engine_accessors!(
    OnnxTextEmbedding,
    OnnxTextEmbeddingEntry,
    get_text_embedding_catalog,
    get_text_embedding_model_by_id,
    "ONNX text-embedding model"
);
engine_accessors!(
    Embed,
    EmbedModelEntry,
    get_embed_catalog,
    get_embed_model_by_id,
    "GGUF pooled embedder"
);
engine_accessors!(
    OnnxSegmentation,
    OnnxSegmentationEntry,
    get_segmentation_catalog,
    get_segmentation_model_by_id,
    "ONNX segmentation model"
);
engine_accessors!(
    OnnxTextSegmentation,
    OnnxTextSegmentationEntry,
    get_text_segmentation_catalog,
    get_text_segmentation_model_by_id,
    "ONNX text-promptable segmentation model"
);
engine_accessors!(
    OnnxDetection,
    OnnxDetectionEntry,
    get_detection_catalog,
    get_detection_model_by_id,
    "ONNX object detector"
);
engine_accessors!(
    OnnxAudio,
    OnnxAudioEntry,
    get_audio_catalog,
    get_audio_model_by_id,
    "ONNX speech-recognition model"
);
engine_accessors!(
    Tts,
    TtsModelEntry,
    get_tts_catalog,
    get_tts_model_by_id,
    "speech-synthesis model"
);
engine_accessors!(
    Omni,
    OmniModelEntry,
    get_omni_catalog,
    get_omni_model_by_id,
    "omni model (spoken replies)"
);
engine_accessors!(
    OnnxVideo,
    OnnxVideoEntry,
    get_video_catalog,
    get_video_model_by_id,
    "ONNX video encoder"
);
engine_accessors!(
    MediaGen,
    MediaGenModelEntry,
    get_media_gen_catalog,
    get_media_gen_model_by_id,
    "generative-media pipeline"
);

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

/// The catalog entry for `model_id` when it runs on this release: an unknown
/// model, and a planned one with [`MEDIA_PLANNED_REFUSAL`], are refused.
pub fn runnable_media_gen_model(model_id: &str) -> Result<MediaGenModelEntry, String> {
    let entry = get_media_gen_model_by_id(model_id)
        .ok_or_else(|| format!("unknown media model '{model_id}'"))?;
    match entry.status {
        MediaGenStatus::Native => Ok(entry),
        MediaGenStatus::Planned => Err(format!("{model_id}: {MEDIA_PLANNED_REFUSAL}")),
    }
}

/// Generative-media pipelines serving a given job kind.
pub fn get_media_gen_models_for_kind(kind: tenzro_types::MediaGenKind) -> Vec<MediaGenModelEntry> {
    get_media_gen_catalog()
        .into_iter()
        .filter(|m| m.kinds.contains(&kind))
        .collect()
}

/// The full entry for `id`, of any engine family.
pub fn entry(id: &str) -> Option<CatalogEntry> {
    store::current().entry(id).cloned()
}

/// The licence tier of the catalogued model `id`, of any engine family.
/// `None` for an id the catalog does not list.
pub fn license_tier_of(id: &str) -> Option<LicenseTier> {
    store::current()
        .entry(id)
        .map(|e| e.licence.effective_tier())
}

/// Whether the catalogued model `id` may be charged for or served to a paying
/// caller. An uncatalogued id carries no licence restriction this node knows
/// of.
pub fn permits_paid_use(id: &str) -> bool {
    license_tier_of(id).is_none_or(LicenseTier::permits_paid_use)
}

/// The entry that lists `repo`/`path`, and its component for that file.
pub fn file(repo: &str, path: &str) -> Option<(CatalogEntry, Component)> {
    let catalog = store::current();
    catalog
        .file(repo, path)
        .map(|(e, c)| (e.clone(), c.clone()))
}

/// Published-benchmark capability prior for a model, in `[0.0, 1.0]`, used to
/// bootstrap model selection at cold start — before the measured per-cluster
/// difficulty path has any observations for a prompt. `None` when the entry
/// states no prior for the use case, in which case cost (then measurement)
/// decides, so an unknown model is never penalised.
pub fn capability_prior(model_id: &str, use_case: &str) -> Option<f32> {
    let bps = *store::current()
        .entry(model_id)?
        .capability_priors
        .get(use_case)?;
    Some(bps as f32 / 10_000.0)
}

/// The unquantised checkpoint a Mixture-of-Experts entry's experts are
/// extracted from. `None` when expert extraction is not available for it.
pub fn moe_source(model_id: &str) -> Option<SourceCheckpoint> {
    store::current().entry(model_id)?.moe_source.clone()
}

/// Every GGUF model family in the catalog.
pub fn get_model_families() -> Vec<String> {
    let mut families: Vec<String> = get_model_catalog().into_iter().map(|m| m.family).collect();
    families.sort();
    families.dedup();
    families
}

/// Read catalog entries from a JSON file (one entry or an array of them) or
/// from every `*.json` file of a directory.
pub fn read_entries(path: &std::path::Path) -> Result<Vec<CatalogEntry>, String> {
    let mut files = Vec::new();
    if path.is_dir() {
        let dir = std::fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
        for f in dir {
            let f = f.map_err(|e| format!("{}: {e}", path.display()))?.path();
            if f.extension().is_some_and(|x| x == "json") {
                files.push(f);
            }
        }
        files.sort();
    } else {
        files.push(path.to_path_buf());
    }
    let mut out = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", f.display()))?;
        let items = match value {
            serde_json::Value::Array(items) => items,
            one => vec![one],
        };
        for item in items {
            out.push(serde_json::from_value(item).map_err(|e| format!("{}: {e}", f.display()))?);
        }
    }
    Ok(out)
}

/// Install the seed entries (this crate's `seed/`) as the process catalog.
/// For the tests of crates that read the catalog; a node installs only what
/// its trusted publishers signed. The catalog is process-wide and a node a
/// test starts installs its own over it, so the seed goes back whenever it is
/// not the catalog in place.
#[cfg(feature = "test-seed")]
pub fn install_test_seed() {
    static SEED: std::sync::OnceLock<Vec<CatalogEntry>> = std::sync::OnceLock::new();
    let entries = SEED.get_or_init(|| {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("seed");
        read_entries(&dir).expect("the seed parses")
    });
    let current = store::current();
    if current.len() == entries.len() && entries.iter().all(|e| current.entry(e.id()).is_some()) {
        return;
    }
    let (catalog, errors) = Catalog::build(entries.clone());
    assert!(errors.is_empty(), "seed entries refused: {errors:?}");
    store::install(catalog);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `xhigh` is valid for both families; `high` is a real level for
    /// muse-glimmer but only an alias on Qwen, whose template folds it into
    /// `xhigh`. Both must round-trip to something the template accepts.
    #[test]
    fn effort_levels_and_aliases_resolve_per_family() {
        let q = EffortPolicy::for_family("qwen3.8-flash-next");
        assert_eq!(q.normalize("xhigh").as_deref(), Some("xhigh"));
        assert_eq!(q.normalize("high").as_deref(), Some("xhigh"));
        assert_eq!(q.normalize("low").as_deref(), Some("low"));

        let m = EffortPolicy::for_family("muse-glimmer");
        assert_eq!(m.normalize("high").as_deref(), Some("high"));
        assert_eq!(m.normalize("xhigh").as_deref(), Some("xhigh"));
    }

    /// Case and surrounding space come from callers, not from us.
    #[test]
    fn effort_matching_is_case_and_space_insensitive() {
        let q = EffortPolicy::for_family("qwen3.8-flash-next");
        assert_eq!(q.normalize("  XHigh ").as_deref(), Some("xhigh"));
    }

    /// An unknown level must fall back to the template default rather than be
    /// forwarded: Qwen's template raises on an unrecognised value, which would
    /// turn a client typo into a failed generation.
    #[test]
    fn unknown_effort_falls_back_rather_than_forwarding() {
        let q = EffortPolicy::for_family("qwen3.8-flash-next");
        assert_eq!(q.normalize("turbo"), None);
        assert_eq!(q.normalize(""), None);
    }

    #[test]
    fn parameter_counts_come_off_the_declared_string() {
        assert_eq!(parse_parameter_count("0.8B"), Some(800_000_000));
        // MoE: the leading total, not the parenthesised active count.
        assert_eq!(
            parse_parameter_count("35B (MoE, 3B active)"),
            Some(35_000_000_000)
        );
        assert_eq!(parse_parameter_count("270M"), Some(270_000_000));
        // Gemma's effective-parameter notation.
        assert_eq!(parse_parameter_count("E2B"), Some(2_000_000_000));
        assert_eq!(parse_parameter_count("E4B"), Some(4_000_000_000));
        // Nothing to read: stay out of the strong tier rather than guess.
        assert_eq!(parse_parameter_count(""), None);
        assert_eq!(parse_parameter_count("MTP head"), None);
        assert_eq!(parse_parameter_count("12"), None);
    }

    #[test]
    fn a_split_gguf_downloads_every_shard_and_a_single_file_downloads_itself() {
        let mut e = HfModelEntry {
            hf_filename: "Q4_K_M/Kimi-K2-Q4_K_M-00001-of-00003.gguf".into(),
            ..Default::default()
        };
        assert_eq!(
            e.download_files(),
            vec![
                "Q4_K_M/Kimi-K2-Q4_K_M-00001-of-00003.gguf",
                "Q4_K_M/Kimi-K2-Q4_K_M-00002-of-00003.gguf",
                "Q4_K_M/Kimi-K2-Q4_K_M-00003-of-00003.gguf",
            ]
        );
        e.hf_filename = "Qwen3.5-4B-Q4_K_M.gguf".into();
        assert_eq!(e.download_files(), vec!["Qwen3.5-4B-Q4_K_M.gguf"]);
        e.hf_filename.clear();
        assert!(e.download_files().is_empty());
        assert!(shard_spec("Model-00002-of-00003.gguf").is_none());
    }
}
